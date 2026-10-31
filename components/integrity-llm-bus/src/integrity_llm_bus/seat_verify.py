"""One-time GO decisions. Signatures never bypass fencing or ChangeIntent."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import sqlite3
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

GO_FIELDS = (
    "approver_seat",
    "key_id",
    "core_instance_id",
    "msg_id",
    "th",
    "decision_ref",
    "request_digest",
    "request_seq",
    "action",
    "scope",
    "created_utc",
    "expires_utc",
)
ALGS = frozenset({"Ed25519", "ECDSA-P256", "RSA-2048"})
WINDOW = timedelta(seconds=300)


class GoError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def canonical_go(payload: dict) -> bytes:
    if not isinstance(payload, dict) or set(payload) != set(GO_FIELDS):
        raise GoError("go payload fields invalid")
    return json.dumps(
        {field: payload[field] for field in GO_FIELDS},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _parse_utc(value: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise GoError("go time invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as err:
        raise GoError("go time invalid") from err
    return parsed.astimezone(timezone.utc)


def verify_signature(alg: str, public_pem: str, payload: bytes, signature: bytes) -> None:
    if alg not in ALGS or not isinstance(public_pem, str) or "PRIVATE" in public_pem:
        raise GoError("go key invalid")
    try:
        key = serialization.load_pem_public_key(public_pem.encode("utf-8"))
        if alg == "Ed25519":
            if not isinstance(key, ed25519.Ed25519PublicKey):
                raise GoError("go key invalid")
            key.verify(signature, payload)
        elif alg == "ECDSA-P256":
            if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
                raise GoError("go key invalid")
            key.verify(signature, payload, ec.ECDSA(hashes.SHA256()))
        else:
            if not isinstance(key, rsa.RSAPublicKey) or key.key_size != 2048:
                raise GoError("go key invalid")
            key.verify(signature, payload, padding.PKCS1v15(), hashes.SHA256())
    except (InvalidSignature, ValueError, TypeError) as err:
        raise GoError("go signature invalid") from err


class GoLedger:
    """Consume each signed decision once. Replay fails closed."""

    def __init__(self, path: Path, *, core_instance_id: str) -> None:
        self.path = path
        self.core_instance_id = core_instance_id
        connection = sqlite3.connect(path)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS consumed_go (
                msg_id TEXT PRIMARY KEY,
                approver_seat TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                consumed_utc TEXT NOT NULL
            )
            """
        )
        connection.commit()
        connection.close()

    def consume(
        self,
        payload: dict,
        signature: bytes,
        *,
        now: datetime,
        decision_seq: int,
        lookup,
    ) -> dict:
        signed = canonical_go(payload)
        created = _parse_utc(payload["created_utc"])
        expires = _parse_utc(payload["expires_utc"])
        if now.tzinfo is None:
            raise GoError("go time invalid")
        current = now.astimezone(timezone.utc)
        if abs(current - created) > WINDOW or expires <= current or expires - created > WINDOW:
            raise GoError("go window invalid")
        if payload["core_instance_id"] != self.core_instance_id:
            raise GoError("go core mismatch")
        if not isinstance(payload["request_seq"], int) or isinstance(payload["request_seq"], bool):
            raise GoError("go request seq invalid")
        if not isinstance(decision_seq, int) or isinstance(decision_seq, bool) or decision_seq <= payload["request_seq"]:
            raise GoError("go seq invalid")
        if not isinstance(payload["decision_ref"], str) or len(payload["decision_ref"]) < 12:
            raise GoError("go decision ref invalid")
        digest = payload["request_digest"]
        if not isinstance(digest, str) or len(digest) != 64 or payload["decision_ref"][:12] != digest[:12]:
            raise GoError("go digest citation invalid")
        record = lookup(payload["approver_seat"], payload["key_id"])
        if record is None or "go_approver" not in record.get("roles", ()) or record.get("retired_at"):
            raise GoError("go approver invalid")
        if record.get("alg") not in ALGS:
            raise GoError("go key invalid")
        verify_signature(record["alg"], record["public_key"], signed, signature)
        connection = sqlite3.connect(self.path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute(
                    """
                    INSERT INTO consumed_go (msg_id, approver_seat, request_digest, consumed_utc)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        payload["msg_id"],
                        payload["approver_seat"],
                        digest,
                        current.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    ),
                )
            except sqlite3.IntegrityError as err:
                connection.execute("ROLLBACK")
                raise GoError("go replay rejected") from err
            connection.execute("COMMIT")
        finally:
            connection.close()
        return {"ok": True, "msg_id": payload["msg_id"], "consumed": True}
