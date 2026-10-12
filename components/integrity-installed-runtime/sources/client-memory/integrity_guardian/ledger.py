"""Append-only local ledger and offline verification primitives."""

from __future__ import annotations

import hashlib
import re
import sqlite3
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Self

from jsonschema import ValidationError

from .canonical import canonical_bytes, parse_json_strict
from .hashing import digest_object
from .schemas import validate
from .signing import Ed25519Signer, TrustedKey, public_key_value, verify_signature

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class LedgerError(RuntimeError):
    """Base class for ledger consistency failures."""


class LedgerAppendError(LedgerError):
    """Raised before an invalid event can be committed."""


class LedgerVerificationError(LedgerError):
    """Raised when stored evidence does not reconstruct exactly."""


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def build_ledger_event(
    *,
    tenant_id: str,
    source_id: str,
    source_sequence: int,
    event_type: str,
    payload_digest: str,
    previous_event_digest: str | None,
    signer: Ed25519Signer,
    recorded_at: str | None = None,
) -> dict[str, Any]:
    unsigned: dict[str, Any] = {
        "protocol": "integrity-guardian/ledger-event/v1",
        "event_id": "event:pending",
        "tenant_id": tenant_id,
        "source_id": source_id,
        "source_sequence": source_sequence,
        "event_type": event_type,
        "recorded_at": recorded_at or _now(),
        "payload_digest": payload_digest,
        "previous_event_digest": previous_event_digest,
    }
    unsigned["event_id"] = ledger_event_identity(unsigned)
    event = signer.sign(unsigned)
    validate("ledger-event", event)
    return event


def ledger_event_identity(event: Mapping[str, Any]) -> str:
    """Return the canonical identity of one ledger event."""

    core = deepcopy(dict(event))
    core.pop("signature", None)
    core["event_id"] = "event:pending"
    digest = digest_object(core, domain="ledger-event-identity-v1")
    return f"event:{digest.split(':', 1)[1]}"


def event_digest(event: dict[str, Any]) -> str:
    return digest_object(event, domain="ledger-event-v1")


def verify_ledger_event(
    event: Mapping[str, Any],
    trusted_key: TrustedKey,
    *,
    expected_tenant_id: str | None = None,
    expected_source_id: str | None = None,
    expected_event_type: str | None = None,
    expected_payload_digest: str | None = None,
) -> dict[str, Any]:
    """Verify schema, content identity, signature and optional exact bindings."""

    try:
        candidate = deepcopy(dict(event))
        validate("ledger-event", candidate)
    except (TypeError, KeyError, ValueError, ValidationError) as exc:
        raise LedgerVerificationError("ledger event schema is invalid") from exc
    if candidate["event_id"] != ledger_event_identity(candidate):
        raise LedgerVerificationError("ledger event identity mismatch")
    if candidate["signature"]["key_id"] != trusted_key.key_id or not verify_signature(
        candidate, trusted_key.public_key
    ):
        raise LedgerVerificationError("ledger event signature verification failed")
    expected = {
        "tenant_id": expected_tenant_id,
        "source_id": expected_source_id,
        "event_type": expected_event_type,
        "payload_digest": expected_payload_digest,
    }
    for field, value in expected.items():
        if value is not None and candidate[field] != value:
            raise LedgerVerificationError(f"ledger event {field} mismatch")
    return candidate


def _leaf_hash(digest: str) -> bytes:
    return hashlib.sha256(b"\x00integrity-guardian-merkle-v1\x00" + digest.encode("ascii")).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01integrity-guardian-merkle-v1\x00" + left + right).digest()


def merkle_root(digests: Iterable[str]) -> str:
    level = [_leaf_hash(digest) for digest in digests]
    if not level:
        raise ValueError("a checkpoint cannot commit an empty ledger")
    while len(level) > 1:
        next_level: list[bytes] = []
        for index in range(0, len(level), 2):
            if index + 1 == len(level):
                next_level.append(level[index])
            else:
                next_level.append(_node_hash(level[index], level[index + 1]))
        level = next_level
    return f"sha256:{level[0].hex()}"


def merkle_inclusion_path(
    digests: Iterable[str],
    leaf_index: int,
) -> list[dict[str, str]]:
    """Build a canonical audit path for the existing promoted-odd Merkle tree."""

    leaves = list(digests)
    if not leaves:
        raise ValueError("an inclusion proof requires a non-empty ledger")
    if (
        not isinstance(leaf_index, int)
        or isinstance(leaf_index, bool)
        or not 0 <= leaf_index < len(leaves)
    ):
        raise ValueError("inclusion leaf index is out of range")

    level = [_leaf_hash(digest) for digest in leaves]
    index = leaf_index
    path: list[dict[str, str]] = []
    while len(level) > 1:
        if index % 2 == 1:
            sibling_index = index - 1
            path.append(
                {
                    "side": "left",
                    "digest": f"sha256:{level[sibling_index].hex()}",
                }
            )
        elif index + 1 < len(level):
            sibling_index = index + 1
            path.append(
                {
                    "side": "right",
                    "digest": f"sha256:{level[sibling_index].hex()}",
                }
            )

        next_level: list[bytes] = []
        for position in range(0, len(level), 2):
            if position + 1 == len(level):
                next_level.append(level[position])
            else:
                next_level.append(_node_hash(level[position], level[position + 1]))
        level = next_level
        index //= 2
    return path


def verify_merkle_inclusion_path(
    *,
    event_digest_value: str,
    leaf_index: int,
    tree_size: int,
    audit_path: Iterable[Mapping[str, str]],
    expected_root_digest: str,
) -> None:
    """Fail closed unless one event digest reconstructs the exact Merkle root."""

    if (
        not isinstance(tree_size, int)
        or isinstance(tree_size, bool)
        or tree_size < 1
        or not isinstance(leaf_index, int)
        or isinstance(leaf_index, bool)
        or not 0 <= leaf_index < tree_size
    ):
        raise LedgerVerificationError("ledger inclusion position rejected")
    if (
        not isinstance(event_digest_value, str)
        or _DIGEST.fullmatch(event_digest_value) is None
        or not isinstance(expected_root_digest, str)
        or _DIGEST.fullmatch(expected_root_digest) is None
    ):
        raise LedgerVerificationError("ledger inclusion digest rejected")
    try:
        path = [dict(step) for step in audit_path]
    except (TypeError, ValueError) as exc:
        raise LedgerVerificationError("ledger inclusion audit path rejected") from exc

    node = _leaf_hash(event_digest_value)
    index = leaf_index
    width = tree_size
    path_index = 0
    while width > 1:
        expected_side: str | None
        if index % 2 == 1:
            expected_side = "left"
        elif index + 1 < width:
            expected_side = "right"
        else:
            expected_side = None

        if expected_side is not None:
            if path_index >= len(path):
                raise LedgerVerificationError("ledger inclusion audit path is incomplete")
            step = path[path_index]
            path_index += 1
            if set(step) != {"side", "digest"} or step["side"] != expected_side:
                raise LedgerVerificationError("ledger inclusion audit path direction mismatch")
            digest = step["digest"]
            if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
                raise LedgerVerificationError("ledger inclusion sibling digest rejected")
            try:
                sibling = bytes.fromhex(digest.split(":", 1)[1])
            except ValueError as exc:
                raise LedgerVerificationError("ledger inclusion sibling digest rejected") from exc
            node = (
                _node_hash(sibling, node) if expected_side == "left" else _node_hash(node, sibling)
            )

        index //= 2
        width = (width + 1) // 2

    if path_index != len(path):
        raise LedgerVerificationError("ledger inclusion audit path has extra steps")
    if f"sha256:{node.hex()}" != expected_root_digest:
        raise LedgerVerificationError("ledger inclusion Merkle root mismatch")


def verify_ledger_inclusion_proof(
    proof: Mapping[str, Any],
    *,
    expected_tenant_id: str | None = None,
    expected_ledger_id: str | None = None,
    expected_event_digest: str | None = None,
    expected_root_digest: str | None = None,
    expected_tree_size: int | None = None,
) -> dict[str, Any]:
    """Verify one portable, unsigned Merkle proof against exact expectations."""

    try:
        candidate = deepcopy(dict(proof))
        validate("ledger-inclusion-proof", candidate)
    except (TypeError, KeyError, ValueError, ValidationError) as exc:
        raise LedgerVerificationError("ledger inclusion proof schema is invalid") from exc
    expected = {
        "tenant_id": expected_tenant_id,
        "ledger_id": expected_ledger_id,
        "event_digest": expected_event_digest,
        "root_digest": expected_root_digest,
        "tree_size": expected_tree_size,
    }
    for field, value in expected.items():
        if value is not None and candidate[field] != value:
            raise LedgerVerificationError(f"ledger inclusion proof {field} mismatch")
    verify_merkle_inclusion_path(
        event_digest_value=candidate["event_digest"],
        leaf_index=candidate["leaf_index"],
        tree_size=candidate["tree_size"],
        audit_path=candidate["audit_path"],
        expected_root_digest=candidate["root_digest"],
    )
    return candidate


class LedgerStore:
    """One customer-local SQLite ledger.

    SQLite is a storage mechanism, not the trust anchor. Trust comes from
    signed objects, reconstructed chains and independently retained checkpoints.
    """

    def __init__(
        self,
        path: Path,
        *,
        tenant_id: str,
        ledger_id: str,
        connection: sqlite3.Connection | None = None,
        busy_timeout_ms: int = 5_000,
    ) -> None:
        if (
            isinstance(busy_timeout_ms, bool)
            or not isinstance(busy_timeout_ms, int)
            or busy_timeout_ms < 0
            or busy_timeout_ms > 60_000
        ):
            raise ValueError("ledger busy timeout must be between 0 and 60000 milliseconds")
        self.path = path
        self.tenant_id = tenant_id
        self.ledger_id = ledger_id
        self._connection = connection or sqlite3.connect(
            path,
            timeout=busy_timeout_ms / 1_000,
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute(f"PRAGMA busy_timeout = {busy_timeout_ms}")
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA journal_mode = WAL")
        self._initialize()

    def _initialize(self) -> None:
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS ledger_meta (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                tenant_id TEXT NOT NULL,
                ledger_id TEXT NOT NULL,
                protocol TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS ledger_events (
                ledger_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                event_digest TEXT NOT NULL UNIQUE,
                tenant_id TEXT NOT NULL,
                source_id TEXT NOT NULL,
                source_sequence INTEGER NOT NULL,
                previous_event_digest TEXT,
                event_json BLOB NOT NULL,
                UNIQUE (tenant_id, source_id, source_sequence)
            );
            """
        )
        existing = self._connection.execute(
            "SELECT tenant_id, ledger_id, protocol FROM ledger_meta WHERE singleton = 1"
        ).fetchone()
        if existing is None:
            self._connection.execute(
                """
                INSERT INTO ledger_meta(singleton, tenant_id, ledger_id, protocol)
                VALUES(1, ?, ?, 'integrity-guardian/ledger-store/v1')
                """,
                (self.tenant_id, self.ledger_id),
            )
            self._connection.commit()
        elif (
            existing["tenant_id"] != self.tenant_id
            or existing["ledger_id"] != self.ledger_id
            or existing["protocol"] != "integrity-guardian/ledger-store/v1"
        ):
            raise LedgerVerificationError("ledger identity does not match requested identity")

    def close(self) -> None:
        self._connection.close()

    def bind_native_trust(
        self,
        enrollment: Mapping[str, Any],
        *,
        issuer_key: TrustedKey,
    ) -> str:
        """Bind one verified native key enrollment before the first event.

        Existing ledgers are never silently adopted.  A populated unbound
        ledger needs an explicit migration receipt; an already bound ledger is
        idempotent only for the exact same canonical enrollment.
        """

        _candidate, enrollment_id, payload = self._verify_native_enrollment(
            enrollment,
            issuer_key=issuer_key,
        )
        existing_table = self._connection.execute(
            """
            SELECT 1 FROM sqlite_master
            WHERE type = 'table' AND name = 'ledger_native_trust'
            """
        ).fetchone()
        if existing_table is not None:
            existing = self._connection.execute(
                "SELECT enrollment_id, enrollment_json FROM ledger_native_trust WHERE singleton = 1"
            ).fetchone()
            if (
                existing is None
                or existing["enrollment_id"] != enrollment_id
                or bytes(existing["enrollment_json"]) != payload
            ):
                raise LedgerVerificationError("native database trust binding differs")
            return str(enrollment_id)
        event_count = self._connection.execute("SELECT COUNT(*) FROM ledger_events").fetchone()[0]
        if event_count:
            raise LedgerVerificationError(
                "populated ledger requires explicit native trust migration"
            )
        self._store_native_trust(enrollment_id, payload)
        return str(enrollment_id)

    def _verify_native_enrollment(
        self,
        enrollment: Mapping[str, Any],
        *,
        issuer_key: TrustedKey,
    ) -> tuple[dict[str, Any], str, bytes]:
        try:
            candidate = deepcopy(dict(enrollment))
            validate("native-database-enrollment", candidate)
        except (TypeError, KeyError, ValueError, ValidationError) as exc:
            raise LedgerVerificationError("native database enrollment schema is invalid") from exc
        core = deepcopy(candidate)
        core.pop("signature")
        enrollment_id = core.pop("enrollment_id")
        if (
            candidate["tenant_id"] != self.tenant_id
            or candidate["ledger_id"] != self.ledger_id
            or enrollment_id != digest_object(core, domain="native-database-enrollment-v1")
            or candidate["signature"]["key_id"] != issuer_key.key_id
            or not verify_signature(candidate, issuer_key.public_key)
        ):
            raise LedgerVerificationError("native database enrollment verification failed")
        return candidate, str(enrollment_id), canonical_bytes(candidate)

    def _store_native_trust(self, enrollment_id: str, payload: bytes) -> None:
        with self._connection:
            self._connection.execute(
                """
                CREATE TABLE ledger_native_trust (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    enrollment_id TEXT NOT NULL UNIQUE,
                    enrollment_json BLOB NOT NULL
                )
                """
            )
            self._connection.execute(
                """
                INSERT INTO ledger_native_trust(singleton, enrollment_id, enrollment_json)
                VALUES(1, ?, ?)
                """,
                (enrollment_id, payload),
            )

    def migrate_native_trust(
        self,
        enrollment: Mapping[str, Any],
        *,
        issuer_key: TrustedKey,
        source_key: TrustedKey,
        checkpoint: Mapping[str, Any],
        checkpoint_key: TrustedKey,
    ) -> dict[str, Any]:
        """Adopt a populated ledger only after full old-chain verification."""

        candidate, enrollment_id, payload = self._verify_native_enrollment(
            enrollment,
            issuer_key=issuer_key,
        )
        source = candidate["source_key"]
        checkpoint_subject = candidate["checkpoint_key"]
        if (
            source["key_id"] != source_key.key_id
            or source["public_key"] != public_key_value(source_key.public_key)
            or checkpoint_subject["key_id"] != checkpoint_key.key_id
            or checkpoint_subject["public_key"] != public_key_value(checkpoint_key.public_key)
        ):
            raise LedgerVerificationError(
                "native database enrollment does not preserve existing keys"
            )
        events = self.events()
        if not events:
            raise LedgerVerificationError("empty ledger uses native trust binding, not migration")
        source_keys = {event["source_id"]: source_key for event in events}
        verification = self.verify(
            source_public_keys=source_keys,
            checkpoint=checkpoint,
            checkpoint_key=checkpoint_key,
        )
        if not verification["ok"] or not verification["checkpoint_verified"]:
            raise LedgerVerificationError("existing ledger chain verification failed")
        existing_enrollment = self.native_trust_enrollment()
        if existing_enrollment is not None:
            if existing_enrollment != candidate:
                raise LedgerVerificationError("native database trust binding differs")
            return {
                "enrollment_id": enrollment_id,
                "previous_checkpoint_digest": digest_object(
                    checkpoint, domain="native-database-migration-checkpoint-v1"
                ),
                "event_count": len(events),
                "tree_size": checkpoint["tree_size"],
            }
        self._store_native_trust(enrollment_id, payload)
        return {
            "enrollment_id": enrollment_id,
            "previous_checkpoint_digest": digest_object(
                checkpoint, domain="native-database-migration-checkpoint-v1"
            ),
            "event_count": len(events),
            "tree_size": checkpoint["tree_size"],
        }

    def native_trust_enrollment(self) -> dict[str, Any] | None:
        """Return the immutable public enrollment, never private key material."""

        existing_table = self._connection.execute(
            """
            SELECT 1 FROM sqlite_master
            WHERE type = 'table' AND name = 'ledger_native_trust'
            """
        ).fetchone()
        if existing_table is None:
            return None
        row = self._connection.execute(
            "SELECT enrollment_json FROM ledger_native_trust WHERE singleton = 1"
        ).fetchone()
        if row is None:
            raise LedgerVerificationError("native database trust binding is incomplete")
        value = parse_json_strict(bytes(row["enrollment_json"]))
        if not isinstance(value, dict):
            raise LedgerVerificationError("native database trust binding is invalid")
        validate("native-database-enrollment", value)
        return value

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _source_tip(self, tenant_id: str, source_id: str) -> sqlite3.Row | None:
        return self._connection.execute(
            """
            SELECT source_sequence, event_digest
            FROM ledger_events
            WHERE tenant_id = ? AND source_id = ?
            ORDER BY source_sequence DESC
            LIMIT 1
            """,
            (tenant_id, source_id),
        ).fetchone()

    def _append_one(self, event: dict[str, Any]) -> str:
        validate("ledger-event", event)
        if event["event_id"] != ledger_event_identity(event):
            raise LedgerAppendError("ledger event identity mismatch")
        if event["tenant_id"] != self.tenant_id:
            raise LedgerAppendError("cross-tenant append is prohibited")

        tip = self._source_tip(event["tenant_id"], event["source_id"])
        expected_sequence = 0 if tip is None else tip["source_sequence"] + 1
        expected_previous = None if tip is None else tip["event_digest"]
        if event["source_sequence"] != expected_sequence:
            raise LedgerAppendError(
                f"source sequence mismatch: expected {expected_sequence}, "
                f"got {event['source_sequence']}"
            )
        if event["previous_event_digest"] != expected_previous:
            raise LedgerAppendError("previous source event digest mismatch")

        digest = event_digest(event)
        self._connection.execute(
            """
            INSERT INTO ledger_events(
                event_digest, tenant_id, source_id, source_sequence,
                previous_event_digest, event_json
            ) VALUES(?, ?, ?, ?, ?, ?)
            """,
            (
                digest,
                event["tenant_id"],
                event["source_id"],
                event["source_sequence"],
                event["previous_event_digest"],
                canonical_bytes(event),
            ),
        )
        return digest

    @contextmanager
    def _write_transaction(self) -> Iterator[None]:
        if self._connection.in_transaction:
            # A caller-owned transaction keeps its historical commit semantics.
            with self._connection:
                yield
            return
        # Take the write lock before reading the source tip, so a concurrent
        # writer to the same source fails with a sequence mismatch instead of
        # racing into the unique constraint.
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self._connection.rollback()
            raise
        self._connection.commit()

    def append(self, event: dict[str, Any]) -> str:
        with self._write_transaction():
            return self._append_one(event)

    def append_many(self, events: Iterable[dict[str, Any]]) -> list[str]:
        """Append an entire batch atomically."""

        digests: list[str] = []
        with self._write_transaction():
            for event in events:
                digests.append(self._append_one(event))
        return digests

    def append_at_checkpoint(
        self,
        event: dict[str, Any],
        *,
        source_public_keys: dict[str, TrustedKey],
        checkpoint: dict[str, Any],
        checkpoint_key: TrustedKey,
        precommit_validator: Callable[[list[dict[str, Any]]], None] | None = None,
    ) -> str:
        """Append only while an exact externally retained checkpoint is current."""

        try:
            self._connection.execute("BEGIN IMMEDIATE")
            self.verify(
                source_public_keys=source_public_keys,
                checkpoint=checkpoint,
                checkpoint_key=checkpoint_key,
            )
            if precommit_validator is not None:
                precommit_validator([*self.events(), deepcopy(event)])
            digest = self._append_one(event)
            self._connection.commit()
            return digest
        except Exception:
            self._connection.rollback()
            raise

    def event_digests(self) -> list[str]:
        rows = self._connection.execute(
            "SELECT event_digest FROM ledger_events ORDER BY ledger_sequence"
        )
        return [row["event_digest"] for row in rows]

    def events(self) -> list[dict[str, Any]]:
        rows = self._connection.execute(
            "SELECT event_json FROM ledger_events ORDER BY ledger_sequence"
        )
        return [parse_json_strict(row["event_json"]) for row in rows]

    def inclusion_proof(self, event_digest_value: str) -> dict[str, Any]:
        """Return a portable Merkle path for one event in the current ledger."""

        digests = self.event_digests()
        try:
            leaf_index = digests.index(event_digest_value)
        except ValueError as exc:
            raise LedgerVerificationError("ledger inclusion event is absent") from exc
        proof = {
            "protocol": "integrity-guardian/ledger-inclusion-proof/v1",
            "tenant_id": self.tenant_id,
            "ledger_id": self.ledger_id,
            "tree_size": len(digests),
            "leaf_index": leaf_index,
            "event_digest": event_digest_value,
            "root_digest": merkle_root(digests),
            "audit_path": merkle_inclusion_path(digests, leaf_index),
        }
        return verify_ledger_inclusion_proof(
            proof,
            expected_tenant_id=self.tenant_id,
            expected_ledger_id=self.ledger_id,
            expected_event_digest=event_digest_value,
        )

    def checkpoint(
        self,
        *,
        checkpoint_id: str,
        signer: Ed25519Signer,
        created_at: str | None = None,
    ) -> dict[str, Any]:
        digests = self.event_digests()
        if not digests:
            raise LedgerAppendError("cannot checkpoint an empty ledger")
        unsigned = {
            "protocol": "integrity-guardian/checkpoint/v1",
            "checkpoint_id": checkpoint_id,
            "tenant_id": self.tenant_id,
            "ledger_id": self.ledger_id,
            "tree_size": len(digests),
            "root_digest": merkle_root(digests),
            "last_event_digest": digests[-1],
            "created_at": created_at or _now(),
            "signer_id": signer.key_id,
        }
        checkpoint = signer.sign(unsigned)
        validate("checkpoint", checkpoint)
        return checkpoint

    def verify(
        self,
        *,
        source_public_keys: dict[str, TrustedKey],
        checkpoint: dict[str, Any] | None = None,
        checkpoint_key: TrustedKey | None = None,
    ) -> dict[str, Any]:
        source_tips: dict[str, tuple[int, str]] = {}
        reconstructed: list[str] = []
        rows = self._connection.execute(
            """
            SELECT ledger_sequence, event_digest, tenant_id, source_id,
                   source_sequence, previous_event_digest, event_json
            FROM ledger_events
            ORDER BY ledger_sequence
            """
        )
        for row in rows:
            try:
                event = parse_json_strict(row["event_json"])
                validate("ledger-event", event)
            except Exception as exc:
                raise LedgerVerificationError(
                    f"ledger sequence {row['ledger_sequence']} has invalid event bytes"
                ) from exc
            calculated = event_digest(event)
            if calculated != row["event_digest"]:
                raise LedgerVerificationError(
                    f"ledger sequence {row['ledger_sequence']} digest mismatch"
                )
            for field in (
                "tenant_id",
                "source_id",
                "source_sequence",
                "previous_event_digest",
            ):
                if event[field] != row[field]:
                    raise LedgerVerificationError(
                        f"ledger sequence {row['ledger_sequence']} indexed {field} mismatch"
                    )
            if event["tenant_id"] != self.tenant_id:
                raise LedgerVerificationError("cross-tenant event found")
            if event["event_id"] != ledger_event_identity(event):
                raise LedgerVerificationError("ledger event identity mismatch")

            previous = source_tips.get(event["source_id"])
            expected_sequence = 0 if previous is None else previous[0] + 1
            expected_digest = None if previous is None else previous[1]
            if event["source_sequence"] != expected_sequence:
                raise LedgerVerificationError("source sequence discontinuity")
            if event["previous_event_digest"] != expected_digest:
                raise LedgerVerificationError("source hash-chain discontinuity")
            trusted_key = source_public_keys.get(event["source_id"])
            if (
                trusted_key is None
                or event["signature"]["key_id"] != trusted_key.key_id
                or not verify_signature(event, trusted_key.public_key)
            ):
                raise LedgerVerificationError("source signature verification failed")
            source_tips[event["source_id"]] = (event["source_sequence"], calculated)
            reconstructed.append(calculated)

        if checkpoint is not None:
            if (
                checkpoint_key is None
                or checkpoint["signer_id"] != checkpoint_key.key_id
                or checkpoint["signature"]["key_id"] != checkpoint_key.key_id
                or not verify_signature(checkpoint, checkpoint_key.public_key)
            ):
                raise LedgerVerificationError("checkpoint signature verification failed")
            validate("checkpoint", checkpoint)
            if checkpoint["tenant_id"] != self.tenant_id:
                raise LedgerVerificationError("checkpoint tenant mismatch")
            if checkpoint["ledger_id"] != self.ledger_id:
                raise LedgerVerificationError("checkpoint ledger mismatch")
            if checkpoint["tree_size"] != len(reconstructed):
                raise LedgerVerificationError("checkpoint tree size mismatch")
            if not reconstructed:
                raise LedgerVerificationError("checkpoint refers to empty ledger")
            if checkpoint["root_digest"] != merkle_root(reconstructed):
                raise LedgerVerificationError("checkpoint Merkle root mismatch")
            if checkpoint["last_event_digest"] != reconstructed[-1]:
                raise LedgerVerificationError("checkpoint tip mismatch")

        return {
            "ok": checkpoint is not None,
            "tenant_id": self.tenant_id,
            "ledger_id": self.ledger_id,
            "tree_size": len(reconstructed),
            "source_count": len(source_tips),
            "checkpoint_verified": checkpoint is not None,
        }
