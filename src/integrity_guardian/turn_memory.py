"""Signed, append-only coverage receipts for Codex memory turns.

The ledger deliberately distinguishes a terminal ``no-event`` decision from a
missing decision.  A runtime may observe and sign the latter as coverage debt,
but it must never silently convert it into the former.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import sqlite3
from collections.abc import Iterable, Mapping
from copy import deepcopy
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes
from .schemas import validate
from .signing import (
    Ed25519Signer,
    TrustedKey,
    public_key_fingerprint,
    verify_signature,
)

REGISTRATION_PROTOCOL = "integrity-guardian/turn-memory-registration/v1"
TERMINAL_PROTOCOL = "integrity-guardian/turn-memory-terminal-receipt/v1"
GAP_PROTOCOL = "integrity-guardian/turn-memory-gap-receipt/v1"
COVERAGE_PROTOCOL = "integrity-guardian/turn-memory-coverage/v1"

NO_EVENT_REASONS = frozenset(
    {
        "read-only",
        "repetition",
        "social-response",
        "no-durable-state-change",
        "user-cancelled",
    }
)
GAP_STAGES = frozenset({"stop", "notify", "reconciliation"})

_DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_IDENTITY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$")
_EVENT_UID_RE = re.compile(r"^client:[A-Za-z0-9][A-Za-z0-9._:-]{7,154}$")


class TurnMemoryError(ValueError):
    """One fail-closed turn-memory contract violation."""


def _utc_now() -> str:
    return dt.datetime.now(dt.UTC).isoformat().replace("+00:00", "Z")


def _digest(value: object, *, domain: str) -> str:
    payload = domain.encode("utf-8") + b"\x00" + canonical_bytes(value)
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _identity(value: object, name: str) -> str:
    if not isinstance(value, str) or _IDENTITY_RE.fullmatch(value) is None:
        raise TurnMemoryError(f"{name} is invalid")
    return value


def _digest_value(value: object, name: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise TurnMemoryError(f"{name} is invalid")
    return value


def _sha256_value(value: object, name: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise TurnMemoryError(f"{name} is invalid")
    return value


def namespace_fingerprint(*, source_namespace: str, trust_fingerprint: str) -> str:
    """Bind one logical Seed namespace to its existing trust lineage."""

    if not isinstance(source_namespace, str) or not source_namespace.startswith("seed://"):
        raise TurnMemoryError("source namespace is invalid")
    _digest_value(trust_fingerprint, "trust fingerprint")
    return _digest(
        {
            "protocol": "integrity-guardian/turn-memory-namespace/v1",
            "source_namespace": source_namespace,
            "trust_fingerprint": trust_fingerprint,
        },
        domain="turn-memory-namespace-v1",
    )


def _signed_receipt(
    core: dict[str, Any],
    *,
    id_domain: str,
    signer: Ed25519Signer,
) -> dict[str, Any]:
    receipt = deepcopy(core)
    receipt["receipt_id"] = _digest(receipt, domain=id_domain)
    return signer.sign(receipt)


def _verify_receipt(
    receipt: Mapping[str, Any],
    *,
    schema: str,
    protocol: str,
    id_domain: str,
    trusted_key: TrustedKey,
) -> dict[str, Any]:
    candidate = deepcopy(dict(receipt))
    validate(schema, candidate)
    if candidate["protocol"] != protocol:
        raise TurnMemoryError("turn-memory receipt protocol mismatch")
    if candidate["signature"]["key_id"] != trusted_key.key_id or not verify_signature(
        candidate, trusted_key.public_key
    ):
        raise TurnMemoryError("turn-memory receipt signature rejected")
    unsigned = deepcopy(candidate)
    unsigned.pop("signature")
    receipt_id = unsigned.pop("receipt_id")
    if receipt_id != _digest(unsigned, domain=id_domain):
        raise TurnMemoryError("turn-memory receipt identity mismatch")
    return candidate


def verify_turn_registration(
    receipt: Mapping[str, Any], *, trusted_key: TrustedKey
) -> dict[str, Any]:
    return _verify_receipt(
        receipt,
        schema="turn-memory-registration",
        protocol=REGISTRATION_PROTOCOL,
        id_domain="turn-memory-registration-v1",
        trusted_key=trusted_key,
    )


def verify_turn_terminal_receipt(
    receipt: Mapping[str, Any], *, trusted_key: TrustedKey
) -> dict[str, Any]:
    candidate = _verify_receipt(
        receipt,
        schema="turn-memory-terminal-receipt",
        protocol=TERMINAL_PROTOCOL,
        id_domain="turn-memory-terminal-v1",
        trusted_key=trusted_key,
    )
    outcome = candidate["outcome"]
    if outcome == "events":
        if "no_event_reason" in candidate or not candidate.get("events"):
            raise TurnMemoryError("events terminal receipt is incomplete")
    elif outcome == "no-event":
        if candidate.get("no_event_reason") not in NO_EVENT_REASONS or "events" in candidate:
            raise TurnMemoryError("no-event terminal receipt is incomplete")
    else:
        raise TurnMemoryError("turn terminal outcome is invalid")
    return candidate


def verify_turn_gap_receipt(
    receipt: Mapping[str, Any], *, trusted_key: TrustedKey
) -> dict[str, Any]:
    return _verify_receipt(
        receipt,
        schema="turn-memory-gap-receipt",
        protocol=GAP_PROTOCOL,
        id_domain="turn-memory-gap-v1",
        trusted_key=trusted_key,
    )


def normalize_event_references(events: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str]] = set()
    for raw in events:
        event_uid = raw.get("event_uid")
        event_id = raw.get("event_id")
        request_sha256 = raw.get("request_sha256")
        if not isinstance(event_uid, str) or _EVENT_UID_RE.fullmatch(event_uid) is None:
            raise TurnMemoryError("event_uid is invalid")
        if isinstance(event_id, bool) or not isinstance(event_id, int) or event_id < 1:
            raise TurnMemoryError("event_id is invalid")
        _sha256_value(request_sha256, "event request_sha256")
        identity = (event_uid, event_id, request_sha256)
        if identity in seen:
            continue
        seen.add(identity)
        normalized.append(
            {
                "event_uid": event_uid,
                "event_id": event_id,
                "request_sha256": request_sha256,
            }
        )
    normalized.sort(key=lambda item: (item["event_id"], item["event_uid"]))
    if not normalized:
        raise TurnMemoryError("events terminal receipt requires at least one event")
    return normalized


class TurnMemoryStore:
    """SQLite-backed immutable turn registrations, terminal receipts and gaps."""

    def __init__(
        self,
        path: Path,
        *,
        namespace: str,
        signer: Ed25519Signer,
    ) -> None:
        self.path = Path(path)
        self.namespace = _digest_value(namespace, "namespace fingerprint")
        self.signer = signer
        self.trusted_key = TrustedKey(signer.key_id, signer.public_key)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def _initialize(self) -> None:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.path.parent.is_symlink() or self.path.is_symlink():
            raise TurnMemoryError("turn-memory store path is unsafe")
        try:
            self.path.parent.chmod(0o700)
        except OSError:
            pass
        if not self.path.exists():
            try:
                descriptor = os.open(
                    self.path,
                    os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                )
            except FileExistsError:
                pass
            else:
                os.close(descriptor)
        if self.path.is_symlink() or not self.path.is_file():
            raise TurnMemoryError("turn-memory store file is unsafe")
        try:
            self.path.chmod(0o600)
        except OSError:
            pass
        with self._connect() as connection:
            journal_mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
            if str(journal_mode).lower() != "wal":
                raise TurnMemoryError("turn-memory WAL durability is unavailable")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS turn_registrations (
                    registration_id TEXT PRIMARY KEY,
                    namespace_fingerprint TEXT NOT NULL,
                    machine_id TEXT NOT NULL,
                    thread_id TEXT NOT NULL,
                    turn_id TEXT NOT NULL,
                    prompt_sha256 TEXT NOT NULL,
                    receipt_json BLOB NOT NULL,
                    UNIQUE(namespace_fingerprint, machine_id, thread_id, turn_id)
                );
                CREATE TABLE IF NOT EXISTS turn_terminal_receipts (
                    registration_id TEXT PRIMARY KEY REFERENCES turn_registrations(registration_id),
                    request_digest TEXT NOT NULL,
                    receipt_json BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS turn_gap_receipts (
                    receipt_id TEXT PRIMARY KEY,
                    registration_id TEXT NOT NULL REFERENCES turn_registrations(registration_id),
                    request_digest TEXT NOT NULL,
                    receipt_json BLOB NOT NULL,
                    UNIQUE(registration_id, request_digest)
                );
                CREATE TABLE IF NOT EXISTS turn_memory_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )
            expected_metadata = {
                "namespace_fingerprint": self.namespace,
                "signer_key_id": self.signer.key_id,
                "signer_public_key_fingerprint": public_key_fingerprint(
                    self.signer.public_key
                ),
            }
            existing_metadata = dict(
                connection.execute("SELECT key, value FROM turn_memory_metadata").fetchall()
            )
            if existing_metadata:
                if existing_metadata != expected_metadata:
                    raise TurnMemoryError("turn-memory store lineage mismatch")
            else:
                connection.executemany(
                    "INSERT INTO turn_memory_metadata(key, value) VALUES (?, ?)",
                    sorted(expected_metadata.items()),
                )

    @staticmethod
    def _decode(row: sqlite3.Row, column: str = "receipt_json") -> dict[str, Any]:
        value = json.loads(bytes(row[column]))
        if not isinstance(value, dict):
            raise TurnMemoryError("stored turn-memory receipt is invalid")
        return value

    def open_turn(
        self,
        *,
        machine_id: str,
        thread_id: str,
        turn_id: str,
        prompt_sha256: str,
        opened_at: str | None = None,
    ) -> dict[str, Any]:
        identity = {
            "machine_id": _identity(machine_id, "machine_id"),
            "thread_id": _identity(thread_id, "thread_id"),
            "turn_id": _identity(turn_id, "turn_id"),
        }
        prompt = _sha256_value(prompt_sha256, "prompt_sha256")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT * FROM turn_registrations
                WHERE namespace_fingerprint = ? AND machine_id = ? AND thread_id = ? AND turn_id = ?
                """,
                (self.namespace, identity["machine_id"], identity["thread_id"], identity["turn_id"]),
            ).fetchone()
            if row is not None:
                receipt = verify_turn_registration(self._decode(row), trusted_key=self.trusted_key)
                if receipt["prompt_sha256"] != prompt:
                    raise TurnMemoryError("turn identity collides with another prompt")
                connection.commit()
                return {"receipt": receipt, "replayed": True}
            receipt = _signed_receipt(
                {
                    "protocol": REGISTRATION_PROTOCOL,
                    "namespace_fingerprint": self.namespace,
                    "identity": identity,
                    "prompt_sha256": prompt,
                    "opened_at": opened_at or _utc_now(),
                    "terminal_required": True,
                    "production_authority": False,
                },
                id_domain="turn-memory-registration-v1",
                signer=self.signer,
            )
            verify_turn_registration(receipt, trusted_key=self.trusted_key)
            connection.execute(
                """
                INSERT INTO turn_registrations(
                    registration_id, namespace_fingerprint, machine_id, thread_id, turn_id,
                    prompt_sha256, receipt_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    receipt["receipt_id"],
                    self.namespace,
                    identity["machine_id"],
                    identity["thread_id"],
                    identity["turn_id"],
                    prompt,
                    canonical_bytes(receipt),
                ),
            )
            connection.commit()
            return {"receipt": receipt, "replayed": False}

    def close_turn(
        self,
        *,
        registration_id: str,
        outcome: str,
        events: Iterable[Mapping[str, Any]] | None = None,
        no_event_reason: str | None = None,
        closed_at: str | None = None,
    ) -> dict[str, Any]:
        registration = _digest_value(registration_id, "registration_id")
        if outcome == "events":
            normalized_events = normalize_event_references(events or ())
            if no_event_reason is not None:
                raise TurnMemoryError("events outcome cannot contain a no-event reason")
        elif outcome == "no-event":
            if events is not None or no_event_reason not in NO_EVENT_REASONS:
                raise TurnMemoryError("no-event outcome requires one closed reason")
            normalized_events = []
        else:
            raise TurnMemoryError("turn terminal outcome is invalid")
        request = {
            "registration_id": registration,
            "outcome": outcome,
            **({"events": normalized_events} if outcome == "events" else {}),
            **({"no_event_reason": no_event_reason} if outcome == "no-event" else {}),
        }
        request_digest = _digest(request, domain="turn-memory-terminal-request-v1")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            registration_row = connection.execute(
                "SELECT * FROM turn_registrations WHERE registration_id = ?",
                (registration,),
            ).fetchone()
            if registration_row is None:
                raise TurnMemoryError("turn registration does not exist")
            verified_registration = verify_turn_registration(
                self._decode(registration_row), trusted_key=self.trusted_key
            )
            if verified_registration["namespace_fingerprint"] != self.namespace:
                raise TurnMemoryError("turn registration belongs to another namespace")
            existing = connection.execute(
                "SELECT * FROM turn_terminal_receipts WHERE registration_id = ?",
                (registration,),
            ).fetchone()
            if existing is not None:
                receipt = verify_turn_terminal_receipt(
                    self._decode(existing), trusted_key=self.trusted_key
                )
                if existing["request_digest"] != request_digest:
                    raise TurnMemoryError("turn already has a conflicting terminal receipt")
                connection.commit()
                return {"receipt": receipt, "replayed": True}
            core: dict[str, Any] = {
                "protocol": TERMINAL_PROTOCOL,
                "namespace_fingerprint": self.namespace,
                "registration_id": registration,
                "identity": verified_registration["identity"],
                "prompt_sha256": verified_registration["prompt_sha256"],
                "outcome": outcome,
                "closed_at": closed_at or _utc_now(),
                "production_authority": False,
            }
            if outcome == "events":
                core["events"] = normalized_events
            else:
                core["no_event_reason"] = no_event_reason
            receipt = _signed_receipt(
                core,
                id_domain="turn-memory-terminal-v1",
                signer=self.signer,
            )
            verify_turn_terminal_receipt(receipt, trusted_key=self.trusted_key)
            connection.execute(
                """
                INSERT INTO turn_terminal_receipts(registration_id, request_digest, receipt_json)
                VALUES (?, ?, ?)
                """,
                (registration, request_digest, canonical_bytes(receipt)),
            )
            connection.commit()
            return {"receipt": receipt, "replayed": False}

    def observe_gap(
        self,
        *,
        registration_id: str,
        stage: str,
        observed_at: str | None = None,
    ) -> dict[str, Any]:
        registration = _digest_value(registration_id, "registration_id")
        if stage not in GAP_STAGES:
            raise TurnMemoryError("coverage gap stage is invalid")
        request = {"registration_id": registration, "stage": stage}
        request_digest = _digest(request, domain="turn-memory-gap-request-v1")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            registration_row = connection.execute(
                "SELECT * FROM turn_registrations WHERE registration_id = ?",
                (registration,),
            ).fetchone()
            if registration_row is None:
                raise TurnMemoryError("turn registration does not exist")
            terminal = connection.execute(
                "SELECT receipt_json FROM turn_terminal_receipts WHERE registration_id = ?",
                (registration,),
            ).fetchone()
            if terminal is not None:
                receipt = verify_turn_terminal_receipt(
                    self._decode(terminal), trusted_key=self.trusted_key
                )
                connection.commit()
                return {"terminal_receipt": receipt, "gap_recorded": False, "replayed": False}
            existing = connection.execute(
                """
                SELECT * FROM turn_gap_receipts
                WHERE registration_id = ? AND request_digest = ?
                """,
                (registration, request_digest),
            ).fetchone()
            if existing is not None:
                receipt = verify_turn_gap_receipt(self._decode(existing), trusted_key=self.trusted_key)
                connection.commit()
                return {"receipt": receipt, "gap_recorded": True, "replayed": True}
            verified_registration = verify_turn_registration(
                self._decode(registration_row), trusted_key=self.trusted_key
            )
            receipt = _signed_receipt(
                {
                    "protocol": GAP_PROTOCOL,
                    "namespace_fingerprint": self.namespace,
                    "registration_id": registration,
                    "identity": verified_registration["identity"],
                    "prompt_sha256": verified_registration["prompt_sha256"],
                    "stage": stage,
                    "reason": "terminal-receipt-missing",
                    "observed_at": observed_at or _utc_now(),
                    "terminal": False,
                    "production_authority": False,
                },
                id_domain="turn-memory-gap-v1",
                signer=self.signer,
            )
            verify_turn_gap_receipt(receipt, trusted_key=self.trusted_key)
            connection.execute(
                """
                INSERT INTO turn_gap_receipts(receipt_id, registration_id, request_digest, receipt_json)
                VALUES (?, ?, ?, ?)
                """,
                (receipt["receipt_id"], registration, request_digest, canonical_bytes(receipt)),
            )
            connection.commit()
            return {"receipt": receipt, "gap_recorded": True, "replayed": False}

    def coverage(
        self,
        *,
        machine_id: str | None = None,
        thread_id: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
            raise TurnMemoryError("coverage limit is invalid")
        clauses = ["r.namespace_fingerprint = ?"]
        parameters: list[Any] = [self.namespace]
        if machine_id is not None:
            clauses.append("r.machine_id = ?")
            parameters.append(_identity(machine_id, "machine_id"))
        if thread_id is not None:
            clauses.append("r.thread_id = ?")
            parameters.append(_identity(thread_id, "thread_id"))
        where = " AND ".join(clauses)
        with self._connect() as connection:
            rows = connection.execute(
                f"""
                SELECT r.rowid AS registration_order, r.registration_id, r.machine_id,
                       r.thread_id, r.turn_id, r.receipt_json AS registration_receipt,
                       t.receipt_json AS terminal_receipt,
                       (
                           SELECT g.receipt_json FROM turn_gap_receipts g
                           WHERE g.registration_id = r.registration_id
                           ORDER BY g.rowid DESC LIMIT 1
                       ) AS latest_gap_receipt
                FROM turn_registrations r
                LEFT JOIN turn_terminal_receipts t USING(registration_id)
                WHERE {where}
                ORDER BY r.rowid DESC
                """,
                parameters,
            ).fetchall()
        counts = {"registered": 0, "terminal": 0, "events": 0, "no_event": 0, "unresolved": 0}
        unresolved: list[dict[str, Any]] = []
        for row in rows:
            registration_receipt = verify_turn_registration(
                json.loads(bytes(row["registration_receipt"])),
                trusted_key=self.trusted_key,
            )
            identity = registration_receipt["identity"]
            if (
                registration_receipt["receipt_id"] != row["registration_id"]
                or registration_receipt["namespace_fingerprint"] != self.namespace
                or identity["machine_id"] != row["machine_id"]
                or identity["thread_id"] != row["thread_id"]
                or identity["turn_id"] != row["turn_id"]
            ):
                raise TurnMemoryError("turn-memory registration index mismatch")
            counts["registered"] += 1
            if row["terminal_receipt"] is not None:
                terminal_receipt = verify_turn_terminal_receipt(
                    json.loads(bytes(row["terminal_receipt"])),
                    trusted_key=self.trusted_key,
                )
                if terminal_receipt["registration_id"] != row["registration_id"]:
                    raise TurnMemoryError("turn-memory terminal index mismatch")
                counts["terminal"] += 1
                counts["events" if terminal_receipt["outcome"] == "events" else "no_event"] += 1
                continue
            counts["unresolved"] += 1
            latest_gap_receipt_id = None
            if row["latest_gap_receipt"] is not None:
                gap_receipt = verify_turn_gap_receipt(
                    json.loads(bytes(row["latest_gap_receipt"])),
                    trusted_key=self.trusted_key,
                )
                if gap_receipt["registration_id"] != row["registration_id"]:
                    raise TurnMemoryError("turn-memory gap index mismatch")
                latest_gap_receipt_id = gap_receipt["receipt_id"]
            if len(unresolved) < limit:
                unresolved.append(
                    {
                        "registration_id": row["registration_id"],
                        "machine_id": row["machine_id"],
                        "thread_id": row["thread_id"],
                        "turn_id": row["turn_id"],
                        "latest_gap_receipt_id": latest_gap_receipt_id,
                    }
                )
        return {
            "protocol": COVERAGE_PROTOCOL,
            "namespace_fingerprint": self.namespace,
            "counts": counts,
            "unresolved": unresolved,
            "returned_count": len(unresolved),
            "production_authority": False,
        }
