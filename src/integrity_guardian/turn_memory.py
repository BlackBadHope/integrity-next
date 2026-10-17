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
from functools import cache
from collections.abc import Iterable, Mapping
from copy import deepcopy
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes
from .schemas import FORMAT_CHECKER, validate
from jsonschema import Draft202012Validator
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


class _ClosingConnection(sqlite3.Connection):
    def __exit__(self, *args):
        try:
            return super().__exit__(*args)
        finally:
            self.close()


@cache
def _legacy_validator(kind: str) -> Draft202012Validator:
    path = Path(__file__).with_name('schema') / 'turn-memory-legacy-v1' / f'turn-memory-{kind}.schema.json'
    schema = json.loads(path.read_text(encoding='utf-8'))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FORMAT_CHECKER)


class TurnMemoryStore:
    """SQLite-backed immutable turn registrations, terminal receipts and gaps."""

    def __init__(
        self,
        path: Path,
        *,
        namespace: str,
        signer: Ed25519Signer,
        identity_profile: str = 'legacy-v1',
        create: bool = True,
    ) -> None:
        self.path = Path(path)
        self.namespace = _digest_value(namespace, "namespace fingerprint")
        self.signer = signer
        self.trusted_key = TrustedKey(signer.key_id, signer.public_key)
        if identity_profile not in {'legacy-v1', 'native-intent-v1'}:
            raise TurnMemoryError('turn-memory identity profile is invalid')
        self.identity_profile = identity_profile
        if not isinstance(create, bool):
            raise TurnMemoryError('turn-memory create flag is invalid')
        if create:
            self._initialize()
        else:
            self._validate_existing()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path.absolute().as_uri() + '?mode=rw', uri=True,
            timeout=5.0, isolation_level=None, factory=_ClosingConnection)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def _read_connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path.absolute().as_uri() + '?mode=ro', uri=True,
            timeout=5.0, isolation_level=None, factory=_ClosingConnection)
        connection.row_factory = sqlite3.Row
        connection.execute('PRAGMA trusted_schema = OFF')
        connection.execute('PRAGMA busy_timeout = 5000')
        return connection

    def _expected_metadata(self) -> dict[str, str]:
        result = {'namespace_fingerprint':self.namespace,'signer_key_id':self.signer.key_id,
            'signer_public_key_fingerprint':public_key_fingerprint(self.signer.public_key)}
        if self.identity_profile == 'native-intent-v1':
            result['identity_profile'] = self.identity_profile
        return result

    def _validate_existing(self) -> None:
        if self.path.parent.is_symlink() or self.path.is_symlink() or not self.path.is_file():
            raise TurnMemoryError('turn-memory existing profile is unavailable')
        with self._read_connection() as connection:
            has_intent = 'intent_id' in {r[1] for r in connection.execute('PRAGMA table_info(turn_registrations)')}
            if has_intent != (self.identity_profile == 'native-intent-v1'):
                raise TurnMemoryError('turn-memory existing identity profile mismatch')
            known = dict(connection.execute('SELECT key,value FROM turn_memory_metadata').fetchall())
            if known != self._expected_metadata():
                raise TurnMemoryError('turn-memory store lineage mismatch')
            if str(connection.execute('PRAGMA journal_mode').fetchone()[0]).lower() != 'wal':
                raise TurnMemoryError('turn-memory WAL durability is unavailable')
            if self.identity_profile == 'native-intent-v1':
                self._creation_policy(connection)

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
            intent_column = "intent_id TEXT NOT NULL," if self.identity_profile == 'native-intent-v1' else ''
            unique_columns = ', intent_id' if self.identity_profile == 'native-intent-v1' else ''
            policy_table = '''CREATE TABLE IF NOT EXISTS turn_memory_creation_policy
                (generation INTEGER PRIMARY KEY, receipt_json BLOB NOT NULL);''' if self.identity_profile == 'native-intent-v1' else ''
            connection.executescript(
                f"""
                BEGIN IMMEDIATE;
                CREATE TABLE IF NOT EXISTS turn_registrations (
                    registration_id TEXT PRIMARY KEY,
                    namespace_fingerprint TEXT NOT NULL,
                    machine_id TEXT NOT NULL,
                    thread_id TEXT NOT NULL,
                    turn_id TEXT NOT NULL,
                    {intent_column}
                    prompt_sha256 TEXT NOT NULL,
                    receipt_json BLOB NOT NULL,
                    UNIQUE(namespace_fingerprint, machine_id, thread_id, turn_id{unique_columns})
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
                {policy_table}
                """
            )
            has_intent = 'intent_id' in {row[1] for row in connection.execute('PRAGMA table_info(turn_registrations)')}
            if has_intent != (self.identity_profile == 'native-intent-v1'):
                raise TurnMemoryError('turn-memory identity profile does not match physical schema; automatic migration is forbidden')
            expected_metadata = self._expected_metadata()
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
            if self.identity_profile == 'native-intent-v1':
                policy_rows = connection.execute('SELECT COUNT(*) FROM turn_memory_creation_policy').fetchone()[0]
                if not policy_rows:
                    if connection.execute('SELECT COUNT(*) FROM turn_registrations').fetchone()[0]:
                        raise TurnMemoryError('existing native history has no verified creation policy')
                    policy = self._sign_creation_policy('enabled',0)
                    connection.execute('INSERT INTO turn_memory_creation_policy VALUES (?,?)',(0,canonical_bytes(policy)))
                self._creation_policy(connection)
            connection.commit()

    def _sign_creation_policy(self, mode: str, generation: int) -> dict[str, Any]:
        return _signed_receipt({'protocol':'integrity-guardian/turn-memory-creation-policy/v1',
            'namespace_fingerprint':self.namespace,'mode':mode,'generation':generation,
            'updated_at':_utc_now(),'production_authority':False},
            id_domain='turn-memory-creation-policy-v1',signer=self.signer)

    def _creation_policy(self, connection: sqlite3.Connection) -> dict[str, Any]:
        if self.identity_profile != 'native-intent-v1':
            raise TurnMemoryError('legacy profile has no modern creation policy')
        row = connection.execute('SELECT generation,receipt_json FROM turn_memory_creation_policy ORDER BY generation DESC LIMIT 1').fetchone()
        if row is None:raise TurnMemoryError('native creation policy is unavailable')
        receipt = _verify_receipt(self._decode(row),schema='turn-memory-creation-policy',
            protocol='integrity-guardian/turn-memory-creation-policy/v1',
            id_domain='turn-memory-creation-policy-v1',trusted_key=self.trusted_key)
        if receipt['namespace_fingerprint'] != self.namespace or receipt['generation'] != row['generation']:
            raise TurnMemoryError('native creation policy lineage mismatch')
        return receipt

    def creation_policy(self) -> dict[str, Any]:
        with self._read_connection() as connection:return self._creation_policy(connection)

    def set_creation_policy(self, mode: str, *, expected_receipt_id: str) -> dict[str, Any]:
        """Operator-only CAS; deliberately absent from the public MCP catalog."""
        if mode not in {'enabled','rollback-read-close'}:raise TurnMemoryError('native creation policy mode is invalid')
        expected = _digest_value(expected_receipt_id,'expected creation policy receipt')
        with self._connect() as connection:
            connection.execute('BEGIN IMMEDIATE')
            previous = self._creation_policy(connection)
            if previous['receipt_id'] != expected:raise TurnMemoryError('native creation policy CAS changed')
            if previous['mode']==mode:
                connection.commit();return previous
            result=self._sign_creation_policy(mode,previous['generation']+1)
            connection.execute('INSERT INTO turn_memory_creation_policy VALUES (?,?)',
                (result['generation'],canonical_bytes(result)))
            connection.commit();return result

    @staticmethod
    def _decode(row: sqlite3.Row, column: str = "receipt_json") -> dict[str, Any]:
        value = json.loads(bytes(row[column]))
        if not isinstance(value, dict):
            raise TurnMemoryError("stored turn-memory receipt is invalid")
        return value

    def _verify_profile_receipt(self, kind: str, receipt: Mapping[str, Any]) -> dict[str, Any]:
        verifier = {'registration':verify_turn_registration,'terminal-receipt':verify_turn_terminal_receipt,
            'gap-receipt':verify_turn_gap_receipt}[kind]
        verified = verifier(receipt, trusted_key=self.trusted_key)
        if self.identity_profile == 'legacy-v1':
            _legacy_validator(kind).validate(verified)
        else:
            identity = verified['identity']
            if (re.fullmatch(r'intent:[a-f0-9]{64}',identity.get('intent_id','')) is None
                    or re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',identity['turn_id']) is None
                    or re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',identity['thread_id']) is None):
                raise TurnMemoryError('native identity profile receipt mismatch')
        return verified

    def find_registration(self, registration_id: str) -> dict[str, Any] | None:
        registration = _digest_value(registration_id,'registration_id')
        with self._read_connection() as connection:
            row = connection.execute('SELECT * FROM turn_registrations WHERE registration_id=?',(registration,)).fetchone()
        if row is None:return None
        return self._verify_registration_row(row)

    def find_terminal(self, registration_id: str) -> dict[str, Any] | None:
        registration = _digest_value(registration_id, "registration_id")
        with self._read_connection() as connection:
            row = connection.execute("SELECT * FROM turn_registrations WHERE registration_id=?", (registration,)).fetchone()
            terminal = connection.execute("SELECT * FROM turn_terminal_receipts WHERE registration_id=?", (registration,)).fetchone()
        if row is None:
            raise TurnMemoryError("turn registration does not exist")
        if terminal is None:
            return None
        verified = self._verify_registration_row(row)
        receipt = self._verify_profile_receipt("terminal-receipt", self._decode(terminal))
        self._verify_join(receipt, verified)
        return receipt

    def _verify_registration_row(self, row: sqlite3.Row) -> dict[str, Any]:
        receipt = self._verify_profile_receipt('registration',self._decode(row))
        identity = receipt['identity']
        expected_intent = row['intent_id'] if self.identity_profile == 'native-intent-v1' else ''
        if (receipt['receipt_id'] != row['registration_id'] or receipt['namespace_fingerprint'] != self.namespace
                or any(identity[key] != row[key] for key in ('machine_id','thread_id','turn_id'))
                or identity.get('intent_id','') != expected_intent):
            raise TurnMemoryError('turn-memory registration index mismatch')
        return receipt

    def _verify_join(self, receipt: Mapping[str, Any], registration: Mapping[str, Any]) -> None:
        if (receipt['registration_id'] != registration['receipt_id']
                or receipt['namespace_fingerprint'] != self.namespace
                or receipt['identity'] != registration['identity']
                or receipt['prompt_sha256'] != registration['prompt_sha256']):
            raise TurnMemoryError('turn-memory receipt registration join mismatch')

    def open_turn(
        self,
        *,
        machine_id: str,
        thread_id: str,
        turn_id: str,
        prompt_sha256: str,
        intent_id: str | None = None,
        opened_at: str | None = None,
        allow_create: bool = True,
    ) -> dict[str, Any]:
        identity = {
            "machine_id": _identity(machine_id, "machine_id"),
            "thread_id": _identity(thread_id, "thread_id"),
            "turn_id": _identity(turn_id, "turn_id"),
        }
        intent = ''
        if not isinstance(allow_create,bool):raise TurnMemoryError('turn-memory creation mode is invalid')
        if (intent_id is not None) != (self.identity_profile == 'native-intent-v1'):
            raise TurnMemoryError('turn-memory open arguments do not match identity profile')
        if intent_id is not None:
            if not isinstance(intent_id, str) or re.fullmatch(r'intent:[a-f0-9]{64}', intent_id) is None:
                raise TurnMemoryError('intent_id is invalid')
            if re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', turn_id) is None:
                raise TurnMemoryError('native turn_id is invalid')
            if re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', thread_id) is None:
                raise TurnMemoryError('native thread_id is invalid')
            intent = intent_id
            identity['intent_id'] = intent
        prompt = _sha256_value(prompt_sha256, "prompt_sha256")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            intent_clause = ' AND intent_id = ?' if self.identity_profile == 'native-intent-v1' else ''
            row = connection.execute(
                f"""
                SELECT * FROM turn_registrations
                WHERE namespace_fingerprint = ? AND machine_id = ? AND thread_id = ? AND turn_id = ?{intent_clause}
                """,
                (self.namespace, identity["machine_id"], identity["thread_id"], identity["turn_id"]) + ((intent,) if intent_clause else ()),
            ).fetchone()
            if row is not None:
                receipt = self._verify_registration_row(row)
                if receipt["prompt_sha256"] != prompt:
                    raise TurnMemoryError("turn identity collides with another prompt")
                connection.commit()
                return {"receipt": receipt, "replayed": True}
            if not allow_create:
                raise TurnMemoryError('new native-intent registrations are disabled; exact replay remains available')
            if self.identity_profile == 'native-intent-v1' and self._creation_policy(connection)['mode'] != 'enabled':
                raise TurnMemoryError('new native-intent registrations are disabled by shared rollback fence')
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
            self._verify_profile_receipt('registration',receipt)
            intent_insert = ', intent_id' if intent_clause else ''
            values = ', ?' if intent_clause else ''
            connection.execute(
                f"""
                INSERT INTO turn_registrations(
                    registration_id, namespace_fingerprint, machine_id, thread_id, turn_id,
                    prompt_sha256, receipt_json{intent_insert}
                ) VALUES (?, ?, ?, ?, ?, ?, ?{values})
                """,
                (
                    receipt["receipt_id"],
                    self.namespace,
                    identity["machine_id"],
                    identity["thread_id"],
                    identity["turn_id"],
                    prompt,
                    canonical_bytes(receipt),
                ) + ((intent,) if intent_clause else ()),
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
            verified_registration = self._verify_registration_row(registration_row)
            if verified_registration["namespace_fingerprint"] != self.namespace:
                raise TurnMemoryError("turn registration belongs to another namespace")
            existing = connection.execute(
                "SELECT * FROM turn_terminal_receipts WHERE registration_id = ?",
                (registration,),
            ).fetchone()
            if existing is not None:
                receipt = self._verify_profile_receipt('terminal-receipt',self._decode(existing))
                self._verify_join(receipt,verified_registration)
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
            self._verify_profile_receipt('terminal-receipt',receipt)
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
            verified_registration = self._verify_registration_row(registration_row)
            terminal = connection.execute(
                "SELECT receipt_json FROM turn_terminal_receipts WHERE registration_id = ?",
                (registration,),
            ).fetchone()
            if terminal is not None:
                receipt = self._verify_profile_receipt('terminal-receipt',self._decode(terminal))
                self._verify_join(receipt,verified_registration)
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
                receipt = self._verify_profile_receipt('gap-receipt',self._decode(existing))
                self._verify_join(receipt,verified_registration)
                connection.commit()
                return {"receipt": receipt, "gap_recorded": True, "replayed": True}
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
            self._verify_profile_receipt('gap-receipt',receipt)
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
        intent_projection = 'r.intent_id' if self.identity_profile == 'native-intent-v1' else "'' AS intent_id"
        with self._read_connection() as connection:
            if self.identity_profile == 'native-intent-v1':self._creation_policy(connection)
            rows = connection.execute(
                f"""
                SELECT r.rowid AS registration_order, r.registration_id, r.machine_id,
                       r.thread_id, r.turn_id, {intent_projection}, r.receipt_json AS registration_receipt,
                       t.receipt_json AS terminal_receipt, t.request_digest AS terminal_request_digest,
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
        receipt_sample: list[dict[str, Any]] = []
        sample_budget = 262_144
        size_limited = False
        sample_header = {"protocol":"integrity-guardian/turn-memory-receipt-sample/v1",
            "receipts":[],"limit":limit,"returned_count":0,"complete":False,"has_more":False,
            "size_limited":False,"byte_budget":sample_budget,
            "absence_is_retry_authority":False,"canonical_writes":0}
        for row in rows:
            registration_receipt = self._verify_profile_receipt('registration',json.loads(bytes(row['registration_receipt'])))
            identity = registration_receipt["identity"]
            if (
                registration_receipt["receipt_id"] != row["registration_id"]
                or registration_receipt["namespace_fingerprint"] != self.namespace
                or identity["machine_id"] != row["machine_id"]
                or identity["thread_id"] != row["thread_id"]
                or identity["turn_id"] != row["turn_id"]
                or identity.get('intent_id', '') != row['intent_id']
            ):
                raise TurnMemoryError("turn-memory registration index mismatch")
            counts["registered"] += 1
            if row["terminal_receipt"] is not None:
                terminal_receipt = self._verify_profile_receipt('terminal-receipt',json.loads(bytes(row['terminal_receipt'])))
                if (terminal_receipt['registration_id'] != row['registration_id']
                        or terminal_receipt['namespace_fingerprint'] != self.namespace
                        or terminal_receipt['identity'] != identity
                        or terminal_receipt['prompt_sha256'] != registration_receipt['prompt_sha256']):
                    raise TurnMemoryError("turn-memory terminal index mismatch")
                request = {"registration_id":row["registration_id"], "outcome":terminal_receipt["outcome"],
                    **({"events":terminal_receipt["events"]} if terminal_receipt["outcome"] == "events" else {}),
                    **({"no_event_reason":terminal_receipt["no_event_reason"]} if terminal_receipt["outcome"] == "no-event" else {})}
                request_digest = _digest(request, domain="turn-memory-terminal-request-v1")
                if row["terminal_request_digest"] != request_digest:
                    raise TurnMemoryError("terminal request digest mismatch")
                if len(receipt_sample) < limit:
                    entry = {"registration_id":row["registration_id"],
                        "registration_receipt":registration_receipt,"terminal_receipt":terminal_receipt,
                        "terminal_request_digest":request_digest,"gap_receipt":None,"status":"closed"}
                    proposed = {**sample_header,"receipts":receipt_sample+[entry],"returned_count":len(receipt_sample)+1}
                    if len(canonical_bytes(proposed)) <= sample_budget: receipt_sample.append(entry)
                    else: size_limited = True
                counts["terminal"] += 1
                counts["events" if terminal_receipt["outcome"] == "events" else "no_event"] += 1
                continue
            counts["unresolved"] += 1
            latest_gap_receipt_id = None
            gap_receipt = None
            if row["latest_gap_receipt"] is not None:
                gap_receipt = self._verify_profile_receipt('gap-receipt',json.loads(bytes(row['latest_gap_receipt'])))
                if (gap_receipt['registration_id'] != row['registration_id']
                        or gap_receipt['namespace_fingerprint'] != self.namespace
                        or gap_receipt['identity'] != identity
                        or gap_receipt['prompt_sha256'] != registration_receipt['prompt_sha256']):
                    raise TurnMemoryError("turn-memory gap index mismatch")
                latest_gap_receipt_id = gap_receipt["receipt_id"]
            if len(receipt_sample) < limit:
                entry = {"registration_id":row["registration_id"],
                    "registration_receipt":registration_receipt,"terminal_receipt":None,
                    "terminal_request_digest":None,"gap_receipt":gap_receipt,"status":"open"}
                proposed = {**sample_header,"receipts":receipt_sample+[entry],"returned_count":len(receipt_sample)+1}
                if len(canonical_bytes(proposed)) <= sample_budget: receipt_sample.append(entry)
                else: size_limited = True
            if len(unresolved) < limit:
                unresolved.append(
                    {
                        "registration_id": row["registration_id"],
                        "machine_id": row["machine_id"],
                        "thread_id": row["thread_id"],
                        "turn_id": row["turn_id"],
                        **({'intent_id':row['intent_id']} if row['intent_id'] else {}),
                        "latest_gap_receipt_id": latest_gap_receipt_id,
                    }
                )
        return {
            "protocol": COVERAGE_PROTOCOL,
            "namespace_fingerprint": self.namespace,
            "counts": counts,
            "unresolved": unresolved,
            "returned_count": len(unresolved),
            "receipt_sample":{"protocol":"integrity-guardian/turn-memory-receipt-sample/v1",
                "receipts":receipt_sample,"limit":limit,"returned_count":len(receipt_sample),
                "complete":counts["registered"] == len(receipt_sample),"has_more":counts["registered"] > len(receipt_sample),
                "size_limited":size_limited,"byte_budget":sample_budget,
                "absence_is_retry_authority":False,"canonical_writes":0},
            "production_authority": False,
        }
