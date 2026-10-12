"""Durable PPv4 dialogue liveness with finite, authority-free batons.

Transport turns, claim batons, conversations and work items are independent
state machines.  Closing a baton never completes its work item implicitly.  A
turn may be sealed only after every baton it processed has one durable outcome:
another wake, an event wait, a blocked work item, a proved completion, or an
owner STOP.

The store is a local SQLite linearization boundary.  It does not deliver wake
events and it grants no execution or production authority.  A scheduler may
consume a pending wake to create one new finite baton, but any authority for
that baton must be supplied afresh and is never copied from its predecessor.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import sqlite3
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
from typing import Any

from .agent_handoff_custody import (
    AgentHandoffCustodyError,
    open_private_sqlite_connection,
)
from .canonical import canonical_bytes
from .schemas import validate
from .signing import Ed25519Signer, TrustedKey, public_key_fingerprint, verify_signature

TRANSITION_PROTOCOL = "integrity-guardian/perpetual-dialogue-transition-receipt/v1"
SNAPSHOT_PROTOCOL = "integrity-guardian/perpetual-dialogue-snapshot/v1"
SCHEMA_VERSION = 1

CONVERSATION_STATES = frozenset(
    {"ACTIVE", "IDLE", "THROTTLED", "PAUSED", "DRAINING", "STOPPED"}
)
WORK_STATES = frozenset({"OPEN", "BLOCKED", "COMPLETE", "CANCELLED"})
BATON_STATES = frozenset({"OPEN", "CLOSED", "CANCELLED"})
WAKE_STATES = frozenset({"PENDING", "WAITING", "LEASED", "CONSUMED", "CANCELLED"})
BATON_DISPOSITIONS = frozenset({"CONTINUE", "WAIT", "HOLD", "WORK_COMPLETE"})
TRANSITION_KINDS = frozenset(
    {
        "conversation-opened",
        "work-opened",
        "baton-issued",
        "baton-closed",
        "wake-admitted",
        "wake-claimed",
        "wake-consumed",
        "conversation-control",
        "turn-exit-sealed",
    }
)

_DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
_IDENTITY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$")
_TENANT_RE = re.compile(r"^tenant:[A-Za-z0-9][A-Za-z0-9._:/-]{0,248}$")


class PerpetualDialogueError(ValueError):
    """One fail-closed PPv4 dialogue contract violation."""


def _utc_now() -> str:
    return dt.datetime.now(dt.UTC).isoformat().replace("+00:00", "Z")


def _digest(value: object, *, domain: str) -> str:
    payload = domain.encode("utf-8") + b"\x00" + canonical_bytes(value)
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _identity(value: object, name: str) -> str:
    if not isinstance(value, str) or _IDENTITY_RE.fullmatch(value) is None:
        raise PerpetualDialogueError(f"{name} is invalid")
    return value


def _tenant(value: object) -> str:
    if not isinstance(value, str) or _TENANT_RE.fullmatch(value) is None:
        raise PerpetualDialogueError("tenant_id is invalid")
    return value


def _digest_value(value: object, name: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise PerpetualDialogueError(f"{name} is invalid")
    return value


def _optional_digest(value: object, name: str) -> str | None:
    if value is None:
        return None
    return _digest_value(value, name)


def _time(value: object, name: str) -> dt.datetime:
    if not isinstance(value, str):
        raise PerpetualDialogueError(f"{name} is invalid")
    try:
        parsed = dt.datetime.fromisoformat(value)
    except ValueError as exc:
        raise PerpetualDialogueError(f"{name} is invalid") from exc
    if parsed.tzinfo is None:
        raise PerpetualDialogueError(f"{name} is invalid")
    return parsed.astimezone(dt.UTC)


def _participants(values: Iterable[str]) -> list[str]:
    normalized = sorted({_identity(value, "participant_id") for value in values})
    if not 2 <= len(normalized) <= 16:
        raise PerpetualDialogueError("conversation requires 2 to 16 unique participants")
    return normalized


def verify_perpetual_dialogue_transition(
    receipt: Mapping[str, Any], *, trusted_key: TrustedKey
) -> dict[str, Any]:
    """Verify one signed transition and its content-derived identity."""

    candidate = deepcopy(dict(receipt))
    validate("perpetual-dialogue-transition-receipt", candidate)
    if candidate["protocol"] != TRANSITION_PROTOCOL:
        raise PerpetualDialogueError("dialogue transition protocol mismatch")
    if candidate["transition_kind"] not in TRANSITION_KINDS:
        raise PerpetualDialogueError("dialogue transition kind is invalid")
    if candidate["signature"]["key_id"] != trusted_key.key_id or not verify_signature(
        candidate, trusted_key.public_key
    ):
        raise PerpetualDialogueError("dialogue transition signature rejected")
    unsigned = deepcopy(candidate)
    unsigned.pop("signature")
    receipt_id = unsigned.pop("receipt_id")
    if receipt_id != _digest(unsigned, domain="perpetual-dialogue-transition-v1"):
        raise PerpetualDialogueError("dialogue transition identity mismatch")
    return candidate


def map_legacy_ppv31_terminal(message: Mapping[str, Any]) -> dict[str, Any]:
    """Map legacy ``lifecycle=CLOSED`` to baton terminality only.

    PPv3.1 had no independent conversation or work-item state.  Importing its
    terminal marker as task completion would repeat the defect that PPv4 fixes.
    """

    lifecycle = message.get("lifecycle")
    if lifecycle != "CLOSED":
        raise PerpetualDialogueError("legacy PPv3.1 lifecycle is not terminal")
    return {
        "protocol": "integrity-guardian/ppv31-terminal-mapping/v1",
        "legacy_lifecycle": "CLOSED",
        "baton_state": "CLOSED",
        "work_state": "OPEN",
        "conversation_state": "ACTIVE",
        "completion_inferred": False,
        "production_authority": False,
    }


class PerpetualDialogueStore:
    """SQLite-backed PPv4 conversation, work, baton and wake state."""

    def __init__(self, path: Path, *, tenant_id: str, signer: Ed25519Signer) -> None:
        self.path = Path(path)
        self.tenant_id = _tenant(tenant_id)
        self.signer = signer
        self.trusted_key = TrustedKey(signer.key_id, signer.public_key)
        self._initialize()

    @contextmanager
    def _connect(self, *, create: bool = False) -> Iterator[sqlite3.Connection]:
        try:
            with open_private_sqlite_connection(
                self.path, create=create
            ) as connection:
                yield connection
        except AgentHandoffCustodyError as exc:
            raise PerpetualDialogueError("dialogue store custody rejected") from exc

    def _initialize(self) -> None:
        create = not self.path.exists()
        with self._connect(create=create) as connection:
            schema_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            user_tables = {
                row[0]
                for row in connection.execute(
                    """
                    SELECT name FROM sqlite_master
                    WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                    """
                ).fetchall()
            }
            if schema_version == 0:
                if user_tables:
                    raise PerpetualDialogueError(
                        "unversioned dialogue store requires an explicit migration"
                    )
                connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS dialogue_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS conversations (
                    conversation_id TEXT PRIMARY KEY,
                    participants_json BLOB NOT NULL,
                    status TEXT NOT NULL,
                    epoch INTEGER NOT NULL,
                    fence INTEGER NOT NULL,
                    control_generation INTEGER NOT NULL,
                    sequence INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS work_items (
                    work_item_id TEXT PRIMARY KEY,
                    conversation_id TEXT NOT NULL REFERENCES conversations(conversation_id),
                    claim_digest TEXT NOT NULL,
                    status TEXT NOT NULL,
                    fence INTEGER NOT NULL,
                    completion_digest TEXT,
                    blocker_digest TEXT
                );
                CREATE TABLE IF NOT EXISTS batons (
                    baton_id TEXT PRIMARY KEY,
                    conversation_id TEXT NOT NULL REFERENCES conversations(conversation_id),
                    work_item_id TEXT NOT NULL REFERENCES work_items(work_item_id),
                    baton_sequence INTEGER NOT NULL,
                    parent_baton_id TEXT REFERENCES batons(baton_id),
                    sender_id TEXT NOT NULL,
                    recipient_id TEXT NOT NULL,
                    processing_turn_id TEXT NOT NULL,
                    claim_digest TEXT NOT NULL,
                    authority_digest TEXT,
                    status TEXT NOT NULL,
                    result_digest TEXT,
                    disposition TEXT,
                    close_receipt_id TEXT,
                    UNIQUE(conversation_id, work_item_id, baton_sequence)
                );
                CREATE UNIQUE INDEX IF NOT EXISTS one_open_baton_per_work
                    ON batons(work_item_id) WHERE status = 'OPEN';
                CREATE TABLE IF NOT EXISTS continuation_checkpoints (
                    checkpoint_id TEXT PRIMARY KEY,
                    conversation_id TEXT NOT NULL REFERENCES conversations(conversation_id),
                    work_item_id TEXT NOT NULL REFERENCES work_items(work_item_id),
                    source_baton_id TEXT NOT NULL UNIQUE REFERENCES batons(baton_id),
                    expected_fence INTEGER NOT NULL,
                    state_digest TEXT NOT NULL,
                    outstanding_work_digest TEXT NOT NULL,
                    required_scope_digest TEXT NOT NULL,
                    authority_required INTEGER NOT NULL,
                    wake_budget INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS wake_outbox (
                    wake_id TEXT PRIMARY KEY,
                    conversation_id TEXT NOT NULL REFERENCES conversations(conversation_id),
                    work_item_id TEXT NOT NULL REFERENCES work_items(work_item_id),
                    source_baton_id TEXT NOT NULL REFERENCES batons(baton_id),
                    checkpoint_id TEXT NOT NULL REFERENCES continuation_checkpoints(checkpoint_id),
                    target_agent_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    trigger_digest TEXT,
                    admitted_event_digest TEXT,
                    next_baton_id TEXT REFERENCES batons(baton_id),
                    wake_budget_remaining INTEGER NOT NULL,
                    lease_holder TEXT,
                    lease_fence INTEGER,
                    lease_expires_at TEXT
                );
                CREATE UNIQUE INDEX IF NOT EXISTS one_live_wake_per_work
                    ON wake_outbox(work_item_id)
                    WHERE status IN ('PENDING', 'WAITING', 'LEASED');
                CREATE TABLE IF NOT EXISTS turn_exits (
                    conversation_id TEXT NOT NULL REFERENCES conversations(conversation_id),
                    agent_id TEXT NOT NULL,
                    turn_id TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    receipt_id TEXT,
                    PRIMARY KEY(conversation_id, agent_id, turn_id)
                );
                CREATE TABLE IF NOT EXISTS dialogue_transitions (
                    receipt_id TEXT PRIMARY KEY,
                    conversation_id TEXT NOT NULL REFERENCES conversations(conversation_id),
                    sequence INTEGER NOT NULL,
                    transition_kind TEXT NOT NULL,
                    subject_id TEXT NOT NULL,
                    request_digest TEXT NOT NULL UNIQUE,
                    receipt_json BLOB NOT NULL,
                    UNIQUE(conversation_id, sequence)
                );
                """
                )
                connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            elif schema_version != SCHEMA_VERSION:
                raise PerpetualDialogueError("dialogue store schema version is unsupported")
            self._assert_schema(connection)
            expected_metadata = {
                "schema_version": str(SCHEMA_VERSION),
                "tenant_id": self.tenant_id,
                "signer_key_id": self.signer.key_id,
                "signer_public_key_fingerprint": public_key_fingerprint(
                    self.signer.public_key
                ),
                "protocol": "integrity-guardian/perpetual-dialogue-store/v1",
            }
            existing_metadata = dict(
                connection.execute("SELECT key, value FROM dialogue_metadata").fetchall()
            )
            if existing_metadata:
                if existing_metadata != expected_metadata:
                    raise PerpetualDialogueError("dialogue store lineage mismatch")
            else:
                connection.executemany(
                    "INSERT INTO dialogue_metadata(key, value) VALUES (?, ?)",
                    sorted(expected_metadata.items()),
                )

    @staticmethod
    def _assert_schema(connection: sqlite3.Connection) -> None:
        expected_tables = {
            "batons",
            "continuation_checkpoints",
            "conversations",
            "dialogue_metadata",
            "dialogue_transitions",
            "turn_exits",
            "wake_outbox",
            "work_items",
        }
        actual_tables = {
            row[0]
            for row in connection.execute(
                """
                SELECT name FROM sqlite_master
                WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                """
            ).fetchall()
        }
        if actual_tables != expected_tables:
            raise PerpetualDialogueError("dialogue store schema tables are invalid")
        work_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(work_items)").fetchall()
        }
        if work_columns != {
            "work_item_id",
            "conversation_id",
            "claim_digest",
            "status",
            "fence",
            "completion_digest",
            "blocker_digest",
        }:
            raise PerpetualDialogueError("dialogue work-item schema is invalid")
        durable_indexes = {
            row[0]
            for row in connection.execute(
                """
                SELECT name FROM sqlite_master
                WHERE type = 'index' AND sql IS NOT NULL
                """
            ).fetchall()
        }
        if durable_indexes != {
            "one_live_wake_per_work",
            "one_open_baton_per_work",
        }:
            raise PerpetualDialogueError("dialogue store schema indexes are invalid")

    @staticmethod
    def _decode_receipt(row: sqlite3.Row) -> dict[str, Any]:
        value = json.loads(bytes(row["receipt_json"]))
        if not isinstance(value, dict):
            raise PerpetualDialogueError("stored dialogue receipt is invalid")
        return value

    def _conversation(self, connection: sqlite3.Connection, conversation_id: str) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM conversations WHERE conversation_id = ?", (conversation_id,)
        ).fetchone()
        if row is None:
            raise PerpetualDialogueError("conversation does not exist")
        if row["status"] not in CONVERSATION_STATES:
            raise PerpetualDialogueError("stored conversation state is invalid")
        return row

    def _participant_set(
        self, connection: sqlite3.Connection, conversation_id: str
    ) -> set[str]:
        row = self._conversation(connection, conversation_id)
        values = json.loads(bytes(row["participants_json"]))
        if not isinstance(values, list):
            raise PerpetualDialogueError("stored conversation participants are invalid")
        return set(_participants(values))

    def _require_participant(
        self, connection: sqlite3.Connection, conversation_id: str, participant_id: str
    ) -> str:
        participant = _identity(participant_id, "participant_id")
        if participant not in self._participant_set(connection, conversation_id):
            raise PerpetualDialogueError("agent is not a conversation participant")
        return participant

    def _work(self, connection: sqlite3.Connection, work_item_id: str) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM work_items WHERE work_item_id = ?", (work_item_id,)
        ).fetchone()
        if row is None:
            raise PerpetualDialogueError("work item does not exist")
        if row["status"] not in WORK_STATES:
            raise PerpetualDialogueError("stored work state is invalid")
        return row

    def _checkpoint_record(self, row: sqlite3.Row) -> dict[str, Any]:
        record = {
            "protocol": "integrity-guardian/perpetual-dialogue-continuation-checkpoint/v1",
            "checkpoint_id": row["checkpoint_id"],
            "tenant_id": self.tenant_id,
            "conversation_id": row["conversation_id"],
            "work_item_id": row["work_item_id"],
            "source_baton_id": row["source_baton_id"],
            "expected_fence": int(row["expected_fence"]),
            "state_digest": row["state_digest"],
            "outstanding_work_digest": row["outstanding_work_digest"],
            "required_scope_digest": row["required_scope_digest"],
            "authority_required": bool(row["authority_required"]),
            "wake_budget": int(row["wake_budget"]),
            "production_authority": False,
        }
        validate("perpetual-dialogue-continuation-checkpoint", record)
        return record

    def _wake_record(self, row: sqlite3.Row) -> dict[str, Any]:
        record = {
            "protocol": "integrity-guardian/perpetual-dialogue-wake-record/v1",
            "tenant_id": self.tenant_id,
            "conversation_id": row["conversation_id"],
            "wake_id": row["wake_id"],
            "work_item_id": row["work_item_id"],
            "source_baton_id": row["source_baton_id"],
            "checkpoint_id": row["checkpoint_id"],
            "target_agent_id": row["target_agent_id"],
            "wake_state": row["status"],
            "trigger_digest": row["trigger_digest"],
            "admitted_event_digest": row["admitted_event_digest"],
            "next_baton_id": row["next_baton_id"],
            "wake_budget_remaining": int(row["wake_budget_remaining"]),
            "lease_holder": row["lease_holder"],
            "lease_fence": row["lease_fence"],
            "lease_expires_at": row["lease_expires_at"],
            "authority_inherited": False,
            "production_authority": False,
        }
        validate("perpetual-dialogue-wake-record", record)
        return record

    def _state(self, connection: sqlite3.Connection, conversation_id: str) -> dict[str, Any]:
        conversation = self._conversation(connection, conversation_id)
        participants = json.loads(bytes(conversation["participants_json"]))
        work_rows = connection.execute(
            "SELECT * FROM work_items WHERE conversation_id = ? ORDER BY work_item_id",
            (conversation_id,),
        ).fetchall()
        baton_rows = connection.execute(
            """
            SELECT * FROM batons WHERE conversation_id = ?
            ORDER BY work_item_id, baton_sequence
            """,
            (conversation_id,),
        ).fetchall()
        wake_rows = connection.execute(
            "SELECT * FROM wake_outbox WHERE conversation_id = ? ORDER BY wake_id",
            (conversation_id,),
        ).fetchall()
        exit_rows = connection.execute(
            """
            SELECT agent_id, turn_id FROM turn_exits
            WHERE conversation_id = ? ORDER BY agent_id, turn_id
            """,
            (conversation_id,),
        ).fetchall()
        return {
            "protocol": SNAPSHOT_PROTOCOL,
            "tenant_id": self.tenant_id,
            "conversation_id": conversation_id,
            "conversation_state": conversation["status"],
            "epoch": int(conversation["epoch"]),
            "fence": int(conversation["fence"]),
            "control_generation": int(conversation["control_generation"]),
            "sequence": int(conversation["sequence"]),
            "participants": participants,
            "work_items": [
                {
                    "work_item_id": row["work_item_id"],
                    "claim_digest": row["claim_digest"],
                    "work_state": row["status"],
                    "fence": int(row["fence"]),
                    "completion_digest": row["completion_digest"],
                    "blocker_digest": row["blocker_digest"],
                }
                for row in work_rows
            ],
            "batons": [
                {
                    "baton_id": row["baton_id"],
                    "work_item_id": row["work_item_id"],
                    "baton_sequence": int(row["baton_sequence"]),
                    "parent_baton_id": row["parent_baton_id"],
                    "sender_id": row["sender_id"],
                    "recipient_id": row["recipient_id"],
                    "processing_turn_id": row["processing_turn_id"],
                    "claim_digest": row["claim_digest"],
                    "authority_digest": row["authority_digest"],
                    "authority_inherited": False,
                    "baton_state": row["status"],
                    "result_digest": row["result_digest"],
                    "disposition": row["disposition"],
                }
                for row in baton_rows
            ],
            "continuation_checkpoints": [
                self._checkpoint_record(row)
                for row in connection.execute(
                    """
                    SELECT * FROM continuation_checkpoints
                    WHERE conversation_id = ? ORDER BY checkpoint_id
                    """,
                    (conversation_id,),
                ).fetchall()
            ],
            "wakes": [
                self._wake_record(row)
                for row in wake_rows
            ],
            "sealed_turn_exits": [
                {"agent_id": row["agent_id"], "turn_id": row["turn_id"]}
                for row in exit_rows
            ],
            "production_authority": False,
        }

    @staticmethod
    def _absent_state(conversation_id: str) -> dict[str, Any]:
        return {
            "protocol": SNAPSHOT_PROTOCOL,
            "conversation_id": conversation_id,
            "absent": True,
            "production_authority": False,
        }

    def _request_digest(self, request: Mapping[str, Any]) -> str:
        return _digest(dict(request), domain="perpetual-dialogue-request-v1")

    def _replay(
        self, connection: sqlite3.Connection, request_digest: str
    ) -> dict[str, Any] | None:
        row = connection.execute(
            "SELECT * FROM dialogue_transitions WHERE request_digest = ?",
            (request_digest,),
        ).fetchone()
        if row is None:
            return None
        receipt = verify_perpetual_dialogue_transition(
            self._decode_receipt(row), trusted_key=self.trusted_key
        )
        return {"receipt": receipt, "replayed": True}

    def _emit_transition(
        self,
        connection: sqlite3.Connection,
        *,
        conversation_id: str,
        transition_kind: str,
        subject_id: str,
        request_digest: str,
        prior_state: Mapping[str, Any],
        recorded_at: str | None,
    ) -> dict[str, Any]:
        if transition_kind not in TRANSITION_KINDS:
            raise PerpetualDialogueError("dialogue transition kind is invalid")
        conversation = self._conversation(connection, conversation_id)
        sequence = int(conversation["sequence"]) + 1
        connection.execute(
            "UPDATE conversations SET sequence = ? WHERE conversation_id = ?",
            (sequence, conversation_id),
        )
        next_state = self._state(connection, conversation_id)
        unsigned = {
            "protocol": TRANSITION_PROTOCOL,
            "tenant_id": self.tenant_id,
            "conversation_id": conversation_id,
            "sequence": sequence,
            "transition_kind": transition_kind,
            "subject_id": _identity(subject_id, "subject_id"),
            "request_digest": request_digest,
            "prior_state_digest": _digest(
                dict(prior_state), domain="perpetual-dialogue-state-v1"
            ),
            "next_state_digest": _digest(
                next_state, domain="perpetual-dialogue-state-v1"
            ),
            "recorded_at": recorded_at or _utc_now(),
            "production_authority": False,
        }
        unsigned["receipt_id"] = _digest(
            unsigned, domain="perpetual-dialogue-transition-v1"
        )
        receipt = self.signer.sign(unsigned)
        verify_perpetual_dialogue_transition(receipt, trusted_key=self.trusted_key)
        connection.execute(
            """
            INSERT INTO dialogue_transitions(
                receipt_id, conversation_id, sequence, transition_kind,
                subject_id, request_digest, receipt_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                receipt["receipt_id"],
                conversation_id,
                sequence,
                transition_kind,
                subject_id,
                request_digest,
                canonical_bytes(receipt),
            ),
        )
        return {"receipt": receipt, "replayed": False, "state": next_state}

    def snapshot(self, *, conversation_id: str) -> dict[str, Any]:
        conversation = _identity(conversation_id, "conversation_id")
        with self._connect() as connection:
            return self._state(connection, conversation)

    def open_conversation(
        self,
        *,
        conversation_id: str,
        participants: Iterable[str],
        recorded_at: str | None = None,
    ) -> dict[str, Any]:
        conversation = _identity(conversation_id, "conversation_id")
        normalized = _participants(participants)
        request = {
            "operation": "open-conversation",
            "conversation_id": conversation,
            "participants": normalized,
        }
        request_digest = self._request_digest(request)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            replay = self._replay(connection, request_digest)
            if replay is not None:
                connection.commit()
                replay["state"] = self._state(connection, conversation)
                return replay
            if connection.execute(
                "SELECT 1 FROM conversations WHERE conversation_id = ?", (conversation,)
            ).fetchone() is not None:
                raise PerpetualDialogueError("conversation already exists with another request")
            prior_state = self._absent_state(conversation)
            connection.execute(
                """
                INSERT INTO conversations(
                    conversation_id, participants_json, status, epoch,
                    fence, control_generation, sequence
                ) VALUES (?, ?, 'ACTIVE', 1, 1, 0, 0)
                """,
                (conversation, canonical_bytes(normalized)),
            )
            result = self._emit_transition(
                connection,
                conversation_id=conversation,
                transition_kind="conversation-opened",
                subject_id=conversation,
                request_digest=request_digest,
                prior_state=prior_state,
                recorded_at=recorded_at,
            )
            connection.commit()
            return result

    def open_work_item(
        self,
        *,
        conversation_id: str,
        work_item_id: str,
        claim_digest: str,
        recorded_at: str | None = None,
    ) -> dict[str, Any]:
        conversation = _identity(conversation_id, "conversation_id")
        work_item = _identity(work_item_id, "work_item_id")
        claim = _digest_value(claim_digest, "claim_digest")
        request = {
            "operation": "open-work-item",
            "conversation_id": conversation,
            "work_item_id": work_item,
            "claim_digest": claim,
        }
        request_digest = self._request_digest(request)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            replay = self._replay(connection, request_digest)
            if replay is not None:
                connection.commit()
                replay["state"] = self._state(connection, conversation)
                return replay
            current = self._conversation(connection, conversation)
            if current["status"] in {"THROTTLED", "PAUSED", "DRAINING", "STOPPED"}:
                raise PerpetualDialogueError("conversation does not admit new work")
            if connection.execute(
                "SELECT 1 FROM work_items WHERE work_item_id = ?", (work_item,)
            ).fetchone() is not None:
                raise PerpetualDialogueError("work item already exists with another request")
            prior_state = self._state(connection, conversation)
            connection.execute(
                """
                INSERT INTO work_items(
                    work_item_id, conversation_id, claim_digest, status, fence
                ) VALUES (?, ?, ?, 'OPEN', 1)
                """,
                (work_item, conversation, claim),
            )
            connection.execute(
                "UPDATE conversations SET status = 'ACTIVE' WHERE conversation_id = ?",
                (conversation,),
            )
            result = self._emit_transition(
                connection,
                conversation_id=conversation,
                transition_kind="work-opened",
                subject_id=work_item,
                request_digest=request_digest,
                prior_state=prior_state,
                recorded_at=recorded_at,
            )
            connection.commit()
            return result

    def issue_baton(
        self,
        *,
        conversation_id: str,
        work_item_id: str,
        sender_id: str,
        recipient_id: str,
        processing_turn_id: str,
        claim_digest: str,
        authority_digest: str | None = None,
        parent_baton_id: str | None = None,
        recorded_at: str | None = None,
    ) -> dict[str, Any]:
        conversation = _identity(conversation_id, "conversation_id")
        work_item = _identity(work_item_id, "work_item_id")
        sender = _identity(sender_id, "sender_id")
        recipient = _identity(recipient_id, "recipient_id")
        turn = _identity(processing_turn_id, "processing_turn_id")
        claim = _digest_value(claim_digest, "claim_digest")
        authority = _optional_digest(authority_digest, "authority_digest")
        parent = None if parent_baton_id is None else _identity(parent_baton_id, "parent_baton_id")
        request = {
            "operation": "issue-baton",
            "conversation_id": conversation,
            "work_item_id": work_item,
            "sender_id": sender,
            "recipient_id": recipient,
            "processing_turn_id": turn,
            "claim_digest": claim,
            "authority_digest": authority,
            "parent_baton_id": parent,
        }
        request_digest = self._request_digest(request)
        baton_id = "baton:" + request_digest.removeprefix("sha256:")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            replay = self._replay(connection, request_digest)
            if replay is not None:
                connection.commit()
                replay.update({"baton_id": baton_id, "state": self._state(connection, conversation)})
                return replay
            current = self._conversation(connection, conversation)
            if current["status"] != "ACTIVE":
                raise PerpetualDialogueError("conversation is not active")
            participants = self._participant_set(connection, conversation)
            if sender not in participants or recipient not in participants or sender == recipient:
                raise PerpetualDialogueError("baton endpoints are invalid")
            work = self._work(connection, work_item)
            if work["conversation_id"] != conversation or work["status"] != "OPEN":
                raise PerpetualDialogueError("work item is not open in this conversation")
            if connection.execute(
                "SELECT 1 FROM batons WHERE work_item_id = ? AND status = 'OPEN'", (work_item,)
            ).fetchone() is not None:
                raise PerpetualDialogueError("work item already has an open baton")
            if connection.execute(
                """
                SELECT 1 FROM wake_outbox
                WHERE work_item_id = ? AND status IN ('PENDING', 'WAITING', 'LEASED')
                """,
                (work_item,),
            ).fetchone() is not None:
                raise PerpetualDialogueError("work item already has a durable continuation")
            if parent is not None:
                parent_row = connection.execute(
                    "SELECT * FROM batons WHERE baton_id = ?", (parent,)
                ).fetchone()
                if (
                    parent_row is None
                    or parent_row["work_item_id"] != work_item
                    or parent_row["status"] != "CLOSED"
                ):
                    raise PerpetualDialogueError("parent baton is not a closed baton for this work")
            prior_state = self._state(connection, conversation)
            baton_sequence = int(
                connection.execute(
                    "SELECT COALESCE(MAX(baton_sequence), 0) FROM batons WHERE work_item_id = ?",
                    (work_item,),
                ).fetchone()[0]
            ) + 1
            connection.execute(
                """
                INSERT INTO batons(
                    baton_id, conversation_id, work_item_id, baton_sequence,
                    parent_baton_id, sender_id, recipient_id, processing_turn_id,
                    claim_digest, authority_digest, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'OPEN')
                """,
                (
                    baton_id,
                    conversation,
                    work_item,
                    baton_sequence,
                    parent,
                    sender,
                    recipient,
                    turn,
                    claim,
                    authority,
                ),
            )
            result = self._emit_transition(
                connection,
                conversation_id=conversation,
                transition_kind="baton-issued",
                subject_id=baton_id,
                request_digest=request_digest,
                prior_state=prior_state,
                recorded_at=recorded_at,
            )
            connection.commit()
            result["baton_id"] = baton_id
            return result

    @staticmethod
    def _validate_close_shape(
        *,
        disposition: str,
        next_agent_id: str | None,
        trigger_digest: str | None,
        completion_digest: str | None,
        blocker_digest: str | None,
        checkpoint_state_digest: str | None,
        outstanding_work_digest: str | None,
        required_scope_digest: str | None,
        wake_budget: int | None,
    ) -> None:
        if disposition not in BATON_DISPOSITIONS:
            raise PerpetualDialogueError("baton disposition is invalid")
        if disposition == "CONTINUE":
            valid = (
                next_agent_id is not None
                and trigger_digest is None
                and completion_digest is None
                and blocker_digest is None
            )
        elif disposition == "WAIT":
            valid = (
                next_agent_id is not None
                and trigger_digest is not None
                and completion_digest is None
                and blocker_digest is None
            )
        elif disposition == "HOLD":
            valid = (
                next_agent_id is None
                and trigger_digest is None
                and completion_digest is None
                and blocker_digest is not None
            )
        else:
            valid = (
                next_agent_id is None
                and trigger_digest is None
                and completion_digest is not None
                and blocker_digest is None
            )
        if not valid:
            raise PerpetualDialogueError("baton closure lacks its required durable outcome")
        continuation_values = (
            checkpoint_state_digest,
            outstanding_work_digest,
            required_scope_digest,
            wake_budget,
        )
        if disposition in {"CONTINUE", "WAIT"}:
            if any(value is None for value in continuation_values):
                raise PerpetualDialogueError(
                    "open work requires a durable checkpoint and bounded wake"
                )
        elif any(value is not None for value in continuation_values):
            raise PerpetualDialogueError(
                "terminal or held work cannot carry a continuation checkpoint"
            )

    def _insert_wake(
        self,
        connection: sqlite3.Connection,
        *,
        wake_id: str,
        conversation_id: str,
        work_item_id: str,
        source_baton_id: str,
        checkpoint_id: str,
        target_agent_id: str,
        wake_state: str,
        trigger_digest: str | None,
        wake_budget: int,
    ) -> None:
        """Insert the outbox row inside the caller's close transaction.

        Kept as a narrow seam so rollback tests can inject a failure exactly
        after checkpoint persistence and before outbox persistence.
        """

        connection.execute(
            """
            INSERT INTO wake_outbox(
                wake_id, conversation_id, work_item_id, source_baton_id,
                checkpoint_id, target_agent_id, status, trigger_digest,
                wake_budget_remaining
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                wake_id,
                conversation_id,
                work_item_id,
                source_baton_id,
                checkpoint_id,
                target_agent_id,
                wake_state,
                trigger_digest,
                wake_budget,
            ),
        )

    def close_baton(
        self,
        *,
        baton_id: str,
        expected_fence: int,
        result_digest: str,
        disposition: str,
        next_agent_id: str | None = None,
        trigger_digest: str | None = None,
        completion_digest: str | None = None,
        blocker_digest: str | None = None,
        checkpoint_state_digest: str | None = None,
        outstanding_work_digest: str | None = None,
        required_scope_digest: str | None = None,
        authority_required: bool = False,
        wake_budget: int | None = None,
        recorded_at: str | None = None,
    ) -> dict[str, Any]:
        baton = _identity(baton_id, "baton_id")
        if isinstance(expected_fence, bool) or not isinstance(expected_fence, int) or expected_fence < 1:
            raise PerpetualDialogueError("expected_fence is invalid")
        result_value = _digest_value(result_digest, "result_digest")
        next_agent = (
            None if next_agent_id is None else _identity(next_agent_id, "next_agent_id")
        )
        trigger = _optional_digest(trigger_digest, "trigger_digest")
        completion = _optional_digest(completion_digest, "completion_digest")
        blocker = _optional_digest(blocker_digest, "blocker_digest")
        checkpoint_state = _optional_digest(
            checkpoint_state_digest, "checkpoint_state_digest"
        )
        outstanding_work = _optional_digest(
            outstanding_work_digest, "outstanding_work_digest"
        )
        required_scope = _optional_digest(required_scope_digest, "required_scope_digest")
        if not isinstance(authority_required, bool):
            raise PerpetualDialogueError("authority_required is invalid")
        if wake_budget is not None and (
            isinstance(wake_budget, bool)
            or not isinstance(wake_budget, int)
            or not 1 <= wake_budget <= 1024
        ):
            raise PerpetualDialogueError("wake_budget is invalid")
        self._validate_close_shape(
            disposition=disposition,
            next_agent_id=next_agent,
            trigger_digest=trigger,
            completion_digest=completion,
            blocker_digest=blocker,
            checkpoint_state_digest=checkpoint_state,
            outstanding_work_digest=outstanding_work,
            required_scope_digest=required_scope,
            wake_budget=wake_budget,
        )
        request = {
            "operation": "close-baton",
            "baton_id": baton,
            "expected_fence": expected_fence,
            "result_digest": result_value,
            "disposition": disposition,
            "next_agent_id": next_agent,
            "trigger_digest": trigger,
            "completion_digest": completion,
            "blocker_digest": blocker,
            "checkpoint_state_digest": checkpoint_state,
            "outstanding_work_digest": outstanding_work,
            "required_scope_digest": required_scope,
            "authority_required": authority_required,
            "wake_budget": wake_budget,
        }
        request_digest = self._request_digest(request)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            replay = self._replay(connection, request_digest)
            baton_row = connection.execute(
                "SELECT * FROM batons WHERE baton_id = ?", (baton,)
            ).fetchone()
            if baton_row is None:
                raise PerpetualDialogueError("baton does not exist")
            conversation = baton_row["conversation_id"]
            if replay is not None:
                continuation = connection.execute(
                    "SELECT * FROM wake_outbox WHERE source_baton_id = ?", (baton,)
                ).fetchone()
                connection.commit()
                replay.update(
                    {
                        "continuation_id": None if continuation is None else continuation["wake_id"],
                        "checkpoint_id": (
                            None if continuation is None else continuation["checkpoint_id"]
                        ),
                        "state": self._state(connection, conversation),
                    }
                )
                return replay
            if baton_row["status"] != "OPEN":
                raise PerpetualDialogueError("baton is already terminal with another result")
            current = self._conversation(connection, conversation)
            if current["status"] == "STOPPED":
                raise PerpetualDialogueError("conversation is stopped")
            if current["status"] == "DRAINING" and disposition in {"CONTINUE", "WAIT"}:
                raise PerpetualDialogueError(
                    "draining conversation requires HOLD or explicit work completion"
                )
            work = self._work(connection, baton_row["work_item_id"])
            if work["conversation_id"] != conversation or work["status"] != "OPEN":
                raise PerpetualDialogueError("baton work item is not open")
            if int(work["fence"]) != expected_fence:
                raise PerpetualDialogueError("work-item fence is stale")
            if next_agent is not None:
                self._require_participant(connection, conversation, next_agent)
            if disposition in {"CONTINUE", "WAIT"}:
                parent_wake = connection.execute(
                    "SELECT * FROM wake_outbox WHERE next_baton_id = ?", (baton,)
                ).fetchone()
                if parent_wake is not None:
                    if (
                        parent_wake["conversation_id"] != conversation
                        or parent_wake["work_item_id"] != baton_row["work_item_id"]
                        or parent_wake["status"] != "CONSUMED"
                    ):
                        raise PerpetualDialogueError(
                            "parent wake lineage is invalid"
                        )
                    if int(wake_budget or 0) > int(
                        parent_wake["wake_budget_remaining"]
                    ):
                        raise PerpetualDialogueError(
                            "child wake budget cannot be replenished by an agent"
                        )
            prior_state = self._state(connection, conversation)
            connection.execute(
                """
                UPDATE batons
                SET status = 'CLOSED', result_digest = ?, disposition = ?
                WHERE baton_id = ?
                """,
                (result_value, disposition, baton),
            )
            continuation_id: str | None = None
            checkpoint_id: str | None = None
            if disposition in {"CONTINUE", "WAIT"}:
                wake_material = {
                    "source_baton_id": baton,
                    "disposition": disposition,
                    "next_agent_id": next_agent,
                    "trigger_digest": trigger,
                }
                continuation_id = "wake:" + _digest(
                    wake_material, domain="perpetual-dialogue-wake-v1"
                ).removeprefix("sha256:")
                checkpoint_material = {
                    "conversation_id": conversation,
                    "work_item_id": baton_row["work_item_id"],
                    "source_baton_id": baton,
                    "expected_fence": expected_fence,
                    "state_digest": checkpoint_state,
                    "outstanding_work_digest": outstanding_work,
                    "required_scope_digest": required_scope,
                    "authority_required": authority_required,
                    "wake_budget": wake_budget,
                }
                checkpoint_id = "checkpoint:" + _digest(
                    checkpoint_material,
                    domain="perpetual-dialogue-checkpoint-v1",
                ).removeprefix("sha256:")
                connection.execute(
                    """
                    INSERT INTO continuation_checkpoints(
                        checkpoint_id, conversation_id, work_item_id,
                        source_baton_id, expected_fence, state_digest,
                        outstanding_work_digest, required_scope_digest,
                        authority_required, wake_budget
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        checkpoint_id,
                        conversation,
                        baton_row["work_item_id"],
                        baton,
                        expected_fence,
                        checkpoint_state,
                        outstanding_work,
                        required_scope,
                        int(authority_required),
                        wake_budget,
                    ),
                )
                wake_state = "PENDING" if disposition == "CONTINUE" else "WAITING"
                self._insert_wake(
                    connection,
                    wake_id=continuation_id,
                    conversation_id=conversation,
                    work_item_id=baton_row["work_item_id"],
                    source_baton_id=baton,
                    checkpoint_id=checkpoint_id,
                    target_agent_id=next_agent,
                    wake_state=wake_state,
                    trigger_digest=trigger,
                    wake_budget=wake_budget,
                )
            elif disposition == "HOLD":
                connection.execute(
                    """
                    UPDATE work_items SET status = 'BLOCKED', blocker_digest = ?
                    WHERE work_item_id = ?
                    """,
                    (blocker, baton_row["work_item_id"]),
                )
            else:
                connection.execute(
                    """
                    UPDATE work_items SET status = 'COMPLETE', completion_digest = ?
                    WHERE work_item_id = ?
                    """,
                    (completion, baton_row["work_item_id"]),
                )
            active_count = int(
                connection.execute(
                    """
                    SELECT
                        (SELECT COUNT(*) FROM batons
                         WHERE conversation_id = ? AND status = 'OPEN') +
                        (SELECT COUNT(*) FROM wake_outbox
                         WHERE conversation_id = ? AND status IN ('PENDING', 'LEASED'))
                    """,
                    (conversation, conversation),
                ).fetchone()[0]
            )
            if current["status"] in {"ACTIVE", "IDLE"}:
                connection.execute(
                    "UPDATE conversations SET status = ? WHERE conversation_id = ?",
                    ("ACTIVE" if active_count else "IDLE", conversation),
                )
            emitted = self._emit_transition(
                connection,
                conversation_id=conversation,
                transition_kind="baton-closed",
                subject_id=baton,
                request_digest=request_digest,
                prior_state=prior_state,
                recorded_at=recorded_at,
            )
            connection.execute(
                "UPDATE batons SET close_receipt_id = ? WHERE baton_id = ?",
                (emitted["receipt"]["receipt_id"], baton),
            )
            connection.commit()
            emitted["continuation_id"] = continuation_id
            emitted["checkpoint_id"] = checkpoint_id
            return emitted

    def close_baton_and_schedule_continuation(
        self,
        *,
        expected_fence: int,
        baton_id: str,
        result_digest: str,
        checkpoint: Mapping[str, Any],
        next_agent_id: str,
        wait_for_event_digest: str | None = None,
        recorded_at: str | None = None,
    ) -> dict[str, Any]:
        """Atomically close one baton and persist its checkpoint plus outbox row."""

        required_keys = {
            "state_digest",
            "outstanding_work_digest",
            "required_scope_digest",
            "authority_required",
            "wake_budget",
        }
        if set(checkpoint) != required_keys:
            raise PerpetualDialogueError("continuation checkpoint shape is invalid")
        disposition = "WAIT" if wait_for_event_digest is not None else "CONTINUE"
        return self.close_baton(
            baton_id=baton_id,
            expected_fence=expected_fence,
            result_digest=result_digest,
            disposition=disposition,
            next_agent_id=next_agent_id,
            trigger_digest=wait_for_event_digest,
            checkpoint_state_digest=checkpoint["state_digest"],
            outstanding_work_digest=checkpoint["outstanding_work_digest"],
            required_scope_digest=checkpoint["required_scope_digest"],
            authority_required=checkpoint["authority_required"],
            wake_budget=checkpoint["wake_budget"],
            recorded_at=recorded_at,
        )

    def reconcile_baton_close(self, *, baton_id: str) -> dict[str, Any]:
        """Resolve a lost close response without replaying the transition."""

        baton = _identity(baton_id, "baton_id")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM batons WHERE baton_id = ?", (baton,)
            ).fetchone()
            if row is None:
                raise PerpetualDialogueError("baton does not exist")
            if row["status"] == "OPEN":
                return {
                    "protocol": "integrity-guardian/perpetual-dialogue-reconciliation/v1",
                    "baton_id": baton,
                    "outcome": "NOT_COMMITTED",
                    "retry_permitted": True,
                    "production_authority": False,
                }
            if row["status"] == "CANCELLED":
                return {
                    "protocol": "integrity-guardian/perpetual-dialogue-reconciliation/v1",
                    "baton_id": baton,
                    "outcome": "CANCELLED",
                    "retry_permitted": False,
                    "production_authority": False,
                }
            receipt_row = connection.execute(
                "SELECT * FROM dialogue_transitions WHERE receipt_id = ?",
                (row["close_receipt_id"],),
            ).fetchone()
            if receipt_row is None:
                raise PerpetualDialogueError("closed baton lost its transition receipt")
            receipt = verify_perpetual_dialogue_transition(
                self._decode_receipt(receipt_row), trusted_key=self.trusted_key
            )
            wake = connection.execute(
                "SELECT * FROM wake_outbox WHERE source_baton_id = ?", (baton,)
            ).fetchone()
            if row["disposition"] in {"CONTINUE", "WAIT"} and wake is None:
                raise PerpetualDialogueError("closed baton lost its durable continuation")
            return {
                "protocol": "integrity-guardian/perpetual-dialogue-reconciliation/v1",
                "baton_id": baton,
                "outcome": "COMMITTED",
                "retry_permitted": False,
                "receipt": receipt,
                "checkpoint_id": None if wake is None else wake["checkpoint_id"],
                "wake_id": None if wake is None else wake["wake_id"],
                "production_authority": False,
            }

    def admit_wake_event(
        self,
        *,
        wake_id: str,
        event_digest: str,
        recorded_at: str | None = None,
    ) -> dict[str, Any]:
        wake = _identity(wake_id, "wake_id")
        event = _digest_value(event_digest, "event_digest")
        request = {
            "operation": "admit-wake-event",
            "wake_id": wake,
            "event_digest": event,
        }
        request_digest = self._request_digest(request)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            replay = self._replay(connection, request_digest)
            row = connection.execute(
                "SELECT * FROM wake_outbox WHERE wake_id = ?", (wake,)
            ).fetchone()
            if row is None:
                raise PerpetualDialogueError("wake does not exist")
            conversation = row["conversation_id"]
            if replay is not None:
                connection.commit()
                replay["state"] = self._state(connection, conversation)
                return replay
            if row["status"] != "WAITING":
                raise PerpetualDialogueError("wake is not waiting for an event")
            if row["trigger_digest"] != event:
                raise PerpetualDialogueError("wake event digest does not match trigger")
            current = self._conversation(connection, conversation)
            if current["status"] == "STOPPED":
                raise PerpetualDialogueError("conversation does not admit a wake event")
            prior_state = self._state(connection, conversation)
            connection.execute(
                """
                UPDATE wake_outbox
                SET status = 'PENDING', admitted_event_digest = ?
                WHERE wake_id = ?
                """,
                (event, wake),
            )
            if current["status"] == "IDLE":
                connection.execute(
                    "UPDATE conversations SET status = 'ACTIVE' WHERE conversation_id = ?",
                    (conversation,),
                )
            result = self._emit_transition(
                connection,
                conversation_id=conversation,
                transition_kind="wake-admitted",
                subject_id=wake,
                request_digest=request_digest,
                prior_state=prior_state,
                recorded_at=recorded_at,
            )
            connection.commit()
            return result

    def claim_due_wake(
        self,
        *,
        wake_id: str,
        expected_fence: int,
        scheduler_id: str,
        lease_expires_at: str,
        now: str | None = None,
        recorded_at: str | None = None,
    ) -> dict[str, Any]:
        wake = _identity(wake_id, "wake_id")
        if isinstance(expected_fence, bool) or not isinstance(expected_fence, int) or expected_fence < 1:
            raise PerpetualDialogueError("expected_fence is invalid")
        scheduler = _identity(scheduler_id, "scheduler_id")
        lease_expiry = _time(lease_expires_at, "lease_expires_at")
        now_value = dt.datetime.now(dt.UTC) if now is None else _time(now, "now")
        if lease_expiry <= now_value:
            raise PerpetualDialogueError("wake lease is already expired")
        request = {
            "operation": "claim-due-wake",
            "wake_id": wake,
            "expected_fence": expected_fence,
            "scheduler_id": scheduler,
            "lease_expires_at": lease_expires_at,
            "now": now,
        }
        request_digest = self._request_digest(request)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            replay = self._replay(connection, request_digest)
            row = connection.execute(
                "SELECT * FROM wake_outbox WHERE wake_id = ?", (wake,)
            ).fetchone()
            if row is None:
                raise PerpetualDialogueError("wake does not exist")
            conversation = row["conversation_id"]
            if replay is not None:
                connection.commit()
                replay.update(
                    {
                        "lease_fence": row["lease_fence"],
                        "state": self._state(connection, conversation),
                    }
                )
                return replay
            current = self._conversation(connection, conversation)
            if current["status"] != "ACTIVE":
                raise PerpetualDialogueError("conversation is not active")
            work = self._work(connection, row["work_item_id"])
            if work["conversation_id"] != conversation or work["status"] != "OPEN":
                raise PerpetualDialogueError("wake work item is not open")
            if int(work["fence"]) != expected_fence:
                raise PerpetualDialogueError("work-item fence is stale")
            if row["status"] == "LEASED":
                if _time(row["lease_expires_at"], "lease_expires_at") > now_value:
                    raise PerpetualDialogueError("wake lease is still active")
            elif row["status"] != "PENDING":
                raise PerpetualDialogueError("wake is not pending or reclaimable")
            if int(row["wake_budget_remaining"]) < 1:
                raise PerpetualDialogueError("wake budget is exhausted")
            prior_state = self._state(connection, conversation)
            lease_fence = expected_fence + 1
            connection.execute(
                """
                UPDATE work_items SET fence = ? WHERE work_item_id = ?
                """,
                (lease_fence, row["work_item_id"]),
            )
            connection.execute(
                """
                UPDATE wake_outbox
                SET status = 'LEASED', lease_holder = ?, lease_fence = ?,
                    lease_expires_at = ?
                WHERE wake_id = ?
                """,
                (scheduler, lease_fence, lease_expires_at, wake),
            )
            result = self._emit_transition(
                connection,
                conversation_id=conversation,
                transition_kind="wake-claimed",
                subject_id=wake,
                request_digest=request_digest,
                prior_state=prior_state,
                recorded_at=recorded_at,
            )
            connection.commit()
            result["lease_fence"] = lease_fence
            return result

    @staticmethod
    def _fresh_authority(
        value: Mapping[str, Any] | None,
        *,
        authority_required: bool,
    ) -> str | None:
        if value is not None:
            raise PerpetualDialogueError(
                "caller-supplied authority is forbidden; verified admission is required"
            )
        if authority_required:
            raise PerpetualDialogueError("AUTHORITY_ADMISSION_REQUIRED")
        return None

    def issue_next_baton(
        self,
        *,
        wake_id: str,
        scheduler_id: str,
        lease_fence: int,
        processing_turn_id: str,
        claim_digest: str,
        fresh_authority: Mapping[str, Any] | None = None,
        now: str | None = None,
        recorded_at: str | None = None,
    ) -> dict[str, Any]:
        wake = _identity(wake_id, "wake_id")
        scheduler = _identity(scheduler_id, "scheduler_id")
        if isinstance(lease_fence, bool) or not isinstance(lease_fence, int) or lease_fence < 1:
            raise PerpetualDialogueError("lease_fence is invalid")
        turn = _identity(processing_turn_id, "processing_turn_id")
        claim = _digest_value(claim_digest, "claim_digest")
        now_value = dt.datetime.now(dt.UTC) if now is None else _time(now, "now")
        authority_request = None if fresh_authority is None else dict(fresh_authority)
        request = {
            "operation": "issue-next-baton",
            "wake_id": wake,
            "scheduler_id": scheduler,
            "lease_fence": lease_fence,
            "processing_turn_id": turn,
            "claim_digest": claim,
            "fresh_authority": authority_request,
        }
        request_digest = self._request_digest(request)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            replay = self._replay(connection, request_digest)
            row = connection.execute(
                "SELECT * FROM wake_outbox WHERE wake_id = ?", (wake,)
            ).fetchone()
            if row is None:
                raise PerpetualDialogueError("wake does not exist")
            conversation = row["conversation_id"]
            if replay is not None:
                connection.commit()
                replay.update(
                    {
                        "baton_id": row["next_baton_id"],
                        "state": self._state(connection, conversation),
                    }
                )
                return replay
            current = self._conversation(connection, conversation)
            if current["status"] != "ACTIVE":
                raise PerpetualDialogueError("conversation is not active")
            work = self._work(connection, row["work_item_id"])
            if work["conversation_id"] != conversation or work["status"] != "OPEN":
                raise PerpetualDialogueError("wake work item is not open")
            if int(work["fence"]) != lease_fence:
                raise PerpetualDialogueError("wake lease fence is stale")
            if (
                row["status"] != "LEASED"
                or row["lease_holder"] != scheduler
                or int(row["lease_fence"] or 0) != lease_fence
            ):
                raise PerpetualDialogueError("wake lease is not held by this scheduler")
            if _time(row["lease_expires_at"], "lease_expires_at") <= now_value:
                raise PerpetualDialogueError("wake lease is expired")
            if connection.execute(
                "SELECT 1 FROM batons WHERE work_item_id = ? AND status = 'OPEN'",
                (row["work_item_id"],),
            ).fetchone() is not None:
                raise PerpetualDialogueError("work item already has an open baton")
            source = connection.execute(
                "SELECT * FROM batons WHERE baton_id = ?", (row["source_baton_id"],)
            ).fetchone()
            if source is None or source["status"] != "CLOSED":
                raise PerpetualDialogueError("wake source baton is not closed")
            checkpoint = connection.execute(
                "SELECT * FROM continuation_checkpoints WHERE checkpoint_id = ?",
                (row["checkpoint_id"],),
            ).fetchone()
            if checkpoint is None:
                raise PerpetualDialogueError("wake continuation checkpoint is missing")
            if int(row["wake_budget_remaining"]) < 1:
                raise PerpetualDialogueError("wake budget is exhausted")
            authority = self._fresh_authority(
                fresh_authority,
                authority_required=bool(checkpoint["authority_required"]),
            )
            prior_state = self._state(connection, conversation)
            baton_material = {
                "wake_id": wake,
                "processing_turn_id": turn,
                "claim_digest": claim,
                "fresh_authority_digest": authority,
                "lease_fence": lease_fence,
            }
            baton_id = "baton:" + _digest(
                baton_material, domain="perpetual-dialogue-baton-v1"
            ).removeprefix("sha256:")
            baton_sequence = int(
                connection.execute(
                    "SELECT COALESCE(MAX(baton_sequence), 0) FROM batons WHERE work_item_id = ?",
                    (row["work_item_id"],),
                ).fetchone()[0]
            ) + 1
            connection.execute(
                """
                INSERT INTO batons(
                    baton_id, conversation_id, work_item_id, baton_sequence,
                    parent_baton_id, sender_id, recipient_id, processing_turn_id,
                    claim_digest, authority_digest, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'OPEN')
                """,
                (
                    baton_id,
                    conversation,
                    row["work_item_id"],
                    baton_sequence,
                    row["source_baton_id"],
                    source["recipient_id"],
                    row["target_agent_id"],
                    turn,
                    claim,
                    authority,
                ),
            )
            connection.execute(
                """
                UPDATE wake_outbox
                SET status = 'CONSUMED', next_baton_id = ?,
                    wake_budget_remaining = wake_budget_remaining - 1
                WHERE wake_id = ?
                """,
                (baton_id, wake),
            )
            result = self._emit_transition(
                connection,
                conversation_id=conversation,
                transition_kind="wake-consumed",
                subject_id=wake,
                request_digest=request_digest,
                prior_state=prior_state,
                recorded_at=recorded_at,
            )
            connection.commit()
            result["baton_id"] = baton_id
            return result

    def consume_wake(self, **_: Any) -> dict[str, Any]:
        """Reject the unfenced PPv3-style shortcut."""

        raise PerpetualDialogueError(
            "unfenced wake consumption is forbidden; claim_due_wake then issue_next_baton"
        )

    @staticmethod
    def _revoke_scheduler_leases(
        connection: sqlite3.Connection, *, conversation_id: str
    ) -> None:
        """Fence and return every leased wake to the durable pending outbox."""

        connection.execute(
            """
            UPDATE work_items SET fence = fence + 1
            WHERE work_item_id IN (
                SELECT work_item_id FROM wake_outbox
                WHERE conversation_id = ? AND status = 'LEASED'
            )
            """,
            (conversation_id,),
        )
        connection.execute(
            """
            UPDATE wake_outbox
            SET status = 'PENDING', lease_holder = NULL, lease_fence = NULL,
                lease_expires_at = NULL
            WHERE conversation_id = ? AND status = 'LEASED'
            """,
            (conversation_id,),
        )

    def control_conversation(
        self,
        *,
        conversation_id: str,
        action: str,
        expected_control_generation: int,
        control_digest: str,
        recorded_at: str | None = None,
    ) -> dict[str, Any]:
        conversation = _identity(conversation_id, "conversation_id")
        if action not in {"PAUSE", "THROTTLE", "DRAIN", "RESUME", "STOP"}:
            raise PerpetualDialogueError("conversation control action is invalid")
        if (
            isinstance(expected_control_generation, bool)
            or not isinstance(expected_control_generation, int)
            or expected_control_generation < 0
        ):
            raise PerpetualDialogueError("expected_control_generation is invalid")
        control = _digest_value(control_digest, "control_digest")
        request = {
            "operation": "control-conversation",
            "conversation_id": conversation,
            "action": action,
            "expected_control_generation": expected_control_generation,
            "control_digest": control,
        }
        request_digest = self._request_digest(request)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            replay = self._replay(connection, request_digest)
            if replay is not None:
                connection.commit()
                replay["state"] = self._state(connection, conversation)
                return replay
            current = self._conversation(connection, conversation)
            if current["status"] == "STOPPED":
                raise PerpetualDialogueError("stopped conversation cannot be resumed")
            if int(current["control_generation"]) != expected_control_generation:
                raise PerpetualDialogueError("owner control generation is stale")
            if action == "PAUSE" and current["status"] == "PAUSED":
                raise PerpetualDialogueError("conversation is already paused")
            if action == "THROTTLE" and current["status"] == "THROTTLED":
                raise PerpetualDialogueError("conversation is already throttled")
            if action == "DRAIN" and current["status"] == "DRAINING":
                raise PerpetualDialogueError("conversation is already draining")
            if action == "RESUME" and current["status"] not in {
                "PAUSED",
                "THROTTLED",
                "DRAINING",
            }:
                raise PerpetualDialogueError(
                    "only a paused, throttled or draining conversation can resume"
                )
            prior_state = self._state(connection, conversation)
            if action in {"PAUSE", "THROTTLE", "DRAIN"}:
                self._revoke_scheduler_leases(
                    connection, conversation_id=conversation
                )
            if action == "PAUSE":
                connection.execute(
                    """
                    UPDATE conversations
                    SET status = 'PAUSED', control_generation = control_generation + 1
                    WHERE conversation_id = ?
                    """,
                    (conversation,),
                )
            elif action in {"THROTTLE", "DRAIN"}:
                connection.execute(
                    """
                    UPDATE conversations
                    SET status = ?, control_generation = control_generation + 1
                    WHERE conversation_id = ?
                    """,
                    (
                        "THROTTLED" if action == "THROTTLE" else "DRAINING",
                        conversation,
                    ),
                )
            elif action == "RESUME":
                active_count = int(
                    connection.execute(
                        """
                        SELECT
                            (SELECT COUNT(*) FROM batons
                             WHERE conversation_id = ? AND status = 'OPEN') +
                            (SELECT COUNT(*) FROM wake_outbox
                             WHERE conversation_id = ? AND status IN ('PENDING', 'LEASED'))
                        """,
                        (conversation, conversation),
                    ).fetchone()[0]
                )
                connection.execute(
                    """
                    UPDATE conversations
                    SET status = ?, control_generation = control_generation + 1
                    WHERE conversation_id = ?
                    """,
                    ("ACTIVE" if active_count else "IDLE", conversation),
                )
            else:
                connection.execute(
                    """
                    UPDATE work_items SET fence = fence + 1
                    WHERE conversation_id = ? AND status = 'OPEN'
                    """,
                    (conversation,),
                )
                connection.execute(
                    """
                    UPDATE conversations
                    SET status = 'STOPPED', epoch = epoch + 1,
                        fence = fence + 1,
                        control_generation = control_generation + 1
                    WHERE conversation_id = ?
                    """,
                    (conversation,),
                )
                connection.execute(
                    """
                    UPDATE wake_outbox SET status = 'CANCELLED'
                    WHERE conversation_id = ? AND status IN ('PENDING', 'WAITING', 'LEASED')
                    """,
                    (conversation,),
                )
                connection.execute(
                    """
                    UPDATE batons SET status = 'CANCELLED'
                    WHERE conversation_id = ? AND status = 'OPEN'
                    """,
                    (conversation,),
                )
            result = self._emit_transition(
                connection,
                conversation_id=conversation,
                transition_kind="conversation-control",
                subject_id=conversation,
                request_digest=request_digest,
                prior_state=prior_state,
                recorded_at=recorded_at,
            )
            connection.commit()
            return result

    def seal_turn_exit(
        self,
        *,
        conversation_id: str,
        agent_id: str,
        turn_id: str,
        recorded_at: str | None = None,
    ) -> dict[str, Any]:
        conversation = _identity(conversation_id, "conversation_id")
        agent = _identity(agent_id, "agent_id")
        turn = _identity(turn_id, "turn_id")
        request = {
            "operation": "seal-turn-exit",
            "conversation_id": conversation,
            "agent_id": agent,
            "turn_id": turn,
        }
        request_digest = self._request_digest(request)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            replay = self._replay(connection, request_digest)
            if replay is not None:
                connection.commit()
                replay.update(
                    {"safe_to_end": True, "state": self._state(connection, conversation)}
                )
                return replay
            self._require_participant(connection, conversation, agent)
            current = self._conversation(connection, conversation)
            batons = connection.execute(
                """
                SELECT * FROM batons
                WHERE conversation_id = ? AND recipient_id = ? AND processing_turn_id = ?
                ORDER BY baton_sequence
                """,
                (conversation, agent, turn),
            ).fetchall()
            if not batons:
                raise PerpetualDialogueError("turn processed no dialogue baton")
            continuation_ids: list[str] = []
            for baton in batons:
                if baton["status"] == "OPEN":
                    raise PerpetualDialogueError("turn still owns an open baton")
                if baton["status"] == "CANCELLED":
                    if current["status"] != "STOPPED":
                        raise PerpetualDialogueError("baton was cancelled without owner STOP")
                    continue
                disposition = baton["disposition"]
                work = self._work(connection, baton["work_item_id"])
                if disposition in {"CONTINUE", "WAIT"}:
                    wake = connection.execute(
                        "SELECT * FROM wake_outbox WHERE source_baton_id = ?",
                        (baton["baton_id"],),
                    ).fetchone()
                    if wake is None:
                        raise PerpetualDialogueError(
                            "closed baton has no durable continuation"
                        )
                    if wake["status"] == "CANCELLED" and current["status"] != "STOPPED":
                        raise PerpetualDialogueError("continuation was cancelled without owner STOP")
                    continuation_ids.append(wake["wake_id"])
                elif disposition == "WORK_COMPLETE":
                    if work["status"] != "COMPLETE" or work["completion_digest"] is None:
                        raise PerpetualDialogueError("work completion is not durable")
                    continuation_ids.append(work["work_item_id"])
                elif disposition == "HOLD":
                    if work["status"] != "BLOCKED" or work["blocker_digest"] is None:
                        raise PerpetualDialogueError("work blocker is not durable")
                    continuation_ids.append(work["work_item_id"])
                else:
                    raise PerpetualDialogueError("terminal baton lacks a valid disposition")
            prior_state = self._state(connection, conversation)
            connection.execute(
                """
                INSERT INTO turn_exits(
                    conversation_id, agent_id, turn_id, request_digest
                ) VALUES (?, ?, ?, ?)
                """,
                (conversation, agent, turn, request_digest),
            )
            result = self._emit_transition(
                connection,
                conversation_id=conversation,
                transition_kind="turn-exit-sealed",
                subject_id=turn,
                request_digest=request_digest,
                prior_state=prior_state,
                recorded_at=recorded_at,
            )
            connection.execute(
                """
                UPDATE turn_exits SET receipt_id = ?
                WHERE conversation_id = ? AND agent_id = ? AND turn_id = ?
                """,
                (result["receipt"]["receipt_id"], conversation, agent, turn),
            )
            connection.commit()
            result.update(
                {
                    "safe_to_end": True,
                    "continuation_ids": sorted(continuation_ids),
                }
            )
            return result
