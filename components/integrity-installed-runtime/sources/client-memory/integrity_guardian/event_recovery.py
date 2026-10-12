"""Pure recovery candidate construction. Never writes, imports or invokes an adapter."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import sqlite3
from typing import Any

RECOVERY_PROTOCOL = "integrity.event-recovery/v1"


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")).hexdigest()


def validate_recovery(event_uid: str, details: Any) -> None:
    if not isinstance(details, dict):
        if event_uid.startswith("client:recovery-v1-"):
            raise ValueError("recovery requires object provenance")
        return
    recovery = details.get("recovery")
    if recovery is None:
        if event_uid.startswith("client:recovery-v1-"):
            raise ValueError("recovery identity requires provenance")
        return
    if not isinstance(recovery, dict) or set(recovery) != {
        "protocol", "fact_key", "occurred_at", "sources", "created_at_policy"
    }:
        raise ValueError("invalid recovery annotation")
    if recovery["protocol"] != RECOVERY_PROTOCOL or recovery["created_at_policy"] != "server-now":
        raise ValueError("recovery cannot supply or backdate creation time")
    fact_key = recovery["fact_key"]
    if not isinstance(fact_key, str) or not 1 <= len(fact_key) <= 200:
        raise ValueError("bounded recovery fact_key is required")
    occurred_at = recovery["occurred_at"]
    if not isinstance(occurred_at, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", occurred_at
    ):
        raise ValueError("recovery occurred_at must be explicit UTC")
    try:
        dt.datetime.fromisoformat(occurred_at)
    except ValueError as exc:
        raise ValueError("invalid recovery occurred_at") from exc
    sources = recovery["sources"]
    if not isinstance(sources, list) or not 1 <= len(sources) <= 20:
        raise ValueError("bounded recovery provenance is required")
    for source in sources:
        if not isinstance(source, dict) or set(source) != {
            "chat_id", "turn_id", "artifact", "artifact_sha256"
        }:
            raise ValueError("recovery requires chat, turn, artifact and hash")
        if not all(isinstance(source[k], str) and 1 <= len(source[k]) <= 1024 for k in source):
            raise ValueError("recovery provenance contains missing or oversized values")
        if not re.fullmatch(r"[a-f0-9]{64}", source["artifact_sha256"]):
            raise ValueError("recovery artifact SHA256 is required")
    identities = [json.dumps(s, sort_keys=True, ensure_ascii=False) for s in sources]
    if identities != sorted(set(identities)):
        raise ValueError("recovery provenance must be sorted and unique")
    identity = {"protocol": RECOVERY_PROTOCOL, "fact_key": fact_key}
    if event_uid != "client:recovery-v1-" + _digest(identity):
        raise ValueError("recovery identity does not match provenance")
    correction = details.get("correction")
    if correction is None:
        if fact_key.startswith("correction:"):
            raise ValueError("correction requires an immutable original event link")
        return
    if not isinstance(correction, dict) or set(correction) != {
        "mode", "target_event_uid", "target_event_digest", "correction_key"
    }:
        raise ValueError("invalid linked correction")
    target = correction["target_event_uid"]
    key = correction["correction_key"]
    digest = correction["target_event_digest"]
    if (correction["mode"] != "superseding" or not isinstance(target, str)
            or not 1 <= len(target) <= 160 or target == event_uid
            or not isinstance(key, str) or not 1 <= len(key) <= 200
            or not isinstance(digest, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", digest)):
        raise ValueError("correction must link an immutable original; in-place mutation forbidden")
    if fact_key != "correction:" + _digest(correction):
        raise ValueError("correction identity does not match original link")


def build_recovery_event(*, fact_key: str, summary: str, occurred_at: str,
                         sources: list[dict[str, str]]) -> dict[str, Any]:
    sources = sorted(sources, key=lambda s: json.dumps(s, sort_keys=True, ensure_ascii=False))
    event_uid = "client:recovery-v1-" + _digest({"protocol": RECOVERY_PROTOCOL, "fact_key": fact_key})
    details = {"recovery": {"protocol": RECOVERY_PROTOCOL, "fact_key": fact_key,
               "occurred_at": occurred_at, "sources": sources, "created_at_policy": "server-now"}}
    validate_recovery(event_uid, details)
    return {"event_uid": event_uid, "kind": "thought", "summary": summary,
            "details": details, "tags": ["recovery", "provenance"]}


def protect_event_schema(connection: sqlite3.Connection) -> None:
    """Protect the application's connection, not a disk/root security boundary."""
    def authorize(operation, first, second, database, trigger):
        first = str(first).casefold()
        second = str(second).casefold()
        if operation in (sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE,
                         sqlite3.SQLITE_DROP_TABLE) and first == "events":
            return sqlite3.SQLITE_DENY
        if operation == sqlite3.SQLITE_ALTER_TABLE and second == "events":
            return sqlite3.SQLITE_DENY
        if operation == sqlite3.SQLITE_DROP_TRIGGER and str(first).startswith("events_append_only_"):
            return sqlite3.SQLITE_DENY
        if operation == sqlite3.SQLITE_PRAGMA and first == "writable_schema":
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK
    connection.set_authorizer(authorize)


def build_correction_event(*, target_event_uid: str, target_event_digest: str,
                           correction_key: str, summary: str, occurred_at: str,
                           sources: list[dict[str, str]]) -> dict[str, Any]:
    correction = {"mode": "superseding", "target_event_uid": target_event_uid,
                  "target_event_digest": target_event_digest, "correction_key": correction_key}
    fact_key = "correction:" + _digest(correction)
    # Link before validation; this remains a new event and never opens the original store.
    sources = sorted(sources, key=lambda s: json.dumps(s, sort_keys=True, ensure_ascii=False))
    event_uid = "client:recovery-v1-" + _digest({"protocol": RECOVERY_PROTOCOL, "fact_key": fact_key})
    details = {"correction": correction, "recovery": {"protocol": RECOVERY_PROTOCOL,
        "fact_key": fact_key, "occurred_at": occurred_at, "sources": sources,
        "created_at_policy": "server-now"}}
    validate_recovery(event_uid, details)
    return {"event_uid": event_uid, "kind": "thought", "summary": summary,
            "details": details, "tags": ["recovery", "correction", "provenance"]}
