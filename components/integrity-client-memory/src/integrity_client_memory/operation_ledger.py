"""Durable original-operation custody. This module grants no send authority.

Only the owning broker decides whether guards and authoritative reconciliation
permit a send. A local absent record is never proof of a remote absent effect.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import time


class LedgerError(RuntimeError):
    pass


class Conflict(LedgerError):
    pass


class Pending(LedgerError):
    pass


STATES = frozenset({"prepared", "sending", "known-unsent", "unknown", "reconciled-absent", "committed", "blocked"})
TRANSITIONS = {
    "prepared": {"sending", "committed", "blocked"},
    "sending": {"known-unsent", "unknown", "committed", "blocked"},
    "known-unsent": {"sending", "committed", "blocked"},
    "unknown": {"reconciled-absent", "committed", "blocked"},
    "reconciled-absent": {"sending", "committed", "blocked"},
    "committed": set(),
    "blocked": set(),
}


def canonical_request(tool, arguments):
    if tool not in {"integrity_append_event", "integrity_turn_memory_close"} or not isinstance(arguments, dict):
        raise LedgerError("unsupported operation")
    # No credentials belong in this Memory operation protocol. Exact application
    # payloads may contain operational data and must stay in broker-private custody.
    def validate(value):
        if value is None or isinstance(value, (str, bool, int)):
            return
        if isinstance(value, float) and math.isfinite(value):
            return
        if isinstance(value, list):
            for item in value: validate(item)
            return
        if isinstance(value, dict) and all(isinstance(k, str) for k in value):
            for key, item in value.items():
                if key.casefold() in {"password", "authorization", "cookie", "access_token", "refresh_token", "private_key"}:
                    raise LedgerError("credential fields are prohibited")
                validate(item)
            return
        raise LedgerError("request is outside the canonical JSON profile")
    validate(arguments)
    raw = json.dumps({"tool": tool, "arguments": arguments}, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    if len(raw) > 262144:
        raise LedgerError("operation exceeds custody budget")
    return raw


def request_digest(tool, arguments):
    return "sha256:" + hashlib.sha256(canonical_request(tool, arguments)).hexdigest()


class OperationLedger:
    """SQLite WAL/FULL ledger, one immutable request per owner/semantic key.

    Caller must supply an already protected directory. Each method uses its own
    transaction, so threads/processes cannot both claim the same pending send.
    """

    def __init__(self, path, *, max_records=256, max_bytes=4194304, retention_seconds=86400, max_tombstones=65536):
        self.path = Path(path).absolute()
        if type(max_records) is not int or not 1 <= max_records <= 4096 or type(max_bytes) is not int or not 1024 <= max_bytes <= 67108864:
            raise LedgerError("ledger quota is invalid")
        self.max_records, self.max_bytes = max_records, max_bytes
        if type(retention_seconds) is not int or not 1 <= retention_seconds <= 604800 or type(max_tombstones) is not int or not 1 <= max_tombstones <= 1048576:
            raise LedgerError("completed custody retention is invalid")
        self.retention_ns, self.max_tombstones = retention_seconds * 1000000000, max_tombstones
        if not self.path.parent.is_dir() or self.path.is_symlink() or any(p.is_symlink() for p in self.path.parents):
            raise LedgerError("ledger custody path is unsafe")
        if not self.path.exists():
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
            except FileExistsError:
                pass
            else:
                os.close(fd)
        with self._db() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("BEGIN IMMEDIATE")
            db.execute("""CREATE TABLE IF NOT EXISTS operations (
                owner_key TEXT NOT NULL, operation_key TEXT NOT NULL,
                tool TEXT NOT NULL, request_bytes BLOB NOT NULL,
                request_sha256 TEXT NOT NULL, state TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0, receipt_bytes BLOB,
                created_ns INTEGER NOT NULL, updated_ns INTEGER NOT NULL,
                PRIMARY KEY(owner_key, operation_key))""")
            db.execute("CREATE UNIQUE INDEX IF NOT EXISTS operation_uid_owner ON operations(operation_key)")
            db.commit()

    @contextmanager
    def _db(self):
        if self.path.is_symlink(): raise LedgerError("ledger custody changed")
        db = sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True, timeout=5, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA trusted_schema=OFF")
        db.execute("PRAGMA busy_timeout=5000")
        try:
            yield db
        finally:
            db.close()

    @staticmethod
    def _record(row):
        if row is None: return None
        value = dict(row)
        raw = bytes(value["request_bytes"])
        if value["state"] == "archived":
            if raw != b"" or value["receipt_bytes"] is not None: raise Conflict("invalid completed custody tombstone")
            value.update(request_bytes=b"", arguments=None, receipt=None)
            value.pop("receipt_bytes")
            return value
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        if value["request_sha256"] != digest:
            raise Conflict("stored original request digest mismatch")
        parsed = json.loads(raw)
        if canonical_request(parsed["tool"], parsed["arguments"]) != raw or parsed["tool"] != value["tool"]:
            raise Conflict("stored request is not canonical")
        value["request_bytes"] = raw
        value["arguments"] = parsed["arguments"]
        value["receipt"] = None if value.pop("receipt_bytes") is None else json.loads(row["receipt_bytes"])
        return value

    @staticmethod
    def _key(owner_key, operation_key, tool, arguments):
        if not isinstance(owner_key, str) or re.fullmatch(r"sha256:[a-f0-9]{64}", owner_key) is None:
            raise LedgerError("owner must be a registration digest")
        expected = "append:" + str(arguments.get("event_uid", "")) if tool == "integrity_append_event" else "close:" + owner_key
        if operation_key != expected or (tool == "integrity_turn_memory_close" and arguments.get("registration_id") != owner_key):
            raise Conflict("semantic operation key or registration mismatch")
        if tool == "integrity_append_event" and not arguments.get("event_uid"):
            raise LedgerError("append requires stable event UID")

    def prepare(self, owner_key, operation_key, tool, arguments):
        raw = canonical_request(tool, arguments)
        self._key(owner_key, operation_key, tool, arguments)
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM operations WHERE operation_key=?", (operation_key,)).fetchone()
            if row is not None:
                result = self._record(row)
                if result["state"] == "archived":
                    if result["owner_key"] != owner_key or result["request_sha256"] != digest: raise Conflict("archived UID belongs to different original operation")
                    raise Pending("completed payload retention expired; no automatic replay")
                if result["owner_key"] != owner_key or result["request_bytes"] != raw or result["request_sha256"] != digest:
                    raise Conflict("same operation key has different original content")
            else:
                # Reclaim only completed payloads; UID ownership/hash survives.
                cutoff = time.time_ns() - self.retention_ns
                db.execute("UPDATE operations SET state='archived',request_bytes=X'',receipt_bytes=NULL WHERE state='committed' AND updated_ns<?", (cutoff,))
                count, size = db.execute("SELECT COUNT(*),COALESCE(SUM(LENGTH(request_bytes)+COALESCE(LENGTH(receipt_bytes),0)),0) FROM operations WHERE state<>'archived'").fetchone()
                tombstones = db.execute("SELECT COUNT(*) FROM operations WHERE state='archived'").fetchone()[0]
                if tombstones >= self.max_tombstones: raise LedgerError("UID ownership tombstone quota exhausted")
                if count >= self.max_records or size + len(raw) > self.max_bytes:
                    raise LedgerError("ledger quota exhausted; unresolved operations were preserved")
                now = time.time_ns()
                db.execute("INSERT INTO operations VALUES (?,?,?,?,?,'prepared',0,NULL,?,?)", (owner_key, operation_key, tool, raw, digest, now, now))
                result = self._record(db.execute("SELECT * FROM operations WHERE owner_key=? AND operation_key=?", (owner_key, operation_key)).fetchone())
            db.commit()  # durable before any network send is permitted
            return result

    def get(self, owner_key, operation_key):
        with self._db() as db:
            return self._record(db.execute("SELECT * FROM operations WHERE owner_key=? AND operation_key=?", (owner_key, operation_key)).fetchone())

    def mark(self, owner_key, operation_key, state, receipt=None, expected_state=None):
        if state not in STATES: raise LedgerError("invalid state")
        if state == "sending": raise LedgerError("use claim_send to consume a bounded attempt")
        if state == "committed" and not isinstance(receipt, dict): raise LedgerError("committed requires a verified receipt supplied by caller")
        if state != "committed" and receipt is not None: raise LedgerError("only committed may store a receipt")
        raw_receipt = None if receipt is None else json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
        if raw_receipt is not None and len(raw_receipt) > 262144: raise LedgerError("receipt exceeds custody budget")
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM operations WHERE owner_key=? AND operation_key=?", (owner_key, operation_key)).fetchone()
            if row is None: raise LedgerError("operation is not prepared")
            previous = self._record(row)
            if expected_state is not None and previous["state"] != expected_state: raise Pending("operation state changed")
            if previous["state"] == "committed":
                if state != "committed" or previous["receipt"] != receipt: raise Conflict("committed operation is immutable")
                db.commit(); return previous
            if previous["state"] == "archived": raise Pending("completed operation custody is archived")
            if state not in TRANSITIONS[previous["state"]]: raise Pending("unsafe operation state transition")
            if raw_receipt is not None:
                size = db.execute("SELECT COALESCE(SUM(LENGTH(request_bytes)+COALESCE(LENGTH(receipt_bytes),0)),0) FROM operations").fetchone()[0]
                if size + len(raw_receipt) > self.max_bytes: raise LedgerError("ledger receipt quota exhausted; effect remains to be reconciled")
            db.execute("UPDATE operations SET state=?,receipt_bytes=?,updated_ns=? WHERE owner_key=? AND operation_key=?", (state, raw_receipt, time.time_ns(), owner_key, operation_key))
            result = self._record(db.execute("SELECT * FROM operations WHERE owner_key=? AND operation_key=?", (owner_key, operation_key)).fetchone())
            db.commit(); return result

    def claim_send(self, owner_key, operation_key, max_attempts=2, expected_state=None):
        if isinstance(max_attempts, bool) or not isinstance(max_attempts, int) or not 1 <= max_attempts <= 3:
            raise LedgerError("send attempt budget is invalid")
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM operations WHERE owner_key=? AND operation_key=?", (owner_key, operation_key)).fetchone()
            if row is None: raise LedgerError("operation is not prepared")
            record = self._record(row)
            if expected_state is not None and record["state"] != expected_state: raise Pending("operation state changed")
            if record["state"] not in {"prepared", "known-unsent", "reconciled-absent"}: raise Pending("operation requires reconciliation or is terminal")
            if record["attempts"] >= max_attempts: raise Pending("durable send attempt budget exhausted")
            db.execute("UPDATE operations SET state='sending',attempts=attempts+1,updated_ns=? WHERE owner_key=? AND operation_key=?", (time.time_ns(), owner_key, operation_key))
            result = self._record(db.execute("SELECT * FROM operations WHERE owner_key=? AND operation_key=?", (owner_key, operation_key)).fetchone())
            db.commit(); return result

    def recover_inflight(self):
        """Expose ambiguous sends after restart; never mutate/claim another sender.

        A still-running sender might be committing. The caller must reconcile
        before changing these rows; absence alone never fences that sender.
        """
        with self._db() as db:
            return [self._record(row) for row in db.execute("SELECT * FROM operations WHERE state IN ('sending','unknown') ORDER BY created_ns")]
