"""Durable run ledger: claim-before-effect, one live run per session, cached duplicates.

This is a local transport cache, not canonical memory, not a permission ledger and
not a witness. A copied or restored ledger cannot re-authorize anything: the SDK
durable permit (M3) remains necessary for every launch.

Custody limits (stated, not hidden): the file must be outside the model's working
directory and free of symlinks/junctions/hard links; on POSIX owner-only mode is
enforced. On Windows the DACL is NOT verified here; the owner must place the file
in a directory the agent account cannot write.
"""
from __future__ import annotations

import os
import secrets
import sqlite3
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from .canonical import Rejected, Unknown, canonical_bytes, identifier, need, sha256_bytes, strict_loads
from .descriptor import descriptor_digest, session_profile_digest
from .identity import is_within, require_plain_path
from .record import REASONS, validate_record

SCHEMA_VERSION = 1
MAX_RESULT_BYTES = 16 * 1024
MAX_RUNS = 100_000
IN_FLIGHT = ("claimed", "dispatching", "running", "cancel_requested")
# 'unknown' and 'stop_unverified' keep the session lease forever: no time-based
# stealing, no replay and no resume from this ledger.
RELEASING = ("completed", "not_started", "cancelled_stopped")
HOLDING = ("unknown", "stop_unverified")
TRANSITIONS = {
    "claimed": {"dispatching", "not_started", "unknown"},
    "dispatching": {"running", "cancel_requested", "not_started", "unknown", "stop_unverified"},
    "running": {"cancel_requested", "completed", "unknown", "stop_unverified"},
    "cancel_requested": {"cancelled_stopped", "not_started", "stop_unverified", "unknown"},
}
RESUMABLE = ("reported_success", "reported_error")
_STATES = IN_FLIGHT + RELEASING + HOLDING


@dataclass(frozen=True)
class Claim:
    """A durable claim held by one ledger instance; the binding is computed by the ledger."""
    request_id: str
    binding: str
    session_id: str


class RunLedger:
    def __init__(self, path: Path, identity: str, *, forbidden_roots: tuple = ()):
        self.path = require_plain_path(Path(path), "ledger")
        self.identity = identifier(identity, "ledger_identity")
        for root in forbidden_roots:
            need(not is_within(self.path, Path(root)), "ledger_inside_agent_workspace")
        info = os.stat(self.path)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "ledger_not_single_regular_file")
        if os.name == "posix":
            need(info.st_uid == os.getuid() and not info.st_mode & 0o077, "ledger_permissions")
        self._file = (info.st_dev, info.st_ino)
        self.owner = "ledger-instance:" + secrets.token_hex(16)
        with self._db() as db:
            need(db.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION,
                 "ledger_schema_requires_explicit_reconciliation")
            row = db.execute("SELECT identity FROM metadata WHERE singleton=1").fetchone()
            need(row == (identity,), "ledger_identity_mismatch")

    @classmethod
    def create(cls, path: Path, identity: str, *, forbidden_roots: tuple = ()) -> "RunLedger":
        path = require_plain_path(Path(path), "ledger")
        identifier(identity, "ledger_identity")
        for root in forbidden_roots:
            need(not is_within(path, Path(root)), "ledger_inside_agent_workspace")
        need(path.parent.is_dir(), "ledger_parent_missing")
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
        db = sqlite3.connect(path, isolation_level=None)
        try:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            db.execute("CREATE TABLE metadata(singleton INTEGER PRIMARY KEY CHECK(singleton=1), "
                       "identity TEXT NOT NULL)")
            db.execute("CREATE TABLE sessions(session_id TEXT PRIMARY KEY, task_id TEXT NOT NULL, "
                       "profile TEXT NOT NULL, blocked TEXT)")
            db.execute("CREATE TABLE leases(session_id TEXT PRIMARY KEY, run_id TEXT NOT NULL, "
                       "request_id TEXT NOT NULL)")
            db.execute("CREATE TABLE runs(request_id TEXT PRIMARY KEY, run_id TEXT NOT NULL UNIQUE, "
                       "session_id TEXT NOT NULL, task_id TEXT NOT NULL, binding TEXT NOT NULL, "
                       "mode TEXT NOT NULL, state TEXT NOT NULL, reason TEXT, owner TEXT NOT NULL, "
                       "result BLOB, result_sha256 TEXT)")
            db.execute("INSERT INTO metadata VALUES(1, ?)", (identity,))
            db.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
            db.execute("COMMIT")
        finally:
            db.close()
        return cls(path, identity, forbidden_roots=forbidden_roots)

    @contextmanager
    def _db(self):
        info = os.stat(self.path)
        need(not self.path.is_symlink() and (info.st_dev, info.st_ino) == self._file
             and info.st_nlink == 1, "ledger_replaced")
        # mode=rw refuses to silently recreate a deleted ledger.
        db = sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True, timeout=30,
                             isolation_level=None)
        try:
            db.execute("PRAGMA synchronous=FULL")
            yield db
        finally:
            db.close()

    @contextmanager
    def _transaction(self):
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                yield db
            except BaseException:
                db.execute("ROLLBACK")
                raise
            db.execute("COMMIT")

    def claim(self, descriptor: dict) -> dict:
        """Claim + session lease in ONE transaction.

        The ledger computes the binding from the complete descriptor itself; callers
        cannot supply it. Returns {'claimed': True, 'claim': Claim} or a cached record.
        An identical duplicate of a finished run returns its digest-checked record; a
        duplicate of an in-flight/unknown run raises Unknown (never replay).
        """
        frozen = strict_loads(canonical_bytes(descriptor))  # detached deep copy
        binding = descriptor_digest(frozen)
        profile = session_profile_digest(frozen)
        request, run = frozen["request_id"], frozen["run_id"]
        session, task, mode = frozen["session_id"], frozen["task_id"], frozen["mode"]
        with self._transaction() as db:
            prior = db.execute("SELECT binding,state,result,result_sha256 FROM runs "
                               "WHERE request_id=?", (request,)).fetchone()
            if prior is not None:
                need(prior[0] == binding, "request_identity_reused")
                return self._cached(prior[1], prior[2], prior[3])
            need(db.execute("SELECT 1 FROM runs WHERE run_id=?", (run,)).fetchone() is None,
                 "run_identity_reused")
            need(db.execute("SELECT count(*) FROM runs").fetchone()[0] < MAX_RUNS, "ledger_capacity")
            known = db.execute("SELECT task_id,profile,blocked FROM sessions WHERE session_id=?",
                               (session,)).fetchone()
            if mode == "new":
                need(known is None, "session_already_exists")
                db.execute("INSERT INTO sessions VALUES(?,?,?,NULL)", (session, task, profile))
            else:
                need(known is not None, "foreign_session")
                need(known[0] == task, "session_task_changed")
                need(known[1] == profile, "session_profile_changed")
                need(known[2] is None, "session_blocked")
            try:
                db.execute("INSERT INTO leases VALUES(?,?,?)", (session, run, request))
            except sqlite3.IntegrityError:
                raise Rejected("session_busy") from None
            db.execute("INSERT INTO runs VALUES(?,?,?,?,?,?,'claimed',NULL,?,NULL,NULL)",
                       (request, run, session, task, binding, mode, self.owner))
        return {"claimed": True, "claim": Claim(request, binding, session)}

    @staticmethod
    def _cached(state: str, result, result_sha256) -> dict:
        if state in IN_FLIGHT or state in HOLDING:
            raise Unknown("prior_outcome_unknown_no_retry")
        need(type(result) is bytes and sha256_bytes(result) == result_sha256, "cached_result_corrupt")
        return {"claimed": False, "state": state,
                "result": validate_record(strict_loads(result, MAX_RESULT_BYTES))}

    def advance(self, claim: Claim, source: str, target: str, *, reason: str | None = None,
                result: dict | None = None) -> None:
        """Owner-only compare-and-set. Terminal targets store only the closed record."""
        need(isinstance(claim, Claim), "claim_required")
        need(target in TRANSITIONS.get(source, ()), "ledger_transition")
        need(reason is None or reason in REASONS, "reason")
        payload = digest = None
        if target in RELEASING + HOLDING:
            record = validate_record(result)
            need(record["descriptor_sha256"] == claim.binding, "record_binding")
            payload = canonical_bytes(record, MAX_RESULT_BYTES)
            digest = sha256_bytes(payload)
        else:
            need(result is None, "result_before_terminal")
        with self._transaction() as db:
            row = db.execute("SELECT session_id,state,owner,binding,mode FROM runs "
                             "WHERE request_id=?", (claim.request_id,)).fetchone()
            need(row is not None, "unknown_request")
            need(row[3] == claim.binding, "request_identity_reused")
            need(row[2] == self.owner, "ledger_owner_mismatch")
            need(row[1] == source, "ledger_state_conflict")
            db.execute("UPDATE runs SET state=?,reason=?,result=?,result_sha256=? "
                       "WHERE request_id=? AND state=?",
                       (target, reason, payload, digest, claim.request_id, source))
            session = row[0]
            if target in RELEASING:
                db.execute("DELETE FROM leases WHERE session_id=? AND request_id=?",
                           (session, claim.request_id))
            blocked = None
            if target in HOLDING:
                blocked = target
            elif target == "not_started" and row[4] == "new":
                blocked = "never_started"  # no provider session exists to resume
            elif target in ("completed", "cancelled_stopped") and \
                    result["classification"] not in RESUMABLE:
                blocked = "unresolved_outcome"
            if blocked:
                db.execute("UPDATE sessions SET blocked=? WHERE session_id=? AND blocked IS NULL",
                           (blocked, session))

    def run(self, request_id: str) -> dict:
        with self._db() as db:
            row = db.execute("SELECT run_id,session_id,state,reason,owner FROM runs "
                             "WHERE request_id=?", (request_id,)).fetchone()
        need(row is not None, "unknown_request")
        return {"run_id": row[0], "session_id": row[1], "state": row[2], "reason": row[3],
                "owned_by_this_instance": row[4] == self.owner}

    def session(self, session_id: str) -> dict:
        with self._db() as db:
            row = db.execute("SELECT task_id,blocked FROM sessions WHERE session_id=?",
                             (session_id,)).fetchone()
            lease = db.execute("SELECT run_id FROM leases WHERE session_id=?",
                               (session_id,)).fetchone()
        need(row is not None, "foreign_session")
        return {"task_id": row[0], "blocked": row[1], "lease_run_id": lease[0] if lease else None}

    def status(self) -> dict:
        with self._db() as db:
            counts = dict(db.execute("SELECT state,count(*) FROM runs GROUP BY state").fetchall())
        return {"runs_by_state": {state: counts.get(state, 0) for state in _STATES},
                "unresolved": sum(counts.get(s, 0) for s in IN_FLIGHT + HOLDING),
                "windows_acl_verified": False, "canonical_memory": False,
                "authority_granted": False}
