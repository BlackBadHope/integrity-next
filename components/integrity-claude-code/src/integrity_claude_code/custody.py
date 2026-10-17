"""Trusted custody of SDK attempt references so the host can reopen and ``recover``.

Stores, per attempt path: the signed envelope, the latest signed journal checkpoint,
the phase, and the signed executor report body once recorded. These are the SDK's own
signed documents (no prompt, file content or secret); nothing here is an unsigned
substitute for them. Lives outside the agent cwd; same custody limits as RunLedger.
"""
from __future__ import annotations

import os
import sqlite3
import stat
from contextlib import contextmanager
from pathlib import Path

from .canonical import canonical_bytes, need, strict_loads
from .identity import is_within, require_plain_path

MAX_DOCUMENT = 256 * 1024
_PHASES = ("prepared", "dispatching", "executor-returned")


class AttemptCustody:
    def __init__(self, path: Path, *, forbidden_roots: tuple = ()):
        self.path = require_plain_path(Path(path), "custody")
        for root in forbidden_roots:
            need(not is_within(self.path, Path(root)), "custody_inside_agent_workspace")
        info = os.stat(self.path)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "custody_not_single_regular_file")
        self._file = (info.st_dev, info.st_ino)
        with self._db() as db:
            need(db.execute("PRAGMA user_version").fetchone()[0] == 1, "custody_schema")

    @classmethod
    def create(cls, path: Path, *, forbidden_roots: tuple = ()) -> "AttemptCustody":
        path = require_plain_path(Path(path), "custody")
        for root in forbidden_roots:
            need(not is_within(path, Path(root)), "custody_inside_agent_workspace")
        os.close(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
        db = sqlite3.connect(path, isolation_level=None)
        try:
            db.execute("BEGIN IMMEDIATE")
            db.execute("CREATE TABLE attempts(path TEXT PRIMARY KEY, document_sha256 TEXT NOT NULL, "
                       "envelope BLOB NOT NULL, phase TEXT NOT NULL, checkpoint BLOB NOT NULL, "
                       "report BLOB, report_digest TEXT)")
            db.execute("PRAGMA user_version=1")
            db.execute("COMMIT")
        finally:
            db.close()
        return cls(path, forbidden_roots=forbidden_roots)

    @contextmanager
    def _db(self):
        info = os.stat(self.path)
        need((info.st_dev, info.st_ino) == self._file and info.st_nlink == 1, "custody_replaced")
        db = sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True, timeout=30,
                             isolation_level=None)  # per-call connection: no cross-thread object
        try:
            db.execute("PRAGMA synchronous=FULL")
            yield db
        finally:
            db.close()

    def record(self, path: str, *, phase: str, checkpoint, document_sha256: str | None = None,
               envelope=None, report=None, report_digest: str | None = None) -> None:
        need(phase in _PHASES, "custody_phase")
        checkpoint_raw = canonical_bytes(checkpoint, MAX_DOCUMENT)
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute("SELECT phase FROM attempts WHERE path=?", (path,)).fetchone()
                if phase == "prepared":
                    need(row is None and envelope is not None and document_sha256, "custody_prepare")
                    db.execute("INSERT INTO attempts VALUES(?,?,?,?,?,NULL,NULL)",
                               (path, document_sha256, canonical_bytes(envelope, MAX_DOCUMENT),
                                phase, checkpoint_raw))
                else:
                    need(row is not None and _PHASES.index(phase) == _PHASES.index(row[0]) + 1,
                         "custody_phase_order")
                    need((report is None) == (phase != "executor-returned"), "custody_report")
                    db.execute("UPDATE attempts SET phase=?,checkpoint=?,report=?,report_digest=? "
                               "WHERE path=?",
                               (phase, checkpoint_raw,
                                None if report is None else canonical_bytes(report, MAX_DOCUMENT),
                                report_digest, path))
            except BaseException:
                db.execute("ROLLBACK")
                raise
            db.execute("COMMIT")

    def get(self, path: str) -> dict:
        with self._db() as db:
            row = db.execute("SELECT document_sha256,envelope,phase,checkpoint,report,report_digest "
                             "FROM attempts WHERE path=?", (path,)).fetchone()
        need(row is not None, "custody_unknown_attempt")
        return {"document_sha256": row[0], "envelope": strict_loads(row[1], MAX_DOCUMENT),
                "phase": row[2], "checkpoint": strict_loads(row[3], MAX_DOCUMENT),
                "report": None if row[4] is None else strict_loads(row[4], MAX_DOCUMENT),
                "report_digest": row[5]}

    def pending_reconciliation(self) -> list[str]:
        """EVERY attempt in custody: the reconciliation list for a host restart.

        Custody records no terminal phase (terminal receipts are host-held), so an attempt
        at ``executor-returned`` is still UNKNOWN to ``AdapterAttemptJournal.recover``
        until the host supplies its terminal receipt. Nothing here re-dispatches.
        """
        with self._db() as db:
            return [r[0] for r in db.execute("SELECT path FROM attempts ORDER BY path")]

    def incomplete(self) -> list[str]:
        """Diagnostic subset: attempts without a recorded executor report. NOT the
        reconciliation list -- use ``pending_reconciliation`` for restart handling."""
        with self._db() as db:
            return [r[0] for r in db.execute(
                "SELECT path FROM attempts WHERE phase != 'executor-returned' ORDER BY path")]
