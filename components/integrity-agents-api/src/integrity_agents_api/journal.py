"""Local transport journal, not canonical memory, a permission ledger or a witness.

Place it outside the agent workspace in an owner-protected directory. Existing
Guardian durable permits remain necessary across copied/restored journals.
"""
from __future__ import annotations

import os
import sqlite3
import stat
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Callable

from .contracts import MAX_BYTES, Unknown, decode, digest, encode, identifier, need, number, sha


class Journal:
    def __init__(self, path: Path, identity: str, namespace: str):
        self.path = Path(path).absolute()
        self.identity, self.namespace = identifier(identity), identifier(namespace)
        need(self.path.is_file() and not self.path.is_symlink(), "journal_not_regular")
        for parent in self.path.parents:
            need(not parent.is_symlink(), "journal_parent_link")
        st = self.path.stat()
        need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1, "journal_link")
        if os.name == "posix":
            need(st.st_uid == os.getuid() and not (st.st_mode & 0o077), "journal_permissions")
        self._inode = (st.st_dev, st.st_ino)
        with self.connection() as db:
            need(db.execute("PRAGMA user_version").fetchone()[0] == 2, "journal_schema_requires_explicit_reconciliation")
            row = db.execute("SELECT identity,namespace FROM metadata WHERE singleton=1").fetchone()
            need(row == (identity, namespace), "journal_identity_mismatch")

    @classmethod
    def create(cls, path: Path, identity: str, namespace: str, *, budget_microusd: int,
               max_billable: int = 1):
        identifier(identity)
        identifier(namespace)
        number(budget_microusd, 1)
        number(max_billable, 1, 100)
        path = Path(path).absolute()
        for parent in path.parents:
            need(not parent.is_symlink(), "journal_parent_link")
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        with closing(sqlite3.connect(path)) as db, db:
            db.execute("PRAGMA synchronous=FULL")
            db.executescript('''
                CREATE TABLE metadata(singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    identity TEXT NOT NULL, namespace TEXT NOT NULL, budget INTEGER NOT NULL,
                    reserved INTEGER NOT NULL, max_billable INTEGER NOT NULL,
                    billable INTEGER NOT NULL, usage_unknown INTEGER NOT NULL,
                    usage_scope TEXT NOT NULL, usage_epoch INTEGER NOT NULL);
                CREATE TABLE operations(key TEXT PRIMARY KEY, binding TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('claimed','done','unknown')),
                    output BLOB, output_sha256 TEXT);
                CREATE TABLE bindings(session TEXT PRIMARY KEY, task TEXT NOT NULL,
                    config_sha256 TEXT NOT NULL, environment TEXT);
            ''')
            db.execute("PRAGMA user_version=2")
            db.execute("INSERT INTO metadata VALUES(1,?,?,?,0,?,0,0,'',0)",
                       (identity, namespace, budget_microusd, max_billable))
        return cls(path, identity, namespace)

    @contextmanager
    def connection(self):
        st = self.path.stat()
        need(not self.path.is_symlink() and (st.st_dev, st.st_ino) == self._inode, "journal_replaced")
        # mode=rw prevents accidental recreation after file loss.
        db = sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True, timeout=5)
        try:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("PRAGMA max_page_count=16384")
            yield db
        finally:
            db.close()

    def run_once(self, operation: str, document: dict, execute: Callable[[], bytes], *,
                 reserve_microusd: int = 0, usage_scope: str = "local") -> bytes:
        identifier(operation)
        number(reserve_microusd)
        identifier(usage_scope)
        binding = sha(encode({"namespace": self.namespace, "operation": operation, "input": document}))
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            prior = db.execute("SELECT binding,state,output,output_sha256 FROM operations WHERE key=?",
                               (operation,)).fetchone()
            if prior:
                need(prior[0] == binding, "operation_identity_reused")
                if prior[1] != "done":
                    raise Unknown("prior_outcome_unknown_no_retry")
                need(type(prior[2]) is bytes and sha(prior[2]) == prior[3], "retained_result_corrupt")
                return prior[2]
            need(db.execute("SELECT count(*) FROM operations").fetchone()[0] < 1024, "journal_capacity")
            if reserve_microusd:
                budget, reserved, maximum, count, unknown = db.execute(
                    "SELECT budget,reserved,max_billable,billable,usage_unknown FROM metadata").fetchone()
                need(not unknown, "usage_unknown_blocks_new_work")
                need(reserved + reserve_microusd <= budget and count < maximum, "budget_exhausted")
                db.execute("UPDATE metadata SET reserved=reserved+?,billable=billable+1,usage_unknown=1, "
                           "usage_scope=?,usage_epoch=usage_epoch+1",
                           (reserve_microusd, usage_scope))
            db.execute("INSERT INTO operations VALUES(?,?,'claimed',NULL,NULL)", (operation, binding))
            db.commit()  # Durable BEFORE touching a provider or target.
        try:
            output = execute()
            need(type(output) is bytes and len(output) <= MAX_BYTES, "result_bound")
            decode(output)
            with self.connection() as db:
                db.execute("BEGIN IMMEDIATE")
                changed = db.execute("UPDATE operations SET state='done',output=?,output_sha256=? "
                                     "WHERE key=? AND binding=? AND state='claimed'",
                                     (output, sha(output), operation, binding)).rowcount
                need(changed == 1, "operation_state_conflict")
                db.commit()
            return output
        except Exception:
            try:
                with self.connection() as db:
                    db.execute("UPDATE operations SET state='unknown' WHERE key=? AND state='claimed'",
                               (operation,))
                    db.commit()
            except Exception:
                pass  # The durable claimed record also blocks replay.
            raise Unknown("operation_outcome_unknown_no_retry") from None

    def bind_session(self, session: str, task: str, config_sha256: str, environment: str | None) -> None:
        identifier(session)
        identifier(task)
        digest(config_sha256)
        if environment is not None:
            identifier(environment)
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            prior = db.execute("SELECT task,config_sha256,environment FROM bindings WHERE session=?",
                               (session,)).fetchone()
            desired = (task, config_sha256, environment)
            need(prior is None or prior == desired, "session_binding_changed")
            if prior is None:
                db.execute("INSERT INTO bindings VALUES(?,?,?,?)", (session, *desired))
            db.commit()

    def require_session(self, session: str) -> tuple:
        identifier(session)
        with self.connection() as db:
            row = db.execute("SELECT task,config_sha256,environment FROM bindings WHERE session=?",
                             (session,)).fetchone()
            need(row is not None, "foreign_session")
            return row

    def retained(self, operation: str, document: dict) -> bytes:
        """Read only. Missing output must not create a claimed/unknown tool attempt."""
        identifier(operation)
        binding = sha(encode({"namespace": self.namespace, "operation": operation, "input": document}))
        with self.connection() as db:
            row = db.execute("SELECT binding,state,output,output_sha256 FROM operations WHERE key=?",
                             (operation,)).fetchone()
        need(row is not None, "no_retained_result")
        need(row[0] == binding, "operation_identity_reused")
        if row[1] != "done":
            raise Unknown("prior_outcome_unknown_no_retry")
        need(type(row[2]) is bytes and sha(row[2]) == row[3], "retained_result_corrupt")
        return row[2]

    def attach_usage(self, pending_scope: str, session: str) -> None:
        """Name the session for this successful create; never rebind later work."""
        identifier(pending_scope)
        identifier(session)
        with self.connection() as db:
            db.execute("UPDATE metadata SET usage_scope=? WHERE usage_scope=?",
                       (session, pending_scope))
            db.commit()

    def usage_checkpoint(self) -> tuple[str, int]:
        with self.connection() as db:
            return db.execute("SELECT usage_scope,usage_epoch FROM metadata").fetchone()

    def usage_observed(self, complete: bool, *, session: str | None = None,
                       expected_epoch: int | None = None) -> bool:
        """CAS a matching observation only; a different or later operation stays blocked.

        Unscoped calls support host-local journal operations only, never a provider
        session. Best-effort token telemetry never refunds monetary reservations.
        """
        need(type(complete) is bool, "usage_flag")
        if session is not None:
            identifier(session)
            number(expected_epoch)
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            scope, epoch = db.execute("SELECT usage_scope,usage_epoch FROM metadata").fetchone()
            if session is None:
                need(scope in ("", "local"), "scoped_usage_observation_required")
            elif scope != session or epoch != expected_epoch:
                return False
            db.execute("UPDATE metadata SET usage_unknown=?", (int(not complete),))
            db.commit()
            return True

    def unresolved(self) -> int:
        with self.connection() as db:
            return db.execute("SELECT count(*) FROM operations WHERE state!='done'").fetchone()[0]

    def status(self) -> dict:
        with self.connection() as db:
            budget, reserved, count, unknown = db.execute(
                "SELECT budget,reserved,billable,usage_unknown FROM metadata").fetchone()
        return {"budget_microusd": budget, "reserved_microusd": reserved, "billable_operations": count,
                "usage_unknown": bool(unknown), "unresolved_operations": self.unresolved(),
                "provider_spend_hard_capped": False, "canonical_memory": False,
                "authority_granted": False}
