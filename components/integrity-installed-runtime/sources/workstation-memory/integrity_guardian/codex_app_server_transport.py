"""Concrete Codex app-server transport for dormant PPv4 continuation tasks.

``thread/start`` creates a loaded Codex task but does not submit a model turn.
The same app-server session gives it a deterministic name and then uses
``thread/inject_items`` to persist both the name and signed transport envelope
without starting a user turn.  A private SQLite dispatch journal is the
authoritative idempotency index because Codex does not expose zero-turn tasks
as a reliably searchable external key.  Starting the later model turn remains
a separate, authority-bearing operation and is deliberately outside this
module.
"""

from __future__ import annotations

import json
import subprocess
import threading
import time
import uuid
from collections import deque
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
from queue import Empty, Queue
from typing import Any, Protocol

from .agent_handoff_custody import (
    AgentHandoffCustodyError,
    open_private_sqlite_connection,
)
from .hashing import digest_object

THREAD_NAME_PREFIX = "Integrity PPv4 dormant "
DISPATCH_JOURNAL_SCHEMA_VERSION = 1
DISPATCH_JOURNAL_PROTOCOL = "integrity-guardian/codex-app-server-dispatch-journal/v1"
DISPATCH_STATES = frozenset({"PREPARED", "STARTED", "READY"})


class CodexAppServerTransportError(RuntimeError):
    """Codex transport failed without granting execution authority."""


class CodexAppServerCommitUnknown(CodexAppServerTransportError):
    """The request crossed stdio but its authoritative response was not read."""


class CodexAppServerClient(Protocol):
    """Small v2 app-server request boundary used by the concrete driver."""

    def call(self, method: str, params: Mapping[str, Any]) -> Mapping[str, Any]:
        """Return one result object or raise a classified transport error."""

    def create_dormant_thread(
        self,
        params: Mapping[str, Any],
        *,
        thread_name: str,
        history_items: Sequence[Mapping[str, Any]],
        on_thread_started: Callable[[str], None],
    ) -> Mapping[str, Any]:
        """Start and durably inject an envelope in one loaded-thread session."""


def _error_tail(lines: deque[str]) -> str:
    tail = " | ".join(value.strip()[:400] for value in lines if value.strip())
    return tail[-2000:]


class _CodexAppServerStdioSession:
    def __init__(self, client: CodexAppServerStdioClient) -> None:
        self.client = client
        self.process = subprocess.Popen(
            list(client.argv),
            cwd=client.process_cwd,
            env=client.env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        self.responses: Queue[dict[str, Any] | None] = Queue()
        self.stderr_lines: deque[str] = deque(maxlen=32)
        self.next_request_id = 1
        self.stdout_thread = threading.Thread(target=self._read_stdout, daemon=True)
        self.stderr_thread = threading.Thread(target=self._read_stderr, daemon=True)
        self.stdout_thread.start()
        self.stderr_thread.start()

    def _read_stdout(self) -> None:
        assert self.process.stdout is not None
        for line in self.process.stdout:
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                self.responses.put(value)
        self.responses.put(None)

    def _read_stderr(self) -> None:
        assert self.process.stderr is not None
        for line in self.process.stderr:
            self.stderr_lines.append(line)

    def _send(self, value: Mapping[str, Any]) -> None:
        if self.process.stdin is None:
            raise CodexAppServerTransportError("Codex app-server stdin is unavailable")
        self.process.stdin.write(json.dumps(dict(value), separators=(",", ":")) + "\n")
        self.process.stdin.flush()

    def _wait_for(self, request_id: int, *, commit_sensitive: bool) -> Mapping[str, Any]:
        deadline = time.monotonic() + self.client.timeout_seconds
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                suffix = _error_tail(self.stderr_lines)
                detail = f": {suffix}" if suffix else ""
                if commit_sensitive:
                    raise CodexAppServerCommitUnknown(
                        f"Codex app-server response timed out after request send{detail}"
                    )
                raise CodexAppServerTransportError(
                    f"Codex app-server initialize timed out{detail}"
                )
            try:
                response = self.responses.get(timeout=min(0.25, remaining))
            except Empty:
                if self.process.poll() is None:
                    continue
                response = None
            if response is None:
                suffix = _error_tail(self.stderr_lines)
                detail = f": {suffix}" if suffix else ""
                if commit_sensitive:
                    raise CodexAppServerCommitUnknown(
                        f"Codex app-server closed after request send{detail}"
                    )
                raise CodexAppServerTransportError(
                    f"Codex app-server closed during initialize{detail}"
                )
            if response.get("id") != request_id:
                continue
            if "error" in response:
                error = response.get("error")
                raise CodexAppServerTransportError(
                    "Codex app-server rejected request: "
                    + json.dumps(error, sort_keys=True, separators=(",", ":"))[:2000]
                )
            result = response.get("result")
            if not isinstance(result, Mapping):
                raise CodexAppServerTransportError(
                    "Codex app-server returned a non-object result"
                )
            return dict(result)

    def initialize(self) -> None:
        try:
            self._send(
                {
                    "method": "initialize",
                    "id": self.next_request_id,
                    "params": {
                        "capabilities": {"experimentalApi": True},
                        "clientInfo": {
                            "name": "integrity_guardian_ppv4_transport",
                            "version": "1.0.0",
                        }
                    },
                }
            )
            self._wait_for(self.next_request_id, commit_sensitive=False)
            self.next_request_id += 1
            self._send({"method": "initialized", "params": {}})
        except (BrokenPipeError, OSError) as exc:
            raise CodexAppServerTransportError(
                "Codex app-server pipe failed during initialize"
            ) from exc

    def call(self, method: str, params: Mapping[str, Any]) -> Mapping[str, Any]:
        if not method or not isinstance(method, str):
            raise CodexAppServerTransportError("Codex app-server method is invalid")
        request_id = self.next_request_id
        try:
            self._send(
                {"method": method, "id": request_id, "params": deepcopy(dict(params))}
            )
        except (BrokenPipeError, OSError) as exc:
            raise CodexAppServerTransportError(
                "Codex app-server pipe failed before request send"
            ) from exc
        self.next_request_id += 1
        return self._wait_for(request_id, commit_sensitive=True)

    def close(self) -> None:
        CodexAppServerStdioClient._stop_process(self.process)
        self.stdout_thread.join(timeout=1.0)
        self.stderr_thread.join(timeout=1.0)


class CodexAppServerStdioClient:
    """Bounded stdio client with explicit loaded-thread transactions.

    Ordinary reads use one fresh app-server process.  Dormant creation keeps
    ``thread/start`` and ``thread/inject_items`` in one process because an
    empty started thread has no rollout and is not durable until history is
    appended.  The process is always proved absent before commit-unknown is
    returned.
    """

    def __init__(
        self,
        *,
        argv: Sequence[str],
        timeout_seconds: float = 15.0,
        process_cwd: str | Path | None = None,
        env: Mapping[str, str] | None = None,
    ) -> None:
        command = tuple(str(value) for value in argv)
        if not command or any(not value for value in command):
            raise CodexAppServerTransportError("Codex app-server argv is invalid")
        if timeout_seconds <= 0 or timeout_seconds > 120:
            raise CodexAppServerTransportError("Codex app-server timeout is invalid")
        self.argv = command
        self.timeout_seconds = float(timeout_seconds)
        self.process_cwd = str(process_cwd) if process_cwd is not None else None
        self.env = dict(env) if env is not None else None

    @staticmethod
    def _stop_process(process: subprocess.Popen[str]) -> None:
        try:
            if process.stdin is not None:
                process.stdin.close()
        except OSError:
            pass
        if process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2.0)

    @contextmanager
    def session(self) -> Iterator[_CodexAppServerStdioSession]:
        session = _CodexAppServerStdioSession(self)
        try:
            session.initialize()
            yield session
        finally:
            session.close()

    def call(self, method: str, params: Mapping[str, Any]) -> Mapping[str, Any]:
        with self.session() as session:
            return session.call(method, params)

    def create_dormant_thread(
        self,
        params: Mapping[str, Any],
        *,
        thread_name: str,
        history_items: Sequence[Mapping[str, Any]],
        on_thread_started: Callable[[str], None],
    ) -> Mapping[str, Any]:
        items = [deepcopy(dict(item)) for item in history_items]
        if not items:
            raise CodexAppServerTransportError("Dormant Codex history envelope is empty")
        with self.session() as session:
            started = session.call("thread/start", params)
            thread = started.get("thread")
            if not isinstance(thread, Mapping):
                raise CodexAppServerTransportError("Codex thread/start omitted the task")
            thread_id = thread.get("id")
            if not isinstance(thread_id, str) or not thread_id:
                raise CodexAppServerTransportError(
                    "Codex thread/start returned invalid identity"
                )
            on_thread_started(thread_id)
            session.call(
                "thread/name/set",
                {"threadId": thread_id, "name": thread_name},
            )
            session.call(
                "thread/inject_items",
                {"threadId": thread_id, "items": items},
            )
            return session.call(
                "thread/read",
                {"threadId": thread_id, "includeTurns": True},
            )


def _dispatch_name(dispatch_id: object) -> str:
    if not isinstance(dispatch_id, str) or len(dispatch_id) != 71:
        raise CodexAppServerTransportError("PPv4 dispatch identity is invalid")
    prefix, separator, digest = dispatch_id.partition(":")
    if prefix != "sha256" or separator != ":" or any(
        value not in "0123456789abcdef" for value in digest
    ):
        raise CodexAppServerTransportError("PPv4 dispatch identity is invalid")
    return THREAD_NAME_PREFIX + dispatch_id


class CodexAppServerDispatchJournal:
    """Private, fail-closed dispatch-to-thread identity journal.

    The journal never grants authority and never assumes that a timed-out
    external request was absent.  ``PREPARED`` and ``STARTED`` therefore block
    another start until the exact recorded thread can be reconciled.  This is
    intentionally conservative: Codex has no durable idempotency key on
    ``thread/start``, so lease expiry cannot make a second start safe.
    """

    def __init__(self, path: str | Path, *, cwd: str | Path) -> None:
        target = Path(path)
        workspace = Path(cwd)
        if not target.is_absolute():
            raise CodexAppServerTransportError("Codex dispatch journal path must be absolute")
        if not workspace.is_absolute():
            raise CodexAppServerTransportError("Codex task cwd must be absolute")
        self.path = target
        self.cwd = str(workspace)
        self._initialize()

    @contextmanager
    def _connect(self, *, create: bool = False) -> Iterator[Any]:
        try:
            with open_private_sqlite_connection(self.path, create=create) as connection:
                yield connection
        except AgentHandoffCustodyError as exc:
            raise CodexAppServerTransportError(
                "Codex dispatch journal custody rejected"
            ) from exc

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
                    raise CodexAppServerTransportError(
                        "Unversioned Codex dispatch journal requires explicit migration"
                    )
                connection.executescript(
                    """
                    CREATE TABLE codex_dispatch_journal_metadata (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    );
                    CREATE TABLE codex_transport_dispatches (
                        dispatch_id TEXT PRIMARY KEY,
                        thread_name TEXT NOT NULL UNIQUE,
                        state TEXT NOT NULL CHECK (state IN ('PREPARED', 'STARTED', 'READY')),
                        attempt_id TEXT NOT NULL,
                        thread_id TEXT UNIQUE,
                        created_at_ns INTEGER NOT NULL CHECK (created_at_ns > 0),
                        updated_at_ns INTEGER NOT NULL CHECK (updated_at_ns >= created_at_ns),
                        CHECK (
                            (state = 'PREPARED' AND thread_id IS NULL)
                            OR (state IN ('STARTED', 'READY') AND thread_id IS NOT NULL)
                        )
                    );
                    CREATE TABLE codex_transport_requests (
                        dispatch_id TEXT NOT NULL
                            REFERENCES codex_transport_dispatches(dispatch_id),
                        request_digest TEXT NOT NULL,
                        first_seen_at_ns INTEGER NOT NULL CHECK (first_seen_at_ns > 0),
                        PRIMARY KEY(dispatch_id, request_digest)
                    );
                    """
                )
                connection.execute(
                    f"PRAGMA user_version = {DISPATCH_JOURNAL_SCHEMA_VERSION}"
                )
            elif schema_version != DISPATCH_JOURNAL_SCHEMA_VERSION:
                raise CodexAppServerTransportError(
                    "Codex dispatch journal schema version is unsupported"
                )
            self._assert_schema(connection)
            expected_metadata = {
                "protocol": DISPATCH_JOURNAL_PROTOCOL,
                "schema_version": str(DISPATCH_JOURNAL_SCHEMA_VERSION),
                "workspace": self.cwd,
            }
            existing_metadata = dict(
                connection.execute(
                    "SELECT key, value FROM codex_dispatch_journal_metadata"
                ).fetchall()
            )
            if existing_metadata:
                if existing_metadata != expected_metadata:
                    raise CodexAppServerTransportError(
                        "Codex dispatch journal lineage mismatch"
                    )
            else:
                connection.executemany(
                    "INSERT INTO codex_dispatch_journal_metadata(key, value) VALUES (?, ?)",
                    sorted(expected_metadata.items()),
                )

    @staticmethod
    def _assert_schema(connection: Any) -> None:
        tables = {
            row[0]
            for row in connection.execute(
                """
                SELECT name FROM sqlite_master
                WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                """
            ).fetchall()
        }
        if tables != {
            "codex_dispatch_journal_metadata",
            "codex_transport_dispatches",
            "codex_transport_requests",
        }:
            raise CodexAppServerTransportError(
                "Codex dispatch journal schema tables are invalid"
            )
        expected_columns = {
            "codex_dispatch_journal_metadata": {"key", "value"},
            "codex_transport_dispatches": {
                "dispatch_id",
                "thread_name",
                "state",
                "attempt_id",
                "thread_id",
                "created_at_ns",
                "updated_at_ns",
            },
            "codex_transport_requests": {
                "dispatch_id",
                "request_digest",
                "first_seen_at_ns",
            },
        }
        actual_columns = {
            table: {
                row[1]
                for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
            }
            for table in expected_columns
        }
        if actual_columns != expected_columns:
            raise CodexAppServerTransportError(
                "Codex dispatch journal schema columns are invalid"
            )

    @staticmethod
    def _row(row: Any, *, dispatch_id: str, thread_name: str) -> dict[str, Any]:
        candidate = dict(row)
        state = candidate.get("state")
        thread_id = candidate.get("thread_id")
        attempt_id = candidate.get("attempt_id")
        if (
            candidate.get("dispatch_id") != dispatch_id
            or candidate.get("thread_name") != thread_name
            or state not in DISPATCH_STATES
            or not isinstance(attempt_id, str)
            or not attempt_id.startswith("attempt:")
            or (state == "PREPARED" and thread_id is not None)
            or (
                state in {"STARTED", "READY"}
                and (not isinstance(thread_id, str) or not thread_id)
            )
        ):
            raise CodexAppServerTransportError(
                "Codex dispatch journal record is invalid"
            )
        return candidate

    def prepare(
        self,
        *,
        dispatch_id: str,
        thread_name: str,
        request: Mapping[str, Any],
    ) -> dict[str, Any]:
        request_digest = digest_object(
            dict(request), domain="codex-app-server-dispatch-request-v1"
        )
        now = time.time_ns()
        attempt_id = "attempt:" + uuid.uuid4().hex
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM codex_transport_dispatches WHERE dispatch_id = ?",
                (dispatch_id,),
            ).fetchone()
            claimed = row is None
            if row is None:
                connection.execute(
                    """
                    INSERT INTO codex_transport_dispatches(
                        dispatch_id, thread_name, state, attempt_id, thread_id,
                        created_at_ns, updated_at_ns
                    ) VALUES (?, ?, 'PREPARED', ?, NULL, ?, ?)
                    """,
                    (dispatch_id, thread_name, attempt_id, now, now),
                )
                row = connection.execute(
                    "SELECT * FROM codex_transport_dispatches WHERE dispatch_id = ?",
                    (dispatch_id,),
                ).fetchone()
            assert row is not None
            candidate = self._row(
                row, dispatch_id=dispatch_id, thread_name=thread_name
            )
            connection.execute(
                """
                INSERT OR IGNORE INTO codex_transport_requests(
                    dispatch_id, request_digest, first_seen_at_ns
                ) VALUES (?, ?, ?)
                """,
                (dispatch_id, request_digest, now),
            )
            connection.commit()
        return {**candidate, "claimed": claimed, "request_digest": request_digest}

    def read(self, *, dispatch_id: str, thread_name: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM codex_transport_dispatches WHERE dispatch_id = ?",
                (dispatch_id,),
            ).fetchone()
        if row is None:
            return None
        return self._row(row, dispatch_id=dispatch_id, thread_name=thread_name)

    def record_started(
        self,
        *,
        dispatch_id: str,
        thread_name: str,
        attempt_id: str,
        thread_id: str,
    ) -> None:
        if not isinstance(thread_id, str) or not thread_id:
            raise CodexAppServerTransportError("Codex task identity is invalid")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM codex_transport_dispatches WHERE dispatch_id = ?",
                (dispatch_id,),
            ).fetchone()
            if row is None:
                raise CodexAppServerTransportError("Codex dispatch journal claim is missing")
            candidate = self._row(
                row, dispatch_id=dispatch_id, thread_name=thread_name
            )
            if candidate["attempt_id"] != attempt_id:
                raise CodexAppServerTransportError("Codex dispatch journal fence is stale")
            if candidate["state"] == "PREPARED":
                connection.execute(
                    """
                    UPDATE codex_transport_dispatches
                    SET state = 'STARTED', thread_id = ?, updated_at_ns = ?
                    WHERE dispatch_id = ? AND state = 'PREPARED' AND attempt_id = ?
                    """,
                    (thread_id, time.time_ns(), dispatch_id, attempt_id),
                )
                if connection.execute("SELECT changes()").fetchone()[0] != 1:
                    raise CodexAppServerTransportError(
                        "Codex dispatch journal start fence was lost"
                    )
            elif candidate["thread_id"] != thread_id:
                raise CodexAppServerTransportError(
                    "Codex dispatch journal task identity conflicts"
                )
            connection.commit()

    def mark_ready(
        self,
        *,
        dispatch_id: str,
        thread_name: str,
        attempt_id: str,
        thread_id: str,
    ) -> None:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM codex_transport_dispatches WHERE dispatch_id = ?",
                (dispatch_id,),
            ).fetchone()
            if row is None:
                raise CodexAppServerTransportError("Codex dispatch journal claim is missing")
            candidate = self._row(
                row, dispatch_id=dispatch_id, thread_name=thread_name
            )
            if (
                candidate["attempt_id"] != attempt_id
                or candidate["thread_id"] != thread_id
                or candidate["state"] not in {"STARTED", "READY"}
            ):
                raise CodexAppServerTransportError(
                    "Codex dispatch journal ready fence is stale"
                )
            if candidate["state"] == "STARTED":
                connection.execute(
                    """
                    UPDATE codex_transport_dispatches
                    SET state = 'READY', updated_at_ns = ?
                    WHERE dispatch_id = ? AND state = 'STARTED'
                        AND attempt_id = ? AND thread_id = ?
                    """,
                    (time.time_ns(), dispatch_id, attempt_id, thread_id),
                )
                if connection.execute("SELECT changes()").fetchone()[0] != 1:
                    raise CodexAppServerTransportError(
                        "Codex dispatch journal ready fence was lost"
                    )
            connection.commit()


class CodexAppServerTransportDriver:
    """Create or read one dormant Codex task for an authority-free PPv4 wake."""

    def __init__(
        self,
        *,
        client: CodexAppServerClient,
        cwd: str | Path,
        journal_path: str | Path,
    ) -> None:
        workspace = Path(cwd)
        if not workspace.is_absolute():
            raise CodexAppServerTransportError("Codex task cwd must be absolute")
        self.client = client
        self.cwd = str(workspace)
        self.journal = CodexAppServerDispatchJournal(journal_path, cwd=workspace)

    @staticmethod
    def _result(outcome: str, dispatch_id: str, thread_id: str) -> dict[str, Any]:
        return {
            "outcome": outcome,
            "dispatch_id": dispatch_id,
            "transport_turn_id": thread_id,
            "execution_started": False,
            "authority_applied": False,
        }

    @staticmethod
    def _validate_created_thread(thread: object, *, thread_name: str) -> str:
        if not isinstance(thread, Mapping):
            raise CodexAppServerTransportError("Codex thread/start omitted the task")
        thread_id = thread.get("id")
        if not isinstance(thread_id, str) or not thread_id:
            raise CodexAppServerTransportError("Codex thread/start returned invalid identity")
        if thread.get("name") != thread_name:
            raise CodexAppServerTransportError(
                "Codex thread/start did not persist the PPv4 dispatch name"
            )
        if thread.get("ephemeral") is not False:
            raise CodexAppServerTransportError("Codex thread/start created an ephemeral task")
        turns = thread.get("turns")
        if turns != []:
            raise CodexAppServerTransportError(
                "Codex thread/start crossed the no-model-execution boundary"
            )
        status = thread.get("status")
        if not isinstance(status, Mapping) or status.get("type") not in {
            "idle",
            "notLoaded",
        }:
            raise CodexAppServerTransportError(
                "Codex thread/start returned an active or invalid task"
            )
        return thread_id

    def start_or_read(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        dispatch_id = request.get("dispatch_id")
        thread_name = _dispatch_name(dispatch_id)
        assert isinstance(dispatch_id, str)
        prepared = self.journal.prepare(
            dispatch_id=dispatch_id,
            thread_name=thread_name,
            request=request,
        )
        if not prepared["claimed"]:
            thread_id = prepared.get("thread_id")
            if prepared["state"] == "READY" and isinstance(thread_id, str):
                return self._result("EXISTS", dispatch_id, thread_id)
            return {
                "outcome": "COMMIT_UNKNOWN",
                "dispatch_id": dispatch_id,
                "execution_started": False,
                "authority_applied": False,
            }
        attempt_id = prepared["attempt_id"]
        assert isinstance(attempt_id, str)
        params = {
            "approvalPolicy": "never",
            "cwd": self.cwd,
            "developerInstructions": (
                "This Codex task is a dormant Integrity PPv4 continuation envelope. "
                "Do not begin work until the signed transport request and receipt are "
                "revalidated by PerpetualDialogueTransportAdapter.admit_turn. The prior "
                "baton's authority is not inherited. Dispatch: "
                + dispatch_id
            ),
            "ephemeral": False,
            "sandbox": "read-only",
        }
        try:
            result = self.client.create_dormant_thread(
                params,
                thread_name=thread_name,
                history_items=[
                    {
                        "type": "message",
                        "role": "developer",
                        "content": [
                            {
                                "type": "input_text",
                                "text": (
                                    "INTEGRITY_PPv4_DORMANT_TRANSPORT\n"
                                    + json.dumps(
                                        dict(request),
                                        sort_keys=True,
                                        separators=(",", ":"),
                                    )
                                ),
                            }
                        ],
                    }
                ],
                on_thread_started=lambda thread_id: self.journal.record_started(
                    dispatch_id=dispatch_id,
                    thread_name=thread_name,
                    attempt_id=attempt_id,
                    thread_id=thread_id,
                ),
            )
        except CodexAppServerCommitUnknown:
            return {
                "outcome": "COMMIT_UNKNOWN",
                "dispatch_id": dispatch_id,
                "execution_started": False,
                "authority_applied": False,
            }
        thread_id = self._validate_created_thread(
            result.get("thread"), thread_name=thread_name
        )
        self.journal.mark_ready(
            dispatch_id=dispatch_id,
            thread_name=thread_name,
            attempt_id=attempt_id,
            thread_id=thread_id,
        )
        return self._result("CREATED", dispatch_id, thread_id)

    def read_by_dispatch_id(self, dispatch_id: str) -> Mapping[str, Any] | None:
        thread_name = _dispatch_name(dispatch_id)
        existing = self.journal.read(dispatch_id=dispatch_id, thread_name=thread_name)
        if existing is None or existing["state"] == "PREPARED":
            return None
        thread_id = existing.get("thread_id")
        assert isinstance(thread_id, str)
        if existing["state"] == "STARTED":
            resumed = self.client.call("thread/resume", {"threadId": thread_id})
            reconciled_id = self._validate_created_thread(
                resumed.get("thread"), thread_name=thread_name
            )
            if reconciled_id != thread_id:
                raise CodexAppServerTransportError(
                    "Codex dispatch journal readback returned another task"
                )
            self.journal.mark_ready(
                dispatch_id=dispatch_id,
                thread_name=thread_name,
                attempt_id=existing["attempt_id"],
                thread_id=thread_id,
            )
        return self._result("EXISTS", dispatch_id, thread_id)


__all__ = [
    "CodexAppServerClient",
    "CodexAppServerCommitUnknown",
    "CodexAppServerDispatchJournal",
    "CodexAppServerStdioClient",
    "CodexAppServerTransportDriver",
    "CodexAppServerTransportError",
]
