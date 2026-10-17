# SPDX-License-Identifier: Apache-2.0
"""Local Claude Code task owner for the existing Integrity host link.

The hub delivers task requests; this module owns subscription CLI sessions on the
enrolled Windows host.  A delivery acknowledgement is never a completion claim.
"""
from __future__ import annotations

from integrity_bridges.configuration import value as _integrity_value, require_config as _integrity_require_config

import hashlib
import json
import os
import sqlite3
import subprocess
import threading
import time
import uuid
from contextlib import closing
from pathlib import Path

MAX_PROMPT = 8_000
MAX_OUTPUT = 60_000
MAX_STREAM = 8 * 1024 * 1024
FINAL = {"completed", "failed", "interrupted", "unknown"}
API_ENV = {"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN"}


class ClaudeError(RuntimeError):
    pass


def _uuid(value, label):
    try:
        return str(uuid.UUID(value))
    except (TypeError, ValueError, AttributeError) as exc:
        raise ClaudeError(f"invalid_{label}") from exc


def _text(value, label, limit):
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ClaudeError(f"invalid_{label}")
    return value


def definitions():
    host = {"type": "string", "description": "Exact enrolled host from claude_list_hosts."}
    task = {"type": "string", "format": "uuid"}
    request = {"type": "string", "minLength": 8, "maxLength": 128}
    return [
        {"name": "claude_list_tasks", "title": "List Claude tasks",
         "description": "List bounded Claude Code sessions owned by this Integrity host link.",
         "inputSchema": {"type": "object", "properties": {"host_id": host,
             "limit": {"type": "integer", "minimum": 1, "maximum": 5}},
             "required": ["host_id"], "additionalProperties": False},
         "annotations": {"readOnlyHint": True, "destructiveHint": False}},
        {"name": "claude_read_task", "title": "Read Claude task",
         "description": "Read one task and its recent turns. Running is not a terminal outcome.",
         "inputSchema": {"type": "object", "properties": {"host_id": host,
             "thread_id": task, "turn_limit": {"type": "integer", "minimum": 1, "maximum": 20}},
             "required": ["host_id", "thread_id"], "additionalProperties": False},
         "annotations": {"readOnlyHint": True, "destructiveHint": False}},
        {"name": "claude_send_prompt", "title": "Start or continue Claude task",
         "description": "Start a new subscription CLI task when thread_id is omitted, or continue an exact idle task. Returns a turn ID for readback; it does not prove execution or success. This host runs Claude with its configured full-access profile. Requires the owner's explicit task instruction.",
         "inputSchema": {"type": "object", "properties": {"host_id": host,
             "thread_id": task, "prompt": {"type": "string", "minLength": 1, "maxLength": MAX_PROMPT},
             "request_id": request}, "required": ["host_id", "prompt", "request_id"],
             "additionalProperties": False},
         "annotations": {"readOnlyHint": False, "destructiveHint": False,
                         "idempotentHint": False}},
        {"name": "claude_operation_status", "title": "Inspect Claude delivery",
         "description": "Read durable host-link delivery for one request ID without retrying it.",
         "inputSchema": {"type": "object", "properties": {"host_id": host,
             "request_id": request}, "required": ["host_id", "request_id"],
             "additionalProperties": False},
         "annotations": {"readOnlyHint": True, "destructiveHint": False}},
    ]


class Owner:
    def __init__(self, config_path):
        config = json.loads(Path(config_path).read_text(encoding="utf-8"))
        if config.get("schema") != "integrity-claude-owner/v1":
            raise ClaudeError("invalid_claude_owner_config")
        self.binary = Path(config["binary"]).resolve(strict=True)
        self.workspace = Path(config["workspace"]).resolve(strict=True)
        self.state = Path(config["state_dir"]).resolve(strict=True)
        self.mcp_config = Path(config["mcp_config"]).resolve(strict=True)
        self.digest = _text(config["binary_sha256"], "binary_digest", 64).lower()
        self.mcp_digest = _text(config["mcp_sha256"], "mcp_digest", 64).lower()
        if (os.name != "nt" or not self.binary.is_file() or not self.workspace.is_dir()
                or not self.state.is_dir() or not self.mcp_config.is_file()
                or config.get("permission_profile") != "full_access"):
            raise ClaudeError("claude_owner_preflight_failed")
        self.db = self.state / "tasks.sqlite3"
        self.lock = threading.RLock()
        self.processes = {}
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute("CREATE TABLE IF NOT EXISTS tasks (id TEXT PRIMARY KEY, session_id TEXT NOT NULL, created REAL NOT NULL, updated REAL NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS turns (id TEXT PRIMARY KEY, task_id TEXT NOT NULL, prompt TEXT NOT NULL, output TEXT NOT NULL DEFAULT '', status TEXT NOT NULL, error TEXT, created REAL NOT NULL, updated REAL NOT NULL)")
            db.execute("UPDATE turns SET status='unknown', error='owner_restarted_before_terminal_readback', updated=? WHERE status IN ('starting','running')", (time.time(),))

    def _connect(self):
        return sqlite3.connect(self.db, timeout=10)

    def _preflight(self):
        if API_ENV.intersection(name.upper() for name in os.environ):
            raise ClaudeError("provider_environment_refused")
        if hashlib.sha256(self.binary.read_bytes()).hexdigest() != self.digest:
            raise ClaudeError("claude_binary_digest_changed")
        if hashlib.sha256(self.mcp_config.read_bytes()).hexdigest() != self.mcp_digest:
            raise ClaudeError("claude_mcp_config_changed")
        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        try:
            auth = subprocess.run([str(self.binary), "--safe-mode", "auth", "status", "--json"],
                cwd=self.workspace, capture_output=True, timeout=15, creationflags=flags, check=False)
            payload = json.loads(auth.stdout)
        except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
            raise ClaudeError("claude_auth_unavailable") from exc
        if auth.returncode != 0 or payload.get("loggedIn") is not True or payload.get("authMethod") != "claude.ai":
            raise ClaudeError("claude_subscription_auth_required")

    def list_tasks(self, args):
        limit = args.get("limit", 5)
        if type(limit) is not int or not 1 <= limit <= 5:
            raise ClaudeError("invalid_limit")
        with self.lock, closing(self._connect()) as db:
            rows = db.execute("SELECT t.id, t.updated, x.status, substr(x.prompt,1,120) FROM tasks t LEFT JOIN turns x ON x.id=(SELECT id FROM turns WHERE task_id=t.id ORDER BY created DESC LIMIT 1) ORDER BY t.updated DESC LIMIT ?", (limit,)).fetchall()
        return {"tasks": [{"thread_id": row[0], "updated_at": row[1],
                            "status": row[2], "preview": row[3]} for row in rows]}

    def read_task(self, args):
        task = _uuid(args.get("thread_id"), "thread_id")
        limit = args.get("turn_limit", 8)
        if type(limit) is not int or not 1 <= limit <= 20:
            raise ClaudeError("invalid_turn_limit")
        with self.lock, closing(self._connect()) as db:
            row = db.execute("SELECT id,created,updated FROM tasks WHERE id=?", (task,)).fetchone()
            if row is None:
                raise ClaudeError("claude_task_not_found")
            turns = db.execute("SELECT id,prompt,output,status,error,created,updated FROM turns WHERE task_id=? ORDER BY created DESC LIMIT ?", (task, limit)).fetchall()
        return {"thread_id": task, "created_at": row[1], "updated_at": row[2],
                "turns": [{"turn_id": x[0], "prompt": x[1], "output": x[2],
                           "status": x[3], "error": x[4], "created_at": x[5],
                           "updated_at": x[6]} for x in reversed(turns)]}

    def send_prompt(self, args):
        prompt = _text(args.get("prompt"), "prompt", MAX_PROMPT)
        task = _uuid(args["thread_id"], "thread_id") if "thread_id" in args else str(uuid.uuid4())
        turn = str(uuid.uuid4())
        self._preflight()
        now = time.time()
        with self.lock, closing(self._connect()) as db, db:
            prior = db.execute("SELECT session_id FROM tasks WHERE id=?", (task,)).fetchone()
            if "thread_id" in args and prior is None:
                raise ClaudeError("claude_task_not_found")
            if "thread_id" not in args:
                db.execute("INSERT INTO tasks(id,session_id,created,updated) VALUES(?,?,?,?)", (task, task, now, now))
            else:
                latest = db.execute("SELECT status FROM turns WHERE task_id=? ORDER BY created DESC LIMIT 1", (task,)).fetchone()
                if latest and latest[0] not in {"completed", "failed", "interrupted"}:
                    raise ClaudeError("claude_task_not_idle")
                db.execute("UPDATE tasks SET updated=? WHERE id=?", (now, task))
            db.execute("INSERT INTO turns(id,task_id,prompt,status,created,updated) VALUES(?,?,?,?,?,?)", (turn, task, prompt, "starting", now, now))
        threading.Thread(target=self._run, args=(task, turn, prompt, prior is not None),
                         name="integrity-claude-turn", daemon=True).start()
        return {"thread_id": task, "turn_id": turn, "status": "starting",
                "execution_complete": False}

    def _update(self, task, turn, *, status=None, output=None, error=None):
        with self.lock, closing(self._connect()) as db, db:
            fields = ["updated=?"]
            values = [time.time()]
            for key, value in (("status", status), ("output", output), ("error", error)):
                if value is not None:
                    fields.append(f"{key}=?")
                    values.append(value)
            values.append(turn)
            db.execute(f"UPDATE turns SET {','.join(fields)} WHERE id=?", values)
            db.execute("UPDATE tasks SET updated=? WHERE id=?", (time.time(), task))

    def _run(self, task, turn, prompt, resume):
        argv = [str(self.binary), "-p", "--input-format", "text", "--output-format",
                "stream-json", "--verbose", "--strict-mcp-config", "--mcp-config",
                str(self.mcp_config), "--dangerously-skip-permissions"]
        argv.extend(["--resume" if resume else "--session-id", task])
        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        observed = ""
        result_error = False
        timed_out = threading.Event()
        timer = None
        try:
            proc = subprocess.Popen(argv, cwd=self.workspace, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                creationflags=flags, shell=False)
            with self.lock:
                self.processes[turn] = proc
            def expire():
                if proc.poll() is None:
                    timed_out.set()
                    proc.terminate()
            timer = threading.Timer(3600, expire)
            timer.daemon = True
            timer.start()
            self._update(task, turn, status="running")
            assert proc.stdin and proc.stdout
            proc.stdin.write(prompt.encode("utf-8"))
            proc.stdin.close()
            total = 0
            for raw in proc.stdout:
                total += len(raw)
                if total > MAX_STREAM:
                    proc.terminate()
                    raise ClaudeError("claude_stream_limit")
                try:
                    item = json.loads(raw)
                except ValueError:
                    continue
                if item.get("type") == "assistant":
                    blocks = (item.get("message") or {}).get("content") or []
                    text = "\n".join(b.get("text", "") for b in blocks
                                     if isinstance(b, dict) and b.get("type") == "text")
                    if text:
                        observed = (observed + "\n" + text).strip()[-MAX_OUTPUT:]
                        self._update(task, turn, output=observed)
                elif item.get("type") == "result":
                    result_error = item.get("is_error") is True
                    result = item.get("result")
                    if isinstance(result, str) and result:
                        observed = result[-MAX_OUTPUT:]
                        self._update(task, turn, output=observed)
            code = proc.wait(timeout=5)
            status = "unknown" if timed_out.is_set() else "failed" if code or result_error else "completed"
            error = "claude_timeout_stop_unverified" if timed_out.is_set() else "claude_error" if code or result_error else ""
            self._update(task, turn, status=status, output=observed, error=error)
        except (OSError, ValueError, ClaudeError, subprocess.TimeoutExpired) as exc:
            self._update(task, turn, status="unknown", error=type(exc).__name__)
        finally:
            if timer is not None:
                timer.cancel()
            with self.lock:
                self.processes.pop(turn, None)

    def call_tool(self, name, args):
        if name == "claude_list_tasks":
            return self.list_tasks(args)
        if name == "claude_read_task":
            return self.read_task(args)
        if name == "claude_send_prompt":
            return self.send_prompt(args)
        raise ClaudeError("unsupported_claude_operation")
