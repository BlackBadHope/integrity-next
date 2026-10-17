# SPDX-License-Identifier: Apache-2.0
"""Bounded host adapter; stdio locally, authenticated loopback through SSH remotely."""
from __future__ import annotations

from integrity_bridges.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import hashlib
import hmac
import json
import os
import socket
import socketserver
import sqlite3
import sys
import threading
from contextlib import closing
from pathlib import Path

import claude_owner
import unified_mcp as core

DISPATCH = core.call_tool

MAX_FRAME = 1024 * 1024
# codex_pong is idempotent through its own handoff ledger (a replay returns the stored PONG) and a
# waiting PONG must be polled again, so it is dispatched as a read; codex_ping sends a prompt.
READS = {"codex_list_models", "codex_list_tasks", "codex_read_task", "codex_wait_pong", "codex_pong",
         "codex_operation_status", "claude_list_tasks", "claude_read_task",
         "claude_operation_status"}
WRITES = {"codex_send_prompt", "codex_ping", "codex_interrupt_turn", "codex_archive_task",
          "codex_unarchive_task", "codex_copy_turn", "claude_send_prompt"}

DEFINITIVE_REJECTIONS = {
    "invalid_thread_id", "invalid_prompt", "invalid_steer_mode", "invalid_steer_reason",
    "invalid_model", "invalid_effort", "unexpected_model_catalog_arguments",
    "effort_requires_model", "executor_override_requires_idle_task",
    "codex_expected_turn_mismatch", "codex_expected_turn_not_active",
    "codex_model_unavailable", "codex_model_catalog_invalid",
    "codex_model_catalog_incomplete", "codex_model_catalog_empty",
    "codex_effort_unsupported", "emergency_steer_requires_expected_turn",
    "emergency_steer_reason_required", "interrupt_confirmation_required",
    "archive_confirmation_required", "restore_confirmation_required",
    "codex_turn_not_active", "codex_task_not_idle", "codex_task_not_completed",
    "codex_native_interrupt_unavailable", "codex_desktop_owner_unavailable",
    "codex_turn_not_found", "codex_task_has_no_turn", "codex_turn_not_final",
    "target_host_has_no_clipboard", "clipboard_requires_windows",
    "invalid_limit", "invalid_turn_limit",
    "claude_task_not_found", "claude_task_not_idle", "provider_environment_refused",
    "claude_binary_digest_changed", "claude_mcp_config_changed",
    "claude_subscription_auth_required",
    "claude_auth_unavailable", "claude_owner_preflight_failed",
    # Handoff checks codex_ping makes before it sends anything.
    "handoff_workflow_stopped", "handoff_pong_pending_for_previous_ping",
    "handoff_thread_bound_to_active_workflow", "handoff_workflow_identity_conflict",
    "handoff_exact_web_target_required", "handoff_invalid_workflow_identity",
    "handoff_scope_shape_invalid", "handoff_scope_goal_invalid", "handoff_scope_targets_invalid",
    "handoff_scope_effect_class_invalid", "handoff_scope_acceptance_invalid",
    "handoff_scope_verification_invalid", "handoff_workflow_target_mismatch", "handoff_no_ping_waiting",
}


def definitive_rejection(message):
    return message in DEFINITIVE_REJECTIONS or message.startswith("codex_owner_lifecycle_")


class Node:
    def __init__(self, host_id, ledger, claude_config=None):
        self.host_id = host_id
        self.claude = None
        if claude_config:
            try:
                self.claude = claude_owner.Owner(claude_config)
            except (claude_owner.ClaudeError, OSError, ValueError, KeyError):
                core.safe_log("claude_owner_unavailable")
        self.ledger = Path(ledger)
        self.ledger.parent.mkdir(parents=True, exist_ok=True)
        self.write_lock = threading.Lock()
        with closing(sqlite3.connect(self.ledger)) as db, db:
            db.execute("CREATE TABLE IF NOT EXISTS operations (id TEXT PRIMARY KEY, digest TEXT NOT NULL, result TEXT)")
            db.execute("CREATE TABLE IF NOT EXISTS operation_rejections (id TEXT PRIMARY KEY, error TEXT NOT NULL)")
            columns = {row[1] for row in db.execute("PRAGMA table_info(operations)")}
            if "error" in columns:
                # Restore the original three-column ledger so an ordinary binary
                # rollback remains writable. Durable rejections live separately.
                db.execute(
                    "INSERT OR REPLACE INTO operation_rejections (id, error) "
                    "SELECT id, error FROM operations WHERE error IS NOT NULL"
                )
                db.execute("ALTER TABLE operations RENAME TO operations_with_error")
                db.execute("CREATE TABLE operations (id TEXT PRIMARY KEY, digest TEXT NOT NULL, result TEXT)")
                db.execute(
                    "INSERT INTO operations (id, digest, result) "
                    "SELECT id, digest, result FROM operations_with_error"
                )
                db.execute("DROP TABLE operations_with_error")

    def operation_status(self, operation):
        if not isinstance(operation, str) or not core.THREAD_ID.fullmatch(operation):
            raise core.RpcError("stable_request_id_required")
        with closing(sqlite3.connect(f"file:{self.ledger}?mode=ro", uri=True)) as db:
            row = db.execute(
                "SELECT o.digest, o.result, r.error FROM operations AS o "
                "LEFT JOIN operation_rejections AS r ON r.id=o.id WHERE o.id=?",
                (operation,),
            ).fetchone()
        if row is None:
            return {"request_id": operation, "found": False, "state": "absent"}
        state = "acknowledged" if row[1] is not None else "rejected" if row[2] is not None else "unknown"
        payload = {"request_id": operation, "found": True, "state": state,
                   "request_digest": row[0]}
        if row[1] is not None:
            # Recovery after a lost response must return the exact stored
            # acknowledgement rather than invite a second write.
            payload["response"] = json.loads(row[1])
        if row[2] is not None:
            payload["error"] = row[2]
        return payload

    def call(self, request):
        if not isinstance(request, dict):
            raise core.RpcError("invalid_host_request")
        if request.get("host_id") != self.host_id:
            raise core.RpcError("host_identity_mismatch")
        name, args = request.get("name"), request.get("arguments")
        if name not in READS | WRITES or not isinstance(args, dict):
            raise core.RpcError("unsupported_host_operation")
        if name in {"codex_operation_status", "claude_operation_status"}:
            return core.pack_payload(self.operation_status(args.get("request_id")))
        if name in READS:
            return self.dispatch(name, args)
        operation = request.get("request_id")
        if not isinstance(operation, str) or not core.THREAD_ID.fullmatch(operation):
            raise core.RpcError("stable_request_id_required")
        digest = hashlib.sha256(json.dumps([name, args], sort_keys=True, ensure_ascii=False).encode()).hexdigest()
        with self.write_lock, closing(sqlite3.connect(self.ledger)) as db, db:
            row = db.execute(
                "SELECT o.digest, o.result, r.error FROM operations AS o "
                "LEFT JOIN operation_rejections AS r ON r.id=o.id WHERE o.id=?",
                (operation,),
            ).fetchone()
            if row:
                if row[0] != digest:
                    raise core.RpcError("request_id_content_conflict")
                if row[2] is not None:
                    raise core.RpcError(row[2])
                if row[1] is None:
                    raise core.RpcError("operation_outcome_unknown_read_task_before_any_new_send")
                return json.loads(row[1])
            db.execute(
                "INSERT INTO operations (id, digest, result) VALUES (?, ?, NULL)",
                (operation, digest),
            )
            db.commit()  # Persist before dispatch: a lost acknowledgement never retries a write.
            try:
                result = self.dispatch(name, args)
            except core.RpcError as exc:
                message = str(exc)
                if definitive_rejection(message):
                    db.execute(
                        "INSERT OR REPLACE INTO operation_rejections (id, error) VALUES (?, ?)",
                        (operation, message),
                    )
                    db.commit()
                raise
            db.execute("UPDATE operations SET result=? WHERE id=?", (json.dumps(result), operation))
            db.commit()
            return result

    def dispatch(self, name, args):
        if name.startswith("claude_"):
            if self.claude is None:
                raise core.RpcError("claude_owner_unavailable")
            try:
                return core.pack_payload(self.claude.call_tool(name, args))
            except claude_owner.ClaudeError as exc:
                raise core.RpcError(str(exc)) from exc
        return DISPATCH(name, args)


def envelope(node, request):
    try:
        return {"result": node.call(request), "host_id": node.host_id}
    except (core.RpcError, OSError, ValueError, TypeError) as exc:
        message = str(exc) if isinstance(exc, core.RpcError) else type(exc).__name__
        return {"error": message, "host_id": node.host_id}


class PeerClient:
    def __init__(self, host_id, config):
        self.host_id, self.config = host_id, config

    def call(self, name, arguments, request_id=None):
        request = {"host_id": self.host_id, "name": name, "arguments": arguments, "request_id": request_id}
        token = Path(self.config["token_file"]).read_text(encoding="ascii").strip()
        request["token"] = token
        try:
            with socket.create_connection(("127.0.0.1", self.config["port"]), timeout=5) as peer:
                peer.settimeout(90)
                peer.sendall(json.dumps(request, ensure_ascii=False).encode("utf-8") + b"\n")
                with peer.makefile("rb") as reader:
                    raw = reader.readline(MAX_FRAME + 1)
                if len(raw) > MAX_FRAME or not raw.endswith(b"\n"):
                    raise core.RpcError("invalid_peer_frame")
                result = json.loads(raw)
        except (OSError, ValueError) as exc:
            raise core.RpcError(f"host_unavailable:{self.host_id};no_automatic_write_retry") from exc
        if result.get("host_id") != self.host_id:
            raise core.RpcError("peer_host_identity_mismatch")
        if "error" in result:
            raise core.RpcError(result["error"])
        return result["result"]


def serve(node, port, token_file):
    token = Path(token_file).read_text(encoding="ascii").strip()
    if len(token) < 32:
        raise ValueError("invalid_peer_token")
    slots = threading.BoundedSemaphore(8)

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.connection.settimeout(90)
            if not slots.acquire(blocking=False):
                return
            try:
                raw = self.rfile.readline(MAX_FRAME + 1)
                if len(raw) > MAX_FRAME or not raw.endswith(b"\n"):
                    return
                request = json.loads(raw)
                supplied = request.pop("token", "")
                if not isinstance(supplied, str) or not hmac.compare_digest(supplied, token):
                    return
                response = envelope(node, request)
                self.wfile.write(json.dumps(response, ensure_ascii=False).encode("utf-8") + b"\n")
            except (OSError, ValueError, TypeError):
                core.safe_log("peer_request_failed")
            finally:
                slots.release()

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True
    with Server(("127.0.0.1", port), Handler) as server:
        server.serve_forever(poll_interval=0.5)


def configure_owner_route(route, command_json=None):
    """Bind one explicit writer route before the lazy Codex backend starts."""
    if route == "desktop":
        if command_json is not None:
            raise ValueError("codex_command_requires_owner_proxy")
        os.environ["INTEGRITY_REQUIRE_DESKTOP"] = "1"
        return
    if route != "owner_proxy" or command_json is None:
        raise ValueError("owner_proxy_command_required")
    command = json.loads(command_json)
    if (not isinstance(command, list) or not command or
            any(not isinstance(part, str) or not part for part in command)):
        raise ValueError("invalid_owner_proxy_command")
    os.environ.pop("INTEGRITY_REQUIRE_DESKTOP", None)
    os.environ["INTEGRITY_CODEX_OWNER_PROXY"] = "1"
    os.environ["INTEGRITY_CODEX_COMMAND"] = json.dumps(command)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host-id", required=True)
    parser.add_argument("--ledger", required=True)
    parser.add_argument("--port", type=int)
    parser.add_argument("--token-file")
    parser.add_argument("--owner-route", choices=("desktop", "owner_proxy"), default="desktop")
    parser.add_argument("--codex-command-json")
    parser.add_argument("--claude-config")
    opts = parser.parse_args()
    node = Node(opts.host_id, opts.ledger, opts.claude_config)
    if opts.port:
        configure_owner_route(opts.owner_route, opts.codex_command_json)
        serve(node, opts.port, opts.token_file)
    else:
        for line in sys.stdin.buffer:
            request = json.loads(line)
            response = envelope(node, request)
            sys.stdout.buffer.write(json.dumps(response, ensure_ascii=False).encode("utf-8") + b"\n")
            sys.stdout.buffer.flush()


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    main()
