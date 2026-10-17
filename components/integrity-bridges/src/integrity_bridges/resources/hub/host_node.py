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

import unified_mcp as core

DISPATCH = core.call_tool

MAX_FRAME = 1024 * 1024
READS = {"codex_list_models", "codex_list_tasks", "codex_read_task",
         "codex_operation_status", "codex_prepare_delegated_task"}
WRITES = {"codex_send_prompt", "codex_interrupt_turn", "codex_archive_task",
          "codex_unarchive_task", "codex_copy_turn"}

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
    "target_host_has_no_clipboard", "clipboard_requires_windows",
}


def definitive_rejection(message):
    return message in DEFINITIVE_REJECTIONS or message.startswith("codex_owner_lifecycle_")


class Node:
    def __init__(self, host_id, ledger):
        self.host_id = host_id
        self.ledger = Path(ledger)
        self.ledger.parent.mkdir(parents=True, exist_ok=True)
        self.write_lock = threading.Lock()
        with closing(sqlite3.connect(self.ledger)) as db, db:
            db.execute("CREATE TABLE IF NOT EXISTS operations (id TEXT PRIMARY KEY, digest TEXT NOT NULL, result TEXT)")
            columns = {row[1] for row in db.execute("PRAGMA table_info(operations)")}
            if "error" not in columns:
                db.execute("ALTER TABLE operations ADD COLUMN error TEXT")

    def operation_status(self, operation):
        if not isinstance(operation, str) or not core.THREAD_ID.fullmatch(operation):
            raise core.RpcError("stable_request_id_required")
        with closing(sqlite3.connect(f"file:{self.ledger}?mode=ro", uri=True)) as db:
            row = db.execute(
                "SELECT digest, result, error FROM operations WHERE id=?", (operation,)
            ).fetchone()
        if row is None:
            return {"request_id": operation, "found": False, "state": "absent"}
        state = "completed" if row[1] is not None else "rejected" if row[2] is not None else "unknown"
        payload = {"request_id": operation, "found": True, "state": state,
                   "request_digest": row[0]}
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
        if name == "codex_operation_status":
            return core.pack_payload(self.operation_status(args.get("request_id")))
        if name == "codex_prepare_delegated_task" and self.host_id not in core.delegation_transport.SUPPORTED_HOSTS:
            raise core.RpcError("delegation_prepare_host_not_supported")
        if name in READS:
            if self.host_id == "node-linux" and name == "codex_prepare_delegated_task":
                return DISPATCH(name, args, delegation_host_id=self.host_id)
            return DISPATCH(name, args)
        operation = request.get("request_id")
        if not isinstance(operation, str) or not core.THREAD_ID.fullmatch(operation):
            raise core.RpcError("stable_request_id_required")
        if name == "codex_send_prompt":
            if core.delegation_transport.is_preparation_prompt(args.get("prompt")):
                if self.host_id not in core.delegation_transport.SUPPORTED_HOSTS:
                    raise core.RpcError("delegation_prepare_host_not_supported")
                try:core.delegation_transport.preparation_arguments(args.get("prompt"),args.get("thread_id"))
                except core.delegation_transport.BoundaryError as exc:raise core.RpcError(str(exc)) from None
                delegated=None
            else:delegated=core.validate_delegation_prompt(args.get("prompt"),args.get("thread_id"),target_host_id=self.host_id)
            if delegated is not None and operation != delegated["operation_id"]:
                raise core.RpcError("delegation_transport_operation_mismatch")
        digest = hashlib.sha256(json.dumps([name, args], sort_keys=True, ensure_ascii=False).encode()).hexdigest()
        with self.write_lock, closing(sqlite3.connect(self.ledger)) as db, db:
            row = db.execute(
                "SELECT digest, result, error FROM operations WHERE id=?", (operation,)
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
                "INSERT INTO operations (id, digest, result, error) VALUES (?, ?, NULL, NULL)",
                (operation, digest),
            )
            db.commit()  # Persist before dispatch: a lost acknowledgement never retries a write.
            try:
                if self.host_id == "node-linux" and name == "codex_send_prompt":
                    result = DISPATCH(name, args, delegation_host_id=self.host_id)
                else:result = DISPATCH(name, args)
            except core.RpcError as exc:
                message = str(exc)
                if definitive_rejection(message):
                    db.execute("UPDATE operations SET error=? WHERE id=?", (message, operation))
                    db.commit()
                raise
            db.execute("UPDATE operations SET result=? WHERE id=?", (json.dumps(result), operation))
            db.commit()
            return result


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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host-id", required=True)
    parser.add_argument("--ledger", required=True)
    parser.add_argument("--port", type=int)
    parser.add_argument("--token-file")
    opts = parser.parse_args()
    node = Node(opts.host_id, opts.ledger)
    if opts.port:
        os.environ["INTEGRITY_REQUIRE_DESKTOP"] = "1"
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
