"""Bounded initialize-era stdio MCP CLIENT, not a competing Integrity server.

The host admits the exact executable, dependencies, arguments and tool call.
This module neither authenticates operators nor infers authorization from MCP
annotations. An exception after send is unknown; no automatic replay exists.
"""
from __future__ import annotations

import os
import queue
import signal
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

from . import contracts as c
from .media import verified_file


class MCPUnknown(c.ContractError):
    """Connection failed; an already-sent tool invocation must not be retried."""


class StdioClient:
    def __init__(self, executable: Path, executable_sha256: str, args: list[str],
                 *, files: dict[str, str], timeout: float = 10) -> None:
        c.require(type(timeout) in (int, float) and 0 < timeout <= 30, "invalid_timeout")
        executable = Path(os.path.abspath(executable))
        c.validate_mcp({"model_id": "host-selected", "model_revision": "0" * 40,
                        "inference_location": "local", "cloud_opt_in": False,
                        "servers": [{"transport": "stdio", "executable": str(executable),
                                     "executable_sha256": executable_sha256, "args": args}]}, set())
        verified_file(executable, executable_sha256, 64 * 1024 * 1024)
        c.require(type(files) is dict and len(files) <= 32, "artifact_manifest_limit")
        for filename, expected in files.items():
            verified_file(Path(filename), expected, 16 * 1024 * 1024)
        self._timeout = timeout
        self._queue: queue.Queue[bytes | None] = queue.Queue(maxsize=4)
        self._closed = False
        self._lock = threading.Lock()
        self._sequence = 0
        self._initialized = False
        environment = {"PATH": os.defpath, "LANG": "C.UTF-8", "PYTHONIOENCODING": "utf-8"}
        if os.name == "nt":
            environment["SystemRoot"] = os.environ.get("SystemRoot", "C:\\Windows")
        self._process = subprocess.Popen([str(executable), *args], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=environment,
            shell=False, start_new_session=os.name != "nt", bufsize=0)
        self._reader = threading.Thread(target=self._read, daemon=True)
        self._reader.start()

    def _read(self) -> None:
        try:
            while not self._closed:
                raw = self._process.stdout.readline(c.MAX_JSON_BYTES + 2)
                if not raw or len(raw) > c.MAX_JSON_BYTES + 1 or not raw.endswith(b"\n"):
                    raw = None
                self._queue.put(raw, timeout=self._timeout)
                if raw is None:
                    return
        except (OSError, ValueError, queue.Full):
            return

    def _send(self, value: dict[str, Any], deadline: float) -> None:
        raw = c.canonical(value) + b"\n"
        failed = threading.Event()
        def write() -> None:
            try:
                remaining = memoryview(raw)
                while remaining:
                    count = self._process.stdin.write(remaining)
                    if not count:
                        raise OSError("closed input")
                    remaining = remaining[count:]
                self._process.stdin.flush()
            except (OSError, ValueError):
                failed.set()
        writer = threading.Thread(target=write, daemon=True)
        writer.start()
        writer.join(max(0, deadline - time.monotonic()))
        if writer.is_alive() or failed.is_set():
            self.close()
            writer.join(1)
            raise MCPUnknown("mcp_send_unknown_no_retry")

    def _request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        c.require(not self._closed, "mcp_client_closed")
        self._sequence += 1
        identifier = self._sequence
        deadline = time.monotonic() + self._timeout
        self._send({"jsonrpc": "2.0", "id": identifier, "method": method, "params": params}, deadline)
        try:
            for _ in range(32):
                raw = self._queue.get(timeout=max(0.001, deadline - time.monotonic()))
                c.require(raw is not None and time.monotonic() < deadline, "mcp_frame_or_deadline")
                reply = c.load_json(raw.rstrip(b"\n"))
                c.require(type(reply) is dict and reply.get("jsonrpc") == "2.0", "invalid_jsonrpc")
                if "method" in reply:
                    c.require("id" not in reply, "server_requests_not_supported")
                    continue
                c.require(type(reply.get("id")) is int and reply["id"] == identifier,
                          "mcp_response_identity")
                c.require(("result" in reply) != ("error" in reply), "ambiguous_mcp_response")
                c.require("error" not in reply, "mcp_remote_error")
                c.require(type(reply["result"]) is dict, "invalid_mcp_result")
                return reply["result"]
            raise c.ContractError("mcp_notification_limit")
        except (c.ContractError, queue.Empty, OSError, ValueError) as exc:
            self.close()
            raise MCPUnknown("mcp_response_unknown_no_retry") from exc

    def initialize(self) -> dict[str, Any]:
        with self._lock:
            c.require(not self._initialized, "mcp_already_initialized")
            result = self._request("initialize", {
                "protocolVersion": "2025-11-25", "capabilities": {},
                "clientInfo": {"name": "integrity-experience", "version": "0.1.0rc3"}})
            if result.get("protocolVersion") != "2025-11-25":
                self.close()
                raise c.ContractError("unsupported_negotiated_protocol")
            self._send({"jsonrpc": "2.0", "method": "notifications/initialized"},
                       time.monotonic() + self._timeout)
            self._initialized = True
            return result

    def list_tools(self) -> dict[str, Any]:
        with self._lock:
            c.require(self._initialized, "mcp_initialize_required")
            return self._request("tools/list", {})

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """One explicitly host-admitted call. Tool metadata never grants permission."""
        c.text(name, 128)
        c.require(type(arguments) is dict, "invalid_tool_arguments")
        with self._lock:
            c.require(self._initialized, "mcp_initialize_required")
            result = self._request("tools/call", {"name": name, "arguments": arguments})
            return c.candidate("mcp-result", {"tool": name,
                "arguments_sha256": c.sha(c.canonical(arguments)), "result": result,
                "epistemic_state": "unverified_tool_response", "automatic_retry_allowed": False})

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._process.poll() is None:
            try:
                if os.name == "posix":
                    os.killpg(self._process.pid, signal.SIGKILL)
                else:
                    self._process.kill()
            except ProcessLookupError:
                pass
        try:
            self._process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self._process.kill()
        for stream in (self._process.stdin, self._process.stdout):
            try:
                stream.close()
            except OSError:
                pass
        if threading.current_thread() is not self._reader:
            self._reader.join(1)

    def __enter__(self) -> StdioClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
