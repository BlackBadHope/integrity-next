# SPDX-License-Identifier: Apache-2.0
"""Unified stdio MCP: Integrity private memory plus bounded local Codex task access."""

from __future__ import annotations

from integrity_client_memory.configuration import (
    ConfigurationError,
    configured_command,
    read_config,
    require_config as _integrity_require_config,
    value as _integrity_value,
)

import atexit
import ctypes
import hashlib
import json
import os
import queue
import re
import shlex
import struct
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from ctypes import wintypes
from pathlib import Path

VERSION = "0.6.0"
MODERN_MCP_VERSION = "2026-07-28"
PROTOCOL_VERSION_META_KEY = "io.modelcontextprotocol/protocolVersion"
CLIENT_INFO_META_KEY = "io.modelcontextprotocol/clientInfo"
CLIENT_CAPABILITIES_META_KEY = "io.modelcontextprotocol/clientCapabilities"
SERVER_INFO_META_KEY = "io.modelcontextprotocol/serverInfo"
LOG_LEVEL_META_KEY = "io.modelcontextprotocol/logLevel"
MODERN_META_KEYS = {
    PROTOCOL_VERSION_META_KEY,
    CLIENT_INFO_META_KEY,
    CLIENT_CAPABILITIES_META_KEY,
    LOG_LEVEL_META_KEY,
}
MODERN_TOOL_CACHE_TTL_MS = 300_000
MAX_PROMPT = 8_000
MAX_MESSAGE = 12_000
MAX_RESULT = 60_000
READ_CHUNK = 4_096
MODEL_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
CODEX_APP_TOOLS_PIPE_ENV = "CODEX_APP_TOOLS_PIPE_PATH"
CODEX_APP_TOOLS_NAMESPACE = "codex_app"
CODEX_HOST_TIMEOUT = 10.0
FINAL_TURN_STATUSES = {"completed", "failed", "interrupted", "cancelled"}
THREAD_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:_-]{7,127}$")
HERE = Path(__file__).resolve().parent
LOG_PATH = Path(os.environ.get("LOCALAPPDATA", str(HERE))) / "IntegrityPrivateMemory" / "bridge-events.log"
LOG_LOCK = threading.Lock()
CODEX = os.environ.get(
    "INTEGRITY_CODEX_BIN",
    str(Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "OpenAI" /
        "Codex" / "bin" / "codex.exe"),
)
MEMORY_COMMAND = os.environ.get(
    "INTEGRITY_MEMORY_COMMAND",
    configured_command('upstream_mcp_command', 'command_b734f1f83ce5'),
)


class RpcError(RuntimeError):
    pass


def safe_log(event: str, **fields):
    """Content-free local diagnostics; never record arguments, prompts, or results."""
    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        record = {"time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": event}
        record.update(fields)
        with LOG_LOCK, LOG_PATH.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(record, ensure_ascii=True, separators=(",", ":")) + "\n")
    except Exception:  # noqa: BLE001, S110 - diagnostics must not interrupt RPC delivery
        pass


class JsonLineRpc:
    def __init__(self, argv: list[str]):
        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        self.proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            shell=False,
            creationflags=flags,
        )
        self._lock = threading.Lock()
        self._pending: dict[int, queue.Queue] = {}
        self._notifications: queue.Queue = queue.Queue()
        self._counter = 0
        threading.Thread(target=self._read_stdout, daemon=True).start()
        threading.Thread(target=self._drain_stderr, daemon=True).start()
        safe_log("backend_started", executable=Path(argv[0]).name)

    def _read_stdout(self):
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                safe_log("backend_invalid_json")
                continue
            message_id = message.get("id")
            if isinstance(message_id, int):
                target = self._pending.get(message_id)
                if target is not None:
                    target.put(message)
            elif isinstance(message.get("method"), str):
                self._notifications.put(message)

    def _drain_stderr(self):
        assert self.proc.stderr is not None
        for _ in self.proc.stderr:
            safe_log("backend_stderr", executable=Path(str(self.proc.args[0])).name)

    def notify(self, method: str, params: dict):
        self._write({"jsonrpc": "2.0", "method": method, "params": params})

    def _write(self, message: dict):
        if self.proc.poll() is not None:
            raise RpcError("backend_unavailable")
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(message, ensure_ascii=False, separators=(",", ":")) + "\n")
        self.proc.stdin.flush()

    def request(self, method: str, params: dict, timeout: float = 20.0) -> dict:
        with self._lock:
            self._counter += 1
            message_id = self._counter
            target: queue.Queue = queue.Queue(maxsize=1)
            self._pending[message_id] = target
            try:
                self._write({"jsonrpc": "2.0", "id": message_id, "method": method, "params": params})
                response = target.get(timeout=timeout)
            except queue.Empty as exc:
                safe_log("backend_retired", method=method, reason="timeout")
                self.close()
                raise RpcError(f"backend_timeout:{method}") from exc
            finally:
                self._pending.pop(message_id, None)
        if "error" in response:
            error = response.get("error") or {}
            raise RpcError(str(error.get("message") or "backend_rejected"))
        result = response.get("result")
        if not isinstance(result, dict):
            raise RpcError("invalid_backend_result")
        return result

    def wait_notification(self, method: str, predicate, timeout: float) -> dict:
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RpcError(f"backend_timeout:{method}")
            try:
                message = self._notifications.get(timeout=remaining)
            except queue.Empty as exc:
                raise RpcError(f"backend_timeout:{method}") from exc
            if message.get("method") != method:
                continue
            params = message.get("params")
            if isinstance(params, dict) and predicate(params):
                return params

    def close(self):
        if self.proc.poll() is None:
            try:
                assert self.proc.stdin is not None
                self.proc.stdin.close()
            except Exception:  # noqa: BLE001, S110 - retain process termination fallback
                pass
            try:
                self.proc.wait(2)
            except subprocess.TimeoutExpired:
                self.proc.terminate()
                try:
                    self.proc.wait(2)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
                    self.proc.wait(2)


class _ProcessEntry32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


class _ProcessBasicInformation(ctypes.Structure):
    _fields_ = [
        ("Reserved1", ctypes.c_void_p),
        ("PebBaseAddress", ctypes.c_void_p),
        ("Reserved2_0", ctypes.c_void_p),
        ("Reserved2_1", ctypes.c_void_p),
        ("UniqueProcessId", ctypes.c_void_p),
        ("Reserved3", ctypes.c_void_p),
    ]


def _codex_process_ids() -> list[int]:
    """Enumerate local Codex processes without importing optional packages."""
    if os.name != "nt":
        return []
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ProcessEntry32W)]
    kernel32.Process32FirstW.restype = wintypes.BOOL
    kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ProcessEntry32W)]
    kernel32.Process32NextW.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    snapshot = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
    invalid_handle = ctypes.c_void_p(-1).value
    if snapshot == invalid_handle:
        return []
    entry = _ProcessEntry32W()
    entry.dwSize = ctypes.sizeof(entry)
    result: list[int] = []
    try:
        ok = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while ok:
            if entry.szExeFile.lower() == "codex.exe":
                result.append(int(entry.th32ProcessID))
            ok = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)
    return result


def _read_process_environment_value(process_id: int, key: str) -> str | None:
    """Read one environment value from a same-user 64-bit Windows process."""
    if os.name != "nt" or ctypes.sizeof(ctypes.c_void_p) != 8:
        return None
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    ntdll = ctypes.WinDLL("ntdll")
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.ReadProcessMemory.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.ReadProcessMemory.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    ntdll.NtQueryInformationProcess.argtypes = [
        wintypes.HANDLE,
        wintypes.ULONG,
        ctypes.c_void_p,
        wintypes.ULONG,
        ctypes.POINTER(wintypes.ULONG),
    ]
    ntdll.NtQueryInformationProcess.restype = wintypes.LONG
    handle = kernel32.OpenProcess(0x0400 | 0x0010, False, process_id)
    if not handle:
        return None

    def read_memory(address: int, size: int) -> bytes:
        buffer = (ctypes.c_ubyte * size)()
        read = ctypes.c_size_t()
        ok = kernel32.ReadProcessMemory(
            handle, ctypes.c_void_p(address), buffer, size, ctypes.byref(read)
        )
        if not ok and read.value == 0:
            raise OSError(ctypes.get_last_error())
        return bytes(buffer[: read.value])

    try:
        info = _ProcessBasicInformation()
        returned = wintypes.ULONG()
        status = ntdll.NtQueryInformationProcess(
            handle, 0, ctypes.byref(info), ctypes.sizeof(info), ctypes.byref(returned)
        )
        if status != 0 or not info.PebBaseAddress:
            return None
        process_parameters = struct.unpack(
            "<Q", read_memory(int(info.PebBaseAddress) + 0x20, 8)
        )[0]
        environment = struct.unpack("<Q", read_memory(process_parameters + 0x80, 8))[0]
        raw = read_memory(environment, 1024 * 1024)
        prefix = f"{key}="
        for entry in raw.decode("utf-16-le", errors="ignore").split("\x00"):
            if entry.startswith(prefix):
                return entry[len(prefix):]
        return None
    except (OSError, ValueError, struct.error):
        return None
    finally:
        kernel32.CloseHandle(handle)


def discover_codex_app_tool_pipes() -> list[str]:
    """Find the native Codex Desktop tool pipe without exposing process environment."""
    candidates = [
        os.environ.get("INTEGRITY_CODEX_APP_TOOLS_PIPE_PATH"),
        os.environ.get(CODEX_APP_TOOLS_PIPE_ENV),
    ]
    candidates.extend(
        _read_process_environment_value(process_id, CODEX_APP_TOOLS_PIPE_ENV)
        for process_id in _codex_process_ids()
    )
    candidates.extend(_enumerate_codex_app_tool_pipes())
    pattern = re.compile(r"^\\\\\.\\pipe\\codex-browser-use-[A-Za-z0-9-]+$")
    result: list[str] = []
    for candidate in candidates:
        if isinstance(candidate, str) and pattern.fullmatch(candidate) and candidate not in result:
            result.append(candidate)
    return result


def _enumerate_codex_app_tool_pipes() -> list[str]:
    """Fall back to the local Windows pipe namespace for non-elevated launchers."""
    if os.name != "nt":
        return []
    try:
        names = os.listdir("\\\\.\\pipe\\")
    except OSError:
        return []
    pattern = re.compile(r"^codex-browser-use-[A-Za-z0-9-]+$")
    return [f"\\\\.\\pipe\\{name}" for name in names if pattern.fullmatch(name)][:128]


class NativeAppHostRpc:
    """Small framed JSON-RPC client for the owner Codex Desktop tool host."""

    def __init__(self, pipe_path: str):
        self.pipe_path = pipe_path
        self._counter = 0
        self._lock = threading.Lock()

    @staticmethod
    def _read_exact(stream, size: int) -> bytes:
        chunks = bytearray()
        while len(chunks) < size:
            chunk = stream.read(size - len(chunks))
            if not chunk:
                raise RpcError("codex_app_host_closed")
            chunks.extend(chunk)
        return bytes(chunks)

    def request(self, method: str, params: dict, timeout: float = CODEX_HOST_TIMEOUT) -> dict:
        with self._lock:
            self._counter += 1
            message_id = self._counter
        request = {
            "jsonrpc": "2.0",
            "id": message_id,
            "method": method,
            "params": params,
        }
        payload = json.dumps(request, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        completed: queue.Queue = queue.Queue(maxsize=1)
        opened: list = []

        def transact():
            try:
                with open(self.pipe_path, "r+b", buffering=0) as pipe:
                    opened.append(pipe)
                    pipe.write(struct.pack("<I", len(payload)) + payload)
                    length = struct.unpack("<I", self._read_exact(pipe, 4))[0]
                    if length > 8 * 1024 * 1024:
                        raise RpcError("codex_app_host_response_too_large")
                    response = json.loads(self._read_exact(pipe, length))
                completed.put((True, response))
            except Exception as exc:  # noqa: BLE001 - transfer worker failure to its caller
                completed.put((False, exc))

        threading.Thread(target=transact, daemon=True).start()
        try:
            ok, response = completed.get(timeout=timeout)
        except queue.Empty as exc:
            if opened:
                try:
                    opened[0].close()
                except Exception:  # noqa: BLE001, S110 - preserve the original timeout
                    pass
            raise RpcError(f"codex_app_host_timeout:{method}") from exc
        if not ok:
            raise RpcError(f"codex_app_host_unavailable:{type(response).__name__}") from response
        if not isinstance(response, dict):
            raise RpcError("codex_app_host_invalid_response")
        if "error" in response:
            error = response.get("error") or {}
            raise RpcError(f"codex_app_host_rejected:{error.get('message') or 'unknown'}")
        result = response.get("result")
        if not isinstance(result, dict):
            raise RpcError("codex_app_host_invalid_result")
        return result

    def list_tools(self) -> list[dict]:
        result = self.request("tools/list", {"threadStartKind": "all"}, 5)
        tools = result.get("tools")
        if not isinstance(tools, list):
            raise RpcError("codex_app_host_tools_invalid")
        return tools

    def call_tool(self, name: str, arguments: dict, context_thread_id: str) -> dict:
        result = self.request("tools/call", {
            "arguments": arguments,
            "callerSource": "codex",
            "callId": f"integrity-web-{uuid.uuid4()}",
            "namespace": CODEX_APP_TOOLS_NAMESPACE,
            "threadId": context_thread_id,
            "tool": name,
            "turnId": f"web-bridge-{uuid.uuid4()}",
        })
        if result.get("success") is not True:
            raise RpcError(f"codex_app_host_tool_failed:{name}")
        return result


class Backends:
    def __init__(self):
        self.memory: JsonLineRpc | None = None
        self.codex: JsonLineRpc | None = None
        self.codex_host: NativeAppHostRpc | None = None
        self.memory_tools: list[dict] | None = None
        self._memory_lock = threading.RLock()
        self._codex_lock = threading.RLock()
        self._codex_host_lock = threading.RLock()

    def get_memory(self) -> JsonLineRpc:
        with self._memory_lock:
            if self.memory is None or self.memory.proc.poll() is not None:
                self.memory = JsonLineRpc(shlex.split(MEMORY_COMMAND, posix=True))
                self.memory.request("initialize", {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "integrity-unified-web-bridge", "version": VERSION},
                }, 15)
                self.memory.notify("notifications/initialized", {})
            return self.memory

    def get_memory_tools(self) -> list[dict]:
        with self._memory_lock:
            if self.memory_tools is None:
                result = self.get_memory().request("tools/list", {}, 15)
                tools = result.get("tools")
                if not isinstance(tools, list):
                    raise RpcError("memory_tools_invalid")
                self.memory_tools = tools
            return self.memory_tools

    def get_codex(self) -> JsonLineRpc:
        with self._codex_lock:
            if self.codex is None or self.codex.proc.poll() is not None:
                command = json.loads(os.environ["INTEGRITY_CODEX_COMMAND"]) if os.environ.get("INTEGRITY_CODEX_COMMAND") else [CODEX, "app-server", "--stdio"]
                if (not isinstance(command, list) or not command or
                        any(not isinstance(part, str) or not part for part in command)):
                    raise RpcError("codex_command_invalid")
                if not Path(command[0]).is_file():
                    raise RpcError("codex_binary_missing")
                self.codex = JsonLineRpc(command)
                self.codex.request("initialize", {
                    "clientInfo": {"name": "integrity-web-codex-bridge", "version": VERSION},
                    "capabilities": {"optOutNotificationMethods": ["remoteControl/status/changed"]},
                }, 15)
                self.codex.notify("initialized", {})
            return self.codex

    def get_codex_host(self) -> NativeAppHostRpc:
        with self._codex_host_lock:
            if self.codex_host is not None:
                return self.codex_host
            for pipe_path in discover_codex_app_tool_pipes():
                candidate = NativeAppHostRpc(pipe_path)
                try:
                    tools = candidate.list_tools()
                except RpcError:
                    continue
                names = {
                    (tool.get("namespace"), tool.get("name"))
                    for tool in tools if isinstance(tool, dict)
                }
                required = {
                    (CODEX_APP_TOOLS_NAMESPACE, "read_thread"),
                    (CODEX_APP_TOOLS_NAMESPACE, "send_message_to_thread"),
                }
                if required.issubset(names):
                    self.codex_host = candidate
                    safe_log("codex_app_host_ready")
                    return candidate
            raise RpcError("codex_app_host_unavailable")

    def invalidate_codex_host(self):
        with self._codex_host_lock:
            self.codex_host = None

    def close(self):
        for backend in (self.memory, self.codex):
            if backend is not None:
                backend.close()


BACKENDS = Backends()
atexit.register(BACKENDS.close)


def tool_definitions() -> list[dict]:
    memory_tools = [dict(tool) for tool in BACKENDS.get_memory_tools()]
    compact_memory_descriptions = {
        "search": "Search the first bounded memory page; use search_memory for exhaustive recall.",
        "fetch": "Fetch one bounded hit; use read_memory for a complete remembered conversation.",
    }
    for tool in memory_tools:
        if tool.get("name") in compact_memory_descriptions:
            tool["description"] = compact_memory_descriptions[tool["name"]]
    tools = memory_tools + [
        {
            "name": "codex_list_models",
            "title": "List available Codex models",
            "description": "Read the connected local Codex model catalog and supported reasoning efforts. Choose an executor suited to the owner's task; respect an explicitly requested model. Reading the catalog never changes a task or starts inference.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False},
        },
        {
            "name": "codex_list_tasks",
            "title": "List Codex tasks",
            "description": "List local Codex tasks on the owner's Windows PC with bounded metadata.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "minimum": 1, "maximum": 5, "default": 1},
                    "cursor": {"type": "string"},
                    "search": {"type": "string", "maxLength": 200},
                    "archived": {"type": "boolean", "default": False},
                },
                "additionalProperties": False,
            },
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False},
        },
        {
            "name": "codex_read_task",
            "title": "Read Codex task",
            "description": "Read task text pages; with turn_id, long-poll the next live delta. During supervision, follow next_action until terminal: an empty chunk while inProgress is a wait boundary, not completion.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "thread_id": {"type": "string", "minLength": 8, "maxLength": 128},
                    "turn_limit": {"type": "integer", "minimum": 1, "maximum": 20, "default": 8},
                    "cursor": {"type": "string", "pattern": "^(0|v1:[0-9]{1,12}:[a-f0-9]{64})$", "maxLength": 80},
                    "turn_id": {"type": "string", "minLength": 8, "maxLength": 128},
                    "wait_seconds": {"type": "integer", "minimum": 0, "maximum": 50, "default": 15},
                },
                "required": ["thread_id"],
                "additionalProperties": False,
            },
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False},
        },
        {
            "name": "codex_wait_pong",
            "title": "Wait for Codex PONG",
            "description": "Keep the current Web tool call bound to one exact Codex turn. Start this tool with cursor=0; continuation cursors are tool-specific, so never pass a cursor returned by codex_read_task. A terminal turn returns event=pong to this same Web conversation; a bounded non-terminal wait returns event=waiting and next_action=wait_pong. If the Web turn has already ended, the bridge cannot inject a new message into it, so call this tool again with the cursor returned by codex_wait_pong.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "thread_id": {"type": "string", "minLength": 8, "maxLength": 128},
                    "turn_id": {"type": "string", "minLength": 8, "maxLength": 128},
                    "cursor": {"type": "string", "pattern": "^(0|v1:[0-9]{1,12}:[a-f0-9]{64})$", "maxLength": 80},
                    "wait_seconds": {"type": "integer", "minimum": 0, "maximum": 50, "default": 50},
                },
                "required": ["thread_id", "turn_id"],
                "additionalProperties": False,
            },
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False},
        },
        {
            "name": "codex_send_prompt",
            "title": "Send prompt to Codex task",
            "description": "Send through the owning Codex process. Omit model and effort to keep this task's settings. For an idle task, choose a suitable model/effort from codex_list_models, respecting the owner's explicit choice. Active-turn steering is queued at an owner message boundary and does not prove application. Emergency steering requires the exact active turn and a reason, but remains queued until the owner exposes native preemption; its receipt requires terminal readback. Returns the turn_id to read.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "thread_id": {"type": "string", "minLength": 8, "maxLength": 128},
                    "prompt": {"type": "string", "minLength": 1, "maxLength": MAX_PROMPT},
                    "model": {"type": "string", "minLength": 1, "maxLength": 128, "description": "Optional model slug from codex_list_models. Omit to preserve the task's model and effort."},
                    "effort": {"type": "string", "minLength": 1, "maxLength": 16, "description": "Optional supported reasoning effort for the selected model; requires model. If omitted with model, uses that model's catalog default."},
                    "expected_turn_id": {"type": "string", "minLength": 8, "maxLength": 128, "description": "Exact active turn to receive a queued steering message through its owning process."},
                    "steer_mode": {"type": "string", "enum": ["normal", "emergency"], "default": "normal"},
                    "steer_reason": {"type": "string", "minLength": 8, "maxLength": 500, "description": "Required audit reason for emergency steering."},
                },
                "required": ["thread_id", "prompt"],
                "additionalProperties": False,
            },
            "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False},
        },
        {
            "name": "codex_interrupt_turn",
            "title": "Interrupt Codex turn",
            "description": "Request interruption of the exact active turn only. Requires confirm_interrupt=true; then use codex_read_task to verify its terminal status. Desktop-owned turns fail explicitly with codex_native_interrupt_unavailable until the native owner exposes an exact interrupt primitive; queued emergency steering is not preemption.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "thread_id": {"type": "string", "minLength": 8, "maxLength": 128},
                    "turn_id": {"type": "string", "minLength": 8, "maxLength": 128},
                    "confirm_interrupt": {"type": "boolean"},
                },
                "required": ["thread_id", "turn_id", "confirm_interrupt"],
                "additionalProperties": False,
            },
            "annotations": {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": False},
        },
        {
            "name": "codex_archive_task",
            "title": "Archive completed Codex task",
            "description": "Archive an exact task only when its thread is idle and its latest turn completed. Requires confirm_archive=true. App Server may also archive spawned descendant threads; this does not delete history and can be reversed with codex_unarchive_task.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "thread_id": {"type": "string", "minLength": 8, "maxLength": 128},
                    "confirm_archive": {"type": "boolean"},
                },
                "required": ["thread_id", "confirm_archive"],
                "additionalProperties": False,
            },
            "annotations": {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": False},
        },
        {
            "name": "codex_unarchive_task",
            "title": "Restore archived Codex task",
            "description": "Restore one exact archived task to the active task list. Requires confirm_restore=true.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "thread_id": {"type": "string", "minLength": 8, "maxLength": 128},
                    "confirm_restore": {"type": "boolean"},
                },
                "required": ["thread_id", "confirm_restore"],
                "additionalProperties": False,
            },
            "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False},
        },
        {
            "name": "codex_copy_turn",
            "title": "Thread",
            "description": "Copy one complete Codex turn to the owner's Windows clipboard.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "thread_id": {"type": "string", "minLength": 8, "maxLength": 128},
                    "turn_id": {"type": "string", "minLength": 8, "maxLength": 128},
                },
                "required": ["thread_id", "turn_id"],
                "additionalProperties": False,
            },
            "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        },
    ]
    return tools


def pack_payload(payload: dict) -> dict:
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    return {"content": [{"type": "text", "text": encoded}], "structuredContent": payload}


def tool_error_result(exc: RpcError) -> dict:
    payload = {"error": str(exc)[:300], "retryable": False}
    result = pack_payload(payload)
    result["isError"] = True
    return result


def clean_thread(item: dict) -> dict:
    return {
        "id": item.get("id"),
        "name": item.get("name"),
        "preview": str(item.get("preview") or "")[:300],
        "cwd": item.get("cwd"),
        "project_id": item.get("projectId"),
        "status": item.get("status"),
        "updated_at": item.get("updatedAt"),
    }


def message_text(item: dict) -> tuple[str, str] | None:
    kind = item.get("type")
    if kind == "agentMessage":
        return "assistant", str(item.get("text") or "")
    if kind == "userMessage":
        parts = []
        for part in item.get("content") or []:
            if isinstance(part, dict) and part.get("type") == "text":
                parts.append(str(part.get("text") or ""))
        return "user", "\n".join(parts)
    return None


def validate_thread_id(value) -> str:
    if not isinstance(value, str) or not THREAD_ID.fullmatch(value):
        raise RpcError("invalid_thread_id")
    return value


def codex_list(args: dict) -> dict:
    limit = args.get("limit", 1)
    if type(limit) is not int or not 1 <= limit <= 5:
        raise RpcError("invalid_limit")
    params = {
        "limit": limit,
        "sortKey": "updated_at",
        "sortDirection": "desc",
        "useStateDbOnly": True,
        "archived": bool(args.get("archived", False)),
    }
    if isinstance(args.get("cursor"), str):
        params["cursor"] = args["cursor"]
    if isinstance(args.get("search"), str) and args["search"]:
        params["searchTerm"] = args["search"][:200]
    result = BACKENDS.get_codex().request("thread/list", params, 20)
    data = result.get("data")
    tasks = []
    for item in data[:limit] if isinstance(data, list) else []:
        if not isinstance(item, dict):
            continue
        tasks.append({
            "id": item.get("id"),
            "title": str(item.get("title") or item.get("name") or "")[:200],
            "updated_at": item.get("updatedAt"),
        })
    task = tasks[0] if tasks else {"id": None, "title": "", "updated_at": None}
    return {**task, "cursor": result.get("nextCursor"), "tasks": tasks}


def read_cursor(scope: str, transcript: str, cursor: str) -> int:
    if cursor == "0":
        return 0
    if not isinstance(cursor, str):
        raise RpcError("invalid_cursor")
    match = re.fullmatch(r"v1:([0-9]{1,12}):([a-f0-9]{64})", cursor)
    if not match:
        raise RpcError("cursor_changed: restart this selected turn from cursor 0")
    offset = int(match[1])
    if offset > len(transcript) or make_cursor(scope, transcript, offset) != cursor:
        raise RpcError("cursor_changed: selected content changed; restart this turn")
    return offset


def make_cursor(scope: str, transcript: str, offset: int) -> str:
    digest = hashlib.sha256((scope + "\0" + transcript[:offset]).encode("utf-8")).hexdigest()
    return f"v1:{offset}:{digest}"


def codex_read(args: dict) -> dict:
    thread_id = validate_thread_id(args.get("thread_id"))
    limit = args.get("turn_limit", 8)
    if type(limit) is not int or not 1 <= limit <= 20:
        raise RpcError("invalid_turn_limit")
    codex = BACKENDS.get_codex()
    metadata = codex.request("thread/read", {"threadId": thread_id, "includeTurns": False}, 20)
    page = codex.request("thread/turns/list", {
        "threadId": thread_id,
        "limit": limit,
        "sortDirection": "desc",
        "itemsView": "full",
    }, 25)
    messages = []
    for turn in reversed(page.get("data") or []):
        if not isinstance(turn, dict):
            continue
        for item in turn.get("items") or []:
            if not isinstance(item, dict):
                continue
            pair = message_text(item)
            if pair and pair[1]:
                messages.append({"role": pair[0], "text": pair[1]})
    thread = metadata.get("thread") if isinstance(metadata.get("thread"), dict) else {}
    transcript = "\n".join(f"{message['role']}: {message['text']}" for message in messages)
    turn_ids = [turn.get("id") for turn in page.get("data") or [] if isinstance(turn, dict)]
    scope = json.dumps([thread_id, limit, turn_ids], separators=(",", ":"))
    offset = read_cursor(scope, transcript, args.get("cursor", "0"))
    chunk = transcript[offset:offset + READ_CHUNK]
    next_offset = offset + len(chunk)
    status = thread.get("status")
    if isinstance(status, dict):
        status = status.get("type")
    return {
        "thread_id": thread.get("id"),
        "status": status,
        "chunk": chunk,
        "next_cursor": make_cursor(scope, transcript, next_offset) if next_offset < len(transcript) else None,
        "more": next_offset < len(transcript),
        "has_older_turns": bool(page.get("nextCursor")),
        "turn_ids": turn_ids,
    }


def _host_tool_json(host: NativeAppHostRpc, name: str, arguments: dict, thread_id: str) -> dict:
    result = host.call_tool(name, arguments, thread_id)
    for item in result.get("contentItems") or []:
        if not isinstance(item, dict) or item.get("type") != "inputText":
            continue
        try:
            parsed = json.loads(item.get("text", ""))
        except (TypeError, json.JSONDecodeError):
            continue
        if isinstance(parsed, dict):
            return parsed
    raise RpcError(f"codex_app_host_tool_result_invalid:{name}")


def _host_latest_turn(host: NativeAppHostRpc, thread_id: str) -> dict | None:
    result = _host_tool_json(host, "read_thread", {
        "threadId": thread_id,
        "turnLimit": 1,
        "includeOutputs": False,
        "maxOutputCharsPerItem": 0,
    }, thread_id)
    turns = result.get("turns")
    if not isinstance(turns, list) or not turns or not isinstance(turns[0], dict):
        return None
    turn = turns[0]
    turn_id = turn.get("id")
    status = turn.get("status")
    if not isinstance(turn_id, str) or not isinstance(status, str):
        return None
    return {"id": turn_id, "status": status}


def _reconcile_owner_turn(
    thread_id: str, owner_turn: dict | None, expected_turn_id: str | None = None
) -> dict:
    """Reconcile lifecycle, with an exact owner-bound escape for active steering."""
    if owner_turn is None:
        raise RpcError("codex_owner_lifecycle_ambiguous")
    read_turn = latest_codex_turn(thread_id)
    owner_id, read_id = owner_turn.get("id"), read_turn.get("id")
    owner_status, read_status = owner_turn.get("status"), read_turn.get("status")
    def state(status):
        if status == "inProgress":
            return "active"
        if status in FINAL_TURN_STATUSES:
            return "terminal"
        return None

    owner_state, read_state = state(owner_status), state(read_status)
    if owner_state is None:
        raise RpcError("codex_owner_lifecycle_ambiguous")
    if expected_turn_id is not None:
        if owner_id != expected_turn_id:
            raise RpcError("codex_expected_turn_mismatch")
        if owner_state != "active":
            raise RpcError("codex_expected_turn_not_active")
        reconciled = dict(owner_turn)
        if owner_id == read_id and read_state == "active":
            reconciled["_lifecycle_reconciliation"] = "exact_owner_active_read_plane_consistent"
        else:
            reconciled["_lifecycle_reconciliation"] = "exact_owner_active_read_plane_stale"
        return reconciled
    if read_state is None:
        raise RpcError("codex_owner_lifecycle_ambiguous")
    if owner_id != read_id:
        raise RpcError("codex_owner_lifecycle_conflict")
    if owner_state != read_state:
        raise RpcError("codex_owner_lifecycle_conflict")
    return owner_turn


def codex_list_models(args: dict) -> dict:
    if args:
        raise RpcError("unexpected_model_catalog_arguments")
    result = BACKENDS.get_codex().request("model/list", {"limit": 100, "includeHidden": False}, 20)
    data = result.get("data")
    if not isinstance(data, list) or len(data) > 100:
        raise RpcError("codex_model_catalog_invalid")
    if result.get("nextCursor"):
        raise RpcError("codex_model_catalog_incomplete")
    models = []
    for item in data:
        if not isinstance(item, dict) or item.get("hidden") is True:
            continue
        model = item.get("model")
        efforts = item.get("supportedReasoningEfforts")
        if not isinstance(model, str) or not MODEL_ID.fullmatch(model) or not isinstance(efforts, list):
            raise RpcError("codex_model_catalog_invalid")
        supported = [entry.get("reasoningEffort") for entry in efforts if isinstance(entry, dict)]
        if not supported or any(not isinstance(e, str) or not 1 <= len(e) <= 16 for e in supported):
            raise RpcError("codex_model_catalog_invalid")
        default = item.get("defaultReasoningEffort")
        if default not in supported:
            raise RpcError("codex_model_catalog_invalid")
        models.append({
            "model": model,
            "display_name": str(item.get("displayName") or model)[:128],
            "description": str(item.get("description") or "")[:300],
            "supported_efforts": supported,
            "default_effort": default,
            "is_default": item.get("isDefault") is True,
        })
    if not models:
        raise RpcError("codex_model_catalog_empty")
    return {"host": "local", "models": models, "selection_scope": "target_task", "speed_policy": "preserve_target"}


def _executor_overrides(args: dict) -> dict:
    if "model" not in args:
        if "effort" in args:
            raise RpcError("effort_requires_model")
        return {}
    model = args["model"]
    if not isinstance(model, str) or not MODEL_ID.fullmatch(model):
        raise RpcError("invalid_model")
    effort = args.get("effort")
    if "effort" in args and (not isinstance(effort, str) or not 1 <= len(effort) <= 16):
        raise RpcError("invalid_effort")
    candidate = next((entry for entry in codex_list_models({})["models"] if entry["model"] == model), None)
    if candidate is None:
        raise RpcError("codex_model_unavailable")
    effort = effort if "effort" in args else candidate["default_effort"]
    if effort not in candidate["supported_efforts"]:
        raise RpcError("codex_effort_unsupported")
    return {"model": model, "effort": effort}


def _requested_executor_profile(overrides: dict) -> dict:
    return {
        "model": overrides.get("model", "preserve_target"),
        "effort": overrides.get("effort", "preserve_target"),
        "service_tier": "preserve_target",
    }


def _codex_send_standalone(
    thread_id: str, prompt: str, overrides: dict, expected_turn_id: str | None = None
) -> dict:
    codex = BACKENDS.get_codex()
    if expected_turn_id is not None:
        latest = latest_codex_turn(thread_id)
        if latest.get("id") != expected_turn_id:
            raise RpcError("codex_expected_turn_mismatch")
        if latest.get("status") != "inProgress":
            raise RpcError("codex_expected_turn_not_active")
        if overrides:
            raise RpcError("executor_override_requires_idle_task")
        codex.request("turn/steer", {
            "threadId": thread_id, "expectedTurnId": expected_turn_id,
            "input": [{"type": "text", "text": prompt, "text_elements": []}],
        }, 30)
        return {"accepted": True, "thread_id": thread_id, "turn_id": expected_turn_id,
                "status": "inProgress", "delivery_mode": "steer_active_turn",
                "delivery_route": "existing_owner_proxy",
                "lifecycle_reconciliation": "exact_owner_active",
                "requested_executor_profile": _requested_executor_profile(overrides)}
    if os.environ.get("INTEGRITY_CODEX_OWNER_PROXY") == "1":
        latest = latest_codex_turn(thread_id)
        if latest.get("status") == "inProgress":
            if overrides:
                raise RpcError("executor_override_requires_idle_task")
            codex.request("turn/steer", {
                "threadId": thread_id, "expectedTurnId": latest["id"],
                "input": [{"type": "text", "text": prompt, "text_elements": []}],
            }, 30)
            return {"accepted": True, "thread_id": thread_id, "turn_id": latest["id"],
                    "status": "inProgress", "delivery_mode": "steer_active_turn",
                    "delivery_route": "existing_owner_proxy",
                    "requested_executor_profile": _requested_executor_profile(overrides)}
    safe_log("codex_send_resume_begin")
    codex.request("thread/resume", {"threadId": thread_id, "excludeTurns": True}, 30)
    safe_log("codex_send_resume_ready")
    safe_log("codex_send_turn_begin")
    result = codex.request("turn/start", {
        "threadId": thread_id,
        "input": [{"type": "text", "text": prompt, "text_elements": []}],
        "turnTrigger": "web-chatgpt-plugin",
        **overrides,
    }, 30)
    safe_log("codex_send_turn_accepted")
    turn = result.get("turn") if isinstance(result.get("turn"), dict) else {}
    turn_id = turn.get("id")
    if not isinstance(turn_id, str):
        raise RpcError("codex_turn_id_missing")
    return {
        "accepted": True,
        "thread_id": thread_id,
        "turn_id": turn_id,
        "status": turn.get("status"),
        "requested_executor_profile": _requested_executor_profile(overrides),
        "delivery_route": "existing_owner_proxy" if os.environ.get("INTEGRITY_CODEX_OWNER_PROXY") == "1" else "standalone_app_server",
    }


def _codex_send_via_desktop(
    host: NativeAppHostRpc, thread_id: str, prompt: str, baseline: dict | None, overrides: dict
) -> dict:
    if overrides and baseline is not None and baseline["status"] not in FINAL_TURN_STATUSES:
        raise RpcError("executor_override_requires_idle_task")
    host_overrides = {"model": overrides["model"], "thinking": overrides["effort"]} if overrides else {}
    host.call_tool("send_message_to_thread", {
        "threadId": thread_id,
        "prompt": prompt,
        **host_overrides,
    }, thread_id)
    safe_log("codex_send_desktop_accepted")

    if baseline is not None and baseline["status"] == "inProgress":
        result = {
            "accepted": True,
            "thread_id": thread_id,
            "turn_id": baseline["id"],
            "status": baseline["status"],
            "delivery_mode": "steer_active_turn",
            "delivery_route": "codex_desktop_owner",
            "requested_executor_profile": _requested_executor_profile(overrides),
        }
        if baseline.get("_lifecycle_reconciliation"):
            result["lifecycle_reconciliation"] = baseline["_lifecycle_reconciliation"]
        return result

    deadline = time.monotonic() + CODEX_HOST_TIMEOUT
    latest = None
    while time.monotonic() < deadline:
        latest = _host_latest_turn(host, thread_id)
        if latest is not None and (baseline is None or latest["id"] != baseline["id"]):
            break
        time.sleep(0.2)
    if latest is None or (baseline is not None and latest["id"] == baseline["id"]):
        raise RpcError("codex_desktop_turn_not_observed")
    return {
        "accepted": True,
        "thread_id": thread_id,
        "turn_id": latest["id"],
        "status": latest["status"],
        "delivery_mode": "start_followup_turn",
        "delivery_route": "codex_desktop_owner",
        "requested_executor_profile": _requested_executor_profile(overrides),
    }


def _mark_queued_emergency(result: dict, steer_reason: str) -> dict:
    result.update({
        "delivery_mode": "queued_emergency_steer",
        "application_verified": False,
        "requires_terminal_readback": True,
        "steer_reason_sha256": hashlib.sha256(steer_reason.encode("utf-8")).hexdigest(),
    })
    return result


def codex_send(args: dict) -> dict:
    thread_id = validate_thread_id(args.get("thread_id"))
    prompt = args.get("prompt")
    if not isinstance(prompt, str) or not prompt.strip() or len(prompt) > MAX_PROMPT or "\x00" in prompt:
        raise RpcError("invalid_prompt")
    steer_mode = args.get("steer_mode", "normal")
    if steer_mode not in {"normal", "emergency"}:
        raise RpcError("invalid_steer_mode")
    expected_turn_id = args.get("expected_turn_id")
    if expected_turn_id is not None:
        expected_turn_id = validate_thread_id(expected_turn_id)
    steer_reason = args.get("steer_reason")
    if steer_reason is not None and (
        not isinstance(steer_reason, str) or not 8 <= len(steer_reason.strip()) <= 500
    ):
        raise RpcError("invalid_steer_reason")
    if steer_mode == "emergency":
        if expected_turn_id is None:
            raise RpcError("emergency_steer_requires_expected_turn")
        if steer_reason is None:
            raise RpcError("emergency_steer_reason_required")
    overrides = _executor_overrides(args)
    if os.environ.get("INTEGRITY_CODEX_OWNER_PROXY") == "1":
        if steer_mode == "emergency":
            return _mark_queued_emergency(
                _codex_send_standalone(thread_id, prompt, overrides, expected_turn_id),
                steer_reason,
            )
        return _codex_send_standalone(thread_id, prompt, overrides, expected_turn_id)
    try:
        host = BACKENDS.get_codex_host()
    except RpcError as exc:
        if str(exc) != "codex_app_host_unavailable":
            raise
        if os.environ.get("INTEGRITY_REQUIRE_DESKTOP") == "1":
            raise RpcError("codex_desktop_owner_unavailable") from exc
        safe_log("codex_send_desktop_unavailable")
        return _codex_send_standalone(thread_id, prompt, overrides, expected_turn_id)
    try:
        baseline = _host_latest_turn(host, thread_id)
    except RpcError:
        BACKENDS.invalidate_codex_host()
        host = BACKENDS.get_codex_host()
        baseline = _host_latest_turn(host, thread_id)
    baseline = _reconcile_owner_turn(thread_id, baseline, expected_turn_id)
    if steer_mode == "emergency":
        return _mark_queued_emergency(
            _codex_send_via_desktop(host, thread_id, prompt, baseline, overrides),
            steer_reason,
        )
    return _codex_send_via_desktop(host, thread_id, prompt, baseline, overrides)


def codex_watch(args: dict) -> dict:
    thread_id = validate_thread_id(args.get("thread_id"))
    turn_id = validate_thread_id(args.get("turn_id"))
    cursor = args.get("cursor", "0")
    wait_seconds = args.get("wait_seconds", 15)
    if type(wait_seconds) is not int or not 0 <= wait_seconds <= 50:
        raise RpcError("invalid_wait_seconds")
    scope = json.dumps([thread_id, turn_id], separators=(",", ":"))
    deadline = time.monotonic() + wait_seconds
    selected = None
    transcript = ""
    while True:
        messages = []
        if os.environ.get("INTEGRITY_REQUIRE_DESKTOP") == "1":
            try:
                owner = _host_tool_json(BACKENDS.get_codex_host(), "read_thread", {
                    "threadId": thread_id,
                    "turnLimit": 10,
                    "includeOutputs": True,
                    "maxOutputCharsPerItem": MAX_PROMPT,
                }, thread_id)
            except RpcError as exc:
                raise RpcError("codex_desktop_owner_unavailable") from exc
            selected = next((turn for turn in owner.get("turns") or []
                             if isinstance(turn, dict) and turn.get("id") == turn_id), None)
            if selected is None:
                raise RpcError("codex_turn_not_found")
            for item in selected.get("items") or []:
                if (isinstance(item, dict) and item.get("type") == "agentMessage" and
                        isinstance(item.get("text"), str) and item["text"]):
                    messages.append(item["text"])
            if not messages:
                try:
                    content_page = BACKENDS.get_codex().request("thread/turns/list", {
                        "threadId": thread_id,
                        "limit": 20,
                        "sortDirection": "desc",
                        "itemsView": "full",
                    }, 20)
                    content_turn = next((turn for turn in content_page.get("data") or []
                                         if isinstance(turn, dict) and turn.get("id") == turn_id), None)
                    if content_turn is not None:
                        for item in content_turn.get("items") or []:
                            if isinstance(item, dict):
                                pair = message_text(item)
                                if pair and pair[0] == "assistant" and pair[1]:
                                    messages.append(pair[1])
                except RpcError as exc:
                    if str(selected.get("status") or "unknown") in FINAL_TURN_STATUSES:
                        raise RpcError("codex_turn_content_unavailable") from exc
                    safe_log("codex_turn_content_fallback_unavailable")
                if (not messages and
                        str(selected.get("status") or "unknown") in FINAL_TURN_STATUSES):
                    raise RpcError("codex_turn_content_unavailable")
        else:
            page = BACKENDS.get_codex().request("thread/turns/list", {
                "threadId": thread_id,
                "limit": 20,
                "sortDirection": "desc",
                "itemsView": "full",
            }, 20)
            selected = next((turn for turn in page.get("data") or []
                             if isinstance(turn, dict) and turn.get("id") == turn_id), None)
            if selected is None:
                raise RpcError("codex_turn_not_found")
            for item in selected.get("items") or []:
                if isinstance(item, dict):
                    pair = message_text(item)
                    if pair and pair[0] == "assistant" and pair[1]:
                        messages.append(pair[1])
        transcript = "\n".join(messages)
        status = str(selected.get("status") or "unknown")
        offset = read_cursor(scope, transcript, cursor)
        if offset < len(transcript) or status in {"completed", "failed", "interrupted", "cancelled"}:
            break
        if time.monotonic() >= deadline:
            break
        time.sleep(1)
    chunk = transcript[offset:offset + READ_CHUNK]
    next_offset = offset + len(chunk)
    final = str(selected.get("status") or "unknown") in FINAL_TURN_STATUSES
    if next_offset < len(transcript):
        next_action = "read_remaining"
    elif final:
        next_action = "terminal"
    elif chunk:
        next_action = "review_then_call_again"
    else:
        next_action = "call_again"
    return {
        "status": selected.get("status"),
        "chunk": chunk,
        "next_cursor": make_cursor(scope, transcript, next_offset),
        "more": next_offset < len(transcript),
        "execution_complete": final,
        "final": final and next_offset >= len(transcript),
        "next_action": next_action,
    }


def codex_wait_pong(args: dict) -> dict:
    """Return a terminal PONG through the exact Web tool call that is waiting."""
    payload = codex_watch(args)
    terminal = payload.get("execution_complete") is True
    payload["event"] = "pong" if terminal else "waiting"
    payload["pong"] = terminal
    if terminal:
        payload["next_action"] = "read_remaining" if payload.get("more") else "review_pong"
    else:
        payload["next_action"] = "review_then_wait_pong" if payload.get("chunk") else "wait_pong"
    return payload


def find_codex_turn(thread_id: str, turn_id: str) -> dict:
    cursor = None
    for _ in range(100):
        params = {
            "threadId": thread_id,
            "limit": 20,
            "sortDirection": "desc",
            "itemsView": "full",
        }
        if cursor:
            params["cursor"] = cursor
        page = BACKENDS.get_codex().request("thread/turns/list", params, 20)
        selected = next((turn for turn in page.get("data") or []
                         if isinstance(turn, dict) and turn.get("id") == turn_id), None)
        if selected is not None:
            return selected
        cursor = page.get("nextCursor")
        if not isinstance(cursor, str) or not cursor:
            break
    raise RpcError("codex_turn_not_found")


def latest_codex_turn(thread_id: str) -> dict:
    page = BACKENDS.get_codex().request("thread/turns/list", {
        "threadId": thread_id,
        "limit": 1,
        "sortDirection": "desc",
        "itemsView": "notLoaded",
    }, 20)
    turns = page.get("data")
    if not isinstance(turns, list) or not turns or not isinstance(turns[0], dict):
        raise RpcError("codex_task_has_no_turn")
    return turns[0]


def format_codex_turn(thread_id: str, turn: dict) -> str:
    sections = [f"# Thread {thread_id}", f"# Turn {turn.get('id')}", f"Status: {turn.get('status')}"]
    for item in turn.get("items") or []:
        if not isinstance(item, dict):
            continue
        kind = item.get("type")
        if kind == "agentMessage":
            text = str(item.get("text") or "")
            if text:
                sections.append(f"## Assistant\n{text}")
        elif kind == "userMessage":
            parts = [str(part.get("text") or "") for part in item.get("content") or []
                     if isinstance(part, dict) and part.get("type") == "text"]
            text = "\n".join(parts)
            if text:
                sections.append(f"## User\n{text}")
        elif kind == "mcpToolCall":
            server = str(item.get("server") or "unknown")
            tool = str(item.get("tool") or "unknown")
            status = str(item.get("status") or "unknown")
            sections.append(f"## Tool\n{server}/{tool} — {status}")
    return "\n\n".join(sections) + "\n"


def set_windows_clipboard(text: str):
    if os.name != "nt":
        raise RpcError("clipboard_requires_windows")
    kernel32 = ctypes.windll.kernel32
    user32 = ctypes.windll.user32
    kernel32.GlobalAlloc.argtypes = [ctypes.c_uint, ctypes.c_size_t]
    kernel32.GlobalAlloc.restype = ctypes.c_void_p
    kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
    kernel32.GlobalLock.restype = ctypes.c_void_p
    kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]
    kernel32.GlobalFree.argtypes = [ctypes.c_void_p]
    user32.SetClipboardData.argtypes = [ctypes.c_uint, ctypes.c_void_p]
    user32.SetClipboardData.restype = ctypes.c_void_p
    encoded = text.encode("utf-16-le") + b"\x00\x00"
    handle = kernel32.GlobalAlloc(0x0002, len(encoded))
    if not handle:
        raise RpcError("clipboard_allocation_failed")
    pointer = kernel32.GlobalLock(handle)
    if not pointer:
        kernel32.GlobalFree(handle)
        raise RpcError("clipboard_lock_failed")
    ctypes.memmove(pointer, encoded, len(encoded))
    kernel32.GlobalUnlock(handle)
    opened = False
    for _ in range(10):
        if user32.OpenClipboard(None):
            opened = True
            break
        time.sleep(0.05)
    if not opened:
        kernel32.GlobalFree(handle)
        raise RpcError("clipboard_busy")
    try:
        if not user32.EmptyClipboard() or not user32.SetClipboardData(13, handle):
            raise RpcError("clipboard_write_failed")
        handle = None
    finally:
        user32.CloseClipboard()
        if handle:
            kernel32.GlobalFree(handle)


def codex_copy_turn(args: dict) -> dict:
    thread_id = validate_thread_id(args.get("thread_id"))
    turn_id = validate_thread_id(args.get("turn_id"))
    turn = find_codex_turn(thread_id, turn_id)
    status = str(turn.get("status") or "unknown")
    if status not in {"completed", "failed", "interrupted", "cancelled"}:
        raise RpcError("codex_turn_not_final")
    text = format_codex_turn(thread_id, turn)
    set_windows_clipboard(text)
    return {"copied": True, "turn_id": turn_id, "status": status, "chars": len(text)}


def codex_interrupt_turn(args: dict) -> dict:
    thread_id = validate_thread_id(args.get("thread_id"))
    turn_id = validate_thread_id(args.get("turn_id"))
    if args.get("confirm_interrupt") is not True:
        raise RpcError("interrupt_confirmation_required")
    if os.environ.get("INTEGRITY_REQUIRE_DESKTOP") == "1":
        try:
            owner_turn = _host_latest_turn(BACKENDS.get_codex_host(), thread_id)
        except RpcError as exc:
            raise RpcError("codex_desktop_owner_unavailable") from exc
        if (owner_turn is None or owner_turn.get("id") != turn_id or
                str(owner_turn.get("status") or "unknown") != "inProgress"):
            raise RpcError("codex_turn_not_active")
        raise RpcError("codex_native_interrupt_unavailable")
    turn = find_codex_turn(thread_id, turn_id)
    if str(turn.get("status") or "unknown") != "inProgress":
        raise RpcError("codex_turn_not_active")
    BACKENDS.get_codex().request("turn/interrupt", {"threadId": thread_id, "turnId": turn_id}, 20)
    return {"requested": True, "thread_id": thread_id, "turn_id": turn_id, "status": "interrupt_requested"}


def codex_archive_task(args: dict) -> dict:
    thread_id = validate_thread_id(args.get("thread_id"))
    if args.get("confirm_archive") is not True:
        raise RpcError("archive_confirmation_required")
    codex = BACKENDS.get_codex()
    metadata = codex.request("thread/read", {"threadId": thread_id, "includeTurns": False}, 20)
    thread = metadata.get("thread") if isinstance(metadata.get("thread"), dict) else {}
    thread_status = thread.get("status")
    if isinstance(thread_status, dict):
        thread_status = thread_status.get("type")
    if thread_status not in {"idle", "notLoaded"}:
        raise RpcError("codex_task_not_idle")
    latest = latest_codex_turn(thread_id)
    latest_status = str(latest.get("status") or "unknown")
    if latest_status != "completed":
        raise RpcError("codex_task_not_completed")
    if os.environ.get("INTEGRITY_REQUIRE_DESKTOP") == "1":
        host = BACKENDS.get_codex_host()
        owner_turn = _host_latest_turn(host, thread_id)
        if owner_turn is None or owner_turn.get("status") != "completed":
            raise RpcError("codex_task_not_completed")
        result = _host_tool_json(host, "set_thread_archived", {
            "threadId": thread_id, "archived": True,
        }, thread_id)
        if result.get("threadId") != thread_id or result.get("archived") is not True:
            raise RpcError("codex_archive_result_unverified")
    else:
        codex.request("thread/archive", {"threadId": thread_id}, 20)
    return {
        "archived": True,
        "thread_id": thread_id,
        "latest_turn_status": latest_status,
        "spawned_descendants_may_also_be_archived": True,
    }


def codex_unarchive_task(args: dict) -> dict:
    thread_id = validate_thread_id(args.get("thread_id"))
    if args.get("confirm_restore") is not True:
        raise RpcError("restore_confirmation_required")
    if os.environ.get("INTEGRITY_REQUIRE_DESKTOP") == "1":
        result = _host_tool_json(BACKENDS.get_codex_host(), "set_thread_archived", {
            "threadId": thread_id, "archived": False,
        }, thread_id)
        if result.get("threadId") != thread_id or result.get("archived") is not False:
            raise RpcError("codex_unarchive_result_unverified")
        return {"restored": True, "thread_id": thread_id}
    result = BACKENDS.get_codex().request("thread/unarchive", {"threadId": thread_id}, 20)
    thread = result.get("thread") if isinstance(result.get("thread"), dict) else {}
    if thread.get("id") != thread_id:
        raise RpcError("codex_unarchive_result_unverified")
    return {"restored": True, "thread_id": thread_id}


def call_tool(name: str, args: dict) -> dict:
    if name == "codex_list_models":
        payload = codex_list_models(args)
    elif name == "codex_list_tasks":
        payload = codex_list(args)
    elif name == "codex_read_task":
        payload = codex_watch(args) if isinstance(args.get("turn_id"), str) else codex_read(args)
    elif name == "codex_wait_pong":
        payload = codex_wait_pong(args)
    elif name == "codex_send_prompt":
        payload = codex_send(args)
    elif name == "codex_interrupt_turn":
        payload = codex_interrupt_turn(args)
    elif name == "codex_archive_task":
        payload = codex_archive_task(args)
    elif name == "codex_unarchive_task":
        payload = codex_unarchive_task(args)
    elif name == "codex_copy_turn":
        payload = codex_copy_turn(args)
    else:
        memory_names = {x.get("name") for x in BACKENDS.get_memory_tools()}
        if name not in memory_names:
            raise RpcError("unknown_tool")
        return BACKENDS.get_memory().request("tools/call", {"name": name, "arguments": args}, 120)
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > MAX_RESULT:
        raise RpcError("result_too_large")
    return {"content": [{"type": "text", "text": encoded}], "structuredContent": payload}


_SEATS_BRIDGE = "integrity-seats-bridge"
_DEPRECATED_BRIDGE_NAME = "integrity-private-memory-codex-bridge"
_SERVER_NAME = _SEATS_BRIDGE


def resolve_bridge_server_name(requested: str | None) -> str:
    """Advertise Integrity Seats. The retired bridge name remains a deprecated alias."""

    if requested is None or requested == "":
        return _SEATS_BRIDGE
    if requested == _SEATS_BRIDGE:
        return requested
    if requested == _DEPRECATED_BRIDGE_NAME:
        import warnings

        warnings.warn(
            f"{_DEPRECATED_BRIDGE_NAME} is a deprecated alias of {_SEATS_BRIDGE}",
            DeprecationWarning,
            stacklevel=2,
        )
        return requested
    raise ValueError("unknown server name")


def server_info() -> dict:
    return {"name": _SERVER_NAME, "version": VERSION}


def rpc_error(message_id, code: int, message: str, data: dict | None = None) -> dict:
    error = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": message_id, "error": error}


def modern_claim(message: dict) -> bool:
    if message.get("method") == "server/discover":
        return True
    params = message.get("params")
    if not isinstance(params, dict):
        return False
    meta = params.get("_meta")
    return isinstance(meta, dict) and bool(MODERN_META_KEYS.intersection(meta))


def modern_envelope(params: dict, message_id) -> dict | None:
    meta = params.get("_meta")
    if not isinstance(meta, dict):
        return rpc_error(message_id, -32602, "modern MCP request requires params._meta")
    requested = meta.get(PROTOCOL_VERSION_META_KEY)
    if requested != MODERN_MCP_VERSION:
        if isinstance(requested, str):
            return rpc_error(
                message_id,
                -32022,
                "unsupported MCP protocol version",
                {"supported": [MODERN_MCP_VERSION], "requested": requested},
            )
        return rpc_error(message_id, -32602, "modern MCP protocol version is required")
    if not isinstance(meta.get(CLIENT_CAPABILITIES_META_KEY), dict):
        return rpc_error(message_id, -32602, "modern MCP client capabilities are required")
    client_info = meta.get(CLIENT_INFO_META_KEY)
    if client_info is not None and (
        not isinstance(client_info, dict)
        or not isinstance(client_info.get("name"), str)
        or not client_info["name"].strip()
        or not isinstance(client_info.get("version"), str)
        or not client_info["version"].strip()
    ):
        return rpc_error(message_id, -32602, "modern MCP clientInfo is invalid")
    if LOG_LEVEL_META_KEY in meta and not isinstance(meta[LOG_LEVEL_META_KEY], str):
        return rpc_error(message_id, -32602, "modern MCP logLevel is invalid")
    return None


def modern_result_meta() -> dict:
    return {SERVER_INFO_META_KEY: server_info()}


def modern_respond(message: dict) -> dict | None:
    if "id" not in message:
        return None
    message_id = message.get("id")
    params = message.get("params", {})
    if not isinstance(params, dict):
        return rpc_error(message_id, -32602, "params must be an object")
    invalid = modern_envelope(params, message_id)
    if invalid is not None:
        return invalid
    visible = {key: value for key, value in params.items() if key != "_meta"}
    method = message.get("method")
    if method == "server/discover":
        if visible:
            return rpc_error(message_id, -32602, "server/discover accepts only _meta")
        result = {
            "resultType": "complete",
            "supportedVersions": [MODERN_MCP_VERSION],
            "capabilities": {"tools": {}},
            "instructions": (
                "Private owner memory plus bounded access to local Codex tasks. "
                "Reading does not grant authority; codex_send_prompt requires the owner's explicit request."
            ),
            "ttlMs": MODERN_TOOL_CACHE_TTL_MS,
            "cacheScope": "private",
            "_meta": modern_result_meta(),
        }
        return {"jsonrpc": "2.0", "id": message_id, "result": result}
    if method == "tools/list":
        cursor = visible.pop("cursor", None)
        if visible or cursor not in (None, ""):
            return rpc_error(message_id, -32602, "invalid tools/list parameters")
        tools = tool_definitions()
        safe_log("tools_list_ready", count=len(tools), protocol=MODERN_MCP_VERSION)
        return {
            "jsonrpc": "2.0",
            "id": message_id,
            "result": {
                "resultType": "complete",
                "tools": tools,
                "ttlMs": MODERN_TOOL_CACHE_TTL_MS,
                "cacheScope": "private",
                "_meta": modern_result_meta(),
            },
        }
    if method != "tools/call":
        return rpc_error(message_id, -32601, "method not found")
    if set(visible) - {"name", "arguments"}:
        return rpc_error(message_id, -32602, "invalid tool call parameters")
    name = visible.get("name")
    args = visible.get("arguments", {})
    if not isinstance(name, str) or not isinstance(args, dict):
        return rpc_error(message_id, -32602, "invalid tool call")
    try:
        result = call_tool(name, args)
        structured = result.get("structuredContent")
        if not isinstance(structured, dict):
            content = result.get("content") or []
            if not content or not isinstance(content[0], dict):
                raise RpcError("invalid_tool_result")
            structured = json.loads(content[0].get("text", ""))
            if not isinstance(structured, dict):
                raise RpcError("invalid_tool_result")
        result = {
            **result,
            "resultType": "complete",
            "structuredContent": structured,
            "_meta": modern_result_meta(),
        }
        # Keep the compatibility text canonical with structuredContent; the
        # control plane validates their equivalence.
        result["content"] = [{
            "type": "text",
            "text": json.dumps(structured, ensure_ascii=False, separators=(",", ":")),
        }]
        return {"jsonrpc": "2.0", "id": message_id, "result": result}
    except RpcError as exc:
        safe_log("tool_error", method=str(method), error_type=type(exc).__name__)
        result = tool_error_result(exc)
        result.update({"resultType": "complete", "_meta": modern_result_meta()})
        return {"jsonrpc": "2.0", "id": message_id, "result": result}
    except Exception as exc:  # noqa: BLE001 - isolate protocol requests, return explicit error
        safe_log("request_error", method=str(method), error=type(exc).__name__)
        return rpc_error(message_id, -32603, str(exc)[:300])


def respond(message: dict) -> dict | None:
    if "id" not in message:
        return None
    message_id = message.get("id")
    method = message.get("method")
    safe_log("request", method=str(method), id_type=type(message_id).__name__)
    if message.get("jsonrpc") != "2.0" or not isinstance(method, str):
        return rpc_error(message_id, -32600, "invalid request")
    if modern_claim(message):
        return modern_respond(message)
    try:
        if method == "initialize":
            result = {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": server_info(),
            }
        elif method == "tools/list":
            result = {"tools": tool_definitions()}
            safe_log("tools_list_ready", count=len(result["tools"]))
        elif method == "tools/call":
            params = message.get("params") or {}
            args = params.get("arguments") or {}
            if not isinstance(args, dict):
                raise RpcError("invalid_arguments")
            result = call_tool(str(params.get("name") or ""), args)
        elif method == "ping":
            result = {}
        else:
            raise RpcError("method_not_found")
        return {"jsonrpc": "2.0", "id": message_id, "result": result}
    except Exception as exc:  # noqa: BLE001 - isolate protocol requests, return explicit error
        safe_log("request_error", method=str(method), error=type(exc).__name__)
        return {
            "jsonrpc": "2.0",
            "id": message_id,
            "result": {"content": [{"type": "text", "text": json.dumps({"error": str(exc)[:300]})}], "isError": True},
        }


def main():
    # MCP is UTF-8 regardless of the Windows console/code page.
    # Keep the input loop available while the independent backends are waiting.
    import argparse
    import warnings

    global _SERVER_NAME
    parser = argparse.ArgumentParser(description="Integrity Seats bridge")
    parser.add_argument("--server-name", default=None)
    args, _unknown = parser.parse_known_args()
    requested = args.server_name if args.server_name is not None else os.environ.get("INTEGRITY_SERVER_NAME")
    if requested is None:
        try:
            raw = read_config().get("values", {}).get("server_name")
        except ConfigurationError:
            raw = None
        if isinstance(raw, str):
            requested = raw
    try:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", DeprecationWarning)
            _SERVER_NAME = resolve_bridge_server_name(requested)
    except ValueError as err:
        print(str(err), file=sys.stderr)
        raise SystemExit(2) from err
    for item in caught:
        print(item.message, file=sys.stderr)
    write_lock = threading.Lock()
    capacity = threading.BoundedSemaphore(8)
    safe_log("server_started", version=VERSION)

    def process(message):
        started = time.monotonic()
        try:
            output = respond(message)
            if output is not None:
                encoded = json.dumps(output, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                with write_lock:
                    sys.stdout.buffer.write(encoded + b"\n")
                    sys.stdout.buffer.flush()
                safe_log("response", method=str(message.get("method")),
                         request_id=message.get("id"), has_error="error" in output,
                         length=len(encoded), elapsed_ms=round((time.monotonic()-started)*1000))
        except (OSError, ValueError, TypeError, RecursionError) as exc:
            safe_log("stdin_error", error=type(exc).__name__)
        finally:
            capacity.release()

    with ThreadPoolExecutor(max_workers=4) as workers:
        for raw in sys.stdin.buffer:
            try:
                message = json.loads(raw.decode("utf-8"))
                if not isinstance(message, dict):
                    raise TypeError("invalid_message")
                safe_log("stdin_line", length=len(raw), request_id=message.get("id"),
                         method=message.get("method"))
                capacity.acquire()
                # Preserve serialized handling of the existing write tools.
                name = (message.get("params") or {}).get("name")
                if name in {
                    "codex_send_prompt",
                    "codex_interrupt_turn",
                    "codex_archive_task",
                    "codex_unarchive_task",
                    "codex_copy_turn",
                }:
                    process(message)
                else:
                    workers.submit(process, message)
            except (OSError, ValueError, TypeError, RecursionError) as exc:
                safe_log("stdin_error", error=type(exc).__name__)


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    main()
