"""Model-free Codex app-server backend on one host-owned, initialized stream.

No subprocess startup, model API, browser/cookies, reconnect, or RPC forwarding.
Only the four explicit command operations below can be transmitted.
"""
from __future__ import annotations

import base64
import concurrent.futures
import os
import select
import threading
import time
import uuid
from collections.abc import Callable
from pathlib import Path

from .contracts import (
    MAX_FRAME,
    MAX_OUTPUT,
    Rejected,
    Unknown,
    decode,
    encode,
    freeze,
    identifier,
    integer,
    require,
    sha,
)

ALLOWED = {"initialize", "command/exec", "command/exec/write", "command/exec/terminate"}


class RpcChannel:
    """Dedicated POSIX pipes; caller retains process and descriptor ownership.

    Threads never execute tool code. Failure retires this channel and every
    pending request. A possibly sent request is never retried automatically.
    """
    def __init__(self, reader, writer):
        require(os.name == "posix", "rpc_platform_unproven")
        self.reader, self.writer = reader, writer
        self.rfd, self.wfd = reader.fileno(), writer.fileno()
        os.set_blocking(self.rfd, False)
        os.set_blocking(self.wfd, False)
        self._lock = threading.RLock()
        self._write_lock = threading.Lock()
        self._pending = {}
        self._outputs = {}
        self._counter = 0
        self._closed = threading.Event()
        self.ready = False
        self._thread = threading.Thread(target=self._read_loop, daemon=True)
        self._thread.start()

    def _write(self, obj, timeout=3.0):
        raw = encode(obj) + b"\n"
        end = time.monotonic() + timeout
        require(self._write_lock.acquire(timeout=timeout), "rpc_writer_busy")
        try:
            position = 0
            while position < len(raw):
                if self._closed.is_set() or time.monotonic() >= end:
                    raise Unknown("rpc_send_unknown")
                if not select.select([], [self.wfd], [], max(0, end - time.monotonic()))[1]:
                    raise Unknown("rpc_send_unknown")
                try:
                    count = os.write(self.wfd, raw[position:])
                except BlockingIOError:
                    continue
                require(count > 0, "rpc_pipe_closed")
                position += count
        finally:
            self._write_lock.release()

    def request(self, method, params, *, on_output=None):
        require(method in ALLOWED, "rpc_method_not_allowed")
        require(method == "initialize" or self.ready, "rpc_not_initialized")
        params = freeze(params)
        with self._lock:
            require(not self._closed.is_set(), "rpc_closed")
            require(len(self._pending) < (24 if method == "command/exec/terminate" else 16),
                    "rpc_capacity")
            self._counter += 1
            key = self._counter
            future = concurrent.futures.Future()
            pid = params.get("processId") if method == "command/exec" else None
            if pid is not None:
                require(pid not in self._outputs, "duplicate_process_identity")
                self._outputs[pid] = on_output
            self._pending[key] = (future, pid)
        try:
            self._write({"id": key, "method": method, "params": params})
        except Exception:
            self._fail()
        return future

    def initialize(self):
        require(not self.ready, "rpc_already_initialized")
        try:
            self.request("initialize", {"clientInfo": {"name": "integrity_execution_bridge",
                         "version": "0.1.0rc5"}, "capabilities": {
                             "optOutNotificationMethods": ["remoteControl/status/changed"]
                         }}).result(3)
            self._write({"method": "initialized", "params": {}})
            with self._lock:
                require(not self._closed.is_set(), "rpc_closed_during_initialize")
                self.ready = True
        except Exception:
            self._fail()
            raise Unknown("rpc_initialize_failed") from None

    def _message(self, message):
        require(type(message) is dict, "rpc_object_required")
        require("jsonrpc" not in message or message["jsonrpc"] == "2.0", "rpc_version")
        keys = set(message) - {"jsonrpc"}
        if "method" in message:
            require(keys in ({"method", "params"}, {"method", "params", "emittedAtMs"}),
                    "unexpected_server_request")
            if "emittedAtMs" in message:
                integer(message["emittedAtMs"])
            if message["method"] != "command/exec/outputDelta":
                # Unsolicited model turns/tool requests must not be hidden by this adapter.
                raise Rejected("unexpected_server_notification")
            params = message["params"]
            require(type(params) is dict and set(params) ==
                    {"processId", "stream", "deltaBase64", "capReached"}, "output_shape")
            require(params["stream"] in {"stdout", "stderr"}
                    and type(params["capReached"]) is bool, "output_fields")
            require(type(params["deltaBase64"]) is str, "output_base64")
            data = base64.b64decode(params["deltaBase64"], validate=True)
            require(len(data) <= MAX_FRAME, "output_chunk_limit")
            with self._lock:
                callback = self._outputs.get(params["processId"])
            require(callable(callback), "foreign_output")
            callback(data, params["capReached"])
            return
        require(keys in ({"id", "result"}, {"id", "error"}), "rpc_response_shape")
        require(type(message["id"]) is int, "rpc_response_identity")
        if "result" in message:
            require(type(message["result"]) is dict, "rpc_result_shape")
        else:
            require(type(message["error"]) is dict, "rpc_error_shape")
        with self._lock:
            pair = self._pending.pop(message["id"], None)
            require(pair is not None, "orphan_rpc_response")
            future, pid = pair
            if pid is not None:
                self._outputs.pop(pid, None)
        if "error" in message:
            future.set_exception(Unknown("backend_rejected_no_replay"))
        else:
            require(type(message["result"]) is dict, "rpc_result_shape")
            future.set_result(message["result"])

    def _read_loop(self):
        buffer = bytearray()
        try:
            while not self._closed.is_set():
                if not select.select([self.rfd], [], [], 0.1)[0]:
                    continue
                chunk = os.read(self.rfd, 65536)
                if not chunk:
                    raise Unknown("rpc_eof")
                buffer.extend(chunk)
                while b"\n" in buffer:
                    raw, _, tail = buffer.partition(b"\n")
                    buffer = bytearray(tail)
                    self._message(decode(bytes(raw)))
                require(len(buffer) <= MAX_FRAME, "rpc_frame_limit")
        except Exception:
            self._fail()

    def _fail(self):
        with self._lock:
            self._closed.set()
            self.ready = False
            pending, self._pending = self._pending, {}
            self._outputs.clear()
        for future, _ in pending.values():
            if not future.done():
                future.set_exception(Unknown("backend_outcome_unknown"))

    def close(self):
        self._fail()
        if threading.current_thread() is not self._thread:
            self._thread.join(1)


class Job:
    """Bounded merged stdout/stderr by absolute byte cursor; no success inference."""
    def __init__(self, job_id, deadline, stop: Callable, write: Callable):
        self.job_id, self.deadline = job_id, deadline
        self._stop, self._write = stop, write
        self._lock = threading.RLock()
        self.output = bytearray()
        self.base = 0
        self.truncated = False
        self.state = "submitted"
        self.exit_code = None
        self.stop_requested = False
        self.stop_deadline = None
        self.future = None
        self.admission_lock = threading.Lock()
        self._stdin_lock = threading.Lock()
        self._stop_thread = None

    def append(self, data, truncated=False):
        with self._lock:
            # Terminal/unknown evidence cannot accumulate forever.
            if self.state != "submitted":
                return
            self.output.extend(data)
            excess = max(0, len(self.output) - MAX_OUTPUT)
            if excess:
                del self.output[:excess]
                self.base += excess
            self.truncated = self.truncated or truncated or bool(excess)

    def complete(self, future):
        with self._lock:
            if self.state != "submitted":
                return
            try:
                result = future.result()
                require(type(result) is dict and set(result) == {"exitCode", "stdout", "stderr"},
                        "command_result_shape")
                require(type(result["exitCode"]) is int and -(2**31) <= result["exitCode"] < 2**31,
                        "command_exit_type")
                require(result["stdout"] == "" and result["stderr"] == "", "unexpected_buffered_output")
                self.exit_code = result["exitCode"]
                self.state = "reported_exit"
            except Exception:
                self.state = "unknown"

    def stop(self, *, wait=True):
        with self._lock:
            if self.stop_requested or self.state == "reported_exit":
                return
            self.stop_requested = True
            self.stop_deadline = time.monotonic() + 3

        def deliver():
            try:
                self._stop()
            except Exception:
                with self._lock:
                    if self.state == "submitted":
                        self.state = "unknown"
        if wait:
            deliver()
        else:
            # At most one sender per bounded retained job. A blocked backend
            # cannot stall the shared owner-control watcher for every task.
            self._stop_thread = threading.Thread(target=deliver, daemon=True)
            try:
                self._stop_thread.start()
            except Exception:
                with self._lock:
                    if self.state == "submitted":
                        self.state = "unknown"

    def write(self, data, close_stdin):
        require(type(data) is bytes and len(data) <= 16384
                and type(close_stdin) is bool and (data or close_stdin), "invalid_stdin")
        require(self._stdin_lock.acquire(blocking=False), "stdin_busy")
        try:
            with self._lock:
                require(self.state == "submitted" and not self.stop_requested
                        and time.monotonic() < self.deadline, "job_not_writable")
            return self._write(data, close_stdin)
        finally:
            self._stdin_lock.release()

    def tick(self, *, revoked=False):
        with self._lock:
            if self.state != "submitted":
                return
            should_stop = revoked or time.monotonic() >= self.deadline
        if should_stop:
            self.stop(wait=False)
        with self._lock:
            # Recheck under lock: a racing, valid exit must not become unknown.
            if (self.state == "submitted" and self.stop_deadline is not None
                    and time.monotonic() >= self.stop_deadline):
                self.state = "unknown"

    def read(self, after, max_bytes):
        integer(after)
        integer(max_bytes, 1, 16384)
        with self._lock:
            total = self.base + len(self.output)
            require(0 <= after <= total, "invalid_output_cursor")
            start = max(after, self.base)
            data = bytes(self.output[start - self.base:start - self.base + max_bytes])
            return {"job_id": self.job_id, "state": self.state, "exit_code": self.exit_code,
                    "output_b64": base64.b64encode(data).decode(), "stream": "merged",
                    "next_cursor": start + len(data), "gap": after < self.base,
                    "truncated": self.truncated, "stop_requested": self.stop_requested,
                    "cleanup_required": self.state != "reported_exit",
                    "host_cleanup_witness_required": True,
                    "independent_acceptance": False, "replay_allowed": False}


class CodexExecutor:
    """Only standalone command execution. Sandbox and environment are host-owned.

    Host must verify effective Codex binary/config/isolation beforehand. This
    request contract is not proof of actual kernel enforcement.
    """
    def __init__(self, channel: RpcChannel, sandbox_policy: dict, *, environment: dict | None = None):
        self._channel = channel
        self._instance_id = uuid.uuid4().hex
        policy = freeze(sandbox_policy)
        require(type(policy) is dict, "sandbox_required")
        kind = policy.get("type")
        require(kind in {"readOnly", "workspaceWrite"}, "sandbox_required")
        require(policy.get("networkAccess") is False, "network_must_be_disabled")
        expected = {"type", "networkAccess"}
        if kind == "workspaceWrite":
            expected |= {"writableRoots", "excludeTmpdirEnvVar", "excludeSlashTmp"}
            roots = policy.get("writableRoots")
            require(type(roots) is list and 1 <= len(roots) <= 8 and all(
                type(root) is str and Path(root).is_absolute()
                and Path(root).is_dir() and str(Path(root).resolve()) == root
                for root in roots), "sandbox_roots_required")
            require(len(set(roots)) == len(roots), "duplicate_sandbox_root")
            require(policy.get("excludeTmpdirEnvVar") is True
                    and policy.get("excludeSlashTmp") is True, "sandbox_tmp_policy")
        require(set(policy) == expected, "sandbox_shape")
        self._sandbox = policy
        env = freeze({} if environment is None else environment)
        require(type(env) is dict and len(env) <= 128 and all(
            type(k) is str and 0 < len(k) <= 256 and "=" not in k and "\x00" not in k
            and (v is None or (type(v) is str and len(v) <= 8192 and "\x00" not in v))
            for k, v in env.items()), "environment_shape")
        self._environment = env

    @property
    def channel(self):
        return self._channel

    @property
    def sandbox(self):
        return freeze(self._sandbox)

    @property
    def environment(self):
        return freeze(self._environment)

    @property
    def binding(self):
        return {"backend": "codex-app-server-command-v2", "instance_id": self._instance_id,
                "sandbox": freeze(self.sandbox),
                "environment_sha256": sha(encode(self.environment))}

    def start(self, *, job_id, argv, cwd, deadline):
        identifier(job_id)
        require(type(argv) in (list, tuple) and 1 <= len(argv) <= 64
                and all(type(part) is str and "\x00" not in part and len(part) <= 8192
                        for part in argv) and Path(argv[0]).is_absolute(), "invalid_argv")
        require(type(cwd) is str and Path(cwd).is_absolute() and "\x00" not in cwd, "invalid_cwd")
        require(self.channel.ready, "backend_not_ready")
        timeout = max(1, int((deadline - time.monotonic()) * 1000))
        require(time.monotonic() < deadline, "job_deadline")

        def stop():
            self.channel.request("command/exec/terminate", {"processId": job_id}).result(3)

        def write(data, close_stdin):
            params = {"processId": job_id, "deltaBase64": base64.b64encode(data).decode(),
                      "closeStdin": close_stdin}
            return self.channel.request("command/exec/write", params).result(3)

        job = Job(job_id, deadline, stop, write)
        future = self.channel.request("command/exec", {
            "processId": job_id, "command": list(argv), "cwd": cwd,
            "streamStdin": True, "streamStdoutStderr": True, "timeoutMs": timeout,
            "outputBytesCap": MAX_OUTPUT, "sandboxPolicy": self.sandbox,
            "env": self.environment,
        }, on_output=job.append)
        job.future = future
        future.add_done_callback(job.complete)
        return job
