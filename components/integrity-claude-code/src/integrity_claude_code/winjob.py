"""Windows Job Object launcher: suspended spawn -> job assign -> resume, bounded I/O, verified stop.

Job Object containment bounds the process TREE (no breakaway, kill on close, process
and memory limits). It is NOT a sandbox: filesystem, registry and network access of
the executor account are not restricted here. Stop is reported verified only when
the Job reports zero active processes, its process-id list is empty, every process
the job announced was observed, and every held process handle is signaled -- never
from a request or ACK.
"""
from __future__ import annotations

import ctypes
import hashlib
import os
import subprocess
import threading
import time
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from . import _winabi as abi
from .canonical import Rejected, need
from .identity import executable_identity, require_plain_path

_CHUNK = 64 * 1024
_STDIN_CHUNK = 4096
_POLL_SECONDS = 0.02
_SUSPENDED_KILL_MS = 5000


class NotStarted(Exception):
    """No executor code ran: refused before spawn, or the never-resumed process was killed
    and the kill verified."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class StopUnverified(Exception):
    """A process existed and could not be proven stopped. Never retry; hold the session."""

    def __init__(self, code: str, stop: dict | None = None):
        super().__init__(code)
        self.code, self.stop = code, stop


class SupervisorFault(Exception):
    """Unexpected supervisor failure after resume. The tree was terminated; see ``stop``."""

    def __init__(self, stop: dict):
        super().__init__("supervisor_exception")
        self.code, self.stop = "supervisor_exception", stop
        self.stop_verified = bool(stop.get("verified"))


@dataclass
class JobResult:
    started: bool
    exit_code: int | None      # natural exit code of the root process, else None
    termination: str | None    # None or a record.TERMINATIONS member
    stop_verified: bool
    stop: dict
    stdin: dict
    stdout: dict
    stderr: dict
    threads_stopped: bool
    orphans_terminated: int


def _close(k, handle) -> None:
    if handle:
        k.CloseHandle(handle)


def _error(code: str) -> Rejected:
    return Rejected(f"{code}_winerror_{ctypes.get_last_error()}")


class _PinnedImage:
    """Hold the executable open (share-read only) from hash to spawn: no swap in between."""

    def __init__(self, k, path: Path, expected_sha256: str):
        executable_identity(path)  # .exe, not a shell, not a link, PE header, bounded size
        self.k, self.handle = k, None
        handle = k.CreateFileW(str(path), abi.GENERIC_READ, abi.FILE_SHARE_READ, None,
                               abi.OPEN_EXISTING, abi.FILE_ATTRIBUTE_NORMAL, None)
        if handle in (None, abi.INVALID_HANDLE_VALUE):
            raise _error("executable_open")
        self.handle = handle
        try:
            self._verify(k, path, expected_sha256)
        except BaseException:
            self.release()
            raise

    def _verify(self, k, path: Path, expected_sha256: str) -> None:
        buffer = ctypes.create_unicode_buffer(32768)
        length = k.GetFinalPathNameByHandleW(self.handle, buffer, len(buffer), 0)
        need(0 < length < len(buffer), "executable_final_path")
        final = buffer.value.removeprefix("\\\\?\\")
        need(os.path.normcase(final) == os.path.normcase(os.path.abspath(path)),
             "executable_final_path_mismatch")
        hasher, chunk, read = hashlib.sha256(), ctypes.create_string_buffer(_CHUNK), wintypes.DWORD()
        while True:
            if not k.ReadFile(self.handle, chunk, _CHUNK, ctypes.byref(read), None):
                raise _error("executable_read")
            if read.value == 0:
                break
            hasher.update(chunk.raw[: read.value])
        need("sha256:" + hasher.hexdigest() == expected_sha256, "executable_digest_mismatch")

    def release(self) -> None:
        _close(self.k, self.handle)
        self.handle = None


class _Reader(threading.Thread):
    def __init__(self, k, handle, limit: int, sink: Callable[[bytes], None] | None):
        super().__init__(daemon=True, name="integrity-claude-reader")
        self.k, self.handle, self.limit, self.sink = k, handle, limit, sink
        self.hasher, self.total = hashlib.sha256(), 0
        self.overflow, self.violation, self.failed = (threading.Event(), threading.Event(),
                                                      threading.Event())

    def run(self) -> None:
        buffer, read = ctypes.create_string_buffer(_CHUNK), wintypes.DWORD()
        try:
            while True:
                if not self.k.ReadFile(self.handle, buffer, _CHUNK, ctypes.byref(read), None):
                    if ctypes.get_last_error() != abi.ERROR_BROKEN_PIPE:
                        self.failed.set()
                    return
                if read.value == 0:
                    return
                data = buffer.raw[: read.value]
                if self.total + len(data) > self.limit:
                    self.overflow.set()
                    return
                self.total += len(data)
                self.hasher.update(data)
                if self.sink is not None and not self.violation.is_set():
                    try:
                        self.sink(data)
                    except Rejected:
                        self.violation.set()  # the parser keeps its own closed code
                        return  # stop reading: the first violation decides the outcome
        except BaseException:
            self.failed.set()  # unexpected: the supervisor must stop the tree now
        finally:
            _close(self.k, self.handle)
            self.handle = None

    def summary(self) -> dict:
        return {"bytes": self.total, "sha256": "sha256:" + self.hasher.hexdigest(),
                "overflow": self.overflow.is_set()}


class _Writer(threading.Thread):
    """Bounded stdin writer: a child that never reads cannot block the supervisor."""

    def __init__(self, k, handle, payload: bytes):
        super().__init__(daemon=True, name="integrity-claude-stdin")
        self.k, self.handle, self.payload, self.written = k, handle, payload, 0
        self.refused, self.failed = False, threading.Event()

    def run(self) -> None:
        written = wintypes.DWORD()
        try:
            while self.written < len(self.payload):
                piece = self.payload[self.written:self.written + _STDIN_CHUNK]
                if not self.k.WriteFile(self.handle, piece, len(piece), ctypes.byref(written), None):
                    self.refused = True  # reader side gone (child exited or was killed)
                    return
                self.written += written.value
        except BaseException:
            self.failed.set()
        finally:
            _close(self.k, self.handle)  # EOF for the child
            self.handle = None


class _Monitor(threading.Thread):
    """Drain job notifications; open a handle to every new process for independent checks."""

    def __init__(self, k, job, port):
        super().__init__(daemon=True, name="integrity-claude-job-monitor")
        self.k, self.job, self.port = k, job, port
        self.handles: dict[int, object] = {}
        self.unopened: set[int] = set()
        self.foreign: set[int] = set()
        self.zero = threading.Event()
        self.stop_flag = threading.Event()
        self.lock = threading.Lock()

    def run(self) -> None:
        message, key, overlapped = wintypes.DWORD(), ctypes.c_size_t(), ctypes.c_void_p()
        while not self.stop_flag.is_set():
            if not self.k.GetQueuedCompletionStatus(self.port, ctypes.byref(message),
                                                    ctypes.byref(key), ctypes.byref(overlapped), 50):
                continue
            if message.value == abi.MSG_ACTIVE_PROCESS_ZERO:
                self.zero.set()
            elif message.value == abi.MSG_NEW_PROCESS:
                self._track(int(overlapped.value or 0))

    def _track(self, pid: int) -> None:
        handle = self.k.OpenProcess(abi.SYNCHRONIZE | abi.PROCESS_QUERY_LIMITED_INFORMATION,
                                    False, pid)
        with self.lock:
            if not handle:
                self.unopened.add(pid)  # exited before it could be opened
                return
            member = wintypes.BOOL()
            if not self.k.IsProcessInJob(handle, self.job, ctypes.byref(member)) or not member.value:
                self.foreign.add(pid)  # PID already reused by an unrelated process
                _close(self.k, handle)
                return
            self.handles.setdefault(pid, handle)

    def tracked(self) -> int:
        with self.lock:
            return len(self.handles) + len(self.unopened) + len(self.foreign)


class JobProcess:
    def __init__(self, *, executable: Path, executable_sha256: str, argv: list, cwd: Path,
                 environment: dict, stdin: bytes, limits: dict,
                 stdout_sink: Callable[[bytes], None] | None = None,
                 cancel: threading.Event | None = None,
                 on_started: Callable[[], None] | None = None,
                 launch_lock: threading.Lock | None = None):
        self.executable = require_plain_path(Path(executable), "executable")
        self.expected = executable_sha256
        self.argv = list(argv)
        self.cwd = require_plain_path(Path(cwd), "cwd")
        need(self.cwd.is_dir(), "cwd_missing")
        need(type(environment) is dict and environment, "environment_shape")
        self.environment = dict(environment)
        need(type(stdin) is bytes, "stdin_bytes")
        self.stdin = stdin
        self.limits = limits
        self.sink = stdout_sink
        self.cancel = cancel or threading.Event()
        self.on_started = on_started
        # Held by the canceller while it records/sets a cancel and by us across the final
        # cancel check + ResumeThread: a cancel is either before resume or after it.
        self.launch_lock = launch_lock or threading.Lock()
        self._job_lock = threading.Lock()
        self._job_handle = None
        self._k = None

    def contains_process(self, handle) -> bool:
        """True only while running and only if the given live process handle is in this Job."""
        with self._job_lock:
            k, job = self._k, self._job_handle
            if k is None or not job or not handle:
                return False
            member = wintypes.BOOL()
            return bool(k.IsProcessInJob(handle, job, ctypes.byref(member)) and member.value)

    # -- construction helpers ---------------------------------------------------
    def _job(self, k):
        job = k.CreateJobObjectW(None, None)
        if not job:
            raise _error("job_create")
        limits = abi.ExtendedLimit()
        limits.basic.flags = (abi.LIMIT_ACTIVE_PROCESS | abi.LIMIT_JOB_MEMORY
                              | abi.LIMIT_KILL_ON_JOB_CLOSE | abi.LIMIT_DIE_ON_UNHANDLED_EXCEPTION)
        limits.basic.active_process_limit = self.limits["max_processes"]
        limits.job_memory_limit = self.limits["job_memory_bytes"]
        if not k.SetInformationJobObject(job, abi.JOB_EXTENDED_LIMIT, ctypes.byref(limits),
                                         ctypes.sizeof(limits)):
            _close(k, job)
            raise _error("job_limits")
        return job

    @staticmethod
    def _port(k, job):
        port = k.CreateIoCompletionPort(abi.INVALID_HANDLE_VALUE, None, 0, 1)
        if not port:
            raise _error("job_port")
        association = abi.CompletionPortAssociation(None, port)
        if not k.SetInformationJobObject(job, abi.JOB_ASSOCIATE_COMPLETION_PORT,
                                         ctypes.byref(association), ctypes.sizeof(association)):
            _close(k, port)
            raise _error("job_port_association")
        return port

    @staticmethod
    def _pipe(k, owned: list, child_reads: bool):
        attributes = abi.SecurityAttributes(ctypes.sizeof(abi.SecurityAttributes), None, True)
        read, write = wintypes.HANDLE(), wintypes.HANDLE()
        if not k.CreatePipe(ctypes.byref(read), ctypes.byref(write), ctypes.byref(attributes), 0):
            raise _error("pipe_create")
        owned.extend((read.value, write.value))  # owned immediately: closed on any later failure
        if not k.SetHandleInformation(write if child_reads else read, abi.HANDLE_FLAG_INHERIT, 0):
            raise _error("pipe_inherit")
        return read.value, write.value

    def _environment_block(self):
        records = []
        for name, value in sorted(self.environment.items(), key=lambda item: item[0].upper()):
            need(type(name) is str and name and "=" not in name and "\x00" not in name
                 and type(value) is str and "\x00" not in value, "environment_entry")
            records.append(f"{name}={value}")
        return ctypes.create_unicode_buffer("\x00".join(records) + "\x00\x00")

    def _command_line(self) -> str:
        for token in self.argv:
            need(type(token) is str and "\x00" not in token, "argv_token")
        return subprocess.list2cmdline([str(self.executable), *self.argv])

    # -- stop -------------------------------------------------------------------
    def _terminate_and_verify(self, k, job, monitor: _Monitor, hard_deadline: float) -> dict:
        k.TerminateJobObject(job, abi.TERMINATED_EXIT_CODE)
        accounting, pids = abi.BasicAccounting(), abi.process_id_list(64)
        active = assigned = total = None
        while True:
            ok = k.QueryInformationJobObject(job, abi.JOB_BASIC_ACCOUNTING, ctypes.byref(accounting),
                                             ctypes.sizeof(accounting), None)
            ok_list = k.QueryInformationJobObject(job, abi.JOB_BASIC_PROCESS_ID_LIST,
                                                  ctypes.byref(pids), ctypes.sizeof(pids), None)
            active = int(accounting.active_processes) if ok else None
            total = int(accounting.total_processes) if ok else None
            assigned = int(pids.assigned) if ok_list else None
            if active == 0 and assigned == 0 and total is not None and monitor.tracked() >= total:
                break
            if time.monotonic() >= hard_deadline:
                break
            k.TerminateJobObject(job, abi.TERMINATED_EXIT_CODE)
            time.sleep(_POLL_SECONDS)
        with monitor.lock:
            handles = list(monitor.handles.values())
            unopened, foreign = len(monitor.unopened), len(monitor.foreign)
        signaled = 0
        for handle in handles:
            remaining = max(0, int((hard_deadline - time.monotonic()) * 1000))
            if k.WaitForSingleObject(handle, remaining) == abi.WAIT_OBJECT_0:
                signaled += 1
        verified = (active == 0 and assigned == 0 and signaled == len(handles) and foreign == 0
                    and total is not None and total == len(handles) + unopened)
        return {"verified": verified, "active_processes": active, "assigned_processes": assigned,
                "processes_total": total, "handles_held": len(handles), "handles_signaled": signaled,
                "processes_unopened": unopened, "pid_reuse_detected": foreign,
                "zero_notification": monitor.zero.is_set()}

    @staticmethod
    def _kill_unassigned(k, info) -> bool:
        k.TerminateProcess(info.process, abi.TERMINATED_EXIT_CODE)
        return k.WaitForSingleObject(info.process, _SUSPENDED_KILL_MS) == abi.WAIT_OBJECT_0

    # -- main -------------------------------------------------------------------
    def run(self) -> JobResult:
        if self.cancel.is_set():
            raise NotStarted("cancelled_before_start")
        k = abi.load()
        hard_deadline = time.monotonic() + self.limits["deadline_seconds"]
        grace = self.limits["stop_grace_seconds"]
        kill_at = hard_deadline - grace
        pinned = job = port = monitor = storage = None
        info = abi.ProcessInformation()
        owned: list = []
        threads: list[threading.Thread] = []
        assigned = False
        try:
            try:
                pinned = _PinnedImage(k, self.executable, self.expected)
                job = self._job(k)
                port = self._port(k, job)
                monitor = _Monitor(k, job, port)
                monitor.start()
                stdin_read, stdin_write = self._pipe(k, owned, child_reads=True)
                stdout_read, stdout_write = self._pipe(k, owned, child_reads=False)
                stderr_read, stderr_write = self._pipe(k, owned, child_reads=False)
                child = (stdin_read, stdout_write, stderr_write)
                inherit = (wintypes.HANDLE * 3)(*child)
                size = ctypes.c_size_t()
                k.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size))
                need(size.value > 0, "attribute_list_size")
                buffer = ctypes.create_string_buffer(size.value)
                if not k.InitializeProcThreadAttributeList(buffer, 1, 0, ctypes.byref(size)):
                    raise _error("attribute_list")
                storage = buffer
                if not k.UpdateProcThreadAttribute(buffer, 0, abi.PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                                   inherit, ctypes.sizeof(inherit), None, None):
                    raise _error("attribute_handle_list")
                startup = abi.StartupInfoEx()
                startup.startup.cb = ctypes.sizeof(startup)
                startup.startup.flags = abi.STARTF_USESTDHANDLES
                startup.startup.stdin, startup.startup.stdout, startup.startup.stderr = child
                startup.attributes = ctypes.cast(buffer, ctypes.c_void_p)
                command = ctypes.create_unicode_buffer(self._command_line())
                block = self._environment_block()
                flags = (abi.CREATE_SUSPENDED | abi.CREATE_UNICODE_ENVIRONMENT
                         | abi.EXTENDED_STARTUPINFO_PRESENT | abi.CREATE_NO_WINDOW)
                if self.cancel.is_set():
                    raise NotStarted("cancelled_before_start")
                if not k.CreateProcessW(str(self.executable), command, None, None, True, flags,
                                        block, str(self.cwd), ctypes.byref(startup),
                                        ctypes.byref(info)):
                    raise NotStarted(f"spawn_refused_winerror_{ctypes.get_last_error()}")
            except Rejected as exc:
                raise NotStarted(exc.code) from None
            pinned.release()
            # Suspended: no executor instruction has run yet.
            if not k.AssignProcessToJobObject(job, info.process):
                code = ctypes.get_last_error()
                if not self._kill_unassigned(k, info):
                    raise StopUnverified("suspended_kill_unverified")
                raise NotStarted(f"job_assign_refused_winerror_{code}")
            assigned = True
            with self._job_lock:
                self._k, self._job_handle = k, job
            for handle in child:
                owned.remove(handle)
                _close(k, handle)
            writer = _Writer(k, stdin_write, self.stdin)
            out = _Reader(k, stdout_read, self.limits["max_stdout_bytes"], self.sink)
            err = _Reader(k, stderr_read, self.limits["max_stderr_bytes"], None)
            for thread, handle in ((out, stdout_read), (err, stderr_read)):
                owned.remove(handle)  # the reader owns and closes it from here
                thread.start()
                threads.append(thread)
            with self.launch_lock:  # last cancel checkpoint, atomic with the resume
                refusal = "cancelled_before_resume" if self.cancel.is_set() else None
                if refusal is None and k.ResumeThread(info.thread) == abi.INFINITE_WAIT_FORBIDDEN:
                    refusal = "resume_refused"
            if refusal is not None:
                stop = self._terminate_and_verify(k, job, monitor,
                                                  min(hard_deadline, time.monotonic() + grace))
                if not stop["verified"]:
                    raise StopUnverified("suspended_kill_unverified", stop)
                raise NotStarted(refusal)
            owned.remove(stdin_write)
            writer.start()
            threads.append(writer)
            termination = None
            if self.on_started is not None:
                try:
                    self.on_started()
                except Exception:
                    termination = "callback_error"
            exit_code = None
            while termination is None:
                if self.cancel.is_set():
                    termination = "cancelled"
                elif out.overflow.is_set():
                    termination = "stdout_limit"
                elif err.overflow.is_set():
                    termination = "stderr_limit"
                elif out.violation.is_set():
                    termination = "protocol_violation"
                elif out.failed.is_set() or err.failed.is_set() or writer.failed.is_set():
                    termination = "io_error"
                elif time.monotonic() >= kill_at:
                    termination = "deadline"
                else:
                    wait = k.WaitForSingleObject(info.process, int(_POLL_SECONDS * 1000))
                    if wait == abi.WAIT_OBJECT_0:
                        code = wintypes.DWORD()
                        if k.GetExitCodeProcess(info.process, ctypes.byref(code)):
                            exit_code = int(code.value)
                        else:
                            termination = "io_error"
                        break
                    if wait != abi.WAIT_TIMEOUT:
                        termination = "io_error"
            accounting = abi.BasicAccounting()
            orphans = 0
            if exit_code is not None and k.QueryInformationJobObject(
                    job, abi.JOB_BASIC_ACCOUNTING, ctypes.byref(accounting),
                    ctypes.sizeof(accounting), None):
                orphans = int(accounting.active_processes)
            # Always terminate the whole tree; after a natural root exit this removes orphans.
            stop = self._terminate_and_verify(k, job, monitor, hard_deadline)
            for thread in threads:
                thread.join(max(0.0, hard_deadline - time.monotonic()))
            threads_stopped = not any(thread.is_alive() for thread in threads)
            for flag, name in ((out.overflow, "stdout_limit"), (err.overflow, "stderr_limit"),
                               (out.violation, "protocol_violation"), (out.failed, "io_error"),
                               (err.failed, "io_error"), (writer.failed, "io_error")):
                if termination is None and flag.is_set():
                    termination = name
            return JobResult(
                started=True, exit_code=exit_code, termination=termination,
                stop_verified=bool(stop["verified"] and threads_stopped), stop=stop,
                stdin={"bytes": len(self.stdin), "written": writer.written,
                       "complete": writer.written == len(self.stdin)},
                stdout=out.summary(), stderr=err.summary(), threads_stopped=threads_stopped,
                orphans_terminated=orphans)
        except (NotStarted, StopUnverified):
            raise
        except BaseException:
            # Keyed on the real process handle, not on a flag set after CreateProcessW.
            if not info.process:
                raise NotStarted("preflight_rejected") from None
            if not assigned:
                if not self._kill_unassigned(k, info):
                    raise StopUnverified("suspended_kill_unverified") from None
                raise NotStarted("preflight_rejected") from None
            stop = self._terminate_and_verify(k, job, monitor,
                                              min(hard_deadline, time.monotonic() + grace)
                                              if time.monotonic() < hard_deadline
                                              else time.monotonic())
            raise SupervisorFault(stop) from None
        finally:
            with self._job_lock:
                self._k, self._job_handle = None, None
            if pinned is not None:
                pinned.release()
            if storage is not None:
                k.DeleteProcThreadAttributeList(storage)
            for handle in owned:
                _close(k, handle)
            for thread in threads:  # same single budget; never extends past the deadline
                thread.join(max(0.0, hard_deadline - time.monotonic()))
            _close(k, info.thread)
            _close(k, info.process)
            if monitor is not None:
                monitor.stop_flag.set()
                monitor.join(max(0.0, hard_deadline - time.monotonic()))
                with monitor.lock:
                    for handle in monitor.handles.values():
                        _close(k, handle)
                    monitor.handles.clear()
            _close(k, job)  # KILL_ON_JOB_CLOSE: last resort for anything left
            _close(k, port)
