"""Fail-closed Win32 Job Object process boundary for native collectors."""

from __future__ import annotations

import ctypes
import os
import sys
import threading
import time
from dataclasses import dataclass

from ._windows_job_abi import (
    JobExtendedLimitInformation as _JobExtendedLimitInformation,
)
from ._windows_job_abi import ProcessInformation as _ProcessInformation
from ._windows_job_abi import SecurityAttributes as _SecurityAttributes
from ._windows_job_abi import StartupInfoEx as _StartupInfoEx
from ._windows_job_abi import kernel32 as _kernel32
from ._windows_job_abi import wintypes

_CREATE_SUSPENDED = 0x00000004
_CREATE_UNICODE_ENVIRONMENT = 0x00000400
_EXTENDED_STARTUPINFO_PRESENT = 0x00080000
_CREATE_NO_WINDOW = 0x08000000
_STARTF_USESTDHANDLES = 0x00000100
_HANDLE_FLAG_INHERIT = 0x00000001
_PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002
_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
_JOB_OBJECT_LIMIT_PROCESS_TIME = 0x00000002
_JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
_JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_WAIT_OBJECT_0 = 0x00000000
_WAIT_TIMEOUT = 0x00000102
_ERROR_BROKEN_PIPE = 109
_TERMINATED_EXIT_CODE = 0xC000013A
_WAIT_SLICE_MILLISECONDS = 20
_MAXIMUM_PROCESSES = 32
_PROCESS_MEMORY_BYTES = 256 * 1024 * 1024


class WindowsJobBoundaryError(ValueError):
    """Raised when Windows process containment cannot be proven."""


class WindowsJobPreflightError(WindowsJobBoundaryError):
    """Raised before the suspended child is created."""


class WindowsJobTimeoutError(WindowsJobBoundaryError):
    """Raised after the bounded Job Object reaches its time limit."""


class WindowsJobOutputBoundError(WindowsJobBoundaryError):
    """Raised after either captured stream crosses its committed bound."""


class WindowsJobPostStartError(WindowsJobBoundaryError):
    """Raised when the child may have acted before its boundary failed."""


def _classify_boundary_failure(
    error: WindowsJobBoundaryError,
    *,
    started: bool,
) -> WindowsJobBoundaryError:
    if started and not isinstance(
        error,
        (
            WindowsJobOutputBoundError,
            WindowsJobPostStartError,
            WindowsJobTimeoutError,
        ),
    ):
        return WindowsJobPostStartError("collector post-start boundary failed")
    return error


def _require_windows() -> None:
    if os.name != "nt" or _kernel32 is None:
        raise WindowsJobBoundaryError("Win32 Job Object boundary requires Windows")


def _raise_last_error(message: str) -> None:
    code = ctypes.get_last_error()
    raise WindowsJobBoundaryError(f"{message} (winerror {code})")


def _close_handle(handle: object | None) -> None:
    if handle:
        _kernel32.CloseHandle(handle)


def _create_pipe(*, child_reads: bool) -> tuple[object, object]:
    attributes = _SecurityAttributes()
    attributes.length = ctypes.sizeof(attributes)
    attributes.inherit_handle = True
    read_handle = wintypes.HANDLE()
    write_handle = wintypes.HANDLE()
    if not _kernel32.CreatePipe(
        ctypes.byref(read_handle),
        ctypes.byref(write_handle),
        ctypes.byref(attributes),
        0,
    ):
        _raise_last_error("collector pipe construction failed")
    parent_handle = write_handle if child_reads else read_handle
    if not _kernel32.SetHandleInformation(
        parent_handle,
        _HANDLE_FLAG_INHERIT,
        0,
    ):
        _close_handle(read_handle)
        _close_handle(write_handle)
        _raise_last_error("collector pipe inheritance restriction failed")
    return read_handle, write_handle


def _quote_windows_argument(value: str) -> str:
    if "\x00" in value:
        raise WindowsJobBoundaryError("collector argument contains NUL")
    needs_quotes = not value or " " in value or "\t" in value
    output = ['"'] if needs_quotes else []
    backslashes = 0
    for character in value:
        if character == "\\":
            backslashes += 1
            continue
        if character == '"':
            output.append("\\" * (backslashes * 2 + 1))
            output.append('"')
            backslashes = 0
            continue
        output.append("\\" * backslashes)
        output.append(character)
        backslashes = 0
    output.append("\\" * (backslashes * (2 if needs_quotes else 1)))
    if needs_quotes:
        output.append('"')
    return "".join(output)


def _command_line(executable: str, argv: tuple[str, ...]) -> str:
    return " ".join(
        _quote_windows_argument(value)
        for value in (executable, *argv)
    )


def _environment_block(environment: dict[str, str]) -> ctypes.Array:
    records: list[str] = []
    for key, value in sorted(environment.items(), key=lambda item: item[0].upper()):
        if not key or "=" in key or "\x00" in key or "\x00" in value:
            raise WindowsJobBoundaryError("collector environment rejected")
        records.append(f"{key}={value}")
    return ctypes.create_unicode_buffer("\x00".join(records) + "\x00\x00")


def collector_environment(credential_reference: str | None) -> dict[str, str]:
    """Build the exact non-inherited environment required by Windows itself."""

    _require_windows()
    buffer = ctypes.create_unicode_buffer(32768)
    length = _kernel32.GetWindowsDirectoryW(buffer, len(buffer))
    if length == 0 or length >= len(buffer):
        _raise_last_error("Windows system directory unavailable")
    windows_directory = buffer.value
    return {
        "SystemRoot": windows_directory,
        "WINDIR": windows_directory,
        "GUARDIAN_CREDENTIAL_REFERENCE": credential_reference or "",
    }


@dataclass
class _PipeCapture:
    handle: object
    maximum_bytes: int

    def __post_init__(self) -> None:
        self.payload = bytearray()
        self.overflowed = threading.Event()
        self.error: WindowsJobBoundaryError | None = None
        self.thread = threading.Thread(
            target=self._read,
            name="integrity-windows-collector-pipe",
            daemon=True,
        )

    def start(self) -> None:
        self.thread.start()

    def _read(self) -> None:
        try:
            while True:
                buffer = ctypes.create_string_buffer(64 * 1024)
                received = wintypes.DWORD()
                if not _kernel32.ReadFile(
                    self.handle,
                    buffer,
                    len(buffer),
                    ctypes.byref(received),
                    None,
                ):
                    code = ctypes.get_last_error()
                    if code == _ERROR_BROKEN_PIPE:
                        return
                    self.error = WindowsJobBoundaryError(
                        f"collector output capture failed (winerror {code})"
                    )
                    return
                if received.value == 0:
                    return
                remaining = self.maximum_bytes + 1 - len(self.payload)
                self.payload.extend(buffer.raw[: min(received.value, remaining)])
                if len(self.payload) > self.maximum_bytes:
                    self.overflowed.set()
                    return
        finally:
            _close_handle(self.handle)
            self.handle = None

    def join(self) -> bytes:
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            raise WindowsJobBoundaryError("collector output capture did not stop")
        if self.error is not None:
            raise self.error
        return bytes(self.payload)


def _configured_job(timeout_seconds: int) -> object:
    job = _kernel32.CreateJobObjectW(None, None)
    if not job:
        _raise_last_error("collector Job Object construction failed")
    limits = _JobExtendedLimitInformation()
    limits.basic_limit_information.per_process_user_time_limit = (
        timeout_seconds * 10_000_000
    )
    limits.basic_limit_information.limit_flags = (
        _JOB_OBJECT_LIMIT_PROCESS_TIME
        | _JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | _JOB_OBJECT_LIMIT_PROCESS_MEMORY
        | _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    )
    limits.basic_limit_information.active_process_limit = _MAXIMUM_PROCESSES
    limits.process_memory_limit = _PROCESS_MEMORY_BYTES
    if not _kernel32.SetInformationJobObject(
        job,
        _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
        ctypes.byref(limits),
        ctypes.sizeof(limits),
    ):
        _close_handle(job)
        _raise_last_error("collector Job Object limits failed")
    return job


def run_windows_job(
    executable: str,
    argv: tuple[str, ...],
    *,
    working_directory: str,
    environment: dict[str, str],
    timeout_seconds: int,
    maximum_output_bytes: int,
) -> tuple[int, bytes, bytes]:
    """Run one executable only after exact Job Object containment is active."""

    _require_windows()
    job = _configured_job(timeout_seconds)
    process = _ProcessInformation()
    stdin_read = stdin_write = None
    stdout_read = stdout_write = None
    stderr_read = stderr_write = None
    attribute_list = None
    stdout_capture = stderr_capture = None
    started = False
    timed_out = False
    output_exceeded = False
    stdout_payload = b""
    stderr_payload = b""
    try:
        stdin_read, stdin_write = _create_pipe(child_reads=True)
        stdout_read, stdout_write = _create_pipe(child_reads=False)
        stderr_read, stderr_write = _create_pipe(child_reads=False)
        _close_handle(stdin_write)
        stdin_write = None

        handles = (wintypes.HANDLE * 3)(
            stdin_read,
            stdout_write,
            stderr_write,
        )
        attribute_size = ctypes.c_size_t()
        _kernel32.InitializeProcThreadAttributeList(
            None,
            1,
            0,
            ctypes.byref(attribute_size),
        )
        if attribute_size.value == 0:
            _raise_last_error("collector handle-list size unavailable")
        attribute_storage = ctypes.create_string_buffer(attribute_size.value)
        attribute_list = ctypes.cast(attribute_storage, ctypes.c_void_p)
        if not _kernel32.InitializeProcThreadAttributeList(
            attribute_list,
            1,
            0,
            ctypes.byref(attribute_size),
        ):
            _raise_last_error("collector handle-list construction failed")
        if not _kernel32.UpdateProcThreadAttribute(
            attribute_list,
            0,
            _PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            ctypes.cast(handles, ctypes.c_void_p),
            ctypes.sizeof(handles),
            None,
            None,
        ):
            _raise_last_error("collector explicit handle-list failed")

        startup = _StartupInfoEx()
        startup.startup_info.cb = ctypes.sizeof(startup)
        startup.startup_info.flags = _STARTF_USESTDHANDLES
        startup.startup_info.stdin = stdin_read
        startup.startup_info.stdout = stdout_write
        startup.startup_info.stderr = stderr_write
        startup.attribute_list = attribute_list
        command_line = ctypes.create_unicode_buffer(_command_line(executable, argv))
        environment_block = _environment_block(environment)
        creation_flags = (
            _CREATE_SUSPENDED
            | _CREATE_UNICODE_ENVIRONMENT
            | _EXTENDED_STARTUPINFO_PRESENT
            | _CREATE_NO_WINDOW
        )
        if not _kernel32.CreateProcessW(
            executable,
            command_line,
            None,
            None,
            True,
            creation_flags,
            environment_block,
            working_directory,
            ctypes.byref(startup),
            ctypes.byref(process),
        ):
            _raise_last_error("collector process construction failed")
        if not _kernel32.AssignProcessToJobObject(job, process.process):
            _kernel32.TerminateProcess(process.process, _TERMINATED_EXIT_CODE)
            _raise_last_error("collector process containment failed")

        _close_handle(stdin_read)
        stdin_read = None
        _close_handle(stdout_write)
        stdout_write = None
        _close_handle(stderr_write)
        stderr_write = None
        stdout_capture = _PipeCapture(stdout_read, maximum_output_bytes)
        stderr_capture = _PipeCapture(stderr_read, maximum_output_bytes)
        stdout_read = stderr_read = None
        stdout_capture.start()
        stderr_capture.start()
        if _kernel32.ResumeThread(process.thread) == 0xFFFFFFFF:
            _kernel32.TerminateJobObject(job, _TERMINATED_EXIT_CODE)
            _raise_last_error("collector process resume failed")
        started = True

        deadline = time.monotonic() + timeout_seconds
        while True:
            if stdout_capture.overflowed.is_set() or stderr_capture.overflowed.is_set():
                output_exceeded = True
                _kernel32.TerminateJobObject(job, _TERMINATED_EXIT_CODE)
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                _kernel32.TerminateJobObject(job, _TERMINATED_EXIT_CODE)
                break
            wait = _kernel32.WaitForSingleObject(
                process.process,
                min(
                    _WAIT_SLICE_MILLISECONDS,
                    max(1, int(remaining * 1000)),
                ),
            )
            if wait == _WAIT_OBJECT_0:
                break
            if wait != _WAIT_TIMEOUT:
                _kernel32.TerminateJobObject(job, _TERMINATED_EXIT_CODE)
                _raise_last_error("collector process wait failed")

        _kernel32.TerminateJobObject(job, _TERMINATED_EXIT_CODE)
        wait = _kernel32.WaitForSingleObject(process.process, 5000)
        if wait != _WAIT_OBJECT_0:
            raise WindowsJobBoundaryError("collector process did not terminate")
        exit_code = wintypes.DWORD()
        if not _kernel32.GetExitCodeProcess(
            process.process,
            ctypes.byref(exit_code),
        ):
            _raise_last_error("collector exit status unavailable")
    except WindowsJobBoundaryError as exc:
        classified = _classify_boundary_failure(exc, started=started)
        if classified is exc:
            raise
        raise classified from exc
    finally:
        pending_exception = sys.exc_info()[0] is not None
        if attribute_list:
            _kernel32.DeleteProcThreadAttributeList(attribute_list)
        if process.thread:
            _close_handle(process.thread)
        if process.process:
            if not started:
                _kernel32.TerminateProcess(
                    process.process,
                    _TERMINATED_EXIT_CODE,
                )
            _close_handle(process.process)
        _close_handle(stdin_read)
        _close_handle(stdin_write)
        _close_handle(stdout_write)
        _close_handle(stderr_write)
        _close_handle(stdout_read)
        _close_handle(stderr_read)
        _close_handle(job)
        try:
            if stdout_capture is not None:
                stdout_payload = stdout_capture.join()
            if stderr_capture is not None:
                stderr_payload = stderr_capture.join()
        except WindowsJobBoundaryError as exc:
            if not pending_exception:
                classified = _classify_boundary_failure(exc, started=started)
                if classified is exc:
                    raise
                raise classified from exc

    if (
        output_exceeded
        or (
            stdout_capture is not None
            and stdout_capture.overflowed.is_set()
        )
        or (
            stderr_capture is not None
            and stderr_capture.overflowed.is_set()
        )
    ):
        raise WindowsJobOutputBoundError("collector output exceeded bound")
    if timed_out:
        raise WindowsJobTimeoutError("collector timeout")
    return exit_code.value, stdout_payload, stderr_payload
