"""Per-run named pipe server between the host coordinator and the in-Job MCP relay.

User-only DACL, FILE_FLAG_FIRST_PIPE_INSTANCE (no squatting on the name), remote
clients rejected, one instance, length-prefixed bounded frames, blocking I/O that the
owner can cancel (CancelSynchronousIo). Authentication of the peer (Job membership,
image path, nonce) is done by the coordinator. Same-account processes can still open
the pipe; they are rejected by those checks, never by the ACL alone.
"""
from __future__ import annotations

import ctypes
import secrets
import struct
import threading
from ctypes import wintypes

from . import _winabi as abi
from .canonical import Rejected, canonical_bytes, need, strict_loads

MAX_FRAME = 8 * 1024 * 1024


def _user_sddl() -> str:
    k, a = abi.load(), abi.advapi()
    token = wintypes.HANDLE()
    need(k.OpenProcessToken(k.GetCurrentProcess(), abi.TOKEN_QUERY, ctypes.byref(token)), "pipe_token")
    try:
        size = wintypes.DWORD()
        a.GetTokenInformation(token, abi.TOKEN_USER_CLASS, None, 0, ctypes.byref(size))
        buffer = ctypes.create_string_buffer(size.value)
        need(a.GetTokenInformation(token, abi.TOKEN_USER_CLASS, buffer, size, ctypes.byref(size)),
             "pipe_token_user")
        sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
        text = wintypes.LPWSTR()
        need(a.ConvertSidToStringSidW(sid, ctypes.byref(text)), "pipe_sid")
        try:
            value = text.value
        finally:
            k.LocalFree(text)
    finally:
        k.CloseHandle(token)
    return f"D:P(A;;GA;;;{value})"  # protected DACL: only the current user, no inheritance


class PipeServer:
    def __init__(self):
        self.k = abi.load()
        self.name = r"\\.\pipe\integrity-claude-" + secrets.token_hex(16)
        descriptor = ctypes.c_void_p()
        need(abi.advapi().ConvertStringSecurityDescriptorToSecurityDescriptorW(
            _user_sddl(), 1, ctypes.byref(descriptor), None), "pipe_sddl")
        try:
            attributes = abi.SecurityAttributes(ctypes.sizeof(abi.SecurityAttributes),
                                                descriptor, False)
            handle = self.k.CreateNamedPipeW(
                self.name, abi.PIPE_ACCESS_DUPLEX | abi.FILE_FLAG_FIRST_PIPE_INSTANCE,
                abi.PIPE_REJECT_REMOTE_CLIENTS, 1, 65536, 65536, 0, ctypes.byref(attributes))
        finally:
            self.k.LocalFree(descriptor)
        need(handle not in (None, abi.INVALID_HANDLE_VALUE), "pipe_create")
        self.handle = handle
        self._thread_handle = None
        self._lock = threading.Lock()

    def bind_current_thread(self) -> None:
        """Allow cancel() to abort this thread's blocking pipe I/O."""
        thread = self.k.OpenThread(abi.THREAD_TERMINATE, False, threading.get_native_id())
        need(thread, "pipe_thread")
        with self._lock:
            self._thread_handle = thread

    def accept(self) -> int:
        """Block until a client connects; return its process id."""
        if not self.k.ConnectNamedPipe(self.handle, None):
            need(ctypes.get_last_error() == abi.ERROR_PIPE_CONNECTED, "pipe_connect")
        pid = wintypes.ULONG()
        need(self.k.GetNamedPipeClientProcessId(self.handle, ctypes.byref(pid)), "pipe_client_pid")
        return int(pid.value)

    def drop_client(self) -> None:
        self.k.DisconnectNamedPipe(self.handle)

    def _read_exact(self, size: int) -> bytes:
        buffer, read, data = ctypes.create_string_buffer(min(size, 65536) or 1), wintypes.DWORD(), bytearray()
        while len(data) < size:
            want = min(size - len(data), 65536)
            if not self.k.ReadFile(self.handle, buffer, want, ctypes.byref(read), None) or not read.value:
                raise Rejected("pipe_closed")
            data.extend(buffer.raw[: read.value])
        return bytes(data)

    def read_frame(self) -> dict:
        (size,) = struct.unpack(">I", self._read_exact(4))
        need(0 < size <= MAX_FRAME, "pipe_frame_size")
        frame = strict_loads(self._read_exact(size), MAX_FRAME)
        need(type(frame) is dict, "pipe_frame_shape")
        return frame

    def write_frame(self, frame: dict) -> None:
        payload = canonical_bytes(frame, MAX_FRAME)
        data = struct.pack(">I", len(payload)) + payload
        written, offset = wintypes.DWORD(), 0
        while offset < len(data):
            piece = data[offset:offset + 65536]
            need(self.k.WriteFile(self.handle, piece, len(piece), ctypes.byref(written), None)
                 and written.value, "pipe_write")
            offset += written.value

    def cancel(self) -> None:
        with self._lock:
            if self._thread_handle:
                self.k.CancelSynchronousIo(self._thread_handle)

    def close(self) -> None:
        with self._lock:
            if self._thread_handle:
                self.k.CloseHandle(self._thread_handle)
                self._thread_handle = None
            if self.handle:
                self.k.CloseHandle(self.handle)
                self.handle = None
