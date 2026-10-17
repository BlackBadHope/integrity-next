# SPDX-License-Identifier: Apache-2.0
"""Restrict the dedicated bus state directory using Windows built-in APIs."""

from __future__ import annotations

from integrity_llm_bus.configuration import value as _integrity_value, require_config as _integrity_require_config

import ctypes
from ctypes import wintypes
from pathlib import Path


TOKEN_QUERY = 0x0008
TOKEN_USER = 1
DACL_SECURITY_INFORMATION = 0x00000004
ERROR_ALREADY_EXISTS = 183


class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("nLength", wintypes.DWORD),
        ("lpSecurityDescriptor", ctypes.c_void_p),
        ("bInheritHandle", wintypes.BOOL),
    ]


def _check(ok: object, operation: str) -> None:
    if not ok:
        raise OSError(f"{operation} failed (Win32 {ctypes.get_last_error()})")


def _current_user_sid() -> str:
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]

    token = wintypes.HANDLE()
    _check(advapi.OpenProcessToken(kernel.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(token)), "OpenProcessToken")
    try:
        size = wintypes.DWORD()
        advapi.GetTokenInformation(token, TOKEN_USER, None, 0, ctypes.byref(size))
        if size.value == 0:
            raise OSError("GetTokenInformation returned no token user")
        buffer = ctypes.create_string_buffer(size.value)
        _check(advapi.GetTokenInformation(token, TOKEN_USER, buffer, size, ctypes.byref(size)), "GetTokenInformation")
        sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p)).contents.value
        sid_text = wintypes.LPWSTR()
        _check(advapi.ConvertSidToStringSidW(sid, ctypes.byref(sid_text)), "ConvertSidToStringSidW")
        try:
            return sid_text.value
        finally:
            kernel.LocalFree(ctypes.cast(sid_text, ctypes.c_void_p))
    finally:
        kernel.CloseHandle(token)


def secure_state_directory(path: Path) -> None:
    """Create/restrict state and existing SQLite files to owner and SYSTEM.

    The directory DACL is protected from inherited project permissions. SQLite
    sidecar files created later inherit this DACL. Startup fails closed if the
    ACL cannot be applied.
    """
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p
    ]
    advapi.SetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
    kernel.CreateDirectoryW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(SECURITY_ATTRIBUTES)]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]

    sid = _current_user_sid()
    sddl = f"D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)"
    descriptor = ctypes.c_void_p()
    _check(
        advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), None),
        "ConvertStringSecurityDescriptorToSecurityDescriptorW",
    )
    try:
        attributes = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), descriptor, False)
        if not kernel.CreateDirectoryW(str(path), ctypes.byref(attributes)):
            error = ctypes.get_last_error()
            if error != ERROR_ALREADY_EXISTS:
                raise OSError(f"CreateDirectoryW failed (Win32 {error})")
        if not path.is_dir() or path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
            raise OSError("Bus state path must be a real directory")
        _check(advapi.SetFileSecurityW(str(path), DACL_SECURITY_INFORMATION, descriptor), "SetFileSecurityW(directory)")
        for name in ("bus.sqlite3", "bus.sqlite3-wal", "bus.sqlite3-shm"):
            child = path / name
            if child.exists():
                if child.is_symlink() or (hasattr(child, "is_junction") and child.is_junction()):
                    raise OSError("SQLite state path must not be a link")
                _check(advapi.SetFileSecurityW(str(child), DACL_SECURITY_INFORMATION, descriptor), "SetFileSecurityW(SQLite)")
    finally:
        kernel.LocalFree(descriptor)
