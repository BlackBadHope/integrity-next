"""Win32 fixed-volume, exact-DACL custody for local Integrity state."""

from __future__ import annotations

import ctypes
import os
from contextlib import AbstractContextManager
from pathlib import Path

from ._windows_file_abi import (
    ByHandleFileInformation as _ByHandleFileInformation,
)
from ._windows_file_abi import kernel32 as _kernel32
from ._windows_files import (
    HeldWindowsDirectory,
    HeldWindowsFile,
    WindowsFileBoundaryError,
    _anchored_fixed_path,
    assert_private_directory_acl,
    create_private_directory_tree,
    set_private_directory_acl,
)

try:
    import msvcrt
except ImportError:  # pragma: no cover - module remains importable on POSIX
    msvcrt = None  # type: ignore[assignment]

_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_FILE_SHARE_READ = 0x00000001
_FILE_SHARE_WRITE = 0x00000002
_CREATE_NEW = 1
_OPEN_EXISTING = 3
_OPEN_ALWAYS = 4
_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_MOVEFILE_REPLACE_EXISTING = 0x00000001
_MOVEFILE_WRITE_THROUGH = 0x00000008
_ERROR_ALREADY_EXISTS = 183


class WindowsPrivateStateError(RuntimeError):
    """Raised before ambiguous Windows private state is read or changed."""


def _require_windows() -> None:
    if os.name != "nt" or _kernel32 is None or msvcrt is None:
        raise WindowsPrivateStateError("Windows private-state backend unavailable")


def _translate(exc: Exception) -> WindowsPrivateStateError:
    return WindowsPrivateStateError(str(exc))


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise WindowsPrivateStateError("Windows private-state write made no progress")
        view = view[written:]


def open_private_file_descriptor(
    path: Path,
    *,
    flags: int,
    maximum_bytes: int | None = None,
    share_write: bool = True,
) -> int:
    """Open one regular non-reparse file and return an owning Python fd."""

    _require_windows()
    target = _anchored_fixed_path(path)
    access_mode = flags & (os.O_RDONLY | os.O_WRONLY | os.O_RDWR)
    if access_mode == os.O_WRONLY:
        desired_access = _GENERIC_WRITE
    elif access_mode == os.O_RDWR:
        desired_access = _GENERIC_READ | _GENERIC_WRITE
    else:
        desired_access = _GENERIC_READ
    if flags & os.O_TRUNC:
        raise WindowsPrivateStateError(
            "Windows private-state truncation requires atomic replacement"
        )
    if flags & os.O_EXCL and not flags & os.O_CREAT:
        raise WindowsPrivateStateError("exclusive Windows open requires create")
    if flags & os.O_CREAT and flags & os.O_EXCL:
        disposition = _CREATE_NEW
    elif flags & os.O_CREAT:
        disposition = _OPEN_ALWAYS
    else:
        disposition = _OPEN_EXISTING

    lineage = HeldWindowsDirectory(target.parent)
    ctypes.set_last_error(0)
    share_mode = _FILE_SHARE_READ | _FILE_SHARE_WRITE
    if not share_write:
        share_mode = _FILE_SHARE_READ
    handle = _kernel32.CreateFileW(
        str(target),
        desired_access,
        share_mode,
        None,
        disposition,
        _FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    invalid = ctypes.c_void_p(-1).value
    if handle == invalid:
        code = ctypes.get_last_error()
        lineage.close()
        raise WindowsPrivateStateError(
            f"Windows private-state file open rejected (winerror {code})"
        )
    created = disposition == _CREATE_NEW or (
        disposition == _OPEN_ALWAYS
        and ctypes.get_last_error() != _ERROR_ALREADY_EXISTS
    )
    descriptor: int | None = None
    succeeded = False
    try:
        information = _ByHandleFileInformation()
        if not _kernel32.GetFileInformationByHandle(
            handle,
            ctypes.byref(information),
        ):
            code = ctypes.get_last_error()
            raise WindowsPrivateStateError(
                f"Windows private-state identity unavailable (winerror {code})"
            )
        if information.file_attributes & (
            _FILE_ATTRIBUTE_DIRECTORY | _FILE_ATTRIBUTE_REPARSE_POINT
        ):
            raise WindowsPrivateStateError(
                "Windows private-state file type rejected"
            )
        size = (information.file_size_high << 32) | information.file_size_low
        if maximum_bytes is not None and size > maximum_bytes:
            raise WindowsPrivateStateError(
                "Windows private-state file size rejected"
            )
        if created:
            set_private_directory_acl(target)
        assert_private_directory_acl(target)
        fd_flags = access_mode
        if hasattr(os, "O_BINARY"):
            fd_flags |= os.O_BINARY
        if hasattr(os, "O_NOINHERIT"):
            fd_flags |= os.O_NOINHERIT
        descriptor = msvcrt.open_osfhandle(handle, fd_flags)
        handle = None
        if flags & os.O_APPEND:
            os.lseek(descriptor, 0, os.SEEK_END)
        succeeded = True
        return descriptor
    except WindowsFileBoundaryError as exc:
        raise _translate(exc) from exc
    finally:
        if handle not in {None, invalid}:
            _kernel32.CloseHandle(handle)
        if not succeeded and descriptor is not None:
            os.close(descriptor)
        if not succeeded and created:
            try:
                target.unlink()
            except FileNotFoundError:
                pass
        lineage.close()


def read_private_bytes(
    path: Path,
    *,
    maximum_bytes: int,
    expected_owner_sid: str | None = None,
) -> bytes:
    """Read one exact-DACL regular file through a held Win32 identity."""

    try:
        assert_private_directory_acl(
            path,
            expected_owner_sid=expected_owner_sid,
        )
        with HeldWindowsFile(path, maximum_bytes=maximum_bytes) as held:
            return held.read_bytes()
    except WindowsFileBoundaryError as exc:
        raise _translate(exc) from exc


def write_private_once(path: Path, payload: bytes) -> None:
    """Create one private file; an existing file is never rewritten."""

    descriptor: int | None = None
    created = False
    try:
        with HeldWindowsDirectory(path.parent):
            descriptor = open_private_file_descriptor(
                path,
                flags=os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            )
            created = True
            _write_all(descriptor, payload)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            if read_private_bytes(path, maximum_bytes=len(payload)) != payload:
                raise WindowsPrivateStateError(
                    "Windows private-state write verification failed"
                )
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
        if created:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        raise


def replace_private_bytes(path: Path, payload: bytes) -> None:
    """Atomically replace one private file and request write-through metadata."""

    _require_windows()
    temporary = path.with_name(
        f".{path.name}.{os.getpid()}.{os.urandom(8).hex()}.tmp"
    )
    try:
        with HeldWindowsDirectory(path.parent):
            if path.exists():
                read_private_bytes(path, maximum_bytes=16 * 1024 * 1024)
            write_private_once(temporary, payload)
            if not _kernel32.MoveFileExW(
                str(temporary),
                str(path),
                _MOVEFILE_REPLACE_EXISTING | _MOVEFILE_WRITE_THROUGH,
            ):
                code = ctypes.get_last_error()
                raise WindowsPrivateStateError(
                    f"Windows private-state replace rejected (winerror {code})"
                )
            if read_private_bytes(path, maximum_bytes=len(payload)) != payload:
                raise WindowsPrivateStateError(
                    "Windows private-state replace verification failed"
                )
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


class WindowsPrivateRoot(AbstractContextManager["WindowsPrivateRoot"]):
    """Hold one private root lineage and its dedicated advisory lock file."""

    def __init__(self, path: Path, *, create: bool) -> None:
        _require_windows()
        self.path = _anchored_fixed_path(path)
        if create and self.path.exists():
            raise WindowsPrivateStateError("Windows private root already exists")
        self._held = None
        self.lock_descriptor = None
        try:
            if create:
                create_private_directory_tree(self.path)
            assert_private_directory_acl(self.path)
            self._held = HeldWindowsDirectory(self.path)
            self.lock_path = self.path / ".integrity-state.lock"
            self.lock_descriptor = open_private_file_descriptor(
                self.lock_path,
                flags=os.O_RDWR | os.O_CREAT,
                maximum_bytes=1,
            )
        except WindowsFileBoundaryError as exc:
            self.close()
            raise _translate(exc) from exc
        except Exception:
            self.close()
            raise

    def close(self) -> None:
        descriptor = getattr(self, "lock_descriptor", None)
        if descriptor is not None:
            os.close(descriptor)
            self.lock_descriptor = None
        held = getattr(self, "_held", None)
        if held is not None:
            held.close()
            self._held = None

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()


__all__ = [
    "WindowsPrivateRoot",
    "WindowsPrivateStateError",
    "open_private_file_descriptor",
    "read_private_bytes",
    "replace_private_bytes",
    "write_private_once",
]
