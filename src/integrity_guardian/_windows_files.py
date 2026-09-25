"""Small Win32 file/DACL primitives shared by native Integrity backends."""

from __future__ import annotations

import ctypes
import hashlib
import os
import re
import stat
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from pathlib import Path

from ._windows_file_abi import (
    AccessAllowedAce as _AccessAllowedAce,
)
from ._windows_file_abi import (
    AclSizeInformation as _AclSizeInformation,
)
from ._windows_file_abi import (
    ByHandleFileInformation as _ByHandleFileInformation,
)
from ._windows_file_abi import SecurityAttributes as _SecurityAttributes
from ._windows_file_abi import TokenUser as _TokenUser
from ._windows_file_abi import advapi32 as _advapi32
from ._windows_file_abi import kernel32 as _kernel32
from ._windows_file_abi import wintypes

_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_FILE_READ_ATTRIBUTES = 0x00000080
_FILE_SHARE_READ = 0x00000001
_FILE_SHARE_WRITE = 0x00000002
_FILE_SHARE_DELETE = 0x00000004
_CREATE_NEW = 1
_OPEN_EXISTING = 3
_FILE_ATTRIBUTE_NORMAL = 0x00000080
_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000
_DRIVE_FIXED = 3
_TOKEN_QUERY = 0x0008
_TOKEN_USER = 1
_SDDL_REVISION_1 = 1
_OWNER_SECURITY_INFORMATION = 0x00000001
_DACL_SECURITY_INFORMATION = 0x00000004
_PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
_SE_DACL_PROTECTED = 0x1000
_ACL_SIZE_INFORMATION = 2
_ACCESS_ALLOWED_ACE_TYPE = 0
_OBJECT_INHERIT_ACE = 0x01
_CONTAINER_INHERIT_ACE = 0x02
_INHERITED_ACE = 0x10
_FILE_ALL_ACCESS = 0x001F01FF
_SYSTEM_SID = "S-1-5-18"
_ADMINISTRATORS_SID = "S-1-5-32-544"
_ERROR_FILE_EXISTS = 80
_ERROR_ALREADY_EXISTS = 183
_MAXIMUM_CLEANUP_ENTRIES = 4096
_MAXIMUM_CLEANUP_DEPTH = 32
_WINDOWS_SID = re.compile(r"^S-1-(?:\d+-){1,14}\d+$", re.IGNORECASE)


class WindowsFileBoundaryError(ValueError):
    """Raised when a Win32 path, identity or DACL boundary is ambiguous."""


def _require_windows() -> None:
    if os.name != "nt" or _kernel32 is None or _advapi32 is None:
        raise WindowsFileBoundaryError("Win32 file boundary requires Windows")


def _raise_last_error(message: str) -> None:
    code = ctypes.get_last_error()
    raise WindowsFileBoundaryError(f"{message} (winerror {code})")


def _anchored_fixed_path(path: Path) -> Path:
    _require_windows()
    value = Path(os.path.abspath(path))
    text = str(value)
    if text.startswith("\\\\") or not value.drive:
        raise WindowsFileBoundaryError("network or unanchored path rejected")
    root = f"{value.drive}\\"
    if _kernel32.GetDriveTypeW(root) != _DRIVE_FIXED:
        raise WindowsFileBoundaryError("non-fixed Windows volume rejected")
    return value


def _local_fixed_path(path: Path) -> Path:
    value = _anchored_fixed_path(path)
    current = value
    lineage: list[Path] = []
    while True:
        lineage.append(current)
        parent = current.parent
        if parent == current:
            break
        current = parent
    for item in reversed(lineage):
        attributes = _kernel32.GetFileAttributesW(str(item))
        if attributes == 0xFFFFFFFF:
            _raise_last_error("Windows path ancestry is absent")
        if attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
            raise WindowsFileBoundaryError("Windows reparse ancestry rejected")
    return value


class _HeldDirectoryLineage(
    AbstractContextManager["_HeldDirectoryLineage"]
):
    """Hold every real ancestor without delete sharing until use completes."""

    def __init__(self, path: Path) -> None:
        _require_windows()
        self.path = _anchored_fixed_path(path)
        self.handles: list[object] = []
        current = self.path
        lineage: list[Path] = []
        while True:
            lineage.append(current)
            parent = current.parent
            if parent == current:
                break
            current = parent
        try:
            for item in reversed(lineage):
                if item.parent == item:
                    continue
                handle = _kernel32.CreateFileW(
                    str(item),
                    _FILE_READ_ATTRIBUTES,
                    _FILE_SHARE_READ | _FILE_SHARE_WRITE,
                    None,
                    _OPEN_EXISTING,
                    _FILE_FLAG_OPEN_REPARSE_POINT
                    | _FILE_FLAG_BACKUP_SEMANTICS,
                    None,
                )
                if handle == _INVALID_HANDLE_VALUE:
                    _raise_last_error("Windows directory lineage open rejected")
                information = _ByHandleFileInformation()
                if not _kernel32.GetFileInformationByHandle(
                    handle,
                    ctypes.byref(information),
                ):
                    _kernel32.CloseHandle(handle)
                    _raise_last_error(
                        "Windows directory lineage identity unavailable"
                    )
                if (
                    not information.file_attributes & _FILE_ATTRIBUTE_DIRECTORY
                    or information.file_attributes
                    & _FILE_ATTRIBUTE_REPARSE_POINT
                ):
                    _kernel32.CloseHandle(handle)
                    raise WindowsFileBoundaryError(
                        "Windows directory lineage type rejected"
                    )
                self.handles.append(handle)
        except Exception:
            self.close()
            raise

    def close(self) -> None:
        while self.handles:
            _kernel32.CloseHandle(self.handles.pop())

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()


class HeldWindowsDirectory(AbstractContextManager["HeldWindowsDirectory"]):
    """Hold one real directory and all ancestors without delete sharing."""

    def __init__(self, path: Path) -> None:
        self.path = _anchored_fixed_path(path)
        self._lineage = _HeldDirectoryLineage(self.path)

    def close(self) -> None:
        self._lineage.close()

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()


def create_held_windows_file_descriptor(path: Path) -> int:
    """Create one mutable file while preventing its file ID from being reused."""

    _require_windows()
    import msvcrt

    target = _anchored_fixed_path(path)
    handle = _kernel32.CreateFileW(
        str(target),
        _GENERIC_READ | _GENERIC_WRITE,
        _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE,
        None,
        _CREATE_NEW,
        _FILE_ATTRIBUTE_NORMAL | _FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    if handle == _INVALID_HANDLE_VALUE:
        _raise_last_error("Windows held mutable file creation rejected")
    try:
        information = _ByHandleFileInformation()
        if not _kernel32.GetFileInformationByHandle(
            handle,
            ctypes.byref(information),
        ):
            _raise_last_error("Windows held mutable file identity unavailable")
        if information.file_attributes & (
            _FILE_ATTRIBUTE_DIRECTORY | _FILE_ATTRIBUTE_REPARSE_POINT
        ):
            raise WindowsFileBoundaryError(
                "Windows held mutable file type rejected"
            )
        descriptor = msvcrt.open_osfhandle(int(handle), os.O_RDWR)
    except Exception:
        _kernel32.CloseHandle(handle)
        raise
    return descriptor


class HeldWindowsFile(AbstractContextManager["HeldWindowsFile"]):
    """Hold a no-write/no-delete Win32 handle across digest and use."""

    def __init__(self, path: Path, *, maximum_bytes: int) -> None:
        _require_windows()
        self.path = _anchored_fixed_path(path)
        self.handle = None
        self._lineage = _HeldDirectoryLineage(self.path.parent)
        try:
            handle = _kernel32.CreateFileW(
                str(self.path),
                _GENERIC_READ,
                _FILE_SHARE_READ,
                None,
                _OPEN_EXISTING,
                _FILE_FLAG_OPEN_REPARSE_POINT | _FILE_FLAG_SEQUENTIAL_SCAN,
                None,
            )
            if handle == _INVALID_HANDLE_VALUE:
                _raise_last_error("Windows file open rejected")
            self.handle = handle
            information = _ByHandleFileInformation()
            if not _kernel32.GetFileInformationByHandle(
                handle,
                ctypes.byref(information),
            ):
                _raise_last_error("Windows file identity unavailable")
            if information.file_attributes & (
                _FILE_ATTRIBUTE_DIRECTORY | _FILE_ATTRIBUTE_REPARSE_POINT
            ):
                raise WindowsFileBoundaryError("Windows file type rejected")
            self.size = (
                information.file_size_high << 32
            ) | information.file_size_low
            self.identity = (
                information.volume_serial_number,
                (
                    information.file_index_high << 32
                ) | information.file_index_low,
            )
            if self.size > maximum_bytes:
                raise WindowsFileBoundaryError("Windows file size rejected")
        except Exception:
            self.close()
            raise

    def read_bytes(self) -> bytes:
        _require_windows()
        moved = ctypes.c_longlong()
        if not _kernel32.SetFilePointerEx(
            self.handle,
            ctypes.c_longlong(0),
            ctypes.byref(moved),
            0,
        ):
            _raise_last_error("Windows file seek rejected")
        chunks: list[bytes] = []
        remaining = self.size
        while remaining:
            amount = min(1024 * 1024, remaining)
            buffer = ctypes.create_string_buffer(amount)
            received = wintypes.DWORD()
            if not _kernel32.ReadFile(
                self.handle,
                buffer,
                amount,
                ctypes.byref(received),
                None,
            ):
                _raise_last_error("Windows file read rejected")
            if received.value == 0:
                raise WindowsFileBoundaryError("Windows file read made no progress")
            chunks.append(buffer.raw[: received.value])
            remaining -= received.value
        payload = b"".join(chunks)
        if len(payload) != self.size:
            raise WindowsFileBoundaryError("Windows file size changed during read")
        return payload

    def sha256(self) -> str:
        _require_windows()
        moved = ctypes.c_longlong()
        if not _kernel32.SetFilePointerEx(
            self.handle,
            ctypes.c_longlong(0),
            ctypes.byref(moved),
            0,
        ):
            _raise_last_error("Windows file seek rejected")
        hasher = hashlib.sha256()
        remaining = self.size
        while remaining:
            amount = min(1024 * 1024, remaining)
            buffer = ctypes.create_string_buffer(amount)
            received = wintypes.DWORD()
            if not _kernel32.ReadFile(
                self.handle,
                buffer,
                amount,
                ctypes.byref(received),
                None,
            ):
                _raise_last_error("Windows file read rejected")
            if received.value == 0:
                raise WindowsFileBoundaryError(
                    "Windows file digest made no progress"
                )
            hasher.update(buffer.raw[: received.value])
            remaining -= received.value
        return hasher.hexdigest()

    def close(self) -> None:
        handle = getattr(self, "handle", None)
        if handle not in {None, _INVALID_HANDLE_VALUE}:
            _kernel32.CloseHandle(handle)
            self.handle = None
        lineage = getattr(self, "_lineage", None)
        if lineage is not None:
            lineage.close()

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()


def _sid_string(sid_pointer: int) -> str:
    _require_windows()
    output = wintypes.LPWSTR()
    if not _advapi32.ConvertSidToStringSidW(sid_pointer, ctypes.byref(output)):
        _raise_last_error("Windows SID conversion rejected")
    try:
        return output.value
    finally:
        _kernel32.LocalFree(ctypes.cast(output, ctypes.c_void_p))


def current_user_sid() -> str:
    _require_windows()
    token = wintypes.HANDLE()
    if not _advapi32.OpenProcessToken(
        _kernel32.GetCurrentProcess(),
        _TOKEN_QUERY,
        ctypes.byref(token),
    ):
        _raise_last_error("current Windows token unavailable")
    try:
        required = wintypes.DWORD()
        _advapi32.GetTokenInformation(
            token,
            _TOKEN_USER,
            None,
            0,
            ctypes.byref(required),
        )
        if required.value == 0:
            _raise_last_error("current Windows SID size unavailable")
        buffer = ctypes.create_string_buffer(required.value)
        if not _advapi32.GetTokenInformation(
            token,
            _TOKEN_USER,
            buffer,
            required.value,
            ctypes.byref(required),
        ):
            _raise_last_error("current Windows SID unavailable")
        user = ctypes.cast(buffer, ctypes.POINTER(_TokenUser)).contents
        return _sid_string(user.user.sid)
    finally:
        _kernel32.CloseHandle(token)


@contextmanager
def _private_security_descriptor() -> Iterator[ctypes.c_void_p]:
    _require_windows()
    current = current_user_sid()
    sddl = (
        f"O:{current}D:P"
        f"(A;OICI;FA;;;{current})"
        "(A;OICI;FA;;;SY)"
        "(A;OICI;FA;;;BA)"
    )
    descriptor = ctypes.c_void_p()
    descriptor_size = wintypes.DWORD()
    if not _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl,
        _SDDL_REVISION_1,
        ctypes.byref(descriptor),
        ctypes.byref(descriptor_size),
    ):
        _raise_last_error("private Windows DACL construction failed")
    try:
        yield descriptor
    finally:
        _kernel32.LocalFree(descriptor.value)


def set_private_directory_acl(path: Path) -> None:
    with _private_security_descriptor() as descriptor:
        information = (
            _OWNER_SECURITY_INFORMATION
            | _DACL_SECURITY_INFORMATION
            | _PROTECTED_DACL_SECURITY_INFORMATION
        )
        if not _advapi32.SetFileSecurityW(str(path), information, descriptor):
            _raise_last_error("private Windows DACL application failed")


def _create_private_directory_atomic(path: Path) -> bool:
    with _private_security_descriptor() as descriptor:
        attributes = _SecurityAttributes()
        attributes.length = ctypes.sizeof(attributes)
        attributes.security_descriptor = descriptor.value
        attributes.inherit_handle = False
        if _kernel32.CreateDirectoryW(str(path), ctypes.byref(attributes)):
            return True
        code = ctypes.get_last_error()
        if code in {_ERROR_FILE_EXISTS, _ERROR_ALREADY_EXISTS}:
            return False
        raise WindowsFileBoundaryError(
            f"private Windows directory creation failed (winerror {code})"
        )


def inspect_private_directory_acl(
    path: Path,
    *,
    expected_owner_sid: str | None = None,
) -> dict[str, object]:
    """Return an exact-DACL receipt for one path.

    When ``expected_owner_sid`` is omitted the caller remains owner-bound to
    the current process, preserving the mutation boundary.  An explicit SID
    enables read-only cross-principal audit without making the auditor an
    accepted owner.
    """

    _require_windows()
    if expected_owner_sid is not None and _WINDOWS_SID.fullmatch(
        expected_owner_sid
    ) is None:
        raise WindowsFileBoundaryError("expected Windows owner SID rejected")
    required = wintypes.DWORD()
    information = _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION
    _advapi32.GetFileSecurityW(str(path), information, None, 0, ctypes.byref(required))
    if required.value == 0:
        _raise_last_error("private Windows security descriptor size unavailable")
    descriptor = ctypes.create_string_buffer(required.value)
    if not _advapi32.GetFileSecurityW(
        str(path),
        information,
        descriptor,
        required.value,
        ctypes.byref(required),
    ):
        _raise_last_error("private Windows security descriptor unavailable")

    control = wintypes.WORD()
    revision = wintypes.DWORD()
    if not _advapi32.GetSecurityDescriptorControl(
        descriptor,
        ctypes.byref(control),
        ctypes.byref(revision),
    ):
        _raise_last_error("private Windows DACL control unavailable")
    if not control.value & _SE_DACL_PROTECTED:
        raise WindowsFileBoundaryError("private Windows DACL inheritance is enabled")

    owner = ctypes.c_void_p()
    owner_defaulted = wintypes.BOOL()
    if not _advapi32.GetSecurityDescriptorOwner(
        descriptor,
        ctypes.byref(owner),
        ctypes.byref(owner_defaulted),
    ):
        _raise_last_error("private Windows DACL owner unavailable")
    current = current_user_sid()
    expected_owner = expected_owner_sid or current
    actual_owner = _sid_string(owner.value)
    if actual_owner.casefold() != expected_owner.casefold():
        raise WindowsFileBoundaryError("private Windows DACL owner mismatch")

    acl = ctypes.c_void_p()
    dacl_present = wintypes.BOOL()
    dacl_defaulted = wintypes.BOOL()
    if not _advapi32.GetSecurityDescriptorDacl(
        descriptor,
        ctypes.byref(dacl_present),
        ctypes.byref(acl),
        ctypes.byref(dacl_defaulted),
    ):
        _raise_last_error("private Windows DACL unavailable")
    if not dacl_present.value or not acl.value:
        raise WindowsFileBoundaryError("private Windows DACL is absent")

    size = _AclSizeInformation()
    if not _advapi32.GetAclInformation(
        acl,
        ctypes.byref(size),
        ctypes.sizeof(size),
        _ACL_SIZE_INFORMATION,
    ):
        _raise_last_error("private Windows DACL size unavailable")
    if size.ace_count != 3:
        raise WindowsFileBoundaryError("private Windows DACL rule count mismatch")

    expected = {expected_owner, _SYSTEM_SID, _ADMINISTRATORS_SID}
    actual: set[str] = set()
    for index in range(size.ace_count):
        ace_pointer = ctypes.c_void_p()
        if not _advapi32.GetAce(acl, index, ctypes.byref(ace_pointer)):
            _raise_last_error("private Windows DACL rule unavailable")
        ace = ctypes.cast(
            ace_pointer,
            ctypes.POINTER(_AccessAllowedAce),
        ).contents
        if (
            ace.header.ace_type != _ACCESS_ALLOWED_ACE_TYPE
            or (ace.header.ace_flags & _INHERITED_ACE)
            or (
                ace.header.ace_flags
                & (_OBJECT_INHERIT_ACE | _CONTAINER_INHERIT_ACE)
            )
            != (_OBJECT_INHERIT_ACE | _CONTAINER_INHERIT_ACE)
            or ace.mask != _FILE_ALL_ACCESS
        ):
            raise WindowsFileBoundaryError("private Windows DACL rule rejected")
        sid_pointer = ace_pointer.value + _AccessAllowedAce.sid_start.offset
        actual.add(_sid_string(sid_pointer))
    if {value.casefold() for value in actual} != {
        value.casefold() for value in expected
    }:
        raise WindowsFileBoundaryError("private Windows DACL principal set mismatch")
    return {
        "owner_sid": actual_owner,
        "current_principal_is_owner": actual_owner.casefold() == current.casefold(),
        "dacl_protected": True,
        "principal_sids": sorted(actual, key=str.casefold),
        "rule_count": size.ace_count,
    }


def assert_private_directory_acl(
    path: Path,
    *,
    expected_owner_sid: str | None = None,
) -> None:
    inspect_private_directory_acl(
        path,
        expected_owner_sid=expected_owner_sid,
    )


def create_private_directory(path: Path) -> Path:
    _require_windows()
    target = _anchored_fixed_path(path)
    created = False
    try:
        with _HeldDirectoryLineage(target.parent):
            created = _create_private_directory_atomic(target)
            with HeldWindowsDirectory(target):
                assert_private_directory_acl(target)
    except Exception:
        if created:
            try:
                os.rmdir(target)
            except OSError:
                pass
        raise
    return target


def create_private_directory_tree(path: Path) -> Path:
    """Create missing local-fixed ancestors with a protected exact DACL."""

    _require_windows()
    target = Path(os.path.abspath(path))
    missing: list[Path] = []
    current = target
    while not current.exists():
        missing.append(current)
        parent = current.parent
        if parent == current:
            raise WindowsFileBoundaryError(
                "private Windows directory has no existing anchor"
            )
        current = parent
    _local_fixed_path(current)
    for item in reversed(missing):
        create_private_directory(item)
    return create_private_directory(target)


def _remove_private_contents(
    path: Path,
    *,
    depth: int,
    counter: list[int],
) -> None:
    if depth > _MAXIMUM_CLEANUP_DEPTH:
        raise WindowsFileBoundaryError(
            "private Windows cleanup depth exceeded"
        )
    with os.scandir(path) as entries:
        for entry in entries:
            counter[0] += 1
            if counter[0] > _MAXIMUM_CLEANUP_ENTRIES:
                raise WindowsFileBoundaryError(
                    "private Windows cleanup entry bound exceeded"
                )
            child = Path(entry.path)
            attributes = _kernel32.GetFileAttributesW(str(child))
            if attributes == 0xFFFFFFFF:
                _raise_last_error("private Windows cleanup entry unavailable")
            if attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
                if attributes & _FILE_ATTRIBUTE_DIRECTORY:
                    os.rmdir(child)
                else:
                    os.unlink(child)
                continue
            if attributes & _FILE_ATTRIBUTE_DIRECTORY:
                with HeldWindowsDirectory(child):
                    _remove_private_contents(
                        child,
                        depth=depth + 1,
                        counter=counter,
                    )
                os.rmdir(child)
                continue
            try:
                os.unlink(child)
            except PermissionError:
                os.chmod(child, stat.S_IWRITE)
                os.unlink(child)


def remove_private_directory_tree(path: Path) -> None:
    """Delete one bounded private tree without traversing reparse points."""

    target = _anchored_fixed_path(path)
    with HeldWindowsDirectory(target):
        assert_private_directory_acl(target)
        _remove_private_contents(target, depth=0, counter=[0])
    os.rmdir(target)
