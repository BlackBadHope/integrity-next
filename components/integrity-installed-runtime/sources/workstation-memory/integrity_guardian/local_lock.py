"""Small cross-platform advisory lock boundary for private local state."""

from __future__ import annotations

import os

try:
    import fcntl
except ImportError:  # pragma: no cover - exercised on Windows
    fcntl = None  # type: ignore[assignment]

try:
    import msvcrt
except ImportError:  # pragma: no cover - exercised on POSIX
    msvcrt = None  # type: ignore[assignment]


class LocalLockError(RuntimeError):
    """Raised when a local state lock cannot be acquired or released."""


def _prepare_windows_lock_byte(descriptor: int) -> None:
    details = os.fstat(descriptor)
    if details.st_size == 0:
        os.lseek(descriptor, 0, os.SEEK_SET)
        written = os.write(descriptor, b"\0")
        if written != 1:
            raise LocalLockError("local lock byte initialization failed")
        os.fsync(descriptor)
    os.lseek(descriptor, 0, os.SEEK_SET)


def lock_exclusive(descriptor: int, *, nonblocking: bool = False) -> None:
    """Acquire an exclusive process lock without changing file ownership."""

    if fcntl is not None:
        operation = fcntl.LOCK_EX
        if nonblocking:
            operation |= fcntl.LOCK_NB
        try:
            fcntl.flock(descriptor, operation)
        except (BlockingIOError, OSError) as exc:
            raise LocalLockError("local state lock is already held") from exc
        return
    if msvcrt is None:
        raise LocalLockError("no admitted local locking backend")
    _prepare_windows_lock_byte(descriptor)
    mode = msvcrt.LK_NBLCK if nonblocking else msvcrt.LK_LOCK
    try:
        msvcrt.locking(descriptor, mode, 1)
    except OSError as exc:
        raise LocalLockError("local state lock is already held") from exc


def lock_shared(descriptor: int) -> None:
    """Acquire a read lock; Windows intentionally serializes it exclusively."""

    if fcntl is not None:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_SH)
        except OSError as exc:
            raise LocalLockError("local state read lock failed") from exc
        return
    lock_exclusive(descriptor)


def unlock(descriptor: int) -> None:
    """Release a lock acquired through this module."""

    if fcntl is not None:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        except OSError as exc:
            raise LocalLockError("local state unlock failed") from exc
        return
    if msvcrt is None:
        raise LocalLockError("no admitted local locking backend")
    os.lseek(descriptor, 0, os.SEEK_SET)
    try:
        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
    except OSError as exc:
        raise LocalLockError("local state unlock failed") from exc


__all__ = [
    "LocalLockError",
    "lock_exclusive",
    "lock_shared",
    "unlock",
]
