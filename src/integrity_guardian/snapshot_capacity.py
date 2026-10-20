"""Cross-process admission for private, immutable per-session catalog copies.

The lock covers inventory and allocation. Existing session owner locks remain
the sole authority for orphan cleanup; capacity admission never deletes data.
"""
from __future__ import annotations

import os
import stat
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

try:
    import fcntl
except ImportError:
    fcntl = None

MAXIMUM_SNAPSHOT_BYTES = 4 * 1024**3
FREE_SPACE_FLOOR_BYTES = 1024**3
LOCK_NAME = ".snapshot-capacity.lock"
MAXIMUM_INVENTORY_ENTRIES = 20_000


class SnapshotCapacityError(ValueError):
    """Allocation was denied before creating a session copy."""


def _private_root(root: Path) -> os.stat_result:
    if not root.is_absolute() or root.resolve(strict=True) != root:
        raise SnapshotCapacityError("Seed snapshot capacity root path is unsafe")
    value = root.lstat()
    if (not stat.S_ISDIR(value.st_mode) or value.st_uid != os.geteuid()
            or stat.S_IMODE(value.st_mode) & 0o077):
        raise SnapshotCapacityError("Seed snapshot capacity root custody is unsafe")
    return value


def _inventory(root: Path) -> int:
    total = 0
    count = 0
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            entries = list(os.scandir(directory))
        except FileNotFoundError:
            # An owning session may close while inventory is in progress.
            continue
        for entry in entries:
            count += 1
            if count > MAXIMUM_INVENTORY_ENTRIES:
                raise SnapshotCapacityError("Seed snapshot capacity inventory is too large")
            try:
                value = entry.stat(follow_symlinks=False)
            except FileNotFoundError:
                continue
            if (value.st_uid != os.geteuid() or stat.S_IMODE(value.st_mode) & 0o077
                    or stat.S_ISLNK(value.st_mode)):
                raise SnapshotCapacityError("Seed snapshot capacity entry custody is unsafe")
            if stat.S_ISDIR(value.st_mode):
                pending.append(Path(entry.path))
            elif stat.S_ISREG(value.st_mode) and value.st_nlink == 1:
                total += value.st_size
            else:
                raise SnapshotCapacityError("Seed snapshot capacity entry type is unsafe")
    return total


@contextmanager
def snapshot_allocation(
    root: Path, source: Path, *, deadline_monotonic: float | None = None,
    maximum_bytes: int = MAXIMUM_SNAPSHOT_BYTES,
    free_floor_bytes: int = FREE_SPACE_FLOOR_BYTES,
) -> Iterator[None]:
    """Serialize the whole copy and deny exhaustion without evicting live state."""
    if fcntl is None:
        raise SnapshotCapacityError("Seed snapshot capacity locking requires Linux")
    before = _private_root(root)
    source_value = source.lstat()
    if (not stat.S_ISREG(source_value.st_mode) or source_value.st_size <= 0
            or maximum_bytes <= 0 or free_floor_bytes < 0):
        raise SnapshotCapacityError("Seed snapshot capacity source or limits are invalid")
    # SQLite backup includes the source page image; reserve two extra pages for
    # filesystem metadata/owner lock, then fail closed if the source changes.
    prospective = source_value.st_size + 8192
    lock_path = root / LOCK_NAME
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        lock_value = os.fstat(descriptor)
        named_value = lock_path.lstat()
        if (not stat.S_ISREG(lock_value.st_mode) or lock_value.st_uid != os.geteuid()
                or stat.S_IMODE(lock_value.st_mode) != 0o600 or lock_value.st_nlink != 1
                or (lock_value.st_dev, lock_value.st_ino) != (named_value.st_dev, named_value.st_ino)):
            raise SnapshotCapacityError("Seed snapshot capacity lock custody is unsafe")
        deadline = min(time.monotonic() + 60.0, deadline_monotonic or float("inf"))
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise SnapshotCapacityError("Seed snapshot capacity admission timed out") from None
                time.sleep(0.05)
        after = _private_root(root)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise SnapshotCapacityError("Seed snapshot capacity root changed")
        used = _inventory(root)
        space = os.statvfs(root)
        free = space.f_bavail * space.f_frsize
        if used + prospective > maximum_bytes:
            raise SnapshotCapacityError("Seed snapshot spool capacity is exhausted")
        if free < free_floor_bytes + prospective:
            raise SnapshotCapacityError("Seed snapshot disk free-space reserve is unavailable")
        yield
    finally:
        os.close(descriptor)
