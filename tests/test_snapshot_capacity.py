import multiprocessing
import os
from pathlib import Path
import stat
import time
from types import SimpleNamespace

import pytest

from integrity_guardian.snapshot_capacity import SnapshotCapacityError, snapshot_allocation

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Linux flock/statvfs boundary")


@pytest.fixture
def spool(tmp_path):
    root = tmp_path / "sessions"
    root.mkdir(mode=0o700)
    source = tmp_path / "source"
    source.write_bytes(b"source" * 100)
    source.chmod(0o600)
    return root, source


def test_allocation_preserves_existing_bytes_and_enforces_total(spool):
    root, source = spool
    live = root / "live"
    live.write_bytes(b"preserved")
    live.chmod(0o600)
    with pytest.raises(SnapshotCapacityError, match="spool capacity"):
        with snapshot_allocation(root, source, maximum_bytes=8000):
            pytest.fail("must deny before allocation")
    assert live.read_bytes() == b"preserved"


def test_disk_reserve_denies_before_allocation(spool, monkeypatch):
    root, source = spool
    monkeypatch.setattr(os, "statvfs", lambda _: SimpleNamespace(f_bavail=100, f_frsize=4096))
    with pytest.raises(SnapshotCapacityError, match="free-space reserve"):
        with snapshot_allocation(root, source):
            pytest.fail("insufficient free reserve")


@pytest.mark.parametrize("bad", ["root-mode", "lock-mode", "lock-symlink", "entry-symlink", "hardlink"])
def test_unsafe_custody_refused(spool, bad):
    root, source = spool
    if bad == "root-mode":
        root.chmod(0o750)
    elif bad == "lock-mode":
        (root / ".snapshot-capacity.lock").touch(mode=0o640)
    elif bad == "lock-symlink":
        (root / ".snapshot-capacity.lock").symlink_to(source)
    elif bad == "entry-symlink":
        (root / "alias").symlink_to(source)
    else:
        os.link(source, root / "hardlink")
    with pytest.raises((SnapshotCapacityError, OSError)):
        with snapshot_allocation(root, source):
            pytest.fail("unsafe custody accepted")
    assert source.read_bytes() == b"source" * 100


def _allocate(root, source, queue):
    try:
        with snapshot_allocation(Path(root), Path(source), maximum_bytes=100_000, free_floor_bytes=0):
            path = Path(root) / ("copy-" + str(os.getpid()))
            path.write_bytes(b"x" * 60_000)
            path.chmod(0o600)
            time.sleep(0.15)
        queue.put("allocated")
    except SnapshotCapacityError:
        queue.put("denied")


def test_parallel_allocators_cannot_oversubscribe(spool):
    root, source = spool
    source.write_bytes(b"x" * 60_000)
    queue = multiprocessing.Queue()
    workers = [multiprocessing.Process(target=_allocate, args=(str(root), str(source), queue)) for _ in range(2)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(5)
        assert worker.exitcode == 0
    assert sorted(queue.get(timeout=1) for _ in workers) == ["allocated", "denied"]


def test_lock_wait_is_bounded(spool):
    import fcntl
    root, source = spool
    with (root / ".snapshot-capacity.lock").open("w") as lock:
        os.chmod(lock.name, 0o600)
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        started = time.monotonic()
        with pytest.raises(SnapshotCapacityError, match="timed out"):
            with snapshot_allocation(root, source, deadline_monotonic=started + 0.05):
                pytest.fail("contended lock accepted")
        assert time.monotonic() - started < 1
