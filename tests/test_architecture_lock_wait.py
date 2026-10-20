"""Real private file-lock wait; all custody validation remains active."""
import multiprocessing
import os
from pathlib import Path
import threading
import time

import pytest

from integrity_guardian import medor_architecture as a
from integrity_guardian.local_lock import lock_exclusive, unlock

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Real Linux flock acceptance")


def holder(path, ready, seconds):
    fd = os.open(path, os.O_RDWR)
    lock_exclusive(fd)
    ready.set()
    time.sleep(seconds)
    unlock(fd)
    os.close(fd)


def service(tmp_path):
    s = a.PersistentMedorArchitectureService.__new__(a.PersistentMedorArchitectureService)
    s.custody_lock_path = tmp_path / a.CUSTODY_LOCK_NAME
    s.custody_lock_path.touch(mode=0o600)
    s._lock = threading.RLock()
    s._custody_lock_descriptor = s._open_custody_lock()
    return s


def test_default_wait_survives_six_second_holder_and_releases(tmp_path):
    assert a.CUSTODY_LOCK_TIMEOUT_SECONDS == 45.0
    s = service(tmp_path)
    ctx = multiprocessing.get_context("fork")
    ready = ctx.Event()
    p = ctx.Process(target=holder, args=(s.custody_lock_path, ready, 6))
    p.start()
    try:
        assert ready.wait(3)
        started = time.monotonic()
        with s._exclusive_custody():
            assert time.monotonic() - started >= 5.5
        p.join(timeout=2)
        assert p.exitcode == 0
        with s._exclusive_custody():
            pass
    finally:
        if p.is_alive():
            p.terminate()
            p.join(timeout=2)
        s.close()


def test_bounded_timeout_keeps_holder_lock_and_releases_afterward(tmp_path, monkeypatch):
    monkeypatch.setattr(a, "CUSTODY_LOCK_TIMEOUT_SECONDS", 0.1)
    s = service(tmp_path)
    ctx = multiprocessing.get_context("fork")
    ready = ctx.Event()
    p = ctx.Process(target=holder, args=(s.custody_lock_path, ready, 0.5))
    p.start()
    try:
        assert ready.wait(3)
        with pytest.raises(a.MedorArchitectureError, match="acquisition timed out"):
            with s._exclusive_custody():
                pytest.fail("holder lock bypassed")
        p.join(timeout=2)
        assert p.exitcode == 0
        with s._exclusive_custody():
            pass
    finally:
        if p.is_alive():
            p.terminate()
            p.join(timeout=2)
        s.close()
