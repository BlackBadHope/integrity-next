"""Bounded replay capacity and independent ordinary registration, private fixtures."""
from contextlib import nullcontext
from copy import deepcopy
import hashlib
import multiprocessing
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from integrity_guardian import memory_synapse_mcp as m
from test_session_recovery_reservation_fallback import gate


def replay_id(text):
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


def facade(root):
    return m.MemorySynapseMcp(SimpleNamespace(), architecture=SimpleNamespace(root=root))


@pytest.fixture
def pool(tmp_path):
    root = tmp_path / "architecture"
    root.mkdir(mode=0o700)
    f = facade(root)
    f._prepare_context_replay_custody()
    return f


@pytest.mark.skipif(os.name != "posix", reason="Actual POSIX replay custody")
def test_logical_quota_and_declared_bounds(pool, monkeypatch):
    assert m.MAX_CONTEXT_ADMISSION_REPLAY_TOTAL_BYTES == 4 * 1024**3
    assert m.MAX_CONTEXT_ADMISSION_REPLAY_BYTES == 32 * 1024**2
    assert m.MAX_CONTEXT_ADMISSION_REPLAY_CATALOG_BYTES == 512 * 1024**2
    assert m.MAX_CONTEXT_ADMISSION_REPLAY_RECORDS == 128
    assert m.CONTEXT_ADMISSION_REPLAY_TTL_SECONDS == 24 * 3600
    f = pool
    monkeypatch.setattr(m, "MAX_CONTEXT_ADMISSION_REPLAY_TOTAL_BYTES", 33 * 1024**2)
    assert f._reserve_context_admission_replay(replay_id("first")) == 0
    first = next(f._context_admission_replay_root.glob("*.reservation.json")).read_bytes()
    assert f._reserve_context_admission_replay(replay_id("second")) is None
    assert f._context_admission_replay_unavailable_reason == "replay-logical-capacity-exhausted"
    assert len(list(f._context_admission_replay_root.glob("*.reservation.json"))) == 1
    assert next(f._context_admission_replay_root.glob("*.reservation.json")).read_bytes() == first


@pytest.mark.skipif(os.name != "posix", reason="Actual POSIX replay custody")
def test_low_disk_denies_without_new_reservation(pool, monkeypatch):
    f = pool
    with f._context_replay_lock(replay_id("low-space")), f._context_replay_maintenance_lock():
        pass
    claim = m.MAX_CONTEXT_ADMISSION_REPLAY_BYTES + m.MAX_CONTEXT_ADMISSION_REPLAY_RESERVATION_BYTES
    monkeypatch.setattr(os, "fstatvfs", lambda fd: SimpleNamespace(
        f_bavail=m.CONTEXT_ADMISSION_REPLAY_DISK_FREE_FLOOR_BYTES + claim - 1, f_frsize=1))
    before = {p.name: p.read_bytes() for p in f._context_admission_replay_root.iterdir()}
    assert f._reserve_context_admission_replay(replay_id("low-space")) is None
    assert f._context_admission_replay_unavailable_reason == "replay-physical-capacity-exhausted"
    after = {p.name: p.read_bytes() for p in f._context_admission_replay_root.iterdir()}
    assert after == before


@pytest.mark.skipif(os.name != "posix", reason="Actual POSIX replay custody")
def test_physical_guard_counts_existing_unallocated_promises(pool, monkeypatch):
    f = pool
    assert f._reserve_context_admission_replay(replay_id("promised")) == 0
    with f._context_replay_lock(replay_id("cannot-reuse-free-space")), f._context_replay_maintenance_lock():
        pass
    root = f._context_admission_replay_root
    before = {p.name: p.read_bytes() for p in root.iterdir()}
    f._context_replay_inventory(prune=False)
    outstanding = f._context_replay_unallocated_reservation_bytes
    assert outstanding > 31 * 1024**2
    claim = m.MAX_CONTEXT_ADMISSION_REPLAY_BYTES + m.MAX_CONTEXT_ADMISSION_REPLAY_RESERVATION_BYTES
    monkeypatch.setattr(os, "fstatvfs", lambda fd: SimpleNamespace(
        f_bavail=m.CONTEXT_ADMISSION_REPLAY_DISK_FREE_FLOOR_BYTES + outstanding + claim - 1,
        f_frsize=1))
    assert f._reserve_context_admission_replay(replay_id("cannot-reuse-free-space")) is None
    assert f._context_admission_replay_unavailable_reason == "replay-physical-capacity-exhausted"
    assert {p.name: p.read_bytes() for p in root.iterdir()} == before


def reserve_worker(root, identity, ready, start, results):
    f = facade(Path(root))
    ready.put(True)
    start.wait(5)
    try:
        value = f._reserve_context_admission_replay(replay_id(identity))
        results.put((value is not None, f._context_admission_replay_unavailable_reason))
    except Exception as exc:
        results.put((False, type(exc).__name__))


@pytest.mark.skipif(os.name != "posix", reason="Actual separate Linux process locks")
def test_two_concurrent_reservations_do_not_double_spend_capacity(pool, monkeypatch):
    monkeypatch.setattr(m, "MAX_CONTEXT_ADMISSION_REPLAY_TOTAL_BYTES", 48 * 1024**2)
    ctx = multiprocessing.get_context("fork")
    ready, results, start = ctx.Queue(), ctx.Queue(), ctx.Event()
    processes = [ctx.Process(target=reserve_worker, args=(
        pool._context_admission_replay_root.parent, str(i), ready, start, results)) for i in range(2)]
    try:
        for p in processes:
            p.start()
        for p in processes:
            assert ready.get(timeout=5)
        start.set()
        observed = [results.get(timeout=8) for p in processes]
        assert sorted(observed) == [(False, "replay-logical-capacity-exhausted"), (True, None)]
        assert len(list(pool._context_admission_replay_root.glob("*.reservation.json"))) == 1
    finally:
        for p in processes:
            p.join(timeout=3)
            if p.is_alive():
                p.terminate()
                p.join(timeout=2)


@pytest.mark.parametrize("reason", ["replay-logical-capacity-exhausted", "replay-physical-capacity-exhausted"])
def test_capacity_degraded_registration_remains_allowed_and_explicit(gate, reason):
    f = gate.f
    f._context_admission_replay_unavailable_reason = reason
    f._remember_unretained_admission()
    opened = f.call("integrity_turn_memory_open", deepcopy(gate.args))
    recovery = opened["session_recovery"]
    assert recovery["status"] == "capacity-degraded"
    assert recovery["capacity_reason"] == reason
    assert recovery["available"] is False
    assert recovery["automatic_retry_allowed"] is False
    assert recovery["read_plane"] == "ready"
    closed = f.call("integrity_turn_memory_close", {"registration_id": opened["receipt"]["receipt_id"],
        "outcome": "no-event", "no_event_reason": "read-only"})
    assert closed["receipt"]["registration_id"] == opened["receipt"]["receipt_id"]
