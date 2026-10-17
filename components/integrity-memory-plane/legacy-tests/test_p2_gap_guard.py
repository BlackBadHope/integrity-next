from __future__ import annotations

import sys
import threading
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import p2_edge_relay  # noqa: E402
import p2_gap_guard  # noqa: E402
from memory_plane_common import exclusive_lock  # noqa: E402


def test_guard_and_relay_share_one_raw_snapshot_lock() -> None:
    assert p2_gap_guard.RAW_PLANE_LOCK == p2_edge_relay.RAW_PLANE_LOCK


def test_gap_status_is_fail_closed() -> None:
    assert p2_gap_guard.classify_status({"missing": 1}, {"fts": 0}) == "FAIL"
    assert p2_gap_guard.classify_status({"missing": 0}, {"fts": 1}) == "DEGRADED"
    assert p2_gap_guard.classify_status({"missing": 0}, {"fts": 0}) == "PASS"


def test_append_only_guard_schema_is_idempotent() -> None:
    schema = (ROOT / "p2-projections.sql").read_text(encoding="utf-8")
    assert "gap_guard_runs_no_update" in schema
    assert "dlq_resolutions_no_delete" in schema
    assert schema.count("EXCEPTION WHEN duplicate_object THEN NULL") >= 4


def test_shared_lock_waits_for_consistent_snapshot(tmp_path: Path) -> None:
    lock = tmp_path / "raw-plane.lock"
    outcome: list[str] = []

    def contender() -> None:
        with exclusive_lock(lock, wait_seconds=1):
            outcome.append("acquired")

    with exclusive_lock(lock):
        worker = threading.Thread(target=contender)
        worker.start()
        time.sleep(0.1)
        assert outcome == []
    worker.join(timeout=2)
    assert outcome == ["acquired"]
