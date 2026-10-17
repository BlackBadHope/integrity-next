from __future__ import annotations

import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import p2_hot_cold_dual as dual  # noqa: E402


combine = dual.combine


def plane(ids: list[int], *, cursor: int, decision: str = "SUPPORTED", causal: list[int] | None = None) -> dict:
    return {
        "query_sha256": "a" * 64,
        "decision": decision,
        "projection_cursor": cursor,
        "raw_head_cursor": 100,
        "projection_lag_events": 0,
        "coverage_complete_to_raw_head": True,
        "offsets_equal": True,
        "included_event_ids": ids,
        "causal_path": {"event_ids": causal or []},
        "all_included_proven": True,
        "unsupported_green_count": 0,
        "elapsed_ms": 10,
        "capsule": {"events": [{"event_id": value, "worm_proof": {"ok": True}} for value in ids]},
    }


def test_exact_cursor_selects_one_domain_and_enforces_boundary() -> None:
    cold = plane([1], cursor=50)
    hot = plane([1, 60], cursor=100)
    result = combine("#1", cold, hot)
    assert result["included_event_ids"] == [1]
    assert result["hot_tail_event_ids"] == [60]
    assert result["decision"] == "SUPPORTED"


def test_semantic_rrf_merges_only_hot_tail_with_proofs() -> None:
    cold = plane([10, 9], cursor=50)
    hot = plane([40, 60, 70], cursor=100)
    result = combine("authority", cold, hot, limit=4)
    assert result["included_event_ids"] == [60, 10, 70, 9]
    assert all(value > 50 for value in result["hot_tail_event_ids"])
    assert result["all_included_proven"] is True


def test_causal_path_is_cursor_ordered_across_boundary() -> None:
    cold = plane([2, 1], cursor=50, causal=[1, 2])
    hot = plane([2, 60, 61], cursor=100, causal=[1, 2, 60, 61])
    result = combine("task_path:task", cold, hot)
    assert result["causal_path"]["event_ids"] == [1, 2, 60, 61]
    assert result["included_event_ids"] == [1, 2, 60, 61]


def test_empty_planes_stay_unknown_without_unsupported_green() -> None:
    result = combine("none", plane([], cursor=50, decision="NO_EVIDENCE"), plane([], cursor=100, decision="NO_EVIDENCE"))
    assert result["decision"] == "NO_EVIDENCE"
    assert result["all_included_proven"] is True
    assert result["unsupported_green_count"] == 0


def test_run_dual_reads_independent_domains_in_parallel(monkeypatch, tmp_path: Path) -> None:
    query = "parallel"
    digest = "a" * 64

    def delayed(value: dict) -> dict:
        time.sleep(0.08)
        return value

    monkeypatch.setattr(dual, "load_env", lambda _path: {})
    monkeypatch.setattr(dual, "s3_client", lambda *_args: object())
    monkeypatch.setattr(dual, "p1_retrieve", lambda *_args, **_kwargs: delayed({"elapsed_ms": 80}))
    monkeypatch.setattr(
        dual,
        "cold_retrieve",
        lambda *_args, **_kwargs: delayed(plane([], cursor=50, decision="NO_EVIDENCE") | {"query_sha256": digest}),
    )

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(dual, "connect", lambda *_args: Connection())
    monkeypatch.setattr(
        dual,
        "hot_retrieve",
        lambda *_args, **_kwargs: delayed(plane([], cursor=100, decision="NO_EVIDENCE") | {"query_sha256": digest}),
    )
    monkeypatch.setattr(dual, "compare", lambda *_args: {"disposition": "EQUIVALENT"})

    started = time.perf_counter()
    _p1, merged, _comparison = dual.run_dual(
        query,
        p1_projection_db=tmp_path / "p1.sqlite",
        p1_store_root=tmp_path,
        index_root=tmp_path,
        catalog_root=tmp_path,
        pg_env=tmp_path / "pg.env",
        minio_env=tmp_path / "minio.env",
        receipts_root=tmp_path,
    )
    observed_ms = (time.perf_counter() - started) * 1000
    assert observed_ms < 180
    assert merged["elapsed_ms"] < 180
    assert merged["end_to_end_elapsed_ms"] < 180
    assert merged["execution"] == "parallel-independent-read-domains"
