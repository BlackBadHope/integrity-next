from __future__ import annotations

import json
import hashlib
import os
import tracemalloc
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from p2_compact_catalog import (  # noqa: E402
    attest_catalog,
    bucket_manifest_digest,
    hydrate_block_integrity,
    route_manifest_digests,
    route_manifest_records,
    sync_catalog,
    uid_cursors,
)
import p2_compact_catalog as catalog_module  # noqa: E402
import p2_compact_index as compact_module  # noqa: E402
from p2_compact_index import build_store, candidate_lookup  # noqa: E402
from test_p2_compact_index import events  # noqa: E402


def test_catalog_rebuild_supports_logarithmic_cursor_and_uid_lookup(tmp_path: Path) -> None:
    index, catalog = tmp_path / "index", tmp_path / "catalog"
    build_store(events(32), index, bucket_span=16, raw_head_cursor=32)
    receipt = sync_catalog(index, catalog, rebuild=True)
    assert receipt["status"] == "PASS"
    assert receipt["event_count"] == 32
    assert receipt["uid_level_count"] <= 2
    assert receipt["route_record_count"] > 0
    assert bucket_manifest_digest(catalog, 1, 16)
    assert bucket_manifest_digest(catalog, 32, 16)
    assert bucket_manifest_digest(catalog, 33, 16) is None
    assert uid_cursors(catalog, "event-00000001") == [1]
    assert route_manifest_digests(catalog, "fts", "canonical")
    assert route_manifest_digests(catalog, "graph", "task_id:task-alpha")
    assert [bucket for bucket, _digest in route_manifest_records(catalog, "fts", "worker")] == [0, 1]
    assert candidate_lookup(index, "#1", catalog_root=catalog)["candidate_cursors"] == [1]
    assert candidate_lookup(index, "event_uid:event-00000032", catalog_root=catalog)["candidate_cursors"] == [32]


def test_catalog_incrementally_carries_uid_lsm_levels(tmp_path: Path) -> None:
    index, catalog = tmp_path / "index", tmp_path / "catalog"
    build_store(events(16), index, bucket_span=16, raw_head_cursor=16)
    first = sync_catalog(index, catalog)
    assert first["new_segments"] == 1
    build_store(events(32), index, bucket_span=16, raw_head_cursor=32)
    second = sync_catalog(index, catalog)
    assert second["new_segments"] == 1
    assert second["uid_level_count"] == 1
    assert uid_cursors(catalog, "event-00000001") == [1]
    assert uid_cursors(catalog, "event-00000032") == [32]
    third = sync_catalog(index, catalog)
    assert third["new_segments"] == 0
    assert third["event_count"] == 32


def test_exact_catalog_route_does_not_scan_all_manifests(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    index, catalog = tmp_path / "index", tmp_path / "catalog"
    build_store(events(32), index, bucket_span=16, raw_head_cursor=32)
    sync_catalog(index, catalog, rebuild=True)

    def forbidden_scan(_root: Path):
        raise AssertionError("exact lookup attempted O(N) manifest scan")

    monkeypatch.setattr(compact_module, "manifests", forbidden_scan)
    assert candidate_lookup(index, "#1", catalog_root=catalog)["candidate_cursors"] == [1]
    assert candidate_lookup(index, "event_uid:event-00000032", catalog_root=catalog)["candidate_cursors"] == [32]
    assert 1 in candidate_lookup(index, "canonical memory", catalog_root=catalog)["candidate_cursors"]
    assert candidate_lookup(index, "task_path:task-alpha", catalog_root=catalog)["candidate_cursors"] == [4, 3, 2, 1]


def test_catalog_excludes_unrouted_terms_from_proven_early_stop_ceiling(tmp_path: Path) -> None:
    index, catalog = tmp_path / "index", tmp_path / "catalog"
    build_store(events(64), index, bucket_span=16, raw_head_cursor=64)
    sync_catalog(index, catalog, rebuild=True)

    result = candidate_lookup(index, "worker term-with-no-postings", limit=20, catalog_root=catalog)

    assert result["candidate_cursors"] == list(range(64, 44, -1))
    assert result["lookup_bounds"]["routed_query_terms"] == ["worker"]
    assert result["lookup_bounds"]["manifest_count"] == 4
    assert result["lookup_bounds"]["scanned_manifest_count"] == 2
    assert result["lookup_bounds"]["early_stopped"] is True


def test_authenticated_block_reader_avoids_full_rehash_and_rejects_touched_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    index, catalog = tmp_path / "index", tmp_path / "catalog"
    build_store(events(32), index, bucket_span=16, raw_head_cursor=32)
    sync_catalog(index, catalog, rebuild=True)
    catalog_module._RUN_VERIFY_CACHE.clear()
    catalog_module._BLOCK_MANIFEST_CACHE.clear()
    catalog_module._BLOCK_VERIFY_CACHE.clear()

    def forbidden_full_hash(_handle):
        raise AssertionError("authenticated random-access reader attempted a full run hash")

    monkeypatch.setattr(catalog_module, "_sha256_handle", forbidden_full_hash)
    assert uid_cursors(catalog, "event-00000001") == [1]
    assert route_manifest_digests(catalog, "fts", "canonical")
    assert uid_cursors(catalog, "event-00000001") == [1]
    assert route_manifest_digests(catalog, "fts", "canonical")

    state = json.loads((catalog / "state.json").read_text(encoding="utf-8"))
    assert state["bucket_integrity"]["block_integrity_sha256"]
    assert all(value["block_integrity_sha256"] for value in state["uid_levels"].values())
    assert all(value["block_integrity_sha256"] for value in state["route_levels"].values())
    run = catalog / next(iter(state["uid_levels"].values()))["path"]
    value = bytearray(run.read_bytes())
    value[-1] ^= 1
    os.chmod(run, 0o640)
    run.write_bytes(value)
    os.chmod(run, 0o440)
    with pytest.raises(RuntimeError, match="catalog run authenticated block mismatch"):
        uid_cursors(catalog, "event-00000001")


def test_reader_attestation_pins_complete_non_authoritative_generation(tmp_path: Path) -> None:
    index, catalog = tmp_path / "index", tmp_path / "catalog"
    build_store(events(32), index, bucket_span=16, raw_head_cursor=32)
    sync_catalog(index, catalog, rebuild=True)
    catalog_module._RUN_VERIFY_CACHE.clear()
    receipt = attest_catalog(catalog)
    assert receipt["status"] == "PASS"
    assert receipt["bucket_records"] == 2
    assert receipt["uid_records"] == 32
    assert receipt["route_records"] > 0
    assert all(receipt["checks"].values())
    assert receipt["production_authority"] is False


def test_existing_catalog_hydrates_block_integrity_without_rewriting_runs(tmp_path: Path) -> None:
    index, catalog = tmp_path / "index", tmp_path / "catalog"
    build_store(events(32), index, bucket_span=16, raw_head_cursor=32)
    sync_catalog(index, catalog, rebuild=True)
    state_path = catalog / "state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    run_paths = [
        catalog / state["bucket_catalog_path"],
        *(catalog / value["path"] for value in state["uid_levels"].values()),
        *(catalog / value["path"] for value in state["route_levels"].values()),
    ]
    before = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in run_paths}
    state.pop("bucket_integrity", None)
    state.pop("block_integrity_version", None)
    for family in ("uid_levels", "route_levels"):
        for value in state[family].values():
            for key in ("block_integrity_path", "block_integrity_sha256", "block_size", "block_count"):
                value.pop(key, None)
    for path in catalog.rglob("*.blocks.json"):
        path.unlink()
    state_path.write_text(json.dumps(state), encoding="utf-8")
    origin_state_sha256 = hashlib.sha256(state_path.read_bytes()).hexdigest()

    receipt = hydrate_block_integrity(catalog)

    assert receipt["status"] == "PASS"
    assert receipt["origin_state_sha256"] == origin_state_sha256
    assert receipt["hydrated_state_sha256"] == hashlib.sha256(state_path.read_bytes()).hexdigest()
    assert receipt["semantic_run_binding_sha256"] == catalog_module.catalog_run_binding_sha256(
        json.loads(state_path.read_text(encoding="utf-8"))
    )
    assert receipt["run_count"] == len(run_paths)
    assert before == {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in run_paths}
    assert attest_catalog(catalog)["status"] == "PASS"


def test_stream_run_writer_is_binary_compatible(tmp_path: Path) -> None:
    root = tmp_path / "catalog"
    records = [(bytes.fromhex("01" * 32), 1), (bytes.fromhex("02" * 32), 2)]
    metadata = catalog_module._write_sorted_run(
        root, "uid-runs", 3, catalog_module.UID_MAGIC, catalog_module.UID_RECORD, iter(records), len(records)
    )
    expected = catalog_module.HEADER.pack(catalog_module.UID_MAGIC, len(records)) + b"".join(
        catalog_module.UID_RECORD.pack(*value) for value in records
    )
    path = root / metadata["path"]
    assert path.read_bytes() == expected
    assert metadata["sha256"] == hashlib.sha256(expected).hexdigest()
    assert metadata["bytes"] == len(expected)


def test_sync_streaming_merge_never_calls_legacy_full_run_materializers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    index, catalog = tmp_path / "index", tmp_path / "catalog"
    build_store(events(64), index, bucket_span=16, raw_head_cursor=64)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("legacy full-run materializer called")

    for name in ("_uid_run_bytes", "_route_run_bytes", "_read_uid_run", "_read_route_run"):
        monkeypatch.setattr(catalog_module, name, forbidden)
    receipt = sync_catalog(index, catalog, rebuild=True)
    assert receipt["status"] == "PASS"
    assert receipt["streaming_run_merge"] is True
    assert receipt["merge_fan_in_max"] == 2
    assert uid_cursors(catalog, "event-00000064") == [64]


def test_streaming_uid_merge_has_bounded_python_heap(tmp_path: Path) -> None:
    root = tmp_path / "catalog"
    count = 50_000
    left = catalog_module._write_sorted_run(
        root, "uid-runs", 0, catalog_module.UID_MAGIC, catalog_module.UID_RECORD,
        (((index * 2).to_bytes(32, "big"), index * 2) for index in range(count)), count,
    )
    right = catalog_module._write_sorted_run(
        root, "uid-runs", 0, catalog_module.UID_MAGIC, catalog_module.UID_RECORD,
        (((index * 2 + 1).to_bytes(32, "big"), index * 2 + 1) for index in range(count)), count,
    )
    tracemalloc.start()
    merged = catalog_module._merge_sorted_runs(
        root, "uid-runs", 1, catalog_module.UID_MAGIC, catalog_module.UID_RECORD, left, right
    )
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert merged["records"] == count * 2
    assert peak < 8 * 1024 * 1024
