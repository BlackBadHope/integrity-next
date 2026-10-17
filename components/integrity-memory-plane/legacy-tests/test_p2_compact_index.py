from __future__ import annotations

import copy
import gzip
import hashlib
import json
import struct
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from memory_plane_common import canonical_json, sha256_bytes  # noqa: E402
import p2_compact_index as compact_module  # noqa: E402
from p2_compact_index import build_store, build_store_stream, candidate_lookup, manifests, object_path, verify_store  # noqa: E402
from p2_compact_catalog import sync_catalog  # noqa: E402
from p2_compact_offhost import mirror  # noqa: E402
from p2_contract import Envelope  # noqa: E402


def events(count: int, *, start: int = 1) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    previous = ""
    for cursor in range(start, start + count):
        payload = {
            "id": cursor,
            "summary": "Action Log canonical memory" if cursor == 1 else f"worker checkpoint {cursor}",
            "details": {"task_id": "task-alpha" if cursor <= 4 else f"task-{cursor // 4}"},
            "tags": ["seed", "early" if cursor == 1 else "progress"],
            "actor": "codex",
            "action": "agent_change_progress",
        }
        envelope = Envelope(
            tenant_id="workspace",
            namespace="seed://project/default",
            edge_id="edge-fixture",
            cursor=cursor,
            event_uid=f"event-{cursor:08d}",
            ts_utc=f"2026-06-{15 + (cursor // 20):02d}T00:00:00Z",
            payload=payload,
            source_manifest_sha256="1" * 64,
            previous_envelope_sha256=previous,
        ).value()
        previous = str(envelope["envelope_sha256"])
        source = {
            "first_cursor": start,
            "last_cursor": start + count - 1,
            "batch_sha256": sha256_bytes(canonical_json([start, count])),
            "raw_key": "raw/fixture.ndjson.gz",
            "raw_version_id": "v1",
            "raw_content_sha256": "2" * 64,
            "receipt_sha256": "3" * 64,
        }
        result.append({"envelope": envelope, "source": source})
    return result


def test_deterministic_rebuild_and_candidate_routes(tmp_path: Path) -> None:
    source = events(32)
    left, right = tmp_path / "left", tmp_path / "right"
    first = build_store(source, left, bucket_span=16, raw_head_cursor=32)
    second = build_store(copy.deepcopy(source), right, bucket_span=16, raw_head_cursor=32)
    left_catalog, right_catalog = tmp_path / "left-catalog", tmp_path / "right-catalog"
    sync_catalog(left, left_catalog, rebuild=True)
    sync_catalog(right, right_catalog, rebuild=True)
    assert first["manifest_head_sha256"] == second["manifest_head_sha256"]
    assert verify_store(left, left_catalog)["status"] == "PASS"
    assert verify_store(left, left_catalog)["semantic_bucket_chain_sha256"] == verify_store(right, right_catalog)["semantic_bucket_chain_sha256"]
    assert candidate_lookup(left, "#1")["candidate_cursors"] == [1]
    assert candidate_lookup(left, "event_uid:event-00000001")["candidate_cursors"] == [1]
    assert 1 in candidate_lookup(left, "canonical memory")["candidate_cursors"]
    assert candidate_lookup(left, "task_path:task-alpha")["candidate_cursors"] == [4, 3, 2, 1]
    assert candidate_lookup(left, "canonical memory")["exact_raw_readback_required"] is True


def test_candidate_lookup_bounds_ranking_and_source_resolution_by_top_k(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "bounded-candidate-union"
    build_store(events(64), root, bucket_span=16, raw_head_cursor=64)
    manifest_values = manifests(root)
    visits = {"candidate_source_scans": 0}

    class CountingSources(list[dict[str, object]]):
        def __iter__(self):  # type: ignore[no-untyped-def]
            visits["candidate_source_scans"] += 1
            return super().__iter__()

    for _path, manifest, _digest in manifest_values:
        manifest["sources"] = CountingSources(manifest["sources"])
    monkeypatch.setattr(compact_module, "manifests", lambda _root: manifest_values)

    result = candidate_lookup(root, "worker checkpoint", limit=20)

    assert result["candidate_cursors"] == list(range(64, 44, -1))
    assert len(result["source_locators"]) == 20
    assert visits["candidate_source_scans"] == 32
    assert result["lookup_bounds"]["manifest_count"] == 4
    assert result["lookup_bounds"]["scanned_manifest_count"] == 2
    assert result["lookup_bounds"]["early_stopped"] is True
    assert result["lookup_bounds"]["candidate_population"] == 32
    assert result["lookup_bounds"]["ranking_state_max"] == 20
    assert result["lookup_bounds"]["ranking_state_limit"] == 20
    assert result["lookup_bounds"]["ranking_mode"] == "lexical-top-k-then-vector-rerank-v1"
    assert result["lookup_bounds"]["routes_truncated"]["fts"] is True


def test_unsealed_tail_is_fail_closed(tmp_path: Path) -> None:
    result = build_store(events(17), tmp_path / "store", bucket_span=16, raw_head_cursor=17)
    assert result["coverage_through_cursor"] == 16
    assert result["coverage_lag_events"] == 1
    assert candidate_lookup(tmp_path / "store", "#17")["decision"] == "NO_EVIDENCE"


def test_streaming_builder_holds_one_bucket_and_skips_sealed_prefix(tmp_path: Path) -> None:
    root = tmp_path / "stream"
    first = build_store_stream(iter(events(16)), root, bucket_span=16, raw_head_cursor=16)
    assert first["streaming_source"] is True
    assert first["peak_bucket_events"] == 16
    second = build_store_stream(iter(events(32)), root, bucket_span=16, raw_head_cursor=32)
    assert second["created_segment_count"] == 1
    assert second["peak_bucket_events"] == 16
    catalog = tmp_path / "stream-catalog"
    sync_catalog(root, catalog, rebuild=True)
    verified = verify_store(root, catalog)
    assert verified["event_count"] == 32
    assert verified["segment_count"] == 2


def test_streaming_builder_rejects_non_monotonic_source(tmp_path: Path) -> None:
    source = events(17)
    source[15], source[16] = source[16], source[15]
    with pytest.raises(RuntimeError, match="unique, ascending"):
        build_store_stream(iter(source), tmp_path / "bad-stream", bucket_span=16, raw_head_cursor=17)


def test_vector_lsh_collision_cannot_support_without_grounded_route(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "vector-only"
    build_store(events(16), root, bucket_span=16, raw_head_cursor=16)
    manifest = manifests(root)[0][1]
    payload = json.loads(gzip.decompress(object_path(root, manifest["payload"]["sha256"]).read_bytes()))
    forced_band = payload["vector_lsh16x4"][0][0]
    monkeypatch.setattr(compact_module, "vector_bands", lambda _value: [forced_band])
    result = candidate_lookup(root, "qzxwvut-no-lexical-evidence")
    assert result["decision"] == "NO_EVIDENCE"
    assert result["routes"]["vector"] == []


def test_incremental_mirror_transfers_only_missing_digests(tmp_path: Path) -> None:
    origin, remote = tmp_path / "origin", tmp_path / "remote"
    build_store(events(16), origin, bucket_span=16, raw_head_cursor=16)
    first = mirror(origin, remote)
    assert first["objects_transferred"] == 2
    assert first["bytes_transferred"] > 0
    build_store(events(32), origin, bucket_span=16, raw_head_cursor=32)
    second = mirror(origin, remote)
    assert second["objects_transferred"] == 2
    assert second["objects_reused"] == 2
    third = mirror(origin, remote)
    assert third["objects_transferred"] == 0
    assert third["objects_reused"] == 4


def test_corrupt_content_addressed_payload_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "store"
    build_store(events(16), root, bucket_span=16, raw_head_cursor=16)
    catalog = tmp_path / "catalog"
    sync_catalog(root, catalog, rebuild=True)
    manifest = json.loads(next((root / "segments").glob("*.json")).read_text())
    payload = object_path(root, manifest["payload"]["sha256"])
    payload.chmod(0o640)
    payload.write_bytes(b"corrupt")
    with pytest.raises(RuntimeError, match="payload digest"):
        verify_store(root, catalog)


def test_bounded_verifier_rejects_duplicate_uid_across_buckets(tmp_path: Path) -> None:
    source = events(32)
    source[16]["envelope"]["event_uid"] = source[0]["envelope"]["event_uid"]
    root, catalog = tmp_path / "duplicate", tmp_path / "duplicate-catalog"
    build_store(source, root, bucket_span=16, raw_head_cursor=32)
    sync_catalog(root, catalog, rebuild=True)
    with pytest.raises(RuntimeError, match="duplicate event_uid hash"):
        verify_store(root, catalog)


def test_bounded_verifier_rejects_cursor_gap_across_buckets(tmp_path: Path) -> None:
    source = events(17)
    del source[1]
    root, catalog = tmp_path / "gap", tmp_path / "gap-catalog"
    build_store_stream(iter(source), root, bucket_span=16, raw_head_cursor=17, seal_head=True)
    sync_catalog(root, catalog, rebuild=True)
    with pytest.raises(RuntimeError, match="cursor gap"):
        verify_store(root, catalog)


def test_bounded_verifier_rejects_same_count_catalog_from_other_generation(tmp_path: Path) -> None:
    clean = events(32)
    duplicate = copy.deepcopy(clean)
    duplicate[16]["envelope"]["event_uid"] = duplicate[0]["envelope"]["event_uid"]
    clean_root, duplicate_root, catalog = tmp_path / "clean", tmp_path / "duplicate-index", tmp_path / "clean-catalog"
    build_store(clean, clean_root, bucket_span=16, raw_head_cursor=32)
    build_store(duplicate, duplicate_root, bucket_span=16, raw_head_cursor=32)
    sync_catalog(clean_root, catalog, rebuild=True)
    catalog_state_path = catalog / "state.json"
    catalog_state = json.loads(catalog_state_path.read_text(encoding="utf-8"))
    duplicate_state = json.loads((duplicate_root / "state.json").read_text(encoding="utf-8"))
    catalog_state["processed_manifest_head_sha256"] = duplicate_state["manifest_head_sha256"]
    catalog_state_path.write_text(
        json.dumps(catalog_state, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
    )
    with pytest.raises(RuntimeError, match="duplicate event_uid hash across compact payloads"):
        verify_store(duplicate_root, catalog)


def test_bounded_verifier_rejects_resigned_unsorted_uid_run(tmp_path: Path) -> None:
    root, catalog = tmp_path / "index", tmp_path / "catalog"
    build_store(events(32), root, bucket_span=16, raw_head_cursor=32)
    sync_catalog(root, catalog, rebuild=True)
    state_path = catalog / "state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    level = next(iter(state["uid_levels"]))
    metadata = state["uid_levels"][level]
    run = catalog / metadata["path"]
    value = bytearray(run.read_bytes())
    header_size, record_size = struct.calcsize(">8sQ"), struct.calcsize(">32sQ")
    first = bytes(value[header_size:header_size + record_size])
    second = bytes(value[header_size + record_size:header_size + 2 * record_size])
    value[header_size:header_size + record_size] = second
    value[header_size + record_size:header_size + 2 * record_size] = first
    digest = hashlib.sha256(value).hexdigest()
    replacement = run.with_name(f"level-{int(level):03d}-{digest}.bin")
    replacement.write_bytes(value)
    replacement.chmod(0o440)
    metadata["path"] = str(replacement.relative_to(catalog))
    metadata["sha256"] = digest
    state_path.write_text(json.dumps(state, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="block-integrity manifest does not bind"):
        verify_store(root, catalog)


def test_bounded_verifier_rejects_resigned_uid_catalog_cursor_substitution(tmp_path: Path) -> None:
    root, catalog = tmp_path / "index", tmp_path / "catalog"
    build_store(events(32), root, bucket_span=16, raw_head_cursor=32)
    sync_catalog(root, catalog, rebuild=True)
    state_path = catalog / "state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    level = next(iter(state["uid_levels"]))
    metadata = state["uid_levels"][level]
    run = catalog / metadata["path"]
    value = bytearray(run.read_bytes())
    header_size = struct.calcsize(">8sQ")
    digest_value, cursor = struct.unpack(">32sQ", value[header_size:header_size + struct.calcsize(">32sQ")])
    value[header_size:header_size + struct.calcsize(">32sQ")] = struct.pack(">32sQ", digest_value, cursor + 1000)
    digest = hashlib.sha256(value).hexdigest()
    replacement = run.with_name(f"level-{int(level):03d}-{digest}.bin")
    replacement.write_bytes(value)
    replacement.chmod(0o440)
    metadata["path"] = str(replacement.relative_to(catalog))
    metadata["sha256"] = digest
    state_path.write_text(json.dumps(state, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="block-integrity manifest does not bind"):
        verify_store(root, catalog)


def test_bounded_verifier_rejects_uncommitted_extra_segment_reference(tmp_path: Path) -> None:
    root, catalog = tmp_path / "index", tmp_path / "catalog"
    build_store(events(16), root, bucket_span=16, raw_head_cursor=16)
    sync_catalog(root, catalog, rebuild=True)
    reference = next((root / "segments").glob("*.json"))
    (root / "segments" / f"{999:020d}-{reference.stem.rsplit('-', 1)[-1]}.json").write_bytes(reference.read_bytes())
    with pytest.raises(RuntimeError, match="compact store verification failed"):
        verify_store(root, catalog)
