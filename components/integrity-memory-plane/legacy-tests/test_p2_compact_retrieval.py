from __future__ import annotations

import gzip
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from memory_plane_common import atomic_json, canonical_json, sha256_bytes, sha256_file  # noqa: E402
from p2_compact_index import build_store, source_ref  # noqa: E402
from p2_compact_retrieval import retrieve  # noqa: E402
from p2_contract import Envelope, build_batch  # noqa: E402
from p2_projection import committed_receipts  # noqa: E402
from p2_receipt_catalog import build_catalog  # noqa: E402


class Body:
    def __init__(self, value: bytes):
        self.value = value

    def read(self) -> bytes:
        return self.value


class FakeS3:
    def __init__(self, body: bytes):
        self.body = body

    def get_object(self, **_: object) -> dict[str, Body]:
        return {"Body": Body(self.body)}


def fixture(root: Path) -> tuple[Path, Path, Path, FakeS3]:
    receipts = root / "receipts"
    receipts.mkdir()
    envelopes: list[Envelope] = []
    previous = ""
    for cursor in range(1, 17):
        envelope = Envelope(
            tenant_id="workspace",
            namespace="seed://project/default",
            edge_id="edge-fixture",
            cursor=cursor,
            event_uid=f"event-{cursor:08d}",
            ts_utc="2026-06-15T00:00:00Z",
            payload={
                "id": cursor,
                "summary": "first canonical memory" if cursor == 1 else f"checkpoint {cursor}",
                "details": {"task_id": "task-alpha"},
                "actor": "codex",
                "action": "note",
            },
            source_manifest_sha256="1" * 64,
            previous_envelope_sha256=previous,
        )
        value = envelope.value()
        previous = str(value["envelope_sha256"])
        envelopes.append(envelope)
    batch = build_batch(envelopes)
    manifest = {key: value for key, value in batch.items() if key != "envelopes"}
    body = gzip.compress(
        canonical_json({"protocol": "integrity-memory-plane.p2-raw-object.v1", "batch_manifest": manifest})
        + b"\n" + b"\n".join(canonical_json(value) for value in batch["envelopes"]) + b"\n",
        mtime=0,
    )
    receipt = {
        "status": "shadow_pipeline_committed",
        "production_authority": False,
        "ack_decision": {"status": "NOT_ACKED"},
        "batch": manifest,
        "raw": {
            "key": manifest["object_key"],
            "version_id": "v1",
            "content_sha256": sha256_bytes(body),
        },
    }
    receipt_path = receipts / f"batch-{manifest['batch_sha256']}.json"
    atomic_json(receipt_path, receipt)
    reference = source_ref(receipt)
    reference["receipt_sha256"] = sha256_file(receipt_path)
    source = [{"envelope": value, "source": reference} for value in batch["envelopes"]]
    index = root / "index"
    build_store(source, index, bucket_span=16, raw_head_cursor=16)
    catalog = root / "catalog" / "receipts.json"
    build_catalog(committed_receipts(receipts), catalog)
    return index, receipts, catalog, FakeS3(body)


def test_exact_and_causal_candidates_require_and_receive_worm_proof(tmp_path: Path) -> None:
    index, receipts, catalog, client = fixture(tmp_path)
    exact = retrieve("#1", index, receipts, client, limit=10, capsule_budget=8192, receipt_catalog_path=catalog)
    assert exact["decision"] == "SUPPORTED"
    assert exact["included_event_ids"] == [1]
    assert exact["capsule"]["events"][0]["worm_proof"]["raw_object_version"] == "v1"
    assert exact["capsule"]["events"][0]["included_by_routes"] == ["exact"]
    assert exact["unsupported_green_count"] == 0
    causal = retrieve("task_path:task-alpha", index, receipts, client, limit=4, capsule_budget=8192, receipt_catalog_path=catalog)
    assert causal["decision"] == "SUPPORTED"
    assert causal["included_event_ids"] == [16, 15, 14, 13]
    assert all(item["included_by_routes"] == ["graph"] for item in causal["capsule"]["events"])


def test_missing_candidate_never_becomes_green(tmp_path: Path) -> None:
    index, receipts, catalog, client = fixture(tmp_path)
    result = retrieve("#17", index, receipts, client, limit=10, capsule_budget=8192, receipt_catalog_path=catalog)
    assert result["decision"] == "NO_EVIDENCE"
    assert result["all_included_proven"] is False
    assert result["unsupported_green_count"] == 0


def test_corrupt_raw_object_cannot_support_candidate(tmp_path: Path) -> None:
    index, receipts, catalog, _client = fixture(tmp_path)
    import pytest

    with pytest.raises(RuntimeError, match="raw object digest"):
        retrieve("#1", index, receipts, FakeS3(b"corrupt"), limit=10, capsule_budget=8192, receipt_catalog_path=catalog)
