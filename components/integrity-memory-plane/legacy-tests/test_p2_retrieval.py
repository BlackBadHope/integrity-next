from __future__ import annotations

import gzip
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from memory_plane_common import atomic_json, canonical_json, sha256_bytes  # noqa: E402
from p2_contract import Envelope, build_batch  # noqa: E402
from p2_retrieval import fts_or_query, fts_terms, receipt_for_cursor, retrieve  # noqa: E402


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


class Rows(list):
    def fetchall(self):
        return list(self)

    def fetchone(self):
        return self[0] if self else None


class FakeConnection:
    def __init__(self, batch_sha: str, payload_sha: str, head: int = 1):
        self.batch_sha = batch_sha
        self.payload_sha = payload_sha
        self.head = head

    def execute(self, query: str, _params: object = None) -> Rows:
        if "FROM integrity_p2.projection_offsets" in query:
            return Rows([(name, self.head, self.batch_sha) for name in ("fts", "graph", "vector", "task-state")])
        if "FROM integrity_p2.raw_events" in query:
            return Rows([(self.payload_sha,)]) if self.head >= 1 else Rows()
        raise AssertionError(query)


def fixture(root: Path) -> tuple[Path, FakeS3, dict[str, object]]:
    receipts = root / "receipts"
    receipts.mkdir()
    source = {"event_cursor": 1, "event_count": 1}
    envelope = Envelope(
        tenant_id="workspace",
        namespace="seed://project/default",
        edge_id="source-linux-action-log",
        cursor=1,
        event_uid="legacy-action-log-1-dual-fixture",
        ts_utc="2026-06-15T00:00:00Z",
        payload={"id": 1, "summary": "first canonical memory"},
        source_manifest_sha256=sha256_bytes(canonical_json(source)),
    )
    batch = build_batch([envelope])
    manifest = {key: value for key, value in batch.items() if key != "envelopes"}
    body = gzip.compress(canonical_json({"protocol": "integrity-memory-plane.p2-raw-object.v1", "source_manifest": source, "batch_manifest": manifest}) + b"\n" + canonical_json(batch["envelopes"][0]) + b"\n", mtime=0)
    receipt = {"status": "shadow_pipeline_committed", "production_authority": False, "ack_decision": {"status": "NOT_ACKED"}, "batch": manifest, "raw": {"key": manifest["object_key"], "version_id": "v1", "content_sha256": sha256_bytes(body)}}
    path = receipts / f"batch-{manifest['batch_sha256']}.json"
    atomic_json(path, receipt)
    return receipts, FakeS3(body), receipt


def test_exact_retrieval_is_grounded_to_exact_worm_version(tmp_path: Path) -> None:
    receipts, client, receipt = fixture(tmp_path)
    envelope = build_batch(
        [Envelope(tenant_id="workspace", namespace="seed://project/default", edge_id="source-linux-action-log", cursor=1, event_uid="legacy-action-log-1-dual-fixture", ts_utc="2026-06-15T00:00:00Z", payload={"id": 1, "summary": "first canonical memory"}, source_manifest_sha256=sha256_bytes(canonical_json({"event_cursor": 1, "event_count": 1})))]
    )["envelopes"][0]
    result = retrieve("#1", FakeConnection(str(receipt["batch"]["batch_sha256"]), str(envelope["payload_sha256"])), client, receipts, limit=10, capsule_budget=8192)
    assert result["decision"] == "SUPPORTED"
    assert result["included_event_ids"] == [1]
    assert result["capsule"]["events"][0]["worm_proof"]["raw_object_version"] == "v1"
    assert result["unsupported_green_count"] == 0


def test_query_beyond_projection_coverage_cannot_be_green(tmp_path: Path) -> None:
    receipts, client, receipt = fixture(tmp_path)
    payload_sha = str(build_batch([Envelope(tenant_id="workspace", namespace="seed://project/default", edge_id="source-linux-action-log", cursor=1, event_uid="legacy-action-log-1-dual-fixture", ts_utc="2026-06-15T00:00:00Z", payload={"id": 1, "summary": "first canonical memory"}, source_manifest_sha256=sha256_bytes(canonical_json({"event_cursor": 1, "event_count": 1})))])["envelopes"][0]["payload_sha256"])
    result = retrieve("#1", FakeConnection(str(receipt["batch"]["batch_sha256"]), payload_sha, head=0), client, receipts, limit=10, capsule_budget=8192)
    assert result["decision"] != "SUPPORTED"


def test_historical_proof_survives_a_moving_raw_tail(tmp_path: Path) -> None:
    receipts, client, receipt = fixture(tmp_path)
    payload_sha = str(build_batch([Envelope(tenant_id="workspace", namespace="seed://project/default", edge_id="source-linux-action-log", cursor=1, event_uid="legacy-action-log-1-dual-fixture", ts_utc="2026-06-15T00:00:00Z", payload={"id": 1, "summary": "first canonical memory"}, source_manifest_sha256=sha256_bytes(canonical_json({"event_cursor": 1, "event_count": 1})))])["envelopes"][0]["payload_sha256"])
    # Add an explained immutable tail batch after projection cursor 1.
    tail_source = {"event_cursor": 2, "event_count": 2}
    previous = str(receipt["batch"]["batch_sha256"])
    prior_envelope = build_batch([Envelope(tenant_id="workspace", namespace="seed://project/default", edge_id="source-linux-action-log", cursor=1, event_uid="legacy-action-log-1-dual-fixture", ts_utc="2026-06-15T00:00:00Z", payload={"id": 1, "summary": "first canonical memory"}, source_manifest_sha256=sha256_bytes(canonical_json({"event_cursor": 1, "event_count": 1})))])["envelopes"][0]["envelope_sha256"]
    tail = build_batch([Envelope(tenant_id="workspace", namespace="seed://project/default", edge_id="source-linux-action-log", cursor=2, event_uid="event-2", ts_utc="2026-06-15T00:01:00Z", payload={"id": 2}, source_manifest_sha256=sha256_bytes(canonical_json(tail_source)), previous_envelope_sha256=str(prior_envelope))], previous_batch_sha256=previous)
    tail_manifest = {key: value for key, value in tail.items() if key != "envelopes"}
    tail_body = gzip.compress(canonical_json({"protocol": "integrity-memory-plane.p2-raw-object.v1", "source_manifest": tail_source, "batch_manifest": tail_manifest}) + b"\n" + canonical_json(tail["envelopes"][0]) + b"\n", mtime=0)
    atomic_json(receipts / f"batch-{tail_manifest['batch_sha256']}.json", {"status": "shadow_pipeline_committed", "production_authority": False, "ack_decision": {"status": "NOT_ACKED"}, "batch": tail_manifest, "raw": {"key": tail_manifest["object_key"], "version_id": "v2", "content_sha256": sha256_bytes(tail_body)}})
    class TwoS3(FakeS3):
        def get_object(self, *, VersionId: str, **_: object):
            return {"Body": Body(self.body if VersionId == "v1" else tail_body)}

    result = retrieve("#1", FakeConnection(previous, payload_sha, head=1), TwoS3(client.body), receipts, limit=10, capsule_budget=8192)
    assert result["decision"] == "SUPPORTED"
    assert result["coverage_complete_to_raw_head"] is False
    assert result["coverage_through_cursor"] == 1


def test_receipt_lookup_uses_cursor_range(tmp_path: Path) -> None:
    receipts, _, _ = fixture(tmp_path)
    loaded = [(path, __import__("json").loads(path.read_text())) for path in receipts.glob("*.json")]
    assert receipt_for_cursor(loaded, 1) is not None
    assert receipt_for_cursor(loaded, 2) is None


def test_fts_or_query_preserves_all_bounded_terms() -> None:
    assert fts_or_query(["action", "canonical", "memory"]) == "action | canonical | memory"
    assert fts_terms("task_path:action-log-smoke-20260620") == ["20260620", "action", "log", "path", "smoke", "task"]
