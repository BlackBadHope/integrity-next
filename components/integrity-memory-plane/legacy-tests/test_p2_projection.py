from __future__ import annotations

import gzip
import json
from pathlib import Path

from memory_plane_common import canonical_json, sha256_bytes
from p2_contract import Envelope, build_batch
from p2_projection import event_nodes, raw_envelopes, sparse_vector
from p2_projection_bootstrap import minio_policy


class FakeBody:
    def __init__(self, value: bytes):
        self.value = value

    def read(self) -> bytes:
        return self.value


class FakeS3:
    def __init__(self, value: bytes):
        self.value = value

    def get_object(self, **_: object) -> dict[str, FakeBody]:
        return {"Body": FakeBody(self.value)}


def fixture() -> tuple[bytes, dict[str, object]]:
    envelope = Envelope(
        tenant_id="workspace",
        namespace="seed://project/default",
        edge_id="source-linux-action-log",
        cursor=1,
        event_uid="legacy-action-log-1-fixture",
        ts_utc="2026-06-15T00:00:00Z",
        payload={"id": 1, "summary": "first canonical memory", "details": {"task_id": "task-1"}, "tags": ["seed"]},
        source_manifest_sha256="1" * 64,
    )
    batch = build_batch([envelope])
    manifest = {key: value for key, value in batch.items() if key != "envelopes"}
    body = gzip.compress(
        canonical_json({"protocol": "integrity-memory-plane.p2-raw-object.v1", "batch_manifest": manifest})
        + b"\n"
        + canonical_json(batch["envelopes"][0])
        + b"\n",
        mtime=0,
    )
    receipt = {
        "batch": manifest,
        "raw": {"bucket": "integrity-p2-raw", "key": manifest["object_key"], "version_id": "v1", "content_sha256": sha256_bytes(body)},
    }
    return body, receipt


def test_raw_batch_reconstruction_and_digest() -> None:
    body, receipt = fixture()
    values = raw_envelopes(FakeS3(body), receipt)
    assert [1] == [value["cursor"] for value in values]
    assert values[0]["payload"]["summary"] == "first canonical memory"


def test_sparse_vector_is_deterministic() -> None:
    assert sparse_vector("Action Log canonical memory") == sparse_vector("Action Log canonical memory")
    assert all(0 <= int(index) < 256 for index, _ in sparse_vector("Action Log canonical memory")[0])


def test_graph_nodes_include_task_and_tag() -> None:
    nodes = set(event_nodes({"actor": "Codex", "action": "note", "details": {"task_id": "task-1"}, "tags": ["seed"]}))
    assert ("task_id", "task-1", "REFERENCES") in nodes
    assert ("tag", "seed", "TAGGED") in nodes


def test_projector_minio_policy_is_strictly_read_only() -> None:
    policy = minio_policy()
    actions = {action for statement in policy["Statement"] for action in statement["Action"]}
    assert "s3:GetObjectVersion" in actions
    assert "s3:GetObjectRetention" in actions
    assert "s3:PutObject" not in actions
    assert "s3:DeleteObject" not in actions
    assert "s3:PutObjectRetention" not in actions
