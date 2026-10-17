from __future__ import annotations

import datetime as dt
import io
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from memory_plane_common import sha256_bytes  # noqa: E402
from p2_attachment_ingress import ingest, prepare_manifest  # noqa: E402


class FakeS3:
    def __init__(self) -> None:
        self.objects: dict[str, dict] = {}

    def list_object_versions(self, **kwargs):
        key = kwargs["Prefix"]
        value = self.objects.get(key)
        return {"Versions": [] if value is None else [{"Key": key, "VersionId": value["version_id"]}]}

    def put_object(self, **kwargs):
        key = kwargs["Key"]
        if key in self.objects:
            raise AssertionError("conditional duplicate should be reused before PUT")
        body = kwargs["Body"]
        self.objects[key] = {
            "body": body,
            "metadata": kwargs["Metadata"],
            "content_type": kwargs["ContentType"],
            "version_id": f"v{len(self.objects) + 1}",
        }
        return {"VersionId": self.objects[key]["version_id"]}

    def head_object(self, **kwargs):
        value = self.objects[kwargs["Key"]]
        return {
            "Metadata": value["metadata"],
            "ContentLength": len(value["body"]),
            "ContentType": value["content_type"],
        }

    def get_object_retention(self, **kwargs):
        return {"Retention": {"Mode": "COMPLIANCE", "RetainUntilDate": dt.datetime.now(dt.UTC) + dt.timedelta(days=30)}}

    def get_object(self, **kwargs):
        return {"Body": io.BytesIO(self.objects[kwargs["Key"]]["body"])}


def policy() -> dict:
    return {
        "tenant_id": "workspace",
        "namespace": "seed://project/default",
        "max_object_bytes": 8,
        "max_objects_per_event": 4,
        "max_payload_bytes_per_event": 20,
        "max_manifest_bytes_per_event": 4096,
    }


def item(body: bytes, *, expected: str | None = None, name: str = "x.bin") -> dict:
    return {
        "name": name,
        "mime": "application/octet-stream",
        "body": body,
        "expected_sha256": sha256_bytes(body) if expected is None else expected,
    }


def test_oversized_object_is_rejected_before_s3() -> None:
    with pytest.raises(RuntimeError, match="object exceeds"):
        prepare_manifest("event-1", [item(b"x" * 9)], policy(), policy_file_sha256="a" * 64)


def test_fifth_object_is_rejected_before_s3() -> None:
    with pytest.raises(RuntimeError, match="count exceeds"):
        prepare_manifest("event-1", [item(bytes([i])) for i in range(5)], policy(), policy_file_sha256="a" * 64)


def test_total_payload_budget_is_independent_of_object_limit() -> None:
    with pytest.raises(RuntimeError, match="payload budget"):
        prepare_manifest("event-1", [item(b"x" * 7) for _ in range(3)], policy(), policy_file_sha256="a" * 64)


def test_expected_digest_mismatch_is_rejected_before_s3() -> None:
    with pytest.raises(RuntimeError, match="expected digest"):
        prepare_manifest("event-1", [item(b"abc", expected="f" * 64)], policy(), policy_file_sha256="a" * 64)


def test_content_addressed_duplicate_is_idempotent_and_exact_version_read_back() -> None:
    client = FakeS3()
    payload = [item(b"same", expected=sha256_bytes(b"same"), name="unsafe path/../photo.jpg")]
    first = ingest(client, "event-1", payload, policy(), policy_file_sha256="a" * 64)
    second = ingest(client, "event-1", payload, policy(), policy_file_sha256="a" * 64)
    assert len(client.objects) == 2
    assert first["objects_created"] == 1 and first["objects_reused"] == 0
    assert second["objects_created"] == 0 and second["objects_reused"] == 1
    assert first["stored_objects"][0]["readback_sha256"] == sha256_bytes(b"same")
    assert first["stored_objects"][0]["retention_mode"] == "COMPLIANCE"
    assert first["manifest_object"]["retention_mode"] == "COMPLIANCE"
    assert first["manifest_object"]["readback_sha256"] == first["manifest_sha256"]
    manifest_body = client.objects[first["manifest_object"]["key"]]["body"]
    assert "manifest_sha256" not in json.loads(manifest_body)
    assert first["manifest_reused"] is False and second["manifest_reused"] is True
    assert first["manifest"]["objects"][0]["name"] == "unsafe-path-..-photo.jpg"
    assert '"path":' not in json.dumps(first["manifest"])
    assert first["canonical_event_reference_bound"] is False
    assert first["production_authority"] is False


def test_two_different_events_reuse_content_but_keep_distinct_manifests() -> None:
    client = FakeS3()
    first = ingest(client, "event-1", [item(b"same")], policy(), policy_file_sha256="a" * 64)
    second = ingest(client, "event-2", [item(b"same")], policy(), policy_file_sha256="a" * 64)
    assert len(client.objects) == 3
    assert first["manifest_sha256"] != second["manifest_sha256"]
    assert second["objects_reused"] == 1
