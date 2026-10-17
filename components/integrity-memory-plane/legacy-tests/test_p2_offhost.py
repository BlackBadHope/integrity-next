from __future__ import annotations

import gzip
import json
import sys
import tarfile
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from memory_plane_common import atomic_json, canonical_json, sha256_bytes  # noqa: E402
from p2_contract import Envelope, build_batch  # noqa: E402
from p2_offhost_dispatch import load_export, remote_command  # noqa: E402
from p2_offhost_export import PROTOCOL, build_capsule  # noqa: E402
from p2_offhost_restore_drill import verify_capsule  # noqa: E402


class Body:
    def __init__(self, value: bytes):
        self.value = value

    def read(self) -> bytes:
        return self.value


class FakeS3:
    def __init__(self, values: dict[tuple[str, str], bytes]):
        self.values = values

    def get_object(self, *, Key: str, VersionId: str, **_: object) -> dict[str, Body]:
        return {"Body": Body(self.values[(Key, VersionId)])}


def fixture(root: Path) -> tuple[Path, FakeS3]:
    receipts = root / "receipts"
    receipts.mkdir()
    source_manifest = {"event_cursor": 1, "event_count": 1}
    envelope = Envelope(
        tenant_id="workspace",
        namespace="seed://project/default",
        edge_id="source-linux-action-log",
        cursor=1,
        event_uid="legacy-action-log-1-offhost-fixture",
        ts_utc="2026-06-15T00:00:00Z",
        payload={"id": 1, "summary": "first canonical memory"},
        source_manifest_sha256=sha256_bytes(canonical_json(source_manifest)),
    )
    batch = build_batch([envelope])
    manifest = {key: value for key, value in batch.items() if key != "envelopes"}
    body = gzip.compress(
        canonical_json({"protocol": "integrity-memory-plane.p2-raw-object.v1", "source_manifest": source_manifest, "batch_manifest": manifest})
        + b"\n"
        + canonical_json(batch["envelopes"][0])
        + b"\n",
        mtime=0,
    )
    receipt = {
        "status": "shadow_pipeline_committed",
        "production_authority": False,
        "ack_decision": {"status": "NOT_ACKED"},
        "batch": manifest,
        "raw": {"bucket": "integrity-p2-raw", "key": manifest["object_key"], "version_id": "v1", "content_sha256": sha256_bytes(body)},
    }
    atomic_json(receipts / f"batch-{manifest['batch_sha256']}.json", receipt)
    return receipts, FakeS3({(manifest["object_key"], "v1"): body})


def test_capsule_is_deterministic_and_contains_exact_raw_and_receipt(tmp_path: Path) -> None:
    receipts, client = fixture(tmp_path)
    first = build_capsule(receipts, client, tmp_path / "export")
    second = build_capsule(receipts, client, tmp_path / "export")
    assert first["sha256"] == second["sha256"]
    assert second["status"] == "already-present"
    assert first["head_cursor"] == 1
    assert first["event_count"] == 1
    with tarfile.open(first["path"], "r:gz") as archive:
        names = sorted(archive.getnames())
        assert names[0] == "inventory.json"
        assert len(names) == 3
        inventory = json.load(archive.extractfile("inventory.json"))  # type: ignore[arg-type]
    assert inventory["protocol"] == PROTOCOL + ".inventory"
    assert inventory["batch_count"] == 1
    assert len(inventory["files"]) == 2


def test_client_command_never_overwrites_and_verifies_every_member() -> None:
    args = SimpleNamespace(
        remote_root=r"D:\workspace\IntegrityMemoryPlane\p2-raw\capsules",
        pull_user="workspace",
        pull_port=22111,
        pull_key=r"C:/workspace/example-data",
        pull_known_hosts=r"C:/workspace/example-data",
        pull_host_key_alias="integrity-offhost",
    )
    command = remote_command(
        args,
        {
            "path": "/opt/integrity-example-f889ba6f9ded",
            "name": "p2-raw-head-1.tar.gz",
            "sha256": "a" * 64,
            "inventory_sha256": "b" * 64,
            "head_cursor": 1,
            "batch_count": 1,
            "event_count": 1,
        },
    )
    assert "existing client P2 capsule digest mismatch" in command
    assert "Move-Item -Force" not in command
    assert "unsafe client P2 capsule member" in command
    assert "Get-FileHash" in command
    assert "verified file count mismatch" in command


def test_dispatch_accepts_only_bound_state_protocol(tmp_path: Path) -> None:
    receipts, client = fixture(tmp_path)
    capsule = build_capsule(receipts, client, tmp_path / "export")
    state = {**capsule, "protocol": PROTOCOL + ".state"}
    state_path = tmp_path / "state.json"
    atomic_json(state_path, state)
    assert load_export(state_path, tmp_path / "export")["sha256"] == capsule["sha256"]
    state["protocol"] = PROTOCOL + ".capsule"
    atomic_json(state_path, state)
    import pytest

    with pytest.raises(RuntimeError, match="protocol"):
        load_export(state_path, tmp_path / "export")


def test_capsule_restores_semantically_without_live_sources(tmp_path: Path) -> None:
    receipts, client = fixture(tmp_path)
    capsule = build_capsule(receipts, client, tmp_path / "export")
    result = verify_capsule(Path(capsule["path"]), capsule["sha256"], capsule["inventory_sha256"])
    assert result["status"] == "PASS"
    assert result["checks"]["early_cursor_present"] is True
    assert all(value is False for value in result["source_dependencies"].values())

    import pytest

    with pytest.raises(RuntimeError, match="outer digest"):
        verify_capsule(Path(capsule["path"]), "0" * 64, capsule["inventory_sha256"])
