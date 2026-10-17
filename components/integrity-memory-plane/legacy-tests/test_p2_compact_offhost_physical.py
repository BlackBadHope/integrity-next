from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from memory_plane_common import atomic_json  # noqa: E402
from p2_compact_catalog import sync_catalog  # noqa: E402
from p2_compact_index import build_store  # noqa: E402
from p2_compact_offhost_dispatch import load_export, remote_command  # noqa: E402
from p2_compact_offhost_export import export  # noqa: E402
from test_p2_compact_index import events  # noqa: E402


def fixture(root: Path) -> tuple[Path, Path, Path, Path]:
    index, catalog, exported = root / "index", root / "catalog", root / "export"
    build_store(events(32), index, bucket_span=16, raw_head_cursor=32)
    sync_catalog(index, catalog, rebuild=True)
    state = root / "export-state.json"
    result = export(index, catalog, exported, state)
    assert result["status"] == "PASS"
    return index, catalog, exported, state


def test_export_stages_digest_objects_and_is_deterministic(tmp_path: Path) -> None:
    _index, _catalog, exported, state = fixture(tmp_path)
    first = json.loads(state.read_text())
    inventory = Path(first["inventory_path"])
    value = json.loads(inventory.read_text())
    assert value["objects"]
    assert all(entry["relative"].endswith(entry["sha256"]) for entry in value["objects"])
    again = export(tmp_path / "index", tmp_path / "catalog", exported, state)
    assert again["inventory_sha256"] == first["inventory_sha256"]
    assert load_export(state, exported)["state"]["inventory_sha256"] == first["inventory_sha256"]


def test_dispatch_command_is_incremental_and_fail_closed(tmp_path: Path) -> None:
    _index, _catalog, exported, state = fixture(tmp_path)
    loaded = load_export(state, exported)
    args = SimpleNamespace(
        remote_root=r"D:\workspace\IntegrityMemoryPlane\p2-compact",
        pull_user="workspace",
        pull_port=22111,
        pull_key=r"C:/workspace/example-data",
        pull_known_hosts=r"C:/workspace/example-data",
        pull_host_key_alias="integrity-offhost",
    )
    command = remote_command(args, loaded)
    assert "objects_transferred" in command
    assert "objects_reused" in command
    assert "existing compact object mismatch" in command
    assert "compact final readback mismatch" in command
    assert "Move-Item -Force" not in command
    assert "^objects/sha256/" in command


def test_corrupt_or_escaped_export_is_rejected(tmp_path: Path) -> None:
    _index, _catalog, exported, state = fixture(tmp_path)
    value = json.loads(state.read_text())
    inventory_path = Path(value["inventory_path"])
    inventory = json.loads(inventory_path.read_text())
    inventory["objects"][0]["relative"] = "../escape"
    atomic_json(inventory_path, inventory)
    value["inventory_sha256"] = __import__("hashlib").sha256(inventory_path.read_bytes()).hexdigest()
    atomic_json(state, value)
    with pytest.raises(RuntimeError, match="relative path"):
        load_export(state, exported)
