"""The Codex registration template loads as Integrity Seats."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "plugins/integrity-seats/.codex-plugin/plugin.json"


def test_plugin_loads_under_integrity_seats():
    document = json.loads(PLUGIN.read_text(encoding="utf-8"))
    assert document["name"] == "integrity-seats"
    assert document["license"] == "Apache-2.0"
    assert document["interface"]["displayName"] == "Integrity Seats"
    assert PLUGIN.parent.parent.joinpath("hooks/hooks.json").is_file()
    assert PLUGIN.parent.parent.joinpath("profile.json").is_file()
