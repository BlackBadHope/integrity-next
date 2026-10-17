"""Synthetic registry/queue tests use only a temporary owner-selected state root."""
import importlib.util
import json
from pathlib import Path
import sqlite3
import sys


def test_registered_harness_can_receive_and_ack_local_data(tmp_path, monkeypatch):
    root = Path(__file__).resolve().parents[1]
    document = json.loads((root / "configuration.example.json").read_text())
    document.update(configured=True, values={"state_directory": str(tmp_path)})
    config = tmp_path / "configuration.json"
    config.write_text(json.dumps(document))
    monkeypatch.setenv("INTEGRITY_LLM_BUS_CONFIG", str(config))
    resources = root / "src/integrity_llm_bus/resources"

    def module(name):
        spec = importlib.util.spec_from_file_location(name, resources / (name + ".py"))
        value = importlib.util.module_from_spec(spec)
        monkeypatch.setitem(sys.modules, name, value)
        spec.loader.exec_module(value)
        return value

    registry = module("agent_registry")
    registry.register("unit-agent", "00000000-0000-4000-8000-000000000001",
                      harness="antigravity", topic="synthetic test", state_dir=tmp_path)
    assert registry.load(tmp_path)["unit-agent"]["harness"] == "antigravity"
    bus = module("bus")
    path = tmp_path / "synthetic.sqlite3"
    store = bus.MessageStore(path, ttl_seconds=60)
    store.post({"id": "public-unit-message", "from": "codex", "to": "unit-agent",
                "body": "Synthetic data only", "reply_to": None})
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT status FROM messages WHERE id='public-unit-message'").fetchone()[0] == "pending"
    store.ack("public-unit-message", "unit-agent")
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT status FROM messages WHERE id='public-unit-message'").fetchone()[0] == "acked"
