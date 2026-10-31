"""Two seats share team/* and cannot read or write each other's seat namespace."""
import importlib.util
import json
import sys
from pathlib import Path

import pytest


def _load(tmp_path, monkeypatch):
    component = Path(__file__).resolve().parents[1]
    source = component / "src/integrity_action_log/resources"
    template = json.loads((component / "configuration.example.json").read_text())
    template.update(configured=True)
    template["values"] = {key: str(tmp_path / key) for key in template["values"]}
    config = tmp_path / "config.json"
    config.write_text(json.dumps(template), encoding="utf-8")
    monkeypatch.setenv("INTEGRITY_ACTION_LOG_CONFIG", str(config))
    monkeypatch.setenv("CODEX_LOG_DB", str(tmp_path / "shared.sqlite3"))
    monkeypatch.setenv("CODEX_LOG_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("INTEGRITY_ISOLATION_MODE", "shared-core")
    monkeypatch.syspath_prepend(str(source))
    spec = importlib.util.spec_from_file_location(
        "seat_namespace_action_log", source / "codex_action_log.py"
    )
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    module.ensure_db()
    return module


def test_alice_and_bob_are_isolated(tmp_path, monkeypatch):
    log = _load(tmp_path, monkeypatch)
    alice = log.SeatView("alice", "host-a", {"read", "write"}, ("team/*", "seat/alice/*"), "alice-principal")
    bob = log.SeatView("bob", "host-b", {"read"}, ("team/*", "seat/bob/*"), "bob-principal")
    with log.seat_view(alice):
        log.insert_event({"actor": "alice", "action": "note", "summary": "shared", "namespace": "team/default"})
        log.insert_event({"actor": "alice", "action": "note", "summary": "private", "namespace": "seat/alice/notes"})
        with pytest.raises(log.SeatAccessError) as denied:
            log.insert_event({
                "actor": "alice", "action": "note", "summary": "nope", "namespace": "seat/bob/notes",
            })
        assert denied.value.status == 403
    with log.seat_view(bob):
        rows = log.query_events({"since": ["all"], "limit": ["50"]})
        namespaces = {row["namespace"] for row in rows}
        assert namespaces == {"team/default"}
        assert log.event_count() == 1
        with pytest.raises(log.SeatAccessError) as write:
            log.insert_event({"actor": "bob", "action": "note", "summary": "no", "namespace": "team/default"})
        assert write.value.status == 403
    with pytest.raises(log.SeatAccessError) as missing:
        log.query_events({"since": ["all"], "limit": ["10"]})
    assert missing.value.status == 401
