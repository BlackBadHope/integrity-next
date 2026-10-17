"""Real synthetic Action Log database → public Guardian validator and HTTP client."""
import importlib.util
import json
from pathlib import Path
import sys
import threading


def test_generated_bootstrap_and_mind_are_admitted_by_guardian(tmp_path, monkeypatch):
    component = Path(__file__).resolve().parents[1]
    source = component / "src/integrity_action_log/resources"
    template = json.loads((component / "configuration.example.json").read_text())
    template.update(configured=True)
    template["values"] = {key: str(tmp_path / key) for key in template["values"]}
    config = tmp_path / "config.json"
    config.write_text(json.dumps(template))
    monkeypatch.setenv("INTEGRITY_ACTION_LOG_CONFIG", str(config))
    monkeypatch.setenv("CODEX_LOG_DB", str(tmp_path / "synthetic.sqlite3"))
    monkeypatch.setenv("CODEX_LOG_DATA_DIR", str(tmp_path / "data"))
    token = "public-synthetic-test-token-" * 3
    monkeypatch.setenv("CODEX_LOG_TOKEN", token)
    monkeypatch.syspath_prepend(str(source))
    spec = importlib.util.spec_from_file_location("public_action_log_interop_test", source / "codex_action_log.py")
    log = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, log)
    spec.loader.exec_module(log)
    log.ensure_db()
    event = log.insert_event({"actor": "unit-test", "action": "agent_change_complete",
                             "summary": "Synthetic transport acceptance event",
                             "details": {}, "tags": ["test"],
                             "event_uid": "client:public-transport-test"})
    cursor = event["id"]
    response = log.build_mind({"q": ["synthetic transport"], "snapshot_event_id": [str(cursor)]})
    from integrity_guardian.mind_admission import verify_mind_companion
    assert verify_mind_companion(response, snapshot_event_id=cursor,
                                 snapshot_event_count=1)["ok"] is True
    bootstrap = log.build_bootstrap({"q": ["synthetic transport"]})
    assert bootstrap["snapshot"]["protocol"] == "integrity.action-log.bootstrap-snapshot/v1"
    assert bootstrap["snapshot"]["event_cursor"] == cursor
    server = log.BoundedThreadingHTTPServer(("127.0.0.1", 0), log.Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        from integrity_guardian.memory_synapse_mcp import ActionLogClient
        client = ActionLogClient("http://127.0.0.1:" + str(server.server_address[1]),
                                 auth_token=token, timeout=2)
        actual_bootstrap = client.request("GET", "/api/bootstrap", query={"q": "synthetic transport"})
        assert actual_bootstrap["snapshot"] == bootstrap["snapshot"]
        client.bind_snapshot(cursor, 1)
        admitted = client.mind({"intent": "synthetic transport", "limit": 5})
        assert admitted["admission_receipt"]["snapshot_event_id"] == cursor
        assert admitted["mind"]["receipt"]["event_cursor"] == cursor
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
