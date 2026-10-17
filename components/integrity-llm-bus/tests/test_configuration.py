import importlib
import json
import pytest

config = importlib.import_module("integrity_llm_bus.configuration")
launcher = importlib.import_module("integrity_llm_bus.launcher")

def test_missing_configuration_is_closed(monkeypatch):
    monkeypatch.delenv(config.ENVIRONMENT, raising=False)
    with pytest.raises(config.ConfigurationError, match="unconfigured"):
        config.read_config()

def test_disabled_and_wrong_contract_are_rejected(tmp_path):
    p = tmp_path / "config.json"
    d = {"schema": config.SCHEMA, "component": config.COMPONENT, "configured": False,
          "guardian_version": "6.1.0", "memory_api_version": "2.11.0", "values": {}}
    p.write_text(json.dumps(d))
    with pytest.raises(config.ConfigurationError): config.read_config(p)
    d.update(configured=True, memory_api_version="2.10.0")
    p.write_text(json.dumps(d))
    with pytest.raises(config.ConfigurationError, match="expected Guardian"): config.read_config(p)

def test_preflight_does_not_start_process_or_connect(tmp_path, monkeypatch):
    p = tmp_path / "config.json"
    p.write_text(json.dumps({"schema": config.SCHEMA, "component": config.COMPONENT,
        "configured": True, "guardian_version": "6.1.0", "memory_api_version": "2.11.0", "values": {}}))
    monkeypatch.setattr(launcher.subprocess, "call", lambda *a, **k: pytest.fail("process started"))
    assert launcher.main(["--config", str(p), "--preflight"]) == 0

def test_catalog_stays_inside_distribution():
    for entry in launcher.resource_catalog().values():
        p = (launcher.HERE / entry["path"]).resolve()
        assert p.is_file() and p.is_relative_to(launcher.HERE)
