"""Configured ownership is exact; UID 1000 is not a universal identity."""
import importlib.util
import json
from pathlib import Path
import pytest


def native_factory(tmp_path, monkeypatch):
    component = Path(__file__).resolve().parents[1]
    template = json.loads((component / "configuration.example.json").read_text())
    kinds = json.loads((component / "CONFIGURATION-VALUES.json").read_text())
    template.update(configured=True)
    template["values"] = {k: str(tmp_path / k) if v["kind"] == "path" else "unit-test-binding"
                          for k, v in kinds.items()}
    template["values"].update(native_owner_uid="2001", native_home_mode="750")
    config = tmp_path / "configuration.json"
    config.write_text(json.dumps(template))
    monkeypatch.setenv("INTEGRITY_CLIENT_MEMORY_CONFIG", str(config))
    path = component / "src/integrity_client_memory/resources/linux/linux_runtime_factory.py"
    spec = importlib.util.spec_from_file_location("public_native_owner_factory_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_non_1000_owner_is_accepted_only_as_exact_caller_and_peer(tmp_path, monkeypatch):
    module = native_factory(tmp_path, monkeypatch)
    assert module._owner_uid() == 2001
    module._verify_peer_uid(2001, 2001)
    with pytest.raises(ValueError, match="linux_owner_peer_uid_invalid"):
        module._verify_peer_uid(1000, 2001)
    with pytest.raises(ValueError, match="linux_owner_peer_uid_invalid"):
        module._verify_peer_uid(2001, 2002)


def test_runbook_catalogues_are_empty_in_both_broker_families():
    import ast
    component = Path(__file__).resolve().parents[1]
    for family in ("windows", "linux"):
        source = component / "src/integrity_client_memory/resources" / family / "integrity-client-turn-broker.py"
        tree = ast.parse(source.read_text())
        assignment = next(n for n in tree.body if isinstance(n, ast.Assign)
                          and any(isinstance(t, ast.Name) and t.id == "_LOCAL_ROUTE_CATALOG"
                                  for t in n.targets))
        catalog = ast.literal_eval(assignment.value)
        assert catalog["paths"] == [] and catalog["production_authority"] is False
