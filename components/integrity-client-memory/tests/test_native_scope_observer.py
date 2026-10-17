import importlib.util
from pathlib import Path
import sys
import uuid

import pytest
from integrity_client_memory import configuration


@pytest.mark.parametrize("route", ["complete", "legacy"])
def test_disabled_rollout_observer_does_not_require_diagnostic_bindings(tmp_path, monkeypatch, route):
    def own_binding(name):
        if name in {"binding_db8055e0e030", "path_ba69d17f10cf"}:
            raise configuration.ConfigurationError("diagnostic binding is deliberately unconfigured")
        if name == "path_92fad53f3db0":
            return str(Path(sys.executable).resolve())
        if name == "path_8a9e4b9f5f66":
            return str(Path(sys.prefix).resolve())
        if name.startswith("pin_"):
            return "0" * 64
        if name.startswith("path_"):
            return str(tmp_path / name)
        raise AssertionError("unexpected binding read: " + name)
    monkeypatch.setattr(configuration, "value", own_binding)
    source = Path(__file__).resolve().parents[1] / "src/integrity_client_memory/resources/linux/native/integrity_scope_synapse.py"
    spec = importlib.util.spec_from_file_location("public_native_scope_observer_test", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.RUNTIME_CANARY is False
    subject = str(uuid.uuid4())
    monkeypatch.delenv("CODEX_THREAD_ID", raising=False)
    store = module.Store(tmp_path / "scope-state")
    if route == "legacy":
        state = module.new_state(subject)
        state["instructions"] = ["Synthetic owner scope used only by this temporary test."]
        with store.locked(subject):
            store.save(subject, state)
    result = module.handle("PreToolUse", {"session_id": subject, "turn_id": str(uuid.uuid4()),
        "tool_name": "Read", "tool_input": {"file_path": "synthetic.txt"}}, store)
    assert result is None
