"""A missing current selector never revives a different topic or Core route."""
import ast
import copy
import hashlib
import json
from types import ModuleType

import pytest

from integrity_client_memory import broker_bundle, core_delivery

SNAPSHOT = "sha256:" + "a" * 64
CATALOG = "sha256:" + "b" * 64
EXPERIMENT = {"parent_thread_id": "", "parent_turn_id": "",
              "control_agent_paths": [], "expires_epoch": 0}
OPAQUE = {"kind": "authenticated-native-delegation-navigation",
          "navigation_text_available": False,
          "navigation_text_reason": "Native-originating-message-encrypted"}


def frozen_module(marker):
    tree = ast.parse(broker_bundle.BROKER.read_text(encoding="utf-8"))
    sources = [node.args[0].value for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        and node.func.id == "compile" and len(node.args) == 3
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
        and isinstance(node.args[1], ast.Constant)
        and node.args[1].value == marker]
    assert len(sources) == 1
    module = ModuleType("fixture_navigation")
    exec(compile(sources[0], marker, "exec"), module.__dict__)
    return module


class Upstream:
    def __init__(self):
        self.calls = []

    def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        value = {"result": "REMAINING", "path_catalog_digest": CATALOG,
                 "receipt_id": "fixture:ttt",
                 "snapshot_binding": {"snapshot_id": SNAPSHOT,
                     "ttt_receipt_id": "fixture:ttt", "receipt_id": "fixture:binding"},
                 "remaining_path": [{"hop_id": str(n)} for n in range(6)]}
        return {"content": [{"type": "text", "text": json.dumps(value)}]}


@pytest.fixture
def navigation(tmp_path, monkeypatch):
    routes = frozen_module("<integrity-local-routes>")
    catalog = {"paths": [{"path_id": "bdcom-fixture", "target": {"olt": "192.0.2.90"},
                           "evidence": [], "hops": [{"hop_id": "identify-switch-ip"}]}]}
    navigator = routes.Navigator(catalog, tmp_path / "state", tmp_path)
    scope = {"hashes": {"thread_id": "c" * 64}, "project_scope_sha256": "sha256:" + "d" * 64,
             "prompt_sha256": "e" * 64}
    monkeypatch.setattr(core_delivery, "journal", lambda *a, **kw: None)
    return navigator, scope


def test_opaque_integrity_task_cannot_revive_retained_bdcom(navigation):
    navigator, scope = navigation
    assert navigator.admit("BDCOM 192.0.2.90 GPON", scope, SNAPSHOT)["status"] == "navigation-ready"
    # Actual project() output for an authenticated encrypted Native carrier is
    # empty; its parent history is never substituted for current task text.
    local = navigator.admit("", scope, SNAPSHOT)
    local["snapshot_id"] = SNAPSHOT
    upstream = Upstream()
    before = copy.deepcopy((local, OPAQUE))
    result = core_delivery.delivery(upstream, local, OPAQUE, EXPERIMENT, CATALOG)
    assert (local, OPAQUE) == before
    assert result["status"] == "task-context-unavailable"
    assert result["task_context"]["retained_context_used"] is False
    assert "task_query" not in result
    assert not any(word in json.dumps(result) for word in ("BDCOM", "GPON", "ONU", "192.0.2.90"))
    assert upstream.calls == [] and navigator.selected is None
    assert json.loads(next(navigator.state_root.glob("navigation-*.json")).read_text())["entities"] == {}
    assert result["external_action_authority"] is False


def test_unrelated_plaintext_integrity_task_has_no_network_query(navigation):
    navigator, scope = navigation
    local = navigator.admit("Integrity same-session recovery Native acceptance", scope, SNAPSHOT)
    upstream = Upstream()
    result = core_delivery.delivery(upstream, local, {"kind": "own-plaintext"}, EXPERIMENT, CATALOG)
    assert result["status"] == "no-matching-task" and "task_query" not in result
    assert upstream.calls == []


def test_genuine_current_bdcom_request_keeps_verified_core_route(navigation):
    navigator, scope = navigation
    local = navigator.admit("BDCOM 192.0.2.90 GPON", scope, SNAPSHOT)
    local["snapshot_id"] = SNAPSHOT
    upstream = Upstream()
    result = core_delivery.delivery(upstream, local, {"kind": "own-plaintext"}, EXPERIMENT, CATALOG)
    assert result["status"] == "navigation-ready" and result["core_delivery"]["status"] == "delivered"
    assert len(upstream.calls) == 1 and len(result["hops"]) == 6
    assert result["external_action_authority"] is False


def test_explicit_current_snapshot_bound_query_remains_available(navigation):
    navigator, scope = navigation
    upstream = Upstream()
    binding = {"snapshot_id": SNAPSHOT, "context_admission_id": "sha256:" + "f" * 64}
    args = {"goal": "BDCOM 192.0.2.90 GPON", "snapshot_id": SNAPSHOT}
    result = core_delivery.query(navigator, upstream, args, binding, scope, OPAQUE, EXPERIMENT, CATALOG)
    value = json.loads(result["content"][0]["text"])["operational_context"]
    assert value["task_source"]["task_selector_source"] == "current-admitted-model-tool-query"
    assert value["external_action_authority"] is False and not result.get("isError")
    assert len(upstream.calls) == 1


def test_foreign_snapshot_never_selects_or_calls_core(navigation):
    navigator, scope = navigation
    upstream = Upstream()
    with pytest.raises(ValueError, match="snapshot mismatch"):
        core_delivery.query(navigator, upstream, {"goal": "BDCOM 192.0.2.90 GPON", "snapshot_id": "foreign"},
            {"snapshot_id": SNAPSHOT}, scope, OPAQUE, EXPERIMENT, CATALOG)
    assert upstream.calls == [] and navigator.selected is None


def test_ambiguous_current_bdcom_target_stays_fail_closed(navigation):
    navigator, scope = navigation
    navigator.catalog["paths"].append(copy.deepcopy(navigator.catalog["paths"][0]))
    local = navigator.admit("BDCOM 192.0.2.90 GPON", scope, SNAPSHOT)
    upstream = Upstream()
    result = core_delivery.delivery(upstream, local, {"kind": "own-plaintext"}, EXPERIMENT, CATALOG)
    assert result["status"] == "incomplete-or-ambiguous-target"
    assert upstream.calls == [] and "task_query" not in result


def test_compiled_navigation_uses_exact_canonical_source_and_pin():
    rendered, proof = broker_bundle.render_windows_broker()
    source = (broker_bundle.ROOT / "core_delivery.py").read_text(encoding="utf-8")
    pin = hashlib.sha256(source.encode()).hexdigest()
    assert proof["source_pins"]["core_delivery.py"] == pin
    tree = ast.parse(rendered.decode())
    frozen = next(node.value.value for node in tree.body if isinstance(node, ast.Assign)
                  and isinstance(node.targets[0], ast.Name)
                  and node.targets[0].id == "_automatic_Core_source")
    assert frozen == source and pin in rendered.decode()
    assert "Use only current task identifiers: BDCOM" not in rendered.decode()


def test_navigation_renderer_rejects_missing_or_ambiguous_anchor():
    text = broker_bundle.BROKER.read_text(encoding="utf-8")
    with pytest.raises(ValueError, match="navigation renderer anchors"):
        broker_bundle._render_navigation(text.replace("<managed-core_delivery.py>", "<foreign>"))
    tree = ast.parse(text)
    statement = next(ast.get_source_segment(text, node) for node in tree.body
                     if isinstance(node, ast.Expr) and "<managed-core_delivery.py>" in ast.get_source_segment(text, node))
    with pytest.raises(ValueError, match="navigation renderer anchors"):
        broker_bundle._render_navigation(text + "\n" + statement)
