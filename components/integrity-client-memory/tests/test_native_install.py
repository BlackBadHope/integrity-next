"""Provider-free Native configuration and real-entrypoint integration checks.

Fixture bindings are never enrolled or treated as Native acceptance evidence.
No vendor binary/model, upstream server, active config or production data is used.
"""
import json
import os
from pathlib import Path
import subprocess
import sqlite3
import sys

import pytest

from integrity_client_memory import native_install as install
from integrity_client_memory import native_runtime as runtime


def bindings(tmp_path, vendor):
    result = {"seed_namespace": "fixture-seed", "namespace_fingerprint": "sha256:" + "a" * 64,
              "architecture_checkpoint_id": "checkpoint:fixture-architecture"}
    if vendor == "claude":
        session = "11111111-1111-4111-8111-111111111111"
        for name in (session + ".jsonl", "host_node.py", "claude_owner.py", "fixture-claude.exe", "owner-mcp.json"):
            (tmp_path / name).write_text("{}\n", encoding="utf-8")
        install.write_json(tmp_path / "owner.json", {"schema": "integrity-claude-owner/v1",
            "binary": str(tmp_path / "fixture-claude.exe"), "binary_sha256": install.digest((tmp_path / "fixture-claude.exe").read_bytes()),
            "workspace": str(tmp_path), "state_dir": str(tmp_path), "mcp_config": str(tmp_path / "owner-mcp.json"),
            "mcp_sha256": install.digest((tmp_path / "owner-mcp.json").read_bytes()), "permission_profile": "full_access"})
        with sqlite3.connect(tmp_path / "ledger.sqlite3") as db:
            db.execute("CREATE TABLE tasks(id TEXT PRIMARY KEY,session_id TEXT)")
            db.execute("INSERT INTO tasks VALUES (?,?)", (session, session))
        result.update(claude_session_id=session, claude_owner_file=str(tmp_path / "owner.json"),
                      claude_ledger=str(tmp_path / "ledger.sqlite3"), claude_transcript=str(tmp_path / (session + ".jsonl")),
                      claude_publisher_script=str(tmp_path / "host_node.py"), claude_publisher_python=sys.executable,
                      claude_project_root=str(tmp_path))
    return result


@pytest.fixture(params=install.VENDORS)
def profile(request, tmp_path):
    vendor = request.param
    if os.name != "nt" and vendor != "antigravity":
        pytest.skip("Native ownership profiles explicitly Windows-only")
    owner = bindings(tmp_path, vendor)
    root = tmp_path / "generated"
    install.build(vendor, {"command": sys.executable, "args": ["-c", "raise RuntimeError('UPSTREAM MUST NOT START')"]}, owner, root)
    return root / "profile.json"


def test_complete_profile_is_source_bound_and_not_live(profile):
    value, root = runtime.verify(profile)
    assert value["live_acceptance"] == "NOT_RUN"
    component = install.read_json(root / "component.json")
    assert install.configuration_keys((root / "runtime").glob("*.py")) <= set(component["values"])
    assert all(isinstance(x, str) and x.strip() for x in component["values"].values())
    assert not (root / "state").exists()
    if value["vendor"] != "antigravity":
        assert "integrity_project_scope.py" in value["files"]


def test_real_entrypoint_imports_and_parsers_load_without_upstream(profile):
    assert runtime.main(["--profile", str(profile), "probe"]) == 0


def test_wire_probe_refuses_a_pinned_but_incompatible_hook_broker_pair(profile):
    import ast
    value, root = runtime.verify(profile)
    if value["vendor"] == "antigravity":
        pytest.skip("Antigravity hook uses its conversation broker rather than McpClient")
    hook = root / "runtime" / value["hook"]
    text = hook.read_text(encoding="utf-8")
    assignment = next(n for n in ast.parse(text).body if isinstance(n, ast.Assign)
                      and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)
                      and n.targets[0].id == "BROKER_SERVER_VERSION")
    lines = text.splitlines(keepends=True)
    lines[assignment.lineno - 1:assignment.end_lineno] = ["BROKER_SERVER_VERSION = '0.0.0'\n"]
    hook.write_text("".join(lines), encoding="utf-8", newline="\n")
    value["files"][value["hook"]] = install.digest(hook.read_bytes())
    install.write_json(profile, value)
    runtime.verify(profile)
    assert runtime.main(["--profile", str(profile), "probe"]) == 2


def test_wire_probe_refuses_missing_claude_sibling_catalog(profile):
    value, root = runtime.verify(profile)
    if value["vendor"] != "claude":
        pytest.skip("Claude owning hook resolves the sibling catalogue")
    catalog = root / "runtime/integrity-client-tools.json"
    catalog.rename(catalog.with_suffix(".fixture-disabled"))
    value["auxiliary_files"] = {}
    install.write_json(profile, value)
    runtime.verify(profile)
    assert runtime.main(["--profile", str(profile), "probe"]) == 2


def test_session_start_runs_real_hook_without_model_or_upstream(profile):
    value, root = runtime.verify(profile)
    if value["vendor"] == "antigravity":
        payload = {"conversationId": "11111111-1111-4111-8111-111111111111"}
    else:
        payload = {"session_id": "11111111-1111-4111-8111-111111111111", "cwd": str(root)}
    result, code = runtime.hook(value, root, "SessionStart", json.dumps(payload).encode())
    assert code == 0
    assert "PENDING" in json.dumps(result) or "current-turn admission required" in json.dumps(result)


def test_source_drift_is_refused_before_process_start(profile, monkeypatch):
    value, root = runtime.verify(profile)
    (root / "runtime" / value["hook"]).write_text("raise AssertionError('changed')")
    monkeypatch.setattr(runtime.subprocess, "run", lambda *a, **k: pytest.fail("process started"))
    with pytest.raises(ValueError, match="source pin changed"):
        runtime.verify(profile)


def test_hook_lifecycle_transport_drift_is_refused(profile):
    value, root = runtime.verify(profile)
    transport = install.read_json(root / "transport.json")
    assert "--tools-contract" in transport["transport"]["args"]
    transport["transport"]["command"] = "foreign-command"
    install.write_json(root / "transport.json", transport)
    with pytest.raises(ValueError, match="configuration pin changed"):
        runtime.verify(profile)


def test_malformed_profile_is_a_controlled_refusal(tmp_path):
    p = tmp_path / "profile.json"
    p.write_text("[]")
    with pytest.raises(ValueError, match="identity/platform mismatch"):
        runtime.verify(p)


def test_existing_output_is_never_overwritten(profile):
    value, root = runtime.verify(profile)
    before = profile.read_bytes()
    with pytest.raises(ValueError, match="new directory"):
        install.build("antigravity", {"command": sys.executable}, bindings(root.parent, "antigravity"), root)
    assert profile.read_bytes() == before


def test_reject_read_only_catalog_before_writing(tmp_path):
    tools = [{"name": "integrity_seed_snapshot", "description": "fixture", "inputSchema": {}, "annotations": {}}]
    with pytest.raises(ValueError, match="lifecycle"):
        install.build("antigravity", {"command": sys.executable}, bindings(tmp_path, "antigravity"), tmp_path / "refused", tools)
    assert not (tmp_path / "refused").exists()


def test_foreign_claude_transcript_rejected_before_output(tmp_path):
    value = bindings(tmp_path, "claude")
    value["claude_session_id"] = "22222222-2222-4222-8222-222222222222"
    with pytest.raises(ValueError, match="transcript/session mismatch"):
        install.required_bindings("claude", value)


def test_foreign_claude_owner_ledger_is_refused(tmp_path):
    value = bindings(tmp_path, "claude")
    with sqlite3.connect(value["claude_ledger"]) as db:
        db.execute("DELETE FROM tasks")
    with pytest.raises(ValueError, match="not enrolled"):
        install.required_bindings("claude", value)


def test_claude_owner_mcp_drift_is_refused(tmp_path):
    value = bindings(tmp_path, "claude")
    (tmp_path / "owner-mcp.json").write_text("{\"changed\":true}")
    with pytest.raises(ValueError, match="MCP pin changed"):
        install.required_bindings("claude", value)


def test_merge_does_not_erase_denial():
    blocked = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "additionalContext": "first"}}
    later = {"hookSpecificOutput": {"permissionDecision": "allow", "additionalContext": "second"}}
    merged = runtime.merge_output(blocked, later)
    assert runtime.blocked(merged)
    assert merged["hookSpecificOutput"]["additionalContext"] == "first\nsecond"


def test_other_integrity_product_is_a_separate_action_boundary():
    assert runtime.memory_call(b'{"tool_name":"mcp__integrity_guardian__apply"}') is False
    assert runtime.memory_call(b'{"tool_name":"mcp__integrity_native__integrity_append_event"}') is True
    assert runtime.memory_call(b'{"tool_name":"integrity_append_event"}') is True


@pytest.mark.skipif(os.name != "nt", reason="observed Windows cmd launcher")
def test_antigravity_refuses_known_broken_quoted_path_before_output(tmp_path):
    output = tmp_path / "profile with spaces"
    with pytest.raises(ValueError, match="space-free"):
        install.build("antigravity", {"command": sys.executable}, bindings(tmp_path, "antigravity"), output)
    assert not output.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows hook shell")
def test_shell_metacharacters_in_hook_paths_are_refused(tmp_path):
    output = tmp_path / "profile&command"
    with pytest.raises(ValueError, match="metacharacters"):
        install.build("codex", {"command": sys.executable}, bindings(tmp_path, "codex"), output)
    assert not output.exists()


def test_antigravity_uses_observed_plugin_shape(profile):
    value, root = runtime.verify(profile)
    if value["vendor"] != "antigravity":
        pytest.skip("Antigravity-only schema")
    hooks = install.read_json(root / "antigravity-plugin/hooks.json")["integrity-native"]
    assert set(hooks) == set(install.AG_EVENTS)
    assert hooks["PreToolUse"][0]["matcher"] == "^call_mcp_tool$"
    assert hooks["PreInvocation"][0]["type"] == "command"


def test_invalid_pretool_input_cannot_allow_effect(profile, monkeypatch, capsys):
    monkeypatch.setattr(runtime.sys, "stdin", type("Input", (), {"buffer": type("Buffer", (), {"read": lambda _self, _n: b"[]"})()})())
    assert runtime.main(["--profile", str(profile), "hook", "PreToolUse"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert runtime.blocked(result)


def test_memory_route_fault_does_not_veto_an_unrelated_authorized_tool(profile, monkeypatch, capsys):
    value, root = runtime.verify(profile)
    (root / "runtime" / value["hook"]).write_text("changed")
    payload = {"toolCall": {"name": "run_command"}} if value["vendor"] == "antigravity" else {"tool_name": "Bash"}
    raw = json.dumps(payload).encode()
    monkeypatch.setattr(runtime.sys, "stdin", type("Input", (), {"buffer": type("Buffer", (), {"read": lambda _self, _n: raw})()})())
    assert runtime.main(["--profile", str(profile), "hook", "PreToolUse"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert not runtime.blocked(result)
    assert "does not revoke" in json.dumps(result)


def test_memory_route_fault_still_refuses_native_mcp_calls(profile, monkeypatch, capsys):
    value, root = runtime.verify(profile)
    (root / "runtime" / value["hook"]).write_text("changed")
    payload = {"toolCall": {"name": "call_mcp_tool", "args": {"ServerName": "integrity_native"}}} if value["vendor"] == "antigravity" else {"tool_name": "mcp__integrity_native__integrity_append_event"}
    raw = json.dumps(payload).encode()
    monkeypatch.setattr(runtime.sys, "stdin", type("Input", (), {"buffer": type("Buffer", (), {"read": lambda _self, _n: raw})()})())
    assert runtime.main(["--profile", str(profile), "hook", "PreToolUse"]) == 0
    assert runtime.blocked(json.loads(capsys.readouterr().out))
