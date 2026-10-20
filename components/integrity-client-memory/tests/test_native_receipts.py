"""Native and broker decode the same bounded compact receipt, before validation."""
import ast
import copy
import hashlib
import json
from pathlib import Path
import sys
import tomllib
import types

import pytest

from integrity_client_memory import native_receipts as receipts
from integrity_client_memory import native_runtime as runtime
from integrity_client_memory import broker_bundle


@pytest.fixture
def decoder(tmp_path):
    source = receipts.ROOT / "resources/windows/native/integrity-client-admission.py"
    original = source.read_text(encoding="utf-8")
    rendered, provenance = receipts.render_hook(original)
    tree = ast.parse(rendered)
    baseline = ast.parse(original)
    # Every existing validator/function except the document decoder is exact.
    before = {n.name: ast.dump(n) for n in baseline.body if isinstance(n, ast.FunctionDef)}
    after = {n.name: ast.dump(n) for n in tree.body if isinstance(n, ast.FunctionDef)}
    assert {k: v for k, v in before.items() if k != "find_document"} == {
        k: v for k, v in after.items() if k != "find_document"}
    module = types.ModuleType("native_receipt_fixture")
    class HookError(Exception):
        pass
    module.__dict__.update(hashlib=hashlib, json=json, Any=object, HookError=HookError)
    start = rendered.index("# BEGIN CANONICAL NATIVE COMPACT RECEIPTS")
    stop = rendered.index("# END CANONICAL NATIVE COMPACT RECEIPTS")
    exec(compile(rendered[start:stop], "fixture-compact", "exec"), module.__dict__)
    function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "find_document")
    exec(compile(ast.Module(body=[function], type_ignores=[]), "fixture-native-decoder", "exec"), module.__dict__)
    compact = module._native_compact_admission
    compact.default_root = lambda: tmp_path
    assert provenance["original_validators_changed"] is False
    return module, compact


def document(version):
    return {"protocol": "integrity-client-memory-mcp/v3/context-admission/" + version,
            "context_admission_id": "sha256:" + "a" * 64, "status": "ready",
            "production_authority": False, "home_record_count": 0, "canonical_writes": 0,
            "snapshot": {"snapshot_id": "sha256:" + "b" * 64}, "mind": {}}


def wrapped(compact, doc):
    result = {"content": [{"type": "text", "text": json.dumps(doc)}], "isError": False}
    ref = compact.store_file(compact.default_root(), compact.encode(result))
    return {"protocol": compact.PROTOCOL, "full_admission": ref,
            "admission": {"context_admission_id": doc["context_admission_id"],
                          "snapshot_id": doc["snapshot"]["snapshot_id"], "status": doc["status"]}}


@pytest.mark.parametrize("version", ["v1", "v2"])
def test_full_and_compact_return_identical_original_document(decoder, version):
    module, compact = decoder
    doc = document(version)
    predicate = lambda value: value.get("protocol") == doc["protocol"]
    full = {"content": [{"type": "text", "text": json.dumps(doc)}]}
    small = {"content": [{"type": "text", "text": json.dumps(wrapped(compact, doc))}]}
    assert module.find_document(full, predicate) == doc
    assert module.find_document(small, predicate) == doc


@pytest.mark.parametrize("bad", ["path", "size", "digest", "admission", "snapshot", "status", "missing"])
def test_compact_tamper_is_refused_before_original_validators(decoder, bad):
    module, compact = decoder
    value = wrapped(compact, document("v2"))
    if bad == "path":
        value["full_admission"]["path"] = str(compact.default_root() / "another.json")
    elif bad == "size":
        value["full_admission"]["bytes"] += 1
    elif bad == "digest":
        Path(value["full_admission"]["path"]).write_bytes(b"{}")
    elif bad == "missing":
        del value["full_admission"]
    else:
        key = {"admission": "context_admission_id", "snapshot": "snapshot_id", "status": "status"}[bad]
        value["admission"][key] = "wrong"
    with pytest.raises(module.HookError, match="compact_artifact_"):
        module.find_document(value, lambda item: "snapshot" in item)


def test_decoder_anchor_drift_is_refused():
    with pytest.raises(ValueError, match="anchor changed"):
        receipts.render_hook("def unrelated():\n    return None\n")


def test_native_execution_proof_is_source_bound_and_does_not_assert_ownership(tmp_path):
    root = tmp_path / "profile"
    hook = root / "runtime/hook.py"
    hook.parent.mkdir(parents=True)
    hook.write_text("HOOK_VERSION = '1.8.0'\n", encoding="utf-8")
    (root / "profile.json").write_text("{}", encoding="utf-8")
    profile = {"vendor": "codex", "hook": hook.name,
               "files": {hook.name: hashlib.sha256(hook.read_bytes()).hexdigest()},
               "python": "fixture-python", "python_sha256": "a" * 64}
    proof = runtime.execution_receipt(profile, root, "PostToolUse")
    assert proof["hook_version"] == "1.8.0"
    assert proof["hook_sha256"] == hashlib.sha256(hook.read_bytes()).hexdigest()
    assert proof["profile_sha256"] == hashlib.sha256((root / "profile.json").read_bytes()).hexdigest()
    assert proof["native_ownership_verified"] is False
    assert proof["external_action_authority"] is False
    assert "prompt" not in proof and "state" not in proof


def test_execution_proof_only_for_native_context_entrypoints():
    assert runtime.receipt_context({}, "SessionStart")
    assert runtime.receipt_context({"tool_name": "integrity_context_admission_current_turn"}, "PostToolUse")
    assert not runtime.receipt_context({"tool_name": "exec_command"}, "PostToolUse")
    assert not runtime.receipt_context({}, "PreToolUse")


@pytest.mark.skipif(sys.platform != "win32", reason="Windows Native execution")
def test_complete_compiled_profile_runs_pinned_native_without_upstream(tmp_path):
    root = tmp_path / "native"
    profile = broker_bundle.build_bundle(root,
        bindings={"seed_namespace": "fixture-seed", "namespace_fingerprint": "sha256:" + "a" * 64,
                  "architecture_checkpoint_id": "checkpoint:fixture", "server_version": "2.10.0"},
        upstream={"command": sys.executable, "args": ["-c", "raise AssertionError('no upstream')"]},
        tools=json.loads((receipts.ROOT / "data/tools-current.json").read_text())["result"]["tools"])
    checked, actual_root = runtime.verify(root / "profile.json")
    assert checked["files"] == profile["files"]
    hook_source = (root / "runtime" / profile["hook"]).read_text(encoding="utf-8")
    assert "BEGIN CANONICAL NATIVE COMPACT RECEIPTS" in hook_source
    payload = {"session_id": "66666666-6666-4666-8666-666666666666",
               "turn_id": "77777777-7777-4777-8777-777777777777", "cwd": str(root)}
    result, code = runtime.hook(checked, actual_root, "SessionStart", json.dumps(payload).encode())
    assert code == 0
    assert "INTEGRITY NATIVE EXECUTION " in result["systemMessage"]
    proof = json.loads(result["systemMessage"].split("INTEGRITY NATIVE EXECUTION ")[-1])
    assert proof["hook_sha256"] == checked["files"][checked["hook"]]
    assert proof["profile_sha256"] == hashlib.sha256((root / "profile.json").read_bytes()).hexdigest()
    assert proof["configuration_verified"] is True


@pytest.fixture
def contract_profile(tmp_path):
    root = tmp_path / "contract-native"
    profile = broker_bundle.build_bundle(root,
        bindings={"seed_namespace": "fixture-seed", "namespace_fingerprint": "sha256:" + "a" * 64,
                  "architecture_checkpoint_id": "checkpoint:fixture", "server_version": "2.10.0"},
        upstream={"command": sys.executable, "args": ["-c", "raise AssertionError('no upstream')"]},
        tools=json.loads((receipts.ROOT / "data/tools-current.json").read_text())["result"]["tools"])
    checked, actual_root = runtime.verify(root / "profile.json")
    return checked, actual_root


def test_tools_contract_is_visible_in_outer_generated_mcp_command(contract_profile):
    profile, root = contract_profile
    config = tomllib.loads((root / "codex-workspace/.codex/config.toml").read_text())
    argv = config["mcp_servers"][profile.get("mcp_server_name", "integrity_native")]["args"]
    assert argv.count("--tools-contract") == 1
    assert argv[argv.index("--tools-contract") + 1] == str(root / "integrity-client-tools.json")
    runtime.validate_tools_contract(profile, root, argv[argv.index("--tools-contract") + 1])


def test_tools_contract_wrong_selection_is_rejected_before_broker_start(contract_profile, monkeypatch):
    profile, root = contract_profile
    foreign = root / "same-bytes-wrong-path.json"
    foreign.write_bytes((root / "integrity-client-tools.json").read_bytes())
    def no_launch(*args, **kwargs):
        raise AssertionError("broker must not launch")
    monkeypatch.setattr(runtime.subprocess, "call", no_launch)
    assert runtime.main(["--profile", str(root / "profile.json"), "--tools-contract", str(foreign), "mcp"]) == 2


def test_tools_contract_matching_selection_keeps_pinned_broker_argv(contract_profile, monkeypatch):
    profile, root = contract_profile
    calls = []
    monkeypatch.setattr(runtime.subprocess, "call", lambda argv, **kwargs: calls.append(argv) or 0)
    assert runtime.main(["--profile", str(root / "profile.json"), "--tools-contract",
                         str(root / "integrity-client-tools.json"), "mcp"]) == 0
    assert calls == [runtime.broker_command(profile, root)]


def test_tools_contract_pin_drift_is_rejected_before_broker_start(contract_profile, monkeypatch):
    profile, root = contract_profile
    monkeypatch.setattr(runtime, "verify", lambda path: (profile, root))
    (root / "integrity-client-tools.json").write_text("[]", encoding="utf-8")
    def no_launch(*args, **kwargs):
        raise AssertionError("broker must not launch")
    monkeypatch.setattr(runtime.subprocess, "call", no_launch)
    assert runtime.main(["--profile", str(root / "profile.json"), "--tools-contract",
                         str(root / "integrity-client-tools.json"), "mcp"]) == 2
