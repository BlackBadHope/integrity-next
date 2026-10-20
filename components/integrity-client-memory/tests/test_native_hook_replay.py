"""Bounded replay of observed native payload shapes; no vendor/model calls."""
import importlib.util
import json
import os
from pathlib import Path
import sys

import pytest

from integrity_client_memory import native_install as install
from integrity_client_memory import native_runtime as runtime


@pytest.fixture
def ag(tmp_path):
    root = tmp_path / "profile"
    install.build("antigravity", {"command": sys.executable, "args": ["-c", "raise AssertionError('no upstream')"]},
                  {"seed_namespace": "fixture-seed", "namespace_fingerprint": "sha256:" + "a" * 64,
                   "architecture_checkpoint_id": "checkpoint:fixture"}, root)
    value, _ = runtime.verify(root / "profile.json")
    return value, root


def run(ag, event, payload):
    value, root = ag
    result, code = runtime.hook(value, root, event, json.dumps(payload).encode())
    assert code == 0
    return result


def owner_payload(root, conversation, model="gemini-2.5-flash"):
    artifact = root / "brain" / conversation
    path = artifact / ".system_generated/logs/transcript_full.jsonl"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"step_index": 0, "type": "USER_INPUT", "source": "USER_EXPLICIT", "content": "Fixture owner question"}) + "\n", encoding="utf-8")
    return {"conversationId": conversation, "artifactDirectoryPath": str(artifact), "transcriptPath": str(path),
            "modelName": model, "invocationNum": 0, "initialNumSteps": 1}


def call(payload, name, arguments):
    return {**payload, "toolCall": {"name": "call_mcp_tool", "args": {
        "ServerName": "integrity_native", "ToolName": name, "Arguments": arguments}}}


def state(root, conversation):
    return json.loads((root / "state/admission-state" / (conversation + ".json")).read_text())


def test_observed_antigravity_boundary_isolates_conversations_and_models(ag):
    _, root = ag
    a = "11111111-1111-4111-8111-111111111111"
    b = "22222222-2222-4222-8222-222222222222"
    first = owner_payload(root, a)
    second = owner_payload(root, b, "claude-sonnet-4-5")
    assert "turn_ref=" in json.dumps(run(ag, "PreInvocation", first))
    run(ag, "PreInvocation", second)
    sa, sb = state(root, a), state(root, b)
    assert sa["turn_ref"] != sb["turn_ref"]
    assert sa["vendor"] == "Google" and sb["vendor"] == "Anthropic"
    denied = run(ag, "PreToolUse", call(first, "integrity_append_event", {"context_admission_id": "sha256:" + "a" * 64}))
    assert denied["decision"] == "deny"
    refused_switch = run(ag, "PreToolUse", call({**first, "modelName": "claude-opus-4-1"}, "integrity_seed_snapshot", {}))
    assert refused_switch["decision"] == "deny"
    assert state(root, b) == sb


def test_observed_antigravity_ref_is_one_use_and_unknown_model_fails_closed(ag):
    _, root = ag
    conversation = "33333333-3333-4333-8333-333333333333"
    payload = owner_payload(root, conversation)
    run(ag, "PreInvocation", payload)
    own = state(root, conversation)
    tool = call(payload, "integrity_context_admission_current_turn", {"turn_ref": own["turn_ref"]})
    allowed = run(ag, "PreToolUse", tool)
    assert allowed["decision"] == "allow"
    assert len(allowed["overwrite"]["Arguments"]["_antigravity_route"]) == 64
    assert run(ag, "PreToolUse", tool)["decision"] == "deny"
    unknown = owner_payload(root, "44444444-4444-4444-8444-444444444444", "unverified-fixture-model")
    assert "DEGRADED" in json.dumps(run(ag, "PreInvocation", unknown))
    assert not (root / "state/admission-state/44444444-4444-4444-8444-444444444444.json").exists()


def test_stop_does_not_invent_no_event_for_unadmitted_turn(ag):
    _, root = ag
    conversation = "55555555-5555-4555-8555-555555555555"
    payload = owner_payload(root, conversation)
    run(ag, "PreInvocation", payload)
    run(ag, "Stop", {**payload, "terminationReason": "NO_TOOL_CALL"})
    result = state(root, conversation)
    assert result["stopped"] is True
    assert result["coverage_status"] == "expired-provisional"
    assert not result.get("turn_memory_closed")


@pytest.mark.skipif(os.name != "nt", reason="Windows Native hooks")
def test_codex_missing_native_turn_is_refused_without_random_identity(tmp_path):
    root = tmp_path / "codex"
    install.build("codex", {"command": sys.executable},
                  {"seed_namespace": "fixture", "namespace_fingerprint": "sha256:" + "a" * 64,
                   "architecture_checkpoint_id": "checkpoint:fixture"}, root)
    value, _ = runtime.verify(root / "profile.json")
    result, code = runtime.hook(value, root, "UserPromptSubmit", json.dumps({
        "session_id": "66666666-6666-4666-8666-666666666666", "prompt": "Fixture owner", "cwd": str(root)}).encode())
    assert code != 0 or runtime.blocked(result)
    assert not list((root / "turn-envelopes").glob("*.json"))
