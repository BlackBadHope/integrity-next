"""Source and routing checks only; Native/SSH acceptance is a separate gate."""
import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from copy import deepcopy
from types import SimpleNamespace

import pytest

from integrity_client_memory import broker_adapter, broker_bundle, native_install
from integrity_client_memory import operation_ledger, recovery_client


def test_renderer_is_deterministic_and_records_entire_shared_cohort():
    first, proof = broker_bundle.render_windows_broker()
    assert first == broker_bundle.render_windows_broker()[0]
    assert hashlib.sha256(first).hexdigest() == proof["rendered_sha256"]
    assert set(broker_bundle.MODULES) <= {
        Path(name).stem for name in proof["source_pins"]}
    for name in broker_bundle.MODULES:
        source = (broker_bundle.ROOT / (name + ".py")).read_text("utf-8-sig")
        tree = ast.parse(first.decode())
        frozen = next(n.value.value for n in tree.body if isinstance(n, ast.Assign)
                      and isinstance(n.targets[0], ast.Name)
                      and n.targets[0].id == "_" + name + "_source")
        assert frozen == source
    assert "pm/admission-selection" not in first.decode()


def test_renderer_refuses_anchor_drift(tmp_path, monkeypatch):
    source = tmp_path / "broker.py"
    source.write_text(broker_bundle.BROKER.read_text(encoding="utf-8").replace(broker_bundle.BEGIN, ""), encoding="utf-8", newline="\n")
    monkeypatch.setattr(broker_bundle, "BROKER", source)
    with pytest.raises(ValueError, match="anchors"):
        broker_bundle.render_windows_broker()


def test_codex_native_uses_resume_capable_canonical_envelope():
    files, _, _ = native_install.source_files("codex")
    envelope = next(p for p in files if p.name == "integrity_client_turn_envelope.py")
    assert envelope == native_install.RESOURCES / "windows/integrity_client_turn_envelope.py"
    names = {n.name for n in ast.parse(envelope.read_text()).body if isinstance(n, ast.FunctionDef)}
    assert {"load_context_resume", "save_context_resume", "_resume_read_state"} <= names


def test_other_platform_families_remain_distinct():
    expected = {
        "linux/integrity-client-turn-broker.py": "fcc79bb33d20c0ee62c9ff732bb4b01ebc5b56908bbed6a872f9423d460277fb",
        "windows-remote/integrity-client-turn-broker.py": "c5a15c2f91e5034dac17325ef77335678f2f27620b1fd1a12c26259a3dc578c5",
        "claude-native/integrity-client-turn-broker.py": "f1023580d3541ddc473534640f2674f2f55e4e41fe381ad9f504b3fa3a66bde2",
        "antigravity/turn_broker_core.py": "711378f5d574cad03a535059349d343c7551afb88f797bd268e9417ee3a194cf"}
    for name, digest in expected.items():
        assert hashlib.sha256((native_install.RESOURCES / name).read_bytes()).hexdigest() == digest


def test_state_environment_cannot_redirect_pinned_profile(tmp_path, monkeypatch):
    source = native_install.RESOURCES / "windows/integrity_client_turn_envelope.py"
    function = next(n for n in ast.parse(source.read_text()).body
                    if isinstance(n, ast.FunctionDef) and n.name == "_owning_state_root")
    module = ast.Module(body=[function], type_ignores=[])
    namespace = {"os": os, "Path": Path, "TurnEnvelopeError": ValueError,
                 "_integrity_value": lambda name: str(tmp_path)}
    exec(compile(module, "fixture-state-root", "exec"), namespace)
    read = namespace["_owning_state_root"]
    monkeypatch.delenv("INTEGRITY_CLIENT_STATE_ROOT", raising=False)
    assert read() == tmp_path
    monkeypatch.setenv("INTEGRITY_CLIENT_STATE_ROOT", str(tmp_path / "foreign"))
    with pytest.raises(ValueError, match="pinned profile"):
        read()
    monkeypatch.setenv("INTEGRITY_CLIENT_STATE_ROOT", str(tmp_path))
    assert read() == tmp_path


@pytest.mark.skipif(os.name != "nt", reason="Codex Native ownership adapter is Windows-only")
def test_private_bundle_uses_pinned_local_support_and_rejects_drift(tmp_path):
    from integrity_client_memory import native_runtime
    output = tmp_path / "private-profile"
    bindings = {"seed_namespace": "fixture-seed", "namespace_fingerprint": "sha256:" + "a" * 64,
                "architecture_checkpoint_id": "checkpoint:fixture"}
    profile = broker_bundle.build_bundle(output, bindings=bindings,
        upstream={"command": sys.executable, "args": ["-c", "raise RuntimeError('NO UPSTREAM')"]}, tools=None)
    native_runtime.verify(output / "profile.json")
    assert profile["files"][profile["broker"]] == broker_bundle.render_windows_broker()[1]["rendered_sha256"]
    assert set(profile["support_files"]) == {"integrity_client_memory/" + name for name in broker_bundle.SUPPORT}
    wire = subprocess.run([sys.executable, str(output / "run-native-profile.py"),
        "--profile", str(output / "profile.json"), "probe"],
        capture_output=True, timeout=30, env=native_runtime.environment(profile, output))
    assert wire.returncode == 0, wire.stderr.decode(errors="replace")
    support = output / "support/integrity_client_memory/broker_adapter.py"
    support.write_text("raise AssertionError('fixture drift')")
    with pytest.raises(ValueError, match="support source pin"):
        native_runtime.verify(output / "profile.json")


@pytest.fixture
def route():
    class Error(RuntimeError):
        def __init__(self, message, **kwargs):
            super().__init__(message)
            self.request_sent = kwargs.get("request_sent", False)
            self.retryable = kwargs.get("retryable", False)

    class Target:
        _same_session_capabilities = {
            "integrity/session-recovery": {"protocol": recovery_client.RECOVERY_PROTOCOL,
                "method": "integrity/session_recover"},
            "integrity/operation-status": {"protocol": recovery_client.STATUS_PROTOCOL,
                "method": "integrity/operation_status"}}

        def call_tool(self, name, arguments):
            calls.append((name, arguments))
            return {"ok": True}

    class Broker:
        def _check_own_lifecycle(self, name, arguments):
            return None

        def _ensure_delivered_context_resume(self):
            return None

        def _standalone_turn_memory_call(self, name, arguments):
            if name == "integrity_turn_memory_open":
                return response
            return self.upstream.call_tool(name, arguments)

        def _own_registration_content(self, current, binding):
            return current["turn_memory_registration_receipt"] == receipt

    arguments = {"machine_id": "machine:fixture", "thread_id": "fixture-thread",
                 "turn_id": "fixture-turn", "intent_id": "intent:fixture",
                 "prompt_sha256": "a" * 64}
    receipt = {"protocol": "integrity-guardian/turn-memory-registration/v1",
               "identity": {k: v for k, v in arguments.items() if k != "prompt_sha256"},
               "prompt_sha256": arguments["prompt_sha256"], "receipt_id": "sha256:" + "b" * 64}
    response = {"content": [{"type": "text", "text": json.dumps({"receipt": receipt,
        "session_recovery": {"protocol": recovery_client.RECOVERY_PROTOCOL,
            "available": False, "reason": "admission-not-retained",
            "registration_id": receipt["receipt_id"], "canonical_registration_unchanged": True}})}]}
    binding = {"admitted": True, "intent_id": arguments["intent_id"], "generation": 3,
               "prompt_sha256": arguments["prompt_sha256"], "turn_ref_digest": "digest:fixture",
               "context_admission_id": "sha256:" + "c" * 64,
               "hashes": {k: hashlib.sha256(arguments[k].encode()).hexdigest()
                          for k in ("machine_id", "thread_id", "turn_id")}}
    state = {"turn_memory_registration_receipt": receipt, "turn_memory_registration_id": receipt["receipt_id"],
             "turn_memory_status": "open",
             "turn_memory_generation": 3, "turn_memory_intent_id": arguments["intent_id"],
             "model_mcp_admission_status": "ready", "model_mcp_context_admission_id": binding["context_admission_id"],
             "prompt_sha256": arguments["prompt_sha256"], "turn_ref": "opaque:fixture", "turn_id": "fixture-turn"}
    class EnvelopeError(ValueError):
        pass
    envelope = SimpleNamespace(TurnEnvelopeError=EnvelopeError, load_context_resume=lambda: None,
        assert_nonretained_context_resume=lambda binding: None,
        _resume_identity=lambda: "fixture-thread", _resume_read_state=lambda identity: state,
        _native_owning_head=lambda identity: {"id": "fixture-turn", "status": "inProgress"},
        _ref_digest=lambda value: "digest:fixture", _machine_id=lambda: "machine:fixture")
    calls = []
    broker_adapter.install({"TurnBroker": Broker, "BrokerError": Error,
                            "turn_envelope": envelope}, recovery_client, operation_ledger)
    broker = Broker()
    broker.upstream, broker.bound, broker._own_turn_binding = Target(), True, binding
    broker._owning_hook_lifecycle_ref = None
    broker._standalone_turn_memory_call("integrity_turn_memory_open", arguments)
    return SimpleNamespace(broker=broker, state=state, binding=binding, envelope=envelope,
                           calls=calls, response=response, Error=Error)


def test_explicit_current_no_retention_uses_original_path(route):
    assert route.broker._same_session_mutation("integrity_append_event",
        {"context_admission_id": route.binding["context_admission_id"]}) == {"ok": True}
    route.broker._standalone_turn_memory_call("integrity_turn_memory_close",
        {"registration_id": route.state["turn_memory_registration_id"]})
    assert [name for name, _ in route.calls] == ["integrity_append_event", "integrity_turn_memory_close"]


@pytest.mark.parametrize("fault", ["missing-open", "foreign-head", "foreign-context", "reconnected",
                                   "existing-descriptor", "corrupt-descriptor", "foreign-machine", "terminal"])
@pytest.mark.parametrize("tool", ["integrity_append_event", "integrity_turn_memory_close"])
def test_invalid_proof_never_falls_back(route, fault, tool):
    if fault == "missing-open":
        route.broker._session_recovery_open = None
    elif fault == "foreign-head":
        route.envelope._native_owning_head = lambda identity: {"id": "foreign", "status": "inProgress"}
    elif fault == "foreign-context":
        route.state["model_mcp_context_admission_id"] = "foreign"
    elif fault == "reconnected":
        route.broker.upstream = type(route.broker.upstream)()
    elif fault == "existing-descriptor":
        def conflict(binding):
            raise route.envelope.TurnEnvelopeError("conflicting descriptor fixture")
        route.envelope.assert_nonretained_context_resume = conflict
    elif fault == "foreign-machine":
        route.envelope._machine_id = lambda: "machine:foreign"
    elif fault == "terminal":
        route.state["turn_memory_terminal_receipt_id"] = "sha256:" + "f" * 64
    else:
        def fail(binding):
            raise route.envelope.TurnEnvelopeError("corrupt fixture")
        route.envelope.assert_nonretained_context_resume = fail
    with pytest.raises(route.Error):
        if tool == "integrity_append_event":
            route.broker._same_session_mutation(tool,
                {"context_admission_id": route.binding["context_admission_id"]})
        else:
            route.broker._standalone_turn_memory_call(tool,
                {"registration_id": route.state["turn_memory_registration_id"]})
    assert route.calls == []


@pytest.mark.parametrize("marker", [None, {"available": False, "protocol": recovery_client.RECOVERY_PROTOCOL,
    "reason": "derived-binding-unavailable", "canonical_registration_unchanged": True}])
def test_missing_or_derived_failure_is_never_explicit_opt_out(route, marker):
    body = json.loads(route.response["content"][0]["text"])
    body["session_recovery"] = marker
    route.response["content"][0]["text"] = json.dumps(body)
    arguments = {**body["receipt"]["identity"], "prompt_sha256": body["receipt"]["prompt_sha256"]}
    route.broker._standalone_turn_memory_call("integrity_turn_memory_open", arguments)
    with pytest.raises(route.Error):
        route.broker._same_session_mutation("integrity_append_event",
            {"context_admission_id": route.binding["context_admission_id"]})
    assert route.calls == []


def test_lost_ordinary_response_keeps_original_uncertainty(route):
    error = route.Error("fixture lost response", request_sent=True)
    def fail(name, arguments):
        raise error
    route.broker.upstream.call_tool = fail
    with pytest.raises(route.Error) as captured:
        route.broker._same_session_mutation("integrity_append_event",
            {"context_admission_id": route.binding["context_admission_id"]})
    assert captured.value is error
    assert captured.value.request_sent is True


def test_ordinary_close_rechecks_owner_state_after_native_read(route):
    route.envelope._resume_read_state = lambda identity: deepcopy(route.state)
    def changed_during_read(identity):
        route.state["model_mcp_context_admission_id"] = "foreign"
        return {"id": "fixture-turn", "status": "inProgress"}
    route.envelope._native_owning_head = changed_during_read
    with pytest.raises(route.Error):
        route.broker._standalone_turn_memory_call("integrity_turn_memory_close",
            {"registration_id": route.state["turn_memory_registration_id"]})
    assert route.calls == []


def test_foreign_close_argument_never_sends(route):
    with pytest.raises(route.Error):
        route.broker._standalone_turn_memory_call("integrity_turn_memory_close",
            {"registration_id": "sha256:" + "f" * 64})
    assert route.calls == []


@pytest.mark.parametrize("fault", ["external-outcome", "unknown-request", "unknown-registration"])
def test_nonretained_close_preserves_real_original_pre_send_guards(route, fault):
    # Exercise the real original lifecycle method through the adapter. Stop at
    # its existing pre-send guards; no subprocess or live transport is involved.
    source = ast.parse(broker_bundle.BROKER.read_text("utf-8"))
    cls = next(n for n in source.body if isinstance(n, ast.ClassDef) and n.name == "TurnBroker")
    method = next(n for n in cls.body if isinstance(n, ast.FunctionDef)
                  and n.name == "_standalone_turn_memory_call")
    route.envelope._owning_state_root = lambda: Path("fixture-unused")
    def guard(*args):
        if fault == "external-outcome":
            raise ValueError("fixture unresolved external outcome")
    namespace = {"BrokerError": route.Error, "turn_envelope": route.envelope,
                 "_local_routes": SimpleNamespace(guard_close=guard)}
    module = ast.Module(body=[ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0),
                             method], type_ignores=[])
    exec(compile(ast.fix_missing_locations(module), "real-original-lifecycle", "exec"), namespace)
    Broker = type(route.broker)
    Broker._standalone_turn_memory_call = namespace["_standalone_turn_memory_call"]
    broker_adapter.install({"TurnBroker": Broker, "BrokerError": route.Error,
                            "turn_envelope": route.envelope}, recovery_client, operation_ledger)
    broker = route.broker
    broker._check_own_lifecycle = lambda *args: None
    broker._lifecycle_request_key = lambda *args: "fixture-key"
    broker._uncertain_lifecycle_requests = {"fixture-key"} if fault == "unknown-request" else set()
    registration = route.state["turn_memory_registration_id"]
    broker._uncertain_lifecycle_registrations = {registration} if fault == "unknown-registration" else set()
    broker._ack_pending_context_replays = lambda: None
    with pytest.raises(route.Error):
        broker._standalone_turn_memory_call("integrity_turn_memory_close", {"registration_id": registration})
    assert route.calls == []


def _stage_pending_own_close(route, request):
    # Mirror the owning hook's dispatch-boundary marker for its first own CLOSE.
    encoded = json.dumps(request, ensure_ascii=False, sort_keys=True,
                         separators=(",", ":"), allow_nan=False).encode("utf-8")
    route.state.update({
        "turn_memory_status": "coverage-debt", "turn_memory_lease": "expired",
        "turn_memory_queue": "recovery", "turn_memory_close_attempted": True,
        "turn_memory_close_attempted_generation": route.binding["generation"],
        "turn_memory_close_request": request,
        "turn_memory_close_request_digest": "sha256:" + hashlib.sha256(
            b"turn-memory-terminal-request-v1\0" + encoded).hexdigest(),
        "turn_memory_failure": {"code": "own_terminal_result_pending",
            "tool": "integrity_turn_memory_close", "outcome": "pending",
            "request_sent": None, "failure_layer": "hook-dispatch-boundary"}})


def test_hook_staged_pending_own_close_is_sent_once(route):
    request = {"registration_id": route.state["turn_memory_registration_id"],
               "outcome": "no-event", "no_event_reason": "read-only"}
    _stage_pending_own_close(route, request)
    route.broker._standalone_turn_memory_call("integrity_turn_memory_close", dict(request))
    assert [name for name, _ in route.calls] == ["integrity_turn_memory_close"]


@pytest.mark.parametrize("fault", ["other-request", "digest", "generation", "failure", "append"])
def test_pending_marker_never_authorizes_other_requests(route, fault):
    request = {"registration_id": route.state["turn_memory_registration_id"],
               "outcome": "no-event", "no_event_reason": "read-only"}
    _stage_pending_own_close(route, request)
    sent = dict(request)
    if fault == "other-request":
        sent["no_event_reason"] = "repetition"
    elif fault == "digest":
        route.state["turn_memory_close_request_digest"] = "sha256:" + "0" * 64
    elif fault == "generation":
        route.state["turn_memory_close_attempted_generation"] += 1
    elif fault == "failure":
        route.state["turn_memory_failure"]["request_sent"] = True
    with pytest.raises(route.Error):
        if fault == "append":
            route.broker._same_session_mutation("integrity_append_event",
                {"context_admission_id": route.binding["context_admission_id"]})
        else:
            route.broker._standalone_turn_memory_call("integrity_turn_memory_close", sent)
    assert route.calls == []


def test_canonical_and_preserved_root_brokers_keep_single_shot_startup_policy():
    # Standalone preserved-root cohorts bypass native_install's policy derivation.
    # Exercise the canonical renderer itself so that path cannot regress to 20 s.
    from integrity_client_memory.transport_policy import INITIALIZE_SECONDS
    raw, proof = broker_bundle.render_windows_broker()
    tree = ast.parse(raw)
    limit = next(n for n in tree.body if isinstance(n, ast.Assign)
                 and any(isinstance(t, ast.Name) and t.id == "UPSTREAM_INITIALIZE_TIMEOUT_SECONDS"
                         for t in n.targets))
    assert ast.literal_eval(limit.value) == INITIALIZE_SECONDS == 45
    assert proof["transport_policy"]["model_admission_retry_allowed"] is False
    assert b"no-model-retry-single-shot-admission" in raw
    assert "transport_policy.py" in broker_bundle.SUPPORT
