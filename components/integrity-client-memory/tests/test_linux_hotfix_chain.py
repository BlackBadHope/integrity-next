"""Linux hotfix chain broker 1.6.1-linux.2..7 / hook 1.8.0-linux.5.

Production functions are extracted from the canonical Linux resources and run
against inert fixtures; no configured runtime, Native reader, MCP upstream or
installed host state is loaded. POSIX-only primitives (fcntl, uid custody) are
skipped on other platforms; everything else runs on every CI platform.
"""
from __future__ import annotations

import ast
from contextlib import contextmanager
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import threading
import time
from types import SimpleNamespace

import pytest


LINUX = Path(__file__).resolve().parents[1] / "src/integrity_client_memory/resources/linux"
HOOK = LINUX / "admission.py"
BROKER = LINUX / "integrity-client-turn-broker.py"
ENVELOPE = LINUX / "integrity_client_turn_envelope.py"
DISPATCHER = LINUX / "native/linux_admission_dispatcher.py"
POSIX = pytest.mark.skipif(os.name != "posix", reason="POSIX custody/flock primitive")

THREAD = "11111111-1111-4111-8111-111111111111"
TURN = "22222222-2222-4222-8222-222222222222"
sha = lambda value: hashlib.sha256(value.encode()).hexdigest()


class FixtureError(RuntimeError):
    pass


class FixtureBrokerError(RuntimeError):
    def __init__(self, message, *, layer, request_sent=False, retryable=False):
        super().__init__(message)
        self.layer, self.request_sent, self.retryable = layer, request_sent, retryable


def module(path):
    return ast.parse(path.read_text(encoding="utf-8"))


def constants(path):
    values = {}
    for node in module(path).body:
        if (isinstance(node, (ast.Assign, ast.AnnAssign)) and isinstance(node.value, ast.Constant)):
            for target in (node.targets if isinstance(node, ast.Assign) else [node.target]):
                if isinstance(target, ast.Name):
                    values[target.id] = node.value.value
    return values


def load(nodes, namespace, label="fixture"):
    """Execute only selected definitions: no imports, configuration or startup code."""
    exec(compile(ast.Module(body=list(nodes), type_ignores=[]), label, "exec"), namespace)
    return namespace


def top_level(path, *names):
    selected = [n for n in module(path).body
                if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name in names]
    assert {n.name for n in selected} == set(names)
    return selected


def method(path, class_name, name):
    cls = next(n for n in module(path).body if isinstance(n, ast.ClassDef) and n.name == class_name)
    node = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == name)
    node.decorator_list = []
    return node


def embedded_core():
    calls = [n for n in ast.walk(module(BROKER)) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
             and n.func.id == "compile" and len(n.args) > 1 and isinstance(n.args[1], ast.Constant)
             and n.args[1].value == "<managed-core_delivery.py>"]
    assert len(calls) == 1
    return ast.literal_eval(calls[0].args[0])


# Versions and budgets -------------------------------------------------------

def test_hook_and_broker_form_one_linux7_cohort():
    hook, broker = constants(HOOK), constants(BROKER)
    assert broker["BROKER_VERSION"] == "1.6.1-linux.7"
    assert hook["LINUX_BROKER_SERVER_VERSION"] == broker["BROKER_VERSION"]
    assert hook["LINUX_PREVIOUS_BROKER_SERVER_VERSION"] == "1.6.1-linux.6"
    assert hook["HOOK_VERSION"] == "1.8.0-linux.5"
    assert broker["BROKER_TARGET_PLATFORM"] == "linux"


def test_lifecycle_budget_covers_two_bounded_broker_starts():
    hook, broker = constants(HOOK), constants(BROKER)
    reads = [n.args[0].args[0].value for n in ast.walk(module(HOOK))
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "_readline"
             and n.args and isinstance(n.args[0], ast.Call)
             and getattr(n.args[0].func, "id", None) == "remaining_lifecycle_seconds"]
    assert reads == [165]
    assert hook["LIFECYCLE_BUDGET_SECONDS"] == 180
    assert broker["UPSTREAM_INITIALIZE_TIMEOUT_SECONDS"] == 60
    assert 2 * broker["UPSTREAM_INITIALIZE_TIMEOUT_SECONDS"] < reads[0] < hook["LIFECYCLE_BUDGET_SECONDS"]


def test_every_current_broker_version_check_accepts_the_previous_broker():
    collections = []
    for node in ast.walk(module(HOOK)):
        if isinstance(node, (ast.Set, ast.Tuple, ast.List)):
            names = {e.id for e in node.elts if isinstance(e, ast.Name)}
            if "LINUX_BROKER_SERVER_VERSION" in names:
                collections.append(names)
    assert len(collections) >= 3
    assert all("LINUX_PREVIOUS_BROKER_SERVER_VERSION" in names for names in collections)


def test_broker_refuses_other_platforms_before_parsing_arguments():
    class Parsed(Exception):
        pass

    def parser(**_kw):
        raise Parsed

    for platform, expected in (("win32", FixtureBrokerError), ("linux", Parsed)):
        ns = load(top_level(BROKER, "main"), {
            "sys": SimpleNamespace(platform=platform), "BrokerError": FixtureBrokerError,
            "BROKER_TARGET_PLATFORM": "linux", "argparse": SimpleNamespace(ArgumentParser=parser),
            "Path": Path, "__doc__": ""})
        with pytest.raises(expected):
            ns["main"]([])


# Registered transport from config.toml ---------------------------------------

def test_linux_reads_registration_directly_before_any_cli_launch():
    function = next(n for n in module(HOOK).body if isinstance(n, ast.FunctionDef) and n.name == "registered_transport")
    linux = next(i for i, n in enumerate(function.body) if isinstance(n, ast.If)
                 and "sys.platform" in ast.unparse(n.test) and "'linux'" in ast.unparse(n.test))
    body = ast.unparse(function.body[linux])
    assert "linux_registered_transport" in body and "config.toml" in body and "CODEX_HOME" in body
    cli = next(i for i, n in enumerate(function.body) if "subprocess.run" in ast.unparse(n))
    assert linux < cli


def transport_reader(tmp_path, text, mode=0o600):
    ns = load(top_level(HOOK, "HookError", "linux_registered_transport"), {"Path": Path})
    path = (tmp_path / "config.toml").resolve()
    path.write_text(text, encoding="utf-8")
    path.chmod(mode)
    return ns, path


REGISTRATION = """
[mcp_servers.integrity_client_memory]
command = "/usr/bin/python3"
args = ["broker.py", "--config", "broker.json"]
env = {INTEGRITY_FIXTURE = "explicit"}
env_vars = ["INTEGRITY_FORWARDED", "INTEGRITY_ABSENT"]
"""


@POSIX
def test_registered_transport_is_read_from_protected_config(tmp_path, monkeypatch):
    monkeypatch.setenv("INTEGRITY_FORWARDED", "forwarded")
    monkeypatch.delenv("INTEGRITY_ABSENT", raising=False)
    ns, path = transport_reader(tmp_path, REGISTRATION)
    assert ns["linux_registered_transport"](path) == {"transport": {
        "type": "stdio", "command": "/usr/bin/python3", "args": ["broker.py", "--config", "broker.json"],
        "env": {"INTEGRITY_FORWARDED": "forwarded", "INTEGRITY_FIXTURE": "explicit"}, "cwd": None}}


@POSIX
@pytest.mark.parametrize("text,mode,code", [
    (REGISTRATION, 0o644, "mcp_registration_unavailable"),
    (REGISTRATION.replace('"/usr/bin/python3"', '"python3"'), 0o600, "mcp_registration_unavailable"),
    (REGISTRATION + 'url = "https://example.invalid/mcp"\n', 0o600, "mcp_registration_unavailable"),
    (REGISTRATION + "enabled = false\n", 0o600, "mcp_registration_unavailable"),
    (REGISTRATION.replace("integrity_client_memory", "other_server"), 0o600, "mcp_registration_unavailable"),
    (REGISTRATION.replace('args = ["broker.py", "--config", "broker.json"]', "args = [1]"), 0o600,
     "invalid_mcp_transport"),
    ("[mcp_servers.integrity_client_memory\n", 0o600, "mcp_registration_unavailable"),
])
def test_registered_transport_fails_closed(tmp_path, text, mode, code):
    ns, path = transport_reader(tmp_path, text, mode)
    with pytest.raises(ns["HookError"], match=code):
        ns["linux_registered_transport"](path)


@POSIX
def test_registered_transport_rejects_symlinked_config(tmp_path):
    ns, path = transport_reader(tmp_path, REGISTRATION)
    link = tmp_path / "linked.toml"
    link.symlink_to(path)
    with pytest.raises(ns["HookError"], match="mcp_registration_unavailable"):
        ns["linux_registered_transport"](link)


# Curator guard: protected admission anchor and current own open receipt ------

def anchor_reader(anchor, environ=None):
    return load(top_level(ENVELOPE, "_curator_owning_identity"), {
        "re": re, "os": SimpleNamespace(environ=environ or {}), "TurnEnvelopeError": FixtureError,
        "_RESUME_CLAIM_OWNER": anchor})["_curator_owning_identity"]


def test_curator_identity_uses_only_the_admitted_anchor():
    anchor = (THREAD, 3, "sha256:" + "a" * 64)
    assert anchor_reader(anchor)() == THREAD
    assert anchor_reader(anchor, {"CODEX_THREAD_ID": THREAD})() == THREAD


@pytest.mark.parametrize("anchor,environ,message", [
    (None, {}, "anchor missing"),
    ((THREAD, 0, "sha256:" + "a" * 64), {}, "anchor missing"),
    ((THREAD, True, "sha256:" + "a" * 64), {}, "anchor missing"),
    ((THREAD, 3, "sha256:short"), {}, "anchor missing"),
    ((THREAD, 3), {}, "anchor missing"),
    (("not-a-thread", 3, "sha256:" + "a" * 64), {}, "identity invalid"),
    ((THREAD, 3, "sha256:" + "a" * 64), {"CODEX_THREAD_ID": TURN}, "caller changed"),
])
def test_curator_identity_rejects_missing_or_foreign_anchor(anchor, environ, message):
    with pytest.raises(FixtureError, match=message):
        anchor_reader(anchor, environ)()


class CuratorFixture:
    def __init__(self, tmp_path):
        self.home = tmp_path
        self.head = {"id": TURN, "status": "inProgress"}
        self.reads = []
        self.state = {"turn_id": TURN, "turn_memory_registration_id": "registration:own",
                      "model_mcp_context_admission_id": "admission:own",
                      "turn_memory_intent_id": "intent:own", "turn_memory_terminal_receipt_id": None}
        self.binding = {"admitted": True, "hashes": {"thread_id": sha(THREAD), "turn_id": sha(TURN)},
                        "context_admission_id": "admission:own", "intent_id": "intent:own"}
        self.args = {"curator_registration_id": "registration:own", "context_admission_id": "admission:own"}
        source = embedded_core()
        guard = next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == "guard_curator")
        self.guard = load([guard], {"hashlib": hashlib, "json": json,
                                    "Path": SimpleNamespace(home=lambda: self.home)})["guard_curator"]
        # No _resume_identity / _native_owning_head: the Linux guard must not use them.
        self.envelope = SimpleNamespace(_curator_owning_identity=lambda: THREAD,
                                        _original_producer_head=self.read_head)

    @property
    def state_path(self):
        return self.home / ".codex/integrity-memory/state" / (sha(THREAD) + ".json")

    def read_head(self, identity, turn):
        self.reads.append((identity, turn))
        return dict(self.head)

    def run(self):
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        if self.state is not None:
            self.state_path.write_text(json.dumps(self.state), encoding="utf-8")
        return self.guard(self.envelope, self.binding, self.args)


def test_curator_guard_accepts_current_own_open_registration(tmp_path):
    fixture = CuratorFixture(tmp_path)
    assert fixture.run() is None
    assert fixture.reads == [(THREAD, TURN)]


@pytest.mark.parametrize("change", [
    "not-admitted", "thread-hash", "turn-hash", "registration", "argument-admission",
    "state-admission", "intent", "closed", "head-completed", "head-other-turn", "state-missing",
])
def test_curator_guard_denies_foreign_stale_or_completed_subject(tmp_path, change):
    fixture = CuratorFixture(tmp_path)
    if change == "not-admitted":
        fixture.binding["admitted"] = False
    elif change == "thread-hash":
        fixture.binding["hashes"]["thread_id"] = sha(TURN)
    elif change == "turn-hash":
        fixture.binding["hashes"]["turn_id"] = sha(THREAD)
    elif change == "registration":
        fixture.args["curator_registration_id"] = "registration:foreign"
    elif change == "argument-admission":
        fixture.args["context_admission_id"] = "admission:foreign"
    elif change == "state-admission":
        fixture.state["model_mcp_context_admission_id"] = "admission:stale"
    elif change == "intent":
        fixture.binding["intent_id"] = "intent:foreign"
    elif change == "closed":
        fixture.state["turn_memory_terminal_receipt_id"] = "sha256:" + "c" * 64
    elif change == "head-completed":
        fixture.head["status"] = "completed"
    elif change == "head-other-turn":
        fixture.head["id"] = THREAD
    elif change == "state-missing":
        fixture.state = None
    with pytest.raises(ValueError, match="curator"):
        fixture.run()


def test_curator_guard_propagates_anchor_failure_and_broker_classifies_it(tmp_path):
    fixture = CuratorFixture(tmp_path)

    def missing():
        raise FixtureError("curator admitted producer anchor missing")

    fixture.envelope._curator_owning_identity = missing
    with pytest.raises(FixtureError):
        fixture.run()
    assert fixture.reads == []
    handlers = [h for n in ast.walk(module(BROKER)) if isinstance(n, ast.Try)
                and isinstance(n.body[0], ast.Expr) and isinstance(n.body[0].value, ast.Call)
                and getattr(n.body[0].value.func, "attr", None) == "guard_curator" for h in n.handlers]
    assert len(handlers) == 1
    assert "turn_envelope.TurnEnvelopeError" in ast.unparse(handlers[0].type)
    assert "broker-curator-actor" in ast.unparse(handlers[0].body)


# Broker classification and canonical lifecycle readback -----------------------

def test_native_observation_failure_is_classified_before_supersession():
    tries = [n for n in ast.walk(module(BROKER)) if isinstance(n, ast.Try)
             and any("NativeObservationError" in ast.unparse(h.type) for h in n.handlers if h.type)]
    assert len(tries) == 1
    kinds = [ast.unparse(h.type) for h in tries[0].handlers]
    observed = next(i for i, k in enumerate(kinds) if "NativeObservationError" in k)
    superseded = next(i for i, k in enumerate(kinds) if "turn_envelope.TurnEnvelopeError" in k)
    assert observed < superseded
    assert "broker-native-reader" in ast.unparse(tries[0].handlers[observed].body)
    envelope = top_level(ENVELOPE, "NativeObservationError")[0]
    assert [ast.unparse(b) for b in envelope.bases] == ["TurnEnvelopeError"]


def signed(protocol, **extra):
    return {"protocol": protocol, "production_authority": False, "receipt_id": "sha256:" + "1" * 64,
            "signature": {"algorithm": "ed25519", "value": "fixture"}, **extra}


OPEN = {"machine_id": "machine:fixture", "thread_id": THREAD, "turn_id": TURN, "intent_id": "intent:own",
        "prompt_sha256": "d" * 64}
REGISTRATION_RECEIPT = signed("integrity-guardian/turn-memory-registration/v1",
                              identity={k: OPEN[k] for k in ("machine_id", "thread_id", "turn_id", "intent_id")},
                              prompt_sha256=OPEN["prompt_sha256"])
REGISTRATION_ID = REGISTRATION_RECEIPT["receipt_id"]


class Coverage:
    def __init__(self, rows, *, error=False, protocol="integrity-guardian/turn-memory-coverage/v2", text=False):
        value = {"protocol": protocol, "receipt_sample": {"receipts": rows}}
        self.result = ({"content": [{"type": "text", "text": json.dumps(value)}]} if text
                       else {"structuredContent": value, "content": []})
        if error:
            self.result["isError"] = True
        self.calls = []

    def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        return self.result


def readback():
    ns = load(top_level(BROKER, "_json_bytes") + [method(BROKER, "TurnBroker", "_read_existing_lifecycle")],
              {"json": json, "re": re, "Any": object})
    return lambda target, name, arguments: ns["_read_existing_lifecycle"](None, target, name, arguments)


def row(**extra):
    return {"registration_id": REGISTRATION_ID, "registration_receipt": REGISTRATION_RECEIPT,
            "status": "open", "terminal_receipt": None, **extra}


@pytest.mark.parametrize("text", [False, True])
def test_positive_exact_open_receipt_resolves_without_replay(text):
    target = Coverage([row()], text=text)
    result = readback()(target, "integrity_turn_memory_open", OPEN)
    assert result["_meta"] == {"integrityLifecycleResolution": "canonical-positive-readback-no-replay"}
    assert json.loads(result["content"][0]["text"]) == {"receipt": REGISTRATION_RECEIPT}
    assert target.calls == [("integrity_turn_memory_coverage",
                             {"limit": 100, "thread_id": THREAD, "machine_id": "machine:fixture"})]


@pytest.mark.parametrize("target", [
    Coverage([]),
    Coverage([row()], error=True),
    Coverage([row()], protocol="integrity-guardian/turn-memory-coverage/v1"),
    Coverage([row(registration_receipt={**REGISTRATION_RECEIPT, "production_authority": True})]),
    Coverage([row(registration_receipt={**REGISTRATION_RECEIPT, "signature": {"algorithm": "none", "value": "x"}})]),
    Coverage([row(registration_receipt={**REGISTRATION_RECEIPT, "prompt_sha256": "e" * 64})]),
    Coverage([row(status="closed")]),
])
def test_absent_or_inexact_readback_never_authorizes_replay(target):
    assert readback()(target, "integrity_turn_memory_open", OPEN) is None


TERMINAL = signed("integrity-guardian/turn-memory-terminal-receipt/v1",
                  registration_id=REGISTRATION_ID, outcome="no-event", no_event_reason="read-only")


def test_close_and_gap_resolve_only_from_matching_signed_receipts():
    read = readback()
    close = {"registration_id": REGISTRATION_ID, "outcome": "no-event", "no_event_reason": "read-only"}
    assert json.loads(read(Coverage([row(terminal_receipt=TERMINAL)]), "integrity_turn_memory_close",
                           close)["content"][0]["text"]) == {"receipt": TERMINAL}
    assert read(Coverage([row(terminal_receipt=TERMINAL)]), "integrity_turn_memory_close",
                {**close, "outcome": "events", "events": [1]}) is None
    assert read(Coverage([row(terminal_receipt=TERMINAL)]), "integrity_turn_memory_close",
                {**close, "registration_id": "sha256:" + "2" * 64}) is None
    gap = signed("integrity-guardian/turn-memory-gap-receipt/v1", registration_id=REGISTRATION_ID,
                 stage="hook", terminal=False)
    gap_args = {"registration_id": REGISTRATION_ID, "stage": "hook"}
    assert json.loads(read(Coverage([row(gap_receipt=gap)]), "integrity_turn_memory_gap",
                           gap_args)["content"][0]["text"]) == {"receipt": gap}
    assert read(Coverage([row(gap_receipt=gap)]), "integrity_turn_memory_gap", {**gap_args, "stage": "other"}) is None
    assert json.loads(read(Coverage([row(terminal_receipt=TERMINAL)]), "integrity_turn_memory_gap",
                           gap_args)["content"][0]["text"]) == {"terminal_receipt": TERMINAL}


@pytest.mark.parametrize("resolved", [None, {"content": []}])
def test_existing_dispatch_journal_requires_positive_readback(tmp_path, monkeypatch, resolved):
    monkeypatch.setenv("INTEGRITY_CLIENT_STATE_ROOT", str(tmp_path))
    ns = load(top_level(BROKER, "_json_bytes") + [method(BROKER, "TurnBroker", "_begin_lifecycle_dispatch")],
              {"json": json, "os": os, "Path": Path, "BrokerError": FixtureBrokerError, "Any": object})
    seen = []
    broker = SimpleNamespace(_lifecycle_request_key=lambda name, subject: "fixture-key",
                             _read_existing_lifecycle=lambda *a: seen.append(a) or resolved)
    begin = lambda: ns["_begin_lifecycle_dispatch"](broker, "integrity_turn_memory_open", OPEN, "target")
    assert begin() is None  # first send creates the journal
    assert seen == []
    if resolved is None:
        with pytest.raises(FixtureBrokerError) as raised:
            begin()
        assert raised.value.layer == "broker-lifecycle-uncertain" and raised.value.request_sent is False
    else:
        assert begin() is resolved
    assert seen == [("target", "integrity_turn_memory_open", OPEN)]
    assert (tmp_path / "lifecycle-dispatch-fixture-key.json").is_file()


def test_both_lifecycle_call_sites_return_readback_before_upstream_send():
    text = BROKER.read_text(encoding="utf-8")
    sites = re.findall(r"resolved = self\._begin_lifecycle_dispatch\(name, arguments, [^)]+\)\n"
                       r"\s+if resolved is not None:\n\s+return resolved\n", text)
    assert len(sites) == 2
    assert "self._begin_lifecycle_dispatch(name, arguments)\n" not in text


# Linux transport-start gate ---------------------------------------------------

def gate_class(root, wait=0.3):
    import fcntl
    return load(top_level(BROKER, "StartupGate"), {
        "errno": errno, "fcntl": fcntl, "os": os, "secrets": secrets, "stat": stat, "time": time,
        "BrokerError": FixtureBrokerError, "STARTUP_GATE_DIRECTORY": root, "STARTUP_GATE_SLOTS": 2,
        "STARTUP_GATE_WAIT_SECONDS": wait, "__builtins__": __builtins__})["StartupGate"]


@POSIX
def test_start_gate_bounds_concurrent_starts_with_private_slots(tmp_path):
    root = tmp_path.resolve() / "gate"
    tmp_path.chmod(0o700)
    Gate = gate_class(root)
    first, second = Gate(threading.Event()).__enter__(), Gate(threading.Event()).__enter__()
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert {stat.S_IMODE(p.stat().st_mode) for p in root.iterdir()} == {0o600}
    with pytest.raises(FixtureBrokerError, match="capacity wait expired") as raised:
        Gate(threading.Event()).__enter__()
    assert raised.value.request_sent is False
    first.__exit__(None, None, None)
    third = Gate(threading.Event()).__enter__()
    for gate in (second, third):
        gate.__exit__(None, None, None)


@POSIX
def test_start_gate_stops_on_cancel_and_rejects_symlinked_root(tmp_path):
    base = tmp_path.resolve()
    base.chmod(0o700)
    cancelled = threading.Event()
    cancelled.set()
    Gate = gate_class(base / "gate", wait=5)
    holders = [Gate(threading.Event()).__enter__() for _ in range(2)]
    with pytest.raises(FixtureBrokerError, match="public input transport closed"):
        Gate(cancelled).__enter__()
    for gate in holders:
        gate.__exit__(None, None, None)
    (base / "elsewhere").mkdir(mode=0o700)
    (base / "linked").symlink_to(base / "elsewhere")
    with pytest.raises(OSError):
        gate_class(base / "linked")(threading.Event()).__enter__()


# Child lifecycle notifications ----------------------------------------------------

class Baseline:
    def __init__(self, state):
        self.state, self.calls = state, []

    def session_id(self, _payload):
        return THREAD

    @contextmanager
    def session_state_lock(self, _identity):
        yield

    def load_state(self, _identity):
        return self.state

    def handle_stop(self, event, identity, state):
        self.calls.append(("stop", event))

    def handle_prompt(self, event, payload, identity):
        self.calls.append(("prompt", event))


@pytest.mark.parametrize("delegated", [False, True])
@pytest.mark.parametrize("event", ["SubagentStart", "SubagentStop", "Stop"])
def test_child_lifecycle_never_retires_parent_admission(event, delegated):
    ns = load(top_level(DISPATCHER, "dispatch"), {"is_carrier": lambda _p: False, "LinuxAdmissionError": FixtureError})
    baseline = Baseline({"turn_id": TURN, **({"delegation_operation_id": "op"} if delegated else {})})
    assert ns["dispatch"](event, {"agent_id": TURN}, baseline, None, schedule_terminal=None) == 0
    assert baseline.calls == []
    own = Baseline({"turn_id": TURN})
    ns["dispatch"]("Stop", {}, own, None, schedule_terminal=None)
    assert own.calls == [("stop", "Stop")]
