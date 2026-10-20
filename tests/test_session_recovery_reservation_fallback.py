"""Focused server regression tests; private test stores, Native authority fixture.

These exercise real facade routing and signed TurnMemoryStore receipts. They
do not claim real Native enrollment, admission dispatch or SSH acceptance.
"""
from copy import deepcopy
import datetime as dt
import hashlib
from types import SimpleNamespace

import pytest

from integrity_guardian.memory_synapse_mcp import (
    ContextBindingUnavailableError,
    MemorySynapseMcp,
)
from integrity_guardian.same_session_recovery import SessionRecoveryError
from integrity_guardian.signing import Ed25519Signer
from integrity_guardian.turn_memory import TurnMemoryStore


def digest(text):
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


@pytest.fixture
def gate(tmp_path):
    now = dt.datetime.now(dt.timezone.utc)
    store = TurnMemoryStore(tmp_path / "turns.sqlite3", namespace=digest("test"),
        signer=Ed25519Signer.generate("key:test:reservation-fallback"),
        identity_profile="native-intent-v1")
    facade = MemorySynapseMcp(SimpleNamespace(),
        action_log=SimpleNamespace(reset_context=lambda: None, bind_project_scope=lambda scope: None),
        home=SimpleNamespace(reset_context=lambda: None),
        architecture=SimpleNamespace(root=tmp_path), turn_memory=store, audit=lambda receipt: None)
    facade._session_recovery_enabled = True
    facade._broker_tool_surface_authenticated = True
    facade.native_device_id = "device:test"
    facade.native_trust = SimpleNamespace(verify_session=lambda lease: deepcopy(lease))
    facade.security_admission = SimpleNamespace(expires_at=(now + dt.timedelta(hours=2)).isoformat())
    facade._security_admission_is_active = lambda admission: True
    facade._context_admission_id = digest("admission")
    facade._context_generation = 1
    facade._session_snapshot = {"snapshot_id": digest("snapshot"), "cursor": 1}
    facade._archive_prompt_binding = {"prompt_sha256": "b" * 64, "generation": 1}
    facade._native_session_lease = {"lease_id": digest("lease"), "device_id": "device:test",
        "expires_at": (now + dt.timedelta(hours=1)).isoformat()}
    facade._session_architecture = {"admission_id": digest("architecture")}
    calls = []

    def unwrapped(name, arguments):
        if name == "integrity_turn_memory_open":
            return facade._turn_memory_call("open", arguments)
        if name == "integrity_turn_memory_close":
            return facade._turn_memory_call("close", arguments)
        if name == "integrity_append_event":
            facade._bind_append_to_current_context(arguments)
            calls.append(deepcopy(arguments))
            return {"test_dispatch": True}
        raise AssertionError(name)

    facade._operation_unwrapped_call = unwrapped
    args = {"machine_id": "machine:test",
        "thread_id": "00000000-0000-4000-8000-000000000001",
        "turn_id": "00000000-0000-4000-8000-000000000002",
        "intent_id": "intent:" + "a" * 64, "prompt_sha256": "b" * 64}
    yield SimpleNamespace(f=facade, store=store, args=args, calls=calls)


def open_unretained(g):
    g.f._remember_unretained_admission()
    return g.f.call("integrity_turn_memory_open", deepcopy(g.args))


def append(g):
    return g.f.call("integrity_append_event", {
        "context_admission_id": g.f._context_admission_id, "event_uid": "test:ordinary"})


def test_unretained_registration_append_and_exact_close(gate):
    g = gate
    result = open_unretained(g)
    reg = result["receipt"]["receipt_id"]
    assert result["session_recovery"] == {"available": False,
        "protocol": "integrity-client/session-recovery/v1", "reason": "admission-not-retained",
        "registration_id": reg, "canonical_registration_unchanged": True}
    assert g.f._session_recovery_binding is None
    g.f._operation_store = lambda store: pytest.fail("unretained intent entered recovery ledger")
    assert append(g) == {"test_dispatch": True}
    terminal = g.f.call("integrity_turn_memory_close", {"registration_id": reg,
        "outcome": "no-event", "no_event_reason": "read-only"})
    assert terminal["receipt"]["registration_id"] == reg
    assert len(g.calls) == 1
    assert g.store.coverage()["counts"]["registered"] == 1


def test_unretained_open_replay_preserves_registration(gate):
    g = gate
    first = open_unretained(g)
    second = g.f.call("integrity_turn_memory_open", deepcopy(g.args))
    assert first["receipt"] == second["receipt"]
    assert second["replayed"] is True
    assert g.store.coverage()["counts"]["registered"] == 1


def test_unretained_foreign_prompt_denied_before_open(gate):
    g = gate
    g.f._remember_unretained_admission()
    with pytest.raises(SessionRecoveryError):
        g.f.call("integrity_turn_memory_open", {**g.args, "prompt_sha256": "c" * 64})
    assert g.store.coverage()["counts"]["registered"] == 0


def test_unretained_foreign_close_and_foreign_second_open_denied(gate):
    g = gate
    result = open_unretained(g)
    with pytest.raises(SessionRecoveryError):
        g.f.call("integrity_turn_memory_close", {"registration_id": digest("foreign"),
            "outcome": "no-event", "no_event_reason": "read-only"})
    with pytest.raises(SessionRecoveryError):
        g.f.call("integrity_turn_memory_open", {**g.args,
            "turn_id": "00000000-0000-4000-8000-000000000003"})
    assert g.store.find_terminal(result["receipt"]["receipt_id"]) is None
    assert g.store.coverage()["counts"]["registered"] == 1


@pytest.mark.parametrize("field", ["_context_admission_id", "_session_snapshot",
    "_native_session_lease", "_session_architecture", "_archive_prompt_binding"])
def test_unretained_context_change_denies_dispatch(gate, field):
    g = gate
    open_unretained(g)
    setattr(g.f, field, digest("changed") if field == "_context_admission_id" else {"changed": True})
    with pytest.raises(SessionRecoveryError):
        append(g)
    assert g.calls == []


def test_unretained_security_revocation_denies_dispatch(gate):
    g = gate
    open_unretained(g)
    g.f._security_admission_is_active = lambda admission: False
    with pytest.raises(SessionRecoveryError):
        append(g)
    assert g.calls == []


def test_idle_preserves_binding_but_never_writes_empty_context(gate):
    g = gate
    result = open_unretained(g)
    marker = deepcopy(g.f._session_recovery_unretained_admission)
    g.f._clear_intent_context(reason="idle-cleanup")
    assert g.f._session_recovery_unretained_admission == marker
    assert g.f._session_recovery_unretained_registration["registration_id"] == result["receipt"]["receipt_id"]
    with pytest.raises(ContextBindingUnavailableError):
        append(g)
    assert g.calls == []


def test_real_rotation_clears_stale_replay_even_without_binding(gate):
    g = gate
    g.f._session_recovery_replay = (digest("old"), digest("request"))
    g.f._clear_intent_context(reason="context-rotation")
    assert g.f._session_recovery_replay is None
    assert g.f._session_recovery_binding is None
    assert g.f._session_recovery_unretained_admission is None
    assert g.f._session_recovery_unretained_registration is None


def test_missing_retained_proof_never_becomes_unretained(gate):
    g = gate
    g.f._session_recovery_replay = (digest("old"), digest("request"))
    g.f._load_context_replay = lambda *args: None
    with pytest.raises(SessionRecoveryError):
        g.f.call("integrity_turn_memory_open", deepcopy(g.args))
    with pytest.raises(SessionRecoveryError):
        g.f._remember_unretained_admission()
    assert g.store.coverage()["counts"]["registered"] == 0


def test_retained_binding_failure_preserves_receipt_and_denies_mutation(gate):
    g = gate
    record = {"phase": "committed", "request_id": digest("replay"),
        "request_digest": digest("request"),
        "result": {"context_admission_id": g.f._context_admission_id,
            "snapshot": deepcopy(g.f._session_snapshot),
            "prompt_binding": deepcopy(g.f._archive_prompt_binding)},
        "state": {"native_session": deepcopy(g.f._native_session_lease)}}
    g.f._session_recovery_replay = (record["request_id"], record["request_digest"])
    g.f._load_context_replay = lambda *args: deepcopy(record)

    def unavailable(*args, **kwargs):
        raise OSError("test derived store unavailable")

    g.f._recovery_registry = unavailable
    result = g.f.call("integrity_turn_memory_open", deepcopy(g.args))
    assert result["session_recovery"]["available"] is False
    assert result["session_recovery"]["reason"] == "derived-binding-unavailable"
    assert g.store.find_registration(result["receipt"]["receipt_id"]) == result["receipt"]
    assert g.f._session_recovery_unretained_admission is None
    with pytest.raises(SessionRecoveryError):
        append(g)
    assert g.calls == []
