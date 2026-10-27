"""Domain-specific replay commitments; strict signature profile is unchanged.

Facade/registry routing uses private signed test stores. Native authority and
catalog installation are fixtures; this is not full Native/SSH acceptance.
"""
from contextlib import nullcontext
from copy import deepcopy
import json
import math

import pytest

from integrity_guardian.canonical import CanonicalizationError, canonical_bytes
from integrity_guardian.memory_synapse_mcp import _sha256, _tool_result
from integrity_guardian.same_session_recovery import (
    SessionRecoveryError,
    digest,
    replay_json_digest,
)
from test_session_recovery_reservation_fallback import gate, digest as fixture_digest


@pytest.fixture
def retained(gate):
    g = gate
    g.record = {"phase": "committed", "request_id": fixture_digest("replay"),
        "request_digest": fixture_digest("request"),
        "result": {"context_admission_id": g.f._context_admission_id,
            "snapshot": {**deepcopy(g.f._session_snapshot), "quality": 1.0},
            "prompt_binding": deepcopy(g.f._archive_prompt_binding),
            "logical_generation": g.f._context_generation,
            "capabilities": {"artifact_digest": fixture_digest("artifact")}},
        "state": {"logical_generation": g.f._context_generation,
            "mind": {"readmodel": {"score": 0.125, "scores": [1.0, -0.0, 1e-30]}},
            "native_session": deepcopy(g.f._native_session_lease),
            "architecture": deepcopy(g.f._session_architecture),
            "write_plane": {"outcome": "ready"},
            "frozen_catalog": {"name": "test-catalog", "bytes": 1}}}
    g.f._session_snapshot = deepcopy(g.record["result"]["snapshot"])
    g.f._session_mind = deepcopy(g.record["state"]["mind"])
    g.f._session_recovery_replay = (g.record["request_id"], g.record["request_digest"])
    g.f._load_context_replay = lambda *args: deepcopy(g.record)
    # Actual POSIX custody is a separate full-path gate.
    g.f._prepare_context_replay_custody = lambda: None
    g.f._context_replay_lock = lambda *args, **kwargs: nullcontext()
    g.f._replay_migration = lambda replay_id: None
    g.f._restore_context_replay_capabilities = lambda value: deepcopy(value)
    g.f._install_context_replay_catalog = lambda *args, **kwargs: None
    original_dispatch = g.f._operation_unwrapped_call

    def unwrapped(name, arguments):
        if name == "integrity_seed_snapshot":
            g.f._session_snapshot = deepcopy(g.record["result"]["snapshot"])
            return deepcopy(g.f._session_snapshot)
        return original_dispatch(name, arguments)

    g.f._operation_unwrapped_call = unwrapped
    g.opened = g.f.call("integrity_turn_memory_open", deepcopy(g.args))
    assert g.opened["session_recovery"]["available"] is True
    g.reg = g.opened["receipt"]["receipt_id"]
    g.controls = {"registration_id": g.reg, "replay_id": g.record["request_id"],
        "request_digest": g.record["request_digest"],
        "response_digest": _sha256(_tool_result(g.record["result"])),
        "context_admission_id": g.f._context_admission_id,
        "snapshot_id": g.f._session_snapshot["snapshot_id"],
        "prompt_binding": deepcopy(g.f._archive_prompt_binding),
        "logical_generation": g.f._context_generation}
    return g


@pytest.mark.parametrize("value", [None, {"a": [1, False, None, "Привіт"]},
    {"nested": {"count": 3}, "unicode": "e\u0301"}])
def test_float_free_existing_commitments_remain_identical(value):
    assert replay_json_digest(value) == digest(value)


def test_replay_commitment_uses_exact_finite_json_encoding():
    value = {"nested": {"score": 0.125}, "values": [1.0, -0.0, 1e-30]}
    assert replay_json_digest(value) == _sha256(value)
    assert replay_json_digest(value) == replay_json_digest(json.loads(json.dumps(value)))
    assert replay_json_digest({"x": 1.0}) != replay_json_digest({"x": 1})
    assert replay_json_digest({"x": -0.0}) != replay_json_digest({"x": 0.0})
    with pytest.raises(CanonicalizationError):
        canonical_bytes(value)
    with pytest.raises(CanonicalizationError):
        digest(value)


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_nonfinite_replay_values_remain_denied(value):
    with pytest.raises(ValueError):
        replay_json_digest({"nested": [value]})


def test_retained_open_status_write_guard_and_idle_restore_accept_float_state(retained):
    g = retained
    _, receipt, record = g.f._recovery_status_binding(g.reg)
    assert receipt == g.opened["receipt"]
    assert record == g.record
    g.f._recovery_before_write("integrity_append_event", {})
    capsule_before = g.f._recovery_registry(g.store).load(g.reg)
    g.f._clear_intent_context(reason="idle-cleanup")
    result = g.f._recover_same_session(g.controls)
    assert result["restored"] is True
    assert g.f._session_snapshot == g.record["result"]["snapshot"]
    assert g.f._recovery_registry(g.store).load(g.reg) == capsule_before
    assert g.store.coverage()["counts"]["registered"] == 1


def test_repeated_open_does_not_extend_float_state_capsule_ttl(retained):
    g = retained
    before = g.f._recovery_registry(g.store).load(g.reg)
    second = g.f.call("integrity_turn_memory_open", deepcopy(g.args))
    assert second["receipt"] == g.opened["receipt"]
    assert g.f._recovery_registry(g.store).load(g.reg) == before
    assert second["session_recovery"]["expires_at"] == before["expires_at"]


def test_changed_retained_float_state_denies_status_write_and_recover(retained):
    g = retained
    g.record["state"]["mind"]["readmodel"]["score"] = 0.25
    with pytest.raises(SessionRecoveryError):
        g.f._recovery_status_binding(g.reg)
    with pytest.raises(SessionRecoveryError):
        g.f._recovery_before_write("integrity_append_event", {})
    with pytest.raises(SessionRecoveryError):
        g.f._recover_same_session(g.controls)
    assert g.calls == []


def test_changed_float_snapshot_type_denies_status_and_recover(retained):
    g = retained
    g.record["result"]["snapshot"]["quality"] = 1
    with pytest.raises(SessionRecoveryError):
        g.f._recovery_status_binding(g.reg)
    with pytest.raises(SessionRecoveryError):
        g.f._recover_same_session(g.controls)


def test_changed_current_float_snapshot_type_denies_write_guard(retained):
    g = retained
    g.f._session_snapshot["quality"] = 1
    with pytest.raises(SessionRecoveryError):
        g.f._recovery_before_write("integrity_append_event", {})
    assert g.calls == []


def test_capsule_signature_still_rejects_float_fields(retained):
    g = retained
    capsule = g.f._recovery_registry(g.store).load(g.reg)
    core = {key: value for key, value in capsule.items() if key != "signature"}
    core["unexpected_float"] = 0.125
    with pytest.raises(CanonicalizationError):
        g.store.signer.sign(core)


def test_capsule_digest_tampering_still_invalidates_signature(retained):
    g = retained
    capsule = g.f._recovery_registry(g.store).load(g.reg)
    capsule["state_digest"] = replay_json_digest({"score": 0.5})
    with pytest.raises(SessionRecoveryError):
        g.f._recovery_registry(g.store)._verified(json.dumps(capsule).encode())
