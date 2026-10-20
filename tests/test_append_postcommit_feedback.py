"""Post-commit failures preserve signed observations, not guessed success.

Private SQLite backend and real passive-witness signatures; no live writes.
"""
from copy import deepcopy
import hashlib
import sqlite3
from types import SimpleNamespace

import pytest

from integrity_guardian import memory_synapse_mcp as m
from integrity_guardian.medor_architecture import (
    MedorArchitectureError, PersistentMedorArchitectureService,
    verify_medor_passive_witness,
)
from integrity_guardian.signing import Ed25519Signer, TrustedKey


def digest(value):
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


@pytest.fixture
def gate(tmp_path, monkeypatch):
    database = tmp_path / "canonical-fixture.sqlite3"
    with sqlite3.connect(database) as db:
        db.execute("CREATE TABLE events(id INTEGER PRIMARY KEY, uid TEXT UNIQUE, request TEXT)")
    signer = Ed25519Signer.generate("key:test:postcommit-witness")
    signed = PersistentMedorArchitectureService.__new__(PersistentMedorArchitectureService)
    signed.keys = SimpleNamespace(checkpoint_signer=signer,
        checkpoint_key=TrustedKey(signer.key_id, signer.public_key))
    state = SimpleNamespace(append_calls=0, observe_calls=0, commit=True,
        transport_error=False, witness_error=False, feedback_error=False,
        outcome_error=False, precommit_error=False, database=database,
        checkpoint_key=signed.keys.checkpoint_key)

    def prepare(arguments, **kwargs):
        return {"event_uid": arguments["event_uid"], "request_sha256": "a" * 64}

    def append(prepared):
        state.append_calls += 1
        if state.commit:
            with sqlite3.connect(database) as db:
                db.execute("INSERT INTO events(uid,request) VALUES(?,?)",
                    (prepared["event_uid"], prepared["request_sha256"]))
        if state.transport_error:
            raise m.McpFacadeError("lost transport response")
        return {"receipt": {"outcome": "appended"}}

    def observe(*, event_uid, request_sha256):
        state.observe_calls += 1
        if state.observe_calls > 1 and state.witness_error:
            raise m.McpFacadeError("observer unavailable")
        with sqlite3.connect(database) as db:
            row = db.execute("SELECT id,request FROM events WHERE uid=?", (event_uid,)).fetchone()
        return {"event_uid": event_uid, "event_id": row[0] if row else 0,
            "request_sha256": request_sha256,
            "status": "exact" if row else "absent", "observed_record_digest": digest(str(row))}

    def authorize(**kwargs):
        if state.precommit_error:
            raise MedorArchitectureError("precommit denied")
        return {"grant_id": digest("grant"), "receipt_id": digest("authority")}

    def feedback(**kwargs):
        if state.feedback_error:
            raise MedorArchitectureError("architecture custody lock acquisition timed out")
        return {"receipt_id": digest("feedback")}

    def outcome(**kwargs):
        if state.outcome_error:
            raise MedorArchitectureError("architecture custody lock acquisition timed out")
        return {"route_stage_id": digest("outcome")}

    facade = m.MemorySynapseMcp.__new__(m.MemorySynapseMcp)
    facade.architecture = SimpleNamespace(sign_passive_witness=signed.sign_passive_witness,
        plan_event_append=lambda **kwargs: {"route_stage_id": digest("pre-action")},
        authorize_event_append=authorize,
        plan_event_execution=lambda **kwargs: {"route_stage_id": digest("action")},
        record_event_append_outcome=feedback, plan_event_outcome=outcome)
    facade.action_log = SimpleNamespace(prepare_append=prepare, append_prepared=append)
    facade.action_witness = SimpleNamespace(observe=observe)
    facade._session_architecture = {"architecture": {"admission_id": digest("architecture"),
        "summary": {"coordination_stop_required": False, "route_disposition": "ready"}}}
    facade.security_admission = SimpleNamespace(admission_id=digest("security"))
    facade.native_trust = None
    state.facade = facade
    state.arguments = {"event_uid": "client:test-postcommit-feedback", "authority_decision": {}}
    monkeypatch.setattr(m, "_audit", lambda receipt: None)
    return state


def invoke(gate):
    return gate.facade._event_append_action(deepcopy(gate.arguments))["receipt"]


@pytest.mark.parametrize("lost_response", [False, True])
def test_committed_event_retains_exact_signed_proof_if_feedback_times_out(gate, lost_response):
    gate.feedback_error = True
    gate.transport_error = lost_response
    receipt = invoke(gate)
    assert gate.append_calls == 1
    with sqlite3.connect(gate.database) as db:
        assert db.execute("SELECT count(*) FROM events").fetchone()[0] == 1
    assert receipt["event_id"] == 1
    assert receipt["event_uid"] == gate.arguments["event_uid"]
    assert receipt["request_sha256"] == "a" * 64
    assert receipt["action_outcome"] == "confirmed-success"
    assert receipt["completion_status"] == "incomplete"
    assert receipt["feedback_status"] == "pending"
    assert receipt["warning"]["error_type"] == "MedorArchitectureError"
    assert receipt["warning"]["stage"] == "record-event-append-outcome"
    assert receipt["feedback_receipt_id"] is None
    assert receipt["outcome_feedback"] is None
    assert receipt["outcome_route_stage_id"] is None
    assert "outcome" not in receipt["route_stages"]
    assert receipt["automatic_retry_allowed"] is False
    assert receipt["transport_response_received"] is (not lost_response)
    proof = verify_medor_passive_witness(receipt["passive_witness"],
        checkpoint_key=gate.checkpoint_key)
    assert proof["ok"] and proof["status"] == "exact"


def test_unknown_observation_stays_unknown_even_if_transport_claimed_success(gate):
    gate.feedback_error = True
    gate.witness_error = True
    receipt = invoke(gate)
    assert gate.append_calls == 1
    assert receipt["action_outcome"] == receipt["outcome"] == "unknown-outcome"
    assert receipt["event_id"] == 0
    assert receipt["witness_observer_available"] is False
    assert receipt["automatic_retry_allowed"] is False
    assert receipt["completion_status"] == "incomplete"


def test_precommit_failure_cannot_claim_success_or_append(gate):
    gate.precommit_error = True
    with pytest.raises(MedorArchitectureError, match="precommit denied"):
        invoke(gate)
    assert gate.append_calls == 0


def test_outcome_routing_failure_preserves_real_feedback_without_fake_stage(gate):
    gate.outcome_error = True
    receipt = invoke(gate)
    assert gate.append_calls == 1
    assert receipt["action_outcome"] == "confirmed-success"
    assert receipt["feedback_receipt_id"] == digest("feedback")
    assert receipt["feedback_status"] == "recorded-route-pending"
    assert receipt["warning"]["stage"] == "plan-event-outcome"
    assert "outcome" not in receipt["route_stages"]
    assert receipt["automatic_retry_allowed"] is False


def test_normal_path_keeps_complete_receipt_without_warning(gate):
    receipt = invoke(gate)
    assert gate.append_calls == 1
    assert receipt["outcome"] == "appended"
    assert receipt["action_outcome"] == "confirmed-success"
    assert receipt["feedback_receipt_id"] == digest("feedback")
    assert receipt["outcome_route_stage_id"] == digest("outcome")
    assert "outcome" in receipt["route_stages"]
    assert "completion_status" not in receipt and "warning" not in receipt
