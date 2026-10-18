"""Exercise extracted lifecycle code without loading configured runtime or Native.

Only private filesystem/Native boundary adapters are inert fixtures. Production
claim validation, binding joins, consume and revalidation functions are executed.
The concurrency gates fail on the former lock-across-Native implementation.
"""
from __future__ import annotations

import ast
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
import math
from pathlib import Path
import re
import secrets
import threading
from types import SimpleNamespace
from typing import Any

import pytest


SOURCE = (Path(__file__).resolve().parents[1]
          / "src/integrity_client_memory/resources/linux/integrity_client_turn_envelope.py")
FUNCTIONS = {
    "_sha256_bytes", "_sha256_text", "_ref_digest", "_identity_hash", "_claim_digest",
    "_require_claim", "_validate_common", "_public", "_resume_successor_join",
    "consume_owning_lifecycle", "revalidate_consumed_own_lifecycle",
    "bind_resume_identity_from_claim",
}


class FixtureEnvelopeError(RuntimeError):
    pass


def load_functions(source=SOURCE):
    """Do not execute imports, configured paths, module startup or CLI code."""
    tree = ast.parse(Path(source).read_text(encoding="utf-8"))
    selected = [node for node in tree.body
                if isinstance(node, ast.FunctionDef) and node.name in FUNCTIONS]
    assert {node.name for node in selected} == FUNCTIONS
    namespace = dict(
        Any=Any, hashlib=hashlib, json=json, math=math, re=re, secrets=secrets,
        TurnEnvelopeError=FixtureEnvelopeError,
        PROTOCOL="integrity-client/turn-envelope/v1", MAX_PROMPT_BYTES=256 * 1024,
        SEGMENT_BYTES=4096, _RESUME_CLAIM_OWNER=None,
    )
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(source), "exec"), namespace)
    return namespace


class LifecycleFixture:
    thread = "11111111-1111-4111-8111-111111111111"
    turn = "22222222-2222-4222-8222-222222222222"
    machine = "machine:fixture"
    ref = "turnref:" + "a" * 43
    claim = "claim:" + "b" * 64
    lifecycle = "lifecycle:" + "c" * 43

    def __init__(self, tmp_path, source=SOURCE):
        self.ns = load_functions(source)
        self.root = tmp_path.resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "owning-lifecycle").mkdir()
        self.lock = threading.RLock()
        self.clock = SimpleNamespace(now=100.0)
        self.ns.update(
            os=SimpleNamespace(name="posix", environ={"CODEX_THREAD_ID": self.thread}),
            time=SimpleNamespace(time=lambda: self.clock.now),
            _ensure_root=lambda _root=None: self.root,
            _default_root=lambda: self.root,
            _validate_root_ancestry=lambda _path: None,
            _validate_root=lambda _path, _details: None,
            _exclusive_root_lock=self.exclusive,
            _read=lambda path: json.loads(path.read_text(encoding="utf-8")),
            _path=lambda root, ref: root / (self.ns["_sha256_text"](ref) + ".json"),
            _unprotect=lambda _encoding, payload, _entropy: payload.encode(),
            _machine_id=lambda: self.machine,
            _owning_process_ancestor=lambda _pid, _birth: True,
            _current_owning_source=lambda _identity, **_kw: (deepcopy(self.state), self.revision),
            _resume_read_state=lambda _identity: deepcopy(self.state),
            _native_owning_head=self.native,
            _original_producer_head=self.native,
        )
        digest = self.ns["_ref_digest"](self.ref)
        self.revision = "fixture-source-revision"
        self.state = {
            "turn_id": self.turn, "turn_memory_generation": 3,
            "turn_memory_intent_id": "intent:" + digest[7:], "prompt_sha256": "d" * 64,
            "model_mcp_context_admission_id": "fixture-admission",
            "model_mcp_admission_status": "pending", "model_mcp_admission_attempted": True,
            "turn_ref": self.ref,
        }
        self.original = {
            "protocol": self.ns["PROTOCOL"], "turn_ref_digest": digest,
            "prompt_sha256": self.state["prompt_sha256"], "prompt_bytes": 7,
            "segment_count": 1, "generation": 3, "expires_epoch": 200.0,
            "expires_utc": "fixture-only", "status": "claimed",
            "claim_id_sha256": self.ns["_claim_digest"](self.claim),
            "native_identity_encoding": "fixture-plaintext-only",
            "native_identity_payload_b64": json.dumps({
                "protocol": "integrity-client/producer-native-identity/v1",
                "machine_id": self.machine, "thread_id": self.thread, "turn_id": self.turn,
            }),
            **{key + "_sha256": self.ns["_identity_hash"](value, key)
               for key, value in (("machine_id", self.machine), ("thread_id", self.thread),
                                  ("turn_id", self.turn))},
        }
        self.claim_path = self.ns["_path"](self.root, self.ref)
        self.claim_path.write_text(json.dumps(self.original), encoding="utf-8")
        self.arguments = {"registration_id": "fixture-registration", "outcome": "no-event",
                          "no_event_reason": "read-only"}
        self.name = "integrity_turn_memory_close"
        self.claims = {
            "protocol": "integrity/owning-hook-lifecycle/v1", "name": self.name,
            "arguments_sha256": self.ns["_sha256_text"](
                json.dumps(self.arguments, sort_keys=True, separators=(",", ":"))),
            "expires_epoch": 200.0, "mode": "current", "source_revision_sha256": self.revision,
            "thread_id_sha256": self.original["thread_id_sha256"],
            "turn_id_sha256": self.original["turn_id_sha256"], "generation": 3,
            "intent_id": self.state["turn_memory_intent_id"],
            "prompt_sha256": self.state["prompt_sha256"],
            "context_admission_id": self.state["model_mcp_context_admission_id"],
            "issuer_parent_pid": 123, "issuer_parent_birth": "fixture-birth",
        }
        self.handoff_path = (self.root / "owning-lifecycle"
                             / (self.ns["_sha256_text"](self.lifecycle) + ".json"))
        self.handoff_path.write_text(json.dumps({"encoding": "fixture-plaintext-only",
                                                "payload_b64": json.dumps(self.claims)}),
                                     encoding="utf-8")
        self.native_calls = 0
        self.on_native = lambda _call: None

    @contextmanager
    def exclusive(self, _root):
        with self.lock:
            yield

    def native(self, identity, turn=None):
        assert identity == self.thread
        assert turn in (None, self.turn)
        self.native_calls += 1
        result = self.on_native(self.native_calls)
        return result or {"id": self.turn, "status": "inProgress"}

    def consume(self):
        return self.ns["consume_owning_lifecycle"](self.lifecycle, self.name, self.arguments,
                                                  root=self.root)

    def bind(self):
        self.ns["bind_resume_identity_from_claim"](producer_turn_ref=self.ref,
                                                  producer_claim_id=self.claim)


def assert_unrelated_operation_unblocked(fixture, operation):
    """Pause simulated Native proof while a different chat acquires custody."""
    entered, release = threading.Event(), threading.Event()
    errors = []

    def native(_call):
        entered.set()
        if not release.wait(5):
            raise AssertionError("fixture release deadline")

    def worker():
        try:
            operation()
        except BaseException as error:
            errors.append(error)

    fixture.on_native = native
    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    acquired = False
    try:
        assert entered.wait(2), ("own operation did not reach its Native proof", errors)
        acquired = fixture.lock.acquire(timeout=0.4)
        if acquired:
            # Stand-in for an unrelated chat staging its own envelope.
            (fixture.root / "unrelated-chat-stage").write_text("fixture", encoding="utf-8")
    finally:
        if acquired:
            fixture.lock.release()
        release.set()
        thread.join(2)
    assert not thread.is_alive(), "own operation failed to finish after Native returned"
    assert not errors, errors
    assert acquired, "unrelated chat blocked while Native proof was waiting"


@pytest.mark.parametrize("operation", ["consume", "bind"])
def test_waiting_native_does_not_block_another_chat(tmp_path, operation):
    fixture = LifecycleFixture(tmp_path)
    assert_unrelated_operation_unblocked(fixture, getattr(fixture, operation))


def test_consumed_handoff_is_one_use_even_when_native_proof_fails(tmp_path):
    fixture = LifecycleFixture(tmp_path)
    fixture.on_native = lambda _call: {"id": fixture.turn, "status": "unknown"}
    with pytest.raises(FixtureEnvelopeError, match="Native source superseded"):
        fixture.consume()
    assert not fixture.handoff_path.exists()
    with pytest.raises(FileNotFoundError):
        fixture.consume()


def test_successful_consume_is_one_use(tmp_path):
    fixture = LifecycleFixture(tmp_path)
    assert fixture.consume() == fixture.claims
    assert not fixture.handoff_path.exists()
    with pytest.raises(FileNotFoundError):
        fixture.consume()


@pytest.mark.parametrize("change", ["revision", "expiry", "turn", "intent", "prompt"])
def test_consumed_handoff_rechecks_source_and_expiry_after_native(tmp_path, change):
    fixture = LifecycleFixture(tmp_path)

    def mutate(_call):
        if change == "revision":
            fixture.revision = "new-source-revision"
        elif change == "expiry":
            fixture.clock.now = 201.0
        else:
            key = {"turn": "turn_id", "intent": "turn_memory_intent_id",
                   "prompt": "prompt_sha256"}[change]
            fixture.state[key] = "changed"

    fixture.on_native = mutate
    with pytest.raises(FixtureEnvelopeError):
        fixture.consume()
    assert not fixture.handoff_path.exists(), "a failed proof must not re-arm its handoff"


def test_valid_private_claim_binds_only_the_original_identity(tmp_path):
    fixture = LifecycleFixture(tmp_path)
    fixture.bind()
    assert fixture.ns["_RESUME_CLAIM_OWNER"] == (
        fixture.thread, 3, fixture.ns["_ref_digest"](fixture.ref))


@pytest.mark.parametrize("change", ["claim", "released", "retired", "expiry", "state", "head"])
def test_bind_rejects_change_during_unlocked_native_proof(tmp_path, change):
    fixture = LifecycleFixture(tmp_path)

    def mutate(call):
        if call != 2:
            return None
        if change == "retired":
            fixture.claim_path.unlink()
        elif change in {"claim", "released"}:
            value = deepcopy(fixture.original)
            if change == "claim":
                value["claim_id_sha256"] = "e" * 64
            else:
                value["status"] = "armed"
            fixture.claim_path.write_text(json.dumps(value), encoding="utf-8")
        elif change == "expiry":
            fixture.clock.now = 201.0
        elif change == "state":
            fixture.state["turn_memory_generation"] += 1
        elif change == "head":
            return {"id": fixture.turn, "status": "completed"}
        return None

    fixture.on_native = mutate
    with pytest.raises((FixtureEnvelopeError, FileNotFoundError)):
        fixture.bind()
    assert fixture.ns["_RESUME_CLAIM_OWNER"] is None


@pytest.mark.parametrize("change", ["caller", "claim-secret", "identity-commitment"])
def test_bind_rejects_wrong_caller_secret_or_native_identity(tmp_path, change):
    fixture = LifecycleFixture(tmp_path)
    if change == "caller":
        fixture.ns["os"].environ["CODEX_THREAD_ID"] = fixture.turn
    elif change == "claim-secret":
        fixture.claim = "claim:" + "f" * 64
    else:
        value = deepcopy(fixture.original)
        value["thread_id_sha256"] = "e" * 64
        fixture.claim_path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(FixtureEnvelopeError):
        fixture.bind()
    assert fixture.native_calls == 0
    assert fixture.ns["_RESUME_CLAIM_OWNER"] is None
