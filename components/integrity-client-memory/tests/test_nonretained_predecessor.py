"""Synthetic protected predecessor classification; no live state or transport.

The classifier may accept an older same-owner cache for a separately proven
non-retained OPEN. It must leave that cache intact and must never make it a
current-generation recovery descriptor.
"""
import base64
import contextlib
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path

import pytest


RESOURCE = (Path(__file__).resolve().parents[1] / "src/integrity_client_memory"
            / "resources/windows/integrity_client_turn_envelope.py")
pytestmark = pytest.mark.skipif(os.name != "nt", reason="real Windows DPAPI/CNG fixture")


def sha(value):
    return hashlib.sha256(value.encode()).hexdigest()


def digest(value):
    return "sha256:" + sha(value)


def payload(identity, machine, turn, generation):
    ref = digest("synthetic-ref-" + turn)
    binding = {
        "hashes": {"machine_id": sha(machine), "thread_id": sha(identity), "turn_id": sha(turn)},
        "generation": generation,
        "intent_id": "intent:" + ref[7:],
        "prompt_sha256": sha("synthetic-prompt-" + turn),
        "turn_ref_digest": ref,
        "project_scope_sha256": sha("synthetic-project"),
        "context_admission_id": digest("synthetic-admission-" + turn),
        "admitted": True,
    }
    prompt = {key: binding[key] for key in
              ("generation", "prompt_sha256", "turn_ref_digest", "project_scope_sha256")}
    prompt.update(protocol="integrity-client/turn-envelope/v1", prompt_bytes=32,
                  segment_count=1, prompt_coverage="text-only", truncation=False)
    return {
        "protocol": "integrity-client/own-context-resume/v1",
        "binding": binding,
        "control": {"replay_id": digest("synthetic-replay-" + turn),
                    "request_digest": digest("synthetic-request-" + turn),
                    "response_digest": digest("synthetic-response-" + turn),
                    "context_admission_id": binding["context_admission_id"],
                    "snapshot_id": digest("synthetic-snapshot"),
                    "prompt_binding": prompt, "logical_generation": generation},
    }


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("nonretained_fixture_envelope", RESOURCE)
    envelope = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(envelope)
    identity, machine = "synthetic-thread", "machine:synthetic"
    predecessor = payload(identity, machine, "old-turn", 7)
    current = payload(identity, machine, "current-turn", 8)["binding"]
    directory = tmp_path / "own-context-resume"
    directory.mkdir()
    path = directory / (sha(identity) + ".json")
    monkeypatch.setattr(envelope, "_resume_identity", lambda: identity)
    monkeypatch.setattr(envelope, "_machine_id", lambda: machine)
    monkeypatch.setattr(envelope, "_resume_directory", lambda **_: (tmp_path, directory))
    monkeypatch.setattr(envelope, "_exclusive_root_lock", lambda _: contextlib.nullcontext())
    # Custody is isolated to this pytest temp directory; no installed paths/ACLs.
    monkeypatch.setattr(envelope, "_read", lambda p: json.loads(p.read_bytes()))
    monkeypatch.setattr(envelope, "_resume_read_state", lambda _: {
        "protocol": "integrity-memory/session-state/v1", "session_hash": sha(identity),
        "turn_id": "current-turn", "turn_memory_generation": 8,
        "turn_memory_intent_id": current["intent_id"],
        "prompt_sha256": current["prompt_sha256"],
    })
    monkeypatch.setattr(envelope, "_native_owning_head",
                        lambda _: {"id": "current-turn", "status": "inProgress"})

    def write(value):
        raw = envelope._canonical({"protocol": envelope._RESUME_STORAGE,
                                   "delivered": True, "payload": value})
        entropy = "own-context-resume:" + sha(identity)
        encoding, protected = envelope._protect(raw, entropy)
        assert encoding in {"dpapi-current-user/v1", "cng-local-logon/v1"}
        assert envelope._unprotect(encoding, protected, entropy) == raw
        path.write_bytes(envelope._canonical({"protocol": envelope._RESUME_STORAGE,
                                              "encoding": encoding, "payload_b64": protected}))
        return path.read_bytes()

    return envelope, predecessor, current, path, write


def test_protected_older_same_owner_cache_is_read_only_and_never_restored(fixture):
    envelope, predecessor, current, path, write = fixture
    original = write(predecessor)
    assert envelope.assert_nonretained_context_resume(current) is None
    assert path.read_bytes() == original
    with pytest.raises(envelope.TurnEnvelopeError, match="resume own identity mismatch"):
        envelope.load_context_resume()
    assert path.read_bytes() == original


@pytest.mark.parametrize("case", ["current-generation", "future-generation", "foreign-machine",
                                  "foreign-thread", "same-turn", "same-ref", "same-admission"])
def test_conflicting_predecessors_deny_without_mutating_bytes(fixture, case):
    envelope, predecessor, current, path, write = fixture
    predecessor = copy.deepcopy(predecessor)
    old = predecessor["binding"]
    if case in {"current-generation", "future-generation"}:
        generation = current["generation"] + (case == "future-generation")
        old["generation"] = generation
        predecessor["control"]["prompt_binding"]["generation"] = generation
    elif case == "foreign-machine":
        old["hashes"]["machine_id"] = sha("machine:foreign")
    elif case == "foreign-thread":
        old["hashes"]["thread_id"] = sha("foreign-thread")
    elif case == "same-turn":
        old["hashes"]["turn_id"] = current["hashes"]["turn_id"]
    elif case == "same-ref":
        old["turn_ref_digest"] = current["turn_ref_digest"]
        old["intent_id"] = current["intent_id"]
        predecessor["control"]["prompt_binding"]["turn_ref_digest"] = current["turn_ref_digest"]
    else:
        old["context_admission_id"] = current["context_admission_id"]
        predecessor["control"]["context_admission_id"] = current["context_admission_id"]
    original = write(predecessor)
    with pytest.raises(envelope.TurnEnvelopeError, match="non-retained admission conflicts"):
        envelope.assert_nonretained_context_resume(current)
    assert path.read_bytes() == original


@pytest.mark.parametrize("case", ["ciphertext", "outer-schema", "protected-schema"])
def test_corruption_denies_and_preserves_original_corrupt_evidence(fixture, case):
    envelope, predecessor, current, path, write = fixture
    if case == "protected-schema":
        predecessor["binding"]["generation"] = True
        write(predecessor)
    else:
        write(predecessor)
        outer = json.loads(path.read_bytes())
        if case == "ciphertext":
            protected = bytearray(base64.b64decode(outer["payload_b64"]))
            protected[len(protected) // 2] ^= 1
            outer["payload_b64"] = base64.b64encode(protected).decode("ascii")
        else:
            outer["unexpected"] = "synthetic"
        path.write_bytes(envelope._canonical(outer))
    original = path.read_bytes()
    with pytest.raises(envelope.TurnEnvelopeError):
        envelope.assert_nonretained_context_resume(current)
    assert path.read_bytes() == original


def test_missing_descriptor_does_not_create_one(fixture):
    envelope, _predecessor, current, path, _write = fixture
    assert not path.exists()
    assert envelope.assert_nonretained_context_resume(current) is None
    assert envelope.load_context_resume() is None
    assert not path.exists()
