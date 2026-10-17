"""Read-session binding rejects tampering without a database or live host."""
import datetime as dt
import pytest
from integrity_action_log import read_session as reader


def declaration():
    now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    envelope = {"native_identity_hashes": {"machine_id": "a" * 64,
                 "thread_id": "b" * 64, "turn_id": "c" * 64},
                "turn_ref_digest": "sha256:" + "d" * 64,
                "prompt_sha256": "e" * 64,
                "expires_utc": (now + dt.timedelta(seconds=60)).isoformat()}
    return reader.issue(envelope, product="codex", now=now), now


def test_snapshot_bound_request_is_authenticated_and_has_no_action_authority():
    value, now = declaration()
    proof = reader.request_proof(value, snapshot_event_id=1, token="unit-test-only")
    accepted = reader.accept({"declaration": value, "proof": proof, "snapshot_event_id": 1},
                             token="unit-test-only", now=now)
    assert accepted["external_action_authority"] is False
    with pytest.raises(reader.ReadSessionError, match="proof mismatch"):
        reader.accept({"declaration": value, "proof": proof, "snapshot_event_id": 2},
                      token="unit-test-only", now=now)


def test_prompt_turn_and_expiry_are_enforced():
    value, now = declaration()
    with pytest.raises(reader.ReadSessionError, match="binding mismatch"):
        reader.validate(value, prompt_sha256="f" * 64, now=now)
    with pytest.raises(reader.ReadSessionError, match="outside its window"):
        reader.validate(value, now=now + dt.timedelta(minutes=2))
    changed = dict(value, external_action_authority=True)
    with pytest.raises(reader.ReadSessionError, match="identity invalid"):
        reader.validate(changed, now=now)
