"""Owner can sign a GO. Bob, who can only read, cannot approve."""
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from integrity_home.seat_policy import SeatAccessError, SeatPolicyRouter
from integrity_home.seat_registry import SeatRegistry
from integrity_llm_bus.mesh import Mesh
from integrity_llm_bus.seat_verify import GoLedger, canonical_go
from integrity_space.seat_hub import SeatHubError, dispatch_seat_tool, wrap_peer_memory


def _utc(offset_seconds: int) -> str:
    moment = datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def test_read_seat_cannot_approve_and_owner_go_unblocks(tmp_path):
    registry = SeatRegistry(tmp_path / "seats.sqlite3")
    registry.create_seat("seat_owner", "Owner", ["read", "write", "go_approver", "admin"], ["team/*", "seat/seat_owner/*"])
    registry.create_seat("alice", "Alice", ["read", "write"], ["team/*", "seat/alice/*"])
    registry.create_seat("bob", "Bob", ["read"], ["team/*", "seat/bob/*"])
    router = SeatPolicyRouter(registry)
    now = _utc(0)
    owner = router.resolve_token(registry.issue_token("seat_owner", "core", _utc(600)).token, now_utc=now)
    alice = router.resolve_token(registry.issue_token("alice", "host-a", _utc(600)).token, now_utc=now)
    bob = router.resolve_token(registry.issue_token("bob", "host-b", _utc(600)).token, now_utc=now)

    assert dispatch_seat_tool("seat_whoami", {}, bob)["seat_id"] == "bob"
    with pytest.raises(SeatHubError) as denied:
        dispatch_seat_tool("seat_whoami", {"seat_id": "alice"}, bob)
    assert denied.value.status == 403
    with pytest.raises(SeatHubError) as bob_note:
        dispatch_seat_tool("seat_append_note", {"note": "no"}, bob)
    assert bob_note.value.status == 403
    assert dispatch_seat_tool("seat_append_note", {"note": "yes"}, alice)["seat_id"] == "alice"
    with pytest.raises(SeatAccessError):
        router.authorize(bob, "team/work", "write")

    mesh = Mesh(tmp_path / "mesh.sqlite3")
    moment = datetime.now(timezone.utc)
    opened = mesh.open("alice", "work-1", "shared", "team/work", now=moment)
    request = mesh.decision_request("alice", "work-1", "ab" * 32, now=moment)
    key = ed25519.Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")
    registry.register_signing_key("owner-key", "seat_owner", "Ed25519", public, now)
    payload = {
        "approver_seat": "seat_owner",
        "key_id": "owner-key",
        "core_instance_id": "core-local",
        "msg_id": "go-owner-1",
        "th": "turn-1",
        "decision_ref": ("ab" * 32)[:12] + "-ok",
        "request_digest": "ab" * 32,
        "request_seq": request["seq"],
        "action": "mesh.decision",
        "scope": "team/work",
        "created_utc": now,
        "expires_utc": _utc(60),
    }
    signature = key.sign(canonical_go(payload))
    ledger = GoLedger(tmp_path / "go.sqlite3", core_instance_id="core-local")

    def lookup(seat_id, key_id):
        if seat_id != "seat_owner" or "go_approver" not in owner.roles:
            return None
        return {"alg": "Ed25519", "public_key": public, "roles": owner.roles, "retired_at": None}

    assert ledger.consume(payload, signature, now=datetime.now(timezone.utc), decision_seq=request["seq"] + 1, lookup=lookup)["ok"]
    decision = mesh.decision("seat_owner", "work-1", request_seq=request["seq"], detail={"by": "seat_owner"}, now=moment)
    assert decision["seq"] > request["seq"]
    peer = wrap_peer_memory({"seat_id": "alice", "body": "note"}, "bob")
    assert peer["trust"] == "untrusted_peer_memory"
    assert opened["kind"] == "open"
    mesh.close()
