"""Namespace globs fail closed across seats."""
import pytest

from integrity_home.seat_policy import SeatAccessError, SeatPolicyRouter, namespace_allowed
from integrity_home.seat_registry import SeatRegistry


def _router(tmp_path):
    registry = SeatRegistry(tmp_path / "seats.sqlite3")
    registry.create_seat("alice", "Alice", ["read", "write"], ["team/*", "seat/alice/*"])
    registry.create_seat("bob", "Bob", ["read"], ["team/*", "seat/bob/*"])
    return SeatPolicyRouter(registry), registry


def test_alice_sees_team_and_her_seat_but_not_bob(tmp_path):
    router, registry = _router(tmp_path)
    alice = router.resolve_token(
        registry.issue_token("alice", "host-a", "2099-01-01T00:00:00Z").token,
        now_utc="2026-01-01T00:00:00Z",
    )
    visible = [
        namespace for namespace in ("team/default", "seat/alice/notes", "seat/bob/notes")
        if namespace_allowed(alice.namespaces, namespace)
    ]
    assert visible == ["team/default", "seat/alice/notes"]
    router.authorize(alice, "team/default", "read")
    router.authorize(alice, "seat/alice/notes", "write")
    with pytest.raises(SeatAccessError) as denied:
        router.authorize(alice, "seat/bob/notes", "write")
    assert denied.value.status == 403


def test_bob_cannot_write_team_or_alice(tmp_path):
    router, registry = _router(tmp_path)
    bob = router.resolve_token(
        registry.issue_token("bob", "host-b", "2099-01-01T00:00:00Z").token,
        now_utc="2026-01-01T00:00:00Z",
    )
    router.authorize(bob, "team/default", "read")
    with pytest.raises(SeatAccessError) as denied:
        router.authorize(bob, "team/default", "write")
    assert denied.value.status == 403
    assert namespace_allowed(bob.namespaces, "seat/alice/notes") is False
