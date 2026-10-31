"""Revoked seats and tokens fail closed, including epoch mismatch."""
import pytest

from integrity_home.seat_policy import SeatAccessError, SeatPolicyRouter
from integrity_home.seat_registry import SeatRegistry


def test_revoked_token_and_revoked_seat_are_rejected(tmp_path):
    registry = SeatRegistry(tmp_path / "seats.sqlite3")
    registry.create_seat("alice", "Alice", ["read", "write"], ["team/*"])
    issued = registry.issue_token("alice", "host-a", "2099-01-01T00:00:00Z")
    router = SeatPolicyRouter(registry)
    registry.revoke_token(issued.token)
    with pytest.raises(SeatAccessError) as token:
        router.resolve_token(issued.token, now_utc="2026-01-01T00:00:00Z")
    assert token.value.status == 401
    replacement = registry.issue_token("alice", "host-a", "2099-01-01T00:00:00Z")
    registry.revoke_seat("alice")
    with pytest.raises(SeatAccessError) as seat:
        router.resolve_token(replacement.token, now_utc="2026-01-01T00:00:00Z")
    assert seat.value.status == 403
    stored = registry.get_seat("alice")
    assert stored.status == "revoked"
    assert stored.revocation_epoch == 1
