"""Seat tokens and OAuth principals resolve to a server-side SeatContext."""
from datetime import datetime, timedelta, timezone

import pytest

from integrity_home.seat_policy import SeatAccessError, SeatPolicyRouter
from integrity_home.seat_registry import SeatRegistry
from integrity_home.tenant import VerifiedOAuthPrincipal


def _now(offset: int = 0) -> str:
    moment = datetime.now(timezone.utc) + timedelta(seconds=offset)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _principal(subject: str = "alice") -> VerifiedOAuthPrincipal:
    return VerifiedOAuthPrincipal(
        issuer="https://issuer.example.invalid",
        subject=subject,
        audience=("https://memory.example.invalid",),
        scopes=frozenset({"memory:read"}),
    )


def test_oauth_principal_maps_to_the_bound_seat(tmp_path):
    registry = SeatRegistry(tmp_path / "seats.sqlite3")
    registry.create_seat("alice", "Alice", ["read", "write"], ["team/*", "seat/alice/*"])
    registry.bind_identity("https://issuer.example.invalid", "alice", "alice")
    context = SeatPolicyRouter(registry).resolve_principal(_principal(), host_id="gateway")
    assert context.seat_id == "alice"
    assert context.host_id == "gateway"
    assert "write" in context.roles
    assert context.auth_principal_sha256


def test_unknown_principal_and_token_fail_closed(tmp_path):
    registry = SeatRegistry(tmp_path / "seats.sqlite3")
    router = SeatPolicyRouter(registry)
    with pytest.raises(SeatAccessError) as missing:
        router.resolve_principal(_principal())
    assert missing.value.status == 401
    with pytest.raises(SeatAccessError) as token:
        router.resolve_token("not-a-real-token", now_utc=_now())
    assert token.value.status == 401


def test_header_token_and_token_file_resolve_the_same_seat(tmp_path, monkeypatch):
    registry = SeatRegistry(tmp_path / "seats.sqlite3")
    registry.create_seat("alice", "Alice", ["read"], ["team/*"])
    issued = registry.issue_token("alice", "laptop", _now(3600))
    token_file = tmp_path / "seat.token"
    token_file.write_text(issued.token + "\n", encoding="utf-8")
    monkeypatch.setenv("INTEGRITY_SEAT_TOKEN_FILE", str(token_file))
    router = SeatPolicyRouter(registry)
    by_header = router.resolve_request(header_token=issued.token, now_utc=_now())
    by_file = router.resolve_request(now_utc=_now())
    assert by_header.seat_id == by_file.seat_id == "alice"
    assert by_header.host_id == "laptop"
    with pytest.raises(SeatAccessError) as mismatch:
        router.resolve_request(header_token="other-token", now_utc=_now())
    assert mismatch.value.status == 401


def test_expired_token_is_rejected(tmp_path):
    registry = SeatRegistry(tmp_path / "seats.sqlite3")
    registry.create_seat("alice", "Alice", ["read"], ["team/*"])
    issued = registry.issue_token("alice", "laptop", _now(60))
    with pytest.raises(SeatAccessError) as expired:
        SeatPolicyRouter(registry).resolve_token(issued.token, now_utc=_now(120))
    assert expired.value.status == 401
