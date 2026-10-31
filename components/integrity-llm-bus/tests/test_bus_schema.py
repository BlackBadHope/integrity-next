"""Strict bus messages and seat-scoped fetch, cursor, and count."""
from datetime import datetime, timezone
from hashlib import sha256

import pytest

from integrity_llm_bus.bus_server import BusCore, BusError, BusSeat, serve
from integrity_llm_bus.schema import BusSchemaError, body_sha256, load_limits, normalize_message


def _message(**overrides):
    body = overrides.pop("body", "synthetic body")
    raw = {
        "id": "msg-1",
        "from": "alice",
        "to": "bob",
        "k": "note",
        "th": "turn-1",
        "delivery": "steer",
        "body": body,
        "body_sha256": body_sha256(body),
    }
    raw.update(overrides)
    return raw


def test_defaults_to_steer_and_rejects_bad_id_and_hash():
    message = normalize_message(
        {key: value for key, value in _message().items() if key != "delivery"},
        sender="alice",
        created_utc="2026-01-01T00:00:00Z",
    )
    assert message["delivery"] == "steer"
    with pytest.raises(BusSchemaError):
        normalize_message(_message(id="bad id"), sender="alice", created_utc="2026-01-01T00:00:00Z")
    with pytest.raises(BusSchemaError):
        normalize_message(_message(body_sha256="a" * 64), sender="alice", created_utc="2026-01-01T00:00:00Z")
    huge = "x" * 70000
    with pytest.raises(BusSchemaError):
        normalize_message(_message(body=huge, body_sha256=sha256(huge.encode()).hexdigest()), sender="alice", created_utc="2026-01-01T00:00:00Z")
    assert load_limits(None)["arbiter"] == "seat_owner"


def _core(tmp_path):
    seats = {
        "alice-token": BusSeat("alice", "host-a", frozenset({"read", "write"}), ("team/*", "seat/alice/*")),
        "bob-token": BusSeat("bob", "host-b", frozenset({"read", "write"}), ("team/*", "seat/bob/*")),
        "carol-token": BusSeat("carol", "host-c", frozenset({"read", "write"}), ("seat/carol/*",)),
    }
    core = BusCore(tmp_path / "bus.sqlite3", lambda token: seats[token])
    for seat in seats.values():
        core.register_agent(seat, seat.seat_id)
    return core, seats


def test_fetch_cursor_and_count_do_not_leak_other_seats(tmp_path):
    core, seats = _core(tmp_path)
    posted = core.post(seats["alice-token"], _message())
    assert posted["namespace"] == "team/bus"
    private = _message(id="priv-1", k="private", body="secret", body_sha256=body_sha256("secret"))
    core.post(seats["alice-token"], private)
    assert core.fetch(seats["bob-token"], "msg-1")["from"] == "alice"
    with pytest.raises(BusError) as denied:
        core.fetch(seats["bob-token"], "priv-1")
    assert denied.value.status == 403
    with pytest.raises(BusError) as missing:
        core.fetch(seats["bob-token"], "missing")
    assert missing.value.status == 404
    carol = core.after(seats["carol-token"], 0)
    assert carol["messages"] == []
    assert carol["next_seq"] == 0
    assert core.meta(seats["carol-token"])["visible_count"] == 0
    assert core.meta(seats["bob-token"])["visible_count"] == 1
    with pytest.raises(BusSchemaError):
        core.post(seats["alice-token"], _message(id="spoof", **{"from": "bob"}))
    core.close()
    assert datetime.now(timezone.utc).tzinfo is not None
