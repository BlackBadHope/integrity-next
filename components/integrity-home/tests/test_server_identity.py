"""Integrity Seats server names and deprecated aliases."""
from __future__ import annotations

import pytest

from integrity_home.server_identity import (
    DEPRECATED_ALIASES,
    SEATS,
    SEATS_BRIDGE,
    ServerNameError,
    resolve_server_name,
)


def test_default_names_are_integrity_seats():
    assert resolve_server_name(None, canonical=SEATS) == SEATS
    assert resolve_server_name("", canonical=SEATS_BRIDGE) == SEATS_BRIDGE


def test_deprecated_alias_is_accepted_for_its_canonical_name():
    with pytest.warns(DeprecationWarning, match="deprecated alias"):
        assert (
            resolve_server_name("integrity-private-memory", canonical=SEATS)
            == "integrity-private-memory"
        )
    with pytest.warns(DeprecationWarning, match="deprecated alias"):
        assert (
            resolve_server_name(
                "integrity-private-memory-codex-bridge", canonical=SEATS_BRIDGE
            )
            == "integrity-private-memory-codex-bridge"
        )


def test_alias_does_not_cross_canonical_names():
    with pytest.raises(ServerNameError):
        resolve_server_name("integrity-private-memory", canonical=SEATS_BRIDGE)
    with pytest.raises(ServerNameError):
        resolve_server_name("not-a-server", canonical=SEATS)


def test_alias_table_points_at_canonical_names():
    assert set(DEPRECATED_ALIASES.values()) <= {SEATS, SEATS_BRIDGE}
