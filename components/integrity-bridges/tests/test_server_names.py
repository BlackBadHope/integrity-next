"""Integrity Seats bridge server names and config aliases."""
from __future__ import annotations

import pytest

from integrity_bridges.server_names import (
    SEATS_BRIDGE,
    ServerNameError,
    configured_server_name,
    resolve_server_name,
)


def test_default_bridge_name():
    assert resolve_server_name(None, canonical=SEATS_BRIDGE) == SEATS_BRIDGE


def test_config_alias_is_optional_and_deprecated():
    assert configured_server_name({"values": {}}) is None
    assert configured_server_name({"values": {"server_name": None}}) is None
    assert (
        configured_server_name(
            {"values": {"server_name": "integrity-private-memory-codex-bridge"}}
        )
        == "integrity-private-memory-codex-bridge"
    )
    with pytest.warns(DeprecationWarning):
        assert (
            resolve_server_name(
                configured_server_name(
                    {"values": {"server_name": "integrity-private-memory-codex-bridge"}}
                ),
                canonical=SEATS_BRIDGE,
            )
            == "integrity-private-memory-codex-bridge"
        )


def test_unknown_config_name_fails_closed():
    with pytest.raises(ServerNameError):
        resolve_server_name("other-server", canonical=SEATS_BRIDGE)
    with pytest.raises(ServerNameError):
        configured_server_name({"values": {"server_name": 7}})
