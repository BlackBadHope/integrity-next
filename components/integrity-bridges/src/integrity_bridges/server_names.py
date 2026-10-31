"""Canonical MCP server names and deprecated aliases.

Kept aligned with ``integrity_home.server_identity``. Bridges do not depend on
that package, so the alias table lives here as well. New processes advertise
Integrity Seats. ``--server-name`` or ``values.server_name`` may still pass a
retired identifier. That alias is accepted with a deprecation warning.
"""

from __future__ import annotations

import warnings

SEATS = "integrity-seats"
SEATS_BRIDGE = "integrity-seats-bridge"

DEPRECATED_ALIASES = {
    "integrity-private-memory": SEATS,
    "integrity-private-memory-tenant": SEATS,
    "integrity-private-memory-codex-bridge": SEATS_BRIDGE,
}


class ServerNameError(ValueError):
    """The requested server name is not the canonical name or a known alias."""


def resolve_server_name(requested: str | None, *, canonical: str) -> str:
    if canonical not in {SEATS, SEATS_BRIDGE}:
        raise ServerNameError("unknown canonical server name")
    if requested is None or requested == "":
        return canonical
    if (
        not isinstance(requested, str)
        or requested != requested.strip()
        or any(character.isspace() for character in requested)
        or len(requested) > 128
    ):
        raise ServerNameError("server name is invalid")
    if requested == canonical:
        return requested
    mapped = DEPRECATED_ALIASES.get(requested)
    if mapped == canonical:
        warnings.warn(
            f"{requested} is a deprecated alias of {canonical}",
            DeprecationWarning,
            stacklevel=2,
        )
        return requested
    raise ServerNameError("unknown server name")


def configured_server_name(document: dict | None) -> str | None:
    """Read an optional ``values.server_name`` without requiring the key."""

    if not isinstance(document, dict):
        return None
    values = document.get("values", {})
    if not isinstance(values, dict) or "server_name" not in values:
        return None
    raw = values.get("server_name")
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise ServerNameError("server name is invalid")
    return raw
