"""Canonical MCP server names and deprecated aliases.

New processes advertise Integrity Seats. ``--server-name`` or configuration may
still pass a retired identifier. That alias is accepted with a deprecation
warning and is the name the process advertises, so existing clients that pin
the old name keep working. Unknown names fail closed.
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
    """Return the name to advertise.

    ``None`` or ``""`` selects ``canonical``. A deprecated alias is returned
    unchanged after a ``DeprecationWarning`` when it maps to that canonical
    name. Any other value raises ``ServerNameError``.
    """

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
