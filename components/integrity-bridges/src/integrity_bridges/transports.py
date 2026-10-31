"""Host transport adapters. Unknown or unconfigured hosts fail with a structured error.

The JSON-line request is ``{"name", "arguments", "request_id"}``. This module
does not execute a caller-supplied command.
"""

from __future__ import annotations

import json

TRANSPORTS = frozenset({
    "local",
    "ssh_reverse_loopback",
    "ssh_stdio",
    "https_seat_mcp",
    "webhook",
})
LINEAGE = "0.8.0"
CANONICAL_RESOURCES = "resources/private-memory"


class TransportError(Exception):
    def __init__(self, payload: dict) -> None:
        super().__init__(payload["error"])
        self.payload = payload


def encode_request(name: str, arguments: dict, request_id: str | None = None) -> bytes:
    message = {"name": name, "arguments": arguments, "request_id": request_id}
    return json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"


class ConfiguredAdapter:
    """A configured non-loopback transport. Missing endpoint data fails closed."""

    def __init__(self, host: str, entry: dict) -> None:
        self.host = host
        self.entry = entry
        self.transport = entry.get("transport")

    def request_line(self, name: str, arguments: dict, request_id: str | None = None) -> bytes:
        return encode_request(name, arguments, request_id)

    def call(self, name: str, arguments: dict, request_id: str | None = None) -> dict:
        line = self.request_line(name, arguments, request_id)
        if not line.endswith(b"\n") or b"\n" in line[:-1]:
            raise TransportError({"error": "wire_frame_invalid", "host_id": self.host})
        endpoint = self.entry.get("endpoint") or self.entry.get("url") or self.entry.get("command")
        if not endpoint:
            raise TransportError({
                "error": "host_transport_unavailable",
                "host_id": self.host,
                "transport": self.transport,
            })
        return {
            "structuredContent": {
                "error": "host_transport_not_connected",
                "host_id": self.host,
                "transport": self.transport,
            }
        }


def open_peer(host: str, entry: dict, loopback_client):
    """Return a peer, or None when the host is not configured for a known transport.

    Callers turn None into a structured RPC error. This function does not raise
    KeyError.
    """

    transport = entry.get("transport") if isinstance(entry, dict) else None
    if transport == "ssh_reverse_loopback":
        return loopback_client(host, entry)
    if transport in TRANSPORTS:
        return ConfiguredAdapter(host, entry)
    return None
