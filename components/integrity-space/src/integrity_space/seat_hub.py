"""Seat-scoped hub tools. Identity comes from SeatContext, never from tool arguments.

search and fetch stay on their existing handlers. These tools are additive.
"""

from __future__ import annotations

import re

ID_RE = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z")
PROFILES = {
    "web-seat": {"roles": ("read", "write"), "namespaces": ("team/*", "seat/<id>/*")},
    "workstation-agent": {"roles": ("read", "write"), "namespaces": ("team/*", "seat/<id>/*")},
    "core-operator": {
        "roles": ("read", "write", "go_approver", "admin"),
        "namespaces": ("team/*", "seat/<id>/*"),
    },
}
ALLOWED_UPSTREAMS = {
    "example-memory": "https://example.invalid/integrity-seats",
}
SEAT_TOOL_NAMES = ("seat_whoami", "seat_append_note", "mesh_status", "bus_post_message")


class SeatHubError(PermissionError):
    def __init__(self, code: str, status: int = 403) -> None:
        super().__init__(code)
        self.code = code
        self.status = status


def tool_definitions() -> list[dict]:
    empty = {"type": "object", "properties": {}, "additionalProperties": False}
    ident = {"type": "string", "pattern": r"^[A-Za-z0-9._:-]{1,128}$"}
    return [
        {"name": "seat_whoami", "description": "Return the server-derived seat. Ignores any seat id in arguments.",
         "inputSchema": empty, "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False}},
        {"name": "seat_append_note", "description": "Append a note when the seat has write. The note is untrusted data.",
         "inputSchema": {"type": "object", "properties": {"note": {"type": "string", "minLength": 1, "maxLength": 4000}},
                          "required": ["note"], "additionalProperties": False},
         "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False}},
        {"name": "mesh_status", "description": "Read mesh status visible to this seat.",
         "inputSchema": {"type": "object", "properties": {"work_id": ident}, "required": ["work_id"], "additionalProperties": False},
         "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False}},
        {"name": "bus_post_message", "description": "Post a bus pointer for a seat with write. Does not accept a URL.",
         "inputSchema": {"type": "object", "properties": {"upstream_id": ident, "body": {"type": "string", "minLength": 1, "maxLength": 4000}},
                          "required": ["upstream_id", "body"], "additionalProperties": False},
         "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False}},
    ]


def resolve_upstream(upstream_id: str) -> str:
    if not isinstance(upstream_id, str) or ID_RE.fullmatch(upstream_id) is None or "://" in upstream_id:
        raise SeatHubError("upstream id invalid", 400)
    if upstream_id not in ALLOWED_UPSTREAMS:
        raise SeatHubError("upstream not allowlisted", 403)
    return ALLOWED_UPSTREAMS[upstream_id]


def wrap_peer_memory(record: dict, reader_seat: str) -> dict:
    wrapped = dict(record)
    if wrapped.get("seat_id") != reader_seat:
        wrapped["trust"] = "untrusted_peer_memory"
    return wrapped


def _reject_identity_arguments(arguments: dict) -> None:
    if not isinstance(arguments, dict):
        raise SeatHubError("arguments invalid", 400)
    if any(key in arguments for key in ("seat_id", "host_id", "roles", "url", "upstream_url")):
        raise SeatHubError("identity is server-derived", 403)


def _require(context, role: str) -> None:
    if context is None:
        raise SeatHubError("seat required", 401)
    roles = set(getattr(context, "roles", ()) or ())
    if role not in roles and "admin" not in roles:
        raise SeatHubError(role + " forbidden", 403)


def dispatch_seat_tool(name: str, arguments: dict, context, *, mesh_status: dict | None = None) -> dict:
    _reject_identity_arguments(arguments or {})
    if name == "seat_whoami":
        if context is None:
            raise SeatHubError("seat required", 401)
        return {
            "seat_id": context.seat_id,
            "host_id": context.host_id,
            "roles": sorted(context.roles),
            "namespaces": list(context.namespaces),
        }
    if name == "seat_append_note":
        _require(context, "write")
        note = (arguments or {}).get("note")
        if not isinstance(note, str) or not note.strip():
            raise SeatHubError("note invalid", 400)
        return {"ok": True, "seat_id": context.seat_id, "namespace": f"seat/{context.seat_id}/notes", "stored": True}
    if name == "mesh_status":
        if context is None:
            raise SeatHubError("seat required", 401)
        work_id = (arguments or {}).get("work_id")
        if not isinstance(work_id, str) or ID_RE.fullmatch(work_id) is None:
            raise SeatHubError("work id invalid", 400)
        status = dict(mesh_status or {"work_id": work_id, "state": "unknown"})
        return wrap_peer_memory(status, context.seat_id)
    if name == "bus_post_message":
        _require(context, "write")
        upstream = resolve_upstream((arguments or {}).get("upstream_id"))
        return {"ok": True, "seat_id": context.seat_id, "upstream": upstream, "delivered": False, "delivery": "steer"}
    raise SeatHubError("unknown seat tool", 404)
