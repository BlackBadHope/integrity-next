"""Strict agent-bus-1 messages. Bodies are untrusted data, never commands."""

from __future__ import annotations

from hashlib import sha256
import json
import re
from pathlib import Path

ID_RE = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z")
KIND_RE = re.compile(r"[a-z][a-z0-9._:-]{0,63}\Z")
SHA_RE = re.compile(r"[a-f0-9]{64}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
DELIVERIES = frozenset({"steer", "queue", "pull"})
MAX_MESSAGE_BYTES = 65536
SCHEMA_PATH = Path(__file__).with_name("agent-bus-1.schema.json")


class BusSchemaError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def body_sha256(body: str) -> str:
    if not isinstance(body, str):
        raise BusSchemaError("body invalid")
    return sha256(body.encode("utf-8")).hexdigest()


def message_bytes(message: dict) -> int:
    encoded = json.dumps(message, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return len(encoded)


def normalize_message(raw: dict, *, sender: str, created_utc: str) -> dict:
    """Fill server-owned fields and reject anything outside the strict shape."""

    if not isinstance(raw, dict):
        raise BusSchemaError("message invalid")
    if any(key in raw for key in ("seat_id", "host_id", "sender_seat", "auth_principal_sha256")):
        raise BusSchemaError("identity is server-derived")
    delivery = raw.get("delivery", "steer")
    message = {
        "id": raw.get("id"),
        "from": sender,
        "to": raw.get("to"),
        "k": raw.get("k"),
        "th": raw.get("th"),
        "delivery": delivery,
        "body": raw.get("body"),
        "body_sha256": raw.get("body_sha256"),
        "created_utc": created_utc,
    }
    if "reply_to" in raw:
        message["reply_to"] = raw["reply_to"]
    if raw.get("from") not in (None, sender):
        raise BusSchemaError("from must match the authenticated seat")
    _validate(message)
    if message_bytes(message) > MAX_MESSAGE_BYTES:
        raise BusSchemaError("message too large")
    return message


def _validate(message: dict) -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    allowed = set(schema["properties"])
    required = set(schema["required"])
    if set(message) - allowed or not required <= set(message):
        raise BusSchemaError("message fields invalid")
    if not isinstance(message["id"], str) or ID_RE.fullmatch(message["id"]) is None:
        raise BusSchemaError("id invalid")
    if not isinstance(message["from"], str) or ID_RE.fullmatch(message["from"]) is None:
        raise BusSchemaError("from invalid")
    if not isinstance(message["to"], str) or ID_RE.fullmatch(message["to"]) is None or message["to"] == message["from"]:
        raise BusSchemaError("to invalid")
    if not isinstance(message["k"], str) or KIND_RE.fullmatch(message["k"]) is None:
        raise BusSchemaError("k invalid")
    if not isinstance(message["th"], str) or ID_RE.fullmatch(message["th"]) is None:
        raise BusSchemaError("th invalid")
    reply = message.get("reply_to", None)
    if reply is not None and (not isinstance(reply, str) or ID_RE.fullmatch(reply) is None):
        raise BusSchemaError("reply_to invalid")
    if message["delivery"] not in DELIVERIES:
        raise BusSchemaError("delivery invalid")
    body = message["body"]
    if not isinstance(body, str) or not body:
        raise BusSchemaError("body invalid")
    if message["body_sha256"] != body_sha256(body):
        raise BusSchemaError("body_sha256 mismatch")
    if not isinstance(message["created_utc"], str) or UTC_RE.fullmatch(message["created_utc"]) is None:
        raise BusSchemaError("created_utc invalid")


def load_limits(document: dict | None = None) -> dict:
    """Arbiter defaults to seat_owner. Callers pass a limits object, not a URL."""

    if document is None:
        return {"arbiter": "seat_owner"}
    if not isinstance(document, dict) or set(document) - {"arbiter"}:
        raise BusSchemaError("limits invalid")
    arbiter = document.get("arbiter", "seat_owner")
    if not isinstance(arbiter, str) or ID_RE.fullmatch(arbiter) is None:
        raise BusSchemaError("arbiter invalid")
    return {"arbiter": arbiter}
