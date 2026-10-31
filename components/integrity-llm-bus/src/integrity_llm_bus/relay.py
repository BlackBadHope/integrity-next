"""Steer by default. A failed steer is not a queue delivery.

Prompts receive a pointer only. Webhook URL and workdir come from config.
"""

from __future__ import annotations

import uuid

POINTER_FIELDS = ("id", "from", "reply_to", "delivery", "body_sha256")
RETRY_NAMESPACE = uuid.UUID("6ba7b811-9dad-11d1-80b4-00c04fd430c8")


class SteerFailure(Exception):
    def __init__(self, reason: str, *, stale_turn: bool = False) -> None:
        super().__init__(reason)
        self.reason = reason
        self.stale_turn = stale_turn


def pointer(message: dict, *, message_id: str | None = None) -> dict:
    value = {
        "id": message_id or message["id"],
        "from": message["from"],
        "reply_to": message.get("reply_to"),
        "delivery": message.get("delivery") or "steer",
        "body_sha256": message["body_sha256"],
    }
    return {key: value[key] for key in POINTER_FIELDS}


def deliver(message: dict, transport, config: dict) -> dict:
    """Return an explicit status. pull is never delivered. queue is never a fallback."""

    if not isinstance(config, dict):
        return {"status": "not_sent:config_invalid", "delivered": False, "queued": False}
    if any(key in message for key in ("webhook_url", "workdir", "command")):
        return {"status": "not_sent:config_only", "delivered": False, "queued": False}
    delivery = message.get("delivery") or "steer"
    if delivery == "pull":
        return {"status": "route=pull", "delivered": False, "queued": False}
    if delivery == "queue":
        if not config.get("queue_enabled"):
            return {"status": "not_sent:queue_not_enabled", "delivered": False, "queued": False}
        transport.enqueue(pointer(message), config=config)
        return {"status": "queued", "delivered": False, "queued": True}
    if delivery != "steer":
        return {"status": "not_sent:delivery_invalid", "delivered": False, "queued": False}
    notice = pointer(message)
    try:
        transport.steer(notice, config=config)
        return {"status": "steered", "delivered": True, "queued": False, "pointer": notice}
    except SteerFailure as exc:
        if not exc.stale_turn:
            return {"status": f"not_sent:{exc.reason}", "delivered": False, "queued": False}
        retry_id = str(uuid.uuid5(RETRY_NAMESPACE, message["id"] + "|" + message.get("th", "")))
        retry = pointer(message, message_id=retry_id)
        try:
            transport.steer(retry, config=config)
        except SteerFailure as retry_exc:
            return {
                "status": f"not_sent:{retry_exc.reason}",
                "delivered": False,
                "queued": False,
                "delivery_failed": True,
            }
        return {"status": "steered", "delivered": True, "queued": False, "retried": True, "pointer": retry}
    except Exception as exc:  # noqa: BLE001
        return {"status": f"not_sent:{type(exc).__name__}", "delivered": False, "queued": False, "delivery_failed": True}
