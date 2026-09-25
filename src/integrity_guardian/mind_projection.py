"""Incremental Mind projection: fold the tail, never replay the archive.

A heartbeat refreshes the clock over the working set. Full rebuild is recovery
only. The model still receives a bounded capsule; this module is the derived
index underneath that capsule.
"""

from __future__ import annotations

from typing import Any, Literal

from .agent_session_gate import ADMISSION_TTL_HOURS
from .schemas import validate

PROTOCOL = "integrity-guardian/mind-projection-checkpoint/v1"
MIND_PROJECTION_PROTOCOL = PROTOCOL
MIND_HEARTBEAT_SECONDS = 300
RebuildKind = Literal["incremental", "clock-refresh", "full-recovery"]
LIFECYCLE_ACTIONS = {
    "agent_change_start",
    "agent_change_progress",
    "agent_change_resumed",
    "agent_change_pending",
    "agent_change_paused",
    "agent_change_complete",
    "agent_change_blocked",
    "agent_change_failed",
    "agent_session_admission",
}
CLOSE_STATUS = {
    "agent_change_complete": "complete",
    "agent_change_blocked": "blocked",
    "agent_change_failed": "failed",
}


class MindProjectionError(ValueError):
    """Raised when a projection cursor cannot be trusted."""


class IncrementalMindProjection:
    """O(delta) task fold. Heartbeat is O(open tasks), not O(history)."""

    def __init__(self) -> None:
        self.cursor = 0
        self.event_count = 0
        self.tasks: dict[str, dict[str, Any]] = {}
        self.events_folded = 0
        self.full_rebuilds = 0
        self.last_kind: RebuildKind = "full-recovery"

    def checkpoint(self, *, generated_utc: str, events_scanned: int) -> dict[str, Any]:
        payload = {
            "protocol": PROTOCOL,
            "rebuild_kind": self.last_kind,
            "event_cursor": self.cursor,
            "events_folded": self.events_folded,
            "events_scanned": events_scanned,
            "task_count": len(self.tasks),
            "heartbeat_seconds": MIND_HEARTBEAT_SECONDS,
            "admission_ttl_hours": ADMISSION_TTL_HOURS,
            "production_authority": False,
            "generated_utc": generated_utc,
        }
        validate("mind-projection-checkpoint", payload)
        return payload

    def recover(self, events: list[dict[str, Any]], *, generated_utc: str) -> dict[str, Any]:
        self.cursor = 0
        self.event_count = 0
        self.tasks = {}
        self.events_folded = 0
        self.full_rebuilds += 1
        self.last_kind = "full-recovery"
        return self.apply(events, generated_utc=generated_utc, kind="full-recovery")

    def apply(
        self,
        events: list[dict[str, Any]],
        *,
        generated_utc: str,
        kind: RebuildKind = "incremental",
    ) -> dict[str, Any]:
        scanned = 0
        for event in events:
            event_id = int(event.get("id") or 0)
            if event_id <= self.cursor:
                continue
            if self.cursor and event_id > self.cursor + 1 and kind != "full-recovery":
                raise MindProjectionError("projection cursor gap; full recovery required")
            self._fold(event)
            scanned += 1
        self.last_kind = kind
        return self.checkpoint(generated_utc=generated_utc, events_scanned=scanned)

    def heartbeat_clock(self, *, generated_utc: str) -> dict[str, Any]:
        """Time moved; history did not. Do not rescan the event stream."""

        self.last_kind = "clock-refresh"
        return self.checkpoint(generated_utc=generated_utc, events_scanned=0)

    def advance(
        self,
        tail: list[dict[str, Any]],
        *,
        store_count: int,
        store_max: int,
        generated_utc: str,
    ) -> dict[str, Any]:
        """Fold only the new tail. Clock-only is a heartbeat. Gaps fail closed."""

        if store_max < self.cursor or store_count < self.event_count:
            raise MindProjectionError("event store shrank; full recovery required")
        if store_max == self.cursor:
            return self.heartbeat_clock(generated_utc=generated_utc)
        if self.cursor == 0:
            raise MindProjectionError("empty projection requires recover")
        if not tail or int(tail[0].get("id") or 0) != self.cursor + 1:
            raise MindProjectionError("projection cursor gap; full recovery required")
        return self.apply(tail, generated_utc=generated_utc, kind="incremental")

    def _fold(self, event: dict[str, Any]) -> None:
        event_id = int(event.get("id") or 0)
        self.cursor = max(self.cursor, event_id)
        self.event_count += 1
        self.events_folded += 1
        action = str(event.get("action") or "")
        if action not in LIFECYCLE_ACTIONS:
            return
        details = event.get("details") if isinstance(event.get("details"), dict) else {}
        task_id = str(details.get("task_id") or "").strip()
        if not task_id:
            return
        current = self.tasks.get(task_id)
        if current is None:
            current = {
                "task_id": task_id,
                "status": "open",
                "session_id": str(event.get("session_id") or ""),
                "first_session_id": str(event.get("session_id") or ""),
                "agent_id": "",
                "agent_product": "",
                "admission_declared_at": "",
                "admission_expires_at": "",
                "capability_class": [],
                "next_action": "",
                "depends_on_task_ids": [],
                "history_count": 0,
            }
            self.tasks[task_id] = current
        current["history_count"] = int(current.get("history_count") or 0) + 1
        current["session_id"] = str(event.get("session_id") or current.get("session_id") or "")
        current["last_id"] = event_id
        next_action = str(details.get("next_action") or "").strip()
        if next_action:
            current["next_action"] = next_action
        if "depends_on_task_ids" in details:
            current["depends_on_task_ids"] = [
                str(item).strip()
                for item in (details.get("depends_on_task_ids") or [])
                if str(item).strip()
            ]
        if action == "agent_session_admission":
            agent = details.get("agent") if isinstance(details.get("agent"), dict) else {}
            agent_id = str(agent.get("agent_id") or details.get("agent_id") or "")
            if agent_id:
                current["agent_id"] = agent_id
            product = str(agent.get("product") or details.get("agent_product") or "")
            if product:
                current["agent_product"] = product
            declared = str(details.get("declared_at") or event.get("ts_utc") or "")
            if declared:
                current["admission_declared_at"] = declared
            expires = str(details.get("expires_at") or "")
            current["admission_expires_at"] = expires
            classes = details.get("capability_class")
            if isinstance(classes, list):
                current["capability_class"] = [str(item) for item in classes if str(item).strip()]
        if action in CLOSE_STATUS:
            current["status"] = CLOSE_STATUS[action]
        elif action == "agent_change_pending":
            current["status"] = "pending"
        elif action == "agent_change_paused":
            current["status"] = "paused"
        elif action in {"agent_change_start", "agent_change_progress", "agent_change_resumed"}:
            current["status"] = "open"
