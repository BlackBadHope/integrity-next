"""Tenant-local append-only Action Log adapter.

The public projection still speaks its existing HTTP-shaped adapter contract,
but these callables never open a listener or accept a tenant selector.  Their
only authority is the fixed path selected from a verified OAuth principal.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
import tempfile
from typing import Any

from integrity_chronicle.json_integrity import (
    DuplicateJsonKeyError,
    loads_json_strict,
)
from integrity_chronicle.state_lock import CorpusStateLockError, corpus_state_lock

from .action_log_projection import ActionLogProjectionError


MAX_ACTION_LOG_BYTES = 128 * 1024 * 1024
MAX_ACTION_LOG_EVENTS = 100_000
MAX_EVENT_LINE_BYTES = 96 * 1024


def _safe_text(value: Any, *, maximum: int, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 and character not in "\t\n\r" for character in value)
    ):
        raise ActionLogProjectionError(f"Action Log {field} is invalid")
    return value.strip()


class TenantActionLogStore:
    """Atomic JSONL event store rooted in exactly one tenant vault."""

    def __init__(self, path: str | os.PathLike[str]):
        candidate = Path(path)
        if not candidate.is_absolute():
            raise ActionLogProjectionError("tenant Action Log path must be absolute")
        try:
            parent = candidate.parent.resolve(strict=True)
            resolved = candidate.resolve(strict=False)
            resolved.relative_to(parent)
        except (OSError, RuntimeError, ValueError) as err:
            raise ActionLogProjectionError("tenant Action Log path is unsafe") from err
        if parent.is_symlink() or not parent.is_dir():
            raise ActionLogProjectionError("tenant Action Log path is unsafe")
        if candidate.exists() and (candidate.is_symlink() or not candidate.is_file()):
            raise ActionLogProjectionError("tenant Action Log path is unsafe")
        self._path = resolved

    @property
    def path(self) -> Path:
        return self._path

    def _read_unlocked(self) -> list[dict[str, Any]]:
        if not self._path.exists():
            return []
        if self._path.is_symlink() or not self._path.is_file():
            raise ActionLogProjectionError("tenant Action Log path is unsafe")
        try:
            if self._path.stat().st_size > MAX_ACTION_LOG_BYTES:
                raise ActionLogProjectionError("tenant Action Log is too large")
            events: list[dict[str, Any]] = []
            previous_id = 0
            with self._path.open("rb") as stream:
                for raw_line in stream:
                    if len(raw_line) > MAX_EVENT_LINE_BYTES:
                        raise ActionLogProjectionError(
                            "tenant Action Log contains an oversized event"
                        )
                    if not raw_line.strip():
                        continue
                    try:
                        value = loads_json_strict(raw_line.decode("utf-8"))
                    except (
                        UnicodeDecodeError,
                        json.JSONDecodeError,
                        DuplicateJsonKeyError,
                    ) as err:
                        raise ActionLogProjectionError(
                            "tenant Action Log contains invalid JSON"
                        ) from err
                    if not isinstance(value, dict):
                        raise ActionLogProjectionError(
                            "tenant Action Log contains an invalid event"
                        )
                    event_id = value.get("id")
                    if (
                        isinstance(event_id, bool)
                        or not isinstance(event_id, int)
                        or event_id != previous_id + 1
                    ):
                        raise ActionLogProjectionError(
                            "tenant Action Log event sequence is invalid"
                        )
                    events.append(value)
                    previous_id = event_id
                    if len(events) > MAX_ACTION_LOG_EVENTS:
                        raise ActionLogProjectionError(
                            "tenant Action Log has too many events"
                        )
            return events
        except OSError as err:
            raise ActionLogProjectionError("tenant Action Log is unavailable") from err

    @staticmethod
    def _encoded_event(event: Mapping[str, Any]) -> bytes:
        try:
            encoded = (
                json.dumps(
                    event,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                )
                + "\n"
            ).encode("utf-8")
        except (TypeError, ValueError) as err:
            raise ActionLogProjectionError("Action Log event is invalid") from err
        if len(encoded) > MAX_EVENT_LINE_BYTES:
            raise ActionLogProjectionError("Action Log event is too large")
        return encoded

    def _replace_unlocked(self, events: list[dict[str, Any]]) -> None:
        if self._path.exists() and self._path.is_symlink():
            raise ActionLogProjectionError("tenant Action Log path is unsafe")
        descriptor, raw_temporary = tempfile.mkstemp(
            prefix=".events-",
            suffix=".jsonl",
            dir=self._path.parent,
        )
        temporary = Path(raw_temporary)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                for event in events:
                    stream.write(self._encoded_event(event))
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.chmod(temporary, 0o600)
            except OSError:
                pass
            os.replace(temporary, self._path)
        except OSError as err:
            temporary.unlink(missing_ok=True)
            raise ActionLogProjectionError("tenant Action Log write failed") from err

    def request_json(
        self,
        _base_url: str,
        path: str,
        params: Mapping[str, object],
        _token: str | None,
    ) -> Mapping[str, Any]:
        if path != "/api/events" or not isinstance(params, Mapping):
            raise ActionLogProjectionError("Action Log request is invalid")
        try:
            with corpus_state_lock(str(self._path)):
                events = self._read_unlocked()
        except CorpusStateLockError as err:
            raise ActionLogProjectionError("tenant Action Log is busy") from err

        event_id = params.get("id")
        if event_id is not None:
            if isinstance(event_id, bool) or not isinstance(event_id, int):
                raise ActionLogProjectionError("Action Log event id is invalid")
            selected = [event for event in events if event["id"] == event_id]
            return {"ok": True, "events": selected}

        query = params.get("q")
        if not isinstance(query, str) or not query.strip() or len(query) > 4_096:
            raise ActionLogProjectionError("Action Log query is invalid")
        query_folded = query.casefold().replace("ё", "е")
        snapshot = params.get("snapshot_event_id", len(events))
        if (
            isinstance(snapshot, bool)
            or not isinstance(snapshot, int)
            or snapshot < 0
            or snapshot > len(events)
        ):
            raise ActionLogProjectionError("Action Log snapshot is invalid")
        before = params.get("before_id")
        if before is not None and (
            isinstance(before, bool) or not isinstance(before, int) or before < 1
        ):
            raise ActionLogProjectionError("Action Log pagination is invalid")
        raw_limit = params.get("page_size", params.get("limit", 20))
        if (
            isinstance(raw_limit, bool)
            or not isinstance(raw_limit, int)
            or not 1 <= raw_limit <= 20
        ):
            raise ActionLogProjectionError("Action Log page size is invalid")

        matches: list[dict[str, Any]] = []
        for event in reversed(events[:snapshot]):
            if before is not None and event["id"] >= before:
                continue
            searchable = json.dumps(
                event,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).casefold().replace("ё", "е")
            if query_folded in searchable:
                matches.append(event)
        page = matches[:raw_limit]
        has_more = len(matches) > len(page)
        next_before = page[-1]["id"] if has_more and page else None
        return {
            "ok": True,
            "events": page,
            "pagination": {
                "snapshot_event_id": snapshot,
                "has_more": has_more,
                "next_before_id": next_before,
            },
        }

    def write_json(
        self,
        _base_url: str,
        path: str,
        payload: Mapping[str, object],
        _token: str | None,
    ) -> Mapping[str, Any]:
        if path != "/api/events" or not isinstance(payload, Mapping):
            raise ActionLogProjectionError("Action Log write is invalid")
        allowed = {
            "actor",
            "level",
            "action",
            "summary",
            "details",
            "tags",
            "event_uid",
        }
        if set(payload) != allowed:
            raise ActionLogProjectionError("Action Log write fields are invalid")
        actor = _safe_text(payload.get("actor"), maximum=128, field="actor")
        level = _safe_text(payload.get("level"), maximum=32, field="level")
        action = _safe_text(payload.get("action"), maximum=128, field="action")
        summary = _safe_text(payload.get("summary"), maximum=2_000, field="summary")
        details = payload.get("details")
        tags = payload.get("tags")
        event_uid = payload.get("event_uid")
        if not isinstance(details, Mapping) or any(
            not isinstance(key, str) for key in details
        ):
            raise ActionLogProjectionError("Action Log details are invalid")
        if (
            not isinstance(tags, list)
            or len(tags) > 32
            or any(
                not isinstance(tag, str)
                or not tag
                or len(tag) > 64
                for tag in tags
            )
        ):
            raise ActionLogProjectionError("Action Log tags are invalid")
        if not isinstance(event_uid, str) or len(event_uid) > 256:
            raise ActionLogProjectionError("Action Log event uid is invalid")

        try:
            with corpus_state_lock(str(self._path)):
                events = self._read_unlocked()
                if event_uid:
                    for existing in events:
                        if existing.get("event_uid") == event_uid:
                            return {
                                "ok": True,
                                "id": existing["id"],
                                "duplicate": True,
                            }
                if len(events) >= MAX_ACTION_LOG_EVENTS:
                    raise ActionLogProjectionError(
                        "tenant Action Log event limit reached"
                    )
                event = {
                    "id": len(events) + 1,
                    "ts_utc": datetime.now(timezone.utc)
                    .isoformat(timespec="seconds")
                    .replace("+00:00", "Z"),
                    "actor": actor,
                    "level": level,
                    "action": action,
                    "summary": summary,
                    "details": dict(details),
                    "tags": list(dict.fromkeys(tags)),
                    "event_uid": event_uid or "tenant-memory:" + secrets.token_hex(16),
                }
                self._encoded_event(event)
                events.append(event)
                self._replace_unlocked(events)
                return {"ok": True, "id": event["id"], "duplicate": False}
        except CorpusStateLockError as err:
            raise ActionLogProjectionError("tenant Action Log is busy") from err


__all__ = [
    "MAX_ACTION_LOG_BYTES",
    "MAX_ACTION_LOG_EVENTS",
    "TenantActionLogStore",
]
