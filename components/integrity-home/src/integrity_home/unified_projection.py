"""Unified read-only search across Integrity Home and Integrity Seed."""

from __future__ import annotations

import json
import re
import secrets
from collections import OrderedDict
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .action_log_projection import (
    ActionLogKnowledgeProjection,
    ActionLogProjectionError,
)
from .solo_projection import (
    SoloKnowledgeProjection,
    SoloProjectionError,
    _text_result,
)

MAX_RESULTS = 20
MAX_UNIFIED_CURSORS = 256


@dataclass(frozen=True)
class _UnifiedSearchCursor:
    query: str
    action_cursor: str | None
    home_cursor: str | None
    action_exhausted: bool
    home_exhausted: bool


class UnifiedProjectionError(ValueError):
    """Safe failure at the unified Integrity memory boundary."""


def _payload(result: Mapping[str, Any]) -> Mapping[str, Any]:
    content = result.get("content")
    if not isinstance(content, list) or len(content) != 1:
        raise UnifiedProjectionError("memory source returned invalid content")
    item = content[0]
    if not isinstance(item, Mapping) or item.get("type") != "text":
        raise UnifiedProjectionError("memory source returned invalid content")
    text = item.get("text")
    if not isinstance(text, str):
        raise UnifiedProjectionError("memory source returned invalid content")
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as err:
        raise UnifiedProjectionError("memory source returned invalid JSON") from err
    if not isinstance(parsed, Mapping):
        raise UnifiedProjectionError("memory source returned invalid payload")
    return parsed


def _results(payload: Mapping[str, Any]) -> list[dict[str, str]]:
    raw = payload.get("results")
    if not isinstance(raw, list):
        raise UnifiedProjectionError("memory source returned invalid results")
    results: list[dict[str, str]] = []
    for item in raw:
        if not isinstance(item, Mapping):
            raise UnifiedProjectionError("memory source returned an invalid result")
        if set(item) != {"id", "title", "url"}:
            raise UnifiedProjectionError("memory source returned an invalid result")
        if not all(isinstance(item[key], str) for key in ("id", "title", "url")):
            raise UnifiedProjectionError("memory source returned an invalid result")
        results.append(dict(item))
    return results


def _balanced_merge(
    action_log: list[dict[str, str]],
    home: list[dict[str, str]],
) -> list[dict[str, str]]:
    merged: list[dict[str, str]] = []
    index = 0
    while len(merged) < MAX_RESULTS and (
        index < len(action_log) or index < len(home)
    ):
        if index < len(action_log):
            merged.append(action_log[index])
            if len(merged) == MAX_RESULTS:
                break
        if index < len(home):
            merged.append(home[index])
        index += 1
    return merged[:MAX_RESULTS]


class UnifiedKnowledgeProjection:
    """Federate current operational events with imported conversation history."""

    def __init__(
        self,
        *,
        home: SoloKnowledgeProjection,
        action_log: ActionLogKnowledgeProjection,
    ):
        self._home = home
        self._action_log = action_log
        self._search_cursors: OrderedDict[str, _UnifiedSearchCursor] = OrderedDict()

    def search(self, query: object) -> dict[str, object]:
        source_results: dict[str, list[dict[str, str]]] = {}
        source_metadata: dict[str, Mapping[str, Any]] = {}
        degraded: list[str] = []
        try:
            action_payload = _payload(self._action_log.search(query))
            source_results["action_log"] = _results(action_payload)
            if isinstance(action_payload.get("metadata"), Mapping):
                source_metadata["action_log"] = action_payload["metadata"]
        except ActionLogProjectionError:
            degraded.append("action_log")
        try:
            home_payload = _payload(self._home.search(query))
            source_results["home"] = _results(home_payload)
            if isinstance(home_payload.get("metadata"), Mapping):
                source_metadata["home"] = home_payload["metadata"]
        except SoloProjectionError:
            degraded.append("home")
        if len(degraded) == 2:
            raise UnifiedProjectionError("Integrity memory sources are unavailable")
        results = _balanced_merge(
            source_results.get("action_log", []),
            source_results.get("home", []),
        )
        possibly_truncated_sources: list[str] = []
        if source_metadata.get("action_log", {}).get("possibly_truncated") is True:
            possibly_truncated_sources.append("integrity-seed-action-log")
        if len(results) >= MAX_RESULTS and (
            sum(len(value) for value in source_results.values()) > len(results)
        ):
            possibly_truncated_sources.append("unified-result-page")
        return _text_result(
            {
                "results": results,
                "metadata": {
                    "queried_sources": [
                        "integrity-seed-action-log",
                        "integrity-home-chronicle",
                    ],
                    "degraded_sources": degraded,
                    "source_result_counts": {
                        "integrity-seed-action-log": len(
                            source_results.get("action_log", [])
                        ),
                        "integrity-home-chronicle": len(
                            source_results.get("home", [])
                        ),
                    },
                    "returned_result_count": len(results),
                    "result_limit": MAX_RESULTS,
                    "possibly_truncated_sources": possibly_truncated_sources,
                },
            }
        )

    def fetch(self, item_id: object) -> dict[str, object]:
        try:
            if self._action_log.owns(item_id):
                return self._action_log.fetch(item_id)
            return self._home.fetch(item_id)
        except (ActionLogProjectionError, SoloProjectionError) as err:
            raise UnifiedProjectionError(str(err)) from err

    def read_action_log_event(self, event_id: object) -> dict[str, object]:
        try:
            return self._action_log.read_event(event_id)
        except ActionLogProjectionError as err:
            raise UnifiedProjectionError(str(err)) from err

    def search_memory(
        self,
        query: object,
        *,
        cursor: object = None,
    ) -> dict[str, object]:
        if not isinstance(query, str) or not query.strip() or len(query) > 4_096:
            raise UnifiedProjectionError("query must be a non-empty bounded string")
        if cursor is None:
            state = _UnifiedSearchCursor(
                query=query,
                action_cursor=None,
                home_cursor=None,
                action_exhausted=False,
                home_exhausted=False,
            )
        else:
            if not isinstance(cursor, str) or not re.fullmatch(
                r"ium_[A-Za-z0-9_-]{24,64}", cursor
            ):
                raise UnifiedProjectionError("search cursor is invalid or expired")
            state = self._search_cursors.get(cursor)
            if state is None or state.query != query:
                raise UnifiedProjectionError("search cursor is invalid or expired")

        action_results: list[dict[str, str]] = []
        home_results: list[dict[str, str]] = []
        action_cursor = state.action_cursor
        home_cursor = state.home_cursor
        action_exhausted = state.action_exhausted
        home_exhausted = state.home_exhausted
        degraded: list[str] = []
        if not action_exhausted:
            try:
                action_payload = _payload(
                    self._action_log.search_page(
                        query, cursor=action_cursor, limit=10
                    )
                )
                action_results = _results(action_payload)
                action_has_more = action_payload.get("has_more")
                if not isinstance(action_has_more, bool):
                    raise UnifiedProjectionError(
                        "Action Log returned invalid continuation"
                    )
                action_cursor = (
                    action_payload.get("next_cursor") if action_has_more else None
                )
                if action_has_more and not isinstance(action_cursor, str):
                    raise UnifiedProjectionError(
                        "Action Log returned invalid continuation"
                    )
                action_exhausted = not action_has_more
            except ActionLogProjectionError:
                degraded.append("action_log")
        if not home_exhausted:
            try:
                home_payload = _payload(
                    self._home.search_page(query, cursor=home_cursor, limit=10)
                )
                home_results = _results(home_payload)
                home_has_more = home_payload.get("has_more")
                if not isinstance(home_has_more, bool):
                    raise UnifiedProjectionError(
                        "Home returned invalid continuation"
                    )
                home_cursor = home_payload.get("next_cursor") if home_has_more else None
                if home_has_more and not isinstance(home_cursor, str):
                    raise UnifiedProjectionError(
                        "Home returned invalid continuation"
                    )
                home_exhausted = not home_has_more
            except SoloProjectionError:
                degraded.append("home")
        if (
            ("action_log" in degraded or action_exhausted)
            and ("home" in degraded or home_exhausted)
            and not action_results
            and not home_results
            and len(degraded) == 2
        ):
            raise UnifiedProjectionError("Integrity memory sources are unavailable")

        results = _balanced_merge(action_results, home_results)
        has_more = not action_exhausted or not home_exhausted
        next_cursor: str | None = None
        if cursor is not None:
            self._search_cursors.pop(cursor, None)
        if has_more:
            next_cursor = "ium_" + secrets.token_urlsafe(24)
            self._search_cursors[next_cursor] = _UnifiedSearchCursor(
                query=query,
                action_cursor=action_cursor,
                home_cursor=home_cursor,
                action_exhausted=action_exhausted,
                home_exhausted=home_exhausted,
            )
            self._search_cursors.move_to_end(next_cursor)
            while len(self._search_cursors) > MAX_UNIFIED_CURSORS:
                self._search_cursors.popitem(last=False)
        return _text_result(
            {
                "results": results,
                "has_more": has_more,
                "next_cursor": next_cursor,
                "metadata": {
                    "queried_sources": [
                        "integrity-seed-action-log",
                        "integrity-home-chronicle",
                    ],
                    "degraded_sources": degraded,
                    "source_result_counts": {
                        "integrity-seed-action-log": len(action_results),
                        "integrity-home-chronicle": len(home_results),
                    },
                    "returned_result_count": len(results),
                    "memory_search_exhausted": not has_more,
                },
            }
        )

    def read_memory(
        self,
        item_id: object,
        *,
        cursor: object = None,
        limit: object = 25,
    ) -> dict[str, object]:
        try:
            if self._action_log.owns(item_id):
                if cursor is not None:
                    raise UnifiedProjectionError(
                        "Action Log events do not have continuation pages"
                    )
                fetched = _payload(self._action_log.fetch(item_id))
                return _text_result(
                    {
                        **dict(fetched),
                        "memory_start": 0,
                        "memory_end": 0,
                        "message_count": 1,
                        "page_start_ordinal": 0,
                        "page_end_ordinal": 0,
                        "has_more": False,
                        "next_cursor": None,
                    }
                )
            return self._home.read_memory(item_id, cursor=cursor, limit=limit)
        except (ActionLogProjectionError, SoloProjectionError) as err:
            raise UnifiedProjectionError(str(err)) from err

    def remember_memory(
        self,
        *,
        title: object,
        memory: object,
        tags: object = None,
        idempotency_key: object = None,
    ) -> dict[str, object]:
        try:
            return self._action_log.remember(
                title=title,
                memory=memory,
                tags=tags,
                idempotency_key=idempotency_key,
            )
        except ActionLogProjectionError as err:
            raise UnifiedProjectionError(str(err)) from err


__all__ = [
    "UnifiedKnowledgeProjection",
    "UnifiedProjectionError",
]
