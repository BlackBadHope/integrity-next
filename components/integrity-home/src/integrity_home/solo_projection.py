"""Standard read-only search/fetch projection for Integrity Solo Memory.

This is the storage-independent core of the remote MCP fork.  Authentication,
TLS, rate limits, and HTTP transport belong to a separate gateway process; the
model can never choose storage paths or expand the server-side scope policy.
"""

from __future__ import annotations

import json
from typing import Any, Iterable, Mapping
from urllib.parse import quote

from .tool_projection import HomeToolError, HomeToolProjection


class SoloProjectionError(ValueError):
    """Safe validation failure at the public Solo tool boundary."""


def _text_result(payload: Mapping[str, Any]) -> dict[str, object]:
    return {
        "content": [
            {
                "type": "text",
                "text": json.dumps(
                    payload,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                ),
            }
        ]
    }


class SoloKnowledgeProjection:
    """Expose the standard connector ``search`` and ``fetch`` tool contract."""

    def __init__(
        self,
        home: HomeToolProjection,
        *,
        canonical_base_url: str,
        scope_ids: Iterable[str] | None = None,
        everywhere: bool = False,
    ):
        if not isinstance(canonical_base_url, str) or not canonical_base_url.startswith(
            "https://"
        ):
            raise SoloProjectionError("canonical_base_url must use HTTPS")
        if everywhere == (scope_ids is not None):
            raise SoloProjectionError(
                "configure exactly explicit scope_ids or everywhere=true"
            )
        self._home = home
        self._base_url = canonical_base_url.rstrip("/")
        self._scope_ids = tuple(scope_ids) if scope_ids is not None else None
        if self._scope_ids is not None and not self._scope_ids:
            raise SoloProjectionError("scope_ids must not be empty")
        self._everywhere = everywhere

    def _url(self, item_id: str) -> str:
        return f"{self._base_url}/memory/{quote(item_id, safe='')}"

    def search(self, query: object) -> dict[str, object]:
        page = self.search_page(query)
        content = page["content"][0]
        payload = json.loads(content["text"])
        return _text_result({"results": payload["results"]})

    def search_page(
        self,
        query: object,
        *,
        cursor: object = None,
        limit: object = 10,
    ) -> dict[str, object]:
        if not isinstance(query, str) or not query.strip() or len(query) > 4_096:
            raise SoloProjectionError("query must be a non-empty bounded string")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 10:
            raise SoloProjectionError("limit must be between 1 and 10")
        arguments: dict[str, object] = {"query": query, "limit": limit}
        if cursor is not None:
            if not isinstance(cursor, str) or not cursor:
                raise SoloProjectionError("cursor must be a non-empty string")
            arguments["cursor"] = cursor
        if self._everywhere:
            arguments["everywhere"] = True
        else:
            arguments["scope_ids"] = list(self._scope_ids or ())
        try:
            payload = self._home.invoke("home_search", arguments)
        except HomeToolError as err:
            raise SoloProjectionError(str(err)) from err
        results: list[dict[str, str]] = []
        for item in payload.get("results", []):
            if not isinstance(item, Mapping):
                raise SoloProjectionError("local search returned an invalid result")
            item_id = item.get("handle")
            if not isinstance(item_id, str):
                continue
            title = item.get("title")
            if not isinstance(title, str) or not title.strip():
                title = item.get("excerpt")
            if not isinstance(title, str) or not title.strip():
                title = "Integrity memory result"
            results.append(
                {"id": item_id, "title": title[:256], "url": self._url(item_id)}
            )
        # Older local projections had one bounded page and no continuation
        # fields. Treat that exact legacy shape as exhausted.
        has_more = payload.get("has_more", False)
        next_cursor = payload.get("next_cursor")
        if not isinstance(has_more, bool):
            raise SoloProjectionError("local search returned invalid continuation")
        if has_more and (not isinstance(next_cursor, str) or not next_cursor):
            raise SoloProjectionError("local search returned invalid continuation")
        return _text_result(
            {
                "results": results,
                "has_more": has_more,
                "next_cursor": next_cursor if has_more else None,
            }
        )

    def fetch(self, item_id: object) -> dict[str, object]:
        if not isinstance(item_id, str) or not item_id:
            raise SoloProjectionError("id must be a non-empty string")
        try:
            payload = self._home.invoke("home_open", {"handle": item_id, "radius": 1})
        except HomeToolError as err:
            raise SoloProjectionError(str(err)) from err
        evidence = payload.get("evidence")
        if not isinstance(evidence, Mapping):
            raise SoloProjectionError("local fetch returned invalid evidence")
        title = evidence.get("title")
        if not isinstance(title, str) or not title.strip():
            title = "Integrity memory result"
        text = evidence.get("excerpt")
        if not isinstance(text, str):
            raise SoloProjectionError("local fetch returned no bounded text")
        metadata = {
            key: evidence[key]
            for key in ("provider", "created_at", "role", "scope_id")
            if key in evidence
        }
        return _text_result(
            {
                "id": item_id,
                "title": title[:256],
                "text": text,
                "url": self._url(item_id),
                "metadata": metadata,
            }
        )

    def read_memory(
        self,
        item_id: object,
        *,
        cursor: object = None,
        limit: object = 25,
    ) -> dict[str, object]:
        if not isinstance(item_id, str) or not item_id:
            raise SoloProjectionError("id must be a non-empty string")
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 25
        ):
            raise SoloProjectionError("limit must be between 1 and 25")
        arguments: dict[str, object] = {"handle": item_id, "limit": limit}
        if cursor is not None:
            if not isinstance(cursor, str) or not cursor:
                raise SoloProjectionError("cursor must be a non-empty string")
            arguments["cursor"] = cursor
        try:
            payload = self._home.invoke("home_read_memory", arguments)
        except HomeToolError as err:
            raise SoloProjectionError(str(err)) from err
        if payload.get("handle") != item_id:
            raise SoloProjectionError("local memory read returned invalid evidence")
        return _text_result(payload)
