"""Read-only projection of the live Integrity Seed Action Log.

The Action Log API address is an operator setting, never a tool argument.  The
public MCP surface receives opaque, process-local handles and can only search
or fetch bounded event evidence.
"""

from __future__ import annotations

import json
import re
import secrets
from collections import OrderedDict, deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, NamedTuple
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import Request, urlopen

from integrity_chronicle.json_integrity import (
    DuplicateJsonKeyError,
    loads_json_strict,
)

from .solo_projection import _text_result

MAX_API_RESPONSE_BYTES = 2 * 1_024 * 1_024
MAX_EVENT_TEXT_CHARS = 24 * 1_024
MAX_HANDLES = 256
MAX_QUERY_VARIANTS = 8
MAX_SEARCH_RESULTS = 20
ACTION_LOG_QUERY_LIMIT = 20
_HANDLE_PREFIX = "ial_"
_CURSOR_PREFIX = "ialc_"
_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{12,}={0,2}"),
    re.compile(r"(?i)\b(password|passwd|token|secret)\s*[:=]\s*\S+"),
)
_DETAIL_FIELDS: tuple[str, ...] = (
    "result",
    "note",
    "verification",
    "next_action",
    "scope",
    "done_when",
    "risk",
    "rollback",
    "truth_status",
)
_QUERY_WORD_RE = re.compile(r"[^\W_]+(?:[’'][^\W_]+)*", re.UNICODE)


class _QueryTermGroup(NamedTuple):
    prefixes: tuple[str, ...]
    english: str
    russian: str
    ukrainian: str
    aliases: tuple[str, ...]


# Action Log summaries are intentionally compact and are frequently recorded
# in English even when the owner request was written in Russian or Ukrainian.
# These are deterministic product-domain aliases, not semantic/model output.
_QUERY_TERM_GROUPS: tuple[_QueryTermGroup, ...] = (
    _QueryTermGroup(
        ("concept", "концепт", "концепц", "концепці"),
        "concept",
        "концепт",
        "концепт",
        ("concept", "концепт", "концепц", "концепці"),
    ),
    _QueryTermGroup(
        ("memory", "memories", "памят", "пам'ят", "пам’ят"),
        "memory",
        "памят",
        "пам'ят",
        ("memory", "памят", "пам'ят", "пам’ят"),
    ),
    _QueryTermGroup(
        ("agent", "агент"),
        "agent",
        "агент",
        "агент",
        ("agent", "агент"),
    ),
    _QueryTermGroup(
        ("project", "проект", "проєкт"),
        "project",
        "проект",
        "проєкт",
        ("project", "проект", "проєкт"),
    ),
    _QueryTermGroup(
        ("architect", "архитектур", "архітектур"),
        "architecture",
        "архитектур",
        "архітектур",
        ("architecture", "architect", "архитектур", "архітектур"),
    ),
    _QueryTermGroup(
        ("protocol", "протокол"),
        "protocol",
        "протокол",
        "протокол",
        ("protocol", "протокол"),
    ),
    _QueryTermGroup(
        ("product", "продукт"),
        "product",
        "продукт",
        "продукт",
        ("product", "продукт"),
    ),
    _QueryTermGroup(
        ("task", "задач", "завдан"),
        "task",
        "задач",
        "завдан",
        ("task", "задач", "завдан"),
    ),
    _QueryTermGroup(
        ("idea", "идея", "идеи", "идею", "ідея", "ідеї", "ідею"),
        "idea",
        "идея",
        "ідея",
        ("idea", "идея", "идеи", "идею", "ідея", "ідеї", "ідею"),
    ),
)


class ActionLogProjectionError(ValueError):
    """Safe failure at the live Action Log read boundary."""


@dataclass
class _ActionSearchState:
    query: str
    variants: tuple[str, ...]
    snapshot_event_id: int | None = None
    next_before_id: dict[str, int | None] = field(default_factory=dict)
    exhausted: set[str] = field(default_factory=set)
    buffers: dict[str, deque[Mapping[str, Any]]] = field(default_factory=dict)
    seen_event_ids: set[int] = field(default_factory=set)
    next_variant: int = 0


def _normalized_query_word(value: str) -> str:
    return value.casefold().replace("ё", "е")


def _query_group(value: str) -> _QueryTermGroup | None:
    normalized = _normalized_query_word(value)
    for group in _QUERY_TERM_GROUPS:
        if any(normalized.startswith(prefix) for prefix in group.prefixes):
            return group
    return None


def _replace_query_words(
    source: str,
    matches: list[tuple[int, int, _QueryTermGroup]],
    language: str,
) -> str:
    pieces: list[str] = []
    cursor = 0
    for start, end, group in matches:
        pieces.append(source[cursor:start])
        pieces.append(getattr(group, language))
        cursor = end
    pieces.append(source[cursor:])
    return "".join(pieces)


def _query_variants(value: str) -> tuple[str, ...]:
    source = " ".join(value.split())
    variants: list[str] = []

    def add(candidate: str) -> None:
        if (
            candidate
            and len(candidate) <= 4_096
            and candidate not in variants
            and len(variants) < MAX_QUERY_VARIANTS
        ):
            variants.append(candidate)

    add(source)
    matches: list[tuple[int, int, _QueryTermGroup]] = []
    for match in _QUERY_WORD_RE.finditer(source):
        group = _query_group(match.group(0))
        if group is not None:
            matches.append((match.start(), match.end(), group))
    if not matches:
        return tuple(variants)

    # Whole-query language projections come first so a mixed or translated
    # owner prompt can still find a compact English operational summary.
    for language in ("english", "russian", "ukrainian"):
        add(_replace_query_words(source, matches, language))

    # A one-word query may need another morphological stem. Multi-word
    # requests deliberately stop at the three whole-query projections rather
    # than creating a Cartesian product.
    if len(matches) == 1:
        start, end, group = matches[0]
        for alias in group.aliases:
            add(source[:start] + alias + source[end:])
    return tuple(variants)


def _validated_loopback_base_url(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ActionLogProjectionError("Action Log base URL is required")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "::1", "localhost"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ActionLogProjectionError(
            "Action Log base URL must be a loopback HTTP origin"
        )
    try:
        port = parsed.port
    except ValueError as err:
        raise ActionLogProjectionError("Action Log base URL has an invalid port") from err
    if port is None:
        raise ActionLogProjectionError("Action Log base URL must include a port")
    return value.rstrip("/")


def _redact_secrets(value: str) -> str:
    redacted = value
    for pattern in _SECRET_PATTERNS:
        if pattern.groups:
            redacted = pattern.sub(lambda match: f"{match.group(1)}=[redacted]", redacted)
        else:
            redacted = pattern.sub("[redacted]", redacted)
    return redacted


def _bounded_public_text(value: Any, *, maximum: int) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        rendered = value
    elif isinstance(value, (bool, int, float)):
        rendered = str(value)
    else:
        try:
            rendered = json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
        except (TypeError, ValueError):
            return None
    normalized = " ".join(rendered.replace("\x00", " ").split())
    if not normalized:
        return None
    normalized = _redact_secrets(normalized)
    if len(normalized) > maximum:
        normalized = normalized[: maximum - 1].rstrip() + "…"
    return normalized


def _default_request_json(
    base_url: str,
    path: str,
    params: Mapping[str, object],
    token: str | None,
) -> Mapping[str, Any]:
    url = f"{base_url}{path}?{urlencode(params)}"
    headers = {"Accept": "application/json"}
    if token:
        headers["X-Codex-Log-Token"] = token
    request = Request(url, headers=headers, method="GET")
    try:
        with urlopen(request, timeout=4.0) as response:
            if response.status != 200:
                raise ActionLogProjectionError("Action Log request failed closed")
            raw = response.read(MAX_API_RESPONSE_BYTES + 1)
    except (HTTPError, URLError, TimeoutError, OSError) as err:
        raise ActionLogProjectionError("Action Log is unavailable") from err
    if len(raw) > MAX_API_RESPONSE_BYTES:
        raise ActionLogProjectionError("Action Log response is too large")
    try:
        decoded = raw.decode("utf-8")
        payload = loads_json_strict(decoded)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        DuplicateJsonKeyError,
    ) as err:
        raise ActionLogProjectionError("Action Log returned invalid JSON") from err
    if not isinstance(payload, Mapping):
        raise ActionLogProjectionError("Action Log returned an invalid response")
    return payload


def _default_write_json(
    base_url: str,
    path: str,
    payload: Mapping[str, object],
    token: str | None,
) -> Mapping[str, Any]:
    if not token:
        raise ActionLogProjectionError("Action Log write token is unavailable")
    raw_body = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    if len(raw_body) > 64 * 1_024:
        raise ActionLogProjectionError("Action Log write is too large")
    request = Request(
        f"{base_url}{path}",
        data=raw_body,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Codex-Log-Token": token,
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=4.0) as response:
            if response.status != 201:
                raise ActionLogProjectionError("Action Log write failed closed")
            raw = response.read(MAX_API_RESPONSE_BYTES + 1)
    except (HTTPError, URLError, TimeoutError, OSError) as err:
        raise ActionLogProjectionError("Action Log is unavailable") from err
    if len(raw) > MAX_API_RESPONSE_BYTES:
        raise ActionLogProjectionError("Action Log response is too large")
    try:
        payload = loads_json_strict(raw.decode("utf-8"))
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        DuplicateJsonKeyError,
    ) as err:
        raise ActionLogProjectionError("Action Log returned invalid JSON") from err
    if not isinstance(payload, Mapping):
        raise ActionLogProjectionError("Action Log returned an invalid response")
    return payload


class ActionLogKnowledgeProjection:
    """Expose live Action Log events through opaque search/fetch handles."""

    def __init__(
        self,
        *,
        base_url: str,
        canonical_base_url: str,
        token: str | None = None,
        request_json: Callable[
            [str, str, Mapping[str, object], str | None], Mapping[str, Any]
        ] = _default_request_json,
        write_json: Callable[
            [str, str, Mapping[str, object], str | None], Mapping[str, Any]
        ] = _default_write_json,
    ):
        self._base_url = _validated_loopback_base_url(base_url)
        if (
            not isinstance(canonical_base_url, str)
            or not canonical_base_url.startswith("https://")
        ):
            raise ActionLogProjectionError("canonical base URL must use HTTPS")
        self._canonical_base_url = canonical_base_url.rstrip("/")
        self._token = token
        self._request_json = request_json
        self._write_json = write_json
        self._handles: OrderedDict[str, int] = OrderedDict()
        self._search_cursors: OrderedDict[str, _ActionSearchState] = OrderedDict()

    def owns(self, item_id: object) -> bool:
        return isinstance(item_id, str) and item_id.startswith(_HANDLE_PREFIX)

    def _issue_handle(self, event_id: int) -> str:
        handle = _HANDLE_PREFIX + secrets.token_urlsafe(24)
        self._handles[handle] = event_id
        self._handles.move_to_end(handle)
        while len(self._handles) > MAX_HANDLES:
            self._handles.popitem(last=False)
        return handle

    def _canonical_url(self, event_id: int) -> str:
        return f"{self._canonical_base_url}/action-log/{quote(str(event_id), safe='')}"

    @staticmethod
    def _events(payload: Mapping[str, Any]) -> list[Mapping[str, Any]]:
        if payload.get("ok") is not True:
            raise ActionLogProjectionError("Action Log request failed closed")
        raw_events = payload.get("events")
        if not isinstance(raw_events, list):
            raise ActionLogProjectionError("Action Log returned invalid events")
        events: list[Mapping[str, Any]] = []
        for item in raw_events:
            if not isinstance(item, Mapping):
                raise ActionLogProjectionError("Action Log returned an invalid event")
            event_id = item.get("id")
            if isinstance(event_id, bool) or not isinstance(event_id, int) or event_id < 1:
                raise ActionLogProjectionError("Action Log event id is invalid")
            events.append(item)
        return events

    @staticmethod
    def _pagination(payload: Mapping[str, Any]) -> Mapping[str, Any]:
        pagination = payload.get("pagination")
        if not isinstance(pagination, Mapping):
            raise ActionLogProjectionError("Action Log pagination is unavailable")
        snapshot = pagination.get("snapshot_event_id")
        has_more = pagination.get("has_more")
        next_before = pagination.get("next_before_id")
        if (
            isinstance(snapshot, bool)
            or not isinstance(snapshot, int)
            or snapshot < 0
            or not isinstance(has_more, bool)
            or (
                next_before is not None
                and (
                    isinstance(next_before, bool)
                    or not isinstance(next_before, int)
                    or next_before < 1
                )
            )
        ):
            raise ActionLogProjectionError("Action Log pagination is invalid")
        return pagination

    def search_page(
        self,
        query: object,
        *,
        cursor: object = None,
        limit: object = 10,
    ) -> dict[str, object]:
        if not isinstance(query, str) or not query.strip() or len(query) > 4_096:
            raise ActionLogProjectionError("query must be a non-empty bounded string")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 20:
            raise ActionLogProjectionError("limit must be between 1 and 20")
        state: _ActionSearchState
        if cursor is None:
            variants = _query_variants(query)
            state = _ActionSearchState(
                query=query,
                variants=variants,
                next_before_id={variant: None for variant in variants},
                buffers={variant: deque() for variant in variants},
            )
        else:
            if not isinstance(cursor, str) or not re.fullmatch(
                r"ialc_[A-Za-z0-9_-]{24,64}", cursor
            ):
                raise ActionLogProjectionError("search cursor is invalid or expired")
            state = self._search_cursors.get(cursor)
            if state is None or state.query != query:
                raise ActionLogProjectionError("search cursor is invalid or expired")

        results: list[dict[str, str]] = []
        variant_count = len(state.variants)
        while len(results) < limit and variant_count:
            progressed = False
            for _ in range(variant_count):
                variant = state.variants[state.next_variant]
                state.next_variant = (state.next_variant + 1) % variant_count
                buffer = state.buffers[variant]
                if not buffer and variant not in state.exhausted:
                    params: dict[str, object] = {
                        "q": variant,
                        "page_size": min(20, limit),
                        "since": "87600h",
                        "order": "desc",
                    }
                    if state.snapshot_event_id is not None:
                        params["snapshot_event_id"] = state.snapshot_event_id
                    before_id = state.next_before_id[variant]
                    if before_id is not None:
                        params["before_id"] = before_id
                    payload = self._request_json(
                        self._base_url,
                        "/api/events",
                        params,
                        self._token,
                    )
                    events = self._events(payload)
                    pagination = self._pagination(payload)
                    snapshot = int(pagination["snapshot_event_id"])
                    if state.snapshot_event_id is None:
                        state.snapshot_event_id = snapshot
                    elif snapshot != state.snapshot_event_id:
                        raise ActionLogProjectionError(
                            "Action Log snapshot changed during search"
                        )
                    buffer.extend(events)
                    if pagination["has_more"] is True:
                        state.next_before_id[variant] = int(
                            pagination["next_before_id"]
                        )
                    else:
                        state.exhausted.add(variant)
                        state.next_before_id[variant] = None
                if not buffer:
                    continue
                progressed = True
                event = buffer.popleft()
                event_id = int(event["id"])
                if event_id in state.seen_event_ids:
                    continue
                state.seen_event_ids.add(event_id)
                title = _bounded_public_text(event.get("summary"), maximum=220)
                if not title:
                    title = _bounded_public_text(event.get("action"), maximum=220)
                if not title:
                    title = f"Action Log event #{event_id}"
                results.append(
                    {
                        "id": self._issue_handle(event_id),
                        "title": f"[Action Log #{event_id}] {title}",
                        "url": self._canonical_url(event_id),
                    }
                )
                break
            if not progressed:
                break

        has_more = any(state.buffers[variant] for variant in state.variants) or any(
            variant not in state.exhausted for variant in state.variants
        )
        if cursor is not None:
            self._search_cursors.pop(cursor, None)
        next_cursor: str | None = None
        if has_more:
            next_cursor = _CURSOR_PREFIX + secrets.token_urlsafe(24)
            self._search_cursors[next_cursor] = state
            self._search_cursors.move_to_end(next_cursor)
            while len(self._search_cursors) > MAX_HANDLES:
                self._search_cursors.popitem(last=False)
        return _text_result(
            {
                "results": results,
                "has_more": has_more,
                "next_cursor": next_cursor,
                "metadata": {
                    "query_mode": "literal-plus-bounded-domain-aliases",
                    "query_variant_count": len(state.variants),
                    "snapshot_event_id": state.snapshot_event_id,
                    "result_count": len(results),
                    "possibly_truncated": has_more,
                },
            }
        )

    def search(self, query: object) -> dict[str, object]:
        if not isinstance(query, str) or not query.strip() or len(query) > 4_096:
            raise ActionLogProjectionError("query must be a non-empty bounded string")
        variants = _query_variants(query)
        results: list[dict[str, str]] = []
        seen_event_ids: set[int] = set()
        possibly_truncated = False
        queried_variant_count = 0
        for variant in variants:
            queried_variant_count += 1
            payload = self._request_json(
                self._base_url,
                "/api/events",
                {
                    "q": variant,
                    "limit": ACTION_LOG_QUERY_LIMIT,
                    "since": "87600h",
                },
                self._token,
            )
            events = self._events(payload)
            if len(events) >= ACTION_LOG_QUERY_LIMIT:
                possibly_truncated = True
            for event in events:
                event_id = int(event["id"])
                if event_id in seen_event_ids:
                    continue
                seen_event_ids.add(event_id)
                title = _bounded_public_text(event.get("summary"), maximum=220)
                if not title:
                    title = _bounded_public_text(event.get("action"), maximum=220)
                if not title:
                    title = f"Action Log event #{event_id}"
                results.append(
                    {
                        "id": self._issue_handle(event_id),
                        "title": f"[Action Log #{event_id}] {title}",
                        "url": self._canonical_url(event_id),
                    }
                )
                if len(results) >= MAX_SEARCH_RESULTS:
                    possibly_truncated = True
                    break
            if len(results) >= MAX_SEARCH_RESULTS:
                break
        return _text_result(
            {
                "results": results,
                "metadata": {
                    "query_mode": "literal-plus-bounded-domain-aliases",
                    "query_variant_count": queried_variant_count,
                    "result_count": len(results),
                    "possibly_truncated": possibly_truncated,
                },
            }
        )

    def read_event(self, event_id: object) -> dict[str, object]:
        """Read one exact event through the existing authorized projection."""
        if (
            isinstance(event_id, bool)
            or not isinstance(event_id, int)
            or not 1 <= event_id <= 9_223_372_036_854_775_807
        ):
            raise ActionLogProjectionError("event_id must be a positive 64-bit integer")
        handle = self._issue_handle(event_id)
        try:
            return self.fetch(handle)
        except Exception:
            self._handles.pop(handle, None)
            raise

    def fetch(self, item_id: object) -> dict[str, object]:
        if not isinstance(item_id, str) or not item_id:
            raise ActionLogProjectionError("id must be a non-empty string")
        event_id = self._handles.get(item_id)
        if event_id is None:
            raise ActionLogProjectionError(
                "Action Log handle is unknown or expired; search again"
            )
        payload = self._request_json(
            self._base_url,
            "/api/events",
            {"id": event_id},
            self._token,
        )
        exact = [event for event in self._events(payload) if event.get("id") == event_id]
        if len(exact) != 1:
            raise ActionLogProjectionError("Action Log event is unavailable")
        event = exact[0]
        details = event.get("details")
        details = details if isinstance(details, Mapping) else {}
        lines = [f"Action Log event #{event_id}"]
        for label, value in (
            ("Summary", event.get("summary")),
            ("Action", event.get("action")),
            *((name.replace("_", " ").title(), details.get(name)) for name in _DETAIL_FIELDS),
        ):
            text = _bounded_public_text(value, maximum=4_096)
            if text:
                lines.append(f"{label}: {text}")
        tags = _bounded_public_text(event.get("tags"), maximum=1_024)
        if tags:
            lines.append(f"Tags: {tags}")
        text = "\n".join(lines)
        if len(text) > MAX_EVENT_TEXT_CHARS:
            text = text[: MAX_EVENT_TEXT_CHARS - 1].rstrip() + "…"
        title = _bounded_public_text(event.get("summary"), maximum=256)
        if not title:
            title = f"Action Log event #{event_id}"
        metadata: dict[str, object] = {
            "source": "integrity-seed-action-log",
            "event_id": event_id,
        }
        for key in ("ts_utc", "created_utc", "level", "event_uid", "session_id"):
            value = event.get(key)
            if isinstance(value, (str, int)):
                metadata[key] = value
        task_id = details.get("task_id")
        if isinstance(task_id, str) and task_id:
            metadata["task_id"] = task_id
        return _text_result(
            {
                "id": item_id,
                "title": title,
                "text": text,
                "url": self._canonical_url(event_id),
                "metadata": metadata,
            }
        )

    def remember(
        self,
        *,
        title: object,
        memory: object,
        tags: object = None,
        idempotency_key: object = None,
    ) -> dict[str, object]:
        if not isinstance(title, str) or not title.strip() or len(title) > 2_000:
            raise ActionLogProjectionError("title must be a non-empty bounded string")
        if not isinstance(memory, str) or not memory.strip() or len(memory) > 24_000:
            raise ActionLogProjectionError("memory must be a non-empty bounded string")
        if tags is None:
            parsed_tags: list[str] = []
        elif (
            not isinstance(tags, list)
            or len(tags) > 16
            or any(
                not isinstance(tag, str)
                or not tag.strip()
                or len(tag) > 64
                for tag in tags
            )
        ):
            raise ActionLogProjectionError("tags must be a bounded string list")
        else:
            parsed_tags = list(dict.fromkeys(tag.strip() for tag in tags))
        event_uid = ""
        if idempotency_key is not None:
            if (
                not isinstance(idempotency_key, str)
                or not idempotency_key
                or len(idempotency_key) > 256
            ):
                raise ActionLogProjectionError("idempotency key is invalid")
            from hashlib import sha256

            event_uid = "work-memory:" + sha256(
                idempotency_key.encode("utf-8")
            ).hexdigest()
        payload = self._write_json(
            self._base_url,
            "/api/events",
            {
                "actor": "chatgpt-work",
                "level": "info",
                "action": "memory_remember",
                "summary": title.strip(),
                "details": {
                    "schema_version": 1,
                    "kind": "user-memory",
                    "note": memory,
                    "truth_status": "reported",
                },
                "tags": [*parsed_tags, "memory", "chatgpt-work"],
                "event_uid": event_uid,
            },
            self._token,
        )
        if payload.get("ok") is not True:
            raise ActionLogProjectionError("Action Log write failed closed")
        event_id = payload.get("id")
        duplicate = payload.get("duplicate")
        if (
            isinstance(event_id, bool)
            or not isinstance(event_id, int)
            or event_id < 1
            or not isinstance(duplicate, bool)
        ):
            raise ActionLogProjectionError("Action Log write receipt is invalid")
        return _text_result(
            {
                "stored": True,
                "duplicate": duplicate,
                "event_id": event_id,
                "source": "integrity-seed-action-log",
            }
        )


__all__ = [
    "ActionLogKnowledgeProjection",
    "ActionLogProjectionError",
]
