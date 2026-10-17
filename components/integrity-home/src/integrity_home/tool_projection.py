"""Bounded read-only projection for the Codex Integrity Home tools.

This module deliberately has no MCP or storage implementation details.  It
accepts an injected federation backend and exposes only a small, content-
bounded projection.  The backend adapter contract is:

``status()``
    Return ``registry_generation`` plus a ``scopes`` list.  Every available
    searchable scope has a stable ``scope_id`` and ``index_generation``.

``search(...)``
    Accept only ``query``, ``scope_ids``, ``everywhere``, ``limit``,
    ``match_mode`` and ``context_radius``.  Return ``complete=True`` and a
    ``results`` list.  Each result carries ``scope_id`` plus an internal
    locator containing ``source_id``, ``conversation_id`` and, for message
    results, ``message_id``.  Canonical payloads may be present; this layer
    never forwards them.

``open(locator=..., radius=...)``
    Resolve only the locator previously returned by ``search`` and return one
    record with optional bounded ``context``.  The locator is never exposed to
    the model.

All imported conversation material is untrusted evidence, never executable
instructions or an authority claim.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import secrets
from typing import Any, Mapping, Protocol

from integrity_chronicle.runtime_paths import state_path


SCOPE_REGISTRY_ENV = "INTEGRITY_HOME_SCOPE_REGISTRY"
MAX_QUERY_CHARS = 4_096
MAX_SCOPE_IDS = 64
MAX_SEARCH_RESULTS = 10
MAX_SEARCH_OUTPUT_BYTES = 12 * 1_024
MAX_OPEN_OUTPUT_BYTES = 32 * 1_024
MAX_MEMORY_OUTPUT_BYTES = 64 * 1_024
MAX_OPEN_RADIUS = 2
MAX_HANDLES = 256
MAX_CURSORS = 256
MAX_MEMORY_PAGE_MESSAGES = 25
MAX_SCOPES = 256

_SCOPE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
_WINDOWS_PATH_RE = re.compile(r"(?i)(?<![\w])(?:[a-z]:[\\/]|\\\\)[^\s\"'<>]+")
_FILE_URI_RE = re.compile(r"(?i)file://[^\s\"'<>]+")
_POSIX_PATH_RE = re.compile(r"(?<![:\w])/(?:[^/\s\"'<>]+/)*[^/\s\"'<>]+")


class HomeToolError(ValueError):
    """A safe, user-facing tool validation or backend-boundary error."""


class HomeReadBackend(Protocol):
    """Minimal storage-independent interface consumed by this projection."""

    def status(self) -> Mapping[str, Any]: ...

    def search(
        self,
        *,
        query: str,
        scope_ids: tuple[str, ...] | None,
        everywhere: bool,
        limit: int,
        offset: int,
        match_mode: str,
        context_radius: int,
    ) -> Mapping[str, Any]: ...

    def open(
        self, *, locator: Mapping[str, Any], radius: int
    ) -> Mapping[str, Any] | None: ...

    def read_conversation_page(
        self,
        *,
        locator: Mapping[str, Any],
        limit: int,
        offset: int,
    ) -> Mapping[str, Any] | None: ...


@dataclass(frozen=True)
class _IssuedHandle:
    process_session: str
    snapshot: str
    scope_generation: str | None
    locator: Mapping[str, Any]


@dataclass(frozen=True)
class _IssuedSearchCursor:
    process_session: str
    snapshot: str
    query: str
    scope_ids: tuple[str, ...] | None
    everywhere: bool
    limit: int
    offset: int


@dataclass(frozen=True)
class _IssuedMemoryCursor:
    process_session: str
    snapshot: str
    handle: str
    limit: int
    offset: int


def scope_registry_path() -> Path:
    """Return the operator-selected registry path, never a model argument."""

    override = os.environ.get(SCOPE_REGISTRY_ENV)
    if override is not None:
        if not override.strip():
            raise HomeToolError(f"{SCOPE_REGISTRY_ENV} must not be empty")
        return Path(override).expanduser().resolve()
    return state_path("config", "memory-scopes.json").resolve()


def _build_default_backend(registry_path: Path) -> HomeReadBackend:
    """Construct the core adapter through one intentionally narrow seam."""

    try:
        from integrity_chronicle.federated_search import FederatedSearch
        from integrity_chronicle.scope_registry import load_scope_registry
    except (ImportError, AttributeError) as err:
        raise HomeToolError("Integrity Home federation backend is unavailable") from err
    try:
        registry = load_scope_registry(str(registry_path))
        return _FederatedBackendAdapter(FederatedSearch(registry))
    except Exception as err:
        raise HomeToolError("Integrity Home scope registry is unavailable") from err


class _FederatedBackendAdapter:
    """Normalize the core federation to the narrow projection protocol."""

    def __init__(self, federation: Any):
        self._federation = federation

    def status(self) -> Mapping[str, Any]:
        raw_status = self._federation.status()
        scopes: list[dict[str, Any]] = []
        for raw in raw_status.get("scopes", []):
            enabled = raw.get("enabled")
            index_generation = raw.get("index_generation")
            scope = {
                "scope_id": raw.get("scope_id"),
                "display_name": raw.get("display_name"),
                "realm": raw.get("realm"),
                "kind": raw.get("scope_kind"),
                "project_id": raw.get("project_id"),
                "enabled": enabled,
                "searchable": enabled is True,
                "state": (
                    "disabled"
                    if enabled is False
                    else "ready" if index_generation else "unvalidated"
                ),
                "index_generation": index_generation,
            }
            if index_generation:
                scope["available"] = True
            scopes.append(scope)
        return {
            "complete": not bool(raw_status.get("closed")),
            "registry_generation": raw_status.get("registry_generation"),
            "scopes": scopes,
        }

    def search(self, **kwargs: Any) -> Mapping[str, Any]:
        return self._federation.search(**kwargs)

    def open(
        self, *, locator: Mapping[str, Any], radius: int
    ) -> Mapping[str, Any] | None:
        return self._federation.open(locator=locator, radius=radius)

    def read_conversation_page(
        self,
        *,
        locator: Mapping[str, Any],
        limit: int,
        offset: int,
    ) -> Mapping[str, Any] | None:
        return self._federation.read_conversation_page(
            locator, limit=limit, offset=offset
        )


def build_default_projection() -> "HomeToolProjection":
    return HomeToolProjection(_build_default_backend(scope_registry_path()))


def build_projection_for_registry(
    registry_path: str | os.PathLike[str],
) -> "HomeToolProjection":
    """Build one read projection from a server-selected registry path."""

    candidate = Path(registry_path)
    if not candidate.is_absolute():
        raise HomeToolError("scope registry path must be absolute")
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as err:
        raise HomeToolError("Integrity Home scope registry is unavailable") from err
    if resolved.is_symlink() or not resolved.is_file():
        raise HomeToolError("Integrity Home scope registry is unavailable")
    return HomeToolProjection(_build_default_backend(resolved))


def _mapping(value: Any, *, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise HomeToolError(f"{field} must be an object")
    return value


def _strict_arguments(
    value: Any, *, allowed: set[str], field: str = "arguments"
) -> Mapping[str, Any]:
    payload = _mapping(value, field=field)
    if any(not isinstance(key, str) for key in payload):
        raise HomeToolError(f"{field} field names must be strings")
    unknown = sorted(set(payload) - allowed)
    if unknown:
        raise HomeToolError(f"unsupported {field} fields")
    return payload


def _bounded_text(value: Any, *, field: str, maximum: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise HomeToolError(f"{field} must be a string")
    normalized = " ".join(value.replace("\x00", " ").split())
    if len(normalized) > maximum:
        normalized = normalized[: maximum - 1].rstrip() + "…"
    return normalized


def _redact_local_paths(value: str) -> str:
    redacted = _FILE_URI_RE.sub("[local-path]", value)
    redacted = _WINDOWS_PATH_RE.sub("[local-path]", redacted)
    return _POSIX_PATH_RE.sub("[local-path]", redacted)


def _public_text(value: Any, *, field: str, maximum: int) -> str | None:
    bounded = _bounded_text(value, field=field, maximum=maximum)
    return _redact_local_paths(bounded) if bounded is not None else None


def _non_negative_int(value: Any, *, field: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise HomeToolError(f"{field} must be a non-negative integer")
    return value


def _scope_id(value: Any, *, field: str = "scope_id") -> str:
    if not isinstance(value, str) or not _SCOPE_ID_RE.fullmatch(value):
        raise HomeToolError(f"{field} is invalid")
    return value


def _string_list(value: Any, *, field: str, maximum: int) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise HomeToolError(f"{field} must be a bounded list")
    result: list[str] = []
    seen: set[str] = set()
    for item in value:
        identifier = _scope_id(item, field=field)
        if identifier in seen:
            raise HomeToolError(f"{field} contains duplicates")
        seen.add(identifier)
        result.append(identifier)
    return result


def _encoded_size(value: Mapping[str, Any]) -> int:
    return len(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )


def _status_snapshot(status: Mapping[str, Any]) -> str:
    generation = status.get("registry_generation")
    if not isinstance(generation, str) or not generation:
        raise HomeToolError("backend status lacks a registry generation")
    raw_scopes = status.get("scopes")
    if not isinstance(raw_scopes, list) or len(raw_scopes) > MAX_SCOPES:
        raise HomeToolError("backend status has an invalid scope list")
    snapshot_scopes: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw_scope in raw_scopes:
        scope = _mapping(raw_scope, field="scope")
        identifier = _scope_id(scope.get("scope_id"))
        if identifier in seen:
            raise HomeToolError("backend status contains duplicate scopes")
        seen.add(identifier)
        available = scope.get("available")
        searchable = scope.get("searchable")
        enabled = scope.get("enabled")
        if not isinstance(enabled, bool):
            raise HomeToolError("scope enabled must be boolean")
        for field, value in (
            ("available", available),
            ("searchable", searchable),
        ):
            if value is not None and not isinstance(value, bool):
                raise HomeToolError(f"scope {field} must be boolean")
        index_generation = scope.get("index_generation")
        if available is True and searchable is True and enabled is not False:
            if not isinstance(index_generation, str) or not index_generation:
                raise HomeToolError("searchable scope lacks an index generation")
        elif index_generation is not None and not isinstance(index_generation, str):
            raise HomeToolError("scope index generation must be a string")
        snapshot_scopes.append(
            {
                "scope_id": identifier,
                "index_generation": index_generation,
                "available": available,
                "searchable": searchable,
                "enabled": enabled,
            }
        )
    material = {
        "registry_generation": generation,
        "backend_session": status.get("session_id"),
        "scopes": sorted(snapshot_scopes, key=lambda item: item["scope_id"]),
    }
    encoded = json.dumps(
        material, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return sha256(encoded).hexdigest()


def _public_scope(raw_scope: Any) -> dict[str, Any]:
    scope = _mapping(raw_scope, field="scope")
    result: dict[str, Any] = {
        "scope_id": _scope_id(scope.get("scope_id")),
        "display_name": _public_text(
            scope.get("display_name"), field="scope display_name", maximum=128
        ),
        "realm": _public_text(scope.get("realm"), field="scope realm", maximum=32),
        "kind": _public_text(scope.get("kind"), field="scope kind", maximum=32),
        "project_id": _public_text(
            scope.get("project_id"), field="scope project_id", maximum=128
        ),
        "state": _public_text(scope.get("state"), field="scope state", maximum=32),
        "enabled": scope.get("enabled"),
        "searchable": scope.get("searchable"),
        "available": scope.get("available"),
        "index_generation": _bounded_text(
            scope.get("index_generation"),
            field="scope index_generation",
            maximum=128,
        ),
        "conversation_count": _non_negative_int(
            scope.get("conversation_count"), field="scope conversation_count"
        ),
        "message_count": _non_negative_int(
            scope.get("message_count"), field="scope message_count"
        ),
    }
    return {key: value for key, value in result.items() if value is not None}


def _public_status(status: Mapping[str, Any]) -> dict[str, Any]:
    _status_snapshot(status)
    scopes = [_public_scope(item) for item in status["scopes"]]
    scopes.sort(key=lambda item: item["scope_id"])
    complete = status.get("complete")
    if complete is not None and not isinstance(complete, bool):
        raise HomeToolError("backend status complete flag must be boolean")
    return {
        "schema_version": "integrity-home-tool-status/1",
        "authority": "local_read_only_evidence",
        "complete": bool(complete) if complete is not None else True,
        "registry_generation": status["registry_generation"],
        "scope_count": len(scopes),
        "scopes": scopes,
    }


def _status_generations(status: Mapping[str, Any]) -> dict[str, str | None]:
    generations: dict[str, str | None] = {}
    for raw_scope in status.get("scopes", []):
        scope = _mapping(raw_scope, field="scope")
        generations[_scope_id(scope.get("scope_id"))] = scope.get(
            "index_generation"
        )
    return generations


def _enabled_scope_ids(status: Mapping[str, Any]) -> set[str]:
    enabled: set[str] = set()
    for raw_scope in status.get("scopes", []):
        scope = _mapping(raw_scope, field="scope")
        if scope.get("enabled") is True:
            enabled.add(_scope_id(scope.get("scope_id")))
    return enabled


def _flatten_result(raw_result: Any) -> dict[str, Any]:
    raw = _mapping(raw_result, field="search result")
    nested_record = raw.get("record")
    nested_scope = raw.get("scope")
    if nested_record is None and nested_scope is None:
        return dict(raw)
    record = dict(_mapping(nested_record, field="search result record"))
    scope = _mapping(nested_scope, field="search result scope")
    record["scope_id"] = scope.get("scope_id")
    record["scope_display_name"] = scope.get("display_name")
    record["scope_generation"] = scope.get("index_generation")
    record["covered_scope_ids"] = raw.get(
        "covered_scope_ids", [scope.get("scope_id")]
    )
    record["locator"] = raw.get("locator")
    return record


def _locator_from_result(raw: Mapping[str, Any]) -> dict[str, Any] | None:
    nested = raw.get("locator")
    if nested is None and raw.get("record_type") == "conversation_metadata":
        return None
    if isinstance(nested, Mapping):
        locator = dict(nested)
    else:
        locator = {
            key: raw.get(key)
            for key in ("scope_id", "source_id", "conversation_id", "message_id")
        }
    physical_fields = {"scope_id", "source_id", "conversation_id", "message_id"}
    logical_fields = physical_fields | {"logical_scope_ids", "view_everywhere"}
    if set(locator) not in (physical_fields, logical_fields):
        raise HomeToolError("search result private locator is invalid")
    locator["scope_id"] = _scope_id(raw.get("scope_id"))
    for required in ("source_id", "conversation_id"):
        if not isinstance(locator.get(required), str) or not locator[required]:
            raise HomeToolError("search result lacks a private locator")
    if not isinstance(locator.get("message_id"), str) or not locator["message_id"]:
        raise HomeToolError("message result lacks a private locator")
    result = {
        key: locator.get(key)
        for key in ("scope_id", "source_id", "conversation_id", "message_id")
    }
    covered_scope_ids = _string_list(
        raw.get("covered_scope_ids", [raw.get("scope_id")]),
        field="covered_scope_ids",
        maximum=MAX_SCOPE_IDS,
    )
    if set(locator) == logical_fields:
        logical_scope_ids = locator.get("logical_scope_ids")
        if (
            not isinstance(logical_scope_ids, list)
            or not logical_scope_ids
            or len(logical_scope_ids) > MAX_SCOPE_IDS
            or any(not isinstance(value, str) or not _SCOPE_ID_RE.fullmatch(value) for value in logical_scope_ids)
            or len(set(logical_scope_ids)) != len(logical_scope_ids)
            or not isinstance(locator.get("view_everywhere"), bool)
        ):
            raise HomeToolError("search result private locator is invalid")
        if logical_scope_ids != covered_scope_ids:
            raise HomeToolError("search result logical coverage is invalid")
        result["logical_scope_ids"] = list(logical_scope_ids)
        result["view_everywhere"] = locator["view_everywhere"]
    elif covered_scope_ids != [locator.get("scope_id")]:
        raise HomeToolError("physical search result coverage is invalid")
    return result


def _public_result(raw_result: Any, handle: str | None) -> dict[str, Any]:
    raw = _mapping(raw_result, field="search result")
    record_type = raw.get("record_type", "message")
    if record_type not in {"message", "conversation_metadata"}:
        raise HomeToolError("search result record type is unsupported")
    content = raw.get("excerpt", raw.get("content"))
    if not isinstance(content, str):
        raise HomeToolError("search result lacks evidence text")
    result: dict[str, Any] = {
        "handle": handle,
        "openable": handle is not None,
        "scope_id": _scope_id(raw.get("scope_id")),
        "scope_ids": _string_list(
            raw.get("covered_scope_ids", [raw.get("scope_id")]),
            field="covered_scope_ids",
            maximum=MAX_SCOPE_IDS,
        ),
        "scope_display_name": _public_text(
            raw.get("scope_display_name"),
            field="scope display name",
            maximum=128,
        ),
        "record_type": record_type,
        "provider": _public_text(
            raw.get("provider"), field="provider", maximum=64
        ),
        "role": _public_text(raw.get("role"), field="role", maximum=32),
        "created_at": _public_text(
            raw.get("created_at"), field="created_at", maximum=64
        ),
        "title": _public_text(
            raw.get("title", raw.get("conversation_title")),
            field="title",
            maximum=240,
        ),
        "excerpt": _public_text(content, field="evidence text", maximum=640),
        "untrusted_evidence": True,
        "authoritative": False,
    }
    return {key: value for key, value in result.items() if value is not None}


def _public_context_record(raw_record: Any, *, maximum: int) -> dict[str, Any]:
    record = _mapping(raw_record, field="context record")
    content = record.get("excerpt", record.get("content"))
    if not isinstance(content, str):
        raise HomeToolError("context record lacks evidence text")
    result: dict[str, Any] = {
        "provider": _public_text(
            record.get("provider"), field="context provider", maximum=64
        ),
        "role": _public_text(record.get("role"), field="context role", maximum=32),
        "created_at": _public_text(
            record.get("created_at"), field="context created_at", maximum=64
        ),
        "content_type": _public_text(
            record.get("content_type"), field="context content_type", maximum=64
        ),
        "excerpt": _public_text(content, field="context evidence", maximum=maximum),
        "untrusted_evidence": True,
        "authoritative": False,
    }
    return {key: value for key, value in result.items() if value is not None}


def _public_memory_message(raw_record: Any) -> dict[str, Any]:
    record = _mapping(raw_record, field="memory message")
    content = record.get("excerpt", record.get("content"))
    if not isinstance(content, str):
        raise HomeToolError("memory message lacks evidence text")
    message_index = _non_negative_int(
        record.get("message_index"), field="memory message index"
    )
    result: dict[str, Any] = {
        "source_message_ordinal": message_index,
        "provider": _public_text(
            record.get("provider"), field="memory provider", maximum=64
        ),
        "role": _public_text(record.get("role"), field="memory role", maximum=32),
        "model": _public_text(record.get("model"), field="memory model", maximum=128),
        "created_at": _public_text(
            record.get("created_at"), field="memory created_at", maximum=64
        ),
        "content_type": _public_text(
            record.get("content_type"), field="memory content_type", maximum=64
        ),
        "content": _public_text(
            content, field="memory evidence", maximum=16 * 1_024
        ),
        "untrusted_evidence": True,
        "authoritative": False,
    }
    return {key: value for key, value in result.items() if value is not None}


class HomeToolProjection:
    """Per-process, read-only Integrity Home tool projection."""

    def __init__(self, backend: HomeReadBackend):
        self._backend = backend
        self._process_session = secrets.token_hex(16)
        self._observed_snapshot: str | None = None
        self._handles: OrderedDict[str, _IssuedHandle] = OrderedDict()
        self._search_cursors: OrderedDict[str, _IssuedSearchCursor] = OrderedDict()
        self._memory_cursors: OrderedDict[str, _IssuedMemoryCursor] = OrderedDict()

    def _status_and_snapshot(self) -> tuple[Mapping[str, Any], str]:
        try:
            status = _mapping(self._backend.status(), field="backend status")
            snapshot = _status_snapshot(status)
        except HomeToolError:
            raise
        except Exception as err:
            raise HomeToolError("Integrity Home status is unavailable") from err
        if self._observed_snapshot is not None and snapshot != self._observed_snapshot:
            self._handles.clear()
            self._search_cursors.clear()
            self._memory_cursors.clear()
        self._observed_snapshot = snapshot
        return status, snapshot

    def status(self, arguments: Any | None = None) -> dict[str, Any]:
        if arguments is not None:
            _strict_arguments(arguments, allowed=set())
        status, _ = self._status_and_snapshot()
        return _public_status(status)

    def search_requires_project_audit(self, arguments: Any) -> bool:
        """Return whether the requested selection can expose project memory."""
        payload = _strict_arguments(
            arguments,
            allowed={"query", "scope_ids", "everywhere", "limit", "cursor"},
        )
        if payload.get("everywhere") is True:
            status, _ = self._status_and_snapshot()
            return any(
                isinstance(scope, Mapping)
                and scope.get("kind") == "project"
                and scope.get("enabled") is True
                for scope in status.get("scopes", [])
            )
        selected = payload.get("scope_ids")
        if not isinstance(selected, list):
            return False
        status, _ = self._status_and_snapshot()
        project_scopes = {
            scope.get("scope_id")
            for scope in status.get("scopes", [])
            if isinstance(scope, Mapping) and scope.get("kind") == "project"
        }
        return bool(set(selected) & project_scopes)

    def search(self, arguments: Any) -> dict[str, Any]:
        payload = _strict_arguments(
            arguments,
            allowed={"query", "scope_ids", "everywhere", "limit", "cursor"},
        )
        query = payload.get("query")
        if not isinstance(query, str) or not query.strip():
            raise HomeToolError("query must be a non-empty string")
        if len(query) > MAX_QUERY_CHARS:
            raise HomeToolError(f"query exceeds {MAX_QUERY_CHARS} characters")
        has_scopes = "scope_ids" in payload
        everywhere = payload.get("everywhere", False)
        if not isinstance(everywhere, bool):
            raise HomeToolError("everywhere must be boolean")
        if has_scopes == everywhere:
            raise HomeToolError(
                "select exactly one of scope_ids or everywhere=true"
            )
        scope_ids: tuple[str, ...] | None = None
        if has_scopes:
            parsed = _string_list(
                payload["scope_ids"], field="scope_ids", maximum=MAX_SCOPE_IDS
            )
            if not parsed:
                raise HomeToolError("scope_ids must not be empty")
            scope_ids = tuple(parsed)
        limit = payload.get("limit", MAX_SEARCH_RESULTS)
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= MAX_SEARCH_RESULTS
        ):
            raise HomeToolError(
                f"limit must be between 1 and {MAX_SEARCH_RESULTS}"
            )

        before_status, before = self._status_and_snapshot()
        offset = 0
        cursor = payload.get("cursor")
        cursor_entry: _IssuedSearchCursor | None = None
        if cursor is not None:
            if not isinstance(cursor, str) or not re.fullmatch(
                r"ihc_[A-Za-z0-9_-]{24,64}", cursor
            ):
                raise HomeToolError("search cursor is invalid or expired")
            cursor_entry = self._search_cursors.get(cursor)
            if (
                cursor_entry is None
                or cursor_entry.process_session != self._process_session
                or cursor_entry.snapshot != before
                or cursor_entry.query != query
                or cursor_entry.scope_ids != scope_ids
                or cursor_entry.everywhere != everywhere
                or cursor_entry.limit != limit
            ):
                self._search_cursors.pop(cursor, None)
                raise HomeToolError("search cursor is invalid or expired")
            offset = cursor_entry.offset
        try:
            raw_response = _mapping(
                self._backend.search(
                    query=query,
                    scope_ids=scope_ids,
                    everywhere=everywhere,
                    limit=limit + 1,
                    offset=offset,
                    match_mode="fts",
                    context_radius=0,
                ),
                field="backend search",
            )
        except HomeToolError:
            raise
        except Exception as err:
            raise HomeToolError("Integrity Home search failed closed") from err
        after_status, after = self._status_and_snapshot()
        before_generations = _status_generations(before_status)
        after_generations = _status_generations(after_status)
        generation_changed = any(
            generation is not None
            and after_generations.get(scope_id) != generation
            for scope_id, generation in before_generations.items()
        )
        if (
            before_status["registry_generation"]
            != after_status["registry_generation"]
            or _enabled_scope_ids(before_status) != _enabled_scope_ids(after_status)
            or generation_changed
        ):
            self._handles.clear()
            raise HomeToolError("memory generation changed during search")
        if raw_response.get("complete") is not True:
            raise HomeToolError("memory search was incomplete")
        response_generation = raw_response.get("registry_generation")
        if response_generation is not None and not isinstance(response_generation, str):
            raise HomeToolError("search generation is invalid")
        if (
            response_generation is not None
            and response_generation != before_status["registry_generation"]
        ):
            raise HomeToolError("search generation is stale")

        raw_results = raw_response.get("results")
        if not isinstance(raw_results, list) or len(raw_results) > limit + 1:
            raise HomeToolError("backend returned an invalid result list")
        backend_has_more = len(raw_results) > limit
        raw_results = raw_results[:limit]
        searched_ids = _string_list(
            raw_response.get("searched_scope_ids", []),
            field="searched_scope_ids",
            maximum=MAX_SCOPES,
        )
        if everywhere and not searched_ids:
            raise HomeToolError("everywhere search covered no scopes")
        if everywhere and set(searched_ids) != _enabled_scope_ids(before_status):
            raise HomeToolError("everywhere scope coverage is incomplete")
        if scope_ids is not None and set(searched_ids) != set(scope_ids):
            raise HomeToolError("explicit scope search coverage is incomplete")
        searched_scope_set = set(searched_ids)

        output: dict[str, Any] = {
            "schema_version": "integrity-home-tool-search/2",
            "authority": "untrusted_evidence",
            "complete": True,
            "mode": "everywhere" if everywhere else "explicit_scopes",
            "requested_scope_ids": list(scope_ids) if scope_ids is not None else None,
            "searched_scope_ids": searched_ids,
            "result_count": 0,
            "output_truncated": False,
            "has_more": False,
            "next_cursor": None,
            "results": [],
        }
        pending_handles: list[tuple[str, _IssuedHandle]] = []
        for raw_result in raw_results:
            raw = _flatten_result(raw_result)
            result_scope_id = _scope_id(raw.get("scope_id"))
            if result_scope_id not in searched_scope_set:
                raise HomeToolError("search result scope is outside covered scopes")
            scope_generation = raw.get("scope_generation")
            if (
                not isinstance(scope_generation, str)
                or not scope_generation
                or after_generations.get(result_scope_id) != scope_generation
            ):
                raise HomeToolError("search result scope generation is stale")
            locator = _locator_from_result(raw)
            if (
                locator is not None
                and locator.get("view_everywhere") is True
                and not everywhere
            ):
                raise HomeToolError("explicit search locator expands its scope")
            handle = "ih_" + secrets.token_urlsafe(24) if locator is not None else None
            public = _public_result(raw, handle)
            candidate = dict(output)
            candidate["results"] = [*output["results"], public]
            candidate["result_count"] = len(candidate["results"])
            if _encoded_size(candidate) > MAX_SEARCH_OUTPUT_BYTES:
                output["output_truncated"] = True
                break
            output = candidate
            if handle is not None and locator is not None:
                pending_handles.append(
                    (
                        handle,
                        _IssuedHandle(
                            process_session=self._process_session,
                            snapshot=after,
                            scope_generation=scope_generation,
                            locator=locator,
                        ),
                    )
                )
        if _encoded_size(output) > MAX_SEARCH_OUTPUT_BYTES:
            raise HomeToolError("bounded search metadata exceeds the output limit")
        for handle, entry in pending_handles:
            self._handles[handle] = entry
            self._handles.move_to_end(handle)
            while len(self._handles) > MAX_HANDLES:
                self._handles.popitem(last=False)
        if cursor is not None:
            self._search_cursors.pop(cursor, None)
        has_more = backend_has_more or output["output_truncated"]
        if has_more:
            next_cursor = "ihc_" + secrets.token_urlsafe(24)
            self._search_cursors[next_cursor] = _IssuedSearchCursor(
                process_session=self._process_session,
                snapshot=after,
                query=query,
                scope_ids=scope_ids,
                everywhere=everywhere,
                limit=limit,
                offset=offset + len(output["results"]),
            )
            self._search_cursors.move_to_end(next_cursor)
            while len(self._search_cursors) > MAX_CURSORS:
                self._search_cursors.popitem(last=False)
            output["has_more"] = True
            output["next_cursor"] = next_cursor
        return output

    def open(self, arguments: Any) -> dict[str, Any]:
        payload = _strict_arguments(arguments, allowed={"handle", "radius"})
        handle = payload.get("handle")
        if not isinstance(handle, str) or not re.fullmatch(
            r"ih_[A-Za-z0-9_-]{24,64}", handle
        ):
            raise HomeToolError("handle is invalid or expired")
        radius = payload.get("radius", 1)
        if (
            isinstance(radius, bool)
            or not isinstance(radius, int)
            or not 0 <= radius <= MAX_OPEN_RADIUS
        ):
            raise HomeToolError(f"radius must be between 0 and {MAX_OPEN_RADIUS}")
        entry = self._handles.get(handle)
        if entry is None or entry.process_session != self._process_session:
            raise HomeToolError("handle is invalid or expired")
        _, before = self._status_and_snapshot()
        if before != entry.snapshot:
            self._handles.pop(handle, None)
            raise HomeToolError("handle is invalid or expired")
        try:
            raw_record = self._backend.open(locator=dict(entry.locator), radius=radius)
        except Exception as err:
            self._handles.pop(handle, None)
            raise HomeToolError("Integrity Home evidence open failed closed") from err
        if raw_record is None:
            self._handles.pop(handle, None)
            raise HomeToolError("handle is invalid or expired")
        raw_envelope = _mapping(raw_record, field="opened evidence")
        raw = _flatten_result(raw_envelope)
        opened_generation = raw.get("scope_generation")
        if (
            entry.scope_generation is not None
            and opened_generation != entry.scope_generation
        ):
            self._handles.pop(handle, None)
            raise HomeToolError("handle is invalid or expired")
        _, after = self._status_and_snapshot()
        if before != after:
            self._handles.pop(handle, None)
            raise HomeToolError("memory generation changed during open")

        main = _public_context_record(raw, maximum=8_192)
        main["scope_id"] = entry.locator["scope_id"]
        if "logical_scope_ids" in entry.locator:
            main["scope_ids"] = list(entry.locator["logical_scope_ids"])
        display_name = _public_text(
            raw.get("scope_display_name"),
            field="scope display name",
            maximum=128,
        )
        if display_name is not None:
            main["scope_display_name"] = display_name
        context = raw.get("context", {})
        context_mapping = _mapping(context, field="opened context")
        public_context: dict[str, Any] = {
            "previous": [],
            "parent": None,
            "children": [],
            "next": [],
            "children_truncated": bool(context_mapping.get("children_truncated", False)),
        }
        if not isinstance(context_mapping.get("children_truncated", False), bool):
            raise HomeToolError("opened context truncation flag is invalid")
        output: dict[str, Any] = {
            "schema_version": "integrity-home-tool-open/2",
            "authority": "untrusted_evidence",
            "handle": handle,
            "radius": radius,
            "output_truncated": False,
            "evidence": main,
            "context": public_context,
        }
        for key in ("previous", "children", "next"):
            values = context_mapping.get(key, [])
            if not isinstance(values, list) or len(values) > 16:
                raise HomeToolError("opened context is invalid")
            for item in values:
                projected = _public_context_record(item, maximum=4_096)
                candidate = json.loads(json.dumps(output))
                candidate["context"][key].append(projected)
                if _encoded_size(candidate) > MAX_OPEN_OUTPUT_BYTES:
                    output["output_truncated"] = True
                    break
                output = candidate
            if output["output_truncated"]:
                break
        if not output["output_truncated"]:
            parent = context_mapping.get("parent")
            if parent is not None:
                projected_parent = _public_context_record(parent, maximum=4_096)
                candidate = json.loads(json.dumps(output))
                candidate["context"]["parent"] = projected_parent
                if _encoded_size(candidate) > MAX_OPEN_OUTPUT_BYTES:
                    output["output_truncated"] = True
                else:
                    output = candidate
        if _encoded_size(output) > MAX_OPEN_OUTPUT_BYTES:
            raise HomeToolError("opened evidence exceeds the output limit")
        self._handles.move_to_end(handle)
        return output

    def read_memory(self, arguments: Any) -> dict[str, Any]:
        payload = _strict_arguments(
            arguments, allowed={"handle", "cursor", "limit"}
        )
        handle = payload.get("handle")
        if not isinstance(handle, str) or not re.fullmatch(
            r"ih_[A-Za-z0-9_-]{24,64}", handle
        ):
            raise HomeToolError("handle is invalid or expired")
        limit = payload.get("limit", MAX_MEMORY_PAGE_MESSAGES)
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= MAX_MEMORY_PAGE_MESSAGES
        ):
            raise HomeToolError(
                f"limit must be between 1 and {MAX_MEMORY_PAGE_MESSAGES}"
            )
        entry = self._handles.get(handle)
        if entry is None or entry.process_session != self._process_session:
            raise HomeToolError("handle is invalid or expired")
        _, before = self._status_and_snapshot()
        if before != entry.snapshot:
            self._handles.pop(handle, None)
            raise HomeToolError("handle is invalid or expired")

        offset = 0
        cursor = payload.get("cursor")
        if cursor is not None:
            if not isinstance(cursor, str) or not re.fullmatch(
                r"ihm_[A-Za-z0-9_-]{24,64}", cursor
            ):
                raise HomeToolError("memory cursor is invalid or expired")
            cursor_entry = self._memory_cursors.get(cursor)
            if (
                cursor_entry is None
                or cursor_entry.process_session != self._process_session
                or cursor_entry.snapshot != before
                or cursor_entry.handle != handle
                or cursor_entry.limit != limit
            ):
                self._memory_cursors.pop(cursor, None)
                raise HomeToolError("memory cursor is invalid or expired")
            offset = cursor_entry.offset

        try:
            raw_page = self._backend.read_conversation_page(
                locator=dict(entry.locator),
                limit=limit,
                offset=offset,
            )
        except Exception as err:
            raise HomeToolError("Integrity Home memory read failed closed") from err
        if raw_page is None:
            raise HomeToolError("handle is invalid or expired")
        envelope = _mapping(raw_page, field="memory page")
        scope = _mapping(envelope.get("scope"), field="memory page scope")
        if scope.get("index_generation") != entry.scope_generation:
            self._handles.pop(handle, None)
            raise HomeToolError("handle is invalid or expired")
        conversation = _mapping(
            envelope.get("conversation"), field="memory conversation"
        )
        total = _non_negative_int(
            conversation.get("message_count"), field="memory message_count"
        )
        page_offset = _non_negative_int(
            conversation.get("page_offset"), field="memory page offset"
        )
        if total is None or total < 1 or page_offset != offset:
            raise HomeToolError("memory page boundary is invalid")
        raw_messages = conversation.get("messages")
        if (
            not isinstance(raw_messages, list)
            or not raw_messages
            or len(raw_messages) > limit
        ):
            raise HomeToolError("memory page messages are invalid")
        _, after = self._status_and_snapshot()
        if before != after:
            self._handles.pop(handle, None)
            raise HomeToolError("memory generation changed during read")

        output: dict[str, Any] = {
            "schema_version": "integrity-home-tool-memory-page/1",
            "authority": "untrusted_evidence",
            "handle": handle,
            "title": _public_text(
                conversation.get("title"), field="memory title", maximum=240
            ),
            "provider": _public_text(
                conversation.get("provider"), field="memory provider", maximum=64
            ),
            "created_at": _public_text(
                conversation.get("created_at"),
                field="memory created_at",
                maximum=64,
            ),
            "memory_start": 0,
            "memory_end": total - 1,
            "message_count": total,
            "page_start_ordinal": offset,
            "page_end_ordinal": None,
            "has_more": False,
            "next_cursor": None,
            "output_truncated": False,
            "messages": [],
        }
        for raw_message in raw_messages:
            public = _public_memory_message(raw_message)
            public["memory_ordinal"] = offset + len(output["messages"])
            candidate = json.loads(json.dumps(output))
            candidate["messages"].append(public)
            candidate["page_end_ordinal"] = (
                offset + len(candidate["messages"]) - 1
            )
            if _encoded_size(candidate) > MAX_MEMORY_OUTPUT_BYTES:
                output["output_truncated"] = True
                break
            output = candidate
        if not output["messages"]:
            raise HomeToolError("one memory message exceeds the output limit")
        backend_has_more = conversation.get("has_more")
        if not isinstance(backend_has_more, bool):
            raise HomeToolError("memory page continuation is invalid")
        if cursor is not None:
            self._memory_cursors.pop(cursor, None)
        has_more = (
            backend_has_more
            or output["output_truncated"]
            or offset + len(output["messages"]) < total
        )
        if has_more:
            next_cursor = "ihm_" + secrets.token_urlsafe(24)
            self._memory_cursors[next_cursor] = _IssuedMemoryCursor(
                process_session=self._process_session,
                snapshot=after,
                handle=handle,
                limit=limit,
                offset=offset + len(output["messages"]),
            )
            self._memory_cursors.move_to_end(next_cursor)
            while len(self._memory_cursors) > MAX_CURSORS:
                self._memory_cursors.popitem(last=False)
            output["has_more"] = True
            output["next_cursor"] = next_cursor
        self._handles.move_to_end(handle)
        return output

    def invoke(self, tool_name: str, arguments: Any) -> dict[str, Any]:
        if tool_name == "home_status":
            return self.status(arguments)
        if tool_name == "home_search":
            return self.search(arguments)
        if tool_name == "home_open":
            return self.open(arguments)
        if tool_name == "home_read_memory":
            return self.read_memory(arguments)
        raise HomeToolError("unknown Integrity Home tool")


__all__ = [
    "HomeReadBackend",
    "HomeToolError",
    "HomeToolProjection",
    "MAX_OPEN_OUTPUT_BYTES",
    "MAX_SEARCH_OUTPUT_BYTES",
    "SCOPE_REGISTRY_ENV",
    "build_projection_for_registry",
    "build_default_projection",
    "scope_registry_path",
]
