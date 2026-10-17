"""Fail-closed FTS federation across registered local corpus scopes."""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable, Mapping
from copy import deepcopy
from hashlib import sha256
import os
import sqlite3
import threading
from typing import Any, Dict, Optional, Tuple

from .corpus_index import CorpusIndexError, ValidatedCorpusReader
from .scope_registry import (
    MAX_SCOPES,
    SCOPE_REGISTRY_SCHEMA_VERSION,
    ScopeRegistry,
)
from .state_lock import CorpusStateLockError


FEDERATED_SEARCH_SCHEMA_VERSION = "integrity-home-federated-search/2"
FEDERATED_OPEN_SCHEMA_VERSION = "integrity-home-federated-open/2"
FEDERATED_MEMORY_PAGE_SCHEMA_VERSION = "integrity-home-federated-memory-page/1"
MAX_FEDERATED_RESULTS = 50
MAX_FEDERATED_OFFSET = 1_000_000
MAX_FEDERATED_CONTEXT_RADIUS = 2
MAX_FEDERATED_QUERY_CHARS = 4096
MAX_FEDERATED_FETCH_BATCH = 8

_UNAVAILABLE = "federated search unavailable"
_PHYSICAL_LOCATOR_FIELDS = frozenset(
    ("scope_id", "source_id", "conversation_id", "message_id")
)
_LOGICAL_LOCATOR_FIELDS = _PHYSICAL_LOCATOR_FIELDS | frozenset(
    ("logical_scope_ids", "view_everywhere")
)


class FederatedSearchError(RuntimeError):
    """Raised for invalid or unavailable federated reads."""


class _BackendFailure(RuntimeError):
    pass


def _request_error(message: str) -> FederatedSearchError:
    return FederatedSearchError(message)


def _bounded_string(value: Any, *, field: str, maximum: int = 4096) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or "\x00" in value
    ):
        raise _request_error(f"{field} must be a bounded non-empty string")
    return value


def _validate_context_radius(value: Any, *, field: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= MAX_FEDERATED_CONTEXT_RADIUS
    ):
        raise _request_error(
            f"{field} must be between 0 and {MAX_FEDERATED_CONTEXT_RADIUS}"
        )
    return value


def _scope_ids(value: Optional[Iterable[str]]) -> Optional[Tuple[str, ...]]:
    if value is None:
        return None
    if isinstance(value, (str, bytes, Mapping)):
        raise _request_error("scope_ids must be a non-empty collection")
    try:
        items = tuple(value)
    except TypeError as err:
        raise _request_error("scope_ids must be a non-empty collection") from err
    if not 1 <= len(items) <= MAX_SCOPES:
        raise _request_error("scope_ids must be a non-empty bounded collection")
    normalized: list[str] = []
    seen: set[str] = set()
    for item in items:
        scope_id = _bounded_string(item, field="scope_id", maximum=128)
        if scope_id in seen:
            raise _request_error("scope_ids must not contain duplicates")
        seen.add(scope_id)
        normalized.append(scope_id)
    return tuple(sorted(normalized))


class FederatedSearch:
    """Long-lived, single-thread owner of validated corpus readers.

    A reader is opened and fully validated once, then reused for warm calls.
    Every reader operation still performs the reader's cheap freshness checks.
    Any unavailable or stale selected scope discards the complete cache and
    returns one path-free error instead of a partial federation.
    """

    def __init__(self, registry: ScopeRegistry):
        if not isinstance(registry, ScopeRegistry):
            raise TypeError("registry must be a ScopeRegistry")
        self._registry = registry
        self._owner_thread_id = threading.get_ident()
        self._readers: Dict[str, Any] = {}
        self._reader_generations: Dict[str, Dict[str, str]] = {}
        self._closed = False

    def __enter__(self) -> "FederatedSearch":
        self._require_owner()
        if self._closed:
            raise _request_error("federated search is closed")
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()

    def _require_owner(self) -> None:
        if threading.get_ident() != self._owner_thread_id:
            raise _request_error("federated search must be used by its owner thread")

    def _require_open(self) -> None:
        self._require_owner()
        if self._closed:
            raise _request_error("federated search is closed")

    def _discard_readers(self) -> None:
        readers = tuple(self._readers.values())
        self._readers.clear()
        self._reader_generations.clear()
        for reader in readers:
            try:
                reader.close()
            except (CorpusIndexError, OSError, RuntimeError):
                pass

    @staticmethod
    def _backend_key(scope: Any) -> str:
        index = os.path.normcase(os.path.normpath(str(scope.index_path)))
        sidecar = (
            os.path.normcase(os.path.normpath(str(scope.history_sidecar_path)))
            if scope.history_sidecar_path is not None
            else ""
        )
        return index + "\0" + sidecar

    def _groups(self, selected: tuple[Any, ...]) -> tuple[tuple[Any, ...], ...]:
        grouped: Dict[str, list[Any]] = {}
        for scope in selected:
            grouped.setdefault(self._backend_key(scope), []).append(scope)
        return tuple(tuple(values) for values in grouped.values())

    def close(self) -> None:
        self._require_owner()
        if self._closed:
            return
        self._discard_readers()
        self._closed = True

    def list_scopes(self) -> list[Dict[str, Any]]:
        """Return path-free scope metadata without opening corpus files."""

        return self._registry.list_scopes()

    def status(self) -> Dict[str, Any]:
        """Return path-free registry/cache status without forcing validation."""

        self._require_owner()
        public_scopes = self._registry.list_scopes()
        for scope in public_scopes:
            generation = self._reader_generations.get(scope["scope_id"])
            if generation is not None:
                scope.update(generation)
        return {
            "schema_version": FEDERATED_SEARCH_SCHEMA_VERSION,
            "registry_generation": self._registry.registry_generation,
            "closed": self._closed,
            "cached_scope_count": len(self._readers),
            "registry": self._registry.status(),
            "scopes": public_scopes,
            "capabilities": {
                "match_modes": ["fts"],
                "max_results": MAX_FEDERATED_RESULTS,
                "max_context_radius": MAX_FEDERATED_CONTEXT_RADIUS,
                "everywhere_includes_enabled_project_scopes": True,
                "partial_results": False,
            },
        }

    def _selection(
        self,
        *,
        scope_ids: Optional[Iterable[str]],
        everywhere: bool,
    ) -> tuple[Any, ...]:
        if not isinstance(everywhere, bool):
            raise _request_error("everywhere must be a boolean")
        if everywhere and scope_ids is not None:
            raise _request_error("choose exactly one of scope_ids or everywhere")
        if not everywhere and scope_ids is None:
            raise _request_error("choose exactly one of scope_ids or everywhere")
        normalized = _scope_ids(scope_ids)
        try:
            selected = self._registry._resolve(
                scope_ids=normalized, everywhere=everywhere
            )
        except KeyError:
            self._discard_readers()
            raise FederatedSearchError(_UNAVAILABLE) from None
        if not selected:
            self._discard_readers()
            raise FederatedSearchError(_UNAVAILABLE)
        return selected

    def _ensure_readers(self, selected: tuple[Any, ...]) -> None:
        """Open every missing selected reader before any data operation."""

        try:
            current_backends: set[str] = set()
            for scope in selected:
                current = scope.index_path.resolve(strict=False)
                if current != scope.index_path:
                    raise _BackendFailure("registered corpus path is no longer canonical")
                if scope.history_sidecar_path is not None:
                    sidecar = scope.history_sidecar_path.resolve(strict=False)
                    if sidecar != scope.history_sidecar_path:
                        raise _BackendFailure(
                            "registered sidecar path is no longer canonical"
                        )
            for scope in selected:
                backend_key = self._backend_key(scope)
                if backend_key in current_backends:
                    continue
                current_backends.add(backend_key)
                if backend_key not in self._readers:
                    if scope.history_sidecar_path is None:
                        self._readers[backend_key] = ValidatedCorpusReader(
                            str(scope.index_path)
                        )
                    else:
                        from integrity_home.history.sidecar import HistorySidecarReader

                        self._readers[backend_key] = HistorySidecarReader(
                            str(scope.index_path), str(scope.history_sidecar_path)
                        )
        except (
            _BackendFailure,
            CorpusIndexError,
            CorpusStateLockError,
            OSError,
            RuntimeError,
            sqlite3.DatabaseError,
        ):
            self._discard_readers()
            raise FederatedSearchError(_UNAVAILABLE) from None

    @staticmethod
    def _scope_with_generation(scope: Any, search_payload: Mapping[str, Any]) -> Dict[str, Any]:
        public = scope.public()
        generation = search_payload.get("index_generation")
        corpus_id = search_payload.get("corpus_id")
        if not isinstance(generation, str) or not generation:
            raise _BackendFailure("missing index generation")
        if not isinstance(corpus_id, str) or not corpus_id:
            raise _BackendFailure("missing corpus id")
        history_view = search_payload.get("history_view")
        if scope.history_sidecar_path is not None:
            if not isinstance(history_view, Mapping):
                raise _BackendFailure("missing History view generation")
            sidecar_generation = history_view.get("sidecar_generation")
            if not isinstance(sidecar_generation, str) or not sidecar_generation:
                raise _BackendFailure("missing History sidecar generation")
            generation = sha256(
                (generation + "\0" + sidecar_generation).encode("ascii")
            ).hexdigest()
            public["sidecar_generation"] = sidecar_generation
        public["index_generation"] = generation
        public["corpus_id"] = corpus_id
        return public

    def search(
        self,
        *,
        query: str,
        scope_ids: Optional[Iterable[str]] = None,
        everywhere: bool = False,
        limit: int = 50,
        offset: int = 0,
        match_mode: str = "fts",
        context_radius: int = 0,
    ) -> Dict[str, Any]:
        """Search one explicit selection or every enabled registered scope."""

        self._require_open()
        query = _bounded_string(
            query, field="query", maximum=MAX_FEDERATED_QUERY_CHARS
        )
        if not query.strip():
            raise _request_error("query must contain a search term")
        if match_mode != "fts":
            raise _request_error("federated search v1 supports only fts")
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= MAX_FEDERATED_RESULTS
        ):
            raise _request_error(
                f"limit must be between 1 and {MAX_FEDERATED_RESULTS}"
            )
        if (
            isinstance(offset, bool)
            or not isinstance(offset, int)
            or not 0 <= offset <= MAX_FEDERATED_OFFSET
        ):
            raise _request_error(
                f"offset must be between 0 and {MAX_FEDERATED_OFFSET}"
            )
        context_radius = _validate_context_radius(
            context_radius, field="context_radius"
        )
        selected = self._selection(scope_ids=scope_ids, everywhere=everywhere)
        self._ensure_readers(selected)
        groups = self._groups(selected)

        local_results: Dict[str, deque[Dict[str, Any]]] = {
            self._backend_key(group[0]): deque() for group in groups
        }
        next_offsets: Dict[str, int] = {
            self._backend_key(group[0]): 0 for group in groups
        }
        exhausted: Dict[str, bool] = {
            self._backend_key(group[0]): False for group in groups
        }
        public_scopes: Dict[str, Dict[str, Any]] = {}

        def fetch_page(group: tuple[Any, ...], page_limit: int) -> None:
            scope = group[0]
            backend_key = self._backend_key(scope)
            reader = self._readers[backend_key]
            if scope.history_sidecar_path is None:
                payload = reader.search(
                    query=query,
                    match_mode="fts",
                    context_radius=context_radius,
                    limit=page_limit,
                    offset=next_offsets[backend_key],
                )
            else:
                logical_scope_ids = tuple(
                    item.logical_scope_id for item in group
                )
                backend_everywhere = everywhere and scope.everywhere_base_access
                payload = reader.search(
                    query=query,
                    scope_ids=None if backend_everywhere else logical_scope_ids,
                    everywhere=backend_everywhere,
                    match_mode="fts",
                    context_radius=context_radius,
                    limit=page_limit,
                    offset=next_offsets[backend_key],
                )
            if not isinstance(payload, Mapping):
                raise _BackendFailure("invalid search payload")
            raw_results = payload.get("results")
            if (
                not isinstance(raw_results, list)
                or len(raw_results) > page_limit
                or any(not isinstance(result, Mapping) for result in raw_results)
            ):
                raise _BackendFailure("invalid search results")
            for item in group:
                public_scope = self._scope_with_generation(item, payload)
                previous_scope = public_scopes.get(item.scope_id)
                if previous_scope is not None and (
                    previous_scope.get("index_generation")
                    != public_scope.get("index_generation")
                    or previous_scope.get("corpus_id") != public_scope.get("corpus_id")
                ):
                    raise _BackendFailure("scope generation changed during search")
                public_scopes[item.scope_id] = public_scope
            copied = [deepcopy(dict(result)) for result in raw_results]
            local_results[backend_key].extend(copied)
            next_offsets[backend_key] += len(copied)
            exhausted[backend_key] = len(copied) < page_limit

        try:
            # Probe every selected scope before merging.  This proves query
            # coverage for an everywhere request while materializing at most
            # one full record per scope for the first round.
            for group in groups:
                fetch_page(group, 1)

            merged: list[Dict[str, Any]] = []
            skipped = 0
            local_rank = 0
            while len(merged) < limit:
                local_rank += 1
                added = False
                for group in groups:
                    scope = group[0]
                    scope_id = scope.scope_id
                    backend_key = self._backend_key(scope)
                    buffer = local_results[backend_key]
                    if not buffer and not exhausted[backend_key]:
                        active_count = sum(
                            1
                            for item in groups
                            if not exhausted[self._backend_key(item[0])]
                        )
                        remaining = limit - len(merged)
                        page_limit = min(
                            MAX_FEDERATED_FETCH_BATCH,
                            max(1, (remaining + active_count - 1) // active_count),
                        )
                        fetch_page(group, page_limit)
                    if not buffer:
                        continue
                    added = True
                    record = buffer.popleft()
                    if skipped < offset:
                        skipped += 1
                        continue
                    locator = None
                    if all(
                        isinstance(record.get(key), str) and record.get(key)
                        for key in ("source_id", "conversation_id", "message_id")
                    ):
                        locator = {
                            "scope_id": scope_id,
                            "source_id": record["source_id"],
                            "conversation_id": record["conversation_id"],
                            "message_id": record["message_id"],
                        }
                        if scope.history_sidecar_path is not None:
                            backend_everywhere = (
                                everywhere and scope.everywhere_base_access
                            )
                            locator["logical_scope_ids"] = [
                                item.logical_scope_id for item in group
                            ]
                            locator["view_everywhere"] = backend_everywhere
                    merged.append(
                        {
                            "scope": deepcopy(public_scopes[scope_id]),
                            "covered_scope_ids": [item.scope_id for item in group],
                            "local_rank": local_rank,
                            "global_rank": offset + len(merged) + 1,
                            "locator": locator,
                            "record": record,
                        }
                    )
                    if len(merged) >= limit:
                        break
                if not added:
                    break
        except (
            _BackendFailure,
            CorpusIndexError,
            CorpusStateLockError,
            RuntimeError,
            OSError,
            sqlite3.DatabaseError,
        ):
            self._discard_readers()
            raise FederatedSearchError(_UNAVAILABLE) from None

        for scope in selected:
            public_scope = public_scopes[scope.scope_id]
            self._reader_generations[scope.scope_id] = {
                "index_generation": public_scope["index_generation"],
                "corpus_id": public_scope["corpus_id"],
            }

        requested_scope_ids = [] if everywhere else [
            scope.scope_id for scope in selected
        ]
        return {
            "schema_version": FEDERATED_SEARCH_SCHEMA_VERSION,
            "registry_schema_version": SCOPE_REGISTRY_SCHEMA_VERSION,
            "registry_generation": self._registry.registry_generation,
            "complete": True,
            "authority": "evidence_only",
            "query": query,
            "match_mode": "fts",
            "context_radius": context_radius,
            "limit": limit,
            "offset": offset,
            "everywhere": everywhere,
            "requested_scope_ids": requested_scope_ids,
            "searched_scope_ids": [scope.scope_id for scope in selected],
            "scope_count": len(selected),
            "scopes": [deepcopy(public_scopes[scope.scope_id]) for scope in selected],
            "result_count": len(merged),
            "results": merged,
        }

    def read_conversation_page(
        self,
        locator: Mapping[str, Any],
        *,
        limit: int = 25,
        offset: int = 0,
    ) -> Optional[Dict[str, Any]]:
        """Read the exact authorized conversation containing a search hit."""

        if not isinstance(locator, Mapping) or frozenset(locator) not in {
            _PHYSICAL_LOCATOR_FIELDS,
            _LOGICAL_LOCATOR_FIELDS,
        }:
            raise _request_error("locator fields do not match federated search v2")
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= MAX_FEDERATED_RESULTS
        ):
            raise _request_error(
                f"limit must be between 1 and {MAX_FEDERATED_RESULTS}"
            )
        if (
            isinstance(offset, bool)
            or not isinstance(offset, int)
            or not 0 <= offset <= MAX_FEDERATED_OFFSET
        ):
            raise _request_error(
                f"offset must be between 0 and {MAX_FEDERATED_OFFSET}"
            )

        logical = frozenset(locator) == _LOGICAL_LOCATOR_FIELDS
        if logical:
            logical_scope_ids = _scope_ids(locator.get("logical_scope_ids"))
            view_everywhere = locator.get("view_everywhere")
            if not isinstance(view_everywhere, bool):
                raise _request_error("logical locator view mode is invalid")
            selected = self._selection(
                scope_ids=logical_scope_ids,
                everywhere=False,
            )
            groups = self._groups(selected)
            if len(groups) != 1 or groups[0][0].history_sidecar_path is None:
                raise _request_error("logical locator backend is invalid")
            if locator.get("scope_id") not in logical_scope_ids:
                raise _request_error("logical locator scope is invalid")
            group = groups[0]
        else:
            scope_id = _bounded_string(
                locator.get("scope_id"), field="scope_id", maximum=128
            )
            selected = self._selection(scope_ids=(scope_id,), everywhere=False)
            group = (selected[0],)

        self._ensure_readers(selected)
        scope = group[0]
        backend_key = self._backend_key(scope)
        source_id = _bounded_string(locator.get("source_id"), field="source_id")
        conversation_id = _bounded_string(
            locator.get("conversation_id"), field="conversation_id"
        )
        try:
            if logical:
                page = self._readers[backend_key].get_conversation_page(
                    source_id=source_id,
                    conversation_id=conversation_id,
                    scope_ids=None if view_everywhere else logical_scope_ids,
                    everywhere=view_everywhere,
                    limit=limit,
                    offset=offset,
                )
                summary = self._readers[backend_key].inspect()
                if page is not None:
                    summary = {**summary, "history_view": page["history_view"]}
            else:
                page = self._readers[backend_key].get_conversation_page(
                    source_id=source_id,
                    conversation_id=conversation_id,
                    limit=limit,
                    offset=offset,
                )
                summary = self._readers[backend_key].inspect()
            public_scope = self._scope_with_generation(scope, summary)
        except (
            _BackendFailure,
            CorpusIndexError,
            CorpusStateLockError,
            RuntimeError,
            OSError,
            sqlite3.DatabaseError,
        ):
            self._discard_readers()
            raise FederatedSearchError(_UNAVAILABLE) from None
        if page is None:
            return None
        self._reader_generations[scope.scope_id] = {
            "index_generation": public_scope["index_generation"],
            "corpus_id": public_scope["corpus_id"],
        }
        return {
            "schema_version": FEDERATED_MEMORY_PAGE_SCHEMA_VERSION,
            "registry_schema_version": SCOPE_REGISTRY_SCHEMA_VERSION,
            "registry_generation": self._registry.registry_generation,
            "complete": True,
            "authority": "evidence_only",
            "scope": public_scope,
            "locator": deepcopy(dict(locator)),
            "conversation": deepcopy(page),
        }

    def open_message(
        self,
        *,
        scope_id: str,
        source_id: str,
        conversation_id: str,
        message_id: str,
        context_radius: int = 0,
    ) -> Optional[Dict[str, Any]]:
        """Open one exact message locator within one validated scope."""

        self._require_open()
        scope_id = _bounded_string(scope_id, field="scope_id", maximum=128)
        source_id = _bounded_string(source_id, field="source_id")
        conversation_id = _bounded_string(conversation_id, field="conversation_id")
        message_id = _bounded_string(message_id, field="message_id")
        context_radius = _validate_context_radius(
            context_radius, field="context_radius"
        )
        selected = self._selection(scope_ids=(scope_id,), everywhere=False)
        self._ensure_readers(selected)
        scope = selected[0]
        backend_key = self._backend_key(scope)
        try:
            summary: Mapping[str, Any]
            cached_generation = self._reader_generations.get(scope.scope_id)
            if cached_generation is None or scope.history_sidecar_path is not None:
                summary = self._readers[backend_key].inspect()
            else:
                summary = cached_generation
            if scope.history_sidecar_path is None:
                record = self._readers[backend_key].get_message(
                    source_id=source_id,
                    conversation_id=conversation_id,
                    message_id=message_id,
                    context_radius=context_radius,
                )
            else:
                record = self._readers[backend_key].get_message(
                    source_id=source_id,
                    conversation_id=conversation_id,
                    message_id=message_id,
                    scope_ids=(scope.logical_scope_id,),
                    context_radius=context_radius,
                )
                summary = {
                    **summary,
                    "history_view": {
                        "sidecar_generation": summary.get("sidecar_generation")
                    },
                }
            public_scope = self._scope_with_generation(scope, summary)
        except (
            _BackendFailure,
            CorpusIndexError,
            CorpusStateLockError,
            RuntimeError,
            OSError,
            sqlite3.DatabaseError,
        ):
            self._discard_readers()
            raise FederatedSearchError(_UNAVAILABLE) from None
        self._reader_generations[scope.scope_id] = {
            "index_generation": public_scope["index_generation"],
            "corpus_id": public_scope["corpus_id"],
        }
        if record is None:
            return None
        locator = {
            "scope_id": scope_id,
            "source_id": source_id,
            "conversation_id": conversation_id,
            "message_id": message_id,
        }
        return {
            "schema_version": FEDERATED_OPEN_SCHEMA_VERSION,
            "registry_schema_version": SCOPE_REGISTRY_SCHEMA_VERSION,
            "registry_generation": self._registry.registry_generation,
            "complete": True,
            "authority": "evidence_only",
            "scope": public_scope,
            "locator": locator,
            "record": deepcopy(record),
        }

    def open(
        self, locator: Mapping[str, Any], radius: int = 0
    ) -> Optional[Dict[str, Any]]:
        """Open a path-free locator returned by :meth:`search`."""

        if not isinstance(locator, Mapping) or frozenset(locator) not in {
            _PHYSICAL_LOCATOR_FIELDS,
            _LOGICAL_LOCATOR_FIELDS,
        }:
            raise _request_error("locator fields do not match federated search v2")
        if frozenset(locator) == _LOGICAL_LOCATOR_FIELDS:
            logical_scope_ids = _scope_ids(locator.get("logical_scope_ids"))
            view_everywhere = locator.get("view_everywhere")
            if not isinstance(view_everywhere, bool):
                raise _request_error("logical locator view mode is invalid")
            selected = self._selection(
                scope_ids=logical_scope_ids,
                everywhere=False,
            )
            groups = self._groups(selected)
            if len(groups) != 1 or groups[0][0].history_sidecar_path is None:
                raise _request_error("logical locator backend is invalid")
            if locator.get("scope_id") not in logical_scope_ids:
                raise _request_error("logical locator scope is invalid")
            self._ensure_readers(selected)
            group = groups[0]
            scope = group[0]
            backend_key = self._backend_key(scope)
            try:
                record = self._readers[backend_key].get_message(
                    source_id=_bounded_string(locator.get("source_id"), field="source_id"),
                    conversation_id=_bounded_string(locator.get("conversation_id"), field="conversation_id"),
                    message_id=_bounded_string(locator.get("message_id"), field="message_id"),
                    scope_ids=None if view_everywhere else logical_scope_ids,
                    everywhere=view_everywhere,
                    context_radius=_validate_context_radius(radius, field="radius"),
                )
                summary = self._readers[backend_key].inspect()
                if record is None:
                    return None
                summary = {**summary, "history_view": record["history_view"]}
                public_scope = self._scope_with_generation(scope, summary)
            except (
                _BackendFailure,
                CorpusIndexError,
                CorpusStateLockError,
                RuntimeError,
                OSError,
                sqlite3.DatabaseError,
            ):
                self._discard_readers()
                raise FederatedSearchError(_UNAVAILABLE) from None
            return {
                "schema_version": FEDERATED_OPEN_SCHEMA_VERSION,
                "registry_schema_version": SCOPE_REGISTRY_SCHEMA_VERSION,
                "registry_generation": self._registry.registry_generation,
                "complete": True,
                "authority": "evidence_only",
                "scope": public_scope,
                "covered_scope_ids": [item.scope_id for item in group],
                "locator": deepcopy(dict(locator)),
                "record": deepcopy(record),
            }
        return self.open_message(
            scope_id=locator.get("scope_id"),
            source_id=locator.get("source_id"),
            conversation_id=locator.get("conversation_id"),
            message_id=locator.get("message_id"),
            context_radius=radius,
        )


FederatedCorpusSearch = FederatedSearch


__all__ = [
    "FEDERATED_OPEN_SCHEMA_VERSION",
    "FEDERATED_SEARCH_SCHEMA_VERSION",
    "MAX_FEDERATED_CONTEXT_RADIUS",
    "MAX_FEDERATED_FETCH_BATCH",
    "MAX_FEDERATED_QUERY_CHARS",
    "MAX_FEDERATED_RESULTS",
    "FederatedCorpusSearch",
    "FederatedSearch",
    "FederatedSearchError",
]
