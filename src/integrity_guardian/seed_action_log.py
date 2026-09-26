"""Loopback-only Action Log adapter for the canonical Integrity Seed.

This adapter reads the existing local compatibility API.  It cannot contact a
remote host, resolve Integrity Home, write Action Log events or acquire
production authority.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import json
import re
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

from .action_log_reader import (
    ActionLogReaderAuthError,
    ActionLogReaderTransportError,
    action_log_reader_headers,
    open_action_log_reader_request,
)
from .seed_catalog import (
    SEED_NAMESPACE,
    SeedCatalog,
    SeedCatalogError,
    SeedCatalogReport,
    _canonical_text,
    validate_seed_events,
    validate_seed_namespace,
)

DEFAULT_ACTION_LOG_URL = "http://127.0.0.1:8765"
MAX_STABILIZATION_PASSES = 3
MAX_PAGE_SIZE = 1_000
_WORKSPACE_ID_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class SeedSnapshot:
    events: list[dict[str, Any]]
    source_url: str
    source_namespace: str
    previous_event_id: int
    maximum_event_id: int
    stabilization_passes: int
    full_snapshot: bool
    # Filled by sync_action_log_seed: the source's workspace_id (None when the
    # runtime does not report one), how the catalog binding was resolved, and
    # the already-stored events re-read from the source and compared.
    source_identity: str | None = None
    source_binding: str = "not-checked"
    compared_event_ids: tuple[int, ...] = ()


def _validate_loopback_url(base_url: str) -> str:
    parsed = urllib.parse.urlsplit(base_url)
    if parsed.scheme != "http":
        raise SeedCatalogError("Seed Action Log adapter requires loopback HTTP")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise SeedCatalogError("Seed Action Log adapter URL contains forbidden fields")
    hostname = parsed.hostname
    if hostname is None:
        raise SeedCatalogError("Seed Action Log adapter URL has no host")
    if hostname != "localhost":
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError as exc:
            raise SeedCatalogError(
                "Seed Action Log adapter does not perform remote DNS resolution"
            ) from exc
        if not address.is_loopback:
            raise SeedCatalogError("Seed Action Log adapter is loopback-only")
    port = parsed.port or 80
    rendered_host = f"[{hostname}]" if ":" in hostname else hostname
    return f"http://{rendered_host}:{port}"


def _headers() -> dict[str, str]:
    try:
        return action_log_reader_headers()
    except ActionLogReaderAuthError as exc:
        raise SeedCatalogError(
            "Seed Action Log authentication token is required before network I/O"
        ) from exc


def _get_json(url: str) -> dict[str, Any]:
    request = urllib.request.Request(url, headers=_headers())
    try:
        response = open_action_log_reader_request(request, timeout=15)
    except ActionLogReaderTransportError as exc:
        raise SeedCatalogError(str(exc)) from exc
    with response:
        if response.status != 200:
            raise SeedCatalogError(
                f"Seed Action Log returned unexpected status {response.status}"
            )
        value = json.load(response)
    if not isinstance(value, dict):
        raise SeedCatalogError("Seed Action Log response is not an object")
    return value


def _fetch_once(base_url: str, *, page_size: int) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    seen_page_edges: set[tuple[int, int, int]] = set()
    offset = 0
    while True:
        query = urllib.parse.urlencode(
            {
                "since": "all",
                "limit": page_size,
                "offset": offset,
                "order": "asc",
                "sort": "id",
            }
        )
        payload = _get_json(f"{base_url}/api/events?{query}")
        page = payload.get("events")
        if not isinstance(page, list):
            raise SeedCatalogError("Seed Action Log page has no event list")
        if not page:
            break
        if not all(isinstance(event, dict) for event in page):
            raise SeedCatalogError("Seed Action Log page contains a non-object event")
        edge = (int(page[0]["id"]), int(page[-1]["id"]), len(page))
        if edge in seen_page_edges:
            raise SeedCatalogError("Seed Action Log repeated a pagination page")
        seen_page_edges.add(edge)
        events.extend(page)
        offset += len(page)
        if len(page) < page_size:
            break
    return events


def _fetch_incremental_once(
    base_url: str,
    *,
    after_event_id: int,
    snapshot_event_id: int,
    page_size: int,
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    cursor = after_event_id
    while cursor < snapshot_event_id:
        query = urllib.parse.urlencode(
            {
                "since": "all",
                "limit": page_size,
                "after_id": cursor,
                "snapshot_event_id": snapshot_event_id,
                "order": "asc",
                "sort": "id",
            }
        )
        payload = _get_json(f"{base_url}/api/events?{query}")
        page = payload.get("events")
        if not isinstance(page, list):
            raise SeedCatalogError("Seed Action Log incremental page is invalid")
        if not page:
            break
        if not all(isinstance(event, dict) for event in page):
            raise SeedCatalogError(
                "Seed Action Log incremental page contains a non-object event"
            )
        first_id = int(page[0]["id"])
        last_id = int(page[-1]["id"])
        if first_id <= cursor or last_id <= cursor:
            raise SeedCatalogError("Seed Action Log incremental cursor did not advance")
        if last_id > snapshot_event_id:
            raise SeedCatalogError("Seed Action Log crossed its pinned snapshot cursor")
        events.extend(page)
        cursor = last_id
        if len(page) < page_size:
            break
    return events


def _tail_maximum_id(base_url: str) -> int:
    # Order by id, like every page fetch: ordering by ts_utc would let a
    # backdated or near-future event hide the real tail.
    query = urllib.parse.urlencode(
        {"since": "all", "limit": 1, "offset": 0, "order": "desc", "sort": "id"}
    )
    payload = _get_json(f"{base_url}/api/events?{query}")
    events = payload.get("events")
    if not isinstance(events, list) or not events:
        raise SeedCatalogError("Seed Action Log tail is empty")
    event_id = events[0].get("id")
    if not isinstance(event_id, int):
        raise SeedCatalogError("Seed Action Log tail id is invalid")
    return event_id


def source_identity(base_url: str) -> str | None:
    """Return the runtime's workspace_id, or None when it reports none.

    workspace_id is derived from the Seed state location by the launcher. It
    identifies a local state, not a person or machine, and proves nothing on
    its own; the catalog also compares stored events with the source.
    """
    payload = _get_json(f"{_validate_loopback_url(base_url)}/api/health")
    value = payload.get("workspace_id")
    if isinstance(value, str) and _WORKSPACE_ID_RE.fullmatch(value):
        return value
    return None


def _source_event(base_url: str, event_id: int) -> dict[str, Any] | None:
    query = urllib.parse.urlencode({"since": "all", "id": event_id, "limit": 1})
    page = _get_json(f"{base_url}/api/events?{query}").get("events")
    if not isinstance(page, list) or len(page) > 1:
        raise SeedCatalogError("Seed Action Log event lookup is invalid")
    if not page:
        return None
    if not isinstance(page[0], dict) or page[0].get("id") != event_id:
        raise SeedCatalogError("Seed Action Log returned a different event")
    return page[0]


def compare_stored_events(
    catalog: SeedCatalog,
    base_url: str,
    *,
    source_namespace: str,
) -> tuple[int, ...]:
    """Re-read the catalog's first and last events from the source and compare.

    Refuses a source whose history differs at those ids. This is a bounded
    spot check, not a proof that every earlier event is unchanged.
    """
    _, cursor = catalog.event_cursor()
    if cursor == 0:
        return ()
    resolved_url = _validate_loopback_url(base_url)
    compared = tuple(sorted({catalog.minimum_event_id(), cursor}))
    for event_id in compared:
        source_event = _source_event(resolved_url, event_id)
        if source_event is None:
            raise SeedCatalogError(
                f"source has no event {event_id} that the catalog holds; "
                "it is a different or rewritten Seed source"
            )
        [normalized] = validate_seed_events([source_event], source_namespace=source_namespace)
        if _canonical_text(normalized) != _canonical_text(catalog.event_at(event_id)):
            raise SeedCatalogError(
                f"source event {event_id} differs from the catalog; "
                "it is a different or rewritten Seed source"
            )
    return compared


def fetch_seed_snapshot(
    *,
    base_url: str = DEFAULT_ACTION_LOG_URL,
    page_size: int = MAX_PAGE_SIZE,
    after_event_id: int = 0,
    source_namespace: str = SEED_NAMESPACE,
) -> SeedSnapshot:
    """Fetch until the complete page set and independent tail cursor agree."""

    validate_seed_namespace(source_namespace)
    resolved_url = _validate_loopback_url(base_url)
    if not 1 <= page_size <= MAX_PAGE_SIZE:
        raise SeedCatalogError("Seed Action Log page size is outside 1..1000")
    if after_event_id < 0:
        raise SeedCatalogError("Seed Action Log cursor cannot be negative")
    for attempt in range(1, MAX_STABILIZATION_PASSES + 1):
        target_tail = _tail_maximum_id(resolved_url)
        if target_tail < after_event_id:
            raise SeedCatalogError(
                "Seed Action Log tail is behind the structured catalog cursor"
            )
        if target_tail == after_event_id:
            return SeedSnapshot(
                events=[],
                source_url=resolved_url,
                source_namespace=source_namespace,
                previous_event_id=after_event_id,
                maximum_event_id=target_tail,
                stabilization_passes=attempt,
                full_snapshot=after_event_id == 0,
            )
        raw_events = (
            _fetch_once(resolved_url, page_size=page_size)
            if after_event_id == 0
            else _fetch_incremental_once(
                resolved_url,
                after_event_id=after_event_id,
                snapshot_event_id=target_tail,
                page_size=page_size,
            )
        )
        events = validate_seed_events(
            raw_events,
            source_namespace=source_namespace,
        )
        if (
            events[-1]["id"] == target_tail
            and _tail_maximum_id(resolved_url) == target_tail
        ):
            return SeedSnapshot(
                events=events,
                source_url=resolved_url,
                source_namespace=source_namespace,
                previous_event_id=after_event_id,
                maximum_event_id=target_tail,
                stabilization_passes=attempt,
                full_snapshot=after_event_id == 0,
            )
    raise SeedCatalogError(
        "Seed Action Log cursor changed during every bounded snapshot attempt"
    )


def sync_action_log_seed(
    catalog: SeedCatalog,
    *,
    base_url: str = DEFAULT_ACTION_LOG_URL,
    profile: str = "live-sync",
    page_size: int = MAX_PAGE_SIZE,
    source_namespace: str | None = None,
) -> tuple[SeedSnapshot, SeedCatalogReport]:
    """Import one stable complete local Action Log snapshot."""

    _, current_cursor = catalog.event_cursor()
    bound_namespace = catalog.bound_source_namespace()
    if current_cursor and catalog.verify()["source_namespace"] != bound_namespace:
        raise SeedCatalogError("catalog namespace changed during sync admission")
    selected_namespace = source_namespace or bound_namespace or SEED_NAMESPACE
    validate_seed_namespace(selected_namespace)
    if bound_namespace is not None and selected_namespace != bound_namespace:
        raise SeedCatalogError("requested sync namespace differs from the catalogue")
    identity = source_identity(base_url)
    bound_identity = catalog.bound_source_identity()
    if bound_identity is not None and identity != bound_identity:
        raise SeedCatalogError(
            "catalog is bound to a different Seed source; nothing was imported"
            if identity is not None
            else "source reports no workspace_id, so it cannot be matched to the "
            "catalog's bound source; nothing was imported"
        )
    compared = compare_stored_events(
        catalog, base_url, source_namespace=selected_namespace
    )
    snapshot = fetch_seed_snapshot(
        base_url=base_url,
        page_size=page_size,
        after_event_id=current_cursor,
        source_namespace=selected_namespace,
    )
    if source_identity(base_url) != identity:
        raise SeedCatalogError("Seed source changed during sync; nothing was imported")
    if identity is None:
        binding = "unavailable"
    elif bound_identity is None:
        binding = "established"
    else:
        binding = "matched"
    snapshot = dataclasses.replace(
        snapshot,
        source_identity=identity,
        source_binding=binding,
        compared_event_ids=compared,
    )
    import_batch = snapshot.events
    if not import_batch:
        if current_cursor == 0:
            raise SeedCatalogError("Seed Action Log and catalog are both empty")
        import_batch = [catalog.event_at(current_cursor)]
    report = catalog.import_events(
        import_batch,
        source_namespace=snapshot.source_namespace,
        profile=profile,
        source_identity=identity,
    )
    return snapshot, report
