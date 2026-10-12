"""Bounded, digest-bound hyperlinks over one immutable canonical Seed snapshot.

The graph is a rebuildable projection.  Canonical Seed remains the only source
of truth; aliases, adjacency indexes and navigation cursors are derived state.
The projection never grants route, execution or production authority.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import sqlite3
import unicodedata
from collections import defaultdict, deque
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote, urlsplit

from .canonical import canonical_bytes
from .hashing import digest_object
from .seed_catalog import HOME_NAMESPACE, SeedCatalog

MEMORY_LINK_GRAPH_PROTOCOL = "integrity-guardian/memory-link-graph/v1"
MEMORY_LINK_RESOLUTION_PROTOCOL = "integrity-guardian/memory-link-resolution/v1"
MEMORY_LINK_NAVIGATION_PROTOCOL = "integrity-guardian/memory-link-navigation/v1"
MEMORY_LINK_CONTEXT_PROTOCOL = "integrity-guardian/memory-link-context/v1"
MEMORY_ENTITY_BRIEF_PROTOCOL = "integrity-guardian/memory-entity-brief/v1"
MEMORY_LINK_AUDIT_PROTOCOL = "integrity-guardian/memory-link-audit/v1"
MEMORY_LINK_RANKING_POLICY = "evidence-first-v1"

DEFAULT_MAX_GRAPH_NODES = 200_000
DEFAULT_MAX_GRAPH_LINKS = 1_000_000
DEFAULT_PAGE_LIMIT = 40
MAX_PAGE_LIMIT = 200
DEFAULT_MAX_CONTEXT_BYTES = 32 * 1024
MIN_CONTEXT_BYTES = 8 * 1024
MAX_CONTEXT_BYTES = 256 * 1024
MAX_TRAIL_LENGTH = 16
MAX_ALIASES_PER_NODE = 64
MAX_RENDERED_ALIASES = 16
MAX_RENDERED_SOURCE_EVENT_IDS = 64
MAX_IDENTIFIER_LENGTH = 512
MAX_TITLE_LENGTH = 512
MAX_ALIAS_LENGTH = 256
DEFAULT_CONTEXT_DEPTH = 2
MAX_CONTEXT_DEPTH = 4
DEFAULT_CONTEXT_NODE_LIMIT = 64
MAX_CONTEXT_NODE_LIMIT = 200
DEFAULT_CONTEXT_LINK_LIMIT = 120
MAX_CONTEXT_LINK_LIMIT = 200
DEFAULT_ENTITY_RELATION_LIMIT = 40
MAX_ENTITY_RELATION_LIMIT = 100
DEFAULT_ENTITY_ACTIVITY_LIMIT = 12
MAX_ENTITY_ACTIVITY_LIMIT = 20
DEFAULT_ENTITY_TASK_LIMIT = 20
MAX_ENTITY_TASK_LIMIT = 20
DEFAULT_DISCOVERY_LIMIT = 10
MAX_DISCOVERY_LIMIT = 20
MAX_DEFINITION_LENGTH = 2048
MAX_DEFINITION_LANGUAGE_LENGTH = 35
MAX_RENDERED_DEFINITIONS = 5
MAX_ACTIVITY_SUMMARY_LENGTH = 1024
MAX_ACTIVITY_ACTION_LENGTH = 128
MAX_ENTITY_TASK_SEARCH_NODES = 256
DEFAULT_AUDIT_LIMIT = 50
MAX_AUDIT_LIMIT = 100
MAX_AUDIT_AMBIGUOUS_ALIASES = 8

_DEFINITION_AUDIT_KINDS = frozenset(
    {
        "artifact",
        "component",
        "concept",
        "decision",
        "location",
        "release",
        "subsystem",
        "system",
        "term",
    }
)
_WHEREABOUTS_AUDIT_KINDS = frozenset({"artifact", "component", "release", "system"})
_FRESHNESS_AUDIT_KINDS = frozenset(
    {"artifact", "component", "location", "release", "subsystem", "system"}
)
_AUDIT_ISSUES = (
    "alias-ambiguous",
    "canonical-task-card-missing",
    "definition-contradicted",
    "definition-unknown",
    "freshness-policy-absent",
    "freshness-policy-partial",
    "legacy-self-link-ignored",
    "whereabouts-unknown",
)
_AUDIT_ISSUE_PRIORITY = {
    "definition-contradicted": 0,
    "canonical-task-card-missing": 1,
    "definition-unknown": 2,
    "freshness-policy-absent": 3,
    "freshness-policy-partial": 4,
    "whereabouts-unknown": 5,
    "legacy-self-link-ignored": 6,
    "alias-ambiguous": 7,
}

_ENTITY_KIND_PRIORITY = {
    "component": 0,
    "system": 1,
    "concept": 2,
    "decision": 3,
    "release": 4,
    "artifact": 5,
    "location": 6,
    "subsystem": 7,
    "task": 8,
    "term": 9,
    "event": 10,
    "evidence": 11,
}

_RELATION_NEIGHBOR_KIND_PRIORITY = {
    "location": 0,
    "task": 1,
    "system": 2,
    "component": 3,
    "concept": 4,
    "decision": 5,
    "release": 6,
    "artifact": 7,
    "subsystem": 8,
    "term": 9,
    "evidence": 10,
    "event": 11,
}

MEMORY_LINK_NODE_KINDS = frozenset(
    {
        "artifact",
        "component",
        "concept",
        "decision",
        "event",
        "evidence",
        "location",
        "release",
        "subsystem",
        "system",
        "task",
        "term",
    }
)
MEMORY_LINK_RELATIONS = frozenset(
    {
        "blocks",
        "child-of",
        "cites",
        "concerns",
        "contradicts",
        "defines",
        "depends-on",
        "derived-from",
        "located-at",
        "preempts",
        "records-task",
        "refers-to",
        "related-to",
        "supports",
        "supersedes",
        "tagged-with",
    }
)

_PROJECT_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_ADDRESS_IDENTIFIER_PATTERN = re.compile(
    r"^(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?$"
)
_TASK_RELATION_FIELDS = {
    "parent_task_id": "child-of",
    "depends_on_task_ids": "depends-on",
    "related_task_ids": "related-to",
    "supersedes_task_ids": "supersedes",
    "blocks_task_ids": "blocks",
    "preempts_task_ids": "preempts",
}
_EVENT_RELATION_FIELDS = {
    "related_event_id": "related-to",
    "related_event_ids": "related-to",
    "verifies_event_id": "supports",
    "verifies_event_ids": "supports",
    "verified_event_id": "supports",
    "verified_event_ids": "supports",
    "supersedes_event_id": "supersedes",
    "supersedes_event_ids": "supersedes",
    "source_event_id": "derived-from",
    "source_event_ids": "derived-from",
    "evidence_event_id": "cites",
    "evidence_event_ids": "cites",
    "external_evidence_id": "cites",
    "external_evidence_ids": "cites",
}
_SYSTEM_FIELDS = ("touched_hosts", "affected_hosts", "target_hosts")
_TASK_JOIN_RELATIONS = frozenset(
    {
        "blocks",
        "child-of",
        "concerns",
        "defines",
        "depends-on",
        "preempts",
        "records-task",
        "refers-to",
        "related-to",
        "supersedes",
    }
)
_CLAIM_STATES = frozenset({"CURRENT", "STALE", "SUPERSEDED", "CONTRADICTED", "UNKNOWN"})
_TASK_STATES = ("active", "pending", "blocked", "unknown", "complete", "failed")
_SECRET_SHAPE = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|(?:password|passwd|token|secret|api[_-]?key)\s*[:=]|bearer\s+[A-Za-z0-9._~-]{12,}",
    re.IGNORECASE,
)


class MemoryLinkGraphError(ValueError):
    """The canonical memory-link projection or request is invalid."""


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _normalize_legacy_projection_text(value: Any) -> str:
    """Collapse control whitespace in derived legacy fields without changing Seed."""

    text = _text(value).strip()
    text = re.sub(r"[\x00-\x1f]+", " ", text)
    return " ".join(text.split())


def _bounded_text(value: Any, *, field: str, maximum: int) -> str:
    text = _text(value).strip()
    if not text:
        raise MemoryLinkGraphError(f"{field} must be a non-empty string")
    if len(text) > maximum:
        raise MemoryLinkGraphError(f"{field} exceeds {maximum} characters")
    if any(ord(character) < 32 for character in text):
        raise MemoryLinkGraphError(f"{field} contains a control character")
    return text


def _strings(value: Any) -> list[str]:
    values = value if isinstance(value, list) else [value]
    result: list[str] = []
    for item in values:
        text = _normalize_legacy_projection_text(item)
        if text and text not in result:
            result.append(text)
    return result


def _normalize_timestamp(value: Any, *, field: str, allow_empty: bool = False) -> str:
    text = _text(value).strip()
    if not text and allow_empty:
        return ""
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise MemoryLinkGraphError(f"{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise MemoryLinkGraphError(f"{field} must include a timezone")
    normalized = parsed.astimezone(UTC).isoformat(timespec="seconds")
    return normalized.replace("+00:00", "Z")


def _lexical_tokens(value: Any) -> tuple[str, ...]:
    normalized = unicodedata.normalize("NFKC", _text(value)).casefold()
    tokens: list[str] = []
    for token in re.findall(r"[\w.-]+", normalized, flags=re.UNICODE):
        cleaned = token.strip("._-")
        if len(cleaned) >= 2 and cleaned not in tokens:
            tokens.append(cleaned)
    return tuple(tokens)


def _redact_secret_shape(value: Any, *, maximum: int, label: str) -> str:
    text = _normalize_legacy_projection_text(value)[:maximum]
    return f"[redacted secret-shaped {label}]" if _SECRET_SHAPE.search(text) else text


def normalize_memory_alias(value: Any) -> str:
    """Return the exact, locale-independent alias lookup key."""

    text = _bounded_text(value, field="memory alias", maximum=MAX_ALIAS_LENGTH)
    return " ".join(unicodedata.normalize("NFKC", text).casefold().split())


def _identifier_shape_rank(value: str) -> int:
    """Demote raw-looking identifiers for presentation without changing truth."""

    text = value.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {"'", '"'}:
        return 3
    if text.isdecimal() or _ADDRESS_IDENTIFIER_PATTERN.fullmatch(text):
        return 2
    if any(marker in text for marker in (",", "(", ")", "[", "]")):
        return 1
    return 0


def memory_link_uri(project_slug: str, kind: str, identifier: Any) -> str:
    """Build one canonical, percent-encoded Integrity Seed URI."""

    if not _PROJECT_PATTERN.fullmatch(project_slug):
        raise MemoryLinkGraphError("project_slug is not a canonical project token")
    if kind not in MEMORY_LINK_NODE_KINDS:
        raise MemoryLinkGraphError(f"unsupported memory-link node kind: {kind}")
    key = _bounded_text(identifier, field="memory-link identifier", maximum=MAX_IDENTIFIER_LENGTH)
    encoded = quote(key, safe="-._~")
    return f"integrity://seed/project/{project_slug}/{kind}/{encoded}"


def _parse_memory_uri(uri: str, *, project_slug: str) -> tuple[str, str]:
    parsed = urlsplit(uri)
    parts = [part for part in parsed.path.split("/") if part]
    if (
        parsed.scheme != "integrity"
        or parsed.netloc != "seed"
        or parsed.query
        or parsed.fragment
        or len(parts) != 4
        or parts[0] != "project"
        or parts[1] != project_slug
        or parts[2] not in MEMORY_LINK_NODE_KINDS
    ):
        raise MemoryLinkGraphError("memory-link URI is outside the admitted project namespace")
    identifier = unquote(parts[3])
    canonical = memory_link_uri(project_slug, parts[2], identifier)
    if canonical != uri:
        raise MemoryLinkGraphError("memory-link URI is not canonically encoded")
    return parts[2], identifier


def _details(event: Mapping[str, Any]) -> Mapping[str, Any]:
    value = event.get("details")
    return value if isinstance(value, Mapping) else {}


def _positive_event_id(value: Any, *, field: str) -> int:
    if isinstance(value, bool):
        raise MemoryLinkGraphError(f"{field} must be a positive event id")
    if isinstance(value, int) and value > 0:
        return value
    text = _text(value).strip()
    if text.isdigit() and int(text) > 0:
        return int(text)
    raise MemoryLinkGraphError(f"{field} must be a positive event id")


def _stream_digest(*, domain: str, documents: Iterable[Mapping[str, Any]]) -> str:
    digest = hashlib.sha256()
    digest.update(f"integrity-guardian\x00memory-link-v1\x00{domain}\x00".encode())
    for document in documents:
        payload = canonical_bytes(document)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return "sha256:" + digest.hexdigest()


def _cursor_encode(value: Mapping[str, Any]) -> str:
    payload = canonical_bytes(value)
    body = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
    checksum = hashlib.sha256(payload).hexdigest()
    return f"{body}.{checksum}"


def _cursor_decode(cursor: str, expected: Mapping[str, Any]) -> int:
    if not cursor or len(cursor) > 4096 or cursor.count(".") != 1:
        raise MemoryLinkGraphError("memory-link cursor is malformed")
    body, supplied_checksum = cursor.split(".", 1)
    try:
        payload = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
        value = json.loads(payload)
    except (ValueError, json.JSONDecodeError) as exc:
        raise MemoryLinkGraphError("memory-link cursor cannot be decoded") from exc
    actual_checksum = hashlib.sha256(payload).hexdigest()
    if not hmac.compare_digest(actual_checksum, supplied_checksum):
        raise MemoryLinkGraphError("memory-link cursor checksum mismatch")
    if not isinstance(value, dict):
        raise MemoryLinkGraphError("memory-link cursor payload is invalid")
    offset = value.pop("offset", None)
    if (
        value != dict(expected)
        or isinstance(offset, bool)
        or not isinstance(offset, int)
        or offset < 0
    ):
        raise MemoryLinkGraphError("memory-link cursor is outside this graph request")
    return offset


def _page_limit(value: int) -> int:
    if isinstance(value, bool) or not 1 <= value <= MAX_PAGE_LIMIT:
        raise MemoryLinkGraphError(f"limit must be inside 1..{MAX_PAGE_LIMIT}")
    return value


def _context_budget(value: int) -> int:
    if isinstance(value, bool) or not MIN_CONTEXT_BYTES <= value <= MAX_CONTEXT_BYTES:
        raise MemoryLinkGraphError(
            f"max_context_bytes must be inside {MIN_CONTEXT_BYTES}..{MAX_CONTEXT_BYTES}"
        )
    return value


def _bounded_integer(value: int, *, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise MemoryLinkGraphError(f"{field} must be inside {minimum}..{maximum}")
    return value


class MemoryLinkGraph:
    """Deterministic URI, alias and adjacency indexes for one Seed snapshot."""

    def __init__(
        self,
        events: Sequence[dict[str, Any]],
        *,
        task_records: Sequence[Mapping[str, Any]] = (),
        project_slug: str = "default",
        source_namespace: str | None = None,
        source_digest: str | None = None,
        catalog_digest: str | None = None,
        max_nodes: int = DEFAULT_MAX_GRAPH_NODES,
        max_links: int = DEFAULT_MAX_GRAPH_LINKS,
    ) -> None:
        if not events:
            raise MemoryLinkGraphError("memory-link graph requires at least one Seed event")
        if not _PROJECT_PATTERN.fullmatch(project_slug):
            raise MemoryLinkGraphError("project_slug is not a canonical project token")
        if max_nodes < 1 or max_links < 1:
            raise MemoryLinkGraphError("memory-link graph limits must be positive")
        self.project_slug = project_slug
        self.source_namespace = source_namespace or f"seed://project/{project_slug}"
        if self.source_namespace != f"seed://project/{project_slug}":
            raise MemoryLinkGraphError("source namespace and project slug disagree")
        self.max_nodes = max_nodes
        self.max_links = max_links
        ordered_events = sorted(events, key=lambda item: int(item["id"]))
        event_ids = [int(event["id"]) for event in ordered_events]
        if len(set(event_ids)) != len(event_ids) or any(event_id < 1 for event_id in event_ids):
            raise MemoryLinkGraphError("Seed events require unique positive ids")
        if any(HOME_NAMESPACE in json.dumps(event, ensure_ascii=False) for event in ordered_events):
            raise MemoryLinkGraphError("Integrity Home is prohibited in memory links")
        self.source_event_count = len(ordered_events)
        self.source_max_event_id = max(event_ids)
        self._event_documents: dict[int, dict[str, Any]] = {}
        self._search_postings: dict[str, set[int]] = defaultdict(set)
        for event in ordered_events:
            event_id = int(event["id"])
            details = _details(event)
            raw_summary = _normalize_legacy_projection_text(event.get("summary"))
            raw_action = _normalize_legacy_projection_text(event.get("action"))
            timestamp = _normalize_timestamp(
                event.get("ts_utc"), field="event.ts_utc", allow_empty=True
            )
            document = {
                "event_id": event_id,
                "ts_utc": timestamp,
                "action": raw_action[:MAX_ACTIVITY_ACTION_LENGTH],
                "summary": raw_summary[:MAX_ACTIVITY_SUMMARY_LENGTH],
                "summary_truncated": len(raw_summary) > MAX_ACTIVITY_SUMMARY_LENGTH,
                "task_id": _normalize_legacy_projection_text(details.get("task_id"))[
                    :MAX_IDENTIFIER_LENGTH
                ],
            }
            self._event_documents[event_id] = document
            for token in _lexical_tokens(raw_summary):
                self._search_postings[token].add(event_id)
        self.source_max_event_time = max(
            (item["ts_utc"] for item in self._event_documents.values() if item["ts_utc"]),
            default="",
        )
        self.source_digest = source_digest or _stream_digest(
            domain="memory-link-source-events-v1", documents=ordered_events
        )
        self.catalog_digest = catalog_digest or ""
        self._nodes: dict[str, dict[str, Any]] = {}
        self._links: dict[tuple[str, str, str, str], dict[str, set[Any]]] = {}
        self._observed_event_ids = frozenset(self._event_documents)
        self._unresolved_event_references: set[tuple[int, str, int]] = set()
        self._ignored_legacy_self_link_nodes: set[str] | frozenset[str] = set()
        self._task_documents = self._normalize_task_records(task_records)

        for event in ordered_events:
            self._index_nodes(event)
        for event in ordered_events:
            self._index_links(event)
        self._freeze()

    @classmethod
    def from_catalog(
        cls,
        catalog_path: Path,
        *,
        immutable: bool = False,
        readonly_connection: sqlite3.Connection | None = None,
        project_slug: str | None = None,
        max_nodes: int = DEFAULT_MAX_GRAPH_NODES,
        max_links: int = DEFAULT_MAX_GRAPH_LINKS,
    ) -> MemoryLinkGraph:
        catalog = SeedCatalog(
            catalog_path,
            immutable=immutable,
            readonly_connection=readonly_connection,
        )
        snapshot = catalog.canonical_projection_snapshot()
        verification = snapshot["verification"]
        namespace = str(verification["source_namespace"])
        match = re.fullmatch(r"seed://project/([A-Za-z0-9][A-Za-z0-9._-]{0,127})", namespace)
        if match is None:
            raise MemoryLinkGraphError("catalog source is not a canonical project Seed")
        selected_slug = project_slug or match.group(1)
        if selected_slug != match.group(1):
            raise MemoryLinkGraphError("requested project slug does not match the catalog")
        return cls(
            snapshot["events"],
            task_records=snapshot["task_records"],
            project_slug=selected_slug,
            source_namespace=namespace,
            source_digest=str(verification["source_digest"]),
            catalog_digest=str(verification["catalog_digest"]),
            max_nodes=max_nodes,
            max_links=max_links,
        )

    @staticmethod
    def _normalize_task_records(
        task_records: Sequence[Mapping[str, Any]],
    ) -> dict[str, dict[str, Any]]:
        documents: dict[str, dict[str, Any]] = {}
        for record in task_records:
            task_id = _bounded_text(
                _normalize_legacy_projection_text(record.get("task_id")),
                field="task record id",
                maximum=MAX_IDENTIFIER_LENGTH,
            )
            if _SECRET_SHAPE.search(task_id):
                raise MemoryLinkGraphError("task record id contains secret-shaped text")
            status = _text(record.get("status")).strip()
            if status not in _TASK_STATES:
                raise MemoryLinkGraphError("task record contains an unknown lifecycle state")
            document = {
                "task_id": task_id,
                "status": status,
                "owner": _redact_secret_shape(record.get("owner"), maximum=512, label="task owner"),
                "priority": _text(record.get("priority")).strip()[:32],
                "summary": _redact_secret_shape(
                    record.get("summary"),
                    maximum=MAX_ACTIVITY_SUMMARY_LENGTH,
                    label="task summary",
                ),
                "scope": _redact_secret_shape(
                    record.get("scope"), maximum=2048, label="task scope"
                ),
                "first_event_id": _positive_event_id(
                    record.get("first_event_id"), field="task first_event_id"
                ),
                "last_event_id": _positive_event_id(
                    record.get("last_event_id"), field="task last_event_id"
                ),
            }
            if document["last_event_id"] < document["first_event_id"]:
                raise MemoryLinkGraphError("task record event range is reversed")
            existing = documents.get(task_id)
            if existing is not None and existing != document:
                raise MemoryLinkGraphError("task record is duplicated with conflicting content")
            documents[task_id] = document
        return documents

    def _add_node(
        self,
        *,
        kind: str,
        identifier: Any,
        source_event_id: int,
        title: Any | None = None,
        aliases: Iterable[Any] = (),
        definition: Any | None = None,
        language: Any | None = None,
        explicit: bool = False,
    ) -> str:
        uri = memory_link_uri(self.project_slug, kind, identifier)
        key = _bounded_text(
            identifier, field="memory-link identifier", maximum=MAX_IDENTIFIER_LENGTH
        )
        if _SECRET_SHAPE.search(key):
            raise MemoryLinkGraphError("memory-link identifier contains secret-shaped text")
        node = self._nodes.get(uri)
        if node is None:
            if len(self._nodes) >= self.max_nodes:
                raise MemoryLinkGraphError("memory-link node limit exceeded")
            node = {
                "uri": uri,
                "kind": kind,
                "key": key,
                "title": key,
                "aliases": set(),
                "source_event_ids": set(),
                "declared_titles": set(),
                "definitions": defaultdict(set),
            }
            self._nodes[uri] = node
        node["source_event_ids"].add(source_event_id)
        if title is not None and _text(title).strip():
            clean_title = _bounded_text(title, field="memory-link title", maximum=MAX_TITLE_LENGTH)
            if _SECRET_SHAPE.search(clean_title):
                raise MemoryLinkGraphError("memory-link title contains secret-shaped text")
            if explicit:
                node["declared_titles"].add(clean_title)
                # A stable URI can acquire a better display title in a later
                # append-only curation event.  Preserve every prior declared
                # title as an alias and let the newest event title win; title
                # evolution must not make the complete graph unavailable.
                node["title"] = clean_title
            elif not node["declared_titles"]:
                node["title"] = clean_title
        alias_values = [key, node["title"], *sorted(node["declared_titles"]), *aliases]
        for alias in alias_values:
            if not _text(alias).strip():
                continue
            clean_alias = _bounded_text(alias, field="memory alias", maximum=MAX_ALIAS_LENGTH)
            if _SECRET_SHAPE.search(clean_alias):
                raise MemoryLinkGraphError("memory alias contains secret-shaped text")
            node["aliases"].add(clean_alias)
            if len(node["aliases"]) > MAX_ALIASES_PER_NODE:
                raise MemoryLinkGraphError(f"memory-link alias limit exceeded for {uri}")
        if definition is not None and _text(definition).strip():
            if not explicit:
                raise MemoryLinkGraphError(
                    "memory definitions require an explicit node declaration"
                )
            clean_definition = _bounded_text(
                definition,
                field="memory node definition",
                maximum=MAX_DEFINITION_LENGTH,
            )
            if _SECRET_SHAPE.search(clean_definition):
                raise MemoryLinkGraphError("memory node definition contains secret-shaped text")
            clean_language = (
                _bounded_text(
                    language,
                    field="memory definition language",
                    maximum=MAX_DEFINITION_LANGUAGE_LENGTH,
                )
                if language is not None and _text(language).strip()
                else "und"
            )
            if re.fullmatch(r"[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*|und", clean_language) is None:
                raise MemoryLinkGraphError(
                    "memory definition language is not a bounded language tag"
                )
            node["definitions"][(clean_definition, clean_language)].add(source_event_id)
        elif language is not None and _text(language).strip():
            raise MemoryLinkGraphError("memory definition language requires a definition")
        return uri

    def _event_uri(self, event_id: int) -> str:
        return memory_link_uri(self.project_slug, "event", event_id)

    def _node_reference(self, value: Any) -> str:
        if isinstance(value, str):
            if value.startswith("integrity://"):
                _parse_memory_uri(value, project_slug=self.project_slug)
                return value
            if ":" in value:
                kind, identifier = value.split(":", 1)
                return memory_link_uri(self.project_slug, kind, identifier)
            raise MemoryLinkGraphError("compact memory-link references use kind:identifier")
        if isinstance(value, Mapping) and set(value) == {"kind", "id"}:
            return memory_link_uri(self.project_slug, _text(value["kind"]), value["id"])
        raise MemoryLinkGraphError("memory-link endpoint must be a canonical URI or {kind,id}")

    def _explicit_nodes(self, event: Mapping[str, Any]) -> list[Mapping[str, Any]]:
        value = _details(event).get("memory_nodes", [])
        if value is None:
            return []
        if not isinstance(value, list) or any(not isinstance(item, Mapping) for item in value):
            raise MemoryLinkGraphError("details.memory_nodes must be a list of objects")
        return list(value)

    def _explicit_links(self, event: Mapping[str, Any]) -> list[Mapping[str, Any]]:
        value = _details(event).get("memory_links", [])
        if value is None:
            return []
        if not isinstance(value, list) or any(not isinstance(item, Mapping) for item in value):
            raise MemoryLinkGraphError("details.memory_links must be a list of objects")
        return list(value)

    def _index_nodes(self, event: Mapping[str, Any]) -> None:
        event_id = _positive_event_id(event.get("id"), field="event.id")
        raw_event_title = (
            _normalize_legacy_projection_text(event.get("summary")) or f"Seed event {event_id}"
        )
        event_title = _redact_secret_shape(
            raw_event_title,
            maximum=MAX_ALIAS_LENGTH,
            label="canonical event title",
        )
        event_uri = self._add_node(
            kind="event",
            identifier=event_id,
            title=event_title,
            aliases=(f"#{event_id}", f"event {event_id}", f"ActionLog #{event_id}"),
            source_event_id=event_id,
        )
        assert event_uri == self._event_uri(event_id)
        details = _details(event)
        task_id = _normalize_legacy_projection_text(details.get("task_id"))
        if task_id:
            self._add_node(kind="task", identifier=task_id, source_event_id=event_id)
        for field in _TASK_RELATION_FIELDS:
            for related_task in _strings(details.get(field)):
                self._add_node(kind="task", identifier=related_task, source_event_id=event_id)
        for subsystem in _strings(details.get("subsystem")):
            self._add_node(kind="subsystem", identifier=subsystem, source_event_id=event_id)
        for field in _SYSTEM_FIELDS:
            for system in _strings(details.get(field)):
                self._add_node(kind="system", identifier=system, source_event_id=event_id)
        for tag in _strings(event.get("tags")):
            self._add_node(kind="term", identifier=tag, source_event_id=event_id)
        for field in _EVENT_RELATION_FIELDS:
            for related_event in _strings(details.get(field)):
                related_id = _positive_event_id(related_event, field=field)
                if related_id not in self._observed_event_ids:
                    self._unresolved_event_references.add((event_id, field, related_id))
        allowed_node_fields = {"kind", "id", "title", "aliases", "definition", "language"}
        for declaration in self._explicit_nodes(event):
            unknown = set(declaration) - allowed_node_fields
            if unknown or "kind" not in declaration or "id" not in declaration:
                raise MemoryLinkGraphError("memory node declaration has unknown or missing fields")
            aliases = declaration.get("aliases", [])
            if not isinstance(aliases, list):
                raise MemoryLinkGraphError("memory node aliases must be a list")
            self._add_node(
                kind=_text(declaration["kind"]),
                identifier=declaration["id"],
                title=declaration.get("title"),
                aliases=aliases,
                definition=declaration.get("definition"),
                language=declaration.get("language"),
                source_event_id=event_id,
                explicit=True,
            )

    def _add_link(
        self,
        *,
        source_uri: str,
        relation: str,
        target_uri: str,
        provenance: str,
        source_event_id: int,
        claim_state: str = "",
        stale_after: str = "",
    ) -> None:
        if relation not in MEMORY_LINK_RELATIONS:
            raise MemoryLinkGraphError(f"unsupported memory-link relation: {relation}")
        if source_uri == target_uri:
            raise MemoryLinkGraphError("memory-link self edges are prohibited")
        if source_uri not in self._nodes or target_uri not in self._nodes:
            raise MemoryLinkGraphError("memory-link endpoint is not declared in this snapshot")
        key = (source_uri, relation, target_uri, provenance)
        if key not in self._links and len(self._links) >= self.max_links:
            raise MemoryLinkGraphError("memory-link edge limit exceeded")
        record = self._links.setdefault(
            key,
            {"source_event_ids": set(), "claim_states": set(), "stale_after": set()},
        )
        record["source_event_ids"].add(source_event_id)
        if claim_state:
            normalized_state = _text(claim_state).strip().upper()
            if normalized_state not in _CLAIM_STATES:
                raise MemoryLinkGraphError("memory link claim_state is unsupported")
            record["claim_states"].add(normalized_state)
        if stale_after:
            record["stale_after"].add(
                _normalize_timestamp(stale_after, field="memory link stale_after")
            )

    def _add_legacy_link(
        self,
        *,
        source_uri: str,
        relation: str,
        target_uri: str,
        source_event_id: int,
    ) -> None:
        if source_uri == target_uri:
            self._ignored_legacy_self_link_nodes.add(source_uri)
            return
        self._add_link(
            source_uri=source_uri,
            relation=relation,
            target_uri=target_uri,
            provenance="structured-seed",
            source_event_id=source_event_id,
        )

    def _index_links(self, event: Mapping[str, Any]) -> None:
        event_id = _positive_event_id(event.get("id"), field="event.id")
        event_uri = self._event_uri(event_id)
        details = _details(event)
        task_id = _normalize_legacy_projection_text(details.get("task_id"))
        task_uri = ""
        if task_id:
            task_uri = memory_link_uri(self.project_slug, "task", task_id)
            self._add_legacy_link(
                source_uri=event_uri,
                relation="records-task",
                target_uri=task_uri,
                source_event_id=event_id,
            )
        for field, relation in _TASK_RELATION_FIELDS.items():
            if not task_uri:
                continue
            for related_task in _strings(details.get(field)):
                self._add_legacy_link(
                    source_uri=task_uri,
                    relation=relation,
                    target_uri=memory_link_uri(self.project_slug, "task", related_task),
                    source_event_id=event_id,
                )
        for subsystem in _strings(details.get("subsystem")):
            self._add_legacy_link(
                source_uri=event_uri,
                relation="concerns",
                target_uri=memory_link_uri(self.project_slug, "subsystem", subsystem),
                source_event_id=event_id,
            )
        for field in _SYSTEM_FIELDS:
            for system in _strings(details.get(field)):
                self._add_legacy_link(
                    source_uri=event_uri,
                    relation="concerns",
                    target_uri=memory_link_uri(self.project_slug, "system", system),
                    source_event_id=event_id,
                )
        for tag in _strings(event.get("tags")):
            self._add_legacy_link(
                source_uri=event_uri,
                relation="tagged-with",
                target_uri=memory_link_uri(self.project_slug, "term", tag),
                source_event_id=event_id,
            )
        for field, relation in _EVENT_RELATION_FIELDS.items():
            for related_event in _strings(details.get(field)):
                related_id = _positive_event_id(related_event, field=field)
                if related_id not in self._observed_event_ids:
                    continue
                self._add_legacy_link(
                    source_uri=event_uri,
                    relation=relation,
                    target_uri=self._event_uri(related_id),
                    source_event_id=event_id,
                )
        for declaration in self._explicit_nodes(event):
            self._add_link(
                source_uri=event_uri,
                relation="defines",
                target_uri=memory_link_uri(
                    self.project_slug,
                    _text(declaration["kind"]),
                    declaration["id"],
                ),
                provenance="explicit-memory-node",
                source_event_id=event_id,
            )
        allowed_link_fields = {"source", "relation", "target", "claim_state", "stale_after"}
        for declaration in self._explicit_links(event):
            unknown = set(declaration) - allowed_link_fields
            if unknown or "relation" not in declaration or "target" not in declaration:
                raise MemoryLinkGraphError("memory link declaration has unknown or missing fields")
            self._add_link(
                source_uri=(
                    self._node_reference(declaration["source"])
                    if "source" in declaration
                    else event_uri
                ),
                relation=_text(declaration["relation"]),
                target_uri=self._node_reference(declaration["target"]),
                provenance="explicit-memory-link",
                source_event_id=event_id,
                claim_state=_text(declaration.get("claim_state")).strip(),
                stale_after=_text(declaration.get("stale_after")).strip(),
            )

    def _freeze(self) -> None:
        node_documents: list[dict[str, Any]] = []
        alias_index: dict[str, set[str]] = defaultdict(set)
        for uri in sorted(self._nodes):
            raw = self._nodes[uri]
            aliases = sorted(raw["aliases"], key=lambda item: (normalize_memory_alias(item), item))
            document = {
                "uri": uri,
                "kind": raw["kind"],
                "key": raw["key"],
                "title": raw["title"],
                "aliases": aliases,
                "source_event_ids": sorted(raw["source_event_ids"]),
                "definitions": [
                    {
                        "text": text,
                        "language": language,
                        "source_event_ids": sorted(source_event_ids),
                    }
                    for (text, language), source_event_ids in sorted(
                        raw["definitions"].items(), key=lambda item: item[0]
                    )
                ],
            }
            node_documents.append(document)
            for alias in aliases:
                alias_index[normalize_memory_alias(alias)].add(uri)
        link_documents = []
        for (source_uri, relation, target_uri, provenance), record in sorted(self._links.items()):
            link_documents.append(
                {
                    "source_uri": source_uri,
                    "relation": relation,
                    "target_uri": target_uri,
                    "provenance": provenance,
                    "source_event_ids": sorted(record["source_event_ids"]),
                    "claim_states": sorted(record["claim_states"]),
                    "stale_after": sorted(record["stale_after"]),
                }
            )
        self._node_documents = {item["uri"]: item for item in node_documents}
        self._alias_index = {key: tuple(sorted(values)) for key, values in alias_index.items()}
        outbound: dict[str, list[dict[str, Any]]] = defaultdict(list)
        inbound: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for link in link_documents:
            outbound[link["source_uri"]].append(link)
            inbound[link["target_uri"]].append(link)
        self._outbound = {key: tuple(value) for key, value in outbound.items()}
        self._inbound = {key: tuple(value) for key, value in inbound.items()}
        self.node_count = len(node_documents)
        self.link_count = len(link_documents)
        self.unresolved_event_reference_count = len(self._unresolved_event_references)
        self.ignored_legacy_self_link_count = len(self._ignored_legacy_self_link_nodes)
        self._ignored_legacy_self_link_nodes = frozenset(
            self._ignored_legacy_self_link_nodes
        )
        task_documents = [self._task_documents[key] for key in sorted(self._task_documents)]
        graph_header = {
            "protocol": MEMORY_LINK_GRAPH_PROTOCOL,
            "source_namespace": self.source_namespace,
            "source_digest": self.source_digest,
            "catalog_digest": self.catalog_digest,
            "source_event_count": self.source_event_count,
            "source_max_event_id": self.source_max_event_id,
            "source_max_event_time": self.source_max_event_time,
            "node_count": self.node_count,
            "link_count": self.link_count,
            "unresolved_event_reference_count": self.unresolved_event_reference_count,
            "ignored_legacy_self_link_count": self.ignored_legacy_self_link_count,
            "task_card_count": len(task_documents),
            "production_authority": False,
            "route_authority": False,
        }
        self.graph_digest = _stream_digest(
            domain="memory-link-graph-v1",
            documents=[graph_header, *node_documents, *link_documents, *task_documents],
        )
        del self._nodes
        del self._links
        del self._observed_event_ids
        del self._unresolved_event_references

    def summary(self) -> dict[str, Any]:
        return {
            "protocol": MEMORY_LINK_GRAPH_PROTOCOL,
            "graph_digest": self.graph_digest,
            "source_namespace": self.source_namespace,
            "source_digest": self.source_digest,
            "catalog_digest": self.catalog_digest,
            "source_event_count": self.source_event_count,
            "source_max_event_id": self.source_max_event_id,
            "source_max_event_time": self.source_max_event_time,
            "node_count": self.node_count,
            "link_count": self.link_count,
            "unresolved_event_reference_count": self.unresolved_event_reference_count,
            "ignored_legacy_self_link_count": self.ignored_legacy_self_link_count,
            "task_card_count": len(self._task_documents),
            "alias_key_count": len(self._alias_index),
            "entity_brief_protocol": MEMORY_ENTITY_BRIEF_PROTOCOL,
            "audit_protocol": MEMORY_LINK_AUDIT_PROTOCOL,
            "persistent_derived_state": False,
            "production_authority": False,
            "route_authority": False,
        }

    def _node_summary(self, uri: str) -> dict[str, Any]:
        node = self._node_documents[uri]
        aliases = node["aliases"][:MAX_RENDERED_ALIASES]
        source_event_ids = node["source_event_ids"][:MAX_RENDERED_SOURCE_EVENT_IDS]
        return {
            "uri": uri,
            "kind": node["kind"],
            "key": node["key"],
            "title": node["title"],
            "aliases": aliases,
            "alias_count": len(node["aliases"]),
            "omitted_alias_count": len(node["aliases"]) - len(aliases),
            "source_event_ids": source_event_ids,
            "source_event_count": len(node["source_event_ids"]),
            "omitted_source_event_count": len(node["source_event_ids"]) - len(source_event_ids),
        }

    def _candidate_rank_key(self, uri: str) -> tuple[int, int, int, int, int, int, str]:
        node = self._node_documents[uri]
        links = (*self._outbound.get(uri, ()), *self._inbound.get(uri, ()))
        explicit_link_count = sum(
            1 for link in links if str(link["provenance"]).startswith("explicit-memory-")
        )
        return (
            0 if node["definitions"] else 1,
            _ENTITY_KIND_PRIORITY[node["kind"]],
            _identifier_shape_rank(node["key"]),
            -explicit_link_count,
            -len(node["source_event_ids"]),
            -len(links),
            uri,
        )

    def _audit_rank_key(
        self,
        uri: str,
        *,
        issues: Sequence[str],
        direct_link_count: int,
    ) -> tuple[int, int, int, int, int, int, str]:
        node = self._node_documents[uri]
        links = (*self._outbound.get(uri, ()), *self._inbound.get(uri, ()))
        explicit_link_count = sum(
            1 for link in links if str(link["provenance"]).startswith("explicit-memory-")
        )
        return (
            _ENTITY_KIND_PRIORITY[node["kind"]],
            _identifier_shape_rank(node["key"]),
            min(_AUDIT_ISSUE_PRIORITY[issue] for issue in issues),
            -explicit_link_count,
            -len(node["source_event_ids"]),
            -direct_link_count,
            uri,
        )

    def _adjacency_rank_key(
        self,
        item: tuple[dict[str, Any], str, str],
    ) -> tuple[int, int, str, str, int, int, str, str, tuple[int, ...]]:
        link, direction, neighbour_uri = item
        neighbour = self._node_documents[neighbour_uri]
        return (
            _RELATION_NEIGHBOR_KIND_PRIORITY[neighbour["kind"]],
            0 if str(link["provenance"]).startswith("explicit-memory-") else 1,
            link["relation"],
            direction,
            _identifier_shape_rank(neighbour["key"]),
            -len(link["source_event_ids"]),
            neighbour_uri,
            link["provenance"],
            tuple(link["source_event_ids"]),
        )

    def _event_time(self, event_id: int) -> str:
        document = self._event_documents.get(event_id)
        return str(document["ts_utc"]) if document is not None else ""

    def _link_freshness(self, link: Mapping[str, Any]) -> dict[str, Any]:
        source_event_ids = list(link["source_event_ids"])
        latest_event_id = max(source_event_ids)
        latest_event_at = self._event_time(latest_event_id)
        claim_states = set(link.get("claim_states", ()))
        stale_after_values = set(link.get("stale_after", ()))
        state = "UNKNOWN"
        basis = "none"
        stale_after = ""
        policy_state = ""
        if len(stale_after_values) > 1:
            state = "CONTRADICTED"
            basis = "conflicting-stale-after-policy"
        elif stale_after_values:
            stale_after = next(iter(stale_after_values))
            if self.source_max_event_time:
                policy_state = "STALE" if self.source_max_event_time > stale_after else "CURRENT"
                state = policy_state
                basis = "stale-after-policy"
        if len(claim_states) > 1:
            state = "CONTRADICTED"
            basis = "conflicting-explicit-claim-state"
        elif claim_states:
            explicit_state = next(iter(claim_states))
            if policy_state and explicit_state not in {policy_state, "UNKNOWN"}:
                state = "CONTRADICTED"
                basis = "explicit-state-policy-conflict"
            else:
                state = explicit_state
                basis = "explicit-claim-state"
        return {
            "state": state,
            "basis": basis,
            "latest_supporting_event_id": latest_event_id,
            "latest_supporting_event_at": latest_event_at,
            "stale_after": stale_after,
        }

    def _link_summary(
        self, link: Mapping[str, Any], *, include_freshness: bool = False
    ) -> dict[str, Any]:
        source_event_ids = link["source_event_ids"][:MAX_RENDERED_SOURCE_EVENT_IDS]
        result = {
            "source_uri": link["source_uri"],
            "relation": link["relation"],
            "target_uri": link["target_uri"],
            "provenance": link["provenance"],
            "source_event_ids": source_event_ids,
            "source_event_count": len(link["source_event_ids"]),
            "omitted_source_event_count": len(link["source_event_ids"]) - len(source_event_ids),
        }
        if include_freshness:
            result["freshness"] = self._link_freshness(link)
        return result

    def _adjacency(
        self,
        uri: str,
        *,
        direction: str,
        relation_filter: Sequence[str],
    ) -> list[tuple[dict[str, Any], str, str]]:
        eligible: list[tuple[dict[str, Any], str, str]] = []
        if direction in {"outbound", "both"}:
            eligible.extend(
                (link, "outbound", link["target_uri"]) for link in self._outbound.get(uri, ())
            )
        if direction in {"inbound", "both"}:
            eligible.extend(
                (link, "inbound", link["source_uri"]) for link in self._inbound.get(uri, ())
            )
        if relation_filter:
            eligible = [item for item in eligible if item[0]["relation"] in relation_filter]
        eligible.sort(key=self._adjacency_rank_key)
        return eligible

    def _resolve_uris(self, reference: str) -> tuple[str, tuple[str, ...]]:
        if reference.startswith("integrity://"):
            _parse_memory_uri(reference, project_slug=self.project_slug)
            matches = (reference,) if reference in self._node_documents else ()
            return reference, matches
        normalized = normalize_memory_alias(reference)
        matches = self._alias_index.get(normalized, ())
        return normalized, tuple(sorted(matches, key=self._candidate_rank_key))

    def resolve(
        self,
        reference: str,
        *,
        limit: int = DEFAULT_PAGE_LIMIT,
        max_context_bytes: int = DEFAULT_MAX_CONTEXT_BYTES,
        cursor: str = "",
    ) -> dict[str, Any]:
        """Resolve one exact URI or normalized alias without fuzzy invention."""

        limit = _page_limit(limit)
        max_context_bytes = _context_budget(max_context_bytes)
        query_key, matches = self._resolve_uris(reference)
        cursor_context = {
            "protocol": MEMORY_LINK_RESOLUTION_PROTOCOL,
            "graph_digest": self.graph_digest,
            "query_key": query_key,
            "ranking_policy": MEMORY_LINK_RANKING_POLICY,
        }
        offset = _cursor_decode(cursor, cursor_context) if cursor else 0
        if offset > len(matches):
            raise MemoryLinkGraphError("memory-link cursor offset exceeds candidate set")
        result = "EXACT" if len(matches) == 1 else "AMBIGUOUS" if matches else "NOT_FOUND"
        rendered: list[dict[str, Any]] = []
        next_offset = offset
        truncated_by = "none"
        for uri in matches[offset:]:
            if len(rendered) >= limit:
                truncated_by = "limit"
                break
            candidate = self._node_summary(uri)
            tentative = {
                "protocol": MEMORY_LINK_RESOLUTION_PROTOCOL,
                "graph_digest": self.graph_digest,
                "query": reference,
                "result": result,
                "candidate_count": len(matches),
                "matches": [*rendered, candidate],
                "max_context_bytes": max_context_bytes,
            }
            if len(canonical_bytes(tentative)) + 1024 > max_context_bytes:
                truncated_by = "context-bytes"
                break
            rendered.append(candidate)
            next_offset += 1
        has_more = next_offset < len(matches)
        next_cursor = _cursor_encode({**cursor_context, "offset": next_offset}) if has_more else ""
        core = {
            "protocol": MEMORY_LINK_RESOLUTION_PROTOCOL,
            "graph_digest": self.graph_digest,
            "source_namespace": self.source_namespace,
            "query": reference,
            "normalized_query": query_key,
            "result": result,
            "candidate_count": len(matches),
            "matches": rendered,
            "pagination": {
                "returned_count": len(rendered),
                "has_more": has_more,
                "next_cursor": next_cursor,
                "omitted_count": len(matches) - next_offset,
                "truncated_by": truncated_by,
            },
            "max_context_bytes": max_context_bytes,
            "production_authority": False,
            "route_authority": False,
        }
        result_document = {
            **core,
            "receipt_id": digest_object(core, domain="memory-link-resolution-v1"),
        }
        if len(canonical_bytes(result_document)) > max_context_bytes:
            raise MemoryLinkGraphError("resolution metadata exceeds the requested context budget")
        return result_document

    def navigate(
        self,
        anchor: str,
        *,
        direction: str = "both",
        relations: Sequence[str] = (),
        trail: Sequence[str] = (),
        limit: int = DEFAULT_PAGE_LIMIT,
        max_context_bytes: int = DEFAULT_MAX_CONTEXT_BYTES,
        cursor: str = "",
    ) -> dict[str, Any]:
        """Return one bounded, cursor-stable hyperlink page around an anchor."""

        limit = _page_limit(limit)
        max_context_bytes = _context_budget(max_context_bytes)
        if direction not in {"outbound", "inbound", "both"}:
            raise MemoryLinkGraphError("direction must be outbound, inbound or both")
        relation_filter = tuple(sorted(set(relations)))
        unknown_relations = set(relation_filter) - MEMORY_LINK_RELATIONS
        if unknown_relations:
            raise MemoryLinkGraphError(
                "unsupported memory-link relation filter: " + ", ".join(sorted(unknown_relations))
            )
        _, candidates = self._resolve_uris(anchor)
        resolution_result = (
            "EXACT" if len(candidates) == 1 else "AMBIGUOUS" if candidates else "NOT_FOUND"
        )
        if len(candidates) != 1:
            rendered_candidates: list[dict[str, Any]] = []
            truncated_by = "limit" if len(candidates) > 20 else "none"
            for uri in candidates[:20]:
                candidate = self._node_summary(uri)
                tentative = {
                    "protocol": MEMORY_LINK_NAVIGATION_PROTOCOL,
                    "graph_digest": self.graph_digest,
                    "source_namespace": self.source_namespace,
                    "result": resolution_result,
                    "candidate_count": len(candidates),
                    "candidates": [*rendered_candidates, candidate],
                    "max_context_bytes": max_context_bytes,
                }
                if len(canonical_bytes(tentative)) + 1536 > max_context_bytes:
                    truncated_by = "context-bytes"
                    break
                rendered_candidates.append(candidate)
            core = {
                "protocol": MEMORY_LINK_NAVIGATION_PROTOCOL,
                "graph_digest": self.graph_digest,
                "source_namespace": self.source_namespace,
                "result": resolution_result,
                "anchor": None,
                "candidate_count": len(candidates),
                "candidates": rendered_candidates,
                "trail": [],
                "visited_digest": digest_object([], domain="memory-link-visited-v1"),
                "direction": direction,
                "relations": list(relation_filter),
                "links": [],
                "link_counts": {"eligible": 0, "returned": 0, "omitted": 0},
                "pagination": {
                    "has_more": False,
                    "next_cursor": "",
                    "truncated_by": truncated_by,
                },
                "max_context_bytes": max_context_bytes,
                "production_authority": False,
                "route_authority": False,
            }
            result_document = {
                **core,
                "receipt_id": digest_object(core, domain="memory-link-navigation-v1"),
            }
            if len(canonical_bytes(result_document)) > max_context_bytes:
                raise MemoryLinkGraphError(
                    "navigation metadata exceeds the requested context budget"
                )
            return result_document
        anchor_uri = candidates[0]
        if len(trail) > MAX_TRAIL_LENGTH:
            raise MemoryLinkGraphError(f"navigation trail exceeds {MAX_TRAIL_LENGTH} nodes")
        canonical_trail: list[str] = []
        for item in trail:
            _, trail_matches = self._resolve_uris(item)
            if len(trail_matches) != 1:
                raise MemoryLinkGraphError("every navigation trail item must resolve exactly")
            canonical_trail.append(trail_matches[0])
        if canonical_trail and canonical_trail[-1] != anchor_uri:
            raise MemoryLinkGraphError("navigation trail must end at the anchor")
        if not canonical_trail:
            canonical_trail.append(anchor_uri)
        visited = set(canonical_trail)
        visited_digest = digest_object(canonical_trail, domain="memory-link-visited-v1")
        eligible = self._adjacency(
            anchor_uri,
            direction=direction,
            relation_filter=relation_filter,
        )
        cursor_context = {
            "protocol": MEMORY_LINK_NAVIGATION_PROTOCOL,
            "graph_digest": self.graph_digest,
            "anchor_uri": anchor_uri,
            "direction": direction,
            "relations": list(relation_filter),
            "visited_digest": visited_digest,
            "ranking_policy": MEMORY_LINK_RANKING_POLICY,
        }
        offset = _cursor_decode(cursor, cursor_context) if cursor else 0
        if offset > len(eligible):
            raise MemoryLinkGraphError("memory-link cursor offset exceeds adjacency set")
        rendered: list[dict[str, Any]] = []
        next_offset = offset
        truncated_by = "none"
        for link, link_direction, neighbour_uri in eligible[offset:]:
            if len(rendered) >= limit:
                truncated_by = "limit"
                break
            cycle = neighbour_uri in visited
            candidate = {
                **self._link_summary(link),
                "direction": link_direction,
                "neighbor": self._node_summary(neighbour_uri),
                "cycle": cycle,
                "follow_allowed": not cycle,
            }
            tentative = {
                "protocol": MEMORY_LINK_NAVIGATION_PROTOCOL,
                "graph_digest": self.graph_digest,
                "anchor": self._node_summary(anchor_uri),
                "trail": canonical_trail,
                "links": [*rendered, candidate],
                "max_context_bytes": max_context_bytes,
            }
            if len(canonical_bytes(tentative)) + 1536 > max_context_bytes:
                if not rendered:
                    raise MemoryLinkGraphError(
                        "navigation item exceeds the requested context budget"
                    )
                truncated_by = "context-bytes"
                break
            rendered.append(candidate)
            next_offset += 1
        has_more = next_offset < len(eligible)
        next_cursor = _cursor_encode({**cursor_context, "offset": next_offset}) if has_more else ""
        core = {
            "protocol": MEMORY_LINK_NAVIGATION_PROTOCOL,
            "graph_digest": self.graph_digest,
            "source_namespace": self.source_namespace,
            "result": "CONNECTED" if eligible else "ISOLATED",
            "anchor": self._node_summary(anchor_uri),
            "candidate_count": 1,
            "candidates": [],
            "trail": canonical_trail,
            "visited_digest": visited_digest,
            "direction": direction,
            "relations": list(relation_filter),
            "links": rendered,
            "link_counts": {
                "eligible": len(eligible),
                "returned": len(rendered),
                "omitted": len(eligible) - next_offset,
            },
            "pagination": {
                "has_more": has_more,
                "next_cursor": next_cursor,
                "truncated_by": truncated_by,
            },
            "max_context_bytes": max_context_bytes,
            "production_authority": False,
            "route_authority": False,
        }
        result = {
            **core,
            "receipt_id": digest_object(core, domain="memory-link-navigation-v1"),
        }
        if len(canonical_bytes(result)) > max_context_bytes:
            raise MemoryLinkGraphError("navigation metadata exceeds the requested context budget")
        return result

    def _definition_summary(self, uri: str) -> dict[str, Any]:
        definitions = self._node_documents[uri]["definitions"]
        values = []
        for definition in definitions[:MAX_RENDERED_DEFINITIONS]:
            source_event_ids = definition["source_event_ids"][:MAX_RENDERED_SOURCE_EVENT_IDS]
            values.append(
                {
                    "text": definition["text"],
                    "language": definition["language"],
                    "source_event_ids": source_event_ids,
                    "source_event_count": len(definition["source_event_ids"]),
                    "omitted_source_event_count": (
                        len(definition["source_event_ids"]) - len(source_event_ids)
                    ),
                }
            )
        status = (
            "UNKNOWN"
            if not definitions
            else "DECLARED"
            if len(definitions) == 1
            else "CONTRADICTED"
        )
        return {
            "status": status,
            "definition_count": len(definitions),
            "values": values,
            "omitted_count": len(definitions) - len(values),
        }

    def _related_task_uris(self, anchor_uri: str) -> tuple[list[str], bool]:
        queue: deque[tuple[str, int]] = deque([(anchor_uri, 0)])
        visited = {anchor_uri}
        tasks: set[str] = set()
        if self._node_documents[anchor_uri]["kind"] == "task":
            tasks.add(anchor_uri)
        search_truncated = False
        while queue:
            current_uri, depth = queue.popleft()
            if depth >= 2:
                continue
            for link, _, neighbour_uri in self._adjacency(
                current_uri,
                direction="both",
                relation_filter=(),
            ):
                if link["relation"] not in _TASK_JOIN_RELATIONS:
                    continue
                if neighbour_uri in visited:
                    continue
                if len(visited) >= MAX_ENTITY_TASK_SEARCH_NODES:
                    search_truncated = True
                    continue
                visited.add(neighbour_uri)
                if self._node_documents[neighbour_uri]["kind"] == "task":
                    tasks.add(neighbour_uri)
                queue.append((neighbour_uri, depth + 1))
        return sorted(tasks), search_truncated

    def _task_section(self, anchor_uri: str, *, limit: int) -> dict[str, Any]:
        task_uris, search_truncated = self._related_task_uris(anchor_uri)
        cards: list[dict[str, Any]] = []
        missing_card_count = 0
        for uri in task_uris:
            task_id = self._node_documents[uri]["key"]
            card = self._task_documents.get(task_id)
            if card is None:
                missing_card_count += 1
                continue
            if len(cards) < limit:
                cards.append(dict(card))
        candidate_count = len(task_uris)
        omitted_count = max(0, candidate_count - missing_card_count - len(cards))
        return {
            "candidate_count": candidate_count,
            "cards": cards,
            "returned_count": len(cards),
            "omitted_count": omitted_count,
            "missing_card_count": missing_card_count,
            "search_truncated": search_truncated,
            "status_counts": {
                status: sum(1 for card in cards if card["status"] == status)
                for status in _TASK_STATES
            },
        }

    def _safe_event_document(self, event_id: int, reasons: Iterable[str]) -> dict[str, Any] | None:
        document = self._event_documents.get(event_id)
        if document is None:
            return None
        summary = str(document["summary"])
        action = str(document["action"])
        task_id = str(document["task_id"])
        redacted = any(_SECRET_SHAPE.search(value) for value in (summary, action, task_id))
        return {
            **document,
            "summary": "[redacted secret-shaped canonical summary]" if redacted else summary,
            "action": (
                "[redacted secret-shaped action]" if _SECRET_SHAPE.search(action) else action
            ),
            "task_id": (
                "[redacted secret-shaped task id]" if _SECRET_SHAPE.search(task_id) else task_id
            ),
            "redacted": redacted,
            "reasons": sorted(set(reasons)),
        }

    def _activity_section(
        self,
        anchor_uri: str,
        adjacency: Sequence[tuple[dict[str, Any], str, str]],
        task_cards: Sequence[Mapping[str, Any]],
        *,
        limit: int,
    ) -> dict[str, Any]:
        reasons_by_event: dict[int, set[str]] = defaultdict(set)
        for event_id in self._node_documents[anchor_uri]["source_event_ids"]:
            reasons_by_event[event_id].add("ENTITY_SOURCE")
        for link, _, _ in adjacency:
            for event_id in link["source_event_ids"]:
                reasons_by_event[event_id].add("LINK_PROVENANCE")
        for card in task_cards:
            reasons_by_event[int(card["last_event_id"])].add("TASK_LIFECYCLE")
        ordered_ids = sorted(reasons_by_event, reverse=True)
        documents = [
            document
            for event_id in ordered_ids
            if (
                document := self._safe_event_document(
                    event_id,
                    reasons_by_event[event_id],
                )
            )
            is not None
        ]
        returned = documents[:limit]
        return {
            "event_count": len(documents),
            "events": returned,
            "returned_count": len(returned),
            "omitted_count": len(documents) - len(returned),
        }

    def _discovery_section(
        self,
        reference: str,
        *,
        excluded_event_ids: set[int],
        limit: int,
    ) -> dict[str, Any]:
        tokens = _lexical_tokens(reference)
        scored: dict[int, set[str]] = defaultdict(set)
        for token in tokens:
            for event_id in self._search_postings.get(token, ()):
                if event_id not in excluded_event_ids:
                    scored[event_id].add(token)
        ordered = sorted(scored, key=lambda item: (-len(scored[item]), -item))
        candidates: list[dict[str, Any]] = []
        for event_id in ordered[:limit]:
            document = self._safe_event_document(event_id, ("LEXICAL_DISCOVERY",))
            if document is None:
                continue
            candidates.append(
                {
                    **document,
                    "matched_terms": sorted(scored[event_id]),
                    "admission_status": "UNADMITTED",
                    "canonical_link": False,
                    "follow_allowed": False,
                }
            )
        return {
            "candidate_count": len(ordered),
            "candidates": candidates,
            "returned_count": len(candidates),
            "omitted_count": len(ordered) - len(candidates),
        }

    def entity_brief(
        self,
        reference: str,
        *,
        relationship_limit: int = DEFAULT_ENTITY_RELATION_LIMIT,
        activity_limit: int = DEFAULT_ENTITY_ACTIVITY_LIMIT,
        task_limit: int = DEFAULT_ENTITY_TASK_LIMIT,
        discovery_limit: int = DEFAULT_DISCOVERY_LIMIT,
        max_context_bytes: int = 64 * 1024,
    ) -> dict[str, Any]:
        """Build one optional, bounded and authority-free entity article."""

        relationship_limit = _bounded_integer(
            relationship_limit,
            field="relationship_limit",
            minimum=1,
            maximum=MAX_ENTITY_RELATION_LIMIT,
        )
        activity_limit = _bounded_integer(
            activity_limit,
            field="activity_limit",
            minimum=1,
            maximum=MAX_ENTITY_ACTIVITY_LIMIT,
        )
        task_limit = _bounded_integer(
            task_limit,
            field="task_limit",
            minimum=1,
            maximum=MAX_ENTITY_TASK_LIMIT,
        )
        discovery_limit = _bounded_integer(
            discovery_limit,
            field="discovery_limit",
            minimum=1,
            maximum=MAX_DISCOVERY_LIMIT,
        )
        max_context_bytes = _context_budget(max_context_bytes)
        query_key, resolved_uris = self._resolve_uris(reference)
        exact = len(resolved_uris) == 1
        result = "READY" if exact else "AMBIGUOUS" if resolved_uris else "NOT_FOUND"
        candidates = [self._node_summary(uri) for uri in resolved_uris[:20]] if not exact else []
        candidate_omitted = max(0, len(resolved_uris) - len(candidates))
        identity = self._node_summary(resolved_uris[0]) if exact else None
        definition = (
            self._definition_summary(resolved_uris[0])
            if exact
            else {
                "status": "UNKNOWN",
                "definition_count": 0,
                "values": [],
                "omitted_count": 0,
            }
        )
        adjacency = (
            self._adjacency(resolved_uris[0], direction="both", relation_filter=()) if exact else []
        )
        relationship_links = [
            {
                **self._link_summary(link, include_freshness=True),
                "direction": direction,
                "neighbor": self._node_summary(neighbour_uri),
            }
            for link, direction, neighbour_uri in adjacency[:relationship_limit]
        ]
        relationships = {
            "eligible_count": len(adjacency),
            "returned_count": len(relationship_links),
            "omitted_count": len(adjacency) - len(relationship_links),
            "truncated_by": "limit" if len(adjacency) > len(relationship_links) else "none",
            "groups": [],
            "continuation": {},
        }
        whereabouts_links = [
            {
                **self._link_summary(link, include_freshness=True),
                "direction": direction,
                "neighbor": self._node_summary(neighbour_uri),
            }
            for link, direction, neighbour_uri in adjacency
            if link["relation"] == "located-at"
        ][:20]
        whereabouts_eligible = sum(
            1 for link, _, _ in adjacency if link["relation"] == "located-at"
        )
        whereabouts = {
            "eligible_count": whereabouts_eligible,
            "links": whereabouts_links,
            "returned_count": len(whereabouts_links),
            "omitted_count": whereabouts_eligible - len(whereabouts_links),
        }
        tasks = (
            self._task_section(resolved_uris[0], limit=task_limit)
            if exact
            else {
                "candidate_count": 0,
                "cards": [],
                "returned_count": 0,
                "omitted_count": 0,
                "missing_card_count": 0,
                "search_truncated": False,
                "status_counts": {status: 0 for status in _TASK_STATES},
            }
        )
        activity = (
            self._activity_section(
                resolved_uris[0],
                adjacency,
                tasks["cards"],
                limit=activity_limit,
            )
            if exact
            else {"event_count": 0, "events": [], "returned_count": 0, "omitted_count": 0}
        )
        excluded_event_ids = {int(item["event_id"]) for item in activity["events"]}
        if exact:
            excluded_event_ids.update(self._node_documents[resolved_uris[0]]["source_event_ids"])
            for link, _, _ in adjacency:
                excluded_event_ids.update(link["source_event_ids"])
            for card in tasks["cards"]:
                excluded_event_ids.add(int(card["first_event_id"]))
                excluded_event_ids.add(int(card["last_event_id"]))
        discovery = self._discovery_section(
            reference,
            excluded_event_ids=excluded_event_ids,
            limit=discovery_limit,
        )
        claim_counts = {state: 0 for state in _CLAIM_STATES}
        for link, _, _ in adjacency:
            claim_counts[self._link_freshness(link)["state"]] += 1
        known_claims = sum(claim_counts[state] for state in _CLAIM_STATES if state != "UNKNOWN")
        freshness = {
            "snapshot_state": "SNAPSHOT_BOUND",
            "source_max_event_id": self.source_max_event_id,
            "source_max_event_time": self.source_max_event_time,
            "entity_latest_event_id": (
                max(self._node_documents[resolved_uris[0]]["source_event_ids"])
                if identity
                else None
            ),
            "entity_latest_event_time": (
                self._event_time(max(self._node_documents[resolved_uris[0]]["source_event_ids"]))
                if identity
                else ""
            ),
            "policy_status": (
                "ABSENT"
                if adjacency and known_claims == 0
                else "PARTIAL"
                if claim_counts["UNKNOWN"] and known_claims
                else "EXPLICIT"
                if adjacency
                else "ABSENT"
            ),
            "claim_counts": claim_counts,
        }
        byte_truncated = False

        eligible_by_relation = {
            relation: sum(1 for link, _, _ in adjacency if link["relation"] == relation)
            for relation in sorted({link["relation"] for link, _, _ in adjacency})
        }

        def relationship_groups() -> list[dict[str, Any]]:
            groups = []
            for relation, eligible_count in eligible_by_relation.items():
                links = [item for item in relationship_links if item["relation"] == relation]
                groups.append(
                    {
                        "relation": relation,
                        "eligible_count": eligible_count,
                        "links": links,
                        "returned_count": len(links),
                        "omitted_count": eligible_count - len(links),
                    }
                )
            return groups

        def current_unknowns() -> list[str]:
            unknowns: set[str] = set()
            if exact and definition["status"] == "UNKNOWN":
                unknowns.add("definition-unknown")
            if exact and definition["status"] == "CONTRADICTED":
                unknowns.add("definition-contradicted")
            if exact and whereabouts["eligible_count"] == 0:
                unknowns.add("whereabouts-unknown")
            if exact and freshness["policy_status"] == "ABSENT":
                unknowns.add("freshness-policy-absent")
            if exact and freshness["policy_status"] == "PARTIAL":
                unknowns.add("freshness-policy-partial")
            if exact and resolved_uris[0] in self._ignored_legacy_self_link_nodes:
                unknowns.add("legacy-self-link-ignored")
            if tasks["missing_card_count"]:
                unknowns.add("canonical-task-card-missing")
            if tasks["search_truncated"]:
                unknowns.add("task-search-truncated")
            if tasks["omitted_count"]:
                unknowns.add("tasks-truncated")
            if relationships["omitted_count"]:
                unknowns.add("relationships-truncated")
            if activity["omitted_count"]:
                unknowns.add("activity-truncated")
            if whereabouts["omitted_count"]:
                unknowns.add("whereabouts-truncated")
            if definition["omitted_count"]:
                unknowns.add("definitions-truncated")
            if candidate_omitted:
                unknowns.add("resolution-candidates-truncated")
            if discovery["candidate_count"]:
                unknowns.add("legacy-discovery-candidates")
            if discovery["omitted_count"]:
                unknowns.add("discovery-candidates-truncated")
            if byte_truncated:
                unknowns.add("context-bytes")
            return sorted(unknowns)

        def core_document() -> dict[str, Any]:
            tasks["returned_count"] = len(tasks["cards"])
            tasks["status_counts"] = {
                status: sum(1 for card in tasks["cards"] if card["status"] == status)
                for status in _TASK_STATES
            }
            activity["returned_count"] = len(activity["events"])
            relationships["returned_count"] = len(relationship_links)
            relationships["groups"] = relationship_groups()
            relationships["continuation"] = {
                "available": relationships["omitted_count"] > 0,
                "cli_command": "memory-link-navigate",
                "endpoint": "/v1/seed/memory-links/navigate",
                "anchor_uri": resolved_uris[0] if exact else "",
                "direction": "both",
            }
            whereabouts["returned_count"] = len(whereabouts["links"])
            discovery["returned_count"] = len(discovery["candidates"])
            return {
                "protocol": MEMORY_ENTITY_BRIEF_PROTOCOL,
                "graph_digest": self.graph_digest,
                "source_namespace": self.source_namespace,
                "query": reference,
                "normalized_query": query_key,
                "result": result,
                "identity": identity,
                "candidate_count": len(resolved_uris),
                "candidates": candidates,
                "candidate_omitted_count": candidate_omitted,
                "definition": definition,
                "whereabouts": whereabouts,
                "relationships": relationships,
                "activity": activity,
                "freshness": freshness,
                "tasks": tasks,
                "discovery_candidates": discovery,
                "unknowns": current_unknowns(),
                "limits": {
                    "relationship_limit": relationship_limit,
                    "activity_limit": activity_limit,
                    "task_limit": task_limit,
                    "discovery_limit": discovery_limit,
                    "max_context_bytes": max_context_bytes,
                },
                "invocation": {
                    "mode": "on-demand",
                    "auto_inject": False,
                    "autonomous_crawl": False,
                },
                "persistent_derived_state": False,
                "production_authority": False,
                "route_authority": False,
            }

        while True:
            core = core_document()
            result_document = {
                **core,
                "receipt_id": digest_object(core, domain="memory-entity-brief-v1"),
            }
            rendered_size = len(json.dumps(result_document, ensure_ascii=False).encode("utf-8"))
            if rendered_size <= max_context_bytes:
                return result_document
            byte_truncated = True
            if discovery["candidates"]:
                discovery["candidates"].pop()
                discovery["omitted_count"] += 1
            elif relationship_links:
                relationship_links.pop()
                relationships["omitted_count"] += 1
                relationships["truncated_by"] = "context-bytes"
            elif whereabouts["links"]:
                whereabouts["links"].pop()
                whereabouts["omitted_count"] += 1
            elif activity["events"]:
                activity["events"].pop()
                activity["omitted_count"] += 1
            elif tasks["cards"]:
                tasks["cards"].pop()
                tasks["omitted_count"] += 1
            elif candidates:
                candidates.pop()
                candidate_omitted += 1
            elif len(definition["values"]) > 1:
                definition["values"].pop()
                definition["omitted_count"] += 1
            else:
                raise MemoryLinkGraphError("entity brief metadata exceeds the context budget")

    def audit(
        self,
        *,
        kinds: Sequence[str] = (),
        limit: int = DEFAULT_AUDIT_LIMIT,
        max_context_bytes: int = 64 * 1024,
        cursor: str = "",
    ) -> dict[str, Any]:
        """Report bounded curation debt without admitting or rewriting memory."""

        limit = _bounded_integer(
            limit,
            field="limit",
            minimum=1,
            maximum=MAX_AUDIT_LIMIT,
        )
        max_context_bytes = _context_budget(max_context_bytes)
        kind_filter = tuple(sorted(set(kinds)))
        if any(kind not in MEMORY_LINK_NODE_KINDS for kind in kind_filter):
            raise MemoryLinkGraphError("memory-link audit contains an unsupported node kind")
        cursor_binding = {
            "protocol": MEMORY_LINK_AUDIT_PROTOCOL,
            "graph_digest": self.graph_digest,
            "kinds": list(kind_filter),
            "ranking_policy": MEMORY_LINK_RANKING_POLICY,
        }
        offset = _cursor_decode(cursor, cursor_binding) if cursor else 0
        issue_counts = {issue: 0 for issue in _AUDIT_ISSUES}
        audited_count = 0
        freshness_eligible_count = 0
        finding_candidates: list[
            tuple[
                tuple[int, int, int, int, int, int, str],
                str,
                tuple[str, ...],
                str,
                int,
                int,
                str,
                str,
                tuple[str, ...],
                int,
            ]
        ] = []

        for uri in sorted(self._node_documents):
            node = self._node_documents[uri]
            if kind_filter and node["kind"] not in kind_filter:
                continue
            audited_count += 1
            definition = self._definition_summary(uri)
            adjacency = self._adjacency(uri, direction="both", relation_filter=())
            whereabouts_count = sum(
                1 for link, _, _ in adjacency if link["relation"] == "located-at"
            )
            freshness_policy_status = "NOT_APPLICABLE"
            if node["kind"] in _FRESHNESS_AUDIT_KINDS:
                freshness_eligible_count += 1
                freshness_adjacency = [
                    (link, direction, neighbor_uri)
                    for link, direction, neighbor_uri in adjacency
                    if self._node_documents[neighbor_uri]["kind"]
                    in _FRESHNESS_AUDIT_KINDS
                ]
                claim_counts = {state: 0 for state in _CLAIM_STATES}
                for link, _, _ in freshness_adjacency:
                    claim_counts[self._link_freshness(link)["state"]] += 1
                known_claims = sum(
                    claim_counts[state] for state in _CLAIM_STATES if state != "UNKNOWN"
                )
                freshness_policy_status = (
                    "ABSENT"
                    if not freshness_adjacency or known_claims == 0
                    else "PARTIAL"
                    if claim_counts["UNKNOWN"]
                    else "EXPLICIT"
                )
            ambiguous_aliases = sorted(
                alias
                for alias in {normalize_memory_alias(value) for value in node["aliases"]}
                if len(self._alias_index.get(alias, ())) > 1
            )
            task_card_status = (
                "PRESENT"
                if node["kind"] == "task" and node["key"] in self._task_documents
                else "MISSING"
                if node["kind"] == "task"
                else "NOT_APPLICABLE"
            )
            issues: list[str] = []
            if ambiguous_aliases:
                issues.append("alias-ambiguous")
            if task_card_status == "MISSING":
                issues.append("canonical-task-card-missing")
            if node["kind"] in _DEFINITION_AUDIT_KINDS:
                if definition["status"] == "UNKNOWN":
                    issues.append("definition-unknown")
                elif definition["status"] == "CONTRADICTED":
                    issues.append("definition-contradicted")
            if freshness_policy_status == "ABSENT":
                issues.append("freshness-policy-absent")
            elif freshness_policy_status == "PARTIAL":
                issues.append("freshness-policy-partial")
            if uri in self._ignored_legacy_self_link_nodes:
                issues.append("legacy-self-link-ignored")
            if node["kind"] in _WHEREABOUTS_AUDIT_KINDS and whereabouts_count == 0:
                issues.append("whereabouts-unknown")
            if not issues:
                continue
            issues.sort()
            for issue in issues:
                issue_counts[issue] += 1
            rendered_aliases = ambiguous_aliases[:MAX_AUDIT_AMBIGUOUS_ALIASES]
            finding_candidates.append(
                (
                    self._audit_rank_key(
                        uri,
                        issues=issues,
                        direct_link_count=len(adjacency),
                    ),
                    uri,
                    tuple(issues),
                    definition["status"],
                    whereabouts_count,
                    len(adjacency),
                    freshness_policy_status,
                    task_card_status,
                    tuple(rendered_aliases),
                    len(ambiguous_aliases) - len(rendered_aliases),
                )
            )

        finding_candidates.sort(key=lambda item: item[0])
        finding_count = len(finding_candidates)

        if offset > finding_count:
            raise MemoryLinkGraphError("memory-link audit cursor is past the finding set")
        page = [
            {
                "identity": self._node_summary(uri),
                "issues": list(issues),
                "definition_status": definition_status,
                "whereabouts_count": whereabouts_count,
                "direct_link_count": direct_link_count,
                "freshness_policy_status": freshness_policy_status,
                "canonical_task_card_status": task_card_status,
                "ambiguous_aliases": list(ambiguous_aliases),
                "omitted_ambiguous_alias_count": omitted_ambiguous_alias_count,
                "admission_status": "UNADMITTED",
                "canonical_write_required": True,
                "auto_apply": False,
            }
            for (
                _,
                uri,
                issues,
                definition_status,
                whereabouts_count,
                direct_link_count,
                freshness_policy_status,
                task_card_status,
                ambiguous_aliases,
                omitted_ambiguous_alias_count,
            ) in finding_candidates[offset : offset + limit]
        ]
        byte_truncated = False

        def build_result() -> dict[str, Any]:
            next_offset = offset + len(page)
            has_more = next_offset < finding_count
            core = {
                "protocol": MEMORY_LINK_AUDIT_PROTOCOL,
                "graph_digest": self.graph_digest,
                "source_namespace": self.source_namespace,
                "scope": {"kinds": list(kind_filter), "all_kinds": not kind_filter},
                "coverage": {
                    "audited_count": audited_count,
                    "freshness_eligible_count": freshness_eligible_count,
                    "freshness_not_applicable_count": audited_count
                    - freshness_eligible_count,
                    "finding_count": finding_count,
                    "clean_count": audited_count - finding_count,
                    "issue_counts": issue_counts,
                },
                "findings": page,
                "returned_count": len(page),
                "omitted_count": finding_count - next_offset,
                "pagination": {
                    "offset": offset,
                    "next_cursor": _cursor_encode({**cursor_binding, "offset": next_offset})
                    if has_more
                    else "",
                    "has_more": has_more,
                },
                "truncated_by": "context-bytes"
                if byte_truncated
                else "limit"
                if has_more
                else "none",
                "limits": {"limit": limit, "max_context_bytes": max_context_bytes},
                "canonical_write_required": finding_count > 0,
                "auto_apply": False,
                "persistent_derived_state": False,
                "production_authority": False,
                "route_authority": False,
            }
            return {**core, "receipt_id": digest_object(core, domain="memory-link-audit-v1")}

        while True:
            result = build_result()
            if len(json.dumps(result, ensure_ascii=False).encode("utf-8")) <= max_context_bytes:
                return result
            byte_truncated = True
            if page:
                page.pop()
                continue
            raise MemoryLinkGraphError("memory-link audit metadata exceeds the context budget")

    def context_pack(
        self,
        anchor: str,
        *,
        direction: str = "both",
        relations: Sequence[str] = (),
        max_depth: int = DEFAULT_CONTEXT_DEPTH,
        max_nodes: int = DEFAULT_CONTEXT_NODE_LIMIT,
        max_links: int = DEFAULT_CONTEXT_LINK_LIMIT,
        max_context_bytes: int = 64 * 1024,
    ) -> dict[str, Any]:
        """Build one deterministic, multi-hop and byte-bounded agent context pack."""

        max_depth = _bounded_integer(
            max_depth,
            field="max_depth",
            minimum=1,
            maximum=MAX_CONTEXT_DEPTH,
        )
        max_nodes = _bounded_integer(
            max_nodes,
            field="max_nodes",
            minimum=1,
            maximum=MAX_CONTEXT_NODE_LIMIT,
        )
        max_links = _bounded_integer(
            max_links,
            field="max_links",
            minimum=1,
            maximum=MAX_CONTEXT_LINK_LIMIT,
        )
        max_context_bytes = _context_budget(max_context_bytes)
        if direction not in {"outbound", "inbound", "both"}:
            raise MemoryLinkGraphError("direction must be outbound, inbound or both")
        relation_filter = tuple(sorted(set(relations)))
        unknown_relations = set(relation_filter) - MEMORY_LINK_RELATIONS
        if unknown_relations:
            raise MemoryLinkGraphError(
                "unsupported memory-link relation filter: " + ", ".join(sorted(unknown_relations))
            )

        _, candidates = self._resolve_uris(anchor)
        resolution_result = (
            "EXACT" if len(candidates) == 1 else "AMBIGUOUS" if candidates else "NOT_FOUND"
        )
        if len(candidates) != 1:
            rendered_candidates: list[dict[str, Any]] = []
            reasons: set[str] = set()
            if len(candidates) > 20:
                reasons.add("candidate-limit")
            for uri in candidates[:20]:
                candidate = self._node_summary(uri)
                tentative = {
                    "protocol": MEMORY_LINK_CONTEXT_PROTOCOL,
                    "graph_digest": self.graph_digest,
                    "source_namespace": self.source_namespace,
                    "result": resolution_result,
                    "candidate_count": len(candidates),
                    "candidates": [*rendered_candidates, candidate],
                    "max_context_bytes": max_context_bytes,
                }
                if len(canonical_bytes(tentative)) + 2048 > max_context_bytes:
                    reasons.add("context-bytes")
                    break
                rendered_candidates.append(candidate)
            core = {
                "protocol": MEMORY_LINK_CONTEXT_PROTOCOL,
                "graph_digest": self.graph_digest,
                "source_namespace": self.source_namespace,
                "result": resolution_result,
                "anchor": None,
                "candidate_count": len(candidates),
                "candidates": rendered_candidates,
                "direction": direction,
                "relations": list(relation_filter),
                "max_depth": max_depth,
                "node_limit": max_nodes,
                "link_limit": max_links,
                "nodes": [],
                "links": [],
                "counts": {
                    "returned_nodes": 0,
                    "omitted_nodes": 0,
                    "returned_links": 0,
                    "omitted_links": 0,
                    "expanded_nodes": 0,
                    "frontier_nodes": 0,
                    "max_reached_depth": 0,
                },
                "truncation": {
                    "truncated": bool(reasons),
                    "reasons": sorted(reasons),
                },
                "max_context_bytes": max_context_bytes,
                "persistent_derived_state": False,
                "production_authority": False,
                "route_authority": False,
            }
            result_document = {
                **core,
                "receipt_id": digest_object(core, domain="memory-link-context-v1"),
            }
            if len(canonical_bytes(result_document)) > max_context_bytes:
                raise MemoryLinkGraphError(
                    "context-pack metadata exceeds the requested byte budget"
                )
            return result_document

        anchor_uri = candidates[0]
        nodes: list[dict[str, Any]] = [
            {
                "node": self._node_summary(anchor_uri),
                "depth": 0,
                "predecessor_uri": None,
                "via_relation": None,
                "via_direction": None,
            }
        ]
        links: list[dict[str, Any]] = []
        queue: deque[tuple[str, int]] = deque([(anchor_uri, 0)])
        visited = {anchor_uri}
        depth_by_uri = {anchor_uri: 0}
        emitted_links: set[tuple[str, str, str, str]] = set()
        omitted_nodes: set[str] = set()
        omitted_link_keys: set[tuple[str, str, str, str]] = set()
        expanded_nodes = 0
        max_reached_depth = 0
        reasons: set[str] = set()
        stopped = False

        while queue and not stopped:
            current_uri, current_depth = queue.popleft()
            expanded_nodes += 1
            max_reached_depth = max(max_reached_depth, current_depth)
            adjacency = self._adjacency(
                current_uri,
                direction=direction,
                relation_filter=relation_filter,
            )
            for index, (link, link_direction, neighbour_uri) in enumerate(adjacency):
                link_key = (
                    link["source_uri"],
                    link["relation"],
                    link["target_uri"],
                    link["provenance"],
                )
                if link_key in emitted_links:
                    continue
                is_new = neighbour_uri not in visited
                if is_new and current_depth >= max_depth:
                    omitted_nodes.add(neighbour_uri)
                    omitted_link_keys.add(link_key)
                    reasons.add("depth-limit")
                    continue
                if is_new and len(nodes) >= max_nodes:
                    omitted_nodes.add(neighbour_uri)
                    omitted_link_keys.add(link_key)
                    reasons.add("node-limit")
                    continue
                if len(links) >= max_links:
                    reasons.add("link-limit")
                    omitted_link_keys.update(
                        (
                            candidate_link["source_uri"],
                            candidate_link["relation"],
                            candidate_link["target_uri"],
                            candidate_link["provenance"],
                        )
                        for candidate_link, _, _ in adjacency[index:]
                    )
                    omitted_nodes.update(
                        candidate_uri
                        for _, _, candidate_uri in adjacency[index:]
                        if candidate_uri not in visited
                    )
                    stopped = True
                    break

                neighbour_depth = current_depth + 1 if is_new else depth_by_uri[neighbour_uri]
                candidate_link = {
                    **self._link_summary(link),
                    "direction": link_direction,
                    "from_uri": current_uri,
                    "to_uri": neighbour_uri,
                    "from_depth": current_depth,
                    "to_depth": neighbour_depth,
                    "cycle": not is_new,
                    "follow_allowed": is_new,
                }
                candidate_node = (
                    {
                        "node": self._node_summary(neighbour_uri),
                        "depth": neighbour_depth,
                        "predecessor_uri": current_uri,
                        "via_relation": link["relation"],
                        "via_direction": link_direction,
                    }
                    if is_new
                    else None
                )
                tentative = {
                    "protocol": MEMORY_LINK_CONTEXT_PROTOCOL,
                    "graph_digest": self.graph_digest,
                    "anchor": self._node_summary(anchor_uri),
                    "nodes": [*nodes, *([candidate_node] if candidate_node else [])],
                    "links": [*links, candidate_link],
                    "max_context_bytes": max_context_bytes,
                }
                if len(canonical_bytes(tentative)) + 2048 > max_context_bytes:
                    reasons.add("context-bytes")
                    omitted_link_keys.update(
                        (
                            remaining_link["source_uri"],
                            remaining_link["relation"],
                            remaining_link["target_uri"],
                            remaining_link["provenance"],
                        )
                        for remaining_link, _, _ in adjacency[index:]
                    )
                    omitted_nodes.update(
                        candidate_uri
                        for _, _, candidate_uri in adjacency[index:]
                        if candidate_uri not in visited
                    )
                    stopped = True
                    break

                emitted_links.add(link_key)
                omitted_link_keys.discard(link_key)
                links.append(candidate_link)
                if is_new and candidate_node is not None:
                    visited.add(neighbour_uri)
                    omitted_nodes.discard(neighbour_uri)
                    depth_by_uri[neighbour_uri] = neighbour_depth
                    nodes.append(candidate_node)
                    queue.append((neighbour_uri, neighbour_depth))
                    max_reached_depth = max(max_reached_depth, neighbour_depth)

        frontier_nodes = len({uri for uri, _ in queue} | omitted_nodes)
        core = {
            "protocol": MEMORY_LINK_CONTEXT_PROTOCOL,
            "graph_digest": self.graph_digest,
            "source_namespace": self.source_namespace,
            "result": "PACKED" if links or omitted_link_keys else "ISOLATED",
            "anchor": self._node_summary(anchor_uri),
            "candidate_count": 1,
            "candidates": [],
            "direction": direction,
            "relations": list(relation_filter),
            "max_depth": max_depth,
            "node_limit": max_nodes,
            "link_limit": max_links,
            "nodes": nodes,
            "links": links,
            "counts": {
                "returned_nodes": len(nodes),
                "omitted_nodes": len(omitted_nodes),
                "returned_links": len(links),
                "omitted_links": len(omitted_link_keys),
                "expanded_nodes": expanded_nodes,
                "frontier_nodes": frontier_nodes,
                "max_reached_depth": max_reached_depth,
            },
            "truncation": {
                "truncated": bool(reasons),
                "reasons": sorted(reasons),
            },
            "max_context_bytes": max_context_bytes,
            "persistent_derived_state": False,
            "production_authority": False,
            "route_authority": False,
        }
        result_document = {
            **core,
            "receipt_id": digest_object(core, domain="memory-link-context-v1"),
        }
        if len(canonical_bytes(result_document)) > max_context_bytes:
            raise MemoryLinkGraphError("context pack exceeds the requested byte budget")
        return result_document

    def ttt_autofill(
        self,
        goal: str,
        last_hop: str,
        *,
        snapshot_id: str | None = None,
        expected_graph_digest: str | None = None,
        catalog: Any | None = None,
    ) -> dict[str, Any]:
        """Return navigational TTT hints through the current graph-bound engine.

        Retain the original Python entrypoint without loading target catalogues
        implicitly or changing the engine's graph, digest or authority checks.
        """
        from .memory_ttt_paths import memory_ttt_autofill

        return memory_ttt_autofill(
            goal,
            last_hop,
            graph=self,
            snapshot_id=snapshot_id,
            expected_graph_digest=expected_graph_digest,
            catalog=catalog,
        )
