"""Explainable, authority-free relationships over canonical Seed events.

The relationship index is a rebuildable projection.  It never rewrites Seed,
does not execute a remembered route and does not turn evidence references into
authority.  Strong links require explicit event/gate references, one exact
evidence artifact, or one exact operational fact.  Broad task, actor, session
and tag overlap is reported as filtered context rather than causal truth.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import stat
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .hashing import digest_object
from .seed_catalog import HOME_NAMESPACE, SeedCatalogError, iter_catalog_events

RELATIONSHIP_PROTOCOL = "integrity-guardian/seed-event-connections/v1"
DEFAULT_MAX_EVIDENCE_FILE_BYTES = 512 * 1024
DEFAULT_MAX_EVIDENCE_TOTAL_BYTES = 32 * 1024 * 1024
DEFAULT_MAX_EVIDENCE_ARTIFACTS = 512
DEFAULT_MAX_CANDIDATE_EVENTS = 256
DEFAULT_RARE_SUBSYSTEM_LIMIT = 12
MAX_FACTS_PER_DOCUMENT = 4096
_ALLOWED_EVIDENCE_SUFFIXES = {
    ".json",
    ".jsonl",
    ".md",
    ".sha256",
    ".txt",
    ".tsv",
    ".csv",
    ".yaml",
    ".yml",
}
_EVENT_REFERENCE_FIELDS = {
    "related_event_id": "explicitly-related",
    "related_event_ids": "explicitly-related",
    "verifies_event_id": "verifies",
    "verifies_event_ids": "verifies",
    "verified_event_id": "verifies",
    "verified_event_ids": "verifies",
    "supersedes_event_id": "supersedes",
    "supersedes_event_ids": "supersedes",
    "source_event_id": "derived-from",
    "source_event_ids": "derived-from",
    "evidence_event_id": "cites-event-evidence",
    "evidence_event_ids": "cites-event-evidence",
    "external_evidence_id": "cites-event-evidence",
    "external_evidence_ids": "cites-event-evidence",
    "transfer_acceptance_event_id": "accepted-by-event",
}
_TASK_RELATION_FIELDS = {
    "parent_task_id": "child-task-of",
    "depends_on_task_ids": "depends-on-task",
    "related_task_ids": "related-task",
    "supersedes_task_ids": "supersedes-task",
    "blocks_task_ids": "blocks-task",
    "preempts_task_ids": "preempts-task",
}
_TASK_ID_FIELDS = {
    "task_id",
    "related_task_id",
    "parent_task_id",
    "depends_on_task_ids",
    "related_task_ids",
    "supersedes_task_ids",
    "blocks_task_ids",
    "preempts_task_ids",
    "transferred_to",
}
_GATE_ID_PATTERN = re.compile(r"\b(?:INV|GATE)-[A-Z0-9][A-Z0-9._-]{2,}\b")
_LABELLED_EVENT_PATTERN = re.compile(
    r"(?i)(?:Action\s*Log\s*:?|ActionLog\s*:|event\s+)#?\s*(\d{1,9})\b"
)
_NAKED_EVENT_PATTERN = re.compile(r"(?<![A-Za-z0-9])#(\d{3,9})\b")
_CIDR_PATTERN = re.compile(
    r"(?<![0-9A-Fa-f:.])(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}(?![0-9])"
)
_IPV4_PATTERN = re.compile(r"(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9.])")


def _as_string(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _as_string_list(value: Any) -> list[str]:
    if value is None:
        return []
    values = value if isinstance(value, list) else [value]
    result: list[str] = []
    for item in values:
        text = _as_string(item).strip()
        if text and text not in result:
            result.append(text)
    return result


def _normalize_digest(value: Any) -> str:
    text = _as_string(value).strip().lower()
    if text.startswith("sha256:"):
        text = text.split(":", 1)[1]
    if re.fullmatch(r"[0-9a-f]{64}", text):
        return "sha256:" + text
    return ""


def _event_reference(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value > 0:
        return value
    text = _as_string(value).strip()
    if text.isdigit():
        number = int(text)
        return number if number > 0 else None
    match = re.fullmatch(r"(?i)(?:Action\s*Log\s*:?|ActionLog\s*:)?#?(\d{1,9})", text)
    if match:
        return int(match.group(1))
    return None


def _parse_utc(value: Any) -> datetime | None:
    text = _as_string(value).strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _optional_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    text = _as_string(value).strip().casefold()
    if text in {"true", "yes", "1"}:
        return True
    if text in {"false", "no", "0"}:
        return False
    return None


def _noncausal_ip_address(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return True
    return bool(
        address.is_loopback
        or address.is_link_local
        or address.is_unspecified
        or address.is_multicast
    )


@dataclass(frozen=True)
class OperationalFact:
    """One sanitized fact with exact provenance and no raw evidence payload."""

    kind: str
    value: str
    source_kind: str
    source_path: str = ""
    artifact_digest: str = ""
    binding_status: str = "canonical-event"

    def document(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "value": self.value,
            "source_kind": self.source_kind,
            "source_path": self.source_path,
            "artifact_digest": self.artifact_digest,
            "binding_status": self.binding_status,
        }


@dataclass(frozen=True)
class EvidenceObservation:
    """Bounded read decision for one evidence reference."""

    path: str
    status: str
    binding_status: str
    digest: str = ""
    expected_digest: str = ""
    size_bytes: int | None = None
    facts: tuple[OperationalFact, ...] = ()
    gates: tuple[dict[str, Any], ...] = ()
    recorded_exists: bool | None = None

    def document(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "status": self.status,
            "binding_status": self.binding_status,
            "digest": self.digest,
            "expected_digest": self.expected_digest,
            "size_bytes": self.size_bytes,
            "fact_count": len(self.facts),
            "gate_count": len(self.gates),
            "recorded_exists": self.recorded_exists,
        }


class _EvidenceResolver:
    def __init__(
        self,
        root: Path | None,
        *,
        source_prefix: Path | None = None,
        max_file_bytes: int = DEFAULT_MAX_EVIDENCE_FILE_BYTES,
        max_total_bytes: int = DEFAULT_MAX_EVIDENCE_TOTAL_BYTES,
        max_artifacts: int = DEFAULT_MAX_EVIDENCE_ARTIFACTS,
    ) -> None:
        self.root: Path | None = None
        self.source_prefix: Path | None = None
        self.max_file_bytes = max_file_bytes
        self.max_total_bytes = max_total_bytes
        self.max_artifacts = max_artifacts
        self.total_bytes = 0
        self.observed_artifacts = 0
        self._content_cache: dict[
            str,
            tuple[
                str,
                int,
                tuple[OperationalFact, ...],
                tuple[dict[str, Any], ...],
                str,
            ],
        ] = {}
        if root is not None:
            requested_root = root.absolute()
            if not requested_root.is_dir() or requested_root.is_symlink():
                raise SeedCatalogError("evidence root must be a non-symlink directory")
            self.root = requested_root.resolve(strict=True)
        if source_prefix is not None:
            requested_prefix = source_prefix.absolute()
            if not requested_prefix.is_absolute() or ".." in requested_prefix.parts:
                raise SeedCatalogError("evidence source prefix must be an absolute clean path")
            self.source_prefix = requested_prefix

    def resolve(
        self,
        *,
        raw_path: str,
        expected_digest: str,
        recorded_exists: bool | None,
    ) -> EvidenceObservation:
        if self.root is None:
            return EvidenceObservation(
                path=raw_path,
                status="evidence-root-not-configured",
                binding_status="missing",
                expected_digest=expected_digest,
                recorded_exists=recorded_exists,
            )
        path = Path(raw_path)
        if ".." in path.parts:
            return EvidenceObservation(
                path=raw_path,
                status="rejected-traversal",
                binding_status="missing",
                expected_digest=expected_digest,
                recorded_exists=recorded_exists,
            )
        if path.is_absolute() and self.source_prefix is not None:
            try:
                relative = path.absolute().relative_to(self.source_prefix)
            except ValueError:
                return EvidenceObservation(
                    path=raw_path,
                    status="rejected-outside-source-prefix",
                    binding_status="missing",
                    expected_digest=expected_digest,
                    recorded_exists=recorded_exists,
                )
            candidate = (self.root / relative).absolute()
        else:
            candidate = path.absolute() if path.is_absolute() else (self.root / path).absolute()
            try:
                relative = candidate.relative_to(self.root)
            except ValueError:
                return EvidenceObservation(
                    path=raw_path,
                    status="rejected-outside-root",
                    binding_status="missing",
                    expected_digest=expected_digest,
                    recorded_exists=recorded_exists,
                )
        current = self.root
        for component in relative.parts:
            if component in {"", ".", ".."}:
                return EvidenceObservation(
                    path=raw_path,
                    status="rejected-ambiguous-path",
                    binding_status="missing",
                    expected_digest=expected_digest,
                    recorded_exists=recorded_exists,
                )
            current = current / component
            if current.is_symlink():
                return EvidenceObservation(
                    path=raw_path,
                    status="rejected-symlink",
                    binding_status="missing",
                    expected_digest=expected_digest,
                    recorded_exists=recorded_exists,
                )
        suffix = candidate.suffix.casefold()
        if suffix not in _ALLOWED_EVIDENCE_SUFFIXES:
            return EvidenceObservation(
                path=raw_path,
                status="unsupported-format",
                binding_status="missing",
                expected_digest=expected_digest,
                recorded_exists=recorded_exists,
            )
        cache_key = str(candidate)
        cached = self._content_cache.get(cache_key)
        if cached is None:
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                descriptor = os.open(candidate, flags)
            except FileNotFoundError:
                return EvidenceObservation(
                    path=raw_path,
                    status="missing",
                    binding_status="missing",
                    expected_digest=expected_digest,
                    recorded_exists=recorded_exists,
                )
            except OSError:
                return EvidenceObservation(
                    path=raw_path,
                    status="rejected-unsafe-open",
                    binding_status="missing",
                    expected_digest=expected_digest,
                    recorded_exists=recorded_exists,
                )
            with os.fdopen(descriptor, "rb") as handle:
                file_status = os.fstat(handle.fileno())
                size = file_status.st_size
                if not stat.S_ISREG(file_status.st_mode):
                    return EvidenceObservation(
                        path=raw_path,
                        status="rejected-non-regular",
                        binding_status="missing",
                        expected_digest=expected_digest,
                        size_bytes=size,
                        recorded_exists=recorded_exists,
                    )
                if size > self.max_file_bytes:
                    return EvidenceObservation(
                        path=raw_path,
                        status="rejected-oversized",
                        binding_status="missing",
                        expected_digest=expected_digest,
                        size_bytes=size,
                        recorded_exists=recorded_exists,
                    )
                if self.observed_artifacts >= self.max_artifacts:
                    return EvidenceObservation(
                        path=raw_path,
                        status="skipped-artifact-budget",
                        binding_status="missing",
                        expected_digest=expected_digest,
                        size_bytes=size,
                        recorded_exists=recorded_exists,
                    )
                if self.total_bytes + size > self.max_total_bytes:
                    return EvidenceObservation(
                        path=raw_path,
                        status="skipped-byte-budget",
                        binding_status="missing",
                        expected_digest=expected_digest,
                        size_bytes=size,
                        recorded_exists=recorded_exists,
                    )
                payload = handle.read(self.max_file_bytes + 1)
            if len(payload) != size:
                return EvidenceObservation(
                    path=raw_path,
                    status="rejected-size-race",
                    binding_status="missing",
                    expected_digest=expected_digest,
                    size_bytes=len(payload),
                    recorded_exists=recorded_exists,
                )
            digest = "sha256:" + hashlib.sha256(payload).hexdigest()
            status = "resolved"
            facts: tuple[OperationalFact, ...] = ()
            gates: tuple[dict[str, Any], ...] = ()
            try:
                text = payload.decode("utf-8", errors="strict")
                value: Any = text
                if suffix in {".json", ".jsonl"}:
                    if suffix == ".jsonl":
                        value = [json.loads(line) for line in text.splitlines() if line.strip()]
                    else:
                        value = json.loads(text)
                facts = tuple(
                    _extract_operational_facts(
                        value,
                        source_kind="evidence",
                        source_path=raw_path,
                        artifact_digest=digest,
                        binding_status="pending",
                    )
                )
                gates = tuple(_extract_gate_records(value))
            except (UnicodeDecodeError, json.JSONDecodeError, SeedCatalogError):
                status = "malformed"
            self.total_bytes += size
            self.observed_artifacts += 1
            cached = (digest, size, facts, gates, status)
            self._content_cache[cache_key] = cached
        digest, size, cached_facts, gates, status = cached
        if expected_digest:
            binding = "digest-bound" if digest == expected_digest else "mismatch"
        else:
            binding = "current-unbound"
        facts = tuple(
            OperationalFact(
                kind=fact.kind,
                value=fact.value,
                source_kind=fact.source_kind,
                source_path=raw_path,
                artifact_digest=fact.artifact_digest,
                binding_status=binding,
            )
            for fact in cached_facts
        )
        return EvidenceObservation(
            path=raw_path,
            status=status,
            binding_status=binding,
            digest=digest,
            expected_digest=expected_digest,
            size_bytes=size,
            facts=facts,
            gates=gates,
            recorded_exists=recorded_exists,
        )


def _emit_fact(
    facts: dict[tuple[str, str, str, str], OperationalFact],
    *,
    kind: str,
    value: str,
    source_kind: str,
    source_path: str,
    artifact_digest: str,
    binding_status: str,
) -> None:
    clean = value.strip()
    if not clean or len(facts) >= MAX_FACTS_PER_DOCUMENT:
        return
    key = (kind, clean, source_kind, source_path)
    facts[key] = OperationalFact(
        kind=kind,
        value=clean,
        source_kind=source_kind,
        source_path=source_path,
        artifact_digest=artifact_digest,
        binding_status=binding_status,
    )


def _extract_operational_facts(
    value: Any,
    *,
    source_kind: str,
    source_path: str = "",
    artifact_digest: str = "",
    binding_status: str = "canonical-event",
) -> list[OperationalFact]:
    facts: dict[tuple[str, str, str, str], OperationalFact] = {}

    def emit(kind: str, fact_value: str) -> None:
        _emit_fact(
            facts,
            kind=kind,
            value=fact_value,
            source_kind=source_kind,
            source_path=source_path,
            artifact_digest=artifact_digest,
            binding_status=binding_status,
        )

    def text_facts(text: str, *, allow_naked_event: bool) -> None:
        for match in _LABELLED_EVENT_PATTERN.finditer(text):
            emit("event-ref", match.group(1))
        if allow_naked_event:
            for match in _NAKED_EVENT_PATTERN.finditer(text):
                emit("event-ref", match.group(1))
        for match in _GATE_ID_PATTERN.finditer(text):
            emit("gate-id", match.group(0))
        for match in _CIDR_PATTERN.finditer(text):
            try:
                network = ipaddress.ip_network(match.group(0), strict=False)
            except ValueError:
                continue
            emit("cidr", str(network))
        for match in _IPV4_PATTERN.finditer(text):
            try:
                address = ipaddress.ip_address(match.group(0))
            except ValueError:
                continue
            emit("ip-address", str(address))

    def walk(item: Any, key: str = "", depth: int = 0) -> None:
        if depth > 16 or len(facts) >= MAX_FACTS_PER_DOCUMENT:
            return
        normalized_key = key.casefold()
        if isinstance(item, Mapping):
            for child_key, child in item.items():
                walk(child, str(child_key), depth + 1)
            return
        if isinstance(item, list):
            for child in item:
                walk(child, key, depth + 1)
            return
        text = _as_string(item).strip()
        if not text:
            return
        if normalized_key in _EVENT_REFERENCE_FIELDS or normalized_key.endswith(
            ("_event_id", "_event_ids")
        ):
            reference = _event_reference(item)
            if reference is not None:
                emit("event-ref", str(reference))
        if (
            normalized_key in _TASK_ID_FIELDS
            or normalized_key.endswith(("_task_id", "_task_ids"))
        ) and len(text) <= 256:
            emit("task-id", text)
        if normalized_key == "gate_id" and len(text) <= 256:
            emit("gate-id", text)
        if normalized_key == "lock_id" and len(text) <= 256:
            emit("lock-id", text)
        text_facts(
            text,
            allow_naked_event=normalized_key in _EVENT_REFERENCE_FIELDS
            or normalized_key.endswith(("_event_id", "_event_ids")),
        )

    walk(value)
    if isinstance(value, str):
        text_facts(value, allow_naked_event=False)
    return sorted(facts.values(), key=lambda fact: (fact.kind, fact.value, fact.source_path))


def _extract_gate_records(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, Mapping):
        return []
    raw_gates = value.get("gates")
    if not isinstance(raw_gates, list):
        return []
    gates: list[dict[str, Any]] = []
    for raw in raw_gates:
        if not isinstance(raw, Mapping):
            continue
        gate_id = _as_string(raw.get("gate_id")).strip()
        if not gate_id or len(gate_id) > 256:
            continue
        event_ids: list[int] = []
        for item in _as_string_list(raw.get("external_evidence_ids")):
            reference = _event_reference(item)
            if reference is not None and reference not in event_ids:
                event_ids.append(reference)
        gates.append(
            {
                "gate_id": gate_id,
                "gate_status": _as_string(raw.get("gate_status")).strip().casefold(),
                "observation_status": _as_string(raw.get("observation_status"))
                .strip()
                .casefold(),
                "current_claim": _optional_bool(raw.get("current_claim")),
                "related_task_id": _as_string(raw.get("related_task_id")).strip(),
                "stale_after": _as_string(raw.get("stale_after")).strip(),
                "external_event_ids": sorted(event_ids),
                "production_authorization": (
                    _optional_bool(raw.get("production_authorization")) is True
                ),
            }
        )
    return sorted(gates, key=lambda gate: gate["gate_id"])


def _event_details(event: Mapping[str, Any]) -> Mapping[str, Any]:
    details = event.get("details")
    return details if isinstance(details, Mapping) else {}


def _event_evidence_references(event: Mapping[str, Any]) -> list[dict[str, Any]]:
    details = _event_details(event)
    expected: dict[str, dict[str, Any]] = {}
    raw_evidence = details.get("evidence")
    if isinstance(raw_evidence, list):
        for item in raw_evidence:
            if not isinstance(item, Mapping):
                continue
            path = _as_string(item.get("path")).strip()
            if not path:
                continue
            exists = item.get("exists")
            expected[path] = {
                "path": path,
                "expected_digest": _normalize_digest(item.get("sha256")),
                "recorded_exists": exists if isinstance(exists, bool) else None,
            }
    for field in ("evidence_files", "files", "evidence_paths"):
        for path in _as_string_list(details.get(field)):
            expected.setdefault(
                path,
                {"path": path, "expected_digest": "", "recorded_exists": None},
            )
    return [expected[path] for path in sorted(expected)]


def _explicit_event_relations(event: Mapping[str, Any]) -> list[tuple[int, str, str]]:
    details = _event_details(event)
    relations: list[tuple[int, str, str]] = []

    def walk(item: Any, key: str = "", depth: int = 0) -> None:
        if depth > 16:
            return
        if isinstance(item, Mapping):
            for child_key, child in item.items():
                walk(child, str(child_key).casefold(), depth + 1)
            return
        if isinstance(item, list):
            for child in item:
                walk(child, key, depth + 1)
            return
        relation = _EVENT_REFERENCE_FIELDS.get(key)
        if relation is None and key.endswith(("_event_id", "_event_ids")):
            relation = "references-event"
        if relation is None:
            return
        reference = _event_reference(item)
        if reference is not None:
            relations.append((reference, relation, key))

    walk(details)
    narrative = "\n".join(
        _as_string(value)
        for value in (
            event.get("summary"),
            details.get("verification"),
            details.get("next_action"),
            details.get("done_when"),
        )
        if value
    )
    for match in _LABELLED_EVENT_PATTERN.finditer(narrative):
        relations.append((int(match.group(1)), "references-event", "narrative"))
    return sorted(set(relations), key=lambda item: (item[0], item[1], item[2]))


def _task_status(event: Mapping[str, Any], current: str | None) -> str:
    action = _as_string(event.get("action")).casefold()
    result = _as_string(_event_details(event).get("result")).strip().casefold()
    if "blocked" in action or result == "blocked":
        return "blocked"
    if any(marker in action for marker in ("failed", "rejected")) or result in {
        "error",
        "fail",
        "failed",
        "rejected",
    }:
        return "failed"
    if any(marker in action for marker in ("pending", "paused", "wait")) or result in {
        "paused",
        "pending",
        "waiting",
    }:
        return "pending"
    if any(marker in action for marker in ("complete", "commit", "done", "resolved")) or result in {
        "complete",
        "completed",
        "done",
        "ok",
        "pass",
        "passed",
        "success",
        "succeeded",
        "verified",
    }:
        return "complete"
    if any(marker in action for marker in ("start", "progress", "resume", "checkpoint")) or result in {
        "active",
        "in-progress",
        "partial",
        "started",
        "running",
    }:
        return "active"
    return current or "unknown"


def _reverse_relation(relation: str) -> str:
    return {
        "verifies": "verified-by",
        "supersedes": "superseded-by",
        "derived-from": "source-for",
        "accepted-by-event": "accepts-event",
        "cites-event-evidence": "cited-as-evidence-by",
        "explicitly-related": "explicitly-related",
        "references-event": "referenced-by",
    }.get(relation, "reverse-" + relation)


class SeedRelationshipIndex:
    """Bounded explainable event relationship projection."""

    def __init__(
        self,
        events: Sequence[dict[str, Any]],
        *,
        evidence_root: Path | None = None,
        evidence_source_prefix: Path | None = None,
        max_candidate_events: int = DEFAULT_MAX_CANDIDATE_EVENTS,
        rare_subsystem_limit: int = DEFAULT_RARE_SUBSYSTEM_LIMIT,
    ) -> None:
        if not events:
            raise SeedCatalogError("relationship index requires at least one Seed event")
        self.events = sorted(events, key=lambda event: int(event["id"]))
        self.by_id = {int(event["id"]): event for event in self.events}
        if len(self.by_id) != len(self.events):
            raise SeedCatalogError("relationship index received duplicate event ids")
        if any(HOME_NAMESPACE in json.dumps(event, ensure_ascii=False) for event in self.events):
            raise SeedCatalogError("Integrity Home is prohibited in Seed relationships")
        self.max_candidate_events = max_candidate_events
        self.rare_subsystem_limit = rare_subsystem_limit
        self.evidence_root = evidence_root.absolute() if evidence_root is not None else None
        self.evidence_source_prefix = (
            evidence_source_prefix.absolute() if evidence_source_prefix is not None else None
        )
        if self.evidence_root is not None:
            _EvidenceResolver(
                self.evidence_root,
                source_prefix=self.evidence_source_prefix,
            )
        self.task_events: dict[str, list[int]] = defaultdict(list)
        self.task_status: dict[str, str] = {}
        self.subsystem_events: dict[str, list[int]] = defaultdict(list)
        self.actor_counts: Counter[str] = Counter()
        self.session_counts: Counter[str] = Counter()
        self.tag_counts: Counter[str] = Counter()
        self.event_facts: dict[int, tuple[OperationalFact, ...]] = {}
        self.fact_events: dict[tuple[str, str], set[int]] = defaultdict(set)
        self.evidence_path_events: dict[str, set[int]] = defaultdict(set)
        self.explicit_out: dict[int, list[tuple[int, str, str]]] = {}
        self.explicit_in: dict[int, list[tuple[int, str, str]]] = defaultdict(list)
        self.as_of = max(
            (_parse_utc(event.get("ts_utc")) for event in self.events),
            key=lambda value: value or datetime.min.replace(tzinfo=UTC),
        ) or datetime.min.replace(tzinfo=UTC)
        for event in self.events:
            event_id = int(event["id"])
            details = _event_details(event)
            task_id = _as_string(details.get("task_id")).strip()
            if task_id:
                self.task_events[task_id].append(event_id)
                self.task_status[task_id] = _task_status(
                    event,
                    self.task_status.get(task_id),
                )
            for subsystem in _as_string_list(details.get("subsystem")):
                self.subsystem_events[subsystem].append(event_id)
            actor = _as_string(event.get("actor")).strip()
            session = _as_string(event.get("session_id")).strip()
            if actor:
                self.actor_counts[actor] += 1
            if session:
                self.session_counts[session] += 1
            for tag in _as_string_list(event.get("tags")):
                self.tag_counts[tag] += 1
            facts = tuple(_extract_operational_facts(event, source_kind="event"))
            self.event_facts[event_id] = facts
            for fact in facts:
                self.fact_events[(fact.kind, fact.value)].add(event_id)
            for reference in _event_evidence_references(event):
                self.evidence_path_events[reference["path"]].add(event_id)
            outgoing = _explicit_event_relations(event)
            self.explicit_out[event_id] = outgoing
            for target_id, relation, field in outgoing:
                self.explicit_in[target_id].append((event_id, relation, field))
        for values in self.task_events.values():
            values.sort()
        for values in self.subsystem_events.values():
            values.sort()

    @classmethod
    def from_catalog(
        cls,
        catalog_path: Path,
        *,
        evidence_root: Path | None = None,
        evidence_source_prefix: Path | None = None,
    ) -> SeedRelationshipIndex:
        return cls(
            list(iter_catalog_events(catalog_path)),
            evidence_root=evidence_root,
            evidence_source_prefix=evidence_source_prefix,
        )

    def _candidate_ids(self, event_id: int) -> tuple[list[int], dict[str, int]]:
        event = self.by_id[event_id]
        details = _event_details(event)
        candidate_rank: dict[int, int] = {}

        def add(candidate_id: int, rank: int) -> None:
            if candidate_id == event_id or candidate_id not in self.by_id:
                return
            candidate_rank[candidate_id] = min(
                rank,
                candidate_rank.get(candidate_id, rank),
            )

        for target_id, _, _ in self.explicit_out.get(event_id, []):
            add(target_id, 0)
        for source_id, _, _ in self.explicit_in.get(event_id, []):
            add(source_id, 0)
        for reference in _event_evidence_references(event):
            for candidate_id in self.evidence_path_events.get(reference["path"], set()):
                add(candidate_id, 1)
        for fact in self.event_facts[event_id]:
            if fact.kind in {"cidr", "ip-address", "gate-id", "event-ref"}:
                if fact.kind == "ip-address" and _noncausal_ip_address(fact.value):
                    continue
                for candidate_id in self.fact_events.get((fact.kind, fact.value), set()):
                    add(candidate_id, 1)
        task_id = _as_string(details.get("task_id")).strip()
        task_members = self.task_events.get(task_id, []) if task_id else []
        if task_members:
            position = task_members.index(event_id)
            for candidate_id in task_members[max(0, position - 1) : position]:
                add(candidate_id, 3)
            for candidate_id in task_members[position + 1 : position + 2]:
                add(candidate_id, 3)
            add(task_members[0], 3)
            add(task_members[-1], 3)
            if len(task_members) <= self.max_candidate_events:
                for candidate_id in task_members:
                    add(candidate_id, 4)
        for field in _TASK_RELATION_FIELDS:
            for related_task in _as_string_list(details.get(field)):
                members = self.task_events.get(related_task, [])
                if members:
                    add(members[0], 2)
                    add(members[-1], 2)
        for subsystem in _as_string_list(details.get("subsystem")):
            members = self.subsystem_events.get(subsystem, [])
            if len(members) <= self.rare_subsystem_limit:
                for candidate_id in members:
                    add(candidate_id, 5)

        # One bounded projection hop discovers the current event that binds an
        # artifact first reached through a historical task member.  This does
        # not itself create a link; the normal evidence/fact rules still have
        # to prove one after the candidate is admitted.
        expansion_frontier = sorted(
            candidate_rank,
            key=lambda candidate: (
                candidate_rank[candidate],
                abs(candidate - event_id),
                candidate,
            ),
        )[: min(64, self.max_candidate_events)]
        for frontier_id in expansion_frontier:
            frontier_event = self.by_id[frontier_id]
            for reference in _event_evidence_references(frontier_event):
                for peer_id in self.evidence_path_events.get(reference["path"], set()):
                    add(peer_id, 2)
            for target_id, _, _ in self.explicit_out.get(frontier_id, []):
                add(target_id, 2)
            for source_id, _, _ in self.explicit_in.get(frontier_id, []):
                add(source_id, 2)

        ordered = sorted(
            candidate_rank,
            key=lambda candidate: (
                candidate_rank[candidate],
                abs(candidate - event_id),
                candidate,
            ),
        )
        dropped = max(0, len(ordered) - self.max_candidate_events)
        ordered = ordered[: self.max_candidate_events]
        noise = {
            "same_actor_events_suppressed": max(
                0, self.actor_counts[_as_string(event.get("actor")).strip()] - 1
            ),
            "same_session_events_suppressed": max(
                0, self.session_counts[_as_string(event.get("session_id")).strip()] - 1
            ),
            "broad_task_events_considered_only_for_facts": max(0, len(task_members) - 3),
            "candidate_budget_dropped": dropped,
            "noncausal_operational_fact_links_suppressed": 0,
            "high_frequency_operational_fact_links_demoted": 0,
            "common_tag_events_suppressed": sum(
                max(0, self.tag_counts[tag] - 1)
                for tag in _as_string_list(event.get("tags"))
            ),
        }
        return ordered, noise

    def _evidence_for_events(
        self,
        event_ids: Iterable[int],
        *,
        resolver: _EvidenceResolver,
    ) -> tuple[dict[int, list[EvidenceObservation]], list[dict[str, Any]]]:
        observations: dict[int, list[EvidenceObservation]] = defaultdict(list)
        state_findings: list[dict[str, Any]] = []
        ordered_event_ids = list(dict.fromkeys(event_ids))
        for event_id in ordered_event_ids:
            event = self.by_id[event_id]
            for reference in _event_evidence_references(event):
                observation = resolver.resolve(
                    raw_path=reference["path"],
                    expected_digest=reference["expected_digest"],
                    recorded_exists=reference["recorded_exists"],
                )
                observations[event_id].append(observation)
                if observation.recorded_exists is False and observation.status == "resolved":
                    state_findings.append(
                        {
                            "kind": "recorded-missing-current-present",
                            "severity": "notice",
                            "event_id": event_id,
                            "path": observation.path,
                            "summary": (
                                "Event recorded the evidence path as missing, while the "
                                "configured current evidence root resolves a regular file."
                            ),
                        }
                    )
                elif observation.recorded_exists is True and observation.status == "missing":
                    state_findings.append(
                        {
                            "kind": "recorded-present-current-missing",
                            "severity": "warning",
                            "event_id": event_id,
                            "path": observation.path,
                            "summary": (
                                "Event recorded the evidence path as present, while the "
                                "configured current evidence root no longer resolves it."
                            ),
                        }
                    )
                if observation.binding_status == "mismatch":
                    state_findings.append(
                        {
                            "kind": "evidence-digest-mismatch",
                            "severity": "warning",
                            "event_id": event_id,
                            "path": observation.path,
                            "summary": "Current evidence bytes do not match the event-bound digest.",
                        }
                    )
        return observations, state_findings

    def explain(
        self,
        event_id: int,
        *,
        limit: int = 20,
        include_contextual: bool = False,
    ) -> dict[str, Any]:
        if event_id not in self.by_id:
            raise SeedCatalogError(f"Seed has no event {event_id}")
        if not 1 <= limit <= 200:
            raise SeedCatalogError("connection limit is outside 1..200")
        candidate_ids, noise = self._candidate_ids(event_id)
        resolver = _EvidenceResolver(
            self.evidence_root,
            source_prefix=self.evidence_source_prefix,
        )
        observations, state_findings = self._evidence_for_events(
            [event_id, *candidate_ids],
            resolver=resolver,
        )
        facts_by_event: dict[int, list[OperationalFact]] = {
            candidate: list(self.event_facts[candidate])
            for candidate in [event_id, *candidate_ids]
        }
        gate_records: list[tuple[int, EvidenceObservation, dict[str, Any]]] = []
        for candidate, candidate_observations in observations.items():
            for observation in candidate_observations:
                facts_by_event[candidate].extend(observation.facts)
                for gate in observation.gates:
                    gate_records.append((candidate, observation, gate))
        observations_by_path = {
            candidate: {
                observation.path: observation
                for observation in candidate_observations
            }
            for candidate, candidate_observations in observations.items()
        }
        links: dict[int, dict[str, Any]] = {}

        def link(target_id: int, relation: str, strength: int, reason: dict[str, Any]) -> None:
            if target_id == event_id or target_id not in self.by_id:
                return
            current = links.setdefault(
                target_id,
                {
                    "target_event_id": target_id,
                    "strength": 0,
                    "relations": set(),
                    "reasons": [],
                },
            )
            current["strength"] = max(current["strength"], strength)
            current["relations"].add(relation)
            if reason not in current["reasons"]:
                current["reasons"].append(reason)

        for target_id, relation, field in self.explicit_out.get(event_id, []):
            strength = 80 if field == "narrative" else 100
            link(
                target_id,
                relation,
                strength,
                {"kind": "explicit-event-reference", "field": field},
            )
        for source_id, relation, field in self.explicit_in.get(event_id, []):
            strength = 80 if field == "narrative" else 100
            link(
                source_id,
                _reverse_relation(relation),
                strength,
                {"kind": "reverse-explicit-event-reference", "field": field},
            )

        source_event = self.by_id[event_id]
        source_details = _event_details(source_event)
        source_evidence_references = {
            reference["path"]: reference
            for reference in _event_evidence_references(source_event)
        }
        for path, source_reference in sorted(source_evidence_references.items()):
            for target_id in sorted(self.evidence_path_events.get(path, set())):
                target_reference = next(
                    (
                        reference
                        for reference in _event_evidence_references(self.by_id[target_id])
                        if reference["path"] == path
                    ),
                    None,
                )
                if target_reference is None:
                    continue
                shared_expected_digest = (
                    source_reference["expected_digest"]
                    if source_reference["expected_digest"]
                    == target_reference["expected_digest"]
                    else ""
                )
                source_observation = observations_by_path.get(event_id, {}).get(path)
                target_observation = observations_by_path.get(target_id, {}).get(path)
                current_digest = ""
                if (
                    source_observation is not None
                    and target_observation is not None
                    and source_observation.status == "resolved"
                    and target_observation.status == "resolved"
                    and source_observation.digest == target_observation.digest
                ):
                    current_digest = source_observation.digest
                if shared_expected_digest:
                    strength = 95
                    evidence_basis = "shared-recorded-digest"
                    artifact_digest = shared_expected_digest
                elif current_digest:
                    strength = 80
                    evidence_basis = "shared-current-unbound-bytes"
                    artifact_digest = current_digest
                else:
                    strength = 55
                    evidence_basis = "shared-path-only"
                    artifact_digest = ""
                relation = (
                    "shared-exact-evidence-artifact"
                    if artifact_digest
                    else "shared-evidence-path"
                )
                link(
                    target_id,
                    relation,
                    strength,
                    {
                        "kind": "shared-evidence-artifact",
                        "path": path,
                        "basis": evidence_basis,
                        "artifact_digest": artifact_digest,
                    },
                )

        source_fact_map = {
            (fact.kind, fact.value): fact for fact in facts_by_event.get(event_id, [])
        }
        fact_populations: Counter[tuple[str, str]] = Counter()
        for candidate_facts in facts_by_event.values():
            fact_populations.update(
                {(fact.kind, fact.value) for fact in candidate_facts}
            )
        fact_strength = {"gate-id": 90, "cidr": 85, "ip-address": 72, "lock-id": 90}
        for target_id in candidate_ids:
            for target_fact in facts_by_event.get(target_id, []):
                source_fact = source_fact_map.get((target_fact.kind, target_fact.value))
                if source_fact is None or target_fact.kind not in fact_strength:
                    continue
                if target_fact.kind == "ip-address" and _noncausal_ip_address(
                    target_fact.value
                ):
                    noise["noncausal_operational_fact_links_suppressed"] += 1
                    continue
                strength = fact_strength[target_fact.kind]
                population = fact_populations[(target_fact.kind, target_fact.value)]
                if (
                    target_fact.kind == "ip-address"
                    and population > 8
                    or target_fact.kind == "cidr"
                    and population > 16
                ):
                    strength = min(strength, 55)
                    noise["high_frequency_operational_fact_links_demoted"] += 1
                if "mismatch" in {
                    source_fact.binding_status,
                    target_fact.binding_status,
                }:
                    strength = min(strength, 40)
                elif "current-unbound" in {
                    source_fact.binding_status,
                    target_fact.binding_status,
                }:
                    strength = min(strength, 80)
                link(
                    target_id,
                    "shares-operational-fact",
                    strength,
                    {
                        "kind": "shared-operational-fact",
                        "fact_kind": target_fact.kind,
                        "value": target_fact.value,
                        "source_provenance": source_fact.document(),
                        "target_provenance": target_fact.document(),
                    },
                )

        task_id = _as_string(source_details.get("task_id")).strip()
        task_members = self.task_events.get(task_id, []) if task_id else []
        if task_members:
            task_lifecycle_strength = 70 if len(task_members) <= 12 else 55
            position = task_members.index(event_id)
            if position > 0:
                link(
                    task_members[position - 1],
                    "same-task-previous",
                    45,
                    {"kind": "task-adjacency", "task_id": task_id},
                )
            if position + 1 < len(task_members):
                link(
                    task_members[position + 1],
                    "same-task-next",
                    45,
                    {"kind": "task-adjacency", "task_id": task_id},
                )
            for endpoint, relation in (
                (task_members[0], "task-lifecycle-start"),
                (task_members[-1], "task-lifecycle-latest"),
            ):
                link(
                    endpoint,
                    relation,
                    task_lifecycle_strength,
                    {
                        "kind": "task-lifecycle",
                        "task_id": task_id,
                        "population": len(task_members),
                    },
                )
        for field, relation in _TASK_RELATION_FIELDS.items():
            for related_task in _as_string_list(source_details.get(field)):
                members = self.task_events.get(related_task, [])
                for endpoint, endpoint_kind in (
                    (members[0], "start") if members else (None, "start"),
                    (members[-1], "latest") if members else (None, "latest"),
                ):
                    if endpoint is not None:
                        link(
                            endpoint,
                            relation,
                            80,
                            {
                                "kind": "related-task-lifecycle",
                                "field": field,
                                "task_id": related_task,
                                "endpoint": endpoint_kind,
                            },
                        )
        for subsystem in _as_string_list(source_details.get("subsystem")):
            members = self.subsystem_events.get(subsystem, [])
            if len(members) <= self.rare_subsystem_limit:
                for target_id in members:
                    link(
                        target_id,
                        "shares-rare-subsystem",
                        55,
                        {
                            "kind": "rare-subsystem-context",
                            "subsystem": subsystem,
                            "population": len(members),
                        },
                    )

        findings = list(state_findings)
        relevant_gates: list[dict[str, Any]] = []
        for artifact_event_id, observation, gate in gate_records:
            external_ids = gate["external_event_ids"]
            supporting_external_ids = [
                target_id
                for target_id in external_ids
                if target_id == event_id
                or int(links.get(target_id, {}).get("strength", 0)) >= 70
            ]
            if not supporting_external_ids:
                continue
            relevant_gates.append(
                {
                    **gate,
                    "source_event_id": artifact_event_id,
                    "source_path": observation.path,
                    "binding_status": observation.binding_status,
                    "relevance": (
                        "direct-external-evidence"
                        if event_id in external_ids
                        else "supported-through-connected-event"
                    ),
                    "relevance_event_ids": supporting_external_ids,
                }
            )
            gate_link_strength = {
                "digest-bound": 90,
                "current-unbound": 80,
                "mismatch": 40,
            }.get(observation.binding_status, 40)
            if event_id not in external_ids:
                gate_link_strength = min(gate_link_strength, 80)
            for target_id in external_ids:
                link(
                    target_id,
                    "co-supports-gate",
                    gate_link_strength,
                    {
                        "kind": "gate-external-evidence",
                        "gate_id": gate["gate_id"],
                        "artifact": observation.path,
                        "artifact_digest": observation.digest,
                        "binding_status": observation.binding_status,
                    },
                )
            if gate["production_authorization"]:
                findings.append(
                    {
                        "kind": "gate-authority-claim-rejected",
                        "severity": "warning",
                        "event_id": event_id,
                        "gate_id": gate["gate_id"],
                        "summary": (
                            "An evidence document claims production authorization; "
                            "the relationship projection does not admit or propagate it."
                        ),
                    }
                )
            task = gate["related_task_id"]
            status = self.task_status.get(task, "missing") if task else "missing"
            gate_is_open = gate["gate_status"] in {"open", "blocked"}
            claim_is_current = gate["current_claim"] is not False
            if gate_is_open and claim_is_current and status in {"complete", "failed", "missing"}:
                findings.append(
                    {
                        "kind": "orphaned-gate-owner",
                        "severity": "warning",
                        "event_id": event_id,
                        "gate_id": gate["gate_id"],
                        "task_id": task,
                        "task_status": status,
                        "summary": (
                            "A current open/blocked gate points to a completed, failed or "
                            "missing task and has no active owner lifecycle in Seed."
                        ),
                    }
                )
            stale_after = _parse_utc(gate["stale_after"])
            if gate["observation_status"] == "stale" or (
                stale_after is not None and stale_after < self.as_of
            ):
                findings.append(
                    {
                        "kind": "stale-gate-evidence",
                        "severity": "notice",
                        "event_id": event_id,
                        "gate_id": gate["gate_id"],
                        "stale_after": gate["stale_after"],
                        "summary": "Gate evidence is stale at the deterministic Seed cursor time.",
                    }
                )

        rendered_links: list[dict[str, Any]] = []
        for target_id, raw in links.items():
            strength = int(raw["strength"])
            link_class = "direct" if strength >= 90 else "supported" if strength >= 70 else "contextual"
            if link_class == "contextual" and not include_contextual:
                continue
            target = self.by_id[target_id]
            rendered_links.append(
                {
                    "target_event_id": target_id,
                    "class": link_class,
                    "strength": strength,
                    "relations": sorted(raw["relations"]),
                    "reasons": sorted(
                        raw["reasons"],
                        key=lambda reason: json.dumps(reason, sort_keys=True),
                    ),
                    "target_action": _as_string(target.get("action")),
                    "target_summary": _as_string(target.get("summary")),
                }
            )
        rendered_links.sort(
            key=lambda item: (-item["strength"], item["target_event_id"])
        )
        total_supported = len(rendered_links)
        rendered_links = rendered_links[:limit]
        source_observations = [
            observation.document() for observation in observations.get(event_id, [])
        ]
        source_facts = sorted(
            {json.dumps(fact.document(), sort_keys=True): fact.document() for fact in facts_by_event[event_id]}.values(),
            key=lambda fact: (fact["kind"], fact["value"], fact["source_path"]),
        )
        relevant_finding_event_ids = {
            event_id,
            *(
                target_id
                for target_id, link_value in links.items()
                if int(link_value["strength"]) >= 70
            ),
        }
        findings = [
            item
            for item in findings
            if "event_id" not in item
            or int(item["event_id"]) in relevant_finding_event_ids
        ]
        findings = sorted(
            {json.dumps(item, sort_keys=True): item for item in findings}.values(),
            key=lambda item: (
                item.get("kind", ""),
                item.get("gate_id", ""),
                item.get("path", ""),
            ),
        )
        relevant_gates = sorted(
            {json.dumps(item, sort_keys=True): item for item in relevant_gates}.values(),
            key=lambda item: item["gate_id"],
        )
        direct_count = sum(item["class"] == "direct" for item in rendered_links)
        supported_count = sum(item["class"] == "supported" for item in rendered_links)
        contextual_count = sum(item["class"] == "contextual" for item in rendered_links)
        result = "CONNECTED" if direct_count or supported_count else "CONTEXT_ONLY" if contextual_count else "ISOLATED"
        core = {
            "protocol": RELATIONSHIP_PROTOCOL,
            "event": {
                "event_id": event_id,
                "ts_utc": _as_string(source_event.get("ts_utc")),
                "action": _as_string(source_event.get("action")),
                "summary": _as_string(source_event.get("summary")),
                "task_id": task_id,
            },
            "as_of_event_time": self.as_of.isoformat().replace("+00:00", "Z"),
            "links": rendered_links,
            "link_counts": {
                "direct": direct_count,
                "supported": supported_count,
                "contextual": contextual_count,
                "returned": len(rendered_links),
                "before_limit": total_supported,
            },
            "facts": source_facts,
            "evidence": source_observations,
            "gates": relevant_gates,
            "findings": findings,
            "filtered_noise": noise,
            "evidence_budget": {
                "artifacts_read": resolver.observed_artifacts,
                "bytes_read": resolver.total_bytes,
                "max_artifacts": resolver.max_artifacts,
                "max_bytes": resolver.max_total_bytes,
            },
            "include_contextual": include_contextual,
            "result": result,
            "home_record_count": 0,
            "production_authority": False,
            "route_authority": False,
        }
        return {
            **core,
            "explanation_digest": digest_object(
                core,
                domain="seed-event-connections-v1",
            ),
        }


def explain_seed_event_connections(
    *,
    catalog_path: Path,
    event_id: int,
    evidence_root: Path | None = None,
    evidence_source_prefix: Path | None = None,
    limit: int = 20,
    include_contextual: bool = False,
) -> dict[str, Any]:
    """Build one deterministic, bounded relationship explanation."""

    return SeedRelationshipIndex.from_catalog(
        catalog_path,
        evidence_root=evidence_root,
        evidence_source_prefix=evidence_source_prefix,
    ).explain(
        event_id,
        limit=limit,
        include_contextual=include_contextual,
    )
