"""Deterministic adaptive context budgeting for Memory Synapse admissions.

The canonical Action Log projection stays complete and immutable inside the
facade session.  This module only chooses a bounded presentation capsule for
the model-facing response; it never changes the source projection or its
authority semantics.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from typing import Any

from .mind_capsule import capsule_is_open, render_mind_capsule

BRIDGE_PROTOCOL = "integrity-client-memory-mcp/v3"
CONTEXT_CAPSULE_PROTOCOL = BRIDGE_PROTOCOL + "/context-capsule/v1"
SELECTION_RECEIPT_PROTOCOL = BRIDGE_PROTOCOL + "/adaptive-context-selection/v1"
ARCHITECTURE_CAPSULE_PROTOCOL = BRIDGE_PROTOCOL + "/architecture-capsule/v1"
POLICY_VERSION = "adaptive-context-v1"
_ARCHITECTURE_SUMMARY_FIELDS = (
    "mind_admission_receipt_id",
    "concept_recovery_digest",
    "coordination_digest",
    "coordination_stop_required",
    "route_disposition",
    "ledger_event_digest",
    "checkpoint_digest",
    "atlas_projection_digest",
    "connectome_compilation_id",
    "synapse_plan_id",
)

DEFAULT_MAX_CONTEXT_BYTES = 32_768
MIN_MAX_CONTEXT_BYTES = 8_192
MAX_MAX_CONTEXT_BYTES = 262_144
DEFAULT_MAX_CANDIDATES = 50
MAX_MAX_CANDIDATES = 50
_CONTEXT_CORE_RESERVE_BYTES = 4_096
_ESTIMATED_CANDIDATE_BYTES = 1_024

_TOKEN_RE = re.compile(r"[^\W_][\w.:/@-]*", re.UNICODE)
_BROAD_SCOPE_MARKERS = (
    "architecture",
    "architectural",
    "dynamic",
    "global",
    "overview",
    "roadmap",
    "system",
    "архитект",
    "глобаль",
    "динамич",
    "дорожн",
    "обзор",
    "роадмап",
    "систем",
)
_BROAD_SCOPE_TERMS = {"all", "everything", "все", "всё", "усі"}
_IMPLEMENTATION_MARKERS = (
    "build",
    "develop",
    "implement",
    "start",
    "внедр",
    "начин",
    "начн",
    "разработ",
    "реализ",
)


class ContextBudgetError(ValueError):
    """The caller supplied an invalid or ambiguous presentation budget."""


@dataclass(frozen=True)
class ContextBudget:
    """Resolved deterministic policy for one intent."""

    mode: str
    max_context_bytes: int
    max_candidates: int
    transport_candidate_cap: int
    intent_term_count: int
    broad_scope: bool
    implementation_scope: bool


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(value)).hexdigest()


def _strict_integer(value: object, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ContextBudgetError(f"{name} must be between {minimum} and {maximum}")
    return value


def resolve_context_budget(
    intent: str,
    *,
    legacy_limit: int | None = None,
    budget: dict[str, Any] | None = None,
) -> ContextBudget:
    """Resolve a fixed compatibility request or an adaptive byte budget.

    ``legacy_limit`` deliberately preserves the old full-response behavior.
    New callers omit it and may optionally tighten the adaptive policy through
    ``budget``.
    """

    if legacy_limit is not None and budget is not None:
        raise ContextBudgetError("limit and budget cannot be combined")
    if legacy_limit is not None:
        limit = _strict_integer(legacy_limit, "limit", 1, MAX_MAX_CANDIDATES)
        return ContextBudget(
            mode="fixed-compat",
            max_context_bytes=0,
            max_candidates=limit,
            transport_candidate_cap=limit,
            intent_term_count=0,
            broad_scope=False,
            implementation_scope=False,
        )

    raw_budget: dict[str, Any] = {} if budget is None else budget
    if not isinstance(raw_budget, dict):
        raise ContextBudgetError("budget must be an object")
    unknown = sorted(set(raw_budget) - {"max_context_bytes", "max_candidates"})
    if unknown:
        raise ContextBudgetError("unsupported budget field(s): " + ", ".join(unknown))
    max_context_bytes = _strict_integer(
        raw_budget.get("max_context_bytes", DEFAULT_MAX_CONTEXT_BYTES),
        "max_context_bytes",
        MIN_MAX_CONTEXT_BYTES,
        MAX_MAX_CONTEXT_BYTES,
    )
    max_candidates = _strict_integer(
        raw_budget.get("max_candidates", DEFAULT_MAX_CANDIDATES),
        "max_candidates",
        1,
        MAX_MAX_CANDIDATES,
    )

    normalized = intent.casefold()
    terms = {match.group(0) for match in _TOKEN_RE.finditer(normalized)}
    term_count = len(terms)
    broad_scope = bool(terms & _BROAD_SCOPE_TERMS) or any(
        marker in normalized for marker in _BROAD_SCOPE_MARKERS
    )
    implementation_scope = any(marker in normalized for marker in _IMPLEMENTATION_MARKERS)
    complexity = min(12, max(1, math.ceil(math.sqrt(max(1, term_count)))))
    intent_target = 4 + (2 * complexity) + (4 if broad_scope else 0)
    if implementation_scope:
        intent_target += 2
    budget_capacity = max(
        1,
        (max_context_bytes - _CONTEXT_CORE_RESERVE_BYTES) // _ESTIMATED_CANDIDATE_BYTES,
    )
    transport_candidate_cap = max(
        1,
        min(max_candidates, intent_target, budget_capacity),
    )
    return ContextBudget(
        mode="adaptive",
        max_context_bytes=max_context_bytes,
        max_candidates=max_candidates,
        transport_candidate_cap=transport_candidate_cap,
        intent_term_count=term_count,
        broad_scope=broad_scope,
        implementation_scope=implementation_scope,
    )


def _mapping(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _items(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def _short_text(value: object, maximum: int = 500) -> str:
    text = str(value or "")
    encoded = text.encode("utf-8")
    if len(encoded) <= maximum:
        return text
    if maximum <= 3:
        return encoded[:maximum].decode("utf-8", errors="ignore")
    return encoded[: maximum - 3].decode("utf-8", errors="ignore").rstrip() + "…"


def _short_list(value: object, *, maximum: int = 6, text_limit: int = 80) -> list[str]:
    return [_short_text(item, text_limit) for item in _items(value)[:maximum]]


def _bounded_value(value: object, *, depth: int = 0) -> Any:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return _short_text(value, 500)
    if depth >= 2:
        return _short_text(value, 240)
    if isinstance(value, list):
        return [_bounded_value(item, depth=depth + 1) for item in value[:8]]
    if isinstance(value, dict):
        return {
            _short_text(key, 80): _bounded_value(item, depth=depth + 1)
            for key, item in list(value.items())[:16]
        }
    return _short_text(value, 240)


_COMMON_RECORD_FIELDS = (
    "event_id",
    "id",
    "task_id",
    "kind",
    "status",
    "truth_status",
    "confidence",
    "memory_status",
    "score",
    "score_reasons",
    "priority",
    "ready",
    "requires_owner_go",
    "requires_fresh_evidence",
    "scope",
    "risk_level",
    "summary",
    "next_action",
    "done_when",
    "reason",
    "subject",
    "predicate",
    "values",
    "dependencies",
    "chain_gaps",
    "last_event",
    "source",
    "type",
    "target",
)


def _compact_record(value: object) -> Any:
    if not isinstance(value, dict):
        return _bounded_value(value)
    compact = {key: _bounded_value(value[key]) for key in _COMMON_RECORD_FIELDS if key in value}
    if compact:
        return compact
    return _bounded_value(value)


def _count_mapping(value: object) -> dict[str, int]:
    if not isinstance(value, dict):
        return {}
    return {
        _short_text(key, 80): int(item)
        for key, item in list(value.items())[:24]
        if isinstance(item, int) and not isinstance(item, bool)
    }


def _synaptic_view(source: dict[str, Any]) -> dict[str, Any] | None:
    raw = source.get("capsule")
    if not isinstance(raw, dict) or not raw.get("door"):
        return None
    here = raw.get("here") if isinstance(raw.get("here"), dict) else {}
    return {
        "protocol": str(raw.get("protocol") or "")[:80],
        "door": str(raw.get("door") or "session-missing")[:32],
        "links_status": str(raw.get("links_status") or "isolated")[:16],
        "budget": str(raw.get("budget") or "complete")[:16],
        "projection": str(raw.get("projection") or "current")[:16],
        "here": {
            "task_id": _short_text(here.get("task_id"), 160),
            "status": _short_text(here.get("status"), 32),
            "agent_id": _short_text(here.get("agent_id"), 200),
            "agent_product": _short_text(here.get("agent_product"), 64),
        },
        "links": _bounded_value(raw.get("links") or []),
        "moves": _bounded_value(raw.get("moves") or []),
        "learned_hints": _short_list(raw.get("learned_hints") or [], maximum=3, text_limit=280),
        "omitted_link_count": (
            int(raw.get("omitted_link_count") or 0)
            if isinstance(raw.get("omitted_link_count"), int)
            and not isinstance(raw.get("omitted_link_count"), bool)
            else 0
        ),
        "production_authority": False,
    }


def _candidate_sources(source: dict[str, Any]) -> dict[str, list[Any]]:
    coordination = _mapping(source.get("coordination"))
    concept = _mapping(source.get("concept_recovery"))
    epistemic = _mapping(source.get("epistemic"))
    plan = _mapping(source.get("plan"))
    recall = _mapping(source.get("recall"))
    attention = _mapping(source.get("attention"))
    hierarchy = _mapping(source.get("hierarchy"))
    return {
        "coordination_conflicts": _items(coordination.get("task_conflicts")),
        "active_locks": _items(coordination.get("active_locks")),
        "contradictions": _items(epistemic.get("contradictions")),
        "invariants": _items(source.get("invariants")),
        "plan_items": _items(plan.get("items")),
        "recall_hits": _items(recall.get("hits")),
        "concept_tasks": _items(concept.get("relevant_tasks")),
        "attention_items": _items(attention.get("items")),
        "logical_chains": _items(source.get("logical_chains")),
        "hierarchy_focus": _items(hierarchy.get("focus")),
    }


def _capsule_core(source: dict[str, Any], admission: dict[str, Any]) -> dict[str, Any]:
    coordination = _mapping(source.get("coordination"))
    concept = _mapping(source.get("concept_recovery"))
    epistemic = _mapping(source.get("epistemic"))
    plan = _mapping(source.get("plan"))
    recall = _mapping(source.get("recall"))
    hierarchy = _mapping(source.get("hierarchy"))
    core = {
        "protocol": CONTEXT_CAPSULE_PROTOCOL,
        "memory_source": source.get("memory_source"),
        "snapshot": {
            key: source.get("snapshot", {}).get(key)
            for key in ("event_count", "event_cursor")
            if isinstance(source.get("snapshot"), dict) and key in source["snapshot"]
        },
        "source_projection": {
            "projection_digest": source.get("projection_digest"),
            "mind_receipt_id": admission.get("mind_receipt_id"),
            "complete": False,
        },
        "concept_summary": {
            "source_digest": admission.get("concept_recovery_digest"),
            "mission_root": _short_text(concept.get("mission_root"), 160),
            "focus_terms": _short_list(
                concept.get("focus_terms", source.get("focus_terms")),
                maximum=12,
                text_limit=80,
            ),
            "relation_count": (
                concept.get("relation_count")
                if isinstance(concept.get("relation_count"), int)
                and not isinstance(concept.get("relation_count"), bool)
                else None
            ),
            "logical_chain_count": (
                concept.get("logical_chain_count")
                if isinstance(concept.get("logical_chain_count"), int)
                and not isinstance(concept.get("logical_chain_count"), bool)
                else None
            ),
            "known_unknowns": _count_mapping(concept.get("known_unknowns")),
            "relevant_tasks": [],
        },
        "coordination_summary": {
            "source_digest": admission.get("coordination_digest"),
            "stop_required": bool(coordination.get("stop_required", True)),
            "owner_go_required": bool(coordination.get("owner_go_required", True)),
            "production_scope_present": bool(coordination.get("production_scope_present", True)),
            "affected_subsystems": _short_list(coordination.get("affected_subsystems")),
            "affected_hosts": _short_list(coordination.get("affected_hosts")),
            "scope_classes": _short_list(coordination.get("scope_classes")),
            "risk_classes": _short_list(coordination.get("risk_classes")),
            "task_conflicts": [],
            "active_locks": [],
        },
        "working_set": {
            "node_counts": _count_mapping(source.get("node_counts")),
            "hierarchy_counts": {
                key: hierarchy.get(key)
                for key in (
                    "task_count",
                    "goal_count",
                    "roadmap_item_count",
                    "domain_count",
                    "subsystem_count",
                    "orphan_parent_count",
                )
                if isinstance(hierarchy.get(key), int) and not isinstance(hierarchy.get(key), bool)
            },
            "epistemic_counts": {
                key: epistemic.get(key)
                for key in (
                    "assertion_count",
                    "active_assertion_count",
                    "current_fact_count",
                    "stale_assertion_count",
                    "contradiction_count",
                )
                if isinstance(epistemic.get(key), int) and not isinstance(epistemic.get(key), bool)
            },
            "plan_counts": {
                key: plan.get(key)
                for key in ("item_count", "ready_count", "blocked_by_dependency_count")
                if isinstance(plan.get(key), int) and not isinstance(plan.get(key), bool)
            },
            "recall_terms": _short_list(recall.get("terms"), maximum=12, text_limit=80),
            "context_text": "",
            "invariants": [],
            "plan_items": [],
            "recall_hits": [],
            "attention_items": [],
            "contradictions": [],
            "logical_chains": [],
            "hierarchy_focus": [],
        },
        "home_record_count": 0,
        "production_authority": False,
    }
    synaptic = _synaptic_view(source)
    if synaptic is not None:
        core["synaptic"] = synaptic
    return core


def _lane_target(capsule: dict[str, Any], lane: str) -> list[Any]:
    if lane == "coordination_conflicts":
        return capsule["coordination_summary"]["task_conflicts"]
    if lane == "active_locks":
        return capsule["coordination_summary"]["active_locks"]
    if lane == "concept_tasks":
        return capsule["concept_summary"]["relevant_tasks"]
    return capsule["working_set"][lane]


def build_context_capsule(
    source: dict[str, Any],
    admission: dict[str, Any],
    policy: ContextBudget,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build and bind a deterministic capsule without mutating ``source``."""

    if policy.mode != "adaptive":
        raise ContextBudgetError("a context capsule requires adaptive mode")
    capsule = _capsule_core(source, admission)
    synaptic = source.get("capsule") if isinstance(source.get("capsule"), dict) else None
    door_open = True if synaptic is None else capsule_is_open(synaptic)
    synaptic_lead = render_mind_capsule(synaptic) if synaptic is not None else ""
    if synaptic_lead:
        capsule["working_set"]["context_text"] = synaptic_lead
    if len(_canonical_json(capsule)) > policy.max_context_bytes:
        raise ContextBudgetError("max_context_bytes cannot hold the mandatory safety capsule")
    sources = (
        _candidate_sources(source)
        if door_open
        else {name: [] for name in _candidate_sources(source)}
    )
    available = {name: len(values) for name, values in sources.items()}
    selected = {name: 0 for name in sources}
    dropped_for_budget = False
    lane_names = tuple(sources)
    maximum_lane_length = max((len(values) for values in sources.values()), default=0)
    for index in range(min(maximum_lane_length, policy.transport_candidate_cap)):
        for lane in lane_names:
            values = sources[lane]
            if index >= len(values):
                continue
            target = _lane_target(capsule, lane)
            candidate = _compact_record(values[index])
            target.append(candidate)
            if len(_canonical_json(capsule)) <= policy.max_context_bytes:
                selected[lane] += 1
            else:
                target.pop()
                dropped_for_budget = True

    if synaptic is not None and not door_open:
        raw_context_text = synaptic_lead
    elif synaptic is not None:
        rest = str(source.get("context_text") or "")
        raw_context_text = rest if rest.startswith(synaptic_lead) else f"{synaptic_lead}\n\n{rest}".strip()
    else:
        raw_context_text = str(source.get("context_text") or "")
    context_text = _short_text(raw_context_text, 4_096)
    if context_text != raw_context_text:
        dropped_for_budget = True
    placed = False
    for length in (4_096, 2_048, 1_024, 512):
        candidate_text = _short_text(context_text, length)
        capsule["working_set"]["context_text"] = candidate_text
        if len(_canonical_json(capsule)) <= policy.max_context_bytes:
            if candidate_text != context_text:
                dropped_for_budget = True
            placed = True
            break
    if not placed and synaptic_lead:
        capsule["working_set"]["context_text"] = synaptic_lead
        if len(_canonical_json(capsule)) <= policy.max_context_bytes:
            dropped_for_budget = True
            placed = True
    if not placed:
        capsule["working_set"]["context_text"] = ""
        dropped_for_budget = dropped_for_budget or bool(context_text)

    capsule_bytes = len(_canonical_json(capsule))
    source_bytes = len(_canonical_json(source))
    candidates_truncated = any(selected[name] < available[name] for name in available)
    selection_core = {
        "protocol": SELECTION_RECEIPT_PROTOCOL,
        "mode": policy.mode,
        "policy_version": POLICY_VERSION,
        "intent_fingerprint": admission.get("intent_fingerprint"),
        "source_projection_digest": admission.get("projection_digest"),
        "capsule_digest": _digest(capsule),
        "max_context_bytes": policy.max_context_bytes,
        "max_candidates": policy.max_candidates,
        "transport_candidate_cap": policy.transport_candidate_cap,
        "intent_term_count": policy.intent_term_count,
        "broad_scope": policy.broad_scope,
        "implementation_scope": policy.implementation_scope,
        "source_projection_bytes": source_bytes,
        "capsule_bytes": capsule_bytes,
        "available_candidates": available,
        "selected_candidates": selected,
        "truncated": True,
        "candidates_truncated": candidates_truncated,
        "stop_reason": (
            "byte-budget-exhausted"
            if dropped_for_budget
            else "candidate-cap-reached"
            if candidates_truncated
            else "bounded-projection-complete"
        ),
        "home_record_count": 0,
        "production_authority": False,
    }
    receipt = {**selection_core, "receipt_id": _digest(selection_core)}
    return capsule, receipt


def compact_architecture_admission(value: dict[str, Any]) -> dict[str, Any]:
    """Remove duplicated signed graph bodies from the model-facing response."""

    if value.get("outcome") == "unavailable":
        return dict(value)
    architecture = _mapping(value.get("architecture"))
    custody = _mapping(value.get("custody"))
    checkpoint = _mapping(custody.get("checkpoint"))
    summary = _mapping(architecture.get("summary"))
    compact = {
        "protocol": ARCHITECTURE_CAPSULE_PROTOCOL,
        "architecture": {
            "admission_id": architecture.get("admission_id"),
            "summary": {field: summary.get(field) for field in _ARCHITECTURE_SUMMARY_FIELDS},
        },
        "custody": {
            "receipt_id": custody.get("receipt_id"),
            "architecture_admission_id": custody.get("architecture_admission_id"),
            "mind_admission_receipt_id": custody.get("mind_admission_receipt_id"),
            "write_status": custody.get("write_status"),
            "checkpoint": {
                key: checkpoint.get(key)
                for key in ("checkpoint_id", "root_digest", "tree_size")
                if key in checkpoint
            },
            "home_record_count": custody.get("home_record_count", 0),
            "production_authority": False,
        },
        "source_architecture_digest": _digest(value),
        "complete": False,
        "home_record_count": 0,
        "production_authority": False,
    }
    return compact
