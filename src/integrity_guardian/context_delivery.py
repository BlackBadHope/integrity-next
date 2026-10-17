"""Pure delivery diagnostics for an already admitted, ready read plane.

Counts mirror context_budget._candidate_sources before its closed-door filter.
This function neither opens a session nor establishes model/append/target authority.
Its output is JSON-safe metadata; candidate bodies are never copied into the signal.
"""
from __future__ import annotations

from typing import Any


PROTOCOL = "integrity-context-delivery-health/v1"
LANE_PATHS = {
    "coordination_conflicts": ("coordination", "task_conflicts"),
    "active_locks": ("coordination", "active_locks"),
    "contradictions": ("epistemic", "contradictions"),
    "invariants": ("invariants",),
    "plan_items": ("plan", "items"),
    "recall_hits": ("recall", "hits"),
    "concept_tasks": ("concept_recovery", "relevant_tasks"),
    "attention_items": ("attention", "items"),
    "logical_chains": ("logical_chains",),
    "hierarchy_focus": ("hierarchy", "focus"),
}


def _mapping(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _count(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def recall_candidates(source: dict[str, Any]) -> list[Any]:
    """Auxiliary search first; keep original recall and never duplicate event IDs."""
    primary = _mapping(source.get("recall")).get("hits")
    auxiliary = _mapping(source.get("auxiliary_recall")).get("hits")
    primary = primary if isinstance(primary, list) else []
    auxiliary = auxiliary if isinstance(auxiliary, list) else []
    result, seen = [], set()
    for hit in [*auxiliary, *primary]:
        event_id = hit.get("id") if isinstance(hit, dict) else None
        if isinstance(event_id, int) and not isinstance(event_id, bool) and event_id > 0:
            if event_id in seen:
                continue
            seen.add(event_id)
        result.append(hit)
    return result


def _source_counts(source: dict[str, Any]) -> dict[str, int]:
    counts = {}
    for lane, path in LANE_PATHS.items():
        value: object = source
        for key in path:
            value = _mapping(value).get(key)
        # Match the selector: _items accepts lists, never mappings/tuples/scalars.
        counts[lane] = len(value) if isinstance(value, list) else 0
    counts["recall_hits"] = len(recall_candidates(source))
    return counts


def _receipt_counts(value: object, label: str) -> tuple[dict[str, int | None], list[str]]:
    mapping = _mapping(value)
    names = tuple(LANE_PATHS) + tuple(sorted(key for key in mapping if isinstance(key, str) and key not in LANE_PATHS))
    counts = {name: _count(mapping.get(name)) for name in names}
    issues = []
    if not isinstance(value, dict):
        issues.append(label + "-missing-or-invalid")
    if any(count is None for count in counts.values()) or any(not isinstance(key, str) for key in mapping):
        issues.append(label + "-incomplete-or-invalid")
    return counts, issues


def _source_event_count(source: dict[str, Any]) -> tuple[int | None, str | None, list[str]]:
    snapshot = _mapping(source.get("snapshot"))
    nodes = _mapping(source.get("node_counts"))
    values = [(label, _count(value)) for label, value in (
        ("snapshot.event_count", snapshot.get("event_count")),
        ("node_counts.event", nodes.get("event")),
    ) if (label == "snapshot.event_count" and "event_count" in snapshot)
        or (label == "node_counts.event" and "event" in nodes)]
    if not values:
        return None, None, ["source-event-count-missing"]
    if any(value is None for _, value in values):
        return None, None, ["source-event-count-invalid"]
    if len({value for _, value in values}) != 1:
        return None, None, ["source-event-count-conflict"]
    return values[0][1], values[0][0], []


def evaluate_context_delivery(source_mind, presented_capsule, selection_receipt) -> dict[str, Any]:
    """Evaluate metadata deterministically without reading or changing any state.

    A nonempty source is degraded when the presented door is session-missing,
    or recall selection and every selector-available lane are zero. Missing
    counters are UNKNOWN, not zero. An empty database is a legal ready state.
    A zero candidate budget is reported separately; it does not override this
    predicate or authorize a session, recall, append, or external action.
    """
    source = _mapping(source_mind)
    capsule = _mapping(presented_capsule)
    receipt = _mapping(selection_receipt)
    raw_counts = _source_counts(source)
    available, available_issues = _receipt_counts(receipt.get("available_candidates"), "available-candidates")
    selected, selected_issues = _receipt_counts(receipt.get("selected_candidates"), "selected-candidates")
    event_count, count_source, source_issues = _source_event_count(source)
    issues = list(source_issues)
    if not isinstance(source_mind, dict):
        issues.append("source-mind-invalid")
    if not isinstance(presented_capsule, dict):
        issues.append("presented-capsule-invalid")
    if not isinstance(selection_receipt, dict):
        issues.append("selection-receipt-invalid")
    issues.extend(available_issues + selected_issues)
    if not available_issues and not selected_issues:
        if any(selected.get(lane, 0) > count for lane, count in available.items()):
            issues.append("selected-exceeds-available")

    door_value = _mapping(capsule.get("synaptic")).get("door")
    # Expose only the known door marker needed for this predicate, not raw text.
    session_missing = door_value == "session-missing"
    door = "session-missing" if session_missing else None
    all_available_zero = not available_issues and all(count == 0 for count in available.values())
    zero_recall_and_available = all_available_zero and selected.get("recall_hits") == 0
    budget = {name: _count(receipt.get(name)) for name in ("max_candidates", "transport_candidate_cap", "max_context_bytes")}
    budget_zero = budget["max_candidates"] == 0 or budget["transport_candidate_cap"] == 0
    reasons = []

    if event_count is None:
        health, status = "unknown", "invalid-delivery-evidence"
    elif event_count == 0:
        health, status = "ready", "ready"
        reasons.append("empty-source")
    elif session_missing or zero_recall_and_available:
        health, status = "degraded", "memory-not-delivered"
        if session_missing:
            reasons.append("session-missing")
        if zero_recall_and_available:
            reasons.append("recall-and-selector-candidates-zero")
    elif issues:
        health, status = "unknown", "invalid-delivery-evidence"
    else:
        health, status = "ready", "ready"
    if any(raw_counts.values()) and all_available_zero:
        reasons.append("raw-candidates-hidden-from-selector")
    if budget_zero:
        reasons.append("candidate-budget-zero")

    return {
        "protocol": PROTOCOL,
        "health": health,
        "status": status,
        "reasons": reasons,
        "evidence_issues": issues,
        "source_event_count": event_count,
        "source_event_count_source": count_source,
        "source_state": "empty" if event_count == 0 else "nonempty" if event_count is not None else "unknown",
        "presented_door": door,
        "raw_candidate_counts": raw_counts,
        "available_candidate_counts": available,
        "selected_candidate_counts": selected,
        "candidate_budget": budget,
        "notify_owner_required": health in ("degraded", "unknown"),
        "read_plane": "ready",
        "external_action_authority": False,
        "external_action_authority_changed": False,
        "model_delivery_verified": False,
    }
