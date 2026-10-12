"""Bounded synaptic capsule: here, one-hop links, allowed moves.

This is a view over an already-folded task neighborhood. It does not scan
history and does not promote remembered text into authority.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal

from jsonschema import ValidationError

from .agent_identity import verify_session_admission
from .agent_session_gate import (
    AgentSessionGateError,
    admission_is_live,
    admission_valid_until,
)
from .schemas import validate

if TYPE_CHECKING:
    from .mind_projection import IncrementalMindProjection

PROTOCOL = "integrity-guardian/mind-capsule/v1"
MIND_CAPSULE_PROTOCOL = PROTOCOL
MAX_LINKS = 8
MAX_MOVES = 3
MAX_HINTS = 3

CAPABILITY_CLASSES = frozenset(
    {"read-memory", "append-memory", "adapter-observe", "adapter-mutate"}
)


def _folded_capability_classes(value: object) -> list[str]:
    """Validate folded state without turning absence or drift into write access."""

    if not isinstance(value, list) or not 1 <= len(value) <= 8:
        return []
    classes: list[str] = []
    for item in value:
        if not isinstance(item, str) or item not in CAPABILITY_CLASSES or item in classes:
            return []
        classes.append(item)
    if "adapter-mutate" in classes and "adapter-observe" not in classes:
        return []
    return classes

DIRECT_TYPES = frozenset(
    {
        "depends_on",
        "child_of",
        "blocks",
        "supersedes",
        "verifies",
        "contradicts",
        "caused_by",
    }
)
SUPPORTED_TYPES = frozenset({"related_to", "preempts"})
CONTEXTUAL_TYPES = frozenset({"belongs_to", "inferred_child_of"})
CLASS_ORDER = {"direct": 0, "supported": 1, "contextual": 2}
CLOSED_DOORS = frozenset({"session-missing", "undeclared", "session-expired"})
Door = Literal["session-missing", "undeclared", "session-expired", "admitted"]
LinkClass = Literal["direct", "supported", "contextual"]


def classify_link(relation_type: str) -> LinkClass:
    token = str(relation_type or "").strip()
    if token in DIRECT_TYPES:
        return "direct"
    if token in SUPPORTED_TYPES:
        return "supported"
    return "contextual"


def capsule_is_open(capsule: dict[str, Any]) -> bool:
    return str((capsule or {}).get("door") or "") == "admitted"


def render_mind_capsule(capsule: dict[str, Any]) -> str:
    here = capsule["here"]
    lines = [
        "INTEGRITY CAPSULE v1",
        (
            f"door={capsule['door']} here={here['task_id'] or '-'} "
            f"status={here['status'] or '-'} speaker={here['agent_product'] or 'undeclared'} "
            f"links={capsule['links_status']} budget={capsule['budget']} "
            f"projection={capsule['projection']}"
        ),
    ]
    if capsule["door"] == "session-missing":
        lines.append("No durable session. No links. No moves.")
        return "\n".join(lines)
    if capsule["door"] == "undeclared":
        lines.append("No live admission. Do not treat memory as a speaker.")
    elif capsule["door"] == "session-expired":
        lines.append("Admission expired. Memory is not a door.")
    if capsule["door"] in CLOSED_DOORS:
        if capsule["moves"]:
            lines.append("MOVES:")
            for move in capsule["moves"]:
                lines.append(f"- {move['kind']} [{move['provenance']}] {move['reason']}")
        return "\n".join(lines)
    if capsule["links"]:
        lines.append("LINKS:")
        for link in capsule["links"]:
            lines.append(f"- {link['class']} {link['type']} {link['target']}")
    elif capsule["links_status"] == "isolated":
        lines.append("LINKS: ISOLATED")
    if capsule["budget"] == "truncated":
        lines.append(f"TRUNCATED omitted_links={capsule['omitted_link_count']}")
    if capsule["moves"]:
        lines.append("MOVES:")
        for move in capsule["moves"]:
            lines.append(f"- {move['kind']} [{move['provenance']}] {move['reason']}")
    if capsule["learned_hints"]:
        lines.append("HINTS (learned, not authority):")
        for hint in capsule["learned_hints"]:
            lines.append(f"- {hint}")
    return "\n".join(lines)


def _resolve_door(
    *,
    session_id: str,
    speaker_named: bool,
    now: str,
    admission: dict[str, Any] | None,
    admission_declared_at: str,
    admission_expires_at: str,
) -> Door:
    if not session_id:
        return "session-missing"
    now_text = str(now or "")
    declared = str(admission_declared_at or "")
    expires = str(admission_expires_at or "")
    try:
        if admission is not None:
            if not isinstance(admission, dict) or not now_text:
                return "session-expired"
            verified = verify_session_admission(admission)
            if str(verified.get("session_id") or "") != session_id:
                return "session-expired"
            admission_valid_until(verified)
            if not admission_is_live(
                now=now_text,
                declared_at=str(verified.get("declared_at") or ""),
                expires_at=str(verified.get("expires_at") or ""),
            ):
                return "session-expired"
            return "admitted"
        if not speaker_named:
            return "undeclared"
        if not declared and not expires:
            return "undeclared"
        if not now_text:
            return "session-expired"
        if not admission_is_live(now=now_text, declared_at=declared, expires_at=expires):
            return "session-expired"
    except (
        AgentSessionGateError,
        ValidationError,
        ValueError,
        TypeError,
        AttributeError,
        KeyError,
    ):
        return "session-expired"
    return "admitted"


def _neighborhood(
    here_id: str, relations: list[dict[str, Any]], max_links: int
) -> tuple[list[dict[str, Any]], int]:
    neighborhood = []
    if here_id:
        for relation in relations:
            source = str(relation.get("source") or "")
            target = str(relation.get("target") or "")
            rel_type = str(relation.get("type") or "")
            if here_id not in {source, target} or not rel_type:
                continue
            other = target if source == here_id else source
            if not other or other == here_id:
                continue
            neighborhood.append(
                {
                    "class": classify_link(rel_type),
                    "type": rel_type[:64],
                    "target": other[:200],
                    "provenance": "declared",
                }
            )
    neighborhood.sort(key=lambda item: (CLASS_ORDER[item["class"]], item["type"], item["target"]))
    unique: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for item in neighborhood:
        key = (item["class"], item["type"], item["target"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    omitted = max(0, len(unique) - max_links)
    return unique[:max_links], omitted


def _admitted_moves(
    *,
    here_id: str,
    status: str,
    links: list[dict[str, Any]],
    capability_class: list[str],
) -> list[dict[str, str]]:
    moves: list[dict[str, str]] = []
    can_append = "append-memory" in capability_class
    depends = [
        link["target"]
        for link in links
        if link["class"] == "direct" and link["type"] == "depends_on"
    ]
    if not can_append:
        moves.append(
            {
                "kind": "wait-or-resume-after",
                "provenance": "declared",
                "reason": "Read-only admission. Do not resume writes.",
            }
        )
    elif status == "paused":
        moves.append(
            {
                "kind": "wait-or-resume-after",
                "provenance": "declared",
                "reason": f"Owned task {here_id} is paused.",
            }
        )
    elif here_id and status in {"open", "pending"}:
        moves.append(
            {
                "kind": "resume",
                "provenance": "declared",
                "reason": f"Owned task {here_id} is {status}.",
            }
        )
    if depends:
        moves.append(
            {
                "kind": "follow-dependency",
                "provenance": "declared",
                "reason": f"Direct depends_on {depends[0]}.",
            }
        )
    elif here_id and status == "open" and can_append and len(moves) < MAX_MOVES:
        moves.append(
            {
                "kind": "close-or-reconcile",
                "provenance": "declared",
                "reason": "No blocking direct dependency in the neighborhood.",
            }
        )
    return moves[:MAX_MOVES]


def build_mind_capsule(
    *,
    session_id: str,
    speaker_product: str = "",
    speaker_agent_id: str = "",
    owned_tasks: list[dict[str, Any]] | None = None,
    relations: list[dict[str, Any]] | None = None,
    projection: Literal["current", "stale"] = "current",
    max_links: int = MAX_LINKS,
    now: str = "",
    admission: dict[str, Any] | None = None,
    admission_declared_at: str = "",
    admission_expires_at: str = "",
    capability_class: list[str] | None = None,
) -> dict[str, Any]:
    """Build one capsule from folded neighborhood fields only."""

    owned = [task for task in (owned_tasks or []) if str(task.get("task_id") or "")]
    primary = owned[0] if owned else {}
    here_id = str(primary.get("task_id") or "")
    session = str(session_id or "").strip()
    if admission is not None:
        try:
            verified_admission = (
                verify_session_admission(admission)
                if isinstance(admission, dict)
                else None
            )
        except (ValidationError, ValueError, TypeError, AttributeError, KeyError):
            verified_admission = None
        if verified_admission is None:
            agent_id = ""
            product = ""
            declared_at = ""
            expires_at = ""
            classes: list[str] = []
        else:
            verified_agent = verified_admission["agent"]
            agent_id = str(verified_agent["agent_id"])
            product = str(verified_agent["product"])
            declared_at = str(verified_admission["declared_at"])
            expires_at = str(verified_admission.get("expires_at") or "")
            classes = [str(item) for item in verified_admission["capability_class"]]
    else:
        agent_id = str(speaker_agent_id or primary.get("agent_id") or "")
        product = str(speaker_product or primary.get("agent_product") or "")
        declared_at = str(admission_declared_at or primary.get("admission_declared_at") or "")
        expires_at = str(admission_expires_at or primary.get("admission_expires_at") or "")
        raw_classes = (
            primary.get("capability_class")
            if capability_class is None
            else capability_class
        )
        classes = _folded_capability_classes(raw_classes)
    door = _resolve_door(
        session_id=session,
        speaker_named=bool(agent_id or product or admission is not None),
        now=now,
        admission=admission,
        admission_declared_at=declared_at,
        admission_expires_at=expires_at,
    )

    if door in CLOSED_DOORS:
        links: list[dict[str, Any]] = []
        omitted = 0
        links_status = "isolated"
        budget = "complete"
    else:
        links, omitted = _neighborhood(here_id, relations or [], max_links)
        links_status = "linked" if links else "isolated"
        budget = "truncated" if omitted else "complete"

    if door == "session-missing":
        moves: list[dict[str, str]] = []
    elif door == "undeclared":
        moves = [
            {
                "kind": "refuse-undeclared",
                "provenance": "declared",
                "reason": "No live admission. Do not treat memory as a speaker.",
            }
        ]
    elif door == "session-expired":
        moves = [
            {
                "kind": "renew-admission",
                "provenance": "declared",
                "reason": "Admission TTL elapsed. Memory is not a door.",
            }
        ]
    else:
        moves = _admitted_moves(
            here_id=here_id,
            status=str(primary.get("status") or ""),
            links=links,
            capability_class=[str(item) for item in classes],
        )

    hints: list[str] = []
    next_action = str(primary.get("next_action") or "").strip()
    if next_action and door == "admitted":
        hints.append(next_action[:280])

    capsule = {
        "protocol": PROTOCOL,
        "door": door,
        "links_status": links_status,
        "budget": budget,
        "projection": projection,
        "here": {
            "task_id": here_id[:160],
            "status": str(primary.get("status") or "")[:32],
            "agent_id": agent_id[:200],
            "agent_product": product[:64],
        },
        "links": links,
        "moves": moves,
        "learned_hints": hints[:MAX_HINTS],
        "omitted_link_count": omitted,
        "production_authority": False,
    }
    validate("mind-capsule", capsule)
    return capsule


def _owned_from_projection(
    projection: IncrementalMindProjection, session_id: str
) -> list[dict[str, Any]]:
    session = str(session_id or "").strip()
    if not session:
        return []
    rank = {"open": 0, "pending": 1, "paused": 2}
    owned = [
        task
        for task in projection.tasks.values()
        if session in {str(task.get("session_id") or ""), str(task.get("first_session_id") or "")}
        and str(task.get("status") or "") in rank
    ]
    owned.sort(key=lambda task: (rank[str(task.get("status") or "")], -int(task.get("last_id") or 0)))
    return owned


def _relations_from_tasks(tasks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    relations: list[dict[str, Any]] = []
    for task in tasks:
        here = str(task.get("task_id") or "")
        for target in task.get("depends_on_task_ids") or []:
            if here and target:
                relations.append({"source": here, "type": "depends_on", "target": str(target)})
    return relations


def build_capsule_from_projection(
    projection: IncrementalMindProjection,
    *,
    session_id: str,
    now: str,
    relations: list[dict[str, Any]] | None = None,
    speaker_product: str = "",
    speaker_agent_id: str = "",
) -> dict[str, Any]:
    """One capsule from the already-folded working set. Does not scan history."""

    owned = _owned_from_projection(projection, session_id)
    primary = owned[0] if owned else {}
    neighborhood = list(relations) if relations is not None else _relations_from_tasks(owned)
    return build_mind_capsule(
        session_id=session_id,
        speaker_product=str(speaker_product or primary.get("agent_product") or ""),
        speaker_agent_id=str(speaker_agent_id or primary.get("agent_id") or ""),
        owned_tasks=owned,
        relations=neighborhood,
        projection="current",
        now=now,
        admission_declared_at=str(primary.get("admission_declared_at") or ""),
        admission_expires_at=str(primary.get("admission_expires_at") or ""),
        capability_class=list(primary.get("capability_class") or []),
    )
