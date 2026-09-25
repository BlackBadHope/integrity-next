"""Runtime agent identity: Integrity must tell agents apart before it trusts them.

This is not a module lease and not mutation authority. It answers only:
who is speaking, which product/runtime, and whether two speakers are the same.
Vendor names are optional labels. Unknown vendors remain valid identities.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Literal

from .admission_clock import AdmissionClockError, admission_clock_valid_until
from .hashing import digest_object
from .schemas import validate

PROTOCOL = "integrity-guardian/agent-identity/v1"
ADMISSION_PROTOCOL = "integrity-guardian/agent-session-admission/v1"
AGENT_IDENTITY_PROTOCOL = PROTOCOL
AGENT_SESSION_ADMISSION_PROTOCOL = ADMISSION_PROTOCOL

AgentKind = Literal["coding-agent", "human", "automation", "unknown"]
Relation = Literal["same-instance", "same-product", "different"]

# Checkable today. More vendors may be added without changing identity identity.
KNOWN_PROFILES: dict[tuple[str, str], dict[str, str]] = {
    ("xai", "grok-build"): {
        "kind": "coding-agent",
        "runtime": "grok-build",
        "product": "grok-build",
    },
    ("openai", "codex"): {
        "kind": "coding-agent",
        "runtime": "codex",
        "product": "codex",
    },
}

CAPABILITY_CLASSES = frozenset(
    {
        "read-memory",
        "append-memory",
        "adapter-observe",
        "adapter-mutate",
    }
)


class AgentIdentityError(ValueError):
    """Raised before an ambiguous speaker can be treated as a known agent."""


def _slug(value: str, *, field: str) -> str:
    text = str(value or "").strip().lower()
    if not text:
        raise AgentIdentityError(f"{field} is required")
    cleaned = []
    for char in text:
        if char.isalnum() or char in ".-":
            cleaned.append(char)
        elif char in "_ :/":
            cleaned.append("-")
    slug = "".join(cleaned).strip("-.")
    if not slug or not slug[0].isalnum():
        raise AgentIdentityError(f"{field} is not a valid slug")
    return slug[:64]


def _instance_id(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise AgentIdentityError("instance_id is required")
    if len(text) > 128:
        raise AgentIdentityError("instance_id is too long")
    return text


def declare_agent(
    *,
    vendor: str,
    product: str,
    instance_id: str,
    runtime: str | None = None,
    kind: AgentKind | None = None,
) -> dict[str, Any]:
    """Build one digest-bound identity. Unknown vendors stay first-class."""

    vendor_slug = _slug(vendor, field="vendor")
    product_slug = _slug(product, field="product")
    profile = KNOWN_PROFILES.get((vendor_slug, product_slug), {})
    runtime_slug = _slug(runtime or profile.get("runtime") or product_slug, field="runtime")
    kind_value: AgentKind = kind or profile.get("kind") or "unknown"  # type: ignore[assignment]
    if kind_value not in {"coding-agent", "human", "automation", "unknown"}:
        raise AgentIdentityError("kind is not a closed Integrity agent kind")
    unsigned: dict[str, Any] = {
        "protocol": PROTOCOL,
        "agent_id": "agent:pending",
        "kind": kind_value,
        "vendor": vendor_slug,
        "product": product_slug,
        "runtime": runtime_slug,
        "instance_id": _instance_id(instance_id),
    }
    digest = digest_object(unsigned, domain="agent-identity-v1").split(":", 1)[1]
    unsigned["agent_id"] = f"agent:{digest}"
    validate("agent-identity", unsigned)
    return unsigned


def declare_known_agent(product: str, *, instance_id: str) -> dict[str, Any]:
    """Convenience for the two profiles this owner can verify today."""

    aliases = {
        "grok": ("xai", "grok-build"),
        "grok-build": ("xai", "grok-build"),
        "grok-4.6": ("xai", "grok-build"),
        "codex": ("openai", "codex"),
        "chatgpt-codex": ("openai", "codex"),
    }
    key = aliases.get(str(product or "").strip().lower())
    if key is None:
        raise AgentIdentityError(
            "product is not one of the currently checkable profiles; use declare_agent"
        )
    vendor, canonical_product = key
    return declare_agent(
        vendor=vendor,
        product=canonical_product,
        instance_id=instance_id,
    )


def verify_agent_identity(identity: dict[str, Any]) -> dict[str, Any]:
    candidate = deepcopy(identity)
    validate("agent-identity", candidate)
    unsigned = deepcopy(candidate)
    actual = unsigned["agent_id"]
    unsigned["agent_id"] = "agent:pending"
    expected = "agent:" + digest_object(unsigned, domain="agent-identity-v1").split(":", 1)[1]
    if actual != expected:
        raise AgentIdentityError("agent_id does not match the identity digest")
    return candidate


def relate_agents(left: dict[str, Any], right: dict[str, Any]) -> Relation:
    first = verify_agent_identity(left)
    second = verify_agent_identity(right)
    if first["agent_id"] == second["agent_id"]:
        return "same-instance"
    if (
        first["vendor"] == second["vendor"]
        and first["product"] == second["product"]
        and first["runtime"] == second["runtime"]
    ):
        return "same-product"
    return "different"


def admit_speaker(
    *,
    vendor: str,
    product: str,
    instance_id: str,
    host_id: str,
    task_id: str,
    declared_at: str,
    capability_class: list[str] | None = None,
    runtime: str | None = None,
    kind: AgentKind | None = None,
    expires_at: str | None = None,
) -> dict[str, Any]:
    """The first Word: name the speaker and bind the session. Not authority."""

    agent = declare_agent(
        vendor=vendor,
        product=product,
        instance_id=instance_id,
        runtime=runtime,
        kind=kind,
    )
    return build_session_admission(
        agent=agent,
        session_id=instance_id,
        host_id=host_id,
        capability_class=(
            ["read-memory"] if capability_class is None else capability_class
        ),
        declared_at=declared_at,
        task_id=task_id,
        expires_at=expires_at,
    )


def build_session_admission(
    *,
    agent: dict[str, Any],
    session_id: str,
    host_id: str,
    capability_class: list[str],
    declared_at: str,
    task_id: str,
    expires_at: str | None = None,
) -> dict[str, Any]:
    """The Word: a session exists only after this admission is built."""

    verified = verify_agent_identity(agent)
    if session_id != verified["instance_id"]:
        raise AgentIdentityError("session_id must match agent.instance_id")
    if not isinstance(capability_class, list):
        raise AgentIdentityError("capability_class must be an array")
    if not 1 <= len(capability_class) <= 8:
        raise AgentIdentityError("capability_class size is invalid")
    classes: list[str] = []
    for item in capability_class:
        if not isinstance(item, str):
            raise AgentIdentityError("capability_class item must be a string")
        if item not in CAPABILITY_CLASSES:
            raise AgentIdentityError(f"capability_class {item!r} is not admitted")
        if item in classes:
            raise AgentIdentityError("capability_class contains duplicates")
        classes.append(item)
    if "adapter-mutate" in classes and "adapter-observe" not in classes:
        raise AgentIdentityError("adapter-mutate requires adapter-observe")
    try:
        admission_clock_valid_until(
            declared_at=declared_at,
            expires_at=expires_at or "",
        )
    except AdmissionClockError as exc:
        raise AgentIdentityError(str(exc)) from exc
    unsigned: dict[str, Any] = {
        "protocol": ADMISSION_PROTOCOL,
        "admission_id": "admission:pending",
        "agent": verified,
        "session_id": _instance_id(session_id),
        "host_id": str(host_id or "").strip(),
        "capability_class": classes,
        "production_authority": False,
        "declared_at": declared_at,
        "task_id": str(task_id or "").strip(),
    }
    if expires_at:
        unsigned["expires_at"] = expires_at
    if not unsigned["host_id"] or not unsigned["task_id"]:
        raise AgentIdentityError("host_id and task_id are required")
    digest = digest_object(unsigned, domain="agent-session-admission-v1").split(":", 1)[1]
    unsigned["admission_id"] = f"admission:{digest}"
    validate("agent-session-admission", unsigned)
    return unsigned

def verify_session_admission(admission: dict[str, Any]) -> dict[str, Any]:
    candidate = deepcopy(admission)
    validate("agent-session-admission", candidate)
    if candidate["production_authority"] is not False:
        raise AgentIdentityError("session admission cannot grant production authority")
    verify_agent_identity(candidate["agent"])
    if candidate["session_id"] != candidate["agent"]["instance_id"]:
        raise AgentIdentityError("session_id does not match agent.instance_id")
    try:
        admission_clock_valid_until(
            declared_at=candidate["declared_at"],
            expires_at=candidate.get("expires_at") or "",
        )
    except AdmissionClockError as exc:
        raise AgentIdentityError(str(exc)) from exc
    unsigned = deepcopy(candidate)
    actual = unsigned["admission_id"]
    unsigned["admission_id"] = "admission:pending"
    expected = "admission:" + digest_object(
        unsigned, domain="agent-session-admission-v1"
    ).split(":", 1)[1]
    if actual != expected:
        raise AgentIdentityError("admission_id does not match the admission digest")
    return candidate

def action_log_event_from_admission(admission: dict[str, Any]) -> dict[str, Any]:
    """Map a verified admission to one Action Log append payload."""

    verified = verify_session_admission(admission)
    agent = verified["agent"]
    return {
        "actor": f"{agent['product']}",
        "session_id": verified["session_id"],
        "level": "info",
        "action": "agent_session_admission",
        "summary": (
            f"Admit {agent['product']} ({agent['vendor']}) instance "
            f"{agent['instance_id']} as a distinct Integrity agent."
        ),
        "details": {
            "task_id": verified["task_id"],
            "result": "admitted",
            "truth_status": "observed",
            "production_authority": False,
            "capability_class": list(verified["capability_class"]),
            "agent": agent,
            "admission_id": verified["admission_id"],
            "host_id": verified["host_id"],
            "declared_at": verified["declared_at"],
            "expires_at": str(verified.get("expires_at") or ""),
            "mutation": False,
        },
        "tags": ["integrity", "admission", agent["product"], agent["vendor"]],
    }
