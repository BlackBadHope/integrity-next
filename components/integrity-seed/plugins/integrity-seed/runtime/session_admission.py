"""Seed-local verification for Guardian agent/session admission receipts.

The exact Seed artifact cannot import the monorepo package. This module keeps
the shared wire protocol, canonical digest, capability rules, and Action Log
event projection inside Seed-owned bytes. A malformed declaration is never a
live speaker and recalled state never gains production authority.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
from copy import deepcopy
from pathlib import Path
from typing import Any

AGENT_PROTOCOL = "integrity-guardian/agent-identity/v1"
ADMISSION_PROTOCOL = "integrity-guardian/agent-session-admission/v1"
PROFILE = "guardian-json-v1"
CAPABILITY_CLASSES = frozenset(
    {
        "read-memory",
        "append-memory",
        "adapter-observe",
        "adapter-mutate",
    }
)
AGENT_KINDS = frozenset({"coding-agent", "human", "automation", "unknown"})
KNOWN_PROFILES: dict[tuple[str, str], dict[str, str]] = {
    ("xai", "grok-build"): {
        "kind": "coding-agent",
        "runtime": "grok-build",
    },
    ("openai", "codex"): {
        "kind": "coding-agent",
        "runtime": "codex",
    },
}
_AGENT_ID_RE = re.compile(r"^agent:[a-f0-9]{64}$")
_ADMISSION_ID_RE = re.compile(r"^admission:[a-f0-9]{64}$")
_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,63}$")
_INSTANCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")

_CLOCK_PATH = Path(__file__).resolve().with_name("admission_clock.py")
_CLOCK_SPEC = importlib.util.spec_from_file_location(
    "integrity_seed_session_admission_clock",
    _CLOCK_PATH,
)
if _CLOCK_SPEC is None or _CLOCK_SPEC.loader is None:
    raise RuntimeError("admission_clock module is missing")
_CLOCK = importlib.util.module_from_spec(_CLOCK_SPEC)
_CLOCK_SPEC.loader.exec_module(_CLOCK)
AdmissionClockError = _CLOCK.AdmissionClockError
admission_clock_valid_until = _CLOCK.admission_clock_valid_until
parse_rfc3339 = _CLOCK.parse_rfc3339


class SessionAdmissionError(ValueError):
    """Raised before an invalid declaration can become a live speaker."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise SessionAdmissionError(message)


def _validate_json(value: Any, path: str = "$") -> None:
    if value is None or type(value) in {str, bool, int}:
        return
    if isinstance(value, float):
        raise SessionAdmissionError(f"{path}: floating-point values are prohibited")
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise SessionAdmissionError(f"{path}: object key must be a string")
            _validate_json(child, f"{path}.{key}")
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            _validate_json(child, f"{path}[{index}]")
        return
    raise SessionAdmissionError(
        f"{path}: unsupported value type {type(value).__name__}"
    )


def canonical_bytes(value: Any) -> bytes:
    _validate_json(value)
    try:
        rendered = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise SessionAdmissionError(str(exc)) from exc
    return rendered.encode("utf-8")


def digest_object(value: Any, *, domain: str) -> str:
    if not domain or any(char.isspace() for char in domain):
        raise SessionAdmissionError(
            "domain must be a non-empty token without whitespace"
        )
    prefix = f"integrity-guardian\\x00{PROFILE}\\x00{domain}\\x00".encode()
    return "sha256:" + hashlib.sha256(prefix + canonical_bytes(value)).hexdigest()


def _exact_object(
    value: Any,
    *,
    label: str,
    required: set[str],
    optional: set[str] | None = None,
) -> dict[str, Any]:
    _require(isinstance(value, dict), f"{label} must be an object")
    candidate = deepcopy(value)
    allowed = required | (optional or set())
    missing = sorted(required - set(candidate))
    extra = sorted(set(candidate) - allowed)
    _require(not missing, f"{label} is missing fields: {missing}")
    _require(not extra, f"{label} has unsupported fields: {extra}")
    return candidate


def _slug(value: str, *, field: str) -> str:
    text = str(value or "").strip().lower()
    _require(bool(text), f"{field} is required")
    cleaned = []
    for char in text:
        if char.isalnum() or char in ".-":
            cleaned.append(char)
        elif char in "_ :/":
            cleaned.append("-")
    slug = "".join(cleaned).strip("-.")
    _require(bool(slug) and slug[0].isalnum(), f"{field} is not a valid slug")
    return slug[:64]


def _instance_id(value: str) -> str:
    text = str(value or "").strip()
    _require(bool(_INSTANCE_RE.fullmatch(text)), "instance_id is invalid")
    return text


def _validate_capability_classes(value: Any) -> list[str]:
    _require(isinstance(value, list), "capability_class must be an array")
    _require(1 <= len(value) <= 8, "capability_class size is invalid")
    classes: list[str] = []
    for item in value:
        _require(isinstance(item, str), "capability_class item must be a string")
        _require(item in CAPABILITY_CLASSES, f"capability_class {item!r} is not admitted")
        _require(item not in classes, "capability_class contains duplicates")
        classes.append(item)
    if "adapter-mutate" in classes:
        _require(
            "adapter-observe" in classes,
            "adapter-mutate requires adapter-observe",
        )
    return classes


def build_agent_identity(
    *,
    vendor: str,
    product: str,
    instance_id: str,
    runtime: str | None = None,
    kind: str | None = None,
) -> dict[str, Any]:
    vendor_slug = _slug(vendor, field="vendor")
    product_slug = _slug(product, field="product")
    profile = KNOWN_PROFILES.get((vendor_slug, product_slug), {})
    runtime_slug = _slug(
        runtime or profile.get("runtime") or product_slug,
        field="runtime",
    )
    kind_value = kind or profile.get("kind") or "unknown"
    _require(kind_value in AGENT_KINDS, "kind is not a closed Integrity agent kind")
    unsigned: dict[str, Any] = {
        "protocol": AGENT_PROTOCOL,
        "agent_id": "agent:pending",
        "kind": kind_value,
        "vendor": vendor_slug,
        "product": product_slug,
        "runtime": runtime_slug,
        "instance_id": _instance_id(instance_id),
    }
    digest = digest_object(unsigned, domain="agent-identity-v1").split(":", 1)[1]
    unsigned["agent_id"] = f"agent:{digest}"
    return verify_agent_identity(unsigned)


def verify_agent_identity(identity: dict[str, Any]) -> dict[str, Any]:
    required = {
        "protocol",
        "agent_id",
        "kind",
        "vendor",
        "product",
        "runtime",
        "instance_id",
    }
    candidate = _exact_object(
        identity,
        label="agent identity",
        required=required,
    )
    _require(candidate["protocol"] == AGENT_PROTOCOL, "agent protocol is invalid")
    _require(
        isinstance(candidate["agent_id"], str)
        and _AGENT_ID_RE.fullmatch(candidate["agent_id"]) is not None,
        "agent_id is invalid",
    )
    _require(candidate["kind"] in AGENT_KINDS, "agent kind is invalid")
    for field in ("vendor", "product", "runtime"):
        _require(
            isinstance(candidate[field], str)
            and _SLUG_RE.fullmatch(candidate[field]) is not None,
            f"{field} is invalid",
        )
    _require(
        isinstance(candidate["instance_id"], str)
        and _INSTANCE_RE.fullmatch(candidate["instance_id"]) is not None,
        "instance_id is invalid",
    )
    unsigned = deepcopy(candidate)
    actual = unsigned["agent_id"]
    unsigned["agent_id"] = "agent:pending"
    expected = "agent:" + digest_object(
        unsigned,
        domain="agent-identity-v1",
    ).split(":", 1)[1]
    _require(actual == expected, "agent_id does not match the identity digest")
    return candidate


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
    verified = verify_agent_identity(agent)
    session = _instance_id(session_id)
    _require(
        session == verified["instance_id"],
        "session_id must match agent.instance_id",
    )
    host = str(host_id or "").strip()
    task = str(task_id or "").strip()
    _require(_HOST_RE.fullmatch(host) is not None, "host_id is invalid")
    _require(_INSTANCE_RE.fullmatch(task) is not None, "task_id is invalid")
    try:
        admission_clock_valid_until(
            declared_at=declared_at,
            expires_at=expires_at or "",
        )
    except AdmissionClockError as exc:
        raise SessionAdmissionError(str(exc)) from exc
    unsigned: dict[str, Any] = {
        "protocol": ADMISSION_PROTOCOL,
        "admission_id": "admission:pending",
        "agent": verified,
        "session_id": session,
        "host_id": host,
        "capability_class": _validate_capability_classes(capability_class),
        "production_authority": False,
        "declared_at": declared_at,
        "task_id": task,
    }
    if expires_at:
        unsigned["expires_at"] = expires_at
    digest = digest_object(
        unsigned,
        domain="agent-session-admission-v1",
    ).split(":", 1)[1]
    unsigned["admission_id"] = f"admission:{digest}"
    return verify_session_admission(unsigned)

def verify_session_admission(admission: dict[str, Any]) -> dict[str, Any]:
    required = {
        "protocol",
        "admission_id",
        "agent",
        "session_id",
        "host_id",
        "capability_class",
        "production_authority",
        "declared_at",
        "task_id",
    }
    candidate = _exact_object(
        admission,
        label="session admission",
        required=required,
        optional={"expires_at"},
    )
    _require(
        candidate["protocol"] == ADMISSION_PROTOCOL,
        "session admission protocol is invalid",
    )
    _require(
        isinstance(candidate["admission_id"], str)
        and _ADMISSION_ID_RE.fullmatch(candidate["admission_id"]) is not None,
        "admission_id is invalid",
    )
    agent = verify_agent_identity(candidate["agent"])
    _require(
        isinstance(candidate["session_id"], str)
        and _INSTANCE_RE.fullmatch(candidate["session_id"]) is not None,
        "session_id is invalid",
    )
    _require(
        candidate["session_id"] == agent["instance_id"],
        "session_id does not match agent.instance_id",
    )
    _require(
        isinstance(candidate["host_id"], str)
        and _HOST_RE.fullmatch(candidate["host_id"]) is not None,
        "host_id is invalid",
    )
    _require(
        isinstance(candidate["task_id"], str)
        and _INSTANCE_RE.fullmatch(candidate["task_id"]) is not None,
        "task_id is invalid",
    )
    candidate["capability_class"] = _validate_capability_classes(
        candidate["capability_class"]
    )
    _require(
        candidate["production_authority"] is False,
        "session admission cannot grant production authority",
    )
    _require(
        isinstance(candidate["declared_at"], str),
        "declared_at must be a string",
    )
    if "expires_at" in candidate:
        _require(
            isinstance(candidate["expires_at"], str),
            "expires_at must be a string",
        )
    try:
        admission_clock_valid_until(
            declared_at=candidate["declared_at"],
            expires_at=candidate.get("expires_at") or "",
        )
    except AdmissionClockError as exc:
        raise SessionAdmissionError(str(exc)) from exc
    unsigned = deepcopy(candidate)
    actual = unsigned["admission_id"]
    unsigned["admission_id"] = "admission:pending"
    expected = "admission:" + digest_object(
        unsigned,
        domain="agent-session-admission-v1",
    ).split(":", 1)[1]
    _require(
        actual == expected,
        "admission_id does not match the admission digest",
    )
    return candidate

def action_log_event_from_admission(admission: dict[str, Any]) -> dict[str, Any]:
    verified = verify_session_admission(admission)
    agent = verified["agent"]
    return {
        "actor": agent["product"],
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
        "tags": [
            "integrity",
            "admission",
            agent["product"],
            agent["vendor"],
        ],
    }


def verify_action_log_admission_event(event: dict[str, Any]) -> dict[str, Any]:
    _require(isinstance(event, dict), "admission event must be an object")
    _require(
        event.get("action") == "agent_session_admission",
        "admission event action is invalid",
    )
    details = event.get("details")
    _require(isinstance(details, dict), "admission event details are invalid")
    _require(details.get("result") == "admitted", "admission event result is invalid")
    _require(
        details.get("truth_status") == "observed",
        "admission event truth status is invalid",
    )
    _require(
        details.get("production_authority") is False,
        "admission event cannot grant production authority",
    )
    _require(details.get("mutation") is False, "admission event cannot be a mutation")
    expires_at = details.get("expires_at")
    admission: dict[str, Any] = {
        "protocol": ADMISSION_PROTOCOL,
        "admission_id": details.get("admission_id"),
        "agent": details.get("agent"),
        "session_id": event.get("session_id"),
        "host_id": details.get("host_id"),
        "capability_class": details.get("capability_class"),
        "production_authority": details.get("production_authority"),
        "declared_at": details.get("declared_at"),
        "task_id": details.get("task_id"),
    }
    if expires_at:
        admission["expires_at"] = expires_at
    verified = verify_session_admission(admission)
    _require(
        event.get("session_id") == verified["session_id"],
        "admission event session_id is invalid",
    )
    actor = str(event.get("actor") or "")
    _require(
        not actor or actor == verified["agent"]["product"],
        "admission event actor does not match the agent product",
    )
    return verified


def speaker_from_admission(admission: dict[str, Any]) -> dict[str, Any]:
    verified = verify_session_admission(admission)
    agent = verified["agent"]
    return {
        "agent_id": agent["agent_id"],
        "kind": agent["kind"],
        "vendor": agent["vendor"],
        "product": agent["product"],
        "runtime": agent["runtime"],
        "instance_id": agent["instance_id"],
        "admission_id": verified["admission_id"],
        "declared_at": verified["declared_at"],
        "expires_at": str(verified.get("expires_at") or ""),
        "capability_class": list(verified["capability_class"]),
    }
