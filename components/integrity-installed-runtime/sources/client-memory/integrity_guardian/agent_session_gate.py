"""Default-deny session gate for Integrity-mediated tools.

Identity names a speaker. This module decides whether that speaker may use a
tool. Loopback is not a principal. Admission is not mutation authority.
"""

from __future__ import annotations

import datetime as dt
import hmac
from copy import deepcopy
from typing import Any, Literal

from .admission_clock import (
    ADMISSION_TTL_HOURS,
    AdmissionClockError,
)
from .admission_clock import (
    admission_clock_valid_until as _clock_valid_until,
)
from .admission_clock import (
    admission_is_live as _clock_is_live,
)
from .admission_clock import (
    parse_rfc3339 as _clock_parse,
)
from .agent_identity import (
    CAPABILITY_CLASSES,
    _slug,
    verify_agent_identity,
    verify_session_admission,
)
from .hashing import FRAME_SEPARATOR, digest_object, sha256_digest
from .schemas import validate

PROTOCOL = "integrity-guardian/agent-session-gate/v1"
READER_PROTOCOL = "integrity-guardian/seed-reader-principal/v1"
AGENT_SESSION_GATE_PROTOCOL = PROTOCOL
SEED_READER_PRINCIPAL_PROTOCOL = READER_PROTOCOL
DEFAULT_ADMISSION_HOURS = ADMISSION_TTL_HOURS

Decision = Literal["allow", "deny"]
Reason = Literal[
    "allowed",
    "session-missing",
    "session-expired",
    "session-scope-mismatch",
    "principal-missing",
    "principal-mismatch",
    "capability-missing",
    "conflicting-identity",
    "policy-bypass",
]
ReconcileResult = Literal["idempotent", "renewed", "different-session"]

TOOL_CAPABILITIES: dict[str, str] = {
    "seed.read": "read-memory",
    "seed.append": "append-memory",
    "seed.mind": "read-memory",
    "integrity.mcp": "read-memory",
    "adapter.observe": "adapter-observe",
    "adapter.mutate": "adapter-mutate",
}
HOST_WRAPPER_TOOLS = frozenset({"host.shell", "host.ssh", "host.gh", "editor.apply"})
KNOWN_TOOLS = frozenset(TOOL_CAPABILITIES) | HOST_WRAPPER_TOOLS
MEDIATED_TOOLS = frozenset(TOOL_CAPABILITIES)


class AgentSessionGateError(ValueError):
    """Raised before an invalid gate input can become an allow."""


def _schema_token(value: str, *, fallback: str) -> str:
    cleaned = []
    for char in str(value or "").strip().lower():
        if char.isalnum() or char in ".-":
            cleaned.append(char)
        elif char in "_:/":
            cleaned.append("-")
    token = "".join(cleaned).strip("-.")[:64]
    if not token or not token[0].isalnum():
        return fallback
    return token


def _schema_path(value: str) -> str:
    cleaned = []
    for char in str(value or "").strip().lower():
        if char.isalnum() or char in "._:/-":
            cleaned.append(char)
        elif char in " ":
            cleaned.append("-")
    path = "".join(cleaned).strip("./")[:128]
    return path if path and path[0].isalnum() else "wrapper"


def _parse_time(value: str, *, field: str) -> dt.datetime:
    try:
        return _clock_parse(value, field=field)
    except AdmissionClockError as exc:
        raise AgentSessionGateError(str(exc)) from exc

def token_fingerprint(token: str) -> str:
    secret = str(token or "")
    if not secret:
        raise AgentSessionGateError("reader token is empty")
    # The fixed prefix uses the frozen guardian-json-v1 frame (ASCII ``\\x00``);
    # the secret is the final field, so the encoding stays unambiguous.
    frame = FRAME_SEPARATOR
    return sha256_digest(f"integrity-guardian{frame}seed-reader-token{frame}{secret}".encode())


def bind_reader_principal(*, vendor: str, product: str, token: str) -> dict[str, Any]:
    """Name one Seed reader. The raw token never enters the principal object."""

    unsigned: dict[str, Any] = {
        "protocol": READER_PROTOCOL,
        "principal_id": "reader:pending",
        "kind": "reader",
        "vendor": _slug(vendor, field="vendor"),
        "product": _slug(product, field="product"),
        "token_fingerprint": token_fingerprint(token),
        "production_authority": False,
    }
    digest = digest_object(unsigned, domain="seed-reader-principal-v1").split(":", 1)[1]
    unsigned["principal_id"] = f"reader:{digest}"
    validate("seed-reader-principal", unsigned)
    return unsigned


def verify_reader_principal(principal: dict[str, Any]) -> dict[str, Any]:
    candidate = deepcopy(principal)
    validate("seed-reader-principal", candidate)
    if candidate["production_authority"] is not False:
        raise AgentSessionGateError("reader principal cannot grant production authority")
    unsigned = deepcopy(candidate)
    actual = unsigned["principal_id"]
    unsigned["principal_id"] = "reader:pending"
    digest = digest_object(unsigned, domain="seed-reader-principal-v1").split(":", 1)[1]
    expected = "reader:" + digest
    if actual != expected:
        raise AgentSessionGateError("principal_id does not match the reader digest")
    return candidate


def identify_reader(
    presented_token: str,
    *,
    secrets: list[dict[str, str]],
) -> dict[str, Any] | None:
    """Match one presented secret to at most one named reader.

    Two products that share a secret match nobody. That is how a second local
    agent is kept from inheriting the Codex reader.
    """

    token = str(presented_token or "")
    if not token:
        return None
    matched: list[dict[str, Any]] = []
    for entry in secrets:
        secret = str(entry.get("token") or "")
        if not secret or not hmac.compare_digest(token, secret):
            continue
        matched.append(
            bind_reader_principal(
                vendor=str(entry.get("vendor") or ""),
                product=str(entry.get("product") or ""),
                token=secret,
            )
        )
    if len(matched) != 1:
        return None
    return matched[0]


def admission_clock_valid_until(*, declared_at: str, expires_at: str = "") -> dt.datetime:
    """Closed five-hour owner clock shared by identity, broker and capsule."""

    try:
        return _clock_valid_until(
            declared_at=declared_at,
            expires_at=expires_at,
        )
    except AdmissionClockError as exc:
        raise AgentSessionGateError(str(exc)) from exc

def admission_is_live(*, now: str, declared_at: str = "", expires_at: str = "") -> bool:
    try:
        return _clock_is_live(
            now=now,
            declared_at=declared_at,
            expires_at=expires_at,
        )
    except AdmissionClockError as exc:
        raise AgentSessionGateError(str(exc)) from exc

def admission_valid_until(admission: dict[str, Any]) -> dt.datetime:
    verified = verify_session_admission(admission)
    return admission_clock_valid_until(
        declared_at=str(verified["declared_at"]),
        expires_at=str(verified.get("expires_at") or ""),
    )


def reconcile_session_admission(
    existing: dict[str, Any], candidate: dict[str, Any]
) -> ReconcileResult:
    """Same session + same agent is idempotent or a renewal. A new speaker is not."""

    left = verify_session_admission(existing)
    right = verify_session_admission(candidate)
    if left["session_id"] != right["session_id"]:
        return "different-session"
    if left["agent"]["agent_id"] != right["agent"]["agent_id"]:
        raise AgentSessionGateError("conflicting-identity")
    if left["admission_id"] == right["admission_id"]:
        return "idempotent"
    return "renewed"


def _deny(
    *,
    reason: Reason,
    tool: str,
    surface: str,
    evaluated_at: str,
    agent_id: str = "",
    principal_id: str = "",
    admission_id: str = "",
) -> dict[str, Any]:
    decision = {
        "protocol": PROTOCOL,
        "decision": "deny",
        "reason": reason,
        "tool": tool,
        "surface": surface,
        "agent_id": agent_id,
        "principal_id": principal_id,
        "admission_id": admission_id,
        "production_authority": False,
        "evaluated_at": evaluated_at,
    }
    validate("agent-session-gate", decision)
    return decision


def _allow(
    *,
    tool: str,
    surface: str,
    evaluated_at: str,
    agent_id: str,
    principal_id: str,
    admission_id: str,
) -> dict[str, Any]:
    decision = {
        "protocol": PROTOCOL,
        "decision": "allow",
        "reason": "allowed",
        "tool": tool,
        "surface": surface,
        "agent_id": agent_id,
        "principal_id": principal_id,
        "admission_id": admission_id,
        "production_authority": False,
        "evaluated_at": evaluated_at,
    }
    validate("agent-session-gate", decision)
    return decision


def evaluate_mediated_tool(
    *,
    tool: str,
    surface: str,
    now: str,
    speaker: dict[str, Any] | None = None,
    admission: dict[str, Any] | None = None,
    principal: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Default deny. Integrity tools need a live admission and a matching reader."""

    tool_name = str(tool or "").strip()
    surface_name = str(surface or "").strip()
    evaluated_at = now
    if not tool_name or not surface_name:
        raise AgentSessionGateError("tool and surface are required")
    if tool_name not in KNOWN_TOOLS:
        return _deny(
            reason="policy-bypass",
            tool=_schema_token(tool_name, fallback="unknown"),
            surface=_schema_path(surface_name),
            evaluated_at=evaluated_at,
        )

    verified_speaker = verify_agent_identity(speaker) if speaker is not None else None
    verified_admission = (
        verify_session_admission(admission) if admission is not None else None
    )
    verified_principal = (
        verify_reader_principal(principal) if principal is not None else None
    )
    agent_id = (verified_speaker or {}).get("agent_id") or (
        (verified_admission or {}).get("agent") or {}
    ).get("agent_id") or ""
    principal_id = (verified_principal or {}).get("principal_id") or ""
    admission_id = (verified_admission or {}).get("admission_id") or ""

    if verified_admission is None:
        return _deny(
            reason="session-missing",
            tool=tool_name,
            surface=surface_name,
            evaluated_at=evaluated_at,
            agent_id=agent_id,
            principal_id=principal_id,
        )

    if verified_speaker is None:
        verified_speaker = verified_admission["agent"]
        agent_id = verified_speaker["agent_id"]
    elif verified_speaker["agent_id"] != verified_admission["agent"]["agent_id"]:
        return _deny(
            reason="conflicting-identity",
            tool=tool_name,
            surface=surface_name,
            evaluated_at=evaluated_at,
            agent_id=verified_speaker["agent_id"],
            principal_id=principal_id,
            admission_id=admission_id,
        )
    if verified_admission["session_id"] != verified_speaker["instance_id"]:
        return _deny(
            reason="session-scope-mismatch",
            tool=tool_name,
            surface=surface_name,
            evaluated_at=evaluated_at,
            agent_id=agent_id,
            principal_id=principal_id,
            admission_id=admission_id,
        )

    if not admission_is_live(
        now=now,
        declared_at=verified_admission["declared_at"],
        expires_at=verified_admission.get("expires_at") or "",
    ):
        return _deny(
            reason="session-expired",
            tool=tool_name,
            surface=surface_name,
            evaluated_at=evaluated_at,
            agent_id=agent_id,
            principal_id=principal_id,
            admission_id=admission_id,
        )

    if tool_name in MEDIATED_TOOLS:
        if verified_principal is None:
            return _deny(
                reason="principal-missing",
                tool=tool_name,
                surface=surface_name,
                evaluated_at=evaluated_at,
                agent_id=agent_id,
                admission_id=admission_id,
            )
        if (
            verified_principal["vendor"] != verified_speaker["vendor"]
            or verified_principal["product"] != verified_speaker["product"]
        ):
            return _deny(
                reason="principal-mismatch",
                tool=tool_name,
                surface=surface_name,
                evaluated_at=evaluated_at,
                agent_id=agent_id,
                principal_id=principal_id,
                admission_id=admission_id,
            )
        needed = TOOL_CAPABILITIES[tool_name]
        if needed not in CAPABILITY_CLASSES:
            raise AgentSessionGateError("capability map is inconsistent")
        if needed not in verified_admission["capability_class"]:
            return _deny(
                reason="capability-missing",
                tool=tool_name,
                surface=surface_name,
                evaluated_at=evaluated_at,
                agent_id=agent_id,
                principal_id=principal_id,
                admission_id=admission_id,
            )

    return _allow(
        tool=tool_name,
        surface=surface_name,
        evaluated_at=evaluated_at,
        agent_id=agent_id,
        principal_id=principal_id,
        admission_id=admission_id,
    )
