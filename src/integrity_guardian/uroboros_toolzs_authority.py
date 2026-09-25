"""Signed one-transition decisions and consumptions for Uroboros Toolzs.

The pure protocol binds one exact a12 request to an authority decision and,
for an approval, one ledger-scoped grant.  A separate local ledger records the
decision at request source sequence zero and the sole consumption at sequence
one.  This module signs and verifies the closed receipts; it never invokes a
Toolz or performs an external effect.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any

from jsonschema import ValidationError

from .canonical import canonical_bytes, parse_json_strict
from .hashing import digest_object
from .schemas import validate
from .signing import (
    Ed25519Signer,
    TrustedKey,
    public_key_fingerprint,
    verify_signature,
)
from .uroboros_toolzs import ToolzCyberEvidence, ToolzFogRouteEvidence
from .uroboros_toolzs_authorization_request import (
    ToolzAuthorizationRequestPolicy,
    toolz_authorization_request_digest,
    toolz_authorization_request_policy_digest,
    verify_toolz_authorization_request,
)
from .uroboros_toolzs_store import ToolzRouteMemoryStore, ToolzStoreCursor

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")

_DECISION_AUTHORITY_BOUNDARY_BASE = {
    "authority_ledger_append_required": True,
    "authorization_decided": True,
    "consumption_recorded": False,
    "execution_performed": False,
    "external_effect_performed": False,
    "ledger_proof_required": True,
    "network": False,
    "production_authority": False,
    "request_transport_performed": False,
    "route_memory_store_write": False,
    "tool_invocation": False,
}
_CONSUMPTION_AUTHORITY_BOUNDARY = {
    "authorization_decided": True,
    "authorization_granted": True,
    "consumption_recorded": False,
    "execution_performed": False,
    "external_effect_performed": False,
    "grant_consumption_requested": True,
    "ledger_proof_required": True,
    "network": False,
    "next_stage_must_contain_execution": True,
    "production_authority": False,
    "request_transport_performed": False,
    "route_memory_store_write": False,
    "tool_invocation": False,
}


class ToolzAuthorityError(RuntimeError):
    """Raised before ambiguous authority or replay state can be accepted."""


class ToolzAuthorityDecisionOutcome(StrEnum):
    """Closed owner/policy outcomes for one exact request."""

    APPROVED = "approved"
    DENIED = "denied"


class ToolzAuthorityDecisionReason(StrEnum):
    """Privacy-safe decision reasons; no free text crosses the boundary."""

    OWNER_APPROVED = "owner-approved"
    OWNER_DENIED = "owner-denied"
    POLICY_DENIED = "policy-denied"


class ToolzGrantConsumptionStatus(StrEnum):
    """A candidate that is authoritative only with its ledger proof."""

    PENDING_LEDGER_RECORD = "pending-ledger-record"


@dataclass(frozen=True)
class ToolzAuthorizationEvidence:
    """Complete a12 evidence needed to re-prove one request."""

    request: Mapping[str, Any]
    request_policy: ToolzAuthorizationRequestPolicy
    readiness_receipt: Mapping[str, Any]
    witness: Mapping[str, Any]
    witness_observer_key: TrustedKey
    feedback_receipt: Mapping[str, Any]
    theoretical_memory: Mapping[str, Any]
    trace: Mapping[str, Any]
    trace_observer_key: TrustedKey
    fog_evidence: ToolzFogRouteEvidence
    cyber_evidence: ToolzCyberEvidence
    observed_memory: Mapping[str, Any]
    memory_key: TrustedKey
    feedback_key: TrustedKey
    store: ToolzRouteMemoryStore
    expected_cursor: ToolzStoreCursor
    store_key: TrustedKey
    readiness_key: TrustedKey
    requester_key: TrustedKey


@dataclass(frozen=True)
class ToolzAuthorityPolicy:
    """Exact request, decision authority and anti-replay-ledger contract."""

    policy_id: str
    request_policy: ToolzAuthorizationRequestPolicy
    ledger_id: str
    ledger_authority_id: str
    ledger_authority_artifact_digest: str
    max_decision_signing_delay_seconds: int = 5
    max_grant_seconds: int = 10

    def __post_init__(self) -> None:
        _require_id(self.policy_id, "policy id", synthetic=True)
        if not isinstance(self.request_policy, ToolzAuthorizationRequestPolicy):
            raise ToolzAuthorityError("Toolzs authority request policy rejected")
        _require_id(self.ledger_id, "ledger id", synthetic=True)
        _require_id(
            self.ledger_authority_id,
            "ledger authority id",
            synthetic=True,
        )
        _require_digest(
            self.ledger_authority_artifact_digest,
            "ledger authority artifact",
        )
        for field, value, maximum in (
            (
                "decision signing delay",
                self.max_decision_signing_delay_seconds,
                10,
            ),
            ("grant validity", self.max_grant_seconds, 30),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= maximum:
                raise ToolzAuthorityError(f"Toolzs authority {field} rejected")


@dataclass(frozen=True)
class ToolzAuthorityDecision:
    """One verified signed decision; ledger evidence remains mandatory."""

    decision: dict[str, Any]
    outcome: ToolzAuthorityDecisionOutcome

    @property
    def authorization_granted(self) -> bool:
        return self.outcome is ToolzAuthorityDecisionOutcome.APPROVED

    @property
    def execution_performed(self) -> bool:
        return False


@dataclass(frozen=True)
class ToolzGrantConsumption:
    """One verified ledger-level consumption with no external effect."""

    consumption: dict[str, Any]
    status: ToolzGrantConsumptionStatus

    @property
    def execution_performed(self) -> bool:
        return False

    @property
    def external_effect_performed(self) -> bool:
        return False


def _require_id(value: object, field: str, *, synthetic: bool = False) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise ToolzAuthorityError(f"Toolzs authority {field} rejected")
    if synthetic and "synthetic" not in value:
        raise ToolzAuthorityError(f"Toolzs authority {field} rejected")
    return value


def _require_digest(value: object, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ToolzAuthorityError(f"Toolzs authority {field} rejected")
    return value


def _parse_time(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise ToolzAuthorityError(f"Toolzs authority {field} rejected")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ToolzAuthorityError(f"Toolzs authority {field} rejected") from exc
    if parsed.tzinfo is None:
        raise ToolzAuthorityError(f"Toolzs authority {field} rejected")
    return parsed


def _format_time(value: datetime) -> str:
    rendered = value.isoformat()
    if rendered.endswith("+00:00"):
        return f"{rendered[:-6]}Z"
    return rendered


def _freeze_mapping(value: Mapping[str, Any], field: str) -> dict[str, Any]:
    try:
        candidate = parse_json_strict(canonical_bytes(dict(value)))
    except Exception as exc:
        raise ToolzAuthorityError(f"Toolzs authority {field} rejected") from exc
    if not isinstance(candidate, dict):
        raise ToolzAuthorityError(f"Toolzs authority {field} rejected")
    return candidate


def _assert_signer(
    signer: Ed25519Signer,
    trusted_key: TrustedKey,
    field: str,
) -> None:
    if (
        not isinstance(signer, Ed25519Signer)
        or not isinstance(trusted_key, TrustedKey)
        or signer.key_id != trusted_key.key_id
        or public_key_fingerprint(signer.public_key)
        != public_key_fingerprint(trusted_key.public_key)
    ):
        raise ToolzAuthorityError(f"Toolzs authority {field} signer rejected")


def _policy_document(policy: ToolzAuthorityPolicy) -> dict[str, Any]:
    return {
        "policy_id": policy.policy_id,
        "request_policy_digest": toolz_authorization_request_policy_digest(policy.request_policy),
        "decision_authority": {
            "authority_id": policy.request_policy.decision_authority_id,
            "authority_artifact_digest": (policy.request_policy.decision_authority_artifact_digest),
        },
        "ledger": {
            "ledger_id": policy.ledger_id,
            "authority_id": policy.ledger_authority_id,
            "authority_artifact_digest": policy.ledger_authority_artifact_digest,
        },
        "max_decision_signing_delay_seconds": (policy.max_decision_signing_delay_seconds),
        "max_grant_seconds": policy.max_grant_seconds,
        "sequence_semantics": "request-source-decision-0-consumption-1-no-2",
        "external_effect_semantics": "not-performed-by-a13",
    }


def toolz_authority_policy_digest(policy: ToolzAuthorityPolicy) -> str:
    """Return the exact a13 authority-policy identity."""

    if not isinstance(policy, ToolzAuthorityPolicy):
        raise ToolzAuthorityError("Toolzs authority policy rejected")
    return digest_object(
        _policy_document(policy),
        domain="toolz-authority-policy-v1",
    )


def _verify_request(
    evidence: ToolzAuthorizationEvidence,
    *,
    used_at: str,
) -> dict[str, Any]:
    if not isinstance(evidence, ToolzAuthorizationEvidence):
        raise ToolzAuthorityError("Toolzs authority evidence rejected")
    try:
        request = verify_toolz_authorization_request(
            evidence.request,
            expected_policy=evidence.request_policy,
            readiness_receipt=evidence.readiness_receipt,
            witness=evidence.witness,
            witness_observer_key=evidence.witness_observer_key,
            feedback_receipt=evidence.feedback_receipt,
            theoretical_memory=evidence.theoretical_memory,
            trace=evidence.trace,
            trace_observer_key=evidence.trace_observer_key,
            fog_evidence=evidence.fog_evidence,
            cyber_evidence=evidence.cyber_evidence,
            observed_memory=evidence.observed_memory,
            memory_key=evidence.memory_key,
            feedback_key=evidence.feedback_key,
            store=evidence.store,
            expected_cursor=evidence.expected_cursor,
            store_key=evidence.store_key,
            readiness_key=evidence.readiness_key,
            requester_key=evidence.requester_key,
            used_at=used_at,
        )
    except Exception as exc:
        raise ToolzAuthorityError("Toolzs authority request proof rejected") from exc
    return request


def _grant_identity(
    *,
    policy: ToolzAuthorityPolicy,
    request: Mapping[str, Any],
    decision_authority: Mapping[str, Any],
    decided_at: str,
    expires_at: str,
) -> str:
    digest = digest_object(
        {
            "policy_digest": toolz_authority_policy_digest(policy),
            "request_id": request["request_id"],
            "request_digest": toolz_authorization_request_digest(request),
            "decision_authority": dict(decision_authority),
            "ledger_id": policy.ledger_id,
            "decided_at": decided_at,
            "expires_at": expires_at,
            "scope": {
                "requested_capability": "single-toolz-transition",
                "max_transitions": 1,
                "single_use": True,
                "consumption_required": True,
            },
        },
        domain="toolz-single-use-grant-identity-v1",
    )
    return f"toolz-single-use-grant:{digest.split(':', 1)[1]}"


def _decision_core(decision: Mapping[str, Any]) -> dict[str, Any]:
    core = deepcopy(dict(decision))
    core.pop("decision_id", None)
    core.pop("signature", None)
    return core


def toolz_authority_decision_identity(
    decision: Mapping[str, Any],
) -> str:
    """Return the domain-separated identity of an unsigned decision."""

    digest = digest_object(
        _decision_core(decision),
        domain="toolz-authority-decision-identity-v1",
    )
    return f"toolz-authority-decision:{digest.split(':', 1)[1]}"


def toolz_authority_decision_digest(
    decision: Mapping[str, Any],
) -> str:
    """Return the exact signed decision digest."""

    return digest_object(
        dict(decision),
        domain="toolz-authority-signed-decision-v1",
    )


def _decision_boundary(
    outcome: ToolzAuthorityDecisionOutcome,
) -> dict[str, bool]:
    return {
        **_DECISION_AUTHORITY_BOUNDARY_BASE,
        "authorization_granted": (outcome is ToolzAuthorityDecisionOutcome.APPROVED),
        "single_use_grant_issued": (outcome is ToolzAuthorityDecisionOutcome.APPROVED),
    }


def _decision_expected_core(
    *,
    policy: ToolzAuthorityPolicy,
    request: Mapping[str, Any],
    outcome: ToolzAuthorityDecisionOutcome,
    reason: ToolzAuthorityDecisionReason,
    decision_key: TrustedKey,
    decided_at: str,
    created_at: str,
    expires_at: str,
) -> dict[str, Any]:
    authority = {
        "authority_id": policy.request_policy.decision_authority_id,
        "authority_artifact_digest": (policy.request_policy.decision_authority_artifact_digest),
        "key_id": decision_key.key_id,
        "key_fingerprint": public_key_fingerprint(decision_key.public_key),
    }
    grant: dict[str, Any] | None = None
    if outcome is ToolzAuthorityDecisionOutcome.APPROVED:
        grant = {
            "grant_id": _grant_identity(
                policy=policy,
                request=request,
                decision_authority=authority,
                decided_at=decided_at,
                expires_at=expires_at,
            ),
            "status": "issued",
            "requested_capability": "single-toolz-transition",
            "max_transitions": 1,
            "single_use": True,
            "consumption_required": True,
            "expires_at": expires_at,
        }
    return {
        "protocol": "integrity-guardian/toolz-authority-decision/v1",
        "tenant_id": request["tenant_id"],
        "policy_id": policy.policy_id,
        "policy_digest": toolz_authority_policy_digest(policy),
        "request": {
            "request_id": request["request_id"],
            "request_digest": toolz_authorization_request_digest(request),
            "policy_digest": request["policy_digest"],
            "expires_at": request["timing"]["expires_at"],
        },
        "authority": authority,
        "ledger_binding": {
            "ledger_id": policy.ledger_id,
            "authority_id": policy.ledger_authority_id,
            "authority_artifact_digest": (policy.ledger_authority_artifact_digest),
        },
        "outcome": outcome.value,
        "reason_code": reason.value,
        "grant": grant,
        "timing": {
            "decided_at": decided_at,
            "created_at": created_at,
            "expires_at": expires_at,
        },
        "authority_boundary": _decision_boundary(outcome),
    }


def _decision_times(
    *,
    policy: ToolzAuthorityPolicy,
    request: Mapping[str, Any],
    outcome: ToolzAuthorityDecisionOutcome,
    decided_at: str,
    created_at: str,
    used_at: str,
) -> str:
    request_created = _parse_time(
        request["timing"]["created_at"],
        "request creation time",
    )
    request_expires = _parse_time(
        request["timing"]["expires_at"],
        "request expiry",
    )
    decided = _parse_time(decided_at, "decision time")
    created = _parse_time(created_at, "decision creation time")
    used = _parse_time(used_at, "decision use time")
    expires = (
        min(
            decided + timedelta(seconds=policy.max_grant_seconds),
            request_expires,
        )
        if outcome is ToolzAuthorityDecisionOutcome.APPROVED
        else request_expires
    )
    if not (request_created <= decided <= created <= used < expires):
        raise ToolzAuthorityError("Toolzs authority decision timing rejected")
    if (created - decided).total_seconds() > policy.max_decision_signing_delay_seconds:
        raise ToolzAuthorityError("Toolzs authority decision signing delay rejected")
    return _format_time(expires)


def _normalize_outcome(
    value: ToolzAuthorityDecisionOutcome | str,
) -> ToolzAuthorityDecisionOutcome:
    try:
        return ToolzAuthorityDecisionOutcome(value)
    except (TypeError, ValueError) as exc:
        raise ToolzAuthorityError("Toolzs authority decision outcome rejected") from exc


def _normalize_reason(
    value: ToolzAuthorityDecisionReason | str,
    *,
    outcome: ToolzAuthorityDecisionOutcome,
) -> ToolzAuthorityDecisionReason:
    try:
        reason = ToolzAuthorityDecisionReason(value)
    except (TypeError, ValueError) as exc:
        raise ToolzAuthorityError("Toolzs authority decision reason rejected") from exc
    if (
        outcome is ToolzAuthorityDecisionOutcome.APPROVED
        and reason is not ToolzAuthorityDecisionReason.OWNER_APPROVED
    ) or (
        outcome is ToolzAuthorityDecisionOutcome.DENIED
        and reason is ToolzAuthorityDecisionReason.OWNER_APPROVED
    ):
        raise ToolzAuthorityError("Toolzs authority decision reason rejected")
    return reason


def build_toolz_authority_decision(
    *,
    policy: ToolzAuthorityPolicy,
    evidence: ToolzAuthorizationEvidence,
    outcome: ToolzAuthorityDecisionOutcome | str,
    reason: ToolzAuthorityDecisionReason | str,
    decided_at: str,
    created_at: str,
    decision_key: TrustedKey,
    decision_signer: Ed25519Signer,
) -> ToolzAuthorityDecision:
    """Sign one exact decision without recording or consuming it."""

    if not isinstance(policy, ToolzAuthorityPolicy):
        raise ToolzAuthorityError("Toolzs authority policy rejected")
    if evidence.request_policy != policy.request_policy:
        raise ToolzAuthorityError("Toolzs authority request policy mismatch")
    _assert_signer(decision_signer, decision_key, "decision")
    normalized_outcome = _normalize_outcome(outcome)
    normalized_reason = _normalize_reason(
        reason,
        outcome=normalized_outcome,
    )
    request = _verify_request(evidence, used_at=decided_at)
    if request["decision_authority"] != {
        "authority_id": policy.request_policy.decision_authority_id,
        "authority_artifact_digest": (policy.request_policy.decision_authority_artifact_digest),
    }:
        raise ToolzAuthorityError("Toolzs authority decision authority mismatch")
    expires_at = _decision_times(
        policy=policy,
        request=request,
        outcome=normalized_outcome,
        decided_at=decided_at,
        created_at=created_at,
        used_at=created_at,
    )
    core = _decision_expected_core(
        policy=policy,
        request=request,
        outcome=normalized_outcome,
        reason=normalized_reason,
        decision_key=decision_key,
        decided_at=decided_at,
        created_at=created_at,
        expires_at=expires_at,
    )
    unsigned = {
        "decision_id": toolz_authority_decision_identity(core),
        **core,
    }
    signed = decision_signer.sign(unsigned)
    decision = verify_toolz_authority_decision(
        signed,
        policy=policy,
        evidence=evidence,
        decision_key=decision_key,
        used_at=created_at,
    )
    return ToolzAuthorityDecision(
        decision=decision,
        outcome=normalized_outcome,
    )


def verify_toolz_authority_decision(
    decision: Mapping[str, Any],
    *,
    policy: ToolzAuthorityPolicy,
    evidence: ToolzAuthorizationEvidence,
    decision_key: TrustedKey,
    used_at: str,
) -> dict[str, Any]:
    """Verify the complete a12 request and exact signed a13 decision."""

    if not isinstance(policy, ToolzAuthorityPolicy):
        raise ToolzAuthorityError("Toolzs authority policy rejected")
    if evidence.request_policy != policy.request_policy:
        raise ToolzAuthorityError("Toolzs authority request policy mismatch")
    if not isinstance(decision_key, TrustedKey):
        raise ToolzAuthorityError("Toolzs authority decision key rejected")
    try:
        candidate = _freeze_mapping(decision, "decision")
        validate("toolz-authority-decision", candidate)
    except (ValidationError, KeyError, TypeError) as exc:
        raise ToolzAuthorityError("Toolzs authority decision schema rejected") from exc
    if candidate["decision_id"] != toolz_authority_decision_identity(candidate):
        raise ToolzAuthorityError("Toolzs authority decision identity mismatch")
    if (
        candidate["signature"]["key_id"] != decision_key.key_id
        or candidate["authority"]["key_id"] != decision_key.key_id
        or candidate["authority"]["key_fingerprint"]
        != public_key_fingerprint(decision_key.public_key)
        or not verify_signature(candidate, decision_key.public_key)
    ):
        raise ToolzAuthorityError("Toolzs authority decision signature rejected")
    request = _verify_request(evidence, used_at=candidate["timing"]["decided_at"])
    outcome = _normalize_outcome(candidate["outcome"])
    reason = _normalize_reason(candidate["reason_code"], outcome=outcome)
    expires_at = _decision_times(
        policy=policy,
        request=request,
        outcome=outcome,
        decided_at=candidate["timing"]["decided_at"],
        created_at=candidate["timing"]["created_at"],
        used_at=used_at,
    )
    expected = _decision_expected_core(
        policy=policy,
        request=request,
        outcome=outcome,
        reason=reason,
        decision_key=decision_key,
        decided_at=candidate["timing"]["decided_at"],
        created_at=candidate["timing"]["created_at"],
        expires_at=expires_at,
    )
    if _decision_core(candidate) != expected:
        raise ToolzAuthorityError("Toolzs authority decision recomputation mismatch")
    return candidate


def _consumption_core(consumption: Mapping[str, Any]) -> dict[str, Any]:
    core = deepcopy(dict(consumption))
    core.pop("consumption_id", None)
    core.pop("signature", None)
    return core


def toolz_grant_consumption_identity(
    consumption: Mapping[str, Any],
) -> str:
    """Return the domain-separated identity of one unsigned consumption."""

    digest = digest_object(
        _consumption_core(consumption),
        domain="toolz-grant-consumption-identity-v1",
    )
    return f"toolz-grant-consumption:{digest.split(':', 1)[1]}"


def toolz_grant_consumption_digest(
    consumption: Mapping[str, Any],
) -> str:
    """Return the exact signed consumption digest."""

    return digest_object(
        dict(consumption),
        domain="toolz-grant-signed-consumption-v1",
    )


def _consumption_expected_core(
    *,
    policy: ToolzAuthorityPolicy,
    request: Mapping[str, Any],
    decision: Mapping[str, Any],
    ledger_key: TrustedKey,
    consumed_at: str,
) -> dict[str, Any]:
    return {
        "protocol": "integrity-guardian/toolz-grant-consumption/v1",
        "tenant_id": request["tenant_id"],
        "policy_id": policy.policy_id,
        "policy_digest": toolz_authority_policy_digest(policy),
        "ledger": {
            "ledger_id": policy.ledger_id,
            "authority_id": policy.ledger_authority_id,
            "authority_artifact_digest": (policy.ledger_authority_artifact_digest),
            "key_id": ledger_key.key_id,
            "key_fingerprint": public_key_fingerprint(ledger_key.public_key),
        },
        "request": {
            "request_id": request["request_id"],
            "request_digest": toolz_authorization_request_digest(request),
        },
        "decision": {
            "decision_id": decision["decision_id"],
            "decision_digest": toolz_authority_decision_digest(decision),
        },
        "grant_id": decision["grant"]["grant_id"],
        "status": ToolzGrantConsumptionStatus.PENDING_LEDGER_RECORD.value,
        "sequence": {
            "decision_source_sequence": 0,
            "consumption_source_sequence": 1,
            "further_source_events_allowed": False,
        },
        "consumed_at": consumed_at,
        "authority_boundary": deepcopy(_CONSUMPTION_AUTHORITY_BOUNDARY),
    }


def build_toolz_grant_consumption(
    *,
    policy: ToolzAuthorityPolicy,
    evidence: ToolzAuthorizationEvidence,
    decision: Mapping[str, Any],
    decision_key: TrustedKey,
    consumed_at: str,
    ledger_key: TrustedKey,
    ledger_signer: Ed25519Signer,
) -> ToolzGrantConsumption:
    """Sign the sole ledger-level consumption without performing the action."""

    _assert_signer(ledger_signer, ledger_key, "ledger")
    verified_decision = verify_toolz_authority_decision(
        decision,
        policy=policy,
        evidence=evidence,
        decision_key=decision_key,
        used_at=consumed_at,
    )
    if (
        verified_decision["outcome"] != ToolzAuthorityDecisionOutcome.APPROVED.value
        or verified_decision["grant"] is None
    ):
        raise ToolzAuthorityError("Toolzs authority denied grant cannot be consumed")
    request = _verify_request(evidence, used_at=consumed_at)
    core = _consumption_expected_core(
        policy=policy,
        request=request,
        decision=verified_decision,
        ledger_key=ledger_key,
        consumed_at=consumed_at,
    )
    unsigned = {
        "consumption_id": toolz_grant_consumption_identity(core),
        **core,
    }
    signed = ledger_signer.sign(unsigned)
    consumption = verify_toolz_grant_consumption(
        signed,
        policy=policy,
        evidence=evidence,
        decision=verified_decision,
        decision_key=decision_key,
        ledger_key=ledger_key,
        used_at=consumed_at,
    )
    return ToolzGrantConsumption(
        consumption=consumption,
        status=ToolzGrantConsumptionStatus.PENDING_LEDGER_RECORD,
    )


def verify_toolz_grant_consumption(
    consumption: Mapping[str, Any],
    *,
    policy: ToolzAuthorityPolicy,
    evidence: ToolzAuthorizationEvidence,
    decision: Mapping[str, Any],
    decision_key: TrustedKey,
    ledger_key: TrustedKey,
    used_at: str,
) -> dict[str, Any]:
    """Verify one exact signed consumption; ledger inclusion is still required."""

    if not isinstance(ledger_key, TrustedKey):
        raise ToolzAuthorityError("Toolzs authority ledger key rejected")
    try:
        candidate = _freeze_mapping(consumption, "consumption")
        validate("toolz-grant-consumption", candidate)
    except (ValidationError, KeyError, TypeError) as exc:
        raise ToolzAuthorityError("Toolzs authority consumption schema rejected") from exc
    if candidate["consumption_id"] != toolz_grant_consumption_identity(candidate):
        raise ToolzAuthorityError("Toolzs authority consumption identity mismatch")
    if (
        candidate["signature"]["key_id"] != ledger_key.key_id
        or candidate["ledger"]["key_id"] != ledger_key.key_id
        or candidate["ledger"]["key_fingerprint"] != public_key_fingerprint(ledger_key.public_key)
        or not verify_signature(candidate, ledger_key.public_key)
    ):
        raise ToolzAuthorityError("Toolzs authority consumption signature rejected")
    verified_decision = verify_toolz_authority_decision(
        decision,
        policy=policy,
        evidence=evidence,
        decision_key=decision_key,
        used_at=used_at,
    )
    if (
        verified_decision["outcome"] != ToolzAuthorityDecisionOutcome.APPROVED.value
        or verified_decision["grant"] is None
    ):
        raise ToolzAuthorityError("Toolzs authority denied grant cannot be consumed")
    request = _verify_request(evidence, used_at=used_at)
    consumed = _parse_time(candidate["consumed_at"], "consumption time")
    current = _parse_time(used_at, "consumption use time")
    if consumed > current:
        raise ToolzAuthorityError("Toolzs authority consumption timing rejected")
    expected = _consumption_expected_core(
        policy=policy,
        request=request,
        decision=verified_decision,
        ledger_key=ledger_key,
        consumed_at=candidate["consumed_at"],
    )
    if _consumption_core(candidate) != expected:
        raise ToolzAuthorityError("Toolzs authority consumption recomputation mismatch")
    return candidate
