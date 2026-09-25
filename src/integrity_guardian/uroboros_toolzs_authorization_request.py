"""Authority-free single-transition request envelopes for Uroboros Toolzs.

The module binds one still-fresh a11 readiness receipt to the exact first
transition of its already verified a7 trace.  It creates a signed request for a
future authority decision; it does not transport that request, make the
decision, grant authority, consume a grant, invoke a Toolz or mutate storage.
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
from .uroboros_toolzs_install import _freeze_mapping
from .uroboros_toolzs_readiness import (
    ToolzReuseReadinessPolicy,
    toolz_reuse_readiness_digest,
    toolz_reuse_readiness_policy_digest,
    verify_toolz_reuse_readiness_receipt,
)
from .uroboros_toolzs_store import ToolzRouteMemoryStore, ToolzStoreCursor
from .uroboros_toolzs_trace import describe_toolz_action_trace_path

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")

_REQUEST_PRIVACY_BOUNDARY = {
    "cookies": False,
    "credentials": False,
    "dom": False,
    "form_values": False,
    "free_text": False,
    "operation_parameters": False,
    "screenshots": False,
    "selectors": False,
    "urls": False,
}
_REQUEST_AUTHORITY_BOUNDARY = {
    "authorization_decided": False,
    "authorization_granted": False,
    "browser_control": False,
    "credentials": False,
    "execution": False,
    "global_publish": False,
    "local_storage_read": True,
    "model_sdk": False,
    "network": False,
    "production_authority": False,
    "raw_ui_data": False,
    "request_created": True,
    "request_transport_performed": False,
    "storage_performed": False,
    "store_write": False,
    "tool_invocation": False,
}


class ToolzAuthorizationRequestError(RuntimeError):
    """Raised before an ambiguous or authority-bearing request is accepted."""


class ToolzAuthorizationRequestStatus(StrEnum):
    """The sole a12 outcome; an authority still has not decided."""

    PENDING_AUTHORITY_DECISION = "pending-authority-decision"


@dataclass(frozen=True)
class ToolzAuthorizationRequestPolicy:
    """Exact readiness, requester, future authority and deadline contract."""

    policy_id: str
    readiness_policy: ToolzReuseReadinessPolicy
    requester_id: str
    requester_artifact_digest: str
    decision_authority_id: str
    decision_authority_artifact_digest: str
    max_request_seconds: int = 15
    max_signing_delay_seconds: int = 5

    def __post_init__(self) -> None:
        _require_id(self.policy_id, "policy id", synthetic=True)
        if not isinstance(self.readiness_policy, ToolzReuseReadinessPolicy):
            raise ToolzAuthorizationRequestError(
                "Toolzs authorization request readiness policy rejected"
            )
        _require_id(self.requester_id, "requester id", synthetic=True)
        _require_digest(
            self.requester_artifact_digest,
            "requester artifact",
        )
        _require_id(
            self.decision_authority_id,
            "decision authority id",
            synthetic=True,
        )
        _require_digest(
            self.decision_authority_artifact_digest,
            "decision authority artifact",
        )
        for field, value, maximum in (
            ("validity", self.max_request_seconds, 60),
            ("signing delay", self.max_signing_delay_seconds, 10),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= maximum:
                raise ToolzAuthorizationRequestError(
                    f"Toolzs authorization request {field} rejected"
                )


@dataclass(frozen=True)
class ToolzAuthorizationRequest:
    """One verified request that still carries no authority."""

    request: dict[str, Any]
    readiness_receipt: dict[str, Any]
    status: ToolzAuthorizationRequestStatus

    @property
    def authorization_granted(self) -> bool:
        return False

    @property
    def execution_authority(self) -> bool:
        return False

    @property
    def transport_performed(self) -> bool:
        return False

    @property
    def storage_performed(self) -> bool:
        return False


@dataclass(frozen=True)
class _VerifiedRequestInputs:
    readiness_receipt: dict[str, Any]
    trace: dict[str, Any]
    first_step: dict[str, Any]
    first_hop: Any


def _require_id(value: object, field: str, *, synthetic: bool = False) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise ToolzAuthorizationRequestError(f"Toolzs authorization request {field} rejected")
    if synthetic and "synthetic" not in value:
        raise ToolzAuthorizationRequestError(f"Toolzs authorization request {field} rejected")
    return value


def _require_digest(value: object, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ToolzAuthorizationRequestError(f"Toolzs authorization request {field} rejected")
    return value


def _parse_time(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise ToolzAuthorizationRequestError(f"Toolzs authorization request {field} rejected")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ToolzAuthorizationRequestError(
            f"Toolzs authorization request {field} rejected"
        ) from exc
    if parsed.tzinfo is None:
        raise ToolzAuthorizationRequestError(f"Toolzs authorization request {field} rejected")
    return parsed


def _format_time(value: datetime) -> str:
    rendered = value.isoformat()
    if rendered.endswith("+00:00"):
        return f"{rendered[:-6]}Z"
    return rendered


def _requester(policy: ToolzAuthorizationRequestPolicy) -> dict[str, str]:
    return {
        "requester_id": policy.requester_id,
        "requester_artifact_digest": policy.requester_artifact_digest,
    }


def _decision_authority(
    policy: ToolzAuthorizationRequestPolicy,
) -> dict[str, str]:
    return {
        "authority_id": policy.decision_authority_id,
        "authority_artifact_digest": (policy.decision_authority_artifact_digest),
    }


def _policy_document(
    policy: ToolzAuthorizationRequestPolicy,
) -> dict[str, Any]:
    return {
        "policy_id": policy.policy_id,
        "readiness_policy_digest": toolz_reuse_readiness_policy_digest(policy.readiness_policy),
        "requester": _requester(policy),
        "decision_authority": _decision_authority(policy),
        "max_request_seconds": policy.max_request_seconds,
        "max_signing_delay_seconds": policy.max_signing_delay_seconds,
        "scope_semantics": ("exact-first-transition-single-use-request-no-route-continuation"),
        "authority_semantics": ("request-is-not-decision-grant-transport-or-execution"),
    }


def toolz_authorization_request_policy_digest(
    policy: ToolzAuthorizationRequestPolicy,
) -> str:
    """Return the exact a12 request policy identity."""

    if not isinstance(policy, ToolzAuthorizationRequestPolicy):
        raise ToolzAuthorizationRequestError("Toolzs authorization request policy rejected")
    return digest_object(
        _policy_document(policy),
        domain="toolz-authorization-request-policy-v1",
    )


def _request_core(request: Mapping[str, Any]) -> dict[str, Any]:
    core = deepcopy(dict(request))
    core.pop("request_id", None)
    core.pop("signature", None)
    return core


def toolz_authorization_request_identity(
    request: Mapping[str, Any],
) -> str:
    """Return the domain-separated identity of an unsigned request."""

    digest = digest_object(
        _request_core(request),
        domain="toolz-authorization-request-identity-v1",
    )
    return f"toolz-authorization-request:{digest.split(':', 1)[1]}"


def toolz_authorization_request_digest(
    request: Mapping[str, Any],
) -> str:
    """Return the exact signed authorization-request digest."""

    return digest_object(
        dict(request),
        domain="toolz-authorization-signed-request-v1",
    )


def _freeze_protocol_mapping(
    value: Mapping[str, Any],
    field: str,
) -> dict[str, Any]:
    try:
        candidate = parse_json_strict(canonical_bytes(dict(value)))
    except Exception as exc:
        raise ToolzAuthorizationRequestError(
            f"Toolzs authorization request {field} rejected"
        ) from exc
    if not isinstance(candidate, dict):
        raise ToolzAuthorizationRequestError(f"Toolzs authorization request {field} rejected")
    return candidate


def _verify_request_inputs(
    *,
    policy: ToolzAuthorizationRequestPolicy,
    readiness_receipt: Mapping[str, Any],
    witness: Mapping[str, Any],
    witness_observer_key: TrustedKey,
    feedback_receipt: Mapping[str, Any],
    theoretical_memory: Mapping[str, Any],
    trace: Mapping[str, Any],
    trace_observer_key: TrustedKey,
    fog_evidence: ToolzFogRouteEvidence,
    cyber_evidence: ToolzCyberEvidence,
    observed_memory: Mapping[str, Any],
    memory_key: TrustedKey,
    feedback_key: TrustedKey,
    store: ToolzRouteMemoryStore,
    expected_cursor: ToolzStoreCursor,
    store_key: TrustedKey,
    readiness_key: TrustedKey,
    requested_at: str,
) -> _VerifiedRequestInputs:
    if not isinstance(policy, ToolzAuthorizationRequestPolicy):
        raise ToolzAuthorizationRequestError("Toolzs authorization request policy rejected")
    try:
        stable_trace = _freeze_mapping(trace, "authorization request trace")
        verified_readiness = verify_toolz_reuse_readiness_receipt(
            readiness_receipt,
            expected_policy=policy.readiness_policy,
            witness=witness,
            witness_observer_key=witness_observer_key,
            feedback_receipt=feedback_receipt,
            theoretical_memory=theoretical_memory,
            trace=stable_trace,
            trace_observer_key=trace_observer_key,
            fog_evidence=fog_evidence,
            cyber_evidence=cyber_evidence,
            observed_memory=observed_memory,
            memory_key=memory_key,
            feedback_key=feedback_key,
            store=store,
            expected_cursor=expected_cursor,
            store_key=store_key,
            readiness_key=readiness_key,
            used_at=requested_at,
        )
        path = describe_toolz_action_trace_path(
            stable_trace,
            expected_policy=policy.readiness_policy.feedback_policy.trace_policy,
            observer_key=trace_observer_key,
        )
        first_hop = path.hops[0]
        first_step = stable_trace["steps"][0]
    except Exception as exc:
        raise ToolzAuthorizationRequestError(
            "Toolzs authorization request readiness proof rejected"
        ) from exc
    if (
        verified_readiness["status"] != "ready-to-request-authorization"
        or verified_readiness["fog_route"]["from_entity_id"] != first_hop.from_entity_id
        or verified_readiness["fog_route"]["start_zone_id"] != first_hop.from_zone_id
        or verified_readiness["witness"]["state_entity_id"] != first_hop.from_entity_id
    ):
        raise ToolzAuthorizationRequestError(
            "Toolzs authorization request first transition mismatch"
        )
    return _VerifiedRequestInputs(
        readiness_receipt=verified_readiness,
        trace=stable_trace,
        first_step=first_step,
        first_hop=first_hop,
    )


def _request_deadline(
    *,
    policy: ToolzAuthorizationRequestPolicy,
    readiness_expires_at: str,
    requested_at: str,
) -> datetime:
    requested = _parse_time(requested_at, "request time")
    readiness_expiry = _parse_time(
        readiness_expires_at,
        "readiness expiry",
    )
    return min(
        requested + timedelta(seconds=policy.max_request_seconds),
        readiness_expiry,
    )


def _validate_request_timing(
    *,
    policy: ToolzAuthorizationRequestPolicy,
    readiness_receipt: Mapping[str, Any],
    requested_at: str,
    created_at: str,
    used_at: str,
) -> str:
    readiness_created = _parse_time(
        readiness_receipt["timing"]["created_at"],
        "readiness creation time",
    )
    requested = _parse_time(requested_at, "request time")
    created = _parse_time(created_at, "creation time")
    used = _parse_time(used_at, "use time")
    deadline = _request_deadline(
        policy=policy,
        readiness_expires_at=readiness_receipt["timing"]["expires_at"],
        requested_at=requested_at,
    )
    if not (readiness_created <= requested <= created <= used < deadline):
        raise ToolzAuthorizationRequestError("Toolzs authorization request causal timing rejected")
    if (created - requested).total_seconds() > policy.max_signing_delay_seconds:
        raise ToolzAuthorizationRequestError("Toolzs authorization request signing delay rejected")
    return _format_time(deadline)


def _expected_core(
    *,
    policy: ToolzAuthorizationRequestPolicy,
    verified: _VerifiedRequestInputs,
    requested_at: str,
    created_at: str,
    expires_at: str,
) -> dict[str, Any]:
    readiness = verified.readiness_receipt
    hop = verified.first_hop
    step = verified.first_step
    return {
        "protocol": "integrity-guardian/toolz-authorization-request/v1",
        "tenant_id": readiness["tenant_id"],
        "policy_id": policy.policy_id,
        "policy_digest": toolz_authorization_request_policy_digest(policy),
        "status": (ToolzAuthorizationRequestStatus.PENDING_AUTHORITY_DECISION.value),
        "requester": _requester(policy),
        "decision_authority": _decision_authority(policy),
        "readiness": {
            "receipt_id": readiness["receipt_id"],
            "receipt_digest": toolz_reuse_readiness_digest(readiness),
            "policy_digest": readiness["policy_digest"],
            "witness_id": readiness["witness"]["witness_id"],
            "expires_at": readiness["timing"]["expires_at"],
        },
        "intent": {
            "route_proposal_id": readiness["fog_route"]["proposal_id"],
            "route_digest": readiness["fog_route"]["route_digest"],
            "hop_index": 0,
            "action_class": step["action_class"],
            "operation_digest": step["operation_digest"],
            "relation_id": hop.relation_id,
            "from_entity_id": hop.from_entity_id,
            "to_entity_id": hop.to_entity_id,
            "from_zone_id": hop.from_zone_id,
            "to_zone_id": hop.to_zone_id,
        },
        "scope": {
            "requested_capability": "single-toolz-transition",
            "max_transitions": 1,
            "replay_allowed": False,
            "route_continuation_allowed": False,
            "production_authority_requested": False,
        },
        "timing": {
            "requested_at": requested_at,
            "created_at": created_at,
            "expires_at": expires_at,
        },
        "privacy_boundary": deepcopy(_REQUEST_PRIVACY_BOUNDARY),
        "authority_boundary": deepcopy(_REQUEST_AUTHORITY_BOUNDARY),
    }


def verify_toolz_authorization_request(
    request: Mapping[str, Any],
    *,
    expected_policy: ToolzAuthorizationRequestPolicy,
    readiness_receipt: Mapping[str, Any],
    witness: Mapping[str, Any],
    witness_observer_key: TrustedKey,
    feedback_receipt: Mapping[str, Any],
    theoretical_memory: Mapping[str, Any],
    trace: Mapping[str, Any],
    trace_observer_key: TrustedKey,
    fog_evidence: ToolzFogRouteEvidence,
    cyber_evidence: ToolzCyberEvidence,
    observed_memory: Mapping[str, Any],
    memory_key: TrustedKey,
    feedback_key: TrustedKey,
    store: ToolzRouteMemoryStore,
    expected_cursor: ToolzStoreCursor,
    store_key: TrustedKey,
    readiness_key: TrustedKey,
    requester_key: TrustedKey,
    used_at: str,
) -> dict[str, Any]:
    """Verify the full a11 proof and exact first-transition request."""

    if not isinstance(expected_policy, ToolzAuthorizationRequestPolicy):
        raise ToolzAuthorizationRequestError("Toolzs authorization request policy rejected")
    if not isinstance(requester_key, TrustedKey):
        raise ToolzAuthorizationRequestError("Toolzs authorization request requester key rejected")
    try:
        candidate = _freeze_protocol_mapping(request, "receipt")
        validate("toolz-authorization-request", candidate)
    except (ValidationError, KeyError, TypeError) as exc:
        raise ToolzAuthorizationRequestError(
            "Toolzs authorization request schema rejected"
        ) from exc
    if candidate["request_id"] != toolz_authorization_request_identity(candidate):
        raise ToolzAuthorizationRequestError("Toolzs authorization request identity mismatch")
    if candidate["signature"]["key_id"] != requester_key.key_id or not verify_signature(
        candidate, requester_key.public_key
    ):
        raise ToolzAuthorizationRequestError("Toolzs authorization request signature rejected")
    if (
        candidate["privacy_boundary"] != _REQUEST_PRIVACY_BOUNDARY
        or candidate["authority_boundary"] != _REQUEST_AUTHORITY_BOUNDARY
    ):
        raise ToolzAuthorizationRequestError("Toolzs authorization request boundary mismatch")
    verified = _verify_request_inputs(
        policy=expected_policy,
        readiness_receipt=readiness_receipt,
        witness=witness,
        witness_observer_key=witness_observer_key,
        feedback_receipt=feedback_receipt,
        theoretical_memory=theoretical_memory,
        trace=trace,
        trace_observer_key=trace_observer_key,
        fog_evidence=fog_evidence,
        cyber_evidence=cyber_evidence,
        observed_memory=observed_memory,
        memory_key=memory_key,
        feedback_key=feedback_key,
        store=store,
        expected_cursor=expected_cursor,
        store_key=store_key,
        readiness_key=readiness_key,
        requested_at=candidate["timing"]["requested_at"],
    )
    expires_at = _validate_request_timing(
        policy=expected_policy,
        readiness_receipt=verified.readiness_receipt,
        requested_at=candidate["timing"]["requested_at"],
        created_at=candidate["timing"]["created_at"],
        used_at=used_at,
    )
    expected = _expected_core(
        policy=expected_policy,
        verified=verified,
        requested_at=candidate["timing"]["requested_at"],
        created_at=candidate["timing"]["created_at"],
        expires_at=expires_at,
    )
    if _request_core(candidate) != expected:
        raise ToolzAuthorizationRequestError("Toolzs authorization request recomputation mismatch")
    return candidate


def build_toolz_authorization_request(
    *,
    policy: ToolzAuthorizationRequestPolicy,
    readiness_receipt: Mapping[str, Any],
    witness: Mapping[str, Any],
    witness_observer_key: TrustedKey,
    feedback_receipt: Mapping[str, Any],
    theoretical_memory: Mapping[str, Any],
    trace: Mapping[str, Any],
    trace_observer_key: TrustedKey,
    fog_evidence: ToolzFogRouteEvidence,
    cyber_evidence: ToolzCyberEvidence,
    observed_memory: Mapping[str, Any],
    memory_key: TrustedKey,
    feedback_key: TrustedKey,
    store: ToolzRouteMemoryStore,
    expected_cursor: ToolzStoreCursor,
    store_key: TrustedKey,
    readiness_key: TrustedKey,
    requested_at: str,
    created_at: str,
    requester_key: TrustedKey,
    requester_signer: Ed25519Signer,
) -> ToolzAuthorizationRequest:
    """Create a local request without transporting it or granting authority."""

    if not isinstance(policy, ToolzAuthorizationRequestPolicy):
        raise ToolzAuthorizationRequestError("Toolzs authorization request policy rejected")
    if not isinstance(requester_key, TrustedKey) or not isinstance(
        requester_signer,
        Ed25519Signer,
    ):
        raise ToolzAuthorizationRequestError("Toolzs authorization request signer rejected")
    if requester_signer.key_id != requester_key.key_id or public_key_fingerprint(
        requester_signer.public_key
    ) != public_key_fingerprint(requester_key.public_key):
        raise ToolzAuthorizationRequestError("Toolzs authorization request signer rejected")
    verified = _verify_request_inputs(
        policy=policy,
        readiness_receipt=readiness_receipt,
        witness=witness,
        witness_observer_key=witness_observer_key,
        feedback_receipt=feedback_receipt,
        theoretical_memory=theoretical_memory,
        trace=trace,
        trace_observer_key=trace_observer_key,
        fog_evidence=fog_evidence,
        cyber_evidence=cyber_evidence,
        observed_memory=observed_memory,
        memory_key=memory_key,
        feedback_key=feedback_key,
        store=store,
        expected_cursor=expected_cursor,
        store_key=store_key,
        readiness_key=readiness_key,
        requested_at=requested_at,
    )
    expires_at = _validate_request_timing(
        policy=policy,
        readiness_receipt=verified.readiness_receipt,
        requested_at=requested_at,
        created_at=created_at,
        used_at=created_at,
    )
    core = _expected_core(
        policy=policy,
        verified=verified,
        requested_at=requested_at,
        created_at=created_at,
        expires_at=expires_at,
    )
    unsigned = {
        "request_id": toolz_authorization_request_identity(core),
        **core,
    }
    signed = requester_signer.sign(unsigned)
    request = verify_toolz_authorization_request(
        signed,
        expected_policy=policy,
        readiness_receipt=verified.readiness_receipt,
        witness=witness,
        witness_observer_key=witness_observer_key,
        feedback_receipt=feedback_receipt,
        theoretical_memory=theoretical_memory,
        trace=verified.trace,
        trace_observer_key=trace_observer_key,
        fog_evidence=fog_evidence,
        cyber_evidence=cyber_evidence,
        observed_memory=observed_memory,
        memory_key=memory_key,
        feedback_key=feedback_key,
        store=store,
        expected_cursor=expected_cursor,
        store_key=store_key,
        readiness_key=readiness_key,
        requester_key=requester_key,
        used_at=created_at,
    )
    return ToolzAuthorizationRequest(
        request=request,
        readiness_receipt=verified.readiness_receipt,
        status=ToolzAuthorizationRequestStatus.PENDING_AUTHORITY_DECISION,
    )
