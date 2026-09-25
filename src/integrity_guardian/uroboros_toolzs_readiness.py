"""Passive start-state and reuse-readiness proofs for Uroboros Toolzs.

The module accepts one already minimized observer attestation, re-verifies the
complete post-route feedback chain and exact generation-two store state, and
proves that the fresh state is the stored Fog route's first state.  Its sole
result is ``ready-to-request-authorization``.  It never requests authority,
invokes a Toolz, controls a browser, writes the store or executes a route.
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
from .uroboros_toolzs import (
    ToolzCyberEvidence,
    ToolzFogRouteEvidence,
    ToolzRouteMemoryDecision,
    ToolzRouteMemoryOutcome,
    toolz_route_memory_digest,
)
from .uroboros_toolzs_feedback import (
    ToolzPostRouteFeedbackDecision,
    ToolzPostRouteFeedbackPolicy,
    toolz_post_route_feedback_digest,
    toolz_post_route_feedback_policy_digest,
    verify_toolz_post_route_feedback_receipt,
)
from .uroboros_toolzs_install import (
    _freeze_cyber_evidence,
    _freeze_fog_evidence,
    _freeze_mapping,
)
from .uroboros_toolzs_store import (
    ToolzRouteMemoryStore,
    ToolzStoreCursor,
    ToolzStoreLifecycle,
    ToolzStoreLookup,
    toolz_store_context_identity,
)
from .uroboros_toolzs_trace import toolz_trace_state_entity_identity

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_STORE_ID = re.compile(r"^toolz-store:[A-Za-z0-9][A-Za-z0-9._:/-]{0,242}$")

_WITNESS_PRIVACY_BOUNDARY = {
    "cookies": False,
    "credentials": False,
    "dom": False,
    "form_values": False,
    "free_text": False,
    "screenshots": False,
    "selectors": False,
    "urls": False,
}
_WITNESS_AUTHORITY_BOUNDARY = {
    "browser_control": False,
    "credentials": False,
    "execution": False,
    "external_observer_attestation": True,
    "global_publish": False,
    "model_sdk": False,
    "network": False,
    "production_authority": False,
    "raw_ui_data": False,
    "storage": False,
    "tool_invocation": False,
}
_READINESS_AUTHORITY_BOUNDARY = {
    "authorization_granted": False,
    "authorization_requested": False,
    "browser_control": False,
    "credentials": False,
    "execution": False,
    "global_publish": False,
    "local_storage_read": True,
    "model_sdk": False,
    "network": False,
    "production_authority": False,
    "raw_ui_data": False,
    "storage_performed": False,
    "store_write": False,
    "tool_invocation": False,
}


class ToolzReuseReadinessError(RuntimeError):
    """Raised before an ambiguous or stale reuse preflight can be accepted."""


class ToolzReuseReadinessStatus(StrEnum):
    """The sole authority-free result of the a11 preflight."""

    READY_TO_REQUEST_AUTHORIZATION = "ready-to-request-authorization"


@dataclass(frozen=True)
class ToolzReuseReadinessPolicy:
    """Exact causal feedback, store, observer and freshness contract."""

    policy_id: str
    feedback_policy: ToolzPostRouteFeedbackPolicy
    store_id: str
    evaluator_id: str
    evaluator_artifact_digest: str
    max_observation_age_seconds: int = 30
    max_witness_signing_delay_seconds: int = 10
    max_readiness_signing_delay_seconds: int = 5

    def __post_init__(self) -> None:
        if (
            not isinstance(self.policy_id, str)
            or _ID.fullmatch(self.policy_id) is None
            or "synthetic" not in self.policy_id
        ):
            raise ToolzReuseReadinessError("Toolzs reuse readiness policy id rejected")
        if not isinstance(self.feedback_policy, ToolzPostRouteFeedbackPolicy):
            raise ToolzReuseReadinessError("Toolzs reuse readiness feedback policy rejected")
        if (
            not isinstance(self.store_id, str)
            or _STORE_ID.fullmatch(self.store_id) is None
            or "synthetic" not in self.store_id
        ):
            raise ToolzReuseReadinessError("Toolzs reuse readiness store id rejected")
        _require_id(self.evaluator_id, "evaluator id", synthetic=True)
        _require_digest(
            self.evaluator_artifact_digest,
            "evaluator artifact",
        )
        bounds = (
            ("observation age", self.max_observation_age_seconds, 1, 300),
            (
                "witness signing delay",
                self.max_witness_signing_delay_seconds,
                0,
                60,
            ),
            (
                "readiness signing delay",
                self.max_readiness_signing_delay_seconds,
                0,
                60,
            ),
        )
        for field, value, minimum, maximum in bounds:
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or not minimum <= value <= maximum
            ):
                raise ToolzReuseReadinessError(f"Toolzs reuse readiness {field} rejected")


@dataclass(frozen=True)
class ToolzReuseReadiness:
    """One verified readiness receipt and its exact read-only store result."""

    receipt: dict[str, Any]
    witness: dict[str, Any]
    lookup: ToolzStoreLookup
    status: ToolzReuseReadinessStatus

    @property
    def execution_authority(self) -> bool:
        return False

    @property
    def authorization_granted(self) -> bool:
        return False

    @property
    def storage_performed(self) -> bool:
        return False


@dataclass(frozen=True)
class _VerifiedReadinessInputs:
    witness: dict[str, Any]
    feedback_receipt: dict[str, Any]
    theoretical_memory: dict[str, Any]
    observed_memory: dict[str, Any]
    lookup: ToolzStoreLookup
    store_entry: dict[str, Any]
    route: dict[str, Any]
    start_zone_id: str


def _require_id(value: object, field: str, *, synthetic: bool = False) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise ToolzReuseReadinessError(f"Toolzs reuse readiness {field} rejected")
    if synthetic and "synthetic" not in value:
        raise ToolzReuseReadinessError(f"Toolzs reuse readiness {field} rejected")
    return value


def _require_digest(value: object, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ToolzReuseReadinessError(f"Toolzs reuse readiness {field} rejected")
    return value


def _parse_time(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise ToolzReuseReadinessError(f"Toolzs reuse readiness {field} rejected")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ToolzReuseReadinessError(f"Toolzs reuse readiness {field} rejected") from exc
    if parsed.tzinfo is None:
        raise ToolzReuseReadinessError(f"Toolzs reuse readiness {field} rejected")
    return parsed


def _format_time(value: datetime) -> str:
    rendered = value.isoformat()
    if rendered.endswith("+00:00"):
        return f"{rendered[:-6]}Z"
    return rendered


def _tool_context(policy: ToolzReuseReadinessPolicy) -> dict[str, Any]:
    memory_policy = policy.feedback_policy.memory_policy
    return {
        "artifact_id": memory_policy.subject.artifact_id,
        "artifact_digest": memory_policy.subject.artifact_digest,
        "environment_profile_id": memory_policy.environment.profile_id,
        "environment_fingerprint_digest": (memory_policy.environment.fingerprint_digest),
        "ui_context_digest": memory_policy.ui_context_digest,
    }


def _observer(policy: ToolzReuseReadinessPolicy) -> dict[str, str]:
    trace_policy = policy.feedback_policy.trace_policy
    return {
        "observer_id": trace_policy.observer_id,
        "observer_artifact_digest": trace_policy.observer_artifact_digest,
    }


def _evaluator(policy: ToolzReuseReadinessPolicy) -> dict[str, str]:
    return {
        "evaluator_id": policy.evaluator_id,
        "evaluator_artifact_digest": policy.evaluator_artifact_digest,
    }


def _policy_document(policy: ToolzReuseReadinessPolicy) -> dict[str, Any]:
    return {
        "policy_id": policy.policy_id,
        "feedback_policy_digest": toolz_post_route_feedback_policy_digest(policy.feedback_policy),
        "store_id": policy.store_id,
        "tool_context": _tool_context(policy),
        "observer": _observer(policy),
        "evaluator": _evaluator(policy),
        "max_observation_age_seconds": policy.max_observation_age_seconds,
        "max_witness_signing_delay_seconds": (policy.max_witness_signing_delay_seconds),
        "max_readiness_signing_delay_seconds": (policy.max_readiness_signing_delay_seconds),
        "readiness_semantics": (
            "fresh-exact-route-start-and-generation-two-state-"
            "is-ready-to-request-authorization-never-authority"
        ),
    }


def toolz_reuse_readiness_policy_digest(
    policy: ToolzReuseReadinessPolicy,
) -> str:
    """Return the exact a11 observer, store and freshness policy identity."""

    if not isinstance(policy, ToolzReuseReadinessPolicy):
        raise ToolzReuseReadinessError("Toolzs reuse readiness policy rejected")
    return digest_object(
        _policy_document(policy),
        domain="toolz-reuse-readiness-policy-v1",
    )


def _witness_core(witness: Mapping[str, Any]) -> dict[str, Any]:
    core = deepcopy(dict(witness))
    core.pop("witness_id", None)
    core.pop("signature", None)
    return core


def toolz_start_state_witness_identity(
    witness: Mapping[str, Any],
) -> str:
    """Return the domain-separated identity of an unsigned state witness."""

    digest = digest_object(
        _witness_core(witness),
        domain="toolz-start-state-witness-identity-v1",
    )
    return f"toolz-start-state-witness:{digest.split(':', 1)[1]}"


def toolz_start_state_witness_digest(
    witness: Mapping[str, Any],
) -> str:
    """Return the exact signed state-witness digest."""

    return digest_object(
        dict(witness),
        domain="toolz-start-state-signed-witness-v1",
    )


def _readiness_core(receipt: Mapping[str, Any]) -> dict[str, Any]:
    core = deepcopy(dict(receipt))
    core.pop("receipt_id", None)
    core.pop("signature", None)
    return core


def toolz_reuse_readiness_identity(receipt: Mapping[str, Any]) -> str:
    """Return the domain-separated identity of an unsigned readiness receipt."""

    digest = digest_object(
        _readiness_core(receipt),
        domain="toolz-reuse-readiness-receipt-identity-v1",
    )
    return f"toolz-reuse-readiness-receipt:{digest.split(':', 1)[1]}"


def toolz_reuse_readiness_digest(receipt: Mapping[str, Any]) -> str:
    """Return the exact signed readiness-receipt digest."""

    return digest_object(
        dict(receipt),
        domain="toolz-reuse-readiness-signed-receipt-v1",
    )


def _freeze_protocol_mapping(
    value: Mapping[str, Any],
    field: str,
) -> dict[str, Any]:
    try:
        candidate = parse_json_strict(canonical_bytes(dict(value)))
    except Exception as exc:
        raise ToolzReuseReadinessError(f"Toolzs reuse readiness {field} rejected") from exc
    if not isinstance(candidate, dict):
        raise ToolzReuseReadinessError(f"Toolzs reuse readiness {field} rejected")
    return candidate


def _validate_witness_timing(
    witness: Mapping[str, Any],
    policy: ToolzReuseReadinessPolicy,
) -> None:
    observed = _parse_time(
        witness["observation"]["observed_at"],
        "witness observation time",
    )
    created = _parse_time(witness["created_at"], "witness creation time")
    if (
        observed > created
        or (created - observed).total_seconds() > policy.max_witness_signing_delay_seconds
    ):
        raise ToolzReuseReadinessError("Toolzs reuse readiness witness timing rejected")


def verify_toolz_start_state_witness(
    witness: Mapping[str, Any],
    *,
    expected_policy: ToolzReuseReadinessPolicy,
    observer_key: TrustedKey,
) -> dict[str, Any]:
    """Verify one closed, observer-signed and still authority-free witness."""

    if not isinstance(expected_policy, ToolzReuseReadinessPolicy):
        raise ToolzReuseReadinessError("Toolzs reuse readiness policy rejected")
    if not isinstance(observer_key, TrustedKey):
        raise ToolzReuseReadinessError("Toolzs reuse readiness observer key rejected")
    try:
        candidate = _freeze_protocol_mapping(witness, "witness")
        validate("toolz-start-state-witness", candidate)
    except (ValidationError, KeyError, TypeError) as exc:
        raise ToolzReuseReadinessError("Toolzs reuse readiness witness schema rejected") from exc
    if candidate["witness_id"] != toolz_start_state_witness_identity(candidate):
        raise ToolzReuseReadinessError("Toolzs reuse readiness witness identity mismatch")
    if candidate["signature"]["key_id"] != observer_key.key_id or not verify_signature(
        candidate, observer_key.public_key
    ):
        raise ToolzReuseReadinessError("Toolzs reuse readiness witness signature rejected")
    expected_fields = {
        "tenant_id": expected_policy.feedback_policy.memory_policy.subject.tenant_id,
        "policy_id": expected_policy.policy_id,
        "policy_digest": toolz_reuse_readiness_policy_digest(expected_policy),
        "tool_context": _tool_context(expected_policy),
        "observer": _observer(expected_policy),
        "privacy_boundary": _WITNESS_PRIVACY_BOUNDARY,
        "authority_boundary": _WITNESS_AUTHORITY_BOUNDARY,
    }
    for field, value in expected_fields.items():
        if candidate[field] != value:
            raise ToolzReuseReadinessError(f"Toolzs reuse readiness witness {field} mismatch")
    observation = candidate["observation"]
    try:
        expected_entity = toolz_trace_state_entity_identity(
            tool_context=candidate["tool_context"],
            state_digest=observation["state_digest"],
            zone_id=observation["zone_id"],
        )
    except Exception as exc:
        raise ToolzReuseReadinessError(
            "Toolzs reuse readiness witness state identity rejected"
        ) from exc
    if observation["state_entity_id"] != expected_entity:
        raise ToolzReuseReadinessError("Toolzs reuse readiness witness state identity mismatch")
    _validate_witness_timing(candidate, expected_policy)
    return candidate


def build_toolz_start_state_witness(
    *,
    policy: ToolzReuseReadinessPolicy,
    state_digest: str,
    zone_id: str,
    evidence_digest: str,
    observed_at: str,
    created_at: str,
    observer_signer: Ed25519Signer,
) -> dict[str, Any]:
    """Sign caller-supplied opaque state evidence without observing a UI."""

    if not isinstance(policy, ToolzReuseReadinessPolicy):
        raise ToolzReuseReadinessError("Toolzs reuse readiness policy rejected")
    if not isinstance(observer_signer, Ed25519Signer):
        raise ToolzReuseReadinessError("Toolzs reuse readiness observer signer rejected")
    _require_digest(state_digest, "state digest")
    _require_id(zone_id, "zone id", synthetic=True)
    _require_digest(evidence_digest, "evidence digest")
    tool_context = _tool_context(policy)
    core = {
        "protocol": "integrity-guardian/toolz-start-state-witness/v1",
        "tenant_id": policy.feedback_policy.memory_policy.subject.tenant_id,
        "policy_id": policy.policy_id,
        "policy_digest": toolz_reuse_readiness_policy_digest(policy),
        "tool_context": tool_context,
        "observer": _observer(policy),
        "observation": {
            "state_digest": state_digest,
            "zone_id": zone_id,
            "state_entity_id": toolz_trace_state_entity_identity(
                tool_context=tool_context,
                state_digest=state_digest,
                zone_id=zone_id,
            ),
            "evidence_digest": evidence_digest,
            "observed_at": observed_at,
        },
        "created_at": created_at,
        "privacy_boundary": deepcopy(_WITNESS_PRIVACY_BOUNDARY),
        "authority_boundary": deepcopy(_WITNESS_AUTHORITY_BOUNDARY),
    }
    _validate_witness_timing(core, policy)
    unsigned = {
        "witness_id": toolz_start_state_witness_identity(core),
        **core,
    }
    signed = observer_signer.sign(unsigned)
    return verify_toolz_start_state_witness(
        signed,
        expected_policy=policy,
        observer_key=TrustedKey(
            observer_signer.key_id,
            observer_signer.public_key,
        ),
    )


def _freeze_readiness_inputs(
    *,
    feedback_receipt: Mapping[str, Any],
    theoretical_memory: Mapping[str, Any],
    trace: Mapping[str, Any],
    fog_evidence: ToolzFogRouteEvidence,
    cyber_evidence: ToolzCyberEvidence,
    observed_memory: Mapping[str, Any],
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    ToolzFogRouteEvidence,
    ToolzCyberEvidence,
    dict[str, Any],
]:
    try:
        return (
            _freeze_mapping(feedback_receipt, "readiness feedback"),
            _freeze_mapping(
                theoretical_memory,
                "readiness theoretical memory",
            ),
            _freeze_mapping(trace, "readiness feedback trace"),
            _freeze_fog_evidence(fog_evidence),
            _freeze_cyber_evidence(cyber_evidence),
            _freeze_mapping(observed_memory, "readiness observed memory"),
        )
    except Exception as exc:
        raise ToolzReuseReadinessError("Toolzs reuse readiness input rejected") from exc


def _validate_store_trust(
    *,
    policy: ToolzReuseReadinessPolicy,
    store: ToolzRouteMemoryStore,
    expected_cursor: ToolzStoreCursor,
    store_key: TrustedKey,
    tenant_id: str,
) -> None:
    if not isinstance(store, ToolzRouteMemoryStore):
        raise ToolzReuseReadinessError("Toolzs reuse readiness store rejected")
    if (
        not isinstance(expected_cursor, ToolzStoreCursor)
        or expected_cursor.store_id != policy.store_id
        or expected_cursor.tenant_id != tenant_id
        or store.store_id != policy.store_id
        or store.tenant_id != tenant_id
    ):
        raise ToolzReuseReadinessError("Toolzs reuse readiness store cursor rejected")
    if (
        not isinstance(store_key, TrustedKey)
        or store.authority_key.key_id != store_key.key_id
        or public_key_fingerprint(store.authority_key.public_key)
        != public_key_fingerprint(store_key.public_key)
    ):
        raise ToolzReuseReadinessError("Toolzs reuse readiness store trust rejected")


def _route_start(
    route: Mapping[str, Any],
) -> tuple[dict[str, Any], str]:
    try:
        stable_route = _freeze_protocol_mapping(route, "Fog route")
        hops = stable_route["hops"]
        first_hop = hops[0]
        start_zone_id = first_hop["from_zone_id"]
    except (KeyError, IndexError, TypeError) as exc:
        raise ToolzReuseReadinessError(
            "Toolzs reuse readiness empty or malformed route rejected"
        ) from exc
    if (
        stable_route["status"] != "candidate"
        or first_hop["from_entity_id"] != stable_route["from_entity_id"]
        or start_zone_id not in stable_route["invalidation_zone_ids"]
    ):
        raise ToolzReuseReadinessError("Toolzs reuse readiness route start rejected")
    return stable_route, start_zone_id


def _verify_store_generation(
    *,
    policy: ToolzReuseReadinessPolicy,
    store: ToolzRouteMemoryStore,
    expected_cursor: ToolzStoreCursor,
    store_key: TrustedKey,
    theoretical_memory: Mapping[str, Any],
    observed_memory: Mapping[str, Any],
    fog_evidence: ToolzFogRouteEvidence,
    cyber_evidence: ToolzCyberEvidence,
    memory_key: TrustedKey,
    evaluated_at: str,
) -> tuple[ToolzStoreLookup, dict[str, Any]]:
    tenant_id = observed_memory["tenant_id"]
    _validate_store_trust(
        policy=policy,
        store=store,
        expected_cursor=expected_cursor,
        store_key=store_key,
        tenant_id=tenant_id,
    )
    context_id = toolz_store_context_identity(observed_memory)
    try:
        lookup = store.lookup(
            context_id,
            expected_cursor=expected_cursor,
            expected_policy=policy.feedback_policy.memory_policy,
            fog_evidence=fog_evidence,
            cyber_evidence=cyber_evidence,
            memory_key=memory_key,
            evaluated_at=evaluated_at,
        )
        entries = {
            entry["context_id"]: entry for entry in store.entries(expected_cursor=expected_cursor)
        }
    except Exception as exc:
        raise ToolzReuseReadinessError(
            "Toolzs reuse readiness store verification rejected"
        ) from exc
    entry = entries.get(context_id)
    if (
        lookup is None
        or entry is None
        or lookup.cursor != expected_cursor
        or lookup.generation != 2
        or lookup.lifecycle is not ToolzStoreLifecycle.REUSABLE
        or lookup.decision is not ToolzRouteMemoryDecision.REUSE_CANDIDATE
        or toolz_route_memory_digest(lookup.receipt) != toolz_route_memory_digest(observed_memory)
        or entry["generation"] != 2
        or entry["receipt_digest"] != toolz_route_memory_digest(observed_memory)
        or entry["previous_receipt_digest"] != toolz_route_memory_digest(theoretical_memory)
        or entry["lifecycle"] != ToolzStoreLifecycle.REUSABLE.value
        or entry["decision"] != ToolzRouteMemoryDecision.REUSE_CANDIDATE.value
        or entry["invalidation_reason"] is not None
    ):
        raise ToolzReuseReadinessError("Toolzs reuse readiness exact generation-two state rejected")
    return lookup, entry


def _readiness_deadline(
    *,
    observed_at: str,
    memory_expires_at: str,
    policy: ToolzReuseReadinessPolicy,
) -> datetime:
    observed = _parse_time(observed_at, "observation time")
    memory_expiry = _parse_time(memory_expires_at, "memory expiry")
    return min(
        observed + timedelta(seconds=policy.max_observation_age_seconds),
        memory_expiry,
    )


def _validate_readiness_timing(
    *,
    policy: ToolzReuseReadinessPolicy,
    witness: Mapping[str, Any],
    feedback_receipt: Mapping[str, Any],
    observed_memory: Mapping[str, Any],
    evaluated_at: str,
    created_at: str,
    used_at: str,
) -> str:
    observed = _parse_time(
        witness["observation"]["observed_at"],
        "observation time",
    )
    witness_created = _parse_time(
        witness["created_at"],
        "witness creation time",
    )
    feedback_created = _parse_time(
        feedback_receipt["created_at"],
        "feedback creation time",
    )
    memory_created = _parse_time(
        observed_memory["created_at"],
        "observed memory creation time",
    )
    evaluated = _parse_time(evaluated_at, "evaluation time")
    created = _parse_time(created_at, "creation time")
    used = _parse_time(used_at, "use time")
    deadline = _readiness_deadline(
        observed_at=witness["observation"]["observed_at"],
        memory_expires_at=observed_memory["expires_at"],
        policy=policy,
    )
    if not (
        memory_created
        <= feedback_created
        < observed
        <= witness_created
        <= evaluated
        <= created
        <= used
        <= deadline
    ):
        raise ToolzReuseReadinessError("Toolzs reuse readiness causal timing rejected")
    if (evaluated - observed).total_seconds() > policy.max_observation_age_seconds or (
        created - evaluated
    ).total_seconds() > policy.max_readiness_signing_delay_seconds:
        raise ToolzReuseReadinessError("Toolzs reuse readiness freshness rejected")
    return _format_time(deadline)


def _verify_readiness_inputs(
    *,
    policy: ToolzReuseReadinessPolicy,
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
    evaluated_at: str,
) -> _VerifiedReadinessInputs:
    if not isinstance(policy, ToolzReuseReadinessPolicy):
        raise ToolzReuseReadinessError("Toolzs reuse readiness policy rejected")
    if not all(
        isinstance(key, TrustedKey)
        for key in (
            witness_observer_key,
            trace_observer_key,
            memory_key,
            feedback_key,
            store_key,
        )
    ):
        raise ToolzReuseReadinessError("Toolzs reuse readiness trust binding rejected")
    stable_witness = verify_toolz_start_state_witness(
        witness,
        expected_policy=policy,
        observer_key=witness_observer_key,
    )
    (
        stable_feedback,
        stable_theoretical,
        stable_trace,
        stable_fog,
        stable_cyber,
        stable_observed,
    ) = _freeze_readiness_inputs(
        feedback_receipt=feedback_receipt,
        theoretical_memory=theoretical_memory,
        trace=trace,
        fog_evidence=fog_evidence,
        cyber_evidence=cyber_evidence,
        observed_memory=observed_memory,
    )
    try:
        verified_feedback = verify_toolz_post_route_feedback_receipt(
            stable_feedback,
            expected_policy=policy.feedback_policy,
            theoretical_memory=stable_theoretical,
            trace=stable_trace,
            observer_key=trace_observer_key,
            fog_evidence=stable_fog,
            cyber_evidence=stable_cyber,
            observed_memory=stable_observed,
            memory_key=memory_key,
            feedback_key=feedback_key,
        )
    except Exception as exc:
        raise ToolzReuseReadinessError("Toolzs reuse readiness feedback proof rejected") from exc
    if (
        verified_feedback.decision is not ToolzPostRouteFeedbackDecision.ADMIT_OBSERVED_SUCCESS
        or verified_feedback.memory_receipt["observation"]["outcome"]
        != ToolzRouteMemoryOutcome.OBSERVED_SUCCESS.value
    ):
        raise ToolzReuseReadinessError("Toolzs reuse readiness observed feedback rejected")
    lookup, entry = _verify_store_generation(
        policy=policy,
        store=store,
        expected_cursor=expected_cursor,
        store_key=store_key,
        theoretical_memory=stable_theoretical,
        observed_memory=verified_feedback.memory_receipt,
        fog_evidence=stable_fog,
        cyber_evidence=stable_cyber,
        memory_key=memory_key,
        evaluated_at=evaluated_at,
    )
    route, start_zone_id = _route_start(stable_fog.route)
    observation = stable_witness["observation"]
    if (
        observation["zone_id"] != start_zone_id
        or observation["state_entity_id"] != route["from_entity_id"]
    ):
        raise ToolzReuseReadinessError("Toolzs reuse readiness current route start mismatch")
    return _VerifiedReadinessInputs(
        witness=stable_witness,
        feedback_receipt=verified_feedback.receipt,
        theoretical_memory=stable_theoretical,
        observed_memory=verified_feedback.memory_receipt,
        lookup=lookup,
        store_entry=entry,
        route=route,
        start_zone_id=start_zone_id,
    )


def _expected_readiness_core(
    *,
    policy: ToolzReuseReadinessPolicy,
    verified: _VerifiedReadinessInputs,
    evaluated_at: str,
    created_at: str,
    expires_at: str,
) -> dict[str, Any]:
    witness = verified.witness
    observed = verified.observed_memory
    route = verified.route
    return {
        "protocol": "integrity-guardian/toolz-reuse-readiness-receipt/v1",
        "tenant_id": observed["tenant_id"],
        "policy_id": policy.policy_id,
        "policy_digest": toolz_reuse_readiness_policy_digest(policy),
        "status": (ToolzReuseReadinessStatus.READY_TO_REQUEST_AUTHORIZATION.value),
        "tool_context": _tool_context(policy),
        "evaluator": _evaluator(policy),
        "witness": {
            "witness_id": witness["witness_id"],
            "witness_digest": toolz_start_state_witness_digest(witness),
            "state_entity_id": witness["observation"]["state_entity_id"],
            "zone_id": witness["observation"]["zone_id"],
            "observed_at": witness["observation"]["observed_at"],
            "created_at": witness["created_at"],
        },
        "feedback": {
            "receipt_id": verified.feedback_receipt["receipt_id"],
            "receipt_digest": toolz_post_route_feedback_digest(verified.feedback_receipt),
            "policy_digest": toolz_post_route_feedback_policy_digest(policy.feedback_policy),
            "decision": verified.feedback_receipt["decision"],
        },
        "memory": {
            "context_id": verified.lookup.context_id,
            "theoretical_receipt_digest": toolz_route_memory_digest(verified.theoretical_memory),
            "observed_receipt_id": observed["receipt_id"],
            "observed_receipt_digest": toolz_route_memory_digest(observed),
            "outcome": observed["observation"]["outcome"],
            "expires_at": observed["expires_at"],
        },
        "fog_route": {
            "proposal_id": route["proposal_id"],
            "route_digest": observed["fog_route"]["route_digest"],
            "from_entity_id": route["from_entity_id"],
            "to_entity_id": route["to_entity_id"],
            "start_zone_id": verified.start_zone_id,
            "hop_count": len(route["hops"]),
        },
        "store": {
            "store_id": policy.store_id,
            "cursor": verified.lookup.cursor.to_document(),
            "generation": verified.lookup.generation,
            "lifecycle": verified.lookup.lifecycle.value,
            "decision": verified.lookup.decision.value,
            "previous_receipt_digest": verified.store_entry["previous_receipt_digest"],
        },
        "timing": {
            "evaluated_at": evaluated_at,
            "created_at": created_at,
            "expires_at": expires_at,
        },
        "authority_boundary": deepcopy(_READINESS_AUTHORITY_BOUNDARY),
    }


def verify_toolz_reuse_readiness_receipt(
    receipt: Mapping[str, Any],
    *,
    expected_policy: ToolzReuseReadinessPolicy,
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
    used_at: str,
) -> dict[str, Any]:
    """Recompute the witness, a7 chain, gen2 store and exact route start."""

    if not isinstance(expected_policy, ToolzReuseReadinessPolicy):
        raise ToolzReuseReadinessError("Toolzs reuse readiness policy rejected")
    if not isinstance(readiness_key, TrustedKey):
        raise ToolzReuseReadinessError("Toolzs reuse readiness authority key rejected")
    try:
        candidate = _freeze_protocol_mapping(receipt, "receipt")
        validate("toolz-reuse-readiness-receipt", candidate)
    except (ValidationError, KeyError, TypeError) as exc:
        raise ToolzReuseReadinessError("Toolzs reuse readiness receipt schema rejected") from exc
    if candidate["receipt_id"] != toolz_reuse_readiness_identity(candidate):
        raise ToolzReuseReadinessError("Toolzs reuse readiness receipt identity mismatch")
    if candidate["signature"]["key_id"] != readiness_key.key_id or not verify_signature(
        candidate, readiness_key.public_key
    ):
        raise ToolzReuseReadinessError("Toolzs reuse readiness receipt signature rejected")
    if candidate["authority_boundary"] != _READINESS_AUTHORITY_BOUNDARY:
        raise ToolzReuseReadinessError("Toolzs reuse readiness authority mismatch")
    verified = _verify_readiness_inputs(
        policy=expected_policy,
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
        evaluated_at=candidate["timing"]["evaluated_at"],
    )
    expires_at = _validate_readiness_timing(
        policy=expected_policy,
        witness=verified.witness,
        feedback_receipt=verified.feedback_receipt,
        observed_memory=verified.observed_memory,
        evaluated_at=candidate["timing"]["evaluated_at"],
        created_at=candidate["timing"]["created_at"],
        used_at=used_at,
    )
    expected = _expected_readiness_core(
        policy=expected_policy,
        verified=verified,
        evaluated_at=candidate["timing"]["evaluated_at"],
        created_at=candidate["timing"]["created_at"],
        expires_at=expires_at,
    )
    if _readiness_core(candidate) != expected:
        raise ToolzReuseReadinessError("Toolzs reuse readiness recomputation mismatch")
    return candidate


def build_toolz_reuse_readiness(
    *,
    policy: ToolzReuseReadinessPolicy,
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
    evaluated_at: str,
    created_at: str,
    readiness_signer: Ed25519Signer,
) -> ToolzReuseReadiness:
    """Build only an authority-request preflight after complete re-verification."""

    if not isinstance(policy, ToolzReuseReadinessPolicy):
        raise ToolzReuseReadinessError("Toolzs reuse readiness policy rejected")
    if not isinstance(readiness_signer, Ed25519Signer):
        raise ToolzReuseReadinessError("Toolzs reuse readiness signer rejected")
    verified = _verify_readiness_inputs(
        policy=policy,
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
        evaluated_at=evaluated_at,
    )
    expires_at = _validate_readiness_timing(
        policy=policy,
        witness=verified.witness,
        feedback_receipt=verified.feedback_receipt,
        observed_memory=verified.observed_memory,
        evaluated_at=evaluated_at,
        created_at=created_at,
        used_at=created_at,
    )
    core = _expected_readiness_core(
        policy=policy,
        verified=verified,
        evaluated_at=evaluated_at,
        created_at=created_at,
        expires_at=expires_at,
    )
    unsigned = {
        "receipt_id": toolz_reuse_readiness_identity(core),
        **core,
    }
    signed = readiness_signer.sign(unsigned)
    receipt = verify_toolz_reuse_readiness_receipt(
        signed,
        expected_policy=policy,
        witness=verified.witness,
        witness_observer_key=witness_observer_key,
        feedback_receipt=verified.feedback_receipt,
        theoretical_memory=verified.theoretical_memory,
        trace=trace,
        trace_observer_key=trace_observer_key,
        fog_evidence=fog_evidence,
        cyber_evidence=cyber_evidence,
        observed_memory=verified.observed_memory,
        memory_key=memory_key,
        feedback_key=feedback_key,
        store=store,
        expected_cursor=expected_cursor,
        store_key=store_key,
        readiness_key=TrustedKey(
            readiness_signer.key_id,
            readiness_signer.public_key,
        ),
        used_at=created_at,
    )
    return ToolzReuseReadiness(
        receipt=receipt,
        witness=verified.witness,
        lookup=verified.lookup,
        status=ToolzReuseReadinessStatus.READY_TO_REQUEST_AUTHORIZATION,
    )
