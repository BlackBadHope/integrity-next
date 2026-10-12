"""Independent post-action state observation for Uroboros Toolzs.

This module binds one exact a13 grant-consumption proof to a later, separately
signed state observation.  It never invokes the external Toolz and never claims
that a consumed grant proves an action attempt or caused an observed change.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from jsonschema import ValidationError

from .canonical import canonical_bytes, parse_json_strict
from .hashing import digest_object
from .ledger import LedgerVerificationError, event_digest, verify_ledger_event
from .schemas import validate
from .signing import (
    Ed25519Signer,
    TrustedKey,
    public_key_fingerprint,
    verify_signature,
)
from .uroboros_toolzs_authority import (
    ToolzAuthorityError,
    ToolzAuthorityPolicy,
    ToolzAuthorizationEvidence,
    toolz_authority_decision_digest,
    toolz_authority_policy_digest,
    toolz_grant_consumption_digest,
)
from .uroboros_toolzs_authority_ledger import ToolzAuthorityLedger
from .uroboros_toolzs_authorization_request import (
    toolz_authorization_request_digest,
)
from .uroboros_toolzs_readiness import (
    toolz_reuse_readiness_digest,
    toolz_start_state_witness_digest,
)
from .uroboros_toolzs_trace import toolz_trace_state_entity_identity

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")

_PRIVACY_BOUNDARY = {
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
_AUTHORITY_BOUNDARY_BASE = {
    "authorization_granted": True,
    "browser_control": False,
    "credentials": False,
    "execution_performed": False,
    "external_action_attempt_proven": False,
    "external_action_causality_proven": False,
    "feedback_promotion": False,
    "grant_consumption_proven": True,
    "independent_observation": True,
    "model_sdk": False,
    "network": False,
    "production_authority": False,
    "raw_ui_data": False,
    "route_memory_store_write": False,
    "tool_invocation": False,
}


class ToolzActionOutcomeError(RuntimeError):
    """Raised before an ambiguous post-action observation can be accepted."""


class ToolzActionOutcome(StrEnum):
    """Closed epistemic outcomes; none claims execution causality."""

    EXPECTED_TRANSITION_OBSERVED = "expected-transition-observed"
    PRE_STATE_RETAINED = "pre-state-retained"
    UNEXPECTED_STATE_OBSERVED = "unexpected-state-observed"
    OUTCOME_UNKNOWN = "outcome-unknown"


class ToolzActionOutcomeReason(StrEnum):
    """Closed privacy-safe reason codes."""

    EXPECTED_TRANSITION = "expected-transition"
    PRE_STATE_RETAINED = "pre-state-retained"
    UNEXPECTED_STATE = "unexpected-state"
    OBSERVER_UNAVAILABLE = "observer-unavailable"
    OBSERVATION_TIMEOUT = "observation-timeout"
    EXECUTOR_CRASH_REPORTED = "executor-crash-reported"
    TRANSPORT_LOSS_REPORTED = "transport-loss-reported"


_EXPECTED_REASON = {
    ToolzActionOutcome.EXPECTED_TRANSITION_OBSERVED: {
        ToolzActionOutcomeReason.EXPECTED_TRANSITION
    },
    ToolzActionOutcome.PRE_STATE_RETAINED: {
        ToolzActionOutcomeReason.PRE_STATE_RETAINED
    },
    ToolzActionOutcome.UNEXPECTED_STATE_OBSERVED: {
        ToolzActionOutcomeReason.UNEXPECTED_STATE
    },
    ToolzActionOutcome.OUTCOME_UNKNOWN: {
        ToolzActionOutcomeReason.OBSERVER_UNAVAILABLE,
        ToolzActionOutcomeReason.OBSERVATION_TIMEOUT,
        ToolzActionOutcomeReason.EXECUTOR_CRASH_REPORTED,
        ToolzActionOutcomeReason.TRANSPORT_LOSS_REPORTED,
    },
}


@dataclass(frozen=True)
class ToolzActionOutcomePolicy:
    """Exact authority, observer and bounded timing contract."""

    policy_id: str
    authority_policy: ToolzAuthorityPolicy
    observer_id: str
    observer_artifact_digest: str
    max_observation_start_delay_seconds: int = 5
    max_observation_duration_seconds: int = 60
    max_signing_delay_seconds: int = 10

    def __post_init__(self) -> None:
        _require_id(self.policy_id, "policy id", synthetic=True)
        if not isinstance(self.authority_policy, ToolzAuthorityPolicy):
            raise ToolzActionOutcomeError("Toolzs outcome authority policy rejected")
        _require_id(self.observer_id, "observer id", synthetic=True)
        _require_digest(self.observer_artifact_digest, "observer artifact")
        for field, value, minimum, maximum in (
            (
                "observation start delay",
                self.max_observation_start_delay_seconds,
                0,
                30,
            ),
            (
                "observation duration",
                self.max_observation_duration_seconds,
                1,
                300,
            ),
            ("signing delay", self.max_signing_delay_seconds, 0, 60),
        ):
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or not minimum <= value <= maximum
            ):
                raise ToolzActionOutcomeError(f"Toolzs outcome {field} rejected")


@dataclass(frozen=True)
class ToolzActionOutcomeObservation:
    """One verified independent post-action state classification."""

    observation: dict[str, Any]
    outcome: ToolzActionOutcome

    @property
    def execution_performed(self) -> bool:
        return False

    @property
    def external_action_causality_proven(self) -> bool:
        return False

    @property
    def production_authority(self) -> bool:
        return False


def _require_id(value: object, field: str, *, synthetic: bool = False) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise ToolzActionOutcomeError(f"Toolzs outcome {field} rejected")
    if synthetic and "synthetic" not in value:
        raise ToolzActionOutcomeError(f"Toolzs outcome {field} rejected")
    return value


def _require_digest(value: object, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ToolzActionOutcomeError(f"Toolzs outcome {field} rejected")
    return value


def _parse_time(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise ToolzActionOutcomeError(f"Toolzs outcome {field} rejected")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ToolzActionOutcomeError(f"Toolzs outcome {field} rejected") from exc
    if parsed.tzinfo is None:
        raise ToolzActionOutcomeError(f"Toolzs outcome {field} rejected")
    return parsed


def _freeze_mapping(value: Mapping[str, Any], field: str) -> dict[str, Any]:
    try:
        candidate = parse_json_strict(canonical_bytes(dict(value)))
    except Exception as exc:
        raise ToolzActionOutcomeError(f"Toolzs outcome {field} rejected") from exc
    if not isinstance(candidate, dict):
        raise ToolzActionOutcomeError(f"Toolzs outcome {field} rejected")
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
        raise ToolzActionOutcomeError(f"Toolzs outcome {field} rejected")


def _observer_document(
    policy: ToolzActionOutcomePolicy,
    observer_key: TrustedKey,
) -> dict[str, str]:
    if not isinstance(observer_key, TrustedKey):
        raise ToolzActionOutcomeError("Toolzs outcome observer key rejected")
    return {
        "observer_id": policy.observer_id,
        "observer_artifact_digest": policy.observer_artifact_digest,
        "key_id": observer_key.key_id,
        "key_fingerprint": public_key_fingerprint(observer_key.public_key),
    }


def _policy_document(policy: ToolzActionOutcomePolicy) -> dict[str, Any]:
    if not isinstance(policy, ToolzActionOutcomePolicy):
        raise ToolzActionOutcomeError("Toolzs outcome policy rejected")
    return {
        "policy_id": policy.policy_id,
        "authority_policy_digest": toolz_authority_policy_digest(
            policy.authority_policy
        ),
        "observer": {
            "observer_id": policy.observer_id,
            "observer_artifact_digest": policy.observer_artifact_digest,
        },
        "max_observation_start_delay_seconds": (
            policy.max_observation_start_delay_seconds
        ),
        "max_observation_duration_seconds": (
            policy.max_observation_duration_seconds
        ),
        "max_signing_delay_seconds": policy.max_signing_delay_seconds,
        "semantics": (
            "independent-post-consumption-state-observation-never-action-"
            "attempt-or-causality-proof"
        ),
    }


def toolz_action_outcome_policy_digest(
    policy: ToolzActionOutcomePolicy,
) -> str:
    """Return the exact observer/authority/timing policy identity."""

    return digest_object(_policy_document(policy), domain="toolz-action-outcome-policy-v1")


def _observation_core(observation: Mapping[str, Any]) -> dict[str, Any]:
    core = deepcopy(dict(observation))
    core.pop("observation_id", None)
    core.pop("signature", None)
    return core


def toolz_action_outcome_identity(
    observation: Mapping[str, Any],
) -> str:
    """Return the domain-separated identity of one unsigned observation."""

    digest = digest_object(
        _observation_core(observation),
        domain="toolz-action-outcome-observation-identity-v1",
    )
    return f"toolz-action-outcome-observation:{digest.split(':', 1)[1]}"


def toolz_action_outcome_digest(
    observation: Mapping[str, Any],
) -> str:
    """Return the exact digest of one signed outcome observation."""

    return digest_object(
        dict(observation),
        domain="toolz-action-outcome-signed-observation-v1",
    )


def _checkpoint_digest(checkpoint: Mapping[str, Any]) -> str:
    return digest_object(
        dict(checkpoint),
        domain="toolz-action-outcome-authority-checkpoint-v1",
    )


def _tool_context(evidence: ToolzAuthorizationEvidence) -> dict[str, Any]:
    try:
        return deepcopy(dict(evidence.readiness_receipt["tool_context"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise ToolzActionOutcomeError("Toolzs outcome tool context rejected") from exc


def _before_observation(evidence: ToolzAuthorizationEvidence) -> dict[str, Any]:
    try:
        observation = deepcopy(dict(evidence.witness["observation"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise ToolzActionOutcomeError("Toolzs outcome start witness rejected") from exc
    expected = {
        "state_digest",
        "zone_id",
        "state_entity_id",
        "evidence_digest",
        "observed_at",
    }
    if set(observation) != expected:
        raise ToolzActionOutcomeError("Toolzs outcome start witness rejected")
    return observation


def _verify_authorization(
    *,
    policy: ToolzActionOutcomePolicy,
    evidence: ToolzAuthorizationEvidence,
    decision: Mapping[str, Any],
    consumption: Mapping[str, Any],
    consumption_event: Mapping[str, Any],
    decision_key: TrustedKey,
    authority_ledger: ToolzAuthorityLedger,
    expected_authority_checkpoint: Mapping[str, Any],
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
    if not isinstance(evidence, ToolzAuthorizationEvidence):
        raise ToolzActionOutcomeError("Toolzs outcome authorization evidence rejected")
    if (
        not isinstance(authority_ledger, ToolzAuthorityLedger)
        or authority_ledger.policy != policy.authority_policy
    ):
        raise ToolzActionOutcomeError("Toolzs outcome authority ledger rejected")
    try:
        decision_document = _freeze_mapping(decision, "decision")
        consumption_document = _freeze_mapping(consumption, "consumption")
        checkpoint_document = _freeze_mapping(
            expected_authority_checkpoint,
            "authority checkpoint",
        )
        event_document = verify_ledger_event(
            consumption_event,
            authority_ledger.ledger_key,
            expected_tenant_id="tenant:public-6e3cdbebaafc8efa",
            expected_source_id=evidence.request["request_id"],
            expected_event_type="toolz-authorization-consumption",
            expected_payload_digest=toolz_grant_consumption_digest(
                consumption_document
            ),
        )
        verified_consumption = authority_ledger.verify_consumption_record(
            evidence=evidence,
            decision=decision_document,
            consumption=consumption_document,
            decision_key=decision_key,
            expected_checkpoint=checkpoint_document,
            used_at=consumption_document["consumed_at"],
        )
    except (
        KeyError,
        LedgerVerificationError,
        ToolzAuthorityError,
        TypeError,
        ValueError,
    ) as exc:
        raise ToolzActionOutcomeError(
            "Toolzs outcome grant consumption proof rejected"
        ) from exc
    if (
        event_document["source_sequence"] != 1
        or event_document["recorded_at"] != verified_consumption["consumed_at"]
    ):
        raise ToolzActionOutcomeError(
            "Toolzs outcome grant consumption event rejected"
        )
    return (
        decision_document,
        verified_consumption,
        event_document,
        checkpoint_document,
    )


def _assert_observer_independence(
    *,
    observer_key: TrustedKey,
    decision_key: TrustedKey,
    evidence: ToolzAuthorizationEvidence,
    authority_ledger: ToolzAuthorityLedger,
) -> None:
    if not isinstance(observer_key, TrustedKey) or not isinstance(
        decision_key, TrustedKey
    ):
        raise ToolzActionOutcomeError("Toolzs outcome trusted key rejected")
    fingerprints = {
        public_key_fingerprint(key.public_key)
        for key in (
            observer_key,
            decision_key,
            evidence.requester_key,
            authority_ledger.ledger_key,
        )
    }
    if len(fingerprints) != 4:
        raise ToolzActionOutcomeError(
            "Toolzs outcome observer is not independently anchored"
        )


def _authorization_document(
    *,
    evidence: ToolzAuthorizationEvidence,
    decision: Mapping[str, Any],
    consumption: Mapping[str, Any],
    event: Mapping[str, Any],
    checkpoint: Mapping[str, Any],
) -> dict[str, str]:
    return {
        "request_id": evidence.request["request_id"],
        "request_digest": toolz_authorization_request_digest(evidence.request),
        "readiness_receipt_digest": toolz_reuse_readiness_digest(
            evidence.readiness_receipt
        ),
        "start_witness_id": evidence.witness["witness_id"],
        "start_witness_digest": toolz_start_state_witness_digest(evidence.witness),
        "decision_id": decision["decision_id"],
        "decision_digest": toolz_authority_decision_digest(decision),
        "grant_id": decision["grant"]["grant_id"],
        "consumption_id": consumption["consumption_id"],
        "consumption_digest": toolz_grant_consumption_digest(consumption),
        "ledger_event_digest": event_digest(event),
        "checkpoint_digest": _checkpoint_digest(checkpoint),
    }


def _coerce_outcome(
    outcome: ToolzActionOutcome | str,
    reason: ToolzActionOutcomeReason | str,
) -> tuple[ToolzActionOutcome, ToolzActionOutcomeReason]:
    try:
        outcome_value = ToolzActionOutcome(outcome)
        reason_value = ToolzActionOutcomeReason(reason)
    except ValueError as exc:
        raise ToolzActionOutcomeError("Toolzs outcome classification rejected") from exc
    if reason_value not in _EXPECTED_REASON[outcome_value]:
        raise ToolzActionOutcomeError("Toolzs outcome reason rejected")
    return outcome_value, reason_value


def _state_observation(
    *,
    tool_context: Mapping[str, Any],
    state_digest: str,
    zone_id: str,
    evidence_digest: str,
    observed_at: str,
) -> dict[str, Any]:
    _require_digest(state_digest, "state digest")
    _require_id(zone_id, "zone id", synthetic=True)
    _require_digest(evidence_digest, "state evidence")
    _parse_time(observed_at, "state observation time")
    return {
        "state_digest": state_digest,
        "zone_id": zone_id,
        "state_entity_id": toolz_trace_state_entity_identity(
            tool_context=tool_context,
            state_digest=state_digest,
            zone_id=zone_id,
        ),
        "evidence_digest": evidence_digest,
        "observed_at": observed_at,
    }


def _validate_timing(
    observation: Mapping[str, Any],
    *,
    policy: ToolzActionOutcomePolicy,
    decision: Mapping[str, Any],
) -> None:
    timing = observation["timing"]
    consumed = _parse_time(timing["consumed_at"], "consumption time")
    started = _parse_time(timing["observation_started_at"], "observation start")
    completed = _parse_time(
        timing["observation_completed_at"],
        "observation completion",
    )
    created = _parse_time(timing["created_at"], "observation signing time")
    grant_expires = _parse_time(decision["grant"]["expires_at"], "grant expiry")
    if (
        consumed > started
        or (started - consumed).total_seconds()
        > policy.max_observation_start_delay_seconds
        or started >= grant_expires
        or started > completed
        or (completed - started).total_seconds()
        > policy.max_observation_duration_seconds
        or completed > created
        or (created - completed).total_seconds() > policy.max_signing_delay_seconds
    ):
        raise ToolzActionOutcomeError("Toolzs outcome timing rejected")
    after = observation["after_observation"]
    if after is not None:
        observed = _parse_time(after["observed_at"], "post-state observation time")
        if not started <= observed <= completed:
            raise ToolzActionOutcomeError(
                "Toolzs outcome post-state timing rejected"
            )


def _validate_semantics(observation: Mapping[str, Any]) -> ToolzActionOutcome:
    outcome = ToolzActionOutcome(observation["outcome"])
    reason = ToolzActionOutcomeReason(observation["reason_code"])
    if reason not in _EXPECTED_REASON[outcome]:
        raise ToolzActionOutcomeError("Toolzs outcome reason rejected")
    before = observation["before_observation"]
    after = observation["after_observation"]
    intent = observation["intent"]
    for label, state in (("before", before), ("after", after)):
        if state is None:
            continue
        try:
            expected_entity = toolz_trace_state_entity_identity(
                tool_context=observation["tool_context"],
                state_digest=state["state_digest"],
                zone_id=state["zone_id"],
            )
        except Exception as exc:
            raise ToolzActionOutcomeError(
                f"Toolzs outcome {label} state identity rejected"
            ) from exc
        if state["state_entity_id"] != expected_entity:
            raise ToolzActionOutcomeError(
                f"Toolzs outcome {label} state identity mismatch"
            )
    state_change: bool | None
    if outcome is ToolzActionOutcome.OUTCOME_UNKNOWN:
        if after is not None or observation["gap_evidence_digest"] is None:
            raise ToolzActionOutcomeError("Toolzs unknown outcome evidence rejected")
        state_change = None
    else:
        if after is None or observation["gap_evidence_digest"] is not None:
            raise ToolzActionOutcomeError("Toolzs observed outcome evidence rejected")
        expected = (
            after["state_entity_id"] == intent["to_entity_id"]
            and after["zone_id"] == intent["to_zone_id"]
        )
        retained = (
            after["state_digest"] == before["state_digest"]
            and after["state_entity_id"] == before["state_entity_id"]
            and after["zone_id"] == before["zone_id"]
        )
        if outcome is ToolzActionOutcome.EXPECTED_TRANSITION_OBSERVED:
            if not expected or retained:
                raise ToolzActionOutcomeError(
                    "Toolzs expected transition observation rejected"
                )
            state_change = True
        elif outcome is ToolzActionOutcome.PRE_STATE_RETAINED:
            if not retained:
                raise ToolzActionOutcomeError(
                    "Toolzs retained pre-state observation rejected"
                )
            state_change = False
        else:
            if expected or retained:
                raise ToolzActionOutcomeError(
                    "Toolzs unexpected state observation rejected"
                )
            state_change = True
    if observation["authority_boundary"]["state_change_observed"] is not state_change:
        raise ToolzActionOutcomeError("Toolzs outcome state-change claim rejected")
    return outcome


def verify_toolz_action_outcome_observation(
    observation: Mapping[str, Any],
    *,
    policy: ToolzActionOutcomePolicy,
    evidence: ToolzAuthorizationEvidence,
    decision: Mapping[str, Any],
    consumption: Mapping[str, Any],
    consumption_event: Mapping[str, Any],
    decision_key: TrustedKey,
    authority_ledger: ToolzAuthorityLedger,
    expected_authority_checkpoint: Mapping[str, Any],
    observer_key: TrustedKey,
) -> dict[str, Any]:
    """Verify one outcome against the full a13 proof and independent observer."""

    if not isinstance(policy, ToolzActionOutcomePolicy):
        raise ToolzActionOutcomeError("Toolzs outcome policy rejected")
    _assert_observer_independence(
        observer_key=observer_key,
        decision_key=decision_key,
        evidence=evidence,
        authority_ledger=authority_ledger,
    )
    (
        decision_document,
        consumption_document,
        event_document,
        checkpoint_document,
    ) = _verify_authorization(
        policy=policy,
        evidence=evidence,
        decision=decision,
        consumption=consumption,
        consumption_event=consumption_event,
        decision_key=decision_key,
        authority_ledger=authority_ledger,
        expected_authority_checkpoint=expected_authority_checkpoint,
    )
    try:
        candidate = _freeze_mapping(observation, "observation")
        validate("toolz-action-outcome-observation", candidate)
    except (KeyError, ValidationError, TypeError, ValueError) as exc:
        if isinstance(exc, ToolzActionOutcomeError):
            raise
        raise ToolzActionOutcomeError("Toolzs outcome schema rejected") from exc
    if candidate["observation_id"] != toolz_action_outcome_identity(candidate):
        raise ToolzActionOutcomeError("Toolzs outcome identity mismatch")
    if (
        candidate["signature"]["key_id"] != observer_key.key_id
        or not verify_signature(candidate, observer_key.public_key)
    ):
        raise ToolzActionOutcomeError("Toolzs outcome signature rejected")
    expected = {
        "tenant_id": "tenant:public-6e3cdbebaafc8efa",
        "policy_id": policy.policy_id,
        "policy_digest": toolz_action_outcome_policy_digest(policy),
        "authorization": _authorization_document(
            evidence=evidence,
            decision=decision_document,
            consumption=consumption_document,
            event=event_document,
            checkpoint=checkpoint_document,
        ),
        "tool_context": _tool_context(evidence),
        "intent": deepcopy(dict(evidence.request["intent"])),
        "observer": _observer_document(policy, observer_key),
        "before_observation": _before_observation(evidence),
        "privacy_boundary": _PRIVACY_BOUNDARY,
    }
    for field, value in expected.items():
        if candidate[field] != value:
            raise ToolzActionOutcomeError(f"Toolzs outcome {field} mismatch")
    expected_boundary = {
        **_AUTHORITY_BOUNDARY_BASE,
        "state_change_observed": candidate["authority_boundary"][
            "state_change_observed"
        ],
    }
    if candidate["authority_boundary"] != expected_boundary:
        raise ToolzActionOutcomeError("Toolzs outcome authority boundary mismatch")
    if candidate["timing"]["consumed_at"] != consumption_document["consumed_at"]:
        raise ToolzActionOutcomeError("Toolzs outcome consumption time mismatch")
    _validate_timing(candidate, policy=policy, decision=decision_document)
    _validate_semantics(candidate)
    return candidate


def build_toolz_action_outcome_observation(
    *,
    policy: ToolzActionOutcomePolicy,
    evidence: ToolzAuthorizationEvidence,
    decision: Mapping[str, Any],
    consumption: Mapping[str, Any],
    consumption_event: Mapping[str, Any],
    decision_key: TrustedKey,
    authority_ledger: ToolzAuthorityLedger,
    expected_authority_checkpoint: Mapping[str, Any],
    outcome: ToolzActionOutcome | str,
    reason: ToolzActionOutcomeReason | str,
    observation_started_at: str,
    observation_completed_at: str,
    created_at: str,
    observer_key: TrustedKey,
    observer_signer: Ed25519Signer,
    after_state_digest: str | None = None,
    after_zone_id: str | None = None,
    after_evidence_digest: str | None = None,
    after_observed_at: str | None = None,
    gap_evidence_digest: str | None = None,
) -> ToolzActionOutcomeObservation:
    """Sign caller-supplied post-state evidence without invoking the Toolz."""

    if not isinstance(policy, ToolzActionOutcomePolicy):
        raise ToolzActionOutcomeError("Toolzs outcome policy rejected")
    _assert_signer(observer_signer, observer_key, "observer signer")
    _assert_observer_independence(
        observer_key=observer_key,
        decision_key=decision_key,
        evidence=evidence,
        authority_ledger=authority_ledger,
    )
    outcome_value, reason_value = _coerce_outcome(outcome, reason)
    (
        decision_document,
        consumption_document,
        event_document,
        checkpoint_document,
    ) = _verify_authorization(
        policy=policy,
        evidence=evidence,
        decision=decision,
        consumption=consumption,
        consumption_event=consumption_event,
        decision_key=decision_key,
        authority_ledger=authority_ledger,
        expected_authority_checkpoint=expected_authority_checkpoint,
    )
    tool_context = _tool_context(evidence)
    after_values = (
        after_state_digest,
        after_zone_id,
        after_evidence_digest,
        after_observed_at,
    )
    if outcome_value is ToolzActionOutcome.OUTCOME_UNKNOWN:
        if any(value is not None for value in after_values):
            raise ToolzActionOutcomeError("Toolzs unknown outcome state rejected")
        _require_digest(gap_evidence_digest, "unknown evidence")
        after_observation = None
        state_change: bool | None = None
    else:
        if any(value is None for value in after_values):
            raise ToolzActionOutcomeError("Toolzs observed outcome state rejected")
        if gap_evidence_digest is not None:
            raise ToolzActionOutcomeError("Toolzs observed outcome gap rejected")
        assert after_state_digest is not None
        assert after_zone_id is not None
        assert after_evidence_digest is not None
        assert after_observed_at is not None
        after_observation = _state_observation(
            tool_context=tool_context,
            state_digest=after_state_digest,
            zone_id=after_zone_id,
            evidence_digest=after_evidence_digest,
            observed_at=after_observed_at,
        )
        state_change = outcome_value is not ToolzActionOutcome.PRE_STATE_RETAINED
    core = {
        "protocol": "integrity-guardian/toolz-action-outcome-observation/v1",
        "tenant_id": "tenant:public-6e3cdbebaafc8efa",
        "policy_id": policy.policy_id,
        "policy_digest": toolz_action_outcome_policy_digest(policy),
        "authorization": _authorization_document(
            evidence=evidence,
            decision=decision_document,
            consumption=consumption_document,
            event=event_document,
            checkpoint=checkpoint_document,
        ),
        "tool_context": tool_context,
        "intent": deepcopy(dict(evidence.request["intent"])),
        "observer": _observer_document(policy, observer_key),
        "outcome": outcome_value.value,
        "reason_code": reason_value.value,
        "before_observation": _before_observation(evidence),
        "after_observation": after_observation,
        "gap_evidence_digest": gap_evidence_digest,
        "timing": {
            "consumed_at": consumption_document["consumed_at"],
            "observation_started_at": observation_started_at,
            "observation_completed_at": observation_completed_at,
            "created_at": created_at,
        },
        "privacy_boundary": deepcopy(_PRIVACY_BOUNDARY),
        "authority_boundary": {
            **deepcopy(_AUTHORITY_BOUNDARY_BASE),
            "state_change_observed": state_change,
        },
    }
    _validate_timing(core, policy=policy, decision=decision_document)
    _validate_semantics(core)
    unsigned = {
        "observation_id": toolz_action_outcome_identity(core),
        **core,
    }
    signed = observer_signer.sign(unsigned)
    verified = verify_toolz_action_outcome_observation(
        signed,
        policy=policy,
        evidence=evidence,
        decision=decision_document,
        consumption=consumption_document,
        consumption_event=event_document,
        decision_key=decision_key,
        authority_ledger=authority_ledger,
        expected_authority_checkpoint=checkpoint_document,
        observer_key=observer_key,
    )
    return ToolzActionOutcomeObservation(
        observation=verified,
        outcome=outcome_value,
    )
