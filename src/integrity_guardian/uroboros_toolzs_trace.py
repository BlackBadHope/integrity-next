"""Sanitized external-action trace ingress for Integrity 5.5 Uroboros.

The module turns one already completed, observer-signed action trace into the
existing Fog of War discovery-record protocol.  It does not observe a UI,
invoke a tool, control a browser, store data, access a network or authorize
replay.  A caller must minimize private source material before constructing the
closed trace shape.
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

from .canonical import CanonicalizationError, canonical_bytes, parse_json_strict
from .discovery import (
    CoverageState,
    DiscoveryCursor,
    DiscoveryEmitter,
    DiscoveryProvenance,
    build_entity_assertion,
    build_relation_assertion,
)
from .hashing import digest_object
from .schemas import validate
from .security_admission import SecurityArtifact, SecurityEnvironment
from .signing import Ed25519Signer, TrustedKey, verify_signature

MAX_TOOLZ_ACTION_TRACE_STEPS = 32
TOOLZ_TRACE_RELATION_TYPE = "relation-type:synthetic-toolz-transition"
TOOLZ_TRACE_ENTITY_TYPE = "entity-type:synthetic-toolz-state"

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_TRACE_AUTHORITY_BOUNDARY = {
    "browser_control": False,
    "credentials": False,
    "execution": False,
    "global_publish": False,
    "model_sdk": False,
    "network": False,
    "production_authority": False,
    "raw_ui_data": False,
    "storage": False,
    "tool_invocation": False,
}
_TRACE_PRIVACY_BOUNDARY = {
    "cookies": False,
    "credentials": False,
    "dom": False,
    "form_values": False,
    "free_text": False,
    "screenshots": False,
    "selectors": False,
    "urls": False,
}


class ToolzActionTraceError(ValueError):
    """Raised when a Toolzs action trace violates the fail-closed contract."""


class ToolzActionClass(StrEnum):
    """Privacy-safe action taxonomy; parameters remain opaque digests."""

    OBSERVE = "observe"
    NAVIGATE = "navigate"
    ACTIVATE = "activate"
    INPUT = "input"
    SUBMIT = "submit"
    WAIT = "wait"
    EXTERNAL_CALL = "external-call"


def _require_id(value: object, field: str, *, synthetic: bool = False) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise ToolzActionTraceError(f"Toolzs trace {field} rejected")
    if synthetic and "synthetic" not in value:
        raise ToolzActionTraceError(f"Toolzs trace {field} rejected")
    return value


def _require_digest(value: object, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ToolzActionTraceError(f"Toolzs trace {field} rejected")
    return value


def _parse_time(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise ToolzActionTraceError(f"Toolzs trace {field} rejected")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ToolzActionTraceError(f"Toolzs trace {field} rejected") from exc
    if parsed.tzinfo is None:
        raise ToolzActionTraceError(f"Toolzs trace {field} rejected")
    return parsed


def _detached_json(value: object, field: str) -> dict[str, Any]:
    """Take one canonical JSON snapshot of a caller-owned mapping."""

    try:
        detached = parse_json_strict(canonical_bytes(value))
    except (CanonicalizationError, TypeError, ValueError) as exc:
        raise ToolzActionTraceError(f"Toolzs trace {field} rejected") from exc
    if not isinstance(detached, dict):
        raise ToolzActionTraceError(f"Toolzs trace {field} rejected")
    return detached


@dataclass(frozen=True)
class ToolzActionTracePolicy:
    """Exact local trace observer, projection source and Toolz context."""

    policy_id: str
    subject: SecurityArtifact
    environment: SecurityEnvironment
    ui_context_digest: str
    observer_id: str
    observer_artifact_digest: str
    discovery_source_id: str
    discovery_source_epoch: str
    discovery_source_artifact_digest: str
    max_steps: int = 16
    max_duration_seconds: int = 3_600

    def __post_init__(self) -> None:
        _require_id(self.policy_id, "policy id", synthetic=True)
        if not isinstance(self.subject, SecurityArtifact):
            raise ToolzActionTraceError("Toolzs trace subject rejected")
        if not isinstance(self.environment, SecurityEnvironment):
            raise ToolzActionTraceError("Toolzs trace environment rejected")
        _require_id(self.subject.artifact_id, "artifact id", synthetic=True)
        _require_id(self.environment.profile_id, "environment profile", synthetic=True)
        _require_digest(self.ui_context_digest, "UI context")
        _require_id(self.observer_id, "observer id", synthetic=True)
        _require_digest(self.observer_artifact_digest, "observer artifact")
        _require_id(self.discovery_source_id, "discovery source id", synthetic=True)
        _require_id(self.discovery_source_epoch, "discovery source epoch", synthetic=True)
        _require_digest(
            self.discovery_source_artifact_digest,
            "discovery source artifact",
        )
        if (
            not isinstance(self.max_steps, int)
            or isinstance(self.max_steps, bool)
            or not 1 <= self.max_steps <= MAX_TOOLZ_ACTION_TRACE_STEPS
        ):
            raise ToolzActionTraceError("Toolzs trace step limit rejected")
        if (
            not isinstance(self.max_duration_seconds, int)
            or isinstance(self.max_duration_seconds, bool)
            or not 1 <= self.max_duration_seconds <= 86_400
        ):
            raise ToolzActionTraceError("Toolzs trace duration limit rejected")


@dataclass(frozen=True)
class ToolzActionStep:
    """One minimized, observed state transition."""

    action_class: ToolzActionClass
    operation_digest: str
    before_state_digest: str
    after_state_digest: str
    before_zone_id: str
    after_zone_id: str
    observed_at: str
    evidence_digest: str
    confidence_ppm: int = 1_000_000

    def __post_init__(self) -> None:
        if not isinstance(self.action_class, ToolzActionClass):
            raise ToolzActionTraceError("Toolzs trace action class rejected")
        _require_digest(self.operation_digest, "operation digest")
        _require_digest(self.before_state_digest, "before-state digest")
        _require_digest(self.after_state_digest, "after-state digest")
        _require_id(self.before_zone_id, "before-zone id", synthetic=True)
        _require_id(self.after_zone_id, "after-zone id", synthetic=True)
        _parse_time(self.observed_at, "observation time")
        _require_digest(self.evidence_digest, "evidence digest")
        if (
            not isinstance(self.confidence_ppm, int)
            or isinstance(self.confidence_ppm, bool)
            or not 1 <= self.confidence_ppm <= 1_000_000
        ):
            raise ToolzActionTraceError("Toolzs trace confidence rejected")
        if (
            self.before_state_digest == self.after_state_digest
            and self.before_zone_id == self.after_zone_id
        ):
            raise ToolzActionTraceError("Toolzs trace no-op transition rejected")


@dataclass(frozen=True)
class ToolzTraceProjection:
    """Signed Fog records and exact endpoints produced from one verified trace."""

    trace_id: str
    trace_digest: str
    projection_digest: str
    from_entity_id: str
    to_entity_id: str
    relation_type: str
    invalidation_zone_ids: tuple[str, ...]
    records: tuple[dict[str, Any], ...]
    next_cursor: DiscoveryCursor

    @property
    def execution_authority(self) -> bool:
        """Projection evidence can never claim action authority."""

        return False


@dataclass(frozen=True)
class ToolzTraceHop:
    """Exact deterministic identity and evidence shape of one trace hop."""

    relation_id: str
    from_entity_id: str
    to_entity_id: str
    from_zone_id: str
    to_zone_id: str
    observed_at: str
    evidence_digest: str
    confidence_ppm: int


@dataclass(frozen=True)
class ToolzTracePath:
    """Deterministic graph identity of one verified minimized trace."""

    trace_id: str
    trace_digest: str
    projection_digest: str
    from_entity_id: str
    to_entity_id: str
    hops: tuple[ToolzTraceHop, ...]
    invalidation_zone_ids: tuple[str, ...]

    @property
    def relation_ids(self) -> tuple[str, ...]:
        return tuple(hop.relation_id for hop in self.hops)

    @property
    def entity_ids(self) -> tuple[str, ...]:
        return (self.from_entity_id, *(hop.to_entity_id for hop in self.hops))


def _policy_document(policy: ToolzActionTracePolicy) -> dict[str, Any]:
    return {
        "policy_id": policy.policy_id,
        "tool_context": {
            "artifact_id": policy.subject.artifact_id,
            "artifact_digest": policy.subject.artifact_digest,
            "environment_profile_id": policy.environment.profile_id,
            "environment_fingerprint_digest": policy.environment.fingerprint_digest,
            "ui_context_digest": policy.ui_context_digest,
        },
        "observer": {
            "observer_id": policy.observer_id,
            "observer_artifact_digest": policy.observer_artifact_digest,
        },
        "projection_target": {
            "source_id": policy.discovery_source_id,
            "source_epoch": policy.discovery_source_epoch,
            "source_artifact_digest": policy.discovery_source_artifact_digest,
            "relation_type": TOOLZ_TRACE_RELATION_TYPE,
        },
        "max_steps": policy.max_steps,
        "max_duration_seconds": policy.max_duration_seconds,
        "learning_semantics": "completed-observation-to-fog-candidate-never-authority",
    }


def toolz_action_trace_policy_digest(policy: ToolzActionTracePolicy) -> str:
    """Return the exact local trace-ingress policy identity."""

    if not isinstance(policy, ToolzActionTracePolicy):
        raise ToolzActionTraceError("Toolzs trace policy rejected")
    return digest_object(_policy_document(policy), domain="toolz-action-trace-policy-v1")


def _trace_core(trace: Mapping[str, Any]) -> dict[str, Any]:
    core = deepcopy(dict(trace))
    core.pop("trace_id", None)
    core.pop("signature", None)
    return core


def toolz_action_trace_identity(trace: Mapping[str, Any]) -> str:
    """Return the domain-separated identity of one unsigned action trace."""

    digest = digest_object(
        _trace_core(trace),
        domain="toolz-action-trace-receipt-identity-v1",
    )
    return f"toolz-action-trace:{digest.split(':', 1)[1]}"


def toolz_action_trace_digest(trace: Mapping[str, Any]) -> str:
    """Return the exact signed trace digest."""

    return digest_object(dict(trace), domain="toolz-action-trace-signed-receipt-v1")


def _projection_digest(trace: Mapping[str, Any]) -> str:
    return digest_object(
        {
            "trace_id": trace["trace_id"],
            "trace_digest": toolz_action_trace_digest(trace),
            "policy_digest": trace["policy_digest"],
            "observer_coverage_digest": trace["coverage_digest"],
            "projection_target": trace["projection_target"],
        },
        domain="toolz-action-trace-fog-projection-v1",
    )


def _validate_trace_semantics(
    trace: Mapping[str, Any],
    policy: ToolzActionTracePolicy,
) -> None:
    started = _parse_time(trace["started_at"], "start time")
    completed = _parse_time(trace["completed_at"], "completion time")
    if (
        started >= completed
        or (completed - started).total_seconds() > policy.max_duration_seconds
    ):
        raise ToolzActionTraceError("Toolzs trace time window rejected")

    steps = trace["steps"]
    if not 1 <= len(steps) <= policy.max_steps:
        raise ToolzActionTraceError("Toolzs trace step count rejected")
    expected_state = trace["initial_state"]
    previous_time = started
    seen_states = {
        (expected_state["state_digest"], expected_state["zone_id"]),
    }
    for sequence, step in enumerate(steps):
        if step["sequence"] != sequence:
            raise ToolzActionTraceError("Toolzs trace sequence rejected")
        if (
            step["before_state_digest"] != expected_state["state_digest"]
            or step["before_zone_id"] != expected_state["zone_id"]
        ):
            raise ToolzActionTraceError("Toolzs trace state chain rejected")
        observed = _parse_time(step["observed_at"], "observation time")
        if not previous_time <= observed <= completed:
            raise ToolzActionTraceError("Toolzs trace observation order rejected")
        next_state = (step["after_state_digest"], step["after_zone_id"])
        if next_state in seen_states:
            raise ToolzActionTraceError("Toolzs trace cyclic state path rejected")
        seen_states.add(next_state)
        previous_time = observed
        expected_state = {
            "state_digest": step["after_state_digest"],
            "zone_id": step["after_zone_id"],
        }
    if expected_state != trace["final_state"]:
        raise ToolzActionTraceError("Toolzs trace final state rejected")


def verify_toolz_action_trace_receipt(
    trace: Mapping[str, Any],
    *,
    expected_policy: ToolzActionTracePolicy,
    observer_key: TrustedKey,
) -> dict[str, Any]:
    """Verify schema, signature, local context, continuity and privacy boundary."""

    if not isinstance(expected_policy, ToolzActionTracePolicy):
        raise ToolzActionTraceError("Toolzs trace policy rejected")
    if not isinstance(observer_key, TrustedKey):
        raise ToolzActionTraceError("Toolzs trace observer key rejected")
    try:
        candidate = _detached_json(trace, "receipt")
        validate("toolz-action-trace-receipt", candidate)
    except (KeyError, ValidationError) as exc:
        raise ToolzActionTraceError("Toolzs trace receipt schema rejected") from exc
    if candidate["trace_id"] != toolz_action_trace_identity(candidate):
        raise ToolzActionTraceError("Toolzs trace identity mismatch")
    if (
        candidate["signature"]["key_id"] != observer_key.key_id
        or not verify_signature(candidate, observer_key.public_key)
    ):
        raise ToolzActionTraceError("Toolzs trace signature rejected")
    if candidate["authority_boundary"] != _TRACE_AUTHORITY_BOUNDARY:
        raise ToolzActionTraceError("Toolzs trace authority boundary mismatch")
    if candidate["privacy_boundary"] != _TRACE_PRIVACY_BOUNDARY:
        raise ToolzActionTraceError("Toolzs trace privacy boundary mismatch")

    policy_document = _policy_document(expected_policy)
    expected = {
        "tenant_id": expected_policy.subject.tenant_id,
        "policy_id": expected_policy.policy_id,
        "policy_digest": toolz_action_trace_policy_digest(expected_policy),
        "tool_context": policy_document["tool_context"],
        "observer": policy_document["observer"],
        "projection_target": policy_document["projection_target"],
    }
    for field, value in expected.items():
        if candidate[field] != value:
            raise ToolzActionTraceError(f"Toolzs trace {field} mismatch")
    _validate_trace_semantics(candidate, expected_policy)
    return candidate


def build_toolz_action_trace_receipt(
    *,
    policy: ToolzActionTracePolicy,
    steps: tuple[ToolzActionStep, ...],
    coverage_digest: str,
    started_at: str,
    completed_at: str,
    observer_signer: Ed25519Signer,
) -> dict[str, Any]:
    """Sign one completed minimized trace without observing or executing it."""

    if not isinstance(policy, ToolzActionTracePolicy):
        raise ToolzActionTraceError("Toolzs trace policy rejected")
    if (
        not isinstance(steps, tuple)
        or not steps
        or any(not isinstance(step, ToolzActionStep) for step in steps)
    ):
        raise ToolzActionTraceError("Toolzs trace steps rejected")
    if not isinstance(observer_signer, Ed25519Signer):
        raise ToolzActionTraceError("Toolzs trace observer signer rejected")
    _require_digest(coverage_digest, "coverage digest")
    core = {
        "protocol": "integrity-guardian/toolz-action-trace-receipt/v1",
        "tenant_id": policy.subject.tenant_id,
        "policy_id": policy.policy_id,
        "policy_digest": toolz_action_trace_policy_digest(policy),
        "tool_context": _policy_document(policy)["tool_context"],
        "observer": _policy_document(policy)["observer"],
        "projection_target": _policy_document(policy)["projection_target"],
        "started_at": started_at,
        "completed_at": completed_at,
        "outcome": "observed-success",
        "coverage_digest": coverage_digest,
        "initial_state": {
            "state_digest": steps[0].before_state_digest,
            "zone_id": steps[0].before_zone_id,
        },
        "final_state": {
            "state_digest": steps[-1].after_state_digest,
            "zone_id": steps[-1].after_zone_id,
        },
        "steps": [
            {
                "sequence": sequence,
                "action_class": step.action_class.value,
                "operation_digest": step.operation_digest,
                "before_state_digest": step.before_state_digest,
                "after_state_digest": step.after_state_digest,
                "before_zone_id": step.before_zone_id,
                "after_zone_id": step.after_zone_id,
                "observed_at": step.observed_at,
                "outcome": "observed-success",
                "evidence_digest": step.evidence_digest,
                "confidence_ppm": step.confidence_ppm,
            }
            for sequence, step in enumerate(steps)
        ],
        "privacy_boundary": deepcopy(_TRACE_PRIVACY_BOUNDARY),
        "authority_boundary": deepcopy(_TRACE_AUTHORITY_BOUNDARY),
    }
    _validate_trace_semantics(core, policy)
    unsigned = {
        "trace_id": toolz_action_trace_identity(core),
        **core,
    }
    signed = observer_signer.sign(unsigned)
    return verify_toolz_action_trace_receipt(
        signed,
        expected_policy=policy,
        observer_key=TrustedKey(
            key_id=observer_signer.key_id,
            public_key=observer_signer.public_key,
        ),
    )


def toolz_trace_state_entity_identity(
    *,
    tool_context: Mapping[str, Any],
    state_digest: str,
    zone_id: str,
) -> str:
    """Return the stable Fog entity identity of one minimized Toolz UI state."""

    context = _detached_json(tool_context, "tool context")
    expected_fields = {
        "artifact_id",
        "artifact_digest",
        "environment_profile_id",
        "environment_fingerprint_digest",
        "ui_context_digest",
    }
    if set(context) != expected_fields:
        raise ToolzActionTraceError("Toolzs trace tool context rejected")
    _require_id(context["artifact_id"], "artifact id", synthetic=True)
    _require_digest(context["artifact_digest"], "artifact digest")
    _require_id(
        context["environment_profile_id"],
        "environment profile",
        synthetic=True,
    )
    _require_digest(
        context["environment_fingerprint_digest"],
        "environment fingerprint",
    )
    _require_digest(context["ui_context_digest"], "UI context")
    _require_digest(state_digest, "state digest")
    _require_id(zone_id, "zone id", synthetic=True)
    digest = digest_object(
        {
            "tool_context": context,
            "state_digest": state_digest,
            "zone_id": zone_id,
        },
        domain="toolz-action-trace-state-entity-v1",
    )
    return f"entity:synthetic-toolz-state-{digest.split(':', 1)[1]}"


def _state_entity_id(
    trace: Mapping[str, Any],
    *,
    state_digest: str,
    zone_id: str,
) -> str:
    return toolz_trace_state_entity_identity(
        tool_context=trace["tool_context"],
        state_digest=state_digest,
        zone_id=zone_id,
    )


def _transition_relation_id(
    trace: Mapping[str, Any],
    step: Mapping[str, Any],
    *,
    from_entity_id: str,
    to_entity_id: str,
) -> str:
    digest = digest_object(
        {
            "tool_context": trace["tool_context"],
            "action_class": step["action_class"],
            "operation_digest": step["operation_digest"],
            "from_entity_id": from_entity_id,
            "to_entity_id": to_entity_id,
            "before_zone_id": step["before_zone_id"],
            "after_zone_id": step["after_zone_id"],
        },
        domain="toolz-action-trace-transition-v1",
    )
    return f"relation:synthetic-toolz-transition-{digest.split(':', 1)[1]}"


def _verified_trace_path(trace: Mapping[str, Any]) -> ToolzTracePath:
    state = trace["initial_state"]
    current_entity_id = _state_entity_id(
        trace,
        state_digest=state["state_digest"],
        zone_id=state["zone_id"],
    )
    from_entity_id = current_entity_id
    hops: list[ToolzTraceHop] = []
    zones = {state["zone_id"]}
    for step in trace["steps"]:
        next_entity_id = _state_entity_id(
            trace,
            state_digest=step["after_state_digest"],
            zone_id=step["after_zone_id"],
        )
        relation_id = _transition_relation_id(
            trace,
            step,
            from_entity_id=current_entity_id,
            to_entity_id=next_entity_id,
        )
        hops.append(
            ToolzTraceHop(
                relation_id=relation_id,
                from_entity_id=current_entity_id,
                to_entity_id=next_entity_id,
                from_zone_id=step["before_zone_id"],
                to_zone_id=step["after_zone_id"],
                observed_at=step["observed_at"],
                evidence_digest=step["evidence_digest"],
                confidence_ppm=step["confidence_ppm"],
            )
        )
        zones.update((step["before_zone_id"], step["after_zone_id"]))
        current_entity_id = next_entity_id
    return ToolzTracePath(
        trace_id=trace["trace_id"],
        trace_digest=toolz_action_trace_digest(trace),
        projection_digest=_projection_digest(trace),
        from_entity_id=from_entity_id,
        to_entity_id=current_entity_id,
        hops=tuple(hops),
        invalidation_zone_ids=tuple(sorted(zones)),
    )


def describe_toolz_action_trace_path(
    trace: Mapping[str, Any],
    *,
    expected_policy: ToolzActionTracePolicy,
    observer_key: TrustedKey,
) -> ToolzTracePath:
    """Return stable graph identities after complete trace verification."""

    verified = verify_toolz_action_trace_receipt(
        trace,
        expected_policy=expected_policy,
        observer_key=observer_key,
    )
    return _verified_trace_path(verified)


def compile_toolz_action_trace(
    trace: Mapping[str, Any],
    *,
    expected_policy: ToolzActionTracePolicy,
    observer_key: TrustedKey,
    discovery_cursor: DiscoveryCursor,
    discovery_signer: Ed25519Signer,
) -> ToolzTraceProjection:
    """Project one verified trace into signed Fog records, never a replay plan."""

    verified = verify_toolz_action_trace_receipt(
        trace,
        expected_policy=expected_policy,
        observer_key=observer_key,
    )
    path = _verified_trace_path(verified)
    if not isinstance(discovery_cursor, DiscoveryCursor):
        raise ToolzActionTraceError("Toolzs trace discovery cursor rejected")
    if not isinstance(discovery_signer, Ed25519Signer):
        raise ToolzActionTraceError("Toolzs trace discovery signer rejected")
    if (
        discovery_cursor.source_id != expected_policy.discovery_source_id
        or discovery_cursor.source_epoch != expected_policy.discovery_source_epoch
    ):
        raise ToolzActionTraceError("Toolzs trace discovery cursor mismatch")

    emitter = DiscoveryEmitter(
        tenant_id=expected_policy.subject.tenant_id,
        cursor=discovery_cursor,
        signer=discovery_signer,
    )
    projection_digest = path.projection_digest
    records: list[dict[str, Any]] = []
    entity_ids: dict[tuple[str, str], str] = {}

    def emit_state(
        state_digest: str,
        zone_id: str,
        observed_at: str,
        confidence_ppm: int,
    ) -> str:
        state_key = (state_digest, zone_id)
        entity_id = entity_ids.get(state_key)
        if entity_id is not None:
            return entity_id
        entity_id = _state_entity_id(
            verified,
            state_digest=state_digest,
            zone_id=zone_id,
        )
        records.append(
            emitter.emit(
                assertion=build_entity_assertion(
                    entity_id=entity_id,
                    entity_type=TOOLZ_TRACE_ENTITY_TYPE,
                ),
                observed_at=observed_at,
                zone_id=zone_id,
                source_artifact_digest=(
                    expected_policy.discovery_source_artifact_digest
                ),
                coverage_digest=projection_digest,
                provenance=DiscoveryProvenance.OBSERVED,
                coverage=CoverageState.PARTIAL,
                confidence_ppm=confidence_ppm,
                content_digest=state_digest,
            )
        )
        entity_ids[state_key] = entity_id
        return entity_id

    first_step = verified["steps"][0]
    from_entity_id = emit_state(
        verified["initial_state"]["state_digest"],
        verified["initial_state"]["zone_id"],
        verified["started_at"],
        first_step["confidence_ppm"],
    )
    current_entity_id = from_entity_id
    for step in verified["steps"]:
        next_entity_id = emit_state(
            step["after_state_digest"],
            step["after_zone_id"],
            step["observed_at"],
            step["confidence_ppm"],
        )
        records.append(
            emitter.emit(
                assertion=build_relation_assertion(
                    relation_id=_transition_relation_id(
                        verified,
                        step,
                        from_entity_id=current_entity_id,
                        to_entity_id=next_entity_id,
                    ),
                    relation_type=TOOLZ_TRACE_RELATION_TYPE,
                    from_entity_id=current_entity_id,
                    to_entity_id=next_entity_id,
                    from_zone_id=step["before_zone_id"],
                    to_zone_id=step["after_zone_id"],
                ),
                observed_at=step["observed_at"],
                zone_id=step["before_zone_id"],
                source_artifact_digest=(
                    expected_policy.discovery_source_artifact_digest
                ),
                coverage_digest=projection_digest,
                provenance=DiscoveryProvenance.LEARNED,
                coverage=CoverageState.PARTIAL,
                confidence_ppm=step["confidence_ppm"],
                content_digest=step["evidence_digest"],
            )
        )
        current_entity_id = next_entity_id

    return ToolzTraceProjection(
        trace_id=path.trace_id,
        trace_digest=path.trace_digest,
        projection_digest=projection_digest,
        from_entity_id=path.from_entity_id,
        to_entity_id=path.to_entity_id,
        relation_type=TOOLZ_TRACE_RELATION_TYPE,
        invalidation_zone_ids=path.invalidation_zone_ids,
        records=tuple(records),
        next_cursor=emitter.cursor,
    )
