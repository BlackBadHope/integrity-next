"""Adapter-neutral execution seam for one authorized Integrity transition.

The SDK composes the existing Uroboros a13 one-use authority proof and a14
independent outcome observation.  It does not issue grants, invoke live tools,
store route memory or provide production authority.  Concrete adapters own the
transport and execution implementation behind the protocols declared here.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

from .canonical import canonical_bytes, parse_json_strict
from .hashing import digest_object
from .ledger import LedgerVerificationError, event_digest, verify_ledger_event
from .operation_audit import OperationAuditError, verify_readonly_operation_manifest
from .schemas import validate
from .signing import (
    Ed25519Signer,
    TrustedKey,
    public_key_fingerprint,
    verify_signature,
)
from .uroboros_toolzs_authority import (
    ToolzAuthorityError,
    ToolzAuthorizationEvidence,
    toolz_authority_decision_digest,
    toolz_grant_consumption_digest,
)
from .uroboros_toolzs_authority_ledger import ToolzAuthorityLedger
from .uroboros_toolzs_authorization_request import (
    toolz_authorization_request_digest,
)
from .uroboros_toolzs_outcome import (
    ToolzActionOutcome,
    ToolzActionOutcomeError,
    ToolzActionOutcomePolicy,
    toolz_action_outcome_digest,
    verify_toolz_action_outcome_observation,
)

ADAPTER_SDK_VERSION = "1.0.0a2"

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_ACTION_CLASSES = {
    "observe",
    "navigate",
    "activate",
    "input",
    "submit",
    "wait",
    "external-call",
}
_CHANNELS = {
    "api",
    "browser_control",
    "computer_use",
    "credentials",
    "network",
    "service_control",
    "shell",
}


class AdapterSdkError(RuntimeError):
    """Raised before an adapter contract can overstate execution evidence."""


class AdapterTransitionOutcome(StrEnum):
    """Closed terminal states across the authority/execution crash boundary."""

    NOT_STARTED = "not-started"
    GRANT_CONSUMED_ACTION_NOT_STARTED = "grant-consumed-action-not-started"
    CONFIRMED_SUCCESS = "confirmed-success"
    CONFIRMED_FAILURE = "confirmed-failure"
    UNKNOWN_OUTCOME = "unknown-outcome"


class AdapterReportedOutcome(StrEnum):
    """Executor-local report; never sufficient to establish the final result."""

    REPORTED_SUCCESS = "reported-success"
    REPORTED_FAILURE = "reported-failure"
    OUTCOME_UNKNOWN = "outcome-unknown"


@dataclass(frozen=True)
class VerifiedAdapterGrant:
    """Exact a13 proof admitted for one adapter envelope."""

    authorization: dict[str, Any]
    intent: dict[str, Any]


@dataclass(frozen=True)
class VerifiedAdapterWitness:
    """Exact a14 observation admitted as the independent terminal witness."""

    observation_id: str
    observation_digest: str
    observer_id: str
    observer_artifact_digest: str
    key_id: str
    key_fingerprint: str
    outcome: ToolzActionOutcome
    reason_code: str
    observation: dict[str, Any] | None = None
    policy: ToolzActionOutcomePolicy | None = None
    evidence: ToolzAuthorizationEvidence | None = None
    decision: dict[str, Any] | None = None
    consumption: dict[str, Any] | None = None
    consumption_event: dict[str, Any] | None = None
    decision_key: TrustedKey | None = None
    authority_ledger: ToolzAuthorityLedger | None = None
    expected_authority_checkpoint: dict[str, Any] | None = None
    observer_key: TrustedKey | None = None


@runtime_checkable
class ObservationAdapter(Protocol):
    """Domain adapter that returns bounded observations, never authority."""

    def observe(self, request: Mapping[str, Any]) -> Mapping[str, Any]: ...


@runtime_checkable
class ExecutionAdapter(Protocol):
    """External adapter invoked only with one verified execution envelope."""

    def execute(self, envelope: Mapping[str, Any]) -> Mapping[str, Any]: ...


@runtime_checkable
class WitnessAdapter(Protocol):
    """Independent adapter that observes the post-action state."""

    def witness(self, request: Mapping[str, Any]) -> Mapping[str, Any]: ...


def _freeze(value: Mapping[str, Any], field: str) -> dict[str, Any]:
    try:
        candidate = parse_json_strict(canonical_bytes(dict(value)))
    except Exception as exc:
        raise AdapterSdkError(f"adapter SDK {field} rejected") from exc
    if not isinstance(candidate, dict):
        raise AdapterSdkError(f"adapter SDK {field} rejected")
    return candidate


def _require_id(value: object, field: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise AdapterSdkError(f"adapter SDK {field} rejected")
    return value


def _require_digest(value: object, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise AdapterSdkError(f"adapter SDK {field} rejected")
    return value


def _parse_time(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise AdapterSdkError(f"adapter SDK {field} rejected")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise AdapterSdkError(f"adapter SDK {field} rejected") from exc
    if parsed.tzinfo is None:
        raise AdapterSdkError(f"adapter SDK {field} rejected")
    return parsed


def _identity(document: Mapping[str, Any], *, field: str, domain: str) -> str:
    core = deepcopy(dict(document))
    core.pop(field, None)
    core.pop("signature", None)
    suffix = digest_object(core, domain=domain).split(":", 1)[1]
    prefix = (
        "adapter-operation-binding"
        if field == "binding_id"
        else "adapter-target-operation"
        if field == "operation_id"
        else field.removesuffix("_id").replace("_", "-")
    )
    return f"{prefix}:{suffix}"


def _verify_signed(
    document: Mapping[str, Any],
    *,
    schema: str,
    id_field: str,
    domain: str,
    trusted_key: TrustedKey,
) -> dict[str, Any]:
    candidate = _freeze(document, schema)
    try:
        validate(schema, candidate)
    except Exception as exc:
        raise AdapterSdkError(f"adapter SDK {schema} schema rejected") from exc
    if candidate[id_field] != _identity(
        candidate,
        field=id_field,
        domain=domain,
    ):
        raise AdapterSdkError(f"adapter SDK {schema} identity mismatch")
    if (
        candidate["signature"]["key_id"] != trusted_key.key_id
        or candidate["signer_id"] != trusted_key.key_id
        or not verify_signature(candidate, trusted_key.public_key)
    ):
        raise AdapterSdkError(f"adapter SDK {schema} signature rejected")
    return candidate


def adapter_capability_manifest_digest(manifest: Mapping[str, Any]) -> str:
    return digest_object(dict(manifest), domain="adapter-capability-manifest-v1")


def build_adapter_capability_manifest(
    *,
    adapter_id: str,
    adapter_version: str,
    adapter_artifact_digest: str,
    roles: Sequence[str],
    action_classes: Sequence[str],
    declared_channels: Mapping[str, bool],
    request_schema_digest: str,
    observation_schema_digest: str,
    result_schema_digest: str,
    max_timeout_seconds: int,
    max_output_bytes: int,
    credential_delivery: str,
    created_at: str,
    signer: Ed25519Signer,
) -> dict[str, Any]:
    """Sign one adapter declaration; declared capability is not authority."""

    _require_id(adapter_id, "adapter id")
    _require_digest(adapter_artifact_digest, "adapter artifact digest")
    _parse_time(created_at, "manifest creation time")
    channels = _freeze(declared_channels, "declared channels")
    if set(channels) != _CHANNELS or any(
        not isinstance(value, bool) for value in channels.values()
    ):
        raise AdapterSdkError("adapter SDK declared channels rejected")
    for value, field in (
        (request_schema_digest, "request schema digest"),
        (observation_schema_digest, "observation schema digest"),
        (result_schema_digest, "result schema digest"),
    ):
        _require_digest(value, field)
    if (
        not isinstance(max_timeout_seconds, int)
        or isinstance(max_timeout_seconds, bool)
        or not 1 <= max_timeout_seconds <= 86400
        or not isinstance(max_output_bytes, int)
        or isinstance(max_output_bytes, bool)
        or not 1 <= max_output_bytes <= 16777216
        or credential_delivery not in {"none", "reference-only"}
    ):
        raise AdapterSdkError("adapter SDK interface contract rejected")
    if channels["credentials"] is False and credential_delivery != "none":
        raise AdapterSdkError("adapter SDK credential declaration mismatch")
    normalized_roles = sorted(set(roles))
    normalized_actions = sorted(set(action_classes))
    if (
        not normalized_roles
        or not normalized_actions
        or not set(normalized_actions) <= _ACTION_CLASSES
    ):
        raise AdapterSdkError("adapter SDK roles or action classes rejected")
    core = {
        "protocol": "integrity-guardian/adapter-capability-manifest/v1",
        "sdk_version": ADAPTER_SDK_VERSION,
        "adapter_id": adapter_id,
        "adapter_version": adapter_version,
        "adapter_artifact_digest": adapter_artifact_digest,
        "roles": normalized_roles,
        "action_classes": normalized_actions,
        "declared_channels": channels,
        "interface_contract": {
            "request_schema_digest": request_schema_digest,
            "observation_schema_digest": observation_schema_digest,
            "result_schema_digest": result_schema_digest,
            "max_timeout_seconds": max_timeout_seconds,
            "max_output_bytes": max_output_bytes,
            "credential_delivery": credential_delivery,
        },
        "limits": {
            "max_transitions_per_grant": 1,
            "replay_allowed": False,
            "automatic_retry_after_unknown": False,
            "route_memory_write": False,
            "production_authority": False,
        },
        "created_at": created_at,
        "signer_id": signer.key_id,
    }
    unsigned = {
        "manifest_id": _identity(
            core,
            field="manifest_id",
            domain="adapter-capability-manifest-identity-v1",
        ),
        **core,
    }
    signed = signer.sign(unsigned)
    validate("adapter-capability-manifest", signed)
    return signed


def verify_adapter_capability_manifest(
    manifest: Mapping[str, Any],
    *,
    adapter_key: TrustedKey,
) -> dict[str, Any]:
    candidate = _verify_signed(
        manifest,
        schema="adapter-capability-manifest",
        id_field="manifest_id",
        domain="adapter-capability-manifest-identity-v1",
        trusted_key=adapter_key,
    )
    if candidate["sdk_version"] != ADAPTER_SDK_VERSION:
        raise AdapterSdkError("adapter SDK version mismatch")
    return candidate


def adapter_action_proposal_digest(proposal: Mapping[str, Any]) -> str:
    return digest_object(dict(proposal), domain="adapter-action-proposal-v1")


def adapter_target_operation_digest(operation: Mapping[str, Any]) -> str:
    """Return the exact signed target-operation document digest."""

    return digest_object(dict(operation), domain="adapter-target-operation-v1")


def build_adapter_target_operation(
    *,
    manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    intent_operation_digest: str,
    target_node_id: str,
    target_zone_id: str,
    target_kind: str,
    environment_digest: str,
    before_state_digest: str,
    expected_after_state_digest: str,
    payload_schema_id: str,
    payload_schema_digest: str,
    payload_document_digest: str,
    blast_radius_kind: str,
    allowed_resource_ids: Sequence[str],
    required_channels: Mapping[str, bool],
    created_at: str,
    signer: Ed25519Signer,
) -> dict[str, Any]:
    """Sign adapter-specific semantics without creating another lifecycle."""

    verified_manifest = verify_adapter_capability_manifest(
        manifest,
        adapter_key=adapter_key,
    )
    for value, field in (
        (intent_operation_digest, "intent operation digest"),
        (environment_digest, "environment digest"),
        (before_state_digest, "before state digest"),
        (expected_after_state_digest, "expected state digest"),
        (payload_schema_digest, "payload schema digest"),
        (payload_document_digest, "payload document digest"),
    ):
        _require_digest(value, field)
    for value, field in (
        (target_node_id, "target node id"),
        (target_zone_id, "target zone id"),
        (payload_schema_id, "payload schema id"),
    ):
        _require_id(value, field)
    channels = _freeze(required_channels, "target operation channels")
    if set(channels) != _CHANNELS or any(
        not isinstance(value, bool) for value in channels.values()
    ):
        raise AdapterSdkError("adapter SDK target operation channels rejected")
    if any(
        channels[name] and not verified_manifest["declared_channels"][name] for name in channels
    ):
        raise AdapterSdkError("adapter SDK target operation channel unsupported")
    resources = list(allowed_resource_ids)
    if not resources or resources != sorted(set(resources)) or len(resources) > 256:
        raise AdapterSdkError("adapter SDK target blast radius rejected")
    for resource in resources:
        _require_id(resource, "blast radius resource id")
    _parse_time(created_at, "target operation creation time")
    core = {
        "protocol": "integrity-guardian/adapter-target-operation/v1",
        "sdk_version": ADAPTER_SDK_VERSION,
        "tenant_id": "tenant:public-6e3cdbebaafc8efa",
        "manifest": {
            "manifest_id": verified_manifest["manifest_id"],
            "manifest_digest": adapter_capability_manifest_digest(verified_manifest),
            "adapter_id": verified_manifest["adapter_id"],
            "adapter_artifact_digest": verified_manifest["adapter_artifact_digest"],
        },
        "intent_operation_digest": intent_operation_digest,
        "target": {
            "node_id": target_node_id,
            "zone_id": target_zone_id,
            "kind": target_kind,
            "environment_digest": environment_digest,
            "before_state_digest": before_state_digest,
            "expected_after_state_digest": expected_after_state_digest,
        },
        "payload": {
            "schema_id": payload_schema_id,
            "schema_digest": payload_schema_digest,
            "document_digest": payload_document_digest,
        },
        "blast_radius": {
            "resource_kind": blast_radius_kind,
            "allowed_resource_ids": resources,
            "allowed_resource_set_digest": digest_object(
                resources,
                domain="adapter-target-operation-resource-set-v1",
            ),
            "max_resources": len(resources),
        },
        "required_channels": channels,
        "controls": {
            "max_invocations": 1,
            "operation_substitution_allowed": False,
            "automatic_retry_after_unknown": False,
            "home_input": False,
            "memory_write": False,
            "production_authority": False,
        },
        "created_at": created_at,
        "signer_id": signer.key_id,
    }
    unsigned = {
        "operation_id": _identity(
            core,
            field="operation_id",
            domain="adapter-target-operation-identity-v1",
        ),
        **core,
    }
    signed = signer.sign(unsigned)
    validate("adapter-target-operation", signed)
    return signed


def verify_adapter_target_operation(
    operation: Mapping[str, Any],
    *,
    manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    operation_key: TrustedKey,
) -> dict[str, Any]:
    candidate = _verify_signed(
        operation,
        schema="adapter-target-operation",
        id_field="operation_id",
        domain="adapter-target-operation-identity-v1",
        trusted_key=operation_key,
    )
    verified_manifest = verify_adapter_capability_manifest(
        manifest,
        adapter_key=adapter_key,
    )
    if candidate["manifest"] != {
        "manifest_id": verified_manifest["manifest_id"],
        "manifest_digest": adapter_capability_manifest_digest(verified_manifest),
        "adapter_id": verified_manifest["adapter_id"],
        "adapter_artifact_digest": verified_manifest["adapter_artifact_digest"],
    }:
        raise AdapterSdkError("adapter SDK target operation manifest mismatch")
    resources = candidate["blast_radius"]["allowed_resource_ids"]
    if (
        resources != sorted(set(resources))
        or candidate["blast_radius"]["max_resources"] != len(resources)
        or candidate["blast_radius"]["allowed_resource_set_digest"]
        != digest_object(
            resources,
            domain="adapter-target-operation-resource-set-v1",
        )
    ):
        raise AdapterSdkError("adapter SDK target operation blast radius mismatch")
    if any(
        candidate["required_channels"][name] and not verified_manifest["declared_channels"][name]
        for name in _CHANNELS
    ):
        raise AdapterSdkError("adapter SDK target operation channel mismatch")
    return candidate


def build_adapter_action_proposal(
    *,
    manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    intent: Mapping[str, Any],
    expected_after_state_digest: str,
    required_channels: Mapping[str, bool],
    proposed_at: str,
    expires_at: str,
    proposer_id: str,
    proposer_artifact_digest: str,
    signer: Ed25519Signer,
) -> dict[str, Any]:
    """Bind a parameter-free action proposal to one adapter and route intent."""

    verified_manifest = verify_adapter_capability_manifest(manifest, adapter_key=adapter_key)
    intent_document = _freeze(intent, "intent")
    required_intent = {
        "route_proposal_id",
        "route_digest",
        "hop_index",
        "action_class",
        "operation_digest",
        "relation_id",
        "from_entity_id",
        "to_entity_id",
        "from_zone_id",
        "to_zone_id",
    }
    if set(intent_document) != required_intent or intent_document["hop_index"] != 0:
        raise AdapterSdkError("adapter SDK intent rejected")
    if intent_document["action_class"] not in verified_manifest["action_classes"]:
        raise AdapterSdkError("adapter SDK action class unsupported")
    channels = _freeze(required_channels, "required channels")
    if set(channels) != set(verified_manifest["declared_channels"]) or any(
        not isinstance(value, bool) for value in channels.values()
    ):
        raise AdapterSdkError("adapter SDK required channels rejected")
    if any(
        channels[name] and not verified_manifest["declared_channels"][name] for name in channels
    ):
        raise AdapterSdkError("adapter SDK undeclared channel requested")
    _require_digest(expected_after_state_digest, "expected state digest")
    _require_id(proposer_id, "proposer id")
    _require_digest(proposer_artifact_digest, "proposer artifact digest")
    if _parse_time(expires_at, "proposal expiry") <= _parse_time(
        proposed_at, "proposal creation time"
    ):
        raise AdapterSdkError("adapter SDK proposal timing rejected")
    core = {
        "protocol": "integrity-guardian/adapter-action-proposal/v1",
        "sdk_version": ADAPTER_SDK_VERSION,
        "tenant_id": "tenant:public-6e3cdbebaafc8efa",
        "manifest": {
            "manifest_id": verified_manifest["manifest_id"],
            "manifest_digest": adapter_capability_manifest_digest(verified_manifest),
            "adapter_id": verified_manifest["adapter_id"],
            "adapter_artifact_digest": verified_manifest["adapter_artifact_digest"],
        },
        "proposer": {
            "proposer_id": proposer_id,
            "proposer_artifact_digest": proposer_artifact_digest,
        },
        "intent": intent_document,
        "expected_transition": {
            "state_digest": expected_after_state_digest,
            "entity_id": intent_document["to_entity_id"],
            "zone_id": intent_document["to_zone_id"],
        },
        "required_channels": channels,
        "scope": {
            "max_transitions": 1,
            "replay_allowed": False,
            "automatic_retry_after_unknown": False,
            "production_authority_requested": False,
        },
        "proposed_at": proposed_at,
        "expires_at": expires_at,
        "signer_id": signer.key_id,
    }
    unsigned = {
        "proposal_id": _identity(
            core,
            field="proposal_id",
            domain="adapter-action-proposal-identity-v1",
        ),
        **core,
    }
    signed = signer.sign(unsigned)
    validate("adapter-action-proposal", signed)
    return signed


def verify_adapter_action_proposal(
    proposal: Mapping[str, Any],
    *,
    manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    proposer_key: TrustedKey,
    used_at: str,
) -> dict[str, Any]:
    candidate = _verify_signed(
        proposal,
        schema="adapter-action-proposal",
        id_field="proposal_id",
        domain="adapter-action-proposal-identity-v1",
        trusted_key=proposer_key,
    )
    verified_manifest = verify_adapter_capability_manifest(manifest, adapter_key=adapter_key)
    if candidate["manifest"] != {
        "manifest_id": verified_manifest["manifest_id"],
        "manifest_digest": adapter_capability_manifest_digest(verified_manifest),
        "adapter_id": verified_manifest["adapter_id"],
        "adapter_artifact_digest": verified_manifest["adapter_artifact_digest"],
    }:
        raise AdapterSdkError("adapter SDK proposal manifest binding mismatch")
    current = _parse_time(used_at, "proposal use time")
    if (
        not _parse_time(candidate["proposed_at"], "proposal time")
        <= current
        < _parse_time(candidate["expires_at"], "proposal expiry")
    ):
        raise AdapterSdkError("adapter SDK proposal is not current")
    return candidate


def _authority_checkpoint_digest(checkpoint: Mapping[str, Any]) -> str:
    # Keep the exact a14 domain so adapter and observer bind the same checkpoint.
    return digest_object(
        dict(checkpoint),
        domain="toolz-action-outcome-authority-checkpoint-v1",
    )


def verify_toolz_grant_for_adapter(
    *,
    evidence: ToolzAuthorizationEvidence,
    decision: Mapping[str, Any],
    consumption: Mapping[str, Any],
    consumption_event: Mapping[str, Any],
    decision_key: TrustedKey,
    authority_ledger: ToolzAuthorityLedger,
    expected_authority_checkpoint: Mapping[str, Any],
) -> VerifiedAdapterGrant:
    """Admit the exact a13 sequence-1 proof; never consume or execute again."""

    if not isinstance(evidence, ToolzAuthorizationEvidence) or not isinstance(
        authority_ledger, ToolzAuthorityLedger
    ):
        raise AdapterSdkError("adapter SDK authority context rejected")
    try:
        decision_document = _freeze(decision, "decision")
        consumption_document = _freeze(consumption, "consumption")
        checkpoint_document = _freeze(expected_authority_checkpoint, "authority checkpoint")
        event_document = verify_ledger_event(
            consumption_event,
            authority_ledger.ledger_key,
            expected_tenant_id="tenant:public-6e3cdbebaafc8efa",
            expected_source_id=evidence.request["request_id"],
            expected_event_type="toolz-authorization-consumption",
            expected_payload_digest=toolz_grant_consumption_digest(consumption_document),
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
        raise AdapterSdkError("adapter SDK a13 grant proof rejected") from exc
    if (
        event_document["source_sequence"] != 1
        or event_document["recorded_at"] != verified_consumption["consumed_at"]
    ):
        raise AdapterSdkError("adapter SDK a13 consumption event rejected")
    request = _freeze(evidence.request, "authorization request")
    grant = decision_document.get("grant")
    if not isinstance(grant, dict):
        raise AdapterSdkError("adapter SDK a13 grant rejected")
    authorization = {
        "request_id": request["request_id"],
        "request_digest": toolz_authorization_request_digest(request),
        "decision_id": decision_document["decision_id"],
        "decision_digest": toolz_authority_decision_digest(decision_document),
        "grant_id": grant["grant_id"],
        "consumption_id": verified_consumption["consumption_id"],
        "consumption_digest": toolz_grant_consumption_digest(verified_consumption),
        "ledger_event_digest": event_digest(event_document),
        "checkpoint_digest": _authority_checkpoint_digest(checkpoint_document),
        "consumed_at": verified_consumption["consumed_at"],
    }
    return VerifiedAdapterGrant(
        authorization=authorization,
        intent=_freeze(request["intent"], "authorization intent"),
    )


def adapter_execution_envelope_digest(envelope: Mapping[str, Any]) -> str:
    return digest_object(dict(envelope), domain="adapter-execution-envelope-v1")


def adapter_operation_binding_digest(binding: Mapping[str, Any]) -> str:
    return digest_object(dict(binding), domain="adapter-operation-binding-v1")


def _operation_binding_reference(binding: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "binding_id": binding["binding_id"],
        "binding_digest": adapter_operation_binding_digest(binding),
        "conformance_receipt_id": binding["conformance"]["receipt_id"],
        "conformance_receipt_digest": binding["conformance"]["receipt_digest"],
        "conformance_readiness": binding["conformance"]["readiness"],
        "operation_kind": binding["operation"]["kind"],
        "operation_manifest_id": binding["operation"]["manifest_id"],
        "operation_manifest_digest": binding["operation"]["manifest_digest"],
        "executor_id": binding["executor"]["executor_id"],
        "executor_artifact_digest": binding["executor"]["executor_artifact_digest"],
        "executor_key_id": binding["executor"]["key_id"],
    }


def _verify_operation_for_binding(
    operation_document: Mapping[str, Any],
    *,
    manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    operation_key: TrustedKey | None,
) -> tuple[dict[str, Any], dict[str, str]]:
    operation = _freeze(operation_document, "operation document")
    protocol = operation.get("protocol")
    if protocol in {
        "integrity-guardian/readonly-operation-manifest/v1",
        "integrity-guardian/readonly-operation-manifest/v2",
        "integrity-guardian/readonly-operation-manifest/v3",
    }:
        try:
            operation_digest = verify_readonly_operation_manifest(operation)
        except OperationAuditError as exc:
            raise AdapterSdkError("adapter SDK read-only operation rejected") from exc
        return operation, {
            "kind": "readonly-operation-manifest",
            "manifest_id": operation["manifest_id"],
            "manifest_digest": operation_digest,
            "target_node_id": operation["target_node_id"],
        }
    if protocol == "integrity-guardian/adapter-target-operation/v1":
        if operation_key is None:
            raise AdapterSdkError("adapter SDK target operation key missing")
        verified = verify_adapter_target_operation(
            operation,
            manifest=manifest,
            adapter_key=adapter_key,
            operation_key=operation_key,
        )
        return verified, {
            "kind": "adapter-target-operation",
            "manifest_id": verified["operation_id"],
            "manifest_digest": adapter_target_operation_digest(verified),
            "target_node_id": verified["target"]["node_id"],
        }
    raise AdapterSdkError("adapter SDK operation protocol rejected")


def build_adapter_operation_binding(
    *,
    manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    proposal: Mapping[str, Any],
    proposer_key: TrustedKey,
    conformance_receipt: Mapping[str, Any],
    operation_manifest: Mapping[str, Any],
    operation_key: TrustedKey | None = None,
    executor_id: str,
    executor_artifact_digest: str,
    executor_key_id: str,
    created_at: str,
    signer: Ed25519Signer,
) -> dict[str, Any]:
    """Sign the exact conformance, operation, target and executor admission.

    The conformance receipt is fully re-verified by the contained runtime.  The
    SDK builder validates its closed shape and binds its content digest; this
    document does not itself grant execution authority.
    """

    verified_manifest = verify_adapter_capability_manifest(
        manifest,
        adapter_key=adapter_key,
    )
    verified_proposal = verify_adapter_action_proposal(
        proposal,
        manifest=verified_manifest,
        adapter_key=adapter_key,
        proposer_key=proposer_key,
        used_at=created_at,
    )
    conformance = _freeze(conformance_receipt, "adapter conformance receipt")
    operation = _freeze(operation_manifest, "operation manifest")
    try:
        validate("adapter-conformance-receipt", conformance)
        operation, operation_reference = _verify_operation_for_binding(
            operation,
            manifest=verified_manifest,
            adapter_key=adapter_key,
            operation_key=operation_key,
        )
    except Exception as exc:
        raise AdapterSdkError("adapter SDK operation binding evidence rejected") from exc
    readiness = conformance["result"]["readiness"]
    if readiness not in {"source-ready", "target-live-ready", "portfolio-ready"}:
        raise AdapterSdkError("adapter SDK operation binding conformance rejected")
    manifest_ref = verified_proposal["manifest"]
    if conformance["profile"] != {
        "profile_id": conformance["profile"]["profile_id"],
        "profile_digest": conformance["profile"]["profile_digest"],
        "adapter_id": manifest_ref["adapter_id"],
        "adapter_artifact_digest": manifest_ref["adapter_artifact_digest"],
    }:
        raise AdapterSdkError("adapter SDK operation binding conformance mismatch")
    if (
        operation["tenant_id"] != verified_proposal["tenant_id"]
        or operation_reference["target_node_id"]
        != verified_proposal["expected_transition"]["entity_id"]
    ):
        raise AdapterSdkError("adapter SDK operation binding target mismatch")
    if operation_reference["kind"] == "readonly-operation-manifest":
        if (
            operation["adapter_id"] != manifest_ref["adapter_id"]
            or len(operation["operations"]) != 1
        ):
            raise AdapterSdkError("adapter SDK read-only operation binding mismatch")
    else:
        if (
            operation["intent_operation_digest"] != verified_proposal["intent"]["operation_digest"]
            or operation["target"]["zone_id"] != verified_proposal["expected_transition"]["zone_id"]
            or operation["target"]["expected_after_state_digest"]
            != verified_proposal["expected_transition"]["state_digest"]
            or operation["required_channels"] != verified_proposal["required_channels"]
        ):
            raise AdapterSdkError("adapter SDK target operation binding mismatch")
    for value, field in (
        (executor_id, "executor id"),
        (executor_key_id, "executor key id"),
    ):
        _require_id(value, field)
    _require_digest(executor_artifact_digest, "executor artifact digest")
    _parse_time(created_at, "operation binding creation time")
    core = {
        "protocol": "integrity-guardian/adapter-operation-binding/v1",
        "sdk_version": ADAPTER_SDK_VERSION,
        "tenant_id": verified_proposal["tenant_id"],
        "manifest": deepcopy(manifest_ref),
        "conformance": {
            "receipt_id": conformance["receipt_id"],
            "receipt_digest": digest_object(
                conformance,
                domain="adapter-conformance-receipt-v1",
            ),
            "readiness": readiness,
        },
        "intent": {
            "operation_digest": verified_proposal["intent"]["operation_digest"],
            "action_class": verified_proposal["intent"]["action_class"],
            "target_entity_id": verified_proposal["expected_transition"]["entity_id"],
            "target_zone_id": verified_proposal["expected_transition"]["zone_id"],
        },
        "operation": operation_reference,
        "executor": {
            "executor_id": executor_id,
            "executor_artifact_digest": executor_artifact_digest,
            "key_id": executor_key_id,
        },
        "controls": {
            "max_invocations": 1,
            "binding_substitution_allowed": False,
            "automatic_retry_after_unknown": False,
            "memory_write": False,
            "production_authority": False,
        },
        "created_at": created_at,
        "signer_id": signer.key_id,
    }
    unsigned = {
        "binding_id": _identity(
            core,
            field="binding_id",
            domain="adapter-operation-binding-identity-v1",
        ),
        **core,
    }
    signed = signer.sign(unsigned)
    validate("adapter-operation-binding", signed)
    return signed


def verify_adapter_operation_binding(
    binding: Mapping[str, Any],
    *,
    manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    proposal: Mapping[str, Any],
    proposer_key: TrustedKey,
    operation_manifest: Mapping[str, Any],
    operation_key: TrustedKey | None = None,
    binding_key: TrustedKey,
    used_at: str,
) -> dict[str, Any]:
    candidate = _verify_signed(
        binding,
        schema="adapter-operation-binding",
        id_field="binding_id",
        domain="adapter-operation-binding-identity-v1",
        trusted_key=binding_key,
    )
    verified_manifest = verify_adapter_capability_manifest(
        manifest,
        adapter_key=adapter_key,
    )
    verified_proposal = verify_adapter_action_proposal(
        proposal,
        manifest=verified_manifest,
        adapter_key=adapter_key,
        proposer_key=proposer_key,
        used_at=used_at,
    )
    operation, operation_reference = _verify_operation_for_binding(
        operation_manifest,
        manifest=verified_manifest,
        adapter_key=adapter_key,
        operation_key=operation_key,
    )
    if operation_reference["kind"] == "adapter-target-operation" and (
        operation["intent_operation_digest"] != verified_proposal["intent"]["operation_digest"]
        or operation["target"]["zone_id"] != verified_proposal["expected_transition"]["zone_id"]
        or operation["target"]["expected_after_state_digest"]
        != verified_proposal["expected_transition"]["state_digest"]
        or operation["required_channels"] != verified_proposal["required_channels"]
    ):
        raise AdapterSdkError("adapter SDK target operation binding mismatch")
    if (
        candidate["manifest"] != verified_proposal["manifest"]
        or candidate["tenant_id"] != verified_proposal["tenant_id"]
        or candidate["intent"]
        != {
            "operation_digest": verified_proposal["intent"]["operation_digest"],
            "action_class": verified_proposal["intent"]["action_class"],
            "target_entity_id": verified_proposal["expected_transition"]["entity_id"],
            "target_zone_id": verified_proposal["expected_transition"]["zone_id"],
        }
        or candidate["operation"] != operation_reference
    ):
        raise AdapterSdkError("adapter SDK operation binding mismatch")
    return candidate


def build_adapter_execution_envelope(
    *,
    manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    proposal: Mapping[str, Any],
    proposer_key: TrustedKey,
    operation_binding: Mapping[str, Any],
    operation_manifest: Mapping[str, Any],
    operation_key: TrustedKey | None = None,
    binding_key: TrustedKey,
    verified_grant: VerifiedAdapterGrant,
    created_at: str,
    signer: Ed25519Signer,
) -> dict[str, Any]:
    """Bind one exact proposal to the already-consumed one-use grant."""

    if signer.key_id != binding_key.key_id:
        raise AdapterSdkError("adapter SDK binding/envelope signer mismatch")
    candidate = verify_adapter_action_proposal(
        proposal,
        manifest=manifest,
        adapter_key=adapter_key,
        proposer_key=proposer_key,
        used_at=created_at,
    )
    if not isinstance(verified_grant, VerifiedAdapterGrant):
        raise AdapterSdkError("adapter SDK verified grant rejected")
    if candidate["intent"] != verified_grant.intent:
        raise AdapterSdkError("adapter SDK grant/proposal intent mismatch")
    binding = verify_adapter_operation_binding(
        operation_binding,
        manifest=manifest,
        adapter_key=adapter_key,
        proposal=candidate,
        proposer_key=proposer_key,
        operation_manifest=operation_manifest,
        operation_key=operation_key,
        binding_key=binding_key,
        used_at=created_at,
    )
    core = {
        "protocol": "integrity-guardian/adapter-execution-envelope/v1",
        "sdk_version": ADAPTER_SDK_VERSION,
        "tenant_id": candidate["tenant_id"],
        "manifest": deepcopy(candidate["manifest"]),
        "proposal": {
            "proposal_id": candidate["proposal_id"],
            "proposal_digest": adapter_action_proposal_digest(candidate),
        },
        "operation_binding": _operation_binding_reference(binding),
        "authorization": deepcopy(verified_grant.authorization),
        "intent": deepcopy(candidate["intent"]),
        "expected_transition": deepcopy(candidate["expected_transition"]),
        "controls": {
            "max_invocations": 1,
            "action_replay_allowed": False,
            "route_continuation_allowed": False,
            "automatic_retry_after_unknown": False,
            "memory_write": False,
            "production_authority": False,
        },
        "created_at": created_at,
        "signer_id": signer.key_id,
    }
    unsigned = {
        "envelope_id": _identity(
            core,
            field="envelope_id",
            domain="adapter-execution-envelope-identity-v1",
        ),
        **core,
    }
    signed = signer.sign(unsigned)
    validate("adapter-execution-envelope", signed)
    return signed


def verify_adapter_execution_envelope(
    envelope: Mapping[str, Any],
    *,
    manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    proposal: Mapping[str, Any],
    proposer_key: TrustedKey,
    operation_binding: Mapping[str, Any],
    operation_manifest: Mapping[str, Any],
    operation_key: TrustedKey | None = None,
    binding_key: TrustedKey,
    coordinator_key: TrustedKey,
    verified_grant: VerifiedAdapterGrant,
    used_at: str,
) -> dict[str, Any]:
    if coordinator_key.key_id != binding_key.key_id:
        raise AdapterSdkError("adapter SDK binding/envelope key mismatch")
    candidate = _verify_signed(
        envelope,
        schema="adapter-execution-envelope",
        id_field="envelope_id",
        domain="adapter-execution-envelope-identity-v1",
        trusted_key=coordinator_key,
    )
    verified_proposal = verify_adapter_action_proposal(
        proposal,
        manifest=manifest,
        adapter_key=adapter_key,
        proposer_key=proposer_key,
        used_at=used_at,
    )
    verified_binding = verify_adapter_operation_binding(
        operation_binding,
        manifest=manifest,
        adapter_key=adapter_key,
        proposal=verified_proposal,
        proposer_key=proposer_key,
        operation_manifest=operation_manifest,
        operation_key=operation_key,
        binding_key=binding_key,
        used_at=used_at,
    )
    if (
        candidate["proposal"]["proposal_id"] != verified_proposal["proposal_id"]
        or candidate["proposal"]["proposal_digest"]
        != adapter_action_proposal_digest(verified_proposal)
        or candidate["authorization"] != verified_grant.authorization
        or candidate["operation_binding"] != _operation_binding_reference(verified_binding)
        or candidate["intent"] != verified_grant.intent
        or candidate["expected_transition"] != verified_proposal["expected_transition"]
    ):
        raise AdapterSdkError("adapter SDK execution envelope binding mismatch")
    return candidate


def verify_toolz_outcome_for_adapter(
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
) -> VerifiedAdapterWitness:
    """Reuse the exact a14 verifier; no second witness protocol is introduced."""

    try:
        verified = verify_toolz_action_outcome_observation(
            observation,
            policy=policy,
            evidence=evidence,
            decision=decision,
            consumption=consumption,
            consumption_event=consumption_event,
            decision_key=decision_key,
            authority_ledger=authority_ledger,
            expected_authority_checkpoint=expected_authority_checkpoint,
            observer_key=observer_key,
        )
    except ToolzActionOutcomeError as exc:
        raise AdapterSdkError("adapter SDK a14 witness rejected") from exc
    return VerifiedAdapterWitness(
        observation_id=verified["observation_id"],
        observation_digest=toolz_action_outcome_digest(verified),
        observer_id=verified["observer"]["observer_id"],
        observer_artifact_digest=verified["observer"]["observer_artifact_digest"],
        key_id=verified["observer"]["key_id"],
        key_fingerprint=verified["observer"]["key_fingerprint"],
        outcome=ToolzActionOutcome(verified["outcome"]),
        reason_code=verified["reason_code"],
        observation=deepcopy(dict(observation)),
        policy=policy,
        evidence=evidence,
        decision=deepcopy(dict(decision)),
        consumption=deepcopy(dict(consumption)),
        consumption_event=deepcopy(dict(consumption_event)),
        decision_key=decision_key,
        authority_ledger=authority_ledger,
        expected_authority_checkpoint=deepcopy(
            dict(expected_authority_checkpoint)
        ),
        observer_key=observer_key,
    )


def _reverify_adapter_witness(
    witness: VerifiedAdapterWitness,
) -> VerifiedAdapterWitness:
    proof = (
        witness.observation,
        witness.policy,
        witness.evidence,
        witness.decision,
        witness.consumption,
        witness.consumption_event,
        witness.decision_key,
        witness.authority_ledger,
        witness.expected_authority_checkpoint,
        witness.observer_key,
    )
    if any(value is None for value in proof):
        raise AdapterSdkError("adapter SDK witness proof missing")
    try:
        verified = verify_toolz_action_outcome_observation(
            witness.observation,
            policy=witness.policy,
            evidence=witness.evidence,
            decision=witness.decision,
            consumption=witness.consumption,
            consumption_event=witness.consumption_event,
            decision_key=witness.decision_key,
            authority_ledger=witness.authority_ledger,
            expected_authority_checkpoint=witness.expected_authority_checkpoint,
            observer_key=witness.observer_key,
        )
    except (ToolzActionOutcomeError, TypeError, ValueError) as exc:
        raise AdapterSdkError("adapter SDK witness proof rejected") from exc
    expected = {
        "observation_id": verified["observation_id"],
        "observation_digest": toolz_action_outcome_digest(verified),
        "observer_id": verified["observer"]["observer_id"],
        "observer_artifact_digest": verified["observer"]["observer_artifact_digest"],
        "key_id": verified["observer"]["key_id"],
        "key_fingerprint": verified["observer"]["key_fingerprint"],
        "outcome": ToolzActionOutcome(verified["outcome"]),
        "reason_code": verified["reason_code"],
    }
    actual = {
        "observation_id": witness.observation_id,
        "observation_digest": witness.observation_digest,
        "observer_id": witness.observer_id,
        "observer_artifact_digest": witness.observer_artifact_digest,
        "key_id": witness.key_id,
        "key_fingerprint": witness.key_fingerprint,
        "outcome": witness.outcome,
        "reason_code": witness.reason_code,
    }
    if actual != expected:
        raise AdapterSdkError("adapter SDK witness proof mismatch")
    return witness


def _normalize_reported_outcome(
    value: AdapterReportedOutcome | str | None,
) -> AdapterReportedOutcome | None:
    if value is None:
        return None
    try:
        return AdapterReportedOutcome(value)
    except ValueError as exc:
        raise AdapterSdkError("adapter SDK executor outcome rejected") from exc


def classify_adapter_transition(
    *,
    grant_consumed: bool,
    invocation_started: bool,
    adapter_reported_outcome: AdapterReportedOutcome | str | None,
    witness: VerifiedAdapterWitness | None,
) -> tuple[AdapterTransitionOutcome, str, bool]:
    """Resolve the closed crash matrix and automatic-retry policy."""

    reported = _normalize_reported_outcome(adapter_reported_outcome)
    if not grant_consumed:
        if invocation_started or reported is not None or witness is not None:
            raise AdapterSdkError("adapter SDK pre-grant execution claim rejected")
        return AdapterTransitionOutcome.NOT_STARTED, "grant-not-consumed", True
    if not invocation_started:
        if reported is not None or witness is not None:
            raise AdapterSdkError("adapter SDK not-started evidence rejected")
        return (
            AdapterTransitionOutcome.GRANT_CONSUMED_ACTION_NOT_STARTED,
            "preflight-stopped-after-consumption",
            False,
        )
    if reported is None:
        raise AdapterSdkError("adapter SDK started invocation lacks executor report")
    if witness is None or reported is AdapterReportedOutcome.OUTCOME_UNKNOWN:
        return AdapterTransitionOutcome.UNKNOWN_OUTCOME, "witness-or-executor-unknown", False
    if witness.outcome is ToolzActionOutcome.OUTCOME_UNKNOWN:
        return AdapterTransitionOutcome.UNKNOWN_OUTCOME, "independent-observation-unknown", False
    if (
        reported is AdapterReportedOutcome.REPORTED_SUCCESS
        and witness.outcome is ToolzActionOutcome.EXPECTED_TRANSITION_OBSERVED
    ):
        return AdapterTransitionOutcome.CONFIRMED_SUCCESS, "executor-and-witness-agree", False
    if witness.outcome in {
        ToolzActionOutcome.PRE_STATE_RETAINED,
        ToolzActionOutcome.UNEXPECTED_STATE_OBSERVED,
    }:
        return AdapterTransitionOutcome.CONFIRMED_FAILURE, "witness-rejects-transition", False
    return AdapterTransitionOutcome.UNKNOWN_OUTCOME, "executor-witness-disagree", False


def adapter_transition_receipt_digest(receipt: Mapping[str, Any]) -> str:
    return digest_object(dict(receipt), domain="adapter-transition-receipt-v1")


def _normalize_executor(value: Mapping[str, Any] | None) -> dict[str, str] | None:
    if value is None:
        return None
    candidate = _freeze(value, "executor provenance")
    if set(candidate) != {"executor_id", "executor_artifact_digest", "key_id"}:
        raise AdapterSdkError("adapter SDK executor provenance rejected")
    _require_id(candidate["executor_id"], "executor id")
    _require_digest(candidate["executor_artifact_digest"], "executor artifact digest")
    _require_id(candidate["key_id"], "executor key id")
    return candidate


def _require_independent_witness(
    *,
    executor: Mapping[str, str] | None,
    executor_key: TrustedKey | None,
    witness: VerifiedAdapterWitness | None,
) -> None:
    if witness is None:
        return
    if executor is None or executor_key is None:
        raise AdapterSdkError("adapter SDK witness lacks executor provenance")
    if executor["key_id"] != executor_key.key_id:
        raise AdapterSdkError("adapter SDK executor key binding rejected")
    collisions = (
        executor["executor_id"] == witness.observer_id,
        executor["executor_artifact_digest"] == witness.observer_artifact_digest,
        executor["key_id"] == witness.key_id,
        public_key_fingerprint(executor_key.public_key) == witness.key_fingerprint,
    )
    if any(collisions):
        raise AdapterSdkError("adapter SDK executor/witness separation rejected")


def build_adapter_transition_receipt(
    *,
    manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    proposal: Mapping[str, Any],
    proposer_key: TrustedKey,
    envelope: Mapping[str, Any] | None,
    operation_binding: Mapping[str, Any] | None,
    operation_manifest: Mapping[str, Any] | None,
    operation_key: TrustedKey | None = None,
    binding_key: TrustedKey | None,
    coordinator_key: TrustedKey,
    verified_grant: VerifiedAdapterGrant | None,
    grant_consumed: bool,
    invocation_started: bool,
    executor: Mapping[str, Any] | None,
    executor_key: TrustedKey | None = None,
    adapter_reported_outcome: AdapterReportedOutcome | str | None,
    adapter_evidence_digest: str | None,
    witness: VerifiedAdapterWitness | None,
    recorded_at: str,
    signer: Ed25519Signer,
) -> dict[str, Any]:
    """Sign one terminal receipt without replaying or writing route memory."""

    verified_proposal = verify_adapter_action_proposal(
        proposal,
        manifest=manifest,
        adapter_key=adapter_key,
        proposer_key=proposer_key,
        used_at=recorded_at,
    )
    if grant_consumed:
        if (
            envelope is None
            or verified_grant is None
            or operation_binding is None
            or operation_manifest is None
            or binding_key is None
        ):
            raise AdapterSdkError("adapter SDK consumed grant envelope missing")
        verified_envelope = verify_adapter_execution_envelope(
            envelope,
            manifest=manifest,
            adapter_key=adapter_key,
            proposal=verified_proposal,
            proposer_key=proposer_key,
            operation_binding=operation_binding,
            operation_manifest=operation_manifest,
            operation_key=operation_key,
            binding_key=binding_key,
            coordinator_key=coordinator_key,
            verified_grant=verified_grant,
            used_at=recorded_at,
        )
        envelope_reference: dict[str, str] | None = {
            "envelope_id": verified_envelope["envelope_id"],
            "envelope_digest": adapter_execution_envelope_digest(verified_envelope),
        }
        authorization = deepcopy(verified_grant.authorization)
        binding_reference: dict[str, str] | None = deepcopy(verified_envelope["operation_binding"])
    else:
        if (
            envelope is not None
            or verified_grant is not None
            or operation_binding is not None
            or operation_manifest is not None
            or operation_key is not None
            or binding_key is not None
        ):
            raise AdapterSdkError("adapter SDK unconsumed grant envelope rejected")
        envelope_reference = None
        binding_reference = None
        authorization = None
    if adapter_evidence_digest is not None:
        _require_digest(adapter_evidence_digest, "adapter evidence digest")
    normalized_executor = _normalize_executor(executor)
    if invocation_started != (normalized_executor is not None):
        raise AdapterSdkError("adapter SDK invocation/executor provenance mismatch")
    if (
        normalized_executor is not None
        and binding_reference is not None
        and normalized_executor
        != {
            "executor_id": binding_reference["executor_id"],
            "executor_artifact_digest": binding_reference["executor_artifact_digest"],
            "key_id": binding_reference["executor_key_id"],
        }
    ):
        raise AdapterSdkError("adapter SDK executor/binding mismatch")
    _require_independent_witness(
        executor=normalized_executor,
        executor_key=executor_key,
        witness=witness,
    )
    verified_witness = (
        None if witness is None else _reverify_adapter_witness(witness)
    )
    outcome, reason, retry = classify_adapter_transition(
        grant_consumed=grant_consumed,
        invocation_started=invocation_started,
        adapter_reported_outcome=adapter_reported_outcome,
        witness=verified_witness,
    )
    if invocation_started and adapter_evidence_digest is None:
        raise AdapterSdkError("adapter SDK started invocation evidence missing")
    if not invocation_started and adapter_evidence_digest is not None:
        raise AdapterSdkError("adapter SDK non-started invocation evidence rejected")
    witness_document = None
    if verified_witness is not None:
        witness_document = {
            "observation_id": verified_witness.observation_id,
            "observation_digest": verified_witness.observation_digest,
            "observer_id": verified_witness.observer_id,
            "observer_artifact_digest": verified_witness.observer_artifact_digest,
            "key_id": verified_witness.key_id,
            "key_fingerprint": verified_witness.key_fingerprint,
            "outcome": verified_witness.outcome.value,
            "reason_code": verified_witness.reason_code,
        }
    reported = _normalize_reported_outcome(adapter_reported_outcome)
    core = {
        "protocol": "integrity-guardian/adapter-transition-receipt/v1",
        "sdk_version": ADAPTER_SDK_VERSION,
        "tenant_id": verified_proposal["tenant_id"],
        "manifest": deepcopy(verified_proposal["manifest"]),
        "proposal": {
            "proposal_id": verified_proposal["proposal_id"],
            "proposal_digest": adapter_action_proposal_digest(verified_proposal),
        },
        "envelope": envelope_reference,
        "operation_binding": binding_reference,
        "authorization": authorization,
        "execution": {
            "grant_consumed": grant_consumed,
            "invocation_started": invocation_started,
            "executor": normalized_executor,
            "adapter_reported_outcome": None if reported is None else reported.value,
            "adapter_evidence_digest": adapter_evidence_digest,
        },
        "witness": witness_document,
        "result": {
            "outcome": outcome.value,
            "reason_code": reason,
            "action_replayed": False,
            "automatic_retry_allowed": retry,
        },
        "memory": {
            "feedback_receipt_required_for_learning": (
                outcome is AdapterTransitionOutcome.CONFIRMED_SUCCESS
            ),
            "route_memory_write_performed": False,
        },
        "authority_boundary": {
            "adapter_capability_is_authority": False,
            "grant_issued_by_sdk": False,
            "independent_witness_required_for_success": True,
            "production_authority": False,
            "route_continuation_authority": False,
        },
        "recorded_at": recorded_at,
        "signer_id": signer.key_id,
    }
    unsigned = {
        "receipt_id": _identity(
            core,
            field="receipt_id",
            domain="adapter-transition-receipt-identity-v1",
        ),
        **core,
    }
    signed = signer.sign(unsigned)
    validate("adapter-transition-receipt", signed)
    return signed


def verify_adapter_transition_receipt(
    receipt: Mapping[str, Any],
    *,
    receipt_key: TrustedKey,
    executor_key: TrustedKey | None = None,
) -> dict[str, Any]:
    """Verify a terminal receipt's identity, signature and crash semantics."""

    candidate = _verify_signed(
        receipt,
        schema="adapter-transition-receipt",
        id_field="receipt_id",
        domain="adapter-transition-receipt-identity-v1",
        trusted_key=receipt_key,
    )
    execution = candidate["execution"]
    witness_document = candidate["witness"]
    witness = None
    if witness_document is not None:
        witness = VerifiedAdapterWitness(
            observation_id=witness_document["observation_id"],
            observation_digest=witness_document["observation_digest"],
            observer_id=witness_document["observer_id"],
            observer_artifact_digest=witness_document["observer_artifact_digest"],
            key_id=witness_document["key_id"],
            key_fingerprint=witness_document["key_fingerprint"],
            outcome=ToolzActionOutcome(witness_document["outcome"]),
            reason_code=witness_document["reason_code"],
        )
    executor = _normalize_executor(execution["executor"])
    if execution["invocation_started"] != (executor is not None):
        raise AdapterSdkError("adapter SDK transition executor semantics mismatch")
    binding = candidate["operation_binding"]
    if execution["grant_consumed"] != (binding is not None):
        raise AdapterSdkError("adapter SDK transition binding semantics mismatch")
    if (
        executor is not None
        and binding is not None
        and executor
        != {
            "executor_id": binding["executor_id"],
            "executor_artifact_digest": binding["executor_artifact_digest"],
            "key_id": binding["executor_key_id"],
        }
    ):
        raise AdapterSdkError("adapter SDK transition executor/binding mismatch")
    _require_independent_witness(
        executor=executor,
        executor_key=executor_key,
        witness=witness,
    )
    outcome, reason, retry = classify_adapter_transition(
        grant_consumed=execution["grant_consumed"],
        invocation_started=execution["invocation_started"],
        adapter_reported_outcome=execution["adapter_reported_outcome"],
        witness=witness,
    )
    if candidate["result"] != {
        "outcome": outcome.value,
        "reason_code": reason,
        "action_replayed": False,
        "automatic_retry_allowed": retry,
    }:
        raise AdapterSdkError("adapter SDK transition receipt semantics mismatch")
    return candidate
