"""Receipt-bound Medor cognition over existing Guardian architecture layers.

This module does not execute a route.  It admits one already verified client
Mind receipt into a signed one-event Guardian Ledger, checkpoints it, projects
Atlas, compiles a fixed read-only Connectome and asks the existing Synapse
kernel for the deterministic coordination route.  Private signing keys are
caller-owned server-side dependencies and never enter the returned bundle.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import stat
import tempfile
import threading
import time
from collections.abc import Mapping
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Self

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .atlas import build_atlas_projection, verify_atlas_projection
from .atlas_synapse import (
    ATLAS_PROJECTION_EVIDENCE_ID,
    AtlasProjectionTrust,
    AtlasSynapsePlanner,
    AtlasSynapsePolicy,
    atlas_projection_evidence_digest,
)
from .canonical import canonical_bytes
from .connectome import (
    build_connectome_manifest,
    compile_connectome_manifest,
    verify_connectome_compilation,
)
from .hashing import digest_object
from .ledger import (
    LedgerAppendError,
    LedgerStore,
    LedgerVerificationError,
    build_ledger_event,
    event_digest,
    merkle_root,
    verify_ledger_event,
    verify_ledger_inclusion_proof,
)
from .local_lock import LocalLockError, lock_exclusive, unlock
from .medor_security import (
    VerifiedMedorSecurityAdmission,
    require_verified_medor_security_admission,
)
from .schemas import validate
from .signing import Ed25519Signer, TrustedKey, public_key_fingerprint, verify_signature
from .synapse import (
    BlastRadius,
    SynapseContext,
    SynapseEvidence,
    SynapseKernel,
    SynapsePolicy,
    TransitionKind,
)

TENANT_ID = "tenant:public-f3351a94ab708c31"
LEDGER_ID = "ledger:medor-architecture"
SOURCE_ID = "source:medor-mind-admission"
CHECKPOINT_ID = "checkpoint:medor-architecture"
CUSTODY_CHECKPOINT_ID = "checkpoint:medor-architecture-custody"
CUSTODY_LEDGER_ID = "ledger:medor-architecture-custody"
SUBSYSTEM = "integrity:medor-cognition"
CAPABILITIES = (
    "capability:medor-concept-recovery",
    "capability:medor-coordination",
    "capability:medor-coordination-stop",
)
EVENT_SUBSYSTEM = "integrity:medor-event-action"
EVENT_AUTHORITY_ID = "authority:medor-event-append-one-use"
EVENT_AUTHORITY_MAX_SECONDS = 900
CUSTODY_LOCK_NAME = ".guardian-architecture.lock"
CUSTODY_LOCK_TIMEOUT_SECONDS = 5.0
CUSTODY_LOCK_POLL_SECONDS = 0.025
CUSTODY_SQLITE_BUSY_TIMEOUT_MS = 2_000
CUSTODY_ADMISSION_ATTEMPTS = 3
CUSTODY_ADMISSION_RETRY_SECONDS = 0.05
EVENT_CAPABILITIES = (
    "capability:medor-event-security-admission",
    "capability:medor-event-ownership-check",
    "capability:medor-event-reuse-exact",
    "capability:medor-event-require-one-use-authority",
    "capability:medor-event-append-once",
    "capability:medor-event-observe-outcome",
    "capability:medor-event-record-feedback",
)
EVENT_EVIDENCE = {
    "architecture": "evidence:medor-architecture-admission",
    "security": "evidence:medor-security-admission",
    "authority": "evidence:medor-one-use-authority",
    "witness": "evidence:medor-passive-witness",
    "feedback": "evidence:medor-outcome-feedback",
}
_INVARIANTS = {
    "execution_performed": False,
    "home_admitted": False,
    "memory_source": "canonical-seed-action-log",
    "model_side_route_invention": False,
    "production_authority": False,
    "route_authority": False,
    "winops_authorized": False,
}


class MedorArchitectureError(ValueError):
    """Raised when a cognition bundle cannot prove the closed composition."""


def _authority_time(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise MedorArchitectureError(f"event append authority {field} is invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise MedorArchitectureError(f"event append authority {field} is invalid") from exc
    if parsed.tzinfo is None:
        raise MedorArchitectureError(f"event append authority {field} is invalid")
    return parsed


def _event_append_context_binding(
    *,
    context_admission_id: str | None,
    logical_generation: int | None,
) -> dict[str, str | int]:
    if context_admission_id is None and logical_generation is None:
        return {}
    if (
        not isinstance(context_admission_id, str)
        or re.fullmatch(r"sha256:[a-f0-9]{64}", context_admission_id) is None
        or isinstance(logical_generation, bool)
        or not isinstance(logical_generation, int)
        or logical_generation < 1
    ):
        raise MedorArchitectureError("event append context binding is invalid")
    return {
        "context_admission_id": context_admission_id,
        "logical_generation": logical_generation,
    }


def build_medor_event_append_decision(
    *,
    architecture_admission_id: str,
    security_admission_id: str,
    request_digest: str,
    valid_from: str,
    valid_until: str,
    authority_signer: Ed25519Signer,
    context_admission_id: str | None = None,
    logical_generation: int | None = None,
) -> dict[str, Any]:
    """Sign one externally governed, exact-request append decision."""

    for value, field in (
        (architecture_admission_id, "architecture admission"),
        (security_admission_id, "security admission"),
        (request_digest, "request"),
    ):
        if not isinstance(value, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", value):
            raise MedorArchitectureError(f"event append {field} digest is invalid")
    start = _authority_time(valid_from, "start")
    end = _authority_time(valid_until, "expiry")
    if not start < end or (end - start).total_seconds() > EVENT_AUTHORITY_MAX_SECONDS:
        raise MedorArchitectureError("event append authority validity window is invalid")
    context_binding = _event_append_context_binding(
        context_admission_id=context_admission_id,
        logical_generation=logical_generation,
    )
    version = 2 if context_binding else 1
    core = {
        "protocol": f"integrity-guardian/medor-event-append-decision/v{version}",
        "architecture_admission_id": architecture_admission_id,
        "security_admission_id": security_admission_id,
        "request_digest": request_digest,
        **context_binding,
        "scope": "single-canonical-seed-append",
        "max_transitions": 1,
        "decision": "approved",
        "authority_id": EVENT_AUTHORITY_ID,
        "authority_key_fingerprint": public_key_fingerprint(authority_signer.public_key),
        "valid_from": valid_from,
        "valid_until": valid_until,
        "automatic_retry_allowed": False,
        "production_authority": False,
    }
    unsigned = {
        **core,
        "decision_id": digest_object(
            core,
            domain=f"medor-event-append-external-decision-v{version}",
        ),
    }
    decision = authority_signer.sign(unsigned)
    validate(
        "medor-event-append-decision-v2" if version == 2 else "medor-event-append-decision",
        decision,
    )
    return decision


def verify_medor_event_append_decision(
    decision: Mapping[str, Any],
    *,
    authority_key: TrustedKey,
    architecture_admission_id: str,
    security_admission_id: str,
    request_digest: str,
    at_time: str,
    context_admission_id: str | None = None,
    logical_generation: int | None = None,
) -> dict[str, Any]:
    """Verify one exact external decision against a configured trust root."""

    expected_binding = _event_append_context_binding(
        context_admission_id=context_admission_id,
        logical_generation=logical_generation,
    )
    version = 2 if expected_binding else 1
    candidate = deepcopy(dict(decision))
    if candidate.get("protocol") != f"integrity-guardian/medor-event-append-decision/v{version}":
        raise MedorArchitectureError("event append external decision context binding mismatch")
    validate(
        "medor-event-append-decision-v2" if version == 2 else "medor-event-append-decision",
        candidate,
    )
    unsigned = deepcopy(candidate)
    unsigned.pop("signature")
    decision_id = unsigned.pop("decision_id")
    if decision_id != digest_object(
        unsigned,
        domain=f"medor-event-append-external-decision-v{version}",
    ):
        raise MedorArchitectureError("event append external decision identity mismatch")
    if (
        candidate["signature"]["key_id"] != authority_key.key_id
        or candidate["authority_key_fingerprint"]
        != public_key_fingerprint(authority_key.public_key)
        or not verify_signature(candidate, authority_key.public_key)
    ):
        raise MedorArchitectureError("event append external decision signature is invalid")
    if any(candidate.get(field) != value for field, value in expected_binding.items()):
        raise MedorArchitectureError("event append external decision context binding mismatch")
    if (
        candidate["architecture_admission_id"] != architecture_admission_id
        or candidate["security_admission_id"] != security_admission_id
        or candidate["request_digest"] != request_digest
    ):
        raise MedorArchitectureError("event append external decision scope mismatch")
    start = _authority_time(candidate["valid_from"], "start")
    end = _authority_time(candidate["valid_until"], "expiry")
    current = _authority_time(at_time, "evaluation time")
    if (
        not start < end
        or (end - start).total_seconds() > EVENT_AUTHORITY_MAX_SECONDS
        or not start <= current < end
    ):
        raise MedorArchitectureError("event append external decision is not active")
    return candidate


def load_medor_architecture_signer(path: Path, *, key_id: str) -> Ed25519Signer:
    """Load one raw server-side Ed25519 key through a descriptor-pinned boundary."""

    if not path.is_absolute() or path.is_symlink():
        raise MedorArchitectureError("architecture key path is unsafe")
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise MedorArchitectureError("architecture key is unavailable") from exc
    try:
        details = os.fstat(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_size != 32
            or stat.S_IMODE(details.st_mode) & 0o077
            or (hasattr(os, "geteuid") and details.st_uid != os.geteuid())
        ):
            raise MedorArchitectureError("architecture key custody is unsafe")
        raw = os.read(descriptor, 33)
        if len(raw) != 32:
            raise MedorArchitectureError("architecture key length is invalid")
        return Ed25519Signer(key_id, Ed25519PrivateKey.from_private_bytes(raw))
    finally:
        os.close(descriptor)


@dataclass(frozen=True)
class MedorArchitectureKeys:
    """Caller-custodied signers for one server-side architecture instance."""

    source_signer: Ed25519Signer
    checkpoint_signer: Ed25519Signer

    def __post_init__(self) -> None:
        if not isinstance(self.source_signer, Ed25519Signer) or not isinstance(
            self.checkpoint_signer, Ed25519Signer
        ):
            raise MedorArchitectureError("architecture signers are required")
        if self.source_signer.key_id == self.checkpoint_signer.key_id:
            raise MedorArchitectureError("source and checkpoint signers must be distinct")

    @property
    def source_key(self) -> TrustedKey:
        return TrustedKey(self.source_signer.key_id, self.source_signer.public_key)

    @property
    def checkpoint_key(self) -> TrustedKey:
        return TrustedKey(
            self.checkpoint_signer.key_id,
            self.checkpoint_signer.public_key,
        )


def _provenance(source_digest: str) -> list[dict[str, Any]]:
    return [
        {
            "class": "DECLARED",
            "source_id": "protocol:medor-architecture-admission",
            "source_digest": source_digest,
            "explanation": "Fixed read-only cognition lifecycle compiled from the admitted Mind receipt.",
        }
    ]


def _capability(
    capability_id: str,
    start: str,
    end: str,
    *,
    transition_kind: str,
    preconditions: list[dict[str, Any]],
    postconditions: list[dict[str, Any]],
    source_digest: str,
    subsystem: str = SUBSYSTEM,
    authority_ids: tuple[str, ...] = (),
    evidence_requirements: tuple[tuple[str, int], ...] = (),
    verifier_id: str | None = None,
    verifier_required: bool = False,
    reversibility: str = "not_applicable",
    blast_radius: str = "none",
    tool_calls: int = 0,
) -> dict[str, Any]:
    return {
        "capability_id": capability_id,
        "from_node_key": start,
        "to_node_key": end,
        "subsystem": subsystem,
        "transition_kind": transition_kind,
        "authority": {
            "required_authority_ids": list(authority_ids),
            "production_authority": False,
        },
        "evidence_requirements": [
            {
                "evidence_id": ATLAS_PROJECTION_EVIDENCE_ID,
                "max_age_seconds": 300,
            },
            *(
                {"evidence_id": evidence_id, "max_age_seconds": max_age}
                for evidence_id, max_age in evidence_requirements
            ),
        ],
        "preconditions": preconditions,
        "postconditions": postconditions,
        "verifier": {"verifier_id": verifier_id, "required": verifier_required},
        "reversibility": {"mode": reversibility, "rollback_capability_id": None},
        "blast_radius": blast_radius,
        "cost": {
            "latency_ms": 1,
            "context_bytes": 2048,
            "model_calls": 0,
            "tool_calls": tool_calls,
            "resource_units": 1,
        },
        "provenance": _provenance(source_digest),
    }


def build_medor_connectome(source_digest: str) -> dict[str, Any]:
    """Build the fixed declared cognition topology; no caller route is accepted."""

    nodes = [
        {
            "node_key": "node:mind-admitted",
            "kind": "evidence",
            "ref": "state:mind-admitted",
            "label": "Frozen Seed Mind admitted",
            "truth_status": "verified",
            "attributes": {},
        },
        {
            "node_key": "node:coordination-checked",
            "kind": "verification",
            "ref": "state:coordination-checked",
            "label": "Ownership and blast surface checked",
            "truth_status": "derived",
            "attributes": {},
        },
        {
            "node_key": "node:route-ready",
            "kind": "decision",
            "ref": "state:route-ready",
            "label": "Read-only project route ready",
            "truth_status": "derived",
            "attributes": {},
        },
        {
            "node_key": "node:coordination-stopped",
            "kind": "decision",
            "ref": "state:coordination-stopped",
            "label": "Ownership or blast-radius stop enforced",
            "truth_status": "derived",
            "attributes": {},
        },
    ]
    capabilities = [
        _capability(
            CAPABILITIES[0],
            "node:mind-admitted",
            "node:coordination-checked",
            transition_kind="analyze",
            preconditions=[
                {"fact": "atlas.projection_verified", "operator": "equals", "value": True},
                {"fact": "mind.receipt_verified", "operator": "equals", "value": True},
            ],
            postconditions=[{"fact": "coordination.checked", "operator": "equals", "value": True}],
            source_digest=source_digest,
        ),
        _capability(
            CAPABILITIES[1],
            "node:coordination-checked",
            "node:route-ready",
            transition_kind="plan",
            preconditions=[
                {"fact": "coordination.checked", "operator": "equals", "value": True},
                {"fact": "coordination.stop_required", "operator": "equals", "value": False},
            ],
            postconditions=[{"fact": "project.route_ready", "operator": "equals", "value": True}],
            source_digest=source_digest,
        ),
        _capability(
            CAPABILITIES[2],
            "node:coordination-checked",
            "node:coordination-stopped",
            transition_kind="plan",
            preconditions=[
                {"fact": "coordination.checked", "operator": "equals", "value": True},
                {"fact": "coordination.stop_required", "operator": "equals", "value": True},
            ],
            postconditions=[
                {"fact": "project.route_ready", "operator": "equals", "value": False},
                {"fact": "coordination.stop_enforced", "operator": "equals", "value": True},
            ],
            source_digest=source_digest,
        ),
    ]
    return build_connectome_manifest(
        tenant_id=TENANT_ID,
        nodes=nodes,
        capabilities=capabilities,
    )


def _event_capability(
    capability_id: str,
    start: str,
    end: str,
    *,
    transition_kind: str,
    preconditions: list[dict[str, Any]],
    postconditions: list[dict[str, Any]],
    request_digest: str,
    evidence_requirements: tuple[tuple[str, int], ...] = (),
    authority_ids: tuple[str, ...] = (),
    verifier_id: str | None = None,
    verifier_required: bool = False,
    reversibility: str = "not_applicable",
    blast_radius: str = "none",
    tool_calls: int = 0,
) -> dict[str, Any]:
    return _capability(
        capability_id,
        start,
        end,
        transition_kind=transition_kind,
        preconditions=preconditions,
        postconditions=postconditions,
        source_digest=request_digest,
        subsystem=EVENT_SUBSYSTEM,
        authority_ids=authority_ids,
        evidence_requirements=evidence_requirements,
        verifier_id=verifier_id,
        verifier_required=verifier_required,
        reversibility=reversibility,
        blast_radius=blast_radius,
        tool_calls=tool_calls,
    )


def build_medor_event_connectome(request_digest: str) -> dict[str, Any]:
    """Build the complete declared append/reuse/outcome topology.

    The graph is an offline plan.  The only mutation edge is an irreversible,
    single-tool, tenant-memory append that requires a separately consumed
    one-use authority and an explicit passive-witness verifier.
    """

    if not isinstance(request_digest, str) or not re.fullmatch(
        r"sha256:[a-f0-9]{64}", request_digest
    ):
        raise MedorArchitectureError("event route request digest is invalid")
    nodes = [
        {
            "node_key": key,
            "kind": kind,
            "ref": ref,
            "label": label,
            "truth_status": status,
            "attributes": {},
        }
        for key, kind, ref, label, status in (
            (
                "node:event-context",
                "evidence",
                "state:event-context",
                "Exact append intent admitted",
                "verified",
            ),
            (
                "node:security-verified",
                "verification",
                "state:security-verified",
                "Exact artifact Security Harness admitted",
                "derived",
            ),
            (
                "node:ownership-checked",
                "verification",
                "state:ownership-checked",
                "Canonical Seed ownership and blast radius checked",
                "derived",
            ),
            (
                "node:reuse-complete",
                "current_state",
                "state:reuse-complete",
                "Exact immutable event reused without action",
                "derived",
            ),
            (
                "node:authority-required",
                "decision",
                "state:authority-required",
                "One-use append authority required",
                "derived",
            ),
            (
                "node:action-attempted",
                "action",
                "state:action-attempted",
                "Exactly one append transport attempt bounded",
                "derived",
            ),
            (
                "node:outcome-witnessed",
                "verification",
                "state:outcome-witnessed",
                "Passive outcome independently witnessed",
                "observed",
            ),
            (
                "node:feedback-recorded",
                "current_state",
                "state:feedback-recorded",
                "Outcome retained as verified route feedback",
                "observed",
            ),
        )
    ]
    architecture_and_security = (
        (EVENT_EVIDENCE["architecture"], 300),
        (EVENT_EVIDENCE["security"], 300),
    )
    capabilities = [
        _event_capability(
            EVENT_CAPABILITIES[0],
            "node:event-context",
            "node:security-verified",
            transition_kind="verify",
            preconditions=[
                {"fact": "architecture.admitted", "operator": "equals", "value": True},
                {"fact": "security.admitted", "operator": "equals", "value": True},
            ],
            postconditions=[{"fact": "security.verified", "operator": "equals", "value": True}],
            request_digest=request_digest,
            evidence_requirements=architecture_and_security,
        ),
        _event_capability(
            EVENT_CAPABILITIES[1],
            "node:security-verified",
            "node:ownership-checked",
            transition_kind="analyze",
            preconditions=[
                {"fact": "security.verified", "operator": "equals", "value": True},
                {"fact": "coordination.checked", "operator": "equals", "value": True},
                {
                    "fact": "memory.append_scope",
                    "operator": "equals",
                    "value": "immutable-non-production-record",
                },
                {"fact": "production.authority", "operator": "equals", "value": False},
                {
                    "fact": "memory.source",
                    "operator": "equals",
                    "value": "canonical-seed-action-log",
                },
            ],
            postconditions=[{"fact": "ownership.checked", "operator": "equals", "value": True}],
            request_digest=request_digest,
            evidence_requirements=architecture_and_security,
        ),
        _event_capability(
            EVENT_CAPABILITIES[2],
            "node:ownership-checked",
            "node:reuse-complete",
            transition_kind="verify",
            preconditions=[
                {"fact": "ownership.checked", "operator": "equals", "value": True},
                {"fact": "event.exact_exists", "operator": "equals", "value": True},
            ],
            postconditions=[
                {"fact": "route.reused", "operator": "equals", "value": True},
                {"fact": "action.invoked", "operator": "equals", "value": False},
            ],
            request_digest=request_digest,
            evidence_requirements=((EVENT_EVIDENCE["witness"], 300),),
        ),
        _event_capability(
            EVENT_CAPABILITIES[3],
            "node:ownership-checked",
            "node:authority-required",
            transition_kind="plan",
            preconditions=[
                {"fact": "ownership.checked", "operator": "equals", "value": True},
                {"fact": "event.exact_exists", "operator": "equals", "value": False},
            ],
            postconditions=[{"fact": "one_use.required", "operator": "equals", "value": True}],
            request_digest=request_digest,
        ),
        _event_capability(
            EVENT_CAPABILITIES[4],
            "node:authority-required",
            "node:action-attempted",
            transition_kind="disposable_mutation",
            preconditions=[
                {"fact": "one_use.required", "operator": "equals", "value": True},
                {"fact": "one_use.consumed", "operator": "equals", "value": True},
                {"fact": "automatic_retry.allowed", "operator": "equals", "value": False},
            ],
            postconditions=[
                {"fact": "action.invoked", "operator": "equals", "value": True},
                {"fact": "action.attempts", "operator": "equals", "value": 1},
            ],
            request_digest=request_digest,
            evidence_requirements=((EVENT_EVIDENCE["authority"], 300),),
            authority_ids=(EVENT_AUTHORITY_ID,),
            verifier_id="verifier:canonical-seed-passive-witness",
            verifier_required=True,
            reversibility="irreversible",
            blast_radius="tenant",
            tool_calls=1,
        ),
        _event_capability(
            EVENT_CAPABILITIES[5],
            "node:action-attempted",
            "node:outcome-witnessed",
            transition_kind="verify",
            preconditions=[
                {"fact": "action.invoked", "operator": "equals", "value": True},
                {"fact": "passive_witness.observed", "operator": "equals", "value": True},
                {"fact": "action.outcome", "operator": "exists", "value": None},
            ],
            postconditions=[{"fact": "outcome.verified", "operator": "equals", "value": True}],
            request_digest=request_digest,
            evidence_requirements=((EVENT_EVIDENCE["witness"], 300),),
        ),
        _event_capability(
            EVENT_CAPABILITIES[6],
            "node:outcome-witnessed",
            "node:feedback-recorded",
            transition_kind="analyze",
            preconditions=[
                {"fact": "outcome.verified", "operator": "equals", "value": True},
                {"fact": "feedback.recorded", "operator": "equals", "value": True},
            ],
            postconditions=[
                {"fact": "route.feedback_verified", "operator": "equals", "value": True}
            ],
            request_digest=request_digest,
            evidence_requirements=((EVENT_EVIDENCE["feedback"], 300),),
        ),
    ]
    return build_connectome_manifest(
        tenant_id=TENANT_ID,
        nodes=nodes,
        capabilities=capabilities,
    )


def _qualified_digest(value: object, field: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", value):
        raise MedorArchitectureError(f"event route {field} digest is invalid")
    return value


def _event_route_inputs(
    *,
    architecture: Mapping[str, Any],
    security: VerifiedMedorSecurityAdmission,
    request_digest: str,
    observed_at: str,
    as_of: str,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, str], dict[str, SynapseEvidence]]:
    candidate = deepcopy(dict(architecture))
    validate("medor-architecture-admission", candidate)
    if candidate.get("admission_id") != _bundle_identity(candidate):
        raise MedorArchitectureError("event route architecture admission is invalid")
    try:
        security = require_verified_medor_security_admission(security)
    except ValueError as exc:
        raise MedorArchitectureError("verified Security Harness admission is required") from exc
    _qualified_digest(request_digest, "request")
    if security.production_authority:
        raise MedorArchitectureError("Security Harness admission expanded authority")
    try:
        current = datetime.fromisoformat(as_of)
        expiry = datetime.fromisoformat(security.expires_at)
        observed = datetime.fromisoformat(observed_at)
    except (AttributeError, ValueError) as exc:
        raise MedorArchitectureError("event route time is invalid") from exc
    if current.tzinfo is None or expiry.tzinfo is None or observed.tzinfo is None:
        raise MedorArchitectureError("event route time must include a timezone")
    if current >= expiry or current < observed:
        raise MedorArchitectureError("Security Harness admission is not active")
    atlas = candidate["atlas_projection"]
    atlas_verification = verify_atlas_projection(atlas)
    atlas_digest = atlas_projection_evidence_digest(atlas)
    summary = candidate["summary"]
    if (
        atlas_verification["production_authority"]
        or summary["atlas_projection_digest"] != atlas_digest
        or candidate["invariants"] != _INVARIANTS
        or not isinstance(summary["coordination_stop_required"], bool)
        or summary["route_disposition"]
        != ("stopped" if summary["coordination_stop_required"] else "ready")
    ):
        raise MedorArchitectureError("event route Atlas or coordination boundary is invalid")
    evidence_digests = {
        ATLAS_PROJECTION_EVIDENCE_ID: atlas_digest,
        EVENT_EVIDENCE["architecture"]: candidate["admission_id"],
        EVENT_EVIDENCE["security"]: security.admission_id,
    }
    evidence = {
        evidence_id: SynapseEvidence(observed_at=observed_at, digest=digest)
        for evidence_id, digest in evidence_digests.items()
    }
    return candidate, deepcopy(dict(atlas)), evidence_digests, evidence


def _event_stage(
    *,
    stage: str,
    request_digest: str,
    architecture_id: str,
    security_id: str,
    manifest: Mapping[str, Any],
    compilation: Mapping[str, Any],
    route: Mapping[str, Any],
    simulation: Mapping[str, Any],
    evidence_digests: Mapping[str, str],
    evidence_observed_at: str,
    current_node_key: str,
    target_node_key: str,
    facts: Mapping[str, str | int | bool | None],
    allowed_capabilities: tuple[str, ...],
    granted_authorities: tuple[str, ...],
    max_transition: TransitionKind,
    max_blast: BlastRadius,
    as_of: str,
) -> dict[str, Any]:
    core = {
        "protocol": "integrity-guardian/medor-event-route-stage/v1",
        "stage": stage,
        "request_digest": request_digest,
        "architecture_admission_id": architecture_id,
        "security_admission_id": security_id,
        "connectome_manifest": deepcopy(dict(manifest)),
        "connectome_compilation": deepcopy(dict(compilation)),
        "synapse_route": deepcopy(dict(route)),
        "synapse_simulation": deepcopy(dict(simulation)),
        "evidence_digests": dict(sorted(evidence_digests.items())),
        "plan_context": {
            "current_node_key": current_node_key,
            "target_node_key": target_node_key,
            "facts": deepcopy(dict(facts)),
            "allowed_capabilities": list(allowed_capabilities),
            "granted_authorities": list(granted_authorities),
            "max_transition": max_transition.value,
            "max_blast_radius": max_blast.value,
            "as_of": as_of,
            "evidence_observed_at": evidence_observed_at,
        },
        "execution_performed_by_planner": False,
        "production_authority": False,
    }
    result = {
        "route_stage_id": digest_object(core, domain="medor-event-route-stage-v1"),
        **core,
    }
    verify_medor_event_route_stage(result)
    return result


def _plan_event_stage(
    *,
    stage: str,
    request_digest: str,
    architecture_id: str,
    security_id: str,
    manifest: Mapping[str, Any],
    current_node_key: str,
    target_node_key: str,
    facts: Mapping[str, str | int | bool | None],
    evidence: Mapping[str, SynapseEvidence],
    evidence_digests: Mapping[str, str],
    allowed_capabilities: tuple[str, ...],
    granted_authorities: tuple[str, ...],
    max_transition: TransitionKind,
    max_blast: BlastRadius,
    as_of: str,
) -> dict[str, Any]:
    compilation = compile_connectome_manifest(manifest)
    bindings = {item["node_key"]: item["node_id"] for item in compilation["node_bindings"]}
    kernel = SynapseKernel(compilation["graph"])
    context = SynapseContext(
        tenant_id=TENANT_ID,
        current_node_id=bindings[current_node_key],
        as_of=as_of,
        policy=SynapsePolicy(
            allowed_subsystems=(EVENT_SUBSYSTEM,),
            allowed_capability_ids=allowed_capabilities,
            granted_authority_ids=granted_authorities,
            max_transition_kind=max_transition,
            max_blast_radius=max_blast,
        ),
        facts=facts,
        evidence=evidence,
    )
    route = kernel.plan_route(context, bindings[target_node_key], max_hops=4)
    simulation = kernel.simulate_route(context, route)
    if simulation["execution_performed"] or simulation["production_mutated"]:
        raise MedorArchitectureError("event route planner escaped offline simulation")
    return _event_stage(
        stage=stage,
        request_digest=request_digest,
        architecture_id=architecture_id,
        security_id=security_id,
        manifest=manifest,
        compilation=compilation,
        route=route,
        simulation=simulation,
        evidence_digests=evidence_digests,
        evidence_observed_at=next(iter(evidence.values())).observed_at,
        current_node_key=current_node_key,
        target_node_key=target_node_key,
        facts=facts,
        allowed_capabilities=allowed_capabilities,
        granted_authorities=granted_authorities,
        max_transition=max_transition,
        max_blast=max_blast,
        as_of=as_of,
    )


def verify_medor_event_route_stage(stage: Mapping[str, Any]) -> dict[str, Any]:
    """Rebuild an action-specific Connectome/Synapse stage from closed inputs."""

    candidate = deepcopy(dict(stage))
    validate("medor-event-route-stage", candidate)
    core = deepcopy(candidate)
    route_stage_id = core.pop("route_stage_id")
    if route_stage_id != digest_object(core, domain="medor-event-route-stage-v1"):
        raise MedorArchitectureError("event route stage identity mismatch")
    expected_manifest = build_medor_event_connectome(candidate["request_digest"])
    if canonical_bytes(expected_manifest) != canonical_bytes(candidate["connectome_manifest"]):
        raise MedorArchitectureError("event route Connectome semantic mismatch")
    compilation_verification = verify_connectome_compilation(
        expected_manifest, candidate["connectome_compilation"]
    )
    if not compilation_verification["ok"]:
        raise MedorArchitectureError("event route Connectome compilation is invalid")
    compilation = candidate["connectome_compilation"]
    bindings = {item["node_key"]: item["node_id"] for item in compilation["node_bindings"]}
    context_record = candidate["plan_context"]
    try:
        policy = SynapsePolicy(
            allowed_subsystems=(EVENT_SUBSYSTEM,),
            allowed_capability_ids=tuple(context_record["allowed_capabilities"]),
            granted_authority_ids=tuple(context_record["granted_authorities"]),
            max_transition_kind=TransitionKind(context_record["max_transition"]),
            max_blast_radius=BlastRadius(context_record["max_blast_radius"]),
        )
        evidence = {
            evidence_id: SynapseEvidence(
                observed_at=context_record["evidence_observed_at"],
                digest=digest,
            )
            for evidence_id, digest in candidate["evidence_digests"].items()
        }
        context = SynapseContext(
            tenant_id=TENANT_ID,
            current_node_id=bindings[context_record["current_node_key"]],
            as_of=context_record["as_of"],
            policy=policy,
            facts=context_record["facts"],
            evidence=evidence,
        )
        kernel = SynapseKernel(compilation["graph"])
        expected_route = kernel.plan_route(
            context,
            bindings[context_record["target_node_key"]],
            max_hops=4,
        )
        expected_simulation = kernel.simulate_route(context, expected_route)
    except (KeyError, TypeError, ValueError) as exc:
        raise MedorArchitectureError("event route stage cannot be replayed") from exc
    if canonical_bytes(expected_route) != canonical_bytes(candidate["synapse_route"]):
        raise MedorArchitectureError("event route Synapse plan semantic mismatch")
    if canonical_bytes(expected_simulation) != canonical_bytes(candidate["synapse_simulation"]):
        raise MedorArchitectureError("event route Synapse simulation semantic mismatch")
    if (
        candidate["execution_performed_by_planner"] is not False
        or candidate["production_authority"] is not False
    ):
        raise MedorArchitectureError("event route stage expanded authority")
    return {
        "ok": True,
        "route_stage_id": route_stage_id,
        "stage": candidate["stage"],
        "route_id": candidate["synapse_route"]["route_id"],
        "simulation_id": candidate["synapse_simulation"]["simulation_id"],
        "production_authority": False,
        "execution_performed_by_planner": False,
    }


def plan_medor_event_append(
    *,
    architecture: Mapping[str, Any],
    security: VerifiedMedorSecurityAdmission,
    request_digest: str,
    exact_event_exists: bool,
    passive_witness_digest: str,
    observed_at: str,
    as_of: str,
    context_admission_id: str | None = None,
    logical_generation: int | None = None,
) -> dict[str, Any]:
    """Plan either exact immutable reuse or the route to a one-use grant gate."""

    candidate, _atlas, evidence_digests, evidence = _event_route_inputs(
        architecture=architecture,
        security=security,
        request_digest=request_digest,
        observed_at=observed_at,
        as_of=as_of,
    )
    witness_digest = _qualified_digest(passive_witness_digest, "passive witness")
    context_binding = _event_append_context_binding(
        context_admission_id=context_admission_id,
        logical_generation=logical_generation,
    )
    evidence_digests[EVENT_EVIDENCE["witness"]] = witness_digest
    evidence[EVENT_EVIDENCE["witness"]] = SynapseEvidence(
        observed_at=observed_at,
        digest=witness_digest,
    )
    manifest = build_medor_event_connectome(request_digest)
    target = "node:reuse-complete" if exact_event_exists else "node:authority-required"
    capabilities = (
        EVENT_CAPABILITIES[:3]
        if exact_event_exists
        else (EVENT_CAPABILITIES[0], EVENT_CAPABILITIES[1], EVENT_CAPABILITIES[3])
    )
    return _plan_event_stage(
        stage="reuse" if exact_event_exists else "pre-action",
        request_digest=request_digest,
        architecture_id=candidate["admission_id"],
        security_id=security.admission_id,
        manifest=manifest,
        current_node_key="node:event-context",
        target_node_key=target,
        facts={
            "architecture.admitted": True,
            "security.admitted": True,
            "coordination.checked": True,
            "coordination.stop_required": candidate["summary"]["coordination_stop_required"],
            "memory.append_scope": "immutable-non-production-record",
            "production.authority": False,
            "memory.source": "canonical-seed-action-log",
            "event.exact_exists": exact_event_exists,
            **(
                {
                    "context.admission_id": context_binding["context_admission_id"],
                    "context.logical_generation": context_binding["logical_generation"],
                }
                if context_binding
                else {}
            ),
        },
        evidence=evidence,
        evidence_digests=evidence_digests,
        allowed_capabilities=capabilities,
        granted_authorities=(),
        max_transition=TransitionKind.PLAN,
        max_blast=BlastRadius.NONE,
        as_of=as_of,
    )


def plan_medor_event_execution(
    *,
    pre_action: Mapping[str, Any],
    authority: Mapping[str, Any],
    source_key: TrustedKey,
    checkpoint_key: TrustedKey,
    authority_key: TrustedKey,
    observed_at: str,
    as_of: str,
) -> dict[str, Any]:
    """Bind a consumed grant to the one declared non-production mutation edge."""

    plan = deepcopy(dict(pre_action))
    grant = deepcopy(dict(authority))
    verify_medor_event_route_stage(plan)
    verify_medor_event_append_authority(
        grant,
        source_key=source_key,
        checkpoint_key=checkpoint_key,
        authority_key=authority_key,
        at_time=as_of,
    )
    plan_facts = plan.get("plan_context", {}).get("facts", {})
    if not isinstance(plan_facts, dict):
        raise MedorArchitectureError("pre-action context binding is invalid")
    plan_binding = _event_append_context_binding(
        context_admission_id=plan_facts.get("context.admission_id"),
        logical_generation=plan_facts.get("context.logical_generation"),
    )
    grant_binding = _event_append_context_binding(
        context_admission_id=grant.get("context_admission_id"),
        logical_generation=grant.get("logical_generation"),
    )
    if plan_binding != grant_binding:
        raise MedorArchitectureError("one-use authority does not bind the logical context")
    if plan.get("stage") != "pre-action" or grant.get("route_digest") != plan.get("route_stage_id"):
        raise MedorArchitectureError("one-use authority does not bind the pre-action route")
    if (
        grant.get("consumption_recorded") is not True
        or grant.get("single_use") is not True
        or grant.get("automatic_retry_allowed") is not False
        or grant.get("production_authority") is not False
    ):
        raise MedorArchitectureError("one-use authority boundary is invalid")
    grant_receipt = _qualified_digest(grant.get("receipt_id"), "authority receipt")
    evidence_digests = dict(plan["evidence_digests"])
    evidence_digests[EVENT_EVIDENCE["authority"]] = grant_receipt
    evidence = {
        evidence_id: SynapseEvidence(observed_at=observed_at, digest=digest)
        for evidence_id, digest in evidence_digests.items()
    }
    return _plan_event_stage(
        stage="action",
        request_digest=plan["request_digest"],
        architecture_id=plan["architecture_admission_id"],
        security_id=plan["security_admission_id"],
        manifest=plan["connectome_manifest"],
        current_node_key="node:authority-required",
        target_node_key="node:action-attempted",
        facts={
            "one_use.required": True,
            "one_use.consumed": True,
            "automatic_retry.allowed": False,
        },
        evidence=evidence,
        evidence_digests=evidence_digests,
        allowed_capabilities=(EVENT_CAPABILITIES[4],),
        granted_authorities=(EVENT_AUTHORITY_ID,),
        max_transition=TransitionKind.DISPOSABLE_MUTATION,
        max_blast=BlastRadius.TENANT,
        as_of=as_of,
    )


def plan_medor_event_outcome(
    *,
    action_stage: Mapping[str, Any],
    outcome: str,
    passive_witness_digest: str,
    feedback_receipt_id: str,
    feedback: Mapping[str, Any],
    source_key: TrustedKey,
    checkpoint_key: TrustedKey,
    observed_at: str,
    as_of: str,
) -> dict[str, Any]:
    """Close the planned route only after witness and durable feedback exist."""

    action = deepcopy(dict(action_stage))
    verify_medor_event_route_stage(action)
    feedback_value = deepcopy(dict(feedback))
    feedback_verification = verify_medor_event_outcome_feedback(
        feedback_value,
        source_key=source_key,
        checkpoint_key=checkpoint_key,
    )
    if action.get("stage") != "action" or outcome not in {
        "confirmed-success",
        "confirmed-failure",
        "unknown-outcome",
    }:
        raise MedorArchitectureError("event outcome route input is invalid")
    witness = _qualified_digest(passive_witness_digest, "passive witness")
    feedback = _qualified_digest(feedback_receipt_id, "feedback receipt")
    if feedback_verification["receipt_id"] != feedback:
        raise MedorArchitectureError("event outcome feedback receipt mismatch")
    evidence_digests = dict(action["evidence_digests"])
    evidence_digests[EVENT_EVIDENCE["witness"]] = witness
    evidence_digests[EVENT_EVIDENCE["feedback"]] = feedback
    evidence = {
        evidence_id: SynapseEvidence(observed_at=observed_at, digest=digest)
        for evidence_id, digest in evidence_digests.items()
    }
    return _plan_event_stage(
        stage="outcome",
        request_digest=action["request_digest"],
        architecture_id=action["architecture_admission_id"],
        security_id=action["security_admission_id"],
        manifest=action["connectome_manifest"],
        current_node_key="node:action-attempted",
        target_node_key="node:feedback-recorded",
        facts={
            "action.invoked": True,
            "action.outcome": outcome,
            "passive_witness.observed": True,
            "feedback.recorded": True,
        },
        evidence=evidence,
        evidence_digests=evidence_digests,
        allowed_capabilities=(EVENT_CAPABILITIES[5], EVENT_CAPABILITIES[6]),
        granted_authorities=(),
        max_transition=TransitionKind.PLAN,
        max_blast=BlastRadius.NONE,
        as_of=as_of,
    )


def _validate_mind_inputs(
    mind_admission: Mapping[str, Any],
    mind: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    admission = deepcopy(dict(mind_admission))
    projection = deepcopy(dict(mind))
    validate("memory-synapse-mind-admission", admission)
    concept = projection.get("concept_recovery")
    coordination = projection.get("coordination")
    if not isinstance(concept, dict) or not isinstance(coordination, dict):
        raise MedorArchitectureError("Mind concept or coordination projection is absent")
    if (
        projection.get("memory_source") != "canonical-seed-action-log"
        or projection.get("home_record_count") != 0
        or projection.get("production_authority") is not False
        or projection.get("projection_digest") != admission["projection_digest"]
        or concept.get("recovery_digest") != admission["concept_recovery_digest"]
        or coordination.get("coordination_digest") != admission["coordination_digest"]
        or coordination.get("stop_required") != admission["coordination_stop_required"]
    ):
        raise MedorArchitectureError("Mind admission and projection do not match")
    return admission, projection


def _summary(
    *,
    admission: Mapping[str, Any],
    ledger_event: Mapping[str, Any],
    checkpoint: Mapping[str, Any],
    atlas_projection: Mapping[str, Any],
    connectome_manifest: Mapping[str, Any],
    compilation: Mapping[str, Any],
    plan: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "mind_admission_receipt_id": admission["receipt_id"],
        "concept_recovery_digest": admission["concept_recovery_digest"],
        "coordination_digest": admission["coordination_digest"],
        "coordination_stop_required": admission["coordination_stop_required"],
        "route_disposition": ("stopped" if admission["coordination_stop_required"] else "ready"),
        "ledger_event_id": ledger_event["event_id"],
        "ledger_event_digest": event_digest(dict(ledger_event)),
        "checkpoint_id": checkpoint["checkpoint_id"],
        "checkpoint_digest": digest_object(
            dict(checkpoint), domain="medor-architecture-checkpoint-reference-v1"
        ),
        "checkpoint_tree_size": checkpoint["tree_size"],
        "atlas_projection_id": atlas_projection["projection_id"],
        "atlas_projection_digest": atlas_projection_evidence_digest(atlas_projection),
        "connectome_manifest_id": connectome_manifest["manifest_id"],
        "connectome_compilation_id": compilation["compilation_id"],
        "synapse_graph_id": compilation["graph_id"],
        "synapse_plan_id": plan["plan_id"],
        "synapse_route_id": plan["route"]["route_id"],
        "synapse_edge_ids": plan["route"]["edge_ids"],
        "synapse_blast_radius_rank": plan["route"]["score"]["blast_radius_rank"],
        "simulation_id": plan["simulation"]["simulation_id"],
        "simulation_status": plan["simulation"]["status"],
    }


def _bundle_identity(document: Mapping[str, Any]) -> str:
    core = deepcopy(dict(document))
    core.pop("admission_id", None)
    return digest_object(core, domain="medor-architecture-admission-v1")


def build_medor_architecture_admission(
    *,
    mind_admission: Mapping[str, Any],
    mind: Mapping[str, Any],
    keys: MedorArchitectureKeys,
    observed_at: str,
    as_of: str,
) -> dict[str, Any]:
    """Compose the actual Guardian→Atlas→Connectome→Synapse read-only path."""

    if not isinstance(keys, MedorArchitectureKeys):
        raise MedorArchitectureError("architecture key custody is required")
    admission, _projection = _validate_mind_inputs(mind_admission, mind)
    payload_digest = digest_object(
        {
            "mind_admission_receipt_id": admission["receipt_id"],
            "projection_digest": admission["projection_digest"],
            "concept_recovery_digest": admission["concept_recovery_digest"],
            "coordination_digest": admission["coordination_digest"],
        },
        domain="medor-mind-guardian-evidence-v1",
    )
    ledger_event = build_ledger_event(
        tenant_id=TENANT_ID,
        source_id=SOURCE_ID,
        source_sequence=0,
        event_type="observation",
        payload_digest=payload_digest,
        previous_event_digest=None,
        signer=keys.source_signer,
        recorded_at=observed_at,
    )
    with (
        tempfile.TemporaryDirectory(prefix="integrity-medor-ledger-") as directory,
        LedgerStore(
            Path(directory) / "ledger.sqlite3",
            tenant_id=TENANT_ID,
            ledger_id=LEDGER_ID,
        ) as ledger,
    ):
        ledger.append(ledger_event)
        checkpoint = ledger.checkpoint(
            checkpoint_id=CHECKPOINT_ID,
            signer=keys.checkpoint_signer,
            created_at=observed_at,
        )
        atlas_projection = build_atlas_projection(
            ledger=ledger,
            source_public_keys={SOURCE_ID: keys.source_key},
            checkpoint=checkpoint,
            checkpoint_key=keys.checkpoint_key,
        )
    connectome_manifest = build_medor_connectome(admission["receipt_id"])
    compilation = compile_connectome_manifest(connectome_manifest)
    bindings = {item["node_key"]: item["node_id"] for item in compilation["node_bindings"]}
    policy = AtlasSynapsePolicy(
        policy_id="policy:medor-read-only-cognition",
        graph_id=compilation["graph_id"],
        allowed_subsystems=(SUBSYSTEM,),
        allowed_capability_ids=CAPABILITIES,
        max_projection_age_seconds=300,
    )
    planner = AtlasSynapsePlanner(
        graph=compilation["graph"],
        policy=policy,
        projection_trust=AtlasProjectionTrust(
            projection_id=atlas_projection["projection_id"],
            checkpoint_digest=atlas_projection["generated_from"]["checkpoint_digest"],
        ),
    )
    target_node_key = (
        "node:coordination-stopped"
        if admission["coordination_stop_required"]
        else "node:route-ready"
    )
    plan = planner.plan(
        projection=atlas_projection,
        current_node_id=bindings["node:mind-admitted"],
        target_node_id=bindings[target_node_key],
        as_of=as_of,
        projection_observed_at=observed_at,
        facts={
            "mind.receipt_verified": True,
            "coordination.stop_required": admission["coordination_stop_required"],
        },
    )
    core = {
        "protocol": "integrity-guardian/medor-architecture-admission/v1",
        "mind_admission": admission,
        "guardian_event": ledger_event,
        "guardian_checkpoint": checkpoint,
        "atlas_projection": atlas_projection,
        "connectome_manifest": connectome_manifest,
        "connectome_compilation": compilation,
        "atlas_synapse_plan": plan,
        "summary": _summary(
            admission=admission,
            ledger_event=ledger_event,
            checkpoint=checkpoint,
            atlas_projection=atlas_projection,
            connectome_manifest=connectome_manifest,
            compilation=compilation,
            plan=plan,
        ),
        "invariants": deepcopy(_INVARIANTS),
    }
    bundle = {"admission_id": _bundle_identity(core), **core}
    validate("medor-architecture-admission", bundle)
    return bundle


def verify_medor_architecture_admission(
    bundle: Mapping[str, Any],
    *,
    mind_admission: Mapping[str, Any],
    mind: Mapping[str, Any],
    source_key: TrustedKey,
    checkpoint_key: TrustedKey,
    observed_at: str,
    as_of: str,
) -> dict[str, Any]:
    """Independently rebuild every layer and reject semantic rehashing."""

    candidate = deepcopy(dict(bundle))
    validate("medor-architecture-admission", candidate)
    admission, _projection = _validate_mind_inputs(mind_admission, mind)
    if candidate["mind_admission"] != admission:
        raise MedorArchitectureError("architecture bundle changed Mind admission")
    if candidate["admission_id"] != _bundle_identity(candidate):
        raise MedorArchitectureError("architecture admission identity mismatch")
    with (
        tempfile.TemporaryDirectory(prefix="integrity-medor-verify-") as directory,
        LedgerStore(
            Path(directory) / "ledger.sqlite3",
            tenant_id=TENANT_ID,
            ledger_id=LEDGER_ID,
        ) as ledger,
    ):
        ledger.append(candidate["guardian_event"])
        verification = ledger.verify(
            source_public_keys={SOURCE_ID: source_key},
            checkpoint=candidate["guardian_checkpoint"],
            checkpoint_key=checkpoint_key,
        )
        if not verification["ok"] or not verification["checkpoint_verified"]:
            raise MedorArchitectureError("Guardian Ledger checkpoint is unverified")
        expected_atlas = build_atlas_projection(
            ledger=ledger,
            source_public_keys={SOURCE_ID: source_key},
            checkpoint=candidate["guardian_checkpoint"],
            checkpoint_key=checkpoint_key,
        )
    if canonical_bytes(expected_atlas) != canonical_bytes(candidate["atlas_projection"]):
        raise MedorArchitectureError("Atlas projection semantic mismatch")
    expected_manifest = build_medor_connectome(admission["receipt_id"])
    if canonical_bytes(expected_manifest) != canonical_bytes(candidate["connectome_manifest"]):
        raise MedorArchitectureError("Connectome manifest semantic mismatch")
    compilation_verification = verify_connectome_compilation(
        expected_manifest,
        candidate["connectome_compilation"],
    )
    if not compilation_verification["ok"]:
        raise MedorArchitectureError("Connectome compilation is unverified")
    compilation = candidate["connectome_compilation"]
    bindings = {item["node_key"]: item["node_id"] for item in compilation["node_bindings"]}
    policy = AtlasSynapsePolicy(
        policy_id="policy:medor-read-only-cognition",
        graph_id=compilation["graph_id"],
        allowed_subsystems=(SUBSYSTEM,),
        allowed_capability_ids=CAPABILITIES,
        max_projection_age_seconds=300,
    )
    planner = AtlasSynapsePlanner(
        graph=compilation["graph"],
        policy=policy,
        projection_trust=AtlasProjectionTrust(
            projection_id=expected_atlas["projection_id"],
            checkpoint_digest=expected_atlas["generated_from"]["checkpoint_digest"],
        ),
    )
    target_node_key = (
        "node:coordination-stopped"
        if admission["coordination_stop_required"]
        else "node:route-ready"
    )
    plan_verification = planner.verify_plan(
        candidate["atlas_synapse_plan"],
        projection=expected_atlas,
        current_node_id=bindings["node:mind-admitted"],
        target_node_id=bindings[target_node_key],
        as_of=as_of,
        projection_observed_at=observed_at,
        facts={
            "mind.receipt_verified": True,
            "coordination.stop_required": admission["coordination_stop_required"],
        },
    )
    expected_summary = _summary(
        admission=admission,
        ledger_event=candidate["guardian_event"],
        checkpoint=candidate["guardian_checkpoint"],
        atlas_projection=expected_atlas,
        connectome_manifest=expected_manifest,
        compilation=compilation,
        plan=candidate["atlas_synapse_plan"],
    )
    if candidate["summary"] != expected_summary or candidate["invariants"] != _INVARIANTS:
        raise MedorArchitectureError("architecture summary or boundary mismatch")
    return {
        "ok": True,
        "admission_id": candidate["admission_id"],
        "ledger_checkpoint_verified": True,
        "atlas_projection_verified": True,
        "connectome_compilation_verified": True,
        "synapse_plan_verified": plan_verification["ok"],
        "edge_count": plan_verification["edge_count"],
        "production_authority": False,
        "execution_performed": False,
    }


def _mind_payload_digest(admission: Mapping[str, Any]) -> str:
    return digest_object(
        {
            "mind_admission_receipt_id": admission["receipt_id"],
            "projection_digest": admission["projection_digest"],
            "concept_recovery_digest": admission["concept_recovery_digest"],
            "coordination_digest": admission["coordination_digest"],
        },
        domain="medor-mind-guardian-evidence-v1",
    )


def _is_retryable_custody_conflict(exc: Exception) -> bool:
    """Recognize only transient SQLite/head races, never general corruption."""

    if isinstance(exc, sqlite3.OperationalError):
        code = getattr(exc, "sqlite_errorcode", None)
        if isinstance(code, int) and code & 0xFF in {
            sqlite3.SQLITE_BUSY,
            sqlite3.SQLITE_LOCKED,
        }:
            return True
        return str(exc).casefold() in {
            "database is locked",
            "database is busy",
            "database table is locked",
            "database schema is locked: main",
        }
    if isinstance(exc, sqlite3.IntegrityError):
        return str(exc) in {
            "UNIQUE constraint failed: ledger_events.event_digest",
            (
                "UNIQUE constraint failed: ledger_events.tenant_id, "
                "ledger_events.source_id, ledger_events.source_sequence"
            ),
        }
    if isinstance(exc, LedgerAppendError):
        return re.fullmatch(
            r"source sequence mismatch: expected [0-9]+, got [0-9]+",
            str(exc),
        ) is not None
    if isinstance(exc, LedgerVerificationError):
        return str(exc) in {
            "checkpoint tree size mismatch",
            "checkpoint Merkle root mismatch",
            "checkpoint tip mismatch",
        }
    return False


class PersistentMedorArchitectureService:
    """Append-only custody for admitted Mind receipts plus portable route proof.

    The persistent ledger proves that an admission survived process restart.
    The returned architecture capsule separately projects the exact admitted
    event through Atlas/Connectome/Synapse, keeping verification bounded rather
    than returning the complete growing custody ledger to the MCP client.
    """

    def __init__(
        self,
        root: Path,
        *,
        keys: MedorArchitectureKeys,
        event_authority_key: TrustedKey | None = None,
        native_database_enrollment: Mapping[str, Any] | None = None,
        native_ledger_issuer_key: TrustedKey | None = None,
    ) -> None:
        if not root.is_absolute() or root.is_symlink():
            raise MedorArchitectureError("architecture custody root is unsafe")
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        details = root.stat()
        if (
            not stat.S_ISDIR(details.st_mode)
            or stat.S_IMODE(details.st_mode) & 0o077
            or (hasattr(os, "geteuid") and details.st_uid != os.geteuid())
        ):
            raise MedorArchitectureError("architecture custody root is not private")
        self.root = root
        self.keys = keys
        self.event_authority_key = event_authority_key
        self.ledger_path = root / "guardian-architecture.sqlite3"
        self.checkpoint_path = root / "guardian-architecture-checkpoint.json"
        self.custody_lock_path = root / CUSTODY_LOCK_NAME
        self._lock = threading.RLock()
        if (native_database_enrollment is None) != (native_ledger_issuer_key is None):
            raise MedorArchitectureError(
                "native database enrollment and issuer key must be supplied together"
            )
        self._custody_lock_descriptor: int | None = self._open_custody_lock()
        try:
            if native_database_enrollment is not None:
                assert native_ledger_issuer_key is not None
                with (
                    self._exclusive_custody(),
                    LedgerStore(
                        self.ledger_path,
                        tenant_id=TENANT_ID,
                        ledger_id=CUSTODY_LEDGER_ID,
                        busy_timeout_ms=CUSTODY_SQLITE_BUSY_TIMEOUT_MS,
                    ) as ledger,
                ):
                    ledger.bind_native_trust(
                        native_database_enrollment,
                        issuer_key=native_ledger_issuer_key,
                    )
        except Exception:
            self.close()
            raise

    def _open_custody_lock(self) -> int:
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(self.custody_lock_path, flags, 0o600)
        except OSError as exc:
            raise MedorArchitectureError("architecture custody lock is unavailable") from exc
        try:
            self._validate_custody_lock(descriptor)
        except Exception:
            os.close(descriptor)
            raise
        return descriptor

    def _validate_custody_lock(self, descriptor: int) -> None:
        try:
            opened = os.fstat(descriptor)
            retained = os.lstat(self.custody_lock_path)
        except OSError as exc:
            raise MedorArchitectureError("architecture custody lock is unavailable") from exc
        if (
            not stat.S_ISREG(opened.st_mode)
            or stat.S_ISLNK(retained.st_mode)
            or (opened.st_dev, opened.st_ino) != (retained.st_dev, retained.st_ino)
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) & 0o077
            or (hasattr(os, "geteuid") and opened.st_uid != os.geteuid())
        ):
            raise MedorArchitectureError("architecture custody lock is unsafe")

    @contextmanager
    def _exclusive_custody(self):
        with self._lock:
            descriptor = self._custody_lock_descriptor
            if descriptor is None:
                raise MedorArchitectureError("architecture custody service is closed")
            self._validate_custody_lock(descriptor)
            deadline = time.monotonic() + CUSTODY_LOCK_TIMEOUT_SECONDS
            while True:
                try:
                    lock_exclusive(descriptor, nonblocking=True)
                    break
                except LocalLockError as exc:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise MedorArchitectureError(
                            "architecture custody lock acquisition timed out"
                        ) from exc
                    time.sleep(min(CUSTODY_LOCK_POLL_SECONDS, remaining))
            try:
                self._validate_custody_lock(descriptor)
                yield
            finally:
                try:
                    unlock(descriptor)
                except LocalLockError as exc:
                    raise MedorArchitectureError(
                        "architecture custody lock release failed"
                    ) from exc

    def close(self) -> None:
        with self._lock:
            descriptor = self._custody_lock_descriptor
            self._custody_lock_descriptor = None
            if descriptor is not None:
                os.close(descriptor)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def _source_public_keys(self, events: list[dict[str, Any]]) -> dict[str, TrustedKey]:
        result = {SOURCE_ID: self.keys.source_key}
        for event in events:
            source_id = event.get("source_id")
            if source_id == SOURCE_ID:
                continue
            if not isinstance(source_id, str) or not source_id.startswith(
                ("source:medor-event-grant:", "source:medor-event-outcome:")
            ):
                raise MedorArchitectureError("architecture custody contains an unknown source")
            suffix = source_id.rsplit(":", 1)[-1]
            if len(suffix) != 64 or any(
                character not in "0123456789abcdef" for character in suffix
            ):
                raise MedorArchitectureError("architecture custody action source is invalid")
            result[source_id] = self.keys.source_key
        return result

    def _load_checkpoint(self) -> dict[str, Any] | None:
        if not self.checkpoint_path.exists():
            return None
        if self.checkpoint_path.is_symlink():
            raise MedorArchitectureError("architecture checkpoint path is unsafe")
        flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(self.checkpoint_path, flags)
        except OSError as exc:
            raise MedorArchitectureError("architecture checkpoint is unavailable") from exc
        try:
            details = os.fstat(descriptor)
            if (
                not stat.S_ISREG(details.st_mode)
                or details.st_size > 64 * 1024
                or stat.S_IMODE(details.st_mode) & 0o077
                or (hasattr(os, "geteuid") and details.st_uid != os.geteuid())
            ):
                raise MedorArchitectureError("architecture checkpoint custody is unsafe")
            raw = bytearray()
            while chunk := os.read(descriptor, 16 * 1024):
                raw.extend(chunk)
                if len(raw) > 64 * 1024:
                    raise MedorArchitectureError("architecture checkpoint is unbounded")
        finally:
            os.close(descriptor)
        try:
            value = json.loads(bytes(raw))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise MedorArchitectureError("architecture checkpoint is invalid") from exc
        if not isinstance(value, dict):
            raise MedorArchitectureError("architecture checkpoint is invalid")
        return value

    def _store_checkpoint(self, checkpoint: Mapping[str, Any]) -> None:
        payload = canonical_bytes(dict(checkpoint))
        descriptor, temporary = tempfile.mkstemp(
            prefix=".checkpoint-", suffix=".tmp", dir=self.root
        )
        temporary_path = Path(temporary)
        try:
            os.fchmod(descriptor, 0o600)
            offset = 0
            while offset < len(payload):
                offset += os.write(descriptor, payload[offset:])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            os.replace(temporary_path, self.checkpoint_path)
            directory = os.open(self.root, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if temporary_path.exists():
                temporary_path.unlink()

    def _verify_prefix(
        self,
        checkpoint: Mapping[str, Any],
        event_digests: list[str],
    ) -> int:
        candidate = dict(checkpoint)
        try:
            validate("checkpoint", candidate)
        except Exception as exc:
            raise MedorArchitectureError("architecture checkpoint schema is invalid") from exc
        if (
            candidate.get("checkpoint_id") != CUSTODY_CHECKPOINT_ID
            or candidate.get("tenant_id") != TENANT_ID
            or candidate.get("ledger_id") != CUSTODY_LEDGER_ID
            or candidate.get("signer_id") != self.keys.checkpoint_key.key_id
            or candidate.get("signature", {}).get("key_id") != self.keys.checkpoint_key.key_id
            or not verify_signature(candidate, self.keys.checkpoint_key.public_key)
        ):
            raise MedorArchitectureError("architecture checkpoint signature or scope is invalid")
        tree_size = candidate["tree_size"]
        if tree_size > len(event_digests):
            raise MedorArchitectureError("architecture ledger is behind retained checkpoint")
        prefix = event_digests[:tree_size]
        if (
            not prefix
            or candidate["root_digest"] != merkle_root(prefix)
            or candidate["last_event_digest"] != prefix[-1]
        ):
            raise MedorArchitectureError("architecture retained checkpoint is not a ledger prefix")
        return tree_size

    def _open_verified(
        self,
        ledger: LedgerStore,
        *,
        recovered_at: str,
    ) -> tuple[list[dict[str, Any]], dict[str, Any] | None, str]:
        events = ledger.events()
        source_public_keys = self._source_public_keys(events)
        ledger.verify(source_public_keys=source_public_keys)
        digests = ledger.event_digests()
        checkpoint = self._load_checkpoint()
        if not events:
            if checkpoint is not None:
                raise MedorArchitectureError("architecture checkpoint refers to an empty ledger")
            return events, None, "empty"
        if checkpoint is None:
            if len(events) != 1:
                raise MedorArchitectureError("architecture checkpoint loss exceeds one child")
            checkpoint = ledger.checkpoint(
                checkpoint_id=CUSTODY_CHECKPOINT_ID,
                signer=self.keys.checkpoint_signer,
                created_at=recovered_at,
            )
            self._store_checkpoint(checkpoint)
            return events, checkpoint, "recovered-immediate-child"
        retained_size = self._verify_prefix(checkpoint, digests)
        distance = len(events) - retained_size
        if distance == 0:
            ledger.verify(
                source_public_keys=source_public_keys,
                checkpoint=checkpoint,
                checkpoint_key=self.keys.checkpoint_key,
            )
            return events, checkpoint, "retained-head"
        if distance != 1:
            raise MedorArchitectureError("architecture checkpoint loss exceeds one child")
        checkpoint = ledger.checkpoint(
            checkpoint_id=CUSTODY_CHECKPOINT_ID,
            signer=self.keys.checkpoint_signer,
            created_at=recovered_at,
        )
        self._store_checkpoint(checkpoint)
        return events, checkpoint, "recovered-immediate-child"

    def _record_admission_custody(
        self,
        *,
        payload_digest: str,
        observed_at: str,
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], str, str]:
        with (
            self._exclusive_custody(),
            LedgerStore(
                self.ledger_path,
                tenant_id=TENANT_ID,
                ledger_id=CUSTODY_LEDGER_ID,
                busy_timeout_ms=CUSTODY_SQLITE_BUSY_TIMEOUT_MS,
            ) as ledger,
        ):
            events, checkpoint, open_status = self._open_verified(
                ledger,
                recovered_at=observed_at,
            )
            matching = [event for event in events if event["payload_digest"] == payload_digest]
            if len(matching) > 1:
                raise MedorArchitectureError("architecture admission was recorded more than once")
            if matching:
                custody_event = matching[0]
                write_status = "already-recorded"
            else:
                source_events = [event for event in events if event["source_id"] == SOURCE_ID]
                previous_digest = event_digest(source_events[-1]) if source_events else None
                custody_event = build_ledger_event(
                    tenant_id=TENANT_ID,
                    source_id=SOURCE_ID,
                    source_sequence=len(source_events),
                    event_type="observation",
                    payload_digest=payload_digest,
                    previous_event_digest=previous_digest,
                    signer=self.keys.source_signer,
                    recorded_at=observed_at,
                )
                if checkpoint is None:
                    ledger.append(custody_event)
                else:
                    ledger.append_at_checkpoint(
                        custody_event,
                        source_public_keys=self._source_public_keys(events),
                        checkpoint=checkpoint,
                        checkpoint_key=self.keys.checkpoint_key,
                    )
                checkpoint = ledger.checkpoint(
                    checkpoint_id=CUSTODY_CHECKPOINT_ID,
                    signer=self.keys.checkpoint_signer,
                    created_at=observed_at,
                )
                self._store_checkpoint(checkpoint)
                write_status = "recorded"
            if checkpoint is None:
                raise MedorArchitectureError("architecture checkpoint was not created")
            inclusion = ledger.inclusion_proof(event_digest(custody_event))
            ledger.verify(
                source_public_keys=self._source_public_keys(ledger.events()),
                checkpoint=checkpoint,
                checkpoint_key=self.keys.checkpoint_key,
            )
            return custody_event, checkpoint, inclusion, open_status, write_status

    def admit(
        self,
        *,
        mind_admission: Mapping[str, Any],
        mind: Mapping[str, Any],
        observed_at: str,
        as_of: str,
    ) -> dict[str, Any]:
        """Record once, then return persistent custody plus the exact route proof."""

        architecture = build_medor_architecture_admission(
            mind_admission=mind_admission,
            mind=mind,
            keys=self.keys,
            observed_at=observed_at,
            as_of=as_of,
        )
        admission, _projection = _validate_mind_inputs(mind_admission, mind)
        payload_digest = _mind_payload_digest(admission)
        for attempt in range(CUSTODY_ADMISSION_ATTEMPTS):
            try:
                (
                    custody_event,
                    checkpoint,
                    inclusion,
                    open_status,
                    write_status,
                ) = self._record_admission_custody(
                    payload_digest=payload_digest,
                    observed_at=observed_at,
                )
                break
            except Exception as exc:
                if (
                    attempt + 1 >= CUSTODY_ADMISSION_ATTEMPTS
                    or not _is_retryable_custody_conflict(exc)
                ):
                    raise
                time.sleep(CUSTODY_ADMISSION_RETRY_SECONDS * (2**attempt))
        custody_core = {
            "protocol": "integrity-guardian/medor-architecture-custody/v1",
            "architecture_admission_id": architecture["admission_id"],
            "mind_admission_receipt_id": admission["receipt_id"],
            "payload_digest": payload_digest,
            "event": custody_event,
            "checkpoint": checkpoint,
            "inclusion_proof": inclusion,
            "open_status": open_status,
            "write_status": write_status,
            "home_record_count": 0,
            "production_authority": False,
        }
        custody = {
            **custody_core,
            "receipt_id": digest_object(custody_core, domain="medor-architecture-custody-v1"),
        }
        validate("medor-architecture-custody", custody)
        verify_medor_architecture_custody(
            custody,
            architecture=architecture,
            source_key=self.keys.source_key,
            checkpoint_key=self.keys.checkpoint_key,
        )
        return {"architecture": architecture, "custody": custody}

    def plan_event_append(
        self,
        *,
        architecture: Mapping[str, Any],
        security: VerifiedMedorSecurityAdmission,
        request_digest: str,
        exact_event_exists: bool,
        passive_witness_digest: str,
        observed_at: str,
        as_of: str,
        context_admission_id: str | None = None,
        logical_generation: int | None = None,
    ) -> dict[str, Any]:
        return plan_medor_event_append(
            architecture=architecture,
            security=security,
            request_digest=request_digest,
            exact_event_exists=exact_event_exists,
            passive_witness_digest=passive_witness_digest,
            observed_at=observed_at,
            as_of=as_of,
            context_admission_id=context_admission_id,
            logical_generation=logical_generation,
        )

    def plan_event_execution(
        self,
        *,
        pre_action: Mapping[str, Any],
        authority: Mapping[str, Any],
        observed_at: str,
        as_of: str,
    ) -> dict[str, Any]:
        if self.event_authority_key is None:
            raise MedorArchitectureError("external event append authority key is not configured")
        return plan_medor_event_execution(
            pre_action=pre_action,
            authority=authority,
            source_key=self.keys.source_key,
            checkpoint_key=self.keys.checkpoint_key,
            authority_key=self.event_authority_key,
            observed_at=observed_at,
            as_of=as_of,
        )

    def plan_event_outcome(
        self,
        *,
        action_stage: Mapping[str, Any],
        outcome: str,
        passive_witness_digest: str,
        feedback_receipt_id: str,
        feedback: Mapping[str, Any],
        observed_at: str,
        as_of: str,
    ) -> dict[str, Any]:
        return plan_medor_event_outcome(
            action_stage=action_stage,
            outcome=outcome,
            passive_witness_digest=passive_witness_digest,
            feedback_receipt_id=feedback_receipt_id,
            feedback=feedback,
            source_key=self.keys.source_key,
            checkpoint_key=self.keys.checkpoint_key,
            observed_at=observed_at,
            as_of=as_of,
        )

    def authorize_event_append(
        self,
        *,
        architecture_admission_id: str,
        security_admission_id: str,
        request_digest: str,
        route_digest: str,
        external_decision: Mapping[str, Any],
        recorded_at: str,
        context_admission_id: str | None = None,
        logical_generation: int | None = None,
    ) -> dict[str, Any]:
        """Record one exact policy grant and consume it before any append call."""

        if self.event_authority_key is None:
            raise MedorArchitectureError("external event append authority key is not configured")
        context_binding = _event_append_context_binding(
            context_admission_id=context_admission_id,
            logical_generation=logical_generation,
        )
        version = 2 if context_binding else 1
        verified_external_decision = verify_medor_event_append_decision(
            external_decision,
            authority_key=self.event_authority_key,
            architecture_admission_id=architecture_admission_id,
            security_admission_id=security_admission_id,
            request_digest=request_digest,
            at_time=recorded_at,
            context_admission_id=context_admission_id,
            logical_generation=logical_generation,
        )
        for value, field in (
            (architecture_admission_id, "architecture admission"),
            (security_admission_id, "security admission"),
            (request_digest, "request"),
            (route_digest, "route"),
        ):
            if not isinstance(value, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", value):
                raise MedorArchitectureError(f"event append {field} digest is invalid")
        grant_core = {
            "architecture_admission_id": architecture_admission_id,
            "security_admission_id": security_admission_id,
            "request_digest": request_digest,
            "route_digest": route_digest,
            **context_binding,
            "external_decision_id": verified_external_decision["decision_id"],
            "scope": "single-canonical-seed-append",
            "max_transitions": 1,
            "production_authority": False,
        }
        grant_id = digest_object(grant_core, domain=f"medor-event-append-grant-v{version}")
        # Request identity, not route identity, is the replay boundary. A later
        # session may compute a new observed-at route stage, but it must never
        # receive a second grant for the same immutable append request.
        source_id = "source:medor-event-grant:" + request_digest.split(":", 1)[1]
        decision_payload = digest_object(
            {
                **grant_core,
                "grant_id": grant_id,
                "decision": "approved-by-external-authority",
            },
            domain=f"medor-event-append-decision-v{version}",
        )
        with (
            self._exclusive_custody(),
            LedgerStore(
                self.ledger_path,
                tenant_id=TENANT_ID,
                ledger_id=CUSTODY_LEDGER_ID,
                busy_timeout_ms=CUSTODY_SQLITE_BUSY_TIMEOUT_MS,
            ) as ledger,
        ):
            events, checkpoint, open_status = self._open_verified(ledger, recovered_at=recorded_at)
            source_events = [event for event in events if event["source_id"] == source_id]
            if len(source_events) >= 2:
                raise MedorArchitectureError("event append grant is already consumed")
            if source_events:
                decision_event = source_events[0]
                if decision_event["payload_digest"] != decision_payload:
                    raise MedorArchitectureError("event append grant decision mismatch")
                decision_checkpoint = checkpoint
            else:
                decision_event = build_ledger_event(
                    tenant_id=TENANT_ID,
                    source_id=source_id,
                    source_sequence=0,
                    event_type="toolz-authorization-decision",
                    payload_digest=decision_payload,
                    previous_event_digest=None,
                    signer=self.keys.source_signer,
                    recorded_at=recorded_at,
                )
                if checkpoint is None:
                    ledger.append(decision_event)
                else:
                    ledger.append_at_checkpoint(
                        decision_event,
                        source_public_keys=self._source_public_keys(events),
                        checkpoint=checkpoint,
                        checkpoint_key=self.keys.checkpoint_key,
                    )
                decision_checkpoint = ledger.checkpoint(
                    checkpoint_id=CUSTODY_CHECKPOINT_ID,
                    signer=self.keys.checkpoint_signer,
                    created_at=recorded_at,
                )
                self._store_checkpoint(decision_checkpoint)
                checkpoint = decision_checkpoint
                events.append(decision_event)
            consumption_payload = digest_object(
                {
                    "grant_id": grant_id,
                    "decision_event_digest": event_digest(decision_event),
                    "request_digest": request_digest,
                    "consumption": "single-use-consumed-before-action",
                    "automatic_retry": False,
                    "production_authority": False,
                },
                domain=f"medor-event-append-consumption-v{version}",
            )
            consumption_event = build_ledger_event(
                tenant_id=TENANT_ID,
                source_id=source_id,
                source_sequence=1,
                event_type="toolz-authorization-consumption",
                payload_digest=consumption_payload,
                previous_event_digest=event_digest(decision_event),
                signer=self.keys.source_signer,
                recorded_at=recorded_at,
            )
            if checkpoint is None:
                raise MedorArchitectureError("event append decision checkpoint is absent")
            ledger.append_at_checkpoint(
                consumption_event,
                source_public_keys=self._source_public_keys(events),
                checkpoint=checkpoint,
                checkpoint_key=self.keys.checkpoint_key,
            )
            consumption_checkpoint = ledger.checkpoint(
                checkpoint_id=CUSTODY_CHECKPOINT_ID,
                signer=self.keys.checkpoint_signer,
                created_at=recorded_at,
            )
            self._store_checkpoint(consumption_checkpoint)
            decision_proof = ledger.inclusion_proof(event_digest(decision_event))
            proof = ledger.inclusion_proof(event_digest(consumption_event))
            ledger.verify(
                source_public_keys=self._source_public_keys(ledger.events()),
                checkpoint=consumption_checkpoint,
                checkpoint_key=self.keys.checkpoint_key,
            )
        core = {
            "protocol": f"integrity-guardian/medor-event-one-use-authority/v{version}",
            "grant_id": grant_id,
            "architecture_admission_id": architecture_admission_id,
            "security_admission_id": security_admission_id,
            "request_digest": request_digest,
            "route_digest": route_digest,
            **context_binding,
            "external_decision": verified_external_decision,
            "decision_event": decision_event,
            "decision_checkpoint": decision_checkpoint,
            "decision_inclusion_proof": decision_proof,
            "consumption_event": consumption_event,
            "consumption_checkpoint": consumption_checkpoint,
            "consumption_inclusion_proof": proof,
            "open_status": open_status,
            "single_use": True,
            "max_transitions": 1,
            "consumption_recorded": True,
            "automatic_retry_allowed": False,
            "production_authority": False,
        }
        receipt = {
            **core,
            "receipt_id": digest_object(
                core,
                domain=f"medor-event-one-use-authority-v{version}",
            ),
        }
        verify_medor_event_append_authority(
            receipt,
            source_key=self.keys.source_key,
            checkpoint_key=self.keys.checkpoint_key,
            authority_key=self.event_authority_key,
            at_time=recorded_at,
        )
        return receipt

    def record_event_append_outcome(
        self,
        *,
        grant_id: str,
        request_digest: str,
        outcome: str,
        witness_digest: str,
        recorded_at: str,
    ) -> dict[str, Any]:
        _qualified_digest(grant_id, "grant")
        _qualified_digest(request_digest, "request")
        _qualified_digest(witness_digest, "witness")
        if outcome not in {
            "confirmed-success",
            "confirmed-failure",
            "unknown-outcome",
        }:
            raise MedorArchitectureError("event append outcome is invalid")
        outcome_core = {
            "grant_id": grant_id,
            "request_digest": request_digest,
            "outcome": outcome,
            "witness_digest": witness_digest,
            "automatic_retry_allowed": False,
            "production_authority": False,
        }
        outcome_digest = digest_object(outcome_core, domain="medor-event-append-outcome-v1")
        source_id = "source:medor-event-outcome:" + grant_id.split(":", 1)[1]
        with (
            self._exclusive_custody(),
            LedgerStore(
                self.ledger_path,
                tenant_id=TENANT_ID,
                ledger_id=CUSTODY_LEDGER_ID,
                busy_timeout_ms=CUSTODY_SQLITE_BUSY_TIMEOUT_MS,
            ) as ledger,
        ):
            events, checkpoint, open_status = self._open_verified(ledger, recovered_at=recorded_at)
            grant_source_id = "source:medor-event-grant:" + request_digest.split(":", 1)[1]
            grant_events = [event for event in events if event["source_id"] == grant_source_id]
            if len(grant_events) != 2 or [event["source_sequence"] for event in grant_events] != [
                0,
                1,
            ]:
                raise MedorArchitectureError("event append outcome lacks a consumed one-use grant")
            prior = [event for event in events if event["source_id"] == source_id]
            if prior:
                if len(prior) != 1 or prior[0]["payload_digest"] != outcome_digest:
                    raise MedorArchitectureError("event append outcome replay mismatch")
                outcome_event = prior[0]
                write_status = "already-recorded"
            else:
                outcome_event = build_ledger_event(
                    tenant_id=TENANT_ID,
                    source_id=source_id,
                    source_sequence=0,
                    event_type="observation",
                    payload_digest=outcome_digest,
                    previous_event_digest=None,
                    signer=self.keys.source_signer,
                    recorded_at=recorded_at,
                )
                if checkpoint is None:
                    ledger.append(outcome_event)
                else:
                    ledger.append_at_checkpoint(
                        outcome_event,
                        source_public_keys=self._source_public_keys(events),
                        checkpoint=checkpoint,
                        checkpoint_key=self.keys.checkpoint_key,
                    )
                checkpoint = ledger.checkpoint(
                    checkpoint_id=CUSTODY_CHECKPOINT_ID,
                    signer=self.keys.checkpoint_signer,
                    created_at=recorded_at,
                )
                self._store_checkpoint(checkpoint)
                write_status = "recorded"
            if checkpoint is None:
                raise MedorArchitectureError("event append outcome checkpoint is absent")
            proof = ledger.inclusion_proof(event_digest(outcome_event))
        core = {
            "protocol": "integrity-guardian/medor-event-outcome-feedback/v1",
            **outcome_core,
            "outcome_event": outcome_event,
            "checkpoint": checkpoint,
            "inclusion_proof": proof,
            "open_status": open_status,
            "write_status": write_status,
        }
        receipt = {
            **core,
            "receipt_id": digest_object(core, domain="medor-event-outcome-feedback-v1"),
        }
        verify_medor_event_outcome_feedback(
            receipt,
            source_key=self.keys.source_key,
            checkpoint_key=self.keys.checkpoint_key,
        )
        return receipt

    def sign_passive_witness(self, witness_core: Mapping[str, Any]) -> dict[str, Any]:
        """Sign a content-free SQLite observation with the distinct checkpoint key."""

        core = deepcopy(dict(witness_core))
        core["production_authority"] = False
        core["causality_proven"] = False
        core["action_invoked_by_observer"] = False
        receipt = {
            "receipt_id": digest_object(core, domain="medor-event-passive-witness-v1"),
            **core,
        }
        signed = self.keys.checkpoint_signer.sign(receipt)
        verify_medor_passive_witness(signed, checkpoint_key=self.keys.checkpoint_key)
        return signed


def _verify_custody_checkpoint(
    checkpoint: Mapping[str, Any], checkpoint_key: TrustedKey
) -> dict[str, Any]:
    candidate = deepcopy(dict(checkpoint))
    validate("checkpoint", candidate)
    if (
        candidate.get("checkpoint_id") != CUSTODY_CHECKPOINT_ID
        or candidate.get("tenant_id") != TENANT_ID
        or candidate.get("ledger_id") != CUSTODY_LEDGER_ID
        or candidate.get("signer_id") != checkpoint_key.key_id
        or candidate.get("signature", {}).get("key_id") != checkpoint_key.key_id
        or not verify_signature(candidate, checkpoint_key.public_key)
    ):
        raise MedorArchitectureError("event receipt checkpoint is invalid")
    return candidate


def verify_medor_event_append_authority(
    authority: Mapping[str, Any],
    *,
    source_key: TrustedKey,
    checkpoint_key: TrustedKey,
    authority_key: TrustedKey,
    at_time: str,
) -> dict[str, Any]:
    candidate = deepcopy(dict(authority))
    protocol = candidate.get("protocol")
    if protocol == "integrity-guardian/medor-event-one-use-authority/v1":
        version = 1
    elif protocol == "integrity-guardian/medor-event-one-use-authority/v2":
        version = 2
    else:
        raise MedorArchitectureError("event append authority protocol is invalid")
    validate(
        "medor-event-one-use-authority-v2" if version == 2 else "medor-event-one-use-authority",
        candidate,
    )
    context_binding = _event_append_context_binding(
        context_admission_id=candidate.get("context_admission_id"),
        logical_generation=candidate.get("logical_generation"),
    )
    if bool(context_binding) != (version == 2):
        raise MedorArchitectureError("event append authority context binding mismatch")
    core = deepcopy(candidate)
    receipt_id = core.pop("receipt_id")
    if receipt_id != digest_object(
        core,
        domain=f"medor-event-one-use-authority-v{version}",
    ):
        raise MedorArchitectureError("event append authority receipt identity mismatch")
    external_decision = verify_medor_event_append_decision(
        candidate["external_decision"],
        authority_key=authority_key,
        architecture_admission_id=candidate["architecture_admission_id"],
        security_admission_id=candidate["security_admission_id"],
        request_digest=candidate["request_digest"],
        at_time=at_time,
        context_admission_id=candidate.get("context_admission_id"),
        logical_generation=candidate.get("logical_generation"),
    )
    grant_core = {
        "architecture_admission_id": candidate["architecture_admission_id"],
        "security_admission_id": candidate["security_admission_id"],
        "request_digest": candidate["request_digest"],
        "route_digest": candidate["route_digest"],
        **context_binding,
        "external_decision_id": external_decision["decision_id"],
        "scope": "single-canonical-seed-append",
        "max_transitions": 1,
        "production_authority": False,
    }
    grant_id = digest_object(grant_core, domain=f"medor-event-append-grant-v{version}")
    if candidate["grant_id"] != grant_id:
        raise MedorArchitectureError("event append authority grant identity mismatch")
    source_id = "source:medor-event-grant:" + candidate["request_digest"].split(":", 1)[1]
    decision_payload = digest_object(
        {
            **grant_core,
            "grant_id": grant_id,
            "decision": "approved-by-external-authority",
        },
        domain=f"medor-event-append-decision-v{version}",
    )
    decision = verify_ledger_event(
        candidate["decision_event"],
        source_key,
        expected_tenant_id=TENANT_ID,
        expected_source_id=source_id,
        expected_event_type="toolz-authorization-decision",
        expected_payload_digest=decision_payload,
    )
    if decision["source_sequence"] != 0 or decision["previous_event_digest"] is not None:
        raise MedorArchitectureError("event append authority decision chain is invalid")
    consumption_payload = digest_object(
        {
            "grant_id": grant_id,
            "decision_event_digest": event_digest(decision),
            "request_digest": candidate["request_digest"],
            "consumption": "single-use-consumed-before-action",
            "automatic_retry": False,
            "production_authority": False,
        },
        domain=f"medor-event-append-consumption-v{version}",
    )
    consumption = verify_ledger_event(
        candidate["consumption_event"],
        source_key,
        expected_tenant_id=TENANT_ID,
        expected_source_id=source_id,
        expected_event_type="toolz-authorization-consumption",
        expected_payload_digest=consumption_payload,
    )
    if consumption["source_sequence"] != 1 or consumption["previous_event_digest"] != event_digest(
        decision
    ):
        raise MedorArchitectureError("event append authority consumption chain is invalid")
    _verify_custody_checkpoint(candidate["decision_checkpoint"], checkpoint_key)
    checkpoint = _verify_custody_checkpoint(candidate["consumption_checkpoint"], checkpoint_key)
    for field, event in (
        ("decision_inclusion_proof", decision),
        ("consumption_inclusion_proof", consumption),
    ):
        verify_ledger_inclusion_proof(
            candidate[field],
            expected_tenant_id=TENANT_ID,
            expected_ledger_id=CUSTODY_LEDGER_ID,
            expected_event_digest=event_digest(event),
            expected_root_digest=checkpoint["root_digest"],
            expected_tree_size=checkpoint["tree_size"],
        )
    return {
        "ok": True,
        "receipt_id": receipt_id,
        "grant_id": grant_id,
        **context_binding,
        "consumption_recorded": True,
        "automatic_retry_allowed": False,
        "production_authority": False,
    }


def verify_medor_event_outcome_feedback(
    feedback: Mapping[str, Any],
    *,
    source_key: TrustedKey,
    checkpoint_key: TrustedKey,
) -> dict[str, Any]:
    candidate = deepcopy(dict(feedback))
    validate("medor-event-outcome-feedback", candidate)
    core = deepcopy(candidate)
    receipt_id = core.pop("receipt_id")
    if receipt_id != digest_object(core, domain="medor-event-outcome-feedback-v1"):
        raise MedorArchitectureError("event outcome feedback identity mismatch")
    outcome_core = {
        "grant_id": candidate["grant_id"],
        "request_digest": candidate["request_digest"],
        "outcome": candidate["outcome"],
        "witness_digest": candidate["witness_digest"],
        "automatic_retry_allowed": False,
        "production_authority": False,
    }
    outcome_digest = digest_object(outcome_core, domain="medor-event-append-outcome-v1")
    source_id = "source:medor-event-outcome:" + candidate["grant_id"].split(":", 1)[1]
    event = verify_ledger_event(
        candidate["outcome_event"],
        source_key,
        expected_tenant_id=TENANT_ID,
        expected_source_id=source_id,
        expected_event_type="observation",
        expected_payload_digest=outcome_digest,
    )
    if event["source_sequence"] != 0 or event["previous_event_digest"] is not None:
        raise MedorArchitectureError("event outcome feedback chain is invalid")
    checkpoint = _verify_custody_checkpoint(candidate["checkpoint"], checkpoint_key)
    verify_ledger_inclusion_proof(
        candidate["inclusion_proof"],
        expected_tenant_id=TENANT_ID,
        expected_ledger_id=CUSTODY_LEDGER_ID,
        expected_event_digest=event_digest(event),
        expected_root_digest=checkpoint["root_digest"],
        expected_tree_size=checkpoint["tree_size"],
    )
    return {
        "ok": True,
        "receipt_id": receipt_id,
        "outcome": candidate["outcome"],
        "automatic_retry_allowed": False,
        "production_authority": False,
    }


def verify_medor_passive_witness(
    witness: Mapping[str, Any], *, checkpoint_key: TrustedKey
) -> dict[str, Any]:
    candidate = deepcopy(dict(witness))
    validate("medor-event-passive-witness", candidate)
    unsigned = deepcopy(candidate)
    unsigned.pop("signature")
    receipt_id = unsigned.pop("receipt_id")
    if (
        receipt_id != digest_object(unsigned, domain="medor-event-passive-witness-v1")
        or candidate["signature"]["key_id"] != checkpoint_key.key_id
        or not verify_signature(candidate, checkpoint_key.public_key)
    ):
        raise MedorArchitectureError("passive witness identity or signature is invalid")
    return {
        "ok": True,
        "receipt_id": receipt_id,
        "phase": candidate["phase"],
        "status": candidate["status"],
        "production_authority": False,
        "causality_proven": False,
    }


def verify_medor_architecture_custody(
    custody: Mapping[str, Any],
    *,
    architecture: Mapping[str, Any],
    source_key: TrustedKey,
    checkpoint_key: TrustedKey,
) -> dict[str, Any]:
    candidate = deepcopy(dict(custody))
    validate("medor-architecture-custody", candidate)
    core = deepcopy(candidate)
    receipt_id = core.pop("receipt_id")
    if receipt_id != digest_object(core, domain="medor-architecture-custody-v1"):
        raise MedorArchitectureError("architecture custody receipt identity mismatch")
    if candidate["architecture_admission_id"] != architecture.get("admission_id") or candidate[
        "mind_admission_receipt_id"
    ] != architecture.get("mind_admission", {}).get("receipt_id"):
        raise MedorArchitectureError("architecture custody admission binding mismatch")
    event = verify_ledger_event(
        candidate["event"],
        source_key,
        expected_tenant_id=TENANT_ID,
        expected_source_id=SOURCE_ID,
        expected_event_type="observation",
        expected_payload_digest=candidate["payload_digest"],
    )
    checkpoint = candidate["checkpoint"]
    if (
        checkpoint.get("checkpoint_id") != CUSTODY_CHECKPOINT_ID
        or checkpoint.get("tenant_id") != TENANT_ID
        or checkpoint.get("ledger_id") != CUSTODY_LEDGER_ID
        or checkpoint.get("signer_id") != checkpoint_key.key_id
        or checkpoint.get("signature", {}).get("key_id") != checkpoint_key.key_id
        or not verify_signature(checkpoint, checkpoint_key.public_key)
    ):
        raise MedorArchitectureError("architecture custody checkpoint is invalid")
    verify_ledger_inclusion_proof(
        candidate["inclusion_proof"],
        expected_tenant_id=TENANT_ID,
        expected_ledger_id=CUSTODY_LEDGER_ID,
        expected_event_digest=event_digest(event),
        expected_root_digest=checkpoint["root_digest"],
        expected_tree_size=checkpoint["tree_size"],
    )
    return {
        "ok": True,
        "receipt_id": receipt_id,
        "tree_size": checkpoint["tree_size"],
        "write_status": candidate["write_status"],
        "production_authority": False,
    }
