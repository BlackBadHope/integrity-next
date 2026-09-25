"""Cross-platform lifecycle evidence for Integrity Adapter SDK admission.

The portable protocol is source code.  This module records a stronger claim:
the same adapter receipt model survived clean installation, upgrade, identity
revocation and cold recovery on real Linux, Windows and macOS hosts.  It has
no installer, transport, credential or execution surface of its own.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
from datetime import datetime
from typing import Any

from .adapter_conformance import (
    require_adapter_conformance_readiness,
    verify_adapter_conformance_receipt,
)
from .adapter_sdk import (
    ADAPTER_SDK_VERSION,
    AdapterSdkError,
    adapter_capability_manifest_digest,
    verify_adapter_capability_manifest,
)
from .canonical import canonical_bytes, parse_json_strict
from .hashing import digest_object
from .schemas import validate
from .signing import (
    Ed25519Signer,
    TrustedKey,
    public_key_fingerprint,
    verify_signature,
)

PORTABLE_FAMILIES = ("linux", "windows", "macos")
DEPLOYMENT_COHORT_ROLES = ("linux-primary", "windows-vm", "client-workstation")
DEPLOYMENT_COHORT_PACKAGE_DISTRIBUTION = "integrity-adapter-sdk"
DEPLOYMENT_COHORT_PACKAGE_VERSION = "1.0.0"
DEPLOYMENT_COHORT_GUARDIAN_DISTRIBUTION = "integrity-guardian"
DEPLOYMENT_COHORT_GUARDIAN_VERSION = "6.0.0"
DEPLOYMENT_COHORT_ROLE_FAMILIES = {
    "linux-primary": "linux",
    "windows-vm": "windows",
    "client-workstation": "windows",
}
_DEPLOYMENT_LIFECYCLE_PHASES = ("install", "upgrade", "revoke", "recovery")
_DEPLOYMENT_PHASE_STATE_KINDS = {
    "install": ("absent", "candidate-installed"),
    "upgrade": ("predecessor-installed", "candidate-installed"),
    "revoke": ("candidate-installed", "candidate-revoked"),
    "recovery": (
        "candidate-revoked",
        "candidate-recovered-revocation-preserved",
    ),
}


class AdapterPortabilityError(AdapterSdkError):
    """Raised when platform lifecycle evidence is incomplete or ambiguous."""


def _freeze(value: Mapping[str, Any]) -> dict[str, Any]:
    try:
        candidate = parse_json_strict(canonical_bytes(dict(value)))
    except Exception as exc:
        raise AdapterPortabilityError("ASDK portability document rejected") from exc
    if not isinstance(candidate, dict):
        raise AdapterPortabilityError("ASDK portability document rejected")
    return candidate


def _identity(
    document: Mapping[str, Any],
    *,
    field: str,
    prefix: str,
    domain: str,
) -> str:
    core = deepcopy(dict(document))
    core.pop(field, None)
    core.pop("signature", None)
    return prefix + digest_object(core, domain=domain).split(":", 1)[1]


def _verify_signed(
    document: Mapping[str, Any],
    *,
    schema: str,
    field: str,
    prefix: str,
    domain: str,
    trusted_key: TrustedKey,
) -> dict[str, Any]:
    candidate = _freeze(document)
    try:
        validate(schema, candidate)
    except Exception as exc:
        raise AdapterPortabilityError(f"ASDK {schema} schema rejected") from exc
    if candidate[field] != _identity(
        candidate,
        field=field,
        prefix=prefix,
        domain=domain,
    ):
        raise AdapterPortabilityError(f"ASDK {schema} identity mismatch")
    if (
        candidate["signer_id"] != trusted_key.key_id
        or candidate["signature"]["key_id"] != trusted_key.key_id
        or not verify_signature(candidate, trusted_key.public_key)
    ):
        raise AdapterPortabilityError(f"ASDK {schema} signature rejected")
    return candidate


def _manifest_reference(manifest: Mapping[str, Any]) -> dict[str, str]:
    return {
        "manifest_id": str(manifest["manifest_id"]),
        "manifest_digest": adapter_capability_manifest_digest(manifest),
        "adapter_id": str(manifest["adapter_id"]),
        "adapter_artifact_digest": str(manifest["adapter_artifact_digest"]),
    }


def adapter_platform_lifecycle_evidence_digest(
    evidence: Mapping[str, Any],
) -> str:
    return digest_object(
        dict(evidence),
        domain="adapter-platform-lifecycle-evidence-v1",
    )


def adapter_portability_receipt_digest(receipt: Mapping[str, Any]) -> str:
    return digest_object(dict(receipt), domain="adapter-portability-receipt-v1")


def adapter_deployment_host_lifecycle_evidence_digest(
    evidence: Mapping[str, Any],
) -> str:
    return digest_object(
        dict(evidence),
        domain="adapter-deployment-host-lifecycle-evidence-v1",
    )


def adapter_deployment_host_lifecycle_evidence_v2_digest(
    evidence: Mapping[str, Any],
) -> str:
    return digest_object(
        dict(evidence),
        domain="adapter-deployment-host-lifecycle-evidence-v2",
    )


def adapter_deployment_lifecycle_execution_receipt_digest(
    receipt: Mapping[str, Any],
) -> str:
    return digest_object(
        dict(receipt),
        domain="adapter-deployment-lifecycle-execution-receipt-v1",
    )


def adapter_deployment_lifecycle_precondition_receipt_digest(
    receipt: Mapping[str, Any],
) -> str:
    return digest_object(
        dict(receipt),
        domain="adapter-deployment-lifecycle-precondition-receipt-v1",
    )


def adapter_deployment_lifecycle_postcondition_receipt_digest(
    receipt: Mapping[str, Any],
) -> str:
    return digest_object(
        dict(receipt),
        domain="adapter-deployment-lifecycle-postcondition-receipt-v1",
    )


def adapter_deployment_lifecycle_phase_receipt_digest(
    receipt: Mapping[str, Any],
) -> str:
    return digest_object(
        dict(receipt),
        domain="adapter-deployment-lifecycle-phase-receipt-v1",
    )


def adapter_deployment_cohort_receipt_digest(receipt: Mapping[str, Any]) -> str:
    return digest_object(
        dict(receipt),
        domain="adapter-deployment-cohort-receipt-v1",
    )


def adapter_deployment_cohort_receipt_v2_digest(receipt: Mapping[str, Any]) -> str:
    return digest_object(
        dict(receipt),
        domain="adapter-deployment-cohort-receipt-v2",
    )


def _package_reference(
    *,
    distribution: str,
    version: str,
    artifact_digest: str,
) -> dict[str, str]:
    return {
        "distribution": distribution,
        "version": version,
        "artifact_digest": artifact_digest,
    }


def _lifecycle_result_v1(*, result: str, receipt_digest: str) -> dict[str, str]:
    return {"result": result, "receipt_digest": receipt_digest}


def build_adapter_deployment_host_lifecycle_evidence(
    *,
    manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    host_role: str,
    platform_family: str,
    architecture: str,
    host_identity_digest: str,
    platform_identity_digest: str,
    environment_identity_digest: str,
    package_distribution: str,
    package_version: str,
    package_artifact_digest: str,
    install_result: str,
    install_receipt_digest: str,
    upgrade_result: str,
    upgrade_receipt_digest: str,
    revoke_result: str,
    revoke_receipt_digest: str,
    recovery_result: str,
    recovery_receipt_digest: str,
    created_at: str,
    signer: Ed25519Signer,
) -> dict[str, Any]:
    """Build the immutable historical digest-only host evidence v1."""

    verified_manifest = verify_adapter_capability_manifest(
        manifest,
        adapter_key=adapter_key,
    )
    expected_family = DEPLOYMENT_COHORT_ROLE_FAMILIES.get(host_role)
    if expected_family is None:
        raise AdapterPortabilityError("ASDK deployment cohort host role is unsupported")
    if platform_family != expected_family:
        raise AdapterPortabilityError("ASDK deployment cohort host role/platform mismatch")
    if (
        package_distribution != DEPLOYMENT_COHORT_PACKAGE_DISTRIBUTION
        or package_version != DEPLOYMENT_COHORT_PACKAGE_VERSION
    ):
        raise AdapterPortabilityError("ASDK deployment cohort package identity mismatch")
    if signer.key_id == adapter_key.key_id:
        raise AdapterPortabilityError(
            "ASDK deployment cohort assessor must be independent from adapter signer"
        )
    lifecycle = {
        "install": _lifecycle_result_v1(
            result=install_result,
            receipt_digest=install_receipt_digest,
        ),
        "upgrade": _lifecycle_result_v1(
            result=upgrade_result,
            receipt_digest=upgrade_receipt_digest,
        ),
        "revoke": _lifecycle_result_v1(
            result=revoke_result,
            receipt_digest=revoke_receipt_digest,
        ),
        "recovery": _lifecycle_result_v1(
            result=recovery_result,
            receipt_digest=recovery_receipt_digest,
        ),
    }
    lifecycle_receipts = [phase["receipt_digest"] for phase in lifecycle.values()]
    if len(set(lifecycle_receipts)) != len(lifecycle_receipts):
        raise AdapterPortabilityError("ASDK deployment cohort lifecycle receipts must be distinct")
    core = {
        "protocol": "integrity-guardian/adapter-deployment-host-lifecycle-evidence/v1",
        "sdk_version": ADAPTER_SDK_VERSION,
        "manifest": _manifest_reference(verified_manifest),
        "package": _package_reference(
            distribution=package_distribution,
            version=package_version,
            artifact_digest=package_artifact_digest,
        ),
        "host": {
            "role": host_role,
            "platform_family": platform_family,
            "architecture": architecture,
            "host_identity_digest": host_identity_digest,
            "platform_identity_digest": platform_identity_digest,
            "environment_identity_digest": environment_identity_digest,
        },
        "lifecycle": lifecycle,
        "actual_host": True,
        "synthetic": False,
        "content_free": True,
        "independence": {
            "subject_signer_id": adapter_key.key_id,
            "assessor_signer_id": signer.key_id,
            "same_identity": False,
        },
        "authority_boundary": _authority_boundary(),
        "created_at": created_at,
        "signer_id": signer.key_id,
    }
    unsigned = {
        "evidence_id": _identity(
            core,
            field="evidence_id",
            prefix="adapter-deployment-host-lifecycle-evidence:",
            domain="adapter-deployment-host-lifecycle-evidence-identity-v1",
        ),
        **core,
    }
    signed = signer.sign(unsigned)
    validate("adapter-deployment-host-lifecycle-evidence", signed)
    return signed


def verify_adapter_deployment_host_lifecycle_evidence(
    evidence: Mapping[str, Any],
    *,
    manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    evidence_key: TrustedKey,
) -> dict[str, Any]:
    """Verify the immutable historical digest-only host evidence v1."""

    candidate = _verify_signed(
        evidence,
        schema="adapter-deployment-host-lifecycle-evidence",
        field="evidence_id",
        prefix="adapter-deployment-host-lifecycle-evidence:",
        domain="adapter-deployment-host-lifecycle-evidence-identity-v1",
        trusted_key=evidence_key,
    )
    verified_manifest = verify_adapter_capability_manifest(
        manifest,
        adapter_key=adapter_key,
    )
    if candidate["manifest"] != _manifest_reference(verified_manifest):
        raise AdapterPortabilityError("ASDK deployment cohort manifest mismatch")
    role = candidate["host"]["role"]
    if candidate["host"]["platform_family"] != DEPLOYMENT_COHORT_ROLE_FAMILIES.get(role):
        raise AdapterPortabilityError("ASDK deployment cohort host role/platform mismatch")
    if candidate["package"] != {
        "distribution": DEPLOYMENT_COHORT_PACKAGE_DISTRIBUTION,
        "version": DEPLOYMENT_COHORT_PACKAGE_VERSION,
        "artifact_digest": candidate["package"]["artifact_digest"],
    }:
        raise AdapterPortabilityError("ASDK deployment cohort package identity mismatch")
    if (
        candidate["signer_id"] == adapter_key.key_id
        or candidate["independence"]["subject_signer_id"] != adapter_key.key_id
        or candidate["independence"]["assessor_signer_id"] != evidence_key.key_id
    ):
        raise AdapterPortabilityError(
            "ASDK deployment cohort assessor is not independent from adapter signer"
        )
    lifecycle_receipts = [
        candidate["lifecycle"][phase]["receipt_digest"] for phase in _DEPLOYMENT_LIFECYCLE_PHASES
    ]
    if len(set(lifecycle_receipts)) != len(lifecycle_receipts):
        raise AdapterPortabilityError("ASDK deployment cohort lifecycle receipts must be distinct")
    return candidate


def _deployment_evidence_reference_v1(
    evidence: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "host_role": evidence["host"]["role"],
        "platform_family": evidence["host"]["platform_family"],
        "evidence_id": evidence["evidence_id"],
        "evidence_digest": adapter_deployment_host_lifecycle_evidence_digest(evidence),
        "host_identity_digest": evidence["host"]["host_identity_digest"],
        "environment_identity_digest": evidence["host"]["environment_identity_digest"],
        "assessor_signer_id": evidence["signer_id"],
    }


def _verified_deployment_evidence_set_v1(
    *,
    manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    evidence_documents: Sequence[Mapping[str, Any]],
    evidence_keys: Mapping[str, TrustedKey],
) -> list[dict[str, Any]]:
    verified: list[dict[str, Any]] = []
    identities: set[str] = set()
    for document in evidence_documents:
        key = evidence_keys.get(str(document.get("signer_id")))
        if key is None:
            raise AdapterPortabilityError("ASDK deployment cohort evidence signer is untrusted")
        candidate = verify_adapter_deployment_host_lifecycle_evidence(
            document,
            manifest=manifest,
            adapter_key=adapter_key,
            evidence_key=key,
        )
        if candidate["evidence_id"] in identities:
            raise AdapterPortabilityError("ASDK deployment cohort duplicate evidence")
        identities.add(candidate["evidence_id"])
        verified.append(candidate)
    return verified


def _deployment_cohort_core_v1(
    *,
    manifest: Mapping[str, Any],
    evidence: Sequence[Mapping[str, Any]],
    created_at: str,
    signer_id: str,
) -> dict[str, Any]:
    roles = [item["host"]["role"] for item in evidence]
    if set(roles) != set(DEPLOYMENT_COHORT_ROLES) or len(roles) != 3:
        raise AdapterPortabilityError(
            "ASDK deployment cohort requires exactly linux-primary, windows-vm and client-workstation"
        )
    packages = {
        (
            item["package"]["distribution"],
            item["package"]["version"],
            item["package"]["artifact_digest"],
        )
        for item in evidence
    }
    if len(packages) != 1:
        raise AdapterPortabilityError(
            "ASDK deployment cohort package artifact/version differs across hosts"
        )
    distribution, version, _artifact_digest = next(iter(packages))
    if (
        distribution != DEPLOYMENT_COHORT_PACKAGE_DISTRIBUTION
        or version != DEPLOYMENT_COHORT_PACKAGE_VERSION
    ):
        raise AdapterPortabilityError("ASDK deployment cohort package identity mismatch")
    for item in evidence:
        if any(
            item["lifecycle"][phase]["result"] != "passed" for phase in _DEPLOYMENT_LIFECYCLE_PHASES
        ):
            raise AdapterPortabilityError(
                "ASDK deployment cohort lifecycle is not complete on every host"
            )
    host_identities = {item["host"]["host_identity_digest"] for item in evidence}
    environment_identities = {item["host"]["environment_identity_digest"] for item in evidence}
    assessor_signers = {item["signer_id"] for item in evidence}
    if len(host_identities) != 3:
        raise AdapterPortabilityError("ASDK deployment cohort hosts must be distinct")
    if len(environment_identities) != 3:
        raise AdapterPortabilityError("ASDK deployment cohort environments must be distinct")
    if len(assessor_signers) != 3:
        raise AdapterPortabilityError(
            "ASDK deployment cohort requires one independent assessor per host"
        )
    lifecycle_receipts = [
        item["lifecycle"][phase]["receipt_digest"]
        for item in evidence
        for phase in _DEPLOYMENT_LIFECYCLE_PHASES
    ]
    if len(set(lifecycle_receipts)) != len(lifecycle_receipts):
        raise AdapterPortabilityError(
            "ASDK deployment cohort lifecycle receipt reused across hosts"
        )
    by_role = {item["host"]["role"]: item for item in evidence}
    ordered = [by_role[role] for role in DEPLOYMENT_COHORT_ROLES]
    package = ordered[0]["package"]
    return {
        "protocol": "integrity-guardian/adapter-deployment-cohort-receipt/v1",
        "sdk_version": ADAPTER_SDK_VERSION,
        "manifest": _manifest_reference(manifest),
        "package": dict(package),
        "evidence": [_deployment_evidence_reference_v1(item) for item in ordered],
        "result": {
            "host_roles": list(DEPLOYMENT_COHORT_ROLES),
            "lifecycle_complete": True,
            "exact_package_shared": True,
            "independent_assessors": True,
            "readiness": "deployment-cohort-ready",
        },
        "authority_boundary": _authority_boundary(),
        "created_at": created_at,
        "signer_id": signer_id,
    }


def build_adapter_deployment_cohort_receipt(
    *,
    manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    evidence_documents: Sequence[Mapping[str, Any]],
    evidence_keys: Mapping[str, TrustedKey],
    created_at: str,
    signer: Ed25519Signer,
) -> dict[str, Any]:
    """Build the immutable historical digest-only cohort receipt v1."""

    verified_manifest = verify_adapter_capability_manifest(
        manifest,
        adapter_key=adapter_key,
    )
    verified = _verified_deployment_evidence_set_v1(
        manifest=verified_manifest,
        adapter_key=adapter_key,
        evidence_documents=evidence_documents,
        evidence_keys=evidence_keys,
    )
    if signer.key_id == adapter_key.key_id or signer.key_id in {
        item["signer_id"] for item in verified
    }:
        raise AdapterPortabilityError("ASDK deployment cohort receipt signer must be independent")
    core = _deployment_cohort_core_v1(
        manifest=verified_manifest,
        evidence=verified,
        created_at=created_at,
        signer_id=signer.key_id,
    )
    unsigned = {
        "receipt_id": _identity(
            core,
            field="receipt_id",
            prefix="adapter-deployment-cohort-receipt:",
            domain="adapter-deployment-cohort-receipt-identity-v1",
        ),
        **core,
    }
    signed = signer.sign(unsigned)
    validate("adapter-deployment-cohort-receipt", signed)
    return signed


def verify_adapter_deployment_cohort_receipt(
    receipt: Mapping[str, Any],
    *,
    manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    evidence_documents: Sequence[Mapping[str, Any]],
    evidence_keys: Mapping[str, TrustedKey],
    receipt_key: TrustedKey,
) -> dict[str, Any]:
    """Verify the immutable historical digest-only cohort receipt v1."""

    candidate = _verify_signed(
        receipt,
        schema="adapter-deployment-cohort-receipt",
        field="receipt_id",
        prefix="adapter-deployment-cohort-receipt:",
        domain="adapter-deployment-cohort-receipt-identity-v1",
        trusted_key=receipt_key,
    )
    verified_manifest = verify_adapter_capability_manifest(
        manifest,
        adapter_key=adapter_key,
    )
    evidence = _verified_deployment_evidence_set_v1(
        manifest=verified_manifest,
        adapter_key=adapter_key,
        evidence_documents=evidence_documents,
        evidence_keys=evidence_keys,
    )
    if receipt_key.key_id == adapter_key.key_id or receipt_key.key_id in {
        item["signer_id"] for item in evidence
    }:
        raise AdapterPortabilityError("ASDK deployment cohort receipt signer must be independent")
    rebuilt = _deployment_cohort_core_v1(
        manifest=verified_manifest,
        evidence=evidence,
        created_at=candidate["created_at"],
        signer_id=receipt_key.key_id,
    )
    expected = deepcopy(candidate)
    expected.pop("signature", None)
    expected.pop("receipt_id", None)
    if rebuilt != expected:
        raise AdapterPortabilityError("ASDK deployment cohort receipt coverage mismatch")
    return candidate


def _guardian_reference(
    *,
    distribution: str,
    version: str,
    artifact_digest: str,
) -> dict[str, str]:
    return {
        "distribution": distribution,
        "version": version,
        "artifact_digest": artifact_digest,
    }


def _host_reference(
    *,
    host_role: str,
    platform_family: str,
    architecture: str,
    host_identity_digest: str,
    platform_identity_digest: str,
    environment_identity_digest: str,
) -> dict[str, str]:
    return {
        "role": host_role,
        "platform_family": platform_family,
        "architecture": architecture,
        "host_identity_digest": host_identity_digest,
        "platform_identity_digest": platform_identity_digest,
        "environment_identity_digest": environment_identity_digest,
    }


def _authority_boundary() -> dict[str, bool]:
    return {
        "issues_grants": False,
        "executes_actions": False,
        "memory_write": False,
        "production_authority": False,
    }


def _trusted_signer(signer: Ed25519Signer) -> TrustedKey:
    return TrustedKey(key_id=signer.key_id, public_key=signer.public_key)


def _require_distinct_key_material(
    *keys: TrustedKey,
    message: str,
) -> None:
    fingerprints = [public_key_fingerprint(key.public_key) for key in keys]
    if len(fingerprints) != len(set(fingerprints)):
        raise AdapterPortabilityError(message)


def _require_host_key_policy(
    key: TrustedKey,
    *,
    binding: Mapping[str, Any],
    signer_role: str,
    host_key_policy: Mapping[str, Mapping[str, str]],
) -> None:
    fingerprint = public_key_fingerprint(key.public_key)
    policy = host_key_policy.get(fingerprint)
    expected = {
        "host_role": str(binding["host"]["role"]),
        "host_identity_digest": str(binding["host"]["host_identity_digest"]),
        "signer_role": signer_role,
    }
    if not isinstance(policy, Mapping) or dict(policy) != expected:
        raise AdapterPortabilityError(
            "ASDK lifecycle signer is not allowed by verifier-supplied host policy"
        )


def _timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except (AttributeError, TypeError, ValueError) as exc:
        raise AdapterPortabilityError("ASDK lifecycle timestamp is malformed") from exc
    if parsed.tzinfo is None:
        raise AdapterPortabilityError("ASDK lifecycle timestamp must include timezone")
    return parsed


def _require_timestamp_order(*values: str) -> None:
    parsed = [_timestamp(value) for value in values]
    if parsed != sorted(parsed):
        raise AdapterPortabilityError("ASDK lifecycle timestamp order mismatch")


def _attempt_identity(binding: Mapping[str, Any]) -> str:
    return _identity(
        binding,
        field="attempt_id",
        prefix="adapter-deployment-lifecycle-attempt:",
        domain="adapter-deployment-lifecycle-attempt-identity-v1",
    )


def adapter_deployment_observed_state_digest(
    observed_state: Mapping[str, Any],
) -> str:
    core = deepcopy(dict(observed_state))
    core.pop("state_digest", None)
    return digest_object(core, domain="adapter-deployment-observed-state-v1")


def _validate_phase_binding(binding: Mapping[str, Any]) -> None:
    deployment = binding.get("deployment")
    if not isinstance(deployment, Mapping):
        raise AdapterPortabilityError("ASDK deployment lifecycle challenge is missing")
    phase = str(binding.get("phase"))
    expected_states = _DEPLOYMENT_PHASE_STATE_KINDS.get(phase)
    if expected_states is None:
        raise AdapterPortabilityError("ASDK deployment lifecycle phase is unsupported")
    host = binding.get("host")
    if not isinstance(host, Mapping):
        raise AdapterPortabilityError("ASDK deployment lifecycle host is malformed")
    role = str(host.get("role"))
    expected_family = DEPLOYMENT_COHORT_ROLE_FAMILIES.get(role)
    if expected_family is None:
        raise AdapterPortabilityError("ASDK deployment cohort host role is unsupported")
    if host.get("platform_family") != expected_family:
        raise AdapterPortabilityError("ASDK deployment cohort host role/platform mismatch")
    package = binding.get("package")
    if not isinstance(package, Mapping) or (
        package.get("distribution") != DEPLOYMENT_COHORT_PACKAGE_DISTRIBUTION
        or package.get("version") != DEPLOYMENT_COHORT_PACKAGE_VERSION
    ):
        raise AdapterPortabilityError("ASDK deployment cohort package identity mismatch")
    guardian = binding.get("guardian")
    if not isinstance(guardian, Mapping) or (
        guardian.get("distribution") != DEPLOYMENT_COHORT_GUARDIAN_DISTRIBUTION
        or guardian.get("version") != DEPLOYMENT_COHORT_GUARDIAN_VERSION
    ):
        raise AdapterPortabilityError("ASDK deployment cohort Guardian identity mismatch")
    transition = binding.get("transition")
    if not isinstance(transition, Mapping):
        raise AdapterPortabilityError("ASDK deployment lifecycle transition is malformed")
    from_state = transition.get("from_state")
    to_state = transition.get("to_state")
    if not isinstance(from_state, Mapping) or not isinstance(to_state, Mapping):
        raise AdapterPortabilityError("ASDK deployment lifecycle transition is malformed")
    if (from_state.get("kind"), to_state.get("kind")) != expected_states:
        raise AdapterPortabilityError("ASDK deployment lifecycle phase transition mismatch")
    predecessor = binding.get("predecessor")
    if phase == "upgrade":
        if not isinstance(predecessor, Mapping):
            raise AdapterPortabilityError(
                "ASDK deployment lifecycle upgrade requires exact predecessor"
            )
        predecessor_package = predecessor.get("package")
        predecessor_guardian = predecessor.get("guardian")
        if not isinstance(predecessor_package, Mapping) or not isinstance(
            predecessor_guardian, Mapping
        ):
            raise AdapterPortabilityError("ASDK deployment lifecycle predecessor is malformed")
        if (
            predecessor_package.get("distribution") != DEPLOYMENT_COHORT_PACKAGE_DISTRIBUTION
            or predecessor_package.get("version") == DEPLOYMENT_COHORT_PACKAGE_VERSION
            or predecessor_guardian.get("distribution") != DEPLOYMENT_COHORT_GUARDIAN_DISTRIBUTION
            or predecessor_guardian.get("version") == DEPLOYMENT_COHORT_GUARDIAN_VERSION
        ):
            raise AdapterPortabilityError("ASDK deployment lifecycle predecessor identity mismatch")
    elif predecessor is not None:
        raise AdapterPortabilityError(
            "ASDK deployment lifecycle predecessor is only valid for upgrade"
        )


def _phase_binding(
    *,
    manifest: Mapping[str, Any],
    deployment_run_id: str,
    challenge_digest: str,
    phase: str,
    host_role: str,
    platform_family: str,
    architecture: str,
    host_identity_digest: str,
    platform_identity_digest: str,
    environment_identity_digest: str,
    expected_package_artifact_digest: str,
    expected_guardian_artifact_digest: str,
    from_state_digest: str,
    to_state_digest: str,
    expected_predecessor: Mapping[str, Any],
) -> dict[str, Any]:
    state_kinds = _DEPLOYMENT_PHASE_STATE_KINDS.get(phase)
    if state_kinds is None:
        raise AdapterPortabilityError("ASDK deployment lifecycle phase is unsupported")
    predecessor_document = _freeze(expected_predecessor) if phase == "upgrade" else None
    binding = {
        "deployment": {
            "deployment_run_id": deployment_run_id,
            "challenge_digest": challenge_digest,
        },
        "phase": phase,
        "manifest": _manifest_reference(manifest),
        "package": _package_reference(
            distribution=DEPLOYMENT_COHORT_PACKAGE_DISTRIBUTION,
            version=DEPLOYMENT_COHORT_PACKAGE_VERSION,
            artifact_digest=expected_package_artifact_digest,
        ),
        "guardian": _guardian_reference(
            distribution=DEPLOYMENT_COHORT_GUARDIAN_DISTRIBUTION,
            version=DEPLOYMENT_COHORT_GUARDIAN_VERSION,
            artifact_digest=expected_guardian_artifact_digest,
        ),
        "host": _host_reference(
            host_role=host_role,
            platform_family=platform_family,
            architecture=architecture,
            host_identity_digest=host_identity_digest,
            platform_identity_digest=platform_identity_digest,
            environment_identity_digest=environment_identity_digest,
        ),
        "transition": {
            "from_state": {
                "kind": state_kinds[0],
                "state_digest": from_state_digest,
            },
            "to_state": {
                "kind": state_kinds[1],
                "state_digest": to_state_digest,
            },
        },
        "predecessor": predecessor_document,
    }
    _validate_phase_binding(binding)
    return binding


def _execution_reference(receipt: Mapping[str, Any]) -> dict[str, str]:
    return {
        "receipt_id": str(receipt["receipt_id"]),
        "receipt_digest": adapter_deployment_lifecycle_execution_receipt_digest(receipt),
        "attempt_id": str(receipt["attempt"]["attempt_id"]),
        "executor_signer_id": str(receipt["signer_id"]),
    }


def _phase_execution_reference(receipt: Mapping[str, Any]) -> dict[str, str]:
    reference = _execution_reference(receipt)
    return {
        "receipt_id": reference["receipt_id"],
        "receipt_digest": reference["receipt_digest"],
        "attempt_id": reference["attempt_id"],
        "signer_id": reference["executor_signer_id"],
    }


def _postcondition_reference(receipt: Mapping[str, Any]) -> dict[str, str]:
    return {
        "receipt_id": str(receipt["receipt_id"]),
        "receipt_digest": adapter_deployment_lifecycle_postcondition_receipt_digest(receipt),
        "signer_id": str(receipt["signer_id"]),
    }


def _precondition_reference(receipt: Mapping[str, Any]) -> dict[str, str]:
    return {
        "receipt_id": str(receipt["receipt_id"]),
        "receipt_digest": adapter_deployment_lifecycle_precondition_receipt_digest(receipt),
        "signer_id": str(receipt["signer_id"]),
    }


def build_adapter_deployment_lifecycle_precondition_receipt(
    *,
    manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    expected_executor_key: TrustedKey,
    deployment_run_id: str,
    challenge_digest: str,
    phase: str,
    host_role: str,
    platform_family: str,
    architecture: str,
    host_identity_digest: str,
    platform_identity_digest: str,
    environment_identity_digest: str,
    expected_package_artifact_digest: str,
    expected_guardian_artifact_digest: str,
    expected_predecessor: Mapping[str, Any],
    from_state_digest: str,
    to_state_digest: str,
    observer_id: str,
    observer_artifact_digest: str,
    observed_state: Mapping[str, Any],
    observed_at: str,
    host_key_policy: Mapping[str, Mapping[str, str]],
    signer: Ed25519Signer,
) -> dict[str, Any]:
    """Sign the independently observed state required before execution starts."""

    verified_manifest = verify_adapter_capability_manifest(
        manifest,
        adapter_key=adapter_key,
    )
    binding = _phase_binding(
        manifest=verified_manifest,
        deployment_run_id=deployment_run_id,
        challenge_digest=challenge_digest,
        phase=phase,
        host_role=host_role,
        platform_family=platform_family,
        architecture=architecture,
        host_identity_digest=host_identity_digest,
        platform_identity_digest=platform_identity_digest,
        environment_identity_digest=environment_identity_digest,
        expected_package_artifact_digest=expected_package_artifact_digest,
        expected_guardian_artifact_digest=expected_guardian_artifact_digest,
        from_state_digest=from_state_digest,
        to_state_digest=to_state_digest,
        expected_predecessor=expected_predecessor,
    )
    observer_key = _trusted_signer(signer)
    _require_distinct_key_material(
        adapter_key,
        expected_executor_key,
        observer_key,
        message=(
            "ASDK lifecycle precondition observer must be independent from executor and adapter"
        ),
    )
    _require_host_key_policy(
        observer_key,
        binding=binding,
        signer_role="precondition-observer",
        host_key_policy=host_key_policy,
    )
    typed_state = _validate_observed_state(observed_state, binding=binding)
    required_before = binding["transition"]["from_state"]
    if (
        typed_state["kind"] != required_before["kind"]
        or typed_state["state_digest"] != required_before["state_digest"]
    ):
        raise AdapterPortabilityError(
            "ASDK lifecycle precondition does not match transition from_state"
        )
    _require_timestamp_order(observed_at)
    core = {
        "protocol": ("integrity-guardian/adapter-deployment-lifecycle-precondition-receipt/v1"),
        "sdk_version": ADAPTER_SDK_VERSION,
        "binding": binding,
        "observation": {
            "observer_id": observer_id,
            "signer_id": signer.key_id,
            "artifact_digest": observer_artifact_digest,
            "observed_state": typed_state,
            "matches_required_before_state": True,
        },
        "result": "passed",
        "actual_host": True,
        "synthetic": False,
        "content_free": True,
        "independence": {
            "executor_signer_id": expected_executor_key.key_id,
            "observer_signer_id": signer.key_id,
            "same_identity": False,
        },
        "authority_boundary": _authority_boundary(),
        "observed_at": observed_at,
        "signer_id": signer.key_id,
    }
    unsigned = {
        "receipt_id": _identity(
            core,
            field="receipt_id",
            prefix="adapter-deployment-lifecycle-precondition-receipt:",
            domain=("adapter-deployment-lifecycle-precondition-receipt-identity-v1"),
        ),
        **core,
    }
    signed = signer.sign(unsigned)
    validate("adapter-deployment-lifecycle-precondition-receipt", signed)
    return signed


def verify_adapter_deployment_lifecycle_precondition_receipt(
    receipt: Mapping[str, Any],
    *,
    manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    expected_executor_key: TrustedKey,
    precondition_key: TrustedKey,
    deployment_run_id: str,
    challenge_digest: str,
    expected_package_artifact_digest: str,
    expected_guardian_artifact_digest: str,
    expected_predecessor: Mapping[str, Any],
    host_key_policy: Mapping[str, Mapping[str, str]],
) -> dict[str, Any]:
    candidate = _verify_signed(
        receipt,
        schema="adapter-deployment-lifecycle-precondition-receipt",
        field="receipt_id",
        prefix="adapter-deployment-lifecycle-precondition-receipt:",
        domain="adapter-deployment-lifecycle-precondition-receipt-identity-v1",
        trusted_key=precondition_key,
    )
    verified_manifest = verify_adapter_capability_manifest(
        manifest,
        adapter_key=adapter_key,
    )
    binding = candidate["binding"]
    _validate_phase_binding(binding)
    if binding["manifest"] != _manifest_reference(verified_manifest):
        raise AdapterPortabilityError("ASDK deployment lifecycle manifest mismatch")
    if binding["deployment"] != {
        "deployment_run_id": deployment_run_id,
        "challenge_digest": challenge_digest,
    }:
        raise AdapterPortabilityError("ASDK lifecycle deployment challenge mismatch")
    if (
        binding["package"]["artifact_digest"] != expected_package_artifact_digest
        or binding["guardian"]["artifact_digest"] != expected_guardian_artifact_digest
    ):
        raise AdapterPortabilityError("ASDK lifecycle verifier-supplied release artifact mismatch")
    if binding["phase"] == "upgrade" and binding["predecessor"] != _freeze(expected_predecessor):
        raise AdapterPortabilityError("ASDK lifecycle verifier-supplied predecessor mismatch")
    _require_distinct_key_material(
        adapter_key,
        expected_executor_key,
        precondition_key,
        message=(
            "ASDK lifecycle precondition observer must be independent from executor and adapter"
        ),
    )
    _require_host_key_policy(
        precondition_key,
        binding=binding,
        signer_role="precondition-observer",
        host_key_policy=host_key_policy,
    )
    typed_state = _validate_observed_state(
        candidate["observation"]["observed_state"],
        binding=binding,
    )
    required_before = binding["transition"]["from_state"]
    if (
        candidate["result"] != "passed"
        or candidate["observation"]["signer_id"] != precondition_key.key_id
        or candidate["observation"]["matches_required_before_state"] is not True
        or typed_state["kind"] != required_before["kind"]
        or typed_state["state_digest"] != required_before["state_digest"]
        or candidate["independence"]
        != {
            "executor_signer_id": expected_executor_key.key_id,
            "observer_signer_id": precondition_key.key_id,
            "same_identity": False,
        }
    ):
        raise AdapterPortabilityError(
            "ASDK lifecycle precondition does not prove the required before-state"
        )
    _require_timestamp_order(candidate["observed_at"])
    return candidate


def build_adapter_deployment_lifecycle_execution_receipt(
    *,
    precondition_receipt: Mapping[str, Any],
    manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    precondition_key: TrustedKey,
    deployment_run_id: str,
    challenge_digest: str,
    phase: str,
    host_role: str,
    platform_family: str,
    architecture: str,
    host_identity_digest: str,
    platform_identity_digest: str,
    environment_identity_digest: str,
    expected_package_artifact_digest: str,
    expected_guardian_artifact_digest: str,
    expected_predecessor: Mapping[str, Any],
    from_state_digest: str,
    to_state_digest: str,
    started_at: str,
    finished_at: str,
    executor_id: str,
    executor_artifact_digest: str,
    result: str,
    observed_at: str,
    host_key_policy: Mapping[str, Mapping[str, str]],
    signer: Ed25519Signer,
) -> dict[str, Any]:
    """Sign one challenge-bound actual-host execution observation."""

    verified_manifest = verify_adapter_capability_manifest(
        manifest,
        adapter_key=adapter_key,
    )
    binding = _phase_binding(
        manifest=verified_manifest,
        deployment_run_id=deployment_run_id,
        challenge_digest=challenge_digest,
        phase=phase,
        host_role=host_role,
        platform_family=platform_family,
        architecture=architecture,
        host_identity_digest=host_identity_digest,
        platform_identity_digest=platform_identity_digest,
        environment_identity_digest=environment_identity_digest,
        expected_package_artifact_digest=expected_package_artifact_digest,
        expected_guardian_artifact_digest=expected_guardian_artifact_digest,
        from_state_digest=from_state_digest,
        to_state_digest=to_state_digest,
        expected_predecessor=expected_predecessor,
    )
    signer_key = _trusted_signer(signer)
    _require_distinct_key_material(
        adapter_key,
        signer_key,
        message="ASDK lifecycle executor must be independent from adapter signer",
    )
    _require_host_key_policy(
        signer_key,
        binding=binding,
        signer_role="executor",
        host_key_policy=host_key_policy,
    )
    precondition = verify_adapter_deployment_lifecycle_precondition_receipt(
        precondition_receipt,
        manifest=verified_manifest,
        adapter_key=adapter_key,
        expected_executor_key=signer_key,
        precondition_key=precondition_key,
        deployment_run_id=deployment_run_id,
        challenge_digest=challenge_digest,
        expected_package_artifact_digest=expected_package_artifact_digest,
        expected_guardian_artifact_digest=expected_guardian_artifact_digest,
        expected_predecessor=expected_predecessor,
        host_key_policy=host_key_policy,
    )
    if precondition["binding"] != binding:
        raise AdapterPortabilityError("ASDK lifecycle precondition binding mismatch")
    if (
        precondition["observation"]["observer_id"] == executor_id
        or precondition["observation"]["artifact_digest"] == executor_artifact_digest
    ):
        raise AdapterPortabilityError(
            "ASDK lifecycle precondition process must be independent from executor"
        )
    if _timestamp(precondition["observed_at"]) >= _timestamp(started_at):
        raise AdapterPortabilityError(
            "ASDK lifecycle precondition must be captured before execution start"
        )
    _require_timestamp_order(
        precondition["observed_at"],
        started_at,
        finished_at,
        observed_at,
    )
    core = {
        "protocol": ("integrity-guardian/adapter-deployment-lifecycle-execution-receipt/v1"),
        "sdk_version": ADAPTER_SDK_VERSION,
        "binding": binding,
        "precondition": _precondition_reference(precondition),
        "attempt": {
            "attempt_id": _attempt_identity(binding),
            "started_at": started_at,
            "finished_at": finished_at,
            "replayed": False,
            "automatic_retry_allowed": False,
        },
        "executor": {
            "executor_id": executor_id,
            "signer_id": signer.key_id,
            "artifact_digest": executor_artifact_digest,
        },
        "result": result,
        "actual_host": True,
        "synthetic": False,
        "content_free": True,
        "authority_boundary": _authority_boundary(),
        "observed_at": observed_at,
        "signer_id": signer.key_id,
    }
    unsigned = {
        "receipt_id": _identity(
            core,
            field="receipt_id",
            prefix="adapter-deployment-lifecycle-execution-receipt:",
            domain="adapter-deployment-lifecycle-execution-receipt-identity-v1",
        ),
        **core,
    }
    signed = signer.sign(unsigned)
    validate("adapter-deployment-lifecycle-execution-receipt", signed)
    return signed


def verify_adapter_deployment_lifecycle_execution_receipt(
    receipt: Mapping[str, Any],
    *,
    precondition_receipt: Mapping[str, Any],
    manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    precondition_key: TrustedKey,
    execution_key: TrustedKey,
    deployment_run_id: str,
    challenge_digest: str,
    expected_package_artifact_digest: str,
    expected_guardian_artifact_digest: str,
    expected_predecessor: Mapping[str, Any],
    host_key_policy: Mapping[str, Mapping[str, str]],
) -> dict[str, Any]:
    candidate = _verify_signed(
        receipt,
        schema="adapter-deployment-lifecycle-execution-receipt",
        field="receipt_id",
        prefix="adapter-deployment-lifecycle-execution-receipt:",
        domain="adapter-deployment-lifecycle-execution-receipt-identity-v1",
        trusted_key=execution_key,
    )
    verified_manifest = verify_adapter_capability_manifest(
        manifest,
        adapter_key=adapter_key,
    )
    precondition = verify_adapter_deployment_lifecycle_precondition_receipt(
        precondition_receipt,
        manifest=verified_manifest,
        adapter_key=adapter_key,
        expected_executor_key=execution_key,
        precondition_key=precondition_key,
        deployment_run_id=deployment_run_id,
        challenge_digest=challenge_digest,
        expected_package_artifact_digest=expected_package_artifact_digest,
        expected_guardian_artifact_digest=expected_guardian_artifact_digest,
        expected_predecessor=expected_predecessor,
        host_key_policy=host_key_policy,
    )
    _validate_phase_binding(candidate["binding"])
    if candidate["binding"]["manifest"] != _manifest_reference(verified_manifest):
        raise AdapterPortabilityError("ASDK deployment lifecycle manifest mismatch")
    if candidate["binding"] != precondition["binding"] or candidate[
        "precondition"
    ] != _precondition_reference(precondition):
        raise AdapterPortabilityError("ASDK lifecycle precondition coverage mismatch")
    if candidate["binding"]["deployment"] != {
        "deployment_run_id": deployment_run_id,
        "challenge_digest": challenge_digest,
    }:
        raise AdapterPortabilityError("ASDK lifecycle deployment challenge mismatch")
    if candidate["binding"]["package"]["artifact_digest"] != (
        expected_package_artifact_digest
    ) or candidate["binding"]["guardian"]["artifact_digest"] != (expected_guardian_artifact_digest):
        raise AdapterPortabilityError("ASDK lifecycle verifier-supplied release artifact mismatch")
    if candidate["binding"]["phase"] == "upgrade" and candidate["binding"][
        "predecessor"
    ] != _freeze(expected_predecessor):
        raise AdapterPortabilityError("ASDK lifecycle verifier-supplied predecessor mismatch")
    _require_distinct_key_material(
        adapter_key,
        execution_key,
        message="ASDK lifecycle executor must be independent from adapter signer",
    )
    _require_host_key_policy(
        execution_key,
        binding=candidate["binding"],
        signer_role="executor",
        host_key_policy=host_key_policy,
    )
    if candidate["executor"]["signer_id"] != execution_key.key_id:
        raise AdapterPortabilityError("ASDK lifecycle executor identity mismatch")
    if (
        precondition["observation"]["observer_id"] == candidate["executor"]["executor_id"]
        or precondition["observation"]["artifact_digest"]
        == candidate["executor"]["artifact_digest"]
    ):
        raise AdapterPortabilityError(
            "ASDK lifecycle precondition process must be independent from executor"
        )
    if candidate["attempt"]["attempt_id"] != _attempt_identity(candidate["binding"]):
        raise AdapterPortabilityError("ASDK lifecycle retry attempt identity mismatch")
    if _timestamp(precondition["observed_at"]) >= _timestamp(candidate["attempt"]["started_at"]):
        raise AdapterPortabilityError(
            "ASDK lifecycle precondition must be captured before execution start"
        )
    _require_timestamp_order(
        precondition["observed_at"],
        candidate["attempt"]["started_at"],
        candidate["attempt"]["finished_at"],
        candidate["observed_at"],
    )
    return candidate


def _postcondition_result_is_consistent(
    execution: Mapping[str, Any],
    *,
    result: str,
    observed_state: Mapping[str, Any],
) -> bool:
    execution_result = execution["result"]
    if execution_result == "failed" and result != "failed":
        return False
    if execution_result == "unknown" and result != "unknown":
        return False
    intended_state = execution["binding"]["transition"]["to_state"]
    matches_intended = (
        observed_state["kind"] == intended_state["kind"]
        and observed_state["state_digest"] == intended_state["state_digest"]
    )
    return (result == "passed") == matches_intended


def _validate_observed_state(
    observed_state: Mapping[str, Any],
    *,
    binding: Mapping[str, Any],
) -> dict[str, Any]:
    candidate = _freeze(observed_state)
    if candidate.get("state_digest") != adapter_deployment_observed_state_digest(candidate):
        raise AdapterPortabilityError(
            "ASDK lifecycle observed-state digest is not derived from typed facts"
        )
    kind = candidate.get("kind")
    package = candidate.get("package")
    guardian = candidate.get("guardian")
    revocation = candidate.get("revocation")
    recovery = candidate.get("recovery")
    if kind == "absent":
        if any(value is not None for value in (package, guardian, revocation, recovery)):
            raise AdapterPortabilityError("ASDK lifecycle absent state is malformed")
    elif kind == "predecessor-installed":
        predecessor = binding.get("predecessor")
        if (
            not isinstance(predecessor, Mapping)
            or package != predecessor["package"]
            or guardian != predecessor["guardian"]
            or revocation is not None
            or recovery is not None
        ):
            raise AdapterPortabilityError("ASDK lifecycle predecessor observed state is malformed")
    elif kind == "candidate-installed":
        if (
            package != binding["package"]
            or guardian != binding["guardian"]
            or revocation is not None
            or recovery is not None
        ):
            raise AdapterPortabilityError("ASDK lifecycle installed observed state is malformed")
    elif kind in {"candidate-revoked", "candidate-recovered-revocation-preserved"}:
        if package != binding["package"] or guardian != binding["guardian"]:
            raise AdapterPortabilityError("ASDK lifecycle revoked observed state artifact mismatch")
        if not isinstance(revocation, Mapping) or dict(revocation) != {
            "grant_invalid": True,
            "operation_refused": True,
            "revocation_digest": revocation.get("revocation_digest"),
        }:
            raise AdapterPortabilityError("ASDK lifecycle revocation postcondition is incomplete")
        if kind == "candidate-revoked" and recovery is not None:
            raise AdapterPortabilityError(
                "ASDK lifecycle revoked state cannot claim recovery facts"
            )
        if kind == "candidate-recovered-revocation-preserved":
            if not isinstance(recovery, Mapping) or dict(recovery) != {
                "prior_boot_session_digest": recovery.get("prior_boot_session_digest"),
                "current_boot_session_digest": recovery.get("current_boot_session_digest"),
                "restart_observed": True,
                "revocation_preserved": True,
            }:
                raise AdapterPortabilityError("ASDK lifecycle recovery postcondition is incomplete")
            if recovery["prior_boot_session_digest"] == recovery["current_boot_session_digest"]:
                raise AdapterPortabilityError(
                    "ASDK lifecycle recovery requires a changed boot/session identity"
                )
    else:
        raise AdapterPortabilityError("ASDK lifecycle observed state kind is unsupported")
    return candidate


def build_adapter_deployment_lifecycle_postcondition_receipt(
    *,
    precondition_receipt: Mapping[str, Any],
    execution_receipt: Mapping[str, Any],
    manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    precondition_key: TrustedKey,
    execution_key: TrustedKey,
    deployment_run_id: str,
    challenge_digest: str,
    expected_package_artifact_digest: str,
    expected_guardian_artifact_digest: str,
    expected_predecessor: Mapping[str, Any],
    observer_id: str,
    observer_artifact_digest: str,
    observed_state: Mapping[str, Any],
    result: str,
    observed_at: str,
    host_key_policy: Mapping[str, Mapping[str, str]],
    signer: Ed25519Signer,
) -> dict[str, Any]:
    """Independently observe the state produced by a full execution receipt."""

    execution = verify_adapter_deployment_lifecycle_execution_receipt(
        execution_receipt,
        precondition_receipt=precondition_receipt,
        manifest=manifest,
        adapter_key=adapter_key,
        precondition_key=precondition_key,
        execution_key=execution_key,
        deployment_run_id=deployment_run_id,
        challenge_digest=challenge_digest,
        expected_package_artifact_digest=expected_package_artifact_digest,
        expected_guardian_artifact_digest=expected_guardian_artifact_digest,
        expected_predecessor=expected_predecessor,
        host_key_policy=host_key_policy,
    )
    precondition = _freeze(precondition_receipt)
    observer_key = _trusted_signer(signer)
    _require_distinct_key_material(
        adapter_key,
        precondition_key,
        execution_key,
        observer_key,
        message="ASDK lifecycle observer must be independent from executor and adapter",
    )
    _require_host_key_policy(
        observer_key,
        binding=execution["binding"],
        signer_role="observer",
        host_key_policy=host_key_policy,
    )
    if (
        observer_id == execution["executor"]["executor_id"]
        or observer_artifact_digest == execution["executor"]["artifact_digest"]
        or observer_id == precondition["observation"]["observer_id"]
        or observer_artifact_digest == precondition["observation"]["artifact_digest"]
    ):
        raise AdapterPortabilityError(
            "ASDK lifecycle observer process must be independent from executor"
        )
    typed_state = _validate_observed_state(
        observed_state,
        binding=execution["binding"],
    )
    if not _postcondition_result_is_consistent(
        execution,
        result=result,
        observed_state=typed_state,
    ):
        raise AdapterPortabilityError(
            "ASDK lifecycle postcondition result contradicts execution or observed state"
        )
    core = {
        "protocol": ("integrity-guardian/adapter-deployment-lifecycle-postcondition-receipt/v1"),
        "sdk_version": ADAPTER_SDK_VERSION,
        "binding": deepcopy(execution["binding"]),
        "execution": _execution_reference(execution),
        "observation": {
            "observer_id": observer_id,
            "signer_id": signer.key_id,
            "artifact_digest": observer_artifact_digest,
            "observed_state": typed_state,
            "matches_intended_transition": result == "passed",
        },
        "result": result,
        "actual_host": True,
        "synthetic": False,
        "content_free": True,
        "independence": {
            "executor_signer_id": execution_key.key_id,
            "observer_signer_id": signer.key_id,
            "same_identity": False,
        },
        "authority_boundary": _authority_boundary(),
        "observed_at": observed_at,
        "signer_id": signer.key_id,
    }
    _require_timestamp_order(execution["observed_at"], observed_at)
    unsigned = {
        "receipt_id": _identity(
            core,
            field="receipt_id",
            prefix="adapter-deployment-lifecycle-postcondition-receipt:",
            domain="adapter-deployment-lifecycle-postcondition-receipt-identity-v1",
        ),
        **core,
    }
    signed = signer.sign(unsigned)
    validate("adapter-deployment-lifecycle-postcondition-receipt", signed)
    return signed


def verify_adapter_deployment_lifecycle_postcondition_receipt(
    receipt: Mapping[str, Any],
    *,
    precondition_receipt: Mapping[str, Any],
    execution_receipt: Mapping[str, Any],
    manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    precondition_key: TrustedKey,
    execution_key: TrustedKey,
    postcondition_key: TrustedKey,
    deployment_run_id: str,
    challenge_digest: str,
    expected_package_artifact_digest: str,
    expected_guardian_artifact_digest: str,
    expected_predecessor: Mapping[str, Any],
    host_key_policy: Mapping[str, Mapping[str, str]],
) -> dict[str, Any]:
    execution = verify_adapter_deployment_lifecycle_execution_receipt(
        execution_receipt,
        precondition_receipt=precondition_receipt,
        manifest=manifest,
        adapter_key=adapter_key,
        precondition_key=precondition_key,
        execution_key=execution_key,
        deployment_run_id=deployment_run_id,
        challenge_digest=challenge_digest,
        expected_package_artifact_digest=expected_package_artifact_digest,
        expected_guardian_artifact_digest=expected_guardian_artifact_digest,
        expected_predecessor=expected_predecessor,
        host_key_policy=host_key_policy,
    )
    precondition = _freeze(precondition_receipt)
    candidate = _verify_signed(
        receipt,
        schema="adapter-deployment-lifecycle-postcondition-receipt",
        field="receipt_id",
        prefix="adapter-deployment-lifecycle-postcondition-receipt:",
        domain="adapter-deployment-lifecycle-postcondition-receipt-identity-v1",
        trusted_key=postcondition_key,
    )
    _require_distinct_key_material(
        adapter_key,
        precondition_key,
        execution_key,
        postcondition_key,
        message="ASDK lifecycle observer must be independent from executor and adapter",
    )
    _require_host_key_policy(
        postcondition_key,
        binding=execution["binding"],
        signer_role="observer",
        host_key_policy=host_key_policy,
    )
    if candidate["binding"] != execution["binding"]:
        raise AdapterPortabilityError("ASDK lifecycle postcondition binding mismatch")
    if candidate["execution"] != _execution_reference(execution):
        raise AdapterPortabilityError("ASDK lifecycle postcondition execution coverage mismatch")
    if candidate["observation"]["signer_id"] != postcondition_key.key_id or candidate[
        "independence"
    ] != {
        "executor_signer_id": execution_key.key_id,
        "observer_signer_id": postcondition_key.key_id,
        "same_identity": False,
    }:
        raise AdapterPortabilityError("ASDK lifecycle observer identity mismatch")
    if (
        candidate["observation"]["observer_id"] == execution["executor"]["executor_id"]
        or candidate["observation"]["artifact_digest"] == execution["executor"]["artifact_digest"]
        or candidate["observation"]["observer_id"] == precondition["observation"]["observer_id"]
        or candidate["observation"]["artifact_digest"]
        == precondition["observation"]["artifact_digest"]
    ):
        raise AdapterPortabilityError(
            "ASDK lifecycle observer process must be independent from executor"
        )
    typed_state = _validate_observed_state(
        candidate["observation"]["observed_state"],
        binding=execution["binding"],
    )
    if not _postcondition_result_is_consistent(
        execution,
        result=candidate["result"],
        observed_state=typed_state,
    ) or candidate["observation"]["matches_intended_transition"] != (
        candidate["result"] == "passed"
    ):
        raise AdapterPortabilityError(
            "ASDK lifecycle postcondition result contradicts execution or observed state"
        )
    _require_timestamp_order(execution["observed_at"], candidate["observed_at"])
    return candidate


def _phase_receipt_core(
    *,
    precondition: Mapping[str, Any],
    execution: Mapping[str, Any],
    postcondition: Mapping[str, Any],
    observed_at: str,
    signer_id: str,
) -> dict[str, Any]:
    return {
        "protocol": "integrity-guardian/adapter-deployment-lifecycle-phase-receipt/v1",
        "sdk_version": ADAPTER_SDK_VERSION,
        "binding": deepcopy(execution["binding"]),
        "precondition": _precondition_reference(precondition),
        "execution": _phase_execution_reference(execution),
        "postcondition": _postcondition_reference(postcondition),
        "result": postcondition["result"],
        "actual_host": True,
        "synthetic": False,
        "content_free": True,
        "independence": {
            "precondition_observer_signer_id": precondition["signer_id"],
            "executor_signer_id": execution["signer_id"],
            "observer_signer_id": postcondition["signer_id"],
            "assessor_signer_id": signer_id,
            "all_distinct": True,
        },
        "authority_boundary": _authority_boundary(),
        "observed_at": observed_at,
        "signer_id": signer_id,
    }


def build_adapter_deployment_lifecycle_phase_receipt(
    *,
    precondition_receipt: Mapping[str, Any],
    execution_receipt: Mapping[str, Any],
    postcondition_receipt: Mapping[str, Any],
    manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    precondition_key: TrustedKey,
    execution_key: TrustedKey,
    postcondition_key: TrustedKey,
    deployment_run_id: str,
    challenge_digest: str,
    expected_package_artifact_digest: str,
    expected_guardian_artifact_digest: str,
    expected_predecessor: Mapping[str, Any],
    observed_at: str,
    host_key_policy: Mapping[str, Mapping[str, str]],
    signer: Ed25519Signer,
) -> dict[str, Any]:
    """Assess full executor and independent-observer bodies as one phase."""

    execution = verify_adapter_deployment_lifecycle_execution_receipt(
        execution_receipt,
        precondition_receipt=precondition_receipt,
        manifest=manifest,
        adapter_key=adapter_key,
        precondition_key=precondition_key,
        execution_key=execution_key,
        deployment_run_id=deployment_run_id,
        challenge_digest=challenge_digest,
        expected_package_artifact_digest=expected_package_artifact_digest,
        expected_guardian_artifact_digest=expected_guardian_artifact_digest,
        expected_predecessor=expected_predecessor,
        host_key_policy=host_key_policy,
    )
    postcondition = verify_adapter_deployment_lifecycle_postcondition_receipt(
        postcondition_receipt,
        precondition_receipt=precondition_receipt,
        execution_receipt=execution,
        manifest=manifest,
        adapter_key=adapter_key,
        precondition_key=precondition_key,
        execution_key=execution_key,
        postcondition_key=postcondition_key,
        deployment_run_id=deployment_run_id,
        challenge_digest=challenge_digest,
        expected_package_artifact_digest=expected_package_artifact_digest,
        expected_guardian_artifact_digest=expected_guardian_artifact_digest,
        expected_predecessor=expected_predecessor,
        host_key_policy=host_key_policy,
    )
    phase_key = _trusted_signer(signer)
    precondition = _freeze(precondition_receipt)
    _require_distinct_key_material(
        adapter_key,
        precondition_key,
        execution_key,
        postcondition_key,
        phase_key,
        message="ASDK lifecycle phase assessor must be independent",
    )
    _require_host_key_policy(
        phase_key,
        binding=execution["binding"],
        signer_role="phase-assessor",
        host_key_policy=host_key_policy,
    )
    _require_timestamp_order(postcondition["observed_at"], observed_at)
    core = _phase_receipt_core(
        precondition=precondition,
        execution=execution,
        postcondition=postcondition,
        observed_at=observed_at,
        signer_id=signer.key_id,
    )
    unsigned = {
        "receipt_id": _identity(
            core,
            field="receipt_id",
            prefix="adapter-deployment-lifecycle-phase-receipt:",
            domain="adapter-deployment-lifecycle-phase-receipt-identity-v1",
        ),
        **core,
    }
    signed = signer.sign(unsigned)
    validate("adapter-deployment-lifecycle-phase-receipt", signed)
    return signed


def verify_adapter_deployment_lifecycle_phase_receipt(
    receipt: Mapping[str, Any],
    *,
    precondition_receipt: Mapping[str, Any],
    execution_receipt: Mapping[str, Any],
    postcondition_receipt: Mapping[str, Any],
    manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    precondition_key: TrustedKey,
    execution_key: TrustedKey,
    postcondition_key: TrustedKey,
    phase_key: TrustedKey,
    deployment_run_id: str,
    challenge_digest: str,
    expected_package_artifact_digest: str,
    expected_guardian_artifact_digest: str,
    expected_predecessor: Mapping[str, Any],
    host_key_policy: Mapping[str, Mapping[str, str]],
) -> dict[str, Any]:
    execution = verify_adapter_deployment_lifecycle_execution_receipt(
        execution_receipt,
        precondition_receipt=precondition_receipt,
        manifest=manifest,
        adapter_key=adapter_key,
        precondition_key=precondition_key,
        execution_key=execution_key,
        deployment_run_id=deployment_run_id,
        challenge_digest=challenge_digest,
        expected_package_artifact_digest=expected_package_artifact_digest,
        expected_guardian_artifact_digest=expected_guardian_artifact_digest,
        expected_predecessor=expected_predecessor,
        host_key_policy=host_key_policy,
    )
    postcondition = verify_adapter_deployment_lifecycle_postcondition_receipt(
        postcondition_receipt,
        precondition_receipt=precondition_receipt,
        execution_receipt=execution,
        manifest=manifest,
        adapter_key=adapter_key,
        precondition_key=precondition_key,
        execution_key=execution_key,
        postcondition_key=postcondition_key,
        deployment_run_id=deployment_run_id,
        challenge_digest=challenge_digest,
        expected_package_artifact_digest=expected_package_artifact_digest,
        expected_guardian_artifact_digest=expected_guardian_artifact_digest,
        expected_predecessor=expected_predecessor,
        host_key_policy=host_key_policy,
    )
    candidate = _verify_signed(
        receipt,
        schema="adapter-deployment-lifecycle-phase-receipt",
        field="receipt_id",
        prefix="adapter-deployment-lifecycle-phase-receipt:",
        domain="adapter-deployment-lifecycle-phase-receipt-identity-v1",
        trusted_key=phase_key,
    )
    _require_distinct_key_material(
        adapter_key,
        precondition_key,
        execution_key,
        postcondition_key,
        phase_key,
        message="ASDK lifecycle phase assessor must be independent",
    )
    _require_host_key_policy(
        phase_key,
        binding=execution["binding"],
        signer_role="phase-assessor",
        host_key_policy=host_key_policy,
    )
    rebuilt = _phase_receipt_core(
        precondition=_freeze(precondition_receipt),
        execution=execution,
        postcondition=postcondition,
        observed_at=candidate["observed_at"],
        signer_id=phase_key.key_id,
    )
    expected = deepcopy(candidate)
    expected.pop("signature", None)
    expected.pop("receipt_id", None)
    if rebuilt != expected:
        raise AdapterPortabilityError("ASDK lifecycle phase receipt coverage mismatch")
    _require_timestamp_order(postcondition["observed_at"], candidate["observed_at"])
    return candidate


def _schema_candidate(
    document: Mapping[str, Any],
    *,
    schema: str,
) -> dict[str, Any]:
    candidate = _freeze(document)
    try:
        validate(schema, candidate)
    except Exception as exc:
        raise AdapterPortabilityError(f"ASDK {schema} schema rejected") from exc
    return candidate


def _document_index(
    documents: Sequence[Mapping[str, Any]],
    *,
    schema: str,
    label: str,
) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for document in documents:
        if not isinstance(document, Mapping):
            raise AdapterPortabilityError(f"ASDK lifecycle {label} body is required")
        candidate = _schema_candidate(document, schema=schema)
        receipt_id = str(candidate["receipt_id"])
        if receipt_id in index:
            raise AdapterPortabilityError(f"ASDK lifecycle duplicate {label} body")
        index[receipt_id] = candidate
    return index


def _required_trusted_key(
    document: Mapping[str, Any],
    keys: Mapping[str, TrustedKey],
    *,
    label: str,
) -> TrustedKey:
    key = keys.get(str(document.get("signer_id")))
    if key is None:
        raise AdapterPortabilityError(f"ASDK lifecycle {label} signer is untrusted")
    if key.key_id != str(document.get("signer_id")):
        raise AdapterPortabilityError(f"ASDK lifecycle {label} trusted-key map identity mismatch")
    return key


def _verified_phase_chains(
    *,
    manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    phase_documents: Sequence[Mapping[str, Any]],
    precondition_documents: Sequence[Mapping[str, Any]],
    execution_documents: Sequence[Mapping[str, Any]],
    postcondition_documents: Sequence[Mapping[str, Any]],
    phase_keys: Mapping[str, TrustedKey],
    precondition_keys: Mapping[str, TrustedKey],
    execution_keys: Mapping[str, TrustedKey],
    postcondition_keys: Mapping[str, TrustedKey],
    deployment_run_id: str,
    challenge_digest: str,
    expected_package_artifact_digest: str,
    expected_guardian_artifact_digest: str,
    expected_predecessor: Mapping[str, Any],
    host_key_policy: Mapping[str, Mapping[str, str]],
) -> list[dict[str, dict[str, Any]]]:
    phases = _document_index(
        phase_documents,
        schema="adapter-deployment-lifecycle-phase-receipt",
        label="phase receipt",
    )
    preconditions = _document_index(
        precondition_documents,
        schema="adapter-deployment-lifecycle-precondition-receipt",
        label="precondition receipt",
    )
    executions = _document_index(
        execution_documents,
        schema="adapter-deployment-lifecycle-execution-receipt",
        label="execution receipt",
    )
    postconditions = _document_index(
        postcondition_documents,
        schema="adapter-deployment-lifecycle-postcondition-receipt",
        label="postcondition receipt",
    )
    verified: list[dict[str, dict[str, Any]]] = []
    referenced_preconditions: set[str] = set()
    referenced_executions: set[str] = set()
    referenced_postconditions: set[str] = set()
    for phase in phases.values():
        precondition_id = str(phase["precondition"]["receipt_id"])
        execution_id = str(phase["execution"]["receipt_id"])
        postcondition_id = str(phase["postcondition"]["receipt_id"])
        precondition = preconditions.get(precondition_id)
        execution = executions.get(execution_id)
        postcondition = postconditions.get(postcondition_id)
        if precondition is None or execution is None or postcondition is None:
            raise AdapterPortabilityError(
                "ASDK lifecycle phase requires full precondition, execution and "
                "postcondition bodies"
            )
        precondition_key = _required_trusted_key(
            precondition,
            precondition_keys,
            label="precondition",
        )
        execution_key = _required_trusted_key(
            execution,
            execution_keys,
            label="execution",
        )
        postcondition_key = _required_trusted_key(
            postcondition,
            postcondition_keys,
            label="postcondition",
        )
        phase_key = _required_trusted_key(phase, phase_keys, label="phase")
        verified_phase = verify_adapter_deployment_lifecycle_phase_receipt(
            phase,
            precondition_receipt=precondition,
            execution_receipt=execution,
            postcondition_receipt=postcondition,
            manifest=manifest,
            adapter_key=adapter_key,
            precondition_key=precondition_key,
            execution_key=execution_key,
            postcondition_key=postcondition_key,
            phase_key=phase_key,
            deployment_run_id=deployment_run_id,
            challenge_digest=challenge_digest,
            expected_package_artifact_digest=expected_package_artifact_digest,
            expected_guardian_artifact_digest=expected_guardian_artifact_digest,
            expected_predecessor=expected_predecessor,
            host_key_policy=host_key_policy,
        )
        verified.append(
            {
                "phase": verified_phase,
                "precondition": precondition,
                "execution": execution,
                "postcondition": postcondition,
            }
        )
        referenced_preconditions.add(precondition_id)
        referenced_executions.add(execution_id)
        referenced_postconditions.add(postcondition_id)
    if (
        referenced_preconditions != set(preconditions)
        or referenced_executions != set(executions)
        or referenced_postconditions != set(postconditions)
    ):
        raise AdapterPortabilityError("ASDK lifecycle contains unconsumed receipt bodies")
    return verified


def _expected_candidate_reference(
    *,
    distribution: str,
    version: str,
    artifact_digest: str,
    expected_distribution: str,
    expected_version: str,
    label: str,
) -> dict[str, str]:
    if distribution != expected_distribution or version != expected_version:
        raise AdapterPortabilityError(f"ASDK deployment cohort {label} identity mismatch")
    return {
        "distribution": distribution,
        "version": version,
        "artifact_digest": artifact_digest,
    }


def _ordered_host_phase_chains(
    chains: Sequence[Mapping[str, Mapping[str, Any]]],
    *,
    manifest_reference: Mapping[str, Any],
    package_reference: Mapping[str, Any],
    guardian_reference: Mapping[str, Any],
    host_reference: Mapping[str, Any],
) -> list[Mapping[str, Mapping[str, Any]]]:
    by_phase: dict[str, Mapping[str, Mapping[str, Any]]] = {}
    for chain in chains:
        phase_receipt = chain["phase"]
        phase = str(phase_receipt["binding"]["phase"])
        if phase in by_phase:
            raise AdapterPortabilityError("ASDK lifecycle duplicate phase")
        binding = phase_receipt["binding"]
        if (
            binding["manifest"] != manifest_reference
            or binding["package"] != package_reference
            or binding["guardian"] != guardian_reference
            or binding["host"] != host_reference
        ):
            raise AdapterPortabilityError(
                "ASDK lifecycle host or candidate artifact binding mismatch"
            )
        by_phase[phase] = chain
    if set(by_phase) != set(_DEPLOYMENT_LIFECYCLE_PHASES):
        raise AdapterPortabilityError(
            "ASDK lifecycle requires exactly install, upgrade, revoke and recovery"
        )
    ordered = [by_phase[phase] for phase in _DEPLOYMENT_LIFECYCLE_PHASES]
    uniqueness_fields = (
        ("phase", "receipt_id"),
        ("precondition", "receipt_id"),
        ("execution", "receipt_id"),
        ("postcondition", "receipt_id"),
    )
    for document_kind, field in uniqueness_fields:
        values = [str(chain[document_kind][field]) for chain in ordered]
        if len(set(values)) != len(values):
            raise AdapterPortabilityError("ASDK lifecycle receipt reused in consumed evidence")
    attempts = [str(chain["execution"]["attempt"]["attempt_id"]) for chain in ordered]
    if len(set(attempts)) != len(attempts):
        raise AdapterPortabilityError("ASDK lifecycle attempt reused in consumed evidence")
    phase_digests = [
        adapter_deployment_lifecycle_phase_receipt_digest(chain["phase"]) for chain in ordered
    ]
    precondition_digests = [
        adapter_deployment_lifecycle_precondition_receipt_digest(chain["precondition"])
        for chain in ordered
    ]
    execution_digests = [
        adapter_deployment_lifecycle_execution_receipt_digest(chain["execution"])
        for chain in ordered
    ]
    postcondition_digests = [
        adapter_deployment_lifecycle_postcondition_receipt_digest(chain["postcondition"])
        for chain in ordered
    ]
    for digests in (
        phase_digests,
        precondition_digests,
        execution_digests,
        postcondition_digests,
    ):
        if len(set(digests)) != len(digests):
            raise AdapterPortabilityError("ASDK lifecycle receipt reused in consumed evidence")
    install, upgrade, revoke, recovery = ordered
    candidate_state_digests = {
        install["phase"]["binding"]["transition"]["to_state"]["state_digest"],
        upgrade["phase"]["binding"]["transition"]["to_state"]["state_digest"],
        revoke["phase"]["binding"]["transition"]["from_state"]["state_digest"],
    }
    if len(candidate_state_digests) != 1:
        raise AdapterPortabilityError("ASDK lifecycle candidate-installed state is not continuous")
    if (
        revoke["phase"]["binding"]["transition"]["to_state"]["state_digest"]
        != recovery["phase"]["binding"]["transition"]["from_state"]["state_digest"]
    ):
        raise AdapterPortabilityError(
            "ASDK lifecycle revoked state is not continuous into recovery"
        )
    return ordered


def _lifecycle_phase_reference(
    chain: Mapping[str, Mapping[str, Any]],
) -> dict[str, str]:
    phase = chain["phase"]
    precondition = chain["precondition"]
    execution = chain["execution"]
    postcondition = chain["postcondition"]
    return {
        "result": str(phase["result"]),
        "phase_receipt_id": str(phase["receipt_id"]),
        "phase_receipt_digest": adapter_deployment_lifecycle_phase_receipt_digest(phase),
        "precondition_receipt_id": str(precondition["receipt_id"]),
        "precondition_receipt_digest": (
            adapter_deployment_lifecycle_precondition_receipt_digest(precondition)
        ),
        "attempt_id": str(execution["attempt"]["attempt_id"]),
        "execution_receipt_id": str(execution["receipt_id"]),
        "execution_receipt_digest": (
            adapter_deployment_lifecycle_execution_receipt_digest(execution)
        ),
        "postcondition_receipt_id": str(postcondition["receipt_id"]),
        "postcondition_receipt_digest": (
            adapter_deployment_lifecycle_postcondition_receipt_digest(postcondition)
        ),
        "executor_signer_id": str(execution["signer_id"]),
        "precondition_observer_signer_id": str(precondition["signer_id"]),
        "observer_signer_id": str(postcondition["signer_id"]),
        "phase_assessor_signer_id": str(phase["signer_id"]),
    }


def _host_lifecycle_core(
    *,
    manifest: Mapping[str, Any],
    package: Mapping[str, Any],
    guardian: Mapping[str, Any],
    host: Mapping[str, Any],
    chains: Sequence[Mapping[str, Mapping[str, Any]]],
    created_at: str,
    adapter_signer_id: str,
    signer_id: str,
) -> dict[str, Any]:
    precondition_signers = sorted({str(chain["precondition"]["signer_id"]) for chain in chains})
    executor_signers = sorted({str(chain["execution"]["signer_id"]) for chain in chains})
    observer_signers = sorted({str(chain["postcondition"]["signer_id"]) for chain in chains})
    phase_signers = sorted({str(chain["phase"]["signer_id"]) for chain in chains})
    consumed_signers = set(
        precondition_signers + executor_signers + observer_signers + phase_signers
    )
    if signer_id == adapter_signer_id or signer_id in consumed_signers:
        raise AdapterPortabilityError(
            "ASDK deployment host assessor must be independent from consumed signers"
        )
    lifecycle = {
        phase: _lifecycle_phase_reference(chain)
        for phase, chain in zip(_DEPLOYMENT_LIFECYCLE_PHASES, chains, strict=True)
    }
    return {
        "protocol": "integrity-guardian/adapter-deployment-host-lifecycle-evidence/v2",
        "sdk_version": ADAPTER_SDK_VERSION,
        "deployment": dict(chains[0]["phase"]["binding"]["deployment"]),
        "manifest": dict(manifest),
        "package": dict(package),
        "guardian": dict(guardian),
        "host": dict(host),
        "lifecycle": lifecycle,
        "actual_host": True,
        "synthetic": False,
        "content_free": True,
        "independence": {
            "subject_signer_id": adapter_signer_id,
            "precondition_observer_signer_ids": precondition_signers,
            "executor_signer_ids": executor_signers,
            "observer_signer_ids": observer_signers,
            "phase_assessor_signer_ids": phase_signers,
            "assessor_signer_id": signer_id,
            "same_identity": False,
            "assessor_distinct_from_all_consumed": True,
        },
        "authority_boundary": _authority_boundary(),
        "created_at": created_at,
        "signer_id": signer_id,
    }


def _require_host_assessor_trust(
    *,
    chains: Sequence[Mapping[str, Mapping[str, Any]]],
    adapter_key: TrustedKey,
    precondition_keys: Mapping[str, TrustedKey],
    execution_keys: Mapping[str, TrustedKey],
    postcondition_keys: Mapping[str, TrustedKey],
    phase_keys: Mapping[str, TrustedKey],
    host_key: TrustedKey,
    host_key_policy: Mapping[str, Mapping[str, str]],
    created_at: str,
) -> None:
    upstream_keys = [adapter_key]
    for chain in chains:
        upstream_keys.extend(
            (
                _required_trusted_key(
                    chain["precondition"],
                    precondition_keys,
                    label="precondition",
                ),
                _required_trusted_key(chain["execution"], execution_keys, label="execution"),
                _required_trusted_key(
                    chain["postcondition"],
                    postcondition_keys,
                    label="postcondition",
                ),
                _required_trusted_key(chain["phase"], phase_keys, label="phase"),
            )
        )
    host_fingerprint = public_key_fingerprint(host_key.public_key)
    if host_fingerprint in {public_key_fingerprint(key.public_key) for key in upstream_keys}:
        raise AdapterPortabilityError(
            "ASDK deployment host assessor must be independent from consumed signers"
        )
    _require_host_key_policy(
        host_key,
        binding=chains[0]["phase"]["binding"],
        signer_role="host-assessor",
        host_key_policy=host_key_policy,
    )
    for chain in chains:
        _require_timestamp_order(chain["phase"]["observed_at"], created_at)


def build_adapter_deployment_host_lifecycle_evidence_v2(
    *,
    manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    deployment_run_id: str,
    challenge_digest: str,
    phase_documents: Sequence[Mapping[str, Any]],
    precondition_documents: Sequence[Mapping[str, Any]],
    execution_documents: Sequence[Mapping[str, Any]],
    postcondition_documents: Sequence[Mapping[str, Any]],
    phase_keys: Mapping[str, TrustedKey],
    precondition_keys: Mapping[str, TrustedKey],
    execution_keys: Mapping[str, TrustedKey],
    postcondition_keys: Mapping[str, TrustedKey],
    host_role: str,
    platform_family: str,
    architecture: str,
    host_identity_digest: str,
    platform_identity_digest: str,
    environment_identity_digest: str,
    expected_package_artifact_digest: str,
    expected_guardian_artifact_digest: str,
    expected_predecessor: Mapping[str, Any],
    created_at: str,
    host_key_policy: Mapping[str, Mapping[str, str]],
    signer: Ed25519Signer,
) -> dict[str, Any]:
    """Aggregate four full typed phase chains for one actual host (v2)."""

    verified_manifest = verify_adapter_capability_manifest(
        manifest,
        adapter_key=adapter_key,
    )
    package = _expected_candidate_reference(
        distribution=DEPLOYMENT_COHORT_PACKAGE_DISTRIBUTION,
        version=DEPLOYMENT_COHORT_PACKAGE_VERSION,
        artifact_digest=expected_package_artifact_digest,
        expected_distribution=DEPLOYMENT_COHORT_PACKAGE_DISTRIBUTION,
        expected_version=DEPLOYMENT_COHORT_PACKAGE_VERSION,
        label="package",
    )
    guardian = _expected_candidate_reference(
        distribution=DEPLOYMENT_COHORT_GUARDIAN_DISTRIBUTION,
        version=DEPLOYMENT_COHORT_GUARDIAN_VERSION,
        artifact_digest=expected_guardian_artifact_digest,
        expected_distribution=DEPLOYMENT_COHORT_GUARDIAN_DISTRIBUTION,
        expected_version=DEPLOYMENT_COHORT_GUARDIAN_VERSION,
        label="Guardian",
    )
    host = _host_reference(
        host_role=host_role,
        platform_family=platform_family,
        architecture=architecture,
        host_identity_digest=host_identity_digest,
        platform_identity_digest=platform_identity_digest,
        environment_identity_digest=environment_identity_digest,
    )
    expected_family = DEPLOYMENT_COHORT_ROLE_FAMILIES.get(host_role)
    if expected_family is None:
        raise AdapterPortabilityError("ASDK deployment cohort host role is unsupported")
    if platform_family != expected_family:
        raise AdapterPortabilityError("ASDK deployment cohort host role/platform mismatch")
    chains = _verified_phase_chains(
        manifest=verified_manifest,
        adapter_key=adapter_key,
        phase_documents=phase_documents,
        precondition_documents=precondition_documents,
        execution_documents=execution_documents,
        postcondition_documents=postcondition_documents,
        phase_keys=phase_keys,
        precondition_keys=precondition_keys,
        execution_keys=execution_keys,
        postcondition_keys=postcondition_keys,
        deployment_run_id=deployment_run_id,
        challenge_digest=challenge_digest,
        expected_package_artifact_digest=expected_package_artifact_digest,
        expected_guardian_artifact_digest=expected_guardian_artifact_digest,
        expected_predecessor=expected_predecessor,
        host_key_policy=host_key_policy,
    )
    ordered = _ordered_host_phase_chains(
        chains,
        manifest_reference=_manifest_reference(verified_manifest),
        package_reference=package,
        guardian_reference=guardian,
        host_reference=host,
    )
    _require_host_assessor_trust(
        chains=ordered,
        adapter_key=adapter_key,
        precondition_keys=precondition_keys,
        execution_keys=execution_keys,
        postcondition_keys=postcondition_keys,
        phase_keys=phase_keys,
        host_key=_trusted_signer(signer),
        host_key_policy=host_key_policy,
        created_at=created_at,
    )
    core = _host_lifecycle_core(
        manifest=_manifest_reference(verified_manifest),
        package=package,
        guardian=guardian,
        host=host,
        chains=ordered,
        created_at=created_at,
        adapter_signer_id=adapter_key.key_id,
        signer_id=signer.key_id,
    )
    unsigned = {
        "evidence_id": _identity(
            core,
            field="evidence_id",
            prefix="adapter-deployment-host-lifecycle-evidence-v2:",
            domain="adapter-deployment-host-lifecycle-evidence-identity-v2",
        ),
        **core,
    }
    signed = signer.sign(unsigned)
    validate("adapter-deployment-host-lifecycle-evidence-v2", signed)
    return signed


def verify_adapter_deployment_host_lifecycle_evidence_v2(
    evidence: Mapping[str, Any],
    *,
    manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    deployment_run_id: str,
    challenge_digest: str,
    expected_package_artifact_digest: str,
    expected_guardian_artifact_digest: str,
    expected_predecessor: Mapping[str, Any],
    phase_documents: Sequence[Mapping[str, Any]],
    precondition_documents: Sequence[Mapping[str, Any]],
    execution_documents: Sequence[Mapping[str, Any]],
    postcondition_documents: Sequence[Mapping[str, Any]],
    phase_keys: Mapping[str, TrustedKey],
    precondition_keys: Mapping[str, TrustedKey],
    execution_keys: Mapping[str, TrustedKey],
    postcondition_keys: Mapping[str, TrustedKey],
    host_key_policy: Mapping[str, Mapping[str, str]],
    evidence_key: TrustedKey,
) -> dict[str, Any]:
    candidate = _verify_signed(
        evidence,
        schema="adapter-deployment-host-lifecycle-evidence-v2",
        field="evidence_id",
        prefix="adapter-deployment-host-lifecycle-evidence-v2:",
        domain="adapter-deployment-host-lifecycle-evidence-identity-v2",
        trusted_key=evidence_key,
    )
    verified_manifest = verify_adapter_capability_manifest(
        manifest,
        adapter_key=adapter_key,
    )
    chains = _verified_phase_chains(
        manifest=verified_manifest,
        adapter_key=adapter_key,
        phase_documents=phase_documents,
        precondition_documents=precondition_documents,
        execution_documents=execution_documents,
        postcondition_documents=postcondition_documents,
        phase_keys=phase_keys,
        precondition_keys=precondition_keys,
        execution_keys=execution_keys,
        postcondition_keys=postcondition_keys,
        deployment_run_id=deployment_run_id,
        challenge_digest=challenge_digest,
        expected_package_artifact_digest=expected_package_artifact_digest,
        expected_guardian_artifact_digest=expected_guardian_artifact_digest,
        expected_predecessor=expected_predecessor,
        host_key_policy=host_key_policy,
    )
    ordered = _ordered_host_phase_chains(
        chains,
        manifest_reference=_manifest_reference(verified_manifest),
        package_reference=candidate["package"],
        guardian_reference=candidate["guardian"],
        host_reference=candidate["host"],
    )
    if candidate["deployment"] != {
        "deployment_run_id": deployment_run_id,
        "challenge_digest": challenge_digest,
    }:
        raise AdapterPortabilityError("ASDK lifecycle deployment challenge mismatch")
    if (
        candidate["package"]["artifact_digest"] != expected_package_artifact_digest
        or candidate["guardian"]["artifact_digest"] != expected_guardian_artifact_digest
    ):
        raise AdapterPortabilityError("ASDK lifecycle verifier-supplied release artifact mismatch")
    _require_host_assessor_trust(
        chains=ordered,
        adapter_key=adapter_key,
        precondition_keys=precondition_keys,
        execution_keys=execution_keys,
        postcondition_keys=postcondition_keys,
        phase_keys=phase_keys,
        host_key=evidence_key,
        host_key_policy=host_key_policy,
        created_at=candidate["created_at"],
    )
    rebuilt = _host_lifecycle_core(
        manifest=_manifest_reference(verified_manifest),
        package=candidate["package"],
        guardian=candidate["guardian"],
        host=candidate["host"],
        chains=ordered,
        created_at=candidate["created_at"],
        adapter_signer_id=adapter_key.key_id,
        signer_id=evidence_key.key_id,
    )
    expected = deepcopy(candidate)
    expected.pop("signature", None)
    expected.pop("evidence_id", None)
    if rebuilt != expected:
        raise AdapterPortabilityError("ASDK deployment host lifecycle evidence coverage mismatch")
    return candidate


def _deployment_evidence_reference_v2(evidence: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "host_role": evidence["host"]["role"],
        "platform_family": evidence["host"]["platform_family"],
        "evidence_id": evidence["evidence_id"],
        "evidence_digest": adapter_deployment_host_lifecycle_evidence_v2_digest(evidence),
        "host_identity_digest": evidence["host"]["host_identity_digest"],
        "environment_identity_digest": evidence["host"]["environment_identity_digest"],
        "phase_receipt_digests": {
            phase: evidence["lifecycle"][phase]["phase_receipt_digest"]
            for phase in _DEPLOYMENT_LIFECYCLE_PHASES
        },
        "precondition_receipt_digests": {
            phase: evidence["lifecycle"][phase]["precondition_receipt_digest"]
            for phase in _DEPLOYMENT_LIFECYCLE_PHASES
        },
        "assessor_signer_id": evidence["signer_id"],
    }


def _group_receipts_by_host_role(
    documents: Sequence[Mapping[str, Any]],
    *,
    schema: str,
    label: str,
) -> dict[str, list[dict[str, Any]]]:
    groups = {role: [] for role in DEPLOYMENT_COHORT_ROLES}
    for document in documents:
        if not isinstance(document, Mapping):
            raise AdapterPortabilityError(f"ASDK lifecycle {label} body is required")
        candidate = _schema_candidate(document, schema=schema)
        role = str(candidate["binding"]["host"]["role"])
        if role not in groups:
            raise AdapterPortabilityError("ASDK deployment cohort host role is unsupported")
        groups[role].append(candidate)
    return groups


def _verified_deployment_evidence_set_v2(
    *,
    manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    evidence_documents: Sequence[Mapping[str, Any]],
    evidence_keys: Mapping[str, TrustedKey],
    phase_documents: Sequence[Mapping[str, Any]],
    precondition_documents: Sequence[Mapping[str, Any]],
    execution_documents: Sequence[Mapping[str, Any]],
    postcondition_documents: Sequence[Mapping[str, Any]],
    phase_keys: Mapping[str, TrustedKey],
    precondition_keys: Mapping[str, TrustedKey],
    execution_keys: Mapping[str, TrustedKey],
    postcondition_keys: Mapping[str, TrustedKey],
    deployment_run_id: str,
    challenge_digest: str,
    expected_package_artifact_digest: str,
    expected_guardian_artifact_digest: str,
    expected_predecessor: Mapping[str, Any],
    host_key_policy: Mapping[str, Mapping[str, str]],
) -> list[dict[str, Any]]:
    evidence_by_role: dict[str, dict[str, Any]] = {}
    for document in evidence_documents:
        if not isinstance(document, Mapping):
            raise AdapterPortabilityError("ASDK deployment cohort host evidence body is required")
        candidate = _schema_candidate(
            document,
            schema="adapter-deployment-host-lifecycle-evidence-v2",
        )
        role = str(candidate["host"]["role"])
        if role in evidence_by_role:
            raise AdapterPortabilityError("ASDK deployment cohort duplicate evidence")
        evidence_by_role[role] = candidate
    if set(evidence_by_role) != set(DEPLOYMENT_COHORT_ROLES):
        raise AdapterPortabilityError(
            "ASDK deployment cohort requires exactly linux-primary, windows-vm and client-workstation"
        )
    phase_by_role = _group_receipts_by_host_role(
        phase_documents,
        schema="adapter-deployment-lifecycle-phase-receipt",
        label="phase receipt",
    )
    precondition_by_role = _group_receipts_by_host_role(
        precondition_documents,
        schema="adapter-deployment-lifecycle-precondition-receipt",
        label="precondition receipt",
    )
    execution_by_role = _group_receipts_by_host_role(
        execution_documents,
        schema="adapter-deployment-lifecycle-execution-receipt",
        label="execution receipt",
    )
    postcondition_by_role = _group_receipts_by_host_role(
        postcondition_documents,
        schema="adapter-deployment-lifecycle-postcondition-receipt",
        label="postcondition receipt",
    )
    verified: list[dict[str, Any]] = []
    for role in DEPLOYMENT_COHORT_ROLES:
        document = evidence_by_role[role]
        key = _required_trusted_key(document, evidence_keys, label="host evidence")
        verified.append(
            verify_adapter_deployment_host_lifecycle_evidence_v2(
                document,
                manifest=manifest,
                adapter_key=adapter_key,
                deployment_run_id=deployment_run_id,
                challenge_digest=challenge_digest,
                expected_package_artifact_digest=expected_package_artifact_digest,
                expected_guardian_artifact_digest=expected_guardian_artifact_digest,
                expected_predecessor=expected_predecessor,
                phase_documents=phase_by_role[role],
                precondition_documents=precondition_by_role[role],
                execution_documents=execution_by_role[role],
                postcondition_documents=postcondition_by_role[role],
                phase_keys=phase_keys,
                precondition_keys=precondition_keys,
                execution_keys=execution_keys,
                postcondition_keys=postcondition_keys,
                host_key_policy=host_key_policy,
                evidence_key=key,
            )
        )
    return verified


def _require_global_role_independence(
    evidence: Sequence[Mapping[str, Any]],
    *,
    adapter_key: TrustedKey,
    evidence_keys: Mapping[str, TrustedKey],
    phase_keys: Mapping[str, TrustedKey],
    precondition_keys: Mapping[str, TrustedKey],
    execution_keys: Mapping[str, TrustedKey],
    postcondition_keys: Mapping[str, TrustedKey],
    cohort_key: TrustedKey,
) -> None:
    def fingerprints(
        signer_ids: set[str],
        keys: Mapping[str, TrustedKey],
        *,
        label: str,
    ) -> set[str]:
        values: set[str] = set()
        for signer_id in signer_ids:
            key = keys.get(signer_id)
            if key is None or key.key_id != signer_id:
                raise AdapterPortabilityError(f"ASDK deployment cohort {label} signer is untrusted")
            values.add(public_key_fingerprint(key.public_key))
        return values

    precondition_ids = {
        item["lifecycle"][phase]["precondition_observer_signer_id"]
        for item in evidence
        for phase in _DEPLOYMENT_LIFECYCLE_PHASES
    }
    executor_ids = {
        item["lifecycle"][phase]["executor_signer_id"]
        for item in evidence
        for phase in _DEPLOYMENT_LIFECYCLE_PHASES
    }
    observer_ids = {
        item["lifecycle"][phase]["observer_signer_id"]
        for item in evidence
        for phase in _DEPLOYMENT_LIFECYCLE_PHASES
    }
    phase_ids = {
        item["lifecycle"][phase]["phase_assessor_signer_id"]
        for item in evidence
        for phase in _DEPLOYMENT_LIFECYCLE_PHASES
    }
    host_ids = {str(item["signer_id"]) for item in evidence}
    host_fingerprints = fingerprints(host_ids, evidence_keys, label="host evidence")
    if len(host_fingerprints) != len(host_ids):
        raise AdapterPortabilityError(
            "ASDK deployment cohort requires one independent assessor per host"
        )
    role_signers = {
        "adapter": {public_key_fingerprint(adapter_key.public_key)},
        "precondition observer": fingerprints(
            precondition_ids,
            precondition_keys,
            label="precondition",
        ),
        "executor": fingerprints(executor_ids, execution_keys, label="execution"),
        "observer": fingerprints(observer_ids, postcondition_keys, label="postcondition"),
        "phase assessor": fingerprints(phase_ids, phase_keys, label="phase"),
        "host assessor": host_fingerprints,
        "cohort signer": {public_key_fingerprint(cohort_key.public_key)},
    }
    labels = list(role_signers)
    for index, left_label in enumerate(labels):
        for right_label in labels[index + 1 :]:
            if role_signers[left_label] & role_signers[right_label]:
                raise AdapterPortabilityError(
                    "ASDK deployment cohort signer roles must be independent"
                )


def _deployment_cohort_core_v2(
    *,
    manifest: Mapping[str, Any],
    evidence: Sequence[Mapping[str, Any]],
    created_at: str,
    signer_id: str,
) -> dict[str, Any]:
    roles = [item["host"]["role"] for item in evidence]
    if set(roles) != set(DEPLOYMENT_COHORT_ROLES) or len(roles) != 3:
        raise AdapterPortabilityError(
            "ASDK deployment cohort requires exactly linux-primary, windows-vm and client-workstation"
        )
    packages = {
        (
            item["package"]["distribution"],
            item["package"]["version"],
            item["package"]["artifact_digest"],
        )
        for item in evidence
    }
    guardians = {
        (
            item["guardian"]["distribution"],
            item["guardian"]["version"],
            item["guardian"]["artifact_digest"],
        )
        for item in evidence
    }
    if len(packages) != 1:
        raise AdapterPortabilityError(
            "ASDK deployment cohort package artifact/version differs across hosts"
        )
    if len(guardians) != 1:
        raise AdapterPortabilityError(
            "ASDK deployment cohort Guardian artifact/version differs across hosts"
        )
    distribution, version, _artifact_digest = next(iter(packages))
    if (
        distribution != DEPLOYMENT_COHORT_PACKAGE_DISTRIBUTION
        or version != DEPLOYMENT_COHORT_PACKAGE_VERSION
    ):
        raise AdapterPortabilityError("ASDK deployment cohort package identity mismatch")
    guardian_distribution, guardian_version, _guardian_digest = next(iter(guardians))
    if (
        guardian_distribution != DEPLOYMENT_COHORT_GUARDIAN_DISTRIBUTION
        or guardian_version != DEPLOYMENT_COHORT_GUARDIAN_VERSION
    ):
        raise AdapterPortabilityError("ASDK deployment cohort Guardian identity mismatch")
    for item in evidence:
        if any(
            item["lifecycle"][phase]["result"] != "passed" for phase in _DEPLOYMENT_LIFECYCLE_PHASES
        ):
            raise AdapterPortabilityError(
                "ASDK deployment cohort lifecycle is not complete on every host"
            )
    host_identities = {item["host"]["host_identity_digest"] for item in evidence}
    environment_identities = {item["host"]["environment_identity_digest"] for item in evidence}
    assessor_signers = {item["signer_id"] for item in evidence}
    if len(host_identities) != 3:
        raise AdapterPortabilityError("ASDK deployment cohort hosts must be distinct")
    if len(environment_identities) != 3:
        raise AdapterPortabilityError("ASDK deployment cohort environments must be distinct")
    if len(assessor_signers) != 3:
        raise AdapterPortabilityError(
            "ASDK deployment cohort requires one independent assessor per host"
        )
    for field in (
        "phase_receipt_id",
        "phase_receipt_digest",
        "precondition_receipt_id",
        "precondition_receipt_digest",
        "attempt_id",
        "execution_receipt_id",
        "execution_receipt_digest",
        "postcondition_receipt_id",
        "postcondition_receipt_digest",
    ):
        values = [
            item["lifecycle"][phase][field]
            for item in evidence
            for phase in _DEPLOYMENT_LIFECYCLE_PHASES
        ]
        if len(set(values)) != len(values):
            raise AdapterPortabilityError(
                "ASDK deployment cohort receipt reused in consumed evidence"
            )
    by_role = {item["host"]["role"]: item for item in evidence}
    ordered = [by_role[role] for role in DEPLOYMENT_COHORT_ROLES]
    package = ordered[0]["package"]
    guardian = ordered[0]["guardian"]
    return {
        "protocol": "integrity-guardian/adapter-deployment-cohort-receipt/v2",
        "sdk_version": ADAPTER_SDK_VERSION,
        "deployment": dict(ordered[0]["deployment"]),
        "manifest": _manifest_reference(manifest),
        "package": dict(package),
        "guardian": dict(guardian),
        "evidence": [_deployment_evidence_reference_v2(item) for item in ordered],
        "result": {
            "host_roles": list(DEPLOYMENT_COHORT_ROLES),
            "lifecycle_complete": True,
            "exact_package_shared": True,
            "exact_guardian_shared": True,
            "typed_phase_receipts_verified": True,
            "typed_preconditions_verified": True,
            "no_receipt_reuse_in_consumed_evidence": True,
            "independent_assessors": True,
            "readiness": "deployment-cohort-ready",
        },
        "authority_boundary": _authority_boundary(),
        "created_at": created_at,
        "signer_id": signer_id,
    }


def build_adapter_deployment_cohort_receipt_v2(
    *,
    manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    deployment_run_id: str,
    challenge_digest: str,
    expected_package_artifact_digest: str,
    expected_guardian_artifact_digest: str,
    expected_predecessor: Mapping[str, Any],
    evidence_documents: Sequence[Mapping[str, Any]],
    evidence_keys: Mapping[str, TrustedKey],
    phase_documents: Sequence[Mapping[str, Any]],
    precondition_documents: Sequence[Mapping[str, Any]],
    execution_documents: Sequence[Mapping[str, Any]],
    postcondition_documents: Sequence[Mapping[str, Any]],
    phase_keys: Mapping[str, TrustedKey],
    precondition_keys: Mapping[str, TrustedKey],
    execution_keys: Mapping[str, TrustedKey],
    postcondition_keys: Mapping[str, TrustedKey],
    host_key_policy: Mapping[str, Mapping[str, str]],
    created_at: str,
    signer: Ed25519Signer,
) -> dict[str, Any]:
    """Aggregate only full-body verified evidence for the three-host cohort."""

    verified_manifest = verify_adapter_capability_manifest(
        manifest,
        adapter_key=adapter_key,
    )
    verified = _verified_deployment_evidence_set_v2(
        manifest=verified_manifest,
        adapter_key=adapter_key,
        evidence_documents=evidence_documents,
        evidence_keys=evidence_keys,
        phase_documents=phase_documents,
        precondition_documents=precondition_documents,
        execution_documents=execution_documents,
        postcondition_documents=postcondition_documents,
        phase_keys=phase_keys,
        precondition_keys=precondition_keys,
        execution_keys=execution_keys,
        postcondition_keys=postcondition_keys,
        deployment_run_id=deployment_run_id,
        challenge_digest=challenge_digest,
        expected_package_artifact_digest=expected_package_artifact_digest,
        expected_guardian_artifact_digest=expected_guardian_artifact_digest,
        expected_predecessor=expected_predecessor,
        host_key_policy=host_key_policy,
    )
    _require_global_role_independence(
        verified,
        adapter_key=adapter_key,
        evidence_keys=evidence_keys,
        phase_keys=phase_keys,
        precondition_keys=precondition_keys,
        execution_keys=execution_keys,
        postcondition_keys=postcondition_keys,
        cohort_key=_trusted_signer(signer),
    )
    for item in verified:
        _require_timestamp_order(item["created_at"], created_at)
    core = _deployment_cohort_core_v2(
        manifest=verified_manifest,
        evidence=verified,
        created_at=created_at,
        signer_id=signer.key_id,
    )
    unsigned = {
        "receipt_id": _identity(
            core,
            field="receipt_id",
            prefix="adapter-deployment-cohort-receipt-v2:",
            domain="adapter-deployment-cohort-receipt-identity-v2",
        ),
        **core,
    }
    signed = signer.sign(unsigned)
    validate("adapter-deployment-cohort-receipt-v2", signed)
    return signed


def verify_adapter_deployment_cohort_receipt_v2(
    receipt: Mapping[str, Any],
    *,
    manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    deployment_run_id: str,
    challenge_digest: str,
    expected_package_artifact_digest: str,
    expected_guardian_artifact_digest: str,
    expected_predecessor: Mapping[str, Any],
    evidence_documents: Sequence[Mapping[str, Any]],
    evidence_keys: Mapping[str, TrustedKey],
    phase_documents: Sequence[Mapping[str, Any]],
    precondition_documents: Sequence[Mapping[str, Any]],
    execution_documents: Sequence[Mapping[str, Any]],
    postcondition_documents: Sequence[Mapping[str, Any]],
    phase_keys: Mapping[str, TrustedKey],
    precondition_keys: Mapping[str, TrustedKey],
    execution_keys: Mapping[str, TrustedKey],
    postcondition_keys: Mapping[str, TrustedKey],
    host_key_policy: Mapping[str, Mapping[str, str]],
    receipt_key: TrustedKey,
) -> dict[str, Any]:
    candidate = _verify_signed(
        receipt,
        schema="adapter-deployment-cohort-receipt-v2",
        field="receipt_id",
        prefix="adapter-deployment-cohort-receipt-v2:",
        domain="adapter-deployment-cohort-receipt-identity-v2",
        trusted_key=receipt_key,
    )
    verified_manifest = verify_adapter_capability_manifest(
        manifest,
        adapter_key=adapter_key,
    )
    evidence = _verified_deployment_evidence_set_v2(
        manifest=verified_manifest,
        adapter_key=adapter_key,
        evidence_documents=evidence_documents,
        evidence_keys=evidence_keys,
        phase_documents=phase_documents,
        precondition_documents=precondition_documents,
        execution_documents=execution_documents,
        postcondition_documents=postcondition_documents,
        phase_keys=phase_keys,
        precondition_keys=precondition_keys,
        execution_keys=execution_keys,
        postcondition_keys=postcondition_keys,
        deployment_run_id=deployment_run_id,
        challenge_digest=challenge_digest,
        expected_package_artifact_digest=expected_package_artifact_digest,
        expected_guardian_artifact_digest=expected_guardian_artifact_digest,
        expected_predecessor=expected_predecessor,
        host_key_policy=host_key_policy,
    )
    if candidate["deployment"] != {
        "deployment_run_id": deployment_run_id,
        "challenge_digest": challenge_digest,
    }:
        raise AdapterPortabilityError("ASDK lifecycle deployment challenge mismatch")
    if (
        candidate["package"]["artifact_digest"] != expected_package_artifact_digest
        or candidate["guardian"]["artifact_digest"] != expected_guardian_artifact_digest
    ):
        raise AdapterPortabilityError("ASDK lifecycle verifier-supplied release artifact mismatch")
    _require_global_role_independence(
        evidence,
        adapter_key=adapter_key,
        evidence_keys=evidence_keys,
        phase_keys=phase_keys,
        precondition_keys=precondition_keys,
        execution_keys=execution_keys,
        postcondition_keys=postcondition_keys,
        cohort_key=receipt_key,
    )
    for item in evidence:
        _require_timestamp_order(item["created_at"], candidate["created_at"])
    rebuilt = _deployment_cohort_core_v2(
        manifest=verified_manifest,
        evidence=evidence,
        created_at=candidate["created_at"],
        signer_id=receipt_key.key_id,
    )
    expected = deepcopy(candidate)
    expected.pop("signature", None)
    expected.pop("receipt_id", None)
    if rebuilt != expected:
        raise AdapterPortabilityError("ASDK deployment cohort receipt coverage mismatch")
    return candidate


def build_adapter_platform_lifecycle_evidence(
    *,
    manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    family: str,
    architecture: str,
    environment_digest: str,
    runtime_digest: str,
    runner_digest: str,
    receipt_model_digest: str,
    clean_install_receipt_digest: str,
    upgrade_receipt_digest: str,
    revoke_receipt_digest: str,
    recovery_receipt_digest: str,
    created_at: str,
    signer: Ed25519Signer,
) -> dict[str, Any]:
    """Reject the historical digest-only platform evidence surface."""

    raise AdapterPortabilityError(
        "ASDK digest-only portability evidence is non-admissible; "
        "migrate to typed deployment lifecycle receipts"
    )


def verify_adapter_platform_lifecycle_evidence(
    evidence: Mapping[str, Any],
    *,
    manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    evidence_key: TrustedKey,
) -> dict[str, Any]:
    """Refuse admission of historical digest-only platform evidence."""

    raise AdapterPortabilityError(
        "ASDK digest-only portability evidence is non-admissible; "
        "migrate to typed deployment lifecycle receipts"
    )


def build_adapter_portability_receipt(
    *,
    manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    evidence_documents: Sequence[Mapping[str, Any]],
    evidence_keys: Mapping[str, TrustedKey],
    created_at: str,
    signer: Ed25519Signer,
) -> dict[str, Any]:
    """Reject the historical aggregate that consumed only opaque digests."""

    raise AdapterPortabilityError(
        "ASDK digest-only portability receipt is non-admissible; "
        "migrate to typed deployment cohort receipts"
    )


def verify_adapter_portability_receipt(
    receipt: Mapping[str, Any],
    *,
    manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    evidence_documents: Sequence[Mapping[str, Any]],
    evidence_keys: Mapping[str, TrustedKey],
    receipt_key: TrustedKey,
) -> dict[str, Any]:
    """Refuse admission of historical digest-only portability receipts."""

    raise AdapterPortabilityError(
        "ASDK digest-only portability receipt is non-admissible; "
        "migrate to typed deployment cohort receipts"
    )


def require_adapter_portfolio_readiness(
    conformance_receipt: Mapping[str, Any],
    portability_receipt: Mapping[str, Any],
    *,
    conformance_profile: Mapping[str, Any],
    conformance_profile_key: TrustedKey,
    conformance_evidence_documents: Sequence[Mapping[str, Any]],
    conformance_evidence_keys: Mapping[str, TrustedKey],
    conformance_receipt_key: TrustedKey,
    manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    deployment_run_id: str,
    challenge_digest: str,
    expected_package_artifact_digest: str,
    expected_guardian_artifact_digest: str,
    expected_predecessor: Mapping[str, Any],
    evidence_documents: Sequence[Mapping[str, Any]],
    evidence_keys: Mapping[str, TrustedKey],
    phase_documents: Sequence[Mapping[str, Any]],
    precondition_documents: Sequence[Mapping[str, Any]],
    execution_documents: Sequence[Mapping[str, Any]],
    postcondition_documents: Sequence[Mapping[str, Any]],
    phase_keys: Mapping[str, TrustedKey],
    precondition_keys: Mapping[str, TrustedKey],
    execution_keys: Mapping[str, TrustedKey],
    postcondition_keys: Mapping[str, TrustedKey],
    host_key_policy: Mapping[str, Mapping[str, str]],
    receipt_key: TrustedKey,
) -> None:
    """Require proof coverage plus the typed three-host lifecycle cohort."""

    if (
        portability_receipt.get("protocol")
        != "integrity-guardian/adapter-deployment-cohort-receipt/v2"
        or portability_receipt.get("result", {}).get("readiness") != "deployment-cohort-ready"
        or portability_receipt.get("result", {}).get("typed_phase_receipts_verified") is not True
        or portability_receipt.get("result", {}).get("typed_preconditions_verified") is not True
    ):
        raise AdapterPortabilityError(
            "ASDK digest-only portability is non-admissible; "
            "typed deployment lifecycle is incomplete"
        )
    try:
        verified_conformance = verify_adapter_conformance_receipt(
            conformance_receipt,
            profile=conformance_profile,
            profile_key=conformance_profile_key,
            manifest=manifest,
            adapter_key=adapter_key,
            evidence_documents=conformance_evidence_documents,
            evidence_keys=conformance_evidence_keys,
            receipt_key=conformance_receipt_key,
        )
        require_adapter_conformance_readiness(
            verified_conformance,
            minimum="portfolio-ready",
        )
    except AdapterSdkError as exc:
        raise AdapterPortabilityError(
            "ASDK portfolio proof coverage is incomplete or unverified"
        ) from exc
    verified_cohort = verify_adapter_deployment_cohort_receipt_v2(
        portability_receipt,
        manifest=manifest,
        adapter_key=adapter_key,
        deployment_run_id=deployment_run_id,
        challenge_digest=challenge_digest,
        expected_package_artifact_digest=expected_package_artifact_digest,
        expected_guardian_artifact_digest=expected_guardian_artifact_digest,
        expected_predecessor=expected_predecessor,
        evidence_documents=evidence_documents,
        evidence_keys=evidence_keys,
        phase_documents=phase_documents,
        precondition_documents=precondition_documents,
        execution_documents=execution_documents,
        postcondition_documents=postcondition_documents,
        phase_keys=phase_keys,
        precondition_keys=precondition_keys,
        execution_keys=execution_keys,
        postcondition_keys=postcondition_keys,
        host_key_policy=host_key_policy,
        receipt_key=receipt_key,
    )
    verified_profile_reference = verified_conformance["profile"]
    portability_manifest = verified_cohort["manifest"]
    if verified_profile_reference.get("adapter_id") != portability_manifest.get(
        "adapter_id"
    ) or verified_profile_reference.get("adapter_artifact_digest") != portability_manifest.get(
        "adapter_artifact_digest"
    ):
        raise AdapterPortabilityError(
            "ASDK portability receipt belongs to a different adapter artifact"
        )


__all__ = [
    "DEPLOYMENT_COHORT_GUARDIAN_DISTRIBUTION",
    "DEPLOYMENT_COHORT_GUARDIAN_VERSION",
    "DEPLOYMENT_COHORT_PACKAGE_DISTRIBUTION",
    "DEPLOYMENT_COHORT_PACKAGE_VERSION",
    "DEPLOYMENT_COHORT_ROLES",
    "DEPLOYMENT_COHORT_ROLE_FAMILIES",
    "PORTABLE_FAMILIES",
    "AdapterPortabilityError",
    "adapter_deployment_cohort_receipt_digest",
    "adapter_deployment_cohort_receipt_v2_digest",
    "adapter_deployment_host_lifecycle_evidence_digest",
    "adapter_deployment_host_lifecycle_evidence_v2_digest",
    "adapter_deployment_lifecycle_execution_receipt_digest",
    "adapter_deployment_lifecycle_phase_receipt_digest",
    "adapter_deployment_lifecycle_postcondition_receipt_digest",
    "adapter_deployment_lifecycle_precondition_receipt_digest",
    "adapter_deployment_observed_state_digest",
    "adapter_platform_lifecycle_evidence_digest",
    "adapter_portability_receipt_digest",
    "build_adapter_deployment_cohort_receipt",
    "build_adapter_deployment_cohort_receipt_v2",
    "build_adapter_deployment_host_lifecycle_evidence",
    "build_adapter_deployment_host_lifecycle_evidence_v2",
    "build_adapter_deployment_lifecycle_execution_receipt",
    "build_adapter_deployment_lifecycle_phase_receipt",
    "build_adapter_deployment_lifecycle_postcondition_receipt",
    "build_adapter_deployment_lifecycle_precondition_receipt",
    "build_adapter_platform_lifecycle_evidence",
    "build_adapter_portability_receipt",
    "require_adapter_portfolio_readiness",
    "verify_adapter_deployment_cohort_receipt",
    "verify_adapter_deployment_cohort_receipt_v2",
    "verify_adapter_deployment_host_lifecycle_evidence",
    "verify_adapter_deployment_host_lifecycle_evidence_v2",
    "verify_adapter_deployment_lifecycle_execution_receipt",
    "verify_adapter_deployment_lifecycle_phase_receipt",
    "verify_adapter_deployment_lifecycle_postcondition_receipt",
    "verify_adapter_deployment_lifecycle_precondition_receipt",
    "verify_adapter_platform_lifecycle_evidence",
    "verify_adapter_portability_receipt",
]
