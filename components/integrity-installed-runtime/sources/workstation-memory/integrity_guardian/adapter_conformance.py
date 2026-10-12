"""Machine-enforced proof coverage and admission for Integrity ASDK adapters."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
from typing import Any

from .adapter_sdk import (
    ADAPTER_SDK_VERSION,
    AdapterSdkError,
    adapter_capability_manifest_digest,
    verify_adapter_capability_manifest,
)
from .canonical import canonical_bytes, parse_json_strict
from .hashing import digest_object
from .schemas import validate
from .signing import Ed25519Signer, TrustedKey, verify_signature

ASDK_PROOF_CONTRACT_VERSION = "1.0"

# (proof id, category, tier, optional channel)
_PROOF_DEFINITIONS: tuple[tuple[str, str, str, str | None], ...] = (
    ("identity.sdk-artifact", "identity", "source", None),
    ("identity.adapter-signature", "identity", "source", None),
    ("identity.executor-witness-distinct", "identity", "source", None),
    ("identity.tenant-target-zone", "identity", "source", None),
    ("identity.adapter-substitution-rejected", "identity", "source", None),
    ("identity.operation-binding-signed", "identity", "source", None),
    ("identity.conformance-operation-executor-bound", "identity", "source", None),
    ("capability.closed-manifest", "capability", "source", None),
    ("capability.unsupported-explicit", "capability", "source", None),
    ("capability.never-authority", "capability", "source", None),
    ("observation.signed-fresh-target", "observation", "source", None),
    ("observation.unknown-explicit", "observation", "source", None),
    ("observation.source-provenance", "observation", "source", None),
    ("observation.home-excluded", "observation", "source", None),
    ("proposal.observation-bound", "proposal", "source", None),
    ("proposal.operation-target-immutable", "proposal", "source", None),
    ("proposal.blast-radius-declared", "proposal", "source", None),
    ("authority.a13-signature-current", "authority", "source", None),
    ("authority.exact-proposal-target", "authority", "source", None),
    ("authority.single-use", "authority", "source", None),
    ("authority.consumed-before-dispatch", "authority", "source", None),
    ("authority.cross-agent-replay-rejected", "authority", "source", None),
    ("authority.production-separate", "authority", "source", None),
    ("dispatch.journal-before-executor", "dispatch", "source", None),
    ("dispatch.one-shot-permit", "dispatch", "source", None),
    ("dispatch.direct-call-rejected", "dispatch", "source", None),
    ("dispatch.permit-nonserializable", "dispatch", "source", None),
    ("dispatch.concurrent-replay-rejected", "dispatch", "source", None),
    ("containment.exact-operation", "containment", "source", None),
    ("containment.bounded-io-environment", "containment", "source", None),
    ("containment.credentials-by-reference", "containment", "source", None),
    ("containment.no-implicit-second-action", "containment", "source", None),
    ("containment.api-operation", "containment", "source", "api"),
    ("containment.shell-boundary", "containment", "source", "shell"),
    ("containment.browser-target", "containment", "source", "browser_control"),
    ("containment.computer-use-target", "containment", "source", "computer_use"),
    ("containment.network-destination", "containment", "source", "network"),
    ("containment.credential-custody", "containment", "source", "credentials"),
    ("containment.service-target", "containment", "source", "service_control"),
    ("crash.five-state-closed", "crash", "source", None),
    ("crash.fresh-process-no-replay", "crash", "source", None),
    ("crash.unknown-no-retry", "crash", "source", None),
    ("crash.stale-checkpoint-rejected", "crash", "source", None),
    ("crash.tampered-journal-rejected", "crash", "source", None),
    ("crash.lost-response-not-success", "crash", "source", None),
    ("executor.signed", "executor", "source", None),
    ("executor.exact-envelope", "executor", "source", None),
    ("executor.bounded-evidence", "executor", "source", None),
    ("executor.failure-taxonomy", "executor", "source", None),
    ("executor.not-independent-witness", "executor", "source", None),
    ("executor.provenance-through-terminal", "executor", "source", None),
    ("witness.independent-a14", "witness", "source", None),
    ("witness.post-action-target", "witness", "source", None),
    ("witness.closed-outcomes", "witness", "source", None),
    ("witness.fresh-source", "witness", "source", None),
    ("witness.disagreement-unknown", "witness", "source", None),
    ("witness.executor-identity-key-artifact-separated", "witness", "source", None),
    ("result.before-after-separated", "result", "source", None),
    ("result.causality-not-inferred", "result", "source", None),
    ("result.blast-radius-observed", "result", "source", None),
    ("result.exit-zero-not-success", "result", "source", None),
    ("memory.append-only-terminal-contract", "memory", "source", None),
    ("memory.failure-unknown-retained", "memory", "source", None),
    ("memory.raw-secrets-excluded", "memory", "source", None),
    ("memory.home-separated", "memory", "source", None),
    ("synapse.route-operation-bound", "synapse", "portfolio", None),
    ("synapse.existing-feedback-path", "synapse", "portfolio", None),
    ("synapse.non-success-not-promoted", "synapse", "source", None),
    ("synapse.provenance-chain", "synapse", "portfolio", None),
    ("reuse.fresh-observation-new-grant", "reuse", "source", None),
    ("reuse.unknown-failure-blocked", "reuse", "source", None),
    ("reuse.version-environment-invalidates", "reuse", "source", None),
    ("reuse.no-hidden-replanning-claim", "reuse", "source", None),
    ("coordination.owner-lease-pinned", "coordination", "portfolio", None),
    ("coordination.single-primary", "coordination", "portfolio", None),
    ("coordination.neighbor-blast-radius", "coordination", "source", None),
    ("coordination.foreign-envelope-rejected", "coordination", "source", None),
    ("coordination.reconcile-not-replay", "coordination", "source", None),
    ("adversarial.forged-grant", "adversarial", "source", None),
    ("adversarial.changed-envelope", "adversarial", "source", None),
    ("adversarial.adapter-substitution", "adversarial", "source", None),
    ("adversarial.binding-substitution", "adversarial", "source", None),
    ("adversarial.permit-replay", "adversarial", "source", None),
    ("adversarial.stale-checkpoint", "adversarial", "source", None),
    ("adversarial.changed-receipt", "adversarial", "source", None),
    ("adversarial.wrong-target", "adversarial", "source", None),
    ("adversarial.timeout-output-flood", "adversarial", "source", None),
    ("adversarial.witness-disagreement", "adversarial", "source", None),
    ("adversarial.home-write-network-production", "adversarial", "source", None),
    ("portability.closed-outcome-semantics", "portability", "source", None),
    ("portability.no-project-hardcode", "portability", "source", None),
    ("portability.unknown-platform-fail-closed", "portability", "source", None),
    ("operations.no-public-listener", "operations", "source", None),
    ("operations.machine-readable-capabilities", "operations", "source", None),
    ("operations.content-free-audit", "operations", "source", None),
    ("statistics.metrics-schema", "statistics", "source", None),
    ("statistics.replay-retry-counters", "statistics", "source", None),
    # Exact-target evidence.  One adapter can satisfy these without pretending
    # that it has proven an operating-system or ecosystem portfolio.
    ("containment.os-sandbox", "containment", "target", None),
    ("witness.real-target-transition", "witness", "target", None),
    ("result.controlled-transition-attribution", "result", "target", None),
    ("operations.fresh-process-recovery", "operations", "target", None),
    # Portfolio evidence aggregates target receipts and operational history.
    # It is deliberately not required for target-local activation.
    ("memory.canonical-append-data-plane", "memory", "portfolio", None),
    ("synapse.feedback-data-plane", "synapse", "portfolio", None),
    ("reuse.no-model-replan-measured", "reuse", "portfolio", None),
    ("coordination.cross-machine", "coordination", "portfolio", None),
    ("portability.windows", "portability", "portfolio", None),
    ("portability.macos", "portability", "portfolio", None),
    ("operations.reboot-upgrade-migration", "operations", "portfolio", None),
    ("operations.key-rotation-revoke", "operations", "portfolio", None),
    ("statistics.real-task-cohort", "statistics", "portfolio", None),
    ("statistics.token-call-time-reduction", "statistics", "portfolio", None),
)

_TYPED_RECEIPT_PROOF_IDS = frozenset(
    {
        "coordination.owner-lease-pinned",
        "coordination.single-primary",
        "coordination.cross-machine",
        "memory.canonical-append-data-plane",
        "synapse.existing-feedback-path",
        "synapse.feedback-data-plane",
        "synapse.provenance-chain",
        "synapse.route-operation-bound",
    }
)


class AdapterConformanceError(AdapterSdkError):
    """Raised before incomplete proof coverage can become adapter readiness."""


def _freeze(value: Mapping[str, Any]) -> dict[str, Any]:
    try:
        candidate = parse_json_strict(canonical_bytes(dict(value)))
    except Exception as exc:
        raise AdapterConformanceError("ASDK conformance document rejected") from exc
    if not isinstance(candidate, dict):
        raise AdapterConformanceError("ASDK conformance document rejected")
    return candidate


def _identity(document: Mapping[str, Any], *, field: str, prefix: str, domain: str) -> str:
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
        raise AdapterConformanceError(f"ASDK {schema} schema rejected") from exc
    if candidate[field] != _identity(
        candidate,
        field=field,
        prefix=prefix,
        domain=domain,
    ):
        raise AdapterConformanceError(f"ASDK {schema} identity mismatch")
    if (
        candidate["signer_id"] != trusted_key.key_id
        or candidate["signature"]["key_id"] != trusted_key.key_id
        or not verify_signature(candidate, trusted_key.public_key)
    ):
        raise AdapterConformanceError(f"ASDK {schema} signature rejected")
    return candidate


def adapter_proof_profile_digest(profile: Mapping[str, Any]) -> str:
    return digest_object(dict(profile), domain="adapter-proof-profile-v1")


def adapter_conformance_evidence_digest(evidence: Mapping[str, Any]) -> str:
    return digest_object(dict(evidence), domain="adapter-conformance-evidence-v1")


def adapter_conformance_receipt_digest(receipt: Mapping[str, Any]) -> str:
    return digest_object(dict(receipt), domain="adapter-conformance-receipt-v1")


def _manifest_reference(manifest: Mapping[str, Any]) -> dict[str, str]:
    return {
        "manifest_id": str(manifest["manifest_id"]),
        "manifest_digest": adapter_capability_manifest_digest(manifest),
        "adapter_id": str(manifest["adapter_id"]),
        "adapter_artifact_digest": str(manifest["adapter_artifact_digest"]),
    }


def _requirements(manifest: Mapping[str, Any]) -> list[dict[str, str]]:
    channels = manifest["declared_channels"]
    result: list[dict[str, str]] = []
    for proof_id, category, tier, channel in _PROOF_DEFINITIONS:
        applicable = channel is None or channels[channel] is True
        result.append(
            {
                "proof_id": proof_id,
                "category": category,
                "tier": tier,
                "applicability": "required" if applicable else "not-applicable",
                "reason_code": (
                    "universal-contract"
                    if channel is None
                    else "declared-channel"
                    if applicable
                    else "channel-not-declared"
                ),
            }
        )
    return result


def build_adapter_proof_profile(
    *,
    manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    created_at: str,
    signer: Ed25519Signer,
) -> dict[str, Any]:
    verified_manifest = verify_adapter_capability_manifest(manifest, adapter_key=adapter_key)
    core = {
        "protocol": "integrity-guardian/adapter-proof-profile/v1",
        "sdk_version": ADAPTER_SDK_VERSION,
        "contract_version": ASDK_PROOF_CONTRACT_VERSION,
        "manifest": _manifest_reference(verified_manifest),
        "requirements": _requirements(verified_manifest),
        "controls": {
            "capability_is_authority": False,
            "home_input_allowed": False,
            "unknown_is_success": False,
            "automatic_retry_after_unknown": False,
            "direct_adapter_call_allowed": False,
            "production_authority": False,
        },
        "created_at": created_at,
        "signer_id": signer.key_id,
    }
    unsigned = {
        "profile_id": _identity(
            core,
            field="profile_id",
            prefix="adapter-proof-profile:",
            domain="adapter-proof-profile-identity-v1",
        ),
        **core,
    }
    signed = signer.sign(unsigned)
    validate("adapter-proof-profile", signed)
    return signed


def verify_adapter_proof_profile(
    profile: Mapping[str, Any],
    *,
    manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    profile_key: TrustedKey,
) -> dict[str, Any]:
    candidate = _verify_signed(
        profile,
        schema="adapter-proof-profile",
        field="profile_id",
        prefix="adapter-proof-profile:",
        domain="adapter-proof-profile-identity-v1",
        trusted_key=profile_key,
    )
    verified_manifest = verify_adapter_capability_manifest(manifest, adapter_key=adapter_key)
    if candidate["manifest"] != _manifest_reference(verified_manifest) or candidate[
        "requirements"
    ] != _requirements(verified_manifest):
        raise AdapterConformanceError("ASDK proof profile manifest or requirements mismatch")
    ids = [item["proof_id"] for item in candidate["requirements"]]
    if len(set(ids)) != len(ids):
        raise AdapterConformanceError("ASDK proof profile duplicate requirement")
    return candidate


def build_adapter_conformance_evidence(
    *,
    profile: Mapping[str, Any],
    profile_key: TrustedKey,
    manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    suite_id: str,
    scope: str,
    artifact_digest: str,
    environment_digest: str,
    command_digest: str,
    proof_ids: Sequence[str],
    test_count: int,
    created_at: str,
    signer: Ed25519Signer,
    target: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    verified_profile = verify_adapter_proof_profile(
        profile,
        manifest=manifest,
        adapter_key=adapter_key,
        profile_key=profile_key,
    )
    if artifact_digest != verified_profile["manifest"]["adapter_artifact_digest"]:
        raise AdapterConformanceError("ASDK conformance artifact digest mismatch")
    requirements = {item["proof_id"]: item for item in verified_profile["requirements"]}
    normalized = sorted(set(proof_ids))
    if len(normalized) != len(proof_ids) or not normalized:
        raise AdapterConformanceError("ASDK conformance evidence proof set rejected")
    if _TYPED_RECEIPT_PROOF_IDS.intersection(normalized):
        raise AdapterConformanceError(
            "ASDK protected proof requires typed receipt evidence"
        )
    tiers: set[str] = set()
    for proof_id in normalized:
        requirement = requirements.get(proof_id)
        if requirement is None or requirement["applicability"] != "required":
            raise AdapterConformanceError("ASDK conformance evidence proof is not applicable")
        tiers.add(requirement["tier"])
    if "source" in tiers and len(tiers) != 1:
        raise AdapterConformanceError("ASDK source and target evidence must be separated")
    if "target" in tiers and "portfolio" in tiers:
        raise AdapterConformanceError("ASDK target and portfolio evidence must be separated")
    target_document = None if target is None else _freeze(target)
    if tiers == {"target"}:
        if scope != "target-live-non-production" or target_document is None:
            raise AdapterConformanceError("ASDK target proof requires exact target evidence")
    elif tiers == {"portfolio"}:
        if scope != "portfolio-live-non-production" or target_document is not None:
            raise AdapterConformanceError("ASDK portfolio proof requires portfolio evidence")
    elif target_document is not None:
        raise AdapterConformanceError("ASDK source evidence cannot claim a live target")
    if target_document is not None:
        expected = {
            "target_id",
            "target_kind",
            "target_zone_id",
            "environment_digest",
            "non_production",
        }
        if (
            set(target_document) != expected
            or target_document["environment_digest"] != environment_digest
            or target_document["non_production"] is not True
        ):
            raise AdapterConformanceError("ASDK conformance target rejected")
    core = {
        "protocol": "integrity-guardian/adapter-conformance-evidence/v1",
        "sdk_version": ADAPTER_SDK_VERSION,
        "profile": {
            "profile_id": verified_profile["profile_id"],
            "profile_digest": adapter_proof_profile_digest(verified_profile),
        },
        "suite_id": suite_id,
        "scope": scope,
        "artifact_digest": artifact_digest,
        "environment_digest": environment_digest,
        "command_digest": command_digest,
        "target": target_document,
        "proof_ids": normalized,
        "test_count": test_count,
        "status": "PASS",
        "content_free": True,
        "created_at": created_at,
        "signer_id": signer.key_id,
    }
    unsigned = {
        "evidence_id": _identity(
            core,
            field="evidence_id",
            prefix="adapter-conformance-evidence:",
            domain="adapter-conformance-evidence-identity-v1",
        ),
        **core,
    }
    signed = signer.sign(unsigned)
    validate("adapter-conformance-evidence", signed)
    return signed


def verify_adapter_conformance_evidence(
    evidence: Mapping[str, Any],
    *,
    profile: Mapping[str, Any],
    evidence_key: TrustedKey,
) -> dict[str, Any]:
    candidate = _verify_signed(
        evidence,
        schema="adapter-conformance-evidence",
        field="evidence_id",
        prefix="adapter-conformance-evidence:",
        domain="adapter-conformance-evidence-identity-v1",
        trusted_key=evidence_key,
    )
    if candidate["profile"] != {
        "profile_id": profile["profile_id"],
        "profile_digest": adapter_proof_profile_digest(profile),
    }:
        raise AdapterConformanceError("ASDK conformance evidence profile mismatch")
    if candidate["artifact_digest"] != profile["manifest"]["adapter_artifact_digest"]:
        raise AdapterConformanceError("ASDK conformance evidence artifact mismatch")
    requirements = {item["proof_id"]: item for item in profile["requirements"]}
    for proof_id in candidate["proof_ids"]:
        requirement = requirements.get(proof_id)
        if requirement is None or requirement["applicability"] != "required":
            raise AdapterConformanceError("ASDK conformance evidence coverage rejected")
        if proof_id in _TYPED_RECEIPT_PROOF_IDS:
            raise AdapterConformanceError(
                "ASDK protected proof generic evidence rejected"
            )
        tier = requirement["tier"]
        if tier == "target" and (
            candidate["scope"] != "target-live-non-production" or candidate["target"] is None
        ):
            raise AdapterConformanceError("ASDK conformance target evidence scope rejected")
        if tier == "portfolio" and (
            candidate["scope"] != "portfolio-live-non-production" or candidate["target"] is not None
        ):
            raise AdapterConformanceError("ASDK conformance portfolio evidence scope rejected")
    target = candidate["target"]
    if target is not None and (
        target["environment_digest"] != candidate["environment_digest"]
        or target["non_production"] is not True
    ):
        raise AdapterConformanceError("ASDK conformance target binding rejected")
    return candidate


def _coverage(
    profile: Mapping[str, Any],
    evidence_documents: Sequence[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any] | None, dict[str, Any]]:
    providers: dict[str, dict[str, Any]] = {}
    for evidence in evidence_documents:
        for proof_id in evidence["proof_ids"]:
            existing = providers.get(proof_id)
            if existing is not None and existing["evidence_id"] != evidence["evidence_id"]:
                raise AdapterConformanceError("ASDK proof has ambiguous evidence providers")
            providers[proof_id] = dict(evidence)
    coverage: list[dict[str, Any]] = []
    for requirement in profile["requirements"]:
        proof_id = requirement["proof_id"]
        provider = providers.get(proof_id)
        if requirement["applicability"] == "not-applicable":
            status = "not-applicable"
            evidence_id = None
        elif proof_id in _TYPED_RECEIPT_PROOF_IDS:
            status = "external-required"
            evidence_id = None
        elif provider is not None:
            status = "verified"
            evidence_id = provider["evidence_id"]
        elif requirement["tier"] in {"target", "portfolio"}:
            status = "external-required"
            evidence_id = None
        else:
            status = "missing"
            evidence_id = None
        coverage.append(
            {
                "proof_id": proof_id,
                "tier": requirement["tier"],
                "status": status,
                "evidence_id": evidence_id,
            }
        )
    counts = {
        status: sum(item["status"] == status for item in coverage)
        for status in ("verified", "external-required", "not-applicable", "missing")
    }
    source_ok = all(
        item["status"] in {"verified", "not-applicable"}
        for item in coverage
        if item["tier"] == "source"
    )
    target_ok = source_ok and all(
        item["status"] in {"verified", "not-applicable"}
        for item in coverage
        if item["tier"] == "target"
    )
    target_documents = [item["target"] for item in evidence_documents if item["target"]]
    target = deepcopy(target_documents[0]) if target_documents else None
    if any(item != target for item in target_documents):
        raise AdapterConformanceError("ASDK target evidence identities disagree")
    target_ok = target_ok and target is not None
    portfolio_ok = target_ok and all(
        item["status"] in {"verified", "not-applicable"}
        for item in coverage
        if item["tier"] == "portfolio"
    )
    readiness = (
        "portfolio-ready"
        if portfolio_ok
        else "target-live-ready"
        if target_ok
        else "source-ready"
        if source_ok
        else "rejected"
    )
    result = {
        "readiness": readiness,
        "verified_count": counts["verified"],
        "external_required_count": counts["external-required"],
        "not_applicable_count": counts["not-applicable"],
        "missing_count": counts["missing"],
        "all_source_requirements_verified": source_ok,
        "all_target_requirements_verified": target_ok,
        "all_portfolio_requirements_verified": portfolio_ok,
    }
    return coverage, target, result


def _verify_evidence_set(
    evidence_documents: Sequence[Mapping[str, Any]],
    *,
    profile: Mapping[str, Any],
    evidence_keys: Mapping[str, TrustedKey],
) -> list[dict[str, Any]]:
    verified: list[dict[str, Any]] = []
    identities: set[str] = set()
    for document in evidence_documents:
        key_id = document.get("signer_id")
        key = evidence_keys.get(str(key_id))
        if key is None:
            raise AdapterConformanceError("ASDK conformance evidence signer is untrusted")
        candidate = verify_adapter_conformance_evidence(
            document,
            profile=profile,
            evidence_key=key,
        )
        if candidate["evidence_id"] in identities:
            raise AdapterConformanceError("ASDK conformance duplicate evidence")
        identities.add(candidate["evidence_id"])
        verified.append(candidate)
    return verified


def build_adapter_conformance_receipt(
    *,
    profile: Mapping[str, Any],
    profile_key: TrustedKey,
    manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    evidence_documents: Sequence[Mapping[str, Any]],
    evidence_keys: Mapping[str, TrustedKey],
    created_at: str,
    signer: Ed25519Signer,
) -> dict[str, Any]:
    verified_profile = verify_adapter_proof_profile(
        profile,
        manifest=manifest,
        adapter_key=adapter_key,
        profile_key=profile_key,
    )
    evidence = _verify_evidence_set(
        evidence_documents,
        profile=verified_profile,
        evidence_keys=evidence_keys,
    )
    coverage, target, result = _coverage(verified_profile, evidence)
    core = {
        "protocol": "integrity-guardian/adapter-conformance-receipt/v1",
        "sdk_version": ADAPTER_SDK_VERSION,
        "profile": {
            "profile_id": verified_profile["profile_id"],
            "profile_digest": adapter_proof_profile_digest(verified_profile),
            "adapter_id": verified_profile["manifest"]["adapter_id"],
            "adapter_artifact_digest": verified_profile["manifest"]["adapter_artifact_digest"],
        },
        "evidence": [
            {
                "evidence_id": item["evidence_id"],
                "evidence_digest": adapter_conformance_evidence_digest(item),
                "scope": item["scope"],
                "test_count": item["test_count"],
            }
            for item in evidence
        ],
        "coverage": coverage,
        "target": target,
        "result": result,
        "authority_boundary": {
            "capability_is_authority": False,
            "conformance_is_execution_authority": False,
            "issues_grants": False,
            "memory_write": False,
            "production_authority": False,
        },
        "created_at": created_at,
        "signer_id": signer.key_id,
    }
    unsigned = {
        "receipt_id": _identity(
            core,
            field="receipt_id",
            prefix="adapter-conformance-receipt:",
            domain="adapter-conformance-receipt-identity-v1",
        ),
        **core,
    }
    signed = signer.sign(unsigned)
    validate("adapter-conformance-receipt", signed)
    return signed


def verify_adapter_conformance_receipt(
    receipt: Mapping[str, Any],
    *,
    profile: Mapping[str, Any],
    profile_key: TrustedKey,
    manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    evidence_documents: Sequence[Mapping[str, Any]],
    evidence_keys: Mapping[str, TrustedKey],
    receipt_key: TrustedKey,
) -> dict[str, Any]:
    candidate = _verify_signed(
        receipt,
        schema="adapter-conformance-receipt",
        field="receipt_id",
        prefix="adapter-conformance-receipt:",
        domain="adapter-conformance-receipt-identity-v1",
        trusted_key=receipt_key,
    )
    verified_profile = verify_adapter_proof_profile(
        profile,
        manifest=manifest,
        adapter_key=adapter_key,
        profile_key=profile_key,
    )
    evidence = _verify_evidence_set(
        evidence_documents,
        profile=verified_profile,
        evidence_keys=evidence_keys,
    )
    expected_coverage, expected_target, expected_result = _coverage(
        verified_profile,
        evidence,
    )
    expected_refs = [
        {
            "evidence_id": item["evidence_id"],
            "evidence_digest": adapter_conformance_evidence_digest(item),
            "scope": item["scope"],
            "test_count": item["test_count"],
        }
        for item in evidence
    ]
    expected_profile = {
        "profile_id": verified_profile["profile_id"],
        "profile_digest": adapter_proof_profile_digest(verified_profile),
        "adapter_id": verified_profile["manifest"]["adapter_id"],
        "adapter_artifact_digest": verified_profile["manifest"]["adapter_artifact_digest"],
    }
    if (
        candidate["profile"] != expected_profile
        or candidate["evidence"] != expected_refs
        or candidate["coverage"] != expected_coverage
        or candidate["target"] != expected_target
        or candidate["result"] != expected_result
    ):
        raise AdapterConformanceError("ASDK conformance receipt coverage mismatch")
    return candidate


def require_adapter_conformance_readiness(
    receipt: Mapping[str, Any],
    *,
    minimum: str,
) -> None:
    readiness = receipt["result"]["readiness"]
    allowed = {
        "source-ready": {"source-ready", "target-live-ready", "portfolio-ready"},
        "target-live-ready": {"target-live-ready", "portfolio-ready"},
        "portfolio-ready": {"portfolio-ready"},
    }
    if minimum not in allowed or readiness not in allowed[minimum]:
        raise AdapterConformanceError("ASDK adapter readiness requirement is not satisfied")


__all__ = [
    "ASDK_PROOF_CONTRACT_VERSION",
    "AdapterConformanceError",
    "adapter_conformance_evidence_digest",
    "adapter_conformance_receipt_digest",
    "adapter_proof_profile_digest",
    "build_adapter_conformance_evidence",
    "build_adapter_conformance_receipt",
    "build_adapter_proof_profile",
    "require_adapter_conformance_readiness",
    "verify_adapter_conformance_evidence",
    "verify_adapter_conformance_receipt",
    "verify_adapter_proof_profile",
]
