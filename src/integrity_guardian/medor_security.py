"""Operational non-production Security Harness admission for Medor/client."""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from .hashing import digest_object
from .schemas import validate
from .signing import (
    Ed25519Signer,
    TrustedKey,
    public_key_fingerprint,
    trusted_key_from_value,
    verify_signature,
)


class MedorSecurityError(ValueError):
    """Raised unless the complete operational, non-authorizing chain verifies."""


_VERIFIED_ADMISSION_SEAL = object()


@dataclass(frozen=True, init=False)
class VerifiedMedorSecurityAdmission:
    admission_id: str
    artifact_digest: str
    decision_receipt_id: str
    decision: str
    expires_at: str
    production_authority: bool = False
    authority_key_fingerprint: str = ""
    _verification_seal: object = field(repr=False, compare=False)

    def __init__(
        self,
        *,
        admission_id: str,
        artifact_digest: str,
        decision_receipt_id: str,
        decision: str,
        expires_at: str,
        authority_key_fingerprint: str,
        _verification_seal: object,
    ) -> None:
        if _verification_seal is not _VERIFIED_ADMISSION_SEAL:
            raise MedorSecurityError(
                "Medor security admission must come from external-key or native "
                "registered verification path"
            )
        object.__setattr__(self, "admission_id", admission_id)
        object.__setattr__(self, "artifact_digest", artifact_digest)
        object.__setattr__(self, "decision_receipt_id", decision_receipt_id)
        object.__setattr__(self, "decision", decision)
        object.__setattr__(self, "expires_at", expires_at)
        object.__setattr__(self, "production_authority", False)
        object.__setattr__(self, "authority_key_fingerprint", authority_key_fingerprint)
        object.__setattr__(self, "_verification_seal", _verification_seal)


def require_verified_medor_security_admission(
    admission: object,
) -> VerifiedMedorSecurityAdmission:
    if (
        not isinstance(admission, VerifiedMedorSecurityAdmission)
        or admission._verification_seal is not _VERIFIED_ADMISSION_SEAL
    ):
        raise MedorSecurityError("verified Medor Security admission is required")
    return admission


def build_native_medor_security_admission(
    *,
    instance_id: str,
    artifact_digest: str,
    issued_at: str,
    expires_at: str,
    security_signer: Ed25519Signer,
) -> dict[str, Any]:
    """Create a local, artifact-bound memory admission for personal-native mode.

    This document deliberately makes no assessment or production-readiness
    claim.  It admits only the canonical memory read/append surface under the
    instance's already established native root.
    """

    if not _time(issued_at, "native issue time") < _time(expires_at, "native expiry"):
        raise MedorSecurityError("native security admission window is invalid")
    core = {
        "protocol": "integrity-guardian/native-security-admission/v2",
        "instance_id": instance_id,
        "artifact_digest": artifact_digest,
        "profile": "personal-native",
        "scopes": ["canonical-memory-read", "single-canonical-seed-append"],
        "authority_boundary": {
            "credentials": False,
            "generic_execution": False,
            "external_systems": False,
            "production": False,
            "winops": False,
        },
        "issued_at": issued_at,
        "expires_at": expires_at,
        "issuer_key_fingerprint": public_key_fingerprint(security_signer.public_key),
    }
    unsigned = {
        **core,
        "admission_id": digest_object(core, domain="native-security-admission-v2"),
    }
    document = security_signer.sign(unsigned)
    validate("native-security-admission", document)
    return document


def verify_native_medor_security_admission(
    document: Mapping[str, Any],
    *,
    expected_instance_id: str,
    expected_artifact_digest: str,
    at_time: str,
    security_key: TrustedKey,
) -> VerifiedMedorSecurityAdmission:
    """Verify native instance policy without converting it to production trust."""

    candidate = deepcopy(dict(document))
    validate("native-security-admission", candidate)
    core = deepcopy(candidate)
    core.pop("signature")
    admission_id = core.pop("admission_id")
    if (
        candidate["instance_id"] != expected_instance_id
        or candidate["artifact_digest"] != expected_artifact_digest
        or admission_id != digest_object(core, domain="native-security-admission-v2")
        or candidate["signature"]["key_id"] != security_key.key_id
        or candidate["issuer_key_fingerprint"] != public_key_fingerprint(security_key.public_key)
        or not verify_signature(candidate, security_key.public_key)
        or any(candidate["authority_boundary"].values())
    ):
        raise MedorSecurityError("native security admission verification failed")
    current = _time(at_time, "native evaluation time")
    if (
        not _time(candidate["issued_at"], "native issue time")
        <= current
        < _time(candidate["expires_at"], "native expiry")
    ):
        raise MedorSecurityError("native security admission is not active")
    return VerifiedMedorSecurityAdmission(
        admission_id=admission_id,
        artifact_digest=expected_artifact_digest,
        decision_receipt_id=admission_id,
        decision="native-local-eligible",
        expires_at=candidate["expires_at"],
        authority_key_fingerprint=public_key_fingerprint(security_key.public_key),
        _verification_seal=_VERIFIED_ADMISSION_SEAL,
    )


def _time(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise MedorSecurityError(f"security {field} is invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise MedorSecurityError(f"security {field} is invalid") from exc
    if parsed.tzinfo is None:
        raise MedorSecurityError(f"security {field} is invalid")
    return parsed


def _receipt(core: Mapping[str, Any], *, domain: str) -> dict[str, Any]:
    value = deepcopy(dict(core))
    return {**value, "receipt_id": digest_object(value, domain=domain)}


def build_medor_security_bundle(
    *,
    artifact_digest: str,
    environment_fingerprint_digest: str,
    source_revision: str,
    source_tree_digest: str,
    dependency_lock_digest: str,
    build_digest: str,
    assessment_evidence_digest: str,
    containment_evidence_digest: str,
    threat_model_digest: str,
    created_at: str,
    decision_expires_at: str,
    evidence_expires_at: str,
    examined_count: int,
    tool_calls: int,
    elapsed_ms: int,
    decision_signer: Ed25519Signer,
) -> dict[str, Any]:
    """Build one exact-artifact operational RC admission.

    The caller-owned signer is an external policy authority. Its public key
    must be configured independently by every verifier; the bundle never
    carries or selects its own trust root. This admits only the client
    forced-stdio candidate and never grants action or production authority.
    """

    if (
        not _time(created_at, "creation")
        < _time(decision_expires_at, "decision expiry")
        <= _time(evidence_expires_at, "evidence expiry")
    ):
        raise MedorSecurityError("security evidence window is invalid")
    if (
        isinstance(examined_count, bool)
        or examined_count < 1
        or isinstance(tool_calls, bool)
        or tool_calls < 0
        or isinstance(elapsed_ms, bool)
        or elapsed_ms < 0
    ):
        raise MedorSecurityError("security evidence counters are invalid")
    subject = {
        "tenant_id": "tenant:public-b9d53e60dea942e6",
        "product_id": "product:integrity-guardian-medor-lts",
        "artifact_id": "artifact:medor-memory-synapse-lts",
        "artifact_digest": artifact_digest,
    }
    environment = {
        "profile_id": "environment:local-client-forced-stdio",
        "fingerprint_digest": environment_fingerprint_digest,
        "consumer": "client-workstation",
        "transport": "openssh-forced-command-stdio",
        "listener": False,
        "winops_authorized": False,
    }
    policy = {
        "policy_id": "policy:medor-memory-synapse-lts-operational-rc",
        "requested_channel": "rc",
        "requirements": {
            "reproducible_provenance": True,
            "assessment_mode": "diff",
            "complete_coverage": True,
            "validated_findings": True,
            "max_unresolved": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
            },
            "containment_required": True,
            "containment_assurance": "protected",
            "genesis_rehearsal_required": True,
        },
    }
    provenance = _receipt(
        {
            "source_revision": source_revision,
            "source_tree_digest": source_tree_digest,
            "dependency_lock_digest": dependency_lock_digest,
            "build_digest": build_digest,
            "artifact_digest": artifact_digest,
            "state": "exact",
            "reproducible": True,
            "artifact_count": 1,
            "created_at": created_at,
            "expires_at": evidence_expires_at,
        },
        domain="medor-operational-provenance-v1",
    )
    assessment = _receipt(
        {
            "mode": "diff",
            "evidence_digest": assessment_evidence_digest,
            "threat_model_digest": threat_model_digest,
            "coverage_state": "complete",
            "examined_count": examined_count,
            "omitted_count": 0,
            "total_findings": 0,
            "unresolved": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
            },
            "validation_state": "validated-complete",
            "tool_calls": tool_calls,
            "model_calls": 0,
            "elapsed_ms": elapsed_ms,
            "created_at": created_at,
            "expires_at": evidence_expires_at,
        },
        domain="medor-operational-assessment-v1",
    )
    containment = _receipt(
        {
            "evidence_digest": containment_evidence_digest,
            "assurance_class": "protected",
            "environment_supported": True,
            "ready_before_untrusted_work": True,
            "policy_frozen": True,
            "controls": {
                "egress": "loopback-and-forced-stdio-only",
                "privilege": "two-exact-local-helpers-only",
                "filesystem": "fixed-server-paths-no-client-selection",
                "secrets": "separate-private-server-custody",
            },
            "genesis_rehearsal": "passed-isolated-synthetic-envelope",
            "post_run_drift": "none",
            "production_targets": False,
            "created_at": created_at,
            "expires_at": evidence_expires_at,
        },
        domain="medor-operational-containment-v1",
    )
    authority_boundary = {
        "execution": False,
        "production": False,
        "route": False,
        "credentials": False,
        "winops": False,
        "external_systems": False,
    }
    decision_core = {
        "decision": "rc-eligible",
        "reasons": [],
        "subject_artifact_digest": artifact_digest,
        "environment_fingerprint_digest": environment_fingerprint_digest,
        "inputs": {
            "provenance": provenance["receipt_id"],
            "assessment": assessment["receipt_id"],
            "containment": containment["receipt_id"],
        },
        "authority_boundary": authority_boundary,
        "evaluated_at": created_at,
        "expires_at": decision_expires_at,
    }
    decision_unsigned = {
        **decision_core,
        "receipt_id": digest_object(decision_core, domain="medor-operational-security-decision-v1"),
    }
    decision = decision_signer.sign(decision_unsigned)
    core = {
        "protocol": "integrity-guardian/medor-security-admission-bundle/v2",
        "subject": subject,
        "environment": environment,
        "policy": policy,
        "evidence": {
            "provenance": provenance,
            "assessment": assessment,
            "containment": containment,
        },
        "decision": decision,
        "trust": {
            "anchor": "configured-trusted-key",
            "key_id": decision_signer.key_id,
            "public_key_fingerprint": public_key_fingerprint(decision_signer.public_key),
        },
    }
    bundle = {
        **core,
        "bundle_id": digest_object(core, domain="medor-operational-security-bundle-v2"),
    }
    validate("medor-security-admission-bundle", bundle)
    return bundle


def _verify_receipt(value: Mapping[str, Any], *, domain: str) -> str:
    core = deepcopy(dict(value))
    receipt_id = core.pop("receipt_id", None)
    if receipt_id != digest_object(core, domain=domain):
        raise MedorSecurityError("security evidence receipt identity mismatch")
    return str(receipt_id)


def verify_medor_security_bundle(
    bundle: Mapping[str, Any],
    *,
    expected_artifact_digest: str,
    at_time: str,
    decision_key: TrustedKey,
) -> VerifiedMedorSecurityAdmission:
    candidate = deepcopy(dict(bundle))
    validate("medor-security-admission-bundle", candidate)
    core = deepcopy(candidate)
    bundle_id = core.pop("bundle_id")
    if bundle_id != digest_object(core, domain="medor-operational-security-bundle-v2"):
        raise MedorSecurityError("security bundle identity mismatch")
    if candidate["subject"]["artifact_digest"] != expected_artifact_digest:
        raise MedorSecurityError("security bundle belongs to another artifact")
    evidence = candidate["evidence"]
    receipt_ids = {
        "provenance": _verify_receipt(
            evidence["provenance"], domain="medor-operational-provenance-v1"
        ),
        "assessment": _verify_receipt(
            evidence["assessment"], domain="medor-operational-assessment-v1"
        ),
        "containment": _verify_receipt(
            evidence["containment"], domain="medor-operational-containment-v1"
        ),
    }
    provenance = evidence["provenance"]
    assessment = evidence["assessment"]
    containment = evidence["containment"]
    if (
        provenance["artifact_digest"] != expected_artifact_digest
        or provenance["state"] != "exact"
        or provenance["reproducible"] is not True
        or provenance["artifact_count"] != 1
        or assessment["mode"] != "diff"
        or assessment["coverage_state"] != "complete"
        or assessment["omitted_count"] != 0
        or assessment["total_findings"] != 0
        or any(assessment["unresolved"].values())
        or assessment["validation_state"] != "validated-complete"
        or containment["assurance_class"] != "protected"
        or containment["environment_supported"] is not True
        or containment["ready_before_untrusted_work"] is not True
        or containment["policy_frozen"] is not True
        or containment["genesis_rehearsal"] != "passed-isolated-synthetic-envelope"
        or containment["production_targets"] is not False
        or containment["post_run_drift"] != "none"
    ):
        raise MedorSecurityError("security evidence does not satisfy the policy")
    decision = candidate["decision"]
    unsigned = deepcopy(decision)
    signature = unsigned.pop("signature")
    receipt_id = unsigned.pop("receipt_id")
    if receipt_id != digest_object(unsigned, domain="medor-operational-security-decision-v1"):
        raise MedorSecurityError("security decision identity mismatch")
    trust = candidate["trust"]
    if (
        trust["anchor"] != "configured-trusted-key"
        or trust["key_id"] != decision_key.key_id
        or signature["key_id"] != decision_key.key_id
        or trust["public_key_fingerprint"] != public_key_fingerprint(decision_key.public_key)
        or not verify_signature(decision, decision_key.public_key)
        or decision["inputs"] != receipt_ids
        or decision["decision"] != "rc-eligible"
        or decision["reasons"]
        or any(decision["authority_boundary"].values())
    ):
        raise MedorSecurityError("security decision signature or boundary is invalid")
    current = _time(at_time, "evaluation time")
    if (
        not _time(decision["evaluated_at"], "decision start")
        <= current
        < _time(decision["expires_at"], "decision expiry")
    ):
        raise MedorSecurityError("security admission is not currently active")
    if any(
        not _time(value["created_at"], "evidence start")
        <= current
        < _time(value["expires_at"], "evidence expiry")
        for value in evidence.values()
    ):
        raise MedorSecurityError("security evidence is not currently active")
    admission_id = digest_object(
        {
            "bundle_id": bundle_id,
            "decision_receipt_id": receipt_id,
            "artifact_digest": expected_artifact_digest,
        },
        domain="medor-operational-security-admission-v2",
    )
    return VerifiedMedorSecurityAdmission(
        admission_id=admission_id,
        artifact_digest=expected_artifact_digest,
        decision_receipt_id=receipt_id,
        decision=decision["decision"],
        expires_at=decision["expires_at"],
        authority_key_fingerprint=public_key_fingerprint(decision_key.public_key),
        _verification_seal=_VERIFIED_ADMISSION_SEAL,
    )


def load_medor_security_bundle(
    path: Path,
    *,
    expected_artifact_digest: str,
    at_time: str,
    decision_key: TrustedKey,
) -> VerifiedMedorSecurityAdmission:
    if not path.is_absolute() or path.is_symlink():
        raise MedorSecurityError("security bundle path is unsafe")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise MedorSecurityError("security bundle is unavailable") from exc
    try:
        details = os.fstat(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != 0
            or details.st_size > 4 * 1024 * 1024
            or stat.S_IMODE(details.st_mode) & 0o022
        ):
            raise MedorSecurityError("security bundle custody is unsafe")
        raw = bytearray()
        while chunk := os.read(descriptor, 64 * 1024):
            raw.extend(chunk)
            if len(raw) > 4 * 1024 * 1024:
                raise MedorSecurityError("security bundle is unbounded")
    finally:
        os.close(descriptor)
    try:
        value = json.loads(bytes(raw))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MedorSecurityError("security bundle is invalid JSON") from exc
    if not isinstance(value, dict):
        raise MedorSecurityError("security bundle must be an object")
    return verify_medor_security_bundle(
        value,
        expected_artifact_digest=expected_artifact_digest,
        at_time=at_time,
        decision_key=decision_key,
    )


def load_medor_trusted_public_key(path: Path, *, key_id: str) -> TrustedKey:
    """Load one externally configured Ed25519 public key from safe custody."""

    if not path.is_absolute() or path.is_symlink():
        raise MedorSecurityError("trusted public key path is unsafe")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise MedorSecurityError("trusted public key is unavailable") from exc
    try:
        details = os.fstat(descriptor)
        allowed_owners = {0}
        if hasattr(os, "geteuid"):
            allowed_owners.add(os.geteuid())
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid not in allowed_owners
            or details.st_size > 1024
            or stat.S_IMODE(details.st_mode) & 0o022
        ):
            raise MedorSecurityError("trusted public key custody is unsafe")
        raw = os.read(descriptor, 1025)
        if len(raw) > 1024:
            raise MedorSecurityError("trusted public key is unbounded")
    finally:
        os.close(descriptor)
    try:
        value = raw.decode("ascii").strip()
        return trusted_key_from_value(key_id, value)
    except (UnicodeDecodeError, ValueError) as exc:
        raise MedorSecurityError("trusted public key is invalid") from exc
