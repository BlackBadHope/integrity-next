"""Project-wide signed security-admission receipts.

This module verifies bounded claims produced by external harnesses. It cannot
run a scanner, launch a sandbox, patch an artifact, promote a release or obtain
production authority.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from pathlib import PurePosixPath
from typing import Any

from jsonschema import ValidationError

from .canonical import canonical_bytes
from .hashing import digest_object
from .schemas import validate
from .signing import Ed25519Signer, TrustedKey, verify_bytes

_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_REVISION = re.compile(r"^[a-f0-9]{40}$")
_SEVERITIES = ("critical", "high", "medium", "low")
_ASSESSMENT_MODES = ("path", "diff", "full")
_CONTAINMENT_CLASSES = (
    "protected",
    "audit",
    "degraded",
    "failed",
    "unsupported",
)
_AUTHORITY_BOUNDARY = {
    "execution_authority": False,
    "promotion_authority": False,
    "production_authority": False,
    "remediation_authority": False,
}
_CONTAINMENT_AUTHORITY_BOUNDARY = {
    **_AUTHORITY_BOUNDARY,
    "semantic_channel_authority": False,
}
_PROMOTION_AUTHORITY_BOUNDARY = {
    "release_executed": False,
    "owner_authorization": False,
    "production_authority": False,
    "remediation_authority": False,
}
_SCHEMAS = {
    "artifact-provenance": "artifact-provenance-receipt",
    "security-assessment": "security-assessment-receipt",
    "execution-containment": "execution-containment-receipt",
    "promotion-decision": "promotion-decision-receipt",
}


class SecurityAdmissionError(ValueError):
    """Raised when a project security-admission claim is untrusted."""


def _require_id(value: object, field: str, *, synthetic: bool = True) -> None:
    if (
        not isinstance(value, str)
        or _ID.fullmatch(value) is None
        or (synthetic and "synthetic" not in value)
    ):
        raise SecurityAdmissionError(f"security admission {field} rejected")


def _require_digest(value: object, field: str) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise SecurityAdmissionError(f"security admission {field} rejected")


def _require_revision(value: object, field: str) -> None:
    if not isinstance(value, str) or _REVISION.fullmatch(value) is None:
        raise SecurityAdmissionError(f"security admission {field} rejected")


def _parse_time(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise SecurityAdmissionError(f"security admission {field} rejected")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise SecurityAdmissionError(
            f"security admission {field} rejected"
        ) from exc
    if parsed.tzinfo is None:
        raise SecurityAdmissionError(f"security admission {field} rejected")
    return parsed


def _require_window(created_at: object, expires_at: object) -> None:
    if _parse_time(created_at, "created time") >= _parse_time(
        expires_at,
        "expiry time",
    ):
        raise SecurityAdmissionError(
            "security admission validity window rejected"
        )


def _within_window(
    receipt: Mapping[str, Any],
    evaluated_at: str,
) -> bool:
    current = _parse_time(evaluated_at, "evaluation time")
    return (
        _parse_time(receipt["created_at"], "created time")
        <= current
        <= _parse_time(receipt["expires_at"], "expiry time")
    )


@dataclass(frozen=True)
class SecurityArtifact:
    """Exact synthetic artifact identity shared by every receipt."""

    tenant_id: str
    artifact_id: str
    artifact_digest: str

    def __post_init__(self) -> None:
        if self.tenant_id != "tenant:public-6e3cdbebaafc8efa":
            raise SecurityAdmissionError(
                "security admission synthetic tenant required"
            )
        _require_id(self.artifact_id, "artifact id")
        _require_digest(self.artifact_digest, "artifact digest")


@dataclass(frozen=True)
class SecurityEnvironment:
    """Exact synthetic execution-environment identity."""

    profile_id: str
    fingerprint_digest: str

    def __post_init__(self) -> None:
        _require_id(self.profile_id, "environment profile id")
        _require_digest(
            self.fingerprint_digest,
            "environment fingerprint",
        )


@dataclass(frozen=True)
class SecurityHarness:
    """Immutable external harness identity."""

    harness_id: str
    revision: str
    artifact_digest: str

    def __post_init__(self) -> None:
        _require_id(self.harness_id, "harness id")
        _require_revision(self.revision, "harness revision")
        _require_digest(self.artifact_digest, "harness artifact digest")


def _subject_document(subject: SecurityArtifact) -> dict[str, str]:
    if not isinstance(subject, SecurityArtifact):
        raise SecurityAdmissionError(
            "security admission artifact identity rejected"
        )
    return {
        "artifact_id": subject.artifact_id,
        "artifact_digest": subject.artifact_digest,
    }


def _environment_document(
    environment: SecurityEnvironment,
) -> dict[str, str]:
    if not isinstance(environment, SecurityEnvironment):
        raise SecurityAdmissionError(
            "security admission environment rejected"
        )
    return {
        "profile_id": environment.profile_id,
        "fingerprint_digest": environment.fingerprint_digest,
    }


def _harness_document(harness: SecurityHarness) -> dict[str, str]:
    if not isinstance(harness, SecurityHarness):
        raise SecurityAdmissionError("security admission harness rejected")
    return {
        "harness_id": harness.harness_id,
        "revision": harness.revision,
        "artifact_digest": harness.artifact_digest,
    }


def _receipt_core(receipt: Mapping[str, Any]) -> dict[str, Any]:
    core = deepcopy(dict(receipt))
    core.pop("receipt_id", None)
    core.pop("signature", None)
    return core


def security_receipt_identity(
    receipt: Mapping[str, Any],
    *,
    receipt_kind: str,
) -> str:
    """Return a domain-separated identity for one unsigned receipt claim."""

    if receipt_kind not in _SCHEMAS:
        raise SecurityAdmissionError(
            "security admission receipt kind rejected"
        )
    digest = digest_object(
        _receipt_core(receipt),
        domain=f"{receipt_kind}-receipt-identity-v1",
    )
    return f"{receipt_kind}-receipt:{digest.split(':', 1)[1]}"


def security_receipt_digest(
    receipt: Mapping[str, Any],
    *,
    receipt_kind: str,
) -> str:
    """Return the exact digest of a signed receipt."""

    if receipt_kind not in _SCHEMAS:
        raise SecurityAdmissionError(
            "security admission receipt kind rejected"
        )
    return digest_object(
        dict(receipt),
        domain=f"{receipt_kind}-signed-receipt-v1",
    )


def _signature_payload(
    receipt: Mapping[str, Any],
    receipt_kind: str,
) -> bytes:
    unsigned = deepcopy(dict(receipt))
    unsigned.pop("signature", None)
    return (
        b"integrity-guardian\x00"
        + f"{receipt_kind}-receipt-v1".encode()
        + b"\x00"
        + canonical_bytes(unsigned)
    )


def _sign_receipt(
    core: Mapping[str, Any],
    *,
    receipt_kind: str,
    signer: Ed25519Signer,
) -> dict[str, Any]:
    if not isinstance(signer, Ed25519Signer):
        raise SecurityAdmissionError(
            "security admission receipt signer rejected"
        )
    document = {
        "receipt_id": security_receipt_identity(
            core,
            receipt_kind=receipt_kind,
        ),
        **deepcopy(dict(core)),
    }
    document["signature"] = {
        "algorithm": "ed25519",
        "key_id": signer.key_id,
        "value": signer.sign_bytes(
            _signature_payload(document, receipt_kind)
        ),
    }
    return document


def _verify_receipt(
    receipt: Mapping[str, Any],
    *,
    receipt_kind: str,
    authority_key: TrustedKey,
    expected_subject: SecurityArtifact,
    expected_policy_digest: str,
    expected_environment: SecurityEnvironment,
    expected_harness: SecurityHarness,
) -> dict[str, Any]:
    if receipt_kind not in _SCHEMAS:
        raise SecurityAdmissionError(
            "security admission receipt kind rejected"
        )
    if not isinstance(expected_subject, SecurityArtifact):
        raise SecurityAdmissionError(
            "security admission expected subject rejected"
        )
    if not isinstance(expected_environment, SecurityEnvironment):
        raise SecurityAdmissionError(
            "security admission expected environment rejected"
        )
    if not isinstance(expected_harness, SecurityHarness):
        raise SecurityAdmissionError(
            "security admission expected harness rejected"
        )
    try:
        candidate = deepcopy(dict(receipt))
        validate(_SCHEMAS[receipt_kind], candidate)
    except (TypeError, KeyError, ValueError, ValidationError) as exc:
        raise SecurityAdmissionError(
            f"security admission {receipt_kind} schema rejected"
        ) from exc
    if not isinstance(authority_key, TrustedKey):
        raise SecurityAdmissionError(
            "security admission trusted authority rejected"
        )
    if candidate["tenant_id"] != expected_subject.tenant_id:
        raise SecurityAdmissionError(
            "security admission tenant mismatch"
        )
    if candidate["subject"] != _subject_document(expected_subject):
        raise SecurityAdmissionError(
            "security admission subject mismatch"
        )
    _require_digest(expected_policy_digest, "expected policy digest")
    if candidate["policy_digest"] != expected_policy_digest:
        raise SecurityAdmissionError(
            "security admission policy mismatch"
        )
    expected_environment_document = _environment_document(
        expected_environment
    )
    if {
        key: candidate["environment"][key]
        for key in expected_environment_document
    } != expected_environment_document:
        raise SecurityAdmissionError(
            "security admission environment mismatch"
        )
    if candidate["harness"] != _harness_document(expected_harness):
        raise SecurityAdmissionError(
            "security admission harness mismatch"
        )
    if candidate["receipt_id"] != security_receipt_identity(
        candidate,
        receipt_kind=receipt_kind,
    ):
        raise SecurityAdmissionError(
            "security admission receipt identity mismatch"
        )
    signature = candidate["signature"]
    if (
        signature["key_id"] != authority_key.key_id
        or not verify_bytes(
            _signature_payload(candidate, receipt_kind),
            signature["value"],
            authority_key.public_key,
        )
    ):
        raise SecurityAdmissionError(
            "security admission receipt signature rejected"
        )
    _require_window(candidate["created_at"], candidate["expires_at"])
    return candidate


def _canonical_selectors(
    values: Sequence[str],
    field: str,
) -> list[str]:
    if (
        isinstance(values, (str, bytes))
        or not isinstance(values, Sequence)
        or len(values) > 128
    ):
        raise SecurityAdmissionError(
            f"security admission {field} rejected"
        )
    result: list[str] = []
    for value in values:
        if not isinstance(value, str) or not value or "\\" in value:
            raise SecurityAdmissionError(
                f"security admission {field} rejected"
            )
        path = PurePosixPath(value)
        if (
            path.is_absolute()
            or any(part == ".." for part in path.parts)
            or (value != "." and path.as_posix() != value)
        ):
            raise SecurityAdmissionError(
                f"security admission {field} rejected"
            )
        result.append(value)
    if len(result) != len(set(result)):
        raise SecurityAdmissionError(
            f"security admission {field} rejected"
        )
    return sorted(result)


def _severity_counts(
    values: Mapping[str, int],
    field: str,
) -> dict[str, int]:
    if (
        not isinstance(values, Mapping)
        or set(values) != set(_SEVERITIES)
    ):
        raise SecurityAdmissionError(
            f"security admission {field} rejected"
        )
    counts: dict[str, int] = {}
    for severity in _SEVERITIES:
        value = values[severity]
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or not 0 <= value <= 1_000_000
        ):
            raise SecurityAdmissionError(
                f"security admission {field} rejected"
            )
        counts[severity] = value
    return counts


def build_artifact_provenance_receipt(
    subject: SecurityArtifact,
    *,
    policy_digest: str,
    environment: SecurityEnvironment,
    harness: SecurityHarness,
    source_revision: str,
    source_tree_digest: str,
    dependency_lock_digest: str,
    build_digest: str,
    state: str,
    reproducible: bool,
    artifact_count: int,
    created_at: str,
    expires_at: str,
    authority_signer: Ed25519Signer,
) -> dict[str, Any]:
    """Build a signed, non-authorizing artifact-provenance claim."""

    _require_digest(policy_digest, "provenance policy digest")
    _require_revision(source_revision, "source revision")
    for value, field in (
        (source_tree_digest, "source tree digest"),
        (dependency_lock_digest, "dependency lock digest"),
        (build_digest, "build digest"),
    ):
        _require_digest(value, field)
    if state not in {"exact", "non-reproducible", "partial", "failed"}:
        raise SecurityAdmissionError(
            "security admission provenance state rejected"
        )
    if not isinstance(reproducible, bool):
        raise SecurityAdmissionError(
            "security admission reproducibility rejected"
        )
    if (
        not isinstance(artifact_count, int)
        or isinstance(artifact_count, bool)
        or not 0 <= artifact_count <= 10_000
    ):
        raise SecurityAdmissionError(
            "security admission artifact count rejected"
        )
    if state == "exact" and (not reproducible or artifact_count == 0):
        raise SecurityAdmissionError(
            "security admission exact provenance rejected"
        )
    if state == "non-reproducible" and (
        reproducible or artifact_count == 0
    ):
        raise SecurityAdmissionError(
            "security admission non-reproducible provenance rejected"
        )
    _require_window(created_at, expires_at)
    core = {
        "protocol": "integrity-guardian/artifact-provenance-receipt/v1",
        "tenant_id": subject.tenant_id,
        "subject": _subject_document(subject),
        "policy_digest": policy_digest,
        "environment": _environment_document(environment),
        "harness": _harness_document(harness),
        "source": {
            "source_revision": source_revision,
            "source_tree_digest": source_tree_digest,
            "dependency_lock_digest": dependency_lock_digest,
            "build_digest": build_digest,
        },
        "outcome": {
            "state": state,
            "reproducible": reproducible,
            "artifact_count": artifact_count,
        },
        "created_at": created_at,
        "expires_at": expires_at,
        "authority_boundary": deepcopy(_AUTHORITY_BOUNDARY),
    }
    receipt = _sign_receipt(
        core,
        receipt_kind="artifact-provenance",
        signer=authority_signer,
    )
    return verify_artifact_provenance_receipt(
        receipt,
        authority_key=TrustedKey(
            authority_signer.key_id,
            authority_signer.public_key,
        ),
        expected_subject=subject,
        expected_policy_digest=policy_digest,
        expected_environment=environment,
        expected_harness=harness,
    )


def verify_artifact_provenance_receipt(
    receipt: Mapping[str, Any],
    *,
    authority_key: TrustedKey,
    expected_subject: SecurityArtifact,
    expected_policy_digest: str,
    expected_environment: SecurityEnvironment,
    expected_harness: SecurityHarness,
) -> dict[str, Any]:
    """Verify provenance identity, signature, exact bindings and semantics."""

    candidate = _verify_receipt(
        receipt,
        receipt_kind="artifact-provenance",
        authority_key=authority_key,
        expected_subject=expected_subject,
        expected_policy_digest=expected_policy_digest,
        expected_environment=expected_environment,
        expected_harness=expected_harness,
    )
    outcome = candidate["outcome"]
    if outcome["state"] == "exact" and (
        not outcome["reproducible"] or outcome["artifact_count"] == 0
    ):
        raise SecurityAdmissionError(
            "security admission exact provenance rejected"
        )
    if outcome["state"] == "non-reproducible" and (
        outcome["reproducible"] or outcome["artifact_count"] == 0
    ):
        raise SecurityAdmissionError(
            "security admission non-reproducible provenance rejected"
        )
    if candidate["authority_boundary"] != _AUTHORITY_BOUNDARY:
        raise SecurityAdmissionError(
            "security admission provenance authority boundary rejected"
        )
    return candidate


def build_security_assessment_receipt(
    subject: SecurityArtifact,
    *,
    policy_digest: str,
    environment: SecurityEnvironment,
    harness: SecurityHarness,
    scope_mode: str,
    selectors: Sequence[str],
    exclusions: Sequence[str],
    threat_model_digest: str,
    knowledge_base_digests: Sequence[str],
    coverage_state: str,
    examined_count: int,
    omitted_count: int,
    termination_reason: str,
    sealed_finding_set_digest: str,
    total_findings: int,
    unresolved: Mapping[str, int],
    validation_state: str,
    previous_receipt_id: str | None,
    history_counts: Mapping[str, int],
    tool_calls: int,
    model_calls: int,
    elapsed_ms: int,
    private_evidence_reference: str,
    private_evidence_retained_until: str,
    created_at: str,
    expires_at: str,
    authority_signer: Ed25519Signer,
) -> dict[str, Any]:
    """Build a signed assessment claim without running an assessment."""

    _require_digest(policy_digest, "assessment policy digest")
    if scope_mode not in _ASSESSMENT_MODES:
        raise SecurityAdmissionError(
            "security admission assessment mode rejected"
        )
    canonical_selectors = _canonical_selectors(selectors, "selectors")
    if not canonical_selectors:
        raise SecurityAdmissionError(
            "security admission selectors rejected"
        )
    canonical_exclusions = _canonical_selectors(exclusions, "exclusions")
    _require_digest(threat_model_digest, "threat model digest")
    if (
        isinstance(knowledge_base_digests, (str, bytes))
        or not isinstance(knowledge_base_digests, Sequence)
    ):
        raise SecurityAdmissionError(
            "security admission knowledge base rejected"
        )
    knowledge = sorted(knowledge_base_digests)
    if (
        len(knowledge) > 32
        or len(knowledge) != len(set(knowledge))
    ):
        raise SecurityAdmissionError(
            "security admission knowledge base rejected"
        )
    for digest in knowledge:
        _require_digest(digest, "knowledge base digest")
    if coverage_state not in {
        "complete",
        "partial",
        "failed",
        "cancelled",
        "unsupported",
    }:
        raise SecurityAdmissionError(
            "security admission coverage state rejected"
        )
    for value, field in (
        (examined_count, "examined count"),
        (omitted_count, "omitted count"),
        (total_findings, "finding count"),
        (tool_calls, "tool calls"),
        (model_calls, "model calls"),
        (elapsed_ms, "elapsed time"),
    ):
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or value < 0
        ):
            raise SecurityAdmissionError(
                f"security admission {field} rejected"
            )
    if coverage_state == "complete" and omitted_count != 0:
        raise SecurityAdmissionError(
            "security admission complete coverage rejected"
        )
    if coverage_state == "complete" and examined_count == 0:
        raise SecurityAdmissionError(
            "security admission empty complete coverage rejected"
        )
    if coverage_state == "partial" and omitted_count == 0:
        raise SecurityAdmissionError(
            "security admission partial coverage rejected"
        )
    if (
        not isinstance(termination_reason, str)
        or not termination_reason
        or len(termination_reason) > 512
    ):
        raise SecurityAdmissionError(
            "security admission termination reason rejected"
        )
    _require_digest(sealed_finding_set_digest, "finding set digest")
    unresolved_counts = _severity_counts(
        unresolved,
        "unresolved findings",
    )
    if sum(unresolved_counts.values()) > total_findings:
        raise SecurityAdmissionError(
            "security admission finding counts rejected"
        )
    if validation_state not in {
        "unvalidated",
        "validated-partial",
        "validated-complete",
    }:
        raise SecurityAdmissionError(
            "security admission validation state rejected"
        )
    if (
        validation_state == "validated-complete"
        and coverage_state != "complete"
    ):
        raise SecurityAdmissionError(
            "security admission complete validation rejected"
        )
    history_keys = {
        "new",
        "persisting",
        "reopened",
        "resolved",
        "unknown",
    }
    if (
        not isinstance(history_counts, Mapping)
        or set(history_counts) != history_keys
    ):
        raise SecurityAdmissionError(
            "security admission finding history rejected"
        )
    history: dict[str, int] = {}
    for field in sorted(history_keys):
        value = history_counts[field]
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or value < 0
        ):
            raise SecurityAdmissionError(
                "security admission finding history rejected"
            )
        history[field] = value
    if coverage_state != "complete" and history["resolved"] != 0:
        raise SecurityAdmissionError(
            "security admission incomplete finding resolution rejected"
        )
    if previous_receipt_id is not None and (
        not isinstance(previous_receipt_id, str)
        or re.fullmatch(
            r"security-assessment-receipt:[a-f0-9]{64}",
            previous_receipt_id,
        )
        is None
    ):
        raise SecurityAdmissionError(
            "security admission previous receipt rejected"
        )
    if (
        not isinstance(private_evidence_reference, str)
        or not private_evidence_reference.startswith("private-evidence:")
        or len(private_evidence_reference) > 257
    ):
        raise SecurityAdmissionError(
            "security admission private evidence reference rejected"
        )
    _require_window(created_at, expires_at)
    if _parse_time(private_evidence_retained_until, "retention time") < (
        _parse_time(created_at, "created time")
    ):
        raise SecurityAdmissionError(
            "security admission evidence retention rejected"
        )
    core = {
        "protocol": "integrity-guardian/security-assessment-receipt/v1",
        "tenant_id": subject.tenant_id,
        "subject": _subject_document(subject),
        "policy_digest": policy_digest,
        "environment": _environment_document(environment),
        "harness": _harness_document(harness),
        "scope": {
            "mode": scope_mode,
            "selectors": canonical_selectors,
            "exclusions": canonical_exclusions,
            "threat_model_digest": threat_model_digest,
            "knowledge_base_digests": knowledge,
        },
        "coverage": {
            "state": coverage_state,
            "examined_count": examined_count,
            "omitted_count": omitted_count,
            "termination_reason": termination_reason,
        },
        "findings": {
            "sealed_set_digest": sealed_finding_set_digest,
            "total_count": total_findings,
            "unresolved": unresolved_counts,
            "validation_state": validation_state,
        },
        "history": {
            "previous_receipt_id": previous_receipt_id,
            **history,
        },
        "budgets": {
            "tool_calls": tool_calls,
            "model_calls": model_calls,
            "elapsed_ms": elapsed_ms,
        },
        "private_evidence": {
            "reference": private_evidence_reference,
            "retained_until": private_evidence_retained_until,
        },
        "created_at": created_at,
        "expires_at": expires_at,
        "authority_boundary": deepcopy(_AUTHORITY_BOUNDARY),
    }
    receipt = _sign_receipt(
        core,
        receipt_kind="security-assessment",
        signer=authority_signer,
    )
    return verify_security_assessment_receipt(
        receipt,
        authority_key=TrustedKey(
            authority_signer.key_id,
            authority_signer.public_key,
        ),
        expected_subject=subject,
        expected_policy_digest=policy_digest,
        expected_environment=environment,
        expected_harness=harness,
    )


def verify_security_assessment_receipt(
    receipt: Mapping[str, Any],
    *,
    authority_key: TrustedKey,
    expected_subject: SecurityArtifact,
    expected_policy_digest: str,
    expected_environment: SecurityEnvironment,
    expected_harness: SecurityHarness,
) -> dict[str, Any]:
    """Verify exact assessment scope, coverage, finding and authority claims."""

    candidate = _verify_receipt(
        receipt,
        receipt_kind="security-assessment",
        authority_key=authority_key,
        expected_subject=expected_subject,
        expected_policy_digest=expected_policy_digest,
        expected_environment=expected_environment,
        expected_harness=expected_harness,
    )
    scope = candidate["scope"]
    if scope["selectors"] != _canonical_selectors(
        scope["selectors"],
        "selectors",
    ) or scope["exclusions"] != _canonical_selectors(
        scope["exclusions"],
        "exclusions",
    ):
        raise SecurityAdmissionError(
            "security admission assessment scope order rejected"
        )
    coverage = candidate["coverage"]
    findings = candidate["findings"]
    if coverage["state"] == "complete" and coverage["omitted_count"] != 0:
        raise SecurityAdmissionError(
            "security admission complete coverage rejected"
        )
    if coverage["state"] == "complete" and coverage["examined_count"] == 0:
        raise SecurityAdmissionError(
            "security admission empty complete coverage rejected"
        )
    if coverage["state"] == "partial" and coverage["omitted_count"] == 0:
        raise SecurityAdmissionError(
            "security admission partial coverage rejected"
        )
    if (
        findings["validation_state"] == "validated-complete"
        and coverage["state"] != "complete"
    ):
        raise SecurityAdmissionError(
            "security admission complete validation rejected"
        )
    if (
        coverage["state"] != "complete"
        and candidate["history"]["resolved"] != 0
    ):
        raise SecurityAdmissionError(
            "security admission incomplete finding resolution rejected"
        )
    if (
        sum(findings["unresolved"].values())
        > findings["total_count"]
    ):
        raise SecurityAdmissionError(
            "security admission finding counts rejected"
        )
    if _parse_time(
        candidate["private_evidence"]["retained_until"],
        "retention time",
    ) < _parse_time(candidate["created_at"], "created time"):
        raise SecurityAdmissionError(
            "security admission evidence retention rejected"
        )
    if candidate["authority_boundary"] != _AUTHORITY_BOUNDARY:
        raise SecurityAdmissionError(
            "security admission assessment authority boundary rejected"
        )
    return candidate


def build_execution_containment_receipt(
    subject: SecurityArtifact,
    *,
    policy_digest: str,
    environment: SecurityEnvironment,
    environment_supported: bool,
    harness: SecurityHarness,
    assurance_class: str,
    ready_before_untrusted_work: bool,
    policy_frozen: bool,
    controls: Mapping[str, str],
    resident_monitor: bool,
    continuous_monitor: bool,
    post_run_drift: str,
    allowed_channels: Sequence[str],
    exceptions: Sequence[str],
    created_at: str,
    expires_at: str,
    authority_signer: Ed25519Signer,
) -> dict[str, Any]:
    """Build a signed containment claim without enforcing a boundary."""

    _require_digest(policy_digest, "containment policy digest")
    if assurance_class not in _CONTAINMENT_CLASSES:
        raise SecurityAdmissionError(
            "security admission containment assurance rejected"
        )
    if not isinstance(environment_supported, bool):
        raise SecurityAdmissionError(
            "security admission environment support rejected"
        )
    if not isinstance(ready_before_untrusted_work, bool) or not isinstance(
        policy_frozen,
        bool,
    ):
        raise SecurityAdmissionError(
            "security admission containment readiness rejected"
        )
    expected_control_fields = {
        "egress",
        "privilege",
        "container_control",
        "secrets",
    }
    if (
        not isinstance(controls, Mapping)
        or set(controls) != expected_control_fields
    ):
        raise SecurityAdmissionError(
            "security admission containment controls rejected"
        )
    control_document = dict(controls)
    allowed_control_values = {
        "egress": {"blocked", "bounded", "observed", "unrestricted"},
        "privilege": {"removed", "bounded", "observed", "unrestricted"},
        "container_control": {
            "disabled",
            "bounded",
            "observed",
            "available",
        },
        "secrets": {"absent", "bounded", "observed", "unrestricted"},
    }
    if any(
        control_document[field] not in values
        for field, values in allowed_control_values.items()
    ):
        raise SecurityAdmissionError(
            "security admission containment controls rejected"
        )
    if not isinstance(resident_monitor, bool) or not isinstance(
        continuous_monitor,
        bool,
    ):
        raise SecurityAdmissionError(
            "security admission containment monitor rejected"
        )
    if post_run_drift not in {"none", "detected", "unknown"}:
        raise SecurityAdmissionError(
            "security admission containment drift rejected"
        )
    for values, field in (
        (allowed_channels, "allowed channels"),
        (exceptions, "containment exceptions"),
    ):
        if (
            isinstance(values, (str, bytes))
            or not isinstance(values, Sequence)
            or len(values) > 64
            or len(values) != len(set(values))
            or any(
                not isinstance(value, str)
                or not value
                or len(value) > 256
                for value in values
            )
        ):
            raise SecurityAdmissionError(
                f"security admission {field} rejected"
            )
    channels = sorted(allowed_channels)
    exception_values = sorted(exceptions)
    _require_window(created_at, expires_at)
    core = {
        "protocol": "integrity-guardian/execution-containment-receipt/v1",
        "tenant_id": subject.tenant_id,
        "subject": _subject_document(subject),
        "policy_digest": policy_digest,
        "environment": {
            **_environment_document(environment),
            "supported": environment_supported,
        },
        "harness": _harness_document(harness),
        "assurance_class": assurance_class,
        "readiness": {
            "ready_before_untrusted_work": ready_before_untrusted_work,
            "policy_frozen": policy_frozen,
        },
        "controls": control_document,
        "monitor": {
            "resident": resident_monitor,
            "continuous": continuous_monitor,
            "post_run_drift": post_run_drift,
        },
        "allowed_channels": channels,
        "exceptions": exception_values,
        "created_at": created_at,
        "expires_at": expires_at,
        "authority_boundary": deepcopy(
            _CONTAINMENT_AUTHORITY_BOUNDARY
        ),
    }
    receipt = _sign_receipt(
        core,
        receipt_kind="execution-containment",
        signer=authority_signer,
    )
    return verify_execution_containment_receipt(
        receipt,
        authority_key=TrustedKey(
            authority_signer.key_id,
            authority_signer.public_key,
        ),
        expected_subject=subject,
        expected_policy_digest=policy_digest,
        expected_environment=environment,
        expected_harness=harness,
    )


def verify_execution_containment_receipt(
    receipt: Mapping[str, Any],
    *,
    authority_key: TrustedKey,
    expected_subject: SecurityArtifact,
    expected_policy_digest: str,
    expected_environment: SecurityEnvironment,
    expected_harness: SecurityHarness,
) -> dict[str, Any]:
    """Verify containment identity, assurance class and no-authority claims."""

    candidate = _verify_receipt(
        receipt,
        receipt_kind="execution-containment",
        authority_key=authority_key,
        expected_subject=expected_subject,
        expected_policy_digest=expected_policy_digest,
        expected_environment=expected_environment,
        expected_harness=expected_harness,
    )
    if candidate["assurance_class"] == "protected":
        controls = candidate["controls"]
        monitor = candidate["monitor"]
        if (
            not candidate["environment"]["supported"]
            or not candidate["readiness"]["ready_before_untrusted_work"]
            or not candidate["readiness"]["policy_frozen"]
            or controls["egress"] not in {"blocked", "bounded"}
            or controls["privilege"] not in {"removed", "bounded"}
            or controls["container_control"] not in {"disabled", "bounded"}
            or controls["secrets"] not in {"absent", "bounded"}
            or not monitor["resident"]
            or not monitor["continuous"]
            or monitor["post_run_drift"] != "none"
        ):
            raise SecurityAdmissionError(
                "security admission protected containment rejected"
            )
    if (
        not candidate["environment"]["supported"]
        and candidate["assurance_class"] != "unsupported"
    ):
        raise SecurityAdmissionError(
            "security admission unsupported containment rejected"
        )
    if (
        candidate["allowed_channels"]
        != sorted(candidate["allowed_channels"])
        or candidate["exceptions"] != sorted(candidate["exceptions"])
    ):
        raise SecurityAdmissionError(
            "security admission containment ordering rejected"
        )
    if (
        candidate["authority_boundary"]
        != _CONTAINMENT_AUTHORITY_BOUNDARY
    ):
        raise SecurityAdmissionError(
            "security admission containment authority boundary rejected"
        )
    return candidate


@dataclass(frozen=True)
class ProjectSecurityAdmissionPolicy:
    """Exact synthetic product profile for one admission decision."""

    policy_id: str
    product_id: str
    subject: SecurityArtifact
    environment: SecurityEnvironment
    provenance_policy_digest: str
    assessment_policy_digest: str
    containment_policy_digest: str
    provenance_harness: SecurityHarness
    assessment_harness: SecurityHarness
    containment_harness: SecurityHarness
    requested_channel: str
    require_reproducible_provenance: bool
    required_assessment_mode: str
    require_complete_coverage: bool
    require_validated_findings: bool
    max_unresolved_critical: int
    max_unresolved_high: int
    max_unresolved_medium: int
    max_unresolved_low: int
    containment_required: bool
    required_containment_assurance: str

    def __post_init__(self) -> None:
        _require_id(self.policy_id, "promotion policy id")
        _require_id(self.product_id, "product id")
        if not isinstance(self.subject, SecurityArtifact):
            raise SecurityAdmissionError(
                "security admission policy subject rejected"
            )
        if not isinstance(self.environment, SecurityEnvironment):
            raise SecurityAdmissionError(
                "security admission policy environment rejected"
            )
        for value, field in (
            (self.provenance_policy_digest, "provenance policy digest"),
            (self.assessment_policy_digest, "assessment policy digest"),
            (self.containment_policy_digest, "containment policy digest"),
        ):
            _require_digest(value, field)
        for harness in (
            self.provenance_harness,
            self.assessment_harness,
            self.containment_harness,
        ):
            if not isinstance(harness, SecurityHarness):
                raise SecurityAdmissionError(
                    "security admission policy harness rejected"
                )
        if self.requested_channel not in {"rc", "stable"}:
            raise SecurityAdmissionError(
                "security admission release channel rejected"
            )
        if not isinstance(
            self.require_reproducible_provenance,
            bool,
        ) or not isinstance(
            self.require_complete_coverage,
            bool,
        ) or not isinstance(
            self.require_validated_findings,
            bool,
        ) or not isinstance(self.containment_required, bool):
            raise SecurityAdmissionError(
                "security admission policy flag rejected"
            )
        if self.required_assessment_mode not in _ASSESSMENT_MODES:
            raise SecurityAdmissionError(
                "security admission policy assessment mode rejected"
            )
        for value in (
            self.max_unresolved_critical,
            self.max_unresolved_high,
            self.max_unresolved_medium,
            self.max_unresolved_low,
        ):
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or not 0 <= value <= 1_000_000
            ):
                raise SecurityAdmissionError(
                    "security admission unresolved limit rejected"
                )
        if self.containment_required:
            if (
                self.required_containment_assurance
                not in {"protected", "audit", "degraded"}
            ):
                raise SecurityAdmissionError(
                    "security admission containment requirement rejected"
                )
        elif self.required_containment_assurance != "none":
            raise SecurityAdmissionError(
                "security admission optional containment rejected"
            )
        if self.requested_channel == "stable" and (
            not self.require_reproducible_provenance
            or self.required_assessment_mode != "full"
            or not self.require_complete_coverage
            or not self.require_validated_findings
            or self.max_unresolved_critical != 0
            or self.max_unresolved_high != 0
            or (
                self.containment_required
                and self.required_containment_assurance != "protected"
            )
        ):
            raise SecurityAdmissionError(
                "security admission weak stable policy rejected"
            )


def _max_unresolved(
    policy: ProjectSecurityAdmissionPolicy,
) -> dict[str, int]:
    return {
        "critical": policy.max_unresolved_critical,
        "high": policy.max_unresolved_high,
        "medium": policy.max_unresolved_medium,
        "low": policy.max_unresolved_low,
    }


def _policy_document(
    policy: ProjectSecurityAdmissionPolicy,
) -> dict[str, Any]:
    if not isinstance(policy, ProjectSecurityAdmissionPolicy):
        raise SecurityAdmissionError(
            "security admission promotion policy rejected"
        )
    return {
        "policy_id": policy.policy_id,
        "product_id": policy.product_id,
        "tenant_id": policy.subject.tenant_id,
        "subject": _subject_document(policy.subject),
        "environment": _environment_document(policy.environment),
        "input_policies": {
            "provenance": policy.provenance_policy_digest,
            "assessment": policy.assessment_policy_digest,
            "containment": policy.containment_policy_digest,
        },
        "harnesses": {
            "provenance": _harness_document(policy.provenance_harness),
            "assessment": _harness_document(policy.assessment_harness),
            "containment": _harness_document(policy.containment_harness),
        },
        "requested_channel": policy.requested_channel,
        "requirements": {
            "reproducible_provenance": (
                policy.require_reproducible_provenance
            ),
            "assessment_mode": policy.required_assessment_mode,
            "complete_coverage": policy.require_complete_coverage,
            "validated_findings": policy.require_validated_findings,
            "max_unresolved": _max_unresolved(policy),
            "containment_required": policy.containment_required,
            "containment_assurance": (
                policy.required_containment_assurance
            ),
        },
    }


def project_security_policy_digest(
    policy: ProjectSecurityAdmissionPolicy,
) -> str:
    """Return the exact identity of one synthetic product profile."""

    return digest_object(
        _policy_document(policy),
        domain="project-security-admission-policy-v1",
    )


def _verify_admission_inputs(
    policy: ProjectSecurityAdmissionPolicy,
    provenance_receipt: Mapping[str, Any],
    assessment_receipt: Mapping[str, Any],
    containment_receipt: Mapping[str, Any] | None,
    *,
    provenance_key: TrustedKey,
    assessment_key: TrustedKey,
    containment_key: TrustedKey | None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any] | None]:
    provenance = verify_artifact_provenance_receipt(
        provenance_receipt,
        authority_key=provenance_key,
        expected_subject=policy.subject,
        expected_policy_digest=policy.provenance_policy_digest,
        expected_environment=policy.environment,
        expected_harness=policy.provenance_harness,
    )
    assessment = verify_security_assessment_receipt(
        assessment_receipt,
        authority_key=assessment_key,
        expected_subject=policy.subject,
        expected_policy_digest=policy.assessment_policy_digest,
        expected_environment=policy.environment,
        expected_harness=policy.assessment_harness,
    )
    containment: dict[str, Any] | None = None
    if containment_receipt is not None:
        if containment_key is None:
            raise SecurityAdmissionError(
                "security admission containment key required"
            )
        containment = verify_execution_containment_receipt(
            containment_receipt,
            authority_key=containment_key,
            expected_subject=policy.subject,
            expected_policy_digest=policy.containment_policy_digest,
            expected_environment=policy.environment,
            expected_harness=policy.containment_harness,
        )
    return provenance, assessment, containment


def _input_reference(
    receipt: Mapping[str, Any],
    receipt_kind: str,
) -> dict[str, str]:
    return {
        "receipt_id": receipt["receipt_id"],
        "receipt_digest": security_receipt_digest(
            receipt,
            receipt_kind=receipt_kind,
        ),
    }


def _decision_for_inputs(
    policy: ProjectSecurityAdmissionPolicy,
    provenance: Mapping[str, Any],
    assessment: Mapping[str, Any],
    containment: Mapping[str, Any] | None,
    *,
    evaluated_at: str,
) -> tuple[str, list[str]]:
    reasons: list[str] = []
    if not _within_window(provenance, evaluated_at):
        reasons.append("provenance-stale")
    if provenance["outcome"]["state"] != "exact":
        reasons.append("provenance-not-exact")
    if (
        policy.require_reproducible_provenance
        and not provenance["outcome"]["reproducible"]
    ):
        reasons.append("provenance-not-reproducible")

    if not _within_window(assessment, evaluated_at):
        reasons.append("assessment-stale")
    if assessment["scope"]["mode"] != policy.required_assessment_mode:
        reasons.append("assessment-mode-mismatch")
    if (
        policy.require_complete_coverage
        and assessment["coverage"]["state"] != "complete"
    ):
        reasons.append("assessment-coverage-incomplete")
    if (
        policy.require_validated_findings
        and assessment["findings"]["validation_state"]
        != "validated-complete"
    ):
        reasons.append("findings-not-validated")
    limits = _max_unresolved(policy)
    for severity in _SEVERITIES:
        if (
            assessment["findings"]["unresolved"][severity]
            > limits[severity]
        ):
            reasons.append(f"unresolved-{severity}")

    if policy.containment_required:
        if containment is None:
            reasons.append("containment-missing")
        else:
            if not _within_window(containment, evaluated_at):
                reasons.append("containment-stale")
            if (
                containment["assurance_class"]
                != policy.required_containment_assurance
            ):
                reasons.append("containment-assurance-mismatch")
    if reasons:
        return "ineligible", sorted(reasons)
    if policy.requested_channel == "stable":
        return "stable-eligible", []
    return "rc-eligible", []


def evaluate_project_security_admission(
    policy: ProjectSecurityAdmissionPolicy,
    provenance_receipt: Mapping[str, Any],
    assessment_receipt: Mapping[str, Any],
    containment_receipt: Mapping[str, Any] | None,
    *,
    provenance_key: TrustedKey,
    assessment_key: TrustedKey,
    containment_key: TrustedKey | None,
    evaluated_at: str,
    expires_at: str,
    authority_signer: Ed25519Signer,
) -> dict[str, Any]:
    """Evaluate signed claims and issue a non-authorizing eligibility receipt."""

    provenance, assessment, containment = _verify_admission_inputs(
        policy,
        provenance_receipt,
        assessment_receipt,
        containment_receipt,
        provenance_key=provenance_key,
        assessment_key=assessment_key,
        containment_key=containment_key,
    )
    _require_window(evaluated_at, expires_at)
    input_expiries = [
        _parse_time(provenance["expires_at"], "provenance expiry"),
        _parse_time(assessment["expires_at"], "assessment expiry"),
    ]
    if containment is not None:
        input_expiries.append(
            _parse_time(containment["expires_at"], "containment expiry")
        )
    if _parse_time(expires_at, "decision expiry") > min(input_expiries):
        raise SecurityAdmissionError(
            "security admission decision expiry exceeds input"
        )
    decision, reasons = _decision_for_inputs(
        policy,
        provenance,
        assessment,
        containment,
        evaluated_at=evaluated_at,
    )
    core = {
        "protocol": "integrity-guardian/promotion-decision-receipt/v1",
        "tenant_id": policy.subject.tenant_id,
        "policy_id": policy.policy_id,
        "policy_digest": project_security_policy_digest(policy),
        "product_id": policy.product_id,
        "subject": _subject_document(policy.subject),
        "environment": _environment_document(policy.environment),
        "requested_channel": policy.requested_channel,
        "inputs": {
            "provenance": _input_reference(
                provenance,
                "artifact-provenance",
            ),
            "assessment": _input_reference(
                assessment,
                "security-assessment",
            ),
            "containment": (
                _input_reference(containment, "execution-containment")
                if containment is not None
                else None
            ),
        },
        "requirements": _policy_document(policy)["requirements"],
        "decision": decision,
        "reasons": reasons,
        "evaluated_at": evaluated_at,
        "expires_at": expires_at,
        "authority_boundary": deepcopy(_PROMOTION_AUTHORITY_BOUNDARY),
    }
    receipt = _sign_receipt(
        core,
        receipt_kind="promotion-decision",
        signer=authority_signer,
    )
    return verify_promotion_decision_receipt(
        receipt,
        expected_policy=policy,
        provenance_receipt=provenance,
        assessment_receipt=assessment,
        containment_receipt=containment,
        provenance_key=provenance_key,
        assessment_key=assessment_key,
        containment_key=containment_key,
        authority_key=TrustedKey(
            authority_signer.key_id,
            authority_signer.public_key,
        ),
    )


def verify_promotion_decision_receipt(
    receipt: Mapping[str, Any],
    *,
    expected_policy: ProjectSecurityAdmissionPolicy,
    provenance_receipt: Mapping[str, Any],
    assessment_receipt: Mapping[str, Any],
    containment_receipt: Mapping[str, Any] | None,
    provenance_key: TrustedKey,
    assessment_key: TrustedKey,
    containment_key: TrustedKey | None,
    authority_key: TrustedKey,
) -> dict[str, Any]:
    """Verify input chains and recompute a promotion eligibility decision."""

    try:
        candidate = deepcopy(dict(receipt))
        validate("promotion-decision-receipt", candidate)
    except (TypeError, KeyError, ValueError, ValidationError) as exc:
        raise SecurityAdmissionError(
            "security admission promotion decision schema rejected"
        ) from exc
    if not isinstance(authority_key, TrustedKey):
        raise SecurityAdmissionError(
            "security admission promotion authority rejected"
        )
    if candidate["receipt_id"] != security_receipt_identity(
        candidate,
        receipt_kind="promotion-decision",
    ):
        raise SecurityAdmissionError(
            "security admission promotion identity mismatch"
        )
    signature = candidate["signature"]
    if (
        signature["key_id"] != authority_key.key_id
        or not verify_bytes(
            _signature_payload(candidate, "promotion-decision"),
            signature["value"],
            authority_key.public_key,
        )
    ):
        raise SecurityAdmissionError(
            "security admission promotion signature rejected"
        )
    provenance, assessment, containment = _verify_admission_inputs(
        expected_policy,
        provenance_receipt,
        assessment_receipt,
        containment_receipt,
        provenance_key=provenance_key,
        assessment_key=assessment_key,
        containment_key=containment_key,
    )
    expected_decision, expected_reasons = _decision_for_inputs(
        expected_policy,
        provenance,
        assessment,
        containment,
        evaluated_at=candidate["evaluated_at"],
    )
    expected_inputs = {
        "provenance": _input_reference(
            provenance,
            "artifact-provenance",
        ),
        "assessment": _input_reference(
            assessment,
            "security-assessment",
        ),
        "containment": (
            _input_reference(containment, "execution-containment")
            if containment is not None
            else None
        ),
    }
    policy_document = _policy_document(expected_policy)
    expected_fields = {
        "tenant_id": expected_policy.subject.tenant_id,
        "policy_id": expected_policy.policy_id,
        "policy_digest": project_security_policy_digest(expected_policy),
        "product_id": expected_policy.product_id,
        "subject": _subject_document(expected_policy.subject),
        "environment": _environment_document(expected_policy.environment),
        "requested_channel": expected_policy.requested_channel,
        "inputs": expected_inputs,
        "requirements": policy_document["requirements"],
        "decision": expected_decision,
        "reasons": expected_reasons,
        "authority_boundary": _PROMOTION_AUTHORITY_BOUNDARY,
    }
    for field, expected_value in expected_fields.items():
        if candidate[field] != expected_value:
            raise SecurityAdmissionError(
                f"security admission promotion {field} mismatch"
            )
    _require_window(candidate["evaluated_at"], candidate["expires_at"])
    input_expiries = [
        _parse_time(provenance["expires_at"], "provenance expiry"),
        _parse_time(assessment["expires_at"], "assessment expiry"),
    ]
    if containment is not None:
        input_expiries.append(
            _parse_time(containment["expires_at"], "containment expiry")
        )
    if _parse_time(candidate["expires_at"], "decision expiry") > min(
        input_expiries
    ):
        raise SecurityAdmissionError(
            "security admission decision expiry exceeds input"
        )
    return candidate


__all__ = [
    "ProjectSecurityAdmissionPolicy",
    "SecurityAdmissionError",
    "SecurityArtifact",
    "SecurityEnvironment",
    "SecurityHarness",
    "build_artifact_provenance_receipt",
    "build_execution_containment_receipt",
    "build_security_assessment_receipt",
    "evaluate_project_security_admission",
    "project_security_policy_digest",
    "security_receipt_digest",
    "security_receipt_identity",
    "verify_artifact_provenance_receipt",
    "verify_execution_containment_receipt",
    "verify_promotion_decision_receipt",
    "verify_security_assessment_receipt",
]
