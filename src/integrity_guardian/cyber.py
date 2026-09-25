"""Deterministic Guardian Cyber interpretation layer.

The engine consumes already verified evidence. It has no active scanning,
networking, remediation or shell execution capability.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from .hashing import digest_object
from .schemas import validate


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TruthStatus(StrEnum):
    REPORTED = "reported"
    OBSERVED = "observed"
    VERIFIED = "verified"
    INFERRED = "inferred"
    UNKNOWN = "unknown"
    STALE = "stale"
    SUPERSEDED = "superseded"
    CONTRADICTED = "contradicted"


class SourceTrust(StrEnum):
    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class BehaviorFact:
    tenant_id: str
    asset_id: str
    fact_type: str
    source_event_id: str
    changed: bool
    attributes: dict[str, str | int | float | bool | None] = field(default_factory=dict)
    truth_status: TruthStatus = TruthStatus.OBSERVED
    confidence: str = "high"
    source_trust: SourceTrust = SourceTrust.UNKNOWN
    observed_at: str | None = None
    valid_until: str | None = None

    def __post_init__(self) -> None:
        if not self.tenant_id.startswith("tenant:"):
            raise ValueError("tenant_id must be explicit and canonical")
        if not self.asset_id:
            raise ValueError("asset_id must not be empty")
        if not self.fact_type:
            raise ValueError("fact_type must not be empty")
        if not self.source_event_id:
            raise ValueError("source_event_id must not be empty")
        if self.confidence not in {"low", "medium", "high"}:
            raise ValueError("confidence must be low, medium or high")
        if str(self.truth_status) not in {status.value for status in TruthStatus}:
            raise ValueError("truth_status is not recognized")
        if str(self.source_trust) not in {trust.value for trust in SourceTrust}:
            raise ValueError("source_trust is not recognized")
        validators: dict[str, tuple[str, type | tuple[type, ...]]] = {
            "control-state": ("compliant", bool),
            "runtime-capability": ("approved", bool),
            "inert-fragment": ("approved", bool),
            "l2-health": ("healthy", bool),
            "external-probe": ("success", bool),
            "baseline-disposition": ("disposition", str),
        }
        requirement = validators.get(self.fact_type)
        if requirement is not None:
            attribute, expected_type = requirement
            if attribute not in self.attributes:
                raise ValueError(
                    f"{self.fact_type} requires the {attribute!r} attribute"
                )
            if not isinstance(self.attributes[attribute], expected_type):
                raise ValueError(
                    f"{self.fact_type} attribute {attribute!r} has invalid type"
                )
        if self.fact_type == "external-probe":
            for attribute in ("probe", "vantage", "expected", "actual"):
                value = self.attributes.get(attribute)
                if not isinstance(value, str) or not value:
                    raise ValueError(
                        f"external-probe requires a non-empty {attribute!r} attribute"
                    )
        if self.fact_type == "l2-health":
            check = self.attributes.get("check")
            if not isinstance(check, str) or not check:
                raise ValueError("l2-health requires a non-empty 'check' attribute")
        if self.fact_type == "control-state":
            control = self.attributes.get("control")
            if not isinstance(control, str) or not control:
                raise ValueError("control-state requires a non-empty 'control' attribute")
        if self.fact_type == "runtime-capability":
            capability = self.attributes.get("capability")
            if not isinstance(capability, str) or not capability:
                raise ValueError(
                    "runtime-capability requires a non-empty 'capability' attribute"
                )
        if self.fact_type == "inert-fragment":
            for attribute in ("activation_group", "capability"):
                value = self.attributes.get(attribute)
                if not isinstance(value, str) or not value:
                    raise ValueError(
                        f"inert-fragment requires a non-empty {attribute!r} attribute"
                    )
        if self.fact_type == "baseline-disposition":
            allowed = {
                "approved",
                "approved-exception",
                "remediation-required",
                "unknown",
                "unsupported",
                "prohibited",
            }
            if self.attributes["disposition"] not in allowed:
                raise ValueError("baseline-disposition is not a recognized state")
            if (
                self.attributes["disposition"] == "approved-exception"
                and self.valid_until is None
            ):
                raise ValueError("approved-exception requires valid_until")


def _finding(
    *,
    tenant_id: str,
    policy_id: str,
    severity: Severity,
    title: str,
    assets: list[str],
    evidence: list[str],
    actual: str,
    worst_case: str,
    changed: bool,
    truth_status: TruthStatus | str = TruthStatus.VERIFIED,
    confidence: str = "high",
    source_trust: SourceTrust | str = SourceTrust.HIGH,
    observed_at: str | None = None,
    valid_until: str | None = None,
    assumptions: list[str] | None = None,
    unresolved_evidence: list[str] | None = None,
    related_intent_ids: list[str] | None = None,
    ticket_ids: list[str] | None = None,
    recommended_next_action: str,
) -> dict[str, Any]:
    core: dict[str, Any] = {
        "protocol": "integrity-guardian/finding/v1",
        "finding_id": "finding:pending",
        "tenant_id": tenant_id,
        "policy_id": policy_id,
        "severity": severity.value,
        "truth_status": str(truth_status),
        "confidence": confidence,
        "source_trust": str(source_trust),
        "title": title,
        "affected_assets": sorted(set(assets)),
        "evidence_event_ids": sorted(set(evidence)),
        "observed_at": observed_at,
        "valid_until": valid_until,
        "actual": actual,
        "worst_case": worst_case,
        "assumptions": sorted(set(assumptions or [])),
        "unresolved_evidence": sorted(set(unresolved_evidence or [])),
        "related_intent_ids": sorted(set(related_intent_ids or [])),
        "ticket_ids": sorted(set(ticket_ids or [])),
        "recommended_next_action": recommended_next_action,
        "changed": changed,
        "status": "open",
    }
    identity = digest_object(core, domain="guardian-cyber-finding-v1").split(":", 1)[1]
    core["finding_id"] = f"finding:{identity}"
    validate("finding", core)
    return core


def _fact_context(fact: BehaviorFact) -> dict[str, Any]:
    return {
        "truth_status": fact.truth_status,
        "confidence": fact.confidence,
        "source_trust": fact.source_trust,
        "observed_at": fact.observed_at,
        "valid_until": fact.valid_until,
    }


class GuardianCyber:
    """Built-in deterministic policies for the M5 prototype."""

    def evaluate(
        self,
        *,
        reconciliation_decisions: list[dict[str, Any]],
        behavior_facts: list[BehaviorFact],
    ) -> list[dict[str, Any]]:
        tenant_ids = {fact.tenant_id for fact in behavior_facts}
        for index, decision in enumerate(reconciliation_decisions):
            tenant_id = decision.get("tenant_id")
            if not isinstance(tenant_id, str) or not tenant_id.startswith("tenant:"):
                raise ValueError(
                    f"reconciliation decision {index} has no canonical tenant identity"
                )
            tenant_ids.add(tenant_id)
        if len(tenant_ids) > 1:
            raise ValueError("cross-tenant Guardian Cyber batches are prohibited")
        findings: list[dict[str, Any]] = []

        for decision in reconciliation_decisions:
            classification = decision["classification"]
            evidence = [decision["source_event_id"]] if decision.get("source_event_id") else []
            asset = decision.get("selector") or "asset:unknown"
            if classification in {"sensor_gap", "ledger_gap"}:
                findings.append(
                    _finding(
                        tenant_id=decision["tenant_id"],
                        policy_id="IG-CYBER-001",
                        severity=Severity.HIGH,
                        title="Integrity evidence gap",
                        assets=[asset],
                        evidence=evidence,
                        actual=f"{classification} prevents complete reconstruction",
                        worst_case=(
                            "Unobserved changes may exist inside the missing evidence horizon"
                        ),
                        changed=True,
                        truth_status=TruthStatus.VERIFIED,
                        unresolved_evidence=[
                            "The missing observation or ledger interval has not been reconstructed"
                        ],
                        related_intent_ids=(
                            [decision["intent_id"]] if decision.get("intent_id") else []
                        ),
                        recommended_next_action=(
                            "Restore evidence continuity and review the uncovered interval "
                            "before any baseline promotion"
                        ),
                    )
                )
            elif classification == "scope_breach":
                findings.append(
                    _finding(
                        tenant_id=decision["tenant_id"],
                        policy_id="IG-CYBER-003",
                        severity=Severity.CRITICAL,
                        title="Observed change exceeded prior intent",
                        assets=[asset],
                        evidence=evidence,
                        actual="A verified observed delta is outside the authorized scope",
                        worst_case="Additional unauthorized system state may have changed",
                        changed=True,
                        related_intent_ids=(
                            [decision["intent_id"]] if decision.get("intent_id") else []
                        ),
                        recommended_next_action=(
                            "Freeze baseline promotion and review the exact out-of-scope delta"
                        ),
                    )
                )
            elif classification == "unrecorded_change":
                findings.append(
                    _finding(
                        tenant_id=decision["tenant_id"],
                        policy_id="IG-CYBER-002",
                        severity=Severity.HIGH,
                        title="Observed change has no applicable prior intent",
                        assets=[asset],
                        evidence=evidence,
                        actual="A verified delta cannot be bound to a valid prior ChangeIntent",
                        worst_case="The change may be unauthorized or incorrectly governed",
                        changed=True,
                        unresolved_evidence=[
                            "No valid prior ChangeIntent explains the observed delta"
                        ],
                        recommended_next_action=(
                            "Preserve evidence, identify the actor and require an explicit "
                            "retrospective review"
                        ),
                    )
                )

        fragment_groups: dict[str, list[BehaviorFact]] = {}
        for fact in behavior_facts:
            if fact.fact_type == "control-state" and fact.attributes.get("compliant") is False:
                control = str(fact.attributes.get("control", "unknown-control"))
                findings.append(
                    _finding(
                        tenant_id=fact.tenant_id,
                        policy_id="IG-CYBER-010",
                        severity=Severity.HIGH,
                        title="Security control is not compliant",
                        assets=[fact.asset_id],
                        evidence=[fact.source_event_id],
                        actual=f"Control {control} is currently non-compliant",
                        worst_case="The control gap may permit a preventable compromise",
                        changed=fact.changed,
                        recommended_next_action=(
                            "Create a scoped remediation proposal or an explicit expiring exception"
                        ),
                        **_fact_context(fact),
                    )
                )
            elif (
                fact.fact_type == "runtime-capability"
                and fact.attributes.get("approved") is False
            ):
                capability = str(fact.attributes.get("capability", "unknown"))
                findings.append(
                    _finding(
                        tenant_id=fact.tenant_id,
                        policy_id="IG-CYBER-020",
                        severity=Severity.HIGH,
                        title="Unapproved runtime capability observed",
                        assets=[fact.asset_id],
                        evidence=[fact.source_event_id],
                        actual=f"Runtime capability {capability} is present without approval",
                        worst_case="The capability may enable unauthorized execution or egress",
                        changed=fact.changed,
                        recommended_next_action=(
                            "Verify provenance and either remove the capability through a separate "
                            "authorized responder or record an expiring exception"
                        ),
                        **_fact_context(fact),
                    )
                )
            elif fact.fact_type == "inert-fragment":
                group = fact.attributes.get("activation_group")
                if isinstance(group, str) and group:
                    fragment_groups.setdefault(group, []).append(fact)
            elif fact.fact_type == "l2-health" and fact.attributes.get("healthy") is False:
                check = str(fact.attributes.get("check", "unknown-check"))
                findings.append(
                    _finding(
                        tenant_id=fact.tenant_id,
                        policy_id="IG-CYBER-040",
                        severity=Severity.HIGH,
                        title="Runtime behavior is unhealthy",
                        assets=[fact.asset_id],
                        evidence=[fact.source_event_id],
                        actual=f"L2 behavior check {check} failed",
                        worst_case=(
                            "The service may be unavailable or operating outside its intended "
                            "runtime relationship"
                        ),
                        changed=fact.changed,
                        unresolved_evidence=[
                            "Local state alone does not establish the end-to-end service impact"
                        ],
                        recommended_next_action=(
                            "Correlate the failed check with an independent external probe and "
                            "the latest ChangeIntent"
                        ),
                        **_fact_context(fact),
                    )
                )
            elif (
                fact.fact_type == "external-probe"
                and fact.attributes.get("success") is False
            ):
                probe = str(fact.attributes.get("probe", "unknown-probe"))
                vantage = str(fact.attributes.get("vantage", "unknown-vantage"))
                expected = str(fact.attributes["expected"])
                actual = str(fact.attributes["actual"])
                findings.append(
                    _finding(
                        tenant_id=fact.tenant_id,
                        policy_id="IG-CYBER-041",
                        severity=Severity.HIGH,
                        title="External behavior probe failed",
                        assets=[fact.asset_id],
                        evidence=[fact.source_event_id],
                        actual=(
                            f"External probe {probe} from {vantage} returned "
                            f"{actual}; expected {expected}"
                        ),
                        worst_case=(
                            "Users at the observed vantage may be unable to reach or correctly "
                            "use the service"
                        ),
                        changed=fact.changed,
                        assumptions=[
                            "The probe vantage and expected result match the monitored service"
                        ],
                        recommended_next_action=(
                            "Repeat once from an independent authorized vantage and preserve "
                            "transport-level evidence"
                        ),
                        **_fact_context(fact),
                    )
                )
            elif fact.fact_type == "baseline-disposition":
                disposition = str(fact.attributes.get("disposition", "unknown"))
                baseline_policy: dict[str, tuple[Severity, str, str, str]] = {
                    "approved-exception": (
                        Severity.LOW,
                        "Approved baseline exception remains active",
                        "The asset is accepted only under an explicit exception",
                        "Review or expire the exception before valid_until",
                    ),
                    "remediation-required": (
                        Severity.HIGH,
                        "Baseline remediation is required",
                        "The first observed asset does not meet approval policy",
                        "Create a separate scoped remediation proposal",
                    ),
                    "unknown": (
                        Severity.MEDIUM,
                        "Baseline disposition is unknown",
                        "The asset has not been approved or prohibited",
                        "Investigate provenance and assign an explicit disposition",
                    ),
                    "unsupported": (
                        Severity.MEDIUM,
                        "Asset is outside assurance coverage",
                        "Guardian cannot currently provide the required assurance",
                        "Add a supported adapter or record the residual coverage gap",
                    ),
                    "prohibited": (
                        Severity.CRITICAL,
                        "Prohibited asset observed",
                        "Policy explicitly prohibits this observed asset",
                        "Escalate for separate authorized containment and evidence preservation",
                    ),
                }
                if disposition in baseline_policy:
                    severity, title, actual, next_action = baseline_policy[disposition]
                    findings.append(
                        _finding(
                            tenant_id=fact.tenant_id,
                            policy_id="IG-CYBER-050",
                            severity=severity,
                            title=title,
                            assets=[fact.asset_id],
                            evidence=[fact.source_event_id],
                            actual=actual,
                            worst_case=(
                                "Unreviewed or excepted baseline state may preserve a latent "
                                "control weakness"
                            ),
                            changed=fact.changed,
                            recommended_next_action=next_action,
                            **_fact_context(fact),
                        )
                    )

        required = {"trigger", "assembly", "network-egress"}
        for group, facts in sorted(fragment_groups.items()):
            unapproved = [
                fact
                for fact in facts
                if fact.attributes.get("approved") is False
            ]
            capabilities = {
                str(fact.attributes.get("capability"))
                for fact in unapproved
            }
            if required <= capabilities:
                observed_times = {
                    fact.observed_at for fact in unapproved if fact.observed_at is not None
                }
                valid_until_times = {
                    fact.valid_until for fact in unapproved if fact.valid_until is not None
                }
                findings.append(
                    _finding(
                        tenant_id=unapproved[0].tenant_id,
                        policy_id="IG-CYBER-030",
                        severity=Severity.HIGH,
                        title="Fragmented dormant capability correlation",
                        assets=[fact.asset_id for fact in unapproved],
                        evidence=[fact.source_event_id for fact in unapproved],
                        actual=(
                            f"Inert evidence group {group} contains unapproved trigger, "
                            "assembly and network-egress capabilities"
                        ),
                        worst_case=(
                            "If executable and causally connected, the fragments could form "
                            "a concealed outbound access path"
                        ),
                        changed=any(fact.changed for fact in unapproved),
                        truth_status=TruthStatus.INFERRED,
                        confidence="medium",
                        source_trust=SourceTrust.MEDIUM,
                        observed_at=(
                            next(iter(observed_times)) if len(observed_times) == 1 else None
                        ),
                        valid_until=(
                            next(iter(valid_until_times))
                            if len(valid_until_times) == 1
                            else None
                        ),
                        assumptions=[
                            "The shared activation_group represents a meaningful provenance link"
                        ],
                        unresolved_evidence=[
                            "Executability and causal runtime connection are not established"
                        ],
                        recommended_next_action=(
                            "Review provenance, scheduler relationships and observed egress "
                            "without reconstructing or executing the fragments"
                        ),
                    )
                )

        unique = {item["finding_id"]: item for item in findings}
        return sorted(
            unique.values(),
            key=lambda item: (item["policy_id"], item["finding_id"]),
        )
