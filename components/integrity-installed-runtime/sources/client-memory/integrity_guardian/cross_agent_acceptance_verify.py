"""Independently verify and reconstruct the Agent A -> B -> C chain."""

from __future__ import annotations

from typing import Any

from integrity_guardian.canonical import parse_json_strict
from integrity_guardian.cross_agent_acceptance_core import (
    PRIOR_DOMAIN,
    RECEIPT_DOMAIN,
    REPORT_DOMAIN,
    REPORT_PROTOCOL,
    RESULT_DOMAIN,
    ROLES,
    TASK_ID,
    CrossAgentAcceptanceError,
    fixture_trust_anchors,
    record_map,
    required,
    verify_leg,
)
from integrity_guardian.cross_agent_acceptance_scenario import build_acceptance_artifacts
from integrity_guardian.hashing import digest_object


def _statement(record: dict[str, Any]) -> dict[str, Any]:
    value = parse_json_strict(record["statement"])
    if not isinstance(value, dict) or not isinstance(value.get("kind"), str):
        raise CrossAgentAcceptanceError("epistemic statement is invalid")
    return value


def _epistemic(package: dict[str, Any]) -> dict[str, list[str]]:
    summary: dict[str, list[str]] = {}
    for record in package["epistemic_records"]:
        value = _statement(record)
        summary.setdefault(record["classification"], []).append(value["kind"])
    return {name: sorted(kinds) for name, kinds in sorted(summary.items())}


def _causal_history(package: dict[str, Any]) -> list[dict[str, Any]]:
    references = {
        item["reference_id"]: item for item in package["receipt_provenance"]
    }
    history = []
    for record in package["epistemic_records"]:
        reference_id = record["source_reference_id"]
        reference = None if reference_id is None else references.get(reference_id)
        if reference_id is not None and reference is None:
            raise CrossAgentAcceptanceError("causal history receipt reference missing")
        history.append(
            {
                "sequence": record["sequence"],
                "classification": record["classification"],
                "kind": _statement(record)["kind"],
                "actor_id": record["actor_id"],
                "evidence": (
                    None
                    if reference is None
                    else {
                        "receipt_id": reference["receipt_id"],
                        "receipt_type": reference["receipt_type"],
                        "issuer_id": reference["issuer_id"],
                    }
                ),
            }
        )
    return history


def _reference(
    references: dict[str, dict[str, Any]],
    record: dict[str, Any],
    *,
    label: str,
) -> dict[str, Any]:
    reference = references.get(record["source_reference_id"])
    if reference is None:
        raise CrossAgentAcceptanceError(f"{label} receipt reference missing")
    return reference


def verify_acceptance_chain(artifacts: dict[str, Any]) -> dict[str, Any]:
    anchors = fixture_trust_anchors()
    keys = anchors.agents
    issuer_keys = anchors.issuers
    first, second = artifacts["first"], artifacts["second"]
    first_result = verify_leg(
        first,
        predecessor_key=keys["agent:a"],
        successor_key=keys["agent:b"],
        issuer_keys=issuer_keys,
        at_time="2026-08-19T12:10:00Z",
    )
    second_result = verify_leg(
        second,
        predecessor_key=keys["agent:b"],
        successor_key=keys["agent:c"],
        issuer_keys=issuer_keys,
        at_time="2026-08-19T12:30:00Z",
    )
    if any(
        first["package"][field] != second["package"][field]
        for field in ("tenant_id", "module_id", "task_id")
    ):
        raise CrossAgentAcceptanceError("continuity legs do not share one task")
    if (
        first["package"]["successor_agent_id"]
        != second["package"]["predecessor_agent_id"]
        or first["package"]["successor_generation"]
        != second["package"]["predecessor_generation"]
        or second["package"]["successor_agent_id"] != "agent:c"
    ):
        raise CrossAgentAcceptanceError("agent or generation chain mismatch")
    if any(
        record["actor_id"] != expected_actor
        for package, expected_actor in (
            (first["package"], "agent:a"),
            (second["package"], "agent:b"),
        )
        for record in package["epistemic_records"]
    ):
        raise CrossAgentAcceptanceError("epistemic actor chain mismatch")

    prior_digest = digest_object(first["admission"], domain=PRIOR_DOMAIN)
    checkpoint = second["checkpoint"]
    if checkpoint["predecessor_head_id"] != first["admission"]["receipt_id"]:
        raise CrossAgentAcceptanceError("prior admission receipt identity mismatch")
    if checkpoint["predecessor_head_digest"] != prior_digest:
        raise CrossAgentAcceptanceError("prior admission digest mismatch")

    a_records, b_records = record_map(first["package"]), record_map(second["package"])
    _, task_input = required(a_records, "task-input", "KNOWN")
    decision_record, decision = required(a_records, "task-decision", "DECIDED")
    required(a_records, "task-assumption", "ASSUMED")
    required(a_records, "external-state", "UNKNOWN")
    prior_record, prior = required(b_records, "prior-admission", "KNOWN")
    required(b_records, "prior-context-verification", "VERIFIED")
    _, task_result = required(b_records, "task-result", "ACTED")
    result_log_record, result_log = required(b_records, "result-log", "KNOWN")
    required(b_records, "production-effect", "UNKNOWN")

    first_references = {
        item["reference_id"]: item
        for item in first["package"]["receipt_provenance"]
    }
    decision_reference = _reference(
        first_references,
        decision_record,
        label="task decision",
    )
    if (
        decision_reference["receipt_type"] != "authority"
        or decision_reference["issuer_id"] != "issuer:owner"
    ):
        raise CrossAgentAcceptanceError("task decision authority provenance mismatch")

    references = {
        item["reference_id"]: item
        for item in second["package"]["receipt_provenance"]
    }
    prior_reference = _reference(references, prior_record, label="prior admission")
    if prior_reference["receipt_type"] != "read":
        raise CrossAgentAcceptanceError("prior admission causal link requires a read receipt")
    if (
        prior_reference["receipt_protocol"] != first["admission"]["protocol"]
        or prior_reference["receipt_digest"] != prior_digest
    ):
        raise CrossAgentAcceptanceError("prior admission receipt binding mismatch")
    if prior != {
        "kind": "prior-admission",
        "admission_digest": prior_digest,
        "admission_receipt_id": first["admission"]["receipt_id"],
        "context_digest": first["package"]["context_digest"],
        "package_id": first["package"]["package_id"],
    }:
        raise CrossAgentAcceptanceError("prior admission structured link mismatch")

    left, right = task_input.get("left"), task_input.get("right")
    if (
        decision.get("operation") != "sum"
        or not isinstance(left, int)
        or isinstance(left, bool)
        or not isinstance(right, int)
        or isinstance(right, bool)
    ):
        raise CrossAgentAcceptanceError("Agent C cannot reconstruct the operation")
    expected = {
        "kind": "task-result",
        "left": left,
        "operation": "sum",
        "right": right,
        "source_admission_receipt_id": first_result["receipt_id"],
        "source_context_digest": first["package"]["context_digest"],
        "source_package_id": first["package"]["package_id"],
        "value": left + right,
    }
    if task_result != expected or artifacts["result"] != expected:
        raise CrossAgentAcceptanceError(
            "Agent B result is not derived from admitted context"
        )
    result_digest = digest_object(expected, domain=RESULT_DOMAIN)
    if result_log != {
        "kind": "result-log",
        "result_digest": result_digest,
        "status": "durably-appended",
    }:
        raise CrossAgentAcceptanceError("durable result receipt does not match output")
    result_reference = _reference(references, result_log_record, label="result log")
    expected_result_receipt_digest = digest_object(
        {"actor": "agent:b", "role": "append", "statement": result_log},
        domain=RECEIPT_DOMAIN,
    )
    if (
        result_reference["receipt_type"] != "append"
        or result_reference["receipt_protocol"]
        != "integrity-guardian/append-receipt/v1"
        or result_reference["receipt_digest"] != expected_result_receipt_digest
    ):
        raise CrossAgentAcceptanceError("result log requires the exact append receipt")

    receipt_ids = [
        {item["receipt_id"] for item in leg["package"]["receipt_provenance"]}
        for leg in (first, second)
    ]
    if receipt_ids[0] & receipt_ids[1]:
        raise CrossAgentAcceptanceError("receipt identities collide across legs")
    roles = sorted(
        {
            item["receipt_type"]
            for leg in (first, second)
            for item in leg["package"]["receipt_provenance"]
        }
    )
    if roles != ROLES:
        raise CrossAgentAcceptanceError("receipt role coverage is incomplete")

    report: dict[str, Any] = {
        "protocol": REPORT_PROTOCOL,
        "result": "PASS",
        "task_id": TASK_ID,
        "agents": ["agent:a", "agent:b", "agent:c"],
        "causal_link": {
            "prior_admission_digest": prior_digest,
            "prior_admission_receipt_id": first["admission"]["receipt_id"],
            "receipt_type": prior_reference["receipt_type"],
            "verified": True,
        },
        "package_ids": [first_result["package_id"], second_result["package_id"]],
        "epistemic_reconstruction": {
            "agent:a": _epistemic(first["package"]),
            "agent:b": _epistemic(second["package"]),
        },
        "causal_history": {
            "agent:a": _causal_history(first["package"]),
            "agent:b": _causal_history(second["package"]),
        },
        "reconstruction": {
            "input": {"left": left, "right": right},
            "operation": "sum",
            "result": left + right,
            "result_digest": result_digest,
        },
        "receipt_roles": roles,
        "authority": {
            "context_admission": "HANDOFF_BOUND",
            "decision_actor_id": decision_record["actor_id"],
            "decision_issuer_id": decision_reference["issuer_id"],
            "read_authority": False,
            "append_authority": False,
            "production_authority": False,
        },
        "hidden_chat_required": False,
        "production_authority": False,
    }
    report["report_digest"] = digest_object(report, domain=REPORT_DOMAIN)
    return report


def run_acceptance() -> dict[str, Any]:
    report = verify_acceptance_chain(build_acceptance_artifacts())
    if report != verify_acceptance_chain(build_acceptance_artifacts()):
        raise CrossAgentAcceptanceError("deterministic replay changed the report")
    return report
