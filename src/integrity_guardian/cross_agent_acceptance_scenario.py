"""Build the deterministic Agent A -> B -> C acceptance artifacts."""

from __future__ import annotations

from typing import Any

from integrity_guardian.cross_agent_acceptance_core import (
    PRIOR_DOMAIN,
    RESULT_DOMAIN,
    TASK_ID,
    CrossAgentAcceptanceError,
    Keys,
    Spec,
    build_leg,
    fixture_keys,
    record_map,
    required,
    verify_leg,
)
from integrity_guardian.hashing import digest_object


def _first(keys: Keys) -> dict[str, Any]:
    task_input = {"kind": "task-input", "left": 17, "right": 25}
    decision = {"kind": "task-decision", "operation": "sum"}
    specs: list[Spec] = [
        ("KNOWN", "read", task_input, None, None),
        (
            "OBSERVED",
            "observation",
            {"kind": "source-observation", "source": "fixture:sum", "status": "present"},
            None,
            None,
        ),
        ("DECIDED", "authority", decision, None, None),
        (
            "KNOWN",
            "append",
            {"kind": "decision-log", "status": "durably-appended"},
            None,
            None,
        ),
        (
            "ACTED",
            "action",
            {"kind": "handoff-action", "successor": "agent:b"},
            None,
            None,
        ),
        (
            "ASSUMED",
            None,
            {"kind": "task-assumption", "statement": "bounded integer addition is exact"},
            None,
            None,
        ),
        (
            "UNKNOWN",
            None,
            {"kind": "external-state", "status": "not-required"},
            None,
            None,
        ),
    ]
    return build_leg(
        keys,
        predecessor="agent:a",
        predecessor_generation=1,
        head_id="head:agent-a-task-start",
        head_digest=digest_object(
            {"task_id": TASK_ID, "state": "started"},
            domain="cross-agent-abc-agent-a-head-v1",
        ),
        successor="agent:b",
        successor_generation=2,
        cursor=10,
        snapshot={"input": task_input, "decision": decision},
        remaining="compute-and-record-result",
        specs=specs,
        minute=0,
        expiry_minutes=(45, 40, 35),
    )


def _continue_b(keys: Keys, first: dict[str, Any]) -> dict[str, Any]:
    admission = verify_leg(
        first,
        predecessor_key=keys.agents["agent:a"],
        successor_key=keys.agents["agent:b"],
        issuer_keys=keys.issuers,
        at_time="2026-08-19T12:10:00Z",
    )
    records = record_map(first["package"])
    _, task_input = required(records, "task-input", "KNOWN")
    _, decision = required(records, "task-decision", "DECIDED")
    required(records, "external-state", "UNKNOWN")
    left, right = task_input.get("left"), task_input.get("right")
    if (
        admission["successor_agent_id"] != "agent:b"
        or decision.get("operation") != "sum"
        or not isinstance(left, int)
        or isinstance(left, bool)
        or not isinstance(right, int)
        or isinstance(right, bool)
    ):
        raise CrossAgentAcceptanceError("Agent B received an invalid task")
    return {
        "kind": "task-result",
        "left": left,
        "operation": "sum",
        "right": right,
        "source_admission_receipt_id": admission["receipt_id"],
        "source_context_digest": first["package"]["context_digest"],
        "source_package_id": first["package"]["package_id"],
        "value": left + right,
    }


def _second(
    keys: Keys,
    first: dict[str, Any],
    result: dict[str, Any],
    chain_link_role: str,
    result_log_role: str,
    digest_override: str | None,
) -> dict[str, Any]:
    actual_digest = digest_object(first["admission"], domain=PRIOR_DOMAIN)
    prior_digest = digest_override or actual_digest
    prior = {
        "kind": "prior-admission",
        "admission_digest": prior_digest,
        "admission_receipt_id": first["admission"]["receipt_id"],
        "context_digest": first["package"]["context_digest"],
        "package_id": first["package"]["package_id"],
    }
    result_digest = digest_object(result, domain=RESULT_DOMAIN)
    specs: list[Spec] = [
        (
            "KNOWN",
            chain_link_role,
            prior,
            first["admission"]["protocol"],
            prior_digest,
        ),
        (
            "VERIFIED",
            "observation",
            {
                "kind": "prior-context-verification",
                "package_id": first["package"]["package_id"],
            },
            None,
            None,
        ),
        ("ACTED", "action", result, None, None),
        (
            "KNOWN",
            result_log_role,
            {
                "kind": "result-log",
                "result_digest": result_digest,
                "status": "durably-appended",
            },
            None,
            None,
        ),
        (
            "UNKNOWN",
            None,
            {"kind": "production-effect", "status": "not-attempted"},
            None,
            None,
        ),
    ]
    return build_leg(
        keys,
        predecessor="agent:b",
        predecessor_generation=2,
        head_id=first["admission"]["receipt_id"],
        head_digest=prior_digest,
        successor="agent:c",
        successor_generation=3,
        cursor=20,
        snapshot={"prior_admission_digest": prior_digest, "result": result},
        remaining="independent-causal-reconstruction",
        specs=specs,
        minute=20,
        expiry_minutes=(50, 45, 40),
    )


def build_acceptance_artifacts(
    *,
    chain_link_role: str = "read",
    result_log_role: str = "append",
    prior_admission_digest_override: str | None = None,
    keys: Keys | None = None,
) -> dict[str, Any]:
    fixture = fixture_keys() if keys is None else keys
    first = _first(fixture)
    result = _continue_b(fixture, first)
    return {
        "first": first,
        "second": _second(
            fixture,
            first,
            result,
            chain_link_role,
            result_log_role,
            prior_admission_digest_override,
        ),
        "result": result,
    }
