"""Provider-neutral cognitive execution receipts for Guardian Atlas.

This module never invokes a model, opens a network connection or stores a
private signing key.  An external executor receives a deterministic request and
returns an agent-signed result receipt.  Atlas L0 verifies the receipt before
advancing durable state.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta
from typing import Any

from .agent_continuity import verify_cognitive_continuation
from .hashing import digest_object
from .schemas import validate
from .signing import Ed25519Signer, TrustedKey, verify_signature


class CognitiveRuntimeError(ValueError):
    """Raised when a cognitive run crosses identity or resource boundaries."""


def _time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except (AttributeError, ValueError) as exc:
        raise CognitiveRuntimeError("cognitive runtime timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise CognitiveRuntimeError("cognitive runtime timestamp requires a timezone")
    return parsed


def _timestamp(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _verify_request_identity(request: dict[str, Any]) -> str:
    validate("cognitive-run-request", request)
    unsigned = deepcopy(request)
    actual_request_id = unsigned["request_id"]
    unsigned["request_id"] = "cognitive-run:pending"
    expected_request_id = (
        "cognitive-run:"
        + digest_object(
            unsigned,
            domain="cognitive-run-request-identity-v1",
        ).split(":", 1)[1]
    )
    if actual_request_id != expected_request_id:
        raise CognitiveRuntimeError("cognitive run request identity mismatch")
    return actual_request_id


def build_cognitive_run_request(
    package: dict[str, Any],
    *,
    requested_at: str,
    output_contract_digest: str,
    max_elapsed_ms: int,
    max_attempts: int,
) -> dict[str, Any]:
    """Build one deterministic, provider-neutral external execution request."""

    package_verification = verify_cognitive_continuation(package)
    requested = _time(requested_at)
    if not 1 <= max_elapsed_ms <= 3_600_000:
        raise CognitiveRuntimeError("run elapsed-time limit is outside the safe range")
    if not 1 <= max_attempts <= 3:
        raise CognitiveRuntimeError("run attempt limit is outside the safe range")
    if not isinstance(output_contract_digest, str):
        raise CognitiveRuntimeError("output contract digest is invalid")

    request: dict[str, Any] = {
        "protocol": "integrity-guardian/cognitive-run-request/v1",
        "request_id": "cognitive-run:pending",
        "package_id": package["package_id"],
        "package_digest": digest_object(
            package,
            domain="cognitive-continuation-package-v1",
        ),
        "tenant_id": package_verification["tenant_id"],
        "module_id": package_verification["module_id"],
        "agent_id": package_verification["agent_id"],
        "agent_key_id": package["agent_key_id"],
        "generation": package_verification["generation"],
        "lease_id": package_verification["lease_id"],
        "route_id": package["route_id"],
        "target_model_id": package_verification["target_model_id"],
        "target_reasoning": package["target_reasoning"],
        "output_contract_digest": output_contract_digest,
        "budgets": deepcopy(package["budgets"]),
        "execution_limits": {
            "max_elapsed_ms": max_elapsed_ms,
            "max_attempts": max_attempts,
        },
        "requested_at": requested_at,
        "deadline_at": _timestamp(requested + timedelta(milliseconds=max_elapsed_ms)),
        "production_authority": False,
    }
    identity = digest_object(
        request,
        domain="cognitive-run-request-identity-v1",
    ).split(":", 1)[1]
    request["request_id"] = f"cognitive-run:{identity}"
    _verify_request_identity(request)
    return request


def verify_cognitive_run_request(
    package: dict[str, Any],
    request: dict[str, Any],
) -> dict[str, Any]:
    """Verify request identity and exact continuation binding."""

    package_verification = verify_cognitive_continuation(package)
    actual_request_id = _verify_request_identity(request)

    expected = {
        "package_id": package["package_id"],
        "package_digest": digest_object(
            package,
            domain="cognitive-continuation-package-v1",
        ),
        "tenant_id": package_verification["tenant_id"],
        "module_id": package_verification["module_id"],
        "agent_id": package_verification["agent_id"],
        "agent_key_id": package["agent_key_id"],
        "generation": package_verification["generation"],
        "lease_id": package_verification["lease_id"],
        "route_id": package["route_id"],
        "target_model_id": package_verification["target_model_id"],
        "target_reasoning": package["target_reasoning"],
        "budgets": package["budgets"],
    }
    for field, value in expected.items():
        if request[field] != value:
            raise CognitiveRuntimeError(
                f"cognitive run request {field} does not match continuation"
            )

    requested = _time(request["requested_at"])
    deadline = _time(request["deadline_at"])
    expected_deadline = requested + timedelta(
        milliseconds=request["execution_limits"]["max_elapsed_ms"]
    )
    if deadline != expected_deadline:
        raise CognitiveRuntimeError("cognitive run request deadline is not exact")
    return {
        "ok": True,
        "request_id": actual_request_id,
        "package_id": package["package_id"],
        "route_id": package["route_id"],
        "target_model_id": package_verification["target_model_id"],
        "production_authority": False,
    }


def sign_cognitive_run_result(
    request: dict[str, Any],
    *,
    status: str,
    executor_id: str,
    executor_version: str,
    observed_model_id: str,
    output_digest: str | None,
    error_code: str | None,
    input_tokens: int,
    output_tokens: int,
    model_calls: int,
    specialist_agents: int,
    attempt_count: int,
    started_at: str,
    finished_at: str,
    agent_signer: Ed25519Signer,
) -> dict[str, Any]:
    """Wrap externally measured execution facts in the stable agent signature."""

    _verify_request_identity(request)
    if request["agent_key_id"] != agent_signer.key_id:
        raise CognitiveRuntimeError("cognitive run signer differs from stable agent")
    unsigned: dict[str, Any] = {
        "protocol": "integrity-guardian/cognitive-run-result/v1",
        "result_id": "cognitive-result:pending",
        "request_id": request["request_id"],
        "request_digest": digest_object(
            request,
            domain="cognitive-run-request-reference-v1",
        ),
        "tenant_id": request["tenant_id"],
        "module_id": request["module_id"],
        "agent_id": request["agent_id"],
        "generation": request["generation"],
        "lease_id": request["lease_id"],
        "route_id": request["route_id"],
        "target_model_id": request["target_model_id"],
        "target_reasoning": request["target_reasoning"],
        "executor_id": executor_id,
        "executor_version": executor_version,
        "observed_model_id": observed_model_id,
        "status": status,
        "output_digest": output_digest,
        "error_code": error_code,
        "usage": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "model_calls": model_calls,
            "specialist_agents": specialist_agents,
        },
        "attempt_count": attempt_count,
        "started_at": started_at,
        "finished_at": finished_at,
        "agent_key_id": agent_signer.key_id,
        "production_authority": False,
    }
    identity = digest_object(
        unsigned,
        domain="cognitive-run-result-identity-v1",
    ).split(":", 1)[1]
    unsigned["result_id"] = f"cognitive-result:{identity}"
    result = agent_signer.sign(unsigned)
    validate("cognitive-run-result", result)
    return result


def verify_cognitive_run_result(
    request: dict[str, Any],
    result: dict[str, Any],
    *,
    agent_key: TrustedKey,
) -> dict[str, Any]:
    """Verify provenance, exact request binding and every execution budget."""

    _verify_request_identity(request)
    validate("cognitive-run-result", result)
    if (
        result["agent_key_id"] != agent_key.key_id
        or result["signature"]["key_id"] != agent_key.key_id
        or not verify_signature(result, agent_key.public_key)
    ):
        raise CognitiveRuntimeError("cognitive run result signature rejected")
    unsigned = deepcopy(result)
    unsigned.pop("signature")
    actual_result_id = unsigned["result_id"]
    unsigned["result_id"] = "cognitive-result:pending"
    expected_result_id = (
        "cognitive-result:"
        + digest_object(
            unsigned,
            domain="cognitive-run-result-identity-v1",
        ).split(":", 1)[1]
    )
    if actual_result_id != expected_result_id:
        raise CognitiveRuntimeError("cognitive run result identity mismatch")

    expected = {
        "request_id": request["request_id"],
        "request_digest": digest_object(
            request,
            domain="cognitive-run-request-reference-v1",
        ),
        "tenant_id": request["tenant_id"],
        "module_id": request["module_id"],
        "agent_id": request["agent_id"],
        "generation": request["generation"],
        "lease_id": request["lease_id"],
        "route_id": request["route_id"],
        "target_model_id": request["target_model_id"],
        "target_reasoning": request["target_reasoning"],
        "agent_key_id": request["agent_key_id"],
    }
    for field, value in expected.items():
        if result[field] != value:
            raise CognitiveRuntimeError(f"cognitive run result {field} does not match request")
    if result["observed_model_id"] != request["target_model_id"]:
        raise CognitiveRuntimeError("cognitive run observed model differs from route")

    started = _time(result["started_at"])
    finished = _time(result["finished_at"])
    requested = _time(request["requested_at"])
    deadline = _time(request["deadline_at"])
    if not requested <= started <= finished <= deadline:
        raise CognitiveRuntimeError("cognitive run time boundary exceeded")
    elapsed_ms = int((finished - started).total_seconds() * 1000)
    if elapsed_ms > request["execution_limits"]["max_elapsed_ms"]:
        raise CognitiveRuntimeError("cognitive run elapsed-time budget exceeded")
    if result["attempt_count"] > request["execution_limits"]["max_attempts"]:
        raise CognitiveRuntimeError("cognitive run attempt budget exceeded")

    usage = result["usage"]
    budgets = request["budgets"]
    limits = {
        "input_tokens": "max_input_tokens",
        "output_tokens": "max_output_tokens",
        "model_calls": "max_model_calls",
        "specialist_agents": "max_specialist_agents",
    }
    for usage_field, budget_field in limits.items():
        if usage[usage_field] > budgets[budget_field]:
            raise CognitiveRuntimeError(f"cognitive run {usage_field} budget exceeded")
    if result["status"] == "completed":
        if result["output_digest"] is None or result["error_code"] is not None:
            raise CognitiveRuntimeError("completed cognitive run result is inconsistent")
        if usage["model_calls"] != 1:
            raise CognitiveRuntimeError("completed cognitive run requires one model call")
    elif result["output_digest"] is not None or result["error_code"] is None:
        raise CognitiveRuntimeError("incomplete cognitive run result is inconsistent")

    return {
        "ok": True,
        "result_id": actual_result_id,
        "request_id": request["request_id"],
        "route_id": request["route_id"],
        "status": result["status"],
        "elapsed_ms": elapsed_ms,
        "usage": deepcopy(usage),
        "production_authority": False,
    }
