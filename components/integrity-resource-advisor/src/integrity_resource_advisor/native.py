"""Lazy, read-only bridge to the existing Guardian ModelRouter, not a replacement."""
from __future__ import annotations

from typing import Any

from .core import AdvisoryPolicy, Budget, Calibration, Candidate, NativeView, Stage, advise
from .metering import AdviceError, UsageEvent, identity, matches_document, summarize_usage


def advise_from_guardian(*, signal: Any, route_policy: Any, registry: list[Any],
                         stage: Stage, candidates: tuple[Candidate, ...],
                         calibrations: tuple[Calibration, ...],
                         expected_invocations: tuple[str, ...], events: tuple[UsageEvent, ...],
                         budget: Budget,
                         policy: AdvisoryPolicy = AdvisoryPolicy()) -> dict[str, Any]:
    """Recompute native routing once from the ORIGINAL full registry.

    Native objects and authenticated observations are supplied by the admitted
    host. The original receipt is returned unchanged. Advice has no dispatch API.
    """
    from integrity_guardian.model_router import (
        REASONING_RANK,
        TIER_RANK,
        AlarmSignal,
        CognitiveTier,
        ModelDescriptor,
        ModelRoutePolicy,
        ReasoningClass,
        route_model,
    )

    if type(signal) is not AlarmSignal or type(route_policy) is not ModelRoutePolicy:
        raise AdviceError("native-object-types-required")
    if type(registry) is not list or len(registry) > 256:
        raise AdviceError("native-registry-bound")
    if any(type(model) is not ModelDescriptor for model in registry):
        raise AdviceError("native-descriptor-required")
    if type(stage) is not Stage or (signal.tenant_id, signal.incident_id) != (
            stage.tenant_id, stage.incident_id):
        raise AdviceError("native-stage-scope-mismatch")
    if type(candidates) is not tuple or not 1 <= len(candidates) <= 32:
        raise AdviceError("candidate-budget")
    if any(type(c) is not Candidate for c in candidates):
        raise AdviceError("invalid-candidate")
    receipt = route_model(signal=signal, policy=route_policy, registry=registry)
    ready = receipt["status"] == "ready"
    selected = receipt["selected_model"]
    eligible = []
    baseline_options = []
    descriptors = {model.model_id: model for model in registry}
    budgets = receipt["budgets"]
    peaks_fit = (stage.input_peak <= budgets["max_input_tokens"]
                 and stage.output_peak <= budgets["max_output_tokens"])
    for candidate in candidates:
        config = candidate.configuration
        model = descriptors.get(config.model)
        if not ready or not peaks_fit or model is None:
            continue
        if (not model.available or model.provider != config.provider
                or model.provider not in route_policy.approved_providers
                or (route_policy.local_only and not model.local)):
            continue
        effort = REASONING_RANK[ReasoningClass(config.native_reasoning)]
        if (TIER_RANK[model.capability_tier] < TIER_RANK[CognitiveTier(receipt["required_tier"])]
                or effort < REASONING_RANK[ReasoningClass(receipt["minimum_reasoning"])]
                or effort > REASONING_RANK[model.max_reasoning]):
            continue
        is_baseline = (selected is not None and config.model == selected["model_id"]
                       and config.provider == selected["provider"]
                       and config.native_reasoning == selected["reasoning"])
        if receipt["mandatory"] and not is_baseline:
            continue
        eligible.append(config.key)
        if is_baseline:
            baseline_options.append(config)
    baseline_options.sort(key=lambda config: (
        config.key != stage.current_configuration, config.speed != "standard", config.key,
    ))
    view = NativeView(
        stage.tenant_id, stage.incident_id, ready, receipt["mandatory"],
        baseline_options[0].key if baseline_options else None,
        tuple(sorted(eligible)), receipt["route_id"],
        identity(receipt, "resource-native-recomputation-v1"),
    )
    usage = summarize_usage(root_task_id=stage.root_task_id, unit=budget.unit,
                            expected=expected_invocations, events=events)
    advice = advise(stage=stage, candidates=candidates, calibrations=calibrations,
                    usage=usage, budget=budget, native=view, policy=policy)
    return {"native_route": receipt, "advice": advice}


def verify_from_guardian(expected: dict[str, Any], **inputs: Any) -> dict[str, Any]:
    """Fresh native recomputation, not reuse of a predecessor's advisory view."""
    fresh = advise_from_guardian(**inputs)
    if not matches_document(expected, fresh):
        raise AdviceError("stale-or-substituted-native-advice")
    return fresh
