"""Evidence-calibrated, authority-free allocation advice. No model or target I/O."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from fractions import Fraction
import math
from typing import Any

from .metering import (
    AdviceError, Rates, Tokens, UsageSummary, digest, identity, integer, matches_document, symbol,
)


@dataclass(frozen=True)
class Interval:
    low: int
    high: int

    def __post_init__(self) -> None:
        integer(self.low)
        integer(self.high, self.low)

    def plus(self, other: Interval) -> Interval:
        return Interval(self.low + other.low, self.high + other.high)


ZERO = Interval(0, 0)


@dataclass(frozen=True)
class Configuration:
    provider: str
    model: str
    revision: str
    effort: str
    native_reasoning: str
    speed: str
    host_revision: str
    capabilities: tuple[str, ...]
    context_window: int
    output_limit: int

    def __post_init__(self) -> None:
        for name in (self.provider, self.model, self.revision, self.effort,
                     self.speed, self.host_revision):
            symbol(name)
        if self.native_reasoning not in ("minimal", "low", "medium", "high", "maximum"):
            raise AdviceError("unmapped-native-reasoning")
        if type(self.capabilities) is not tuple or len(self.capabilities) > 32:
            raise AdviceError("invalid-capabilities")
        for name in self.capabilities:
            symbol(name)
        if self.capabilities != tuple(sorted(set(self.capabilities))):
            raise AdviceError("noncanonical-capabilities")
        integer(self.context_window, 1)
        integer(self.output_limit, 1, self.context_window)

    @property
    def key(self) -> str:
        return identity(asdict(self), "resource-configuration-v1")


@dataclass(frozen=True)
class Workload:
    family: str
    environment_digest: str
    tools_digest: str
    evaluator_digest: str
    instructions_digest: str
    # Owner/host assessment: novelty, ambiguity, coupling, consequence of error.
    complexity: tuple[int, int, int, int]
    reliable_verifier: bool
    capabilities: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        symbol(self.family)
        for value in (self.environment_digest, self.tools_digest, self.evaluator_digest, self.instructions_digest):
            digest(value)
        if type(self.complexity) is not tuple or len(self.complexity) != 4:
            raise AdviceError("invalid-complexity-profile")
        for value in self.complexity:
            integer(value, 0, 3)
        if type(self.reliable_verifier) is not bool:
            raise AdviceError("invalid-verifier-assessment")
        if (type(self.capabilities) is not tuple or len(self.capabilities) > 32
                or self.capabilities != tuple(sorted(set(self.capabilities)))):
            raise AdviceError("invalid-required-capabilities")
        for value in self.capabilities:
            symbol(value)

    @property
    def key(self) -> str:
        # No permanent model ladder; comparable work is defined by these inputs.
        return identity(asdict(self), "resource-calibration-scope-v1")


@dataclass(frozen=True)
class Stage:
    tenant_id: str
    incident_id: str
    root_task_id: str
    stage_id: str
    workload: Workload
    current_configuration: str
    now: int
    checkpoint: int
    last_switch_checkpoint: int
    boundary: str
    input_peak: int
    output_peak: int
    context_digest: str
    evidence_mode: str = "measured"

    def __post_init__(self) -> None:
        for value in (self.tenant_id, self.incident_id, self.root_task_id, self.stage_id):
            symbol(value)
        if not self.tenant_id.startswith("tenant:") or not self.incident_id.startswith("incident:"):
            raise AdviceError("noncanonical-native-scope")
        if type(self.workload) is not Workload:
            raise AdviceError("invalid-workload")
        digest(self.current_configuration)
        digest(self.context_digest)
        integer(self.now)
        integer(self.checkpoint)
        integer(self.last_switch_checkpoint, 0, self.checkpoint)
        integer(self.input_peak, 1)
        integer(self.output_peak, 1)
        if self.boundary not in ("entry", "phase", "checkpoint", "milestone", "failure",
                                 "drift", "budget", "unchanged"):
            raise AdviceError("invalid-boundary")
        if self.evidence_mode not in ("measured", "synthetic"):
            raise AdviceError("invalid-evidence-mode")


@dataclass(frozen=True)
class Candidate:
    configuration: Configuration
    low_tokens: Tokens
    high_tokens: Tokens
    rates: Rates | None
    extra_units: Interval = ZERO
    handoff_units: Interval = ZERO
    latency_ms: Interval = ZERO
    handoff_ms: Interval = ZERO
    handoff_tokens: int = 0

    def __post_init__(self) -> None:
        if type(self.configuration) is not Configuration:
            raise AdviceError("invalid-configuration")
        if type(self.low_tokens) is not Tokens or type(self.high_tokens) is not Tokens:
            raise AdviceError("invalid-forecast")
        for low, high in zip(self.low_tokens.charged, self.high_tokens.charged, strict=True):
            if low is not None and high is not None and low > high:
                raise AdviceError("inverted-token-forecast")
        if self.rates is not None and (type(self.rates) is not Rates
                                      or self.rates.configuration_id != self.configuration.key):
            raise AdviceError("rate-configuration-mismatch")
        integer(self.handoff_tokens)
        for value in (self.extra_units, self.handoff_units, self.latency_ms, self.handoff_ms):
            if type(value) is not Interval:
                raise AdviceError("invalid-interval")


@dataclass(frozen=True)
class Calibration:
    configuration_id: str
    workload_id: str
    accepted: int
    trials: int
    observed_at: int
    expires_at: int
    evidence_digest: str
    basis: str = "measured"

    def __post_init__(self) -> None:
        for value in (self.configuration_id, self.workload_id, self.evidence_digest):
            digest(value)
        integer(self.trials, 1, 1_000_000)
        integer(self.accepted, 0, self.trials)
        integer(self.observed_at)
        integer(self.expires_at, self.observed_at + 1)
        if self.basis not in ("measured", "synthetic", "self-report"):
            raise AdviceError("invalid-calibration-basis")

    def wilson_bps(self) -> tuple[int, int]:
        """Two-sided 95% Wilson interval, conditional on comparable Bernoulli trials.

        This estimates past-sample uncertainty, not future-task correctness.
        """
        n = self.trials
        p = self.accepted / n
        z2 = 1.96**2
        center = p + z2 / (2 * n)
        radius = 1.96 * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n))
        denominator = 1 + z2 / n
        return (max(0, math.floor((center - radius) / denominator * 10_000)),
                min(10_000, math.ceil((center + radius) / denominator * 10_000)))


@dataclass(frozen=True)
class AdvisoryPolicy:
    minimum_quality_bps: int = 9000
    minimum_trials: int = 30
    minimum_gain_bps: int = 1000
    minimum_gain_units: int = 0
    residence_checkpoints: int = 2

    def __post_init__(self) -> None:
        integer(self.minimum_quality_bps, 1, 10_000)
        integer(self.minimum_trials, 1, 1_000_000)
        integer(self.minimum_gain_bps, 0, 10_000)
        integer(self.minimum_gain_units)
        integer(self.residence_checkpoints, 0, 1000)


@dataclass(frozen=True)
class Budget:
    unit: str
    ceiling: int
    reserved_units: int = 0
    token_ceiling: int | None = None
    reserved_tokens: int = 0
    remaining_latency_ms: int | None = None

    def __post_init__(self) -> None:
        symbol(self.unit)
        for value in (self.ceiling, self.reserved_units, self.reserved_tokens):
            integer(value)
        for value in (self.token_ceiling, self.remaining_latency_ms):
            if value is not None:
                integer(value)


@dataclass(frozen=True)
class NativeView:
    """A recomputed gate view in native.py; never an execution envelope."""

    tenant_id: str
    incident_id: str
    ready: bool
    mandatory: bool
    baseline_configuration: str | None
    eligible: tuple[str, ...]
    native_route_id: str
    native_inputs_digest: str

    def __post_init__(self) -> None:
        symbol(self.tenant_id)
        symbol(self.incident_id)
        symbol(self.native_route_id)
        digest(self.native_inputs_digest)
        if type(self.ready) is not bool or type(self.mandatory) is not bool:
            raise AdviceError("invalid-native-state")
        if (type(self.eligible) is not tuple or len(self.eligible) > 32
                or self.eligible != tuple(sorted(set(self.eligible)))):
            raise AdviceError("invalid-native-eligibility")
        for value in self.eligible:
            digest(value)
        if self.baseline_configuration is not None:
            digest(self.baseline_configuration)
            if self.baseline_configuration not in self.eligible:
                raise AdviceError("native-baseline-not-eligible")
        if not self.ready and (self.eligible or self.baseline_configuration is not None):
            raise AdviceError("pending-native-selection")


def _future_cost(candidate: Candidate, stage: Stage) -> tuple[Interval | None, Interval]:
    switching = candidate.configuration.key != stage.current_configuration
    elapsed = candidate.latency_ms.plus(candidate.handoff_ms if switching else ZERO)
    if candidate.rates is None:
        return None, elapsed
    low = candidate.rates.quote(candidate.low_tokens,
                                configuration_id=candidate.configuration.key, now=stage.now)
    high = candidate.rates.quote(candidate.high_tokens,
                                 configuration_id=candidate.configuration.key, now=stage.now)
    if low is None or high is None:
        return None, elapsed
    cost = Interval(low, high).plus(candidate.extra_units)
    return cost.plus(candidate.handoff_units if switching else ZERO), elapsed


def advise(*, stage: Stage, candidates: tuple[Candidate, ...],
           calibrations: tuple[Calibration, ...], usage: UsageSummary,
           budget: Budget, native: NativeView,
           policy: AdvisoryPolicy = AdvisoryPolicy()) -> dict[str, Any]:
    """Pure bounded decision. Use advise_from_guardian for actual native recomputation.

    The caller is responsible for authenticating observations and a complete usage
    inventory. Output is a suggestion even when all input records are genuine.
    """
    if any(type(value) is not kind for value, kind in (
            (stage, Stage), (usage, UsageSummary), (budget, Budget),
            (native, NativeView), (policy, AdvisoryPolicy))):
        raise AdviceError("invalid-request-type")
    if type(candidates) is not tuple or not 1 <= len(candidates) <= 32:
        raise AdviceError("candidate-budget")
    if type(calibrations) is not tuple or len(calibrations) > 256:
        raise AdviceError("calibration-budget")
    if any(type(c) is not Candidate for c in candidates):
        raise AdviceError("invalid-candidate")
    by_id = {c.configuration.key: c for c in candidates}
    if len(by_id) != len(candidates):
        raise AdviceError("duplicate-configuration")
    if (usage.root_task_id != stage.root_task_id or usage.unit != budget.unit
            or native.tenant_id != stage.tenant_id or native.incident_id != stage.incident_id):
        raise AdviceError("advice-scope-mismatch")
    if not set(native.eligible).issubset(by_id):
        raise AdviceError("native-unknown-configuration")
    evidence: dict[tuple[str, str], Calibration] = {}
    for item in calibrations:
        if type(item) is not Calibration:
            raise AdviceError("invalid-calibration")
        key = (item.configuration_id, item.workload_id)
        if key in evidence and evidence[key] != item:
            raise AdviceError("conflicting-calibration")
        evidence[key] = item
    fingerprint = identity({
        "stage": asdict(stage), "candidates": [asdict(by_id[k]) for k in sorted(by_id)],
        "calibrations": [asdict(evidence[k]) for k in sorted(evidence)],
        "usage": asdict(usage), "budget": asdict(budget), "native": asdict(native),
        "policy": asdict(policy),
    }, "resource-advice-input-v1")
    evaluations: list[dict[str, Any]] = []

    def finish(status: str, selected: str | None, reasons: list[str]) -> dict[str, Any]:
        result = {
            "protocol": "integrity-resource-advisor/advice/v1",
            "status": status, "configuration_id": selected,
            "current_configuration_id": stage.current_configuration,
            "input_digest": fingerprint, "native_route_id": native.native_route_id,
            "workload_id": stage.workload.key, "usage_digest": usage.input_digest,
            "unit": budget.unit, "known_spent_units": usage.known_amount,
            "amount_complete": usage.amount_complete, "tokens_complete": usage.tokens_complete,
            "unknown_operations": list(usage.unknown_operations),
            "missing_invocations": list(usage.missing_invocations),
            "reason_codes": sorted(set(reasons)), "evaluations": evaluations,
            "evidence_mode": stage.evidence_mode, "advisory_only": True,
            "execution_authority": False, "observed_switch": False,
            "independent_verification": False,
        }
        return {"advice_id": identity(result, "resource-advice-v1"), **result}

    if usage.unknown_operations:
        return finish("RECONCILE_REQUIRED", None, ["unknown-outcome-is-not-routing-failure"])
    if not native.ready:
        return finish("NATIVE_PENDING", None, ["native-policy-not-ready"])
    if not usage.amount_complete or (budget.token_ceiling is not None and not usage.tokens_complete):
        return finish("USAGE_UNKNOWN", None, ["accounting-incomplete-no-zero-imputation"])
    if usage.known_amount + budget.reserved_units > budget.ceiling:
        return finish("BUDGET_CONFLICT", None, ["cumulative-budget-exceeded"])

    feasible: dict[str, tuple[Interval, tuple[int, int] | None, Interval]] = {}
    qualified: dict[str, tuple[Fraction, Fraction]] = {}
    for key in sorted(by_id):
        candidate = by_id[key]
        config = candidate.configuration
        reasons = []
        if key not in native.eligible:
            reasons.append("native-ineligible")
        if not set(stage.workload.capabilities).issubset(config.capabilities):
            reasons.append("capability-missing")
        if (stage.input_peak + stage.output_peak > config.context_window
                or stage.output_peak > config.output_limit):
            reasons.append("context-capacity")
        if (candidate.high_tokens.input_total is not None
                and candidate.high_tokens.input_total < stage.input_peak):
            reasons.append("forecast-below-input-peak")
        if candidate.high_tokens.output is not None and candidate.high_tokens.output < stage.output_peak:
            reasons.append("forecast-below-output-peak")
        if candidate.rates is not None and candidate.rates.unit != budget.unit:
            reasons.append("incomparable-cost-unit")
        cost, elapsed = _future_cost(candidate, stage)
        if cost is None:
            reasons.append("cost-unknown-or-stale")
        elif usage.known_amount + budget.reserved_units + cost.high > budget.ceiling:
            reasons.append("forecast-budget-exceeded")
        if budget.remaining_latency_ms is not None and elapsed.high > budget.remaining_latency_ms:
            reasons.append("latency-budget-exceeded")
        if budget.token_ceiling is not None:
            total = candidate.high_tokens.total
            if total is None:
                reasons.append("token-forecast-unknown")
            elif (usage.known_tokens + budget.reserved_tokens + total
                  + (candidate.handoff_tokens if key != stage.current_configuration else 0)
                  > budget.token_ceiling):
                reasons.append("token-budget-exceeded")
        item = evidence.get((key, stage.workload.key))
        quality = None
        quality_reason = "quality-evidence-missing"
        if item is not None:
            if item.basis != stage.evidence_mode:
                quality_reason = "quality-basis-mismatch"
            elif not item.observed_at <= stage.now < item.expires_at:
                quality_reason = "quality-stale-or-future"
            elif item.trials < policy.minimum_trials:
                quality_reason = "quality-sample-too-small"
            elif not stage.workload.reliable_verifier:
                quality_reason = "verifier-inadequate"
            else:
                quality = item.wilson_bps()
                quality_reason = ("quality-supported" if quality[0] >= policy.minimum_quality_bps
                                  else "quality-below-floor")
        evaluations.append({
            "configuration_id": key, "rejected": sorted(reasons),
            "quality_reason": quality_reason, "wilson_bps": None if quality is None else list(quality),
            "estimated_forward_units": None if cost is None else asdict(cost),
            "estimated_latency_ms": asdict(elapsed),
        })
        if not reasons and cost is not None:
            feasible[key] = cost, quality, elapsed
            if quality_reason == "quality-supported" and quality is not None:
                qualified[key] = (Fraction(cost.low * 10_000, quality[1]),
                                  Fraction(cost.high * 10_000, quality[0]))

    # Mandatory native routing cannot be replaced by an economic recommendation.
    if native.mandatory:
        key = native.baseline_configuration
        if key not in feasible:
            return finish("NATIVE_BASELINE_UNAVAILABLE", None,
                          ["mandatory-route-preserved", "missing-cost-capacity-or-budget"])
        return finish("NATIVE_BASELINE", key,
                      ["mandatory-route-preserved", "quality-not-certified-by-routing"])

    current = stage.current_configuration
    if not qualified:
        baseline = current if current in feasible else native.baseline_configuration
        if baseline in feasible and feasible[baseline][1] is None:
            return finish("BASELINE_NEEDS_EVIDENCE", baseline,
                          ["no-proven-cheaper-choice", "not-a-quality-pass"])
        return finish("NO_SUPPORTED_CHOICE", None, ["no-configuration-meets-evidence-and-budget"])
    best = min(qualified, key=lambda k: (qualified[k][1], feasible[k][2].high, k))
    if current not in qualified:
        # Replacing a failed/ineligible/unproven configuration is not advertised as savings.
        return finish("RECOMMEND", best, ["evidence-supported-choice", "savings-not-established"])
    if best == current:
        return finish("RETAIN", current, ["current-choice-remains-supported"])
    if stage.boundary == "unchanged":
        return finish("RETAIN", current, ["no-meaningful-boundary"])
    urgent = stage.boundary in ("failure", "drift", "budget")
    if not urgent and stage.checkpoint - stage.last_switch_checkpoint < policy.residence_checkpoints:
        return finish("RETAIN", current, ["switch-residence-hysteresis"])
    # Require pessimistic challenger score to beat optimistic incumbent score.
    gain = qualified[current][0] - qualified[best][1]
    threshold = max(Fraction(policy.minimum_gain_units),
                    qualified[current][0] * Fraction(policy.minimum_gain_bps, 10_000))
    if gain <= 0 or gain < threshold:
        return finish("RETAIN", current, ["switch-benefit-not-robust-after-overhead"])
    return finish("RECOMMEND", best,
                  ["bounded-estimate-advantage", "switch-and-verification-costs-included",
                   "future-savings-not-guaranteed"])


def verify_advice(expected: dict[str, Any], **inputs: Any) -> dict[str, Any]:
    """Recompute ALL inputs before use; a hash alone is not a validity proof."""
    fresh = advise(**inputs)
    if not matches_document(expected, fresh):
        raise AdviceError("stale-or-substituted-advice")
    return fresh
