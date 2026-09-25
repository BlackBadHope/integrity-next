"""Offline synthetic demonstrations; no provider names, network or key discovery."""
from __future__ import annotations

import argparse
from dataclasses import replace
import json

from .core import (
    AdvisoryPolicy, Budget, Calibration, Candidate, Configuration, Interval,
    NativeView, Stage, Workload, advise,
)
from .metering import Rates, Tokens, UsageEvent, identity, summarize_usage


def fixture() -> dict:
    d = "sha256:" + "a" * 64
    strong = Configuration("fixture", "generalist", "r1", "thorough", "high", "standard",
                           "host-r1", ("tools",), 32_000, 4000)
    narrow = Configuration("fixture", "specialist", "r1", "brief", "low", "standard",
                           "host-r1", ("tools",), 32_000, 4000)
    workload = Workload("checked-edits", d, d, d, d, (0, 0, 1, 1), True, ("tools",))
    stage = Stage("tenant:public-6e3cdbebaafc8efa", "incident:synthetic", "task:root", "stage:edit",
                  workload, strong.key, 100, 10, 0, "phase", 1000, 100, d, "synthetic")
    a = Candidate(strong, Tokens(1000, 0, 0, 100), Tokens(1200, 0, 0, 150),
                  Rates(strong.key, "microUNIT", (1_000_000, 100_000, 1_200_000, 5_000_000),
                        0, 200, d), extra_units=Interval(100, 200),
                  latency_ms=Interval(1000, 2000))
    b = Candidate(narrow, a.low_tokens, a.high_tokens,
                  Rates(narrow.key, "microUNIT", (100_000, 10_000, 120_000, 500_000),
                        0, 200, d), extra_units=Interval(100, 200),
                  handoff_units=Interval(50, 100), latency_ms=Interval(500, 1000),
                  handoff_ms=Interval(20, 50), handoff_tokens=200)
    calibrations = tuple(Calibration(c.configuration.key, workload.key, 100, 100, 0, 200, d,
                                     "synthetic") for c in (a, b))
    native = NativeView(stage.tenant_id, stage.incident_id, True, False, strong.key,
                        tuple(sorted((strong.key, narrow.key))), "route:fixture", d)
    usage = summarize_usage(root_task_id=stage.root_task_id, unit="microUNIT", expected=(), events=())
    return dict(stage=stage, candidates=(a, b), calibrations=calibrations, usage=usage,
                budget=Budget("microUNIT", 100_000), native=native, policy=AdvisoryPolicy())


def demos() -> dict:
    base = fixture()
    output = {"checked-edit": advise(**base)}
    for name, change in (
        ("unchanged", {"stage": replace(base["stage"], boundary="unchanged")}),
        ("transfer-too-expensive", {"candidates": (base["candidates"][0], replace(
            base["candidates"][1], handoff_units=Interval(10_000, 20_000)))}),
        ("cold-start", {"calibrations": ()}),
        ("wrong-workload", {"stage": replace(base["stage"], workload=replace(
            base["stage"].workload, complexity=(3, 3, 3, 3)))}),
        ("missing-usage", {"usage": summarize_usage(root_task_id="task:root", unit="microUNIT",
                                                    expected=("request:missing",), events=())}),
        ("budget-exhausted", {"budget": Budget("microUNIT", 1)}),
        ("mandatory-native", {"native": replace(base["native"], mandatory=True,
            eligible=(base["stage"].current_configuration,))}),
    ):
        output[name] = advise(**(base | change))
    event = UsageEvent("request:lost", "task:root", "task:child", base["stage"].current_configuration,
                       "microUNIT", 42, Tokens(None, None, None, None), "unknown",
                       "sha256:" + "b" * 64)
    output["unknown-outcome"] = advise(**(base | {"usage": summarize_usage(
        root_task_id="task:root", unit="microUNIT", expected=(event.invocation_id,), events=(event,))}))
    return {"synthetic": True, "measured_savings": None, "cases": output,
            "fixture_id": identity({k: v["input_digest"] for k, v in output.items()}, "demo-v1")}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--demo", action="store_true", help="run synthetic data-only scenarios")
    args = parser.parse_args()
    if not args.demo:
        parser.print_help()
        return
    print(json.dumps(demos(), ensure_ascii=True, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
