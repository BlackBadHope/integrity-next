"""Local demonstration and bounded stdin planning; no live target commands."""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import replace

from .core import MAX_DOCUMENT_BYTES, Goal, Inquiry, Probe, digest, load_request


def fixture(*, rich: bool = True, bit: bool = True, allowed: bool = True,
            required_basis: str = "synthetic", **budgets: int) -> Inquiry:
    answers = {"old-healthy": False, "old-broken": False, "new-healthy": True, "new-broken": True}
    goal = Goal("goal:version", "tenant:public-6e3cdbebaafc8efa", "service:fixture", "env:fixture", "rev:1",
                "predicate:version-matches", digest("fixture-context"),
                required_basis=required_basis, **budgets)
    common = {"manifest_digest": digest("synthetic-manifest"),
              "operation_digest": digest("synthetic-operation"),
              "response_schema_digest": digest("synthetic-response")}
    probes = (
        Probe("health", "edge:health", "cap:health",
              predictions={w: "1" if w.endswith("healthy") else "0" for w in answers}, **common),
        Probe("structured", "edge:structured", "cap:structured",
              predictions={w: w.split("-")[0] for w in answers},
              availability="available" if rich else "unavailable", **common),
        Probe("predicate-bit", "edge:bit", "cap:bit", cost=2, max_output_bytes=1,
              predictions={w: "1" if a else "0" for w, a in answers.items()},
              availability="available" if bit else "unavailable", **common),
        Probe("ack", "edge:ack", "cap:ack", predictions={w: "ack" for w in answers}, **common),
    )
    # Each fixed predicate has its own operation and response contract identities.
    probes = tuple(replace(p, operation_digest=digest(["operation", p.probe_id]),
                           response_schema_digest=digest(["response", p.probe_id])) for p in probes)
    return Inquiry(goal, answers, probes, task_allowed=allowed)


def run_fixture(inquiry: Inquiry, world: str) -> dict:
    if world not in inquiry.answers:
        raise ValueError("unknown synthetic world")
    for _ in range(inquiry.goal.max_steps):
        if inquiry.plan()["status"] != "PROPOSED":
            break
        binding = inquiry.begin_simulation()
        probe = next(p for p in inquiry.probes if p.probe_id == binding["probe_id"])
        inquiry.receive_simulation(binding, stage="ack")
        inquiry.receive_simulation(binding, stage="synthetic-fact", token=probe.predictions[world])
    return {"plan": inquiry.plan(), "queries": inquiry.steps,
            "independent_real_world_verification": False}


def demos() -> dict:
    result = {"structured": run_fixture(fixture(), "new-broken"),
              "predicate_bit": run_fixture(fixture(rich=False), "new-broken"),
              "health_only": run_fixture(fixture(rich=False, bit=False), "new-broken"),
              "denied": run_fixture(fixture(allowed=False), "new-broken"),
              "witness_required": run_fixture(fixture(required_basis="witnessed"), "new-broken")}
    session = fixture()
    binding = session.begin_simulation()
    session.receive_simulation(binding, stage="unknown")
    result["unknown"] = {"plan": session.plan(), "queries": session.steps}
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("demo", "plan", "fixture"), nargs="?", default="demo")
    args = parser.parse_args()
    try:
        if args.command == "demo":
            result = demos()
        elif args.command == "fixture":
            result = fixture().document()
        else:
            result = load_request(sys.stdin.buffer.read(MAX_DOCUMENT_BYTES + 1)).plan()
        print(json.dumps(result, sort_keys=True, ensure_ascii=True, indent=2))
    except (ValueError, TypeError) as exc:
        print(f"Inquiry rejected: {type(exc).__name__}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
