# Integrity Resource Advisor 0.1.0rc6

> Current continuation: **0.1.0rc6**, source candidate **2026.09.19-resource-advisor.7**. Bounded read-only Codex model/rate-limit discovery and one exact local PM-thread usage reader are implemented; real admitted dispatch and end-to-end acceptance are still
> required by the owner IN THIS PR. Earlier RC2 validation below is historical.
> See CODEX-INTEGRATION.md (not included in public source) and the current
> residual review (not included in public source).

**Choose computing effort for the work, not work for the largest model.**
This optional, dependency-free Python component provides deterministic advice
about a stage's model, effort and speed. It performs no provider call and changes
no model setting. The existing Guardian ModelRouter and permissions remain intact.

Status: intermediate source RC. Real transport, authenticated calibration custody
and admitted host switching remain required IN THIS PR for the owner's end-to-end
request. The capture reader is implemented, not the full working loop. No measured
live saving, universal optimality or independent certification is claimed.

Run the bounded discovery client with an exact trusted executable path:

```sh
python -m integrity_resource_advisor.app_server_snapshot --codex /exact/path/to/codex --timeout 30
```

It starts one owned stdio process with MCP servers, hooks, notify commands and
analytics disabled for that child. Its code allowlist permits only `initialize`,
paginated `model/list`, and `account/rateLimits/read`. Missing limit values remain
unknown. The output is not task usage, quality evidence, or dispatch authority.

Read one explicitly selected local PM rollout without starting or resuming a turn:

```sh
python -m integrity_resource_advisor.rollout_usage \
  --rollout /exact/path/to/rollout.jsonl --thread-id EXACT_THREAD_ID
```

The command fixes the byte boundary before reading, requires the rollout's
`session_meta.id` to match, and emits only identifiers, writer metadata, counters,
completeness and a snapshot digest. Save that JSON and its digest outside Git.
For a later delta, pass them back with `--checkpoint` and `--pin`; write the new
stdout to a different temporary file before replacing the prior checkpoint.
The reader never scans sibling sessions. Local `token_usage_record` companions
are kept distinct from `event_msg/token_count` and ignored to prevent double count.

## Implemented

- Exact provider/model/revision/effort/speed/host configuration identity.
- Workload-specific calibration bound to environment, tools, instructions,
  evaluator and a four-dimensional complexity assessment. No model-name ladder
  or rule assigning implementation to a weak model.
- Quality qualification before cost comparison. Sparse, stale, wrong-scope,
  synthetic-as-measured and self-reported evidence cannot justify downgrading.
- Bounded cost intervals for the remaining stage, verification/rework, transfers
  and context/cache overhead. Switching requires a robust estimated advantage;
  meaningful boundaries and residence hysteresis prevent oscillation.
- Normalization of inclusive/exclusive provider token counters. Cached input and
  reasoning output are not added twice. Missing counters are not zero.
- Cumulative root-task leaf-invocation accounting, including failed calls and
  children, with exact duplicate deduplication and conflicting-record rejection.
- Unknown outcomes retain operation IDs and yield RECONCILE_REQUIRED, not retry.
- A **real lazy bridge** to `integrity_guardian.model_router.route_model`. It
  recomputes the ORIGINAL full registry once, returns the native receipt intact,
  and excludes forbidden providers/locality/tiers/effort/token peaks. Mandatory
  native selection is preserved even when another candidate is cheaper.
- Full-input revalidation, including native policy/registry changes, before
  using advice. Advice is not an authorization lease.

## RC2 result-document compatibility

Advice is a JSON-native document: serialize it, retain it, decode it and call
`verify_advice` or `verify_from_guardian` with freshly reconstructed inputs.
Wilson bounds in the result are lists; `Calibration.wilson_bps()` itself still
returns a tuple. Valid serialized v1 advice bytes/IDs are unchanged by this fix.
Verification checks exact scalar/container types: `true`, `1`, and `1.0` are not
interchangeable. Custom objects cannot supply their own equality decision.
The input is already decoded; a host accepting raw JSON remains responsible for
bounded, duplicate-key-rejecting parsing before invoking this library.

See MERGE-HANDOFF.md (not included in public source) for source-stage acceptance commands.
Live calibration, metering transport and admitted switching remain unfinished
parts of the current deliverable. Installing the optional package does not by
itself satisfy those integration gates.

## Run

From this directory:

```sh
python tests/run_suite.py
PYTHONPATH=src python -m integrity_resource_advisor --demo
```

From an environment with both packages installed:

```python
from integrity_resource_advisor import advise_from_guardian, verify_from_guardian

# inputs supplies native AlarmSignal / ModelRoutePolicy / full registry,
# immutable Stage / Candidate / Calibration data, actual leaf events, the
# complete expected-invocation inventory and the already applicable budget.
proposal = advise_from_guardian(**inputs)
# Rebuild inputs from CURRENT observations before any separate host action.
verified_proposal = verify_from_guardian(proposal, **current_inputs)
```

This example does not imply `inputs` is auto-discovered. There is no credential
lookup, ambient configuration discovery, metering daemon, background benchmark,
provider client, model switch or dispatch callback. `--demo` only uses declared
synthetic data. `advise()` is also available for offline replay; only the native
bridge recomputes genuine native policy, and neither function authenticates its
caller-provided measurement sources.

## Main outcomes

| Status | Meaning |
| --- | --- |
| RETAIN | Current supported choice; insufficient benefit or no meaningful boundary. |
| RECOMMEND | A feasible evidence-supported choice; NOT an observed switch. |
| BASELINE_NEEDS_EVIDENCE | A feasible baseline, without a quality pass or a saving claim. |
| NATIVE_BASELINE | Mandatory original native model/effort preserved; not a quality certificate. |
| NATIVE_PENDING / NATIVE_BASELINE_UNAVAILABLE | Native policy pending, or exact baseline cannot fit supplied resources. |
| USAGE_UNKNOWN / RECONCILE_REQUIRED | Missing accounting / unknown sent-operation outcome. |
| BUDGET_CONFLICT / NO_SUPPORTED_CHOICE | Resource conflict or no supported option; not permission to weaken checks. |

Default thresholds are changeable advisory parameters, not doctrine, mandatory
phase-switching rules or a claim that 90% quality is acceptable for every task.
Costs use an explicit unit (for example micro-USD or micro-credits), never an
implicit conversion between API charges and subscription quota. Latency is a
separate constraint; parallel child durations are not added as wall time.

## Integration and maintenance

Read DESIGN.md (not included in public source), RESEARCH.md (not included in public source), and
THREAT-MODEL.md (not included in public source). In the full monorepo run
`python -m pytest tests/test_resource_advisor_component.py`.
Its native cases use the real Guardian objects, not mocks.

The native optional baseline and an economic recommendation can differ. A host
must not edit `selected_model` in the returned native receipt to apply advice.
Honoring a different configuration needs the existing exact-admission workflow
or a separately reviewed native-policy extension. This RC does not install one.
No default runtime path is changed by installing this optional wheel.

The component is additive to main d6b57bed832401690628a03c78e9552c03dabc68.
It does not depend on merging Active Inquiry #210 or doctrine #217 first and
changes neither branch. It carries its own source inventory. At future merge,
refresh actual refs, run native tests in the prospective combined tree and do
not reuse this candidate's CI as certification of a different tree.
