# Integrity Active Inquiry 0.1.0rc2

**A development-ready source candidate for asking the next useful question.**
Candidate ID: `2026.09.17-active-inquiry.2`. Authority: ChangeIntent #209.
This is optional, offline, and independently packaged. Guardian remains 5.5.1;
no existing product or signed LTS identity is changed.

## RC2 continuation and integration

Read MERGE-HANDOFF.md (not included in public source) before integrating this PR. The RC1
history and evidence remain unchanged. RC2 fixes a reproduced simulation gap:
a native-filtered proposal could be followed by ungated reselection. Use
`begin_from_synapse(inquiry, kernel, context, expected_view_digest=view["view_digest"])`
to refresh the exact native view before reserving the selected simulation. A
changed view, revoked choice or unknown outcome cannot spend another attempt.
This remains offline: it does not implement W1 SDK dispatch.

`tools/merge_preflight.py` is a SOURCE-ONLY developer diagnostic, not packaged
runtime code. It reads explicitly pinned Git objects using a bounded Git child;
it does not merge, fetch, checkout, alter refs, run hooks or authorize a merge.
The component runtime remains dependency-free and without a target executor.

Current verification is in `evidence/rc2-verification.json`. The reports below
with 61 tests and the 18,706-byte wheel are historical RC1 evidence, NOT RC2.

## Start here

From the repository root, without installing this component:

```text
python -I components/integrity-active-inquiry/tests/run_suite.py
python -m pytest tests/test_active_inquiry_component.py -q
```

Build from a disposable clean copy of this component using the pinned local
build dependency, without an index or runtime dependency installation:

```text
python -m pip wheel --no-deps --no-build-isolation --no-index . -w dist
```

After installing the resulting wheel in a disposable test environment:

```text
python -m integrity_active_inquiry demo
python -m integrity_active_inquiry fixture
python -m integrity_active_inquiry plan < inquiry.json
python -I tests/run_suite.py --installed
```

The CLI reads only its explicitly supplied, bounded stdin document. `fixture`
prints a complete valid input. `demo` runs six synthetic conditions. No command
contacts a service, discovers credentials, emits HID input or executes a target
program. The shell redirection above is the caller's ordinary CLI usage, not a
shell launched by this package.

## One useful question, not full machine inventory

The example model contains four worlds: old/new version times healthy/broken.
The goal is whether the version matches. A structured version response and a
one-bit version predicate can settle it; a health indicator cannot. Two worlds
may remain after answering the goal. This is intentional: full state recovery
is neither needed nor claimed.

The model is supplied by the developer. Predictions are not discovered facts.
A token that is compatible with an incomplete model may still describe a
previously unmodeled real system. The component therefore reports
`ANSWERED_IN_MODEL`, not confirmed real-world success. Even a requested
`witnessed` basis cannot be satisfied by local synthetic observations.

## Five capabilities, one narrow component

| Direction | Executable source foundation | Still requires separate integration |
| --- | --- | --- |
| Learn how to ask | Finite model, goal-relative disagreement ranking, reasons for exclusion, adaptive next step | Discovery of real application contracts and evidence of model adequacy |
| Compute near data | Fixed predicate/manifest/response references; aggregate cost, reserved time and token-byte budgets | Admitted fixed executor, real deadline/transport enforcement and private custody |
| Add observability | Inert predicate/readback request; exact unknown operation reference | Separate approval, implementation and verification of the new readback channel |
| Reuse experience | Conditional recipe candidate, environment/catalog expiry and compatibility checks | Existing a7/a8 Toolz feedback, real witnessed evidence and multi-agent acceptance |
| Ask a person narrowly | Exact subject/predicate question and attributed, bounded human report | UI delivery and policy-approved use of that report as evidence |

## Public source APIs

`Goal` binds goal, tenant, subject, environment/revision, predicate, current
context digest, required basis and budgets. `Probe` binds the reviewed catalog
entry to a native edge/capability, adapter manifest, fixed operation and response
contract. None of these references are a permit or an authenticated signature.

`Inquiry.plan()` returns a versioned, hashed proposal or a terminal explanation.
With no supplied gate it uses declared synthetic fixture availability. The
actual read-only integration is `capture_context(kernel, context)` followed by
`select_from_synapse(inquiry, kernel, context)`: it reuses the existing native
zero-hop route's context digest, consumes `available_moves`, cross-checks
`explain_edge`, and preserves native risk/authority ordering. It cannot dispatch.
The host must supply a trusted actual Synapse instance. A Python Protocol and
matching strings do not authenticate the host or a remote response.

`begin_simulation()` and `receive_simulation()` are deliberately named synthetic
methods. They reserve budgets before recording an in-memory start, bind every
response to the exact session, request, operation, model and contracts, and
keep ACK/ready/completed distinct from an observed fact. They are NOT alternate
SDK lifecycle methods. All canonical stores, one-use grants and witnesses
remain outside this component.

`observation_request()`, `human_question()`, `human_report()`,
`recipe_candidate()`, `recipe_compatibility()` and `capsule()` create inert
views. Recipes contain conditions and evidence references, not permanent
instructions. Compatible means eligible for fresh planning checks, not true,
trusted, admitted or executable. Capsules never truncate unknown status or
reconciliation identity to fit a byte limit; they fail explicitly instead.

## Deterministic choice and bounded resources

At most 64 model worlds and 32 probes are accepted. JSON is capped at 256 KiB;
duplicate keys, including escaped duplicates, nonfinite numbers, extra fields,
invalid digests, booleans posing as integers and incomplete model tables are
rejected. `schemas/inquiry.schema.json` supplies the closed structural grammar;
runtime also enforces cross-field invariants and UTF-8 byte limits.

Candidate selection first excludes unavailable, denied, undeclared/proposed,
already observed and non-discriminating probes. The Synapse bridge additionally
restricts candidates to current native eligibility and read-only transition
classes. Among remaining candidates, native safety/authority ordering dominates
minimax remaining goal disagreement, gain/cost and stable identity. No estimated
probability or claimed POMDP optimum is used. The union of eligible probe
signatures is checked before starting: indistinguishable opposite answers
produce `NEEDS_OBSERVATION` rather than blind attempts.

Budgets cover count, integer cost, reserved worst-case duration and response
TOKEN payload bytes. They are conservative in-memory reservations; there is no
refund on missing results. They are not a running I/O watchdog or a complete
transport-frame budget. Actual SDK host budgets and cumulative disclosure
policy are mandatory before any real probe is admitted.

## Outcomes and limits

`PROPOSED` is not dispatched. `WAITING` is not success. `TASK_DENIED` cannot be
circumvented via another probe or human delegation. `NEEDS_OBSERVATION` means
the supplied eligible model cannot settle the predicate. `BUDGET_EXHAUSTED`
is distinct from denial. ACK, executor readiness and completion never narrow
the fact set. Unknown, model-mismatch, payload-limit and event-limit outcomes
retain the current operation identity and stop this simulation without retry.
Real reconciliation must use the SDK's existing exact operation path; it must
not rerun this in-memory simulation as permission to repeat a target action.

No durable crash/replay registry, real target or real independent witness is
implemented here. Deliberate corruption by same-process Python callers is not
contained. A digest proves stable identity, not factual truth. A separate
process or another agent name does not alone prove independent administration.

See DEVELOPMENT.md for complete acceptance gates, THREAT-MODEL.md for adverse
cases and coverage.json for the mapping of all requirements. Actual local
commands and input hashes are in evidence/source-verification.json. Hosted
results must be attached to the exact Git head in the PR; predecessor tests
must never certify successor bytes.

## Integration anchors at the input pin

Input: `integrity-project/integrity-guardian@d6b57bed832401690628a03c78e9552c03dabc68`.
Read root AGENTS.md and DESIGN-PHILOSOPHY.md, then `src/integrity_guardian/synapse.py`,
`docs/SYNAPSE-KERNEL.md`, `docs/ADAPTER-SDK.md`, the closed
`adapter-capability-manifest.schema.json` and `toolz-route-memory-receipt.schema.json`.
The native route-memory schema read at this pin has synthetic-only scope;
it cannot be relabeled as a live universal memory contract.

Rollback affects only this uninstalled new component and its root index/test.
Keep the PR draft. No merge, Stable activation, tag, signature, deployment,
paid review, provider call, public release or canonical completion is implied.
