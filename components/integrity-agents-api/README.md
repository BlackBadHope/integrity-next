# Integrity Agents API — 0.1.0rc2

**September integration successor — ChangeIntent #201.** See UPDATE-RC.md (not included in public source) for fixes, journal compatibility and exact evidence boundaries. Original RC evidence is historical, not a claim about this successor.

An optional executor adapter in the canonical Integrity monorepo. Implements
ChangeIntent #199 from exact base
`e40b9973fb8864fed29297a8dc61ba41111f5dbf`. This is a separate component/version,
not a Guardian, Seed, Adapter SDK or LTS release. Experience Adapters PR #198 is
untouched. No live provider request, credentials, deployment, merge or signed
release is performed by the development/test workflow.

**This is executable lifecycle/recovery code, not a claim of production
admission.** The HTTP wire is tested with a mocked HTTPS peer. The real SDK
bridge is implemented but its signed grant/permit lifecycle is not certified
for this new component. An application must supply the existing trusted host
coordinator, exact permits, API credentials and independent outcome observer.

## Implemented surfaces

| Surface | Implementation | Important boundary |
|---|---|---|
| Provider lifecycle | `Sessions.start/snapshot/message/cancel/delete` | Actual agents=v1 request construction; no automatic model loop |
| Environment lifecycle | `Sessions.environment_state`, configuration compiler | Session and environment IDs are distinct; no automatic reconstruction of files or exec-server launch |
| Recovery | `Sessions.pages/recover`, `sse_events`, `reconcile` | Full bounded pages, gap awareness, terminal-state protection; provider snapshot is not atomic |
| Functions | `execute_function`, `submit_retained_result` | Only current required_actions, schema-checked arguments, existing SDK gate and retained outputs |
| Crash/replay | `Journal.run_once` | Real SQLite claim-before-call and cached result; unknown outcomes never execute again automatically |
| Export privacy | `context_capsule`, `ExportPolicy` | Exact reviewed bytes and explicit US/non-ZDR opt-in; no PII-detection guarantee |
| Tools/subagents | `compile_session`, `observer_separation` | PTC explicitly disabled by default and for write/approval sessions; no functions in subagents |
| Budget | Journal reservations, `aggregate_usage`, `watchdog_tick` | Unknown usage blocks new billable work; not a provider-enforced dollar ceiling |
| Provider handoff | `handoff_candidate` | Canonical snapshot remains source; no automatic handoff or task closure |
| First workload | `audit_snapshot`, offline demo | Explicit hash-bound files and version/documentation drift; no filesystem crawl or Git-authenticity claim |

`coverage.json` maps every recommendation to code, regression tests and remaining
acceptance. API product comparisons and security tradeoffs are in RUNBOOK.md.
There is no second model SDK/agent loop, no second MCP server and no canonical
memory store. The journal holds operational identities and bounded pending tool
results only, with no authority of its own.

## Run offline

Python 3.11+ and its standard library are sufficient for source tests:

```text
python tools/run_checks.py
```

For the CLI, from this component directory set `PYTHONPATH=src` on POSIX or
`$env:PYTHONPATH = 'src'` on native PowerShell, then run:

```text
python -m integrity_agents_api capabilities
python -m integrity_agents_api demo
```

The demo finds deliberately mismatched version documentation in a synthetic
snapshot. It does not contact OpenAI, read the user's repository, create a
session, spend tokens or claim AI reasoning. CLI exit zero means the offline
transform ran, not that any task was completed by an independent observer.

The separate wheel exposes `integrity-agents`, has no default runtime package
dependencies, and never overwrites/imports the Guardian package during metadata
or offline CLI access. Its build backend is pinned to setuptools 82.0.1.
To verify a wheel from two fresh copies, run `python tools/build_verify.py
--output /absolute/empty/output` with the pinned backend already installed.
No build dependency is downloaded by that script.

## Host integration

1. Build a minimal capsule from a verified canonical snapshot. Approve each exact
   final request body for export under the host's data policy. Do not export raw
   Home, the full Action Log, private user data or a broad filesystem by default.
2. Use `compile_session` for an explicit model and a closed tool catalog.
   Default: no environment, no delegation, no PTC. The returned object uses
   documented Agents API fields, not Responses-only `allowed_callers`.
3. Create a `Journal` in a protected directory OUTSIDE the agent workspace and
   bind its identity/namespace through host configuration. Journal snapshots or
   alternate paths cannot grant another execution: the existing durable SDK
   permit and its pinned authority journal are still required.
4. Construct `OpenAIHTTP` with an explicitly injected server secret, reviewed
   ExportPolicy and host-owned `GuardianGate` factory. The factory must obtain
   genuine SDK proof and a durable permit for the exact request descriptor.
   The library has no fallback signing key, permission boolean or key loader.
5. Construct `Sessions(transport, journal, configuration, catalog)`. Explicitly
   create the session with a bounded local reservation. Read current
   required_actions; dispatch each registered function with another exact SDK
   gate; retain output BEFORE submitting it. No automatic replay exists.
6. Follow events or recover using saved items/turns. For a live UI, open the new
   stream first and buffer bounded events, fetch saved pages, then reconcile.
   The caller owns its event loop; this component starts no background service.
7. Obtain independent target-result evidence through the existing a14 observer.
   Only the existing canonical append process may record completion. No method
   in this component upgrades provider self-report into that state.

Read RUNBOOK.md before enabling an environment, MCP, PTC or subagents. These
options require separate host admission and actual deployment acceptance.

## Known limits, not hidden readiness claims

Real provider/SDK admission, target OS isolation, live environment/MCP testing,
independent security review and owner-signed release are not established by
synthetic tests. The policy compiler deliberately rejects raw stdio MCP and
MCP writes in RC1; use a separately admitted narrow HTTPS read gateway or direct
functions. It does not pretend an unguarded remote MCP call passes through a
local function permit. No automatic exec-server installer/launcher is shipped.

The provider API is beta. Unsupported JSON Schema features, oversized histories,
unknown status/attribution, path ambiguity and unsupported stream events fail
closed or remain explicitly unknown. Run-to-completion, long-term session
retention and reconnect do not restore lost environment side effects.

Local reservations limit this client's admitted *new* work but do not meter or
terminate every internal model/tool/subagent step. API billing is separate from
ChatGPT subscriptions. Unknown usage is never treated as zero. Independent
provider-side spend controls and actual cancellation observation remain needed.

Tests are self-authored and synthetic; Linux/Windows CI checks portability, not
independent security certification. Historical local reports remain unsigned.
No task completion or stable track activation is claimed by this candidate.
