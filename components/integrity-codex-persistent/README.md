# Integrity Codex Persistent supervisor 0.1.0rc3

**Private source/package candidate. Disabled by default. No live activation.**

This is an attach-only supervisor for one externally admitted Codex app-server
turn. It implements bounded event processing and control feedback, not a full
Persistent launcher. It does not replace Galaxy, PPv4, Memory, the Adapter SDK,
or their signature, one-use grant, journal and independent-witness protocols.

## Implemented

- Explicit per-job Persistent selection for capable worker models only.
  Classifier, curator, synthesis and arbiter roles cannot enable it. There is
  no global environment fallback. Returned config overrides preserve Galaxy's
  disabled native fan-out, finite-goal ownership, `never` local approvals and
  read-only sandbox. They never overwrite managed hooks or canonical MCP.
- Exact thread/turn correlation, typed terminal states and content-free result
  observations. A final_answer item, plan, tool result or interrupt response is
  not turn completion. Protocol completion is not independent acceptance.
- Absolute mission deadline anchored to monotonic time; retained mission token
  usage and thread-baseline accounting; duplicate counters do not double-count.
  Counter rollback fails closed instead of silently replenishing the budget.
- Periodic trusted owner-control checks without model requests. PAUSE, STOP,
  generation change and canonical snapshot change request interruption. Owner
  control is rechecked before publishing a terminal observation.
- Context compaction and model rerouting require host re-admission. Unexpected
  native fan-out is reported and interruption requested, not treated as success.
- Provider usage-limit/fatal-error handling; bounded JSONL frames, strict JSON,
  transport EOF, backpressure, cancellation and explicit unknown outcomes.
- Only `turn/interrupt` and refusal/error responses can leave JsonlConnection.
  There is no thread/turn creation, resume, tool execution or acceptance path.

## Integration boundary

The existing host must supply an already initialized connection, an already
admitted active turn and a control reader backed by the canonical coordinator.
`Binding` and `ControlView` are correlations/observations, **not authorization**.

Before launch, the host still verifies the exact current PPv4 request/receipt
through `PerpetualDialogueTransportAdapter.admit_turn`, ownership/fences, fresh
canonical memory, model capability and every required action grant. Admission
checking alone does not atomically consume launch authority. Existing journal,
one-use dispatch and actual effect gates remain required immediately at their
sinks. Do not add `turn/start` to the dormant Codex transport to use this module.

For example, after those host-owned operations, an integration can attach:

```python
from integrity_codex_persistent.connection import JsonlConnection
from integrity_codex_persistent.policy import Binding, Budget, JobPolicy
from integrity_codex_persistent.supervisor import Supervisor

# reader/writer, ids, snapshot, generation, deadline, usage and read_owner_state
# come from the existing host, NOT a model-generated document.
policy = JobPolicy(
    model=verified_model_id,
    enabled=True,
    supported_efforts=verified_model_efforts,
)
supervisor = Supervisor(
    Binding(job_id, thread_id, turn_id, snapshot_id, control_generation),
    Budget(deadline_epoch=mission_deadline, max_tokens=mission_token_budget,
           used_tokens=previous_mission_usage, thread_baseline_tokens=thread_usage),
    policy,
)
observation = await supervisor.run(
    JsonlConnection(reader, writer), read_owner_state,
)
# Append observation.as_dict() to the EXISTING host journal, using its protocol.
# cleanup_required => stop the owned runtime and reconcile; do not replay work.
# protocol_completed => proceed to the existing independent acceptance path.
```

The sample is an integration seam, not a turnkey command or a grant. The
connection must be dedicated or host-demultiplexed; this supervisor is its sole
reader while attached. Initialization/start-response buffering and delivery of
already received events belong to the host. Use a StreamReader limit no greater
than max_frame_bytes. RC2 checks CPython's reader limit; alternative stream
implementations should implement EventConnection with equivalent bounds.

RC2 recognizes the pinned app-server `collabAgentToolCall` and
`subAgentActivity` types as well as the older documented `collabToolCall`
spelling. Such evidence always requires host runtime reconciliation, even after
a parent terminal event. Retained terminal item inventories are inspected too;
a late attachment must not discard children or a context reset it did not stream.
Unknown item types and legacy `thread/compacted` require re-admission.

JSON-RPC envelopes cannot mix request/notification/response fields. Usage and
approval events must identify the exact turn; only MCP elicitation permits the
upstream's optional turn identity. Foreign requests are not answered. Repeated
request identities fail closed instead of receiving another response.

The supervisor never owns or kills a process, closes a shared connection,
reconnects, or creates a new task. On async cancellation it propagates
CancelledError after a bounded interrupt attempt and retains last_observation.
When no matching terminal event is observed, cleanup_required remains true even
if the interrupt was acknowledged. It also remains true after observed native
agent activity or an incomplete, event-budget-limited stream. A parent terminal
notification is not proof that unowned children or skipped effects are cleaned up. The host must prove process/runtime cleanup
and reconcile exact identities before any separately authorized continuation.

## Waiting without wasting model calls

A quiet active turn stays attached until a real event, control change or budget
boundary. Polling the trusted control reader is not polling a model. A read-only
external CI wait should be represented by the existing Galaxy/PPv4 scheduler:
retain the original mission deadline, used tokens, target, snapshot, fence,
last evidence and stop condition there. Start another admitted phase only when
an authorized external result warrants it. This component does not implement a
second scheduler or silently turn an active model turn into a durable wait.

`clock.sleep` inside Codex still uses the original wall deadline. The short
stop_grace_seconds interval is only for observing cancellation, not fresh work.
The stop grace begins at the first stop condition, before any refusal or
interrupt write; backpressure and acknowledgment waiting share that deadline.
Reconciliation after an event flood is limited to 32 extra terminal/ACK frames,
without growing the server-request identity set. Repeated task cancellation
still retains last_observation, and never sends a second interrupt.

The token guard is notification-based and can overshoot; it is not an API-side
hard spending cap, a quota reset mechanism, or a promise of reduced billing.
Every observation explicitly carries `usage_is_lower_bound=true`: zero may mean
no usage notification arrived, not zero cost. The host must reconcile final
usage before using it as an authoritative budget for another phase.

Caller-provided coroutines must be nonblocking and cancellation-cooperative.
An asyncio deadline cannot preempt a callback that blocks the event loop or
suppresses cancellation indefinitely. The existing host's independently owned
process watchdog remains necessary; this library does not claim to replace it.

## Safety limits and next acceptance gates

A read-only sandbox does not, by itself, restrict external MCP writes. Config
suggestions and a model capability list do not prove effective isolation. The
live host must verify effective tool/feature inventory, credentials, egress,
canonical MCP availability, and OS/runtime containment before launch. Observing
an item after it starts cannot prevent its side effect. This is an observer and
interrupt controller, **not an enforcement substitute** for those gates.

RC2 deliberately has no production host binding. Next gates are a reviewed
Galaxy integration, exact pinned Codex interoperability, real-account capability
acceptance, interruption/cleanup races, cold recovery against external retained
checkpoints, and platform-specific evidence. No signature, canonical numeric
completion receipt, independent acceptance, full monorepo test pass or live soak
is supplied by this candidate. A green synthetic peer is not a real LLM run.

## Offline verification

Python 3.11+; runtime has no third-party dependencies. The build backend is
setuptools >=77. With the backend already available:

```sh
python components/integrity-codex-persistent/tools/check_candidate.py
python -m pip wheel --no-index --no-deps --no-build-isolation \
  components/integrity-codex-persistent -w /tmp/persistent-wheel
python -m pip install --no-index --no-deps --no-compile --target /tmp/persistent-installed \
  /tmp/persistent-wheel/integrity_codex_persistent-0.1.0rc3-py3-none-any.whl
python components/integrity-codex-persistent/tools/check_candidate.py \
  --installed /tmp/persistent-installed \
  --wheel /tmp/persistent-wheel/integrity_codex_persistent-0.1.0rc3-py3-none-any.whl
```

Use fresh temporary directories, not an installed runtime. The checker verifies
all declared source files, wheel membership and RECORD hashes. With --installed,
it also verifies actual installed package bytes and exact membership before and
after tests; checking a different pristine wheel is not sufficient. Preexisting
package bytecode is rejected, so install this verification target with
--no-compile. Tests run with isolated, fresh bytecode lookup and checked import
origins. Manifest duplicates, path aliases, symlinked/special payloads and
zero/partial test inventories fail the gate. No credentials or model calls
are needed. Test subprocesses are isolated Python protocol peers with real pipes.
The repository root tests/test_codex_persistent_candidate.py invokes this source
gate through the existing root CI suite; no separate workflow is required.

## Source references

The app-server v2 lifecycle/approval documentation was checked on 2026-09-17:
https://developers.openai.com/codex/app-server/

The audited upstream revision is 787823cf957709b314276646024ec54e1761c089:
https://github.com/openai/codex/tree/787823cf957709b314276646024ec54e1761c089

For event tags and identity fields, the same revision's generated
codex-rs/app-server-protocol/schema/typescript/v2/ThreadItem.ts,
SubAgentActivityKind.ts and ThreadTokenUsageUpdatedNotification.ts take
precedence over older prose/exec-JSONL naming. Tests contain synthetic
protocol-shaped events, not a claim of live backend interoperability.

Local persistent-to-wire effort normalization is Codex's responsibility. This
component passes the local setting `persistent`; it never sends `disabled` as a
substitute API request and does not imply account availability.

Original root license is retained verbatim. No public publication or license
change is part of this private candidate. See UPDATE-RC.md and candidate.json.
