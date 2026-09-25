# Integrity Execution Bridge 0.1.0rc5

**Private source/package candidate. Not installed or activated on any user host.**

ChatGPT is the model; the machine executes concrete operations. This component
provides a real MCP-to-workspace/command bridge without invoking a second LLM.
It synthesizes selected design patterns from six projects, not six complete
applications pasted together. Exact source/license inputs are in UPSTREAMS.json.

```text
ChatGPT developer plugin (not connected by this candidate)
 -> authenticated private ingress
 -> explicit MCP schemas + host-registered task
 -> existing Integrity SDK verification + one-use permit
 -> exact file edit OR Codex app-server command/exec
 -> bounded result / job handle / output cursor
 -> existing Integrity outcome verification and canonical memory
```

## Delivered surface

| Tool | Actual behavior |
|---|---|
| `bridge_info` | Component and catalog identity; configured is not ready or accepted |
| `workspace_read` | UTF-8 slice, full file digest, next character offset; default 8192 chars |
| `workspace_replace` | Expected SHA-256 and exact occurrence count, atomic replacement/readback |
| `command_start` | Exact argv, workspace cwd and absolute bounded deadline; returns a handle |
| `command_read` | New bounded merged stdout/stderr, byte cursor, gap/truncation and exit status |
| `command_write` | Literal stdin with its own operation ID and SDK admission |
| `command_stop` | Owned-process stop request, never an automatic retry or success assertion |

Use `command_start` for installed Python/Git/test/build tools. There is no implicit
shell parsing: invoke an absolute shell explicitly only with separately admitted
argv. New files can be created by an admitted command; the safer edit tool only
replaces existing files. Direct workspace tools reject `.git`, symlinks, hardlinks,
special files, traversal and noncanonical roots. Host prepares one disposable Git
worktree; this component never changes global Git configuration or remote repos
implicitly. Git commit/push are distinct consequential commands, not inferred
from a green test.

## Reuse rather than a new authority system

`SDKInvoker` consumes the existing `integrity_adapter_sdk` facade. It requires
a genuine `AdapterDispatchPermit`, verifies the exact execution envelope against
the host's retained conformance/operation/executor context and descriptor digest,
then consumes the permit before the effect. The host must actually furnish that
evidence; task registration, profile settings and annotations cannot fabricate it.
The bridge rechecks owner control immediately before dispatch. No runtime API
issues grants or changes ACTIVE/PAUSED/STOPPED, generations or snapshots.

`DeliveryCache` is a bounded private SQLite delivery/dedup cache, **not** a competing
signed Action Log or authority ledger. It retains only opaque identities, hashes
and delivery states, not source code, commands or output. Process output is a bounded
in-memory ring. Following a crash, incomplete records become UNKNOWN, output may
be unavailable and registered tasks remain fenced. No read or retry converts
UNKNOWN into a new dispatch. Existing external SDK checkpoints remain necessary:
rollback of this cache alone cannot establish safe replay or authority.

A returned handle is not a completed command; an interrupt ACK is not an exit;
a process exit is not independent success or proof that every descendant is gone.
The host still owes process-tree cleanup/witness evidence. The component never
writes a canonical successful outcome on its own. #215 supervises *model turns*;
this separate component handles *model-free machine operations* and does not
modify or depend on the unpublished Persistent RC.

## Host embedding (explicitly not live acceptance)

The host supplies: one canonical workspace, Task and trusted Control reader,
private DeliveryCache directory/namespace, authenticated principal mapping,
existing SDK evidence factory, and a verified Codex app-server process with
private initialized pipes. `RpcChannel.initialize()` performs the app-server
handshake; `CodexExecutor` sends only `command/exec`, `/write`, `/terminate`.
`turn/start`, `thread/start`, account/config APIs and arbitrary RPC forwarding are
not available. The channel stays resident across separate HTTP calls.

An example trusted-host composition (not an executable grant generator):

```python
channel = RpcChannel(owned_codex_stdout, owned_codex_stdin)
channel.initialize()
backend = CodexExecutor(channel, {
    "type": "workspaceWrite", "writableRoots": [str(worktree)],
    "networkAccess": False, "excludeTmpdirEnvVar": True, "excludeSlashTmp": True,
}, environment=host_reviewed_environment_overrides)
bridge = Bridge(private_cache, backend, SDKInvoker(existing_evidence_factory))
bridge.register(existing_task_binding, Workspace(worktree), read_existing_owner_control)
server = PrivateHTTPServer(Dispatcher(bridge), existing_private_principal_tokens)
# Host owns serving, tunnel authentication, shutdown and independent cleanup.
```

The backend request policy is NOT a sandbox attestation. The host must verify the
actual Codex executable, effective read/write/network policy, empty/controlled
credential environment and platform capability before admitting the adapter.
Codex merges environment overrides; this bridge does not magically remove all
ambient credentials from an incorrectly launched app-server. Prefer a dedicated
VM/container/worktree account. Expected-hash checks and directory descriptors
assume no hostile same-UID writer; they do not solve hostile concurrent filesystem
mutation. Other processes must not share this workspace's mutation ownership.

## MCP / HTTP profile

The implemented profile is **MCP 2025-11-25, stateless Streamable HTTP JSON
responses**: initialize, initialized notification, ping, tools/list and tools/call.
No SSE, prompts/resources, MCP Tasks, modern 2026 negotiation or OAuth issuer is
claimed. Unsupported versions/methods are explicitly rejected. All tool input
schemas are closed and are used unchanged for both discovery and validation.

HTTP binds only 127.0.0.1. Authentication uses host-injected high-entropy bearer
values mapped to principals, not model arguments or URL tokens. Host/Origin,
framing, duplicate security headers and body limits are checked. Requests close
after each response while the backend channel persists. Eight work slots leave
control calls outside the work budget; twelve HTTP connection slots bound ingress.
Slow/hostile ingress can still saturate connection slots: an upstream tunnel/proxy
must implement network-level rate limits. `/healthz` means process liveness only.

The provided server is a private integration adapter, not an internet-facing
production HTTP stack or an automatically deployable public ChatGPT plugin. Use
an independently reviewed private ingress/tunnel and verify the actual tool schema
visible to ChatGPT. No tunnel, browser profile, credentials or account configuration
were created by this RC. Modern protocol integration and real account compatibility
are explicit later gates, not hidden behind successful synthetic tests.

## Limits, cancellation and recovery

The original mission deadline is anchored to monotonic time at host registration.
Each command has a tighter deadline; reads and stop never reset either budget.
A trusted-control watcher requests stops on PAUSE, STOP, expired context or deadline.
Control callbacks must be fast and nonblocking. An independent host watchdog is
still needed to stop a blocked interpreter or terminate escaped process trees.

At most 8 tasks and one mutation owner per workspace; at most 128 retained jobs per
task and 1024 operation records per cache. No silent eviction/reuse of identities.
RPC frames are capped at 256 KiB; file size/output rings at 64 KiB, returned output
at 16 KiB. Truncation is explicit. No unlimited output/timeout flags reach Codex.
Unknown jobs fence further mutations. The host can inspect state and separately
reconcile/re-admit, but no model-facing operation clears a fence.

There is no automatic browser continuation, autonomous planner, fallback to Codex
inference, quota bypass, learned authority or cross-task grant inheritance. A
requested command can itself do expensive work; host policy must bound that work.
The bridge has no inference client; this is not a measurement of an account quota.

## What was actually demonstrated

`tools/demo.py` runs HTTP -> MCP -> bridge -> **real disposable Python processes
and Git**: reproduce a failing addition test, read source, apply the exact patch,
rerun successfully, commit and read the committed file with a separate process.
The demo uses explicitly synthetic authority and a local TEST backend. Separate
pipe tests exercise the actual Codex RPC adapter against a strict protocol peer.
Neither is a live Codex binary, signed SDK admission, real ChatGPT plugin session,
Windows/macOS acceptance or canonical independent outcome verification.

## Offline gates

With Python 3.11+, jsonschema and setuptools already available, no network install:

```sh
python tools/check_candidate.py
python -m pip wheel --no-index --no-deps --no-build-isolation . -w /tmp/bridge-wheel
python -m pip install --no-index --no-deps --no-compile --target /tmp/bridge-installed \
  /tmp/bridge-wheel/integrity_execution_bridge-0.1.0rc5-py3-none-any.whl
python tools/check_candidate.py --installed /tmp/bridge-installed \
  --wheel /tmp/bridge-wheel/integrity_execution_bridge-0.1.0rc5-py3-none-any.whl
```

Use fresh disposable directories. The checker verifies source/installed bytes,
wheel membership/RECORD, test inventory and import origins, before and after tests.
`tests/test_execution_bridge_candidate.py` brings this gate into the existing root
suite, without a workflow change. Source-only tooling/skills are in the source
archive, not the wheel. Do not promote a candidate on a skipped or predecessor CI.

## RC2 repairs and exact verification boundary

RC2 retains the seven-tool surface and all RC1 tests. It fixes failures reproduced
against the unchanged RC1, rather than interpreting the old green CI as proof of
complete coverage. See UPDATE-RC.md for the original pins and observed stages.

- Shutdown closes admission immediately. Actual effect dispatch is ordered against
  shutdown, and task registration after closure is rejected. An approval callback
  cannot execute twice, escape its invocation lifetime, or retarget the backend.
- Current generation/snapshot and read permission are rechecked before returning
  file content or process output. PAUSE can preserve reading the same admitted
  context; stale contexts are rejected. Owned stop remains available independently
  of read/write admission. Concurrent stdin admissions are serialized per job.
- Backend instances have distinct correlation identities and expose copies of
  configuration, not mutable policy dictionaries. The transport property cannot
  be retargeted after construction. These identities are not binary/OS attestations.
  Workspace-write policies require the complete closed sandbox shape and canonical
  writable roots. Cwd/root identity is revalidated after admission, before dispatch.
- Workspaces cannot overlap another workspace or the delivery cache. Cache lock
  files must have private custody, cache closure is idempotent, terminal delivery
  records are immutable, and UNKNOWN cannot become returned/running. Failure to
  persist a command outcome fences later mutations even before the watcher ticks.
- Stop delivery no longer blocks the shared watcher. A valid terminal exit cannot
  be overwritten by a racing stop error; output is frozen after terminal state.
  Exit codes and direct job cursors/stdin are validated. Stop ACK is still not exit
  or process-tree cleanup, and a blocked host still requires its external watchdog.
- MCP errors use a finite public code vocabulary, not raw exception strings. HTTP
  rejects ambiguous content headers, unsupported encodings, invalid Accept values,
  oversized numeric lengths and Expect handshakes. A three-second absolute input
  deadline bounds header/body trickling; it ends before tool execution, not after
  a long command. Ingress rate limiting remains the host/tunnel's responsibility.
- Verification rejects undeclared source bytecode and false/commented versions,
  pins the exact candidate manifest across tests and checks the entire wheel hash,
  not merely a self-consistent RECORD. Installed acceptance requires that exact
  wheel; source and installed payloads are checked again after tests.

Host control/admission callbacks must remain nonblocking. Shutdown can report
`shutdown_requires_host_watchdog` when a previously entered host sink does not
settle within the bounded wait. It does not certify process termination. No
new permission issuer, launcher, retry, inference client or live connection is
introduced by these repairs.

## Next acceptance, in order

1. Reconcile current main/other RCs and verify this exact source artifact.
2. Bind the existing SDK's source conformance/one-use operation and independent
   witness contract to this new adapter. No test fixture may stand in for it.
3. Use a dedicated disposable Linux/WSL environment with an actual pinned Codex
   binary; prove sandbox, permissions, stdin/output, cancellation and crash handling.
4. Connect a private ChatGPT developer plugin to the admitted host and reproduce
   the same failing-test -> repair -> readback loop with the actual selected model.
5. Evaluate native Windows/macOS, modern MCP and optional user interfaces separately.

No merge, signing, public release, private-memory switch-on or machine activation
is part of this source/package RC.
