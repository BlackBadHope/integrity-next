# Native memory with lifecycle hooks

This is the complete **client wiring** for the Native lifecycle: an exact owner
prompt, an opaque one-use reference, model-owned admission, a signed registration,
snapshot-bound reads, an authorized append, and a signed terminal receipt. It is
separate from the [four-tool read-only walkthrough](../examples/local-memory/README.md).
The latter cannot perform this lifecycle by adding more allowed tool names.

The profile compiler produces actual commands, source pins, private state paths,
MCP registration and vendor hook configuration. It refuses missing runtime
bindings. `native_runtime verify` checks source and configuration bytes;
`native_runtime probe` imports the real entrypoints and executes the actual
hook/client `initialize` and `tools/list` exchange with the local broker, without
a model or upstream call. It catches incompatible broker versions and missing
sibling catalogues. Neither command is a live acceptance certificate.

Revision 1.9.2 also pins every generated vendor hook/MCP/enable file. Changing
one makes verification fail before launching a hook or broker. Profiles made
by 1.9.1 lack those pins: regenerate them into a new private directory with
1.9.3, review the emitted files, and keep the old profile for rollback. Do not
add hashes by hand to make a changed profile appear accepted.

## Supported owner routes and prerequisites

The supplied Codex and Claude Native ownership adapters target **Windows**.
Codex uses the local Desktop Native tool host. The Claude CLI adapter uses an
enrolled local publisher, its actual CLI ancestor, its delivery ledger and its
full transcript. Antigravity uses its observed native conversation/step boundary.
There is no silent Linux/macOS substitute for a missing Windows owner route.

Install Python 3.11+ and PowerShell 7.3+. Install and sign in to the chosen vendor
through its normal installer. Provider authentication stays with that client.
No API key, subscription, model binary or provider session is distributed here.

You also need an **owner-operated Integrity Memory instance** with the Native
API 2.11 tools, its own catalog, trust material, Action Log witness and lifecycle
store. A source checkout is not such an instance. In particular:

- `personal-native` requires your own Native trust bootstrap, instance and device
  enrollment. Caller-supplied `authority_decision` is refused in that mode.
- `managed-external` requires the chosen architecture keys, Security admission
  bundle and external event authority. A client profile does not create them.
- The Action Log side must accept the `codex`, `claude` and `antigravity` reader
  declarations, including Antigravity's model/vendor join. Updating only a client
  hook cannot repair an older server validator.
- Source namespace, namespace fingerprint and architecture checkpoint ID below
  must be the values from that same instance. Never copy another deployment's
  fingerprints or bypass their checks to make admission succeed.

The core commands for creating a new owner trust store and serving the Native
protocol are `guardian native-trust-bootstrap` and
`guardian-memory-synapse-mcp --trust-profile personal-native`. Their `--help`
lists the required owner paths and instance/device values. A new instance also
needs a configured Action Log append/witness route; this client installer does
not claim to deploy an Action Log service. The boundary is deliberate: ordinary
client configuration must not mint authority over a different instance.

## 1. Install the public client code in a clean environment

From the public repository checkout, in PowerShell:

```powershell
py -3.12 -m venv .venv-native
$nativePython = (Resolve-Path .venv-native/Scripts/python.exe).Path
& $nativePython -m pip install . ./components/integrity-action-log './components/integrity-client-memory[native]'
& $nativePython -m integrity_client_memory.native_install --help
```

Keep generated profiles outside the Git checkout. They contain private paths and
may contain the owner-selected transport environment. Do not commit or publish
them. Use a separate output directory per vendor; existing directories are
refused rather than overwritten.

## 2. Describe your existing server once

Save `upstream.json` in your private configuration directory. It is the exact
stdio command for your own verified Memory instance:

```json
{
  "command": "C:/Integrity/server-venv/Scripts/python.exe",
  "args": ["C:/Integrity/owner-memory-transport.py"],
  "env": {}
}
```

The paths above illustrate the descriptor shape. Select your actual installed
transport, including its required arguments. `command` must name an existing
absolute executable. A remote connection, if your deployment uses one, belongs
in that owner-approved transport; the installer never chooses a host or an SSH
alias for you. Keep credentials in your normal protected store.

Create common bindings from the selected instance's real metadata:

```powershell
$bindings = @{
  seed_namespace = (Read-Host 'Source namespace of your own Memory instance')
  namespace_fingerprint = (Read-Host 'Its signed namespace fingerprint, sha256:...')
  architecture_checkpoint_id = (Read-Host 'Its architecture checkpoint ID')
}
$bindings | ConvertTo-Json | Set-Content -Encoding utf8NoBOM .\bindings.json
```

These are instance bindings, not provider secrets. The compiler checks their
shape and resolves the source dependencies. Admission and the server's signed
receipts still have to establish that they belong together.

If your selected server has a different tools/list catalog, save the exact list
or JSON-RPC tools/list response and pass `--tools-json`. The compiler validates
the original schemas and annotations and requires the Native lifecycle tools.
It never relabels a four-tool reader as a full Native server.

## 3. Connect Codex

Generate the Windows Desktop Native profile:

```powershell
& $nativePython -m integrity_client_memory.native_install `
  --vendor codex --upstream-json .\upstream.json --bindings-json .\bindings.json `
  --output C:\Integrity\clients\codex-native
& $nativePython -m integrity_client_memory.native_runtime `
  --profile C:\Integrity\clients\codex-native\profile.json verify
& $nativePython -m integrity_client_memory.native_runtime `
  --profile C:\Integrity\clients\codex-native\profile.json probe
```

The output contains `codex-workspace/.codex/config.toml` and
`codex-workspace/.codex/hooks.json`. Open that isolated workspace in the local
Codex Desktop first. Review/trust the exact hook definitions using `/hooks` or
the client hook review UI, and trust the project configuration layer. Do not
bypass hook trust. Hooks must be enabled in the active policy; a managed policy
that disables them has to be addressed by its owner.

The MCP server appears as `integrity_native`. The generated config gives its
outer tool boundary 210 seconds.
Both compiled Windows transports (Codex and Claude Code) allow up to 45 seconds for a cold upstream
`initialize`, within the existing request deadline. A failed admission never
instructs the model to invoke its one-use reference again; a pre-send refusal
still has `request_sent=false`. A sent or unknown operation requires receipt
reconciliation. Increasing startup time does not permit extra admissions.

The local hook/broker runtime checks its own
source, Python and config pins before launch. The compiler binds the hook's exact
local broker-version constant to the selected broker and records that derivation
alongside template and emitted source pins. Strict identity and exact
tools-contract validation remain in place.

Expected first turn:

1. `UserPromptSubmit` receives the genuine Native `session_id` and `turn_id`.
   A missing Native turn is refused; the profile does not invent a UUID.
2. The hook stages the exact prompt and emits one opaque `turn_ref`.
3. The model calls `integrity_context_admission_current_turn` with that reference
   exactly once in its own MCP session. It inspects `context_delivery` separately
   from capabilities and write-plane health.
4. It opens only the registration named by its owning hook, reads the returned
   immutable snapshot, and finishes with the matching signed terminal receipt.

The current Windows adapter verifies owning lifecycle calls against the Desktop
Native head. A successful `codex --version`, a CLI app-server thread, or a copied
transcript cannot stand in for that host. Do not set another thread's environment
identity to work around a failed owner check.

Once this workspace is accepted, merge its single Integrity MCP entry and hook
definitions into the intended active layer, preserving unrelated entries. Keep
the generated private directory at its absolute path. Do not install both this
profile and an older Integrity plugin for the same scope: matching Codex hook
sources run together, and duplicate admission handlers can consume one intent
twice. [Codex hook locations and trust](https://learn.chatgpt.com/docs/hooks).

## 4. Connect Claude Code with its real Native owner

This route is **Claude Code CLI under the enrolled publisher**. It is not a
Claude Desktop transport switch, and it is not an arbitrary CLI launched with a
copied session environment variable.

The owner publisher records task/turn IDs in its private delivery ledger and
launches Claude with the actual session ID. The Native reader joins that ledger
to the verified CLI ancestor and the current full JSONL user item. The item UUID
is source evidence; it is never substituted for a missing delivery turn ID.
The public publisher code is under `integrity-bridges/resources/private-memory`.
Provision its owner config and local listener through your normal owner route
before selecting a session. This profile does not start that service or grant a
new full-access provider session.

The retained CLI owner proof expects the publisher's loopback listener on
`127.0.0.1:49481` and one actual `--session-id`/`--resume` session argument on the
CLI ancestor. Keep that exact owner contract when provisioning this route. A
publisher on another port or an unrelated Claude process is not admitted by
changing an environment selector.

For an already enrolled session, extend the common bindings using its actual
files and ID:

```powershell
$bindings.claude_session_id = Read-Host 'Actual enrolled Claude session UUID'
$bindings.claude_project_root = Read-Host 'Exact project directory of that session'
$bindings.claude_owner_file = Read-Host 'Absolute publisher owner.json path'
$bindings.claude_ledger = Read-Host 'Absolute publisher tasks.sqlite3 path'
$bindings.claude_transcript = Read-Host 'Absolute full session UUID.jsonl transcript path'
$bindings.claude_publisher_script = Read-Host 'Absolute installed host_node.py path'
$bindings.claude_publisher_python = Read-Host 'Absolute Python executable used by the publisher'
$bindings | ConvertTo-Json | Set-Content -Encoding utf8NoBOM .\claude-bindings.json
& $nativePython -m integrity_client_memory.native_install `
  --vendor claude --upstream-json .\upstream.json --bindings-json .\claude-bindings.json `
  --output C:\Integrity\clients\claude-native
& $nativePython -m integrity_client_memory.native_runtime `
  --profile C:\Integrity\clients\claude-native\profile.json verify
& $nativePython -m integrity_client_memory.native_runtime `
  --profile C:\Integrity\clients\claude-native\profile.json probe
```

The compiler computes file pins itself, verifies the transcript filename/session
join, and exports `claude-workspace/.mcp.json` plus
`claude-workspace/.claude/settings.json`. The latter includes admission, outcome,
stop and Scope hooks. The hook-only lifecycle transport exposes the same exact
tools contract as the public broker. Source/config drift prevents launch.

For normal later use, merge those files into the **publisher-selected** workspace
and MCP/settings registration, preserve other settings, update the publisher's
MCP pin through its owner-controlled source, and resume the enrolled session
through that publisher. A direct `claude --mcp-config ...` is useful for the
read-only example but does not establish this Native publisher proof.

On `UserPromptSubmit`, the current user row may not yet be persisted. The hook
therefore uses a pending publisher/ledger proof first. Before admission it
requires the exact full user input to appear in the session transcript and
revalidates the process, session and delivery. A stale transcript, foreign session,
changed binary/publisher or missing live ancestor remains a refusal.

**Paused-account validation:** run only `verify`, `probe` and the provider-free
tests. Do not launch/resume the session or send a prompt while its quota is on
hold. Historical evidence is described below; the installer never spends Claude
quota to replace a missing acceptance result.

## 5. Connect Antigravity

Generate a conversation-isolated profile from the same server metadata:

Use a Python environment and output path without spaces or `cmd` metacharacters
on Windows. The historical Antigravity launcher runs hooks through `cmd /c` and
was observed to break quoted executable paths. The compiler refuses that layout
before writing a profile. If your checkout lives under a path with spaces,
create the client environment under a space-free private path first, for example
`py -3.12 -m venv C:\Integrity\client-venv`, and install the same local packages
using that environment's Python.

```powershell
& $nativePython -m integrity_client_memory.native_install `
  --vendor antigravity --upstream-json .\upstream.json --bindings-json .\bindings.json `
  --output C:\Integrity\clients\antigravity-native
& $nativePython -m integrity_client_memory.native_runtime `
  --profile C:\Integrity\clients\antigravity-native\profile.json verify
& $nativePython -m integrity_client_memory.native_runtime `
  --profile C:\Integrity\clients\antigravity-native\profile.json probe
```

The observed Windows configuration layout is:

- plugin hook file: `~/.gemini/config/plugins/integrity-native/hooks.json`;
- plugin enable entry: `plugins.integrity-native.enabled = true` in that config
  directory's `config.json`;
- MCP server entry: `integrity_native` in `mcp_config.json`.

With the application closed, save the original configuration files, copy the
generated `antigravity-plugin/hooks.json` into that plugin directory, and merge
the generated MCP and enable fragments into the existing files. Preserve other
servers, plugins and `userSettings`. The hook file uses the observed plugin-name
root and tool matcher groups, rather than Codex's top-level `hooks` shape.
Reopen the application after the normal quota hold is lifted.

`SessionStart` injects the contract. `PreInvocation` obtains the real
`conversationId`, `initialNumSteps`, `modelName`, artifact directory and full
transcript path. A new explicit owner input stages one opaque reference. The
model calls admission; the conversation broker opens its signed registration.
It returns that registration ID for the model's close, so the model must not
open a second registration.

`PreToolUse` validates `call_mcp_tool` / `ServerName` / `ToolName` / `Arguments`
and supplies the local one-use broker route. The model must not provide that
route itself. Append requires the current admission and live registration.
`PostToolUse` has no actual MCP result in the observed payload; the broker
validates the returned receipt instead. `Stop` checks close or records a signed
coverage gap. It does not turn an unfinished action into `no-event`.

Gemini model names map to Google; Claude model names inside Antigravity map to
Anthropic. An unknown model is refused. A model switch within an existing owner
turn requires a new explicit owner turn; a parallel conversation cannot reuse
the first conversation's reference, state or registration.

No Antigravity compaction callback was established in the captured contract.
This guide does not invent `PreCompact`/`PostCompact` support for it. Its native
per-input and per-conversation guards still apply.

## Hook behavior and expected results

| Hook | What the user gets | What constitutes failure |
|---|---|---|
| SessionStart | Contract injected; no premature snapshot or registration | Hook not trusted/loaded, or source/config pin drift |
| UserPromptSubmit / AG PreInvocation | Exact owning input, a fresh opaque reference and isolated provisional state | Missing/foreign Native identity, incomplete input or unknown model |
| PreToolUse | Current-reference admission and mutation gate | Wrong/ref reused, stale admission, missing own live registration |
| PostToolUse / broker result observer | Receipt-backed admission/append/terminal state | Plausible tool text without the required receipt; unknown outcome |
| Stop | Verified own terminal or explicit signed coverage debt | Missing terminal remains debt; no fabricated close |
| SubagentStart / SubagentStop | Parent registration preserved | These parent notifications do not prove a child's Native identity; a child needs its own owning hook |
| PreCompact / PostCompact / compact SessionStart | Codex/Claude Scope anchor retained outside the model; effects require the exact reattestation | An old summary cannot renew the scope lease |

Native and Scope handlers are composed in one sequential runner. Scope checks
effects before an admission handoff is armed; a later context handler cannot
overwrite an earlier denial. This avoids depending on the order of concurrent
hooks loaded by a client.

A broken Native Memory profile refuses its own MCP route and reports the fault.
It does not revoke separately verified owner authorization for unrelated tools.
That advisory is not an approval for those tools; their own target guard still
applies. Scope reorientation uses its distinct owner-anchor contract.

## Minimal acceptance, rollback and truthful status

Use a harmless project fact such as a chosen test command. Require admission in
the model's own MCP session, inspect `context_delivery`, retrieve the exact
record in its returned snapshot, append only an explicitly authorized durable
result, and close using its exact event ID/UID/request digest. In a second own
turn, retrieve that UID. Also check that a foreign reference and append before
admission are refused. Retain the signed receipts; a green server indicator is
not sufficient.

If no durable result was created, close with the accurate supported no-event
reason. If a send outcome is unknown, inspect canonical status instead of
resending it. A Stop gap is nonterminal accounting debt. The fresh profile does
not enroll the publisher's historical archive/recovery exceptions; those require
a separately bound recovery procedure and cannot authorize normal appends.

Rollback removes only the newly installed Integrity MCP/hook/plugin entries and
restores the saved configuration preimages. Retain private state and canonical
receipts for accounting. Do not delete a lifecycle store to clear a failure.
Generated profiles do not modify active settings themselves.

The evidence categories for this change are intentionally distinct:

- **Current source/offline:** complete generated commands and real entrypoint
  loads; actual hook replay checks configuration, conversation/model isolation,
  one-use reference gating and negative Native identity cases. No model calls.
- **Codex installed route:** the current owner conversation uses its actual
  Native admission/registration/close route. This does not by itself certify a
  newly generated profile in another workspace.
- **Claude historical:** the canonical record dated 2026-10-09 reports the
  installed Native package and managed policy verified, while full repair
  acceptance remained incomplete. This is not upgraded into an all-green fresh
  Claude CLI or Desktop run. Later historical Claude Code probes dated October
  16 do prove opaque-reference admission, event append and signed terminal,
  including two read-only closes. Their receipts use the legacy store and
  synthetic `intent:...` turn IDs. They do not certify the separate Native
  publisher route with an actual turn UUID. The exported CLI owner adapter's
  process/ledger/transcript checks are preserved and replayable.
- **Antigravity historical:** the operator record dated 2026-10-16 UTC reports
  admission and signed close for Gemini and Claude, append-before-admission
  refusal, one model writing a record and the other reading its exact UID,
  model/conversation isolation, gap handling and an actual rollback. Bus delivery
  was partial because one acknowledgment was missing; it remains partial.

Historical records are private operator evidence, not independently reproduced
public benchmarks. While Claude and Antigravity are paused, their fresh model
acceptance remains **NOT_RUN**. The accompanying code does not launch either
provider, refill quota, create a paid obligation or conceal that distinction.
