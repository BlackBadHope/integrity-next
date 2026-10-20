# integrity-client-memory

Windows and Linux Codex hooks/brokers, Claude admission, Antigravity conversation-bound broker, and common opaque turn envelopes. Distribution revision is 1.9.2; admission hook revisions remain 1.8.0 / 1.8.0-linux.1 and broker wire families remain Windows 1.6.0, Linux 1.6.1-linux.1, Antigravity 1.4.1. They are distinct implementations, not version aliases. Native ownership adapters require fresh install-time bindings; absent adapters must fail closed, never fabricate session identity.

## Linux lifecycle repair

Slow Native ownership proofs execute outside the shared custody lock. One-use
consumption, claim expiry and final state comparisons remain under the lock.
The shared MCP process verifies the original private producer's exact Native
thread and turn without manufacturing a per-thread environment identity.
Runtime failures expose bounded static codes, message digests and safe frame
names, never arbitrary exception text or prompt content.

`generation_navigation.render_config()` is a pure helper for adding an inert
generation navigation field to a caller-owned config. Supply your own exact
preimage digest, generation, Python command and broker script. It preserves
unrelated bytes and rejects foreign drift. Applying the result and requesting
the normal MCP refresh remain separate owner actions; importing or calling the
renderer performs neither action.

## Installation and configuration

Install this distribution and its declared dependencies into your own environment.
Importing `integrity_client_memory` starts no process, opens no database and connects to no host.
`integrity-client-memory --list` lists preserved entrypoints without importing their resources.

Copy `configuration.example.json` outside the source installation, supply your own
values, then set `configured` to `true`. Templates are deliberately disabled.
`CONFIGURATION-VALUES.json` lists the source locations requiring paths, endpoints
or commands. Values have no maintainer defaults. Keep credentials in your own
credential store or environment, never in published configuration.

```text
integrity-client-memory --config /absolute/path/to/own-config.json --preflight
integrity-client-memory --config /absolute/path/to/own-config.json ENTRYPOINT [its arguments]
```

The launcher uses a fresh subprocess per profile so private top-level names cannot
collide with other installed components. It does not install hooks, register MCP,
mint identity, initialize databases, start background processes or contact services
until an explicit entrypoint is launched with owner configuration. A configured
entrypoint can have its documented service/database/network effects.

Configuration environment variable: `INTEGRITY_CLIENT_MEMORY_CONFIG`. Original script CLI arguments still
apply (e.g. a native profile's upstream TOML and tools contract). The public server
contract is Guardian 6.1.0 / memory MCP API 2.11.0. Profile revisions remain separate.

`SOURCE-MAP.json` preserves source coverage and copy hashes. Existing source tests
are in `legacy-tests`; datasets or deployment-specific fixtures are not synthesized.
These files provide source coverage, not proof of live multi-host acceptance.

## License

Apache-2.0; see LICENSE and NOTICE. No user memory, event corpus, enrollment, private
keys, service configuration, retained session state or live deployment pins are included.

## Fresh catalogue and Native source pins

`python -m integrity_client_memory.profile --tools-json OWN_TOOLS.json --output NEW_DIRECTORY`
validates the actual owner-selected tools/list catalogue, preserves its schemas
and annotations and computes its exact digest. The sole bundled catalogue is the
current public memory API2.11 surface; older personalized copies are not retained.
The compiler emits source-derived Native pins and leaves identity, upstream,
project scope and Native owner bindings unset. It refuses an existing directory.

Linux Native custody requires an explicit native_owner_uid, native_daemon_directory,
native_home_parent and native_home_mode. The peer UID must equal both that chosen
owner and the actual process UID. A non-1000 owner is supported; any UID is not an
admission. No pre-enrolled Native subjects or room/session bindings are shipped.

Local runbook navigation defaults to paths:[]. Optional owner_local_catalogue
configuration names an absolute private file, its exact SHA256 and host_id.
POSIX private ownership or Windows SID-based ACL custody and digest/readback are
checked before the existing Navigator route/Native/closure validation. This is
navigation data and never grants target-action authority or executes a recipe.

The immutable-generation launcher is preserved at common/generation_launcher.
Cross-platform scope capture is preserved at common/integrity_scope_synapse,
with scope.ps1/scope.sh wrappers calling the installed public entrypoint. The
complete Linux scope profile additionally retains its sanitized, digest-bound
frozen modules. These are distinct profile implementations, not a live registration.

Preflight validates configuration header/version only; it reports runtime_bindings_verified:false. Complete owner bindings and an explicit entrypoint are still required before runtime use.

Scope wrapper setup must select its harness explicitly: `scope.sh EVENT codex` or `scope.sh EVENT claude`; PowerShell uses `scope.ps1 -Event EVENT -Harness codex` (or `claude`). Both forward --harness to the shared scope parser.

## Weekly Windows source profiles (2026-10-20)

Revision 1.8.2 adds two explicit source entrypoints. Existing Linux and default
Windows broker profiles retain their implementations. No hook or service is
installed, no host is enrolled and no saved state is migrated by this package.

- `windows/native_scope` ships the managed Windows Native/SCOPE selector and its
  protected adapter sources. Compaction reads one turn per page, at most 30 pages,
  retaining the 15-second observation deadline and rejecting truncated, duplicate
  or foreign evidence. Safe diagnostics preserve the last 8 failures and observed
  callbacks without raw errors or prompts. The publisher diagnostic session is
  disabled. The entrypoint rejects non-Windows execution.
- `windows-remote/integrity-client-turn-broker` preserves the separate remote
  Windows broker family 1.4.1. Nested upstream work shares one 180-second public
  request budget; cold initialization can use 45 seconds. An owner choosing this
  profile should allow at least 210 seconds at the outer MCP client boundary.

All source paths, pins and runtime bindings must be supplied in the owner
configuration. The generated profile includes hashes of the packaged Windows
Native sources; those hashes describe source bytes and grant no activation.
Live credentials, transport enrollment, machine settings and historical memory
records are deliberately absent. Local fake-IPC tests establish source behavior;
a new installation still needs its own lifecycle acceptance.

## Complete Native client profiles

`integrity-native-profile` generates private, source-pinned Codex, Claude CLI
and Antigravity MCP/hook registrations from an owner-selected server and real
Native bindings. See the [complete Native onboarding guide](../../docs/native-onboarding.md)
for installation, lifecycle behavior, paused-provider verification and rollback.
`native_runtime verify` checks exact source/configuration bytes; `probe` imports
the real entrypoints without calling a model. Both remain distinct from live
acceptance. The original header-only launcher preflight retains its original
meaning.
