# integrity-client-memory

Windows and Linux Codex hooks/brokers, Claude admission, Antigravity conversation-bound broker, and common opaque turn envelopes. Hook revision is 1.8.0; broker wire families remain Windows 1.6.0, Linux 1.6.1-linux.1, Antigravity 1.4.1. They are distinct implementations, not version aliases. Native ownership adapters require fresh install-time bindings; absent adapters must fail closed, never fabricate session identity.

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
