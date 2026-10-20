# Owner-selected Windows cohort roots

`native_install.build` and `broker_bundle.build_bundle` accept three optional,
keyword-only arguments for the Windows Codex profile:

- `deployment_root`: a new absolute local directory. The compiler writes to its
  ordinary `output` staging directory but renders all runtime and launch paths
  for this exact deployment target.
- `state_root`: an existing owner-selected private directory, retained in place.
- `envelope_root`: an existing owner-selected private directory, retained in
  place.

The CLI exposes the same arguments as `--deployment-root`, `--state-root`, and
`--envelope-root`. There is no environment fallback for these compiler inputs.
The default compiler path and output format remain unchanged when none is
provided. Other platform profiles reject these optional arguments.

The compiler and runtime inspect directory identity, ancestry and private
ownership metadata. On Windows, the owner must be the current user and allow
entries must be restricted to that user, SYSTEM, Administrators or OWNER RIGHTS.
The existing ACL, owner and inheritance setting are not changed. The profile
pins a directory identity and hashes of its owner/DACL metadata; runtime checks
repeat the audit and reject replacement, changed custody or a reparse point.
Protected state, enrollment, envelopes and keys are never opened or copied by
this path. Existing Native head, producer custody and Guardian checks remain
independent requirements.

Staging is intentionally not runnable: `native_runtime.verify` requires the
profile's declared root to equal its actual directory. Install the complete
source-pinned payload at the exact deployment root, then verify it there using
the pinned Python interpreter. A full bundle includes runtime sources, support
package, component/transport/tools configuration, bootstrap, generated launch
files and profile. Copying only the broker, tools and envelope files is not a
Native cohort installation.

The explicit owner binding `mcp_server_name` supports `integrity_native` (the
default) and `integrity_client_memory` (the canonical existing owner route).
Both receive the same Memory-hook classification. Other names are rejected;
another Integrity product is not automatically a Memory route.

An optional Windows Codex owner binding `server_version` derives only the hook's
`SERVER_VERSION` metadata constant from an exact observed upstream version.
It accepts numeric semantic versions and records the original/selected values
in profile derivations. An absent or null binding retains the default source.
Contract versions, capability shapes, protocol negotiation, authority,
checkpoint, source and Native ownership checks are unchanged. The selected
hook must pass the complete pure validators against the actual admitted
upstream response before activation; a matching version string alone is not
compatibility evidence.

These APIs compile a package. They do not change active settings, switch a
producer, start a provider, migrate encrypted state or authorize deployment.
An installer must pin the full payload and exact launch-file preimages, retain
the previous complete startup route, coordinate the switch with the owner, and
verify rollback independently. A two-file config/hooks switch requires a
journal and an exclusive writer; two file replacements are not a single atomic
operating-system transaction.
