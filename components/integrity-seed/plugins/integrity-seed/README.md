# Integrity Seed

Integrity Seed is a local, workspace-scoped memory plugin for Codex. Plugin
version 0.1.14 packages stdlib runtime 0.1.4; these independent versions describe
separate release contracts. Both component LICENSE files are Apache-2.0.

The bundled service binds loopback only, uses a private bearer token, preserves
append-only events and bounded source-linked context, and disables event deletion.
It starts no remote connection and ships no retained database, event, identity,
token, room or enrollment. Multiple-machine operation needs a separately operated,
authenticated transport; local health is not remote or model-delivery acceptance.

From this plugin directory, inspect the CLI and existing runtime:

```sh
python -I skills/integrity-seed/scripts/integrity_seed.py --help
python -I skills/integrity-seed/scripts/integrity_seed.py status --json
```

After the workspace owner requests initialization, select an empty private
INTEGRITY_SEED_HOME or accept the documented workspace-specific default, then run:

```sh
python -I skills/integrity-seed/scripts/integrity_seed.py setup --json
python -I skills/integrity-seed/scripts/integrity_seed.py doctor --json
```

Setup creates only the selected local state, credentials and loopback service.
Doctor starts and verifies that service; neither command is a pure read. Stop
terminates only the identity-verified local runtime and preserves its database:

```sh
python -I skills/integrity-seed/scripts/integrity_seed.py stop --json
```

Lifecycle hooks are described by hooks/hooks.json. Test hook delivery in a fresh
supported Codex session; runtime readiness alone does not prove context reached
the model. The canonical-provider marker can suppress this local writer when an
owner selects an external canonical provider. It does not grant that provider
credentials or authority. Do not enable fallback hooks alongside working bundled
hooks; compatibility hook installation requires its explicit CLI option.

On Windows virtualenvs the stdlib service launches the current interpreter's
strict-resolved base Python directly. PID, startup nonce, source/workspace digest,
process start/image, receipt signature and health must still match exactly.

The opt-in skill is skills/integrity-seed/SKILL.md. Its claim boundary distinguishes
canonical records, local receipts and actual model delivery. Nothing in memory
or this plugin grants authority to change unrelated files, services or machines.
