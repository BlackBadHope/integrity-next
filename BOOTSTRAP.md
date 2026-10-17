# Clean bootstrap

This guide creates an isolated Integrity installation from the reviewed public
source tree. You choose which included component packages to install and bind
to your own machine.

## Requirements

- Python 3.11 or newer;
- Git;
- an isolated virtual environment;
- network access to the configured Python package index for dependencies.

## Install

```bash
git clone --branch main --depth 1 <URL copied from Code → Local → HTTPS>
cd integrity-next
git rev-parse HEAD
python -m venv .venv
```

Activate `.venv` using the command for your shell, then run:

```bash
python -m pip install .
guardian version --all
guardian capabilities
guardian lts-contracts
```

The expected Guardian version is `6.1.1`; the memory MCP facade is `2.11.0`.
Record the commit above alongside test results: `main` can advance. This guide
does not depend on an unpublished version tag. The source tree contains no owner credentials,
release signatures or deployment activation. Configure each adapter with
credentials and authority that belong to your own environment.

## Install functional components

Install the components needed for your test directly from their package trees:

```bash
python -m pip install . ./components/integrity-adapter-sdk
python -m pip install ./components/integrity-execution-bridge
python -m pip install ./components/integrity-agents-api
python -m pip install ./components/integrity-codex-persistent
python -m pip install ./components/integrity-active-inquiry
python -m pip install ./components/integrity-resource-advisor
```

The SDK is bound to Guardian `6.1.1`; the Claude executor requires SDK
`2.0.0rc3`. Supplying local package paths together lets the resolver use the
matching source rather than look for an unpublished version on an index.
For example:

```bash
python -m pip install . ./components/integrity-adapter-sdk ./components/integrity-claude-code
python -m pip check
integrity-claude-code capabilities
```

Other optional packages are listed in [COMPONENTS.json](COMPONENTS.json) and
the [README component table](README.md#components). Each has its own README,
license, Python dependencies and platform limits. Install only what you need.
Home/Chronicle uses the standard library; Space additionally installs its pinned
MCP/UI dependencies. Storage extras belong to the memory-plane tool that uses
them. Packages do not automatically start services or import personal data.

The transport packages provide disabled `configuration.example.json` templates.
Copy one outside the source tree, supply your own paths and endpoints and run
the package's documented preflight. Native hooks additionally need verified
owner/session bindings and a tool catalogue for the selected server. A package
version alone is not an enrolled client identity. No example contains an active
route catalogue, enrolled session, service token or queue.

## Memory MCP profiles

The `guardian-memory-synapse-mcp` entrypoint uses the modern MCP transport.
Its default surface is request-independent; the full session/Native broker
contract requires explicit architecture, catalog, trust and evidence inputs.
Inspect `guardian-memory-synapse-mcp --help` before selecting a profile.

Turn Memory registration is distinct from context admission. Native lifecycle
state has its own store; `--bootstrap-native-intent-store` is an explicit
initialization request and never an implicit migration of legacy history.
Missing session or delivery evidence must remain visible as a degraded result.
Memory read availability and authorization to act on another target are separate.

Historical deployment and replay schemas retain their original version pins.
Installing 6.1.1 does not revalidate an older signed deployment receipt. In
particular, the retained reviewed 5.5.1-to-6.0 replay path is not a migration
path to 6.1.1; create and review the appropriate new evidence for a new deployment.

## First read-only check

Create a disposable directory outside the repository and change into the path
printed by this command:

```bash
python -c "import tempfile; print(tempfile.mkdtemp(prefix='integrity-demo-'))"
```

```bash
echo '{"b":2,"a":1}' > observation.json
guardian canonicalize observation.json
guardian digest demo observation.json
```

The canonical form is `{"a":1,"b":2}` and the digest is
`sha256:642c2d4d9286b31e56f6090f47b0435de8b034e713fe160d5ba51457138954b8`.
No Integrity state or host authority is created by these commands. Delete the
temporary demo directory when finished, then return to the checkout.

## Build a wheel

```bash
python -m pip wheel . --no-deps --wheel-dir dist
python -m pip install --force-reinstall dist/integrity_guardian-6.1.1-py3-none-any.whl
guardian version --all
```

Use the exact wheel filename printed by the build if its platform tag differs.
Do not substitute another build or release merely because its filename matches
a wildcard.

## Initialize a local instance

Initialization creates local trust material and persistent state. Choose a
private directory that is not inside the repository. Both roots below are
filesystem paths, not instance or architecture identifiers. Run the block
for your shell from the checkout; the absolute paths keep state outside it.

Bash (Linux/macOS):

```bash
guardian native-trust-bootstrap \
  --state-root "$HOME/.local/state/integrity-guardian" \
  --instance-id "instance:personal" \
  --device-id "device:local" \
  --architecture-root "$HOME/.local/state/integrity-guardian/architecture"
```

PowerShell (Windows):

```powershell
$stateRoot = Join-Path $HOME '.local/state/integrity-guardian'
guardian native-trust-bootstrap `
  --state-root $stateRoot `
  --instance-id "instance:personal" `
  --device-id "device:local" `
  --architecture-root (Join-Path $stateRoot 'architecture')
```

The command reports the database path in `database`. Verify that it is under
your chosen private architecture directory and outside the checkout before
using the instance. Keep generated trust material and databases out of Git.

This command does not configure credentials, production endpoints or external
action authority. Before connecting an adapter, review its included component
README and the root `SECURITY.md` guidance. Keep local state outside the source
checkout and preserve any state you need before removing it.
