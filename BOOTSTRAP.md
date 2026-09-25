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
git clone --branch v6.0.0 --depth 1 <URL copied from Code → Local → HTTPS>
cd integrity-next
python -m venv .venv
```

Activate `.venv` using the command for your shell, then run:

```bash
python -m pip install .
guardian version --all
guardian capabilities
guardian lts-contracts
```

The expected version is `6.0.0`. The source tree contains no owner credentials,
release signatures or deployment activation. Configure each adapter with
credentials and authority that belong to your own environment.

## Install functional components

Install the components needed for your test directly from their package trees:

```bash
python -m pip install ./components/integrity-adapter-sdk
python -m pip install ./components/integrity-execution-bridge
python -m pip install ./components/integrity-agents-api
python -m pip install ./components/integrity-codex-persistent
python -m pip install ./components/integrity-active-inquiry
python -m pip install ./components/integrity-resource-advisor
```

Experience Adapters is also available under
`components/integrity-experience-adapters`. Each component README documents its
entrypoint and required optional dependencies.

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
python -m pip install --force-reinstall dist/integrity_guardian-*.whl
guardian version --all
```

## Initialize a local instance

Initialization creates local trust material and persistent state. Choose a
private directory that is not inside the repository:

```bash
guardian native-trust-bootstrap \
  --state-root "$HOME/.local/state/integrity-guardian" \
  --instance-id "instance:personal" \
  --device-id "device:local" \
  --architecture-root "architecture:personal"
```

This command does not configure credentials, production endpoints or external
action authority. Before connecting an adapter, review its included component
README and the root `SECURITY.md` guidance. Keep local state outside the source
checkout and preserve any state you need before removing it.
