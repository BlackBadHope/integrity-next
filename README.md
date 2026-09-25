# Integrity Guardian

This source release is version `6.0.0`.

Integrity Guardian is a local-first integrity layer for humans, automation and
AI agents. It keeps four questions separate:

1. What was observed?
2. What action was authorized?
3. What actually changed?
4. Can an independent observer verify the outcome?

That separation prevents memory, model output or a successful request from
being mistaken for truth, permission or completion.

## Current status

This repository contains the portable Guardian runtime and reviewed component
and plugin source. Its exact file allowlist omits operational and deployment
tools, Orbit scenarios, host instructions, runbooks, rollback notes, fixtures,
retained evidence, history and release archives. The included package files are
available under Apache-2.0.

Installation does not silently connect to somebody else's infrastructure.
Configure the included adapters with authority and credentials belonging to
your own machine or environment. Target-specific route aliases are not part of
the public core; supply your own route catalogue when needed.

## Who should try it

Integrity Guardian is for developers and operators building AI agents,
automation or evidence-sensitive workflows who need to distinguish an observed
fact, an authorized action and a verified outcome. It is intended for real use
and testing on user-owned machines. Reports from different operating systems,
agent stacks and external targets are the main purpose of this public project.

## Try it in five minutes

Open **Code → Local → HTTPS** on this repository and copy its URL. Install the
exact stable release by replacing `<copied-url>` below:

```bash
git clone --depth 1 <copied-url>
cd integrity-next
python -m venv .venv
```

Activate `.venv` using the command for your shell, then run:

```bash
python -m pip install .
guardian version --all
guardian platform-profile
```

Create a disposable demo directory outside the checkout:

```bash
python -c "import tempfile; print(tempfile.mkdtemp(prefix='integrity-demo-'))"
```

Change into the printed directory. Create a deliberately unordered JSON
observation and ask Guardian for its canonical representation and
domain-separated digest:

```bash
echo '{"b":2,"a":1}' > observation.json
guardian canonicalize observation.json
guardian digest demo observation.json
```

Expected output:

```text
{"a":1,"b":2}
sha256:642c2d4d9286b31e56f6090f47b0435de8b034e713fe160d5ba51457138954b8
```

This first exercise does not create or modify Integrity state. Delete the
temporary demo directory when finished, then return to the checkout. Continue with the
[clean bootstrap guide](BOOTSTRAP.md) when you are ready to create an isolated
local instance.

## Install from source

Linux, macOS and Windows users need Python 3.11 or newer:

```bash
git clone <URL copied from Code → Local → HTTPS>
cd integrity-next
python -m venv .venv
```

Activate the environment:

```bash
# Linux/macOS
. .venv/bin/activate

# Windows PowerShell
.venv\Scripts\Activate.ps1
```

Install Guardian and inspect the local profile:

```bash
python -m pip install .
guardian version --all
guardian capabilities
guardian lts-contracts
```

`version --all` reports the public source profile. The other commands are
read-only; continue with [BOOTSTRAP.md](BOOTSTRAP.md) to initialize local state
and install the included functional components.

## Run the test suite

```bash
python -m pip install ".[dev]"
python -m pytest -q
```

Public CI verifies the closed export manifest, builds and installs the package,
runs the three CLI smoke commands and executes the public functional suite.

## How it fits together

```text
observation -> signed evidence -> proposed action -> prior authority
            -> bounded execution -> independent observation -> replay
```

- **Guardian Core** validates identities, signed evidence and lifecycle rules.
- **Seed** provides append-only memory without turning memory into authority.
- **Adapters** establish explicit capabilities at an external boundary.
- **Observers** verify outcomes independently from the actor that requested them.

Start with the [clean bootstrap guide](BOOTSTRAP.md), then review
[security guidance](SECURITY.md), the [roadmap](ROADMAP.md) and
[contribution guide](CONTRIBUTING.md).

## Platform support

| Platform | Source/install | Public CI | Operational integration |
| --- | --- | --- | --- |
| Linux | Supported | Python 3.12 | Requires an independently configured adapter |
| Windows | Supported | Locally acceptance-tested | Requires an independently configured adapter |
| macOS | Expected from portable Python code | Not yet in public CI | Unverified |

Platform support is a capability vector. An installation PASS does not imply
that host binding, credentials or production actions are configured.

## Project policy

- [Installation and bootstrap](BOOTSTRAP.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [Roadmap](ROADMAP.md)
- [Changelog](CHANGELOG.md)
- [Public export boundary](PUBLIC-EXPORT-NOTICE.md)

Security-sensitive reports should use **Security → Advisories → Report a
vulnerability** in this repository, not a public issue.

Questions, use-case proposals and first-user feedback are welcome in
the repository's **Discussions** tab.
Reproducible defects belong in the repository's **Issues** tab.

## License

Copyright 2026 Integrity Project contributors. Licensed under the
[Apache License 2.0](LICENSE).
