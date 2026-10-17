# Integrity Guardian

This source release is Guardian **6.1.1**, with memory MCP facade API **2.11.0**.

Integrity Guardian is a local-first integrity layer for humans, automation and
AI agents. It keeps four questions separate:

1. What was observed?
2. What action was authorized?
3. What actually changed?
4. Can an independent observer verify the outcome?

That separation prevents memory, model output or a successful request from
being mistaken for truth, permission or completion.

## Current status

This repository contains one canonical Guardian runtime and 15 optional Python
distributions. [COMPONENTS.json](COMPONENTS.json) records their independent
versions, dependencies, import namespaces and entrypoints. Source for local
archives, memory delivery, agent transports and the UI is included; user data,
credentials, enrolled sessions, host bindings and retained operational evidence
are not. Tests use synthetic inputs. Integrity source is Apache-2.0; bundled
third-party code keeps its own [license notices](LICENSES.md).

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
current `main` source by replacing `<copied-url>` below. Record the checked-out
commit when reporting a result:

```bash
git clone --depth 1 <copied-url>
cd integrity-next
git rev-parse HEAD
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

`version --all` reports the public source profile. These commands do not enroll
a host or grant action authority. Continue with [BOOTSTRAP.md](BOOTSTRAP.md) to
select optional components and, separately, initialize your own local state.

## Components

All distributions require Python 3.11 or newer. Their versions describe
different interfaces and deliberately do not all match the Guardian version.

| Distribution | Version | Purpose |
| --- | --- | --- |
| `integrity-guardian` | 6.1.1 | Canonical protocol, evidence, authorization and memory core |
| [`integrity-adapter-sdk`](components/integrity-adapter-sdk/README.md) | 2.0.0rc3 | Guardian-bound adapter facade |
| [`integrity-execution-bridge`](components/integrity-execution-bridge/README.md) | 0.1.0rc5 | Verified execution and observation boundaries |
| [`integrity-agents-api`](components/integrity-agents-api/README.md) | 0.1.0rc2 | Agent API integration |
| [`integrity-codex-persistent`](components/integrity-codex-persistent/README.md) | 0.1.0rc3 | Persistent Codex adapter |
| [`integrity-active-inquiry`](components/integrity-active-inquiry/README.md) | 0.1.0rc2 | Bounded active inquiry |
| [`integrity-experience-adapters`](components/integrity-experience-adapters/README.md) | 0.1.0rc3 | Experience adapter interfaces |
| [`integrity-resource-advisor`](components/integrity-resource-advisor/README.md) | 0.1.0rc6 | Local resource and usage projections |
| [`integrity-action-log`](components/integrity-action-log/README.md) | 2.10.0 | Action Log HTTP service and read-session evidence |
| [`integrity-memory-plane`](components/integrity-memory-plane/README.md) | 1.0.0 | Catalog synchronization, retention and storage tools |
| [`integrity-client-memory`](components/integrity-client-memory/README.md) | 1.8.0 | Codex, Claude and Antigravity hook/broker profiles |
| [`integrity-home`](components/integrity-home/README.md) | 0.2.0a1 | Home archive and Chronicle projections |
| [`integrity-space`](components/integrity-space/README.md) | 0.2.0 | Read-only MCP Apps lab and workbench UI |
| [`integrity-claude-code`](components/integrity-claude-code/README.md) | 0.1.0rc3 | Separately guarded Windows CLI executor |
| [`integrity-llm-bus`](components/integrity-llm-bus/README.md) | 1.0.0 | Local queue, registry, relay and steering transports |
| [`integrity-bridges`](components/integrity-bridges/README.md) | 0.7.0 | Hub, delegation and native peer transports |

`components/integrity-seed` and `plugins/` also retain their specific plugin
interfaces; they are not extra Python distributions. Historical source-profile
metadata is documented in the [source layout](components/integrity-installed-runtime/README.md).

## Run the test suite

```bash
python -m pip install ".[dev]"
python -m pytest -q
```

Public release checks verify the closed export manifest, component metadata,
canonical source layout, package builds and dependency compatibility, CLI smoke
commands and synthetic functional tests. See
[architecture and verification boundaries](ARCHITECTURE.md#what-the-public-suite-verifies).

## How it fits together

```text
observation -> signed evidence -> proposed action -> prior authority
            -> bounded execution -> independent observation -> replay
```

- **Guardian Core** validates identities, signed evidence and lifecycle rules.
- **Seed** provides append-only memory without turning memory into authority.
- **Adapters** establish explicit capabilities at an external boundary.
- **Observers** verify outcomes independently from the actor that requested them.

Start with the [clean bootstrap guide](BOOTSTRAP.md), then review the
[architecture map](ARCHITECTURE.md), [security guidance](SECURITY.md), the
[roadmap](ROADMAP.md) and [contribution guide](CONTRIBUTING.md).

### Verified scope

The public suite verifies the protocol core, the Ledger, one-use
ChangeIntent custody, index-backed Seed queries and fenced blast-radius
claims between processes **on one machine**. Coordination across machines,
authenticated agent identity for claims and production operation are not
provided or claimed; [ARCHITECTURE.md](ARCHITECTURE.md) lists each boundary.

## Platform support

| Platform | Source/install | Public CI | Operational integration |
| --- | --- | --- | --- |
| Linux | Supported | Python 3.12 | Requires an independently configured adapter |
| Windows | Portable core supported | Local source/package checks | POSIX-only custody and Windows-only executors have separate gates |
| macOS | Expected from portable Python code | Not yet in public CI | Unverified |

Platform support is a capability vector. An installation PASS does not imply
that host binding, credentials or production actions are configured.

## Project policy

- [Installation and bootstrap](BOOTSTRAP.md)
- [Architecture and verified scope](ARCHITECTURE.md)
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

Copyright 2026 Integrity Project contributors. Integrity source is licensed under
the [Apache License 2.0](LICENSE). See [LICENSES.md](LICENSES.md) for bundled
third-party notices and external dependency boundaries.

## Runtime source reference

[The canonical source layout](components/integrity-installed-runtime/README.md)
replaces former copied kernel trees with one maintained implementation per
namespace. Historical version matrices remain reference metadata, not active
package versions or evidence of a deployment.

## Installation acceptance evidence

See the [6.1.0 / 6.1.1 isolated installation report](docs/audits/installation-6.1.1-20261017/REPORT_RU.md) for Linux and Windows results, single-run command timings, preserved failures, limitations and evidence SHA256. These timings are not product-performance or cross-platform speed claims.
