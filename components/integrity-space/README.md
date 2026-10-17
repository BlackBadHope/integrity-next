# Integrity Space 0.2.0

Optional MCP Apps UI over explicitly configured Integrity sources. Python 3.11+
and Guardian `>=6.1.0,<6.2` are required. Versions of the MCP wire/API packages
are pinned because `mcp.server.apps`/`MCPServer` are part of the interface.

## Two explicit modes

- `integrity-space --config CONFIG` serves read-only `space-lab-*` projects.
  Its Lab UI reads registered `integrity_projects`, `integrity_project`,
  `integrity_task`, `integrity_context` and `integrity_source` tools.
  Catalog paths must be absolute, process-owned and private. This custody
  implementation supports POSIX only and fails closed on Windows.
- `integrity-space-workbench --config CONFIG --hub-manifest MANIFEST
  --hosts-config HOSTS` adds the UI to an existing explicitly enrolled Hub.
  The manifest pins the existing Hub source; it is created by its operator,
  never shipped with user host identities. Original Hub tool definitions,
  dispatch checks and permissions remain authoritative. The UI itself issues
  bounded inventory/read calls and does not dispatch tasks or certify outcomes.

`CONFIG`, `MANIFEST` and `HOSTS` are operator-owned files, not browser arguments.
No configuration, enrollment, transcript, task store, key or token is included.
Installing the wheel starts no service. `integrity-space-lab --help` describes
the separate explicit synthetic-fixture generator; it is never run on import.
Stdio is default. Either mode supports explicit `--transport http --token-file
TOKEN_FILE` for local preview, bound to loopback only. The page asks for that
local token before bootstrap. It keeps it only in memory, sends it in the
Authorization header on every read, and asks again after a refused token.
No token is embedded in a build, URL, browser storage or log. Origin/Host and
backend custody checks remain enabled. The two modes have separate read-only
HTTP tool allowlists; preview cannot dispatch a task.

## Build

```sh
npm ci --ignore-scripts
npm run build
npm test
python -m build
```

The wheel includes two distinct resources: `assets/lab.html` for Seed lab
projects and `assets/workbench.html` for the configured Hub. They share the
ephemeral-auth preview client. Each has maintained JS/HTML sources in `ui/`.
The old separate installed launcher, duplicate backend, preview harness and
deployment runtime lock were removed; useful Lab features remain available.
Python tests exercise actual MCP/ASGI routes over a disposable synthetic Seed
catalog, including the real JS preview client and explicit authentication retry.
On Windows only the POSIX-only backend custody seam is replaced for paths
inside the test directory; Guardian catalog files still use actual protected
Windows ACLs. No user source, live installation or cross-host acceptance is
implied by this offline evidence.
Install the `test` extra for the offline suite; the compiled-Hub integration
uses the real Home stdio server as an explicit disposable memory provider.

## Prepare an explicitly configured public Hub

Install `integrity-space[hub]` (the matching `integrity-bridges` package is
0.7.0). Materialize the supported private-memory family into a **new absolute**
operator-selected directory:

```sh
python -m integrity_bridges.profile --family private-memory --output ABSOLUTE_NEW_DIR
```

The compiler copies published source bytes and emits `hub-manifest.json` plus
a disabled `hub.example.json`; it does not import the Hub or start a route.
The manifest pins every profile Python file. Space rejects unsafe names,
changed hashes, unlisted extra Python files and imports from another profile.
No installed path is inferred. Keep the directory and configuration files
private to their process owner (POSIX directory0700/files0600).

Before loading the Hub, create your own Bridge component configuration from
`components/integrity-bridges/configuration.example.json`, set the explicit
`INTEGRITY_BRIDGES_CONFIG` path and fill only your intended local bindings.
`CONFIGURATION-VALUES.json` describes the required opaque value names. The
private-memory profile needs an explicitly selected memory provider command;
loading its tool inventory initializes that configured stdio provider. It
does not discover or substitute another memory source. Fill `hub.example.json`
with your local identity, ledger path and explicitly enrolled hosts. Starting
the Hub initializes that configured local operation ledger; compilation alone
does not. No example includes an identity, credential or working endpoint.

Then run `integrity-space-workbench` with the lab config, compiled manifest and
your Hub config paths. The plain `integrity-space` entrypoint remains a useful
independent Lab UI and does not require a Hub or Bridge configuration.

Apache-2.0 for Integrity code; bundled third-party license notices remain in
`NOTICE`, `THIRD-PARTY-NOTICES.txt` and the generated UI. The CLI executor is not
part of this package, and an unavailable continuation is explicitly reported.
