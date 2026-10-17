# integrity-bridges

Separate hub and private-memory bridge profiles, delegation transports and authenticated native peer adapters. Both profiles are retained because reconciliation/ownership behavior differs. Byte-identical unix_ws_stdio has one canonical implementation. No SSH alias, command, endpoint or peer credential is preconfigured.

## Installation and configuration

Install this distribution and its declared dependencies into your own environment.
Importing `integrity_bridges` starts no process, opens no database and connects to no host.
`integrity-bridges --list` lists preserved entrypoints without importing their resources.

Copy `configuration.example.json` outside the source installation, supply your own
values, then set `configured` to `true`. Templates are deliberately disabled.
`CONFIGURATION-VALUES.json` lists the source locations requiring paths, endpoints
or commands. Values have no maintainer defaults. Keep credentials in your own
credential store or environment, never in published configuration.

```text
integrity-bridges --config /absolute/path/to/own-config.json --preflight
integrity-bridges --config /absolute/path/to/own-config.json ENTRYPOINT [its arguments]
```

The launcher uses a fresh subprocess per profile so private top-level names cannot
collide with other installed components. It does not install hooks, register MCP,
mint identity, initialize databases, start background processes or contact services
until an explicit entrypoint is launched with owner configuration. A configured
entrypoint can have its documented service/database/network effects.

Configuration environment variable: `INTEGRITY_BRIDGES_CONFIG`. Original script CLI arguments still
apply (e.g. a native profile's upstream TOML and tools contract). The public server
contract is Guardian 6.1.0 / memory MCP API 2.11.0. Profile revisions remain separate.

`SOURCE-MAP.json` preserves source coverage and copy hashes. Existing source tests
are in `legacy-tests`; datasets or deployment-specific fixtures are not synthesized.
These files provide source coverage, not proof of live multi-host acceptance.

## License

Apache-2.0; see LICENSE and NOTICE. No user memory, event corpus, enrollment, private
keys, service configuration, retained session state or live deployment pins are included.

## Complete optional Space Hub profile

`python -m integrity_bridges.profile --family private-memory --output ABSOLUTE_NEW_DIRECTORY`
materializes the complete Space-compatible Hub family and hub-manifest.json:
`{directory:absolute,files:{basename:sha256}}`. All Python files are pinned and
the single canonical unix_ws_stdio source is included in the generated profile.
`hub.example.json` is disabled: local_host and ledger are null and hosts is empty.
The compiler imports no Hub and makes no connection. It refuses an existing directory.

Install integrity-bridges0.7.0 (Space's optional hub extra pins this version),
provide your own INTEGRITY_BRIDGES_CONFIG and a separate explicit Hubconfig, then
point Space at the generated manifest. Hub(config) creates only its selected
operation ledger; do not activate it before configuring the owner-selected ledger.
No peer transport, token or source/target room is configured by this compiler.
The hub family is also retained separately for its delegated Native transport.

Preflight validates configuration header/version only; it reports runtime_bindings_verified:false. Complete owner bindings and an explicit entrypoint are still required before runtime use.
