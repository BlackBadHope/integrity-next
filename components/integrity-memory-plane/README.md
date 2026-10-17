# integrity-memory-plane

Seed delta sync, signed catalog seal, archive/capacity/retention, retrieval/projection, NATS/S3/PostgreSQL and physical verification tools. SQL migrations and existing tests are retained. Operational config, credentials, containers and dataset fixtures are intentionally not shipped. Choose extras only for the tools used.

## Installation and configuration

Install this distribution and its declared dependencies into your own environment.
Importing `integrity_memory_plane` starts no process, opens no database and connects to no host.
`integrity-memory-plane --list` lists preserved entrypoints without importing their resources.

Copy `configuration.example.json` outside the source installation, supply your own
values, then set `configured` to `true`. Templates are deliberately disabled.
`CONFIGURATION-VALUES.json` lists the source locations requiring paths, endpoints
or commands. Values have no maintainer defaults. Keep credentials in your own
credential store or environment, never in published configuration.

```text
integrity-memory-plane --config /absolute/path/to/own-config.json --preflight
integrity-memory-plane --config /absolute/path/to/own-config.json ENTRYPOINT [its arguments]
```

The launcher uses a fresh subprocess per profile so private top-level names cannot
collide with other installed components. It does not install hooks, register MCP,
mint identity, initialize databases, start background processes or contact services
until an explicit entrypoint is launched with owner configuration. A configured
entrypoint can have its documented service/database/network effects.

Configuration environment variable: `INTEGRITY_MEMORY_PLANE_CONFIG`. Original script CLI arguments still
apply (e.g. a native profile's upstream TOML and tools contract). The public server
contract is Guardian 6.1.0 / memory MCP API 2.11.0. Profile revisions remain separate.

`SOURCE-MAP.json` preserves source coverage and copy hashes. Existing source tests
are in `legacy-tests`; datasets or deployment-specific fixtures are not synthesized.
These files provide source coverage, not proof of live multi-host acceptance.

## License

Apache-2.0; see LICENSE and NOTICE. No user memory, event corpus, enrollment, private
keys, service configuration, retained session state or live deployment pins are included.

## Host requirement

The operational tools require Linux/POSIX: fcntl locking and custody checks are
part of the implementation. Installing this distribution alongside Windows client
packages is safe; launching memory-plane tools on Windows is rejected explicitly.
The original offline snapshot/backup tests were NOT_RUN on this Windows host
because fcntl is unavailable. No replacement lock implementation was simulated.
The optional NATS range includes the retained requirements-nats.txt2.15.0 lock.

Preflight validates configuration header/version only; it reports runtime_bindings_verified:false. Complete owner bindings and an explicit entrypoint are still required before runtime use.
