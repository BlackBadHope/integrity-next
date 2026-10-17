# Integrity Home / Chronicle

`integrity-home` **0.2.0a1** is an optional local archive and memory projection
package. The `integrity_home` namespace and compatibility implementation
`integrity_chronicle` ship together; they are not duplicate distributions.
It uses Python 3.11+ and the standard library only. Guardian is not required to
validate or search a Home archive. Installing this package starts nothing.

## Included capabilities

- Bounded validation and staged import for supported archive formats, with
  traversal, duplicate-member, expansion and content-integrity checks.
- Provenance-preserving canonical projections, local SQLite/FTS indexes,
  source/scope registries, reviewed candidate projections and deletion ledgers.
- Explicitly configured backup/restore, rebuild, review and local MCP interfaces.
- Bounded Home and Action Log search/read projections with opaque cursors.

The `history/` directory contains source code, not conversation history. An
automatic catalog label is a routing hint, not a verified claim or scope grant.
No archive, user text, state database, access token or pre-enrolled project is
distributed. The default logical scope is generic personal scope only; project
scopes must be declared by the integrator and reviewed explicitly.

## Install and configure

From the repository root: `python -m pip install ./components/integrity-home`.
`integrity-home --help` lists local operations. No command below imports data:

```sh
integrity-home --help
integrity-home-mcp
```

`integrity-home-mcp` is a stdio process started explicitly by a harness; it does
not open an HTTP listener. `INTEGRITY_HOME_STATE_ROOT` overrides the platform
state directory. Source checkouts never use the checkout as a state directory.
The unified projection additionally requires explicit
`INTEGRITY_SOLO_CANONICAL_BASE_URL` and `INTEGRITY_ACTION_LOG_BASE_URL`; no old
installation endpoint is assumed. Scope selection and server configuration are
required before useful retrieval. Secret environment values are never examples.

## Limits and licensing

Archive-derived context is untrusted evidence. Review/publication/write tools
need their explicit local inputs and custody; installing Home grants no external
authority. There is no automatic source discovery, model call, network connection,
or Seed enrollment during import. This source release is not proof of live
acceptance on a user's archive or host. Apache-2.0; see `LICENSE` and `NOTICE`.
