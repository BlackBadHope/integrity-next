# Integrity memory hook registration template

The canonical implementation is the independently packaged
[integrity-client-memory](../../components/integrity-client-memory/README.md)
1.8.0 profile, bound to memory facade API 2.11.0. This directory keeps only
the host registration template, not another copied hook, broker or tool list.

Install the matching public distributions in your own environment and compile
the tool catalogue from your selected server. Configure fresh session, Native
owner and upstream bindings as described by the client package. Set
`INTEGRITY_CLIENT_MEMORY_CONFIG` to your explicit configuration before adopting
`hooks/hooks.json` in a supported Codex host. The executable must be available
in that host's PATH. Missing configuration fails closed; no service, identity,
hook registration or database is created by copying this source template.

The template selects the Linux or Windows admission entrypoint explicitly and
the Codex scope profile with `--harness codex`. Claude and Antigravity have
their own client profiles. Unique immutable-generation launching and scope
capture remain in the canonical package's `resources/common`; they require
owner-generated bindings and are not activated by this directory.

The former standalone hook/broker/tool copies are retired. Existing deployments
are not modified; adopting this source requires an explicit local migration.
