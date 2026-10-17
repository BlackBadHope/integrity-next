# Integrity Claude Code executor 0.1.0rc3

Optional Windows executor through the genuine Integrity Adapter SDK
`2.0.0rc3` (Guardian 6.1.1). It is separate from Guardian, Home and the read-only
Space UI. Python 3.11+ is required. No CLI binary or provider authentication is
bundled; installing the package does not launch a process or create a ledger.

```sh
python -m pip install ./components/integrity-adapter-sdk ./components/integrity-claude-code
integrity-claude-code capabilities
```

`capabilities` is the only command-line operation and is offline. The Python
API exposes exact descriptors/policies, a claim-before-effect run ledger,
SDK-mediated launch/tool boundaries, a bounded JSONL parser, Windows Job Object
process control, handle-verified sinks, observation and closure handoff.

## Authority and limits

- No authority is minted here. Launch and mediated effects require the genuine
  SDK facade, verified envelopes, durable attempts and consume-once permits.
- Native CLI activation remains fail-closed until exact host-supplied evidence
  verifies the declared CLI profile. The source declares CLI 2.1.281 and its help
  digest; this is an interface constraint, not a claim that this is the latest
  CLI or that any public user has passed live acceptance.
- Subscription authentication is required; API-key/provider billing paths are
  refused. The operator supplies subscription credentials outside this package.
- Job Objects bound the process tree, not filesystem or network access.
  Runtime launch/pipe/file custody is Windows-only; pure parsers and policies
  remain testable on other platforms.
- Unknown/in-flight outcomes block blind retry. A provider result remains a
  claim; `verified_success` needs independent observation and host authority.
- On Windows the run ledger's directory DACL is an operator responsibility.
  The component does not prove host custody by installation alone.

The public tests cover source/package integration and synthetic protocol
refusals. They do not activate a subscription, sign an envelope, launch Claude
or claim live end-to-end acceptance. No user session, run record, ledger, key,
activation artifact or installed executable pin is distributed.

Apache-2.0 for Integrity source; Anthropic CLI licensing is separate. See
`LICENSE` and `NOTICE`.
