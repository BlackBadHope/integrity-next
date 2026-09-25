# Security policy

## Supported version

Security fixes currently target the latest stable `6.0.0` public release.
Older snapshots are unsupported.

## Report a vulnerability

Use **Security → Advisories → Report a vulnerability** in this repository. Do
not open a public issue containing credentials, customer data, private
topology or working exploit details.

Include the affected commit/version, platform, reproduction steps, impact and
the smallest safe evidence needed to confirm the issue. Maintainers will
acknowledge the report through the private advisory and coordinate disclosure
there. No response-time SLA is promised.

## Repository boundary

Never commit credentials, cookies, tokens, private keys, customer hostnames,
private IP inventories, production evidence, databases or memory exports.
Synthetic examples must use reserved names and documentation address ranges.

Guardian reports only what its observed coverage supports. Missing evidence is
`UNKNOWN`, never a green result. Installation and memory do not grant production
authority.
