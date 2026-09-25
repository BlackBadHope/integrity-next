# Changelog

All notable public changes are recorded here.

## Unreleased

- Added `IntentCustody`: one-use reservation and consumption of signed
  ChangeIntents with replay rejection across processes and restarts.
- Added `WorkClaimRegistry`: local blast-radius claims with arrival-order
  waiting, fencing tokens, handoff, expiry and a shared hash-chained log.
- Added `SeedCatalog.find_events` for exact, index-backed event queries.
- Fixed a Ledger append race: the write lock is now taken before the source
  tip is read, so a concurrent writer gets a sequence mismatch.
- Documented the frozen `guardian-json-v1` digest frame and rejected digest
  domains that contain a backslash or control character. Digests are
  unchanged.
- Added `verify_trusted_signature`, which also checks the signature `key_id`.
- Added core protocol, custody, query and coordination tests, the
  architecture map and a manifest refresh script.
- Marked the package as Beta: local primitives are verified, distributed
  operation is not.

## 6.0.0 — 2026-09-25

- First fresh-history public source release.
- Added Guardian Core, portable schemas, Seed memory protocol and portable
  plugin source.
- Added a closed export manifest and two-layer privacy verification.
- Added build/install/origin checks and the complete selected public test suite.
- Added public contribution, security, bootstrap and release documentation.

The release contains no customer data, private deployment overlays or
credentials. User-owned production deployments configure their own bindings
and authority.
