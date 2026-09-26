# Changelog

All notable public changes are recorded here.

## Unreleased

- Seed writes no longer change identifiers or accepted text silently.
  `event_uid` is stored exactly as sent (up to 200 characters of
  `[A-Za-z0-9._:@/+-]`) or refused before the write; the same `event_uid`
  with a different operation returns `409 event_uid_conflict` and leaves the
  stored event unchanged. Operations are compared after normalization and
  redaction: actor, session_id, level, action, summary and tags exactly,
  `details` as a JSON object (key order ignored, `1` and `1.0` differ), and
  the fact time only when the server accepted the client's `ts_utc`, to the
  stored second. A `ts_utc` the server replaced (invalid or more than five
  minutes ahead) is not part of the operation, so an identical retry returns
  the first event. Requests that differ only inside redacted secret values
  cannot be told apart and are answered as duplicates. Over-limit `summary` (2000), `actor` (120),
  `session_id` (200) and `action` (160) are refused with `<field>_too_long`
  instead of being cut. Secret masking matches whole key segments, so keys
  such as `session_id`, `tokens_used` or `secretary` keep their values and
  types; every intentional change is listed in the reply's
  `transformations`. In text, `Authorization: <scheme> <credential>` (also
  `=` and `Proxy-Authorization`) keeps the scheme word and masks the
  credential; a value without a known scheme is masked as one token. `integrity_seed.py remember` prints these refusals.
- `guardian seed-sync` finds the source tail by event id, so backdated or
  near-future `ts_utc` values no longer stall or break a sync.
- A Seed catalog is bound to one runtime: the first sync records its
  `workspace_id`, later syncs refuse another source, and the catalog's first
  and last events are re-read from the source and compared before import.
  The sync report states which range was read and that earlier history is
  not proven unchanged; `seed-catalog-verify` states it checks the catalog
  only.
- Upgrade notes: events stored before this change keep their truncated or
  redacted values; nothing is restored, and an Authorization credential that
  the earlier filter left in place stays in those events, snapshots and
  exports. Retrying such an old operation now normalizes differently and
  returns `409 event_uid_conflict`. An `event_uid` longer than 160
  characters that was truncated before will not match its old row, so a
  retry stores a new event. Clients that relied on silent truncation, or on
  a reused `event_uid` returning the old event for a different operation,
  now receive an explicit error. Existing catalogs are bound on their next
  successful sync.
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
