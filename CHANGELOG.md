# Changelog

All notable public changes are recorded here.

## Unreleased

## 6.1.1 — 2026-10-17

- Fixed the clean bootstrap example to use an absolute private architecture
  directory outside the source checkout; added the PowerShell equivalent and
  an explicit database-path check.
- Updated the supported stable version in SECURITY.md.
- Advanced Guardian patch metadata to 6.1.1 and regenerated the exact SDK
  source binding. Adapter SDK 2.0.0rc3 and Claude executor 0.1.0rc3 carry the
  matching dependencies; historical receipt/profile pins are unchanged.

## 6.1.0 — 2026-10-17

- Consolidated the canonical Guardian implementation and independently versioned
  optional distributions. Removed repeated runtime source trees while retaining
  distinct broker/plugin contracts and historical LTS profile metadata.
- Integrated snapshot-bound context delivery, bounded canonical event context,
  topic extraction, ranked recall, separate Native/legacy Turn Memory and
  explicitly gated lifecycle curation. Memory facade API is 2.11.0; the modern
  request-independent transport remains the default surface.
- Added source packages for Action Log, Memory Plane, client hooks/brokers,
  Home/Chronicle, Space, the guarded Claude executor, LLM Bus and Bridges.
  Installation starts no service and includes no user archive, active host
  binding, session, route catalogue, credential or runtime database.
- Added one component catalogue with dependency, namespace, license and version
  checks. Adapter SDK 2.0.0rc2 binds Guardian 6.1.0 and its exact package origin;
  optional distributions keep their own versions and platform boundaries.
- Preserved Apache-2.0 ownership notices and third-party license texts, including
  the Space UI bundle and Execution Bridge supporting code.
- Catalog verification now rejects disagreement between indexed event fields
  and canonical payloads before ranked recall. Archive provenance policy is an
  explicit immutable input rather than a pre-enrolled corpus. Full source and
  catalog verification remain required.
- Preserved public export/privacy, functional and package checks; extended the
  release gate to canonical source layout, modes, metadata and optional packages.
  Tests use synthetic data and do not imply live production or model-delivery
  acceptance.
- Fixed the minimal Seed runtime's Windows virtual-environment launch boundary
  without relaxing exact process or signed-receipt checks. Its runtime revision
  is 0.1.4; the source plugin has a separate version and explicit package allowlist.
  Public CI now exercises isolated co-installation on both Linux and Windows.
- Upgrade boundary: historical signed deployment receipts and their reviewed
  replay paths retain their original version pins. This release neither rewrites
  those receipts nor silently migrates or bootstraps Native lifecycle state.

### Earlier changes since 6.0.0

- Seed writes no longer change identifiers or accepted text silently.
  `event_uid` is stored exactly as sent (up to 200 characters of
  `[A-Za-z0-9._:@/+-]`) or refused before the write; the same `event_uid`
  with a different operation returns `409 event_uid_conflict` and leaves the
  stored event unchanged. Operations are compared after normalization and
  redaction: actor, session_id, level, action, summary and tags exactly,
  `details` as a JSON object (key order ignored, `1` and `1.0` differ), and
  the fact time only when the client's `ts_utc` is accepted, to the stored
  second. Acceptance is judged against the stored first write's
  `created_utc`, not the retry's arrival, so an identical retry gets the same
  answer whenever it arrives. A `ts_utc` that was invalid or more than five
  minutes ahead of the first write is not part of the operation, so an
  identical retry returns the first event even after that time has passed. Requests that differ only inside redacted secret values
  cannot be told apart and are answered as duplicates. Over-limit `summary` (2000), `actor` (120),
  `session_id` (200) and `action` (160) are refused with `<field>_too_long`
  instead of being cut. Secret masking matches whole key segments, so keys
  such as `session_id`, `tokens_used` or `secretary` keep their values and
  types; every intentional change is listed in the reply's
  `transformations`. In text, `Authorization: <scheme> <credential>` (also
  `=` and `Proxy-Authorization`) keeps the scheme word and masks the whole
  credential: a token, or a comma-separated parameter list with quoted values
  such as Digest `username="…", response="…"`. A value without a scheme is
  masked as one token or one parameter list. A value whose end cannot be
  found (an unterminated quote, text glued to it, or an unparsed `name=`
  right after it) is refused with `400 authorization_value_unbounded`; the
  refusal does not repeat the value. `integrity_seed.py remember` prints these refusals.
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
  exports; the same holds for Digest parameters after the first one. Retrying
  such an old operation now normalizes differently and returns
  `409 event_uid_conflict`; that is not a signal to resend it under a new
  `event_uid`. An `event_uid` longer than 160
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
