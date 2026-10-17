# Architecture

The Chronicle [product brief](docs/architecture/chronicle/PRODUCT-BRIEF.md) and
[indexing pipeline](docs/architecture/chronicle/SORTING-AND-INDEXING-PIPELINE.md)
are retained as **DESIGN_ONLY** documents. They do not certify that every
proposed vault, graph, review or forgetting workflow is implemented.

Integrity Guardian keeps four questions apart: what was observed, what was
authorized, what changed, and whether an independent observer can verify the
outcome. This page maps the package onto those questions and states which
guarantees the public test suite actually exercises.

The current product version is Guardian **6.1.0**. The memory MCP facade API is
**2.11.0**; optional distributions have independent versions recorded in
[COMPONENTS.json](COMPONENTS.json). These numbers identify separate contracts.

## Layers

| Layer | Modules | Role |
| --- | --- | --- |
| Protocol core | `canonical`, `hashing`, `signing`, `schemas`, `schema/` | Deterministic JSON, domain-separated digests, Ed25519 signatures, closed JSON schemas |
| Evidence stores | `ledger`, `observer_anchor`, `retention`, `release`, `key_lifecycle` | Append-only per-source hash chains, signed checkpoints, key transitions |
| Authorization | `reconciler`, `intent_custody`, `policy`, `shadow`, `authority_scope`, `operation_audit` | Signed ChangeIntents, one-use custody, pre-execution commitments |
| Execution | `adapter_sdk`, `adapter_runtime`, `adapter_conformance`, `adapter_portability`, `*_adapter`, `collector*` | Contained adapters with dispatch permits that cannot be replayed |
| Independent observation | `*_observer`, `sensor`, `canary`, `readonly_canary` | Outcome witnesses that are separate from the actor |
| Memory (Seed) | `seed_catalog`, `seed_relationships`, `memory_link_graph`, `mind_*`, `context_delivery`, `canonical_read_context`, `turn_memory*`, `turn_curator`, `task_closure` | Snapshot-bound projections, explicit delivery health and separate lifecycle coverage; memory never grants authority |
| Agent identity and coordination | `agent_identity`, `agent_session_gate`, `agent_continuity`, `agent_handoff*`, `cross_agent_*`, `work_claims` | Identity, session gates, signed handoff, fenced local claims |
| Discovery | `discovery*`, `passive_*` | Signed, bounded discovery deltas ("Fog of War") |
| Platform backends | `_windows_*`, `windows_*`, `collector_posix`, `local_lock`, `platform_profile` | OS-specific custody and process boundaries |

Some product lines carry internal code names:

- **Atlas** (`atlas*`, `model_router`, `cognitive_runtime`): a deterministic
  tenant projection and model routing without model calls on the L0 path.
- **Synapse / Connectome** (`synapse`, `connectome*`, `memory_synapse_*`,
  `context_budget`): a policy-filtered capability graph and its MCP facade.
- **Uroboros Toolzs** (`uroboros_toolzs_*`): signed route memory learned
  from verified external actions, with one-use authority and recovery.
- **Medor** (`medor_*`): receipt-bound cognition and security admission over
  the layers above.
- **PPv4 / Galaxy** (`perpetual_dialogue*`, `galaxy_ppv4_bridge`,
  `codex_app_server_transport`): durable dialogue continuation with finite,
  authority-free batons.

`src/integrity_guardian` is the single canonical Guardian implementation.
`components/` holds separately packaged integrations and the Seed plugin
runtime; `plugins/` holds specific client plugin hooks. Former copies of the
kernel and SDK under `integrity-installed-runtime/sources/` were consolidated
into these canonical package trees. The
[source-layout metadata](components/integrity-installed-runtime/VARIANTS.json)
retains the meaningful historical version matrices without keeping duplicate
runtime implementations.

## Optional integration layers

```text
owner-configured Action Log -> synchronized, verified Seed catalog
  -> Guardian snapshot and context admission
  -> client-memory broker/hook -> model context

owner-imported archives -> Home / Chronicle -> explicit read projections
registered sources -> Space lab or Hub workbench -> bounded read-only UI

LLM bus / bridges -> transport receipts -> separate execution and observation
SDK -> configured executor -> independent outcome evidence
```

- **Action Log** is the separately versioned HTTP service. **Memory Plane**
  contains synchronization, seals, retention, projections and optional storage
  integrations. Storage schemas and tools are source, not an initialized store.
- **Client Memory** contains distinct Codex Windows/Linux, Claude and
  Antigravity profiles. Verified native ownership, tool catalogues and upstream
  configuration are supplied by the owner. Hook revisions and broker wire
  revisions are separate; matching one number does not attest a session.
- **Home / Chronicle** is an optional archive library and local projection.
  `integrity_home` and its `integrity_chronicle` compatibility namespace share
  one distribution. No archive, inferred project enrollment or imported text
  accompanies it. Home data does not automatically become canonical Seed data.
- **Space** exposes a read-only lab UI or a separately configured Hub workbench.
  It retains source custody and tool permissions. Its POSIX catalog-custody
  path is not a Windows implementation.
- **LLM Bus** and **Bridges** carry messages and bound peer requests. Queue
  acceptance, steering, receipt and ACK are transport evidence; they do not
  prove that a model acted or that a requested outcome occurred.
- **Claude Code** is a separate Windows executor through the Adapter SDK.
  Installation supplies neither a provider executable nor subscription access
  nor an activation proof. An executor is not the read-only memory client.

Packages with preserved standalone script profiles run those profiles in
separate subprocesses to avoid legacy import-name collisions. This small
launcher boundary is intentional; it does not create a second Guardian kernel.

The public tree includes implemented Chronicle modules, not a promise that
every proposed archive/cognition design has been implemented. Design material
and operational acceptance are not interchangeable with executable contracts.

## Seed service and plugin boundaries

- `guardian seed-serve` (`seed_runtime`) is a loopback, **read-only** view of
  a Seed catalog. It rejects every write method.
- The minimal plugin runtime in `components/integrity-seed` is loopback-only too,
  but it **accepts appends** (`POST /api/events`, `/api/tasks/accept`). Its
  task and lock conflicts are advisory attention items; they do not block a
  write.
- `components/integrity-action-log` additionally packages the service and its
  read-session evidence implementation. Its explicitly configured entrypoint
  can create state, accept appends and expose HTTP; importing the package does
  none of these. It is separate from the minimal plugin contract above.

`SeedCatalog.search()` is a free-text scan over every event.
`SeedCatalog.find_events()` gives exact, index-backed filters by actor,
action, time and task.

**Seed write contract.** The Action Log runtime stores `event_uid` exactly
as sent or refuses it, treats a repeated `event_uid` as idempotent only for
the same operation (otherwise `409 event_uid_conflict`), refuses over-limit
text instead of cutting it, and lists every intentional change (secret
redaction, `ts_utc` replacement) in the reply's `transformations`. Secret
redaction is not a data-loss-prevention system: it masks secret-named keys
and `key=value` pairs in text.

**Catalog sync.** `guardian seed-sync` reads the source by event id and
binds a catalog to the runtime's `workspace_id`, an identifier derived from
the Seed state location, not an authenticated identity. Before each import
it re-reads the catalog's first and last events from the source. That is a
spot check: an incremental sync does not re-read earlier events, and Seed
events are not signed, so the catalog cannot prove the source's earlier
history unchanged. The Guardian Ledger's signed guarantees do not apply to
Seed.

## Context delivery and Turn Memory

The modern `guardian-memory-synapse-mcp` transport retains a request-independent
default surface. The full Native/broker surface is selected only with explicit
catalog, architecture, trust and evidence configuration; this source release
does not enroll a client on import or invent an authenticated session.

Admission binds reads to an immutable session snapshot. `canonical_read_context`
contains bounded event evidence, while `selected` describes the adaptive
candidate projection. Empty selection is not proof that an event does not
exist. Exact reads and bounded recall remain separate evidence paths.

`context_delivery` is evaluated separately from generic capabilities and write
availability. Missing admission or delivery evidence yields explicit degraded
reasons instead of a quiet empty capsule. `model_delivery_verified=false` must
remain a limitation: a server response or transport receipt alone cannot prove
what reached a model. A ready memory read plane grants no authority to change
an unrelated external target.

Turn Memory registration and terminal receipts track lifecycle coverage
separately from context admission. Native lifecycle state uses a separate store;
initializing it requires an explicit flag. Legacy-only coverage remains
supported without creating native history, while configured but damaged or
inaccessible native history is not silently treated as absent. Curator repair
requires its own platform, grant and evidence checks; it is not an automatic
consequence of a read call.

Catalog verification checks canonical event payloads against indexed fields
before ranked recall. Full catalog and package-byte verification are retained;
the public source does not rely on installation-specific immutable-release
caches or a maintainer's precomputed live source pins.

## Authorization lifecycle

`reconcile()` is a pure classifier: the same signed intent classifies the
same observation identically every time. The one-use path is:

```text
verify ChangeIntent -> IntentCustody.reserve (exactly once)
  -> execute -> IntentCustody.consume against independent observations
  -> consumption receipt; any second reserve or consume is replay
```

Adapter execution has its own no-replay dispatch permits in
`adapter_runtime.AdapterDispatchRegistry`.

## Blast-radius coordination

`WorkClaimRegistry` serializes claims on one SQLite database:

```text
claim(resources) -> acquired (fenced) | waiting (queued) | rejected
release / handoff / expiry -> earliest compatible waiter is promoted
writer: assert_fence(claim, fence) before every write
```

Every transition goes into a hash-chained log that all agents can read.
Agent identities are asserted by the caller and not authenticated by this
module.

## What the public suite verifies

| Property | Status | Evidence |
| --- | --- | --- |
| Canonical JSON, digest vectors, signatures | Verified | `tests/test_core_protocol.py` |
| Ledger chain, replay rejection, reopen, tamper | Verified | `tests/test_core_protocol.py`, isolated canary |
| Two processes sharing one Ledger | Verified locally | `tests/test_core_protocol.py` |
| One-use ChangeIntent, cross-process race | Verified locally | `tests/test_intent_custody.py` |
| Exact Seed queries use indexes | Verified | `tests/test_seed_catalog_query.py` |
| Snapshot/context delivery, ranked recall integrity, separate legacy/native lifecycle | Synthetic contract coverage | `tests/test_memory_delivery_contract.py` |
| Overlapping claims: one writer, queue, fencing, handoff | Verified locally | `tests/test_work_claims.py` |
| Coordination across machines, network backend, consensus | **Not provided** | Local SQLite scope only |
| Authenticated agent identity for claims | **Not provided** | Caller-asserted |
| Production deployment and operational acceptance | **Not claimed** | See `guardian capabilities` |

Release gates additionally check component versions, internal dependency
constraints, import-root uniqueness, required license files, wheel contents,
canonical source hashes and executable modes. The closed public manifest and
privacy checks remain part of the public gate. Component tests exercise
synthetic archives, transports, parsers and UI contracts; they do not certify
owner credentials, live model delivery or a production deployment.

## Historical contracts and upgrades

Historical portability/deployment receipts intentionally retain the exact
Guardian/SDK cohort that their signed evidence describes. The reviewed
5.5.1-to-6.0 replay migration remains that path and refuses unrelated versions;
it is not a generic 6.1 migration. Updating a package does not rewrite old
signed evidence, restore an archived session or activate a deployment. The
current SDK's byte-origin binding targets the canonical 6.1.0 source separately.

`guardian capabilities` keeps `multi_agent_coordination_proven` and
`blast_radius_coverage_proven` false: local primitives are not a proven
distributed system.

## Protocol notes

- `guardian-json-v1` digests frame their input with the four ASCII
  characters `\x00` (backslash, `x`, `0`, `0`), not with a NUL byte. The
  frame is frozen because every retained digest depends on it. Domains may
  not contain whitespace, control characters or a backslash, which keeps the
  frame unambiguous.
- The signature `key_id` is not part of the signed bytes. Verifiers that pick
  a key by identity must compare it; `verify_trusted_signature` does both.
- Floating-point numbers are rejected. Integers are unbounded, so an
  implementation in another language must use arbitrary-precision integers
  to reproduce digests of values beyond 2^53.
