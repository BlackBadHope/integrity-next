# Architecture

Integrity Guardian keeps four questions apart: what was observed, what was
authorized, what changed, and whether an independent observer can verify the
outcome. This page maps the package onto those questions and states which
guarantees the public test suite actually exercises.

## Layers

| Layer | Modules | Role |
| --- | --- | --- |
| Protocol core | `canonical`, `hashing`, `signing`, `schemas`, `schema/` | Deterministic JSON, domain-separated digests, Ed25519 signatures, closed JSON schemas |
| Evidence stores | `ledger`, `observer_anchor`, `retention`, `release`, `key_lifecycle` | Append-only per-source hash chains, signed checkpoints, key transitions |
| Authorization | `reconciler`, `intent_custody`, `policy`, `shadow`, `authority_scope`, `operation_audit` | Signed ChangeIntents, one-use custody, pre-execution commitments |
| Execution | `adapter_sdk`, `adapter_runtime`, `adapter_conformance`, `adapter_portability`, `*_adapter`, `collector*` | Contained adapters with dispatch permits that cannot be replayed |
| Independent observation | `*_observer`, `sensor`, `canary`, `readonly_canary` | Outcome witnesses that are separate from the actor |
| Memory (Seed) | `seed_catalog`, `seed_relationships`, `memory_link_graph`, `mind_*`, `turn_memory`, `task_closure` | Rebuildable projections over the canonical Action Log; memory never grants authority |
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

`components/` holds separately packaged adapters and the Seed plugin runtime;
`plugins/` holds client plugin hooks.

## Two Seed runtimes

- `guardian seed-serve` (`seed_runtime`) is a loopback, **read-only** view of
  a Seed catalog. It rejects every write method.
- The Action Log runtime in `components/integrity-seed` is loopback-only too,
  but it **accepts appends** (`POST /api/events`, `/api/tasks/accept`). Its
  task and lock conflicts are advisory attention items; they do not block a
  write.

`SeedCatalog.search()` is a free-text scan over every event.
`SeedCatalog.find_events()` gives exact, index-backed filters by actor,
action, time and task.

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
| Overlapping claims: one writer, queue, fencing, handoff | Verified locally | `tests/test_work_claims.py` |
| Coordination across machines, network backend, consensus | **Not provided** | Local SQLite scope only |
| Authenticated agent identity for claims | **Not provided** | Caller-asserted |
| Production deployment and operational acceptance | **Not claimed** | See `guardian capabilities` |

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
