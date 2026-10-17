# Integrity Chronicle product brief

Status: **DESIGN_ONLY**. This is a design target, not an implementation or
acceptance claim. Command names below are proposed journeys. For the shipped
library and its actual entrypoints, see the [Home package](../../../components/integrity-home/README.md).

## Mission

Build a local-first, model-agnostic personal context ledger that converts
user-owned AI chat exports into searchable evidence and bounded, cited,
correctable, revocable memory.

Product promise:

> Every remembered claim can show why it exists, when it may have been valid,
> what contradicts or supersedes it, and how to correct or forget it.

Do not promise that the AI knows everything, that stored text is true, or that
memory is perfect.

## Product architecture

1. **Raw Vault** — immutable original exports outside the application workspace.
2. **Source Registry** — provider identity, size, digest, custody and processing
   receipts; no message payloads in ordinary logs.
3. **Canonical Conversation Store** — provider-neutral conversations, message
   topology, roles, timestamps, attachments and source locators.
4. **Lexical Index** — exact phrase/term/field search using a rebuildable local
   index such as SQLite FTS5.
5. **Chronicle Graph** — claims, preferences, projects, decisions, open loops,
   corrections, contradictions and temporal validity, always with provenance.
6. **Context Broker** — creates task-scoped context capsules with purpose,
   sensitivity, expiry and evidence citations.
7. **Review Surface** — local loopback UI/API for inspecting sources, accepting,
   correcting, superseding and forgetting derived memory.
8. **Receipts** — deterministic import, projection, access, rebuild and deletion
   evidence suitable for later Integrity Action Log integration.

## Required user journeys

### A. Safe intake

- `chronicle doctor`
- `chronicle import <archive> --dry-run`
- validate format without executing content;
- show safe statistics and planned actions;
- ingest only after explicit confirmation;
- resume or roll back interrupted imports deterministically.

### B. Search with evidence

- exact and ranked search across conversations and messages;
- filter by provider, date, speaker, model, conversation and content type;
- every result opens its exact source context and provenance chain.

### C. Personal memory review

- propose candidate preference, biography, project, decision, open loop,
  correction and changed-belief records;
- distinguish user assertion, quoted material and assistant inference;
- accept, reject, edit, contradict, supersede or mark unknown;
- no candidate becomes authoritative merely because a model emitted it.

### D. Scoped context delivery

- generate a bounded context capsule for a named task;
- exclude disallowed sensitivity classes and stale/contradicted items by policy;
- include citations and expiry;
- record a receipt without leaking raw content.

### E. Forget and rebuild

- delete or revoke a source/message/derived item;
- rebuild every projection and index deterministically;
- prove the forgotten material is no longer retrievable;
- retain only a content-free deletion receipt when policy requires it.

## Implementation milestones

Work through these in order unless repository evidence justifies a dependency
reordering. Continue improving the next unfinished gate on every new agent turn.

1. Package structure, CLI, doctor, configuration and deterministic test harness.
2. Hostile ZIP validator: traversal, links, malformed members, duplicate paths,
   compression ratio, total/member limits and atomic temporary extraction.
3. Synthetic ChatGPT and Claude adapters with explicit schema-version handling.
4. Canonical conversation/message topology preserving branches and unknowns.
5. SQLite schema, migrations, idempotent ingest and reproducible rebuild.
6. Unicode-aware lexical pipeline and FTS5 search with filters and citations.
7. Duplicate/near-duplicate candidate generation without destructive merging.
8. Chronicle claim schema, provenance, temporal state and contradiction rules.
9. Pluggable semantic extraction interface plus deterministic fake backend for
   tests; never require a hosted model for core product operation.
10. Context policy engine and signed/digested context capsule receipts.
11. Forget/supersede/rebuild lifecycle with negative retrieval verification.
12. Local loopback review API and minimal usable web UI.
13. Threat model, backup/restore, crash recovery, performance fixtures and
    operator documentation.
14. Clean-room release verifier proving install, import fixture, search,
    contradiction, context capsule, forgetting and deterministic replay.

## Acceptance gates

The product is not complete until all are true:

- installation works in a clean Python 3.11+ environment;
- no test or application path needs access to the real archive vault;
- identical input produces identical canonical IDs and projection results;
- malicious archive fixtures cannot escape bounded temporary storage;
- alternate reply branches remain reconstructable;
- assistant text cannot silently become a user fact;
- contradictions and supersession remain inspectable;
- search results and memory items cite exact source records;
- forgetting removes material from canonical projections, FTS and context
  capsules and is verified by negative tests;
- the UI binds to loopback by default and has no third-party telemetry;
- documentation distinguishes implemented, tested, partial and aspirational
  functionality;
- full automated tests and a clean-room verifier pass.

## Worker strategy

Use ordinary algorithms for corpus-scale work: stable sorting, hashes, canonical
serialization, inverted indexes/FTS, bounded parsers and deterministic state
machines. Spend model reasoning on architecture, ambiguity, adversarial tests
and review—not on classifying every word individually.

