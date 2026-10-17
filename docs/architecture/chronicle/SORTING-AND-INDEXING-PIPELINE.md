# Chronicle: deterministic sorting and indexing pipeline

Status: **DESIGN_ONLY**. This is a design target, not an implementation or
acceptance claim. Command names below are proposed journeys. For the shipped
library and its actual entrypoints, see the [Home package](../../../components/integrity-home/README.md).

Status: **design note only**. No archive contents have been processed.

The intended approach is to spend deterministic computation before model
tokens. Sorting, normalization, exact indexing, deduplication, and structural
classification should shrink and organize the corpus before any semantic model
sees it.

## Important distinction

"Index every word" should mean a rebuildable lexical index, not an LLM call for
every token. Exact terms can be handled with an inverted index/BM25-style
pipeline. Models should operate at bounded message, turn, topic, episode, claim,
and decision levels.

Raw evidence is never deleted merely because it looks like noise. Low-priority
material stays addressable in the source vault while the active memory
projection remains small.

## Proposed passes

1. **Register source**
   - provider, original filename, byte length, SHA-256, archive format;
   - immutable source ID derived from the digest;
   - no extraction and no network egress.

2. **Validate and normalize container**
   - reject path traversal, malformed ZIP members, decompression bombs, and
     unsupported encryption;
   - extract only into an isolated disposable workspace;
   - preserve the original archive unchanged.

3. **Provider adapter to canonical records**
   - conversation ID and title;
   - message ID, parent ID, branch/sibling relationship;
   - provider, model, speaker role, timestamps, content type;
   - attachment reference and source byte range/digest where available.

4. **Deterministic chronology and conversation topology**
   - provider timestamp;
   - conversation start time;
   - parent/child reply order rather than array position alone;
   - alternate branches preserved instead of flattened silently;
   - original first prompt retained as a navigation facet.

5. **Exact lexical index**
   - Unicode normalization and language-aware tokenization;
   - exact phrase, word, prefix, date, speaker, provider, and conversation
     indexes;
   - duplicate and near-duplicate candidate detection;
   - stop words reduce ranking weight but remain searchable.

6. **Structural segmentation**
   - messages -> turns -> topic segments -> sessions/episodes;
   - code, quotes, copied documents, instructions, jokes, hypotheticals, and
     assistant assertions marked as distinct evidence types;
   - secret and high-sensitivity candidates quarantined before model use.

7. **Semantic classification**
   - topic direction and entities;
   - preference, biography, project, decision, open loop, correction, promise,
     and changed belief;
   - user assertion kept separate from assistant inference;
   - every derived item must cite exact source message IDs.

8. **Priority projection**
   - rank candidates by personal relevance, recurrence, actionability,
     uniqueness, temporal freshness/validity, source confidence, contradiction,
     and sensitivity;
   - priority chooses what enters the bounded active context, not what survives
     in the archive;
   - contradictory and superseded claims remain visible rather than averaged.

9. **Scoped delivery**
   - an agent receives a task-specific context capsule, never the complete raw
     personal archive by default;
   - access has an explicit purpose, scope, expiry, and receipt;
   - deletion or correction triggers deterministic projection/index rebuild.

## Suggested canonical ordering key

```text
provider
  -> conversation_created_at
  -> conversation_id
  -> branch_path / parent_message_id
  -> message_created_at
  -> message_id
```

Dates alone are insufficient because exports may contain edits, regenerated
answers, missing timestamps, and alternate branches. Unknown ordering must be
represented explicitly instead of guessed.

## First acceptance fixture

A future implementation should start with a sanitized bounded sample and prove:

- stable replay produces byte-identical canonical records;
- one duplicated conversation is detected without deleting evidence;
- one alternate answer branch remains reconstructable;
- one assistant claim is not promoted into a user fact;
- one correction supersedes an earlier claim while preserving both sources;
- one sensitive item can be removed and becomes absent from every rebuilt
  retrieval index.

