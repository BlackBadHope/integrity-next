#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Retrieve bounded P1 context with reproducible route and provenance receipts."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import datetime as dt
import json
import math
import re
import sqlite3
import time
from pathlib import Path
from typing import Any

from memory_plane_common import atomic_json, canonical_json, sha256_bytes, sha256_file
from p1_projection import PROJECTION_PROTOCOL, sparse_vector, tokens


RETRIEVAL_PROTOCOL = "integrity-memory-plane.p1-retrieval.v1"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("query")
    parser.add_argument("--projection-db", type=Path, default=Path(_integrity_value('path_1ba0c7fb8a53')))
    parser.add_argument("--store-root", type=Path, default=Path(_integrity_value('path_5350cd670b63')))
    parser.add_argument("--receipt-root", type=Path, default=None)
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--capsule-bytes", type=int, default=32768)
    return parser.parse_args()


def _meta(connection: sqlite3.Connection, key: str, default: str = "") -> str:
    row = connection.execute("SELECT value FROM projection_meta WHERE key=?", (key,)).fetchone()
    return str(row[0]) if row else default


def _vector_map(value: str) -> dict[int, float]:
    return {int(index): float(weight) for index, weight in json.loads(value)}


def _manifest_proof(store_root: Path, digest: str) -> dict[str, Any]:
    matches = list((store_root / "segments").glob(f"*-{digest}.json"))
    if len(matches) != 1:
        return {"ok": False, "manifest_sha256": digest, "error": "manifest-reference-count"}
    path = matches[0]
    observed = sha256_file(path)
    return {
        "ok": observed == digest,
        "manifest_sha256": digest,
        "reference": path.name,
        "observed_sha256": observed,
    }


def _fts_query(query: str) -> str:
    values = tokens(query)[:16]
    return " OR ".join('"' + value.replace('"', '""') + '"' for value in values)


def retrieve(
    query: str,
    projection_db: Path,
    store_root: Path,
    *,
    limit: int = 20,
    capsule_budget: int = 32768,
) -> dict[str, Any]:
    started = time.perf_counter()
    normalized = query.strip()
    if not normalized:
        raise ValueError("retrieval query cannot be empty")
    if limit < 1 or limit > 100:
        raise ValueError("limit must be between 1 and 100")
    if capsule_budget < 8192 or capsule_budget > 32768:
        raise ValueError("capsule budget must be between 8192 and 32768 bytes")
    connection = sqlite3.connect(f"file:{projection_db.resolve()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        if _meta(connection, "protocol") != PROJECTION_PROTOCOL:
            raise RuntimeError("P1 projection protocol mismatch")
        projection_cursor = int(_meta(connection, "last_cursor", "0"))
        projection_head = _meta(connection, "manifest_head_sha256", "")
        witness_state = json.loads((store_root / "state.json").read_text(encoding="utf-8"))
        witness_cursor = int(witness_state.get("last_cursor") or 0)
        witness_head = str(witness_state.get("previous_manifest_sha256") or "")
        scores: dict[int, float] = {}
        routes: dict[str, list[dict[str, Any]]] = {"exact": [], "causal_path": [], "fts": [], "lexical": [], "graph": [], "vector": []}
        causal_path: dict[str, Any] | None = None

        if normalized.startswith("task_path:"):
            task_id = normalized.removeprefix("task_path:").strip()
            node_key = f"task_id:{task_id.casefold()}"
            path_ids = [
                int(row[0])
                for row in connection.execute(
                    "SELECT event_id FROM graph_edges WHERE node_key=? ORDER BY event_id",
                    (node_key,),
                )
            ]
            causal_path = {
                "kind": "TASK_SEQUENCE",
                "task_id": task_id,
                "event_ids": path_ids,
                "complete": bool(path_ids),
            }
            for index, event_id in enumerate(path_ids):
                score = 20.0 - (index / max(1, len(path_ids) * 1000))
                scores[event_id] = score
                routes["causal_path"].append({"event_id": event_id, "score": round(score, 8), "sequence_index": index})

        exact_match = re.fullmatch(r"#?(\d+)", normalized)
        exact_uid = normalized.removeprefix("event_uid:").strip() if normalized.startswith("event_uid:") else ""
        if exact_match:
            event_id = int(exact_match.group(1))
            if connection.execute("SELECT 1 FROM events WHERE id=?", (event_id,)).fetchone():
                scores[event_id] = 10.0
                routes["exact"].append({"event_id": event_id, "score": 10.0, "match": "event_id"})
        elif exact_uid:
            row = connection.execute("SELECT id FROM events WHERE event_uid=?", (exact_uid,)).fetchone()
            if row:
                event_id = int(row[0])
                scores[event_id] = 10.0
                routes["exact"].append({"event_id": event_id, "score": 10.0, "match": "event_uid"})

        fts = _fts_query(normalized)
        if fts:
            for row in connection.execute(
                "SELECT CAST(event_id AS INTEGER) event_id, bm25(events_fts) rank FROM events_fts WHERE events_fts MATCH ? ORDER BY rank LIMIT ?",
                (fts, min(1000, max(200, limit * 20))),
            ):
                event_id = int(row["event_id"])
                score = 4.0 / (1.0 + abs(float(row["rank"])))
                scores[event_id] = scores.get(event_id, 0.0) + score
                routes["fts"].append({"event_id": event_id, "score": round(score, 8)})
                event_row = connection.execute("SELECT body_text FROM events WHERE id=?", (event_id,)).fetchone()
                body = str(event_row[0] if event_row else "").casefold()
                query_terms = set(tokens(normalized))
                body_terms = set(tokens(body))
                coverage = len(query_terms & body_terms) / max(1, len(query_terms))
                lexical_score = coverage * 12.0
                if normalized.casefold() in body:
                    lexical_score += 8.0
                if lexical_score:
                    scores[event_id] = scores.get(event_id, 0.0) + lexical_score
                    routes["lexical"].append({"event_id": event_id, "score": round(lexical_score, 8), "coverage": round(coverage, 8)})

        query_tokens = sorted(set(tokens(normalized)))[:16]
        if query_tokens:
            placeholders = ",".join("?" for _ in query_tokens)
            graph_matches: dict[int, set[str]] = {}
            for row in connection.execute(
                f"SELECT e.event_id,n.node_key,n.kind,n.value FROM graph_edges e JOIN graph_nodes n ON n.node_key=e.node_key WHERE lower(n.value) IN ({placeholders}) ORDER BY e.event_id DESC LIMIT ?",
                (*query_tokens, min(1000, max(200, limit * 20))),
            ):
                event_id = int(row["event_id"])
                graph_matches.setdefault(event_id, set()).add(str(row["node_key"]))
            for event_id, nodes in graph_matches.items():
                score = min(2.0, 1.0 + 0.25 * (len(nodes) - 1))
                scores[event_id] = scores.get(event_id, 0.0) + score
                routes["graph"].append({"event_id": event_id, "score": score, "node_keys": sorted(nodes)[:8]})

        # P1 vectors are a deterministic sparse projection, not an authority or
        # a semantic proof source.  Hash collisions are therefore expected at
        # scale.  A vector hit may re-rank an event already grounded by an
        # exact/causal/FTS/graph route, but must never introduce support on its
        # own.
        grounded_event_ids = set(scores)
        query_vector_list, query_norm = sparse_vector(normalized)
        query_vector = {int(index): float(value) for index, value in query_vector_list}
        vector_hits: list[tuple[float, int]] = []
        if query_norm:
            for row in connection.execute("SELECT event_id,sparse_json,norm FROM event_vectors WHERE norm > 0"):
                candidate = _vector_map(str(row["sparse_json"]))
                dot = sum(value * candidate.get(index, 0.0) for index, value in query_vector.items())
                similarity = dot / (query_norm * float(row["norm"]))
                if similarity > 0:
                    vector_hits.append((similarity, int(row["event_id"])))
            for similarity, event_id in sorted(vector_hits, reverse=True)[: min(100, limit * 5)]:
                score = similarity
                eligible = event_id in grounded_event_ids
                if eligible:
                    scores[event_id] = scores.get(event_id, 0.0) + score
                routes["vector"].append(
                    {
                        "event_id": event_id,
                        "score": round(score, 8),
                        "eligible_for_support": eligible,
                    }
                )

        ranked = sorted(scores.items(), key=lambda item: (-item[1], -item[0]))
        included: list[dict[str, Any]] = []
        rejected_unproven = 0
        for event_id, score in ranked:
            row = connection.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
            if row is None:
                rejected_unproven += 1
                continue
            proof = _manifest_proof(store_root, str(row["source_manifest_sha256"]))
            if not proof["ok"]:
                rejected_unproven += 1
                continue
            details = str(row["details"] or "")
            candidate = {
                "event_id": event_id,
                "event_uid": str(row["event_uid"] or ""),
                "ts_utc": str(row["ts_utc"]),
                "actor": str(row["actor"]),
                "action": str(row["action"]),
                "summary": str(row["summary"])[:1200],
                "details": details[:4000],
                "score": round(score, 8),
                "manifest_proof": proof,
            }
            trial = {
                "protocol": RETRIEVAL_PROTOCOL + ".capsule",
                "query_sha256": sha256_bytes(normalized.encode("utf-8")),
                "event_cursor": projection_cursor,
                "events": [*included, candidate],
                "production_authority": False,
            }
            if len(canonical_json(trial)) > capsule_budget:
                continue
            included.append(candidate)
            if len(included) >= limit:
                break
        capsule = {
            "protocol": RETRIEVAL_PROTOCOL + ".capsule",
            "query_sha256": sha256_bytes(normalized.encode("utf-8")),
            "event_cursor": projection_cursor,
            "events": included,
            "production_authority": False,
        }
        capsule_bytes = len(canonical_json(capsule))
        proofs_ok = all((event.get("manifest_proof") or {}).get("ok") is True for event in included)
        supported = bool(included) and proofs_ok
        decision = "SUPPORTED" if supported else "NO_EVIDENCE"
        elapsed_ms = (time.perf_counter() - started) * 1000
        return {
            "protocol": RETRIEVAL_PROTOCOL + ".receipt",
            "decision": decision,
            "truth_status": "supported" if supported else "unknown",
            "query": normalized,
            "query_sha256": capsule["query_sha256"],
            "projection_cursor": projection_cursor,
            "witness_cursor": witness_cursor,
            "projection_lag_events": max(0, witness_cursor - projection_cursor),
            "projection_manifest_head_sha256": projection_head,
            "witness_manifest_head_sha256": witness_head,
            "routes": {name: {"candidate_count": len(values), "candidates": values[:20]} for name, values in routes.items()},
            "support_gate": {
                "policy": "grounded-route-required;vector-rerank-only",
                "grounded_candidate_count": len(grounded_event_ids),
                "vector_only_support_allowed": False,
            },
            "causal_path": causal_path,
            "ranked_candidate_count": len(ranked),
            "included_event_ids": [event["event_id"] for event in included],
            "rejected_unproven_count": rejected_unproven,
            "all_included_proven": proofs_ok,
            "unsupported_green_count": 0,
            "capsule_bytes": capsule_bytes,
            "capsule_budget_bytes": capsule_budget,
            "capsule_sha256": sha256_bytes(canonical_json(capsule)),
            "capsule": capsule,
            "elapsed_ms": round(elapsed_ms, 3),
            "production_authority": False,
            "memory_grants_authority": False,
        }
    finally:
        connection.close()


def main() -> int:
    args = parse_args()
    result = retrieve(args.query, args.projection_db, args.store_root, limit=args.limit, capsule_budget=args.capsule_bytes)
    if args.receipt_root is not None:
        stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
        atomic_json(args.receipt_root / f"retrieval-{stamp}-{result['query_sha256'][:16]}.json", result, mode=0o440)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
