#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bounded P2 shadow retrieval grounded back to exact WORM raw versions."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import concurrent.futures
import json
import math
import re
import time
from pathlib import Path
from typing import Any

import boto3
import psycopg
from botocore.client import Config

from memory_plane_common import canonical_json, sha256_bytes, sha256_file
from p2_projection import EDGE_ID, NAMESPACE, RAW_BUCKET, TENANT_ID, committed_receipts, event_body, raw_envelopes, sparse_vector, tokens
from p2_receipt_catalog import entry_for_cursor, load_catalog as load_receipt_catalog, verified_receipt


PROTOCOL = "integrity-memory-plane.p2-retrieval.v1"
FTS_TERM_RE = re.compile(r"[0-9A-Za-zА-Яа-яЁё]{2,}", re.UNICODE)


def load_env(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            key, separator, value = line.partition("=")
            if not separator:
                raise RuntimeError(f"invalid environment line in {path}")
            result[key] = value
    return result


def connect(env: dict[str, str], host: str) -> psycopg.Connection[Any]:
    return psycopg.connect(host=host, port=55432, user=env["POSTGRES_DUAL_USER"], password=env["POSTGRES_DUAL_PASSWORD"], dbname=env["POSTGRES_DUAL_DB"], connect_timeout=5)


def s3_client(env: dict[str, str], endpoint: str) -> Any:
    return boto3.client("s3", endpoint_url=endpoint, aws_access_key_id=env["MINIO_DUAL_ACCESS_KEY"], aws_secret_access_key=env["MINIO_DUAL_SECRET_KEY"], region_name="us-east-1", config=Config(signature_version="s3v4", s3={"addressing_style": "path"}, retries={"max_attempts": 2}))


def vector_map(value: Any) -> dict[int, float]:
    return {int(index): float(weight) for index, weight in value}


def receipt_for_cursor(receipts: list[tuple[Path, dict[str, Any]]], cursor: int) -> tuple[Path, dict[str, Any]] | None:
    for path, receipt in receipts:
        batch = receipt["batch"]
        if int(batch["first_cursor"]) <= cursor <= int(batch["last_cursor"]):
            return path, receipt
    return None


def fts_or_query(query_terms: list[str]) -> str:
    """Build a bounded simple-dictionary OR query from tokenizer output."""

    return " | ".join(query_terms)


def fts_terms(value: str) -> list[str]:
    """Return tsquery-safe lexemes without route/task punctuation."""

    return sorted({match.group(0).casefold() for match in FTS_TERM_RE.finditer(value)})[:16]


def retrieve(
    query: str,
    connection: psycopg.Connection[Any],
    client: Any,
    receipts_root: Path,
    *,
    limit: int = 20,
    capsule_budget: int = 32768,
    receipt_catalog_path: Path | None = None,
) -> dict[str, Any]:
    started = time.perf_counter()
    normalized = query.strip()
    if not normalized:
        raise ValueError("retrieval query cannot be empty")
    if limit < 1 or limit > 100 or capsule_budget < 8192 or capsule_budget > 32768:
        raise ValueError("retrieval bounds rejected")
    receipt_catalog = load_receipt_catalog(receipt_catalog_path) if receipt_catalog_path else None
    receipts = [] if receipt_catalog else committed_receipts(receipts_root)
    raw_head = int(receipt_catalog["last_cursor"]) if receipt_catalog else int(receipts[-1][1]["batch"]["last_cursor"]) if receipts else 0
    offset_rows = connection.execute(
        "SELECT projection_name,last_cursor,last_batch_sha256 FROM integrity_p2.projection_offsets WHERE tenant_id=%s AND namespace=%s AND edge_id=%s",
        (TENANT_ID, NAMESPACE, EDGE_ID),
    ).fetchall()
    offsets = {str(row[0]): (int(row[1]), str(row[2]).rstrip()) for row in offset_rows}
    required = ("fts", "graph", "vector", "task-state")
    projection_cursor = min((offsets.get(name, (0, ""))[0] for name in required), default=0)
    offsets_complete = all(name in offsets for name in required)
    offsets_equal = offsets_complete and len({offsets[name] for name in required}) == 1
    scores: dict[int, float] = {}
    routes: dict[str, list[dict[str, Any]]] = {"exact": [], "causal_path": [], "fts": [], "lexical": [], "graph": [], "vector": []}
    payload_digests: dict[int, str] = {}
    causal_path: dict[str, Any] | None = None
    if normalized.startswith("task_path:"):
        task_id = normalized.removeprefix("task_path:").strip()
        node_key = f"task_id:{task_id.casefold()}"
        path_ids = [int(row[0]) for row in connection.execute("SELECT cursor FROM integrity_p2.projection_graph_edges WHERE tenant_id=%s AND namespace=%s AND edge_id=%s AND node_key=%s AND cursor<=%s ORDER BY cursor", (TENANT_ID, NAMESPACE, EDGE_ID, node_key, projection_cursor))]
        causal_path = {"kind": "TASK_SEQUENCE", "task_id": task_id, "event_ids": path_ids, "complete": bool(path_ids)}
        for index, cursor in enumerate(path_ids):
            score = 20.0 - index / max(1, len(path_ids) * 1000)
            scores[cursor] = score
            routes["causal_path"].append({"event_id": cursor, "score": round(score, 8), "sequence_index": index})
    exact_match = re.fullmatch(r"#?(\d+)", normalized)
    exact_uid = normalized.removeprefix("event_uid:").strip() if normalized.startswith("event_uid:") else ""
    if exact_match:
        cursor = int(exact_match.group(1))
        row = connection.execute("SELECT payload_sha256 FROM integrity_p2.raw_events WHERE tenant_id=%s AND namespace=%s AND edge_id=%s AND cursor=%s AND cursor<=%s", (TENANT_ID, NAMESPACE, EDGE_ID, cursor, projection_cursor)).fetchone()
        if row:
            scores[cursor] = 10.0
            payload_digests[cursor] = str(row[0]).rstrip()
            routes["exact"].append({"event_id": cursor, "score": 10.0, "match": "event_id"})
    elif exact_uid:
        row = connection.execute("SELECT cursor,payload_sha256 FROM integrity_p2.raw_events WHERE tenant_id=%s AND namespace=%s AND event_uid=%s AND cursor<=%s", (TENANT_ID, NAMESPACE, exact_uid, projection_cursor)).fetchone()
        if row:
            cursor = int(row[0])
            scores[cursor] = 10.0
            payload_digests[cursor] = str(row[1]).rstrip()
            routes["exact"].append({"event_id": cursor, "score": 10.0, "match": "event_uid"})
    # Exact and causal routes are already typed, deterministic and grounded.
    # Do not fan them out into a broad lexical scan: that adds unrelated hits,
    # wastes the latency budget and weakens route semantics.
    query_terms = [] if causal_path is not None or exact_match or exact_uid else fts_terms(normalized)
    if query_terms:
        or_query = fts_or_query(query_terms)
        rows = connection.execute(
            "SELECT cursor,payload_sha256,body_text,"
            " ts_rank_cd(search_document,to_tsquery('simple',%s),32) AS fts_rank,"
            " search_document @@ plainto_tsquery('simple',%s) AS all_terms,"
            " position(lower(%s) in lower(body_text)) > 0 AS exact_phrase"
            " FROM integrity_p2.projection_fts_events"
            " WHERE tenant_id=%s AND namespace=%s AND edge_id=%s AND cursor<=%s"
            " AND search_document @@ to_tsquery('simple',%s)"
            " ORDER BY exact_phrase DESC,all_terms DESC,fts_rank DESC,cursor DESC LIMIT %s",
            (or_query, normalized, normalized, TENANT_ID, NAMESPACE, EDGE_ID, projection_cursor, or_query, min(1000, max(200, limit * 20))),
        ).fetchall()
        for row in rows:
            cursor = int(row[0])
            body = str(row[2]).casefold()
            body_terms = set(tokens(body))
            coverage = len(set(query_terms) & body_terms) / max(1, len(query_terms))
            lexical = coverage * 12.0 + (8.0 if normalized.casefold() in body else 0.0)
            fts_rank = max(0.0, float(row[3]))
            all_terms = bool(row[4])
            exact_phrase = bool(row[5])
            fts_score = 4.0 + min(4.0, fts_rank * 8.0) + (2.0 if all_terms else 0.0) + (4.0 if exact_phrase else 0.0)
            scores[cursor] = scores.get(cursor, 0.0) + fts_score + lexical
            payload_digests[cursor] = str(row[1]).rstrip()
            routes["fts"].append({"event_id": cursor, "score": round(fts_score, 8), "rank": round(fts_rank, 8), "all_terms": all_terms, "exact_phrase": exact_phrase})
            if lexical:
                routes["lexical"].append({"event_id": cursor, "score": round(lexical, 8), "coverage": round(coverage, 8)})
        graph_rows = connection.execute(
            "SELECT e.cursor,e.node_key FROM integrity_p2.projection_graph_edges e JOIN integrity_p2.projection_graph_nodes n ON n.tenant_id=e.tenant_id AND n.namespace=e.namespace AND n.node_key=e.node_key WHERE e.tenant_id=%s AND e.namespace=%s AND e.edge_id=%s AND e.cursor<=%s AND lower(n.value)=ANY(%s) ORDER BY e.cursor DESC LIMIT %s",
            (TENANT_ID, NAMESPACE, EDGE_ID, projection_cursor, query_terms, min(1000, max(200, limit * 20))),
        ).fetchall()
        graph_matches: dict[int, set[str]] = {}
        for row in graph_rows:
            graph_matches.setdefault(int(row[0]), set()).add(str(row[1]))
        for cursor, nodes in graph_matches.items():
            score = min(2.0, 1.0 + 0.25 * (len(nodes) - 1))
            scores[cursor] = scores.get(cursor, 0.0) + score
            routes["graph"].append({"event_id": cursor, "score": score, "node_keys": sorted(nodes)[:8]})
    grounded = set(scores)
    query_vector_list, query_norm = sparse_vector(normalized)
    query_vector = vector_map(query_vector_list)
    if query_norm and grounded:
        for row in connection.execute("SELECT cursor,sparse_vector,norm FROM integrity_p2.projection_vector_events WHERE tenant_id=%s AND namespace=%s AND edge_id=%s AND cursor=ANY(%s)", (TENANT_ID, NAMESPACE, EDGE_ID, list(grounded))):
            candidate = vector_map(row[1])
            similarity = sum(value * candidate.get(index, 0.0) for index, value in query_vector.items()) / (query_norm * float(row[2])) if float(row[2]) else 0.0
            if similarity > 0:
                cursor = int(row[0])
                scores[cursor] += similarity
                routes["vector"].append({"event_id": cursor, "score": round(similarity, 8), "eligible_for_support": True})
    ranked = sorted(scores.items(), key=lambda value: (-value[1], -value[0]))
    batch_cache: dict[str, list[dict[str, Any]]] = {}
    included: list[dict[str, Any]] = []
    rejected_unproven = 0
    planned: list[tuple[int, float, Path, dict[str, Any]]] = []
    for cursor, score in ranked:
        if receipt_catalog:
            entry = entry_for_cursor(receipt_catalog, cursor)
            source = verified_receipt(receipts_root, entry) if entry else None
        else:
            source = receipt_for_cursor(receipts, cursor)
        if source is None:
            rejected_unproven += 1
            continue
        receipt_path, receipt = source
        planned.append((cursor, score, receipt_path, receipt))
        if len(planned) >= limit:
            break
    unique = {str(receipt["batch"]["batch_sha256"]): receipt for _cursor, _score, _path, receipt in planned}
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, max(1, len(unique))), thread_name_prefix="integrity-hot-worm") as executor:
        futures = {batch_sha: executor.submit(raw_envelopes, client, receipt) for batch_sha, receipt in unique.items()}
        for batch_sha, future in futures.items():
            batch_cache[batch_sha] = future.result()
    for cursor, score, receipt_path, receipt in planned:
        batch_sha = str(receipt["batch"]["batch_sha256"])
        envelope = next((value for value in batch_cache[batch_sha] if int(value["cursor"]) == cursor), None)
        if envelope is None or (payload_digests.get(cursor) and payload_digests[cursor] != str(envelope["payload_sha256"])):
            rejected_unproven += 1
            continue
        raw = receipt["raw"]
        proof = {
            "ok": True,
            "receipt_sha256": sha256_file(receipt_path),
            "batch_sha256": batch_sha,
            "raw_object_key": str(raw["key"]),
            "raw_object_version": str(raw["version_id"]),
            "raw_content_sha256": str(raw["content_sha256"]),
            "envelope_sha256": str(envelope["envelope_sha256"]),
            "payload_sha256": str(envelope["payload_sha256"]),
        }
        event = envelope["payload"]
        candidate = {
            "event_id": cursor,
            "event_uid": str(envelope["event_uid"]),
            "ts_utc": str(envelope["ts_utc"]),
            "actor": str(event.get("actor") or ""),
            "action": str(event.get("action") or ""),
            "summary": str(event.get("summary") or "")[:1200],
            "details": json.dumps(event.get("details") or {}, ensure_ascii=False, sort_keys=True)[:4000],
            "score": round(score, 8),
            "worm_proof": proof,
        }
        trial = {"protocol": PROTOCOL + ".capsule", "query_sha256": sha256_bytes(normalized.encode()), "event_cursor": projection_cursor, "events": [*included, candidate], "production_authority": False}
        if len(canonical_json(trial)) <= capsule_budget:
            included.append(candidate)
        if len(included) >= limit:
            break
    capsule = {"protocol": PROTOCOL + ".capsule", "query_sha256": sha256_bytes(normalized.encode()), "event_cursor": projection_cursor, "events": included, "production_authority": False}
    proofs_ok = all((value.get("worm_proof") or {}).get("ok") is True for value in included)
    # A retrieval receipt proves a bounded immutable prefix.  A moving raw
    # tail does not invalidate historical WORM evidence; it only limits
    # coverage through projection_cursor.  Queries beyond that prefix cannot
    # produce candidates because every projection/raw lookup is cursor-bound.
    proven_plane = offsets_equal
    supported = bool(included) and proofs_ok and proven_plane
    return {
        "protocol": PROTOCOL + ".receipt",
        "decision": "SUPPORTED" if supported else "NO_EVIDENCE" if not included else "UNPROVEN",
        "truth_status": "shadow-supported-prefix" if supported else "unknown",
        "query": normalized,
        "query_sha256": capsule["query_sha256"],
        "projection_cursor": projection_cursor,
        "raw_head_cursor": raw_head,
        "projection_lag_events": max(0, raw_head - projection_cursor),
        "coverage_complete_to_raw_head": projection_cursor == raw_head,
        "coverage_through_cursor": projection_cursor,
        "offsets_equal": offsets_equal,
        "routes": {name: {"candidate_count": len(values), "candidates": values[:20]} for name, values in routes.items()},
        "support_gate": {"policy": "grounded-route-and-exact-WORM-proof-required;vector-rerank-only", "vector_only_support_allowed": False, "exact_worm_version_required": True},
        "causal_path": causal_path,
        "ranked_candidate_count": len(ranked),
        "included_event_ids": [value["event_id"] for value in included],
        "rejected_unproven_count": rejected_unproven,
        "all_included_proven": proofs_ok,
        "unsupported_green_count": 0,
        "capsule_bytes": len(canonical_json(capsule)),
        "capsule_budget_bytes": capsule_budget,
        "capsule_sha256": sha256_bytes(canonical_json(capsule)),
        "capsule": capsule,
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
        "production_authority": False,
        "memory_grants_authority": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("query")
    parser.add_argument("--pg-env", type=Path, default=Path("/etc/integrity-memory-p2/dual-reader.env"))
    parser.add_argument("--minio-env", type=Path, default=Path("/etc/integrity-memory-p2/dual-reader-minio.env"))
    parser.add_argument("--receipts", type=Path, default=Path(_integrity_value('path_f5a9a1727fe8')))
    parser.add_argument("--postgres-host", default="127.0.0.1")
    parser.add_argument("--s3-endpoint", default=_integrity_value('endpoint_1940bdd68a0a'))
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--capsule-bytes", type=int, default=32768)
    args = parser.parse_args()
    with connect(load_env(args.pg_env), args.postgres_host) as connection:
        result = retrieve(args.query, connection, s3_client(load_env(args.minio_env), args.s3_endpoint), args.receipts, limit=args.limit, capsule_budget=args.capsule_bytes)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["decision"] != "UNPROVEN" else 2


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
