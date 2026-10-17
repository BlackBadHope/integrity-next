#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Ground compact-index candidates back to exact committed WORM versions."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import concurrent.futures
import json
import time
from pathlib import Path
from typing import Any

from memory_plane_common import canonical_json, sha256_bytes, sha256_file
from p2_compact_index import PROTOCOL as INDEX_PROTOCOL, candidate_lookup
from p2_projection import raw_envelopes
from p2_receipt_catalog import load_catalog as load_receipt_catalog, verified_receipt
from p2_retrieval import load_env, s3_client


PROTOCOL = "integrity-memory-plane.p2-compact-retrieval.v1"


def retrieve(
    query: str,
    index_root: Path,
    receipts_root: Path,
    client: Any,
    *,
    limit: int = 20,
    capsule_budget: int = 32768,
    catalog_root: Path | None = None,
    receipt_catalog_path: Path | None = None,
) -> dict[str, Any]:
    started = time.perf_counter()
    if limit < 1 or limit > 100:
        raise ValueError("limit must be between 1 and 100")
    if capsule_budget < 8192 or capsule_budget > 32768:
        raise ValueError("capsule_budget must be between 8192 and 32768")
    candidates = candidate_lookup(index_root, query, max(limit * 4, 20), catalog_root)
    state = json.loads((index_root / "state.json").read_text(encoding="utf-8"))
    projection_cursor = int(state.get("last_covered_cursor") or 0)
    raw_head_cursor = int(state.get("raw_head_cursor") or 0)
    if receipt_catalog_path is None:
        if catalog_root is None:
            raise RuntimeError("compact retrieval requires a receipt catalog")
        receipt_catalog_path = catalog_root / "receipts.json"
    receipt_catalog = load_receipt_catalog(receipt_catalog_path)
    by_batch = {str(value["batch_sha256"]): value for value in receipt_catalog["entries"]}
    cache: dict[str, list[dict[str, Any]]] = {}
    included: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    planned: list[tuple[int, dict[str, Any], Path, dict[str, Any]]] = []
    for cursor in candidates["candidate_cursors"]:
        locator = candidates["source_locators"].get(str(cursor))
        if not locator:
            rejected.append({"cursor": cursor, "reason": "missing-source-locator"})
            continue
        batch_sha = str(locator["batch_sha256"])
        entry = by_batch.get(batch_sha)
        if entry is None:
            rejected.append({"cursor": cursor, "reason": "missing-committed-receipt"})
            continue
        receipt_path, receipt = verified_receipt(receipts_root, entry)
        if sha256_file(receipt_path) != str(locator["receipt_sha256"]):
            rejected.append({"cursor": cursor, "reason": "receipt-digest-mismatch"})
            continue
        raw = receipt["raw"]
        expected_raw = {
            "raw_key": str(raw["key"]),
            "raw_version_id": str(raw["version_id"]),
            "raw_content_sha256": str(raw["content_sha256"]),
        }
        if any(str(locator[name]) != value for name, value in expected_raw.items()):
            rejected.append({"cursor": cursor, "reason": "raw-version-locator-mismatch"})
            continue
        planned.append((int(cursor), locator, receipt_path, receipt))
        if len(planned) >= limit:
            break
    unique = {str(receipt["batch"]["batch_sha256"]): receipt for _cursor, _locator, _path, receipt in planned}
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, max(1, len(unique))), thread_name_prefix="integrity-cold-worm") as executor:
        futures = {batch_sha: executor.submit(raw_envelopes, client, receipt) for batch_sha, receipt in unique.items()}
        for batch_sha, future in futures.items():
            cache[batch_sha] = future.result()
    for cursor, locator, receipt_path, receipt in planned:
        batch_sha = str(receipt["batch"]["batch_sha256"])
        raw = receipt["raw"]
        envelope = next((value for value in cache[batch_sha] if int(value["cursor"]) == int(cursor)), None)
        if envelope is None:
            rejected.append({"cursor": cursor, "reason": "cursor-absent-from-proven-raw"})
            continue
        event = envelope["payload"]
        route_hits = [name for name, values in candidates["routes"].items() if int(cursor) in values]
        proof = {
            "ok": True,
            "receipt_sha256": str(locator["receipt_sha256"]),
            "batch_sha256": batch_sha,
            "raw_object_key": str(raw["key"]),
            "raw_object_version": str(raw["version_id"]),
            "raw_content_sha256": str(raw["content_sha256"]),
            "envelope_sha256": str(envelope["envelope_sha256"]),
            "payload_sha256": str(envelope["payload_sha256"]),
        }
        item = {
            "event_id": int(cursor),
            "event_uid": str(envelope["event_uid"]),
            "ts_utc": str(envelope["ts_utc"]),
            "actor": str(event.get("actor") or ""),
            "action": str(event.get("action") or ""),
            "summary": str(event.get("summary") or "")[:1200],
            "details": json.dumps(event.get("details") or {}, ensure_ascii=False, sort_keys=True)[:4000],
            "included_by_routes": route_hits,
            "why_included": "compact candidate intersected a verified committed raw WORM version",
            "worm_proof": proof,
        }
        trial = {
            "protocol": PROTOCOL + ".capsule",
            "query_sha256": sha256_bytes(query.strip().encode("utf-8")),
            "coverage_through_cursor": projection_cursor,
            "events": [*included, item],
            "production_authority": False,
        }
        if len(canonical_json(trial)) > capsule_budget:
            rejected.append({"cursor": cursor, "reason": "capsule-budget"})
            continue
        included.append(item)
        if len(included) >= limit:
            break
    capsule = {
        "protocol": PROTOCOL + ".capsule",
        "query_sha256": sha256_bytes(query.strip().encode("utf-8")),
        "coverage_through_cursor": projection_cursor,
        "events": included,
        "production_authority": False,
    }
    proofs_ok = bool(included) and all(item["worm_proof"]["ok"] is True for item in included)
    decision = "SUPPORTED" if proofs_ok else "NO_EVIDENCE" if not included else "UNPROVEN"
    result = {
        "protocol": PROTOCOL + ".receipt",
        "decision": decision,
        "truth_status": "shadow-supported-prefix" if decision == "SUPPORTED" else "unknown",
        "query": query.strip(),
        "query_sha256": capsule["query_sha256"],
        "index_protocol": INDEX_PROTOCOL,
        "projection_cursor": projection_cursor,
        "raw_head_cursor": raw_head_cursor,
        "projection_lag_events": max(0, raw_head_cursor - projection_cursor),
        "coverage_complete_to_observed_raw_head": projection_cursor == raw_head_cursor,
        "candidate_receipt": candidates,
        "causal_path": candidates.get("causal_path"),
        "included_event_ids": [item["event_id"] for item in included],
        "rejected_candidates": rejected,
        "all_included_proven": proofs_ok,
        "unsupported_green_count": 0,
        "support_gate": {
            "compact_candidate_alone_may_support": False,
            "exact_committed_worm_version_required": True,
            "receipt_and_envelope_digest_required": True,
        },
        "capsule_bytes": len(canonical_json(capsule)),
        "capsule_budget_bytes": capsule_budget,
        "capsule_sha256": sha256_bytes(canonical_json(capsule)),
        "capsule": capsule,
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
        "production_authority": False,
        "memory_grants_authority": False,
    }
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("query")
    parser.add_argument("--index-root", type=Path, required=True)
    parser.add_argument("--receipts", type=Path, default=Path(_integrity_value('path_f5a9a1727fe8')))
    parser.add_argument("--catalog-root", type=Path)
    parser.add_argument("--minio-env", type=Path, default=Path("/etc/integrity-memory-p2/dual-reader-minio.env"))
    parser.add_argument("--s3-endpoint", default=_integrity_value('endpoint_1940bdd68a0a'))
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--capsule-bytes", type=int, default=32768)
    args = parser.parse_args()
    result = retrieve(
        args.query,
        args.index_root,
        args.receipts,
        s3_client(load_env(args.minio_env), args.s3_endpoint),
        limit=args.limit,
        capsule_budget=args.capsule_bytes,
        catalog_root=args.catalog_root,
    )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["decision"] != "UNPROVEN" else 2


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
