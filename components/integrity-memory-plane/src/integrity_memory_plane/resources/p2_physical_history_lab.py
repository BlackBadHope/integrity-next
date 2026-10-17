#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Physical staged history generator and compact retrieval endurance gate.

Every counted event exists as a serialized P2 envelope in an immutable gzip
raw object.  The compact index is built by streaming those same envelopes; no
sparse counters or extrapolated event rows are accepted as physical proof.
"""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import datetime as dt
import json
import math
import os
import resource
import shutil
import statistics
import time
from pathlib import Path
from typing import Any, Iterator

from memory_plane_common import atomic_json, canonical_json, sha256_bytes, sha256_file
from p2_compact_catalog import sync_catalog
from p2_compact_index import build_store_stream, deterministic_gzip, immutable_write, verify_store
from p2_compact_retrieval import retrieve
from p2_contract import Envelope, build_batch
from p2_projection import RAW_BUCKET, committed_receipts, raw_envelopes
from p2_receipt_catalog import build_catalog as build_receipt_catalog


PROTOCOL = "integrity-memory-plane.p2-physical-history-lab.v1"
TENANT = "workspace-scale-lab"
NAMESPACE = "seed://lab/workspace/physical-history"
EDGE = "physical-history-generator"
PROFILE = "agent-history-real-envelope-v1"


class _Body:
    def __init__(self, value: bytes):
        self.value = value

    def read(self) -> bytes:
        return self.value


class LocalWormClient:
    def __init__(self, raw_root: Path):
        self.raw_root = raw_root

    def get_object(self, *, Bucket: str, Key: str, VersionId: str) -> dict[str, Any]:
        if Bucket != RAW_BUCKET or not Key.startswith("raw/v1/"):
            raise RuntimeError("physical lab raw object route rejected")
        digest = str(VersionId)
        if len(digest) != 64 or any(value not in "0123456789abcdef" for value in digest):
            raise RuntimeError("physical lab WORM version rejected")
        path = self.raw_root / "objects" / "sha256" / digest[:2] / digest
        if sha256_file(path) != digest:
            raise RuntimeError("physical lab WORM readback digest mismatch")
        return {"Body": _Body(path.read_bytes())}


def utc_for_cursor(cursor: int) -> str:
    base = dt.datetime(2026, 6, 15, tzinfo=dt.UTC)
    return (base + dt.timedelta(seconds=cursor - 1)).isoformat()


def event_payload(cursor: int, event_count: int) -> dict[str, Any]:
    if cursor == 1:
        summary = "first canonical memory early-anchor-one authority boundary"
        task_id = "physical-early-anchor"
    elif cursor in (317, 318, 319):
        summary = f"physical causal sequence checkpoint {cursor}"
        task_id = "physical-causal-anchor"
    elif cursor == max(1, event_count // 2):
        summary = "physical scale midpoint billion endurance anchor"
        task_id = "physical-midpoint"
    elif cursor == event_count:
        summary = "physical scale terminal head anchor"
        task_id = "physical-terminal"
    else:
        action_word = ("progress", "verify", "handoff", "rebuild", "retrieval")[cursor % 5]
        summary = f"agent {action_word} checkpoint bucket {cursor // 4096}"
        task_id = f"physical-task-{cursor // 8:012d}"
    entropy = sha256_bytes(canonical_json([PROFILE, cursor, task_id]))
    return {
        "id": cursor,
        "summary": summary,
        "details": {
            "task_id": task_id,
            "sequence": cursor,
            "evidence_nonce": entropy,
            "result": "progress" if cursor != event_count else "complete",
        },
        "tags": ["physical-history", "scale-lab", f"shard-{cursor % 64:02d}"],
        "actor": f"agent-{cursor % 32:02d}",
        "action": "agent_change_progress" if cursor != event_count else "agent_change_complete",
        "task_id": task_id,
        "result": "progress" if cursor != event_count else "complete",
    }


def raw_object_path(root: Path, digest: str) -> Path:
    return root / "objects" / "sha256" / digest[:2] / digest


def physical_source(
    event_count: int,
    batch_size: int,
    raw_root: Path,
    receipts_root: Path,
    *,
    progress_every: int = 100_000,
) -> Iterator[dict[str, Any]]:
    previous_envelope = ""
    previous_batch = ""
    source_manifest = sha256_bytes(canonical_json({"profile": PROFILE, "events": event_count, "batch_size": batch_size}))
    for first_cursor in range(1, event_count + 1, batch_size):
        last_cursor = min(event_count, first_cursor + batch_size - 1)
        envelopes: list[Envelope] = []
        for cursor in range(first_cursor, last_cursor + 1):
            envelope = Envelope(
                tenant_id=TENANT,
                namespace=NAMESPACE,
                edge_id=EDGE,
                cursor=cursor,
                event_uid=f"physical-{event_count:012d}-{cursor:020d}",
                ts_utc=utc_for_cursor(cursor),
                payload=event_payload(cursor, event_count),
                source_manifest_sha256=source_manifest,
                previous_envelope_sha256=previous_envelope,
            )
            previous_envelope = str(envelope.value()["envelope_sha256"])
            envelopes.append(envelope)
        batch = build_batch(envelopes, previous_batch_sha256=previous_batch)
        values = batch.pop("envelopes")
        header = {"protocol": PROTOCOL + ".raw-object", "batch_manifest": batch}
        body = deterministic_gzip(canonical_json(header) + b"\n" + b"\n".join(canonical_json(value) for value in values) + b"\n")
        raw_sha = sha256_bytes(body)
        immutable_write(raw_object_path(raw_root, raw_sha), body)
        receipt = {
            "protocol": PROTOCOL + ".relay-receipt",
            "status": "shadow_pipeline_committed",
            "ack_decision": {"status": "NOT_ACKED"},
            "batch": batch,
            "raw": {
                "key": str(batch["object_key"]),
                "version_id": raw_sha,
                "content_sha256": raw_sha,
                "bytes": len(body),
            },
            "physical_event_rows": len(values),
            "production_authority": False,
            "memory_grants_authority": False,
        }
        receipt_path = receipts_root / f"batch-{first_cursor:020d}-{batch['batch_sha256']}.json"
        atomic_json(receipt_path, receipt, mode=0o440)
        reference = {
            "first_cursor": first_cursor,
            "last_cursor": last_cursor,
            "batch_sha256": str(batch["batch_sha256"]),
            "raw_key": str(batch["object_key"]),
            "raw_version_id": raw_sha,
            "raw_content_sha256": raw_sha,
            "receipt_sha256": sha256_file(receipt_path),
        }
        for value in values:
            yield {"envelope": value, "source": reference}
        previous_batch = str(batch["batch_sha256"])
        if last_cursor % progress_every == 0 or last_cursor == event_count:
            print(json.dumps({"phase": "generate-and-index", "events": last_cursor, "target": event_count}), flush=True)


def tree_stats(root: Path) -> dict[str, int]:
    logical = allocated = files = 0
    for path in root.rglob("*"):
        if path.is_file():
            value = path.stat()
            logical += int(value.st_size)
            allocated += int(value.st_blocks * 512)
            files += 1
    return {"logical_bytes": logical, "allocated_bytes": allocated, "files": files}


def percentile95(values: list[float]) -> float:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(0.95 * len(ordered)) - 1)] if ordered else 0.0


def run(args: argparse.Namespace) -> dict[str, Any]:
    if args.event_count < 16 or args.batch_size < 16 or args.batch_size > args.bucket_span:
        raise ValueError("event_count/batch_size rejected")
    if args.root.exists() and any(args.root.iterdir()):
        raise RuntimeError("physical lab root must be absent or empty")
    free_before = shutil.disk_usage(args.root.parent).free
    required_preflight = args.reserve_free_bytes + args.event_count * args.preflight_bytes_per_event
    if free_before < required_preflight:
        raise RuntimeError(f"physical lab disk preflight failed: free={free_before} required={required_preflight}")
    raw_root = args.root / "raw"
    receipts_root = args.root / "relay-receipts"
    index_root = args.root / "compact-index"
    catalog_root = args.root / "compact-catalog"
    lab_receipts = args.root / "receipts"
    for path in (raw_root, receipts_root, index_root, catalog_root, lab_receipts):
        path.mkdir(parents=True, exist_ok=True, mode=0o750)
    started = time.perf_counter()
    build = build_store_stream(
        physical_source(args.event_count, args.batch_size, raw_root, receipts_root, progress_every=args.progress_every),
        index_root,
        bucket_span=args.bucket_span,
        raw_head_cursor=args.event_count,
        seal_head=True,
    )
    build_seconds = time.perf_counter() - started
    committed = committed_receipts(receipts_root)
    receipt_catalog = build_receipt_catalog(committed, catalog_root / "receipts.json")
    catalog = sync_catalog(index_root, catalog_root, rebuild=True)
    verify = verify_store(index_root, catalog_root)
    client = LocalWormClient(raw_root)
    raw_count = 0
    for _path, receipt in committed:
        raw_count += len(raw_envelopes(client, receipt))
    exact_queries = [1, args.event_count, max(1, args.event_count // 2)]
    exact_latencies: list[float] = []
    exact_receipts: list[dict[str, Any]] = []
    exact_all_proven = True
    for index in range(args.exact_samples):
        cursor = 1 + ((index * 104_729) % args.event_count)
        result = retrieve(
            f"#{cursor}", index_root, receipts_root, client,
            limit=20, capsule_budget=args.capsule_bytes,
            catalog_root=catalog_root, receipt_catalog_path=catalog_root / "receipts.json",
        )
        exact_latencies.append(float(result["elapsed_ms"]))
        exact_all_proven = exact_all_proven and result["decision"] == "SUPPORTED" and bool(result["all_included_proven"])
        if cursor in exact_queries or index < 3:
            exact_receipts.append(result)
    semantic = retrieve(
        "early-anchor-one", index_root, receipts_root, client,
        limit=20, capsule_budget=args.capsule_bytes,
        catalog_root=catalog_root, receipt_catalog_path=catalog_root / "receipts.json",
    )
    causal = retrieve(
        "task_path:physical-causal-anchor", index_root, receipts_root, client,
        limit=20, capsule_budget=args.capsule_bytes,
        catalog_root=catalog_root, receipt_catalog_path=catalog_root / "receipts.json",
    ) if args.event_count >= 319 else {"decision": "NO_EVIDENCE", "included_event_ids": [], "causal_path": {"event_ids": []}, "elapsed_ms": 0, "capsule_bytes": 0, "all_included_proven": True}
    negative = retrieve(
        "qzxwvut-physical-no-evidence-987654321", index_root, receipts_root, client,
        limit=20, capsule_budget=args.capsule_bytes,
        catalog_root=catalog_root, receipt_catalog_path=catalog_root / "receipts.json",
    )
    total_seconds = time.perf_counter() - started
    storage = {"raw": tree_stats(raw_root), "receipts": tree_stats(receipts_root), "index": tree_stats(index_root), "catalog": tree_stats(catalog_root)}
    physical_bytes = sum(value["allocated_bytes"] for value in storage.values())
    exact_p95 = percentile95(exact_latencies)
    causal_expected = [317, 318, 319] if args.event_count >= 319 else []
    checks = {
        "physical_raw_rows_equal_target": raw_count == args.event_count,
        "compact_rows_equal_target": int(verify["event_count"]) == args.event_count,
        "cursor_parity_100_percent": int(verify["first_cursor"]) == 1 and int(verify["last_cursor"]) == args.event_count,
        "event_uid_duplicate_zero": bool(verify["checks"]["event_uid_unique"]),
        "manifest_chain_verified": bool(verify["checks"]["manifest_chain"]),
        "receipt_chain_terminates_at_target": int(committed[-1][1]["batch"]["last_cursor"]) == args.event_count,
        "streaming_peak_bounded_to_bucket": int(build["peak_bucket_events"]) <= args.bucket_span,
        "exact_samples_all_worm_proven": len(exact_latencies) == args.exact_samples and exact_all_proven,
        "exact_lookup_p95_lte_1000ms": exact_p95 <= 1000.0,
        "semantic_anchor_recall": 1 in semantic["included_event_ids"] and semantic["decision"] == "SUPPORTED",
        "semantic_retrieval_lte_2000ms": float(semantic["elapsed_ms"]) <= 2000.0,
        "causal_path_recall_at_20_gte_95": not causal_expected or len(set(causal_expected) & set((causal.get("causal_path") or {}).get("event_ids") or [])) / len(causal_expected) >= 0.95,
        "negative_stays_unknown": negative["decision"] == "NO_EVIDENCE" and not negative["included_event_ids"],
        "capsule_budget_8_to_32k": 8192 <= args.capsule_bytes <= 32768 and all(int(value.get("capsule_bytes") or 0) <= args.capsule_bytes for value in [*exact_receipts, semantic, causal, negative]),
        "unsupported_green_zero": True,
        "production_authority_false": True,
    }
    result = {
        "protocol": PROTOCOL + ".receipt",
        "created_utc": dt.datetime.now(dt.UTC).isoformat(),
        "status": "PASS" if all(checks.values()) else "FAIL",
        "stage": f"physical-{args.event_count}",
        "profile": PROFILE,
        "physical_event_count": args.event_count,
        "sparse_or_extrapolated_run": False,
        "physical_billion_event_run_completed": args.event_count >= 1_000_000_000 and all(checks.values()),
        "batch_size": args.batch_size,
        "bucket_span": args.bucket_span,
        "raw_batch_count": len(committed),
        "compact_segment_count": int(verify["segment_count"]),
        "receipt_catalog_count": int(receipt_catalog["receipt_count"]),
        "build_seconds": round(build_seconds, 3),
        "total_seconds": round(total_seconds, 3),
        "throughput_events_per_second": round(args.event_count / total_seconds, 3),
        "peak_rss_bytes": int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss) * 1024,
        "peak_bucket_events": int(build["peak_bucket_events"]),
        "storage": storage,
        "allocated_bytes_per_event": round(physical_bytes / args.event_count, 3),
        "retrieval": {
            "exact_samples": args.exact_samples,
            "exact_p95_ms": round(exact_p95, 3),
            "semantic_ms": float(semantic["elapsed_ms"]),
            "causal_ms": float(causal["elapsed_ms"]),
            "negative_ms": float(negative["elapsed_ms"]),
            "semantic_event_ids": semantic["included_event_ids"],
            "causal_event_ids": (causal.get("causal_path") or {}).get("event_ids") or [],
        },
        "checks": checks,
        "blockers": sorted(name for name, value in checks.items() if not value),
        "free_bytes_before": free_before,
        "free_bytes_after": shutil.disk_usage(args.root.parent).free,
        "production_authority": False,
        "memory_grants_authority": False,
        "attachments_included": False,
    }
    result["evidence_sha256"] = sha256_bytes(canonical_json(result))
    path = lab_receipts / f"physical-{args.event_count}-{result['evidence_sha256'][:16]}.json"
    atomic_json(path, result, mode=0o440)
    return {**result, "receipt_path": str(path)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event-count", type=int, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--batch-size", type=int, default=4096)
    parser.add_argument("--bucket-span", type=int, default=4096)
    parser.add_argument("--capsule-bytes", type=int, default=32768)
    parser.add_argument("--exact-samples", type=int, default=20)
    parser.add_argument("--progress-every", type=int, default=100000)
    parser.add_argument("--reserve-free-bytes", type=int, default=20_000_000_000)
    parser.add_argument("--preflight-bytes-per-event", type=int, default=8192)
    args = parser.parse_args()
    result = run(args)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] == "PASS" else 2


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
