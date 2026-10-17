#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Measure and fail closed on physical billion-event capacity prerequisites."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import json
import os
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import boto3
import psycopg
from botocore.client import Config

from memory_plane_common import atomic_json, canonical_json, sha256_bytes
from offhost_windows_replica import execute_remote


PROTOCOL = "integrity-memory-plane.p2-billion-capacity.v1"
TARGET_EVENTS = 1_000_000_000
HEADROOM_FACTOR = 2.0
RAW_BUCKET = "integrity-p2-raw"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        key, separator, value = raw.strip().partition("=")
        if separator and key and value:
            values[key] = value
    return values


def connect(env: dict[str, str], prefix: str) -> psycopg.Connection[Any]:
    return psycopg.connect(
        host="127.0.0.1",
        port=55432,
        user=env[f"POSTGRES_{prefix}_USER"],
        password=env[f"POSTGRES_{prefix}_PASSWORD"],
        dbname=env[f"POSTGRES_{prefix}_DB"],
        connect_timeout=5,
    )


def relation(connection: psycopg.Connection[Any], name: str) -> dict[str, int]:
    rows = int(connection.execute(f"SELECT count(*) FROM integrity_p2.{name}").fetchone()[0])
    heap, indexes, total = connection.execute(
        "SELECT pg_relation_size(%s),pg_indexes_size(%s),pg_total_relation_size(%s)",
        (f"integrity_p2.{name}",) * 3,
    ).fetchone()
    return {"rows": rows, "heap_bytes": int(heap), "index_bytes": int(indexes), "total_bytes": int(total)}


def postgres_observation(guard_env: Path, dual_env: Path) -> dict[str, Any]:
    with connect(load_env(guard_env), "GUARD") as connection:
        events = int(connection.execute("SELECT count(*) FROM integrity_p2.raw_events").fetchone()[0])
        distribution = [
            {"relation": str(row[0]), "rows": int(row[1])}
            for row in connection.execute(
                "SELECT tableoid::regclass::text,count(*) FROM integrity_p2.raw_events GROUP BY tableoid ORDER BY tableoid::regclass::text"
            )
        ]
        partition_sizes = [
            {"relation": str(row[0]), "total_bytes": int(row[1])}
            for row in connection.execute(
                "SELECT c.relname,pg_total_relation_size(c.oid) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                "WHERE n.nspname='integrity_p2' AND c.relkind='r' AND c.relname ~ '^raw_events_p[0-9]+$' ORDER BY c.relname"
            )
        ]
        guard = {name: relation(connection, name) for name in ("ingest_batches", "dead_letters", "gap_guard_runs")}
    with connect(load_env(dual_env), "DUAL") as connection:
        projections = {
            name: relation(connection, name)
            for name in (
                "projection_fts_events",
                "projection_vector_events",
                "projection_graph_nodes",
                "projection_graph_edges",
                "current_task_state",
            )
        }
    return {
        "events": events,
        "raw_partition_distribution": distribution,
        "raw_partition_sizes": partition_sizes,
        "raw_partition_total_bytes": sum(value["total_bytes"] for value in partition_sizes),
        "guard_tables": guard,
        "projections": projections,
    }


def s3_observation(env_path: Path, endpoint: str) -> dict[str, int]:
    env = load_env(env_path)
    client = boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=env["MINIO_GUARD_ACCESS_KEY"],
        aws_secret_access_key=env["MINIO_GUARD_SECRET_KEY"],
        region_name="us-east-1",
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}, retries={"max_attempts": 2}),
    )
    latest_objects = latest_bytes = versions = version_bytes = 0
    for page in client.get_paginator("list_object_versions").paginate(Bucket=RAW_BUCKET, Prefix="raw/v1/"):
        for item in page.get("Versions", []):
            size = int(item["Size"])
            versions += 1
            version_bytes += size
            if item.get("IsLatest"):
                latest_objects += 1
                latest_bytes += size
    return {
        "latest_objects": latest_objects,
        "latest_logical_bytes": latest_bytes,
        "versions": versions,
        "all_version_bytes": version_bytes,
    }


def filesystem_free(path: Path) -> int:
    value = os.statvfs(path)
    return int(value.f_bavail * value.f_frsize)


def client_observation(endpoint: str, token_file: Path) -> dict[str, Any]:
    command = r'''$capsuleRoot='D:\workspace\IntegrityMemoryPlane\p2-raw\capsules';$files=@(Get-ChildItem -LiteralPath $capsuleRoot -File -ErrorAction SilentlyContinue);$vols=@(Get-Volume|Where-Object {$_.DriveLetter -in 'C','D'}|ForEach-Object{[ordered]@{drive=[string]$_.DriveLetter;free_bytes=[int64]$_.SizeRemaining;size_bytes=[int64]$_.Size}});[ordered]@{ok=$true;host=$env:COMPUTERNAME;volumes=$vols;capsules=$files.Count;capsule_total_bytes=[int64]($files|Measure-Object Length -Sum).Sum;capsule_max_bytes=[int64]($files|Measure-Object Length -Maximum).Maximum}|ConvertTo-Json -Depth 4 -Compress'''
    return execute_remote(endpoint, token_file, command, timeout=40)


def per_event(total: int, events: int) -> float:
    return float(total) / events if events > 0 else float("inf")


def evaluate(observed: dict[str, Any]) -> dict[str, Any]:
    postgres = observed["postgres"]
    s3 = observed["s3"]
    client = observed["client"]
    events = int(postgres["events"])
    projections = postgres["projections"]
    guard = postgres["guard_tables"]
    raw_object_bpe = per_event(int(s3["latest_logical_bytes"]), events)
    raw_metadata_bpe = per_event(int(postgres["raw_partition_total_bytes"]), events)
    ingest_bpe = per_event(int(guard["ingest_batches"]["total_bytes"]), events)
    fts_bpe = per_event(int(projections["projection_fts_events"]["total_bytes"]), events)
    vector_bpe = per_event(int(projections["projection_vector_events"]["total_bytes"]), events)
    graph_bpe = per_event(
        int(projections["projection_graph_nodes"]["total_bytes"])
        + int(projections["projection_graph_edges"]["total_bytes"]),
        events,
    )
    pg_linear_bpe = raw_metadata_bpe + ingest_bpe + fts_bpe + vector_bpe + graph_bpe
    steady_bpe = 2 * raw_object_bpe + pg_linear_bpe
    steady_bytes = int(steady_bpe * TARGET_EVENTS)
    required_bytes = int(steady_bytes * HEADROOM_FACTOR)
    client_free = sum(int(value["free_bytes"]) for value in client.get("volumes", []) if value.get("drive") == "D")
    available = int(observed["linux_free_bytes"]) + client_free
    distribution = postgres["raw_partition_distribution"]
    max_partition_share = max((int(value["rows"]) for value in distribution), default=0) / events if events else 1.0
    capsules = int(client.get("capsules") or 0)
    capsule_max = int(client.get("capsule_max_bytes") or 0)
    capsule_total = int(client.get("capsule_total_bytes") or 0)
    repetition = float(capsule_total) / capsule_max if capsule_max else float("inf")
    checks = {
        "sample_events_at_least_5000": events >= 5000,
        "raw_partition_max_share_at_most_25_percent": max_partition_share <= 0.25,
        "offhost_is_incremental_not_cumulative_snapshots": capsules <= 1 or repetition <= 1.25,
        "combined_proven_free_capacity_has_2x_headroom": available >= required_bytes,
        "physical_billion_run_already_completed": False,
    }
    blockers = sorted(name for name, value in checks.items() if not value)
    result = {
        "protocol": PROTOCOL + ".evidence",
        "created_utc": utc_now(),
        "status": "PASS" if not blockers else "FAIL",
        "target_events": TARGET_EVENTS,
        "headroom_factor": HEADROOM_FACTOR,
        "sample_events": events,
        "observed_bytes_per_event": {
            "raw_worm_object": round(raw_object_bpe, 3),
            "raw_postgres_metadata": round(raw_metadata_bpe, 3),
            "ingest_batch_metadata": round(ingest_bpe, 3),
            "fts_projection": round(fts_bpe, 3),
            "vector_projection": round(vector_bpe, 3),
            "graph_projection": round(graph_bpe, 3),
            "postgres_event_linear_total": round(pg_linear_bpe, 3),
            "two_raw_domains_plus_postgres": round(steady_bpe, 3),
        },
        "capacity_projection": {
            "steady_state_bytes": steady_bytes,
            "required_with_rebuild_headroom_bytes": required_bytes,
            "linux_free_bytes": int(observed["linux_free_bytes"]),
            "client_d_free_bytes": client_free,
            "combined_proven_free_bytes": available,
            "available_fraction": round(available / required_bytes, 6) if required_bytes else 0,
        },
        "partitioning": {
            "active_partitions": len(distribution),
            "distribution": distribution,
            "max_partition_share": round(max_partition_share, 6),
        },
        "offhost": {
            "capsules": capsules,
            "total_bytes": capsule_total,
            "max_capsule_bytes": capsule_max,
            "cumulative_repetition_factor": round(repetition, 6),
        },
        "current_task_state_bytes": int(projections["current_task_state"]["total_bytes"]),
        "checks": checks,
        "blockers": blockers,
        "sparse_or_extrapolated_pass": False,
        "production_authority": False,
        "memory_grants_authority": False,
    }
    result["evidence_sha256"] = sha256_bytes(canonical_json(result))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--guard-env", type=Path, default=Path("/etc/integrity-memory-p2/guard.env"))
    parser.add_argument("--dual-env", type=Path, default=Path("/etc/integrity-memory-p2/dual-reader.env"))
    parser.add_argument("--minio-env", type=Path, default=Path("/etc/integrity-memory-p2/guard-minio.env"))
    parser.add_argument("--minio-endpoint", default=_integrity_value('endpoint_1940bdd68a0a'))
    parser.add_argument("--data-root", type=Path, default=Path(_integrity_value('path_0dcb1df88675')))
    parser.add_argument("--client-endpoint", default=_integrity_value('endpoint_f5891d8ae959'))
    parser.add_argument(
        "--client-token",
        type=Path,
        default=Path("~workspace/.workspace/personal-pc-exec-token").expanduser(),
    )
    parser.add_argument("--receipt-root", type=Path, default=Path(_integrity_value('path_3002b53ff3e8')))
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError("billion capacity gate must run as root across scoped read identities")
    observed = {
        "postgres": postgres_observation(args.guard_env, args.dual_env),
        "s3": s3_observation(args.minio_env, args.minio_endpoint),
        "linux_free_bytes": filesystem_free(args.data_root),
        "client": client_observation(args.client_endpoint, args.client_token),
    }
    result = evaluate(observed)
    args.receipt_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = args.receipt_root / f"billion-capacity-{stamp}-{result['evidence_sha256'][:16]}.json"
    atomic_json(path, result, mode=0o440)
    print(json.dumps({**result, "receipt_path": str(path)}, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "PASS" else 2


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
