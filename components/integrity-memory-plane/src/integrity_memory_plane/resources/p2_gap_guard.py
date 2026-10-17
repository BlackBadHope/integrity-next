#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed P2 gap/collision guard over committed raw and shadow metadata."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import hashlib
import json
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import boto3
import psycopg
from botocore.client import Config
from psycopg.types.json import Jsonb

from memory_plane_common import atomic_json, canonical_json, exclusive_lock, sha256_bytes
from p2_projection import EDGE_ID, NAMESPACE, RAW_BUCKET, TENANT_ID, committed_receipts, raw_envelopes


PROTOCOL = "integrity-memory-plane.p2-gap-guard.v1"
DLQ_NAMESPACE = uuid.UUID("c6906cf7-2bc8-44c6-8f6d-7065b21f9322")
RAW_PLANE_LOCK = Path(_integrity_value('path_13faba5553a5'))


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_env(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or not key:
            raise RuntimeError(f"invalid environment line in {path}")
        result[key] = value
    return result


def connect(env: dict[str, str], host: str) -> psycopg.Connection[Any]:
    return psycopg.connect(
        host=host,
        port=55432,
        user=env["POSTGRES_GUARD_USER"],
        password=env["POSTGRES_GUARD_PASSWORD"],
        dbname=env["POSTGRES_GUARD_DB"],
        connect_timeout=5,
    )


def s3_client(env: dict[str, str], endpoint: str) -> Any:
    return boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=env["MINIO_GUARD_ACCESS_KEY"],
        aws_secret_access_key=env["MINIO_GUARD_SECRET_KEY"],
        region_name="us-east-1",
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}, retries={"max_attempts": 2}),
    )


def all_versions(client: Any) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    paginator = client.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=RAW_BUCKET, Prefix="raw/v1/"):
        for value in page.get("Versions", []):
            result.setdefault(str(value["Key"]), []).append(str(value["VersionId"]))
    return result


def classify_status(hard_failures: dict[str, int], projection_lag: dict[str, int]) -> str:
    """Never turn unknown drift into green: hard invariants dominate lag."""
    if any(hard_failures.values()):
        return "FAIL"
    if any(projection_lag.values()):
        return "DEGRADED"
    return "PASS"


def guard(args: argparse.Namespace) -> dict[str, Any]:
    pg_env = load_env(args.guard_env)
    minio_env = load_env(args.minio_env)
    receipts = committed_receipts(args.receipts)
    client = s3_client(minio_env, args.s3_endpoint)
    expected_events: list[tuple[Any, ...]] = []
    expected_batches: list[tuple[Any, ...]] = []
    committed_keys: set[str] = set()
    for _, receipt in receipts:
        batch = receipt["batch"]
        envelopes = raw_envelopes(client, receipt)
        committed_keys.add(str(receipt["raw"]["key"]))
        expected_batches.append(
            (
                int(batch["first_cursor"]),
                int(batch["last_cursor"]),
                int(batch["event_count"]),
                str(batch["batch_sha256"]),
                str(batch["previous_batch_sha256"]).rstrip(),
                str(receipt["raw"]["key"]),
                str(receipt["raw"]["version_id"]),
                int(receipt["bus"]["sequence"]),
            )
        )
        for envelope in envelopes:
            expected_events.append(
                (
                    int(envelope["cursor"]),
                    str(envelope["event_uid"]),
                    str(envelope["payload_sha256"]),
                    str(envelope["envelope_sha256"]),
                    str(envelope["previous_envelope_sha256"]).rstrip(),
                    str(envelope["batch_sha256"] if "batch_sha256" in envelope else batch["batch_sha256"]),
                    str(receipt["raw"]["key"]),
                    str(receipt["raw"]["version_id"]),
                )
            )
    expected_events.sort(key=lambda value: value[0])
    with connect(pg_env, args.postgres_host) as connection:
        observed_events = [
            (int(row[0]), str(row[1]), str(row[2]).rstrip(), str(row[3]).rstrip(), str(row[4]).rstrip(), str(row[5]).rstrip(), str(row[6]), str(row[7]))
            for row in connection.execute(
                "SELECT cursor,event_uid,payload_sha256,envelope_sha256,previous_envelope_sha256,batch_sha256,raw_object_key,raw_object_version "
                "FROM integrity_p2.raw_events WHERE tenant_id=%s AND namespace=%s AND edge_id=%s ORDER BY cursor",
                (TENANT_ID, NAMESPACE, EDGE_ID),
            )
        ]
        observed_batches = [
            (int(row[0]), int(row[1]), int(row[2]), str(row[3]).rstrip(), str(row[4]).rstrip(), str(row[5]), str(row[6]), int(row[7]))
            for row in connection.execute(
                "SELECT first_cursor,last_cursor,event_count,batch_sha256,previous_batch_sha256,raw_object_key,raw_object_version,bus_sequence "
                "FROM integrity_p2.ingest_batches WHERE tenant_id=%s AND namespace=%s AND edge_id=%s ORDER BY first_cursor",
                (TENANT_ID, NAMESPACE, EDGE_ID),
            )
        ]
        dead_letters = connection.execute(
            "SELECT dlq_id,reason_code,raw_object_key,evidence FROM integrity_p2.dead_letters WHERE tenant_id=%s AND namespace=%s",
            (TENANT_ID, NAMESPACE),
        ).fetchall()
        offsets = connection.execute(
            "SELECT projection_name,last_cursor FROM integrity_p2.projection_offsets WHERE tenant_id=%s AND namespace=%s AND edge_id=%s",
            (TENANT_ID, NAMESPACE, EDGE_ID),
        ).fetchall()
        uid_collisions = int(
            connection.execute(
                "SELECT count(*) FROM (SELECT event_uid FROM integrity_p2.raw_events WHERE tenant_id=%s AND namespace=%s GROUP BY event_uid HAVING count(DISTINCT payload_sha256)>1) value",
                (TENANT_ID, NAMESPACE),
            ).fetchone()[0]
        )
        versions = all_versions(client)
        known_dlq_keys = {str(row[2]) for row in dead_letters if row[2]}
        missing_keys = sorted(committed_keys - set(versions))
        unexplained_keys = sorted(set(versions) - committed_keys - known_dlq_keys)
        version_multiplicity = {key: len(values) for key, values in versions.items() if len(values) != 1}
        missing_event_rows = len(set(expected_events) - set(observed_events))
        extra_event_rows = len(set(observed_events) - set(expected_events))
        missing_batch_rows = len(set(expected_batches) - set(observed_batches))
        extra_batch_rows = len(set(observed_batches) - set(expected_batches))
        head_cursor = int(expected_events[-1][0]) if expected_events else 0
        projection_offsets = {str(row[0]): int(row[1]) for row in offsets}
        projection_lag = {name: max(0, head_cursor - projection_offsets.get(name, 0)) for name in ("fts", "graph", "vector", "task-state")}
        bus_orphans = sum(1 for row in dead_letters if isinstance(row[3], dict) and row[3].get("sequence"))
        nats = json.load(urllib.request.urlopen(args.nats_monitor.rstrip("/") + "/jsz?streams=true", timeout=5))
        nats_messages = int(nats["messages"])
        expected_nats = len(expected_batches) + 1 + bus_orphans
        hard_failures = {
            "missing_event_rows": missing_event_rows,
            "extra_event_rows": extra_event_rows,
            "missing_batch_rows": missing_batch_rows,
            "extra_batch_rows": extra_batch_rows,
            "missing_s3_keys": len(missing_keys),
            "unexplained_s3_keys": len(unexplained_keys),
            "multi_version_keys": len(version_multiplicity),
            "uid_collisions": uid_collisions,
            "nats_count_mismatch": int(nats_messages != expected_nats),
        }
        status = classify_status(hard_failures, projection_lag)
        evidence = {
            "protocol": PROTOCOL + ".evidence",
            "status": status,
            "committed_batches": len(expected_batches),
            "committed_events": len(expected_events),
            "head_cursor": head_cursor,
            "early_cursor_present": bool(expected_events and expected_events[0][0] == 1),
            "hard_failures": hard_failures,
            "projection_lag": projection_lag,
            "s3": {
                "keys": len(versions),
                "committed_keys": len(committed_keys),
                "known_dlq_keys": len(known_dlq_keys),
                "missing_keys": missing_keys[:20],
                "unexplained_keys": unexplained_keys[:20],
                "version_multiplicity": dict(list(version_multiplicity.items())[:20]),
            },
            "nats": {"messages": nats_messages, "expected": expected_nats, "bootstrap_messages": 1, "explained_dlq_bus_orphans": bus_orphans},
            "dead_letters": len(dead_letters),
            "production_authority": False,
            "memory_grants_authority": False,
        }
        evidence_sha = sha256_bytes(canonical_json(evidence))
        run_uid = uuid.uuid5(DLQ_NAMESPACE, "guard-run:" + evidence_sha)
        with connection.transaction():
            connection.execute(
                "INSERT INTO integrity_p2.gap_guard_runs(run_uid,status,committed_batches,committed_events,head_cursor,missing_count,unexplained_extra_count,uid_collision_count,max_versions_per_key,evidence_sha256,evidence) "
                "VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
                (
                    run_uid,
                    status,
                    len(expected_batches),
                    len(expected_events),
                    head_cursor,
                    missing_event_rows + missing_batch_rows + len(missing_keys),
                    extra_event_rows + extra_batch_rows + len(unexplained_keys),
                    uid_collisions,
                    max((len(value) for value in versions.values()), default=0),
                    evidence_sha,
                    Jsonb(evidence),
                ),
            )
            if status == "FAIL":
                dlq_id = uuid.uuid5(DLQ_NAMESPACE, "guard-failure:" + evidence_sha)
                connection.execute(
                    "INSERT INTO integrity_p2.dead_letters(dlq_id,tenant_id,namespace,edge_id,reason_code,evidence) "
                    "VALUES(%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
                    (dlq_id, TENANT_ID, NAMESPACE, EDGE_ID, "gap_guard_invariant_failure", Jsonb(evidence)),
                )
        return {**evidence, "evidence_sha256": evidence_sha, "run_uid": str(run_uid), "created_utc": utc_now()}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--guard-env", type=Path, default=Path("/etc/integrity-memory-p2/guard.env"))
    parser.add_argument("--minio-env", type=Path, default=Path("/etc/integrity-memory-p2/guard-minio.env"))
    parser.add_argument("--receipts", type=Path, default=Path(_integrity_value('path_f5a9a1727fe8')))
    parser.add_argument("--postgres-host", default="127.0.0.1")
    parser.add_argument("--s3-endpoint", default=_integrity_value('endpoint_1940bdd68a0a'))
    parser.add_argument("--nats-monitor", default=_integrity_value('endpoint_37a28bd31428'))
    parser.add_argument("--receipt-root", type=Path, default=Path(_integrity_value('path_b476072d92ff')))
    parser.add_argument(
        "--lock",
        type=Path,
        default=RAW_PLANE_LOCK,
    )
    args = parser.parse_args()
    with exclusive_lock(args.lock, wait_seconds=120):
        result = guard(args)
    args.receipt_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    atomic_json(
        args.receipt_root / f"gap-{stamp}-{result['run_uid']}-{result['evidence_sha256'][:16]}.json",
        result,
        mode=0o440,
    )
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "PASS" else 2 if result["status"] == "DEGRADED" else 1


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
