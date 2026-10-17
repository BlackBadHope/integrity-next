#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Inspect and resolve P2 dead letters without silently replaying uncertain data."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from psycopg.types.json import Jsonb

from memory_plane_common import atomic_json, canonical_json, sha256_bytes
from p2_gap_guard import RAW_BUCKET, connect, load_env, s3_client


PROTOCOL = "integrity-memory-plane.p2-dlq.v1"
RESOLUTION_NAMESPACE = uuid.UUID("fbd91003-30cc-475a-8205-92fa59034d79")
SAFE_REPLAY_REASONS = {"delivery_failed_before_bus_publish_after_worm_commit"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def replay_eligibility(reason_code: str, evidence: dict[str, Any], has_resolution: bool) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    if has_resolution:
        reasons.append("immutable_resolution_exists")
    if reason_code not in SAFE_REPLAY_REASONS:
        reasons.append("reason_not_replay_allowlisted")
    if evidence.get("postgres_ingest_committed"):
        reasons.append("postgres_ingest_already_committed")
    if evidence.get("sequence"):
        reasons.append("bus_sequence_already_assigned")
    raw = evidence.get("raw_object")
    if not isinstance(raw, dict) or not raw.get("key") or not raw.get("version_id") or not raw.get("content_sha256"):
        reasons.append("exact_worm_source_missing")
    return not reasons, reasons


def fetch_dlq(connection: Any, dlq_id: uuid.UUID) -> dict[str, Any]:
    row = connection.execute(
        "SELECT dlq_id,tenant_id,namespace,edge_id,observed_cursor,event_uid,reason_code,evidence,raw_object_key,created_utc "
        "FROM integrity_p2.dead_letters WHERE dlq_id=%s",
        (dlq_id,),
    ).fetchone()
    if not row:
        raise RuntimeError(f"unknown dlq_id: {dlq_id}")
    resolutions = connection.execute(
        "SELECT resolution_uid,disposition,reason,evidence,created_utc FROM integrity_p2.dlq_resolutions WHERE dlq_id=%s ORDER BY created_utc",
        (dlq_id,),
    ).fetchall()
    return {
        "dlq_id": str(row[0]),
        "tenant_id": str(row[1]),
        "namespace": str(row[2]),
        "edge_id": str(row[3]),
        "observed_cursor": row[4],
        "event_uid": row[5],
        "reason_code": str(row[6]),
        "evidence": row[7] if isinstance(row[7], dict) else {},
        "raw_object_key": row[8],
        "created_utc": row[9].isoformat(),
        "resolutions": [
            {"resolution_uid": str(value[0]), "disposition": str(value[1]), "reason": str(value[2]), "evidence": value[3], "created_utc": value[4].isoformat()}
            for value in resolutions
        ],
    }


def verify_raw(client: Any, record: dict[str, Any]) -> dict[str, Any]:
    raw = record["evidence"].get("raw_object")
    if not isinstance(raw, dict):
        raise RuntimeError("DLQ lacks exact raw object evidence")
    key = str(raw.get("key", ""))
    version_id = str(raw.get("version_id", ""))
    expected_sha = str(raw.get("content_sha256", ""))
    if not key or not version_id or len(expected_sha) != 64 or record.get("raw_object_key") != key:
        raise RuntimeError("DLQ raw object identity is incomplete or inconsistent")
    response = client.get_object(Bucket=RAW_BUCKET, Key=key, VersionId=version_id)
    digest = hashlib.sha256()
    size = 0
    for block in iter(lambda: response["Body"].read(1024 * 1024), b""):
        digest.update(block)
        size += len(block)
    observed_sha = digest.hexdigest()
    if observed_sha != expected_sha:
        raise RuntimeError("DLQ exact WORM readback digest mismatch")
    retention = client.get_object_retention(Bucket=RAW_BUCKET, Key=key, VersionId=version_id).get("Retention", {})
    if retention.get("Mode") != "COMPLIANCE":
        raise RuntimeError("DLQ source is not under COMPLIANCE retention")
    return {
        "bucket": RAW_BUCKET,
        "key": key,
        "version_id": version_id,
        "content_sha256": observed_sha,
        "bytes": size,
        "retention_mode": retention.get("Mode"),
        "retain_until_utc": retention.get("RetainUntilDate").isoformat() if retention.get("RetainUntilDate") else None,
    }


def public_record(record: dict[str, Any]) -> dict[str, Any]:
    eligible, reasons = replay_eligibility(record["reason_code"], record["evidence"], bool(record["resolutions"]))
    return {
        "dlq_id": record["dlq_id"],
        "reason_code": record["reason_code"],
        "observed_cursor": record["observed_cursor"],
        "event_uid": record["event_uid"],
        "raw_object_key": record["raw_object_key"],
        "resolution_count": len(record["resolutions"]),
        "resolutions": [{"resolution_uid": value["resolution_uid"], "disposition": value["disposition"], "reason": value["reason"]} for value in record["resolutions"]],
        "replay_eligible": eligible,
        "replay_denial_reasons": reasons,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--guard-env", type=Path, default=Path("/etc/integrity-memory-p2/guard.env"))
    parser.add_argument("--minio-env", type=Path, default=Path("/etc/integrity-memory-p2/guard-minio.env"))
    parser.add_argument("--postgres-host", default="127.0.0.1")
    parser.add_argument("--s3-endpoint", default=_integrity_value('endpoint_1940bdd68a0a'))
    parser.add_argument("--receipt-root", type=Path, default=Path(_integrity_value('path_b476072d92ff')))
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("list")
    inspect_parser = subparsers.add_parser("inspect")
    inspect_parser.add_argument("--dlq-id", type=uuid.UUID, required=True)
    replay_parser = subparsers.add_parser("replay")
    replay_parser.add_argument("--dlq-id", type=uuid.UUID, required=True)
    resolve_parser = subparsers.add_parser("resolve-permanent")
    resolve_parser.add_argument("--dlq-id", type=uuid.UUID, required=True)
    resolve_parser.add_argument("--reason", required=True)
    args = parser.parse_args()
    pg_env = load_env(args.guard_env)
    minio_env = load_env(args.minio_env)
    with connect(pg_env, args.postgres_host) as connection:
        if args.command == "list":
            ids = [value[0] for value in connection.execute("SELECT dlq_id FROM integrity_p2.dead_letters ORDER BY created_utc")]
            print(json.dumps({"protocol": PROTOCOL, "dead_letters": [public_record(fetch_dlq(connection, value)) for value in ids]}, sort_keys=True))
            return 0
        record = fetch_dlq(connection, args.dlq_id)
        if args.command == "inspect":
            print(json.dumps({"protocol": PROTOCOL, **public_record(record)}, sort_keys=True))
            return 0
        eligible, denial_reasons = replay_eligibility(record["reason_code"], record["evidence"], bool(record["resolutions"]))
        if args.command == "replay":
            result = {"protocol": PROTOCOL, "status": "REJECTED", "dlq_id": record["dlq_id"], "replay_eligible": eligible, "denial_reasons": denial_reasons}
            if eligible:
                result["denial_reasons"] = ["replay_executor_requires_separate_scoped_authority_and_is_not_enabled"]
            print(json.dumps(result, sort_keys=True))
            return 3
        if len(args.reason.strip()) < 20:
            raise RuntimeError("permanent quarantine reason must be at least 20 characters")
        if record["resolutions"]:
            existing = record["resolutions"][0]
            print(json.dumps({"protocol": PROTOCOL, "status": "EXISTING", **public_record(record)}, sort_keys=True))
            return 0
        verified_raw = verify_raw(s3_client(minio_env, args.s3_endpoint), record)
        evidence = {
            "protocol": PROTOCOL + ".resolution-evidence",
            "dlq_id": record["dlq_id"],
            "reason_code": record["reason_code"],
            "original_evidence_sha256": sha256_bytes(canonical_json(record["evidence"])),
            "verified_raw": verified_raw,
            "replay_allowed": False,
            "replay_denial_reasons": replay_eligibility(record["reason_code"], record["evidence"], False)[1],
            "production_authority": False,
            "memory_grants_authority": False,
        }
        resolution_uid = uuid.uuid5(RESOLUTION_NAMESPACE, record["dlq_id"] + ":PERMANENT_QUARANTINE:" + sha256_bytes(args.reason.strip().encode()))
        connection.execute(
            "INSERT INTO integrity_p2.dlq_resolutions(resolution_uid,dlq_id,disposition,reason,evidence) VALUES(%s,%s,'PERMANENT_QUARANTINE',%s,%s)",
            (resolution_uid, args.dlq_id, args.reason.strip(), Jsonb(evidence)),
        )
        result = {"protocol": PROTOCOL, "status": "RESOLVED", "resolution_uid": str(resolution_uid), "disposition": "PERMANENT_QUARANTINE", **evidence, "created_utc": utc_now()}
    args.receipt_root.mkdir(parents=True, exist_ok=True, mode=0o750)
    atomic_json(args.receipt_root / f"dlq-resolution-{resolution_uid}.json", result, mode=0o440)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
