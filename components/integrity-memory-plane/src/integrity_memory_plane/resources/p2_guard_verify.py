#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Live least-privilege verification for the independent P2 guard."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import json
import os
import uuid
from pathlib import Path
from typing import Any, Callable

import boto3
import psycopg
from botocore.client import Config
from botocore.exceptions import ClientError
from psycopg.types.json import Jsonb

from p2_gap_guard import RAW_BUCKET, connect, load_env, s3_client


def denied(call: Callable[[], Any]) -> bool:
    try:
        call()
    except (psycopg.errors.InsufficientPrivilege, ClientError) as exc:
        if isinstance(exc, ClientError):
            code = str(exc.response.get("Error", {}).get("Code", ""))
            return code in {"AccessDenied", "MethodNotAllowed", "XMinioInvalidObjectName"}
        return True
    return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--guard-env", type=Path, default=Path("/etc/integrity-memory-p2/guard.env"))
    parser.add_argument("--minio-env", type=Path, default=Path("/etc/integrity-memory-p2/guard-minio.env"))
    parser.add_argument("--postgres-host", default="127.0.0.1")
    parser.add_argument("--s3-endpoint", default=_integrity_value('endpoint_1940bdd68a0a'))
    args = parser.parse_args()
    pg_env = load_env(args.guard_env)
    minio_env = load_env(args.minio_env)
    result: dict[str, Any] = {"os_uid": os.getuid()}
    with connect(pg_env, args.postgres_host) as connection:
        result["pg_raw_select"] = int(connection.execute("SELECT count(*) FROM integrity_p2.raw_events").fetchone()[0]) >= 1
        result["pg_raw_insert_denied"] = denied(
            lambda: connection.execute(
                "INSERT INTO integrity_p2.raw_events(tenant_id,namespace,edge_id,cursor,event_uid,ts_utc,time_bucket,cursor_bucket,payload_sha256,envelope_sha256,previous_envelope_sha256,source_manifest_sha256,batch_sha256,raw_object_key,raw_object_version,metadata) "
                "VALUES('deny','deny','deny',1,'deny',clock_timestamp(),current_date,0,repeat('0',64),repeat('0',64),repeat('0',64),repeat('0',64),repeat('0',64),'deny','deny','{}')"
            )
        )
        connection.rollback()
        result["pg_raw_delete_denied"] = denied(lambda: connection.execute("DELETE FROM integrity_p2.raw_events WHERE false"))
        connection.rollback()
        probe_uid = uuid.uuid4()
        connection.execute(
            "INSERT INTO integrity_p2.gap_guard_runs(run_uid,status,committed_batches,committed_events,head_cursor,missing_count,unexplained_extra_count,uid_collision_count,max_versions_per_key,evidence_sha256,evidence) "
            "VALUES(%s,'PASS',0,0,0,0,0,0,0,%s,%s)",
            (probe_uid, uuid.uuid4().hex + uuid.uuid4().hex, Jsonb({"permission_probe": True})),
        )
        connection.rollback()
        result["pg_gap_append_allowed_rollback_only"] = True
        result["pg_gap_update_denied"] = denied(lambda: connection.execute("UPDATE integrity_p2.gap_guard_runs SET status='PASS' WHERE false"))
        connection.rollback()
    client = s3_client(minio_env, args.s3_endpoint)
    versions = client.list_object_versions(Bucket=RAW_BUCKET, Prefix="raw/v1/", MaxKeys=1).get("Versions", [])
    if not versions:
        raise RuntimeError("no raw WORM object is available for guard read probe")
    first = versions[0]
    body = client.get_object(Bucket=RAW_BUCKET, Key=first["Key"], VersionId=first["VersionId"])["Body"].read(1)
    result["s3_exact_version_read"] = len(body) == 1
    result["s3_put_denied"] = denied(lambda: client.put_object(Bucket=RAW_BUCKET, Key="raw/v1/deny-probe", Body=b"deny"))
    result["s3_delete_denied"] = denied(lambda: client.delete_object(Bucket=RAW_BUCKET, Key=first["Key"], VersionId=first["VersionId"]))
    checks = {key: value for key, value in result.items() if key != "os_uid"}
    result["status"] = "PASS" if all(checks.values()) else "FAIL"
    result["production_authority"] = False
    result["memory_grants_authority"] = False
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
