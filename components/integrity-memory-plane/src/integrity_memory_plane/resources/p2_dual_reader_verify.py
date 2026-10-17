#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Live deny/allow verification for the P2 dual-read identity."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import json
import os
from pathlib import Path
from typing import Any, Callable

import psycopg
from botocore.exceptions import ClientError

from p2_projection import RAW_BUCKET
from p2_retrieval import connect, load_env, s3_client


def denied(call: Callable[[], Any]) -> bool:
    try:
        call()
    except (psycopg.errors.InsufficientPrivilege, ClientError) as exc:
        if isinstance(exc, ClientError):
            return str(exc.response.get("Error", {}).get("Code", "")) in {"AccessDenied", "MethodNotAllowed"}
        return True
    return False


def main() -> int:
    pg = load_env(Path("/etc/integrity-memory-p2/dual-reader.env"))
    with connect(pg, "127.0.0.1") as connection:
        projection_count = int(connection.execute("SELECT count(*) FROM integrity_p2.projection_fts_events").fetchone()[0])
        pg_insert_denied = denied(lambda: connection.execute("INSERT INTO integrity_p2.projection_fts_events(tenant_id,namespace,edge_id,cursor,event_uid,ts_utc,payload_sha256,summary,body_text) VALUES('deny','deny','deny',1,'deny',clock_timestamp(),repeat('0',64),'deny','deny')"))
        connection.rollback()
        pg_raw_delete_denied = denied(lambda: connection.execute("DELETE FROM integrity_p2.raw_events WHERE false"))
        connection.rollback()
    client = s3_client(load_env(Path("/etc/integrity-memory-p2/dual-reader-minio.env")), _integrity_value('endpoint_1940bdd68a0a'))
    versions = client.list_object_versions(Bucket=RAW_BUCKET, Prefix="raw/v1/", MaxKeys=1).get("Versions", [])
    first = versions[0]
    exact = len(client.get_object(Bucket=RAW_BUCKET, Key=first["Key"], VersionId=first["VersionId"])["Body"].read(1)) == 1
    result = {
        "os_uid_nonroot": os.getuid() != 0,
        "pg_projection_select": projection_count > 0,
        "pg_projection_insert_denied": pg_insert_denied,
        "pg_raw_delete_denied": pg_raw_delete_denied,
        "s3_exact_version_read": exact,
        "s3_put_denied": denied(lambda: client.put_object(Bucket=RAW_BUCKET, Key="raw/v1/dual-reader-deny", Body=b"deny")),
        "s3_delete_denied": denied(lambda: client.delete_object(Bucket=RAW_BUCKET, Key=first["Key"], VersionId=first["VersionId"])),
        "relay_secret_denied": not os.access("/etc/integrity-memory-p2/relay-minio.env", os.R_OK),
        "client_token_denied": not os.access(
            Path("~workspace/.workspace/personal-pc-exec-token").expanduser(), os.R_OK
        ),
        "production_authority": False,
        "memory_grants_authority": False,
    }
    result["status"] = "PASS" if all(value for key, value in result.items() if key not in {"production_authority", "memory_grants_authority"}) else "FAIL"
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
