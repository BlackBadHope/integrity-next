#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify the live off-host exporter cannot mutate raw storage or read dispatch authority."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import json
import os
from pathlib import Path
from typing import Any, Callable

from botocore.exceptions import ClientError

from p2_offhost_export import load_env, s3_client
from p2_projection import RAW_BUCKET


def denied(call: Callable[[], Any]) -> bool:
    try:
        call()
    except ClientError as exc:
        return str(exc.response.get("Error", {}).get("Code", "")) in {"AccessDenied", "MethodNotAllowed"}
    return False


def main() -> int:
    client = s3_client(load_env(Path("/etc/integrity-memory-p2/offhost-minio.env")), _integrity_value('endpoint_1940bdd68a0a'))
    versions = client.list_object_versions(Bucket=RAW_BUCKET, Prefix="raw/v1/", MaxKeys=1).get("Versions", [])
    if not versions:
        raise RuntimeError("no raw object available for off-host permission probe")
    first = versions[0]
    body = client.get_object(Bucket=RAW_BUCKET, Key=first["Key"], VersionId=first["VersionId"])["Body"].read(1)
    result = {
        "os_uid_nonroot": os.getuid() != 0,
        "exact_version_read": len(body) == 1,
        "put_denied": denied(lambda: client.put_object(Bucket=RAW_BUCKET, Key="raw/v1/offhost-deny-probe", Body=b"deny")),
        "delete_denied": denied(lambda: client.delete_object(Bucket=RAW_BUCKET, Key=first["Key"], VersionId=first["VersionId"])),
        "client_exec_token_denied": not os.access(
            Path("~workspace/.workspace/personal-pc-exec-token").expanduser(), os.R_OK
        ),
        "relay_secret_denied": not os.access("/etc/integrity-memory-p2/relay-minio.env", os.R_OK),
        "guard_secret_denied": not os.access("/etc/integrity-memory-p2/guard-minio.env", os.R_OK),
        "production_authority": False,
        "memory_grants_authority": False,
    }
    checks = [value for key, value in result.items() if key not in {"production_authority", "memory_grants_authority"}]
    result["status"] = "PASS" if all(checks) else "FAIL"
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
