#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Create and independently verify the Integrity P2 WORM shadow buckets."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import hashlib
import json
import os
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import boto3
from botocore.client import Config
from botocore.exceptions import ClientError


BUCKETS = ("integrity-p2-raw", "integrity-p2-attachments")
RETENTION_DAYS = 30


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or not key:
            raise RuntimeError(f"invalid environment line for key-only parser: {path}")
        values[key] = value
    return values


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o640)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def bucket_exists(client: Any, bucket: str) -> bool:
    try:
        client.head_bucket(Bucket=bucket)
        return True
    except ClientError as error:
        status = int(error.response.get("ResponseMetadata", {}).get("HTTPStatusCode", 0))
        if status == 404:
            return False
        raise


def verify_bucket_contract(client: Any, bucket: str) -> dict[str, Any]:
    versioning = client.get_bucket_versioning(Bucket=bucket)
    if versioning.get("Status") != "Enabled":
        raise RuntimeError(f"versioning is not enabled for {bucket}")
    lock = client.get_object_lock_configuration(Bucket=bucket)["ObjectLockConfiguration"]
    retention = lock.get("Rule", {}).get("DefaultRetention", {})
    if lock.get("ObjectLockEnabled") != "Enabled":
        raise RuntimeError(f"Object Lock is not enabled for {bucket}")
    if retention.get("Mode") != "COMPLIANCE" or int(retention.get("Days", 0)) != RETENTION_DAYS:
        raise RuntimeError(f"unexpected retention contract for {bucket}")
    return {
        "bucket": bucket,
        "object_lock": "Enabled",
        "retention_mode": "COMPLIANCE",
        "retention_days": RETENTION_DAYS,
        "versioning": "Enabled",
    }


def create_smoke_object(client: Any, bucket: str) -> dict[str, Any]:
    object_uid = str(uuid.uuid4())
    body = json.dumps(
        {
            "protocol": "integrity.p2.s3-worm-smoke.v1",
            "bucket": bucket,
            "object_uid": object_uid,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    digest = hashlib.sha256(body).hexdigest()
    key = f"_bootstrap/sha256/{digest[:2]}/{digest}.json"
    written = client.put_object(
        Bucket=bucket,
        Key=key,
        Body=body,
        ContentType="application/json",
        Metadata={"sha256": digest, "protocol": "integrity-p2-s3-worm-smoke-v1"},
    )
    version_id = str(written.get("VersionId") or "")
    if not version_id or version_id == "null":
        raise RuntimeError(f"versioned put did not return a version ID for {bucket}")
    readback = client.get_object(Bucket=bucket, Key=key, VersionId=version_id)
    readback_body = readback["Body"].read()
    if hashlib.sha256(readback_body).hexdigest() != digest:
        raise RuntimeError(f"readback digest mismatch for {bucket}")
    head = client.head_object(Bucket=bucket, Key=key, VersionId=version_id)
    if head.get("ObjectLockMode") != "COMPLIANCE" or not head.get("ObjectLockRetainUntilDate"):
        raise RuntimeError(f"object retention metadata missing for {bucket}")
    delete_denied = False
    delete_status = 0
    try:
        client.delete_object(Bucket=bucket, Key=key, VersionId=version_id)
    except ClientError as error:
        delete_status = int(error.response.get("ResponseMetadata", {}).get("HTTPStatusCode", 0))
        delete_denied = delete_status in {400, 403, 405, 409}
    if not delete_denied:
        raise RuntimeError(f"retained exact version was deletable for {bucket}")
    return {
        "key": key,
        "payload_sha256": digest,
        "readback_sha256": digest,
        "version_id": version_id,
        "retention_mode": str(head["ObjectLockMode"]),
        "retain_until_utc": head["ObjectLockRetainUntilDate"].astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "exact_version_delete_denied": True,
        "delete_http_status": delete_status,
    }


def verify_existing_smoke(client: Any, smoke: dict[str, Any], bucket: str) -> None:
    body = client.get_object(
        Bucket=bucket,
        Key=str(smoke["key"]),
        VersionId=str(smoke["version_id"]),
    )["Body"].read()
    if hashlib.sha256(body).hexdigest() != smoke["payload_sha256"]:
        raise RuntimeError(f"existing smoke receipt readback mismatch for {bucket}")
    head = client.head_object(Bucket=bucket, Key=str(smoke["key"]), VersionId=str(smoke["version_id"]))
    if head.get("ObjectLockMode") != "COMPLIANCE" or not head.get("ObjectLockRetainUntilDate"):
        raise RuntimeError(f"existing smoke object is no longer retained for {bucket}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env-file", type=Path, default=Path("/etc/integrity-memory-p2/minio.env"))
    parser.add_argument("--endpoint", default=_integrity_value('endpoint_1940bdd68a0a'))
    parser.add_argument(
        "--receipt",
        type=Path,
        default=Path(_integrity_value('path_0530856699a0')),
    )
    args = parser.parse_args()
    env = load_env(args.env_file)
    client = boto3.client(
        "s3",
        endpoint_url=args.endpoint,
        aws_access_key_id=env["MINIO_ROOT_USER"],
        aws_secret_access_key=env["MINIO_ROOT_PASSWORD"],
        region_name="us-east-1",
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}, retries={"max_attempts": 2}),
    )

    if args.receipt.exists():
        receipt = json.loads(args.receipt.read_text(encoding="utf-8"))
        for bucket in BUCKETS:
            verify_bucket_contract(client, bucket)
            verify_existing_smoke(client, receipt["buckets"][bucket]["smoke"], bucket)
        receipt["reused_verified_utc"] = utc_now()
        receipt["reused"] = True
        print(json.dumps(receipt, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
        return 0

    results: dict[str, Any] = {}
    for bucket in BUCKETS:
        created = False
        if not bucket_exists(client, bucket):
            client.create_bucket(Bucket=bucket, ObjectLockEnabledForBucket=True)
            created = True
        client.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
        client.put_object_lock_configuration(
            Bucket=bucket,
            ObjectLockConfiguration={
                "ObjectLockEnabled": "Enabled",
                "Rule": {"DefaultRetention": {"Mode": "COMPLIANCE", "Days": RETENTION_DAYS}},
            },
        )
        results[bucket] = {
            "created": created,
            "contract": verify_bucket_contract(client, bucket),
            "smoke": create_smoke_object(client, bucket),
        }

    receipt = {
        "protocol": "integrity.p2.s3-bootstrap-receipt.v1",
        "created_utc": utc_now(),
        "endpoint_scope": "loopback-only",
        "production_authority": False,
        "reused": False,
        "buckets": results,
    }
    atomic_json(args.receipt, receipt)
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
