#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Content-addressed, quota-bounded P2 attachment ingress.

This component stages immutable attachment objects before an Action Log event
references them.  It does not append or update canonical memory, and its
manifest explicitly grants no authority.  A future append wrapper must bind
the returned manifest digest into the canonical event before P2 admission can
be enabled.
"""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import datetime as dt
import io
import json
import re
from pathlib import Path
from typing import Any

import boto3
from botocore.client import Config
from botocore.exceptions import ClientError

from memory_plane_common import atomic_json, canonical_json, sha256_bytes, sha256_file
from p2_attachment_capacity import POLICY_PROTOCOL, validate_policy
from p2_capacity_supplement import ATTACHMENT_BUCKET
from p2_contract import UID_RE


MANIFEST_PROTOCOL = "integrity-memory-plane.p2-attachment-manifest.v1"
OBJECT_PROTOCOL = "integrity-memory-plane.p2-attachment-object.v1"
RECEIPT_PROTOCOL = "integrity-memory-plane.p2-attachment-ingress.v1.receipt"
PAYLOAD_KEY_PREFIX = "attachments/v1/sha256/"
MANIFEST_KEY_PREFIX = "attachment-manifests/v1/sha256/"
MIME_RE = re.compile(r"^[a-z0-9][a-z0-9.+-]*/[a-z0-9][a-z0-9.+-]*$")


def _clean_name(value: Any, index: int) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(value or "").strip()).strip(".-")
    return (cleaned or f"attachment-{index}")[:120]


def _clean_mime(value: Any) -> str:
    cleaned = str(value or "application/octet-stream").lower().split(";", 1)[0].strip()
    return cleaned if MIME_RE.fullmatch(cleaned) else "application/octet-stream"


def attachment_key(digest: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise RuntimeError("attachment digest is invalid")
    return f"{PAYLOAD_KEY_PREFIX}{digest[:2]}/{digest}"


def manifest_key(digest: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise RuntimeError("attachment manifest digest is invalid")
    return f"{MANIFEST_KEY_PREFIX}{digest[:2]}/{digest}.json"


def prepare_manifest(
    event_uid: str,
    items: list[dict[str, Any]],
    policy: dict[str, Any],
    *,
    policy_file_sha256: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not UID_RE.fullmatch(str(event_uid or "")):
        raise RuntimeError("attachment event_uid is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", policy_file_sha256):
        raise RuntimeError("attachment policy digest is invalid")
    if not items:
        raise RuntimeError("attachment list is empty")
    max_objects = int(policy["max_objects_per_event"])
    max_object = int(policy["max_object_bytes"])
    max_payload = int(policy["max_payload_bytes_per_event"])
    if len(items) > max_objects:
        raise RuntimeError("attachment count exceeds policy")
    prepared: list[dict[str, Any]] = []
    total = 0
    for index, item in enumerate(items, 1):
        if not isinstance(item, dict) or set(item) != {"name", "mime", "body", "expected_sha256"}:
            raise RuntimeError("attachment input schema mismatch")
        body = item["body"]
        if not isinstance(body, bytes) or not body:
            raise RuntimeError("attachment body must be non-empty bytes")
        if len(body) > max_object:
            raise RuntimeError("attachment object exceeds policy")
        total += len(body)
        if total > max_payload:
            raise RuntimeError("attachment payload budget exceeds policy")
        digest = sha256_bytes(body)
        expected = str(item.get("expected_sha256") or "")
        if not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise RuntimeError("attachment expected digest is required")
        if expected != digest:
            raise RuntimeError("attachment expected digest mismatch")
        prepared.append(
            {
                "index": index,
                "name": _clean_name(item.get("name"), index),
                "mime": _clean_mime(item.get("mime")),
                "size_bytes": len(body),
                "content_sha256": digest,
                "key": attachment_key(digest),
                "object_protocol": OBJECT_PROTOCOL,
                "body": body,
            }
        )
    manifest = {
        "protocol": MANIFEST_PROTOCOL,
        "tenant_id": policy["tenant_id"],
        "namespace": policy["namespace"],
        "event_uid": event_uid,
        "policy_file_sha256": policy_file_sha256,
        "object_count": len(prepared),
        "total_payload_bytes": total,
        "objects": [],
        "production_authority": False,
        "memory_grants_authority": False,
    }
    return manifest, prepared


def exact_versions(client: Any, key: str) -> list[dict[str, Any]]:
    response = client.list_object_versions(Bucket=ATTACHMENT_BUCKET, Prefix=key)
    return [item for item in response.get("Versions", []) if item.get("Key") == key]


def verify_version(client: Any, item: dict[str, Any], version_id: str) -> dict[str, Any]:
    head = client.head_object(Bucket=ATTACHMENT_BUCKET, Key=item["key"], VersionId=version_id)
    metadata = head.get("Metadata") or {}
    if metadata.get("sha256") != item["content_sha256"]:
        raise RuntimeError("attachment metadata digest mismatch")
    if int(head.get("ContentLength") or -1) != item["size_bytes"]:
        raise RuntimeError("attachment exact-version size mismatch")
    if str(head.get("ContentType") or "") != item["mime"]:
        raise RuntimeError("attachment exact-version content type mismatch")
    if metadata.get("protocol") != item["object_protocol"]:
        raise RuntimeError("attachment object protocol metadata mismatch")
    retention = client.get_object_retention(
        Bucket=ATTACHMENT_BUCKET, Key=item["key"], VersionId=version_id
    ).get("Retention") or {}
    if retention.get("Mode") != "COMPLIANCE" or not retention.get("RetainUntilDate"):
        raise RuntimeError("attachment COMPLIANCE retention is missing")
    body = client.get_object(Bucket=ATTACHMENT_BUCKET, Key=item["key"], VersionId=version_id)["Body"].read()
    if sha256_bytes(body) != item["content_sha256"]:
        raise RuntimeError("attachment exact-version readback mismatch")
    retain_until = retention["RetainUntilDate"]
    if hasattr(retain_until, "astimezone"):
        retain_until = retain_until.astimezone(dt.UTC).isoformat().replace("+00:00", "Z")
    return {
        "bucket": ATTACHMENT_BUCKET,
        "key": item["key"],
        "version_id": version_id,
        "content_sha256": item["content_sha256"],
        "readback_sha256": item["content_sha256"],
        "size_bytes": item["size_bytes"],
        "retention_mode": "COMPLIANCE",
        "retain_until_utc": str(retain_until),
    }


def put_once(client: Any, item: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    versions = exact_versions(client, item["key"])
    if len(versions) > 1:
        raise RuntimeError("multiple attachment versions violate content-addressed idempotency")
    if versions:
        return verify_version(client, item, str(versions[0]["VersionId"])), True
    try:
        response = client.put_object(
            Bucket=ATTACHMENT_BUCKET,
            Key=item["key"],
            Body=item["body"],
            ContentType=item["mime"],
            IfNoneMatch="*",
            Metadata={"sha256": item["content_sha256"], "protocol": item["object_protocol"]},
        )
        version_id = str(response.get("VersionId") or "")
    except ClientError as error:
        status = int(error.response.get("ResponseMetadata", {}).get("HTTPStatusCode", 0))
        if status not in {409, 412}:
            raise
        versions = exact_versions(client, item["key"])
        if len(versions) != 1:
            raise RuntimeError("conditional attachment PUT raced without one reusable version") from error
        version_id = str(versions[0]["VersionId"])
    if not version_id or version_id == "null":
        raise RuntimeError("attachment PUT did not return a version ID")
    return verify_version(client, item, version_id), False


def ingest(
    client: Any,
    event_uid: str,
    items: list[dict[str, Any]],
    policy: dict[str, Any],
    *,
    policy_file_sha256: str,
) -> dict[str, Any]:
    manifest, prepared = prepare_manifest(event_uid, items, policy, policy_file_sha256=policy_file_sha256)
    stored = []
    reused = 0
    for item in prepared:
        value, was_reused = put_once(client, item)
        stored.append(value)
        reused += int(was_reused)
    manifest["objects"] = [
        {
            "name": source["name"],
            "mime": source["mime"],
            "size_bytes": source["size_bytes"],
            "content_sha256": stored_item["content_sha256"],
            "bucket": stored_item["bucket"],
            "key": stored_item["key"],
            "version_id": stored_item["version_id"],
        }
        for source, stored_item in zip(prepared, stored, strict=True)
    ]
    manifest_body = canonical_json(manifest)
    if len(manifest_body) > int(policy["max_manifest_bytes_per_event"]):
        raise RuntimeError("attachment manifest exceeds policy")
    manifest_sha256 = sha256_bytes(manifest_body)
    manifest_item = {
        "name": "manifest.json",
        "mime": "application/json",
        "size_bytes": len(manifest_body),
        "content_sha256": manifest_sha256,
        "key": manifest_key(manifest_sha256),
        "object_protocol": MANIFEST_PROTOCOL,
        "body": manifest_body,
    }
    manifest_object, manifest_reused = put_once(client, manifest_item)
    receipt = {
        "protocol": RECEIPT_PROTOCOL,
        "created_utc": dt.datetime.now(dt.UTC).isoformat(),
        "status": "PASS",
        "manifest": manifest,
        "manifest_sha256": manifest_sha256,
        "manifest_object": manifest_object,
        "manifest_reused": manifest_reused,
        "stored_objects": stored,
        "objects_reused": reused,
        "objects_created": len(stored) - reused,
        "exact_version_readback_verified": True,
        "canonical_event_reference_bound": False,
        "production_authority": False,
        "memory_grants_authority": False,
    }
    receipt["evidence_sha256"] = sha256_bytes(canonical_json(receipt))
    return receipt


def _load_env(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or not key:
            raise RuntimeError("invalid attachment ingress environment")
        result[key] = value
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--policy", type=Path, default=Path("/etc/integrity-memory-p2/p2-attachment-capacity-policy.json"))
    parser.add_argument("--env-file", type=Path, default=Path("/etc/integrity-memory-p2/attachment-ingress.env"))
    parser.add_argument("--endpoint", default=_integrity_value('endpoint_1940bdd68a0a'))
    parser.add_argument("--project-root", type=Path, default=Path(_integrity_value('path_6c566dbbf48b')))
    parser.add_argument(
        "--receipt-root",
        type=Path,
        default=Path(_integrity_value('path_21965e89ee01')),
    )
    args = parser.parse_args()
    policy = json.loads(args.policy.read_text(encoding="utf-8"))
    if policy.get("protocol") != POLICY_PROTOCOL:
        raise RuntimeError("attachment policy protocol mismatch")
    validated = validate_policy(policy, args.project_root)
    if validated["source_constraints_current"] is not True:
        raise RuntimeError("attachment policy source constraints drifted")
    request = json.loads(args.request.read_text(encoding="utf-8"))
    if not isinstance(request, dict) or set(request) != {"event_uid", "attachments"}:
        raise RuntimeError("attachment ingress request schema mismatch")
    inputs = []
    for item in request["attachments"]:
        if not isinstance(item, dict) or set(item) != {"path", "name", "mime", "expected_sha256"}:
            raise RuntimeError("attachment ingress file descriptor schema mismatch")
        path = Path(str(item["path"]))
        body = path.read_bytes()
        inputs.append({"name": item["name"], "mime": item["mime"], "body": body, "expected_sha256": item["expected_sha256"]})
    env = _load_env(args.env_file)
    client = boto3.client(
        "s3",
        endpoint_url=args.endpoint,
        aws_access_key_id=env["MINIO_ACCESS_KEY"],
        aws_secret_access_key=env["MINIO_SECRET_KEY"],
        region_name="us-east-1",
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}, retries={"max_attempts": 2}),
    )
    receipt = ingest(client, request["event_uid"], inputs, policy, policy_file_sha256=sha256_file(args.policy))
    args.receipt_root.mkdir(parents=True, exist_ok=True, mode=0o750)
    path = args.receipt_root / (
        f"attachment-ingress-{receipt['manifest_sha256']}-{receipt['evidence_sha256'][:16]}.json"
    )
    if path.exists():
        existing = json.loads(path.read_text(encoding="utf-8"))
        if existing.get("evidence_sha256") != receipt["evidence_sha256"]:
            raise RuntimeError("existing attachment ingress receipt conflicts with current result")
    else:
        atomic_json(path, receipt, mode=0o440)
    print(json.dumps({**receipt, "receipt_path": str(path)}, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
