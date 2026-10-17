#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run a resumable live attachment ingress enforcement canary.

The canary intentionally writes retained non-authoritative WORM objects and a
small number of append-only Action Log evidence events.  A durable intent is
committed before the first S3 write so interruption is resumed idempotently by
the same content hashes and event_uids.
"""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import datetime as dt
import hashlib
import json
import os
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any

import boto3
from botocore.client import Config

from memory_plane_common import (
    action_log_reader_headers,
    atomic_json,
    canonical_json,
    open_direct_http_request,
    sha256_bytes,
    sha256_file,
    validate_action_log_reader_url,
)
from p2_attachment_capacity import (
    ENFORCEMENT_CHECKS,
    ENFORCEMENT_PROTOCOL,
    POLICY_PROTOCOL,
    validate_policy,
)
from p2_attachment_ingress import _load_env, ingest, prepare_manifest
from p2_attachment_credentials import (
    BUCKET as CREDENTIAL_BUCKET,
    MINIO_POLICY,
    MINIO_USER,
    PREFIXES,
    PROTOCOL as CREDENTIAL_PROTOCOL,
)
from p2_capacity_supplement import ATTACHMENT_BUCKET


INTENT_PROTOCOL = "integrity-memory-plane.p2-attachment-enforcement-intent.v1"
REFERENCE_PROTOCOL = "integrity-memory-plane.p2-attachment-reference.v1"
CANARY_NAMESPACE = uuid.UUID("9ed886c7-e20b-5d06-8909-f36aa995877d")
SAMPLE_EVENTS = 4
OBJECTS_PER_EVENT = 4
DEFAULT_OBJECT_BYTES = 4 * 1024 * 1024
FILESYSTEM_RESERVE_BYTES = 1024 * 1024 * 1024


def deterministic_body(seed: str, size: int) -> bytes:
    if size < 1:
        raise RuntimeError("attachment canary body size must be positive")
    return hashlib.shake_256(seed.encode("utf-8")).digest(size)


def build_intent(policy_sha256: str, credential_file_sha256: str, object_bytes: int) -> dict[str, Any]:
    if object_bytes < 1:
        raise RuntimeError("attachment canary object size must be positive")
    events = []
    for event_index in range(1, SAMPLE_EVENTS + 1):
        event_uid = str(uuid.uuid5(CANARY_NAMESPACE, f"{policy_sha256}:event:{event_index}"))
        objects = []
        for object_index in range(1, OBJECTS_PER_EVENT + 1):
            seed = f"{policy_sha256}:event:{event_index}:object:{object_index}:bytes:{object_bytes}"
            body = deterministic_body(seed, object_bytes)
            objects.append(
                {
                    "index": object_index,
                    "seed": seed,
                    "size_bytes": object_bytes,
                    "content_sha256": sha256_bytes(body),
                    "name": f"capacity-sample-{event_index:02d}-{object_index:02d}.bin",
                    "mime": "application/octet-stream",
                }
            )
        events.append({"index": event_index, "event_uid": event_uid, "objects": objects})
    intent = {
        "protocol": INTENT_PROTOCOL,
        "policy_file_sha256": policy_sha256,
        "credential_file_sha256": credential_file_sha256,
        "sample_events": SAMPLE_EVENTS,
        "objects_per_event": OBJECTS_PER_EVENT,
        "object_bytes": object_bytes,
        "total_payload_bytes": SAMPLE_EVENTS * OBJECTS_PER_EVENT * object_bytes,
        "events": events,
        "production_authority": False,
        "memory_grants_authority": False,
    }
    intent["evidence_sha256"] = sha256_bytes(canonical_json(intent))
    return intent


def negative_checks(policy: dict[str, Any], policy_sha256: str) -> dict[str, bool]:
    def rejected(items: list[dict[str, Any]], match: str) -> bool:
        try:
            prepare_manifest("attachment-enforcement-negative", items, policy, policy_file_sha256=policy_sha256)
        except RuntimeError as error:
            return match in str(error)
        return False

    def item(body: bytes, expected: str | None = None) -> dict[str, Any]:
        return {
            "name": "negative.bin",
            "mime": "application/octet-stream",
            "body": body,
            "expected_sha256": sha256_bytes(body) if expected is None else expected,
        }

    max_object = int(policy["max_object_bytes"])
    oversized = b"x" * (max_object + 1)
    one = b"x"
    maximum = b"y" * max_object
    return {
        "oversized_object_rejected": rejected([item(oversized)], "object exceeds"),
        "fifth_object_rejected": rejected([item(bytes([i])) for i in range(5)], "count exceeds"),
        "payload_budget_overflow_rejected": rejected([item(maximum)] * 4, "payload budget"),
        "digest_mismatch_rejected": rejected([item(one, "f" * 64)], "expected digest mismatch"),
    }


def _http_events(base_url: str, event_uid: str) -> list[dict[str, Any]]:
    resolved_base_url = validate_action_log_reader_url(base_url)
    url = resolved_base_url + "/api/events?" + urllib.parse.urlencode({"event_uid": event_uid})
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json", **action_log_reader_headers()},
        method="GET",
    )
    with open_direct_http_request(request, timeout=5) as response:
        value = json.load(response)
    return list(value.get("events") or [])


def validate_credential_receipt(path: Path, env_path: Path) -> str:
    value = json.loads(path.read_text(encoding="utf-8"))
    claimed = str(value.get("evidence_sha256") or "")
    unsigned = dict(value)
    unsigned.pop("evidence_sha256", None)
    minio = value.get("minio") or {}
    secret = value.get("secret_file") or {}
    valid = (
        value.get("protocol") == CREDENTIAL_PROTOCOL
        and claimed == sha256_bytes(canonical_json(unsigned))
        and value.get("status") == "PASS"
        and minio.get("user") == MINIO_USER
        and minio.get("policy") == MINIO_POLICY
        and minio.get("bucket") == CREDENTIAL_BUCKET
        and minio.get("prefixes") == list(PREFIXES)
        and minio.get("delete_actions_granted") is False
        and value.get("secret_values_exposed") is False
        and secret.get("path") == str(env_path)
        and secret.get("sha256") == sha256_file(env_path)
        and value.get("production_authority") is False
        and value.get("memory_grants_authority") is False
    )
    if not valid:
        raise RuntimeError("attachment credential receipt validation failed")
    return sha256_file(path)


def _all_events(base_url: str) -> list[dict[str, Any]]:
    after = 0
    result: list[dict[str, Any]] = []
    while True:
        query = urllib.parse.urlencode(
            {
                "page_size": 1000,
                "after_id": after,
                "order": "asc",
                "since": "1970-01-01T00:00:00Z",
            }
        )
        resolved_base_url = validate_action_log_reader_url(base_url)
        request = urllib.request.Request(
            resolved_base_url + "/api/events?" + query,
            headers={"Accept": "application/json", **action_log_reader_headers()},
            method="GET",
        )
        with open_direct_http_request(request, timeout=8) as response:
            page = json.load(response)
        events = list(page.get("events") or [])
        cursors = [int(item.get("id") or 0) for item in events]
        if cursors != sorted(cursors) or any(cursor <= after for cursor in cursors):
            raise RuntimeError("Action Log attachment scan cursor contract failed")
        result.extend(events)
        if not events:
            break
        after = cursors[-1]
        if (page.get("pagination") or {}).get("has_more") is False:
            break
    return result


def _contains_path_key(value: Any) -> bool:
    if isinstance(value, dict):
        return "path" in value or any(_contains_path_key(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_path_key(item) for item in value)
    return False


def _reference_policy_sha256(
    reference: dict[str, Any],
    event_uid: str,
    current_policy_sha256: str,
    required_event_uids: set[str],
) -> str:
    """Bind every reference to its immutable policy generation.

    Historical WORM references remain valid under the policy hash written into
    their manifest.  Only the event_uids required by this canary must bind to
    the current policy generation.
    """

    policy_sha256 = str(reference.get("policy_file_sha256") or "")
    if len(policy_sha256) != 64 or any(char not in "0123456789abcdef" for char in policy_sha256):
        raise RuntimeError("canonical attachment reference policy digest is invalid")
    if event_uid in required_event_uids and policy_sha256 != current_policy_sha256:
        raise RuntimeError("current attachment reference policy mismatch")
    return policy_sha256


def scan_canonical_references(
    client: Any,
    base_url: str,
    policy_sha256: str,
    required_event_uids: set[str],
) -> dict[str, Any]:
    references = []
    for event in _all_events(base_url):
        reference = ((event.get("details") or {}).get("attachment_reference") or {})
        if reference.get("protocol") != REFERENCE_PROTOCOL:
            continue
        event_uid = str(event.get("event_uid") or "")
        reference_policy_sha256 = _reference_policy_sha256(
            reference, event_uid, policy_sha256, required_event_uids
        )
        if reference.get("bucket") != ATTACHMENT_BUCKET:
            raise RuntimeError("canonical attachment reference bucket mismatch")
        key = str(reference.get("key") or "")
        version_id = str(reference.get("version_id") or "")
        expected = str(reference.get("content_sha256") or "")
        head = client.head_object(Bucket=ATTACHMENT_BUCKET, Key=key, VersionId=version_id)
        if (head.get("Metadata") or {}).get("sha256") != expected:
            raise RuntimeError("canonical attachment manifest metadata mismatch")
        retention = client.get_object_retention(
            Bucket=ATTACHMENT_BUCKET, Key=key, VersionId=version_id
        ).get("Retention") or {}
        if retention.get("Mode") != "COMPLIANCE" or not retention.get("RetainUntilDate"):
            raise RuntimeError("canonical attachment manifest retention mismatch")
        body = client.get_object(Bucket=ATTACHMENT_BUCKET, Key=key, VersionId=version_id)["Body"].read()
        if sha256_bytes(body) != expected or expected != reference.get("manifest_sha256"):
            raise RuntimeError("canonical attachment manifest exact-version digest mismatch")
        manifest = json.loads(body)
        if (
            manifest.get("event_uid") != event_uid
            or manifest.get("policy_file_sha256") != reference_policy_sha256
            or manifest.get("object_count") != reference.get("object_count")
            or manifest.get("total_payload_bytes") != reference.get("total_payload_bytes")
            or _contains_path_key(manifest)
        ):
            raise RuntimeError("canonical attachment manifest/event binding mismatch")
        objects = manifest.get("objects") or []
        if len(objects) != int(manifest.get("object_count") or -1):
            raise RuntimeError("canonical attachment manifest object count mismatch")
        if sum(int(item.get("size_bytes") or -1) for item in objects) != int(
            manifest.get("total_payload_bytes") or -1
        ):
            raise RuntimeError("canonical attachment manifest byte accounting mismatch")
        for item in objects:
            object_key = str(item.get("key") or "")
            object_version = str(item.get("version_id") or "")
            object_sha = str(item.get("content_sha256") or "")
            object_head = client.head_object(
                Bucket=ATTACHMENT_BUCKET, Key=object_key, VersionId=object_version
            )
            if (
                (object_head.get("Metadata") or {}).get("sha256") != object_sha
                or int(object_head.get("ContentLength") or -1) != int(item.get("size_bytes") or -1)
                or str(object_head.get("ContentType") or "") != str(item.get("mime") or "")
            ):
                raise RuntimeError("canonical attachment payload metadata mismatch")
            object_retention = client.get_object_retention(
                Bucket=ATTACHMENT_BUCKET, Key=object_key, VersionId=object_version
            ).get("Retention") or {}
            if object_retention.get("Mode") != "COMPLIANCE" or not object_retention.get("RetainUntilDate"):
                raise RuntimeError("canonical attachment payload retention mismatch")
            object_body = client.get_object(
                Bucket=ATTACHMENT_BUCKET, Key=object_key, VersionId=object_version
            )["Body"].read()
            if sha256_bytes(object_body) != object_sha:
                raise RuntimeError("canonical attachment payload exact-version digest mismatch")
        references.append(
            {
                "event_id": int(event["id"]),
                "event_uid": event_uid,
                "policy_file_sha256": reference_policy_sha256,
                "manifest_sha256": expected,
                "object_count": len(objects),
                "payload_bytes": int(manifest["total_payload_bytes"]),
            }
        )
    observed_uids = {item["event_uid"] for item in references}
    return {
        "valid": required_event_uids.issubset(observed_uids),
        "references_scanned": len(references),
        "required_event_uids_found": sorted(required_event_uids & observed_uids),
        "references": references,
    }


def append_reference_once(base_url: str, event_uid: str, reference: dict[str, Any], sample_index: int) -> int:
    resolved_base_url = validate_action_log_reader_url(base_url)
    existing = _http_events(resolved_base_url, event_uid)
    if existing:
        if len(existing) != 1 or ((existing[0].get("details") or {}).get("attachment_reference") or {}) != reference:
            raise RuntimeError("existing attachment canary event reference collision")
        event_id = existing[0].get("id")
        if type(event_id) is not int:
            raise RuntimeError("existing attachment canary has no numeric receipt")
        return event_id
    payload = {
        "actor": "integrity-p2-attachment-canary",
        "session_id": "integrity-memory-plane-p1-p3-20260808",
        "level": "info",
        "action": "integrity_attachment_canary",
        "summary": f"P2 non-authoritative attachment WORM canary {sample_index}/{SAMPLE_EVENTS}",
        "details": {
            "task_id": "integrity-memory-plane-p1-p3-20260808",
            "status": "open",
            "sample_index": sample_index,
            "attachment_reference": reference,
            "production_authority": False,
            "memory_grants_authority": False,
        },
        "tags": ["integrity", "memory-plane", "p2", "attachment", "canary"],
        "created_utc": dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "event_uid": event_uid,
    }
    request = urllib.request.Request(
        resolved_base_url + "/api/events",
        data=json.dumps(payload, separators=(",", ":")).encode(),
        headers={
            "Content-Type": "application/json",
            **action_log_reader_headers(),
        },
        method="POST",
    )
    try:
        with open_direct_http_request(request, timeout=8) as response:
            posted = json.load(response)
        if not isinstance(posted.get("id"), int):
            raise RuntimeError("attachment canary append returned no numeric receipt")
    except Exception:
        # The request may have committed before transport failure.  Never retry;
        # reconcile by immutable event_uid below.
        pass
    reconciled = _http_events(resolved_base_url, event_uid)
    if len(reconciled) != 1 or ((reconciled[0].get("details") or {}).get("attachment_reference") or {}) != reference:
        raise RuntimeError("attachment canary append outcome could not be reconciled")
    event_id = reconciled[0].get("id")
    if type(event_id) is not int:
        raise RuntimeError("attachment canary reconciliation has no numeric receipt")
    return event_id


def run_canary(
    client: Any,
    policy: dict[str, Any],
    policy_sha256: str,
    intent: dict[str, Any],
    action_log_url: str,
) -> tuple[list[dict[str, Any]], dict[str, bool], dict[str, Any]]:
    results = []
    duplicate_ok = True
    readback_ok = True
    reference_ok = True
    for event in intent["events"]:
        inputs = []
        for planned in event["objects"]:
            body = deterministic_body(str(planned["seed"]), int(planned["size_bytes"]))
            if sha256_bytes(body) != planned["content_sha256"]:
                raise RuntimeError("attachment canary intent body digest drift")
            inputs.append(
                {
                    "name": planned["name"],
                    "mime": planned["mime"],
                    "body": body,
                    "expected_sha256": planned["content_sha256"],
                }
            )
        receipt = ingest(client, event["event_uid"], inputs, policy, policy_file_sha256=policy_sha256)
        if int(event["index"]) == 1:
            replay = ingest(client, event["event_uid"], inputs, policy, policy_file_sha256=policy_sha256)
            duplicate_ok = (
                replay["objects_reused"] == OBJECTS_PER_EVENT
                and replay["objects_created"] == 0
                and replay["manifest_reused"] is True
                and replay["manifest_sha256"] == receipt["manifest_sha256"]
            )
        readback_ok = readback_ok and receipt["exact_version_readback_verified"] is True
        reference = {
            "protocol": REFERENCE_PROTOCOL,
            "policy_file_sha256": policy_sha256,
            "manifest_sha256": receipt["manifest_sha256"],
            "bucket": receipt["manifest_object"]["bucket"],
            "key": receipt["manifest_object"]["key"],
            "version_id": receipt["manifest_object"]["version_id"],
            "content_sha256": receipt["manifest_object"]["content_sha256"],
            "object_count": receipt["manifest"]["object_count"],
            "total_payload_bytes": receipt["manifest"]["total_payload_bytes"],
            "p2_non_authoritative": True,
        }
        event_id = append_reference_once(action_log_url, event["event_uid"], reference, int(event["index"]))
        observed = _http_events(action_log_url, event["event_uid"])
        reference_ok = reference_ok and len(observed) == 1 and int(observed[0]["id"]) == event_id
        results.append(
            {
                "sample_index": event["index"],
                "event_uid": event["event_uid"],
                "action_log_event_id": event_id,
                "manifest_reference": reference,
                "payload_objects_created": receipt["objects_created"],
                "payload_objects_reused": receipt["objects_reused"],
                "manifest_reused": receipt["manifest_reused"],
            }
        )
    scan = scan_canonical_references(
        client,
        action_log_url,
        policy_sha256,
        {str(item["event_uid"]) for item in intent["events"]},
    )
    checks = negative_checks(policy, policy_sha256)
    checks.update(
        {
            "content_addressed_duplicate_idempotent": duplicate_ok,
            "exact_version_readback_verified": readback_ok,
            "canonical_event_reference_bound": reference_ok,
            "all_canonical_attachment_references_validated": scan["valid"] is True,
        }
    )
    return results, checks, scan


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, default=Path("/etc/integrity-memory-p2/p2-attachment-capacity-policy.json"))
    parser.add_argument("--env-file", type=Path, default=Path("/etc/integrity-memory-p2/attachment-ingress.env"))
    parser.add_argument("--credential-receipt", type=Path, required=True)
    parser.add_argument("--endpoint", default=_integrity_value('endpoint_1940bdd68a0a'))
    parser.add_argument("--action-log-url", default=_integrity_value('endpoint_72b0e86b156f'))
    parser.add_argument("--project-root", type=Path, default=Path(_integrity_value('path_6c566dbbf48b')))
    parser.add_argument("--minio-root", type=Path, default=Path(_integrity_value('path_731bbb2bf224')))
    parser.add_argument("--object-bytes", type=int, default=DEFAULT_OBJECT_BYTES)
    parser.add_argument("--plan", action="store_true")
    parser.add_argument(
        "--intent-root",
        type=Path,
        default=Path(_integrity_value('path_5ff234173927')),
    )
    parser.add_argument(
        "--receipt-root",
        type=Path,
        default=Path(_integrity_value('path_a0681b2e17fc')),
    )
    args = parser.parse_args()
    policy = json.loads(args.policy.read_text(encoding="utf-8"))
    if policy.get("protocol") != POLICY_PROTOCOL:
        raise RuntimeError("attachment policy protocol mismatch")
    if validate_policy(policy, args.project_root)["source_constraints_current"] is not True:
        raise RuntimeError("attachment policy source constraints drifted")
    policy_sha256 = sha256_file(args.policy)
    credential_file_sha256 = validate_credential_receipt(args.credential_receipt, args.env_file)
    intent = build_intent(policy_sha256, credential_file_sha256, args.object_bytes)
    if intent["total_payload_bytes"] < int(policy["minimum_physical_sample_payload_bytes"]):
        raise RuntimeError("attachment canary is smaller than the capacity sample policy")
    if SAMPLE_EVENTS * OBJECTS_PER_EVENT < int(policy["minimum_physical_sample_objects"]):
        raise RuntimeError("attachment canary has too few payload objects")
    stat = os.statvfs(args.minio_root)
    available = int(stat.f_frsize * stat.f_bavail)
    if available <= int(intent["total_payload_bytes"]) + FILESYSTEM_RESERVE_BYTES:
        raise RuntimeError("attachment canary filesystem reserve gate failed")
    planned_negative = negative_checks(policy, policy_sha256)
    if not all(planned_negative.values()):
        raise RuntimeError("attachment canary negative preflight failed")
    if args.plan:
        print(
            json.dumps(
                {
                    "status": "PLAN",
                    "policy_file_sha256": policy_sha256,
                    "credential_receipt_file_sha256": credential_file_sha256,
                    "intent_evidence_sha256": intent["evidence_sha256"],
                    "sample_events": SAMPLE_EVENTS,
                    "payload_objects": SAMPLE_EVENTS * OBJECTS_PER_EVENT,
                    "payload_bytes": intent["total_payload_bytes"],
                    "filesystem_available_bytes": available,
                    "filesystem_reserve_bytes": FILESYSTEM_RESERVE_BYTES,
                    "negative_checks": planned_negative,
                    "worm_write_started": False,
                    "action_log_append_started": False,
                },
                sort_keys=True,
            )
        )
        return 0
    args.intent_root.mkdir(parents=True, exist_ok=True, mode=0o750)
    intent_path = args.intent_root / f"attachment-enforcement-intent-{intent['evidence_sha256']}.json"
    if intent_path.exists():
        existing = json.loads(intent_path.read_text(encoding="utf-8"))
        if existing != intent:
            raise RuntimeError("attachment enforcement intent collision")
    else:
        atomic_json(intent_path, intent, mode=0o440)
    env = _load_env(args.env_file)
    client = boto3.client(
        "s3",
        endpoint_url=args.endpoint,
        aws_access_key_id=env["MINIO_ACCESS_KEY"],
        aws_secret_access_key=env["MINIO_SECRET_KEY"],
        region_name="us-east-1",
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}, retries={"max_attempts": 2}),
    )
    samples, checks, reference_scan = run_canary(client, policy, policy_sha256, intent, args.action_log_url)
    if set(checks) != ENFORCEMENT_CHECKS or any(type(value) is not bool for value in checks.values()):
        raise RuntimeError("attachment enforcement check schema mismatch")
    receipt = {
        "protocol": ENFORCEMENT_PROTOCOL,
        "created_utc": dt.datetime.now(dt.UTC).isoformat(),
        "status": "PASS" if all(checks.values()) else "FAIL",
        "policy_file_sha256": policy_sha256,
        "bucket": ATTACHMENT_BUCKET,
        "intent": {
            "path": str(intent_path.resolve()),
            "file_sha256": sha256_file(intent_path),
            "evidence_sha256": intent["evidence_sha256"],
        },
        "credential_receipt": {
            "path": str(args.credential_receipt.resolve()),
            "file_sha256": credential_file_sha256,
        },
        "sample": {
            "events": SAMPLE_EVENTS,
            "payload_objects": SAMPLE_EVENTS * OBJECTS_PER_EVENT,
            "payload_bytes": intent["total_payload_bytes"],
            "results": samples,
        },
        "canonical_reference_scan": reference_scan,
        "checks": checks,
        "production_authority": False,
        "memory_grants_authority": False,
    }
    receipt["evidence_sha256"] = sha256_bytes(canonical_json(receipt))
    args.receipt_root.mkdir(parents=True, exist_ok=True, mode=0o750)
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    path = args.receipt_root / f"attachment-enforcement-{stamp}-{receipt['evidence_sha256'][:16]}.json"
    atomic_json(path, receipt, mode=0o440)
    print(json.dumps({**receipt, "receipt_path": str(path)}, ensure_ascii=False, sort_keys=True))
    return 0 if receipt["status"] == "PASS" else 2


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
