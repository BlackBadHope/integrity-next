#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Provision a dedicated no-delete MinIO identity for P2 attachment ingress."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import datetime as dt
import grp
import json
import os
import secrets
import tempfile
from pathlib import Path
from typing import Any

import boto3
from botocore.client import Config

from memory_plane_common import atomic_json, canonical_json, sha256_bytes, sha256_file
from p2_scoped_credentials import load_env, run_mc, write_secret_once


PROTOCOL = "integrity-memory-plane.p2-attachment-credentials.v1.receipt"
MINIO_USER = "integrityp2attachment"
MINIO_POLICY = "integrity-p2-attachment-ingress-v1"
BUCKET = "integrity-p2-attachments"
PREFIXES = ("attachments/v1/", "attachment-manifests/v1/")


def minio_policy() -> dict[str, Any]:
    resources = [f"arn:aws:s3:::{BUCKET}/{prefix}*" for prefix in PREFIXES]
    prefixes = [f"{prefix}*" for prefix in PREFIXES]
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetBucketLocation"],
                "Resource": [f"arn:aws:s3:::{BUCKET}"],
            },
            {
                "Effect": "Allow",
                "Action": ["s3:ListBucket", "s3:ListBucketVersions"],
                "Resource": [f"arn:aws:s3:::{BUCKET}"],
                "Condition": {"StringLike": {"s3:prefix": prefixes}},
            },
            {
                "Effect": "Allow",
                "Action": [
                    "s3:PutObject",
                    "s3:GetObject",
                    "s3:GetObjectVersion",
                    "s3:GetObjectRetention",
                ],
                "Resource": resources,
            },
        ],
    }


def configure_minio(mc: Path, admin: dict[str, str], ingress: dict[str, str], endpoint: str) -> str:
    policy = minio_policy()
    policy_sha256 = sha256_bytes(canonical_json(policy))
    with tempfile.TemporaryDirectory(prefix="integrity-p2-attachment-mc-") as temporary:
        root = Path(temporary)
        policy_path = root / "attachment-policy.json"
        policy_path.write_bytes(canonical_json(policy) + b"\n")
        os.chmod(policy_path, 0o600)
        run_mc(
            mc,
            root,
            ["alias", "set", "p2", endpoint, "--api", "S3v4", "--path", "on"],
            f"{admin['MINIO_ROOT_USER']}\n{admin['MINIO_ROOT_PASSWORD']}\n",
        )
        run_mc(
            mc,
            root,
            ["admin", "user", "add", "p2"],
            f"{ingress['MINIO_ACCESS_KEY']}\n{ingress['MINIO_SECRET_KEY']}\n",
        )
        run_mc(mc, root, ["admin", "policy", "create", "p2", MINIO_POLICY, str(policy_path)])
        run_mc(mc, root, ["admin", "policy", "attach", "p2", MINIO_POLICY, "--user", MINIO_USER])
        info = run_mc(mc, root, ["admin", "user", "info", "p2", MINIO_USER])
        if "Status: enabled" not in info or MINIO_POLICY not in info:
            raise RuntimeError("MinIO attachment identity policy readback failed")
    client = boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=ingress["MINIO_ACCESS_KEY"],
        aws_secret_access_key=ingress["MINIO_SECRET_KEY"],
        region_name="us-east-1",
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
    )
    for prefix in PREFIXES:
        client.list_object_versions(Bucket=BUCKET, Prefix=prefix, MaxKeys=1)
    return policy_sha256


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config-root", type=Path, default=Path("/etc/integrity-memory-p2"))
    parser.add_argument("--mc", type=Path, default=Path(_integrity_value('path_2c1826989a4a')))
    parser.add_argument("--endpoint", default=_integrity_value('endpoint_1940bdd68a0a'))
    parser.add_argument(
        "--receipt-root",
        type=Path,
        default=Path(_integrity_value('path_e2bbc4323d03')),
    )
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError("attachment credential bootstrap must run as root")
    group_id = grp.getgrnam("integrity-p2-worker").gr_gid
    env_path = args.config_root / "attachment-ingress.env"
    outcome = write_secret_once(
        env_path,
        {"MINIO_ACCESS_KEY": MINIO_USER, "MINIO_SECRET_KEY": secrets.token_urlsafe(42)},
        group_id,
    )
    ingress = load_env(env_path)
    if ingress.get("MINIO_ACCESS_KEY") != MINIO_USER:
        raise RuntimeError("existing attachment ingress identity is incompatible")
    policy_sha256 = configure_minio(
        args.mc,
        load_env(args.config_root / "minio.env"),
        ingress,
        args.endpoint,
    )
    receipt = {
        "protocol": PROTOCOL,
        "created_utc": dt.datetime.now(dt.UTC).isoformat(),
        "status": "PASS",
        "outcome": outcome,
        "minio": {
            "user": MINIO_USER,
            "policy": MINIO_POLICY,
            "policy_sha256": policy_sha256,
            "bucket": BUCKET,
            "prefixes": list(PREFIXES),
            "delete_actions_granted": False,
        },
        "secret_file": {
            "path": str(env_path),
            "sha256": sha256_file(env_path),
            "mode": "0640",
            "group": "integrity-p2-worker",
        },
        "secret_values_exposed": False,
        "production_authority": False,
        "memory_grants_authority": False,
    }
    receipt["evidence_sha256"] = sha256_bytes(canonical_json(receipt))
    args.receipt_root.mkdir(parents=True, exist_ok=True, mode=0o750)
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    path = args.receipt_root / f"attachment-credentials-{stamp}-{receipt['evidence_sha256'][:16]}.json"
    atomic_json(path, receipt, mode=0o440)
    print(json.dumps({**receipt, "receipt_path": str(path)}, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
