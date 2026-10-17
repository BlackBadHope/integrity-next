#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Provision the S3-read-only identity used by the P2 off-host exporter."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import grp
import json
import os
import secrets
import tempfile
from pathlib import Path

import boto3
from botocore.client import Config

from memory_plane_common import atomic_json, canonical_json, sha256_bytes, sha256_file
from p2_projection_bootstrap import RAW_BUCKET, RAW_PREFIX, minio_policy
from p2_scoped_credentials import load_env, run_mc, write_secret_once


PROTOCOL = "integrity-memory-plane.p2-offhost-bootstrap.v1"
MINIO_USER = "integrityp2offhost"
MINIO_POLICY = "integrity-p2-offhost-raw-read-v1"


def configure_minio(mc: Path, admin: dict[str, str], worker: dict[str, str], endpoint: str) -> str:
    policy = minio_policy()
    digest = sha256_bytes(canonical_json(policy))
    with tempfile.TemporaryDirectory(prefix="integrity-p2-offhost-mc-") as temporary:
        root = Path(temporary)
        policy_path = root / "offhost-policy.json"
        policy_path.write_bytes(canonical_json(policy) + b"\n")
        os.chmod(policy_path, 0o600)
        run_mc(mc, root, ["alias", "set", "p2", endpoint, "--api", "S3v4", "--path", "on"], f"{admin['MINIO_ROOT_USER']}\n{admin['MINIO_ROOT_PASSWORD']}\n")
        run_mc(mc, root, ["admin", "user", "add", "p2"], f"{worker['MINIO_OFFHOST_ACCESS_KEY']}\n{worker['MINIO_OFFHOST_SECRET_KEY']}\n")
        run_mc(mc, root, ["admin", "policy", "create", "p2", MINIO_POLICY, str(policy_path)])
        run_mc(mc, root, ["admin", "policy", "attach", "p2", MINIO_POLICY, "--user", MINIO_USER])
        info = run_mc(mc, root, ["admin", "user", "info", "p2", MINIO_USER])
        if "Status: enabled" not in info or MINIO_POLICY not in info:
            raise RuntimeError("MinIO off-host policy attachment readback failed")
    client = boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=worker["MINIO_OFFHOST_ACCESS_KEY"],
        aws_secret_access_key=worker["MINIO_OFFHOST_SECRET_KEY"],
        region_name="us-east-1",
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
    )
    client.list_object_versions(Bucket=RAW_BUCKET, Prefix=RAW_PREFIX, MaxKeys=1)
    return digest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config-root", type=Path, default=Path("/etc/integrity-memory-p2"))
    parser.add_argument("--receipt", type=Path, default=Path(_integrity_value('path_170508bd7c92')))
    parser.add_argument("--mc", type=Path, default=Path(_integrity_value('path_2c1826989a4a')))
    parser.add_argument("--minio-endpoint", default=_integrity_value('endpoint_1940bdd68a0a'))
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError("off-host bootstrap must run as root")
    group_id = grp.getgrnam("integrity-p2-offhost").gr_gid
    env_path = args.config_root / "offhost-minio.env"
    outcome = write_secret_once(
        env_path,
        {"MINIO_OFFHOST_ACCESS_KEY": MINIO_USER, "MINIO_OFFHOST_SECRET_KEY": secrets.token_urlsafe(42)},
        group_id,
    )
    worker = load_env(env_path)
    if worker.get("MINIO_OFFHOST_ACCESS_KEY") != MINIO_USER:
        raise RuntimeError("existing MinIO off-host identity is incompatible")
    policy_sha256 = configure_minio(args.mc, load_env(args.config_root / "minio.env"), worker, args.minio_endpoint)
    receipt = {
        "protocol": PROTOCOL,
        "status": "pass",
        "outcome": outcome,
        "minio": {"user": MINIO_USER, "policy": MINIO_POLICY, "policy_sha256": policy_sha256, "raw_read": True, "raw_write": False},
        "secret_file": {"path": str(env_path), "sha256": sha256_file(env_path), "mode": "0640", "group": "integrity-p2-offhost"},
        "secret_values_exposed": False,
        "production_authority": False,
        "memory_grants_authority": False,
    }
    args.receipt.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    atomic_json(args.receipt, receipt, mode=0o440)
    print(json.dumps({**receipt, "secret_file": {"path": str(env_path), "mode": "0640", "group": "integrity-p2-offhost"}}, sort_keys=True))
    return 0


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
