#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Provision least-privilege credentials for the P2 edge relay.

This is a root-only, idempotent bootstrap.  The relay never receives the
PostgreSQL owner, NATS administrator, or MinIO root credentials used here.
"""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import grp
import json
import os
import secrets
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import boto3
import psycopg
from botocore.client import Config

from memory_plane_common import atomic_json, canonical_json, sha256_bytes, sha256_file


PROTOCOL = "integrity-memory-plane.p2-scoped-credentials.v1"
PG_ROLE = "integrity_p2_relay"
NATS_USER = "integrity_p2_relay"
MINIO_USER = "integrityp2relay"
MINIO_POLICY = "integrity-p2-relay-raw-v1"
RAW_BUCKET = "integrity-p2-raw"
RAW_PREFIX = "raw/v1/"


def load_env(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or not key or "\n" in value or "\r" in value:
            raise RuntimeError(f"invalid environment line in {path}")
        result[key] = value
    return result


def write_secret_once(path: Path, values: dict[str, str], group_id: int) -> str:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists():
        if not path.is_file() or path.is_symlink() or path.stat().st_mode & 0o007:
            raise RuntimeError(f"unsafe existing relay secret file: {path}")
        os.chown(path, 0, group_id)
        os.chmod(path, 0o640)
        return "existing"
    content = "".join(f"{key}={value}\n" for key, value in values.items())
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    os.chown(path, 0, group_id)
    os.chmod(path, 0o640)
    directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return "created"


def run_mc(mc: Path, config_dir: Path, args: list[str], input_text: str | None = None) -> str:
    command = [str(mc), "--config-dir", str(config_dir), "--no-color", "--disable-pager", *args]
    result = subprocess.run(
        command,
        input=input_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        timeout=30,
    )
    if result.returncode != 0:
        safe_output = result.stdout
        for token in (input_text or "").splitlines():
            if token:
                safe_output = safe_output.replace(token, "[REDACTED]")
        safe_output = " ".join(safe_output.split())[-800:]
        raise RuntimeError(
            f"mc command failed without exposing arguments: {args[:3]} "
            f"exit={result.returncode} output={safe_output}"
        )
    return result.stdout


def minio_policy() -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetBucketLocation"],
                "Resource": [f"arn:aws:s3:::{RAW_BUCKET}"],
            },
            {
                "Effect": "Allow",
                "Action": ["s3:ListBucket", "s3:ListBucketVersions"],
                "Resource": [f"arn:aws:s3:::{RAW_BUCKET}"],
                "Condition": {"StringLike": {"s3:prefix": [f"{RAW_PREFIX}*"]}},
            },
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject", "s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectRetention"],
                "Resource": [f"arn:aws:s3:::{RAW_BUCKET}/{RAW_PREFIX}*"],
            },
        ],
    }


def configure_postgres(admin: dict[str, str], relay: dict[str, str], host: str) -> None:
    role = psycopg.sql.Identifier(relay["POSTGRES_RELAY_USER"])
    database = psycopg.sql.Identifier(relay["POSTGRES_RELAY_DB"])
    with psycopg.connect(
        host=host,
        port=55432,
        user=admin["POSTGRES_USER"],
        password=admin["POSTGRES_PASSWORD"],
        dbname=admin["POSTGRES_DB"],
        connect_timeout=5,
        autocommit=True,
    ) as connection:
        exists = connection.execute("SELECT 1 FROM pg_roles WHERE rolname=%s", (PG_ROLE,)).fetchone()
        if not exists:
            connection.execute(
                psycopg.sql.SQL(
                    "CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB NOCREATEROLE "
                    "NOINHERIT NOREPLICATION CONNECTION LIMIT 8"
                ).format(role, psycopg.sql.Literal(relay["POSTGRES_RELAY_PASSWORD"])),
            )
        else:
            connection.execute(
                psycopg.sql.SQL(
                    "ALTER ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB NOCREATEROLE "
                    "NOINHERIT NOREPLICATION CONNECTION LIMIT 8"
                ).format(role, psycopg.sql.Literal(relay["POSTGRES_RELAY_PASSWORD"])),
            )
        connection.execute(psycopg.sql.SQL("REVOKE ALL PRIVILEGES ON DATABASE {} FROM PUBLIC").format(database))
        connection.execute(psycopg.sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(database, role))
        connection.execute(psycopg.sql.SQL("REVOKE ALL ON SCHEMA integrity_p2 FROM {}").format(role))
        connection.execute(psycopg.sql.SQL("GRANT USAGE ON SCHEMA integrity_p2 TO {}").format(role))
        connection.execute(psycopg.sql.SQL("REVOKE ALL ON ALL TABLES IN SCHEMA integrity_p2 FROM {}").format(role))
        connection.execute(
            psycopg.sql.SQL("GRANT SELECT,INSERT ON integrity_p2.raw_events, integrity_p2.ingest_batches TO {}").format(role)
        )


def configure_minio(mc: Path, admin: dict[str, str], relay: dict[str, str], endpoint: str) -> str:
    policy = minio_policy()
    policy_sha256 = sha256_bytes(canonical_json(policy))
    with tempfile.TemporaryDirectory(prefix="integrity-p2-mc-") as temporary:
        root = Path(temporary)
        policy_path = root / "relay-policy.json"
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
            f"{relay['MINIO_ACCESS_KEY']}\n{relay['MINIO_SECRET_KEY']}\n",
        )
        run_mc(mc, root, ["admin", "policy", "create", "p2", MINIO_POLICY, str(policy_path)])
        run_mc(mc, root, ["admin", "policy", "attach", "p2", MINIO_POLICY, "--user", MINIO_USER])
        info = run_mc(mc, root, ["admin", "user", "info", "p2", MINIO_USER])
        if "Status: enabled" not in info or MINIO_POLICY not in info:
            raise RuntimeError("MinIO relay user policy attachment readback failed")
    client = boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=relay["MINIO_ACCESS_KEY"],
        aws_secret_access_key=relay["MINIO_SECRET_KEY"],
        region_name="us-east-1",
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
    )
    client.list_object_versions(Bucket=RAW_BUCKET, Prefix=RAW_PREFIX, MaxKeys=1)
    return policy_sha256


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config-root", type=Path, default=Path("/etc/integrity-memory-p2"))
    parser.add_argument("--receipt", type=Path, default=Path(_integrity_value('path_b758804704c1')))
    parser.add_argument("--mc", type=Path, default=Path(_integrity_value('path_2c1826989a4a')))
    parser.add_argument("--postgres-host", default="127.0.0.1")
    parser.add_argument("--minio-endpoint", default=_integrity_value('endpoint_1940bdd68a0a'))
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError("scoped credential bootstrap must run as root")
    group_id = grp.getgrnam("integrity-p2-worker").gr_gid
    relay_shadow_path = args.config_root / "relay-shadow.env"
    relay_minio_path = args.config_root / "relay-minio.env"
    shadow_values = {
        "NATS_RELAY_USER": NATS_USER,
        "NATS_RELAY_PASSWORD": secrets.token_urlsafe(36),
        "POSTGRES_RELAY_USER": PG_ROLE,
        "POSTGRES_RELAY_PASSWORD": secrets.token_urlsafe(36),
        "POSTGRES_RELAY_DB": "integrity_p2",
    }
    minio_values = {
        "MINIO_ACCESS_KEY": MINIO_USER,
        "MINIO_SECRET_KEY": secrets.token_urlsafe(42),
    }
    outcomes = {
        "relay_shadow_env": write_secret_once(relay_shadow_path, shadow_values, group_id),
        "relay_minio_env": write_secret_once(relay_minio_path, minio_values, group_id),
    }
    relay_shadow = load_env(relay_shadow_path)
    relay_minio = load_env(relay_minio_path)
    if relay_shadow.get("NATS_RELAY_USER") != NATS_USER or relay_shadow.get("POSTGRES_RELAY_USER") != PG_ROLE:
        raise RuntimeError("existing relay shadow identity is incompatible")
    if relay_minio.get("MINIO_ACCESS_KEY") != MINIO_USER:
        raise RuntimeError("existing MinIO relay identity is incompatible")
    admin_shadow = load_env(args.config_root / "shadow.env")
    admin_minio = load_env(args.config_root / "minio.env")
    configure_postgres(admin_shadow, relay_shadow, args.postgres_host)
    policy_sha256 = configure_minio(args.mc, admin_minio, relay_minio, args.minio_endpoint)
    receipt = {
        "protocol": PROTOCOL,
        "status": "pass",
        "outcomes": outcomes,
        "postgres": {"role": PG_ROLE, "privileges": ["CONNECT", "USAGE", "raw_events:SELECT,INSERT", "ingest_batches:SELECT,INSERT"]},
        "nats": {"user": NATS_USER, "configuration_pending_reload": True},
        "minio": {"user": MINIO_USER, "policy": MINIO_POLICY, "policy_sha256": policy_sha256},
        "secret_files": {
            str(relay_shadow_path): {"sha256": sha256_file(relay_shadow_path), "mode": "0640", "group": "integrity-p2-worker"},
            str(relay_minio_path): {"sha256": sha256_file(relay_minio_path), "mode": "0640", "group": "integrity-p2-worker"},
        },
        "secret_values_exposed": False,
        "production_authority": False,
        "memory_grants_authority": False,
    }
    args.receipt.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    atomic_json(args.receipt, receipt, mode=0o440)
    print(json.dumps({**receipt, "secret_files": {path: {"mode": value["mode"], "group": value["group"]} for path, value in receipt["secret_files"].items()}}, sort_keys=True))
    return 0


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
