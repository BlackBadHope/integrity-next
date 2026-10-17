#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Provision the disposable P2 projection schema and scoped worker identities."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import grp
import json
import os
import secrets
import tempfile
from pathlib import Path
from typing import Any

import boto3
import psycopg
from botocore.client import Config

from memory_plane_common import atomic_json, canonical_json, sha256_bytes, sha256_file
from p2_scoped_credentials import load_env, run_mc, write_secret_once


PROTOCOL = "integrity-memory-plane.p2-projection-bootstrap.v1"
PG_ROLE = "integrity_p2_projector"
MINIO_USER = "integrityp2projector"
MINIO_POLICY = "integrity-p2-projector-raw-read-v1"
RAW_BUCKET = "integrity-p2-raw"
RAW_PREFIX = "raw/v1/"


def minio_policy() -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetBucketLocation"], "Resource": [f"arn:aws:s3:::{RAW_BUCKET}"]},
            {
                "Effect": "Allow",
                "Action": ["s3:ListBucket", "s3:ListBucketVersions"],
                "Resource": [f"arn:aws:s3:::{RAW_BUCKET}"],
                "Condition": {"StringLike": {"s3:prefix": [f"{RAW_PREFIX}*"]}},
            },
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectRetention"],
                "Resource": [f"arn:aws:s3:::{RAW_BUCKET}/{RAW_PREFIX}*"],
            },
        ],
    }


def configure_postgres(admin: dict[str, str], worker: dict[str, str], host: str, schema_sql: Path) -> None:
    role = psycopg.sql.Identifier(worker["POSTGRES_PROJECTION_USER"])
    database = psycopg.sql.Identifier(worker["POSTGRES_PROJECTION_DB"])
    password = psycopg.sql.Literal(worker["POSTGRES_PROJECTION_PASSWORD"])
    with psycopg.connect(
        host=host,
        port=55432,
        user=admin["POSTGRES_USER"],
        password=admin["POSTGRES_PASSWORD"],
        dbname=admin["POSTGRES_DB"],
        connect_timeout=5,
        autocommit=True,
    ) as connection:
        connection.execute(schema_sql.read_text(encoding="utf-8"), prepare=False)
        exists = connection.execute("SELECT 1 FROM pg_roles WHERE rolname=%s", (PG_ROLE,)).fetchone()
        if not exists:
            connection.execute(
                psycopg.sql.SQL(
                    "CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB NOCREATEROLE "
                    "NOINHERIT NOREPLICATION CONNECTION LIMIT 8"
                ).format(role, password)
            )
        else:
            connection.execute(
                psycopg.sql.SQL(
                    "ALTER ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB NOCREATEROLE "
                    "NOINHERIT NOREPLICATION CONNECTION LIMIT 8"
                ).format(role, password)
            )
        connection.execute(psycopg.sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(database, role))
        connection.execute(psycopg.sql.SQL("REVOKE ALL ON SCHEMA integrity_p2 FROM {}").format(role))
        connection.execute(psycopg.sql.SQL("GRANT USAGE ON SCHEMA integrity_p2 TO {}").format(role))
        connection.execute(psycopg.sql.SQL("REVOKE ALL ON ALL TABLES IN SCHEMA integrity_p2 FROM {}").format(role))
        connection.execute(
            psycopg.sql.SQL(
                "GRANT SELECT,INSERT,UPDATE,DELETE,TRUNCATE ON "
                "integrity_p2.projection_fts_events,integrity_p2.projection_graph_nodes,"
                "integrity_p2.projection_graph_edges,integrity_p2.projection_vector_events,"
                "integrity_p2.current_task_state TO {}"
            ).format(role)
        )
        connection.execute(
            psycopg.sql.SQL(
                "GRANT SELECT,INSERT,UPDATE,DELETE ON integrity_p2.projection_offsets TO {}"
            ).format(role)
        )
        connection.execute(
            psycopg.sql.SQL("GRANT SELECT,INSERT ON integrity_p2.projection_runs TO {}").format(role)
        )


def configure_minio(mc: Path, admin: dict[str, str], worker: dict[str, str], endpoint: str) -> str:
    policy = minio_policy()
    policy_sha256 = sha256_bytes(canonical_json(policy))
    with tempfile.TemporaryDirectory(prefix="integrity-p2-projector-mc-") as temporary:
        root = Path(temporary)
        policy_path = root / "projector-policy.json"
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
            f"{worker['MINIO_PROJECTION_ACCESS_KEY']}\n{worker['MINIO_PROJECTION_SECRET_KEY']}\n",
        )
        run_mc(mc, root, ["admin", "policy", "create", "p2", MINIO_POLICY, str(policy_path)])
        run_mc(mc, root, ["admin", "policy", "attach", "p2", MINIO_POLICY, "--user", MINIO_USER])
        info = run_mc(mc, root, ["admin", "user", "info", "p2", MINIO_USER])
        if "Status: enabled" not in info or MINIO_POLICY not in info:
            raise RuntimeError("MinIO projector policy attachment readback failed")
    client = boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=worker["MINIO_PROJECTION_ACCESS_KEY"],
        aws_secret_access_key=worker["MINIO_PROJECTION_SECRET_KEY"],
        region_name="us-east-1",
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
    )
    client.list_object_versions(Bucket=RAW_BUCKET, Prefix=RAW_PREFIX, MaxKeys=1)
    return policy_sha256


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config-root", type=Path, default=Path("/etc/integrity-memory-p2"))
    parser.add_argument("--schema-sql", type=Path, default=Path("/etc/integrity-memory-p2/p2-projections.sql"))
    parser.add_argument("--receipt", type=Path, default=Path(_integrity_value('path_a64a3373ff59')))
    parser.add_argument("--mc", type=Path, default=Path(_integrity_value('path_2c1826989a4a')))
    parser.add_argument("--postgres-host", default="127.0.0.1")
    parser.add_argument("--minio-endpoint", default=_integrity_value('endpoint_1940bdd68a0a'))
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError("projection bootstrap must run as root")
    group_id = grp.getgrnam("integrity-p2-projector").gr_gid
    pg_path = args.config_root / "projection.env"
    minio_path = args.config_root / "projection-minio.env"
    pg_values = {
        "POSTGRES_PROJECTION_USER": PG_ROLE,
        "POSTGRES_PROJECTION_PASSWORD": secrets.token_urlsafe(36),
        "POSTGRES_PROJECTION_DB": "integrity_p2",
    }
    minio_values = {
        "MINIO_PROJECTION_ACCESS_KEY": MINIO_USER,
        "MINIO_PROJECTION_SECRET_KEY": secrets.token_urlsafe(42),
    }
    outcomes = {
        "projection_env": write_secret_once(pg_path, pg_values, group_id),
        "projection_minio_env": write_secret_once(minio_path, minio_values, group_id),
    }
    pg_worker = load_env(pg_path)
    minio_worker = load_env(minio_path)
    if pg_worker.get("POSTGRES_PROJECTION_USER") != PG_ROLE or minio_worker.get("MINIO_PROJECTION_ACCESS_KEY") != MINIO_USER:
        raise RuntimeError("existing projection identity is incompatible")
    configure_postgres(load_env(args.config_root / "shadow.env"), pg_worker, args.postgres_host, args.schema_sql)
    policy_sha256 = configure_minio(args.mc, load_env(args.config_root / "minio.env"), minio_worker, args.minio_endpoint)
    receipt = {
        "protocol": PROTOCOL,
        "status": "pass",
        "outcomes": outcomes,
        "postgres": {"role": PG_ROLE, "raw_write": False, "projection_write": True},
        "minio": {"user": MINIO_USER, "policy": MINIO_POLICY, "policy_sha256": policy_sha256, "raw_write": False},
        "secret_files": {
            str(pg_path): {"sha256": sha256_file(pg_path), "mode": "0640", "group": "integrity-p2-projector"},
            str(minio_path): {"sha256": sha256_file(minio_path), "mode": "0640", "group": "integrity-p2-projector"},
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
