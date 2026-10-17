#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Provision read-only PostgreSQL and MinIO identities for P2 dual-read."""

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
import psycopg
from botocore.client import Config

from memory_plane_common import atomic_json, canonical_json, sha256_bytes, sha256_file
from p2_projection_bootstrap import RAW_BUCKET, RAW_PREFIX, minio_policy
from p2_scoped_credentials import load_env, run_mc, write_secret_once


PROTOCOL = "integrity-memory-plane.p2-dual-reader-bootstrap.v1"
PG_ROLE = "integrity_p2_dual_reader"
MINIO_USER = "integrityp2dualreader"
MINIO_POLICY = "integrity-p2-dual-reader-raw-read-v1"


def configure_postgres(admin: dict[str, str], reader: dict[str, str], host: str) -> None:
    role = psycopg.sql.Identifier(reader["POSTGRES_DUAL_USER"])
    database = psycopg.sql.Identifier(reader["POSTGRES_DUAL_DB"])
    password = psycopg.sql.Literal(reader["POSTGRES_DUAL_PASSWORD"])
    tables = (
        "integrity_p2.raw_events,integrity_p2.ingest_batches,integrity_p2.projection_fts_events,"
        "integrity_p2.projection_graph_nodes,integrity_p2.projection_graph_edges,"
        "integrity_p2.projection_vector_events,integrity_p2.projection_offsets,integrity_p2.current_task_state"
    )
    with psycopg.connect(host=host, port=55432, user=admin["POSTGRES_USER"], password=admin["POSTGRES_PASSWORD"], dbname=admin["POSTGRES_DB"], connect_timeout=5, autocommit=True) as connection:
        exists = connection.execute("SELECT 1 FROM pg_roles WHERE rolname=%s", (PG_ROLE,)).fetchone()
        statement = "ALTER ROLE" if exists else "CREATE ROLE"
        connection.execute(psycopg.sql.SQL(statement + " {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION CONNECTION LIMIT 8").format(role, password))
        connection.execute(psycopg.sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(database, role))
        connection.execute(psycopg.sql.SQL("REVOKE ALL ON SCHEMA integrity_p2 FROM {}").format(role))
        connection.execute(psycopg.sql.SQL("GRANT USAGE ON SCHEMA integrity_p2 TO {}").format(role))
        connection.execute(psycopg.sql.SQL("REVOKE ALL ON ALL TABLES IN SCHEMA integrity_p2 FROM {}").format(role))
        connection.execute(psycopg.sql.SQL("GRANT SELECT ON " + tables + " TO {}").format(role))


def configure_minio(mc: Path, admin: dict[str, str], reader: dict[str, str], endpoint: str) -> str:
    policy = minio_policy()
    digest = sha256_bytes(canonical_json(policy))
    with tempfile.TemporaryDirectory(prefix="integrity-p2-dual-reader-mc-") as temporary:
        root = Path(temporary)
        policy_path = root / "dual-reader-policy.json"
        policy_path.write_bytes(canonical_json(policy) + b"\n")
        os.chmod(policy_path, 0o600)
        run_mc(mc, root, ["alias", "set", "p2", endpoint, "--api", "S3v4", "--path", "on"], f"{admin['MINIO_ROOT_USER']}\n{admin['MINIO_ROOT_PASSWORD']}\n")
        run_mc(mc, root, ["admin", "user", "add", "p2"], f"{reader['MINIO_DUAL_ACCESS_KEY']}\n{reader['MINIO_DUAL_SECRET_KEY']}\n")
        run_mc(mc, root, ["admin", "policy", "create", "p2", MINIO_POLICY, str(policy_path)])
        run_mc(mc, root, ["admin", "policy", "attach", "p2", MINIO_POLICY, "--user", MINIO_USER])
        info = run_mc(mc, root, ["admin", "user", "info", "p2", MINIO_USER])
        if "Status: enabled" not in info or MINIO_POLICY not in info:
            raise RuntimeError("MinIO dual-reader policy attachment readback failed")
    client = boto3.client("s3", endpoint_url=endpoint, aws_access_key_id=reader["MINIO_DUAL_ACCESS_KEY"], aws_secret_access_key=reader["MINIO_DUAL_SECRET_KEY"], region_name="us-east-1", config=Config(signature_version="s3v4", s3={"addressing_style": "path"}))
    client.list_object_versions(Bucket=RAW_BUCKET, Prefix=RAW_PREFIX, MaxKeys=1)
    return digest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config-root", type=Path, default=Path("/etc/integrity-memory-p2"))
    parser.add_argument("--receipt", type=Path, default=Path(_integrity_value('path_f4132be049c7')))
    parser.add_argument("--mc", type=Path, default=Path(_integrity_value('path_2c1826989a4a')))
    parser.add_argument("--postgres-host", default="127.0.0.1")
    parser.add_argument("--minio-endpoint", default=_integrity_value('endpoint_1940bdd68a0a'))
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError("dual-reader bootstrap must run as root")
    group_id = grp.getgrnam("integrity-p2-dual-reader").gr_gid
    pg_path = args.config_root / "dual-reader.env"
    minio_path = args.config_root / "dual-reader-minio.env"
    outcomes = {
        "postgres": write_secret_once(pg_path, {"POSTGRES_DUAL_USER": PG_ROLE, "POSTGRES_DUAL_PASSWORD": secrets.token_urlsafe(36), "POSTGRES_DUAL_DB": "integrity_p2"}, group_id),
        "minio": write_secret_once(minio_path, {"MINIO_DUAL_ACCESS_KEY": MINIO_USER, "MINIO_DUAL_SECRET_KEY": secrets.token_urlsafe(42)}, group_id),
    }
    reader = load_env(pg_path)
    minio_reader = load_env(minio_path)
    configure_postgres(load_env(args.config_root / "shadow.env"), reader, args.postgres_host)
    policy_sha256 = configure_minio(args.mc, load_env(args.config_root / "minio.env"), minio_reader, args.minio_endpoint)
    receipt = {
        "protocol": PROTOCOL,
        "status": "pass",
        "outcomes": outcomes,
        "postgres": {"role": PG_ROLE, "projection_read": True, "raw_metadata_read": True, "write": False},
        "minio": {"user": MINIO_USER, "policy": MINIO_POLICY, "policy_sha256": policy_sha256, "raw_read": True, "raw_write": False},
        "secret_files": {str(pg_path): {"sha256": sha256_file(pg_path), "mode": "0640"}, str(minio_path): {"sha256": sha256_file(minio_path), "mode": "0640"}},
        "production_authority": False,
        "memory_grants_authority": False,
    }
    args.receipt.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    atomic_json(args.receipt, receipt, mode=0o440)
    print(json.dumps({**receipt, "secret_files": {key: {"mode": "0640", "group": "integrity-p2-dual-reader"} for key in receipt["secret_files"]}}, sort_keys=True))
    return 0


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
