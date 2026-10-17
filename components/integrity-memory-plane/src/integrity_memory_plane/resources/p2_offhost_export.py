#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build a deterministic P2 raw recovery capsule from committed WORM versions."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import gzip
import grp
import json
import os
import pwd
import shutil
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import boto3
from botocore.client import Config

from memory_plane_common import atomic_json, canonical_json, exclusive_lock, sha256_bytes, sha256_file
from p2_projection import RAW_BUCKET, committed_receipts, raw_envelopes


PROTOCOL = "integrity-memory-plane.p2-offhost-export.v1"
RAW_PLANE_LOCK = Path(_integrity_value('path_13faba5553a5'))


def load_env(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or not key:
            raise RuntimeError(f"invalid environment line in {path}")
        result[key] = value
    return result


def s3_client(env: dict[str, str], endpoint: str) -> Any:
    return boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=env["MINIO_OFFHOST_ACCESS_KEY"],
        aws_secret_access_key=env["MINIO_OFFHOST_SECRET_KEY"],
        region_name="us-east-1",
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}, retries={"max_attempts": 2}),
    )


def deterministic_tar(stage: Path, destination: Path) -> str:
    with destination.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=6) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as bundle:
                for path in sorted(stage.rglob("*")):
                    if not path.is_file():
                        continue
                    relative = path.relative_to(stage).as_posix()
                    if relative.startswith("/") or ".." in Path(relative).parts or "\\" in relative:
                        raise RuntimeError(f"unsafe capsule member: {relative}")
                    info = bundle.gettarinfo(str(path), arcname=relative)
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    info.mtime = 0
                    with path.open("rb") as handle:
                        bundle.addfile(info, handle)
    return sha256_file(destination)


def build_capsule(receipts_root: Path, client: Any, export_root: Path, owner_user: str | None = None, shared_group: str | None = None) -> dict[str, Any]:
    receipts = committed_receipts(receipts_root)
    if not receipts:
        raise RuntimeError("no committed raw receipts are available")
    export_root.mkdir(parents=True, exist_ok=True, mode=0o2750)
    with tempfile.TemporaryDirectory(prefix=".p2-offhost-", dir=export_root) as temporary:
        root = Path(temporary)
        stage = root / "stage"
        (stage / "raw").mkdir(parents=True, mode=0o700)
        (stage / "receipts").mkdir(mode=0o700)
        files: list[dict[str, Any]] = []
        event_count = 0
        receipt_chain: list[dict[str, Any]] = []
        for index, (receipt_path, receipt) in enumerate(receipts, start=1):
            envelopes = raw_envelopes(client, receipt)
            event_count += len(envelopes)
            batch = receipt["batch"]
            raw = receipt["raw"]
            raw_bytes = client.get_object(Bucket=RAW_BUCKET, Key=raw["key"], VersionId=raw["version_id"])["Body"].read()
            if sha256_bytes(raw_bytes) != raw["content_sha256"]:
                raise RuntimeError("exact-version raw digest changed between semantic verification and export")
            prefix = f"{index:020d}-{str(batch['batch_sha256'])}"
            raw_target = stage / "raw" / f"{prefix}.ndjson.gz"
            raw_target.write_bytes(raw_bytes)
            receipt_target = stage / "receipts" / f"{prefix}.receipt.json"
            shutil.copyfile(receipt_path, receipt_target)
            raw_entry = {
                "path": raw_target.relative_to(stage).as_posix(),
                "bytes": len(raw_bytes),
                "sha256": sha256_file(raw_target),
                "s3_key": str(raw["key"]),
                "s3_version_id": str(raw["version_id"]),
                "first_cursor": int(batch["first_cursor"]),
                "last_cursor": int(batch["last_cursor"]),
                "event_count": int(batch["event_count"]),
                "batch_sha256": str(batch["batch_sha256"]),
            }
            receipt_entry = {
                "path": receipt_target.relative_to(stage).as_posix(),
                "bytes": receipt_target.stat().st_size,
                "sha256": sha256_file(receipt_target),
                "batch_sha256": str(batch["batch_sha256"]),
            }
            files.extend((raw_entry, receipt_entry))
            receipt_chain.append({"batch_sha256": str(batch["batch_sha256"]), "receipt_sha256": receipt_entry["sha256"]})
        tip = str(receipts[-1][1]["batch"]["batch_sha256"])
        head_cursor = int(receipts[-1][1]["batch"]["last_cursor"])
        inventory = {
            "protocol": PROTOCOL + ".inventory",
            "tenant_id": str(receipts[-1][1]["batch"]["tenant_id"]),
            "namespace": str(receipts[-1][1]["batch"]["namespace"]),
            "edge_id": str(receipts[-1][1]["batch"]["edge_id"]),
            "batch_count": len(receipts),
            "event_count": event_count,
            "head_cursor": head_cursor,
            "tip_batch_sha256": tip,
            "receipt_chain_sha256": sha256_bytes(canonical_json(receipt_chain)),
            "files": files,
            "production_authority": False,
            "memory_grants_authority": False,
        }
        inventory_path = stage / "inventory.json"
        inventory_path.write_bytes(canonical_json(inventory) + b"\n")
        inventory_sha = sha256_file(inventory_path)
        name = f"p2-raw-head-{head_cursor:020d}-batches-{len(receipts):08d}-{tip[:12]}-{inventory_sha[:12]}.tar.gz"
        temporary_capsule = root / (name + ".part")
        capsule_sha = deterministic_tar(stage, temporary_capsule)
        target = export_root / name
        if target.exists():
            if not target.is_file() or target.is_symlink() or sha256_file(target) != capsule_sha:
                raise RuntimeError("existing content-addressed off-host capsule digest mismatch")
            status = "already-present"
        else:
            os.replace(temporary_capsule, target)
            status = "created"
        os.chmod(target, 0o440)
        if owner_user and shared_group:
            os.chown(target, pwd.getpwnam(owner_user).pw_uid, grp.getgrnam(shared_group).gr_gid)
        return {
            "protocol": PROTOCOL + ".capsule",
            "status": status,
            "path": str(target),
            "name": name,
            "bytes": target.stat().st_size,
            "sha256": capsule_sha,
            "inventory_sha256": inventory_sha,
            "batch_count": len(receipts),
            "event_count": event_count,
            "head_cursor": head_cursor,
            "tip_batch_sha256": tip,
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipts", type=Path, default=Path(_integrity_value('path_f5a9a1727fe8')))
    parser.add_argument("--minio-env", type=Path, default=Path("/etc/integrity-memory-p2/offhost-minio.env"))
    parser.add_argument("--s3-endpoint", default=_integrity_value('endpoint_1940bdd68a0a'))
    parser.add_argument("--export-root", type=Path, default=Path(_integrity_value('path_806caa795eda')))
    parser.add_argument("--state", type=Path, default=Path(_integrity_value('path_a3114bdbc720')))
    parser.add_argument("--receipt-root", type=Path, default=Path(_integrity_value('path_be535046aac6')))
    parser.add_argument("--lock", type=Path, default=RAW_PLANE_LOCK)
    parser.add_argument("--owner-user", default="integrity-p2-offhost")
    parser.add_argument("--shared-group", default="integrity-p2-offhost-export")
    args = parser.parse_args()
    with exclusive_lock(args.lock, wait_seconds=120):
        capsule = build_capsule(args.receipts, s3_client(load_env(args.minio_env), args.s3_endpoint), args.export_root, args.owner_user, args.shared_group)
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    state = {**capsule, "protocol": PROTOCOL + ".state", "updated_utc": now, "production_authority": False}
    args.state.parent.mkdir(parents=True, exist_ok=True, mode=0o2750)
    atomic_json(args.state, state, mode=0o440)
    os.chown(args.state, pwd.getpwnam(args.owner_user).pw_uid, grp.getgrnam(args.shared_group).gr_gid)
    args.receipt_root.mkdir(parents=True, exist_ok=True, mode=0o750)
    receipt_path = args.receipt_root / f"export-head-{capsule['head_cursor']:020d}-{capsule['sha256'][:16]}.json"
    atomic_json(receipt_path, state, mode=0o440)
    print(json.dumps({**state, "receipt_path": str(receipt_path)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
