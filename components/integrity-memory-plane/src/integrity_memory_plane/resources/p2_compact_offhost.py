#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Incrementally mirror content-addressed compact-index objects off-host."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import datetime as dt
import json
import os
import shutil
from pathlib import Path
from typing import Any

from memory_plane_common import atomic_json, canonical_json, exclusive_lock, sha256_bytes, sha256_file
from p2_compact_index import PROTOCOL as INDEX_PROTOCOL, immutable_write, manifests, object_path


PROTOCOL = "integrity-memory-plane.p2-compact-offhost.v1"


def inventory(origin: Path) -> dict[str, Any]:
    objects: dict[str, dict[str, Any]] = {}
    head = ""
    for _reference, manifest, digest in manifests(origin):
        for object_digest in (digest, str(manifest["payload"]["sha256"])):
            path = object_path(origin, object_digest)
            objects[object_digest] = {"sha256": object_digest, "bytes": path.stat().st_size}
        head = digest
    state = json.loads((origin / "state.json").read_text(encoding="utf-8"))
    if head != str(state.get("manifest_head_sha256") or ""):
        raise RuntimeError("origin head does not match verified manifest chain")
    value = {
        "protocol": PROTOCOL + ".inventory",
        "index_protocol": INDEX_PROTOCOL,
        "manifest_head_sha256": head,
        "event_count": int(state.get("event_count") or 0),
        "objects": [objects[key] for key in sorted(objects)],
        "production_authority": False,
    }
    value["inventory_sha256"] = sha256_bytes(canonical_json(value))
    return value


def mirror(origin: Path, remote: Path) -> dict[str, Any]:
    remote.mkdir(parents=True, exist_ok=True, mode=0o750)
    (remote / "receipts").mkdir(parents=True, exist_ok=True, mode=0o750)
    with exclusive_lock(remote / "mirror.lock"):
        source = inventory(origin)
        transferred: list[dict[str, Any]] = []
        reused = 0
        for item in source["objects"]:
            digest = str(item["sha256"])
            source_path = object_path(origin, digest)
            destination = object_path(remote, digest)
            if destination.is_file():
                if sha256_file(destination) != digest:
                    raise RuntimeError(f"remote immutable object collision: {digest}")
                reused += 1
                continue
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
            temporary = destination.parent / f".{digest}.{os.getpid()}.tmp"
            try:
                with source_path.open("rb") as src, temporary.open("xb") as dst:
                    shutil.copyfileobj(src, dst, length=1024 * 1024)
                    dst.flush()
                    os.fsync(dst.fileno())
                if sha256_file(temporary) != digest:
                    raise RuntimeError(f"off-host transfer digest mismatch: {digest}")
                os.chmod(temporary, 0o440)
                os.replace(temporary, destination)
            finally:
                try:
                    temporary.unlink()
                except FileNotFoundError:
                    pass
            if sha256_file(destination) != digest:
                raise RuntimeError(f"off-host independent readback mismatch: {digest}")
            transferred.append({"sha256": digest, "bytes": int(item["bytes"])})
        head_bytes = canonical_json(source) + b"\n"
        head_digest = sha256_bytes(head_bytes)
        immutable_write(remote / "heads" / f"{head_digest}.json", head_bytes)
        state = {
            "protocol": PROTOCOL + ".state",
            "updated_utc": dt.datetime.now(dt.UTC).isoformat(),
            "origin_inventory_sha256": source["inventory_sha256"],
            "remote_head_sha256": head_digest,
            "manifest_head_sha256": source["manifest_head_sha256"],
            "event_count": source["event_count"],
            "object_count": len(source["objects"]),
            "production_authority": False,
        }
        atomic_json(remote / "state.json", state, mode=0o640)
    receipt = {
        "protocol": PROTOCOL + ".receipt",
        "status": "PASS",
        "created_utc": dt.datetime.now(dt.UTC).isoformat(),
        "origin_inventory_sha256": source["inventory_sha256"],
        "manifest_head_sha256": source["manifest_head_sha256"],
        "event_count": source["event_count"],
        "objects_total": len(source["objects"]),
        "objects_reused": reused,
        "objects_transferred": len(transferred),
        "bytes_transferred": sum(int(item["bytes"]) for item in transferred),
        "transferred": transferred,
        "incremental_only": True,
        "all_objects_readback_verified": True,
        "production_authority": False,
        "memory_grants_authority": False,
    }
    receipt["evidence_sha256"] = sha256_bytes(canonical_json(receipt))
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    path = remote / "receipts" / f"mirror-{stamp}-{receipt['evidence_sha256'][:16]}.json"
    atomic_json(path, receipt, mode=0o440)
    return {**receipt, "receipt_path": str(path)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--origin", type=Path, required=True)
    parser.add_argument("--remote", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(mirror(args.origin, args.remote), ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
