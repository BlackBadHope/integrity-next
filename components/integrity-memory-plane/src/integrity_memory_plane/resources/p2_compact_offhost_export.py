#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Stage verified compact content-addressed objects for split-authority pull."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import datetime as dt
import json
import os
import re
from pathlib import Path
from typing import Any

from memory_plane_common import atomic_json, canonical_json, exclusive_lock, safe_copy, sha256_bytes, sha256_file
from p2_compact_index import PROTOCOL as INDEX_PROTOCOL, manifests, object_path


PROTOCOL = "integrity-memory-plane.p2-compact-offhost-export.v1"
DIGEST = re.compile(r"^[0-9a-f]{64}$")


def _stage_object(source: Path, export_root: Path, kind: str) -> dict[str, Any]:
    digest = sha256_file(source)
    if not DIGEST.fullmatch(digest):
        raise RuntimeError("invalid staged object digest")
    relative = f"objects/sha256/{digest[:2]}/{digest}"
    destination = export_root / relative
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    if destination.is_file():
        if destination.is_symlink() or sha256_file(destination) != digest:
            raise RuntimeError(f"staged compact object collision: {digest}")
    else:
        safe_copy(source, destination, mode=0o440)
    return {"relative": relative, "sha256": digest, "bytes": source.stat().st_size, "kind": kind}


def export(index_root: Path, catalog_root: Path, export_root: Path, state_path: Path) -> dict[str, Any]:
    export_root.mkdir(parents=True, exist_ok=True, mode=0o750)
    values = manifests(index_root)
    if not values:
        raise RuntimeError("compact offhost export has no verified manifests")
    index_state = json.loads((index_root / "state.json").read_text(encoding="utf-8"))
    catalog_state = json.loads((catalog_root / "state.json").read_text(encoding="utf-8"))
    if str(index_state.get("manifest_head_sha256") or "") != values[-1][2]:
        raise RuntimeError("compact export index head mismatch")
    if str(catalog_state.get("processed_manifest_head_sha256") or "") != values[-1][2]:
        raise RuntimeError("compact export catalog head mismatch")
    sources: dict[Path, str] = {}
    for _reference, manifest, digest in values:
        sources[object_path(index_root, digest)] = "index-manifest"
        sources[object_path(index_root, str(manifest["payload"]["sha256"]))] = "index-payload"
    logical: dict[str, str] = {}
    for logical_name, source in (
        ("index/state.json", index_root / "state.json"),
        ("catalog/state.json", catalog_root / "state.json"),
        ("catalog/buckets.bin", catalog_root / "buckets.bin"),
    ):
        sources[source] = "logical-head"
        logical[logical_name] = sha256_file(source)
    for path in sorted((catalog_root / "uid-runs").glob("*.bin")):
        sources[path] = "uid-lsm-run"
        logical[f"catalog/uid-runs/{path.name}"] = sha256_file(path)
    with exclusive_lock(export_root / "export.lock"):
        entries = [_stage_object(path, export_root, kind) for path, kind in sorted(sources.items(), key=lambda item: str(item[0]))]
        entries.sort(key=lambda value: value["relative"])
        inventory = {
            "protocol": PROTOCOL + ".inventory",
            "index_protocol": INDEX_PROTOCOL,
            "manifest_head_sha256": values[-1][2],
            "event_count": int(index_state["event_count"]),
            "segment_count": int(index_state["segment_count"]),
            "logical_heads": logical,
            "objects": entries,
            "production_authority": False,
        }
        inventory_bytes = canonical_json(inventory) + b"\n"
        inventory_sha = sha256_bytes(inventory_bytes)
        inventory_path = export_root / "inventories" / f"{inventory_sha}.json"
        inventory_path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        if inventory_path.is_file():
            if sha256_file(inventory_path) != inventory_sha:
                raise RuntimeError("compact inventory immutable collision")
        else:
            descriptor = os.open(inventory_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o440)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(inventory_bytes)
                handle.flush()
                os.fsync(handle.fileno())
        state = {
            "protocol": PROTOCOL + ".state",
            "updated_utc": dt.datetime.now(dt.UTC).isoformat(),
            "export_root": str(export_root),
            "inventory_path": str(inventory_path),
            "inventory_sha256": inventory_sha,
            "manifest_head_sha256": values[-1][2],
            "event_count": int(index_state["event_count"]),
            "segment_count": int(index_state["segment_count"]),
            "object_count": len(entries),
            "logical_bytes": sum(int(value["bytes"]) for value in entries),
            "production_authority": False,
            "memory_grants_authority": False,
        }
        atomic_json(state_path, state, mode=0o440)
    receipt = {
        "protocol": PROTOCOL + ".receipt",
        "status": "PASS",
        "created_utc": dt.datetime.now(dt.UTC).isoformat(),
        **{key: state[key] for key in ("inventory_sha256", "manifest_head_sha256", "event_count", "segment_count", "object_count", "logical_bytes")},
        "incremental_content_addressed": True,
        "production_authority": False,
        "memory_grants_authority": False,
    }
    receipt["evidence_sha256"] = sha256_bytes(canonical_json(receipt))
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--index-root", type=Path, default=Path(_integrity_value('path_2bc0a1dc9ccf')))
    parser.add_argument("--catalog-root", type=Path, default=Path(_integrity_value('path_545661f97ab7')))
    parser.add_argument("--export-root", type=Path, default=Path(_integrity_value('path_0b6cc4f54ed3')))
    parser.add_argument("--state", type=Path, default=Path(_integrity_value('path_842e373e982a')))
    args = parser.parse_args()
    print(json.dumps(export(args.index_root, args.catalog_root, args.export_root, args.state), ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
