#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Disposable O(log N) locator catalog for committed P2 relay receipts.

The catalog is candidate infrastructure only.  A lookup is usable solely after
the selected receipt file digest and its immutable batch identity are verified;
the raw WORM reader then independently verifies the referenced object version.
"""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import bisect
import json
from pathlib import Path
from typing import Any

from memory_plane_common import atomic_json, canonical_json, sha256_bytes, sha256_file


PROTOCOL = "integrity-memory-plane.p2-receipt-catalog.v1"


def build_catalog(receipts: list[tuple[Path, dict[str, Any]]], path: Path) -> dict[str, Any]:
    if not receipts:
        raise RuntimeError("receipt catalog source is empty")
    entries: list[dict[str, Any]] = []
    for receipt_path, receipt in receipts:
        batch = receipt["batch"]
        entries.append(
            {
                "first_cursor": int(batch["first_cursor"]),
                "last_cursor": int(batch["last_cursor"]),
                "batch_sha256": str(batch["batch_sha256"]),
                "receipt_filename": receipt_path.name,
                "receipt_sha256": sha256_file(receipt_path),
            }
        )
    value = {
        "protocol": PROTOCOL + ".catalog",
        "first_cursor": entries[0]["first_cursor"],
        "last_cursor": entries[-1]["last_cursor"],
        "receipt_count": len(entries),
        "entries": entries,
        "production_authority": False,
        "memory_grants_authority": False,
    }
    value["catalog_sha256"] = sha256_bytes(canonical_json(value))
    atomic_json(path, value, mode=0o640)
    return value


def load_catalog(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    claimed = str(value.pop("catalog_sha256", ""))
    if value.get("protocol") != PROTOCOL + ".catalog":
        raise RuntimeError("receipt catalog protocol mismatch")
    if value.get("production_authority") is not False or value.get("memory_grants_authority") is not False:
        raise RuntimeError("receipt catalog claims authority")
    if sha256_bytes(canonical_json(value)) != claimed:
        raise RuntimeError("receipt catalog self-digest mismatch")
    value["catalog_sha256"] = claimed
    entries = value.get("entries") or []
    if int(value.get("receipt_count") or 0) != len(entries) or not entries:
        raise RuntimeError("receipt catalog count mismatch")
    previous = 0
    for entry in entries:
        first, last = int(entry["first_cursor"]), int(entry["last_cursor"])
        name = str(entry["receipt_filename"])
        if first <= previous or last < first or Path(name).name != name:
            raise RuntimeError("receipt catalog order or filename rejected")
        previous = last
    if int(value["first_cursor"]) != int(entries[0]["first_cursor"]) or int(value["last_cursor"]) != previous:
        raise RuntimeError("receipt catalog boundary mismatch")
    return value


def entry_for_cursor(catalog: dict[str, Any], cursor: int) -> dict[str, Any] | None:
    entries = catalog["entries"]
    firsts = [int(value["first_cursor"]) for value in entries]
    position = bisect.bisect_right(firsts, int(cursor)) - 1
    if position < 0:
        return None
    entry = entries[position]
    return entry if int(entry["first_cursor"]) <= cursor <= int(entry["last_cursor"]) else None


def verified_receipt(receipts_root: Path, entry: dict[str, Any]) -> tuple[Path, dict[str, Any]]:
    path = receipts_root / str(entry["receipt_filename"])
    if sha256_file(path) != str(entry["receipt_sha256"]):
        raise RuntimeError("selected relay receipt digest mismatch")
    receipt = json.loads(path.read_text(encoding="utf-8"))
    batch = receipt.get("batch") or {}
    if (
        receipt.get("status") != "shadow_pipeline_committed"
        or receipt.get("production_authority") is not False
        or (receipt.get("ack_decision") or {}).get("status") != "NOT_ACKED"
        or int(batch.get("first_cursor") or 0) != int(entry["first_cursor"])
        or int(batch.get("last_cursor") or 0) != int(entry["last_cursor"])
        or str(batch.get("batch_sha256") or "") != str(entry["batch_sha256"])
    ):
        raise RuntimeError("selected relay receipt contract mismatch")
    return path, receipt

