#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Restore a P2 capsule back from client and verify it without live memory services."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import gzip
import hashlib
import json
import os
import re
import tarfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from memory_plane_common import atomic_json, canonical_json, sha256_bytes, sha256_file
from offhost_windows_replica import execute_remote, ps_quote
from p2_contract import Envelope, build_batch


PROTOCOL = "integrity-memory-plane.p2-offhost-restore-drill.v1"
MEMBER_RE = re.compile(r"^(inventory\.json|raw/[0-9]{20}-[0-9a-f]{64}\.ndjson\.gz|receipts/[0-9]{20}-[0-9a-f]{64}\.receipt\.json)$")


def archive_files(path: Path) -> dict[str, bytes]:
    values: dict[str, bytes] = {}
    with tarfile.open(path, "r:gz") as archive:
        for member in archive.getmembers():
            if not member.isfile() or not MEMBER_RE.fullmatch(member.name) or member.name in values:
                raise RuntimeError(f"unsafe or duplicate restored capsule member: {member.name}")
            handle = archive.extractfile(member)
            if handle is None:
                raise RuntimeError(f"unreadable restored capsule member: {member.name}")
            values[member.name] = handle.read()
    return values


def verify_capsule(path: Path, expected_capsule_sha256: str, expected_inventory_sha256: str) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink() or sha256_file(path) != expected_capsule_sha256:
        raise RuntimeError("restored capsule outer digest mismatch")
    members = archive_files(path)
    inventory_bytes = members.get("inventory.json")
    if inventory_bytes is None or sha256_bytes(inventory_bytes) != expected_inventory_sha256:
        raise RuntimeError("restored capsule inventory digest mismatch")
    inventory = json.loads(inventory_bytes)
    if inventory.get("protocol") != "integrity-memory-plane.p2-offhost-export.v1.inventory":
        raise RuntimeError("restored capsule inventory protocol mismatch")
    entries = inventory.get("files")
    if not isinstance(entries, list):
        raise RuntimeError("restored capsule inventory files missing")
    entry_paths = [str(value.get("path") or "") for value in entries]
    if len(entry_paths) != len(set(entry_paths)) or set(entry_paths) != set(members) - {"inventory.json"}:
        raise RuntimeError("restored capsule inventory/member set mismatch")
    by_batch: dict[str, dict[str, dict[str, Any]]] = {}
    for entry in entries:
        member = members[str(entry["path"])]
        if len(member) != int(entry["bytes"]) or sha256_bytes(member) != str(entry["sha256"]):
            raise RuntimeError(f"restored member readback mismatch: {entry['path']}")
        kind = "raw" if str(entry["path"]).startswith("raw/") else "receipt"
        batch_sha = str(entry.get("batch_sha256") or "")
        if not re.fullmatch(r"[0-9a-f]{64}", batch_sha) or kind in by_batch.setdefault(batch_sha, {}):
            raise RuntimeError("restored inventory batch mapping invalid")
        by_batch[batch_sha][kind] = {"entry": entry, "bytes": member}
    ordered: list[tuple[int, str, dict[str, Any], list[dict[str, Any]]]] = []
    for batch_sha, pair in by_batch.items():
        if set(pair) != {"raw", "receipt"}:
            raise RuntimeError("restored batch lacks raw/receipt pair")
        receipt = json.loads(pair["receipt"]["bytes"])
        if receipt.get("status") != "shadow_pipeline_committed" or receipt.get("production_authority") is not False or (receipt.get("ack_decision") or {}).get("status") != "NOT_ACKED":
            raise RuntimeError("restored receipt is not a committed shadow receipt")
        batch = receipt["batch"]
        if str(batch.get("batch_sha256")) != batch_sha:
            raise RuntimeError("restored receipt batch identity mismatch")
        raw_meta = receipt["raw"]
        raw_entry = pair["raw"]["entry"]
        raw_bytes = pair["raw"]["bytes"]
        if (
            sha256_bytes(raw_bytes) != str(raw_meta.get("content_sha256"))
            or str(raw_entry.get("s3_key")) != str(raw_meta.get("key"))
            or str(raw_entry.get("s3_version_id")) != str(raw_meta.get("version_id"))
        ):
            raise RuntimeError("restored raw exact-version binding mismatch")
        lines = gzip.decompress(raw_bytes).splitlines()
        if len(lines) < 2:
            raise RuntimeError("restored raw object has no envelopes")
        header = json.loads(lines[0])
        if header.get("batch_manifest") != batch:
            raise RuntimeError("restored raw header/receipt mismatch")
        source_sha = sha256_bytes(canonical_json(header.get("source_manifest")))
        envelopes: list[dict[str, Any]] = []
        reconstructed: list[Envelope] = []
        for line in lines[1:]:
            value = json.loads(line)
            if str(value.get("source_manifest_sha256")) != source_sha:
                raise RuntimeError("restored envelope/source manifest mismatch")
            envelope = Envelope(
                tenant_id=value["tenant_id"],
                namespace=value["namespace"],
                edge_id=value["edge_id"],
                cursor=int(value["cursor"]),
                event_uid=value["event_uid"],
                ts_utc=value["ts_utc"],
                payload=value["payload"],
                source_manifest_sha256=value["source_manifest_sha256"],
                previous_envelope_sha256=value["previous_envelope_sha256"],
            )
            if envelope.value() != value:
                raise RuntimeError("restored envelope digest mismatch")
            reconstructed.append(envelope)
            envelopes.append(value)
        rebuilt = build_batch(reconstructed, previous_batch_sha256=str(batch["previous_batch_sha256"]).rstrip())
        if {key: value for key, value in rebuilt.items() if key != "envelopes"} != batch:
            raise RuntimeError("restored batch digest reconstruction mismatch")
        ordered.append((int(batch["first_cursor"]), batch_sha, receipt, envelopes))
    ordered.sort()
    previous_batch = ""
    previous_envelope = ""
    previous_cursor = 0
    event_count = 0
    receipt_chain: list[dict[str, Any]] = []
    for first_cursor, batch_sha, receipt, envelopes in ordered:
        batch = receipt["batch"]
        if str(batch["previous_batch_sha256"]).rstrip() != previous_batch or first_cursor <= previous_cursor:
            raise RuntimeError("restored batch chain/order mismatch")
        if str(envelopes[0]["previous_envelope_sha256"]).rstrip() != previous_envelope:
            raise RuntimeError("restored cross-batch envelope chain mismatch")
        previous_batch = batch_sha
        previous_envelope = str(envelopes[-1]["envelope_sha256"])
        previous_cursor = int(batch["last_cursor"])
        event_count += len(envelopes)
        receipt_path = next(str(value["path"]) for value in entries if str(value.get("batch_sha256")) == batch_sha and str(value["path"]).startswith("receipts/"))
        receipt_chain.append({"batch_sha256": batch_sha, "receipt_sha256": sha256_bytes(members[receipt_path])})
    checks = {
        "early_cursor_present": bool(ordered and ordered[0][0] == 1),
        "batch_count": len(ordered) == int(inventory["batch_count"]),
        "event_count": event_count == int(inventory["event_count"]),
        "head_cursor": previous_cursor == int(inventory["head_cursor"]),
        "tip_batch_sha256": previous_batch == str(inventory["tip_batch_sha256"]),
        "receipt_chain_sha256": sha256_bytes(canonical_json(receipt_chain)) == str(inventory["receipt_chain_sha256"]),
        "all_members_verified": len(members) == 1 + 2 * len(ordered),
    }
    if not all(checks.values()):
        raise RuntimeError("restored capsule semantic checks failed")
    return {
        "status": "PASS",
        "checks": checks,
        "batch_count": len(ordered),
        "event_count": event_count,
        "head_cursor": previous_cursor,
        "tip_batch_sha256": previous_batch,
        "capsule_sha256": expected_capsule_sha256,
        "inventory_sha256": expected_inventory_sha256,
        "source_dependencies": {"action_log": False, "minio": False, "postgres": False, "nats": False},
        "production_authority": False,
        "memory_grants_authority": False,
    }


def push_command(state: dict[str, Any], destination: Path, args: argparse.Namespace) -> str:
    source = str(state.get("remote_path") or "")
    if not re.fullmatch(r"[A-Za-z]:\\[^\r\n]+\.tar\.gz", source) or ".." in source.split("\\"):
        raise RuntimeError("unsafe client restore source path")
    target = f"{args.pull_user}@127.0.0.1:{destination}"
    return ";".join(
        [
            "$ErrorActionPreference='Stop'",
            f"$source={ps_quote(source)}",
            f"$expected={ps_quote(str(state['capsule_sha256']))}",
            "if(-not (Test-Path -LiteralPath $source -PathType Leaf)){throw 'client restore source missing'}",
            "$digest=(Get-FileHash -Algorithm SHA256 -LiteralPath $source).Hash.ToLowerInvariant()",
            "if($digest -ne $expected){throw 'client restore source digest mismatch'}",
            f"& scp.exe -q -P {args.pull_port} -i {ps_quote(args.pull_key)} -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o HostKeyAlias={ps_quote(args.pull_host_key_alias)} -o UserKnownHostsFile={ps_quote(args.pull_known_hosts)} $source {ps_quote(target)}",
            "if($LASTEXITCODE -ne 0){throw ('client restore push failed rc='+$LASTEXITCODE)}",
            "[ordered]@{ok=$true;host=$env:COMPUTERNAME;sha256=$digest;bytes=(Get-Item -LiteralPath $source).Length;source=$source} | ConvertTo-Json -Compress",
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dispatch-state", type=Path, default=Path(_integrity_value('path_d91576ab5b73')))
    parser.add_argument("--restore-root", type=Path, default=Path(_integrity_value('path_c0ab81a72ace')))
    parser.add_argument("--endpoint", default=_integrity_value('endpoint_f5891d8ae959'))
    parser.add_argument(
        "--token-file",
        type=Path,
        default=Path("~workspace/.workspace/personal-pc-exec-token").expanduser(),
    )
    parser.add_argument("--pull-user", default="workspace")
    parser.add_argument("--pull-port", type=int, default=22111)
    parser.add_argument("--pull-key", default=_integrity_value('path_5164c4d20152'))
    parser.add_argument("--pull-known-hosts", default=_integrity_value('path_5164c4d20152'))
    parser.add_argument("--pull-host-key-alias", default="integrity-offhost")
    args = parser.parse_args()
    state = json.loads(args.dispatch_state.read_text(encoding="utf-8"))
    if state.get("protocol") != "integrity-memory-plane.p2-offhost-client.v1.state" or state.get("remote_host") != "client" or not all((state.get("checks") or {}).values()):
        raise RuntimeError("no independently verified client P2 state is available")
    run_uid = uuid.uuid4()
    run_root = args.restore_root / str(run_uid)
    run_root.mkdir(parents=True, mode=0o700)
    incoming = run_root / "client-capsule.part"
    if incoming.exists():
        raise RuntimeError("restore destination unexpectedly exists")
    remote = execute_remote(args.endpoint, args.token_file, push_command(state, incoming, args), timeout=180)
    if str(remote.get("host") or "").upper() != "client" or str(remote.get("sha256") or "").lower() != state["capsule_sha256"]:
        raise RuntimeError("client restore push receipt mismatch")
    final = run_root / "client-restored-capsule.tar.gz"
    os.replace(incoming, final)
    verification = verify_capsule(final, state["capsule_sha256"], state["inventory_sha256"])
    receipt = {
        "protocol": PROTOCOL + ".receipt",
        "run_uid": str(run_uid),
        "created_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "remote": {"host": remote["host"], "source": remote["source"], "sha256": remote["sha256"], "bytes": remote["bytes"]},
        "restored_path": str(final),
        **verification,
    }
    receipt_path = run_root / "restore-receipt.json"
    atomic_json(receipt_path, receipt, mode=0o400)
    print(json.dumps({**receipt, "receipt_path": str(receipt_path)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
