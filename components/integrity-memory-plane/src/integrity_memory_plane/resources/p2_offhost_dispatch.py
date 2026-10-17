#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Dispatch one verified P2 raw capsule to client and require independent readback."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from memory_plane_common import atomic_json, sha256_file
from offhost_windows_replica import SAFE_WINDOWS_ROOT, execute_remote, ps_quote


PROTOCOL = "integrity-memory-plane.p2-offhost-client.v1"


def load_export(path: Path, root: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("protocol") != "integrity-memory-plane.p2-offhost-export.v1.state":
        raise RuntimeError("untrusted P2 export state protocol")
    capsule = Path(str(value.get("path") or ""))
    resolved_root = root.resolve()
    if not capsule.is_file() or capsule.is_symlink() or resolved_root not in capsule.resolve().parents:
        raise RuntimeError("untrusted P2 export capsule path")
    if capsule.name != value.get("name") or sha256_file(capsule) != value.get("sha256") or capsule.stat().st_size != int(value.get("bytes") or -1):
        raise RuntimeError("P2 export state/capsule readback mismatch")
    return value


def remote_command(args: argparse.Namespace, capsule: dict[str, Any]) -> str:
    if not SAFE_WINDOWS_ROOT.fullmatch(args.remote_root) or ".." in args.remote_root.replace("/", "\\").split("\\"):
        raise RuntimeError("unsafe Windows P2 off-host root")
    source = f"{args.pull_user}@127.0.0.1:{capsule['path']}"
    parts = [
        "$ErrorActionPreference='Stop'",
        f"$root={ps_quote(args.remote_root)}",
        "New-Item -ItemType Directory -Force -Path $root | Out-Null",
        f"$final=Join-Path $root {ps_quote(str(capsule['name']))}",
        f"$expected={ps_quote(str(capsule['sha256']))}",
        f"$inventoryExpected={ps_quote(str(capsule['inventory_sha256']))}",
        f"$headExpected=[int64]{int(capsule['head_cursor'])}",
        f"$batchExpected=[int64]{int(capsule['batch_count'])}",
        f"$eventExpected=[int64]{int(capsule['event_count'])}",
        "$status='created'",
        "if(Test-Path -LiteralPath $final){$digest=(Get-FileHash -Algorithm SHA256 -LiteralPath $final).Hash.ToLowerInvariant();if($digest -ne $expected){throw 'existing client P2 capsule digest mismatch'};$status='already-present'}else{",
        "$part=$final+'.'+[guid]::NewGuid().ToString('N')+'.part'",
        f"& scp.exe -q -P {args.pull_port} -i {ps_quote(args.pull_key)} -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o HostKeyAlias={ps_quote(args.pull_host_key_alias)} -o UserKnownHostsFile={ps_quote(args.pull_known_hosts)} {ps_quote(source)} $part",
        "if($LASTEXITCODE -ne 0){throw ('scp failed rc='+$LASTEXITCODE)}",
        "$digest=(Get-FileHash -Algorithm SHA256 -LiteralPath $part).Hash.ToLowerInvariant()",
        "if($digest -ne $expected){Remove-Item -LiteralPath $part -Force;throw 'client P2 outer readback digest mismatch'}",
        "Move-Item -LiteralPath $part -Destination $final",
        "(Get-Item -LiteralPath $final).IsReadOnly=$true",
        "}",
        "$verify=Join-Path $root ('verify-'+[guid]::NewGuid().ToString('N'))",
        "New-Item -ItemType Directory -Path $verify | Out-Null",
        "try{",
        "$members=@(& tar.exe -tf $final);if($LASTEXITCODE -ne 0 -or $members.Count -lt 3){throw 'client P2 tar listing failed'}",
        "foreach($member in $members){if($member -notmatch '^(inventory\\.json|raw/[0-9]{20}-[0-9a-f]{64}\\.ndjson\\.gz|receipts/[0-9]{20}-[0-9a-f]{64}\\.receipt\\.json)$'){throw ('unsafe client P2 capsule member: '+$member)}}",
        "& tar.exe -xf $final -C $verify;if($LASTEXITCODE -ne 0){throw 'client P2 extraction failed'}",
        "$inventoryPath=Join-Path $verify 'inventory.json'",
        "$inventoryDigest=(Get-FileHash -Algorithm SHA256 -LiteralPath $inventoryPath).Hash.ToLowerInvariant()",
        "if($inventoryDigest -ne $inventoryExpected){throw 'client P2 inventory digest mismatch'}",
        "$inventory=Get-Content -Raw -LiteralPath $inventoryPath | ConvertFrom-Json",
        "if([int64]$inventory.head_cursor -ne $headExpected -or [int64]$inventory.batch_count -ne $batchExpected -or [int64]$inventory.event_count -ne $eventExpected){throw 'client P2 inventory counters mismatch'}",
        "$verified=0",
        "foreach($entry in @($inventory.files)){$relative=[string]$entry.path;if($relative -notmatch '^(raw|receipts)/'){throw 'client P2 inventory path rejected'};$path=Join-Path $verify ($relative -replace '/',[IO.Path]::DirectorySeparatorChar);if(-not (Test-Path -LiteralPath $path -PathType Leaf)){throw ('client P2 inventory file missing: '+$relative)};$item=Get-Item -LiteralPath $path;if([int64]$item.Length -ne [int64]$entry.bytes){throw ('client P2 file size mismatch: '+$relative)};$fileDigest=(Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant();if($fileDigest -ne [string]$entry.sha256){throw ('client P2 file digest mismatch: '+$relative)};$verified++}",
        "if($verified -ne (2*$batchExpected)){throw 'client P2 verified file count mismatch'}",
        "[ordered]@{ok=$true;status=$status;path=$final;sha256=$digest;bytes=(Get-Item -LiteralPath $final).Length;inventory_sha256=$inventoryDigest;head_cursor=$headExpected;batch_count=$batchExpected;event_count=$eventExpected;files_verified=$verified;host=$env:COMPUTERNAME} | ConvertTo-Json -Compress",
        "}finally{if(Test-Path -LiteralPath $verify){Remove-Item -LiteralPath $verify -Recurse -Force}}",
    ]
    return ";".join(parts)


def load_state(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    value = json.loads(path.read_text(encoding="utf-8"))
    return value if value.get("protocol") == PROTOCOL + ".state" else {}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--export-state", type=Path, default=Path(_integrity_value('path_a3114bdbc720')))
    parser.add_argument("--export-root", type=Path, default=Path(_integrity_value('path_806caa795eda')))
    parser.add_argument("--state", type=Path, default=Path(_integrity_value('path_d91576ab5b73')))
    parser.add_argument("--receipt-root", type=Path, default=Path(_integrity_value('path_aaa8aa64c11b')))
    parser.add_argument("--endpoint", default=_integrity_value('endpoint_f5891d8ae959'))
    parser.add_argument(
        "--token-file",
        type=Path,
        default=Path("~workspace/.workspace/personal-pc-exec-token").expanduser(),
    )
    parser.add_argument("--remote-root", default=_integrity_value('path_bed84c86fbe2'))
    parser.add_argument("--pull-user", default="workspace")
    parser.add_argument("--pull-port", type=int, default=22111)
    parser.add_argument("--pull-key", default=_integrity_value('path_5164c4d20152'))
    parser.add_argument("--pull-known-hosts", default=_integrity_value('path_5164c4d20152'))
    parser.add_argument("--pull-host-key-alias", default="integrity-offhost")
    parser.add_argument("--max-readback-age-seconds", type=int, default=1800)
    parser.add_argument("--force-readback", action="store_true")
    args = parser.parse_args()
    capsule = load_export(args.export_state, args.export_root)
    existing = load_state(args.state)
    now = datetime.now(timezone.utc)
    same = existing.get("capsule_sha256") == capsule["sha256"] and existing.get("remote_host") == "client"
    verified_at = datetime.fromisoformat(str(existing.get("verified_utc") or "1970-01-01T00:00:00+00:00").replace("Z", "+00:00"))
    if not args.force_readback and same and (now - verified_at).total_seconds() < args.max_readback_age_seconds:
        print(json.dumps({"protocol": PROTOCOL + ".receipt", "status": "noop", "head_cursor": capsule["head_cursor"], "capsule_sha256": capsule["sha256"]}, sort_keys=True))
        return 0
    remote = execute_remote(args.endpoint, args.token_file, remote_command(args, capsule), timeout=180)
    checks = {
        "remote_host_bound": str(remote.get("host") or "").upper() == "client",
        "outer_digest_readback": str(remote.get("sha256") or "").lower() == capsule["sha256"],
        "outer_size_readback": int(remote.get("bytes") or -1) == int(capsule["bytes"]),
        "inventory_digest_readback": str(remote.get("inventory_sha256") or "").lower() == capsule["inventory_sha256"],
        "semantic_counters_bound": (int(remote.get("head_cursor") or -1), int(remote.get("batch_count") or -1), int(remote.get("event_count") or -1)) == (int(capsule["head_cursor"]), int(capsule["batch_count"]), int(capsule["event_count"])),
        "all_inventory_files_readback": int(remote.get("files_verified") or -1) == 2 * int(capsule["batch_count"]),
    }
    if not all(checks.values()):
        raise RuntimeError("client P2 independent readback failed")
    verified_utc = now.isoformat().replace("+00:00", "Z")
    state = {
        "protocol": PROTOCOL + ".state",
        "verified_utc": verified_utc,
        "capsule_sha256": capsule["sha256"],
        "inventory_sha256": capsule["inventory_sha256"],
        "head_cursor": capsule["head_cursor"],
        "batch_count": capsule["batch_count"],
        "event_count": capsule["event_count"],
        "remote_host": remote["host"],
        "remote_path": remote["path"],
        "checks": checks,
        "production_authority": False,
        "memory_grants_authority": False,
    }
    args.state.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    atomic_json(args.state, state, mode=0o400)
    args.receipt_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    receipt_path = args.receipt_root / f"client-head-{int(capsule['head_cursor']):020d}-{capsule['sha256'][:16]}.json"
    atomic_json(receipt_path, {"protocol": PROTOCOL + ".receipt", "status": "pass", **state, "remote_status": remote.get("status")}, mode=0o400)
    print(json.dumps({"protocol": PROTOCOL + ".receipt", "status": "pass", **state, "remote_status": remote.get("status"), "receipt_path": str(receipt_path)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
