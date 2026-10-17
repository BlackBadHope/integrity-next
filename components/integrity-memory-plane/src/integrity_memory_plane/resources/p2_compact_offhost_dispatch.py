#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Pull only missing compact digest objects to physical client and read them back."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import datetime as dt
import json
import re
from pathlib import Path
from typing import Any

from memory_plane_common import atomic_json, canonical_json, sha256_bytes, sha256_file
from offhost_windows_replica import SAFE_WINDOWS_ROOT, execute_remote, ps_quote


PROTOCOL = "integrity-memory-plane.p2-compact-offhost-client.v1"
EXPORT_PROTOCOL = "integrity-memory-plane.p2-compact-offhost-export.v1"
RELATIVE = re.compile(r"^objects/sha256/[0-9a-f]{2}/[0-9a-f]{64}$")


def load_export(state_path: Path, export_root: Path) -> dict[str, Any]:
    state = json.loads(state_path.read_text(encoding="utf-8"))
    if state.get("protocol") != EXPORT_PROTOCOL + ".state" or state.get("production_authority") is not False:
        raise RuntimeError("untrusted compact export state")
    inventory_path = Path(str(state.get("inventory_path") or ""))
    if not inventory_path.is_file() or inventory_path.is_symlink() or export_root.resolve() not in inventory_path.resolve().parents:
        raise RuntimeError("untrusted compact inventory path")
    if sha256_file(inventory_path) != str(state.get("inventory_sha256") or ""):
        raise RuntimeError("compact inventory digest mismatch")
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    if inventory.get("protocol") != EXPORT_PROTOCOL + ".inventory" or inventory.get("production_authority") is not False:
        raise RuntimeError("compact inventory protocol/authority mismatch")
    if str(inventory.get("manifest_head_sha256") or "") != str(state.get("manifest_head_sha256") or ""):
        raise RuntimeError("compact inventory head mismatch")
    for entry in inventory.get("objects") or []:
        relative = str(entry.get("relative") or "")
        if not RELATIVE.fullmatch(relative):
            raise RuntimeError("compact inventory relative path rejected")
        path = export_root / relative
        if not path.is_file() or path.is_symlink() or sha256_file(path) != entry.get("sha256") or path.stat().st_size != int(entry.get("bytes") or -1):
            raise RuntimeError(f"compact staged object readback mismatch: {relative}")
    return {"state": state, "inventory": inventory, "inventory_path": inventory_path}


def remote_command(args: argparse.Namespace, exported: dict[str, Any]) -> str:
    if not SAFE_WINDOWS_ROOT.fullmatch(args.remote_root) or ".." in args.remote_root.replace("/", "\\").split("\\"):
        raise RuntimeError("unsafe compact Windows root")
    state = exported["state"]
    inventory_source = f"{args.pull_user}@127.0.0.1:{exported['inventory_path']}"
    source_root = str(state["export_root"]).rstrip("/")
    parts = [
        "$ErrorActionPreference='Stop'",
        f"$root={ps_quote(args.remote_root)}",
        f"$inventoryExpected={ps_quote(str(state['inventory_sha256']))}",
        f"$headExpected={ps_quote(str(state['manifest_head_sha256']))}",
        f"$eventExpected=[int64]{int(state['event_count'])}",
        f"$objectExpected=[int64]{int(state['object_count'])}",
        f"$sourceRoot={ps_quote(source_root)}",
        "New-Item -ItemType Directory -Force -Path $root | Out-Null",
        "$heads=Join-Path $root 'heads';New-Item -ItemType Directory -Force -Path $heads | Out-Null",
        "$inventoryFinal=Join-Path $heads ($inventoryExpected+'.json')",
        "$inventoryPart=$inventoryFinal+'.'+[guid]::NewGuid().ToString('N')+'.part'",
        f"& scp.exe -q -P {args.pull_port} -i {ps_quote(args.pull_key)} -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o HostKeyAlias={ps_quote(args.pull_host_key_alias)} -o UserKnownHostsFile={ps_quote(args.pull_known_hosts)} {ps_quote(inventory_source)} $inventoryPart",
        "if($LASTEXITCODE -ne 0){throw ('compact inventory scp failed rc='+$LASTEXITCODE)}",
        "$inventoryDigest=(Get-FileHash -Algorithm SHA256 -LiteralPath $inventoryPart).Hash.ToLowerInvariant()",
        "if($inventoryDigest -ne $inventoryExpected){Remove-Item -LiteralPath $inventoryPart -Force;throw 'compact inventory readback digest mismatch'}",
        "$inventory=Get-Content -Raw -LiteralPath $inventoryPart|ConvertFrom-Json",
        "if([string]$inventory.manifest_head_sha256 -ne $headExpected -or [int64]$inventory.event_count -ne $eventExpected -or @($inventory.objects).Count -ne $objectExpected){throw 'compact inventory semantic counters mismatch'}",
        "$transferred=0;$reused=0;$bytesTransferred=[int64]0;$verified=0",
        "foreach($entry in @($inventory.objects)){$relative=[string]$entry.relative;if($relative -notmatch '^objects/sha256/[0-9a-f]{2}/[0-9a-f]{64}$'){throw ('compact relative path rejected: '+$relative)};$expected=[string]$entry.sha256;if($relative.Substring($relative.Length-64) -ne $expected){throw 'compact path/digest mismatch'};$windowsRelative=$relative -replace '/', [IO.Path]::DirectorySeparatorChar;$final=Join-Path $root $windowsRelative;$parent=Split-Path -Parent $final;New-Item -ItemType Directory -Force -Path $parent|Out-Null;if(Test-Path -LiteralPath $final){$item=Get-Item -LiteralPath $final;$digest=(Get-FileHash -Algorithm SHA256 -LiteralPath $final).Hash.ToLowerInvariant();if($digest -ne $expected -or [int64]$item.Length -ne [int64]$entry.bytes){throw ('existing compact object mismatch: '+$relative)};$reused++}else{$part=$final+'.'+[guid]::NewGuid().ToString('N')+'.part';$source=$sourceRoot+'/'+$relative;$remoteSource=" + ps_quote(args.pull_user + "@127.0.0.1:") + "+$source;& scp.exe -q -P " + str(args.pull_port) + " -i " + ps_quote(args.pull_key) + " -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o HostKeyAlias=" + ps_quote(args.pull_host_key_alias) + " -o UserKnownHostsFile=" + ps_quote(args.pull_known_hosts) + " $remoteSource $part;if($LASTEXITCODE -ne 0){throw ('compact object scp failed rc='+$LASTEXITCODE+': '+$relative)};$item=Get-Item -LiteralPath $part;$digest=(Get-FileHash -Algorithm SHA256 -LiteralPath $part).Hash.ToLowerInvariant();if($digest -ne $expected -or [int64]$item.Length -ne [int64]$entry.bytes){Remove-Item -LiteralPath $part -Force;throw ('compact transfer readback mismatch: '+$relative)};Move-Item -LiteralPath $part -Destination $final;(Get-Item -LiteralPath $final).IsReadOnly=$true;$transferred++;$bytesTransferred+=[int64]$entry.bytes};$finalDigest=(Get-FileHash -Algorithm SHA256 -LiteralPath $final).Hash.ToLowerInvariant();if($finalDigest -ne $expected){throw ('compact final readback mismatch: '+$relative)};$verified++}",
        "if($verified -ne $objectExpected){throw 'compact verified object count mismatch'}",
        "if(Test-Path -LiteralPath $inventoryFinal){$existing=(Get-FileHash -Algorithm SHA256 -LiteralPath $inventoryFinal).Hash.ToLowerInvariant();if($existing -ne $inventoryExpected){throw 'existing compact head inventory mismatch'};Remove-Item -LiteralPath $inventoryPart -Force}else{Move-Item -LiteralPath $inventoryPart -Destination $inventoryFinal;(Get-Item -LiteralPath $inventoryFinal).IsReadOnly=$true}",
        "[ordered]@{ok=$true;host=$env:COMPUTERNAME;root=$root;inventory_sha256=$inventoryDigest;manifest_head_sha256=$headExpected;event_count=$eventExpected;objects_verified=$verified;objects_transferred=$transferred;objects_reused=$reused;bytes_transferred=$bytesTransferred}|ConvertTo-Json -Compress",
    ]
    return ";".join(parts)


def dispatch(args: argparse.Namespace) -> dict[str, Any]:
    exported = load_export(args.export_state, args.export_root)
    remote = execute_remote(args.endpoint, args.token_file, remote_command(args, exported), timeout=300)
    state = exported["state"]
    checks = {
        "remote_host_bound": str(remote.get("host") or "").upper() == "client",
        "inventory_digest_readback": str(remote.get("inventory_sha256") or "").lower() == str(state["inventory_sha256"]),
        "manifest_head_bound": str(remote.get("manifest_head_sha256") or "").lower() == str(state["manifest_head_sha256"]),
        "event_count_bound": int(remote.get("event_count") or -1) == int(state["event_count"]),
        "all_objects_readback": int(remote.get("objects_verified") or -1) == int(state["object_count"]),
        "transfer_accounting": int(remote.get("objects_transferred") or 0) + int(remote.get("objects_reused") or 0) == int(state["object_count"]),
    }
    if not all(checks.values()):
        raise RuntimeError(f"compact client readback gate failed: {checks}")
    now = dt.datetime.now(dt.UTC).isoformat()
    persisted = {
        "protocol": PROTOCOL + ".state",
        "verified_utc": now,
        "inventory_sha256": state["inventory_sha256"],
        "manifest_head_sha256": state["manifest_head_sha256"],
        "event_count": int(state["event_count"]),
        "object_count": int(state["object_count"]),
        "remote_host": remote["host"],
        "remote_root": remote["root"],
        "checks": checks,
        "production_authority": False,
        "memory_grants_authority": False,
    }
    args.state.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    atomic_json(args.state, persisted, mode=0o400)
    receipt = {
        "protocol": PROTOCOL + ".receipt",
        "status": "PASS",
        "created_utc": now,
        **persisted,
        "objects_transferred": int(remote.get("objects_transferred") or 0),
        "objects_reused": int(remote.get("objects_reused") or 0),
        "bytes_transferred": int(remote.get("bytes_transferred") or 0),
        "incremental_physical_offhost": True,
    }
    receipt["evidence_sha256"] = sha256_bytes(canonical_json(receipt))
    args.receipt_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = args.receipt_root / f"client-compact-{receipt['manifest_head_sha256'][:16]}-{receipt['evidence_sha256'][:16]}.json"
    atomic_json(path, receipt, mode=0o400)
    return {**receipt, "receipt_path": str(path)}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--export-state", type=Path, default=Path(_integrity_value('path_842e373e982a')))
    parser.add_argument("--export-root", type=Path, default=Path(_integrity_value('path_0b6cc4f54ed3')))
    parser.add_argument("--state", type=Path, default=Path(_integrity_value('path_0142cbe1b8f7')))
    parser.add_argument("--receipt-root", type=Path, default=Path(_integrity_value('path_02ebb2142aa5')))
    parser.add_argument("--endpoint", default=_integrity_value('endpoint_f5891d8ae959'))
    parser.add_argument(
        "--token-file",
        type=Path,
        default=Path("~workspace/.workspace/personal-pc-exec-token").expanduser(),
    )
    parser.add_argument("--remote-root", default=_integrity_value('path_16db7d64e654'))
    parser.add_argument("--pull-user", default="workspace")
    parser.add_argument("--pull-port", type=int, default=22111)
    parser.add_argument("--pull-key", default=_integrity_value('path_5164c4d20152'))
    parser.add_argument("--pull-known-hosts", default=_integrity_value('path_5164c4d20152'))
    parser.add_argument("--pull-host-key-alias", default="integrity-offhost")
    return parser.parse_args()


def main() -> int:
    print(json.dumps(dispatch(parse_args()), ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
