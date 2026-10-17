#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Replicate the verified Action Log recovery chain to a physical Windows host.

The Windows host pulls one immutable capsule through an already authenticated
reverse SSH lane.  The local ACK advances only after Windows independently
reads the completed file and returns the expected SHA-256 digest.
"""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import datetime as dt
import gzip
import hashlib
import json
import os
import pwd
import re
import shutil
import tarfile
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from memory_plane_common import atomic_json, canonical_json, exclusive_lock, safe_copy, sha256_file


PROTOCOL = "integrity-memory-plane.offhost-windows.v1"
TAIL_PROTOCOL = "integrity-memory-plane.tail-segment.v1"
SAFE_WINDOWS_ROOT = re.compile(r"^[A-Za-z]:\\[^\r\n]*$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--full-root", type=Path, default=Path(_integrity_value('path_4e44c119019c')))
    parser.add_argument("--tail-root", type=Path, default=Path(_integrity_value('path_f99c29cce43c')))
    parser.add_argument("--local-tail-root", type=Path, default=Path("/var/backups/integrity-memory-plane/action-log/tail"))
    parser.add_argument("--export-root", type=Path, default=Path("/run/integrity-memory-plane/offhost-export"))
    parser.add_argument("--state", type=Path, default=Path(_integrity_value('path_bacb81ae4ea5')))
    parser.add_argument("--evidence-root", type=Path, default=Path(_integrity_value('path_29857010143f')))
    parser.add_argument("--tail-lock", type=Path, default=Path("/run/lock/integrity-memory-plane-tail.lock"))
    parser.add_argument("--replica-lock", type=Path, default=Path("/run/lock/integrity-memory-plane-offhost.lock"))
    parser.add_argument("--endpoint", default=_integrity_value('endpoint_f5891d8ae959'))
    parser.add_argument(
        "--token-file",
        type=Path,
        default=Path("~workspace/.workspace/personal-pc-exec-token").expanduser(),
    )
    parser.add_argument("--remote-root", default=_integrity_value('path_83bf3efd1843'))
    parser.add_argument("--pull-user", default="workspace")
    parser.add_argument("--pull-port", type=int, default=22111)
    parser.add_argument("--pull-key", default=_integrity_value('path_5164c4d20152'))
    parser.add_argument("--pull-known-hosts", default=_integrity_value('path_5164c4d20152'))
    parser.add_argument("--pull-host-key-alias", default="integrity-offhost")
    parser.add_argument("--export-user", default="workspace")
    parser.add_argument("--keep", type=int, default=7)
    parser.add_argument("--force-readback", action="store_true")
    return parser.parse_args()


def require_regular(path: Path, root: Path) -> None:
    if not path.is_file() or path.is_symlink() or root.resolve() not in path.resolve().parents:
        raise RuntimeError(f"untrusted recovery artifact path: {path}")


def latest_full(root: Path) -> tuple[Path, Path, dict[str, Any]]:
    for receipt_path in sorted(root.glob("full-backup-*.json"), reverse=True):
        require_regular(receipt_path, root)
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        archive_meta = receipt.get("archive") or {}
        archive = root / str(archive_meta.get("name") or "")
        if archive.is_file() and not archive.is_symlink() and sha256_file(archive) == archive_meta.get("sha256"):
            require_regular(archive, root)
            return archive, receipt_path, receipt
    raise RuntimeError("no digest-valid full backup is available")


def verify_tail_payload(payload: Path, manifest: dict[str, Any]) -> None:
    expected = manifest.get("payload") or {}
    if sha256_file(payload) != expected.get("sha256") or payload.stat().st_size != int(expected.get("bytes") or -1):
        raise RuntimeError(f"tail payload digest/size mismatch: {payload}")
    with gzip.open(payload, "rb") as handle:
        lines = handle.read().splitlines()
    if not lines:
        raise RuntimeError("empty tail payload")
    header = json.loads(lines[0])
    if header.get("protocol") != TAIL_PROTOCOL or header.get("columns") != manifest.get("columns"):
        raise RuntimeError("tail payload header mismatch")
    digest = hashlib.sha256()
    for line in lines[1:]:
        row = json.loads(line)
        encoded = canonical_json(row)
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    if len(lines) - 1 != int(manifest.get("event_count") or -1) or digest.hexdigest() != manifest.get("row_sha256"):
        raise RuntimeError("tail payload row verification failed")


def verified_source(full_root: Path, tail_root: Path) -> dict[str, Any]:
    archive, full_receipt_path, full_receipt = latest_full(full_root)
    state_path = tail_root / "state.json"
    require_regular(state_path, tail_root)
    tail_state = json.loads(state_path.read_text(encoding="utf-8"))
    if tail_state.get("protocol") != TAIL_PROTOCOL + ".state":
        raise RuntimeError("tail state protocol mismatch")
    previous = ""
    previous_last = 0
    tail_files: list[Path] = []
    manifests = sorted(tail_root.glob("events-*.manifest.json"))
    for manifest_path in manifests:
        require_regular(manifest_path, tail_root)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        first = int(manifest.get("first_cursor") or 0)
        last = int(manifest.get("last_cursor") or 0)
        if manifest.get("protocol") != TAIL_PROTOCOL:
            raise RuntimeError("tail manifest protocol mismatch")
        if str(manifest.get("previous_manifest_sha256") or "") != previous:
            raise RuntimeError("tail manifest hash-chain mismatch")
        if previous_last and first != previous_last + 1:
            raise RuntimeError("tail cursor chain is not contiguous")
        if first < 1 or last < first:
            raise RuntimeError("invalid tail cursor range")
        payload = tail_root / str((manifest.get("payload") or {}).get("name") or "")
        require_regular(payload, tail_root)
        verify_tail_payload(payload, manifest)
        previous = sha256_file(manifest_path)
        previous_last = last
        tail_files.extend((manifest_path, payload))
    archived_cursor = int(tail_state.get("archived_cursor") or 0)
    if not manifests or previous != tail_state.get("previous_manifest_sha256") or previous_last != archived_cursor:
        raise RuntimeError("tail state does not bind the verified chain tip")
    return {
        "full_archive": archive,
        "full_receipt_path": full_receipt_path,
        "full_receipt": full_receipt,
        "full_cursor": int((full_receipt.get("snapshot") or {}).get("event_cursor") or 0),
        "tail_state_path": state_path,
        "tail_state": tail_state,
        "tail_files": tail_files,
        "tail_cursor": archived_cursor,
        "tail_manifest_sha256": previous,
    }


def build_capsule(source: dict[str, Any], export_root: Path, export_user: str) -> dict[str, Any]:
    account = pwd.getpwnam(export_user)
    export_root.parent.mkdir(parents=True, exist_ok=True, mode=0o710)
    os.chown(export_root.parent, 0, account.pw_gid)
    os.chmod(export_root.parent, 0o710)
    export_root.mkdir(parents=True, exist_ok=True, mode=0o710)
    os.chown(export_root, 0, account.pw_gid)
    os.chmod(export_root, 0o710)
    full_digest = sha256_file(source["full_archive"])
    name = (
        f"action-log-recovery-full-{source['full_cursor']}-tail-{source['tail_cursor']}-"
        f"{full_digest[:12]}-{source['tail_manifest_sha256'][:12]}.tar.gz"
    )
    with tempfile.TemporaryDirectory(prefix="offhost-capsule-", dir=export_root) as temporary:
        stage = Path(temporary) / "capsule"
        (stage / "full").mkdir(parents=True, mode=0o700)
        (stage / "tail").mkdir(mode=0o700)
        selected = [source["full_archive"], source["full_receipt_path"]]
        for path in selected:
            shutil.copy2(path, stage / "full" / path.name)
        for path in source["tail_files"]:
            shutil.copy2(path, stage / "tail" / path.name)
        shutil.copy2(source["tail_state_path"], stage / "tail" / "state.json")
        files = []
        for path in sorted(stage.rglob("*")):
            if path.is_file():
                files.append({"path": path.relative_to(stage).as_posix(), "bytes": path.stat().st_size, "sha256": sha256_file(path)})
        inventory = {
            "protocol": PROTOCOL + ".capsule",
            "source_sealed_utc": str(source["tail_state"].get("updated_utc") or ""),
            "full_cursor": source["full_cursor"],
            "full_archive_sha256": full_digest,
            "tail_cursor": source["tail_cursor"],
            "tail_manifest_sha256": source["tail_manifest_sha256"],
            "files": files,
        }
        atomic_json(stage / "inventory.json", inventory)
        temporary_archive = Path(temporary) / name
        with temporary_archive.open("wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=6) as compressed:
                with tarfile.open(fileobj=compressed, mode="w") as bundle:
                    for path in sorted(stage.rglob("*")):
                        info = bundle.gettarinfo(str(path), arcname=path.relative_to(stage).as_posix())
                        info.uid = 0
                        info.gid = 0
                        info.uname = ""
                        info.gname = ""
                        info.mtime = 0
                        if path.is_file():
                            with path.open("rb") as handle:
                                bundle.addfile(info, handle)
                        else:
                            bundle.addfile(info)
        target = export_root / name
        digest = safe_copy(temporary_archive, target, mode=0o400)
    os.chown(target, account.pw_uid, account.pw_gid)
    os.chmod(target, 0o400)
    return {"path": target, "name": name, "bytes": target.stat().st_size, "sha256": digest, "inventory": inventory}


def ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def remote_pull_command(args: argparse.Namespace, capsule: dict[str, Any]) -> str:
    if not SAFE_WINDOWS_ROOT.fullmatch(args.remote_root) or ".." in args.remote_root.replace("/", "\\").split("\\"):
        raise RuntimeError("unsafe Windows off-host root")
    source = f"{args.pull_user}@127.0.0.1:{capsule['path']}"
    parts = [
        "$ErrorActionPreference='Stop'",
        f"$root={ps_quote(args.remote_root)}",
        "New-Item -ItemType Directory -Force -Path $root | Out-Null",
        f"$final=Join-Path $root {ps_quote(capsule['name'])}",
        f"$expected={ps_quote(capsule['sha256'])}",
        "$status='created'",
        "if(Test-Path -LiteralPath $final){$digest=(Get-FileHash -Algorithm SHA256 -LiteralPath $final).Hash.ToLowerInvariant();if($digest -ne $expected){throw 'existing offhost capsule digest mismatch'};$status='already-present'}else{",
        "$part=$final+'.'+[guid]::NewGuid().ToString('N')+'.part'",
        f"& scp.exe -q -P {args.pull_port} -i {ps_quote(args.pull_key)} -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o HostKeyAlias={ps_quote(args.pull_host_key_alias)} -o UserKnownHostsFile={ps_quote(args.pull_known_hosts)} {ps_quote(source)} $part",
        "if($LASTEXITCODE -ne 0){throw ('scp failed rc='+$LASTEXITCODE)}",
        "$digest=(Get-FileHash -Algorithm SHA256 -LiteralPath $part).Hash.ToLowerInvariant()",
        "if($digest -ne $expected){Remove-Item -LiteralPath $part -Force;throw 'offhost readback digest mismatch'}",
        "Move-Item -LiteralPath $part -Destination $final",
        "(Get-Item -LiteralPath $final).IsReadOnly=$true",
        "}",
        "[ordered]@{ok=$true;status=$status;path=$final;sha256=$digest;bytes=(Get-Item -LiteralPath $final).Length;host=$env:COMPUTERNAME} | ConvertTo-Json -Compress",
    ]
    return ";".join(parts)


def parse_exec_wrapper(wrapper: dict[str, Any]) -> dict[str, Any]:
    exit_code = wrapper.get("exit_code")
    if (
        wrapper.get("ok") is not True
        or wrapper.get("timed_out") is not False
        or isinstance(exit_code, bool)
        or not isinstance(exit_code, int)
        or exit_code != 0
    ):
        raise RuntimeError(f"off-host pull failed: {str(wrapper.get('stderr') or wrapper.get('error') or '')[-1000:]}")
    result: dict[str, Any] | None = None
    for line in reversed(str(wrapper.get("stdout") or "").splitlines()):
        try:
            candidate = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(candidate, dict):
            result = candidate
            break
    if result is None or result.get("ok") is not True:
        raise RuntimeError("off-host pull returned no bound JSON result")
    return result


def execute_remote(endpoint: str, token_file: Path, command: str, timeout: int = 180) -> dict[str, Any]:
    parsed = urllib.parse.urlparse(endpoint)
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or not parsed.port:
        raise RuntimeError("off-host exec endpoint must be an explicit loopback HTTP port")
    token_lines = token_file.read_text(encoding="ascii").splitlines()
    if len([line for line in token_lines if line.strip()]) != 1:
        raise RuntimeError("off-host exec token file shape mismatch")
    token = next(line.strip() for line in token_lines if line.strip())
    request = urllib.request.Request(
        endpoint.rstrip("/") + "/exec",
        data=json.dumps({"command": command}).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Integrity-Token": token},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise RuntimeError("off-host exec response exceeded bound")
    wrapper = json.loads(raw)
    if not isinstance(wrapper, dict):
        raise RuntimeError("off-host exec response is not an object")
    return parse_exec_wrapper(wrapper)


def load_replica_state(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    value = json.loads(path.read_text(encoding="utf-8"))
    return value if value.get("protocol") == PROTOCOL + ".state" else {}


def prune_exports(root: Path, keep: int) -> None:
    if keep < 1:
        return
    for path in sorted(root.glob("action-log-recovery-*.tar.gz"), reverse=True)[keep:]:
        path.unlink()


def main() -> int:
    args = parse_args()
    args.evidence_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    args.state.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with exclusive_lock(args.replica_lock):
        with exclusive_lock(args.tail_lock):
            source = verified_source(args.full_root, args.tail_root)
            existing = load_replica_state(args.state)
            signature = {
                "full_archive_sha256": sha256_file(source["full_archive"]),
                "tail_cursor": source["tail_cursor"],
                "tail_manifest_sha256": source["tail_manifest_sha256"],
            }
            if not args.force_readback and all(existing.get(key) == value for key, value in signature.items()):
                print(json.dumps({"protocol": PROTOCOL + ".receipt", "status": "noop", **signature}, sort_keys=True))
                return 0
            capsule = build_capsule(source, args.export_root, args.export_user)
        remote = execute_remote(args.endpoint, args.token_file, remote_pull_command(args, capsule))
        checks = {
            "remote_host_bound": str(remote.get("host") or "").upper() == "client",
            "remote_digest_readback": str(remote.get("sha256") or "").lower() == capsule["sha256"],
            "remote_size_readback": int(remote.get("bytes") or -1) == capsule["bytes"],
        }
        if not all(checks.values()):
            raise RuntimeError("off-host independent readback failed")
        now = dt.datetime.now(dt.UTC).isoformat()
        state = {
            "protocol": PROTOCOL + ".state",
            "updated_utc": now,
            **signature,
            "capsule_name": capsule["name"],
            "capsule_sha256": capsule["sha256"],
            "remote_host": remote["host"],
            "remote_path": remote["path"],
            "remote_status": remote.get("status"),
        }
        atomic_json(args.state, state)
        with exclusive_lock(args.tail_lock):
            current_tail = json.loads((args.tail_root / "state.json").read_text(encoding="utf-8"))
            current_tail["offhost_ack_cursor"] = max(int(current_tail.get("offhost_ack_cursor") or 0), source["tail_cursor"])
            current_tail["offhost_ack_host"] = "client"
            current_tail["offhost_ack_capsule_sha256"] = capsule["sha256"]
            current_tail["offhost_ack_utc"] = now
            atomic_json(args.tail_root / "state.json", current_tail)
            safe_copy(args.tail_root / "state.json", args.local_tail_root / "state.json", mode=0o400)
        stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
        receipt = {
            "protocol": PROTOCOL + ".receipt",
            "status": "pass",
            "created_utc": now,
            "checks": checks,
            "source": {"full_cursor": source["full_cursor"], "tail_cursor": source["tail_cursor"], **signature},
            "capsule": {key: capsule[key] for key in ("name", "bytes", "sha256")},
            "remote": remote,
            "offhost_ack_cursor": source["tail_cursor"],
        }
        receipt_path = args.evidence_root / f"offhost-windows-{stamp}-cursor-{source['tail_cursor']}.json"
        atomic_json(receipt_path, receipt)
        prune_exports(args.export_root, args.keep)
        print(json.dumps({**receipt, "receipt_path": str(receipt_path)}, ensure_ascii=False, sort_keys=True))
        return 0


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
