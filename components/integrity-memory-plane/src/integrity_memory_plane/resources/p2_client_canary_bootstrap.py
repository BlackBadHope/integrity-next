#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bootstrap a loopback-only client NATS canary without claiming a quorum gate."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import grp
import json
import os
import pwd
import tempfile
import time
from pathlib import Path
from typing import Any

from memory_plane_common import atomic_json, canonical_json, sha256_bytes, sha256_file
from offhost_windows_replica import execute_remote, ps_quote


PROTOCOL = "integrity-memory-plane.p2-client-canary.v1"
ARCHIVE_SHA256 = _integrity_value('pin_80e56ca384f1')
ARCHIVE_URL = _integrity_value('endpoint_7ac78b8f0bd5')
REQUIRED_ENV = ("NATS_CANARY_USER", "NATS_CANARY_PASSWORD", "NATS_CLUSTER_USER", "NATS_CLUSTER_PASSWORD")


def load_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="ascii").splitlines():
        key, separator, value = raw.strip().partition("=")
        if not separator or not key or not value or key in values:
            raise RuntimeError("invalid regional canary secret shape")
        values[key] = value
    if set(values) != set(REQUIRED_ENV):
        raise RuntimeError("regional canary secret keys differ from contract")
    return values


def quote(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def render_linux_config(values: dict[str, str]) -> str:
    return f'''server_name: integrity-p2-canary-linux-1
host: "127.0.0.1"
port: 14222
http_port: 18232
max_payload: 8MB
write_deadline: "2s"
authorization {{
  user: {quote(values["NATS_CANARY_USER"])}
  password: {quote(values["NATS_CANARY_PASSWORD"])}
  timeout: 2
}}
jetstream {{
  store_dir: "/data"
  max_memory_store: 256MB
  max_file_store: 5GB
  sync_interval: always
  strict: true
}}
cluster {{
  name: "INTEGRITY_P2_REGIONAL_CANARY"
  host: "127.0.0.1"
  port: 16222
  authorization {{
    user: {quote(values["NATS_CLUSTER_USER"])}
    password: {quote(values["NATS_CLUSTER_PASSWORD"])}
    timeout: 2
  }}
  routes: [ "nats-route://{values["NATS_CLUSTER_USER"]}:{values["NATS_CLUSTER_PASSWORD"]}@127.0.0.1:26223" ]
}}
debug: false
trace: false
logtime: true
'''


def atomic_text(path: Path, value: str, mode: int, gid: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        os.fchown(descriptor, 0, gid)
        with os.fdopen(descriptor, "w", encoding="ascii") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, mode)
        os.chown(path, 0, gid)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def wait_file(path: Path, timeout: float = 30) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.is_file() and path.stat().st_size > 0:
            return
        time.sleep(0.25)
    raise RuntimeError("client did not stage the regional canary secret")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", default=_integrity_value('endpoint_f5891d8ae959'))
    parser.add_argument(
        "--token-file",
        type=Path,
        default=Path("~workspace/.workspace/personal-pc-exec-token").expanduser(),
    )
    parser.add_argument("--installer", type=Path, default=Path(__file__).with_name("p2_client_canary_install.ps1"))
    parser.add_argument(
        "--staging-root",
        type=Path,
        default=Path("~workspace/.cache/integrity-p2-regional").expanduser(),
    )
    parser.add_argument("--linux-host", default="integrity-offhost")
    parser.add_argument("--linux-host-key-alias", default="integrity-offhost")
    parser.add_argument("--secret", type=Path, default=Path("/etc/integrity-memory-p2/regional-canary.env"))
    parser.add_argument("--config", type=Path, default=Path("/etc/integrity-memory-p2/regional-canary-nats.conf"))
    parser.add_argument("--receipt", type=Path, default=Path(_integrity_value('path_221cb698ccb4')))
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError("client canary bootstrap must run as root")
    runtime_gid = grp.getgrnam("integrity-p2-regional-canary").gr_gid
    worker = pwd.getpwnam("workspace")
    args.staging_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chown(args.staging_root, worker.pw_uid, worker.pw_gid)
    os.chmod(args.staging_root, 0o700)
    staged = args.staging_root / "client-regional-canary.env"
    try:
        staged.unlink()
    except FileNotFoundError:
        pass
    preamble = ";".join(
        (
            "$LinuxSecretStage=" + ps_quote(str(staged)),
            "$ExpectedArchiveSha256=" + ps_quote(ARCHIVE_SHA256),
            "$ArchiveUrl=" + ps_quote(ARCHIVE_URL),
            "$LinuxHost=" + ps_quote(args.linux_host),
            "$LinuxHostKeyAlias=" + ps_quote(args.linux_host_key_alias),
        )
    ) + ";"
    remote = execute_remote(args.endpoint, args.token_file, preamble + args.installer.read_text(encoding="utf-8"), timeout=240)
    wait_file(staged)
    values = load_env(staged)
    existing = load_env(args.secret) if args.secret.is_file() else None
    if existing is not None and existing != values:
        raise RuntimeError("client canary secret differs from the established Linux secret")
    atomic_text(args.secret, "".join(f"{key}={values[key]}\n" for key in REQUIRED_ENV), 0o640, runtime_gid)
    # The pinned NATS container runs as uid/gid 65532.  Give only that numeric
    # runtime group read access to the rendered config; the shared secret source
    # remains with the Integrity runtime group.
    atomic_text(args.config, render_linux_config(values), 0o640, 65532)
    staged.unlink()
    checks = {
        "remote_host_bound": str(remote.get("host") or "").upper() == "client",
        "official_archive_digest": remote.get("archive_sha256") == ARCHIVE_SHA256,
        "binary_version": remote.get("binary_version") == "nats-server: v2.11.8",
        "node_task_running": remote.get("node_task") == "Running",
        "tunnel_task_running": remote.get("tunnel_task") == "Running",
        "node_loopback_port": remote.get("node_port") is True,
        "route_loopback_port": remote.get("route_port") is True,
        "loopback_only": remote.get("bind_scope") == "loopback-only",
        "secret_staging_removed": not staged.exists(),
    }
    if not all(checks.values()):
        raise RuntimeError("client canary bootstrap checks failed: " + ",".join(key for key, value in checks.items() if not value))
    receipt = {
        "protocol": PROTOCOL + ".receipt",
        "status": "PASS",
        "checks": checks,
        "remote_host": "client",
        "nats_server_name": "integrity-p2-client-1",
        "linux_route_forward_observed_before_linux_node": remote.get("linux_route_forward") is True,
        "host_domains_proven": 1,
        "regional_gate_passed": False,
        "production_ack_allowed": False,
        "production_authority": False,
        "memory_grants_authority": False,
        "secret_file": {"path": str(args.secret), "sha256": sha256_file(args.secret), "mode": "0640", "values_exposed": False},
        "config_file": {"path": str(args.config), "sha256": sha256_file(args.config)},
    }
    receipt["evidence_sha256"] = sha256_bytes(canonical_json(receipt))
    atomic_json(args.receipt, receipt, mode=0o440)
    print(json.dumps({**receipt, "secret_file": {**receipt["secret_file"], "sha256": "[redacted]"}}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
