#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Create P2 shadow credentials once and emit a content-free receipt."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import hashlib
import json
import os
import secrets
from pathlib import Path

from memory_plane_common import atomic_json, sha256_file


PROTOCOL = "integrity-memory-plane.p2-shadow-bootstrap.v1"


def write_once(path: Path, content: str) -> str:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        if not path.is_file() or path.is_symlink() or path.stat().st_mode & 0o077:
            raise RuntimeError(f"unsafe existing secret file: {path}")
        return "existing"
    with os.fdopen(descriptor, "w", encoding="ascii") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(path, 0o600)
    directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return "created"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config-root", type=Path, default=Path("/etc/integrity-memory-p2"))
    parser.add_argument("--receipt-root", type=Path, default=Path(_integrity_value('path_3cdcb28c5cbe')))
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError("P2 bootstrap must run as root")
    shadow = args.config_root / "shadow.env"
    minio = args.config_root / "minio.env"
    shadow_content = "\n".join(
        (
            "NATS_USER=integrity_p2",
            f"NATS_PASSWORD={secrets.token_urlsafe(36)}",
            "POSTGRES_USER=integrity_p2",
            f"POSTGRES_PASSWORD={secrets.token_urlsafe(36)}",
            "POSTGRES_DB=integrity_p2",
            "",
        )
    )
    minio_content = "\n".join(
        (
            "MINIO_ROOT_USER=integrityp2root",
            f"MINIO_ROOT_PASSWORD={secrets.token_urlsafe(42)}",
            "MINIO_BROWSER=off",
            "MINIO_PROMETHEUS_AUTH_TYPE=public",
            "",
        )
    )
    status = {"shadow_env": write_once(shadow, shadow_content), "minio_env": write_once(minio, minio_content)}
    result = {
        "protocol": PROTOCOL,
        "status": "pass",
        "files": {
            "shadow_env": {"path": str(shadow), "sha256": sha256_file(shadow), "mode": "0600"},
            "minio_env": {"path": str(minio), "sha256": sha256_file(minio), "mode": "0600"},
        },
        "outcomes": status,
        "secret_values_exposed": False,
        "shadow_mode": True,
        "production_authority": False,
        "memory_grants_authority": False,
    }
    args.receipt_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    atomic_json(args.receipt_root / "shadow-bootstrap.json", result, mode=0o440)
    print(json.dumps({**result, "files": {key: {"sha256": value["sha256"], "mode": value["mode"]} for key, value in result["files"].items()}}, sort_keys=True))
    return 0


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
