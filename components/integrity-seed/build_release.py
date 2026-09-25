#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import io
import json
import shutil
import tarfile
from pathlib import Path, PurePosixPath

from verify_seed import validate_public_text


FORBIDDEN_SUFFIXES = {".pyc", ".pyo", ".sqlite3", ".wal", ".shm"}
FORBIDDEN_NAMES = {"auth.json", "runtime.json", "server.log", "server.pid", "token"}


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_exclusive(path: Path, value: bytes) -> None:
    with path.open("xb") as handle:
        handle.write(value)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build one immutable Integrity Seed candidate")
    parser.add_argument("--repo", default=".")
    parser.add_argument("--release-dir", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--candidate", required=True)
    args = parser.parse_args()

    repo = Path(args.repo).resolve(strict=True)
    release_dir = Path(args.release_dir).resolve(strict=False)
    if release_dir.exists():
        raise FileExistsError(f"release directory already exists: {release_dir}")
    release_dir.mkdir(parents=True, exist_ok=False)
    archive = release_dir / f"integrity-seed-{args.version}-{args.candidate}.tar"
    manifest_path = release_dir / f"integrity-seed-{args.version}-{args.candidate}-source-manifest.json"
    release_allowlist = release_dir / "PACKAGE_ALLOWLIST.txt"

    try:
        allowlist_bytes = (repo / "PACKAGE_ALLOWLIST.txt").read_bytes()
        allowlist = [line for line in allowlist_bytes.decode("utf-8").splitlines() if line]
        if len(allowlist) != len(set(allowlist)):
            raise RuntimeError("package allowlist contains duplicates")

        members: list[dict[str, object]] = []
        with tarfile.open(archive, "x:", format=tarfile.PAX_FORMAT) as output:
            for name in allowlist:
                relative = PurePosixPath(name)
                if relative.is_absolute() or ".." in relative.parts:
                    raise RuntimeError(f"unsafe allowlist path: {name}")
                source = repo.joinpath(*relative.parts)
                if not source.is_file() or source.is_symlink():
                    raise RuntimeError(f"source is not one regular file: {name}")
                if source.suffix.lower() in FORBIDDEN_SUFFIXES or source.name.lower() in FORBIDDEN_NAMES:
                    raise RuntimeError(f"state or bytecode member is forbidden: {name}")
                value = source.read_bytes()
                validate_public_text("archive member name", name)
                validate_public_text(name, value.decode("utf-8"))
                mode = 0o755 if name.endswith(".sh") else 0o644
                info = tarfile.TarInfo(name)
                info.size = len(value)
                info.mode = mode
                info.uid = 0
                info.gid = 0
                info.uname = "root"
                info.gname = "root"
                info.mtime = 0
                output.addfile(info, io.BytesIO(value))
                members.append({"path": name, "bytes": len(value), "sha256": sha256_bytes(value)})

        write_exclusive(release_allowlist, allowlist_bytes)
        manifest = {
            "schema": "integrity-seed.release-manifest.v1",
            "artifact": archive.name,
            "version": args.version,
            "candidate": args.candidate,
            "created_at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
            "sha256": sha256_file(archive),
            "bytes": archive.stat().st_size,
            "member_count": len(members),
            "privacy_scan": {
                "bytecode_or_state_members": 0,
                "private_identifier_matches": 0,
                "language_marker_matches": 0,
                "allowlist_diff": 0,
            },
            "members": members,
        }
        write_exclusive(
            manifest_path,
            (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
        )
        print(json.dumps(manifest, ensure_ascii=False, indent=2))
        return 0
    except BaseException:
        shutil.rmtree(release_dir, ignore_errors=True)
        raise


if __name__ == "__main__":
    raise SystemExit(main())
