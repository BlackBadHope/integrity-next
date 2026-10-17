#!/usr/bin/env python3
"""Refresh PUBLIC-EXPORT-MANIFEST.json after a reviewed public change.

The manifest stays deny-by-default: entries already listed get their bytes,
mode and sha256 refreshed from the working tree, while a new or removed file
must be named explicitly. Run public_surface_check.py afterwards; it remains
the authority on membership and privacy.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath

MANIFEST_NAME = "PUBLIC-EXPORT-MANIFEST.json"
GROUPS = ("files", "generated_files")


def portable_mode(native_mode: int, recorded: str | None, indexed: str | None,
                  *, windows: bool) -> str:
    """Windows mode bits cannot describe POSIX executability; retain Git's claim."""
    if indexed not in {None, "100644", "100755"}:
        raise SystemExit("unsupported Git file mode")
    if recorded not in {None, "0o644", "0o755"}:
        raise SystemExit("unsupported recorded file mode")
    if not windows:
        return "0o755" if native_mode & 0o111 else "0o644"
    if indexed is not None:
        return "0o755" if indexed == "100755" else "0o644"
    return recorded or "0o644"


def git_modes(root: Path) -> dict[str, str]:
    try:
        result = subprocess.run(
            ["git", "--no-optional-locks", "-C", str(root), "ls-files", "--stage", "-z"],
            capture_output=True, timeout=30, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {}
    if result.returncode:
        return {}
    modes = {}
    for row in result.stdout.split(b"\0"):
        if not row:
            continue
        metadata, name = row.split(b"\t", 1)
        mode, _object_id, stage = metadata.split()
        if stage != b"0":
            raise SystemExit("unmerged Git index")
        modes[name.decode("utf-8")] = mode.decode("ascii")
    return modes


def entry_for(root: Path, relative: str, sanitization_edits: int,
              recorded_mode: str | None = None,
              indexed_modes: dict[str, str] | None = None) -> dict[str, object]:
    portable = PurePosixPath(relative)
    if (not relative or portable.is_absolute() or portable.as_posix() != relative
            or "\\" in relative or ":" in relative
            or any(part in {".", ".."} for part in portable.parts)
            or any(ord(c) < 32 for c in relative)):
        raise SystemExit("invalid relative manifest path")
    path = root / relative
    metadata = path.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
            or not path.resolve().is_relative_to(root.resolve())):
        raise SystemExit(f"not a regular file: {relative}")
    data = path.read_bytes()
    mode = portable_mode(metadata.st_mode, recorded_mode,
                         (indexed_modes or {}).get(relative), windows=os.name == "nt")
    return {
        "bytes": len(data),
        "mode": mode,
        "path": relative,
        "sanitization_edits": sanitization_edits,
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--add", action="append", default=[], metavar="PATH",
                        help="add a new projected source file")
    parser.add_argument("--add-generated", action="append", default=[], metavar="PATH",
                        help="add a new publication-layer file (docs, CI, packaging)")
    parser.add_argument("--remove", action="append", default=[], metavar="PATH")
    parser.add_argument("--add-from", type=Path, metavar="JSON",
                        help="explicit JSON array of new source paths (no glob expansion)")
    parser.add_argument("--remove-from", type=Path, metavar="JSON",
                        help="explicit JSON array of removed paths")
    args = parser.parse_args(argv)
    root = args.root.absolute()
    manifest_path = root / MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for option, target in ((args.add_from, args.add), (args.remove_from, args.remove)):
        if option is not None:
            values = json.loads(option.read_text(encoding="utf-8"))
            if not isinstance(values, list) or not all(isinstance(x, str) for x in values):
                raise SystemExit("manifest path list must be an array of strings")
            target.extend(values)
    if len(set(args.add + args.add_generated)) != len(args.add + args.add_generated):
        raise SystemExit("duplicate addition")
    indexed_modes = git_modes(root)

    listed = {entry["path"] for group in GROUPS for entry in manifest[group]}
    for relative in [*args.add, *args.add_generated]:
        if relative in listed:
            raise SystemExit(f"already listed: {relative}")
    for relative in args.remove:
        if relative not in listed:
            raise SystemExit(f"not listed: {relative}")

    removed = set(args.remove)
    for group in GROUPS:
        manifest[group] = [
            entry_for(root, entry["path"], entry["sanitization_edits"],
                      entry["mode"], indexed_modes)
            for entry in manifest[group]
            if entry["path"] not in removed
        ]
    manifest["files"] += [entry_for(root, relative, 0, indexed_modes=indexed_modes)
                          for relative in args.add]
    manifest["generated_files"] += [entry_for(root, relative, 0, indexed_modes=indexed_modes)
                                    for relative in args.add_generated]
    for group in GROUPS:
        manifest[group].sort(key=lambda entry: entry["path"])

    files = manifest["files"]
    manifest["file_count"] = len(files)
    manifest["generated_file_count"] = len(manifest["generated_files"])
    manifest["transformed_file_count"] = sum(entry["sanitization_edits"] > 0 for entry in files)
    manifest["sanitization_edit_count"] = sum(entry["sanitization_edits"] for entry in files)
    entries = sorted([*files, *manifest["generated_files"]], key=lambda entry: entry["path"])
    payload = json.dumps(entries, ensure_ascii=False, sort_keys=True,
                         separators=(",", ":")).encode("utf-8")
    manifest["projection_digest"] = "sha256:" + hashlib.sha256(payload).hexdigest()
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8", newline="\n",
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
