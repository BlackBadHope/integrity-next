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
import sys
from pathlib import Path

MANIFEST_NAME = "PUBLIC-EXPORT-MANIFEST.json"
GROUPS = ("files", "generated_files")


def entry_for(root: Path, relative: str, sanitization_edits: int) -> dict[str, object]:
    path = root / relative
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        raise SystemExit(f"not a regular file: {relative}")
    data = path.read_bytes()
    mode = "0o755" if os.name != "nt" and metadata.st_mode & 0o111 else "0o644"
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
    args = parser.parse_args(argv)
    root = args.root.absolute()
    manifest_path = root / MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

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
            entry_for(root, entry["path"], entry["sanitization_edits"])
            for entry in manifest[group]
            if entry["path"] not in removed
        ]
    manifest["files"] += [entry_for(root, relative, 0) for relative in args.add]
    manifest["generated_files"] += [entry_for(root, relative, 0) for relative in args.add_generated]
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
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
