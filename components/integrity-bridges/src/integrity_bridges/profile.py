"""Materialize one complete Hub family into a new owner-selected source directory."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys

HERE = Path(__file__).resolve().parent
REQUIRED = {"host_hub.py", "host_node.py", "unified_mcp.py", "claude_owner.py",
            "ping_pong.py", "unix_ws_stdio.py"}


def compile_profile(family, output):
    if family not in {"private-memory", "hub"}:
        raise ValueError("choose an explicit Hub family")
    sources = {path.name: path for path in sorted((HERE / "resources" / family).glob("*.py"))}
    # One published implementation; materialization duplicates bytes only in the
    # new owner's selected runtime profile so existing local imports still work.
    sources.setdefault("unix_ws_stdio.py", HERE / "resources/hub/unix_ws_stdio.py")
    if family == "private-memory" and not REQUIRED <= sources.keys():
        raise ValueError("private-memory Hub family incomplete")
    output = Path(output)
    if not output.is_absolute():
        raise ValueError("output must be an absolute new directory")
    output.mkdir()
    hashes = {}
    for name, source in sources.items():
        if source.is_symlink() or not source.is_file():
            raise ValueError("Hub source integrity invalid")
        data = source.read_bytes()
        (output / name).write_bytes(data)
        hashes[name] = hashlib.sha256(data).hexdigest()
    manifest = {"directory": str(output.resolve()), "files": hashes}
    (output / "hub-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (output / "hub.example.json").write_text(json.dumps({
        "local_host": None, "ledger": None, "hosts": {},
    }, indent=2) + "\n", encoding="utf-8")
    # This command emits source and metadata only. Hub(config) is never imported
    # or called; it would create the explicitly configured local operation ledger.
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--family", choices=("private-memory", "hub"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        manifest = compile_profile(args.family, args.output)
        print(json.dumps({"family": args.family, "files": len(manifest["files"]),
                          "configured": False, "network_used": False,
                          "manifest": str(args.output / "hub-manifest.json")}))
        return 0
    except (OSError, ValueError) as exc:
        print("Hub profile compilation rejected: " + type(exc).__name__, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
