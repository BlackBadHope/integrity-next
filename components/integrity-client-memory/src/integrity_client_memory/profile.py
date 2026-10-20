"""Compile an owner-selected MCP catalogue without contacting or enrolling a host."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

NAME = re.compile(r"integrity_[a-z0-9_]{1,80}\Z")
REQUIRED = {"integrity_context_admission_current_turn", "integrity_turn_memory_open",
            "integrity_turn_memory_close"}


def compile_catalog(tools):
    """Validate the actual selected server catalogue; never fabricate tool schemas."""
    if not isinstance(tools, list) or not tools or len(tools) > 200:
        raise ValueError("tools catalogue must be a bounded nonempty list")
    names = set()
    for item in tools:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            raise ValueError("tool catalogue entry shape invalid")
        if not NAME.fullmatch(item["name"]) or item["name"] in names:
            raise ValueError("invalid or duplicate tool name")
        if (not isinstance(item.get("description"), str)
                or not isinstance(item.get("inputSchema"), dict)
                or not isinstance(item.get("annotations"), dict)):
            raise ValueError("tool catalogue must retain descriptions, schemas and annotations")
        names.add(item["name"])
    if not REQUIRED <= names:
        raise ValueError("current-turn admission and lifecycle contract required")
    data = (json.dumps(tools, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")
    return data, hashlib.sha256(data).hexdigest()


def native_source_pins():
    """Pins are derived from this distribution's source, never an installed host."""
    root = Path(__file__).resolve().parent
    paths = [root / "owning_native.py", root / "project_scope.py",
             root / "resources/linux/linux_runtime_factory.py"]
    paths += sorted((root / "resources/linux/native").glob("*.py"))
    paths += sorted((root / "resources/windows/native").glob("*.py"))
    return {path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in paths}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tools-json", type=Path, required=True,
                        help="Exact tools/list catalogue from the server chosen by its owner")
    parser.add_argument("--output", type=Path, required=True,
                        help="New empty output directory; existing directories are refused")
    args = parser.parse_args(argv)
    try:
        if args.tools_json.is_symlink() or args.tools_json.stat().st_size > 4 * 1024 * 1024:
            raise ValueError("catalogue must be a bounded regular source file")
        data, digest = compile_catalog(json.loads(args.tools_json.read_text(encoding="utf-8")))
        pins = native_source_pins()
        # One mkdir with no exist_ok is the no-clobber boundary; do not modify an
        # existing profile, production MCP configuration or enrollment.
        args.output.mkdir(parents=False)
        (args.output / "integrity-client-tools.json").write_bytes(data)
        (args.output / "profile-source.json").write_text(json.dumps({
            "schema": "integrity/public-client-profile-source/v1", "configured": False,
            "guardian_version": "6.1.0", "memory_api_version": "2.11.0",
            "tools_sha256": digest, "native_source_pins": pins,
            "upstream_command": None, "upstream_args": [], "upstream_environment": {},
            "machine_id": None, "project_scope": None, "native_owner_bindings": None,
            "production_authority": False,
        }, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"tools_sha256": digest, "tool_count": len(json.loads(data)),
                          "configured": False, "network_used": False}))
        return 0
    except (OSError, UnicodeError, ValueError) as exc:
        print("profile compilation rejected: " + type(exc).__name__, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
