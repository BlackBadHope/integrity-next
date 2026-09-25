#!/usr/bin/env python3
"""Validate the opt-in marker that suppresses the bundled local writer."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import sys


SCHEMA = "integrity-seed.canonical-provider.v1"
MODE = "external-canonical"


def marker_suppresses_local_runtime(path: Path) -> bool:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
            return False
        if os.name == "posix":
            if metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
                return False
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False
    return bool(
        isinstance(value, dict)
        and value.get("schema") == SCHEMA
        and value.get("mode") == MODE
        and value.get("suppress_local_runtime") is True
        and isinstance(value.get("provider"), str)
        and bool(value["provider"].strip())
    )


def main() -> int:
    if len(sys.argv) != 2:
        return 1
    return 0 if marker_suppresses_local_runtime(Path(sys.argv[1])) else 1


if __name__ == "__main__":
    raise SystemExit(main())
