#!/usr/bin/env python3
"""Co-install reviewed wheels into a new isolated verification environment."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import venv


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheels", required=True, type=Path)
    parser.add_argument("--venv", required=True, type=Path)
    parser.add_argument("--github-path", type=Path,
                        help="explicit Actions PATH output, never a user shell configuration")
    args = parser.parse_args()
    target = args.venv.resolve()
    if target.exists():
        parser.error("verification environment must be new")
    wheels = sorted(args.wheels.resolve().glob("*.whl"))
    if not wheels:
        parser.error("no reviewed wheels")
    venv.EnvBuilder(with_pip=True).create(target)
    scripts = target / ("Scripts" if os.name == "nt" else "bin")
    python = scripts / ("python.exe" if os.name == "nt" else "python")
    subprocess.run([str(python), "-m", "pip", "install", "pytest>=8.2,<10",
                    "packaging>=24,<27", *map(str, wheels)], check=True)
    subprocess.run([str(python), "-m", "pip", "check"], check=True)
    if args.github_path:
        with args.github_path.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(str(scripts) + "\n")
    print(json.dumps({"passed": True, "installed_wheels": len(wheels),
                      "isolated_environment": True, "service_started": False}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
