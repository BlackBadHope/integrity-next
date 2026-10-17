#!/usr/bin/env python3
"""Build every catalogued distribution; never install or configure a service."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    output = args.output.resolve()
    if output.exists() and any(output.iterdir()):
        parser.error("output must be empty; stale wheels cannot participate in a release")
    output.mkdir(parents=True, exist_ok=True)
    catalog = json.loads((root / "COMPONENTS.json").read_text(encoding="utf-8"))
    for component in catalog["components"]:
        source = (root / component["path"]).resolve()
        if not source.is_relative_to(root):
            raise ValueError("component path escapes the source tree")
        subprocess.run([sys.executable, "-m", "build", "--outdir", str(output),
                        str(source)], check=True, cwd=root)
    wheels = sorted(output.glob("*.whl"))
    sdists = sorted(output.glob("*.tar.gz"))
    count = len(catalog["components"])
    if len(wheels) != count or len(sdists) != count:
        raise ValueError("one wheel and one sdist are required for every distribution")
    for component in catalog.get("source_components", []):
        if component["type"] != "source-plugin":
            raise ValueError("unsupported source component type")
        source = (root / component["path"]).resolve()
        if not source.is_relative_to(root):
            raise ValueError("source plugin escapes the source tree")
        subprocess.run([sys.executable, "-B", str(source / "build_release.py"),
                        "--repo", str(source), "--release-dir", str(output / component["name"]),
                        "--version", component["version"], "--candidate", "source"],
                       check=True, cwd=root)
    print(json.dumps({"passed": True, "distributions": count,
                      "wheels": len(wheels), "sdists": len(sdists),
                      "source_plugins": len(catalog.get("source_components", []))}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
