#!/usr/bin/env python3
"""Reject conflicting wheel ownership and missing declared versions/licenses."""
from __future__ import annotations

import argparse
from email.parser import BytesParser
import json
from pathlib import Path, PurePosixPath
import tarfile
import zipfile

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name


def verify(root: Path, directory: Path) -> dict:
    catalog = json.loads((root / "COMPONENTS.json").read_text(encoding="utf-8"))
    expected = {canonicalize_name(c["distribution"]): c for c in catalog["components"]}
    seen, ownership = set(), {}
    for wheel in sorted(directory.glob("*.whl")):
        with zipfile.ZipFile(wheel) as archive:
            names = archive.namelist()
            if len(names) != len(set(names)):
                raise ValueError("duplicate wheel member")
            for name in names:
                path = PurePosixPath(name)
                if path.is_absolute() or ".." in path.parts or "\\" in name:
                    raise ValueError("nonportable wheel member")
            metadata_names = [n for n in names if n.endswith(".dist-info/METADATA")]
            if len(metadata_names) != 1:
                raise ValueError("ambiguous wheel metadata")
            metadata = BytesParser().parsebytes(archive.read(metadata_names[0]))
            name = canonicalize_name(metadata["Name"])
            component = expected.get(name)
            if not component or name in seen or metadata["Version"] != component["version"]:
                raise ValueError("unexpected, duplicate or stale wheel")
            seen.add(name)
            declared = [Requirement(raw) for raw in metadata.get_all("Requires-Dist", [])]
            installed = {str(req) for req in declared
                         if req.marker is None or "extra" not in str(req.marker)}
            source = {str(Requirement(raw)) for raw in component["dependencies"]}
            if installed != source:
                raise ValueError("wheel runtime dependencies differ from the catalog: " + name)
            expected_extras = set(component["optional_dependencies"])
            if set(metadata.get_all("Provides-Extra", [])) != expected_extras:
                raise ValueError("wheel extras differ from the catalog: " + name)
            for extra, requirements in component["optional_dependencies"].items():
                installed_extra = set()
                for req in declared:
                    if req.marker and "extra" in str(req.marker) and req.marker.evaluate({"extra": extra}):
                        base = Requirement(str(req))
                        base.marker = None
                        installed_extra.add(str(base))
                if installed_extra != {str(Requirement(raw)) for raw in requirements}:
                    raise ValueError("wheel extra dependencies differ from the catalog: " + name)
            license_text = metadata.get("License-Expression", metadata.get("License", ""))
            license_members = [n for n in names if ".dist-info/" in n
                               and PurePosixPath(n).name.upper().startswith("LICENSE")]
            if ("Apache-2.0" not in license_text and "Apache License" not in license_text) or not license_members:
                raise ValueError("missing Apache license metadata or license bytes: " + name)
            for member in names:
                if member.endswith("/") or ".dist-info/" in member:
                    continue
                key = member.casefold()
                if key in ownership:
                    raise ValueError("conflicting installed file ownership: " + member)
                ownership[key] = name
    if seen != set(expected):
        raise ValueError("wheel set does not cover every public component")
    guardian = expected["integrity-guardian"]
    sdist = directory / ("integrity_guardian-" + guardian["version"] + ".tar.gz")
    with tarfile.open(sdist) as archive:
        prefix = "integrity_guardian-" + guardian["version"] + "/"
        members = archive.getmembers()
        relative = [m.name.removeprefix(prefix) for m in members if m.isfile()]
        expected_source = {p.relative_to(root).as_posix()
                           for p in (root / "src/integrity_guardian").rglob("*") if p.is_file()}
        expected_source.update({"README.md", "LICENSE", "NOTICE", "AUTHORS.md", "pyproject.toml", "PKG-INFO", ".gitignore"})
        if any(not m.name.startswith(prefix) or not m.isfile() for m in members):
            raise ValueError("nonregular Guardian source archive member")
        if len(relative) != len(set(relative)) or set(relative) != expected_source:
            raise ValueError("Guardian source archive must contain exactly the canonical package and root metadata")
    return {"passed": True, "distributions": len(seen), "owned_files": len(ownership),
            "guardian_sdist_boundary": "PASS"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--wheels", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.root.resolve(), args.wheels.resolve()), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
