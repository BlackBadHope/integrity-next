#!/usr/bin/env python3
"""Generate or verify the public component inventory and exact SDK source binding."""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
import shlex
import tomllib

CATALOG = "COMPONENTS.json"
ORIGIN = "components/integrity-adapter-sdk/src/integrity_adapter_sdk/guardian-origin.json"


def project(root: Path, relative: str) -> dict:
    return tomllib.loads((root / relative).read_text(encoding="utf-8"))["project"]


def literal(root: Path, relative: str, name: str) -> str:
    tree = ast.parse((root / relative).read_text(encoding="utf-8"))
    for node in tree.body:
        if (isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant)
                and any(isinstance(t, ast.Name) and t.id == name for t in node.targets)):
            return node.value.value
    raise ValueError("missing declared source version: " + relative)


def source_origin(root: Path) -> dict:
    rows = []
    source_root = root / "src/integrity_guardian"
    for path in sorted(source_root.rglob("*"),
                       key=lambda p: p.relative_to(source_root).as_posix()):
        if (not path.is_file() or "__pycache__" in path.parts
                or path.suffix in {".pyc", ".pyo"}):
            continue
        data = path.read_bytes()
        rows.append(("integrity_guardian/" + path.relative_to(source_root).as_posix(),
                     len(data), hashlib.sha256(data).hexdigest()))
    digest = hashlib.sha256()
    for name, size, sha in rows:
        digest.update(f"{name}\0{size}\0{sha}\n".encode("utf-8"))
    return {"distribution": "integrity-guardian", "file_count": len(rows),
            "package_root": "integrity_guardian",
            "protocol": "integrity-adapter-sdk/guardian-origin-manifest/v1",
            "tree_sha256": "sha256:" + digest.hexdigest(),
            "version": project(root, "pyproject.toml")["version"]}


def source_roots(directory: Path) -> list[str]:
    source = directory / "src"
    if not source.is_dir():
        return []
    return sorted(p.stem if p.is_file() else p.name for p in source.iterdir()
                  if ((p.is_dir() and (p / "__init__.py").is_file())
                      or (p.is_file() and p.suffix == ".py")))


def catalog(root: Path) -> dict:
    version = project(root, "pyproject.toml")["version"]
    if literal(root, "src/integrity_guardian/__init__.py", "__version__") != version:
        raise ValueError("Guardian metadata and implementation versions differ")
    rows = []
    paths = [root / "pyproject.toml", *sorted((root / "components").glob("*/pyproject.toml"))]
    for path in paths:
        p = project(root, path.relative_to(root).as_posix())
        license_value = p.get("license")
        license_file = path.parent / (license_value.get("file", "LICENSE")
                                     if isinstance(license_value, dict) else "LICENSE")
        if not license_file.is_file():
            raise ValueError("missing component license: " + p["name"])
        if "Apache License" not in license_file.read_text(encoding="utf-8"):
            raise ValueError("component requires an explicit supported license: " + p["name"])
        for declared in p.get("license-files", []):
            if not list(path.parent.glob(declared)):
                raise ValueError("missing declared license file: " + p["name"])
        rows.append({"distribution": p["name"], "version": p["version"],
                     "path": path.parent.relative_to(root).as_posix(),
                     "python": p["requires-python"], "license": "Apache-2.0",
                     "dependencies": p.get("dependencies", []),
                     "optional_dependencies": p.get("optional-dependencies", {}),
                     "import_roots": source_roots(path.parent),
                     "entry_points": p.get("scripts", {})})
    seed_root = "components/integrity-seed"
    plugin_root = seed_root + "/plugins/integrity-seed"
    seed = json.loads((root / plugin_root / ".codex-plugin/plugin.json").read_text(encoding="utf-8"))
    seed_runtime = literal(root, plugin_root + "/runtime/__init__.py", "__version__")
    if (literal(root, plugin_root + "/runtime/action_log.py", "SERVICE_VERSION") != seed_runtime
            or literal(root, plugin_root + "/skills/integrity-seed/scripts/integrity_seed.py", "VERSION") != seed_runtime):
        raise ValueError("Seed launcher and runtime versions differ")
    if (seed.get("license") != "Apache-2.0"
            or any("Apache License" not in (root / p / "LICENSE").read_text(encoding="utf-8")
                   for p in (seed_root, plugin_root))):
        raise ValueError("Seed plugin license metadata and license bytes differ")
    source_components = [{"name": "integrity-seed", "type": "source-plugin",
                          "path": seed_root, "version": seed["version"],
                          "runtime_version": seed_runtime, "license": seed["license"],
                          "dependencies": [], "runtime": "Python standard library",
                          "runtime_data_included": False,
                          "allowlist": seed_root + "/PACKAGE_ALLOWLIST.txt"}]
    return {"schema": "integrity.public-component-catalog/v1",
            "release_version": version,
            "memory_facade_api": literal(root, "src/integrity_guardian/memory_synapse_lts.py",
                                          "FACADE_SERVER_VERSION"),
            "configured": False, "runtime_data_included": False,
            "components": rows,
            "source_components": source_components,
            "source_profiles": "components/integrity-installed-runtime/VARIANTS.json"}


def verify_dependencies(value: dict) -> None:
    from packaging.requirements import Requirement
    from packaging.utils import canonicalize_name
    from packaging.version import Version

    known = {canonicalize_name(c["distribution"]): c for c in value["components"]}
    if len(known) != len(value["components"]):
        raise ValueError("duplicate distribution identity")
    owners = {}
    for c in value["components"]:
        for name in c["import_roots"]:
            if name.casefold() in owners:
                raise ValueError("overlapping import root: " + name)
            owners[name.casefold()] = c["distribution"]
        requirements = list(c["dependencies"])
        requirements.extend(raw for group in c["optional_dependencies"].values() for raw in group)
        for raw in requirements:
            req = Requirement(raw)
            if req.url:
                raise ValueError("direct URL dependency needs a separate reviewed boundary")
            target = known.get(canonicalize_name(req.name))
            if target and Version(target["version"]) not in req.specifier:
                raise ValueError("unsatisfied internal dependency: " + c["distribution"] + " -> " + raw)


def verify_hook_template(root: Path, value: dict) -> None:
    profile = json.loads((root / "plugins/integrity-memory/profile.json").read_text(encoding="utf-8"))
    client = next(c for c in value["components"] if c["distribution"] == "integrity-client-memory")
    if (profile.get("version") != client["version"]
            or profile.get("distribution") != client["distribution"]
            or profile.get("memory_facade_api") != value["memory_facade_api"]
            or profile.get("configured") is not False):
        raise ValueError("stale or activated public hook profile")
    resources = json.loads((root / client["path"] / "src/integrity_client_memory/resources.json").read_text(encoding="utf-8"))
    hooks = json.loads((root / "plugins/integrity-memory/hooks/hooks.json").read_text(encoding="utf-8"))["hooks"]
    for event, groups in hooks.items():
        for group in groups:
            for hook in group["hooks"]:
                for field in ("command", "commandWindows"):
                    args = shlex.split(hook[field])
                    if (len(args) < 4 or args[0] not in client["entry_points"]
                            or args[1] not in resources or args[-2:] != ["--event", event]):
                        raise ValueError("hook template does not select a packaged event entrypoint")
                    if args[1].startswith("common/") and args[2:4] != ["--harness", "codex"]:
                        raise ValueError("scope hook must select its explicit harness")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--write", action="store_true",
                        help="refresh metadata after reviewed source changes; CI never uses this")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    expected = catalog(root)
    verify_dependencies(expected)
    verify_hook_template(root, expected)
    origin = source_origin(root)
    layout_path = root / expected["source_profiles"]
    layout = json.loads(layout_path.read_text(encoding="utf-8"))
    layout["release_version"] = expected["release_version"]
    layout["canonical_sources"] = [
        {"component": c["distribution"],
         "path": (Path(c["path"]) / "src" / name).as_posix()}
        for c in expected["components"] for name in c["import_roots"]
    ]
    for relative, data in ((CATALOG, expected), (ORIGIN, origin),
                           (expected["source_profiles"], layout)):
        path = root / relative
        if args.write:
            path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n",
                            encoding="utf-8", newline="\n")
        elif json.loads(path.read_text(encoding="utf-8")) != data:
            raise ValueError("stale component metadata: " + relative)
    print(json.dumps({"passed": True, "components": len(expected["components"]),
                      "version": expected["release_version"],
                      "guardian_source_files": origin["file_count"],
                      "guardian_tree": origin["tree_sha256"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
