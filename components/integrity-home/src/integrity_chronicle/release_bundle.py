"""Deterministic self-contained Codex marketplace release bundles."""

from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import tempfile
from typing import Any, Dict, Iterable, Mapping
import zipfile

from .json_integrity import load_json_strict

BUNDLE_SCHEMA = "integrity-home-native-codex-bundle/1"
MARKETPLACE_NAME = "integrity-home-local"
PLUGIN_NAME = "integrity-home"
SUPPORTED_TARGETS = frozenset({
    "linux-x64", "linux-arm64", "macos-x64", "macos-arm64",
    "windows-x64", "windows-arm64",
})
_ZIP_TIME = (2020, 1, 1, 0, 0, 0)


class ReleaseBundleError(ValueError):
    pass


def _canonical(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _sha_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ReleaseBundleError("bundle inputs must not contain links")
        if path.is_file():
            files.append(path)
    return sorted(files, key=lambda item: item.relative_to(root).as_posix())


def _validate_target(target: str) -> str:
    if target not in SUPPORTED_TARGETS:
        raise ReleaseBundleError(f"unsupported native target: {target}")
    return target


def _native_name(base: str, target: str) -> str:
    return f"{base}.exe" if target.startswith("windows-") else base


def _copy_plugin(source: Path, destination: Path) -> None:
    if not source.is_dir() or source.is_symlink():
        raise ReleaseBundleError("plugin source must be a real directory")
    for relative in (
        Path(".codex-plugin/plugin.json"), Path(".mcp.json"),
        Path("skills/integrity-home/SKILL.md"),
    ):
        candidate = source / relative
        if not candidate.is_file() or candidate.is_symlink():
            raise ReleaseBundleError(f"plugin source missing {relative.as_posix()}")
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(candidate, target)


def _write_zip(root: Path, archive_path: Path, top_level: str) -> None:
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix="integrity-home-bundle-", suffix=".zip", dir=archive_path.parent)
    os.close(fd)
    temporary = Path(temporary_name)
    try:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for path in _safe_files(root):
                relative = path.relative_to(root).as_posix()
                info = zipfile.ZipInfo(f"{top_level}/{relative}", _ZIP_TIME)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                executable = relative.startswith("plugins/integrity-home/bin/")
                info.external_attr = ((0o755 if executable else 0o644) & 0xFFFF) << 16
                archive.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
        os.replace(temporary, archive_path)
    finally:
        temporary.unlink(missing_ok=True)


def build_native_codex_bundle(
    *, plugin_source: str, cli_executable: str, mcp_executable: str,
    output_zip: str, version: str, target: str,
) -> Dict[str, Any]:
    target = _validate_target(target)
    if not isinstance(version, str) or not version.strip() or "/" in version or "\\" in version:
        raise ReleaseBundleError("version must be a safe non-empty string")
    cli = Path(cli_executable)
    mcp = Path(mcp_executable)
    for label, path in (("CLI", cli), ("MCP", mcp)):
        if not path.is_file() or path.is_symlink() or path.stat().st_size == 0:
            raise ReleaseBundleError(f"{label} executable must be a non-empty regular file")
    output = Path(output_zip).resolve()
    top_level = f"integrity-home-{version}-{target}"
    with tempfile.TemporaryDirectory(prefix="integrity-home-native-bundle-") as temporary:
        root = Path(temporary) / top_level
        plugin = root / "plugins" / PLUGIN_NAME
        _copy_plugin(Path(plugin_source), plugin)
        plugin_manifest_path = plugin / ".codex-plugin" / "plugin.json"
        with plugin_manifest_path.open("r", encoding="utf-8") as stream:
            plugin_manifest = load_json_strict(stream)
        if not isinstance(plugin_manifest, dict) or plugin_manifest.get("name") != PLUGIN_NAME:
            raise ReleaseBundleError("plugin manifest name mismatch")
        plugin_manifest["version"] = version
        plugin_manifest_path.write_bytes(_canonical(plugin_manifest))
        bin_root = plugin / "bin"
        bin_root.mkdir(parents=True)
        cli_name = _native_name("integrity-home", target)
        mcp_name = _native_name("integrity-home-mcp", target)
        shutil.copyfile(cli, bin_root / cli_name)
        shutil.copyfile(mcp, bin_root / mcp_name)

        mcp_config = {
            "mcpServers": {
                "integrity-home": {
                    "command": f"./bin/{mcp_name}", "args": [], "cwd": ".",
                    "env_vars": ["INTEGRITY_HOME_SCOPE_REGISTRY", "INTEGRITY_HOME_STATE_ROOT"],
                    "tool_timeout_sec": 120,
                }
            }
        }
        (plugin / ".mcp.json").write_bytes(_canonical(mcp_config))
        marketplace = {
            "name": MARKETPLACE_NAME,
            "interface": {"displayName": "Integrity Home Local"},
            "plugins": [{
                "name": PLUGIN_NAME,
                "source": {"source": "local", "path": f"./plugins/{PLUGIN_NAME}"},
                "policy": {"installation": "AVAILABLE", "authentication": "ON_INSTALL"},
                "category": "Productivity",
            }],
        }
        marketplace_path = root / ".agents" / "plugins" / "marketplace.json"
        marketplace_path.parent.mkdir(parents=True)
        marketplace_path.write_bytes(_canonical(marketplace))
        payload_files = _safe_files(root)
        manifest = {
            "schema_version": BUNDLE_SCHEMA,
            "version": version,
            "target": target,
            "marketplace_name": MARKETPLACE_NAME,
            "plugin_name": PLUGIN_NAME,
            "requires_python": False,
            "requires_pip": False,
            "files": [
                {
                    "path": path.relative_to(root).as_posix(),
                    "size_bytes": path.stat().st_size,
                    "sha256": _sha_file(path),
                }
                for path in payload_files
            ],
        }
        (root / "release-manifest.json").write_bytes(_canonical(manifest))
        verify_native_codex_bundle(str(root), expected_target=target)
        _write_zip(root, output, top_level)
    return {
        "schema_version": BUNDLE_SCHEMA,
        "target": target,
        "version": version,
        "archive_sha256": _sha_file(output),
        "archive_size_bytes": output.stat().st_size,
        "output": str(output),
    }


def verify_native_codex_bundle(bundle_root: str, *, expected_target: str | None = None) -> Dict[str, Any]:
    root = Path(bundle_root)
    if not root.is_dir() or root.is_symlink():
        raise ReleaseBundleError("bundle root must be a real directory")
    manifest_path = root / "release-manifest.json"
    try:
        with manifest_path.open("r", encoding="utf-8") as stream:
            manifest = load_json_strict(stream)
    except (OSError, ValueError, json.JSONDecodeError) as err:
        raise ReleaseBundleError("invalid release manifest") from err
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema_version", "version", "target", "marketplace_name", "plugin_name",
        "requires_python", "requires_pip", "files",
    }:
        raise ReleaseBundleError("release manifest has invalid fields")
    if manifest["schema_version"] != BUNDLE_SCHEMA:
        raise ReleaseBundleError("release manifest has invalid schema")
    target = _validate_target(manifest["target"])
    if expected_target is not None and target != expected_target:
        raise ReleaseBundleError("release target mismatch")
    if manifest["requires_python"] is not False or manifest["requires_pip"] is not False:
        raise ReleaseBundleError("native bundle must not require Python or pip")
    records = manifest["files"]
    if not isinstance(records, list):
        raise ReleaseBundleError("release manifest files must be an array")
    expected_paths: set[str] = set()
    for index, record in enumerate(records):
        if not isinstance(record, dict) or set(record) != {"path", "size_bytes", "sha256"}:
            raise ReleaseBundleError(f"invalid file record at index {index}")
        relative = record["path"]
        if not isinstance(relative, str) or PurePosixPath(relative).is_absolute() or ".." in PurePosixPath(relative).parts:
            raise ReleaseBundleError(f"unsafe file path at index {index}")
        if relative in expected_paths:
            raise ReleaseBundleError("duplicate release file path")
        expected_paths.add(relative)
        path = root / Path(*PurePosixPath(relative).parts)
        if not path.is_file() or path.is_symlink():
            raise ReleaseBundleError(f"release file missing: {relative}")
        if record["size_bytes"] != path.stat().st_size or record["sha256"] != _sha_file(path):
            raise ReleaseBundleError(f"release file digest mismatch: {relative}")
    actual_paths = {path.relative_to(root).as_posix() for path in _safe_files(root)} - {"release-manifest.json"}
    if actual_paths != expected_paths:
        raise ReleaseBundleError("release file set mismatch")
    mcp_name = _native_name("integrity-home-mcp", target)
    config = json.loads((root / "plugins" / PLUGIN_NAME / ".mcp.json").read_text(encoding="utf-8"))
    if config.get("mcpServers", {}).get(PLUGIN_NAME, {}).get("command") != f"./bin/{mcp_name}":
        raise ReleaseBundleError("plugin MCP command is not bundle-local")
    plugin_manifest = json.loads(
        (root / "plugins" / PLUGIN_NAME / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    if plugin_manifest.get("name") != PLUGIN_NAME or plugin_manifest.get("version") != manifest["version"]:
        raise ReleaseBundleError("plugin manifest release identity mismatch")
    marketplace_path = root / ".agents" / "plugins" / "marketplace.json"
    try:
        marketplace = json.loads(marketplace_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as err:
        raise ReleaseBundleError("Codex marketplace manifest is invalid") from err
    entries = marketplace.get("plugins") if isinstance(marketplace, dict) else None
    if (
        marketplace.get("name") != MARKETPLACE_NAME
        or not isinstance(entries, list)
        or len(entries) != 1
        or entries[0].get("name") != PLUGIN_NAME
        or entries[0].get("source", {}).get("path") != f"./plugins/{PLUGIN_NAME}"
    ):
        raise ReleaseBundleError("Codex marketplace identity mismatch")
    return {
        "schema_version": BUNDLE_SCHEMA,
        "target": target,
        "version": manifest["version"],
        "file_count": len(expected_paths),
        "valid": True,
    }
