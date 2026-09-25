"""Export the exact first-party Windows bootstrap asset set."""

from __future__ import annotations

import hashlib
import os
from importlib.resources import files
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes, parse_json_strict
from .hashing import digest_object
from .local_machine import _read_private, _write_private
from .schemas import validate

WINDOWS_ASSET_NAMES = (
    "AGENTS.md",
    "Build-IntegrityHostCollector.ps1",
    "Install-IntegritySeedRuntime.ps1",
    "IntegrityHostCollector.cs",
    "Invoke-UroborosWinOpsZeroDayReset.ps1",
    "START-HERE-RU.md",
    "Uninstall-IntegritySeedRuntime.ps1",
    "Verify-IntegritySeedPersistence.ps1",
    "Verify-IntegrityZeroDay.ps1",
)


class WindowsAssetError(ValueError):
    """Raised before an asset export can mix with unrelated bytes."""


def windows_asset_inventory() -> list[dict[str, Any]]:
    root = files("integrity_guardian").joinpath("assets", "windows")
    inventory: list[dict[str, Any]] = []
    for name in WINDOWS_ASSET_NAMES:
        payload = root.joinpath(name).read_bytes()
        inventory.append(
            {
                "name": name,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size": len(payload),
            }
        )
    return inventory


def load_windows_asset_manifest(path: Path) -> dict[str, Any]:
    payload = _read_private(path, maximum_bytes=1024 * 1024)
    value = parse_json_strict(payload)
    if not isinstance(value, dict):
        raise WindowsAssetError("Windows asset manifest is not an object")
    validate("windows-asset-manifest", value)
    return value


def verify_windows_asset_manifest(
    manifest: dict[str, Any],
    *,
    assets_directory: Path,
) -> dict[str, Any]:
    validate("windows-asset-manifest", manifest)
    if [item["name"] for item in manifest["assets"]] != list(WINDOWS_ASSET_NAMES):
        raise WindowsAssetError("Windows asset manifest inventory mismatch")
    core = {key: value for key, value in manifest.items() if key != "manifest_digest"}
    expected = digest_object(core, domain="windows-asset-manifest-v1")
    if manifest["manifest_digest"] != expected:
        raise WindowsAssetError("Windows asset manifest identity mismatch")
    root = assets_directory.absolute()
    for item in manifest["assets"]:
        payload = _read_private(root / item["name"], maximum_bytes=16 * 1024 * 1024)
        if (
            len(payload) != item["size"]
            or hashlib.sha256(payload).hexdigest() != item["sha256"]
        ):
            raise WindowsAssetError("Windows asset bytes do not match manifest")
    return {
        "status": "PASS",
        "asset_count": len(manifest["assets"]),
        "manifest_digest": expected,
        "production_authority": False,
    }


def export_windows_assets(output_directory: Path) -> dict[str, Any]:
    target = output_directory.absolute()
    if target.exists() and (not target.is_dir() or any(target.iterdir())):
        raise WindowsAssetError("Windows asset output directory must be absent or empty")
    if os.name == "nt":
        from ._windows_files import create_private_directory_tree

        create_private_directory_tree(target)
    else:
        target.mkdir(mode=0o700, parents=True, exist_ok=True)
    root = files("integrity_guardian").joinpath("assets", "windows")
    inventory = windows_asset_inventory()
    for item in inventory:
        payload = root.joinpath(item["name"]).read_bytes()
        _write_private(target / item["name"], payload)
    core = {
        "protocol": "integrity-guardian/windows-asset-manifest/v1",
        "assets": inventory,
        "add_type_required": False,
        "console_persistence": False,
        "production_authority": False,
    }
    manifest = {
        **core,
        "manifest_digest": digest_object(
            core,
            domain="windows-asset-manifest-v1",
        ),
    }
    validate("windows-asset-manifest", manifest)
    manifest_path = target / "windows-asset-manifest.json"
    _write_private(manifest_path, canonical_bytes(manifest) + b"\n")
    return {
        "ok": True,
        "output_directory": str(target),
        "asset_count": len(inventory),
        "manifest": str(manifest_path),
        "manifest_digest": manifest["manifest_digest"],
        "production_authority": False,
    }


def build_windows_host_collector_profile(
    *,
    executable: Path,
    tenant_id: str,
    collector_id: str,
    node_id: str,
) -> dict[str, Any]:
    """Bind the exact compiled first-party PE into collector profile v2."""

    from .collector import CollectorProfile

    target = executable.absolute()
    if target.suffix.casefold() != ".exe" or not target.is_file():
        raise WindowsAssetError("Windows host collector executable is absent")
    if os.name == "nt":
        from ._windows_files import HeldWindowsFile

        with HeldWindowsFile(target, maximum_bytes=512 * 1024 * 1024) as held:
            executable_digest = "sha256:" + held.sha256()
    else:
        executable_digest = "sha256:" + hashlib.sha256(target.read_bytes()).hexdigest()
    document = {
        "protocol": "integrity-guardian/collector-profile/v2",
        "tenant_id": tenant_id,
        "collector_id": collector_id,
        "node_id": node_id,
        "executable": str(target),
        "executable_digest": executable_digest,
        "argv": [],
        "timeout_seconds": 30,
        "max_output_bytes": 1024 * 1024,
        "credential_reference": None,
        "controls": {
            "read_only_intent": True,
            "shell": False,
            "inherited_environment": False,
            "production_authority": False,
        },
        "application_files": [],
    }
    CollectorProfile.from_document(document)
    return document


def write_windows_host_collector_profile(
    path: Path,
    profile: dict[str, Any],
) -> Path:
    from .collector import CollectorProfile

    CollectorProfile.from_document(profile)
    return _write_private(path, canonical_bytes(profile) + b"\n")


__all__ = [
    "WINDOWS_ASSET_NAMES",
    "WindowsAssetError",
    "build_windows_host_collector_profile",
    "export_windows_assets",
    "load_windows_asset_manifest",
    "verify_windows_asset_manifest",
    "windows_asset_inventory",
    "write_windows_host_collector_profile",
]
