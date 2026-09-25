"""Explicit Windows install discovery without drive or quarantine scanning."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

from .canonical import parse_json_strict
from .local_machine import LocalMachineError, _read_private
from .schemas import validate
from .windows_assets import (
    load_windows_asset_manifest,
    verify_windows_asset_manifest,
)

_MAXIMUM_LOCATOR_BYTES = 1024 * 1024
_MAXIMUM_GUARDIAN_BYTES = 16 * 1024 * 1024


class WindowsInstallError(ValueError):
    """Raised when the one explicit local install locator is unsafe."""


def default_windows_install_locator_path() -> Path:
    local = os.environ.get("LOCALAPPDATA")
    if not local:
        raise WindowsInstallError("LOCALAPPDATA is required for Windows install discovery")
    return Path(local) / "IntegrityGuardian" / "active-install.json"


def _same_path(left: Path, right: Path) -> bool:
    return os.path.normcase(str(left.absolute())) == os.path.normcase(
        str(right.absolute())
    )


def _installed_guardian_digest(target: Path, guardian: Path) -> str:
    if os.name == "nt":
        from ._windows_files import (
            HeldWindowsFile,
            WindowsFileBoundaryError,
            assert_private_directory_acl,
        )

        try:
            assert_private_directory_acl(target)
            with HeldWindowsFile(
                guardian,
                maximum_bytes=_MAXIMUM_GUARDIAN_BYTES,
            ) as held:
                return "sha256:" + held.sha256()
        except WindowsFileBoundaryError as exc:
            raise WindowsInstallError(str(exc)) from exc
    payload = _read_private(guardian, maximum_bytes=_MAXIMUM_GUARDIAN_BYTES)
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def load_windows_install_locator(
    path: Path,
    *,
    expected_version: str | None = None,
) -> dict[str, Any]:
    try:
        payload = _read_private(path, maximum_bytes=_MAXIMUM_LOCATOR_BYTES)
    except LocalMachineError as exc:
        raise WindowsInstallError(str(exc)) from exc
    value = parse_json_strict(payload)
    if not isinstance(value, dict):
        raise WindowsInstallError("Windows install locator is not an object")
    validate("windows-install-locator", value)
    if expected_version is not None and value["version"] != expected_version:
        raise WindowsInstallError("Windows install locator version mismatch")
    target = Path(value["target"])
    guardian = Path(value["guardian"])
    manifest_path = Path(value["assets_manifest"])
    if not target.is_absolute() or not guardian.is_absolute() or not manifest_path.is_absolute():
        raise WindowsInstallError("Windows install locator path is not absolute")
    if not _same_path(guardian, target / "Scripts" / "guardian.exe"):
        raise WindowsInstallError("Windows install locator launcher path mismatch")
    expected_manifest_path = target / "Integrity" / "windows-asset-manifest.json"
    if not _same_path(manifest_path, expected_manifest_path):
        raise WindowsInstallError("Windows install locator asset path mismatch")
    manifest = load_windows_asset_manifest(manifest_path)
    verification = verify_windows_asset_manifest(
        manifest,
        assets_directory=manifest_path.parent,
    )
    if value["assets_manifest_digest"] != verification["manifest_digest"]:
        raise WindowsInstallError("Windows install locator asset digest mismatch")
    if not guardian.is_file():
        raise WindowsInstallError("Windows install locator launcher is absent")
    guardian_digest = _installed_guardian_digest(target, guardian)
    if value["guardian_digest"] != guardian_digest:
        raise WindowsInstallError("Windows install locator launcher digest mismatch")
    return value


def windows_installation_status(
    path: Path,
    *,
    expected_version: str,
) -> dict[str, Any]:
    locator = load_windows_install_locator(path, expected_version=expected_version)
    target = Path(locator["target"])
    return {
        "status": "INSTALLED_UNINITIALIZED",
        "coverage": "UNKNOWN",
        "version": locator["version"],
        "install_source": "explicit-user-locator",
        "install_locator": str(path.absolute()),
        "guardian": locator["guardian"],
        "guardian_digest": locator["guardian_digest"],
        "windows_assets": str(target / "Integrity"),
        "start_here": str(target / "Integrity" / "START-HERE-RU.md"),
        "agent_contract": str(target / "Integrity" / "AGENTS.md"),
        "assets_manifest_digest": locator["assets_manifest_digest"],
        "next_command": "guardian machine-init --help",
        "imports_remote_memory": False,
        "production_authority": False,
    }


__all__ = [
    "WindowsInstallError",
    "default_windows_install_locator_path",
    "load_windows_install_locator",
    "windows_installation_status",
]
