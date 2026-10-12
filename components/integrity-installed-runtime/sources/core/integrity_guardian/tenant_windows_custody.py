"""Windows-native custody backend for customer-local tenant workspaces."""

from __future__ import annotations

from contextlib import ExitStack
from pathlib import Path
from typing import Any, Protocol

from ._windows_files import (
    HeldWindowsDirectory,
    WindowsFileBoundaryError,
    assert_private_directory_acl,
    create_private_directory_tree,
    inspect_private_directory_acl,
)
from .canonical import canonical_bytes, parse_json_strict
from .schemas import validate
from .windows_private_state import (
    WindowsPrivateStateError,
    open_private_file_descriptor,
    read_private_bytes,
    write_private_once,
)

_MAXIMUM_TENANT_PROFILE_BYTES = 4 * 1024 * 1024
_STATE_KINDS = frozenset({"ledger", "checkpoints", "receipts", "reports"})


class WindowsTenantCustodyError(RuntimeError):
    """Raised before a Windows tenant workspace boundary can be weakened."""


class _Workspace(Protocol):
    state_root: Path
    tenant_id: str
    namespace: str
    tenant_root: Path
    profile_path: Path


def _translate(exc: Exception) -> WindowsTenantCustodyError:
    return WindowsTenantCustodyError(str(exc))


def _private_directories(workspace: _Workspace) -> tuple[Path, ...]:
    return (
        workspace.state_root,
        workspace.state_root / "tenants",
        workspace.tenant_root,
        *(workspace.tenant_root / kind for kind in sorted(_STATE_KINDS)),
    )


def initialize_windows_workspace(
    workspace: _Workspace,
    profile: dict[str, Any],
) -> None:
    """Create an exact-DACL workspace, idempotent only for identical identity."""

    expected = canonical_bytes(profile) + b"\n"
    try:
        for directory in _private_directories(workspace):
            create_private_directory_tree(directory)
        try:
            existing = read_private_bytes(
                workspace.profile_path,
                maximum_bytes=_MAXIMUM_TENANT_PROFILE_BYTES,
            )
        except WindowsPrivateStateError:
            if not workspace.profile_path.exists():
                write_private_once(workspace.profile_path, expected)
                existing = expected
            else:
                raise
        if existing != expected:
            raise WindowsTenantCustodyError(
                "existing tenant profile does not match"
            )
    except (
        OSError,
        WindowsFileBoundaryError,
        WindowsPrivateStateError,
    ) as exc:
        raise _translate(exc) from exc


def verify_windows_workspace(
    workspace: _Workspace,
    *,
    expected_owner_sid: str | None = None,
) -> dict[str, Any]:
    """Verify the complete directory lineage, DACLs and canonical profile."""

    try:
        with ExitStack() as stack:
            for directory in _private_directories(workspace):
                assert_private_directory_acl(
                    directory,
                    expected_owner_sid=expected_owner_sid,
                )
                stack.enter_context(HeldWindowsDirectory(directory))
            payload = read_private_bytes(
                workspace.profile_path,
                maximum_bytes=_MAXIMUM_TENANT_PROFILE_BYTES,
                expected_owner_sid=expected_owner_sid,
            )
            profile = parse_json_strict(payload)
            if not isinstance(profile, dict) or canonical_bytes(profile) + b"\n" != payload:
                raise WindowsTenantCustodyError(
                    "tenant profile is not canonical"
                )
            validate("tenant-profile", profile)
            if (
                profile["tenant_id"] != workspace.tenant_id
                or profile["namespace"] != workspace.namespace
            ):
                raise WindowsTenantCustodyError(
                    "tenant profile identity mismatch"
                )
            return profile
    except (
        OSError,
        WindowsFileBoundaryError,
        WindowsPrivateStateError,
    ) as exc:
        raise _translate(exc) from exc


def audit_windows_workspace(
    workspace: _Workspace,
    *,
    expected_owner_sid: str,
) -> dict[str, Any]:
    """Read and verify another principal's tenant under an external SID pin."""

    profile = verify_windows_workspace(
        workspace,
        expected_owner_sid=expected_owner_sid,
    )
    custody = inspect_private_directory_acl(
        workspace.tenant_root,
        expected_owner_sid=expected_owner_sid,
    )
    return {
        "profile": profile,
        "custody": custody,
        "audit_only": True,
        "production_authority": False,
    }


def open_windows_artifact(
    workspace: _Workspace,
    kind: str,
    name: str,
    *,
    flags: int,
) -> int:
    """Open one regular artifact under the already verified tenant namespace."""

    if kind not in _STATE_KINDS:
        raise WindowsTenantCustodyError("unknown tenant state class")
    verify_windows_workspace(workspace)
    directory = workspace.tenant_root / kind
    try:
        with HeldWindowsDirectory(directory):
            return open_private_file_descriptor(
                directory / name,
                flags=flags,
            )
    except (
        OSError,
        WindowsFileBoundaryError,
        WindowsPrivateStateError,
    ) as exc:
        raise _translate(exc) from exc


__all__ = [
    "WindowsTenantCustodyError",
    "audit_windows_workspace",
    "initialize_windows_workspace",
    "open_windows_artifact",
    "verify_windows_workspace",
]
