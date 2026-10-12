"""Read-only host capability profiling for portable Integrity routes.

The profile reports which local backend contracts are available.  It does not
collect host identity, grant authority, install dependencies or execute an
adapter.
"""

from __future__ import annotations

import importlib.util
import os
import platform
import shutil
import sys
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any


class PlatformFamily(StrEnum):
    """Closed routing families; unknown systems remain explicit."""

    LINUX = "linux"
    WINDOWS = "windows"
    MACOS = "macos"
    BSD = "bsd"
    POSIX_OTHER = "posix-other"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class RuntimeFacts:
    """Sanitized facts used to select local backend contracts."""

    system: str
    os_name: str
    machine: str
    python_implementation: str
    python_version: tuple[int, int, int]
    secure_posix_custody: bool
    windows_private_custody: bool
    linux_procfs: bool
    resource_limits: bool
    bubblewrap: bool
    prlimit: bool
    python314: bool


PORTABLE_COMMANDS = (
    "guardian version",
    "guardian status",
    "guardian capabilities",
    "guardian platform-profile",
    "guardian canonicalize",
    "guardian digest",
    "guardian validate",
    "guardian governance-verify",
)

STATEFUL_COMMANDS = (
    "guardian tenant-init",
    "guardian tenant-verify",
    "guardian agent-preflight",
    "guardian observer-anchor-init",
    "guardian observer-anchor-verify",
    "guardian observer-anchor-advance",
)


def _platform_family(system: str, os_name: str) -> PlatformFamily:
    normalized = system.casefold()
    if normalized == "linux":
        return PlatformFamily.LINUX
    if normalized == "windows":
        return PlatformFamily.WINDOWS
    if normalized == "darwin":
        return PlatformFamily.MACOS
    if normalized.endswith("bsd"):
        return PlatformFamily.BSD
    if os_name == "posix":
        return PlatformFamily.POSIX_OTHER
    return PlatformFamily.UNKNOWN


def _architecture(machine: str) -> str:
    normalized = machine.strip().casefold()
    if normalized in {"amd64", "x64", "x86_64"}:
        return "x86_64"
    if normalized in {"aarch64", "arm64"}:
        return "aarch64"
    if normalized in {"i386", "i686", "x86"}:
        return "x86"
    return normalized or "unknown"


def _supports_secure_posix_custody() -> bool:
    if os.name != "posix" or not hasattr(os, "geteuid") or not hasattr(os, "O_NOFOLLOW"):
        return False
    if importlib.util.find_spec("fcntl") is None:
        return False
    required_dir_fd = (os.open, os.mkdir, os.unlink, os.rename, os.stat)
    return all(function in os.supports_dir_fd for function in required_dir_fd)


def detect_runtime_facts() -> RuntimeFacts:
    """Inspect bounded non-identifying local runtime features."""

    return RuntimeFacts(
        system=platform.system(),
        os_name=os.name,
        machine=platform.machine(),
        python_implementation=platform.python_implementation(),
        python_version=(
            sys.version_info.major,
            sys.version_info.minor,
            sys.version_info.micro,
        ),
        secure_posix_custody=_supports_secure_posix_custody(),
        windows_private_custody=(
            os.name == "nt" and importlib.util.find_spec("msvcrt") is not None
        ),
        linux_procfs=Path("/proc/self/fd").is_dir(),
        resource_limits=importlib.util.find_spec("resource") is not None,
        bubblewrap=shutil.which("bwrap") is not None,
        prlimit=shutil.which("prlimit") is not None,
        python314=shutil.which("python3.14") is not None,
    )


def _required_backend(family: PlatformFamily, capability: str) -> str:
    names = {
        "private-state-custody": {
            PlatformFamily.WINDOWS: "windows-acl-locking-custody-v1",
            PlatformFamily.MACOS: "macos-private-state-custody-v1",
            PlatformFamily.BSD: "bsd-private-state-custody-v1",
        },
        "live-snapshot-collection": {
            PlatformFamily.WINDOWS: "windows-snapshot-collector-v1",
            PlatformFamily.MACOS: "macos-snapshot-collector-v1",
            PlatformFamily.BSD: "bsd-snapshot-collector-v1",
        },
        "local-adversarial-rehearsal": {
            PlatformFamily.WINDOWS: "windows-sandbox-rehearsal-v1",
            PlatformFamily.MACOS: "macos-sandbox-rehearsal-v1",
            PlatformFamily.BSD: "bsd-sandbox-rehearsal-v1",
        },
    }
    return names.get(capability, {}).get(
        family,
        f"{family.value}-{capability}-adapter-v1",
    )


def _backend(
    *,
    capability: str,
    status: str,
    selected: str | None,
    required: str | None,
    commands: tuple[str, ...],
    reason_codes: tuple[str, ...] = (),
) -> dict[str, object]:
    return {
        "capability": capability,
        "status": status,
        "selected_backend": selected,
        "required_backend": required,
        "commands": list(commands),
        "reason_codes": list(reason_codes),
        "execution_authority": False,
    }


def build_platform_profile(
    version: str,
    facts: RuntimeFacts | None = None,
) -> dict[str, Any]:
    """Build one unsigned self-report without host identity or target authority."""

    current = facts or detect_runtime_facts()
    family = _platform_family(current.system, current.os_name)

    if (
        family is PlatformFamily.WINDOWS
        and current.windows_private_custody
    ):
        custody = _backend(
            capability="private-state-custody",
            status="alpha-ready",
            selected="windows-acl-locking-custody-v1",
            required=None,
            commands=STATEFUL_COMMANDS,
            reason_codes=("native-private-state-alpha-no-production-soak",),
        )
    elif current.secure_posix_custody:
        custody = _backend(
            capability="private-state-custody",
            status="ready",
            selected="posix-descriptor-custody-v1",
            required=None,
            commands=STATEFUL_COMMANDS,
        )
    else:
        custody = _backend(
            capability="private-state-custody",
            status="adapter-required",
            selected=None,
            required=_required_backend(family, "private-state-custody"),
            commands=STATEFUL_COMMANDS,
            reason_codes=("native-private-state-backend-not-admitted",),
        )

    linux_collector_ready = (
        family is PlatformFamily.LINUX
        and current.linux_procfs
        and current.resource_limits
        and current.secure_posix_custody
    )
    windows_collector_ready = family is PlatformFamily.WINDOWS
    collector_ready = linux_collector_ready or windows_collector_ready
    selected_collector = None
    if linux_collector_ready:
        selected_collector = "linux-procfs-collector-v1"
    elif windows_collector_ready:
        selected_collector = "windows-job-object-collector-v1"
    collector = _backend(
        capability="live-snapshot-collection",
        status="ready" if collector_ready else "adapter-required",
        selected=selected_collector,
        required=(
            None
            if collector_ready
            else _required_backend(family, "live-snapshot-collection")
        ),
        commands=("guardian collector-run",),
        reason_codes=(
            ()
            if collector_ready
            else ("native-live-collector-not-admitted",)
        ),
    )

    genesis_tools = (
        family is PlatformFamily.LINUX
        and current.bubblewrap
        and current.prlimit
        and current.python314
    )
    if genesis_tools:
        rehearsal = _backend(
            capability="local-adversarial-rehearsal",
            status="alpha-ready",
            selected="linux-bubblewrap-rehearsal-v1",
            required=None,
            commands=(),
        )
    elif family is PlatformFamily.LINUX:
        missing = tuple(
            name
            for name, present in (
                ("bubblewrap-missing", current.bubblewrap),
                ("prlimit-missing", current.prlimit),
                ("python3.14-missing", current.python314),
            )
            if not present
        )
        rehearsal = _backend(
            capability="local-adversarial-rehearsal",
            status="prerequisite-missing",
            selected="linux-bubblewrap-rehearsal-v1",
            required=None,
            commands=(),
            reason_codes=missing,
        )
    else:
        rehearsal = _backend(
            capability="local-adversarial-rehearsal",
            status="adapter-required",
            selected=None,
            required=_required_backend(family, "local-adversarial-rehearsal"),
            commands=(),
            reason_codes=("native-containment-backend-not-admitted",),
        )

    backends = [
        _backend(
            capability="portable-protocol-core",
            status="ready",
            selected="python-portable-core-v1",
            required=None,
            commands=PORTABLE_COMMANDS,
        ),
        custody,
        collector,
        rehearsal,
        _backend(
            capability="external-action",
            status="adapter-required",
            selected=None,
            required="target-specific-external-action-adapter",
            commands=(),
            reason_codes=("integrity-core-has-no-actuator",),
        ),
    ]
    missing_backends = [
        {
            "capability": item["capability"],
            "required_backend": item["required_backend"],
            "reason_codes": item["reason_codes"],
        }
        for item in backends
        if item["status"] in {"adapter-required", "prerequisite-missing"}
    ]
    return {
        "protocol": "integrity-guardian/platform-profile/v1",
        "product": "Integrity Guardian",
        "version": version,
        "self_reported": True,
        "signed": False,
        "host_identity_collected": False,
        "runtime": {
            "family": family.value,
            "os_name": current.os_name,
            "architecture": _architecture(current.machine),
            "python_implementation": current.python_implementation,
            "python_version": ".".join(str(part) for part in current.python_version),
        },
        "readiness": {
            "overall": "portable-core-ready",
            "portable_core": "ready",
            "stateful_runtime": custody["status"],
            "live_observation": collector["status"],
            "local_rehearsal": rehearsal["status"],
        },
        "backends": backends,
        "unknowns": missing_backends,
        "recommended_first_route": [
            "guardian platform-profile",
            "guardian capabilities",
            "guardian governance-verify",
            "guardian canonicalize/digest on a bounded local fixture",
        ],
        "authority_boundary": {
            "credentials": False,
            "network": False,
            "production_authority": False,
            "remediation": False,
            "tool_invocation": False,
        },
    }
