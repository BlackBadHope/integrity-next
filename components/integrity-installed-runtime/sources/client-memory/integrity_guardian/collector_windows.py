"""Windows execution backend for digest-pinned customer collectors."""

from __future__ import annotations

import os
import secrets
import tempfile
from pathlib import Path

from ._windows_files import (
    HeldWindowsDirectory,
    WindowsFileBoundaryError,
    create_private_directory,
    remove_private_directory_tree,
)
from ._windows_job import (
    WindowsJobBoundaryError,
    collector_environment,
    run_windows_job,
)
from .collector import (
    CollectorBoundaryError,
    CollectorProfile,
    _build_collector_result,
    _parse_output,
    _require_verified_windows_profile,
    _VerifiedCollectorProfile,
)
from .collector_windows_bundle import HeldWindowsApplication


def _private_working_directory() -> Path:
    parent = Path(tempfile.gettempdir()).absolute()
    for _ in range(16):
        target = parent / f"integrity-collector-{secrets.token_hex(16)}"
        if target.exists():
            continue
        return create_private_directory(target)
    raise CollectorBoundaryError("private Windows collector directory unavailable")


def run_collector_windows(
    verified_profile: CollectorProfile | _VerifiedCollectorProfile,
) -> dict[str, object]:
    """Run one exact PE executable inside a bounded Win32 Job Object."""

    if os.name != "nt":
        raise CollectorBoundaryError("Windows collector backend requires Windows")
    verified = _require_verified_windows_profile(verified_profile)
    profile = verified.profile
    if profile.executable.suffix.lower() != ".exe":
        raise CollectorBoundaryError("Windows collector executable must be .exe")
    working_directory = _private_working_directory()
    failure: Exception | None = None
    try:
        try:
            with (
                HeldWindowsDirectory(working_directory),
                HeldWindowsApplication(
                    profile.executable,
                    profile.executable_digest,
                    profile.application_files,
                ) as executable,
            ):
                return_code, stdout_payload, stderr_payload = (
                    run_windows_job(
                        str(executable.path),
                        profile.argv,
                        working_directory=str(working_directory),
                        environment=collector_environment(
                            profile.credential_reference
                        ),
                        timeout_seconds=profile.timeout_seconds,
                        maximum_output_bytes=profile.max_output_bytes,
                    )
                )
        except (WindowsFileBoundaryError, WindowsJobBoundaryError) as exc:
            raise CollectorBoundaryError(str(exc)) from exc
        if return_code != 0:
            raise CollectorBoundaryError(
                f"collector exited nonzero: {return_code}"
            )
        if len(stdout_payload) > profile.max_output_bytes or len(
            stderr_payload
        ) > profile.max_output_bytes:
            raise CollectorBoundaryError("collector output exceeded bound")
        document, facts = _parse_output(stdout_payload)
        return _build_collector_result(
            profile,
            document,
            facts,
            stdout_payload,
            profile_digest=verified.profile_digest,
        )
    except Exception as exc:
        failure = exc
        raise
    finally:
        try:
            remove_private_directory_tree(working_directory)
        except (OSError, WindowsFileBoundaryError) as exc:
            message = "collector working directory cleanup failed"
            if failure is not None:
                raise CollectorBoundaryError(message) from failure
            raise CollectorBoundaryError(message) from exc
