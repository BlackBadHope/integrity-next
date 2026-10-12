"""Windows profile and result custody for the native collector boundary."""

from __future__ import annotations

import os
from pathlib import Path

from ._windows_files import (
    HeldWindowsFile,
    WindowsFileBoundaryError,
    assert_private_directory_acl,
    create_private_directory_tree,
    set_private_directory_acl,
)
from .collector import CollectorBoundaryError

_MAXIMUM_PROFILE_BYTES = 1024 * 1024


def load_profile_windows_payload(path: Path, expected_digest: str | None) -> bytes:
    """Read one profile through a held handle and mandatory external pin."""

    if expected_digest is None:
        raise CollectorBoundaryError(
            "Windows collector profile digest is required"
        )
    try:
        with HeldWindowsFile(
            path,
            maximum_bytes=_MAXIMUM_PROFILE_BYTES,
        ) as profile:
            if f"sha256:{profile.sha256()}" != expected_digest:
                raise CollectorBoundaryError(
                    "collector profile digest mismatch"
                )
            return profile.read_bytes()
    except WindowsFileBoundaryError as exc:
        raise CollectorBoundaryError(str(exc)) from exc


def write_collector_result_windows(
    output_directory: Path,
    name: str,
    payload: bytes,
) -> Path:
    """Write one content-addressed result under exact Windows DACL custody."""

    try:
        directory = create_private_directory_tree(output_directory)
        target = directory / name
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        try:
            descriptor = os.open(target, flags, 0o600)
        except FileExistsError:
            with HeldWindowsFile(
                target,
                maximum_bytes=len(payload),
            ) as existing:
                if existing.read_bytes() != payload:
                    raise CollectorBoundaryError(
                        "collector result identity collision"
                    )
                assert_private_directory_acl(target)
            return target
        succeeded = False
        try:
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise CollectorBoundaryError(
                        "collector result write made no progress"
                    )
                view = view[written:]
            os.fsync(descriptor)
            succeeded = True
        finally:
            os.close(descriptor)
            if not succeeded:
                try:
                    target.unlink()
                except FileNotFoundError:
                    pass
        try:
            set_private_directory_acl(target)
            assert_private_directory_acl(target)
        except Exception:
            target.unlink()
            raise
        return target
    except WindowsFileBoundaryError as exc:
        raise CollectorBoundaryError(str(exc)) from exc
