"""Immutable flat application-bundle custody for Windows collectors."""

from __future__ import annotations

import os
from contextlib import AbstractContextManager, ExitStack
from pathlib import Path

from ._windows_files import (
    HeldWindowsDirectory,
    HeldWindowsFile,
    WindowsFileBoundaryError,
    assert_private_directory_acl,
)
from .collector import CollectorApplicationFile, CollectorBoundaryError

_MAXIMUM_APPLICATION_FILE_BYTES = 512 * 1024 * 1024
_MAXIMUM_APPLICATION_BUNDLE_BYTES = 1024 * 1024 * 1024


class HeldWindowsApplication(AbstractContextManager["HeldWindowsApplication"]):
    """Hold every admitted file in one exact private flat bundle."""

    def __init__(
        self,
        executable: Path,
        executable_digest: str,
        application_files: tuple[CollectorApplicationFile, ...],
    ) -> None:
        self._stack = ExitStack()
        self.executable: HeldWindowsFile | None = None
        try:
            directory = executable.parent
            self._stack.enter_context(HeldWindowsDirectory(directory))
            assert_private_directory_acl(directory)

            expected = {
                executable.name.casefold(),
                *(item.relative_path.casefold() for item in application_files),
            }
            actual: set[str] = set()
            unsafe: list[str] = []
            with os.scandir(directory) as entries:
                for entry in entries:
                    if entry.is_file(follow_symlinks=False):
                        actual.add(entry.name.casefold())
                    else:
                        unsafe.append(entry.name)
            if unsafe or actual != expected:
                raise CollectorBoundaryError(
                    "collector application directory contents mismatch"
                )

            held_executable = self._stack.enter_context(
                HeldWindowsFile(
                    executable,
                    maximum_bytes=_MAXIMUM_APPLICATION_FILE_BYTES,
                )
            )
            if f"sha256:{held_executable.sha256()}" != executable_digest:
                raise CollectorBoundaryError(
                    "collector executable digest mismatch"
                )
            total = held_executable.size
            for item in application_files:
                held = self._stack.enter_context(
                    HeldWindowsFile(
                        directory / item.relative_path,
                        maximum_bytes=_MAXIMUM_APPLICATION_FILE_BYTES,
                    )
                )
                if f"sha256:{held.sha256()}" != item.content_digest:
                    raise CollectorBoundaryError(
                        "collector application file digest mismatch"
                    )
                total += held.size
                if total > _MAXIMUM_APPLICATION_BUNDLE_BYTES:
                    raise CollectorBoundaryError(
                        "collector application bundle size rejected"
                    )
            self.executable = held_executable
        except WindowsFileBoundaryError as exc:
            self.close()
            raise CollectorBoundaryError(str(exc)) from exc
        except Exception:
            self.close()
            raise

    @property
    def path(self) -> Path:
        if self.executable is None:
            raise CollectorBoundaryError(
                "collector application custody is closed"
            )
        return self.executable.path

    def close(self) -> None:
        self.executable = None
        self._stack.close()

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()
