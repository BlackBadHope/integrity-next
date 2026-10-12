"""Read-only local sensor primitives.

This module has no networking and no remediation interface.
"""

from __future__ import annotations

import errno
import fnmatch
import hashlib
import os
import stat
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .hashing import digest_object, sha256_digest
from .schemas import validate
from .signing import Ed25519Signer


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("sensor clock must return a timezone-aware datetime")
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _file_digest(path: Path, expected: os.stat_result) -> str:
    hasher = hashlib.sha256()
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino)
        ):
            raise OSError(errno.ESTALE, "observed file changed before open")
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                hasher.update(chunk)
        finished = os.fstat(descriptor)
        if (
            finished.st_size,
            finished.st_mtime_ns,
            finished.st_ctime_ns,
        ) != (
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        ):
            raise OSError(errno.ESTALE, "observed file changed while hashing")
    finally:
        os.close(descriptor)
    return f"sha256:{hasher.hexdigest()}"


class LinuxSensor:
    def __init__(
        self,
        *,
        tenant_id: str,
        sensor_id: str,
        node_id: str,
        signer: Ed25519Signer,
        exclusions: Iterable[str] = (),
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self.tenant_id = tenant_id
        self.sensor_id = sensor_id
        self.node_id = node_id
        self.signer = signer
        self.exclusions = tuple(exclusions)
        self.clock = clock
        self._sequence = 0
        self._previous_digest: str | None = None
        self._last_clock: datetime | None = None

    def _is_excluded(self, path: Path) -> bool:
        rendered = os.fspath(path)
        return any(fnmatch.fnmatchcase(rendered, pattern) for pattern in self.exclusions)

    def _evidence(self, path: Path) -> tuple[str, str | None, dict[str, Any], str]:
        if self._is_excluded(path):
            return "unknown", None, {"coverage": "excluded"}, "file"

        try:
            details = path.lstat()
            metadata: dict[str, Any] = {
                "mode": stat.S_IMODE(details.st_mode),
                "uid": details.st_uid,
                "gid": details.st_gid,
                "size": details.st_size,
                "mtime_ns": details.st_mtime_ns,
            }
            if stat.S_ISLNK(details.st_mode):
                target = os.readlink(path)
                metadata["symlink_target"] = target
                return "present", sha256_digest(os.fsencode(target)), metadata, "file"
            if stat.S_ISREG(details.st_mode):
                return "present", _file_digest(path, details), metadata, "file"
            if stat.S_ISDIR(details.st_mode):
                return "present", None, metadata, "directory"
            metadata["special_file"] = True
            return "present", None, metadata, "file"
        except FileNotFoundError:
            return "absent", None, {"error_kind": "not-found"}, "file"
        except OSError as exc:
            return (
                "sensor-gap",
                None,
                {"error_kind": type(exc).__name__, "errno": exc.errno},
                "file",
            )

    def observe_path(self, path: Path) -> dict[str, Any]:
        clock_value = self.clock()
        observed_at = _timestamp(clock_value)
        state, content_digest, metadata, kind = self._evidence(path)
        if self._last_clock is not None and clock_value < self._last_clock:
            state = "sensor-gap"
            content_digest = None
            metadata = {
                "error_kind": "clock-rollback",
                "previous_observed_at": _timestamp(self._last_clock),
            }
        unsigned: dict[str, Any] = {
            "protocol": "integrity-guardian/observation/v1",
            "observation_id": "observation:pending",
            "tenant_id": self.tenant_id,
            "sensor_id": self.sensor_id,
            "node_id": self.node_id,
            "sequence": self._sequence,
            "observed_at": observed_at,
            "layer": "L1",
            "subject": {"kind": kind, "identity": os.fspath(path)},
            "evidence": {
                "state": state,
                "content_digest": content_digest,
                "metadata": metadata,
            },
            "previous_observation_digest": self._previous_digest,
        }
        identity = digest_object(unsigned, domain="observation-identity-v1").split(":", 1)[1]
        unsigned["observation_id"] = f"observation:{identity}"
        signed = self.signer.sign(unsigned)
        validate("observation", signed)
        self._previous_digest = digest_object(signed, domain="observation-chain-v1")
        if self._last_clock is None or clock_value > self._last_clock:
            self._last_clock = clock_value
        self._sequence += 1
        return signed

    def observe(self, paths: Iterable[Path]) -> list[dict[str, Any]]:
        return [self.observe_path(path) for path in paths]
