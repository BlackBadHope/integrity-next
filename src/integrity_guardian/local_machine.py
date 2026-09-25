"""Discoverable local-machine bootstrap and final zero-day witness.

The profile is an explicit locator, not a disk scanner.  It contains paths and
loopback configuration only; credentials, remote memory and production
authority are structurally excluded.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import socket
import stat
import threading
import urllib.request
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any

from jsonschema import ValidationError

from .canonical import canonical_bytes, parse_json_strict
from .hashing import digest_object
from .schemas import validate
from .seed_catalog import SeedCatalog, validate_seed_namespace
from .tenant import (
    TenantWorkspace,
    build_unenrolled_tenant_profile,
    tenant_enrollment_status,
    validate_tenant_id,
    verify_tenant_governance,
)

_MAXIMUM_PROFILE_BYTES = 1024 * 1024
_MAXIMUM_CREDENTIAL_SOURCE_BYTES = 4 * 1024 * 1024
_MAXIMUM_SCAN_FILES = 4096
_MAXIMUM_SCAN_BYTES = 64 * 1024 * 1024
_MAXIMUM_PRIVATE_OUTPUT_RESERVATION_BYTES = 4096
_MAXIMUM_PRIVATE_OUTPUT_FINAL_BYTES = 4 * 1024 * 1024
_PRIVATE_OUTPUT_RESERVATION_PROTOCOL = (
    "integrity-guardian/private-output-reservation/v1"
)
_PRIVATE_OUTPUT_RECONCILIATION_PROTOCOL = (
    "integrity-guardian/private-output-reconciliation/v1"
)
_PRIVATE_OUTPUT_PURPOSE_SCHEMAS = MappingProxyType(
    {
        "local-machine-profile": "local-machine-profile",
        "readonly-operation-receipt": "readonly-operation-receipt",
        "zero-day-seed-build-receipt": "zero-day-seed-build-receipt",
    }
)
PRIVATE_DOCUMENT_SCHEMAS = (
    "windows-offline-install-receipt",
    "windows-host-collector-build-receipt",
    "windows-install-locator",
    "windows-seed-persistence-removal-receipt",
    "windows-seed-persistence-receipt",
    "windows-seed-persistence-witness",
)
PRIVATE_DOCUMENT_READ_SCHEMAS = (
    "local-machine-profile",
    "zero-day-final-witness",
    *PRIVATE_DOCUMENT_SCHEMAS,
)
_SECRET_MARKERS = (
    "secret",
    "password",
    "passwd",
    "token",
    "cookie",
    "private_key",
    "api_key",
    "credential",
)


class LocalMachineError(ValueError):
    """Raised before local bootstrap or witness semantics become ambiguous."""


class PrivateOutputReconciliationRequired(LocalMachineError):
    """Raised when an unfinished private output makes retry unsafe."""

    def __init__(self, status: dict[str, Any]) -> None:
        super().__init__(
            "private output outcome is unknown; reconciliation required and "
            "automatic retry forbidden"
        )
        self.status = status


class _PrivateOutputReservation:
    """One process-local, single-use guard for an exact reservation file."""

    __slots__ = (
        "_consumed",
        "_descriptor",
        "_identity",
        "_lock",
        "_path",
        "_payload",
        "_purpose",
    )

    def __init__(
        self,
        *,
        path: Path,
        purpose: str,
        payload: bytes,
        descriptor: int,
    ) -> None:
        details = os.fstat(descriptor)
        self._path = path
        self._purpose = purpose
        self._payload = payload
        self._descriptor: int | None = descriptor
        self._identity = (details.st_dev, details.st_ino)
        self._consumed = False
        self._lock = threading.Lock()


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def default_local_profile_path() -> Path:
    explicit = os.environ.get("INTEGRITY_LOCAL_PROFILE")
    if explicit:
        return Path(explicit).absolute()
    if os.name == "nt":
        local = os.environ.get("LOCALAPPDATA")
        if not local:
            raise LocalMachineError("LOCALAPPDATA is required for Windows bootstrap")
        return Path(local) / "IntegrityGuardian" / "active-profile.json"
    state_home = os.environ.get("XDG_STATE_HOME")
    root = Path(state_home) if state_home else Path.home() / ".local" / "state"
    return root / "integrity-guardian" / "active-profile.json"


def _path_lexists(path: Path) -> bool:
    return os.path.lexists(os.fspath(path))


def _assert_no_symlink_ancestors(path: Path) -> None:
    """Reject every existing POSIX symlink in one absolute path lineage."""

    if os.name == "nt":
        return
    target = path.absolute()
    current = Path(target.anchor)
    for component in target.parts[1:]:
        current /= component
        if _path_lexists(current) and current.is_symlink():
            raise LocalMachineError("private output symlink ancestor rejected")


def _fsync_directory(path: Path) -> None:
    """Persist one POSIX directory entry boundary before returning."""

    if os.name == "nt":
        return
    _assert_no_symlink_ancestors(path)
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISDIR(details.st_mode) or details.st_uid != os.geteuid():
            raise LocalMachineError("private output parent owner or type rejected")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _prepare_private_directory(path: Path) -> Path:
    target = path.absolute()
    if os.name == "nt":
        from ._windows_files import (
            WindowsFileBoundaryError,
            create_private_directory_tree,
        )

        try:
            return create_private_directory_tree(target)
        except WindowsFileBoundaryError as exc:
            raise LocalMachineError("private output parent custody rejected") from exc

    _assert_no_symlink_ancestors(target)
    missing: list[Path] = []
    current = target
    while not _path_lexists(current):
        missing.append(current)
        if current.parent == current:
            raise LocalMachineError("private output parent root is absent")
        current = current.parent
    if current.is_symlink() or not current.is_dir():
        raise LocalMachineError("private output parent owner or type rejected")
    for directory in reversed(missing):
        os.mkdir(directory, mode=0o700)
        details = directory.lstat()
        if (
            not stat.S_ISDIR(details.st_mode)
            or details.st_uid != os.geteuid()
            or stat.S_IMODE(details.st_mode) != 0o700
        ):
            raise LocalMachineError("private output parent owner or mode rejected")
        _fsync_directory(directory.parent)
    _assert_no_symlink_ancestors(target)
    details = target.lstat()
    if not stat.S_ISDIR(details.st_mode) or details.st_uid != os.geteuid():
        raise LocalMachineError("private output parent owner or type rejected")
    if stat.S_IMODE(details.st_mode) != 0o700:
        raise LocalMachineError("private output parent mode rejected")
    return target


def _prepare_private_output(path: Path) -> Path:
    """Verify one absent output and prepare its exact-private parent only."""

    target = path.absolute()
    if _path_lexists(target):
        raise LocalMachineError("private output must be absent")
    _prepare_private_directory(target.parent)
    if _path_lexists(target):
        raise LocalMachineError("private output appeared during preparation")
    return target


def _create_held_private_output(path: Path, payload: bytes) -> int:
    """Create, persist and retain one private output identity."""

    target = _prepare_private_output(path)
    descriptor: int | None = None
    created = False
    if os.name == "nt":
        from .windows_private_state import open_private_file_descriptor

        descriptor = open_private_file_descriptor(
            target,
            flags=os.O_RDWR | os.O_CREAT | os.O_EXCL,
            share_write=False,
        )
    else:
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(target, flags, 0o600)
    created = True
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise LocalMachineError("private output reservation made no progress")
            view = view[written:]
        os.fsync(descriptor)
        if os.name != "nt":
            os.fchmod(descriptor, 0o600)
            _fsync_directory(target.parent)
        os.lseek(descriptor, 0, os.SEEK_SET)
        observed = bytearray()
        while chunk := os.read(descriptor, 64 * 1024):
            observed.extend(chunk)
        if not secrets.compare_digest(bytes(observed), payload):
            raise LocalMachineError("private output reservation verification failed")
        return descriptor
    except (LocalMachineError, OSError):
        if descriptor is not None:
            os.close(descriptor)
            descriptor = None
        if created:
            try:
                target.unlink()
            except FileNotFoundError:
                pass
            if os.name != "nt":
                _fsync_directory(target.parent)
        raise


def _validate_private_output_reservation_purpose(purpose: str) -> None:
    if purpose not in _PRIVATE_OUTPUT_PURPOSE_SCHEMAS:
        raise LocalMachineError("private output reservation purpose rejected")


def _parse_private_output_reservation(reservation: bytes) -> dict[str, str]:
    if not isinstance(reservation, bytes) or not (
        1 <= len(reservation) <= _MAXIMUM_PRIVATE_OUTPUT_RESERVATION_BYTES
    ):
        raise LocalMachineError("private output reservation size rejected")
    try:
        document = parse_json_strict(reservation)
    except (TypeError, ValueError) as exc:
        raise LocalMachineError("private output reservation is invalid") from exc
    if (
        not isinstance(document, dict)
        or set(document) != {"protocol", "purpose", "reservation_id"}
        or document.get("protocol") != _PRIVATE_OUTPUT_RESERVATION_PROTOCOL
        or not isinstance(document.get("purpose"), str)
        or not isinstance(document.get("reservation_id"), str)
        or not document["reservation_id"].startswith("private-output-reservation:")
        or len(document["reservation_id"]) != 91
        or any(
            character not in "0123456789abcdef"
            for character in document["reservation_id"].split(":", 1)[1]
        )
        or document["purpose"] not in _PRIVATE_OUTPUT_PURPOSE_SCHEMAS
        or canonical_bytes(document) + b"\n" != reservation
    ):
        raise LocalMachineError("private output reservation is invalid")
    return document


def _validate_private_output_reservation(reservation: bytes) -> None:
    _parse_private_output_reservation(reservation)


def _validated_private_output_status(document: dict[str, Any]) -> dict[str, Any]:
    validate("private-output-reconciliation-status", document)
    return document


def _private_output_commit_failure_status(
    status: dict[str, Any],
) -> dict[str, Any]:
    """Make every consumed-guard failure explicitly non-retryable."""

    if status["status"] == "UNKNOWN_OUTCOME":
        return status
    result = dict(status)
    result["status"] = "UNKNOWN_OUTCOME"
    result["reconciliation_required"] = True
    if status["status"] == "COMMITTED":
        result["reservation_state"] = "COMMITTED_OUTPUT_DURABILITY_UNCERTAIN"
    else:
        result["reservation_state"] = "OUTPUT_MISSING_AFTER_COMMIT_ATTEMPT"
    return _validated_private_output_status(result)


def private_output_reconciliation_status(
    path: Path,
    *,
    expected_purpose: str,
) -> dict[str, Any]:
    """Classify a private output without granting authority to retry it.

    An exact reservation left by another process is deliberately interpreted
    as an unknown outcome.  This function does not remove, replace or advance
    the reservation; a higher-level observer must reconcile the operation.
    """

    _validate_private_output_reservation_purpose(expected_purpose)
    target = path.absolute()
    expected_schema = _PRIVATE_OUTPUT_PURPOSE_SCHEMAS[expected_purpose]
    if not _path_lexists(target):
        return _validated_private_output_status({
            "protocol": _PRIVATE_OUTPUT_RECONCILIATION_PROTOCOL,
            "status": "NO_RESERVATION",
            "reservation_state": "ABSENT",
            "purpose": expected_purpose,
            "expected_schema": expected_schema,
            "purpose_match": None,
            "reservation_id": None,
            "reservation_digest": None,
            "final_output_digest": None,
            "reconciliation_required": False,
            "automatic_retry_allowed": False,
            "production_authority": False,
        })
    try:
        payload = _read_private(
            target,
            maximum_bytes=_MAXIMUM_PRIVATE_OUTPUT_FINAL_BYTES,
        )
    except (LocalMachineError, OSError):
        return _validated_private_output_status({
            "protocol": _PRIVATE_OUTPUT_RECONCILIATION_PROTOCOL,
            "status": "UNKNOWN_OUTCOME",
            "reservation_state": "NON_RESERVATION_OUTPUT_PRESENT",
            "purpose": expected_purpose,
            "expected_schema": expected_schema,
            "purpose_match": None,
            "reservation_id": None,
            "reservation_digest": None,
            "final_output_digest": None,
            "reconciliation_required": True,
            "automatic_retry_allowed": False,
            "production_authority": False,
        })
    try:
        reservation = _parse_private_output_reservation(payload)
    except LocalMachineError:
        reservation = None
    if reservation is not None:
        return _validated_private_output_status({
            "protocol": _PRIVATE_OUTPUT_RECONCILIATION_PROTOCOL,
            "status": "UNKNOWN_OUTCOME",
            "reservation_state": "RESERVATION_PRESENT",
            "purpose": expected_purpose,
            "expected_schema": expected_schema,
            "purpose_match": reservation["purpose"] == expected_purpose,
            "reservation_id": reservation["reservation_id"],
            "reservation_digest": "sha256:" + hashlib.sha256(payload).hexdigest(),
            "final_output_digest": None,
            "reconciliation_required": True,
            "automatic_retry_allowed": False,
            "production_authority": False,
        })
    try:
        final_output = parse_json_strict(payload)
        if (
            not isinstance(final_output, dict)
            or canonical_bytes(final_output) + b"\n" != payload
        ):
            raise LocalMachineError("private final output is not canonical")
        validate(expected_schema, final_output)
    except (LocalMachineError, TypeError, ValueError, ValidationError):
        return _validated_private_output_status({
            "protocol": _PRIVATE_OUTPUT_RECONCILIATION_PROTOCOL,
            "status": "UNKNOWN_OUTCOME",
            "reservation_state": "NON_RESERVATION_OUTPUT_PRESENT",
            "purpose": expected_purpose,
            "expected_schema": expected_schema,
            "purpose_match": None,
            "reservation_id": None,
            "reservation_digest": None,
            "final_output_digest": None,
            "reconciliation_required": True,
            "automatic_retry_allowed": False,
            "production_authority": False,
        })
    return _validated_private_output_status({
        "protocol": _PRIVATE_OUTPUT_RECONCILIATION_PROTOCOL,
        "status": "COMMITTED",
        "reservation_state": "COMMITTED_OUTPUT_PRESENT",
        "purpose": expected_purpose,
        "expected_schema": expected_schema,
        "purpose_match": True,
        "reservation_id": None,
        "reservation_digest": None,
        "final_output_digest": "sha256:" + hashlib.sha256(payload).hexdigest(),
        "reconciliation_required": False,
        "automatic_retry_allowed": False,
        "production_authority": False,
    })


def _reserve_private_output(path: Path, purpose: str) -> _PrivateOutputReservation:
    """Create and hold an exclusive single-use private reservation."""

    _validate_private_output_reservation_purpose(purpose)
    reservation = canonical_bytes(
        {
            "protocol": _PRIVATE_OUTPUT_RESERVATION_PROTOCOL,
            "purpose": purpose,
            "reservation_id": "private-output-reservation:" + secrets.token_hex(32),
        }
    ) + b"\n"
    try:
        descriptor = _create_held_private_output(path, reservation)
    except Exception as exc:
        if _path_lexists(path.absolute()):
            status = private_output_reconciliation_status(
                path,
                expected_purpose=purpose,
            )
            if status["status"] == "UNKNOWN_OUTCOME":
                raise PrivateOutputReconciliationRequired(status) from exc
        raise
    try:
        return _PrivateOutputReservation(
            path=path.absolute(),
            purpose=purpose,
            payload=reservation,
            descriptor=descriptor,
        )
    except Exception as exc:
        os.close(descriptor)
        status = private_output_reconciliation_status(
            path,
            expected_purpose=purpose,
        )
        raise PrivateOutputReconciliationRequired(status) from exc


def _release_private_output_reservation(
    reservation: _PrivateOutputReservation,
) -> Path:
    """Consume one guard without changing its on-disk unknown marker."""

    if not isinstance(reservation, _PrivateOutputReservation):
        raise LocalMachineError("private output reservation guard rejected")
    with reservation._lock:
        if reservation._consumed:
            raise LocalMachineError("private output reservation guard already consumed")
        reservation._consumed = True
        descriptor = reservation._descriptor
        reservation._descriptor = None
        if descriptor is not None:
            os.close(descriptor)
    return reservation._path


def _commit_private_output_reservation(
    reservation: _PrivateOutputReservation,
    document: dict[str, Any],
) -> Path:
    """Validate and atomically commit one held, purpose-bound reservation."""

    if not isinstance(reservation, _PrivateOutputReservation):
        raise LocalMachineError("private output reservation guard rejected")
    with reservation._lock:
        if reservation._consumed:
            raise LocalMachineError("private output reservation guard already consumed")
        reservation._consumed = True
        descriptor = reservation._descriptor
        reservation._descriptor = None
        try:
            if descriptor is None:
                raise LocalMachineError("private output reservation guard is closed")
            schema = _PRIVATE_OUTPUT_PURPOSE_SCHEMAS[reservation._purpose]
            validate(schema, document)
            payload = canonical_bytes(document) + b"\n"
            details = os.fstat(descriptor)
            if (details.st_dev, details.st_ino) != reservation._identity:
                raise LocalMachineError("private output reservation identity changed")
            os.lseek(descriptor, 0, os.SEEK_SET)
            observed = bytearray()
            while chunk := os.read(descriptor, 64 * 1024):
                observed.extend(chunk)
                if len(observed) > _MAXIMUM_PRIVATE_OUTPUT_RESERVATION_BYTES:
                    raise LocalMachineError("private output reservation size changed")
            if not secrets.compare_digest(bytes(observed), reservation._payload):
                raise LocalMachineError("private output reservation mismatch")
            target_details = reservation._path.lstat()
            if (
                not stat.S_ISREG(target_details.st_mode)
                or (target_details.st_dev, target_details.st_ino)
                != reservation._identity
            ):
                raise LocalMachineError("private output reservation path changed")
            if os.name == "nt":
                os.close(descriptor)
                descriptor = None
            try:
                return _write_private(reservation._path, payload)
            except Exception as exc:
                status = private_output_reconciliation_status(
                    reservation._path,
                    expected_purpose=reservation._purpose,
                )
                raise PrivateOutputReconciliationRequired(
                    _private_output_commit_failure_status(status)
                ) from exc
        except PrivateOutputReconciliationRequired:
            raise
        except Exception as exc:
            status = private_output_reconciliation_status(
                reservation._path,
                expected_purpose=reservation._purpose,
            )
            raise PrivateOutputReconciliationRequired(
                _private_output_commit_failure_status(status)
            ) from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)


def _write_private(path: Path, payload: bytes) -> Path:
    path = path.absolute()
    if os.name == "nt":
        from ._windows_files import create_private_directory_tree
        from .windows_private_state import (
            replace_private_bytes,
            write_private_once,
        )

        create_private_directory_tree(path.parent)
        if path.exists():
            replace_private_bytes(path, payload)
        else:
            write_private_once(path, payload)
        return path

    _assert_no_symlink_ancestors(path.parent)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _assert_no_symlink_ancestors(path.parent)
    path.parent.chmod(0o700)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(12)}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    succeeded = False
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise LocalMachineError("local profile write made no progress")
            view = view[written:]
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o600)
        os.replace(temporary, path)
        _fsync_directory(path.parent)
        succeeded = True
    finally:
        os.close(descriptor)
        if not succeeded:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
    return path


def _read_private(path: Path, *, maximum_bytes: int) -> bytes:
    path = path.absolute()
    if os.name == "nt":
        from .windows_private_state import read_private_bytes

        return read_private_bytes(path, maximum_bytes=maximum_bytes)
    _assert_no_symlink_ancestors(path.parent)
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise LocalMachineError("local profile is absent or unsafe") from exc
    try:
        details = os.fstat(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != os.geteuid()
            or stat.S_IMODE(details.st_mode) & 0o077
            or details.st_size > maximum_bytes
        ):
            raise LocalMachineError("local profile owner, mode or size rejected")
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 64 * 1024):
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _read_untrusted_bounded(path: Path, *, maximum_bytes: int) -> bytes:
    """Read a local regular staging file without granting it custody authority."""

    target = path.absolute()
    if os.name == "nt":
        from ._windows_files import HeldWindowsFile, WindowsFileBoundaryError

        try:
            with HeldWindowsFile(target, maximum_bytes=maximum_bytes) as held:
                return held.read_bytes()
        except WindowsFileBoundaryError as exc:
            raise LocalMachineError("staged document is absent or unsafe") from exc
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(target, flags)
    except OSError as exc:
        raise LocalMachineError("staged document is absent or unsafe") from exc
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or details.st_size > maximum_bytes:
            raise LocalMachineError("staged document type or size rejected")
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 64 * 1024):
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def store_private_document(
    *,
    input_path: Path,
    output_path: Path,
    schema: str,
) -> Path:
    if schema not in PRIVATE_DOCUMENT_SCHEMAS:
        raise LocalMachineError("private document schema is not admitted")
    if output_path.exists():
        raise LocalMachineError("private document output must be absent")
    payload = _read_untrusted_bounded(input_path, maximum_bytes=4 * 1024 * 1024)
    value = parse_json_strict(payload)
    if not isinstance(value, dict):
        raise LocalMachineError("private document must be an object")
    validate(schema, value)
    return _write_private(output_path, canonical_bytes(value) + b"\n")


def load_private_document(*, path: Path, schema: str) -> dict[str, Any]:
    if schema not in PRIVATE_DOCUMENT_READ_SCHEMAS:
        raise LocalMachineError("private document read schema is not admitted")
    if schema == "local-machine-profile":
        return load_local_machine_profile(path)
    payload = _read_private(path, maximum_bytes=4 * 1024 * 1024)
    value = parse_json_strict(payload)
    if (
        not isinstance(value, dict)
        or canonical_bytes(value) + b"\n" != payload
    ):
        raise LocalMachineError("private document is not canonical")
    validate(schema, value)
    return value


def build_local_machine_profile(
    *,
    state_root: Path,
    tenant_id: str,
    catalog_path: Path,
    source_namespace: str,
    created_at: str,
    runtime_port: int = 8775,
    persistence_task: str | None = None,
    forbidden_context_ports: Sequence[int] = (8765,),
) -> dict[str, Any]:
    validate_tenant_id(tenant_id)
    validate_seed_namespace(source_namespace)
    if not 1 <= runtime_port <= 65535:
        raise LocalMachineError("runtime port is outside 1..65535")
    if (
        not 1 <= len(forbidden_context_ports) <= 16
        or len(set(forbidden_context_ports)) != len(forbidden_context_ports)
        or any(
            not isinstance(port, int)
            or isinstance(port, bool)
            or not 1 <= port <= 65535
            or port == runtime_port
            for port in forbidden_context_ports
        )
    ):
        raise LocalMachineError("forbidden context port set rejected")
    core = {
        "tenant": {
            "tenant_id": tenant_id,
            "state_root": str(state_root.absolute()),
        },
        "seed": {
            "catalog": str(catalog_path.absolute()),
            "source_namespace": source_namespace,
        },
        "runtime": {
            "host": "127.0.0.1",
            "port": runtime_port,
            "persistence_task": persistence_task,
        },
        "created_at": created_at,
        "controls": {
            "imports_remote_memory": False,
            "forbidden_context_ports": list(forbidden_context_ports),
            "loopback_only": True,
            "production_authority": False,
        },
    }
    profile = {
        "protocol": "integrity-guardian/local-machine-profile/v1",
        "profile_id": "local-profile:"
        + digest_object(core, domain="local-machine-profile-v1").split(":", 1)[1],
        **core,
    }
    validate("local-machine-profile", profile)
    return profile


def write_local_machine_profile(path: Path, profile: dict[str, Any]) -> Path:
    validate("local-machine-profile", profile)
    expected = build_local_machine_profile(
        state_root=Path(profile["tenant"]["state_root"]),
        tenant_id=profile["tenant"]["tenant_id"],
        catalog_path=Path(profile["seed"]["catalog"]),
        source_namespace=profile["seed"]["source_namespace"],
        created_at=profile["created_at"],
        runtime_port=profile["runtime"]["port"],
        persistence_task=profile["runtime"]["persistence_task"],
        forbidden_context_ports=profile["controls"]["forbidden_context_ports"],
    )
    if expected != profile:
        raise LocalMachineError("local machine profile identity mismatch")
    return _write_private(path, canonical_bytes(profile) + b"\n")


def load_local_machine_profile(path: Path | None = None) -> dict[str, Any]:
    target = (path or default_local_profile_path()).absolute()
    payload = _read_private(target, maximum_bytes=_MAXIMUM_PROFILE_BYTES)
    profile = parse_json_strict(payload)
    if not isinstance(profile, dict) or canonical_bytes(profile) + b"\n" != payload:
        raise LocalMachineError("local machine profile is not canonical")
    validate("local-machine-profile", profile)
    expected = build_local_machine_profile(
        state_root=Path(profile["tenant"]["state_root"]),
        tenant_id=profile["tenant"]["tenant_id"],
        catalog_path=Path(profile["seed"]["catalog"]),
        source_namespace=profile["seed"]["source_namespace"],
        created_at=profile["created_at"],
        runtime_port=profile["runtime"]["port"],
        persistence_task=profile["runtime"]["persistence_task"],
        forbidden_context_ports=profile["controls"]["forbidden_context_ports"],
    )
    if expected != profile:
        raise LocalMachineError("local machine profile identity mismatch")
    return profile


def initialize_local_machine(
    *,
    profile_path: Path | None,
    state_root: Path,
    tenant_id: str,
    deployment_id: str,
    catalog_path: Path,
    source_namespace: str,
    created_at: str,
    runtime_port: int = 8775,
    persistence_task: str | None = None,
    forbidden_context_ports: Sequence[int] = (8765,),
) -> dict[str, Any]:
    root = state_root.absolute()
    catalog = catalog_path.absolute()
    target = (profile_path or default_local_profile_path()).absolute()
    try:
        catalog.relative_to(root)
    except ValueError as exc:
        raise LocalMachineError("fresh Seed catalog must be inside the state root") from exc
    if root in {Path(root.anchor), Path.home().absolute()} or root.parent == root:
        raise LocalMachineError("local state root is too broad")
    existing_profile = private_output_reconciliation_status(
        target,
        expected_purpose="local-machine-profile",
    )
    if existing_profile["status"] == "UNKNOWN_OUTCOME":
        raise PrivateOutputReconciliationRequired(existing_profile)
    if existing_profile["status"] == "COMMITTED":
        raise LocalMachineError(
            "local profile output already contains a committed profile"
        )
    if _path_lexists(root):
        raise LocalMachineError("local state root must be absent for fresh bootstrap")
    if _path_lexists(catalog):
        raise LocalMachineError("fresh bootstrap output already exists")
    if target == root or root in target.parents:
        raise LocalMachineError("local profile locator must be outside state root")
    tenant_profile = build_unenrolled_tenant_profile(
        tenant_id=tenant_id,
        deployment_id=deployment_id,
        created_at=created_at,
    )
    local_profile = build_local_machine_profile(
        state_root=root,
        tenant_id=tenant_id,
        catalog_path=catalog,
        source_namespace=source_namespace,
        created_at=created_at,
        runtime_port=runtime_port,
        persistence_task=persistence_task,
        forbidden_context_ports=forbidden_context_ports,
    )
    workspace = TenantWorkspace(root, tenant_id)
    reservation = _reserve_private_output(target, "local-machine-profile")
    try:
        workspace.initialize(tenant_profile)
        _prepare_private_output(catalog)
        _prepare_private_directory(root / "evidence")
        _commit_private_output_reservation(
            reservation,
            local_profile,
        )
    except Exception as failure:
        failure_status = (
            failure.status
            if isinstance(failure, PrivateOutputReconciliationRequired)
            else None
        )
        preserve_committed_state = bool(
            failure_status is not None
            and failure_status["final_output_digest"] is not None
        )
        if not reservation._consumed:
            _release_private_output_reservation(reservation)
        try:
            if _path_lexists(root) and not preserve_committed_state:
                if os.name == "nt":
                    from ._windows_files import remove_private_directory_tree

                    remove_private_directory_tree(root)
                else:
                    details = root.lstat()
                    if (
                        not stat.S_ISDIR(details.st_mode)
                        or details.st_uid != os.geteuid()
                        or stat.S_IMODE(details.st_mode) != 0o700
                    ):
                        raise LocalMachineError(
                            "fresh bootstrap rollback root custody rejected"
                        )
                    shutil.rmtree(root)
                if _path_lexists(root):
                    raise LocalMachineError(
                        "fresh bootstrap rollback did not remove exact state root"
                    )
        except (OSError, LocalMachineError, ValueError) as rollback_error:
            failure = LocalMachineError(
                "local bootstrap failed and exact state rollback failed"
            )
            failure.__cause__ = rollback_error
        if isinstance(failure, PrivateOutputReconciliationRequired):
            raise
        status = private_output_reconciliation_status(
            target,
            expected_purpose="local-machine-profile",
        )
        if status["status"] == "UNKNOWN_OUTCOME":
            raise PrivateOutputReconciliationRequired(status) from failure
        raise failure  # noqa: TRY201 - rollback can replace the original failure
    return {
        "ok": True,
        "status": "INITIALIZED_UNENROLLED",
        "profile": str(target),
        "profile_id": local_profile["profile_id"],
        "tenant_id": tenant_id,
        "source_namespace": source_namespace,
        "coverage": "UNKNOWN",
        "production_authority": False,
    }


def local_machine_status(profile_path: Path | None = None) -> dict[str, Any]:
    profile = load_local_machine_profile(profile_path)
    tenant = profile["tenant"]
    workspace = TenantWorkspace(Path(tenant["state_root"]), tenant["tenant_id"])
    tenant_profile = workspace.verify()
    enrollment = tenant_enrollment_status(tenant_profile)
    governance = verify_tenant_governance(tenant_profile)
    catalog_path = Path(profile["seed"]["catalog"])
    catalog_status: dict[str, Any] | None = None
    if catalog_path.is_file():
        catalog_status = SeedCatalog(catalog_path).status()
        if catalog_status["source_namespace"] != profile["seed"]["source_namespace"]:
            raise LocalMachineError("local profile Seed namespace mismatch")
    local_ready = catalog_status is not None
    return {
        "status": "READY_LOCAL_READONLY" if local_ready else f"INITIALIZED_{enrollment}",
        "coverage": "LOCAL_OBSERVATION_ONLY" if local_ready else "UNKNOWN",
        "enrollment": enrollment,
        "tenant_id": tenant["tenant_id"],
        "namespace": tenant_profile["namespace"],
        "profile_id": profile["profile_id"],
        "profile_source": "explicit-locator",
        "forbidden_context_ports": profile["controls"]["forbidden_context_ports"],
        "catalog": catalog_status,
        "runtime": {
            **profile["runtime"],
            "observed": False,
        },
        "governance": governance,
        "local_readonly_ready": local_ready,
        "operational_ready": False,
        "production_authority": False,
    }


def _secret_candidates(value: Any, *, parent_secret: bool = False) -> list[bytes]:
    result: list[bytes] = []
    if isinstance(value, dict):
        for key, child in value.items():
            lowered = str(key).casefold()
            result.extend(
                _secret_candidates(
                    child,
                    parent_secret=parent_secret
                    or any(marker in lowered for marker in _SECRET_MARKERS),
                )
            )
    elif isinstance(value, list):
        for child in value:
            result.extend(_secret_candidates(child, parent_secret=parent_secret))
    elif parent_secret and isinstance(value, str) and len(value.encode()) >= 8:
        result.append(value.encode())
    return result


def _assert_private_state_directory(path: Path) -> None:
    if path.is_symlink():
        raise LocalMachineError("credential audit state symlink rejected")
    if os.name == "nt":
        from ._windows_files import WindowsFileBoundaryError, assert_private_directory_acl

        try:
            assert_private_directory_acl(path)
        except WindowsFileBoundaryError as exc:
            raise LocalMachineError("credential audit state custody rejected") from exc
        return
    details = path.stat()
    if (
        not stat.S_ISDIR(details.st_mode)
        or details.st_uid != os.geteuid()
        or stat.S_IMODE(details.st_mode) & 0o077
    ):
        raise LocalMachineError("credential audit state custody rejected")


def _inventory_private_state(
    root: Path,
    *,
    secret_candidates: Sequence[bytes],
) -> dict[str, Any]:
    _assert_private_state_directory(root)
    hasher = hashlib.sha256()
    scanned_files = 0
    scanned_bytes = 0
    named = 0
    matches = 0
    directory_count = 0
    for directory, directories, files in os.walk(root, followlinks=False):
        directories.sort()
        files.sort()
        base = Path(directory)
        _assert_private_state_directory(base)
        directory_count += len(directories)
        if directory_count > _MAXIMUM_SCAN_FILES:
            raise LocalMachineError("credential audit directory bound exceeded")
        for name in directories:
            candidate = base / name
            is_junction = getattr(candidate, "is_junction", lambda: False)()
            if candidate.is_symlink() or is_junction:
                raise LocalMachineError("credential audit state reparse point rejected")
        for name in [*directories, *files]:
            if any(marker in name.casefold() for marker in _SECRET_MARKERS):
                named += 1
        for name in files:
            path = base / name
            if path.is_symlink():
                raise LocalMachineError("credential audit state symlink rejected")
            scanned_files += 1
            if scanned_files > _MAXIMUM_SCAN_FILES:
                raise LocalMachineError("credential audit file bound exceeded")
            payload = _read_private(
                path,
                maximum_bytes=_MAXIMUM_SCAN_BYTES - scanned_bytes,
            )
            scanned_bytes += len(payload)
            if scanned_bytes > _MAXIMUM_SCAN_BYTES:
                raise LocalMachineError("credential audit byte bound exceeded")
            relative = path.relative_to(root).as_posix().encode("utf-8")
            hasher.update(b"FILE\0")
            hasher.update(relative)
            hasher.update(b"\0")
            hasher.update(str(len(payload)).encode("ascii"))
            hasher.update(b"\0")
            hasher.update(payload)
            matches += sum(candidate in payload for candidate in secret_candidates)
    return {
        "scanned_file_count": scanned_files,
        "scanned_byte_count": scanned_bytes,
        "credential_named_file_count": named,
        "secret_value_match_count": matches,
        "state_inventory_digest": "sha256:" + hasher.hexdigest(),
    }


def audit_credential_custody(
    *,
    state_root: Path,
    credential_sources: Sequence[Path],
) -> dict[str, Any]:
    root = state_root.absolute()
    if not root.is_dir() or root.is_symlink():
        raise LocalMachineError("credential audit state root is absent or unsafe")
    if not 1 <= len(credential_sources) <= 32:
        raise LocalMachineError("credential source count is outside 1..32")
    candidates: list[bytes] = []
    source_paths: set[Path] = set()
    for source in credential_sources:
        path = source.absolute()
        if path == root or root in path.parents:
            raise LocalMachineError("credential source must be outside state root")
        if path in source_paths:
            raise LocalMachineError("credential source is duplicated")
        payload = _read_untrusted_bounded(
            path,
            maximum_bytes=_MAXIMUM_CREDENTIAL_SOURCE_BYTES,
        )
        source_paths.add(path)
        if len(payload) >= 8:
            candidates.append(payload)
        try:
            parsed = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError):
            for line in payload.splitlines():
                key, separator, value = line.partition(b"=")
                if (
                    separator
                    and any(marker.encode() in key.casefold() for marker in _SECRET_MARKERS)
                    and len(value.strip()) >= 8
                ):
                    candidates.append(value.strip())
        else:
            candidates.extend(_secret_candidates(parsed))
    unique_candidates = tuple(dict.fromkeys(candidates))
    inventory = _inventory_private_state(
        root,
        secret_candidates=unique_candidates,
    )
    receipt = {
        "protocol": "integrity-guardian/credential-custody-receipt/v1",
        "status": (
            "PASS"
            if not inventory["credential_named_file_count"]
            and not inventory["secret_value_match_count"]
            else "FAIL"
        ),
        "audited_at": _utc_now(),
        "state_root": str(root),
        "state_inventory_digest": inventory["state_inventory_digest"],
        "source_file_count": len(source_paths),
        "secret_candidate_count": len(unique_candidates),
        "scanned_file_count": inventory["scanned_file_count"],
        "scanned_byte_count": inventory["scanned_byte_count"],
        "credential_named_file_count": inventory["credential_named_file_count"],
        "secret_value_match_count": inventory["secret_value_match_count"],
        "values_emitted": False,
        "value_digests_emitted": False,
        "bounded": True,
        "production_authority": False,
    }
    validate("credential-custody-receipt", receipt)
    return receipt


def write_credential_custody_receipt(path: Path, receipt: dict[str, Any]) -> Path:
    validate("credential-custody-receipt", receipt)
    return _write_private(path, canonical_bytes(receipt) + b"\n")


def _health(profile: dict[str, Any]) -> dict[str, Any]:
    runtime = profile["runtime"]
    host = runtime["host"]
    if host not in {"127.0.0.1", "::1"}:
        raise LocalMachineError("runtime health endpoint is not loopback")
    bracketed = f"[{host}]" if ":" in host else host
    request = urllib.request.Request(
        f"http://{bracketed}:{runtime['port']}/healthz",
        method="GET",
        headers={"Accept": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        if response.status != 200:
            raise LocalMachineError("runtime health returned non-200")
        payload = response.read(1024 * 1024 + 1)
    if len(payload) > 1024 * 1024:
        raise LocalMachineError("runtime health response exceeds bound")
    value = parse_json_strict(payload)
    if (
        not isinstance(value, dict)
        or value.get("ok") is not True
        or value.get("service") != "integrity-seed"
        or value.get("production_authority") is not False
    ):
        raise LocalMachineError("runtime health receipt rejected")
    return value


def _probe_context_isolation(profile: dict[str, Any]) -> dict[str, Any]:
    endpoints: list[dict[str, Any]] = []
    for port in profile["controls"]["forbidden_context_ports"]:
        for host in ("127.0.0.1", "::1"):
            listener_absent = False
            try:
                connection = socket.create_connection((host, port), timeout=0.5)
            except ConnectionRefusedError:
                listener_absent = True
            except OSError as exc:
                if getattr(exc, "errno", None) in {61, 111, 10061} or getattr(
                    exc,
                    "winerror",
                    None,
                ) == 10061:
                    listener_absent = True
            else:
                connection.close()
            endpoints.append(
                {
                    "host": host,
                    "port": port,
                    "listener_absent": listener_absent,
                }
            )
    return {
        "status": (
            "PASS" if all(item["listener_absent"] for item in endpoints) else "FAIL"
        ),
        "endpoints": endpoints,
        "imports_remote_memory": False,
        "production_authority": False,
    }


def _load_receipt(path: Path, schema: str) -> dict[str, Any]:
    value = parse_json_strict(_read_private(path, maximum_bytes=4 * 1024 * 1024))
    if not isinstance(value, dict):
        raise LocalMachineError(f"{schema} receipt is not an object")
    validate(schema, value)
    return value


def _private_file_digest(path: Path) -> str:
    payload = _read_private(path, maximum_bytes=16 * 1024 * 1024)
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _require_private_evidence_root(
    root: Path,
    paths: Sequence[Path | None],
) -> None:
    normalized_root = Path(os.path.normcase(str(root.absolute())))
    for value in paths:
        if value is None:
            continue
        target = Path(os.path.normcase(str(value.absolute())))
        try:
            target.relative_to(normalized_root)
        except ValueError as exc:
            raise LocalMachineError(
                "final evidence must remain inside the audited private state root"
            ) from exc
        if target == normalized_root:
            raise LocalMachineError("final evidence path cannot be the state root")


def build_zero_day_final_witness(
    *,
    profile_path: Path | None,
    credential_source_paths: Sequence[Path],
    seed_build_receipt_path: Path | None,
    collector_result_paths: Sequence[Path],
    operation_manifest_path: Path | None,
    operation_receipt_path: Path | None,
    operation_evidence_directory: Path | None,
    persistence_receipt_path: Path | None,
    persistence_witness_path: Path | None,
    require_runtime: bool,
    require_cold_start: bool = False,
    observed_at: str | None = None,
) -> dict[str, Any]:
    profile = load_local_machine_profile(profile_path)
    state_root = Path(profile["tenant"]["state_root"]).absolute()
    _require_private_evidence_root(
        state_root,
        (
            seed_build_receipt_path,
            *collector_result_paths,
            operation_manifest_path,
            operation_receipt_path,
            operation_evidence_directory,
            persistence_receipt_path,
            persistence_witness_path,
        ),
    )
    status = local_machine_status(profile_path)
    if status["catalog"] is None:
        raise LocalMachineError("final witness requires a verified Seed catalog")
    catalog = SeedCatalog(Path(profile["seed"]["catalog"]))
    before = _health(profile) if require_runtime else None
    snapshot = catalog.runtime_snapshot()
    after = _health(profile) if require_runtime else None
    runtime_stable = before == after if require_runtime else False
    if require_runtime:
        catalog_status = snapshot["status"]
        comparable = {
            key: catalog_status[key]
            for key in (
                "source_namespace",
                "event_count",
                "source_digest",
                "catalog_digest",
                "home_record_count",
            )
        }
        if not runtime_stable or any(before[key] != value for key, value in comparable.items()):
            raise LocalMachineError("runtime and catalog did not form one stable witness")
    operation_manifest: dict[str, Any] | None = None
    operation_receipt: dict[str, Any] | None = None
    supplied_operation_inputs = (
        operation_manifest_path,
        operation_receipt_path,
        operation_evidence_directory,
    )
    if any(value is not None for value in supplied_operation_inputs) and not all(
        value is not None for value in supplied_operation_inputs
    ):
        raise LocalMachineError(
            "operation manifest, receipt and evidence directory must be supplied together"
        )
    if operation_receipt_path is not None:
        from .operation_audit import (
            verify_readonly_operation_evidence,
            verify_readonly_operation_receipt,
        )

        operation_manifest = _load_receipt(
            operation_manifest_path,
            "readonly-operation-manifest",
        )
        operation_receipt = _load_receipt(
            operation_receipt_path,
            "readonly-operation-receipt",
        )
        operation_verification = verify_readonly_operation_receipt(
            operation_receipt,
            manifest=operation_manifest,
        )
        evidence_verification = verify_readonly_operation_evidence(
            operation_receipt,
            evidence_directory=operation_evidence_directory,
        )
        operation = {
            "status": operation_verification["status"],
            "manifest_id": operation_verification["manifest_id"],
            "operation_count": operation_verification["operation_count"],
            "outcome_counts": operation_verification["outcome_counts"],
            "unknown_outcome_count": operation_verification[
                "unknown_outcome_count"
            ],
            "all_operations_confirmed_success": operation_verification[
                "all_operations_confirmed_success"
            ],
            "evidence_artifact_count": evidence_verification["artifact_count"],
            "receipt_id": operation_receipt["receipt_id"],
            "production_authority": False,
        }
    else:
        operation = {"status": "NOT_ASSESSED"}
    if seed_build_receipt_path is not None:
        if (
            operation_manifest is None
            or operation_receipt is None
            or not collector_result_paths
        ):
            raise LocalMachineError(
                "Seed build receipt requires operation and collector evidence"
            )
        from .zero_day_seed import verify_zero_day_seed_build_receipt

        seed_build_receipt = _load_receipt(
            seed_build_receipt_path,
            "zero-day-seed-build-receipt",
        )
        profile_target = profile_path or default_local_profile_path()
        expected_evidence = [
            ("local-machine-profile", _private_file_digest(profile_target)),
            *[
                ("collector-result", _private_file_digest(path))
                for path in collector_result_paths
            ],
            (
                "readonly-operation-manifest",
                _private_file_digest(operation_manifest_path),
            ),
            (
                "readonly-operation-receipt",
                _private_file_digest(operation_receipt_path),
            ),
        ]
        seed_verification = verify_zero_day_seed_build_receipt(
            seed_build_receipt,
            catalog_path=Path(profile["seed"]["catalog"]),
            expected_evidence=expected_evidence,
        )
        if seed_build_receipt["profile_id"] != profile["profile_id"]:
            raise LocalMachineError("Seed build receipt profile mismatch")
        seed_build = {
            **seed_verification,
            "imports_remote_memory": False,
        }
    elif collector_result_paths:
        raise LocalMachineError(
            "collector evidence requires a Seed build receipt"
        )
    else:
        seed_build = {"status": "NOT_ASSESSED"}
    if (persistence_receipt_path is None) != (persistence_witness_path is None):
        raise LocalMachineError(
            "persistence receipt and witness must be supplied together"
        )
    if persistence_receipt_path is not None:
        persistence_receipt = _load_receipt(
            persistence_receipt_path,
            "windows-seed-persistence-receipt",
        )
        persistence_witness = _load_receipt(
            persistence_witness_path,
            "windows-seed-persistence-witness",
        )
        expected_listener = (
            f"{profile['runtime']['host']}:{profile['runtime']['port']}"
        )
        if (
            persistence_receipt["task_name"]
            != profile["runtime"]["persistence_task"]
            or persistence_receipt["task_path"] != "\\"
            or persistence_witness["task_name"]
            != persistence_receipt["task_name"]
            or persistence_witness["task_path"]
            != persistence_receipt["task_path"]
            or persistence_witness["mode"] != persistence_receipt["mode"]
            or persistence_witness["trigger_user_id"]
            != persistence_receipt["trigger_user_id"]
            or persistence_witness["action_digest"]
            != persistence_receipt["action_digest"]
            or persistence_witness["trigger"] != persistence_receipt["trigger"]
            or persistence_witness["multiple_instances"]
            != persistence_receipt["multiple_instances"]
            or persistence_witness["start_when_available"]
            is not persistence_receipt["start_when_available"]
            or persistence_witness["installed_boot_time"]
            != persistence_receipt["install_boot_time"]
            or persistence_witness["listener"] != expected_listener
            or persistence_witness["source_digest"]
            != snapshot["status"]["source_digest"]
            or persistence_witness["catalog_digest"]
            != snapshot["status"]["catalog_digest"]
            or persistence_witness["event_count"]
            != snapshot["status"]["event_count"]
            or persistence_receipt["source_digest"]
            != snapshot["status"]["source_digest"]
            or persistence_receipt["catalog_digest"]
            != snapshot["status"]["catalog_digest"]
            or persistence_receipt["event_count"]
            != snapshot["status"]["event_count"]
            or persistence_witness["require_reboot"] is not require_cold_start
        ):
            raise LocalMachineError("persistence receipt, witness or runtime mismatch")
        persistence_pass = (
            persistence_witness["status"] == "PASS"
            and persistence_witness["task_ran_this_boot"] is True
            and (
                not require_cold_start
                or persistence_witness["reboot_since_install"] is True
            )
        )
        persistence = {
            "status": "PASS" if persistence_pass else "FAIL",
            "task_name": persistence_receipt["task_name"],
            "task_path": persistence_receipt["task_path"],
            "mode": persistence_receipt["mode"],
            "trigger_user_id": persistence_receipt["trigger_user_id"],
            "task_state": persistence_witness["task_state"],
            "task_ran_this_boot": persistence_witness["task_ran_this_boot"],
            "reboot_since_install": persistence_witness[
                "reboot_since_install"
            ],
            "cold_start_required": require_cold_start,
            "production_authority": False,
        }
    else:
        persistence = {"status": "NOT_ASSESSED"}
    context_isolation = _probe_context_isolation(profile)
    tenant_profile = TenantWorkspace(
        state_root,
        profile["tenant"]["tenant_id"],
    ).verify()
    credential = (
        audit_credential_custody(
            state_root=state_root,
            credential_sources=credential_source_paths,
        )
        if credential_source_paths
        else {"status": "NOT_ASSESSED"}
    )
    unsatisfied: list[str] = []
    if not require_runtime:
        unsatisfied.append("runtime-not-observed")
    if credential.get("status") != "PASS":
        unsatisfied.append("credential-custody-not-proven")
    if operation.get("status") != "PASS":
        unsatisfied.append("operation-audit-not-proven")
    if seed_build.get("status") != "PASS":
        unsatisfied.append("seed-evidence-not-proven")
    if persistence.get("status") != "PASS":
        unsatisfied.append("persistence-not-proven")
    if context_isolation["status"] != "PASS":
        unsatisfied.append("context-isolation-not-proven")
    local_acceptance = "PASS" if not unsatisfied else "PARTIAL"
    acceptance_claims = {
        "local_bootstrap": "PROVEN",
        "local_host_observation": (
            "PROVEN" if seed_build.get("status") == "PASS" else "NOT_PROVEN"
        ),
        "exact_operation_execution": (
            "PROVEN" if operation.get("status") == "PASS" else "NOT_PROVEN"
        ),
        "post_action_seed": (
            "PROVEN" if seed_build.get("status") == "PASS" else "NOT_PROVEN"
        ),
        "loopback_runtime": (
            "PROVEN" if require_runtime and runtime_stable else "NOT_PROVEN"
        ),
        "credential_custody": (
            "PROVEN" if credential.get("status") == "PASS" else "NOT_PROVEN"
        ),
        "persistence": (
            "PROVEN" if persistence.get("status") == "PASS" else "NOT_PROVEN"
        ),
        "cold_start": (
            "PROVEN"
            if require_cold_start and persistence.get("status") == "PASS"
            else ("NOT_REQUIRED" if not require_cold_start else "NOT_PROVEN")
        ),
        "full_external_topology": "NOT_PROVEN",
        "multi_agent_coordination": "NOT_PROVEN",
        "blast_radius_coverage": "NOT_PROVEN",
        "production_causality": "NOT_PROVEN",
    }
    catalog_status = snapshot["status"]
    witness = {
        "protocol": "integrity-guardian/zero-day-final-witness/v2",
        "scope": "LOCAL_READONLY_ZERO_DAY",
        "result": (
            "BOUNDED_PASS_NOT_PRODUCTION_READY"
            if local_acceptance == "PASS"
            else "PARTIAL_NOT_PRODUCTION_READY"
        ),
        "local_acceptance": local_acceptance,
        "observed_at": observed_at or _utc_now(),
        "profile_id": profile["profile_id"],
        "tenant": {
            "tenant_id": tenant_profile["tenant_id"],
            "namespace": tenant_profile["namespace"],
            "enrollment": tenant_enrollment_status(tenant_profile),
            "local_readonly_ready": True,
        },
        "seed": {
            "status": catalog_status["status"],
            "source_namespace": catalog_status["source_namespace"],
            "event_count": catalog_status["event_count"],
            "minimum_event_id": catalog_status["minimum_event_id"],
            "maximum_event_id": catalog_status["maximum_event_id"],
            "source_digest": catalog_status["source_digest"],
            "catalog_digest": catalog_status["catalog_digest"],
            "home_record_count": catalog_status["home_record_count"],
            "production_authority": False,
        },
        "seed_build": seed_build,
        "runtime": {
            "required": require_runtime,
            "observed": before is not None,
            "stable_two_read_witness": runtime_stable,
            "health": before,
        },
        "credential_custody": credential,
        "operation_audit": operation,
        "persistence": persistence,
        "context_isolation": context_isolation,
        "acceptance_claims": acceptance_claims,
        "unsatisfied_claims": sorted(unsatisfied),
        "unproven_external_claims": [
            "blast_radius_coverage",
            "full_external_topology",
            "multi_agent_coordination",
            "production_causality",
        ],
        "operational_ready": False,
        "production_ready": False,
        "production_authority": False,
    }
    validate("zero-day-final-witness", witness)
    return witness


def write_zero_day_final_witness(path: Path, witness: dict[str, Any]) -> Path:
    validate("zero-day-final-witness", witness)
    return _write_private(path, canonical_bytes(witness) + b"\n")


__all__ = [
    "PRIVATE_DOCUMENT_READ_SCHEMAS",
    "PRIVATE_DOCUMENT_SCHEMAS",
    "LocalMachineError",
    "PrivateOutputReconciliationRequired",
    "audit_credential_custody",
    "build_local_machine_profile",
    "build_zero_day_final_witness",
    "default_local_profile_path",
    "initialize_local_machine",
    "load_local_machine_profile",
    "load_private_document",
    "local_machine_status",
    "private_output_reconciliation_status",
    "store_private_document",
    "write_credential_custody_receipt",
    "write_local_machine_profile",
    "write_zero_day_final_witness",
]
