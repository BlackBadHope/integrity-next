"""Deterministic release inventory and signed manifest verification.

The release module inventories caller-selected local artifacts. It does not
build, publish, upload or install them, and it never obtains production
authority from a manifest.
"""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Iterable
from copy import deepcopy
from pathlib import Path, PurePosixPath
from typing import Any

from .canonical import canonical_bytes
from .hashing import digest_object
from .schemas import validate
from .signing import Ed25519Signer, TrustedKey, verify_bytes


class ReleaseManifestError(ValueError):
    """Raised when release provenance is ambiguous or untrusted."""


def _open_bounded_regular(root: Path, artifact: Path) -> tuple[int, str]:
    root = root.absolute()
    artifact = artifact.absolute()
    if root.is_symlink():
        raise ReleaseManifestError("release root must be a real directory")
    try:
        relative = artifact.relative_to(root)
    except ValueError as exc:
        raise ReleaseManifestError("release artifact escaped the release root") from exc
    portable = PurePosixPath(relative.as_posix())
    if portable.is_absolute() or any(part in {"", ".", ".."} for part in portable.parts):
        raise ReleaseManifestError("release artifact path is not canonical")

    directory_flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        directory_flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        directory_flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    file_flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        file_flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        file_flags |= os.O_NOFOLLOW

    descriptor = os.open(root, directory_flags)
    try:
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise ReleaseManifestError("release root must be a real directory")
        for part in portable.parts[:-1]:
            child = os.open(part, directory_flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        artifact_descriptor = os.open(
            portable.parts[-1],
            file_flags,
            dir_fd=descriptor,
        )
    except OSError as exc:
        raise ReleaseManifestError(
            "release artifact path is unsafe, symlinked, or absent"
        ) from exc
    finally:
        os.close(descriptor)
    if not stat.S_ISREG(os.fstat(artifact_descriptor).st_mode):
        os.close(artifact_descriptor)
        raise ReleaseManifestError("release artifact must be a regular file")
    return artifact_descriptor, portable.as_posix()


def _digest_open_file(descriptor: int) -> tuple[str, os.stat_result]:
    before = os.fstat(descriptor)
    hasher = hashlib.sha256()
    while chunk := os.read(descriptor, 1024 * 1024):
        hasher.update(chunk)
    after = os.fstat(descriptor)
    if (
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) != (
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        raise ReleaseManifestError("release artifact changed while being inventoried")
    return f"sha256:{hasher.hexdigest()}", after


def _inventory_windows_artifact(
    root: Path,
    artifact: Path,
) -> tuple[str, str, int, bool]:
    """Hold Windows ancestry and bytes while deriving one inventory record."""

    from ._windows_files import (
        HeldWindowsDirectory,
        HeldWindowsFile,
        WindowsFileBoundaryError,
    )

    root = root.absolute()
    artifact = artifact.absolute()
    if root.is_symlink() or artifact.is_symlink():
        raise ReleaseManifestError("release root or artifact is reparse-backed")
    try:
        relative = artifact.relative_to(root)
    except ValueError as exc:
        raise ReleaseManifestError("release artifact escaped the release root") from exc
    portable = PurePosixPath(relative.as_posix())
    if portable.is_absolute() or any(part in {"", ".", ".."} for part in portable.parts):
        raise ReleaseManifestError("release artifact path is not canonical")
    try:
        with HeldWindowsDirectory(root), HeldWindowsFile(
            artifact,
            maximum_bytes=(1 << 63) - 1,
        ) as held:
            digest = f"sha256:{held.sha256()}"
            details = artifact.stat()
            if details.st_size != held.size:
                raise ReleaseManifestError(
                    "release artifact changed while being inventoried"
                )
            return (
                portable.as_posix(),
                digest,
                held.size,
                bool(details.st_mode & 0o111),
            )
    except ReleaseManifestError:
        raise
    except (OSError, WindowsFileBoundaryError) as exc:
        raise ReleaseManifestError(
            "release artifact path is unsafe, reparse-backed, or absent"
        ) from exc


def build_artifact_inventory(
    root: Path,
    artifacts: Iterable[Path],
) -> list[dict[str, Any]]:
    """Return a sorted, exact inventory for local release files."""

    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    for artifact in artifacts:
        if os.name == "nt":
            relative, digest, size, executable = _inventory_windows_artifact(
                root,
                artifact,
            )
            if relative in seen:
                raise ReleaseManifestError("duplicate release artifact path")
            seen.add(relative)
            records.append(
                {
                    "path": relative,
                    "digest": digest,
                    "size_bytes": size,
                    "executable": executable,
                }
            )
            continue
        descriptor, relative = _open_bounded_regular(root, artifact)
        try:
            if relative in seen:
                raise ReleaseManifestError("duplicate release artifact path")
            seen.add(relative)
            digest, details = _digest_open_file(descriptor)
            records.append(
                {
                    "path": relative,
                    "digest": digest,
                    "size_bytes": details.st_size,
                    "executable": bool(details.st_mode & 0o111),
                }
            )
        finally:
            os.close(descriptor)
    return sorted(records, key=lambda item: item["path"])


def source_tree_digest(artifacts: list[dict[str, Any]]) -> str:
    """Commit to an exact ordered release inventory."""

    return digest_object(artifacts, domain="release-source-tree-v1")


def _validate_manifest_artifacts(artifacts: list[dict[str, Any]]) -> None:
    paths: list[str] = []
    for artifact in artifacts:
        path = PurePosixPath(artifact["path"])
        if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
            raise ReleaseManifestError("release artifact path is not canonical")
        paths.append(path.as_posix())
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise ReleaseManifestError("release artifact inventory is not unique and sorted")


def _signature_payload(document: dict[str, Any]) -> bytes:
    unsigned = deepcopy(document)
    authorization = unsigned.get("authorization")
    if not isinstance(authorization, dict):
        raise ReleaseManifestError("release authorization is missing")
    authorization.pop("signature", None)
    return b"integrity-guardian\x00release-manifest-v1\x00" + canonical_bytes(unsigned)


def sign_release_manifest(
    unsigned_manifest: dict[str, Any],
    signer: Ed25519Signer,
) -> dict[str, Any]:
    document = deepcopy(unsigned_manifest)
    authorization = document.get("authorization")
    if not isinstance(authorization, dict):
        raise ReleaseManifestError("release authorization is missing")
    if "signature" in authorization:
        raise ReleaseManifestError("release manifest is already signed")
    authorization["signature"] = {
        "algorithm": "ed25519",
        "key_id": signer.key_id,
        "value": signer.sign_bytes(_signature_payload(document)),
    }
    validate("release-manifest", document)
    return document


def authenticate_release_manifest(
    document: dict[str, Any],
    *,
    authority_key: TrustedKey,
    expected_source_revision: str,
) -> None:
    """Authenticate one manifest before following its artifact inventory."""

    try:
        validate("release-manifest", document)
    except Exception as exc:
        raise ReleaseManifestError("release manifest schema rejected") from exc
    signature = document["authorization"]["signature"]
    if (
        document["authorization"]["authority_id"] != authority_key.key_id
        or signature["key_id"] != authority_key.key_id
        or not verify_bytes(
            _signature_payload(document),
            signature["value"],
            authority_key.public_key,
        )
    ):
        raise ReleaseManifestError("release authority signature rejected")
    if document["source_revision"] != expected_source_revision:
        raise ReleaseManifestError("release source revision mismatch")


def verify_release_manifest(
    document: dict[str, Any],
    *,
    authority_key: TrustedKey,
    expected_source_revision: str,
    expected_artifacts: list[dict[str, Any]],
) -> str:
    """Verify signature, clean-room controls and exact artifact inventory."""

    authenticate_release_manifest(
        document,
        authority_key=authority_key,
        expected_source_revision=expected_source_revision,
    )

    canonical_expected = sorted(expected_artifacts, key=lambda item: item["path"])
    _validate_manifest_artifacts(document["artifacts"])
    _validate_manifest_artifacts(canonical_expected)
    if document["artifacts"] != canonical_expected:
        raise ReleaseManifestError("release artifact inventory mismatch")
    if document["artifact_count"] != len(canonical_expected):
        raise ReleaseManifestError("release artifact count mismatch")
    if document["source_tree_digest"] != source_tree_digest(canonical_expected):
        raise ReleaseManifestError("release source tree digest mismatch")

    controls = document["controls"]
    if controls != {
        "clean_room": True,
        "credentials_included": False,
        "customer_data_included": False,
        "production_authority": False,
        "reproducible_build_required": True,
    }:
        raise ReleaseManifestError("release safety controls rejected")
    return digest_object(document, domain="release-manifest-v1")
