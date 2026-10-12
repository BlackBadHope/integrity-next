"""Version matrix and signed-manifest-bound Integrity LTS release index."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from copy import deepcopy
from datetime import datetime, timedelta
from importlib.resources import files
from pathlib import Path, PurePosixPath
from typing import Any

from .canonical import canonical_bytes, parse_json_strict
from .hashing import digest_object
from .lts import LTS_TRACK_IDS
from .public_source import public_source_version_report
from .release import verify_release_manifest
from .schemas import validate
from .signing import TrustedKey

_VERSION_RE = re.compile(
    r"^(?P<major>0|[1-9][0-9]*)\."
    r"(?P<minor>0|[1-9][0-9]*)\."
    r"(?P<patch>0|[1-9][0-9]*)"
    r"(?P<prerelease>(?:(?:a|b|rc)[0-9]+|-[A-Za-z0-9]+(?:\.[A-Za-z0-9]+)*))?$"
)
_CANONICAL_COMPONENT_NAMES = {
    "guardian-core-lts": "Guardian Core",
    "seed-synapse-lts": "Seed & Synapse",
    "adapter-observer-sdk-lts": "Adapter & Observer SDK",
}


class LtsReleaseIndexError(ValueError):
    """Raised when an umbrella matrix or its signed release binding is invalid."""


def _is_stable_version(value: str) -> bool:
    match = _VERSION_RE.fullmatch(value)
    if match is None:
        raise LtsReleaseIndexError(f"invalid version: {value}")
    return match.group("prerelease") is None


def _verify_lifecycle(version: str, lifecycle: str, subject: str) -> None:
    expected = "stable" if _is_stable_version(version) else "prerelease"
    if lifecycle != expected:
        raise LtsReleaseIndexError(f"{subject} lifecycle does not match its version")


def _verify_utc_timestamp(value: str) -> None:
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise LtsReleaseIndexError("release index timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise LtsReleaseIndexError("release index timestamp must be timezone-aware")
    if parsed.utcoffset() != timedelta(0):
        raise LtsReleaseIndexError("release index timestamp must be UTC")


def _verify_artifact_path(value: str) -> None:
    portable = PurePosixPath(value)
    if (
        portable.is_absolute()
        or portable.as_posix() != value
        or any(part in {"", ".", ".."} for part in portable.parts)
    ):
        raise LtsReleaseIndexError("release index artifact path is not canonical")


def load_lts_version_matrix() -> dict[str, Any]:
    value = parse_json_strict(
        files("integrity_guardian").joinpath("lts-version-matrix.json").read_bytes()
    )
    if not isinstance(value, dict):
        raise LtsReleaseIndexError("LTS version matrix must be an object")
    return value


def verify_lts_version_matrix(
    matrix: Mapping[str, Any] | None = None,
    *,
    expected_product_version: str | None = None,
) -> dict[str, Any]:
    """Verify the exact component BOM without deriving deployment authority."""

    candidate = deepcopy(dict(load_lts_version_matrix() if matrix is None else matrix))
    try:
        validate("lts-version-matrix", candidate)
    except Exception as exc:
        raise LtsReleaseIndexError("LTS version matrix schema rejected") from exc

    umbrella = candidate["umbrella"]
    product = candidate["product"]
    if expected_product_version is not None and product["version"] != expected_product_version:
        raise LtsReleaseIndexError("LTS matrix product version mismatch")
    _verify_lifecycle(product["version"], product["lifecycle"], "product")
    umbrella_stable = _is_stable_version(umbrella["version"])
    expected_release_id = f"release:lts:integrity:{umbrella['version']}"
    expected_tag = f"lts/integrity/v{umbrella['version']}"
    if umbrella["release_id"] != expected_release_id or umbrella["tag"] != expected_tag:
        raise LtsReleaseIndexError("umbrella release identity is inconsistent")

    components = candidate["components"]
    track_ids = tuple(component["track_id"] for component in components)
    if track_ids != LTS_TRACK_IDS:
        raise LtsReleaseIndexError("LTS component order or membership changed")
    for component in components:
        track_id = component["track_id"]
        if component["name"] != _CANONICAL_COMPONENT_NAMES[track_id]:
            raise LtsReleaseIndexError("LTS component canonical name changed")
        _verify_lifecycle(component["version"], component["lifecycle"], track_id)
        release = component.get("release")
        if component["status"] == "active":
            if component["lifecycle"] != "stable" or not isinstance(release, dict):
                raise LtsReleaseIndexError("active LTS component lacks a stable release")
        elif release is not None:
            raise LtsReleaseIndexError("candidate LTS component cannot claim a release")
        if isinstance(release, dict):
            expected_component_tag = f"lts/{track_id}/v{component['version']}"
            if release["tag"] != expected_component_tag:
                raise LtsReleaseIndexError("component release tag is inconsistent")

    integration_ids = [item["integration_id"] for item in candidate["integrations"]]
    if len(integration_ids) != len(set(integration_ids)):
        raise LtsReleaseIndexError("duplicate integration identity in LTS matrix")
    for integration in candidate["integrations"]:
        _verify_lifecycle(
            integration["version"],
            integration["lifecycle"],
            integration["integration_id"],
        )
        if integration["status"] == "included" and integration["lifecycle"] != "stable":
            raise LtsReleaseIndexError("included integration must be stable")

    prerelease_present = product["lifecycle"] == "prerelease" or any(
        component["lifecycle"] == "prerelease" for component in components
    )
    inactive_component = any(component["status"] != "active" for component in components)
    if umbrella["status"] == "active":
        if not umbrella_stable or prerelease_present or inactive_component:
            raise LtsReleaseIndexError("prerelease or candidate state blocks umbrella activation")
    elif umbrella_stable:
        raise LtsReleaseIndexError("candidate umbrella version must be visibly prerelease")

    return {
        "ok": True,
        "status": umbrella["status"],
        "matrix_digest": digest_object(candidate, domain="integrity-lts-version-matrix-v2"),
        "track_ids": list(track_ids),
        "production_authority": False,
        "memory_grants_authority": False,
    }


def lts_version_report(*, expected_product_version: str) -> dict[str, Any]:
    # Public source has its own explicitly unsigned profile. Never reconstruct
    # the omitted private LTS matrix or infer public status from a missing file.
    public = public_source_version_report(expected_product_version=expected_product_version)
    if public is not None:
        return public
    matrix = load_lts_version_matrix()
    verification = verify_lts_version_matrix(
        matrix,
        expected_product_version=expected_product_version,
    )
    return {
        "protocol": "integrity-guardian/version-report/v1",
        "ok": True,
        "umbrella": matrix["umbrella"],
        "product": matrix["product"],
        "components": matrix["components"],
        "integrations": matrix["integrations"],
        "compatibility": matrix["compatibility"],
        "installation": matrix["installation"],
        "matrix_digest": verification["matrix_digest"],
        "verification_scope": "packaged-structure-and-policy",
        "release_evidence": "requires-signed-release-index",
        "production_authority": False,
        "memory_grants_authority": False,
    }


def build_lts_release_index(
    *,
    source_revision: str,
    artifact_path: str,
    created_at: str,
    matrix: Mapping[str, Any] | None = None,
    expected_product_version: str | None = None,
) -> dict[str, Any]:
    """Build the BOM payload that must enter an ordinary signed release manifest."""

    current = deepcopy(dict(load_lts_version_matrix() if matrix is None else matrix))
    verification = verify_lts_version_matrix(
        current,
        expected_product_version=expected_product_version,
    )
    _verify_artifact_path(artifact_path)
    _verify_utc_timestamp(created_at)
    umbrella = current["umbrella"]
    index: dict[str, Any] = {
        "protocol": "integrity-guardian/lts-release-index/v1",
        "artifact_path": artifact_path,
        "release": {
            "release_id": umbrella["release_id"],
            "version": umbrella["version"],
            "tag": umbrella["tag"],
            "status": umbrella["status"],
        },
        "source_revision": source_revision,
        "created_at": created_at,
        "matrix_digest": verification["matrix_digest"],
        "matrix": current,
        "controls": {
            "signed_release_manifest_required": True,
            "exact_artifact_inventory_required": True,
            "production_authority": False,
            "memory_grants_authority": False,
            "automatic_remote_rollout": False,
        },
    }
    try:
        validate("lts-release-index", index)
    except Exception as exc:
        raise LtsReleaseIndexError("LTS release index schema rejected") from exc
    return index


def write_lts_release_index(path: Path, index: Mapping[str, Any]) -> Path:
    """Write one immutable public index payload without replacing existing bytes."""

    validate("lts-release-index", dict(index))
    parent = path.parent
    if not parent.is_dir() or parent.is_symlink() or path.is_symlink():
        raise LtsReleaseIndexError("release index parent or output path is unsafe")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o644)
    except OSError as exc:
        raise LtsReleaseIndexError("release index output must be absent") from exc
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(canonical_bytes(dict(index)) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return path


def verify_lts_release_index(
    index: Mapping[str, Any],
    *,
    release_manifest: Mapping[str, Any],
    authority_key: TrustedKey,
    expected_source_revision: str,
    expected_product_version: str,
    expected_artifacts: list[dict[str, Any]],
    index_artifact_path: str,
) -> dict[str, Any]:
    """Verify the BOM only when its exact bytes are covered by the signed manifest."""

    manifest_digest = verify_release_manifest(
        dict(release_manifest),
        authority_key=authority_key,
        expected_source_revision=expected_source_revision,
        expected_artifacts=expected_artifacts,
    )
    candidate = deepcopy(dict(index))
    try:
        validate("lts-release-index", candidate)
    except Exception as exc:
        raise LtsReleaseIndexError("LTS release index schema rejected") from exc
    _verify_artifact_path(index_artifact_path)
    if candidate["artifact_path"] != index_artifact_path:
        raise LtsReleaseIndexError("release index artifact path mismatch")
    verification = verify_lts_version_matrix(
        candidate["matrix"],
        expected_product_version=expected_product_version,
    )
    if candidate["matrix_digest"] != verification["matrix_digest"]:
        raise LtsReleaseIndexError("release index matrix digest mismatch")
    umbrella = candidate["matrix"]["umbrella"]
    if candidate["release"] != {
        "release_id": umbrella["release_id"],
        "version": umbrella["version"],
        "tag": umbrella["tag"],
        "status": umbrella["status"],
    }:
        raise LtsReleaseIndexError("release index umbrella metadata diverged")
    manifest = dict(release_manifest)
    release = candidate["release"]
    if (
        manifest["release_id"] != release["release_id"]
        or manifest["version"] != release["version"]
        or manifest["source_revision"] != candidate["source_revision"]
        or candidate["source_revision"] != expected_source_revision
        or manifest["created_at"] != candidate["created_at"]
    ):
        raise LtsReleaseIndexError("release index does not match its signed manifest")
    if not any(item["path"] == index_artifact_path for item in manifest["artifacts"]):
        raise LtsReleaseIndexError("release index is absent from the signed inventory")
    return {
        "ok": True,
        "status": release["status"],
        "release_id": release["release_id"],
        "version": release["version"],
        "source_revision": candidate["source_revision"],
        "matrix_digest": verification["matrix_digest"],
        "release_manifest_digest": manifest_digest,
        "production_authority": False,
        "memory_grants_authority": False,
        "automatic_remote_rollout": False,
    }


__all__ = [
    "LtsReleaseIndexError",
    "build_lts_release_index",
    "load_lts_version_matrix",
    "lts_version_report",
    "verify_lts_release_index",
    "verify_lts_version_matrix",
    "write_lts_release_index",
]
