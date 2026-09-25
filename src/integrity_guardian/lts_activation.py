"""Verify one LTS track activation covered by an exact signed release manifest."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Any

from .canonical import canonical_bytes
from .hashing import digest_object
from .lts import (
    LTS_TRACK_IDS,
    load_lts_contracts,
    lts_track_contract_digest,
    verify_lts_contracts,
)
from .release import verify_release_manifest
from .schemas import validate
from .signing import TrustedKey

STABLE_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
MINIMUM_SUPPORT_DAYS = 730


class LtsActivationError(ValueError):
    """Raised when external evidence cannot activate one LTS track."""


def _track(contracts: Mapping[str, Any], track_id: str) -> Mapping[str, Any]:
    for track in contracts["tracks"]:
        if track["track_id"] == track_id:
            return track
    raise LtsActivationError("activation track is not canonical")


def _parse_timestamp(value: str, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise LtsActivationError(f"{field} is not a valid timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise LtsActivationError(f"{field} must be UTC")
    return parsed.astimezone(UTC)


def _verify_support_window(receipt: Mapping[str, Any], track: Mapping[str, Any]) -> None:
    activated_at = _parse_timestamp(receipt["activated_at"], "activated_at")
    support_until = _parse_timestamp(receipt["support_until"], "support_until")
    if receipt["support_window_months"] != track["support_window_months"]:
        raise LtsActivationError("activation support window changed the track contract")
    if support_until - activated_at < timedelta(days=MINIMUM_SUPPORT_DAYS):
        raise LtsActivationError("activation support window is shorter than 24 months")


def _verify_stable_release(receipt: Mapping[str, Any]) -> None:
    track_id = receipt["track_id"]
    version = receipt["release"]["version"]
    if not STABLE_VERSION_RE.fullmatch(version):
        raise LtsActivationError("LTS activation requires a non-prerelease stable version")
    if receipt["release"]["release_id"] != f"release:lts:{track_id}:{version}":
        raise LtsActivationError("LTS activation release identity mismatch")
    if receipt["release"]["tag"] != f"lts/{track_id}/v{version}":
        raise LtsActivationError("LTS activation tag does not match the track and version")


def _verify_artifact_path(value: str) -> None:
    portable = PurePosixPath(value)
    if (
        portable.is_absolute()
        or portable.as_posix() != value
        or any(part in {"", ".", ".."} for part in portable.parts)
    ):
        raise LtsActivationError("activation receipt artifact path is not canonical")


def build_lts_track_activation_receipt(
    *,
    track_id: str,
    release_id: str,
    release_version: str,
    release_tag: str,
    product_version: str,
    source_revision: str,
    artifact_path: str,
    activated_at: str,
    support_until: str,
    reproducible_artifacts_digest: str,
    local_suite_digest: str,
    hosted_linux_digest: str,
    track_gate_digest: str,
    release_review_digest: str,
    contracts: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build unsigned track evidence that must itself enter the signed inventory."""

    current = dict(load_lts_contracts() if contracts is None else contracts)
    verify_lts_contracts(current)
    track = _track(current, track_id)
    receipt: dict[str, Any] = {
        "protocol": "integrity-guardian/lts-track-activation-receipt/v2",
        "track_id": track_id,
        "contract_version": track["contract_version"],
        "contract_digest": lts_track_contract_digest(track),
        "contract_digest_scope": "track",
        "artifact_path": artifact_path,
        "release": {
            "release_id": release_id,
            "version": release_version,
            "tag": release_tag,
            "product_version": product_version,
            "source_revision": source_revision,
        },
        "activated_at": activated_at,
        "support_until": support_until,
        "support_window_months": track["support_window_months"],
        "evidence": {
            "reproducible_artifacts_digest": reproducible_artifacts_digest,
            "local_suite_digest": local_suite_digest,
            "hosted_linux_digest": hosted_linux_digest,
            "track_gate_digest": track_gate_digest,
            "release_review_digest": release_review_digest,
        },
        "controls": {
            "production_authority": False,
            "memory_grants_authority": False,
            "signed_release_manifest_required": True,
            "other_tracks_activated": False,
        },
    }
    try:
        validate("lts-track-activation-receipt", receipt)
    except Exception as exc:
        raise LtsActivationError("LTS activation receipt schema rejected") from exc
    _verify_artifact_path(receipt["artifact_path"])
    _verify_stable_release(receipt)
    _verify_support_window(receipt, track)
    return receipt


def write_lts_track_activation_receipt(path: Path, receipt: Mapping[str, Any]) -> Path:
    """Write one non-secret release artifact without replacing an existing file."""

    validate("lts-track-activation-receipt", dict(receipt))
    parent = path.parent
    if not parent.is_dir() or parent.is_symlink() or path.is_symlink():
        raise LtsActivationError("activation receipt parent or output path is unsafe")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o644)
    except OSError as exc:
        raise LtsActivationError("activation receipt output must be absent") from exc
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(canonical_bytes(dict(receipt)) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return path


def verify_lts_track_activation(
    receipt: Mapping[str, Any],
    *,
    release_manifest: Mapping[str, Any],
    authority_key: TrustedKey,
    expected_source_revision: str,
    expected_product_version: str,
    expected_artifacts: list[dict[str, Any]],
    receipt_artifact_path: str,
    contracts: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Derive one active track without mutating the packaged candidate contract."""

    document = dict(receipt)
    try:
        validate("lts-track-activation-receipt", document)
    except Exception as exc:
        raise LtsActivationError("LTS activation receipt schema rejected") from exc
    _verify_artifact_path(document["artifact_path"])
    _verify_stable_release(document)

    current = dict(load_lts_contracts() if contracts is None else contracts)
    verification = verify_lts_contracts(current)
    track = _track(current, document["track_id"])
    if document["contract_version"] != track["contract_version"]:
        raise LtsActivationError("activation contract version mismatch")
    if document["protocol"] == "integrity-guardian/lts-track-activation-receipt/v1":
        expected_contract_digest = verification["contract_digest"]
    else:
        if document.get("contract_digest_scope") != "track":
            raise LtsActivationError("activation contract digest scope mismatch")
        expected_contract_digest = lts_track_contract_digest(track)
    if document["contract_digest"] != expected_contract_digest:
        raise LtsActivationError("activation contract digest mismatch")
    _verify_support_window(document, track)

    release = document["release"]
    if release["source_revision"] != expected_source_revision:
        raise LtsActivationError("activation source revision mismatch")
    if release["product_version"] != expected_product_version:
        raise LtsActivationError("activation product version mismatch")
    if release_manifest.get("release_id") != release["release_id"]:
        raise LtsActivationError("activation release identity mismatch")
    if release_manifest.get("version") != release["version"]:
        raise LtsActivationError("activation release version mismatch")
    if release_manifest.get("created_at") != document["activated_at"]:
        raise LtsActivationError("activation timestamp does not match the signed release")
    manifest_digest = verify_release_manifest(
        dict(release_manifest),
        authority_key=authority_key,
        expected_source_revision=expected_source_revision,
        expected_artifacts=expected_artifacts,
    )

    if receipt_artifact_path != document["artifact_path"]:
        raise LtsActivationError("activation receipt path mismatch")
    manifest_paths = {item["path"] for item in release_manifest["artifacts"]}
    if document["artifact_path"] not in manifest_paths:
        raise LtsActivationError("activation receipt is not covered by the release manifest")

    statuses = {track_id: "lts-candidate" for track_id in LTS_TRACK_IDS}
    statuses[document["track_id"]] = "active"
    return {
        "ok": True,
        "track_id": document["track_id"],
        "status": "active",
        "track_statuses": statuses,
        "contract_version": document["contract_version"],
        "contract_digest": document["contract_digest"],
        "activation_receipt_digest": digest_object(
            document,
            domain=(
                "integrity-lts-track-activation-receipt-v2"
                if document["protocol"].endswith("/v2")
                else "integrity-lts-track-activation-receipt-v1"
            ),
        ),
        "release_manifest_digest": manifest_digest,
        "release_id": release["release_id"],
        "release_version": release["version"],
        "release_tag": release["tag"],
        "product_version": release["product_version"],
        "source_revision": release["source_revision"],
        "activated_at": document["activated_at"],
        "support_until": document["support_until"],
        "production_authority": False,
        "memory_grants_authority": False,
    }
