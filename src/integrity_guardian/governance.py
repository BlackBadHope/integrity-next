"""Verified product governance distributed with every Guardian installation."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import Any

from .canonical import parse_json_strict
from .hashing import digest_object

DOCUMENTS = (
    "AGENT-OPERATING-CONTRACT.md",
    "AUTHORITY-AND-GO.md",
    "CREDENTIAL-HANDLING.md",
    "EVIDENCE-AND-TRUTH.md",
    "HANDOFF-AND-CONTINUITY.md",
    "INCIDENT-AND-ROLLBACK.md",
    "OPERATOR-REQUEST-PROTOCOL.md",
)
MANIFEST_NAME = "governance-manifest.json"
# This anchor is part of the signed executable package, not data supplied by the
# governance directory.  It prevents a replaced document set from authorizing
# itself by replacing the adjacent manifest at the same time.
EXPECTED_MANIFEST_DIGEST = (
    "sha256:6164d3a2382a57d6eee81218690bc106ef781ba468c84ac0e61c552482227a31"
)
EXPECTED_CONTROLS = {
    "production_authority": False,
    "credentials_permitted": False,
    "customer_policy_embedded": False,
    "unknown_fails_closed": True,
}


class GovernanceBundleError(ValueError):
    """Raised when the installed governance bundle cannot be trusted."""


def packaged_governance_root() -> Path:
    return Path(__file__).with_name("governance")


def _read_regular_nofollow(path: Path) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise GovernanceBundleError(f"governance path is absent or unsafe: {path.name}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise GovernanceBundleError(f"governance path is not a regular file: {path.name}")
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 64 * 1024):
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise GovernanceBundleError(f"governance file changed during read: {path.name}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def verify_governance_bundle(root: Path | None = None) -> dict[str, Any]:
    """Verify the exact installed document set and return its trusted identity."""

    bundle_root = packaged_governance_root() if root is None else root
    try:
        root_details = bundle_root.lstat()
    except OSError as exc:
        raise GovernanceBundleError("governance bundle is absent") from exc
    if not stat.S_ISDIR(root_details.st_mode):
        raise GovernanceBundleError("governance bundle root is not a real directory")

    actual_names = sorted(
        item.name
        for item in bundle_root.iterdir()
        if item.name != "__pycache__"
    )
    expected_names = sorted((*DOCUMENTS, MANIFEST_NAME))
    if actual_names != expected_names:
        raise GovernanceBundleError("governance bundle file set mismatch")

    manifest = parse_json_strict(_read_regular_nofollow(bundle_root / MANIFEST_NAME))
    manifest_digest = digest_object(
        manifest,
        domain="governance-bundle-manifest-v1",
    )
    if manifest_digest != EXPECTED_MANIFEST_DIGEST:
        raise GovernanceBundleError("governance manifest digest mismatch")
    if not isinstance(manifest, dict) or set(manifest) != {
        "protocol",
        "bundle_id",
        "version",
        "documents",
        "controls",
    }:
        raise GovernanceBundleError("governance manifest shape rejected")
    if manifest["protocol"] != "integrity-guardian/governance-bundle/v1":
        raise GovernanceBundleError("governance manifest protocol rejected")
    if manifest["bundle_id"] != "governance:guardian-core-3.0.2":
        raise GovernanceBundleError("governance bundle identity rejected")
    if manifest["version"] != "3.0.2":
        raise GovernanceBundleError("governance version rejected")
    if manifest["controls"] != EXPECTED_CONTROLS:
        raise GovernanceBundleError("governance controls rejected")

    documents = manifest["documents"]
    if not isinstance(documents, list) or [
        item.get("path") for item in documents if isinstance(item, dict)
    ] != list(DOCUMENTS):
        raise GovernanceBundleError("governance document inventory rejected")

    for item in documents:
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "size_bytes"}:
            raise GovernanceBundleError("governance document entry rejected")
        path = item["path"]
        if path not in DOCUMENTS or Path(path).name != path:
            raise GovernanceBundleError("governance document path rejected")
        payload = _read_regular_nofollow(bundle_root / path)
        if len(payload) != item["size_bytes"]:
            raise GovernanceBundleError(f"governance document size mismatch: {path}")
        if hashlib.sha256(payload).hexdigest() != item["sha256"]:
            raise GovernanceBundleError(f"governance document digest mismatch: {path}")
        try:
            payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise GovernanceBundleError(
                f"governance document is not UTF-8: {path}"
            ) from exc

    return {
        "manifest": manifest,
        "digest": manifest_digest,
        "document_count": len(documents),
        "production_authority": False,
    }


def governance_bundle_digest(root: Path | None = None) -> str:
    return str(verify_governance_bundle(root)["digest"])
