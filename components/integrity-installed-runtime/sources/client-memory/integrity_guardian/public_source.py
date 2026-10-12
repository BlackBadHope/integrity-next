"""Truthful version metadata for public production source releases.

This optional descriptor carries no source-history IDs, keys, signed release
receipts or LTS activation. It is informational, never an authority source.
The ordinary private distribution continues to use its existing LTS inventory.
"""
from __future__ import annotations

from importlib.resources import files
from typing import Any

from .canonical import parse_json_strict

DESCRIPTOR_NAME = "public-source-descriptor.json"
MAX_DESCRIPTOR_BYTES = 16 * 1024
_FIXED = {
    "protocol": "integrity-guardian/public-source-descriptor/v2",
    "artifact_class": "production-source-release",
    "validation_status": "accepted",
    "publication_ready": True,
    "user_managed_production_supported": True,
    "private_release_evidence_included": False,
    "lts_activation_inherited": False,
    "maintainer_infrastructure_authority_inherited": False,
    "memory_grants_authority": False,
}


class PublicSourceDescriptorError(ValueError):
    """The optional public package profile is malformed or ambiguous."""


def verify_public_source_descriptor(
    data: bytes, *, expected_product_version: str
) -> dict[str, Any]:
    """Validate a closed informational descriptor, not a signed attestation."""
    if len(data) > MAX_DESCRIPTOR_BYTES:
        raise PublicSourceDescriptorError("public source descriptor exceeds the bound")
    try:
        value = parse_json_strict(data)
    except (ValueError, UnicodeError, TypeError, RecursionError) as exc:
        raise PublicSourceDescriptorError("invalid public source descriptor JSON") from exc
    if not isinstance(value, dict) or set(value) != {*_FIXED, "product_version"}:
        raise PublicSourceDescriptorError("public source descriptor shape mismatch")
    for key, expected in _FIXED.items():
        if type(value[key]) is not type(expected) or value[key] != expected:
            raise PublicSourceDescriptorError("public source descriptor profile mismatch")
    if (
        type(value["product_version"]) is not str
        or type(expected_product_version) is not str
        or not expected_product_version
        or value["product_version"] != expected_product_version
    ):
        raise PublicSourceDescriptorError("public source descriptor version mismatch")
    return value


def public_source_version_report(*, expected_product_version: str) -> dict[str, Any] | None:
    """Return the explicit public profile or None; never infer one from missing LTS data."""
    package = files("integrity_guardian")
    descriptor = package.joinpath(DESCRIPTOR_NAME)
    if not descriptor.is_file():
        return None
    if package.joinpath("lts-version-matrix.json").is_file():
        raise PublicSourceDescriptorError("mixed public and private release inventories")
    with descriptor.open("rb") as stream:
        data = stream.read(MAX_DESCRIPTOR_BYTES + 1)
    value = verify_public_source_descriptor(data, expected_product_version=expected_product_version)
    return {
        **value,
        "protocol": "integrity-guardian/public-version-report/v2",
        "product": "Integrity Guardian",
        "version": expected_product_version,
        "verification_scope": "public-manifest-privacy-build-install-functional-gates",
        "release_evidence": "public-release-gates",
        "lts_inventory": "not-packaged",
    }
