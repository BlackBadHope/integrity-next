"""Signed admission contracts for external discovery appliances.

The trusted core validates appliance identity, protocol, taxonomy, limits and
conformance requirements. It does not import, launch, sandbox or communicate
with an appliance and cannot obtain execution authority from this manifest.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from jsonschema import ValidationError

from .canonical import canonical_bytes
from .discovery import (
    MAX_DISCOVERY_BATCH_RECORDS,
    DiscoveryAssertionKind,
    UnknownClass,
)
from .hashing import digest_object
from .schemas import validate
from .signing import Ed25519Signer, TrustedKey, verify_bytes

MAX_DISCOVERY_APPLIANCE_EVENTS = 1_000
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[.-][A-Za-z0-9.]+)?$")
_EVENT_KIND = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_APPLIANCE_CLASS = "synthetic-fixture-compiler"
_APPLIANCE_BOUNDARY = {
    "active_capture": False,
    "credentials": False,
    "execution": False,
    "filesystem_write": False,
    "model_sdk": False,
    "network": False,
    "production_authority": False,
    "raw_addresses": False,
}


class DiscoveryApplianceError(ValueError):
    """Raised when an external appliance admission contract is untrusted."""


def _require_id(value: object, field: str, *, synthetic: bool = False) -> None:
    if (
        not isinstance(value, str)
        or _ID.fullmatch(value) is None
        or (synthetic and "synthetic" not in value)
    ):
        raise DiscoveryApplianceError(
            f"discovery appliance {field} rejected"
        )


def _require_digest(value: object, field: str) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise DiscoveryApplianceError(
            f"discovery appliance {field} rejected"
        )


@dataclass(frozen=True)
class DiscoveryApplianceAdmissionPolicy:
    """Out-of-band exact contract for one non-executable appliance."""

    policy_id: str
    tenant_id: str
    appliance_id: str
    appliance_version: str
    source_protocol: str
    source_id: str
    source_artifact_digest: str
    input_schema_digest: str
    allowed_event_kinds: tuple[str, ...]
    max_events: int
    max_records: int
    conformance_profile_digest: str
    required_assertion_kinds: tuple[DiscoveryAssertionKind, ...]
    required_gap_classes: tuple[UnknownClass, ...]
    require_cross_zone_relation: bool
    require_tombstone: bool

    def __post_init__(self) -> None:
        _require_id(self.policy_id, "policy id", synthetic=True)
        if self.tenant_id != "tenant:public-6e3cdbebaafc8efa":
            raise DiscoveryApplianceError(
                "discovery appliance synthetic tenant required"
            )
        _require_id(self.appliance_id, "identity", synthetic=True)
        if (
            not isinstance(self.appliance_version, str)
            or _VERSION.fullmatch(self.appliance_version) is None
        ):
            raise DiscoveryApplianceError(
                "discovery appliance version rejected"
            )
        if (
            not isinstance(self.source_protocol, str)
            or not self.source_protocol.startswith("integrity-guardian/")
            or not self.source_protocol.endswith("/v1")
            or any(char.isspace() for char in self.source_protocol)
        ):
            raise DiscoveryApplianceError(
                "discovery appliance source protocol rejected"
            )
        _require_id(self.source_id, "source id", synthetic=True)
        _require_digest(self.source_artifact_digest, "artifact digest")
        _require_digest(self.input_schema_digest, "input schema digest")
        _require_digest(
            self.conformance_profile_digest,
            "conformance profile digest",
        )
        if (
            not isinstance(self.allowed_event_kinds, tuple)
            or not self.allowed_event_kinds
            or len(set(self.allowed_event_kinds))
            != len(self.allowed_event_kinds)
            or any(
                not isinstance(kind, str)
                or _EVENT_KIND.fullmatch(kind) is None
                for kind in self.allowed_event_kinds
            )
        ):
            raise DiscoveryApplianceError(
                "discovery appliance event taxonomy rejected"
            )
        if (
            not isinstance(self.max_events, int)
            or isinstance(self.max_events, bool)
            or not 1 <= self.max_events <= MAX_DISCOVERY_APPLIANCE_EVENTS
            or not isinstance(self.max_records, int)
            or isinstance(self.max_records, bool)
            or not self.max_events
            <= self.max_records
            <= MAX_DISCOVERY_BATCH_RECORDS
        ):
            raise DiscoveryApplianceError(
                "discovery appliance limits rejected"
            )
        if (
            not isinstance(self.required_assertion_kinds, tuple)
            or not self.required_assertion_kinds
            or any(
                not isinstance(kind, DiscoveryAssertionKind)
                for kind in self.required_assertion_kinds
            )
            or len(set(self.required_assertion_kinds))
            != len(self.required_assertion_kinds)
        ):
            raise DiscoveryApplianceError(
                "discovery appliance assertion requirements rejected"
            )
        if (
            not isinstance(self.required_gap_classes, tuple)
            or any(
                not isinstance(gap_class, UnknownClass)
                for gap_class in self.required_gap_classes
            )
            or len(set(self.required_gap_classes))
            != len(self.required_gap_classes)
        ):
            raise DiscoveryApplianceError(
                "discovery appliance gap requirements rejected"
            )
        if not isinstance(
            self.require_cross_zone_relation,
            bool,
        ) or not isinstance(self.require_tombstone, bool):
            raise DiscoveryApplianceError(
                "discovery appliance conformance flags rejected"
            )


def _policy_document(
    policy: DiscoveryApplianceAdmissionPolicy,
) -> dict[str, Any]:
    if not isinstance(policy, DiscoveryApplianceAdmissionPolicy):
        raise DiscoveryApplianceError(
            "discovery appliance admission policy rejected"
        )
    return {
        "policy_id": policy.policy_id,
        "tenant_id": policy.tenant_id,
        "appliance_id": policy.appliance_id,
        "appliance_version": policy.appliance_version,
        "appliance_class": _APPLIANCE_CLASS,
        "source": {
            "protocol": policy.source_protocol,
            "source_id": policy.source_id,
            "artifact_digest": policy.source_artifact_digest,
            "input_schema_digest": policy.input_schema_digest,
        },
        "taxonomy": {
            "event_kinds": sorted(policy.allowed_event_kinds),
            "assertion_kinds": sorted(
                kind.value for kind in policy.required_assertion_kinds
            ),
            "gap_classes": sorted(
                gap_class.value for gap_class in policy.required_gap_classes
            ),
        },
        "limits": {
            "max_events": policy.max_events,
            "max_records": policy.max_records,
        },
        "conformance": {
            "profile_digest": policy.conformance_profile_digest,
            "require_cross_zone_relation": (
                policy.require_cross_zone_relation
            ),
            "require_tombstone": policy.require_tombstone,
        },
        "boundary": deepcopy(_APPLIANCE_BOUNDARY),
    }


def discovery_appliance_policy_digest(
    policy: DiscoveryApplianceAdmissionPolicy,
) -> str:
    """Return the exact identity of an out-of-band admission policy."""

    return digest_object(
        _policy_document(policy),
        domain="discovery-appliance-admission-policy-v1",
    )


def _manifest_core(manifest: Mapping[str, Any]) -> dict[str, Any]:
    core = deepcopy(dict(manifest))
    core.pop("manifest_id", None)
    core.pop("signature", None)
    return core


def discovery_appliance_manifest_identity(
    manifest: Mapping[str, Any],
) -> str:
    """Return the content identity of one appliance admission manifest."""

    digest = digest_object(
        _manifest_core(manifest),
        domain="discovery-appliance-manifest-identity-v1",
    )
    return f"discovery-appliance-manifest:{digest.split(':', 1)[1]}"


def _signature_payload(document: Mapping[str, Any]) -> bytes:
    unsigned = deepcopy(dict(document))
    unsigned.pop("signature", None)
    return (
        b"integrity-guardian\x00discovery-appliance-manifest-v1\x00"
        + canonical_bytes(unsigned)
    )


def build_discovery_appliance_manifest(
    policy: DiscoveryApplianceAdmissionPolicy,
    *,
    created_at: str,
    authority_signer: Ed25519Signer,
) -> dict[str, Any]:
    """Build and sign a non-executable external-appliance admission manifest."""

    if not isinstance(authority_signer, Ed25519Signer):
        raise DiscoveryApplianceError(
            "discovery appliance authority signer rejected"
        )
    core = {
        "protocol": "integrity-guardian/discovery-appliance-manifest/v1",
        "policy_digest": discovery_appliance_policy_digest(policy),
        **_policy_document(policy),
        "created_at": created_at,
    }
    document = {
        "manifest_id": discovery_appliance_manifest_identity(core),
        **core,
    }
    document["signature"] = {
        "algorithm": "ed25519",
        "key_id": authority_signer.key_id,
        "value": authority_signer.sign_bytes(_signature_payload(document)),
    }
    verify_discovery_appliance_manifest(
        document,
        authority_key=TrustedKey(
            key_id=authority_signer.key_id,
            public_key=authority_signer.public_key,
        ),
        expected_policy=policy,
    )
    return document


def verify_discovery_appliance_manifest(
    manifest: Mapping[str, Any],
    *,
    authority_key: TrustedKey,
    expected_policy: DiscoveryApplianceAdmissionPolicy,
) -> dict[str, Any]:
    """Verify schema, identity, signature and the complete exact policy."""

    try:
        candidate = deepcopy(dict(manifest))
        validate("discovery-appliance-manifest", candidate)
    except (TypeError, KeyError, ValueError, ValidationError) as exc:
        raise DiscoveryApplianceError(
            "discovery appliance manifest schema rejected"
        ) from exc
    if not isinstance(authority_key, TrustedKey):
        raise DiscoveryApplianceError(
            "discovery appliance trusted authority rejected"
        )
    if (
        candidate["manifest_id"]
        != discovery_appliance_manifest_identity(candidate)
    ):
        raise DiscoveryApplianceError(
            "discovery appliance manifest identity mismatch"
        )
    signature = candidate["signature"]
    if (
        signature["key_id"] != authority_key.key_id
        or not verify_bytes(
            _signature_payload(candidate),
            signature["value"],
            authority_key.public_key,
        )
    ):
        raise DiscoveryApplianceError(
            "discovery appliance authority signature rejected"
        )
    expected_policy_digest = discovery_appliance_policy_digest(
        expected_policy
    )
    if candidate["policy_digest"] != expected_policy_digest:
        raise DiscoveryApplianceError(
            "discovery appliance admission policy mismatch"
        )
    expected_document = _policy_document(expected_policy)
    for field, expected_value in expected_document.items():
        if candidate[field] != expected_value:
            raise DiscoveryApplianceError(
                f"discovery appliance {field} policy mismatch"
            )
    if candidate["boundary"] != _APPLIANCE_BOUNDARY:
        raise DiscoveryApplianceError(
            "discovery appliance non-execution boundary mismatch"
        )
    return candidate
