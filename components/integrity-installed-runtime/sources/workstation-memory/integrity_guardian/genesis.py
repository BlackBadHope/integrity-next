"""Pure receipt contract for the Integrity 5.5 Genesis rehearsal.

Genesis does not execute attacks.  The packaged core verifies one bounded,
synthetic result produced by an external containment appliance.  It performs
no filesystem, process, network, browser, credential or service I/O.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from jsonschema import ValidationError

from .canonical import CanonicalizationError, canonical_bytes, parse_json_strict
from .hashing import digest_object
from .schemas import validate
from .signing import Ed25519Signer, TrustedKey, verify_signature

GENESIS_SCENARIOS = (
    "synthetic-ddos-burst",
    "synthetic-hostile-operator",
    "synthetic-system-file-change",
    "synthetic-zero-day-cascade",
)

_ISOLATION_BOUNDARY = {
    "existing_integrity_attached": False,
    "existing_integrity_paths_read": False,
    "host_files_mutated": False,
    "network_namespace_isolated": True,
    "network_used": False,
    "production_targets": False,
    "real_vulnerability_exploited": False,
    "seed_mcp_oauth_accessed": False,
    "system_services_accessed": False,
    "sudo_used": False,
}
_AUTHORITY_BOUNDARY = {
    "attack_authority": False,
    "execution_authority": False,
    "production_authority": False,
    "promotion_authority": False,
    "remediation_authority": False,
}
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")


class GenesisReceiptError(ValueError):
    """Raised when a Genesis rehearsal claim is not closed and reproducible."""


@dataclass(frozen=True)
class GenesisRehearsalPolicy:
    """Exact user-space identity and budgets for one synthetic session."""

    policy_id: str
    session_id: str
    owner_uid: int
    owner_gid: int
    root_identity_digest: str
    seed_digest: str
    appliance_digest: str
    containment_profile_digest: str
    max_events: int = 256
    max_bytes: int = 1_048_576
    max_assets: int = 32
    max_cascade_depth: int = 8
    timeout_ms: int = 10_000

    def __post_init__(self) -> None:
        if (
            not isinstance(self.policy_id, str)
            or not self.policy_id.startswith("policy:synthetic-genesis-")
            or not isinstance(self.session_id, str)
            or not self.session_id.startswith("genesis-session:synthetic-")
        ):
            raise GenesisReceiptError("Genesis synthetic identity rejected")
        if (
            not isinstance(self.owner_uid, int)
            or isinstance(self.owner_uid, bool)
            or not isinstance(self.owner_gid, int)
            or isinstance(self.owner_gid, bool)
            or min(self.owner_uid, self.owner_gid) <= 0
        ):
            raise GenesisReceiptError("Genesis owner identity rejected")
        for value, field in (
            (self.root_identity_digest, "root identity"),
            (self.seed_digest, "seed"),
            (self.appliance_digest, "appliance"),
            (self.containment_profile_digest, "containment profile"),
        ):
            if (
                not isinstance(value, str)
                or _DIGEST.fullmatch(value) is None
            ):
                raise GenesisReceiptError(f"Genesis {field} digest rejected")
        limits = (
            (self.max_events, 1, 4096),
            (self.max_bytes, 4096, 16_777_216),
            (self.max_assets, 1, 256),
            (self.max_cascade_depth, 1, 32),
            (self.timeout_ms, 100, 60_000),
        )
        if any(
            not isinstance(value, int)
            or isinstance(value, bool)
            or not lower <= value <= upper
            for value, lower, upper in limits
        ):
            raise GenesisReceiptError("Genesis rehearsal budget rejected")

    def to_document(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "session_id": self.session_id,
            "owner_uid": self.owner_uid,
            "owner_gid": self.owner_gid,
            "root_identity_digest": self.root_identity_digest,
            "seed_digest": self.seed_digest,
            "appliance_digest": self.appliance_digest,
            "containment_profile_digest": self.containment_profile_digest,
            "budgets": {
                "max_events": self.max_events,
                "max_bytes": self.max_bytes,
                "max_assets": self.max_assets,
                "max_cascade_depth": self.max_cascade_depth,
                "timeout_ms": self.timeout_ms,
            },
            "mode": "synthetic-user-space-rehearsal",
            "direct_test_gate": "owner-attended-disabled",
        }

    @property
    def digest(self) -> str:
        return digest_object(
            self.to_document(),
            domain="genesis-rehearsal-policy-v1",
        )


def _detached_mapping(value: object) -> dict[str, Any]:
    try:
        detached = parse_json_strict(canonical_bytes(value))
    except (CanonicalizationError, TypeError, ValueError) as exc:
        raise GenesisReceiptError("Genesis receipt value rejected") from exc
    if not isinstance(detached, dict):
        raise GenesisReceiptError("Genesis receipt value rejected")
    return detached


def genesis_scenario_digest(scenario: Mapping[str, Any]) -> str:
    """Return the identity of one result without trusting its digest field."""

    core = deepcopy(dict(scenario))
    core.pop("scenario_digest", None)
    return digest_object(core, domain="genesis-synthetic-scenario-v1")


def _receipt_core(receipt: Mapping[str, Any]) -> dict[str, Any]:
    core = deepcopy(dict(receipt))
    core.pop("receipt_id", None)
    core.pop("signature", None)
    return core


def genesis_rehearsal_receipt_identity(receipt: Mapping[str, Any]) -> str:
    digest = digest_object(
        _receipt_core(receipt),
        domain="genesis-rehearsal-receipt-identity-v1",
    )
    return f"genesis-rehearsal-receipt:{digest.split(':', 1)[1]}"


def genesis_rehearsal_receipt_digest(receipt: Mapping[str, Any]) -> str:
    return digest_object(
        dict(receipt),
        domain="genesis-rehearsal-signed-receipt-v1",
    )


def _parse_time(value: object) -> datetime:
    if not isinstance(value, str):
        raise GenesisReceiptError("Genesis timing rejected")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise GenesisReceiptError("Genesis timing rejected") from exc
    if parsed.tzinfo is None:
        raise GenesisReceiptError("Genesis timing rejected")
    return parsed


def _verify_semantics(
    receipt: Mapping[str, Any],
    policy: GenesisRehearsalPolicy,
) -> None:
    if receipt["policy"] != policy.to_document() or receipt["policy_digest"] != policy.digest:
        raise GenesisReceiptError("Genesis policy binding mismatch")
    if receipt["isolation"] != _ISOLATION_BOUNDARY:
        raise GenesisReceiptError("Genesis isolation boundary mismatch")
    if receipt["authority_boundary"] != _AUTHORITY_BOUNDARY:
        raise GenesisReceiptError("Genesis authority boundary mismatch")

    scenarios = receipt["scenarios"]
    if tuple(item["name"] for item in scenarios) != GENESIS_SCENARIOS:
        raise GenesisReceiptError("Genesis scenario set or order rejected")
    if any(item["outcome"] != "synthetic-detected" for item in scenarios):
        raise GenesisReceiptError("Genesis scenario outcome rejected")
    if any(item["scenario_digest"] != genesis_scenario_digest(item) for item in scenarios):
        raise GenesisReceiptError("Genesis scenario digest mismatch")

    totals = {
        "scenario_count": len(scenarios),
        "event_count": sum(item["event_count"] for item in scenarios),
        "mutation_count": sum(item["mutation_count"] for item in scenarios),
        "affected_asset_count": sum(len(item["affected_assets"]) for item in scenarios),
    }
    if receipt["totals"] != totals:
        raise GenesisReceiptError("Genesis totals mismatch")
    budgets = policy.to_document()["budgets"]
    if (
        totals["event_count"] > budgets["max_events"]
        or totals["affected_asset_count"] > budgets["max_assets"]
        or max(item["cascade_depth"] for item in scenarios)
        > budgets["max_cascade_depth"]
        or receipt["workspace"]["bytes_written"] > budgets["max_bytes"]
    ):
        raise GenesisReceiptError("Genesis budget exceeded")
    started = _parse_time(receipt["timing"]["started_at"])
    completed = _parse_time(receipt["timing"]["completed_at"])
    if started > completed or receipt["timing"]["elapsed_ms"] > policy.timeout_ms:
        raise GenesisReceiptError("Genesis timing budget exceeded")


def verify_genesis_rehearsal_receipt(
    receipt: Mapping[str, Any],
    *,
    expected_policy: GenesisRehearsalPolicy,
    observer_key: TrustedKey,
) -> dict[str, Any]:
    """Verify a signed synthetic receipt without running or observing anything."""

    if not isinstance(expected_policy, GenesisRehearsalPolicy):
        raise GenesisReceiptError("Genesis policy rejected")
    if not isinstance(observer_key, TrustedKey):
        raise GenesisReceiptError("Genesis observer key rejected")
    candidate = _detached_mapping(receipt)
    try:
        validate("genesis-rehearsal-receipt", candidate)
    except ValidationError as exc:
        raise GenesisReceiptError("Genesis receipt schema rejected") from exc
    if candidate["receipt_id"] != genesis_rehearsal_receipt_identity(candidate):
        raise GenesisReceiptError("Genesis receipt identity mismatch")
    if (
        candidate["signature"]["key_id"] != observer_key.key_id
        or not verify_signature(candidate, observer_key.public_key)
    ):
        raise GenesisReceiptError("Genesis receipt signature rejected")
    _verify_semantics(candidate, expected_policy)
    return candidate


def build_genesis_rehearsal_receipt(
    *,
    policy: GenesisRehearsalPolicy,
    worker_result: Mapping[str, Any],
    observer_signer: Ed25519Signer,
) -> dict[str, Any]:
    """Bind, sign and self-verify one already completed synthetic rehearsal."""

    if not isinstance(policy, GenesisRehearsalPolicy):
        raise GenesisReceiptError("Genesis policy rejected")
    if not isinstance(observer_signer, Ed25519Signer):
        raise GenesisReceiptError("Genesis observer signer rejected")
    worker = _detached_mapping(worker_result)
    expected_fields = {
        "protocol",
        "session_id",
        "owner_uid",
        "owner_gid",
        "root_identity_digest",
        "seed_digest",
        "budgets",
        "scenarios",
        "totals",
        "workspace",
        "isolation",
        "timing",
    }
    if set(worker) != expected_fields:
        raise GenesisReceiptError("Genesis worker fields rejected")
    expected = policy.to_document()
    bindings = {
        "protocol": "integrity-guardian/genesis-worker-result/v1",
        "session_id": policy.session_id,
        "owner_uid": policy.owner_uid,
        "owner_gid": policy.owner_gid,
        "root_identity_digest": policy.root_identity_digest,
        "seed_digest": policy.seed_digest,
        "budgets": expected["budgets"],
    }
    if any(worker[field] != value for field, value in bindings.items()):
        raise GenesisReceiptError("Genesis worker binding mismatch")
    core = {
        "protocol": "integrity-guardian/genesis-rehearsal-receipt/v1",
        "tenant_id": "tenant:public-6e3cdbebaafc8efa",
        "policy": expected,
        "policy_digest": policy.digest,
        "scenarios": worker["scenarios"],
        "totals": worker["totals"],
        "workspace": worker["workspace"],
        "isolation": worker["isolation"],
        "timing": worker["timing"],
        "authority_boundary": deepcopy(_AUTHORITY_BOUNDARY),
    }
    unsigned = {
        "receipt_id": genesis_rehearsal_receipt_identity(core),
        **core,
    }
    signed = observer_signer.sign(unsigned)
    return verify_genesis_rehearsal_receipt(
        signed,
        expected_policy=policy,
        observer_key=TrustedKey(
            key_id=observer_signer.key_id,
            public_key=observer_signer.public_key,
        ),
    )


__all__ = [
    "GENESIS_SCENARIOS",
    "GenesisReceiptError",
    "GenesisRehearsalPolicy",
    "build_genesis_rehearsal_receipt",
    "genesis_rehearsal_receipt_digest",
    "genesis_rehearsal_receipt_identity",
    "genesis_scenario_digest",
    "verify_genesis_rehearsal_receipt",
]
