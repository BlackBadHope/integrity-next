"""Machine-readable Adapter Execution SDK LTS candidate contract."""

from __future__ import annotations

import hashlib
import json
from importlib.resources import files
from typing import Any

from ._facade import FACADE_MODULES
from ._version import ADAPTER_SDK_VERSION, __version__

LTS_TRACK_ID = "adapter-execution-sdk-lts"
LTS_CONTRACT_PROTOCOL = "integrity-adapter-sdk/lts-support-contract/v1"


class SdkContractError(ValueError):
    """Raised when the packaged candidate contract is malformed or mismatched."""


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SdkContractError("duplicate key in Adapter SDK contract")
        result[key] = value
    return result


def adapter_execution_sdk_lts_contract() -> dict[str, Any]:
    """Load and verify the immutable package-local LTS candidate declaration."""

    path = files("integrity_adapter_sdk").joinpath("contracts", "adapter-execution-sdk-lts.json")
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_strict_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SdkContractError("Adapter SDK LTS contract could not be loaded") from exc
    if not isinstance(value, dict):
        raise SdkContractError("Adapter SDK LTS contract must be an object")
    expected = {
        "protocol": LTS_CONTRACT_PROTOCOL,
        "track_id": LTS_TRACK_ID,
        "component": "integrity-adapter-sdk",
        "distribution": "integrity-adapter-sdk",
        "package_version": __version__,
        "signed_document_version": ADAPTER_SDK_VERSION,
        "guardian_dependency": "integrity-guardian==6.0.0",
        "status": "lts-candidate",
        "support_window_months": 24,
        "activation_rule": "first-signed-non-prerelease-release",
        "implementation_boundary": "transitional-guardian-facade",
        "implementation_extraction": "later-major-boundary",
        "facade_modules": sorted(FACADE_MODULES),
        "owned_import_roots": ["integrity_adapter_sdk"],
        "forbidden_wheel_prefixes": ["integrity_guardian/"],
        "production_authority": False,
        "memory_grants_authority": False,
        "stable_activated": False,
    }
    for key, expected_value in expected.items():
        if value.get(key) != expected_value:
            raise SdkContractError(f"Adapter SDK LTS contract mismatch: {key}")
    invariants = value.get("invariants")
    if (
        set(value) != set(expected) | {"invariants"}
        or not isinstance(invariants, list)
        or invariants != sorted(set(invariants))
        or not invariants
        or any(not isinstance(item, str) or not item for item in invariants)
    ):
        raise SdkContractError("Adapter SDK LTS contract invariant set rejected")
    return value


def adapter_execution_sdk_lts_contract_digest() -> str:
    """Return the deterministic digest of the verified candidate contract."""

    payload = json.dumps(
        adapter_execution_sdk_lts_contract(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


__all__ = [
    "LTS_CONTRACT_PROTOCOL",
    "LTS_TRACK_ID",
    "SdkContractError",
    "adapter_execution_sdk_lts_contract",
    "adapter_execution_sdk_lts_contract_digest",
]
