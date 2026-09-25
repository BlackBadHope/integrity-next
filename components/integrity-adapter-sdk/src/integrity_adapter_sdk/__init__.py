"""Separately versioned transitional Integrity Adapter SDK facade."""

from __future__ import annotations

from typing import Any

from ._facade import (
    EXPECTED_GUARDIAN_DISTRIBUTION,
    EXPECTED_GUARDIAN_VERSION,
    FACADE_MODULES,
    SdkCompatibilityError,
    guardian_dependency_status,
    load_facade_module,
    require_guardian,
)
from ._version import ADAPTER_SDK_VERSION, __version__
from .contract import (
    LTS_CONTRACT_PROTOCOL,
    LTS_TRACK_ID,
    SdkContractError,
    adapter_execution_sdk_lts_contract,
    adapter_execution_sdk_lts_contract_digest,
)


def sdk_status() -> dict[str, Any]:
    """Return package, protocol, contract and dependency status without authority."""

    return {
        "protocol": "integrity-adapter-sdk/status/v1",
        "package_version": __version__,
        "signed_document_version": ADAPTER_SDK_VERSION,
        "lts_track_id": LTS_TRACK_ID,
        "lts_status": "lts-candidate",
        "lts_contract_digest": adapter_execution_sdk_lts_contract_digest(),
        "guardian_dependency": guardian_dependency_status(),
        "implementation_boundary": "transitional-guardian-facade",
        "production_authority": False,
        "memory_grants_authority": False,
    }


def __getattr__(name: str) -> Any:
    if name in FACADE_MODULES:
        module = load_facade_module(name)
        globals()[name] = module
        return module
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(FACADE_MODULES))


__all__ = [
    "ADAPTER_SDK_VERSION",
    "EXPECTED_GUARDIAN_DISTRIBUTION",
    "EXPECTED_GUARDIAN_VERSION",
    "FACADE_MODULES",
    "LTS_CONTRACT_PROTOCOL",
    "LTS_TRACK_ID",
    "SdkCompatibilityError",
    "SdkContractError",
    "__version__",
    "adapter_execution_sdk_lts_contract",
    "adapter_execution_sdk_lts_contract_digest",
    "guardian_dependency_status",
    "load_facade_module",
    "require_guardian",
    "sdk_status",
    *sorted(FACADE_MODULES),
]
