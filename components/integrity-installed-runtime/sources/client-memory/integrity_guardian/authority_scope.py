"""Shared authority-scope vocabulary for memory and external actions.

Integrity Memory reports what the memory provider itself can do.  It never
evaluates authority for an unrelated target action.  Keeping those decisions
in separate typed fields prevents a provider capability boundary from being
misread as either an external authorization or an external denial.
"""

from __future__ import annotations

from typing import Literal

AUTHORITY_SEPARATION_PROTOCOL = "integrity-guardian/authority-separation/v1"

MemoryCoordinationStatus = Literal["not-evaluated", "ready", "stopped"]


def memory_authority_contract(
    coordination_status: MemoryCoordinationStatus = "not-evaluated",
) -> dict[str, object]:
    """Return the closed authority contract exposed by Memory surfaces."""

    if coordination_status not in {"not-evaluated", "ready", "stopped"}:
        raise ValueError("memory coordination status is invalid")
    return {
        "protocol": AUTHORITY_SEPARATION_PROTOCOL,
        "provider_authority": {
            "provider": "integrity-client-memory",
            "scope": "canonical-seed-memory",
            "execution": "absent",
            "production": "absent",
            "route": "absent",
            "canonical_seed_append": "one-use-only",
        },
        "target_action_authority": {
            "decision": "not-evaluated",
            "authoritative_source": "target-specific-action-guard",
            "provider_boundary_is_target_denial": False,
        },
        "coordination": {
            "scope": "integrity-memory-route",
            "status": coordination_status,
            "canonical_seed_append_affected": False,
            "external_target_actions_affected": False,
        },
        "legacy_projection": {
            "production_authority": False,
            "semantics": "memory-provider-does-not-grant-production-authority",
            "deprecated": True,
            "replacement": "authority_contract.provider_authority.production",
        },
    }
