"""Read-only Atlas integration for the deterministic Synapse kernel.

Atlas supplies a verified projection and a target node.  It never supplies a
route or executable edge list.  Synapse compiles the policy-filtered local
capability slice, chooses the exact declared route and simulates it without
adapter execution, model calls or production authority.
"""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from jsonschema import ValidationError

from .atlas import AtlasProjectionError, verify_atlas_projection
from .canonical import canonical_bytes
from .hashing import digest_object
from .schemas import validate
from .synapse import (
    BlastRadius,
    SynapseContext,
    SynapseEvidence,
    SynapseGraphError,
    SynapseKernel,
    SynapsePolicy,
    SynapsePolicyError,
    SynapseRouteError,
    TransitionKind,
    verify_synapse_graph,
)

ATLAS_PROJECTION_EVIDENCE_ID = "evidence:atlas-projection"
_READ_ONLY_TRANSITIONS = {
    TransitionKind.OBSERVE.value,
    TransitionKind.ANALYZE.value,
    TransitionKind.PLAN.value,
    TransitionKind.VERIFY.value,
}
_ZERO_CALLS = {"model_calls": 0, "tool_calls": 0}
_INVARIANTS = {
    "execution_performed": False,
    "graph_policy_bound": True,
    "model_calls": 0,
    "production_authority": False,
    "projection_verified": True,
    "read_only": True,
    "route_context_bound": True,
    "route_edges_declared": True,
    "tool_calls": 0,
}


class AtlasSynapseError(ValueError):
    """Raised when Atlas cannot form one trusted read-only Synapse plan."""


def _time(value: str, *, field_name: str) -> datetime:
    if not isinstance(value, str):
        raise AtlasSynapseError(f"{field_name} must be an RFC3339 string")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise AtlasSynapseError(f"{field_name} must be RFC3339") from exc
    if parsed.tzinfo is None:
        raise AtlasSynapseError(f"{field_name} must include a timezone")
    return parsed


def _qualified_sha256(value: str, *, field_name: str) -> None:
    algorithm, separator, digest = value.partition(":")
    if (
        algorithm != "sha256"
        or separator != ":"
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise AtlasSynapseError(f"{field_name} must be an algorithm-qualified SHA-256")


@dataclass(frozen=True)
class AtlasSynapsePolicy:
    """Exact graph and capability authority for one Atlas integration."""

    policy_id: str
    graph_id: str
    allowed_subsystems: tuple[str, ...]
    allowed_capability_ids: tuple[str, ...]
    granted_authority_ids: tuple[str, ...] = ()
    max_projection_age_seconds: int = 300
    max_route_hops: int = 8
    max_route_expansions: int = 512
    slice_max_depth: int = 3
    slice_max_nodes: int = 64
    slice_max_edges: int = 128
    production_authority: bool = False

    def __post_init__(self) -> None:
        if not self.policy_id.startswith("policy:"):
            raise AtlasSynapseError("Atlas-Synapse policy identity is not canonical")
        _qualified_sha256(self.graph_id, field_name="graph_id")
        if not self.allowed_subsystems or "*" in self.allowed_subsystems:
            raise AtlasSynapseError("Atlas requires an explicit subsystem allowlist")
        if not self.allowed_capability_ids or "*" in self.allowed_capability_ids:
            raise AtlasSynapseError("Atlas requires an explicit capability allowlist")
        try:
            normalized = SynapsePolicy(
                allowed_subsystems=self.allowed_subsystems,
                allowed_capability_ids=self.allowed_capability_ids,
                granted_authority_ids=self.granted_authority_ids,
                max_transition_kind=TransitionKind.PLAN,
                max_blast_radius=BlastRadius.NONE,
            )
        except SynapsePolicyError as exc:
            raise AtlasSynapseError("Atlas-Synapse policy identifiers are invalid") from exc
        object.__setattr__(self, "allowed_subsystems", normalized.allowed_subsystems)
        object.__setattr__(
            self,
            "allowed_capability_ids",
            normalized.allowed_capability_ids,
        )
        object.__setattr__(
            self,
            "granted_authority_ids",
            normalized.granted_authority_ids,
        )
        if not 0 <= self.max_projection_age_seconds <= 31_536_000:
            raise AtlasSynapseError("projection freshness bound is outside the safe range")
        if not 1 <= self.max_route_hops <= 32:
            raise AtlasSynapseError("route hop bound is outside the safe range")
        if not 1 <= self.max_route_expansions <= 4_096:
            raise AtlasSynapseError("route expansion bound is outside the safe range")
        if not 0 <= self.slice_max_depth <= 32:
            raise AtlasSynapseError("slice depth bound is outside the safe range")
        if not 1 <= self.slice_max_nodes <= 512:
            raise AtlasSynapseError("slice node bound is outside the safe range")
        if not 0 <= self.slice_max_edges <= 2_048:
            raise AtlasSynapseError("slice edge bound is outside the safe range")
        if self.production_authority:
            raise AtlasSynapseError("Atlas-Synapse integration cannot grant production authority")

    def record(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "graph_id": self.graph_id,
            "allowed_subsystems": list(self.allowed_subsystems),
            "allowed_capability_ids": list(self.allowed_capability_ids),
            "granted_authority_ids": list(self.granted_authority_ids),
            "max_projection_age_seconds": self.max_projection_age_seconds,
            "max_route_hops": self.max_route_hops,
            "max_route_expansions": self.max_route_expansions,
            "slice_max_depth": self.slice_max_depth,
            "slice_max_nodes": self.slice_max_nodes,
            "slice_max_edges": self.slice_max_edges,
            "production_authority": False,
        }

    @property
    def digest(self) -> str:
        return digest_object(self.record(), domain="atlas-synapse-policy-v1")

    def synapse_policy(self) -> SynapsePolicy:
        return SynapsePolicy(
            allowed_subsystems=self.allowed_subsystems,
            allowed_capability_ids=self.allowed_capability_ids,
            granted_authority_ids=self.granted_authority_ids,
            max_transition_kind=TransitionKind.PLAN,
            max_blast_radius=BlastRadius.NONE,
        )


@dataclass(frozen=True)
class AtlasProjectionTrust:
    """Externally retained provenance pin for one Atlas projection."""

    projection_id: str
    checkpoint_digest: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.projection_id, str)
            or not self.projection_id.startswith("atlas:")
            or len(self.projection_id) != len("atlas:") + 64
            or any(
                character not in "0123456789abcdef"
                for character in self.projection_id.removeprefix("atlas:")
            )
        ):
            raise AtlasSynapseError("trusted Atlas projection identity is not canonical")
        _qualified_sha256(
            self.checkpoint_digest,
            field_name="trusted Atlas checkpoint_digest",
        )


def atlas_projection_evidence_digest(projection: Mapping[str, Any]) -> str:
    """Digest the exact verified Atlas projection used by Synapse."""

    return digest_object(
        deepcopy(dict(projection)),
        domain="atlas-synapse-projection-evidence-v1",
    )


class AtlasSynapsePlanner:
    """One prevalidated Atlas view over an explicit Synapse capability allowlist."""

    def __init__(
        self,
        *,
        graph: Mapping[str, Any],
        policy: AtlasSynapsePolicy,
        projection_trust: AtlasProjectionTrust,
    ) -> None:
        if not isinstance(policy, AtlasSynapsePolicy):
            raise AtlasSynapseError("policy must be an AtlasSynapsePolicy")
        if not isinstance(projection_trust, AtlasProjectionTrust):
            raise AtlasSynapseError(
                "projection_trust must be an independently retained AtlasProjectionTrust"
            )
        try:
            graph_verification = verify_synapse_graph(graph)
            kernel = SynapseKernel(graph)
        except (SynapseGraphError, ValidationError, KeyError, TypeError, ValueError) as exc:
            raise AtlasSynapseError("Atlas received an invalid Synapse graph") from exc
        if graph_verification["graph_id"] != policy.graph_id:
            raise AtlasSynapseError("Atlas policy does not bind the exact Synapse graph")

        graph_copy = deepcopy(dict(graph))
        capability_ids = {edge["capability_id"] for edge in graph_copy["edges"]}
        missing_capabilities = sorted(set(policy.allowed_capability_ids) - capability_ids)
        if missing_capabilities:
            raise AtlasSynapseError(
                f"Atlas policy names an unknown capability: {missing_capabilities[0]}"
            )
        allowed_edges = [
            edge
            for edge in graph_copy["edges"]
            if edge["capability_id"] in policy.allowed_capability_ids
        ]
        for edge in allowed_edges:
            if edge["transition_kind"] not in _READ_ONLY_TRANSITIONS:
                raise AtlasSynapseError("Atlas capability allowlist contains a mutation edge")
            if edge["blast_radius"] != BlastRadius.NONE.value:
                raise AtlasSynapseError("Atlas read-only edge declares a non-zero blast radius")
            evidence_ids = {
                requirement["evidence_id"]
                for requirement in edge["evidence_requirements"]
            }
            if ATLAS_PROJECTION_EVIDENCE_ID not in evidence_ids:
                raise AtlasSynapseError(
                    "Atlas capability lacks required projection evidence"
                )

        self.policy = policy
        self.projection_trust = projection_trust
        self._graph = graph_copy
        self._graph_tenant_id = graph_verification["tenant_id"]
        self._kernel = kernel
        self._edge_by_id = {
            edge["edge_id"]: edge for edge in graph_copy["edges"]
        }

    @property
    def graph_id(self) -> str:
        return self._kernel.graph_id

    def _verify_projection(
        self,
        projection: Mapping[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        candidate = deepcopy(dict(projection))
        try:
            verification = verify_atlas_projection(candidate)
        except (AtlasProjectionError, ValidationError, KeyError, TypeError, ValueError) as exc:
            raise AtlasSynapseError("Atlas projection verification failed") from exc
        if verification["tenant_id"] != self._graph_tenant_id:
            raise AtlasSynapseError("Atlas projection and Synapse graph tenant mismatch")
        if verification["production_authority"]:
            raise AtlasSynapseError("Atlas projection unexpectedly carries production authority")
        if (
            verification["projection_id"] != self.projection_trust.projection_id
            or candidate["generated_from"]["checkpoint_digest"]
            != self.projection_trust.checkpoint_digest
        ):
            raise AtlasSynapseError("Atlas projection trusted provenance mismatch")
        return candidate, verification

    def build_context(
        self,
        *,
        projection: Mapping[str, Any],
        current_node_id: str,
        as_of: str,
        projection_observed_at: str,
        facts: Mapping[str, str | int | bool | None] | None = None,
        evidence: Mapping[str, SynapseEvidence] | None = None,
    ) -> SynapseContext:
        candidate, verification = self._verify_projection(projection)
        return self._build_context_from_verified_projection(
            projection=candidate,
            projection_verification=verification,
            current_node_id=current_node_id,
            as_of=as_of,
            projection_observed_at=projection_observed_at,
            facts=facts,
            evidence=evidence,
        )

    def _build_context_from_verified_projection(
        self,
        *,
        projection: Mapping[str, Any],
        projection_verification: Mapping[str, Any],
        current_node_id: str,
        as_of: str,
        projection_observed_at: str,
        facts: Mapping[str, str | int | bool | None] | None,
        evidence: Mapping[str, SynapseEvidence] | None,
    ) -> SynapseContext:
        current_time = _time(as_of, field_name="as_of")
        observed_time = _time(
            projection_observed_at,
            field_name="projection_observed_at",
        )
        age_seconds = (current_time - observed_time).total_seconds()
        if age_seconds < 0:
            raise AtlasSynapseError("Atlas projection evidence is from the future")
        if age_seconds > self.policy.max_projection_age_seconds:
            raise AtlasSynapseError("Atlas projection evidence is stale")

        supplied_facts = deepcopy(dict(facts or {}))
        reserved_facts = sorted(
            key for key in supplied_facts if key.startswith("atlas.")
        )
        if reserved_facts:
            raise AtlasSynapseError(
                f"caller cannot override reserved Atlas fact: {reserved_facts[0]}"
            )
        supplied_evidence = deepcopy(dict(evidence or {}))
        if ATLAS_PROJECTION_EVIDENCE_ID in supplied_evidence:
            raise AtlasSynapseError("caller cannot override Atlas projection evidence")

        projection_digest = atlas_projection_evidence_digest(projection)
        supplied_facts.update(
            {
                "atlas.checkpoint_digest": projection["generated_from"][
                    "checkpoint_digest"
                ],
                "atlas.open_finding_count": projection_verification[
                    "open_finding_count"
                ],
                "atlas.projection_digest": projection_digest,
                "atlas.projection_id": projection_verification["projection_id"],
                "atlas.projection_verified": True,
                "atlas.tree_size": projection["generated_from"]["tree_size"],
            }
        )
        supplied_evidence[ATLAS_PROJECTION_EVIDENCE_ID] = SynapseEvidence(
            observed_at=projection_observed_at,
            digest=projection_digest,
        )
        context = SynapseContext(
            tenant_id=str(projection_verification["tenant_id"]),
            current_node_id=current_node_id,
            as_of=as_of,
            policy=self.policy.synapse_policy(),
            facts=supplied_facts,
            evidence=supplied_evidence,
        )
        try:
            self._kernel.where_am_i(context)
        except (SynapseGraphError, SynapsePolicyError) as exc:
            raise AtlasSynapseError("Atlas current Synapse node is invalid") from exc
        return context

    def _compose_plan(
        self,
        *,
        projection: Mapping[str, Any],
        current_node_id: str,
        target_node_id: str,
        as_of: str,
        projection_observed_at: str,
        facts: Mapping[str, str | int | bool | None] | None,
        evidence: Mapping[str, SynapseEvidence] | None,
    ) -> dict[str, Any]:
        candidate, projection_verification = self._verify_projection(projection)
        context = self._build_context_from_verified_projection(
            projection=candidate,
            projection_verification=projection_verification,
            current_node_id=current_node_id,
            as_of=as_of,
            projection_observed_at=projection_observed_at,
            facts=facts,
            evidence=evidence,
        )
        try:
            location = self._kernel.where_am_i(context)
            available = self._kernel.available_moves(context)
            capability_slice = self._kernel.compile_capability_slice(
                context,
                max_depth=self.policy.slice_max_depth,
                max_nodes=self.policy.slice_max_nodes,
                max_edges=self.policy.slice_max_edges,
            )
            route = self._kernel.plan_route(
                context,
                target_node_id,
                max_hops=self.policy.max_route_hops,
                max_expansions=self.policy.max_route_expansions,
            )
            simulation = self._kernel.simulate_route(context, route)
        except (SynapseGraphError, SynapsePolicyError, SynapseRouteError) as exc:
            raise AtlasSynapseError("Synapse rejected the Atlas plan") from exc

        for edge_id in route["edge_ids"]:
            edge = self._edge_by_id.get(edge_id)
            if edge is None:
                raise AtlasSynapseError("Synapse route contains an undeclared edge")
            if edge["capability_id"] not in self.policy.allowed_capability_ids:
                raise AtlasSynapseError("Synapse route escaped the Atlas capability policy")
        control_plane_outputs = (location, available, capability_slice, route, simulation)
        if any(
            item["control_plane_calls"] != _ZERO_CALLS
            for item in control_plane_outputs
        ):
            raise AtlasSynapseError("Atlas-Synapse plan added a control-plane call")
        if simulation["execution_performed"] or simulation["production_mutated"]:
            raise AtlasSynapseError("Atlas-Synapse simulation crossed the execution boundary")

        core: dict[str, Any] = {
            "protocol": "integrity-guardian/atlas-synapse-plan/v1",
            "tenant_id": projection_verification["tenant_id"],
            "projection_id": projection_verification["projection_id"],
            "projection_digest": atlas_projection_evidence_digest(candidate),
            "projection_observed_at": projection_observed_at,
            "as_of": as_of,
            "graph_id": self.graph_id,
            "policy_digest": self.policy.digest,
            "current_node_id": current_node_id,
            "target_node_id": target_node_id,
            "location": location,
            "available_moves": available,
            "capability_slice": capability_slice,
            "route": route,
            "simulation": simulation,
            "invariants": deepcopy(_INVARIANTS),
        }
        plan = {
            "plan_id": digest_object(core, domain="atlas-synapse-plan-v1"),
            **core,
        }
        validate("atlas-synapse-plan", plan)
        return plan

    def plan(
        self,
        *,
        projection: Mapping[str, Any],
        current_node_id: str,
        target_node_id: str,
        as_of: str,
        projection_observed_at: str,
        facts: Mapping[str, str | int | bool | None] | None = None,
        evidence: Mapping[str, SynapseEvidence] | None = None,
    ) -> dict[str, Any]:
        """Build one deterministic read-only Atlas-to-Synapse plan bundle."""

        return self._compose_plan(
            projection=projection,
            current_node_id=current_node_id,
            target_node_id=target_node_id,
            as_of=as_of,
            projection_observed_at=projection_observed_at,
            facts=facts,
            evidence=evidence,
        )

    def verify_plan(
        self,
        plan: Mapping[str, Any],
        *,
        projection: Mapping[str, Any],
        current_node_id: str,
        target_node_id: str,
        as_of: str,
        projection_observed_at: str,
        facts: Mapping[str, str | int | bool | None] | None = None,
        evidence: Mapping[str, SynapseEvidence] | None = None,
    ) -> dict[str, Any]:
        """Rebuild and byte-compare the complete plan against trusted inputs."""

        candidate = deepcopy(dict(plan))
        try:
            validate("atlas-synapse-plan", candidate)
        except (ValidationError, KeyError, TypeError, ValueError) as exc:
            raise AtlasSynapseError("Atlas-Synapse plan schema is invalid") from exc
        unsigned = deepcopy(candidate)
        actual_plan_id = unsigned.pop("plan_id")
        if actual_plan_id != digest_object(unsigned, domain="atlas-synapse-plan-v1"):
            raise AtlasSynapseError("Atlas-Synapse plan identity mismatch")
        expected = self._compose_plan(
            projection=projection,
            current_node_id=current_node_id,
            target_node_id=target_node_id,
            as_of=as_of,
            projection_observed_at=projection_observed_at,
            facts=facts,
            evidence=evidence,
        )
        if canonical_bytes(candidate) != canonical_bytes(expected):
            raise AtlasSynapseError("Atlas-Synapse plan semantic mismatch")
        return {
            "ok": True,
            "plan_id": actual_plan_id,
            "projection_id": candidate["projection_id"],
            "graph_id": candidate["graph_id"],
            "route_id": candidate["route"]["route_id"],
            "edge_count": len(candidate["route"]["edge_ids"]),
            "model_calls": 0,
            "tool_calls": 0,
            "execution_performed": False,
            "production_authority": False,
        }


def build_atlas_synapse_plan(
    graph: Mapping[str, Any],
    policy: AtlasSynapsePolicy,
    *,
    projection_trust: AtlasProjectionTrust,
    projection: Mapping[str, Any],
    current_node_id: str,
    target_node_id: str,
    as_of: str,
    projection_observed_at: str,
    facts: Mapping[str, str | int | bool | None] | None = None,
    evidence: Mapping[str, SynapseEvidence] | None = None,
) -> dict[str, Any]:
    return AtlasSynapsePlanner(
        graph=graph,
        policy=policy,
        projection_trust=projection_trust,
    ).plan(
        projection=projection,
        current_node_id=current_node_id,
        target_node_id=target_node_id,
        as_of=as_of,
        projection_observed_at=projection_observed_at,
        facts=facts,
        evidence=evidence,
    )


def verify_atlas_synapse_plan(
    graph: Mapping[str, Any],
    policy: AtlasSynapsePolicy,
    plan: Mapping[str, Any],
    *,
    projection_trust: AtlasProjectionTrust,
    projection: Mapping[str, Any],
    current_node_id: str,
    target_node_id: str,
    as_of: str,
    projection_observed_at: str,
    facts: Mapping[str, str | int | bool | None] | None = None,
    evidence: Mapping[str, SynapseEvidence] | None = None,
) -> dict[str, Any]:
    return AtlasSynapsePlanner(
        graph=graph,
        policy=policy,
        projection_trust=projection_trust,
    ).verify_plan(
        plan,
        projection=projection,
        current_node_id=current_node_id,
        target_node_id=target_node_id,
        as_of=as_of,
        projection_observed_at=projection_observed_at,
        facts=facts,
        evidence=evidence,
    )
