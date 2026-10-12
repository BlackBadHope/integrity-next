"""Deterministic, policy-filtered Integrity Synapse capability graph.

The kernel is deliberately offline and read-only.  It validates and compiles
declared transitions, explains availability, plans bounded routes and simulates
postconditions.  It has no adapter execution, network, model, credential or
production-authority capability.
"""

from __future__ import annotations

import heapq
from collections import deque
from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from types import MappingProxyType
from typing import Any

from jsonschema import ValidationError

from .canonical import canonical_bytes
from .hashing import digest_object
from .schemas import validate

MAX_GRAPH_NODES = 10_000
MAX_GRAPH_EDGES = 25_000
MAX_ROUTE_HOPS = 32
MAX_ROUTE_EXPANSIONS = 4_096
MAX_SLICE_NODES = 512
MAX_SLICE_EDGES = 2_048


class SynapseError(ValueError):
    """Base error for a fail-closed Synapse operation."""


class SynapseGraphError(SynapseError):
    """Raised when a graph violates its schema or semantic invariants."""


class SynapsePolicyError(SynapseError):
    """Raised when a runtime policy is invalid or attempts an authority upgrade."""


class SynapseRouteError(SynapseError):
    """Raised when no bounded policy-compliant route can be produced."""


class TransitionKind(str, Enum):
    OBSERVE = "observe"
    ANALYZE = "analyze"
    PLAN = "plan"
    DISPOSABLE_MUTATION = "disposable_mutation"
    PRODUCTION_MUTATION = "production_mutation"
    VERIFY = "verify"
    ROLLBACK = "rollback"


class BlastRadius(str, Enum):
    NONE = "none"
    PROCESS = "process"
    HOST = "host"
    TENANT = "tenant"
    NETWORK = "network"


class ProvenanceClass(str, Enum):
    DECLARED = "DECLARED"
    OBSERVED = "OBSERVED"
    DERIVED = "DERIVED"
    LEARNED = "LEARNED"
    PROPOSED = "PROPOSED"


_TRANSITION_RANK = {
    TransitionKind.OBSERVE.value: 0,
    TransitionKind.ANALYZE.value: 0,
    TransitionKind.PLAN.value: 0,
    TransitionKind.VERIFY.value: 0,
    TransitionKind.DISPOSABLE_MUTATION.value: 1,
    TransitionKind.ROLLBACK.value: 1,
    TransitionKind.PRODUCTION_MUTATION.value: 2,
}
_BLAST_RANK = {
    BlastRadius.NONE.value: 0,
    BlastRadius.PROCESS.value: 1,
    BlastRadius.HOST.value: 2,
    BlastRadius.TENANT.value: 3,
    BlastRadius.NETWORK.value: 4,
}
_REVERSIBILITY_RANK = {
    "not_applicable": 0,
    "automatic": 0,
    "manual": 1,
    "irreversible": 2,
}
_CONTROL_PLANE_CALLS = {"model_calls": 0, "tool_calls": 0}
_OFFLINE_CAPABILITIES = {
    "credentials": False,
    "execution": False,
    "model_sdk": False,
    "network": False,
    "production_authority": False,
}


def _parse_rfc3339(value: str, *, field_name: str) -> datetime:
    if not isinstance(value, str):
        raise SynapsePolicyError(f"{field_name} must be an RFC3339 string")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise SynapsePolicyError(f"{field_name} must be RFC3339") from exc
    if parsed.tzinfo is None:
        raise SynapsePolicyError(f"{field_name} must include a timezone")
    return parsed


def _ordered_unique(values: Sequence[str]) -> tuple[str, ...]:
    if any(not isinstance(value, str) or not value for value in values):
        raise SynapsePolicyError("policy identifiers must be non-empty strings")
    result = tuple(sorted(set(values)))
    if len(result) != len(values):
        raise SynapsePolicyError("policy identifiers must be unique")
    return result


@dataclass(frozen=True)
class SynapseEvidence:
    """One immutable evidence pointer used only for freshness decisions."""

    observed_at: str
    digest: str

    def __post_init__(self) -> None:
        _parse_rfc3339(self.observed_at, field_name="evidence.observed_at")
        algorithm, separator, value = self.digest.partition(":")
        if (
            algorithm != "sha256"
            or separator != ":"
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise SynapsePolicyError("evidence.digest must be an algorithm-qualified SHA-256")


@dataclass(frozen=True)
class SynapsePolicy:
    """Bounded authority and risk policy for one local planning context."""

    allowed_subsystems: tuple[str, ...] = ("*",)
    allowed_capability_ids: tuple[str, ...] = ("*",)
    granted_authority_ids: tuple[str, ...] = ()
    max_transition_kind: TransitionKind = TransitionKind.PLAN
    max_blast_radius: BlastRadius = BlastRadius.NONE
    production_authority: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "allowed_subsystems",
            _ordered_unique(self.allowed_subsystems),
        )
        object.__setattr__(
            self,
            "allowed_capability_ids",
            _ordered_unique(self.allowed_capability_ids),
        )
        object.__setattr__(
            self,
            "granted_authority_ids",
            _ordered_unique(self.granted_authority_ids),
        )
        if not isinstance(self.max_transition_kind, TransitionKind):
            raise SynapsePolicyError("max_transition_kind must be a TransitionKind")
        if not isinstance(self.max_blast_radius, BlastRadius):
            raise SynapsePolicyError("max_blast_radius must be a BlastRadius")
        if self.production_authority:
            raise SynapsePolicyError(
                "the offline Synapse kernel cannot grant production authority"
            )


@dataclass(frozen=True)
class SynapseContext:
    """Current node, facts, evidence and policy at an explicit deterministic time."""

    tenant_id: str
    current_node_id: str
    as_of: str
    policy: SynapsePolicy = field(default_factory=SynapsePolicy)
    facts: Mapping[str, str | int | bool | None] = field(default_factory=dict)
    evidence: Mapping[str, SynapseEvidence] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.tenant_id.startswith("tenant:"):
            raise SynapsePolicyError("tenant_id must be canonical")
        if not self.current_node_id.startswith("synapse-node:"):
            raise SynapsePolicyError("current_node_id must be canonical")
        _parse_rfc3339(self.as_of, field_name="as_of")
        if not isinstance(self.policy, SynapsePolicy):
            raise SynapsePolicyError("policy must be a SynapsePolicy")
        facts = deepcopy(dict(self.facts))
        evidence = deepcopy(dict(self.evidence))
        canonical_bytes(facts)
        for evidence_id, record in evidence.items():
            if not isinstance(evidence_id, str) or not evidence_id:
                raise SynapsePolicyError("evidence ids must be non-empty strings")
            if not isinstance(record, SynapseEvidence):
                raise SynapsePolicyError("evidence values must be SynapseEvidence")
        object.__setattr__(self, "facts", MappingProxyType(facts))
        object.__setattr__(self, "evidence", MappingProxyType(evidence))


def build_synapse_node(
    *,
    tenant_id: str,
    kind: str,
    ref: str,
    label: str,
    truth_status: str,
    attributes: Mapping[str, str | int | bool | None] | None = None,
) -> dict[str, Any]:
    """Build one content-addressed node definition."""

    identity = digest_object(
        {"tenant_id": tenant_id, "kind": kind, "ref": ref},
        domain="synapse-node-identity-v1",
    ).split(":", 1)[1]
    return {
        "node_id": f"synapse-node:{identity}",
        "kind": kind,
        "ref": ref,
        "label": label,
        "truth_status": truth_status,
        "attributes": dict(sorted((attributes or {}).items())),
    }


def _edge_identity_core(edge: Mapping[str, Any]) -> dict[str, Any]:
    core = deepcopy(dict(edge))
    core.pop("edge_id", None)
    reversibility = core.get("reversibility")
    if isinstance(reversibility, dict):
        # Rollback references are graph topology.  Excluding this one field
        # prevents recursive identities for mutually linked apply/rollback edges;
        # the enclosing graph digest still commits to the exact reference.
        reversibility["rollback_edge_id"] = None
    return core


def build_synapse_edge(
    *,
    from_node_id: str,
    to_node_id: str,
    capability_id: str,
    subsystem: str,
    transition_kind: TransitionKind,
    required_authority_ids: Sequence[str] = (),
    production_authority: bool = False,
    evidence_requirements: Sequence[Mapping[str, Any]] = (),
    preconditions: Sequence[Mapping[str, Any]] = (),
    postconditions: Sequence[Mapping[str, Any]] = (),
    verifier_id: str | None = None,
    verifier_required: bool = False,
    reversibility: str = "not_applicable",
    rollback_edge_id: str | None = None,
    blast_radius: BlastRadius = BlastRadius.NONE,
    latency_ms: int = 0,
    context_bytes: int = 0,
    model_calls: int = 0,
    tool_calls: int = 0,
    resource_units: int = 0,
    provenance: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Build one content-addressed transition definition."""

    edge: dict[str, Any] = {
        "from_node_id": from_node_id,
        "to_node_id": to_node_id,
        "capability_id": capability_id,
        "subsystem": subsystem,
        "transition_kind": transition_kind.value,
        "authority": {
            "required_authority_ids": sorted(set(required_authority_ids)),
            "production_authority": production_authority,
        },
        "evidence_requirements": sorted(
            (dict(item) for item in evidence_requirements),
            key=lambda item: (str(item.get("evidence_id")), int(item.get("max_age_seconds", 0))),
        ),
        "preconditions": sorted(
            (dict(item) for item in preconditions),
            key=lambda item: canonical_bytes(item),
        ),
        "postconditions": sorted(
            (dict(item) for item in postconditions),
            key=lambda item: canonical_bytes(item),
        ),
        "verifier": {"verifier_id": verifier_id, "required": verifier_required},
        "reversibility": {
            "mode": reversibility,
            "rollback_edge_id": rollback_edge_id,
        },
        "blast_radius": blast_radius.value,
        "cost": {
            "latency_ms": latency_ms,
            "context_bytes": context_bytes,
            "model_calls": model_calls,
            "tool_calls": tool_calls,
            "resource_units": resource_units,
        },
        "provenance": sorted(
            (dict(item) for item in provenance),
            key=lambda item: canonical_bytes(item),
        ),
    }
    identity = digest_object(
        _edge_identity_core(edge),
        domain="synapse-edge-identity-v1",
    ).split(":", 1)[1]
    return {"edge_id": f"synapse-edge:{identity}", **edge}


def synapse_graph_digest(graph: Mapping[str, Any]) -> str:
    """Return the deterministic graph identity for an unsigned or signed graph."""

    core = deepcopy(dict(graph))
    core.pop("graph_id", None)
    return digest_object(core, domain="synapse-graph-v1")


def build_synapse_graph(
    *,
    tenant_id: str,
    nodes: Sequence[Mapping[str, Any]],
    edges: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Assemble and verify a deterministic offline capability graph."""

    core: dict[str, Any] = {
        "protocol": "integrity-guardian/synapse-graph/v1",
        "tenant_id": tenant_id,
        "nodes": sorted((deepcopy(dict(node)) for node in nodes), key=lambda item: item["node_id"]),
        "edges": sorted((deepcopy(dict(edge)) for edge in edges), key=lambda item: item["edge_id"]),
        "capabilities": deepcopy(_OFFLINE_CAPABILITIES),
    }
    graph = {"graph_id": synapse_graph_digest(core), **core}
    verify_synapse_graph(graph)
    return graph


def verify_synapse_graph(graph: Mapping[str, Any]) -> dict[str, Any]:
    """Verify schema, identities, endpoints and safety relationships."""

    candidate = deepcopy(dict(graph))
    try:
        validate("synapse-graph", candidate)
    except (ValidationError, KeyError, TypeError, ValueError) as exc:
        raise SynapseGraphError(f"invalid Synapse graph schema: {exc}") from exc
    expected_graph_id = synapse_graph_digest(candidate)
    if candidate["graph_id"] != expected_graph_id:
        raise SynapseGraphError("Synapse graph identity mismatch")
    if candidate["capabilities"] != _OFFLINE_CAPABILITIES:
        raise SynapseGraphError("Synapse offline capability boundary mismatch")

    nodes = candidate["nodes"]
    edges = candidate["edges"]
    if nodes != sorted(nodes, key=lambda item: item["node_id"]):
        raise SynapseGraphError("Synapse nodes are not in canonical order")
    if edges != sorted(edges, key=lambda item: item["edge_id"]):
        raise SynapseGraphError("Synapse edges are not in canonical order")
    node_by_id = {node["node_id"]: node for node in nodes}
    edge_by_id = {edge["edge_id"]: edge for edge in edges}
    if len(node_by_id) != len(nodes):
        raise SynapseGraphError("duplicate Synapse node identity")
    if len(edge_by_id) != len(edges):
        raise SynapseGraphError("duplicate Synapse edge identity")
    if len(nodes) > MAX_GRAPH_NODES or len(edges) > MAX_GRAPH_EDGES:
        raise SynapseGraphError("Synapse graph limit exceeded")

    for node in nodes:
        expected_node_id = build_synapse_node(
            tenant_id=candidate["tenant_id"],
            kind=node["kind"],
            ref=node["ref"],
            label=node["label"],
            truth_status=node["truth_status"],
            attributes=node["attributes"],
        )["node_id"]
        if node["node_id"] != expected_node_id:
            raise SynapseGraphError("Synapse node identity mismatch")

    for edge in edges:
        if edge["from_node_id"] not in node_by_id or edge["to_node_id"] not in node_by_id:
            raise SynapseGraphError("Synapse edge endpoint does not exist")
        expected_edge_id = "synapse-edge:" + digest_object(
            _edge_identity_core(edge),
            domain="synapse-edge-identity-v1",
        ).split(":", 1)[1]
        if edge["edge_id"] != expected_edge_id:
            raise SynapseGraphError("Synapse edge identity mismatch")
        if edge["transition_kind"] == TransitionKind.PRODUCTION_MUTATION.value:
            if not edge["authority"]["production_authority"]:
                raise SynapseGraphError("production edge lacks production authority requirement")
        elif edge["authority"]["production_authority"]:
            raise SynapseGraphError("non-production edge requests production authority")
        if edge["transition_kind"] in {
            TransitionKind.DISPOSABLE_MUTATION.value,
            TransitionKind.PRODUCTION_MUTATION.value,
        } and (
            not edge["verifier"]["required"] or edge["verifier"]["verifier_id"] is None
        ):
            raise SynapseGraphError("mutation edge requires an explicit verifier")
        mode = edge["reversibility"]["mode"]
        rollback_edge_id = edge["reversibility"]["rollback_edge_id"]
        if mode in {"automatic", "manual"} and rollback_edge_id is None:
            raise SynapseGraphError("reversible edge lacks rollback edge")
        if mode in {"not_applicable", "irreversible"} and rollback_edge_id is not None:
            raise SynapseGraphError("non-reversible edge declares rollback edge")
        if rollback_edge_id is not None:
            rollback = edge_by_id.get(rollback_edge_id)
            if rollback is None:
                raise SynapseGraphError("rollback edge does not exist")
            if (
                rollback["from_node_id"] != edge["to_node_id"]
                or rollback["to_node_id"] != edge["from_node_id"]
                or rollback["transition_kind"] != TransitionKind.ROLLBACK.value
            ):
                raise SynapseGraphError("rollback edge does not reverse its transition")

    return {
        "ok": True,
        "graph_id": candidate["graph_id"],
        "tenant_id": candidate["tenant_id"],
        "node_count": len(nodes),
        "edge_count": len(edges),
        "production_authority": False,
    }


def _condition_holds(
    condition: Mapping[str, Any],
    facts: Mapping[str, str | int | bool | None],
) -> bool:
    fact = condition["fact"]
    operator = condition["operator"]
    value = condition["value"]
    if operator == "equals":
        return fact in facts and facts[fact] == value
    if operator == "not_equals":
        return fact not in facts or facts[fact] != value
    if operator == "exists":
        return fact in facts
    if operator == "absent":
        return fact not in facts
    raise SynapseGraphError(f"unsupported condition operator: {operator}")


def _apply_postconditions(
    facts: Mapping[str, str | int | bool | None],
    conditions: Sequence[Mapping[str, Any]],
) -> dict[str, str | int | bool | None] | None:
    result = deepcopy(dict(facts))
    for condition in conditions:
        fact = condition["fact"]
        operator = condition["operator"]
        value = condition["value"]
        if operator == "equals":
            result[fact] = value
        elif operator == "absent":
            result.pop(fact, None)
        elif operator == "exists":
            if fact not in result:
                return None
        elif operator == "not_equals":
            if result.get(fact) == value:
                return None
        else:
            raise SynapseGraphError(f"unsupported condition operator: {operator}")
    return result


def _edge_score(edge: Mapping[str, Any]) -> tuple[int, ...]:
    cost = edge["cost"]
    return (
        _TRANSITION_RANK[edge["transition_kind"]],
        _BLAST_RANK[edge["blast_radius"]],
        _REVERSIBILITY_RANK[edge["reversibility"]["mode"]],
        len(edge["authority"]["required_authority_ids"]),
        cost["model_calls"],
        cost["tool_calls"],
        cost["latency_ms"],
        cost["resource_units"],
        cost["context_bytes"],
        1,
    )


def _path_score(edges: Sequence[Mapping[str, Any]]) -> tuple[int, ...]:
    if not edges:
        return (0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    return (
        max(_TRANSITION_RANK[edge["transition_kind"]] for edge in edges),
        max(_BLAST_RANK[edge["blast_radius"]] for edge in edges),
        sum(_REVERSIBILITY_RANK[edge["reversibility"]["mode"]] for edge in edges),
        sum(len(edge["authority"]["required_authority_ids"]) for edge in edges),
        sum(edge["cost"]["model_calls"] for edge in edges),
        sum(edge["cost"]["tool_calls"] for edge in edges),
        sum(edge["cost"]["latency_ms"] for edge in edges),
        sum(edge["cost"]["resource_units"] for edge in edges),
        sum(edge["cost"]["context_bytes"] for edge in edges),
        len(edges),
    )


def _score_object(score: tuple[int, ...]) -> dict[str, int]:
    return {
        "transition_rank": score[0],
        "blast_radius_rank": score[1],
        "reversibility_penalty": score[2],
        "authority_count": score[3],
        "estimated_model_calls": score[4],
        "estimated_tool_calls": score[5],
        "estimated_latency_ms": score[6],
        "resource_units": score[7],
        "context_bytes": score[8],
        "hop_count": score[9],
    }


def _context_digest(context: SynapseContext) -> str:
    policy = context.policy
    evidence = {
        evidence_id: {
            "observed_at": record.observed_at,
            "digest": record.digest,
        }
        for evidence_id, record in sorted(context.evidence.items())
    }
    return digest_object(
        {
            "tenant_id": context.tenant_id,
            "current_node_id": context.current_node_id,
            "as_of": context.as_of,
            "policy": {
                "allowed_subsystems": list(policy.allowed_subsystems),
                "allowed_capability_ids": list(policy.allowed_capability_ids),
                "granted_authority_ids": list(policy.granted_authority_ids),
                "max_transition_kind": policy.max_transition_kind.value,
                "max_blast_radius": policy.max_blast_radius.value,
                "production_authority": False,
            },
            "facts": dict(context.facts),
            "evidence": evidence,
        },
        domain="synapse-context-v1",
    )


class SynapseKernel:
    """Prevalidated and indexed offline Synapse graph."""

    def __init__(self, graph: Mapping[str, Any]):
        verify_synapse_graph(graph)
        self._graph = deepcopy(dict(graph))
        self._nodes = {node["node_id"]: node for node in self._graph["nodes"]}
        self._edges = {edge["edge_id"]: edge for edge in self._graph["edges"]}
        outbound: dict[str, list[dict[str, Any]]] = {}
        direct: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for edge in self._graph["edges"]:
            outbound.setdefault(edge["from_node_id"], []).append(edge)
            direct.setdefault((edge["from_node_id"], edge["to_node_id"]), []).append(edge)
        self._outbound = {
            key: tuple(sorted(value, key=lambda item: (_edge_score(item), item["edge_id"])))
            for key, value in outbound.items()
        }
        self._direct = {
            key: tuple(sorted(value, key=lambda item: (_edge_score(item), item["edge_id"])))
            for key, value in direct.items()
        }

    @property
    def graph_id(self) -> str:
        return str(self._graph["graph_id"])

    def _validate_context(self, context: SynapseContext) -> None:
        if context.tenant_id != self._graph["tenant_id"]:
            raise SynapsePolicyError("cross-tenant Synapse context")
        if context.current_node_id not in self._nodes:
            raise SynapsePolicyError("current Synapse node does not exist")

    def _availability(
        self,
        edge: Mapping[str, Any],
        context: SynapseContext,
        facts: Mapping[str, str | int | bool | None],
    ) -> tuple[bool, list[str]]:
        reasons: list[str] = []
        policy = context.policy
        if (
            "*" not in policy.allowed_subsystems
            and edge["subsystem"] not in policy.allowed_subsystems
        ):
            reasons.append("policy:subsystem-denied")
        if (
            "*" not in policy.allowed_capability_ids
            and edge["capability_id"] not in policy.allowed_capability_ids
        ):
            reasons.append("policy:capability-denied")
        if (
            _TRANSITION_RANK[edge["transition_kind"]]
            > _TRANSITION_RANK[policy.max_transition_kind.value]
        ):
            reasons.append("policy:transition-kind-denied")
        if _BLAST_RANK[edge["blast_radius"]] > _BLAST_RANK[policy.max_blast_radius.value]:
            reasons.append("policy:blast-radius-denied")
        missing_authorities = sorted(
            set(edge["authority"]["required_authority_ids"])
            - set(policy.granted_authority_ids)
        )
        reasons.extend(f"authority:missing:{item}" for item in missing_authorities)
        if edge["authority"]["production_authority"]:
            reasons.append("authority:production-unavailable")
        provenance = {item["class"] for item in edge["provenance"]}
        if ProvenanceClass.DECLARED.value not in provenance:
            reasons.append("provenance:not-declared")

        as_of = _parse_rfc3339(context.as_of, field_name="as_of")
        for requirement in edge["evidence_requirements"]:
            evidence_id = requirement["evidence_id"]
            record = context.evidence.get(evidence_id)
            if record is None:
                reasons.append(f"evidence:missing:{evidence_id}")
                continue
            observed_at = _parse_rfc3339(
                record.observed_at,
                field_name=f"evidence[{evidence_id}].observed_at",
            )
            age = (as_of - observed_at).total_seconds()
            if age < 0:
                reasons.append(f"evidence:future:{evidence_id}")
            elif age > requirement["max_age_seconds"]:
                reasons.append(f"evidence:stale:{evidence_id}")
        for condition in edge["preconditions"]:
            if not _condition_holds(condition, facts):
                reasons.append(f"precondition:failed:{condition['fact']}")
        return not reasons, reasons

    def where_am_i(self, context: SynapseContext) -> dict[str, Any]:
        self._validate_context(context)
        node = deepcopy(self._nodes[context.current_node_id])
        return {
            "protocol": "integrity-guardian/synapse-location/v1",
            "graph_id": self.graph_id,
            "tenant_id": context.tenant_id,
            "as_of": context.as_of,
            "node": node,
            "facts_digest": digest_object(dict(context.facts), domain="synapse-facts-v1"),
            "control_plane_calls": deepcopy(_CONTROL_PLANE_CALLS),
            "execution_authority": False,
        }

    def explain_edge(
        self,
        context: SynapseContext,
        edge_id: str,
        *,
        facts: Mapping[str, str | int | bool | None] | None = None,
    ) -> dict[str, Any]:
        self._validate_context(context)
        edge = self._edges.get(edge_id)
        if edge is None:
            raise SynapseGraphError("invented or unknown Synapse edge")
        evaluated_facts = dict(context.facts if facts is None else facts)
        available, reasons = self._availability(edge, context, evaluated_facts)
        return {
            "protocol": "integrity-guardian/synapse-edge-explanation/v1",
            "graph_id": self.graph_id,
            "edge": deepcopy(edge),
            "available": available,
            "reason_codes": reasons or ["available"],
            "control_plane_calls": deepcopy(_CONTROL_PLANE_CALLS),
            "execution_authority": False,
        }

    def available_moves(self, context: SynapseContext) -> dict[str, Any]:
        self._validate_context(context)
        moves: list[dict[str, Any]] = []
        for edge in self._outbound.get(context.current_node_id, ()):
            available, _ = self._availability(edge, context, context.facts)
            if available:
                moves.append(
                    {
                        "edge_id": edge["edge_id"],
                        "capability_id": edge["capability_id"],
                        "to_node_id": edge["to_node_id"],
                        "transition_kind": edge["transition_kind"],
                        "blast_radius": edge["blast_radius"],
                        "cost": deepcopy(edge["cost"]),
                    }
                )
        return {
            "protocol": "integrity-guardian/synapse-available-moves/v1",
            "graph_id": self.graph_id,
            "tenant_id": context.tenant_id,
            "current_node_id": context.current_node_id,
            "moves": moves,
            "control_plane_calls": deepcopy(_CONTROL_PLANE_CALLS),
            "execution_authority": False,
        }

    def _route_receipt(
        self,
        context: SynapseContext,
        target_node_id: str,
        edge_ids: Sequence[str],
        node_ids: Sequence[str],
    ) -> dict[str, Any]:
        selected_edges = [self._edges[edge_id] for edge_id in edge_ids]
        score = _path_score(selected_edges)
        core: dict[str, Any] = {
            "protocol": "integrity-guardian/synapse-route/v1",
            "graph_id": self.graph_id,
            "tenant_id": context.tenant_id,
            "context_digest": _context_digest(context),
            "start_node_id": context.current_node_id,
            "target_node_id": target_node_id,
            "edge_ids": list(edge_ids),
            "node_ids": list(node_ids),
            "score": _score_object(score),
            "verifier_ids": [
                edge["verifier"]["verifier_id"]
                for edge in selected_edges
                if edge["verifier"]["required"]
            ],
            "rollback_edge_ids": [
                edge["reversibility"]["rollback_edge_id"]
                for edge in reversed(selected_edges)
                if edge["reversibility"]["rollback_edge_id"] is not None
            ],
            "control_plane_calls": deepcopy(_CONTROL_PLANE_CALLS),
            "execution_authority": False,
        }
        route = {"route_id": digest_object(core, domain="synapse-route-v1"), **core}
        validate("synapse-route", route)
        return route

    def plan_route(
        self,
        context: SynapseContext,
        target_node_id: str,
        *,
        max_hops: int = 8,
        max_expansions: int = 512,
    ) -> dict[str, Any]:
        self._validate_context(context)
        if target_node_id not in self._nodes:
            raise SynapseRouteError("target Synapse node does not exist")
        if not 0 <= max_hops <= MAX_ROUTE_HOPS:
            raise SynapseRouteError("max_hops is outside the bounded kernel limit")
        if not 1 <= max_expansions <= MAX_ROUTE_EXPANSIONS:
            raise SynapseRouteError("max_expansions is outside the bounded kernel limit")
        if target_node_id == context.current_node_id:
            return self._route_receipt(
                context,
                target_node_id,
                (),
                (context.current_node_id,),
            )

        # Known one-hop routes retain a direct indexed fast path.
        if max_hops > 0:
            direct_candidates: list[dict[str, Any]] = []
            for edge in self._direct.get((context.current_node_id, target_node_id), ()):
                available, _ = self._availability(edge, context, context.facts)
                if (
                    available
                    and _apply_postconditions(context.facts, edge["postconditions"])
                    is not None
                ):
                    direct_candidates.append(edge)
            if direct_candidates:
                selected = min(
                    direct_candidates,
                    key=lambda edge: (_edge_score(edge), edge["edge_id"]),
                )
                # Only the zero-risk, zero-authority direct route bypasses graph
                # search.  A risky shortcut must still compete with safer routes.
                if _edge_score(selected)[:4] == (0, 0, 0, 0):
                    return self._route_receipt(
                        context,
                        target_node_id,
                        (selected["edge_id"],),
                        (context.current_node_id, target_node_id),
                    )

        start_facts = deepcopy(dict(context.facts))
        start_score = _path_score(())
        queue: list[
            tuple[
                tuple[int, ...],
                tuple[str, ...],
                int,
                str,
                dict[str, str | int | bool | None],
                tuple[str, ...],
                tuple[str, ...],
            ]
        ] = [
            (
                start_score,
                (),
                0,
                context.current_node_id,
                start_facts,
                (),
                (context.current_node_id,),
            )
        ]
        best: dict[
            tuple[str, str, int],
            tuple[tuple[int, ...], tuple[str, ...]],
        ] = {}
        expansions = 0
        while queue:
            _score, _tie, depth, node_id, facts, edge_ids, node_ids = heapq.heappop(queue)
            if node_id == target_node_id:
                return self._route_receipt(
                    context,
                    target_node_id,
                    edge_ids,
                    node_ids,
                )
            if depth >= max_hops or expansions >= max_expansions:
                continue
            expansions += 1
            for edge in self._outbound.get(node_id, ()):
                available, _ = self._availability(edge, context, facts)
                if not available:
                    continue
                next_facts = _apply_postconditions(facts, edge["postconditions"])
                if next_facts is None:
                    continue
                next_edge_ids = (*edge_ids, edge["edge_id"])
                next_node_ids = (*node_ids, edge["to_node_id"])
                selected_edges = [self._edges[item] for item in next_edge_ids]
                next_score = _path_score(selected_edges)
                next_tie = tuple(next_edge_ids)
                state_key = (
                    edge["to_node_id"],
                    digest_object(next_facts, domain="synapse-facts-v1"),
                    depth + 1,
                )
                previous = best.get(state_key)
                decision_key = (next_score, next_tie)
                if previous is not None and previous <= decision_key:
                    continue
                best[state_key] = decision_key
                heapq.heappush(
                    queue,
                    (
                        next_score,
                        next_tie,
                        depth + 1,
                        edge["to_node_id"],
                        next_facts,
                        next_edge_ids,
                        next_node_ids,
                    ),
                )
        raise SynapseRouteError("no policy-compliant route within bounded search")

    def simulate_route(
        self,
        context: SynapseContext,
        route: Mapping[str, Any],
    ) -> dict[str, Any]:
        self._validate_context(context)
        candidate = deepcopy(dict(route))
        try:
            validate("synapse-route", candidate)
        except ValidationError as exc:
            raise SynapseRouteError(f"invalid route schema: {exc}") from exc
        unsigned = deepcopy(candidate)
        route_id = unsigned.pop("route_id")
        if route_id != digest_object(unsigned, domain="synapse-route-v1"):
            raise SynapseRouteError("route identity mismatch")
        if candidate["graph_id"] != self.graph_id:
            raise SynapseRouteError("route belongs to another graph")
        if candidate["tenant_id"] != context.tenant_id:
            raise SynapseRouteError("route belongs to another tenant")
        if candidate["context_digest"] != _context_digest(context):
            raise SynapseRouteError("route belongs to another policy or evidence context")
        if candidate["start_node_id"] != context.current_node_id:
            raise SynapseRouteError("route does not start at the current node")
        if len(candidate["node_ids"]) != len(candidate["edge_ids"]) + 1:
            raise SynapseRouteError("route node and edge counts are inconsistent")
        if candidate["node_ids"][0] != context.current_node_id:
            raise SynapseRouteError("route node sequence has the wrong start")
        try:
            expected_route = self._route_receipt(
                context,
                candidate["target_node_id"],
                candidate["edge_ids"],
                candidate["node_ids"],
            )
        except KeyError as exc:
            raise SynapseRouteError("route contains invented edge") from exc
        if canonical_bytes(candidate) != canonical_bytes(expected_route):
            raise SynapseRouteError("route semantic receipt mismatch")

        facts = deepcopy(dict(context.facts))
        start_facts_digest = digest_object(facts, domain="synapse-facts-v1")
        trace: list[dict[str, Any]] = []
        current_node_id = context.current_node_id
        for index, edge_id in enumerate(candidate["edge_ids"]):
            edge = self._edges.get(edge_id)
            if edge is None:
                raise SynapseRouteError("route contains invented edge")
            if edge["from_node_id"] != current_node_id:
                raise SynapseRouteError("route edges are not contiguous")
            if (
                candidate["node_ids"][index] != edge["from_node_id"]
                or candidate["node_ids"][index + 1] != edge["to_node_id"]
            ):
                raise SynapseRouteError("route node sequence does not match its edges")
            available, reasons = self._availability(edge, context, facts)
            if not available:
                raise SynapseRouteError(f"route edge is unavailable: {reasons[0]}")
            next_facts = _apply_postconditions(facts, edge["postconditions"])
            if next_facts is None:
                raise SynapseRouteError("route postcondition cannot be simulated")
            trace.append(
                {
                    "index": index,
                    "edge_id": edge_id,
                    "from_node_id": edge["from_node_id"],
                    "to_node_id": edge["to_node_id"],
                    "verifier_id": edge["verifier"]["verifier_id"],
                    "rollback_edge_id": edge["reversibility"]["rollback_edge_id"],
                    "facts_digest": digest_object(next_facts, domain="synapse-facts-v1"),
                }
            )
            facts = next_facts
            current_node_id = edge["to_node_id"]
        if current_node_id != candidate["target_node_id"]:
            raise SynapseRouteError("route target does not match its edge sequence")

        core: dict[str, Any] = {
            "protocol": "integrity-guardian/synapse-simulation/v1",
            "graph_id": self.graph_id,
            "route_id": candidate["route_id"],
            "tenant_id": context.tenant_id,
            "start_node_id": context.current_node_id,
            "target_node_id": current_node_id,
            "start_facts_digest": start_facts_digest,
            "final_facts_digest": digest_object(facts, domain="synapse-facts-v1"),
            "trace": trace,
            "rollback_edge_ids": candidate["rollback_edge_ids"],
            "status": "simulated",
            "execution_performed": False,
            "production_mutated": False,
            "control_plane_calls": deepcopy(_CONTROL_PLANE_CALLS),
        }
        simulation = {
            "simulation_id": digest_object(core, domain="synapse-simulation-v1"),
            **core,
        }
        validate("synapse-simulation", simulation)
        return simulation

    def compile_capability_slice(
        self,
        context: SynapseContext,
        *,
        max_depth: int = 3,
        max_nodes: int = 64,
        max_edges: int = 128,
    ) -> dict[str, Any]:
        self._validate_context(context)
        if not 0 <= max_depth <= MAX_ROUTE_HOPS:
            raise SynapsePolicyError("max_depth is outside the bounded kernel limit")
        if not 1 <= max_nodes <= MAX_SLICE_NODES:
            raise SynapsePolicyError("max_nodes is outside the bounded kernel limit")
        if not 0 <= max_edges <= MAX_SLICE_EDGES:
            raise SynapsePolicyError("max_edges is outside the bounded kernel limit")

        selected_nodes = {context.current_node_id}
        selected_edges: set[str] = set()
        queue = deque(
            [(context.current_node_id, deepcopy(dict(context.facts)), 0)]
        )
        visited: set[tuple[str, str, int]] = set()
        truncated = False
        while queue:
            node_id, facts, depth = queue.popleft()
            state_key = (
                node_id,
                digest_object(facts, domain="synapse-facts-v1"),
                depth,
            )
            if state_key in visited:
                continue
            visited.add(state_key)
            if depth >= max_depth:
                for edge in self._outbound.get(node_id, ()):
                    available, _ = self._availability(edge, context, facts)
                    if not available:
                        continue
                    if _apply_postconditions(facts, edge["postconditions"]) is None:
                        continue
                    if edge["edge_id"] not in selected_edges:
                        truncated = True
                        break
                continue
            for edge in self._outbound.get(node_id, ()):
                available, _ = self._availability(edge, context, facts)
                if not available:
                    continue
                next_facts = _apply_postconditions(facts, edge["postconditions"])
                if next_facts is None:
                    continue
                if edge["edge_id"] not in selected_edges and len(selected_edges) >= max_edges:
                    truncated = True
                    continue
                if edge["to_node_id"] not in selected_nodes and len(selected_nodes) >= max_nodes:
                    truncated = True
                    continue
                selected_edges.add(edge["edge_id"])
                selected_nodes.add(edge["to_node_id"])
                queue.append((edge["to_node_id"], next_facts, depth + 1))

        core: dict[str, Any] = {
            "protocol": "integrity-guardian/synapse-capability-slice/v1",
            "graph_id": self.graph_id,
            "tenant_id": context.tenant_id,
            "current_node_id": context.current_node_id,
            "as_of": context.as_of,
            "nodes": [
                deepcopy(self._nodes[node_id]) for node_id in sorted(selected_nodes)
            ],
            "edges": [
                deepcopy(self._edges[edge_id]) for edge_id in sorted(selected_edges)
            ],
            "bounds": {
                "max_depth": max_depth,
                "max_nodes": max_nodes,
                "max_edges": max_edges,
            },
            "truncated": truncated,
            "control_plane_calls": deepcopy(_CONTROL_PLANE_CALLS),
            "execution_authority": False,
        }
        capability_slice = {
            "slice_id": digest_object(core, domain="synapse-capability-slice-v1"),
            **core,
        }
        validate("synapse-capability-slice", capability_slice)
        return capability_slice


def where_am_i(
    graph: Mapping[str, Any],
    context: SynapseContext,
) -> dict[str, Any]:
    return SynapseKernel(graph).where_am_i(context)


def available_moves(
    graph: Mapping[str, Any],
    context: SynapseContext,
) -> dict[str, Any]:
    return SynapseKernel(graph).available_moves(context)


def explain_edge(
    graph: Mapping[str, Any],
    context: SynapseContext,
    edge_id: str,
) -> dict[str, Any]:
    return SynapseKernel(graph).explain_edge(context, edge_id)


def plan_route(
    graph: Mapping[str, Any],
    context: SynapseContext,
    target_node_id: str,
    *,
    max_hops: int = 8,
    max_expansions: int = 512,
) -> dict[str, Any]:
    return SynapseKernel(graph).plan_route(
        context,
        target_node_id,
        max_hops=max_hops,
        max_expansions=max_expansions,
    )


def simulate_route(
    graph: Mapping[str, Any],
    context: SynapseContext,
    route: Mapping[str, Any],
) -> dict[str, Any]:
    return SynapseKernel(graph).simulate_route(context, route)


def compile_capability_slice(
    graph: Mapping[str, Any],
    context: SynapseContext,
    *,
    max_depth: int = 3,
    max_nodes: int = 64,
    max_edges: int = 128,
) -> dict[str, Any]:
    return SynapseKernel(graph).compile_capability_slice(
        context,
        max_depth=max_depth,
        max_nodes=max_nodes,
        max_edges=max_edges,
    )
