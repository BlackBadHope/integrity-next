"""Read-only Synapse projection. Never invokes an adapter or creates a permit."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol

from .core import Inquiry, checksum, digest


class SynapseReader(Protocol):
    def plan_route(self, context: Any, target_node_id: str) -> Mapping[str, Any]: ...
    def available_moves(self, context: Any) -> Mapping[str, Any]: ...
    def explain_edge(self, context: Any, edge_id: str) -> Mapping[str, Any]: ...


def capture_context(kernel: SynapseReader, context: Any) -> dict[str, Any]:
    """Reuse the native zero-hop route's context digest; do not reimplement it."""
    route = dict(kernel.plan_route(context, context.current_node_id))
    if (route.get("protocol") != "integrity-guardian/synapse-route/v1"
            or route.get("execution_authority") is not False
            or route.get("tenant_id") != context.tenant_id
            or route.get("start_node_id") != context.current_node_id
            or route.get("target_node_id") != context.current_node_id
            or route.get("edge_ids") != []):
        raise ValueError("unexpected native Synapse context projection")
    checksum(route["context_digest"])
    checksum(route["graph_id"])
    return route


def _selection(inquiry: Inquiry, kernel: SynapseReader, context: Any) -> tuple[dict[str, Any], dict]:
    """A proposal narrowed by native eligibility, NOT signed SDK acceptance.

    Adapter/operation digests remain references. Fresh source conformance, exact
    target operation and a13/a14 verification still belong to the SDK host.
    """
    captured = capture_context(kernel, context)
    if (captured["context_digest"] != inquiry.goal.context_digest
            or captured["tenant_id"] != inquiry.goal.tenant_id):
        raise ValueError("stale or cross-tenant inquiry context")
    moves = kernel.available_moves(context)
    if (moves.get("protocol") != "integrity-guardian/synapse-available-moves/v1"
            or moves.get("execution_authority") is not False
            or moves.get("graph_id") != captured["graph_id"]
            or moves.get("tenant_id") != context.tenant_id
            or moves.get("current_node_id") != context.current_node_id):
        raise ValueError("inconsistent Synapse projection")
    by_edge = {m["edge_id"]: m for m in moves["moves"]}
    if len(by_edge) != len(moves["moves"]):
        raise ValueError("duplicate native edge")
    gate = {}
    excluded = {}
    blast = {"none": 0, "process": 1, "host": 2, "tenant": 3, "network": 4}
    reversible = {"not_applicable": 0, "automatic": 0, "manual": 1, "irreversible": 2}
    for probe in inquiry.probes:
        move = by_edge.get(probe.edge_id)
        if move is None:
            excluded[probe.probe_id] = "not-in-native-available-moves"
            continue
        detail = kernel.explain_edge(context, probe.edge_id)
        edge = detail["edge"]
        if (detail.get("protocol") != "integrity-guardian/synapse-edge-explanation/v1"
                or detail.get("execution_authority") is not False or detail.get("available") is not True
                or detail.get("graph_id") != captured["graph_id"]
                or edge["edge_id"] != probe.edge_id
                or edge["capability_id"] != probe.capability_id
                or move["capability_id"] != probe.capability_id
                or edge.get("from_node_id") != context.current_node_id
                or any(move.get(key) != edge.get(key) for key in
                       ("to_node_id", "transition_kind", "blast_radius", "cost"))):
            raise ValueError("native edge/capability disagreement")
        if (edge["transition_kind"] not in {"observe", "analyze", "plan", "verify"}
                or edge["authority"]["production_authority"] is not False):
            excluded[probe.probe_id] = "outside-read-only-inquiry-scope"
            continue
        gate[probe.probe_id] = (0, blast[edge["blast_radius"]],
                               reversible[edge["reversibility"]["mode"]],
                               len(edge["authority"]["required_authority_ids"]))
    if capture_context(kernel, context) != captured:
        raise ValueError("Synapse context changed during selection")
    plan = inquiry.plan(gate)
    # Own view identity is separate from the underlying plan identity.
    result = {"protocol": "integrity-active-inquiry/synapse-view/v1", "plan": plan,
              "native_route_id": captured["route_id"], "graph_id": captured["graph_id"],
              "context_digest": captured["context_digest"], "bridge_excluded": excluded,
              "execution_authority": False, "sdk_acceptance": "not-performed"}
    result["view_digest"] = digest(result)
    return result, gate


def select_from_synapse(inquiry: Inquiry, kernel: SynapseReader, context: Any) -> dict[str, Any]:
    """Return only the current native-filtered proposal, with no execution rights."""
    return _selection(inquiry, kernel, context)[0]


def begin_from_synapse(
    inquiry: Inquiry, kernel: SynapseReader, context: Any, *, expected_view_digest: str,
) -> dict[str, Any]:
    """Refresh a selected view and start that exact SIMULATION, never an SDK call.

    No reservation occurs on stale view, denial, context drift or non-proposal.
    Unknown outcomes remain terminal. This is not durable execution recovery.
    """
    checksum(expected_view_digest)
    view, gate = _selection(inquiry, kernel, context)
    if view["view_digest"] != expected_view_digest:
        raise ValueError("stale native inquiry view; no reservation made")
    return inquiry.begin_simulation(gate=gate, expected_plan_digest=view["plan"]["plan_digest"])
