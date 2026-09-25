"""Deterministic tenant-bound Guardian Atlas projection.

Atlas projects already verified Guardian evidence into an explainable graph.
It performs no collection, networking, remediation or model invocation.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from .canonical import canonical_bytes
from .hashing import digest_object
from .ledger import LedgerStore, event_digest
from .schemas import validate
from .signing import TrustedKey

MAX_ATLAS_NODES = 10_000
MAX_ATLAS_EDGES = 25_000


class AtlasProjectionError(ValueError):
    """Raised when trusted evidence cannot form one unambiguous tenant graph."""


def _node_id(*, tenant_id: str, kind: str, ref: str) -> str:
    identity = digest_object(
        {"tenant_id": tenant_id, "kind": kind, "ref": ref},
        domain="atlas-node-identity-v1",
    ).split(":", 1)[1]
    return f"atlas-node:{identity}"


def _edge(
    *,
    from_node_id: str,
    to_node_id: str,
    relation: str,
    evidence_event_ids: list[str],
) -> dict[str, Any]:
    core: dict[str, Any] = {
        "from_node_id": from_node_id,
        "to_node_id": to_node_id,
        "relation": relation,
        "evidence_event_ids": sorted(set(evidence_event_ids)),
    }
    identity = digest_object(core, domain="atlas-edge-identity-v1").split(":", 1)[1]
    return {"edge_id": f"atlas-edge:{identity}", **core}


def _verify_decision_identity(decision: dict[str, Any]) -> None:
    tenant_id = decision.get("tenant_id")
    if not isinstance(tenant_id, str) or not tenant_id.startswith("tenant:"):
        raise AtlasProjectionError("reconciliation decision has no canonical tenant")
    decision_id = decision.get("decision_id")
    if not isinstance(decision_id, str) or not decision_id.startswith("decision:"):
        raise AtlasProjectionError("reconciliation decision identity is missing")
    if not isinstance(decision.get("classification"), str):
        raise AtlasProjectionError("reconciliation decision classification is missing")
    unsigned = deepcopy(decision)
    unsigned.pop("decision_id")
    expected = "decision:" + digest_object(
        unsigned, domain="reconciliation-decision-v1"
    ).split(":", 1)[1]
    if decision_id != expected:
        raise AtlasProjectionError("reconciliation decision identity mismatch")


def _verify_finding_identity(finding: dict[str, Any]) -> None:
    validate("finding", finding)
    unsigned = deepcopy(finding)
    finding_id = unsigned["finding_id"]
    unsigned["finding_id"] = "finding:pending"
    expected = "finding:" + digest_object(
        unsigned, domain="guardian-cyber-finding-v1"
    ).split(":", 1)[1]
    if finding_id != expected:
        raise AtlasProjectionError("Guardian finding identity mismatch")


def build_atlas_projection(
    *,
    ledger: LedgerStore,
    source_public_keys: dict[str, TrustedKey],
    checkpoint: dict[str, Any],
    checkpoint_key: TrustedKey,
    reconciliation_decisions: list[dict[str, Any]] | None = None,
    findings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build one deterministic graph from a verified checkpoint.

    Reconciliation decisions and findings are identity-checked derived objects.
    Atlas reflects their claims but only Ledger events and the checkpoint are
    labelled ``verified`` by this projection.
    """

    decisions = list(reconciliation_decisions or [])
    finding_objects = list(findings or [])
    verification = ledger.verify(
        source_public_keys=source_public_keys,
        checkpoint=checkpoint,
        checkpoint_key=checkpoint_key,
    )
    if not verification["ok"] or not verification["checkpoint_verified"]:
        raise AtlasProjectionError("Atlas requires a verified Ledger checkpoint")

    tenant_id = ledger.tenant_id
    events = ledger.events()
    event_by_id = {event["event_id"]: event for event in events}
    if len(event_by_id) != len(events):
        raise AtlasProjectionError("duplicate Ledger event identity")
    event_id_by_digest = {event_digest(event): event["event_id"] for event in events}

    decision_ids = [decision.get("decision_id") for decision in decisions]
    if len(set(decision_ids)) != len(decision_ids):
        raise AtlasProjectionError("duplicate reconciliation decision identity")
    finding_ids = [finding.get("finding_id") for finding in finding_objects]
    if len(set(finding_ids)) != len(finding_ids):
        raise AtlasProjectionError("duplicate Guardian finding identity")

    for decision in decisions:
        if decision.get("tenant_id") != tenant_id:
            raise AtlasProjectionError("cross-tenant reconciliation decision")
        _verify_decision_identity(decision)
    for finding in finding_objects:
        if finding.get("tenant_id") != tenant_id:
            raise AtlasProjectionError("cross-tenant Guardian finding")
        _verify_finding_identity(finding)

    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[str, dict[str, Any]] = {}

    def add_node(
        *,
        kind: str,
        ref: str,
        label: str,
        truth_status: str,
        evidence_event_ids: list[str] | None = None,
        attributes: dict[str, str | int | bool | None] | None = None,
    ) -> str:
        node_id = _node_id(tenant_id=tenant_id, kind=kind, ref=ref)
        node = {
            "node_id": node_id,
            "kind": kind,
            "ref": ref,
            "label": label,
            "truth_status": truth_status,
            "evidence_event_ids": sorted(set(evidence_event_ids or [])),
            "attributes": dict(sorted((attributes or {}).items())),
        }
        existing = nodes.get(node_id)
        if existing is not None and canonical_bytes(existing) != canonical_bytes(node):
            raise AtlasProjectionError(f"conflicting Atlas node identity: {ref}")
        if existing is None and len(nodes) >= MAX_ATLAS_NODES:
            raise AtlasProjectionError("Atlas node limit exceeded")
        nodes[node_id] = node
        return node_id

    def add_edge(
        *,
        from_node_id: str,
        to_node_id: str,
        relation: str,
        evidence_event_ids: list[str] | None = None,
    ) -> None:
        if from_node_id not in nodes or to_node_id not in nodes:
            raise AtlasProjectionError("Atlas edge endpoint does not exist")
        edge = _edge(
            from_node_id=from_node_id,
            to_node_id=to_node_id,
            relation=relation,
            evidence_event_ids=evidence_event_ids or [],
        )
        if edge["edge_id"] not in edges and len(edges) >= MAX_ATLAS_EDGES:
            raise AtlasProjectionError("Atlas edge limit exceeded")
        edges[edge["edge_id"]] = edge

    def require_events(evidence_event_ids: list[str]) -> None:
        missing = sorted(set(evidence_event_ids) - event_by_id.keys())
        if missing:
            raise AtlasProjectionError(
                f"dangling evidence event reference: {missing[0]}"
            )

    checkpoint_node = add_node(
        kind="checkpoint",
        ref=checkpoint["checkpoint_id"],
        label="Verified Ledger checkpoint",
        truth_status="verified",
        attributes={
            "checkpoint_digest": digest_object(
                checkpoint, domain="atlas-checkpoint-reference-v1"
            ),
            "root_digest": checkpoint["root_digest"],
            "tree_size": checkpoint["tree_size"],
        },
    )

    for event in events:
        source_node = add_node(
            kind="source",
            ref=event["source_id"],
            label=event["source_id"],
            truth_status="verified",
        )
        event_node = add_node(
            kind="event",
            ref=event["event_id"],
            label=event["event_type"],
            truth_status="verified",
            evidence_event_ids=[event["event_id"]],
            attributes={
                "event_digest": event_digest(event),
                "payload_digest": event["payload_digest"],
                "recorded_at": event["recorded_at"],
                "source_sequence": event["source_sequence"],
            },
        )
        add_edge(
            from_node_id=event_node,
            to_node_id=source_node,
            relation="reported_by",
            evidence_event_ids=[event["event_id"]],
        )
        previous_digest = event["previous_event_digest"]
        if previous_digest is not None:
            previous_event_id = event_id_by_digest.get(previous_digest)
            if previous_event_id is None:
                raise AtlasProjectionError("verified source chain has a missing predecessor")
            previous_node = _node_id(
                tenant_id=tenant_id,
                kind="event",
                ref=previous_event_id,
            )
            add_edge(
                from_node_id=event_node,
                to_node_id=previous_node,
                relation="follows",
                evidence_event_ids=[event["event_id"], previous_event_id],
            )

    tip_event_id = event_id_by_digest.get(checkpoint["last_event_digest"])
    if tip_event_id is None:
        raise AtlasProjectionError("checkpoint tip is absent from verified events")
    tip_node = _node_id(tenant_id=tenant_id, kind="event", ref=tip_event_id)
    add_edge(
        from_node_id=checkpoint_node,
        to_node_id=tip_node,
        relation="commits_tip",
        evidence_event_ids=[tip_event_id],
    )

    for decision in sorted(decisions, key=lambda item: item["decision_id"]):
        source_event_id = decision.get("source_event_id")
        evidence_ids = [source_event_id] if isinstance(source_event_id, str) else []
        require_events(evidence_ids)
        decision_node = add_node(
            kind="decision",
            ref=decision["decision_id"],
            label=decision["classification"],
            truth_status="reported",
            evidence_event_ids=evidence_ids,
            attributes={
                "classification": decision["classification"],
                "operation": decision.get("operation"),
                "reason": decision.get("reason"),
            },
        )
        if evidence_ids:
            event_node = _node_id(
                tenant_id=tenant_id,
                kind="event",
                ref=evidence_ids[0],
            )
            add_edge(
                from_node_id=decision_node,
                to_node_id=event_node,
                relation="derived_from",
                evidence_event_ids=evidence_ids,
            )
        selector = decision.get("selector")
        if isinstance(selector, str):
            asset_node = add_node(
                kind="asset",
                ref=selector,
                label=selector,
                truth_status="unknown",
            )
            add_edge(
                from_node_id=decision_node,
                to_node_id=asset_node,
                relation="classifies",
                evidence_event_ids=evidence_ids,
            )
        intent_id = decision.get("intent_id")
        if isinstance(intent_id, str):
            intent_node = add_node(
                kind="intent",
                ref=intent_id,
                label=intent_id,
                truth_status="reported",
            )
            add_edge(
                from_node_id=decision_node,
                to_node_id=intent_node,
                relation="evaluates_against",
                evidence_event_ids=evidence_ids,
            )

    for finding in sorted(finding_objects, key=lambda item: item["finding_id"]):
        evidence_ids = list(finding["evidence_event_ids"])
        require_events(evidence_ids)
        finding_node = add_node(
            kind="finding",
            ref=finding["finding_id"],
            label=finding["title"],
            truth_status="reported",
            evidence_event_ids=evidence_ids,
            attributes={
                "claimed_truth_status": finding["truth_status"],
                "object_digest": digest_object(
                    finding, domain="atlas-finding-reference-v1"
                ),
                "policy_id": finding["policy_id"],
                "severity": finding["severity"],
                "status": finding["status"],
            },
        )
        for evidence_id in evidence_ids:
            event_node = _node_id(
                tenant_id=tenant_id,
                kind="event",
                ref=evidence_id,
            )
            add_edge(
                from_node_id=finding_node,
                to_node_id=event_node,
                relation="supported_by",
                evidence_event_ids=[evidence_id],
            )
        for asset in finding["affected_assets"]:
            asset_node = add_node(
                kind="asset",
                ref=asset,
                label=asset,
                truth_status="unknown",
            )
            add_edge(
                from_node_id=finding_node,
                to_node_id=asset_node,
                relation="affects",
                evidence_event_ids=evidence_ids,
            )
        for intent_id in finding["related_intent_ids"]:
            intent_node = add_node(
                kind="intent",
                ref=intent_id,
                label=intent_id,
                truth_status="reported",
            )
            add_edge(
                from_node_id=finding_node,
                to_node_id=intent_node,
                relation="relates_to_intent",
                evidence_event_ids=evidence_ids,
            )

    if len(nodes) > MAX_ATLAS_NODES:
        raise AtlasProjectionError("Atlas node limit exceeded")
    if len(edges) > MAX_ATLAS_EDGES:
        raise AtlasProjectionError("Atlas edge limit exceeded")

    ordered_nodes = sorted(nodes.values(), key=lambda item: item["node_id"])
    ordered_edges = sorted(edges.values(), key=lambda item: item["edge_id"])
    projection: dict[str, Any] = {
        "protocol": "integrity-guardian/atlas-projection/v1",
        "projection_id": "atlas:pending",
        "tenant_id": tenant_id,
        "ledger_id": ledger.ledger_id,
        "generated_from": {
            "checkpoint_id": checkpoint["checkpoint_id"],
            "checkpoint_digest": digest_object(
                checkpoint, domain="atlas-checkpoint-reference-v1"
            ),
            "tree_size": checkpoint["tree_size"],
            "root_digest": checkpoint["root_digest"],
            "last_event_digest": checkpoint["last_event_digest"],
        },
        "nodes": ordered_nodes,
        "edges": ordered_edges,
        "summary": {
            "node_count": len(ordered_nodes),
            "edge_count": len(ordered_edges),
            "event_count": len(events),
            "decision_count": len(decisions),
            "finding_count": len(finding_objects),
            "open_finding_count": sum(
                finding["status"] == "open" for finding in finding_objects
            ),
        },
        "capabilities": {
            "network": False,
            "remediation": False,
            "production_authority": False,
        },
    }
    identity = digest_object(
        projection, domain="atlas-projection-identity-v1"
    ).split(":", 1)[1]
    projection["projection_id"] = f"atlas:{identity}"
    validate("atlas-projection", projection)
    return projection


def verify_atlas_projection(projection: dict[str, Any]) -> dict[str, Any]:
    """Independently verify one Atlas projection's deterministic structure."""

    validate("atlas-projection", projection)
    tenant_id = projection["tenant_id"]
    nodes = projection["nodes"]
    edges = projection["edges"]
    node_by_id = {node["node_id"]: node for node in nodes}
    if len(node_by_id) != len(nodes):
        raise AtlasProjectionError("duplicate Atlas node identity")
    edge_by_id = {edge["edge_id"]: edge for edge in edges}
    if len(edge_by_id) != len(edges):
        raise AtlasProjectionError("duplicate Atlas edge identity")

    for node in nodes:
        expected = _node_id(
            tenant_id=tenant_id,
            kind=node["kind"],
            ref=node["ref"],
        )
        if node["node_id"] != expected:
            raise AtlasProjectionError("Atlas node identity mismatch")

    verified_event_ids = {
        node["ref"] for node in nodes if node["kind"] == "event"
    }
    for node in nodes:
        missing = set(node["evidence_event_ids"]) - verified_event_ids
        if missing:
            raise AtlasProjectionError("Atlas node has dangling evidence")

    for edge in edges:
        if (
            edge["from_node_id"] not in node_by_id
            or edge["to_node_id"] not in node_by_id
        ):
            raise AtlasProjectionError("Atlas edge endpoint does not exist")
        expected = _edge(
            from_node_id=edge["from_node_id"],
            to_node_id=edge["to_node_id"],
            relation=edge["relation"],
            evidence_event_ids=edge["evidence_event_ids"],
        )
        if canonical_bytes(edge) != canonical_bytes(expected):
            raise AtlasProjectionError("Atlas edge identity mismatch")
        missing = set(edge["evidence_event_ids"]) - verified_event_ids
        if missing:
            raise AtlasProjectionError("Atlas edge has dangling evidence")

    summary = projection["summary"]
    expected_summary = {
        "node_count": len(nodes),
        "edge_count": len(edges),
        "event_count": sum(node["kind"] == "event" for node in nodes),
        "decision_count": sum(node["kind"] == "decision" for node in nodes),
        "finding_count": sum(node["kind"] == "finding" for node in nodes),
        "open_finding_count": sum(
            node["kind"] == "finding" and node["attributes"].get("status") == "open"
            for node in nodes
        ),
    }
    if summary != expected_summary:
        raise AtlasProjectionError("Atlas summary count mismatch")

    unsigned = deepcopy(projection)
    actual_projection_id = unsigned["projection_id"]
    unsigned["projection_id"] = "atlas:pending"
    expected_projection_id = "atlas:" + digest_object(
        unsigned, domain="atlas-projection-identity-v1"
    ).split(":", 1)[1]
    if actual_projection_id != expected_projection_id:
        raise AtlasProjectionError("Atlas projection identity mismatch")

    return {
        "ok": True,
        "projection_id": actual_projection_id,
        "tenant_id": tenant_id,
        "ledger_id": projection["ledger_id"],
        **expected_summary,
        "production_authority": False,
    }
