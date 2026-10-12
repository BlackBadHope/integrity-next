"""Canonical offline Connectome manifests and deterministic Synapse compilation.

Connectome is declarative topology, not authority.  This module validates one
tenant-bound capability manifest, derives all Synapse identities itself and
returns a content-addressed compilation receipt.  It performs no discovery,
adapter execution, network, model or production operation.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Mapping, Sequence
from copy import deepcopy
from threading import RLock
from typing import Any

from jsonschema import ValidationError

from .canonical import canonical_bytes
from .hashing import digest_object
from .schemas import validate
from .synapse import (
    BlastRadius,
    SynapseGraphError,
    TransitionKind,
    build_synapse_edge,
    build_synapse_graph,
    build_synapse_node,
)

MAX_CONNECTOME_NODES = 10_000
MAX_CONNECTOME_CAPABILITIES = 25_000
_RESERVED_PROVENANCE_PREFIX = "connectome-manifest:"
_OFFLINE_BOUNDARY = {
    "credentials": False,
    "execution": False,
    "model_sdk": False,
    "network": False,
    "production_authority": False,
}
_ZERO_CALLS = {"model_calls": 0, "tool_calls": 0}
_COMPILATION_INVARIANTS = {
    "all_capabilities_declared": True,
    "execution_performed": False,
    "identities_compiler_derived": True,
    "manifest_graph_bound": True,
    "model_calls": 0,
    "production_authority": False,
    "tenant_bound": True,
    "tool_calls": 0,
}
_COMPILATION_CACHE_LIMIT = 32
_COMPILATION_CACHE: OrderedDict[str, dict[str, Any]] = OrderedDict()
_MANIFEST_VERIFICATION_CACHE: OrderedDict[str, dict[str, Any]] = (
    OrderedDict()
)
_COMPILATION_CACHE_LOCK = RLock()


class ConnectomeError(ValueError):
    """Raised when a capability manifest cannot form one trusted graph."""


def _manifest_core(manifest: Mapping[str, Any]) -> dict[str, Any]:
    core = deepcopy(dict(manifest))
    core.pop("manifest_id", None)
    return core


def connectome_manifest_digest(manifest: Mapping[str, Any]) -> str:
    """Return the canonical identity of a manifest with or without its id."""

    return digest_object(_manifest_core(manifest), domain="connectome-manifest-v1")


def _sorted_records(
    records: Sequence[Mapping[str, Any]],
    *,
    field: str,
) -> list[dict[str, Any]]:
    return sorted(
        (deepcopy(dict(record)) for record in records),
        key=lambda record: str(record.get(field, "")),
    )


def _normalize_capability(capability: Mapping[str, Any]) -> dict[str, Any]:
    normalized = deepcopy(dict(capability))
    authority = normalized.get("authority")
    if isinstance(authority, dict):
        authority["required_authority_ids"] = sorted(
            authority.get("required_authority_ids", [])
        )
    evidence_requirements = normalized.get("evidence_requirements")
    if isinstance(evidence_requirements, list):
        evidence_requirements.sort(
            key=lambda requirement: (
                str(requirement.get("evidence_id", "")),
                int(requirement.get("max_age_seconds", 0)),
            )
        )
    for field in ("preconditions", "postconditions", "provenance"):
        records = normalized.get(field)
        if isinstance(records, list):
            records.sort(key=canonical_bytes)
    return normalized


def build_connectome_manifest(
    *,
    tenant_id: str,
    nodes: Sequence[Mapping[str, Any]],
    capabilities: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Build and verify one canonical tenant capability manifest."""

    core: dict[str, Any] = {
        "protocol": "integrity-guardian/connectome-manifest/v1",
        "tenant_id": tenant_id,
        "nodes": _sorted_records(nodes, field="node_key"),
        "capabilities": sorted(
            (_normalize_capability(capability) for capability in capabilities),
            key=lambda capability: str(capability.get("capability_id", "")),
        ),
        "compiler_boundary": deepcopy(_OFFLINE_BOUNDARY),
    }
    manifest = {
        "manifest_id": digest_object(core, domain="connectome-manifest-v1"),
        **core,
    }
    verify_connectome_manifest(manifest)
    return manifest


def _require_canonical_capability(capability: Mapping[str, Any]) -> None:
    authority_ids = capability["authority"]["required_authority_ids"]
    if authority_ids != sorted(authority_ids):
        raise ConnectomeError("Connectome authority ids are not in canonical order")
    evidence_requirements = capability["evidence_requirements"]
    if evidence_requirements != sorted(
        evidence_requirements,
        key=lambda requirement: (
            requirement["evidence_id"],
            requirement["max_age_seconds"],
        ),
    ):
        raise ConnectomeError(
            "Connectome evidence requirements are not in canonical order"
        )
    for field in ("preconditions", "postconditions", "provenance"):
        records = capability[field]
        if records != sorted(records, key=canonical_bytes):
            raise ConnectomeError(
                f"Connectome {field} are not in canonical order"
            )


def verify_connectome_manifest(manifest: Mapping[str, Any]) -> dict[str, Any]:
    """Verify schema, identity, ordering, topology and authority boundaries."""

    try:
        candidate = deepcopy(dict(manifest))
        supplied_manifest_id = candidate["manifest_id"]
        actual_manifest_id = connectome_manifest_digest(candidate)
    except (KeyError, TypeError, ValueError) as exc:
        raise ConnectomeError("Connectome manifest cannot be read") from exc
    if supplied_manifest_id != actual_manifest_id:
        raise ConnectomeError("Connectome manifest identity mismatch")
    with _COMPILATION_CACHE_LOCK:
        cached_verification = _MANIFEST_VERIFICATION_CACHE.get(
            actual_manifest_id
        )
        if cached_verification is not None:
            _MANIFEST_VERIFICATION_CACHE.move_to_end(actual_manifest_id)
            return deepcopy(cached_verification)
    try:
        validate("connectome-manifest", candidate)
    except (ValidationError, KeyError, TypeError, ValueError) as exc:
        raise ConnectomeError("Connectome manifest schema is invalid") from exc
    if candidate["compiler_boundary"] != _OFFLINE_BOUNDARY:
        raise ConnectomeError("Connectome offline compiler boundary mismatch")

    nodes = candidate["nodes"]
    capabilities = candidate["capabilities"]
    if nodes != sorted(nodes, key=lambda node: node["node_key"]):
        raise ConnectomeError("Connectome nodes are not in canonical order")
    if capabilities != sorted(
        capabilities,
        key=lambda capability: capability["capability_id"],
    ):
        raise ConnectomeError("Connectome capabilities are not in canonical order")
    node_by_key = {node["node_key"]: node for node in nodes}
    capability_by_id = {
        capability["capability_id"]: capability
        for capability in capabilities
    }
    if len(node_by_key) != len(nodes):
        raise ConnectomeError("duplicate Connectome node key")
    if len(capability_by_id) != len(capabilities):
        raise ConnectomeError("duplicate Connectome capability identity")
    if len(nodes) > MAX_CONNECTOME_NODES:
        raise ConnectomeError("Connectome node limit exceeded")
    if len(capabilities) > MAX_CONNECTOME_CAPABILITIES:
        raise ConnectomeError("Connectome capability limit exceeded")

    for capability in capabilities:
        _require_canonical_capability(capability)
        if (
            capability["from_node_key"] not in node_by_key
            or capability["to_node_key"] not in node_by_key
        ):
            raise ConnectomeError("Connectome capability endpoint does not exist")
        if capability["authority"]["production_authority"]:
            raise ConnectomeError(
                "Connectome compiler cannot accept production authority"
            )
        if capability["transition_kind"] == TransitionKind.PRODUCTION_MUTATION.value:
            raise ConnectomeError(
                "Connectome compiler cannot compile production mutation"
            )
        if capability[
            "transition_kind"
        ] == TransitionKind.DISPOSABLE_MUTATION.value and (
            not capability["verifier"]["required"]
            or capability["verifier"]["verifier_id"] is None
        ):
            raise ConnectomeError(
                "Connectome mutation requires an explicit verifier"
            )
        provenance_classes = {
            record["class"] for record in capability["provenance"]
        }
        if "DECLARED" not in provenance_classes:
            raise ConnectomeError("Connectome capability is not DECLARED")
        if any(
            record["source_id"].startswith(_RESERVED_PROVENANCE_PREFIX)
            for record in capability["provenance"]
        ):
            raise ConnectomeError(
                "Connectome capability uses reserved compiler provenance"
            )

        mode = capability["reversibility"]["mode"]
        rollback_capability_id = capability["reversibility"][
            "rollback_capability_id"
        ]
        if mode in {"automatic", "manual"} and rollback_capability_id is None:
            raise ConnectomeError(
                "reversible Connectome capability lacks rollback capability"
            )
        if mode in {"not_applicable", "irreversible"} and rollback_capability_id:
            raise ConnectomeError(
                "non-reversible Connectome capability names rollback capability"
            )
        if rollback_capability_id is not None:
            rollback = capability_by_id.get(rollback_capability_id)
            if rollback is None:
                raise ConnectomeError(
                    "Connectome rollback capability does not exist"
                )
            if (
                rollback["transition_kind"] != TransitionKind.ROLLBACK.value
                or rollback["from_node_key"] != capability["to_node_key"]
                or rollback["to_node_key"] != capability["from_node_key"]
            ):
                raise ConnectomeError(
                    "Connectome rollback does not reverse its capability"
                )

    verification = {
        "ok": True,
        "manifest_id": candidate["manifest_id"],
        "tenant_id": candidate["tenant_id"],
        "node_count": len(nodes),
        "capability_count": len(capabilities),
        "execution_performed": False,
        "model_calls": 0,
        "tool_calls": 0,
        "production_authority": False,
    }
    with _COMPILATION_CACHE_LOCK:
        _MANIFEST_VERIFICATION_CACHE[actual_manifest_id] = deepcopy(
            verification
        )
        _MANIFEST_VERIFICATION_CACHE.move_to_end(actual_manifest_id)
        while len(_MANIFEST_VERIFICATION_CACHE) > _COMPILATION_CACHE_LIMIT:
            _MANIFEST_VERIFICATION_CACHE.popitem(last=False)
    return verification


def _derived_provenance(manifest_id: str) -> dict[str, Any]:
    return {
        "class": "DERIVED",
        "source_id": _RESERVED_PROVENANCE_PREFIX + manifest_id.split(":", 1)[1],
        "source_digest": manifest_id,
        "explanation": "Compiled deterministically from the exact Connectome manifest.",
    }


def _cached_compilation(manifest_id: str) -> dict[str, Any] | None:
    with _COMPILATION_CACHE_LOCK:
        compilation = _COMPILATION_CACHE.get(manifest_id)
        if compilation is None:
            return None
        _COMPILATION_CACHE.move_to_end(manifest_id)
        return deepcopy(compilation)


def _cache_compilation(compilation: Mapping[str, Any]) -> None:
    manifest_id = str(compilation["manifest_id"])
    with _COMPILATION_CACHE_LOCK:
        _COMPILATION_CACHE[manifest_id] = deepcopy(dict(compilation))
        _COMPILATION_CACHE.move_to_end(manifest_id)
        while len(_COMPILATION_CACHE) > _COMPILATION_CACHE_LIMIT:
            _COMPILATION_CACHE.popitem(last=False)


def _build_edge(
    capability: Mapping[str, Any],
    *,
    node_id_by_key: Mapping[str, str],
    manifest_id: str,
    rollback_edge_id: str | None,
) -> dict[str, Any]:
    authority = capability["authority"]
    verifier = capability["verifier"]
    reversibility = capability["reversibility"]
    cost = capability["cost"]
    provenance = [
        *deepcopy(capability["provenance"]),
        _derived_provenance(manifest_id),
    ]
    return build_synapse_edge(
        from_node_id=node_id_by_key[capability["from_node_key"]],
        to_node_id=node_id_by_key[capability["to_node_key"]],
        capability_id=capability["capability_id"],
        subsystem=capability["subsystem"],
        transition_kind=TransitionKind(capability["transition_kind"]),
        required_authority_ids=authority["required_authority_ids"],
        production_authority=False,
        evidence_requirements=capability["evidence_requirements"],
        preconditions=capability["preconditions"],
        postconditions=capability["postconditions"],
        verifier_id=verifier["verifier_id"],
        verifier_required=verifier["required"],
        reversibility=reversibility["mode"],
        rollback_edge_id=rollback_edge_id,
        blast_radius=BlastRadius(capability["blast_radius"]),
        latency_ms=cost["latency_ms"],
        context_bytes=cost["context_bytes"],
        model_calls=cost["model_calls"],
        tool_calls=cost["tool_calls"],
        resource_units=cost["resource_units"],
        provenance=provenance,
    )


def compile_connectome_manifest(
    manifest: Mapping[str, Any],
) -> dict[str, Any]:
    """Compile one verified Connectome manifest into an exact Synapse graph."""

    try:
        candidate = deepcopy(dict(manifest))
        actual_manifest_id = connectome_manifest_digest(candidate)
        supplied_manifest_id = candidate["manifest_id"]
    except (KeyError, TypeError, ValueError) as exc:
        raise ConnectomeError("Connectome manifest cannot be read") from exc
    if supplied_manifest_id != actual_manifest_id:
        raise ConnectomeError("Connectome manifest identity mismatch")
    cached = _cached_compilation(actual_manifest_id)
    if cached is not None:
        return cached

    verification = verify_connectome_manifest(candidate)
    nodes = [
        build_synapse_node(
            tenant_id=candidate["tenant_id"],
            kind=node["kind"],
            ref=node["ref"],
            label=node["label"],
            truth_status=node["truth_status"],
            attributes=node["attributes"],
        )
        for node in candidate["nodes"]
    ]
    node_id_by_key = {
        node_spec["node_key"]: node["node_id"]
        for node_spec, node in zip(candidate["nodes"], nodes, strict=True)
    }

    first_pass_edges = {
        capability["capability_id"]: _build_edge(
            capability,
            node_id_by_key=node_id_by_key,
            manifest_id=candidate["manifest_id"],
            rollback_edge_id=None,
        )
        for capability in candidate["capabilities"]
    }
    edges = []
    for capability in candidate["capabilities"]:
        rollback_capability_id = capability["reversibility"][
            "rollback_capability_id"
        ]
        rollback_edge_id = (
            first_pass_edges[rollback_capability_id]["edge_id"]
            if rollback_capability_id is not None
            else None
        )
        edges.append(
            _build_edge(
                capability,
                node_id_by_key=node_id_by_key,
                manifest_id=candidate["manifest_id"],
                rollback_edge_id=rollback_edge_id,
            )
        )
    try:
        graph = build_synapse_graph(
            tenant_id=candidate["tenant_id"],
            nodes=nodes,
            edges=edges,
        )
    except (SynapseGraphError, KeyError, TypeError, ValueError) as exc:
        raise ConnectomeError(
            "Connectome manifest cannot form a valid Synapse graph"
        ) from exc

    edge_id_by_capability = {
        edge["capability_id"]: edge["edge_id"]
        for edge in graph["edges"]
    }
    core: dict[str, Any] = {
        "protocol": "integrity-guardian/connectome-compilation/v1",
        "tenant_id": verification["tenant_id"],
        "manifest_id": verification["manifest_id"],
        "graph_id": graph["graph_id"],
        "node_bindings": [
            {
                "node_key": node_key,
                "node_id": node_id,
            }
            for node_key, node_id in sorted(node_id_by_key.items())
        ],
        "capability_bindings": [
            {
                "capability_id": capability_id,
                "edge_id": edge_id,
            }
            for capability_id, edge_id in sorted(edge_id_by_capability.items())
        ],
        "graph": graph,
        "control_plane_calls": deepcopy(_ZERO_CALLS),
        "invariants": deepcopy(_COMPILATION_INVARIANTS),
    }
    compilation = {
        "compilation_id": digest_object(core, domain="connectome-compilation-v1"),
        **core,
    }
    validate("connectome-compilation", compilation)
    _cache_compilation(compilation)
    return compilation


def verify_connectome_compilation(
    manifest: Mapping[str, Any],
    compilation: Mapping[str, Any],
) -> dict[str, Any]:
    """Rebuild and byte-compare a complete Connectome compilation receipt."""

    try:
        candidate = deepcopy(dict(compilation))
        validate("connectome-compilation", candidate)
    except (ValidationError, KeyError, TypeError, ValueError) as exc:
        raise ConnectomeError("Connectome compilation schema is invalid") from exc
    unsigned = deepcopy(candidate)
    actual_compilation_id = unsigned.pop("compilation_id")
    expected_compilation_id = digest_object(
        unsigned,
        domain="connectome-compilation-v1",
    )
    if actual_compilation_id != expected_compilation_id:
        raise ConnectomeError("Connectome compilation identity mismatch")
    expected = compile_connectome_manifest(manifest)
    if canonical_bytes(candidate) != canonical_bytes(expected):
        raise ConnectomeError("Connectome compilation semantic mismatch")
    return {
        "ok": True,
        "compilation_id": actual_compilation_id,
        "manifest_id": candidate["manifest_id"],
        "graph_id": candidate["graph_id"],
        "tenant_id": candidate["tenant_id"],
        "node_count": len(candidate["node_bindings"]),
        "capability_count": len(candidate["capability_bindings"]),
        "execution_performed": False,
        "model_calls": 0,
        "tool_calls": 0,
        "production_authority": False,
    }
