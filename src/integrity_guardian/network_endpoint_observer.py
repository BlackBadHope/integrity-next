"""Independent read-only endpoint-state observer for NetworkHttpAdapter."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from .adapter_sdk import ADAPTER_SDK_VERSION
from .canonical import canonical_bytes, parse_json_strict
from .hashing import digest_object
from .network_adapter import (
    NetworkAdapterError,
    _bytes_digest,
    _exact_http_request,
    _peer_request_body_digest,
    _verify_network_peer_response_receipt_scope,
    network_action_manifest_digest,
    network_peer_response_receipt_digest,
    verify_network_action_manifest,
)
from .schemas import validate
from .signing import Ed25519Signer, TrustedKey, verify_signature


def _freeze(value: Mapping[str, Any]) -> dict[str, Any]:
    try:
        candidate = parse_json_strict(canonical_bytes(dict(value)))
    except Exception as exc:
        raise NetworkAdapterError("network endpoint witness rejected") from exc
    if not isinstance(candidate, dict):
        raise NetworkAdapterError("network endpoint witness rejected")
    return candidate


def _identity(document: Mapping[str, Any]) -> str:
    core = deepcopy(dict(document))
    core.pop("witness_id", None)
    core.pop("signature", None)
    suffix = digest_object(core, domain="network-endpoint-witness-identity-v2").split(
        ":", 1
    )[1]
    return f"network-endpoint-witness:{suffix}"


def network_endpoint_witness_digest(witness: Mapping[str, Any]) -> str:
    return digest_object(dict(witness), domain="network-endpoint-witness-v2")


def build_network_endpoint_witness(
    *,
    action_manifest: Mapping[str, Any],
    capability_manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    action_key: TrustedKey,
    endpoint_key: TrustedKey,
    executor_id: str,
    executor_artifact_digest: str,
    executor_key_id: str,
    observer_id: str,
    observer_artifact_digest: str,
    observed_at: str,
    signer: Ed25519Signer,
) -> dict[str, Any]:
    action = verify_network_action_manifest(
        action_manifest,
        capability_manifest=capability_manifest,
        adapter_key=adapter_key,
        action_key=action_key,
        endpoint_key=endpoint_key,
    )
    if (
        executor_id == observer_id
        or executor_artifact_digest == observer_artifact_digest
        or executor_key_id == signer.key_id
    ):
        raise NetworkAdapterError("network executor/witness separation rejected")
    witness = action["witness"]
    authenticated = _exact_http_request(
        manifest=action,
        endpoint_key=endpoint_key,
        method=witness["method"],
        path=witness["path"],
        content_type="text/plain",
        body=b"",
        maximum_body_bytes=witness["maximum_body_bytes"],
    )
    status = authenticated.status
    content_type = authenticated.content_type
    body = authenticated.body
    body_digest = _bytes_digest(body, domain="network-state-body-v1")
    core = {
        "protocol": "integrity-guardian/network-endpoint-witness/v2",
        "sdk_version": ADAPTER_SDK_VERSION,
        "action": {
            "action_id": action["action_id"],
            "action_manifest_digest": network_action_manifest_digest(action),
        },
        "target": {
            "node_id": action["target"]["node_id"],
            "zone_id": action["target"]["zone_id"],
            "environment_digest": action["target"]["environment_digest"],
            "endpoint_digest": digest_object(
                {
                    "host": action["destination"]["host"],
                    "port": action["destination"]["port"],
                    "peer": action["destination"]["peer"],
                },
                domain="network-witness-endpoint-v1",
            ),
        },
        "executor": {
            "actor_id": executor_id,
            "artifact_digest": executor_artifact_digest,
            "key_id": executor_key_id,
        },
        "observer": {
            "actor_id": observer_id,
            "artifact_digest": observer_artifact_digest,
            "key_id": signer.key_id,
        },
        "observed": {
            "method": witness["method"],
            "path_digest": digest_object(
                witness["path"],
                domain="network-witness-path-v1",
            ),
            "status": status,
            "content_type": content_type,
            "body_digest": body_digest,
            "body_byte_count": len(body),
            "peer_receipt_id": authenticated.peer_receipt["receipt_id"],
            "peer_receipt_digest": network_peer_response_receipt_digest(
                authenticated.peer_receipt
            ),
            "peer_receipt": authenticated.peer_receipt,
            "peer_key_id": endpoint_key.key_id,
            "peer_key_fingerprint": action["destination"]["peer"][
                "key_fingerprint"
            ],
            "raw_body_retained": False,
        },
        "result": {
            "expected_status_observed": status == witness["status"],
            "expected_content_type_observed": content_type == witness["content_type"],
            "expected_state_observed": body_digest == witness["expected_body_digest"],
            "executor_claim_trusted": False,
            "external_causality_proven": False,
            "peer_authenticated": True,
        },
        "controls": {
            "action_invocations": 0,
            "read_only": True,
            "connection_count": 1,
            "request_count": 1,
            "numeric_loopback_destination": True,
            "dns_resolution": False,
            "proxy": False,
            "redirects": False,
            "credentials": False,
            "peer_authentication": "ed25519-challenge-v1",
            "fresh_response_challenge_required": True,
            "home_input": False,
            "production_authority": False,
        },
        "observed_at": observed_at,
        "signer_id": signer.key_id,
    }
    signed = signer.sign({"witness_id": _identity(core), **core})
    validate("network-endpoint-witness", signed)
    return signed


def verify_network_endpoint_witness(
    witness: Mapping[str, Any],
    *,
    observer_key: TrustedKey,
    action_manifest: Mapping[str, Any],
    capability_manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    action_key: TrustedKey,
    endpoint_key: TrustedKey,
) -> dict[str, Any]:
    action = verify_network_action_manifest(
        action_manifest,
        capability_manifest=capability_manifest,
        adapter_key=adapter_key,
        action_key=action_key,
        endpoint_key=endpoint_key,
    )
    candidate = _freeze(witness)
    try:
        validate("network-endpoint-witness", candidate)
    except Exception as exc:
        raise NetworkAdapterError("network endpoint witness schema rejected") from exc
    if candidate["witness_id"] != _identity(candidate):
        raise NetworkAdapterError("network endpoint witness identity mismatch")
    if (
        candidate["signer_id"] != observer_key.key_id
        or candidate["signature"]["key_id"] != observer_key.key_id
        or not verify_signature(candidate, observer_key.public_key)
    ):
        raise NetworkAdapterError("network endpoint witness signature rejected")
    executor = candidate["executor"]
    observer = candidate["observer"]
    if (
        executor["actor_id"] == observer["actor_id"]
        or executor["artifact_digest"] == observer["artifact_digest"]
        or executor["key_id"] == observer["key_id"]
    ):
        raise NetworkAdapterError("network executor/witness separation rejected")
    observed = candidate["observed"]
    peer_receipt = _verify_network_peer_response_receipt_scope(
        observed["peer_receipt"],
        manifest=action,
        endpoint_key=endpoint_key,
    )
    expected_endpoint_digest = digest_object(
        {
            "host": action["destination"]["host"],
            "port": action["destination"]["port"],
            "peer": action["destination"]["peer"],
        },
        domain="network-witness-endpoint-v1",
    )
    if (
        candidate["action"]
        != {
            "action_id": action["action_id"],
            "action_manifest_digest": network_action_manifest_digest(action),
        }
        or candidate["target"]["endpoint_digest"] != expected_endpoint_digest
        or {
            "key_id": observed["peer_key_id"],
            "key_fingerprint": observed["peer_key_fingerprint"],
        }
        != action["destination"]["peer"]
        or observed["peer_receipt_id"] != peer_receipt["receipt_id"]
        or observed["peer_receipt_digest"]
        != network_peer_response_receipt_digest(peer_receipt)
        or peer_receipt["request"]
        != {
            "method": action["witness"]["method"],
            "path": action["witness"]["path"],
            "content_type": "text/plain",
            "body_digest": _peer_request_body_digest(
                action["witness"]["method"],
                action["witness"]["path"],
                b"",
            ),
            "body_byte_count": 0,
        }
        or peer_receipt["response"]
        != {
            "status": observed["status"],
            "content_type": observed["content_type"],
            "body_digest": observed["body_digest"],
            "body_byte_count": observed["body_byte_count"],
        }
        or candidate["result"]["peer_authenticated"] is not True
        or candidate["result"]["expected_status_observed"]
        is not (observed["status"] == action["witness"]["status"])
        or candidate["result"]["expected_content_type_observed"]
        is not (observed["content_type"] == action["witness"]["content_type"])
        or candidate["result"]["expected_state_observed"]
        is not (observed["body_digest"] == action["witness"]["expected_body_digest"])
    ):
        raise NetworkAdapterError("network endpoint witness peer evidence rejected")
    return candidate


__all__ = [
    "build_network_endpoint_witness",
    "network_endpoint_witness_digest",
    "verify_network_endpoint_witness",
]
