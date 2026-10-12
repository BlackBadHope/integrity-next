"""Exact loopback HTTP transition over the shared Adapter SDK lifecycle."""

from __future__ import annotations

import base64
import hashlib
import http.client
import ipaddress
import re
import secrets
import stat
from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .adapter_conformance import (
    require_adapter_conformance_readiness,
    verify_adapter_conformance_receipt,
)
from .adapter_runtime import (
    AdapterDispatchPermit,
    AdapterRuntimeError,
    _verify_envelope_signature,
    build_adapter_execution_report,
)
from .adapter_sdk import (
    ADAPTER_SDK_VERSION,
    AdapterReportedOutcome,
    adapter_capability_manifest_digest,
    adapter_execution_envelope_digest,
    adapter_operation_binding_digest,
    adapter_target_operation_digest,
    verify_adapter_capability_manifest,
    verify_adapter_operation_binding,
    verify_adapter_target_operation,
)
from .canonical import canonical_bytes, parse_json_strict
from .hashing import digest_object
from .operation_audit import write_operation_document
from .schemas import load_schema, validate
from .signing import (
    Ed25519Signer,
    TrustedKey,
    public_key_fingerprint,
    verify_signature,
)

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_AUTHORITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}\.invalid$")
NETWORK_EXECUTION_RECEIPT_ARTIFACT = "network-execution-receipt.json"
NETWORK_ACTION_ID_HEADER = "X-Integrity-Action-Id"
NETWORK_ACTION_DIGEST_HEADER = "X-Integrity-Action-Digest"
NETWORK_CHALLENGE_HEADER = "X-Integrity-Challenge-Nonce"
NETWORK_PEER_RECEIPT_HEADER = "X-Integrity-Peer-Receipt"
NETWORK_PEER_IDENTITY_PATH = "/integrity/identity"
_MAX_REQUEST_BYTES = 4096
_MAX_RESPONSE_BYTES = 4096
_MAX_PEER_RECEIPT_HEADER_BYTES = 16384
_NONCE = re.compile(r"^nonce:[a-f0-9]{64}$")
_ENCODED_RECEIPT = re.compile(r"^[A-Za-z0-9_-]+$")


class NetworkAdapterError(AdapterRuntimeError):
    """Raised before an exact network target can be widened or overstated."""


@dataclass(frozen=True)
class AuthenticatedNetworkResponse:
    """Exact response plus fresh endpoint-authentication evidence."""

    status: int
    content_type: str
    body: bytes
    peer_receipt: dict[str, Any]
    preflight_peer_receipt: dict[str, Any] | None
    connection_count: int
    request_count: int
    action_request_sent: bool


class NetworkExchangeError(NetworkAdapterError):
    """Fail closed while preserving whether the action request crossed the socket."""

    def __init__(
        self,
        message: str,
        *,
        connection_count: int,
        request_count: int,
        action_request_sent: bool,
        preflight_peer_receipt: Mapping[str, Any] | None,
    ) -> None:
        super().__init__(message)
        self.connection_count = connection_count
        self.request_count = request_count
        self.action_request_sent = action_request_sent
        self.preflight_peer_receipt = (
            deepcopy(dict(preflight_peer_receipt))
            if preflight_peer_receipt is not None
            else None
        )


def _freeze(value: Mapping[str, Any], field: str) -> dict[str, Any]:
    try:
        candidate = parse_json_strict(canonical_bytes(dict(value)))
    except Exception as exc:
        raise NetworkAdapterError(f"network {field} rejected") from exc
    if not isinstance(candidate, dict):
        raise NetworkAdapterError(f"network {field} rejected")
    return candidate


def _identity(
    document: Mapping[str, Any],
    *,
    field: str,
    prefix: str,
    domain: str,
) -> str:
    core = deepcopy(dict(document))
    core.pop(field, None)
    core.pop("signature", None)
    return prefix + digest_object(core, domain=domain).split(":", 1)[1]


def _bytes_digest(value: bytes, *, domain: str) -> str:
    return "sha256:" + hashlib.sha256(domain.encode("ascii") + b"\0" + value).hexdigest()


def _peer_request_body_digest(method: str, path: str, body: bytes) -> str:
    domain = (
        "network-request-body-v1"
        if method == "POST" and path == "/apply"
        else "network-peer-request-body-v1"
    )
    return _bytes_digest(body, domain=domain)


def _peer_response_body_digest(method: str, path: str, body: bytes) -> str:
    if method == "POST" and path == "/apply":
        domain = "network-response-body-v1"
    elif method == "GET" and path == "/state":
        domain = "network-state-body-v1"
    else:
        domain = "network-peer-response-body-v1"
    return _bytes_digest(body, domain=domain)


def _peer_identity(key: TrustedKey) -> dict[str, str]:
    if not isinstance(key, TrustedKey):
        raise NetworkAdapterError("network endpoint key rejected")
    return {
        "key_id": key.key_id,
        "key_fingerprint": public_key_fingerprint(key.public_key),
    }


def _peer_receipt_identity(core: Mapping[str, Any]) -> str:
    return _identity(
        core,
        field="receipt_id",
        prefix="network-peer-response:",
        domain="network-peer-response-receipt-identity-v1",
    )


def network_peer_response_receipt_digest(receipt: Mapping[str, Any]) -> str:
    return digest_object(dict(receipt), domain="network-peer-response-receipt-v1")


def build_network_peer_response_receipt(
    *,
    action_id: str,
    action_manifest_digest: str,
    challenge_nonce: str,
    method: str,
    path: str,
    request_content_type: str,
    request_body: bytes,
    response_status: int,
    response_content_type: str,
    response_body: bytes,
    signer: Ed25519Signer,
) -> dict[str, Any]:
    """Sign one challenge and the exact HTTP exchange as endpoint identity proof."""

    if (
        not isinstance(action_id, str)
        or re.fullmatch(r"network-action:[a-f0-9]{64}", action_id) is None
        or not isinstance(action_manifest_digest, str)
        or _DIGEST.fullmatch(action_manifest_digest) is None
        or not isinstance(challenge_nonce, str)
        or _NONCE.fullmatch(challenge_nonce) is None
        or method not in {"HEAD", "POST", "GET"}
        or not isinstance(path, str)
        or not path.startswith("/")
        or len(path) > 256
        or not isinstance(request_content_type, str)
        or len(request_content_type) > 128
        or not isinstance(request_body, bytes)
        or len(request_body) > _MAX_REQUEST_BYTES
        or not isinstance(response_status, int)
        or isinstance(response_status, bool)
        or not 100 <= response_status <= 599
        or not isinstance(response_content_type, str)
        or len(response_content_type) > 128
        or not isinstance(response_body, bytes)
        or len(response_body) > _MAX_RESPONSE_BYTES
    ):
        raise NetworkAdapterError("network peer response input rejected")
    core = {
        "protocol": "integrity-guardian/network-peer-response-receipt/v1",
        "sdk_version": ADAPTER_SDK_VERSION,
        "action": {
            "action_id": action_id,
            "action_manifest_digest": action_manifest_digest,
        },
        "challenge_nonce": challenge_nonce,
        "request": {
            "method": method,
            "path": path,
            "content_type": request_content_type,
            "body_digest": _peer_request_body_digest(method, path, request_body),
            "body_byte_count": len(request_body),
        },
        "response": {
            "status": response_status,
            "content_type": response_content_type,
            "body_digest": _peer_response_body_digest(method, path, response_body),
            "body_byte_count": len(response_body),
        },
        "peer": {
            "key_id": signer.key_id,
            "key_fingerprint": public_key_fingerprint(signer.public_key),
        },
        "signer_id": signer.key_id,
    }
    signed = signer.sign({"receipt_id": _peer_receipt_identity(core), **core})
    validate("network-peer-response-receipt", signed)
    return signed


def _verify_network_peer_response_receipt_scope(
    receipt: Mapping[str, Any],
    *,
    manifest: Mapping[str, Any],
    endpoint_key: TrustedKey,
) -> dict[str, Any]:
    candidate = _freeze(receipt, "peer response receipt")
    try:
        validate("network-peer-response-receipt", candidate)
    except Exception as exc:
        raise NetworkAdapterError("network peer response schema rejected") from exc
    expected_peer = _peer_identity(endpoint_key)
    if (
        candidate["receipt_id"] != _peer_receipt_identity(candidate)
        or candidate["signer_id"] != endpoint_key.key_id
        or candidate["signature"]["key_id"] != endpoint_key.key_id
        or candidate["peer"] != expected_peer
        or not verify_signature(candidate, endpoint_key.public_key)
    ):
        raise NetworkAdapterError("network peer response signature rejected")
    if candidate["action"] != {
        "action_id": manifest["action_id"],
        "action_manifest_digest": network_action_manifest_digest(manifest),
    } or manifest["destination"]["peer"] != expected_peer:
        raise NetworkAdapterError("network peer response scope rejected")
    return candidate


def verify_network_peer_response_receipt(
    receipt: Mapping[str, Any],
    *,
    manifest: Mapping[str, Any],
    endpoint_key: TrustedKey,
    challenge_nonce: str,
    method: str,
    path: str,
    request_content_type: str,
    request_body: bytes,
    response_status: int,
    response_content_type: str,
    response_body: bytes,
) -> dict[str, Any]:
    candidate = _verify_network_peer_response_receipt_scope(
        receipt,
        manifest=manifest,
        endpoint_key=endpoint_key,
    )
    expected = {
        "challenge_nonce": challenge_nonce,
        "request": {
            "method": method,
            "path": path,
            "content_type": request_content_type,
            "body_digest": _peer_request_body_digest(method, path, request_body),
            "body_byte_count": len(request_body),
        },
        "response": {
            "status": response_status,
            "content_type": response_content_type,
            "body_digest": _peer_response_body_digest(method, path, response_body),
            "body_byte_count": len(response_body),
        },
    }
    if (
        candidate["challenge_nonce"] != expected["challenge_nonce"]
        or candidate["request"] != expected["request"]
        or candidate["response"] != expected["response"]
    ):
        raise NetworkAdapterError("network peer response binding rejected")
    return candidate


def encode_network_peer_response_receipt(receipt: Mapping[str, Any]) -> str:
    candidate = _freeze(receipt, "peer response receipt")
    validate("network-peer-response-receipt", candidate)
    return base64.urlsafe_b64encode(canonical_bytes(candidate)).decode("ascii").rstrip("=")


def _decode_network_peer_response_receipt(encoded: str | None) -> dict[str, Any]:
    if (
        not isinstance(encoded, str)
        or not 1 <= len(encoded) <= _MAX_PEER_RECEIPT_HEADER_BYTES
        or _ENCODED_RECEIPT.fullmatch(encoded) is None
    ):
        raise NetworkAdapterError("network peer response header rejected")
    padded = encoded + "=" * (-len(encoded) % 4)
    try:
        raw = base64.b64decode(padded, altchars=b"-_", validate=True)
        candidate = parse_json_strict(raw)
    except Exception as exc:
        raise NetworkAdapterError("network peer response header rejected") from exc
    if not isinstance(candidate, dict):
        raise NetworkAdapterError("network peer response header rejected")
    return candidate


def _strict_loopback_destination(host: str, port: int, authority: str) -> None:
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise NetworkAdapterError("network numeric destination rejected") from exc
    if address.version != 4 or str(address) != "127.0.0.1" or not address.is_loopback:
        raise NetworkAdapterError("network loopback destination rejected")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise NetworkAdapterError("network destination port rejected")
    if not isinstance(authority, str) or _AUTHORITY.fullmatch(authority) is None:
        raise NetworkAdapterError("network authority rejected")


def network_action_schema_digest() -> str:
    return digest_object(
        load_schema("network-http-action-manifest"),
        domain="network-http-action-manifest-schema-v2",
    )


def network_action_manifest_digest(manifest: Mapping[str, Any]) -> str:
    return digest_object(dict(manifest), domain="network-http-action-manifest-v2")


def network_resource_ids(manifest: Mapping[str, Any]) -> list[str]:
    destination = manifest["destination"]
    endpoint = {
        "host": destination["host"],
        "port": destination["port"],
        "peer": destination["peer"],
    }
    request = manifest["request"]
    return [
        "network-endpoint:"
        + digest_object(endpoint, domain="network-endpoint-resource-v1").split(":", 1)[1],
        "network-request:"
        + digest_object(
            {"method": request["method"], "path": request["path"]},
            domain="network-request-resource-v1",
        ).split(":", 1)[1],
    ]


def build_network_action_manifest(
    *,
    tenant_id: str,
    capability_manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    intent_operation_digest: str,
    target_node_id: str,
    target_zone_id: str,
    environment_digest: str,
    host: str,
    port: int,
    authority: str,
    endpoint_key: TrustedKey,
    request_body: bytes,
    expected_state_body: bytes,
    created_at: str,
    signer: Ed25519Signer,
    timeout_seconds: int = 10,
) -> dict[str, Any]:
    capability = verify_adapter_capability_manifest(
        capability_manifest,
        adapter_key=adapter_key,
    )
    _strict_loopback_destination(host, port, authority)
    endpoint_identity = _peer_identity(endpoint_key)
    if (
        _ID.fullmatch(tenant_id) is None
        or _ID.fullmatch(target_node_id) is None
        or _ID.fullmatch(target_zone_id) is None
        or _DIGEST.fullmatch(intent_operation_digest) is None
        or _DIGEST.fullmatch(environment_digest) is None
        or not isinstance(request_body, bytes)
        or not 1 <= len(request_body) <= _MAX_REQUEST_BYTES
        or not isinstance(expected_state_body, bytes)
        or not 1 <= len(expected_state_body) <= _MAX_RESPONSE_BYTES
        or not 1 <= timeout_seconds <= 30
    ):
        raise NetworkAdapterError("network action input rejected")
    channels = {
        "api": True,
        "browser_control": False,
        "computer_use": False,
        "credentials": False,
        "network": True,
        "service_control": False,
        "shell": False,
    }
    if capability["declared_channels"] != channels:
        raise NetworkAdapterError("network channel declaration rejected")
    core = {
        "protocol": "integrity-guardian/network-http-action-manifest/v2",
        "sdk_version": ADAPTER_SDK_VERSION,
        "tenant_id": tenant_id,
        "manifest": {
            "manifest_id": capability["manifest_id"],
            "manifest_digest": adapter_capability_manifest_digest(capability),
            "adapter_id": capability["adapter_id"],
            "adapter_artifact_digest": capability["adapter_artifact_digest"],
        },
        "intent_operation_digest": intent_operation_digest,
        "target": {
            "node_id": target_node_id,
            "zone_id": target_zone_id,
            "environment_digest": environment_digest,
        },
        "destination": {
            "scheme": "http",
            "transport": "tcp",
            "address_family": "ipv4",
            "host": host,
            "port": port,
            "authority": authority,
            "peer": endpoint_identity,
        },
        "request": {
            "method": "POST",
            "path": "/apply",
            "content_type": "application/json",
            "body_digest": _bytes_digest(request_body, domain="network-request-body-v1"),
            "body_byte_count": len(request_body),
        },
        "expected_response": {
            "status": 204,
            "content_type": "application/json",
            "body_digest": _bytes_digest(b"", domain="network-response-body-v1"),
            "maximum_body_bytes": _MAX_RESPONSE_BYTES,
        },
        "witness": {
            "method": "GET",
            "path": "/state",
            "status": 200,
            "content_type": "text/plain; charset=utf-8",
            "expected_body_digest": _bytes_digest(
                expected_state_body,
                domain="network-state-body-v1",
            ),
            "maximum_body_bytes": _MAX_RESPONSE_BYTES,
        },
        "limits": {
            "timeout_seconds": timeout_seconds,
            "maximum_connection_count": 1,
            "maximum_request_count": 2,
        },
        "controls": {
            "numeric_destination_only": True,
            "dns_resolution": False,
            "proxy": False,
            "redirects": False,
            "tls": False,
            "credential_reference": None,
            "peer_authentication": "ed25519-challenge-v1",
            "action_preflight_required": True,
            "fresh_response_challenge_required": True,
            "home_input": False,
            "raw_body_retained": False,
            "production_authority": False,
            "max_invocations": 1,
            "automatic_retry_after_unknown": False,
        },
        "created_at": created_at,
        "signer_id": signer.key_id,
    }
    signed = signer.sign(
        {
            "action_id": _identity(
                core,
                field="action_id",
                prefix="network-action:",
                domain="network-http-action-manifest-identity-v2",
            ),
            **core,
        }
    )
    validate("network-http-action-manifest", signed)
    return signed


def verify_network_action_manifest(
    manifest: Mapping[str, Any],
    *,
    capability_manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    action_key: TrustedKey,
    endpoint_key: TrustedKey,
) -> dict[str, Any]:
    candidate = _freeze(manifest, "action manifest")
    try:
        validate("network-http-action-manifest", candidate)
    except Exception as exc:
        raise NetworkAdapterError("network action manifest schema rejected") from exc
    if candidate["action_id"] != _identity(
        candidate,
        field="action_id",
        prefix="network-action:",
        domain="network-http-action-manifest-identity-v2",
    ):
        raise NetworkAdapterError("network action identity mismatch")
    if (
        candidate["signer_id"] != action_key.key_id
        or candidate["signature"]["key_id"] != action_key.key_id
        or not verify_signature(candidate, action_key.public_key)
    ):
        raise NetworkAdapterError("network action signature rejected")
    capability = verify_adapter_capability_manifest(
        capability_manifest,
        adapter_key=adapter_key,
    )
    if candidate["manifest"] != {
        "manifest_id": capability["manifest_id"],
        "manifest_digest": adapter_capability_manifest_digest(capability),
        "adapter_id": capability["adapter_id"],
        "adapter_artifact_digest": capability["adapter_artifact_digest"],
    }:
        raise NetworkAdapterError("network adapter manifest mismatch")
    destination = candidate["destination"]
    _strict_loopback_destination(
        destination["host"],
        destination["port"],
        destination["authority"],
    )
    if destination["peer"] != _peer_identity(endpoint_key):
        raise NetworkAdapterError("network endpoint identity mismatch")
    return candidate


def _exact_http_request(
    *,
    manifest: Mapping[str, Any],
    endpoint_key: TrustedKey,
    method: str,
    path: str,
    content_type: str,
    body: bytes,
    maximum_body_bytes: int,
) -> AuthenticatedNetworkResponse:
    destination = manifest["destination"]
    _strict_loopback_destination(
        destination["host"],
        destination["port"],
        destination["authority"],
    )
    if destination["peer"] != _peer_identity(endpoint_key):
        raise NetworkAdapterError("network endpoint identity mismatch")
    connection = http.client.HTTPConnection(
        destination["host"],
        destination["port"],
        timeout=manifest["limits"]["timeout_seconds"],
    )
    connection_count = 0
    request_count = 0
    action_request_sent = False
    preflight: dict[str, Any] | None = None

    def exchange(
        *,
        request_method: str,
        request_path: str,
        request_content_type: str,
        request_body: bytes,
        response_limit: int,
        close: bool,
        action_request: bool,
        required_socket: object | None = None,
    ) -> tuple[int, str, bytes, dict[str, Any]]:
        nonlocal connection_count, request_count, action_request_sent
        nonce = "nonce:" + secrets.token_hex(32)
        connection_count = 1
        request_count += 1
        if action_request:
            action_request_sent = True
        if required_socket is not None and connection.sock is not required_socket:
            raise NetworkAdapterError("network peer connection continuity rejected")
        connection.putrequest(
            request_method,
            request_path,
            skip_host=True,
            skip_accept_encoding=True,
        )
        connection.putheader("Host", destination["authority"])
        connection.putheader("Content-Type", request_content_type)
        connection.putheader("Content-Length", str(len(request_body)))
        connection.putheader(NETWORK_ACTION_ID_HEADER, manifest["action_id"])
        connection.putheader(
            NETWORK_ACTION_DIGEST_HEADER,
            network_action_manifest_digest(manifest),
        )
        connection.putheader(NETWORK_CHALLENGE_HEADER, nonce)
        connection.putheader("Connection", "close" if close else "keep-alive")
        connection.endheaders(request_body)
        if required_socket is not None and connection.sock is not required_socket:
            raise NetworkAdapterError("network peer connection continuity rejected")
        response = connection.getresponse()
        response_body = response.read(response_limit + 1)
        if len(response_body) > response_limit:
            raise NetworkAdapterError("network response exceeded bound")
        response_content_type = response.getheader("Content-Type", "")
        receipt = _decode_network_peer_response_receipt(
            response.getheader(NETWORK_PEER_RECEIPT_HEADER)
        )
        verified = verify_network_peer_response_receipt(
            receipt,
            manifest=manifest,
            endpoint_key=endpoint_key,
            challenge_nonce=nonce,
            method=request_method,
            path=request_path,
            request_content_type=request_content_type,
            request_body=request_body,
            response_status=response.status,
            response_content_type=response_content_type,
            response_body=response_body,
        )
        if not close and (response.will_close or connection.sock is None):
            raise NetworkAdapterError("network peer keep-alive rejected")
        return response.status, response_content_type, response_body, verified

    try:
        authenticated_action = method == "POST"
        if method not in {"POST", "GET"}:
            raise NetworkAdapterError("network request method rejected")
        preflight_socket: object | None = None
        if authenticated_action:
            (
                preflight_status,
                preflight_content_type,
                preflight_body,
                preflight,
            ) = exchange(
                request_method="HEAD",
                request_path=NETWORK_PEER_IDENTITY_PATH,
                request_content_type="text/plain",
                request_body=b"",
                response_limit=0,
                close=False,
                action_request=False,
            )
            if (
                preflight_status != 204
                or preflight_content_type != "application/json"
                or preflight_body != b""
            ):
                raise NetworkAdapterError("network peer preflight response rejected")
            preflight_socket = connection.sock
            if preflight_socket is None:
                raise NetworkAdapterError("network peer connection continuity rejected")
        status, response_content_type, response_body, peer_receipt = exchange(
            request_method=method,
            request_path=path,
            request_content_type=content_type,
            request_body=body,
            response_limit=maximum_body_bytes,
            close=True,
            action_request=authenticated_action,
            required_socket=preflight_socket,
        )
        return AuthenticatedNetworkResponse(
            status=status,
            content_type=response_content_type,
            body=response_body,
            peer_receipt=peer_receipt,
            preflight_peer_receipt=preflight,
            connection_count=connection_count,
            request_count=request_count,
            action_request_sent=action_request_sent,
        )
    except (NetworkAdapterError, OSError, http.client.HTTPException) as exc:
        raise NetworkExchangeError(
            "network authenticated request failed",
            connection_count=connection_count,
            request_count=request_count,
            action_request_sent=action_request_sent,
            preflight_peer_receipt=preflight,
        ) from exc
    finally:
        connection.close()


def _receipt_identity(core: Mapping[str, Any]) -> str:
    return _identity(
        core,
        field="receipt_id",
        prefix="network-execution:",
        domain="network-http-execution-receipt-identity-v2",
    )


def network_execution_receipt_digest(receipt: Mapping[str, Any]) -> str:
    return digest_object(dict(receipt), domain="network-http-execution-receipt-v2")


def verify_network_execution_receipt(
    receipt: Mapping[str, Any],
    *,
    executor_key: TrustedKey,
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
    candidate = _freeze(receipt, "execution receipt")
    try:
        validate("network-http-execution-receipt", candidate)
    except Exception as exc:
        raise NetworkAdapterError("network execution receipt schema rejected") from exc
    if candidate["receipt_id"] != _receipt_identity(candidate):
        raise NetworkAdapterError("network execution receipt identity mismatch")
    if (
        candidate["signer_id"] != executor_key.key_id
        or candidate["signature"]["key_id"] != executor_key.key_id
        or not verify_signature(candidate, executor_key.public_key)
    ):
        raise NetworkAdapterError("network execution receipt signature rejected")
    observed = candidate["observed"]
    result = candidate["result"]
    if candidate["operation"]["action_id"] != action["action_id"] or candidate[
        "operation"
    ]["action_manifest_digest"] != network_action_manifest_digest(action):
        raise NetworkAdapterError("network execution receipt action rejected")
    if {
        "key_id": observed["peer_key_id"],
        "key_fingerprint": observed["peer_key_fingerprint"],
    } != action["destination"]["peer"]:
        raise NetworkAdapterError("network execution receipt peer rejected")

    preflight = observed["preflight_peer_receipt"]
    response = observed["response_peer_receipt"]
    preflight_fields = (
        observed["preflight_peer_receipt_id"],
        observed["preflight_peer_receipt_digest"],
        preflight,
    )
    response_fields = (
        observed["response_peer_receipt_id"],
        observed["response_peer_receipt_digest"],
        response,
    )
    if any(value is None for value in preflight_fields) != all(
        value is None for value in preflight_fields
    ) or any(value is None for value in response_fields) != all(
        value is None for value in response_fields
    ):
        raise NetworkAdapterError("network execution peer evidence partial")
    if preflight is not None:
        verified_preflight = _verify_network_peer_response_receipt_scope(
            preflight,
            manifest=action,
            endpoint_key=endpoint_key,
        )
        if (
            observed["preflight_peer_receipt_id"]
            != verified_preflight["receipt_id"]
            or observed["preflight_peer_receipt_digest"]
            != network_peer_response_receipt_digest(verified_preflight)
            or verified_preflight["request"]
            != {
                "method": "HEAD",
                "path": NETWORK_PEER_IDENTITY_PATH,
                "content_type": "text/plain",
                "body_digest": _peer_request_body_digest(
                    "HEAD",
                    NETWORK_PEER_IDENTITY_PATH,
                    b"",
                ),
                "body_byte_count": 0,
            }
            or verified_preflight["response"]
            != {
                "status": 204,
                "content_type": "application/json",
                "body_digest": _peer_response_body_digest(
                    "HEAD",
                    NETWORK_PEER_IDENTITY_PATH,
                    b"",
                ),
                "body_byte_count": 0,
            }
        ):
            raise NetworkAdapterError("network execution preflight evidence rejected")
    if response is not None:
        verified_response = _verify_network_peer_response_receipt_scope(
            response,
            manifest=action,
            endpoint_key=endpoint_key,
        )
        if (
            observed["response_peer_receipt_id"] != verified_response["receipt_id"]
            or observed["response_peer_receipt_digest"]
            != network_peer_response_receipt_digest(verified_response)
            or verified_response["request"]
            != {
                "method": action["request"]["method"],
                "path": action["request"]["path"],
                "content_type": action["request"]["content_type"],
                "body_digest": action["request"]["body_digest"],
                "body_byte_count": action["request"]["body_byte_count"],
            }
            or verified_response["response"]
            != {
                "status": observed["response_status"],
                "content_type": observed["response_content_type"],
                "body_digest": observed["response_body_digest"],
                "body_byte_count": observed["response_byte_count"],
            }
        ):
            raise NetworkAdapterError("network execution response evidence rejected")
    peer_authenticated = preflight is not None
    expected_response_observed = (
        observed["response_status"] == action["expected_response"]["status"]
        and observed["response_content_type"]
        == action["expected_response"]["content_type"]
        and observed["response_body_digest"]
        == action["expected_response"]["body_digest"]
    )
    if (
        result["peer_authenticated"] is not peer_authenticated
        or response is not None and not peer_authenticated
        or result["reported_outcome"] == "reported-success"
        and (
            not observed["request_sent"]
            or observed["connection_count"] != 1
            or observed["request_count"] != 2
            or response is None
            or not expected_response_observed
            or result["reason_code"] != "expected-response-observed"
        )
        or result["reason_code"] == "peer-authentication-failed-before-action"
        and (
            observed["request_sent"]
            or observed["request_count"] != 1
            or peer_authenticated
            or response is not None
        )
        or result["reason_code"] == "post-request-outcome-unknown"
        and (not observed["request_sent"] or not peer_authenticated or response is not None)
    ):
        raise NetworkAdapterError("network execution receipt semantics rejected")
    return candidate


class NetworkHttpAdapter:
    """One exact peer-authenticated HTTP POST to a loopback synthetic endpoint."""

    def __init__(
        self,
        *,
        capability_manifest: Mapping[str, Any],
        adapter_key: TrustedKey,
        conformance_profile: Mapping[str, Any],
        conformance_profile_key: TrustedKey,
        conformance_receipt: Mapping[str, Any],
        conformance_evidence: Sequence[Mapping[str, Any]],
        conformance_evidence_keys: Mapping[str, TrustedKey],
        conformance_receipt_key: TrustedKey,
        proposal: Mapping[str, Any],
        proposer_key: TrustedKey,
        operation_binding: Mapping[str, Any],
        target_operation: Mapping[str, Any],
        operation_key: TrustedKey,
        action_manifest: Mapping[str, Any],
        action_key: TrustedKey,
        endpoint_key: TrustedKey,
        coordinator_key: TrustedKey,
        executor_id: str,
        executor_artifact_digest: str,
        request_body: bytes,
        signer: Ed25519Signer,
        evidence_directory: Path,
    ) -> None:
        manifest = verify_adapter_capability_manifest(
            capability_manifest,
            adapter_key=adapter_key,
        )
        conformance = verify_adapter_conformance_receipt(
            conformance_receipt,
            profile=conformance_profile,
            profile_key=conformance_profile_key,
            manifest=manifest,
            adapter_key=adapter_key,
            evidence_documents=conformance_evidence,
            evidence_keys=conformance_evidence_keys,
            receipt_key=conformance_receipt_key,
        )
        require_adapter_conformance_readiness(conformance, minimum="source-ready")
        action = verify_network_action_manifest(
            action_manifest,
            capability_manifest=manifest,
            adapter_key=adapter_key,
            action_key=action_key,
            endpoint_key=endpoint_key,
        )
        operation = verify_adapter_target_operation(
            target_operation,
            manifest=manifest,
            adapter_key=adapter_key,
            operation_key=operation_key,
        )
        binding = verify_adapter_operation_binding(
            operation_binding,
            manifest=manifest,
            adapter_key=adapter_key,
            proposal=proposal,
            proposer_key=proposer_key,
            operation_manifest=operation,
            operation_key=operation_key,
            binding_key=coordinator_key,
            used_at=operation_binding["created_at"],
        )
        if (
            operation["payload"]
            != {
                "schema_id": "network-http-action-manifest/v2",
                "schema_digest": network_action_schema_digest(),
                "document_digest": network_action_manifest_digest(action),
            }
            or operation["target"]["kind"] != "network"
            or operation["blast_radius"]["resource_kind"] != "network-endpoint"
            or operation["blast_radius"]["allowed_resource_ids"]
            != network_resource_ids(action)
            or action["intent_operation_digest"] != operation["intent_operation_digest"]
            or action["target"]["node_id"] != operation["target"]["node_id"]
            or action["target"]["zone_id"] != operation["target"]["zone_id"]
            or action["target"]["environment_digest"]
            != operation["target"]["environment_digest"]
        ):
            raise NetworkAdapterError("network typed operation mismatch")
        if (
            not isinstance(request_body, bytes)
            or len(request_body) != action["request"]["body_byte_count"]
            or _bytes_digest(request_body, domain="network-request-body-v1")
            != action["request"]["body_digest"]
        ):
            raise NetworkAdapterError("network request body mismatch")
        evidence = evidence_directory.resolve(strict=True)
        mode = stat.S_IMODE(evidence.stat().st_mode)
        if not evidence.is_dir() or mode & 0o077:
            raise NetworkAdapterError("network evidence custody rejected")
        self.manifest = manifest
        self.adapter_key = adapter_key
        self.conformance = conformance
        self.binding = binding
        self.operation = operation
        self.action = action
        self.action_key = action_key
        self.endpoint_key = endpoint_key
        self.coordinator_key = coordinator_key
        self.executor_id = executor_id
        self.executor_artifact_digest = executor_artifact_digest
        self.request_body = request_body
        self.signer = signer
        self.evidence_directory = evidence
        self._used: set[str] = set()

    def execute(
        self,
        envelope: Mapping[str, Any],
        *,
        dispatch_permit: AdapterDispatchPermit,
        recorded_at: str,
    ) -> dict[str, Any]:
        candidate = _verify_envelope_signature(
            envelope,
            coordinator_key=self.coordinator_key,
        )
        if candidate["manifest"] != {
            "manifest_id": self.manifest["manifest_id"],
            "manifest_digest": adapter_capability_manifest_digest(self.manifest),
            "adapter_id": self.manifest["adapter_id"],
            "adapter_artifact_digest": self.manifest["adapter_artifact_digest"],
        } or candidate["operation_binding"] != {
            "binding_id": self.binding["binding_id"],
            "binding_digest": adapter_operation_binding_digest(self.binding),
            "conformance_receipt_id": self.binding["conformance"]["receipt_id"],
            "conformance_receipt_digest": self.binding["conformance"]["receipt_digest"],
            "conformance_readiness": self.binding["conformance"]["readiness"],
            "operation_kind": self.binding["operation"]["kind"],
            "operation_manifest_id": self.binding["operation"]["manifest_id"],
            "operation_manifest_digest": self.binding["operation"]["manifest_digest"],
            "executor_id": self.binding["executor"]["executor_id"],
            "executor_artifact_digest": self.binding["executor"][
                "executor_artifact_digest"
            ],
            "executor_key_id": self.binding["executor"]["key_id"],
        }:
            raise NetworkAdapterError("network envelope mismatch")
        if candidate["envelope_id"] in self._used:
            raise NetworkAdapterError("network replay rejected")
        dispatch_permit.consume(envelope=candidate)
        self._used.add(candidate["envelope_id"])
        request_sent = False
        connection_count = 0
        request_count = 0
        response_status: int | None = None
        response_content_type: str | None = None
        response_body_digest: str | None = None
        response_byte_count: int | None = None
        preflight_peer_receipt_id: str | None = None
        preflight_peer_receipt_digest: str | None = None
        response_peer_receipt_id: str | None = None
        response_peer_receipt_digest: str | None = None
        preflight_peer_receipt: dict[str, Any] | None = None
        response_peer_receipt: dict[str, Any] | None = None
        outcome = AdapterReportedOutcome.REPORTED_FAILURE
        reason = "pre-request-network-failure"
        action = self.action
        try:
            authenticated = _exact_http_request(
                manifest=action,
                endpoint_key=self.endpoint_key,
                method=action["request"]["method"],
                path=action["request"]["path"],
                content_type=action["request"]["content_type"],
                body=self.request_body,
                maximum_body_bytes=action["expected_response"]["maximum_body_bytes"],
            )
            connection_count = authenticated.connection_count
            request_count = authenticated.request_count
            request_sent = authenticated.action_request_sent
            response_status = authenticated.status
            response_content_type = authenticated.content_type
            response_body = authenticated.body
            if authenticated.preflight_peer_receipt is None:
                raise NetworkAdapterError("network peer preflight evidence missing")
            preflight_peer_receipt = authenticated.preflight_peer_receipt
            response_peer_receipt = authenticated.peer_receipt
            preflight_peer_receipt_id = preflight_peer_receipt["receipt_id"]
            preflight_peer_receipt_digest = network_peer_response_receipt_digest(
                preflight_peer_receipt
            )
            response_peer_receipt_id = response_peer_receipt["receipt_id"]
            response_peer_receipt_digest = network_peer_response_receipt_digest(
                response_peer_receipt
            )
            response_body_digest = _bytes_digest(
                response_body,
                domain="network-response-body-v1",
            )
            response_byte_count = len(response_body)
            success = (
                response_status == action["expected_response"]["status"]
                and response_content_type == action["expected_response"]["content_type"]
                and response_body_digest == action["expected_response"]["body_digest"]
            )
            outcome = (
                AdapterReportedOutcome.REPORTED_SUCCESS
                if success
                else AdapterReportedOutcome.REPORTED_FAILURE
            )
            reason = "expected-response-observed" if success else "response-mismatch"
        except NetworkExchangeError as exc:
            connection_count = exc.connection_count
            request_count = exc.request_count
            request_sent = exc.action_request_sent
            if exc.preflight_peer_receipt is not None:
                preflight_peer_receipt = exc.preflight_peer_receipt
                preflight_peer_receipt_id = preflight_peer_receipt["receipt_id"]
                preflight_peer_receipt_digest = network_peer_response_receipt_digest(
                    preflight_peer_receipt
                )
            if request_sent:
                outcome = AdapterReportedOutcome.OUTCOME_UNKNOWN
                reason = "post-request-outcome-unknown"
            else:
                outcome = AdapterReportedOutcome.REPORTED_FAILURE
                reason = "peer-authentication-failed-before-action"
        except NetworkAdapterError:
            outcome = AdapterReportedOutcome.REPORTED_FAILURE
            reason = "pre-request-network-failure"
        core = {
            "protocol": "integrity-guardian/network-http-execution-receipt/v2",
            "sdk_version": ADAPTER_SDK_VERSION,
            "envelope": {
                "envelope_id": candidate["envelope_id"],
                "envelope_digest": adapter_execution_envelope_digest(candidate),
            },
            "operation": {
                "target_operation_id": self.operation["operation_id"],
                "target_operation_digest": adapter_target_operation_digest(self.operation),
                "action_id": action["action_id"],
                "action_manifest_digest": network_action_manifest_digest(action),
            },
            "executor": {
                "executor_id": self.executor_id,
                "executor_artifact_digest": self.executor_artifact_digest,
                "key_id": self.signer.key_id,
            },
            "observed": {
                "request_sent": request_sent,
                "connection_count": connection_count,
                "request_count": request_count,
                "response_status": response_status,
                "response_content_type": response_content_type,
                "response_body_digest": response_body_digest,
                "response_byte_count": response_byte_count,
                "peer_key_id": self.endpoint_key.key_id,
                "peer_key_fingerprint": public_key_fingerprint(
                    self.endpoint_key.public_key
                ),
                "preflight_peer_receipt_id": preflight_peer_receipt_id,
                "preflight_peer_receipt_digest": preflight_peer_receipt_digest,
                "preflight_peer_receipt": preflight_peer_receipt,
                "response_peer_receipt_id": response_peer_receipt_id,
                "response_peer_receipt_digest": response_peer_receipt_digest,
                "response_peer_receipt": response_peer_receipt,
                "raw_body_retained": False,
            },
            "result": {
                "reported_outcome": outcome.value,
                "reason_code": reason,
                "peer_authenticated": preflight_peer_receipt_id is not None,
                "action_replayed": False,
                "automatic_retry_allowed": False,
            },
            "controls": {
                "numeric_loopback_destination": True,
                "dns_resolution": False,
                "proxy": False,
                "redirects": False,
                "credentials": False,
                "peer_authentication": "ed25519-challenge-v1",
                "action_preflight_required": True,
                "fresh_response_challenge_required": True,
                "home_input": False,
                "production_authority": False,
            },
            "recorded_at": recorded_at,
            "signer_id": self.signer.key_id,
        }
        receipt = self.signer.sign(
            {"receipt_id": _receipt_identity(core), **core}
        )
        validate("network-http-execution-receipt", receipt)
        verified = verify_network_execution_receipt(
            receipt,
            executor_key=TrustedKey(self.signer.key_id, self.signer.public_key),
            action_manifest=self.action,
            capability_manifest=self.manifest,
            adapter_key=self.adapter_key,
            action_key=self.action_key,
            endpoint_key=self.endpoint_key,
        )
        write_operation_document(
            self.evidence_directory / NETWORK_EXECUTION_RECEIPT_ARTIFACT,
            verified,
            schema="network-http-execution-receipt",
        )
        return build_adapter_execution_report(
            envelope=candidate,
            coordinator_key=self.coordinator_key,
            adapter_id=self.manifest["adapter_id"],
            adapter_artifact_digest=self.manifest["adapter_artifact_digest"],
            executor_id=self.executor_id,
            executor_artifact_digest=self.executor_artifact_digest,
            operation_binding=self.binding,
            conformance_receipt=self.conformance,
            operation_evidence_reference={
                "schema_id": "network-http-execution-receipt/v2",
                "receipt_id": verified["receipt_id"],
                "receipt_digest": network_execution_receipt_digest(verified),
            },
            evidence_artifact_count=1,
            reported_outcome=verified["result"]["reported_outcome"],
            recorded_at=recorded_at,
            signer=self.signer,
            network_used=True,
        )


__all__ = [
    "NETWORK_ACTION_DIGEST_HEADER",
    "NETWORK_ACTION_ID_HEADER",
    "NETWORK_CHALLENGE_HEADER",
    "NETWORK_EXECUTION_RECEIPT_ARTIFACT",
    "NETWORK_PEER_IDENTITY_PATH",
    "NETWORK_PEER_RECEIPT_HEADER",
    "NetworkAdapterError",
    "NetworkHttpAdapter",
    "build_network_action_manifest",
    "build_network_peer_response_receipt",
    "encode_network_peer_response_receipt",
    "network_action_manifest_digest",
    "network_action_schema_digest",
    "network_execution_receipt_digest",
    "network_peer_response_receipt_digest",
    "network_resource_ids",
    "verify_network_action_manifest",
    "verify_network_execution_receipt",
    "verify_network_peer_response_receipt",
]
