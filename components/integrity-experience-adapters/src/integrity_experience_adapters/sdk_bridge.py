"""Reuse Guardian's verifier and durable permit; never manufacture an authority.

Construct this bridge only in trusted host code. Keys, verified grants, sinks
and conformance policy must not come from request JSON. No SDK fallback exists.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable

from . import contracts as c

PAYLOAD_SCHEMA_ID = "integrity-experience-operation/v1"
PAYLOAD_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object", "additionalProperties": False,
    "required": ["kind", "input_sha256", "configuration_sha256"],
    "properties": {
        "kind": {"enum": ["transcribe", "synthesize", "mcp-call", "voice-sdp"]},
        "input_sha256": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
        "configuration_sha256": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
    },
}


def operation_payload(kind: str, input_bytes: bytes, configuration: dict[str, Any]) -> dict[str, Any]:
    c.require(kind in ("transcribe", "synthesize", "mcp-call", "voice-sdp"), "unknown_operation")
    c.require(type(input_bytes) is bytes and len(input_bytes) <= 8 * 1024 * 1024, "input_size_limit")
    return {"kind": kind, "input_sha256": c.sha(input_bytes),
            "configuration_sha256": c.sha(c.canonical(configuration))}


class GuardianDispatch:
    """Host-bound dispatch of one exact input/config to one already-admitted sink.

    Conformance receipt admission and the signed envelope/grant are produced by
    the existing host coordinator. This bridge does not grant conformance or
    independently witness a result. Failures after permit consumption stay unknown.
    """
    def __init__(self, *, verification_context: dict[str, Any], envelope: dict[str, Any],
                 permit: Any, kind: str, configuration: dict[str, Any],
                 sink: Callable[[bytes], Any]) -> None:
        try:
            import integrity_adapter_sdk as sdk
            sdk.require_guardian()
            self._api, self._runtime = sdk.adapter_sdk, sdk.adapter_runtime
        except (ImportError, RuntimeError) as exc:
            raise c.ContractError("exact_guardian_sdk_unavailable") from exc
        c.require(type(permit) is self._runtime.AdapterDispatchPermit, "real_sdk_permit_required")
        # Context includes the trusted keys, proposal, target operation, binding
        # and genuine VerifiedAdapterGrant expected by the existing verifier.
        self._context = dict(verification_context)
        for field in ("manifest", "proposal", "operation_binding", "operation_manifest"):
            c.require(field in self._context, "incomplete_verification_context")
            self._context[field] = c.load_json(c.canonical(self._context[field]))
        self._envelope = c.load_json(c.canonical(envelope))
        self._permit, self._kind, self._sink = permit, kind, sink
        self._configuration = c.load_json(c.canonical(configuration))
        c.require(callable(sink), "admitted_sink_required")

    def __call__(self, raw: bytes) -> Any:
        payload = operation_payload(self._kind, raw, self._configuration)
        # Full standard verifier: no bare signature check and no duck-typed grant.
        envelope = self._api.verify_adapter_execution_envelope(
            self._envelope, **{**self._context, "used_at": datetime.now(timezone.utc).isoformat()})
        operation = self._context["operation_manifest"]
        c.require(operation["payload"] == {
            "schema_id": PAYLOAD_SCHEMA_ID,
            "schema_digest": c.sha(c.canonical(PAYLOAD_SCHEMA)),
            "document_digest": c.sha(c.canonical(payload)),
        }, "exact_operation_payload_mismatch")
        self._permit.consume(envelope=envelope)
        # The sink receives those same immutable bytes, never a mutable file path.
        # No exception handler repeats the call or fabricates an observer receipt.
        return self._sink(raw)
