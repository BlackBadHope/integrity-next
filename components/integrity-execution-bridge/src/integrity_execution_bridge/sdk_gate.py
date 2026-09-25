"""Reuse Guardian's existing verification and one-use permit; no new grants."""
from __future__ import annotations

from datetime import UTC, datetime

from .contracts import Rejected, encode, freeze, require, sha

DESCRIPTOR_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "properties": {key: {"type": "string"} for key in (
        "protocol", "principal", "task_id", "operation_id", "snapshot_id", "tool",
        "arguments_sha256", "catalog_sha256", "workspace_sha256", "backend_sha256")},
    "required": ["protocol", "principal", "task_id", "operation_id", "snapshot_id", "tool",
                 "arguments_sha256", "catalog_sha256", "workspace_sha256", "backend_sha256",
                 "generation", "deadline_epoch"],
}
DESCRIPTOR_SCHEMA["properties"].update({"generation": {"type": "integer"},
                                         "deadline_epoch": {"type": "number"}})
SCHEMA_ID = "integrity-execution-bridge/operation/v1"


class SDKInvoker:
    """Trusted host supplies exact evidence for each descriptor; not an MCP tool.

    evidence_factory returns (envelope, verification_context, genuine_permit),
    optionally followed by a same-thread finalizer.  The finalizer persists and
    closes provider-owned permit resources after consumption and before effect.
    External permission/credential/model/production authority is not implied.
    """
    def __init__(self, evidence_factory=None):
        self.factory = evidence_factory

    def invoke(self, descriptor, action):
        if self.factory is None:
            raise Rejected("sdk_admission_unavailable")
        try:
            import integrity_adapter_sdk as sdk
            sdk.require_guardian()
        except (ImportError, RuntimeError):
            raise Rejected("exact_sdk_unavailable") from None
        evidence = self.factory(freeze(descriptor))
        require(type(evidence) is tuple and len(evidence) in (3, 4), "sdk_evidence_shape")
        envelope, context, permit = evidence[:3]
        finalize = evidence[3] if len(evidence) == 4 else None
        require(finalize is None or callable(finalize), "sdk_finalizer_required")
        try:
            require(type(permit) is sdk.adapter_runtime.AdapterDispatchPermit,
                    "genuine_sdk_permit_required")
            context = dict(context)
            for key in ("manifest", "proposal", "operation_binding", "operation_manifest"):
                require(key in context, "sdk_context_missing")
                context[key] = freeze(context[key])
            expected = {
                "schema_id": SCHEMA_ID,
                "schema_digest": "sha256:" + sha(encode(DESCRIPTOR_SCHEMA)),
                "document_digest": "sha256:" + sha(encode(descriptor)),
            }
            require(context["operation_manifest"].get("payload") == expected,
                    "sdk_payload_mismatch")
            verified = sdk.adapter_sdk.verify_adapter_execution_envelope(
                freeze(envelope), **(context | {"used_at": datetime.now(UTC).isoformat()}))
            permit.consume(envelope=verified)
        finally:
            if finalize is not None:
                finalize()
        return action()
