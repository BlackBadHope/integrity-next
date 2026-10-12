"""Windows Job Object adapter profile with explicit non-sandbox evidence semantics."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from copy import deepcopy
from pathlib import Path
from typing import Any

from .adapter_runtime import ContainedReadOnlyOperationAdapter
from .adapter_sdk import ADAPTER_SDK_VERSION
from .hashing import digest_object
from .operation_audit import (
    WINDOWS_JOB_PROCESS_BOUNDARY_KIND,
    verify_readonly_operation_evidence,
    verify_readonly_operation_manifest,
    verify_readonly_operation_receipt,
    windows_job_process_boundary_contract,
)
from .schemas import validate
from .signing import (
    Ed25519Signer,
    TrustedKey,
    public_key_fingerprint,
    verify_signature,
)

_SAFE_EXACT_ENVIRONMENT = {
    "COMSPEC",
    "LANG",
    "LC_ALL",
    "PATH",
    "PATHEXT",
    "PROGRAMDATA",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "WINDIR",
}


class WindowsBoundedProcessError(ValueError):
    """Raised before Job Object evidence can be mistaken for sandbox evidence."""


def _identity(document: Mapping[str, Any]) -> str:
    core = deepcopy(dict(document))
    core.pop("witness_id", None)
    core.pop("signature", None)
    suffix = digest_object(
        core,
        domain="windows-bounded-process-witness-identity-v1",
    ).split(":", 1)[1]
    return f"windows-bounded-process-witness:{suffix}"


def windows_bounded_process_witness_digest(witness: Mapping[str, Any]) -> str:
    return digest_object(dict(witness), domain="windows-bounded-process-witness-v1")


def require_windows_bounded_operation_manifest(
    manifest: Mapping[str, Any],
) -> dict[str, Any]:
    candidate = deepcopy(dict(manifest))
    try:
        verify_readonly_operation_manifest(candidate)
    except Exception as exc:
        raise WindowsBoundedProcessError(
            "Windows bounded process manifest rejected"
        ) from exc
    if (
        candidate.get("protocol")
        != "integrity-guardian/readonly-operation-manifest/v2"
        or len(candidate["operations"]) != 1
        or candidate["controls"]
        != {
            "read_only_intent": True,
            "shell": False,
            "raw_argv_retained": True,
            "executable_digest_required": True,
            "credential_values_in_argv_prohibited": True,
            "credential_values_in_argv_preexecution_proven": False,
            "final_credential_custody_audit_required": True,
            "credentials_by_reference": True,
            "environment_policy": "per-operation-exact",
            "exact_working_directory": True,
            "os_readonly_containment": False,
            "process_tree_contained": True,
            "network_blocked": False,
            "host_filesystem_write_blocked": False,
            "home_hidden": False,
            "mutation_observation": "not-observed-by-guardian",
            "automatic_retry_after_unknown": False,
        }
    ):
        raise WindowsBoundedProcessError("Windows bounded process controls rejected")
    operation = candidate["operations"][0]
    context = operation["execution_context"]
    if (
        operation["credential_reference"] is not None
        or context["containment"] != windows_job_process_boundary_contract()
        or context["containment"]["kind"] != WINDOWS_JOB_PROCESS_BOUNDARY_KIND
        or not {name.upper() for name in context["environment"]}
        <= _SAFE_EXACT_ENVIRONMENT
    ):
        raise WindowsBoundedProcessError("Windows bounded process context rejected")
    return candidate


class WindowsBoundedProcessAdapter(ContainedReadOnlyOperationAdapter):
    """One-shot reviewed Windows executable; Job Object containment is not a sandbox."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        for manifest in self.operations.values():
            require_windows_bounded_operation_manifest(manifest)


def build_windows_bounded_process_witness(
    *,
    operation_manifest: Mapping[str, Any],
    operation_receipt: Mapping[str, Any],
    evidence_directory: Path,
    independent_stdout: bytes,
    independent_source_id: str,
    executor_id: str,
    executor_artifact_digest: str,
    executor_key_id: str,
    executor_key: TrustedKey,
    observer_id: str,
    observer_artifact_digest: str,
    observed_at: str,
    signer: Ed25519Signer,
) -> dict[str, Any]:
    manifest = require_windows_bounded_operation_manifest(operation_manifest)
    receipt = deepcopy(dict(operation_receipt))
    manifest_digest = verify_readonly_operation_manifest(manifest)
    verified_receipt = verify_readonly_operation_receipt(receipt, manifest=manifest)
    verify_readonly_operation_evidence(receipt, evidence_directory=evidence_directory)
    operation = manifest["operations"][0]
    result = receipt["operations"][0]
    context = operation["execution_context"]
    if verified_receipt["status"] != "PASS" or result["outcome"] != "confirmed-success":
        raise WindowsBoundedProcessError("Windows bounded process result rejected")
    independent_digest = "sha256:" + hashlib.sha256(independent_stdout).hexdigest()
    if (
        independent_digest != result["stdout_digest"]
        or len(independent_stdout) != result["stdout_byte_count"]
    ):
        raise WindowsBoundedProcessError("Windows bounded process independent result mismatch")
    if (
        executor_key_id != executor_key.key_id
        or executor_id == observer_id
        or executor_artifact_digest == observer_artifact_digest
        or executor_key_id == signer.key_id
        or public_key_fingerprint(executor_key.public_key)
        == public_key_fingerprint(signer.public_key)
    ):
        raise WindowsBoundedProcessError(
            "Windows bounded process executor/witness separation rejected"
        )
    core = {
        "protocol": "integrity-guardian/windows-bounded-process-witness/v1",
        "sdk_version": ADAPTER_SDK_VERSION,
        "manifest": {
            "manifest_id": manifest["manifest_id"],
            "manifest_digest": manifest_digest,
            "adapter_id": manifest["adapter_id"],
            "target_node_id": manifest["target_node_id"],
        },
        "operation": {
            "operation_id": operation["operation_id"],
            "executable_digest": operation["executable_digest"],
            "argv_digest": operation["argv_digest"],
            "environment_digest": context["environment_digest"],
            "working_directory_digest": digest_object(
                context["working_directory"],
                domain="windows-bounded-process-working-directory-v1",
            ),
            "containment_digest": digest_object(
                context["containment"],
                domain="windows-bounded-process-containment-v1",
            ),
        },
        "receipt": {
            "receipt_id": receipt["receipt_id"],
            "receipt_digest": digest_object(
                receipt,
                domain="readonly-operation-receipt-document-v1",
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
            "source_id": independent_source_id,
            "stdout_digest": independent_digest,
            "stdout_byte_count": len(independent_stdout),
            "content_retained": False,
        },
        "result": {
            "executor_confirmed_success": True,
            "independent_output_match": True,
            "executor_claim_trusted": False,
            "external_causality_proven": False,
            "production_mutated": "UNKNOWN",
        },
        "controls": {
            "read_only_intent_only": True,
            "shell_expansion": False,
            "process_tree_contained": True,
            "network": "not-enforced",
            "host_filesystem_write": "not-enforced",
            "host_filesystem_visibility": "host-visible-under-executor-identity",
            "home_visible": "not-enforced",
            "credentials": False,
            "automatic_retry": False,
            "production_authority": False,
        },
        "observed_at": observed_at,
        "signer_id": signer.key_id,
    }
    signed = signer.sign({"witness_id": _identity(core), **core})
    validate("windows-bounded-process-witness", signed)
    return signed


def verify_windows_bounded_process_witness(
    witness: Mapping[str, Any],
    *,
    executor_key: TrustedKey,
    observer_key: TrustedKey,
) -> dict[str, Any]:
    candidate = deepcopy(dict(witness))
    validate("windows-bounded-process-witness", candidate)
    if candidate["witness_id"] != _identity(candidate):
        raise WindowsBoundedProcessError("Windows bounded process witness identity mismatch")
    if (
        candidate["signer_id"] != observer_key.key_id
        or candidate["signature"]["key_id"] != observer_key.key_id
        or not verify_signature(candidate, observer_key.public_key)
    ):
        raise WindowsBoundedProcessError("Windows bounded process witness signature rejected")
    executor = candidate["executor"]
    observer = candidate["observer"]
    if observer["key_id"] != observer_key.key_id:
        raise WindowsBoundedProcessError(
            "Windows bounded process observer key binding rejected"
        )
    if executor["key_id"] != executor_key.key_id:
        raise WindowsBoundedProcessError(
            "Windows bounded process executor key binding rejected"
        )
    if (
        executor["actor_id"] == observer["actor_id"]
        or executor["artifact_digest"] == observer["artifact_digest"]
        or executor["key_id"] == observer["key_id"]
        or public_key_fingerprint(executor_key.public_key)
        == public_key_fingerprint(observer_key.public_key)
    ):
        raise WindowsBoundedProcessError(
            "Windows bounded process executor/witness separation rejected"
        )
    return candidate


__all__ = [
    "WindowsBoundedProcessAdapter",
    "WindowsBoundedProcessError",
    "build_windows_bounded_process_witness",
    "require_windows_bounded_operation_manifest",
    "verify_windows_bounded_process_witness",
    "windows_bounded_process_witness_digest",
]
