"""Exact read-only HostCommand admission over the existing operation runner."""

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
    verify_readonly_operation_evidence,
    verify_readonly_operation_manifest,
    verify_readonly_operation_receipt,
)
from .schemas import validate
from .signing import Ed25519Signer, TrustedKey, verify_signature

_SAFE_EXACT_ENVIRONMENT = {
    "COMSPEC",
    "LANG",
    "LC_ALL",
    "PATH",
    "PATHEXT",
    "PWD",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "WINDIR",
}


class HostCommandError(ValueError):
    """Raised before an exact host result can be overstated."""


def _identity(document: Mapping[str, Any]) -> str:
    core = deepcopy(dict(document))
    core.pop("witness_id", None)
    core.pop("signature", None)
    suffix = digest_object(
        core,
        domain="host-command-witness-identity-v1",
    ).split(":", 1)[1]
    return f"host-command-witness:{suffix}"


def host_command_witness_digest(witness: Mapping[str, Any]) -> str:
    return digest_object(dict(witness), domain="host-command-witness-v1")


class HostCommandAdapter(ContainedReadOnlyOperationAdapter):
    """Exact-context profile; execution remains in the shared one-shot runner."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        for operation_manifest in self.operations.values():
            controls = operation_manifest["controls"]
            if not (
                controls["environment_policy"] == "per-operation-exact"
                and controls["exact_working_directory"] is True
                and controls["os_readonly_containment"] is True
                and controls["host_filesystem_write_blocked"] is True
                and controls["home_hidden"] is True
            ):
                raise HostCommandError("host command exact execution controls rejected")
            operation = operation_manifest["operations"][0]
            context = operation.get("execution_context")
            if (
                context is None
                or operation["credential_reference"] is not None
                or not set(context["environment"]) <= _SAFE_EXACT_ENVIRONMENT
                or context["containment"]["kind"] != "bubblewrap-readonly-host"
            ):
                raise HostCommandError("host command exact execution context rejected")
            working_directory = Path(context["working_directory"])
            if working_directory.is_relative_to(Path("/root")) or (
                working_directory.is_relative_to(Path("/home"))
                or not (
                    working_directory == Path("/")
                    or working_directory == Path("/tmp")
                    or any(
                        working_directory.is_relative_to(root)
                        for root in (Path("/usr"), Path("/lib"), Path("/lib64"))
                    )
                )
            ):
                raise HostCommandError("host command Home working directory rejected")


def build_host_command_witness(
    *,
    operation_manifest: Mapping[str, Any],
    operation_receipt: Mapping[str, Any],
    evidence_directory: Path,
    independent_stdout: bytes,
    independent_source_id: str,
    executor_id: str,
    executor_artifact_digest: str,
    executor_key_id: str,
    observer_id: str,
    observer_artifact_digest: str,
    observed_at: str,
    signer: Ed25519Signer,
) -> dict[str, Any]:
    """Bind one content-free independent result to exact executor evidence."""

    manifest = deepcopy(dict(operation_manifest))
    receipt = deepcopy(dict(operation_receipt))
    manifest_digest = verify_readonly_operation_manifest(manifest)
    verified_receipt = verify_readonly_operation_receipt(receipt, manifest=manifest)
    verify_readonly_operation_evidence(receipt, evidence_directory=evidence_directory)
    if (
        len(manifest["operations"]) != 1
        or verified_receipt["status"] != "PASS"
        or manifest["controls"]["environment_policy"] != "per-operation-exact"
        or manifest["controls"]["os_readonly_containment"] is not True
        or manifest["controls"]["host_filesystem_write_blocked"] is not True
        or manifest["controls"]["home_hidden"] is not True
    ):
        raise HostCommandError("host command witness manifest rejected")
    operation = manifest["operations"][0]
    context = operation.get("execution_context")
    result = receipt["operations"][0]
    if context is None or result["outcome"] != "confirmed-success":
        raise HostCommandError("host command witness execution result rejected")
    independent_digest = "sha256:" + hashlib.sha256(independent_stdout).hexdigest()
    if (
        independent_digest != result["stdout_digest"]
        or len(independent_stdout) != result["stdout_byte_count"]
    ):
        raise HostCommandError("host command independent result mismatch")
    if (
        executor_id == observer_id
        or executor_artifact_digest == observer_artifact_digest
        or executor_key_id == signer.key_id
    ):
        raise HostCommandError("host command executor/witness separation rejected")
    core = {
        "protocol": "integrity-guardian/host-command-witness/v1",
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
                domain="host-command-working-directory-v1",
            ),
            "containment_executable_digest": context["containment"][
                "executable_digest"
            ],
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
        },
        "controls": {
            "shell_expansion": False,
            "network": False,
            "host_filesystem_write": False,
            "host_filesystem_visibility": "runtime-only",
            "home_visible": False,
            "credentials": False,
            "automatic_retry": False,
            "production_authority": False,
        },
        "observed_at": observed_at,
        "signer_id": signer.key_id,
    }
    signed = signer.sign({"witness_id": _identity(core), **core})
    validate("host-command-witness", signed)
    return signed


def verify_host_command_witness(
    witness: Mapping[str, Any],
    *,
    observer_key: TrustedKey,
) -> dict[str, Any]:
    candidate = deepcopy(dict(witness))
    validate("host-command-witness", candidate)
    if candidate["witness_id"] != _identity(candidate):
        raise HostCommandError("host command witness identity mismatch")
    if (
        candidate["signer_id"] != observer_key.key_id
        or candidate["signature"]["key_id"] != observer_key.key_id
        or not verify_signature(candidate, observer_key.public_key)
    ):
        raise HostCommandError("host command witness signature rejected")
    executor = candidate["executor"]
    observer = candidate["observer"]
    if (
        executor["actor_id"] == observer["actor_id"]
        or executor["artifact_digest"] == observer["artifact_digest"]
        or executor["key_id"] == observer["key_id"]
    ):
        raise HostCommandError("host command executor/witness separation rejected")
    return candidate


__all__ = [
    "HostCommandAdapter",
    "HostCommandError",
    "build_host_command_witness",
    "host_command_witness_digest",
    "verify_host_command_witness",
]
