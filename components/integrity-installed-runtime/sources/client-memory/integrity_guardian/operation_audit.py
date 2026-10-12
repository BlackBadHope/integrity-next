"""Exact pre-execution commitments and proof-bearing read-only operation runs."""

from __future__ import annotations

import hashlib
import os
import re
import signal
import stat
import subprocess
import threading
import time
from collections.abc import Sequence
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path, PureWindowsPath
from typing import Any

from .canonical import canonical_bytes, parse_json_strict
from .hashing import digest_object
from .schemas import validate
from .signing import (
    Ed25519Signer,
    TrustedKey,
    public_key_fingerprint,
    verify_signature,
)
from .tenant import validate_tenant_id

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_CREDENTIAL = re.compile(r"^credential:[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_ARTIFACT_SAFE = re.compile(r"[^A-Za-z0-9._-]+")
_OUTCOMES = (
    "not-started",
    "confirmed-success",
    "confirmed-failure",
    "unknown-outcome",
)
_ALLOWED_ENVIRONMENT = (
    "COMSPEC",
    "HOME",
    "LANG",
    "LC_ALL",
    "LOCALAPPDATA",
    "PATH",
    "PATHEXT",
    "PROGRAMDATA",
    "SSH_AUTH_SOCK",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "WINDIR",
)
_MAXIMUM_EXECUTABLE_BYTES = 512 * 1024 * 1024
_MAXIMUM_AUTHORIZATION_SECONDS = 3_600
_ENVIRONMENT_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_POSIX_CONTAINED_RUNTIME_ROOTS = tuple(
    Path(value) for value in ("/usr", "/lib", "/lib64")
)
READONLY_OPERATION_RECEIPT_ARTIFACT = "operation-receipt.json"
WINDOWS_JOB_PROCESS_BOUNDARY_KIND = "windows-job-process-boundary-v1"

_WINDOWS_JOB_PROCESS_BOUNDARY_CORE: dict[str, Any] = {
    "kind": WINDOWS_JOB_PROCESS_BOUNDARY_KIND,
    "process_creation": "suspended-before-job-assignment",
    "inherited_handles": ["stdin", "stdout", "stderr"],
    "kill_on_job_close": True,
    "active_process_limit": 32,
    "process_memory_bytes": 256 * 1024 * 1024,
    "timeout_enforced": True,
    "output_bound_enforced": True,
    "executable_identity_held": True,
    "application_dependency_closure": "not-bound",
    "network": "not-enforced",
    "host_filesystem_write": "not-enforced",
    "host_filesystem_visibility": "host-visible-under-executor-identity",
    "home_visible": "not-enforced",
    "production_mutation": "UNKNOWN",
}

_WINDOWS_BOUNDED_CONTROLS = {
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


class OperationAuditError(ValueError):
    """Raised before an operation audit can overstate execution evidence."""


def windows_job_process_boundary_contract() -> dict[str, Any]:
    """Return the canonical Job Object capability statement, not a sandbox claim."""

    core = deepcopy(_WINDOWS_JOB_PROCESS_BOUNDARY_CORE)
    return {
        **core,
        "contract_digest": digest_object(
            core,
            domain="windows-job-process-boundary-contract-v1",
        ),
    }


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _is_lexical_posix_runtime_path(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    path = Path(value)
    return (
        path.is_absolute()
        and str(path) == value
        and ".." not in path.parts
        and any(
            path == root or path.is_relative_to(root)
            for root in _POSIX_CONTAINED_RUNTIME_ROOTS
        )
    )


def _is_live_posix_runtime_executable(value: object) -> bool:
    if not _is_lexical_posix_runtime_path(value):
        return False
    declared = Path(value)
    try:
        resolved = declared.resolve(strict=True)
    except OSError:
        return False
    return declared == resolved and _is_lexical_posix_runtime_path(str(resolved))


def _identity(document: dict[str, Any], *, prefix: str, domain: str) -> str:
    return prefix + digest_object(document, domain=domain).split(":", 1)[1]


def _digest_executable(path: Path) -> str:
    if not path.is_absolute():
        raise OperationAuditError("operation executable must be absolute")
    if os.name == "nt":
        from ._windows_files import HeldWindowsFile, WindowsFileBoundaryError

        try:
            with HeldWindowsFile(path, maximum_bytes=_MAXIMUM_EXECUTABLE_BYTES) as held:
                return "sha256:" + held.sha256()
        except WindowsFileBoundaryError as exc:
            raise OperationAuditError("operation executable is absent or unsafe") from exc
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise OperationAuditError("operation executable is absent or unsafe") from exc
    try:
        details = os.fstat(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_size > _MAXIMUM_EXECUTABLE_BYTES
            or stat.S_IMODE(details.st_mode) & 0o022
        ):
            raise OperationAuditError("operation executable type, size or mode rejected")
        hasher = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            hasher.update(chunk)
        return "sha256:" + hasher.hexdigest()
    finally:
        os.close(descriptor)


def _normalized_operation_spec(operation: dict[str, Any]) -> dict[str, Any]:
    required = {
        "operation_id",
        "purpose",
        "argv",
        "credential_reference",
    }
    optional = {"timeout_seconds", "max_output_bytes"}
    if not required.issubset(operation) or set(operation) - required - optional:
        raise OperationAuditError("operation specification field set rejected")
    operation_id = operation["operation_id"]
    purpose = operation["purpose"]
    argv = operation["argv"]
    credential_reference = operation["credential_reference"]
    timeout = operation.get("timeout_seconds", 30)
    maximum = operation.get("max_output_bytes", 1024 * 1024)
    if not isinstance(operation_id, str) or _ID.fullmatch(operation_id) is None:
        raise OperationAuditError("operation identity rejected")
    if not isinstance(purpose, str) or not 1 <= len(purpose) <= 512:
        raise OperationAuditError("operation purpose rejected")
    if (
        not isinstance(argv, list)
        or not 1 <= len(argv) <= 64
        or any(
            not isinstance(value, str)
            or not value
            or len(value) > 4096
            or "\x00" in value
            or "\r" in value
            or "\n" in value
            for value in argv
        )
    ):
        raise OperationAuditError("operation argv rejected")
    if credential_reference is not None and (
        not isinstance(credential_reference, str)
        or _CREDENTIAL.fullmatch(credential_reference) is None
    ):
        raise OperationAuditError("credential reference rejected")
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 300:
        raise OperationAuditError("operation timeout rejected")
    if (
        not isinstance(maximum, int)
        or isinstance(maximum, bool)
        or not 1024 <= maximum <= 4 * 1024 * 1024
    ):
        raise OperationAuditError("operation output bound rejected")
    executable = Path(argv[0])
    executable_digest = _digest_executable(executable)
    return {
        "operation_id": operation_id,
        "purpose": purpose,
        "executable": str(executable),
        "executable_digest": executable_digest,
        "argv": list(argv),
        "argv_digest": digest_object(argv, domain="readonly-operation-argv-v1"),
        "argument_count": len(argv),
        "credential_reference": credential_reference,
        "timeout_seconds": timeout,
        "max_output_bytes": maximum,
    }


def _normalized_posix_operation_spec(operation: dict[str, Any]) -> dict[str, Any]:
    if set(operation) - {
        "operation_id",
        "purpose",
        "argv",
        "credential_reference",
        "timeout_seconds",
        "max_output_bytes",
        "execution_context",
    } or "execution_context" not in operation:
        raise OperationAuditError("POSIX operation execution context required")
    normalized = _normalized_operation_spec(
        {key: value for key, value in operation.items() if key != "execution_context"}
    )
    if not _is_live_posix_runtime_executable(normalized["executable"]):
        raise OperationAuditError(
            "POSIX operation executable is not canonical within the contained runtime"
        )
    context = operation["execution_context"]
    if not isinstance(context, dict) or set(context) != {
        "working_directory",
        "environment",
        "containment",
    }:
        raise OperationAuditError("POSIX operation execution context rejected")
    working_directory = context["working_directory"]
    environment = context["environment"]
    containment = context["containment"]
    if (
        not isinstance(working_directory, str)
        or not working_directory
        or "\x00" in working_directory
        or not Path(working_directory).is_absolute()
        or not isinstance(environment, dict)
        or len(environment) > 32
    ):
        raise OperationAuditError("POSIX operation execution context rejected")
    if (
        not isinstance(containment, dict)
        or set(containment) != {"kind", "executable"}
        or containment["kind"] != "bubblewrap-readonly-host"
        or not isinstance(containment["executable"], str)
    ):
        raise OperationAuditError("POSIX operation containment context rejected")
    normalized_environment: dict[str, str] = {}
    for name, value in sorted(environment.items()):
        if (
            not isinstance(name, str)
            or _ENVIRONMENT_NAME.fullmatch(name) is None
            or not isinstance(value, str)
            or len(value) > 4096
            or "\x00" in value
            or "\r" in value
            or "\n" in value
        ):
            raise OperationAuditError("POSIX operation exact environment rejected")
        normalized_environment[name] = value
    resolved_working_directory = Path(working_directory).resolve(strict=True)
    if not resolved_working_directory.is_dir():
        raise OperationAuditError("POSIX operation working directory rejected")
    if "PWD" in normalized_environment and normalized_environment["PWD"] != str(
        resolved_working_directory
    ):
        raise OperationAuditError("POSIX operation working directory mismatch")
    normalized_environment["PWD"] = str(resolved_working_directory)
    containment_executable = Path(containment["executable"])
    if not containment_executable.is_absolute():
        raise OperationAuditError("POSIX containment executable path rejected")
    containment_digest = _digest_executable(containment_executable)
    normalized["execution_context"] = {
        "working_directory": str(resolved_working_directory),
        "environment": normalized_environment,
        "environment_digest": digest_object(
            normalized_environment,
            domain="readonly-operation-environment-v3",
        ),
        "containment": {
            "kind": "bubblewrap-readonly-host",
            "executable": str(containment_executable),
            "executable_digest": containment_digest,
            "network": False,
            "host_filesystem_write": False,
            "host_filesystem_visibility": "runtime-only",
            "home_visible": False,
        },
    }
    return normalized


def build_readonly_operation_manifest(
    *,
    tenant_id: str,
    adapter_id: str,
    target_node_id: str,
    created_at: str,
    operations: Sequence[dict[str, Any]],
) -> dict[str, Any]:
    validate_tenant_id(tenant_id)
    if _ID.fullmatch(adapter_id) is None or _ID.fullmatch(target_node_id) is None:
        raise OperationAuditError("adapter or target identity rejected")
    if not 1 <= len(operations) <= 64:
        raise OperationAuditError("operation count is outside 1..64")
    committed: list[dict[str, Any]] = []
    identifiers: set[str] = set()
    for raw in operations:
        if not isinstance(raw, dict):
            raise OperationAuditError("operation specification rejected")
        operation = _normalized_operation_spec(raw)
        if operation["operation_id"] in identifiers:
            raise OperationAuditError("operation identity rejected")
        identifiers.add(operation["operation_id"])
        committed.append(operation)
    core = {
        "tenant_id": tenant_id,
        "adapter_id": adapter_id,
        "target_node_id": target_node_id,
        "created_at": created_at,
        "operations": committed,
        "controls": {
            "read_only_intent": True,
            "shell": False,
            "raw_argv_retained": True,
            "executable_digest_required": True,
            "credential_values_in_argv_prohibited": True,
            "credential_values_in_argv_preexecution_proven": False,
            "final_credential_custody_audit_required": True,
            "credentials_by_reference": True,
            "environment_policy": "allowlisted-host",
            "automatic_retry_after_unknown": False,
        },
        "production_authority": False,
    }
    manifest = {
        "protocol": "integrity-guardian/readonly-operation-manifest/v1",
        "manifest_id": _identity(
            core,
            prefix="operation-manifest:",
            domain="readonly-operation-manifest-v1",
        ),
        **core,
    }
    validate("readonly-operation-manifest", manifest)
    return manifest


def build_posix_bounded_operation_manifest(
    *,
    tenant_id: str,
    adapter_id: str,
    target_node_id: str,
    created_at: str,
    operations: Sequence[dict[str, Any]],
) -> dict[str, Any]:
    """Build the additive POSIX exact-context grammar without changing v1."""

    if os.name == "nt":
        raise OperationAuditError("POSIX bounded operation manifest requires POSIX")
    validate_tenant_id(tenant_id)
    if _ID.fullmatch(adapter_id) is None or _ID.fullmatch(target_node_id) is None:
        raise OperationAuditError("adapter or target identity rejected")
    if not 1 <= len(operations) <= 64:
        raise OperationAuditError("operation count is outside 1..64")
    committed: list[dict[str, Any]] = []
    identifiers: set[str] = set()
    for raw in operations:
        if not isinstance(raw, dict):
            raise OperationAuditError("POSIX operation specification rejected")
        operation = _normalized_posix_operation_spec(raw)
        if operation["operation_id"] in identifiers:
            raise OperationAuditError("operation identity rejected")
        identifiers.add(operation["operation_id"])
        committed.append(operation)
    core = {
        "tenant_id": tenant_id,
        "adapter_id": adapter_id,
        "target_node_id": target_node_id,
        "created_at": created_at,
        "operations": committed,
        "controls": {
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
            "os_readonly_containment": True,
            "host_filesystem_write_blocked": True,
            "home_hidden": True,
            "automatic_retry_after_unknown": False,
        },
        "production_authority": False,
    }
    manifest = {
        "protocol": "integrity-guardian/readonly-operation-manifest/v3",
        "manifest_id": _identity(
            core,
            prefix="operation-manifest:",
            domain="readonly-operation-manifest-v3",
        ),
        **core,
    }
    validate("readonly-operation-manifest-v3", manifest)
    return manifest


def _normalize_windows_exact_environment(environment: object) -> dict[str, str]:
    if not isinstance(environment, dict) or len(environment) > 32:
        raise OperationAuditError("Windows operation exact environment rejected")
    normalized: dict[str, str] = {}
    casefolded: set[str] = set()
    for name, value in sorted(environment.items(), key=lambda item: str(item[0]).upper()):
        if (
            not isinstance(name, str)
            or _ENVIRONMENT_NAME.fullmatch(name) is None
            or name.upper() in casefolded
            or not isinstance(value, str)
            or len(value) > 4096
            or "\x00" in value
            or "\r" in value
            or "\n" in value
        ):
            raise OperationAuditError("Windows operation exact environment rejected")
        casefolded.add(name.upper())
        normalized[name] = value
    return normalized


def _is_anchored_windows_path(value: str) -> bool:
    path = PureWindowsPath(value)
    return bool(path.drive) and path.is_absolute() and not value.startswith("\\\\")


def build_windows_bounded_operation_manifest(
    *,
    tenant_id: str,
    adapter_id: str,
    target_node_id: str,
    created_at: str,
    operations: Sequence[dict[str, Any]],
) -> dict[str, Any]:
    """Build v2 only on Windows, where executable and directory identity are observable."""

    if os.name != "nt":
        raise OperationAuditError("Windows bounded operation manifest requires Windows")
    validate_tenant_id(tenant_id)
    if _ID.fullmatch(adapter_id) is None or _ID.fullmatch(target_node_id) is None:
        raise OperationAuditError("adapter or target identity rejected")
    if not 1 <= len(operations) <= 64:
        raise OperationAuditError("operation count is outside 1..64")
    committed: list[dict[str, Any]] = []
    identifiers: set[str] = set()
    for raw in operations:
        if not isinstance(raw, dict) or "execution_context" not in raw:
            raise OperationAuditError("Windows operation execution context required")
        context = raw["execution_context"]
        if not isinstance(context, dict) or set(context) != {
            "working_directory",
            "environment",
            "containment",
        }:
            raise OperationAuditError("Windows operation execution context rejected")
        containment = context["containment"]
        if containment != {"kind": WINDOWS_JOB_PROCESS_BOUNDARY_KIND}:
            raise OperationAuditError("Windows operation containment context rejected")
        base = _normalized_operation_spec(
            {key: value for key, value in raw.items() if key != "execution_context"}
        )
        if base["operation_id"] in identifiers:
            raise OperationAuditError("operation identity rejected")
        identifiers.add(base["operation_id"])
        if not _is_anchored_windows_path(base["executable"]):
            raise OperationAuditError("Windows operation executable path rejected")
        working_directory = context["working_directory"]
        if (
            not isinstance(working_directory, str)
            or not _is_anchored_windows_path(working_directory)
        ):
            raise OperationAuditError("Windows operation working directory rejected")
        resolved_working_directory = Path(working_directory).resolve(strict=True)
        if not resolved_working_directory.is_dir():
            raise OperationAuditError("Windows operation working directory rejected")
        environment = _normalize_windows_exact_environment(context["environment"])
        base["execution_context"] = {
            "platform_family": "Windows",
            "working_directory": str(resolved_working_directory),
            "environment": environment,
            "environment_digest": digest_object(
                environment,
                domain="readonly-operation-environment-v2",
            ),
            "containment": windows_job_process_boundary_contract(),
        }
        committed.append(base)
    core = {
        "tenant_id": tenant_id,
        "adapter_id": adapter_id,
        "target_node_id": target_node_id,
        "created_at": created_at,
        "operations": committed,
        "controls": deepcopy(_WINDOWS_BOUNDED_CONTROLS),
        "production_authority": False,
    }
    manifest = {
        "protocol": "integrity-guardian/readonly-operation-manifest/v2",
        "manifest_id": _identity(
            core,
            prefix="operation-manifest:",
            domain="readonly-operation-manifest-v2",
        ),
        **core,
    }
    validate("readonly-operation-manifest-v2", manifest)
    return manifest


def _verify_windows_bounded_operation_manifest(manifest: dict[str, Any]) -> str:
    validate("readonly-operation-manifest-v2", manifest)
    identifiers: set[str] = set()
    for operation in manifest["operations"]:
        operation_id = operation["operation_id"]
        context = operation["execution_context"]
        environment = context["environment"]
        if operation_id in identifiers:
            raise OperationAuditError("operation manifest identity is duplicated")
        identifiers.add(operation_id)
        if (
            operation["argv"][0] != operation["executable"]
            or operation["argument_count"] != len(operation["argv"])
            or operation["argv_digest"]
            != digest_object(operation["argv"], domain="readonly-operation-argv-v1")
            or not _is_anchored_windows_path(operation["executable"])
            or PureWindowsPath(operation["executable"]).suffix.lower() != ".exe"
            or context["platform_family"] != "Windows"
            or not _is_anchored_windows_path(context["working_directory"])
            or context["environment_digest"]
            != digest_object(environment, domain="readonly-operation-environment-v2")
            or context["containment"] != windows_job_process_boundary_contract()
        ):
            raise OperationAuditError("Windows operation manifest binding mismatch")
        _normalize_windows_exact_environment(environment)
    if manifest["controls"] != _WINDOWS_BOUNDED_CONTROLS:
        raise OperationAuditError("Windows operation manifest controls mismatch")
    core = {
        key: value
        for key, value in manifest.items()
        if key not in {"protocol", "manifest_id"}
    }
    expected = _identity(
        core,
        prefix="operation-manifest:",
        domain="readonly-operation-manifest-v2",
    )
    if manifest["manifest_id"] != expected:
        raise OperationAuditError("operation manifest identity mismatch")
    return digest_object(manifest, domain="readonly-operation-manifest-document-v2")


def _verify_posix_bounded_operation_manifest(manifest: dict[str, Any]) -> str:
    validate("readonly-operation-manifest-v3", manifest)
    identifiers: set[str] = set()
    for operation in manifest["operations"]:
        operation_id = operation["operation_id"]
        context = operation["execution_context"]
        containment = context["containment"]
        if operation_id in identifiers:
            raise OperationAuditError("operation manifest identity is duplicated")
        identifiers.add(operation_id)
        if (
            operation["argv"][0] != operation["executable"]
            or operation["argument_count"] != len(operation["argv"])
            or operation["argv_digest"]
            != digest_object(operation["argv"], domain="readonly-operation-argv-v1")
            or not _is_lexical_posix_runtime_path(operation["executable"])
            or not Path(context["working_directory"]).is_absolute()
            or context["environment_digest"]
            != digest_object(
                context["environment"],
                domain="readonly-operation-environment-v3",
            )
            or containment["kind"] != "bubblewrap-readonly-host"
            or not Path(containment["executable"]).is_absolute()
            or containment["network"] is not False
            or containment["host_filesystem_write"] is not False
            or containment["host_filesystem_visibility"] != "runtime-only"
            or containment["home_visible"] is not False
        ):
            raise OperationAuditError("POSIX operation manifest binding mismatch")
    core = {
        key: value
        for key, value in manifest.items()
        if key not in {"protocol", "manifest_id"}
    }
    expected = _identity(
        core,
        prefix="operation-manifest:",
        domain="readonly-operation-manifest-v3",
    )
    if manifest["manifest_id"] != expected:
        raise OperationAuditError("operation manifest identity mismatch")
    return digest_object(manifest, domain="readonly-operation-manifest-document-v3")


def verify_readonly_operation_manifest(manifest: dict[str, Any]) -> str:
    protocol = manifest.get("protocol")
    if protocol == "integrity-guardian/readonly-operation-manifest/v2":
        return _verify_windows_bounded_operation_manifest(manifest)
    if protocol == "integrity-guardian/readonly-operation-manifest/v3":
        return _verify_posix_bounded_operation_manifest(manifest)
    validate("readonly-operation-manifest", manifest)
    identifiers: set[str] = set()
    for operation in manifest["operations"]:
        operation_id = operation["operation_id"]
        if operation_id in identifiers:
            raise OperationAuditError("operation manifest identity is duplicated")
        identifiers.add(operation_id)
        if (
            operation["argv"][0] != operation["executable"]
            or operation["argument_count"] != len(operation["argv"])
            or operation["argv_digest"]
            != digest_object(operation["argv"], domain="readonly-operation-argv-v1")
        ):
            raise OperationAuditError("operation manifest argv binding mismatch")
    core = {
        key: value
        for key, value in manifest.items()
        if key not in {"protocol", "manifest_id"}
    }
    expected = _identity(
        core,
        prefix="operation-manifest:",
        domain="readonly-operation-manifest-v1",
    )
    if manifest["manifest_id"] != expected:
        raise OperationAuditError("operation manifest identity mismatch")
    return digest_object(manifest, domain="readonly-operation-manifest-document-v1")


def _operation_authorization_identity(document: dict[str, Any]) -> str:
    candidate = deepcopy(document)
    candidate.pop("signature", None)
    candidate["authorization_id"] = "operation-authorization:pending"
    return _identity(
        candidate,
        prefix="operation-authorization:",
        domain="readonly-operation-authorization-identity-v1",
    )


def build_readonly_operation_authorization(
    *,
    manifest: dict[str, Any],
    valid_from: str,
    valid_until: str,
    authority_signer: Ed25519Signer,
) -> dict[str, Any]:
    """Sign exact operation scope without claiming that the command is harmless."""

    manifest_digest = verify_readonly_operation_manifest(manifest)
    start = _parse_time(valid_from)
    end = _parse_time(valid_until)
    if not 0 < (end - start).total_seconds() <= _MAXIMUM_AUTHORIZATION_SECONDS:
        raise OperationAuditError("operation authorization validity is outside the safe bound")
    unsigned = {
        "protocol": "integrity-guardian/readonly-operation-authorization/v1",
        "authorization_id": "operation-authorization:pending",
        "manifest_id": manifest["manifest_id"],
        "manifest_digest": manifest_digest,
        "tenant_id": manifest["tenant_id"],
        "adapter_id": manifest["adapter_id"],
        "target_node_id": manifest["target_node_id"],
        "operation_ids": [item["operation_id"] for item in manifest["operations"]],
        "authority_id": authority_signer.key_id,
        "authority_key_fingerprint": public_key_fingerprint(
            authority_signer.public_key
        ),
        "valid_from": valid_from,
        "valid_until": valid_until,
        "read_only_intent_only": True,
        "max_executions": 1,
        "production_authority": False,
    }
    unsigned["authorization_id"] = _operation_authorization_identity(unsigned)
    authorization = authority_signer.sign(unsigned)
    validate("readonly-operation-authorization", authorization)
    return authorization


def verify_readonly_operation_authorization(
    authorization: dict[str, Any],
    *,
    manifest: dict[str, Any],
    authority_key: TrustedKey,
    at_time: str,
) -> dict[str, Any]:
    """Verify signature, exact manifest scope, trust root and active time window."""

    try:
        candidate = deepcopy(authorization)
        validate("readonly-operation-authorization", candidate)
        manifest_digest = verify_readonly_operation_manifest(manifest)
    except Exception as exc:
        raise OperationAuditError("operation authorization schema or manifest rejected") from exc
    expected_fingerprint = public_key_fingerprint(authority_key.public_key)
    if (
        candidate["authority_id"] != authority_key.key_id
        or candidate["signature"]["key_id"] != authority_key.key_id
        or candidate["authority_key_fingerprint"] != expected_fingerprint
        or not verify_signature(candidate, authority_key.public_key)
    ):
        raise OperationAuditError("operation authority signature rejected")
    if candidate["authorization_id"] != _operation_authorization_identity(candidate):
        raise OperationAuditError("operation authorization identity mismatch")
    expected_scope = {
        "manifest_id": manifest["manifest_id"],
        "manifest_digest": manifest_digest,
        "tenant_id": manifest["tenant_id"],
        "adapter_id": manifest["adapter_id"],
        "target_node_id": manifest["target_node_id"],
        "operation_ids": [item["operation_id"] for item in manifest["operations"]],
    }
    if any(candidate[key] != value for key, value in expected_scope.items()):
        raise OperationAuditError("operation authorization scope mismatch")
    start = _parse_time(candidate["valid_from"])
    end = _parse_time(candidate["valid_until"])
    current = _parse_time(at_time)
    if (
        not 0 < (end - start).total_seconds() <= _MAXIMUM_AUTHORIZATION_SECONDS
        or not start <= current < end
    ):
        raise OperationAuditError("operation authorization is not active")
    return {
        "authorization_id": candidate["authorization_id"],
        "manifest_id": candidate["manifest_id"],
        "manifest_digest": candidate["manifest_digest"],
        "authority_key_fingerprint": expected_fingerprint,
        "operation_count": len(candidate["operation_ids"]),
        "production_authority": False,
    }


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise OperationAuditError("operation result timestamp rejected")
    return parsed


def _validate_result(result: dict[str, Any]) -> None:
    required = {
        "operation_id",
        "outcome",
        "started_at",
        "finished_at",
        "exit_code",
        "stdout_digest",
        "stderr_digest",
        "stdout_byte_count",
        "stderr_byte_count",
        "stdout_artifact",
        "stderr_artifact",
        "reason_code",
        "automatic_retry_allowed",
    }
    if set(result) != required:
        raise OperationAuditError("operation result field set rejected")
    outcome = result["outcome"]
    started = result["started_at"]
    finished = result["finished_at"]
    exit_code = result["exit_code"]
    retry = result["automatic_retry_allowed"]
    artifacts = (
        result["stdout_digest"],
        result["stderr_digest"],
        result["stdout_byte_count"],
        result["stderr_byte_count"],
        result["stdout_artifact"],
        result["stderr_artifact"],
    )
    if started is not None and finished is not None and _parse_time(finished) < _parse_time(started):
        raise OperationAuditError("operation result timestamp order rejected")
    if outcome == "not-started":
        valid = (
            started is None
            and finished is None
            and exit_code is None
            and all(value is None for value in artifacts)
            and result["reason_code"]
            in {
                "preflight-rejected",
                "spawn-rejected",
                "prior-operation-not-successful",
            }
            and retry is True
        )
    elif outcome == "confirmed-success":
        valid = (
            started is not None
            and finished is not None
            and exit_code == 0
            and all(value is not None for value in artifacts)
            and result["reason_code"] == "completed-exit-zero"
            and retry is False
        )
    elif outcome == "confirmed-failure":
        valid = (
            started is not None
            and finished is not None
            and isinstance(exit_code, int)
            and not isinstance(exit_code, bool)
            and exit_code != 0
            and all(value is not None for value in artifacts)
            and result["reason_code"] == "completed-nonzero"
            and retry is False
        )
    elif outcome == "unknown-outcome":
        valid = (
            started is not None
            and finished is not None
            and exit_code is None
            and all(value is not None for value in artifacts)
            and result["reason_code"]
            in {"timeout", "output-bound-exceeded", "interrupted"}
            and retry is False
        )
    else:
        valid = False
    if not valid:
        raise OperationAuditError("operation outcome semantics rejected")
    for digest in (result["stdout_digest"], result["stderr_digest"]):
        if digest is not None and _DIGEST.fullmatch(digest) is None:
            raise OperationAuditError("operation output digest rejected")


def _outcome_counts(results: Sequence[dict[str, Any]]) -> dict[str, int]:
    return {
        outcome: sum(result["outcome"] == outcome for result in results)
        for outcome in _OUTCOMES
    }


def build_readonly_operation_receipt(
    *,
    manifest: dict[str, Any],
    results: Sequence[dict[str, Any]],
    observed_at: str,
) -> dict[str, Any]:
    manifest_digest = verify_readonly_operation_manifest(manifest)
    expected_ids = [item["operation_id"] for item in manifest["operations"]]
    if [item.get("operation_id") for item in results] != expected_ids:
        raise OperationAuditError("operation receipt coverage or order mismatch")
    normalized = [dict(item) for item in results]
    for result in normalized:
        _validate_result(result)
    counts = _outcome_counts(normalized)
    all_success = counts["confirmed-success"] == len(normalized)
    core = {
        "manifest_id": manifest["manifest_id"],
        "manifest_digest": manifest_digest,
        "status": "PASS" if all_success else "FAIL",
        "observed_at": observed_at,
        "operations": normalized,
        "outcome_counts": counts,
        "unknown_outcome_count": counts["unknown-outcome"],
        "all_operations_confirmed_success": all_success,
        "complete_operation_coverage": True,
        "production_authority": False,
    }
    receipt = {
        "protocol": "integrity-guardian/readonly-operation-receipt/v1",
        "receipt_id": _identity(
            core,
            prefix="operation-receipt:",
            domain="readonly-operation-receipt-v1",
        ),
        **core,
    }
    validate("readonly-operation-receipt", receipt)
    return receipt


def verify_readonly_operation_receipt(
    receipt: dict[str, Any],
    *,
    manifest: dict[str, Any],
) -> dict[str, Any]:
    validate("readonly-operation-receipt", receipt)
    manifest_digest = verify_readonly_operation_manifest(manifest)
    if (
        receipt["manifest_id"] != manifest["manifest_id"]
        or receipt["manifest_digest"] != manifest_digest
    ):
        raise OperationAuditError("operation receipt manifest binding mismatch")
    expected_ids = [item["operation_id"] for item in manifest["operations"]]
    if [item["operation_id"] for item in receipt["operations"]] != expected_ids:
        raise OperationAuditError("operation receipt coverage or order mismatch")
    for result in receipt["operations"]:
        _validate_result(result)
    counts = _outcome_counts(receipt["operations"])
    all_success = counts["confirmed-success"] == len(expected_ids)
    if (
        receipt["outcome_counts"] != counts
        or receipt["unknown_outcome_count"] != counts["unknown-outcome"]
        or receipt["all_operations_confirmed_success"] is not all_success
        or receipt["status"] != ("PASS" if all_success else "FAIL")
    ):
        raise OperationAuditError("operation receipt outcome summary mismatch")
    core = {key: value for key, value in receipt.items() if key not in {"protocol", "receipt_id"}}
    expected = _identity(
        core,
        prefix="operation-receipt:",
        domain="readonly-operation-receipt-v1",
    )
    if receipt["receipt_id"] != expected:
        raise OperationAuditError("operation receipt identity mismatch")
    return {
        "status": receipt["status"],
        "manifest_id": manifest["manifest_id"],
        "operation_count": len(expected_ids),
        "outcome_counts": counts,
        "unknown_outcome_count": counts["unknown-outcome"],
        "all_operations_confirmed_success": all_success,
        "production_authority": False,
    }


class _BoundedCapture:
    def __init__(self, maximum: int) -> None:
        self.maximum = maximum
        self.payload = bytearray()
        self.exceeded = threading.Event()

    def read(self, stream: Any) -> None:
        try:
            while chunk := stream.read(64 * 1024):
                remaining = self.maximum - len(self.payload)
                if remaining > 0:
                    self.payload.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    self.exceeded.set()
        finally:
            stream.close()


def _operation_environment(operation: dict[str, Any]) -> dict[str, str]:
    context = operation.get("execution_context")
    if context is not None:
        environment = dict(context["environment"])
        domain = (
            "readonly-operation-environment-v2"
            if context["containment"]["kind"] == WINDOWS_JOB_PROCESS_BOUNDARY_KIND
            else "readonly-operation-environment-v3"
        )
        if context["environment_digest"] != digest_object(
            environment,
            domain=domain,
        ):
            raise OperationAuditError("operation exact environment digest mismatch")
        return environment
    return {
        key: os.environ[key]
        for key in _ALLOWED_ENVIRONMENT
        if key in os.environ
    }


def _contained_argv(operation: dict[str, Any]) -> tuple[list[str], str | None]:
    context = operation.get("execution_context")
    if context is None:
        return list(operation["argv"]), None
    containment = context["containment"]
    executable = Path(containment["executable"])
    if (
        containment
        != {
            "kind": "bubblewrap-readonly-host",
            "executable": str(executable),
            "executable_digest": containment["executable_digest"],
            "network": False,
            "host_filesystem_write": False,
            "host_filesystem_visibility": "runtime-only",
            "home_visible": False,
        }
        or _digest_executable(executable) != containment["executable_digest"]
        or os.name != "posix"
    ):
        raise OperationAuditError("operation containment preflight rejected")
    argv = [
        str(executable),
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "--tmpfs",
        "/tmp",
    ]
    for runtime_root in ("/usr", "/lib", "/lib64"):
        if Path(runtime_root).exists():
            argv.extend(["--ro-bind", runtime_root, runtime_root])
    for private_directory in ("/home", "/root", "/run", "/run/user"):
        argv.extend(["--dir", private_directory])
    argv.extend(["--clearenv"])
    for name, value in context["environment"].items():
        argv.extend(["--setenv", name, value])
    argv.extend(
        [
            "--chdir",
            context["working_directory"],
            "--",
            *operation["argv"],
        ]
    )
    return argv, None


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    if os.name != "posix":
        raise OperationAuditError("POSIX process-group termination used off platform")
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        pass


def _runtime_os_name() -> str:
    return os.name


def _run_windows_job_with_held_identity(
    operation: dict[str, Any],
    *,
    working_directory: str,
    environment: dict[str, str],
) -> tuple[int, bytes, bytes]:
    from ._windows_files import (
        HeldWindowsDirectory,
        HeldWindowsFile,
        WindowsFileBoundaryError,
    )
    from ._windows_job import WindowsJobPreflightError, run_windows_job

    try:
        with (
            HeldWindowsDirectory(Path(working_directory)),
            HeldWindowsFile(
                Path(operation["executable"]),
                maximum_bytes=_MAXIMUM_EXECUTABLE_BYTES,
            ) as executable,
        ):
            if "sha256:" + executable.sha256() != operation["executable_digest"]:
                raise WindowsJobPreflightError(
                    "operation executable digest changed before process creation"
                )
            return run_windows_job(
                str(executable.path),
                tuple(operation["argv"][1:]),
                working_directory=working_directory,
                environment=environment,
                timeout_seconds=operation["timeout_seconds"],
                maximum_output_bytes=operation["max_output_bytes"],
            )
    except WindowsFileBoundaryError as exc:
        raise WindowsJobPreflightError(
            "operation Windows path identity preflight rejected"
        ) from exc


def _run_committed_operation_windows(
    operation: dict[str, Any],
    *,
    evidence_directory: Path,
) -> dict[str, Any]:
    """Run only through the existing suspended Win32 Job Object boundary."""

    from ._windows_job import (
        WindowsJobBoundaryError,
        WindowsJobOutputBoundError,
        WindowsJobPostStartError,
        WindowsJobPreflightError,
        WindowsJobTimeoutError,
    )

    started_at = _utc_now()
    context = operation.get("execution_context")
    working_directory = (
        context["working_directory"] if context is not None else str(evidence_directory)
    )
    try:
        return_code, stdout_payload, stderr_payload = _run_windows_job_with_held_identity(
            operation,
            working_directory=working_directory,
            environment=_operation_environment(operation),
        )
    except WindowsJobPreflightError:
        return _not_started(operation["operation_id"], "preflight-rejected")
    except (
        WindowsJobTimeoutError,
        WindowsJobOutputBoundError,
        WindowsJobPostStartError,
    ) as exc:
        stdout_payload = b""
        stderr_payload = b""
        if isinstance(exc, WindowsJobTimeoutError):
            reason_code = "timeout"
        elif isinstance(exc, WindowsJobOutputBoundError):
            reason_code = "output-bound-exceeded"
        else:
            reason_code = "interrupted"
        return_code = None
    except WindowsJobBoundaryError:
        return _not_started(operation["operation_id"], "spawn-rejected")
    stdout_name = _artifact_name(operation["operation_id"], "stdout")
    stderr_name = _artifact_name(operation["operation_id"], "stderr")
    _write_output_artifact(evidence_directory, stdout_name, stdout_payload)
    _write_output_artifact(evidence_directory, stderr_name, stderr_payload)
    finished_at = _utc_now()
    if return_code is None:
        outcome = "unknown-outcome"
        exit_code = None
    elif return_code == 0:
        outcome = "confirmed-success"
        exit_code = 0
        reason_code = "completed-exit-zero"
    else:
        outcome = "confirmed-failure"
        exit_code = return_code
        reason_code = "completed-nonzero"
    return {
        "operation_id": operation["operation_id"],
        "outcome": outcome,
        "started_at": started_at,
        "finished_at": finished_at,
        "exit_code": exit_code,
        "stdout_digest": "sha256:" + hashlib.sha256(stdout_payload).hexdigest(),
        "stderr_digest": "sha256:" + hashlib.sha256(stderr_payload).hexdigest(),
        "stdout_byte_count": len(stdout_payload),
        "stderr_byte_count": len(stderr_payload),
        "stdout_artifact": stdout_name,
        "stderr_artifact": stderr_name,
        "reason_code": reason_code,
        "automatic_retry_allowed": False,
    }


def _artifact_name(operation_id: str, stream: str) -> str:
    safe = _ARTIFACT_SAFE.sub("_", operation_id).strip("._-") or "operation"
    identity = hashlib.sha256(operation_id.encode("utf-8")).hexdigest()
    return f"{safe[:64]}.{identity}.{stream}.bin"


def _write_output_artifact(directory: Path, name: str, payload: bytes) -> str:
    from .local_machine import _write_private

    _write_private(directory / name, payload)
    return name


def _not_started(operation_id: str, reason: str) -> dict[str, Any]:
    return {
        "operation_id": operation_id,
        "outcome": "not-started",
        "started_at": None,
        "finished_at": None,
        "exit_code": None,
        "stdout_digest": None,
        "stderr_digest": None,
        "stdout_byte_count": None,
        "stderr_byte_count": None,
        "stdout_artifact": None,
        "stderr_artifact": None,
        "reason_code": reason,
        "automatic_retry_allowed": True,
    }


def _run_committed_operation(
    operation: dict[str, Any],
    *,
    evidence_directory: Path,
) -> dict[str, Any]:
    try:
        context = operation.get("execution_context")
        if (
            context is not None
            and context["containment"]["kind"] == "bubblewrap-readonly-host"
            and not _is_live_posix_runtime_executable(operation["executable"])
        ):
            return _not_started(operation["operation_id"], "preflight-rejected")
        if (
            digest_object(operation["argv"], domain="readonly-operation-argv-v1")
            != operation["argv_digest"]
            or _digest_executable(Path(operation["executable"]))
            != operation["executable_digest"]
        ):
            return _not_started(operation["operation_id"], "preflight-rejected")
        containment_kind = (
            context["containment"]["kind"] if context is not None else None
        )
        environment = _operation_environment(operation)
        if containment_kind == WINDOWS_JOB_PROCESS_BOUNDARY_KIND:
            if _runtime_os_name() != "nt":
                return _not_started(operation["operation_id"], "preflight-rejected")
            return _run_committed_operation_windows(
                operation,
                evidence_directory=evidence_directory,
            )
        if _runtime_os_name() == "nt":
            if context is not None:
                return _not_started(operation["operation_id"], "preflight-rejected")
            return _run_committed_operation_windows(
                operation,
                evidence_directory=evidence_directory,
            )
        working_directory = None
        if context is not None:
            candidate = Path(context["working_directory"])
            resolved = candidate.resolve(strict=True)
            if (
                candidate.is_symlink()
                or not resolved.is_dir()
                or str(resolved) != str(candidate)
            ):
                return _not_started(operation["operation_id"], "preflight-rejected")
            working_directory = str(resolved)
        argv, process_working_directory = _contained_argv(operation)
    except (OperationAuditError, OSError):
        return _not_started(operation["operation_id"], "preflight-rejected")
    creationflags = 0
    start_new_session = False
    if os.name == "posix":
        start_new_session = True
    started_at = _utc_now()
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            cwd=process_working_directory if context is not None else working_directory,
            env=environment,
            close_fds=True,
            creationflags=creationflags,
            start_new_session=start_new_session,
        )
    except OSError:
        return _not_started(operation["operation_id"], "spawn-rejected")
    assert process.stdout is not None and process.stderr is not None
    stdout = _BoundedCapture(operation["max_output_bytes"])
    stderr = _BoundedCapture(operation["max_output_bytes"])
    threads = (
        threading.Thread(target=stdout.read, args=(process.stdout,), daemon=True),
        threading.Thread(target=stderr.read, args=(process.stderr,), daemon=True),
    )
    for thread in threads:
        thread.start()
    reason: str | None = None
    deadline = time.monotonic() + operation["timeout_seconds"]
    try:
        while process.poll() is None:
            if stdout.exceeded.is_set() or stderr.exceeded.is_set():
                reason = "output-bound-exceeded"
                _terminate_process(process)
                break
            if time.monotonic() >= deadline:
                reason = "timeout"
                _terminate_process(process)
                break
            time.sleep(0.02)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            reason = reason or "interrupted"
            _terminate_process(process)
            process.wait(timeout=5)
    except BaseException:  # noqa: BLE001 - every caller interruption must reap the child
        reason = "interrupted"
        _terminate_process(process)
        process.wait(timeout=5)
    for thread in threads:
        thread.join(timeout=5)
    if any(thread.is_alive() for thread in threads):
        reason = reason or "interrupted"
    if stdout.exceeded.is_set() or stderr.exceeded.is_set():
        reason = "output-bound-exceeded"
    stdout_payload = bytes(stdout.payload)
    stderr_payload = bytes(stderr.payload)
    stdout_name = _artifact_name(operation["operation_id"], "stdout")
    stderr_name = _artifact_name(operation["operation_id"], "stderr")
    _write_output_artifact(evidence_directory, stdout_name, stdout_payload)
    _write_output_artifact(evidence_directory, stderr_name, stderr_payload)
    finished_at = _utc_now()
    if reason is not None:
        outcome = "unknown-outcome"
        exit_code = None
        reason_code = reason
    elif process.returncode == 0:
        outcome = "confirmed-success"
        exit_code = 0
        reason_code = "completed-exit-zero"
    else:
        outcome = "confirmed-failure"
        exit_code = process.returncode
        reason_code = "completed-nonzero"
    return {
        "operation_id": operation["operation_id"],
        "outcome": outcome,
        "started_at": started_at,
        "finished_at": finished_at,
        "exit_code": exit_code,
        "stdout_digest": "sha256:" + hashlib.sha256(stdout_payload).hexdigest(),
        "stderr_digest": "sha256:" + hashlib.sha256(stderr_payload).hexdigest(),
        "stdout_byte_count": len(stdout_payload),
        "stderr_byte_count": len(stderr_payload),
        "stdout_artifact": stdout_name,
        "stderr_artifact": stderr_name,
        "reason_code": reason_code,
        "automatic_retry_allowed": outcome == "not-started",
    }


def execute_readonly_operation_manifest(
    manifest: dict[str, Any],
    *,
    authorization: dict[str, Any],
    authority_key: TrustedKey,
    at_time: str,
    evidence_directory: Path,
    observed_at: str | None = None,
) -> dict[str, Any]:
    """Run an exact manifest once and return a receipt for every committed item."""

    verify_readonly_operation_authorization(
        authorization,
        manifest=manifest,
        authority_key=authority_key,
        at_time=at_time,
    )
    target = evidence_directory.absolute()
    if target.exists() and (not target.is_dir() or any(target.iterdir())):
        raise OperationAuditError("operation evidence directory must be absent or empty")
    if os.name == "nt":
        from ._windows_files import create_private_directory_tree

        create_private_directory_tree(target)
    else:
        target.mkdir(mode=0o700, parents=True, exist_ok=True)
        target.chmod(0o700)
    results: list[dict[str, Any]] = []
    stopped = False
    for operation in manifest["operations"]:
        if stopped:
            result = _not_started(
                operation["operation_id"],
                "prior-operation-not-successful",
            )
        else:
            result = _run_committed_operation(operation, evidence_directory=target)
        results.append(result)
        stopped = result["outcome"] != "confirmed-success"
    return build_readonly_operation_receipt(
        manifest=manifest,
        results=results,
        observed_at=observed_at or _utc_now(),
    )


def verify_readonly_operation_evidence(
    receipt: dict[str, Any],
    *,
    evidence_directory: Path,
) -> dict[str, Any]:
    """Re-read every retained stream and bind its bytes to the operation receipt."""

    from .local_machine import _read_private

    root = evidence_directory.absolute()
    checked = 0
    for result in receipt["operations"]:
        if result["outcome"] == "not-started":
            continue
        for stream in ("stdout", "stderr"):
            name = result[f"{stream}_artifact"]
            if Path(name).name != name:
                raise OperationAuditError("operation evidence artifact path rejected")
            payload = _read_private(root / name, maximum_bytes=4 * 1024 * 1024)
            if (
                len(payload) != result[f"{stream}_byte_count"]
                or "sha256:" + hashlib.sha256(payload).hexdigest()
                != result[f"{stream}_digest"]
            ):
                raise OperationAuditError("operation evidence artifact mismatch")
            checked += 1
    return {
        "status": "PASS",
        "artifact_count": checked,
        "production_authority": False,
    }


def write_operation_document(path: Path, document: dict[str, Any], *, schema: str) -> Path:
    validate(schema, document)
    from .local_machine import _write_private

    return _write_private(path, canonical_bytes(document) + b"\n")


def load_operation_document(path: Path, *, schema: str) -> dict[str, Any]:
    from .local_machine import _read_private

    payload = _read_private(path, maximum_bytes=4 * 1024 * 1024)
    value = parse_json_strict(payload)
    if (
        not isinstance(value, dict)
        or canonical_bytes(value) + b"\n" != payload
    ):
        raise OperationAuditError("operation document is not canonical")
    validate(schema, value)
    return value


__all__ = [
    "READONLY_OPERATION_RECEIPT_ARTIFACT",
    "WINDOWS_JOB_PROCESS_BOUNDARY_KIND",
    "OperationAuditError",
    "build_posix_bounded_operation_manifest",
    "build_readonly_operation_authorization",
    "build_readonly_operation_manifest",
    "build_readonly_operation_receipt",
    "build_windows_bounded_operation_manifest",
    "execute_readonly_operation_manifest",
    "load_operation_document",
    "verify_readonly_operation_authorization",
    "verify_readonly_operation_evidence",
    "verify_readonly_operation_manifest",
    "verify_readonly_operation_receipt",
    "windows_job_process_boundary_contract",
    "write_operation_document",
]
