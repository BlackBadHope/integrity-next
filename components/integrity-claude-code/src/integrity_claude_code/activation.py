"""Activation contract for the native CLI profile (default deny).

A policy may pin ``cli_activation_sha256``, but a digest is only a pointer. A launch
also needs ``verify_activation`` to succeed on the RETAINED artifact directory:

* ``activation.json`` (strict JSON, bounded) whose digest equals the policy pin and
  which binds the exact binary (path/sha256/version), the CLI help digest, the profile
  document, the policy core digest, the model and the expected init auth source;
* every required live observation recorded as true (these are the J checks);
* every listed evidence artifact present in the directory with matching size/digest;
* host acceptance verified through the PUBLIC SDK: the acceptance envelope must verify
  with an operation payload bound to this exact activation document, and a signed
  transition receipt for that envelope must verify with outcome ``confirmed-success``.

No such artifact exists yet: on this base the exact SDK is unavailable, so even a
well-formed artifact is refused. Nothing here fabricates or signs evidence.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import authority as _authority
from .authority import payload_expectation
from .canonical import (Rejected, canonical_bytes, digest_object, digest_value, identifier, need,
                        sha256_bytes, strict_loads)
from .identity import require_plain_path
from .policy import CLI_HELP_SHA256, ExecutorPolicy, cli_profile_document

ACTIVATION_SCHEMA = "integrity-claude-code/cli-activation/v1"
ACTIVATION_SCHEMA_DOCUMENT = {"schema_id": ACTIVATION_SCHEMA, "required_observations": None}
REQUIRED_OBSERVATIONS = (
    "help_digest_matches", "auth_status_subscription", "init_tools_exact", "init_mcp_exact",
    "init_permission_mode_dont_ask", "init_model_exact", "init_version_exact",
    "init_api_key_source_expected", "builtin_tool_unavailable", "uncataloged_tool_killed",
    "managed_sources_pinned", "server_managed_settings_absent", "hooks_not_executed",
    "claude_md_effect_reviewed")
ACTIVATION_SCHEMA_DOCUMENT["required_observations"] = list(REQUIRED_OBSERVATIONS)
MAX_ACTIVATION_BYTES = 64 * 1024
MAX_ARTIFACTS = 64
MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
MAX_TOTAL_ARTIFACT_BYTES = 128 * 1024 * 1024
_ISSUER = object()


@dataclass(frozen=True)
class ActivationAcceptance:
    """Host-supplied genuine SDK acceptance evidence (never built here)."""
    envelope: Any
    verification: dict        # verify_adapter_execution_envelope kwargs except used_at
    used_at: str
    receipt: Any
    receipt_key: Any
    executor_key: Any = None


@dataclass(frozen=True)
class VerifiedActivation:
    document_sha256: str
    host_id: str
    executable_path: str
    executable_sha256: str
    executable_version: str
    profile_sha256: str
    policy_core_sha256: str
    model: str
    _issuer: object = field(repr=False, compare=False, default=None)

    def matches(self, policy: ExecutorPolicy, descriptor: dict) -> bool:
        return (self._issuer is _ISSUER
                and self.document_sha256 == policy.cli_activation_sha256
                and self.policy_core_sha256 == policy.core_digest()
                and self.profile_sha256 == profile_digest()
                and self.model == descriptor["model"] == policy.model
                and self.host_id == descriptor["host_id"]
                and self.executable_path == descriptor["executable"]["path"]
                and self.executable_sha256 == descriptor["executable"]["sha256"]
                and self.executable_version == descriptor["executable"]["version"])


def profile_digest() -> str:
    return digest_object("integrity-claude-code-cli-profile-v1", cli_profile_document())


def _document(directory: Path, policy: ExecutorPolicy) -> tuple[dict, str]:
    path = require_plain_path(Path(directory) / "activation.json", "activation")
    need(path.is_file() and path.stat().st_size <= MAX_ACTIVATION_BYTES, "activation_file")
    raw = path.read_bytes()
    document = strict_loads(raw, MAX_ACTIVATION_BYTES)
    digest = sha256_bytes(canonical_bytes(document))
    need(policy.cli_activation_sha256 is not None and digest == policy.cli_activation_sha256,
         "activation_pin_mismatch")
    return document, digest


def _check_document(document: dict, directory: Path, policy: ExecutorPolicy, executable: dict) -> None:
    need(type(document) is dict and set(document) == {
        "schema", "host_id", "binary", "cli_help_sha256", "profile_sha256", "policy_core_sha256",
        "model", "expected_api_key_source", "observations", "artifacts", "observed_at"},
        "activation_shape")
    need(document["schema"] == ACTIVATION_SCHEMA, "activation_schema")
    identifier(document["host_id"], "activation_host")
    need(document["binary"] == {"path": executable["path"], "sha256": executable["sha256"],
                                "version": executable["version"]}, "activation_binary")
    need(document["cli_help_sha256"] == CLI_HELP_SHA256, "activation_help")
    need(document["profile_sha256"] == profile_digest(), "activation_profile")
    need(document["policy_core_sha256"] == policy.core_digest(), "activation_policy")
    need(document["model"] == policy.model, "activation_model")
    need(policy.expected_api_key_source is not None
         and document["expected_api_key_source"] == policy.expected_api_key_source,
         "activation_auth_source")
    observations = document["observations"]
    need(type(observations) is dict and set(observations) == set(REQUIRED_OBSERVATIONS)
         and all(value is True for value in observations.values()), "activation_observations")
    artifacts = document["artifacts"]
    need(type(artifacts) is list and 0 < len(artifacts) <= MAX_ARTIFACTS, "activation_artifacts")
    names = [a.get("name") for a in artifacts if type(a) is dict]
    need(len(names) == len(artifacts) and len({str(n).lower() for n in names}) == len(names),
         "activation_artifact_duplicate")
    need(all(type(a.get("bytes")) is int and 0 < a["bytes"] <= MAX_ARTIFACT_BYTES for a in artifacts)
         and sum(a["bytes"] for a in artifacts) <= MAX_TOTAL_ARTIFACT_BYTES, "activation_artifact_bounds")
    for artifact in artifacts:
        need(type(artifact) is dict and set(artifact) == {"name", "sha256", "bytes"}, "activation_artifact")
        name = artifact["name"]
        need(type(name) is str and name not in ("activation.json", "", ".", "..")
             and "/" not in name and "\\" not in name and ":" not in name, "activation_artifact_name")
        digest_value(artifact["sha256"], "activation_artifact_digest")
        path = require_plain_path(Path(directory) / name, "activation_artifact")
        need(path.is_file() and path.stat().st_size == artifact["bytes"], "activation_artifact_missing")
        # size checked against the declared bound before any read/allocation
        need(sha256_bytes(path.read_bytes()) == artifact["sha256"], "activation_artifact_digest")


def verify_activation(directory: Path, *, policy: ExecutorPolicy, executable: dict,
                      acceptance: ActivationAcceptance) -> VerifiedActivation:
    """Default deny. ``executable`` is identity.executable_identity(...) plus 'version'."""
    need(isinstance(policy, ExecutorPolicy), "policy_type")
    need(type(acceptance) is ActivationAcceptance, "activation_acceptance")
    document, digest = _document(directory, policy)
    _check_document(document, directory, policy, executable)
    sdk = _authority._load_sdk()  # exact SDK or refusal
    context = {key: (strict_loads(canonical_bytes(value)) if key in (
        "manifest", "proposal", "operation_binding", "operation_manifest") else value)
        for key, value in dict(acceptance.verification).items()}
    need("used_at" not in context, "activation_acceptance_shape")
    expected = payload_expectation(ACTIVATION_SCHEMA, canonical_bytes(ACTIVATION_SCHEMA_DOCUMENT), document)
    need(type(context.get("operation_manifest")) is dict
         and context["operation_manifest"].get("payload") == expected, "activation_payload_mismatch")
    envelope = strict_loads(canonical_bytes(acceptance.envelope))
    try:
        verified = sdk.adapter_sdk.verify_adapter_execution_envelope(envelope, **context,
                                                                     used_at=acceptance.used_at)
        receipt = sdk.adapter_sdk.verify_adapter_transition_receipt(
            acceptance.receipt, receipt_key=acceptance.receipt_key, executor_key=acceptance.executor_key)
    except Exception:
        raise Rejected("activation_acceptance_rejected") from None
    need(receipt["envelope"] == {"envelope_id": verified["envelope_id"],
                                 "envelope_digest": sdk.adapter_sdk.adapter_execution_envelope_digest(verified)},
         "activation_receipt_binding")
    need(receipt["result"]["outcome"] == "confirmed-success", "activation_not_confirmed")
    return VerifiedActivation(document_sha256=digest, host_id=document["host_id"],
                              executable_path=executable["path"], executable_sha256=executable["sha256"],
                              executable_version=executable["version"], profile_sha256=profile_digest(),
                              policy_core_sha256=policy.core_digest(), model=policy.model,
                              _issuer=_ISSUER)
