"""Crash-durable, no-replay runtime primitives for contained SDK adapters."""

from __future__ import annotations

import os
import re
import sqlite3
import sys
from collections.abc import Mapping, Sequence
from contextlib import AbstractContextManager
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Self

from jsonschema import ValidationError

from .adapter_conformance import (
    AdapterConformanceError,
    adapter_conformance_receipt_digest,
    require_adapter_conformance_readiness,
    verify_adapter_conformance_receipt,
)
from .adapter_sdk import (
    ADAPTER_SDK_VERSION,
    AdapterReportedOutcome,
    AdapterSdkError,
    AdapterTransitionOutcome,
    VerifiedAdapterGrant,
    VerifiedAdapterWitness,
    adapter_execution_envelope_digest,
    adapter_operation_binding_digest,
    adapter_transition_receipt_digest,
    build_adapter_transition_receipt,
    verify_adapter_capability_manifest,
    verify_adapter_transition_receipt,
)
from .agent_handoff_custody import (
    AgentHandoffCustodyError,
    open_private_sqlite_connection,
)
from .hashing import digest_object
from .ledger import (
    LedgerError,
    LedgerStore,
    build_ledger_event,
    event_digest,
    verify_ledger_event,
    verify_ledger_inclusion_proof,
)
from .operation_audit import (
    READONLY_OPERATION_RECEIPT_ARTIFACT,
    OperationAuditError,
    execute_readonly_operation_manifest,
    verify_readonly_operation_authorization,
    verify_readonly_operation_evidence,
    verify_readonly_operation_manifest,
    verify_readonly_operation_receipt,
    write_operation_document,
)
from .schemas import validate
from .signing import (
    Ed25519Signer,
    TrustedKey,
    public_key_fingerprint,
    verify_signature,
)

_PHASES = (
    "adapter-attempt-prepared",
    "adapter-attempt-dispatching",
    "adapter-attempt-executor-returned",
    "adapter-attempt-witnessed",
)
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")


class AdapterRuntimeError(AdapterSdkError):
    """Raised before an attempt can be replayed or overstated."""


def _signed_identity(document: Mapping[str, Any], *, field: str, domain: str) -> str:
    core = deepcopy(dict(document))
    core.pop(field, None)
    core.pop("signature", None)
    suffix = digest_object(core, domain=domain).split(":", 1)[1]
    prefix = (
        "adapter-operation-binding"
        if field == "binding_id"
        else field.removesuffix("_id").replace("_", "-")
    )
    return f"{prefix}:{suffix}"


def _verify_envelope_signature(
    envelope: Mapping[str, Any],
    *,
    coordinator_key: TrustedKey,
) -> dict[str, Any]:
    candidate = deepcopy(dict(envelope))
    try:
        validate("adapter-execution-envelope", candidate)
    except Exception as exc:
        raise AdapterRuntimeError("adapter runtime envelope schema rejected") from exc
    if candidate["envelope_id"] != _signed_identity(
        candidate,
        field="envelope_id",
        domain="adapter-execution-envelope-identity-v1",
    ):
        raise AdapterRuntimeError("adapter runtime envelope identity mismatch")
    if (
        candidate["signer_id"] != coordinator_key.key_id
        or candidate["signature"]["key_id"] != coordinator_key.key_id
        or not verify_signature(candidate, coordinator_key.public_key)
    ):
        raise AdapterRuntimeError("adapter runtime envelope signature rejected")
    if candidate["controls"] != {
        "max_invocations": 1,
        "action_replay_allowed": False,
        "route_continuation_allowed": False,
        "automatic_retry_after_unknown": False,
        "memory_write": False,
        "production_authority": False,
    }:
        raise AdapterRuntimeError("adapter runtime envelope controls rejected")
    return candidate


def _verify_operation_binding_signature(
    binding: Mapping[str, Any],
    *,
    coordinator_key: TrustedKey,
) -> dict[str, Any]:
    candidate = deepcopy(dict(binding))
    try:
        validate("adapter-operation-binding", candidate)
    except Exception as exc:
        raise AdapterRuntimeError("adapter runtime operation binding schema rejected") from exc
    if candidate["binding_id"] != _signed_identity(
        candidate,
        field="binding_id",
        domain="adapter-operation-binding-identity-v1",
    ):
        raise AdapterRuntimeError("adapter runtime operation binding identity mismatch")
    if (
        candidate["signer_id"] != coordinator_key.key_id
        or candidate["signature"]["key_id"] != coordinator_key.key_id
        or not verify_signature(candidate, coordinator_key.public_key)
    ):
        raise AdapterRuntimeError("adapter runtime operation binding signature rejected")
    return candidate


def adapter_execution_report_digest(report: Mapping[str, Any]) -> str:
    return digest_object(dict(report), domain="adapter-execution-report-v1")


def build_adapter_execution_report(
    *,
    envelope: Mapping[str, Any],
    coordinator_key: TrustedKey,
    adapter_id: str,
    adapter_artifact_digest: str,
    executor_id: str,
    executor_artifact_digest: str,
    operation_binding: Mapping[str, Any],
    conformance_receipt: Mapping[str, Any],
    operation_manifest: Mapping[str, Any] | None = None,
    operation_receipt: Mapping[str, Any] | None = None,
    operation_evidence_reference: Mapping[str, Any] | None = None,
    evidence_artifact_count: int,
    reported_outcome: AdapterReportedOutcome | str,
    recorded_at: str,
    signer: Ed25519Signer,
    network_used: bool = False,
    credentials_used: bool = False,
) -> dict[str, Any]:
    """Sign executor-local evidence without turning it into a witness."""

    verified_envelope = _verify_envelope_signature(
        envelope,
        coordinator_key=coordinator_key,
    )
    manifest = None if operation_manifest is None else deepcopy(dict(operation_manifest))
    receipt = None if operation_receipt is None else deepcopy(dict(operation_receipt))
    binding = deepcopy(dict(operation_binding))
    conformance = deepcopy(dict(conformance_receipt))
    try:
        validate("adapter-operation-binding", binding)
        validate("adapter-conformance-receipt", conformance)
        normalized = AdapterReportedOutcome(reported_outcome)
    except (OperationAuditError, ValueError) as exc:
        raise AdapterRuntimeError("adapter runtime operation evidence rejected") from exc
    if not isinstance(network_used, bool) or not isinstance(credentials_used, bool):
        raise AdapterRuntimeError("adapter runtime execution channel evidence rejected")
    if verified_envelope["manifest"] != {
        "manifest_id": verified_envelope["manifest"]["manifest_id"],
        "manifest_digest": verified_envelope["manifest"]["manifest_digest"],
        "adapter_id": adapter_id,
        "adapter_artifact_digest": adapter_artifact_digest,
    }:
        raise AdapterRuntimeError("adapter runtime report adapter binding mismatch")
    binding_reference = verified_envelope["operation_binding"]
    if operation_evidence_reference is None:
        if manifest is None or receipt is None:
            raise AdapterRuntimeError("adapter runtime operation evidence missing")
        try:
            manifest_digest = verify_readonly_operation_manifest(manifest)
            verify_readonly_operation_receipt(receipt, manifest=manifest)
        except OperationAuditError as exc:
            raise AdapterRuntimeError("adapter runtime operation evidence rejected") from exc
        if manifest["adapter_id"] != adapter_id:
            raise AdapterRuntimeError("adapter runtime report adapter binding mismatch")
        operation_reference = {
            "schema_id": "readonly-operation-receipt/v1",
            "receipt_id": receipt["receipt_id"],
            "receipt_digest": digest_object(
                receipt,
                domain="readonly-operation-receipt-document-v1",
            ),
        }
        if (
            binding_reference["operation_kind"] != "readonly-operation-manifest"
            or binding_reference["operation_manifest_id"] != manifest["manifest_id"]
            or binding_reference["operation_manifest_digest"] != manifest_digest
        ):
            raise AdapterRuntimeError("adapter runtime report operation binding mismatch")
    else:
        if manifest is not None or receipt is not None:
            raise AdapterRuntimeError("adapter runtime operation evidence is ambiguous")
        operation_reference = deepcopy(dict(operation_evidence_reference))
        if set(operation_reference) != {"schema_id", "receipt_id", "receipt_digest"}:
            raise AdapterRuntimeError("adapter runtime operation evidence reference rejected")
        if (
            not all(
                isinstance(operation_reference[name], str) and operation_reference[name]
                for name in ("schema_id", "receipt_id")
            )
            or _DIGEST.fullmatch(str(operation_reference["receipt_digest"])) is None
        ):
            raise AdapterRuntimeError("adapter runtime operation evidence reference rejected")
    if (
        binding_reference["binding_id"] != binding["binding_id"]
        or binding_reference["binding_digest"] != adapter_operation_binding_digest(binding)
        or binding_reference["conformance_receipt_id"] != conformance["receipt_id"]
        or binding_reference["conformance_receipt_digest"]
        != adapter_conformance_receipt_digest(conformance)
        or binding_reference["executor_id"] != executor_id
        or binding_reference["executor_artifact_digest"] != executor_artifact_digest
        or binding_reference["executor_key_id"] != signer.key_id
    ):
        raise AdapterRuntimeError("adapter runtime report provenance binding mismatch")
    core = {
        "protocol": "integrity-guardian/adapter-execution-report/v1",
        "sdk_version": ADAPTER_SDK_VERSION,
        "tenant_id": verified_envelope["tenant_id"],
        "envelope": {
            "envelope_id": verified_envelope["envelope_id"],
            "envelope_digest": adapter_execution_envelope_digest(verified_envelope),
        },
        "adapter": {
            "adapter_id": adapter_id,
            "adapter_artifact_digest": adapter_artifact_digest,
        },
        "operation_binding": deepcopy(binding_reference),
        "conformance": {
            "receipt_id": conformance["receipt_id"],
            "receipt_digest": adapter_conformance_receipt_digest(conformance),
            "readiness": conformance["result"]["readiness"],
        },
        "executor": {
            "executor_id": executor_id,
            "executor_artifact_digest": executor_artifact_digest,
            "key_id": signer.key_id,
        },
        "operation": {
            "intent_operation_digest": verified_envelope["intent"]["operation_digest"],
            "contract_kind": binding_reference["operation_kind"],
            "contract_id": binding_reference["operation_manifest_id"],
            "contract_digest": binding_reference["operation_manifest_digest"],
            **operation_reference,
            "evidence_artifact_count": evidence_artifact_count,
        },
        "reported_outcome": normalized.value,
        "controls": {
            "action_replay_allowed": False,
            "automatic_retry_after_unknown": False,
            "independent_witness_is_executor": False,
            "memory_write": False,
            "network": network_used,
            "credentials": credentials_used,
            "production_authority": False,
        },
        "recorded_at": recorded_at,
        "signer_id": signer.key_id,
    }
    unsigned = {
        "report_id": _signed_identity(
            core,
            field="report_id",
            domain="adapter-execution-report-identity-v1",
        ),
        **core,
    }
    signed = signer.sign(unsigned)
    validate("adapter-execution-report", signed)
    return signed


def verify_adapter_execution_report(
    report: Mapping[str, Any],
    *,
    envelope: Mapping[str, Any],
    coordinator_key: TrustedKey,
    executor_key: TrustedKey,
) -> dict[str, Any]:
    candidate = deepcopy(dict(report))
    try:
        validate("adapter-execution-report", candidate)
    except Exception as exc:
        raise AdapterRuntimeError("adapter runtime execution report schema rejected") from exc
    if candidate["report_id"] != _signed_identity(
        candidate,
        field="report_id",
        domain="adapter-execution-report-identity-v1",
    ):
        raise AdapterRuntimeError("adapter runtime execution report identity mismatch")
    if (
        candidate["signer_id"] != executor_key.key_id
        or candidate["signature"]["key_id"] != executor_key.key_id
        or not verify_signature(candidate, executor_key.public_key)
    ):
        raise AdapterRuntimeError("adapter runtime execution report signature rejected")
    if candidate["executor"]["key_id"] != executor_key.key_id:
        raise AdapterRuntimeError("adapter runtime execution report executor key mismatch")
    verified_envelope = _verify_envelope_signature(
        envelope,
        coordinator_key=coordinator_key,
    )
    expected_executor = verified_envelope["operation_binding"]
    if candidate["executor"] != {
        "executor_id": expected_executor["executor_id"],
        "executor_artifact_digest": expected_executor["executor_artifact_digest"],
        "key_id": expected_executor["executor_key_id"],
    }:
        raise AdapterRuntimeError("adapter runtime execution report executor binding mismatch")
    if (
        candidate["envelope"]
        != {
            "envelope_id": verified_envelope["envelope_id"],
            "envelope_digest": adapter_execution_envelope_digest(verified_envelope),
        }
        or candidate["operation"]["intent_operation_digest"]
        != verified_envelope["intent"]["operation_digest"]
    ):
        raise AdapterRuntimeError("adapter runtime execution report envelope mismatch")
    if candidate["adapter"] != {
        "adapter_id": verified_envelope["manifest"]["adapter_id"],
        "adapter_artifact_digest": verified_envelope["manifest"]["adapter_artifact_digest"],
    }:
        raise AdapterRuntimeError("adapter runtime execution report adapter mismatch")
    if candidate["operation_binding"] != verified_envelope["operation_binding"]:
        raise AdapterRuntimeError("adapter runtime execution report binding mismatch")
    if candidate["conformance"] != {
        "receipt_id": verified_envelope["operation_binding"]["conformance_receipt_id"],
        "receipt_digest": verified_envelope["operation_binding"]["conformance_receipt_digest"],
        "readiness": verified_envelope["operation_binding"]["conformance_readiness"],
    }:
        raise AdapterRuntimeError("adapter runtime execution report conformance mismatch")
    if (
        candidate["operation"]["contract_kind"]
        != verified_envelope["operation_binding"]["operation_kind"]
        or candidate["operation"]["contract_id"]
        != verified_envelope["operation_binding"]["operation_manifest_id"]
        or candidate["operation"]["contract_digest"]
        != verified_envelope["operation_binding"]["operation_manifest_digest"]
    ):
        raise AdapterRuntimeError("adapter runtime execution report operation mismatch")
    return candidate


@dataclass(frozen=True)
class AdapterAttemptRecovery:
    """Content-free recovery result derived from a checkpoint-pinned journal."""

    phase: str
    outcome: AdapterTransitionOutcome
    reason_code: str
    action_replayed: bool
    automatic_retry_allowed: bool
    terminal_receipt_digest: str | None


def adapter_dispatch_admission_digest(admission: Mapping[str, Any]) -> str:
    return digest_object(dict(admission), domain="adapter-dispatch-admission-v1")


def _attempt_source(envelope: Mapping[str, Any]) -> str:
    suffix = adapter_execution_envelope_digest(envelope).split(":", 1)[1]
    return f"adapter-attempt:{suffix}"


def _attempt_ledger(source_id: str) -> str:
    return f"adapter-attempt-ledger:{source_id.rsplit(':', 1)[1]}"


def _attempt_store_digest(path: Path) -> str:
    target = Path(os.path.abspath(path))
    return digest_object(
        {
            "protocol": "integrity-guardian/adapter-attempt-store/v1",
            "absolute_path": str(target),
            "production_authority": False,
        },
        domain="adapter-attempt-store-identity-v1",
    )


def _dispatch_registry_id(key: TrustedKey) -> str:
    suffix = public_key_fingerprint(key.public_key).split(":", 1)[1]
    return f"adapter-dispatch-registry:{suffix}"


def _dispatch_registry_policy_digest(registry_id: str, key: TrustedKey) -> str:
    return digest_object(
        {
            "protocol": "integrity-guardian/adapter-dispatch-registry-policy/v1",
            "tenant_id": "tenant:public-6e3cdbebaafc8efa",
            "registry_id": registry_id,
            "key_id": key.key_id,
            "key_fingerprint": public_key_fingerprint(key.public_key),
            "production_authority": False,
        },
        domain="adapter-dispatch-registry-policy-v1",
    )


def _require_signer(signer: Ed25519Signer, key: TrustedKey, label: str) -> None:
    if (
        not isinstance(signer, Ed25519Signer)
        or signer.key_id != key.key_id
        or public_key_fingerprint(signer.public_key)
        != public_key_fingerprint(key.public_key)
    ):
        raise AdapterRuntimeError(f"adapter {label} signer rejected")


def _adapter_dispatch_admission_identity(document: Mapping[str, Any]) -> str:
    core = deepcopy(dict(document))
    core.pop("admission_id", None)
    core.pop("signature", None)
    suffix = digest_object(
        core,
        domain="adapter-dispatch-admission-identity-v1",
    ).split(":", 1)[1]
    return f"adapter-dispatch-admission:{suffix}"


def _build_adapter_dispatch_admission(
    *,
    registry_id: str,
    envelope: Mapping[str, Any],
    attempt_path: Path,
    journal_key: TrustedKey,
    checkpoint_key: TrustedKey,
    recorded_at: str,
    signer: Ed25519Signer,
) -> dict[str, Any]:
    core = {
        "protocol": "integrity-guardian/adapter-dispatch-admission/v1",
        "tenant_id": envelope["tenant_id"],
        "registry": {
            "registry_id": registry_id,
            "key_id": signer.key_id,
            "key_fingerprint": public_key_fingerprint(signer.public_key),
        },
        "envelope": {
            "envelope_id": envelope["envelope_id"],
            "envelope_digest": adapter_execution_envelope_digest(envelope),
        },
        "attempt": {
            "source_id": _attempt_source(envelope),
            "store_digest": _attempt_store_digest(attempt_path),
            "journal_key_id": journal_key.key_id,
            "journal_key_fingerprint": public_key_fingerprint(journal_key.public_key),
            "checkpoint_key_id": checkpoint_key.key_id,
            "checkpoint_key_fingerprint": public_key_fingerprint(
                checkpoint_key.public_key
            ),
        },
        "controls": {
            "max_invocations": 1,
            "action_replay_allowed": False,
            "production_authority": False,
        },
        "recorded_at": recorded_at,
        "signer_id": signer.key_id,
    }
    unsigned = {
        "admission_id": _adapter_dispatch_admission_identity(core),
        **core,
    }
    signed = signer.sign(unsigned)
    validate("adapter-dispatch-admission", signed)
    return signed


def _verify_adapter_dispatch_admission(
    admission: Mapping[str, Any],
    *,
    coordinator_key: TrustedKey,
) -> dict[str, Any]:
    candidate = deepcopy(dict(admission))
    try:
        validate("adapter-dispatch-admission", candidate)
    except Exception as exc:
        raise AdapterRuntimeError("adapter dispatch admission schema rejected") from exc
    if candidate["admission_id"] != _adapter_dispatch_admission_identity(candidate):
        raise AdapterRuntimeError("adapter dispatch admission identity rejected")
    if (
        candidate["signer_id"] != coordinator_key.key_id
        or candidate["signature"]["key_id"] != coordinator_key.key_id
        or not verify_signature(candidate, coordinator_key.public_key)
    ):
        raise AdapterRuntimeError("adapter dispatch admission signature rejected")
    if candidate["registry"] != {
        "registry_id": _dispatch_registry_id(coordinator_key),
        "key_id": coordinator_key.key_id,
        "key_fingerprint": public_key_fingerprint(coordinator_key.public_key),
    }:
        raise AdapterRuntimeError("adapter dispatch admission registry rejected")
    if candidate["controls"] != {
        "max_invocations": 1,
        "action_replay_allowed": False,
        "production_authority": False,
    }:
        raise AdapterRuntimeError("adapter dispatch admission controls rejected")
    return candidate


def _require_dispatch_admission_binding(
    admission: Mapping[str, Any],
    *,
    envelope: Mapping[str, Any],
    attempt_path: Path,
    coordinator_key: TrustedKey,
    journal_key: TrustedKey,
    checkpoint_key: TrustedKey,
) -> dict[str, Any]:
    verified = _verify_adapter_dispatch_admission(
        admission,
        coordinator_key=coordinator_key,
    )
    if verified["envelope"] != {
        "envelope_id": envelope["envelope_id"],
        "envelope_digest": adapter_execution_envelope_digest(envelope),
    } or verified["attempt"] != {
        "source_id": _attempt_source(envelope),
        "store_digest": _attempt_store_digest(attempt_path),
        "journal_key_id": journal_key.key_id,
        "journal_key_fingerprint": public_key_fingerprint(journal_key.public_key),
        "checkpoint_key_id": checkpoint_key.key_id,
        "checkpoint_key_fingerprint": public_key_fingerprint(
            checkpoint_key.public_key
        ),
    }:
        raise AdapterRuntimeError("adapter dispatch admission attempt binding rejected")
    return verified


def _verify_checkpoint_inclusion(
    *,
    checkpoint: Mapping[str, Any],
    checkpoint_key: TrustedKey,
    proof: Mapping[str, Any],
    event: Mapping[str, Any],
    tenant_id: str,
    ledger_id: str,
) -> None:
    candidate = deepcopy(dict(checkpoint))
    try:
        validate("checkpoint", candidate)
        if (
            candidate["signer_id"] != checkpoint_key.key_id
            or candidate["signature"]["key_id"] != checkpoint_key.key_id
            or not verify_signature(candidate, checkpoint_key.public_key)
        ):
            raise AdapterRuntimeError("adapter dispatch checkpoint signature rejected")
        if candidate["tenant_id"] != tenant_id or candidate["ledger_id"] != ledger_id:
            raise AdapterRuntimeError("adapter dispatch checkpoint scope rejected")
        verify_ledger_inclusion_proof(
            proof,
            expected_tenant_id=tenant_id,
            expected_ledger_id=ledger_id,
            expected_event_digest=event_digest(dict(event)),
            expected_root_digest=candidate["root_digest"],
            expected_tree_size=candidate["tree_size"],
        )
    except (LedgerError, ValidationError, KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, AdapterRuntimeError):
            raise
        raise AdapterRuntimeError("adapter dispatch checkpoint evidence rejected") from exc


@dataclass(frozen=True)
class AdapterDispatchAdmission:
    """Portable signed claim and durable registry inclusion evidence."""

    admission: dict[str, Any]
    event: dict[str, Any]
    inclusion_proof: dict[str, Any]
    checkpoint: dict[str, Any]


class AdapterDispatchRegistry:
    """Coordinator-owned durable uniqueness namespace for consumed envelopes."""

    def __init__(
        self,
        *,
        store: LedgerStore,
        coordinator_key: TrustedKey,
        coordinator_signer: Ed25519Signer | None,
        custody_context: AbstractContextManager[sqlite3.Connection],
    ) -> None:
        self._store = store
        self.coordinator_key = coordinator_key
        self.registry_id = _dispatch_registry_id(coordinator_key)
        self._coordinator_signer = coordinator_signer
        self._custody_context = custody_context
        self._checkpoint: dict[str, Any] | None = None
        self._closed = False

    @classmethod
    def _open_store(
        cls,
        path: Path,
        *,
        coordinator_key: TrustedKey,
        create: bool,
    ) -> tuple[LedgerStore, AbstractContextManager[sqlite3.Connection]]:
        custody = open_private_sqlite_connection(path, create=create)
        try:
            connection = custody.__enter__()
            store = LedgerStore(
                path,
                tenant_id="tenant:public-6e3cdbebaafc8efa",
                ledger_id=_dispatch_registry_id(coordinator_key),
                connection=connection,
            )
        except Exception:
            custody.__exit__(*sys.exc_info())
            raise
        return store, custody

    @classmethod
    def initialize(
        cls,
        path: Path,
        *,
        coordinator_key: TrustedKey,
        coordinator_signer: Ed25519Signer,
        created_at: str,
    ) -> tuple[AdapterDispatchRegistry, dict[str, Any]]:
        _require_signer(coordinator_signer, coordinator_key, "dispatch registry")
        try:
            store, custody = cls._open_store(
                path,
                coordinator_key=coordinator_key,
                create=True,
            )
        except AgentHandoffCustodyError as exc:
            raise AdapterRuntimeError(
                f"adapter dispatch registry custody rejected: {exc}"
            ) from exc
        instance = cls(
            store=store,
            coordinator_key=coordinator_key,
            coordinator_signer=coordinator_signer,
            custody_context=custody,
        )
        initial = build_ledger_event(
            tenant_id="tenant:public-6e3cdbebaafc8efa",
            source_id=instance.registry_id,
            source_sequence=0,
            event_type="key-event",
            payload_digest=_dispatch_registry_policy_digest(
                instance.registry_id,
                coordinator_key,
            ),
            previous_event_digest=None,
            signer=coordinator_signer,
            recorded_at=created_at,
        )
        try:
            store.append(initial)
            checkpoint = instance._new_checkpoint(recorded_at=created_at)
            instance._refresh(checkpoint)
            return instance, checkpoint
        except Exception:
            instance._abort()
            raise

    @classmethod
    def open(
        cls,
        path: Path,
        *,
        coordinator_key: TrustedKey,
        expected_checkpoint: Mapping[str, Any],
        coordinator_signer: Ed25519Signer | None = None,
    ) -> AdapterDispatchRegistry:
        if coordinator_signer is not None:
            _require_signer(coordinator_signer, coordinator_key, "dispatch registry")
        try:
            store, custody = cls._open_store(
                path,
                coordinator_key=coordinator_key,
                create=False,
            )
        except AgentHandoffCustodyError as exc:
            raise AdapterRuntimeError(
                f"adapter dispatch registry custody rejected: {exc}"
            ) from exc
        instance = cls(
            store=store,
            coordinator_key=coordinator_key,
            coordinator_signer=coordinator_signer,
            custody_context=custody,
        )
        try:
            instance._refresh(expected_checkpoint)
            return instance
        except Exception:
            instance._abort()
            raise

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._store.close()
        finally:
            self._custody_context.__exit__(None, None, None)

    def _abort(self) -> None:
        if self._closed:
            return
        self._closed = True
        exception = sys.exc_info()
        try:
            self._store.close()
        finally:
            self._custody_context.__exit__(*exception)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @property
    def checkpoint(self) -> dict[str, Any]:
        if self._checkpoint is None:
            raise AdapterRuntimeError("adapter dispatch registry is not verified")
        return deepcopy(self._checkpoint)

    def _source_keys(self) -> dict[str, TrustedKey]:
        return {
            event["source_id"]: self.coordinator_key
            for event in self._store.events()
        }

    def _validate_structure(self, events: list[dict[str, Any]]) -> None:
        if not events:
            raise AdapterRuntimeError("adapter dispatch registry is empty")
        initial = events[0]
        if (
            initial["source_id"] != self.registry_id
            or initial["source_sequence"] != 0
            or initial["event_type"] != "key-event"
            or initial["previous_event_digest"] is not None
            or initial["payload_digest"]
            != _dispatch_registry_policy_digest(
                self.registry_id,
                self.coordinator_key,
            )
        ):
            raise AdapterRuntimeError("adapter dispatch registry identity rejected")
        by_source: dict[str, list[dict[str, Any]]] = {}
        for event in events[1:]:
            source_id = event["source_id"]
            if not source_id.startswith("adapter-attempt:"):
                raise AdapterRuntimeError("adapter dispatch registry source rejected")
            by_source.setdefault(source_id, []).append(event)
        for chain in by_source.values():
            if not 1 <= len(chain) <= 2:
                raise AdapterRuntimeError("adapter dispatch registry sequence exhausted")
            claimed = chain[0]
            if (
                claimed["source_sequence"] != 0
                or claimed["event_type"] != "adapter-attempt-prepared"
                or claimed["previous_event_digest"] is not None
            ):
                raise AdapterRuntimeError("adapter dispatch registry claim rejected")
            if len(chain) == 2:
                consumed = chain[1]
                if (
                    consumed["source_sequence"] != 1
                    or consumed["event_type"] != "adapter-attempt-dispatching"
                    or consumed["previous_event_digest"] != event_digest(claimed)
                ):
                    raise AdapterRuntimeError(
                        "adapter dispatch registry consumption rejected"
                    )

    def _refresh(self, expected_checkpoint: Mapping[str, Any]) -> None:
        try:
            checkpoint = deepcopy(dict(expected_checkpoint))
            self._store.verify(
                source_public_keys=self._source_keys(),
                checkpoint=checkpoint,
                checkpoint_key=self.coordinator_key,
            )
            self._validate_structure(self._store.events())
        except (LedgerError, KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, AdapterRuntimeError):
                raise
            raise AdapterRuntimeError("adapter dispatch registry checkpoint rejected") from exc
        self._checkpoint = checkpoint

    def _new_checkpoint(self, *, recorded_at: str) -> dict[str, Any]:
        if self._coordinator_signer is None:
            raise AdapterRuntimeError("adapter dispatch registry signer unavailable")
        return self._store.checkpoint(
            checkpoint_id=f"checkpoint:{self.registry_id}:{len(self._store.events())}",
            signer=self._coordinator_signer,
            created_at=recorded_at,
        )

    def _source_events(self, source_id: str) -> list[dict[str, Any]]:
        return [
            event for event in self._store.events() if event["source_id"] == source_id
        ]

    def claim(
        self,
        *,
        envelope: Mapping[str, Any],
        attempt_path: Path,
        journal_key: TrustedKey,
        checkpoint_key: TrustedKey,
        expected_checkpoint: Mapping[str, Any],
        recorded_at: str,
    ) -> AdapterDispatchAdmission:
        if self._coordinator_signer is None:
            raise AdapterRuntimeError("adapter dispatch registry signer unavailable")
        self._refresh(expected_checkpoint)
        candidate = _verify_envelope_signature(
            envelope,
            coordinator_key=self.coordinator_key,
        )
        source_id = _attempt_source(candidate)
        if self._source_events(source_id):
            raise AdapterRuntimeError("adapter dispatch envelope already claimed")
        admission = _build_adapter_dispatch_admission(
            registry_id=self.registry_id,
            envelope=candidate,
            attempt_path=attempt_path,
            journal_key=journal_key,
            checkpoint_key=checkpoint_key,
            recorded_at=recorded_at,
            signer=self._coordinator_signer,
        )
        event = build_ledger_event(
            tenant_id=candidate["tenant_id"],
            source_id=source_id,
            source_sequence=0,
            event_type="adapter-attempt-prepared",
            payload_digest=adapter_dispatch_admission_digest(admission),
            previous_event_digest=None,
            signer=self._coordinator_signer,
            recorded_at=recorded_at,
        )
        try:
            self._store.append_at_checkpoint(
                event,
                source_public_keys=self._source_keys(),
                checkpoint=deepcopy(dict(expected_checkpoint)),
                checkpoint_key=self.coordinator_key,
                precommit_validator=self._validate_structure,
            )
            checkpoint = self._new_checkpoint(recorded_at=recorded_at)
            self._refresh(checkpoint)
            proof = self._store.inclusion_proof(event_digest(event))
        except LedgerError as exc:
            raise AdapterRuntimeError("adapter dispatch envelope claim rejected") from exc
        result = AdapterDispatchAdmission(
            admission=admission,
            event=event,
            inclusion_proof=proof,
            checkpoint=checkpoint,
        )
        _verify_dispatch_admission_evidence(
            result,
            coordinator_key=self.coordinator_key,
        )
        return result

    def consume(
        self,
        *,
        admission: Mapping[str, Any],
        dispatch_event_digest: str,
        recorded_at: str,
    ) -> dict[str, Any]:
        if self._coordinator_signer is None:
            raise AdapterRuntimeError("adapter dispatch registry signer unavailable")
        verified = _verify_adapter_dispatch_admission(
            admission,
            coordinator_key=self.coordinator_key,
        )
        source_id = verified["attempt"]["source_id"]
        events = self._source_events(source_id)
        if len(events) != 1:
            raise AdapterRuntimeError("adapter dispatch permit already consumed")
        if events[0]["payload_digest"] != adapter_dispatch_admission_digest(verified):
            raise AdapterRuntimeError("adapter dispatch registry admission mismatch")
        payload_digest = digest_object(
            {
                "admission_digest": adapter_dispatch_admission_digest(verified),
                "dispatch_event_digest": dispatch_event_digest,
                "phase": "adapter-attempt-dispatching",
            },
            domain="adapter-dispatch-registry-consumption-v1",
        )
        event = build_ledger_event(
            tenant_id=verified["tenant_id"],
            source_id=source_id,
            source_sequence=1,
            event_type="adapter-attempt-dispatching",
            payload_digest=payload_digest,
            previous_event_digest=event_digest(events[0]),
            signer=self._coordinator_signer,
            recorded_at=recorded_at,
        )
        checkpoint = self.checkpoint
        try:
            self._store.append_at_checkpoint(
                event,
                source_public_keys=self._source_keys(),
                checkpoint=checkpoint,
                checkpoint_key=self.coordinator_key,
                precommit_validator=self._validate_structure,
            )
            next_checkpoint = self._new_checkpoint(recorded_at=recorded_at)
            self._refresh(next_checkpoint)
            return next_checkpoint
        except LedgerError as exc:
            raise AdapterRuntimeError("adapter dispatch permit consumption rejected") from exc


def _verify_dispatch_admission_evidence(
    evidence: AdapterDispatchAdmission,
    *,
    coordinator_key: TrustedKey,
) -> dict[str, Any]:
    if not isinstance(evidence, AdapterDispatchAdmission):
        raise AdapterRuntimeError("adapter dispatch admission evidence rejected")
    admission = _verify_adapter_dispatch_admission(
        evidence.admission,
        coordinator_key=coordinator_key,
    )
    try:
        event = verify_ledger_event(
            evidence.event,
            coordinator_key,
            expected_tenant_id=admission["tenant_id"],
            expected_source_id=admission["attempt"]["source_id"],
            expected_event_type="adapter-attempt-prepared",
            expected_payload_digest=adapter_dispatch_admission_digest(admission),
        )
    except LedgerError as exc:
        raise AdapterRuntimeError("adapter dispatch admission event rejected") from exc
    if event["source_sequence"] != 0 or event["previous_event_digest"] is not None:
        raise AdapterRuntimeError("adapter dispatch admission event sequence rejected")
    _verify_checkpoint_inclusion(
        checkpoint=evidence.checkpoint,
        checkpoint_key=coordinator_key,
        proof=evidence.inclusion_proof,
        event=event,
        tenant_id=admission["tenant_id"],
        ledger_id=admission["registry"]["registry_id"],
    )
    return admission


def _journal_dispatch_payload_digest(admission: Mapping[str, Any]) -> str:
    return digest_object(
        {
            "admission_digest": adapter_dispatch_admission_digest(admission),
            "envelope_digest": admission["envelope"]["envelope_digest"],
            "phase": "adapter-attempt-dispatching",
        },
        domain="adapter-attempt-dispatching-v2",
    )


class AdapterDispatchPermit:
    """Non-serializable verifier for one durable registry and journal dispatch."""

    __slots__ = (
        "_admission_evidence",
        "_checkpoint_key",
        "_consumed",
        "_coordinator_key",
        "_dispatch_checkpoint",
        "_dispatch_event",
        "_dispatch_inclusion_proof",
        "_journal_key",
        "_registry",
        "dispatch_event_digest",
        "envelope_digest",
        "source_id",
    )

    def __init__(
        self,
        *,
        envelope_digest: str,
        source_id: str,
        dispatch_event_digest: str,
        _issuer: object,
    ) -> None:
        del envelope_digest, source_id, dispatch_event_digest, _issuer
        raise AdapterRuntimeError("adapter dispatch permit issuer rejected")

    @classmethod
    def _from_dispatch_evidence(
        cls,
        *,
        admission_evidence: AdapterDispatchAdmission,
        dispatch_event: Mapping[str, Any],
        dispatch_inclusion_proof: Mapping[str, Any],
        dispatch_checkpoint: Mapping[str, Any],
        registry: AdapterDispatchRegistry,
        coordinator_key: TrustedKey,
        journal_key: TrustedKey,
        checkpoint_key: TrustedKey,
    ) -> AdapterDispatchPermit:
        instance = object.__new__(cls)
        instance._admission_evidence = admission_evidence
        instance._dispatch_event = deepcopy(dict(dispatch_event))
        instance._dispatch_inclusion_proof = deepcopy(dict(dispatch_inclusion_proof))
        instance._dispatch_checkpoint = deepcopy(dict(dispatch_checkpoint))
        instance._registry = registry
        instance._coordinator_key = coordinator_key
        instance._journal_key = journal_key
        instance._checkpoint_key = checkpoint_key
        admission = _verify_dispatch_permit_evidence(instance)
        instance.envelope_digest = admission["envelope"]["envelope_digest"]
        instance.source_id = admission["attempt"]["source_id"]
        instance.dispatch_event_digest = event_digest(instance._dispatch_event)
        instance._consumed = False
        return instance

    def consume(self, *, envelope: Mapping[str, Any]) -> None:
        if self._consumed:
            raise AdapterRuntimeError("adapter dispatch permit replay rejected")
        admission = _verify_dispatch_permit_evidence(self)
        if (
            self.envelope_digest != adapter_execution_envelope_digest(envelope)
            or admission["envelope"]["envelope_id"] != envelope["envelope_id"]
        ):
            raise AdapterRuntimeError("adapter dispatch permit envelope mismatch")
        self._registry.consume(
            admission=admission,
            dispatch_event_digest=self.dispatch_event_digest,
            recorded_at=self._dispatch_event["recorded_at"],
        )
        self._consumed = True

    def __reduce__(self) -> object:
        raise AdapterRuntimeError("adapter dispatch permit serialization rejected")


def _verify_dispatch_permit_evidence(
    permit: AdapterDispatchPermit,
) -> dict[str, Any]:
    admission = _verify_dispatch_admission_evidence(
        permit._admission_evidence,
        coordinator_key=permit._coordinator_key,
    )
    if permit._registry.registry_id != admission["registry"]["registry_id"]:
        raise AdapterRuntimeError("adapter dispatch permit registry mismatch")
    attempt = admission["attempt"]
    if (
        permit._journal_key.key_id != attempt["journal_key_id"]
        or public_key_fingerprint(permit._journal_key.public_key)
        != attempt["journal_key_fingerprint"]
        or permit._checkpoint_key.key_id != attempt["checkpoint_key_id"]
        or public_key_fingerprint(permit._checkpoint_key.public_key)
        != attempt["checkpoint_key_fingerprint"]
    ):
        raise AdapterRuntimeError("adapter dispatch permit journal keys rejected")
    try:
        dispatch_event = verify_ledger_event(
            permit._dispatch_event,
            permit._journal_key,
            expected_tenant_id=admission["tenant_id"],
            expected_source_id=attempt["source_id"],
            expected_event_type="adapter-attempt-dispatching",
            expected_payload_digest=_journal_dispatch_payload_digest(admission),
        )
    except LedgerError as exc:
        raise AdapterRuntimeError("adapter dispatch permit event rejected") from exc
    if dispatch_event["source_sequence"] != 1 or dispatch_event["previous_event_digest"] is None:
        raise AdapterRuntimeError("adapter dispatch permit event sequence rejected")
    _verify_checkpoint_inclusion(
        checkpoint=permit._dispatch_checkpoint,
        checkpoint_key=permit._checkpoint_key,
        proof=permit._dispatch_inclusion_proof,
        event=dispatch_event,
        tenant_id=admission["tenant_id"],
        ledger_id=_attempt_ledger(attempt["source_id"]),
    )
    return admission


@dataclass(frozen=True)
class AdapterDispatchStart:
    """Durable dispatch checkpoint plus its non-serializable process permit."""

    checkpoint: dict[str, Any]
    permit: AdapterDispatchPermit


class AdapterAttemptJournal:
    """One append-only attempt chain for one exact consumed-grant envelope."""

    def __init__(
        self,
        *,
        store: LedgerStore,
        envelope: dict[str, Any],
        source_id: str,
        journal_signer: Ed25519Signer | None,
        journal_key: TrustedKey,
        checkpoint_signer: Ed25519Signer | None,
        checkpoint_key: TrustedKey,
        initial_dispatch_allowed: bool,
        dispatch_admission: AdapterDispatchAdmission | None,
        dispatch_registry: AdapterDispatchRegistry | None,
        custody_context: AbstractContextManager[sqlite3.Connection],
    ) -> None:
        self._store = store
        self.envelope = envelope
        self.source_id = source_id
        self._journal_signer = journal_signer
        self._journal_key = journal_key
        self._checkpoint_signer = checkpoint_signer
        self._checkpoint_key = checkpoint_key
        self._initial_dispatch_allowed = initial_dispatch_allowed
        self._dispatch_admission = dispatch_admission
        self._dispatch_registry = dispatch_registry
        self._custody_context = custody_context
        self._closed = False

    @staticmethod
    def _source(envelope: Mapping[str, Any]) -> str:
        return _attempt_source(envelope)

    @staticmethod
    def _ledger(source_id: str) -> str:
        return _attempt_ledger(source_id)

    @classmethod
    def _open_custodied_store(
        cls,
        path: Path,
        *,
        tenant_id: str,
        source_id: str,
        create: bool,
    ) -> tuple[LedgerStore, AbstractContextManager[sqlite3.Connection]]:
        custody = open_private_sqlite_connection(path, create=create)
        try:
            connection = custody.__enter__()
            store = LedgerStore(
                path,
                tenant_id=tenant_id,
                ledger_id=cls._ledger(source_id),
                connection=connection,
            )
        except Exception:
            custody.__exit__(*sys.exc_info())
            raise
        return store, custody

    @classmethod
    def prepare_new(
        cls,
        path: Path,
        *,
        envelope: Mapping[str, Any],
        coordinator_key: TrustedKey,
        journal_signer: Ed25519Signer,
        checkpoint_signer: Ed25519Signer,
        dispatch_registry: AdapterDispatchRegistry,
        expected_dispatch_registry_checkpoint: Mapping[str, Any],
        recorded_at: str,
    ) -> tuple[AdapterAttemptJournal, dict[str, Any]]:
        """Create the unique initial record; an existing path is never replayed."""

        candidate = _verify_envelope_signature(envelope, coordinator_key=coordinator_key)
        source_id = cls._source(candidate)
        if (
            not isinstance(dispatch_registry, AdapterDispatchRegistry)
            or dispatch_registry.coordinator_key != coordinator_key
        ):
            raise AdapterRuntimeError("adapter dispatch registry binding rejected")
        try:
            store, custody = cls._open_custodied_store(
                path,
                tenant_id=candidate["tenant_id"],
                source_id=source_id,
                create=True,
            )
        except AgentHandoffCustodyError as exc:
            raise AdapterRuntimeError(
                f"adapter attempt custody rejected: {exc}"
            ) from exc
        try:
            dispatch_admission = dispatch_registry.claim(
                envelope=candidate,
                attempt_path=path,
                journal_key=TrustedKey(journal_signer.key_id, journal_signer.public_key),
                checkpoint_key=TrustedKey(
                    checkpoint_signer.key_id,
                    checkpoint_signer.public_key,
                ),
                expected_checkpoint=expected_dispatch_registry_checkpoint,
                recorded_at=recorded_at,
            )
            _require_dispatch_admission_binding(
                dispatch_admission.admission,
                envelope=candidate,
                attempt_path=path,
                coordinator_key=coordinator_key,
                journal_key=TrustedKey(
                    journal_signer.key_id,
                    journal_signer.public_key,
                ),
                checkpoint_key=TrustedKey(
                    checkpoint_signer.key_id,
                    checkpoint_signer.public_key,
                ),
            )
        except Exception:
            exception = sys.exc_info()
            store.close()
            custody.__exit__(*exception)
            raise
        instance = cls(
            store=store,
            envelope=candidate,
            source_id=source_id,
            journal_signer=journal_signer,
            journal_key=TrustedKey(journal_signer.key_id, journal_signer.public_key),
            checkpoint_signer=checkpoint_signer,
            checkpoint_key=TrustedKey(checkpoint_signer.key_id, checkpoint_signer.public_key),
            initial_dispatch_allowed=True,
            dispatch_admission=dispatch_admission,
            dispatch_registry=dispatch_registry,
            custody_context=custody,
        )
        event = build_ledger_event(
            tenant_id=candidate["tenant_id"],
            source_id=source_id,
            source_sequence=0,
            event_type=_PHASES[0],
            payload_digest=adapter_execution_envelope_digest(candidate),
            previous_event_digest=None,
            signer=journal_signer,
            recorded_at=recorded_at,
        )
        try:
            store.append(event)
            checkpoint = instance._new_checkpoint(1)
            instance._validate_chain()
            return instance, checkpoint
        except Exception:
            instance._abort()
            raise

    @classmethod
    def open(
        cls,
        path: Path,
        *,
        envelope: Mapping[str, Any],
        coordinator_key: TrustedKey,
        journal_key: TrustedKey,
        checkpoint: Mapping[str, Any],
        checkpoint_key: TrustedKey,
        journal_signer: Ed25519Signer | None = None,
        checkpoint_signer: Ed25519Signer | None = None,
    ) -> AdapterAttemptJournal:
        candidate = _verify_envelope_signature(envelope, coordinator_key=coordinator_key)
        source_id = cls._source(candidate)
        try:
            store, custody = cls._open_custodied_store(
                path,
                tenant_id=candidate["tenant_id"],
                source_id=source_id,
                create=False,
            )
        except AgentHandoffCustodyError as exc:
            raise AdapterRuntimeError(
                f"adapter attempt custody rejected: {exc}"
            ) from exc
        instance = cls(
            store=store,
            envelope=candidate,
            source_id=source_id,
            journal_signer=journal_signer,
            journal_key=journal_key,
            checkpoint_signer=checkpoint_signer,
            checkpoint_key=checkpoint_key,
            initial_dispatch_allowed=False,
            dispatch_admission=None,
            dispatch_registry=None,
            custody_context=custody,
        )
        try:
            store.verify(
                source_public_keys={source_id: journal_key},
                checkpoint=deepcopy(dict(checkpoint)),
                checkpoint_key=checkpoint_key,
            )
            instance._validate_chain()
            return instance
        except Exception:
            instance._abort()
            raise

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._store.close()
        finally:
            self._custody_context.__exit__(None, None, None)

    def _abort(self) -> None:
        if self._closed:
            return
        self._closed = True
        exception = sys.exc_info()
        try:
            self._store.close()
        finally:
            self._custody_context.__exit__(*exception)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @property
    def phase(self) -> str:
        return self._store.events()[-1]["event_type"]

    @property
    def dispatch_registry_checkpoint(self) -> dict[str, Any]:
        if self._dispatch_registry is None:
            raise AdapterRuntimeError("adapter dispatch registry unavailable")
        return self._dispatch_registry.checkpoint

    def _validate_chain(self, events: list[dict[str, Any]] | None = None) -> None:
        candidate = self._store.events() if events is None else events
        types = [event["event_type"] for event in candidate]
        if not 1 <= len(types) <= len(_PHASES) or types != list(_PHASES[: len(types)]):
            raise AdapterRuntimeError("adapter attempt phase chain rejected")
        if any(event["source_id"] != self.source_id for event in candidate):
            raise AdapterRuntimeError("adapter attempt source rejected")
        if candidate[0]["payload_digest"] != adapter_execution_envelope_digest(self.envelope):
            raise AdapterRuntimeError("adapter attempt envelope binding mismatch")

    def _new_checkpoint(self, tree_size: int) -> dict[str, Any]:
        if self._checkpoint_signer is None:
            raise AdapterRuntimeError("adapter attempt checkpoint signer unavailable")
        return self._store.checkpoint(
            checkpoint_id=f"checkpoint:adapter-attempt:{tree_size}",
            signer=self._checkpoint_signer,
        )

    def _append(
        self,
        *,
        expected_phase: str,
        phase: str,
        payload_digest: str,
        checkpoint: Mapping[str, Any],
        recorded_at: str,
    ) -> dict[str, Any]:
        if self._journal_signer is None or self._checkpoint_signer is None:
            raise AdapterRuntimeError("adapter attempt opened read-only")
        if self.phase != expected_phase:
            raise AdapterRuntimeError("adapter attempt replay or phase mismatch")
        events = self._store.events()
        event = build_ledger_event(
            tenant_id=self.envelope["tenant_id"],
            source_id=self.source_id,
            source_sequence=len(events),
            event_type=phase,
            payload_digest=payload_digest,
            previous_event_digest=event_digest(events[-1]),
            signer=self._journal_signer,
            recorded_at=recorded_at,
        )
        self._store.append_at_checkpoint(
            event,
            source_public_keys={self.source_id: self._journal_key},
            checkpoint=deepcopy(dict(checkpoint)),
            checkpoint_key=self._checkpoint_key,
            precommit_validator=self._validate_chain,
        )
        return self._new_checkpoint(len(events) + 1)

    def mark_dispatching(
        self,
        *,
        checkpoint: Mapping[str, Any],
        recorded_at: str,
    ) -> AdapterDispatchStart:
        if (
            not self._initial_dispatch_allowed
            or self._dispatch_admission is None
            or self._dispatch_registry is None
        ):
            raise AdapterRuntimeError("adapter attempt replay or phase mismatch")
        admission = _verify_dispatch_admission_evidence(
            self._dispatch_admission,
            coordinator_key=self._dispatch_registry.coordinator_key,
        )
        _require_dispatch_admission_binding(
            admission,
            envelope=self.envelope,
            attempt_path=self._store.path,
            coordinator_key=self._dispatch_registry.coordinator_key,
            journal_key=self._journal_key,
            checkpoint_key=self._checkpoint_key,
        )
        digest = _journal_dispatch_payload_digest(admission)
        next_checkpoint = self._append(
            expected_phase=_PHASES[0],
            phase=_PHASES[1],
            payload_digest=digest,
            checkpoint=checkpoint,
            recorded_at=recorded_at,
        )
        dispatch_event = self._store.events()[-1]
        dispatch_proof = self._store.inclusion_proof(event_digest(dispatch_event))
        return AdapterDispatchStart(
            checkpoint=next_checkpoint,
            permit=AdapterDispatchPermit._from_dispatch_evidence(
                admission_evidence=self._dispatch_admission,
                dispatch_event=dispatch_event,
                dispatch_inclusion_proof=dispatch_proof,
                dispatch_checkpoint=next_checkpoint,
                registry=self._dispatch_registry,
                coordinator_key=self._dispatch_registry.coordinator_key,
                journal_key=self._journal_key,
                checkpoint_key=self._checkpoint_key,
            ),
        )

    def record_executor_report(
        self,
        report: Mapping[str, Any],
        *,
        coordinator_key: TrustedKey,
        executor_key: TrustedKey,
        checkpoint: Mapping[str, Any],
        recorded_at: str,
    ) -> dict[str, Any]:
        verified = verify_adapter_execution_report(
            report,
            envelope=self.envelope,
            coordinator_key=coordinator_key,
            executor_key=executor_key,
        )
        return self._append(
            expected_phase=_PHASES[1],
            phase=_PHASES[2],
            payload_digest=adapter_execution_report_digest(verified),
            checkpoint=checkpoint,
            recorded_at=recorded_at,
        )

    def record_terminal_receipt(
        self,
        receipt: Mapping[str, Any],
        *,
        receipt_key: TrustedKey,
        executor_key: TrustedKey | None = None,
        checkpoint: Mapping[str, Any],
        recorded_at: str,
    ) -> dict[str, Any]:
        verified = verify_adapter_transition_receipt(
            receipt,
            receipt_key=receipt_key,
            executor_key=executor_key,
        )
        if verified["envelope"] != {
            "envelope_id": self.envelope["envelope_id"],
            "envelope_digest": adapter_execution_envelope_digest(self.envelope),
        }:
            raise AdapterRuntimeError("adapter attempt terminal envelope mismatch")
        return self._append(
            expected_phase=_PHASES[2],
            phase=_PHASES[3],
            payload_digest=adapter_transition_receipt_digest(verified),
            checkpoint=checkpoint,
            recorded_at=recorded_at,
        )

    def recover(
        self,
        *,
        terminal_receipt: Mapping[str, Any] | None = None,
        receipt_key: TrustedKey | None = None,
        executor_key: TrustedKey | None = None,
    ) -> AdapterAttemptRecovery:
        events = self._store.events()
        phase = events[-1]["event_type"]
        if phase == _PHASES[0]:
            return AdapterAttemptRecovery(
                phase=phase,
                outcome=AdapterTransitionOutcome.GRANT_CONSUMED_ACTION_NOT_STARTED,
                reason_code="prepared-before-dispatch",
                action_replayed=False,
                automatic_retry_allowed=False,
                terminal_receipt_digest=None,
            )
        if phase in {_PHASES[1], _PHASES[2]}:
            return AdapterAttemptRecovery(
                phase=phase,
                outcome=AdapterTransitionOutcome.UNKNOWN_OUTCOME,
                reason_code="dispatch-boundary-incomplete",
                action_replayed=False,
                automatic_retry_allowed=False,
                terminal_receipt_digest=None,
            )
        terminal_digest = events[-1]["payload_digest"]
        if terminal_receipt is None or receipt_key is None:
            return AdapterAttemptRecovery(
                phase=phase,
                outcome=AdapterTransitionOutcome.UNKNOWN_OUTCOME,
                reason_code="terminal-receipt-body-required",
                action_replayed=False,
                automatic_retry_allowed=False,
                terminal_receipt_digest=terminal_digest,
            )
        verified = verify_adapter_transition_receipt(
            terminal_receipt,
            receipt_key=receipt_key,
            executor_key=executor_key,
        )
        if adapter_transition_receipt_digest(verified) != terminal_digest:
            raise AdapterRuntimeError("adapter attempt terminal receipt digest mismatch")
        return AdapterAttemptRecovery(
            phase=phase,
            outcome=AdapterTransitionOutcome(verified["result"]["outcome"]),
            reason_code=verified["result"]["reason_code"],
            action_replayed=False,
            automatic_retry_allowed=False,
            terminal_receipt_digest=terminal_digest,
        )


class ContainedReadOnlyOperationAdapter:
    """One-shot local child adapter over the existing audited operation runner."""

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
        operation_bindings: Mapping[str, Mapping[str, Any]],
        operation_manifests: Mapping[str, Mapping[str, Any]],
        coordinator_key: TrustedKey,
        executor_id: str,
        executor_artifact_digest: str,
        signer: Ed25519Signer,
    ) -> None:
        manifest = verify_adapter_capability_manifest(
            capability_manifest,
            adapter_key=adapter_key,
        )
        try:
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
            require_adapter_conformance_readiness(
                conformance,
                minimum="source-ready",
            )
        except AdapterConformanceError as exc:
            raise AdapterRuntimeError("contained adapter conformance admission rejected") from exc
        if manifest["declared_channels"] != {
            "api": False,
            "browser_control": False,
            "computer_use": False,
            "credentials": False,
            "network": False,
            "service_control": False,
            "shell": False,
        }:
            raise AdapterRuntimeError("contained adapter channel declaration rejected")
        self.manifest = manifest
        self.conformance_receipt = conformance
        self.conformance_receipt_digest = adapter_conformance_receipt_digest(conformance)
        self.bindings = {
            key: _verify_operation_binding_signature(
                value,
                coordinator_key=coordinator_key,
            )
            for key, value in operation_bindings.items()
        }
        self.operations = {key: deepcopy(dict(value)) for key, value in operation_manifests.items()}
        if set(self.bindings) != set(self.operations):
            raise AdapterRuntimeError("contained adapter operation binding set rejected")
        for key, binding in self.bindings.items():
            if _DIGEST.fullmatch(key) is None:
                raise AdapterRuntimeError("contained adapter operation binding rejected")
            value = self.operations[key]
            operation_manifest_digest = verify_readonly_operation_manifest(value)
            operations = value["operations"]
            interface = manifest["interface_contract"]
            if (
                value["adapter_id"] != manifest["adapter_id"]
                or len(operations) != 1
                or binding["manifest"]
                != {
                    "manifest_id": manifest["manifest_id"],
                    "manifest_digest": digest_object(
                        manifest,
                        domain="adapter-capability-manifest-v1",
                    ),
                    "adapter_id": manifest["adapter_id"],
                    "adapter_artifact_digest": manifest["adapter_artifact_digest"],
                }
                or binding["conformance"]
                != {
                    "receipt_id": conformance["receipt_id"],
                    "receipt_digest": self.conformance_receipt_digest,
                    "readiness": conformance["result"]["readiness"],
                }
                or binding["intent"]["operation_digest"] != key
                or binding["operation"]
                != {
                    "kind": "readonly-operation-manifest",
                    "manifest_id": value["manifest_id"],
                    "manifest_digest": operation_manifest_digest,
                    "target_node_id": value["target_node_id"],
                }
                or binding["executor"]
                != {
                    "executor_id": executor_id,
                    "executor_artifact_digest": executor_artifact_digest,
                    "key_id": signer.key_id,
                }
            ):
                raise AdapterRuntimeError("contained adapter operation binding rejected")
            operation = operations[0]
            if (
                operation["timeout_seconds"] > interface["max_timeout_seconds"]
                or operation["max_output_bytes"] > interface["max_output_bytes"]
                or (
                    operation["credential_reference"] is not None
                    and interface["credential_delivery"] != "reference-only"
                )
            ):
                raise AdapterRuntimeError("contained adapter interface limit rejected")
        self.coordinator_key = coordinator_key
        self.executor_id = executor_id
        self.executor_artifact_digest = executor_artifact_digest
        self.signer = signer
        self._used: set[str] = set()

    def execute(
        self,
        envelope: Mapping[str, Any],
        *,
        dispatch_permit: AdapterDispatchPermit,
        authorization: Mapping[str, Any],
        authority_key: TrustedKey,
        at_time: str,
        evidence_directory: Path,
        recorded_at: str,
    ) -> dict[str, Any]:
        candidate = _verify_envelope_signature(
            envelope,
            coordinator_key=self.coordinator_key,
        )
        if candidate["manifest"] != {
            "manifest_id": self.manifest["manifest_id"],
            "manifest_digest": digest_object(
                self.manifest,
                domain="adapter-capability-manifest-v1",
            ),
            "adapter_id": self.manifest["adapter_id"],
            "adapter_artifact_digest": self.manifest["adapter_artifact_digest"],
        }:
            raise AdapterRuntimeError("contained adapter manifest binding mismatch")
        if candidate["envelope_id"] in self._used:
            raise AdapterRuntimeError("contained adapter replay rejected")
        binding = self.bindings.get(candidate["intent"]["operation_digest"])
        operation = self.operations.get(candidate["intent"]["operation_digest"])
        if binding is None or operation is None:
            raise AdapterRuntimeError("contained adapter operation is not allowlisted")
        binding_reference = candidate["operation_binding"]
        if (
            binding_reference["binding_id"] != binding["binding_id"]
            or binding_reference["binding_digest"] != adapter_operation_binding_digest(binding)
            or binding["intent"]
            != {
                "operation_digest": candidate["intent"]["operation_digest"],
                "action_class": candidate["intent"]["action_class"],
                "target_entity_id": candidate["expected_transition"]["entity_id"],
                "target_zone_id": candidate["expected_transition"]["zone_id"],
            }
        ):
            raise AdapterRuntimeError("contained adapter envelope binding mismatch")
        if operation["target_node_id"] != candidate["expected_transition"]["entity_id"]:
            raise AdapterRuntimeError("contained adapter operation target mismatch")
        if not isinstance(dispatch_permit, AdapterDispatchPermit):
            raise AdapterRuntimeError("contained adapter dispatch permit rejected")
        try:
            verified_authorization = deepcopy(dict(authorization))
            verify_readonly_operation_authorization(
                verified_authorization,
                manifest=operation,
                authority_key=authority_key,
                at_time=at_time,
            )
        except (OperationAuditError, TypeError, ValueError) as exc:
            raise AdapterRuntimeError(
                "contained adapter operation authorization rejected"
            ) from exc
        dispatch_permit.consume(envelope=candidate)
        self._used.add(candidate["envelope_id"])
        receipt = execute_readonly_operation_manifest(
            operation,
            authorization=verified_authorization,
            authority_key=authority_key,
            at_time=at_time,
            evidence_directory=evidence_directory,
            observed_at=recorded_at,
        )
        verification = verify_readonly_operation_receipt(receipt, manifest=operation)
        evidence = verify_readonly_operation_evidence(
            receipt,
            evidence_directory=evidence_directory,
        )
        write_operation_document(
            evidence_directory / READONLY_OPERATION_RECEIPT_ARTIFACT,
            receipt,
            schema="readonly-operation-receipt",
        )
        counts = verification["outcome_counts"]
        if counts["unknown-outcome"]:
            reported = AdapterReportedOutcome.OUTCOME_UNKNOWN
        elif counts["confirmed-failure"] or counts["not-started"]:
            reported = AdapterReportedOutcome.REPORTED_FAILURE
        else:
            reported = AdapterReportedOutcome.REPORTED_SUCCESS
        return build_adapter_execution_report(
            envelope=candidate,
            coordinator_key=self.coordinator_key,
            adapter_id=self.manifest["adapter_id"],
            adapter_artifact_digest=self.manifest["adapter_artifact_digest"],
            executor_id=self.executor_id,
            executor_artifact_digest=self.executor_artifact_digest,
            operation_binding=binding,
            conformance_receipt=self.conformance_receipt,
            operation_manifest=operation,
            operation_receipt=receipt,
            evidence_artifact_count=evidence["artifact_count"],
            reported_outcome=reported,
            recorded_at=recorded_at,
            signer=self.signer,
        )


def build_adapter_transition_receipt_from_report(
    *,
    report: Mapping[str, Any],
    executor_key: TrustedKey,
    manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    proposal: Mapping[str, Any],
    proposer_key: TrustedKey,
    envelope: Mapping[str, Any],
    operation_binding: Mapping[str, Any],
    operation_manifest: Mapping[str, Any],
    operation_key: TrustedKey | None = None,
    binding_key: TrustedKey,
    coordinator_key: TrustedKey,
    verified_grant: VerifiedAdapterGrant,
    witness: VerifiedAdapterWitness | None,
    recorded_at: str,
    signer: Ed25519Signer,
) -> dict[str, Any]:
    """Build the existing terminal receipt from one verified executor report."""

    verified = verify_adapter_execution_report(
        report,
        envelope=envelope,
        coordinator_key=coordinator_key,
        executor_key=executor_key,
    )
    return build_adapter_transition_receipt(
        manifest=manifest,
        adapter_key=adapter_key,
        proposal=proposal,
        proposer_key=proposer_key,
        envelope=envelope,
        operation_binding=operation_binding,
        operation_manifest=operation_manifest,
        operation_key=operation_key,
        binding_key=binding_key,
        coordinator_key=coordinator_key,
        verified_grant=verified_grant,
        grant_consumed=True,
        invocation_started=True,
        executor=verified["executor"],
        executor_key=executor_key,
        adapter_reported_outcome=verified["reported_outcome"],
        adapter_evidence_digest=adapter_execution_report_digest(verified),
        witness=witness,
        recorded_at=recorded_at,
        signer=signer,
    )


__all__ = [
    "AdapterAttemptJournal",
    "AdapterAttemptRecovery",
    "AdapterDispatchAdmission",
    "AdapterDispatchPermit",
    "AdapterDispatchRegistry",
    "AdapterDispatchStart",
    "AdapterRuntimeError",
    "ContainedReadOnlyOperationAdapter",
    "adapter_dispatch_admission_digest",
    "adapter_execution_report_digest",
    "build_adapter_execution_report",
    "build_adapter_transition_receipt_from_report",
    "verify_adapter_execution_report",
]
