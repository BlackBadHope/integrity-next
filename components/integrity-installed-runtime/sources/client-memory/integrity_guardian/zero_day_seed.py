"""Build a fresh local Seed only from proof-bearing zero-day observations."""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes, parse_json_strict
from .collector import verify_collector_result
from .hashing import digest_object
from .local_machine import (
    PrivateOutputReconciliationRequired,
    _commit_private_output_reservation,
    _read_private,
    _release_private_output_reservation,
    _reserve_private_output,
    load_local_machine_profile,
    private_output_reconciliation_status,
)
from .operation_audit import (
    load_operation_document,
    verify_readonly_operation_evidence,
    verify_readonly_operation_receipt,
)
from .schemas import validate
from .seed_catalog import SeedCatalog, iter_catalog_events

_MAXIMUM_EVIDENCE_BYTES = 16 * 1024 * 1024


class ZeroDaySeedError(ValueError):
    """Raised before unrelated or unverified bytes can enter a fresh Seed."""


def _private_document(
    path: Path,
    *,
    schema: str,
    maximum_bytes: int = _MAXIMUM_EVIDENCE_BYTES,
) -> tuple[dict[str, Any], str]:
    payload = _read_private(path, maximum_bytes=maximum_bytes)
    value = parse_json_strict(payload)
    if not isinstance(value, dict) or canonical_bytes(value) + b"\n" != payload:
        raise ZeroDaySeedError(f"{schema} evidence is not canonical")
    validate(schema, value)
    return value, "sha256:" + hashlib.sha256(payload).hexdigest()


def _event(
    event_id: int,
    *,
    timestamp: str,
    action: str,
    summary: str,
    evidence_kind: str,
    evidence_digest: str,
    details: dict[str, Any],
    level: str = "info",
) -> dict[str, Any]:
    uid_core = {
        "event_id": event_id,
        "action": action,
        "evidence_kind": evidence_kind,
        "evidence_digest": evidence_digest,
    }
    uid = digest_object(uid_core, domain="zero-day-seed-event-v1").split(":", 1)[1]
    return {
        "id": event_id,
        "event_uid": f"zero-day-{uid}",
        "ts_utc": timestamp,
        "actor": "integrity-guardian",
        "action": action,
        "level": level,
        "summary": summary,
        "details": {
            **details,
            "truth_status": "observed",
            "evidence_kind": evidence_kind,
            "evidence_digest": evidence_digest,
            "imports_remote_memory": False,
            "production_authority": False,
        },
        "tags": ["zero-day", "observed", "digest-bound"],
    }


def _receipt_identity(core: dict[str, Any]) -> str:
    return "zero-day-seed:" + digest_object(
        core,
        domain="zero-day-seed-build-receipt-v1",
    ).split(":", 1)[1]


def _build_fresh_zero_day_seed(
    *,
    profile_path: Path | None,
    collector_result_paths: Sequence[Path],
    operation_manifest_path: Path,
    operation_receipt_path: Path,
    operation_evidence_directory: Path,
) -> dict[str, Any]:
    profile = load_local_machine_profile(profile_path)
    if not 1 <= len(collector_result_paths) <= 64:
        raise ZeroDaySeedError("collector result count is outside 1..64")
    catalog_path = Path(profile["seed"]["catalog"])
    if os.path.lexists(os.fspath(catalog_path)):
        raise ZeroDaySeedError("fresh zero-day Seed catalog must be absent")
    tenant_id = profile["tenant"]["tenant_id"]
    profile_target = profile_path
    if profile_target is None:
        from .local_machine import default_local_profile_path

        profile_target = default_local_profile_path()
    profile_document, profile_digest = _private_document(
        profile_target,
        schema="local-machine-profile",
    )
    if profile_document != profile:
        raise ZeroDaySeedError("local profile evidence mismatch")
    manifest = load_operation_document(
        operation_manifest_path,
        schema="readonly-operation-manifest",
    )
    receipt = load_operation_document(
        operation_receipt_path,
        schema="readonly-operation-receipt",
    )
    operation_verification = verify_readonly_operation_receipt(
        receipt,
        manifest=manifest,
    )
    verify_readonly_operation_evidence(
        receipt,
        evidence_directory=operation_evidence_directory,
    )
    if manifest["tenant_id"] != tenant_id:
        raise ZeroDaySeedError("operation tenant does not match local profile")
    _, manifest_digest = _private_document(
        operation_manifest_path,
        schema="readonly-operation-manifest",
    )
    _, operation_receipt_digest = _private_document(
        operation_receipt_path,
        schema="readonly-operation-receipt",
    )

    events: list[dict[str, Any]] = []
    bindings: list[dict[str, Any]] = []
    next_id = 1
    events.append(
        _event(
            next_id,
            timestamp=profile["created_at"],
            action="zero_day_local_profile_initialized",
            summary="Fresh local Integrity profile initialized without remote memory",
            evidence_kind="local-machine-profile",
            evidence_digest=profile_digest,
            details={
                "profile_id": profile["profile_id"],
                "tenant_id": tenant_id,
                "source_namespace": profile["seed"]["source_namespace"],
            },
        )
    )
    bindings.append(
        {
            "kind": "local-machine-profile",
            "digest": profile_digest,
            "event_ids": [next_id],
        }
    )
    next_id += 1

    seen_collector_digests: set[str] = set()
    for path in collector_result_paths:
        result, result_digest = _private_document(path, schema="collector-result")
        collector_verification = verify_collector_result(result)
        if result_digest in seen_collector_digests:
            raise ZeroDaySeedError("collector result is duplicated")
        seen_collector_digests.add(result_digest)
        if result["profile"]["tenant_id"] != tenant_id:
            raise ZeroDaySeedError("collector result tenant mismatch")
        if result["receipt"]["fact_count"] != len(result["facts"]):
            raise ZeroDaySeedError("collector result fact count mismatch")
        if collector_verification["profile_digest_custody"] != "verified-file":
            raise ZeroDaySeedError(
                "zero-day Seed requires a digest-verified collector profile"
            )
        event_ids: list[int] = []
        events.append(
            _event(
                next_id,
                timestamp=result["observed_at"],
                action="zero_day_collector_result_observed",
                summary=(
                    f"Collector {result['profile']['collector_id']} produced "
                    f"{len(result['facts'])} bounded facts"
                ),
                evidence_kind="collector-result",
                evidence_digest=result_digest,
                details={
                    "collector_id": result["profile"]["collector_id"],
                    "node_id": result["profile"]["node_id"],
                    "fact_count": len(result["facts"]),
                    "stdout_digest": result["receipt"]["stdout_digest"],
                    "collector_result_id": result["result_id"],
                    "profile_digest": result["profile"]["profile_digest"],
                },
            )
        )
        event_ids.append(next_id)
        next_id += 1
        for fact in result["facts"]:
            events.append(
                _event(
                    next_id,
                    timestamp=result["observed_at"],
                    action="zero_day_fact_observed",
                    summary=f"Observed {fact['subject_kind']} {fact['identity']}",
                    evidence_kind="collector-result",
                    evidence_digest=result_digest,
                    details={
                        "collector_id": result["profile"]["collector_id"],
                        "node_id": result["profile"]["node_id"],
                        "subject_kind": fact["subject_kind"],
                        "identity": fact["identity"],
                        "layer": fact["layer"],
                        "state": fact["state"],
                        "content_digest": fact["content_digest"],
                        "metadata": fact["metadata"],
                    },
                )
            )
            event_ids.append(next_id)
            next_id += 1
        bindings.append(
            {
                "kind": "collector-result",
                "digest": result_digest,
                "event_ids": event_ids,
            }
        )

    manifest_event_id = next_id
    events.append(
        _event(
            manifest_event_id,
            timestamp=manifest["created_at"],
            action="zero_day_operation_manifest_committed",
            summary=f"Committed {len(manifest['operations'])} exact read-only operations",
            evidence_kind="readonly-operation-manifest",
            evidence_digest=manifest_digest,
            details={
                "manifest_id": manifest["manifest_id"],
                "adapter_id": manifest["adapter_id"],
                "target_node_id": manifest["target_node_id"],
                "operations": [
                    {
                        "operation_id": item["operation_id"],
                        "purpose": item["purpose"],
                        "argv": item["argv"],
                        "argv_digest": item["argv_digest"],
                        "executable_digest": item["executable_digest"],
                        "credential_reference": item["credential_reference"],
                    }
                    for item in manifest["operations"]
                ],
            },
        )
    )
    bindings.append(
        {
            "kind": "readonly-operation-manifest",
            "digest": manifest_digest,
            "event_ids": [manifest_event_id],
        }
    )
    next_id += 1
    receipt_event_ids: list[int] = []
    for result in receipt["operations"]:
        events.append(
            _event(
                next_id,
                timestamp=receipt["observed_at"],
                action="zero_day_operation_outcome_observed",
                summary=f"Operation {result['operation_id']} outcome: {result['outcome']}",
                evidence_kind="readonly-operation-receipt",
                evidence_digest=operation_receipt_digest,
                details={
                    "manifest_id": manifest["manifest_id"],
                    "receipt_id": receipt["receipt_id"],
                    "operation_id": result["operation_id"],
                    "outcome": result["outcome"],
                    "exit_code": result["exit_code"],
                    "stdout_digest": result["stdout_digest"],
                    "stderr_digest": result["stderr_digest"],
                    "automatic_retry_allowed": result[
                        "automatic_retry_allowed"
                    ],
                },
                level=("info" if result["outcome"] == "confirmed-success" else "warning"),
            )
        )
        receipt_event_ids.append(next_id)
        next_id += 1
    bindings.append(
        {
            "kind": "readonly-operation-receipt",
            "digest": operation_receipt_digest,
            "event_ids": receipt_event_ids,
        }
    )

    report = SeedCatalog(catalog_path).import_events(
        events,
        source_namespace=profile["seed"]["source_namespace"],
        profile="zero-day-local-observation",
    )
    core = {
        "status": operation_verification["status"],
        "profile_id": profile["profile_id"],
        "source_namespace": report.source_namespace,
        "evidence_bindings": bindings,
        "event_count": report.event_count,
        "minimum_event_id": report.minimum_event_id,
        "maximum_event_id": report.maximum_event_id,
        "source_digest": report.source_digest,
        "catalog_digest": report.catalog_digest,
        "home_record_count": report.home_record_count,
        "imports_remote_memory": False,
        "production_authority": False,
    }
    build_receipt = {
        "protocol": "integrity-guardian/zero-day-seed-build-receipt/v1",
        "receipt_id": _receipt_identity(core),
        **core,
    }
    validate("zero-day-seed-build-receipt", build_receipt)
    return build_receipt


def verify_zero_day_seed_build_receipt(
    receipt: dict[str, Any],
    *,
    catalog_path: Path,
    expected_evidence: Sequence[tuple[str, str]],
) -> dict[str, Any]:
    validate("zero-day-seed-build-receipt", receipt)
    core = {key: value for key, value in receipt.items() if key not in {"protocol", "receipt_id"}}
    if receipt["receipt_id"] != _receipt_identity(core):
        raise ZeroDaySeedError("zero-day Seed receipt identity mismatch")
    status = SeedCatalog(catalog_path).status()
    for key in (
        "source_namespace",
        "event_count",
        "minimum_event_id",
        "maximum_event_id",
        "source_digest",
        "catalog_digest",
        "home_record_count",
    ):
        if receipt[key] != status[key]:
            raise ZeroDaySeedError("zero-day Seed receipt catalog binding mismatch")
    actual_evidence = [
        (binding["kind"], binding["digest"])
        for binding in receipt["evidence_bindings"]
    ]
    if sorted(actual_evidence) != sorted(expected_evidence):
        raise ZeroDaySeedError("zero-day Seed evidence inventory mismatch")
    events = {event["id"]: event for event in iter_catalog_events(catalog_path)}
    bound_ids: set[int] = set()
    for binding in receipt["evidence_bindings"]:
        for event_id in binding["event_ids"]:
            event = events.get(event_id)
            if (
                event is None
                or event.get("details", {}).get("evidence_kind") != binding["kind"]
                or event.get("details", {}).get("evidence_digest") != binding["digest"]
            ):
                raise ZeroDaySeedError("zero-day Seed event evidence binding mismatch")
            bound_ids.add(event_id)
    if bound_ids != set(events):
        raise ZeroDaySeedError("zero-day Seed contains unbound events")
    return {
        "status": receipt["status"],
        "receipt_id": receipt["receipt_id"],
        "event_count": receipt["event_count"],
        "evidence_binding_count": len(receipt["evidence_bindings"]),
        "production_authority": False,
    }


def _fresh_catalog_artifacts(catalog_path: Path) -> tuple[Path, ...]:
    """Return the exact bounded SQLite file set owned by one fresh build."""

    return (
        catalog_path,
        Path(f"{catalog_path}-wal"),
        Path(f"{catalog_path}-shm"),
    )


def _rollback_fresh_catalog(catalog_path: Path) -> None:
    """Remove only catalog files proven absent before this build began."""

    artifacts = _fresh_catalog_artifacts(catalog_path)
    parent = catalog_path.parent.absolute()
    if os.name == "nt":
        from ._windows_files import (
            HeldWindowsDirectory,
            assert_private_directory_acl,
        )

        assert_private_directory_acl(parent)
        context = HeldWindowsDirectory(parent)
    else:
        details = parent.stat()
        if (
            parent.is_symlink()
            or not stat.S_ISDIR(details.st_mode)
            or details.st_uid != os.geteuid()
            or stat.S_IMODE(details.st_mode) & 0o077
        ):
            raise ZeroDaySeedError("fresh Seed rollback parent custody rejected")
        from contextlib import nullcontext

        context = nullcontext()
    with context:
        for artifact in artifacts:
            if os.path.lexists(os.fspath(artifact)) and (
                artifact.is_symlink() or not artifact.is_file()
            ):
                raise ZeroDaySeedError("fresh Seed rollback artifact type rejected")
        for artifact in reversed(artifacts):
            try:
                artifact.unlink()
            except FileNotFoundError:
                pass
        if any(os.path.lexists(os.fspath(artifact)) for artifact in artifacts):
            raise ZeroDaySeedError("fresh Seed rollback did not remove exact artifacts")


def build_and_write_fresh_zero_day_seed(
    *,
    profile_path: Path | None,
    collector_result_paths: Sequence[Path],
    operation_manifest_path: Path,
    operation_receipt_path: Path,
    operation_evidence_directory: Path,
    output_path: Path,
) -> tuple[dict[str, Any], Path]:
    """Build one fresh local Seed with receipt custody admitted first.

    The catalog is a derived, not-yet-committed candidate until its mandatory
    receipt is durably written.  A receipt failure therefore rolls back only
    the exact catalog files that were proven absent before this invocation.
    """

    existing_output = private_output_reconciliation_status(
        output_path,
        expected_purpose="zero-day-seed-build-receipt",
    )
    if existing_output["status"] == "UNKNOWN_OUTCOME":
        raise PrivateOutputReconciliationRequired(existing_output)
    if existing_output["status"] == "COMMITTED":
        raise ZeroDaySeedError(
            "zero-day Seed output already contains a committed receipt"
        )
    profile = load_local_machine_profile(profile_path)
    catalog_path = Path(profile["seed"]["catalog"]).absolute()
    artifacts = _fresh_catalog_artifacts(catalog_path)
    if any(os.path.lexists(os.fspath(artifact)) for artifact in artifacts):
        raise ZeroDaySeedError("fresh zero-day Seed catalog artifacts must be absent")
    reservation = _reserve_private_output(
        output_path,
        "zero-day-seed-build-receipt",
    )
    try:
        receipt = _build_fresh_zero_day_seed(
            profile_path=profile_path,
            collector_result_paths=collector_result_paths,
            operation_manifest_path=operation_manifest_path,
            operation_receipt_path=operation_receipt_path,
            operation_evidence_directory=operation_evidence_directory,
        )
        validate("zero-day-seed-build-receipt", receipt)
        output = _commit_private_output_reservation(
            reservation,
            receipt,
        )
    except Exception as failure:
        failure_status = (
            failure.status
            if isinstance(failure, PrivateOutputReconciliationRequired)
            else None
        )
        preserve_committed_catalog = bool(
            failure_status is not None
            and failure_status["final_output_digest"] is not None
        )
        if not reservation._consumed:
            _release_private_output_reservation(reservation)
        if (
            not preserve_committed_catalog
            and any(os.path.lexists(os.fspath(artifact)) for artifact in artifacts)
        ):
            try:
                _rollback_fresh_catalog(catalog_path)
            except (OSError, ZeroDaySeedError) as rollback_error:
                failure = ZeroDaySeedError(
                    "fresh Seed catalog may exist without its receipt"
                )
                failure.__cause__ = rollback_error
        if isinstance(failure, PrivateOutputReconciliationRequired):
            raise
        status = private_output_reconciliation_status(
            output_path,
            expected_purpose="zero-day-seed-build-receipt",
        )
        if status["status"] == "UNKNOWN_OUTCOME":
            raise PrivateOutputReconciliationRequired(status) from failure
        raise failure  # noqa: TRY201 - rollback can replace the original failure
    return receipt, output


__all__ = [
    "ZeroDaySeedError",
    "build_and_write_fresh_zero_day_seed",
    "verify_zero_day_seed_build_receipt",
]
