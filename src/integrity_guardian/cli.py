"""Minimal clean-room command line interface."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from . import __version__
from .canonical import canonical_bytes, parse_json_strict
from .capabilities import integrity_capabilities
from .collector import load_profile, run_collector, write_collector_result
from .governance import verify_governance_bundle
from .hashing import digest_object
from .local_machine import (
    PRIVATE_DOCUMENT_READ_SCHEMAS,
    PRIVATE_DOCUMENT_SCHEMAS,
    LocalMachineError,
    PrivateOutputReconciliationRequired,
    _commit_private_output_reservation,
    _release_private_output_reservation,
    _reserve_private_output,
    audit_credential_custody,
    build_zero_day_final_witness,
    default_local_profile_path,
    initialize_local_machine,
    load_private_document,
    local_machine_status,
    private_output_reconciliation_status,
    store_private_document,
    write_credential_custody_receipt,
    write_zero_day_final_witness,
)
from .lts import lts_contract_report
from .lts_activation import (
    build_lts_track_activation_receipt,
    verify_lts_track_activation,
    write_lts_track_activation_receipt,
)
from .memory_link_graph import MemoryLinkGraph
from .memory_ttt_paths import (
    MemoryTttPathError,
    RunbookPathCatalog,
    load_runbook_path_catalog,
    memory_ttt_autofill,
    memory_ttt_list_paths,
)
from .observer_anchor import (
    ObserverAnchorCursor,
    ObserverAnchorStore,
    ObserverAnchorSubjectKind,
)
from .operation_audit import (
    build_readonly_operation_manifest,
    build_readonly_operation_receipt,
    execute_readonly_operation_manifest,
    load_operation_document,
    write_operation_document,
)
from .platform_profile import build_platform_profile
from .release import (
    authenticate_release_manifest,
    build_artifact_inventory,
    verify_release_manifest,
)
from .release_index import (
    build_lts_release_index,
    lts_version_report,
    verify_lts_release_index,
    write_lts_release_index,
)
from .schemas import validate
from .seed_action_log import DEFAULT_ACTION_LOG_URL, sync_action_log_seed
from .seed_catalog import (
    SEED_NAMESPACE,
    SeedCatalog,
    catalog_from_jsonl,
    iter_catalog_events,
    write_events_jsonl,
)
from .seed_relationships import explain_seed_event_connections
from .seed_runtime import serve_seed_runtime
from .signing import public_key_fingerprint, trusted_key_from_value
from .tenant import (
    TenantWorkspace,
    build_tenant_profile,
    build_unenrolled_tenant_profile,
    tenant_enrollment_status,
    verify_tenant_governance,
)
from .windows_assets import (
    build_windows_host_collector_profile,
    export_windows_assets,
    load_windows_asset_manifest,
    verify_windows_asset_manifest,
    write_windows_host_collector_profile,
)
from .windows_install import (
    default_windows_install_locator_path,
    windows_installation_status,
)
from .zero_day_seed import build_and_write_fresh_zero_day_seed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="guardian")
    subparsers = parser.add_subparsers(dest="command", required=True)

    canonical = subparsers.add_parser("canonicalize")
    canonical.add_argument("file", type=Path)

    digest = subparsers.add_parser("digest")
    digest.add_argument("domain")
    digest.add_argument("file", type=Path)

    schema = subparsers.add_parser("validate")
    schema.add_argument("schema")
    schema.add_argument("file", type=Path)

    tenant_init = subparsers.add_parser("tenant-init")
    tenant_init.add_argument("--state-root", required=True, type=Path)
    tenant_init.add_argument("--tenant-id", required=True)
    tenant_init.add_argument("--deployment-id", required=True)
    tenant_init.add_argument("--retention-policy-digest")
    tenant_init.add_argument("--key-registry-digest")
    tenant_init.add_argument("--unenrolled", action="store_true")
    tenant_init.add_argument("--created-at", required=True)

    tenant_verify = subparsers.add_parser("tenant-verify")
    tenant_verify.add_argument("--state-root", required=True, type=Path)
    tenant_verify.add_argument("--tenant-id", required=True)

    tenant_audit = subparsers.add_parser("tenant-audit")
    tenant_audit.add_argument("--state-root", required=True, type=Path)
    tenant_audit.add_argument("--tenant-id", required=True)
    tenant_audit.add_argument("--expected-owner-sid", required=True)

    agent_preflight = subparsers.add_parser("agent-preflight")
    agent_preflight.add_argument("--state-root", required=True, type=Path)
    agent_preflight.add_argument("--tenant-id", required=True)
    agent_preflight.add_argument("--policy-authority-key-id")
    agent_preflight.add_argument("--policy-authority-public-key-file", type=Path)
    agent_preflight.add_argument("--policy-authority-key-fingerprint")
    agent_preflight.add_argument("--at-time")

    collector_run = subparsers.add_parser("collector-run")
    collector_run.add_argument("--profile", required=True, type=Path)
    collector_run.add_argument("--profile-digest")
    collector_run.add_argument("--output-directory", required=True, type=Path)
    collector_run.add_argument("--confirm-readonly", required=True, action="store_true")

    release_verify = subparsers.add_parser("release-verify")
    release_verify.add_argument("--manifest", required=True, type=Path)
    release_verify.add_argument("--artifact-root", required=True, type=Path)
    release_verify.add_argument("--authority-key-id", required=True)
    release_verify.add_argument("--authority-public-key-file", required=True, type=Path)
    release_verify.add_argument("--authority-key-fingerprint", required=True)
    release_verify.add_argument("--source-revision", required=True)

    version = subparsers.add_parser("version")
    version.add_argument("--all", action="store_true")
    status = subparsers.add_parser("status")
    status.add_argument("--profile", type=Path)
    status.add_argument("--install-locator", type=Path)
    subparsers.add_parser("governance-verify")
    subparsers.add_parser("capabilities")
    subparsers.add_parser("lts-contracts")
    lts_index_build = subparsers.add_parser("lts-release-index-build")
    lts_index_build.add_argument("--source-revision", required=True)
    lts_index_build.add_argument("--artifact-path", required=True)
    lts_index_build.add_argument("--created-at", required=True)
    lts_index_build.add_argument("--output", required=True, type=Path)
    lts_index_verify = subparsers.add_parser("lts-release-index-verify")
    lts_index_verify.add_argument("--index", required=True, type=Path)
    lts_index_verify.add_argument("--manifest", required=True, type=Path)
    lts_index_verify.add_argument("--artifact-root", required=True, type=Path)
    lts_index_verify.add_argument("--authority-key-id", required=True)
    lts_index_verify.add_argument("--authority-public-key-file", required=True, type=Path)
    lts_index_verify.add_argument("--authority-key-fingerprint", required=True)
    lts_index_verify.add_argument("--source-revision", required=True)
    lts_index_verify.add_argument("--native-trust-genesis", type=Path)
    lts_index_verify.add_argument("--native-release-enrollment", type=Path)
    lts_index_verify.add_argument("--native-trust-instance-id")
    lts_index_verify.add_argument("--native-root-key-fingerprint")
    lts_activation_build = subparsers.add_parser("lts-activation-build")
    lts_activation_build.add_argument("--track-id", required=True)
    lts_activation_build.add_argument("--release-id", required=True)
    lts_activation_build.add_argument("--release-version", required=True)
    lts_activation_build.add_argument("--release-tag", required=True)
    lts_activation_build.add_argument("--source-revision", required=True)
    lts_activation_build.add_argument("--artifact-path", required=True)
    lts_activation_build.add_argument("--activated-at", required=True)
    lts_activation_build.add_argument("--support-until", required=True)
    lts_activation_build.add_argument("--reproducible-artifacts-digest", required=True)
    lts_activation_build.add_argument("--local-suite-digest", required=True)
    lts_activation_build.add_argument("--hosted-linux-digest", required=True)
    lts_activation_build.add_argument("--track-gate-digest", required=True)
    lts_activation_build.add_argument("--release-review-digest", required=True)
    lts_activation_build.add_argument("--output", required=True, type=Path)

    lts_activation_verify = subparsers.add_parser("lts-activation-verify")
    lts_activation_verify.add_argument("--receipt", required=True, type=Path)
    lts_activation_verify.add_argument("--manifest", required=True, type=Path)
    lts_activation_verify.add_argument("--artifact-root", required=True, type=Path)
    lts_activation_verify.add_argument("--authority-key-id", required=True)
    lts_activation_verify.add_argument("--authority-public-key-file", required=True, type=Path)
    lts_activation_verify.add_argument("--authority-key-fingerprint", required=True)
    lts_activation_verify.add_argument("--source-revision", required=True)
    lts_activation_verify.add_argument("--native-trust-genesis", type=Path)
    lts_activation_verify.add_argument("--native-release-enrollment", type=Path)
    lts_activation_verify.add_argument("--native-trust-instance-id")
    lts_activation_verify.add_argument("--native-root-key-fingerprint")
    subparsers.add_parser("platform-profile")

    native_bootstrap = subparsers.add_parser("native-trust-bootstrap")
    native_bootstrap.add_argument("--state-root", required=True, type=Path)
    native_bootstrap.add_argument("--instance-id", required=True)
    native_bootstrap.add_argument("--device-id", required=True)
    native_bootstrap.add_argument("--architecture-root", required=True, type=Path)
    native_bootstrap.add_argument("--legacy-source-key", type=Path)
    native_bootstrap.add_argument("--legacy-checkpoint-key", type=Path)

    native_release_authority = subparsers.add_parser("native-release-authority-init")
    native_release_authority.add_argument("--state-root", required=True, type=Path)
    native_release_authority.add_argument("--instance-id", required=True)

    native_device_request = subparsers.add_parser("native-device-request")
    native_device_request.add_argument("--state-root", required=True, type=Path)
    native_device_request.add_argument("--instance-id", required=True)
    native_device_request.add_argument("--device-id", required=True)
    native_device_request.add_argument("--scope", action="append")

    native_device_enroll = subparsers.add_parser("native-device-enroll")
    native_device_enroll.add_argument("--state-root", required=True, type=Path)
    native_device_enroll.add_argument("--instance-id", required=True)
    native_device_enroll.add_argument("--request", required=True, type=Path)

    native_module_enroll = subparsers.add_parser("native-module-enroll")
    native_module_enroll.add_argument("--state-root", required=True, type=Path)
    native_module_enroll.add_argument("--instance-id", required=True)
    native_module_enroll.add_argument("--module-id", required=True)
    native_module_enroll.add_argument("--artifact-digest", required=True)
    native_module_enroll.add_argument("--scope", action="append")

    anchor_init = subparsers.add_parser("observer-anchor-init")
    anchor_init.add_argument("--root", required=True, type=Path)
    anchor_init.add_argument("--store-id", required=True)
    anchor_init.add_argument(
        "--subject-kind",
        required=True,
        choices=[value.value for value in ObserverAnchorSubjectKind],
    )
    anchor_init.add_argument("--subject-file", required=True, type=Path)
    anchor_init.add_argument("--created-at", required=True)

    anchor_verify = subparsers.add_parser("observer-anchor-verify")
    anchor_verify.add_argument("--root", required=True, type=Path)
    anchor_verify.add_argument("--store-id", required=True)
    anchor_verify.add_argument("--cursor-file", type=Path)
    anchor_verify.add_argument(
        "--allow-unpinned-availability-recovery",
        action="store_true",
    )

    anchor_advance = subparsers.add_parser("observer-anchor-advance")
    anchor_advance.add_argument("--root", required=True, type=Path)
    anchor_advance.add_argument("--store-id", required=True)
    anchor_advance.add_argument("--cursor-file", required=True, type=Path)
    anchor_advance.add_argument(
        "--subject-kind",
        required=True,
        choices=[value.value for value in ObserverAnchorSubjectKind],
    )
    anchor_advance.add_argument("--subject-file", required=True, type=Path)
    anchor_advance.add_argument("--created-at", required=True)

    seed_build = subparsers.add_parser("seed-catalog-build")
    seed_build.add_argument("--catalog", required=True, type=Path)
    seed_build.add_argument("--events-jsonl", required=True, type=Path)
    seed_build.add_argument("--profile", default="full")
    seed_build.add_argument("--source-namespace", default=SEED_NAMESPACE)

    seed_sync = subparsers.add_parser("seed-sync")
    seed_sync.add_argument("--catalog", required=True, type=Path)
    seed_sync.add_argument("--source-url", default=DEFAULT_ACTION_LOG_URL)
    seed_sync.add_argument("--profile", default="live-sync")
    seed_sync.add_argument("--source-namespace", help="Explicit canonical project namespace")
    seed_sync.add_argument("--page-size", type=int, default=1000)
    seed_sync.add_argument("--export-events", type=Path)

    seed_verify = subparsers.add_parser("seed-catalog-verify")
    seed_verify.add_argument("--catalog", required=True, type=Path)
    seed_verify.add_argument("--expected-source-digest")
    seed_verify.add_argument("--expected-event-count", type=int)

    seed_status = subparsers.add_parser("seed-status")
    seed_status.add_argument("--catalog", required=True, type=Path)

    seed_capsule = subparsers.add_parser("seed-capsule")
    seed_capsule.add_argument("--catalog", required=True, type=Path)
    seed_capsule.add_argument("--active-limit", type=int, default=12)
    seed_capsule.add_argument("--context", action="store_true")

    seed_search = subparsers.add_parser("seed-search")
    seed_search.add_argument("--catalog", required=True, type=Path)
    seed_search.add_argument("--query", required=True)
    seed_search.add_argument("--limit", type=int, default=20)

    seed_connections = subparsers.add_parser("seed-connections")
    seed_connections.add_argument("--catalog", required=True, type=Path)
    seed_connections.add_argument("--event-id", required=True, type=int)
    seed_connections.add_argument("--evidence-root", type=Path)
    seed_connections.add_argument("--evidence-source-prefix", type=Path)
    seed_connections.add_argument("--limit", type=int, default=20)
    seed_connections.add_argument("--include-contextual", action="store_true")

    memory_link_resolve = subparsers.add_parser("memory-link-resolve")
    memory_link_resolve.add_argument("--catalog", required=True, type=Path)
    memory_link_resolve.add_argument("--reference", required=True)
    memory_link_resolve.add_argument("--project-slug")
    memory_link_resolve.add_argument("--limit", type=int, default=40)
    memory_link_resolve.add_argument("--max-context-bytes", type=int, default=32768)
    memory_link_resolve.add_argument("--cursor", default="")

    memory_entity_brief = subparsers.add_parser("memory-entity-brief")
    memory_entity_brief.add_argument("--catalog", required=True, type=Path)
    memory_entity_brief.add_argument("--reference", required=True)
    memory_entity_brief.add_argument("--project-slug")
    memory_entity_brief.add_argument("--relationship-limit", type=int, default=40)
    memory_entity_brief.add_argument("--activity-limit", type=int, default=12)
    memory_entity_brief.add_argument("--task-limit", type=int, default=20)
    memory_entity_brief.add_argument("--discovery-limit", type=int, default=10)
    memory_entity_brief.add_argument("--max-context-bytes", type=int, default=65536)

    memory_link_audit = subparsers.add_parser("memory-link-audit")
    memory_link_audit.add_argument("--catalog", required=True, type=Path)
    memory_link_audit.add_argument("--project-slug")
    memory_link_audit.add_argument("--kind", action="append", default=[])
    memory_link_audit.add_argument("--limit", type=int, default=50)
    memory_link_audit.add_argument("--max-context-bytes", type=int, default=65536)
    memory_link_audit.add_argument("--cursor", default="")

    memory_link_context = subparsers.add_parser("memory-link-context")
    memory_link_context.add_argument("--catalog", required=True, type=Path)
    memory_link_context.add_argument("--anchor", required=True)
    memory_link_context.add_argument("--project-slug")
    memory_link_context.add_argument(
        "--direction", choices=["outbound", "inbound", "both"], default="both"
    )
    memory_link_context.add_argument("--relation", action="append", default=[])
    memory_link_context.add_argument("--max-depth", type=int, default=2)
    memory_link_context.add_argument("--max-nodes", type=int, default=64)
    memory_link_context.add_argument("--max-links", type=int, default=120)
    memory_link_context.add_argument("--max-context-bytes", type=int, default=65536)

    memory_link_navigate = subparsers.add_parser("memory-link-navigate")
    memory_link_navigate.add_argument("--catalog", required=True, type=Path)
    memory_link_navigate.add_argument("--anchor", required=True)
    memory_link_navigate.add_argument("--project-slug")
    memory_link_navigate.add_argument(
        "--direction", choices=["outbound", "inbound", "both"], default="both"
    )
    memory_link_navigate.add_argument("--relation", action="append", default=[])
    memory_link_navigate.add_argument("--trail", action="append", default=[])
    memory_link_navigate.add_argument("--limit", type=int, default=40)
    memory_link_navigate.add_argument("--max-context-bytes", type=int, default=32768)
    memory_link_navigate.add_argument("--cursor", default="")

    memory_ttt_autofill_cmd = subparsers.add_parser("memory-ttt-autofill")
    memory_ttt_autofill_cmd.add_argument(
        "--catalog",
        type=Path,
        help="Optional Seed SQLite catalogue used to construct a Memory Link Graph",
    )
    memory_ttt_autofill_cmd.add_argument(
        "--path-catalog",
        type=Path,
        help="Explicit JSON runbook-path catalogue; never discovered automatically",
    )
    memory_ttt_autofill_cmd.add_argument("--expected-path-catalog-digest")
    memory_ttt_autofill_cmd.add_argument("--goal")
    memory_ttt_autofill_cmd.add_argument("--last-hop")
    memory_ttt_autofill_cmd.add_argument("--project-slug")
    memory_ttt_autofill_cmd.add_argument("--snapshot-id")
    memory_ttt_autofill_cmd.add_argument("--expected-graph-digest")
    memory_ttt_autofill_cmd.add_argument(
        "--list-paths",
        action="store_true",
        help="List explicitly registered TIME-TO-TASK paths instead of autofill",
    )

    seed_serve = subparsers.add_parser("seed-serve")
    seed_serve.add_argument("--catalog", required=True, type=Path)
    seed_serve.add_argument("--host", default="127.0.0.1")
    seed_serve.add_argument("--port", type=int, default=8775)
    seed_serve.add_argument("--evidence-root", type=Path)
    seed_serve.add_argument("--evidence-source-prefix", type=Path)

    machine_init = subparsers.add_parser("machine-init")
    machine_init.add_argument("--profile", type=Path)
    machine_init.add_argument("--state-root", required=True, type=Path)
    machine_init.add_argument("--tenant-id", required=True)
    machine_init.add_argument("--deployment-id", required=True)
    machine_init.add_argument("--catalog", required=True, type=Path)
    machine_init.add_argument("--source-namespace", required=True)
    machine_init.add_argument("--created-at", required=True)
    machine_init.add_argument("--runtime-port", type=int, default=8775)
    machine_init.add_argument("--persistence-task")
    machine_init.add_argument(
        "--forbidden-context-port",
        action="append",
        type=int,
    )

    credential_audit = subparsers.add_parser("credential-audit")
    credential_audit.add_argument("--state-root", required=True, type=Path)
    credential_audit.add_argument(
        "--credential-source",
        required=True,
        action="append",
        type=Path,
    )
    credential_audit.add_argument("--output", required=True, type=Path)

    zero_day_verify = subparsers.add_parser("zero-day-verify")
    zero_day_verify.add_argument("--profile", type=Path)
    zero_day_verify.add_argument("--credential-receipt", type=Path)
    zero_day_verify.add_argument(
        "--credential-source",
        action="append",
        type=Path,
    )
    zero_day_verify.add_argument("--seed-build-receipt", type=Path)
    zero_day_verify.add_argument(
        "--collector-result",
        action="append",
        type=Path,
    )
    zero_day_verify.add_argument("--operation-manifest", type=Path)
    zero_day_verify.add_argument("--operation-receipt", type=Path)
    zero_day_verify.add_argument("--operation-evidence-directory", type=Path)
    zero_day_verify.add_argument("--persistence-receipt", type=Path)
    zero_day_verify.add_argument("--persistence-witness", type=Path)
    zero_day_verify.add_argument("--require-runtime", action="store_true")
    zero_day_verify.add_argument("--require-cold-start", action="store_true")
    zero_day_verify.add_argument("--observed-at")
    zero_day_verify.add_argument("--output", required=True, type=Path)

    zero_day_seed = subparsers.add_parser("zero-day-seed-build")
    zero_day_seed.add_argument("--profile", type=Path)
    zero_day_seed.add_argument(
        "--collector-result",
        required=True,
        action="append",
        type=Path,
    )
    zero_day_seed.add_argument("--operation-manifest", required=True, type=Path)
    zero_day_seed.add_argument("--operation-receipt", required=True, type=Path)
    zero_day_seed.add_argument(
        "--operation-evidence-directory",
        required=True,
        type=Path,
    )
    zero_day_seed.add_argument("--output", required=True, type=Path)

    operation_manifest = subparsers.add_parser("operation-manifest-build")
    operation_manifest.add_argument("--spec", required=True, type=Path)
    operation_manifest.add_argument("--output", required=True, type=Path)

    operation_receipt = subparsers.add_parser("operation-receipt-build")
    operation_receipt.add_argument("--manifest", required=True, type=Path)
    operation_receipt.add_argument("--results", required=True, type=Path)
    operation_receipt.add_argument("--observed-at", required=True)
    operation_receipt.add_argument("--output", required=True, type=Path)

    operation_run = subparsers.add_parser("operation-run")
    operation_run.add_argument("--manifest", required=True, type=Path)
    operation_run.add_argument("--authorization", required=True, type=Path)
    operation_run.add_argument("--authority-key-id", required=True)
    operation_run.add_argument("--authority-public-key-file", required=True, type=Path)
    operation_run.add_argument("--authority-key-fingerprint", required=True)
    operation_run.add_argument("--at-time", required=True)
    operation_run.add_argument("--evidence-directory", required=True, type=Path)
    operation_run.add_argument("--observed-at")
    operation_run.add_argument("--output", required=True, type=Path)

    private_output_status = subparsers.add_parser("private-output-status")
    private_output_status.add_argument("--output", required=True, type=Path)
    private_output_status.add_argument(
        "--purpose",
        required=True,
        choices=(
            "local-machine-profile",
            "readonly-operation-receipt",
            "zero-day-seed-build-receipt",
        ),
    )

    windows_assets = subparsers.add_parser("windows-assets-export")
    windows_assets.add_argument("--output-directory", required=True, type=Path)
    windows_assets_verify = subparsers.add_parser("windows-assets-verify")
    windows_assets_verify.add_argument("--manifest", required=True, type=Path)
    windows_assets_verify.add_argument("--assets-directory", required=True, type=Path)

    windows_profile = subparsers.add_parser("windows-host-profile")
    windows_profile.add_argument("--executable", required=True, type=Path)
    windows_profile.add_argument("--tenant-id", required=True)
    windows_profile.add_argument("--collector-id", required=True)
    windows_profile.add_argument("--node-id", required=True)
    windows_profile.add_argument("--output", required=True, type=Path)

    private_store = subparsers.add_parser("private-document-store")
    private_store.add_argument("--schema", required=True, choices=PRIVATE_DOCUMENT_SCHEMAS)
    private_store.add_argument("--input", required=True, type=Path)
    private_store.add_argument("--output", required=True, type=Path)
    private_read = subparsers.add_parser("private-document-read")
    private_read.add_argument(
        "--schema",
        required=True,
        choices=PRIVATE_DOCUMENT_READ_SCHEMAS,
    )
    private_read.add_argument("--path", required=True, type=Path)
    return parser


def _read_object(path: Path, field: str) -> dict[str, object]:
    value = parse_json_strict(path.read_bytes())
    if not isinstance(value, dict):
        raise TypeError(f"{field} must contain one JSON object")
    return value


def _anchor_result(store: ObserverAnchorStore) -> dict[str, object]:
    recovery = store.recovery
    return {
        "ok": True,
        "store_id": store.store_id,
        "cursor": recovery.cursor.to_document(),
        "subject_kind": recovery.record["subject_kind"],
        "subject_digest": recovery.record["subject_digest"],
        "availability_recovery": recovery.availability_recovery,
        "rollback_protection": recovery.rollback_protection,
        "same_failure_domain_rollback_protection": False,
        "production_authority": False,
    }


def _emit(value: object) -> None:
    print(json.dumps(value, sort_keys=True))


def _handle_status(args: argparse.Namespace) -> None:
    target = args.profile
    if target is None:
        discovered = default_local_profile_path()
        target = discovered if discovered.is_file() else None
    if target is not None:
        _emit(local_machine_status(target))
        return
    install_locator = args.install_locator
    if install_locator is None and os.name == "nt":
        install_locator = default_windows_install_locator_path()
    if install_locator is not None and install_locator.is_file():
        _emit(
            windows_installation_status(
                install_locator,
                expected_version=__version__,
            )
        )
        return
    profile = build_platform_profile(__version__)
    _emit(
        {
            "status": "UNINITIALIZED",
            "coverage": "UNKNOWN",
            "platform_family": profile["runtime"]["family"],
            "portable_core": profile["readiness"]["portable_core"],
            "platform_profile_command": "guardian platform-profile",
            "production_authority": False,
        }
    )


def _handle_machine_init(args: argparse.Namespace) -> None:
    _emit(
        initialize_local_machine(
            profile_path=args.profile,
            state_root=args.state_root,
            tenant_id=args.tenant_id,
            deployment_id=args.deployment_id,
            catalog_path=args.catalog,
            source_namespace=args.source_namespace,
            created_at=args.created_at,
            runtime_port=args.runtime_port,
            persistence_task=args.persistence_task,
            forbidden_context_ports=tuple(args.forbidden_context_port or (8765,)),
        )
    )


def _handle_credential_audit(args: argparse.Namespace) -> int:
    receipt = audit_credential_custody(
        state_root=args.state_root,
        credential_sources=args.credential_source,
    )
    output = write_credential_custody_receipt(args.output, receipt)
    _emit({**receipt, "output": str(output)})
    return 0 if receipt["status"] == "PASS" else 1


def _handle_zero_day_verify(args: argparse.Namespace) -> int:
    credential_sources = tuple(args.credential_source or ())
    if bool(credential_sources) != (args.credential_receipt is not None):
        raise ValueError("credential sources and receipt output must be supplied together")
    if args.output.exists() or (
        args.credential_receipt is not None and args.credential_receipt.exists()
    ):
        raise ValueError("zero-day witness outputs must be absent")
    witness = build_zero_day_final_witness(
        profile_path=args.profile,
        credential_source_paths=credential_sources,
        seed_build_receipt_path=args.seed_build_receipt,
        collector_result_paths=tuple(args.collector_result or ()),
        operation_manifest_path=args.operation_manifest,
        operation_receipt_path=args.operation_receipt,
        operation_evidence_directory=args.operation_evidence_directory,
        persistence_receipt_path=args.persistence_receipt,
        persistence_witness_path=args.persistence_witness,
        require_runtime=args.require_runtime,
        require_cold_start=args.require_cold_start,
        observed_at=args.observed_at,
    )
    credential_output: Path | None = None
    try:
        if args.credential_receipt is not None:
            credential_output = write_credential_custody_receipt(
                args.credential_receipt,
                witness["credential_custody"],
            )
        output = write_zero_day_final_witness(args.output, witness)
    except Exception:
        if credential_output is not None:
            credential_output.unlink(missing_ok=True)
        raise
    _emit(
        {
            "ok": witness["local_acceptance"] == "PASS",
            "result": witness["result"],
            "local_acceptance": witness["local_acceptance"],
            "output": str(output),
            "credential_receipt": (
                str(credential_output) if credential_output is not None else None
            ),
            "profile_id": witness["profile_id"],
            "source_digest": witness["seed"]["source_digest"],
            "catalog_digest": witness["seed"]["catalog_digest"],
            "event_count": witness["seed"]["event_count"],
            "unsatisfied_claims": witness["unsatisfied_claims"],
            "unproven_external_claims": witness["unproven_external_claims"],
            "operational_ready": False,
            "production_ready": False,
            "production_authority": False,
        }
    )
    return 0 if witness["local_acceptance"] == "PASS" else 1


def _handle_zero_day_seed_build(args: argparse.Namespace) -> int:
    receipt, output = build_and_write_fresh_zero_day_seed(
        profile_path=args.profile,
        collector_result_paths=args.collector_result,
        operation_manifest_path=args.operation_manifest,
        operation_receipt_path=args.operation_receipt,
        operation_evidence_directory=args.operation_evidence_directory,
        output_path=args.output,
    )
    _emit(
        {
            "ok": receipt["status"] == "PASS",
            "status": receipt["status"],
            "receipt_id": receipt["receipt_id"],
            "event_count": receipt["event_count"],
            "source_digest": receipt["source_digest"],
            "catalog_digest": receipt["catalog_digest"],
            "home_record_count": receipt["home_record_count"],
            "output": str(output),
            "production_authority": False,
        }
    )
    return 0 if receipt["status"] == "PASS" else 1


def _handle_operation_manifest_build(args: argparse.Namespace) -> None:
    spec = _read_object(args.spec, "operation specification")
    if set(spec) != {
        "tenant_id",
        "adapter_id",
        "target_node_id",
        "created_at",
        "operations",
    }:
        raise ValueError("operation specification field set rejected")
    manifest = build_readonly_operation_manifest(**spec)
    output = write_operation_document(
        args.output,
        manifest,
        schema="readonly-operation-manifest",
    )
    _emit(
        {
            "ok": True,
            "manifest_id": manifest["manifest_id"],
            "operation_count": len(manifest["operations"]),
            "output": str(output),
            "production_authority": False,
        }
    )


def _handle_operation_receipt_build(args: argparse.Namespace) -> int:
    manifest = load_operation_document(
        args.manifest,
        schema="readonly-operation-manifest",
    )
    results = _read_object(args.results, "operation results")
    if set(results) != {"operations"} or not isinstance(results["operations"], list):
        raise ValueError("operation results field set rejected")
    receipt = build_readonly_operation_receipt(
        manifest=manifest,
        results=results["operations"],
        observed_at=args.observed_at,
    )
    output = write_operation_document(
        args.output,
        receipt,
        schema="readonly-operation-receipt",
    )
    _emit(
        {
            "ok": receipt["status"] == "PASS",
            "status": receipt["status"],
            "receipt_id": receipt["receipt_id"],
            "outcome_counts": receipt["outcome_counts"],
            "unknown_outcome_count": receipt["unknown_outcome_count"],
            "output": str(output),
            "production_authority": False,
        }
    )
    return 0 if receipt["status"] == "PASS" else 1


def _handle_operation_run(args: argparse.Namespace) -> int:
    manifest = load_operation_document(
        args.manifest,
        schema="readonly-operation-manifest",
    )
    existing_output = private_output_reconciliation_status(
        args.output,
        expected_purpose="readonly-operation-receipt",
    )
    if existing_output["status"] == "UNKNOWN_OUTCOME":
        raise PrivateOutputReconciliationRequired(existing_output)
    if existing_output["status"] == "COMMITTED":
        raise LocalMachineError("operation output already contains a committed receipt")
    reservation = _reserve_private_output(
        args.output,
        "readonly-operation-receipt",
    )
    try:
        authorization = load_operation_document(
            args.authorization,
            schema="readonly-operation-authorization",
        )
        authority_key = trusted_key_from_value(
            args.authority_key_id,
            args.authority_public_key_file.read_text(encoding="ascii").strip(),
        )
        if public_key_fingerprint(authority_key.public_key) != args.authority_key_fingerprint:
            raise ValueError("operation authority fingerprint mismatch")
        receipt = execute_readonly_operation_manifest(
            manifest,
            authorization=authorization,
            authority_key=authority_key,
            at_time=args.at_time,
            evidence_directory=args.evidence_directory,
            observed_at=args.observed_at,
        )
        validate("readonly-operation-receipt", receipt)
        output = _commit_private_output_reservation(
            reservation,
            receipt,
        )
    except Exception as failure:
        if not reservation._consumed:
            _release_private_output_reservation(reservation)
        status = private_output_reconciliation_status(
            args.output,
            expected_purpose="readonly-operation-receipt",
        )
        if status["status"] == "UNKNOWN_OUTCOME":
            raise PrivateOutputReconciliationRequired(status) from failure
        raise
    _emit(
        {
            "ok": receipt["status"] == "PASS",
            "status": receipt["status"],
            "receipt_id": receipt["receipt_id"],
            "outcome_counts": receipt["outcome_counts"],
            "unknown_outcome_count": receipt["unknown_outcome_count"],
            "output": str(output),
            "evidence_directory": str(args.evidence_directory.absolute()),
            "production_authority": False,
        }
    )
    return 0 if receipt["status"] == "PASS" else 1


def _handle_private_output_status(args: argparse.Namespace) -> int:
    status = private_output_reconciliation_status(
        args.output,
        expected_purpose=args.purpose,
    )
    _emit(status)
    return 2 if status["status"] == "UNKNOWN_OUTCOME" else 0


def _handle_windows_assets_export(args: argparse.Namespace) -> None:
    _emit(export_windows_assets(args.output_directory))


def _handle_windows_assets_verify(args: argparse.Namespace) -> None:
    manifest = load_windows_asset_manifest(args.manifest)
    _emit(
        verify_windows_asset_manifest(
            manifest,
            assets_directory=args.assets_directory,
        )
    )


def _handle_windows_host_profile(args: argparse.Namespace) -> None:
    profile = build_windows_host_collector_profile(
        executable=args.executable,
        tenant_id=args.tenant_id,
        collector_id=args.collector_id,
        node_id=args.node_id,
    )
    output = write_windows_host_collector_profile(args.output, profile)
    profile_digest = "sha256:" + hashlib.sha256(output.read_bytes()).hexdigest()
    _emit(
        {
            "ok": True,
            "output": str(output),
            "profile_digest": profile_digest,
            "executable_digest": profile["executable_digest"],
            "production_authority": False,
        }
    )


def _handle_private_document_store(args: argparse.Namespace) -> None:
    output = store_private_document(
        input_path=args.input,
        output_path=args.output,
        schema=args.schema,
    )
    _emit(
        {
            "ok": True,
            "schema": args.schema,
            "output": str(output),
            "production_authority": False,
        }
    )


def _handle_private_document_read(args: argparse.Namespace) -> None:
    _emit(load_private_document(path=args.path, schema=args.schema))


def _handle_version(args: argparse.Namespace) -> None:
    if args.all:
        _emit(lts_version_report(expected_product_version=__version__))
        return
    _emit(
        {
            "product": "Integrity Guardian",
            "version": __version__,
            "production_authority": False,
        }
    )


def _handle_capabilities(_: argparse.Namespace) -> None:
    _emit(integrity_capabilities(__version__))


def _handle_lts_contracts(_: argparse.Namespace) -> None:
    _emit(lts_contract_report())


def _handle_lts_release_index_build(args: argparse.Namespace) -> None:
    index = build_lts_release_index(
        source_revision=args.source_revision,
        artifact_path=args.artifact_path,
        created_at=args.created_at,
        expected_product_version=__version__,
    )
    output = write_lts_release_index(args.output, index)
    _emit(
        {
            "ok": True,
            "status": index["release"]["status"],
            "release_id": index["release"]["release_id"],
            "version": index["release"]["version"],
            "matrix_digest": index["matrix_digest"],
            "output": str(output),
            "production_authority": False,
            "memory_grants_authority": False,
        }
    )


def _handle_lts_release_index_verify(args: argparse.Namespace) -> None:
    manifest = parse_json_strict(args.manifest.read_bytes())
    validate("release-manifest", manifest)
    public_key_value = args.authority_public_key_file.read_text(encoding="ascii").strip()
    authority_key = trusted_key_from_value(args.authority_key_id, public_key_value)
    actual_fingerprint = public_key_fingerprint(authority_key.public_key)
    if actual_fingerprint != args.authority_key_fingerprint:
        raise ValueError("release authority fingerprint mismatch")

    native_inputs = (
        args.native_trust_genesis,
        args.native_release_enrollment,
        args.native_trust_instance_id,
        args.native_root_key_fingerprint,
    )
    if any(value is not None for value in native_inputs):
        if not all(value is not None for value in native_inputs):
            raise ValueError("native release trust inputs must be supplied together")
        from .native_trust import verify_native_release_authority_enrollment

        genesis = parse_json_strict(args.native_trust_genesis.read_bytes())
        enrollment = parse_json_strict(args.native_release_enrollment.read_bytes())
        native_authority = verify_native_release_authority_enrollment(
            enrollment,
            genesis=genesis,
            expected_instance_id=args.native_trust_instance_id,
            expected_root_fingerprint=args.native_root_key_fingerprint,
        )
        if (
            native_authority.key_id != authority_key.key_id
            or public_key_fingerprint(native_authority.public_key) != actual_fingerprint
        ):
            raise ValueError("native release authority does not match the manifest key")

    # Authenticate before following any artifact path supplied by the manifest.
    authenticate_release_manifest(
        manifest,
        authority_key=authority_key,
        expected_source_revision=args.source_revision,
    )
    artifact_root = args.artifact_root.absolute()
    try:
        index_artifact_path = args.index.absolute().relative_to(artifact_root).as_posix()
    except ValueError as exc:
        raise ValueError("release index escaped the artifact root") from exc
    artifacts = build_artifact_inventory(
        artifact_root,
        [artifact_root / item["path"] for item in manifest["artifacts"]],
    )
    index = parse_json_strict(args.index.read_bytes())
    report = verify_lts_release_index(
        index,
        release_manifest=manifest,
        authority_key=authority_key,
        expected_source_revision=args.source_revision,
        expected_product_version=__version__,
        expected_artifacts=artifacts,
        index_artifact_path=index_artifact_path,
    )
    _emit({**report, "authority_key_fingerprint": actual_fingerprint})


def _handle_lts_activation_build(args: argparse.Namespace) -> None:
    receipt = build_lts_track_activation_receipt(
        track_id=args.track_id,
        release_id=args.release_id,
        release_version=args.release_version,
        release_tag=args.release_tag,
        product_version=__version__,
        source_revision=args.source_revision,
        artifact_path=args.artifact_path,
        activated_at=args.activated_at,
        support_until=args.support_until,
        reproducible_artifacts_digest=args.reproducible_artifacts_digest,
        local_suite_digest=args.local_suite_digest,
        hosted_linux_digest=args.hosted_linux_digest,
        track_gate_digest=args.track_gate_digest,
        release_review_digest=args.release_review_digest,
    )
    output = write_lts_track_activation_receipt(args.output, receipt)
    _emit(
        {
            "ok": True,
            "track_id": receipt["track_id"],
            "status": "lts-candidate",
            "output": str(output),
            "production_authority": False,
            "memory_grants_authority": False,
        }
    )


def _handle_lts_activation_verify(args: argparse.Namespace) -> None:
    receipt = parse_json_strict(args.receipt.read_bytes())
    manifest = parse_json_strict(args.manifest.read_bytes())
    validate("release-manifest", manifest)
    public_key_value = args.authority_public_key_file.read_text(encoding="ascii").strip()
    authority_key = trusted_key_from_value(args.authority_key_id, public_key_value)
    actual_fingerprint = public_key_fingerprint(authority_key.public_key)
    if actual_fingerprint != args.authority_key_fingerprint:
        raise ValueError("release authority fingerprint mismatch")
    native_inputs = (
        args.native_trust_genesis,
        args.native_release_enrollment,
        args.native_trust_instance_id,
        args.native_root_key_fingerprint,
    )
    if any(value is not None for value in native_inputs):
        if not all(value is not None for value in native_inputs):
            raise ValueError("native release trust inputs must be supplied together")
        from .native_trust import verify_native_release_authority_enrollment

        genesis = parse_json_strict(args.native_trust_genesis.read_bytes())
        enrollment = parse_json_strict(args.native_release_enrollment.read_bytes())
        native_authority = verify_native_release_authority_enrollment(
            enrollment,
            genesis=genesis,
            expected_instance_id=args.native_trust_instance_id,
            expected_root_fingerprint=args.native_root_key_fingerprint,
        )
        if (
            native_authority.key_id != authority_key.key_id
            or public_key_fingerprint(native_authority.public_key) != actual_fingerprint
        ):
            raise ValueError("native release authority does not match the manifest key")
    authenticate_release_manifest(
        manifest,
        authority_key=authority_key,
        expected_source_revision=args.source_revision,
    )
    artifact_root = args.artifact_root.absolute()
    try:
        receipt_artifact_path = args.receipt.absolute().relative_to(artifact_root).as_posix()
    except ValueError as exc:
        raise ValueError("activation receipt escaped the artifact root") from exc
    artifacts = build_artifact_inventory(
        artifact_root,
        [artifact_root / item["path"] for item in manifest["artifacts"]],
    )
    report = verify_lts_track_activation(
        receipt,
        release_manifest=manifest,
        authority_key=authority_key,
        expected_source_revision=args.source_revision,
        expected_product_version=__version__,
        expected_artifacts=artifacts,
        receipt_artifact_path=receipt_artifact_path,
    )
    _emit({**report, "authority_key_fingerprint": actual_fingerprint})


def _handle_platform_profile(_: argparse.Namespace) -> None:
    _emit(build_platform_profile(__version__))


def _handle_governance_verify(_: argparse.Namespace) -> None:
    result = verify_governance_bundle()
    _emit(
        {
            "ok": True,
            "status": "VERIFIED",
            "digest": result["digest"],
            "document_count": result["document_count"],
            "production_authority": False,
        }
    )


def _handle_tenant_init(args: argparse.Namespace) -> None:
    supplied_digests = (
        args.retention_policy_digest is not None,
        args.key_registry_digest is not None,
    )
    if args.unenrolled:
        if any(supplied_digests):
            raise ValueError("--unenrolled cannot be combined with registry digests")
        profile = build_unenrolled_tenant_profile(
            tenant_id=args.tenant_id,
            deployment_id=args.deployment_id,
            created_at=args.created_at,
        )
    else:
        if not all(supplied_digests):
            raise ValueError("both registry digests are required unless --unenrolled is explicit")
        profile = build_tenant_profile(
            tenant_id=args.tenant_id,
            deployment_id=args.deployment_id,
            retention_policy_digest=args.retention_policy_digest,
            key_registry_digest=args.key_registry_digest,
            created_at=args.created_at,
        )
    workspace = TenantWorkspace(args.state_root.absolute(), args.tenant_id)
    workspace.initialize(profile)
    enrollment = tenant_enrollment_status(profile)
    governance = verify_tenant_governance(profile)
    _emit(
        {
            "ok": True,
            "status": f"INITIALIZED_{enrollment}",
            "coverage": "UNKNOWN",
            "enrollment": enrollment,
            "tenant_id": args.tenant_id,
            "namespace": workspace.namespace,
            "governance": governance,
            "production_authority": False,
        }
    )


def _handle_native_trust_bootstrap(args: argparse.Namespace) -> None:
    """Initialize native trust or migrate exact existing architecture custody."""

    from .ledger import LedgerStore
    from .medor_architecture import CUSTODY_LEDGER_ID, TENANT_ID
    from .native_trust import NativeTrustStore, load_ed25519_seed

    state_root = args.state_root.absolute()
    architecture_root = args.architecture_root.absolute()
    if architecture_root.is_symlink():
        raise ValueError("native architecture root must not be a symlink")
    architecture_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    store = NativeTrustStore(state_root, instance_id=args.instance_id)
    genesis = store.bootstrap()
    store.ensure_local_transport_device(device_id=args.device_id)
    database_path = architecture_root / "guardian-architecture.sqlite3"
    checkpoint_path = architecture_root / "guardian-architecture-checkpoint.json"
    tenant_id = TENANT_ID
    ledger_id = CUSTODY_LEDGER_ID
    populated = False
    already_bound = False
    if database_path.exists():
        with LedgerStore(
            database_path,
            tenant_id=tenant_id,
            ledger_id=ledger_id,
        ) as ledger:
            populated = bool(ledger.events())
            already_bound = ledger.native_trust_enrollment() is not None
    migration_receipt = None
    if populated and not already_bound:
        if (
            args.legacy_source_key is None
            or args.legacy_checkpoint_key is None
            or not checkpoint_path.exists()
            or checkpoint_path.is_symlink()
        ):
            raise ValueError("populated architecture requires legacy keys and exact checkpoint")
        checkpoint = parse_json_strict(checkpoint_path.read_bytes())
        if not isinstance(checkpoint, dict):
            raise ValueError("legacy architecture checkpoint is invalid")
        migration_receipt = store.migrate_existing_database(
            database_path=database_path,
            tenant_id=tenant_id,
            ledger_id=ledger_id,
            source_key_id="key:medor-architecture-source",
            source_seed=load_ed25519_seed(args.legacy_source_key),
            checkpoint_key_id="key:medor-architecture-checkpoint",
            checkpoint_seed=load_ed25519_seed(args.legacy_checkpoint_key),
            checkpoint=checkpoint,
        )
        outcome = "migrated-existing-exact-chain"
    else:
        keys = store.ensure_database(tenant_id=tenant_id, ledger_id=ledger_id)
        with LedgerStore(
            database_path,
            tenant_id=tenant_id,
            ledger_id=ledger_id,
        ) as ledger:
            ledger.bind_native_trust(
                keys.enrollment,
                issuer_key=store.trusted_key("ledger-issuer"),
            )
        outcome = "verified-existing-native" if already_bound else "initialized-native"
    _emit(
        {
            "ok": True,
            "status": outcome,
            "instance_id": args.instance_id,
            "genesis_id": genesis["genesis_id"],
            "database": str(database_path),
            "migration_receipt_id": (
                migration_receipt["receipt_id"] if migration_receipt is not None else None
            ),
            "history_rewritten": False,
            "trust_profile": "personal-native",
            "production_authority": False,
        }
    )


def _handle_native_device_request(args: argparse.Namespace) -> None:
    from .native_trust import initialize_native_device_request

    request = initialize_native_device_request(
        args.state_root,
        instance_id=args.instance_id,
        device_id=args.device_id,
        scopes=tuple(args.scope or ("memory.read",)),
    )
    _emit(request)


def _handle_native_release_authority_init(args: argparse.Namespace) -> None:
    """Initialize durable release custody under one native instance root."""

    from .native_trust import NativeTrustStore

    store = NativeTrustStore(args.state_root, instance_id=args.instance_id)
    genesis = store.bootstrap()
    authority = store.ensure_release_authority()
    _emit(
        {
            "ok": True,
            "status": "verified-existing-native-release-authority",
            "instance_id": args.instance_id,
            "genesis_id": genesis["genesis_id"],
            "enrollment_id": authority.enrollment["enrollment_id"],
            "authority_key_id": authority.signer.key_id,
            "authority_key_fingerprint": public_key_fingerprint(authority.signer.public_key),
            "backend": genesis["backend"],
            "production_authority": False,
            "memory_grants_authority": False,
        }
    )


def _handle_native_device_enroll(args: argparse.Namespace) -> None:
    from .native_trust import NativeTrustStore

    request = parse_json_strict(args.request.read_bytes())
    if not isinstance(request, dict):
        raise TypeError("native device enrollment request is invalid")
    store = NativeTrustStore(args.state_root, instance_id=args.instance_id)
    store.verify_genesis()
    enrollment = store.enroll_device_request(request)
    _emit(enrollment)


def _handle_native_module_enroll(args: argparse.Namespace) -> None:
    from .native_trust import NativeTrustStore

    store = NativeTrustStore(args.state_root, instance_id=args.instance_id)
    store.verify_genesis()
    enrollment = store.enroll_module(
        module_id=args.module_id,
        artifact_digest=args.artifact_digest,
        scopes=tuple(args.scope or ("memory.read",)),
    )
    _emit(enrollment)


def _handle_tenant_verify(args: argparse.Namespace) -> None:
    workspace = TenantWorkspace(args.state_root.absolute(), args.tenant_id)
    profile = workspace.verify()
    enrollment = tenant_enrollment_status(profile)
    preflight = args.command == "agent-preflight"
    policy_authority_key = None
    at_time = None
    if preflight:
        trust_inputs = (
            args.policy_authority_key_id,
            args.policy_authority_public_key_file,
            args.policy_authority_key_fingerprint,
            args.at_time,
        )
        if any(value is not None for value in trust_inputs):
            if not all(value is not None for value in trust_inputs):
                raise ValueError("agent-preflight policy trust inputs must be supplied together")
            public_key_value = args.policy_authority_public_key_file.read_text(
                encoding="ascii"
            ).strip()
            policy_authority_key = trusted_key_from_value(
                args.policy_authority_key_id,
                public_key_value,
            )
            actual_fingerprint = public_key_fingerprint(policy_authority_key.public_key)
            if actual_fingerprint != args.policy_authority_key_fingerprint:
                raise ValueError("customer policy authority fingerprint mismatch")
            at_time = args.at_time
    governance = verify_tenant_governance(
        profile,
        policy_authority_key=policy_authority_key,
        at_time=at_time,
    )
    onboarding_ready = governance["product_bundle"] == "BOUND"
    operational_ready = (
        onboarding_ready
        and enrollment == "ENROLLED"
        and governance["customer_policy"] == "VERIFIED"
    )
    _emit(
        {
            "ok": True,
            "status": "VERIFIED",
            "coverage": "UNKNOWN",
            "enrollment": enrollment,
            "tenant_id": profile["tenant_id"],
            "namespace": profile["namespace"],
            "governance": governance,
            "production_authority": False,
            "agent_ready": operational_ready if preflight else False,
            "onboarding_ready": onboarding_ready if preflight else False,
            "operational_ready": operational_ready,
        }
    )


def _handle_tenant_audit(args: argparse.Namespace) -> None:
    workspace = TenantWorkspace(args.state_root.absolute(), args.tenant_id)
    audit = workspace.audit(expected_windows_owner_sid=args.expected_owner_sid)
    profile = audit["profile"]
    governance = verify_tenant_governance(profile)
    _emit(
        {
            "ok": True,
            "status": "AUDITED",
            "audit_only": True,
            "tenant_id": profile["tenant_id"],
            "namespace": profile["namespace"],
            "enrollment": tenant_enrollment_status(profile),
            "governance": governance,
            "custody": audit["custody"],
            "production_authority": False,
        }
    )


def _handle_collector_run(args: argparse.Namespace) -> None:
    result = run_collector(load_profile(args.profile, args.profile_digest))
    output = write_collector_result(args.output_directory, result)
    _emit(
        {
            "ok": True,
            "output": str(output),
            "result_id": result["result_id"],
            "fact_count": result["receipt"]["fact_count"],
            "production_authority": False,
            "production_mutated": "UNKNOWN",
        }
    )


def _handle_release_verify(args: argparse.Namespace) -> None:
    manifest = parse_json_strict(args.manifest.read_bytes())
    validate("release-manifest", manifest)
    public_key_value = args.authority_public_key_file.read_text(encoding="ascii").strip()
    authority_key = trusted_key_from_value(
        args.authority_key_id,
        public_key_value,
    )
    actual_fingerprint = public_key_fingerprint(authority_key.public_key)
    if actual_fingerprint != args.authority_key_fingerprint:
        raise ValueError("release authority fingerprint mismatch")
    authenticate_release_manifest(
        manifest,
        authority_key=authority_key,
        expected_source_revision=args.source_revision,
    )
    artifact_root = args.artifact_root
    artifacts = build_artifact_inventory(
        artifact_root,
        [artifact_root / item["path"] for item in manifest["artifacts"]],
    )
    manifest_digest = verify_release_manifest(
        manifest,
        authority_key=authority_key,
        expected_source_revision=args.source_revision,
        expected_artifacts=artifacts,
    )
    _emit(
        {
            "ok": True,
            "version": manifest["version"],
            "source_revision": manifest["source_revision"],
            "source_tree_digest": manifest["source_tree_digest"],
            "artifact_count": manifest["artifact_count"],
            "release_manifest_digest": manifest_digest,
            "authority_key_fingerprint": actual_fingerprint,
            "production_authority": False,
        }
    )


def _handle_anchor_init(args: argparse.Namespace) -> None:
    subject = _read_object(args.subject_file, "anchor subject")
    with ObserverAnchorStore.initialize(
        args.root,
        store_id=args.store_id,
        subject_kind=args.subject_kind,
        subject=subject,
        created_at=args.created_at,
    ) as store:
        _emit(_anchor_result(store))


def _handle_anchor_verify(args: argparse.Namespace) -> None:
    if args.cursor_file is None and not args.allow_unpinned_availability_recovery:
        raise ValueError(
            "--cursor-file is required unless explicit unpinned availability recovery is selected"
        )
    cursor = (
        ObserverAnchorCursor.from_document(_read_object(args.cursor_file, "anchor cursor"))
        if args.cursor_file is not None
        else None
    )
    with ObserverAnchorStore.open(
        args.root,
        store_id=args.store_id,
        expected_cursor=cursor,
        allow_unpinned_availability_recovery=(args.allow_unpinned_availability_recovery),
    ) as store:
        _emit(_anchor_result(store))


def _handle_anchor_advance(args: argparse.Namespace) -> None:
    subject = _read_object(args.subject_file, "anchor subject")
    cursor = ObserverAnchorCursor.from_document(_read_object(args.cursor_file, "anchor cursor"))
    with ObserverAnchorStore.open(
        args.root,
        store_id=args.store_id,
        expected_cursor=cursor,
    ) as store:
        store.advance(
            expected_cursor=cursor,
            subject_kind=args.subject_kind,
            subject=subject,
            created_at=args.created_at,
        )
        _emit(_anchor_result(store))


def _handle_seed_build(args: argparse.Namespace) -> None:
    report = catalog_from_jsonl(
        events_path=args.events_jsonl,
        catalog_path=args.catalog,
        profile=args.profile,
        source_namespace=args.source_namespace,
    )
    _emit(report.to_document())


def _handle_seed_sync(args: argparse.Namespace) -> None:
    catalog = SeedCatalog(args.catalog)
    snapshot, report = sync_action_log_seed(
        catalog,
        base_url=args.source_url,
        profile=args.profile,
        page_size=args.page_size,
        source_namespace=args.source_namespace,
    )
    if args.export_events is not None:
        write_events_jsonl(
            args.export_events,
            list(iter_catalog_events(args.catalog)),
        )
    _emit(
        {
            **report.to_document(),
            "source_url": snapshot.source_url,
            "event_cursor": snapshot.maximum_event_id,
            "previous_event_cursor": snapshot.previous_event_id,
            "fetched_event_count": len(snapshot.events),
            "full_snapshot": snapshot.full_snapshot,
            "stabilization_passes": snapshot.stabilization_passes,
            "events_exported": args.export_events is not None,
            "events_export_path": (
                str(args.export_events.absolute()) if args.export_events is not None else None
            ),
        }
    )


def _handle_seed_verify(args: argparse.Namespace) -> None:
    _emit(
        SeedCatalog(args.catalog).verify(
            expected_source_digest=args.expected_source_digest,
            expected_event_count=args.expected_event_count,
        )
    )


def _handle_seed_status(args: argparse.Namespace) -> None:
    _emit(SeedCatalog(args.catalog).status())


def _handle_seed_capsule(args: argparse.Namespace) -> None:
    capsule = SeedCatalog(args.catalog).capsule(active_limit=args.active_limit)
    if args.context:
        print(capsule["context_text"], end="")
    else:
        _emit(capsule)


def _handle_seed_search(args: argparse.Namespace) -> None:
    results = SeedCatalog(args.catalog).search(args.query, limit=args.limit)
    _emit(
        {
            "ok": True,
            "query": args.query,
            "count": len(results),
            "events": results,
            "production_authority": False,
        }
    )


def _handle_seed_connections(args: argparse.Namespace) -> None:
    _emit(
        explain_seed_event_connections(
            catalog_path=args.catalog,
            event_id=args.event_id,
            evidence_root=args.evidence_root,
            evidence_source_prefix=args.evidence_source_prefix,
            limit=args.limit,
            include_contextual=args.include_contextual,
        )
    )


def _handle_memory_link_resolve(args: argparse.Namespace) -> None:
    graph = MemoryLinkGraph.from_catalog(args.catalog, project_slug=args.project_slug)
    _emit(
        graph.resolve(
            args.reference,
            limit=args.limit,
            max_context_bytes=args.max_context_bytes,
            cursor=args.cursor,
        )
    )


def _load_memory_ttt_path_catalog(
    path: Path | None,
    expected_digest: str | None,
) -> RunbookPathCatalog:
    try:
        return load_runbook_path_catalog(path, expected_digest)
    except (MemoryTttPathError, OSError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc


def _handle_memory_ttt_autofill(args: argparse.Namespace) -> None:
    paths = _load_memory_ttt_path_catalog(
        args.path_catalog,
        args.expected_path_catalog_digest,
    )
    graph = None
    if args.catalog is not None:
        graph = MemoryLinkGraph.from_catalog(args.catalog, project_slug=args.project_slug)
    if args.list_paths:
        _emit(memory_ttt_list_paths(catalog=paths, graph=graph))
        return
    if not args.goal or not args.last_hop:
        raise SystemExit("memory-ttt-autofill requires --goal and --last-hop (or --list-paths)")
    _emit(
        memory_ttt_autofill(
            args.goal,
            args.last_hop,
            graph=graph,
            snapshot_id=args.snapshot_id,
            expected_graph_digest=args.expected_graph_digest,
            catalog=paths,
        )
    )


def _handle_memory_entity_brief(args: argparse.Namespace) -> None:
    graph = MemoryLinkGraph.from_catalog(args.catalog, project_slug=args.project_slug)
    _emit(
        graph.entity_brief(
            args.reference,
            relationship_limit=args.relationship_limit,
            activity_limit=args.activity_limit,
            task_limit=args.task_limit,
            discovery_limit=args.discovery_limit,
            max_context_bytes=args.max_context_bytes,
        )
    )


def _handle_memory_link_audit(args: argparse.Namespace) -> None:
    graph = MemoryLinkGraph.from_catalog(args.catalog, project_slug=args.project_slug)
    _emit(
        graph.audit(
            kinds=args.kind,
            limit=args.limit,
            max_context_bytes=args.max_context_bytes,
            cursor=args.cursor,
        )
    )


def _handle_memory_link_context(args: argparse.Namespace) -> None:
    graph = MemoryLinkGraph.from_catalog(args.catalog, project_slug=args.project_slug)
    _emit(
        graph.context_pack(
            args.anchor,
            direction=args.direction,
            relations=args.relation,
            max_depth=args.max_depth,
            max_nodes=args.max_nodes,
            max_links=args.max_links,
            max_context_bytes=args.max_context_bytes,
        )
    )


def _handle_memory_link_navigate(args: argparse.Namespace) -> None:
    graph = MemoryLinkGraph.from_catalog(args.catalog, project_slug=args.project_slug)
    _emit(
        graph.navigate(
            args.anchor,
            direction=args.direction,
            relations=args.relation,
            trail=args.trail,
            limit=args.limit,
            max_context_bytes=args.max_context_bytes,
            cursor=args.cursor,
        )
    )


def _handle_seed_serve(args: argparse.Namespace) -> None:
    serve_seed_runtime(
        catalog_path=args.catalog,
        host=args.host,
        port=args.port,
        evidence_root=args.evidence_root,
        evidence_source_prefix=args.evidence_source_prefix,
    )


def _handle_file_command(args: argparse.Namespace) -> None:
    value = parse_json_strict(args.file.read_bytes())
    if args.command == "canonicalize":
        print(canonical_bytes(value).decode("utf-8"))
    elif args.command == "digest":
        print(digest_object(value, domain=args.domain))
    else:
        validate(args.schema, value)
        _emit({"ok": True, "schema": args.schema})


_HANDLERS: dict[str, Any] = {
    "status": _handle_status,
    "version": _handle_version,
    "capabilities": _handle_capabilities,
    "lts-contracts": _handle_lts_contracts,
    "lts-release-index-build": _handle_lts_release_index_build,
    "lts-release-index-verify": _handle_lts_release_index_verify,
    "lts-activation-build": _handle_lts_activation_build,
    "lts-activation-verify": _handle_lts_activation_verify,
    "platform-profile": _handle_platform_profile,
    "governance-verify": _handle_governance_verify,
    "native-device-enroll": _handle_native_device_enroll,
    "native-device-request": _handle_native_device_request,
    "native-module-enroll": _handle_native_module_enroll,
    "native-release-authority-init": _handle_native_release_authority_init,
    "native-trust-bootstrap": _handle_native_trust_bootstrap,
    "tenant-init": _handle_tenant_init,
    "tenant-verify": _handle_tenant_verify,
    "tenant-audit": _handle_tenant_audit,
    "agent-preflight": _handle_tenant_verify,
    "collector-run": _handle_collector_run,
    "release-verify": _handle_release_verify,
    "observer-anchor-init": _handle_anchor_init,
    "observer-anchor-verify": _handle_anchor_verify,
    "observer-anchor-advance": _handle_anchor_advance,
    "seed-catalog-build": _handle_seed_build,
    "seed-sync": _handle_seed_sync,
    "seed-catalog-verify": _handle_seed_verify,
    "seed-status": _handle_seed_status,
    "seed-capsule": _handle_seed_capsule,
    "seed-search": _handle_seed_search,
    "seed-connections": _handle_seed_connections,
    "memory-entity-brief": _handle_memory_entity_brief,
    "memory-link-audit": _handle_memory_link_audit,
    "memory-link-context": _handle_memory_link_context,
    "memory-link-resolve": _handle_memory_link_resolve,
    "memory-link-navigate": _handle_memory_link_navigate,
    "memory-ttt-autofill": _handle_memory_ttt_autofill,
    "seed-serve": _handle_seed_serve,
    "machine-init": _handle_machine_init,
    "credential-audit": _handle_credential_audit,
    "zero-day-verify": _handle_zero_day_verify,
    "zero-day-seed-build": _handle_zero_day_seed_build,
    "operation-manifest-build": _handle_operation_manifest_build,
    "operation-receipt-build": _handle_operation_receipt_build,
    "operation-run": _handle_operation_run,
    "private-output-status": _handle_private_output_status,
    "windows-assets-export": _handle_windows_assets_export,
    "windows-assets-verify": _handle_windows_assets_verify,
    "windows-host-profile": _handle_windows_host_profile,
    "private-document-store": _handle_private_document_store,
    "private-document-read": _handle_private_document_read,
}


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handler = _HANDLERS.get(args.command, _handle_file_command)
    try:
        result = handler(args)
    except PrivateOutputReconciliationRequired as exc:
        _emit(exc.status)
        return 2
    return result if isinstance(result, int) else 0


if __name__ == "__main__":
    raise SystemExit(main())
