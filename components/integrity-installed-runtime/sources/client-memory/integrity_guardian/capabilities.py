"""Deterministic product capability and maturity inventory."""

from __future__ import annotations

from typing import Any

from .lts import verify_lts_contracts


def integrity_capabilities(version: str) -> dict[str, Any]:
    """Return the closed operator-facing capability map for this artifact."""

    lts_contract = verify_lts_contracts()
    return {
        "protocol": "integrity-guardian/capability-inventory/v1",
        "product": "Integrity Guardian",
        "version": version,
        "release_channel": "stable",
        "modules": [
            {
                "module": "guardian-core",
                "status": "implemented",
                "capability": "offline evidence verification and reconciliation",
                "execution": False,
            },
            {
                "module": "native-trust-bootstrap",
                "status": "1.0.0-candidate.2-source-candidate",
                "capability": (
                    "native first initialization with OS-generated Ed25519 identity, "
                    "proof-of-possession device requests, issuer-signed database/device/"
                    "module enrollment, cached session leases, exact legacy-chain "
                    "migration without history rewrite and "
                    "a replaceable file, TPM, HSM or managed signer backend"
                ),
                "execution": True,
            },
            {
                "module": "integrity-seed-runtime",
                "status": "linux-live-windows-rc7-local-seed-pass-rc8-source-candidate",
                "capability": (
                    "lossless canonical project-memory catalog, deterministic "
                    "entity/relation/task/lock/topic projections and a bounded "
                    "read-only mission capsule; Integrity Home is excluded"
                ),
                "execution": False,
            },
            {
                "module": "memory-synapse-lts",
                "status": "source-complete-native-trust-activation-pending",
                "capability": (
                    "versioned canonical Seed snapshots, explainable direct/supported/"
                    "contextual SeedRelationshipIndex links, independent raw-Seed "
                    "verification and deterministic no-reroll cold replay; Home remains "
                    "a separate read-only source"
                ),
                "execution": False,
            },
            {
                "module": "memory-link-graph",
                "status": "v1-source-candidate",
                "capability": (
                    "rebuildable canonical Seed term registry with stable integrity:// "
                    "URIs, exact alias disambiguation, digest-bound outbound/backlink "
                    "adjacency, byte-bounded cursor navigation, path-preserving multi-hop "
                    "context packs, plus optional entity briefs with provenance-bound "
                    "definitions, claim freshness, canonical task lifecycle, bounded "
                    "activity and unadmitted legacy discovery candidates, and a paginated "
                    "curation-debt audit that never auto-applies suggestions; exposed through "
                    "a run-id-bound loopback read API for large agent memory with no "
                    "persistent second store or authority"
                ),
                "execution": False,
            },
            {
                "module": "receipt-bound-task-closure",
                "status": "source-candidate",
                "capability": (
                    "hash-linked owner instructions with phase-local constraints, "
                    "single-attempt terminal Action Log append classification, "
                    "content-free exact-UID reconciliation and a mandatory numeric "
                    "event receipt before task completion"
                ),
                "execution": False,
            },
            {
                "module": "turn-memory-receipt",
                "status": "source-candidate",
                "capability": (
                    "globally registered machine/thread/turn coverage with a stable "
                    "Seed trust-lineage namespace fingerprint, Ed25519-signed terminal "
                    "Seed-event or no-event receipts, exact replay, conflict denial and "
                    "visible non-terminal coverage debt when closure is omitted"
                ),
                "execution": False,
            },
            {
                "module": "zero-day-local-bootstrap",
                "status": "rc7-live-pass-rc8-source-candidate",
                "capability": (
                    "create a fresh machine-local Seed from exact collector and "
                    "operation evidence without importing remote memory or Home"
                ),
                "execution": False,
            },
            {
                "module": "bounded-owner-approved-operation-runner",
                "status": "rc7-live-network-read-pass-rc8-source-candidate",
                "capability": (
                    "execute externally authorized, exact precommitted argv without a shell, "
                    "retain bounded streams and prohibit automatic retry after "
                    "unknown outcome; semantic read-only status is not inferred"
                ),
                "execution": True,
            },
            {
                "module": "windows-first-party-host-observer",
                "status": "rc7-live-host-observation-pass-rc8-source-candidate",
                "capability": (
                    "manifest-bound compiler, host/interface/route collector, "
                    "digest-pinned profile and private result custody"
                ),
                "execution": True,
            },
            {
                "module": "windows-loopback-seed-persistence",
                "status": "rc7-pre-reboot-pass-atlogon-pending-rc8-source-candidate",
                "capability": (
                    "hidden least-privilege AtLogOn runtime with exact semantic "
                    "install, reboot witness and rollback-capable removal receipts"
                ),
                "execution": True,
            },
            {
                "module": "winops-zero-day-reset-receipt",
                "status": "rc8-open-client-preflight-pass-rc7-live-recovered-no-replay",
                "capability": (
                    "monotonic private terminal receipt creation plus exact-plan, "
                    "postcondition-only reconciliation after an unknown receipt; "
                    "reconciliation never replays the destructive action"
                ),
                "execution": True,
            },
            {
                "module": "guardian-cyber",
                "status": "implemented-pure-evaluator",
                "capability": "interpret already collected verified facts",
                "execution": False,
            },
            {
                "module": "atlas",
                "status": "development-candidate",
                "capability": "deterministic evidence projection and routing receipts",
                "execution": False,
            },
            {
                "module": "agent-handoff-evidence",
                "status": "local-linearizable-candidate",
                "capability": (
                    "signed predecessor checkpoint, shadow successor ACK, "
                    "SQLite atomic head CAS, monotonic fencing and no-retry "
                    "COMMIT_UNKNOWN reconciliation"
                ),
                "execution": False,
            },
            {
                "module": "synapse-connectome",
                "status": "offline-development-candidate",
                "capability": "compile, plan and simulate capability routes",
                "execution": False,
            },
            {
                "module": "fog-of-war",
                "status": "alpha",
                "capability": (
                    "digest-only lifecycle-separated passive adapters, "
                    "controller-bound boot epochs and external checkpoint "
                    "candidates, signed discovery, synchronized cohorts, "
                    "unknown taxonomy and route theory"
                ),
                "execution": False,
            },
            {
                "module": "uroboros-route-memory",
                "status": "alpha",
                "capability": "cursor-pinned local Toolz route memory",
                "execution": False,
            },
            {
                "module": "uroboros-one-use-authority",
                "status": "alpha",
                "capability": "single-transition decision and anti-replay consumption",
                "execution": False,
            },
            {
                "module": "independent-action-outcome-observer",
                "status": "alpha",
                "capability": "post-consumption state classification without causality claim",
                "execution": False,
            },
            {
                "module": "adapter-sdk",
                "status": "1.0.0a2-target-adapter-candidate",
                "capability": (
                    "adapter-neutral capability, proposal, signed typed-operation "
                    "and executor binding, consumed-grant envelope and five-state "
                    "independently witnessed transition receipt contracts"
                ),
                "execution": False,
            },
            {
                "module": "adapter-sdk-conformance",
                "status": "proof-contract-1.0-source-target-portfolio",
                "capability": (
                    "signed manifest-derived proof profiles, content-free test evidence "
                    "and fail-closed source/target/portfolio receipts across the closed "
                    "ASDK proof contract, plus a separate exact Linux/Windows/macOS "
                    "install/upgrade/revoke/recovery portability receipt gate; native "
                    "platform evidence remains external and conformance is never "
                    "execution authority"
                ),
                "execution": False,
            },
            {
                "module": "adapter-sdk-contained-runtime",
                "status": "1.0.0a2-conformance-admitted-local-synthetic-only",
                "capability": (
                    "mandatory source-ready conformance admission, checkpoint-pinned "
                    "signed conformance/operation/executor binding, append-only attempt "
                    "journal, coordinator-signed durable dispatch registry and "
                    "checkpoint-proven one-shot permit, plus digest-pinned "
                    "shell=false local child fixture; no network, credentials or "
                    "production target"
                ),
                "execution": True,
            },
            {
                "module": "workspace-patch-adapter",
                "status": "1.0.0a2-target-live-non-production-candidate",
                "capability": (
                    "typed tracked-text Git patch with exact worktree and tree identity, "
                    "path blast radius, bwrap network isolation, one-use dispatch and "
                    "independent Git state witness; no index, remote or production write"
                ),
                "execution": True,
            },
            {
                "module": "host-command-adapter",
                "status": "1.0.0a2-target-live-non-production-candidate",
                "capability": (
                    "one exact shell=false argv under exact cwd/environment, "
                    "bubblewrap runtime-only filesystem and network isolation, "
                    "retained content-free receipt, independent output witness, "
                    "one-use dispatch and recovery; no Home, credentials or production"
                ),
                "execution": True,
            },
            {
                "module": "windows-bounded-process-adapter",
                "status": "1.0.0a2-source-contract-native-lifecycle-required",
                "capability": (
                    "one exact reviewed Windows executable under exact cwd/environment, "
                    "suspended Job Object process-tree bounds and independent output "
                    "witness; filesystem, network and Home isolation remain explicitly "
                    "not enforced and production mutation remains UNKNOWN"
                ),
                "execution": True,
            },
            {
                "module": "genesis",
                "status": "alpha-user-space",
                "capability": "contained synthetic adversarial rehearsal and signed receipts",
                "execution": False,
            },
            {
                "module": "observer-anchor-store",
                "status": "alpha-local",
                "capability": "crash-atomic external cursor and checkpoint custody",
                "execution": False,
            },
            {
                "module": "platform-profile",
                "status": "implemented-portable",
                "capability": "classify host backends without treating platform gaps as product absence",
                "execution": False,
            },
            {
                "module": "external-security-harness",
                "status": "optional-managed-profile",
                "capability": (
                    "externally supplied assessment and containment remain available "
                    "for managed deployments; personal-native memory admission is "
                    "minted internally and grants no production authority"
                ),
                "execution": False,
            },
            {
                "module": "browser-adapter",
                "status": "1.0.0a2-target-live-non-production-candidate",
                "capability": (
                    "one exact signed Firefox click against an HTTP .invalid origin "
                    "through a fresh profile and loopback-only WebDriver/proxy, with "
                    "retained execution receipt, independent passive page witness, "
                    "one-use recovery and no external egress, credentials, Home or "
                    "production authority; current live target is Linux Firefox/geckodriver"
                ),
                "execution": True,
            },
            {
                "module": "computer-use-adapter",
                "status": "not-implemented",
                "capability": "none",
                "execution": False,
            },
            {
                "module": "network-adapter",
                "status": "1.0.0a2-target-live-non-production-candidate",
                "capability": (
                    "one exact HTTP/1.1 POST to a numeric IPv4 loopback endpoint "
                    "after manifest-bound Ed25519 challenge authentication, with exact "
                    "body/response bounds, retained peer receipts, independently "
                    "challenged read-only witness and one-use recovery; no DNS, proxy, "
                    "redirects, TLS, secret credentials, Home or production authority"
                ),
                "execution": True,
            },
            {
                "module": "production-actuator",
                "status": "not-implemented",
                "capability": "none",
                "execution": False,
            },
        ],
        "assurance": {
            "production_deployed": False,
            "production_soak_completed": False,
            "stable_5x_released": False,
            "real_toolz_stable_admitted": False,
            # Hosted checks are external evidence for one exact artifact.  The
            # source/runtime inventory can report that the lanes exist, but it
            # cannot self-certify their current result.
            "hosted_linux_ci": False,
            "hosted_windows_ci": False,
            "hosted_ci_workflows_present": {
                "linux": True,
                "windows": True,
            },
            "exact_artifact_hosted_ci": {
                "linux": "unknown-external-receipt-required",
                "windows": "unknown-external-receipt-required",
            },
            "synthetic_protocol_coverage": True,
            "real_environment_coverage": {
                "linux": "historical-digest-bound-dedicated-user-full-suite",
                "windows_cp312_amd64": (
                    "historical-digest-bound-portable-core-native-installer-job-"
                    "collector-and-private-state-custody-hosted"
                ),
                "macos": "not-yet-practically-verified",
                "bsd": "not-yet-practically-verified",
            },
            "windows_native_installer_admitted": True,
            "windows_native_backend_admitted": False,
            "windows_native_collector_admitted": True,
            "windows_private_state_custody_admitted": True,
            "winops_independent_zero_day_baseline": ("bounded-pass-not-production-ready"),
            "winops_rc6_cold_start_retest_completed": False,
            "winops_rc6_reset_receipt_outcome": "unknown-no-retry",
            "winops_rc7_reset_native_fixture_completed": True,
            "winops_rc7_reset_live_attempt": ("confirmed-failure-exact-child-recovered-no-replay"),
            "winops_rc7_reset_reconciliation_completed": True,
            "winops_rc7_exact_offline_install_completed": True,
            "winops_rc7_collector_completed": True,
            "winops_rc7_network_read_completed": True,
            "winops_rc7_local_seed_completed": True,
            "winops_rc7_persistence_pre_reboot_completed": True,
            "winops_rc7_reboot_observed": True,
            "winops_rc7_atlogon_completed": False,
            "winops_rc7_cold_start_retest_completed": False,
            "winops_rc8_open_client_preflight_completed": True,
            "full_external_topology_proven": False,
            "multi_agent_coordination_proven": False,
            "successor_handoff_bindings_proven": True,
            "atomic_agent_lease_transfer_proven": True,
            "atomic_agent_lease_transfer_scope": "local-sqlite-targeted",
            "agent_handoff_custody_backend": "sqlite-local-linearizable-candidate",
            "agent_handoff_distributed_consensus_proven": False,
            "blast_radius_coverage_proven": False,
            "production_causality_proven": False,
            "genesis_direct_test_gate": "owner-attended-disabled",
        },
        "lts_contract": lts_contract,
        "platform_contract": {
            "portable_protocol_core": True,
            "runtime_probe_command": "guardian platform-profile",
            "source_probe_commands": {
                "posix": "./scripts/probe-platform.sh",
                "windows": "scripts\\probe-platform.cmd",
                "direct_python": "scripts/probe_platform.py",
            },
            "backend_strategy": "capability-profiled",
            "offline_build_locks": {
                "linux_cp314_x86_64": (
                    "requirements/offline-wheelhouse-linux-x86_64-cp314.lock.json"
                ),
                "windows_cp312_amd64": (
                    "requirements/offline-wheelhouse-windows-amd64-cp312.lock.json"
                ),
            },
            "build_dependency_closure": ("selected-target-metadata-probe-before-seal"),
            "families": [
                "linux",
                "windows",
                "macos",
                "bsd",
                "posix-other",
                "unknown",
            ],
            "unknown_platform_fails_closed": True,
        },
        "authority_boundary": {
            "browser_control": False,
            "bounded_non_production_browser_control": True,
            "bounded_loopback_browser_network": True,
            "credentials": False,
            "model_sdk": False,
            "network": False,
            "bounded_loopback_network_action": True,
            "production_authority": False,
            "remediation": False,
            "tool_invocation": False,
            "bounded_owner_approved_operation_runner": True,
            "operation_manifest_required": True,
            "operation_external_authorization_required": True,
            "automatic_retry_after_unknown_outcome": False,
            "adapter_sdk_issues_or_consumes_grants": False,
            "adapter_sdk_requires_independent_witness_for_success": True,
            "adapter_sdk_conformance_is_execution_authority": False,
            "adapter_sdk_source_ready_required_before_dispatch": True,
            "adapter_sdk_signed_operation_binding_required": True,
            "adapter_sdk_executor_witness_identity_separation": True,
            "adapter_sdk_live_adapters_bundled": True,
            "adapter_sdk_workspace_patch_only": False,
            "adapter_sdk_target_readiness_is_production_authority": False,
            "task_completion_requires_terminal_event_receipt": True,
            "phase_constraints_expire_at_phase_boundary": True,
            "unknown_append_reconciliation_by_event_uid_only": True,
        },
        "memory_boundary": {
            "canonical_project_namespace": "profile-selected-seed://project/<slug>",
            "compatibility_project_namespace": "seed://project/default",
            "compatibility_alias": "actionlog://global",
            "integrity_home_imported": False,
            "remote_seed_imported_by_zero_day_bootstrap": False,
            "derived_catalog_rebuildable": True,
            "memory_grants_authority": False,
        },
    }
