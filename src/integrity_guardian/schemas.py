"""Versioned schema loading and validation."""

from __future__ import annotations

import json
import re
from datetime import datetime
from functools import cache
from importlib.resources import files
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

SCHEMA_NAMES = (
    "action-log-append-attempt-receipt",
    "action-log-event-uid-reconciliation",
    "action-log-recovery-verification",
    "agent-identity",
    "agent-session-admission",
    "agent-session-gate",
    "adapter-action-proposal",
    "adapter-conformance-evidence",
    "adapter-conformance-receipt",
    "adapter-deployment-cohort-receipt",
    "adapter-deployment-cohort-receipt-v2",
    "adapter-deployment-host-lifecycle-evidence",
    "adapter-deployment-host-lifecycle-evidence-v2",
    "adapter-deployment-lifecycle-execution-receipt",
    "adapter-deployment-lifecycle-phase-receipt",
    "adapter-deployment-lifecycle-postcondition-receipt",
    "adapter-deployment-lifecycle-precondition-receipt",
    "adapter-dispatch-admission",
    "adapter-execution-report",
    "adapter-capability-manifest",
    "adapter-execution-envelope",
    "adapter-operation-binding",
    "adapter-platform-lifecycle-evidence",
    "adapter-portability-receipt",
    "adapter-target-operation",
    "adapter-proof-profile",
    "adapter-transition-receipt",
    "artifact-provenance-receipt",
    "atlas-projection",
    "atlas-synapse-plan",
    "browser-action-manifest",
    "browser-execution-receipt",
    "browser-page-witness",
    "network-endpoint-witness",
    "network-http-action-manifest",
    "network-http-execution-receipt",
    "network-peer-response-receipt",
    "change-intent",
    "cognitive-continuation",
    "cognitive-continuation-receipt",
    "cognitive-run-request",
    "cognitive-run-result",
    "cross-agent-continuity-admission-receipt",
    "cross-agent-continuity-package",
    "connectome-compilation",
    "connectome-authorization",
    "connectome-authorized-compilation",
    "connectome-manifest",
    "collector-result",
    "credential-custody-receipt",
    "customer-policy-binding",
    "discovery-conformance-receipt",
    "discovery-appliance-manifest",
    "discovery-delta-receipt",
    "discovery-feedback-overlay",
    "discovery-feedback-overlay-delta",
    "discovery-feedback-ranked-route",
    "discovery-index-snapshot",
    "discovery-record",
    "discovery-snapshot-inclusion",
    "discovery-theory-feedback",
    "discovery-theory-route",
    "observation",
    "observer-anchor-record",
    "native-passive-capture-envelope",
    "native-database-enrollment",
    "native-database-migration-receipt",
    "native-device-enrollment",
    "native-device-enrollment-request",
    "native-module-enrollment",
    "native-release-authority-enrollment",
    "native-security-admission",
    "native-session-lease",
    "native-trust-genesis",
    "passive-controller-checkpoint",
    "passive-discovery-cohort-receipt",
    "passive-source-snapshot",
    "perpetual-dialogue-continuation-checkpoint",
    "perpetual-dialogue-transport-receipt",
    "perpetual-dialogue-transport-request",
    "perpetual-dialogue-transition-receipt",
    "perpetual-dialogue-wake-record",
    "ledger-event",
    "ledger-inclusion-proof",
    "local-machine-profile",
    "lts-support-contracts",
    "lts-release-index",
    "lts-track-activation-receipt",
    "lts-version-matrix",
    "model-route-receipt",
    "memory-synapse-capabilities",
    "memory-synapse-architecture-capsule",
    "memory-synapse-context-selection",
    "memory-synapse-mind-admission",
    "memory-synapse-snapshot",
    "memory-entity-brief",
    "memory-link-audit",
    "memory-link-context",
    "memory-link-navigation",
    "memory-link-resolution",
    "memory-ttt-autofill",
    "medor-architecture-admission",
    "medor-architecture-custody",
    "medor-event-route-stage",
    "medor-event-append-decision",
    "medor-event-append-decision-v2",
    "medor-event-one-use-authority",
    "medor-event-one-use-authority-v2",
    "medor-event-outcome-feedback",
    "medor-event-passive-witness",
    "medor-security-admission-bundle",
    "mind-projection-checkpoint",
    "mind-capsule",
    "module-agent-lease",
    "module-agent-lease-head",
    "module-agent-handoff-checkpoint",
    "module-agent-handoff-commit-receipt",
    "module-agent-handoff-reconciliation-receipt",
    "module-agent-successor-ack",
    "checkpoint",
    "checkpoint-retention-receipt",
    "execution-containment-receipt",
    "execution-receipt",
    "finding",
    "genesis-rehearsal-receipt",
    "host-command-witness",
    "windows-bounded-process-witness",
    "key-transition",
    "release-manifest",
    "readonly-operation-manifest",
    "readonly-operation-manifest-v2",
    "readonly-operation-manifest-v3",
    "readonly-operation-authorization",
    "readonly-operation-receipt",
    "promotion-decision-receipt",
    "private-output-reconciliation-status",
    "response-envelope",
    "retention-decision",
    "retention-policy",
    "security-assessment-receipt",
    "seed-connections-receipt",
    "seed-event-uid-lookup",
    "seed-task-inventory-receipt",
    "seed-direct-link-verification",
    "seed-relationship-replay",
    "seed-reader-principal",
    "shadow-authorization",
    "synapse-capability-slice",
    "synapse-graph",
    "synapse-route",
    "synapse-simulation",
    "task-closure-receipt",
    "task-instruction-envelope",
    "tenant-profile",
    "toolz-action-outcome-observation",
    "toolz-action-trace-receipt",
    "toolz-authority-decision",
    "toolz-authorization-request",
    "toolz-admission-install-receipt",
    "toolz-admission-recovery-receipt",
    "toolz-feedback-install-receipt",
    "toolz-feedback-recovery-receipt",
    "toolz-feedback-resume-receipt",
    "toolz-grant-consumption",
    "toolz-post-route-feedback-receipt",
    "toolz-reuse-readiness-receipt",
    "toolz-route-memory-receipt",
    "toolz-route-store-manifest",
    "toolz-start-state-witness",
    "toolz-trace-admission-receipt",
    "turn-memory-gap-receipt",
    "turn-memory-registration",
    "turn-memory-terminal-receipt",
    "uroboros-winops-zero-day-reset-receipt",
    "uroboros-winops-zero-day-reset-reconciliation",
    "uroboros-winops-zero-day-reset-reservation",
    "zero-day-final-witness",
    "zero-day-seed-build-receipt",
    "windows-asset-manifest",
    "windows-host-collector-build-receipt",
    "windows-install-locator",
    "windows-offline-install-receipt",
    "windows-seed-persistence-removal-receipt",
    "windows-seed-persistence-receipt",
    "windows-seed-persistence-witness",
    "workspace-patch-execution-receipt",
    "workspace-patch-manifest",
    "workspace-patch-witness",
)

RFC3339 = re.compile(
    r"^\d{4}-\d{2}-\d{2}T"
    r"\d{2}:\d{2}:\d{2}(?:\.\d+)?"
    r"(?:Z|[+-]\d{2}:\d{2})$"
)
FORMAT_CHECKER = FormatChecker()


@FORMAT_CHECKER.checks("date-time")
def _is_rfc3339(value: object) -> bool:
    if not isinstance(value, str):
        return True
    if RFC3339.fullmatch(value) is None:
        return False
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return False
    return parsed.tzinfo is not None


def load_schema(name: str) -> dict[str, Any]:
    if name not in SCHEMA_NAMES:
        raise KeyError(f"unknown Guardian schema: {name}")
    path = files("integrity_guardian").joinpath("schema", f"{name}.schema.json")
    return json.loads(path.read_text(encoding="utf-8"))


@cache
def _validator(name: str) -> Draft202012Validator:
    schema = load_schema(name)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FORMAT_CHECKER)


def validate(name: str, instance: Any) -> None:
    _validator(name).validate(instance)
