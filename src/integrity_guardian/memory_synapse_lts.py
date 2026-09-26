"""Durable, authority-free Memory & Synapse LTS contracts.

The service projects relationships directly over the canonical Integrity Seed
(the Action Log compatibility alias).  Integrity Home is never admitted to the
projection.  All identities are deterministic, receipts are content-free, and
no method grants execution, route, production, or mutation authority.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import integrity_guardian

from .authority_scope import memory_authority_contract
from .hashing import digest_object
from .seed_catalog import (
    ACTION_LOG_ALIAS,
    CATALOG_PROTOCOL,
    CATALOG_SCHEMA_VERSION,
    HOME_NAMESPACE,
    SeedCatalog,
    iter_catalog_events,
    open_catalog_readonly,
    validate_seed_namespace,
)
from .seed_relationships import RELATIONSHIP_PROTOCOL, SeedRelationshipIndex

LTS_PROTOCOL = "integrity-guardian/memory-synapse-lts/v1"
LTS_VERSION = "1.9.0"
FACADE_SERVER_NAME = "integrity-client-memory"
FACADE_SERVER_VERSION = "2.10.0"
RELEASE_WRAPPER_CONTRACT = "integrity-client-memory-lts/runtime-seal-token-env/v1"
SNAPSHOT_PROTOCOL = "integrity-guardian/memory-synapse-snapshot/v1"
TASK_INVENTORY_PROTOCOL = "integrity-guardian/seed-task-inventory-receipt/v1"
EVENT_UID_LOOKUP_PROTOCOL = "integrity-guardian/seed-event-uid-lookup/v1"
EVENT_UID_LOOKUP_RECEIPT_PROTOCOL = EVENT_UID_LOOKUP_PROTOCOL + "/receipt/v1"
CONNECTION_RECEIPT_PROTOCOL = "integrity-guardian/seed-connections-receipt/v1"
DIRECT_VERIFICATION_PROTOCOL = "integrity-guardian/seed-direct-link-verification/v1"
REPLAY_PROTOCOL = "integrity-guardian/seed-relationship-replay/v1"

_EVENT_FIELDS = {
    "related_event_id",
    "related_event_ids",
    "verifies_event_id",
    "verifies_event_ids",
    "verified_event_id",
    "verified_event_ids",
    "supersedes_event_id",
    "supersedes_event_ids",
    "source_event_id",
    "source_event_ids",
    "evidence_event_id",
    "evidence_event_ids",
    "external_evidence_id",
    "external_evidence_ids",
    "transfer_acceptance_event_id",
}
_TASK_FIELDS = {
    "parent_task_id",
    "depends_on_task_ids",
    "related_task_ids",
    "supersedes_task_ids",
    "blocks_task_ids",
    "preempts_task_ids",
}
_PATH_FIELDS = {"evidence_files", "files", "evidence_paths"}


class MemorySynapseLtsError(ValueError):
    """Raised when an LTS source, receipt, or replay fails closed."""


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _event_digest(event: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(_canonical_bytes(event)).hexdigest()


def package_artifact_digest() -> str:
    """Hash the installed package files without importing build metadata."""

    package_root = Path(integrity_guardian.__file__).resolve().parent
    hasher = hashlib.sha256()
    for path in sorted(
        item
        for item in package_root.rglob("*")
        if item.is_file()
        and "__pycache__" not in item.parts
        and item.suffix not in {".pyc", ".pyo"}
    ):
        relative = path.relative_to(package_root).as_posix().encode("utf-8")
        payload = path.read_bytes()
        hasher.update(len(relative).to_bytes(8, "big"))
        hasher.update(relative)
        hasher.update(len(payload).to_bytes(8, "big"))
        hasher.update(payload)
    return "sha256:" + hasher.hexdigest()


def _structured_surface(details: dict[str, Any]) -> bool:
    evidence = details.get("evidence")
    if isinstance(evidence, list) and any(
        isinstance(item, dict) and bool(str(item.get("path", "")).strip()) for item in evidence
    ):
        return True
    if any(details.get(field) for field in _PATH_FIELDS):
        return True

    def walk(value: Any, key: str = "", depth: int = 0) -> bool:
        if depth > 16:
            return False
        if isinstance(value, dict):
            return any(
                walk(child, str(child_key).casefold(), depth + 1)
                for child_key, child in value.items()
            )
        if isinstance(value, list):
            return any(walk(child, key, depth + 1) for child in value)
        return key in _EVENT_FIELDS | _TASK_FIELDS and bool(str(value).strip())

    return walk(details)


def eligible_event_ids(events: list[dict[str, Any]]) -> list[int]:
    """Return the closed, deterministic LTS random-selection population."""

    eligible: list[int] = []
    for event in events:
        if HOME_NAMESPACE in json.dumps(event, ensure_ascii=False):
            raise MemorySynapseLtsError("Integrity Home entered the Seed input")
        details = event.get("details")
        if not isinstance(details, dict):
            continue
        if str(details.get("task_id", "")).strip() and _structured_surface(details):
            eligible.append(int(event["id"]))
    return sorted(set(eligible))


def _uniform_index(seed_hex: str, source_digest: str, population: int) -> tuple[int, int]:
    if not re.fullmatch(r"[0-9a-f]{64}", seed_hex):
        raise MemorySynapseLtsError("selection seed must be 256 lowercase hexadecimal bits")
    if population < 1:
        raise MemorySynapseLtsError("Seed relationship eligibility set is empty")
    seed = bytes.fromhex(seed_hex)
    ceiling = 1 << 256
    admitted = ceiling - (ceiling % population)
    counter = 0
    while True:
        sample = int.from_bytes(
            hashlib.sha256(
                seed + source_digest.encode("utf-8") + counter.to_bytes(8, "big")
            ).digest(),
            "big",
        )
        if sample < admitted:
            return sample % population, counter
        counter += 1


def _parse_event_id(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value > 0:
        return value
    match = re.fullmatch(
        r"(?i)(?:Action\s*Log\s*:?|ActionLog\s*:)?\s*#?(\d{1,9})",
        str(value).strip(),
    )
    return int(match.group(1)) if match else None


def _event_references(details: Any, target_id: int) -> bool:
    def walk(value: Any, key: str = "", depth: int = 0) -> bool:
        if depth > 16:
            return False
        if isinstance(value, dict):
            return any(
                walk(child, str(child_key).casefold(), depth + 1)
                for child_key, child in value.items()
            )
        if isinstance(value, list):
            return any(walk(child, key, depth + 1) for child in value)
        if key not in _EVENT_FIELDS and not key.endswith(("_event_id", "_event_ids")):
            return False
        return _parse_event_id(value) == target_id

    return walk(details)


def _evidence_references(event: dict[str, Any]) -> dict[str, str]:
    details = event.get("details")
    if not isinstance(details, dict):
        return {}
    references: dict[str, str] = {}
    evidence = details.get("evidence")
    if isinstance(evidence, list):
        for item in evidence:
            if not isinstance(item, dict):
                continue
            path = str(item.get("path", "")).strip()
            digest = str(item.get("sha256", "")).strip().casefold().removeprefix("sha256:")
            if path:
                references[path] = (
                    "sha256:" + digest if re.fullmatch(r"[0-9a-f]{64}", digest) else ""
                )
    for path_field in _PATH_FIELDS:
        values = details.get(path_field)
        for value in values if isinstance(values, list) else [values]:
            path = str(value or "").strip()
            if path:
                references.setdefault(path, "")
    return references


def _read_evidence(
    root: Path,
    raw_path: str,
    *,
    source_prefix: Path | None = None,
) -> bytes:
    root = root.absolute()
    if not root.is_dir() or root.is_symlink():
        raise MemorySynapseLtsError("evidence root is not a regular directory")
    resolved_root = root.resolve(strict=True)
    path = Path(raw_path)
    if ".." in path.parts:
        raise MemorySynapseLtsError("evidence path contains traversal")
    if path.is_absolute() and source_prefix is not None:
        try:
            relative = path.absolute().relative_to(source_prefix.absolute())
        except ValueError as exc:
            raise MemorySynapseLtsError("evidence path escapes its source prefix") from exc
        candidate = (resolved_root / relative).absolute()
    else:
        candidate = path.absolute() if path.is_absolute() else (resolved_root / path).absolute()
        try:
            relative = candidate.relative_to(resolved_root)
        except ValueError as exc:
            raise MemorySynapseLtsError("evidence path escapes its root") from exc
    current = resolved_root
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise MemorySynapseLtsError("evidence path contains a symlink")
    descriptor = os.open(
        candidate,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    with os.fdopen(descriptor, "rb") as handle:
        status = os.fstat(handle.fileno())
        if not stat.S_ISREG(status.st_mode) or status.st_size > 512 * 1024:
            raise MemorySynapseLtsError("evidence is not a bounded regular file")
        payload = handle.read(512 * 1024 + 1)
    if len(payload) != status.st_size:
        raise MemorySynapseLtsError("evidence changed during verification")
    return payload


def _verify_link(
    source: dict[str, Any],
    target: dict[str, Any],
    link: dict[str, Any],
    evidence_root: Path | None,
    evidence_source_prefix: Path | None,
) -> list[str]:
    source_id, target_id = int(source["id"]), int(target["id"])
    methods: set[str] = set()
    for reason in link.get("reasons", []):
        kind = reason.get("kind")
        if kind == "explicit-event-reference" and _event_references(
            source.get("details"), target_id
        ):
            methods.add("source-raw-structured-reference")
        elif kind == "reverse-explicit-event-reference" and _event_references(
            target.get("details"), source_id
        ):
            methods.add("target-raw-structured-reference")
        elif kind == "shared-evidence-artifact":
            path = str(reason.get("path", ""))
            expected = str(reason.get("artifact_digest", ""))
            if expected and _evidence_references(source).get(
                path
            ) == expected == _evidence_references(target).get(path):
                methods.add("matching-raw-recorded-artifact-digest")
        elif kind == "shared-operational-fact":
            value = str(reason.get("value", ""))
            proven: list[bool] = []
            for key, event in (("source_provenance", source), ("target_provenance", target)):
                provenance = reason.get(key, {})
                if provenance.get("source_kind") == "event":
                    proven.append(value in json.dumps(event, ensure_ascii=False))
                elif evidence_root is not None:
                    payload = _read_evidence(
                        evidence_root,
                        str(provenance.get("source_path", "")),
                        source_prefix=evidence_source_prefix,
                    )
                    proven.append(
                        value.encode("utf-8") in payload
                        and "sha256:" + hashlib.sha256(payload).hexdigest()
                        == provenance.get("artifact_digest")
                    )
                else:
                    proven.append(False)
            if proven == [True, True]:
                methods.add("independent-raw-fact-provenance")
        elif kind == "gate-external-evidence" and evidence_root is not None:
            payload = _read_evidence(
                evidence_root,
                str(reason.get("artifact", "")),
                source_prefix=evidence_source_prefix,
            )
            if "sha256:" + hashlib.sha256(payload).hexdigest() != reason.get("artifact_digest"):
                continue
            document = json.loads(payload)
            for gate in document.get("gates", []):
                ids = {
                    int(str(item).split("#")[-1])
                    for item in gate.get("external_evidence_ids", [])
                    if str(item).split("#")[-1].isdigit()
                }
                if gate.get("gate_id") == reason.get("gate_id") and {source_id, target_id} <= ids:
                    methods.add("independent-gate-evidence-readback")
    return sorted(methods)


@dataclass(frozen=True)
class MemorySynapseLtsService:
    """Read-only relationship service over one immutable Seed snapshot."""

    catalog_path: Path
    evidence_root: Path | None = None
    evidence_source_prefix: Path | None = None
    artifact_digest: str | None = None
    immutable_catalog: bool = False
    expected_source_namespace: str | None = None
    catalog_connection: sqlite3.Connection | None = field(
        default=None,
        compare=False,
        repr=False,
    )

    @contextmanager
    def _read_connection(self) -> Iterator[sqlite3.Connection]:
        retained = self.catalog_connection
        if retained is None:
            with open_catalog_readonly(self.catalog_path, immutable=self.immutable_catalog) as connection:
                yield connection
            return
        try:
            yield retained
        finally:
            if retained.in_transaction:
                retained.rollback()

    def _artifact_digest(self) -> str:
        return self.artifact_digest or package_artifact_digest()

    def capabilities(self) -> dict[str, Any]:
        core = {
            "protocol": LTS_PROTOCOL,
            "contract_version": LTS_VERSION,
            "artifact_digest": self._artifact_digest(),
            "seed_relationship_protocol": RELATIONSHIP_PROTOCOL,
            "seed_catalog_protocol": CATALOG_PROTOCOL,
            "seed_catalog_schema_version": CATALOG_SCHEMA_VERSION,
            "source_mapping": {
                "canonical_seed": (self.snapshot()["source_namespace"]
                                   if self.catalog_path.is_file() else None),
                "action_log_alias": ACTION_LOG_ALIAS,
                "integrity_home": HOME_NAMESPACE,
                "seed_equals_action_log": True,
                "home_separate": True,
            },
            "operations": {
                "context_admission": "one-call-per-owner-intent-server-rotated-context",
                "seed_snapshot": "read-only",
                "seed_mind_graph": "read-only-mandatory-admission",
                "architecture_admission": "persistent-content-free-evidence",
                "event_append": "append-only-one-use-witnessed-action",
                "turn_memory_open": "signed-global-registration",
                "turn_memory_close": "signed-terminal-events-or-no-event",
                "turn_memory_gap": "signed-nonterminal-coverage-debt",
                "turn_memory_coverage": "read-only",
                "seed_tasks": "read-only-canonical-projection",
                "seed_event_uid": "read-only-snapshot-wide-unique-lookup",
                "memory_entity_brief": "read-only-optional-bounded-projection",
                "memory_link_audit": "read-only-unadmitted-curation-debt",
                "seed_connections": "read-only",
                "seed_direct_verification": "read-only",
                "seed_replay": "read-only",
            },
            "authority": {
                "execution": False,
                "production": False,
                "route": False,
                "atlas_planning": False,
                "uroboros_reuse": False,
                "canonical_seed_append_one_use": True,
            },
            "authority_contract": memory_authority_contract(),
            "processing": {
                "guardian_ledger": True,
                "signed_checkpoint": True,
                "atlas_projection": True,
                "connectome_compilation": True,
                "synapse_route_planning": True,
                "ownership_blast_coordination": True,
                "deep_mind_graph": True,
                "concept_recovery": True,
                "security_harness_admission": True,
                "uroboros_exact_route_reuse": True,
                "one_use_authority": True,
                "passive_outcome_witness": True,
                "immutable_outcome_feedback": True,
                "turn_memory_registration": True,
                "turn_memory_terminal_receipt": True,
                "turn_memory_coverage_gap": True,
                "model_side_route_invention": False,
            },
            "mutation": {
                "update": False,
                "delete": False,
                "import": False,
                "overwrite": False,
                "bulk_write": False,
            },
            "facade": {
                "server_name": FACADE_SERVER_NAME,
                "server_version": FACADE_SERVER_VERSION,
                "transport": "openssh-forced-command-stdio",
                "listener": False,
                "authentication_enforcement": "external-existing-client-key",
                "allowed_consumer": "client-workstation",
                "winops_authorized": False,
                "startup_admission": "exact-artifact-security-harness-bundle",
                "session_admission": {
                    "preferred_tool": "integrity_context_admission",
                    "home_binding": "capabilities-required-source-separated",
                    "required_sequence": [
                        "integrity_memory_capabilities",
                        "integrity_seed_snapshot",
                        "integrity_mind_graph",
                        "integrity_architecture_admission",
                    ],
                    "seed_snapshot_activation": "lazy-on-first-seed-tool",
                    "seed_snapshot_binding": "server-fixed-per-logical-context",
                    "mind_graph_binding": "same-snapshot-required-before-seed-read-or-append",
                    "architecture_binding": "same-mind-receipt-required-before-seed-read-or-append",
                    "client_cursor_policy": "omit-or-exact-session-match",
                    "duplicate_page_policy": "deny-after-success-in-session",
                    "context_presentation": {
                        "default_protocol": "integrity-client-memory-mcp/v3/context-admission/v2",
                        "supported_protocols": [
                            "integrity-client-memory-mcp/v3/context-admission/v2",
                            "integrity-client-memory-mcp/v3/context-admission/v1",
                        ],
                        "legacy_fixed_selector": "explicit-limit",
                    },
                    "action_contract": {
                        "route": "request-bound-connectome-synapse",
                        "scope": "single-canonical-seed-append",
                        "grant": "consumed-once-before-action",
                        "context_binding": (
                            "exact-current-context-admission-id-before-side-effects"
                        ),
                        "authority_binding": "signed-context-decision-and-ledger-grant-v2",
                        "passive_witness": "restricted-owner-one-shot-read-only-sqlite",
                        "outcomes": [
                            "confirmed-success",
                            "confirmed-failure",
                            "unknown-outcome",
                        ],
                        "automatic_retry": False,
                    },
                },
                "compatible_tools": [
                    "integrity_read_events",
                    "integrity_append_event",
                    "integrity_home_search",
                    "integrity_home_fetch",
                ],
                "turn_memory_tools": [
                    "integrity_turn_memory_open",
                    "integrity_turn_memory_close",
                    "integrity_turn_memory_gap",
                    "integrity_turn_memory_coverage",
                ],
                "lts_tools": [
                    "integrity_context_admission",
                    "integrity_memory_capabilities",
                    "integrity_seed_snapshot",
                    "integrity_mind_graph",
                    "integrity_architecture_admission",
                    "integrity_seed_tasks",
                    "integrity_seed_event_uid",
                    "integrity_seed_connections",
                    "integrity_memory_entity_brief",
                    "integrity_memory_link_audit",
                    "integrity_seed_replay",
                ],
            },
            "lifecycle": {
                "persistent_derived_state": False,
                "persistent_architecture_custody": True,
                "persistent_turn_memory_coverage": True,
                "snapshot_storage": "private-tmpfs-session-copy",
                "startup_seed_copy": False,
                "migration": "verify-schema-and-rebuild-from-canonical-seed",
                "upgrade": "parallel-successor-acceptance-before-forced-command-switch",
                "recovery": "identical-snapshot-plus-exact-single-guardian-child-only",
                "read_audit": "content-free-receipts",
                "key_rotation": "external-forced-command-dual-admission-then-revoke-old",
                "installed_runtime_verification": (
                    "canonical-complete-release-inventory-before-exec"
                ),
            },
            "health": "ready" if self.catalog_path.is_file() else "unavailable",
        }
        return {
            **core,
            "capabilities_digest": digest_object(core, domain="memory-synapse-lts-capabilities-v1"),
        }

    def snapshot(self) -> dict[str, Any]:
        catalog = SeedCatalog(
            self.catalog_path,
            immutable=self.immutable_catalog,
            readonly_connection=self.catalog_connection,
        )
        verification = catalog.verify()
        count, maximum = catalog.event_cursor()
        validate_seed_namespace(verification["source_namespace"])
        if (self.expected_source_namespace is not None
                and verification["source_namespace"] != validate_seed_namespace(self.expected_source_namespace)):
            raise MemorySynapseLtsError("catalog does not match configured Seed namespace")
        if verification["home_record_count"] != 0:
            raise MemorySynapseLtsError("Integrity Home entered the canonical Seed catalog")
        immutable_core = {
            "protocol": SNAPSHOT_PROTOCOL,
            "contract_version": LTS_VERSION,
            "artifact_digest": self._artifact_digest(),
            "source_namespace": verification["source_namespace"],
            "action_log_alias": ACTION_LOG_ALIAS,
            "catalog_protocol": CATALOG_PROTOCOL,
            "catalog_schema_version": CATALOG_SCHEMA_VERSION,
            "cursor": {"event_count": count, "maximum_event_id": maximum},
            "source_digest": verification["source_digest"],
            "catalog_digest": verification["catalog_digest"],
            "home_record_count": 0,
            "health": "ready",
            "immutable": True,
            "production_authority": False,
            "route_authority": False,
            "authority_contract": memory_authority_contract(),
        }
        # A no-op synchronization creates a new operational run receipt even
        # when canonical Seed content is unchanged.  Keep that useful lineage
        # visible, but exclude it from the immutable snapshot identity so a
        # restart cannot invalidate deterministic replay by itself.
        return {
            **immutable_core,
            "catalog_run_id": catalog.latest_run_id(),
            "snapshot_id": digest_object(immutable_core, domain="memory-synapse-snapshot-v1"),
        }

    def _assert_snapshot(self, expected_snapshot_id: str) -> dict[str, Any]:
        snapshot = self.snapshot()
        if snapshot["snapshot_id"] != expected_snapshot_id:
            raise MemorySynapseLtsError("canonical Seed snapshot changed")
        return snapshot

    def tasks(
        self,
        *,
        expected_snapshot_id: str,
        view: str = "work_queue_review",
        after_task_id: str = "",
        limit: int = 50,
    ) -> dict[str, Any]:
        """Return the canonical derived task lifecycle without model heuristics."""

        snapshot = self._assert_snapshot(expected_snapshot_id)
        views = {
            "work_queue_review": ["active", "pending", "blocked", "unknown"],
            "failed": ["failed"],
        }
        if not isinstance(view, str) or view not in views:
            raise MemorySynapseLtsError("task inventory view is not exposed")
        selected = views[view]
        if not isinstance(after_task_id, str) or len(after_task_id) > 256:
            raise MemorySynapseLtsError("task pagination cursor is invalid")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 200:
            raise MemorySynapseLtsError("task page limit is outside 1..200")
        ordered_statuses = sorted(selected)
        placeholders = ",".join("?" for _ in ordered_statuses)
        with self._read_connection() as connection:
            connection.row_factory = sqlite3.Row
            status_counts = {
                status: 0
                for status in ("active", "pending", "blocked", "unknown", "complete", "failed")
            }
            for row in connection.execute(
                "SELECT status, COUNT(*) AS count FROM seed_tasks GROUP BY status"
            ):
                status = str(row["status"])
                if status not in status_counts:
                    raise MemorySynapseLtsError("catalog contains an unknown task lifecycle")
                status_counts[status] = int(row["count"])
            rows = list(
                connection.execute(
                    f"""
                    SELECT task_id, status, owner, priority, summary, scope,
                           first_event_id, last_event_id
                    FROM seed_tasks
                    WHERE status IN ({placeholders}) AND task_id > ?
                    ORDER BY task_id
                    LIMIT ?
                    """,
                    (*ordered_statuses, after_task_id, limit + 1),
                )
            )
        has_more = len(rows) > limit
        tasks = [dict(row) for row in rows[:limit]]
        next_after_task_id = str(tasks[-1]["task_id"]) if has_more and tasks else ""
        page_binding = {
            "after_task_id": after_task_id,
            "limit": limit,
            "next_after_task_id": next_after_task_id,
            "tasks_digest": digest_object(tasks, domain="seed-task-inventory-page-v1"),
        }
        receipt_core = {
            "protocol": TASK_INVENTORY_PROTOCOL,
            "snapshot_id": snapshot["snapshot_id"],
            "source_digest": snapshot["source_digest"],
            "catalog_digest": snapshot["catalog_digest"],
            "view": view,
            "selected_statuses": ordered_statuses,
            "status_counts": status_counts,
            "returned_count": len(tasks),
            "has_more": has_more,
            "page_binding": page_binding,
            "home_record_count": 0,
            "production_authority": False,
            "route_authority": False,
        }
        return {
            "lifecycle_contract": {
                "work_queue": ["active", "pending", "blocked"],
                "review_debt": ["unknown"],
                "terminal": ["complete", "failed"],
            },
            "tasks": tasks,
            "pagination": {
                "next_after_task_id": next_after_task_id,
                "has_more": has_more,
            },
            "receipt": {
                **receipt_core,
                "receipt_id": digest_object(receipt_core, domain="seed-task-inventory-receipt-v1"),
            },
        }

    def event_uid_lookup(
        self,
        *,
        expected_snapshot_id: str,
        event_uid: str,
    ) -> dict[str, Any]:
        """Resolve one UID across the complete immutable Seed snapshot."""

        snapshot = self._assert_snapshot(expected_snapshot_id)
        if (
            not isinstance(event_uid, str)
            or not event_uid
            or event_uid != event_uid.strip()
            or len(event_uid) > 256
        ):
            raise MemorySynapseLtsError("event_uid must contain 1 to 256 exact characters")
        with self._read_connection() as connection:
            rows = list(
                connection.execute(
                    """
                    SELECT event_id, canonical_json
                    FROM seed_events
                    WHERE event_uid = ?
                    ORDER BY event_id
                    LIMIT 2
                    """,
                    (event_uid,),
                )
            )
        if len(rows) > 1:
            raise MemorySynapseLtsError("canonical Seed contains a duplicate event_uid")
        event = json.loads(str(rows[0][1])) if rows else None
        if event is not None and not isinstance(event, dict):
            raise MemorySynapseLtsError("canonical Seed event payload is invalid")
        outcome = "found" if event is not None else "not-found"
        event_id = int(rows[0][0]) if rows else 0
        event_digest = _event_digest(event) if event is not None else None
        receipt_core = {
            "protocol": EVENT_UID_LOOKUP_RECEIPT_PROTOCOL,
            "snapshot_id": snapshot["snapshot_id"],
            "source_digest": snapshot["source_digest"],
            "catalog_digest": snapshot["catalog_digest"],
            "event_uid_digest": digest_object(event_uid, domain="seed-event-uid-v1"),
            "outcome": outcome,
            "event_id": event_id,
            "event_digest": event_digest,
            "home_record_count": 0,
            "production_authority": False,
            "route_authority": False,
        }
        return {
            "protocol": EVENT_UID_LOOKUP_PROTOCOL,
            "snapshot_id": snapshot["snapshot_id"],
            "event_uid": event_uid,
            "outcome": outcome,
            "event": event,
            "event_digest": event_digest,
            "receipt": {
                **receipt_core,
                "receipt_id": digest_object(
                    receipt_core,
                    domain="seed-event-uid-lookup-receipt-v1",
                ),
            },
        }

    def connections(
        self,
        *,
        expected_snapshot_id: str,
        event_id: int | None = None,
        selection_seed: str | None = None,
        limit: int = 20,
        include_contextual: bool = False,
    ) -> dict[str, Any]:
        if (event_id is None) == (selection_seed is None):
            raise MemorySynapseLtsError("provide exactly one event_id or selection_seed")
        snapshot = self._assert_snapshot(expected_snapshot_id)
        events = list(iter_catalog_events(self.catalog_path))
        by_id = {int(event["id"]): event for event in events}
        selection: dict[str, Any]
        if selection_seed is not None:
            eligible = eligible_event_ids(events)
            index, rejection_counter = _uniform_index(
                selection_seed, snapshot["source_digest"], len(eligible)
            )
            event_id = eligible[index]
            selection = {
                "mode": "recorded-random-seed",
                "seed": selection_seed,
                "eligible_count": len(eligible),
                "eligible_digest": digest_object(
                    eligible, domain="memory-synapse-eligible-events-v1"
                ),
                "selected_index": index,
                "rejection_counter": rejection_counter,
                "reroll_count": 0,
            }
        else:
            selection = {"mode": "explicit-event-id", "reroll_count": 0}
        assert event_id is not None
        if event_id not in by_id:
            raise MemorySynapseLtsError(f"canonical Seed has no event {event_id}")
        relationship = SeedRelationshipIndex(
            events,
            evidence_root=self.evidence_root,
            evidence_source_prefix=self.evidence_source_prefix,
        ).explain(
            event_id, limit=limit, include_contextual=include_contextual
        )
        source = SeedCatalog(
            self.catalog_path,
            immutable=self.immutable_catalog,
            readonly_connection=self.catalog_connection,
        ).event_at(event_id)
        verified_links: list[dict[str, Any]] = []
        for link in relationship["links"]:
            if link["class"] != "direct":
                continue
            target_id = int(link["target_event_id"])
            target = SeedCatalog(
                self.catalog_path,
                immutable=self.immutable_catalog,
                readonly_connection=self.catalog_connection,
            ).event_at(target_id)
            methods = _verify_link(
                source,
                target,
                link,
                self.evidence_root,
                self.evidence_source_prefix,
            )
            verified_links.append(
                {
                    "target_event_id": target_id,
                    "source_event_digest": _event_digest(source),
                    "target_event_digest": _event_digest(target),
                    "methods": methods,
                    "result": "PASS" if methods else "FAIL",
                }
            )
        verification_core = {
            "protocol": DIRECT_VERIFICATION_PROTOCOL,
            "snapshot_id": expected_snapshot_id,
            "source_event_id": event_id,
            "direct_link_count": len(verified_links),
            "verified_link_count": sum(item["result"] == "PASS" for item in verified_links),
            "links": verified_links,
            "result": "PASS"
            if all(item["result"] == "PASS" for item in verified_links)
            else "FAIL",
            "home_record_count": 0,
        }
        verification = {
            **verification_core,
            "verification_receipt_id": digest_object(
                verification_core, domain="seed-direct-link-verification-v1"
            ),
        }
        if verification["result"] != "PASS":
            raise MemorySynapseLtsError("independent direct-link verification failed")
        receipt_core = {
            "protocol": CONNECTION_RECEIPT_PROTOCOL,
            "snapshot_id": expected_snapshot_id,
            "artifact_digest": snapshot["artifact_digest"],
            "source_namespace": snapshot["source_namespace"],
            "selected_event_id": event_id,
            "selection": selection,
            "limit": limit,
            "include_contextual": include_contextual,
            "relationship_protocol": relationship["protocol"],
            "explanation_digest": relationship["explanation_digest"],
            "link_counts": relationship["link_counts"],
            "direct_verification_receipt_id": verification["verification_receipt_id"],
            "home_record_count": 0,
            "production_authority": False,
            "route_authority": False,
        }
        receipt = {
            **receipt_core,
            "receipt_id": digest_object(receipt_core, domain="seed-connections-receipt-v1"),
        }
        return {
            "relationship": relationship,
            "direct_verification": verification,
            "receipt": receipt,
        }

    def replay(
        self,
        *,
        expected_snapshot_id: str,
        selection_seed: str,
        expected_event_id: int,
        expected_explanation_digest: str,
        expected_receipt_id: str,
        limit: int = 20,
        include_contextual: bool = False,
    ) -> dict[str, Any]:
        result = self.connections(
            expected_snapshot_id=expected_snapshot_id,
            selection_seed=selection_seed,
            limit=limit,
            include_contextual=include_contextual,
        )
        receipt = result["receipt"]
        checks = {
            "event_id": receipt["selected_event_id"] == expected_event_id,
            "explanation_digest": receipt["explanation_digest"] == expected_explanation_digest,
            "receipt_id": receipt["receipt_id"] == expected_receipt_id,
            "reroll_zero": receipt["selection"]["reroll_count"] == 0,
        }
        core = {
            "protocol": REPLAY_PROTOCOL,
            "snapshot_id": expected_snapshot_id,
            "selection_seed": selection_seed,
            "selected_event_id": receipt["selected_event_id"],
            "explanation_digest": receipt["explanation_digest"],
            "connections_receipt_id": receipt["receipt_id"],
            "checks": checks,
            "deterministic": all(checks.values()),
            "reroll_count": 0,
            "home_record_count": 0,
            "production_authority": False,
            "route_authority": False,
        }
        replay = {
            **core,
            "replay_receipt_id": digest_object(core, domain="seed-relationship-replay-v1"),
        }
        if not replay["deterministic"]:
            raise MemorySynapseLtsError("cold replay did not reproduce the frozen receipt")
        return replay
