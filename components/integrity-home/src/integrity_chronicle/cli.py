"""CLI entrypoint for Integrity Home."""

from __future__ import annotations

from argparse import ArgumentParser, Namespace
from pathlib import Path
from typing import Dict, List, Optional
from hashlib import sha256
import os
import json
import tempfile
import sys

from .ingest import (
    CanonicalizationError,
    build_semantic_extractor,
    parse_staged_archive,
    write_canonical_manifest,
)
from .action_log import (
    ACTION_LOG_EVENT_IMPORT_COMPLETED,
    ACTION_LOG_EVENT_IMPORT_DRY_RUN_COMPLETED,
    ACTION_LOG_EVENT_IMPORT_DRY_RUN_REJECTED,
    ACTION_LOG_EVENT_IMPORT_FAILED,
    ACTION_LOG_EVENT_FORGET_COMPLETED,
    ACTION_LOG_EVENT_FORGET_FAILED,
    append_import_action_event,
    append_forget_action_event,
    append_corpus_recall_action_receipt,
    load_reviewed_candidate_projection,
    publish_reviewed_candidate_bundle,
)
from .context_policy import (
    ContextPolicy,
    build_context_bundle,
    ALLOWED_CLAIM_TYPES,
    ALLOWED_TEMPORAL_STATES,
    parse_csv_set,
)
from .forget import apply_forget
from .validator import (
    MAX_COMPRESSION_RATIO,
    MAX_MEMBER_COUNT,
    MAX_MEMBER_SIZE_BYTES,
    MAX_TOTAL_UNCOMPRESSED_BYTES,
    staged_archive_extraction,
    validate_archive,
    write_manifest_file,
)
from .search import search_projection
from .source_registry import (
    STATE_CANONICAL_FORGOT,
    STATE_CANONICAL_PARSED,
    record_projection_rebuild,
    record_source_manifest,
)
from .review import run_review_api_server
from .candidates import build_candidate_bundle
from .json_integrity import load_json_strict
from .corpus_backup import (
    CorpusBackupError,
    backup_corpus_state,
    restore_corpus_state,
)
from .runtime_paths import state_path, state_root
from .folder_intake import (
    DEFAULT_MAX_ARCHIVES,
    DEFAULT_MAX_ARCHIVE_BYTES,
    FolderIntakeError,
    import_archive_folder,
    refresh_archive_generation_receipt,
)
from .project_action_log import (
    ProjectActionLogError,
    append_project_action,
    verify_project_action_log,
)


_MAX_HISTORY_RECOVERY_BYTES = 512 << 20


def _source_manifest_path() -> str:
    return str(state_path("manifests", "source-manifest.json"))


def _action_log_root() -> str:
    return str(state_path("manifests", "action-logs"))


def _projection_root() -> Path:
    return state_path("vault", "index")


def _scope_registry_path() -> str:
    override = os.environ.get("INTEGRITY_HOME_SCOPE_REGISTRY")
    if override is not None:
        if not override.strip():
            raise ValueError("INTEGRITY_HOME_SCOPE_REGISTRY must not be empty")
        return str(Path(override).expanduser().resolve())
    return str(state_path("config", "memory-scopes.json").resolve())


def _sha256_file(path: str) -> str:
    digest = sha256()
    with open(path, "rb") as fp:
        for chunk in iter(lambda: fp.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_payload(payload: Dict) -> str:
    encoded = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return sha256(encoded).hexdigest()


def _project_context_args(args: Namespace) -> Optional[Dict[str, str]]:
    fields = {
        "project_id": getattr(args, "project_id", None),
        "root_thread_id": getattr(args, "root_thread_id", None),
        "session_id": getattr(args, "session_id", None),
        "actor_id": getattr(args, "actor_id", None),
        "operation_id": getattr(args, "operation_id", None),
    }
    if not any(value is not None for value in fields.values()):
        return None
    if not all(isinstance(value, str) and bool(value.strip()) for value in fields.values()):
        raise ValueError(
            "project audit requires project-id, root-thread-id, session-id, actor-id, and operation-id"
        )
    return {key: str(value) for key, value in fields.items()}


def _add_project_audit_arguments(parser: ArgumentParser) -> None:
    parser.add_argument("--project-id", default=None)
    parser.add_argument("--root-thread-id", default=None)
    parser.add_argument("--session-id", default=None)
    parser.add_argument("--actor-id", default=None)
    parser.add_argument("--operation-id", default=None)
    parser.add_argument("--project-action-log-root", default=_action_log_root())


def _append_project_failure(args: Namespace, *, action: str, error: BaseException) -> None:
    context = _project_context_args(args)
    if context is None:
        return
    failure_context = dict(context)
    failure_context["operation_id"] += ".failed." + sha256(
        type(error).__name__.encode("utf-8")
    ).hexdigest()[:12]
    append_project_action(
        args.project_action_log_root,
        **failure_context,
        action=action,
        status="failed",
    )


def _default_canonical_path(archive_path: str) -> str:
    source_id = _sha256_file(archive_path)[:24]
    return str(_projection_root() / f"{source_id}-canonical.json")


def _build_parser() -> ArgumentParser:
    parser = ArgumentParser(
        prog="integrity-home", description="Integrity Home command line"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    doctor = sub.add_parser("doctor", help="show environment checks")
    doctor.set_defaults(func=_run_doctor)

    import_parser = sub.add_parser("import", help="import provider archive")
    import_parser.add_argument("archive", help="path to archive zip")
    import_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="validate archive safely without extraction",
    )
    import_parser.add_argument("--max-members", type=int, default=MAX_MEMBER_COUNT)
    import_parser.add_argument("--max-member-size", type=int, default=MAX_MEMBER_SIZE_BYTES)
    import_parser.add_argument("--max-total-uncompressed", type=int, default=MAX_TOTAL_UNCOMPRESSED_BYTES)
    import_parser.add_argument("--max-compression-ratio", type=float, default=MAX_COMPRESSION_RATIO)
    import_parser.add_argument(
        "--output-manifest",
        default=None,
        help="write deterministic canonical manifest for the dry-run result",
    )
    import_parser.add_argument(
        "--record-source",
        action="store_true",
        help="append a deterministic source entry to the source registry",
    )
    import_parser.add_argument(
        "--user-id",
        default=None,
        help="namespace action-log entries for this import",
    )
    import_parser.add_argument(
        "--action-log-root",
        default=_action_log_root(),
        help="root directory for per-user action logs",
    )
    import_parser.add_argument(
        "--source-manifest",
        default=_source_manifest_path(),
        help="source registry path for --record-source output",
    )
    import_parser.add_argument(
        "--output-canonical",
        default=None,
        help="write parsed canonical payload for a non-dry-run import; defaults to "
        "vault/index/<source_id>-canonical.json when omitted",
    )
    import_parser.add_argument(
        "--provider-hint",
        default=None,
        help="force provider parser for staged payloads, e.g. openai_chatgpt, anthropic_claude, or custom labels",
    )
    import_parser.add_argument(
        "--semantic-backend",
        default="fake",
        help=(
            "semantic claim backend: 'fake' for deterministic builtin extraction "
            "or 'module.path:ClassName' for custom backends implementing "
            "extract_claim_records"
        ),
    )
    import_parser.set_defaults(func=_run_import)

    folder_parser = sub.add_parser(
        "import-folder", help="atomically import a folder of provider export ZIPs"
    )
    folder_parser.add_argument("folder", help="folder containing export ZIPs")
    folder_parser.add_argument("--output", required=True, help="new corpus generation directory")
    folder_parser.add_argument("--max-archives", type=int, default=DEFAULT_MAX_ARCHIVES)
    folder_parser.add_argument("--max-archive-bytes", type=int, default=DEFAULT_MAX_ARCHIVE_BYTES)
    folder_parser.add_argument("--max-members", type=int, default=MAX_MEMBER_COUNT)
    folder_parser.add_argument("--max-member-size", type=int, default=MAX_MEMBER_SIZE_BYTES)
    folder_parser.add_argument("--max-total-uncompressed", type=int, default=MAX_TOTAL_UNCOMPRESSED_BYTES)
    folder_parser.add_argument("--max-compression-ratio", type=float, default=MAX_COMPRESSION_RATIO)
    folder_parser.add_argument("--semantic-backend", default="fake")
    folder_parser.add_argument("--project-id", default=None)
    folder_parser.add_argument("--root-thread-id", default=None)
    folder_parser.add_argument("--session-id", default=None)
    folder_parser.add_argument("--actor-id", default=None)
    folder_parser.add_argument("--operation-id", default=None)
    folder_parser.add_argument("--project-action-log-root", default=_action_log_root())
    folder_parser.set_defaults(func=_run_import_folder)

    context_parser = sub.add_parser("context-capsule", help="build scoped context capsule from canonical projection")
    context_parser.add_argument("canonical", help="path to canonical projection JSON")
    context_parser.add_argument(
        "--purpose",
        default="task_context",
        help="named purpose used in the context receipt",
    )
    context_parser.add_argument("--task-id", default="", help="task identifier to scope the capsule")
    context_parser.add_argument(
        "--scope",
        default="default",
        help="scope label for the context bundle",
    )
    context_parser.add_argument(
        "--claim-types",
        default=None,
        help="comma-separated allowlist of claim_type values",
    )
    context_parser.add_argument(
        "--temporal-states",
        default=None,
        help="comma-separated allowlist of temporal_state values",
    )
    context_parser.add_argument(
        "--conversation-ids",
        default=None,
        help="comma-separated allowlist of conversation ids",
    )
    context_parser.add_argument(
        "--sensitivity-labels",
        default=None,
        help="comma-separated allowlist of sensitivity labels",
    )
    context_parser.add_argument(
        "--scope-labels",
        default=None,
        help="comma-separated allowlist of scope labels",
    )
    context_parser.add_argument(
        "--include-user-assertions-only",
        action="store_true",
        help="only include user_assertion claims",
    )
    context_parser.add_argument(
        "--max-items",
        type=int,
        default=None,
        help="maximum number of claims in the capsule",
    )
    context_parser.add_argument(
        "--signing-secret",
        default=None,
        help="optional signing secret used for HMAC receipt signing",
    )
    context_parser.add_argument(
        "--output-capsule",
        default=None,
        help="optional path to write just the context capsule payload",
    )
    context_parser.add_argument(
        "--output-receipt",
        default=None,
        help="optional path to write the context receipt payload",
    )
    context_parser.set_defaults(func=_run_context_capsule)

    forget_parser = sub.add_parser("forget", help="rebuild canonical projection with selected claims removed")
    forget_parser.add_argument("canonical", help="path to canonical projection JSON")
    forget_parser.add_argument(
        "--claim-ids",
        default=None,
        help="comma-separated claim ids to remove",
    )
    forget_parser.add_argument(
        "--conversation-ids",
        default=None,
        help="comma-separated conversation ids to remove claims for",
    )
    forget_parser.add_argument(
        "--reason",
        default="",
        help="optional reason string copied into the forget receipt",
    )
    forget_parser.add_argument(
        "--output-projection",
        default=None,
        help="optional path to write the rebuilt projection JSON; defaults to <canonical>.forgotten.json",
    )
    forget_parser.add_argument(
        "--output-receipt",
        default=None,
        help="optional path to write the forget receipt",
    )
    forget_parser.add_argument(
        "--corpus-index",
        default=None,
        help=(
            "atomically tombstone forgotten conversations in this global "
            "corpus index; without it the receipt requires an explicit rebuild"
        ),
    )
    forget_parser.add_argument(
        "--record-source",
        action="store_true",
        help="record forget rebuild result into source manifest",
    )
    forget_parser.add_argument(
        "--source-manifest",
        default=_source_manifest_path(),
        help="source registry path to update when --record-source is set",
    )
    forget_parser.add_argument(
        "--user-id",
        default=None,
        help="namespace action-log entries for this forget",
    )
    forget_parser.add_argument(
        "--action-log-root",
        default=_action_log_root(),
        help="root directory for per-user action logs",
    )
    forget_parser.add_argument("--project-id", default=None)
    forget_parser.add_argument("--root-thread-id", default=None)
    forget_parser.add_argument("--session-id", default=None)
    forget_parser.add_argument("--actor-id", default=None)
    forget_parser.add_argument("--operation-id", default=None)
    forget_parser.add_argument(
        "--project-action-log-root", default=_action_log_root()
    )
    forget_parser.set_defaults(func=_run_forget)

    candidates_parser = sub.add_parser(
        "candidates",
        help="build an explicit-review candidate bundle and content-free receipt",
    )
    candidates_parser.add_argument("canonical", help="path to canonical projection JSON")
    candidates_parser.add_argument(
        "--output-bundle",
        default=None,
        help="candidate bundle path; defaults to <canonical>.candidates.json",
    )
    candidates_parser.add_argument(
        "--output-receipt",
        default=None,
        help="content-free receipt path; defaults to <bundle>.receipt.json",
    )
    candidates_parser.set_defaults(func=_run_candidates)

    concepts_parser = sub.add_parser(
        "concepts-build",
        help="compile a private provenance-aware concept inventory from recall JSONL",
    )
    concepts_parser.add_argument(
        "recall",
        help="existing private concept-recall JSONL",
    )
    concepts_parser.add_argument(
        "--output-inventory",
        required=True,
        help="new private inventory JSON path",
    )
    concepts_parser.add_argument(
        "--output-receipt",
        required=True,
        help="new content-free receipt JSON path",
    )
    concepts_parser.add_argument(
        "--domain-keywords",
        default=None,
        help="optional JSON file of operator domain keywords; default is empty",
    )
    concepts_parser.set_defaults(func=_run_concepts_build)

    corpus_build_parser = sub.add_parser(
        "corpus-build",
        help="build one global lossless message index from canonical projections",
    )
    corpus_build_parser.add_argument("index", help="output Integrity Home SQLite index")
    corpus_build_parser.add_argument(
        "canonicals",
        nargs="+",
        help="one or more canonical projection JSON files",
    )
    corpus_build_parser.add_argument(
        "--allow-synthetic-attachment-text",
        action="store_true",
        help="index attachment text only when every synthetic fixture gate passes",
    )
    corpus_build_parser.add_argument(
        "--deletion-ledger",
        default=None,
        help=(
            "verified authoritative deletion ledger to bind to this index; "
            "required when rebuilding at a new path without the old database"
        ),
    )
    corpus_build_parser.set_defaults(func=_run_corpus_build)

    corpus_upsert_parser = sub.add_parser(
        "corpus-upsert",
        help="atomically add or replace canonical sources in a global corpus index",
    )
    corpus_upsert_parser.add_argument("index", help="existing Integrity Home SQLite index")
    corpus_upsert_parser.add_argument(
        "canonicals",
        nargs="+",
        help="one or more canonical projection JSON files",
    )
    corpus_upsert_parser.add_argument(
        "--allow-synthetic-attachment-text",
        action="store_true",
        help="index attachment text only when every synthetic fixture gate passes",
    )
    corpus_upsert_parser.add_argument(
        "--deletion-ledger",
        default=None,
        help="verified ledger path; must match the existing immutable binding",
    )
    corpus_upsert_parser.set_defaults(func=_run_corpus_upsert)

    corpus_inspect_parser = sub.add_parser(
        "corpus-inspect",
        help="show content-free identity and counts for a global corpus index",
    )
    corpus_inspect_parser.add_argument("index", help="Integrity Home SQLite index")
    corpus_inspect_parser.set_defaults(func=_run_corpus_inspect)

    corpus_v2_gate_parser = sub.add_parser(
        "corpus-prepare-v2-rebuild",
        help="seal a verified v2 backup and export its deletion ledger",
    )
    corpus_v2_gate_parser.add_argument("index", help="legacy v2 SQLite index")
    corpus_v2_gate_parser.add_argument(
        "backup", help="private SQLite snapshot to retain before rebuilding"
    )
    corpus_v2_gate_parser.add_argument(
        "--deletion-ledger",
        default=None,
        help="output ledger path; defaults to <index>.deletions.json",
    )
    corpus_v2_gate_parser.add_argument(
        "--replace-backup",
        action="store_true",
        help="explicitly replace an existing private v2 snapshot",
    )
    corpus_v2_gate_parser.set_defaults(func=_run_corpus_prepare_v2_rebuild)

    corpus_backup_parser = sub.add_parser(
        "corpus-backup",
        help="create a verified local backup of the corpus and deletion ledger",
    )
    corpus_backup_parser.add_argument("index", help="existing Integrity Home corpus index")
    corpus_backup_parser.add_argument("backup", help="new local backup archive path")
    _add_project_audit_arguments(corpus_backup_parser)
    corpus_backup_parser.set_defaults(func=_run_corpus_backup)

    corpus_restore_parser = sub.add_parser(
        "corpus-restore",
        help="restore a verified local corpus backup and replay newer deletions",
    )
    corpus_restore_parser.add_argument("backup", help="verified local backup archive")
    corpus_restore_parser.add_argument("index", help="restored Integrity Home corpus index")
    corpus_restore_parser.add_argument(
        "--replace",
        action="store_true",
        help="replace an adjacent-bound index after preserving newer deletions",
    )
    _add_project_audit_arguments(corpus_restore_parser)
    corpus_restore_parser.set_defaults(func=_run_corpus_restore)

    corpus_search_parser = sub.add_parser(
        "corpus-search",
        help="search every indexed message with exact provenance and bounded context",
    )
    corpus_search_parser.add_argument("index", help="Integrity Home SQLite index")
    corpus_search_parser.add_argument("--query", default="")
    corpus_search_parser.add_argument("--providers", default=None)
    corpus_search_parser.add_argument("--source-ids", default=None)
    corpus_search_parser.add_argument("--conversation-ids", default=None)
    corpus_search_parser.add_argument("--roles", default=None)
    corpus_search_parser.add_argument("--models", default=None)
    corpus_search_parser.add_argument("--content-types", default=None)
    corpus_search_parser.add_argument("--created-from", default=None)
    corpus_search_parser.add_argument("--created-to", default=None)
    corpus_search_parser.add_argument(
        "--match-mode",
        choices=("fts", "substring"),
        default="fts",
    )
    corpus_search_parser.add_argument(
        "--include-attachment-text",
        action="store_true",
    )
    corpus_search_parser.add_argument("--context-radius", type=int, default=1)
    corpus_search_parser.add_argument("--limit", type=int, default=50)
    corpus_search_parser.add_argument("--offset", type=int, default=0)
    corpus_search_parser.add_argument(
        "--max-substring-scan-rows",
        type=int,
        default=10_000,
    )
    corpus_search_parser.add_argument("--output", default=None)
    corpus_search_parser.set_defaults(func=_run_corpus_search)

    memory_status_parser = sub.add_parser(
        "memory-status",
        help="list configured personal and project memory scopes without paths",
    )
    memory_status_parser.add_argument(
        "--registry",
        default=None,
        help="trusted local scope-registry path (defaults to Integrity Home state)",
    )
    memory_status_parser.set_defaults(func=_run_memory_status)

    memory_search_parser = sub.add_parser(
        "memory-search",
        help="search explicit memory scopes or every enabled registered scope",
    )
    memory_search_parser.add_argument("--query", required=True)
    memory_search_parser.add_argument(
        "--registry",
        default=None,
        help="trusted local scope-registry path (defaults to Integrity Home state)",
    )
    memory_scope = memory_search_parser.add_mutually_exclusive_group(required=True)
    memory_scope.add_argument(
        "--scope-id",
        action="append",
        dest="scope_ids",
        help="stable scope ID; repeat to search more than one explicit scope",
    )
    memory_scope.add_argument(
        "--everywhere",
        action="store_true",
        help="search every enabled scope, including all registered project scopes",
    )
    memory_search_parser.add_argument("--context-radius", type=int, default=0)
    memory_search_parser.add_argument("--limit", type=int, default=50)
    memory_search_parser.add_argument("--output", default=None)
    memory_search_parser.set_defaults(func=_run_memory_search)

    action_log_sync_parser = sub.add_parser(
        "action-log-sync",
        help="publish projection receipt and explicitly reviewed candidates",
    )
    action_log_sync_parser.add_argument("candidate_bundle", help="local candidate bundle JSON")
    action_log_sync_parser.add_argument("candidate_receipt", help="content-free candidate receipt JSON")
    action_log_sync_parser.add_argument("review_state", help="projection-bound review state JSON")
    action_log_sync_parser.add_argument("--user-id", required=True, help="Action Log user namespace")
    action_log_sync_parser.add_argument(
        "--action-log-root",
        default=_action_log_root(),
        help="root directory for per-user action logs",
    )
    action_log_sync_parser.add_argument(
        "--review-signing-secret",
        default=None,
        help="optional secret required to verify signed review decisions",
    )
    _add_project_audit_arguments(action_log_sync_parser)
    action_log_sync_parser.set_defaults(func=_run_action_log_sync)

    action_log_context_parser = sub.add_parser(
        "action-log-context",
        help="build a context capsule from reviewed non-authoritative Action Log candidates",
    )
    action_log_context_parser.add_argument("--user-id", required=True)
    action_log_context_parser.add_argument("--action-log-root", default=_action_log_root())
    action_log_context_parser.add_argument(
        "--corpus-index",
        required=True,
        help="current global Integrity Home SQLite index used for freshness and tombstones",
    )
    action_log_context_parser.add_argument("--purpose", default="task_context")
    action_log_context_parser.add_argument("--task-id", default="")
    action_log_context_parser.add_argument("--scope", default="default")
    action_log_context_parser.add_argument("--claim-types", default=None)
    action_log_context_parser.add_argument("--temporal-states", default=None)
    action_log_context_parser.add_argument("--conversation-ids", default=None)
    action_log_context_parser.add_argument("--sensitivity-labels", default=None)
    action_log_context_parser.add_argument("--scope-labels", default=None)
    action_log_context_parser.add_argument(
        "--include-user-assertions-only", action="store_true"
    )
    action_log_context_parser.add_argument("--max-items", type=int, default=None)
    action_log_context_parser.add_argument("--signing-secret", default=None)
    action_log_context_parser.add_argument("--output-capsule", default=None)
    action_log_context_parser.add_argument("--output-receipt", default=None)
    _add_project_audit_arguments(action_log_context_parser)
    action_log_context_parser.set_defaults(func=_run_action_log_context)

    action_log_recall_parser = sub.add_parser(
        "action-log-recall",
        help="run one bounded global-corpus recall and record a content-free receipt",
    )
    action_log_recall_parser.add_argument("index", help="global Integrity Home SQLite index")
    action_log_recall_parser.add_argument("--query", required=True)
    action_log_recall_parser.add_argument("--user-id", required=True)
    action_log_recall_parser.add_argument("--action-log-root", default=_action_log_root())
    action_log_recall_parser.add_argument("--context-radius", type=int, default=1)
    action_log_recall_parser.add_argument("--limit", type=int, default=10)
    action_log_recall_parser.add_argument(
        "--expect-index-generation",
        default=None,
        help="fail closed unless the corpus index generation matches",
    )
    action_log_recall_parser.add_argument(
        "--output-results",
        default=None,
        help="optional local path for the bounded recall payload",
    )
    action_log_recall_parser.add_argument("--project-id", default=None)
    action_log_recall_parser.add_argument("--root-thread-id", default=None)
    action_log_recall_parser.add_argument("--session-id", default=None)
    action_log_recall_parser.add_argument("--actor-id", default=None)
    action_log_recall_parser.add_argument("--operation-id", default=None)
    action_log_recall_parser.add_argument(
        "--project-action-log-root", default=_action_log_root()
    )
    action_log_recall_parser.set_defaults(func=_run_action_log_recall)

    project_action_parser = sub.add_parser(
        "project-action-record",
        help="append a content-free, hash-chained work-project Action Log entry",
    )
    project_action_parser.add_argument("--action-log-root", default=_action_log_root())
    project_action_parser.add_argument("--project-id", required=True)
    project_action_parser.add_argument("--root-thread-id", required=True)
    project_action_parser.add_argument("--session-id", required=True)
    project_action_parser.add_argument("--actor-id", required=True)
    project_action_parser.add_argument("--operation-id", required=True)
    project_action_parser.add_argument("--action", required=True)
    project_action_parser.add_argument(
        "--status", required=True, choices=("started", "ok", "failed", "cancelled")
    )
    project_action_parser.add_argument(
        "--artifact-sha256", action="append", default=[],
        help="content-free artifact digest; repeat for multiple artifacts",
    )
    project_action_parser.set_defaults(func=_run_project_action_record)

    project_verify_parser = sub.add_parser(
        "project-action-verify", help="verify a complete work-project Action Log chain"
    )
    project_verify_parser.add_argument("--action-log-root", default=_action_log_root())
    project_verify_parser.add_argument("--project-id", required=True)
    project_verify_parser.set_defaults(func=_run_project_action_verify)

    search_parser = sub.add_parser("search", help="search canonical projection with deterministic evidence")
    search_parser.add_argument("canonical", help="path to canonical projection JSON")
    search_parser.add_argument("--query", default="", help="query text to rank claims")
    search_parser.add_argument(
        "--provider",
        default=None,
        help="filter results to a provider value",
    )
    search_parser.add_argument(
        "--conversation-ids",
        default=None,
        help="comma-separated conversation ids",
    )
    search_parser.add_argument(
        "--claim-types",
        default=None,
        help="comma-separated claim types",
    )
    search_parser.add_argument(
        "--temporal-states",
        default=None,
        help="comma-separated temporal states",
    )
    search_parser.add_argument(
        "--speakers",
        default=None,
        help="comma-separated speakers (user|assistant|other)",
    )
    search_parser.add_argument(
        "--models",
        default=None,
        help="comma-separated model names",
    )
    search_parser.add_argument(
        "--content-types",
        default=None,
        help="comma-separated content type filters",
    )
    search_parser.add_argument(
        "--from-timestamp",
        default=None,
        help="minimum created_at timestamp (inclusive)",
    )
    search_parser.add_argument(
        "--to-timestamp",
        default=None,
        help="maximum created_at timestamp (inclusive)",
    )
    search_parser.add_argument(
        "--max-results",
        type=int,
        default=None,
        help="optional result limit",
    )
    search_parser.add_argument(
        "--output",
        default=None,
        help="optional path to write search results JSON",
    )
    search_parser.set_defaults(func=_run_search)

    review_parser = sub.add_parser("review", help="run a loopback review API server")
    review_parser.add_argument("canonical", help="path to canonical projection JSON")
    review_parser.add_argument(
        "--state-path",
        default=None,
        help="path to persist review decisions; defaults to <canonical>.reviews.json",
    )
    review_parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="host interface to bind the review API",
    )
    review_parser.add_argument(
        "--port",
        type=int,
        default=8765,
        help="listen port for the review API",
    )
    review_parser.add_argument(
        "--signing-secret",
        default=None,
        help="optional HMAC secret to sign review decisions",
    )
    review_parser.set_defaults(func=_run_review_api)

    return parser


def _doctor_checks() -> List[str]:
    checks = []
    runtime_root = state_root()
    checks.append(f"state_root={runtime_root}")
    checks.append(f"python_exec={sys.executable}")
    for env_var in ("PYTHONHASHSEED", "TZ"):
        checks.append(f"{env_var}={os.environ.get(env_var, '')}")
    required_dirs = [
        "vault/raw",
        "vault/tmp",
        "vault/index",
        "manifests",
        "tests",
    ]
    for rel in required_dirs:
        path = runtime_root / rel
        checks.append(f"{rel}_exists={path.is_dir()}")
    return checks


def _write_payload(payload: Dict, path: str) -> str:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    target = Path(path)
    payload_text = json.dumps(payload, sort_keys=True, indent=2) + "\n"
    fd, tmp = tempfile.mkstemp(prefix="chronicle-context-", suffix=".json", dir=target.parent)
    with open(fd, "w", encoding="utf-8") as fp:
        fp.write(payload_text)
    Path(tmp).replace(target)
    return str(target)


def _run_doctor(_: Namespace) -> int:
    checks = _doctor_checks()
    print("\n".join(checks))
    return 0


def _run_import(args: Namespace) -> int:
    archive_path = Path(args.archive)
    if not archive_path.is_file():
        print(f"archive path does not exist: {archive_path}", file=sys.stderr)
        return 2

    source_sha = _sha256_file(str(archive_path))
    source_id = source_sha[:24]

    report = validate_archive(
        str(archive_path),
        max_member_count=args.max_members,
        max_member_size_bytes=args.max_member_size,
        max_total_uncompressed_bytes=args.max_total_uncompressed,
        max_compression_ratio=args.max_compression_ratio,
    )

    if args.output_manifest and not args.dry_run:
        print("--output-manifest is only supported with --dry-run", file=sys.stderr)
        return 1

    if args.dry_run:
        payload: Dict = report.to_dict()
        print(json.dumps(payload, sort_keys=True, indent=2))

        if args.output_manifest:
            write_manifest_file(report, str(archive_path), args.output_manifest)
            print(f"manifest_written={args.output_manifest}")

        if args.record_source and report.valid:
            record_source_manifest(
                report,
                str(archive_path),
                args.source_manifest,
                user_id=args.user_id,
                processing_state="dry_run_validated",
                content_inspected=False,
                content_extracted=False,
            )
            print(f"source_manifest_updated={args.source_manifest}")

        if args.user_id:
            event_type = (
                ACTION_LOG_EVENT_IMPORT_DRY_RUN_COMPLETED
                if report.valid
                else ACTION_LOG_EVENT_IMPORT_DRY_RUN_REJECTED
            )
            try:
                append_import_action_event(
                    args.action_log_root,
                    args.user_id,
                    event_type=event_type,
                    source_id=source_id,
                    source_sha256=source_sha,
                    archive_name=archive_path.name,
                    dry_run=True,
                    provider_guess=report.provider_guess,
                    provider_hint=getattr(args, "provider_hint", None),
                    status="ok" if report.valid else "rejected",
                    source_manifest_recorded=bool(args.record_source),
                    source_manifest_path=str(Path(args.source_manifest).resolve()),
                    status_reason=None if report.valid else "invalid_archive",
                )
            except (TypeError, ValueError) as err:
                print(f"action-log failed: {err}", file=sys.stderr)
                return 2

        return 0 if report.valid else 2

    if not report.valid:
        if args.user_id:
            append_import_action_event(
                args.action_log_root,
                args.user_id,
                event_type=ACTION_LOG_EVENT_IMPORT_FAILED,
                source_id=source_id,
                source_sha256=source_sha,
                archive_name=archive_path.name,
                dry_run=False,
                provider_guess=report.provider_guess,
                provider_hint=getattr(args, "provider_hint", None),
                status="rejected",
                status_reason="invalid_archive",
            )
        print(json.dumps(report.to_dict(), sort_keys=True, indent=2))
        return 2

    try:
        semantic_extractor = build_semantic_extractor(args.semantic_backend)
    except CanonicalizationError as err:
        print(f"adapter failed: {err}", file=sys.stderr)
        if args.user_id:
            append_import_action_event(
                args.action_log_root,
                args.user_id,
                event_type=ACTION_LOG_EVENT_IMPORT_FAILED,
                source_id=source_id,
                source_sha256=source_sha,
                archive_name=archive_path.name,
                dry_run=False,
                provider_guess=report.provider_guess,
                provider_hint=getattr(args, "provider_hint", None),
                status="failed",
                status_reason=str(err),
            )
        return 2

    try:
        with staged_archive_extraction(
            str(archive_path),
            max_member_count=args.max_members,
            max_member_size_bytes=args.max_member_size,
            max_total_uncompressed_bytes=args.max_total_uncompressed,
            max_compression_ratio=args.max_compression_ratio,
        ) as workspace:
            print(json.dumps(report.to_dict(), sort_keys=True, indent=2))
            print(f"extraction_workspace={workspace.path}")
            print(f"extracted_files={len(workspace.extracted_files)}")
            print(f"extracted_bytes={workspace.extracted_bytes}")
            canonical_payload = parse_staged_archive(
                workspace.path,
                provider_hint=args.provider_hint,
                semantic_extractor=semantic_extractor,
            )
            canonical_path = args.output_canonical or _default_canonical_path(str(archive_path))
            canonical_written = write_canonical_manifest(
                canonical_payload,
                canonical_path,
            )
            print(f"canonical_manifest_written={canonical_written}")
            canonical_projection_sha256 = _sha256_file(canonical_written)
            print(
                json.dumps(
                    {
                        "canonical_import": {
                            "schema_version": canonical_payload.get("schema_version"),
                            "source_id": canonical_payload.get("source_id"),
                            "provider": canonical_payload.get("provider"),
                            "provider_schema_version": canonical_payload.get(
                                "provider_schema_version"
                            ),
                            "conversation_count": canonical_payload.get(
                                "conversation_count", 0
                            ),
                            "message_count": canonical_payload.get("message_count", 0),
                            "claim_count": canonical_payload.get("claim_count", 0),
                            "duplicate_candidate_count": len(
                                canonical_payload.get("message_duplicate_candidates", [])
                            ),
                            "projection_sha256": canonical_payload.get(
                                "projection_sha256"
                            ),
                            "canonical_manifest_sha256": canonical_projection_sha256,
                        }
                    },
                    sort_keys=True,
                    indent=2,
                )
            )
            if args.record_source:
                record_source_manifest(
                    report,
                    str(archive_path),
                    args.source_manifest,
                    user_id=args.user_id,
                    processing_state=STATE_CANONICAL_PARSED,
                    content_inspected=True,
                    content_extracted=True,
                    canonical_projection_path=str(Path(canonical_written).resolve()),
                    canonical_projection_sha256=canonical_projection_sha256,
                )
                print(f"source_manifest_updated={args.source_manifest}")

            if args.user_id:
                append_import_action_event(
                    args.action_log_root,
                    args.user_id,
                    event_type=ACTION_LOG_EVENT_IMPORT_COMPLETED,
                    source_id=source_id,
                    source_sha256=source_sha,
                    archive_name=archive_path.name,
                    dry_run=False,
                    provider_guess=report.provider_guess,
                    provider_hint=getattr(args, "provider_hint", None),
                    status="ok",
                    status_reason=None,
                    source_manifest_recorded=bool(args.record_source),
                    source_manifest_path=str(Path(args.source_manifest).resolve()),
                    canonical_projection_path=str(Path(canonical_written).resolve()),
                    canonical_projection_sha256=canonical_projection_sha256,
                )
    except RuntimeError as err:
        print(f"import failed: {err}", file=sys.stderr)
        if args.user_id:
            try:
                append_import_action_event(
                    args.action_log_root,
                    args.user_id,
                    event_type=ACTION_LOG_EVENT_IMPORT_FAILED,
                    source_id=source_id,
                    source_sha256=source_sha,
                    archive_name=archive_path.name,
                    dry_run=False,
                    provider_guess=report.provider_guess,
                    provider_hint=getattr(args, "provider_hint", None),
                    status="failed",
                    status_reason=str(err),
                )
            except (TypeError, ValueError) as exc:
                print(f"action-log failed: {exc}", file=sys.stderr)
                return 2
        return 2
    except CanonicalizationError as err:
        print(f"adapter failed: {err}", file=sys.stderr)
        if args.user_id:
            try:
                append_import_action_event(
                    args.action_log_root,
                    args.user_id,
                    event_type=ACTION_LOG_EVENT_IMPORT_FAILED,
                    source_id=source_id,
                    source_sha256=source_sha,
                    archive_name=archive_path.name,
                    dry_run=False,
                    provider_guess=report.provider_guess,
                    provider_hint=getattr(args, "provider_hint", None),
                    status="failed",
                    status_reason=str(err),
                )
            except (TypeError, ValueError) as exc:
                print(f"action-log failed: {exc}", file=sys.stderr)
                return 2
        return 2

    return 0


def _run_context_capsule(args: Namespace) -> int:
    canonical_path = Path(args.canonical)
    if not canonical_path.is_file():
        print(f"canonical projection path does not exist: {canonical_path}", file=sys.stderr)
        return 2

    try:
        projection = _read_json_object(str(canonical_path), label="canonical projection")
        if not isinstance(projection, dict):
            raise ValueError("canonical projection is not an object")
    except (OSError, ValueError, json.JSONDecodeError) as err:
        print(f"context-capsule failed: {err}", file=sys.stderr)
        return 2

    try:
        policy = ContextPolicy(
            include_claim_types=parse_csv_set(
                args.claim_types,
                field_name="claim_types",
                allowed_values=ALLOWED_CLAIM_TYPES,
            ),
            include_temporal_states=parse_csv_set(
                args.temporal_states,
                field_name="temporal_states",
                allowed_values=ALLOWED_TEMPORAL_STATES,
            ),
            include_user_assertion_only=bool(args.include_user_assertions_only),
            include_conversation_ids=parse_csv_set(args.conversation_ids, field_name="conversation_ids"),
            include_sensitivity_labels=parse_csv_set(
                args.sensitivity_labels,
                field_name="sensitivity_labels",
            ),
            include_scope_labels=parse_csv_set(
                args.scope_labels,
                field_name="scope_labels",
            ),
            max_items=args.max_items,
        )
        if policy.max_items is not None and policy.max_items < 0:
            raise ValueError("max-items must be non-negative")
        result = build_context_bundle(
            projection,
            policy,
            purpose=str(args.purpose),
            task_id=str(args.task_id),
            scope=str(args.scope),
            signing_secret=args.signing_secret,
        )
    except (TypeError, ValueError) as err:
        print(f"context-capsule failed: {err}", file=sys.stderr)
        return 2

    if args.output_capsule:
        _write_payload(result["context_capsule"], str(args.output_capsule))
    if args.output_receipt:
        _write_payload(result["context_receipt"], str(args.output_receipt))

    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


def _append_sanitized_forget_failure(
    args: Namespace,
    *,
    source_id: str,
    source_projection_sha256_before: Optional[str],
    source_projection_sha256_after: Optional[str],
    stage: str,
    error: BaseException,
    operation_id: Optional[str] = None,
) -> None:
    """Record a failure without copying paths, prose, or exception text."""

    details = {
        "error_sha256": sha256(str(error).encode("utf-8", errors="replace")).hexdigest(),
        "reason_sha256": sha256(
            str(getattr(args, "reason", "")).encode("utf-8", errors="replace")
        ).hexdigest(),
    }
    append_forget_action_event(
        args.action_log_root,
        args.user_id,
        event_type=ACTION_LOG_EVENT_FORGET_FAILED,
        source_id=source_id,
        source_projection_sha256_before=source_projection_sha256_before,
        source_projection_sha256_after=source_projection_sha256_after,
        canonical_projection_path=None,
        status="failed",
        status_reason=stage,
        reason="",
        extra=details,
        operation_id=operation_id,
    )


def _run_forget(args: Namespace) -> int:
    canonical_path = Path(args.canonical)
    if not canonical_path.is_file():
        print(f"canonical projection path does not exist: {canonical_path}", file=sys.stderr)
        return 2

    projection_source_id: Optional[str] = None
    source_projection_sha256_before: Optional[str] = None
    claim_ids = set()
    conversation_ids = set()
    rebuilt_projection: Optional[Dict] = None
    receipt: Optional[Dict] = None
    project_context: Optional[Dict[str, str]] = None
    folder_generation_root: Optional[Path] = None
    history_sidecar_path: Optional[Path] = None
    history_recovery_path: Optional[Path] = None
    history_snapshot = None

    try:
        project_context = _project_context_args(args)
        if args.corpus_index:
            candidate_root = Path(args.corpus_index).resolve().parent
            if (candidate_root / "folder-intake.receipt.json").is_file():
                folder_generation_root = candidate_root
                candidate_sidecar = candidate_root / "history.sqlite"
                if candidate_sidecar.is_file():
                    from integrity_home.unified_publication import (
                        _capture_unified_sidecar_snapshot,
                        _snapshot_from_payload,
                        _snapshot_payload,
                    )
                    history_sidecar_path = candidate_sidecar
                    history_recovery_path = candidate_root / "history-forget-recovery.json"
                    try:
                        history_snapshot = _capture_unified_sidecar_snapshot(
                            str(Path(args.corpus_index).resolve()), str(candidate_sidecar)
                        )
                        if history_recovery_path.exists():
                            history_recovery_path.unlink()
                    except RuntimeError:
                        if not history_recovery_path.is_file():
                            raise
                        if history_recovery_path.stat().st_size > _MAX_HISTORY_RECOVERY_BYTES:
                            raise ValueError("History recovery journal exceeds resource limit")
                        recovery_payload = _read_json_object(
                            str(history_recovery_path), label="History recovery journal"
                        )
                        history_snapshot = _snapshot_from_payload(
                            recovery_payload,
                            actual_sidecar_sha256=_sha256_file(str(candidate_sidecar)),
                        )
                    if not history_recovery_path.exists():
                        _write_payload(
                            _snapshot_payload(
                                history_snapshot,
                                source_sidecar_sha256=_sha256_file(str(candidate_sidecar)),
                            ),
                            str(history_recovery_path),
                        )
        projection = _read_json_object(
            str(canonical_path), label="canonical projection"
        )
        if isinstance(projection.get("source_id"), str) and projection["source_id"]:
            projection_source_id = projection["source_id"]
        claim_ids = parse_csv_set(args.claim_ids, field_name="claim_ids") or set()
        conversation_ids = (
            parse_csv_set(args.conversation_ids, field_name="conversation_ids") or set()
        )
        rebuilt_projection, receipt = apply_forget(
            projection,
            forget_claim_ids=claim_ids,
            forget_conversation_ids=conversation_ids,
            reason=str(args.reason),
        )
        source_projection_sha256_before = str(
            receipt["source_projection_sha256_before"]
        )
        if conversation_ids and args.corpus_index:
            from .corpus_index import (
                forget_corpus_conversations,
                upsert_corpus_sources,
            )
            from .state_lock import corpus_state_lock

            # One outer lock covers both the durable tombstone commit and the
            # source-generation refresh. The called writer APIs are re-entrant.
            with corpus_state_lock(str(args.corpus_index)):
                corpus_result = forget_corpus_conversations(
                    str(args.corpus_index),
                    source_id=str(projection.get("source_id") or ""),
                    conversation_ids=conversation_ids,
                )
                corpus_summary = upsert_corpus_sources(
                    rebuilt_projection,
                    str(args.corpus_index),
                )
            receipt["corpus_rebuild_required"] = False
            receipt["corpus_index_generation_before"] = corpus_result[
                "index_generation_before"
            ]
            receipt["corpus_index_generation_after_forget"] = corpus_result[
                "index_generation_after"
            ]
            receipt["corpus_index_generation_after"] = corpus_summary[
                "index_generation"
            ]
            receipt["corpus_tombstone_count"] = corpus_summary["tombstone_count"]
            receipt["corpus_source_projection_sha256_after"] = str(
                rebuilt_projection["projection_sha256"]
            )
            receipt["operation_state"] = "durable_revocation_committed"
        elif conversation_ids:
            receipt["operation_state"] = "projection_rebuild_required"
        elif args.corpus_index:
            from .corpus_index import inspect_corpus_index, upsert_corpus_sources
            from .state_lock import corpus_state_lock

            with corpus_state_lock(str(args.corpus_index)):
                corpus_before = inspect_corpus_index(str(args.corpus_index))
                corpus_summary = upsert_corpus_sources(
                    rebuilt_projection,
                    str(args.corpus_index),
                )
            receipt["corpus_index_generation_before"] = corpus_before[
                "index_generation"
            ]
            receipt["corpus_index_generation_after"] = corpus_summary[
                "index_generation"
            ]
            receipt["corpus_source_projection_sha256_after"] = str(
                rebuilt_projection["projection_sha256"]
            )
            receipt["corpus_generation_refresh_required"] = False
            receipt["operation_state"] = "corpus_generation_refreshed"
        else:
            receipt["corpus_generation_refresh_required"] = True
            receipt["operation_state"] = "projection_prepared"
        if projection_source_id is None:
            projection_source_id = str(projection.get("source_id") or "")
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError, TypeError) as err:
        if args.user_id and projection_source_id:
            try:
                _append_sanitized_forget_failure(
                    args,
                    source_id=projection_source_id,
                    source_projection_sha256_before=source_projection_sha256_before,
                    source_projection_sha256_after=None,
                    stage="prepare_failed",
                    error=err,
                )
            except (OSError, TypeError, ValueError) as log_err:
                print(f"action-log failed: {log_err}", file=sys.stderr)
                return 2
        print(f"forget failed: {err}", file=sys.stderr)
        return 2

    output_projection = str(args.output_projection) if args.output_projection else (
        str(canonical_path)
        if folder_generation_root is not None
        and canonical_path.resolve().parent == folder_generation_root / "canonical"
        else str(canonical_path.parent / f"{canonical_path.name}.forgotten.json")
    )
    assert rebuilt_projection is not None and receipt is not None

    # For claim-only deletion the Action Log is the revocation barrier used by
    # reviewed-memory replay. Commit it before publishing a forgotten artifact
    # or source-manifest generation so an append failure cannot split state.
    if args.user_id and projection_source_id:
        try:
            append_forget_action_event(
                args.action_log_root,
                args.user_id,
                event_type=ACTION_LOG_EVENT_FORGET_COMPLETED,
                source_id=projection_source_id,
                source_projection_sha256_before=source_projection_sha256_before,
                source_projection_sha256_after=str(
                    rebuilt_projection.get("projection_sha256", "")
                ),
                canonical_projection_path=str(Path(output_projection).resolve()),
                status="ok",
                status_reason=None,
                removed_claim_ids=sorted(claim_ids),
                removed_conversation_ids=sorted(conversation_ids),
                reason=str(args.reason),
                operation_id=str(receipt["operation_id"]),
            )
            receipt["action_log_revocation_committed"] = True
        except (OSError, TypeError, ValueError) as err:
            try:
                _append_sanitized_forget_failure(
                    args,
                    source_id=projection_source_id,
                    source_projection_sha256_before=source_projection_sha256_before,
                    source_projection_sha256_after=str(
                        rebuilt_projection.get("projection_sha256", "")
                    ),
                    stage="revocation_barrier_failed",
                    error=err,
                    operation_id=receipt.get("operation_id"),
                )
            except (OSError, TypeError, ValueError):
                pass
            print(f"action-log failed before artifact publication: {err}", file=sys.stderr)
            return 2

    try:
        _write_payload(rebuilt_projection, output_projection)
        if history_sidecar_path is not None and history_snapshot is not None:
            from integrity_home.unified_publication import (
                _rebuild_unified_sidecar_from_snapshot,
            )
            history_summary = _rebuild_unified_sidecar_from_snapshot(
                str(Path(args.corpus_index).resolve()),
                str(history_sidecar_path), history_snapshot,
            )
            receipt["history_sidecar_resealed"] = True
            receipt["history_sidecar_generation_after"] = history_summary[
                "sidecar_generation"
            ]
            if history_recovery_path is not None:
                history_recovery_path.unlink(missing_ok=True)
        if folder_generation_root is not None:
            refresh_archive_generation_receipt(str(folder_generation_root))
            receipt["folder_generation_receipt_refreshed"] = True
        if args.output_receipt:
            _write_payload(receipt, str(args.output_receipt))
        if project_context is not None:
            evidence = [_sha256_file(output_projection), _sha256_payload(receipt)]
            if history_sidecar_path is not None:
                evidence.append(_sha256_file(str(history_sidecar_path)))
            if args.output_receipt:
                evidence.append(_sha256_file(str(args.output_receipt)))
            append_project_action(
                args.project_action_log_root,
                **project_context,
                action="memory_forget",
                status="ok",
                artifact_sha256s=evidence,
            )
    except (OSError, ProjectActionLogError, ValueError) as err:
        if args.user_id and projection_source_id:
            try:
                _append_sanitized_forget_failure(
                    args,
                    source_id=projection_source_id,
                    source_projection_sha256_before=source_projection_sha256_before,
                    source_projection_sha256_after=str(
                        rebuilt_projection.get("projection_sha256", "")
                    ),
                    stage="artifact_publication_failed",
                    error=err,
                    operation_id=receipt.get("operation_id"),
                )
            except (OSError, TypeError, ValueError) as log_err:
                print(f"action-log failed: {log_err}", file=sys.stderr)
        print(
            "forget artifact publication failed after "
            f"{receipt.get('operation_state')}; retry operation "
            f"{receipt.get('operation_id')}: {err}",
            file=sys.stderr,
        )
        return 2

    if args.record_source:
        try:
            record_projection_rebuild(
                str(args.source_manifest),
                str(rebuilt_projection.get("source_id", "")),
                processing_state=STATE_CANONICAL_FORGOT,
                canonical_projection_path=str(Path(output_projection).resolve()),
                canonical_projection_sha256=str(rebuilt_projection["projection_sha256"]),
                before_projection_sha256=receipt.get("source_projection_sha256_before"),
                event_type="forget",
                action_schema_version=receipt["action_schema_version"],
                receipt_id=receipt["receipt_id"],
                reason=str(args.reason),
                removed_claim_ids=receipt["removed_claim_ids"],
                removed_conversation_ids=receipt["removed_conversation_ids"],
                removed_claim_id_count_from_selector=receipt[
                    "removed_claim_id_count_from_selector"
                ],
            )
        except (ValueError, RuntimeError, OSError, KeyError) as err:
            if args.user_id and projection_source_id:
                try:
                    _append_sanitized_forget_failure(
                        args,
                        source_id=projection_source_id,
                        source_projection_sha256_before=source_projection_sha256_before,
                        source_projection_sha256_after=str(
                            rebuilt_projection.get("projection_sha256", "")
                        ),
                        stage="source_manifest_publication_failed",
                        error=err,
                        operation_id=receipt.get("operation_id"),
                    )
                except (OSError, TypeError, ValueError):
                    pass
            print(f"forget manifest update failed: {err}", file=sys.stderr)
            return 2
        print(f"source_manifest_updated={args.source_manifest}")

    print(json.dumps({"forget_receipt": receipt, "projection_path": output_projection}, sort_keys=True, indent=2))
    return 0


def _run_candidates(args: Namespace) -> int:
    canonical_path = Path(args.canonical)
    if not canonical_path.is_file():
        print(f"canonical projection path does not exist: {canonical_path}", file=sys.stderr)
        return 2

    try:
        with open(canonical_path, "r", encoding="utf-8") as fp:
            projection = load_json_strict(fp)
        result = build_candidate_bundle(projection)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as err:
        print(f"candidates failed: {err}", file=sys.stderr)
        return 2

    bundle_path = str(args.output_bundle or f"{canonical_path}.candidates.json")
    receipt_path = str(args.output_receipt or f"{bundle_path}.receipt.json")
    _write_payload(result["candidate_bundle"], bundle_path)
    _write_payload(result["candidate_receipt"], receipt_path)

    print(f"candidate_bundle_written={bundle_path}")
    print(f"candidate_receipt_written={receipt_path}")
    print(json.dumps(result["candidate_receipt"], sort_keys=True, indent=2))
    return 0


def _run_import_folder(args: Namespace) -> int:
    context_fields: Optional[Dict[str, str]] = None
    try:
        context_fields = _project_context_args(args)
        receipt = import_archive_folder(
            args.folder,
            args.output,
            max_archives=args.max_archives,
            max_archive_bytes=args.max_archive_bytes,
            max_member_count=args.max_members,
            max_member_size_bytes=args.max_member_size,
            max_total_uncompressed_bytes=args.max_total_uncompressed,
            max_compression_ratio=args.max_compression_ratio,
            semantic_backend=args.semantic_backend,
        )
        if context_fields is not None:
            receipt_path = Path(args.output).resolve() / "folder-intake.receipt.json"
            corpus_path = Path(args.output).resolve() / "corpus.sqlite"
            append_project_action(
                args.project_action_log_root,
                **context_fields,
                action="archive_folder_import",
                status="ok",
                artifact_sha256s=[
                    _sha256_file(str(receipt_path)),
                    _sha256_file(str(corpus_path)),
                ],
            )
    except (FolderIntakeError, RuntimeError, CanonicalizationError, OSError, ValueError) as err:
        if context_fields is not None:
            try:
                append_project_action(
                    args.project_action_log_root,
                    **context_fields,
                    action="archive_folder_import",
                    status="failed",
                )
            except (OSError, ProjectActionLogError, TypeError, ValueError) as log_err:
                print(f"project action log failed: {log_err}", file=sys.stderr)
        print(f"folder import failed: {err}", file=sys.stderr)
        return 2
    print(json.dumps(receipt, sort_keys=True, indent=2))
    print(f"generation_written={Path(args.output).resolve()}")
    return 0


def _run_concepts_build(args: Namespace) -> int:
    """Compile private recall without echoing private paths or evidence."""

    try:
        from .concept_inventory import compile_concept_inventory

        receipt = compile_concept_inventory(
            str(args.recall),
            str(args.output_inventory),
            str(args.output_receipt),
            replace=False,
            domain_keywords_path=args.domain_keywords,
        )
    except (OSError, TypeError, ValueError, RuntimeError, json.JSONDecodeError):
        # Recall paths, source identifiers, and evidence text are private. The
        # library exposes coded validation errors to trusted local callers;
        # the general CLI deliberately emits only a content-free failure.
        print("concepts-build failed", file=sys.stderr)
        return 2

    print(json.dumps(receipt, sort_keys=True, indent=2))
    return 0


def _read_json_object(path: str, *, label: str) -> Dict:
    with open(path, "r", encoding="utf-8") as fp:
        payload = load_json_strict(fp)
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must be a JSON object")
    return payload


def _read_canonical_projections(paths: List[str]) -> List[Dict]:
    projections: List[Dict] = []
    for index, path in enumerate(paths):
        projections.append(
            _read_json_object(path, label=f"canonical projection at index {index}")
        )
    return projections


def _run_corpus_build(args: Namespace) -> int:
    try:
        from .corpus_index import build_corpus_index

        summary = build_corpus_index(
            _read_canonical_projections(list(args.canonicals)),
            str(args.index),
            allow_synthetic_attachment_text=bool(
                args.allow_synthetic_attachment_text
            ),
            deletion_ledger_path=args.deletion_ledger,
        )
    except (OSError, TypeError, ValueError, RuntimeError, json.JSONDecodeError) as err:
        print(f"corpus-build failed: {err}", file=sys.stderr)
        return 2
    print(json.dumps(summary, sort_keys=True, indent=2))
    return 0


def _run_corpus_upsert(args: Namespace) -> int:
    try:
        from .corpus_index import upsert_corpus_sources

        summary = upsert_corpus_sources(
            _read_canonical_projections(list(args.canonicals)),
            str(args.index),
            allow_synthetic_attachment_text=bool(
                args.allow_synthetic_attachment_text
            ),
            deletion_ledger_path=args.deletion_ledger,
        )
    except (OSError, TypeError, ValueError, RuntimeError, json.JSONDecodeError) as err:
        print(f"corpus-upsert failed: {err}", file=sys.stderr)
        return 2
    print(json.dumps(summary, sort_keys=True, indent=2))
    return 0


def _run_corpus_inspect(args: Namespace) -> int:
    try:
        from .corpus_index import inspect_corpus_index

        summary = inspect_corpus_index(str(args.index))
    except (OSError, TypeError, ValueError, RuntimeError) as err:
        print(f"corpus-inspect failed: {err}", file=sys.stderr)
        return 2
    print(json.dumps(summary, sort_keys=True, indent=2))
    return 0


def _run_corpus_prepare_v2_rebuild(args: Namespace) -> int:
    try:
        from .corpus_migration import prepare_corpus_v2_rebuild

        result = prepare_corpus_v2_rebuild(
            str(args.index),
            backup_path=str(args.backup),
            ledger_path=args.deletion_ledger,
            replace_backup=bool(args.replace_backup),
        )
    except (OSError, TypeError, ValueError, RuntimeError) as err:
        print(f"corpus-prepare-v2-rebuild failed: {err}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


def _run_corpus_backup(args: Namespace) -> int:
    try:
        project_context = _project_context_args(args)
        result = backup_corpus_state(str(args.index), str(args.backup))
        if project_context is not None:
            append_project_action(
                args.project_action_log_root,
                **project_context,
                action="corpus_backup",
                status="ok",
                artifact_sha256s=[_sha256_file(str(args.backup))],
            )
    except (OSError, TypeError, ValueError, RuntimeError, CorpusBackupError, ProjectActionLogError) as err:
        try:
            _append_project_failure(args, action="corpus_backup", error=err)
        except (OSError, TypeError, ValueError, ProjectActionLogError):
            pass
        print(f"corpus-backup failed: {err}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


def _run_corpus_restore(args: Namespace) -> int:
    try:
        project_context = _project_context_args(args)
        result = restore_corpus_state(
            str(args.backup),
            str(args.index),
            replace=bool(args.replace),
        )
        generation_root = Path(args.index).resolve().parent
        if (generation_root / "folder-intake.receipt.json").is_file():
            refresh_archive_generation_receipt(str(generation_root))
            result["folder_generation_receipt_refreshed"] = True
        if project_context is not None:
            evidence = [
                _sha256_file(str(args.index)),
                _sha256_payload(result),
            ]
            restored_index = Path(args.index).resolve()
            restored_sidecar = (
                generation_root / "history.sqlite"
                if restored_index.name == "corpus.sqlite"
                else Path(f"{restored_index}.history.sqlite")
            )
            if restored_sidecar.is_file():
                evidence.append(_sha256_file(str(restored_sidecar)))
            append_project_action(
                args.project_action_log_root,
                **project_context,
                action="corpus_restore",
                status="ok",
                artifact_sha256s=evidence,
            )
    except (OSError, TypeError, ValueError, RuntimeError, CorpusBackupError, ProjectActionLogError) as err:
        try:
            _append_project_failure(args, action="corpus_restore", error=err)
        except (OSError, TypeError, ValueError, ProjectActionLogError):
            pass
        print(f"corpus-restore failed: {err}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


def _run_corpus_search(args: Namespace) -> int:
    try:
        from .corpus_index import search_corpus

        result = search_corpus(
            str(args.index),
            query=str(args.query),
            providers=parse_csv_set(args.providers, field_name="providers"),
            source_ids=parse_csv_set(args.source_ids, field_name="source_ids"),
            conversation_ids=parse_csv_set(
                args.conversation_ids, field_name="conversation_ids"
            ),
            roles=parse_csv_set(args.roles, field_name="roles"),
            models=parse_csv_set(args.models, field_name="models"),
            content_types=parse_csv_set(
                args.content_types, field_name="content_types"
            ),
            created_from=args.created_from,
            created_to=args.created_to,
            include_attachment_text=bool(args.include_attachment_text),
            match_mode=str(args.match_mode),
            context_radius=args.context_radius,
            limit=args.limit,
            offset=args.offset,
            max_substring_scan_rows=args.max_substring_scan_rows,
        )
    except (OSError, TypeError, ValueError, RuntimeError) as err:
        print(f"corpus-search failed: {err}", file=sys.stderr)
        return 2
    if args.output:
        _write_payload(result, str(args.output))
    else:
        print(json.dumps(result, sort_keys=True, indent=2))
    return 0


def _run_memory_status(args: Namespace) -> int:
    service = None
    try:
        from .federated_search import FederatedSearch
        from .scope_registry import load_scope_registry

        registry_path = str(args.registry) if args.registry else _scope_registry_path()
        service = FederatedSearch(load_scope_registry(registry_path))
        result = service.status()
    except (OSError, TypeError, ValueError, RuntimeError) as err:
        print(f"memory-status failed: {err}", file=sys.stderr)
        return 2
    finally:
        if service is not None:
            service.close()
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


def _run_memory_search(args: Namespace) -> int:
    service = None
    try:
        from .federated_search import FederatedSearch
        from .scope_registry import load_scope_registry

        registry_path = str(args.registry) if args.registry else _scope_registry_path()
        service = FederatedSearch(load_scope_registry(registry_path))
        result = service.search(
            query=str(args.query),
            scope_ids=args.scope_ids,
            everywhere=bool(args.everywhere),
            context_radius=args.context_radius,
            limit=args.limit,
        )
    except (OSError, TypeError, ValueError, RuntimeError) as err:
        print(f"memory-search failed: {err}", file=sys.stderr)
        return 2
    finally:
        if service is not None:
            service.close()
    if args.output:
        _write_payload(result, str(args.output))
    else:
        print(json.dumps(result, sort_keys=True, indent=2))
    return 0


def _run_action_log_sync(args: Namespace) -> int:
    try:
        project_context = _project_context_args(args)
        bundle = _read_json_object(args.candidate_bundle, label="candidate bundle")
        receipt = _read_json_object(args.candidate_receipt, label="candidate receipt")
        review_state = _read_json_object(args.review_state, label="review state")
        result = publish_reviewed_candidate_bundle(
            args.action_log_root,
            args.user_id,
            candidate_bundle=bundle,
            candidate_receipt=receipt,
            review_manifest=review_state,
            review_signing_secret=args.review_signing_secret,
        )
        if project_context is not None:
            append_project_action(
                args.project_action_log_root,
                **project_context,
                action="classification_review_publish",
                status="ok",
                artifact_sha256s=[
                    _sha256_file(str(args.candidate_receipt)),
                    _sha256_file(str(args.review_state)),
                ],
            )
    except (OSError, TypeError, ValueError, json.JSONDecodeError, ProjectActionLogError) as err:
        try:
            _append_project_failure(
                args, action="classification_review_publish", error=err
            )
        except (OSError, TypeError, ValueError, ProjectActionLogError):
            pass
        print(f"action-log-sync failed: {err}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


def _run_action_log_context(args: Namespace) -> int:
    try:
        project_context = _project_context_args(args)
        projection = load_reviewed_candidate_projection(
            args.action_log_root,
            args.user_id,
            corpus_index_path=args.corpus_index,
        )
        policy = ContextPolicy(
            include_claim_types=parse_csv_set(
                args.claim_types,
                field_name="claim_types",
                allowed_values=ALLOWED_CLAIM_TYPES,
            ),
            include_temporal_states=parse_csv_set(
                args.temporal_states,
                field_name="temporal_states",
                allowed_values=ALLOWED_TEMPORAL_STATES,
            ),
            include_user_assertion_only=bool(args.include_user_assertions_only),
            include_conversation_ids=parse_csv_set(
                args.conversation_ids, field_name="conversation_ids"
            ),
            include_sensitivity_labels=parse_csv_set(
                args.sensitivity_labels, field_name="sensitivity_labels"
            ),
            include_scope_labels=parse_csv_set(
                args.scope_labels, field_name="scope_labels"
            ),
            max_items=args.max_items,
        )
        if policy.max_items is not None and policy.max_items < 0:
            raise ValueError("max-items must be non-negative")
        result = build_context_bundle(
            projection,
            policy,
            purpose=str(args.purpose),
            task_id=str(args.task_id),
            scope=str(args.scope),
            signing_secret=args.signing_secret,
        )
        if project_context is not None:
            append_project_action(
                args.project_action_log_root,
                **project_context,
                action="context_delivery",
                status="ok",
                artifact_sha256s=[_sha256_payload(result["context_receipt"])],
            )
    except (OSError, TypeError, ValueError, json.JSONDecodeError, ProjectActionLogError) as err:
        try:
            _append_project_failure(args, action="context_delivery", error=err)
        except (OSError, TypeError, ValueError, ProjectActionLogError):
            pass
        print(f"action-log-context failed: {err}", file=sys.stderr)
        return 2
    if args.output_capsule:
        _write_payload(result["context_capsule"], str(args.output_capsule))
    if args.output_receipt:
        _write_payload(result["context_receipt"], str(args.output_receipt))
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


def _run_action_log_recall(args: Namespace) -> int:
    try:
        project_context = _project_context_args(args)
        if args.limit < 1 or args.limit > 100:
            raise ValueError("limit must be between 1 and 100")
        if args.context_radius < 0 or args.context_radius > 5:
            raise ValueError("context-radius must be between 0 and 5")
        # Late import keeps Action Log receipts decoupled from the corpus index
        # implementation and avoids a circular storage dependency.
        from .corpus_index import search_corpus

        recall = search_corpus(
            str(args.index),
            query=str(args.query),
            context_radius=args.context_radius,
            limit=args.limit,
        )
        receipt = append_corpus_recall_action_receipt(
            args.action_log_root,
            args.user_id,
            recall_result=recall,
            query=str(args.query),
            filters={
                "context_radius": args.context_radius,
                "limit": args.limit,
            },
            expected_index_generation=args.expect_index_generation,
        )
        if project_context is not None:
            append_project_action(
                args.project_action_log_root,
                **project_context,
                action="corpus_recall",
                status="ok",
                artifact_sha256s=[_sha256_payload(receipt)],
            )
    except (OSError, TypeError, ValueError, RuntimeError) as err:
        print(f"action-log-recall failed: {err}", file=sys.stderr)
        return 2
    if args.output_results:
        _write_payload(recall, str(args.output_results))
    print(
        json.dumps(
            {"recall": recall, "action_log_receipt": receipt},
            sort_keys=True,
            indent=2,
        )
    )
    return 0


def _run_project_action_record(args: Namespace) -> int:
    try:
        result = append_project_action(
            args.action_log_root,
            project_id=args.project_id,
            root_thread_id=args.root_thread_id,
            session_id=args.session_id,
            actor_id=args.actor_id,
            operation_id=args.operation_id,
            action=args.action,
            status=args.status,
            artifact_sha256s=args.artifact_sha256,
        )
    except (OSError, ProjectActionLogError, TypeError, ValueError) as err:
        print(f"project-action-record failed: {err}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


def _run_project_action_verify(args: Namespace) -> int:
    try:
        result = verify_project_action_log(args.action_log_root, args.project_id)
    except (OSError, ProjectActionLogError, TypeError, ValueError) as err:
        print(f"project-action-verify failed: {err}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


def _run_search(args: Namespace) -> int:
    canonical_path = Path(args.canonical)
    if not canonical_path.is_file():
        print(f"canonical projection path does not exist: {canonical_path}", file=sys.stderr)
        return 2

    try:
        index_path = f"{canonical_path}.search.sqlite"
        with open(canonical_path, "r", encoding="utf-8") as fp:
            projection = load_json_strict(fp)
        if not isinstance(projection, dict):
            raise ValueError("canonical projection is not an object")

        result = search_projection(
            projection,
            query=args.query,
            provider=args.provider,
            conversation_ids=parse_csv_set(args.conversation_ids, field_name="conversation_ids"),
            claim_types=parse_csv_set(args.claim_types, field_name="claim_types"),
            temporal_states=parse_csv_set(args.temporal_states, field_name="temporal_states"),
            speakers=parse_csv_set(args.speakers, field_name="speakers", allowed_values={"user", "assistant", "other"}),
            models=parse_csv_set(args.models, field_name="models"),
            content_types=parse_csv_set(args.content_types, field_name="content_types"),
            from_timestamp=args.from_timestamp,
            to_timestamp=args.to_timestamp,
            max_results=args.max_results,
            index_path=index_path,
        )
    except (OSError, ValueError, json.JSONDecodeError) as err:
        print(f"search failed: {err}", file=sys.stderr)
        return 2

    if args.output:
        _write_payload(result, str(args.output))
    else:
        print(json.dumps(result, sort_keys=True, indent=2))

    return 0


def _run_review_api(args: Namespace) -> int:
    canonical_path = Path(args.canonical)
    if not canonical_path.is_file():
        print(f"canonical projection path does not exist: {canonical_path}", file=sys.stderr)
        return 2

    try:
        with open(canonical_path, "r", encoding="utf-8") as fp:
            projection = load_json_strict(fp)
        if not isinstance(projection, dict):
            raise ValueError("canonical projection is not an object")
    except (OSError, ValueError, json.JSONDecodeError) as err:
        print(f"review api failed: {err}", file=sys.stderr)
        return 2

    state_path = (
        args.state_path
        if args.state_path is not None
        else f"{str(canonical_path)}.reviews.json"
    )

    try:
        server = run_review_api_server(
            projection=projection,
            state_path=state_path,
            projection_path=str(canonical_path),
            host=str(args.host),
            port=int(args.port),
            signing_secret=args.signing_secret,
        )
        print(f"review_api_url=http://{server.server_name}:{server.server_port}/")
        print("press Ctrl+C to stop")
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    except (OSError, ValueError) as err:
        print(f"review api failed: {err}", file=sys.stderr)
        return 2
    finally:
        if "server" in locals():
            server.server_close()

    return 0


def run(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
