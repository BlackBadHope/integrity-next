"""Server-rooted write tools for local Integrity Home operations."""

from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
from typing import Any, Dict, Mapping

from integrity_chronicle.folder_intake import (
    FolderIntakeError,
    import_archive_folder,
    verify_archive_generation,
)
from integrity_chronicle.project_action_log import (
    ProjectActionLogError,
    append_project_action,
    verify_project_action_log,
)
from integrity_chronicle.runtime_paths import state_root
from integrity_chronicle.scope_registry import (
    SCOPE_REGISTRY_SCHEMA_VERSION,
    ScopeRegistryError,
    validate_scope_registry,
)
from integrity_chronicle.json_integrity import load_json_strict
from integrity_chronicle.state_lock import CorpusStateLockError, corpus_state_lock

from .history.sidecar import inspect_history_sidecar
from .tool_projection import HomeToolError
from .unified_publication import build_unified_sidecar_successor


_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_PROJECT_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_CONTEXT_FIELDS = (
    "project_id", "root_thread_id", "session_id", "actor_id", "operation_id"
)

OPS_TOOLS: tuple[dict[str, Any], ...] = (
    {
        "name": "home_ops_status",
        "description": (
            "Report content-free readiness and counts for the fixed local import inbox, "
            "published generations, and project Action Logs. Exposes no paths."
        ),
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False},
    },
    {
        "name": "home_import_batch",
        "description": (
            "Atomically import one named batch from the fixed local inbox into a new "
            "Personal or audited project generation. No filesystem path is accepted."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "batch_name": {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"},
                "generation_name": {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"},
                "scope_kind": {"type": "string", "enum": ["personal"]},
                **{field: {"type": "string", "minLength": 1, "maxLength": 256} for field in _CONTEXT_FIELDS},
            },
            "required": ["batch_name", "generation_name"],
            "oneOf": [
                {"required": list(_CONTEXT_FIELDS), "not": {"required": ["scope_kind"]}},
                {
                    "required": ["scope_kind"],
                    "not": {"anyOf": [{"required": [field]} for field in _CONTEXT_FIELDS]},
                },
            ],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
    },
    {
        "name": "home_verify_import",
        "description": (
            "Verify a named Personal or project generation against its intake receipt, canonical "
            "manifests, corpus summary, and exact file set. Exposes no paths or content."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_id": {"type": "string", "minLength": 1, "maxLength": 256},
                "scope_kind": {"type": "string", "enum": ["personal"]},
                "generation_name": {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"},
            },
            "required": ["generation_name"],
            "oneOf": [
                {"required": ["project_id"], "not": {"required": ["scope_kind"]}},
                {"required": ["scope_kind"], "not": {"required": ["project_id"]}},
            ],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False},
    },
    {
        "name": "home_project_action_verify",
        "description": (
            "Verify the complete hash chain for one project Action Log. Returns only "
            "content-free chain evidence."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"project_id": {"type": "string", "minLength": 1, "maxLength": 256}},
            "required": ["project_id"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False},
    },
)


def _identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.encode("utf-8")) > 256:
        raise HomeToolError(f"{field} must be a non-empty identifier")
    if any(ord(char) < 32 for char in value):
        raise HomeToolError(f"{field} must be a non-empty identifier")
    return value


def _name(value: Any, field: str) -> str:
    if not isinstance(value, str) or _NAME_RE.fullmatch(value) is None or value in {".", ".."}:
        raise HomeToolError(f"{field} must be a safe local name")
    return value


def _reparse(path: Path) -> bool:
    try:
        return path.is_symlink() or bool(getattr(path.lstat(), "st_file_attributes", 0) & 0x400)
    except OSError:
        return False


class HomeOpsProjection:
    """Operations rooted under application state; callers never provide paths."""

    def __init__(self, fixed_state_root: str | None = None):
        raw = Path(fixed_state_root) if fixed_state_root is not None else state_root()
        if raw.exists() and _reparse(raw):
            raise HomeToolError("Integrity Home state root is unsafe")
        self._root = raw.resolve()
        self._inbox = self._root / "inbox"
        self._generations = self._root / "generations"
        self._actions = self._root / "manifests" / "project-action-logs"
        self._registry = self._root / "config" / "memory-scopes.json"

    def _generation(self, generation_name: str) -> Path:
        return self._generations / "shared" / generation_name

    def _batch(self, batch_name: str) -> Path:
        batch = self._inbox / batch_name
        if not batch.is_dir() or _reparse(batch):
            raise HomeToolError("named inbox batch is unavailable or unsafe")
        return batch

    def _registry_payload(
        self, scope_id: str, corpus: Path, sidecar: Path | None = None,
    ) -> dict[str, Any]:
        scopes: list[dict[str, Any]] = []
        if self._registry.exists():
            if not self._registry.is_file() or _reparse(self._registry):
                raise HomeToolError("scope registry is unsafe")
            try:
                with self._registry.open("r", encoding="utf-8") as stream:
                    current = load_json_strict(stream)
            except (OSError, UnicodeError, ValueError) as err:
                raise HomeToolError("scope registry is invalid") from err
            if not isinstance(current, Mapping) or not isinstance(current.get("scopes"), list):
                raise HomeToolError("scope registry is invalid")
            scopes = [dict(item) for item in current["scopes"] if isinstance(item, Mapping)]
            if len(scopes) != len(current["scopes"]):
                raise HomeToolError("scope registry is invalid")
        scopes = [scope for scope in scopes if scope.get("scope_id") != scope_id]
        if scope_id == "personal:core":
            scopes.append({
                "scope_id": scope_id, "display_name": "Personal",
                "scope_kind": "personal", "realm": "personal", "enabled": True,
                "index_path": str(corpus.resolve()),
            })
        else:
            project_id = scope_id.removeprefix("project:")
            scopes.append({
                "scope_id": scope_id,
                "display_name": project_id,
                "scope_kind": "project", "realm": "work", "project_id": project_id,
                "enabled": True, "index_path": str(corpus.resolve()),
            })
        if sidecar is not None:
            for scope in scopes:
                scope["index_path"] = str(corpus.resolve())
                scope["history_sidecar_path"] = str(sidecar.resolve())
                scope["logical_scope_id"] = scope["scope_id"]
                scope["everywhere_base_access"] = True
        payload = {
            "schema_version": SCOPE_REGISTRY_SCHEMA_VERSION,
            "scopes": sorted(scopes, key=lambda item: str(item.get("scope_id", ""))),
        }
        try:
            validate_scope_registry(payload)
        except ScopeRegistryError as err:
            raise HomeToolError("scope registry publication failed validation") from err
        return payload

    def _active_generation(self) -> Path | None:
        if not self._registry.exists():
            return None
        try:
            with self._registry.open("r", encoding="utf-8") as stream:
                payload = load_json_strict(stream)
            validate_scope_registry(payload)
        except (OSError, UnicodeError, ValueError, ScopeRegistryError) as err:
            raise HomeToolError("scope registry is invalid") from err
        scopes = payload["scopes"]
        if not scopes:
            return None
        corpus_paths = {str(Path(item["index_path"]).resolve()) for item in scopes}
        sidecar_paths = {
            str(Path(item.get("history_sidecar_path", "")).resolve()) for item in scopes
        }
        if len(corpus_paths) != 1 or len(sidecar_paths) != 1:
            raise HomeToolError("active shared generation is inconsistent")
        corpus = Path(next(iter(corpus_paths)))
        sidecar = Path(next(iter(sidecar_paths)))
        shared_root = (self._generations / "shared").resolve()
        if (
            corpus.name != "corpus.sqlite" or sidecar.name != "history.sqlite"
            or corpus.parent != sidecar.parent or corpus.parent.parent != shared_root
            or not corpus.is_file() or not sidecar.is_file() or _reparse(corpus.parent)
        ):
            raise HomeToolError("active shared generation is unsafe")
        try:
            inspect_history_sidecar(str(corpus), str(sidecar))
        except (OSError, RuntimeError, ValueError) as err:
            raise HomeToolError("active shared generation is invalid") from err
        return corpus.parent

    def _project_ids(self, target_scope_id: str) -> set[str]:
        projects: set[str] = set()
        if self._registry.exists():
            try:
                with self._registry.open("r", encoding="utf-8") as stream:
                    payload = load_json_strict(stream)
                validate_scope_registry(payload)
            except (OSError, UnicodeError, ValueError, ScopeRegistryError) as err:
                raise HomeToolError("scope registry is invalid") from err
            projects.update(
                str(scope["project_id"]) for scope in payload["scopes"]
                if scope.get("scope_kind") == "project"
            )
        if target_scope_id.startswith("project:"):
            projects.add(target_scope_id.removeprefix("project:"))
        return projects

    def _registry_has_scope(self, scope_id: str) -> bool:
        try:
            with self._registry.open("r", encoding="utf-8") as stream:
                payload = load_json_strict(stream)
            validate_scope_registry(payload)
        except (OSError, UnicodeError, ValueError, ScopeRegistryError) as err:
            raise HomeToolError("scope registry is invalid") from err
        return any(scope.get("scope_id") == scope_id for scope in payload["scopes"])

    def _write_registry(self, payload: Mapping[str, Any]) -> None:
        self._registry.parent.mkdir(parents=True, exist_ok=True)
        if _reparse(self._registry.parent):
            raise HomeToolError("scope registry root is unsafe")
        encoded = (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode("utf-8")
        fd, temporary_name = tempfile.mkstemp(
            prefix="memory-scopes-", suffix=".json", dir=self._registry.parent
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self._registry)
        finally:
            temporary.unlink(missing_ok=True)

    def _restore_registry(self, previous: bytes | None) -> None:
        if previous is None:
            self._registry.unlink(missing_ok=True)
            return
        self._registry.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary_name = tempfile.mkstemp(
            prefix="memory-scopes-rollback-", suffix=".json", dir=self._registry.parent
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(previous)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self._registry)
        finally:
            temporary.unlink(missing_ok=True)

    @staticmethod
    def _arguments(arguments: Any, expected: set[str]) -> Dict[str, Any]:
        if not isinstance(arguments, Mapping) or any(not isinstance(key, str) for key in arguments):
            raise HomeToolError("tool arguments must be an object")
        if set(arguments) != expected:
            raise HomeToolError("tool arguments do not match the required contract")
        return dict(arguments)

    def status(self, arguments: Any) -> Dict[str, Any]:
        self._arguments(arguments, set())
        batch_count = 0
        if self._inbox.is_dir() and not _reparse(self._inbox):
            batch_count = sum(
                1 for path in self._inbox.iterdir()
                if path.is_dir() and not _reparse(path)
            )
        generation_count = 0
        if self._generations.is_dir() and not _reparse(self._generations):
            generation_count = sum(
                1 for project in self._generations.iterdir()
                if project.is_dir() and not _reparse(project)
                for generation in project.iterdir()
                if generation.is_dir() and not _reparse(generation)
            )
        return {
            "schema_version": "integrity-home-ops-status/1",
            "state_root_ready": self._root.is_dir() and not _reparse(self._root),
            "inbox_ready": self._inbox.is_dir() and not _reparse(self._inbox),
            "batch_count": batch_count,
            "generation_count": generation_count,
            "network_listener": False,
            "telemetry": False,
        }

    def import_batch(self, arguments: Any) -> Dict[str, Any]:
        if not isinstance(arguments, Mapping):
            raise HomeToolError("tool arguments must be an object")
        values = dict(arguments)
        project_fields = {"batch_name", "generation_name", *_CONTEXT_FIELDS}
        personal_fields = {"batch_name", "generation_name", "scope_kind"}
        if set(values) == project_fields:
            scope_kind = "project"
        elif set(values) == personal_fields and values.get("scope_kind") == "personal":
            scope_kind = "personal"
        else:
            raise HomeToolError("tool arguments do not match the import contract")
        batch_name = _name(values["batch_name"], "batch_name")
        generation_name = _name(values["generation_name"], "generation_name")
        context: dict[str, str] | None = None
        if scope_kind == "project":
            context = {field: _identifier(values[field], field) for field in _CONTEXT_FIELDS}
            if _PROJECT_RE.fullmatch(context["project_id"]) is None:
                raise HomeToolError("project_id must be a stable lowercase identifier")
            scope_id = f"project:{context['project_id']}"
        else:
            scope_id = "personal:core"
        output = self._generation(generation_name)
        reused = output.exists()
        previous_registry: bytes | None = None
        registry_snapshot_taken = False
        try:
            with corpus_state_lock(str(self._registry)):
                previous_registry = (
                    self._registry.read_bytes() if self._registry.exists() else None
                )
                registry_snapshot_taken = True
                output.parent.mkdir(parents=True, exist_ok=True)
                if _reparse(output.parent):
                    raise HomeToolError("project generation root is unsafe")
                if reused:
                    verification = verify_archive_generation(str(output))
                    inspect_history_sidecar(
                        str(output / "corpus.sqlite"), str(output / "history.sqlite")
                    )
                    if self._active_generation() != output.resolve():
                        raise HomeToolError("existing generation is not the active publication")
                    if not self._registry_has_scope(scope_id):
                        raise HomeToolError("existing generation belongs to another scope operation")
                else:
                    batch = self._batch(batch_name)
                    base = self._active_generation()
                    import_archive_folder(
                        str(batch), str(output),
                        base_generation=str(base) if base is not None else None,
                    )
                    verification = verify_archive_generation(str(output))
                receipt_path = output / "folder-intake.receipt.json"
                corpus_path = output / "corpus.sqlite"
                sidecar_path = output / "history.sqlite"
                if not reused:
                    authority_sha256 = sha256(receipt_path.read_bytes()).hexdigest()
                    build_unified_sidecar_successor(
                        str(corpus_path), str(sidecar_path),
                        target_scope_id=scope_id,
                        project_ids=self._project_ids(scope_id),
                        authority_sha256=authority_sha256,
                        previous_corpus_path=(str(base / "corpus.sqlite") if base else None),
                        previous_sidecar_path=(str(base / "history.sqlite") if base else None),
                    )
                    inspect_history_sidecar(str(corpus_path), str(sidecar_path))
                registry_payload = self._registry_payload(
                    scope_id, corpus_path, sidecar_path
                )
                self._write_registry(registry_payload)
                try:
                    if context is None:
                        action = {"appended": False}
                        continue_audit = False
                    else:
                        continue_audit = True
                    if continue_audit:
                        action = append_project_action(
                            str(self._actions), **context,
                            action="archive_folder_import", status="ok",
                            artifact_sha256s=[
                                sha256(receipt_path.read_bytes()).hexdigest(),
                                sha256(corpus_path.read_bytes()).hexdigest(),
                                sha256(sidecar_path.read_bytes()).hexdigest(),
                            ],
                        )
                except (OSError, ProjectActionLogError, ValueError):
                    self._restore_registry(previous_registry)
                    raise
        except (
            FolderIntakeError, OSError, RuntimeError, ValueError,
            ProjectActionLogError, CorpusStateLockError, HomeToolError,
        ) as err:
            failure_report = (
                dict(err.report)
                if isinstance(err, FolderIntakeError) and err.report is not None
                else None
            )
            if registry_snapshot_taken:
                try:
                    self._restore_registry(previous_registry)
                except OSError:
                    pass
            if not reused:
                shutil.rmtree(output, ignore_errors=True)
            if context is not None:
                failure_id = context["operation_id"] + ".failed." + sha256(
                    type(err).__name__.encode("utf-8")
                ).hexdigest()[:12]
                try:
                    append_project_action(
                        str(self._actions), **{**context, "operation_id": failure_id},
                        action="archive_folder_import", status="failed",
                        artifact_sha256s=(
                            [sha256(json.dumps(
                                failure_report, sort_keys=True, separators=(",", ":")
                            ).encode("utf-8")).hexdigest()]
                            if failure_report is not None else None
                        ),
                    )
                except (OSError, ProjectActionLogError, ValueError):
                    pass
            if reused and isinstance(err, (FolderIntakeError, RuntimeError, ValueError)):
                raise HomeToolError("existing generation verification failed closed") from err
            if failure_report is not None:
                raise HomeToolError(
                    "batch import rejected: "
                    + json.dumps(failure_report, sort_keys=True, separators=(",", ":"))
                ) from err
            raise HomeToolError("batch import failed closed") from err
        return {
            "schema_version": "integrity-home-mcp-import/1",
            "scope_id": scope_id,
            "reused": reused,
            "action_appended": action["appended"],
            "verification": verification,
        }

    def verify_import(self, arguments: Any) -> Dict[str, Any]:
        if not isinstance(arguments, Mapping):
            raise HomeToolError("tool arguments must be an object")
        values = dict(arguments)
        if set(values) == {"project_id", "generation_name"}:
            project_id = _identifier(values["project_id"], "project_id")
            scope_id = f"project:{project_id}"
        elif set(values) == {"scope_kind", "generation_name"} and values.get("scope_kind") == "personal":
            scope_id = "personal:core"
        else:
            raise HomeToolError("tool arguments do not match the required contract")
        generation_name = _name(values["generation_name"], "generation_name")
        try:
            generation = self._generation(generation_name)
            result = verify_archive_generation(str(generation))
            result["history"] = inspect_history_sidecar(
                str(generation / "corpus.sqlite"), str(generation / "history.sqlite")
            )
            return result
        except (FolderIntakeError, OSError, RuntimeError, ValueError) as err:
            raise HomeToolError("generation verification failed closed") from err

    def verify_action_log(self, arguments: Any) -> Dict[str, Any]:
        values = self._arguments(arguments, {"project_id"})
        project_id = _identifier(values["project_id"], "project_id")
        try:
            return verify_project_action_log(str(self._actions), project_id)
        except (OSError, ProjectActionLogError, ValueError) as err:
            raise HomeToolError("project Action Log verification failed closed") from err

    def record_search(self, context: Any, result: Mapping[str, Any]) -> Dict[str, Any]:
        values = self._arguments(context, set(_CONTEXT_FIELDS))
        parsed = {field: _identifier(values[field], field) for field in _CONTEXT_FIELDS}
        evidence = {
            "mode": result.get("mode"),
            "searched_scope_ids": result.get("searched_scope_ids"),
            "result_count": result.get("result_count"),
            "output_truncated": result.get("output_truncated"),
        }
        try:
            return append_project_action(
                str(self._actions), **parsed, action="memory_search", status="ok",
                artifact_sha256s=[sha256(
                    json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode("utf-8")
                ).hexdigest()],
            )
        except (OSError, ProjectActionLogError, ValueError) as err:
            raise HomeToolError("project search audit failed closed") from err

    def record_search_failure(self, context: Any, error: BaseException) -> None:
        values = self._arguments(context, set(_CONTEXT_FIELDS))
        parsed = {field: _identifier(values[field], field) for field in _CONTEXT_FIELDS}
        parsed["operation_id"] += ".failed." + sha256(
            type(error).__name__.encode("utf-8")
        ).hexdigest()[:12]
        try:
            append_project_action(
                str(self._actions), **parsed, action="memory_search", status="failed"
            )
        except (OSError, ProjectActionLogError, ValueError):
            return

    def invoke(self, name: str, arguments: Any) -> Dict[str, Any]:
        if name == "home_ops_status":
            return self.status(arguments)
        if name == "home_import_batch":
            return self.import_batch(arguments)
        if name == "home_verify_import":
            return self.verify_import(arguments)
        if name == "home_project_action_verify":
            return self.verify_action_log(arguments)
        raise HomeToolError("unknown Integrity Home operations tool")


__all__ = ["HomeOpsProjection", "OPS_TOOLS"]
