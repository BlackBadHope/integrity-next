"""Strict local scope registry for federated Integrity Home corpus reads.

The registry is a trusted control-plane file, but its corpus paths are private
implementation details.  Public status/list payloads therefore expose only
stable scope identity and classification metadata.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
from typing import Any, Dict, Iterable, Tuple

from .json_integrity import DuplicateJsonKeyError, load_json_strict


LEGACY_SCOPE_REGISTRY_SCHEMA_VERSION = "integrity-home-scope-registry/1"
SCOPE_REGISTRY_SCHEMA_VERSION = "integrity-home-scope-registry/2"
MAX_SCOPE_REGISTRY_BYTES = 1 << 20
MAX_SCOPES = 64

_REALMS = frozenset(("personal", "work", "public"))
_SCOPE_KINDS = frozenset(("personal", "project", "public"))
_ROOT_FIELDS = frozenset(("schema_version", "scopes"))
_REQUIRED_SCOPE_FIELDS = frozenset(
    (
        "scope_id",
        "display_name",
        "scope_kind",
        "realm",
        "enabled",
        "index_path",
    )
)
_OPTIONAL_SCOPE_FIELDS = frozenset(
    (
        "project_id",
        "history_sidecar_path",
        "logical_scope_id",
        "everywhere_base_access",
    )
)
_STABLE_ID = re.compile(
    r"^[a-z0-9](?:[a-z0-9._-]{0,63})(?::[a-z0-9][a-z0-9._-]{0,63})*$"
)


class ScopeRegistryError(ValueError):
    """Raised when a scope registry is malformed or ambiguous."""


def _stable_id(value: Any, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 128
        or _STABLE_ID.fullmatch(value) is None
    ):
        raise ScopeRegistryError(f"{field} must be a stable lowercase identifier")
    return value


def _display_name(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 128
        or value.strip() != value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ScopeRegistryError("display_name must be a bounded printable string")
    return value


def _canonical_path(value: Any, *, field: str) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ScopeRegistryError(f"{field} must be an absolute canonical path")
    candidate = Path(value)
    if not candidate.is_absolute():
        raise ScopeRegistryError(f"{field} must be an absolute canonical path")
    try:
        canonical = candidate.resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as err:
        raise ScopeRegistryError(
            f"{field} must be an absolute canonical path"
        ) from err
    if os.path.normcase(str(candidate)) != os.path.normcase(str(canonical)):
        raise ScopeRegistryError(f"{field} must be an absolute canonical path")
    return canonical


def _canonical_index_path(value: Any) -> Path:
    return _canonical_path(value, field="index_path")


def _path_identity(path: Path) -> str:
    return os.path.normcase(os.path.normpath(str(path)))


@dataclass(frozen=True)
class _ScopeEntry:
    scope_id: str
    display_name: str
    scope_kind: str
    realm: str
    enabled: bool
    index_path: Path
    project_id: str | None = None
    history_sidecar_path: Path | None = None
    logical_scope_id: str | None = None
    everywhere_base_access: bool = False

    @property
    def is_logical(self) -> bool:
        return self.history_sidecar_path is not None

    def public(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "scope_id": self.scope_id,
            "display_name": self.display_name,
            "scope_kind": self.scope_kind,
            "realm": self.realm,
            "enabled": self.enabled,
        }
        if self.project_id is not None:
            payload["project_id"] = self.project_id
        payload["storage_mode"] = "history_view" if self.is_logical else "physical"
        if self.is_logical:
            payload["everywhere_base_access"] = self.everywhere_base_access
        return payload


class ScopeRegistry:
    """Validated immutable registry with path-free public projections."""

    def __init__(self, scopes: Iterable[_ScopeEntry]):
        entries = tuple(sorted(scopes, key=lambda item: item.scope_id))
        self._scopes: Tuple[_ScopeEntry, ...] = entries
        self._by_id = {entry.scope_id: entry for entry in entries}
        public_generation_payload = {
            "schema_version": SCOPE_REGISTRY_SCHEMA_VERSION,
            "scopes": [entry.public() for entry in entries],
        }
        encoded = json.dumps(
            public_generation_payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        self._registry_generation = sha256(encoded).hexdigest()

    @property
    def registry_generation(self) -> str:
        """Stable digest of public scope identity and classification metadata."""

        return self._registry_generation

    def list_scopes(self) -> list[Dict[str, Any]]:
        """Return deterministic public scope metadata without corpus paths."""

        return [entry.public() for entry in self._scopes]

    def status(self) -> Dict[str, Any]:
        """Return configuration counts without probing or disclosing paths."""

        enabled = [entry for entry in self._scopes if entry.enabled]
        projects = [entry for entry in self._scopes if entry.scope_kind == "project"]
        return {
            "schema_version": SCOPE_REGISTRY_SCHEMA_VERSION,
            "registry_generation": self._registry_generation,
            "configured": bool(enabled),
            "scope_count": len(self._scopes),
            "enabled_scope_count": len(enabled),
            "project_scope_count": len(projects),
            "enabled_project_scope_count": sum(
                1 for entry in projects if entry.enabled
            ),
        }

    def _resolve(
        self, *, scope_ids: tuple[str, ...] | None, everywhere: bool
    ) -> Tuple[_ScopeEntry, ...]:
        if everywhere:
            return tuple(entry for entry in self._scopes if entry.enabled)
        assert scope_ids is not None
        selected: list[_ScopeEntry] = []
        for scope_id in sorted(scope_ids):
            entry = self._by_id.get(scope_id)
            if entry is None or not entry.enabled:
                raise KeyError(scope_id)
            selected.append(entry)
        return tuple(selected)


def validate_scope_registry(payload: Any) -> ScopeRegistry:
    """Validate an exact v1/v2 registry payload and return an immutable view."""

    if not isinstance(payload, Mapping):
        raise ScopeRegistryError("scope registry must be a JSON object")
    fields = frozenset(payload)
    if fields != _ROOT_FIELDS:
        raise ScopeRegistryError("scope registry fields do not match schema v1")
    schema_version = payload.get("schema_version")
    if schema_version not in {
        LEGACY_SCOPE_REGISTRY_SCHEMA_VERSION,
        SCOPE_REGISTRY_SCHEMA_VERSION,
    }:
        raise ScopeRegistryError("unsupported scope registry schema_version")

    raw_scopes = payload.get("scopes")
    if not isinstance(raw_scopes, list) or not 1 <= len(raw_scopes) <= MAX_SCOPES:
        raise ScopeRegistryError(
            f"scopes must contain between 1 and {MAX_SCOPES} entries"
        )

    scopes: list[_ScopeEntry] = []
    seen_ids: set[str] = set()
    backends_by_index: dict[str, tuple[str | None, bool, set[str]]] = {}
    allowed_scope_fields = _REQUIRED_SCOPE_FIELDS | _OPTIONAL_SCOPE_FIELDS
    for index, raw_scope in enumerate(raw_scopes):
        if not isinstance(raw_scope, Mapping):
            raise ScopeRegistryError(f"scope at index {index} must be an object")
        scope_fields = frozenset(raw_scope)
        if not _REQUIRED_SCOPE_FIELDS <= scope_fields or not scope_fields <= allowed_scope_fields:
            raise ScopeRegistryError(
                f"scope at index {index} fields do not match registry schema"
            )
        if schema_version == LEGACY_SCOPE_REGISTRY_SCHEMA_VERSION and (
            scope_fields - (_REQUIRED_SCOPE_FIELDS | {"project_id"})
        ):
            raise ScopeRegistryError(
                f"scope at index {index} fields do not match schema v1"
            )

        scope_id = _stable_id(raw_scope.get("scope_id"), field="scope_id")
        if scope_id in seen_ids:
            raise ScopeRegistryError("scope_id values must be unique")
        seen_ids.add(scope_id)

        display_name = _display_name(raw_scope.get("display_name"))
        realm = raw_scope.get("realm")
        if realm not in _REALMS:
            raise ScopeRegistryError("realm must be personal, work, or public")
        scope_kind = raw_scope.get("scope_kind")
        if scope_kind not in _SCOPE_KINDS:
            raise ScopeRegistryError(
                "scope_kind must be personal, project, or public"
            )
        enabled = raw_scope.get("enabled")
        if not isinstance(enabled, bool):
            raise ScopeRegistryError("enabled must be a boolean")

        project_id: str | None = None
        if "project_id" in raw_scope:
            project_id = _stable_id(raw_scope.get("project_id"), field="project_id")
        if scope_kind == "project" and project_id is None:
            raise ScopeRegistryError("project scopes require project_id")
        if scope_kind != "project" and project_id is not None:
            raise ScopeRegistryError("only project scopes may define project_id")
        if scope_kind == "personal" and realm != "personal":
            raise ScopeRegistryError("personal scopes require realm=personal")
        if scope_kind == "public" and realm != "public":
            raise ScopeRegistryError("public scopes require realm=public")

        index_path = _canonical_index_path(raw_scope.get("index_path"))
        path_identity = _path_identity(index_path)
        has_sidecar = "history_sidecar_path" in raw_scope
        has_logical_id = "logical_scope_id" in raw_scope
        has_everywhere_policy = "everywhere_base_access" in raw_scope
        if has_sidecar != has_logical_id or has_sidecar != has_everywhere_policy:
            raise ScopeRegistryError(
                "History logical fields must be defined together"
            )
        history_sidecar_path: Path | None = None
        logical_scope_id: str | None = None
        sidecar_identity: str | None = None
        everywhere_base_access = False
        if has_sidecar:
            history_sidecar_path = _canonical_path(
                raw_scope.get("history_sidecar_path"), field="history_sidecar_path"
            )
            if _path_identity(history_sidecar_path) == path_identity:
                raise ScopeRegistryError("history sidecar must not alias index_path")
            logical_scope_id = _stable_id(
                raw_scope.get("logical_scope_id"), field="logical_scope_id"
            )
            if logical_scope_id != scope_id:
                raise ScopeRegistryError("logical_scope_id must equal scope_id")
            sidecar_identity = _path_identity(history_sidecar_path)
            everywhere_base_access = raw_scope.get("everywhere_base_access")
            if type(everywhere_base_access) is not bool:
                raise ScopeRegistryError("everywhere_base_access must be a boolean")

        existing_backend = backends_by_index.get(path_identity)
        if existing_backend is None:
            backends_by_index[path_identity] = (
                sidecar_identity,
                everywhere_base_access,
                {logical_scope_id} if logical_scope_id is not None else set(),
            )
        else:
            existing_sidecar, existing_everywhere_policy, existing_logical_ids = existing_backend
            if sidecar_identity is None and existing_sidecar is None:
                raise ScopeRegistryError("index_path values must be unique")
            if (
                sidecar_identity is None
                or existing_sidecar is None
                or sidecar_identity != existing_sidecar
                or everywhere_base_access != existing_everywhere_policy
                or logical_scope_id in existing_logical_ids
            ):
                raise ScopeRegistryError(
                    "shared index_path requires one shared sidecar and unique logical scopes"
                )
            existing_logical_ids.add(logical_scope_id)

        scopes.append(
            _ScopeEntry(
                scope_id=scope_id,
                display_name=display_name,
                scope_kind=scope_kind,
                realm=realm,
                enabled=enabled,
                index_path=index_path,
                project_id=project_id,
                history_sidecar_path=history_sidecar_path,
                logical_scope_id=logical_scope_id,
                everywhere_base_access=everywhere_base_access,
            )
        )

    index_owners = {_path_identity(scope.index_path) for scope in scopes}
    sidecar_owners: dict[str, str] = {}
    for scope in scopes:
        if scope.history_sidecar_path is None:
            continue
        sidecar_identity = _path_identity(scope.history_sidecar_path)
        index_identity = _path_identity(scope.index_path)
        if sidecar_identity in index_owners:
            raise ScopeRegistryError(
                "history sidecar must not alias any registered index_path"
            )
        prior_index = sidecar_owners.setdefault(sidecar_identity, index_identity)
        if prior_index != index_identity:
            raise ScopeRegistryError(
                "one history sidecar must not bind multiple index paths"
            )

    return ScopeRegistry(scopes)


def load_scope_registry(path: str) -> ScopeRegistry:
    """Load a bounded, duplicate-key-safe registry from a trusted path."""

    if not isinstance(path, str) or not path:
        raise ScopeRegistryError("scope registry path is required")
    target = Path(path)
    try:
        if not target.is_file() or target.stat().st_size > MAX_SCOPE_REGISTRY_BYTES:
            raise ScopeRegistryError("scope registry could not be read")
        with target.open("r", encoding="utf-8") as stream:
            payload = load_json_strict(stream)
    except ScopeRegistryError:
        raise
    except (OSError, UnicodeError, DuplicateJsonKeyError, ValueError) as err:
        raise ScopeRegistryError("scope registry could not be read") from err
    return validate_scope_registry(payload)


__all__ = [
    "MAX_SCOPE_REGISTRY_BYTES",
    "MAX_SCOPES",
    "LEGACY_SCOPE_REGISTRY_SCHEMA_VERSION",
    "SCOPE_REGISTRY_SCHEMA_VERSION",
    "ScopeRegistry",
    "ScopeRegistryError",
    "load_scope_registry",
    "validate_scope_registry",
]
