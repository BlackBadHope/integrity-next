"""Compose one authenticated tenant's Action Log and Chronicle runtime."""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import threading
from typing import Any

from .action_log_projection import ActionLogKnowledgeProjection
from .secure_https import HTTPSFileMaterializer
from .solo_projection import SoloKnowledgeProjection
from .tenant import (
    TenantRuntimeFactory,
    TenantVault,
    TenantVaultRouter,
    VerifiedOAuthPrincipal,
)
from .tenant_action_log import TenantActionLogStore
from .tenant_mcp_server import TenantMemoryMCPServer
from .tool_projection import (
    HomeToolError,
    build_projection_for_registry,
)
from .unified_projection import UnifiedKnowledgeProjection
from .work_import import (
    FileMaterializer,
    WorkImportCoordinator,
    commit_personal_batch,
)


class _RefreshingHomeProjection:
    """Retain handles until the tenant registry atomically changes."""

    def __init__(self, registry_path: Path):
        self._registry_path = registry_path
        self._generation: str | None = None
        self._projection: Any = None
        self._lock = threading.RLock()

    def _registry_generation(self) -> str | None:
        if not self._registry_path.exists():
            return None
        if self._registry_path.is_symlink() or not self._registry_path.is_file():
            raise HomeToolError("tenant memory registry is unsafe")
        try:
            raw = self._registry_path.read_bytes()
        except OSError as err:
            raise HomeToolError("tenant memory registry is unavailable") from err
        return sha256(raw).hexdigest()

    def invoke(self, tool_name: str, arguments: Any) -> dict[str, Any]:
        with self._lock:
            generation = self._registry_generation()
            if generation is None:
                if tool_name == "home_search":
                    return {
                        "schema_version": "integrity-home-tool-search/2",
                        "authority": "untrusted_evidence",
                        "complete": True,
                        "mode": "everywhere",
                        "requested_scope_ids": None,
                        "searched_scope_ids": [],
                        "result_count": 0,
                        "output_truncated": False,
                        "has_more": False,
                        "next_cursor": None,
                        "results": [],
                    }
                raise HomeToolError("tenant conversation memory is empty")
            if generation != self._generation or self._projection is None:
                self._projection = build_projection_for_registry(
                    self._registry_path
                )
                self._generation = generation
            return self._projection.invoke(tool_name, arguments)


class TenantRuntimeState:
    """Shared state for one tenant, dispatched with the current token scopes."""

    def __init__(
        self,
        vault: TenantVault,
        *,
        canonical_base_url: str,
        materializer: FileMaterializer,
    ):
        self.vault = vault
        action_store = TenantActionLogStore(vault.action_log_path)
        action_log = ActionLogKnowledgeProjection(
            base_url="http://127.0.0.1:1",
            canonical_base_url=canonical_base_url,
            token="authenticated-in-process",
            request_json=action_store.request_json,
            write_json=action_store.write_json,
        )
        home = SoloKnowledgeProjection(
            _RefreshingHomeProjection(vault.registry_path),
            canonical_base_url=canonical_base_url,
            everywhere=True,
        )
        self._projection = UnifiedKnowledgeProjection(
            home=home,
            action_log=action_log,
        )
        self._imports = WorkImportCoordinator(
            vault,
            materializer,
            commit_batch=commit_personal_batch,
        )
        self._lock = threading.RLock()

    def dispatch(
        self,
        principal: VerifiedOAuthPrincipal,
        request: Any,
    ) -> dict[str, Any] | None:
        with self._lock:
            return TenantMemoryMCPServer(
                principal=principal,
                projection=self._projection,
                imports=self._imports,
            ).handle(request)


class AuthenticatedTenantRuntimeFactory:
    """Cache storage state, never token privileges, across HTTP requests."""

    def __init__(
        self,
        router: TenantVaultRouter,
        *,
        canonical_base_url: str,
        materializer: FileMaterializer | None = None,
    ):
        self._materializer = materializer or HTTPSFileMaterializer()
        self._states = TenantRuntimeFactory(
            router,
            lambda vault: TenantRuntimeState(
                vault,
                canonical_base_url=canonical_base_url,
                materializer=self._materializer,
            ),
            required_scope="memory:read",
        )

    def for_principal(
        self, principal: VerifiedOAuthPrincipal
    ) -> TenantRuntimeState:
        return self._states.for_principal(principal)


__all__ = [
    "AuthenticatedTenantRuntimeFactory",
    "TenantRuntimeState",
]
