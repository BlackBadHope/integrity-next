"""Server-selected tenant isolation for remote Integrity memory.

This module does not validate OAuth tokens.  A remote resource server must
validate signature, issuer, audience, lifetime, and scopes first, then create a
``VerifiedOAuthPrincipal``.  Tool arguments never contain a tenant identifier.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
import re
import threading
from typing import Callable, Generic, TypeVar
from urllib.parse import urlsplit


_SCOPE_RE = re.compile(r"^[a-z][a-z0-9:_-]{0,127}$")
_TENANT_RE = re.compile(r"^t_[0-9a-f]{64}$")
_RuntimeT = TypeVar("_RuntimeT")


class TenantIsolationError(ValueError):
    """Safe failure at the authenticated tenant boundary."""


@dataclass(frozen=True)
class VerifiedOAuthPrincipal:
    """Identity claims already verified by the HTTPS OAuth resource server."""

    issuer: str
    subject: str
    audience: tuple[str, ...]
    scopes: frozenset[str]

    def __post_init__(self) -> None:
        parsed = urlsplit(self.issuer)
        if (
            parsed.scheme != "https"
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise TenantIsolationError("verified issuer must be an HTTPS origin")
        if (
            not isinstance(self.subject, str)
            or not self.subject
            or len(self.subject) > 512
            or any(ord(character) < 32 for character in self.subject)
        ):
            raise TenantIsolationError("verified subject is invalid")
        if (
            not isinstance(self.audience, tuple)
            or not self.audience
            or len(self.audience) > 16
            or any(
                not isinstance(value, str) or not value or len(value) > 512
                for value in self.audience
            )
        ):
            raise TenantIsolationError("verified audience is invalid")
        if (
            not isinstance(self.scopes, frozenset)
            or len(self.scopes) > 64
            or any(
                not isinstance(value, str) or _SCOPE_RE.fullmatch(value) is None
                for value in self.scopes
            )
        ):
            raise TenantIsolationError("verified scopes are invalid")

    def require(self, scope: str) -> None:
        if scope not in self.scopes:
            raise TenantIsolationError("OAuth scope is insufficient")


@dataclass(frozen=True)
class TenantVault:
    tenant_id: str
    root: Path
    registry_path: Path
    action_log_path: Path
    inbox_path: Path
    jobs_path: Path


class TenantVaultRouter:
    """Derive a private vault only from a verified OAuth issuer and subject."""

    def __init__(self, root: str | os.PathLike[str], *, hmac_key: bytes):
        if not isinstance(hmac_key, bytes) or len(hmac_key) < 32:
            raise TenantIsolationError("tenant HMAC key must contain at least 32 bytes")
        candidate = Path(root)
        if not candidate.is_absolute():
            raise TenantIsolationError("tenant root must be absolute")
        try:
            unresolved = Path(os.path.abspath(candidate))
            resolved = candidate.resolve(strict=False)
        except (OSError, RuntimeError, ValueError) as err:
            raise TenantIsolationError("tenant root is invalid") from err
        if os.path.normcase(str(unresolved)) != os.path.normcase(str(resolved)):
            raise TenantIsolationError("tenant root must not traverse a symlink")
        resolved.mkdir(parents=True, exist_ok=True)
        if resolved.is_symlink() or not resolved.is_dir():
            raise TenantIsolationError("tenant root must be a real directory")
        try:
            os.chmod(resolved, 0o700)
        except OSError:
            pass
        self._root = resolved
        self._key = bytes(hmac_key)

    @property
    def root(self) -> Path:
        return self._root

    def tenant_id(self, principal: VerifiedOAuthPrincipal) -> str:
        if not isinstance(principal, VerifiedOAuthPrincipal):
            raise TenantIsolationError("verified OAuth principal is required")
        material = json.dumps(
            [principal.issuer, principal.subject],
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        return "t_" + hmac.new(self._key, material, sha256).hexdigest()

    def vault(self, principal: VerifiedOAuthPrincipal, *, create: bool = True) -> TenantVault:
        tenant_id = self.tenant_id(principal)
        if _TENANT_RE.fullmatch(tenant_id) is None:
            raise TenantIsolationError("derived tenant id is invalid")
        tenant_parent = self._root / "tenants"
        tenant_root = tenant_parent / tenant_id
        paths = (
            tenant_parent,
            tenant_root,
            tenant_root / "config",
            tenant_root / "action-log",
            tenant_root / "inbox",
            tenant_root / "import-jobs",
        )
        if create:
            for path in paths:
                path.mkdir(exist_ok=True)
                if path.is_symlink() or not path.is_dir():
                    raise TenantIsolationError(
                        "tenant vault contains a redirected directory"
                    )
                try:
                    path.relative_to(self._root)
                except ValueError as err:
                    raise TenantIsolationError(
                        "tenant vault escapes the configured root"
                    ) from err
                try:
                    os.chmod(path, 0o700)
                except OSError:
                    pass
        elif not tenant_root.is_dir() or tenant_root.is_symlink():
            raise TenantIsolationError("tenant vault is unavailable")
        return TenantVault(
            tenant_id=tenant_id,
            root=tenant_root,
            registry_path=tenant_root / "config" / "memory-scopes.json",
            action_log_path=tenant_root / "action-log" / "events.jsonl",
            inbox_path=tenant_root / "inbox",
            jobs_path=tenant_root / "import-jobs",
        )


class TenantRuntimeFactory(Generic[_RuntimeT]):
    """Construct and cache one isolated tool runtime per verified principal."""

    def __init__(
        self,
        router: TenantVaultRouter,
        builder: Callable[[TenantVault], _RuntimeT],
        *,
        required_scope: str = "memory:read",
        max_runtimes: int = 256,
    ):
        if not callable(builder):
            raise TenantIsolationError("tenant runtime builder is required")
        if _SCOPE_RE.fullmatch(required_scope) is None:
            raise TenantIsolationError("required OAuth scope is invalid")
        if (
            isinstance(max_runtimes, bool)
            or not isinstance(max_runtimes, int)
            or not 1 <= max_runtimes <= 4096
        ):
            raise TenantIsolationError("tenant runtime cache size is invalid")
        self._router = router
        self._builder = builder
        self._required_scope = required_scope
        self._max_runtimes = max_runtimes
        self._runtimes: OrderedDict[str, _RuntimeT] = OrderedDict()
        self._lock = threading.RLock()

    def for_principal(self, principal: VerifiedOAuthPrincipal) -> _RuntimeT:
        principal.require(self._required_scope)
        vault = self._router.vault(principal)
        with self._lock:
            runtime = self._runtimes.get(vault.tenant_id)
            if runtime is None:
                runtime = self._builder(vault)
                self._runtimes[vault.tenant_id] = runtime
                while len(self._runtimes) > self._max_runtimes:
                    self._runtimes.popitem(last=False)
            else:
                self._runtimes.move_to_end(vault.tenant_id)
            return runtime


__all__ = [
    "TenantIsolationError",
    "TenantRuntimeFactory",
    "TenantVault",
    "TenantVaultRouter",
    "VerifiedOAuthPrincipal",
]
