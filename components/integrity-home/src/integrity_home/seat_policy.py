"""Resolve a verified caller into SeatContext and authorize namespaces.

Mode A uses a verified OAuth principal. Mode B uses a seat token from the
``X-Integrity-Seat-Token`` header or ``INTEGRITY_SEAT_TOKEN_FILE``. Seat and
host identity are never taken from request JSON.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path

from .seat_registry import SeatRecord, SeatRegistry, SeatRegistryError
from .tenant import VerifiedOAuthPrincipal


ISOLATION_MODES = frozenset({"silo", "shared-core", "single-user"})


class SeatAccessError(PermissionError):
    def __init__(self, code: str, status: int = 403) -> None:
        super().__init__(code)
        self.code = code
        self.status = status


@dataclass(frozen=True)
class SeatContext:
    seat_id: str
    host_id: str
    roles: frozenset[str]
    namespaces: tuple[str, ...]
    auth_principal_sha256: str


def namespace_allowed(patterns: tuple[str, ...] | list[str], namespace: str) -> bool:
    if not isinstance(namespace, str) or not namespace or len(namespace) > 128:
        return False
    parts = namespace.split("/")
    if any(not part or part == "*" for part in parts):
        return False
    for pattern in patterns:
        pattern_parts = pattern.split("/")
        if len(pattern_parts) != len(parts):
            continue
        if all(pat == "*" or pat == part for pat, part in zip(pattern_parts, parts)):
            return True
    return False


def _context_from_seat(seat: SeatRecord, host_id: str, principal_sha256: str) -> SeatContext:
    if seat.status != "active":
        raise SeatAccessError("seat revoked", 403)
    return SeatContext(
        seat_id=seat.seat_id,
        host_id=host_id,
        roles=seat.roles,
        namespaces=seat.namespaces,
        auth_principal_sha256=principal_sha256,
    )


class SeatPolicyRouter:
    """One shared Action Log. Unknown, expired, or revoked callers fail closed."""

    def __init__(self, registry: SeatRegistry) -> None:
        self.registry = registry

    def resolve_principal(
        self, principal: VerifiedOAuthPrincipal, *, host_id: str = "oauth"
    ) -> SeatContext:
        if not isinstance(principal, VerifiedOAuthPrincipal):
            raise SeatAccessError("oauth principal required", 401)
        try:
            seat = self.registry.seat_for_identity(principal.issuer, principal.subject)
        except SeatRegistryError as err:
            raise SeatAccessError(err.code, err.status) from err
        digest = sha256(
            f"{principal.issuer}\n{principal.subject}".encode("utf-8")
        ).hexdigest()
        return _context_from_seat(seat, host_id, digest)

    def resolve_token(self, token: str, *, now_utc: str) -> SeatContext:
        try:
            seat, host_id, digest = self.registry.resolve_token(token, now_utc=now_utc)
        except SeatRegistryError as err:
            raise SeatAccessError(err.code, err.status) from err
        return _context_from_seat(seat, host_id, digest)

    def resolve_request(
        self,
        *,
        principal: VerifiedOAuthPrincipal | None = None,
        header_token: str | None = None,
        now_utc: str,
        host_id: str = "oauth",
    ) -> SeatContext:
        file_token = _token_from_file()
        if header_token and file_token and header_token != file_token:
            raise SeatAccessError("seat token mismatch", 401)
        token = header_token or file_token
        if token:
            return self.resolve_token(token, now_utc=now_utc)
        if principal is not None:
            return self.resolve_principal(principal, host_id=host_id)
        raise SeatAccessError("seat required", 401)

    def authorize(self, context: SeatContext, namespace: str, action: str) -> None:
        if action not in {"read", "write"}:
            raise SeatAccessError("action invalid", 403)
        if not namespace_allowed(context.namespaces, namespace):
            raise SeatAccessError("namespace forbidden", 403)
        if action == "read":
            if context.roles.isdisjoint({"read", "write", "admin", "go_approver"}):
                raise SeatAccessError("read forbidden", 403)
            return
        if context.roles.isdisjoint({"write", "admin"}):
            raise SeatAccessError("write forbidden", 403)


def _token_from_file() -> str | None:
    path = os.environ.get("INTEGRITY_SEAT_TOKEN_FILE")
    if not path:
        return None
    file_path = Path(path)
    try:
        token = file_path.read_text(encoding="utf-8").strip()
    except OSError as err:
        raise SeatAccessError("seat token unreadable", 401) from err
    if not token:
        raise SeatAccessError("seat token invalid", 401)
    return token


def isolation_mode_for(root: str | os.PathLike[str]) -> str:
    """Shared-core for a new root. An existing silo or marker wins until migrate."""

    directory = Path(root)
    marker = directory / "isolation-mode.json"
    if marker.is_file():
        try:
            document = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as err:
            raise SeatAccessError("isolation mode unreadable", 403) from err
        mode = document.get("mode") if isinstance(document, dict) else None
        if mode not in ISOLATION_MODES:
            raise SeatAccessError("isolation mode invalid", 403)
        return str(mode)
    tenants = directory / "tenants"
    if tenants.is_dir() and any(tenants.iterdir()):
        return "silo"
    configured = os.environ.get("INTEGRITY_ISOLATION_MODE")
    if configured:
        if configured not in ISOLATION_MODES:
            raise SeatAccessError("isolation mode invalid", 403)
        return configured
    if directory.exists() and any(directory.iterdir()):
        return "single-user"
    return "shared-core"


def write_isolation_mode(root: str | os.PathLike[str], mode: str) -> None:
    if mode not in ISOLATION_MODES:
        raise SeatAccessError("isolation mode invalid", 400)
    directory = Path(root)
    directory.mkdir(parents=True, exist_ok=True)
    marker = directory / "isolation-mode.json"
    marker.write_text(
        json.dumps({"mode": mode, "verified": True}, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    try:
        os.chmod(marker, 0o600)
    except OSError:
        pass
