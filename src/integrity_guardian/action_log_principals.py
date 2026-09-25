"""Closed reader-principal and append-credential contracts for Action Log.

The module is intentionally independent from the HTTP server. Registries retain
only domain-separated credential fingerprints, and read receipts retain only
response identities and budgets. Raw credentials, queries, and memory bodies
must never enter persisted evidence.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import os
import re
import stat
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows has no fcntl.
    fcntl = None

REGISTRY_SCHEMA: Final = "integrity.action-log.reader-principals.v1"
APPEND_CREDENTIAL_SCHEMA: Final = "integrity.action-log.append-credential.v1"
READ_RECEIPT_PROTOCOL: Final = "integrity.action-log.read-receipt.v1"
READER_HEADER: Final = "X-Codex-Log-Token"
APPEND_HEADER: Final = "X-Codex-Append-Token"
READER_SURFACES: Final = frozenset(
    {
        "bootstrap",
        "context",
        "events",
        "health",
        "locks",
        "mind",
        "reflex",
        "tasks",
        "ui",
    }
)
READ_ROUTE_SURFACES: Final = {
    ("GET", "/"): "ui",
    ("GET", "/api/health"): "health",
    ("GET", "/api/events"): "events",
    ("GET", "/api/tasks"): "tasks",
    ("GET", "/api/locks"): "locks",
    ("GET", "/api/bootstrap"): "bootstrap",
    ("GET", "/api/reflex"): "reflex",
    ("GET", "/api/mind"): "mind",
    ("GET", "/api/context"): "context",
    ("POST", "/api/bootstrap"): "bootstrap",
    ("POST", "/api/mind"): "mind",
}
APPEND_ROUTES: Final = frozenset(
    {
        ("POST", "/api/events"),
        ("POST", "/api/tasks/accept"),
        ("POST", "/events"),
        ("POST", "/ui/events"),
    }
)
MAX_REGISTRY_BYTES: Final = 131_072
MAX_CREDENTIAL_BYTES: Final = 512
MIN_CREDENTIAL_BYTES: Final = 32
MAX_PRINCIPALS: Final = 128
MAX_READER_LIFETIME: Final = dt.timedelta(days=30)
MAX_RESPONSE_BYTES: Final = 32 * 1024 * 1024
MAX_RECORDS: Final = 2_000
MAX_RECEIPT_BYTES: Final = 16_384
MAX_AUDIT_BYTES: Final = 128 * 1024 * 1024
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,191}$")
_NONCE_RE = re.compile(r"^[0-9a-f]{32}$")
_RFC3339_RE = re.compile(
    r"^(?:[0-9]{4})-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]{1,9})?"
    r"(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])$"
)
_CURSOR_FIELDS: Final = {
    "event_cursor": int,
    "snapshot_event_id": int,
    "maximum_event_id": int,
    "minimum_event_id": int,
    "next_after_id": int,
    "offset": int,
    "limit": int,
    "page_size": int,
    "returned_count": int,
    "has_more": bool,
}
_RECEIPT_FIELDS: Final = {
    "protocol",
    "receipt_id",
    "registry_digest",
    "principal_id",
    "principal_fingerprint",
    "tenant",
    "surface",
    "method",
    "path",
    "response_digest",
    "response_bytes",
    "returned_records",
    "cursor_window",
    "max_response_bytes",
    "max_records",
    "observed_at",
    "nonce",
    "production_authority",
}
_AUDIT_LOCK = threading.Lock()


class PrincipalError(RuntimeError):
    """A fail-closed principal, credential, budget, or audit denial."""


@dataclass(frozen=True)
class ReaderPrincipal:
    principal_id: str
    token_fingerprint: str
    surfaces: frozenset[str]
    active: bool
    issued_at: str
    expires_at: str
    max_response_bytes: int
    max_records: int


@dataclass(frozen=True)
class ReaderRegistry:
    tenant: str
    principals: tuple[ReaderPrincipal, ...]
    digest: str


@dataclass(frozen=True)
class ReaderAdmission:
    """Content-free result of one current private-registry authentication."""

    registry_digest: str
    principal_id: str
    principal_fingerprint: str
    tenant: str
    surface: str
    max_response_bytes: int
    max_records: int
    admitted_at: str
    expires_at: str
    production_authority: bool = False


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256(value: object, *, domain: bytes) -> str:
    return "sha256:" + hashlib.sha256(domain + b"\0" + canonical_json(value)).hexdigest()


def _utc_now() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_time(value: object) -> dt.datetime:
    if not isinstance(value, str) or not _RFC3339_RE.fullmatch(value):
        raise PrincipalError("principal time is not canonical RFC3339")
    try:
        parsed = dt.datetime.fromisoformat(value)
    except ValueError as exc:
        raise PrincipalError("principal time is invalid") from exc
    if parsed.tzinfo is None:
        raise PrincipalError("principal time has no offset")
    return parsed.astimezone(dt.UTC)


def credential_wire(value: object, *, label: str) -> str:
    if not isinstance(value, str):
        raise PrincipalError(f"{label} credential is missing")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise PrincipalError(f"{label} credential is not visible ASCII") from exc
    if not MIN_CREDENTIAL_BYTES <= len(encoded) <= MAX_CREDENTIAL_BYTES:
        raise PrincipalError(f"{label} credential length is invalid")
    if any(byte < 0x21 or byte > 0x7E for byte in encoded):
        raise PrincipalError(f"{label} credential contains whitespace or controls")
    return value


def reader_token_fingerprint(token: object) -> str:
    value = credential_wire(token, label="reader")
    return "sha256:" + hashlib.sha256(
        b"integrity-action-log-reader-token-v1\0" + value.encode("ascii")
    ).hexdigest()


def append_token_fingerprint(token: object) -> str:
    # Append identity stays domain-separated from every reader principal.
    value = credential_wire(token, label="append")
    return "sha256:" + hashlib.sha256(
        b"integrity-action-log-append-token-v1\0" + value.encode("ascii")
    ).hexdigest()


def read_surface_for(method: object, path: object) -> str | None:
    if not isinstance(method, str) or not isinstance(path, str):
        return None
    return READ_ROUTE_SURFACES.get((method, path))


def is_append_route(method: object, path: object) -> bool:
    return isinstance(method, str) and isinstance(path, str) and (method, path) in APPEND_ROUTES


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PrincipalError("reader registry contains duplicate JSON keys")
        result[key] = value
    return result


def _is_link_like(path: Path) -> bool:
    try:
        value = path.lstat()
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(value.st_mode):
        return True
    attributes = int(getattr(value, "st_file_attributes", 0))
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return bool(attributes & reparse_flag)


def _assert_no_link_chain(path: Path) -> None:
    if not path.is_absolute():
        raise PrincipalError("principal state path must be absolute")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if _is_link_like(current):
            raise PrincipalError("principal state path contains a link or reparse point")


def _require_private_parent(path: Path) -> None:
    if os.name == "nt":
        raise PrincipalError("native Windows principal custody verifier is required")
    _assert_no_link_chain(path.parent)
    try:
        current = Path(path.parent.anchor)
        for part in path.parent.parts[1:]:
            current /= part
            value = current.lstat()
            mode = stat.S_IMODE(value.st_mode)
            owner_ok = value.st_uid in {0, os.geteuid()}
            sticky_root = value.st_uid == 0 and bool(mode & stat.S_ISVTX)
            if (
                not stat.S_ISDIR(value.st_mode)
                or not owner_ok
                or (mode & (stat.S_IWGRP | stat.S_IWOTH) and not sticky_root)
            ):
                raise PrincipalError("principal state directory chain is unsafe")
        parent = path.parent.lstat()
    except OSError as exc:
        raise PrincipalError("principal state parent is unavailable") from exc
    if (
        not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.geteuid()
        or stat.S_IMODE(parent.st_mode) & 0o077
    ):
        raise PrincipalError("principal state parent custody is unsafe")


def _read_private_file(path: Path, *, maximum_bytes: int, label: str) -> bytes:
    _require_private_parent(path)
    _assert_no_link_chain(path)
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise PrincipalError(f"{label} is unavailable") from exc
    try:
        before = os.fstat(descriptor)
        owner_ok = not hasattr(os, "geteuid") or before.st_uid == os.geteuid()
        if (
            not stat.S_ISREG(before.st_mode)
            or int(getattr(before, "st_nlink", 1)) != 1
            or not owner_ok
            or (os.name != "nt" and stat.S_IMODE(before.st_mode) & 0o077)
            or before.st_size < 1
            or before.st_size > maximum_bytes
        ):
            raise PrincipalError(f"{label} custody is unsafe")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                raise PrincipalError(f"{label} changed while reading")
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_nlink",
            "st_uid",
            "st_gid",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if any(getattr(before, field, None) != getattr(after, field, None) for field in stable_fields):
            raise PrincipalError(f"{label} changed while reading")
        return payload
    finally:
        os.close(descriptor)


def _registry_payload(registry: ReaderRegistry) -> dict[str, Any]:
    return {
        "schema": REGISTRY_SCHEMA,
        "tenant": registry.tenant,
        "principals": [
            {
                "principal_id": principal.principal_id,
                "token_fingerprint": principal.token_fingerprint,
                "surfaces": sorted(principal.surfaces),
                "active": principal.active,
                "issued_at": principal.issued_at,
                "expires_at": principal.expires_at,
                "max_response_bytes": principal.max_response_bytes,
                "max_records": principal.max_records,
            }
            for principal in registry.principals
        ],
    }


def _validate_reader_registry(registry: object) -> ReaderRegistry:
    """Reject fabricated, stale, ambiguous, or non-canonical registry objects."""

    if (
        not isinstance(registry, ReaderRegistry)
        or not isinstance(registry.tenant, str)
        or not _ID_RE.fullmatch(registry.tenant)
        or not isinstance(registry.principals, tuple)
        or not 1 <= len(registry.principals) <= MAX_PRINCIPALS
    ):
        raise PrincipalError("reader registry object is invalid")
    seen_ids: set[str] = set()
    seen_fingerprints: set[str] = set()
    principal_ids: list[str] = []
    for principal in registry.principals:
        if not isinstance(principal, ReaderPrincipal):
            raise PrincipalError("reader registry principal object is invalid")
        issued_at = _parse_time(principal.issued_at)
        expires_at = _parse_time(principal.expires_at)
        if (
            not isinstance(principal.principal_id, str)
            or not _ID_RE.fullmatch(principal.principal_id)
            or principal.principal_id in seen_ids
            or not isinstance(principal.token_fingerprint, str)
            or not _DIGEST_RE.fullmatch(principal.token_fingerprint)
            or principal.token_fingerprint in seen_fingerprints
            or not isinstance(principal.surfaces, frozenset)
            or not principal.surfaces
            or not all(
                isinstance(surface, str) and surface in READER_SURFACES
                for surface in principal.surfaces
            )
            or not isinstance(principal.active, bool)
            or issued_at >= expires_at
            or expires_at - issued_at > MAX_READER_LIFETIME
            or isinstance(principal.max_response_bytes, bool)
            or not isinstance(principal.max_response_bytes, int)
            or not 1 <= principal.max_response_bytes <= MAX_RESPONSE_BYTES
            or isinstance(principal.max_records, bool)
            or not isinstance(principal.max_records, int)
            or not 1 <= principal.max_records <= MAX_RECORDS
        ):
            raise PrincipalError("reader registry principal contract is invalid")
        seen_ids.add(principal.principal_id)
        seen_fingerprints.add(principal.token_fingerprint)
        principal_ids.append(principal.principal_id)
    if principal_ids != sorted(principal_ids):
        raise PrincipalError("reader registry principals are not canonical")
    expected_digest = _sha256(
        _registry_payload(
            ReaderRegistry(
                tenant=registry.tenant,
                principals=registry.principals,
                digest="",
            )
        ),
        domain=b"action-log-reader-registry-v1",
    )
    if (
        not isinstance(registry.digest, str)
        or not _DIGEST_RE.fullmatch(registry.digest)
        or not hmac.compare_digest(registry.digest, expected_digest)
    ):
        raise PrincipalError("reader registry digest is invalid")
    return registry


def load_reader_registry(path: Path) -> ReaderRegistry:
    try:
        value = json.loads(
            _read_private_file(
                path,
                maximum_bytes=MAX_REGISTRY_BYTES,
                label="reader registry",
            ).decode("utf-8"),
            object_pairs_hook=_no_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PrincipalError("reader registry JSON is invalid") from exc
    if not isinstance(value, dict) or set(value) != {"schema", "tenant", "principals"}:
        raise PrincipalError("reader registry fields are invalid")
    tenant = value.get("tenant")
    raw_principals = value.get("principals")
    if (
        value.get("schema") != REGISTRY_SCHEMA
        or not isinstance(tenant, str)
        or not _ID_RE.fullmatch(tenant)
        or not isinstance(raw_principals, list)
        or not 1 <= len(raw_principals) <= MAX_PRINCIPALS
    ):
        raise PrincipalError("reader registry identity is invalid")
    seen_ids: set[str] = set()
    seen_fingerprints: set[str] = set()
    principals: list[ReaderPrincipal] = []
    required = {
        "principal_id",
        "token_fingerprint",
        "surfaces",
        "active",
        "issued_at",
        "expires_at",
        "max_response_bytes",
        "max_records",
    }
    for raw in raw_principals:
        if not isinstance(raw, dict) or set(raw) != required:
            raise PrincipalError("reader principal fields are invalid")
        principal_id = raw["principal_id"]
        fingerprint = raw["token_fingerprint"]
        surfaces = raw["surfaces"]
        issued_at = _parse_time(raw["issued_at"])
        expires_at = _parse_time(raw["expires_at"])
        max_bytes = raw["max_response_bytes"]
        max_records = raw["max_records"]
        if (
            not isinstance(principal_id, str)
            or not _ID_RE.fullmatch(principal_id)
            or principal_id in seen_ids
            or not isinstance(fingerprint, str)
            or not _DIGEST_RE.fullmatch(fingerprint)
            or fingerprint in seen_fingerprints
            or not isinstance(raw["active"], bool)
            or not isinstance(surfaces, list)
            or not surfaces
            or surfaces != sorted(surfaces)
            or len(set(surfaces)) != len(surfaces)
            or not all(isinstance(item, str) and item in READER_SURFACES for item in surfaces)
            or issued_at >= expires_at
            or expires_at - issued_at > MAX_READER_LIFETIME
            or isinstance(max_bytes, bool)
            or not isinstance(max_bytes, int)
            or not 1 <= max_bytes <= MAX_RESPONSE_BYTES
            or isinstance(max_records, bool)
            or not isinstance(max_records, int)
            or not 1 <= max_records <= MAX_RECORDS
        ):
            raise PrincipalError("reader principal contract is invalid")
        seen_ids.add(principal_id)
        seen_fingerprints.add(fingerprint)
        principals.append(
            ReaderPrincipal(
                principal_id=principal_id,
                token_fingerprint=fingerprint,
                surfaces=frozenset(surfaces),
                active=raw["active"],
                issued_at=raw["issued_at"],
                expires_at=raw["expires_at"],
                max_response_bytes=max_bytes,
                max_records=max_records,
            )
        )
    temporary = ReaderRegistry(tenant=tenant, principals=tuple(principals), digest="")
    digest = _sha256(_registry_payload(temporary), domain=b"action-log-reader-registry-v1")
    return _validate_reader_registry(
        ReaderRegistry(tenant=tenant, principals=tuple(principals), digest=digest)
    )


def _authenticate_reader_registry(
    token: object,
    *,
    registry: ReaderRegistry,
    surface: str,
    tenant: str,
    at_time: str,
) -> ReaderPrincipal:
    registry = _validate_reader_registry(registry)
    if surface not in READER_SURFACES or registry.tenant != tenant:
        raise PrincipalError("reader principal tenant or surface is invalid")
    fingerprint = reader_token_fingerprint(token)
    matched: ReaderPrincipal | None = None
    for principal in registry.principals:
        if hmac.compare_digest(principal.token_fingerprint, fingerprint):
            matched = principal
    if matched is None:
        raise PrincipalError("reader principal is unknown")
    if not matched.active:
        raise PrincipalError("reader principal is inactive or revoked")
    if surface not in matched.surfaces:
        raise PrincipalError("reader principal scope mismatch")
    now = _parse_time(at_time)
    if not _parse_time(matched.issued_at) <= now < _parse_time(matched.expires_at):
        raise PrincipalError("reader principal is expired or not active yet")
    return matched


def _load_registry_authority(registry_path: object) -> ReaderRegistry:
    if not isinstance(registry_path, Path):
        raise PrincipalError("reader registry path is invalid")
    return load_reader_registry(registry_path)


def _authenticate_reader_at(
    token: object,
    *,
    registry_path: Path,
    surface: str,
    tenant: str,
    at_time: str,
) -> ReaderAdmission:
    """Deterministic internal boundary used by the public clock-owned API."""

    observed = at_time
    registry = _load_registry_authority(registry_path)
    principal = _authenticate_reader_registry(
        token,
        registry=registry,
        surface=surface,
        tenant=tenant,
        at_time=observed,
    )
    return ReaderAdmission(
        registry_digest=registry.digest,
        principal_id=principal.principal_id,
        principal_fingerprint=principal.token_fingerprint,
        tenant=tenant,
        surface=surface,
        max_response_bytes=principal.max_response_bytes,
        max_records=principal.max_records,
        admitted_at=observed,
        expires_at=principal.expires_at,
        production_authority=False,
    )


def authenticate_reader(
    token: object,
    *,
    registry_path: Path,
    surface: str,
    tenant: str,
) -> ReaderAdmission:
    """Authenticate at the kernel-owned current time."""

    return _authenticate_reader_at(
        token,
        registry_path=registry_path,
        surface=surface,
        tenant=tenant,
        at_time=_utc_now(),
    )


def load_append_credential_fingerprint(path: Path) -> str:
    try:
        value = json.loads(
            _read_private_file(
                path,
                maximum_bytes=4_096,
                label="append credential authority",
            ).decode("utf-8"),
            object_pairs_hook=_no_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PrincipalError("append credential authority JSON is invalid") from exc
    if (
        not isinstance(value, dict)
        or set(value) != {"schema", "token_fingerprint"}
        or value.get("schema") != APPEND_CREDENTIAL_SCHEMA
        or not isinstance(value.get("token_fingerprint"), str)
        or not _DIGEST_RE.fullmatch(value["token_fingerprint"])
    ):
        raise PrincipalError("append credential authority is invalid")
    return value["token_fingerprint"]


def require_append_credential(
    token: object,
    *,
    credential_path: Path,
    registry_path: Path,
) -> str:
    registry = _load_registry_authority(registry_path)
    actual = append_token_fingerprint(token)
    expected = load_append_credential_fingerprint(credential_path)
    if not hmac.compare_digest(actual, expected):
        raise PrincipalError("append credential mismatch")
    reader_fingerprint = reader_token_fingerprint(credential_wire(token, label="append"))
    for principal in registry.principals:
        if hmac.compare_digest(principal.token_fingerprint, reader_fingerprint):
            raise PrincipalError("append credential collides with a reader principal")
    return actual


def _validated_cursor_window(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise PrincipalError("read receipt cursor window is invalid")
    result: dict[str, object] = {}
    for raw_key, raw_value in value.items():
        if not isinstance(raw_key, str) or raw_key not in _CURSOR_FIELDS:
            raise PrincipalError("read receipt cursor window contains an unsupported field")
        expected_type = _CURSOR_FIELDS[raw_key]
        if expected_type is bool:
            if not isinstance(raw_value, bool):
                raise PrincipalError("read receipt cursor window value is invalid")
        elif isinstance(raw_value, bool) or not isinstance(raw_value, int) or raw_value < 0:
            raise PrincipalError("read receipt cursor window value is invalid")
        result[raw_key] = raw_value
    return result


def _receipt_core(receipt: Mapping[str, Any]) -> dict[str, Any]:
    return {key: receipt[key] for key in sorted(_RECEIPT_FIELDS - {"receipt_id"})}


def validate_read_receipt(receipt: object) -> dict[str, Any]:
    if not isinstance(receipt, dict) or set(receipt) != _RECEIPT_FIELDS:
        raise PrincipalError("read receipt fields are invalid")
    method = receipt["method"]
    path = receipt["path"]
    surface = receipt["surface"]
    if (
        receipt["protocol"] != READ_RECEIPT_PROTOCOL
        or read_surface_for(method, path) != surface
        or not isinstance(receipt["registry_digest"], str)
        or not _DIGEST_RE.fullmatch(receipt["registry_digest"])
        or not isinstance(receipt["principal_id"], str)
        or not _ID_RE.fullmatch(receipt["principal_id"])
        or not isinstance(receipt["principal_fingerprint"], str)
        or not _DIGEST_RE.fullmatch(receipt["principal_fingerprint"])
        or not isinstance(receipt["tenant"], str)
        or not _ID_RE.fullmatch(receipt["tenant"])
        or not isinstance(receipt["response_digest"], str)
        or not _DIGEST_RE.fullmatch(receipt["response_digest"])
        or isinstance(receipt["response_bytes"], bool)
        or not isinstance(receipt["response_bytes"], int)
        or receipt["response_bytes"] < 0
        or isinstance(receipt["returned_records"], bool)
        or not isinstance(receipt["returned_records"], int)
        or receipt["returned_records"] < 0
        or isinstance(receipt["max_response_bytes"], bool)
        or not isinstance(receipt["max_response_bytes"], int)
        or not 1 <= receipt["max_response_bytes"] <= MAX_RESPONSE_BYTES
        or receipt["response_bytes"] > receipt["max_response_bytes"]
        or isinstance(receipt["max_records"], bool)
        or not isinstance(receipt["max_records"], int)
        or not 1 <= receipt["max_records"] <= MAX_RECORDS
        or receipt["returned_records"] > receipt["max_records"]
        or not isinstance(receipt["observed_at"], str)
        or not isinstance(receipt["nonce"], str)
        or not _NONCE_RE.fullmatch(receipt["nonce"])
        or receipt["production_authority"] is not False
    ):
        raise PrincipalError("read receipt contract is invalid")
    _parse_time(receipt["observed_at"])
    normalized = dict(receipt)
    normalized["cursor_window"] = _validated_cursor_window(receipt["cursor_window"])
    expected_id = _sha256(
        _receipt_core(normalized),
        domain=b"action-log-read-receipt-v1",
    )
    if not isinstance(normalized["receipt_id"], str) or not hmac.compare_digest(
        normalized["receipt_id"], expected_id
    ):
        raise PrincipalError("read receipt identity is invalid")
    payload = canonical_json(normalized)
    if len(payload) > MAX_RECEIPT_BYTES:
        raise PrincipalError("read receipt exceeds its byte limit")
    return normalized


def _build_read_receipt_at(
    *,
    registry_path: Path,
    reader_token: object,
    tenant: str,
    surface: str,
    method: str,
    path: str,
    response_digest: str,
    response_bytes: int,
    returned_records: int,
    cursor_window: Mapping[str, object],
    observed_at: str,
    nonce: str,
) -> dict[str, Any]:
    """Deterministic internal receipt boundary used by the public API."""

    observed = observed_at
    admission = _authenticate_reader_at(
        reader_token,
        registry_path=registry_path,
        surface=surface,
        tenant=tenant,
        at_time=observed,
    )
    nonce_value = nonce
    if (
        read_surface_for(method, path) != surface
        or not isinstance(response_digest, str)
        or not _DIGEST_RE.fullmatch(response_digest)
        or isinstance(response_bytes, bool)
        or not isinstance(response_bytes, int)
        or response_bytes < 0
        or response_bytes > admission.max_response_bytes
        or isinstance(returned_records, bool)
        or not isinstance(returned_records, int)
        or returned_records < 0
        or returned_records > admission.max_records
    ):
        raise PrincipalError("reader response exceeds its admitted budget or route")
    core = {
        "protocol": READ_RECEIPT_PROTOCOL,
        "registry_digest": admission.registry_digest,
        "principal_id": admission.principal_id,
        "principal_fingerprint": admission.principal_fingerprint,
        "tenant": tenant,
        "surface": surface,
        "method": method,
        "path": path,
        "response_digest": response_digest,
        "response_bytes": response_bytes,
        "returned_records": returned_records,
        "cursor_window": _validated_cursor_window(cursor_window),
        "max_response_bytes": admission.max_response_bytes,
        "max_records": admission.max_records,
        "observed_at": observed,
        "nonce": nonce_value,
        "production_authority": False,
    }
    receipt = {
        **core,
        "receipt_id": _sha256(core, domain=b"action-log-read-receipt-v1"),
    }
    return validate_read_receipt(receipt)


def build_read_receipt(
    *,
    registry_path: Path,
    reader_token: object,
    tenant: str,
    surface: str,
    method: str,
    path: str,
    response_digest: str,
    response_bytes: int,
    returned_records: int,
    cursor_window: Mapping[str, object],
) -> dict[str, Any]:
    """Reauthenticate at the kernel-owned current time and generate the nonce."""

    return _build_read_receipt_at(
        registry_path=registry_path,
        reader_token=reader_token,
        tenant=tenant,
        surface=surface,
        method=method,
        path=path,
        response_digest=response_digest,
        response_bytes=response_bytes,
        returned_records=returned_records,
        cursor_window=cursor_window,
        observed_at=_utc_now(),
        nonce=os.urandom(16).hex(),
    )


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("audit write did not advance")
        view = view[written:]


def append_read_receipt(path: Path, receipt: object) -> None:
    validated = validate_read_receipt(receipt)
    payload = canonical_json(validated) + b"\n"
    _require_private_parent(path)
    _assert_no_link_chain(path)
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    with _AUDIT_LOCK:
        try:
            descriptor = os.open(path, flags, 0o600)
        except OSError as exc:
            raise PrincipalError("read audit is unavailable") from exc
        locked = False
        original_size = 0
        can_rollback = False
        try:
            state = os.fstat(descriptor)
            owner_ok = not hasattr(os, "geteuid") or state.st_uid == os.geteuid()
            if (
                not stat.S_ISREG(state.st_mode)
                or int(getattr(state, "st_nlink", 1)) != 1
                or not owner_ok
                or (os.name != "nt" and stat.S_IMODE(state.st_mode) & 0o077)
            ):
                raise PrincipalError("read audit custody is unsafe")
            if fcntl is not None:
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                locked = True
            original_size = os.fstat(descriptor).st_size
            if (
                original_size > MAX_AUDIT_BYTES
                or len(payload) > MAX_AUDIT_BYTES
                or original_size + len(payload) > MAX_AUDIT_BYTES
            ):
                raise PrincipalError("read audit exceeds its byte limit")
            can_rollback = True
            _write_all(descriptor, payload)
            os.fsync(descriptor)
        except Exception as exc:
            if can_rollback:
                try:
                    os.ftruncate(descriptor, original_size)
                    os.fsync(descriptor)
                except OSError:
                    pass
            if isinstance(exc, PrincipalError):
                raise
            raise PrincipalError("read audit append failed") from exc
        finally:
            if locked and fcntl is not None:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                except OSError:
                    pass
            os.close(descriptor)
