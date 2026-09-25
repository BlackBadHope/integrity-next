"""Native, replaceable trust bootstrap for personal Integrity instances.

The default backend creates keys from the operating-system CSPRNG and keeps
their raw Ed25519 seeds in a private local state root.  The protocol-facing
store depends only on ``SignerBackend``: a TPM, HSM, remote signer or managed
CA can replace the file backend without changing database, device, module or
session documents.

Private keys are never stored in an Integrity SQLite database.  Databases keep
only an issuer-signed enrollment and use caller-custodied signer handles.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from collections.abc import Callable, Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

from .canonical import canonical_bytes, parse_json_strict
from .hashing import digest_object
from .medor_architecture import build_medor_event_append_decision
from .medor_security import (
    VerifiedMedorSecurityAdmission,
    build_native_medor_security_admission,
    verify_native_medor_security_admission,
)
from .schemas import validate
from .signing import (
    Ed25519Signer,
    TrustedKey,
    public_key_fingerprint,
    public_key_value,
    trusted_key_from_value,
    verify_signature,
)

_ROLE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_INSTANCE = re.compile(r"^instance:[a-z0-9][a-z0-9._-]{0,127}$")
_DEVICE = re.compile(r"^device:[A-Za-z0-9._:-]+$")
_MODULE = re.compile(r"^module:[A-Za-z0-9._:-]+$")
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_MAX_PRIVATE_FILE = 4 * 1024 * 1024

NATIVE_TRUST_PROTOCOL = "integrity-guardian/native-trust-genesis/v1"
NATIVE_TRUST_PROFILE = "personal-native"
MANAGED_TRUST_PROFILE = "managed-external"
DEFAULT_DEVICE_SCOPES = ("memory.append", "memory.read")
DEVICE_SCOPES = frozenset(DEFAULT_DEVICE_SCOPES)
MODULE_SCOPES = frozenset({*DEFAULT_DEVICE_SCOPES, "module.manage"})
ALL_NATIVE_SCOPES = frozenset(
    {
        "database.create",
        "device.enroll",
        "memory.append",
        "memory.read",
        "module.manage",
        "trust.rotate",
    }
)
OPERATIONAL_ROLES = (
    "ledger-issuer",
    "device-issuer",
    "module-issuer",
    "session-issuer",
    "event-append-issuer",
    "security-issuer",
)
RELEASE_AUTHORITY_ROLE = "release-authority"


class NativeTrustError(ValueError):
    """Raised before native trust state can be weakened or made ambiguous."""


class SignerBackend(Protocol):
    """Replaceable key-custody boundary used by the native trust protocols."""

    backend_id: str

    def ensure_signer(self, role: str, *, key_id: str) -> Ed25519Signer:
        """Return an existing signer or create it atomically when supported."""

    def load_signer(self, role: str, *, key_id: str) -> Ed25519Signer:
        """Return one signer without creating missing key material."""


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_time(value: str, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise NativeTrustError(f"native trust {field} is invalid") from exc
    if parsed.tzinfo is None:
        raise NativeTrustError(f"native trust {field} must include timezone")
    return parsed


def _validate_scopes(scopes: Sequence[str]) -> tuple[str, ...]:
    result = tuple(sorted(set(scopes)))
    if not result or any(scope not in ALL_NATIVE_SCOPES for scope in result):
        raise NativeTrustError("native trust scope set is invalid")
    return result


def _validate_device_scopes(scopes: Sequence[str]) -> tuple[str, ...]:
    result = _validate_scopes(scopes)
    if not set(result).issubset(DEVICE_SCOPES):
        raise NativeTrustError("native device scope set exceeds connector authority")
    return result


def _validate_module_scopes(scopes: Sequence[str]) -> tuple[str, ...]:
    result = _validate_scopes(scopes)
    if not set(result).issubset(MODULE_SCOPES):
        raise NativeTrustError("native module scope set exceeds module authority")
    return result


def _ensure_private_directory(path: Path) -> None:
    if not path.is_absolute() or path.is_symlink():
        raise NativeTrustError("native trust directory path is unsafe")
    if os.name == "nt":
        from ._windows_files import create_private_directory_tree

        create_private_directory_tree(path)
        return
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    details = path.stat()
    if (
        not stat.S_ISDIR(details.st_mode)
        or details.st_uid != os.geteuid()
        or stat.S_IMODE(details.st_mode) & 0o077
    ):
        raise NativeTrustError("native trust directory custody is unsafe")


def _read_private(path: Path, *, maximum_bytes: int = _MAX_PRIVATE_FILE) -> bytes:
    if not path.is_absolute() or path.is_symlink():
        raise NativeTrustError("native trust file path is unsafe")
    if os.name == "nt":
        from .windows_private_state import read_private_bytes

        return read_private_bytes(path, maximum_bytes=maximum_bytes)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise NativeTrustError("native trust private file is unavailable") from exc
    try:
        details = os.fstat(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != os.geteuid()
            or stat.S_IMODE(details.st_mode) & 0o077
            or details.st_size > maximum_bytes
        ):
            raise NativeTrustError("native trust private file custody is unsafe")
        payload = os.read(descriptor, maximum_bytes + 1)
        if len(payload) > maximum_bytes:
            raise NativeTrustError("native trust private file is unbounded")
        return payload
    finally:
        os.close(descriptor)


def _write_private_once(path: Path, payload: bytes) -> None:
    _ensure_private_directory(path.parent)
    if os.name == "nt":
        from .windows_private_state import write_private_once

        write_private_once(path, payload)
        return
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    descriptor: int | None = None
    created = False
    try:
        descriptor = os.open(path, flags, 0o600)
        created = True
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise NativeTrustError("native trust private write made no progress")
            view = view[written:]
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o600)
    except Exception:
        if created:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)


def load_ed25519_seed(path: Path) -> bytes:
    """Read one exact private raw Ed25519 seed through native custody checks."""

    raw = _read_private(path.absolute(), maximum_bytes=32)
    if len(raw) != 32:
        raise NativeTrustError("native Ed25519 seed length is invalid")
    return raw


def _canonical_document(document: Mapping[str, object]) -> bytes:
    return canonical_bytes(dict(document)) + b"\n"


def _load_document(path: Path, schema: str) -> dict[str, object]:
    payload = _read_private(path)
    value = parse_json_strict(payload)
    if not isinstance(value, dict) or _canonical_document(value) != payload:
        raise NativeTrustError("native trust document is not canonical")
    validate(schema, value)
    return value


def _write_document_once(path: Path, document: Mapping[str, object], schema: str) -> None:
    value = dict(document)
    validate(schema, value)
    payload = _canonical_document(value)
    try:
        _write_private_once(path, payload)
    except FileExistsError:
        if _read_private(path) != payload:
            raise NativeTrustError("existing native trust document differs")


def verify_native_device_request(
    request: Mapping[str, object],
) -> dict[str, object]:
    """Verify one device-generated enrollment request and proof of possession."""

    candidate = deepcopy(dict(request))
    validate("native-device-enrollment-request", candidate)
    core = deepcopy(candidate)
    core.pop("signature")
    request_id = core.pop("request_id")
    instance_id = str(candidate["instance_id"])
    device_id = str(candidate["device_id"])
    identity = hashlib.sha256(f"{instance_id}\0{device_id}".encode()).hexdigest()
    expected_key_id = f"key:device:{identity}:identity"
    device_key = trusted_key_from_value(
        expected_key_id,
        str(candidate["public_key"]),
    )
    if (
        request_id != digest_object(core, domain="native-device-enrollment-request-v1")
        or candidate["signature"]["key_id"] != expected_key_id
        or not verify_signature(candidate, device_key.public_key)
    ):
        raise NativeTrustError("native device enrollment request verification failed")
    _validate_device_scopes(candidate["scopes"])
    _parse_time(str(candidate["created_at"]), "device request time")
    return candidate


def initialize_native_device_request(
    state_root: Path,
    *,
    instance_id: str,
    device_id: str,
    scopes: Sequence[str] = ("memory.read",),
    created_at: str | None = None,
) -> dict[str, object]:
    """Create an idempotent local identity request without any remote secret."""

    if _INSTANCE.fullmatch(instance_id) is None or _DEVICE.fullmatch(device_id) is None:
        raise NativeTrustError("native device or instance id is invalid")
    scope_set = _validate_device_scopes(scopes)
    instance_hash = hashlib.sha256(instance_id.encode()).hexdigest()
    identity = hashlib.sha256(f"{instance_id}\0{device_id}".encode()).hexdigest()
    root = state_root.absolute() / "native-device" / "v1" / "instances" / instance_hash
    _ensure_private_directory(root)
    backend = FileSignerBackend(root / "keys")
    signer = backend.ensure_signer(
        "identity",
        key_id=f"key:device:{identity}:identity",
    )
    path = root / "enrollment-request.json"
    if path.exists() or path.is_symlink():
        existing = verify_native_device_request(
            _load_document(path, "native-device-enrollment-request")
        )
        if (
            existing["instance_id"] != instance_id
            or existing["device_id"] != device_id
            or tuple(existing["scopes"]) != scope_set
            or existing["public_key"] != public_key_value(signer.public_key)
        ):
            raise NativeTrustError("existing native device request differs")
        return existing
    timestamp = created_at or _now()
    _parse_time(timestamp, "device request time")
    core: dict[str, object] = {
        "protocol": "integrity-guardian/native-device-enrollment-request/v1",
        "instance_id": instance_id,
        "device_id": device_id,
        "public_key": public_key_value(signer.public_key),
        "scopes": list(scope_set),
        "created_at": timestamp,
    }
    unsigned = {
        **core,
        "request_id": digest_object(
            core,
            domain="native-device-enrollment-request-v1",
        ),
    }
    request = signer.sign(unsigned)
    _write_document_once(path, request, "native-device-enrollment-request")
    return verify_native_device_request(request)


class FileSignerBackend:
    """OS-CSPRNG Ed25519 keys under exact private filesystem custody."""

    backend_id = "native-private-files-v1"

    def __init__(self, root: Path) -> None:
        self.root = root.absolute()
        _ensure_private_directory(self.root)

    def _path(self, role: str) -> Path:
        if _ROLE.fullmatch(role) is None:
            raise NativeTrustError("native signer role is invalid")
        return self.root / f"{role}.ed25519"

    def load_signer(self, role: str, *, key_id: str) -> Ed25519Signer:
        raw = _read_private(self._path(role), maximum_bytes=32)
        if len(raw) != 32:
            raise NativeTrustError("native signer key length is invalid")
        return Ed25519Signer(key_id, Ed25519PrivateKey.from_private_bytes(raw))

    def ensure_signer(self, role: str, *, key_id: str) -> Ed25519Signer:
        path = self._path(role)
        if path.exists() or path.is_symlink():
            return self.load_signer(role, key_id=key_id)
        key = Ed25519PrivateKey.generate()
        raw = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        try:
            _write_private_once(path, raw)
        except Exception:
            if not path.exists() or path.is_symlink():
                raise
        return self.load_signer(role, key_id=key_id)

    def import_seed(
        self,
        role: str,
        *,
        key_id: str,
        seed: bytes,
    ) -> Ed25519Signer:
        """Adopt one existing raw key without changing its public identity."""

        if len(seed) != 32:
            raise NativeTrustError("imported native signer seed length is invalid")
        expected = Ed25519Signer(key_id, Ed25519PrivateKey.from_private_bytes(seed))
        path = self._path(role)
        if path.exists() or path.is_symlink():
            existing = self.load_signer(role, key_id=key_id)
            if public_key_value(existing.public_key) != public_key_value(expected.public_key):
                raise NativeTrustError("existing native signer differs from imported key")
            return existing
        try:
            _write_private_once(path, seed)
        except Exception:
            if not path.exists() or path.is_symlink():
                raise
        existing = self.load_signer(role, key_id=key_id)
        if public_key_value(existing.public_key) != public_key_value(expected.public_key):
            raise NativeTrustError("imported native signer readback differs")
        return existing


class ExternalSignerBackend:
    """Adapter for managed CA/HSM signers without protocol format changes."""

    def __init__(
        self,
        backend_id: str,
        resolver: Callable[[str, str], Ed25519Signer],
    ) -> None:
        if not backend_id or len(backend_id) > 128:
            raise NativeTrustError("external signer backend id is invalid")
        self.backend_id = backend_id
        self._resolver = resolver

    def load_signer(self, role: str, *, key_id: str) -> Ed25519Signer:
        signer = self._resolver(role, key_id)
        if signer.key_id != key_id:
            raise NativeTrustError("external signer returned another key identity")
        return signer

    def ensure_signer(self, role: str, *, key_id: str) -> Ed25519Signer:
        return self.load_signer(role, key_id=key_id)


def _key_document(signer: Ed25519Signer, *, role: str) -> dict[str, object]:
    return {
        "key_id": signer.key_id,
        "role": role,
        "algorithm": "ed25519",
        "public_key": public_key_value(signer.public_key),
        "fingerprint": public_key_fingerprint(signer.public_key),
    }


def _certificate(
    subject: Ed25519Signer,
    *,
    role: str,
    issuer: Ed25519Signer,
    created_at: str,
) -> dict[str, object]:
    core: dict[str, object] = {
        "protocol": "integrity-guardian/native-key-certificate/v1",
        "issuer_key_id": issuer.key_id,
        "subject": _key_document(subject, role=role),
        "created_at": created_at,
    }
    unsigned = {
        **core,
        "certificate_id": digest_object(core, domain="native-key-certificate-v1"),
    }
    return issuer.sign(unsigned)


def _verify_certificate(
    certificate: Mapping[str, object],
    *,
    issuer: TrustedKey,
) -> TrustedKey:
    candidate = deepcopy(dict(certificate))
    core = deepcopy(candidate)
    signature = core.pop("signature", None)
    certificate_id = core.pop("certificate_id", None)
    if (
        not isinstance(signature, dict)
        or candidate.get("issuer_key_id") != issuer.key_id
        or certificate_id != digest_object(core, domain="native-key-certificate-v1")
        or not verify_signature(candidate, issuer.public_key)
    ):
        raise NativeTrustError("native key certificate verification failed")
    subject = candidate.get("subject")
    if not isinstance(subject, dict):
        raise NativeTrustError("native key certificate subject is invalid")
    key = trusted_key_from_value(str(subject["key_id"]), str(subject["public_key"]))
    if subject.get("fingerprint") != public_key_fingerprint(key.public_key):
        raise NativeTrustError("native key certificate fingerprint mismatch")
    return key


def verify_native_release_authority_enrollment(
    enrollment: Mapping[str, object],
    *,
    genesis: Mapping[str, object],
    expected_instance_id: str,
    expected_root_fingerprint: str,
) -> TrustedKey:
    """Verify public release custody from an owner-pinned native root."""

    genesis_document = deepcopy(dict(genesis))
    validate("native-trust-genesis", genesis_document)
    genesis_core = deepcopy(genesis_document)
    genesis_id = genesis_core.pop("genesis_id")
    root_document = genesis_document["root"]
    assert isinstance(root_document, dict)
    root = trusted_key_from_value(
        str(root_document["key_id"]),
        str(root_document["public_key"]),
    )
    roles: set[str] = set()
    for certificate in genesis_document["operational_keys"]:
        verified = _verify_certificate(certificate, issuer=root)
        subject = certificate["subject"]
        assert isinstance(subject, dict)
        role = str(subject["role"])
        if role in roles or role not in OPERATIONAL_ROLES or verified.key_id != subject["key_id"]:
            raise NativeTrustError("native trust operational certificate set is invalid")
        roles.add(role)
    if (
        genesis_document["instance_id"] != expected_instance_id
        or genesis_id != digest_object(genesis_core, domain="native-trust-genesis-v1")
        or root_document["role"] != "instance-root"
        or root_document["fingerprint"] != public_key_fingerprint(root.public_key)
        or root_document["fingerprint"] != expected_root_fingerprint
        or roles != set(OPERATIONAL_ROLES)
    ):
        raise NativeTrustError("native trust public genesis verification failed")

    candidate = deepcopy(dict(enrollment))
    validate("native-release-authority-enrollment", candidate)
    core = deepcopy(candidate)
    core.pop("signature")
    enrollment_id = core.pop("enrollment_id")
    authority = candidate["authority"]
    assert isinstance(authority, dict)
    authority_key = trusted_key_from_value(
        str(authority["key_id"]),
        str(authority["public_key"]),
    )
    if (
        candidate["instance_id"] != expected_instance_id
        or enrollment_id != digest_object(core, domain="native-release-authority-enrollment-v1")
        or candidate["signature"]["key_id"] != root.key_id
        or not verify_signature(candidate, root.public_key)
        or authority["role"] != RELEASE_AUTHORITY_ROLE
        or authority["fingerprint"] != public_key_fingerprint(authority_key.public_key)
    ):
        raise NativeTrustError("native release authority enrollment verification failed")
    return authority_key


def verify_native_database_enrollment(
    enrollment: Mapping[str, object],
    *,
    genesis: Mapping[str, object],
    expected_instance_id: str,
    expected_root_fingerprint: str,
    expected_tenant_id: str | None = None,
    expected_ledger_id: str | None = None,
) -> dict[str, object]:
    """Verify one database enrollment using public, owner-pinned native trust.

    This is the read-only counterpart to :meth:`NativeTrustStore.verify_database`.
    A consumer such as Galaxy can authenticate a database source key without
    being granted access to the native state directory or any private signer.
    """

    genesis_document = deepcopy(dict(genesis))
    validate("native-trust-genesis", genesis_document)
    genesis_core = deepcopy(genesis_document)
    genesis_id = genesis_core.pop("genesis_id")
    root_document = genesis_document["root"]
    assert isinstance(root_document, dict)
    root = trusted_key_from_value(
        str(root_document["key_id"]),
        str(root_document["public_key"]),
    )
    if (
        genesis_document["instance_id"] != expected_instance_id
        or genesis_id != digest_object(genesis_core, domain="native-trust-genesis-v1")
        or root_document["role"] != "instance-root"
        or root_document["fingerprint"] != public_key_fingerprint(root.public_key)
        or root_document["fingerprint"] != expected_root_fingerprint
    ):
        raise NativeTrustError("native trust public genesis verification failed")

    roles: dict[str, TrustedKey] = {}
    for certificate in genesis_document["operational_keys"]:
        verified = _verify_certificate(certificate, issuer=root)
        subject = certificate["subject"]
        assert isinstance(subject, dict)
        role = str(subject["role"])
        if role in roles or role not in OPERATIONAL_ROLES:
            raise NativeTrustError("native trust operational certificate set is invalid")
        roles[role] = verified
    if set(roles) != set(OPERATIONAL_ROLES):
        raise NativeTrustError("native trust operational certificate set is incomplete")

    candidate = deepcopy(dict(enrollment))
    validate("native-database-enrollment", candidate)
    core = deepcopy(candidate)
    core.pop("signature")
    enrollment_id = core.pop("enrollment_id")
    issuer = roles["ledger-issuer"]
    if (
        candidate["instance_id"] != expected_instance_id
        or (expected_tenant_id is not None and candidate["tenant_id"] != expected_tenant_id)
        or (expected_ledger_id is not None and candidate["ledger_id"] != expected_ledger_id)
        or enrollment_id != digest_object(core, domain="native-database-enrollment-v1")
        or candidate["signature"]["key_id"] != issuer.key_id
        or not verify_signature(candidate, issuer.public_key)
    ):
        raise NativeTrustError("native database enrollment verification failed")
    for name in ("source_key", "checkpoint_key"):
        key_document = candidate[name]
        assert isinstance(key_document, dict)
        trusted = trusted_key_from_value(
            str(key_document["key_id"]),
            str(key_document["public_key"]),
        )
        if key_document["fingerprint"] != public_key_fingerprint(trusted.public_key):
            raise NativeTrustError("native database key fingerprint mismatch")
    return candidate


@dataclass(frozen=True)
class NativeDatabaseKeys:
    enrollment: dict[str, object]
    source_signer: Ed25519Signer
    checkpoint_signer: Ed25519Signer

    @property
    def source_key(self) -> TrustedKey:
        return TrustedKey(self.source_signer.key_id, self.source_signer.public_key)

    @property
    def checkpoint_key(self) -> TrustedKey:
        return TrustedKey(self.checkpoint_signer.key_id, self.checkpoint_signer.public_key)


@dataclass(frozen=True)
class NativeReleaseAuthority:
    enrollment: dict[str, object]
    signer: Ed25519Signer

    @property
    def trusted_key(self) -> TrustedKey:
        return TrustedKey(self.signer.key_id, self.signer.public_key)


class NativeTrustStore:
    """One immutable genesis plus issuer-signed child enrollments."""

    def __init__(
        self,
        state_root: Path,
        *,
        instance_id: str,
        profile: str = NATIVE_TRUST_PROFILE,
        backend: SignerBackend | None = None,
    ) -> None:
        if _INSTANCE.fullmatch(instance_id) is None:
            raise NativeTrustError("native Integrity instance id is invalid")
        if profile not in {NATIVE_TRUST_PROFILE, MANAGED_TRUST_PROFILE}:
            raise NativeTrustError("native trust profile is invalid")
        self.state_root = state_root.absolute()
        self.root = self.state_root / "native-trust" / "v1"
        self.instance_id = instance_id
        self.profile = profile
        _ensure_private_directory(self.root)
        self.backend = backend or FileSignerBackend(self.root / "keys")
        self._trusted_keys: dict[str, TrustedKey] = {}
        self.genesis_path = self.root / "genesis.json"
        self.enrollments_root = self.root / "enrollments"
        _ensure_private_directory(self.enrollments_root)

    def _key_id(self, role: str) -> str:
        suffix = self.instance_id.split(":", 1)[1]
        return f"key:{suffix}:{role}"

    def signer(self, role: str, *, create: bool = False) -> Ed25519Signer:
        if role != "instance-root" and role not in OPERATIONAL_ROLES:
            raise NativeTrustError("unknown native trust signer role")
        method = self.backend.ensure_signer if create else self.backend.load_signer
        return method(role, key_id=self._key_id(role))

    def bootstrap(self, *, created_at: str | None = None) -> dict[str, object]:
        """Create or verify one native genesis; never replace existing identity."""

        if self.genesis_path.exists() or self.genesis_path.is_symlink():
            return self.verify_genesis()
        timestamp = created_at or _now()
        _parse_time(timestamp, "genesis time")
        root_signer = self.signer("instance-root", create=True)
        certificates = [
            _certificate(
                self.signer(role, create=True),
                role=role,
                issuer=root_signer,
                created_at=timestamp,
            )
            for role in OPERATIONAL_ROLES
        ]
        core: dict[str, object] = {
            "protocol": NATIVE_TRUST_PROTOCOL,
            "instance_id": self.instance_id,
            "profile": self.profile,
            "backend": self.backend.backend_id,
            "created_at": timestamp,
            "root": _key_document(root_signer, role="instance-root"),
            "operational_keys": certificates,
        }
        document = {
            **core,
            "genesis_id": digest_object(core, domain="native-trust-genesis-v1"),
        }
        _write_document_once(self.genesis_path, document, "native-trust-genesis")
        return self.verify_genesis()

    def verify_genesis(self) -> dict[str, object]:
        self._trusted_keys.clear()
        candidate = _load_document(self.genesis_path, "native-trust-genesis")
        core = deepcopy(candidate)
        genesis_id = core.pop("genesis_id")
        if genesis_id != digest_object(core, domain="native-trust-genesis-v1"):
            raise NativeTrustError("native trust genesis identity mismatch")
        if (
            candidate["instance_id"] != self.instance_id
            or candidate["profile"] != self.profile
            or candidate["backend"] != self.backend.backend_id
        ):
            raise NativeTrustError("native trust genesis belongs to another instance")
        root = candidate["root"]
        assert isinstance(root, dict)
        root_key = trusted_key_from_value(str(root["key_id"]), str(root["public_key"]))
        if root["fingerprint"] != public_key_fingerprint(root_key.public_key):
            raise NativeTrustError("native trust root fingerprint mismatch")
        roles: set[str] = set()
        trusted_keys = {"instance-root": root_key}
        for certificate in candidate["operational_keys"]:
            assert isinstance(certificate, dict)
            key = _verify_certificate(certificate, issuer=root_key)
            subject = certificate["subject"]
            assert isinstance(subject, dict)
            role = str(subject["role"])
            if role in roles or role not in OPERATIONAL_ROLES:
                raise NativeTrustError("native trust operational role set is invalid")
            roles.add(role)
            trusted_keys[role] = key
            signer = self.signer(role)
            if public_key_value(signer.public_key) != public_key_value(key.public_key):
                raise NativeTrustError("native trust private/public custody mismatch")
        if roles != set(OPERATIONAL_ROLES):
            raise NativeTrustError("native trust operational role set is incomplete")
        self._trusted_keys = trusted_keys
        return candidate

    def trusted_key(self, role: str) -> TrustedKey:
        if role not in self._trusted_keys:
            self.verify_genesis()
        try:
            return self._trusted_keys[role]
        except KeyError as exc:
            raise NativeTrustError("native trust role is not enrolled") from exc

    def ensure_database(
        self,
        *,
        tenant_id: str,
        ledger_id: str,
        created_at: str | None = None,
        source_key_id: str | None = None,
        checkpoint_key_id: str | None = None,
    ) -> NativeDatabaseKeys:
        self.verify_genesis()
        identity = hashlib.sha256(f"{tenant_id}\0{ledger_id}".encode()).hexdigest()
        database_id = f"database:{identity}"
        directory = self.enrollments_root / "databases" / identity
        _ensure_private_directory(directory)
        path = directory / "enrollment.json"
        source_role = f"database-{identity[:32]}-source"
        checkpoint_role = f"database-{identity[:32]}-checkpoint"
        existing_enrollment = (
            _load_document(path, "native-database-enrollment")
            if path.exists() or path.is_symlink()
            else None
        )
        if existing_enrollment is not None:
            source_id = str(existing_enrollment["source_key"]["key_id"])
            checkpoint_id = str(existing_enrollment["checkpoint_key"]["key_id"])
            if source_key_id not in {None, source_id} or checkpoint_key_id not in {
                None,
                checkpoint_id,
            }:
                raise NativeTrustError("native database enrollment key identity differs")
        else:
            source_id = source_key_id or f"key:database:{identity}:source"
            checkpoint_id = checkpoint_key_id or f"key:database:{identity}:checkpoint"
        source = self.backend.ensure_signer(source_role, key_id=source_id)
        checkpoint = self.backend.ensure_signer(checkpoint_role, key_id=checkpoint_id)
        if existing_enrollment is not None:
            enrollment = existing_enrollment
        else:
            timestamp = created_at or _now()
            _parse_time(timestamp, "database enrollment time")
            core: dict[str, object] = {
                "protocol": "integrity-guardian/native-database-enrollment/v1",
                "instance_id": self.instance_id,
                "tenant_id": tenant_id,
                "ledger_id": ledger_id,
                "database_id": database_id,
                "source_key": _key_document(source, role="database-source"),
                "checkpoint_key": _key_document(checkpoint, role="database-checkpoint"),
                "created_at": timestamp,
            }
            unsigned = {
                **core,
                "enrollment_id": digest_object(core, domain="native-database-enrollment-v1"),
            }
            enrollment = self.signer("ledger-issuer").sign(unsigned)
            _write_document_once(path, enrollment, "native-database-enrollment")
        self.verify_database(enrollment)
        if (
            enrollment["tenant_id"] != tenant_id
            or enrollment["ledger_id"] != ledger_id
            or enrollment["source_key"]["public_key"] != public_key_value(source.public_key)
            or enrollment["checkpoint_key"]["public_key"] != public_key_value(checkpoint.public_key)
        ):
            raise NativeTrustError("native database key custody mismatch")
        return NativeDatabaseKeys(dict(enrollment), source, checkpoint)

    def migrate_existing_database(
        self,
        *,
        database_path: Path,
        tenant_id: str,
        ledger_id: str,
        source_key_id: str,
        source_seed: bytes,
        checkpoint_key_id: str,
        checkpoint_seed: bytes,
        checkpoint: Mapping[str, object],
        migrated_at: str | None = None,
    ) -> dict[str, object]:
        """Adopt an existing chain with the exact same signing keys and bytes."""

        if not isinstance(self.backend, FileSignerBackend):
            raise NativeTrustError(
                "managed backend migration must be performed by its custody adapter"
            )
        if len(source_seed) != 32 or len(checkpoint_seed) != 32:
            raise NativeTrustError("legacy database signer seed length is invalid")
        source_candidate = Ed25519Signer(
            source_key_id,
            Ed25519PrivateKey.from_private_bytes(source_seed),
        )
        checkpoint_candidate = Ed25519Signer(
            checkpoint_key_id,
            Ed25519PrivateKey.from_private_bytes(checkpoint_seed),
        )
        from .ledger import LedgerStore, LedgerVerificationError

        with LedgerStore(
            database_path,
            tenant_id=tenant_id,
            ledger_id=ledger_id,
        ) as ledger:
            events = ledger.events()
            if not events:
                raise NativeTrustError("empty database uses native trust binding, not migration")
            try:
                verification = ledger.verify(
                    source_public_keys={
                        event["source_id"]: TrustedKey(
                            source_candidate.key_id,
                            source_candidate.public_key,
                        )
                        for event in events
                    },
                    checkpoint=checkpoint,
                    checkpoint_key=TrustedKey(
                        checkpoint_candidate.key_id,
                        checkpoint_candidate.public_key,
                    ),
                )
            except LedgerVerificationError as exc:
                raise NativeTrustError(
                    "existing database verification failed before migration"
                ) from exc
            if not verification["ok"] or not verification["checkpoint_verified"]:
                raise NativeTrustError("existing database verification failed before migration")
            bound = ledger.native_trust_enrollment()
            if bound is not None and (
                bound["source_key"]["key_id"] != source_candidate.key_id
                or bound["source_key"]["public_key"]
                != public_key_value(source_candidate.public_key)
                or bound["checkpoint_key"]["key_id"] != checkpoint_candidate.key_id
                or bound["checkpoint_key"]["public_key"]
                != public_key_value(checkpoint_candidate.public_key)
            ):
                raise NativeTrustError("existing native database enrollment uses other keys")

        identity = hashlib.sha256(f"{tenant_id}\0{ledger_id}".encode()).hexdigest()
        source_role = f"database-{identity[:32]}-source"
        checkpoint_role = f"database-{identity[:32]}-checkpoint"
        self.backend.import_seed(
            source_role,
            key_id=source_key_id,
            seed=source_seed,
        )
        self.backend.import_seed(
            checkpoint_role,
            key_id=checkpoint_key_id,
            seed=checkpoint_seed,
        )
        keys = self.ensure_database(
            tenant_id=tenant_id,
            ledger_id=ledger_id,
            created_at=migrated_at,
            source_key_id=source_key_id,
            checkpoint_key_id=checkpoint_key_id,
        )
        with LedgerStore(
            database_path,
            tenant_id=tenant_id,
            ledger_id=ledger_id,
        ) as ledger:
            migration = ledger.migrate_native_trust(
                keys.enrollment,
                issuer_key=self.trusted_key("ledger-issuer"),
                source_key=keys.source_key,
                checkpoint=checkpoint,
                checkpoint_key=keys.checkpoint_key,
            )
        directory = self.enrollments_root / "databases" / identity
        migration_path = directory / "migration.json"
        if migration_path.exists() or migration_path.is_symlink():
            receipt = _load_document(
                migration_path,
                "native-database-migration-receipt",
            )
            verified = self._verify_enrollment(
                receipt,
                schema="native-database-migration-receipt",
                id_field="receipt_id",
                domain="native-database-migration-receipt-v1",
                issuer_role="ledger-issuer",
            )
            if (
                verified["enrollment_id"] != migration["enrollment_id"]
                or verified["previous_checkpoint_digest"] != migration["previous_checkpoint_digest"]
                or verified["event_count"] != migration["event_count"]
                or verified["tree_size"] != migration["tree_size"]
            ):
                raise NativeTrustError("native database migration receipt differs")
            return verified
        timestamp = migrated_at or _now()
        core: dict[str, object] = {
            "protocol": "integrity-guardian/native-database-migration-receipt/v1",
            "instance_id": self.instance_id,
            "database_id": keys.enrollment["database_id"],
            "enrollment_id": migration["enrollment_id"],
            "previous_checkpoint_digest": migration["previous_checkpoint_digest"],
            "event_count": migration["event_count"],
            "tree_size": migration["tree_size"],
            "history_rewritten": False,
            "migrated_at": timestamp,
        }
        unsigned = {
            **core,
            "receipt_id": digest_object(core, domain="native-database-migration-receipt-v1"),
        }
        receipt = self.signer("ledger-issuer").sign(unsigned)
        _write_document_once(
            migration_path,
            receipt,
            "native-database-migration-receipt",
        )
        return receipt

    def verify_database(self, enrollment: Mapping[str, object]) -> dict[str, object]:
        candidate = deepcopy(dict(enrollment))
        validate("native-database-enrollment", candidate)
        core = deepcopy(candidate)
        core.pop("signature")
        enrollment_id = core.pop("enrollment_id")
        issuer = self.trusted_key("ledger-issuer")
        if (
            candidate["instance_id"] != self.instance_id
            or enrollment_id != digest_object(core, domain="native-database-enrollment-v1")
            or candidate["signature"]["key_id"] != issuer.key_id
            or not verify_signature(candidate, issuer.public_key)
        ):
            raise NativeTrustError("native database enrollment verification failed")
        for name in ("source_key", "checkpoint_key"):
            key = candidate[name]
            assert isinstance(key, dict)
            trusted = trusted_key_from_value(str(key["key_id"]), str(key["public_key"]))
            if key["fingerprint"] != public_key_fingerprint(trusted.public_key):
                raise NativeTrustError("native database key fingerprint mismatch")
        return candidate

    def verify_release_authority(
        self,
        enrollment: Mapping[str, object],
    ) -> dict[str, object]:
        """Verify one root-signed, manifest-only release authority enrollment."""

        candidate = deepcopy(dict(enrollment))
        validate("native-release-authority-enrollment", candidate)
        core = deepcopy(candidate)
        core.pop("signature")
        enrollment_id = core.pop("enrollment_id")
        root = self.trusted_key("instance-root")
        authority = candidate["authority"]
        assert isinstance(authority, dict)
        authority_key = trusted_key_from_value(
            str(authority["key_id"]),
            str(authority["public_key"]),
        )
        if (
            candidate["instance_id"] != self.instance_id
            or enrollment_id != digest_object(core, domain="native-release-authority-enrollment-v1")
            or candidate["signature"]["key_id"] != root.key_id
            or not verify_signature(candidate, root.public_key)
            or authority["role"] != RELEASE_AUTHORITY_ROLE
            or authority["fingerprint"] != public_key_fingerprint(authority_key.public_key)
        ):
            raise NativeTrustError("native release authority enrollment verification failed")
        return candidate

    def release_authority(self) -> NativeReleaseAuthority:
        """Load an existing release authority without creating key material."""

        self.verify_genesis()
        path = self.enrollments_root / RELEASE_AUTHORITY_ROLE / "enrollment.json"
        enrollment = self.verify_release_authority(
            _load_document(path, "native-release-authority-enrollment")
        )
        signer = self.backend.load_signer(
            RELEASE_AUTHORITY_ROLE,
            key_id=str(enrollment["authority"]["key_id"]),
        )
        if public_key_value(signer.public_key) != enrollment["authority"]["public_key"]:
            raise NativeTrustError("native release authority custody mismatch")
        return NativeReleaseAuthority(dict(enrollment), signer)

    def ensure_release_authority(
        self,
        *,
        created_at: str | None = None,
    ) -> NativeReleaseAuthority:
        """Create one durable child authority or verify the existing identity."""

        self.verify_genesis()
        directory = self.enrollments_root / RELEASE_AUTHORITY_ROLE
        _ensure_private_directory(directory)
        path = directory / "enrollment.json"
        if path.exists() or path.is_symlink():
            return self.release_authority()
        timestamp = created_at or _now()
        _parse_time(timestamp, "release authority enrollment time")
        signer = self.backend.ensure_signer(
            RELEASE_AUTHORITY_ROLE,
            key_id=self._key_id(RELEASE_AUTHORITY_ROLE),
        )
        core: dict[str, object] = {
            "protocol": "integrity-guardian/native-release-authority-enrollment/v1",
            "instance_id": self.instance_id,
            "authority": _key_document(signer, role=RELEASE_AUTHORITY_ROLE),
            "created_at": timestamp,
            "controls": {
                "manifest_signing_only": True,
                "production_authority": False,
                "memory_grants_authority": False,
            },
        }
        unsigned = {
            **core,
            "enrollment_id": digest_object(
                core,
                domain="native-release-authority-enrollment-v1",
            ),
        }
        enrollment = self.signer("instance-root").sign(unsigned)
        _write_document_once(
            path,
            enrollment,
            "native-release-authority-enrollment",
        )
        return self.release_authority()

    def enroll_device(
        self,
        *,
        device_id: str,
        public_key: str,
        scopes: Sequence[str],
        created_at: str | None = None,
    ) -> dict[str, object]:
        if _DEVICE.fullmatch(device_id) is None:
            raise NativeTrustError("native device id is invalid")
        trusted_key_from_value(f"key:{device_id}:identity", public_key)
        scope_set = _validate_device_scopes(scopes)
        identity = hashlib.sha256(device_id.encode()).hexdigest()
        path = self.enrollments_root / "devices" / f"{identity}.json"
        if path.exists() or path.is_symlink():
            existing = self.load_device(device_id)
            if existing["public_key"] != public_key or tuple(existing["scopes"]) != scope_set:
                raise NativeTrustError("existing native device enrollment differs")
            return existing
        timestamp = created_at or _now()
        core: dict[str, object] = {
            "protocol": "integrity-guardian/native-device-enrollment/v1",
            "instance_id": self.instance_id,
            "device_id": device_id,
            "public_key": public_key,
            "scopes": list(scope_set),
            "created_at": timestamp,
        }
        unsigned = {
            **core,
            "enrollment_id": digest_object(core, domain="native-device-enrollment-v1"),
        }
        enrollment = self.signer("device-issuer").sign(unsigned)
        _write_document_once(path, enrollment, "native-device-enrollment")
        return self.verify_device(enrollment)

    def enroll_device_request(
        self,
        request: Mapping[str, object],
    ) -> dict[str, object]:
        """Enroll a device only after its signed proof-of-possession request."""

        verified = verify_native_device_request(request)
        if verified["instance_id"] != self.instance_id:
            raise NativeTrustError("native device request belongs to another instance")
        return self.enroll_device(
            device_id=str(verified["device_id"]),
            public_key=str(verified["public_key"]),
            scopes=verified["scopes"],
            created_at=str(verified["created_at"]),
        )

    def ensure_local_transport_device(
        self,
        *,
        device_id: str,
        scopes: Sequence[str] = DEFAULT_DEVICE_SCOPES,
        created_at: str | None = None,
    ) -> dict[str, object]:
        """Create the first local transport identity without operator key files.

        Remote machines use ``enroll_device`` with a public key generated on
        that machine.  This helper is only for the initial same-machine or
        forced-command transport adapter.
        """

        if _DEVICE.fullmatch(device_id) is None:
            raise NativeTrustError("native device id is invalid")
        scope_set = _validate_device_scopes(scopes)
        identity = hashlib.sha256(device_id.encode()).hexdigest()
        path = self.enrollments_root / "devices" / f"{identity}.json"
        role = f"transport-device-{identity[:32]}"
        signer = self.backend.ensure_signer(
            role,
            key_id=f"key:device:{identity}:transport",
        )
        if path.exists() or path.is_symlink():
            enrollment = self.load_device(device_id)
            if enrollment["public_key"] != public_key_value(signer.public_key):
                raise NativeTrustError("native transport device custody mismatch")
            if tuple(enrollment["scopes"]) != scope_set:
                raise NativeTrustError("native transport device scope differs")
            return enrollment
        return self.enroll_device(
            device_id=device_id,
            public_key=public_key_value(signer.public_key),
            scopes=scope_set,
            created_at=created_at,
        )

    def verify_device(self, enrollment: Mapping[str, object]) -> dict[str, object]:
        return self._verify_enrollment(
            enrollment,
            schema="native-device-enrollment",
            id_field="enrollment_id",
            domain="native-device-enrollment-v1",
            issuer_role="device-issuer",
        )

    def load_device(self, device_id: str) -> dict[str, object]:
        identity = hashlib.sha256(device_id.encode()).hexdigest()
        return self.verify_device(
            _load_document(
                self.enrollments_root / "devices" / f"{identity}.json",
                "native-device-enrollment",
            )
        )

    def enroll_module(
        self,
        *,
        module_id: str,
        artifact_digest: str,
        scopes: Sequence[str],
        created_at: str | None = None,
    ) -> dict[str, object]:
        if _MODULE.fullmatch(module_id) is None or _DIGEST.fullmatch(artifact_digest) is None:
            raise NativeTrustError("native module identity is invalid")
        scope_set = _validate_module_scopes(scopes)
        identity = hashlib.sha256(module_id.encode()).hexdigest()
        path = self.enrollments_root / "modules" / f"{identity}.json"
        if path.exists() or path.is_symlink():
            existing = self.load_module(module_id)
            if (
                existing["artifact_digest"] != artifact_digest
                or tuple(existing["scopes"]) != scope_set
            ):
                raise NativeTrustError("existing native module enrollment differs")
            return existing
        timestamp = created_at or _now()
        core: dict[str, object] = {
            "protocol": "integrity-guardian/native-module-enrollment/v1",
            "instance_id": self.instance_id,
            "module_id": module_id,
            "artifact_digest": artifact_digest,
            "scopes": list(scope_set),
            "created_at": timestamp,
        }
        unsigned = {
            **core,
            "enrollment_id": digest_object(core, domain="native-module-enrollment-v1"),
        }
        enrollment = self.signer("module-issuer").sign(unsigned)
        _write_document_once(path, enrollment, "native-module-enrollment")
        return self._verify_enrollment(
            enrollment,
            schema="native-module-enrollment",
            id_field="enrollment_id",
            domain="native-module-enrollment-v1",
            issuer_role="module-issuer",
        )

    def load_module(self, module_id: str) -> dict[str, object]:
        identity = hashlib.sha256(module_id.encode()).hexdigest()
        return self._verify_enrollment(
            _load_document(
                self.enrollments_root / "modules" / f"{identity}.json",
                "native-module-enrollment",
            ),
            schema="native-module-enrollment",
            id_field="enrollment_id",
            domain="native-module-enrollment-v1",
            issuer_role="module-issuer",
        )

    def _verify_enrollment(
        self,
        enrollment: Mapping[str, object],
        *,
        schema: str,
        id_field: str,
        domain: str,
        issuer_role: str,
    ) -> dict[str, object]:
        candidate = deepcopy(dict(enrollment))
        validate(schema, candidate)
        core = deepcopy(candidate)
        core.pop("signature")
        identity = core.pop(id_field)
        issuer = self.trusted_key(issuer_role)
        if (
            candidate["instance_id"] != self.instance_id
            or identity != digest_object(core, domain=domain)
            or candidate["signature"]["key_id"] != issuer.key_id
            or not verify_signature(candidate, issuer.public_key)
        ):
            raise NativeTrustError("native enrollment verification failed")
        return candidate

    def open_session(
        self,
        *,
        device_id: str,
        scopes: Sequence[str],
        issued_at: str | None = None,
        ttl_seconds: int = 8 * 60 * 60,
        idempotency_key: str | None = None,
    ) -> dict[str, object]:
        """Issue one cached lease after the transport adapter authenticated a device."""

        if not 60 <= ttl_seconds <= 24 * 60 * 60:
            raise NativeTrustError("native session lease lifetime is invalid")
        if idempotency_key is not None and not _DIGEST.fullmatch(idempotency_key):
            raise NativeTrustError("native session idempotency key is invalid")
        device = self.load_device(device_id)
        requested = _validate_scopes(scopes)
        if not set(requested).issubset(device["scopes"]):
            raise NativeTrustError("native session requests unenrolled scope")
        start_text = issued_at or _now()
        start = _parse_time(start_text, "session start")
        end_text = (start + timedelta(seconds=ttl_seconds)).isoformat().replace("+00:00", "Z")
        nonce = (
            hashlib.sha256(
                b"integrity-native-session-idempotency-v1\0"
                + idempotency_key.encode()
                + b"\0"
                + self.instance_id.encode()
                + b"\0"
                + device_id.encode()
                + b"\0"
                + canonical_bytes(
                    {
                        "scopes": list(requested),
                        "ttl_seconds": ttl_seconds,
                    }
                )
            ).digest()
            if idempotency_key is not None
            else os.urandom(32)
        )
        session_id = (
            "session:"
            + hashlib.sha256(nonce + device_id.encode() + start_text.encode()).hexdigest()
        )
        core: dict[str, object] = {
            "protocol": "integrity-guardian/native-session-lease/v1",
            "instance_id": self.instance_id,
            "session_id": session_id,
            "device_id": device_id,
            "scopes": list(requested),
            "issued_at": start_text,
            "expires_at": end_text,
        }
        unsigned = {
            **core,
            "lease_id": digest_object(core, domain="native-session-lease-v1"),
        }
        lease = self.signer("session-issuer").sign(unsigned)
        return self.verify_session(lease, at_time=start_text)

    def verify_session(
        self,
        lease: Mapping[str, object],
        *,
        at_time: str | None = None,
        required_scope: str | None = None,
    ) -> dict[str, object]:
        candidate = self._verify_enrollment(
            lease,
            schema="native-session-lease",
            id_field="lease_id",
            domain="native-session-lease-v1",
            issuer_role="session-issuer",
        )
        current = _parse_time(at_time or _now(), "session evaluation time")
        if (
            not _parse_time(str(candidate["issued_at"]), "session start")
            <= current
            < _parse_time(str(candidate["expires_at"]), "session expiry")
        ):
            raise NativeTrustError("native session lease is not active")
        device = self.load_device(str(candidate["device_id"]))
        if not set(candidate["scopes"]).issubset(device["scopes"]):
            raise NativeTrustError("native session exceeds current device enrollment")
        if required_scope is not None and required_scope not in candidate["scopes"]:
            raise NativeTrustError("native session lacks required scope")
        return candidate

    def issue_event_append_decision(
        self,
        *,
        session_lease: Mapping[str, object],
        architecture_admission_id: str,
        security_admission_id: str,
        request_digest: str,
        at_time: str | None = None,
        context_admission_id: str | None = None,
        logical_generation: int | None = None,
    ) -> dict[str, object]:
        """Create the existing one-use decision internally, not as a caller token."""

        current_text = at_time or _now()
        current = _parse_time(current_text, "append decision time")
        self.verify_session(
            session_lease,
            at_time=current_text,
            required_scope="memory.append",
        )
        valid_until = (current + timedelta(minutes=5)).isoformat().replace("+00:00", "Z")
        return build_medor_event_append_decision(
            architecture_admission_id=architecture_admission_id,
            security_admission_id=security_admission_id,
            request_digest=request_digest,
            valid_from=current_text,
            valid_until=valid_until,
            authority_signer=self.signer("event-append-issuer"),
            context_admission_id=context_admission_id,
            logical_generation=logical_generation,
        )

    def security_admission(
        self,
        *,
        artifact_digest: str,
        issued_at: str | None = None,
        ttl_seconds: int = 24 * 60 * 60,
    ) -> VerifiedMedorSecurityAdmission:
        """Build and verify a short-lived local admission for one exact artifact."""

        if _DIGEST.fullmatch(artifact_digest) is None:
            raise NativeTrustError("native security artifact digest is invalid")
        if not 60 <= ttl_seconds <= 7 * 24 * 60 * 60:
            raise NativeTrustError("native security admission lifetime is invalid")
        start_text = issued_at or _now()
        start = _parse_time(start_text, "security admission start")
        end_text = (start + timedelta(seconds=ttl_seconds)).isoformat().replace("+00:00", "Z")
        signer = self.signer("security-issuer")
        document = build_native_medor_security_admission(
            instance_id=self.instance_id,
            artifact_digest=artifact_digest,
            issued_at=start_text,
            expires_at=end_text,
            security_signer=signer,
        )
        return verify_native_medor_security_admission(
            document,
            expected_instance_id=self.instance_id,
            expected_artifact_digest=artifact_digest,
            at_time=start_text,
            security_key=self.trusted_key("security-issuer"),
        )


__all__ = [
    "ALL_NATIVE_SCOPES",
    "DEFAULT_DEVICE_SCOPES",
    "MANAGED_TRUST_PROFILE",
    "NATIVE_TRUST_PROFILE",
    "ExternalSignerBackend",
    "FileSignerBackend",
    "NativeDatabaseKeys",
    "NativeTrustError",
    "NativeTrustStore",
    "SignerBackend",
    "initialize_native_device_request",
    "load_ed25519_seed",
    "verify_native_database_enrollment",
    "verify_native_device_request",
]
