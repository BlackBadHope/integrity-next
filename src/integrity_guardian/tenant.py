"""Customer-local tenant namespace and isolation primitives.

The workspace owns only Guardian state under a caller-selected local root. It
does not discover customer systems, open a network connection, or hold
production credentials.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes, parse_json_strict
from .governance import governance_bundle_digest
from .hashing import digest_object
from .policy import verify_customer_policy_binding
from .retention import verify_retention_policy
from .schemas import validate
from .signing import TrustedKey

TENANT_ID = re.compile(r"^tenant:[a-z0-9][a-z0-9._-]{0,63}$")
ARTIFACT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
STATE_KINDS = frozenset({"ledger", "checkpoints", "receipts", "reports"})


class TenantIsolationError(ValueError):
    """Raised before a tenant boundary can be crossed or weakened."""


def validate_tenant_id(tenant_id: str) -> str:
    if TENANT_ID.fullmatch(tenant_id) is None:
        raise TenantIsolationError(
            "tenant_id is outside the canonical profile; expected "
            "tenant:<lowercase-name> matching "
            "^tenant:[a-z0-9][a-z0-9._-]{0,63}$ "
            "(example: tenant:public-230ac094c6cd4921)"
        )
    return tenant_id


def tenant_namespace(tenant_id: str) -> str:
    """Return an opaque filesystem namespace that cannot contain path syntax."""

    validate_tenant_id(tenant_id)
    digest = hashlib.sha256(
        b"integrity-guardian\x00tenant-namespace-v1\x00" + tenant_id.encode("utf-8")
    ).hexdigest()
    return digest


def build_tenant_profile(
    *,
    tenant_id: str,
    deployment_id: str,
    retention_policy_digest: str,
    key_registry_digest: str,
    created_at: str,
) -> dict[str, Any]:
    zero_digest = "sha256:" + "0" * 64
    if retention_policy_digest == zero_digest or key_registry_digest == zero_digest:
        raise TenantIsolationError(
            "zero digest is not enrollment; use an explicit unenrolled profile"
        )
    profile = {
        "protocol": "integrity-guardian/tenant-profile/v3",
        "tenant_id": validate_tenant_id(tenant_id),
        "deployment_id": deployment_id,
        "namespace": tenant_namespace(tenant_id),
        "enrollment": {
            "retention_policy": {
                "status": "PRESENT_UNVERIFIED",
                "digest": retention_policy_digest,
            },
            "key_registry": {
                "status": "PRESENT_UNVERIFIED",
                "digest": key_registry_digest,
            },
        },
        "governance": {
            "product_bundle": {
                "status": "VERIFIED",
                "digest": governance_bundle_digest(),
            },
            "customer_policy": {"status": "UNENROLLED"},
        },
        "created_at": created_at,
        "controls": {
            "customer_local": True,
            "guardian_has_production_credentials": False,
            "network_service_required": False,
            "cross_tenant_access": False,
        },
    }
    validate("tenant-profile", profile)
    return profile


def build_unenrolled_tenant_profile(
    *,
    tenant_id: str,
    deployment_id: str,
    created_at: str,
) -> dict[str, Any]:
    """Build an explicit UNKNOWN initial state without magic digest values."""

    profile = {
        "protocol": "integrity-guardian/tenant-profile/v3",
        "tenant_id": validate_tenant_id(tenant_id),
        "deployment_id": deployment_id,
        "namespace": tenant_namespace(tenant_id),
        "enrollment": {
            "retention_policy": {"status": "UNENROLLED"},
            "key_registry": {"status": "UNENROLLED"},
        },
        "governance": {
            "product_bundle": {
                "status": "VERIFIED",
                "digest": governance_bundle_digest(),
            },
            "customer_policy": {"status": "UNENROLLED"},
        },
        "created_at": created_at,
        "controls": {
            "customer_local": True,
            "guardian_has_production_credentials": False,
            "network_service_required": False,
            "cross_tenant_access": False,
        },
    }
    validate("tenant-profile", profile)
    return profile


def build_operational_tenant_profile(
    *,
    tenant_id: str,
    deployment_id: str,
    retention_policy: dict[str, Any],
    retention_authority_key: TrustedKey,
    key_registry_transitions: Sequence[dict[str, Any]],
    key_registry_authority_key: TrustedKey,
    customer_policy_binding: dict[str, Any],
    policy_authority_key: TrustedKey,
    created_at: str,
    at_time: str,
) -> dict[str, Any]:
    """Build v4 only after independent policy and key-registry verification."""

    retention_policy_digest = verify_retention_policy(
        retention_policy,
        authority_key=retention_authority_key,
        expected_tenant_id=tenant_id,
        now=at_time,
    )
    if not key_registry_transitions:
        raise TenantIsolationError("tenant key registry evidence is absent")
    from .key_lifecycle import (
        KeyLifecycleState,
        apply_key_transition,
        trusted_active_key,
    )

    state = KeyLifecycleState(tenant_id, "authority")
    verified_transitions: list[dict[str, Any]] = []
    for transition in key_registry_transitions:
        state = apply_key_transition(
            state,
            transition,
            authority_key=key_registry_authority_key,
        )
        verified_transitions.append(transition)
    trusted_active_key(state, at=at_time)
    key_registry_digest = digest_object(
        verified_transitions,
        domain="tenant-key-registry-reference-v1",
    )

    base = build_tenant_profile(
        tenant_id=tenant_id,
        deployment_id=deployment_id,
        retention_policy_digest=retention_policy_digest,
        key_registry_digest=key_registry_digest,
        created_at=created_at,
    )
    verify_customer_policy_binding(
        customer_policy_binding,
        tenant_id=tenant_id,
        authority_key=policy_authority_key,
        at_time=at_time,
    )
    base["protocol"] = "integrity-guardian/tenant-profile/v4"
    base["enrollment"] = {
        "retention_policy": {
            "status": "ENROLLED",
            "digest": retention_policy_digest,
        },
        "key_registry": {
            "status": "ENROLLED",
            "digest": key_registry_digest,
        },
    }
    base["governance"]["customer_policy"] = {
        "status": "BOUND",
        "binding": customer_policy_binding,
    }
    validate("tenant-profile", base)
    return base


def tenant_enrollment_status(profile: dict[str, Any]) -> str:
    """Return ENROLLED only when both trust registries are actually enrolled."""

    if profile["protocol"] == "integrity-guardian/tenant-profile/v1":
        zero_digest = "sha256:" + "0" * 64
        return (
            "UNENROLLED"
            if zero_digest
            in {
                profile["retention_policy_digest"],
                profile["key_registry_digest"],
            }
            else "PRESENT_UNVERIFIED"
        )
    enrollment = profile["enrollment"]
    statuses = {
        enrollment["retention_policy"]["status"],
        enrollment["key_registry"]["status"],
    }
    if statuses == {"ENROLLED"}:
        return "ENROLLED"
    if "PRESENT_UNVERIFIED" in statuses:
        return "PRESENT_UNVERIFIED"
    return "UNENROLLED"


def verify_tenant_governance(
    profile: dict[str, Any],
    *,
    policy_authority_key: TrustedKey | None = None,
    at_time: str | None = None,
) -> dict[str, str]:
    """Require the tenant to bind the exact installed governance bundle."""

    try:
        validate("tenant-profile", profile)
    except Exception as exc:
        raise TenantIsolationError("tenant profile schema rejected") from exc
    if profile["namespace"] != tenant_namespace(profile["tenant_id"]):
        raise TenantIsolationError("tenant profile namespace mismatch")
    if profile["protocol"] in {
        "integrity-guardian/tenant-profile/v1",
        "integrity-guardian/tenant-profile/v2",
    }:
        raise TenantIsolationError("legacy tenant profile has no governance binding")
    expected = governance_bundle_digest()
    governance = profile["governance"]
    product = governance["product_bundle"]
    if product["status"] != "VERIFIED" or product["digest"] != expected:
        raise TenantIsolationError("tenant governance bundle mismatch")
    customer_policy = governance["customer_policy"]["status"]
    customer_policy_digest: str | None = None
    if customer_policy == "UNENROLLED":
        pass
    elif customer_policy == "BOUND":
        if policy_authority_key is None or at_time is None:
            customer_policy = "PRESENT_UNVERIFIED"
        else:
            verification = verify_customer_policy_binding(
                governance["customer_policy"]["binding"],
                tenant_id=profile["tenant_id"],
                authority_key=policy_authority_key,
                at_time=at_time,
            )
            customer_policy = "VERIFIED"
            customer_policy_digest = verification["policy_digest"]
    else:
        raise TenantIsolationError("tenant customer policy state is not recognized")
    result = {
        "product_bundle": "BOUND",
        "product_bundle_digest": expected,
        "customer_policy": customer_policy,
    }
    if customer_policy_digest is not None:
        result["customer_policy_digest"] = customer_policy_digest
    return result


def _directory_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _assert_owned_private(
    descriptor: int,
    *,
    name: str,
    directory: bool,
    exact_mode: int,
) -> os.stat_result:
    details = os.fstat(descriptor)
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected_type(details.st_mode):
        expected = "directory" if directory else "file"
        raise TenantIsolationError(f"required {expected} is unsafe: {name}")
    if details.st_uid != os.geteuid():
        raise TenantIsolationError(f"tenant state owner mismatch: {name}")
    if stat.S_IMODE(details.st_mode) != exact_mode:
        raise TenantIsolationError(f"tenant state mode mismatch: {name}")
    return details


def _open_root(path: Path, *, create: bool) -> int:
    if create:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, _directory_flags())
    except OSError as exc:
        raise TenantIsolationError(
            f"symlink or unsafe state root is prohibited: {path.name}"
        ) from exc
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISDIR(details.st_mode):
            raise TenantIsolationError("state_root must be a real directory")
        if details.st_uid != os.geteuid():
            raise TenantIsolationError("state_root owner mismatch")
        if create:
            os.fchmod(descriptor, 0o700)
        _assert_owned_private(
            descriptor,
            name=path.name,
            directory=True,
            exact_mode=0o700,
        )
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _open_private_child(parent: int, name: str, *, create: bool) -> int:
    if create:
        try:
            os.mkdir(name, 0o700, dir_fd=parent)
        except FileExistsError:
            pass
    try:
        descriptor = os.open(name, _directory_flags(), dir_fd=parent)
    except OSError as exc:
        raise TenantIsolationError(f"symlink or unsafe directory is prohibited: {name}") from exc
    try:
        if create:
            os.fchmod(descriptor, 0o700)
        _assert_owned_private(
            descriptor,
            name=name,
            directory=True,
            exact_mode=0o700,
        )
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _read_descriptor(descriptor: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    while chunk := os.read(descriptor, 64 * 1024):
        chunks.append(chunk)
    return b"".join(chunks)


@dataclass(frozen=True)
class TenantWorkspace:
    """One isolated namespace inside a customer-owned Guardian state root."""

    state_root: Path
    tenant_id: str

    def __post_init__(self) -> None:
        validate_tenant_id(self.tenant_id)
        if not self.state_root.is_absolute():
            raise TenantIsolationError("state_root must be absolute")

    @property
    def namespace(self) -> str:
        return tenant_namespace(self.tenant_id)

    @property
    def tenant_root(self) -> Path:
        return self.state_root / "tenants" / self.namespace

    @property
    def profile_path(self) -> Path:
        return self.tenant_root / "tenant.json"

    def initialize(self, profile: dict[str, Any]) -> None:
        """Create an empty, private, customer-local workspace.

        Initialization is idempotent only for byte-identical identity metadata.
        Existing non-matching bytes fail closed.
        """

        validate("tenant-profile", profile)
        if (
            profile["tenant_id"] != self.tenant_id
            or profile["namespace"] != self.namespace
        ):
            raise TenantIsolationError("tenant profile identity mismatch")
        if os.name == "nt":
            from .tenant_windows_custody import (
                WindowsTenantCustodyError,
                initialize_windows_workspace,
            )

            try:
                initialize_windows_workspace(self, profile)
            except WindowsTenantCustodyError as exc:
                raise TenantIsolationError(str(exc)) from exc
            return

        root_descriptor = _open_root(self.state_root, create=True)
        tenants_descriptor = tenant_descriptor = profile_descriptor = None
        try:
            tenants_descriptor = _open_private_child(
                root_descriptor,
                "tenants",
                create=True,
            )
            tenant_descriptor = _open_private_child(
                tenants_descriptor,
                self.namespace,
                create=True,
            )

            expected = canonical_bytes(profile) + b"\n"
            flags = os.O_RDWR
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                profile_descriptor = os.open(
                    "tenant.json",
                    flags,
                    dir_fd=tenant_descriptor,
                )
            except FileNotFoundError:
                profile_descriptor = os.open(
                    "tenant.json",
                    flags | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=tenant_descriptor,
                )
                view = memoryview(expected)
                while view:
                    written = os.write(profile_descriptor, view)
                    if written <= 0:
                        raise TenantIsolationError(
                            "tenant profile write made no progress"
                        )
                    view = view[written:]
                os.fsync(profile_descriptor)
            if _read_descriptor(profile_descriptor) != expected:
                raise TenantIsolationError("existing tenant profile does not match")
            os.fchmod(profile_descriptor, 0o600)
            _assert_owned_private(
                profile_descriptor,
                name="tenant.json",
                directory=False,
                exact_mode=0o600,
            )

            for kind in sorted(STATE_KINDS):
                child = _open_private_child(tenant_descriptor, kind, create=True)
                os.close(child)
        finally:
            if profile_descriptor is not None:
                os.close(profile_descriptor)
            if tenant_descriptor is not None:
                os.close(tenant_descriptor)
            if tenants_descriptor is not None:
                os.close(tenants_descriptor)
            os.close(root_descriptor)

    def verify(self) -> dict[str, Any]:
        """Verify identity, layout, ownership mode and absence of symlinks."""

        if os.name == "nt":
            from .tenant_windows_custody import (
                WindowsTenantCustodyError,
                verify_windows_workspace,
            )

            try:
                return verify_windows_workspace(self)
            except WindowsTenantCustodyError as exc:
                raise TenantIsolationError(str(exc)) from exc

        root_descriptor = _open_root(self.state_root, create=False)
        tenants_descriptor = tenant_descriptor = profile_descriptor = None
        try:
            tenants_descriptor = _open_private_child(
                root_descriptor,
                "tenants",
                create=False,
            )
            tenant_descriptor = _open_private_child(
                tenants_descriptor,
                self.namespace,
                create=False,
            )
            flags = os.O_RDONLY
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                profile_descriptor = os.open(
                    "tenant.json",
                    flags,
                    dir_fd=tenant_descriptor,
                )
            except OSError as exc:
                raise TenantIsolationError("tenant profile is absent or unsafe") from exc
            _assert_owned_private(
                profile_descriptor,
                name="tenant.json",
                directory=False,
                exact_mode=0o600,
            )
            profile = parse_json_strict(_read_descriptor(profile_descriptor))
            validate("tenant-profile", profile)
            if (
                profile["tenant_id"] != self.tenant_id
                or profile["namespace"] != self.namespace
            ):
                raise TenantIsolationError("tenant profile identity mismatch")
            for kind in STATE_KINDS:
                child = _open_private_child(tenant_descriptor, kind, create=False)
                os.close(child)
            return profile
        finally:
            if profile_descriptor is not None:
                os.close(profile_descriptor)
            if tenant_descriptor is not None:
                os.close(tenant_descriptor)
            if tenants_descriptor is not None:
                os.close(tenants_descriptor)
            os.close(root_descriptor)

    def audit(self, *, expected_windows_owner_sid: str) -> dict[str, Any]:
        """Audit Windows custody without granting the auditor owner authority.

        Normal ``verify`` remains bound to the current principal.  This method
        is deliberately read-only and requires the expected owner SID as an
        external input so an administrator or assessor cannot silently treat
        itself as the tenant owner.
        """

        if os.name != "nt":
            raise TenantIsolationError(
                "cross-principal tenant audit is available only on Windows"
            )
        from .tenant_windows_custody import (
            WindowsTenantCustodyError,
            audit_windows_workspace,
        )

        try:
            return audit_windows_workspace(
                self,
                expected_owner_sid=expected_windows_owner_sid,
            )
        except WindowsTenantCustodyError as exc:
            raise TenantIsolationError(str(exc)) from exc

    def open_artifact(
        self,
        kind: str,
        name: str,
        *,
        flags: int = os.O_RDONLY,
        mode: int = 0o600,
    ) -> int:
        """Open a tenant artifact relative to verified directory descriptors."""

        if kind not in STATE_KINDS:
            raise TenantIsolationError("unknown tenant state class")
        if ARTIFACT_NAME.fullmatch(name) is None:
            raise TenantIsolationError("artifact name is outside the safe profile")
        if os.name == "nt":
            from .tenant_windows_custody import (
                WindowsTenantCustodyError,
                open_windows_artifact,
            )

            try:
                return open_windows_artifact(
                    self,
                    kind,
                    name,
                    flags=flags,
                )
            except WindowsTenantCustodyError as exc:
                raise TenantIsolationError(str(exc)) from exc
        root_descriptor = _open_root(self.state_root, create=False)
        tenants_descriptor = tenant_descriptor = kind_descriptor = None
        try:
            tenants_descriptor = _open_private_child(
                root_descriptor,
                "tenants",
                create=False,
            )
            tenant_descriptor = _open_private_child(
                tenants_descriptor,
                self.namespace,
                create=False,
            )
            kind_descriptor = _open_private_child(
                tenant_descriptor,
                kind,
                create=False,
            )
            safe_flags = flags
            if hasattr(os, "O_CLOEXEC"):
                safe_flags |= os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                safe_flags |= os.O_NOFOLLOW
            descriptor = os.open(name, safe_flags, mode, dir_fd=kind_descriptor)
            details = os.fstat(descriptor)
            if not stat.S_ISREG(details.st_mode) or details.st_uid != os.geteuid():
                os.close(descriptor)
                raise TenantIsolationError("tenant artifact is not an owned regular file")
            return descriptor
        except OSError as exc:
            raise TenantIsolationError("tenant artifact path is unsafe") from exc
        finally:
            if kind_descriptor is not None:
                os.close(kind_descriptor)
            if tenant_descriptor is not None:
                os.close(tenant_descriptor)
            if tenants_descriptor is not None:
                os.close(tenants_descriptor)
            os.close(root_descriptor)
