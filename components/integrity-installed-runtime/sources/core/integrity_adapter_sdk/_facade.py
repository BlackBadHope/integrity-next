"""Fail-closed loader for the transitional Guardian-backed implementation."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import stat
import sys
import threading
from collections.abc import Callable, Mapping, Sequence
from importlib import import_module, metadata
from importlib.abc import Loader, MetaPathFinder
from importlib.machinery import PathFinder
from importlib.util import spec_from_file_location
from pathlib import Path, PurePosixPath
from types import ModuleType
from typing import Any

EXPECTED_GUARDIAN_DISTRIBUTION = "integrity-guardian"
EXPECTED_GUARDIAN_VERSION = "5.5.1"
GUARDIAN_ORIGIN_MANIFEST_PROTOCOL = "integrity-adapter-sdk/guardian-origin-manifest/v1"
GUARDIAN_PACKAGE_ROOT = "integrity_guardian"
_MAX_GUARDIAN_FILE_BYTES = 8 * 1024 * 1024
_MAX_GUARDIAN_TREE_BYTES = 16 * 1024 * 1024
_FACADE_IMPORT_LOCK = threading.RLock()

FACADE_MODULES = {
    "adapter_sdk": "integrity_guardian.adapter_sdk",
    "adapter_conformance": "integrity_guardian.adapter_conformance",
    "adapter_portability": "integrity_guardian.adapter_portability",
    "adapter_runtime": "integrity_guardian.adapter_runtime",
    "workspace_patch_adapter": "integrity_guardian.workspace_patch_adapter",
    "host_command_adapter": "integrity_guardian.host_command_adapter",
    "browser_adapter": "integrity_guardian.browser_adapter",
    "browser_page_observer": "integrity_guardian.browser_page_observer",
    "network_adapter": "integrity_guardian.network_adapter",
    "network_endpoint_observer": "integrity_guardian.network_endpoint_observer",
    "webdriver_transport": "integrity_guardian.webdriver_transport",
    "windows_bounded_process_adapter": ("integrity_guardian.windows_bounded_process_adapter"),
}


class SdkCompatibilityError(ImportError):
    """Raised when the exact transitional Guardian dependency is unavailable."""


class _VerifiedGuardianLoader(Loader):
    """Execute only the verified source snapshot, never a bytecode cache."""

    def __init__(self, fullname: str, path: Path, payload: bytes) -> None:
        self.fullname = fullname
        self.path = path
        self.payload = payload

    def create_module(self, spec):
        return None

    def exec_module(self, module: ModuleType) -> None:
        code = compile(
            self.payload,
            str(self.path),
            "exec",
            dont_inherit=True,
            optimize=sys.flags.optimize,
        )
        # The loader receives only the digest-verified Guardian source snapshot.
        exec(code, module.__dict__)  # noqa: S102


class _VerifiedGuardianFinder(MetaPathFinder):
    """Resolve only modules present in the verified Guardian source snapshot."""

    def __init__(
        self,
        *,
        package_root: Path,
        sources: Mapping[Path, bytes],
        tree_sha256: str,
    ) -> None:
        self.package_root = package_root
        self.tree_sha256 = tree_sha256
        self.modules: dict[str, tuple[Path, bytes, bool]] = {}
        for path, payload in sources.items():
            if path.suffix != ".py":
                continue
            relative = path.relative_to(package_root)
            if relative.name == "__init__.py":
                fullname = ".".join((GUARDIAN_PACKAGE_ROOT, *relative.parent.parts))
                is_package = True
            else:
                fullname = ".".join((GUARDIAN_PACKAGE_ROOT, *relative.with_suffix("").parts))
                is_package = False
            self.modules[fullname] = (path, payload, is_package)

    def find_spec(self, fullname: str, path=None, target=None):
        source = self.modules.get(fullname)
        if source is None:
            return None
        source_path, payload, is_package = source
        loader = _VerifiedGuardianLoader(fullname, source_path, payload)
        search_locations = [str(source_path.parent)] if is_package else None
        return spec_from_file_location(
            fullname,
            source_path,
            loader=loader,
            submodule_search_locations=search_locations,
        )


_ACTIVE_GUARDIAN_FINDER: _VerifiedGuardianFinder | None = None


def _distribution_version(distribution: str) -> str:
    return metadata.version(distribution)


def _stable_payload(path: Path) -> bytes:
    try:
        before = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(before.st_mode):
            raise SdkCompatibilityError("Guardian origin file envelope rejected")
        if before.st_size < 0 or before.st_size > _MAX_GUARDIAN_FILE_BYTES:
            raise SdkCompatibilityError("Guardian origin file size rejected")
        payload = path.read_bytes()
        after = path.lstat()
    except OSError as exc:
        raise SdkCompatibilityError("Guardian origin file unreadable") from exc
    stable_fields = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    if any(getattr(before, field) != getattr(after, field) for field in stable_fields):
        raise SdkCompatibilityError("Guardian origin file changed during verification")
    if len(payload) != before.st_size:
        raise SdkCompatibilityError("Guardian origin file size changed")
    return payload


def _load_guardian_origin_manifest() -> dict[str, object]:
    path = Path(__file__).with_name("guardian-origin.json")
    try:
        value = json.loads(_stable_payload(path).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SdkCompatibilityError("Guardian origin manifest rejected") from exc
    if not isinstance(value, dict):
        raise SdkCompatibilityError("Guardian origin manifest must be an object")
    return value


def _decode_record_hash(value: str) -> bytes:
    try:
        padding = "=" * (-len(value) % 4)
        decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
        canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
        if len(decoded) != hashlib.sha256().digest_size or canonical != value:
            raise ValueError
        return decoded
    except (UnicodeEncodeError, ValueError, binascii.Error) as exc:
        raise SdkCompatibilityError("Guardian RECORD hash rejected") from exc


def _install_guardian_finder(
    *,
    package_root: Path,
    sources: Mapping[Path, bytes],
    tree_sha256: str,
) -> None:
    global _ACTIVE_GUARDIAN_FINDER
    active = _ACTIVE_GUARDIAN_FINDER
    if active is not None:
        if active.package_root != package_root or active.tree_sha256 != tree_sha256:
            raise SdkCompatibilityError("Guardian verified loader identity changed")
        return
    finder = _VerifiedGuardianFinder(
        package_root=package_root,
        sources=sources,
        tree_sha256=tree_sha256,
    )
    sys.meta_path.insert(0, finder)
    _ACTIVE_GUARDIAN_FINDER = finder


def _expected_origin_manifest(value: Mapping[str, object]) -> tuple[int, str]:
    if set(value) != {
        "distribution",
        "file_count",
        "package_root",
        "protocol",
        "tree_sha256",
        "version",
    }:
        raise SdkCompatibilityError("Guardian origin manifest fields rejected")
    if (
        value.get("distribution") != EXPECTED_GUARDIAN_DISTRIBUTION
        or value.get("version") != EXPECTED_GUARDIAN_VERSION
        or value.get("package_root") != GUARDIAN_PACKAGE_ROOT
        or value.get("protocol") != GUARDIAN_ORIGIN_MANIFEST_PROTOCOL
    ):
        raise SdkCompatibilityError("Guardian origin manifest identity rejected")
    file_count = value.get("file_count")
    tree_sha256 = value.get("tree_sha256")
    if (
        isinstance(file_count, bool)
        or not isinstance(file_count, int)
        or file_count < 1
        or not isinstance(tree_sha256, str)
        or not tree_sha256.startswith("sha256:")
        or len(tree_sha256) != 71
        or any(character not in "0123456789abcdef" for character in tree_sha256[7:])
    ):
        raise SdkCompatibilityError("Guardian origin manifest digest rejected")
    return file_count, tree_sha256


def _verify_guardian_origin(
    *,
    target: str | None = None,
    manifest: Mapping[str, object] | None = None,
    distribution_reader: Callable[[str], Any] | None = None,
    search_path: Sequence[str] | None = None,
    install_finder: bool = True,
) -> dict[str, object]:
    """Bind Guardian metadata, RECORD, bytes and import origin before import."""

    expected_count, expected_tree = _expected_origin_manifest(
        manifest or _load_guardian_origin_manifest()
    )
    reader = distribution_reader or metadata.distribution
    try:
        distribution = reader(EXPECTED_GUARDIAN_DISTRIBUTION)
    except metadata.PackageNotFoundError as exc:
        raise SdkCompatibilityError("Guardian distribution is absent") from exc
    if distribution.version != EXPECTED_GUARDIAN_VERSION:
        raise SdkCompatibilityError("Guardian distribution version changed")
    entries = distribution.files
    if entries is None:
        raise SdkCompatibilityError("Guardian RECORD is unavailable")

    package_root = Path(distribution.locate_file(GUARDIAN_PACKAGE_ROOT))
    try:
        root_state = package_root.lstat()
    except OSError as exc:
        raise SdkCompatibilityError("Guardian package root is unavailable") from exc
    if package_root.is_symlink() or not stat.S_ISDIR(root_state.st_mode):
        raise SdkCompatibilityError("Guardian package root envelope rejected")
    package_root = Path(os.path.abspath(package_root))

    rows: list[tuple[str, int, str]] = []
    verified_origins: set[Path] = set()
    verified_sources: dict[Path, bytes] = {}
    seen: set[str] = set()
    total_size = 0
    for entry in entries:
        relative = str(entry)
        candidate = PurePosixPath(relative)
        if not candidate.parts or candidate.parts[0] != GUARDIAN_PACKAGE_ROOT:
            continue
        if (
            candidate.is_absolute()
            or "\\" in relative
            or ".." in candidate.parts
            or "\x00" in relative
            or relative in seen
        ):
            raise SdkCompatibilityError("Guardian RECORD path rejected")
        if "__pycache__" in candidate.parts:
            if candidate.suffix != ".pyc":
                raise SdkCompatibilityError("Guardian bytecode RECORD member rejected")
            continue
        seen.add(relative)
        located = Path(os.path.abspath(distribution.locate_file(entry)))
        expected_path = Path(os.path.abspath(package_root.parent / relative))
        if located != expected_path:
            raise SdkCompatibilityError("Guardian RECORD location rejected")
        payload = _stable_payload(located)
        total_size += len(payload)
        if total_size > _MAX_GUARDIAN_TREE_BYTES:
            raise SdkCompatibilityError("Guardian origin tree size rejected")
        record_hash = getattr(entry, "hash", None)
        record_size = getattr(entry, "size", None)
        if (
            record_hash is None
            or getattr(record_hash, "mode", None) != "sha256"
            or not isinstance(getattr(record_hash, "value", None), str)
            or isinstance(record_size, bool)
            or not isinstance(record_size, int)
            or record_size != len(payload)
            or _decode_record_hash(record_hash.value) != hashlib.sha256(payload).digest()
        ):
            raise SdkCompatibilityError("Guardian RECORD content rejected")
        digest = hashlib.sha256(payload).hexdigest()
        rows.append((relative, len(payload), digest))
        verified_origins.add(located)
        verified_sources[located] = payload

    disk_files: set[str] = set()
    for directory, directories, filenames in os.walk(package_root, followlinks=False):
        current = Path(directory)
        for name in directories:
            path = current / name
            if path.is_symlink():
                raise SdkCompatibilityError("Guardian origin directory link rejected")
        for name in filenames:
            path = current / name
            if "__pycache__" in path.relative_to(package_root).parts:
                if path.is_symlink() or not path.is_file() or path.suffix != ".pyc":
                    raise SdkCompatibilityError("Guardian bytecode cache member rejected")
                continue
            relative = path.relative_to(package_root.parent).as_posix()
            if path.is_symlink() or not path.is_file():
                raise SdkCompatibilityError("Guardian origin disk member rejected")
            disk_files.add(relative)
    if disk_files != seen or len(rows) != expected_count:
        raise SdkCompatibilityError("Guardian origin file set rejected")

    tree = hashlib.sha256()
    for relative, size, digest in sorted(rows):
        tree.update(f"{relative}\0{size}\0{digest}\n".encode())
    observed_tree = f"sha256:{tree.hexdigest()}"
    if observed_tree != expected_tree:
        raise SdkCompatibilityError("Guardian origin tree digest mismatch")

    effective_search_path = list(sys.path if search_path is None else search_path)
    package_spec = PathFinder.find_spec(GUARDIAN_PACKAGE_ROOT, effective_search_path)
    if (
        package_spec is None
        or package_spec.origin is None
        or Path(os.path.abspath(package_spec.origin)) not in verified_origins
    ):
        raise SdkCompatibilityError("Guardian package import origin rejected")
    facade_targets = set(FACADE_MODULES.values())
    if target is not None and target not in facade_targets:
        raise SdkCompatibilityError("Guardian facade target rejected")
    for facade_target in sorted(facade_targets):
        target_spec = PathFinder.find_spec(facade_target, [str(package_root)])
        if (
            target_spec is None
            or target_spec.origin is None
            or Path(os.path.abspath(target_spec.origin)) not in verified_origins
        ):
            raise SdkCompatibilityError("Guardian facade import origin rejected")
    for module_name, loaded in tuple(sys.modules.items()):
        if not (
            module_name == GUARDIAN_PACKAGE_ROOT
            or module_name.startswith(f"{GUARDIAN_PACKAGE_ROOT}.")
        ):
            continue
        loaded_spec = getattr(loaded, "__spec__", None)
        loaded_origin = getattr(loaded_spec, "origin", None)
        loaded_loader = getattr(loaded_spec, "loader", None)
        if (
            loaded_origin is None
            or Path(os.path.abspath(loaded_origin)) not in verified_origins
            or not isinstance(loaded_loader, _VerifiedGuardianLoader)
        ):
            raise SdkCompatibilityError("Loaded Guardian module origin rejected")
    if install_finder:
        _install_guardian_finder(
            package_root=package_root,
            sources=verified_sources,
            tree_sha256=observed_tree,
        )
    return {
        "origin_verified": True,
        "origin_file_count": len(rows),
        "origin_tree_sha256": observed_tree,
    }


def guardian_dependency_status(
    *,
    version_reader: Callable[[str], str] | None = None,
) -> dict[str, object]:
    """Return a content-free status for the exact facade dependency."""

    reader = version_reader or _distribution_version
    try:
        actual = reader(EXPECTED_GUARDIAN_DISTRIBUTION)
    except metadata.PackageNotFoundError:
        actual = None
    matched = actual == EXPECTED_GUARDIAN_VERSION
    return {
        "protocol": "integrity-adapter-sdk/guardian-dependency-status/v1",
        "distribution": EXPECTED_GUARDIAN_DISTRIBUTION,
        "expected_version": EXPECTED_GUARDIAN_VERSION,
        "actual_version": actual,
        "matched": matched,
        "production_authority": False,
        "memory_grants_authority": False,
    }


def require_guardian(*, target: str | None = None) -> dict[str, object]:
    """Require the exact Guardian build that owns the transitional modules."""

    status = guardian_dependency_status()
    if status["matched"] is not True:
        actual = status["actual_version"] or "absent"
        raise SdkCompatibilityError(
            "integrity-adapter-sdk 1.0.0 requires exact "
            f"{EXPECTED_GUARDIAN_DISTRIBUTION}=={EXPECTED_GUARDIAN_VERSION}; "
            f"observed {actual}"
        )
    return {**status, **_verify_guardian_origin(target=target)}


def load_facade_module(name: str) -> ModuleType:
    """Load one allowlisted implementation module after the exact-version gate."""

    target = FACADE_MODULES.get(name)
    if target is None:
        raise AttributeError(f"unknown Integrity Adapter SDK facade module: {name}")
    with _FACADE_IMPORT_LOCK:
        require_guardian(target=target)
        return import_module(target)


__all__ = [
    "EXPECTED_GUARDIAN_DISTRIBUTION",
    "EXPECTED_GUARDIAN_VERSION",
    "FACADE_MODULES",
    "SdkCompatibilityError",
    "guardian_dependency_status",
    "load_facade_module",
    "require_guardian",
]
