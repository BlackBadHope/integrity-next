"""Explicit, byte-bound read-only handover of retained context admissions.

This is an operator boundary, not an MCP tool or an implicit legacy reader.
A private admission archives the original JSON bytes. No journal is reset and
no predecessor name is built into the universal runtime. A migrated session
cannot reuse action authority: obtain a fresh current-version admission first.
"""
from __future__ import annotations

import argparse
import ast
import base64
import copy
import hashlib
import json
import os
import re
import stat
import time
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import integrity_guardian

from .hashing import digest_object
from .memory_synapse_lts import (
    MemorySynapseLtsError,
    MemorySynapseLtsService,
    package_artifact_digest,
)

# Exact reviewed 5.5.1 package and structural-dialect identities. They confer
# no permission without an explicit per-record, per-target owner admission.
SOURCE_PACKAGE_SHA256 = "92465dfd4dd21de6181ec25b1895a274ec9c9437b0a23b4c834794bd21f01da4"
SOURCE_CONTRACT_SHA256 = "b0a792702d6b9ace7c85ac5663a7b065b3474ff027039726e25d72e7a84fd976"
PROTOCOL = "integrity-guardian/context-replay-migration/v1"
MAX_RECORD = 32 * 1024 * 1024
MAX_CATALOG = 512 * 1024 * 1024
MAX_RESERVATION = 1024
MAX_ADMISSION = 48 * 1024 * 1024
MAX_AGE = 24 * 60 * 60


class ReplayMigrationError(ValueError):
    """An unadmitted, unsupported, stale or altered handover was rejected."""


def _require(condition: object, message: str) -> None:
    if not condition:
        raise ReplayMigrationError(message)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _digest(value: str) -> bool:
    return isinstance(value, str) and re.fullmatch(r"sha256:[a-f0-9]{64}", value) is not None


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        _require(key not in value, "ambiguous migration JSON")
        value[key] = item
    return value


def _nonfinite(_value: str) -> None:
    raise ReplayMigrationError("non-finite migration JSON")


def _json(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_nonfinite)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ReplayMigrationError("invalid migration JSON") from exc
    _require(isinstance(value, dict), "migration JSON must be an object")
    return value


def _identity(details: os.stat_result) -> tuple[int, ...]:
    return (details.st_dev, details.st_ino, details.st_uid, details.st_gid,
            details.st_mode, details.st_size, details.st_mtime_ns, details.st_ctime_ns)


@contextmanager
def _directory(path: Path):
    """Walk with no symlink following, then require private owner custody."""
    _require(os.name == "posix", "replay migration requires POSIX custody")
    _require(path.is_absolute() and ".." not in path.parts, "absolute migration path required")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open("/", flags)
    try:
        for part in path.parts[1:]:
            next_descriptor = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        meta = os.fstat(descriptor)
        _require(meta.st_uid == os.geteuid() and stat.S_IMODE(meta.st_mode) == 0o700,
                 "migration directory must be owner-private mode 0700")
        yield descriptor
        _require(_identity(os.fstat(descriptor))[:5] == _identity(path.lstat())[:5],
                 "migration directory was replaced")
    finally:
        os.close(descriptor)


def _read_at(directory: int, name: str, limit: int) -> bytes:
    _require(name and "/" not in name and "\\" not in name and name not in {".", ".."},
             "invalid migration member")
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        meta = os.fstat(descriptor)
        _require(stat.S_ISREG(meta.st_mode) and meta.st_uid == os.geteuid()
                 and stat.S_IMODE(meta.st_mode) == 0o600 and meta.st_nlink == 1
                 and 0 < meta.st_size <= limit, "unsafe migration member custody")
        chunks, remaining = [], meta.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            _require(chunk, "truncated migration member")
            chunks.append(chunk)
            remaining -= len(chunk)
        _require(_identity(meta) == _identity(os.fstat(descriptor))
                 == _identity(os.stat(name, dir_fd=directory, follow_symlinks=False)),
                 "migration member changed while reading")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


@contextmanager
def _locked(directory: int, replay_hex: str):
    import fcntl

    with ExitStack() as stack:
        for name in (f".replay-lock-{replay_hex[:2]}", ".replay-maintenance.lock"):
            fd = os.open(name, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            stack.callback(os.close, fd)
            meta = os.fstat(fd)
            _require(stat.S_ISREG(meta.st_mode) and meta.st_uid == os.geteuid()
                     and stat.S_IMODE(meta.st_mode) == 0o600 and meta.st_nlink == 1
                     and meta.st_size == 0, "unsafe migration lock")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ReplayMigrationError("replay is busy; handover was not admitted") from exc
        yield


def _source_contract(package: Path) -> dict[str, str]:
    """Read only the exact reviewed package. Do not import predecessor code."""
    _require(package.is_absolute() and not package.is_symlink(), "explicit source package required")
    files = sorted(item for item in package.rglob("*") if item.is_file()
                   and "__pycache__" not in item.parts and item.suffix not in {".pyc", ".pyo"})
    _require(len(files) == 336, "unsupported predecessor package inventory")
    digest = hashlib.sha256()
    sources: dict[str, bytes] = {}
    total = 0
    for item in files:
        _require(not item.is_symlink() and item.stat().st_size <= MAX_RECORD,
                 "unsafe predecessor package member")
        raw = item.read_bytes()
        total += len(raw)
        _require(total <= MAX_RECORD, "predecessor package exceeds bound")
        relative = item.relative_to(package).as_posix()
        path_bytes = relative.encode()
        digest.update(len(path_bytes).to_bytes(8, "big"))
        digest.update(path_bytes)
        digest.update(len(raw).to_bytes(8, "big"))
        digest.update(raw)
        if relative in {"memory_synapse_mcp.py", "authority_scope.py"}:
            sources[relative] = raw
    _require(digest.hexdigest() == SOURCE_PACKAGE_SHA256, "unsupported predecessor package bytes")
    tree = ast.parse(sources["memory_synapse_mcp.py"])
    assignments = {node.targets[0].id: node.value for node in tree.body
                   if isinstance(node, ast.Assign) and len(node.targets) == 1
                   and isinstance(node.targets[0], ast.Name)}
    catalogs = {node.value for node in ast.walk(tree)
                if isinstance(node, ast.Constant) and isinstance(node.value, str)
                and node.value.endswith("/context-admission-frozen-catalog/v1")}
    providers = [ast.literal_eval(value)
                 for node in ast.walk(ast.parse(sources["authority_scope.py"]))
                 if isinstance(node, ast.Dict)
                 for key, value in zip(node.keys, node.values, strict=True)
                 if isinstance(key, ast.Constant) and key.value == "provider"]
    _require(len(catalogs) == len(providers) == 1, "ambiguous predecessor contract")
    contract = {
        "record": ast.literal_eval(assignments["CONTEXT_ADMISSION_REPLAY_PROTOCOL"]),
        "reservation": ast.literal_eval(assignments["CONTEXT_ADMISSION_REPLAY_RESERVATION_PROTOCOL"]),
        "catalog": catalogs.pop(),
        "provider": providers[0],
    }
    _require(_sha(_canonical(contract)) == SOURCE_CONTRACT_SHA256, "unsupported predecessor contract")
    return contract


@dataclass(frozen=True)
class ReplayMigration:
    """Captured immutable owner admission. Source JSON is retained verbatim."""

    encoded: bytes
    receipt_sha256: str

    @property
    def document(self) -> dict[str, Any]:
        return _json(self.encoded)

    @property
    def request_id(self) -> str:
        return self.document["request_id"]

    @property
    def original(self) -> dict[str, Any]:
        return _json(base64.b64decode(self.document["record_base64"], validate=True))

    @property
    def capsule(self) -> dict[str, Any]:
        original = self.original
        return original["prepared" if original["phase"] == "prepared" else "result"]

    @property
    def catalog_binding(self) -> dict[str, Any]:
        original = self.original
        return (original["prepared"] if original["phase"] == "prepared" else original["state"])["frozen_catalog"]

    def validate(self, replay_root: Path, target_artifact: str) -> None:
        _require(isinstance(self.encoded, bytes) and 0 < len(self.encoded) <= MAX_ADMISSION,
                 "migration admission exceeds bound")
        doc = self.document
        expected_keys = {"protocol", "source_version", "target_version", "source_package_sha256",
                         "target_package_sha256", "source_artifact_digest", "target_artifact_digest",
                         "request_id", "request_digest", "created_at", "expires_at", "root_identity",
                         "contract", "record_base64", "reservation_base64", "record_sha256",
                         "reservation_sha256", "source_record_mtime_ns", "read_only"}
        _require(set(doc) == expected_keys and doc["protocol"] == PROTOCOL
                 and doc["read_only"] is True and doc["source_version"] == "5.5.1"
                 and doc["target_version"] == integrity_guardian.__version__ == "6.0.0"
                 and doc["source_package_sha256"] == SOURCE_PACKAGE_SHA256
                 and doc["target_package_sha256"] == package_artifact_digest()
                 and doc["target_artifact_digest"] == target_artifact
                 and _digest(target_artifact) and _digest(doc["source_artifact_digest"])
                 and _digest(doc["request_id"]) and _digest(doc["request_digest"])
                 and _sha(self.encoded) == self.receipt_sha256
                 and _sha(_canonical(doc["contract"])) == SOURCE_CONTRACT_SHA256,
                 "migration identity is not admitted")
        now = time.time()
        _require(type(doc["created_at"]) is int and type(doc["expires_at"]) is int
                 and doc["created_at"] <= now <= doc["expires_at"]
                 and 0 < doc["expires_at"] - doc["created_at"] <= MAX_AGE,
                 "migration admission is stale")
        source_mtime = doc["source_record_mtime_ns"]
        _require(type(source_mtime) is int and source_mtime > 0
                 and 0 <= doc["created_at"] - source_mtime // 1_000_000_000 < MAX_AGE
                 and doc["expires_at"] <= source_mtime // 1_000_000_000 + MAX_AGE,
                 "predecessor replay is stale")
        _require(isinstance(doc["root_identity"], list) and len(doc["root_identity"]) == 5
                 and all(type(value) is int for value in doc["root_identity"]),
                 "invalid migration root identity")
        with _directory(replay_root) as fd:
            _require(list(_identity(os.fstat(fd))[:5]) == doc["root_identity"],
                     "migration root identity changed")
        for kind in ("record", "reservation"):
            raw = base64.b64decode(doc[kind + "_base64"], validate=True)
            _require(len(raw) <= (MAX_RECORD if kind == "record" else MAX_RESERVATION)
                     and _sha(raw) == doc[kind + "_sha256"], "migration archive changed")
            value = _json(raw)
            _require(value.get("protocol") == doc["contract"][kind]
                     and value.get("request_id") == doc["request_id"],
                     "predecessor replay identity changed")
        reservation = _json(base64.b64decode(doc["reservation_base64"], validate=True))
        _require(type(reservation.get("record_bytes")) is int
                 and reservation["record_bytes"] == MAX_RECORD
                 and type(reservation.get("catalog_bytes")) is int
                 and 0 < reservation["catalog_bytes"] <= MAX_CATALOG,
                 "invalid predecessor reservation budget")
        record = self.original
        _require(record.get("request_digest") == doc["request_digest"]
                 and record.get("phase") in {"prepared", "committed"}, "unsupported replay record")
        capsule = self.capsule
        _require(capsule["capabilities"]["artifact_digest"] == doc["source_artifact_digest"]
                 and capsule["snapshot"]["artifact_digest"] == doc["source_artifact_digest"],
                 "predecessor artifact changed")
        caps = dict(capsule["capabilities"])
        caps_digest = caps.pop("capabilities_digest", None)
        _require(digest_object(caps, domain="memory-synapse-lts-capabilities-v1") == caps_digest,
                 "predecessor capabilities digest changed")
        snapshot = dict(capsule["snapshot"])
        snapshot_id = snapshot.pop("snapshot_id", None)
        snapshot.pop("catalog_run_id", None)
        _require(digest_object(snapshot, domain="memory-synapse-snapshot-v1") == snapshot_id
                 and snapshot["authority_contract"]["provider_authority"]["provider"] == doc["contract"]["provider"],
                 "predecessor snapshot identity changed")
        _require(type(self.catalog_binding.get("bytes")) is int
                 and 0 < self.catalog_binding["bytes"] <= reservation["catalog_bytes"]
                 and _digest(self.catalog_binding.get("sha256")),
                 "invalid predecessor catalog budget")
        _require(self.catalog_binding["protocol"] == doc["contract"]["catalog"]
                 and self.catalog_binding["name"] == self.request_id.split(":")[1] + ".catalog.sqlite3",
                 "predecessor catalog identity changed")

    def accepts_source(self, kind: str, raw: bytes) -> bool:
        doc = self.document
        return _sha(raw) == doc[kind + "_sha256"]

    def validate_record(self, raw: bytes, record: dict[str, Any]) -> None:
        _require(record == _json(raw), "ambiguous migrated record")
        if self.accepts_source("record", raw):
            return
        original = self.original
        _require(original["phase"] == "prepared" and record.get("phase") == "committed"
                 and record.get("migration_admission_sha256") == self.receipt_sha256
                 and record.get("request_id") == original["request_id"]
                 and record.get("request_digest") == original["request_digest"],
                 "migrated replay record changed")
        for name in ("capabilities", "snapshot", "mind", "logical_generation"):
            _require(record["result"].get(name) == original["prepared"].get(name),
                     "migrated replay capsule changed")
        _require(record["state"].get("frozen_catalog") == self.catalog_binding
                 and record["state"].get("architecture") is None
                 and record["state"].get("native_session") is None
                 and record["state"]["write_plane"].get("outcome") == "unavailable",
                 "migrated replay cannot grant action authority")

    def retained_lts(self, service: MemorySynapseLtsService) -> MemorySynapseLtsService:
        return _MigratedLts(service, self.capsule["snapshot"])


class _MigratedLts(MemorySynapseLtsService):
    def __init__(self, source: MemorySynapseLtsService, snapshot: dict[str, Any]):
        super().__init__(source.catalog_path, evidence_root=source.evidence_root,
                         evidence_source_prefix=source.evidence_source_prefix,
                         artifact_digest=source.artifact_digest, immutable_catalog=True,
                         catalog_connection=source.catalog_connection,
                         expected_source_namespace=snapshot["source_namespace"])
        self._original_snapshot = copy.deepcopy(snapshot)

    def snapshot(self) -> dict[str, Any]:
        current = super().snapshot()
        # Only a presentation label changed in this reviewed schema transition.
        # Every authority bit, source digest, cursor and catalog identity must agree.
        current["authority_contract"]["provider_authority"]["provider"] = (
            self._original_snapshot["authority_contract"]["provider_authority"]["provider"])
        material = {key: value for key, value in current.items()
                    if key not in {"snapshot_id", "catalog_run_id"}}
        current["snapshot_id"] = digest_object(material, domain="memory-synapse-snapshot-v1")
        if current != self._original_snapshot:
            raise MemorySynapseLtsError("migration frozen snapshot differs from predecessor")
        return current


def load_admission(path: Path, expected_sha256: str, *, replay_root: Path,
                   target_artifact: str) -> ReplayMigration:
    _require(re.fullmatch(r"[a-f0-9]{64}", expected_sha256) is not None,
             "explicit migration admission digest required")
    with _directory(path.parent) as fd:
        raw = _read_at(fd, path.name, MAX_ADMISSION)
    admission = ReplayMigration(raw, expected_sha256)
    admission.validate(replay_root, target_artifact)
    return admission


def create_admission(*, replay_root: Path, source_package: Path, source_artifact: str,
                     target_artifact: str, request_id: str, request_digest: str,
                     record_sha256: str, reservation_sha256: str, output: Path,
                     lifetime_seconds: int = 3600) -> str:
    """Admit exact previously observed inputs, with create-only audit storage."""
    _require(_digest(request_id) and _digest(request_digest), "explicit request identity required")
    _require(type(lifetime_seconds) is int and 0 < lifetime_seconds <= MAX_AGE,
             "bounded migration lifetime required")
    _require(output.is_absolute() and not output.is_relative_to(replay_root),
             "migration audit must be outside active replay custody")
    contract = _source_contract(source_package)
    replay_hex = request_id.split(":")[1]
    with _directory(replay_root) as fd, _locked(fd, replay_hex), _directory(output.parent) as out:
        record_raw = _read_at(fd, replay_hex + ".json", MAX_RECORD)
        reservation_raw = _read_at(fd, replay_hex + ".reservation.json", MAX_RESERVATION)
        _require(_sha(record_raw) == record_sha256 and _sha(reservation_raw) == reservation_sha256,
                 "predecessor differs from the explicitly admitted preimage")
        now = int(time.time())
        record_mtime = os.stat(replay_hex + ".json", dir_fd=fd, follow_symlinks=False).st_mtime_ns
        expires_at = min(now + lifetime_seconds, record_mtime // 1_000_000_000 + MAX_AGE)
        _require(0 <= now - record_mtime // 1_000_000_000 < MAX_AGE,
                 "predecessor replay is stale")
        doc = {
            "protocol": PROTOCOL, "source_version": "5.5.1", "target_version": "6.0.0",
            "source_package_sha256": SOURCE_PACKAGE_SHA256,
            "target_package_sha256": package_artifact_digest(),
            "source_artifact_digest": source_artifact, "target_artifact_digest": target_artifact,
            "request_id": request_id, "request_digest": request_digest,
            "created_at": now, "expires_at": expires_at,
            "source_record_mtime_ns": record_mtime,
            "root_identity": list(_identity(os.fstat(fd))[:5]), "contract": contract,
            "record_base64": base64.b64encode(record_raw).decode(),
            "reservation_base64": base64.b64encode(reservation_raw).decode(),
            "record_sha256": record_sha256, "reservation_sha256": reservation_sha256,
            "read_only": True,
        }
        raw = _canonical(doc)
        _require(len(raw) <= MAX_ADMISSION, "migration admission exceeds bound")
        admission = ReplayMigration(raw, _sha(raw))
        admission.validate(replay_root, target_artifact)
        binding = admission.catalog_binding
        catalog = _read_at(fd, binding["name"], MAX_CATALOG)
        _require(len(catalog) == binding["bytes"] and "sha256:" + _sha(catalog) == binding["sha256"],
                 "frozen catalog differs from admitted source")
        temporary = f".migration-{os.getpid()}-{time.monotonic_ns()}.tmp"
        dest = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                       0o600, dir_fd=out)
        try:
            with os.fdopen(dest, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            # Link is atomic and create-only. Rename/replace could clobber a
            # different concurrent owner's admission at the destination.
            os.link(temporary, output.name, src_dir_fd=out, dst_dir_fd=out, follow_symlinks=False)
        finally:
            os.unlink(temporary, dir_fd=out)
            os.fsync(out)
    return admission.receipt_sha256


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("replay-root", "source-package", "output"):
        parser.add_argument("--" + option, type=Path, required=True)
    for option in ("source-artifact", "target-artifact", "request-id", "request-digest",
                   "record-sha256", "reservation-sha256"):
        parser.add_argument("--" + option, required=True)
    args = parser.parse_args(argv)
    try:
        result = create_admission(**vars(args))
    except (ReplayMigrationError, OSError, KeyError, TypeError) as exc:
        print(json.dumps({"protocol": PROTOCOL, "outcome": "rejected", "error_type": type(exc).__name__}))
        return 1
    print(json.dumps({"protocol": PROTOCOL, "outcome": "admitted", "sha256": result,
                      "read_only": True, "source_bytes_rewritten": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
