"""client Memory & Synapse LTS MCP facade over forced-command stdio.

Authentication is deliberately external to this source process: an OpenSSH
forced command admits the existing client key and supplies fixed server-side
paths.  The client cannot select a catalog, Home adapter, URL, listener, or
authority scope through MCP arguments.
"""

from __future__ import annotations

import argparse
import atexit
import datetime as dt
import hashlib
import hmac
import json
import math
import os
import re
import selectors
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from contextlib import closing, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jsonschema import ValidationError

try:
    import fcntl as _fcntl
except ImportError:  # The production Memory LTS service is Linux-only.
    _fcntl = None

from .action_log_reader import (
    ActionLogReaderAuthError,
    ActionLogReaderTransportError,
    action_log_reader_headers,
    open_action_log_reader_request,
    require_action_log_reader_token,
)
from .authority_scope import memory_authority_contract

try:
    import syslog as _syslog
except ImportError:  # Windows has no stdlib syslog module.
    _syslog = None

from .context_budget import (
    ContextBudgetError,
    build_context_capsule,
    compact_architecture_admission,
    resolve_context_budget,
)
from .medor_architecture import (
    CUSTODY_LEDGER_ID,
    TENANT_ID,
    MedorArchitectureKeys,
    PersistentMedorArchitectureService,
    load_medor_architecture_signer,
)
from .medor_security import (
    VerifiedMedorSecurityAdmission,
    load_medor_security_bundle,
    load_medor_trusted_public_key,
    require_verified_medor_security_admission,
)
from .memory_link_graph import MemoryLinkGraph, MemoryLinkGraphError
from .memory_synapse_lts import (
    FACADE_SERVER_NAME,
    FACADE_SERVER_VERSION,
    MemorySynapseLtsError,
    MemorySynapseLtsService,
)
from .memory_ttt_paths import (
    MemoryTttPathError,
    RunbookPathCatalog,
    load_runbook_path_catalog,
    memory_ttt_autofill,
    register_paths,
)
from .mind_admission import MindAdmissionError, admit_mind_companion, bind_seed_catalog_to_admission
from .native_trust import (
    DEFAULT_DEVICE_SCOPES,
    NATIVE_TRUST_PROFILE,
    NativeTrustError,
    NativeTrustStore,
)
from .replay_migration import ReplayMigration, ReplayMigrationError, load_admission
from .schemas import validate
from .signing import public_key_fingerprint
from .turn_memory import (
    NO_EVENT_REASONS,
    TurnMemoryError,
    TurnMemoryStore,
    namespace_fingerprint,
)

BRIDGE_PROTOCOL = "integrity-client-memory-mcp/v3"
MIND_PROJECTION_PROTOCOL = "integrity.action-log.mind-projection/v1"
SERVER_NAME = FACADE_SERVER_NAME
SERVER_VERSION = FACADE_SERVER_VERSION
SOURCE_LABEL = "client-workstation"
SERVER_INSTRUCTIONS = (
    "MANDATORY client Integrity memory admission: before any substantive answer or action about the "
    "owner's projects, systems, tasks, releases, architecture, operations, or remembered "
    "context, invoke integrity_context_admission_current_turn exactly once per owner intent/turn "
    "with the opaque turn_ref supplied by the owning hook; legacy clients may use "
    "integrity_context_admission with the exact current intent. Omit limit for adaptive selection. "
    "The server rotates the "
    "isolated logical context inside the existing stdio transport. The read plane is independent "
    "from action admission: "
    "architecture, coordination, witness, or Security Harness blockers apply only to append/action "
    "authority and must never be interpreted as unavailable memory. Continue with the returned "
    "snapshot-bound Seed reads when write_plane.outcome is unavailable or coordination stops an "
    "action. A read-plane denial is an infrastructure fault; report it and do not answer from model "
    "memory or invent another source. Integrity Home is separate/read-only and never enters Seed "
    "cognition. Canonical mutation is only "
    "integrity_append_event, and it must echo the context_admission_id from the current owner "
    "intent before any append side effect; the current binding enters the signed v2 decision "
    "and one-use Ledger grant. The legacy production_authority=false field describes only "
    "this Memory provider's capability boundary. It is not a denial of an unrelated target "
    "action and must never override current user authorization or a target-specific action "
    "guard. coordination_stop_required describes only the Integrity Memory coordination "
    "route; it does not deny the independently gated one-use Seed append or any external "
    "target action; production "
    "authority, update, edit, delete, import, overwrite, "
    "bulk write, shell, and arbitrary action authority are absent. Every registered turn must "
    "finish with integrity_turn_memory_close: either verified Seed event references or one "
    "closed no-event reason. A missing close is coverage debt, never an inferred no-event."
)
DEFAULT_ACTION_LOG_BASE_URL = "http://127.0.0.1:8765"
DEFAULT_HOME_HELPER = (
    "/usr/bin/sudo",
    "-n",
    "-u",
    "integrity-memory",
    "--",
    "/usr/local/libexec/integrity-client-home-mcp",
)
DEFAULT_ACTION_WITNESS_HELPER = (
    "/usr/bin/sudo",
    "-n",
    "-u",
    "codex-action-log",
    "--",
    "/usr/local/libexec/integrity-client-action-log-witness",
)
RELEASE_ACTION_WITNESS_RE = re.compile(
    r"^/opt/integrity-client-memory-lts/releases/[a-f0-9]{64}/"
    r"action-log-passive-witness$"
)
SUPPORTED_MCP_VERSIONS = {"2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"}
DEFAULT_MCP_VERSION = "2025-06-18"
CURRENT_TOOL_CONTRACT_PROFILE = "current"
PRE_TTT_TOOL_CONTRACT_PROFILE = "pre-ttt"
PRE_V4_TOOL_CONTRACT_PROFILE = "pre-v4"
LEGACY_TURN_BROKER_TOOL_CONTRACT_PROFILE = "turn-broker-1.2.1"
BROKER_TOOL_SURFACE_PROTOCOL = "integrity-client/broker-tool-surface/v1"
BROKER_TOOL_SURFACE_CAPABILITY = "integrityClientToolSurface"
CONTEXT_ADMISSION_REPLAY_PROTOCOL = "integrity-client/context-admission-replay/v2"
CONTEXT_ADMISSION_REPLAY_CAPABILITY = "integrityClientContextAdmissionReplay"
CONTEXT_ADMISSION_REPLAY_FIELD = "_integrity_replay_id"
TURN_ENVELOPE_BINDING_FIELD = "_integrity_turn_binding"
TURN_ENVELOPE_PROTOCOL = "integrity-client/turn-envelope/v1"
MAX_FULL_PROMPT_BYTES = 256 * 1024
FULL_PROMPT_SEGMENT_BYTES = 4096
CONTEXT_ADMISSION_REPLAY_ACK_NOTIFICATION = (
    "notifications/integrity_context_admission_replay_ack"
)
CONTEXT_ADMISSION_REPLAY_RESERVE_METHOD = (
    "integrity/context_admission_replay_reserve"
)
CONTEXT_ADMISSION_REPLAY_ACK_METHOD = "integrity/context_admission_replay_ack"
CONTEXT_ADMISSION_REPLAY_RESERVATION_PROTOCOL = (
    "integrity-client/context-admission-replay-reservation/v1"
)
MAX_CONTEXT_ADMISSION_REPLAY_BYTES = 32 * 1_048_576
MAX_CONTEXT_ADMISSION_REPLAY_CATALOG_BYTES = 512 * 1_048_576
MAX_CONTEXT_ADMISSION_REPLAY_TOTAL_BYTES = 2 * 1_024 * 1_024 * 1_024
MAX_CONTEXT_ADMISSION_REPLAY_RECORDS = 128
CONTEXT_ADMISSION_REPLAY_TTL_SECONDS = 24 * 60 * 60
CONTEXT_ADMISSION_REPLAY_ORPHAN_GRACE_SECONDS = 10 * 60
CONTEXT_ADMISSION_REPLAY_LOCK_TIMEOUT_SECONDS = 60.0
CONTEXT_ADMISSION_REPLAY_OPERATION_TIMEOUT_SECONDS = 150.0
CONTEXT_ADMISSION_REPLAY_RESERVATION_TIMEOUT_SECONDS = 5.0
CONTEXT_ADMISSION_REPLAY_RESERVATION_OPERATION_TIMEOUT_SECONDS = 12.0
CONTEXT_ADMISSION_REPLAY_RESERVATION_TTL_SECONDS = 10 * 60
MAX_CONTEXT_ADMISSION_REPLAY_RESERVATION_BYTES = 1_024
# Monotonic rolling-upgrade custody. Never remove a digest merely because the
# current tools() surface changed; retire it only after installed broker state
# has been independently migrated and observed.
RETAINED_BROKER_TOOL_SURFACE_SHA256 = {
    "sha256:4fa06b9e25e652fd47deacef85136a08a477d2e6782b4de432c8831a98dc61e7",
    "sha256:6d0b9a3a5c02aa9257ac05423ee279eb6ab539ced593ede338ab0315d9999914",
    "sha256:e092f9005b35f611cd5469fe18ada48351f63e172cf318e0418c397c3b201c7e",
    "sha256:6ff6b9708be59156648556d9cae5218f11aa14d95e634eacdffc0b1207f2244e",
    "sha256:75fc187123bff958c1de77bbf30e2876d08ed75770c54cb26c5ea120ea24719f",
    "sha256:c5b4f6b597eb228b3978439c585b30e41cb006b5ec02ae23cab810a5e48496cb",
    "sha256:333cc9a747ec56238b6c30e231f20b597d91245c39365479934bf778c2c621da",
    "sha256:ed1ffb14fcb87c4a6ca5b865e1afe6456dd7e0e7ee8fdaa9b0fcc6e89e0160d1",
}
# A valid 256 KiB prompt may expand to roughly 1.5 MiB after JSON escaping
# control characters. Keep stdio bounded while making the advertised prompt
# limit reachable for every valid UTF-8 text payload.
MAX_REQUEST_BYTES = 2 * 1_048_576
MAX_RESPONSE_BYTES = 32 * 1_048_576
MAX_HOME_RESPONSE_BYTES = 64 * 1_024
HOME_CHILD_TIMEOUT_SECONDS = 15.0
MAX_EVENT_PAGE_SIZE = 100
MAX_HOME_PAGE_SIZE = 10
MAX_DETAILS_BYTES = 65_536
EVENT_KINDS = {"task", "thought", "concept"}
SECURITY_AUTHORITY_KEY_ID = "key:medor-security-owner"
EVENT_AUTHORITY_KEY_ID = "key:medor-event-append-owner"
RESERVED_DETAILS_KEY = "_integrity_client"
EVENT_UID_RE = re.compile(r"^client:[A-Za-z0-9][A-Za-z0-9._:-]{7,154}$")
ACTION_WITNESS_READINESS_EVENT_UID = "client:action-witness-readiness"
ACTION_WITNESS_READINESS_REQUEST_SHA256 = "0" * 64
WRITE_PLANE_RECOVERY_INITIAL_COOLDOWN_SECONDS = 5.0
WRITE_PLANE_RECOVERY_MAX_COOLDOWN_SECONDS = 300.0


class McpFacadeError(RuntimeError):
    """One bounded facade denial."""


class InputValidationError(McpFacadeError):
    """A deterministic caller error before read-plane initialization."""

    def __init__(self, message: str, *, reason_code: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


class ReadPlaneUnavailableError(McpFacadeError):
    """A typed infrastructure denial after read-plane initialization starts."""

    def __init__(
        self,
        technical_reason: str,
        *,
        reason_code: str,
        user_message: str,
        operator_action: str,
    ) -> None:
        super().__init__(technical_reason)
        self.technical_reason = technical_reason
        self.reason_code = reason_code
        self.user_message = user_message
        self.operator_action = operator_action


@dataclass(frozen=True)
class WritePlaneRuntime:
    """One complete candidate set of write-plane services."""

    architecture: PersistentMedorArchitectureService | None
    action_witness: SqliteActionLogWitness | RestrictedActionLogWitnessClient | None
    security_admission: VerifiedMedorSecurityAdmission | None
    native_trust: NativeTrustStore | None
    native_device_id: str | None
    turn_memory: TurnMemoryStore | None
    status: dict[str, str]
    failure_reason_digests: dict[str, str]


SEED_SNAPSHOT_SESSION_PREFIX = ".seed-session-"
SEED_SNAPSHOT_OWNER_LOCK = "owner.lock"
# A session copy without an owner lock can only come from a crash between the
# private directory creation and the lock. Keep it long enough to never race a
# starting session, then treat it as abandoned.
SEED_SNAPSHOT_UNLOCKED_GRACE_SECONDS = 3600


def _lock_seed_snapshot_owner(directory: Path) -> int | None:
    """Hold an exclusive lock that proves this process owns the session copy."""
    if _fcntl is None:
        return None
    descriptor = os.open(
        directory / SEED_SNAPSHOT_OWNER_LOCK,
        os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        _fcntl.flock(descriptor, _fcntl.LOCK_EX | _fcntl.LOCK_NB)
    except OSError:
        os.close(descriptor)
        raise
    return descriptor


def _remove_seed_snapshot_directory(directory: Path) -> None:
    for entry in os.scandir(directory):
        if entry.is_dir(follow_symlinks=False):
            raise McpFacadeError("Seed session copy contains an unexpected directory")
        os.unlink(entry.path)
    os.rmdir(directory)


def sweep_orphaned_seed_snapshots(root: Path, *, now: float | None = None) -> int:
    """Remove private Seed session copies whose owning process is gone.

    A process killed by the kernel (for example by a memory-cgroup OOM) never
    runs its cleanup, and its tmpfs copy keeps charging the cgroup. The owner
    lock is released by the kernel with the process, so an acquirable lock is
    proof of abandonment. Only this principal's own private root is touched.
    """
    if _fcntl is None:
        return 0
    try:
        details = root.lstat()
    except FileNotFoundError:
        return 0
    if (
        not stat.S_ISDIR(details.st_mode)
        or details.st_uid != os.geteuid()
        or stat.S_IMODE(details.st_mode) & 0o077
    ):
        raise McpFacadeError("Seed snapshot root custody is unsafe")
    current = time.time() if now is None else now
    removed = 0
    for entry in os.scandir(root):
        if not entry.name.startswith(SEED_SNAPSHOT_SESSION_PREFIX):
            continue
        entry_details = entry.stat(follow_symlinks=False)
        if not stat.S_ISDIR(entry_details.st_mode) or entry_details.st_uid != os.geteuid():
            continue
        directory = Path(entry.path)
        try:
            descriptor = os.open(
                directory / SEED_SNAPSHOT_OWNER_LOCK,
                os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            )
        except FileNotFoundError:
            if current - entry_details.st_mtime >= SEED_SNAPSHOT_UNLOCKED_GRACE_SECONDS:
                _remove_seed_snapshot_directory(directory)
                removed += 1
            continue
        try:
            try:
                _fcntl.flock(descriptor, _fcntl.LOCK_EX | _fcntl.LOCK_NB)
            except BlockingIOError:
                continue
            # Delete while holding the lock so a racing sweeper cannot also act.
            _remove_seed_snapshot_directory(directory)
            removed += 1
        finally:
            os.close(descriptor)
    return removed


class FrozenSeedCatalogSnapshot:
    """One private session copy of a quiescent, read-only WAL-mode Seed catalog.

    SQLite keeps an empty ``-wal`` and a live ``-shm`` next to a healthy
    long-running database.  Their mere presence is not pending data.  A
    non-empty WAL is denied because an immutable reader would otherwise miss
    frames.  The WAL keeps its complete identity check.  SHM custody is checked
    before and after the backup, while transient SHM ``mtime``/``ctime`` churn
    is deliberately ignored: ordinary read-only SQLite traffic updates SHM
    lock state without changing the logical catalog.
    """

    def __init__(
        self,
        source: Path,
        destination_root: Path,
        *,
        deadline_monotonic: float | None = None,
        maximum_bytes: int | None = None,
    ) -> None:
        if not source.is_absolute() or source.is_symlink():
            raise McpFacadeError("Seed catalog source path is unsafe")
        if not destination_root.is_absolute() or destination_root.is_symlink():
            raise McpFacadeError("Seed snapshot destination path is unsafe")
        try:
            source_before = source.lstat()
            root_details = destination_root.lstat()
        except OSError as exc:
            raise McpFacadeError("Seed catalog freeze paths are unavailable") from exc
        if (
            not stat.S_ISREG(source_before.st_mode)
            or source_before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or not stat.S_ISDIR(root_details.st_mode)
            or root_details.st_uid != os.geteuid()
            or stat.S_IMODE(root_details.st_mode) & 0o077
        ):
            raise McpFacadeError("Seed catalog freeze custody is unsafe")
        if maximum_bytes is not None and (
            source_before.st_size <= 0 or source_before.st_size > maximum_bytes
        ):
            raise McpFacadeError("Seed catalog exceeds replay reservation")
        self._source = source
        self._sidecars = tuple(
            source.with_name(source.name + suffix) for suffix in ("-wal", "-shm")
        )
        self._sidecar_descriptors: list[int] = []
        companion_flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )

        def companion_identity(path: Path, *, pin: bool = False) -> tuple[int, ...] | None:
            descriptor: int | None = None
            if pin:
                try:
                    descriptor = os.open(path, companion_flags)
                except FileNotFoundError:
                    return None
                except OSError as exc:
                    raise McpFacadeError("Seed catalog companion is unavailable") from exc
                self._sidecar_descriptors.append(descriptor)
            try:
                value = path.lstat()
            except FileNotFoundError:
                if descriptor is not None:
                    raise McpFacadeError("Seed catalog companion custody is unsafe")
                return None
            except OSError as exc:
                raise McpFacadeError("Seed catalog companion is unavailable") from exc
            pinned = os.fstat(descriptor) if descriptor is not None else None
            if (
                stat.S_ISLNK(value.st_mode)
                or not stat.S_ISREG(value.st_mode)
                or value.st_uid != source_before.st_uid
                or value.st_gid != source_before.st_gid
                or value.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                or (
                    pinned is not None
                    and (
                        not stat.S_ISREG(pinned.st_mode)
                        or (pinned.st_dev, pinned.st_ino) != (value.st_dev, value.st_ino)
                    )
                )
            ):
                raise McpFacadeError("Seed catalog companion custody is unsafe")
            return (
                value.st_dev,
                value.st_ino,
                value.st_uid,
                value.st_gid,
                stat.S_IMODE(value.st_mode),
                value.st_size,
                value.st_mtime_ns,
                value.st_ctime_ns,
            )

        try:
            sidecars_before = tuple(
                companion_identity(path, pin=True) for path in self._sidecars
            )
        except Exception:
            self._close_sidecar_descriptors()
            raise
        wal_before = sidecars_before[0]
        if wal_before is not None and wal_before[5] != 0:
            self._close_sidecar_descriptors()
            raise ReadPlaneUnavailableError(
                "Seed catalog has uncheckpointed WAL data",
                reason_code="seed_catalog_checkpoint_required",
                user_message=(
                    "Canonical memory is temporarily unavailable while pending "
                    "catalog changes are finalized."
                ),
                operator_action=(
                    "Ask the Seed catalog owner to run the supported synchronization "
                    "recovery procedure."
                ),
            )
        try:
            self._temporary = tempfile.TemporaryDirectory(
                prefix=SEED_SNAPSHOT_SESSION_PREFIX, dir=destination_root
            )
            self._owner_lock = _lock_seed_snapshot_owner(Path(self._temporary.name))
            self.path = Path(self._temporary.name) / "catalog.sqlite3"
            quoted = urllib.parse.quote(source.as_posix(), safe="/")
            with (
                closing(
                    sqlite3.connect(f"file:{quoted}?mode=ro&immutable=1", uri=True)
                ) as source_connection,
                closing(sqlite3.connect(self.path)) as destination_connection,
            ):
                def check_deadline(
                    status: int,
                    remaining: int,
                    total: int,
                ) -> None:
                    del status, remaining, total
                    if (
                        deadline_monotonic is not None
                        and time.monotonic() >= deadline_monotonic
                    ):
                        raise McpFacadeError(
                            "Seed catalog freeze exceeded replay operation deadline"
                        )

                source_connection.backup(
                    destination_connection,
                    pages=1_024,
                    progress=check_deadline,
                )
                if (
                    deadline_monotonic is not None
                    and time.monotonic() >= deadline_monotonic
                ):
                    raise McpFacadeError(
                        "Seed catalog freeze exceeded replay operation deadline"
                    )

                def quick_check_deadline() -> int:
                    return int(
                        deadline_monotonic is not None
                        and time.monotonic() >= deadline_monotonic
                    )

                destination_connection.set_progress_handler(
                    quick_check_deadline,
                    1_000,
                )
                try:
                    integrity = destination_connection.execute(
                        "PRAGMA quick_check"
                    ).fetchone()[0]
                except sqlite3.DatabaseError as exc:
                    if (
                        deadline_monotonic is not None
                        and time.monotonic() >= deadline_monotonic
                    ):
                        raise McpFacadeError(
                            "Seed catalog freeze exceeded replay operation deadline"
                        ) from exc
                    raise
                finally:
                    destination_connection.set_progress_handler(None, 0)
                if (
                    deadline_monotonic is not None
                    and time.monotonic() >= deadline_monotonic
                ):
                    raise McpFacadeError(
                        "Seed catalog freeze exceeded replay operation deadline"
                    )
                if integrity != "ok":
                    raise McpFacadeError("frozen Seed catalog integrity check failed")
            os.chmod(self.path, 0o600)
            if maximum_bytes is not None and self.path.stat().st_size > maximum_bytes:
                raise McpFacadeError("Seed catalog exceeds replay reservation")
            source_after = source.lstat()

            def source_identity(value: os.stat_result) -> tuple[int, ...]:
                return (
                    value.st_dev,
                    value.st_ino,
                    value.st_uid,
                    value.st_gid,
                    stat.S_IMODE(value.st_mode),
                    value.st_size,
                    value.st_mtime_ns,
                    value.st_ctime_ns,
                )

            sidecars_after = tuple(companion_identity(path) for path in self._sidecars)
            wal_after, shm_after = sidecars_after
            _, shm_before = sidecars_before

            def companion_custody(value: tuple[int, ...] | None) -> tuple[int, ...] | None:
                # dev, inode, owner, group, mode and size establish custody.
                # A read-only client legitimately mutates SHM lock metadata.
                # WAL retains its complete identity check above.
                return None if value is None else value[:6]

            if (
                source_identity(source_before) != source_identity(source_after)
                or wal_before != wal_after
                or companion_custody(shm_before) != companion_custody(shm_after)
                or (wal_after is not None and wal_after[5] != 0)
            ):
                raise McpFacadeError("Seed catalog changed during session freeze")
        except Exception:
            self.close()
            raise
        finally:
            self._close_sidecar_descriptors()

    def _close_sidecar_descriptors(self) -> None:
        descriptors = getattr(self, "_sidecar_descriptors", [])
        self._sidecar_descriptors = []
        for descriptor in descriptors:
            os.close(descriptor)

    def close(self) -> None:
        self._close_sidecar_descriptors()
        temporary = getattr(self, "_temporary", None)
        owner_lock = getattr(self, "_owner_lock", None)
        self._owner_lock = None
        try:
            if temporary is not None:
                self._temporary = None
                temporary.cleanup()
        finally:
            if owner_lock is not None:
                os.close(owner_lock)


class RetainedSeedCatalogSnapshot:
    """One descriptor-pinned durable replay copy of a frozen Seed catalog."""

    def __init__(
        self,
        descriptor: int,
        *,
        deadline_monotonic: float | None = None,
    ) -> None:
        self._descriptor: int | None = descriptor
        self.path = Path(f"/proc/self/fd/{descriptor}")
        try:
            self.connection: sqlite3.Connection | None = sqlite3.connect(
                f"file:{self.path}?mode=ro&immutable=1",
                uri=True,
            )
            self.connection.execute("PRAGMA query_only = ON")
            if (
                deadline_monotonic is not None
                and time.monotonic() >= deadline_monotonic
            ):
                raise McpFacadeError(
                    "retained Seed replay catalog exceeded operation deadline"
                )

            def quick_check_deadline() -> int:
                return int(
                    deadline_monotonic is not None
                    and time.monotonic() >= deadline_monotonic
                )

            self.connection.set_progress_handler(quick_check_deadline, 1_000)
            try:
                integrity = self.connection.execute("PRAGMA quick_check").fetchone()[0]
            except sqlite3.DatabaseError as exc:
                if (
                    deadline_monotonic is not None
                    and time.monotonic() >= deadline_monotonic
                ):
                    raise McpFacadeError(
                        "retained Seed replay catalog exceeded operation deadline"
                    ) from exc
                raise
            finally:
                self.connection.set_progress_handler(None, 0)
            if (
                deadline_monotonic is not None
                and time.monotonic() >= deadline_monotonic
            ):
                raise McpFacadeError(
                    "retained Seed replay catalog exceeded operation deadline"
                )
            if integrity != "ok":
                raise McpFacadeError(
                    "retained Seed replay catalog integrity check failed"
                )
        except Exception:
            connection = getattr(self, "connection", None)
            if connection is not None:
                connection.close()
            os.close(descriptor)
            self._descriptor = None
            raise

    def close(self) -> None:
        connection = getattr(self, "connection", None)
        self.connection = None
        if connection is not None:
            connection.close()
        descriptor = self._descriptor
        self._descriptor = None
        if descriptor is not None:
            os.close(descriptor)


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def _sha256(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def _sha256_hex(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _utc_now() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _audit(receipt: dict[str, Any]) -> None:
    """Write only content-free request identities and outcomes."""

    message = canonical_json(receipt).decode("utf-8")
    if _syslog is None:
        print(f"{SERVER_NAME}-audit {message}", file=sys.stderr, flush=True)
        return
    try:
        _syslog.openlog(SERVER_NAME, _syslog.LOG_PID, _syslog.LOG_AUTHPRIV)
        _syslog.syslog(_syslog.LOG_INFO, message)
    except OSError:
        print(f"{SERVER_NAME}-audit {message}", file=sys.stderr, flush=True)


def _reject_unknown(arguments: dict[str, Any], allowed: set[str]) -> None:
    unknown = sorted(set(arguments) - allowed)
    if unknown:
        raise McpFacadeError("unsupported argument(s): " + ", ".join(unknown))


def _integer(arguments: dict[str, Any], name: str, default: int, minimum: int, maximum: int) -> int:
    value = arguments.get(name, default)
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise McpFacadeError(f"{name} must be between {minimum} and {maximum}")
    return value


def _boolean(arguments: dict[str, Any], name: str, default: bool) -> bool:
    value = arguments.get(name, default)
    if not isinstance(value, bool):
        raise McpFacadeError(f"{name} must be a boolean")
    return value


def _full_prompt_segments(prompt: str) -> list[str]:
    if not isinstance(prompt, str) or not prompt.strip():
        raise InputValidationError("intent is empty", reason_code="intent_invalid")
    encoded = prompt.encode("utf-8")
    if len(encoded) > MAX_FULL_PROMPT_BYTES:
        raise InputValidationError(
            "full prompt exceeds the 256 KiB admission bound",
            reason_code="intent_too_long",
        )
    segments: list[str] = []
    current: list[str] = []
    current_bytes = 0
    for character in prompt:
        character_bytes = len(character.encode("utf-8"))
        if current and current_bytes + character_bytes > FULL_PROMPT_SEGMENT_BYTES:
            segments.append("".join(current))
            current = []
            current_bytes = 0
        current.append(character)
        current_bytes += character_bytes
    if current:
        segments.append("".join(current))
    if not segments or "".join(segments) != prompt:
        raise InputValidationError(
            "full prompt segmentation failed",
            reason_code="turn_envelope_invalid",
        )
    return segments


def _validated_turn_binding(value: Any, prompt: str) -> dict[str, Any]:
    expected_keys = {
        "protocol",
        "turn_ref_digest",
        "prompt_sha256",
        "prompt_bytes",
        "segment_count",
        "prompt_coverage",
        "truncation",
        "generation",
    }
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise InputValidationError(
            "turn envelope binding is invalid",
            reason_code="turn_envelope_invalid",
        )
    prompt_bytes = prompt.encode("utf-8")
    segments = _full_prompt_segments(prompt)
    if (
        value.get("protocol") != TURN_ENVELOPE_PROTOCOL
        or not isinstance(value.get("turn_ref_digest"), str)
        or re.fullmatch(r"sha256:[a-f0-9]{64}", value["turn_ref_digest"]) is None
        or value.get("prompt_sha256") != hashlib.sha256(prompt_bytes).hexdigest()
        or value.get("prompt_bytes") != len(prompt_bytes)
        or value.get("segment_count") != len(segments)
        or value.get("prompt_coverage") != "text-only"
        or value.get("truncation") is not False
        or isinstance(value.get("generation"), bool)
        or not isinstance(value.get("generation"), int)
        or value["generation"] < 1
    ):
        raise InputValidationError(
            "turn envelope binding does not match the exact full prompt",
            reason_code="turn_envelope_mismatch",
        )
    return dict(value)


class ActionLogClient:
    """Compatibility client for the existing canonical Action Log API."""

    def __init__(
        self,
        base_url: str = DEFAULT_ACTION_LOG_BASE_URL,
        *,
        auth_token: str | None = None,
        timeout: float = 15.0,
    ) -> None:
        parsed = urllib.parse.urlsplit(base_url)
        if (
            parsed.scheme != "http"
            or parsed.hostname != "127.0.0.1"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or parsed.port is None
        ):
            raise McpFacadeError("only an explicit IPv4 loopback Action Log endpoint is supported")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0.05 <= timeout <= 15.0:
            raise McpFacadeError("Action Log timeout must be bounded")
        if auth_token is None:
            self._auth_token = None
        else:
            try:
                self._auth_token = require_action_log_reader_token(auth_token)
            except ActionLogReaderAuthError as exc:
                raise McpFacadeError(str(exc)) from exc
        self.base_url = base_url
        self.timeout = float(timeout)
        self._session_snapshot_event_id: int | None = None
        self._session_snapshot_event_count: int | None = None
        self._seen_read_request_ids: set[str] = set()

    def reset_context(self) -> None:
        """Forget every snapshot-bound value before admitting a new owner intent."""

        self._session_snapshot_event_id = None
        self._session_snapshot_event_count = None
        self._seen_read_request_ids.clear()

    def bind_snapshot(self, snapshot_event_id: int, event_count: int) -> None:
        """Bind all event reads in this stdio session to one server snapshot."""

        if isinstance(snapshot_event_id, bool) or not isinstance(snapshot_event_id, int):
            raise McpFacadeError("session snapshot cursor must be a positive integer")
        if snapshot_event_id < 1:
            raise McpFacadeError("session snapshot cursor must be a positive integer")
        if isinstance(event_count, bool) or not isinstance(event_count, int) or event_count < 1:
            raise McpFacadeError("session snapshot event count must be a positive integer")
        if self._session_snapshot_event_id is None:
            self._session_snapshot_event_id = snapshot_event_id
            self._session_snapshot_event_count = event_count
            return
        if (
            self._session_snapshot_event_id != snapshot_event_id
            or self._session_snapshot_event_count != event_count
        ):
            raise McpFacadeError("Seed snapshot is already fixed for this session")

    def mind(self, arguments: dict[str, Any]) -> dict[str, Any]:
        """Project the existing Action Log Mind over the exact admitted snapshot."""

        if self._session_snapshot_event_id is None or self._session_snapshot_event_count is None:
            raise McpFacadeError("integrity_seed_snapshot admission is required before Mind Graph")
        _reject_unknown(arguments, {"intent", "limit", "_integrity_exact_prompt"})
        intent = arguments.get("intent")
        if not isinstance(intent, str) or not intent.strip():
            raise McpFacadeError("intent must be non-empty")
        exact_prompt = arguments.get("_integrity_exact_prompt", False)
        if not isinstance(exact_prompt, bool):
            raise McpFacadeError("exact prompt selector is invalid")
        segments = _full_prompt_segments(intent)
        limit = _integer(arguments, "limit", 20, 1, 50)
        if not exact_prompt and len(intent) <= 4_096 and len(segments) == 1:
            response = self.request(
                "GET",
                "/api/mind",
                query={
                    "q": intent.strip(),
                    "compact": "true",
                    "limit": str(limit),
                    "snapshot_event_id": str(self._session_snapshot_event_id),
                },
            )
        else:
            response = self.request(
                "POST",
                "/api/mind",
                payload={
                    "q_segments": segments,
                    "compact": True,
                    "limit": limit,
                    "snapshot_event_id": self._session_snapshot_event_id,
                },
            )
        try:
            return admit_mind_companion(
                response,
                snapshot_event_id=self._session_snapshot_event_id,
                snapshot_event_count=self._session_snapshot_event_count,
            )
        except MindAdmissionError as exc:
            raise McpFacadeError(str(exc)) from exc

    def request(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, str] | None = None,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if method not in {"GET", "POST"} or not path.startswith("/"):
            raise McpFacadeError("invalid Action Log request")
        url = self.base_url + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        body = canonical_json(payload) if payload is not None else None
        try:
            headers = {
                "Accept": "application/json",
                **action_log_reader_headers(self._auth_token),
            }
        except ActionLogReaderAuthError as exc:
            raise McpFacadeError(str(exc)) from exc
        if body is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            response = open_action_log_reader_request(request, timeout=self.timeout)
            with response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except ActionLogReaderTransportError as exc:
            raise McpFacadeError(str(exc)) from exc
        except urllib.error.HTTPError as exc:
            raise McpFacadeError(f"Action Log rejected request with HTTP {exc.code}") from exc
        except (OSError, TimeoutError, urllib.error.URLError) as exc:
            raise McpFacadeError("Action Log is unavailable") from exc
        if len(raw) > MAX_RESPONSE_BYTES:
            raise McpFacadeError("Action Log response exceeds the facade limit")
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise McpFacadeError("Action Log returned invalid JSON") from exc
        if not isinstance(value, dict):
            raise McpFacadeError("Action Log response must be an object")
        return value

    def read(self, arguments: dict[str, Any]) -> dict[str, Any]:
        if self._session_snapshot_event_id is None:
            raise McpFacadeError("integrity_seed_snapshot admission is required before Seed reads")
        _reject_unknown(arguments, {"page_size", "after_id", "snapshot_event_id"})
        page_size = _integer(arguments, "page_size", 50, 1, MAX_EVENT_PAGE_SIZE)
        after_id = _integer(arguments, "after_id", 0, 0, 2**63 - 1)
        requested_snapshot_event_id = _integer(arguments, "snapshot_event_id", 0, 0, 2**63 - 1)
        snapshot_event_id = self._session_snapshot_event_id
        if requested_snapshot_event_id not in {0, snapshot_event_id}:
            raise McpFacadeError("client snapshot cursor does not match session admission")
        request_identity = _sha256_hex(
            {
                "page_size": page_size,
                "after_id": after_id,
                "snapshot_event_id": snapshot_event_id,
            }
        )
        if request_identity in self._seen_read_request_ids:
            raise McpFacadeError("duplicate Seed page read denied in this session")
        query = {
            "since": "all",
            "order": "asc",
            "sort": "id",
            "page_size": str(page_size),
            "after_id": str(after_id),
            "snapshot_event_id": str(snapshot_event_id),
        }
        response = self.request("GET", "/api/events", query=query)
        events, pagination = response.get("events"), response.get("pagination")
        if (
            not response.get("ok")
            or not isinstance(events, list)
            or not isinstance(pagination, dict)
        ):
            raise McpFacadeError("Action Log returned an invalid event page")
        returned_snapshot_event_id = pagination.get("snapshot_event_id")
        if (
            isinstance(returned_snapshot_event_id, bool)
            or not isinstance(returned_snapshot_event_id, int)
            or returned_snapshot_event_id != snapshot_event_id
        ):
            raise McpFacadeError("Action Log response escaped the session snapshot")
        self._seen_read_request_ids.add(request_identity)
        receipt = {
            "protocol": BRIDGE_PROTOCOL + "/read-receipt",
            "source_label": SOURCE_LABEL,
            "memory_source": "canonical-seed-action-log",
            "observed_utc": _utc_now(),
            "request_sha256": request_identity,
            "returned_count": len(events),
            "first_event_id": int(events[0].get("id") or 0) if events else 0,
            "last_event_id": int(events[-1].get("id") or 0) if events else 0,
            "snapshot_event_id": int(pagination.get("snapshot_event_id") or 0),
            "next_after_id": int(pagination.get("next_after_id") or 0),
            "has_more": bool(pagination.get("has_more")),
        }
        _audit(receipt)
        return {"events": events, "pagination": pagination, "receipt": receipt}

    def prepare_append(
        self,
        arguments: dict[str, Any],
        *,
        route_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        _reject_unknown(arguments, {"event_uid", "kind", "summary", "details", "tags"})
        event_uid = arguments.get("event_uid")
        if not isinstance(event_uid, str) or not EVENT_UID_RE.fullmatch(event_uid):
            raise McpFacadeError("event_uid must be a bounded immutable client: identity")
        kind = arguments.get("kind")
        if kind not in EVENT_KINDS:
            raise McpFacadeError("kind must be one of: concept, task, thought")
        summary = arguments.get("summary")
        if not isinstance(summary, str) or not summary.strip() or len(summary) > 2_000:
            raise McpFacadeError("summary must contain 1 to 2000 characters")
        details = arguments.get("details", {})
        if not isinstance(details, dict) or RESERVED_DETAILS_KEY in details:
            raise McpFacadeError("details must be an object without the reserved marker")
        if len(canonical_json(details)) > MAX_DETAILS_BYTES:
            raise McpFacadeError("details exceed the facade limit")
        raw_tags = arguments.get("tags", [])
        if (
            not isinstance(raw_tags, list)
            or len(raw_tags) > 20
            or not all(isinstance(tag, str) and 1 <= len(tag.strip()) <= 80 for tag in raw_tags)
        ):
            raise McpFacadeError("tags must be a bounded string array")
        tags = list(
            dict.fromkeys(
                [*(tag.strip() for tag in raw_tags), SOURCE_LABEL, "medor", "remote-append", kind]
            )
        )
        normalized = {
            "event_uid": event_uid,
            "kind": kind,
            "summary": summary.strip(),
            "details": details,
            "tags": tags,
        }
        request_sha256 = _sha256_hex(normalized)
        stored_details = dict(details)
        stored_details[RESERVED_DETAILS_KEY] = {
            "schema_version": 1,
            "source_label": SOURCE_LABEL,
            "source_protocol": BRIDGE_PROTOCOL,
            "kind": kind,
            "immutable_event_uid": event_uid,
            "request_sha256": request_sha256,
        }
        if route_context is not None:
            legacy_fields = {
                "architecture_admission_id",
                "route_digest",
                "security_admission_id",
            }
            bound_fields = {
                *legacy_fields,
                "context_admission_id",
                "logical_generation",
            }
            digest_fields = legacy_fields | {"context_admission_id"}
            route_fields = frozenset(route_context)
            if route_fields not in {frozenset(legacy_fields), frozenset(bound_fields)}:
                raise McpFacadeError("event append route context is invalid")
            if any(
                not isinstance(route_context.get(field), str)
                or not re.fullmatch(r"sha256:[a-f0-9]{64}", route_context[field])
                for field in digest_fields & route_fields
            ):
                raise McpFacadeError("event append route context is invalid")
            generation = route_context.get("logical_generation")
            if "logical_generation" in route_context and (
                isinstance(generation, bool) or not isinstance(generation, int) or generation < 1
            ):
                raise McpFacadeError("event append route context is invalid")
            stored_details[RESERVED_DETAILS_KEY]["uroboros"] = dict(route_context)
        return {
            "event_uid": event_uid,
            "kind": kind,
            "request_sha256": request_sha256,
            "payload": {
                "event_uid": event_uid,
                "actor": "medor-client",
                "session_id": "client-memory-mcp",
                "level": "info",
                "action": f"medor_{kind}_create",
                "summary": summary.strip(),
                "details": stored_details,
                "tags": tags,
            },
        }

    def append_prepared(self, prepared: dict[str, Any]) -> dict[str, Any]:
        if set(prepared) != {"event_uid", "kind", "request_sha256", "payload"}:
            raise McpFacadeError("prepared event append is invalid")
        event_uid = prepared["event_uid"]
        request_sha256 = prepared["request_sha256"]
        response = self.request(
            "POST",
            "/api/events",
            payload=prepared["payload"],
        )
        marker = response.get("details", {}).get(RESERVED_DETAILS_KEY, {})
        if marker.get("request_sha256") != request_sha256:
            raise McpFacadeError("event_uid collides with different immutable content")
        event_id = response.get("id")
        if not response.get("ok") or isinstance(event_id, bool) or not isinstance(event_id, int):
            raise McpFacadeError("Action Log did not confirm append")
        receipt = {
            "protocol": BRIDGE_PROTOCOL + "/append-receipt",
            "source_label": SOURCE_LABEL,
            "observed_utc": _utc_now(),
            "event_uid": event_uid,
            "event_id": event_id,
            "request_sha256": request_sha256,
            "outcome": "duplicate" if response.get("duplicate") else "created",
        }
        _audit(receipt)
        return {"receipt": receipt}

    def append(self, arguments: dict[str, Any]) -> dict[str, Any]:
        return self.append_prepared(self.prepare_append(arguments))


class SqliteActionLogWitness:
    """Independent read-only event-UID witness over the canonical SQLite store."""

    def __init__(self, database_path: Path) -> None:
        if not database_path.is_absolute() or database_path.is_symlink():
            raise McpFacadeError("Action Log witness path is unsafe")
        flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            self._descriptor = os.open(database_path, flags)
        except OSError as exc:
            raise McpFacadeError("Action Log witness database is unavailable") from exc
        details = os.fstat(self._descriptor)
        linked = database_path.stat()
        if (
            not stat.S_ISREG(details.st_mode)
            or (details.st_dev, details.st_ino) != (linked.st_dev, linked.st_ino)
            or stat.S_IMODE(details.st_mode) & 0o002
        ):
            os.close(self._descriptor)
            raise McpFacadeError("Action Log witness database custody is unsafe")
        self._database_path = database_path
        self._device_inode = (details.st_dev, details.st_ino)
        self._companion_bindings: list[tuple[Path, int, tuple[int, int]]] = []
        try:
            self._connection = sqlite3.connect(f"file:{database_path}?mode=ro", uri=True)
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA query_only = ON")
            journal_mode = str(
                self._connection.execute("PRAGMA journal_mode").fetchone()[0]
            ).casefold()
            if journal_mode == "wal":
                for suffix in ("-wal", "-shm"):
                    companion = Path(str(database_path) + suffix)
                    if companion.is_symlink():
                        raise McpFacadeError("Action Log witness companion is unsafe")
                    descriptor = os.open(companion, flags)
                    companion_details = os.fstat(descriptor)
                    linked_companion = companion.stat()
                    if (
                        not stat.S_ISREG(companion_details.st_mode)
                        or (companion_details.st_dev, companion_details.st_ino)
                        != (linked_companion.st_dev, linked_companion.st_ino)
                        or stat.S_IMODE(companion_details.st_mode) & 0o002
                    ):
                        os.close(descriptor)
                        raise McpFacadeError("Action Log witness companion custody is unsafe")
                    self._companion_bindings.append(
                        (
                            companion,
                            descriptor,
                            (companion_details.st_dev, companion_details.st_ino),
                        )
                    )
        except Exception:
            for _path, descriptor, _identity in self._companion_bindings:
                os.close(descriptor)
            os.close(self._descriptor)
            raise

    def close(self) -> None:
        connection = getattr(self, "_connection", None)
        if connection is not None:
            connection.close()
            self._connection = None
        descriptor = getattr(self, "_descriptor", None)
        if descriptor is not None:
            os.close(descriptor)
            self._descriptor = None
        companions = getattr(self, "_companion_bindings", [])
        for _path, companion_descriptor, _identity in companions:
            os.close(companion_descriptor)
        self._companion_bindings = []

    def observe(self, *, event_uid: str, request_sha256: str) -> dict[str, Any]:
        if self._connection is None or self._descriptor is None:
            raise McpFacadeError("Action Log witness is closed")
        if self._database_path.is_symlink():
            raise McpFacadeError("Action Log witness binding changed")
        descriptor = os.fstat(self._descriptor)
        linked = self._database_path.stat()
        if (
            (descriptor.st_dev, descriptor.st_ino) != self._device_inode
            or (linked.st_dev, linked.st_ino) != self._device_inode
            or stat.S_IMODE(linked.st_mode) & 0o002
            or self._connection.execute("PRAGMA query_only").fetchone()[0] != 1
        ):
            raise McpFacadeError("Action Log witness binding changed")
        for path, companion_descriptor, identity in self._companion_bindings:
            if path.is_symlink():
                raise McpFacadeError("Action Log witness binding changed")
            descriptor_details = os.fstat(companion_descriptor)
            linked_details = path.stat()
            if (
                (descriptor_details.st_dev, descriptor_details.st_ino) != identity
                or (linked_details.st_dev, linked_details.st_ino) != identity
                or stat.S_IMODE(linked_details.st_mode) & 0o002
            ):
                raise McpFacadeError("Action Log witness binding changed")
        rows = list(
            self._connection.execute(
                "SELECT id, event_uid, details FROM events WHERE event_uid = ? LIMIT 2",
                (event_uid,),
            )
        )
        if not rows:
            return {
                "status": "absent",
                "event_uid": event_uid,
                "event_id": 0,
                "request_sha256": request_sha256,
                "observed_record_digest": _sha256([]),
            }
        if len(rows) != 1:
            raise McpFacadeError("Action Log witness found duplicate event UID rows")
        row = rows[0]
        try:
            details = json.loads(row["details"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise McpFacadeError("Action Log witness details are invalid") from exc
        marker = details.get(RESERVED_DETAILS_KEY, {}) if isinstance(details, dict) else {}
        actual = marker.get("request_sha256") if isinstance(marker, dict) else None
        event_id = row["id"]
        if isinstance(event_id, bool) or not isinstance(event_id, int) or event_id < 1:
            raise McpFacadeError("Action Log witness event identity is invalid")
        status = "exact" if actual == request_sha256 else "collision"
        return {
            "status": status,
            "event_uid": event_uid,
            "event_id": event_id,
            "request_sha256": request_sha256,
            "observed_record_digest": _sha256(
                {
                    "event_id": event_id,
                    "event_uid": row["event_uid"],
                    "stored_request_sha256": actual,
                }
            ),
        }


class RestrictedActionLogWitnessClient:
    """One-shot, content-free witness through an exact sudo forced helper.

    The bridge principal never receives SQLite custody.  Each observation is a
    fresh process owned by the canonical Action Log principal, so a WAL that is
    created or checkpointed between observations cannot be silently missed by
    a long-lived read-only SQLite connection.
    """

    def __init__(
        self,
        command: tuple[str, ...] = DEFAULT_ACTION_WITNESS_HELPER,
    ) -> None:
        if command != DEFAULT_ACTION_WITNESS_HELPER and not self._is_release_command(command):
            raise McpFacadeError(
                "only a fixed or immutable-release Action Log witness helper is supported"
            )
        self.command = command

    @classmethod
    def for_release_helper(cls, helper: Path) -> RestrictedActionLogWitnessClient:
        """Bind the witness to one immutable, root-custodied release helper."""

        helper_text = str(helper)
        if not RELEASE_ACTION_WITNESS_RE.fullmatch(helper_text):
            raise McpFacadeError("Action Log witness release path is invalid")
        release = helper.parent
        for custody_path in (
            Path("/opt"),
            Path("/opt/integrity-client-memory-lts"),
            Path("/opt/integrity-client-memory-lts/releases"),
            release,
            helper,
        ):
            try:
                metadata = custody_path.lstat()
            except OSError as exc:
                raise McpFacadeError("Action Log witness release custody is unavailable") from exc
            expected_kind = stat.S_ISREG if custody_path == helper else stat.S_ISDIR
            if (
                custody_path.is_symlink()
                or not expected_kind(metadata.st_mode)
                or metadata.st_uid != 0
                or metadata.st_gid != 0
                or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            ):
                raise McpFacadeError("Action Log witness release custody is invalid")
        if not os.access(helper, os.X_OK):
            raise McpFacadeError("Action Log witness release helper is not executable")
        command = (
            "/usr/bin/sudo",
            "-n",
            "-u",
            "codex-action-log",
            "--",
            helper_text,
        )
        client = cls(command)
        client.require_ready()
        return client

    def require_ready(self) -> dict[str, Any]:
        "Prove the fixed sudo/helper path before advertising witness readiness."

        observed = self.observe(
            event_uid=ACTION_WITNESS_READINESS_EVENT_UID,
            request_sha256=ACTION_WITNESS_READINESS_REQUEST_SHA256,
        )
        receipt = {
            "protocol": BRIDGE_PROTOCOL + "/action-witness-readiness/v1",
            "source_label": SOURCE_LABEL,
            "observed_utc": _utc_now(),
            "outcome": "ready",
            "witness_status": observed["status"],
            "observed_record_digest": observed["observed_record_digest"],
            "canonical_writes": 0,
            "production_authority": False,
        }
        _audit(receipt)
        return receipt

    @staticmethod
    def _is_release_command(command: tuple[str, ...]) -> bool:
        return (
            len(command) == 6
            and command[:5] == ("/usr/bin/sudo", "-n", "-u", "codex-action-log", "--")
            and bool(RELEASE_ACTION_WITNESS_RE.fullmatch(command[5]))
        )

    def close(self) -> None:
        return None

    def observe(self, *, event_uid: str, request_sha256: str) -> dict[str, Any]:
        if not EVENT_UID_RE.fullmatch(event_uid):
            raise McpFacadeError("Action Log witness event_uid is invalid")
        if not re.fullmatch(r"[a-f0-9]{64}", request_sha256):
            raise McpFacadeError("Action Log witness request digest is invalid")
        request = canonical_json({"event_uid": event_uid, "request_sha256": request_sha256}) + b"\n"
        try:
            completed = subprocess.run(
                self.command,
                input=request,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise McpFacadeError("Action Log passive witness is unavailable") from exc
        if completed.returncode != 0 or not completed.stdout:
            raise McpFacadeError("Action Log passive witness denied the observation")
        if len(completed.stdout) > 4_096:
            raise McpFacadeError("Action Log passive witness response is oversized")
        try:
            value = json.loads(completed.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise McpFacadeError("Action Log passive witness returned invalid JSON") from exc
        if not isinstance(value, dict) or set(value) != {
            "status",
            "event_uid",
            "event_id",
            "request_sha256",
            "observed_record_digest",
        }:
            raise McpFacadeError("Action Log passive witness response shape is invalid")
        if (
            value["status"] not in {"absent", "exact", "collision"}
            or value["event_uid"] != event_uid
            or value["request_sha256"] != request_sha256
            or isinstance(value["event_id"], bool)
            or not isinstance(value["event_id"], int)
            or value["event_id"] < 0
            or (value["status"] == "absent" and value["event_id"] != 0)
            or (value["status"] != "absent" and value["event_id"] < 1)
            or not isinstance(value["observed_record_digest"], str)
            or not re.fullmatch(r"sha256:[a-f0-9]{64}", value["observed_record_digest"])
        ):
            raise McpFacadeError("Action Log passive witness response is invalid")
        return value


class HomeClient:
    """Exact-child, read-only Home client with no source path input surface."""

    def __init__(self, command: tuple[str, ...] = DEFAULT_HOME_HELPER) -> None:
        if command != DEFAULT_HOME_HELPER:
            raise McpFacadeError("only the fixed Home helper command is supported")
        self.command = command
        self.process: subprocess.Popen[bytes] | None = None
        self.next_id = 1000
        self.ready = False
        self._stdout_buffer = bytearray()

    def close(self) -> None:
        process, self.process, self.ready = self.process, None, False
        self._stdout_buffer.clear()
        if process is None:
            return
        try:
            if process.stdin:
                process.stdin.close()
            process.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            process.kill()
            try:
                process.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                pass
        finally:
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is None or stream.closed:
                    continue
                try:
                    stream.close()
                except OSError:
                    pass

    def reset_context(self) -> None:
        """Drop helper/session state between logical owner intents."""

        self.close()
        self.next_id = 1000

    def _request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if self.process is None:
            try:
                self.process = subprocess.Popen(
                    self.command,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                )
                assert self.process.stdout is not None
                os.set_blocking(self.process.stdout.fileno(), False)
            except OSError as exc:
                raise McpFacadeError("Home adapter is unavailable") from exc
        assert self.process.stdin is not None and self.process.stdout is not None
        request_id, self.next_id = self.next_id, self.next_id + 1
        self.process.stdin.write(
            canonical_json({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
            + b"\n"
        )
        self.process.stdin.flush()
        raw = self._readline_bounded()
        if not raw or len(raw) > MAX_HOME_RESPONSE_BYTES:
            self.close()
            raise McpFacadeError("Home adapter returned no bounded response")
        try:
            response = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise McpFacadeError("Home adapter returned invalid JSON") from exc
        if (
            not isinstance(response, dict)
            or response.get("id") != request_id
            or response.get("error") is not None
        ):
            raise McpFacadeError("Home adapter rejected the request")
        result = response.get("result")
        if not isinstance(result, dict):
            raise McpFacadeError("Home adapter returned an invalid result")
        return result

    def _readline_bounded(self) -> bytes:
        if self.process is None or self.process.stdout is None:
            raise McpFacadeError("Home adapter is unavailable")
        descriptor = self.process.stdout.fileno()
        deadline = time.monotonic() + HOME_CHILD_TIMEOUT_SECONDS
        with selectors.DefaultSelector() as selector:
            selector.register(descriptor, selectors.EVENT_READ)
            while True:
                newline = self._stdout_buffer.find(b"\n")
                if newline >= 0:
                    raw = bytes(self._stdout_buffer[: newline + 1])
                    del self._stdout_buffer[: newline + 1]
                    return raw
                if len(self._stdout_buffer) > MAX_HOME_RESPONSE_BYTES:
                    self.close()
                    raise McpFacadeError("Home adapter response exceeds the facade limit")
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    self.close()
                    raise McpFacadeError("Home adapter response timed out")
                try:
                    chunk = os.read(descriptor, min(65_536, MAX_HOME_RESPONSE_BYTES + 1))
                except BlockingIOError:
                    continue
                if not chunk:
                    self.close()
                    raise McpFacadeError("Home adapter closed its response stream")
                self._stdout_buffer.extend(chunk)

    def ensure_ready(self) -> None:
        if self.ready:
            return
        initialized = self._request(
            "initialize",
            {
                "protocolVersion": DEFAULT_MCP_VERSION,
                "capabilities": {},
                "clientInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            },
        )
        if initialized.get("serverInfo", {}).get("name") != "integrity-client-home":
            raise McpFacadeError("Home adapter identity mismatch")
        tools = self._request("tools/list", {}).get("tools")
        if not isinstance(tools, list) or [item.get("name") for item in tools] != [
            "search",
            "fetch",
        ]:
            raise McpFacadeError("Home adapter tool contract changed")
        if not all(
            item.get("annotations", {}).get("readOnlyHint") is True
            and item.get("annotations", {}).get("destructiveHint") is False
            for item in tools
        ):
            raise McpFacadeError("Home adapter lost its read-only boundary")
        self.ready = True

    def call(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self.ensure_ready()
        result = self._request("tools/call", {"name": name, "arguments": arguments})
        if result.get("isError"):
            raise McpFacadeError("Home adapter denied the read")
        content = result.get("content")
        if not isinstance(content, list) or len(content) != 1 or content[0].get("type") != "text":
            raise McpFacadeError("Home adapter returned invalid content")
        text = content[0].get("text")
        if not isinstance(text, str) or len(text.encode("utf-8")) > MAX_HOME_RESPONSE_BYTES:
            raise McpFacadeError("Home adapter content is unbounded")
        value = json.loads(text)
        if not isinstance(value, dict):
            raise McpFacadeError("Home adapter content is invalid")
        return value


class MemorySynapseMcp:
    """One stdio-only facade instance with fixed server-side dependencies."""

    def __init__(
        self,
        lts: MemorySynapseLtsService,
        *,
        action_log: ActionLogClient | None = None,
        home: HomeClient | None = None,
        architecture: PersistentMedorArchitectureService | None = None,
        action_witness: SqliteActionLogWitness | RestrictedActionLogWitnessClient | None = None,
        security_admission: VerifiedMedorSecurityAdmission | None = None,
        write_plane_status: dict[str, str] | None = None,
        snapshot_source: Path | None = None,
        snapshot_root: Path | None = None,
        native_trust: NativeTrustStore | None = None,
        native_device_id: str | None = None,
        turn_memory: TurnMemoryStore | None = None,
        memory_ttt_path_catalog: RunbookPathCatalog | None = None,
        write_plane_reinitializer: Callable[[], WritePlaneRuntime] | None = None,
        write_plane_recovery_initial_cooldown_seconds: float = (
            WRITE_PLANE_RECOVERY_INITIAL_COOLDOWN_SECONDS
        ),
        write_plane_recovery_max_cooldown_seconds: float = (
            WRITE_PLANE_RECOVERY_MAX_COOLDOWN_SECONDS
        ),
        monotonic_clock: Callable[[], float] = time.monotonic,
        audit: Callable[[dict[str, Any]], None] = _audit,
    ) -> None:
        self.lts = lts
        self._base_lts = lts
        self.action_log = action_log or ActionLogClient()
        self.home = home or HomeClient()
        self.architecture = architecture
        self.action_witness = action_witness
        if security_admission is not None:
            try:
                security_admission = require_verified_medor_security_admission(security_admission)
            except ValueError as exc:
                raise McpFacadeError("verified Security Harness admission is required") from exc
        self.security_admission = security_admission
        self.write_plane_status = dict(
            write_plane_status
            or {
                "outcome": (
                    "ready"
                    if architecture is not None
                    and action_witness is not None
                    and security_admission is not None
                    else "unavailable"
                ),
                "architecture": "ready" if architecture is not None else "unavailable",
                "action_witness": "ready" if action_witness is not None else "unavailable",
                "security_admission": (
                    "ready" if security_admission is not None else "unavailable"
                ),
            }
        )
        if (native_trust is None) != (native_device_id is None):
            raise McpFacadeError(
                "native trust store and authenticated device must be configured together"
            )
        self.native_trust = native_trust
        self.native_device_id = native_device_id
        self.turn_memory = turn_memory
        configured_ttt = memory_ttt_path_catalog or RunbookPathCatalog()
        configured_ttt.validate()
        self._memory_ttt_path_documents = tuple(
            path.as_public_dict() for path in configured_ttt.all_paths()
        )
        self._memory_ttt_path_catalog_digest = configured_ttt.source_digest
        if write_plane_reinitializer is not None and not callable(write_plane_reinitializer):
            raise McpFacadeError("write-plane reinitializer must be callable")
        if (
            isinstance(write_plane_recovery_initial_cooldown_seconds, bool)
            or not isinstance(write_plane_recovery_initial_cooldown_seconds, (int, float))
            or write_plane_recovery_initial_cooldown_seconds <= 0
            or isinstance(write_plane_recovery_max_cooldown_seconds, bool)
            or not isinstance(write_plane_recovery_max_cooldown_seconds, (int, float))
            or write_plane_recovery_max_cooldown_seconds
            < write_plane_recovery_initial_cooldown_seconds
            or not math.isfinite(float(write_plane_recovery_initial_cooldown_seconds))
            or not math.isfinite(float(write_plane_recovery_max_cooldown_seconds))
            or not callable(monotonic_clock)
        ):
            raise McpFacadeError("write-plane recovery timing is invalid")
        self._write_plane_reinitializer = write_plane_reinitializer
        self._write_plane_recovery_initial_cooldown_seconds = float(
            write_plane_recovery_initial_cooldown_seconds
        )
        self._write_plane_recovery_max_cooldown_seconds = float(
            write_plane_recovery_max_cooldown_seconds
        )
        self._write_plane_recovery_cooldown_seconds = (
            self._write_plane_recovery_initial_cooldown_seconds
        )
        self._write_plane_recovery_next_attempt_monotonic = 0.0
        self._monotonic_clock = monotonic_clock
        self.audit = audit
        if (snapshot_source is None) != (snapshot_root is None):
            raise McpFacadeError("Seed snapshot source and root must be configured together")
        self._snapshot_source = snapshot_source
        self._snapshot_root = snapshot_root
        if snapshot_root is not None:
            try:
                sweep_orphaned_seed_snapshots(snapshot_root)
            except (OSError, McpFacadeError):
                # Custody is re-checked on every freeze; a failed sweep only
                # leaves abandoned bytes and must not block the read plane.
                pass
        self._frozen_catalog: FrozenSeedCatalogSnapshot | RetainedSeedCatalogSnapshot | None = None
        self._session_capabilities: dict[str, Any] | None = None
        self._session_snapshot: dict[str, Any] | None = None
        self._session_mind: dict[str, Any] | None = None
        self._session_architecture: dict[str, Any] | None = None
        self._session_memory_link_graph: MemoryLinkGraph | None = None
        self._session_memory_ttt_path_catalog: RunbookPathCatalog | None = None
        self._native_session_lease: dict[str, Any] | None = None
        self._context_generation = 0
        self._context_admission_id: str | None = None
        self._tool_contract_profile = CURRENT_TOOL_CONTRACT_PROFILE
        self._session_write_plane_status = dict(self.write_plane_status)
        self._context_admission_replay_enabled = False
        self._context_admission_replay_control_enabled = False
        self._broker_tool_surface_authenticated = False
        architecture_root = getattr(architecture, "root", None)
        self._context_admission_replay_root = (
            Path(architecture_root) / "context-admission-replay-v2"
            if isinstance(architecture_root, (str, os.PathLike))
            else None
        )
        self._context_admission_replay_root_fd: int | None = None
        self._context_admission_replay_parent_fd: int | None = None
        self._context_admission_replay_anchor_fd: int | None = None
        self._context_admission_replay_root_identity: tuple[int, int, int, int, int] | None = None
        self._context_admission_replay_parent_identity: tuple[int, int, int, int, int] | None = None
        self._active_context_replay_id: str | None = None
        self._active_context_replay_deadline: float | None = None
        self._context_admission_replay_reservation_id: str | None = None
        self._context_admission_replay_catalog_budget = 0
        self._closed = False
        self._replay_migrations: dict[str, ReplayMigration] = {}

    def admit_replay_migration(self, admission: ReplayMigration) -> None:
        """Owner-only construction API; deliberately absent from MCP tools."""
        if self._context_admission_replay_enabled or self._session_snapshot is not None:
            raise McpFacadeError("migration must be admitted before protocol initialization")
        if not isinstance(admission, ReplayMigration) or self._context_admission_replay_root is None:
            raise McpFacadeError("explicit replay migration is required")
        try:
            admission.validate(self._context_admission_replay_root, self._base_lts._artifact_digest())
        except (ReplayMigrationError, OSError, KeyError, TypeError) as exc:
            raise McpFacadeError("replay migration admission is invalid") from exc
        if admission.request_id in self._replay_migrations:
            raise McpFacadeError("duplicate replay migration admission")
        self._replay_migrations[admission.request_id] = admission

    def _replay_migration(self, replay_id: str) -> ReplayMigration | None:
        admission = self._replay_migrations.get(replay_id)
        if admission is not None:
            try:
                admission.validate(self._context_admission_replay_root, self._base_lts._artifact_digest())
            except (ReplayMigrationError, OSError, KeyError, TypeError) as exc:
                raise McpFacadeError("replay migration no longer matches its admission") from exc
        return admission

    def _deny_migrated_action_authority(self) -> None:
        self._session_architecture = None
        self._native_session_lease = None
        self._mark_session_write_plane_unavailable("replay_migration")

    def _prospective_context_replay_catalog_budget(self) -> int | None:
        if self._snapshot_source is None:
            return 0
        if self._snapshot_root is None:
            return None
        source = self._snapshot_source
        destination_root = self._snapshot_root
        try:
            source_details = source.lstat()
            root_details = destination_root.lstat()
        except OSError:
            return None
        expected_uid = os.geteuid() if hasattr(os, "geteuid") else root_details.st_uid
        if (
            not source.is_absolute()
            or stat.S_ISLNK(source_details.st_mode)
            or not stat.S_ISREG(source_details.st_mode)
            or source_details.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or not destination_root.is_absolute()
            or stat.S_ISLNK(root_details.st_mode)
            or not stat.S_ISDIR(root_details.st_mode)
            or root_details.st_uid != expected_uid
            or stat.S_IMODE(root_details.st_mode) & 0o077
            or not 0 < source_details.st_size <= MAX_CONTEXT_ADMISSION_REPLAY_CATALOG_BYTES
        ):
            return None
        for suffix in ("-wal", "-shm"):
            companion = source.with_name(source.name + suffix)
            try:
                details = companion.lstat()
            except FileNotFoundError:
                continue
            except OSError:
                return None
            if (
                stat.S_ISLNK(details.st_mode)
                or not stat.S_ISREG(details.st_mode)
                or details.st_uid != source_details.st_uid
                or details.st_gid != source_details.st_gid
                or details.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                or (suffix == "-wal" and details.st_size != 0)
            ):
                return None
        growth_reserve = max(16 * 1_048_576, source_details.st_size // 2)
        return min(
            MAX_CONTEXT_ADMISSION_REPLAY_CATALOG_BYTES,
            source_details.st_size + growth_reserve,
        )

    def _reserve_context_admission_replay(self, replay_id: str) -> int | None:
        catalog_budget = self._prospective_context_replay_catalog_budget()
        if catalog_budget is None:
            return None
        reservation_deadline = (
            time.monotonic()
            + CONTEXT_ADMISSION_REPLAY_RESERVATION_OPERATION_TIMEOUT_SECONDS
        )
        reservation_name = self._context_replay_reservation_name(replay_id)
        replay_hex = replay_id.split(":", 1)[1]
        with self._context_replay_lock(
            replay_id,
            timeout_seconds=CONTEXT_ADMISSION_REPLAY_RESERVATION_TIMEOUT_SECONDS,
            deadline_monotonic=reservation_deadline,
        ), self._context_replay_maintenance_lock(
            timeout_seconds=(
                CONTEXT_ADMISSION_REPLAY_RESERVATION_OPERATION_TIMEOUT_SECONDS
            ),
            deadline_monotonic=reservation_deadline,
        ):
            total_bytes, record_count = self._context_replay_inventory(prune=True)
            existing = self._load_context_replay_reservation(replay_id)
            if existing is None and replay_id in self._replay_migrations:
                raise McpFacadeError("migrated replay reservation is absent or retired")
            if existing is not None:
                existing_budget = int(existing["catalog_bytes"])
                record_name = replay_hex + ".json"
                try:
                    os.stat(
                        record_name,
                        dir_fd=self._prepare_context_replay_custody(),
                        follow_symlinks=False,
                    )
                    established = True
                except FileNotFoundError:
                    established = False
                if established or existing_budget >= catalog_budget:
                    return existing_budget
                additional = catalog_budget - existing_budget
                if total_bytes + additional > MAX_CONTEXT_ADMISSION_REPLAY_TOTAL_BYTES:
                    return None
            elif (
                record_count + 1 > MAX_CONTEXT_ADMISSION_REPLAY_RECORDS
                or total_bytes
                + MAX_CONTEXT_ADMISSION_REPLAY_BYTES
                + catalog_budget
                + MAX_CONTEXT_ADMISSION_REPLAY_RESERVATION_BYTES
                > MAX_CONTEXT_ADMISSION_REPLAY_TOTAL_BYTES
            ):
                return None
            encoded = canonical_json(
                {
                    "protocol": CONTEXT_ADMISSION_REPLAY_RESERVATION_PROTOCOL,
                    "request_id": replay_id,
                    "record_bytes": MAX_CONTEXT_ADMISSION_REPLAY_BYTES,
                    "catalog_bytes": catalog_budget,
                }
            )
            if len(encoded) > MAX_CONTEXT_ADMISSION_REPLAY_RESERVATION_BYTES:
                raise McpFacadeError(
                    "context admission replay reservation exceeds budget"
                )
            root_descriptor = self._prepare_context_replay_custody()
            temporary = (
                f".{replay_hex}.json.{os.getpid()}.{time.monotonic_ns()}.tmp"
            )
            descriptor = os.open(
                temporary,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=root_descriptor,
            )
            try:
                offset = 0
                while offset < len(encoded):
                    offset += os.write(descriptor, encoded[offset:])
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            try:
                os.replace(
                    temporary,
                    reservation_name,
                    src_dir_fd=root_descriptor,
                    dst_dir_fd=root_descriptor,
                )
            finally:
                try:
                    os.unlink(temporary, dir_fd=root_descriptor)
                except FileNotFoundError:
                    pass
            os.fsync(root_descriptor)
            stored = self._load_context_replay_reservation(replay_id)
            if stored is None or int(stored["catalog_bytes"]) != catalog_budget:
                raise McpFacadeError(
                    "context admission replay reservation was not committed"
                )
            return catalog_budget

    def _supports_context_admission_replay(
        self,
        reservation_id: str | None = None,
    ) -> bool:
        if self._context_admission_replay_root is None or _fcntl is None:
            return False
        if reservation_id is not None:
            try:
                catalog_budget = self._reserve_context_admission_replay(
                    reservation_id
                )
            except (McpFacadeError, OSError):
                return False
            if catalog_budget is None:
                return False
            self._context_admission_replay_reservation_id = reservation_id
            self._context_admission_replay_catalog_budget = catalog_budget
            return True
        catalog_budget = self._prospective_context_replay_catalog_budget()
        if catalog_budget is None:
            return False
        try:
            self._prepare_context_replay_custody()
            with self._context_replay_maintenance_lock():
                total_bytes, record_count = self._context_replay_inventory(prune=True)
        except (McpFacadeError, OSError):
            return False
        return bool(
            record_count < MAX_CONTEXT_ADMISSION_REPLAY_RECORDS
            and total_bytes
            + MAX_CONTEXT_ADMISSION_REPLAY_BYTES
            + catalog_budget
            + MAX_CONTEXT_ADMISSION_REPLAY_RESERVATION_BYTES
            <= MAX_CONTEXT_ADMISSION_REPLAY_TOTAL_BYTES
        )

    def _supports_context_admission_replay_control(self) -> bool:
        if (
            self._context_admission_replay_root is None
            or _fcntl is None
        ):
            return False
        try:
            self._prepare_context_replay_custody()
        except (McpFacadeError, OSError):
            return False
        return True

    @staticmethod
    def _context_replay_root_identity(details: os.stat_result) -> tuple[int, int, int, int, int]:
        return (
            details.st_dev,
            details.st_ino,
            details.st_uid,
            details.st_gid,
            stat.S_IMODE(details.st_mode),
        )

    @staticmethod
    def _context_replay_record_identity(
        details: os.stat_result,
    ) -> tuple[int, int, int, int, int, int, int, int, int]:
        return (
            details.st_dev,
            details.st_ino,
            details.st_uid,
            details.st_gid,
            stat.S_IMODE(details.st_mode),
            details.st_nlink,
            details.st_size,
            details.st_mtime_ns,
            details.st_ctime_ns,
        )

    def _prepare_context_replay_custody(self) -> int:
        descriptor = self._context_admission_replay_root_fd
        parent_descriptor = self._context_admission_replay_parent_fd
        anchor_descriptor = self._context_admission_replay_anchor_fd
        identity = self._context_admission_replay_root_identity
        parent_identity = self._context_admission_replay_parent_identity
        root = self._context_admission_replay_root
        if (
            descriptor is not None
            and parent_descriptor is not None
            and anchor_descriptor is not None
            and identity is not None
            and parent_identity is not None
            and root is not None
        ):
            details = os.fstat(descriptor)
            parent_details = os.fstat(parent_descriptor)
            try:
                named = os.stat(root.name, dir_fd=parent_descriptor, follow_symlinks=False)
                named_parent = os.stat(
                    root.parent.name,
                    dir_fd=anchor_descriptor,
                    follow_symlinks=False,
                )
            except OSError as exc:
                raise McpFacadeError("context admission replay custody changed") from exc
            if (
                not stat.S_ISDIR(details.st_mode)
                or self._context_replay_root_identity(details) != identity
                or self._context_replay_root_identity(named) != identity
                or self._context_replay_root_identity(parent_details) != parent_identity
                or self._context_replay_root_identity(named_parent) != parent_identity
            ):
                raise McpFacadeError("context admission replay custody changed")
            return descriptor
        if root is None:
            raise McpFacadeError("context admission durable replay is unavailable")
        parent_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        anchor_descriptor = os.open(root.parent.parent, parent_flags)
        parent_descriptor: int | None = None
        try:
            parent_before = os.stat(
                root.parent.name,
                dir_fd=anchor_descriptor,
                follow_symlinks=False,
            )
            parent_descriptor = os.open(
                root.parent.name,
                parent_flags,
                dir_fd=anchor_descriptor,
            )
            parent_details = os.fstat(parent_descriptor)
            expected_uid = os.geteuid() if hasattr(os, "geteuid") else parent_details.st_uid
            if (
                not stat.S_ISDIR(parent_before.st_mode)
                or not stat.S_ISDIR(parent_details.st_mode)
                or parent_before.st_dev != parent_details.st_dev
                or parent_before.st_ino != parent_details.st_ino
                or parent_details.st_uid != expected_uid
                or stat.S_IMODE(parent_details.st_mode) & 0o022
            ):
                raise McpFacadeError("context admission replay parent custody is not private")
        except Exception:
            if parent_descriptor is not None:
                os.close(parent_descriptor)
            os.close(anchor_descriptor)
            raise
        assert parent_descriptor is not None
        try:
            try:
                os.mkdir(root.name, 0o700, dir_fd=parent_descriptor)
            except FileExistsError:
                pass
            before = os.stat(root.name, dir_fd=parent_descriptor, follow_symlinks=False)
            try:
                root_descriptor = os.open(root.name, parent_flags, dir_fd=parent_descriptor)
            except OSError as exc:
                raise McpFacadeError(
                    "context admission replay custody is not private"
                ) from exc
        except Exception:
            os.close(parent_descriptor)
            os.close(anchor_descriptor)
            raise
        try:
            details = os.fstat(root_descriptor)
            expected_uid = os.geteuid() if hasattr(os, "geteuid") else details.st_uid
            if (
                stat.S_ISLNK(before.st_mode)
                or not stat.S_ISDIR(before.st_mode)
                or not stat.S_ISDIR(details.st_mode)
                or before.st_dev != details.st_dev
                or before.st_ino != details.st_ino
                or details.st_uid != expected_uid
                or stat.S_IMODE(details.st_mode) != 0o700
            ):
                raise McpFacadeError("context admission replay custody is not private")
            self._context_admission_replay_anchor_fd = anchor_descriptor
            self._context_admission_replay_parent_fd = parent_descriptor
            self._context_admission_replay_parent_identity = self._context_replay_root_identity(
                parent_details
            )
            self._context_admission_replay_root_fd = root_descriptor
            self._context_admission_replay_root_identity = self._context_replay_root_identity(
                details
            )
            return root_descriptor
        except Exception:
            os.close(root_descriptor)
            os.close(parent_descriptor)
            os.close(anchor_descriptor)
            raise

    def _open_context_replay_lock_file(self, name: str) -> int:
        if _fcntl is None:
            raise McpFacadeError("context admission replay locking is unavailable")
        root_descriptor = self._prepare_context_replay_custody()
        try:
            descriptor = os.open(
                name,
                os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=root_descriptor,
            )
        except OSError as exc:
            raise McpFacadeError("context admission replay lock is invalid") from exc
        try:
            details = os.fstat(descriptor)
            expected_uid = os.geteuid() if hasattr(os, "geteuid") else details.st_uid
            if (
                not stat.S_ISREG(details.st_mode)
                or details.st_uid != expected_uid
                or stat.S_IMODE(details.st_mode) != 0o600
                or details.st_nlink != 1
                or details.st_size != 0
            ):
                raise McpFacadeError("context admission replay lock is invalid")
            return descriptor
        except Exception:
            os.close(descriptor)
            raise

    @contextmanager
    def _context_replay_file_lock(
        self,
        name: str,
        *,
        timeout_seconds: float,
        deadline_monotonic: float | None = None,
    ):
        descriptor = self._open_context_replay_lock_file(name)
        try:
            deadline = time.monotonic() + timeout_seconds
            if deadline_monotonic is not None:
                deadline = min(deadline, deadline_monotonic)
            while True:
                try:
                    _fcntl.flock(descriptor, _fcntl.LOCK_EX | _fcntl.LOCK_NB)
                    break
                except BlockingIOError as exc:
                    if time.monotonic() >= deadline:
                        raise McpFacadeError(
                            "context admission replay lock wait exceeded budget"
                        ) from exc
                    time.sleep(0.05)
            self._prepare_context_replay_custody()
            yield
        finally:
            try:
                _fcntl.flock(descriptor, _fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    @contextmanager
    def _context_replay_maintenance_lock(
        self,
        *,
        timeout_seconds: float | None = None,
        deadline_monotonic: float | None = None,
    ):
        effective_deadline = self._active_context_replay_deadline
        if deadline_monotonic is not None:
            effective_deadline = (
                deadline_monotonic
                if effective_deadline is None
                else min(effective_deadline, deadline_monotonic)
            )
        with self._context_replay_file_lock(
            ".replay-maintenance.lock",
            timeout_seconds=(
                CONTEXT_ADMISSION_REPLAY_LOCK_TIMEOUT_SECONDS
                if timeout_seconds is None
                else timeout_seconds
            ),
            deadline_monotonic=effective_deadline,
        ):
            yield

    @contextmanager
    def _context_replay_gc_shard_lock(self, replay_hex: str):
        """Probe a candidate shard without inverting shard -> maintenance order."""

        if re.fullmatch(r"[a-f0-9]{64}", replay_hex) is None:
            raise McpFacadeError("context admission replay identity is invalid")
        descriptor = self._open_context_replay_lock_file(
            f".replay-lock-{replay_hex[:2]}"
        )
        acquired = False
        try:
            try:
                _fcntl.flock(descriptor, _fcntl.LOCK_EX | _fcntl.LOCK_NB)
                acquired = True
            except BlockingIOError:
                yield False
                return
            self._prepare_context_replay_custody()
            yield True
        finally:
            if acquired:
                _fcntl.flock(descriptor, _fcntl.LOCK_UN)
            os.close(descriptor)

    @staticmethod
    def _context_replay_reservation_name(replay_id: str) -> str:
        if re.fullmatch(r"sha256:[a-f0-9]{64}", replay_id) is None:
            raise McpFacadeError("context admission replay identity is invalid")
        return replay_id.split(":", 1)[1] + ".reservation.json"

    def _load_context_replay_reservation(
        self,
        replay_id: str,
    ) -> dict[str, Any] | None:
        name = self._context_replay_reservation_name(replay_id)
        root_descriptor = self._prepare_context_replay_custody()
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=root_descriptor,
            )
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise McpFacadeError(
                "context admission replay reservation is invalid"
            ) from exc
        try:
            details = os.fstat(descriptor)
            expected_uid = os.geteuid() if hasattr(os, "geteuid") else details.st_uid
            if (
                not stat.S_ISREG(details.st_mode)
                or details.st_uid != expected_uid
                or stat.S_IMODE(details.st_mode) != 0o600
                or details.st_nlink != 1
                or not 0 < details.st_size <= MAX_CONTEXT_ADMISSION_REPLAY_RESERVATION_BYTES
            ):
                raise McpFacadeError(
                    "context admission replay reservation is invalid"
                )
            encoded = os.read(
                descriptor,
                MAX_CONTEXT_ADMISSION_REPLAY_RESERVATION_BYTES + 1,
            )
            if (
                len(encoded) != details.st_size
                or self._context_replay_record_identity(os.fstat(descriptor))
                != self._context_replay_record_identity(details)
            ):
                raise McpFacadeError(
                    "context admission replay reservation changed while reading"
                )
        finally:
            os.close(descriptor)
        try:
            reservation = json.loads(encoded)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise McpFacadeError(
                "context admission replay reservation is invalid"
            ) from exc
        migration = self._replay_migration(replay_id)
        source_admitted = bool(migration and migration.accepts_source("reservation", encoded))
        if migration is not None and not source_admitted:
            raise McpFacadeError("migrated reservation bytes changed")
        if (
            not isinstance(reservation, dict)
            or (reservation.get("protocol")
                != CONTEXT_ADMISSION_REPLAY_RESERVATION_PROTOCOL and not source_admitted)
            or reservation.get("request_id") != replay_id
            or isinstance(reservation.get("record_bytes"), bool)
            or reservation.get("record_bytes") != MAX_CONTEXT_ADMISSION_REPLAY_BYTES
            or isinstance(reservation.get("catalog_bytes"), bool)
            or not isinstance(reservation.get("catalog_bytes"), int)
            or not 0
            <= reservation["catalog_bytes"]
            <= MAX_CONTEXT_ADMISSION_REPLAY_CATALOG_BYTES
        ):
            raise McpFacadeError("context admission replay reservation is invalid")
        return reservation

    def _context_replay_inventory(self, *, prune: bool) -> tuple[int, int]:
        """Validate bounded replay custody and optionally collect expired debris."""

        # An explicit handover must not turn a failed validation into TTL
        # deletion of predecessor evidence. ACK still retires exact active files.
        if self._replay_migrations:
            prune = False
        root_descriptor = self._prepare_context_replay_custody()
        expected_uid = os.geteuid() if hasattr(os, "geteuid") else os.fstat(
            root_descriptor
        ).st_uid
        now = time.time()
        changed = False
        record_pattern = re.compile(r"^(?P<id>[a-f0-9]{64})\.json$")
        catalog_pattern = re.compile(r"^(?P<id>[a-f0-9]{64})\.catalog\.sqlite3$")
        reservation_pattern = re.compile(
            r"^(?P<id>[a-f0-9]{64})\.reservation\.json$"
        )
        temporary_pattern = re.compile(
            r"^\.(?P<id>[a-f0-9]{64})\.(?P<kind>json|catalog\.sqlite3)\."
            r"[0-9]+\.[0-9]+\.tmp$"
        )
        lock_pattern = re.compile(r"^\.replay-lock-[a-f0-9]{2}$")

        def details_for(name: str) -> os.stat_result:
            try:
                details = os.stat(name, dir_fd=root_descriptor, follow_symlinks=False)
            except OSError as exc:
                raise McpFacadeError(
                    "context admission replay inventory changed"
                ) from exc
            if (
                not stat.S_ISREG(details.st_mode)
                or details.st_uid != expected_uid
                or stat.S_IMODE(details.st_mode) != 0o600
                or details.st_nlink != 1
            ):
                raise McpFacadeError("context admission replay inventory is unsafe")
            return details

        names = sorted(os.listdir(root_descriptor))
        for name in names:
            record_match = record_pattern.fullmatch(name)
            catalog_match = catalog_pattern.fullmatch(name)
            reservation_match = reservation_pattern.fullmatch(name)
            temporary_match = temporary_pattern.fullmatch(name)
            is_lock = name == ".replay-maintenance.lock" or lock_pattern.fullmatch(name)
            if not (
                record_match
                or catalog_match
                or reservation_match
                or temporary_match
                or is_lock
            ):
                raise McpFacadeError("context admission replay inventory has unknown entries")
            details = details_for(name)
            if is_lock and details.st_size != 0:
                raise McpFacadeError("context admission replay lock is invalid")
            if record_match and details.st_size > MAX_CONTEXT_ADMISSION_REPLAY_BYTES:
                raise McpFacadeError("context admission replay record exceeds budget")
            if catalog_match and details.st_size > MAX_CONTEXT_ADMISSION_REPLAY_CATALOG_BYTES:
                raise McpFacadeError("context admission replay catalog exceeds budget")
            if reservation_match and not (
                0 < details.st_size <= MAX_CONTEXT_ADMISSION_REPLAY_RESERVATION_BYTES
            ):
                raise McpFacadeError(
                    "context admission replay reservation exceeds budget"
                )
            if (
                temporary_match
                and details.st_size > MAX_CONTEXT_ADMISSION_REPLAY_CATALOG_BYTES
            ):
                raise McpFacadeError("context admission replay temporary exceeds budget")
            age = max(0.0, now - details.st_mtime)
            if prune and temporary_match and age >= CONTEXT_ADMISSION_REPLAY_ORPHAN_GRACE_SECONDS:
                replay_hex = temporary_match.group("id")
                with self._context_replay_gc_shard_lock(replay_hex) as acquired:
                    if acquired:
                        current = details_for(name)
                        if (
                            max(0.0, now - current.st_mtime)
                            >= CONTEXT_ADMISSION_REPLAY_ORPHAN_GRACE_SECONDS
                        ):
                            os.unlink(name, dir_fd=root_descriptor)
                            changed = True

        if prune:
            names = sorted(os.listdir(root_descriptor))
            records = {
                match.group("id")
                for name in names
                if (match := record_pattern.fullmatch(name)) is not None
            }
            reservations = {
                match.group("id")
                for name in names
                if (match := reservation_pattern.fullmatch(name)) is not None
            }
            removed: set[str] = set()
            for name in names:
                if name in removed:
                    continue
                record_match = record_pattern.fullmatch(name)
                catalog_match = catalog_pattern.fullmatch(name)
                if record_match is not None:
                    details = details_for(name)
                    if max(0.0, now - details.st_mtime) >= CONTEXT_ADMISSION_REPLAY_TTL_SECONDS:
                        replay_hex = record_match.group("id")
                        with self._context_replay_gc_shard_lock(replay_hex) as acquired:
                            if not acquired:
                                continue
                            current = details_for(name)
                            if (
                                max(0.0, now - current.st_mtime)
                                < CONTEXT_ADMISSION_REPLAY_TTL_SECONDS
                            ):
                                continue
                            for related in (
                                name,
                                replay_hex + ".catalog.sqlite3",
                                replay_hex + ".reservation.json",
                            ):
                                try:
                                    os.unlink(related, dir_fd=root_descriptor)
                                    removed.add(related)
                                except FileNotFoundError:
                                    pass
                            changed = True
                elif (
                    reservation_match is not None
                    and reservation_match.group("id") not in records
                ):
                    replay_hex = reservation_match.group("id")
                    details = details_for(name)
                    if (
                        max(0.0, now - details.st_mtime)
                        >= CONTEXT_ADMISSION_REPLAY_RESERVATION_TTL_SECONDS
                    ):
                        with self._context_replay_gc_shard_lock(replay_hex) as acquired:
                            if not acquired:
                                continue
                            current = details_for(name)
                            if (
                                max(0.0, now - current.st_mtime)
                                < CONTEXT_ADMISSION_REPLAY_RESERVATION_TTL_SECONDS
                            ):
                                continue
                            for related in (
                                name,
                                replay_hex + ".catalog.sqlite3",
                            ):
                                try:
                                    os.unlink(related, dir_fd=root_descriptor)
                                    removed.add(related)
                                except FileNotFoundError:
                                    pass
                            changed = True
                elif (
                    catalog_match is not None
                    and catalog_match.group("id") not in records
                    and catalog_match.group("id") not in reservations
                ):
                    replay_hex = catalog_match.group("id")
                    details = details_for(name)
                    if (
                        max(0.0, now - details.st_mtime)
                        >= CONTEXT_ADMISSION_REPLAY_ORPHAN_GRACE_SECONDS
                    ):
                        with self._context_replay_gc_shard_lock(replay_hex) as acquired:
                            if acquired:
                                current = details_for(name)
                                if (
                                    max(0.0, now - current.st_mtime)
                                    >= CONTEXT_ADMISSION_REPLAY_ORPHAN_GRACE_SECONDS
                                ):
                                    os.unlink(name, dir_fd=root_descriptor)
                                    changed = True
        if changed:
            os.fsync(root_descriptor)

        total_bytes = 0
        record_count = 0
        record_sizes: dict[str, int] = {}
        catalog_sizes: dict[str, int] = {}
        temporary_record_sizes: dict[str, int] = {}
        temporary_catalog_sizes: dict[str, int] = {}
        reservations: dict[str, dict[str, Any]] = {}
        for name in sorted(os.listdir(root_descriptor)):
            details = details_for(name)
            record_match = record_pattern.fullmatch(name)
            catalog_match = catalog_pattern.fullmatch(name)
            reservation_match = reservation_pattern.fullmatch(name)
            temporary_match = temporary_pattern.fullmatch(name)
            if record_match is not None:
                record_count += 1
                record_sizes[record_match.group("id")] = details.st_size
            elif catalog_match is not None:
                catalog_sizes[catalog_match.group("id")] = details.st_size
            elif reservation_match is not None:
                replay_hex = reservation_match.group("id")
                reservation = self._load_context_replay_reservation(
                    "sha256:" + replay_hex
                )
                assert reservation is not None
                reservations[replay_hex] = reservation
            elif temporary_match is not None:
                sizes = (
                    temporary_record_sizes
                    if temporary_match.group("kind") == "json"
                    else temporary_catalog_sizes
                )
                replay_hex = temporary_match.group("id")
                sizes[replay_hex] = sizes.get(replay_hex, 0) + details.st_size
            total_bytes += details.st_size
        effective_record_count = record_count
        for replay_hex, reservation in reservations.items():
            record_consumed = record_sizes.get(replay_hex, 0) + temporary_record_sizes.get(
                replay_hex, 0
            )
            catalog_consumed = catalog_sizes.get(
                replay_hex, 0
            ) + temporary_catalog_sizes.get(replay_hex, 0)
            total_bytes += max(
                0,
                int(reservation["record_bytes"]) - record_consumed,
            )
            total_bytes += max(
                0,
                int(reservation["catalog_bytes"]) - catalog_consumed,
            )
            if replay_hex not in record_sizes:
                effective_record_count += 1
        return total_bytes, effective_record_count

    @contextmanager
    def _context_replay_lock(
        self,
        replay_id: str,
        *,
        timeout_seconds: float | None = None,
        deadline_monotonic: float | None = None,
    ):
        if re.fullmatch(r"sha256:[a-f0-9]{64}", replay_id) is None:
            raise McpFacadeError("context admission replay identity is invalid")
        replay_hex = replay_id.split(":", 1)[1]
        with self._context_replay_file_lock(
            f".replay-lock-{replay_hex[:2]}",
            timeout_seconds=(
                CONTEXT_ADMISSION_REPLAY_LOCK_TIMEOUT_SECONDS
                if timeout_seconds is None
                else timeout_seconds
            ),
            deadline_monotonic=deadline_monotonic,
        ):
            yield

    def _context_replay_name(self, replay_id: str) -> str:
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", replay_id):
            raise McpFacadeError("context admission replay identity is invalid")
        # ACK/control cleanup is valid even when a new reservation could not be
        # negotiated (for example because older delivered records filled the
        # quota). Admission itself remains bound by _require_context_replay_reservation.
        self._prepare_context_replay_custody()
        return replay_id.split(":", 1)[1] + ".json"

    def _require_context_replay_reservation(
        self,
        replay_id: str,
    ) -> dict[str, Any]:
        if replay_id != self._context_admission_replay_reservation_id:
            raise McpFacadeError(
                "context admission replay identity was not reserved"
            )
        reservation = self._load_context_replay_reservation(replay_id)
        if reservation is None:
            raise McpFacadeError("context admission replay reservation is absent")
        if int(reservation["catalog_bytes"]) != (
            self._context_admission_replay_catalog_budget
        ):
            raise McpFacadeError("context admission replay reservation changed")
        os.utime(
            self._context_replay_reservation_name(replay_id),
            None,
            dir_fd=self._prepare_context_replay_custody(),
            follow_symlinks=False,
        )
        return reservation

    def _check_context_replay_deadline(self) -> None:
        deadline = self._active_context_replay_deadline
        if deadline is not None and time.monotonic() >= deadline:
            raise McpFacadeError(
                "context admission replay operation exceeded deadline"
            )

    def _context_replay_path(self, replay_id: str) -> Path:
        root = self._context_admission_replay_root
        if root is None:
            raise McpFacadeError("context admission durable replay is unavailable")
        return root / self._context_replay_name(replay_id)

    def _load_context_replay(
        self, replay_id: str, request_digest: str
    ) -> dict[str, Any] | None:
        name = self._context_replay_name(replay_id)
        root_descriptor = self._prepare_context_replay_custody()
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=root_descriptor,
            )
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise McpFacadeError("context admission replay record is invalid") from exc
        try:
            details = os.fstat(descriptor)
            expected_uid = os.geteuid() if hasattr(os, "geteuid") else details.st_uid
            if (
                not stat.S_ISREG(details.st_mode)
                or details.st_uid != expected_uid
                or stat.S_IMODE(details.st_mode) != 0o600
                or details.st_nlink != 1
                or details.st_size > MAX_CONTEXT_ADMISSION_REPLAY_BYTES
            ):
                raise McpFacadeError("context admission replay record is invalid")
            encoded = b""
            while len(encoded) <= MAX_CONTEXT_ADMISSION_REPLAY_BYTES:
                chunk = os.read(descriptor, min(1_048_576, MAX_CONTEXT_ADMISSION_REPLAY_BYTES + 1 - len(encoded)))
                if not chunk:
                    break
                encoded += chunk
            if self._context_replay_record_identity(os.fstat(descriptor)) != (
                self._context_replay_record_identity(details)
            ):
                raise McpFacadeError("context admission replay record changed while reading")
        finally:
            os.close(descriptor)
        try:
            record = json.loads(encoded)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise McpFacadeError("context admission replay record is invalid") from exc
        migration = self._replay_migration(replay_id)
        source_admitted = bool(migration and migration.accepts_source("record", encoded))
        if migration is not None:
            try:
                migration.validate_record(encoded, record)
            except (ReplayMigrationError, KeyError, TypeError) as exc:
                raise McpFacadeError("migrated replay record changed") from exc
        if (
            not isinstance(record, dict)
            or (record.get("protocol") != CONTEXT_ADMISSION_REPLAY_PROTOCOL and not source_admitted)
            or record.get("request_id") != replay_id
            or record.get("request_digest") != request_digest
            or record.get("phase") not in {"prepared", "committed"}
        ):
            raise McpFacadeError("context admission replay identity collision")
        if record["phase"] == "prepared":
            if not isinstance(record.get("prepared"), dict) or not isinstance(
                record.get("state"), dict
            ):
                raise McpFacadeError("context admission replay record is invalid")
        elif not isinstance(record.get("result"), dict) or not isinstance(
            record.get("state"), dict
        ):
            raise McpFacadeError("context admission replay record is invalid")
        return record

    def _store_context_replay(
        self,
        record: dict[str, Any],
        *,
        expected_phase: str | None = None,
    ) -> dict[str, Any]:
        replay_id = str(record["request_id"])
        request_digest = str(record["request_digest"])
        existing = self._load_context_replay(replay_id, request_digest)
        if existing == record:
            return existing
        if existing is not None and expected_phase is None:
            return existing
        if existing is None and expected_phase is not None:
            raise McpFacadeError("context admission replay phase changed")
        if existing is not None and existing.get("phase") != expected_phase:
            raise McpFacadeError("context admission replay phase changed")
        name = self._context_replay_name(replay_id)
        root_descriptor = self._prepare_context_replay_custody()
        encoded = canonical_json(record)
        reservation = self._require_context_replay_reservation(replay_id)
        if len(encoded) > int(reservation["record_bytes"]):
            raise McpFacadeError("context admission replay record exceeds budget")
        temporary = f".{name}.{os.getpid()}.{time.monotonic_ns()}.tmp"
        with self._context_replay_maintenance_lock():
            self._context_replay_inventory(prune=True)
            self._require_context_replay_reservation(replay_id)
            self._check_context_replay_deadline()
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(temporary, flags, 0o600, dir_fd=root_descriptor)
            try:
                offset = 0
                while offset < len(encoded):
                    offset += os.write(descriptor, encoded[offset:])
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            try:
                os.replace(
                    temporary,
                    name,
                    src_dir_fd=root_descriptor,
                    dst_dir_fd=root_descriptor,
                )
            finally:
                try:
                    os.unlink(temporary, dir_fd=root_descriptor)
                except FileNotFoundError:
                    pass
            os.fsync(root_descriptor)
            if self._context_replay_root_identity(os.fstat(root_descriptor)) != (
                self._context_admission_replay_root_identity
            ):
                raise McpFacadeError("context admission replay custody changed")
        stored = self._load_context_replay(replay_id, request_digest)
        if stored != record:
            raise McpFacadeError("context admission replay record was not committed")
        return stored

    def _open_context_replay_catalog(
        self,
        replay_id: str,
        binding: dict[str, Any],
    ) -> int:
        expected_name = replay_id.split(":", 1)[1] + ".catalog.sqlite3"
        migration = self._replay_migration(replay_id)
        source_admitted = bool(migration and migration.catalog_binding == binding)
        if (
            (binding.get("protocol")
             != "integrity-client/context-admission-frozen-catalog/v1" and not source_admitted)
            or binding.get("name") != expected_name
            or not re.fullmatch(r"sha256:[a-f0-9]{64}", str(binding.get("sha256", "")))
            or isinstance(binding.get("bytes"), bool)
            or not isinstance(binding.get("bytes"), int)
            or not 0 < binding["bytes"] <= MAX_CONTEXT_ADMISSION_REPLAY_CATALOG_BYTES
        ):
            raise McpFacadeError("context admission replay catalog binding is invalid")
        self._check_context_replay_deadline()
        root_descriptor = self._prepare_context_replay_custody()
        try:
            descriptor = os.open(
                expected_name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=root_descriptor,
            )
        except OSError as exc:
            raise McpFacadeError("context admission replay catalog is unavailable") from exc
        try:
            details = os.fstat(descriptor)
            expected_uid = os.geteuid() if hasattr(os, "geteuid") else details.st_uid
            if (
                not stat.S_ISREG(details.st_mode)
                or details.st_uid != expected_uid
                or stat.S_IMODE(details.st_mode) != 0o600
                or details.st_nlink != 1
                or details.st_size != binding["bytes"]
            ):
                raise McpFacadeError("context admission replay catalog custody is invalid")
            identity = self._context_replay_record_identity(details)
            digest = hashlib.sha256()
            remaining = binding["bytes"]
            while remaining:
                self._check_context_replay_deadline()
                chunk = os.read(descriptor, min(1_048_576, remaining))
                if not chunk:
                    raise McpFacadeError("context admission replay catalog is truncated")
                digest.update(chunk)
                remaining -= len(chunk)
            self._check_context_replay_deadline()
            if (
                "sha256:" + digest.hexdigest() != binding["sha256"]
                or self._context_replay_record_identity(os.fstat(descriptor)) != identity
            ):
                raise McpFacadeError("context admission replay catalog digest changed")
            os.lseek(descriptor, 0, os.SEEK_SET)
            return descriptor
        except Exception:
            os.close(descriptor)
            raise

    def _persist_context_replay_catalog(self, replay_id: str) -> dict[str, Any] | None:
        frozen_catalog = self._frozen_catalog
        if not isinstance(frozen_catalog, FrozenSeedCatalogSnapshot):
            return None
        source_descriptor = os.open(
            frozen_catalog.path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        reservation = self._require_context_replay_reservation(replay_id)
        catalog_budget = int(reservation["catalog_bytes"])
        name = replay_id.split(":", 1)[1] + ".catalog.sqlite3"
        root_descriptor = self._prepare_context_replay_custody()
        temporary = f".{name}.{os.getpid()}.{time.monotonic_ns()}.tmp"
        destination_descriptor: int | None = None
        try:
            details = os.fstat(source_descriptor)
            expected_uid = os.geteuid() if hasattr(os, "geteuid") else details.st_uid
            if (
                not stat.S_ISREG(details.st_mode)
                or details.st_uid != expected_uid
                or stat.S_IMODE(details.st_mode) != 0o600
                or details.st_nlink != 1
                or not 0 < details.st_size <= catalog_budget
            ):
                raise McpFacadeError("frozen Seed replay catalog custody is invalid")
            source_identity = self._context_replay_record_identity(details)
            destination_descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=root_descriptor,
            )
            digest = hashlib.sha256()
            copied = 0
            while copied < details.st_size:
                self._check_context_replay_deadline()
                chunk = os.read(
                    source_descriptor,
                    min(1_048_576, details.st_size - copied),
                )
                if not chunk:
                    raise McpFacadeError("frozen Seed replay catalog is truncated")
                digest.update(chunk)
                offset = 0
                while offset < len(chunk):
                    offset += os.write(destination_descriptor, chunk[offset:])
                copied += len(chunk)
            if (
                self._context_replay_record_identity(os.fstat(source_descriptor))
                != source_identity
            ):
                raise McpFacadeError("frozen Seed replay catalog changed while copying")
            os.fsync(destination_descriptor)
            os.close(destination_descriptor)
            destination_descriptor = None
            with self._context_replay_maintenance_lock():
                self._context_replay_inventory(prune=True)
                self._require_context_replay_reservation(replay_id)
                self._check_context_replay_deadline()
                os.replace(
                    temporary,
                    name,
                    src_dir_fd=root_descriptor,
                    dst_dir_fd=root_descriptor,
                )
                os.fsync(root_descriptor)
            binding = {
                "protocol": "integrity-client/context-admission-frozen-catalog/v1",
                "name": name,
                "sha256": "sha256:" + digest.hexdigest(),
                "bytes": copied,
            }
            verification_descriptor = self._open_context_replay_catalog(replay_id, binding)
            os.close(verification_descriptor)
            return binding
        finally:
            os.close(source_descriptor)
            if destination_descriptor is not None:
                os.close(destination_descriptor)
            try:
                os.unlink(temporary, dir_fd=root_descriptor)
            except FileNotFoundError:
                pass

    def _ack_context_replay(
        self,
        replay_id: str,
        request_digest: str,
        response_digest: str,
    ) -> bool:
        if (
            re.fullmatch(r"sha256:[a-f0-9]{64}", replay_id) is None
            or re.fullmatch(r"sha256:[a-f0-9]{64}", request_digest) is None
            or re.fullmatch(r"sha256:[a-f0-9]{64}", response_digest) is None
        ):
            raise McpFacadeError("context admission replay acknowledgement is invalid")
        with self._context_replay_lock(replay_id, timeout_seconds=0.0):
            record = self._load_context_replay(replay_id, request_digest)
            if record is not None and record.get("phase") == "committed":
                expected_response_digest = _sha256(_tool_result(record["result"]))
                if not hmac.compare_digest(response_digest, expected_response_digest):
                    raise McpFacadeError(
                        "context admission replay acknowledgement digest mismatch"
                    )
            elif record is not None and record.get("phase") != "prepared":
                raise McpFacadeError("context admission replay phase changed")
            record_name = self._context_replay_name(replay_id)
            catalog_name = replay_id.split(":", 1)[1] + ".catalog.sqlite3"
            reservation_name = self._context_replay_reservation_name(replay_id)
            with self._context_replay_maintenance_lock(timeout_seconds=0.0):
                # An ACK means that the broker delivered either the committed
                # response or a denial. Validate custody before retiring exact
                # PREPARED/no-record reservation debt as well.
                self._context_replay_inventory(prune=False)
                changed = False
                for related in (record_name, catalog_name, reservation_name):
                    try:
                        os.unlink(
                            related,
                            dir_fd=self._prepare_context_replay_custody(),
                        )
                        changed = True
                    except FileNotFoundError:
                        pass
                if changed:
                    os.fsync(self._prepare_context_replay_custody())
        return True

    def _install_context_replay_catalog(
        self,
        replay_id: str,
        binding: dict[str, Any] | None,
        *,
        artifact_digest: str,
    ) -> None:
        if binding is None:
            return
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", artifact_digest):
            raise McpFacadeError("context admission replay artifact digest is invalid")
        descriptor = self._open_context_replay_catalog(replay_id, binding)
        retained = RetainedSeedCatalogSnapshot(
            descriptor,
            deadline_monotonic=self._active_context_replay_deadline,
        )
        try:
            self.lts = MemorySynapseLtsService(
                retained.path,
                evidence_root=self._base_lts.evidence_root,
                evidence_source_prefix=self._base_lts.evidence_source_prefix,
                artifact_digest=artifact_digest,
                immutable_catalog=True,
                catalog_connection=retained.connection,
            )
            migration = self._replay_migration(replay_id)
            if migration is not None:
                self.lts = migration.retained_lts(self.lts)
        except Exception:
            retained.close()
            raise
        self._frozen_catalog = retained

    def _restore_context_replay_capabilities(
        self,
        recorded: dict[str, Any],
    ) -> dict[str, Any]:
        live = self._base_lts.capabilities()
        for field in (
            "protocol",
            "contract_version",
            "seed_catalog_protocol",
            "seed_catalog_schema_version",
            "source_mapping",
        ):
            if field in recorded and live.get(field) != recorded[field]:
                raise McpFacadeError("context admission replay capability contract changed")
        self._session_capabilities = dict(recorded)
        return self._audit_lts_read(
            "integrity_memory_capabilities",
            {},
            self._session_capabilities,
        )

    def _restore_context_replay(self, record: dict[str, Any]) -> dict[str, Any]:
        if record.get("phase") != "committed":
            raise McpFacadeError("context admission replay is not committed")
        state = record["state"]
        result = record["result"]
        self._clear_intent_context()
        generation = state.get("logical_generation")
        if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
            raise McpFacadeError("context admission replay generation is invalid")
        self._context_generation = generation
        recorded_capabilities = result.get("capabilities")
        if not isinstance(recorded_capabilities, dict):
            raise McpFacadeError("context admission replay capabilities are invalid")
        capabilities = self._restore_context_replay_capabilities(recorded_capabilities)
        catalog_binding = state.get("frozen_catalog")
        if catalog_binding is not None and not isinstance(catalog_binding, dict):
            raise McpFacadeError("context admission replay catalog binding is invalid")
        self._install_context_replay_catalog(
            str(record["request_id"]),
            catalog_binding,
            artifact_digest=str(recorded_capabilities.get("artifact_digest", "")),
        )
        snapshot = self.call("integrity_seed_snapshot", {})
        if capabilities != result.get("capabilities") or snapshot != result.get("snapshot"):
            self._clear_intent_context()
            self._context_generation = generation
            raise McpFacadeError("context admission replay snapshot changed")
        self._session_mind = state.get("mind")
        self._session_architecture = state.get("architecture")
        self._session_write_plane_status = dict(state.get("write_plane", {}))
        self._native_session_lease = state.get("native_session")
        self._context_admission_id = result.get("context_admission_id")
        migration = self._replay_migration(str(record["request_id"]))
        if migration is not None:
            self._deny_migrated_action_authority()
            self.audit({"protocol": "integrity-guardian/replay-migration-restored/v1",
                        "admission_sha256": migration.receipt_sha256,
                        "read_only": True, "historical_response_unchanged": True})
        return dict(result)

    def _require_turn_memory(self) -> TurnMemoryStore:
        if self.turn_memory is None:
            raise McpFacadeError("Turn Memory Receipt service is unavailable")
        return self.turn_memory

    def _turn_memory_call(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        store = self._require_turn_memory()
        if name == "open":
            _reject_unknown(
                arguments,
                {"machine_id", "thread_id", "turn_id", "prompt_sha256"},
            )
            required = {"machine_id", "thread_id", "turn_id", "prompt_sha256"}
            if set(arguments) != required:
                raise McpFacadeError("turn registration requires one complete identity")
            result = store.open_turn(**arguments)
        elif name == "close":
            _reject_unknown(
                arguments,
                {"registration_id", "outcome", "events", "no_event_reason"},
            )
            registration_id = arguments.get("registration_id")
            outcome = arguments.get("outcome")
            events = arguments.get("events")
            no_event_reason = arguments.get("no_event_reason")
            if outcome == "events":
                if no_event_reason is not None:
                    raise McpFacadeError("events outcome cannot include a no-event reason")
                if not isinstance(events, list) or not all(
                    isinstance(item, dict) for item in events
                ):
                    raise McpFacadeError("events outcome requires event references")
                if self.action_witness is None:
                    raise McpFacadeError("canonical event witness is unavailable")
                verified: list[dict[str, Any]] = []
                for item in events:
                    _reject_unknown(item, {"event_uid", "event_id", "request_sha256"})
                    event_uid = item.get("event_uid")
                    event_id = item.get("event_id")
                    request_sha256 = item.get("request_sha256")
                    if not isinstance(event_uid, str) or not isinstance(request_sha256, str):
                        raise McpFacadeError("event reference is invalid")
                    observed = self.action_witness.observe(
                        event_uid=event_uid,
                        request_sha256=request_sha256,
                    )
                    if observed.get("status") != "exact" or observed.get("event_id") != event_id:
                        raise McpFacadeError(
                            "terminal event reference is not canonically witnessed"
                        )
                    verified.append(dict(item))
                result = store.close_turn(
                    registration_id=registration_id,
                    outcome=outcome,
                    events=verified,
                )
            elif outcome == "no-event":
                if events is not None or no_event_reason not in NO_EVENT_REASONS:
                    raise McpFacadeError("no-event outcome requires one closed reason")
                result = store.close_turn(
                    registration_id=registration_id,
                    outcome=outcome,
                    no_event_reason=no_event_reason,
                )
            else:
                raise McpFacadeError("turn terminal outcome is invalid")
        elif name == "gap":
            _reject_unknown(arguments, {"registration_id", "stage"})
            if set(arguments) != {"registration_id", "stage"}:
                raise McpFacadeError("coverage gap requires registration_id and stage")
            result = store.observe_gap(**arguments)
        else:
            _reject_unknown(arguments, {"machine_id", "thread_id", "limit"})
            result = store.coverage(
                machine_id=arguments.get("machine_id"),
                thread_id=arguments.get("thread_id"),
                limit=_integer(arguments, "limit", 100, 1, 500),
            )
        self.audit(
            {
                "protocol": BRIDGE_PROTOCOL + "/turn-memory-audit/v1",
                "source_label": SOURCE_LABEL,
                "observed_utc": _utc_now(),
                "operation": name,
                "arguments_digest": _sha256(arguments),
                "outcome": "observed",
                "namespace_fingerprint": store.namespace,
                "production_authority": False,
            }
        )
        return result

    @staticmethod
    def _close_write_plane_services(
        *,
        architecture: object | None,
        action_witness: object | None,
        native_trust: object | None,
        turn_memory: object | None,
        keep: tuple[object | None, ...] = (),
    ) -> None:
        """Best-effort teardown for installed or discarded runtime services."""

        closed: set[int] = set()
        for service in (turn_memory, action_witness, architecture, native_trust):
            if service is None or any(service is retained for retained in keep):
                continue
            if id(service) in closed:
                continue
            closed.add(id(service))
            try:
                close = getattr(service, "close", None)
                if close is not None:
                    close()
            except Exception:  # noqa: BLE001, S110 - teardown must preserve the read plane
                pass

    @staticmethod
    def _security_admission_is_active(
        security: VerifiedMedorSecurityAdmission | None,
    ) -> bool:
        try:
            verified = require_verified_medor_security_admission(security)
            expiry = dt.datetime.fromisoformat(verified.expires_at)
            now = dt.datetime.fromisoformat(_utc_now())
            return expiry.tzinfo is not None and now.tzinfo is not None and now < expiry
        except (TypeError, ValueError):
            return False

    def _write_plane_runtime_is_ready(self) -> bool:
        return bool(
            self.write_plane_status.get("outcome") == "ready"
            and self.architecture is not None
            and self.action_witness is not None
            and self._security_admission_is_active(self.security_admission)
            and self.turn_memory is not None
            and (self.native_trust is None) == (self.native_device_id is None)
        )

    def _recovery_monotonic(self) -> float:
        try:
            value = float(self._monotonic_clock())
            if math.isfinite(value):
                return value
        except Exception:  # noqa: BLE001, S110 - injected clock failure uses the OS clock
            pass
        return time.monotonic()

    def _recovery_runtime_status(self, runtime: WritePlaneRuntime) -> dict[str, str]:
        status = dict(runtime.status)
        required = {
            "outcome",
            "architecture",
            "action_witness",
            "security_admission",
            "turn_memory",
        }
        if not required.issubset(status) or any(
            not isinstance(status.get(field), str) for field in required
        ):
            raise McpFacadeError("write-plane recovery status is incomplete")
        if status["outcome"] != "ready" or any(
            status[field] != "ready" for field in required - {"outcome"}
        ):
            raise McpFacadeError("write-plane recovery candidate is not ready")
        if (
            runtime.architecture is None
            or runtime.action_witness is None
            or runtime.security_admission is None
            or runtime.turn_memory is None
            or (runtime.native_trust is None) != (runtime.native_device_id is None)
        ):
            raise McpFacadeError("write-plane recovery candidate is incomplete")
        try:
            require_verified_medor_security_admission(runtime.security_admission)
        except ValueError as exc:
            raise McpFacadeError(
                "write-plane recovery Security admission is invalid"
            ) from exc
        if not self._security_admission_is_active(runtime.security_admission):
            raise McpFacadeError("write-plane recovery Security admission is not active")
        return status

    def _install_recovered_write_plane(self, runtime: WritePlaneRuntime) -> None:
        """Validate first, then replace every write-plane service as one set."""

        status = self._recovery_runtime_status(runtime)
        architecture_root = getattr(runtime.architecture, "root", None)
        replay_root = (
            Path(architecture_root) / "context-admission-replay-v2"
            if isinstance(architecture_root, (str, os.PathLike))
            else None
        )
        replay_descriptors_open = any(
            descriptor is not None
            for descriptor in (
                self._context_admission_replay_root_fd,
                self._context_admission_replay_parent_fd,
                self._context_admission_replay_anchor_fd,
            )
        )
        if replay_descriptors_open and replay_root != self._context_admission_replay_root:
            raise McpFacadeError("write-plane recovery changed active replay custody")
        previous = (
            self.architecture,
            self.action_witness,
            self.native_trust,
            self.turn_memory,
        )
        (
            self.architecture,
            self.action_witness,
            self.security_admission,
            self.native_trust,
            self.native_device_id,
            self.turn_memory,
            self.write_plane_status,
            self._session_write_plane_status,
        ) = (
            runtime.architecture,
            runtime.action_witness,
            runtime.security_admission,
            runtime.native_trust,
            runtime.native_device_id,
            runtime.turn_memory,
            dict(status),
            dict(status),
        )
        if not replay_descriptors_open:
            self._context_admission_replay_root = replay_root
        self._close_write_plane_services(
            architecture=previous[0],
            action_witness=previous[1],
            native_trust=previous[2],
            turn_memory=previous[3],
            keep=(
                runtime.architecture,
                runtime.action_witness,
                runtime.native_trust,
                runtime.turn_memory,
            ),
        )

    def _audit_write_plane_recovery(
        self,
        *,
        outcome: str,
        elapsed_ms: int,
        component_status: dict[str, str],
        reason_digest: str | None = None,
        component_reason_digests: dict[str, str] | None = None,
        retry_after_seconds: float | None = None,
    ) -> None:
        receipt: dict[str, Any] = {
            "protocol": BRIDGE_PROTOCOL + "/write-plane-recovery/v1",
            "source_label": SOURCE_LABEL,
            "observed_utc": _utc_now(),
            "stage": "post-read-pre-architecture-admission",
            "outcome": outcome,
            "component_status": dict(component_status),
            "elapsed_ms": max(0, elapsed_ms),
            "canonical_writes": 0,
            "production_authority": False,
        }
        if reason_digest is not None:
            receipt["reason_digest"] = reason_digest
        if component_reason_digests:
            receipt["component_reason_digests"] = dict(component_reason_digests)
        if retry_after_seconds is not None:
            receipt["retry_after_ms"] = max(0, int(retry_after_seconds * 1000))
        try:
            self.audit(receipt)
        except Exception:  # noqa: BLE001, S110 - audit failure must preserve the read plane
            pass

    def _maybe_recover_write_plane(self) -> None:
        # The stdio transport can outlive its startup admission. A fresh owner
        # intent must revalidate that admission before advertising write readiness.
        if not self._security_admission_is_active(self.security_admission):
            self.write_plane_status = {
                **self.write_plane_status,
                "outcome": "unavailable",
                "security_admission": "unavailable",
            }
            self._mark_session_write_plane_unavailable("security_admission")
        reinitialize = self._write_plane_reinitializer
        if reinitialize is None or self._write_plane_runtime_is_ready():
            return
        now = self._recovery_monotonic()
        if now < self._write_plane_recovery_next_attempt_monotonic:
            return
        started = now
        candidate: WritePlaneRuntime | None = None
        failure: Exception | None = None
        try:
            candidate = reinitialize()
            if not isinstance(candidate, WritePlaneRuntime):
                raise McpFacadeError("write-plane reinitializer returned an invalid runtime")
            self._install_recovered_write_plane(candidate)
        except Exception as exc:  # noqa: BLE001 - reinitializer failures become bounded cooldown
            failure = exc
        finished = self._recovery_monotonic()
        elapsed_ms = max(0, int((finished - started) * 1000))
        if failure is None:
            self._write_plane_recovery_cooldown_seconds = (
                self._write_plane_recovery_initial_cooldown_seconds
            )
            self._write_plane_recovery_next_attempt_monotonic = 0.0
            self._audit_write_plane_recovery(
                outcome="ready",
                elapsed_ms=elapsed_ms,
                component_status=dict(self.write_plane_status),
            )
            return
        if candidate is not None:
            self._close_write_plane_services(
                architecture=candidate.architecture,
                action_witness=candidate.action_witness,
                native_trust=candidate.native_trust,
                turn_memory=candidate.turn_memory,
                keep=(
                    self.architecture,
                    self.action_witness,
                    self.native_trust,
                    self.turn_memory,
                ),
            )
        cooldown = self._write_plane_recovery_cooldown_seconds
        self._write_plane_recovery_next_attempt_monotonic = finished + cooldown
        self._write_plane_recovery_cooldown_seconds = min(
            self._write_plane_recovery_max_cooldown_seconds,
            cooldown * 2,
        )
        component_status = dict(self.write_plane_status)
        component_reason_digests: dict[str, str] = {}
        if candidate is not None:
            allowed_components = {
                "outcome",
                "architecture",
                "action_witness",
                "security_admission",
                "turn_memory",
            }
            candidate_status = getattr(candidate, "status", None)
            if isinstance(candidate_status, dict):
                filtered_status = {
                    key: value
                    for key, value in candidate_status.items()
                    if key in allowed_components and value in {"ready", "unavailable"}
                }
                if filtered_status:
                    component_status = filtered_status
            candidate_reason_digests = getattr(candidate, "failure_reason_digests", None)
            if isinstance(candidate_reason_digests, dict):
                component_reason_digests = {
                    key: value
                    for key, value in candidate_reason_digests.items()
                    if key in allowed_components
                    and isinstance(value, str)
                    and re.fullmatch(r"sha256:[a-f0-9]{64}", value)
                }
        self._audit_write_plane_recovery(
            outcome="unavailable",
            elapsed_ms=elapsed_ms,
            component_status=component_status,
            reason_digest=_sha256(
                {
                    "exception_type": type(failure).__name__,
                }
            ),
            component_reason_digests=component_reason_digests,
            retry_after_seconds=cooldown,
        )

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._clear_intent_context()
        finally:
            try:
                self._close_write_plane_services(
                    architecture=self.architecture,
                    action_witness=self.action_witness,
                    native_trust=self.native_trust,
                    turn_memory=self.turn_memory,
                )
            finally:
                descriptor = self._context_admission_replay_root_fd
                parent_descriptor = self._context_admission_replay_parent_fd
                anchor_descriptor = self._context_admission_replay_anchor_fd
                self._context_admission_replay_root_fd = None
                self._context_admission_replay_parent_fd = None
                self._context_admission_replay_anchor_fd = None
                self._context_admission_replay_root_identity = None
                self._context_admission_replay_parent_identity = None
                if descriptor is not None:
                    os.close(descriptor)
                if parent_descriptor is not None:
                    os.close(parent_descriptor)
                if anchor_descriptor is not None:
                    os.close(anchor_descriptor)

    def release_idle_context(self) -> bool:
        """Release the frozen Seed copy and derived projections of an idle intent.

        The stdio transport stays open: a client that returns starts its next
        owner intent with a fresh admission, exactly as after any rotation.
        Nothing is released while a context replay is being admitted.
        """
        if self._closed or self._active_context_replay_id is not None:
            return False
        if (
            self._frozen_catalog is None
            and self._session_snapshot is None
            and self._session_mind is None
        ):
            return False
        self._clear_intent_context()
        return True

    def _clear_intent_context(self) -> None:
        """Destroy logical owner-intent state while retaining shared services."""

        frozen_catalog = self._frozen_catalog
        self._frozen_catalog = None
        self.lts = self._base_lts
        self._session_capabilities = None
        self._session_snapshot = None
        self._session_mind = None
        self._session_architecture = None
        self._session_memory_link_graph = None
        self._session_memory_ttt_path_catalog = None
        self._native_session_lease = None
        self._context_admission_id = None
        self._session_write_plane_status = dict(self.write_plane_status)
        cleanup_errors: list[Exception] = []
        home_cleanup = getattr(self.home, "reset_context", None) or getattr(
            self.home,
            "close",
            None,
        )
        for cleanup in (
            getattr(self.action_log, "reset_context", None),
            home_cleanup,
            *((frozen_catalog.close,) if frozen_catalog is not None else ()),
        ):
            if cleanup is None:
                continue
            try:
                cleanup()
            except Exception as exc:  # noqa: BLE001 - finish all cleanup steps
                cleanup_errors.append(exc)
        if cleanup_errors:
            raise McpFacadeError("intent context cleanup failed") from cleanup_errors[0]

    def _mark_session_write_plane_unavailable(self, component: str) -> None:
        status = dict(self._session_write_plane_status)
        status["outcome"] = "unavailable"
        status[component] = "unavailable"
        self._session_write_plane_status = status

    def _architecture_unavailable(self, exc: Exception) -> dict[str, Any]:
        self._session_architecture = None
        self._native_session_lease = None
        self._mark_session_write_plane_unavailable("architecture")
        return {
            "protocol": BRIDGE_PROTOCOL + "/architecture-unavailable/v1",
            "outcome": "unavailable",
            "failure_layer": "write-plane-admission",
            "reason_digest": _sha256(
                {
                    "exception_type": type(exc).__name__,
                    "reason": str(exc)[:500],
                }
            ),
            "canonical_writes": 0,
            "production_authority": False,
        }

    def _architecture_admission(
        self,
        arguments: dict[str, Any],
        *,
        observed_at: str | None = None,
    ) -> dict[str, Any]:
        self._require_mind_admission()
        _reject_unknown(arguments, {"mind_receipt_id"})
        if self.architecture is None:
            raise McpFacadeError("Guardian architecture custody is unavailable")
        if self._session_architecture is not None:
            raise McpFacadeError("architecture admission is already fixed for this session")
        assert self._session_mind is not None
        mind_receipt = self._session_mind.get("admission_receipt")
        mind = self._session_mind.get("mind")
        if not isinstance(mind_receipt, dict) or not isinstance(mind, dict):
            raise McpFacadeError("Mind admission state is invalid")
        if arguments.get("mind_receipt_id") != mind_receipt.get("receipt_id"):
            raise McpFacadeError("mind_receipt_id does not match session admission")
        now = observed_at or _utc_now()
        value = self.architecture.admit(
            mind_admission=mind_receipt,
            mind=mind,
            observed_at=now,
            as_of=now,
        )
        self._session_architecture = value
        return self._audit_lts_read("integrity_architecture_admission", arguments, value)

    def _context_admission_receipt_id(
        self,
        *,
        generation: int,
        snapshot: dict[str, Any],
        mind: dict[str, Any],
        architecture: dict[str, Any],
        prompt_binding: dict[str, Any] | None = None,
    ) -> str:
        mind_receipt = mind.get("admission_receipt", {})
        architecture_value = architecture.get("architecture", {})
        architecture_summary = (
            architecture_value.get("summary", {}) if isinstance(architecture_value, dict) else {}
        )

        receipt_material: dict[str, Any] = {
                "protocol": BRIDGE_PROTOCOL + "/context-admission-receipt/v1",
                "logical_generation": generation,
                "snapshot_id": snapshot.get("snapshot_id"),
                "seed_source_digest": snapshot.get("source_digest"),
                "seed_catalog_digest": snapshot.get("catalog_digest"),
                "mind_admission_receipt_id": (
                    mind_receipt.get("receipt_id") if isinstance(mind_receipt, dict) else None
                ),
                "architecture_admission_id": (
                    architecture_value.get("admission_id")
                    if isinstance(architecture_value, dict)
                    else None
                ),
                "architecture_outcome": architecture.get("outcome"),
                "architecture_failure_layer": architecture.get("failure_layer"),
                "coordination_stop_required": (
                    architecture_summary.get("coordination_stop_required")
                    if isinstance(architecture_summary, dict)
                    else None
                ),
                "write_plane": dict(self._session_write_plane_status),
                "canonical_writes": 0,
                "production_authority": False,
                "authority_contract": memory_authority_contract(
                    "stopped"
                    if mind_receipt.get("coordination_stop_required") is True
                    else "ready"
                ),
            }
        # Keep the pre-v4 receipt byte-for-byte stable.  The binding becomes
        # part of the receipt only for the authenticated current-turn path.
        if prompt_binding is not None:
            receipt_material["prompt_binding"] = prompt_binding
        return _sha256(receipt_material)

    def _bind_append_to_current_context(
        self,
        arguments: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        """Validate the caller's current-context echo before any append side effect."""

        event_arguments = dict(arguments)
        supplied = event_arguments.pop("context_admission_id", None)
        current = self._context_admission_id
        if current is None and self._context_generation == 0:
            if supplied is not None:
                raise McpFacadeError(
                    "append context binding DENY: no composite context admission is active"
                )
            return event_arguments, None
        if current is None:
            raise McpFacadeError("append context binding DENY: current logical context is empty")
        if not isinstance(supplied, str) or re.fullmatch(r"sha256:[a-f0-9]{64}", supplied) is None:
            raise McpFacadeError("append context binding DENY: context_admission_id is required")
        if not hmac.compare_digest(supplied, current):
            raise McpFacadeError(
                "append context binding DENY: context_admission_id is stale or mismatched"
            )
        external_decision = event_arguments.get("authority_decision")
        if external_decision is not None:
            if self.native_trust is not None:
                raise McpFacadeError(
                    "caller-supplied authority decision is prohibited in personal-native mode"
                )
            if (
                not isinstance(external_decision, dict)
                or external_decision.get("protocol")
                != "integrity-guardian/medor-event-append-decision/v2"
                or external_decision.get("context_admission_id") != current
                or external_decision.get("logical_generation") != self._context_generation
            ):
                raise McpFacadeError(
                    "append context binding DENY: signed authority decision is stale or unbound"
                )
        return event_arguments, {
            "context_admission_id": current,
            "logical_generation": self._context_generation,
        }

    def _ensure_frozen_lts(self) -> None:
        if self._snapshot_source is None:
            return
        if self._frozen_catalog is not None:
            return
        assert self._snapshot_root is not None
        frozen_catalog: FrozenSeedCatalogSnapshot | None = None
        try:
            frozen_catalog = FrozenSeedCatalogSnapshot(
                self._snapshot_source,
                self._snapshot_root,
                deadline_monotonic=self._active_context_replay_deadline,
                maximum_bytes=(
                    self._context_admission_replay_catalog_budget
                    if self._active_context_replay_id is not None
                    else None
                ),
            )
            self.lts = MemorySynapseLtsService(
                frozen_catalog.path,
                evidence_root=self.lts.evidence_root,
                evidence_source_prefix=self.lts.evidence_source_prefix,
                artifact_digest=self.lts._artifact_digest(),
            )
        except ReadPlaneUnavailableError:
            raise
        except (
            McpFacadeError,
            MemorySynapseLtsError,
            OSError,
            sqlite3.Error,
            ValueError,
            TypeError,
        ) as exc:
            if frozen_catalog is not None:
                try:
                    frozen_catalog.close()
                except OSError:
                    pass
            raise ReadPlaneUnavailableError(
                str(exc),
                reason_code="seed_snapshot_initialization_failed",
                user_message=(
                    "Canonical memory is temporarily unavailable because its "
                    "verified snapshot could not be prepared."
                ),
                operator_action=(
                    "Ask the Seed catalog owner to run the supported verification "
                    "and recovery procedure."
                ),
            ) from exc
        assert frozen_catalog is not None
        self._frozen_catalog = frozen_catalog

    def _read_seed_snapshot(self) -> dict[str, Any]:
        try:
            snapshot = self.lts.snapshot()
            if not isinstance(snapshot, dict):
                raise McpFacadeError("Seed snapshot returned an invalid document")
            cursor = snapshot.get("cursor")
            if not isinstance(cursor, dict):
                raise McpFacadeError("Seed snapshot returned an invalid cursor")
            maximum_event_id = cursor.get("maximum_event_id")
            event_count = cursor.get("event_count")
            if (
                isinstance(maximum_event_id, bool)
                or not isinstance(maximum_event_id, int)
                or isinstance(event_count, bool)
                or not isinstance(event_count, int)
            ):
                raise McpFacadeError("Seed snapshot returned an invalid cursor")
            self.action_log.bind_snapshot(maximum_event_id, event_count)
            return snapshot
        except ReadPlaneUnavailableError:
            raise
        except (
            McpFacadeError,
            MemorySynapseLtsError,
            OSError,
            sqlite3.Error,
            ValueError,
            TypeError,
        ) as exc:
            raise ReadPlaneUnavailableError(
                str(exc),
                reason_code="seed_snapshot_read_failed",
                user_message=(
                    "Canonical memory is temporarily unavailable because its "
                    "verified snapshot could not be read."
                ),
                operator_action=(
                    "Ask the Seed catalog owner to run the supported verification "
                    "and recovery procedure."
                ),
            ) from exc

    def _event_append_action(
        self,
        arguments: dict[str, Any],
        *,
        context_binding: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if (
            self.architecture is None
            or self.action_witness is None
            or self._session_architecture is None
            or self.security_admission is None
        ):
            raise McpFacadeError("Uroboros append action boundary is unavailable")
        architecture = self._session_architecture.get("architecture")
        if not isinstance(architecture, dict):
            raise McpFacadeError("architecture admission state is invalid")
        architecture_id = architecture.get("admission_id")
        summary = architecture.get("summary")
        if (
            not isinstance(architecture_id, str)
            or not isinstance(summary, dict)
            or not isinstance(summary.get("coordination_stop_required"), bool)
            or summary.get("route_disposition")
            != ("stopped" if summary["coordination_stop_required"] else "ready")
        ):
            raise McpFacadeError("architecture route is not action-admissible")
        coordination_stop_observed = summary["coordination_stop_required"]
        event_arguments = dict(arguments)
        external_decision = event_arguments.pop("authority_decision", None)
        prepared = self.action_log.prepare_append(event_arguments)
        request_digest = "sha256:" + prepared["request_sha256"]
        before = self.action_witness.observe(
            event_uid=prepared["event_uid"],
            request_sha256=prepared["request_sha256"],
        )
        if before["status"] == "collision":
            raise McpFacadeError("event_uid collides with different immutable content")
        before_witness = self.architecture.sign_passive_witness(
            {
                "protocol": BRIDGE_PROTOCOL + "/passive-event-witness/v1",
                "phase": "before-action",
                **before,
            }
        )
        observed_at = _utc_now()
        before_witness_digest = _sha256(
            {
                "domain": "medor-event-signed-passive-witness-v1",
                "witness": before_witness,
            }
        )
        pre_action = self.architecture.plan_event_append(
            architecture=architecture,
            security=self.security_admission,
            request_digest=request_digest,
            exact_event_exists=before["status"] == "exact",
            passive_witness_digest=before_witness_digest,
            observed_at=observed_at,
            as_of=observed_at,
            **(context_binding or {}),
        )
        route_digest = pre_action["route_stage_id"]
        route_context: dict[str, Any] = {
            "architecture_admission_id": architecture_id,
            "route_digest": route_digest,
            "security_admission_id": self.security_admission.admission_id,
        }
        if context_binding is not None:
            route_context.update(context_binding)
        prepared = self.action_log.prepare_append(
            event_arguments,
            route_context=route_context,
        )
        if before["status"] == "exact":
            receipt = {
                "protocol": BRIDGE_PROTOCOL + "/append-receipt",
                "source_label": SOURCE_LABEL,
                "observed_utc": _utc_now(),
                "event_uid": prepared["event_uid"],
                "event_id": before["event_id"],
                "request_sha256": prepared["request_sha256"],
                "outcome": "duplicate",
                "action_outcome": "confirmed-success",
                "route_memory": "reuse-existing-exact-event",
                "route_digest": route_digest,
                "route_stage_id": pre_action["route_stage_id"],
                "route_stage": pre_action,
                "architecture_admission_id": architecture_id,
                "security_admission_id": self.security_admission.admission_id,
                "request_sent": False,
                "grant_consumed": False,
                "automatic_retry_allowed": False,
                "coordination_stop_observed": coordination_stop_observed,
                "production_execution_performed": False,
                "passive_witness": before_witness,
                "home_record_count": 0,
                "production_authority": False,
            }
            if context_binding is not None:
                receipt.update(context_binding)
            _audit(
                {
                    "protocol": receipt["protocol"],
                    "source_label": receipt["source_label"],
                    "observed_utc": receipt["observed_utc"],
                    "event_uid_digest": _sha256(receipt["event_uid"]),
                    "event_id": receipt["event_id"],
                    "request_sha256": receipt["request_sha256"],
                    "outcome": receipt["outcome"],
                    "route_stage_id": receipt["route_stage_id"],
                    "request_sent": False,
                    "grant_consumed": False,
                    "coordination_stop_observed": coordination_stop_observed,
                    **(context_binding or {}),
                    "production_authority": False,
                }
            )
            return {"receipt": receipt}
        recorded_at = _utc_now()
        if not isinstance(external_decision, dict):
            if self.native_trust is None or self._native_session_lease is None:
                raise McpFacadeError("externally signed event append decision is required")
            try:
                external_decision = self.native_trust.issue_event_append_decision(
                    session_lease=self._native_session_lease,
                    architecture_admission_id=architecture_id,
                    security_admission_id=self.security_admission.admission_id,
                    request_digest=request_digest,
                    at_time=recorded_at,
                    **(context_binding or {}),
                )
            except NativeTrustError as exc:
                raise McpFacadeError("native session append admission denied") from exc
        elif self.native_trust is not None:
            raise McpFacadeError(
                "caller-supplied authority decision is prohibited in personal-native mode"
            )
        authority = self.architecture.authorize_event_append(
            architecture_admission_id=architecture_id,
            security_admission_id=self.security_admission.admission_id,
            request_digest=request_digest,
            route_digest=route_digest,
            external_decision=external_decision,
            recorded_at=recorded_at,
            **(context_binding or {}),
        )
        action_stage = self.architecture.plan_event_execution(
            pre_action=pre_action,
            authority=authority,
            observed_at=recorded_at,
            as_of=recorded_at,
        )
        transport_receipt: dict[str, Any] | None = None
        transport_error = False
        try:
            transport_receipt = self.action_log.append_prepared(prepared)["receipt"]
        except McpFacadeError:
            transport_error = True
        witness_observer_available = True
        try:
            after = self.action_witness.observe(
                event_uid=prepared["event_uid"],
                request_sha256=prepared["request_sha256"],
            )
        except McpFacadeError:
            # The mutation was attempted exactly once and its grant is already
            # consumed. Preserve UNKNOWN durably; observer failure must never
            # become an automatic retry or a guessed success/failure.
            witness_observer_available = False
            after = {
                "status": "observer-unavailable",
                "event_uid": prepared["event_uid"],
                "event_id": 0,
                "request_sha256": prepared["request_sha256"],
                "observed_record_digest": _sha256(
                    {
                        "observer": "canonical-action-log-restricted-witness",
                        "status": "unavailable",
                    }
                ),
            }
        after_witness = self.architecture.sign_passive_witness(
            {
                "protocol": BRIDGE_PROTOCOL + "/passive-event-witness/v1",
                "phase": "after-action",
                **after,
            }
        )
        if after["status"] == "exact":
            action_outcome = "confirmed-success"
        elif after["status"] == "collision":
            action_outcome = "confirmed-failure"
        else:
            action_outcome = "unknown-outcome"
        witness_digest = _sha256(
            {
                "domain": "medor-event-signed-passive-witness-v1",
                "witness": after_witness,
            }
        )
        feedback = self.architecture.record_event_append_outcome(
            grant_id=authority["grant_id"],
            request_digest=request_digest,
            outcome=action_outcome,
            witness_digest=witness_digest,
            recorded_at=_utc_now(),
        )
        outcome_observed_at = _utc_now()
        outcome_stage = self.architecture.plan_event_outcome(
            action_stage=action_stage,
            outcome=action_outcome,
            passive_witness_digest=witness_digest,
            feedback_receipt_id=feedback["receipt_id"],
            feedback=feedback,
            observed_at=outcome_observed_at,
            as_of=outcome_observed_at,
        )
        receipt = {
            "protocol": BRIDGE_PROTOCOL + "/append-receipt",
            "source_label": SOURCE_LABEL,
            "observed_utc": _utc_now(),
            "event_uid": prepared["event_uid"],
            "event_id": after["event_id"],
            "request_sha256": prepared["request_sha256"],
            "outcome": (
                transport_receipt["outcome"]
                if action_outcome == "confirmed-success" and transport_receipt is not None
                else action_outcome
            ),
            "action_outcome": action_outcome,
            "route_memory": "explore-to-observed",
            "route_digest": route_digest,
            "pre_action_route_stage_id": pre_action["route_stage_id"],
            "action_route_stage_id": action_stage["route_stage_id"],
            "outcome_route_stage_id": outcome_stage["route_stage_id"],
            "architecture_admission_id": architecture_id,
            "security_admission_id": self.security_admission.admission_id,
            "request_sent": True,
            "transport_response_received": not transport_error,
            "grant_consumed": True,
            "grant_id": authority["grant_id"],
            "authority_receipt_id": authority["receipt_id"],
            "one_use_authority": authority,
            "automatic_retry_allowed": False,
            "coordination_stop_observed": coordination_stop_observed,
            "production_execution_performed": False,
            "passive_witness": after_witness,
            "witness_observer_available": witness_observer_available,
            "feedback_receipt_id": feedback["receipt_id"],
            "outcome_feedback": feedback,
            "route_stages": {
                "pre_action": pre_action,
                "action": action_stage,
                "outcome": outcome_stage,
            },
            "home_record_count": 0,
            "production_authority": False,
        }
        if context_binding is not None:
            receipt.update(context_binding)
        _audit(
            {
                "protocol": receipt["protocol"],
                "source_label": receipt["source_label"],
                "observed_utc": receipt["observed_utc"],
                "event_uid_digest": _sha256(receipt["event_uid"]),
                "event_id": receipt["event_id"],
                "request_sha256": receipt["request_sha256"],
                "outcome": receipt["outcome"],
                "action_outcome": receipt["action_outcome"],
                "grant_id": receipt["grant_id"],
                "feedback_receipt_id": receipt["feedback_receipt_id"],
                "outcome_route_stage_id": receipt["outcome_route_stage_id"],
                "request_sent": True,
                "grant_consumed": True,
                "automatic_retry_allowed": False,
                "coordination_stop_observed": coordination_stop_observed,
                **(context_binding or {}),
                "production_authority": False,
            }
        )
        return {"receipt": receipt}

    def _audit_lts_read(
        self,
        name: str,
        arguments: dict[str, Any],
        value: dict[str, Any],
    ) -> dict[str, Any]:
        receipt: dict[str, Any] = {
            "protocol": BRIDGE_PROTOCOL + "/lts-read-receipt",
            "source_label": SOURCE_LABEL,
            "memory_source": "canonical-seed-action-log",
            "observed_utc": _utc_now(),
            "tool": name,
            "arguments_digest": _sha256(arguments),
            "outcome": "read",
        }
        if name == "integrity_memory_capabilities":
            receipt.update(
                {
                    "artifact_digest": value.get("artifact_digest"),
                    "capabilities_digest": value.get("capabilities_digest"),
                    "health": value.get("health"),
                }
            )
        elif name == "integrity_seed_snapshot":
            receipt.update(
                {
                    "snapshot_id": value.get("snapshot_id"),
                    "source_digest": value.get("source_digest"),
                    "catalog_digest": value.get("catalog_digest"),
                    "cursor": value.get("cursor"),
                    "home_record_count": value.get("home_record_count"),
                }
            )
        elif name == "integrity_mind_graph":
            answer_receipt = value.get("admission_receipt", {})
            receipt.update(
                {
                    "snapshot_event_id": answer_receipt.get("snapshot_event_id"),
                    "snapshot_event_count": answer_receipt.get("snapshot_event_count"),
                    "projection_digest": answer_receipt.get("projection_digest"),
                    "mind_receipt_id": answer_receipt.get("mind_receipt_id"),
                    "concept_recovery_digest": answer_receipt.get("concept_recovery_digest"),
                    "coordination_digest": answer_receipt.get("coordination_digest"),
                    "coordination_stop_required": answer_receipt.get("coordination_stop_required"),
                    "admission_receipt_id": answer_receipt.get("receipt_id"),
                    "home_record_count": answer_receipt.get("home_record_count"),
                    "production_authority": answer_receipt.get("production_authority"),
                }
            )
        elif name == "integrity_architecture_admission":
            architecture = value.get("architecture", {})
            custody = value.get("custody", {})
            summary = architecture.get("summary", {})
            receipt.update(
                {
                    "architecture_admission_id": architecture.get("admission_id"),
                    "guardian_event_digest": summary.get("ledger_event_digest"),
                    "guardian_checkpoint_digest": summary.get("checkpoint_digest"),
                    "atlas_projection_digest": summary.get("atlas_projection_digest"),
                    "connectome_compilation_id": summary.get("connectome_compilation_id"),
                    "synapse_plan_id": summary.get("synapse_plan_id"),
                    "coordination_stop_required": summary.get("coordination_stop_required"),
                    "custody_receipt_id": custody.get("receipt_id"),
                    "custody_tree_size": custody.get("checkpoint", {}).get("tree_size"),
                    "custody_write_status": custody.get("write_status"),
                    "home_record_count": custody.get("home_record_count"),
                    "production_authority": custody.get("production_authority"),
                }
            )
        elif name == "integrity_seed_connections":
            answer_receipt = value.get("receipt", {})
            receipt.update(
                {
                    "snapshot_id": answer_receipt.get("snapshot_id"),
                    "selected_event_id": answer_receipt.get("selected_event_id"),
                    "explanation_digest": answer_receipt.get("explanation_digest"),
                    "connections_receipt_id": answer_receipt.get("receipt_id"),
                    "direct_verification_receipt_id": answer_receipt.get(
                        "direct_verification_receipt_id"
                    ),
                    "link_counts": answer_receipt.get("link_counts"),
                    "home_record_count": answer_receipt.get("home_record_count"),
                }
            )
        elif name == "integrity_seed_event_uid":
            answer_receipt = value.get("receipt", {})
            receipt.update(
                {
                    "snapshot_id": answer_receipt.get("snapshot_id"),
                    "event_uid_lookup_receipt_id": answer_receipt.get("receipt_id"),
                    "lookup_outcome": answer_receipt.get("outcome"),
                    "event_id": answer_receipt.get("event_id"),
                    "event_digest": answer_receipt.get("event_digest"),
                    "home_record_count": answer_receipt.get("home_record_count"),
                }
            )
        elif name == "integrity_seed_tasks":
            answer_receipt = value.get("receipt", {})
            receipt.update(
                {
                    "snapshot_id": answer_receipt.get("snapshot_id"),
                    "task_inventory_receipt_id": answer_receipt.get("receipt_id"),
                    "view": answer_receipt.get("view"),
                    "selected_statuses": answer_receipt.get("selected_statuses"),
                    "status_counts": answer_receipt.get("status_counts"),
                    "returned_count": answer_receipt.get("returned_count"),
                    "has_more": answer_receipt.get("has_more"),
                    "home_record_count": answer_receipt.get("home_record_count"),
                }
            )
        elif name in {
            "integrity_memory_entity_brief",
            "integrity_memory_link_audit",
            "integrity_memory_ttt_autofill",
        }:
            receipt.update(
                {
                    "snapshot_id": self._session_snapshot.get("snapshot_id")
                    if self._session_snapshot
                    else None,
                    "graph_digest": value.get("graph_digest"),
                    "memory_link_receipt_id": value.get("receipt_id"),
                    "path_catalog_digest": value.get("path_catalog_digest"),
                    "result": value.get("result"),
                    "returned_count": value.get("returned_count"),
                    "finding_count": value.get("coverage", {}).get("finding_count")
                    if isinstance(value.get("coverage"), dict)
                    else None,
                    "production_authority": value.get("production_authority"),
                }
            )
        else:
            receipt.update(
                {
                    "snapshot_id": value.get("snapshot_id"),
                    "selected_event_id": value.get("selected_event_id"),
                    "explanation_digest": value.get("explanation_digest"),
                    "connections_receipt_id": value.get("connections_receipt_id"),
                    "replay_receipt_id": value.get("replay_receipt_id"),
                    "deterministic": value.get("deterministic"),
                    "reroll_count": value.get("reroll_count"),
                    "home_record_count": value.get("home_record_count"),
                }
            )
        self.audit(receipt)
        return value

    def _home(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if self._session_capabilities is None:
            raise McpFacadeError(
                "integrity_memory_capabilities admission is required before Home reads"
            )
        if name == "search":
            _reject_unknown(arguments, {"query", "cursor", "page_size"})
            if ("query" in arguments) == ("cursor" in arguments):
                raise McpFacadeError("provide exactly one Home query or cursor")
            if "page_size" in arguments:
                _integer(arguments, "page_size", 10, 1, MAX_HOME_PAGE_SIZE)
        else:
            _reject_unknown(arguments, {"id"})
            if set(arguments) != {"id"}:
                raise McpFacadeError("Home fetch accepts one opaque id")
            item_id = arguments.get("id")
            if not isinstance(item_id, str) or not 8 <= len(item_id) <= 80:
                raise McpFacadeError("id must be one opaque Home result identifier")
        payload = self.home.call(name, arguments)
        receipt: dict[str, Any] = {
            "protocol": BRIDGE_PROTOCOL + f"/home-{name}-receipt",
            "source_label": SOURCE_LABEL,
            "memory_source": "integrity-home",
            "observed_utc": _utc_now(),
            "request_sha256": _sha256_hex(arguments),
            "outcome": "read",
        }
        if name == "search":
            results, pagination = payload.get("results"), payload.get("pagination")
            if not isinstance(results, list) or not isinstance(pagination, dict):
                raise McpFacadeError("Integrity Home returned an invalid search page")
            returned_count = pagination.get("returned_count")
            if (
                isinstance(returned_count, bool)
                or not isinstance(returned_count, int)
                or returned_count != len(results)
                or not 0 <= returned_count <= MAX_HOME_PAGE_SIZE
            ):
                raise McpFacadeError("Integrity Home returned an invalid search count")
            receipt.update(
                {
                    "returned_count": returned_count,
                    "has_more": bool(pagination.get("has_more")),
                    "possibly_truncated": bool(pagination.get("possibly_truncated")),
                }
            )
        else:
            encoded = canonical_json(payload)
            receipt.update(
                {
                    "response_sha256": hashlib.sha256(encoded).hexdigest(),
                    "response_bytes": len(encoded),
                }
            )
        self.audit(receipt)
        return {"home": payload, "receipt": receipt}

    def call(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name == "integrity_turn_memory_open":
            return self._turn_memory_call("open", arguments)
        if name == "integrity_turn_memory_close":
            return self._turn_memory_call("close", arguments)
        if name == "integrity_turn_memory_gap":
            return self._turn_memory_call("gap", arguments)
        if name == "integrity_turn_memory_coverage":
            return self._turn_memory_call("coverage", arguments)
        if name == "integrity_context_admission_current_turn":
            raise InputValidationError(
                "current-turn admission must be resolved by the authenticated local broker",
                reason_code="turn_envelope_resolution_required",
            )
        if name == "integrity_context_admission":
            incoming_replay_id = arguments.get(CONTEXT_ADMISSION_REPLAY_FIELD)
            if (
                isinstance(incoming_replay_id, str)
                and self._active_context_replay_id != incoming_replay_id
            ):
                deadline = (
                    time.monotonic()
                    + CONTEXT_ADMISSION_REPLAY_OPERATION_TIMEOUT_SECONDS
                )
                with self._context_replay_lock(
                    incoming_replay_id,
                    deadline_monotonic=deadline,
                ):
                    self._active_context_replay_id = incoming_replay_id
                    self._active_context_replay_deadline = deadline
                    try:
                        return self.call(name, arguments)
                    finally:
                        self._active_context_replay_id = None
                        self._active_context_replay_deadline = None
            admission_arguments = dict(arguments)
            replay_id = admission_arguments.pop(CONTEXT_ADMISSION_REPLAY_FIELD, None)
            _reject_unknown(
                admission_arguments,
                {"intent", "limit", "budget", TURN_ENVELOPE_BINDING_FIELD},
            )
            if replay_id is not None and not isinstance(replay_id, str):
                raise McpFacadeError("context admission replay identity is invalid")
            if isinstance(replay_id, str):
                self._require_context_replay_reservation(replay_id)
                self._check_context_replay_deadline()
            request_digest = _sha256(admission_arguments)
            replay: dict[str, Any] | None = None
            if isinstance(replay_id, str):
                replay = self._load_context_replay(replay_id, request_digest)
                if replay is not None and replay.get("phase") == "committed":
                    return self._restore_context_replay(replay)
            arguments = admission_arguments
            intent = arguments.get("intent")
            raw_prompt_binding = arguments.get(TURN_ENVELOPE_BINDING_FIELD)
            if raw_prompt_binding is not None and not self._broker_tool_surface_authenticated:
                raise InputValidationError(
                    "turn envelope binding requires an authenticated local broker surface",
                    reason_code="turn_envelope_unauthenticated",
                )
            if not isinstance(intent, str) or not intent.strip() or (
                raw_prompt_binding is None and len(intent) > 4_096
            ):
                raise InputValidationError(
                    "intent must contain 1 to 4096 characters",
                    reason_code=(
                        "intent_too_long"
                        if isinstance(intent, str) and len(intent) > 4_096
                        else "intent_invalid"
                    ),
                )
            prompt_binding = (
                _validated_turn_binding(raw_prompt_binding, intent)
                if raw_prompt_binding is not None
                else None
            )
            try:
                policy = resolve_context_budget(
                    intent.strip(),
                    legacy_limit=(
                        _integer(arguments, "limit", 20, 1, 50) if "limit" in arguments else None
                    ),
                    budget=arguments.get("budget") if "budget" in arguments else None,
                )
            except ContextBudgetError as exc:
                raise McpFacadeError(str(exc)) from exc
            if replay is not None:
                prepared = replay["prepared"]
                generation = prepared.get("logical_generation")
                observed_at = prepared.get("observed_at")
                if (
                    isinstance(generation, bool)
                    or not isinstance(generation, int)
                    or generation < 1
                    or not isinstance(observed_at, str)
                    or prepared.get("policy_mode") != policy.mode
                    or not isinstance(prepared.get("capabilities"), dict)
                    or not isinstance(prepared.get("snapshot"), dict)
                    or not isinstance(prepared.get("mind"), dict)
                    or prepared.get("prompt_binding") != prompt_binding
                    or not isinstance(replay.get("state", {}).get("mind"), dict)
                ):
                    raise McpFacadeError("context admission replay record is invalid")
                self._clear_intent_context()
                self._context_generation = generation
                capabilities = self._restore_context_replay_capabilities(
                    prepared["capabilities"]
                )
                catalog_binding = prepared.get("frozen_catalog")
                if catalog_binding is not None and not isinstance(catalog_binding, dict):
                    raise McpFacadeError("context admission replay catalog binding is invalid")
                self._install_context_replay_catalog(
                    replay_id,
                    catalog_binding,
                    artifact_digest=str(prepared["capabilities"].get("artifact_digest", "")),
                )
                snapshot = self.call("integrity_seed_snapshot", {})
                if (
                    capabilities != prepared["capabilities"] or snapshot != prepared["snapshot"]
                ):
                    self._clear_intent_context()
                    self._context_generation = generation
                    raise McpFacadeError("context admission replay snapshot changed")
                mind = prepared["mind"]
                self._session_mind = replay["state"]["mind"]
            else:
                generation = self._context_generation + 1
                self._context_generation = generation
                self._clear_intent_context()
                try:
                    capabilities = self.call("integrity_memory_capabilities", {})
                    snapshot = self.call("integrity_seed_snapshot", {})
                    mind_arguments: dict[str, Any] = {
                        "snapshot_id": snapshot["snapshot_id"],
                        "intent": intent,
                    }
                    if prompt_binding is not None:
                        mind_arguments[TURN_ENVELOPE_BINDING_FIELD] = prompt_binding
                    if policy.mode == "fixed-compat":
                        mind_arguments["limit"] = policy.transport_candidate_cap
                    else:
                        mind_arguments["budget"] = {
                            "max_context_bytes": policy.max_context_bytes,
                            "max_candidates": policy.max_candidates,
                        }
                    mind = self.call(
                        "integrity_mind_graph",
                        mind_arguments,
                    )
                    if isinstance(replay_id, str):
                        self._check_context_replay_deadline()
                except Exception as exc:  # Every read fault must leave EMPTY.
                    self._clear_intent_context()
                    self._context_generation = generation
                    if isinstance(exc, McpFacadeError):
                        raise
                    raise McpFacadeError("context admission read plane unavailable") from exc
                observed_at = _utc_now()
                if isinstance(replay_id, str):
                    catalog_binding = self._persist_context_replay_catalog(replay_id)
                    replay = self._store_context_replay(
                        {
                            "protocol": CONTEXT_ADMISSION_REPLAY_PROTOCOL,
                            "phase": "prepared",
                            "request_id": replay_id,
                            "request_digest": request_digest,
                            "prepared": {
                                "logical_generation": generation,
                                "observed_at": observed_at,
                                "policy_mode": policy.mode,
                                "capabilities": capabilities,
                                "snapshot": snapshot,
                                "mind": mind,
                                "prompt_binding": prompt_binding,
                                "frozen_catalog": catalog_binding,
                            },
                            "state": {
                                "logical_generation": generation,
                                "mind": self._session_mind,
                            },
                        }
                    )
                    if replay.get("phase") == "committed":
                        return self._restore_context_replay(replay)
            # Seed/Mind is already fixed: recovery failure remains a write-plane
            # condition and cannot revoke the canonical read capsule.
            migration = self._replay_migration(replay_id) if isinstance(replay_id, str) else None
            if migration is None:
                self._maybe_recover_write_plane()
            try:
                if migration is not None:
                    self._deny_migrated_action_authority()
                    raise McpFacadeError("migrated replay is read-only; fresh action admission required")
                if isinstance(replay_id, str):
                    self._check_context_replay_deadline()
                    self._prepare_context_replay_custody()
                architecture = self._architecture_admission(
                    {"mind_receipt_id": mind["admission_receipt"]["receipt_id"]},
                    observed_at=observed_at if isinstance(replay_id, str) else None,
                )
                if isinstance(replay_id, str):
                    self._check_context_replay_deadline()
                    self._prepare_context_replay_custody()
                if policy.mode == "adaptive":
                    architecture = compact_architecture_admission(architecture)
                    validate("memory-synapse-architecture-capsule", architecture)
            except (
                McpFacadeError,
                MemorySynapseLtsError,
                ValidationError,
                OSError,
                sqlite3.Error,
                ValueError,
                TypeError,
            ) as exc:
                architecture = self._architecture_unavailable(exc)
            if (
                self.native_trust is not None
                and self._session_architecture is not None
                and self._session_write_plane_status.get("outcome") == "ready"
            ):
                assert self.native_device_id is not None
                try:
                    if isinstance(replay_id, str):
                        self._check_context_replay_deadline()
                        self._prepare_context_replay_custody()
                    self._native_session_lease = self.native_trust.open_session(
                        device_id=self.native_device_id,
                        scopes=DEFAULT_DEVICE_SCOPES,
                        **(
                            {"issued_at": observed_at, "idempotency_key": replay_id}
                            if isinstance(replay_id, str)
                            else {}
                        ),
                    )
                    if isinstance(replay_id, str):
                        self._check_context_replay_deadline()
                        self._prepare_context_replay_custody()
                except (
                    NativeTrustError,
                    OSError,
                    sqlite3.Error,
                    ValueError,
                    TypeError,
                ) as exc:
                    self._native_session_lease = None
                    self._session_architecture = None
                    self._mark_session_write_plane_unavailable("native_session")
                    native_denial = {
                        "exception_type": type(exc).__name__,
                        "reason": str(exc)[:500],
                    }
                    architecture = {
                        **architecture,
                        "native_session": {
                            "protocol": BRIDGE_PROTOCOL + "/native-session-unavailable/v1",
                            "outcome": "unavailable",
                            "failure_layer": "write-plane-admission",
                            "reason_digest": _sha256(native_denial),
                            "canonical_writes": 0,
                            "production_authority": False,
                        },
                    }
            context_admission_id = self._context_admission_receipt_id(
                generation=generation,
                snapshot=snapshot,
                mind=mind,
                architecture=architecture,
                prompt_binding=prompt_binding,
            )
            self._context_admission_id = context_admission_id
            coordination_status = (
                "stopped"
                if mind["admission_receipt"]["coordination_stop_required"] is True
                else "ready"
            )
            result = {
                "protocol": BRIDGE_PROTOCOL
                + (
                    "/context-admission/v2"
                    if policy.mode == "adaptive"
                    else "/context-admission/v1"
                ),
                "logical_generation": generation,
                "context_admission_id": context_admission_id,
                "capabilities": capabilities,
                "snapshot": snapshot,
                "mind": mind,
                "architecture": architecture,
                "write_plane": dict(self._session_write_plane_status),
                "trust_profile": (
                    NATIVE_TRUST_PROFILE if self.native_trust is not None else "managed-external"
                ),
                "canonical_writes": 0,
                "home_record_count": 0,
                "production_authority": False,
                "authority_contract": memory_authority_contract(coordination_status),
            }
            if prompt_binding is not None:
                result["prompt_binding"] = prompt_binding
            if policy.mode == "adaptive":
                result["presentation_mode"] = policy.mode
            if isinstance(replay_id, str):
                self._check_context_replay_deadline()
                record = {
                    "protocol": CONTEXT_ADMISSION_REPLAY_PROTOCOL,
                    "phase": "committed",
                    "request_id": replay_id,
                    "request_digest": request_digest,
                    "result": result,
                    "state": {
                        "logical_generation": generation,
                        "mind": self._session_mind,
                        "architecture": self._session_architecture,
                        "write_plane": self._session_write_plane_status,
                        "native_session": self._native_session_lease,
                        "frozen_catalog": (
                            replay.get("prepared", {}).get("frozen_catalog")
                            if replay is not None
                            else None
                        ),
                    },
                }
                if migration is not None:
                    # The private owner admission preserves the exact original
                    # PREPARED bytes; this is a new, linked COMMITTED record.
                    record["migration_admission_sha256"] = migration.receipt_sha256
                stored = self._store_context_replay(record, expected_phase="prepared")
                if stored != record:
                    return self._restore_context_replay(stored)
            return result
        if name == "integrity_read_events":
            self._require_seed_snapshot()
            return self.action_log.read(arguments)
        if name == "integrity_append_event":
            event_arguments, context_binding = self._bind_append_to_current_context(arguments)
            if self._session_write_plane_status.get("outcome") != "ready":
                raise McpFacadeError("Uroboros append action boundary is unavailable")
            self._require_architecture_admission()
            return self._event_append_action(
                event_arguments,
                context_binding=context_binding,
            )
        if name == "integrity_home_search":
            return self._home("search", arguments)
        if name == "integrity_home_fetch":
            return self._home("fetch", arguments)
        if name == "integrity_memory_capabilities":
            _reject_unknown(arguments, set())
            if self._session_capabilities is None:
                self._session_capabilities = self.lts.capabilities()
            return self._audit_lts_read(name, arguments, self._session_capabilities)
        if name == "integrity_seed_snapshot":
            _reject_unknown(arguments, set())
            if self._session_capabilities is None:
                raise McpFacadeError(
                    "integrity_memory_capabilities admission is required before Seed snapshot"
                )
            if self._session_snapshot is None:
                self._ensure_frozen_lts()
                self._session_snapshot = self._read_seed_snapshot()
            return self._audit_lts_read(name, arguments, self._session_snapshot)
        if name == "integrity_mind_graph":
            snapshot = self._require_seed_snapshot()
            _reject_unknown(
                arguments,
                {"snapshot_id", "intent", "limit", "budget", TURN_ENVELOPE_BINDING_FIELD},
            )
            expected_snapshot_id = str(arguments.get("snapshot_id", ""))
            if expected_snapshot_id != snapshot.get("snapshot_id"):
                raise McpFacadeError("snapshot_id does not match session admission")
            if self._session_mind is not None:
                raise McpFacadeError("Mind Graph admission is already fixed for this session")
            intent = arguments.get("intent")
            raw_prompt_binding = arguments.get(TURN_ENVELOPE_BINDING_FIELD)
            if raw_prompt_binding is not None and not self._broker_tool_surface_authenticated:
                raise McpFacadeError("turn envelope binding is not authenticated")
            if not isinstance(intent, str) or not intent.strip() or (
                raw_prompt_binding is None and len(intent) > 4_096
            ):
                raise McpFacadeError("intent must contain 1 to 4096 characters")
            if raw_prompt_binding is not None:
                _validated_turn_binding(raw_prompt_binding, intent)
            try:
                policy = resolve_context_budget(
                    intent.strip(),
                    legacy_limit=(
                        _integer(arguments, "limit", 20, 1, 50) if "limit" in arguments else None
                    ),
                    budget=arguments.get("budget") if "budget" in arguments else None,
                )
            except ContextBudgetError as exc:
                raise McpFacadeError(str(exc)) from exc
            action_log_arguments: dict[str, Any] = {
                "intent": intent,
                "limit": policy.transport_candidate_cap,
            }
            if raw_prompt_binding is not None:
                action_log_arguments["_integrity_exact_prompt"] = True
            value = self.action_log.mind(action_log_arguments)
            admission_receipt = value.get("admission_receipt")
            if not isinstance(admission_receipt, dict):
                raise McpFacadeError("Mind Graph returned no admission receipt")
            try:
                value["admission_receipt"] = bind_seed_catalog_to_admission(
                    admission_receipt,
                    seed_snapshot_id=str(snapshot.get("snapshot_id") or ""),
                    seed_source_digest=str(snapshot.get("source_digest") or ""),
                    seed_catalog_digest=str(snapshot.get("catalog_digest") or ""),
                )
            except MindAdmissionError as exc:
                raise McpFacadeError(str(exc)) from exc
            if policy.mode == "fixed-compat":
                self._session_mind = value
                return self._audit_lts_read(name, arguments, value)
            source_mind = value.get("mind")
            if not isinstance(source_mind, dict):
                raise McpFacadeError("Mind Graph returned an invalid projection")
            try:
                capsule, selection_receipt = build_context_capsule(
                    source_mind,
                    value["admission_receipt"],
                    policy,
                )
                validate("memory-synapse-context-selection", selection_receipt)
            except ValidationError as exc:
                raise McpFacadeError("context selection receipt schema is invalid") from exc
            except ContextBudgetError as exc:
                raise McpFacadeError(str(exc)) from exc
            presented = {
                "mind": capsule,
                "admission_receipt": value["admission_receipt"],
                "selection_receipt": selection_receipt,
            }
            self._session_mind = value
            return self._audit_lts_read(name, arguments, presented)
        if name == "integrity_architecture_admission":
            return self._architecture_admission(arguments)
        if name == "integrity_seed_connections":
            snapshot = self._require_seed_snapshot()
            _reject_unknown(
                arguments,
                {"snapshot_id", "event_id", "selection_seed", "limit", "include_contextual"},
            )
            event_id = arguments.get("event_id")
            if event_id is not None and (
                isinstance(event_id, bool) or not isinstance(event_id, int) or event_id < 1
            ):
                raise McpFacadeError("event_id must be a positive integer")
            selection_seed = arguments.get("selection_seed")
            if selection_seed is not None and not isinstance(selection_seed, str):
                raise McpFacadeError("selection_seed must be a string")
            if (event_id is None) == (selection_seed is None):
                raise McpFacadeError("provide exactly one event_id or selection_seed")
            expected_snapshot_id = str(arguments.get("snapshot_id", ""))
            if expected_snapshot_id != snapshot.get("snapshot_id"):
                raise McpFacadeError("snapshot_id does not match session admission")
            value = self.lts.connections(
                expected_snapshot_id=expected_snapshot_id,
                event_id=event_id,
                selection_seed=selection_seed,
                limit=_integer(arguments, "limit", 20, 1, 200),
                include_contextual=_boolean(arguments, "include_contextual", False),
            )
            return self._audit_lts_read(name, arguments, value)
        if name == "integrity_seed_event_uid":
            snapshot = self._require_seed_snapshot()
            _reject_unknown(arguments, {"snapshot_id", "event_uid"})
            expected_snapshot_id = str(arguments.get("snapshot_id", ""))
            if expected_snapshot_id != snapshot.get("snapshot_id"):
                raise McpFacadeError("snapshot_id does not match session admission")
            event_uid = arguments.get("event_uid")
            if (
                not isinstance(event_uid, str)
                or not event_uid
                or event_uid != event_uid.strip()
                or len(event_uid) > 256
            ):
                raise McpFacadeError("event_uid must contain 1 to 256 exact characters")
            value = self.lts.event_uid_lookup(
                expected_snapshot_id=expected_snapshot_id,
                event_uid=event_uid,
            )
            return self._audit_lts_read(name, arguments, value)
        if name == "integrity_seed_tasks":
            snapshot = self._require_seed_snapshot()
            _reject_unknown(arguments, {"snapshot_id", "view", "after_task_id", "limit"})
            expected_snapshot_id = str(arguments.get("snapshot_id", ""))
            if expected_snapshot_id != snapshot.get("snapshot_id"):
                raise McpFacadeError("snapshot_id does not match session admission")
            view = arguments.get("view", "work_queue_review")
            if not isinstance(view, str):
                raise McpFacadeError("view must be a canonical task inventory view")
            after_task_id = arguments.get("after_task_id", "")
            if not isinstance(after_task_id, str):
                raise McpFacadeError("after_task_id must be a string")
            value = self.lts.tasks(
                expected_snapshot_id=expected_snapshot_id,
                view=view,
                after_task_id=after_task_id,
                limit=_integer(arguments, "limit", 50, 1, 200),
            )
            return self._audit_lts_read(name, arguments, value)
        if name == "integrity_memory_entity_brief":
            snapshot = self._require_seed_snapshot()
            _reject_unknown(
                arguments,
                {
                    "snapshot_id",
                    "reference",
                    "relationship_limit",
                    "activity_limit",
                    "task_limit",
                    "discovery_limit",
                    "max_context_bytes",
                },
            )
            expected_snapshot_id = str(arguments.get("snapshot_id", ""))
            if expected_snapshot_id != snapshot.get("snapshot_id"):
                raise McpFacadeError("snapshot_id does not match session admission")
            reference = arguments.get("reference")
            if not isinstance(reference, str) or not reference.strip() or len(reference) > 4096:
                raise McpFacadeError("reference must contain 1 to 4096 characters")
            value = self._memory_link_graph().entity_brief(
                reference.strip(),
                relationship_limit=_integer(arguments, "relationship_limit", 40, 1, 100),
                activity_limit=_integer(arguments, "activity_limit", 12, 1, 20),
                task_limit=_integer(arguments, "task_limit", 20, 1, 20),
                discovery_limit=_integer(arguments, "discovery_limit", 10, 1, 20),
                max_context_bytes=_integer(
                    arguments,
                    "max_context_bytes",
                    65_536,
                    8_192,
                    262_144,
                ),
            )
            try:
                validate("memory-entity-brief", value)
            except ValidationError as exc:
                raise McpFacadeError("memory entity brief schema is invalid") from exc
            return self._audit_lts_read(name, arguments, value)
        if name == "integrity_memory_ttt_autofill":
            snapshot = self._require_seed_snapshot()
            _reject_unknown(arguments, {"snapshot_id", "goal", "last_hop"})
            expected_snapshot_id = str(arguments.get("snapshot_id", ""))
            if expected_snapshot_id != snapshot.get("snapshot_id"):
                raise McpFacadeError("snapshot_id does not match session admission")
            goal = arguments.get("goal")
            last_hop = arguments.get("last_hop")
            if not isinstance(goal, str) or not goal.strip() or len(goal) > 512:
                raise McpFacadeError("goal must contain 1 to 512 characters")
            if not isinstance(last_hop, str) or not last_hop.strip() or len(last_hop) > 512:
                raise McpFacadeError("last_hop must contain 1 to 512 characters")
            graph = self._memory_link_graph()
            try:
                value = memory_ttt_autofill(
                    goal,
                    last_hop,
                    graph=graph,
                    snapshot_id=expected_snapshot_id,
                    expected_graph_digest=graph.graph_digest,
                    catalog=self._memory_ttt_catalog(),
                )
                binding_core = {
                    "protocol": "integrity-client/memory-ttt-snapshot-binding/v1",
                    "snapshot_id": snapshot["snapshot_id"],
                    "seed_source_digest": snapshot.get("source_digest"),
                    "seed_catalog_digest": snapshot.get("catalog_digest"),
                    "snapshot_event_id": snapshot.get("cursor", {}).get("maximum_event_id"),
                    "graph_digest": graph.graph_digest,
                    "path_catalog_digest": value.get("path_catalog_digest"),
                    "ttt_receipt_id": value["receipt_id"],
                    "production_authority": False,
                    "route_authority": False,
                }
                value["snapshot_binding"] = {
                    **binding_core,
                    "receipt_id": _sha256({
                        "domain": "memory-ttt-mcp-snapshot-binding-v1",
                        "binding": binding_core,
                    }),
                }
                validate("memory-ttt-autofill", value)
            except (MemoryTttPathError, ValidationError) as exc:
                raise McpFacadeError("memory TTT result failed closed") from exc
            return self._audit_lts_read(name, arguments, value)
        if name == "integrity_memory_link_audit":
            snapshot = self._require_seed_snapshot()
            _reject_unknown(
                arguments,
                {"snapshot_id", "kinds", "limit", "max_context_bytes", "cursor"},
            )
            expected_snapshot_id = str(arguments.get("snapshot_id", ""))
            if expected_snapshot_id != snapshot.get("snapshot_id"):
                raise McpFacadeError("snapshot_id does not match session admission")
            kinds = arguments.get("kinds", [])
            if not isinstance(kinds, list) or any(not isinstance(kind, str) for kind in kinds):
                raise McpFacadeError("kinds must be an array of memory node kinds")
            cursor = arguments.get("cursor", "")
            if not isinstance(cursor, str):
                raise McpFacadeError("cursor must be a string")
            value = self._memory_link_graph().audit(
                kinds=kinds,
                limit=_integer(arguments, "limit", 50, 1, 100),
                max_context_bytes=_integer(
                    arguments,
                    "max_context_bytes",
                    65_536,
                    8_192,
                    262_144,
                ),
                cursor=cursor,
            )
            try:
                validate("memory-link-audit", value)
            except ValidationError as exc:
                raise McpFacadeError("memory link audit schema is invalid") from exc
            return self._audit_lts_read(name, arguments, value)
        if name == "integrity_seed_replay":
            snapshot = self._require_seed_snapshot()
            allowed = {
                "snapshot_id",
                "selection_seed",
                "expected_event_id",
                "expected_explanation_digest",
                "expected_receipt_id",
                "limit",
                "include_contextual",
            }
            _reject_unknown(arguments, allowed)
            expected_event_id = arguments.get("expected_event_id")
            if (
                isinstance(expected_event_id, bool)
                or not isinstance(expected_event_id, int)
                or expected_event_id < 1
            ):
                raise McpFacadeError("expected_event_id must be a positive integer")
            expected_snapshot_id = str(arguments.get("snapshot_id", ""))
            if expected_snapshot_id != snapshot.get("snapshot_id"):
                raise McpFacadeError("snapshot_id does not match session admission")
            value = self.lts.replay(
                expected_snapshot_id=expected_snapshot_id,
                selection_seed=str(arguments.get("selection_seed", "")),
                expected_event_id=expected_event_id,
                expected_explanation_digest=str(arguments.get("expected_explanation_digest", "")),
                expected_receipt_id=str(arguments.get("expected_receipt_id", "")),
                limit=_integer(arguments, "limit", 20, 1, 200),
                include_contextual=_boolean(arguments, "include_contextual", False),
            )
            return self._audit_lts_read(name, arguments, value)
        raise McpFacadeError("tool is not exposed by the client facade")

    def _memory_link_graph(self) -> MemoryLinkGraph:
        snapshot = self._require_seed_snapshot()
        if self._session_memory_link_graph is None:
            try:
                graph = MemoryLinkGraph.from_catalog(
                    self.lts.catalog_path,
                    immutable=self.lts.immutable_catalog,
                    readonly_connection=self.lts.catalog_connection,
                )
            except MemoryLinkGraphError as exc:
                raise McpFacadeError("memory link graph projection failed closed") from exc
            if (
                graph.source_digest != snapshot.get("source_digest")
                or graph.catalog_digest != snapshot.get("catalog_digest")
                or graph.source_max_event_id != snapshot.get("cursor", {}).get("maximum_event_id")
            ):
                raise McpFacadeError("memory link graph does not match the session snapshot")
            self._session_memory_link_graph = graph
        return self._session_memory_link_graph

    def _memory_ttt_catalog(self) -> RunbookPathCatalog:
        self._require_seed_snapshot()
        if self._session_memory_ttt_path_catalog is None:
            catalog = register_paths(
                RunbookPathCatalog(),
                self._memory_ttt_path_documents,
            )
            catalog.source_digest = self._memory_ttt_path_catalog_digest
            catalog.validate()
            self._session_memory_ttt_path_catalog = catalog
        return self._session_memory_ttt_path_catalog

    def _require_seed_snapshot(self) -> dict[str, Any]:
        if self._session_snapshot is None:
            raise McpFacadeError(
                "capabilities and integrity_seed_snapshot admission are required before Seed reads"
            )
        return self._session_snapshot

    def _require_mind_admission(self) -> dict[str, Any]:
        snapshot = self._require_seed_snapshot()
        if self._session_mind is None:
            raise McpFacadeError(
                "integrity_mind_graph admission is required before Seed read or append"
            )
        return snapshot

    def _require_architecture_admission(self) -> dict[str, Any]:
        snapshot = self._require_mind_admission()
        if self._session_architecture is None:
            raise McpFacadeError(
                "integrity_architecture_admission is required before Seed read or append"
            )
        return snapshot


def _annotations(*, read_only: bool, idempotent: bool = True) -> dict[str, bool]:
    return {
        "readOnlyHint": read_only,
        "destructiveHint": False,
        "idempotentHint": idempotent,
        "openWorldHint": False,
    }


def _tool_contract_profile(initialize_params: dict[str, Any]) -> str:
    # Broker 1.2.1 was deployed with more than one tools contract, including
    # the later 19-tool surface.  Its initialize request carries only the
    # broker version, so selecting a surface from that version is ambiguous
    # and broke the live 1.2.1 + 19-tool pairing during the 2.10 rollout.
    # Non-declarative brokers therefore retain the current pre-2.10 behavior.
    # Broker 1.3+ declares the exact local surface digest and negotiates older
    # local catalogs through _broker_tool_surface_ack instead.
    requested = _requested_broker_tool_surface(initialize_params)
    if requested == _tool_surface_sha256(tools()):
        return CURRENT_TOOL_CONTRACT_PROFILE
    if requested == _tool_surface_sha256(tools(profile=PRE_TTT_TOOL_CONTRACT_PROFILE)):
        return PRE_TTT_TOOL_CONTRACT_PROFILE
    return PRE_V4_TOOL_CONTRACT_PROFILE


def _tool_surface_sha256(value: list[dict[str, Any]]) -> str:
    surface = [
        {
            "name": item.get("name"),
            "inputSchema": item.get("inputSchema"),
            "annotations": item.get("annotations"),
        }
        for item in value
    ]
    return "sha256:" + hashlib.sha256(canonical_json(surface)).hexdigest()


def _requested_broker_tool_surface(initialize_params: dict[str, Any]) -> str | None:
    client_info = initialize_params.get("clientInfo")
    capabilities = initialize_params.get("capabilities")
    if (
        not isinstance(client_info, dict)
        or client_info.get("name") != "integrity-client-turn-broker"
        or not isinstance(capabilities, dict)
    ):
        return None
    experimental = capabilities.get("experimental")
    declaration = (
        experimental.get(BROKER_TOOL_SURFACE_CAPABILITY) if isinstance(experimental, dict) else None
    )
    if (
        not isinstance(declaration, dict)
        or declaration.get("protocol") != BROKER_TOOL_SURFACE_PROTOCOL
    ):
        return None
    surface_sha256 = declaration.get("tools_surface_sha256")
    if (
        not isinstance(surface_sha256, str)
        or re.fullmatch(r"sha256:[a-f0-9]{64}", surface_sha256) is None
    ):
        return None
    return surface_sha256


def _broker_tool_surface_ack(initialize_params: dict[str, Any]) -> dict[str, Any] | None:
    requested = _requested_broker_tool_surface(initialize_params)
    if requested is None:
        return None
    supported = {
        _tool_surface_sha256(tools()),
        *RETAINED_BROKER_TOOL_SURFACE_SHA256,
    }
    if requested not in supported:
        return None
    return {
        "protocol": BROKER_TOOL_SURFACE_PROTOCOL,
        "accepted_tools_surface_sha256": requested,
        "compatibility": "local-contract-facade-with-upstream-name-subset/v1",
    }


def _broker_context_admission_replay_ack(
    initialize_params: dict[str, Any],
    *,
    durable_replay_available: bool,
) -> dict[str, Any] | None:
    client_info = initialize_params.get("clientInfo")
    capabilities = initialize_params.get("capabilities")
    experimental = capabilities.get("experimental") if isinstance(capabilities, dict) else None
    declaration = (
        experimental.get(CONTEXT_ADMISSION_REPLAY_CAPABILITY)
        if isinstance(experimental, dict)
        else None
    )
    reservation_id = (
        declaration.get("reservation_id") if isinstance(declaration, dict) else None
    )
    if (
        not isinstance(client_info, dict)
        or client_info.get("name") != "integrity-client-turn-broker"
        or not durable_replay_available
        or not isinstance(declaration, dict)
        or declaration.get("protocol") != CONTEXT_ADMISSION_REPLAY_PROTOCOL
        or declaration.get("request_identity_field") != CONTEXT_ADMISSION_REPLAY_FIELD
        or declaration.get("request_identity_format") != "sha256/v1"
        or not isinstance(reservation_id, str)
        or re.fullmatch(r"sha256:[a-f0-9]{64}", reservation_id) is None
    ):
        return None
    return {
        "protocol": CONTEXT_ADMISSION_REPLAY_PROTOCOL,
        "request_identity_field": CONTEXT_ADMISSION_REPLAY_FIELD,
        "request_identity_format": "sha256/v1",
        "reservation_id": reservation_id,
        "reservation_method": CONTEXT_ADMISSION_REPLAY_RESERVE_METHOD,
        "ack_method": CONTEXT_ADMISSION_REPLAY_ACK_METHOD,
        "durability": "architecture-custody-root/v1",
        "replay_semantics": "exact-response/v1",
        "max_transport_retries": 1,
    }


def _broker_supports_replay_control_only(initialize_params: dict[str, Any]) -> bool:
    client_info = initialize_params.get("clientInfo")
    if not isinstance(client_info, dict):
        return False
    version = client_info.get("version")
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", str(version))
    return bool(
        client_info.get("name") == "integrity-client-turn-broker"
        and match is not None
        and tuple(int(match.group(index)) for index in range(1, 4)) >= (1, 3, 1)
    )


def tools(*, profile: str = CURRENT_TOOL_CONTRACT_PROFILE) -> list[dict[str, Any]]:
    """Closed backwards-compatible allowlist; there is no generic write tool."""

    if profile not in {
        CURRENT_TOOL_CONTRACT_PROFILE,
        PRE_TTT_TOOL_CONTRACT_PROFILE,
        PRE_V4_TOOL_CONTRACT_PROFILE,
        LEGACY_TURN_BROKER_TOOL_CONTRACT_PROFILE,
    }:
        raise ValueError("unknown MCP tool contract profile")

    object_schema = {"type": "object", "additionalProperties": False, "properties": {}}
    context_budget_schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "max_context_bytes": {
                "type": "integer",
                "minimum": 8_192,
                "maximum": 262_144,
            },
            "max_candidates": {"type": "integer", "minimum": 1, "maximum": 50},
        },
    }
    exposed = [
        {
            "name": "integrity_read_events",
            "description": "Read historical Seed evidence from the server-bound snapshot; do not infer task lifecycle from raw pages. Exact duplicates are denied.",
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "page_size": {"type": "integer", "minimum": 1, "maximum": 100},
                    "after_id": {"type": "integer", "minimum": 0},
                    "snapshot_event_id": {"type": "integer", "minimum": 0},
                },
            },
            "annotations": _annotations(read_only=True),
        },
        {
            "name": "integrity_append_event",
            "description": "Append one immutable client task, thought, or concept. Echo the context_admission_id returned for the current owner intent; missing, stale or mismatched bindings are denied before prepare, witness, native, ledger or append side effects, while the current binding enters the signed v2 decision and one-use Ledger grant.",
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["event_uid", "kind", "summary", "context_admission_id"],
                "properties": {
                    "event_uid": {
                        "type": "string",
                        "pattern": "^client:[A-Za-z0-9][A-Za-z0-9._:-]{7,154}$",
                    },
                    "kind": {"enum": sorted(EVENT_KINDS)},
                    "summary": {"type": "string", "minLength": 1, "maxLength": 2000},
                    "details": {"type": "object"},
                    "tags": {"type": "array", "maxItems": 20, "items": {"type": "string"}},
                    "context_admission_id": {
                        "type": "string",
                        "pattern": "^sha256:[a-f0-9]{64}$",
                    },
                    "authority_decision": {"type": "object"},
                },
            },
            "annotations": _annotations(read_only=False),
        },
        {
            "name": "integrity_turn_memory_open",
            "description": "Register one machine/thread/turn and prompt digest in the canonical Turn Memory coverage ledger before semantic work begins.",
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["machine_id", "thread_id", "turn_id", "prompt_sha256"],
                "properties": {
                    "machine_id": {"type": "string", "minLength": 1, "maxLength": 256},
                    "thread_id": {"type": "string", "minLength": 1, "maxLength": 256},
                    "turn_id": {"type": "string", "minLength": 1, "maxLength": 256},
                    "prompt_sha256": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
                },
            },
            "annotations": _annotations(read_only=False),
        },
        {
            "name": "integrity_turn_memory_close",
            "description": "Create exactly one signed terminal receipt. Supply events only when outcome=events; supply no_event_reason only when outcome=no-event. The server rejects missing or mixed alternatives.",
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["registration_id", "outcome"],
                "properties": {
                    "registration_id": {"type": "string", "pattern": "^sha256:[a-f0-9]{64}$"},
                    "outcome": {"enum": ["events", "no-event"]},
                    "events": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": 32,
                        "items": {
                            "type": "object",
                            "additionalProperties": False,
                            "required": ["event_uid", "event_id", "request_sha256"],
                            "properties": {
                                "event_uid": {"type": "string"},
                                "event_id": {"type": "integer", "minimum": 1},
                                "request_sha256": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
                            },
                        },
                    },
                    "no_event_reason": {"enum": sorted(NO_EVENT_REASONS)},
                },
            },
            "annotations": _annotations(read_only=False),
        },
        {
            "name": "integrity_turn_memory_gap",
            "description": "Record signed coverage debt when a registered turn reaches an observer boundary without a terminal receipt; never classifies no-event.",
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["registration_id", "stage"],
                "properties": {
                    "registration_id": {"type": "string", "pattern": "^sha256:[a-f0-9]{64}$"},
                    "stage": {"enum": ["stop", "notify", "reconciliation"]},
                },
            },
            "annotations": _annotations(read_only=False),
        },
        {
            "name": "integrity_turn_memory_coverage",
            "description": "Read bounded terminal and unresolved Turn Memory coverage for the canonical namespace.",
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "machine_id": {"type": "string", "minLength": 1, "maxLength": 256},
                    "thread_id": {"type": "string", "minLength": 1, "maxLength": 256},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 500},
                },
            },
            "annotations": _annotations(read_only=True),
        },
        {
            "name": "integrity_home_search",
            "description": "Search the fixed separate Integrity Home in bounded pages. Supply exactly one of query (first page) or cursor (next page); the server rejects missing or mixed alternatives.",
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "query": {"type": "string", "minLength": 1, "maxLength": 4096},
                    "cursor": {"type": "string", "minLength": 8, "maxLength": 80},
                    "page_size": {"type": "integer", "minimum": 1, "maximum": 10},
                },
            },
            "annotations": _annotations(read_only=True),
        },
        {
            "name": "integrity_home_fetch",
            "description": "Fetch bounded Home evidence by opaque handle.",
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["id"],
                "properties": {"id": {"type": "string", "minLength": 8, "maxLength": 80}},
            },
            "annotations": _annotations(read_only=True),
        },
        {
            "name": "integrity_context_admission",
            "description": "Preferred per-owner-intent hot path: invoke exactly once per owner intent/turn; each valid call rotates the isolated logical context inside the existing stdio transport, then adaptively selects a byte-bounded context capsule for the exact intent while retaining the complete immutable Seed/Mind projection inside the session for Guardian custody and append admission. Omit limit for adaptive mode; explicit limit is fixed/full compatibility only.",
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["intent"],
                "properties": {
                    "intent": {"type": "string", "minLength": 1, "maxLength": 4096},
                    "budget": context_budget_schema,
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 50,
                        "description": "Deprecated fixed/full compatibility path; omit for adaptive selection.",
                    },
                },
                "not": {"required": ["limit", "budget"]},
            },
            "annotations": _annotations(read_only=False, idempotent=False),
        },
        {
            "name": "integrity_context_admission_current_turn",
            "description": "Preferred full-prompt hot path. Resolve the exact current owner prompt from the opaque one-use turn_ref staged by the owning hook; never copy, truncate, summarize, or reconstruct the prompt in tool arguments. Omit limit for adaptive selection.",
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["turn_ref"],
                "properties": {
                    "turn_ref": {
                        "type": "string",
                        "pattern": "^turnref:[A-Za-z0-9_-]{43}$",
                    },
                    "budget": context_budget_schema,
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 50,
                        "description": "Deprecated fixed/full compatibility path; omit for adaptive selection.",
                    },
                },
                "not": {"required": ["limit", "budget"]},
            },
            "annotations": _annotations(read_only=False, idempotent=False),
        },
        {
            "name": "integrity_memory_capabilities",
            "description": "Mandatory first admission step: read the closed LTS capability/source contract.",
            "inputSchema": object_schema,
            "annotations": _annotations(read_only=True),
        },
        {
            "name": "integrity_seed_snapshot",
            "description": "After capabilities, freeze the server-side Seed cursor for the current isolated logical context.",
            "inputSchema": object_schema,
            "annotations": _annotations(read_only=True),
        },
        {
            "name": "integrity_mind_graph",
            "description": "Mandatory third admission step: project the complete Action Log Mind over the frozen Seed snapshot, retain it internally, and return an adaptive digest-bound context capsule. Explicit limit selects the fixed/full compatibility path.",
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["snapshot_id", "intent"],
                "properties": {
                    "snapshot_id": {"type": "string", "pattern": "^sha256:[a-f0-9]{64}$"},
                    "intent": {"type": "string", "minLength": 1, "maxLength": 4096},
                    "budget": context_budget_schema,
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 50,
                        "description": "Deprecated fixed/full compatibility path; omit for adaptive selection.",
                    },
                },
                "not": {"required": ["limit", "budget"]},
            },
            "annotations": _annotations(read_only=True),
        },
        {
            "name": "integrity_architecture_admission",
            "description": "Mandatory fourth admission step: persist the exact Mind receipt in the signed Guardian Ledger, checkpoint it, project Atlas, compile Connectome and return a verified authority-free Synapse route.",
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["mind_receipt_id"],
                "properties": {
                    "mind_receipt_id": {
                        "type": "string",
                        "pattern": "^sha256:[a-f0-9]{64}$",
                    }
                },
            },
            "annotations": _annotations(read_only=False, idempotent=False),
        },
        {
            "name": "integrity_seed_tasks",
            "description": "Read canonical snapshot-bound task lifecycle. Every receipt has all status counts; default returns work/review cards, view=failed returns only failed cards, and complete bodies are deliberately unavailable.",
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["snapshot_id"],
                "properties": {
                    "snapshot_id": {"type": "string", "pattern": "^sha256:[a-f0-9]{64}$"},
                    "view": {"enum": ["work_queue_review", "failed"]},
                    "after_task_id": {"type": "string", "maxLength": 256},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 200},
                },
            },
            "annotations": _annotations(read_only=True),
        },
        {
            "name": "integrity_seed_event_uid",
            "description": "Resolve one exact event_uid across the complete immutable Seed snapshot. Returns a deterministic found/not-found receipt and never performs a write.",
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["snapshot_id", "event_uid"],
                "properties": {
                    "snapshot_id": {"type": "string", "pattern": "^sha256:[a-f0-9]{64}$"},
                    "event_uid": {"type": "string", "minLength": 1, "maxLength": 256},
                },
            },
            "annotations": _annotations(read_only=True),
        },
        {
            "name": "integrity_seed_connections",
            "description": "Explain typed canonical Seed links with independent direct-link receipt. Supply exactly one of event_id or selection_seed; the server rejects missing or mixed alternatives.",
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["snapshot_id"],
                "properties": {
                    "snapshot_id": {"type": "string", "pattern": "^sha256:[a-f0-9]{64}$"},
                    "event_id": {"type": "integer", "minimum": 1},
                    "selection_seed": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 200},
                    "include_contextual": {"type": "boolean"},
                },
            },
            "annotations": _annotations(read_only=True),
        },
        {
            "name": "integrity_memory_entity_brief",
            "description": "Optionally resolve one canonical Seed entity into a bounded, provenance-bound article with definition, whereabouts, typed links, claim freshness, activity and same-snapshot task lifecycle. Never grants route or production authority.",
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["snapshot_id", "reference"],
                "properties": {
                    "snapshot_id": {"type": "string", "pattern": "^sha256:[a-f0-9]{64}$"},
                    "reference": {"type": "string", "minLength": 1, "maxLength": 4096},
                    "relationship_limit": {"type": "integer", "minimum": 1, "maximum": 100},
                    "activity_limit": {"type": "integer", "minimum": 1, "maximum": 20},
                    "task_limit": {"type": "integer", "minimum": 1, "maximum": 20},
                    "discovery_limit": {"type": "integer", "minimum": 1, "maximum": 20},
                    "max_context_bytes": {"type": "integer", "minimum": 8192, "maximum": 262144},
                },
            },
            "annotations": _annotations(read_only=True),
        },
        {
            "name": "integrity_memory_ttt_autofill",
            "description": "Return the remaining suffix of one owner-configured, digest-bound read-only runbook path after exact session snapshot and Memory Link Graph admission. Empty configuration is BLOCKED and never grants execution or production authority.",
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["snapshot_id", "goal", "last_hop"],
                "properties": {
                    "snapshot_id": {"type": "string", "pattern": "^sha256:[a-f0-9]{64}$"},
                    "goal": {"type": "string", "minLength": 1, "maxLength": 512},
                    "last_hop": {"type": "string", "minLength": 1, "maxLength": 512},
                },
            },
            "annotations": _annotations(read_only=True),
        },
        {
            "name": "integrity_memory_link_audit",
            "description": "Optionally page through bounded Memory Link Graph curation debt. Findings are unadmitted suggestions, never auto-applied canonical writes.",
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["snapshot_id"],
                "properties": {
                    "snapshot_id": {"type": "string", "pattern": "^sha256:[a-f0-9]{64}$"},
                    "kinds": {
                        "type": "array",
                        "maxItems": 13,
                        "uniqueItems": True,
                        "items": {
                            "enum": [
                                "artifact",
                                "component",
                                "concept",
                                "decision",
                                "event",
                                "evidence",
                                "location",
                                "release",
                                "subsystem",
                                "system",
                                "task",
                                "term",
                            ]
                        },
                    },
                    "limit": {"type": "integer", "minimum": 1, "maximum": 100},
                    "max_context_bytes": {"type": "integer", "minimum": 8192, "maximum": 262144},
                    "cursor": {"type": "string", "maxLength": 4096},
                },
            },
            "annotations": _annotations(read_only=True),
        },
        {
            "name": "integrity_seed_replay",
            "description": "Cold-replay a recorded Seed selection and receipt without reroll.",
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "snapshot_id",
                    "selection_seed",
                    "expected_event_id",
                    "expected_explanation_digest",
                    "expected_receipt_id",
                ],
                "properties": {
                    "snapshot_id": {"type": "string"},
                    "selection_seed": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
                    "expected_event_id": {"type": "integer", "minimum": 1},
                    "expected_explanation_digest": {"type": "string"},
                    "expected_receipt_id": {"type": "string"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 200},
                    "include_contextual": {"type": "boolean"},
                },
            },
            "annotations": _annotations(read_only=True),
        },
    ]
    if profile in {
        PRE_TTT_TOOL_CONTRACT_PROFILE,
        PRE_V4_TOOL_CONTRACT_PROFILE,
        LEGACY_TURN_BROKER_TOOL_CONTRACT_PROFILE,
    }:
        exposed = [
            item
            for item in exposed
            if item["name"] != "integrity_memory_ttt_autofill"
        ]
    if profile in {PRE_V4_TOOL_CONTRACT_PROFILE, LEGACY_TURN_BROKER_TOOL_CONTRACT_PROFILE}:
        exposed = [
            item for item in exposed
            if item["name"] != "integrity_context_admission_current_turn"
        ]
    if profile == LEGACY_TURN_BROKER_TOOL_CONTRACT_PROFILE:
        exposed = [item for item in exposed if item["name"] != "integrity_seed_event_uid"]
        exclusive_inputs = {
            "integrity_turn_memory_close": ("events", "no_event_reason"),
            "integrity_home_search": ("query", "cursor"),
            "integrity_seed_connections": ("event_id", "selection_seed"),
        }
        for item in exposed:
            pair = exclusive_inputs.get(item["name"])
            if pair is None:
                continue
            left, right = pair
            item["inputSchema"]["oneOf"] = [
                {"required": [left], "not": {"required": [right]}},
                {"required": [right], "not": {"required": [left]}},
            ]
    return exposed


def _tool_result(value: dict[str, Any], *, error: bool = False) -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": canonical_json(value).decode("utf-8")}],
        "isError": error,
    }


def dispatch(server: MemorySynapseMcp, message: dict[str, Any]) -> dict[str, Any] | None:
    request_id = message.get("id")
    if message.get("jsonrpc") != "2.0" or not isinstance(message.get("method"), str):
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": -32600, "message": "invalid request"},
        }
    if (
        message["method"] == CONTEXT_ADMISSION_REPLAY_ACK_NOTIFICATION
        and "id" not in message
    ):
        params = message.get("params", {})
        if server._context_admission_replay_control_enabled and isinstance(
            params, dict
        ) and set(params) == {
            "replay_id",
            "request_digest",
            "response_digest",
        }:
            try:
                server._ack_context_replay(
                    str(params["replay_id"]),
                    str(params["request_digest"]),
                    str(params["response_digest"]),
                )
            except (McpFacadeError, OSError):
                # Notifications have no response channel. A rejected/lost ACK
                # deliberately retains the record for TTL garbage collection.
                pass
        return None
    if message["method"].startswith("notifications/") or "id" not in message:
        return None
    params = message.get("params", {})
    if not isinstance(params, dict):
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": -32602, "message": "params must be an object"},
        }
    if message["method"] == "initialize":
        requested = params.get("protocolVersion")
        protocol = requested if requested in SUPPORTED_MCP_VERSIONS else DEFAULT_MCP_VERSION
        server._tool_contract_profile = _tool_contract_profile(params)
        capabilities: dict[str, Any] = {"tools": {"listChanged": False}}
        broker_surface_ack = _broker_tool_surface_ack(params)
        server._broker_tool_surface_authenticated = broker_surface_ack is not None
        requested_replay_ack = _broker_context_admission_replay_ack(
            params,
            durable_replay_available=(
                server._supports_context_admission_replay_control()
            ),
        )
        server._context_admission_replay_control_enabled = (
            requested_replay_ack is not None
        )
        replay_reserved = bool(
            requested_replay_ack is not None
            and server._supports_context_admission_replay(
                str(requested_replay_ack["reservation_id"])
            )
        )
        replay_ack = None
        if requested_replay_ack is not None and (
            replay_reserved or _broker_supports_replay_control_only(params)
        ):
            replay_ack = {
                **requested_replay_ack,
                "reservation_status": (
                    "reserved" if replay_reserved else "unavailable"
                ),
            }
        server._context_admission_replay_enabled = replay_reserved
        experimental: dict[str, Any] = {}
        if broker_surface_ack is not None:
            experimental[BROKER_TOOL_SURFACE_CAPABILITY] = broker_surface_ack
        if replay_ack is not None:
            experimental[CONTEXT_ADMISSION_REPLAY_CAPABILITY] = replay_ack
        if experimental:
            capabilities["experimental"] = experimental
        result = {
            "protocolVersion": protocol,
            "capabilities": capabilities,
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            "instructions": SERVER_INSTRUCTIONS,
        }
    elif message["method"] == "ping":
        result = {}
    elif message["method"] == CONTEXT_ADMISSION_REPLAY_RESERVE_METHOD:
        reservation_id = params.get("reservation_id")
        if (
            set(params) != {"reservation_id"}
            or not isinstance(reservation_id, str)
            or re.fullmatch(r"sha256:[a-f0-9]{64}", reservation_id) is None
        ):
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32602, "message": "invalid replay reservation"},
            }
        reserved = bool(
            server._context_admission_replay_control_enabled
            and server._supports_context_admission_replay(reservation_id)
        )
        if reserved:
            server._context_admission_replay_enabled = True
        result = {
            "protocol": CONTEXT_ADMISSION_REPLAY_RESERVATION_PROTOCOL,
            "reservation_id": reservation_id,
            "reserved": reserved,
        }
    elif message["method"] == CONTEXT_ADMISSION_REPLAY_ACK_METHOD:
        if set(params) != {"replay_id", "request_digest", "response_digest"}:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32602, "message": "invalid replay acknowledgement"},
            }
        retired = False
        if server._context_admission_replay_control_enabled:
            try:
                retired = server._ack_context_replay(
                    str(params["replay_id"]),
                    str(params["request_digest"]),
                    str(params["response_digest"]),
                )
            except (McpFacadeError, OSError):
                retired = False
        result = {
            "protocol": CONTEXT_ADMISSION_REPLAY_RESERVATION_PROTOCOL,
            "replay_id": str(params["replay_id"]),
            "retired": retired,
        }
    elif message["method"] == "tools/list":
        result = {"tools": tools(profile=server._tool_contract_profile)}
    elif message["method"] == "tools/call":
        name, arguments = params.get("name"), params.get("arguments", {})
        if not isinstance(name, str) or not isinstance(arguments, dict):
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32602, "message": "invalid tool call"},
            }
        try:
            result = _tool_result(server.call(name, arguments))
        except (
            McpFacadeError,
            MemorySynapseLtsError,
            OSError,
            sqlite3.Error,
            ValueError,
            TypeError,
        ) as exc:
            receipt = {
                "protocol": BRIDGE_PROTOCOL + "/denial-receipt",
                "source_label": SOURCE_LABEL,
                "observed_utc": _utc_now(),
                "tool": name[:120],
                "arguments_digest": _sha256(arguments),
                "outcome": "denied",
                "reason": str(exc)[:500],
            }
            if isinstance(exc, InputValidationError):
                receipt.update(
                    {
                        "failure_layer": "input-validation",
                        "reason_code": exc.reason_code,
                        "read_plane_status": "not-attempted",
                        "automatic_retry_allowed": False,
                        "canonical_writes": 0,
                        "production_authority": False,
                    }
                )
            elif isinstance(exc, ReadPlaneUnavailableError):
                retryable_after_seal = (
                    exc.reason_code == "seed_catalog_checkpoint_required"
                    and name == "integrity_context_admission"
                    and isinstance(arguments.get(TURN_ENVELOPE_BINDING_FIELD), dict)
                )
                receipt.update(
                    {
                        "reason": exc.user_message,
                        "failure_layer": "read-plane-initialization",
                        "reason_code": exc.reason_code,
                        "read_plane_status": "unavailable",
                        "automatic_retry_allowed": retryable_after_seal,
                        "canonical_writes": 0,
                        "production_authority": False,
                        "operator_action": exc.operator_action,
                    }
                )
                if retryable_after_seal:
                    receipt["retry_disposition"] = (
                        "exact-envelope-after-supported-read-seal"
                    )
            audit_receipt = receipt
            if isinstance(exc, ReadPlaneUnavailableError):
                audit_receipt = {
                    **receipt,
                    "technical_reason": exc.technical_reason[:500],
                }
            server.audit(audit_receipt)
            result = _tool_result({"receipt": receipt}, error=True)
    else:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": -32601, "message": "method not found"},
        }
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def serve(server: MemorySynapseMcp) -> int:
    try:
        while True:
            raw = sys.stdin.buffer.readline(MAX_REQUEST_BYTES + 1)
            if not raw:
                break
            try:
                if len(raw) > MAX_REQUEST_BYTES:
                    raise ValueError("request exceeds the stdio limit")
                message = json.loads(raw)
                if not isinstance(message, dict):
                    raise TypeError("request must be an object")
                response = dispatch(server, message)
            except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
                response = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": "parse error"},
                }
            if response is not None:
                sys.stdout.buffer.write(canonical_json(response) + b"\n")
                sys.stdout.buffer.flush()
        return 0
    finally:
        server.close()


def _build_write_plane_runtime(
    args: argparse.Namespace,
    package_lts: MemorySynapseLtsService,
    *,
    audit: Callable[[dict[str, Any]], None] = _audit,
    emit_component_audit: bool = True,
) -> WritePlaneRuntime:
    """Build one independent startup/recovery candidate without installing it."""

    status = {
        "outcome": "ready",
        "architecture": "ready",
        "action_witness": "ready",
        "security_admission": "ready",
        "turn_memory": "ready",
    }
    failure_reason_digests: dict[str, str] = {}

    def mark_unavailable(component: str, exc: Exception) -> None:
        reason_digest = _sha256(
            {"exception_type": type(exc).__name__, "reason": str(exc)[:500]}
        )
        status["outcome"] = "unavailable"
        status[component] = "unavailable"
        failure_reason_digests[component] = reason_digest
        if emit_component_audit:
            audit(
                {
                    "protocol": BRIDGE_PROTOCOL + "/write-plane-startup/v1",
                    "source_label": SOURCE_LABEL,
                    "observed_utc": _utc_now(),
                    "component": component,
                    "outcome": "unavailable",
                    "reason_digest": reason_digest,
                    "canonical_writes": 0,
                    "production_authority": False,
                }
            )

    architecture = None
    native_trust = None
    try:
        native_database = None
        native_ledger_issuer_key = None
        if args.trust_profile == NATIVE_TRUST_PROFILE:
            native_trust = NativeTrustStore(
                args.native_state_root,
                instance_id=args.native_instance_id,
            )
            native_trust.bootstrap()
            native_trust.ensure_local_transport_device(device_id=args.native_device_id)
            native_database = native_trust.ensure_database(
                tenant_id=TENANT_ID,
                ledger_id=CUSTODY_LEDGER_ID,
            )
            architecture_keys = MedorArchitectureKeys(
                source_signer=native_database.source_signer,
                checkpoint_signer=native_database.checkpoint_signer,
            )
            event_authority_key = native_trust.trusted_key("event-append-issuer")
            native_ledger_issuer_key = native_trust.trusted_key("ledger-issuer")
        else:
            architecture_keys = MedorArchitectureKeys(
                source_signer=load_medor_architecture_signer(
                    args.architecture_source_key,
                    key_id="key:medor-architecture-source",
                ),
                checkpoint_signer=load_medor_architecture_signer(
                    args.architecture_checkpoint_key,
                    key_id="key:medor-architecture-checkpoint",
                ),
            )
            event_authority_key = load_medor_trusted_public_key(
                args.event_authority_public_key,
                key_id=EVENT_AUTHORITY_KEY_ID,
            )
        architecture = PersistentMedorArchitectureService(
            args.architecture_root,
            keys=architecture_keys,
            event_authority_key=event_authority_key,
            native_database_enrollment=(
                native_database.enrollment if native_database is not None else None
            ),
            native_ledger_issuer_key=native_ledger_issuer_key,
        )
    except (
        McpFacadeError,
        MemorySynapseLtsError,
        OSError,
        sqlite3.Error,
        ValueError,
        TypeError,
    ) as exc:
        mark_unavailable("architecture", exc)

    security = None
    try:
        if native_trust is not None:
            security = native_trust.security_admission(
                artifact_digest=package_lts.capabilities()["artifact_digest"],
            )
        else:
            security_authority_key = load_medor_trusted_public_key(
                args.security_authority_public_key,
                key_id=SECURITY_AUTHORITY_KEY_ID,
            )
            security = load_medor_security_bundle(
                args.security_admission_bundle,
                expected_artifact_digest=package_lts.capabilities()["artifact_digest"],
                at_time=_utc_now(),
                decision_key=security_authority_key,
            )
    except (
        McpFacadeError,
        MemorySynapseLtsError,
        OSError,
        sqlite3.Error,
        ValueError,
        TypeError,
    ) as exc:
        mark_unavailable("security_admission", exc)

    action_witness = None
    try:
        action_witness = RestrictedActionLogWitnessClient.for_release_helper(
            args.action_log_witness_helper
        )
    except (
        McpFacadeError,
        MemorySynapseLtsError,
        OSError,
        sqlite3.Error,
        ValueError,
        TypeError,
    ) as exc:
        mark_unavailable("action_witness", exc)

    turn_memory = None
    if architecture is not None:
        try:
            turn_memory = TurnMemoryStore(
                args.architecture_root / "turn-memory" / "turn-memory.sqlite3",
                namespace=namespace_fingerprint(
                    source_namespace=package_lts.snapshot().get("source_namespace"),
                    trust_fingerprint=public_key_fingerprint(
                        architecture.keys.source_signer.public_key
                    ),
                ),
                signer=architecture.keys.checkpoint_signer,
            )
        except (
            McpFacadeError,
            MemorySynapseLtsError,
            TurnMemoryError,
            AttributeError,
            OSError,
            sqlite3.Error,
            ValueError,
            TypeError,
        ) as exc:
            mark_unavailable("turn_memory", exc)
    else:
        status["turn_memory"] = "unavailable"
        failure_reason_digests["turn_memory"] = _sha256(
            {"dependency": "architecture", "outcome": "unavailable"}
        )

    return WritePlaneRuntime(
        architecture=architecture,
        action_witness=action_witness,
        security_admission=security,
        native_trust=native_trust,
        native_device_id=(args.native_device_id if native_trust is not None else None),
        turn_memory=turn_memory,
        status=dict(status),
        failure_reason_digests=dict(failure_reason_digests),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path)
    parser.add_argument("--ttt-path-catalog", type=Path)
    parser.add_argument("--expected-ttt-path-catalog-digest")
    parser.add_argument("--evidence-root", type=Path)
    parser.add_argument("--evidence-source-prefix", type=Path)
    parser.add_argument("--architecture-root", type=Path)
    parser.add_argument("--snapshot-root", type=Path)
    parser.add_argument("--replay-migration", nargs=2, action="append", default=[],
                        metavar=("ADMISSION_FILE", "SHA256"))
    parser.add_argument("--architecture-source-key", type=Path)
    parser.add_argument("--architecture-checkpoint-key", type=Path)
    parser.add_argument("--security-admission-bundle", type=Path)
    parser.add_argument("--security-authority-public-key", type=Path)
    parser.add_argument("--event-authority-public-key", type=Path)
    parser.add_argument("--action-log-witness-helper", type=Path)
    parser.add_argument(
        "--trust-profile",
        choices=("personal-native", "managed-external"),
        default="managed-external",
    )
    parser.add_argument("--native-state-root", type=Path)
    parser.add_argument("--native-instance-id")
    parser.add_argument("--native-device-id")
    parser.add_argument("--version", action="store_true")
    args = parser.parse_args(argv)
    if args.version:
        print(f"{SERVER_NAME} {SERVER_VERSION}")
        return 0
    if args.catalog is None:
        parser.error("--catalog is required unless --version is used")
    if any(
        value is None
        for value in (
            args.architecture_root,
            args.snapshot_root,
            args.action_log_witness_helper,
        )
    ):
        parser.error(
            "--architecture-root, --snapshot-root, and --action-log-witness-helper are required"
        )
    managed_inputs = (
        args.architecture_source_key,
        args.architecture_checkpoint_key,
        args.security_admission_bundle,
        args.security_authority_public_key,
        args.event_authority_public_key,
    )
    native_inputs = (
        args.native_state_root,
        args.native_instance_id,
        args.native_device_id,
    )
    if args.trust_profile == "managed-external" and any(value is None for value in managed_inputs):
        parser.error(
            "managed-external requires architecture keys, Security bundle, and authority public keys"
        )
    if args.trust_profile == NATIVE_TRUST_PROFILE and any(value is None for value in native_inputs):
        parser.error(
            "personal-native requires --native-state-root, --native-instance-id, and --native-device-id"
        )
    if (args.evidence_root is None) != (args.evidence_source_prefix is None):
        parser.error("--evidence-root and --evidence-source-prefix must be supplied together")
    try:
        ttt_path_catalog = load_runbook_path_catalog(
            args.ttt_path_catalog,
            args.expected_ttt_path_catalog_digest,
        )
    except (MemoryTttPathError, OSError, ValueError) as exc:
        parser.error(f"TTT path catalogue rejected: {exc}")
    package_lts = MemorySynapseLtsService(
        args.catalog,
        evidence_root=args.evidence_root,
        evidence_source_prefix=args.evidence_source_prefix,
    )
    # Reject an invalid operator handover before constructing any write-plane
    # service. The protocol itself cannot supply or amend these admissions.
    if len(args.replay_migration) > MAX_CONTEXT_ADMISSION_REPLAY_RECORDS:
        parser.error("too many replay migration admissions")
    migrations = []
    for filename, expected_digest in args.replay_migration:
        try:
            migrations.append(load_admission(
                Path(filename), expected_digest,
                replay_root=args.architecture_root / "context-admission-replay-v2",
                target_artifact=package_lts._artifact_digest(),
            ))
        except (ReplayMigrationError, OSError, KeyError, TypeError, ValueError) as exc:
            parser.error(f"replay migration rejected: {type(exc).__name__}")
    runtime = _build_write_plane_runtime(args, package_lts)

    server = MemorySynapseMcp(
        package_lts,
        architecture=runtime.architecture,
        action_witness=runtime.action_witness,
        security_admission=runtime.security_admission,
        write_plane_status=runtime.status,
        snapshot_source=args.catalog,
        snapshot_root=args.snapshot_root,
        native_trust=runtime.native_trust,
        native_device_id=runtime.native_device_id,
        turn_memory=runtime.turn_memory,
        memory_ttt_path_catalog=ttt_path_catalog,
        write_plane_reinitializer=lambda: _build_write_plane_runtime(
            args,
            package_lts,
            emit_component_audit=False,
        ),
    )
    atexit.register(server.close)
    for admission in migrations:
        try:
            server.admit_replay_migration(admission)
        except (ReplayMigrationError, McpFacadeError, OSError, KeyError, TypeError) as exc:
            server.close()
            parser.error(f"replay migration rejected: {type(exc).__name__}")
    return serve(server)


if __name__ == "__main__":
    raise SystemExit(main())
