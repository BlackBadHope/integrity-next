"""Linearizable local custody for atomic module-agent lease handoff.

The single SQLite database is the canonical coordination authority for one
tenant/module pair.  It serializes state changes with ``BEGIN IMMEDIATE``,
advances a monotonic fencing token in the same transaction as the head swap,
and durably records transaction outcomes.  It grants no production authority.
"""

from __future__ import annotations

import os
import re
import sqlite3
import stat
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Self

from .agent_continuity import (
    AgentContinuityError,
    verify_current_module_agent_lease,
    verify_module_agent_lease,
    verify_module_agent_lease_head,
)
from .agent_handoff import (
    AgentHandoffError,
    verify_module_agent_successor_ack,
)
from .canonical import canonical_bytes, parse_json_strict
from .hashing import digest_object
from .schemas import validate
from .signing import (
    Ed25519Signer,
    TrustedKey,
    public_key_fingerprint,
    verify_signature,
)

SCHEMA_VERSION = 1
MAX_FENCE_TOKEN = 2**63 - 1
_STORE_ID = re.compile(r"^agent-custody:[A-Za-z0-9][A-Za-z0-9._:/-]{0,240}$")
_TRANSACTION_ID = re.compile(r"^handoff-tx:[a-f0-9]{64}$")
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")


class AgentHandoffCustodyError(RuntimeError):
    """Raised before unsafe or ambiguous custody state is accepted."""


class StaleAgentFenceError(AgentHandoffCustodyError):
    """Raised when an actor no longer owns the canonical fencing token."""


class HandoffSignerRole(StrEnum):
    PREDECESSOR = "predecessor"
    SUCCESSOR = "successor"


class HandoffTransactionStatus(StrEnum):
    COMMITTED = "COMMITTED"
    COMMIT_UNKNOWN = "COMMIT_UNKNOWN"
    NOT_COMMITTED = "NOT_COMMITTED"


@dataclass(frozen=True)
class AgentSignerBinding:
    role: HandoffSignerRole
    agent_id: str
    key: TrustedKey


@dataclass(frozen=True)
class HandoffSignerPolicy:
    """Closed signer allocation for one tenant/module custody domain."""

    tenant_id: str
    module_id: str
    custody_authority: TrustedKey
    agent_bindings: tuple[AgentSignerBinding, ...]

    def __post_init__(self) -> None:
        if (
            not self.tenant_id.startswith("tenant:")
            or _ID.fullmatch(self.tenant_id) is None
            or _ID.fullmatch(self.module_id) is None
        ):
            raise AgentHandoffCustodyError("handoff signer policy scope rejected")
        if not isinstance(self.custody_authority, TrustedKey):
            raise AgentHandoffCustodyError("custody authority key rejected")
        if not isinstance(self.agent_bindings, tuple):
            raise AgentHandoffCustodyError("agent signer bindings must be a tuple")
        authority_fingerprint = public_key_fingerprint(
            self.custody_authority.public_key
        )
        seen: set[tuple[HandoffSignerRole, str]] = set()
        for binding in self.agent_bindings:
            if (
                not isinstance(binding, AgentSignerBinding)
                or not isinstance(binding.role, HandoffSignerRole)
                or _ID.fullmatch(binding.agent_id) is None
                or not isinstance(binding.key, TrustedKey)
            ):
                raise AgentHandoffCustodyError("agent signer binding rejected")
            if public_key_fingerprint(binding.key.public_key) == authority_fingerprint:
                raise AgentHandoffCustodyError(
                    "custody authority key cannot be an agent signer"
                )
            identity = (binding.role, binding.agent_id)
            if identity in seen:
                raise AgentHandoffCustodyError("duplicate agent signer binding")
            seen.add(identity)

    @property
    def digest(self) -> str:
        document = {
            "protocol": "integrity-guardian/handoff-signer-policy/v1",
            "tenant_id": self.tenant_id,
            "module_id": self.module_id,
            "custody_authority": {
                "key_id": self.custody_authority.key_id,
                "fingerprint": public_key_fingerprint(
                    self.custody_authority.public_key
                ),
            },
            "agent_bindings": sorted(
                (
                    {
                        "role": binding.role.value,
                        "agent_id": binding.agent_id,
                        "key_id": binding.key.key_id,
                        "fingerprint": public_key_fingerprint(
                            binding.key.public_key
                        ),
                    }
                    for binding in self.agent_bindings
                ),
                key=lambda value: (
                    value["role"], value["agent_id"], value["key_id"]
                ),
            ),
            "production_authority": False,
        }
        return digest_object(document, domain="handoff-signer-policy-v1")

    def key_for(
        self,
        role: HandoffSignerRole,
        agent_id: str,
        key_id: str,
    ) -> TrustedKey:
        matches = [
            binding.key
            for binding in self.agent_bindings
            if binding.role is role and binding.agent_id == agent_id
        ]
        if len(matches) != 1 or matches[0].key_id != key_id:
            raise AgentHandoffCustodyError(
                f"{role.value} signer is not admitted by policy"
            )
        return matches[0]

    def require_authority_signer(self, signer: Ed25519Signer) -> None:
        if (
            signer.key_id != self.custody_authority.key_id
            or public_key_fingerprint(signer.public_key)
            != public_key_fingerprint(self.custody_authority.public_key)
        ):
            raise AgentHandoffCustodyError("custody authority signer rejected")


@dataclass(frozen=True)
class HandoffTransactionReference:
    transaction_id: str
    request_digest: str

    def __post_init__(self) -> None:
        if (
            _TRANSACTION_ID.fullmatch(self.transaction_id) is None
            or _DIGEST.fullmatch(self.request_digest) is None
        ):
            raise AgentHandoffCustodyError("handoff transaction reference rejected")


@dataclass(frozen=True)
class AgentCustodySnapshot:
    store_id: str
    tenant_id: str
    module_id: str
    signer_policy_digest: str
    fence_token: int
    lease: dict[str, Any]
    head: dict[str, Any]

    @property
    def head_digest(self) -> str:
        return module_agent_head_digest(self.head)


@dataclass(frozen=True)
class HandoffCommitResult:
    status: HandoffTransactionStatus
    reference: HandoffTransactionReference
    receipt: dict[str, Any] | None

    @property
    def retry_permitted(self) -> bool:
        return False


def module_agent_head_digest(head: dict[str, Any]) -> str:
    return digest_object(head, domain="module-agent-lease-head-reference-v1")


def _json(document: dict[str, Any]) -> str:
    return canonical_bytes(document).decode("utf-8")


def _time(value: str, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise AgentHandoffCustodyError(f"custody {field} timestamp rejected") from exc
    if parsed.tzinfo is None:
        raise AgentHandoffCustodyError(f"custody {field} timestamp rejected")
    return parsed


def _document(value: str, field: str) -> dict[str, Any]:
    try:
        parsed = parse_json_strict(value.encode("utf-8"))
    except Exception as exc:
        raise AgentHandoffCustodyError(f"custody {field} document rejected") from exc
    if not isinstance(parsed, dict):
        raise AgentHandoffCustodyError(f"custody {field} document rejected")
    return parsed


def _path_lineage(path: Path) -> tuple[Path, ...]:
    current = path
    lineage: list[Path] = []
    while True:
        lineage.append(current)
        parent = current.parent
        if parent == current:
            return tuple(reversed(lineage))
        current = parent


def _assert_posix_custody_ancestry(path: Path, *, private_leaf: bool) -> None:
    effective_uid = os.geteuid()
    for item in _path_lineage(path):
        try:
            details = item.lstat()
        except OSError as exc:
            raise AgentHandoffCustodyError(
                "agent custody ancestry is unavailable"
            ) from exc
        mode = stat.S_IMODE(details.st_mode)
        if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode):
            raise AgentHandoffCustodyError("agent custody ancestry rejected")
        if details.st_uid not in {0, effective_uid}:
            raise AgentHandoffCustodyError("agent custody ancestry owner rejected")
        if mode & 0o022 and not (
            details.st_uid == 0 and mode & stat.S_ISVTX
        ):
            raise AgentHandoffCustodyError("agent custody ancestry mode rejected")
    if private_leaf:
        details = path.lstat()
        if (
            details.st_uid != effective_uid
            or stat.S_IMODE(details.st_mode) != 0o700
        ):
            raise AgentHandoffCustodyError(
                "agent custody parent is not private"
            )


def _prepare_custody_parent(path: Path) -> None:
    if os.name == "nt":
        try:
            from ._windows_files import create_private_directory_tree

            create_private_directory_tree(path)
        except Exception as exc:
            raise AgentHandoffCustodyError(
                "agent custody Windows ancestry rejected"
            ) from exc
        return

    missing: list[Path] = []
    current = path
    while True:
        try:
            current.lstat()
            break
        except FileNotFoundError:
            missing.append(current)
            parent = current.parent
            if parent == current:
                raise AgentHandoffCustodyError(
                    "agent custody ancestry has no existing anchor"
                )
            current = parent
        except OSError as exc:
            raise AgentHandoffCustodyError(
                "agent custody ancestry is unavailable"
            ) from exc
    _assert_posix_custody_ancestry(current, private_leaf=False)
    for item in reversed(missing):
        try:
            os.mkdir(item, 0o700)
        except OSError as exc:
            raise AgentHandoffCustodyError(
                "agent custody private parent creation rejected"
            ) from exc
        details = item.lstat()
        if (
            stat.S_ISLNK(details.st_mode)
            or not stat.S_ISDIR(details.st_mode)
            or details.st_uid != os.geteuid()
            or stat.S_IMODE(details.st_mode) != 0o700
        ):
            raise AgentHandoffCustodyError(
                "agent custody private parent creation rejected"
            )
    _assert_posix_custody_ancestry(path, private_leaf=True)


@contextmanager
def _hold_custody_parent(path: Path) -> Iterator[int | None]:
    if os.name == "nt":
        try:
            from ._windows_files import (
                HeldWindowsDirectory,
                assert_private_directory_acl,
            )

            assert_private_directory_acl(path)
            held_directory = HeldWindowsDirectory(path)
            assert_private_directory_acl(path)
        except Exception as exc:
            if isinstance(exc, AgentHandoffCustodyError):
                raise
            raise AgentHandoffCustodyError(
                "agent custody Windows parent guard rejected"
            ) from exc
        try:
            yield None
        finally:
            try:
                assert_private_directory_acl(path)
            except Exception as exc:
                raise AgentHandoffCustodyError(
                    "agent custody Windows parent guard rejected"
                ) from exc
            finally:
                held_directory.close()
        return

    _assert_posix_custody_ancestry(path, private_leaf=True)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(
        os, "O_NOFOLLOW", 0
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise AgentHandoffCustodyError(
            "agent custody parent guard rejected"
        ) from exc
    try:
        before = os.fstat(descriptor)
        observed = path.lstat()
        if (
            not stat.S_ISDIR(before.st_mode)
            or (before.st_dev, before.st_ino) != (observed.st_dev, observed.st_ino)
        ):
            raise AgentHandoffCustodyError(
                "agent custody parent identity rejected"
            )
        yield descriptor
        observed = path.lstat()
        if (before.st_dev, before.st_ino) != (observed.st_dev, observed.st_ino):
            raise AgentHandoffCustodyError("agent custody parent changed during use")
        _assert_posix_custody_ancestry(path, private_leaf=True)
    finally:
        os.close(descriptor)


def _assert_custody_file(path: Path) -> tuple[int, int]:
    try:
        details = path.lstat()
    except OSError as exc:
        raise AgentHandoffCustodyError("agent custody database missing") from exc
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(details.st_mode):
        raise AgentHandoffCustodyError("agent custody file type rejected")
    attributes = getattr(details, "st_file_attributes", 0)
    if attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0):
        raise AgentHandoffCustodyError("agent custody reparse point rejected")
    if os.name == "nt":
        try:
            from ._windows_files import assert_private_directory_acl

            assert_private_directory_acl(path)
        except Exception as exc:
            raise AgentHandoffCustodyError(
                "agent custody Windows file ACL rejected"
            ) from exc
    elif (
        details.st_uid != os.geteuid()
        or stat.S_IMODE(details.st_mode) != 0o600
    ):
        raise AgentHandoffCustodyError("agent custody file owner or mode rejected")
    return details.st_dev, details.st_ino


def _remove_created_database(
    path: Path,
    *,
    identity: tuple[int, int],
    created_descriptor: int,
    parent_descriptor: int | None,
) -> None:
    try:
        held_details = os.fstat(created_descriptor)
    except OSError as exc:
        raise AgentHandoffCustodyError(
            "agent custody failed-create held descriptor rejected"
        ) from exc
    if (
        not stat.S_ISREG(held_details.st_mode)
        or (held_details.st_dev, held_details.st_ino) != identity
    ):
        raise AgentHandoffCustodyError(
            "agent custody failed-create held identity changed"
        )
    try:
        database_details = path.lstat()
    except OSError as exc:
        raise AgentHandoffCustodyError(
            "agent custody failed-create database disappeared"
        ) from exc
    if (
        stat.S_ISLNK(database_details.st_mode)
        or not stat.S_ISREG(database_details.st_mode)
        or (database_details.st_dev, database_details.st_ino) != identity
    ):
        raise AgentHandoffCustodyError(
            "agent custody failed-create identity changed"
        )
    candidates = (
        path.with_name(path.name + "-wal"),
        path.with_name(path.name + "-shm"),
        path,
    )
    for candidate in candidates:
        try:
            details = candidate.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(details.st_mode):
            raise AgentHandoffCustodyError(
                "agent custody failed-create cleanup rejected"
            )
        if os.name == "nt" or parent_descriptor is None:
            candidate.unlink()
        else:
            os.unlink(candidate.name, dir_fd=parent_descriptor)
    if parent_descriptor is not None:
        os.fsync(parent_descriptor)


@contextmanager
def open_private_sqlite_connection(
    path: Path,
    *,
    create: bool = False,
) -> Iterator[sqlite3.Connection]:
    """Open one SQLite file under the canonical held-lineage custody boundary."""

    target = Path(os.path.abspath(path))
    if create:
        _prepare_custody_parent(target.parent)
    with _hold_custody_parent(target.parent) as parent_descriptor:
        created_identity: tuple[int, int] | None = None
        created_descriptor: int | None = None
        connection: sqlite3.Connection | None = None
        try:
            if create:
                try:
                    target.lstat()
                except FileNotFoundError:
                    pass
                except OSError as exc:
                    raise AgentHandoffCustodyError(
                        "agent custody path inspection rejected"
                    ) from exc
                else:
                    raise AgentHandoffCustodyError(
                        "agent custody path already exists"
                    )
                for sidecar in (
                    target.with_name(target.name + "-wal"),
                    target.with_name(target.name + "-shm"),
                ):
                    try:
                        sidecar.lstat()
                    except FileNotFoundError:
                        continue
                    except OSError as exc:
                        raise AgentHandoffCustodyError(
                            "agent custody reserved sidecar inspection rejected"
                        ) from exc
                    raise AgentHandoffCustodyError(
                        "agent custody reserved sidecar already exists"
                    )
                flags = (
                    os.O_CREAT
                    | os.O_EXCL
                    | os.O_RDWR
                    | getattr(os, "O_NOFOLLOW", 0)
                )
                if os.name == "nt":
                    try:
                        from ._windows_files import (
                            create_held_windows_file_descriptor,
                        )

                        descriptor = create_held_windows_file_descriptor(target)
                    except Exception as exc:
                        raise AgentHandoffCustodyError(
                            "agent custody path creation rejected"
                        ) from exc
                else:
                    try:
                        descriptor = os.open(
                            target.name,
                            flags,
                            0o600,
                            dir_fd=parent_descriptor,
                        )
                    except OSError as exc:
                        raise AgentHandoffCustodyError(
                            "agent custody path creation rejected"
                        ) from exc
                try:
                    created = os.fstat(descriptor)
                    created_identity = (created.st_dev, created.st_ino)
                    created_descriptor = descriptor
                except Exception:
                    os.close(descriptor)
                    raise
                if os.name == "nt":
                    try:
                        from ._windows_files import (
                            assert_private_directory_acl,
                            set_private_directory_acl,
                        )

                        set_private_directory_acl(target)
                        assert_private_directory_acl(target)
                    except Exception as exc:
                        raise AgentHandoffCustodyError(
                            "agent custody Windows file ACL rejected"
                        ) from exc
            before = _assert_custody_file(target)
            connection = sqlite3.connect(
                target,
                timeout=5.0,
                isolation_level=None,
            )
            after = _assert_custody_file(target)
            if before != after:
                raise AgentHandoffCustodyError(
                    "agent custody file changed during open"
                )
            connection.row_factory = sqlite3.Row
            journal_mode = connection.execute(
                "PRAGMA journal_mode = WAL"
            ).fetchone()[0]
            connection.execute("PRAGMA synchronous = FULL")
            synchronous = connection.execute("PRAGMA synchronous").fetchone()[0]
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA trusted_schema = OFF")
            connection.execute("PRAGMA busy_timeout = 5000")
            if str(journal_mode).lower() != "wal" or synchronous != 2:
                raise AgentHandoffCustodyError(
                    "agent custody durability pragmas rejected"
                )
            yield connection
        except Exception:
            if connection is not None:
                connection.close()
                connection = None
            if (
                create
                and created_identity is not None
                and created_descriptor is not None
            ):
                _remove_created_database(
                    target,
                    identity=created_identity,
                    created_descriptor=created_descriptor,
                    parent_descriptor=parent_descriptor,
                )
            raise
        finally:
            if connection is not None:
                connection.close()
            if created_descriptor is not None:
                os.close(created_descriptor)


def module_agent_handoff_transaction_reference(
    *,
    store_id: str,
    expected_head_id: str,
    expected_fence_token: int,
    checkpoint: dict[str, Any],
    ack: dict[str, Any],
    successor_lease: dict[str, Any],
    successor_head: dict[str, Any],
) -> HandoffTransactionReference:
    """Return the immutable identity used for commit and reconciliation."""

    if (
        _STORE_ID.fullmatch(store_id) is None
        or _ID.fullmatch(expected_head_id) is None
        or isinstance(expected_fence_token, bool)
        or not isinstance(expected_fence_token, int)
        or not 0 <= expected_fence_token <= MAX_FENCE_TOKEN
    ):
        raise AgentHandoffCustodyError("handoff transaction scope rejected")
    core = {
        "protocol": "integrity-guardian/module-agent-handoff-transaction/v1",
        "store_id": store_id,
        "expected_head_id": expected_head_id,
        "expected_fence_token": expected_fence_token,
        "checkpoint_digest": digest_object(
            checkpoint, domain="module-agent-handoff-checkpoint-reference-v1"
        ),
        "ack_digest": digest_object(
            ack, domain="module-agent-successor-ack-reference-v1"
        ),
        "successor_lease_digest": digest_object(
            successor_lease, domain="module-agent-lease-reference-v1"
        ),
        "successor_head_digest": module_agent_head_digest(successor_head),
    }
    request_digest = digest_object(
        core, domain="module-agent-handoff-request-v1"
    )
    transaction_id = "handoff-tx:" + digest_object(
        core, domain="module-agent-handoff-transaction-identity-v1"
    ).split(":", 1)[1]
    return HandoffTransactionReference(transaction_id, request_digest)


def _signed_identity(
    document: dict[str, Any],
    *,
    field: str,
    prefix: str,
    domain: str,
) -> str:
    unsigned = deepcopy(document)
    unsigned.pop("signature", None)
    actual = unsigned[field]
    unsigned[field] = f"{prefix}pending"
    expected = prefix + digest_object(unsigned, domain=domain).split(":", 1)[1]
    if actual != expected:
        raise AgentHandoffCustodyError(f"custody {field} identity mismatch")
    return actual


def _build_commit_receipt(
    *,
    reference: HandoffTransactionReference,
    snapshot: AgentCustodySnapshot,
    successor_lease: dict[str, Any],
    successor_head: dict[str, Any],
    committed_at: str,
    fence_token: int,
    signer: Ed25519Signer,
) -> dict[str, Any]:
    unsigned: dict[str, Any] = {
        "protocol": "integrity-guardian/module-agent-handoff-commit-receipt/v1",
        "receipt_id": "handoff-commit:pending",
        "transaction_id": reference.transaction_id,
        "request_digest": reference.request_digest,
        "store_id": snapshot.store_id,
        "tenant_id": snapshot.tenant_id,
        "module_id": snapshot.module_id,
        "signer_policy_digest": snapshot.signer_policy_digest,
        "predecessor_head_id": snapshot.head["head_id"],
        "predecessor_head_digest": snapshot.head_digest,
        "predecessor_fence_token": snapshot.fence_token,
        "successor_head_id": successor_head["head_id"],
        "successor_head_digest": module_agent_head_digest(successor_head),
        "successor_lease_id": successor_lease["lease_id"],
        "successor_agent_id": successor_lease["agent_id"],
        "successor_generation": successor_lease["generation"],
        "fence_token": fence_token,
        "committed_at": committed_at,
        "status": "COMMITTED",
        "production_authority": False,
    }
    identity = digest_object(
        unsigned, domain="module-agent-handoff-commit-receipt-identity-v1"
    ).split(":", 1)[1]
    unsigned["receipt_id"] = f"handoff-commit:{identity}"
    receipt = signer.sign(unsigned)
    validate("module-agent-handoff-commit-receipt", receipt)
    return receipt


def verify_module_agent_handoff_commit_receipt(
    receipt: dict[str, Any], *, authority_key: TrustedKey
) -> dict[str, Any]:
    validate("module-agent-handoff-commit-receipt", receipt)
    if (
        receipt["signature"]["key_id"] != authority_key.key_id
        or not verify_signature(receipt, authority_key.public_key)
    ):
        raise AgentHandoffCustodyError("handoff commit receipt signature rejected")
    receipt_id = _signed_identity(
        receipt,
        field="receipt_id",
        prefix="handoff-commit:",
        domain="module-agent-handoff-commit-receipt-identity-v1",
    )
    if receipt["fence_token"] != receipt["predecessor_fence_token"] + 1:
        raise AgentHandoffCustodyError("handoff commit fence transition rejected")
    return {
        "ok": True,
        "receipt_id": receipt_id,
        "transaction_id": receipt["transaction_id"],
        "request_digest": receipt["request_digest"],
        "status": "COMMITTED",
        "fence_token": receipt["fence_token"],
        "production_authority": False,
    }


def _build_reconciliation_receipt(
    *,
    reference: HandoffTransactionReference,
    snapshot: AgentCustodySnapshot,
    status: HandoffTransactionStatus,
    commit_receipt_id: str | None,
    reconciled_at: str,
    signer: Ed25519Signer,
) -> dict[str, Any]:
    unsigned: dict[str, Any] = {
        "protocol": (
            "integrity-guardian/module-agent-handoff-reconciliation-receipt/v1"
        ),
        "receipt_id": "handoff-reconciliation:pending",
        "transaction_id": reference.transaction_id,
        "request_digest": reference.request_digest,
        "store_id": snapshot.store_id,
        "tenant_id": snapshot.tenant_id,
        "module_id": snapshot.module_id,
        "signer_policy_digest": snapshot.signer_policy_digest,
        "status": status.value,
        "commit_receipt_id": commit_receipt_id,
        "observed_head_id": snapshot.head["head_id"],
        "observed_head_digest": snapshot.head_digest,
        "observed_fence_token": snapshot.fence_token,
        "reconciled_at": reconciled_at,
        "retry_permitted": False,
        "production_authority": False,
    }
    identity = digest_object(
        unsigned, domain="module-agent-handoff-reconciliation-receipt-identity-v1"
    ).split(":", 1)[1]
    unsigned["receipt_id"] = f"handoff-reconciliation:{identity}"
    receipt = signer.sign(unsigned)
    validate("module-agent-handoff-reconciliation-receipt", receipt)
    return receipt


def verify_module_agent_handoff_reconciliation_receipt(
    receipt: dict[str, Any], *, authority_key: TrustedKey
) -> dict[str, Any]:
    validate("module-agent-handoff-reconciliation-receipt", receipt)
    if (
        receipt["signature"]["key_id"] != authority_key.key_id
        or not verify_signature(receipt, authority_key.public_key)
    ):
        raise AgentHandoffCustodyError("handoff reconciliation signature rejected")
    receipt_id = _signed_identity(
        receipt,
        field="receipt_id",
        prefix="handoff-reconciliation:",
        domain="module-agent-handoff-reconciliation-receipt-identity-v1",
    )
    if receipt["retry_permitted"] is not False:
        raise AgentHandoffCustodyError("handoff reconciliation retry policy rejected")
    return {
        "ok": True,
        "receipt_id": receipt_id,
        "transaction_id": receipt["transaction_id"],
        "request_digest": receipt["request_digest"],
        "status": receipt["status"],
        "retry_permitted": False,
        "production_authority": False,
    }


def _require_receipt_binding(
    receipt: dict[str, Any],
    *,
    reference: HandoffTransactionReference,
    store_id: str,
    policy: HandoffSignerPolicy,
    expected_transition: dict[str, Any] | None = None,
) -> None:
    expected: dict[str, Any] = {
        "transaction_id": reference.transaction_id,
        "request_digest": reference.request_digest,
        "store_id": store_id,
        "tenant_id": policy.tenant_id,
        "module_id": policy.module_id,
        "signer_policy_digest": policy.digest,
    }
    if expected_transition is not None:
        expected.update(expected_transition)
    if any(receipt.get(field) != value for field, value in expected.items()):
        raise AgentHandoffCustodyError("handoff receipt binding rejected")


class AgentLeaseCustody:
    """One canonical SQLite head with CAS, fencing and durable outcomes."""

    def __init__(
        self,
        path: Path,
        *,
        store_id: str,
        policy: HandoffSignerPolicy,
    ) -> None:
        self.path = Path(os.path.abspath(path))
        self.store_id = store_id
        self.policy = policy
        if _STORE_ID.fullmatch(store_id) is None:
            raise AgentHandoffCustodyError("agent custody store identity rejected")

    @classmethod
    def create(
        cls,
        path: Path,
        *,
        store_id: str,
        policy: HandoffSignerPolicy,
        initial_lease: dict[str, Any],
        initial_head: dict[str, Any],
        at_time: str,
    ) -> Self:
        store = cls(path, store_id=store_id, policy=policy)
        store._verify_current_documents(
            initial_lease, initial_head, at_time=at_time, require_active=True
        )
        with store._connect(create=True) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                store._create_schema(connection)
                connection.execute(
                    """
                    INSERT INTO custody_state (
                        singleton, schema_version, store_id, tenant_id, module_id,
                        authority_key_id, authority_key_fingerprint,
                        signer_policy_digest, fence_token,
                        current_lease_id, current_lease_digest, current_lease_json,
                        current_head_id, current_head_digest, current_head_json
                    ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        SCHEMA_VERSION,
                        store_id,
                        policy.tenant_id,
                        policy.module_id,
                        policy.custody_authority.key_id,
                        public_key_fingerprint(policy.custody_authority.public_key),
                        policy.digest,
                        initial_lease["lease_id"],
                        digest_object(
                            initial_lease,
                            domain="module-agent-lease-reference-v1",
                        ),
                        _json(initial_lease),
                        initial_head["head_id"],
                        module_agent_head_digest(initial_head),
                        _json(initial_head),
                    ),
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        return store

    @classmethod
    def open(
        cls,
        path: Path,
        *,
        store_id: str,
        policy: HandoffSignerPolicy,
        at_time: str,
    ) -> Self:
        store = cls(path, store_id=store_id, policy=policy)
        store._read_snapshot(at_time=at_time, require_active=False)
        return store

    @contextmanager
    def _connect(self, *, create: bool = False) -> Iterator[sqlite3.Connection]:
        with open_private_sqlite_connection(self.path, create=create) as connection:
            yield connection

    @staticmethod
    def _create_schema(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE custody_state (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                schema_version INTEGER NOT NULL,
                store_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                module_id TEXT NOT NULL,
                authority_key_id TEXT NOT NULL,
                authority_key_fingerprint TEXT NOT NULL,
                signer_policy_digest TEXT NOT NULL,
                fence_token INTEGER NOT NULL CHECK (fence_token >= 0),
                current_lease_id TEXT NOT NULL,
                current_lease_digest TEXT NOT NULL,
                current_lease_json TEXT NOT NULL,
                current_head_id TEXT NOT NULL,
                current_head_digest TEXT NOT NULL,
                current_head_json TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE handoff_transactions (
                transaction_id TEXT PRIMARY KEY,
                request_digest TEXT NOT NULL,
                outcome TEXT NOT NULL CHECK (outcome IN ('COMMITTED', 'NOT_COMMITTED')),
                commit_receipt_json TEXT,
                reconciliation_receipt_json TEXT,
                CHECK (
                    (outcome = 'COMMITTED' AND commit_receipt_json IS NOT NULL)
                    OR (outcome = 'NOT_COMMITTED' AND commit_receipt_json IS NULL)
                )
            )
            """
        )
        connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    def _snapshot_from_row(
        self, row: sqlite3.Row, *, at_time: str, require_active: bool
    ) -> AgentCustodySnapshot:
        if (
            row["schema_version"] != SCHEMA_VERSION
            or row["store_id"] != self.store_id
            or row["tenant_id"] != self.policy.tenant_id
            or row["module_id"] != self.policy.module_id
            or row["authority_key_id"] != self.policy.custody_authority.key_id
            or row["authority_key_fingerprint"]
            != public_key_fingerprint(self.policy.custody_authority.public_key)
            or row["signer_policy_digest"] != self.policy.digest
        ):
            raise AgentHandoffCustodyError("agent custody identity rejected")
        fence_token = row["fence_token"]
        if (
            not isinstance(fence_token, int)
            or not 0 <= fence_token <= MAX_FENCE_TOKEN
        ):
            raise AgentHandoffCustodyError("agent custody fence rejected")
        lease = _document(row["current_lease_json"], "lease")
        head = _document(row["current_head_json"], "head")
        self._verify_current_documents(
            lease, head, at_time=at_time, require_active=require_active
        )
        if (
            row["current_lease_id"] != lease["lease_id"]
            or row["current_lease_digest"]
            != digest_object(lease, domain="module-agent-lease-reference-v1")
            or row["current_head_id"] != head["head_id"]
            or row["current_head_digest"] != module_agent_head_digest(head)
        ):
            raise AgentHandoffCustodyError("agent custody row digest rejected")
        return AgentCustodySnapshot(
            store_id=self.store_id,
            tenant_id=self.policy.tenant_id,
            module_id=self.policy.module_id,
            signer_policy_digest=self.policy.digest,
            fence_token=fence_token,
            lease=lease,
            head=head,
        )

    def _load_snapshot(
        self,
        connection: sqlite3.Connection,
        *,
        at_time: str,
        require_active: bool,
    ) -> AgentCustodySnapshot:
        row = connection.execute(
            "SELECT * FROM custody_state WHERE singleton = 1"
        ).fetchone()
        if row is None:
            raise AgentHandoffCustodyError("agent custody state missing")
        return self._snapshot_from_row(
            row, at_time=at_time, require_active=require_active
        )

    def _verify_current_documents(
        self,
        lease: dict[str, Any],
        head: dict[str, Any],
        *,
        at_time: str,
        require_active: bool,
    ) -> None:
        try:
            lease_verification = verify_module_agent_lease(
                lease,
                authority_key=self.policy.custody_authority,
                at_time=at_time,
            )
            head_verification = verify_module_agent_lease_head(
                head,
                authority_key=self.policy.custody_authority,
            )
        except (AgentContinuityError, KeyError, ValueError) as exc:
            raise AgentHandoffCustodyError("agent custody current head rejected") from exc
        if (
            lease_verification["tenant_id"] != self.policy.tenant_id
            or lease_verification["module_id"] != self.policy.module_id
            or head_verification["tenant_id"] != self.policy.tenant_id
            or head_verification["module_id"] != self.policy.module_id
        ):
            raise AgentHandoffCustodyError("agent custody current scope rejected")
        if require_active and not lease_verification["active"]:
            raise AgentHandoffCustodyError("agent custody current lease is not active")
        expected = {
            "lease_id": lease["lease_id"],
            "lease_digest": digest_object(
                lease, domain="module-agent-lease-reference-v1"
            ),
            "agent_id": lease["agent_id"],
            "agent_key_id": lease["agent_key_id"],
            "generation": lease["generation"],
            "sequence": lease["sequence"],
            "event_cursor": lease["event_cursor"],
            "state_digest": lease["state_digest"],
        }
        for field, value in expected.items():
            if head[field] != value:
                raise AgentHandoffCustodyError(
                    f"agent custody head {field} differs from lease"
                )

    def _read_snapshot(
        self, *, at_time: str, require_active: bool
    ) -> AgentCustodySnapshot:
        with self._connect() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                snapshot = self._load_snapshot(
                    connection,
                    at_time=at_time,
                    require_active=require_active,
                )
                connection.commit()
                return snapshot
            except Exception:
                connection.rollback()
                raise

    def read_current(self, *, at_time: str) -> AgentCustodySnapshot:
        return self._read_snapshot(at_time=at_time, require_active=True)

    def assert_current_fence(
        self,
        *,
        fence_token: int,
        head_id: str,
        agent_id: str,
        at_time: str,
    ) -> AgentCustodySnapshot:
        if (
            isinstance(fence_token, bool)
            or not isinstance(fence_token, int)
            or not 0 <= fence_token <= MAX_FENCE_TOKEN
        ):
            raise StaleAgentFenceError("agent custody fence is invalid")
        snapshot = self.read_current(at_time=at_time)
        if (
            snapshot.fence_token != fence_token
            or snapshot.head["head_id"] != head_id
            or snapshot.lease["agent_id"] != agent_id
        ):
            raise StaleAgentFenceError("agent custody fence is stale")
        return snapshot

    def _validate_handoff(
        self,
        snapshot: AgentCustodySnapshot,
        *,
        checkpoint: dict[str, Any],
        ack: dict[str, Any],
        successor_lease: dict[str, Any],
        successor_head: dict[str, Any],
        at_time: str,
    ) -> None:
        predecessor_key = self.policy.key_for(
            HandoffSignerRole.PREDECESSOR,
            snapshot.lease["agent_id"],
            snapshot.lease["agent_key_id"],
        )
        successor_key = self.policy.key_for(
            HandoffSignerRole.SUCCESSOR,
            checkpoint["successor_agent_id"],
            checkpoint["successor_key_id"],
        )
        try:
            verify_module_agent_successor_ack(
                checkpoint,
                ack,
                predecessor_key=predecessor_key,
                successor_key=successor_key,
                at_time=at_time,
            )
            lease_verification = verify_module_agent_lease(
                successor_lease,
                authority_key=self.policy.custody_authority,
                at_time=at_time,
            )
            head_verification = verify_module_agent_lease_head(
                successor_head,
                authority_key=self.policy.custody_authority,
            )
            verify_current_module_agent_lease(
                successor_lease,
                lease_head=successor_head,
                trusted_head_id=successor_head["head_id"],
                authority_key=self.policy.custody_authority,
                at_time=at_time,
            )
        except (AgentHandoffError, AgentContinuityError, KeyError, ValueError) as exc:
            raise AgentHandoffCustodyError("agent handoff evidence rejected") from exc
        checkpoint_expected = {
            "tenant_id": snapshot.tenant_id,
            "module_id": snapshot.module_id,
            "predecessor_agent_id": snapshot.lease["agent_id"],
            "predecessor_key_id": snapshot.lease["agent_key_id"],
            "predecessor_generation": snapshot.lease["generation"],
            "predecessor_lease_id": snapshot.lease["lease_id"],
            "predecessor_head_id": snapshot.head["head_id"],
            "predecessor_head_digest": snapshot.head_digest,
            "snapshot_digest": snapshot.lease["state_digest"],
            "event_cursor": snapshot.lease["event_cursor"],
        }
        for field, value in checkpoint_expected.items():
            if checkpoint[field] != value:
                raise AgentHandoffCustodyError(
                    f"handoff checkpoint {field} differs from custody"
                )
        lease_expected = {
            "tenant_id": snapshot.tenant_id,
            "module_id": snapshot.module_id,
            "agent_id": checkpoint["successor_agent_id"],
            "agent_key_id": checkpoint["successor_key_id"],
            "generation": checkpoint["successor_generation"],
            "event_cursor": checkpoint["event_cursor"],
            "state_digest": checkpoint["snapshot_digest"],
        }
        for field, value in lease_expected.items():
            if successor_lease[field] != value:
                raise AgentHandoffCustodyError(
                    f"successor lease {field} differs from checkpoint"
                )
        if not lease_verification["active"]:
            raise AgentHandoffCustodyError("successor lease is not active")
        if successor_lease["sequence"] <= snapshot.lease["sequence"]:
            raise AgentHandoffCustodyError("successor lease sequence did not advance")
        if (
            successor_head["previous_head_id"] != snapshot.head["head_id"]
            or successor_head["head_revision"]
            != snapshot.head["head_revision"] + 1
            or head_verification["head_id"] != successor_head["head_id"]
        ):
            raise AgentHandoffCustodyError("successor head chain rejected")
        predecessor_recorded = _time(snapshot.head["recorded_at"], "predecessor head")
        successor_recorded = _time(successor_head["recorded_at"], "successor head")
        if not predecessor_recorded <= successor_recorded <= _time(
            at_time, "commit"
        ):
            raise AgentHandoffCustodyError("successor head chronology rejected")

    def commit_handoff(
        self,
        *,
        expected_fence_token: int,
        checkpoint: dict[str, Any],
        ack: dict[str, Any],
        successor_lease: dict[str, Any],
        successor_head: dict[str, Any],
        committed_at: str,
        authority_signer: Ed25519Signer,
        delivery_hook: Callable[[], None] | None = None,
    ) -> HandoffCommitResult:
        """Atomically swap the current head or return a non-retriable unknown."""

        self.policy.require_authority_signer(authority_signer)
        if (
            isinstance(expected_fence_token, bool)
            or not isinstance(expected_fence_token, int)
            or not 0 <= expected_fence_token <= MAX_FENCE_TOKEN
        ):
            raise StaleAgentFenceError("handoff custody fence is invalid")
        reference = module_agent_handoff_transaction_reference(
            store_id=self.store_id,
            expected_head_id=checkpoint["predecessor_head_id"],
            expected_fence_token=expected_fence_token,
            checkpoint=checkpoint,
            ack=ack,
            successor_lease=successor_lease,
            successor_head=successor_head,
        )
        with self._connect() as connection:
            commit_started = False
            try:
                connection.execute("BEGIN IMMEDIATE")
                existing = connection.execute(
                    "SELECT * FROM handoff_transactions WHERE transaction_id = ?",
                    (reference.transaction_id,),
                ).fetchone()
                if existing is not None:
                    if existing["request_digest"] != reference.request_digest:
                        raise AgentHandoffCustodyError(
                            "handoff transaction identity collision"
                        )
                    if existing["outcome"] == HandoffTransactionStatus.NOT_COMMITTED:
                        raise AgentHandoffCustodyError(
                            "handoff transaction was retired by reconciliation"
                        )
                    receipt = _document(
                        existing["commit_receipt_json"], "commit receipt"
                    )
                    verify_module_agent_handoff_commit_receipt(
                        receipt, authority_key=self.policy.custody_authority
                    )
                    _require_receipt_binding(
                        receipt,
                        reference=reference,
                        store_id=self.store_id,
                        policy=self.policy,
                        expected_transition={
                            "predecessor_head_id": checkpoint[
                                "predecessor_head_id"
                            ],
                            "predecessor_head_digest": checkpoint[
                                "predecessor_head_digest"
                            ],
                            "predecessor_fence_token": expected_fence_token,
                            "successor_head_id": successor_head["head_id"],
                            "successor_head_digest": module_agent_head_digest(
                                successor_head
                            ),
                            "successor_lease_id": successor_lease["lease_id"],
                            "successor_agent_id": successor_lease["agent_id"],
                            "successor_generation": successor_lease["generation"],
                            "fence_token": expected_fence_token + 1,
                            "status": "COMMITTED",
                            "production_authority": False,
                        },
                    )
                    connection.commit()
                    return HandoffCommitResult(
                        HandoffTransactionStatus.COMMITTED, reference, receipt
                    )
                snapshot = self._load_snapshot(
                    connection, at_time=committed_at, require_active=True
                )
                if (
                    snapshot.fence_token != expected_fence_token
                    or snapshot.head["head_id"]
                    != checkpoint["predecessor_head_id"]
                ):
                    raise StaleAgentFenceError(
                        "handoff custody CAS predecessor is stale"
                    )
                self._validate_handoff(
                    snapshot,
                    checkpoint=checkpoint,
                    ack=ack,
                    successor_lease=successor_lease,
                    successor_head=successor_head,
                    at_time=committed_at,
                )
                if snapshot.fence_token >= MAX_FENCE_TOKEN:
                    raise AgentHandoffCustodyError("agent custody fence exhausted")
                next_fence = snapshot.fence_token + 1
                receipt = _build_commit_receipt(
                    reference=reference,
                    snapshot=snapshot,
                    successor_lease=successor_lease,
                    successor_head=successor_head,
                    committed_at=committed_at,
                    fence_token=next_fence,
                    signer=authority_signer,
                )
                updated = connection.execute(
                    """
                    UPDATE custody_state
                    SET fence_token = ?, current_lease_id = ?,
                        current_lease_digest = ?, current_lease_json = ?,
                        current_head_id = ?, current_head_digest = ?,
                        current_head_json = ?
                    WHERE singleton = 1 AND fence_token = ? AND current_head_id = ?
                    """,
                    (
                        next_fence,
                        successor_lease["lease_id"],
                        digest_object(
                            successor_lease,
                            domain="module-agent-lease-reference-v1",
                        ),
                        _json(successor_lease),
                        successor_head["head_id"],
                        module_agent_head_digest(successor_head),
                        _json(successor_head),
                        snapshot.fence_token,
                        snapshot.head["head_id"],
                    ),
                )
                if updated.rowcount != 1:
                    raise StaleAgentFenceError("handoff custody CAS lost")
                connection.execute(
                    """
                    INSERT INTO handoff_transactions (
                        transaction_id, request_digest, outcome,
                        commit_receipt_json, reconciliation_receipt_json
                    ) VALUES (?, ?, 'COMMITTED', ?, NULL)
                    """,
                    (
                        reference.transaction_id,
                        reference.request_digest,
                        _json(receipt),
                    ),
                )
                commit_started = True
                try:
                    connection.commit()
                except sqlite3.Error:
                    return HandoffCommitResult(
                        HandoffTransactionStatus.COMMIT_UNKNOWN,
                        reference,
                        None,
                    )
            except Exception:
                if not commit_started:
                    connection.rollback()
                raise
        if delivery_hook is not None:
            try:
                delivery_hook()
            except OSError:
                return HandoffCommitResult(
                    HandoffTransactionStatus.COMMIT_UNKNOWN, reference, None
                )
        return HandoffCommitResult(
            HandoffTransactionStatus.COMMITTED, reference, receipt
        )

    def reconcile_commit_unknown(
        self,
        reference: HandoffTransactionReference,
        *,
        reconciled_at: str,
        authority_signer: Ed25519Signer,
    ) -> dict[str, Any]:
        """Resolve unknown once, tombstoning absence so replay stays impossible."""

        self.policy.require_authority_signer(authority_signer)
        if (
            _TRANSACTION_ID.fullmatch(reference.transaction_id) is None
            or _DIGEST.fullmatch(reference.request_digest) is None
        ):
            raise AgentHandoffCustodyError("handoff transaction reference rejected")
        with self._connect() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                snapshot = self._load_snapshot(
                    connection, at_time=reconciled_at, require_active=False
                )
                existing = connection.execute(
                    "SELECT * FROM handoff_transactions WHERE transaction_id = ?",
                    (reference.transaction_id,),
                ).fetchone()
                if (
                    existing is not None
                    and existing["request_digest"] != reference.request_digest
                ):
                    raise AgentHandoffCustodyError(
                        "handoff reconciliation digest mismatch"
                    )
                if existing is not None and existing["reconciliation_receipt_json"]:
                    receipt = _document(
                        existing["reconciliation_receipt_json"],
                        "reconciliation receipt",
                    )
                    verify_module_agent_handoff_reconciliation_receipt(
                        receipt, authority_key=self.policy.custody_authority
                    )
                    _require_receipt_binding(
                        receipt,
                        reference=reference,
                        store_id=self.store_id,
                        policy=self.policy,
                        expected_transition={
                            "status": existing["outcome"],
                            "production_authority": False,
                        },
                    )
                    if existing["outcome"] == "COMMITTED":
                        commit_receipt = _document(
                            existing["commit_receipt_json"], "commit receipt"
                        )
                        commit_verification = (
                            verify_module_agent_handoff_commit_receipt(
                                commit_receipt,
                                authority_key=self.policy.custody_authority,
                            )
                        )
                        _require_receipt_binding(
                            commit_receipt,
                            reference=reference,
                            store_id=self.store_id,
                            policy=self.policy,
                            expected_transition={
                                "status": "COMMITTED",
                                "production_authority": False,
                            },
                        )
                        if (
                            receipt["commit_receipt_id"]
                            != commit_verification["receipt_id"]
                        ):
                            raise AgentHandoffCustodyError(
                                "handoff reconciliation commit binding rejected"
                            )
                    elif receipt["commit_receipt_id"] is not None:
                        raise AgentHandoffCustodyError(
                            "handoff reconciliation absence binding rejected"
                        )
                    connection.commit()
                    return receipt
                if existing is not None and existing["outcome"] == "COMMITTED":
                    commit_receipt = _document(
                        existing["commit_receipt_json"], "commit receipt"
                    )
                    commit_verification = verify_module_agent_handoff_commit_receipt(
                        commit_receipt, authority_key=self.policy.custody_authority
                    )
                    _require_receipt_binding(
                        commit_receipt,
                        reference=reference,
                        store_id=self.store_id,
                        policy=self.policy,
                        expected_transition={
                            "status": "COMMITTED",
                            "production_authority": False,
                        },
                    )
                    if _time(reconciled_at, "reconciliation") < _time(
                        commit_receipt["committed_at"], "commit receipt"
                    ):
                        raise AgentHandoffCustodyError(
                            "handoff reconciliation predates commit"
                        )
                    status = HandoffTransactionStatus.COMMITTED
                    commit_receipt_id = commit_verification["receipt_id"]
                else:
                    status = HandoffTransactionStatus.NOT_COMMITTED
                    commit_receipt_id = None
                receipt = _build_reconciliation_receipt(
                    reference=reference,
                    snapshot=snapshot,
                    status=status,
                    commit_receipt_id=commit_receipt_id,
                    reconciled_at=reconciled_at,
                    signer=authority_signer,
                )
                if existing is None:
                    connection.execute(
                        """
                        INSERT INTO handoff_transactions (
                            transaction_id, request_digest, outcome,
                            commit_receipt_json, reconciliation_receipt_json
                        ) VALUES (?, ?, 'NOT_COMMITTED', NULL, ?)
                        """,
                        (
                            reference.transaction_id,
                            reference.request_digest,
                            _json(receipt),
                        ),
                    )
                else:
                    connection.execute(
                        """
                        UPDATE handoff_transactions
                        SET reconciliation_receipt_json = ?
                        WHERE transaction_id = ? AND request_digest = ?
                        """,
                        (
                            _json(receipt),
                            reference.transaction_id,
                            reference.request_digest,
                        ),
                    )
                connection.commit()
                return receipt
            except Exception:
                connection.rollback()
                raise
