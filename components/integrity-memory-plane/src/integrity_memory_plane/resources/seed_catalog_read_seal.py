#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Dependency-free point-in-time read seal for a writer-owned Seed catalog."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import datetime as dt
import hashlib
import json
import os
import sqlite3
import stat
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

READ_SEAL_PROTOCOL = "integrity-guardian/seed-catalog-read-seal/v1"
READ_SEAL_BUSY_TIMEOUT_MS = 5_000
GENERATION_DIGEST_DOMAIN = (
    b"integrity-guardian\\x00guardian-json-v1\\x00"
    b"seed-catalog-read-seal-generation-v1\\x00"
)
GenerationReader = Callable[[sqlite3.Connection], dict[str, Any]]


class SeedCatalogReadSealError(RuntimeError):
    """The catalog could not produce a generation-bound immutable-read seal."""

    def __init__(
        self,
        message: str,
        *,
        reason_code: str,
        catalog_state: str,
    ) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.catalog_state = catalog_state


def _canonical(value: Any) -> bytes:
    def validate(current: Any, path: str = "$") -> None:
        if current is None or isinstance(current, (str, bool, int)):
            return
        if isinstance(current, float):
            raise TypeError(f"{path}: floating-point values are prohibited")
        if isinstance(current, Mapping):
            for key, child in current.items():
                if not isinstance(key, str):
                    raise TypeError(f"{path}: object key must be a string")
                validate(child, f"{path}.{key}")
            return
        if isinstance(current, Sequence) and not isinstance(
            current,
            (str, bytes, bytearray),
        ):
            for index, child in enumerate(current):
                validate(child, f"{path}[{index}]")
            return
        raise ValueError(f"{path}: unsupported value type {type(current).__name__}")

    validate(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def seal_catalog_for_immutable_read(
    connection: sqlite3.Connection,
    catalog: Path,
    *,
    generation_reader: GenerationReader,
    expected_generation: dict[str, Any] | None = None,
    busy_timeout_ms: int | None = None,
    durable_commit: bool = True,
) -> dict[str, Any]:
    """Checkpoint main, pin a writer barrier, and bind one logical generation."""

    catalog_state = "COMMITTED_UNSEALED" if durable_commit else "UNSEALED"

    def reject(message: str, reason_code: str) -> SeedCatalogReadSealError:
        return SeedCatalogReadSealError(
            message,
            reason_code=reason_code,
            catalog_state=catalog_state,
        )

    if connection.in_transaction:
        raise reject(
            "Seed catalog checkpoint requires a committed transaction",
            "seed_catalog_transaction_active",
        )
    timeout = READ_SEAL_BUSY_TIMEOUT_MS if busy_timeout_ms is None else busy_timeout_ms
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 0 <= timeout <= 30_000:
        raise reject(
            "Seed catalog checkpoint timeout is invalid",
            "seed_catalog_checkpoint_timeout_invalid",
        )
    catalog = catalog.absolute()
    try:
        catalog_before = catalog.lstat()
        main_rows = [
            row for row in connection.execute("PRAGMA database_list") if str(row[1]) == "main"
        ]
        if len(main_rows) != 1:
            raise OSError("main database identity is ambiguous")
        connected_path = Path(str(main_rows[0][2])).absolute()
        bound = os.path.samefile(connected_path, catalog)
    except (OSError, sqlite3.Error) as exc:
        raise reject(
            "Seed catalog checkpoint connection is not bound to the requested catalog",
            "seed_catalog_connection_mismatch",
        ) from exc
    if (
        not bound
        or stat.S_ISLNK(catalog_before.st_mode)
        or not stat.S_ISREG(catalog_before.st_mode)
    ):
        raise reject(
            "Seed catalog checkpoint connection is not bound to the requested catalog",
            "seed_catalog_connection_mismatch",
        )
    try:
        mode_row = connection.execute("PRAGMA main.journal_mode").fetchone()
    except sqlite3.Error as exc:
        raise reject(
            "Seed catalog journal mode could not be inspected",
            "seed_catalog_journal_mode_inspection_failed",
        ) from exc
    if mode_row is None or str(mode_row[0]).lower() != "wal":
        raise reject(
            "Seed catalog checkpoint requires WAL journal mode",
            "seed_catalog_journal_mode_invalid",
        )
    try:
        previous_timeout_row = connection.execute("PRAGMA busy_timeout").fetchone()
        previous_timeout = int(previous_timeout_row[0]) if previous_timeout_row else 0
    except (sqlite3.Error, TypeError, ValueError) as exc:
        raise reject(
            "Seed catalog checkpoint timeout could not be inspected",
            "seed_catalog_checkpoint_timeout_inspection_failed",
        ) from exc
    checkpoint_error: sqlite3.Error | None = None
    try:
        connection.execute(f"PRAGMA busy_timeout={timeout}")
        checkpoint = connection.execute("PRAGMA main.wal_checkpoint(TRUNCATE)").fetchone()
    except sqlite3.Error as exc:
        checkpoint = None
        checkpoint_error = exc
    try:
        connection.execute(f"PRAGMA busy_timeout={previous_timeout}")
    except sqlite3.Error as exc:
        raise reject(
            "Seed catalog checkpoint timeout could not be restored",
            "seed_catalog_checkpoint_timeout_restore_failed",
        ) from exc
    if checkpoint_error is not None:
        raise reject(
            "Seed catalog checkpoint could not produce an immutable read seal",
            "seed_catalog_checkpoint_failed",
        ) from checkpoint_error
    if checkpoint is None or len(checkpoint) != 3:
        raise reject(
            "Seed catalog checkpoint returned an invalid receipt",
            "seed_catalog_checkpoint_receipt_invalid",
        )
    try:
        busy, log_frames, checkpointed_frames = (int(value) for value in checkpoint)
    except (TypeError, ValueError) as exc:
        raise reject(
            "Seed catalog checkpoint returned an invalid receipt",
            "seed_catalog_checkpoint_receipt_invalid",
        ) from exc
    frames = (log_frames, checkpointed_frames)
    if busy != 0 or frames not in ((0, 0), (-1, -1)):
        raise reject(
            "Seed catalog checkpoint is busy; committed catalog is not sealed for immutable reads",
            "seed_catalog_checkpoint_busy",
        )

    try:
        connection.execute("BEGIN IMMEDIATE")
    except sqlite3.Error as exc:
        raise reject(
            "Seed catalog writer barrier is busy; immutable read seal was not produced",
            "seed_catalog_writer_busy",
        ) from exc
    try:
        wal = catalog.with_name(catalog.name + "-wal")
        try:
            wal_details = wal.lstat()
        except FileNotFoundError:
            wal_state = "ABSENT"
            wal_bytes = 0
        else:
            if stat.S_ISLNK(wal_details.st_mode) or not stat.S_ISREG(wal_details.st_mode):
                raise reject(
                    "Seed catalog WAL custody is unsafe",
                    "seed_catalog_wal_custody_invalid",
                )
            wal_state = "PRESENT_EMPTY" if wal_details.st_size == 0 else "PRESENT_DATA"
            wal_bytes = wal_details.st_size
        if wal_bytes != 0:
            raise reject(
                "Seed catalog checkpoint left pending WAL data",
                "seed_catalog_checkpoint_busy",
            )
        logical_generation = generation_reader(connection)
        if not isinstance(logical_generation, dict):
            raise reject(
                "Seed catalog generation reader returned an invalid identity",
                "seed_catalog_generation_invalid",
            )
        if expected_generation is not None and logical_generation != expected_generation:
            raise reject(
                "Seed catalog generation changed before immutable read seal",
                "seed_catalog_generation_changed",
            )
        catalog_after = catalog.lstat()
        if (
            stat.S_ISLNK(catalog_after.st_mode)
            or not stat.S_ISREG(catalog_after.st_mode)
            or (catalog_after.st_dev, catalog_after.st_ino)
            != (catalog_before.st_dev, catalog_before.st_ino)
        ):
            raise reject(
                "Seed catalog custody changed during immutable read seal",
                "seed_catalog_custody_changed",
            )
        generation_digest = "sha256:" + hashlib.sha256(
            GENERATION_DIGEST_DOMAIN + _canonical(logical_generation)
        ).hexdigest()
        observed_utc = dt.datetime.now(dt.UTC).isoformat(timespec="microseconds").replace(
            "+00:00", "Z"
        )
    except SeedCatalogReadSealError:
        raise
    except Exception as exc:
        raise reject(
            "Seed catalog generation could not be verified for immutable reads",
            "seed_catalog_generation_verification_failed",
        ) from exc
    finally:
        if connection.in_transaction:
            try:
                connection.rollback()
            except sqlite3.Error as exc:
                raise reject(
                    "Seed catalog writer barrier could not be released",
                    "seed_catalog_writer_barrier_release_failed",
                ) from exc

    return {
        "protocol": READ_SEAL_PROTOCOL,
        "status": "SEALED",
        "scope": "point-in-time-not-a-lease",
        "catalog_state": "COMMITTED_SEALED" if durable_commit else "SEALED",
        "checkpoint_mode": "TRUNCATE",
        "checkpoint_outcome": "TRUNCATED" if frames == (0, 0) else "NO_WAL",
        "busy": busy,
        "log_frames": log_frames,
        "checkpointed_frames": checkpointed_frames,
        "wal_state": wal_state,
        "wal_bytes": wal_bytes,
        "logical_generation": logical_generation,
        "generation_digest": generation_digest,
        "observed_utc": observed_utc,
        "catalog_identity": {
            "device": catalog_after.st_dev,
            "inode": catalog_after.st_ino,
            "bytes": catalog_after.st_size,
            "mtime_ns": catalog_after.st_mtime_ns,
        },
        "production_authority": False,
    }
