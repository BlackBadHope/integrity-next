#!/opt/integrity/current/venv/bin/python
# SPDX-License-Identifier: Apache-2.0
"""Loopback read-only Seed runtime backed by verified delta checkpoints."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import sqlite3
import threading
from contextlib import closing
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any

import integrity_guardian.seed_runtime as legacy_runtime
from integrity_guardian.seed_catalog import CATALOG_SCHEMA_VERSION, SEED_NAMESPACE, SeedCatalog, SeedCatalogError
from integrity_guardian.seed_relationships import SeedRelationshipIndex
from integrity_guardian.seed_runtime import SeedRuntimeHandler

from seed_delta_sync import PROTOCOL, fast_status


DELTA_RUNTIME_VERSION = "5.5.2rc2"


def checkpoint_verification(status: dict[str, Any]) -> dict[str, Any]:
    counts = dict(status["counts"])
    return {
        "ok": True,
        "protocol": PROTOCOL,
        "schema_version": CATALOG_SCHEMA_VERSION,
        "source_namespace": SEED_NAMESPACE,
        "source_digest": status["mmr_root"],
        "catalog_digest": status["checkpoint_digest"],
        **counts,
        "verification_mode": "delta-checkpoint",
        "last_full_source_digest": status["last_full_source_digest"],
        "last_full_catalog_digest": status["last_full_catalog_digest"],
        "last_full_verified_at": status["last_full_verified_at"],
        "delta_since_full": status["delta_since_full"],
        "raw_event_mmr_root": status["mmr_root"],
        "production_authority": False,
    }


class FastSeedCatalog(SeedCatalog):
    def runtime_snapshot(self, *, active_limit: int = 12) -> dict[str, Any]:
        if not 1 <= active_limit <= 50:
            raise SeedCatalogError("capsule active task limit is outside 1..50")
        delta_status = fast_status(self.path)
        verification = checkpoint_verification(delta_status)
        with closing(sqlite3.connect(f"file:{self.path}?mode=ro", uri=True)) as connection:
            connection.row_factory = sqlite3.Row
            status = self._status_from_connection(connection, verification)
            status.update(
                {
                    "status": "READY",
                    "checkpoint_digest": delta_status["checkpoint_digest"],
                    "verification_mode": "delta-checkpoint",
                }
            )
            capsule = self._capsule_from_connection(connection, verification, active_limit=active_limit)
        return {"run_id": delta_status["checkpoint_digest"], "status": status, "capsule": capsule}

    def status(self) -> dict[str, Any]:
        return self.runtime_snapshot()["status"]

    def capsule(self, *, active_limit: int = 12) -> dict[str, Any]:
        return self.runtime_snapshot(active_limit=active_limit)["capsule"]


class DeltaSeedRuntimeServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], catalog_path: Path, *, evidence_root: Path | None = None):
        host, _ = address
        if host not in {"127.0.0.1", "::1", "localhost"}:
            raise SeedCatalogError("Integrity Seed delta runtime is loopback-only")
        self.catalog = FastSeedCatalog(catalog_path)
        self.evidence_root = evidence_root.absolute() if evidence_root is not None else None
        self._snapshot_lock = threading.Lock()
        self._snapshot = self.catalog.runtime_snapshot()
        self._relationship_lock = threading.Lock()
        self._relationship_run_id = ""
        self._relationship_index: SeedRelationshipIndex | None = None
        legacy_runtime.__version__ = DELTA_RUNTIME_VERSION
        super().__init__(address, SeedRuntimeHandler)

    def verified_snapshot(self) -> dict[str, Any]:
        checkpoint = fast_status(self.catalog.path)["checkpoint_digest"]
        if checkpoint == self._snapshot["run_id"]:
            return self._snapshot
        with self._snapshot_lock:
            checkpoint = fast_status(self.catalog.path)["checkpoint_digest"]
            if checkpoint != self._snapshot["run_id"]:
                self._snapshot = self.catalog.runtime_snapshot()
            return self._snapshot

    def event_connections(self, event_id: int, *, limit: int, include_contextual: bool) -> dict[str, Any]:
        checkpoint = fast_status(self.catalog.path)["checkpoint_digest"]
        with self._relationship_lock:
            if self._relationship_index is None or checkpoint != self._relationship_run_id:
                self._relationship_index = SeedRelationshipIndex.from_catalog(
                    self.catalog.path, evidence_root=self.evidence_root
                )
                self._relationship_run_id = checkpoint
            return self._relationship_index.explain(
                event_id, limit=limit, include_contextual=include_contextual
            )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18775)
    parser.add_argument("--evidence-root", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not 1 <= args.port <= 65535:
        raise SeedCatalogError("Integrity Seed delta runtime port is invalid")
    with DeltaSeedRuntimeServer(
        (args.host, args.port), args.catalog, evidence_root=args.evidence_root
    ) as server:
        server.serve_forever(poll_interval=0.5)
    return 0


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
