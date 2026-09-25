"""Loopback read-only runtime for the structured canonical Integrity Seed."""

from __future__ import annotations

import json
import threading
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from . import __version__
from .memory_link_graph import MemoryLinkGraph
from .seed_catalog import SeedCatalog, SeedCatalogError
from .seed_relationships import SeedRelationshipIndex

MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_REJECTED_REQUEST_BODY_BYTES = 64 * 1024


class SeedRuntimeServer(ThreadingHTTPServer):
    """Bounded loopback HTTP server holding no credentials or write primitive."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        address: tuple[str, int],
        catalog_path: Path,
        *,
        evidence_root: Path | None = None,
        evidence_source_prefix: Path | None = None,
    ):
        host, _ = address
        if host not in {"127.0.0.1", "::1", "localhost"}:
            raise SeedCatalogError("Integrity Seed runtime is loopback-only")
        self.catalog = SeedCatalog(catalog_path)
        self.evidence_root = evidence_root.absolute() if evidence_root is not None else None
        self.evidence_source_prefix = (
            evidence_source_prefix.absolute()
            if evidence_source_prefix is not None
            else None
        )
        self._snapshot_lock = threading.Lock()
        self._snapshot = self.catalog.runtime_snapshot()
        self._relationship_lock = threading.Lock()
        self._relationship_run_id = ""
        self._relationship_index: SeedRelationshipIndex | None = None
        self._memory_link_lock = threading.Lock()
        self._memory_link_run_id = ""
        self._memory_link_graph: MemoryLinkGraph | None = None
        super().__init__(address, SeedRuntimeHandler)

    def verified_snapshot(self) -> dict[str, Any]:
        """Refresh exactly once after a committed sync run, then serve from memory."""

        latest_run_id = self.catalog.latest_run_id()
        if latest_run_id == self._snapshot["run_id"]:
            return self._snapshot
        with self._snapshot_lock:
            latest_run_id = self.catalog.latest_run_id()
            if latest_run_id != self._snapshot["run_id"]:
                self._snapshot = self.catalog.runtime_snapshot()
            return self._snapshot

    def event_connections(
        self,
        event_id: int,
        *,
        limit: int,
        include_contextual: bool,
    ) -> dict[str, Any]:
        """Build one read-only relationship view and cache only its raw index."""

        latest_run_id = self.catalog.latest_run_id()
        with self._relationship_lock:
            if self._relationship_index is None or latest_run_id != self._relationship_run_id:
                self._relationship_index = SeedRelationshipIndex.from_catalog(
                    self.catalog.path,
                    evidence_root=self.evidence_root,
                    evidence_source_prefix=self.evidence_source_prefix,
                )
                self._relationship_run_id = latest_run_id
            return self._relationship_index.explain(
                event_id,
                limit=limit,
                include_contextual=include_contextual,
            )

    def memory_link_graph(self) -> MemoryLinkGraph:
        """Return one run-id-bound, rebuildable graph without persistent derived state."""

        latest_run_id = self.catalog.latest_run_id()
        with self._memory_link_lock:
            if self._memory_link_graph is None or latest_run_id != self._memory_link_run_id:
                self._memory_link_graph = MemoryLinkGraph.from_catalog(self.catalog.path)
                self._memory_link_run_id = latest_run_id
            return self._memory_link_graph


class SeedRuntimeHandler(BaseHTTPRequestHandler):
    server: SeedRuntimeServer
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:
        return

    def _send(self, status: HTTPStatus, value: Any) -> None:
        body = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(body) > MAX_RESPONSE_BYTES:
            status = HTTPStatus.REQUEST_ENTITY_TOO_LARGE
            body = b'{"error":"response exceeds bounded runtime limit","ok":false}'
        self.send_response(status.value)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        raw_length = self.headers.get("Content-Length", "0")
        try:
            content_length = int(raw_length)
        except ValueError:
            content_length = -1
        if 0 < content_length <= MAX_REJECTED_REQUEST_BODY_BYTES:
            self.rfile.read(content_length)
        elif content_length < 0 or content_length > MAX_REJECTED_REQUEST_BODY_BYTES:
            self.close_connection = True
        self._send(
            HTTPStatus.METHOD_NOT_ALLOWED,
            {
                "ok": False,
                "error": "Integrity Seed runtime is read-only",
                "production_authority": False,
            },
        )

    def do_PUT(self) -> None:
        self.do_POST()

    def do_DELETE(self) -> None:
        self.do_POST()

    def do_PATCH(self) -> None:
        self.do_POST()

    def do_GET(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=False)
        try:
            snapshot = self.server.verified_snapshot()
            if parsed.path == "/healthz":
                status = snapshot["status"]
                value = {
                    "ok": True,
                    "service": "integrity-seed",
                    "version": __version__,
                    "status": status["status"],
                    "source_namespace": status["source_namespace"],
                    "event_count": status["event_count"],
                    "event_cursor": status["maximum_event_id"],
                    "source_digest": status["source_digest"],
                    "catalog_digest": status["catalog_digest"],
                    "home_record_count": status["home_record_count"],
                    "production_authority": False,
                }
            elif parsed.path == "/v1/seed/status":
                value = snapshot["status"]
            elif parsed.path == "/v1/seed/capsule":
                raw_limit = query.get("active_limit", ["12"])[0]
                active_limit = int(raw_limit)
                value = (
                    snapshot["capsule"]
                    if active_limit == 12
                    else self.server.catalog.capsule(active_limit=active_limit)
                )
            elif parsed.path == "/v1/seed/search":
                search_query = query.get("q", [""])[0]
                raw_limit = query.get("limit", ["20"])[0]
                results = self.server.catalog.search(
                    search_query,
                    limit=int(raw_limit),
                )
                value = {
                    "ok": True,
                    "query": search_query,
                    "count": len(results),
                    "events": results,
                    "production_authority": False,
                }
            elif parsed.path == "/v1/seed/connections":
                event_id = int(query.get("event_id", [""])[0])
                raw_limit = query.get("limit", ["20"])[0]
                include_contextual = query.get("include_contextual", ["false"])[0].casefold() in {
                    "1",
                    "true",
                    "yes",
                }
                value = self.server.event_connections(
                    event_id,
                    limit=int(raw_limit),
                    include_contextual=include_contextual,
                )
            elif parsed.path == "/v1/seed/memory-links/status":
                value = self.server.memory_link_graph().summary()
            elif parsed.path == "/v1/seed/memory-links/resolve":
                graph = self.server.memory_link_graph()
                value = graph.resolve(
                    query.get("reference", [""])[0],
                    limit=int(query.get("limit", ["40"])[0]),
                    max_context_bytes=int(query.get("max_context_bytes", ["32768"])[0]),
                    cursor=query.get("cursor", [""])[0],
                )
            elif parsed.path == "/v1/seed/memory-links/entity":
                graph = self.server.memory_link_graph()
                value = graph.entity_brief(
                    query.get("reference", [""])[0],
                    relationship_limit=int(query.get("relationship_limit", ["40"])[0]),
                    activity_limit=int(query.get("activity_limit", ["12"])[0]),
                    task_limit=int(query.get("task_limit", ["20"])[0]),
                    discovery_limit=int(query.get("discovery_limit", ["10"])[0]),
                    max_context_bytes=int(query.get("max_context_bytes", ["65536"])[0]),
                )
            elif parsed.path == "/v1/seed/memory-links/audit":
                graph = self.server.memory_link_graph()
                value = graph.audit(
                    kinds=query.get("kind", []),
                    limit=int(query.get("limit", ["50"])[0]),
                    max_context_bytes=int(query.get("max_context_bytes", ["65536"])[0]),
                    cursor=query.get("cursor", [""])[0],
                )
            elif parsed.path == "/v1/seed/memory-links/navigate":
                graph = self.server.memory_link_graph()
                value = graph.navigate(
                    query.get("anchor", [""])[0],
                    direction=query.get("direction", ["both"])[0],
                    relations=query.get("relation", []),
                    trail=query.get("trail", []),
                    limit=int(query.get("limit", ["40"])[0]),
                    max_context_bytes=int(query.get("max_context_bytes", ["32768"])[0]),
                    cursor=query.get("cursor", [""])[0],
                )
            elif parsed.path == "/v1/seed/memory-links/context":
                graph = self.server.memory_link_graph()
                value = graph.context_pack(
                    query.get("anchor", [""])[0],
                    direction=query.get("direction", ["both"])[0],
                    relations=query.get("relation", []),
                    max_depth=int(query.get("max_depth", ["2"])[0]),
                    max_nodes=int(query.get("max_nodes", ["64"])[0]),
                    max_links=int(query.get("max_links", ["120"])[0]),
                    max_context_bytes=int(query.get("max_context_bytes", ["65536"])[0]),
                )
            else:
                self._send(
                    HTTPStatus.NOT_FOUND,
                    {"ok": False, "error": "unknown Integrity Seed endpoint"},
                )
                return
        except (SeedCatalogError, ValueError) as exc:
            self._send(
                HTTPStatus.BAD_REQUEST,
                {"ok": False, "error": str(exc), "production_authority": False},
            )
            return
        self._send(HTTPStatus.OK, value)


def serve_seed_runtime(
    *,
    catalog_path: Path,
    host: str = "127.0.0.1",
    port: int = 8775,
    evidence_root: Path | None = None,
    evidence_source_prefix: Path | None = None,
) -> None:
    if not 1 <= port <= 65535:
        raise SeedCatalogError("Integrity Seed runtime port is invalid")
    with SeedRuntimeServer(
        (host, port),
        catalog_path,
        evidence_root=evidence_root,
        evidence_source_prefix=evidence_source_prefix,
    ) as server:
        server.serve_forever(poll_interval=0.5)
