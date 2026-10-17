#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Pure P2 ordering, partition, hash-chain, and ACK contracts."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import datetime as dt
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Iterable
from urllib.parse import quote

from memory_plane_common import canonical_json, sha256_bytes


ENVELOPE_PROTOCOL = "integrity-memory-plane.p2-envelope.v1"
BATCH_PROTOCOL = "integrity-memory-plane.p2-batch.v1"
ACK_PROTOCOL = "integrity-memory-plane.p2-ack.v1"
CURSOR_BUCKET_SIZE = 1_000_000
UID_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,200}$")


def _utc(value: str) -> dt.datetime:
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    return parsed.astimezone(dt.UTC)


def _component(value: str) -> str:
    cleaned = quote(value.strip(), safe="._-")
    if not cleaned or len(cleaned) > 120:
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
        cleaned = f"sha256-{digest}"
    return cleaned


def raw_partition_key(tenant_id: str, namespace: str, ts_utc: str, first_cursor: int, last_cursor: int, batch_sha256: str) -> str:
    when = _utc(ts_utc)
    if first_cursor < 1 or last_cursor < first_cursor:
        raise ValueError("invalid cursor range")
    if not re.fullmatch(r"[0-9a-f]{64}", batch_sha256):
        raise ValueError("invalid batch digest")
    bucket = first_cursor // CURSOR_BUCKET_SIZE
    return (
        f"raw/v1/tenant={_component(tenant_id)}/namespace={_component(namespace)}/"
        f"year={when:%Y}/month={when:%m}/day={when:%d}/cursor_bucket={bucket:012d}/"
        f"events-{first_cursor:020d}-{last_cursor:020d}-{batch_sha256}.ndjson.gz"
    )


@dataclass(frozen=True)
class Envelope:
    tenant_id: str
    namespace: str
    edge_id: str
    cursor: int
    event_uid: str
    ts_utc: str
    payload: dict[str, Any]
    source_manifest_sha256: str
    previous_envelope_sha256: str = ""

    def value(self) -> dict[str, Any]:
        if not self.tenant_id.strip() or not self.namespace.strip() or not self.edge_id.strip():
            raise ValueError("tenant, namespace and edge are required")
        if self.cursor < 1:
            raise ValueError("cursor must be positive")
        if not UID_RE.fullmatch(self.event_uid):
            raise ValueError("event_uid is required and must be bounded")
        _utc(self.ts_utc)
        for name, digest in (("source_manifest_sha256", self.source_manifest_sha256),):
            if not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ValueError(f"invalid {name}")
        if self.previous_envelope_sha256 and not re.fullmatch(r"[0-9a-f]{64}", self.previous_envelope_sha256):
            raise ValueError("invalid previous envelope digest")
        payload_bytes = canonical_json(self.payload)
        unsigned = {
            "protocol": ENVELOPE_PROTOCOL,
            "tenant_id": self.tenant_id,
            "namespace": self.namespace,
            "edge_id": self.edge_id,
            "cursor": self.cursor,
            "event_uid": self.event_uid,
            "ts_utc": _utc(self.ts_utc).isoformat(),
            "payload_sha256": sha256_bytes(payload_bytes),
            "source_manifest_sha256": self.source_manifest_sha256,
            "previous_envelope_sha256": self.previous_envelope_sha256,
        }
        digest = sha256_bytes(canonical_json(unsigned) + payload_bytes)
        return {**unsigned, "envelope_sha256": digest, "payload": self.payload}


def build_batch(envelopes: Iterable[Envelope], previous_batch_sha256: str = "") -> dict[str, Any]:
    values = [item.value() for item in envelopes]
    if not values:
        raise ValueError("batch cannot be empty")
    if previous_batch_sha256 and not re.fullmatch(r"[0-9a-f]{64}", previous_batch_sha256):
        raise ValueError("invalid previous batch digest")
    identity = {(value["tenant_id"], value["namespace"], value["edge_id"]) for value in values}
    if len(identity) != 1:
        raise ValueError("a batch cannot cross an ordered edge stream")
    cursors = [int(value["cursor"]) for value in values]
    if cursors != sorted(cursors) or len(set(cursors)) != len(cursors):
        raise ValueError("batch cursors must be unique and ascending")
    uids: dict[str, str] = {}
    for value in values:
        prior = uids.setdefault(value["event_uid"], value["payload_sha256"])
        if prior != value["payload_sha256"]:
            raise ValueError("event_uid payload collision")
    for previous, current in zip(values, values[1:]):
        if current["previous_envelope_sha256"] != previous["envelope_sha256"]:
            raise ValueError("envelope hash chain is not contiguous")
    ordered_digest = sha256_bytes(b"".join(canonical_json(value) for value in values))
    tenant_id, namespace, edge_id = next(iter(identity))
    manifest = {
        "protocol": BATCH_PROTOCOL,
        "tenant_id": tenant_id,
        "namespace": namespace,
        "edge_id": edge_id,
        "first_cursor": cursors[0],
        "last_cursor": cursors[-1],
        "event_count": len(values),
        "first_ts_utc": values[0]["ts_utc"],
        "last_ts_utc": values[-1]["ts_utc"],
        "ordered_envelopes_sha256": ordered_digest,
        "previous_batch_sha256": previous_batch_sha256,
    }
    batch_sha256 = sha256_bytes(canonical_json(manifest))
    return {
        **manifest,
        "batch_sha256": batch_sha256,
        "object_key": raw_partition_key(tenant_id, namespace, values[0]["ts_utc"], cursors[0], cursors[-1], batch_sha256),
        "envelopes": values,
        "production_authority": False,
        "memory_grants_authority": False,
    }


def ack_decision(*, chain_contiguous: bool, worm_primary_readback: bool, bus_replicas: int, bus_fault_domains: int, offhost_readback: bool, uid_collision_count: int, shadow_mode: bool = True) -> dict[str, Any]:
    checks = {
        "chain_contiguous": bool(chain_contiguous),
        "worm_primary_readback": bool(worm_primary_readback),
        "bus_quorum_replicas_at_least_3": int(bus_replicas) >= 3,
        "bus_fault_domains_at_least_2": int(bus_fault_domains) >= 2,
        "offhost_readback": bool(offhost_readback),
        "uid_collision_zero": int(uid_collision_count) == 0,
    }
    durable = all(checks.values())
    production_ack = durable and not shadow_mode
    return {
        "protocol": ACK_PROTOCOL,
        "status": "SHADOW_DURABLE" if durable and shadow_mode else "PRODUCTION_ACK" if production_ack else "NOT_ACKED",
        "checks": checks,
        "shadow_mode": shadow_mode,
        "rpo_zero_after_this_ack": production_ack,
        "production_authority": False,
        "memory_grants_authority": False,
    }

