#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail closed until P2 has real multi-domain and billion-history evidence."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import json
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from memory_plane_common import atomic_json, canonical_json, sha256_bytes


PROTOCOL = "integrity-memory-plane.p2-regional-gate.v1"
TOPOLOGY_PROTOCOL = "integrity-memory-plane.p2-fault-domains.v1"
FAILOVER_PROTOCOL = "integrity-memory-plane.p2-regional-failover.v1.receipt"
BILLION_PROTOCOL = "integrity-memory-plane.p2-billion-bootstrap.v1.receipt"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"JSON root is not an object: {path}")
    return value


def stream_detail(jsz: dict[str, Any], stream_name: str) -> dict[str, Any] | None:
    for account in jsz.get("account_details", []):
        for stream in account.get("stream_detail", []):
            if stream.get("name") == stream_name:
                return stream
    return None


def nodes_by_name(topology: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if topology.get("protocol") != TOPOLOGY_PROTOCOL:
        raise RuntimeError("untrusted fault-domain topology protocol")
    if topology.get("production_authority") is not False or topology.get("memory_grants_authority") is not False:
        raise RuntimeError("fault-domain topology claims authority")
    result: dict[str, dict[str, Any]] = {}
    for node in topology.get("nodes", []):
        required = ("node_id", "nats_server_name", "host_domain", "power_domain", "storage_domain", "region")
        if not isinstance(node, dict) or any(not str(node.get(key) or "").strip() for key in required):
            raise RuntimeError("fault-domain node is incomplete")
        names = [str(node["nats_server_name"]), *(str(value) for value in node.get("nats_server_aliases", []))]
        for name in names:
            if not name or name in result:
                raise RuntimeError(f"duplicate/empty NATS server mapping: {name}")
            result[name] = node
    return result


def live_bus_nodes(stream: dict[str, Any]) -> tuple[list[str], list[dict[str, Any]]]:
    cluster = stream.get("cluster") or {}
    leader = str(cluster.get("leader") or "")
    nodes = [leader] if leader else []
    replicas: list[dict[str, Any]] = []
    for replica in cluster.get("replicas") or []:
        value = {
            "name": str(replica.get("name") or ""),
            "current": replica.get("current") is True,
            "offline": replica.get("offline") is True,
            "lag": int(replica.get("lag") or 0),
        }
        replicas.append(value)
        if value["name"] and value["current"] and not value["offline"] and value["lag"] == 0:
            nodes.append(value["name"])
    return sorted(set(nodes)), replicas


def aliases(node: dict[str, Any]) -> set[str]:
    return {str(value).upper() for value in node.get("remote_host_aliases", [])}


def valid_offhost(offhost: dict[str, Any] | None) -> bool:
    if not offhost or offhost.get("protocol") != "integrity-memory-plane.p2-offhost-client.v1.state":
        return False
    checks = offhost.get("checks") or {}
    return (
        offhost.get("production_authority") is False
        and offhost.get("memory_grants_authority") is False
        and bool(checks)
        and all(value is True for value in checks.values())
    )


def valid_failover(receipt: dict[str, Any] | None) -> bool:
    return bool(
        receipt
        and receipt.get("protocol") == FAILOVER_PROTOCOL
        and receipt.get("status") == "PASS"
        and receipt.get("production_authority") is False
        and int(receipt.get("rpo_after_ack_events", -1)) == 0
        and 0 <= float(receipt.get("rto_seconds", float("inf"))) <= 900
        and receipt.get("source_authority_fenced") is True
        and receipt.get("independent_readback") is True
    )


def valid_billion(receipt: dict[str, Any] | None) -> bool:
    if not receipt or receipt.get("protocol") != BILLION_PROTOCOL or receipt.get("status") != "PASS":
        return False
    metrics = receipt.get("metrics") or {}
    capsule = int(metrics.get("context_capsule_bytes", -1))
    return bool(
        receipt.get("production_authority") is False
        and int(metrics.get("physical_events", -1)) >= 1_000_000_000
        and float(metrics.get("bootstrap_p95_seconds", float("inf"))) <= 1.0
        and float(metrics.get("retrieval_p95_seconds", float("inf"))) <= 2.0
        and str(metrics.get("exact_lookup_complexity") or "") in {"O(log N)", "O(1)"}
        and float(metrics.get("causal_path_recall_at_20", -1)) >= 0.95
        and float(metrics.get("authority_boundary_recall", -1)) == 1.0
        and 8192 <= capsule <= 32768
        and receipt.get("sparse_or_extrapolated") is False
    )


def evaluate(
    topology: dict[str, Any],
    jsz: dict[str, Any],
    offhost: dict[str, Any] | None,
    failover: dict[str, Any] | None,
    billion: dict[str, Any] | None,
    *,
    stream_name: str,
) -> dict[str, Any]:
    mapped = nodes_by_name(topology)
    stream = stream_detail(jsz, stream_name)
    if stream is None:
        raise RuntimeError(f"JetStream monitor has no stream {stream_name}")
    names, replicas = live_bus_nodes(stream)
    unknown = sorted(name for name in names if name not in mapped)
    active = [mapped[name] for name in names if name in mapped]
    host_domains = sorted({str(node["host_domain"]) for node in active})
    power_domains = sorted({str(node["power_domain"]) for node in active if node["power_domain"] != "unknown"})
    regions = sorted({str(node["region"]) for node in active if node.get("regional_attested") is True and node["region"] != "unknown"})

    offhost_ok = valid_offhost(offhost)
    object_nodes = [node for node in topology.get("nodes", []) if node.get("primary_object_store") is True]
    if offhost_ok:
        remote = str(offhost.get("remote_host") or "").upper()
        object_nodes.extend(node for node in topology.get("nodes", []) if remote in aliases(node))
    object_storage_domains = sorted({str(node["storage_domain"]) for node in object_nodes})
    object_regions = sorted({str(node["region"]) for node in object_nodes if node.get("regional_attested") is True and node["region"] != "unknown"})

    configured_replicas = int((stream.get("config") or {}).get("num_replicas") or 0)
    checks = {
        "bus_replicas_at_least_3": configured_replicas >= 3,
        "bus_live_current_nodes_at_least_3": len(names) >= 3,
        "bus_nodes_all_mapped": not unknown,
        "bus_unique_host_domains_at_least_3": len(host_domains) >= 3,
        "bus_known_power_domains_at_least_2": len(power_domains) >= 2,
        "bus_attested_regions_at_least_2": len(regions) >= 2,
        "offhost_worm_readback_proven": offhost_ok,
        "object_storage_domains_at_least_2": len(object_storage_domains) >= 2,
        "object_attested_regions_at_least_2": len(object_regions) >= 2,
        "regional_failover_rpo_rto_proven": valid_failover(failover),
        "physical_billion_event_agent_gate_proven": valid_billion(billion),
    }
    blockers = sorted(name for name, passed in checks.items() if not passed)
    evidence = {
        "protocol": PROTOCOL + ".evidence",
        "created_utc": utc_now(),
        "status": "PASS" if not blockers else "FAIL",
        "checks": checks,
        "blockers": blockers,
        "bus": {
            "stream": stream_name,
            "configured_replicas": configured_replicas,
            "leader": (stream.get("cluster") or {}).get("leader"),
            "live_current_nodes": names,
            "replicas": replicas,
            "unknown_nodes": unknown,
            "host_domains": host_domains,
            "known_power_domains": power_domains,
            "attested_regions": regions,
        },
        "object": {
            "offhost_remote": (offhost or {}).get("remote_host"),
            "storage_domains": object_storage_domains,
            "attested_regions": object_regions,
        },
        "regional_failover_receipt_present": failover is not None,
        "billion_bootstrap_receipt_present": billion is not None,
        "transition_preconditions_observed": not blockers,
        "migration_authority_allowed": False,
        "production_authority": False,
        "memory_grants_authority": False,
    }
    evidence["evidence_sha256"] = sha256_bytes(canonical_json(evidence))
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--topology", type=Path, default=Path("/etc/integrity-memory-p2/p2-fault-domains.json"))
    parser.add_argument("--nats-monitor", default=_integrity_value('endpoint_37a28bd31428'))
    parser.add_argument("--stream", default="INTEGRITY_P2_RAW")
    parser.add_argument("--offhost-state", type=Path, default=Path(_integrity_value('path_d91576ab5b73')))
    parser.add_argument("--failover-receipt", type=Path, default=Path(_integrity_value('path_c1a60a74857f')))
    parser.add_argument("--billion-receipt", type=Path, default=Path(_integrity_value('path_51a568597975')))
    parser.add_argument("--receipt-root", type=Path, default=Path(_integrity_value('path_0feb606df08b')))
    args = parser.parse_args()
    topology = load_json(args.topology)
    if topology is None:
        raise RuntimeError("fault-domain topology is missing")
    with urllib.request.urlopen(args.nats_monitor.rstrip("/") + "/jsz?streams=true&config=true", timeout=5) as response:
        jsz = json.load(response)
    result = evaluate(
        topology,
        jsz,
        load_json(args.offhost_state),
        load_json(args.failover_receipt),
        load_json(args.billion_receipt),
        stream_name=args.stream,
    )
    args.receipt_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = args.receipt_root / f"regional-gate-{stamp}-{result['evidence_sha256'][:16]}.json"
    atomic_json(path, result, mode=0o440)
    print(json.dumps({**result, "receipt_path": str(path)}, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "PASS" else 2


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    sys.exit(main())
