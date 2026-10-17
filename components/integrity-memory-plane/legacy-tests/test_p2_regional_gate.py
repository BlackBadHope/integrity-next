from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import p2_regional_gate as gate  # noqa: E402


def node(name: str, host: str, storage: str, region: str, *, primary: bool = False) -> dict:
    return {
        "node_id": name,
        "nats_server_name": name,
        "host_domain": host,
        "power_domain": host + "-power",
        "storage_domain": storage,
        "region": region,
        "regional_attested": True,
        "primary_object_store": primary,
        "remote_host_aliases": [name.upper()],
    }


def topology() -> dict:
    return {
        "protocol": gate.TOPOLOGY_PROTOCOL,
        "production_authority": False,
        "memory_grants_authority": False,
        "nodes": [
            node("n1", "h1", "s1", "r1", primary=True),
            node("n2", "h2", "s2", "r2"),
            node("n3", "h3", "s3", "r2"),
        ],
    }


def jsz(replicas: int = 3) -> dict:
    return {
        "account_details": [{
            "stream_detail": [{
                "name": "INTEGRITY_P2_RAW",
                "config": {"num_replicas": replicas},
                "cluster": {
                    "leader": "n1",
                    "replicas": [
                        {"name": "n2", "current": True, "offline": False, "lag": 0},
                        {"name": "n3", "current": True, "offline": False, "lag": 0},
                    ] if replicas == 3 else [],
                },
            }]
        }]
    }


def offhost() -> dict:
    return {
        "protocol": "integrity-memory-plane.p2-offhost-client.v1.state",
        "remote_host": "N2",
        "production_authority": False,
        "memory_grants_authority": False,
        "checks": {"outer_digest_readback": True, "all_inventory_files_readback": True},
    }


def failover() -> dict:
    return {
        "protocol": gate.FAILOVER_PROTOCOL,
        "status": "PASS",
        "production_authority": False,
        "rpo_after_ack_events": 0,
        "rto_seconds": 600,
        "source_authority_fenced": True,
        "independent_readback": True,
    }


def billion() -> dict:
    return {
        "protocol": gate.BILLION_PROTOCOL,
        "status": "PASS",
        "production_authority": False,
        "sparse_or_extrapolated": False,
        "metrics": {
            "physical_events": 1_000_000_000,
            "bootstrap_p95_seconds": 0.8,
            "retrieval_p95_seconds": 1.7,
            "exact_lookup_complexity": "O(log N)",
            "causal_path_recall_at_20": 0.96,
            "authority_boundary_recall": 1.0,
            "context_capsule_bytes": 16384,
        },
    }


class P2RegionalGateTests(unittest.TestCase):
    def test_complete_evidence_is_precondition_pass_but_never_authority(self) -> None:
        result = gate.evaluate(topology(), jsz(), offhost(), failover(), billion(), stream_name="INTEGRITY_P2_RAW")
        self.assertEqual("PASS", result["status"])
        self.assertTrue(result["transition_preconditions_observed"])
        self.assertFalse(result["migration_authority_allowed"])
        self.assertFalse(result["production_authority"])

    def test_r1_and_missing_receipts_are_red(self) -> None:
        result = gate.evaluate(topology(), jsz(1), offhost(), None, None, stream_name="INTEGRITY_P2_RAW")
        self.assertEqual("FAIL", result["status"])
        self.assertIn("bus_replicas_at_least_3", result["blockers"])
        self.assertIn("regional_failover_rpo_rto_proven", result["blockers"])
        self.assertIn("physical_billion_event_agent_gate_proven", result["blockers"])

    def test_unknown_region_cannot_be_counted(self) -> None:
        value = copy.deepcopy(topology())
        for item in value["nodes"]:
            item["region"] = "unknown"
            item["regional_attested"] = False
        result = gate.evaluate(value, jsz(), offhost(), failover(), billion(), stream_name="INTEGRITY_P2_RAW")
        self.assertIn("bus_attested_regions_at_least_2", result["blockers"])
        self.assertIn("object_attested_regions_at_least_2", result["blockers"])

    def test_stale_replica_does_not_count_as_live_domain(self) -> None:
        observed = jsz()
        observed["account_details"][0]["stream_detail"][0]["cluster"]["replicas"][1]["lag"] = 1
        result = gate.evaluate(topology(), observed, offhost(), failover(), billion(), stream_name="INTEGRITY_P2_RAW")
        self.assertIn("bus_live_current_nodes_at_least_3", result["blockers"])
        self.assertIn("bus_unique_host_domains_at_least_3", result["blockers"])

    def test_server_alias_maps_to_same_physical_domain(self) -> None:
        value = topology()
        value["nodes"][0]["nats_server_aliases"] = ["n1-canary"]
        observed = jsz()
        observed["account_details"][0]["stream_detail"][0]["cluster"]["leader"] = "n1-canary"
        result = gate.evaluate(value, observed, offhost(), failover(), billion(), stream_name="INTEGRITY_P2_RAW")
        self.assertEqual("PASS", result["status"])
        self.assertEqual(["h1", "h2", "h3"], result["bus"]["host_domains"])


if __name__ == "__main__":
    unittest.main()
