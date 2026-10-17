from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import p2_regional_canary_verify as canary  # noqa: E402


class P2RegionalCanaryVerifyTests(unittest.TestCase):
    def test_stream_contract_is_r2_canary_not_production(self) -> None:
        config = canary.expected_config()
        self.assertEqual(2, config.num_replicas)
        self.assertEqual("canary", config.metadata["integrity.mode"])
        self.assertEqual("false", config.metadata["integrity.production_authority"])
        self.assertTrue(config.deny_delete)
        self.assertTrue(config.deny_purge)

    def test_only_current_zero_lag_replicas_count(self) -> None:
        info = SimpleNamespace(cluster=SimpleNamespace(
            leader="integrity-p2-canary-linux-1",
            replicas=[SimpleNamespace(name="integrity-p2-client-1", current=True, offline=False, lag=0)],
        ))
        nodes, _ = canary.cluster_nodes(info)
        self.assertEqual(canary.EXPECTED_NODES, nodes)
        info.cluster.replicas[0].lag = 1
        nodes, _ = canary.cluster_nodes(info)
        self.assertNotEqual(canary.EXPECTED_NODES, nodes)


if __name__ == "__main__":
    unittest.main()
