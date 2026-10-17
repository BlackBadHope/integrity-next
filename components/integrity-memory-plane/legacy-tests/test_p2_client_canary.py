from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import p2_client_canary_bootstrap as canary  # noqa: E402


class P2clientCanaryTests(unittest.TestCase):
    def test_env_shape_is_exact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "node.env"
            path.write_text("".join(f"{key}=value-{index}\n" for index, key in enumerate(canary.REQUIRED_ENV)), encoding="ascii")
            self.assertEqual(set(canary.REQUIRED_ENV), set(canary.load_env(path)))
            path.write_text(path.read_text(encoding="ascii") + "EXTRA=forbidden\n", encoding="ascii")
            with self.assertRaises(RuntimeError):
                canary.load_env(path)

    def test_linux_config_is_loopback_and_non_production(self) -> None:
        values = {key: "safevalue" + str(index) for index, key in enumerate(canary.REQUIRED_ENV)}
        config = canary.render_linux_config(values)
        self.assertIn('host: "127.0.0.1"', config)
        self.assertIn("port: 14222", config)
        self.assertIn("port: 16222", config)
        self.assertIn("127.0.0.1:26223", config)
        self.assertNotIn("0.0.0.0", config)
        self.assertNotIn("INTEGRITY_P2_RAW", config)

    def test_official_windows_asset_digest_is_pinned(self) -> None:
        self.assertEqual(64, len(canary.ARCHIVE_SHA256))
        self.assertIn("v2.11.8", canary.ARCHIVE_URL)


if __name__ == "__main__":
    unittest.main()
