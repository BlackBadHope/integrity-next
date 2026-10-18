"""The portable advice profile must not implicitly activate a host integration."""
from contextlib import ExitStack
import importlib
import unittest
from unittest.mock import patch


def no_host_effects():
    guards = ExitStack()
    for target in ("socket.socket", "socket.create_connection", "subprocess.Popen", "os.system"):
        guards.enter_context(patch(target, side_effect=AssertionError("unexpected-host-effect")))
    return guards


class PortableHostBoundaryTests(unittest.TestCase):
    def test_a_all_portable_modules_import_without_network_or_processes(self):
        with no_host_effects():
            package = importlib.import_module("integrity_resource_advisor")
            for name in ("core", "metering", "native", "codex", "app_server_snapshot",
                         "rollout_usage", "__main__"):
                importlib.import_module("integrity_resource_advisor." + name)
        self.assertEqual(package.__version__, "0.1.0rc6")

    def test_b_synthetic_advice_does_not_activate_http_or_native_process(self):
        with no_host_effects():
            cli = importlib.import_module("integrity_resource_advisor.__main__")
            result = cli.demos()
        self.assertIs(result["synthetic"], True)
        self.assertIsNone(result["measured_savings"])
        self.assertTrue(result["cases"])
        self.assertEqual(result["cases"]["unknown-outcome"]["status"], "RECONCILE_REQUIRED")


if __name__ == "__main__":
    unittest.main()
