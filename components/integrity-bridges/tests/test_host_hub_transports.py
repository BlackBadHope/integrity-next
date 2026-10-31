"""Transport adapters fail closed, and no generic exec tool is exposed."""
import re
from pathlib import Path

import pytest

from integrity_bridges.canonical import CANONICAL_RESOURCES, LINEAGE
from integrity_bridges.configuration import ConfigurationError, configured_command
from integrity_bridges.transports import TransportError, encode_request, open_peer


ROOT = Path(__file__).resolve().parents[1]


def test_unknown_transport_is_not_a_keyerror():
    assert open_peer("host-a", {"transport": "carrier-pigeon"}, lambda *_args: None) is None
    adapter = open_peer("host-a", {"transport": "webhook"}, lambda *_args: None)
    with pytest.raises(TransportError) as raised:
        adapter.call("codex_ping", {"thread_id": "thread-1"})
    assert raised.value.payload["error"] == "host_transport_unavailable"
    assert raised.value.payload["transport"] == "webhook"
    line = encode_request("codex_ping", {"thread_id": "thread-1"}, "request-1")
    assert line.endswith(b"\n")
    assert line.count(b"\n") == 1


def test_lineage_points_at_private_memory():
    assert LINEAGE == "0.8.0"
    assert CANONICAL_RESOURCES == "resources/private-memory"
    assert (ROOT / "src/integrity_bridges" / CANONICAL_RESOURCES / "host_hub.py").is_file()
    assert (ROOT / "src/integrity_bridges/resources/hub/host_hub.py").is_file()


def test_legacy_command_key_is_a_deprecated_alias(tmp_path, monkeypatch):
    config = tmp_path / "config.json"
    config.write_text(
        '{"schema":"integrity/component-config/v1","component":"integrity-bridges",'
        '"configured":true,"guardian_version":"6.1.0","memory_api_version":"2.11.0",'
        '"values":{"command_b734f1f83ce5":"python -m example"}}',
        encoding="utf-8",
    )
    monkeypatch.setenv("INTEGRITY_BRIDGES_CONFIG", str(config))
    with pytest.warns(DeprecationWarning, match="deprecated"):
        assert configured_command("upstream_mcp_command", "command_b734f1f83ce5") == "python -m example"
    config.write_text(
        '{"schema":"integrity/component-config/v1","component":"integrity-bridges",'
        '"configured":true,"guardian_version":"6.1.0","memory_api_version":"2.11.0",'
        '"values":{}}',
        encoding="utf-8",
    )
    with pytest.raises(ConfigurationError):
        configured_command("upstream_mcp_command", "command_b734f1f83ce5")


def test_no_generic_exec_tool_is_exposed():
    forbidden = {"exec", "shell", "run_command", "bash", "system", "host_exec"}
    for relative in (
        "src/integrity_bridges/resources/private-memory/host_hub.py",
        "src/integrity_bridges/resources/hub/host_hub.py",
        "src/integrity_bridges/resources/private-memory/unified_mcp.py",
        "src/integrity_bridges/resources/hub/unified_mcp.py",
    ):
        text = (ROOT / relative).read_text(encoding="utf-8")
        names = set(re.findall(r'"name":\s*"([^"]+)"', text))
        assert names.isdisjoint(forbidden)
        assert "self.peers[host].call" not in text
