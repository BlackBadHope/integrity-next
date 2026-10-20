"""Independently launch a generated config and check actual MCP read behavior."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import threading
import queue
import tomllib
from pathlib import Path


def verify(path: Path) -> dict:
    if path.suffix == ".toml":
        entry = tomllib.loads(path.read_text(encoding="utf-8"))["mcp_servers"]["integrity_local_example"]
    else:
        entry = json.loads(path.read_text(encoding="utf-8"))["mcpServers"]["integrity_local_example"]
    catalog = Path(entry["args"][entry["args"].index("--catalog") + 1])
    before = hashlib.sha256(catalog.read_bytes()).hexdigest()
    process = subprocess.Popen([entry["command"], *entry["args"]], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")
    responses = queue.Queue()
    def read():
        for line in process.stdout:
            responses.put(line)
        responses.put(None)
    threading.Thread(target=read, daemon=True).start()
    counter = 0
    def rpc(method, params):
        nonlocal counter
        counter += 1
        process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": counter,
                                        "method": method, "params": params}) + "\n")
        process.stdin.flush()
        line = responses.get(timeout=30)
        assert line is not None, "server exited before response"
        result = json.loads(line)
        assert result["id"] == counter
        return result
    def call(name, args):
        result = rpc("tools/call", {"name": name, "arguments": args})
        assert "error" not in result, result
        value = result["result"]
        assert not value.get("isError"), value
        return json.loads(value["content"][0]["text"])
    try:
        initialized = rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                                         "clientInfo": {"name": "independent-example-check", "version": "1"}})
        assert initialized["result"]["serverInfo"]["name"] == "integrity-local-readonly-example"
        listed = rpc("tools/list", {})["result"]["tools"]
        names = {t["name"] for t in listed}
        assert len(names) == 4 and "integrity_append_event" not in names
        call("integrity_memory_capabilities", {})
        snapshot = call("integrity_seed_snapshot", {})
        sid = snapshot["snapshot_id"]
        found = call("integrity_seed_event_uid", {"event_uid": "client:public-remote-timeout-decision", "snapshot_id": sid})
        assert found["outcome"] == "found" and found["event"]["id"] == 1
        assert found["event"]["details"]["decision"]["tool_timeout_sec"] == 210
        recalled = call("integrity_seed_recall", {"query": "remote broker", "limit": 5, "snapshot_id": sid})
        assert any(row["event_id"] == 1 for row in recalled["events"])
        missing = call("integrity_seed_event_uid", {"event_uid": "client:does-not-exist", "snapshot_id": sid})
        assert missing["outcome"] == "not-found"
        refused = rpc("tools/call", {"name": "integrity_append_event", "arguments": {}})
        assert "error" in refused
        foreign = rpc("tools/call", {"name": "integrity_seed_event_uid", "arguments": {
            "event_uid": "client:public-remote-timeout-decision", "snapshot_id": "sha256:" + "0"*64}})
        assert "error" in foreign or foreign.get("result", {}).get("isError") is True
    finally:
        process.stdin.close()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    assert process.returncode == 0
    assert hashlib.sha256(catalog.read_bytes()).hexdigest() == before
    return {"config": path.name, "status": "PASS", "checks": ["discovery", "exact-found", "ranked-recall",
            "exact-not-found", "append-refused", "foreign-snapshot-refused", "catalog-unchanged"],
            "vendor_client_executed": False, "catalog_sha256": before}


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("configs", type=Path, nargs="+")
    a = p.parse_args()
    print(json.dumps([verify(path) for path in a.configs], indent=2))


if __name__ == "__main__":
    main()
