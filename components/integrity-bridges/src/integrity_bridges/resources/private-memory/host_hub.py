# SPDX-License-Identifier: Apache-2.0
"""Central Linux MCP routing for explicitly enrolled Codex hosts."""
from __future__ import annotations

from integrity_bridges.configuration import value as _integrity_value, require_config as _integrity_require_config
from integrity_bridges.transports import open_peer

import base64
import json
import os
from pathlib import Path

import unified_mcp as core
import claude_owner
from host_node import WRITES, Node, PeerClient

BASE_TOOLS = core.tool_definitions
BASE_CALL = core.call_tool


def scope(host, name, args):
    return [host, name, args.get("thread_id"), args.get("turn_id"), args.get("turn_limit", 8),
            args.get("search"), args.get("archived", False)]


def encode_cursor(identity, value):
    if value is None:
        return None
    payload = json.dumps([identity, value], ensure_ascii=True, separators=(",", ":")).encode()
    return "h1:" + base64.urlsafe_b64encode(payload).decode().rstrip("=")


def decode_cursor(identity, value):
    if value in (None, "0"):
        return value
    try:
        if not isinstance(value, str) or not value.startswith("h1:") or len(value) > 2048:
            raise ValueError
        encoded = value[3:]
        actual, inner = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        if actual != identity or not isinstance(inner, str):
            raise ValueError
        return inner
    except (ValueError, TypeError) as exc:
        raise core.RpcError("cursor_host_or_task_mismatch") from exc


class Hub:
    def __init__(self, config):
        self.config = config
        self.local = Node(config["local_host"], config["ledger"])
        self.peers = {}
        for host, entry in config["hosts"].items():
            peer = open_peer(host, entry, PeerClient)
            if peer is not None and entry.get("transport") != "local":
                self.peers[host] = peer

    def definitions(self):
        tools = BASE_TOOLS()
        for tool in tools:
            if not tool["name"].startswith("codex_"):
                continue
            schema = tool["inputSchema"]
            schema["properties"]["host_id"] = {"type": "string", "enum": list(self.config["hosts"]),
                "description": "Exact machine from codex_list_hosts. Never substitute another host after a failure."}
            schema.setdefault("required", []).append("host_id")
            if "cursor" in schema["properties"]:
                schema["properties"]["cursor"] = {"type": "string", "maxLength": 2048,
                    "description": "Opaque host-bound cursor returned by this tool, or 0."}
            if tool["name"] in WRITES:
                schema["properties"]["request_id"] = {"type": "string", "minLength": 8, "maxLength": 128,
                    "description": "Stable unique ID for this one operation. Reuse the same ID and identical arguments after a lost response; never blindly resend with a new ID."}
                schema["required"].append("request_id")
            tool["description"] = tool["description"].replace("local Codex", "selected host's Codex").replace("owner's Windows PC", "selected machine")
        tools.append({"name": "codex_operation_status", "title": "Inspect one Codex operation",
            "description": "Read the durable outcome for one exact request_id without retrying it. An acknowledged operation returns its stored response, including the exact turn_id. Reconcile that turn with codex_read_task before any new send.",
            "inputSchema": {"type": "object", "properties": {
                "host_id": {"type": "string", "enum": list(self.config["hosts"])},
                "request_id": {"type": "string", "minLength": 8, "maxLength": 128},
            }, "required": ["host_id", "request_id"], "additionalProperties": False},
            "annotations": {"readOnlyHint": True, "destructiveHint": False,
                            "openWorldHint": False}})
        tools.append({"name": "codex_list_hosts", "title": "List enrolled Codex machines",
            "description": "List enrolled machines, their configured routes and known limitations. Online status is established by a successful call to that machine, not by enrollment alone.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False}})
        claude_hosts = [host for host, entry in self.config["hosts"].items()
                        if entry.get("claude_enabled") is True]
        if claude_hosts:
            for tool in claude_owner.definitions():
                tool["inputSchema"]["properties"]["host_id"]["enum"] = claude_hosts
                tools.append(tool)
            tools.append({"name": "claude_list_hosts", "title": "List Claude task owners",
                "description": "List enrolled Claude owner hosts. Enrollment does not establish live availability.",
                "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
                "annotations": {"readOnlyHint": True, "destructiveHint": False,
                                "openWorldHint": False}})
        return tools

    def call(self, name, args):
        if name == "claude_list_hosts":
            if args:
                raise core.RpcError("unexpected_host_list_arguments")
            return self.pack({"hosts": [{"host_id": host, "label": entry["label"],
                "route": entry["transport"], "availability": "not_probed"}
                for host, entry in self.config["hosts"].items()
                if entry.get("claude_enabled") is True]})
        if name == "codex_list_hosts":
            if args:
                raise core.RpcError("unexpected_host_list_arguments")
            return self.pack({"central_host": self.config["local_host"], "hosts": [
                {"host_id": h, "label": c["label"], "route": c["transport"],
                 "availability": "disabled" if c["transport"] == "disabled" else "not_probed",
                 "reason": c.get("reason"), "clipboard": c.get("clipboard", False)}
                for h, c in self.config["hosts"].items()]})
        if not name.startswith(("codex_", "claude_")):
            return BASE_CALL(name, args)
        host = args.get("host_id")
        if host not in self.config["hosts"]:
            raise core.RpcError("explicit_enrolled_host_id_required")
        entry = self.config["hosts"][host]
        if name.startswith("claude_") and entry.get("claude_enabled") is not True:
            raise core.RpcError("claude_owner_not_enrolled_on_host")
        if entry["transport"] == "disabled":
            raise core.RpcError(f"host_unavailable:{host}:{entry['reason']}")
        if name == "codex_copy_turn" and not entry.get("clipboard"):
            raise core.RpcError("target_host_has_no_clipboard")
        forwarded = dict(args)
        forwarded.pop("host_id")
        request_id = forwarded.pop("request_id", None) if name in WRITES else None
        identity = scope(host, name, forwarded)
        if "cursor" in forwarded:
            forwarded["cursor"] = decode_cursor(identity, forwarded["cursor"])
        if host == self.config["local_host"]:
            # Node uses the original dispatcher, not the hub wrapper.
            result = self.local.call({"host_id": host, "name": name, "arguments": forwarded, "request_id": request_id})
        else:
            peer = self.peers.get(host)
            if peer is None:
                raise core.RpcError("host_transport_unavailable:" + str(entry.get("transport")))
            try:
                result = peer.call(name, forwarded, request_id)
            except Exception as exc:
                payload = getattr(exc, "payload", None)
                if isinstance(payload, dict):
                    raise core.RpcError(payload["error"] + ":" + str(payload.get("transport"))) from exc
                raise
        payload = result.get("structuredContent")
        if not isinstance(payload, dict):
            raise core.RpcError("invalid_host_result")
        payload = dict(payload)
        payload["host_id"] = host
        if "host" in payload:
            payload["host"] = host
        for key in ("cursor", "next_cursor"):
            if key in payload:
                payload[key] = encode_cursor(identity, payload[key])
        for task in payload.get("tasks", []):
            task["host_id"] = host
        return self.pack(payload)

    @staticmethod
    def pack(payload):
        return {"content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False)}], "structuredContent": payload}


def main():
    config = json.loads(Path(os.environ["INTEGRITY_HOSTS_FILE"]).read_text(encoding="utf-8"))
    hub = Hub(config)
    # Keep backend dispatch stable inside the local node while publishing hub functions.
    import host_node
    host_node.DISPATCH = BASE_CALL
    core.VERSION = "0.8.0"
    core.tool_definitions = hub.definitions
    core.call_tool = hub.call
    core.main()


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    main()
