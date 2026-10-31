"""Add the lab UI to the pinned owner hub using the official MCP wire server.

Existing hub definitions and dispatch are reused verbatim. This module does not
create an executor route, read its transcripts, or modify its operation ledger.
The hub's ordinary constructor retains its existing startup/schema behaviour.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib
import json
import os
import re
import sys
import threading
from functools import partial
from pathlib import Path

import anyio
from mcp.server.mcpserver import MCPServer
from mcp.types import CallToolResult, Tool

from .backend import Backend, private_path
from .server import create_server, http_app

UI_NAMES = frozenset({"integrity_projects", "integrity_project", "integrity_task",
                      "integrity_context", "integrity_source"})
HUB_FILES = frozenset({"host_hub.py", "host_node.py", "unified_mcp.py",
                       "claude_owner.py", "ping_pong.py", "unix_ws_stdio.py"})
SERIALIZED_WRITES = frozenset({"codex_send_prompt", "codex_interrupt_turn",
    "codex_archive_task", "codex_unarchive_task", "codex_copy_turn"})


class HubServer(MCPServer):
    """Public SDK list/call overrides; old business dispatch stays authoritative."""

    def __init__(self, *args, hub, core, **kwargs):
        self.hub, self.core = hub, core
        self._old_definitions = None
        self._definition_lock = threading.Lock()
        self._write_lock = threading.Lock()
        self._capacity = threading.BoundedSemaphore(8)
        super().__init__(*args, **kwargs)

    def old_definitions(self):
        with self._definition_lock:
            if self._old_definitions is None:
                definitions = self.hub.definitions()
                names = [item["name"] for item in definitions]
                if len(set(names)) != len(names) or UI_NAMES.intersection(names):
                    raise ValueError("existing hub tool name collision")
                self._old_definitions = copy.deepcopy(definitions)
            return copy.deepcopy(self._old_definitions)

    async def list_tools(self):
        definitions = await anyio.to_thread.run_sync(self.old_definitions)
        return [Tool.model_validate(item) for item in definitions] + await super().list_tools()

    async def call_tool(self, name, arguments, context=None):
        if name in UI_NAMES:
            return await super().call_tool(name, arguments, context)
        definitions = await anyio.to_thread.run_sync(self.old_definitions)
        if name not in {item["name"] for item in definitions}:
            return await super().call_tool(name, arguments, context)
        # No rewriting of host/task/turn/request IDs, model choices or arguments.
        try:
            def dispatch():
                with self._capacity:
                    if name in SERIALIZED_WRITES:
                        with self._write_lock:
                            return self.hub.call(name, arguments)
                    return self.hub.call(name, arguments)
            result = await anyio.to_thread.run_sync(dispatch)
        except self.core.RpcError as exc:
            result = self.core.tool_error_result(exc)
        return CallToolResult.model_validate(result)


def load_hub(manifest_path: Path, config_path: Path):
    """Admit exact installed source bytes; paths never come from an MCP caller."""
    private_path(manifest_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    directory = Path(manifest["directory"])
    members = manifest.get("files")
    if (not directory.is_absolute() or not isinstance(members, dict)
            or not HUB_FILES <= set(members) or not 6 <= len(members) <= 64
            or any(not isinstance(name, str) or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*\.py", name) is None
                   for name in members)):
        raise ValueError("invalid pinned hub manifest")
    private_path(directory, directory=True)
    if {path.name for path in directory.glob("*.py")} != set(members):
        raise ValueError("unpinned hub source present")
    for name, digest in members.items():
        path = directory / name
        if (not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None
                or path.is_symlink() or not path.is_file()
                or hashlib.sha256(path.read_bytes()).hexdigest() != digest):
            raise ValueError("pinned hub source changed")
    private_path(config_path)
    sys.path.insert(0, str(directory))
    module = importlib.import_module("host_hub")
    if Path(module.__file__).resolve() != (directory / "host_hub.py").resolve():
        raise ValueError("wrong hub module loaded")
    for name in members:
        loaded = sys.modules.get(Path(name).stem)
        if loaded is not None and Path(loaded.__file__).resolve() != (directory / name).resolve():
            raise ValueError("wrong hub dependency loaded")
    config = json.loads(config_path.read_text(encoding="utf-8"))
    hub = module.Hub(config)
    import host_node
    host_node.DISPATCH = module.BASE_CALL
    return hub, module.core


def main(*, workbench: bool = True):
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--hub-manifest", required=True, type=Path)
    parser.add_argument("--hosts-config", type=Path,
                        default=os.environ.get("INTEGRITY_HOSTS_FILE"))
    parser.add_argument("--transport", choices=["stdio", "http"], default="stdio")
    parser.add_argument("--port", type=int, default=8791)
    parser.add_argument("--token-file", type=Path)
    parser.add_argument(
        "--server-name",
        default=None,
        help="advertised MCP server name; deprecated aliases are accepted",
    )
    args = parser.parse_args()
    if args.hosts_config is None:
        parser.error("existing owner hosts config required")
    os.umask(0o077)
    backend = Backend(args.config)
    backend.projects()  # Reject a private namespace before exposing any UI.
    hub, core = load_hub(args.hub_manifest, args.hosts_config)
    if workbench:
        from .workspace_backend import WorkspaceBackend
        backend = WorkspaceBackend(backend, hub)
    import warnings

    from integrity_bridges.server_names import SEATS_BRIDGE, ServerNameError, resolve_server_name

    requested = args.server_name
    if requested is None and args.hosts_config is not None:
        try:
            hosts_document = json.loads(args.hosts_config.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            hosts_document = None
        if isinstance(hosts_document, dict) and isinstance(hosts_document.get("server_name"), str):
            requested = hosts_document["server_name"]
    try:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", DeprecationWarning)
            server_name = resolve_server_name(requested, canonical=SEATS_BRIDGE)
    except ServerNameError as err:
        parser.error(str(err))
    for item in caught:
        print(item.message, file=sys.stderr)
    server = create_server(backend, server_factory=partial(HubServer, hub=hub, core=core),
        name=server_name, version="0.2.0",
        ui_mode="workbench" if workbench else "lab",
        instructions=("Existing owner memory and host routes retain their permissions and exact request IDs. "
            "Host writes require the owner's explicit instruction; reconcile unknown outcomes before any new send. "
            "The workbench reads explicitly enrolled hosts and existing task responses. "
            "It does not dispatch work or certify completion. Lab tools retain their own checks."))
    if args.transport == "stdio":
        server.run()
    else:
        if args.token_file is None:
            parser.error("HTTP requires --token-file")
        import uvicorn
        uvicorn.run(http_app(server, backend, args.token_file, ui_mode="workbench" if workbench else "lab"),
                    host="127.0.0.1", port=args.port, access_log=False, log_level="warning")


if __name__ == "__main__":
    main()
