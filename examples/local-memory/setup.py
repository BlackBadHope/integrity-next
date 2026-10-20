"""Generate complete, isolated MCP configs for this example; no active files are changed."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--catalog", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    catalog = a.catalog.resolve(strict=True)
    output = a.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    command = str(Path(sys.executable).resolve())
    args = [str(Path(__file__).with_name("memory_server.py").resolve()),
            "--catalog", str(catalog), "--snapshots", str(output / "private-snapshots")]
    entry = {"command": command, "args": args}
    for name in ("claude.mcp.json", "antigravity.mcp.json"):
        (output / name).write_text(json.dumps({"mcpServers": {"integrity_local_example": entry}},
                                             indent=2) + "\n", encoding="utf-8")
    # JSON quoted strings/arrays are valid TOML basic strings/arrays here.
    toml = ("[mcp_servers.integrity_local_example]\ncommand = " + json.dumps(command)
            + "\nargs = " + json.dumps(args) + "\nstartup_timeout_sec = 30\ntool_timeout_sec = 60\n")
    (output / "codex.config.toml").write_text(toml, encoding="utf-8")
    codex_project = output / "codex-workspace" / ".codex"
    codex_project.mkdir(parents=True)
    (codex_project / "config.toml").write_text(toml, encoding="utf-8")
    ag_project = output / "antigravity-workspace" / ".agents"
    ag_project.mkdir(parents=True)
    (ag_project / "mcp_config.json").write_text(
        json.dumps({"mcpServers": {"integrity_local_example": entry}}, indent=2) + "\n", encoding="utf-8")
    (output / "claude-isolated-settings.json").write_text(
        json.dumps({"disableAllHooks": True, "autoMemoryEnabled": False}, indent=2) + "\n", encoding="utf-8")
    (output / "server.json").write_text(json.dumps(entry, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(output), "active_configs_changed": False,
                      "native_hooks_installed": False}))


if __name__ == "__main__":
    main()
