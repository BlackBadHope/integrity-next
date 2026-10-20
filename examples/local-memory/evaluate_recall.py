"""Optional model pilot. Uses the client's existing account and quota; never run on import."""
from __future__ import annotations
import argparse
import hashlib
import json
import shutil
import subprocess
import time
from pathlib import Path

PROMPT = (
    "Prepare the MCP timeout settings for the Integrity Windows remote broker from the recorded maintenance decision. "
    "Return tool_timeout_sec, request_budget_sec and initialize_timeout_sec. "
    "Use null for a value unsupported by the evidence available in this session. Do not guess. "
    "This is a fresh-session configuration rehearsal, not permission to change any active configuration."
)
SCHEMA = {"type": "object", "properties": {
    **{name: {"type": ["integer", "null"]} for name in
       ("tool_timeout_sec", "request_budget_sec", "initialize_timeout_sec")},
    "evidence": {"type": "string"}}, "required": ["tool_timeout_sec", "request_budget_sec",
    "initialize_timeout_sec", "evidence"], "additionalProperties": False}


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--claude", default=shutil.which("claude"))
    p.add_argument("--config", type=Path, required=True)
    p.add_argument("--note", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--conditions", nargs="+", choices=("missing", "note", "mcp"),
                   default=["missing", "note", "mcp"])
    a = p.parse_args()
    if not a.claude:
        p.error("select an installed Claude Code executable with --claude")
    config = a.config.resolve(strict=True)
    note = a.note.read_text(encoding="utf-8")
    a.output.mkdir(parents=True, exist_ok=False)
    results = []
    for condition in a.conditions:
        prompt = PROMPT
        cmd = [a.claude, "-p", "--output-format", "stream-json", "--verbose",
               "--no-session-persistence", "--setting-sources", "",
               "--settings", '{"disableAllHooks":true,"autoMemoryEnabled":false}',
               "--strict-mcp-config", "--tools", "", "--permission-prompts", "none",
               "--max-turns", "8", "--json-schema", json.dumps(SCHEMA)]
        if condition == "note":
            prompt += "\nSaved project note:\n" + note
        if condition == "mcp":
            cmd += ["--mcp-config", str(config), "--allowedTools", "mcp__integrity_local_example__*"]
            prompt += ("\nThe project decision is available through integrity_local_example. "
                       "Look it up using UID client:public-remote-timeout-decision and cite its event ID. "
                       "Follow that server's read-only snapshot workflow.")
        started = time.perf_counter()
        completed = subprocess.run(cmd + ["--", prompt], cwd=a.output, text=True,
                                   encoding="utf-8", capture_output=True, timeout=180)
        frames = [json.loads(line) for line in completed.stdout.splitlines() if line.strip()]
        last = next((frame for frame in reversed(frames) if frame.get("type") == "result"), {})
        usage = last.get("usage") or {}
        item = {"condition": condition, "elapsed_seconds": round(time.perf_counter()-started, 3),
                "exit_code": completed.returncode, "is_error": last.get("is_error"),
                "response": last.get("structured_output"), "usage": usage,
                "input_including_cache": sum(usage.get(k, 0) for k in
                    ("input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens")),
                "num_turns": last.get("num_turns"), "modelUsage": last.get("modelUsage"),
                "tool_calls": [block["name"] for frame in frames
                    for block in frame.get("message", {}).get("content", [])
                    if isinstance(block, dict) and block.get("type") == "tool_use"],
                "note_sha256": hashlib.sha256(note.encode()).hexdigest()}
        results.append(item)
        (a.output / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(json.dumps({"condition": condition, "exit_code": completed.returncode,
                          "elapsed_seconds": item["elapsed_seconds"]}), flush=True)
        if completed.returncode or last.get("is_error") or item["response"] is None:
            raise SystemExit("Pilot stopped; inspect the outcome before using more quota.")


if __name__ == "__main__":
    main()
