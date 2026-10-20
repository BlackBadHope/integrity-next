"""Run exactly a generated Native profile, with source/config drift checks."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from .native_install import digest, plain, read_json

MAX_HOOK = 1024 * 1024


def verify(path):
    path = plain(path)
    profile = read_json(path)
    root = path.parent
    if (not isinstance(profile, dict) or profile.get("protocol") != "integrity/native-client-profile/v1"
            or profile.get("root") != str(root) or profile.get("platform") != sys.platform
            or profile.get("vendor") not in {"codex", "claude", "antigravity"}
            or not isinstance(profile.get("files"), dict)
            or not isinstance(profile.get("auxiliary_files", {}), dict)
            or not isinstance(profile.get("support_files", {}), dict)
            or not isinstance(profile.get("generated_launch_files", {}), dict)):
        raise ValueError("Native profile identity/platform mismatch")
    python = plain(profile["python"], 1024 * 1024 * 1024)
    if python != Path(sys.executable).resolve() or digest(python.read_bytes()) != profile["python_sha256"]:
        raise ValueError("Native Python pin changed")
    for key, name in (("component_sha256", "component.json"), ("upstream_sha256", "upstream.toml"),
                      ("transport_sha256", "transport.json"),
                      ("tools_sha256", "integrity-client-tools.json")):
        if digest(plain(root / name).read_bytes()) != profile[key]:
            raise ValueError("Native configuration pin changed")
    from .profile_roots import validate_existing
    preserved = validate_existing(profile)
    component = read_json(root / "component.json")
    server_name = profile.get("mcp_server_name", "integrity_native")
    if (server_name not in {"integrity_native", "integrity_client_memory"}
            or ("mcp_server_name" in component.get("values", {})
                and component["values"]["mcp_server_name"] != server_name)):
        raise ValueError("Native Memory server name binding changed")
    for field, name, component_key in (("state_root", "state", "path_2dbd800b4e29"),
                                       ("envelope_root", "envelopes", "path_f51de7de1b1c")):
        expected = preserved.get(name, {}).get("path", str(root / ("state" if name == "state" else "turn-envelopes")))
        values = component.get("values", {})
        if profile.get(field, expected) != expected or (profile["vendor"] == "codex" and
                (name in preserved or component_key in values) and values.get(component_key) != expected):
            raise ValueError("Native preserved root binding changed")
    for name, pin in profile["files"].items():
        if Path(name).name != name or not name.endswith(".py") or digest(plain(root / "runtime" / name).read_bytes()) != pin:
            raise ValueError("Native source pin changed")
    for name, pin in profile.get("auxiliary_files", {}).items():
        if Path(name).name != name or digest(plain(root / "runtime" / name).read_bytes()) != pin:
            raise ValueError("Native auxiliary file pin changed")
    if profile["hook"] not in profile["files"] or profile["broker"] not in profile["files"]:
        raise ValueError("Native entrypoint missing")
    for relative, pin in profile.get("support_files", {}).items():
        member = Path(relative)
        if member.is_absolute() or ".." in member.parts or str(member.as_posix()) != relative:
            raise ValueError("Native support path invalid")
        if digest(plain(root / "support" / member).read_bytes()) != pin:
            raise ValueError("Native support source pin changed")
    if profile.get("support_files"):
        if digest(plain(root / "run-native-profile.py").read_bytes()) != profile["support_bootstrap_sha256"]:
            raise ValueError("Native bootstrap pin changed")
        for relative, pin in profile.get("generated_launch_files", {}).items():
            member = Path(relative)
            if member.is_absolute() or ".." in member.parts or str(member.as_posix()) != relative:
                raise ValueError("Native launch path invalid")
            if digest(plain(root / member).read_bytes()) != pin:
                raise ValueError("Native launch configuration pin changed")
    return profile, root


def environment(profile, root):
    result = dict(os.environ)
    result.update(INTEGRITY_CLIENT_MEMORY_CONFIG=str(root / "component.json"),
                  INTEGRITY_CLIENT_STATE_ROOT=profile.get("state_root", str(root / "state")),
                  INTEGRITY_CLIENT_ENVELOPE_ROOT=profile.get("envelope_root", str(root / "turn-envelopes")),
                  INTEGRITY_CLIENT_MCP_TRANSPORT=str(root / "transport.json"),
                  INTEGRITY_SCOPE_STATE_ROOT=str(root / "scope-state"))
    if profile["vendor"] == "claude":
        # This is a selector, never evidence. The reader still verifies the
        # actual CLI ancestor, publisher, delivery ledger and full transcript.
        result["CLAUDE_SESSION_ID"] = read_json(root / "component.json")["values"]["claude_session_id"]
    if profile.get("support_files"):
        result["PYTHONPATH"] = str(root / "support") + os.pathsep + result.get("PYTHONPATH", "")
    return result


def broker_command(profile, root):
    args = [profile["python"], "-B", str(root / "runtime" / profile["broker"]),
            "--config", str(root / "upstream.toml"), "--tools-contract", str(root / "integrity-client-tools.json")]
    if profile["vendor"] != "antigravity":
        args += ["--upstream-server", "integrity-upstream"]
    return args


def merge_output(left, right):
    """Compose context sequentially. A later handler cannot erase a denial."""
    result = dict(left)
    for key, value in right.items():
        if key == "hookSpecificOutput":
            if not isinstance(value, dict) or not isinstance(result.get(key, {}), dict):
                raise ValueError("Native hook specific output shape invalid")
            combined = dict(result.get(key, {}))
            for field, item in value.items():
                if field == "additionalContext" and combined.get(field):
                    combined[field] += "\n" + item
                elif field == "permissionDecision" and combined.get(field) == "deny":
                    continue
                else:
                    combined[field] = item
            result[key] = combined
        elif key in {"additionalContext", "systemMessage"} and result.get(key):
            result[key] += "\n" + value
        elif key == "decision" and result.get(key) in {"block", "deny"}:
            continue
        elif key == "injectSteps":
            result[key] = result.get(key, []) + value
        else:
            result[key] = value
    return result


def blocked(value):
    return (value.get("decision") in {"block", "deny"}
            or value.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"
            or value.get("continue") is False)


def memory_call(raw):
    """A broken Memory route must not become an unrelated target-action veto."""
    try:
        payload = json.loads(raw or b"{}")
        if not isinstance(payload, dict):
            return None
        if isinstance(payload.get("toolCall"), dict):
            tool = payload["toolCall"]
            if tool.get("name") != "call_mcp_tool":
                return False
            arguments = tool.get("args", {})
            if not isinstance(arguments, dict):
                return None
            return arguments.get("ServerName") in {"integrity_native", "integrity_client_memory"}
        name = payload.get("tool_name") or payload.get("toolName")
        if not isinstance(name, str) or not name:
            return None
        if name.startswith(("mcp__integrity_native__", "mcp__integrity_client_memory__")):
            return True
        # Another Integrity product/server is a separate action boundary.
        if "__" in name or "." in name:
            return False
        if not name.startswith("integrity_"):
            return False
        catalog = read_json(Path(__file__).with_name("data") / "tools-current.json")
        tools = catalog.get("result", catalog).get("tools", [])
        return name in {item["name"] for item in tools}
    except (OSError, ValueError, UnicodeError, TypeError, KeyError, AttributeError):
        return None


def hook(profile, root, event, raw):
    if len(raw) > MAX_HOOK:
        raise ValueError("Native hook input bound exceeded")
    payload = json.loads(raw or b"{}")
    if not isinstance(payload, dict):
        raise ValueError("Native hook input must be an object")
    vendor = profile["vendor"]
    native_events = {"SessionStart", "PreInvocation", "PreToolUse", "PostToolUse", "Stop"} if vendor == "antigravity" else {
        "SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "SubagentStart", "Stop", "SubagentStop"}
    scope_events = {"SessionStart", "UserPromptSubmit", "PreToolUse", "PreCompact", "PostCompact"} if vendor != "antigravity" else set()
    handlers = []
    native = [profile["python"], "-B", str(root / "runtime" / profile["hook"]), "--event", event]
    scope = [profile["python"], "-B", str(root / "runtime/integrity_scope_synapse.py"), "--harness", vendor,
             "--state", str(root / "scope-state"), "--event", event]
    # Reorientation denies an effect before any admission handoff is armed.
    if event == "PreToolUse" and event in scope_events:
        handlers.append(scope)
    if event in native_events:
        handlers.append(native)
    if event != "PreToolUse" and event in scope_events:
        handlers.append(scope)
    if not handlers:
        raise ValueError("unsupported Native event")
    result = {}
    for command in handlers:
        done = subprocess.run(command, input=raw, capture_output=True, env=environment(profile, root),
                              timeout=50, check=False, creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        if len(done.stdout) > 4 * 1024 * 1024:
            raise ValueError("Native hook output bound exceeded")
        try:
            value = json.loads(done.stdout or b"{}")
        except (ValueError, UnicodeError):
            raise ValueError("Native hook output invalid") from None
        if not isinstance(value, dict):
            raise ValueError("Native hook output shape invalid")
        result = merge_output(result, value)
        if done.returncode or blocked(result):
            return result, done.returncode
    return result, 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("mode", choices=("verify", "probe", "mcp", "hook"))
    parser.add_argument("event", nargs="?")
    args = parser.parse_args(argv)
    raw_input = None
    try:
        if args.mode == "hook":
            raw_input = sys.stdin.buffer.read(MAX_HOOK + 1)
        profile, root = verify(args.profile)
        if args.mode == "verify":
            print(json.dumps({"status": "source-and-config-verified", "vendor": profile["vendor"],
                              "upstream_started": False, "native_ownership_verified": False, "live_acceptance": "NOT_RUN"}))
            return 0
        if args.mode == "mcp":
            return subprocess.call(broker_command(profile, root), env=environment(profile, root))
        if args.mode == "probe":
            probes = [broker_command(profile, root) + ["--help"],
                      [profile["python"], "-B", str(root / "runtime" / profile["hook"]), "--help"]]
            for command in probes:
                value = subprocess.run(command, env=environment(profile, root), capture_output=True, timeout=15,
                                       creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
                if value.returncode:
                    # Import errors can contain local paths. Retain only safe type/code here.
                    raise ValueError("Native entrypoint import/parser probe failed")
            if profile["vendor"] != "antigravity":
                # Exercise the REAL hook's control client, not a parallel schema
                # checker. This starts only the lazy local broker, not upstream.
                code = ('import runpy,sys;sys.path.insert(0,sys.argv[1]);'
                        'm=runpy.run_path(sys.argv[2],run_name="native_wire_probe");'
                        'c=m["McpClient"]();c.close()')
                wire = subprocess.run([profile["python"], "-B", "-c", code, str(root / "runtime"),
                                       str(root / "runtime" / profile["hook"])],
                                      env=environment(profile, root), capture_output=True, timeout=25,
                                      creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
                if wire.returncode:
                    raise ValueError("Native hook/broker initialize-tools-list handshake failed")
            else:
                messages = [
                    {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                        "protocolVersion": "2025-06-18", "capabilities": {},
                        "clientInfo": {"name": "native-wire-probe", "version": "1"}}},
                    {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
                    {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                ]
                wire = subprocess.run(broker_command(profile, root),
                    input="".join(json.dumps(m) + "\n" for m in messages).encode(),
                    env=environment(profile, root), capture_output=True, timeout=25,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
                if wire.returncode or len(wire.stdout) > 4 * 1024 * 1024:
                    raise ValueError("Native broker control handshake failed")
                replies = {m.get("id"): m for m in (json.loads(line) for line in wire.stdout.splitlines())}
                info = replies.get(1, {}).get("result", {}).get("serverInfo", {})
                names = [t["name"] for t in replies.get(2, {}).get("result", {}).get("tools", [])]
                expected = [t["name"] for t in read_json(root / "integrity-client-tools.json")]
                if info != {"name": "integrity-client-memory", "version": profile["broker_version"]} or names != expected:
                    raise ValueError("Native broker identity/tools mismatch")
            print(json.dumps({"status": "entrypoints-load", "vendor": profile["vendor"],
                              "hook_broker_wire": "initialize-tools-list-PASS",
                              "upstream_started": False, "model_calls": 0, "live_acceptance": "NOT_RUN"}))
            return 0
        result, code = hook(profile, root, args.event, raw_input)
        print(json.dumps(result, ensure_ascii=False), flush=True)
        return code
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as exc:
        if args.mode == "hook" and args.event == "PreToolUse":
            try:
                ag = read_json(args.profile).get("vendor") == "antigravity"
            except Exception:
                ag = False
            notice = "Integrity Native infrastructure unavailable; report this Memory-route fault. It grants no target authority and does not revoke separately verified owner authorization for this unrelated tool."
            if memory_call(raw_input) is False:
                result = ({"injectSteps": [{"ephemeralMessage": notice}]} if ag else
                          {"hookSpecificOutput": {"hookEventName": "PreToolUse", "additionalContext": notice}})
                print(json.dumps(result), flush=True)
                return 0
            result = ({"decision": "deny", "reason": "Integrity Native infrastructure unavailable"} if ag else
                      {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                               "permissionDecisionReason": "Integrity Native infrastructure unavailable"}})
            print(json.dumps(result), flush=True)
            return 0
        print("Native runtime refused: " + type(exc).__name__, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
