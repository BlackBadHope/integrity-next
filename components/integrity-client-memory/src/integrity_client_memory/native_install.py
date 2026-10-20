"""Build a complete, isolated Native client profile; never edit active settings.

An owner-selected stdio server and its namespace remain explicit prerequisites.
No credential, remote endpoint, enrollment or Native identity is shipped.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import tomllib

from .profile import compile_catalog

HERE = Path(__file__).resolve().parent
RESOURCES = HERE / "resources"
LAUNCH_FILES = {
    "codex": ("codex-workspace/.codex/config.toml", "codex-workspace/.codex/hooks.json"),
    "claude": ("claude-workspace/.mcp.json", "claude-workspace/.claude/settings.json"),
    "antigravity": ("antigravity-plugin/hooks.json", "antigravity.mcp.json", "antigravity.enable-fragment.json"),
}
VENDORS = ("codex", "claude", "antigravity")
EVENTS = ("SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse",
          "SubagentStart", "Stop", "SubagentStop")
AG_EVENTS = ("SessionStart", "PreInvocation", "PreToolUse", "PostToolUse", "Stop")
SHA = re.compile(r"[a-f0-9]{64}\Z")
UUID = re.compile(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\Z")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def plain(path, maximum=4 * 1024 * 1024):
    path = Path(path).absolute()
    for item in (path, *path.parents):
        st = item.lstat()
        if item.is_symlink() or getattr(st, "st_file_attributes", 0) & 1024:
            raise ValueError("linked path refused")
    if not path.is_file() or not 0 < path.stat().st_size <= maximum:
        raise ValueError("bounded regular file required")
    return path


def read_json(path):
    def unique(rows):
        result = {}
        for key, value in rows:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    return json.loads(plain(path).read_text(encoding="utf-8"), object_pairs_hook=unique)


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def private_root(path):
    if path.exists() or path.is_symlink() or not path.parent.is_dir():
        raise ValueError("output must be a new directory with an existing parent")
    if os.name == "nt":
        from integrity_guardian._windows_files import create_private_directory_tree
        create_private_directory_tree(path)
    else:
        path.mkdir(mode=0o700)


def source_strings(text):
    """Inspect frozen Python sources without importing/executing any of them."""
    import base64
    pending, seen = [text], set()
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        if len(seen) > 100:
            raise ValueError("source nesting bound")
        tree = ast.parse(current)
        yield current, tree
        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant) or not isinstance(node.value, str) or len(node.value) < 256:
                continue
            value = node.value
            if re.fullmatch(r"[A-Za-z0-9+/=]+", value):
                try:
                    value = base64.b64decode(value, validate=True).decode("utf-8")
                except (ValueError, UnicodeError):
                    continue
            try:
                child = ast.parse(value)
            except SyntaxError:
                continue
            if any(isinstance(n, (ast.FunctionDef, ast.ClassDef)) for n in child.body):
                pending.append(value)


def configuration_keys(paths):
    keys = set()
    for path in paths:
        for _, tree in source_strings(path.read_text(encoding="utf-8")):
            for node in ast.walk(tree):
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                        and node.func.id == "_integrity_value" and len(node.args) == 1
                        and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)):
                    keys.add(node.args[0].value)
    return keys


def source_files(vendor):
    if vendor == "antigravity":
        return sorted((RESOURCES / "antigravity").glob("*.py")), "integrity_antigravity_hook.py", "integrity_antigravity_broker.py"
    if vendor == "claude":
        return sorted((RESOURCES / "claude-native").glob("*.py")), "integrity-client-admission.py", "integrity-client-turn-broker.py"
    names = {"integrity-client-admission.py", "delegation-native-reader.py"}
    paths = [RESOURCES / "windows/native" / n for n in sorted(names)]
    # The Windows broker's resume API and the Native hook must share one
    # envelope cohort; the historical native/ envelope predates these methods.
    paths.append(RESOURCES / "windows/integrity_client_turn_envelope.py")
    paths.append(RESOURCES / "windows/integrity-client-turn-broker.py")
    return paths, "integrity-client-admission.py", "integrity-client-turn-broker.py"


def required_bindings(vendor, bindings):
    for key in ("seed_namespace", "namespace_fingerprint", "architecture_checkpoint_id"):
        if not isinstance(bindings.get(key), str) or not bindings[key].strip():
            raise ValueError("owner binding required: " + key)
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", bindings["namespace_fingerprint"]):
        raise ValueError("namespace_fingerprint must come from the selected server")
    if vendor != "claude":
        return
    if not UUID.fullmatch(str(bindings.get("claude_session_id", ""))):
        raise ValueError("Claude requires its actual enrolled session ID")
    for key in ("claude_owner_file", "claude_ledger", "claude_transcript", "claude_publisher_script", "claude_publisher_python"):
        bindings[key] = str(plain(bindings.get(key, ""), 1024 * 1024 * 1024))
    bindings["claude_project_root"] = str(Path(bindings["claude_project_root"]).resolve(strict=True))
    if Path(bindings["claude_transcript"]).name != bindings["claude_session_id"] + ".jsonl":
        raise ValueError("Claude transcript/session mismatch")
    owner = read_json(bindings["claude_owner_file"])
    if (not isinstance(owner, dict) or owner.get("schema") != "integrity-claude-owner/v1"
            or not isinstance(owner.get("binary"), str)
            or str(Path(owner.get("workspace", "")).resolve()) != bindings["claude_project_root"]
            or Path(owner.get("state_dir", "")).resolve() != Path(bindings["claude_ledger"]).parent
            or owner.get("permission_profile") != "full_access"):
        raise ValueError("existing Claude Native owner profile does not match the selected session roots")
    binary = plain(owner["binary"], 1024 * 1024 * 1024)
    if digest(binary.read_bytes()) != owner.get("binary_sha256"):
        raise ValueError("Claude owner binary pin changed")
    mcp = plain(owner.get("mcp_config", ""))
    if digest(mcp.read_bytes()) != owner.get("mcp_sha256"):
        raise ValueError("Claude owner MCP pin changed")
    try:
        with sqlite3.connect(Path(bindings["claude_ledger"]).as_uri() + "?mode=ro", uri=True, timeout=2) as db:
            db.execute("PRAGMA query_only=ON")
            row = db.execute("SELECT session_id FROM tasks WHERE id=?", (bindings["claude_session_id"],)).fetchone()
            if not row or row[0] != bindings["claude_session_id"]:
                raise ValueError("Claude session is not enrolled in the selected owner ledger")
    except sqlite3.Error:
        raise ValueError("Claude owner ledger is unavailable or incompatible") from None
    for source, target in (("claude_owner_file", "claude_owner_sha256"),
                           ("claude_publisher_script", "claude_publisher_sha256"),
                           ("claude_publisher_python", "claude_publisher_python_sha256")):
        bindings[target] = digest(Path(bindings[source]).read_bytes())
    publisher_owner = plain(Path(bindings["claude_publisher_script"]).with_name("claude_owner.py"))
    bindings["claude_publisher_owner_sha256"] = digest(publisher_owner.read_bytes())


def build(vendor, upstream, bindings, output, tools=None, *, deployment_root=None,
          state_root=None, envelope_root=None):
    server_name = bindings.get("mcp_server_name", "integrity_native")
    if server_name not in {"integrity_native", "integrity_client_memory"}:
        raise ValueError("Native Memory server name must be an explicit supported Memory route")
    if vendor not in VENDORS:
        raise ValueError("unknown vendor")
    if os.name != "nt" and vendor in {"codex", "claude"}:
        raise ValueError("these Native ownership profiles require Windows; no cross-host fallback")
    if os.name == "nt":
        for value in (str(Path(output).absolute()), sys.executable):
            if any(c in value for c in '&|<>^()%!\r\n\x00'):
                raise ValueError("Windows hook paths must not contain cmd metacharacters")
            if vendor == "antigravity" and any(c.isspace() for c in value):
                raise ValueError("observed Antigravity cmd hook launcher requires space-free Python and profile paths")
    bindings = dict(bindings)
    required_bindings(vendor, bindings)
    server_version = bindings.get("server_version")
    if server_version is not None and (vendor != "codex" or not isinstance(server_version, str)
            or re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", server_version) is None):
        raise ValueError("server_version requires an exact semantic version for Windows Codex")
    if (not isinstance(upstream, dict) or not isinstance(upstream.get("command"), str)
            or not Path(upstream["command"]).is_absolute() or not Path(upstream["command"]).is_file()
            or not isinstance(upstream.get("args", []), list)
            or any(not isinstance(x, str) for x in upstream.get("args", []))
            or ("cwd" in upstream and (not isinstance(upstream["cwd"], str)
                or not Path(upstream["cwd"]).is_absolute() or not Path(upstream["cwd"]).is_dir()))
            or not isinstance(upstream.get("env", {}), dict)
            or any(not isinstance(k, str) or not isinstance(v, str) for k, v in upstream.get("env", {}).items())):
        raise ValueError("complete owner-selected absolute stdio command required")
    tools = tools if tools is not None else read_json(HERE / "data/tools-current.json")
    if isinstance(tools, dict):
        envelope = tools.get("result", tools)
        if not isinstance(envelope, dict):
            raise ValueError("tools/list response shape invalid")
        tools = envelope.get("tools")
    encoded, tools_sha = compile_catalog(tools)
    required = {"integrity_append_event", "integrity_turn_memory_gap", "integrity_turn_memory_coverage", "integrity_seed_event_uid"}
    if not required <= {x["name"] for x in tools}:
        raise ValueError("full Native lifecycle catalogue required; read-only example is insufficient")
    output = Path(output).absolute()
    logical = output
    preserved = {}
    selected_state = selected_envelopes = None
    if any(value is not None for value in (deployment_root, state_root, envelope_root)):
        if vendor != "codex":
            raise ValueError("explicit preserved roots require the Windows Codex cohort")
        from . import profile_roots
        if deployment_root is not None:
            logical = profile_roots.deployment_root(deployment_root)
            if any(c in str(logical) for c in '&|<>^()%!\r\n\x00'):
                raise ValueError("Windows hook paths must not contain cmd metacharacters")
        if state_root is not None:
            selected_state, preserved["state"] = profile_roots.existing_root(state_root)
        if envelope_root is not None:
            selected_envelopes, preserved["envelopes"] = profile_roots.existing_root(envelope_root)
        roots = [Path(value["path"]) for value in preserved.values()]
        for index, first in enumerate(roots):
            if (first == logical or first.is_relative_to(logical) or logical.is_relative_to(first)
                    or any(first == second or first.is_relative_to(second) or second.is_relative_to(first)
                           for second in roots[index + 1:])):
                raise ValueError("preserved roots and deployment must not overlap")
    selected_state = selected_state or logical / "state"
    selected_envelopes = selected_envelopes or logical / "turn-envelopes"
    paths, hook_name, broker_name = source_files(vendor)
    if not paths or any(not x.is_file() for x in paths):
        raise ValueError("Native source profile missing")
    selected = list(paths)
    if vendor != "antigravity":
        selected.append(RESOURCES / "common/integrity_scope_synapse.py")
        selected.append(RESOURCES / "windows/native/integrity_project_scope.py")
    required_keys = configuration_keys(selected)
    if preserved:
        required_keys |= {"path_2dbd800b4e29", "path_f51de7de1b1c"}
    private_root(output)
    runtime = output / "runtime"
    live_runtime = logical / "runtime"
    runtime.mkdir()
    source_pins = {}
    for source in selected:
        target = runtime / source.name
        if target.exists():
            raise ValueError("duplicate runtime module")
        target.write_bytes(source.read_bytes())
        source_pins[source.name] = digest(target.read_bytes())
    template_pins = dict(source_pins)
    derivations = []
    if vendor == "codex":
        from .native_receipts import render_hook
        hook_path = runtime / hook_name
        rendered_hook, receipt_provenance = render_hook(hook_path.read_text(encoding="utf-8"))
        hook_path.write_text(rendered_hook, encoding="utf-8", newline="\n")
        source_pins[hook_name] = digest(hook_path.read_bytes())
        derivations.append({"file": hook_name,
                            "reason": "Decode canonical compact receipts before unchanged admission validators",
                            **receipt_provenance})
        from .broker_bundle import render_windows_broker
        rendered, provenance = render_windows_broker()
        (runtime / broker_name).write_bytes(rendered)
        source_pins[broker_name] = digest(rendered)
        derivations.append({"file": broker_name, "reason": "Freeze canonical shared recovery modules",
                            **provenance})
    if vendor in {"codex", "claude"}:
        from .transport_policy import render_windows_transport
        broker_path = runtime / broker_name
        rendered, policy = render_windows_transport(broker_path.read_bytes())
        broker_path.write_bytes(rendered)
        source_pins[broker_name] = digest(rendered)
        derivations.append({"file": broker_name, **policy})
    # The Native ownership hook is a distinct preserved source cohort. Compile
    # its local broker identity against the broker actually selected here,
    # retaining the original exact identity and full tools-contract checks.
    version_source = runtime / ("turn_broker_core.py" if vendor == "antigravity" else broker_name)
    broker_tree = ast.parse(version_source.read_text(encoding="utf-8"))
    broker_version = next(ast.literal_eval(n.value) for n in broker_tree.body
                          if isinstance(n, ast.Assign) and len(n.targets) == 1
                          and isinstance(n.targets[0], ast.Name) and n.targets[0].id == "BROKER_VERSION")
    if vendor != "antigravity":
        hook_path = runtime / hook_name
        text = hook_path.read_text(encoding="utf-8")
        assignment = next(n for n in ast.parse(text).body if isinstance(n, ast.Assign)
                          and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)
                          and n.targets[0].id == "BROKER_SERVER_VERSION")
        if ast.literal_eval(assignment.value) != broker_version:
            lines = text.splitlines(keepends=True)
            lines[assignment.lineno - 1:assignment.end_lineno] = ["BROKER_SERVER_VERSION = " + repr(broker_version) + "\n"]
            hook_path.write_text("".join(lines), encoding="utf-8", newline="\n")
            source_pins[hook_name] = digest(hook_path.read_bytes())
            derivations.append({"file": hook_name, "constant": "BROKER_SERVER_VERSION", "value": broker_version,
                                "reason": "Exact pairing with selected local broker; contract verification retained"})
        if server_version is not None:
            text = hook_path.read_text(encoding="utf-8")
            assignments = [n for n in ast.parse(text).body if isinstance(n, ast.Assign)
                           and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)
                           and n.targets[0].id == "SERVER_VERSION"]
            if len(assignments) != 1:
                raise ValueError("Native server identity derivation anchor changed")
            assignment = assignments[0]
            original = ast.literal_eval(assignment.value)
            lines = text.splitlines(keepends=True)
            lines[assignment.lineno - 1:assignment.end_lineno] = ["SERVER_VERSION = " + repr(server_version) + "\n"]
            hook_path.write_text("".join(lines), encoding="utf-8", newline="\n")
            source_pins[hook_name] = digest(hook_path.read_bytes())
            derivations.append({"file": hook_name, "constant": "SERVER_VERSION", "original": original,
                                "value": server_version, "binding": "server_version",
                                "reason": "Exact owner-selected upstream metadata identity; all contract checks retained"})
    values = dict(bindings)
    values.update({"mcp_server_name": server_name, "upstream_toml": str(logical / "upstream.toml"),
                   "tools_catalogue": str(logical / "integrity-client-tools.json"),
                   "private_state_root": str(selected_state),
                   "path_b90aa9f0d1c5": str(logical / "optional-bus"),
                   "pin_dd9fa64be3f2": bindings["namespace_fingerprint"],
                   "path_5164c4d20152": str(live_runtime / "delegation-native-reader.py"),
                   "pin_8355e401d593": source_pins.get("delegation-native-reader.py", "disabled"),
                   "command_b734f1f83ce5": subprocess.list2cmdline([upstream["command"], *upstream.get("args", [])]),
                   "path_6417ae8b427b": str(logical / "startup-gates"),
                   "path_0b4608844dcc": str(logical / "optional-bus/agents-registry.json"),
                   "path_a136563213bf": str(logical / "attachments"),
                   "path_dd2435d503a6": str(logical / "workspace"),
                   "pin_fd1c0d5a8471": digest(b"optional-core-catalogue-disabled"),
                   "claude_state_home": str(logical), "path_b8097dd72ab5": str(logical),
                   "path_2dbd800b4e29": str(selected_state),
                   "path_f51de7de1b1c": str(selected_envelopes),
                   "path_e7a3397d5cef": str(logical / "delegation-config.json"),
                   "path_5337709e82f6": str(logical),
                   "claude_native_reader_sha256": source_pins.get("claude_owning_native.py", "disabled")})
    values["path_a7a775fb78e8"] = str(logical / "disabled-historical-recovery")
    values["pin_0266e73cb5e7"] = "disabled-no-historical-owner-enrollment"
    values["pin_37c8b12ade41"] = "disabled-no-historical-owner-enrollment"
    # The former publisher's one-off archive recovery allowlist is inert here.
    for key in ("pin_57b074bde43c", "pin_3c8ef62afebf", "pin_b3e80aea09e2", "pin_9ae1c0f33d07", "pin_3cf6719e1f73", "pin_10b8b4c69d7c", "pin_e8a92f8dbfa3"):
        values[key] = "disabled-no-historical-owner-enrollment"
    values["binding_9627b6210e51"] = "disabled-no-historical-owner-enrollment"
    # Rebind intrinsically frozen source pins to the actual packaged bytes.
    broker_text = (runtime / broker_name).read_text(encoding="utf-8")
    broker_tree = ast.parse(broker_text)
    assigned = {n.targets[0].id: n.value.value for n in broker_tree.body
                if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)
                and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str)}
    for key, name in (("pin_498c7592d714", "_attachment_retrieval_source"), ("pin_74e986d01516", "_topic_context_source")):
        if name in assigned:
            values[key] = digest(assigned[name].encode("utf-8"))
    # Historical factory and delegation extras are not silently enabled.
    missing = sorted(k for k in required_keys if not isinstance(values.get(k), str) or not values[k].strip())
    if missing:
        write_json(output / "INCOMPLETE.json", {"missing_bindings": missing, "enabled": False})
        raise ValueError("unresolved Native runtime bindings: " + ", ".join(missing))
    component = {"schema": "integrity/component-config/v1", "component": "integrity-client-memory",
                 "configured": True, "guardian_version": "6.1.0", "memory_api_version": "2.11.0",
                 "values": {k: values[k] for k in sorted(required_keys)}, "owner_local_catalogue": None}
    write_json(output / "component.json", component)
    (output / "integrity-client-tools.json").write_bytes(encoded)
    auxiliary_pins = {}
    if vendor == "claude":
        # The owning Claude hook resolves its contract next to its exact broker.
        # Both catalogues are the same reviewed bytes, and both are pinned.
        (runtime / "integrity-client-tools.json").write_bytes(encoded)
        auxiliary_pins["integrity-client-tools.json"] = tools_sha
    toml = "[mcp_servers.integrity-upstream]\nenabled = false\n"
    for key in ("command", "args", "cwd"):
        if key in upstream:
            toml += key + " = " + json.dumps(upstream[key], ensure_ascii=False) + "\n"
    if upstream.get("env"):
        toml += "\n[mcp_servers.integrity-upstream.env]\n"
        for key, value in upstream["env"].items():
            toml += json.dumps(key) + " = " + json.dumps(value) + "\n"
    tomllib.loads(toml)
    (output / "upstream.toml").write_text(toml, encoding="utf-8")
    python = str(Path(sys.executable).resolve())
    entry_args = ["-m", "integrity_client_memory.native_runtime", "--profile", str(logical / "profile.json")]
    contract_args = ["--tools-contract", str(logical / "integrity-client-tools.json")] if vendor == "codex" else []
    transport = {"command": python, "args": [*entry_args, *contract_args, "mcp"]}
    lifecycle_args = ["-B", str(live_runtime / broker_name), "--config", str(logical / "upstream.toml"),
                      "--tools-contract", str(logical / "integrity-client-tools.json")]
    if vendor != "antigravity":
        lifecycle_args += ["--upstream-server", "integrity-upstream"]
    lifecycle_env = {"INTEGRITY_CLIENT_MEMORY_CONFIG": str(logical / "component.json"),
                     "INTEGRITY_CLIENT_STATE_ROOT": str(selected_state),
                     "INTEGRITY_CLIENT_ENVELOPE_ROOT": str(selected_envelopes)}
    if vendor == "claude":
        lifecycle_env["CLAUDE_SESSION_ID"] = bindings["claude_session_id"]
    write_json(output / "transport.json", {"transport": {"type": "stdio", "command": python,
               "args": lifecycle_args, "env": lifecycle_env}})
    hook_events = AG_EVENTS if vendor == "antigravity" else (*EVENTS, "PreCompact", "PostCompact")
    hooks = {}
    for event in hook_events:
        argv = [python, *entry_args, "hook", event]
        command = subprocess.list2cmdline(argv) if os.name == "nt" else __import__("shlex").join(argv)
        item = {"type": "command", "command": command, "timeout": 60}
        hooks[event] = [{"hooks": [item]}]
    if vendor == "codex":
        folder = output / "codex-workspace/.codex"
        folder.mkdir(parents=True)
        t = "[mcp_servers." + server_name + "]\ncommand = " + json.dumps(python) + "\nargs = " + json.dumps(transport["args"]) + "\nstartup_timeout_sec = 60\ntool_timeout_sec = 210\n"
        (folder / "config.toml").write_text(t, encoding="utf-8")
        write_json(folder / "hooks.json", {"hooks": hooks})
    elif vendor == "claude":
        write_json(output / "claude-workspace/.mcp.json", {"mcpServers": {"integrity_native": transport}})
        write_json(output / "claude-workspace/.claude/settings.json", {"hooks": hooks})
    else:
        # Antigravity uses its observed direct-handler plugin schema.
        ag_hooks = {}
        for event in AG_EVENTS:
            argv = [python, *entry_args, "hook", event]
            command = subprocess.list2cmdline(argv) if os.name == "nt" else __import__("shlex").join(argv)
            handler = {"type": "command", "command": command, "timeout": 60}
            ag_hooks[event] = ([{"matcher": "^call_mcp_tool$", "hooks": [handler]}]
                               if event in {"PreToolUse", "PostToolUse"} else [handler])
        write_json(output / "antigravity-plugin/hooks.json", {"integrity-native": ag_hooks})
        write_json(output / "antigravity.mcp.json", {"mcpServers": {"integrity_native": transport}})
        write_json(output / "antigravity.enable-fragment.json", {"plugins": {"integrity-native": {"enabled": True}}})
    profile = {"protocol": "integrity/native-client-profile/v1", "vendor": vendor, "platform": sys.platform,
               "root": str(logical), "python": python, "python_sha256": digest(Path(python).read_bytes()),
               "hook": hook_name, "broker": broker_name, "files": source_pins,
               "template_source_pins": template_pins, "derivations": derivations,
               "auxiliary_files": auxiliary_pins, "broker_version": broker_version,
               "launch_files": {name: digest((output / name).read_bytes()) for name in LAUNCH_FILES[vendor]},
               "tools_sha256": tools_sha, "component_sha256": digest((output / "component.json").read_bytes()),
               "transport_sha256": digest((output / "transport.json").read_bytes()),
               "upstream_sha256": digest((output / "upstream.toml").read_bytes()),
               "active_configs_changed": False, "live_acceptance": "NOT_RUN"}
    if preserved:
        profile.update(state_root=str(selected_state), envelope_root=str(selected_envelopes),
                       preserved_roots=preserved)
    if "mcp_server_name" in bindings:
        profile["mcp_server_name"] = server_name
    write_json(output / "profile.json", profile)
    write_json(output / "receipt.json", {"protocol": profile["protocol"], "vendor": vendor,
               "configured": True, "required_bindings_resolved": True, "tools": len(tools),
               "source_files": len(source_pins), "active_configs_changed": False, "live_acceptance": "NOT_RUN"})
    return profile


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--vendor", choices=VENDORS, required=True)
    p.add_argument("--upstream-json", type=Path, required=True)
    p.add_argument("--bindings-json", type=Path, required=True)
    p.add_argument("--tools-json", type=Path)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--deployment-root", type=Path)
    p.add_argument("--state-root", type=Path)
    p.add_argument("--envelope-root", type=Path)
    a = p.parse_args(argv)
    try:
        result = build(a.vendor, read_json(a.upstream_json), read_json(a.bindings_json), a.output,
                       read_json(a.tools_json) if a.tools_json else None,
                       deployment_root=a.deployment_root, state_root=a.state_root, envelope_root=a.envelope_root)
        print(json.dumps({"vendor": result["vendor"], "profile": str(Path(a.output).absolute() / "profile.json"),
                          "configured": True, "active_configs_changed": False, "live_acceptance": "NOT_RUN"}))
        return 0
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print("Native profile rejected: " + str(exc) if isinstance(exc, ValueError) else "Native profile rejected: " + type(exc).__name__, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
