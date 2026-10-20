"""Render the canonical Windows broker and compile an isolated Native profile.

The package resource is the sole broker source. Standalone profiles freeze the
same shared modules deterministically; no installed broker or private baseline
is read. Owner configuration is an explicit input to the existing compiler.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
BROKER = ROOT / "resources/windows/integrity-client-turn-broker.py"
MODULES = ("operation_ledger", "recovery_client", "broker_adapter")
SUPPORT = ("__init__.py", "configuration.py", "catalogue.py", "native_runtime.py",
           "native_install.py", "profile.py", "broker_bundle.py", "project_scope.py",
           "profile_roots.py",
           "operation_ledger.py", "recovery_client.py", "broker_adapter.py",
           "data/tools-current.json")
BEGIN = "# BEGIN CANONICAL SESSION RECOVERY\n"
END = "# END CANONICAL SESSION RECOVERY\n"


def source_pins():
    paths = [BROKER, *(ROOT / (name + ".py") for name in MODULES),
             Path(__file__).resolve(),
             ROOT / "resources/windows/integrity_client_turn_envelope.py"]
    return {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in paths}


def render_windows_broker():
    """Return frozen bytes and source provenance without writing or importing."""
    text = BROKER.read_text(encoding="utf-8")
    if text.count(BEGIN) != 1 or text.count(END) != 1:
        raise ValueError("canonical recovery renderer anchors changed")
    start = text.index(BEGIN)
    finish = text.index(END, start) + len(END)
    embedded = BEGIN + "import types as _recovery_types\n"
    for name in MODULES:
        source = (ROOT / (name + ".py")).read_text(encoding="utf-8-sig")
        ast.parse(source)
        digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
        embedded += (f"_{name} = _recovery_types.ModuleType({name!r})\n"
                     f"_{name}_source = {source!r}\n"
                     f"assert hashlib.sha256(_{name}_source.encode('utf-8')).hexdigest() == {digest!r}\n"
                     f"exec(compile(_{name}_source, '<canonical-{name}>', 'exec'), _{name}.__dict__)\n")
    embedded += "_broker_adapter.install(globals(), _recovery_client, _operation_ledger)\n" + END
    rendered = (text[:start] + embedded + text[finish:]).encode("utf-8")
    ast.parse(rendered.decode("utf-8"))
    return rendered, {"protocol": "integrity/canonical-broker-render/v1",
                      "profile": "windows", "source_pins": source_pins(),
                      "rendered_sha256": hashlib.sha256(rendered).hexdigest(),
                      "source": "resources/windows/integrity-client-turn-broker.py"}


def build_bundle(output, *, bindings, upstream, tools, deployment_root=None,
                 state_root=None, envelope_root=None):
    """Compile a complete source-pinned client package and Native profile.

    Guardian's declared distribution dependencies remain prerequisites. The
    client support package is copied from this exact source tree, never from an
    installed broker, and selected by a pinned local bootstrap.
    """
    from .native_install import build, digest, read_json, write_json
    output = Path(output).absolute()
    if output.is_relative_to(ROOT):
        raise ValueError("bundle output must be outside canonical package sources")
    profile = build("codex", upstream, bindings, output, tools,
                    deployment_root=deployment_root, state_root=state_root, envelope_root=envelope_root)
    logical = Path(profile["root"])
    support = output / "support"
    pins = {}
    # Explicit runtime closure: no scan can accidentally copy private local
    # configuration, unrelated modules, bytecode, or another profile's state.
    for member in SUPPORT:
        source = ROOT / member
        if source.is_symlink() or not source.resolve().is_relative_to(ROOT):
            raise ValueError("canonical support source custody changed")
        relative = Path("integrity_client_memory") / source.relative_to(ROOT)
        raw = source.read_bytes()
        target = support / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        pins[relative.as_posix()] = digest(raw)
    for relative, expected in pins.items():
        source = ROOT / Path(relative).relative_to("integrity_client_memory")
        if digest(source.read_bytes()) != expected:
            raise ValueError("canonical support sources changed during compilation")
    bootstrap = ("from pathlib import Path\nimport sys\n"
                 "sys.dont_write_bytecode=True\n"
                 "sys.path.insert(0,str(Path(__file__).resolve().parent/'support'))\n"
                 "from integrity_client_memory.native_runtime import main\n"
                 "raise SystemExit(main())\n")
    (output / "run-native-profile.py").write_text(bootstrap, encoding="utf-8", newline="\n")
    profile["support_files"] = pins
    profile["support_bootstrap_sha256"] = digest((output / "run-native-profile.py").read_bytes())
    profile["support_prerequisites"] = ["integrity-guardian>=6.1.0,<7", "integrity-action-log>=2.10.0,<3"]
    args = [str(logical / "run-native-profile.py"), "--profile", str(logical / "profile.json")]
    transport = read_json(output / "transport.json")
    transport["transport"]["env"]["PYTHONPATH"] = str(logical / "support")
    write_json(output / "transport.json", transport)
    profile["transport_sha256"] = digest((output / "transport.json").read_bytes())
    folder = output / "codex-workspace/.codex"
    config = ("[mcp_servers." + profile.get("mcp_server_name", "integrity_native") + "]\ncommand = " + json.dumps(profile["python"]) +
              "\nargs = " + json.dumps([*args, "mcp"]) +
              "\nstartup_timeout_sec = 60\ntool_timeout_sec = 210\n")
    (folder / "config.toml").write_text(config, encoding="utf-8")
    hooks = read_json(folder / "hooks.json")
    for event, groups in hooks["hooks"].items():
        argv = [profile["python"], *args, "hook", event]
        command = subprocess.list2cmdline(argv) if os.name == "nt" else __import__("shlex").join(argv)
        for group in groups:
            for hook in group["hooks"]:
                hook["command"] = command
    write_json(folder / "hooks.json", hooks)
    profile["generated_launch_files"] = {str(p.relative_to(output).as_posix()): digest(p.read_bytes())
        for p in (folder / "config.toml", folder / "hooks.json")}
    write_json(output / "profile.json", profile)
    return profile


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--bindings-json", type=Path, required=True)
    parser.add_argument("--upstream-json", type=Path, required=True)
    parser.add_argument("--tools-json", type=Path, required=True)
    parser.add_argument("--deployment-root", type=Path)
    parser.add_argument("--state-root", type=Path)
    parser.add_argument("--envelope-root", type=Path)
    args = parser.parse_args(argv)
    from .native_install import read_json
    value = build_bundle(args.output, bindings=read_json(args.bindings_json),
                         upstream=read_json(args.upstream_json), tools=read_json(args.tools_json),
                         deployment_root=args.deployment_root, state_root=args.state_root,
                         envelope_root=args.envelope_root)
    print(json.dumps({"protocol": value["protocol"], "vendor": value["vendor"],
                      "active_configs_changed": False, "live_acceptance": "NOT_RUN"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
