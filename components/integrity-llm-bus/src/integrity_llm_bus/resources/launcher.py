# SPDX-License-Identifier: Apache-2.0
"""Launch the owner's relay without inheriting terminal pipe handles."""
from __future__ import annotations

from integrity_llm_bus.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent


def start(targets: str = "grok", max_calls: int = 20, environment: dict | None = None,
          thread_id: str | None = None) -> int:
    state = Path(_integrity_value('state_directory'))
    if (state / "relay.pid").exists():
        raise RuntimeError("Existing relay PID manifest: inspect relay.ps1 status before another start")
    if not state.is_dir():
        raise RuntimeError("Initialize the local bus first")
    child_environment = os.environ.copy() if environment is None else environment.copy()
    if "grok" in targets and not (child_environment.get("GROKBOT_WEBHOOK_KEY") or child_environment.get("GROK_WEBHOOK_TOKEN")):
        raise RuntimeError("Grok process environment credential unavailable")
    if "codex" in targets and not thread_id:
        raise RuntimeError("The codex target requires an explicit thread id")
    command = [sys.executable, "-B", str(HERE / "relay.py"), "--watch",
               "--targets", targets, "--max-calls", str(max_calls)]
    if thread_id:
        command += ["--thread-id", thread_id]
    with (state / "relay.log").open("ab") as out, (state / "relay.err").open("ab") as err:
        process = subprocess.Popen(command,
                                   cwd=_integrity_value('path_dd2435d503a6'), env=child_environment, stdin=subprocess.DEVNULL,
                                   stdout=out, stderr=err, close_fds=True,
                                   creationflags=subprocess.CREATE_NO_WINDOW)
    return process.pid


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--targets", default="grok")
    parser.add_argument("--max-calls", type=int, default=20)
    parser.add_argument("--thread-id")
    args = parser.parse_args()
    print(json.dumps({"launched_pid": start(args.targets, args.max_calls, thread_id=args.thread_id)}))
