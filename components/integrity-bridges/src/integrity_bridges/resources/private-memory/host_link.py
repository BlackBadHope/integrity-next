# SPDX-License-Identifier: Apache-2.0
"""Hidden Windows host node and outgoing SSH forward, supervised as one task."""
from __future__ import annotations

from integrity_bridges.configuration import configured_command, require_config as _integrity_require_config

import json
import subprocess
import sys
import time
from pathlib import Path


def main():
    config = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    flags = subprocess.CREATE_NO_WINDOW
    log_path = Path(config["log"])
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("ab", buffering=0) as log:
        node = subprocess.Popen(config["node"], stdin=subprocess.DEVNULL, stdout=log, stderr=log, creationflags=flags)
        forward = None
        try:
            while node.poll() is None:
                forward = subprocess.Popen(config[configured_command('ssh_command', 'command_7f5a55cf3f88')], stdin=subprocess.DEVNULL, stdout=log, stderr=log, creationflags=flags)
                while forward.poll() is None and node.poll() is None:
                    time.sleep(1)
                if forward.poll() is None:
                    forward.terminate()
                    forward.wait(5)
                log.write((time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()) + " forward disconnected; reconnect in 10s\n").encode())
                time.sleep(10)
        finally:
            for proc in (forward, node):
                if proc is not None and proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(5)
                    except subprocess.TimeoutExpired:
                        proc.kill()


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    main()
