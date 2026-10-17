# SPDX-License-Identifier: Apache-2.0
"""JSONL adapter to an existing Codex owner's local Unix WebSocket."""

from integrity_bridges.configuration import value as _integrity_value, require_config as _integrity_require_config
import sys
import threading

from websockets.sync.client import unix_connect


def main():
    with unix_connect(sys.argv[1], open_timeout=5, close_timeout=2, max_size=8 * 1024 * 1024) as connection:
        def receive():
            try:
                for message in connection:
                    raw = message.encode('utf-8') if isinstance(message, str) else message
                    sys.stdout.buffer.write(raw + b'\n')
                    sys.stdout.buffer.flush()
            finally:
                # Main stdin is owned by the parent; connection loss terminates this adapter.
                import os
                os._exit(0)
        threading.Thread(target=receive, daemon=True).start()
        for line in sys.stdin.buffer:
            connection.send(line.decode('utf-8').rstrip('\n'))


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == '__main__':
    main()
