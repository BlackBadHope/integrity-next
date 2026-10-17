#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exec the fixed Integrity P2 loopback proxy target for a socket instance."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import os
import sys


TARGETS = {
    "4222": "192.0.2.3:4222",
    "18222": "192.0.2.3:8222",
    "55432": "192.0.2.2:5432",
}
PROXYD = "/usr/lib/systemd/systemd-socket-proxyd"


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in TARGETS:
        print("unsupported Integrity P2 proxy instance", file=sys.stderr)
        return 64
    os.execv(
        PROXYD,
        [PROXYD, "--connections-max=256", "--exit-idle-time=5min", TARGETS[sys.argv[1]]],
    )
    return 70


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
