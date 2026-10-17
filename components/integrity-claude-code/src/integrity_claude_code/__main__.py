"""``python -m integrity_claude_code capabilities`` -- the only CLI command; fully offline."""
from __future__ import annotations

import json
import sys


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args != ["capabilities"]:
        sys.stderr.write("usage: python -m integrity_claude_code capabilities\n")
        return 2
    from .capabilities import capabilities
    print(json.dumps(capabilities(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
