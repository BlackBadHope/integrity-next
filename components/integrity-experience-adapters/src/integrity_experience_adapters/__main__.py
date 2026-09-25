"""Bounded offline CLI. Output is always an unsigned candidate document."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import contracts as c


def read_bounded(filename: str) -> bytes:
    with Path(filename).open("rb") as stream:
        raw = stream.read(c.MAX_JSON_BYTES + 1)
    c.require(len(raw) <= c.MAX_JSON_BYTES, "input_size_limit")
    return raw


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("capabilities", "memory-estimate", "transcript",
                                              "workplan", "preview", "parity"))
    parser.add_argument("files", nargs="*")
    args = parser.parse_args()
    expected = 0 if args.operation == "capabilities" else 2 if args.operation == "parity" else 1
    if len(args.files) != expected:
        parser.error(f"{args.operation} requires {expected} input file(s)")
    try:
        if args.operation == "capabilities":
            result = c.capabilities()
        elif args.operation == "parity":
            result = c.compare_contract(*(read_bounded(f) for f in args.files))
        elif args.operation == "preview":
            result = c.inert_preview(read_bounded(args.files[0]).decode("utf-8"))
        else:
            handlers = {"memory-estimate": c.estimate_memory, "transcript": c.transcript_observation,
                        "workplan": c.validate_workplan}
            result = handlers[args.operation](c.load_json(read_bounded(args.files[0])))
        print(c.canonical(result).decode("utf-8"))
        return 1 if args.operation == "parity" and not result["payload"]["equal"] else 0
    except (c.ContractError, OSError, UnicodeError):
        # No filesystem paths, transcript text, credentials or provider response are echoed.
        print(json.dumps({"status": "rejected", "error": "invalid_or_unreadable_input"}),
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
