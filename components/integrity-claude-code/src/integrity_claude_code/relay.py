"""Integrity MCP relay: stdio MCP server inside the Job, forwarding to the host coordinator.

Standalone by design: standard library only, never imports the package, launched as
``python -I -S -B relay.py``: isolated (no PYTHON* env, no user site, script directory
not on sys.path) and WITHOUT the site module, so no ``.pth`` file of the installation
runs before this code. It refuses to run unless those flags are set and every loaded
module comes from the interpreter's own installation. Trust boundary (stated): the
pinned interpreter's stdlib and DLLs are trusted as part of the interpreter identity;
they are not re-hashed here. It holds no key, permit or file access; it only frames
calls. Its digest is pinned in policy.
"""
import json
import os
import struct
import sys
import threading

PROTOCOLS = ("2025-11-25", "2025-06-18", "2025-03-26")
MAX_LINE = 8 * 1024 * 1024
MAX_FRAME = 8 * 1024 * 1024
TOOLS = [
    {"name": "read_file", "description": "Read one allowed UTF-8 text file (mediated).",
     "inputSchema": {"type": "object", "additionalProperties": False, "required": ["path"],
                     "properties": {"path": {"type": "string", "maxLength": 512}}}},
    {"name": "list_dir", "description": "List one directory (mediated).",
     "inputSchema": {"type": "object", "additionalProperties": False, "required": ["path"],
                     "properties": {"path": {"type": "string", "maxLength": 512}}}},
    {"name": "write_file",
     "description": "Replace or create one allowed file; expected_sha256 is the current "
                    "sha256:<hex> or 'absent' (mediated).",
     "inputSchema": {"type": "object", "additionalProperties": False,
                     "required": ["path", "content", "expected_sha256"],
                     "properties": {"path": {"type": "string", "maxLength": 512},
                                    "content": {"type": "string"},
                                    "expected_sha256": {"type": "string", "maxLength": 71}}}},
    {"name": "edit_file",
     "description": "Replace exactly one occurrence of old with new (mediated).",
     "inputSchema": {"type": "object", "additionalProperties": False,
                     "required": ["path", "old", "new", "expected_sha256"],
                     "properties": {"path": {"type": "string", "maxLength": 512},
                                    "old": {"type": "string"}, "new": {"type": "string"},
                                    "expected_sha256": {"type": "string", "maxLength": 71}}}},
]


def isolation_problem():
    if not (sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode):
        return "not_isolated"
    base = os.path.normcase(os.path.abspath(sys.base_prefix)) + os.sep
    me = os.path.normcase(os.path.abspath(__file__))
    for name, module in list(sys.modules.items()):
        origin = getattr(module, "__file__", None)
        if origin is None:
            continue
        origin = os.path.normcase(os.path.abspath(origin))
        if origin != me and not origin.startswith(base):
            return "foreign_module"
    return None


class Link:
    def __init__(self, name, nonce, run_id, timeout):
        self.stream = open(name, "r+b", buffering=0)
        self.timeout = timeout
        self.dead = False
        if not self.send({"type": "hello", "nonce": nonce, "run_id": run_id}) \
                or self.receive(timeout).get("type") != "hello_ok":
            raise SystemExit(4)

    def send(self, frame):
        """Complete, bounded write with a deadline; a failed/late write kills the link."""
        payload = json.dumps(frame, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False, allow_nan=False).encode("utf-8")
        if not 0 < len(payload) <= MAX_FRAME:
            self.dead = True
            return False
        data, box = struct.pack(">I", len(payload)) + payload, {}

        def write():
            try:
                view, offset = memoryview(data), 0
                while offset < len(data):
                    written = self.stream.write(view[offset:])
                    if not written:
                        raise OSError
                    offset += written
                box["ok"] = True
            except Exception:
                pass

        worker = threading.Thread(target=write, daemon=True)
        worker.start()
        worker.join(self.timeout)
        if worker.is_alive() or not box.get("ok"):
            self.dead = True
            return False
        return True

    def _exact(self, size):
        data = b""
        while len(data) < size:
            chunk = self.stream.read(size - len(data))
            if not chunk:
                raise EOFError
            data += chunk
        return data

    def receive(self, timeout):
        box = {}

        def read():
            try:
                (size,) = struct.unpack(">I", self._exact(4))
                if not 0 < size <= MAX_FRAME:
                    raise ValueError
                box["frame"] = json.loads(self._exact(size))
            except Exception:
                box["error"] = True

        worker = threading.Thread(target=read, daemon=True)
        worker.start()
        worker.join(timeout)
        if worker.is_alive() or "frame" not in box or type(box["frame"]) is not dict:
            self.dead = True  # never reuse a link whose last call has an unknown outcome
            return {}
        return box["frame"]


def reply(message_id, result=None, error=None):
    body = {"jsonrpc": "2.0", "id": message_id}
    body["error" if error else "result"] = error or result
    sys.stdout.write(json.dumps(body, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def main():
    problem = isolation_problem()
    if problem:
        sys.stderr.write("relay refused: " + problem + "\n")
        return 3
    link = Link(os.environ["INTEGRITY_RELAY_PIPE"], os.environ["INTEGRITY_RELAY_NONCE"],
                os.environ["INTEGRITY_RELAY_RUN"], int(os.environ.get("INTEGRITY_RELAY_TIMEOUT", "60")))
    sequence = 0
    stdin = sys.stdin.buffer
    while True:
        line = stdin.readline(MAX_LINE + 1)  # bounded: never buffers an unbounded line
        if not line:
            break
        if len(line) > MAX_LINE:
            return 5
        try:
            message = json.loads(line.decode("utf-8", errors="strict"))
        except ValueError:
            continue
        if type(message) is not dict:
            continue
        method, message_id = message.get("method"), message.get("id")
        if message_id is None:
            continue  # notifications (initialized, cancelled): nothing to do
        if method == "initialize":
            asked = (message.get("params") or {}).get("protocolVersion")
            reply(message_id, {"protocolVersion": asked if asked in PROTOCOLS else PROTOCOLS[0],
                               "capabilities": {"tools": {"listChanged": False}},
                               "serverInfo": {"name": "integrity", "version": "0.1.0rc2"}})
        elif method == "tools/list":
            reply(message_id, {"tools": TOOLS})
        elif method == "ping":
            reply(message_id, {})
        elif method == "tools/call":
            params = message.get("params") or {}
            if link.dead:
                reply(message_id, {"content": [{"type": "text", "text": "relay unavailable"}],
                                   "isError": True})
                continue
            sequence += 1
            sent = link.send({"type": "call", "seq": sequence, "tool": params.get("name"),
                              "arguments": params.get("arguments")})
            answer = link.receive(link.timeout) if sent else {}
            ok = answer.get("type") == "result" and answer.get("seq") == sequence and answer.get("ok") is True
            text = answer.get("text") if type(answer.get("text")) is str else "call failed"
            reply(message_id, {"content": [{"type": "text", "text": text}], "isError": not ok})
        else:
            reply(message_id, error={"code": -32601, "message": "method not found"})
    return 0


if __name__ == "__main__":
    sys.exit(main())
