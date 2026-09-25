"""Bounded JSONL on caller-owned, already initialized app-server streams.

No process spawn, connection discovery, credentials, initialization, turn/start,
thread/resume, tools, or automatic retries. Give this object a dedicated stream
or a host-demultiplexed channel, not one concurrently read by another client.
"""

from __future__ import annotations

import asyncio
import json
import math
from typing import Any, Protocol

from .policy import positive


class ProtocolError(ValueError):
    """Malformed or oversized transport data; raw content is never in the error."""


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError("duplicate JSON key")
        result[key] = value
    return result


def _constant(_: str) -> None:
    raise ProtocolError("non-finite JSON number")


def _float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ProtocolError("non-finite JSON float")
    return number



def validate_message(message: object) -> None:
    """Reject ambiguous JSON-RPC directions before interpreting any lifecycle data.

    Codex omits jsonrpc on stdio. An explicit version must be exactly 2.0.
    Payloads remain forward-compatible; the envelope cannot combine a request,
    response and notification or impersonate an omitted method with JSON null.
    """
    if type(message) is not dict:
        raise ProtocolError("message is not an object")
    if "jsonrpc" in message and message["jsonrpc"] != "2.0":
        raise ProtocolError("unsupported JSON-RPC version")
    keys = set(message) - {"jsonrpc"}
    if "id" in message:
        request_id = message["id"]
        if type(request_id) not in (str, int) or not 0 < len(str(request_id)) <= 256:
            raise ProtocolError("invalid request identity")
    if "method" in message:
        method = message["method"]
        if not isinstance(method, str) or not 0 < len(method) <= 256:
            raise ProtocolError("invalid method")
        expected = {"method", "params"} | ({"id"} if "id" in message else set())
        if keys != expected or type(message["params"]) is not dict:
            raise ProtocolError("ambiguous request or notification envelope")
    elif keys not in ({"id", "result"}, {"id", "error"}):
        raise ProtocolError("invalid response envelope")
    elif "error" in message and type(message["error"]) is not dict:
        raise ProtocolError("invalid response error")


class EventConnection(Protocol):
    async def receive(self, timeout: float) -> dict[str, Any] | None:
        """Return one message, None on EOF, or raise TimeoutError."""
        ...

    async def send(self, message: dict[str, Any]) -> None: ...


class JsonlConnection:
    def __init__(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
        *, max_frame_bytes: int = 65536,
    ) -> None:
        if type(max_frame_bytes) is not int or not 1024 <= max_frame_bytes <= 1048576:
            raise ValueError("invalid frame bound")
        self.reader = reader
        self.writer = writer
        self.max_frame_bytes = max_frame_bytes
        # StreamReader must ALSO be created with limit <= max_frame_bytes;
        # its own limit prevents allocation before our post-read length check.
        if reader._limit > max_frame_bytes:
            raise ValueError("StreamReader limit exceeds frame bound")

    async def receive(self, timeout: float) -> dict[str, Any] | None:
        positive(timeout)
        try:
            raw = await asyncio.wait_for(self.reader.readline(), timeout)
        except (ValueError, asyncio.LimitOverrunError) as exc:
            raise ProtocolError("JSONL frame exceeds reader limit") from exc
        if not raw:
            return None
        if len(raw) > self.max_frame_bytes or not raw.endswith(b"\n"):
            raise ProtocolError("oversized or unterminated JSONL frame")
        try:
            result = json.loads(raw.decode("utf-8"), object_pairs_hook=_object,
                                parse_constant=_constant, parse_float=_float)
        except (UnicodeError, ValueError, RecursionError) as exc:
            raise ProtocolError("invalid JSONL object") from exc
        if not isinstance(result, dict):
            raise ProtocolError("JSONL message is not an object")
        return result

    async def send(self, message: dict[str, Any]) -> None:
        # This surface deliberately cannot start work or grant permissions.
        validate_message(message)
        method = message.get("method")
        interrupt = method == "turn/interrupt" and set(message) == {"id", "method", "params"}
        denial = method is None and set(message) in ({"id", "result"}, {"id", "error"}) and (
            message.get("result") in ({"decision": "decline"},
                                       {"permissions": {}, "scope": "turn"},
                                       {"action": "decline", "content": None})
            or message.get("error") == {"code": -32601, "message": "Unsupported by supervisor"}
        )
        if interrupt:
            params = message["params"]
            interrupt = isinstance(params, dict) and set(params) == {"threadId", "turnId"} and all(
                isinstance(value, str) and 0 < len(value) <= 256 for value in params.values()
            )
        valid_id = type(message.get("id")) in (str, int) and len(str(message["id"])) <= 256
        if not (valid_id and (interrupt or denial)):
            raise ProtocolError("outgoing operation is not interrupt or denial")
        raw = (json.dumps(message, allow_nan=False, separators=(",", ":")) + "\n").encode()
        if len(raw) > self.max_frame_bytes:
            raise ProtocolError("outgoing frame exceeds limit")
        self.writer.write(raw)
        await self.writer.drain()
