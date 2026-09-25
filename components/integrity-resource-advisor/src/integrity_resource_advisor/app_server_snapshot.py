"""Bounded read-only Codex App Server snapshot over a caller-owned process."""
from __future__ import annotations

import argparse
import json
import queue
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, BinaryIO, Sequence

from .metering import AdviceError

MAX_MESSAGE_BYTES = 256 * 1024
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_PAGES = 16
MAX_MODELS = 512
ALLOWED_REQUESTS = frozenset({"initialize", "model/list", "account/rateLimits/read"})


def _decode(raw: bytes) -> dict[str, Any]:
    if not raw.endswith(b"\n") or len(raw) > MAX_MESSAGE_BYTES:
        raise AdviceError("app-server-frame-bound")
    try:
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate")
                result[key] = value
            return result
        value = json.loads(raw, object_pairs_hook=unique)
    except (UnicodeError, json.JSONDecodeError, ValueError):
        raise AdviceError("app-server-invalid-response") from None
    if type(value) is not dict:
        raise AdviceError("app-server-invalid-response")
    return value


class _Reader(threading.Thread):
    def __init__(self, stream: BinaryIO, output: queue.Queue):
        super().__init__(daemon=True)
        self.stream, self.output = stream, output

    def run(self) -> None:
        consumed = 0
        try:
            while True:
                raw = self.stream.readline(MAX_MESSAGE_BYTES + 2)
                if not raw:
                    self.output.put(("eof", None))
                    return
                consumed += len(raw)
                if consumed > MAX_RESPONSE_BYTES:
                    self.output.put(("error", "app-server-response-bound"))
                    return
                self.output.put(("message", _decode(raw)))
        except AdviceError as error:
            self.output.put(("error", str(error)))
        except OSError:
            self.output.put(("error", "app-server-read-failed"))


class ReadOnlyAppServerClient:
    """One-connection client that can only initialize and read models/limits."""

    def __init__(self, command: Sequence[str], *, timeout: float = 30.0):
        if (not isinstance(command, (list, tuple)) or not command
                or any(type(part) is not str or not part for part in command)):
            raise AdviceError("app-server-command-required")
        if type(timeout) not in (int, float) or isinstance(timeout, bool) or not 0 < timeout <= 60:
            raise AdviceError("app-server-deadline-bound")
        self.deadline = time.monotonic() + float(timeout)
        try:
            self.process = subprocess.Popen(
                list(command), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, bufsize=0,
            )
        except OSError:
            raise AdviceError("app-server-start-failed") from None
        if self.process.stdin is None or self.process.stdout is None:
            self.close()
            raise AdviceError("app-server-pipe-required")
        self.messages: queue.Queue = queue.Queue()
        self.reader = _Reader(self.process.stdout, self.messages)
        self.reader.start()
        self.next_id = 1
        self.sent_methods: list[str] = []

    def close(self) -> None:
        process = getattr(self, "process", None)
        if process is None:
            return
        try:
            if process.stdin:
                process.stdin.close()
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            if process.poll() is None:
                process.kill()
                process.wait(timeout=2)
        finally:
            if process.stdout:
                process.stdout.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def _write(self, message: dict[str, Any]) -> None:
        raw = json.dumps(message, ensure_ascii=True, separators=(",", ":")).encode() + b"\n"
        if len(raw) > MAX_MESSAGE_BYTES:
            raise AdviceError("app-server-frame-bound")
        try:
            self.process.stdin.write(raw)
            self.process.stdin.flush()
        except (AttributeError, BrokenPipeError, OSError):
            raise AdviceError("app-server-write-failed") from None

    def _next(self) -> dict[str, Any]:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise AdviceError("app-server-deadline")
        try:
            kind, value = self.messages.get(timeout=remaining)
        except queue.Empty:
            raise AdviceError("app-server-deadline") from None
        if kind == "eof":
            raise AdviceError("app-server-eof")
        if kind == "error":
            raise AdviceError(value)
        return value

    def _request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        if method not in ALLOWED_REQUESTS:
            raise AdviceError("app-server-method-not-allowed")
        request_id = self.next_id
        self.next_id += 1
        message: dict[str, Any] = {"method": method, "id": request_id}
        if params is not None:
            if type(params) is not dict:
                raise AdviceError("app-server-params-shape")
            message["params"] = params
        self._write(message)
        self.sent_methods.append(method)
        while True:
            response = self._next()
            if "id" not in response:
                if type(response.get("method")) is not str:
                    raise AdviceError("app-server-invalid-response")
                continue
            if response.get("id") != request_id:
                raise AdviceError("app-server-response-id-mismatch")
            if "error" in response:
                raise AdviceError("app-server-request-failed")
            result = response.get("result")
            if type(result) is not dict:
                raise AdviceError("app-server-result-shape")
            return result

    def initialize(self) -> None:
        self._request("initialize", {"clientInfo": {
            "name": "integrity_resource_advisor", "title": "Integrity Resource Advisor",
            "version": "0.1.0rc5",
        }})
        self._write({"method": "initialized", "params": {}})

    def snapshot(self) -> dict[str, Any]:
        self.initialize()
        models: list[dict[str, Any]] = []
        identities: set[str] = set()
        cursors: set[str] = set()
        cursor: str | None = None
        for _ in range(MAX_PAGES):
            params: dict[str, Any] = {"limit": 100, "includeHidden": False}
            if cursor is not None:
                params["cursor"] = cursor
            page = self._request("model/list", params)
            rows, next_cursor = page.get("data"), page.get("nextCursor")
            if type(rows) is not list or not all(type(row) is dict for row in rows):
                raise AdviceError("app-server-catalog-shape")
            for row in rows:
                model = row.get("model")
                identifier = row.get("id")
                if type(model) is not str or not model or type(identifier) is not str or not identifier:
                    raise AdviceError("app-server-model-identity")
                if model in identities or identifier in identities:
                    raise AdviceError("app-server-model-duplicate")
                identities.update((model, identifier))
                models.append(row)
                if len(models) > MAX_MODELS:
                    raise AdviceError("app-server-model-bound")
            if next_cursor is None:
                break
            if type(next_cursor) is not str or not next_cursor or next_cursor in cursors:
                raise AdviceError("app-server-cursor-invalid")
            cursors.add(next_cursor)
            cursor = next_cursor
        else:
            raise AdviceError("app-server-page-bound")
        limits = self._request("account/rateLimits/read")
        observed = int(time.time())
        return {
            "protocol": "integrity-resource-advisor/app-server-read-snapshot/v1",
            "complete": True,
            "catalog": {"data": models, "nextCursor": None},
            "rate_limits": _rate_limits(limits, observed),
            "observed_at": observed,
            "quality_measured": False,
            "rpc_methods_sent": list(self.sent_methods),
            "turn_start_sent": 0,
        }


def _integer_or_unknown(value: Any) -> int | None:
    return value if type(value) is int else None


def _window(value: Any) -> dict[str, int | None] | None:
    if value is None:
        return None
    if type(value) is not dict:
        raise AdviceError("app-server-limit-shape")
    return {key: _integer_or_unknown(value.get(key))
            for key in ("windowDurationMins", "usedPercent", "resetsAt")}


def _rate_limits(result: dict[str, Any], observed: int) -> dict[str, Any]:
    multi = result.get("rateLimitsByLimitId")
    if multi is not None and type(multi) is not dict:
        raise AdviceError("app-server-limit-shape")
    rows = list(multi.values()) if multi else [result.get("rateLimits")]
    buckets = []
    for row in rows:
        if row is None:
            continue
        if type(row) is not dict:
            raise AdviceError("app-server-limit-shape")
        limit_id = row.get("limitId")
        if limit_id is not None and type(limit_id) is not str:
            raise AdviceError("app-server-limit-shape")
        buckets.append({"limitId": limit_id, "primary": _window(row.get("primary")),
                        "secondary": _window(row.get("secondary"))})
    return {"observedAt": observed, "buckets": buckets,
            "unknown": not buckets or any(bucket["limitId"] is None for bucket in buckets)}


def collect_snapshot(command: Sequence[str], *, timeout: float = 30.0) -> dict[str, Any]:
    with ReadOnlyAppServerClient(command, timeout=timeout) as client:
        return client.snapshot()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codex", type=Path, required=True,
                        help="exact trusted codex executable path")
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()
    if not args.codex.is_file():
        parser.error("--codex must name an existing file")
    try:
        command = (str(args.codex), "app-server", "-c", "mcp_servers={}",
                   "-c", "hooks={}", "-c", "notify=[]",
                   "-c", "analytics.enabled=false", "--listen", "stdio://")
        result = collect_snapshot(command, timeout=args.timeout)
    except AdviceError as error:
        raise SystemExit("snapshot failed: " + str(error)) from None
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
