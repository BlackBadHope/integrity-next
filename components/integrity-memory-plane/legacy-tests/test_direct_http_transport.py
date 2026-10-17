from __future__ import annotations

import json
import os
import threading
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar

import pytest

from memory_plane_common import (
    ACTION_LOG_READER_HEADER,
    DirectHttpTransportError,
    open_direct_http_request,
)

TOKEN = "synthetic-memory-plane-token"


@contextmanager
def server(handler: type[BaseHTTPRequestHandler]) -> Iterator[str]:
    instance = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{instance.server_port}"
    finally:
        instance.shutdown()
        thread.join(timeout=5)
        instance.server_close()


def sink_handler() -> type[BaseHTTPRequestHandler]:
    class Sink(BaseHTTPRequestHandler):
        requests: ClassVar[list[str]] = []

        def record(self) -> None:
            type(self).requests.append(
                self.headers.get(ACTION_LOG_READER_HEADER, "")
            )
            self.send_response(204)
            self.end_headers()

        do_GET = record
        do_POST = record

        def log_message(self, _format: str, *_args: object) -> None:
            return None

    return Sink


@pytest.mark.parametrize("method,status", (("GET", 302), ("POST", 307)))
def test_memory_plane_transport_denies_redirect_before_second_connection(
    method: str,
    status: int,
) -> None:
    sink = sink_handler()
    with server(sink) as sink_url:
        class Redirect(BaseHTTPRequestHandler):
            requests = 0

            def redirect(self) -> None:
                type(self).requests += 1
                self.send_response(status)
                self.send_header("Location", sink_url + "/capture")
                self.end_headers()

            do_GET = redirect
            do_POST = redirect

            def log_message(self, _format: str, *_args: object) -> None:
                return None

        with server(Redirect) as source_url:
            request = urllib.request.Request(
                source_url + "/protected",
                data=b"{}" if method == "POST" else None,
                headers={ACTION_LOG_READER_HEADER: TOKEN},
                method=method,
            )
            with pytest.raises(DirectHttpTransportError) as raised:
                open_direct_http_request(request, timeout=2)
    assert Redirect.requests == 1
    assert sink.requests == []
    assert TOKEN not in str(raised.value)


def test_memory_plane_transport_ignores_ambient_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proxy = sink_handler()

    class Target(BaseHTTPRequestHandler):
        requests = 0

        def do_GET(self) -> None:
            type(self).requests += 1
            payload = b'{"ok":true}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, _format: str, *_args: object) -> None:
            return None

    with server(proxy) as proxy_url, server(Target) as target_url:
        for name in ("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
            monkeypatch.setenv(name, proxy_url)
        monkeypatch.setenv("NO_PROXY", "")
        monkeypatch.setenv("no_proxy", "")
        request = urllib.request.Request(
            target_url + "/ok",
            headers={ACTION_LOG_READER_HEADER: TOKEN},
        )
        with open_direct_http_request(request, timeout=2) as response:
            assert json.loads(response.read()) == {"ok": True}
    assert Target.requests == 1
    assert proxy.requests == []
    assert os.environ.get("HTTP_PROXY") == proxy_url
