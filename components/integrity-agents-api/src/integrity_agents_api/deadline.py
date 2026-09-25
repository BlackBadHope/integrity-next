"""One monotonic I/O lifetime, including terminable, keyless DNS resolution.

No retry or credential lookup. Caller owns host custody and the SDK permit.
Every raw read uses the remaining lifetime; duplicate shutdown is defense in depth.
"""
from __future__ import annotations

import io
import ipaddress
import json
import os
import socket
import subprocess
import sys
import threading
import time


class DeadlineExceeded(TimeoutError):
    """Outcome may be unknown; callers must not replay a sent request."""


class Lifetime:
    def __init__(self, seconds: float):
        self.until = time.monotonic() + seconds
        self._lock = threading.Lock()
        self._sockets = []
        self._closed = False
        self._expired = False
        self._timer = threading.Timer(max(0, seconds), self._expire)
        self._timer.daemon = True
        self._timer.start()

    def remaining(self):
        left = self.until - time.monotonic()
        if left <= 0 or self._expired or self._closed:
            raise DeadlineExceeded("http_absolute_deadline")
        return left

    def _expire(self):
        with self._lock:
            self._expired = True
            for sock in self._sockets:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def track(self, sock):
        duplicate = sock.dup()
        with self._lock:
            if self._expired or self._closed or time.monotonic() >= self.until:
                duplicate.close()
                raise DeadlineExceeded("http_absolute_deadline")
            self._sockets.append(duplicate)
        sock.settimeout(self.remaining())

    def connect(self, address, timeout=None, source_address=None, **kwargs):
        host, port = address
        candidates = resolve(host, port, self)
        error = None
        for family, kind, protocol, sockaddr in candidates:
            self.remaining()
            sock = socket.socket(family, kind, protocol)
            try:
                self.track(sock)
                if source_address:
                    sock.bind(source_address)
                sock.connect(tuple(sockaddr))
                sock.settimeout(self.remaining())
                return sock
            except OSError as exc:
                sock.close()
                error = exc
        if error:
            raise error
        raise OSError("dns_no_stream_address")

    def close(self):
        self._timer.cancel()
        with self._lock:
            self._closed = True
            for sock in self._sockets:
                sock.close()
            self._sockets.clear()
        self._timer.join(timeout=1)


# Never passes request bytes, credentials or parent globals to a DNS subprocess.
_DNS_CODE = (
    "import json,socket,sys; h,p=json.loads(sys.stdin.buffer.read(4096)); "
    "v=socket.getaddrinfo(h,p,type=socket.SOCK_STREAM); "
    "print(json.dumps([(a,b,c,e) for a,b,c,d,e in v[:16]]))"
)


def resolve(host, port, lifetime):
    try:
        numeric = ipaddress.ip_address(host)
    except ValueError:
        numeric = None
    if numeric is not None:
        family = socket.AF_INET6 if numeric.version == 6 else socket.AF_INET
        address = (str(numeric), port, 0, 0) if numeric.version == 6 else (str(numeric), port)
        return [(family, socket.SOCK_STREAM, 0, address)]
    environment = {"PATH": os.defpath}
    if os.name == "nt":
        environment["SystemRoot"] = os.environ.get("SystemRoot", "C:\\Windows")
    child = subprocess.Popen(
        [sys.executable, "-I", "-S", "-c", _DNS_CODE], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=environment,
    )
    try:
        output, _ = child.communicate(json.dumps([host, port]).encode(),
                                      timeout=lifetime.remaining())
        lifetime.remaining()
        if child.returncode or len(output) > 16384:
            raise OSError("dns_resolution_failed")
        rows = json.loads(output)
        if not isinstance(rows, list) or not 1 <= len(rows) <= 16:
            raise OSError("dns_resolution_failed")
        for row in rows:
            family, kind, protocol, address = row
            if (family not in (socket.AF_INET, socket.AF_INET6)
                    or kind != socket.SOCK_STREAM or not isinstance(protocol, int)
                    or ipaddress.ip_address(address[0]).version != (6 if family == socket.AF_INET6 else 4)
                    or address[1] != port):
                raise OSError("dns_address_rejected")
        return rows
    except subprocess.TimeoutExpired:
        raise DeadlineExceeded("dns_absolute_deadline") from None
    finally:
        if child.poll() is None:
            child.kill()
        child.communicate(timeout=2)


class DeadlineSocket:
    """HTTPResponse socket facade: no slow peer can renew a raw-read timeout."""
    def __init__(self, sock, lifetime):
        self.sock, self.lifetime = sock, lifetime

    def makefile(self, mode):
        if mode != "rb":
            raise ValueError("response_read_only")
        return io.BufferedReader(_DeadlineReader(self.sock, self.lifetime))


class _DeadlineReader(io.RawIOBase):
    def __init__(self, sock, lifetime):
        super().__init__()
        self.sock, self.lifetime = sock, lifetime
        self.raw = sock.makefile("rb", buffering=0)

    def readable(self):
        return True

    def readinto(self, buffer):
        self.sock.settimeout(self.lifetime.remaining())
        count = self.raw.readinto(buffer)
        self.lifetime.remaining()
        return count

    def close(self):
        try:
            self.raw.close()
        finally:
            super().close()


def bind_connection(connection, lifetime):
    """Bind actual HTTP sockets; mock peers need not implement connection internals."""
    original_connect = getattr(connection, "connect", None)
    original_send = getattr(connection, "send", None)
    if original_connect is not None:
        def connect():
            lifetime.remaining()
            original_connect()
            connection.sock.settimeout(lifetime.remaining())
        connection.connect = connect
    if original_send is not None:
        def send(data):
            lifetime.remaining()
            if connection.sock is not None:
                connection.sock.settimeout(lifetime.remaining())
            original_send(data)
            lifetime.remaining()
        connection.send = send
    response_class = getattr(connection, "response_class", None)
    if response_class is not None:
        connection.response_class = lambda sock, **kwargs: response_class(
            DeadlineSocket(sock, lifetime), **kwargs)
