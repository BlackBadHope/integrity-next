"""Bounded HTTPS downloads with DNS and redirect SSRF protection.

The resolved socket address is the address that is actually connected.  TLS
still authenticates the original hostname through SNI and certificate hostname
verification, avoiding the usual resolve-check-then-resolve-again race.
"""

from __future__ import annotations

from collections.abc import Mapping
from hashlib import sha256
import http.client
import ipaddress
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

from integrity_chronicle.json_integrity import (
    DuplicateJsonKeyError,
    loads_json_strict,
)

from .work_import import MaterializedFile, WorkFileRef, WorkImportError


MAX_REDIRECTS = 3
MAX_URL_CHARS = 8_192
_REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})


class SecureHTTPSError(ValueError):
    """Fail-closed HTTPS transport error without private network details."""


def _validated_url(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_URL_CHARS
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise SecureHTTPSError("HTTPS URL is invalid")
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError as err:
        raise SecureHTTPSError("HTTPS URL is invalid") from err
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or port not in (None, 443)
    ):
        raise SecureHTTPSError("HTTPS URL is invalid")
    hostname = parsed.hostname.casefold()
    if not hostname.isascii():
        raise SecureHTTPSError("HTTPS URL host is not allowed")
    if hostname == "localhost" or hostname.endswith(".localhost"):
        raise SecureHTTPSError("HTTPS URL host is not allowed")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        address = None
    if address is not None and not address.is_global:
        raise SecureHTTPSError("HTTPS URL host is not allowed")
    return value


def _global_addresses(hostname: str, port: int) -> list[tuple[int, int, int, tuple]]:
    try:
        records = socket.getaddrinfo(
            hostname,
            port,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
    except OSError as err:
        raise SecureHTTPSError("HTTPS host resolution failed") from err
    prepared: list[tuple[int, int, int, tuple]] = []
    seen: set[tuple[int, str]] = set()
    for family, socktype, proto, _, sockaddr in records:
        try:
            address = ipaddress.ip_address(sockaddr[0])
        except ValueError as err:
            raise SecureHTTPSError("HTTPS host resolution is invalid") from err
        if not address.is_global:
            raise SecureHTTPSError("HTTPS host resolved outside the public network")
        key = (family, str(address))
        if key not in seen:
            seen.add(key)
            prepared.append((family, socktype, proto, sockaddr))
    if not prepared:
        raise SecureHTTPSError("HTTPS host resolution failed")
    return prepared


class SecureHTTPSClient:
    """Small dependency-free HTTPS client for trusted-size downloads."""

    def __init__(
        self,
        *,
        timeout_seconds: float = 15.0,
        ssl_context: ssl.SSLContext | None = None,
    ):
        if not 0.1 <= timeout_seconds <= 120.0:
            raise SecureHTTPSError("HTTPS timeout is invalid")
        self._timeout = timeout_seconds
        self._ssl_context = ssl_context or ssl.create_default_context()

    def _single_get(
        self,
        url: str,
        *,
        max_bytes: int,
        accept: str,
    ) -> tuple[int, Mapping[str, str], bytes]:
        parsed = urlsplit(_validated_url(url))
        hostname = parsed.hostname
        assert hostname is not None
        port = 443
        target = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        host_header = (
            f"[{hostname}]" if ":" in hostname and not hostname.startswith("[") else hostname
        )
        last_error: Exception | None = None
        for family, socktype, proto, sockaddr in _global_addresses(hostname, port):
            raw_socket: socket.socket | None = None
            tls_socket: ssl.SSLSocket | None = None
            response: http.client.HTTPResponse | None = None
            try:
                raw_socket = socket.socket(family, socktype, proto)
                raw_socket.settimeout(self._timeout)
                raw_socket.connect(sockaddr)
                tls_socket = self._ssl_context.wrap_socket(
                    raw_socket,
                    server_hostname=hostname,
                )
                raw_socket = None
                request = (
                    f"GET {target} HTTP/1.1\r\n"
                    f"Host: {host_header}\r\n"
                    f"Accept: {accept}\r\n"
                    "User-Agent: Integrity-Home/0.1\r\n"
                    "Connection: close\r\n\r\n"
                ).encode("ascii")
                tls_socket.sendall(request)
                response = http.client.HTTPResponse(tls_socket)
                response.begin()
                header_pairs = response.getheaders()
                for singleton in ("content-length", "location"):
                    if (
                        sum(
                            1
                            for key, _ in header_pairs
                            if key.casefold() == singleton
                        )
                        > 1
                    ):
                        raise SecureHTTPSError(
                            "HTTPS response contains ambiguous headers"
                        )
                headers = {
                    key.casefold(): value for key, value in header_pairs
                }
                content_length = headers.get("content-length")
                if content_length is not None:
                    try:
                        declared = int(content_length)
                    except ValueError as err:
                        raise SecureHTTPSError(
                            "HTTPS response has invalid content length"
                        ) from err
                    if declared < 0 or declared > max_bytes:
                        raise SecureHTTPSError("HTTPS response exceeds the byte limit")
                body = response.read(max_bytes + 1)
                if len(body) > max_bytes:
                    raise SecureHTTPSError("HTTPS response exceeds the byte limit")
                return response.status, headers, body
            except (OSError, ssl.SSLError, http.client.HTTPException) as err:
                last_error = err
            finally:
                if response is not None:
                    response.close()
                if tls_socket is not None:
                    tls_socket.close()
                if raw_socket is not None:
                    raw_socket.close()
        raise SecureHTTPSError("HTTPS request failed") from last_error

    def get_bytes(
        self,
        url: str,
        *,
        max_bytes: int,
        accept: str = "application/octet-stream",
    ) -> bytes:
        if isinstance(max_bytes, bool) or not 1 <= max_bytes <= 1024 * 1024 * 1024:
            raise SecureHTTPSError("HTTPS byte limit is invalid")
        current = _validated_url(url)
        for redirect_count in range(MAX_REDIRECTS + 1):
            status, headers, body = self._single_get(
                current,
                max_bytes=max_bytes,
                accept=accept,
            )
            if status == 200:
                return body
            if status not in _REDIRECT_CODES or redirect_count == MAX_REDIRECTS:
                raise SecureHTTPSError("HTTPS request returned an unexpected status")
            location = headers.get("location")
            if not location:
                raise SecureHTTPSError("HTTPS redirect is missing a destination")
            current = _validated_url(urljoin(current, location))
        raise SecureHTTPSError("HTTPS redirect limit exceeded")

    def get_json(self, url: str, *, max_bytes: int = 1024 * 1024) -> Mapping[str, Any]:
        raw = self.get_bytes(
            url,
            max_bytes=max_bytes,
            accept="application/json",
        )
        try:
            payload = loads_json_strict(raw.decode("utf-8"))
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            DuplicateJsonKeyError,
        ) as err:
            raise SecureHTTPSError("HTTPS endpoint returned invalid JSON") from err
        if not isinstance(payload, Mapping):
            raise SecureHTTPSError("HTTPS endpoint returned invalid JSON")
        return payload


class HTTPSFileMaterializer:
    """Materialize an Apps SDK temporary file URL into a fixed inbox slot."""

    def __init__(self, client: SecureHTTPSClient | None = None):
        self._client = client or SecureHTTPSClient()

    def materialize(
        self,
        source: WorkFileRef,
        destination: Path,
        *,
        max_bytes: int,
    ) -> MaterializedFile:
        if not isinstance(source, WorkFileRef):
            raise WorkImportError("file attachment is invalid")
        parent = destination.parent
        try:
            parent_resolved = parent.resolve(strict=True)
            destination_resolved = destination.resolve(strict=False)
            destination_resolved.relative_to(parent_resolved)
        except (OSError, RuntimeError, ValueError) as err:
            raise WorkImportError("file destination is unsafe") from err
        if (
            parent.is_symlink()
            or not parent.is_dir()
            or destination.exists()
            or destination.is_symlink()
        ):
            raise WorkImportError("file destination is unsafe")
        try:
            body = self._client.get_bytes(
                source.download_url,
                max_bytes=max_bytes,
            )
        except SecureHTTPSError as err:
            raise WorkImportError("file attachment download failed closed") from err
        temporary = parent / (
            f".{destination.name}.{secrets.token_urlsafe(12)}.part"
        )
        try:
            with temporary.open("xb") as stream:
                stream.write(body)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.chmod(temporary, 0o600)
            except OSError:
                pass
            os.replace(temporary, destination)
        except OSError as err:
            temporary.unlink(missing_ok=True)
            raise WorkImportError("file attachment could not be stored") from err
        return MaterializedFile(
            byte_length=len(body),
            sha256=sha256(body).hexdigest(),
        )


__all__ = [
    "HTTPSFileMaterializer",
    "MAX_REDIRECTS",
    "SecureHTTPSClient",
    "SecureHTTPSError",
]
