"""Server-side WebRTC SDP exchange and a narrowly authenticated WSGI endpoint.

No credential is read from environment, logged or sent to a browser. The
hosting application must supply its existing SDK-bound dispatcher; there is
no default permit, public approval endpoint, automatic retry or server launcher.
"""
from __future__ import annotations

import hashlib
import hmac
import http.client
import secrets
import ssl
import threading
import time
from contextlib import ExitStack
from dataclasses import dataclass, field
from typing import Any, Callable

from . import contracts as c
from ._deadline import Lifetime, bind_connection


def validate_sdp(raw: bytes) -> bytes:
    c.require(type(raw) is bytes and 5 <= len(raw) <= 65536, "sdp_size_limit")
    c.require(raw.startswith((b"v=0\r\n", b"v=0\n")) and b"\x00" not in raw,
              "invalid_sdp")
    try:
        raw.decode("utf-8")
    except UnicodeError as exc:
        raise c.ContractError("invalid_sdp_encoding") from exc
    return raw


class ProviderUnknown(c.ContractError):
    """Provider outcome is unknown after dispatch; automatic retry is forbidden."""


class OpenAIWebRTC:
    def __init__(self, api_key: str, model: str, *, voice: str = "marin") -> None:
        c.require(type(api_key) is str and 20 <= len(api_key) <= 1024
                  and all(32 < ord(char) < 127 for char in api_key), "invalid_server_credential")
        c.require(type(model) is str and bool(model) and len(model) <= 128
                  and all(char.isalnum() or char in "-_." for char in model), "invalid_model")
        c.require(voice in ("marin", "cedar"), "voice_not_allowlisted")
        self.__key = api_key
        self.model, self.voice = model, voice

    def exchange(self, offer: bytes, principal: str) -> bytes:
        validate_sdp(offer)
        c.text(principal, 256)
        boundary = "integrity-" + secrets.token_hex(24)
        c.require(boundary.encode() not in offer, "multipart_boundary_collision")
        config = c.canonical({"type": "realtime", "model": self.model,
            "audio": {"output": {"voice": self.voice}}, "tools": [],
            "tool_choice": "none", "max_output_tokens": 256})
        body = (f'--{boundary}\r\nContent-Disposition: form-data; name="sdp"\r\n\r\n'.encode()
                + offer + f'\r\n--{boundary}\r\nContent-Disposition: form-data; name="session"\r\n'
                'Content-Type: application/json\r\n\r\n'.encode()
                + config + f'\r\n--{boundary}--\r\n'.encode())
        try:
            with ExitStack() as cleanup:
                lifetime = Lifetime(15)
                cleanup.callback(lifetime.close)
                connection = http.client.HTTPSConnection(
                    "api.openai.com", timeout=lifetime.remaining(), context=ssl.create_default_context())
                cleanup.callback(connection.close)
                bind_connection(connection, lifetime)
                lifetime.remaining()
                connection.request("POST", "/v1/realtime/calls", body, {
                    "Authorization": "Bearer " + self.__key,
                    "Content-Type": "multipart/form-data; boundary=" + boundary,
                    "OpenAI-Safety-Identifier": hashlib.sha256(principal.encode()).hexdigest(),
                })
                lifetime.remaining()
                response = connection.getresponse()
                close_response = getattr(response, "close", None)
                if close_response is not None:
                    cleanup.callback(close_response)
                lifetime.remaining()
                c.require(response.status in (200, 201), "provider_request_failed")
                c.require(response.getheader("Content-Type", "").split(";", 1)[0]
                          == "application/sdp", "provider_response_type")
                answer = response.read(65537)
                lifetime.remaining()
                return validate_sdp(answer)
        except Exception:
            # Includes deadline/cleanup failures. Never expose provider or credential text.
            raise ProviderUnknown("provider_outcome_unknown_no_retry") from None


@dataclass(frozen=True, repr=False)
class BrokerIdentity:
    """Host-issued application session, NOT an OpenAI credential or action grant."""
    principal: str
    bearer_sha256: str
    csrf_sha256: str
    expires_at: int


@dataclass(frozen=True, repr=False)
class BoundExchange:
    """Opaque host-side dispatch closure bound to one SDP digest and principal.

    execute MUST consume the existing SDK's durable one-use permit. Binding or
    consuming this broker-cache entry does not create that permit.
    """
    principal: str
    offer_sha256: str
    expires_at: int
    execute: Callable[[bytes], bytes] = field(repr=False)


class VoiceBroker:
    def __init__(self, origin: str, identity: BrokerIdentity,
                 *, max_sessions: int = 3, clock: Callable[[], float] = time.time) -> None:
        c.https_endpoint(origin)
        c.require(origin.count("/") == 2, "origin_must_not_have_path")
        c.require(type(identity) is BrokerIdentity, "host_identity_required")
        c.text(identity.principal)
        c.digest(identity.bearer_sha256)
        c.digest(identity.csrf_sha256)
        c.integer(identity.expires_at, 1, 2**53 - 1, "invalid_identity_expiry")
        c.integer(max_sessions, 1, 100, "invalid_session_budget")
        self.origin, self.identity, self._clock = origin, identity, clock
        self._remaining = max_sessions
        self._exchanges: dict[str, BoundExchange | None] = {}
        self._lock = threading.Lock()

    def bind(self, request_id: str, exchange: BoundExchange) -> None:
        """Host API only. This method is never exposed as an HTTP endpoint."""
        c.text(request_id, 128)
        c.require(type(exchange) is BoundExchange and exchange.principal == self.identity.principal,
                  "exchange_identity_mismatch")
        c.digest(exchange.offer_sha256)
        c.integer(exchange.expires_at, 1, self.identity.expires_at, "invalid_exchange_expiry")
        now = self._clock()
        c.require(now < exchange.expires_at <= now + 60, "exchange_ttl_limit")
        c.require(callable(exchange.execute), "sdk_dispatcher_required")
        with self._lock:
            c.require(len(self._exchanges) < 128 and request_id not in self._exchanges,
                      "exchange_registry_limit_or_duplicate")
            self._exchanges[request_id] = exchange

    def __call__(self, environ: dict[str, Any], start_response: Callable) -> list[bytes]:
        headers = [("Cache-Control", "no-store"), ("Pragma", "no-cache"),
                   ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer"),
                   ("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")]
        status, body, content_type = "400 Bad Request", b'{"error":"request_rejected"}', "application/json"
        try:
            c.require(environ.get("PATH_INFO") == "/voice/session" and
                      environ.get("REQUEST_METHOD") == "POST", "unsupported_route")
            c.require(environ.get("wsgi.url_scheme") == "https" and
                      environ.get("HTTP_ORIGIN") == self.origin, "origin_rejected")
            c.require(environ.get("HTTP_HOST") == self.origin.split("//", 1)[1], "host_rejected")
            c.require(environ.get("CONTENT_TYPE", "").split(";", 1)[0] == "application/sdp",
                      "request_type_rejected")
            auth = environ.get("HTTP_AUTHORIZATION", "")
            csrf = environ.get("HTTP_X_INTEGRITY_CSRF", "")
            c.require(type(auth) is str and auth.startswith("Bearer ") and len(auth) <= 1024
                      and type(csrf) is str and 16 <= len(csrf) <= 256, "authentication_required")
            c.require(hmac.compare_digest(c.sha(auth[7:].encode()), self.identity.bearer_sha256)
                      and hmac.compare_digest(c.sha(csrf.encode()), self.identity.csrf_sha256),
                      "authentication_failed")
            c.require(environ.get("HTTP_TRANSFER_ENCODING") is None, "chunked_body_not_supported")
            length = environ.get("CONTENT_LENGTH", "")
            c.require(type(length) is str and length.isascii() and length.isdecimal()
                      and 5 <= int(length) <= 65536, "request_size_limit")
            # The hosting WSGI server must enforce socket/header/body deadlines.
            offer = validate_sdp(environ["wsgi.input"].read(int(length)))
            c.require(len(offer) == int(length), "truncated_request")
            identifier = environ.get("HTTP_X_INTEGRITY_REQUEST", "")
            with self._lock:
                now = self._clock()
                c.require(now < self.identity.expires_at and self._remaining > 0, "session_expired_or_limited")
                exchange = self._exchanges.get(identifier)
                c.require(exchange is not None and now < exchange.expires_at,
                          "exact_sdk_dispatch_required")
                c.require(exchange.offer_sha256 == c.sha(offer), "sdp_binding_mismatch")
                # Keep the ID as a spent tombstone: no re-binding or retry after loss.
                self._exchanges[identifier] = None
                self._remaining -= 1
            try:
                body = validate_sdp(exchange.execute(offer))
                status, content_type = "200 OK", "application/sdp"
            except Exception:
                status, body = "502 Bad Gateway", b'{"error":"outcome_unknown_no_retry"}'
        except (c.ContractError, KeyError, TypeError, ValueError, OSError):
            pass
        headers += [("Content-Type", content_type), ("Content-Length", str(len(body)))]
        start_response(status, headers)
        return [body]
