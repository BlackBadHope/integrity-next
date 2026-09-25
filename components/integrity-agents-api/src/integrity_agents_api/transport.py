"""Documented agents=v1 HTTP and bounded SSE; no SDK retries or ambient credentials."""
from __future__ import annotations

import http.client
import re
import ssl
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Iterator

from .deadline import Lifetime, bind_connection

from .contracts import (MAX_BYTES, REQUEST_SCHEMA, SCHEMA, ExportPolicy, Rejected, Unknown,
                        decode, encode, frozen, identifier, need, sha)


@dataclass(frozen=True, repr=False)
class Request:
    method: str
    path: str
    body: bytes = field(default=b"", repr=False)

    def descriptor(self, namespace: str) -> dict:
        identifier(namespace)
        need(self.method in ("GET", "POST", "DELETE"), "http_method")
        need(type(self.path) is str and len(self.path) <= 512, "http_path")
        path, separator, query = self.path.partition("?")
        session = re.fullmatch(r"/v1/agents/sessions/([A-Za-z0-9_.-]+)(?:/(events|items|turns))?", path)
        environment = re.fullmatch(r"/v1/agents/environments/([A-Za-z0-9_.-]+)", path)
        if session:
            identifier(session[1])
            collection = session[2]
            if collection in ("items", "turns"):
                need(self.method == "GET" and bool(re.fullmatch(
                    r"order=asc&limit=100(?:&after=[A-Za-z0-9_.-]+)?", query)), "history_query")
                if "&after=" in query:
                    identifier(query.split("&after=", 1)[1])
            elif collection == "events":
                need((self.method == "POST" and not separator) or
                     (self.method == "GET" and query == "stream=true"), "events_route")
            else:
                need(self.method in ("GET", "DELETE") and not separator, "session_route")
        elif environment:
            identifier(environment[1])
            need(self.method == "GET" and not separator, "environment_route")
        else:
            need(path == "/v1/agents/sessions" and self.method == "POST" and not separator,
                 "http_route_not_admitted")
        need(type(self.body) is bytes and len(self.body) <= MAX_BYTES, "http_body")
        if self.body:
            decode(self.body)
        need(self.method == "POST" or not self.body, "unexpected_http_body")
        return {"schema": SCHEMA, "namespace": namespace, "operation": self.method + " " + self.path,
                "input_sha256": sha(self.body)}


class GuardianGate:
    """Host constructs genuine SDK evidence; this class never creates a grant."""
    def __init__(self, *, envelope: dict, verification_context: dict, permit):
        try:
            import integrity_adapter_sdk as sdk
            sdk.require_guardian()
            self._api, runtime = sdk.adapter_sdk, sdk.adapter_runtime
        except (ImportError, RuntimeError):
            raise Rejected("exact_sdk_unavailable") from None
        need(type(permit) is runtime.AdapterDispatchPermit, "genuine_sdk_permit_required")
        self._envelope = frozen(envelope)
        self._context = dict(verification_context)
        for key in ("manifest", "proposal", "operation_binding", "operation_manifest"):
            need(key in self._context, "sdk_context_missing")
            self._context[key] = frozen(self._context[key])
        self._permit = permit

    def invoke(self, descriptor: dict, execute: Callable):
        expected = {"schema_id": SCHEMA, "schema_digest": sha(encode(REQUEST_SCHEMA)),
                    "document_digest": sha(encode(descriptor))}
        need(self._context["operation_manifest"].get("payload") == expected, "sdk_payload_mismatch")
        verified = self._api.verify_adapter_execution_envelope(
            self._envelope, **{**self._context, "used_at": datetime.now(timezone.utc).isoformat()})
        self._permit.consume(envelope=verified)
        return execute()


def sse_events(stream, *, deadline: float, max_events: int = 1024) -> Iterator[dict]:
    """UTF-8 line framing, multiline data, duplicate IDs handled by the projection."""
    fields, size, total, count = [], 0, 0, 0
    while True:
        need(time.monotonic() < deadline, "stream_deadline")
        line = stream.readline(MAX_BYTES + 2)
        need(time.monotonic() < deadline, "stream_deadline")
        need(len(line) <= MAX_BYTES + 1, "sse_line_limit")
        if not line:
            need(not fields, "truncated_sse_event")
            return
        need(line.endswith(b"\n"), "truncated_sse_line")
        total += len(line)
        need(total <= 4 * MAX_BYTES, "sse_total_limit")
        line = line.rstrip(b"\r\n")
        if line == b"":
            if fields:
                payload = b"\n".join(fields)
                if payload == b"[DONE]":
                    return
                event = decode(payload)
                need(type(event) is dict and type(event.get("type")) is str, "event_shape")
                count += 1
                need(count <= max_events, "sse_event_limit")
                yield event
            fields, size = [], 0
        elif line.startswith(b"data:"):
            value = line[5:].removeprefix(b" ")
            size += len(value) + 1
            need(size <= MAX_BYTES, "sse_event_bytes")
            fields.append(value)
        # Comments/event/id/retry fields cannot cause replay or execution.


class OpenAIHTTP:
    """Explicitly injected server key; only exact SDK-guarded requests reach HTTPS.

    Factory, keys and ExportPolicy belong to trusted host code, not an agent.
    The transport is a sink, not host isolation. No live mode on the default CLI.
    """
    def __init__(self, server_key: str, namespace: str, export_policy: ExportPolicy,
                 gate_factory: Callable[[dict], GuardianGate], *, timeout: int = 20):
        need(type(server_key) is str and 20 <= len(server_key) <= 1024
             and all(32 < ord(c) < 127 for c in server_key), "server_key")
        identifier(namespace)
        need(type(timeout) is int and 1 <= timeout <= 60, "http_timeout")
        need(callable(gate_factory), "sdk_gate_factory_required")
        self.__key, self.namespace, self.policy = server_key, namespace, export_policy
        self._factory, self._timeout = gate_factory, timeout

    def _prepare(self, request: Request):
        descriptor = request.descriptor(self.namespace)
        if request.body:
            self.policy.check(request.body)
        else:
            self.policy.check(b"")  # Explicit consent also required for reads/deletion.
        gate = self._factory(descriptor)
        need(type(gate) is GuardianGate, "verified_sdk_gate_required")
        return descriptor, gate

    def _connect(self, request: Request, accept: str, lifetime: Lifetime):
        connection = http.client.HTTPSConnection("api.openai.com", timeout=lifetime.remaining(),
                                                context=ssl.create_default_context())
        connection._create_connection = lifetime.connect
        bind_connection(connection, lifetime)
        try:
            lifetime.remaining()
            connection.request(request.method, request.path, body=request.body or None, headers={
                "Authorization": "Bearer " + self.__key, "OpenAI-Beta": "agents=v1",
                "Content-Type": "application/json", "Accept": accept,
                "Cache-Control": "no-store"})
            response = connection.getresponse()
            lifetime.remaining()
            need(200 <= response.status < 300, "provider_http_failure")
            need(response.getheader("Content-Encoding", "identity") == "identity", "compressed_response")
            need(response.getheader("Content-Type", "").split(";", 1)[0] == accept,
                 "provider_content_type")
            return connection, response
        except Exception:
            connection.close()
            raise Unknown("provider_outcome_unknown_no_retry") from None

    def send(self, request: Request) -> dict:
        lifetime = Lifetime(self._timeout)
        try:
            descriptor, gate = self._prepare(request)
            lifetime.remaining()
            def execute():
                lifetime.remaining()
                connection, response = self._connect(request, "application/json", lifetime)
                try:
                    output = decode(response.read(MAX_BYTES + 1))
                    lifetime.remaining()
                    need(type(output) is dict, "provider_object_required")
                    return output
                except Exception:
                    raise Unknown("provider_result_unknown_no_retry") from None
                finally:
                    response.close()
                    connection.close()
            return gate.invoke(descriptor, execute)
        finally:
            lifetime.close()

    @contextmanager
    def stream(self, session: str):
        lifetime = Lifetime(self._timeout)
        connection, response = None, None
        try:
            request = Request("GET", "/v1/agents/sessions/" + identifier(session) + "/events?stream=true")
            descriptor, gate = self._prepare(request)
            lifetime.remaining()
            connection, response = gate.invoke(descriptor, lambda: self._connect(
                request, "text/event-stream", lifetime))
            yield sse_events(response, deadline=lifetime.until)
        finally:
            if response is not None:
                response.close()
            if connection is not None:
                connection.close()
            lifetime.close()
