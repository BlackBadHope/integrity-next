"""Exercise the broker's actual receive/denial methods with a virtual clock."""
import ast
import json
from pathlib import Path
import queue
from types import SimpleNamespace, MethodType

import pytest

from integrity_client_memory.transport_policy import render_windows_transport

@pytest.fixture(params=["windows", "claude-native"])
def broker_source(request):
    return (Path(__file__).resolve().parents[1] /
            "src/integrity_client_memory/resources" / request.param /
            "integrity-client-turn-broker.py").read_bytes()


def methods(raw):
    tree = ast.parse(raw)
    nodes = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "BrokerError"]
    for name, wanted in (("UpstreamFacade", {"_receive", "_decode_response"}),
                         ("TurnBroker", {"_denial"})):
        cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == name)
        nodes += [n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name in wanted]
    module = ast.parse("from __future__ import annotations\n")
    module.body += nodes
    values = {"queue": queue, "json": json, "MAX_MESSAGE_BYTES": 4 * 1024 * 1024,
              "CURRENT_TURN_CONTEXT_TOOL": "integrity_context_admission_current_turn",
              "STANDALONE_TURN_MEMORY_TOOLS": {"integrity_turn_memory_open", "integrity_turn_memory_close"},
              "_persist_transport_diagnostic": lambda *a, **kw: False,
              "_json_bytes": lambda x: json.dumps(x).encode()}
    exec(compile(module, "actual-broker-methods", "exec"), values)
    return values


def receive(values, budget, delay):
    clock = SimpleNamespace(now=0.0)
    values["time"] = SimpleNamespace(monotonic=lambda: clock.now)
    class Delayed:
        def get(self, timeout):
            clock.now = min(clock.now + timeout, delay)
            if clock.now < delay:
                raise queue.Empty
            return b'{"jsonrpc":"2.0","id":1,"result":{"serverInfo":{"name":"integrity-client-memory"}}}'
    subject = SimpleNamespace(_check_public=lambda **kw: None, _responses=Delayed())
    if "_decode_response" in values:
        subject._decode_response = MethodType(values["_decode_response"], subject)
    return values["_receive"](subject, 1, timeout=budget, request_sent=True)


def test_delayed_initialize_survives_previous_twenty_second_cutoff(broker_source):
    before = methods(broker_source)
    with pytest.raises(before["BrokerError"], match="timed out"):
        receive(before, 20, 21)
    rendered, policy = render_windows_transport(broker_source)
    assert receive(methods(rendered), policy["initialize_timeout_seconds"], 21)["serverInfo"]


def test_unresponsive_initialize_still_has_a_finite_deadline(broker_source):
    rendered, policy = render_windows_transport(broker_source)
    values = methods(rendered)
    with pytest.raises(values["BrokerError"], match="timed out"):
        receive(values, policy["initialize_timeout_seconds"], 46)


@pytest.mark.parametrize("sent", [False, True])
def test_admission_never_advises_second_model_call(sent, broker_source):
    rendered, _ = render_windows_transport(broker_source)
    values = methods(rendered)
    error = values["BrokerError"]("upstream response timed out", layer="broker-upstream", request_sent=sent)
    result = values["_denial"](SimpleNamespace(), values["CURRENT_TURN_CONTEXT_TOOL"], error)
    denial = json.loads(result["content"][0]["text"])
    assert denial["automatic_retry_allowed"] is False
    assert denial["retry_disposition"] == "no-model-retry-single-shot-admission"
    assert denial["request_sent"] is sent


def test_renderer_preserves_every_owning_guard_and_is_deterministic(broker_source):
    rendered, _ = render_windows_transport(broker_source)
    def guards(raw):
        cls = next(n for n in ast.parse(raw).body if isinstance(n, ast.ClassDef) and n.name == "TurnBroker")
        return {n.name: ast.dump(n) for n in cls.body if isinstance(n, ast.FunctionDef) and n.name != "_denial"}
    assert guards(rendered) == guards(broker_source)
    assert render_windows_transport(rendered)[0] == rendered
    with pytest.raises(ValueError, match="structure changed"):
        render_windows_transport(broker_source.replace(b"UPSTREAM_INITIALIZE_TIMEOUT_SECONDS = 20",
                                               b"UPSTREAM_INITIALIZE_TIMEOUT_SECONDS = 900"))
