"""Read-only Native fault regressions; no app host, hook state or RPC is used."""
import ast
from types import SimpleNamespace

import pytest

from integrity_client_memory import native_install


class EnvelopeError(RuntimeError):
    pass


class RpcError(RuntimeError):
    pass


def reader_fixture(outcomes):
    source = native_install.RESOURCES / "windows/integrity_client_turn_envelope.py"
    names = {"_native_owning_head", "_owning_native_rpc_retryable"}
    tree = ast.parse(source.read_text())
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                 and node.name in names]
    observed = {"loads": 0, "closes": 0, "reads": 0}

    def load():
        observed["loads"] += 1

        def read(host, identity):
            assert identity == "own-thread"
            observed["reads"] += 1
            value = outcomes.pop(0)
            if isinstance(value, BaseException):
                raise value
            return value

        def close():
            observed["closes"] += 1

        return SimpleNamespace(RpcError=RpcError, _host_latest_turn=read,
            BACKENDS=SimpleNamespace(get_codex_host=lambda: object(), close=close))

    namespace = {"os": SimpleNamespace(name="nt"), "re": __import__("re"),
        "TurnEnvelopeError": EnvelopeError, "_load_owning_native_reader": load,
        "_owning_codex_app_tool_pipes": lambda reader: []}
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(source), "exec"), namespace)
    return SimpleNamespace(read=namespace["_native_owning_head"], seen=observed,
                           namespace=namespace)


def test_transient_native_read_has_one_fresh_read_retry():
    fixture = reader_fixture([RpcError("codex_app_host_closed"),
                              {"id": "own-turn", "status": "inProgress"}])
    assert fixture.read("own-thread") == {"id": "own-turn", "status": "inProgress"}
    assert fixture.seen == {"loads": 2, "closes": 2, "reads": 2}


@pytest.mark.parametrize("message", ["codex_app_host_unavailable",
    "codex_app_host_unavailable:BrokenPipeError", "codex_app_host_timeout:tools/call"])
def test_transport_failure_retry_is_bounded(message):
    fixture = reader_fixture([RpcError(message), RpcError(message),
                              {"id": "own-turn", "status": "inProgress"}])
    with pytest.raises(EnvelopeError):
        fixture.read("own-thread")
    assert fixture.seen == {"loads": 2, "closes": 2, "reads": 2}


@pytest.mark.parametrize("failure", [RpcError("codex_app_host_invalid_result"),
    RpcError("codex_app_host_rejected:PRIVATE UNTRUSTED TEXT"),
    RpcError("codex_app_host_tool_result_invalid:read_thread"),
    RpcError("codex_app_host_tool_failed:read_thread"),
    EnvelopeError("reader pin changed")])
def test_invalid_evidence_is_never_retried(failure):
    fixture = reader_fixture([failure, {"id": "own-turn", "status": "inProgress"}])
    with pytest.raises(EnvelopeError):
        fixture.read("own-thread")
    assert fixture.seen == {"loads": 1, "closes": 1, "reads": 1}


@pytest.mark.parametrize("head", [None, {"id": "foreign", "status": "inProgress"},
                                  {"id": "own-turn", "status": "completed"}])
def test_returned_head_is_never_replaced_by_retry(head):
    fixture = reader_fixture([head, {"id": "own-turn", "status": "inProgress"}])
    assert fixture.read("own-thread") == head
    assert fixture.seen == {"loads": 1, "closes": 1, "reads": 1}


def test_reader_custody_failure_is_never_retried():
    fixture = reader_fixture([])

    def fail_load():
        fixture.seen["loads"] += 1
        raise EnvelopeError("reader pin changed")

    fixture.namespace["_load_owning_native_reader"] = fail_load
    with pytest.raises(EnvelopeError, match="pin changed"):
        fixture.read("own-thread")
    assert fixture.seen == {"loads": 1, "closes": 0, "reads": 0}
