"""Pure protocol tests. No Claude CLI, account, subscription or SDK grant."""
import json

import pytest

from integrity_claude_code import __version__
from integrity_claude_code.__main__ import main
from integrity_claude_code.canonical import Rejected, strict_loads
from integrity_claude_code.capabilities import capabilities
from integrity_claude_code.stream import ClaudeStream, classify


SESSION = "00000000-0000-4000-8000-000000000001"


def parser():
    return ClaudeStream(SESSION, max_line_bytes=4096, max_events=10,
                        expected_model="synthetic-model", expected_tools=(), expected_mcp_servers=())


def event(value):
    return json.dumps(value).encode() + b"\n"


def init():
    return {"type": "system", "subtype": "init", "session_id": SESSION,
            "model": "synthetic-model", "tools": [], "mcp_servers": []}


def test_capabilities_are_honest_and_version_aligned(capsys):
    assert __version__ == "0.1.0rc2"
    assert main(["capabilities"]) == 0
    value = json.loads(capsys.readouterr().out)
    assert value == capabilities()
    assert value["production_authority"] is False
    assert value["live_activation_present"] is False
    assert value["canonical_append"] is False


def test_duplicate_json_is_refused():
    with pytest.raises(Rejected):
        strict_loads(b'{"x":1,"x":2}', 256)


def test_wrong_session_refused_before_a_result():
    stream = parser()
    bad = init()
    bad["session_id"] = "00000000-0000-4000-8000-000000000002"
    with pytest.raises(Rejected, match="session_mismatch"):
        stream.feed(event(bad))


def test_success_is_only_a_reported_claim_and_content_is_hashed():
    stream = parser()
    stream.feed(event(init()))
    stream.feed(event({"type": "result", "session_id": SESSION, "subtype": "success",
                       "is_error": False, "num_turns": 1, "result": "synthetic private result"}))
    stream.finish()
    summary = stream.summary()
    assert "synthetic private result" not in json.dumps(summary)
    assert classify(summary, {"exit_code": 0, "stdin_complete": True}) == "reported_success"


def test_duplicate_terminal_is_refused():
    stream = parser()
    stream.feed(event(init()))
    result = event({"type": "result", "session_id": SESSION, "subtype": "success", "is_error": False})
    stream.feed(result)
    with pytest.raises(Rejected, match="duplicate_result"):
        stream.feed(result)


def test_truncated_stream_never_becomes_success():
    stream = parser()
    stream.feed(event(init()))
    stream.feed(b'{"type":"result"')
    stream.finish()
    assert classify(stream.summary(), {"exit_code": 0, "stdin_complete": True}) == "protocol_violation"
