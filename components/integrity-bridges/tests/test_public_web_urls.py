import ast
import importlib.util
from pathlib import Path
import re
import sys
from integrity_bridges.web_url import CONVERSATION_PREFIX, CONVERSATION_PATTERN


def test_runtime_and_schema_accept_only_official_conversation_urls(monkeypatch):
    root = Path(__file__).resolve().parents[1] / "src/integrity_bridges/resources/private-memory"
    spec = importlib.util.spec_from_file_location("public_ping_pong_policy_test", root / "ping_pong.py")
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    tree = ast.parse((root / "unified_mcp.py").read_text())
    schema_pattern_refs = [n.id for n in ast.walk(tree) if isinstance(n, ast.Name)
                           and n.id == "_public_web_pattern"]
    assert schema_pattern_refs
    assert module.WEB_URL.pattern == CONVERSATION_PATTERN
    good = CONVERSATION_PREFIX + "00000000-0000-4000-8000-000000000001"
    assert module.WEB_URL.fullmatch(good)
    assert re.fullmatch(CONVERSATION_PATTERN, good)
    for bad in (good.replace("chatgpt.com", "chatgpt.com.evil.example.invalid"),
                good.replace("chatgpt.com", "untrusted.example.invalid"), good.replace("https:", "http:"),
                good + "\n", good + "?redirect=evil"):
        assert not module.WEB_URL.fullmatch(bad)
