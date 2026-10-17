"""Sanitized frozen modules keep intrinsic source integrity, not deployment pins."""
import ast
import base64
import hashlib
from pathlib import Path
import re


def test_frozen_scope_modules_have_matching_public_source_digests():
    source = Path(__file__).resolve().parents[1] / "src/integrity_client_memory/resources/linux/native/integrity_scope_synapse.py"
    visited = []

    def inspect(text, depth=0):
        assert depth < 8
        tree = ast.parse(text)
        literals = {n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
        for value in literals:
            if len(value) < 256 or re.fullmatch(r"[A-Za-z0-9+/=]+", value) is None:
                continue
            try:
                raw = base64.b64decode(value, validate=True)
                decoded = raw.decode("utf-8")
                parsed = ast.parse(decoded)
            except (ValueError, UnicodeError, SyntaxError):
                continue
            if not any(isinstance(n, (ast.FunctionDef, ast.ClassDef)) for n in parsed.body):
                continue
            assert hashlib.sha256(raw).hexdigest() in literals
            compile(decoded, "public-frozen-module", "exec")
            visited.append(hashlib.sha256(raw).hexdigest())
            inspect(decoded, depth + 1)

    inspect(source.read_text(encoding="utf-8"))
    assert len(visited) >= 3
