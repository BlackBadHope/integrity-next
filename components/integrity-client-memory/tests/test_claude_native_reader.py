"""The Claude Native owning reader must load through the envelope's own custody read.

Regression: the claude-native envelope called ``_checked_owning_bytes`` without
defining it, so every real ``_native_owning_head`` raised ``NameError`` while
tests that stub the head never reached it. Fixtures are synthetic files; no
Claude session, hook state or vendor call is involved.
"""
import ast
import hashlib
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from integrity_client_memory import native_install

ENVELOPE = native_install.RESOURCES / "claude-native/integrity_client_turn_envelope.py"
NAMES = {"_checked_owning_bytes", "_claude_profile_reader", "_native_owning_head", "_sha256_bytes"}


class EnvelopeError(RuntimeError):
    pass


def envelope_fixture(tmp_path, reader_source, *, pinned_sha256=None):
    tree = ast.parse(ENVELOPE.read_text(encoding="utf-8"))
    functions = [node for node in tree.body
                 if isinstance(node, ast.FunctionDef) and node.name in NAMES]
    assert {node.name for node in functions} == NAMES, "envelope must define every helper it calls"
    module_file = tmp_path / "integrity_client_turn_envelope.py"
    module_file.write_text("# fixture copy of the envelope location\n", encoding="utf-8")
    reader = tmp_path / "claude_owning_native.py"
    reader.write_text(reader_source, encoding="utf-8")
    expected = pinned_sha256 or native_install.digest(reader.read_bytes())
    namespace = {
        "__file__": str(module_file), "os": os, "stat": __import__("stat"), "Path": Path,
        "hashlib": hashlib, "TurnEnvelopeError": EnvelopeError,
        "MAX_ENVELOPE_FILE_BYTES": 2 * 1024 * 1024,
        "_integrity_value": lambda key: {"claude_native_reader_sha256": expected}[key],
    }
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(ENVELOPE), "exec"), namespace)  # noqa: S102
    return SimpleNamespace(namespace=namespace, reader=reader, module_file=module_file)


READER = "def current_owning_turn(identity):\n    return {'id': 'turn-' + identity, 'status': 'inProgress'}\n"


def test_native_owning_head_reads_the_pinned_reader(tmp_path):
    fixture = envelope_fixture(tmp_path, READER)
    head = fixture.namespace["_native_owning_head"]("abc")
    assert head == {"id": "turn-abc", "status": "inProgress"}


def test_changed_reader_is_refused_before_execution(tmp_path):
    fixture = envelope_fixture(tmp_path, READER, pinned_sha256="0" * 64)
    with pytest.raises(EnvelopeError, match="claude_native_reader_changed"):
        fixture.namespace["_native_owning_head"]("abc")


def test_custody_read_rejects_missing_empty_and_oversized_sources(tmp_path):
    fixture = envelope_fixture(tmp_path, READER)
    read = fixture.namespace["_checked_owning_bytes"]
    assert read(fixture.reader, 2 * 1024 * 1024) == fixture.reader.read_bytes()
    with pytest.raises(EnvelopeError, match="size or type invalid"):
        read(fixture.reader, len(fixture.reader.read_bytes()) - 1)
    empty = tmp_path / "empty.py"
    empty.write_bytes(b"")
    with pytest.raises(EnvelopeError, match="size or type invalid"):
        read(empty, 1024)
    with pytest.raises(FileNotFoundError):
        read(tmp_path / "missing.py", 1024)


@pytest.mark.skipif(os.name == "nt", reason="symlink creation needs privileges on Windows")
def test_custody_read_rejects_symlinked_sources(tmp_path):
    fixture = envelope_fixture(tmp_path, READER)
    link = tmp_path / "linked_reader.py"
    link.symlink_to(fixture.reader)
    with pytest.raises(EnvelopeError, match="custody invalid"):
        fixture.namespace["_checked_owning_bytes"](link, 1024 * 1024)
