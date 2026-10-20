"""Derive Native compact receipt support from the canonical broker resolver.

The frozen Native source stays an auditable template. Compilation adds the
same bounded file-backed decoder used by its broker, before the unchanged
prompt, snapshot, authority and receipt validators.
"""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BROKER = ROOT / "resources/windows/integrity-client-turn-broker.py"
LABEL = "frozen-compact-admission"


def compact_source():
    """Extract one explicitly named frozen module without executing sources."""
    tree = ast.parse(BROKER.read_text(encoding="utf-8"))
    sources = []
    for node in tree.body:
        if (not isinstance(node, ast.Expr) or not isinstance(node.value, ast.Call)
                or not isinstance(node.value.func, ast.Name) or node.value.func.id != "exec"):
            continue
        call = node.value
        if not call.args or not isinstance(call.args[0], ast.Call):
            continue
        compiled = call.args[0]
        if (not isinstance(compiled.func, ast.Name) or compiled.func.id != "compile"
                or len(compiled.args) != 3
                or not isinstance(compiled.args[1], ast.Constant)
                or compiled.args[1].value != LABEL):
            continue
        source = ast.literal_eval(compiled.args[0])
        target = call.args[1] if len(call.args) > 1 else None
        if (not isinstance(source, str) or not isinstance(target, ast.Attribute)
                or not isinstance(target.value, ast.Name)
                or target.value.id != "_compact_admission" or target.attr != "__dict__"):
            raise ValueError("Native compact resolver anchor changed")
        parsed = ast.parse(source)
        protocol = [ast.literal_eval(n.value) for n in parsed.body
                    if isinstance(n, ast.Assign) and len(n.targets) == 1
                    and isinstance(n.targets[0], ast.Name) and n.targets[0].id == "PROTOCOL"]
        if protocol != ["integrity-admission-compact/v1"]:
            raise ValueError("Native compact protocol changed")
        sources.append(source)
    if len(sources) != 1:
        raise ValueError("Native compact resolver must be unique")
    return sources[0]


def render_hook(text):
    """Return a source-pinned decoder derivation; no state or network I/O."""
    tree = ast.parse(text)
    functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "find_document"]
    if len(functions) != 1 or "_native_compact_admission" in text:
        raise ValueError("Native document decoder anchor changed")
    function = functions[0]
    lines = text.splitlines(keepends=True)
    original = "".join(lines[function.lineno - 1:function.end_lineno])
    anchor = "    if isinstance(value, dict):\n        if predicate(value):"
    if original.count(anchor) != 1:
        raise ValueError("Native document decoder structure changed")
    decoder = (
        "    if isinstance(value, dict):\n"
        "        if value.get('protocol') == _native_compact_admission.PROTOCOL:\n"
        "            try:\n"
        "                value = _native_compact_admission.resolve_wrapper(value)\n"
        "            except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError) as exc:\n"
        "                raise HookError('compact_artifact_' + type(exc).__name__) from None\n"
        "        if predicate(value):"
    )
    source = compact_source()
    source_digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
    embedded = (
        "# BEGIN CANONICAL NATIVE COMPACT RECEIPTS\n"
        "import types as _native_receipt_types\n"
        "_native_compact_admission = _native_receipt_types.ModuleType('integrity_native_compact_admission')\n"
        f"_native_compact_source = {source!r}\n"
        f"assert hashlib.sha256(_native_compact_source.encode('utf-8')).hexdigest() == {source_digest!r}\n"
        "exec(compile(_native_compact_source, '<canonical-native-compact>', 'exec'), _native_compact_admission.__dict__)\n"
        "# END CANONICAL NATIVE COMPACT RECEIPTS\n\n\n"
    )
    lines[function.lineno - 1:function.end_lineno] = [embedded + original.replace(anchor, decoder)]
    result = "".join(lines)
    ast.parse(result)
    return result, {"protocol": "integrity/native-compact-receipt-derivation/v1",
                    "resolver_sha256": source_digest,
                    "source_pins": {
                        "native_receipts.py": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                        "resources/windows/integrity-client-turn-broker.py": hashlib.sha256(BROKER.read_bytes()).hexdigest()},
                    "original_validators_changed": False}
