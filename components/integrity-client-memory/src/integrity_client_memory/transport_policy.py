"""Compile bounded Windows startup policy without changing owning guards."""
from __future__ import annotations

import ast
import hashlib

INITIALIZE_SECONDS = 45


def render_windows_transport(source: bytes):
    """Derive one audited broker; reject unexpected source structure.

    This is a startup allowance, not an admission replay. The model still
    invokes its owning reference once. Internal receipt-backed replay remains
    governed by the broker's existing protocol and request deadline.
    """
    text = source.decode("utf-8")
    tree = ast.parse(text)
    limits = [n for n in tree.body if isinstance(n, ast.Assign)
              and any(isinstance(t, ast.Name) and t.id == "UPSTREAM_INITIALIZE_TIMEOUT_SECONDS"
                      for t in n.targets)]
    broker = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "TurnBroker")
    denial = next(n for n in broker.body if isinstance(n, ast.FunctionDef) and n.name == "_denial")
    advice = [n for n in denial.body if isinstance(n, ast.Assign)
              and any(isinstance(t, ast.Name) and t.id == "safe_current_turn_retry" for t in n.targets)]
    disposition = [n for n in denial.body if isinstance(n, ast.If)
                   and (isinstance(n.test, ast.Name) and n.test.id == "safe_current_turn_retry"
                        or ast.unparse(n.test) == "name == CURRENT_TURN_CONTEXT_TOOL"
                        and "no-model-retry-single-shot-admission" in ast.unparse(n))]
    if (len(limits) != 1 or len(advice) != 1 or len(disposition) != 1
            or ast.literal_eval(limits[0].value) not in (20, INITIALIZE_SECONDS)):
        raise ValueError("Windows transport policy source structure changed")
    edits = [
        (limits[0], f"UPSTREAM_INITIALIZE_TIMEOUT_SECONDS = {INITIALIZE_SECONDS}\n"),
        (advice[0], "        safe_current_turn_retry = False\n"),
        (disposition[0], "        if name == CURRENT_TURN_CONTEXT_TOOL:\n"
                         "            value['retry_disposition'] = 'no-model-retry-single-shot-admission'\n"),
    ]
    lines = text.splitlines(keepends=True)
    for node, replacement in sorted(edits, key=lambda item: item[0].lineno, reverse=True):
        lines[node.lineno - 1:node.end_lineno] = [replacement]
    rendered = "".join(lines).encode("utf-8")
    ast.parse(rendered)
    return rendered, {
        "protocol": "integrity/windows-transport-policy/v1",
        "initialize_timeout_seconds": INITIALIZE_SECONDS,
        "model_admission_retry_allowed": False,
        "source_sha256": hashlib.sha256(source).hexdigest(),
        "rendered_sha256": hashlib.sha256(rendered).hexdigest(),
    }
