"""Repaired public bounds with fake IPC and synthetic state only."""
import ast
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import types

import pytest
from integrity_client_memory import configuration, launcher, profile

ROOT = Path(__file__).resolve().parents[1] / "src/integrity_client_memory"
SESSION = "11111111-1111-4111-8111-111111111111"
TURN = "22222222-2222-4222-8222-222222222222"
MARKER = "33333333-3333-4333-8333-333333333333"


@pytest.fixture
def native(tmp_path, monkeypatch):
    monkeypatch.setattr(configuration, "value", lambda name:
                        "0" * 64 if name.startswith("pin_") else str(tmp_path / name))
    path = ROOT / "resources/windows/native/integrity_scope_synapse.py"
    spec = importlib.util.spec_from_file_location("public_windows_scope_fixture", path)
    wrapper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(wrapper)
    assert wrapper.TARGET_SESSION is None
    def module(raw, name):
        value = types.ModuleType(name)
        value.__file__ = str(path)
        monkeypatch.setitem(sys.modules, name, value)
        exec(compile(raw, str(path), "exec"), value.__dict__)
        return value
    core = module(wrapper.CYCLE_SOURCE, "_integrity_native_scope_cycle")
    entry = module(wrapper.NATIVE_CYCLE_SOURCE, "public_windows_scope_entry_fixture")
    return wrapper, core, entry


class Pages:
    deadline = 15.0
    def __init__(self, marker_page=None, mutation=None):
        self.marker_page, self.mutation, self.calls = marker_page, mutation, []
    def read(self, thread, host, **kwargs):
        self.calls.append(kwargs)
        number = len(self.calls)
        turn = TURN if number == 1 else "44444444-4444-4444-8444-" + str(number).zfill(12)
        value = {"page": {"hasMore": True, "nextCursor": "cursor-" + str(number)},
                 "turns": [{"id": turn, "status": "inProgress" if number == 1 else "completed", "items": []}]}
        if number == self.marker_page:
            value["turns"][0]["items"] = [{"type": "contextCompaction", "id": MARKER, "status": "completed"}]
        if self.mutation: self.mutation(value, number)
        return value


@pytest.mark.parametrize("page", [1, 4, 30])
def test_one_turn_pages_find_marker_through_thirtieth(native, page):
    reader = Pages(page)
    observation = native[2].observe_history(reader, types.SimpleNamespace(check_page=lambda *a: None),
                                           SESSION, TURN, "PostCompact")
    assert observation["context_compaction_ids"] == [MARKER]
    assert observation["history_proof"]["pages"] == page
    assert all(call["limit"] == 1 for call in reader.calls)


def test_marker_after_bound_is_rejected(native):
    reader = Pages(31)
    with pytest.raises(native[2].NativeObservationError):
        native[2].observe_history(reader, types.SimpleNamespace(check_page=lambda *a: None), SESSION, TURN, "PostCompact")
    assert len(reader.calls) == 30


@pytest.mark.parametrize("fault", ["truncated", "extra-turn", "duplicate-cursor", "wrong-current"])
def test_pagination_and_subject_guards_remain_closed(native, fault):
    def mutate(value, page):
        if fault == "truncated": value["turns"][0]["itemsTruncated"] = True
        elif fault == "extra-turn": value["turns"].append(dict(value["turns"][0]))
        elif fault == "duplicate-cursor" and page == 4: value["page"]["nextCursor"] = "cursor-1"
        elif fault == "wrong-current" and page == 1: value["turns"][0]["id"] = MARKER
    with pytest.raises(native[2].NativeObservationError):
        native[2].observe_history(Pages(30, mutate), types.SimpleNamespace(check_page=lambda *a: None),
                                 SESSION, TURN, "PostCompact")


def test_diagnostic_view_preserves_response_and_exception_identity(native):
    result, error, calls = {"synthetic": "same object"}, TimeoutError("SYNTHETIC_SECRET"), []
    class Host:
        def request(self, *args, **kwargs):
            calls.append((args, kwargs))
            if kwargs.get("fail"): raise error
            return result
    trace = {}
    host = native[2].diagnostic_bridge(types.SimpleNamespace(NativeAppHostRpc=Host), trace).NativeAppHostRpc()
    assert host.request("tools/call", {"tool": "read_thread"}) is result
    with pytest.raises(TimeoutError) as caught: host.request("tools/call", {"tool": "read_thread"}, fail=True)
    assert caught.value is error and len(calls) == 2
    assert "SYNTHETIC_SECRET" not in json.dumps(trace)


def test_diagnostic_history_bounds_and_untrusted_content(native):
    entry = native[2]
    state = {"native_cycle_last_failure": {"code": ["SYNTHETIC_SECRET"], "message": "SYNTHETIC_SECRET"},
             "native_cycle_failure_history": ["SYNTHETIC_SECRET", None, {"code": "native_read_size_limit", "prompt": "SYNTHETIC_SECRET"}] * 12,
             "native_cycle_observation_history": ["SYNTHETIC_SECRET"] * 12}
    entry.retain_diagnostics(state)
    assert len(state.get("native_cycle_failure_history", [])) <= 8
    assert "SYNTHETIC_SECRET" not in json.dumps(state)
    observation = entry.observation(SESSION, TURN, TURN, [MARKER], [TURN], 1)
    state.update(epoch=1, native_compaction_cycle={"phase": "leased"})
    for _ in range(12): entry.record_observation(state, observation, "Reattest", "allow", "2026-10-20T00:00:00+00:00")
    assert len(state["native_cycle_observation_history"]) == 8


def test_profiles_are_catalogued_and_windows_pins_are_derived():
    assert launcher.resource_catalog()["windows/native_scope"]["path"].startswith("resources/windows/")
    assert "windows-remote/integrity-client-turn-broker" in launcher.resource_catalog()
    assert any(name.startswith("resources/windows/native/") for name in profile.native_source_pins())


def test_frozen_windows_sources_have_rebound_intrinsic_digests():
    visited = []
    def inspect(text, depth=0):
        assert depth < 8
        literals = {n.value for n in ast.walk(ast.parse(text)) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
        for value in literals:
            if len(value) < 256: continue
            try:
                raw = base64.b64decode(value, validate=True)
                decoded, parsed = raw.decode("utf-8"), ast.parse(raw)
            except (ValueError, UnicodeError, SyntaxError): continue
            if not any(isinstance(n, (ast.FunctionDef, ast.ClassDef)) for n in parsed.body): continue
            assert hashlib.sha256(raw).hexdigest() in literals
            compile(decoded, "public-windows-frozen-source", "exec")
            visited.append(raw)
            inspect(decoded, depth + 1)
    for path in (ROOT / "resources/windows/native").glob("*.py"): inspect(path.read_text(encoding="utf-8"))
    assert len(visited) >= 5


def test_remote_request_budget_and_cold_initialize():
    path = ROOT / "resources/windows-remote/integrity-client-turn-broker.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    selected = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef))
                and n.name in {"BrokerError", "_public_request_budget", "_remaining_timeout", "_require_request_budget"}]
    from contextlib import contextmanager
    from contextvars import ContextVar
    clock = types.SimpleNamespace(monotonic=lambda: 100.0)
    namespace = {"contextmanager": contextmanager, "time": clock,
                 "_REQUEST_DEADLINE": ContextVar("synthetic_deadline", default=None), "PUBLIC_REQUEST_BUDGET_SECONDS": 180}
    exec(compile("from __future__ import annotations\n" + "\n\n".join(ast.unparse(n) for n in selected), "public-remote-budget", "exec"), namespace)
    assignments = {n.targets[0].id: ast.literal_eval(n.value) for n in tree.body
                   if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name)
                   and n.targets[0].id in {"UPSTREAM_INITIALIZE_TIMEOUT_SECONDS", "PUBLIC_REQUEST_BUDGET_SECONDS"}}
    assert assignments == {"UPSTREAM_INITIALIZE_TIMEOUT_SECONDS": 45, "PUBLIC_REQUEST_BUDGET_SECONDS": 180}
    with namespace["_public_request_budget"]():
        assert namespace["_remaining_timeout"](200) == 180
        clock.monotonic = lambda: 150.0
        with namespace["_public_request_budget"](): assert namespace["_remaining_timeout"](200) == 130
        clock.monotonic = lambda: 281.0
        with pytest.raises(namespace["BrokerError"]): namespace["_require_request_budget"]()
    assert namespace["_REQUEST_DEADLINE"].get() is None
