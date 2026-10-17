"""Public packaging seams and hostile inputs; all state is disposable."""
import io
import json
import zipfile

import pytest

from integrity_chronicle.json_integrity import DuplicateJsonKeyError, loads_json_strict
from integrity_chronicle.runtime_paths import state_root
from integrity_chronicle.validator import validate_archive
from integrity_home import __version__
from integrity_home.history.sidecar import DEFAULT_LOGICAL_SCOPES
from integrity_home.mcp_server import HomeMCPServer, run
from integrity_home.unified_mcp_server import build_unified_projection
from integrity_home.unified_projection import UnifiedProjectionError
from integrity_home.unified_publication import _scopes
from integrity_home.history.decisions import _review_scope_ids
from integrity_home.ops_projection import HomeOpsProjection


def test_version_and_no_pre_enrolled_project():
    assert __version__ == "0.2.0a1"
    assert all(scope.project_id is None for scope in DEFAULT_LOGICAL_SCOPES)


def test_unified_publication_uses_only_explicit_project_ids():
    assert [scope.scope_id for scope in _scopes(())] == ["personal:core"]
    assert [scope.scope_id for scope in _scopes(("synthetic-alpha",))] == ["personal:core", "project:synthetic-alpha"]


def test_import_coordinator_does_not_invent_a_project(tmp_path):
    projection = object.__new__(HomeOpsProjection)
    projection._registry = tmp_path / "missing-registry.json"
    assert projection._project_ids("personal:core") == set()
    assert projection._project_ids("project:synthetic-alpha") == {"synthetic-alpha"}


def test_review_scope_set_is_bound_to_explicit_sidecar_descriptors():
    class Reader:
        def list_scopes(self):
            return [scope.to_dict() for scope in _scopes(("synthetic-alpha",))]
    assert _review_scope_ids(Reader()) == ("personal:core", "project:synthetic-alpha")


def test_archive_traversal_rejected_without_extracting(tmp_path):
    archive = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(archive, "w") as stream:
        stream.writestr("../escape.txt", "synthetic")
    report = validate_archive(str(archive))
    assert not report.valid
    assert not (tmp_path.parent / "escape.txt").exists()


def test_archive_member_budget_is_enforced(tmp_path):
    archive = tmp_path / "bounded.zip"
    with zipfile.ZipFile(archive, "w") as stream:
        stream.writestr("one.txt", "synthetic")
        stream.writestr("two.txt", "synthetic")
    report = validate_archive(str(archive), max_member_count=1)
    assert not report.valid
    assert any(issue.code == "member_count_exceeded" for issue in report.issues)


def test_duplicate_json_keys_are_not_silently_overwritten():
    with pytest.raises(DuplicateJsonKeyError):
        loads_json_strict('{"scope":"a","scope":"b"}')


def test_state_directory_is_explicit_and_does_not_create_it(monkeypatch, tmp_path):
    target = tmp_path / "empty-state"
    monkeypatch.setenv("INTEGRITY_HOME_STATE_ROOT", str(target))
    assert state_root() == target.resolve()
    assert not target.exists()


def test_unified_projection_requires_explicit_endpoint_before_connecting(monkeypatch):
    monkeypatch.delenv("INTEGRITY_ACTION_LOG_BASE_URL", raising=False)
    monkeypatch.setenv("INTEGRITY_SOLO_CANONICAL_BASE_URL", "https://memory.example.invalid")
    # Configuration is checked before any local Home backend is loaded.
    with pytest.raises(UnifiedProjectionError, match="INTEGRITY_ACTION_LOG_BASE_URL"):
        build_unified_projection()


def test_initialize_and_list_are_lazy_and_do_not_open_a_corpus():
    def refuse():
        raise AssertionError("unexpected source access")
    server = HomeMCPServer(projection_factory=refuse, ops_projection_factory=refuse)
    handshake = server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert handshake["result"]["serverInfo"]["version"] == __version__
    listed = server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert any(tool["name"] == "home_search" for tool in listed["result"]["tools"])


def test_stdio_bad_json_is_explicit_parse_error():
    output = io.StringIO()
    run(stdin=io.StringIO('{"id":1,"id":2}\n'), stdout=output)
    assert json.loads(output.getvalue())["error"]["code"] == -32700
