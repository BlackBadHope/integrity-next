"""Read-only mock sources exercise the boundary without creating catalogs."""
import json
from pathlib import Path

import pytest

from integrity_space.server import create_server, invoke, ui_html
from integrity_space.workspace_backend import WorkspaceBackend


class Hub:
    def __init__(self, result):
        self.result, self.calls = result, []

    def call(self, name, args):
        self.calls.append((name, args))
        return self.result


class Lab:
    def call(self, name, args):
        return {"name": name, "arguments": args}


def test_workspace_inventory_preserves_identity_and_omits_unrequested_fields():
    hub = Hub({"structuredContent": {"hosts": [{"host_id": "synthetic-host", "label": "Test", "secret": "not-exported"}]}})
    backend = WorkspaceBackend(Lab(), hub)
    result = backend.call("integrity_projects", {})
    assert result["read_only"] and not result["canonical_completion_claim"]
    assert result["hosts"] == [{"host_id": "synthetic-host", "label": "Test"}]
    assert hub.calls == [("codex_list_hosts", {})]


@pytest.mark.parametrize("rows", [
    [{"host_id": "same"}, {"host_id": "same"}],
    [{"label": "missing identity"}],
    [{"host_id": ""}],
])
def test_workspace_inventory_refuses_ambiguous_or_absent_identity(rows):
    backend = WorkspaceBackend(Lab(), Hub({"structuredContent": {"hosts": rows}}))
    with pytest.raises(ValueError):
        backend.call("integrity_projects", {})


def test_workspace_cannot_be_given_browser_selected_configuration():
    hub = Hub({"structuredContent": {"hosts": []}})
    with pytest.raises(ValueError, match="no arguments"):
        WorkspaceBackend(Lab(), hub).call("integrity_projects", {"path": "/synthetic"})
    assert not hub.calls


def test_workspace_delegates_lab_calls_without_inventing_a_new_route():
    args = {"project_id": "space-lab-synthetic"}
    result = WorkspaceBackend(Lab(), Hub({})).call("integrity_project", args)
    assert result == {"name": "integrity_project", "arguments": args}


def test_bad_backend_outcome_is_an_explicit_mcp_error():
    class Broken:
        def call(self, *args):
            raise ValueError("synthetic invalid source")
    result = invoke(Broken(), "integrity_projects", {})
    assert result.is_error
    assert result.structured_content["code"] == "source_error"
    assert result.structured_content["success"] is False


def test_distinct_mode_resources_and_server_create_without_io():
    assert "<!doctype html" in ui_html().lower()
    assert "Проекты" in ui_html("lab")
    assert "Рабочая панель" in ui_html("workbench")
    assert ui_html("lab") != ui_html("workbench")
    server = create_server(Lab())
    assert server is not None
    root = Path(__file__).parents[1]
    assert not (root / "workspace_entry.py").exists()
    assert not (root / "ui/app.js").exists()
    assert not (root / "ui/dist/harness.js").exists()
