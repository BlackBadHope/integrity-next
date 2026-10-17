"""Real MCP/ASGI over a disposable synthetic Seed catalog.

Windows cannot assert POSIX custody. Only that seam is replaced there, and
the test replacement admits regular paths inside this fixture's tmp root.
No Backend, MCP tool, record, response, HTTP route or JS client is mocked.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import secrets
import threading
import shlex
import sys
from functools import partial

import anyio
import pytest
from starlette.testclient import TestClient

from integrity_space import backend as backend_module
from integrity_space import server as server_module
from integrity_space.backend import Backend
from integrity_space.lab import provision, lab_events
from integrity_guardian.seed_catalog import SeedCatalog
from integrity_space.server import create_server, http_app
from integrity_space.workspace_backend import WorkspaceBackend


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    root = tmp_path / "synthetic-lab"
    if os.name == "nt":
        # Use actual protected Windows directories/files for the synthetic
        # catalog; chmod(0700) is not a Windows ACL constructor.
        from integrity_guardian._windows_files import create_private_directory
        from integrity_guardian.windows_private_state import write_private_once
        create_private_directory(root)
        state = root / "space-lab-interface"
        create_private_directory(state)
        catalog = state / "catalog.sqlite3"
        SeedCatalog(catalog).import_events(lab_events("space-lab-interface"), source_namespace="seed://project/space-lab-interface")
        config = root / "projects.json"
        write_private_once(config, json.dumps({"version": 1, "mode": "isolated-lab", "projects": [{"id": "space-lab-interface", "label": "Synthetic", "catalog": str(catalog)}]}).encode())
        write_private_once(root / "transport.token", secrets.token_urlsafe(32).encode())
    else:
        config = provision(root)
    if os.name != "posix":
        def test_custody(path, *, directory=False):
            path = Path(path)
            assert path.resolve().is_relative_to(tmp_path.resolve())
            assert not path.is_symlink()
            assert path.is_dir() if directory else path.is_file()
        monkeypatch.setattr(backend_module, "private_path", test_custody)
        monkeypatch.setattr(server_module, "private_path", test_custody)
    backend = Backend(config)
    server = create_server(backend)
    token_file = root / "transport.token"
    token = token_file.read_text(encoding="utf-8")
    return server, backend, token_file, token


def test_registered_mcp_lab_tools_can_read_real_seed_task(runtime):
    server, _, _, _ = runtime
    async def run():
        names = {tool.name for tool in await server.list_tools()}
        assert {"integrity_projects", "integrity_project", "integrity_task", "integrity_context", "integrity_source"} <= names
        assert "codex_list_hosts" not in names
        bootstrap = await server.call_tool("integrity_projects", {})
        assert bootstrap.structured_content["mode"] == "isolated-lab"
        project = await server.call_tool("integrity_project", {"project_id": "space-lab-interface"})
        data = project.structured_content
        assert not project.is_error and data["tasks"]
        task = await server.call_tool("integrity_task", {"project_id": "space-lab-interface", "task_id": "review-interface", "snapshot_id": data["snapshot_id"]})
        assert not task.is_error
        assert task.structured_content["task_id"] == "review-interface"
    anyio.run(run)


def test_http_preview_requires_token_and_matching_origin_then_reads_registered_tool(runtime):
    server, backend, token_file, token = runtime
    with TestClient(http_app(server, backend, token_file), base_url="http://127.0.0.1") as client:
        page = client.get("/")
        assert page.status_code == 200 and "Проекты" in page.text
        assert token not in page.text
        assert client.get("/preview/bootstrap").status_code == 401
        headers = {"Authorization": "Bearer " + token}
        assert client.get("/preview/bootstrap", headers={**headers, "Origin": "https://foreign.example.invalid"}).status_code == 403
        assert client.get("/preview/bootstrap", headers={**headers, "Host": "foreign.example.invalid"}).status_code == 403
        bootstrap = client.get("/preview/bootstrap", headers=headers)
        assert bootstrap.status_code == 200
        assert bootstrap.json()["structuredContent"]["mode"] == "isolated-lab"
        assert bootstrap.headers["cache-control"] == "no-store"
        assert client.post("/preview/tool", json={"name": "integrity_projects", "arguments": {}}).status_code == 401
        project = client.post("/preview/tool", headers=headers, json={"name": "integrity_project", "arguments": {"project_id": "space-lab-interface"}})
        assert project.status_code == 200
        assert project.json()["structuredContent"]["tasks"]
        assert client.post("/preview/tool", headers=headers, json={"name": "codex_send_prompt", "arguments": {}}).status_code == 403
        assert client.post("/preview/tool", headers=headers, json={"name": "codex_list_hosts", "arguments": {}}).status_code == 403


def test_exact_source_summary_has_a_utf8_byte_limit(runtime):
    server, backend, _, _ = runtime
    catalog = Path(backend._projects()[0]["catalog"])
    event = {**lab_events("space-lab-interface")[-1], "id": 7,
             "event_uid": "synthetic-long-source-7", "action": "agent_change_progress",
             "summary": "Источник " * 2000, "details": {"task_id": "review-interface"}}
    SeedCatalog(catalog).import_events([event], source_namespace="seed://project/space-lab-interface")
    async def run():
        project = await server.call_tool("integrity_project", {"project_id": "space-lab-interface"})
        result = await server.call_tool("integrity_source", {"project_id": "space-lab-interface", "event_id": 7, "snapshot_id": project.structured_content["snapshot_id"]})
        source = result.structured_content
        assert not result.is_error
        assert source["events"][0]["event_id"] == 7
        assert source["events"][0]["summary_truncated"] is True
        assert len(source["events"][0]["summary"].encode("utf-8")) <= 4096
        assert len(json.dumps(source, ensure_ascii=False).encode("utf-8")) < 8192
    anyio.run(run)


def test_compiled_public_hub_workbench_bootstrap_uses_existing_business_route(runtime, tmp_path, monkeypatch):
    from integrity_bridges.profile import compile_profile
    from integrity_space import hub as hub_module
    from integrity_space.hub import HubServer, load_hub
    _, backend, token_file, token = runtime
    profile = tmp_path / "compiled-private-memory"
    manifest = compile_profile("private-memory", profile)
    component = tmp_path / "bridge-config.json"
    component.write_text(json.dumps({"schema": "integrity/component-config/v1", "component": "integrity-bridges",
        "configured": True, "guardian_version": "6.1.0", "memory_api_version": "2.11.0",
        "values": {"command_b734f1f83ce5": shlex.join([sys.executable, "-m", "integrity_home.mcp_server"])}}), encoding="utf-8")
    monkeypatch.setenv("INTEGRITY_BRIDGES_CONFIG", str(component))
    config = tmp_path / "hub.json"
    config.write_text(json.dumps({"local_host": "synthetic-local", "ledger": str(tmp_path / "operations.sqlite3"), "hosts": {}}), encoding="utf-8")
    if os.name != "posix":
        def fixture_custody(path, *, directory=False):
            assert Path(path).resolve().is_relative_to(tmp_path.resolve())
            assert not Path(path).is_symlink()
            assert Path(path).is_dir() if directory else Path(path).is_file()
        monkeypatch.setattr(hub_module, "private_path", fixture_custody)
    else:
        profile.chmod(0o700)
        config.chmod(0o600)
        (profile / "hub-manifest.json").chmod(0o600)
    names = {Path(name).stem for name in manifest["files"]}
    previous = {name: sys.modules.get(name) for name in names}
    monkeypatch.setattr(sys, "path", list(sys.path))
    for name in names:
        sys.modules.pop(name, None)
    core = None
    try:
        hub, core = load_hub(profile / "hub-manifest.json", config)
        workspace = WorkspaceBackend(backend, hub)
        server = create_server(workspace, server_factory=partial(HubServer, hub=hub, core=core), ui_mode="workbench")
        with TestClient(http_app(server, workspace, token_file, ui_mode="workbench"), base_url="http://127.0.0.1") as client:
            assert "Рабочая панель" in client.get("/").text
            headers = {"Authorization": "Bearer " + token}
            result = client.get("/preview/bootstrap", headers=headers)
            assert result.status_code == 200
            assert result.json()["structuredContent"]["mode"] == "workspace"
            assert result.json()["structuredContent"]["hosts"] == []
            inventory = client.post("/preview/tool", headers=headers, json={"name": "codex_list_hosts", "arguments": {}})
            assert inventory.status_code == 200
            assert inventory.json()["structuredContent"]["hosts"] == []
            assert client.post("/preview/tool", headers=headers, json={"name": "codex_send_prompt", "arguments": {}}).status_code == 403
    finally:
        if core is not None:
            core.BACKENDS.close()
        for name in names:
            sys.modules.pop(name, None)
            if previous[name] is not None:
                sys.modules[name] = previous[name]


def test_actual_js_preview_client_bootstraps_and_reads_real_asgi_seed(runtime):
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is required for the JS-to-ASGI integration test")
    server, backend, token_file, token = runtime
    script = Path(__file__).with_name("preview-roundtrip.mjs")
    with TestClient(http_app(server, backend, token_file), base_url="http://127.0.0.1") as client:
        process = subprocess.Popen([node, str(script)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")
        deadline = threading.Timer(20, process.kill)
        deadline.start()
        try:
            process.stdin.write(json.dumps({"token": token}) + "\n")
            process.stdin.flush()
            requests = []
            while True:
                line = process.stdout.readline()
                if not line:
                    detail = process.stderr.read().replace(token, "[synthetic-token]")[-1600:]
                    raise RuntimeError("JS preview bridge ended before its terminal result: " + detail)
                item = json.loads(line)
                if item.get("done"):
                    break
                assert item["path"] in {"/preview/bootstrap", "/preview/tool"}
                assert item["headers"].get("Authorization", "").startswith("Bearer ")
                assert item["credentials"] == "omit"
                requests.append(item["path"])
                result = client.request(item["method"], item["path"], headers=item["headers"], content=item.get("body"))
                process.stdin.write(json.dumps({"status": result.status_code, "data": result.json()}, ensure_ascii=True) + "\n")
                process.stdin.flush()
            process.stdin.close()
            assert process.wait(timeout=10) == 0
            assert requests == ["/preview/bootstrap", "/preview/bootstrap", "/preview/tool", "/preview/tool", "/preview/tool"]
        finally:
            deadline.cancel()
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
