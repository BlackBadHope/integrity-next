"""Official MCP Apps server. Default stdio, optional temporary loopback runtime."""
from __future__ import annotations
import argparse
import hmac
import json
import logging
import os
import sqlite3
from importlib.resources import files
from pathlib import Path

from mcp.server.apps import Apps, APP_MIME_TYPE
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.mcpserver.resources import TextResource
from mcp.types import CallToolResult, TextContent, ToolAnnotations
from openai_mcp_extensions import OpenAIExtensions

from .backend import Backend, SpaceError, private_path

URI = "ui://integrity/projects"
UI_MODES = frozenset({"lab", "workbench"})
LAB_READ_TOOLS = frozenset({"integrity_projects", "integrity_project", "integrity_task", "integrity_context", "integrity_source"})
WORKBENCH_READ_TOOLS = frozenset({"codex_list_hosts", "codex_list_tasks", "codex_read_task", "codex_cloud_list_tasks", "codex_cloud_read_task"})
ANNOTATIONS = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)


def ui_html(mode: str = "lab") -> str:
    if mode not in UI_MODES:
        raise ValueError("unknown Integrity Space UI mode")
    installed = files("integrity_space") / "assets" / f"{mode}.html"
    if installed.is_file():
        return installed.read_text(encoding="utf-8")
    raise FileNotFoundError("Integrity Space UI asset missing; run npm run build before packaging")


def invoke(backend: Backend, name: str, arguments: dict) -> CallToolResult:
    try:
        value = backend.call(name, arguments)
        return CallToolResult(content=[TextContent(type="text", text=json.dumps(value, ensure_ascii=False))], structuredContent=value)
    except SpaceError as exc:
        value = {"code": exc.code, "message": str(exc), "success": False}
    except PermissionError:
        value = {"code": "access_denied", "message": "Источник недоступен текущему владельцу.", "success": False}
    except (FileNotFoundError, sqlite3.Error, OSError):
        value = {"code": "connection_error", "message": "Не удалось прочитать источник Integrity. Состояние не подтверждено.", "success": False}
    except (ValueError, TypeError, KeyError):
        value = {"code": "source_error", "message": "Неверные аргументы или состояние источника. Успех не подтверждён.", "success": False}
    return CallToolResult(content=[TextContent(type="text", text=value["message"])], structuredContent=value, isError=True)


def create_server(backend: Backend, *, server_factory=MCPServer,
                  name="integrity-space", version="0.2.0", instructions=None,
                  ui_mode: str = "lab") -> MCPServer:
    apps = Apps()
    resource_uri = URI if ui_mode == "lab" else "ui://integrity/workbench"
    apps.add_resource(TextResource(uri=resource_uri, name=f"integrity-{ui_mode}", title="Проекты Integrity" if ui_mode == "lab" else "Рабочая панель Integrity", mime_type=APP_MIME_TYPE,
        text=ui_html(ui_mode), meta={"ui": {"csp": {"connectDomains": [], "resourceDomains": []}},
                            "openai/ui": {"preferredDisplayMode": "fullscreen", "availableDisplayModes": ["inline", "fullscreen"]}}))

    @apps.tool(resource_uri=resource_uri, name="integrity_projects", title="Проекты Integrity", annotations=ANNOTATIONS,
               meta={"openai/ui": {"entrypoints": [{"type": "global"}, {"type": "thread"}]}})
    def projects() -> CallToolResult:
        """Open the private Integrity project selector. Accepts no identifiers or paths."""
        return invoke(backend, "integrity_projects", {})

    server = server_factory(name, version=version, extensions=[apps, OpenAIExtensions()],
                       instructions=instructions or "Read only isolated lab projects. Select existing project and task IDs. Continuation to an executor is unavailable; never send a replacement task or treat claimed results as verified.")

    @server.tool(name="integrity_project", title="Состояние проекта", annotations=ANNOTATIONS)
    def project(project_id: str, after_task_id: str = "") -> CallToolResult:
        """Read canonical task lifecycle, project decisions and constraints. No arbitrary paths."""
        return invoke(backend, "integrity_project", {"project_id": project_id, "after_task_id": after_task_id})

    @server.tool(name="integrity_task", title="Контекст существующей задачи", annotations=ANNOTATIONS)
    def task(project_id: str, task_id: str, snapshot_id: str) -> CallToolResult:
        """Read one exact existing Seed task with source links, claim freshness and results."""
        return invoke(backend, "integrity_task", {"project_id": project_id, "task_id": task_id, "snapshot_id": snapshot_id})

    @server.tool(name="integrity_context", title="Ограниченный контекст задачи", annotations=ANNOTATIONS)
    def context(project_id: str, task_id: str, snapshot_id: str) -> CallToolResult:
        """Prepare bounded context for the selected task. Does not start inference or dispatch work."""
        return invoke(backend, "integrity_context", {"project_id": project_id, "task_id": task_id, "snapshot_id": snapshot_id})

    @server.tool(name="integrity_source", title="Источник Integrity", annotations=ANNOTATIONS)
    def source(project_id: str, event_id: int, snapshot_id: str) -> CallToolResult:
        """Read a source summary by exact project, snapshot and numeric event ID; no raw archive."""
        return invoke(backend, "integrity_source", {"project_id": project_id, "event_id": event_id, "snapshot_id": snapshot_id})
    return server


def http_app(server: MCPServer, backend: Backend, token_file: Path, *, ui_mode: str = "lab"):
    """A temporary owner-token transport, not another project authorization store."""
    from starlette.responses import HTMLResponse, JSONResponse
    from starlette.routing import Route
    if ui_mode not in UI_MODES:
        raise ValueError("unknown Integrity Space UI mode")
    private_path(token_file)
    secret = token_file.read_text(encoding="utf-8").strip()
    if len(secret) < 32:
        raise ValueError("owner transport token is too short")
    application = server.streamable_http_app(json_response=True, stateless_http=True, max_request_body_size=65536)
    read_tools = LAB_READ_TOOLS if ui_mode == "lab" else WORKBENCH_READ_TOOLS

    def response(value, status_code=200):
        return JSONResponse(value, status_code=status_code, headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})

    async def index(request):
        return HTMLResponse(ui_html(ui_mode), headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})

    async def bootstrap(request):
        value = await server.call_tool("integrity_projects", {})
        return response(value.model_dump(by_alias=True, exclude_none=True, mode="json"))

    async def preview(request):
        try:
            if int(request.headers.get("content-length", "0")) > 65536:
                return response({"error": "request too large"}, 413)
            raw = await request.body()
            if len(raw) > 65536:
                return response({"error": "request too large"}, 413)
            payload = await request.json()
            if (not isinstance(payload, dict) or set(payload) != {"name", "arguments"}
                    or not isinstance(payload["name"], str) or not isinstance(payload["arguments"], dict)):
                return response({"error": "invalid request"}, 400)
            if payload["name"] not in read_tools:
                return response({"error": "tool is outside this read-only UI mode"}, 403)
            value = await server.call_tool(payload["name"], payload["arguments"])
            return response(value.model_dump(by_alias=True, exclude_none=True, mode="json"))
        except (ValueError, TypeError, KeyError, ToolError):
            return response({"error": "invalid request"}, 400)

    application.routes.extend([Route("/", index), Route("/preview/bootstrap", bootstrap), Route("/preview/tool", preview, methods=["POST"])])
    async def guarded(scope, receive, send):
        if scope["type"] == "http":
            headers = dict(scope["headers"])
            host = headers.get(b"host", b"").decode()
            origin = headers.get(b"origin", b"").decode()
            allowed_hosts = ("127.0.0.1", "localhost", "[::1]")
            valid_host = any(host == h or host.startswith(h + ":") for h in allowed_hosts)
            valid_origin = not origin or origin in (f"http://{host}", f"https://{host}")
            authorized = hmac.compare_digest(headers.get(b"authorization", b""), ("Bearer " + secret).encode())
            if not valid_host or not valid_origin:
                await JSONResponse({"error": "untrusted origin"}, status_code=403)(scope, receive, send)
                return
            if scope["path"] != "/" and not authorized:
                await JSONResponse({"error": "owner transport authentication required"}, status_code=401)(scope, receive, send)
                return
        await application(scope, receive, send)
    return guarded


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--transport", choices=["stdio", "http"], default="stdio")
    parser.add_argument("--port", type=int, default=8791)
    parser.add_argument("--token-file", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    backend = Backend(args.config)
    backend.projects()  # Validate before opening a listener.
    server = create_server(backend)
    if args.transport == "stdio":
        server.run()
    else:
        if args.token_file is None:
            parser.error("HTTP requires --token-file")
        import uvicorn
        uvicorn.run(http_app(server, backend, args.token_file), host="127.0.0.1", port=args.port,
                    access_log=False, log_level="warning")


if __name__ == "__main__":
    main()
