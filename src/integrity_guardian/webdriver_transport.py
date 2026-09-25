"""Small bounded W3C WebDriver transport for local Firefox targets."""

from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Self

_ELEMENT_KEY = "element-6066-11e4-a52e-4f735466cecf"
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024


class WebDriverTransportError(RuntimeError):
    """Raised when the bounded browser transport cannot prove its state."""


class _RejectRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_: object, **__: object) -> None:
        return None


def _ephemeral_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
        candidate.bind(("127.0.0.1", 0))
        return int(candidate.getsockname()[1])


def _closed_environment() -> dict[str, str]:
    environment = {
        "HOME": os.environ.get("HOME", "/nonexistent-integrity-browser"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "MOZ_DISABLE_NONLOCAL_CONNECTIONS": "1",
        "MOZ_HEADLESS": "1",
        "NO_PROXY": "127.0.0.1,localhost",
        "PATH": "/snap/bin:/usr/bin:/bin",
        "TMPDIR": "/tmp",
    }
    for name in ("DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR"):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    return environment


class GeckoWebDriverSession:
    """One fresh Firefox session behind an exact loopback HTTP proxy."""

    def __init__(
        self,
        *,
        geckodriver_launcher: Path,
        proxy_host: str,
        proxy_port: int,
        timeout_seconds: int,
        viewport_width: int,
        viewport_height: int,
        locale: str,
    ) -> None:
        if proxy_host != "127.0.0.1" or not 1 <= proxy_port <= 65535:
            raise WebDriverTransportError("WebDriver proxy endpoint rejected")
        if not 1 <= timeout_seconds <= 120:
            raise WebDriverTransportError("WebDriver timeout rejected")
        if not 320 <= viewport_width <= 3840 or not 240 <= viewport_height <= 2160:
            raise WebDriverTransportError("WebDriver viewport rejected")
        launcher = geckodriver_launcher
        if not launcher.is_absolute() or not launcher.exists():
            raise WebDriverTransportError("WebDriver launcher unavailable")
        self.launcher = launcher
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.timeout = timeout_seconds
        self.viewport_width = viewport_width
        self.viewport_height = viewport_height
        self.locale = locale
        self.process: subprocess.Popen[bytes] | None = None
        self.process_group_id: int | None = None
        self.base_url = ""
        self.session_id = ""
        self.capabilities: dict[str, Any] = {}
        self.profile_is_temporary = False
        self.request_count = 0
        self._direct_opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _RejectRedirectHandler(),
        )

    def __enter__(self) -> Self:
        port = _ephemeral_loopback_port()
        argv = [
            str(self.launcher),
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log",
            "fatal",
        ]
        try:
            self.process = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=_closed_environment(),
                start_new_session=True,
            )
            self.process_group_id = self.process.pid
        except OSError as exc:
            raise WebDriverTransportError("WebDriver process unavailable") from exc
        try:
            self.base_url = f"http://127.0.0.1:{port}"
            deadline = time.monotonic() + min(self.timeout, 15)
            while time.monotonic() < deadline:
                if self.process.poll() is not None:
                    raise WebDriverTransportError(
                        "WebDriver exited before readiness"
                    )
                try:
                    status = self._request("GET", "/status", count=False)
                except WebDriverTransportError:
                    time.sleep(0.05)
                    continue
                if status.get("ready") is True:
                    break
                time.sleep(0.05)
            else:
                raise WebDriverTransportError("WebDriver readiness timeout")
            return self._create_session()
        except Exception:
            self._close()
            raise

    def _create_session(self) -> GeckoWebDriverSession:
        proxy_preferences = {
            "network.proxy.type": 1,
            "network.proxy.http": self.proxy_host,
            "network.proxy.http_port": self.proxy_port,
            "network.proxy.ssl": self.proxy_host,
            "network.proxy.ssl_port": self.proxy_port,
            "network.proxy.ftp": self.proxy_host,
            "network.proxy.ftp_port": self.proxy_port,
            "network.proxy.socks": self.proxy_host,
            "network.proxy.socks_port": self.proxy_port,
            "network.proxy.no_proxies_on": "",
            "network.proxy.allow_hijacking_localhost": True,
            "network.prefetch-next": False,
            "network.dns.disablePrefetch": True,
            "network.predictor.enabled": False,
            "network.connectivity-service.enabled": False,
            "browser.safebrowsing.downloads.enabled": False,
            "browser.safebrowsing.malware.enabled": False,
            "browser.safebrowsing.phishing.enabled": False,
            "browser.search.update": False,
            "app.update.auto": False,
            "app.normandy.enabled": False,
            "app.shield.optoutstudies.enabled": False,
            "extensions.shield-recipe-client.enabled": False,
            "services.settings.server": "data:,#remote-settings-dummy/v1",
            "datareporting.healthreport.uploadEnabled": False,
            "toolkit.telemetry.enabled": False,
            "intl.locale.requested": self.locale,
        }
        created = self._request(
            "POST",
            "/session",
            {
                "capabilities": {
                    "alwaysMatch": {
                        "browserName": "firefox",
                        "acceptInsecureCerts": False,
                        "pageLoadStrategy": "normal",
                        "moz:firefoxOptions": {
                            "args": [
                                "-headless",
                                "-width",
                                str(self.viewport_width),
                                "-height",
                                str(self.viewport_height),
                            ],
                            "prefs": proxy_preferences,
                        },
                    }
                }
            },
            count=False,
        )
        if not isinstance(created, dict):
            raise WebDriverTransportError("WebDriver session response rejected")
        session_id = created.get("sessionId")
        capabilities = created.get("capabilities")
        if not isinstance(session_id, str) or not session_id or not isinstance(capabilities, dict):
            raise WebDriverTransportError("WebDriver session identity rejected")
        if capabilities.get("browserName") != "firefox":
            raise WebDriverTransportError("WebDriver browser identity rejected")
        profile = capabilities.get("moz:profile")
        if not isinstance(profile, str) or not profile:
            raise WebDriverTransportError("WebDriver temporary profile missing")
        self.session_id = session_id
        self.capabilities = capabilities
        self.profile_is_temporary = True
        self._request(
            "POST",
            f"/session/{self.session_id}/timeouts",
            {
                "script": self.timeout * 1000,
                "pageLoad": self.timeout * 1000,
                "implicit": 0,
            },
            count=False,
        )
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self._close()

    def _close(self) -> None:
        if self.session_id:
            try:
                self._request(
                    "DELETE",
                    f"/session/{self.session_id}",
                    count=False,
                )
            except WebDriverTransportError:
                pass
            finally:
                self.session_id = ""
        if self.process is not None:
            if self.process_group_id is not None and hasattr(os, "killpg"):
                try:
                    os.killpg(self.process_group_id, signal.SIGTERM)
                except ProcessLookupError:
                    pass
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=3)
            self.process = None
            self.process_group_id = None

    def _request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        count: bool = True,
    ) -> Any:
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            self.base_url + path,
            data=data,
            method=method,
            headers={"Content-Type": "application/json"},
        )
        try:
            with self._direct_opener.open(request, timeout=self.timeout) as response:
                if response.status < 200 or response.status >= 300:
                    raise WebDriverTransportError("WebDriver HTTP status rejected")
                body = response.read(_MAX_RESPONSE_BYTES + 1)
        except (OSError, urllib.error.URLError) as exc:
            raise WebDriverTransportError("WebDriver request failed") from exc
        if len(body) > _MAX_RESPONSE_BYTES:
            raise WebDriverTransportError("WebDriver response exceeded bound")
        try:
            document = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise WebDriverTransportError("WebDriver response JSON rejected") from exc
        if not isinstance(document, dict) or "value" not in document:
            raise WebDriverTransportError("WebDriver response envelope rejected")
        value = document["value"]
        if isinstance(value, dict) and isinstance(value.get("error"), str):
            raise WebDriverTransportError("WebDriver remote error")
        if count:
            self.request_count += 1
        return value

    def navigate(self, url: str) -> None:
        self._request("POST", f"/session/{self.session_id}/url", {"url": url})

    def current_url(self) -> str:
        value = self._request("GET", f"/session/{self.session_id}/url")
        if not isinstance(value, str):
            raise WebDriverTransportError("WebDriver current URL rejected")
        return value

    def find_elements(self, selector: str) -> list[str]:
        value = self._request(
            "POST",
            f"/session/{self.session_id}/elements",
            {"using": "css selector", "value": selector},
        )
        if not isinstance(value, list):
            raise WebDriverTransportError("WebDriver element set rejected")
        identifiers: list[str] = []
        for item in value:
            if not isinstance(item, dict) or not isinstance(item.get(_ELEMENT_KEY), str):
                raise WebDriverTransportError("WebDriver element identity rejected")
            identifiers.append(item[_ELEMENT_KEY])
        return identifiers

    def click(self, element_id: str) -> None:
        self._request(
            "POST",
            f"/session/{self.session_id}/element/{element_id}/click",
            {},
        )

    def element_text(self, element_id: str) -> str:
        value = self._request(
            "GET",
            f"/session/{self.session_id}/element/{element_id}/text",
        )
        if not isinstance(value, str):
            raise WebDriverTransportError("WebDriver element text rejected")
        return value

    def page_source(self) -> str:
        value = self._request("GET", f"/session/{self.session_id}/source")
        if not isinstance(value, str) or len(value.encode("utf-8")) > _MAX_RESPONSE_BYTES:
            raise WebDriverTransportError("WebDriver page source rejected")
        return value


__all__ = ["GeckoWebDriverSession", "WebDriverTransportError"]
