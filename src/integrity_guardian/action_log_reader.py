# Fail-closed authentication for repository-owned Action Log readers.

from __future__ import annotations

import os
import urllib.request
from collections.abc import Mapping

ACTION_LOG_READER_HEADER = "X-Codex-Log-Token"
ACTION_LOG_READER_TOKEN_ENV = "CODEX_LOG_TOKEN"
MAX_ACTION_LOG_READER_TOKEN_BYTES = 4_096


class ActionLogReaderAuthError(RuntimeError):
    pass


class ActionLogReaderTransportError(RuntimeError):
    pass


class _DenyActionLogRedirects(urllib.request.HTTPRedirectHandler):
    """Stop before urllib can copy authentication to a redirect target."""

    def _deny(self, _request, response, _code, _message, _headers):
        response.close()
        raise ActionLogReaderTransportError(
            "Action Log authenticated redirect is forbidden"
        )

    http_error_301 = _deny
    http_error_302 = _deny
    http_error_303 = _deny
    http_error_307 = _deny
    http_error_308 = _deny


def require_action_log_reader_token(
    token: str | None = None,
    *,
    environment: Mapping[str, str] | None = None,
) -> str:
    if token is None:
        source = os.environ if environment is None else environment
        token = source.get(ACTION_LOG_READER_TOKEN_ENV)
    if not isinstance(token, str) or not token or token != token.strip():
        raise ActionLogReaderAuthError(
            "Action Log reader authentication token is required before network I/O"
        )
    if (
        len(token) > MAX_ACTION_LOG_READER_TOKEN_BYTES
        or any(not 0x21 <= ord(character) <= 0x7E for character in token)
    ):
        raise ActionLogReaderAuthError(
            "Action Log reader authentication token is invalid"
        )
    return token


def action_log_reader_headers(
    token: str | None = None,
    *,
    environment: Mapping[str, str] | None = None,
) -> dict[str, str]:
    return {
        ACTION_LOG_READER_HEADER: require_action_log_reader_token(
            token,
            environment=environment,
        )
    }


def open_action_log_reader_request(
    request: urllib.request.Request,
    *,
    timeout: float,
):
    """Open one authenticated request without ambient proxies or redirects."""

    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _DenyActionLogRedirects(),
    )
    return opener.open(request, timeout=timeout)
