"""CLI commands that talk to a running vault over its local admin socket.

They run inside the vault container (``docker exec <vault> zoeymcp secret set NAME``), as the
vault's uid, so the socket's filesystem permissions are the authentication.
"""

from __future__ import annotations

import getpass
import json
import os
from typing import Any, Final, TextIO
from urllib.parse import quote

import httpx

from ..vault.admin import DEFAULT_SOCKET, SOCKET_ENV
from ..vault.oauth.protocol import EXCHANGE_DEADLINE, REFRESH_BUDGET

DEFAULT_TIMEOUT: Final = 10.0
# A login may wait for the code exchange, then for a refresh of the slot already in flight
# (commit waits for it before storing), plus time to answer.
LOGIN_TIMEOUT: Final = EXCHANGE_DEADLINE + REFRESH_BUDGET + 15


class AdminUnavailable(Exception):
    """The admin socket can't be reached or answered with an error.

    ``data`` is the error answer, when there was one: OAuth errors carry a stable ``reason``.
    """

    def __init__(self, message: str, data: dict[str, Any] | None = None) -> None:
        self.data = data or {}
        super().__init__(message)

    @property
    def reason(self) -> str | None:
        reason = self.data.get("reason")
        return reason if isinstance(reason, str) else None


def socket_path(explicit: str | None) -> str:
    return explicit or os.environ.get(SOCKET_ENV) or DEFAULT_SOCKET


def _request(
    socket: str,
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
    transport: httpx.BaseTransport | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    transport = transport or httpx.HTTPTransport(uds=socket)
    try:
        with httpx.Client(
            transport=transport, base_url="http://vault-admin", timeout=timeout
        ) as client:
            response = client.request(method, path, json=body)
    except (httpx.HTTPError, OSError, RuntimeError) as exc:
        # RuntimeError: httpx on Windows, where Unix sockets aren't supported.
        raise AdminUnavailable(f"can't reach the vault's admin socket at {socket}: {exc}") from exc
    try:
        data: dict[str, Any] = response.json()
    except ValueError as exc:
        raise AdminUnavailable(f"unexpected answer (HTTP {response.status_code})") from exc
    if response.status_code >= 400:
        raise AdminUnavailable(str(data.get("error", f"HTTP {response.status_code}")), data)
    return data


def read_secret_value(stdin: TextIO) -> str:
    """Read a secret from a hidden prompt, or from stdin when it isn't a terminal.

    Never from the command line: arguments show up in ``ps`` and shell history.
    """
    if stdin.isatty():
        value = getpass.getpass("Secret value (input hidden): ")
    else:
        value = stdin.read()
        if value.endswith("\r\n"):
            value = value[:-2]
        elif value.endswith("\n"):
            value = value[:-1]
    if not value:
        raise AdminUnavailable("no value given")
    return value


def read_redirect_url(stdin: TextIO, prompt: str) -> str:
    """Read the address the browser was sent to: hidden on a terminal, else one stdin line.

    Never from the command line, and never echoed: it holds the authorization code.
    """
    value = getpass.getpass(prompt) if stdin.isatty() else stdin.readline()
    value = value.strip()
    if not value:
        raise AdminUnavailable("no address given")
    return value


def secret_set(
    socket: str,
    name: str,
    value: str,
    origins: list[str] | None,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {"value": value}
    if origins:
        body["origins"] = origins
    return _request(socket, "PUT", f"/secrets/{name}", body, transport)


def secret_list(socket: str, transport: httpx.BaseTransport | None = None) -> dict[str, Any]:
    return _request(socket, "GET", "/secrets", transport=transport)


def secret_delete(
    socket: str, name: str, transport: httpx.BaseTransport | None = None
) -> dict[str, Any]:
    return _request(socket, "DELETE", f"/secrets/{name}", transport=transport)


def setup_code(socket: str, transport: httpx.BaseTransport | None = None) -> dict[str, Any]:
    return _request(socket, "POST", "/setup-code", transport=transport)


def gateway_key(socket: str, transport: httpx.BaseTransport | None = None) -> dict[str, Any]:
    return _request(socket, "GET", "/gateway-key", transport=transport)


def oauth_login(
    socket: str, credential: str, *, rebind: bool, transport: httpx.BaseTransport | None = None
) -> dict[str, Any]:
    """Start a login. For client_credentials this is the test fetch, so it may wait as long."""
    path = f"/oauth/{quote(credential, safe='')}/login"
    return _request(socket, "POST", path, {"rebind": rebind}, transport, LOGIN_TIMEOUT)


def oauth_complete(
    socket: str,
    credential: str,
    flow: str,
    redirect_url: str,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    path = f"/oauth/{quote(credential, safe='')}/complete"
    body = {"flow": flow, "redirect_url": redirect_url}
    return _request(socket, "POST", path, body, transport, LOGIN_TIMEOUT)


def oauth_cancel(
    socket: str, flow: str, transport: httpx.BaseTransport | None = None
) -> dict[str, Any]:
    return _request(socket, "DELETE", f"/oauth/flows/{quote(flow, safe='')}", transport=transport)


def oauth_status(socket: str, transport: httpx.BaseTransport | None = None) -> dict[str, Any]:
    return _request(socket, "GET", "/oauth", transport=transport)


def oauth_reset(
    socket: str, credential: str, transport: httpx.BaseTransport | None = None
) -> dict[str, Any]:
    path = f"/oauth/{quote(credential, safe='')}/reset"
    return _request(socket, "POST", path, transport=transport)


def describe_binding(binding: dict[str, Any]) -> str:
    if "origins" in binding:
        return "origins " + ", ".join(binding["origins"])
    if "oauth" in binding:
        oauth = binding["oauth"]
        return f"token endpoint {oauth['token']}, access tokens to {', '.join(oauth['resources'])}"
    if "smtp" in binding:
        smtp = binding["smtp"]
        return f"SMTP {smtp['host']}:{smtp['port']} from {smtp['from']} to {', '.join(smtp['to'])}"
    return json.dumps(binding)
