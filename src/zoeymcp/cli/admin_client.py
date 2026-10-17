"""CLI commands that talk to a running vault over its local admin socket.

They run inside the vault container (``docker exec <vault> zoeymcp secret set NAME``), as the
vault's uid, so the socket's filesystem permissions are the authentication.
"""

from __future__ import annotations

import getpass
import json
import os
from typing import Any, TextIO

import httpx

from ..vault.admin import DEFAULT_SOCKET, SOCKET_ENV


class AdminUnavailable(Exception):
    """The admin socket can't be reached or answered with an error."""


def socket_path(explicit: str | None) -> str:
    return explicit or os.environ.get(SOCKET_ENV) or DEFAULT_SOCKET


def _request(
    socket: str,
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    transport = transport or httpx.HTTPTransport(uds=socket)
    try:
        with httpx.Client(transport=transport, base_url="http://vault-admin", timeout=10) as client:
            response = client.request(method, path, json=body)
    except (httpx.HTTPError, OSError, RuntimeError) as exc:
        # RuntimeError: httpx on Windows, where Unix sockets aren't supported.
        raise AdminUnavailable(f"can't reach the vault's admin socket at {socket}: {exc}") from exc
    try:
        data: dict[str, Any] = response.json()
    except ValueError as exc:
        raise AdminUnavailable(f"unexpected answer (HTTP {response.status_code})") from exc
    if response.status_code >= 400:
        raise AdminUnavailable(str(data.get("error", f"HTTP {response.status_code}")))
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


def describe_binding(binding: dict[str, Any]) -> str:
    if "origins" in binding:
        return "origins " + ", ".join(binding["origins"])
    if "smtp" in binding:
        smtp = binding["smtp"]
        return f"SMTP {smtp['host']}:{smtp['port']} from {smtp['from']} to {', '.join(smtp['to'])}"
    return json.dumps(binding)
