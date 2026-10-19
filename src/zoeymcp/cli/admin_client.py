"""CLI commands that talk to a running vault or gateway over its local admin socket.

They run inside the container (``docker exec <vault> zoeymcp secret set NAME``, ``docker exec
<gateway> zoeymcp review notes``), as the uid that owns the socket's directory, so the socket's
filesystem permissions are the authentication.

``docker exec`` runs as root, and in the standard tier root has no ``DAC_OVERRIDE``, so it can't
open those ``0700`` directories. Run as root, the CLI first becomes the directory's owner (M3
design B.2): the container keeps ``SETUID`` and ``SETGID`` for this.
"""

from __future__ import annotations

import getpass
import json
import os
from typing import Any, Final, TextIO
from urllib.parse import quote

import httpx

from ..common.adminsocket import DEFAULT_SOCKET, EXCHANGE_DEADLINE, REFRESH_BUDGET, SOCKET_ENV

GATEWAY_SOCKET: Final = "/run/zoeymcp-gateway/admin.sock"
GATEWAY_SOCKET_ENV: Final = "ZOEYMCP_GATEWAY_ADMIN_SOCKET"
DEFAULT_TIMEOUT: Final = 10.0
# A review lists the server on a fresh connection: up to the largest list_timeout (300 s), the
# gateway's own wait beyond it, and closing the connection.
REVIEW_TIMEOUT: Final = 300 + 15 + 15
# A login may wait for the code exchange, then for a refresh of the slot already in flight
# (commit waits for it before storing), plus time to answer.
LOGIN_TIMEOUT: Final = EXCHANGE_DEADLINE + REFRESH_BUDGET + 15
# Setting or deleting a secret an OAuth credential uses waits for its refresh in flight.
SECRET_TIMEOUT: Final = REFRESH_BUDGET + 15


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


def gateway_socket_path(explicit: str | None) -> str:
    return explicit or os.environ.get(GATEWAY_SOCKET_ENV) or GATEWAY_SOCKET


def become_socket_owner(socket: str, system: Any = os) -> None:
    """Run as root, become the owner of the socket's directory before connecting.

    ``system`` is :mod:`os`, or a stand-in in tests. Nothing happens unless the effective uid is
    0 and the directory belongs to another uid. Supplementary groups are dropped first, then the
    group, then the user, so nothing of root is left.
    """
    if not hasattr(system, "geteuid") or system.geteuid() != 0:
        return
    try:
        info = system.stat(os.path.dirname(socket) or ".")
    except OSError:
        return  # connecting says what is wrong
    if info.st_uid == 0:
        return
    try:
        system.setgroups([])
        system.setgid(info.st_gid)
        system.setuid(info.st_uid)
    except OSError as exc:
        raise AdminUnavailable(
            f"can't switch to uid {info.st_uid}, which owns {os.path.dirname(socket)} "
            f"({exc.strerror}); run with -u {info.st_uid}"
        ) from exc


def _request(
    socket: str,
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
    transport: httpx.BaseTransport | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    *,
    role: str = "vault",
) -> dict[str, Any]:
    if transport is None:
        become_socket_owner(socket)
        transport = httpx.HTTPTransport(uds=socket)
    try:
        with httpx.Client(
            transport=transport, base_url=f"http://{role}-admin", timeout=timeout
        ) as client:
            response = client.request(method, path, json=body)
    except (httpx.HTTPError, OSError, RuntimeError) as exc:
        # RuntimeError: httpx on Windows, where Unix sockets aren't supported.
        raise AdminUnavailable(f"can't reach the {role}'s admin socket at {socket}: {exc}") from exc
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
    return _request(socket, "PUT", f"/secrets/{name}", body, transport, SECRET_TIMEOUT)


def secret_list(socket: str, transport: httpx.BaseTransport | None = None) -> dict[str, Any]:
    return _request(socket, "GET", "/secrets", transport=transport)


def secret_delete(
    socket: str, name: str, transport: httpx.BaseTransport | None = None
) -> dict[str, Any]:
    return _request(
        socket, "DELETE", f"/secrets/{name}", transport=transport, timeout=SECRET_TIMEOUT
    )


def setup_code(socket: str, transport: httpx.BaseTransport | None = None) -> dict[str, Any]:
    return _request(socket, "POST", "/setup-code", transport=transport)


def gateway_key(socket: str, transport: httpx.BaseTransport | None = None) -> dict[str, Any]:
    return _request(socket, "GET", "/gateway-key", transport=transport)


def gateway_key_retire_previous(
    socket: str, transport: httpx.BaseTransport | None = None
) -> dict[str, Any]:
    """Retire the previous gateway key now. The answer is ``gateway_key``'s, plus ``retired``."""
    return _request(socket, "POST", "/gateway-key/retire-previous", transport=transport)


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


def gateway_status(socket: str, transport: httpx.BaseTransport | None = None) -> dict[str, Any]:
    return _request(socket, "GET", "/status", transport=transport, role="gateway")


def gateway_review(
    socket: str, server: str, *, clear: bool, transport: httpx.BaseTransport | None = None
) -> dict[str, Any]:
    """Review ``server`` on a fresh connection; with ``clear``, also clear its drift marks."""
    path = f"/review/{quote(server, safe='')}" + ("/clear" if clear else "")
    return _request(
        socket, "POST", path, transport=transport, timeout=REVIEW_TIMEOUT, role="gateway"
    )


LEDGER_PAGE: Final = 10_000


def gateway_ledger(
    socket: str,
    *,
    client: str | None = None,
    server: str | None = None,
    tool: str | None = None,
    transport: httpx.BaseTransport | None = None,
) -> list[dict[str, Any]]:
    """Every ledger record, oldest first, a page at a time."""
    found: list[dict[str, Any]] = []
    after = -1
    while True:
        query = {"after": str(after), "limit": str(LEDGER_PAGE)}
        query |= {k: v for k, v in (("client", client), ("server", server), ("tool", tool)) if v}
        path = "/ledger?" + "&".join(f"{k}={quote(v, safe='')}" for k, v in query.items())
        page = _request(socket, "GET", path, transport=transport, role="gateway")["records"]
        found.extend(page)
        if len(page) < LEDGER_PAGE:
            return found
        after = page[-1]["seq"]


def gateway_ledger_verify(
    socket: str, transport: httpx.BaseTransport | None = None
) -> dict[str, Any]:
    return _request(socket, "POST", "/ledger/verify", transport=transport, role="gateway")


def gateway_ledger_check(
    socket: str, ref: str, args: Any, transport: httpx.BaseTransport | None = None
) -> dict[str, Any]:
    body = {"ref": ref, "args": args}
    return _request(socket, "POST", "/ledger/check", body, transport=transport, role="gateway")


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
