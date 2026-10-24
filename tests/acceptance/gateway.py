"""The gateway's acceptance rig: a shipped remote MCP profile (S10 by default), the real vault
and the real gateway (M3 design L.3, L.4).

Agent (SDK client) -> gateway (real socket) -> vault (real socket) -> fake MCP server (real
TLS, verified against the test CA). The gateway reaches the vault over TCP with the gateway key,
as in the hardened tier, or over the link socket with the peer check, as in the standard tier
(Linux only).

Every log line of both roles goes to one buffer, and every CLI output and agent answer a test
looks at is recorded too, so a test can sweep them all for anything that must never appear
(G13, G20).
"""

from __future__ import annotations

import io
import json
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Literal

import httpx

from tests.fakes.harness import serve
from tests.gateway.rig import Running, WithAdmin, token_for
from tests.gateway.toolkit_rig import ENTRY_POINTS
from zoeymcp.cli.main import main
from zoeymcp.common import logs
from zoeymcp.common.policy import Policy
from zoeymcp.common.policy.schema import hash_token
from zoeymcp.common.policy.view import build_view
from zoeymcp.gateway.app import GatewayApp
from zoeymcp.gateway.defstore import DefinitionStore
from zoeymcp.gateway.ledger import Ledger
from zoeymcp.gateway.marks import DriftMarks
from zoeymcp.gateway.server import pushed_status
from zoeymcp.gateway.toolkits import Toolkits
from zoeymcp.gateway.upstream import UpstreamPool
from zoeymcp.gateway.vaultlink import (
    KeySource,
    parse_link,
    report_client,
    status_client,
    view_client,
)

from .conftest import Clock, Deployment, _HTTPTransport
from .helpers import Seen, wait_until
from .tls import ProviderCA

PROFILE = "remote-mcp-static-key.yaml"
SERVER = "notes"
CLIENTS = ("agent1", "agent2")
NO_TOOLS = "tools: {include: [], allow: [], approve: []}"
NO_PINS = "review: {}"
Link = Literal["tcp", "unix"]


def no_client(server: str) -> str:
    """A profile's placeholder client, assigned ``server``."""
    return '      token_sha256: "sha256:' + "0" * 64 + f'"\n      servers: [{server}]\n'


NO_CLIENT = no_client(SERVER)


def server_text(
    tools: Mapping[str, str],
    pins: Mapping[str, str],
    declined: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """The profile's replacements for these tools (name -> allow or approve) and pins, and the
    server's declined block when ``declined`` is given (M6 design J.5)."""
    include = sorted(tools)
    allow = [name for name in include if tools[name] == "allow"]
    approve = [name for name in include if tools[name] == "approve"]
    review = "review: " + json.dumps(dict(pins))
    if declined is not None:
        review += "\n      declined: " + json.dumps(dict(declined))
    return {
        NO_TOOLS: "tools: " + json.dumps({"include": include, "allow": allow, "approve": approve}),
        NO_PINS: review,
    }


def client_text(clients: tuple[str, ...], server: str = SERVER) -> dict[str, str]:
    lines = [
        f'      token_sha256: "{hash_token(token_for(clients[0]))}"\n      servers: [{server}]\n'
    ]
    lines += [
        f'    {name}:\n      token_sha256: "{hash_token(token_for(name))}"\n'
        f"      servers: [{server}]\n"
        for name in clients[1:]
    ]
    return {no_client(server): "".join(lines)}


class GatewayAdminTransport(httpx.BaseTransport):
    """The CLI's gateway admin requests, sent to the running gateway's admin app."""

    def __init__(self, admin_url: str) -> None:
        self._url = httpx.URL(admin_url)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        request.url = request.url.copy_with(
            scheme=self._url.scheme,
            host=self._url.host,
            port=self._url.port,
            raw_path=self._url.raw_path + request.url.raw_path,
        )
        with _HTTPTransport() as transport:
            response = transport.handle_request(request)
            response.read()
        return response


class GatewayDeployment:
    """``profile`` (S10 by default) with its upstream swapped for the fake, its tools and pins
    set, and a client per name in ``clients``.

    ``tools`` and ``pins`` fill in S10's empty lists; leave both out to keep a profile's own.
    ``declined`` is the server's declined block beside them (M6 design J.5).
    ``secrets`` go into the store before the vault starts, and the vault's token manager reads
    ``clock``, which a test can move along with the fakes' clocks. With ``portal`` the vault
    serves its portal too, over either link (M5 design O.1, review finding R9).

    With ``reporter`` the gateway reports its ledger to the vault's copy over the link, as
    ``zoeymcp gateway`` does (M5 design J.3), and the portal's Ledger page reads it; with
    ``status_push`` it pushes its status report, which health and Home read (M6 design K.1).
    ``extra`` merges another fragment into the profile's (``Deployment``); with ``toolkits`` the
    gateway loads the example toolkits from their entry points, as the toolkit rig does.

    ``server`` is the profile's one server, which its placeholder client is assigned; with
    ``socket_clients`` the vault reaches a ``unix:`` route's bridge as ``--bridge`` has it (M7
    design B.2, S11), and with ``guarded`` its routes on its own guarded clients
    (``Deployment``).
    """

    def __init__(
        self,
        tmp_path: Path,
        upstream: str,
        ca: ProviderCA,
        *,
        profile: str = PROFILE,
        secrets: Mapping[str, str] | None = None,
        tools: Mapping[str, str] | None = None,
        pins: Mapping[str, str] | None = None,
        declined: Mapping[str, str] | None = None,
        clients: tuple[str, ...] = CLIENTS,
        link: Link = "tcp",
        link_uid: int | None = None,
        replace: Mapping[str, str] | None = None,
        clock: Clock | None = None,
        portal: bool = False,
        reporter: bool = False,
        status_push: bool = False,
        extra: Mapping[str, Any] | None = None,
        toolkits: bool = False,
        server: str = SERVER,
        socket_clients: Callable[[str], httpx.AsyncClient | None] | None = None,
        guarded: bool = False,
    ) -> None:
        self.state = tmp_path / "gateway"
        self.link = link
        self.reporter = reporter
        self.status_push = status_push
        self.toolkits = toolkits
        self.clients = clients
        self.seen = Seen()
        socket = tmp_path / "link" / "vault.sock" if link == "unix" else None
        if socket is not None:
            socket.parent.mkdir(mode=0o700)
        listed = (
            {} if tools is None and pins is None else server_text(tools or {}, pins or {}, declined)
        )
        self.vault = Deployment(
            tmp_path / "vault",
            profile,
            upstream,
            ca,
            secrets=dict(secrets or {}),
            replace={**listed, **client_text(clients, server), **(replace or {})},
            link_socket=socket,
            link_uid=link_uid,
            clock=clock,
            portal=portal,
            reports=reporter,
            extra=extra,
            socket_clients=socket_clients,
            guarded=guarded,
        )

    @property
    def policy(self) -> Policy:
        return self.vault.app.policy

    def reload(
        self,
        tools: Mapping[str, str],
        pins: Mapping[str, str],
        declined: Mapping[str, str] | None = None,
    ) -> None:
        """A new policy with these tools, pins and declined tools, swapped into the running
        vault (SIGHUP)."""
        policy = self.vault.load(server_text(tools, pins, declined))
        self.vault.call(lambda: self.vault.app.reload(policy))

    @contextmanager
    def running(self, *, ready: bool = True) -> Iterator[Running]:
        """The vault, then the gateway on it; waits for a fresh view unless ``ready`` is off."""
        logs.set_stream(self.seen.log)
        try:
            with self.vault.running() as vault:
                if self.link == "unix":
                    assert self.vault.link_socket is not None
                    link = parse_link(f"unix:{self.vault.link_socket}")
                    keys = None
                else:
                    link = parse_link(str(vault.base_url).rstrip("/"))
                    keys = KeySource(self.vault.keys.gateway_key(1))
                limits = build_view(self.vault.policy).gateway.limits
                marks = DriftMarks.load(self.state)
                pool = UpstreamPool(
                    link, keys, marks, DefinitionStore(self.state), limits=limits,
                )  # fmt: skip
                toolkits = None
                if self.toolkits:
                    toolkits = Toolkits(
                        link, keys, marks, entry_points=lambda: ENTRY_POINTS, allow_writable=True
                    )
                app = GatewayApp(
                    pool,
                    view_client(link, keys),
                    policy_wait=1,
                    toolkits=toolkits,
                    report_http=report_client(link, keys) if self.reporter else None,
                    status_http=status_client(link, keys) if self.status_push else None,
                    status=pushed_status,
                )
                app.ledger, _ = Ledger.open_at(self.state, max_bytes=limits.ledger_max_bytes)
                with serve(WithAdmin(app), lifespan=True, proxy_headers=False) as url:
                    running = Running(app, url)
                    if ready:
                        wait_healthy(running)
                    yield running
        finally:
            logs.set_stream(None)

    def cli(self, running: Running, *argv: str) -> tuple[int, str, str]:
        """``zoeymcp <argv>`` against the running gateway's admin socket; output is recorded."""
        original = httpx.HTTPTransport
        httpx.HTTPTransport = lambda **_: GatewayAdminTransport(running.admin_url)  # type: ignore[assignment,misc]
        try:
            out, err = io.StringIO(), io.StringIO()
            code = main(list(argv), stdin=io.StringIO(), out=out, err=err)
        finally:
            httpx.HTTPTransport = original  # type: ignore[misc]
        self.seen.outputs += [out.getvalue(), err.getvalue()]
        return code, out.getvalue(), err.getvalue()


def wait_healthy(running: Running, timeout: float = 15.0) -> None:
    wait_until(
        lambda: httpx.get(f"{running.url}/healthz", timeout=5).status_code == 200,
        "the gateway didn't become ready",
        timeout,
    )
