"""The gateway's acceptance rig: the shipped S10 profile, the real vault and the real gateway
(M3 design L.3, L.4).

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
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import httpx

from tests.fakes.harness import serve
from tests.gateway.rig import Running, WithAdmin, token_for
from zoeymcp.cli.main import main
from zoeymcp.common import logs
from zoeymcp.common.policy import Policy
from zoeymcp.common.policy.schema import hash_token
from zoeymcp.common.policy.view import build_view
from zoeymcp.gateway.app import GatewayApp
from zoeymcp.gateway.defstore import DefinitionStore
from zoeymcp.gateway.marks import DriftMarks
from zoeymcp.gateway.upstream import UpstreamPool
from zoeymcp.gateway.vaultlink import KeySource, parse_link, view_client

from .conftest import Deployment, _HTTPTransport
from .tls import ProviderCA

PROFILE = "remote-mcp-static-key.yaml"
SERVER = "notes"
CLIENTS = ("agent1", "agent2")
NO_TOOLS = "tools: {include: [], allow: [], approve: []}"
NO_PINS = "review: {}"
NO_CLIENT = '      token_sha256: "sha256:' + "0" * 64 + '"\n      servers: [notes]\n'

Link = Literal["tcp", "unix"]


def server_text(tools: Mapping[str, str], pins: Mapping[str, str]) -> dict[str, str]:
    """The profile's replacements for these tools (name -> allow or approve) and pins."""
    include = sorted(tools)
    allow = [name for name in include if tools[name] == "allow"]
    approve = [name for name in include if tools[name] == "approve"]
    return {
        NO_TOOLS: "tools: " + json.dumps({"include": include, "allow": allow, "approve": approve}),
        NO_PINS: "review: " + json.dumps(dict(pins)),
    }


def client_text(clients: tuple[str, ...]) -> dict[str, str]:
    lines = [f'      token_sha256: "{hash_token(token_for(clients[0]))}"\n      servers: [notes]\n']
    lines += [
        f'    {name}:\n      token_sha256: "{hash_token(token_for(name))}"\n'
        "      servers: [notes]\n"
        for name in clients[1:]
    ]
    return {NO_CLIENT: "".join(lines)}


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


@dataclass
class Seen:
    """Everything a test showed an agent or an operator, for the sweeps."""

    log: io.StringIO = field(default_factory=io.StringIO)
    outputs: list[str] = field(default_factory=list)

    def everything(self) -> str:
        return self.log.getvalue() + "\n".join(self.outputs)

    def events(self, kind: str | None = None) -> list[dict[str, Any]]:
        parsed = [json.loads(line) for line in self.log.getvalue().splitlines() if line]
        return [line for line in parsed if kind is None or line["event"] == kind]


class GatewayDeployment:
    """The S10 profile with its upstream swapped for the fake, its tools and pins set, and a
    client per name in ``clients``."""

    def __init__(
        self,
        tmp_path: Path,
        upstream: str,
        ca: ProviderCA,
        *,
        key: str,
        tools: Mapping[str, str] | None = None,
        pins: Mapping[str, str] | None = None,
        clients: tuple[str, ...] = CLIENTS,
        link: Link = "tcp",
        link_uid: int | None = None,
        replace: Mapping[str, str] | None = None,
    ) -> None:
        self.state = tmp_path / "gateway"
        self.link = link
        self.clients = clients
        self.seen = Seen()
        socket = tmp_path / "link" / "vault.sock" if link == "unix" else None
        if socket is not None:
            socket.parent.mkdir(mode=0o700)
        self.vault = Deployment(
            tmp_path / "vault",
            PROFILE,
            upstream,
            ca,
            secrets={"notes-key": key},
            replace={
                **server_text(tools or {}, pins or {}),
                **client_text(clients),
                **(replace or {}),
            },
            link_socket=socket,
            link_uid=link_uid,
        )

    @property
    def policy(self) -> Policy:
        return self.vault.app.policy

    def reload(self, tools: Mapping[str, str], pins: Mapping[str, str]) -> None:
        """A new policy with these tools and pins, swapped into the running vault (SIGHUP)."""
        policy = self.vault.load(server_text(tools, pins))
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
                pool = UpstreamPool(
                    link, keys, DriftMarks.load(self.state), DefinitionStore(self.state),
                    limits=limits,
                )  # fmt: skip
                app = GatewayApp(pool, view_client(link, keys), policy_wait=1)
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
    deadline = time.monotonic() + timeout
    while httpx.get(f"{running.url}/healthz", timeout=5).status_code != 200:
        if time.monotonic() > deadline:
            raise RuntimeError("the gateway didn't become ready")
        time.sleep(0.05)
