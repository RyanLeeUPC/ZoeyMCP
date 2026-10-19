"""A real vault in front of the fake MCP server, and the gateway's upstream pool on it.

The fake and the vault each run on a uvicorn thread. The pool runs in the test's event loop and
reaches the vault over TCP with the gateway key, as the hardened tier does.
"""

from __future__ import annotations

import copy
import io
import json
import time
from collections.abc import AsyncIterator, Callable, Iterator
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import anyio
import httpx
import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.types import Tool
from starlette.types import ASGIApp, Receive, Scope, Send

from tests.fakes.harness import serve
from tests.fakes.mcp_server import McpFake
from zoeymcp.common.policy import Policy
from zoeymcp.common.policy.schema import hash_token
from zoeymcp.common.policy.view import GatewayView, ViewRemoteServer, build_view
from zoeymcp.gateway import logs
from zoeymcp.gateway.app import GatewayApp
from zoeymcp.gateway.defstore import DefinitionStore
from zoeymcp.gateway.ledger import Ledger
from zoeymcp.gateway.marks import DriftMarks
from zoeymcp.gateway.pins import project_and_pin
from zoeymcp.gateway.server import AdminApp
from zoeymcp.gateway.upstream import UpstreamPool
from zoeymcp.gateway.vaultlink import KeySource, parse_link, view_client
from zoeymcp.vault.app import VaultApp
from zoeymcp.vault.bindings import derive_binding
from zoeymcp.vault.keys import KeySet
from zoeymcp.vault.store import SecretStore

KEYS = KeySet.from_master(bytes(range(64, 96)))
SERVER = "notes"
CLIENTS = ("agent1", "agent2")


def pin_of_fake(fake: McpFake, name: str, *, session: str | None = None, listing: int = 1) -> str:
    """The pin of one of the fake's tools, as a session's ``listing``-th listing shows it."""
    tools = fake.tools_for(session, listing)
    wire = next(tool for tool in tools if tool["name"] == name)
    return project_and_pin(Tool.model_validate(copy.deepcopy(wire))).pin


def raw_policy(
    fake_url: str,
    *,
    include: list[str],
    review: dict[str, str],
    era: str = "auto",
    on_drift: str = "hide",
    shared_session: bool = False,
    limits: dict[str, Any] | None = None,
    clients: tuple[str, ...] = CLIENTS,
    path: str = "/mcp",
    approve: list[str] | None = None,
    wrap_results: bool = False,
    sources: dict[str, list[str]] | None = None,
    servers: dict[str, Any] | None = None,
    assigned: dict[str, list[str]] | None = None,
    hosts: list[str] | None = None,
    origins: list[str] | None = None,
    approvals: dict[str, dict[str, Any]] | None = None,
    gateway_approvals: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """The rig's policy. ``servers`` adds gateway servers; ``assigned`` overrides a client's
    server list (each client gets ``[SERVER]`` otherwise)."""
    approve = approve or []
    gateway: dict[str, Any] = {
        "limits": limits or {},
        "clients": {
            name: {
                "token_sha256": hash_token(f"zgc1-{name}-token"),
                "servers": (assigned or {}).get(name, [SERVER]),
                "sources": (sources or {}).get(name, []),
                **({"approvals": (approvals or {})[name]} if name in (approvals or {}) else {}),
            }
            for name in clients
        },
        "servers": {
            SERVER: {
                "kind": "remote",
                "route": "notes",
                "path": path,
                "era": era,
                "on_drift": on_drift,
                "shared_session": shared_session,
                "wrap_results": wrap_results,
                "tools": {
                    "include": include,
                    "allow": [name for name in include if name not in approve],
                    "approve": approve,
                },
                "review": review,
            },
            **(servers or {}),
        },
    }
    if gateway_approvals is not None:
        gateway["approvals"] = gateway_approvals
    if hosts is not None:
        gateway["hosts"] = hosts
    if origins is not None:
        gateway["origins"] = origins
    return {
        "version": 1,
        "mode": "declarative",
        "gateway_key_generation": 1,
        "credentials": {"notes-key": {"kind": "header", "secret": "store:notes-key"}},
        "routes": [
            {
                "name": "notes",
                "prefix": "/notes",
                "upstream": fake_url,
                "allow_insecure_upstream": True,
                "credential": "notes-key",
                "callers": ["gateway"],
                "stream": True,
                "rules": [{"methods": ["POST", "GET", "DELETE"], "paths": [path]}],
            }
        ],
        "gateway": gateway,
    }


@dataclass
class Deployed:
    fake: McpFake
    vault_url: str
    policy: Policy
    view: GatewayView
    state: Path
    log: io.StringIO = field(default_factory=io.StringIO)
    fake_url: str = ""
    options: dict[str, Any] = field(default_factory=dict)

    @property
    def server(self) -> ViewRemoteServer:
        server = self.view.gateway.servers[SERVER]
        assert isinstance(server, ViewRemoteServer)
        return server

    def events(self, kind: str | None = None) -> list[dict[str, Any]]:
        parsed = [json.loads(line) for line in self.log.getvalue().splitlines()]
        return [line for line in parsed if kind is None or line["event"] == kind]

    def changed(self, **options: Any) -> GatewayView:
        """The view of this deployment's policy with ``raw_policy`` options changed."""
        raw = raw_policy(self.fake_url, **{**self.options, **options})
        return build_view(Policy.model_validate(raw))

    def reload(self, **options: Any) -> None:
        """Reload the running vault with ``raw_policy`` options changed, as SIGHUP would."""
        self.options = {**self.options, **options}
        raw = raw_policy(self.fake_url, **self.options)
        answer = httpx.post(self.vault_url + RELOAD_PATH, json=raw, timeout=10)
        assert answer.status_code == 204, answer.text
        self.policy = Policy.model_validate(raw)
        self.view = build_view(self.policy)


RELOAD_PATH = "/_test_reload"


class Reloadable:
    """The vault, plus a test-only path that swaps its policy on the vault's own loop."""

    def __init__(self, app: VaultApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope["path"] == RELOAD_PATH:
            chunks = []
            while True:
                message = await receive()
                chunks.append(message.get("body", b""))
                if not message.get("more_body"):
                    break
            self.app.reload(Policy.model_validate(json.loads(b"".join(chunks))))
            await send({"type": "http.response.start", "status": 204, "headers": []})
            await send({"type": "http.response.body", "body": b""})
            return
        await self.app(scope, receive, send)


@contextmanager
def deployment(tmp_path: Path, fake: McpFake, **options: Any) -> Iterator[Deployed]:
    """The fake, and a real vault routing ``/notes`` to it for the gateway only."""
    log = io.StringIO()
    logs.set_stream(log)
    try:
        with serve(fake.app(), lifespan=True) as fake_url:
            policy = Policy.model_validate(raw_policy(fake_url, **options))
            store = SecretStore(tmp_path / "vault", KEYS)
            store.load()
            store.put("notes-key", fake.secret, derive_binding(policy, "notes-key"))
            app = VaultApp(policy, store, KEYS, client=httpx.AsyncClient(), environ={})
            with serve(Reloadable(app)) as vault_url:
                yield Deployed(
                    fake,
                    vault_url,
                    policy,
                    build_view(policy),
                    tmp_path / "gateway",
                    log,
                    fake_url=fake_url,
                    options=options,
                )
    finally:
        logs.set_stream(None)


@asynccontextmanager
async def pool_for(
    deployed: Deployed, *, clock: Callable[[], float] | None = None
) -> AsyncIterator[UpstreamPool]:
    """The gateway's upstream pool on the deployment's vault, running until the block ends."""
    pool = UpstreamPool(
        parse_link(deployed.vault_url),
        KeySource(KEYS.gateway_key(1)),
        DriftMarks.load(deployed.state),
        DefinitionStore(deployed.state),
        limits=deployed.view.gateway.limits,
        clock=clock if clock is not None else time.monotonic,
    )
    async with anyio.create_task_group() as group:
        await group.start(pool.run)
        try:
            yield pool
        finally:
            await pool.aclose()
            group.cancel_scope.cancel()


async def until(condition: Callable[[], object], timeout: float = 10.0) -> None:
    """Wait for ``condition``, failing instead of hanging."""
    with anyio.fail_after(timeout):
        while not condition():
            await anyio.sleep(0.02)


class Clock:
    """A clock the test moves. Starts at the real monotonic time, so timers agree at first."""

    def __init__(self) -> None:
        self.now = time.monotonic()

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


# --- the whole gateway ---------------------------------------------------------------------------


def token_for(client: str) -> str:
    """The token whose hash ``raw_policy`` gives each client."""
    return f"zgc1-{client}-token"


ADMIN_PREFIX = "/_test_admin"


class WithAdmin:
    """The gateway app, and its admin app under :data:`ADMIN_PREFIX`, on one event loop.

    The admin socket is served next to the gateway in the same loop in production too: a review
    opens a connection in the pool's task group.
    """

    def __init__(self, app: GatewayApp) -> None:
        self.app = app
        self.admin: ASGIApp = AdminApp(app)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        path = scope.get("path", "")
        if scope["type"] == "http" and path.startswith(ADMIN_PREFIX):
            await self.admin({**scope, "path": path[len(ADMIN_PREFIX) :]}, receive, send)
            return
        await self.app(scope, receive, send)


@dataclass
class Running:
    app: GatewayApp
    url: str  # the gateway's base URL

    def mcp(self, server: str = SERVER) -> str:
        return f"{self.url}/s/{server}/mcp"

    @property
    def admin_url(self) -> str:
        return self.url + ADMIN_PREFIX


@contextmanager
def gateway(deployed: Deployed, *, policy_wait: int = 1) -> Iterator[Running]:
    """The gateway app on a uvicorn thread, on the deployment's vault, once it is ready."""
    pool = UpstreamPool(
        parse_link(deployed.vault_url),
        KeySource(KEYS.gateway_key(1)),
        DriftMarks.load(deployed.state),
        DefinitionStore(deployed.state),
        limits=deployed.view.gateway.limits,
    )
    http = view_client(parse_link(deployed.vault_url), KeySource(KEYS.gateway_key(1)))
    app = GatewayApp(pool, http, policy_wait=policy_wait)
    app.ledger, _ = Ledger.open_at(
        deployed.state, max_bytes=deployed.view.gateway.limits.ledger_max_bytes
    )
    with serve(WithAdmin(app), lifespan=True, proxy_headers=False) as url:
        deadline = time.monotonic() + 10
        while httpx.get(f"{url}/healthz", timeout=5).status_code != 200:
            if time.monotonic() > deadline:
                raise RuntimeError("the gateway didn't become ready")
            time.sleep(0.05)
        yield Running(app, url)


@asynccontextmanager
async def agent(
    running: Running,
    client: str = CLIENTS[0],
    mode: str = "auto",
    *,
    server: str = SERVER,
    headers: dict[str, str] | None = None,
    **options: Any,
) -> AsyncIterator[Client]:
    """An SDK client as an agent uses it, with the client's bearer token."""
    headers = {"authorization": f"Bearer {token_for(client)}", **(headers or {})}
    async with httpx2.AsyncClient(headers=headers, timeout=httpx2.Timeout(30.0)) as http:
        transport = streamable_http_client(running.mcp(server), http_client=http)
        async with Client(transport, mode=mode, cache=None, **options) as connected:
            yield connected
