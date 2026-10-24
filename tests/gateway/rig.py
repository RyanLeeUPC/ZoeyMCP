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
from zoeymcp.common.policy.schema import GatewayLimits, hash_token
from zoeymcp.common.policy.view import GatewayView, ViewRemoteServer, build_view
from zoeymcp.gateway import logs
from zoeymcp.gateway.app import GatewayApp
from zoeymcp.gateway.defstore import DefinitionStore
from zoeymcp.gateway.ledger import Ledger
from zoeymcp.gateway.marks import DriftMarks
from zoeymcp.gateway.pins import ProjectionError, project_and_pin, tool_problems
from zoeymcp.gateway.server import AdminApp, pushed_status
from zoeymcp.gateway.upstream import UpstreamPool
from zoeymcp.gateway.vaultlink import (
    KeySource,
    parse_link,
    report_client,
    review_client,
    status_client,
    view_client,
)
from zoeymcp.vault.admin import AdminApp as VaultAdmin
from zoeymcp.vault.admin import SetupCodes
from zoeymcp.vault.app import VaultApp
from zoeymcp.vault.bindings import derive_binding
from zoeymcp.vault.keys import KeySet
from zoeymcp.vault.reportstore import ReportStore
from zoeymcp.vault.store import SecretStore

KEYS = KeySet.from_master(bytes(range(64, 96)))
SERVER = "notes"
CLIENTS = ("agent1", "agent2")
LIMITS = GatewayLimits()


def pin_of_fake(fake: McpFake, name: str, *, session: str | None = None, listing: int = 1) -> str:
    """The pin of one of the fake's tools, as a session's ``listing``-th listing shows it."""
    tools = fake.tools_for(session, listing)
    wire = next(tool for tool in tools if tool["name"] == name)
    return project_and_pin(Tool.model_validate(copy.deepcopy(wire))).pin


def pins_of_the_rest(fake: McpFake, include: list[str]) -> dict[str, str]:
    """The pins of every tool the fake lists that ``include`` leaves out and that can be pinned:
    the declined block of a server reviewed once, so nothing is left that nobody reviewed (M6
    design J.5)."""
    rest = {}
    for wire in fake.tools_for(None, 1):
        try:
            projected = project_and_pin(Tool.model_validate(copy.deepcopy(wire)))
        except ProjectionError:
            continue
        if wire["name"] not in include and not tool_problems(projected.definition, LIMITS):
            rest[wire["name"]] = projected.pin
    return rest


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
    declined: dict[str, str] | None = None,
) -> dict[str, Any]:
    """The rig's policy. ``servers`` adds gateway servers; ``assigned`` overrides a client's
    server list (each client gets ``[SERVER]`` otherwise); ``declined`` is the server's
    declined block (M6 design J.5), left out when not given."""
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
                **({"declined": declined} if declined is not None else {}),
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
    # The vault app, for what it keeps in memory (the gateway's status report, M6 design K.1).
    vault: VaultApp | None = None

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

    @property
    def vault_admin_url(self) -> str:
        """The vault's admin socket app, served beside it (:class:`Reloadable`)."""
        return self.vault_url + VAULT_ADMIN_PREFIX

    def reload(self, **options: Any) -> None:
        """Reload the running vault with ``raw_policy`` options changed, as SIGHUP would."""
        self.options = {**self.options, **options}
        raw = raw_policy(self.fake_url, **self.options)
        answer = httpx.post(self.vault_url + RELOAD_PATH, json=raw, timeout=10)
        assert answer.status_code == 204, answer.text
        self.policy = Policy.model_validate(raw)
        self.view = build_view(self.policy)


RELOAD_PATH = "/_test_reload"
VAULT_ADMIN_PREFIX = "/_test_vault_admin"


class Reloadable:
    """The vault, plus a test-only path that swaps its policy on the vault's own loop and, with
    ``admin``, the vault's admin socket app under :data:`VAULT_ADMIN_PREFIX`, on that loop too,
    as the vault serves its socket."""

    def __init__(self, app: VaultApp, admin: ASGIApp | None = None) -> None:
        self.app = app
        self.admin = admin

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        path = scope.get("path", "")
        if (
            scope["type"] == "http"
            and self.admin is not None
            and path.startswith(VAULT_ADMIN_PREFIX)
        ):
            inner = {**scope, "path": path[len(VAULT_ADMIN_PREFIX) :], "root_path": ""}
            await self.admin(inner, receive, send)
            return
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
    with deployment_with(tmp_path, fake, options) as deployed:
        yield deployed


@contextmanager
def deployment_with(
    tmp_path: Path,
    fake: McpFake,
    options: dict[str, Any],
    *,
    reports: ReportStore | None = None,
    wrap: Callable[[ASGIApp], ASGIApp] | None = None,
) -> Iterator[Deployed]:
    """:func:`deployment` with ``raw_policy`` ``options``, where ``reports`` is the vault's copy
    of the gateway's ledger (the report path answers 503 without one) and ``wrap`` wraps the
    vault's app, for a test that changes how it answers."""
    log = io.StringIO()
    logs.set_stream(log)
    try:
        with serve(fake.app(), lifespan=True) as fake_url:
            policy = Policy.model_validate(raw_policy(fake_url, **options))
            store = SecretStore(tmp_path / "vault", KEYS)
            store.load()
            store.put("notes-key", fake.secret, derive_binding(policy, "notes-key"))
            app = VaultApp(
                policy, store, KEYS, client=httpx.AsyncClient(), environ={}, reports=reports
            )
            setup = SetupCodes(tmp_path / "vault", KEYS.portal_key)
            admin = VaultAdmin(
                store,
                KEYS,
                lambda: app.policy,
                setup,
                reviews=app,
                gateway_status=app.gateway_status,
            )
            served: ASGIApp = Reloadable(app, admin.app)
            with serve(wrap(served) if wrap is not None else served) as vault_url:
                yield Deployed(
                    fake,
                    vault_url,
                    policy,
                    build_view(policy),
                    tmp_path / "gateway",
                    log,
                    fake_url=fake_url,
                    options=options,
                    vault=app,
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
def gateway(
    deployed: Deployed,
    *,
    policy_wait: int = 1,
    report: bool = False,
    review: bool = False,
    status_push: bool = False,
) -> Iterator[Running]:
    """The gateway app on a uvicorn thread, on the deployment's vault, once it is ready.
    With ``report``, it reports its ledger to the vault, with ``review`` it polls for the
    vault's review jobs, and with ``status_push`` it pushes its status report (M6 design K.1),
    as ``zoeymcp gateway`` does."""
    pool = UpstreamPool(
        parse_link(deployed.vault_url),
        KeySource(KEYS.gateway_key(1)),
        DriftMarks.load(deployed.state),
        DefinitionStore(deployed.state),
        limits=deployed.view.gateway.limits,
    )
    link, keys = parse_link(deployed.vault_url), KeySource(KEYS.gateway_key(1))
    reporting = report_client(link, keys) if report else None
    reviewing = review_client(link, keys) if review else None
    app = GatewayApp(
        pool,
        view_client(link, keys),
        policy_wait=policy_wait,
        report_http=reporting,
        review_http=reviewing,
        status_http=status_client(link, keys) if status_push else None,
        status=pushed_status,
    )
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
