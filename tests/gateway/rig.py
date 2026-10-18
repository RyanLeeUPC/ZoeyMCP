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
from mcp.types import Tool

from tests.fakes.harness import serve
from tests.fakes.mcp_server import McpFake
from zoeymcp.common.policy import Policy
from zoeymcp.common.policy.schema import hash_token
from zoeymcp.common.policy.view import GatewayView, ViewRemoteServer, build_view
from zoeymcp.gateway import logs
from zoeymcp.gateway.defstore import DefinitionStore
from zoeymcp.gateway.marks import DriftMarks
from zoeymcp.gateway.pins import project_and_pin
from zoeymcp.gateway.upstream import UpstreamPool
from zoeymcp.gateway.vaultlink import KeySource, parse_link
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
) -> dict[str, Any]:
    return {
        "version": 1,
        "mode": "declarative",
        "gateway_key_generation": 1,
        "admin": {"listen": "127.0.0.1:8081", "hosts": ["localhost"]},
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
        "gateway": {
            "limits": limits or {},
            "clients": {
                name: {"token_sha256": hash_token(f"zgc1-{name}-token"), "servers": [SERVER]}
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
                    "tools": {"include": include, "allow": include},
                    "review": review,
                }
            },
        },
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
            with serve(app) as vault_url:
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
