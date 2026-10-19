"""A connection close drains committed calls; shutdown waits for them (M4 design B.6, step 6b)."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any

import anyio
import pytest
from mcp.types import CallToolResult
from starlette.types import Message

from tests.fakes.mcp_server import McpFake
from tests.gateway.rig import CLIENTS, KEYS, SERVER, deployment, pool_for, until
from tests.gateway.test_upstream import review, text
from zoeymcp.gateway.app import GatewayApp
from zoeymcp.gateway.upstream import UpstreamError, UpstreamPool
from zoeymcp.gateway.vaultlink import KeySource, parse_link, view_client

pytestmark = pytest.mark.anyio

TOOLS = ["echo", "add", "slow"]


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


async def slow(
    pool: UpstreamPool, deployed: Any, *, committed: bool, steps: int = 10
) -> CallToolResult:
    return await pool.call(
        SERVER,
        deployed.server,
        CLIENTS[0],
        "slow",
        {"steps": steps, "interval": 0.1},
        committed=committed,
    )


async def test_a_close_drains_committed_calls_and_cuts_the_rest(tmp_path: Path) -> None:
    fake = McpFake()
    with deployment(tmp_path, fake, include=TOOLS, review=review(fake), era="legacy") as deployed:
        async with pool_for(deployed) as pool:
            results: dict[str, Any] = {}

            async def run(name: str, committed: bool) -> None:
                try:
                    results[name] = text(await slow(pool, deployed, committed=committed))
                except UpstreamError as exc:
                    results[name] = (exc.outcome, exc.detail)

            async with anyio.create_task_group() as group:
                group.start_soon(run, "approved", True)
                group.start_soon(run, "allowed", False)
                await until(lambda: len(fake.calls) == 2)
                [connection] = pool.connections()
                assert connection.committed == 1
                pool.close_all("policy_stale")
                assert pool._draining == {connection}
                assert pool.connections() == []
            assert results == {
                "approved": "done after 10 steps",
                "allowed": ("connection_lost", "closed"),
            }
            await until(lambda: connection.done.is_set())
            assert pool._draining == set()
    [draining] = deployed.events("upstream_draining")
    assert draining["committed"] == 1
    assert len(fake.cancellations) == 1  # the allowed call's cancel reached the upstream


async def test_a_close_with_nothing_committed_ends_at_once(tmp_path: Path) -> None:
    fake = McpFake()
    with deployment(tmp_path, fake, include=TOOLS, review=review(fake), era="legacy") as deployed:
        async with pool_for(deployed) as pool:
            await pool.call(SERVER, deployed.server, CLIENTS[0], "echo", {"text": "hi"})
            [connection] = pool.connections()
            pool.close_all("policy_stale")
            await until(lambda: connection.done.is_set())
            assert pool._draining == set()
    assert deployed.events("upstream_draining") == []


async def test_a_new_call_opens_a_new_connection_while_one_drains(tmp_path: Path) -> None:
    fake = McpFake()
    with deployment(tmp_path, fake, include=TOOLS, review=review(fake), era="legacy") as deployed:
        async with pool_for(deployed) as pool:
            async with anyio.create_task_group() as group:
                group.start_soon(lambda: slow(pool, deployed, committed=True))
                await until(lambda: len(fake.calls) == 1)
                pool.close_all("policy_stale")
                args = {"a": 1, "b": 2}
                result = await pool.call(SERVER, deployed.server, CLIENTS[0], "add", args)
                assert text(result) == "3"
            assert len(fake.requests("initialize")) == 2


async def test_an_approved_call_is_never_retried_after_a_404(tmp_path: Path) -> None:
    fake = McpFake(session_404_after=1)
    with deployment(tmp_path, fake, include=TOOLS, review=review(fake), era="legacy") as deployed:
        async with pool_for(deployed) as pool:
            await pool.call(SERVER, deployed.server, CLIENTS[0], "echo", {"text": "1"})
            with pytest.raises(UpstreamError) as raised:
                await pool.call(
                    SERVER,
                    deployed.server,
                    CLIENTS[0],
                    "echo",
                    {"text": "2"},
                    committed=True,
                    retry_expired=False,
                )
    assert (raised.value.outcome, raised.value.detail) == ("connection_lost", "session_expired")
    assert [item.status for item in fake.requests("tools/call")] == [200, 404]


async def test_aclose_waits_for_a_committed_call(tmp_path: Path) -> None:
    fake = McpFake()
    with deployment(tmp_path, fake, include=TOOLS, review=review(fake), era="legacy") as deployed:
        async with pool_for(deployed) as pool:
            results: list[str] = []

            async def run() -> None:
                results.append(text(await slow(pool, deployed, committed=True, steps=8)))

            async with anyio.create_task_group() as group:
                group.start_soon(run)
                await until(lambda: len(fake.calls) == 1)
                await pool.aclose()
                assert results == ["done after 8 steps"]


async def test_cancel_committed_is_the_backstop(tmp_path: Path) -> None:
    fake = McpFake()
    with deployment(tmp_path, fake, include=TOOLS, review=review(fake), era="legacy") as deployed:
        async with pool_for(deployed) as pool:
            connection = pool.connection(SERVER, deployed.server, CLIENTS[0])
            scope, other = anyio.CancelScope(), anyio.CancelScope()
            connection._calls[scope] = anyio.current_time() + 1
            connection._calls[other] = None
            assert connection.committed == 1
            assert connection.cancel_committed() == 1
            assert scope.cancel_called
            assert not other.cancel_called
            connection._calls.clear()


async def test_a_full_pool_counts_draining_connections(tmp_path: Path) -> None:
    fake = McpFake()
    with deployment(tmp_path, fake, include=TOOLS, review=review(fake), era="legacy") as deployed:
        async with pool_for(deployed) as pool:
            pool.limits = pool.limits.model_copy(update={"max_upstream_sessions": 1})
            async with anyio.create_task_group() as group:
                group.start_soon(lambda: slow(pool, deployed, committed=True))
                await until(lambda: len(fake.calls) == 1)
                pool.close_all("policy_stale")
                with pytest.raises(UpstreamError) as raised:
                    pool.connection(SERVER, deployed.server, CLIENTS[1])
                assert raised.value.detail == "gateway busy"


# --- the gateway's stop -------------------------------------------------------------------------


def gateway_app(deployed: Any, pool: UpstreamPool) -> GatewayApp:
    http = view_client(parse_link(deployed.vault_url), KeySource(KEYS.gateway_key(1)))
    return GatewayApp(pool, http, policy_wait=1)


async def test_the_stop_flag_runs_its_hooks_once(tmp_path: Path) -> None:
    fake = McpFake()
    with deployment(tmp_path, fake, include=TOOLS, review=review(fake), era="legacy") as deployed:
        async with pool_for(deployed) as pool:
            app = gateway_app(deployed, pool)
            seen: list[str] = []
            app.stop_hooks.append(lambda: seen.append("stop"))
            assert not app.stop_requested
            app.request_stop()
            app.request_stop()
            assert app.stop_requested
            assert seen == ["stop"]


async def test_shutdown_waits_for_committed_calls_first(tmp_path: Path) -> None:
    fake = McpFake()
    with deployment(tmp_path, fake, include=TOOLS, review=review(fake), era="legacy") as deployed:
        async with pool_for(deployed) as pool:
            app = gateway_app(deployed, pool)
            started, shutdown = anyio.Event(), anyio.Event()
            sent: list[tuple[str, float]] = []
            phase = iter(["startup", "shutdown"])

            async def receive() -> Message:
                which = next(phase)
                if which == "shutdown":
                    await shutdown.wait()
                return {"type": f"lifespan.{which}"}

            async def send(message: Message) -> None:
                sent.append((message["type"], time.monotonic()))
                if message["type"] == "lifespan.startup.complete":
                    started.set()

            finished: list[float] = []

            async def work() -> None:
                await anyio.sleep(0.5)
                finished.append(time.monotonic())

            async with anyio.create_task_group() as group:
                group.start_soon(app.lifespan, receive, send)
                await started.wait()
                # A request task awaiting a committed call, cancelled as uvicorn would.
                request = asyncio.get_running_loop().create_task(app.committed.run("r1", 5, work))
                await anyio.sleep(0.05)
                request.cancel()
                shutdown.set()
            [(_, done_at)] = [item for item in sent if item[0] == "lifespan.shutdown.complete"]
            assert finished
            assert finished[0] <= done_at
