"""Listen streams, both ways (M6 design K.4; D-46).

Upstream: a modern connection lists once its listen stream is acknowledged, on the first open and
on every reopen, so a change the server announced before the stream was there, which no stream
heard, is seen within a second, with no re-announcement (the fake's ``announce_before_listen``,
step 3a). That listing is a background re-list, as the timer's is: one that fails leaves a READY
connection READY. Listings may follow each other at once here (``COALESCE`` 0), as in
test_upstream.py.

Downstream: an agent's listen is acknowledged for what the path sends and nothing else: tools
only, until R31 is switched on; never resource subscriptions.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import anyio
import pytest

from tests.fakes.mcp_server import McpFake, Switch
from tests.gateway.rig import (
    CLIENTS,
    SERVER,
    agent,
    deployment,
    gateway,
    pin_of_fake,
    pool_for,
    until,
)
from zoeymcp.gateway import upstream
from zoeymcp.gateway.connstate import Phase
from zoeymcp.gateway.upstream import Connection, ListingFailed

pytestmark = pytest.mark.anyio

TOOLS = ["echo", "add", "slow"]
SEEN_WITHIN = 1.0  # seconds from the server's change to the gateway's listing of it


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(autouse=True)
def quick(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(upstream, "COALESCE", 0.0)


def review(fake: McpFake) -> dict[str, str]:
    return {name: pin_of_fake(fake, name) for name in TOOLS}


def echo_shows(connection: Connection, change: int) -> Callable[[], bool]:
    """Whether the connection's last listing shows the fake's ``change``-th change of echo."""

    def shown() -> bool:
        [echo] = [tool for tool in connection.tools if tool.name == "echo"]
        return (echo.description or "").endswith(f" Changed before listen stream {change}.")

    return shown


async def test_a_change_before_the_first_listen_is_seen(tmp_path: Path) -> None:
    fake = McpFake(switches={Switch.ANNOUNCE_BEFORE_LISTEN})
    pinned = review(fake)
    with deployment(tmp_path, fake, include=TOOLS, review=pinned) as deployed:
        async with pool_for(deployed) as pool:
            connection = pool.connection(SERVER, deployed.server, CLIENTS[0])
            assert "echo" in (await pool.wait_ready(connection)).exposed
            await until(lambda: fake.listen_changes == 1)
            await until(echo_shows(connection, 1), timeout=SEEN_WITHIN)
            await until(lambda: pool.marks.for_server(SERVER))
    assert connection.era == "modern"
    # The announcement reached no stream: only the listing on the open saw the change.
    assert (fake.listens, fake.announced) == (1, 1)
    triggers = [line["trigger"] for line in deployed.events("listing")]
    assert triggers == ["connect", "subscribed"]
    assert pool.marks.for_server(SERVER) == {("echo", pinned["echo"])}
    [drift] = deployed.events("tool_drift")
    assert (drift["tool"], drift["changed"]) == ("echo", ["description"])


async def test_a_change_before_a_reopen_is_seen(tmp_path: Path) -> None:
    fake = McpFake(switches={Switch.ANNOUNCE_BEFORE_LISTEN})
    with deployment(tmp_path, fake, include=TOOLS, review=review(fake)) as deployed:
        async with pool_for(deployed) as pool:
            connection = pool.connection(SERVER, deployed.server, CLIENTS[0])
            await pool.wait_ready(connection)
            await until(echo_shows(connection, 1))
            await anyio.to_thread.run_sync(fake.drop_listens)
            # The reopen waits out the listen backoff (0.5 to 1.5 s) after the loss's listing.
            await until(lambda: fake.listen_changes == 2)
            await until(echo_shows(connection, 2), timeout=SEEN_WITHIN)
    assert (fake.listens, fake.dropped, fake.announced) == (2, 1, 2)
    triggers = [line["trigger"] for line in deployed.events("listing")]
    assert triggers == ["connect", "subscribed", "subscription_lost", "subscribed"]


async def test_a_failed_listing_on_open_keeps_the_connection_ready(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    walk = Connection._walk
    walks = 0

    async def second_fails(self: Connection, client: Any) -> Any:
        nonlocal walks
        walks += 1
        if walks == 2:
            raise ListingFailed("pages")
        return await walk(self, client)

    monkeypatch.setattr(Connection, "_walk", second_fails)
    fake = McpFake()
    with deployment(tmp_path, fake, include=TOOLS, review=review(fake)) as deployed:
        async with pool_for(deployed) as pool:
            connection = pool.connection(SERVER, deployed.server, CLIENTS[0])
            await pool.wait_ready(connection)
            await until(lambda: bool(deployed.events("server_list_failed")))
            # The connect listing is recent, so the failed one on the open is within its grace.
            assert connection.state.phase is Phase.READY
            assert await pool.admit(connection, "echo") == pin_of_fake(fake, "echo")
    assert fake.listens == 1
    assert [line["trigger"] for line in deployed.events("listing")] == ["connect"]
    assert [line["reason"] for line in deployed.events("server_list_failed")] == ["pages"]


async def test_an_agents_listen_is_acknowledged_for_tool_changes_only(tmp_path: Path) -> None:
    fake = McpFake()
    with (
        deployment(tmp_path, fake, include=TOOLS, review=review(fake)) as deployed,
        gateway(deployed) as running,
    ):
        async with agent(running) as client:
            await client.list_tools()
            listen = client.listen(
                tools_list_changed=True,
                prompts_list_changed=True,
                resources_list_changed=True,
                resource_subscriptions=["file:///notes/1"],
            )
            async with listen as events:
                honored = events.honored.model_dump(by_alias=True, exclude_none=True)
            async with client.listen(prompts_list_changed=True) as events:
                nothing = events.honored.model_dump(by_alias=True, exclude_none=True)
    assert honored == {"toolsListChanged": True}
    assert nothing == {}
