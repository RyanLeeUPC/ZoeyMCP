"""A bridge killed mid-call (M7 design N's crash tests; FM-18's process half, C.5, Q44).

The S11 rig (tests/acceptance/bridges.py) in B's shape: ``zoeymcp bridge`` around the stdio fake
on its socket behind a ``unix:`` route, the real vault and gateway. SIGKILL ends the bridge while
a call waits on its child: the vault answers the gateway 502, so the agent gets an error and no
answer is made up; nothing listens on the socket until a new bridge starts there, which answers
the old session's id 404, and then the gateway's next call goes through a fresh session. Linux
only, as every bridge test; bounded by ``anyio.fail_after``, sleeping only to poll.
"""

from __future__ import annotations

import re
import socket
from pathlib import Path
from typing import Any

import anyio
import pytest
from mcp.shared.exceptions import MCPError
from mcp.types import TextContent

from tests.bridge.test_bridge_process import TOKEN, UID, socket_dir
from tests.gateway.rig import agent

from .bridges import (
    SERVER,
    SOCKET_UPSTREAM,
    deployment,
    ready,
    socket_clients,
    start_bridge,
    stderr_line,
    stop,
    wire_pins,
)
from .tls import ProviderCA

pytestmark = [
    pytest.mark.anyio,
    pytest.mark.skipif(
        not hasattr(socket, "SO_PEERCRED"),
        reason="the bridge runs on Linux (SO_PEERCRED, process groups)",
    ),
    pytest.mark.skipif(UID <= 0, reason="the vault never takes a bridge running as root"),
]

DEADLINE = 90


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def short_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A short directory: a socket's path has at most 107 bytes."""
    return tmp_path_factory.mktemp("crash", numbered=True)


def text(result: Any) -> str:
    block = result.content[0]
    assert isinstance(block, TextContent)
    return str(block.text)


async def echo(client: Any) -> str | None:
    """``echo``'s answer through the bridge, or None while the server isn't answering."""
    try:
        result = await client.call_tool("echo", {"text": "after"})
    except MCPError:
        return None
    return None if result.is_error else text(result)


async def test_a_bridge_killed_mid_call(
    short_dir: Path, tmp_path: Path, ca: ProviderCA, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = socket_dir(short_dir)
    options = ("--stderr", "text")
    first = start_bridge(directory, short_dir / "first.log", options=options)
    second = None
    try:
        with anyio.fail_after(DEADLINE):
            await ready(first)
            pins = await wire_pins(first.client(), "legacy")
            gateway = deployment(
                tmp_path,
                ca,
                SOCKET_UPSTREAM,
                pins=pins,
                sockets=socket_clients(short_dir, monkeypatch),
            )
            with gateway.running() as running:
                async with agent(running, server=SERVER) as client:
                    before = await echo(client)
                    connected = len(gateway.seen.events("upstream_connected"))

                    async def kill_when_hanging() -> None:
                        await stderr_line(first, "hanging ")
                        first.process.kill()

                    async with anyio.create_task_group() as group:
                        group.start_soon(kill_when_hanging)
                        hung = await client.call_tool("hang", {})
                    # Nothing can answer on the dead bridge's socket.
                    assert await echo(client) is None
                    second = start_bridge(directory, short_dir / "second.log", options=options)
                    await ready(second)
                    while (after := await echo(client)) is None:
                        await anyio.sleep(0.2)
                    reconnected = gateway.seen.events("upstream_connected")[connected:]
                    # Taken before the teardown: a request arriving while the bridge closes is
                    # refused not_ready, which says nothing about the restart.
                    refused = second.events("bridge_refused")
                    started = second.events("bridge_session_started")
            failed = [
                line
                for line in gateway.seen.events("request")
                if line.get("status") == 502 and line.get("method") == "POST"
            ]
            everything = gateway.seen.everything()
    finally:
        await stop(first)
        if second is not None:
            await stop(second)
    assert before == "after"
    assert hung.is_error
    # The vault's 502 reaches the gateway as the upstream's error: the agent gets the gateway's
    # own text for it, nothing from the dead bridge.
    assert re.fullmatch(r"upstream error \(ref [0-9a-f]{16}\)", text(hung)), text(hung)
    assert failed, "the vault answered the call through the dead bridge with no 502"
    assert after == "after"
    # A fresh session on the new bridge: the old session's id means nothing there (404, as for
    # any legacy restart), so the gateway initialized a new session after the kill.
    assert {line["reason"] for line in refused} <= {"session_unknown"}, refused
    assert reconnected, "the gateway didn't initialize a new session after the kill"
    assert started
    assert TOKEN not in everything
