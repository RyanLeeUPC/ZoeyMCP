"""Contracts 57 to 61 (M6 design O.2): what M6's code relies on in the MCP SDK. Each lands in the
step before the code that leans on it.

Contract 59 (step 3a): the SDK's ``ListenHandler`` acknowledges every kind a listen asks for,
whether or not the server will ever send it, and then delivers only the kinds it acknowledged.
The gateway hands an agent's listen to that handler as it came (``gateway/app.py``'s
``_listen``), so its acknowledgment can name prompts, resources and resource subscriptions the
gateway never sends; design K.4's filter narrows the params first (step 3b). The server here is
shaped as the gateway's client-facing side is (``test_server_contract.Shaped``), and the stream
is read raw, since the SDK client also drops on its own side whatever wasn't acknowledged.

They join D-95's re-run list: run again on every SDK bump.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import anyio
import httpx
import pytest
from mcp.server.subscriptions import (
    SUBSCRIPTION_ID_META_KEY,
    PromptsListChanged,
    ResourcesListChanged,
    ResourceUpdated,
    ServerEvent,
    ToolsListChanged,
)

from .test_server_contract import Shaped, modern_body, modern_headers, modern_post, running

pytestmark = pytest.mark.anyio

ACKNOWLEDGED = "notifications/subscriptions/acknowledged"
NOTES = "file:///notes.txt"
# Every SDK interaction gets a deadline, so a behaviour change after a bump fails, not hangs.
DEADLINE = 5


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class Frames:
    """The JSON-RPC messages of one listen stream, in the order sent."""

    def __init__(self, lines: AsyncIterator[str]) -> None:
        self._lines = lines

    async def next(self) -> dict[str, Any]:
        with anyio.fail_after(DEADLINE):
            async for line in self._lines:
                if line.startswith("data:") and line[5:].strip():
                    message: dict[str, Any] = json.loads(line[5:])
                    return message
        raise AssertionError("the stream ended")


@asynccontextmanager
async def listening(url: str, notifications: dict[str, Any]) -> AsyncIterator[Frames]:
    """A raw modern ``subscriptions/listen`` from client ``a``, open until the block ends."""
    method = "subscriptions/listen"
    body = modern_body(method, {"notifications": notifications})
    timeout = httpx.Timeout(10.0, read=30.0)
    async with (
        httpx.AsyncClient(timeout=timeout) as http,
        http.stream("POST", url, json=body, headers=modern_headers(method)) as response,
    ):
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
        yield Frames(response.aiter_lines())


# --- 59. the listen acknowledgment -------------------------------------------------------------


@pytest.mark.parametrize(
    ("asked", "acknowledged"),
    [
        (
            {
                "toolsListChanged": True,
                "promptsListChanged": True,
                "resourcesListChanged": True,
                "resourceSubscriptions": [NOTES],
            },
            {
                "toolsListChanged": True,
                "promptsListChanged": True,
                "resourcesListChanged": True,
                "resourceSubscriptions": [NOTES],
            },
        ),
        # A false flag or an empty list is left out, not echoed.
        (
            {"toolsListChanged": True, "promptsListChanged": False, "resourceSubscriptions": []},
            {"toolsListChanged": True},
        ),
    ],
)
async def test_59_listen_handler_acknowledges_every_kind_asked_for(
    asked: dict[str, Any], acknowledged: dict[str, Any]
) -> None:
    """Even kinds the server doesn't serve: it registers only the tools handlers."""
    shaped = Shaped()
    with running(shaped) as url:
        discovered = modern_post(url, "server/discover").json()["result"]["capabilities"]
        async with listening(url, asked) as frames:
            ack = await frames.next()
    assert not {"prompts", "resources"} & set(discovered)
    assert ack["method"] == ACKNOWLEDGED
    assert ack["params"]["notifications"] == acknowledged
    assert ack["params"]["_meta"] == {SUBSCRIPTION_ID_META_KEY: 7}


async def test_59_listen_handler_delivers_only_the_kinds_it_acknowledged() -> None:
    shaped = Shaped()
    asked = {"toolsListChanged": True, "promptsListChanged": True, "resourceSubscriptions": [NOTES]}
    events: list[ServerEvent] = [
        ResourcesListChanged(),
        ResourceUpdated(uri="file:///other.txt"),
        ResourceUpdated(uri=NOTES),
        PromptsListChanged(),
        ToolsListChanged(),
    ]
    with running(shaped) as url:
        async with listening(url, asked) as frames:
            ack = await frames.next()
            for event in events:
                await shaped.run(shaped.buses["a"].publish(event))
            delivered = [await frames.next() for _ in range(3)]
            with anyio.move_on_after(0.5) as quiet:
                await frames.next()
    assert ack["method"] == ACKNOWLEDGED
    assert [frame["method"] for frame in delivered] == [
        "notifications/resources/updated",
        "notifications/prompts/list_changed",
        "notifications/tools/list_changed",
    ]
    assert delivered[0]["params"]["uri"] == NOTES
    assert all(frame["params"]["_meta"] == {SUBSCRIPTION_ID_META_KEY: 7} for frame in delivered)
    assert quiet.cancelled_caught
