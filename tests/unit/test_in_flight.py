"""Stopping requests in flight when a client's access changes (M3 design D.3)."""

from __future__ import annotations

import anyio
import pytest

from zoeymcp.gateway.pipeline import InFlight

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


async def test_stop_cancels_only_that_pair() -> None:
    in_flight = InFlight()
    ended: dict[str, bool] = {}

    async def wait(key: str, client: str, server: str) -> None:
        with in_flight.track(client, server) as scope:
            await anyio.sleep(5)
        ended[key] = scope.cancelled_caught

    async with anyio.create_task_group() as group:
        group.start_soon(wait, "a1", "alpha", "notes")
        group.start_soon(wait, "a2", "alpha", "notes")
        group.start_soon(wait, "b", "beta", "notes")
        group.start_soon(wait, "m", "alpha", "mail")
        await anyio.sleep(0.05)
        assert in_flight.stop("alpha", "notes") == 2
        assert in_flight.stop("alpha", "notes") == 0
        await anyio.sleep(0.05)
        assert ended == {"a1": True, "a2": True}
        group.cancel_scope.cancel()


async def test_a_finished_request_is_forgotten() -> None:
    in_flight = InFlight()
    with in_flight.track("alpha", "notes"):
        pass
    assert in_flight.stop("alpha", "notes") == 0
