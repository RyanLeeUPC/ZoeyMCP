"""The registry of committed calls that a shutdown waits for (M4 design B.6)."""

from __future__ import annotations

import asyncio

import anyio
import pytest

from zoeymcp.gateway import committed as committed_module
from zoeymcp.gateway.committed import Committed, CommittedCancelled

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


async def test_a_held_call_ignores_an_outer_cancel() -> None:
    registry = Committed()
    finished: list[str] = []

    async def call() -> None:
        with registry.hold("r1", 5):
            await anyio.sleep(0.2)
            finished.append("r1")

    async with anyio.create_task_group() as group:
        group.start_soon(call)
        await anyio.sleep(0.05)
        assert "r1" in registry
        assert len(registry) == 1
        group.cancel_scope.cancel()  # an agent cancel, a revocation, uvicorn's shutdown cancel
    assert finished == ["r1"]
    assert len(registry) == 0


async def test_drain_returns_at_once_when_nothing_is_committed() -> None:
    with anyio.fail_after(1):
        assert await Committed().drain() == []


async def test_drain_waits_for_every_call_to_end() -> None:
    registry = Committed()
    ended: list[float] = []

    async def call(ref: str, seconds: float) -> None:
        with registry.hold(ref, 5):
            await anyio.sleep(seconds)
            ended.append(anyio.current_time())

    async with anyio.create_task_group() as group:
        group.start_soon(call, "a", 0.1)
        group.start_soon(call, "b", 0.3)
        await anyio.sleep(0.02)
        assert await registry.drain() == []
        drained = anyio.current_time()
    assert len(ended) == 2
    assert drained >= max(ended)


async def test_past_the_deadline_drain_cancels_and_reports(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(committed_module, "OUTCOME_GRACE", 1.0)
    registry = Committed()
    outcome: list[str] = []

    async def call() -> None:
        with registry.hold("stuck", 0.2):
            try:
                await anyio.sleep(30)
            except anyio.get_cancelled_exc_class():
                with anyio.CancelScope(shield=True):
                    await anyio.sleep(0.05)  # the outcome is written on the way out
                    outcome.append("unknown")
                raise

    async with anyio.create_task_group() as group:
        group.start_soon(call)
        await anyio.sleep(0.02)
        with anyio.fail_after(3):
            assert await registry.drain() == ["stuck"]
    assert outcome == ["unknown"]
    assert len(registry) == 0


async def test_run_outlives_a_native_cancel_of_its_caller() -> None:
    registry = Committed()
    finished: list[str] = []

    async def work() -> str:
        await anyio.sleep(0.3)
        finished.append("sent")
        return "result"

    async with anyio.create_task_group() as owner:
        registry.attach(owner)
        caller = asyncio.get_running_loop().create_task(registry.run("r1", 5, work))
        await anyio.sleep(0.05)
        caller.cancel()  # what uvicorn does to a request task at its grace's end
        with pytest.raises(asyncio.CancelledError):
            await caller
        assert "r1" in registry  # still running
        assert await registry.drain() == []
    assert finished == ["sent"]


async def test_run_returns_and_raises_what_the_work_does() -> None:
    registry = Committed()

    async def ok() -> int:
        return 7

    async def broken() -> int:
        raise ValueError("vault refused")

    async with anyio.create_task_group() as owner:
        registry.attach(owner)
        assert await registry.run("a", 5, ok) == 7
        with pytest.raises(ValueError, match="vault refused"):
            await registry.run("b", 5, broken)
    registry.attach(None)
    assert await registry.run("c", 5, ok) == 7  # without a group, inline


async def test_a_call_cancelled_at_the_deadline_is_reported_to_its_caller(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(committed_module, "OUTCOME_GRACE", 1.0)
    registry = Committed()

    async def stuck() -> None:
        await anyio.sleep(30)

    raised: list[BaseException] = []

    async def caller() -> None:
        try:
            await registry.run("stuck", 0.2, stuck)
        except CommittedCancelled as exc:
            raised.append(exc)

    async with anyio.create_task_group() as owner:
        registry.attach(owner)
        owner.start_soon(caller)
        await anyio.sleep(0.05)
        assert await registry.drain() == ["stuck"]
    assert len(raised) == 1
