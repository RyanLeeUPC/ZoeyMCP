"""Progress while a held call blocks (M8 design F.1, G-29, M.3; the progress-ticker unit test).

Every :data:`~zoeymcp.gateway.approve.PROGRESS_EVERY` seconds the agent is told the seconds waited,
strictly increasing, with no total and the fixed message; and the ticker stops in the synchronous
section the wait's answer comes back in, so no notification follows the answer, not even one that
was being sent. Each test drives the ticker with no real wait (an interval of zero, a clock the
test moves) and bounds itself.
"""

from __future__ import annotations

import anyio
import pytest

from zoeymcp.gateway import approve
from zoeymcp.gateway.approve import PROGRESS_EVERY, PROGRESS_MESSAGE, ticking

pytestmark = pytest.mark.anyio
BOUND = 10


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


async def settle(times: int = 20) -> None:
    """Let every other task run, a few times over."""
    for _ in range(times):
        await anyio.sleep(0)


def test_the_constants() -> None:
    assert PROGRESS_EVERY == 15.0
    assert PROGRESS_MESSAGE == "waiting for the operator's approval"
    assert approve.ticking.__defaults__ == (PROGRESS_EVERY,)  # the interval every wait uses


async def test_progress_is_the_seconds_waited_and_stops_with_the_answer() -> None:
    clock = Clock()
    sent: list[tuple[float, str]] = []
    enough = anyio.Event()

    async def tick(seconds: float, message: str) -> None:
        sent.append((seconds, message))
        clock.now += 15.5
        if len(sent) == 3:
            enough.set()

    async def work() -> str:
        await enough.wait()
        return "the answer"

    with anyio.fail_after(BOUND):
        answer = await ticking(work, tick, clock, every=0.0)
        count = len(sent)
        await settle()
    assert answer == "the answer"
    assert sent == [(1.0, PROGRESS_MESSAGE), (15.0, PROGRESS_MESSAGE), (31.0, PROGRESS_MESSAGE)]
    assert len(sent) == count  # nothing after the answer


async def test_each_notification_is_more_than_the_last() -> None:
    """A clock that doesn't move (or moves back) still gives strictly increasing progress."""
    clock = Clock()
    sent: list[float] = []
    enough = anyio.Event()

    async def tick(seconds: float, message: str) -> None:
        sent.append(seconds)
        clock.now -= 1.0
        if len(sent) == 4:
            enough.set()

    async def work() -> None:
        await enough.wait()

    with anyio.fail_after(BOUND):
        await ticking(work, tick, clock, every=0.0)
    assert sent == [1.0, 2.0, 3.0, 4.0]


async def test_a_notification_being_sent_is_cut_by_the_answer() -> None:
    """The answer comes while a notification is being sent: that send is cancelled, and none
    starts after."""
    sending = anyio.Event()
    calls: list[str] = []

    async def tick(seconds: float, message: str) -> None:
        calls.append("started")
        sending.set()
        try:
            await anyio.sleep_forever()
        except anyio.get_cancelled_exc_class():
            calls.append("cut")
            raise

    async def work() -> int:
        await sending.wait()
        return 7

    with anyio.fail_after(BOUND):
        assert await ticking(work, tick, Clock(), every=0.0) == 7
        await settle()
    assert calls == ["started", "cut"]


async def test_a_failed_wait_raises_its_own_error_and_stops_the_ticks() -> None:
    sent: list[float] = []
    ticked = anyio.Event()

    async def tick(seconds: float, message: str) -> None:
        sent.append(seconds)
        ticked.set()

    async def work() -> None:
        await ticked.wait()
        raise LookupError("the wait failed")

    with anyio.fail_after(BOUND), pytest.raises(LookupError, match="the wait failed"):
        await ticking(work, tick, Clock(), every=0.0)
    count = len(sent)
    with anyio.fail_after(BOUND):
        await settle()
    assert len(sent) == count >= 1


async def test_a_notification_that_fails_ends_the_ticks_not_the_wait() -> None:
    """Progress is never relied on: a send that fails stops the ticking, and the wait runs on."""
    calls: list[float] = []
    done = anyio.Event()

    async def tick(seconds: float, message: str) -> None:
        calls.append(seconds)
        raise RuntimeError("the stream is gone")

    async def work() -> str:
        await settle()
        await settle()
        done.set()
        return "ran"

    with anyio.fail_after(BOUND):
        assert await ticking(work, tick, Clock(), every=0.0) == "ran"
    assert calls == [1.0]
    assert done.is_set()


async def test_with_no_progress_wanted_the_wait_runs_alone() -> None:
    async def work() -> str:
        return "alone"

    with anyio.fail_after(BOUND):
        assert await ticking(work, None, Clock(), every=0.0) == "alone"


async def test_a_cancelled_wait_is_cancelled() -> None:
    sent: list[float] = []

    async def tick(seconds: float, message: str) -> None:
        sent.append(seconds)

    async def work() -> None:
        await anyio.sleep_forever()

    with anyio.fail_after(BOUND):
        with anyio.move_on_after(0) as scope:
            await ticking(work, tick, Clock(), every=0.0)
        assert scope.cancelled_caught
        count = len(sent)
        await settle()
    assert len(sent) == count
