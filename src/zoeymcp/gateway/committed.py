"""Approved calls past their accept, which a shutdown waits for (M4 design B.6).

From the moment an approval is accepted until its outcome is written, the call runs in a task this
registry owns, inside a shielded scope, never in the request's own task: uvicorn ends request
tasks with asyncio's native cancel, which an anyio shield doesn't stop (SDK contract item 35).
The request only waits for the result, so an agent cancel, a disconnect, a revocation, a stale
view or uvicorn's shutdown leaves the call running. Shutdown waits for the registry to empty
before anything else stops, up to the latest entry's deadline, and only then cancels what is
left: the one cancel that may reach a committed call.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager
from typing import Any, TypeVar

import anyio
from anyio.abc import TaskGroup

T = TypeVar("T")

# Seconds a call cancelled at the deadline gets to write its outcome.
OUTCOME_GRACE = 5.0


class CommittedCancelled(Exception):
    """The shutdown deadline passed while the committed call ran, and it was cancelled."""


class Committed:
    def __init__(self) -> None:
        self._entries: dict[str, tuple[anyio.CancelScope, float]] = {}
        # Made on first use: an anyio event belongs to the loop it is used on.
        self._changed: anyio.Event | None = None
        self._group: TaskGroup | None = None

    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, ref: object) -> bool:
        return ref in self._entries

    def attach(self, group: TaskGroup | None) -> None:
        """The task group committed calls run in: the gateway's lifespan group."""
        self._group = group

    async def run(self, ref: str, seconds: float, work: Callable[[], Awaitable[T]]) -> T:
        """Run ``work`` as the committed call ``ref``, which must end within ``seconds`` (its
        forward's deadline plus the outcome's write), and return its result.

        The work runs in the registry's own task, so cancelling the caller only stops the wait.
        Without an attached group (in tests), it runs in the caller's task, shielded.
        """
        if self._group is None:
            with self.hold(ref, seconds) as scope:
                inline = await work()
            if scope.cancelled_caught:
                raise CommittedCancelled(ref)
            return inline
        result: list[Any] = []
        failure: list[BaseException] = []
        finished = anyio.Event()

        async def task() -> None:
            try:
                with self.hold(ref, seconds) as scope:
                    result.append(await work())
                if scope.cancelled_caught:  # the scope swallows its own cancel
                    failure.append(CommittedCancelled(ref))
            except BaseException as exc:  # handed to the caller, never to the lifespan group
                failure.append(exc)
            finally:
                finished.set()

        self._group.start_soon(task)
        await finished.wait()
        if failure:
            if isinstance(failure[0], anyio.get_cancelled_exc_class()):
                raise CommittedCancelled(ref) from None
            raise failure[0]
        value: T = result[0]
        return value

    @contextmanager
    def hold(self, ref: str, seconds: float) -> Iterator[anyio.CancelScope]:
        """A shielded scope for the committed call ``ref``, which must end within ``seconds``."""
        scope = anyio.CancelScope(shield=True)
        self._entries[ref] = (scope, anyio.current_time() + seconds)
        try:
            with scope:
                yield scope
        finally:
            del self._entries[ref]
            self._notify()

    def _notify(self) -> None:
        if self._changed is not None:
            self._changed.set()
        self._changed = None

    async def _wait_change(self, seconds: float) -> None:
        if self._changed is None:
            self._changed = anyio.Event()
        changed = self._changed
        with anyio.move_on_after(seconds):
            await changed.wait()

    async def drain(self) -> list[str]:
        """Wait until every committed call has ended, or the latest deadline has passed; then
        cancel what is left. Returns the refs it cancelled."""
        while self._entries:
            latest = max(deadline for _, deadline in self._entries.values())
            remaining = latest - anyio.current_time()
            if remaining <= 0:
                break
            await self._wait_change(remaining)
        cancelled = sorted(self._entries)
        for scope, _ in self._entries.values():
            scope.cancel()
        # The cancelled calls record their outcome (unknown) on the way out.
        with anyio.move_on_after(OUTCOME_GRACE):
            while self._entries:
                await self._wait_change(OUTCOME_GRACE)
        return cancelled
