"""What the acceptance tests share beyond the rig: what a test showed, and waiting (M7 design O.5,
fold-in C31).

:class:`Seen` keeps every log line of both roles and every CLI output and agent answer a test
looked at, for the sweeps (G13, G20); :meth:`Seen.events` can wait for a line, since a role logs
once it has acted and the test may read the answer first. :func:`listening` waits until the fake
MCP server has answered every upstream connection's stream, before a test moves the clock.
:func:`wait_for` and :func:`wait_until` poll from the test's thread, failing instead of hanging.
"""

from __future__ import annotations

import io
import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import anyio

from tests.fakes.mcp_server import McpFake

# How often a wait looks again.
INTERVAL = 0.02


def wait_for[T](
    read: Callable[[], T],
    until: Callable[[T], bool] = bool,
    *,
    what: str = "condition not met in time",
    timeout: float = 10.0,
) -> T:
    """``read`` again until ``until`` holds for its value, which is returned. Fails with
    ``what`` and the last value read once ``timeout`` seconds have passed."""
    deadline = time.monotonic() + timeout
    while True:
        value = read()
        if until(value):
            return value
        if time.monotonic() > deadline:
            raise AssertionError(f"{what}: {value!r}")
        time.sleep(INTERVAL)


def wait_until(
    condition: Callable[[], bool], what: str = "condition not met in time", timeout: float = 10.0
) -> None:
    """Until ``condition`` holds."""
    wait_for(condition, what=what, timeout=timeout)


@dataclass
class Seen:
    """Everything a test showed an agent or an operator, for the sweeps."""

    log: io.StringIO = field(default_factory=io.StringIO)
    outputs: list[str] = field(default_factory=list)

    def everything(self) -> str:
        return self.log.getvalue() + "\n".join(self.outputs)

    def events(
        self, kind: str | None = None, *, at_least: int = 0, timeout: float = 10.0
    ) -> list[dict[str, Any]]:
        """The log lines of ``kind`` (every line, with None). With ``at_least``, waits from the
        test's thread until there are that many."""

        def read() -> list[dict[str, Any]]:
            parsed = [json.loads(line) for line in self.log.getvalue().splitlines() if line]
            return [line for line in parsed if kind is None or line["event"] == kind]

        return wait_for(
            read, lambda lines: len(lines) >= at_least, what=f"{kind} lines", timeout=timeout
        )


@dataclass(frozen=True)
class Mark:
    """Where the log and the fake's record stood: :func:`listening` looks only past it."""

    lines: int = 0  # log lines
    received: int = 0  # requests the fake recorded


# Before anything: every line and request.
START = Mark()


def mark(seen: Seen, fake: McpFake) -> Mark:
    return Mark(len(seen.events()), len(fake.received))


async def listening(seen: Seen, fake: McpFake, since: Mark = START) -> None:
    """Wait until the server has answered the stream of every upstream connection open since
    ``since``: a modern connection's ``subscriptions/listen``, a legacy session's GET.

    A connection opens that stream in the background once it has listed, while the agent's
    first calls go on. Until the server has answered it, its request carries the access token the
    vault picked for it: a token the test may expire (moving the clock) or drop meanwhile. The
    server then answers 401, the vault drops the token or sees a newer one, and the gateway
    takes the stream as lost and lists again, COALESCE (5 s) after its last listing, its calls
    waiting for that. Once the streams are open, no request is on its way when the test moves
    the clock or drops the tokens. A connection that has closed since (a review's) is left out.
    """
    deadline = anyio.current_time() + 10
    while True:
        opened: dict[str, str] = {}
        for line in seen.events()[since.lines :]:
            if line["event"] == "upstream_connected":
                opened[line["key"]] = line["era"]
            elif line["event"] == "upstream_closed":
                opened.pop(line["key"], None)
        received = fake.received[since.received :]
        listens = [item.status for item in received if item.rpc_method == "subscriptions/listen"]
        streams = [
            item.status for item in received if item.method == "GET" and item.path == fake.path
        ]
        modern = sum(1 for era in opened.values() if era == "modern")
        legacy = len(opened) - modern
        answered = [status for status in [*listens, *streams] if status]
        if opened and listens.count(200) >= modern and streams.count(200) >= legacy:
            break
        if anyio.current_time() > deadline:
            raise AssertionError(json.dumps({"opened": opened, "streams": answered}))
        await anyio.sleep(0.01)
    assert answered == [200] * len(answered), answered
