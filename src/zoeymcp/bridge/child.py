"""One child process (M7 design C.3, C.4, X14; FM-18, FM-20 to FM-23).

The command is fixed at start (everything after ``--``); no request names or changes it. It is
run with ``asyncio``'s subprocess support, no shell, in a session of its own (so its process
group is its own), with pipes for stdin, stdout and stderr, ``<work>/work`` as its working
directory and :func:`.childenv.build`'s environment.

- **stdout** is read a line at a time with a ``limit`` of ``--max-message-bytes``
  (:func:`.framing.next_line`, contract 47). A line that is too long, isn't one strict JSON
  object, or is a batch ends the child (``bridge_child_violation``). Each message goes where
  :class:`.relay.Relay` routes it: an answer or a progress notification to its exchange's stream
  (:class:`Exchange`), a legacy notification to the session's GET stream, and a request from the
  child is answered by the bridge itself (``ping``) or refused (``-32601``, logged
  ``bridge_client_request_refused``), never relayed. Answers no exchange waits for are counted
  (``bridge_unmatched``, logged at the 1st, 2nd, 4th, 8th... so a flood can't flood the log).
- **stderr** is read in chunks, not lines, so a flood with no newline holds at most
  :data:`.framing.STDERR_LINE_MAX` bytes of a line; :class:`.framing.StderrLog` logs counts per
  window by default and, with ``--stderr text``, capped lines.
- **Stopping** (C.3, the SDK's numbers): close stdin, wait 2 s, ``SIGTERM`` to the process group,
  wait 2 s, ``SIGKILL`` to the group. Once the child has exited, its group is sent ``SIGKILL``
  too, so a grandchild it left (an ``npx``-style launcher's) doesn't outlive it (contract 48);
  the group's id can't be reused while any of its processes lives. A child that exits on its own
  is noticed when it exits, even while a grandchild still holds its pipes.

When the child is gone, every request in flight is answered as failed (502, FM-18) and
``on_exit`` is called once, so a legacy session ends and a modern bridge starts another child at
the next request.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import signal
import sys
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Final, Literal

from . import event
from .framing import (
    MESSAGE_MAX,
    STDERR_LINE_MAX,
    STDERR_WINDOW,
    Era,
    LogLine,
    Message,
    StderrLog,
    StderrMode,
    Violation,
    next_line,
    parse,
)
from .relay import Broadcast, Deliver, Drop, Pending, Relay, Reply

# M7 design C.3 and M.6: each of a stop's two waits, in seconds, and what follows each.
STOP_WAIT: Final = 2.0
# (Windows, a development host, has no SIGKILL: there both end the process.)
STOP_SIGNALS: Final[tuple[int, int]] = (
    signal.SIGTERM,
    getattr(signal, "SIGKILL", signal.SIGTERM),
)
STDERR_CHUNK: Final = 64 * 1024
# How many messages a stream holds for a client that reads slowly; beyond, progress and
# notifications are dropped, never an answer.
STREAM_ITEMS_MAX: Final = 1024
# What a child is for: the readiness probe, a legacy session, or a modern bridge's one child.
Purpose = Literal["probe", "session", "shared"]


@dataclass(frozen=True)
class Spec:
    """How every child of this bridge is started."""

    command: tuple[str, ...]
    env: Mapping[str, str] = field(repr=False)
    cwd: str
    max_message_bytes: int = MESSAGE_MAX
    stderr: StderrMode = "counts"


@dataclass(frozen=True)
class Item:
    """One thing for an exchange's stream: a message's bytes (``final`` when it is the answer),
    or ``data`` None when the child is gone before the answer."""

    data: bytes | None
    final: bool = False


GONE: Final = Item(None, True)


class Exchange:
    """One relayed request's stream: what the child sent for it, in order. At most
    :data:`STREAM_ITEMS_MAX` progress or listen notifications wait for a slow client; beyond,
    they are dropped, and the answer (or :data:`GONE`) never is."""

    def __init__(self, number: int) -> None:
        self.number = number
        self.pending: Pending | None = None
        self._items: asyncio.Queue[Item] = asyncio.Queue()

    def put(self, item: Item) -> None:
        if item.final or self._items.qsize() < STREAM_ITEMS_MAX:
            self._items.put_nowait(item)

    async def get(self) -> Item:
        return await self._items.get()


class _Protocol(asyncio.subprocess.SubprocessStreamProtocol):
    """asyncio's own protocol for a subprocess's streams, which also says when the process
    exited, whether or not its pipes are still open (a grandchild may hold them)."""

    def __init__(self, limit: int, loop: asyncio.AbstractEventLoop) -> None:
        super().__init__(limit=limit, loop=loop)
        self.exited = asyncio.Event()

    def process_exited(self) -> None:
        super().process_exited()
        self.exited.set()


class Child:
    """A running child, its relay, and the exchanges waiting on it."""

    def __init__(
        self,
        process: asyncio.subprocess.Process,
        exited: asyncio.Event,
        spec: Spec,
        era: Era,
        purpose: Purpose,
        clock: Callable[[], float],
    ) -> None:
        self.process = process
        self.pid = process.pid
        self.spec = spec
        self.purpose = purpose
        self.relay = Relay(era)
        self.exchanges: dict[int, Exchange] = {}
        # Called with a legacy notification for the session's GET stream, once there is one.
        self.on_broadcast: Callable[[bytes], None] | None = None
        # Called once when the child is gone.
        self.on_exit: Callable[[Child], None] | None = None
        self.done = asyncio.Event()
        self._exited = exited
        self._clock = clock
        self._stderr = StderrLog(spec.stderr, clock())
        self._stopping: asyncio.Task[None] | None = None
        self._tasks: list[asyncio.Task[None]] = []

    @classmethod
    async def spawn(
        cls,
        spec: Spec,
        era: Era,
        purpose: Purpose,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> Child:
        """Start a child; :class:`OSError` when its command can't be run."""
        loop = asyncio.get_running_loop()
        transport, protocol = await loop.subprocess_exec(
            lambda: _Protocol(spec.max_message_bytes, loop),
            *spec.command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=spec.cwd,
            env=dict(spec.env),
            start_new_session=True,
        )
        process = asyncio.subprocess.Process(transport, protocol, loop)
        child = cls(process, protocol.exited, spec, era, purpose, clock)
        event("bridge_child_started", pid=child.pid, purpose=purpose)
        child._tasks = [
            asyncio.create_task(child._run()),
            asyncio.create_task(child._read_stderr()),
            asyncio.create_task(child._tick()),
        ]
        return child

    # --- writing to the child ----------------------------------------------------------------

    def _stdin(self) -> asyncio.StreamWriter | None:
        stdin = self.process.stdin
        if stdin is None or stdin.is_closing() or self.done.is_set():
            return None
        return stdin

    async def send(self, line: bytes) -> None:
        """Write one line to the child's stdin, waiting while its pipe is full. A child that is
        gone is noticed by its reader, so a failed write is left to it."""
        stdin = self._stdin()
        if stdin is None:
            return
        try:
            stdin.write(line)
            await stdin.drain()
        except (BrokenPipeError, ConnectionResetError, RuntimeError):
            pass

    def write(self, line: bytes) -> None:
        """Write one line without waiting for the pipe: a cancel, or an answer to the child's
        own request, so neither a client that left nor the stdout reader waits on a child that
        stops reading its stdin (which then can't fill its stdout either)."""
        stdin = self._stdin()
        if stdin is not None:
            with contextlib.suppress(BrokenPipeError, ConnectionResetError, RuntimeError):
                stdin.write(line)

    def _unread(self) -> int:
        """How many bytes written to the child's stdin it hasn't read yet."""
        stdin = self._stdin()
        return 0 if stdin is None else stdin.transport.get_write_buffer_size()

    async def request(self, message: Message, exchange: Exchange) -> Pending | None:
        """Relay a request for ``exchange``: what is now in flight, or None when the child has
        :data:`.relay.IDS_MAX` requests in flight already (503 ``bridge_busy``)."""
        if self.done.is_set():
            exchange.put(GONE)
            return None
        sent = self.relay.outbound(message, exchange.number)
        if sent is None:
            return None
        line, pending = sent
        exchange.pending = pending
        self.exchanges[exchange.number] = exchange
        await self.send(line)
        return pending

    def left(self, exchange: Exchange) -> None:
        """The client left ``exchange`` before its answer (modern: that is its cancel)."""
        self.exchanges.pop(exchange.number, None)
        for line in self.relay.disconnect(exchange.number):
            self.write(line)

    # --- reading from the child --------------------------------------------------------------

    async def _run(self) -> None:
        """Read stdout until the child ends, then stop it and answer what was in flight."""
        reading = asyncio.create_task(self._read_stdout())
        exited = asyncio.create_task(self._exited.wait())
        try:
            await asyncio.wait((reading, exited), return_when=asyncio.FIRST_COMPLETED)
            if exited.done():
                # Gone on its own: free its pipes from any grandchild, then read what is left.
                self._kill_group()
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(asyncio.shield(reading), STOP_WAIT)
            await self.stop()
        finally:
            for task in (reading, exited):
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
            # Its stderr ends with the group: the last counts are logged before the exit.
            with contextlib.suppress(TimeoutError, asyncio.CancelledError):
                await asyncio.wait_for(asyncio.shield(self._tasks[1]), STOP_WAIT)
            self._finish()

    async def _read_stdout(self) -> None:
        reader = self.process.stdout
        assert reader is not None  # noqa: S101 - spawned with a pipe
        while True:
            line = await next_line(reader)
            if line == "eof":
                return
            if line == "too_long":
                self._violation("too_long")
                return
            found = parse(line, self.spec.max_message_bytes)
            if found is None:
                continue
            if isinstance(found, Violation):
                self._violation(found.reason)
                return
            self._route(found)

    def _violation(self, reason: str) -> None:
        event("bridge_child_violation", pid=self.pid, reason=reason)

    def _route(self, message: Message) -> None:
        route = self.relay.inbound(message)
        if isinstance(route, Deliver):
            exchange = self.exchanges.get(route.exchange)
            if exchange is not None:
                exchange.put(Item(route.data, route.final))
                if route.final:
                    del self.exchanges[route.exchange]
        elif isinstance(route, Broadcast):
            if self.on_broadcast is not None:
                self.on_broadcast(route.data)
        elif isinstance(route, Reply):
            if route.refused is not None:
                event("bridge_client_request_refused", pid=self.pid, method=route.refused)
            # Answers to a child that doesn't read them are dropped past one message's size, so
            # its requests can't grow the bridge's buffer.
            if self._unread() <= self.spec.max_message_bytes:
                self.write(route.line)
        elif isinstance(route, Drop) and route.reason == "unmatched":
            count = self.relay.unmatched
            if count & (count - 1) == 0:
                event("bridge_unmatched", pid=self.pid, count=count)

    async def _read_stderr(self) -> None:
        reader = self.process.stderr
        assert reader is not None  # noqa: S101 - spawned with a pipe
        held = b""
        size = 0
        while chunk := await reader.read(STDERR_CHUNK):
            start = 0
            while (end := chunk.find(b"\n", start)) != -1:
                piece = chunk[start : end + 1]
                self._stderr_line((held + piece)[: STDERR_LINE_MAX + 1], size + len(piece))
                held, size, start = b"", 0, end + 1
            rest = chunk[start:]
            held = (held + rest)[: STDERR_LINE_MAX + 1]
            size += len(rest)
        if size:
            self._stderr_line(held, size)

    def _stderr_line(self, data: bytes, size: int) -> None:
        self._log(self._stderr.line(data, self._clock(), size))

    async def _tick(self) -> None:
        while True:
            await asyncio.sleep(STDERR_WINDOW)
            self._log(self._stderr.tick(self._clock()))

    def _log(self, lines: list[LogLine]) -> None:
        for kind, fields in lines:
            event(kind, pid=self.pid, **fields)

    # --- stopping ----------------------------------------------------------------------------

    async def stop(self) -> None:
        """Stop the child (idempotent): close stdin, then ``SIGTERM`` and ``SIGKILL`` to its
        group, :data:`STOP_WAIT` apart, and sweep the group once it has exited."""
        if self._stopping is None:
            self._stopping = asyncio.create_task(self._stop())
        await asyncio.shield(self._stopping)

    async def _stop(self) -> None:
        stdin = self.process.stdin
        if stdin is not None and not stdin.is_closing():
            stdin.close()
        for then in STOP_SIGNALS:
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._exited.wait(), STOP_WAIT)
                break
            self._signal(then)
        await self._exited.wait()
        self._kill_group()
        with contextlib.suppress(TimeoutError):
            # The pipes close once nothing in the group holds them.
            await asyncio.wait_for(self.process.wait(), STOP_WAIT)

    def _signal(self, signum: int) -> None:
        if sys.platform == "win32":
            with contextlib.suppress(ProcessLookupError):
                self.process.kill()
            return
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(self.pid, signum)

    def _kill_group(self) -> None:
        if sys.platform != "win32":
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(self.pid, signal.SIGKILL)

    def _finish(self) -> None:
        if self.done.is_set():
            return
        self.done.set()
        for task in self._tasks[1:]:
            task.cancel()
        self._log(self._stderr.close())
        code = self.process.returncode
        signum = -code if code is not None and code < 0 else None
        event(
            "bridge_child_exited",
            pid=self.pid,
            purpose=self.purpose,
            code=None if signum is not None else code,
            signal=signum,
        )
        for pending in self.relay.fail():
            exchange = self.exchanges.pop(pending.exchange, None)
            if exchange is not None:
                exchange.put(GONE)
        for exchange in self.exchanges.values():
            exchange.put(GONE)
        self.exchanges.clear()
        if self.on_exit is not None:
            self.on_exit(self)

    async def wait(self) -> None:
        """Until the child is gone and everything in flight was answered."""
        await self.done.wait()
