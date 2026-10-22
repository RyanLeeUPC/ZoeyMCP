"""The egress role's connections and tunnels (M7 design I.4, X15): the I/O around
:mod:`.connect`'s decisions.

Each connection on a source's listener reads one request head, is checked against that source's
list, resolves its name once, connects to the address it checked (never a second lookup), and
answers ``200 Connection established``; then bytes are copied both ways until either side
closes, the tunnel is idle for ``--idle-timeout`` or open for ``--max-tunnel-seconds``. A refusal
is :func:`.connect.answer`'s empty answer and an ``egress_refused`` line with the step's reason;
each tunnel ends with one ``egress_tunnel`` line. When new lists arrive, tunnels whose
destination left their source's list are closed (``result: removed``).

Resolution and dialling are passed in, so tests answer names from the fake resolver and reach
loopback fakes by the addresses it reserved (tests/fakes/resolver.py), with the guard unchanged.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from . import connect, event
from .connect import Lists, Refusal, Target

# A name's addresses (may raise OSError or TimeoutError), and where a checked address is dialled.
Resolve = Callable[[str, int], Awaitable[list[str]]]
Dial = Callable[[str, int], tuple[str, int]]
_CHUNK = 64 * 1024


async def system_resolve(host: str, port: int) -> list[str]:
    """Every address ``host`` resolves to for a stream socket, in the resolver's order, once
    each."""
    infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(str(info[4][0]) for info in infos))


def direct(address: str, port: int) -> tuple[str, int]:
    return address, port


@dataclass(eq=False)
class Tunnel:
    """One open tunnel; :meth:`cut` closes both sides and names why."""

    source: str
    target: Target
    sides: tuple[asyncio.StreamWriter, asyncio.StreamWriter]
    result: str | None = None

    def cut(self, result: str) -> None:
        if self.result is None:
            self.result = result
        for side in self.sides:
            side.close()


@dataclass
class Tunnels:
    """The tunnels open, and being opened, per listener and in all (the caps of M.6)."""

    per_listener: int = connect.TUNNELS_PER_LISTENER
    counts: dict[str, int] = field(default_factory=dict)
    open: set[Tunnel] = field(default_factory=set)

    def reserve(self, source: str) -> bool:
        listener, total = self.counts.get(source, 0), sum(self.counts.values())
        if not connect.has_room(listener, total, self.per_listener):
            return False
        self.counts[source] = listener + 1
        return True

    def release(self, source: str) -> None:
        self.counts[source] -= 1

    def prune(self, lists: Lists) -> None:
        """Close every tunnel whose destination left its source's list."""
        for tunnel in list(self.open):
            if not connect.still_listed(lists, tunnel.source, tunnel.target.key):
                tunnel.cut("removed")

    def cut_all(self, result: str) -> None:
        for tunnel in list(self.open):
            tunnel.cut(result)


class Handler:
    """Serves each connection one source's listener accepts."""

    def __init__(
        self,
        lists: Callable[[], Lists | None],
        tunnels: Tunnels,
        *,
        resolve: Resolve = system_resolve,
        dial: Dial = direct,
        idle_timeout: float = connect.IDLE_TIMEOUT,
        max_seconds: float = connect.TUNNEL_MAX_SECONDS,
        head_timeout: float = connect.HEAD_TIMEOUT,
    ) -> None:
        self._lists = lists
        self._tunnels = tunnels
        self._resolve = resolve
        self._dial = dial
        self._idle_timeout = idle_timeout
        self._max_seconds = max_seconds
        self._head_timeout = head_timeout
        self.connections: set[asyncio.StreamWriter] = set()

    def close_all(self) -> None:
        """Close every connection still being read or refused (the role is stopping)."""
        for writer in list(self.connections):
            writer.close()

    async def handle(
        self, source: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        self.connections.add(writer)
        try:
            await self._handle(source, reader, writer)
        except (OSError, EOFError):
            pass  # the client went away while it was answered
        finally:
            self.connections.discard(writer)
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()

    async def _handle(
        self, source: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        read = await self._read_head(reader)
        if isinstance(read, Refusal):
            await _refuse(writer, source, read)
            return
        head, early = read
        target = connect.parse_head(head)
        if isinstance(target, Refusal):
            await _refuse(writer, source, target)
            return
        private = connect.admit(self._lists(), source, target)
        if isinstance(private, Refusal):
            await _refuse(writer, source, private, target)
            return
        if not self._tunnels.reserve(source):
            await _refuse(writer, source, Refusal("busy"), target)
            return
        try:
            await self._open(source, target, private, early, reader, writer)
        finally:
            self._tunnels.release(source)

    async def _read_head(self, reader: asyncio.StreamReader) -> tuple[bytes, bytes] | Refusal:
        buffer = b""
        try:
            async with asyncio.timeout(self._head_timeout):
                while True:
                    found = connect.split_head(buffer)
                    if found is not None:
                        return found
                    chunk = await reader.read(connect.HEAD_MAX)
                    if not chunk:
                        return Refusal("bad_request")  # closed before a whole head
                    buffer += chunk
        except TimeoutError:
            return Refusal("head_timeout")

    async def _open(
        self,
        source: str,
        target: Target,
        private: bool,
        early: bytes,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            async with asyncio.timeout(connect.RESOLVE_TIMEOUT):
                addresses = await self._resolve(target.host, target.port)
        except (OSError, TimeoutError, ValueError):
            await _refuse(writer, source, Refusal("resolve_failed"), target)
            return
        address = connect.address(addresses, private)
        if isinstance(address, Refusal):
            await _refuse(writer, source, address, target)
            return
        try:
            async with asyncio.timeout(connect.CONNECT_TIMEOUT):
                up_reader, up_writer = await asyncio.open_connection(
                    *self._dial(address, target.port)
                )
        except (OSError, TimeoutError, ValueError):
            await _refuse(writer, source, Refusal("connect_failed"), target, address)
            return
        # The lists may have changed while the name was resolved and connected: check once more.
        # Nothing awaits between this check and the tunnel's registration, so no new list can
        # slip in between and leave the tunnel unpruned.
        if not connect.still_listed(self._lists(), source, target.key):
            up_writer.close()
            await _refuse(writer, source, Refusal("not_allowed"), target, address)
            return
        tunnel = Tunnel(source, target, (writer, up_writer))
        self._tunnels.open.add(tunnel)
        started = time.monotonic()
        counts = [0, 0]
        try:
            writer.write(connect.ESTABLISHED)
            if early:
                up_writer.write(early)
                counts[0] += len(early)
            tunnel.cut(await self._copy(tunnel, (reader, up_reader), counts))
        finally:
            self._tunnels.open.discard(tunnel)
            tunnel.cut("closed")
            with contextlib.suppress(OSError):
                await up_writer.wait_closed()
            event(
                "egress_tunnel",
                source=source,
                host=target.host,
                port=target.port,
                address=address,
                result=tunnel.result,
                bytes_up=counts[0],
                bytes_down=counts[1],
                ms=round((time.monotonic() - started) * 1000),
            )

    async def _copy(
        self,
        tunnel: Tunnel,
        readers: tuple[asyncio.StreamReader, asyncio.StreamReader],
        counts: list[int],
    ) -> str:
        """Bytes both ways until both sides are done (``closed``), or the tunnel is idle
        (``idle``) or too old (``timeout``)."""
        last = [time.monotonic()]
        deadline = last[0] + self._max_seconds

        async def pipe(index: int) -> None:
            source, sink = readers[index], tunnel.sides[1 - index]
            try:
                while data := await source.read(_CHUNK):
                    counts[index] += len(data)
                    last[0] = time.monotonic()
                    sink.write(data)
                    await sink.drain()
                if sink.can_write_eof():
                    sink.write_eof()  # half-close: the other way may still be sending
            except (OSError, RuntimeError):
                pass  # a side reset or closed: the other pipe ends with it

        pending = {asyncio.create_task(pipe(0)), asyncio.create_task(pipe(1))}
        try:
            while pending:
                now = time.monotonic()
                if now >= deadline:
                    return "timeout"
                if now - last[0] >= self._idle_timeout:
                    return "idle"
                wait = min(deadline, last[0] + self._idle_timeout) - now
                _, pending = await asyncio.wait(pending, timeout=wait)
            return "closed"
        finally:
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)


async def _refuse(
    writer: asyncio.StreamWriter,
    source: str,
    refusal: Refusal,
    target: Target | None = None,
    address: str | None = None,
) -> None:
    """The refusal's answer, and its log line."""
    fields: dict[str, object] = {"source": source, "reason": refusal.reason}
    if target is not None:
        fields.update(host=target.host, port=target.port)
    if refusal.verdict is not None:
        fields["verdict"] = refusal.verdict
    if address is not None:
        fields["address"] = address
    event("egress_refused", **fields)
    writer.write(connect.answer(refusal.status))
    await writer.drain()
