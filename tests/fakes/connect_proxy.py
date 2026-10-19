"""A fake egress proxy that speaks CONNECT (M4 design N.1), asyncio only.

It records every CONNECT target and pipes bytes to the target, so an SMTP fake behind it sees the
connector's real session. :class:`ProxySwitch` turns on each way a proxy can refuse, garble or
tamper with a tunnel, including stripping ``STARTTLS`` from EHLO (the downgrade the connector must
refuse to authenticate through).
"""

from __future__ import annotations

import asyncio
import contextlib
import enum
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field


class ProxySwitch(enum.Enum):
    REFUSE_403 = "refuse_403"
    REFUSE_407 = "refuse_407"
    MALFORMED = "malformed"  # a status line that isn't HTTP
    OVERSIZED = "oversized"  # a reply head over 8 KiB
    GREETING_WITH_200 = "greeting_with_200"  # the target's first bytes in the same write as 200
    CLOSE_MID_TUNNEL = "close_mid_tunnel"  # hang up after the first bytes from the target
    STRIP_STARTTLS = "strip_starttls"  # remove STARTTLS from the target's EHLO answer


@dataclass
class ConnectProxy:
    switches: set[ProxySwitch] = field(default_factory=set)
    targets: list[str] = field(default_factory=list)
    _loop: asyncio.AbstractEventLoop | None = None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await reader.readuntil(b"\r\n\r\n")
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            writer.close()
            return
        request_line = head.split(b"\r\n", 1)[0].decode(errors="replace")
        method, _, rest = request_line.partition(" ")
        target = rest.rpartition(" ")[0]
        self.targets.append(target)
        if method != "CONNECT":
            writer.write(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            await writer.drain()
            writer.close()
            return
        for switch, reply in (
            (ProxySwitch.REFUSE_403, b"HTTP/1.1 403 Forbidden\r\n\r\n"),
            (ProxySwitch.REFUSE_407, b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"),
            (ProxySwitch.MALFORMED, b"SMTP/1.0 200 sure\r\n\r\n"),
            (ProxySwitch.OVERSIZED, b"HTTP/1.1 200 OK\r\nX-Pad: " + b"x" * 9000 + b"\r\n\r\n"),
        ):
            if switch in self.switches:
                writer.write(reply)
                await writer.drain()
                writer.close()
                return
        host, _, port = target.rpartition(":")
        try:
            upstream_reader, upstream_writer = await asyncio.open_connection(host, int(port))
        except OSError:
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            await writer.drain()
            writer.close()
            return
        established = b"HTTP/1.1 200 Connection established\r\n\r\n"
        if ProxySwitch.GREETING_WITH_200 in self.switches:
            first = await upstream_reader.read(4096)
            writer.write(established + first)
        else:
            writer.write(established)
        await writer.drain()
        await asyncio.gather(
            self._pipe(reader, upstream_writer, from_target=False),
            self._pipe(upstream_reader, writer, from_target=True),
            return_exceptions=True,
        )

    async def _pipe(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, *, from_target: bool
    ) -> None:
        try:
            while True:
                chunk = await reader.read(4096)
                if not chunk:
                    break
                if from_target and ProxySwitch.STRIP_STARTTLS in self.switches:
                    chunk = chunk.replace(b"250-STARTTLS\r\n", b"").replace(
                        b"250 STARTTLS\r\n", b""
                    )
                writer.write(chunk)
                await writer.drain()
                if from_target and ProxySwitch.CLOSE_MID_TUNNEL in self.switches:
                    break
        except (ConnectionError, OSError):
            pass
        finally:
            with contextlib.suppress(Exception):
                writer.close()


@contextmanager
def serve_proxy(proxy: ConnectProxy) -> Iterator[str]:
    """Run ``proxy`` on 127.0.0.1 in its own thread; yields its ``http://`` URL."""
    started = threading.Event()
    port: list[int] = []
    stop: list[asyncio.Event] = []

    async def main() -> None:
        proxy._loop = asyncio.get_running_loop()
        stop.append(asyncio.Event())
        server = await asyncio.start_server(proxy._handle, "127.0.0.1", 0)
        port.append(server.sockets[0].getsockname()[1])
        started.set()
        async with server:
            await stop[0].wait()

    thread = threading.Thread(target=lambda: asyncio.run(main()), daemon=True)
    thread.start()
    if not started.wait(10):
        raise RuntimeError("the fake proxy didn't start")
    try:
        yield f"http://127.0.0.1:{port[0]}"
    finally:
        loop = proxy._loop
        if loop is not None:
            loop.call_soon_threadsafe(stop[0].set)
        thread.join(5)
