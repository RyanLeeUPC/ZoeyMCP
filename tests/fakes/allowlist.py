"""A fake of the vault's allowlist endpoint, for the egress role's tests (M7 design O.1, BP-7).

``GET /_zoeymcp/egress/v1/allowlists`` as G.2 describes it: the egress key in
``x-zoeymcp-egress`` (403 otherwise, empty), the document ``egresslist.document`` builds (so its
form is the vault's), its digest as the ``ETag``, and the long poll: with ``If-None-Match``
naming the current digest, 304 at once, or with ``?wait=N`` once ``N`` seconds pass (at most
:attr:`AllowlistFake.max_wait`) unless :meth:`AllowlistFake.publish` changes the lists first (200).
Before the first publish it answers 503. The ``down`` switch makes it unreachable: a connection
is closed before anything is read, and a waiting poll is dropped. Asyncio only, in the test's
own event loop, next to an in-process role.

:class:`Clock` is the clock a test hands the role, so the lists go stale at 300 s without
waiting; :data:`KEY` is a well-formed egress key the fake accepts.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import time
from collections.abc import AsyncIterator, Iterable, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from zoeymcp.common import egresslist
from zoeymcp.common.egresslist import Destination

PATH = "/_zoeymcp/egress/v1/allowlists"
HEADER = "x-zoeymcp-egress"
KEY = "zeg1-" + "fakeEgressKeyForTheRoleTests0123456789abcde"
# A destination as a test writes it: (host, port), or (host, port, private).
Entry = tuple[str, int] | tuple[str, int, bool]


class Clock:
    """A clock the test moves. Starts at the real monotonic time."""

    def __init__(self) -> None:
        self.now = time.monotonic()

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@dataclass(frozen=True)
class Seen:
    """One request: its query, ``If-None-Match`` and egress key header, as sent."""

    query: dict[str, str]
    if_none_match: str | None
    key: str | None


def document(sources: Mapping[str, Iterable[Entry]]) -> dict[str, Any]:
    """The vault's answer for these lists (G.2), through ``egresslist.document``."""
    lists = {
        source: tuple(
            Destination(e[0], e[1], bool(e[2]) if len(e) == 3 else False, frozenset({"route"}))
            for e in sorted(entries)
        )
        for source, entries in sources.items()
    }
    return egresslist.document(lists)


@dataclass
class AllowlistFake:
    key: str = KEY
    max_wait: float = 25.0
    down: bool = False
    seen: list[Seen] = field(default_factory=list)
    # The answer body, as published; raw bytes stand for a document the role must refuse.
    body: bytes | None = None
    digest: str | None = None
    _changed: asyncio.Event | None = None

    def publish(self, sources: Mapping[str, Iterable[Entry]]) -> str:
        """New lists; a waiting poll answers them at once. Returns their digest."""
        made = document(sources)
        self.publish_raw(json.dumps(made).encode(), made["digest"])
        return str(made["digest"])

    def publish_raw(self, body: bytes, digest: str) -> None:
        """Any body under any digest (a broken document, say)."""
        self.body, self.digest = body, digest
        self._wake()

    def set_down(self, down: bool) -> None:
        self.down = down
        self._wake()

    def _wake(self) -> None:
        if self._changed is not None:
            self._changed.set()
            self._changed = asyncio.Event()

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            if not self.down:
                await self._answer(reader, writer)
        except (OSError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            pass
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()

    async def _answer(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        head = (await reader.readuntil(b"\r\n\r\n")).decode("latin-1")
        lines = head.removesuffix("\r\n\r\n").split("\r\n")
        method, target, _ = lines[0].split(" ", 2)
        headers = {}
        for line in lines[1:]:
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
        parts = urlsplit(target)
        seen = Seen(dict(parse_qsl(parts.query)), headers.get("if-none-match"), headers.get(HEADER))
        self.seen.append(seen)
        if parts.path != PATH:
            await _send(writer, 404)
            return
        if method != "GET":
            await _send(writer, 405)
            return
        if seen.key != self.key:
            await _send(writer, 403)
            return
        if self.body is None:
            await _send(writer, 503)
            return
        if seen.if_none_match == f'"{self.digest}"':
            if "wait" in seen.query:
                changed = self._changed
                assert changed is not None
                wait = min(float(seen.query["wait"]), self.max_wait)
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(changed.wait(), wait)
                if self.down:
                    return  # dropped, as by a vault that went away
            if seen.if_none_match == f'"{self.digest}"':
                await _send(writer, 304, etag=self.digest)
                return
        await _send(writer, 200, self.body, etag=self.digest)


async def _send(
    writer: asyncio.StreamWriter, status: int, body: bytes = b"", *, etag: str | None = None
) -> None:
    head = [f"HTTP/1.1 {status} Fake", f"content-length: {len(body)}"]
    if body:
        head.append("content-type: application/json")
    if etag is not None:
        head.append(f'etag: "{etag}"')
    writer.write(("\r\n".join(head) + "\r\n\r\n").encode() + body)
    await writer.drain()


@asynccontextmanager
async def serve_allowlist(fake: AllowlistFake) -> AsyncIterator[str]:
    """Serve ``fake`` on ``127.0.0.1`` in the running loop; yields its ``http://`` URL."""
    fake._changed = asyncio.Event()
    server = await asyncio.start_server(fake.handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.close()
        fake._wake()  # ends every waiting poll, so the server can close
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(server.wait_closed(), 5)
