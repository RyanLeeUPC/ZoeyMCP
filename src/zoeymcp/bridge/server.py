"""The bridge's endpoint (M7 design C.4, C.5, M.3, N; X13, X17; SPEC-4, GR-10).

One path, ``/mcp``; every other path is 404, so the bridge answers no well-known, registration,
token or authorization path (X17). Each request is admitted by :mod:`.admit` before any body byte
is read (the path, the method, no ``Origin``, the token's hash, the content headers, the
session), and its body after; the bridge's own answers (M.3) have empty bodies but for a 400
or a 404 on a session, which carry a JSON-RPC error. ``Host`` is never read.

**Answers** to a request are an SSE stream, one event per message from the child, sent as each
arrives (contract 49): progress passes unbuffered. While the answer is pending, the stream
carries a ``: keepalive`` comment every ``--keepalive`` seconds (15 by default, GR-10). The
vault sends a stream route with no read timeout, so the keepalives serve the other hops. A
child that is gone before the stream began is answered 502; after, the stream ends with a
JSON-RPC error for the request. An accepted notification is 202 with no body, in both eras.

**Eras** (C.5). A **legacy** bridge runs a child per session: an ``initialize`` without
``Mcp-Session-Id`` reserves a place (beyond ``--max-sessions``, 503), starts a child, relays the
request and, on its answer, mints the session id sent back as ``Mcp-Session-Id``. Each GET opens
a stream of its own for the session's unsolicited notifications, each of which goes to the
oldest open one; DELETE stops the session's child (204); a session idle for ``--idle-timeout``
is stopped; a child that exits ends its session, so the next request on it is 404 and the
gateway initializes again. A **modern** bridge has one child, kept from the readiness probe and
started again at the next request once it exits; there an HTTP disconnect before the answer is
the request's cancel, sent to the child as ``notifications/cancelled``.

**Readiness** (C.5, fold-in C8). At start the bridge probes a child with ``initialize``
(legacy) or ``server/discover`` (modern) as ``zoeymcp-bridge-probe``; on a result within
``--start-timeout`` it writes ``<work>/ready`` (what ``zoeymcp bridge --ready-check`` tests) and
stops that child (legacy) or keeps it (modern). Until then every admitted request is 503
(``not_ready``); a probe that fails is logged and tried again.
"""

from __future__ import annotations

import asyncio
import contextlib
import itertools
import json
import os
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any, Final

from starlette.types import Receive, Scope, Send

from . import admit, event
from .admit import BridgeTokenHash, Refusal
from .child import STREAM_ITEMS_MAX, Child, Exchange, Item, Purpose, Spec
from .framing import (
    KEEPALIVE,
    KEEPALIVE_INTERVAL,
    LEGACY_VERSIONS,
    MODERN_VERSIONS,
    Era,
    Message,
    parse,
    sse_event,
    to_line,
)
from .sessions import IDLE_TIMEOUT, SESSIONS_MAX, Session, Sessions

# M7 design C.5 and M.6.
START_TIMEOUT: Final = 60.0
PROBE_CLIENT: Final = "zoeymcp-bridge-probe"
PROBE_RETRY: Final = 5.0
IDLE_CHECK_MAX: Final = 30.0
# The JSON-RPC error that ends a stream whose child is gone.
INTERNAL_ERROR: Final = -32603
CHILD_GONE_MESSAGE: Final = "the bridge's child exited"
START_TIMED_OUT: Final = Refusal(502, "start_timeout")
SSE_HEADERS: Final = (
    (b"content-type", b"text/event-stream"),
    (b"cache-control", b"no-cache"),
    (b"x-accel-buffering", b"no"),
)
CLIENT_INFO: Final = {"name": PROBE_CLIENT, "version": "1"}


@dataclass(frozen=True)
class Settings:
    """What the bridge serves with, from its command line (C.8)."""

    era: Era
    spec: Spec
    token: BridgeTokenHash
    ready_path: str
    max_sessions: int = SESSIONS_MAX
    idle_timeout: float = IDLE_TIMEOUT
    start_timeout: float = START_TIMEOUT
    keepalive: float = KEEPALIVE_INTERVAL


def probe_message(era: Era) -> Message:
    """The readiness probe's request, as a client named :data:`PROBE_CLIENT` sends it."""
    if era == "legacy":
        params: dict[str, Any] = {
            "protocolVersion": LEGACY_VERSIONS[-1],
            "capabilities": {},
            "clientInfo": CLIENT_INFO,
        }
        body = {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": params}
    else:
        meta = {
            admit.PROTOCOL_VERSION_META: MODERN_VERSIONS[-1],
            "io.modelcontextprotocol/clientInfo": CLIENT_INFO,
            "io.modelcontextprotocol/clientCapabilities": {},
        }
        body = {"jsonrpc": "2.0", "id": 0, "method": "server/discover", "params": {"_meta": meta}}
    found = parse(json.dumps(body, separators=(",", ":")).encode())
    assert isinstance(found, Message)  # noqa: S101 - a fixed, valid request
    return found


def is_result(data: bytes, max_bytes: int) -> bool:
    found = parse(data, max_bytes)
    return isinstance(found, Message) and "result" in found.value


class _Gone(Exception):
    """The client left while its request body was read."""


async def _body(receive: Receive, limit: int) -> bytes | None:
    """The request's body, or None when it is over ``limit``."""
    chunks: list[bytes] = []
    size = 0
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            raise _Gone
        chunk = message.get("body", b"")
        size += len(chunk)
        if size > limit:
            return None
        chunks.append(chunk)
        if not message.get("more_body", False):
            return b"".join(chunks)


async def _disconnected(receive: Receive) -> None:
    """Returns when the client leaves (its request body was read already)."""
    while (await receive())["type"] != "http.disconnect":
        pass


async def _answer(
    send: Send, status: int, headers: Iterable[tuple[bytes, bytes]] = (), body: bytes = b""
) -> None:
    head = [*headers, (b"content-length", str(len(body)).encode("ascii"))]
    await send({"type": "http.response.start", "status": status, "headers": head})
    await send({"type": "http.response.body", "body": body, "more_body": False})


async def _stream_start(send: Send) -> None:
    await send({"type": "http.response.start", "status": 200, "headers": list(SSE_HEADERS)})


async def _body_part(send: Send, body: bytes, *, more: bool = True) -> None:
    await send({"type": "http.response.body", "body": body, "more_body": more})


async def _refuse(refusal: Refusal, send: Send) -> None:
    event("bridge_refused", reason=refusal.reason, status=refusal.status)
    headers = [(name.encode("ascii"), value.encode("ascii")) for name, value in refusal.headers()]
    await _answer(send, refusal.status, headers, refusal.body())


def _error_event(exchange: Exchange) -> bytes:
    """The event that ends a started stream whose child is gone: an error for its request."""
    id_text = exchange.pending.id_text if exchange.pending is not None else "null"
    error = json.dumps({"code": INTERNAL_ERROR, "message": CHILD_GONE_MESSAGE})
    return sse_event(f'{{"jsonrpc":"2.0","id":{id_text},"error":{error}}}'.encode())


class _Stream:
    """A legacy session's GET stream: the unsolicited notifications it is sent."""

    def __init__(self) -> None:
        self.items: asyncio.Queue[bytes | None] = asyncio.Queue()

    def put(self, data: bytes | None) -> None:
        if data is None or self.items.qsize() < STREAM_ITEMS_MAX:
            self.items.put_nowait(data)


class Bridge:
    """The ASGI app, its children and its sessions. :meth:`start` begins the readiness probe;
    :meth:`close` stops every child and ends every stream."""

    def __init__(self, settings: Settings, *, clock: Callable[[], float] = time.monotonic) -> None:
        self.settings = settings
        self.era = settings.era
        self.ready = False
        self.sessions: Sessions[Child] = Sessions(settings.max_sessions, settings.idle_timeout)
        self._clock = clock
        self._numbers = itertools.count(1)
        self._children: set[Child] = set()
        self._session_of: dict[Child, Session[Child]] = {}
        self._streams: dict[Session[Child], dict[int, _Stream]] = {}
        self._shared: Child | None = None
        self._spawning = asyncio.Lock()
        self._tasks: list[asyncio.Task[None]] = []
        # Idle sessions' children being stopped.
        self._stops: set[asyncio.Task[None]] = set()
        self._closing = False

    # --- the lifetime ------------------------------------------------------------------------

    def start(self) -> None:
        """Probe for readiness, and (legacy) stop idle sessions, from now on."""
        self._tasks.append(asyncio.create_task(self._probe_until_ready()))
        if self.era == "legacy":
            self._tasks.append(asyncio.create_task(self._stop_idle()))

    async def close(self) -> None:
        """Stop: every stream ends, every child is stopped (C.3's numbers, at once)."""
        self._closing = True
        for task in self._tasks:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        for streams in self._streams.values():
            for stream in streams.values():
                stream.put(None)
        await asyncio.gather(*(child.stop() for child in list(self._children)))

    async def _spawn(self, purpose: Purpose) -> Child:
        try:
            child = await Child.spawn(self.settings.spec, self.era, purpose, clock=self._clock)
        except OSError as exc:
            event("bridge_child_failed", purpose=purpose, error_type=type(exc).__name__)
            raise
        self._children.add(child)
        child.on_exit = self._exited
        if self._closing:
            await child.stop()
        return child

    def _exited(self, child: Child) -> None:
        self._children.discard(child)
        session = self._session_of.pop(child, None)
        if session is not None:
            self._end(session, "child_exited")

    # --- readiness (C.5) ---------------------------------------------------------------------

    async def _probe_until_ready(self) -> None:
        while not self.ready:
            reason = await self._probe()
            if reason is None:
                self._write_ready()
                self.ready = True
                event("bridge_ready")
                return
            event("bridge_probe_failed", reason=reason)
            await asyncio.sleep(PROBE_RETRY)

    async def _probe(self) -> str | None:
        """None once a child answered the probe with a result; else why not."""
        try:
            child = await self._spawn("probe")
        except OSError:
            return "spawn_failed"
        exchange = Exchange(next(self._numbers))
        await child.request(probe_message(self.era), exchange)
        try:
            async with asyncio.timeout(self.settings.start_timeout):
                item = await exchange.get()
                while not item.final:
                    item = await exchange.get()
        except TimeoutError:
            await child.stop()
            return "timeout"
        if item.data is None:
            return "exited"
        if not is_result(item.data, self.settings.spec.max_message_bytes):
            await child.stop()
            return "error"
        if self.era == "legacy":
            await child.stop()
        else:
            self._shared = child
        return None

    def _write_ready(self) -> None:
        fd = os.open(self.settings.ready_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.close(fd)

    # --- legacy sessions (C.5) ---------------------------------------------------------------

    async def _stop_idle(self) -> None:
        interval = min(self.settings.idle_timeout / 2, IDLE_CHECK_MAX)
        while True:
            await asyncio.sleep(interval)
            for session in self.sessions.idle(self._clock()):
                self._session_of.pop(session.child, None)
                event("bridge_session_ended", session=session.hash8, reason="idle")
                stop = asyncio.create_task(session.child.stop())
                self._stops.add(stop)
                stop.add_done_callback(self._stops.discard)

    def _end(self, session: Session[Child], reason: str) -> None:
        """Forget a session and end its GET streams; its child is the caller's to stop."""
        if self.sessions.end(session):
            event("bridge_session_ended", session=session.hash8, reason=reason)
        for stream in self._streams.pop(session, {}).values():
            stream.put(None)

    def _broadcast(self, session: Session[Child], data: bytes) -> None:
        number = session.stream
        stream = None if number is None else self._streams.get(session, {}).get(number)
        if stream is not None:
            stream.put(data)

    async def _start_session(self, message: Message, receive: Receive, send: Send) -> None:
        """A legacy ``initialize``: a child for a new session, which exists once it answered."""
        if not self.sessions.reserve():
            await _refuse(admit.SESSIONS_FULL, send)
            return
        child: Child | None = None
        established = False
        try:
            try:
                child = await self._spawn("session")
            except OSError:
                await _refuse(admit.CHILD_EXITED, send)
                return
            exchange = Exchange(next(self._numbers))
            await child.request(message, exchange)
            items = await self._answer_of(exchange, receive)
            if items is None:
                return  # the client left
            if not items:
                await _refuse(START_TIMED_OUT, send)
                return
            answer = items[-1].data
            if answer is None:
                await _refuse(admit.CHILD_EXITED, send)
                return
            headers = list(SSE_HEADERS)
            if is_result(answer, self.settings.spec.max_message_bytes):
                session = self.sessions.establish(child, self._clock())
                established = True
                self._session_of[child] = session
                child.on_broadcast = lambda data: self._broadcast(session, data)
                headers.append((b"mcp-session-id", session.session_id.encode("ascii")))
                event("bridge_session_started", session=session.hash8, pid=child.pid)
                if child.done.is_set():
                    self._exited(child)
            body = b"".join(sse_event(item.data) for item in items if item.data is not None)
            await _answer(send, 200, headers, body)
        finally:
            if not established:
                self.sessions.release()
                if child is not None:
                    await child.stop()

    async def _answer_of(self, exchange: Exchange, receive: Receive) -> list[Item] | None:
        """Everything the child sends for ``exchange`` up to its answer: empty when it took
        longer than ``--start-timeout``, None when the client left first, and ending in
        :data:`~.child.GONE` when the child is gone."""
        items: list[Item] = []
        watcher = asyncio.ensure_future(_disconnected(receive))
        getter = asyncio.ensure_future(exchange.get())
        try:
            async with asyncio.timeout(self.settings.start_timeout):
                while True:
                    await asyncio.wait((getter, watcher), return_when=asyncio.FIRST_COMPLETED)
                    if not getter.done():
                        return None
                    items.append(getter.result())
                    if items[-1].final:
                        return items
                    getter = asyncio.ensure_future(exchange.get())
        except TimeoutError:
            return []
        finally:
            getter.cancel()
            watcher.cancel()

    async def _get(self, session: Session[Child], receive: Receive, send: Send) -> None:
        """A legacy GET: a stream of the session's notifications until it ends or the client
        leaves."""
        number = session.open_stream()
        stream = _Stream()
        self._streams.setdefault(session, {})[number] = stream
        watcher = asyncio.ensure_future(_disconnected(receive))
        getter = asyncio.ensure_future(stream.items.get())
        try:
            await _stream_start(send)
            while True:
                done, _ = await asyncio.wait(
                    (getter, watcher),
                    timeout=self.settings.keepalive,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if getter in done:
                    data = getter.result()
                    if data is None:
                        await _body_part(send, b"", more=False)
                        return
                    await _body_part(send, sse_event(data))
                    getter = asyncio.ensure_future(stream.items.get())
                elif watcher in done:
                    return
                else:
                    await _body_part(send, KEEPALIVE)
        finally:
            getter.cancel()
            watcher.cancel()
            session.close_stream(number, self._clock())
            self._streams.get(session, {}).pop(number, None)

    async def _delete(self, session: Session[Child], send: Send) -> None:
        self._session_of.pop(session.child, None)
        self._end(session, "deleted")
        await session.child.stop()
        await _answer(send, 204)

    # --- requests ----------------------------------------------------------------------------

    async def _shared_child(self) -> Child | None:
        """A modern bridge's one child, started again once it exited; None when it can't be."""
        async with self._spawning:
            child = self._shared
            if child is None or child.done.is_set():
                try:
                    child = await self._spawn("shared")
                except OSError:
                    return None
                self._shared = child
            return child

    async def _relay(self, child: Child, message: Message, receive: Receive, send: Send) -> None:
        """A request relayed to ``child``, its answer streamed back."""
        if child.done.is_set():
            await _refuse(admit.CHILD_EXITED, send)
            return
        exchange = Exchange(next(self._numbers))
        # The client's leaving is watched from before the line is written: a child that stops
        # reading its stdin holds the write, and the disconnect must still end the request
        # (legacy: so the session can go idle, FM-20).
        watcher = asyncio.ensure_future(_disconnected(receive))
        sending = asyncio.ensure_future(child.request(message, exchange))
        getter: asyncio.Future[Item] | None = None
        started = False
        try:
            await asyncio.wait((sending, watcher), return_when=asyncio.FIRST_COMPLETED)
            if not sending.done():
                # Cancelled before it ran, or while waiting on the pipe with the line written.
                sending.cancel()
                child.left(exchange)
                return
            if sending.result() is None:
                await _refuse(admit.BUSY, send)
                return
            getter = asyncio.ensure_future(exchange.get())
            while True:
                done, _ = await asyncio.wait(
                    (getter, watcher),
                    timeout=self.settings.keepalive,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if getter in done:
                    item = getter.result()
                    if item.data is None and not started:
                        await _refuse(admit.CHILD_EXITED, send)
                        return
                    if not started:
                        await _stream_start(send)
                        started = True
                    data = _error_event(exchange) if item.data is None else sse_event(item.data)
                    await _body_part(send, data, more=not item.final)
                    if item.final:
                        return
                    getter = asyncio.ensure_future(exchange.get())
                elif watcher in done:
                    child.left(exchange)
                    return
                else:
                    if not started:
                        await _stream_start(send)
                        started = True
                    await _body_part(send, KEEPALIVE)
        finally:
            sending.cancel()
            if getter is not None:
                getter.cancel()
            watcher.cancel()
            child.exchanges.pop(exchange.number, None)

    async def _notification(self, session: Session[Child] | None, admitted: admit.Admitted) -> None:
        """A legacy notification for the session's child: ``initialized`` as it is, a cancel
        resolved against the session's own requests (C.4)."""
        if session is None:
            return
        if admitted.action == "notify":
            await session.child.send(to_line(admitted.message.raw))
        elif admitted.action == "cancel":
            line = session.child.relay.cancel(admitted.message)
            if line is not None:
                session.child.write(line)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return
        method = scope["method"]
        seen = admit.head(
            self.era,
            method,
            scope["path"],
            scope["headers"],
            token=self.settings.token,
            find=self.sessions.find,
            max_bytes=self.settings.spec.max_message_bytes,
        )
        if isinstance(seen, Refusal):
            await _refuse(seen, send)
            return
        if not self.ready or self._closing:
            await _refuse(admit.NOT_READY, send)
            return
        if method == "GET" and seen.session is not None:
            await self._get(seen.session, receive, send)
            return
        if method == "DELETE" and seen.session is not None:
            await self._delete(seen.session, send)
            return
        try:
            data = await _body(receive, self.settings.spec.max_message_bytes)
        except _Gone:
            return
        if data is None:
            await _refuse(admit.TOO_LARGE, send)
            return
        admitted = admit.body(self.era, seen, data, max_bytes=self.settings.spec.max_message_bytes)
        if isinstance(admitted, Refusal):
            await _refuse(admitted, send)
            return
        if admitted.action == "start":
            await self._start_session(admitted.message, receive, send)
            return
        if admitted.accepted:
            await self._notification(seen.session, admitted)
            await _answer(send, 202)
            return
        if seen.session is not None:
            session = seen.session
            session.begin(self._clock())
            try:
                await self._relay(session.child, admitted.message, receive, send)
            finally:
                session.finish(self._clock())
            return
        child = await self._shared_child()
        if child is None:
            await _refuse(admit.CHILD_EXITED, send)
            return
        await self._relay(child, admitted.message, receive, send)
