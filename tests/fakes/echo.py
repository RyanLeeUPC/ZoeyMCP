"""The echo provider: reports exactly what it received.

It is the upstream for route self-tests and for checking what the vault forwards: method, path,
query, headers and body. ``GET /sse?n=3`` streams ``n`` server-sent events with a delay between
them, so tests can tell streaming from buffering.

``/slow`` never answers: it waits until its caller goes away and notes when. With ``?events=N`` it
first sends the headers and ``N`` events, then goes silent. Tests use it to check that the vault
closes a silent upstream request when its own caller leaves.
"""

from __future__ import annotations

import asyncio
import base64
import threading
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route
from starlette.types import Receive, Scope, Send


@dataclass
class Received:
    method: str
    path: str
    query: list[tuple[str, str]]
    headers: list[tuple[str, str]]
    body: bytes

    def header(self, name: str) -> str | None:
        for key, value in self.headers:
            if key.lower() == name.lower():
                return value
        return None


@dataclass
class EchoProvider:
    received: list[Received] = field(default_factory=list)
    sse_delay: float = 0.05
    # When each /slow request saw its caller leave, by time.monotonic(). The server runs on its
    # own thread, so the event lets a test wait for the first one.
    departures: list[float] = field(default_factory=list)
    departed: threading.Event = field(default_factory=threading.Event)

    def app(self) -> Starlette:
        return Starlette(
            routes=[
                Route("/sse", self._sse, methods=["GET"]),
                Route("/slow", _Slow(self), methods=["GET", "POST"]),
                Route(
                    "/{path:path}",
                    self._echo,
                    methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
                ),
            ]
        )

    async def _record(self, request: Request) -> Received:
        item = Received(
            method=request.method,
            path=request.url.path,
            query=list(request.query_params.multi_items()),
            headers=[(k.decode("latin-1"), v.decode("latin-1")) for k, v in request.headers.raw],
            body=await request.body(),
        )
        self.received.append(item)
        return item

    async def _echo(self, request: Request) -> Response:
        item = await self._record(request)
        return JSONResponse(
            {
                "method": item.method,
                "path": item.path,
                "query": item.query,
                "headers": item.headers,
                "body_b64": base64.b64encode(item.body).decode(),
            }
        )

    async def _sse(self, request: Request) -> Response:
        await self._record(request)
        count = int(request.query_params.get("n", "3"))

        async def events() -> AsyncIterator[bytes]:
            for index in range(count):
                yield f"id: {index}\ndata: event {index}\n\n".encode()
                await asyncio.sleep(self.sse_delay)

        return StreamingResponse(events(), media_type="text/event-stream")


class _Slow:
    """The ``/slow`` endpoint, as a raw ASGI app so it can watch ``receive()`` itself."""

    def __init__(self, provider: EchoProvider) -> None:
        self.provider = provider

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive)
        await self.provider._record(request)
        events = int(request.query_params.get("events", "0"))
        if events:
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [(b"content-type", b"text/event-stream")],
                }
            )
            for index in range(events):
                body = f"data: slow {index}\n\n".encode()
                await send({"type": "http.response.body", "body": body, "more_body": True})
        while (await receive())["type"] != "http.disconnect":
            pass
        self.provider.departures.append(time.monotonic())
        self.provider.departed.set()
