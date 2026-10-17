"""The echo provider: reports exactly what it received.

It is the upstream for route self-tests and for checking what the vault forwards: method, path,
query, headers and body. ``GET /sse?n=3`` streams ``n`` server-sent events with a delay between
them, so tests can tell streaming from buffering.
"""

from __future__ import annotations

import asyncio
import base64
from collections.abc import AsyncIterator
from dataclasses import dataclass, field

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route


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

    def app(self) -> Starlette:
        return Starlette(
            routes=[
                Route("/sse", self._sse, methods=["GET"]),
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
