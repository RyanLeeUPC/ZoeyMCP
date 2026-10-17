"""Fake providers, one per service shape (design §8.1).

Each fake checks credentials the way the real provider does, answers like it, and records what
it received. Some error paths deliberately echo the key or the full request URL back, as real
APIs sometimes do, so the tests can show the vault scrubs them.
"""

from __future__ import annotations

import asyncio
import base64
import json
from collections.abc import AsyncIterator
from dataclasses import dataclass, field

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route


@dataclass
class Seen:
    method: str
    path: str
    query: list[tuple[str, str]]
    headers: dict[str, str]
    body: bytes


@dataclass
class Fake:
    received: list[Seen] = field(default_factory=list)

    async def record(self, request: Request) -> Seen:
        seen = Seen(
            request.method,
            request.url.path,
            list(request.query_params.multi_items()),
            {k.lower(): v for k, v in request.headers.items()},
            await request.body(),
        )
        self.received.append(seen)
        return seen


# --- S1: OpenAI-compatible inference -----------------------------------------------------------


@dataclass
class InferenceFake(Fake):
    key: str = ""
    chunk_delay: float = 0.2

    def app(self) -> Starlette:
        return Starlette(
            routes=[
                Route("/v1/chat/completions", self.completions, methods=["POST"]),
                Route("/v1/models", self.models, methods=["GET"]),
                Route(
                    "/{path:path}", self.anything, methods=["GET", "POST", "PUT", "PATCH", "DELETE"]
                ),
            ]
        )

    def _authorized(self, seen: Seen) -> Response | None:
        presented = seen.headers.get("authorization", "")
        if presented != f"Bearer {self.key}":
            token = presented.removeprefix("Bearer ")
            return JSONResponse(
                {
                    "error": {
                        "message": f"Incorrect API key provided: {token}",
                        "type": "invalid_request_error",
                    }
                },
                status_code=401,
            )
        return None

    async def completions(self, request: Request) -> Response:
        seen = await self.record(request)
        if (refused := self._authorized(seen)) is not None:
            return refused
        body = json.loads(seen.body)
        if body.get("stream"):

            async def chunks() -> AsyncIterator[bytes]:
                for word in ("Hello", " from", " the model"):
                    delta = {"choices": [{"delta": {"content": word}}]}
                    yield f"data: {json.dumps(delta)}\n\n".encode()
                    await asyncio.sleep(self.chunk_delay)
                yield b"data: [DONE]\n\n"

            return StreamingResponse(chunks(), media_type="text/event-stream")
        return JSONResponse(
            {
                "choices": [{"message": {"role": "assistant", "content": "Hello"}}],
                "model": body.get("model"),
            }
        )

    async def models(self, request: Request) -> Response:
        seen = await self.record(request)
        if (refused := self._authorized(seen)) is not None:
            return refused
        return JSONResponse({"data": [{"id": "fake-model"}]})

    async def anything(self, request: Request) -> Response:
        await self.record(request)
        return JSONResponse({"error": {"message": "not found"}}, status_code=404)


# --- S2: Last.fm-style query key ---------------------------------------------------------------


@dataclass
class LastFmFake(Fake):
    key: str = ""

    def app(self) -> Starlette:
        return Starlette(routes=[Route("/2.0/", self.api, methods=["GET"])])

    async def api(self, request: Request) -> Response:
        seen = await self.record(request)
        params = dict(seen.query)
        if params.get("api_key") != self.key:
            return JSONResponse(
                {"error": 10, "message": "Invalid API key - You must be granted a valid key"},
                status_code=403,
            )
        if params.get("method") != "user.getinfo":
            # Like some real APIs, the error repeats the request URL, key included.
            return JSONResponse(
                {"error": 3, "message": f"Invalid Method - no such method: {request.url}"},
                status_code=400,
            )
        return JSONResponse({"user": {"name": params.get("user"), "playcount": "12345"}})


# --- S3: Telegram-style path token -------------------------------------------------------------


@dataclass
class TelegramFake(Fake):
    token: str = ""

    def app(self) -> Starlette:
        return Starlette(routes=[Route("/{bot}/{method}", self.api, methods=["GET", "POST"])])

    async def api(self, request: Request) -> Response:
        seen = await self.record(request)
        if request.path_params["bot"] != f"bot{self.token}":
            return JSONResponse(
                {"ok": False, "error_code": 401, "description": "Unauthorized"}, status_code=401
            )
        method = request.path_params["method"]
        if method == "getMe":
            return JSONResponse(
                {"ok": True, "result": {"id": 42, "is_bot": True, "username": "example_bot"}}
            )
        if method == "sendMessage":
            return JSONResponse({"ok": True, "result": {"message_id": 7}})
        return JSONResponse(
            {"ok": False, "error_code": 404, "description": f"Not Found: {seen.path}"},
            status_code=404,
        )


# --- S4: Atlassian-style basic auth ------------------------------------------------------------


@dataclass
class AtlassianFake(Fake):
    user: str = ""
    token: str = ""

    def app(self) -> Starlette:
        return Starlette(routes=[Route("/rest/api/3/myself", self.myself, methods=["GET"])])

    async def myself(self, request: Request) -> Response:
        seen = await self.record(request)
        expected = base64.b64encode(f"{self.user}:{self.token}".encode()).decode()
        if seen.headers.get("authorization") != f"Basic {expected}":
            return Response(
                "Unauthorized", status_code=401, headers={"WWW-Authenticate": 'Basic realm="x"'}
            )
        return JSONResponse({"emailAddress": self.user, "accountType": "atlassian"})


# --- S7: Grist-style documents -----------------------------------------------------------------


@dataclass
class GristFake(Fake):
    key: str = ""

    def app(self) -> Starlette:
        return Starlette(
            routes=[
                Route("/api/docs/{doc}/tables", self.tables, methods=["GET"]),
                Route(
                    "/api/docs/{doc}/tables/{table}/records",
                    self.records,
                    methods=["GET", "POST", "PATCH", "DELETE"],
                ),
                Route("/api/docs/{doc}", self.document, methods=["DELETE"]),
            ]
        )

    def _authorized(self, seen: Seen) -> bool:
        return seen.headers.get("authorization") == f"Bearer {self.key}"

    async def tables(self, request: Request) -> Response:
        seen = await self.record(request)
        if not self._authorized(seen):
            return JSONResponse({"error": "Unauthorized"}, status_code=401)
        return JSONResponse({"tables": [{"id": "Health_Log"}]})

    async def records(self, request: Request) -> Response:
        seen = await self.record(request)
        if not self._authorized(seen):
            return JSONResponse({"error": "Unauthorized"}, status_code=401)
        if request.method == "GET":
            return JSONResponse({"records": [{"id": 1, "fields": {"note": "ok"}}]})
        # The fake happily deletes: it's the vault's rules that must stop it.
        return JSONResponse({"records": [{"id": 2}]})

    async def document(self, request: Request) -> Response:
        await self.record(request)
        return JSONResponse({"deleted": True})


# --- S8: GitHub-style read-only ----------------------------------------------------------------


@dataclass
class GitHubFake(Fake):
    token: str = ""

    def app(self) -> Starlette:
        return Starlette(
            routes=[
                Route("/repos/{owner}/{repo}/issues", self.issues, methods=["GET", "POST"]),
                Route("/user", self.user, methods=["GET"]),
            ]
        )

    def _check(self, seen: Seen) -> Response | None:
        if not seen.headers.get("user-agent"):
            return JSONResponse({"message": "Request forbidden: no User-Agent"}, status_code=403)
        if seen.headers.get("authorization") != f"Bearer {self.token}":
            return JSONResponse({"message": "Bad credentials"}, status_code=401)
        return None

    async def issues(self, request: Request) -> Response:
        seen = await self.record(request)
        if (refused := self._check(seen)) is not None:
            return refused
        if request.method == "POST":
            return JSONResponse({"number": 99}, status_code=201)
        return JSONResponse(
            [{"number": 1, "title": "First issue"}],
            headers={
                "Link": '<https://api.github.com/repos/o/r/issues?page=2>; rel="next"',
                "Set-Cookie": "_gh_sess=session-cookie-value; Path=/; HttpOnly",
                "X-RateLimit-Remaining": "4999",
            },
        )

    async def user(self, request: Request) -> Response:
        seen = await self.record(request)
        if (refused := self._check(seen)) is not None:
            return refused
        return JSONResponse({"login": "example-user"})
