"""SDK contract for approvals: M4 design N.3, items 16 to 31.

Each test pins one fact the gateway's elicitation back end rests on (M4 design D): how a legacy
``elicitation/create`` travels and is answered, what a timeout or a cancel does, the exact params
on the wire per protocol version, the modern ``input_required`` round trip, and what middleware
can see. The server here is a low-level ``Server`` behind ``StreamableHTTPSessionManager`` with
``json_response=False``, as the gateway runs it; its ``tools/call`` handler runs whatever the test
supplies. Agents are raw ``httpx`` (to see which stream carries what) and the SDK client.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import threading
import time
import warnings
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager, contextmanager
from typing import Any

import anyio
import httpx
import mcp_types as types
import pydantic
import pytest
from mcp.server import Server
from mcp.server.context import ServerRequestContext
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.shared.exceptions import MCPError, NoBackChannelError
from mcp.shared.message import ServerMessageMetadata
from starlette.types import Message, Receive, Scope, Send

from tests.fakes.harness import serve
from zoeymcp.common.canonical import loads_strict

from .test_server_contract import (
    CURRENT,
    LEGACY,
    MODERN,
    PATH,
    legacy_session,
    modern_body,
    modern_headers,
    wire,
)

pytestmark = pytest.mark.anyio

OLD_LEGACY = "2025-06-18"
EMPTY_SCHEMA: dict[str, Any] = {"type": "object", "properties": {}}
Handler = Callable[[ServerRequestContext[Any], types.CallToolRequestParams], Awaitable[Any]]


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def done(text: str) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(type="text", text=text)])


class Asker:
    """The gateway's client-facing server, cut down to a ``tools/call`` handler a test supplies.

    Like the gateway's glue, it wraps ``receive`` for every request, here only to note an
    ``http.disconnect`` (M4 design D.4), and sets a contextvar from a test header.
    """

    def __init__(
        self, handler: Handler, *, stateless: bool = False, middleware: list[Any] | None = None
    ) -> None:
        self.handler = handler
        self.server: Server[Any] = Server(
            "zoeymcp-gateway", version="1", on_call_tool=self._call, on_list_tools=self._list
        )
        self.server.middleware = list(middleware or [])
        self.manager = StreamableHTTPSessionManager(
            self.server, json_response=False, stateless=stateless
        )
        self.disconnects: list[str] = []  # the request's x-test-request header, per disconnect
        self.bodies: list[Any] = []  # every POST body, parsed
        self.events: list[str] = []
        self.loop: asyncio.AbstractEventLoop | None = None

    async def _list(self, ctx: ServerRequestContext[Any], params: Any) -> types.ListToolsResult:
        tool = types.Tool(name="send", input_schema={"type": "object"})
        return types.ListToolsResult(tools=[tool])

    async def _call(
        self, ctx: ServerRequestContext[Any], params: types.CallToolRequestParams
    ) -> Any:
        self.events.append("started")
        try:
            result = await self.handler(ctx, params)
        except BaseException as exc:
            self.events.append(f"ended:{type(exc).__name__}")
            raise
        self.events.append("finished")
        return result

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            await receive()
            self.loop = asyncio.get_running_loop()
            async with self.manager.run():
                await send({"type": "lifespan.startup.complete"})
                await receive()
            await send({"type": "lifespan.shutdown.complete"})
            return
        if scope["type"] != "http":
            return
        headers = {k.decode().lower(): v.decode() for k, v in scope["headers"]}
        tag = headers.get("x-test-request", "")
        body = b""
        if scope["method"] == "POST":  # read the body first and replay it, as the gateway does
            while True:
                message = await receive()
                body += message.get("body", b"")
                if message["type"] != "http.request" or not message.get("more_body"):
                    break
            if body:
                self.bodies.append(json.loads(body))
        replayed = False

        async def watched() -> Message:
            nonlocal replayed
            if scope["method"] == "POST" and not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            message = await receive()
            if message["type"] == "http.disconnect":
                self.disconnects.append(tag)
            return message

        token = CURRENT.set((headers.get("x-test-client"), tag))
        try:
            await self.manager.handle_request(scope, watched, send)
        finally:
            CURRENT.reset(token)


@contextmanager
def running(asker: Asker) -> Any:
    with serve(asker, lifespan=True) as base:
        yield f"{base}{PATH}"


def form(
    message: str = "Approve this call?", schema: dict[str, Any] | None = None
) -> types.ElicitRequest:
    params = types.ElicitRequestFormParams(message=message, requested_schema=schema or EMPTY_SCHEMA)
    return types.ElicitRequest(params=params)


async def ask(
    ctx: ServerRequestContext[Any], *, timeout: float | None = 10.0
) -> types.ElicitResult:
    """The legacy prompt as M4 design D.2 sends it: on the call's own stream, with a timeout."""
    return await ctx.session.send_request(
        form(),
        types.ElicitResult,
        request_read_timeout_seconds=timeout,
        metadata=ServerMessageMetadata(related_request_id=ctx.request_id),
    )


def session_headers(session: str, version: str = LEGACY, tag: str | None = None) -> dict[str, str]:
    return wire("a", tag, {"mcp-session-id": session, "mcp-protocol-version": version})


def call_body(request_id: int = 2, name: str = "send", **params: Any) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": name, "arguments": {}, **params},
    }


async def messages(lines: AsyncIterator[str]) -> AsyncIterator[dict[str, Any]]:
    """The JSON-RPC messages of an SSE stream, as they arrive."""
    async for line in lines:
        if line.startswith("data:") and line[5:].strip():
            value = loads_strict(line[5:].strip())
            assert isinstance(value, dict)
            yield value


@asynccontextmanager
async def legacy_call(
    url: str, session: str, *, tag: str = "call", request_id: int = 2, version: str = LEGACY
) -> AsyncIterator[tuple[httpx.AsyncClient, AsyncIterator[dict[str, Any]]]]:
    """A legacy ``tools/call`` POST held open, and the messages on its SSE stream."""
    async with httpx.AsyncClient(timeout=10) as http:
        headers = session_headers(session, version, tag)
        async with http.stream(
            "POST", url, json=call_body(request_id), headers=headers
        ) as response:
            assert response.status_code == 200
            assert response.headers["content-type"].startswith("text/event-stream")
            yield http, messages(response.aiter_lines())


async def answer(
    http: httpx.AsyncClient,
    url: str,
    session: str,
    request_id: Any,
    result: dict[str, Any] | None = None,
    *,
    error: dict[str, Any] | None = None,
) -> httpx.Response:
    body: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id}
    if error is not None:
        body["error"] = error
    else:
        body["result"] = result if result is not None else {"action": "accept"}
    return await http.post(url, json=body, headers=session_headers(session, tag="answer"))


@asynccontextmanager
async def get_stream(url: str, session: str) -> AsyncIterator[list[dict[str, Any]]]:
    """A legacy session's GET stream, collecting what it carries."""
    seen: list[dict[str, Any]] = []

    async def read() -> None:
        async with httpx.AsyncClient(timeout=httpx.Timeout(10, read=60)) as http:
            headers = {**session_headers(session, tag="get"), "accept": "text/event-stream"}
            async with http.stream("GET", url, headers=headers) as response:
                async for message in messages(response.aiter_lines()):
                    seen.append(message)

    async with anyio.create_task_group() as group:
        group.start_soon(read)
        await anyio.sleep(0.3)
        yield seen
        group.cancel_scope.cancel()


# --- 16. a legacy prompt travels on the call's own POST stream -----------------------------------


async def test_a_legacy_prompt_travels_on_the_calls_post_stream() -> None:
    async def handler(ctx: ServerRequestContext[Any], params: types.CallToolRequestParams) -> Any:
        result = await ask(ctx)
        return done(result.action)

    asker = Asker(handler)
    with running(asker) as url:
        session = legacy_session(url)
        async with get_stream(url, session) as on_get, legacy_call(url, session) as (http, stream):
            request = await anext(stream)
            assert request["method"] == "elicitation/create"
            assert request["params"]["message"] == "Approve this call?"
            assert (await answer(http, url, session, request["id"])).status_code == 202
            final = await anext(stream)
        assert final["id"] == 2
        assert final["result"]["content"][0]["text"] == "accept"
        assert not any(m.get("method") == "elicitation/create" for m in on_get)


# --- 17. the response POST resolves it; an unknown or late id is dropped ------------------------


async def test_the_response_post_resolves_the_prompt_and_strays_are_dropped() -> None:
    async def handler(ctx: ServerRequestContext[Any], params: types.CallToolRequestParams) -> Any:
        return done((await ask(ctx)).action)

    asker = Asker(handler)
    with running(asker) as url:
        session = legacy_session(url)
        async with legacy_call(url, session) as (http, stream):
            request = await anext(stream)
            stray = await answer(http, url, session, 987654)  # an id nobody asked
            assert stray.status_code == 202
            assert (
                await answer(http, url, session, request["id"], {"action": "decline"})
            ).status_code == 202
            final = await anext(stream)
            assert final["result"]["content"][0]["text"] == "decline"
            late = await answer(http, url, session, request["id"])  # answered already
            assert late.status_code == 202
    assert asker.events == ["started", "finished"]


# --- 18. a timeout raises REQUEST_TIMEOUT and cancels the prompt --------------------------------


async def test_a_prompt_timeout_raises_and_sends_a_cancel() -> None:
    outcome: list[Any] = []

    async def handler(ctx: ServerRequestContext[Any], params: types.CallToolRequestParams) -> Any:
        try:
            await ask(ctx, timeout=0.3)
        except MCPError as exc:
            outcome.append(exc.error.code)
        return done("timed out")

    asker = Asker(handler)
    with running(asker) as url:
        session = legacy_session(url)
        async with legacy_call(url, session) as (_, stream):
            request = await anext(stream)
            cancel = await anext(stream)
            final = await anext(stream)
    assert outcome == [types.REQUEST_TIMEOUT]
    assert cancel["method"] == "notifications/cancelled"
    assert cancel["params"]["requestId"] == request["id"]
    assert final["result"]["content"][0]["text"] == "timed out"


# --- 19. the agent's cancel of its call cancels the prompt --------------------------------------


async def test_cancelling_the_call_cancels_the_prompt_with_a_courtesy_cancel() -> None:
    async def handler(ctx: ServerRequestContext[Any], params: types.CallToolRequestParams) -> Any:
        return done((await ask(ctx)).action)

    asker = Asker(handler)
    with running(asker) as url:
        session = legacy_session(url)
        async with legacy_call(url, session) as (http, stream):
            request = await anext(stream)
            notice = {
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": {"requestId": 2, "reason": "agent gave up"},
            }
            sent = await http.post(url, json=notice, headers=session_headers(session, tag="cancel"))
            assert sent.status_code == 202
            seen = [m async for m in stream]
    cancels = [m for m in seen if m.get("method") == "notifications/cancelled"]
    assert [c["params"]["requestId"] for c in cancels] == [request["id"]]
    assert asker.events == ["started", "ended:CancelledError"]
    assert not any("result" in m for m in seen)


# --- 20. an accept with no content -------------------------------------------------------------


async def test_an_accept_with_no_content_parses() -> None:
    results: list[types.ElicitResult] = []

    async def handler(ctx: ServerRequestContext[Any], params: types.CallToolRequestParams) -> Any:
        results.append(await ask(ctx))
        return done("ok")

    asker = Asker(handler)
    with running(asker) as url:
        session = legacy_session(url)
        async with legacy_call(url, session) as (http, stream):
            request = await anext(stream)
            await answer(http, url, session, request["id"], {"action": "accept"})
            await anext(stream)
    assert results == [types.ElicitResult(action="accept", content=None)]


# --- 21. the exact params on the wire, per version ----------------------------------------------


def legacy_init_at(url: str, version: str) -> str:
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": version,
            "capabilities": {"elicitation": {}},
            "clientInfo": {"name": "agent", "version": "1"},
        },
    }
    response = httpx.post(url, json=body, headers=wire("a"), timeout=10)
    assert response.status_code == 200, response.text
    session = response.headers["mcp-session-id"]
    initialized = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    sent = httpx.post(url, json=initialized, headers=session_headers(session, version), timeout=10)
    assert sent.status_code == 202
    return session


def gateway_form(ctx: ServerRequestContext[Any]) -> types.ElicitRequest:
    """M4 design D.2's params: no ``mode`` on 2025-06-18, ``mode: "form"`` on 2025-11-25."""
    if ctx.session.protocol_version == OLD_LEGACY:
        params: Any = types.ElicitRequestFormParams.model_construct(
            mode=None,  # type: ignore[arg-type]  # deliberately: the dump then drops the key
            message="m",
            requested_schema=EMPTY_SCHEMA,
        )
    else:
        params = types.ElicitRequestFormParams(message="m", requested_schema=EMPTY_SCHEMA)
    return types.ElicitRequest.model_construct(method="elicitation/create", params=params)


@pytest.mark.parametrize(("version", "mode"), [(OLD_LEGACY, None), (LEGACY, "form")])
async def test_the_wire_params_per_version(version: str, mode: str | None) -> None:
    async def handler(ctx: ServerRequestContext[Any], params: types.CallToolRequestParams) -> Any:
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            result = await ctx.session.send_request(
                gateway_form(ctx),
                types.ElicitResult,
                request_read_timeout_seconds=10,
                metadata=ServerMessageMetadata(related_request_id=ctx.request_id),
            )
        return done(result.action)

    asker = Asker(handler)
    with running(asker) as url:
        session = legacy_init_at(url, version)
        async with legacy_call(url, session, version=version) as (http, stream):
            request = await anext(stream)
            await answer(http, url, session, request["id"])
            await anext(stream)
    assert request["params"] == (
        {"message": "m", "requestedSchema": EMPTY_SCHEMA}
        | ({"mode": mode} if mode is not None else {})
    )


def test_model_construct_without_mode_still_sends_form() -> None:
    # The guard: only an explicit mode=None drops the key.
    params = types.ElicitRequestFormParams.model_construct(
        message="m", requested_schema=EMPTY_SCHEMA
    )
    request = types.ElicitRequest.model_construct(method="elicitation/create", params=params)
    dumped = request.model_dump(by_alias=True, mode="json", exclude_none=True)
    assert dumped["params"]["mode"] == "form"


# --- 22. no back channel on a stateless legacy request ------------------------------------------


async def test_a_stateless_legacy_request_has_no_back_channel() -> None:
    seen: list[Any] = []

    async def handler(ctx: ServerRequestContext[Any], params: types.CallToolRequestParams) -> Any:
        seen.append(ctx.session.can_send_request)
        try:
            await ask(ctx)
        except NoBackChannelError as exc:
            seen.append(isinstance(exc, MCPError))
        return done("refused")

    asker = Asker(handler, stateless=True)
    with running(asker) as url:
        headers = wire("a", extra={"mcp-protocol-version": LEGACY})
        response = httpx.post(url, json=call_body(), headers=headers, timeout=10)
    assert response.status_code == 200
    assert seen == [False, True]
    assert issubclass(NoBackChannelError, MCPError)


# --- 23. input_required: an internal error on legacy, served as is on modern ---------------------

HANDLE = "za1." + "A" * 43


def approval_input_required() -> types.InputRequiredResult:
    return types.InputRequiredResult(
        input_requests={"zoeymcp-approval": form()}, request_state=HANDLE
    )


def modern_call(
    params: dict[str, Any] | None = None,
    *,
    capabilities: dict[str, Any] | None = None,
    tag: str = "call",
) -> tuple[dict[str, Any], dict[str, str]]:
    call = {"name": "send", "arguments": {}, **(params or {})}
    meta = {types.CLIENT_CAPABILITIES_META_KEY: capabilities} if capabilities is not None else None
    body = modern_body("tools/call", call, meta)
    headers = {**modern_headers("tools/call", call), "x-test-request": tag}
    return body, headers


def rpc(response: httpx.Response) -> dict[str, Any]:
    lines = [line[5:].strip() for line in response.text.splitlines() if line.startswith("data:")]
    raw = lines[-1] if lines else response.text
    value = loads_strict(raw)
    assert isinstance(value, dict)
    return value


async def test_input_required_is_an_error_on_legacy_and_a_result_on_modern() -> None:
    async def handler(ctx: ServerRequestContext[Any], params: types.CallToolRequestParams) -> Any:
        return approval_input_required()

    asker = Asker(handler)
    with running(asker) as url:
        session = legacy_session(url)
        legacy = httpx.post(url, json=call_body(), headers=session_headers(session), timeout=10)
        body, headers = modern_call(capabilities={"elicitation": {}})
        modern = httpx.post(url, json=body, headers=headers, timeout=10)
    assert rpc(legacy)["error"]["code"] == types.INTERNAL_ERROR
    result = rpc(modern)["result"]
    assert result["resultType"] == "input_required"
    assert result["requestState"] == HANDLE
    assert result["inputRequests"]["zoeymcp-approval"]["method"] == "elicitation/create"
    assert "ttlMs" not in result
    assert "cacheScope" not in result


# --- 24. a dropped legacy POST stream doesn't cancel the handler --------------------------------


async def test_a_dropped_legacy_stream_leaves_the_handler_running_and_is_seen() -> None:
    outcome: list[str] = []

    async def handler(ctx: ServerRequestContext[Any], params: types.CallToolRequestParams) -> Any:
        try:
            await ask(ctx, timeout=1.5)
        except MCPError:
            outcome.append("timed out")
        return done("late")

    asker = Asker(handler)
    with running(asker) as url:
        session = legacy_session(url)
        async with legacy_call(url, session, tag="dropped") as (_, stream):
            await anext(stream)
        # The client hung up while the prompt waited.
        with anyio.fail_after(1):
            while "dropped" not in asker.disconnects:
                await anyio.sleep(0.02)
        assert asker.events == ["started"]  # the handler still waits
        with anyio.fail_after(5):
            while "finished" not in asker.events:
                await anyio.sleep(0.05)
    assert outcome == ["timed out"]


# --- 25, 26. a modern retry's state and answers reach the handler verbatim -----------------------


async def test_a_modern_retrys_state_and_answers_reach_the_handler() -> None:
    seen: list[types.CallToolRequestParams] = []

    async def handler(ctx: ServerRequestContext[Any], params: types.CallToolRequestParams) -> Any:
        seen.append(params)
        return done("ok")

    asker = Asker(handler)
    with running(asker) as url:
        answers = {"zoeymcp-approval": {"action": "accept"}, "stray": {"action": "decline"}}
        body, headers = modern_call(
            {"requestState": HANDLE, "inputResponses": answers}, capabilities={"elicitation": {}}
        )
        response = httpx.post(url, json=body, headers=headers, timeout=10)
    assert rpc(response)["result"]["content"][0]["text"] == "ok"
    [params] = seen
    assert params.request_state == HANDLE
    assert params.input_responses is not None
    approval = params.input_responses["zoeymcp-approval"]
    assert isinstance(approval, types.ElicitResult)
    assert (approval.action, approval.content) == ("accept", None)
    assert isinstance(params.input_responses["stray"], types.ElicitResult)


# --- 27. what the capability checks see ----------------------------------------------------------

ELICITATION = types.ClientCapabilities(elicitation=types.ElicitationCapability())


async def test_capabilities_per_era() -> None:
    seen: list[tuple[str | None, bool, Any]] = []

    async def handler(ctx: ServerRequestContext[Any], params: types.CallToolRequestParams) -> Any:
        capabilities = ctx.session.client_capabilities
        elicitation = capabilities.elicitation if capabilities is not None else None
        seen.append(
            (CURRENT.get()[1], ctx.session.check_client_capability(ELICITATION), elicitation)
        )
        return done("ok")

    asker = Asker(handler)
    with running(asker) as url:
        init = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": LEGACY,
                "capabilities": {"elicitation": {"url": {}}},
                "clientInfo": {"name": "agent", "version": "1"},
            },
        }
        response = httpx.post(url, json=init, headers=wire("a"), timeout=10)
        session = response.headers["mcp-session-id"]
        initialized = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        httpx.post(url, json=initialized, headers=session_headers(session), timeout=10)
        httpx.post(
            url, json=call_body(), headers=session_headers(session, tag="url-only"), timeout=10
        )
        cases: list[tuple[str, dict[str, Any]]] = [
            ("form", {"elicitation": {"form": {}}}),
            ("none", {}),
        ]
        for tag, capabilities in cases:
            body, headers = modern_call(capabilities=capabilities, tag=tag)
            httpx.post(url, json=body, headers=headers, timeout=10)
    by_tag = {tag: (checked, elicitation) for tag, checked, elicitation in seen}
    checked, elicitation = by_tag["url-only"]
    assert checked  # the SDK's check doesn't tell URL-only from form (M4 design D.1)
    assert elicitation.form is None
    assert elicitation.url is not None
    checked, elicitation = by_tag["form"]
    assert checked
    assert elicitation.form is not None  # this request's own _meta
    assert by_tag["none"] == (False, None)


# --- 28. a modern client disconnect cancels the handler ------------------------------------------


async def test_a_modern_disconnect_cancels_the_handler() -> None:
    async def handler(ctx: ServerRequestContext[Any], params: types.CallToolRequestParams) -> Any:
        await anyio.sleep(30)
        return done("never")

    asker = Asker(handler)
    with running(asker) as url:
        body, headers = modern_call(capabilities={})
        # A modern response sends nothing before its result, so the agent hangs up on a timeout.
        async with httpx.AsyncClient(timeout=httpx.Timeout(10, read=0.5)) as http:
            with pytest.raises(httpx.ReadTimeout):
                await http.post(url, json=body, headers=headers)
        with anyio.fail_after(5):
            while len(asker.events) < 2:
                await anyio.sleep(0.02)
    assert asker.events == ["started", "ended:CancelledError"]


# --- 29. middleware sees the typed parse fail; only the envelope ladder runs before it ----------


async def test_middleware_wraps_the_typed_parse() -> None:
    seen: list[tuple[str, Any, str]] = []

    async def guard(ctx: ServerRequestContext[Any], call_next: Any) -> Any:
        try:
            return await call_next(ctx)
        except BaseException as exc:
            seen.append((ctx.method, CURRENT.get()[1], type(exc).__name__))
            raise

    async def handler(ctx: ServerRequestContext[Any], params: types.CallToolRequestParams) -> Any:
        return done("ok")

    asker = Asker(handler, middleware=[guard])
    with running(asker) as url:
        nested = {"zoeymcp-approval": {"action": "accept", "content": {"a": {"deep": 1}}}}
        body, headers = modern_call(
            {"requestState": HANDLE, "inputResponses": nested}, capabilities={}, tag="nested"
        )
        bad_parse = httpx.post(url, json=body, headers=headers, timeout=10)
        # Capabilities of the wrong type pass the SDK's envelope ladder and fail the typed parse,
        # inside the chain, so the gateway's guard sees them too.
        body, headers = modern_call(capabilities={}, tag="capabilities")
        body["params"]["_meta"][types.CLIENT_CAPABILITIES_META_KEY] = "not an object"
        bad_capabilities = httpx.post(url, json=body, headers=headers, timeout=10)
        # A missing envelope key is refused by the ladder, before any middleware.
        body, headers = modern_call(capabilities={}, tag="envelope")
        del body["params"]["_meta"][types.CLIENT_CAPABILITIES_META_KEY]
        bad_envelope = httpx.post(url, json=body, headers=headers, timeout=10)
    assert rpc(bad_parse)["error"]["code"] == types.INVALID_PARAMS
    assert rpc(bad_capabilities)["error"]["code"] == types.INVALID_PARAMS
    assert rpc(bad_envelope)["error"]["code"] == types.INVALID_PARAMS
    assert seen == [
        ("tools/call", "nested", pydantic.ValidationError.__name__),
        ("tools/call", "capabilities", pydantic.ValidationError.__name__),
    ]
    assert asker.events == []


# --- 30. the modern SDK client's retry -----------------------------------------------------------


async def test_the_sdk_clients_modern_retry() -> None:
    async def handler(ctx: ServerRequestContext[Any], params: types.CallToolRequestParams) -> Any:
        if params.request_state is None:
            return approval_input_required()
        return done("retried")

    async def callback(context: Any, params: types.ElicitRequestParams) -> types.ElicitResult:
        return types.ElicitResult(action="accept", content={"code": "K7QD"})

    from mcp import Client

    asker = Asker(handler)
    with running(asker) as url:
        async with Client(url, mode=MODERN, cache=None, elicitation_callback=callback) as client:
            result = await client.call_tool("send", {"b": 1, "a": "x"})
    assert result.content[0].text == "retried"  # type: ignore[union-attr]
    first, retry = [b for b in asker.bodies if b.get("method") == "tools/call"]
    assert first["id"] != retry["id"]
    assert retry["params"]["arguments"] == first["params"]["arguments"] == {"b": 1, "a": "x"}
    assert retry["params"]["requestState"] == HANDLE
    assert retry["params"]["inputResponses"] == {
        "zoeymcp-approval": {"action": "accept", "content": {"code": "K7QD"}}
    }


@pytest.mark.parametrize("failure", ["raise", "error_data"])
async def test_a_failing_callback_raises_locally_and_never_retries(failure: str) -> None:
    async def handler(ctx: ServerRequestContext[Any], params: types.CallToolRequestParams) -> Any:
        return approval_input_required()

    async def callback(context: Any, params: types.ElicitRequestParams) -> Any:
        if failure == "raise":
            raise RuntimeError("the callback broke")
        return types.ErrorData(code=types.INTERNAL_ERROR, message="no")

    from mcp import Client

    asker = Asker(handler)
    with running(asker) as url:
        async with Client(url, mode=MODERN, cache=None, elicitation_callback=callback) as client:
            if failure == "raise":
                with pytest.raises(ExceptionGroup) as raised:
                    await client.call_tool("send", {})
                assert isinstance(raised.value.exceptions[0], RuntimeError)
            else:
                with pytest.raises(MCPError, match=r"^no$"):
                    await client.call_tool("send", {})
    assert len([b for b in asker.bodies if b.get("method") == "tools/call"]) == 1


# --- 31. a response POST reaches only the session it names ---------------------------------------


async def test_a_response_post_reaches_only_its_own_session() -> None:
    async def handler(ctx: ServerRequestContext[Any], params: types.CallToolRequestParams) -> Any:
        return done((await ask(ctx, timeout=5)).action)

    asker = Asker(handler)
    with running(asker) as url:
        mine, other = legacy_session(url), legacy_session(url)
        async with legacy_call(url, mine) as (http, stream):
            request = await anext(stream)
            wrong = await answer(http, url, other, request["id"], {"action": "decline"})
            assert wrong.status_code == 202
            await anyio.sleep(0.3)
            assert asker.events == ["started"]  # the other session's answer went nowhere
            await answer(http, url, mine, request["id"], {"action": "accept"})
            final = await anext(stream)
    assert final["result"]["content"][0]["text"] == "accept"


# --- 35. how a shutdown cancels a handler, both ways (M4 design B.6) ------------------------------


class GracefulApp:
    """An app whose one request handler shields a long wait, recording when things happen."""

    def __init__(self) -> None:
        self.events: list[tuple[str, float]] = []

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            await receive()
            await send({"type": "lifespan.startup.complete"})
            await receive()
            self.events.append(("lifespan_shutdown", time.monotonic()))
            await send({"type": "lifespan.shutdown.complete"})
            return
        self.events.append(("started", time.monotonic()))
        with anyio.CancelScope(shield=True):
            await anyio.sleep(2.0)
        self.events.append(("handler_done", time.monotonic()))
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"done"})


def _get(url: str) -> None:
    with contextlib.suppress(httpx.HTTPError):
        httpx.get(url, timeout=10)


def test_uvicorns_graceful_cancel_is_native_and_goes_through_a_shield() -> None:
    # uvicorn ends request tasks still running at timeout_graceful_shutdown with asyncio's own
    # task.cancel(), which an anyio shield doesn't stop. So the gateway never runs a committed
    # call in the request's task (M4 design B.6): it runs in a task the gateway owns.
    app = GracefulApp()
    with serve(app, lifespan=True) as base:  # timeout_graceful_shutdown is 1 s there
        threading.Thread(target=_get, args=(base,), daemon=True).start()
        deadline = time.monotonic() + 5
        while not app.events and time.monotonic() < deadline:
            time.sleep(0.01)
    names = dict(app.events)
    assert "started" in names
    assert "handler_done" not in names  # cut inside its shield
    assert names["lifespan_shutdown"] - names["started"] < 2.0  # right after the grace


async def test_the_session_managers_exit_doesnt_reach_into_a_shield() -> None:
    finished: list[float] = []

    async def handler(ctx: ServerRequestContext[Any], params: types.CallToolRequestParams) -> Any:
        with anyio.CancelScope(shield=True):
            await anyio.sleep(1.5)
            finished.append(time.monotonic())
        return done("ok")

    asker = Asker(handler)
    with running(asker) as url:
        session = legacy_session(url)

        def call() -> None:
            with contextlib.suppress(httpx.HTTPError):
                httpx.post(url, json=call_body(), headers=session_headers(session), timeout=10)

        threading.Thread(target=call, daemon=True).start()
        with anyio.fail_after(5):
            while asker.events != ["started"]:
                await anyio.sleep(0.02)
    # Leaving the server ran the lifespan shutdown, whose manager.run() exit cancelled the
    # session's tasks; the legacy handler still finished inside its shield.
    assert len(finished) == 1
