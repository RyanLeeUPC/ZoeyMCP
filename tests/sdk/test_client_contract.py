"""SDK contract, client side: design K items 1 to 7, 13 and 15, against the fake upstream.

The client here is built the way the gateway's upstream side builds it (design F.2): an
``httpx2`` client with ``follow_redirects=False`` and ``trust_env=False``, the Streamable HTTP
transport, and an SDK ``Client`` with no callbacks. It also passes ``cache=None``, which F.2
doesn't say: the SDK's default response cache would answer a re-list from memory for as long as
the upstream's ``ttlMs`` asks (the cache test below).
"""

from __future__ import annotations

import copy
import logging
import time
from collections.abc import AsyncIterator, Callable, Iterator
from contextlib import AsyncExitStack, asynccontextmanager, contextmanager
from contextvars import Token
from dataclasses import dataclass, field
from typing import Any

import anyio
import httpx2
import mcp_types as types
import pytest
from mcp import Client, InputRequiredRoundsExceededError
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.exceptions import MCPDeprecationWarning, MCPError
from opentelemetry import context, trace
from opentelemetry.context import Context
from opentelemetry.trace import NonRecordingSpan, SpanContext, TraceFlags
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from tests.fakes.harness import serve
from tests.fakes.mcp_server import (
    BACK_CHANNELS,
    REQUEST_STATE,
    BackChannel,
    BackChannelAnswer,
    BackChannelStream,
    McpFake,
    Recorded,
)
from zoeymcp.common.canonical import dumps_canonical, loads_strict

pytestmark = pytest.mark.anyio

CLIENT_INFO = types.Implementation(name="zoeymcp-gateway", version="1")
LATEST_LEGACY = "2025-11-25"
# The server requests a legacy client can be sent, and the modern input requests.
ASKING: list[BackChannel] = [kind for kind in BACK_CHANNELS if kind != "state_only"]
REQUEST_METHODS: dict[BackChannel, str] = {
    "sampling": "sampling/createMessage",
    "elicit_form": "elicitation/create",
    "elicit_url": "elicitation/create",
    "roots": "roots/list",
}
# What the egress filter lets through (design F.2), so a new shape fails here first.
EGRESS_REQUESTS = frozenset(
    {"initialize", "server/discover", "tools/list", "tools/call", "subscriptions/listen", "ping"}
)
EGRESS_NOTIFICATIONS = frozenset({"notifications/initialized", "notifications/cancelled"})
EGRESS_CALL_PARAMS = frozenset({"name", "arguments", "_meta"})
EGRESS_META_KEYS = frozenset(
    {
        types.PROTOCOL_VERSION_META_KEY,
        types.CLIENT_CAPABILITIES_META_KEY,
        types.CLIENT_INFO_META_KEY,
        "progressToken",
    }
)
# Design F.2's header list, plus Cache-Control: the SDK sends "Cache-Control: no-store" on the
# legacy GET stream, so the egress filter has to allow it there.
EGRESS_HEADERS = frozenset(
    {
        "host",
        "accept",
        "accept-encoding",
        "connection",
        "content-type",
        "content-length",
        "user-agent",
        "mcp-protocol-version",
        "mcp-session-id",
        "mcp-method",
        "mcp-name",
        "last-event-id",
        "cache-control",
    }
)
TRACE_HEADERS = ("traceparent", "tracestate", "baggage")
TRACE_ID = "0af7651916cd43dd8448eb211c80319c"
# Every SDK interaction gets a deadline, so a behaviour change after a bump fails, not hangs.
DEADLINE = 60


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@contextmanager
def running(
    fake: McpFake | None = None, wrap: Callable[[ASGIApp], ASGIApp] | None = None
) -> Iterator[str]:
    """The fake's MCP endpoint URL while it runs."""
    fake = fake if fake is not None else McpFake()
    app: ASGIApp = fake.app()
    if wrap is not None:
        app = wrap(app)
    with serve(app, lifespan=True) as base:
        yield f"{base}{fake.path}"


def gateway_http(**options: Any) -> httpx2.AsyncClient:
    """An HTTP client set up as the gateway's upstream clients are (design F.2)."""
    timeout = httpx2.Timeout(10.0, read=30.0)
    return httpx2.AsyncClient(follow_redirects=False, trust_env=False, timeout=timeout, **options)


@asynccontextmanager
async def connect(
    url: str,
    mode: str = "auto",
    *,
    http: httpx2.AsyncClient | None = None,
    **options: Any,
) -> AsyncIterator[Client]:
    """An SDK client as the gateway builds one: no callbacks, no response cache."""
    with anyio.fail_after(DEADLINE):
        async with AsyncExitStack() as stack:
            if http is None:
                http = await stack.enter_async_context(gateway_http())
            transport = streamable_http_client(url, http_client=http, terminate_on_close=True)
            client = Client(transport, mode=mode, client_info=CLIENT_INFO, cache=None, **options)
            yield await stack.enter_async_context(client)


@asynccontextmanager
async def owned(url: str, mode: str = "auto") -> AsyncIterator[Client]:
    """A client opened and closed by an owner task of its own, as the gateway's pool does (F.4).

    The caller's calls come from other tasks, which aren't the owner's children. An error in
    the owner fails the caller's ``async with``.
    """
    clients: list[Client] = []
    opened = anyio.Event()
    finish = anyio.Event()

    async def owner() -> None:
        async with connect(url, mode) as client:
            clients.append(client)
            opened.set()
            await finish.wait()

    async with anyio.create_task_group() as group:
        group.start_soon(owner)
        await opened.wait()
        try:
            yield clients[0]
        finally:
            finish.set()


async def until(condition: Callable[[], bool], timeout: float = 5.0) -> None:
    with anyio.fail_after(timeout):
        while not condition():
            await anyio.sleep(0.02)


def get_stream_open(fake: McpFake) -> Callable[[], bool]:
    return lambda: any(item.method == "GET" and item.status == 200 for item in fake.received)


def text_of(result: types.CallToolResult) -> str:
    block = result.content[0]
    assert isinstance(block, types.TextContent)
    return block.text


def leaf(error: BaseException) -> BaseException:
    """The one exception inside nested single-member groups."""
    while isinstance(error, BaseExceptionGroup) and len(error.exceptions) == 1:
        error = error.exceptions[0]
    return error


def answers(record: Recorded) -> list[dict[str, Any]]:
    """The JSON-RPC messages the fake sent in answer to ``record``, as JSON or SSE."""
    body = bytes(record.response)
    if body.startswith(b"{"):
        return [loads_strict(body)]
    lines = [line[5:].strip() for line in body.splitlines() if line.startswith(b"data:")]
    return [loads_strict(line) for line in lines if line]


def metas(fake: McpFake) -> list[dict[str, Any]]:
    """The ``params._meta`` of every message the fake received that has one."""
    found = []
    for item in fake.received:
        meta = item.params.get("_meta")
        if isinstance(meta, dict):
            found.append(meta)
    return found


class Messages:
    """A message handler that keeps everything it is given."""

    def __init__(self) -> None:
        self.received: list[object] = []

    async def __call__(self, message: object) -> None:
        self.received.append(message)

    @property
    def methods(self) -> list[str]:
        return [m.method for m in self.received if isinstance(m, types.ServerNotification)]


@dataclass
class ExtraToolsFake(McpFake):
    """The fake with more tools listed after its own."""

    extra: list[dict[str, Any]] = field(default_factory=list)

    def tools_for(self, session_id: str | None, listing: int) -> list[dict[str, Any]]:
        return [*super().tools_for(session_id, listing), *copy.deepcopy(self.extra)]


@dataclass
class TtlFake(McpFake):
    """The fake with a cache lifetime on its listings, as a hostile upstream may ask for."""

    ttl_ms: int = 600_000

    def listing(self, session_id: str | None, cursor: Any) -> dict[str, Any]:
        return {**super().listing(session_id, cursor), "ttlMs": self.ttl_ms}


# --- 1. no capabilities ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("mode", "legacy_version"), [("auto", None), ("legacy", "2025-11-25"), ("legacy", "2025-06-18")]
)
async def test_a_client_with_no_callbacks_declares_no_capabilities(
    mode: str, legacy_version: str | None
) -> None:
    fake = McpFake(legacy_version=legacy_version)
    with running(fake) as url:
        async with connect(url, mode) as client:
            await client.list_tools()
            await client.call_tool("echo", {"text": "hi"})
            version = client.protocol_version
    if mode == "legacy":
        assert version == legacy_version
        [initialize] = fake.requests("initialize")
        assert initialize.params["capabilities"] == {}
        assert initialize.params["protocolVersion"] == LATEST_LEGACY
        assert metas(fake) == []
    else:
        assert fake.requests("initialize") == []
        assert len(metas(fake)) == len([item for item in fake.received if item.rpc_method])
        for meta in metas(fake):
            assert meta[types.CLIENT_CAPABILITIES_META_KEY] == {}
            assert types.LOG_LEVEL_META_KEY not in meta
    assert fake.requests("logging/setLevel") == []


async def answer_sampling(
    context: Any, params: types.CreateMessageRequestParams
) -> types.CreateMessageResult:
    content = types.TextContent(type="text", text="fake answer")
    return types.CreateMessageResult(role="assistant", content=content, model="fake-model")


async def answer_elicitation(context: Any, params: types.ElicitRequestParams) -> types.ElicitResult:
    return types.ElicitResult(action="decline")


async def answer_roots(context: Any) -> types.ListRootsResult:
    return types.ListRootsResult(roots=[])


async def log_nothing(params: types.LoggingMessageNotificationParams) -> None:
    """A logging callback, which is not an opt-in to log messages."""


@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_a_callback_is_what_declares_a_capability(mode: str) -> None:
    """The check above can see a declaration; a logging callback declares nothing."""
    fake = McpFake()
    with running(fake) as url:
        async with connect(url, mode, logging_callback=log_nothing) as client:
            await client.list_tools()
        async with connect(
            url,
            mode,
            sampling_callback=answer_sampling,
            elicitation_callback=answer_elicitation,
            list_roots_callback=answer_roots,
        ) as client:
            await client.list_tools()
    if mode == "legacy":
        declared = [item.params["capabilities"] for item in fake.requests("initialize")]
    else:
        declared = [
            fake.requests("tools/list")[index].params["_meta"][types.CLIENT_CAPABILITIES_META_KEY]
            for index in (0, 1)
        ]
        assert all(types.LOG_LEVEL_META_KEY not in meta for meta in metas(fake))
    assert declared[0] == {}
    assert sorted(declared[1]) == ["elicitation", "roots", "sampling"]


# --- the response cache (not in K; F.2 and F.5 depend on it) -----------------------------------


@pytest.mark.parametrize("cache", ["default", "none"])
async def test_only_cache_none_sends_every_re_list_upstream(cache: str) -> None:
    """With the default cache, a timer re-list (F.5) would read memory for as long as the
    upstream's ttlMs says, and a silent change would go unseen. F.2 must pass ``cache=None``."""
    fake = TtlFake()
    with running(fake) as url:
        async with gateway_http() as http:
            transport = streamable_http_client(url, http_client=http, terminate_on_close=True)
            if cache == "default":
                client = Client(transport, mode="auto", client_info=CLIENT_INFO)
            else:
                client = Client(transport, mode="auto", client_info=CLIENT_INFO, cache=None)
            with anyio.fail_after(DEADLINE):
                async with client:
                    for _ in range(3):
                        await client.list_tools()
    assert len(fake.requests("tools/list")) == (1 if cache == "default" else 3)


# --- 2. legacy server requests -----------------------------------------------------------------


@pytest.mark.parametrize("stream", ["call", "get"])
@pytest.mark.parametrize("kind", ASKING)
async def test_a_legacy_server_request_gets_an_error_answer(
    kind: BackChannel, stream: BackChannelStream
) -> None:
    fake = McpFake(back_channel=kind, back_channel_stream=stream)
    messages = Messages()
    with running(fake) as url:
        async with connect(url, "legacy", message_handler=messages) as client:
            await client.list_tools()
            await until(get_stream_open(fake))
            result = await client.call_tool("echo", {"text": "hi"})
    assert text_of(result) == "hi"
    assert fake.answers == [BackChannelAnswer(kind, stream, "error -32600")]
    [answer] = [item for item in fake.received if item.method == "POST" and item.rpc_method is None]
    message = answer.message
    # The shape the egress filter lets out: a JSON-RPC error and nothing else.
    assert sorted(message) == ["error", "id", "jsonrpc"]
    assert sorted(message["error"]) == ["code", "message"]
    assert message["error"]["code"] == types.INVALID_REQUEST
    asked = [
        sent
        for item in fake.received
        for sent in answers(item)
        if sent.get("method") == REQUEST_METHODS[kind]
    ]
    assert [request["id"] for request in asked] == [message["id"]]
    # Nothing about the request reached the client's handler.
    assert messages.received == []


# --- 3. modern input_required ------------------------------------------------------------------


@pytest.mark.parametrize("kind", ASKING)
async def test_a_modern_input_required_ends_the_call_with_a_typed_error(kind: BackChannel) -> None:
    fake = McpFake(back_channel=kind)
    with running(fake) as url:
        async with connect(url) as client:
            await client.list_tools()
            with pytest.raises(MCPError) as refused:
                await client.call_tool("echo", {"text": "hi"})
    assert refused.value.error.code == types.INVALID_REQUEST
    assert [call.retry for call in fake.calls] == [False]
    assert len(fake.requests("tools/call")) == 1


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason=(
        "SDK 2.3.0 retries a state-only input_required (requestState and no inputRequests) "
        "after a 50 ms backoff, with no callback involved. The fallback is ours: the egress "
        "filter blocks a tools/call carrying requestState (design F.2), and "
        "input_required_max_rounds=0 ends the call before any retry (the tests below)."
    ),
)
async def test_a_state_only_input_required_is_not_retried() -> None:
    fake = McpFake(back_channel="state_only")
    outcome: list[object] = []
    with running(fake) as url:
        async with connect(url) as client:
            await client.list_tools()
            try:
                outcome.append(await client.call_tool("echo", {"text": "hi"}))
            except MCPError as error:
                outcome.append(error)
    assert [call.retry for call in fake.calls] == [False]
    assert isinstance(outcome[0], MCPError)


async def test_the_state_only_retry_carries_the_request_state_and_nothing_else() -> None:
    """Today's retry, which the egress filter's requestState rule has to match (F.2)."""
    fake = McpFake(back_channel="state_only")
    with running(fake) as url:
        async with connect(url) as client:
            await client.list_tools()
            await client.call_tool("echo", {"text": "hi"})
    assert [call.retry for call in fake.calls] == [False, True]
    first, retry = fake.requests("tools/call")
    assert sorted(first.params) == ["_meta", "arguments", "name"]
    assert sorted(retry.params) == ["_meta", "arguments", "name", "requestState"]
    assert retry.params["requestState"] == REQUEST_STATE
    assert retry.params["arguments"] == first.params["arguments"]


@pytest.mark.parametrize("kind", BACK_CHANNELS)
async def test_no_input_rounds_ends_any_input_required_before_a_retry(kind: BackChannel) -> None:
    fake = McpFake(back_channel=kind)
    with running(fake) as url:
        async with connect(url, input_required_max_rounds=0) as client:
            await client.list_tools()
            with pytest.raises(InputRequiredRoundsExceededError):
                await client.call_tool("echo", {"text": "hi"})
            # The connection is still good.
            assert text_of(await client.call_tool("add", {"a": 1, "b": 2})) == "3"
    assert [(call.name, call.retry) for call in fake.calls] == [("echo", False), ("add", False)]


# --- 4. cancellation ---------------------------------------------------------------------------


@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_cancelling_the_calling_task_cancels_upstream(mode: str) -> None:
    """The calling task isn't the owner's child, as with the gateway's request tasks (F.4)."""
    fake = McpFake()
    with running(fake) as url:
        async with owned(url, mode) as client:
            await client.list_tools()

            async def call() -> None:
                await client.call_tool("slow", {"steps": 200, "interval": 0.05})

            with anyio.fail_after(20):
                async with anyio.create_task_group() as group:
                    group.start_soon(call)
                    await until(lambda: [c.name for c in fake.calls] == ["slow"])
                    left = time.monotonic()
                    group.cancel_scope.cancel()
                assert await anyio.to_thread.run_sync(fake.cancelled.wait, 5)
            # The client is still usable after a cancelled call.
            assert text_of(await client.call_tool("echo", {"text": "after"})) == "after"
    [cancelled] = fake.cancellations
    assert cancelled - left < 2
    call_record = fake.requests("tools/call")[0]
    notices = fake.requests("notifications/cancelled")
    if mode == "auto":
        # The modern wire has no client notifications: closing the stream is the signal.
        assert call_record.disconnected
        assert notices == []
    else:
        [notice] = notices
        assert notice.params["requestId"] == call_record.message["id"]


# --- 5. concurrency ----------------------------------------------------------------------------


@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_concurrent_calls_from_several_tasks_on_one_client(mode: str) -> None:
    fake = McpFake()
    results: dict[int, str] = {}
    finished: list[int] = []
    with running(fake) as url:
        async with owned(url, mode) as client:
            await client.list_tools()

            async def call(number: int) -> None:
                if number == 0:
                    result = await client.call_tool("slow", {"steps": 4, "interval": 0.25})
                else:
                    result = await client.call_tool("echo", {"text": f"call {number}"})
                results[number] = text_of(result)
                finished.append(number)

            with anyio.fail_after(20):
                async with anyio.create_task_group() as group:
                    for number in range(8):
                        group.start_soon(call, number)
    assert results == {0: "done after 4 steps", **{n: f"call {n}" for n in range(1, 8)}}
    # The slow call didn't hold the others up.
    assert finished[-1] == 0
    calls = fake.requests("tools/call")
    assert len({item.message["id"] for item in calls}) == 8
    if mode == "legacy":
        assert len({item.session_id for item in calls}) == 1


# --- 6. a legacy session that expired ----------------------------------------------------------


async def test_a_legacy_404_is_an_error_and_the_response_hook_sees_it() -> None:
    fake = McpFake(session_404_after=1)
    seen: list[tuple[str, int, str | None]] = []

    async def hook(response: httpx2.Response) -> None:
        request = response.request
        seen.append((request.method, response.status_code, request.headers.get("mcp-session-id")))

    with running(fake) as url:
        async with (
            gateway_http(event_hooks={"response": [hook]}) as http,
            connect(url, "legacy", http=http) as client,
        ):
            await client.list_tools()
            await client.call_tool("echo", {"text": "1"})
            with pytest.raises(MCPError) as expired:
                await client.call_tool("echo", {"text": "2"})
            # The SDK doesn't start a new session by itself.
            with pytest.raises(MCPError):
                await client.call_tool("echo", {"text": "3"})
    assert (expired.value.error.code, expired.value.error.message) == (
        types.INVALID_REQUEST,
        "Session not found",
    )
    [initialize] = fake.requests("initialize")
    session = initialize.issued_session_id
    assert session is not None
    assert [item.status for item in fake.requests("tools/call")] == [200, 404, 404]
    assert [item.session_id for item in fake.requests("tools/call")] == [session] * 3
    assert seen.count(("POST", 404, session)) == 2


class SessionSwap:
    """Wraps the fake: once ``on``, every answer names another session id."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        self.on = False

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if not self.on or scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def swapped(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = [
                    (key, b"swapped-session" if key.lower() == b"mcp-session-id" else value)
                    for key, value in message.get("headers", [])
                ]
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, swapped)


async def test_a_new_session_id_mid_session_is_seen_only_by_the_response_hook() -> None:
    """The SDK keeps its first session id, so noticing a new one is the hook's job (F.4)."""
    fake = McpFake()
    swap: SessionSwap | None = None
    answered: list[str | None] = []

    def wrap(app: ASGIApp) -> ASGIApp:
        nonlocal swap
        swap = SessionSwap(app)
        return swap

    async def hook(response: httpx2.Response) -> None:
        if response.request.method == "POST":
            answered.append(response.headers.get("mcp-session-id"))

    with running(fake, wrap) as url:
        assert swap is not None
        async with (
            gateway_http(event_hooks={"response": [hook]}) as http,
            connect(url, "legacy", http=http) as client,
        ):
            await client.list_tools()
            swap.on = True
            await client.call_tool("echo", {"text": "1"})
            await client.call_tool("echo", {"text": "2"})
            swap.on = False
    session = fake.requests("initialize")[0].issued_session_id
    assert answered[-2:] == ["swapped-session", "swapped-session"]
    assert [item.session_id for item in fake.requests("tools/call")] == [session, session]


# --- 7. schemas as parsed ----------------------------------------------------------------------


ODD_TOOL: dict[str, Any] = {
    "name": "shapes",
    "description": "Takes odd shapes.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "region": {"type": "string", "x-mcp-header": "Region"},
            "note": {"type": ["string", "null"], "default": None, "description": None},
            "ratio": {"type": "number", "minimum": 0.0, "maximum": 1.5, "multipleOf": 0.25},
            "count": {"type": "integer", "const": 3, "examples": [1, 2.0, None]},
            "label": {"type": "string", "enum": ["caf\u00e9", "na\u00efve", "\u65e5\u672c", None]},
        },
        "required": ["region"],
        "additionalProperties": False,
        "x-vendor": {"nested": [None, {"deep": None}], "big": 9007199254740991},
    },
    "outputSchema": {
        "type": "object",
        "properties": {"value": {"default": None, "minimum": 1.0}},
        "x-extra": None,
    },
}
# An x-mcp-header on an array property, which 2026-07-28 clients must drop the tool for.
BAD_HEADER_TOOL: dict[str, Any] = {
    "name": "tagged",
    "description": "Takes tags.",
    "inputSchema": {
        "type": "object",
        "properties": {"tags": {"type": "array", "x-mcp-header": "Tags"}},
    },
}


@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_schemas_are_the_parsed_json_unchanged(mode: str) -> None:
    fake = ExtraToolsFake(extra=[ODD_TOOL])
    with running(fake) as url:
        async with connect(url, mode) as client:
            tools = (await client.list_tools()).tools
    [tool] = [tool for tool in tools if tool.name == "shapes"]
    assert tool.input_schema == ODD_TOOL["inputSchema"]
    assert tool.output_schema == ODD_TOOL["outputSchema"]
    # Exact, down to an integer staying an integer and a float a float.
    assert dumps_canonical(tool.input_schema) == dumps_canonical(ODD_TOOL["inputSchema"])
    assert dumps_canonical(tool.output_schema) == dumps_canonical(ODD_TOOL["outputSchema"])
    # And as the fake sent them.
    [listing] = fake.requests("tools/list")
    [answer] = answers(listing)
    [sent] = [item for item in answer["result"]["tools"] if item["name"] == "shapes"]
    assert dumps_canonical(tool.input_schema) == dumps_canonical(sent["inputSchema"])


@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_a_tool_with_an_invalid_x_mcp_header_is_dropped_from_modern_listings(
    mode: str,
) -> None:
    """The gateway sees such a tool as missing on a modern upstream, and as listed on legacy."""
    fake = ExtraToolsFake(extra=[BAD_HEADER_TOOL])
    with running(fake) as url:
        async with connect(url, mode) as client:
            names = [tool.name for tool in (await client.list_tools()).tools]
    assert ("tagged" in names) is (mode == "legacy")
    assert "lookup" in names


# --- 13. redirects -----------------------------------------------------------------------------


class Watching(httpx2.AsyncBaseTransport):
    """A wrapping transport, where the gateway's egress filter sits. It can refuse a request.

    It records the origin as well as the path: the SDK follows an http-to-https upgrade on the
    same host, so the egress filter has to check both.
    """

    def __init__(self, refuse: bool = False) -> None:
        self.inner = httpx2.AsyncHTTPTransport()
        self.refuse = refuse
        self.sent: list[tuple[str, str, str]] = []
        self.origin: str | None = None

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        url = request.url
        origin = f"{url.scheme}://{url.host}:{url.port}"
        self.sent.append((request.method, origin, url.path))
        if self.origin is None:
            self.origin = origin
        if self.refuse and (origin, url.path) != (self.origin, "/mcp"):
            raise RuntimeError("upstream_request_blocked")
        return await self.inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self.inner.aclose()


def other_paths(fake: McpFake) -> list[tuple[str, str]]:
    return [(item.method, item.path) for item in fake.received if item.path != fake.path]


@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_a_same_origin_307_is_followed_despite_follow_redirects_false(mode: str) -> None:
    """The reason the gateway needs its own egress filter (G14)."""
    fake = McpFake(redirect="/mail/send")
    watching = Watching()
    with running(fake) as url:
        async with (
            gateway_http(transport=watching) as http,
            connect(url, mode, http=http) as client,
        ):
            await client.list_tools()
            with pytest.raises(MCPError):
                await client.call_tool("echo", {"text": "hi"})
    assert other_paths(fake) == [("POST", "/mail/send")]
    # The follow goes through the client's transport, where a filter can stop it.
    assert ("POST", watching.origin, "/mail/send") in watching.sent


@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_a_redirect_to_another_origin_is_not_followed(mode: str) -> None:
    # The other origin is a second local server: another port, so no DNS is involved.
    elsewhere = McpFake(path="/other")
    watching = Watching()
    with running(elsewhere) as other_url:
        fake = McpFake(redirect=other_url)
        with running(fake) as url:
            async with (
                gateway_http(transport=watching) as http,
                connect(url, mode, http=http) as client,
            ):
                await client.list_tools()
                with pytest.raises(MCPError) as refused:
                    await client.call_tool("echo", {"text": "hi"})
                assert text_of(await client.call_tool("add", {"a": 1, "b": 1})) == "2"
    assert refused.value.error.code == types.INVALID_REQUEST
    assert "not followed" in refused.value.error.message
    assert elsewhere.received == []
    assert {(origin, path) for _, origin, path in watching.sent} == {(watching.origin, "/mcp")}
    assert watching.origin is not None
    assert url.startswith(watching.origin)


@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_max_redirects_zero_stops_the_follow_and_keeps_the_connection(mode: str) -> None:
    fake = McpFake(redirect="/mail/send")
    with running(fake) as url:
        async with gateway_http(max_redirects=0) as http, connect(url, mode, http=http) as client:
            await client.list_tools()
            with pytest.raises(MCPError) as refused:
                await client.call_tool("echo", {"text": "hi"})
            assert text_of(await client.call_tool("add", {"a": 1, "b": 1})) == "2"
    assert refused.value.error.code == types.INVALID_REQUEST
    assert "not followed" in refused.value.error.message
    assert other_paths(fake) == []


@pytest.mark.parametrize("mode", ["auto", "legacy"])
@pytest.mark.parametrize("where", ["transport", "hook"])
async def test_a_refusal_raised_in_the_http_client_ends_the_connection(
    mode: str, where: str
) -> None:
    """The follow is stopped; the owner task gets the refusal and callers "Connection closed"."""
    fake = McpFake(redirect="/mail/send")

    async def refuse_redirects(response: httpx2.Response) -> None:
        if response.is_redirect:
            raise RuntimeError("upstream_redirect_refused")

    if where == "transport":
        http = gateway_http(transport=Watching(refuse=True))
    else:
        http = gateway_http(event_hooks={"response": [refuse_redirects]})
    opened = anyio.Event()
    finish = anyio.Event()
    clients: list[Client] = []
    owner_errors: list[BaseException] = []
    call_errors: list[BaseException] = []

    async def owner(url: str) -> None:
        try:
            async with http, connect(url, mode, http=http) as client:
                clients.append(client)
                opened.set()
                await finish.wait()
        except BaseException as error:
            owner_errors.append(error)
            opened.set()

    with running(fake) as url:
        async with anyio.create_task_group() as group:
            group.start_soon(owner, url)
            await opened.wait()
            [client] = clients
            await client.list_tools()
            for name, arguments in (("echo", {"text": "hi"}), ("add", {"a": 1, "b": 1})):
                with anyio.fail_after(10), pytest.raises(MCPError) as raised:
                    await client.call_tool(name, arguments)
                call_errors.append(raised.value)
            finish.set()
    assert other_paths(fake) == []
    assert [error.error.code for error in call_errors if isinstance(error, MCPError)] == [
        types.CONNECTION_CLOSED,
        types.CONNECTION_CLOSED,
    ]
    [error] = owner_errors
    refusal = leaf(error)
    assert isinstance(refusal, RuntimeError)
    expected = "upstream_request_blocked" if where == "transport" else "upstream_redirect_refused"
    assert str(refusal) == expected


# --- 15. nothing beyond the allowlists ---------------------------------------------------------


@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_nothing_beyond_the_egress_allowlists_is_sent(mode: str) -> None:
    fake = McpFake()
    steps: list[float] = []

    async def on_progress(progress: float, total: float | None, message: str | None) -> None:
        steps.append(progress)

    with running(fake) as url:
        async with connect(url, mode) as client:
            await client.list_tools()
            await client.call_tool("echo", {"text": "hi"}, progress_callback=on_progress)
            await client.call_tool("lookup", {"region": "eu"})
            await client.call_tool(
                "slow", {"steps": 2, "interval": 0}, progress_callback=on_progress
            )
            if mode == "legacy":
                # Modern has no ping (2026-07-28); the watcher (F.5) listens instead.
                with pytest.warns(MCPDeprecationWarning):
                    await client.send_ping()
            else:
                async with client.listen(tools_list_changed=True):
                    pass
            async with anyio.create_task_group() as group:
                group.start_soon(client.call_tool, "slow", {"steps": 100, "interval": 0.05})
                await until(lambda: [c.name for c in fake.calls].count("slow") == 2)
                group.cancel_scope.cancel()
            assert await anyio.to_thread.run_sync(fake.cancelled.wait, 5)
    assert steps == [0, 1]
    assert fake.received
    for item in fake.received:
        names = {key.lower() for key, _ in item.headers}
        assert names - EGRESS_HEADERS <= {"mcp-param-region"}, item
        assert not any(name in names for name in TRACE_HEADERS)
        if "cache-control" in names:
            assert (item.method, item.header("cache-control")) == ("GET", "no-store")
        if "mcp-param-region" in names:
            lookup = (item.rpc_method, item.params.get("name"), item.header("mcp-param-region"))
            assert lookup == ("tools/call", "lookup", "eu")
        assert set(item.meta_keys) <= EGRESS_META_KEYS, item
        if item.method == "POST":
            assert is_egress_shape(item), item
    regions = [item for item in fake.received if item.header("mcp-param-region") is not None]
    # Mcp-Param-* headers are modern only.
    assert len(regions) == (1 if mode == "auto" else 0)
    sent = {item.rpc_method for item in fake.received if item.rpc_method}
    expected = {"tools/list", "tools/call"}
    if mode == "legacy":
        expected |= {"initialize", "notifications/initialized", "notifications/cancelled", "ping"}
    else:
        expected |= {"server/discover", "subscriptions/listen"}
    assert sent == expected


def is_egress_shape(item: Recorded) -> bool:
    """One of the POST body shapes the egress filter allows (design F.2)."""
    message = item.message
    if not isinstance(message, dict):
        return False
    method = message.get("method")
    if method is None:
        return "error" in message or message.get("result") == {}
    allowed = EGRESS_REQUESTS if "id" in message else EGRESS_NOTIFICATIONS
    if method not in allowed:
        return False
    params = message.get("params", {})
    if method == "tools/call" and not set(params) <= EGRESS_CALL_PARAMS:
        return False
    if method == "initialize" and params.get("capabilities") != {}:
        return False
    declared: object = params.get("_meta", {}).get(types.CLIENT_CAPABILITIES_META_KEY, {})
    return declared == {}


def traced() -> Token[Context]:
    """Make a valid span context current, as a server's tracing middleware does."""
    span = SpanContext(
        trace_id=0x0AF7651916CD43DD8448EB211C80319C,
        span_id=0xB7AD6B7169203331,
        is_remote=True,
        trace_flags=TraceFlags(TraceFlags.SAMPLED),
    )
    return context.attach(trace.set_span_in_context(NonRecordingSpan(span)))


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason=(
        "SDK 2.3.0 injects W3C trace context into every request's _meta when a valid span "
        "context is current, even with only the no-op OpenTelemetry API installed. The "
        "fallback is ours: the egress filter's _meta allowlist has no traceparent (F.2), and "
        "the gateway's server drops the SDK's OpenTelemetryMiddleware, which would make an "
        "agent's traceparent current (test_server_contract.py)."
    ),
)
@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_no_traceparent_inside_a_traced_context(mode: str) -> None:
    fake = McpFake()
    with running(fake) as url:
        async with connect(url, mode) as client:
            token = traced()
            try:
                await client.call_tool("echo", {"text": "hi"})
            finally:
                context.detach(token)
    assert all("traceparent" not in meta for meta in metas(fake))


@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_inside_a_traced_context_the_sdk_adds_a_traceparent_meta_key_only(mode: str) -> None:
    """What the egress filter has to strip or block today: one ``_meta`` key, no header."""
    fake = McpFake()
    with running(fake) as url:
        async with connect(url, mode) as client:
            token = traced()
            try:
                await client.list_tools()
                await client.call_tool("echo", {"text": "hi"})
            finally:
                context.detach(token)
    inside = [item for item in fake.received if item.rpc_method in ("tools/list", "tools/call")]
    assert [item.rpc_method for item in inside] == ["tools/list", "tools/call"]
    for item in fake.received:
        assert {key.lower() for key, _ in item.headers} <= EGRESS_HEADERS, item
    for item in inside:
        assert set(item.meta_keys) - EGRESS_META_KEYS == {"traceparent"}, item
        assert item.params["_meta"]["traceparent"].split("-")[1] == TRACE_ID


# --- logging (not in K; design M says session ids are never logged) ----------------------------


async def test_the_client_logs_its_session_id_and_a_redirects_location(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The SDK's own loggers carry a session id and an upstream's Location, so the gateway has to
    silence or filter the ``mcp`` loggers (G20)."""
    caplog.set_level(logging.DEBUG, logger="mcp")
    fake = McpFake(redirect="/mail/send?fake-query=1")
    with running(fake) as url:
        async with (
            gateway_http(max_redirects=0) as http,
            connect(url, "legacy", http=http) as client,
        ):
            await client.list_tools()
            with pytest.raises(MCPError):
                await client.call_tool("echo", {"text": "hi"})
    session = fake.requests("initialize")[0].issued_session_id
    assert session is not None
    logged = [r for r in caplog.records if r.name.startswith("mcp.")]
    infos = [r.getMessage() for r in logged if r.levelno == logging.INFO]
    warnings = [r.getMessage() for r in logged if r.levelno >= logging.WARNING]
    assert f"Received session ID: {session}" in infos
    [redirect] = [message for message in warnings if "/mail/send" in message]
    assert redirect.startswith(f"Redirect to {url.removesuffix(fake.path)}/mail/send not followed")
    # The query is dropped from the message.
    assert not any("fake-query" in r.getMessage() for r in logged)
