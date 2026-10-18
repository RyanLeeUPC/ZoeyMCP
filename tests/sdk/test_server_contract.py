"""SDK contract, server side: design K items 8 to 12 and 14.

The server here is shaped as the gateway's client-facing side is (design E.1): one low-level
``Server`` with only the tools handlers, ``subscriptions/listen`` and ``get_tool_input_schema``,
behind one ``StreamableHTTPSessionManager``. A small ASGI layer stands in for the gateway's
admission glue: it names the client from a test header (``scope["user"]`` and a contextvar), and
nothing else. Agents are the SDK client and raw ``httpx``. The fake upstream serves as the
projections' source and as the upstream for the trace context test.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Coroutine, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, TypeVar

import anyio
import httpx
import mcp_types as types
import pytest
from mcp.server import Server
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken
from mcp.server.context import CallNext, HandlerResult, ServerRequestContext
from mcp.server.lowlevel.server import NotificationOptions
from mcp.server.models import InitializationOptions
from mcp.server.session import ServerSession
from mcp.server.streamable_http_manager import (
    DEFAULT_MAX_REQUEST_BODY_SIZE,
    StreamableHTTPSessionManager,
)
from mcp.server.subscriptions import InMemorySubscriptionBus, ListenHandler, ToolsListChanged
from mcp.server.transport_security import TransportSecuritySettings
from mcp_types.version import MODERN_PROTOCOL_VERSIONS
from starlette.datastructures import Headers
from starlette.requests import Request
from starlette.types import Message, Receive, Scope, Send

from tests.fakes.harness import serve
from tests.fakes.mcp_server import McpFake, base_tools
from zoeymcp.common.canonical import dumps_canonical, loads_strict

from .test_client_contract import Messages, connect, gateway_http, text_of, until

pytestmark = pytest.mark.anyio

T = TypeVar("T")

LEGACY = "2025-11-25"
MODERN = MODERN_PROTOCOL_VERSIONS[-1]
ACCEPT = {"accept": "application/json, text/event-stream"}
CLIENT_HEADER = "x-test-client"
REQUEST_HEADER = "x-test-request"
PATH = "/s/example/mcp"
TRACEPARENT = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
# What the gateway's glue sets for each request: (client, request), here from test headers.
CURRENT: ContextVar[tuple[str | None, str | None]] = ContextVar(
    "zoeymcp_sdk_contract", default=(None, None)
)

# A projection with every kind of value G.1 keeps: nulls and floats inside schemas, non-ASCII
# text, an x-mcp-header, annotations, an output schema.
GOLDEN: dict[str, Any] = {
    "name": "golden.tool-1",
    "title": "Golden \u00e9t\u00e9",
    "description": "Fixed wire JSON: caf\u00e9, \u65e5\u672c, and a \\ backslash.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "region": {"type": "string", "x-mcp-header": "Region"},
            "note": {"type": ["string", "null"], "default": None},
            "ratio": {"type": "number", "minimum": 0.0, "maximum": 2.5},
            "count": {"type": "integer", "enum": [1, 2, 3], "default": 1},
            "nested": {
                "type": "object",
                "properties": {"flag": {"type": "boolean", "description": None}},
                "required": ["flag"],
            },
        },
        "required": ["region", "count"],
        "additionalProperties": False,
    },
    "outputSchema": {
        "type": "object",
        "properties": {"total": {"type": "number", "default": 1.5}, "none": {"const": None}},
    },
    "annotations": {
        "title": "Golden",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
}


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class ListChangedServer(Server[Any]):
    """A low-level server whose legacy handshake also advertises ``tools.listChanged``."""

    def create_initialization_options(
        self,
        notification_options: NotificationOptions | None = None,
        experimental_capabilities: dict[str, dict[str, Any]] | None = None,
        extensions: dict[str, dict[str, Any]] | None = None,
    ) -> InitializationOptions:
        return super().create_initialization_options(
            NotificationOptions(tools_changed=True), experimental_capabilities, extensions
        )


@dataclass
class Seen:
    """One handler run: the method, the contextvar's value, and the carrying request's header."""

    method: str
    current: tuple[str | None, str | None]
    request: str | None


class Shaped:
    """The gateway's client-facing server, without its own checks, as an ASGI app."""

    def __init__(
        self,
        projections: list[dict[str, Any]] | None = None,
        *,
        security: TransportSecuritySettings | None = None,
        body_limit: int = DEFAULT_MAX_REQUEST_BODY_SIZE,
        idle: float | None = 1800,
        max_sessions: int | None = None,
        otel: bool = False,
        list_changed: bool = True,
        upstream: str | None = None,
    ) -> None:
        self.projections = projections if projections is not None else base_tools()
        self.upstream = upstream
        self.seen: list[Seen] = []
        self.lookups: list[tuple[str, tuple[str | None, str | None]]] = []
        self.sessions: dict[str, ServerSession] = {}
        self.buses: dict[str | None, InMemorySubscriptionBus] = {}
        self.listeners: dict[str | None, ListenHandler] = {}
        self.statuses: list[tuple[str, int]] = []
        self.loop: asyncio.AbstractEventLoop | None = None
        server_class = ListChangedServer if list_changed else Server
        self.server: Server[Any] = server_class(
            "zoeymcp-gateway",
            version="1",
            on_list_tools=self._list,
            on_call_tool=self._call,
            on_subscriptions_listen=self._listen,
            get_tool_input_schema=self._input_schema,
        )
        if not otel:
            self.server.middleware = []
        self.manager = StreamableHTTPSessionManager(
            self.server,
            json_response=False,
            security_settings=security,
            max_request_body_size=body_limit,
            session_idle_timeout=idle,
            max_sessions=max_sessions,
        )

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
        headers = Headers(scope=scope)
        client = headers.get(CLIENT_HEADER)
        if client is not None:
            # Named after the client, never the token (design E.2).
            scope["user"] = AuthenticatedUser(AccessToken(token="", client_id=client, scopes=[]))
        token = CURRENT.set((client, headers.get(REQUEST_HEADER)))
        try:
            await self.manager.handle_request(scope, receive, self._watch(scope, send))
        finally:
            CURRENT.reset(token)

    def _watch(self, scope: Scope, send: Send) -> Send:
        async def watched(message: Message) -> None:
            if message["type"] == "http.response.start":
                self.statuses.append((scope["method"], message["status"]))
            await send(message)

        return watched

    async def run(self, coroutine: Coroutine[Any, Any, T]) -> T:
        """Run ``coroutine`` on the server's event loop, as the gateway's own tasks would."""
        assert self.loop is not None
        return await asyncio.wrap_future(asyncio.run_coroutine_threadsafe(coroutine, self.loop))

    def _note(self, ctx: ServerRequestContext[Any], method: str) -> None:
        request = ctx.request if isinstance(ctx.request, Request) else None
        header = request.headers.get(REQUEST_HEADER) if request is not None else None
        self.seen.append(Seen(method, CURRENT.get(), header))
        session_id = request.headers.get("mcp-session-id") if request is not None else None
        if session_id is not None:
            self.sessions.setdefault(session_id, ctx.session)

    async def _list(
        self, ctx: ServerRequestContext[Any], params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        self._note(ctx, "tools/list")
        tools = [types.Tool.model_validate(projection) for projection in self.projections]
        return types.ListToolsResult(tools=tools, ttl_ms=60_000, cache_scope="private")

    async def _call(
        self, ctx: ServerRequestContext[Any], params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        self._note(ctx, "tools/call")
        if params.name == "relay" and self.upstream is not None:
            async with connect(self.upstream) as upstream:
                return await upstream.call_tool("echo", {"text": "relayed"})
        client, request = CURRENT.get()
        text = f"{params.name} for {client} in {request}"
        return types.CallToolResult(content=[types.TextContent(type="text", text=text)])

    async def _listen(
        self, ctx: ServerRequestContext[Any], params: types.SubscriptionsListenRequestParams
    ) -> types.SubscriptionsListenResult:
        client, _ = CURRENT.get()
        bus = self.buses.setdefault(client, InMemorySubscriptionBus())
        handler = self.listeners.setdefault(client, ListenHandler(bus))
        return await handler(ctx, params)

    def _input_schema(self, name: str) -> dict[str, Any] | None:
        self.lookups.append((name, CURRENT.get()))
        for projection in self.projections:
            if projection["name"] == name:
                schema = projection["inputSchema"]
                return schema if isinstance(schema, dict) else None
        return None


@contextmanager
def running(shaped: Shaped) -> Iterator[str]:
    """The shaped server's MCP URL while it runs."""
    with serve(shaped, lifespan=True) as base:
        yield f"{base}{PATH}"


def wire(
    client: str | None, request: str | None = None, extra: dict[str, str] | None = None
) -> dict[str, str]:
    headers = dict(ACCEPT)
    if client is not None:
        headers[CLIENT_HEADER] = client
    if request is not None:
        headers[REQUEST_HEADER] = request
    return {**headers, **(extra or {})}


def initialize_body() -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": LEGACY,
            "capabilities": {},
            "clientInfo": {"name": "agent", "version": "1"},
        },
    }


def legacy_init(
    url: str, client: str | None = "a", extra: dict[str, str] | None = None
) -> httpx.Response:
    return httpx.post(url, json=initialize_body(), headers=wire(client, extra=extra), timeout=10)


def legacy_session(url: str, client: str | None = "a") -> str:
    """A raw legacy session for ``client``, with no GET stream. Returns its id."""
    response = legacy_init(url, client)
    assert response.status_code == 200, response.text
    session = response.headers["mcp-session-id"]
    initialized = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    headers = wire(client, extra={"mcp-session-id": session, "mcp-protocol-version": LEGACY})
    assert httpx.post(url, json=initialized, headers=headers, timeout=10).status_code == 202
    return session


def legacy_post(
    url: str,
    session: str,
    method: str,
    params: dict[str, Any] | None = None,
    client: str | None = "a",
) -> httpx.Response:
    body = {"jsonrpc": "2.0", "id": 2, "method": method, "params": params or {}}
    headers = wire(client, extra={"mcp-session-id": session, "mcp-protocol-version": LEGACY})
    return httpx.post(url, json=body, headers=headers, timeout=10)


def modern_body(
    method: str, params: dict[str, Any] | None = None, meta: dict[str, Any] | None = None
) -> dict[str, Any]:
    full_meta = {
        types.PROTOCOL_VERSION_META_KEY: MODERN,
        types.CLIENT_CAPABILITIES_META_KEY: {},
        **(meta or {}),
    }
    return {
        "jsonrpc": "2.0",
        "id": 7,
        "method": method,
        "params": {**(params or {}), "_meta": full_meta},
    }


def modern_headers(
    method: str, params: dict[str, Any] | None = None, client: str | None = "a"
) -> dict[str, str]:
    headers = wire(client, extra={"mcp-protocol-version": MODERN, "mcp-method": method})
    if params is not None and "name" in params:
        headers["mcp-name"] = params["name"]
    return headers


def modern_post(
    url: str,
    method: str,
    params: dict[str, Any] | None = None,
    *,
    client: str | None = "a",
    extra: dict[str, str] | None = None,
    meta: dict[str, Any] | None = None,
) -> httpx.Response:
    headers = {**modern_headers(method, params, client), **(extra or {})}
    return httpx.post(url, json=modern_body(method, params, meta), headers=headers, timeout=10)


def rpc_messages(response: httpx.Response) -> list[Any]:
    """The JSON-RPC messages in a response, JSON or SSE."""
    if response.headers.get("content-type", "").startswith("application/json"):
        return [loads_strict(response.content)]
    lines = [line[5:].strip() for line in response.text.splitlines() if line.startswith("data:")]
    return [loads_strict(line) for line in lines if line]


def rpc_result(response: httpx.Response) -> dict[str, Any]:
    [message] = rpc_messages(response)
    assert "result" in message, message
    result = message["result"]
    assert isinstance(result, dict)
    return result


# --- 8. the wire tools/list is the projection --------------------------------------------------


@pytest.mark.parametrize("era", ["legacy", "modern"])
async def test_the_wire_tool_list_is_the_projection(era: str) -> None:
    projections = [*base_tools(), GOLDEN]
    shaped = Shaped(projections)
    with running(shaped) as url:
        if era == "legacy":
            session = legacy_session(url)
            response = legacy_post(url, session, "tools/list")
        else:
            response = modern_post(url, "tools/list")
    assert response.status_code == 200
    result = rpc_result(response)
    tools = result["tools"]
    assert [dumps_canonical(tool) for tool in tools] == [dumps_canonical(p) for p in projections]
    if era == "legacy":
        assert set(result) == {"tools"}
    else:
        assert set(result) == {"tools", "ttlMs", "cacheScope", "resultType", "_meta"}
        assert (result["ttlMs"], result["cacheScope"], result["resultType"]) == (
            60_000,
            "private",
            "complete",
        )
        stamp = {"name": "zoeymcp-gateway", "version": "1"}
        assert result["_meta"] == {types.SERVER_INFO_META_KEY: stamp}


def test_the_projections_are_valid_wire_json() -> None:
    """The golden projection survives the strict parser, so the comparison above is exact."""
    text = json.dumps(GOLDEN)
    assert dumps_canonical(loads_strict(text)) == dumps_canonical(GOLDEN)
    assert isinstance(GOLDEN["inputSchema"]["properties"]["ratio"]["minimum"], float)


async def server_info_from_path(
    ctx: ServerRequestContext[Any], call_next: CallNext
) -> HandlerResult:
    """Names the server after its path, as E.4 asks of the one shared ``Server``."""
    result = await call_next(ctx)
    request = ctx.request
    if not isinstance(request, Request) or not isinstance(result, dict):
        return result
    info = {"name": f"zoeymcp/{request.url.path.split('/')[2]}", "version": "1"}
    if "serverInfo" in result:
        result["serverInfo"] = info
    meta = result.get("_meta")
    if isinstance(meta, dict) and types.SERVER_INFO_META_KEY in meta:
        result["_meta"] = {**meta, types.SERVER_INFO_META_KEY: info}
    return result


async def test_a_server_middleware_can_name_the_server_after_its_path() -> None:
    """The constructor's name is fixed; a middleware rewrites it in both eras' answers."""
    shaped = Shaped()
    shaped.server.middleware = [server_info_from_path]
    with running(shaped) as url:
        other = url.replace("/s/example/", "/s/other/")
        initialize = rpc_result(legacy_init(url))
        discover = rpc_result(modern_post(other, "server/discover"))
        listing = rpc_result(modern_post(url, "tools/list"))
    example = {"name": "zoeymcp/example", "version": "1"}
    assert initialize["serverInfo"] == example
    assert discover["_meta"] == {
        types.SERVER_INFO_META_KEY: {"name": "zoeymcp/other", "version": "1"}
    }
    assert listing["_meta"] == {types.SERVER_INFO_META_KEY: example}


# --- 9. sessions belong to their user -----------------------------------------------------------


def session_headers(session: str, client: str | None) -> dict[str, str]:
    return wire(client, extra={"mcp-session-id": session, "mcp-protocol-version": LEGACY})


def legacy_get(url: str, session: str, client: str | None) -> tuple[int, bytes]:
    """A GET stream on ``session``: its status, and its body if it was refused."""
    headers = session_headers(session, client)
    with httpx.stream("GET", url, headers=headers, timeout=10) as response:
        if response.status_code == 200:
            return 200, b""
        return response.status_code, response.read()


async def test_another_users_session_id_is_refused_like_an_unknown_one() -> None:
    """For every method: B can't post to, listen on or end A's session."""
    shaped = Shaped()
    with running(shaped) as url:
        session = legacy_session(url, "a")
        own = legacy_post(url, session, "tools/list", client="a")
        other = legacy_post(url, session, "tools/list", client="b")
        anonymous = legacy_post(url, session, "tools/list", client=None)
        unknown = legacy_post(url, "0" * 32, "tools/list", client="a")
        listen = legacy_get(url, session, "b")
        anonymous_listen = legacy_get(url, session, None)
        end = httpx.delete(url, headers=session_headers(session, "b"), timeout=10)
        anonymous_end = httpx.delete(url, headers=session_headers(session, None), timeout=10)
        again = legacy_post(url, session, "tools/list", client="a")
    assert (own.status_code, again.status_code) == (200, 200)
    assert other.status_code == anonymous.status_code == unknown.status_code == 404
    assert other.content == anonymous.content == unknown.content
    assert listen == anonymous_listen == (404, unknown.content)
    assert (end.status_code, anonymous_end.status_code) == (404, 404)
    assert end.content == anonymous_end.content == unknown.content
    assert unknown.json()["error"] == {
        "code": types.INVALID_REQUEST,
        "message": "Session not found",
    }
    assert [seen.current[0] for seen in shaped.seen] == ["a", "a"]


async def test_the_manager_does_not_bind_a_session_to_its_path() -> None:
    """One manager serves every path, so binding a session to its server path is ours (E.3)."""
    shaped = Shaped()
    with running(shaped) as url:
        session = legacy_session(url, "a")
        elsewhere = legacy_post(url.replace("/s/example/", "/s/other/"), session, "tools/list")
    assert elsewhere.status_code == 200


# --- 10. limits and host checks ----------------------------------------------------------------


def padded(body: dict[str, Any], size: int) -> bytes:
    """``body`` with a padding parameter, exactly ``size`` bytes long."""
    bare = json.dumps({**body, "params": {**body["params"], "pad": ""}}, separators=(",", ":"))
    pad = size - len(bare.encode())
    assert pad >= 0
    data = {**body, "params": {**body["params"], "pad": "x" * pad}}
    encoded = json.dumps(data, separators=(",", ":")).encode()
    assert len(encoded) == size
    return encoded


LIMIT = 4096


@pytest.mark.parametrize("era", ["legacy", "modern"])
async def test_the_manager_enforces_the_body_limit(era: str) -> None:
    shaped = Shaped(body_limit=LIMIT)
    if era == "legacy":
        body, headers = initialize_body(), wire("a", extra={"content-type": "application/json"})
    else:
        body = modern_body("server/discover")
        headers = {**modern_headers("server/discover"), "content-type": "application/json"}

    def chunks(data: bytes) -> Iterator[bytes]:
        yield data[: len(data) // 2]
        yield data[len(data) // 2 :]

    with running(shaped) as url:
        at_limit = httpx.post(url, content=padded(body, LIMIT), headers=headers, timeout=10)
        over = httpx.post(url, content=padded(body, LIMIT + 1), headers=headers, timeout=10)
        streamed_at_limit = httpx.post(
            url, content=chunks(padded(body, LIMIT)), headers=headers, timeout=10
        )
        streamed = httpx.post(
            url, content=chunks(padded(body, LIMIT + 1)), headers=headers, timeout=10
        )
    assert (at_limit.status_code, streamed_at_limit.status_code) == (200, 200)
    assert "content-length" not in streamed.request.headers
    assert "content-length" not in streamed_at_limit.request.headers
    assert (over.status_code, streamed.status_code) == (413, 413)
    assert ("mcp-session-id" in at_limit.headers) is (era == "legacy")
    assert "mcp-session-id" not in over.headers
    assert "mcp-session-id" not in streamed.headers


async def test_the_manager_closes_an_idle_session() -> None:
    shaped = Shaped(idle=0.5)
    with running(shaped) as url:
        session = legacy_session(url)
        fresh = legacy_post(url, session, "tools/list")
        await anyio.sleep(1.5)
        idle = legacy_post(url, session, "tools/list")
    assert fresh.status_code == 200
    assert idle.status_code == 404


async def test_idle_time_counts_from_the_last_request_and_not_while_a_get_stream_is_open() -> None:
    """``SessionBindings`` expiry (E.3) has to follow this notion of idle, not the time since
    the session's last POST: an agent holding a GET stream keeps its session."""
    shaped = Shaped(idle=1.0)
    with running(shaped) as url:
        busy = legacy_session(url)
        statuses = []
        for _ in range(4):
            await anyio.sleep(0.4)
            statuses.append(legacy_post(url, busy, "tools/list").status_code)
        listening = legacy_session(url)
        headers = session_headers(listening, "a")
        with httpx.stream("GET", url, headers=headers, timeout=10) as stream:
            assert stream.status_code == 200
            await anyio.sleep(2.5)
            held = legacy_post(url, listening, "tools/list")
        await anyio.sleep(2.5)
        after = legacy_post(url, busy, "tools/list")
    # 1.6 s of requests 0.4 s apart outlive a 1 s idle timeout, and the GET stream 2.5 s.
    assert statuses == [200] * 4
    assert held.status_code == 200
    assert after.status_code == 404


async def test_the_manager_caps_the_number_of_sessions() -> None:
    shaped = Shaped(max_sessions=2)
    with running(shaped) as url:
        first = legacy_session(url, "a")
        legacy_session(url, "b")
        refused = legacy_init(url, "c")
        modern = modern_post(url, "server/discover", client="c")
        closed = httpx.delete(
            url, headers=wire("a", extra={"mcp-session-id": first, "mcp-protocol-version": LEGACY})
        )
        later = legacy_init(url, "c")
    assert refused.status_code == 503
    assert refused.json()["error"] == {
        "code": types.INTERNAL_ERROR,
        "message": "Too many open sessions",
    }
    assert modern.status_code == 200
    assert closed.status_code == 200
    assert later.status_code == 200


def security_for(hosts: list[str], origins: list[str]) -> TransportSecuritySettings:
    """The settings the gateway derives from its lists: each host bare and with any port (E.1)."""
    allowed = []
    for host in hosts:
        name = f"[{host}]" if ":" in host else host
        allowed += [name, f"{name}:*"]
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True, allowed_hosts=allowed, allowed_origins=origins
    )


HOST_CASES = [
    ("gateway:8090", None, 200),
    ("gateway", None, 200),
    ("zoeymcp.example:443", None, 200),
    ("[::1]:8090", None, 200),
    ("[::1]", None, 200),
    ("evil.example", None, 421),
    ("gateway.evil.example:8090", None, 421),
    ("gatewayx:8090", None, 421),
    # The SDK compares case-sensitively; the gateway's own check lowercases first (E.2), so the
    # gateway hands the SDK a lowercased Host.
    ("GATEWAY:8090", None, 421),
    ("gateway:8090", "https://agent.example", 200),
    ("gateway:8090", "https://evil.example", 403),
    ("gateway:8090", "null", 403),
    # Origin is compared as an exact string too: no case folding, no default port removal. The
    # gateway's own origin check must compare the same way, or normalize what it hands the SDK.
    ("gateway:8090", "HTTPS://AGENT.EXAMPLE", 403),
    ("gateway:8090", "https://agent.example:443", 403),
    ("gateway:8090", "https://agent.example/", 403),
]


@pytest.mark.parametrize("era", ["legacy", "modern"])
async def test_transport_security_settings_accept_our_host_and_origin_lists(era: str) -> None:
    hosts = ["gateway", "zoeymcp.example", "::1"]
    shaped = Shaped(security=security_for(hosts, ["https://agent.example"]))
    statuses = []
    with running(shaped) as url:
        for host, origin, _ in HOST_CASES:
            extra = {"host": host}
            if origin is not None:
                extra["origin"] = origin
            if era == "legacy":
                response = legacy_init(url, "a", extra=extra)
            else:
                response = modern_post(url, "server/discover", extra=extra)
            statuses.append(response.status_code)
    assert statuses == [expected for _, _, expected in HOST_CASES]


async def test_without_security_settings_the_manager_checks_no_host() -> None:
    """The manager's default is no check at all, unlike ``streamable_http_app``'s localhost one."""
    shaped = Shaped()
    with running(shaped) as url:
        response = modern_post(url, "server/discover", extra={"host": "evil.example"})
    assert response.status_code == 200


# --- 11. legacy list_changed outside a request -------------------------------------------------


@pytest.mark.parametrize("list_changed", [True, False])
async def test_the_legacy_handshake_advertises_list_changed_only_when_told(
    list_changed: bool,
) -> None:
    shaped = Shaped(list_changed=list_changed)
    with running(shaped) as url:
        async with (
            gateway_http(headers={CLIENT_HEADER: "a"}) as http,
            connect(url, "legacy", http=http) as legacy,
        ):
            legacy_capabilities = legacy.server_capabilities
            legacy_instructions = legacy.instructions
        async with (
            gateway_http(headers={CLIENT_HEADER: "a"}) as http,
            connect(url, http=http) as modern,
        ):
            modern_capabilities = modern.server_capabilities
            modern_instructions = modern.instructions
        initialize = rpc_result(legacy_init(url))
        discover = rpc_result(modern_post(url, "server/discover"))
    # Only the handler families the server was given, and no instructions (R31, E.4).
    tools = types.ToolsCapability(list_changed=list_changed)
    assert legacy_capabilities == types.ServerCapabilities(tools=tools)
    # Modern: listChanged follows from serving subscriptions/listen.
    tools = types.ToolsCapability(list_changed=True)
    assert modern_capabilities == types.ServerCapabilities(tools=tools)
    assert (legacy_instructions, modern_instructions) == (None, None)
    assert initialize["capabilities"] == {"tools": {"listChanged": list_changed}}
    assert discover["capabilities"] == {"tools": {"listChanged": True}}
    assert "instructions" not in initialize
    assert "instructions" not in discover


async def test_a_registered_legacy_session_can_be_sent_list_changed_outside_a_request() -> None:
    shaped = Shaped()
    messages = Messages()
    with running(shaped) as url:
        http = gateway_http(headers={CLIENT_HEADER: "a"})
        async with http, connect(url, "legacy", http=http, message_handler=messages) as agent:
            await agent.list_tools()
            await until(lambda: ("GET", 200) in shaped.statuses)
            [session] = shaped.sessions.values()
            with anyio.fail_after(5):
                await shaped.run(session.send_tool_list_changed())
            await until(lambda: "notifications/tools/list_changed" in messages.methods)
        # Once the agent has gone (DELETE), sending to its session neither hangs nor raises.
        assert ("DELETE", 200) in shaped.statuses
        [session_id] = shaped.sessions
        assert legacy_post(url, session_id, "tools/list").status_code == 404
        with anyio.fail_after(5):
            await shaped.run(session.send_tool_list_changed())
    assert messages.methods == ["notifications/tools/list_changed"]


# --- 12. modern listen streams -----------------------------------------------------------------


async def test_on_subscriptions_listen_can_publish_tools_list_changed_to_one_client() -> None:
    shaped = Shaped()
    with running(shaped) as url:
        async with (
            gateway_http(headers={CLIENT_HEADER: "a"}) as http_a,
            gateway_http(headers={CLIENT_HEADER: "b"}) as http_b,
            connect(url, http=http_a) as agent_a,
            connect(url, http=http_b) as agent_b,
            agent_a.listen(tools_list_changed=True) as events_a,
            agent_b.listen(tools_list_changed=True) as events_b,
        ):
            with anyio.fail_after(5):
                await shaped.run(shaped.buses["a"].publish(ToolsListChanged()))
                event = await events_a.__anext__()
            with anyio.move_on_after(0.5) as quiet:
                await events_b.__anext__()
            with anyio.fail_after(5):
                await shaped.run(shaped.buses["b"].publish(ToolsListChanged()))
                other = await events_b.__anext__()
    assert isinstance(event, ToolsListChanged)
    assert quiet.cancelled_caught
    assert isinstance(other, ToolsListChanged)


# --- 14. the contextvar ------------------------------------------------------------------------


@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_handlers_and_the_schema_hook_see_their_own_requests_contextvar(mode: str) -> None:
    shaped = Shaped()
    numbers = iter(range(1, 1000))

    async def stamp(request: Any) -> None:
        request.headers[REQUEST_HEADER] = f"r{next(numbers)}"

    with running(shaped) as url:
        http = gateway_http(headers={CLIENT_HEADER: "a"}, event_hooks={"request": [stamp]})
        async with http, connect(url, mode, http=http) as agent:
            await agent.list_tools()
            result = await agent.call_tool("lookup", {"region": "eu"})
    [call] = [seen for seen in shaped.seen if seen.method == "tools/call"]
    assert call.request is not None
    # The handler sees the contextvar of the request that carried its message, not the
    # session's first one.
    assert call.current == ("a", call.request)
    assert all(seen.current == ("a", seen.request) for seen in shaped.seen)
    assert text_of(result) == f"lookup for a in {call.request}"
    if mode == "auto":
        assert shaped.lookups == [("lookup", ("a", call.request))]
    else:
        # Mcp-Param-* headers are modern only.
        assert shaped.lookups == []


async def test_the_schema_hook_is_what_checks_mcp_param_headers() -> None:
    shaped = Shaped()
    params = {"name": "lookup", "arguments": {"region": "eu"}}
    with running(shaped) as url:
        refused = modern_post(
            url, "tools/call", params, extra={"mcp-param-region": "us", REQUEST_HEADER: "r9"}
        )
    assert refused.status_code == 400
    assert refused.json()["error"]["code"] == types.HEADER_MISMATCH
    assert shaped.lookups == [("lookup", ("a", "r9"))]
    assert shaped.seen == []


# --- trace context (item 15's server half) -----------------------------------------------------


def test_the_low_level_server_installs_opentelemetry_middleware_by_default() -> None:
    server: Server[Any] = Server("zoeymcp-gateway")
    assert [type(middleware).__name__ for middleware in server.middleware] == [
        "OpenTelemetryMiddleware"
    ]


@pytest.mark.parametrize("otel", [True, False])
async def test_the_default_middleware_carries_an_agents_traceparent_upstream(otel: bool) -> None:
    """Why the gateway's server drops the middleware: with it, an agent's trace context
    becomes current in the handler, and the SDK client sends it upstream."""
    fake = McpFake()
    with serve(fake.app(), lifespan=True) as fake_base:
        shaped = Shaped(otel=otel, upstream=f"{fake_base}{fake.path}")
        with running(shaped) as url:
            response = modern_post(
                url,
                "tools/call",
                {"name": "relay", "arguments": {}},
                meta={"traceparent": TRACEPARENT},
            )
    assert response.status_code == 200
    assert rpc_result(response)["content"][0]["text"] == "relayed"
    [upstream_call] = fake.requests("tools/call")
    assert ("traceparent" in upstream_call.meta_keys) is otel
    if otel:
        assert (
            upstream_call.params["_meta"]["traceparent"].split("-")[1] == TRACEPARENT.split("-")[1]
        )


def logged(caplog: pytest.LogCaptureFixture, level: int) -> list[str]:
    """What the SDK's own loggers said at ``level`` or above."""
    records = caplog.records
    return [r.getMessage() for r in records if r.name.startswith("mcp.") and r.levelno >= level]


async def test_the_session_manager_logs_session_ids_and_origins(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Design M never logs a session id or a request header; the SDK does both, and warnings
    reach stderr even with no logging set up. The gateway has to silence or filter ``mcp``."""
    caplog.set_level(logging.DEBUG, logger="mcp")
    security = security_for(["127.0.0.1"], ["https://agent.example"])
    shaped = Shaped(idle=0.5, security=security)
    with running(shaped) as url:
        session = legacy_session(url, "a")
        refused = legacy_post(url, session, "tools/list", client="b")
        origin = modern_post(url, "server/discover", extra={"origin": "https://evil.example"})
        idle = f"Session {session} idle timeout"
        await until(lambda: idle in logged(caplog, logging.INFO))
    assert (refused.status_code, origin.status_code) == (404, 403)
    warnings = logged(caplog, logging.WARNING)
    assert [message for message in warnings if session in message] == [
        f"Rejecting request for session {session}: credential does not match the one that "
        "created the session"
    ]
    assert "Invalid Origin header: https://evil.example" in warnings
    assert f"Created new transport with session ID: {session}" in logged(caplog, logging.INFO)


async def test_an_agent_client_cannot_reach_another_clients_session() -> None:
    """Item 9 through the SDK client: the session id an agent holds works for it alone."""
    shaped = Shaped()
    with running(shaped) as url:
        http = gateway_http(headers={CLIENT_HEADER: "a"})
        async with http, connect(url, "legacy", http=http) as agent:
            await agent.list_tools()
            [session] = shaped.sessions
            stolen = legacy_post(url, session, "tools/call", {"name": "echo"}, client="b")
            assert text_of(await agent.call_tool("echo", {})) == "echo for a in None"
    assert stolen.status_code == 404
    assert [seen.method for seen in shaped.seen] == ["tools/list", "tools/call"]
