"""The client-facing MCP server (M3 design E.1 to E.5).

``/s/<server>/mcp`` takes POST, GET and DELETE; ``/healthz`` answers ``200 ok`` while the view
is fresh and 503 otherwise; everything else is 404, so agents never start OAuth discovery.

The admission checks run here, in the design's order, before the SDK sees anything, and no body
byte is read before the client and server are known (:mod:`.access` holds the decisions). Then
one low-level SDK ``Server`` behind one ``StreamableHTTPSessionManager`` serves every server
path: handlers read who is asking from a contextvar the glue sets per request, never from
``clientInfo`` or ``_meta``. ``scope["user"]`` names the client (never its token), so the SDK
also refuses another client's session id; :class:`~.access.SessionBindings` adds the server
path, which the SDK's binding doesn't cover.

The capabilities are computed, never copied from upstream: ``tools: {listChanged: true}`` and
nothing else. The server is named ``zoeymcp/<server>``, and no ``instructions`` are sent.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any

import anyio
import httpx2
import mcp_types
from mcp.server import Server
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken
from mcp.server.context import CallNext, HandlerResult, ServerRequestContext
from mcp.server.lowlevel.server import NotificationOptions
from mcp.server.models import InitializationOptions
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.exceptions import MCPError
from mcp.types import (
    CallToolRequestParams,
    CallToolResult,
    ListToolsResult,
    PaginatedRequestParams,
    SubscriptionsListenRequestParams,
    SubscriptionsListenResult,
    Tool,
)
from starlette.datastructures import Headers
from starlette.requests import Request
from starlette.types import Message, Receive, Scope, Send

from ..common.policy.view import ViewGateway, ViewRemoteServer
from . import access, logs, pipeline
from .connstate import Era
from .notify import Notifier
from .policyclient import PolicyClient, Snapshot
from .upstream import NotAdmitted, UpstreamError, UpstreamPool

HEALTH_PATH = "/healthz"
SDK_MAX_SESSIONS = 1024
LISTING_TTL_MS = 60_000


@dataclass(frozen=True)
class RequestScope:
    """Who is asking, set by the glue for one request and read by the handlers."""

    client: str
    server: str
    policy: ViewRemoteServer
    snapshot: Snapshot
    era: Era
    session_id: str | None


CURRENT: ContextVar[RequestScope | None] = ContextVar("zoeymcp_gateway_request", default=None)


class ListChangedServer(Server[Any]):
    """The low-level server, with ``tools.listChanged`` in the legacy handshake too."""

    def create_initialization_options(
        self,
        notification_options: NotificationOptions | None = None,
        experimental_capabilities: dict[str, dict[str, Any]] | None = None,
        extensions: dict[str, dict[str, Any]] | None = None,
    ) -> InitializationOptions:
        return super().create_initialization_options(
            NotificationOptions(tools_changed=True), experimental_capabilities, extensions
        )


async def server_info_from_path(
    ctx: ServerRequestContext[Any], call_next: CallNext
) -> HandlerResult:
    """Names the server ``zoeymcp/<server>`` in both eras' answers (E.4).

    It replaces the SDK's default middleware, OpenTelemetry's, which would make an agent's
    ``traceparent`` current and so carry it upstream.
    """
    result = await call_next(ctx)
    request = ctx.request
    if not isinstance(request, Request) or not isinstance(result, dict):
        return result
    name = access.server_from_path(request.url.path)
    info = {"name": f"zoeymcp/{name}", "version": "1"}
    if "serverInfo" in result:
        result["serverInfo"] = info
    result.pop("instructions", None)
    meta = result.get("_meta")
    if isinstance(meta, dict) and mcp_types.SERVER_INFO_META_KEY in meta:
        result["_meta"] = {**meta, mcp_types.SERVER_INFO_META_KEY: info}
    return result


def security_settings(gateway: ViewGateway) -> TransportSecuritySettings:
    """The SDK's own Host and Origin checks, from the same lists as the gateway's (E.1)."""
    allowed: list[str] = []
    for host in gateway.hosts:
        name = host.lower()
        name = f"[{name}]" if ":" in name else name
        allowed += [name, f"{name}:*"]
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=allowed,
        allowed_origins=list(gateway.origins),
    )


def _scope() -> RequestScope:
    scope = CURRENT.get()
    if scope is None:  # only the glue's requests reach the handlers
        raise MCPError(mcp_types.INTERNAL_ERROR, "no admission")
    return scope


async def _send_refusal(send: Send, refusal: access.Refusal) -> None:
    body = access.refusal_body(refusal)
    headers = [(name.encode(), value.encode()) for name, value in access.refusal_headers(refusal)]
    headers.append((b"content-length", str(len(body)).encode()))
    await send({"type": "http.response.start", "status": refusal.status, "headers": headers})
    await send({"type": "http.response.body", "body": body})


async def _send_plain(send: Send, status: int, text: str) -> None:
    body = text.encode()
    headers = [(b"content-type", b"text/plain"), (b"content-length", str(len(body)).encode())]
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})


class _TooLarge(Exception):
    pass


async def _read_body(receive: Receive, limit: int) -> bytes:
    chunks: list[bytes] = []
    size = 0
    while True:
        message = await receive()
        if message["type"] != "http.request":
            raise _TooLarge  # the client left; nothing is answered
        chunk = message.get("body", b"")
        size += len(chunk)
        if size > limit:
            raise _TooLarge
        chunks.append(chunk)
        if not message.get("more_body", False):
            return b"".join(chunks)


def _replay(body: bytes, receive: Receive) -> Receive:
    sent = False

    async def replayed() -> Message:
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return await receive()

    return replayed


STALE_CHECK = 1.0  # seconds between staleness checks


class GatewayApp:
    """The gateway as one ASGI app. Its lifespan runs the pool, the notifier, the policy client
    and, once the first view has arrived, the SDK's session manager."""

    def __init__(
        self,
        pool: UpstreamPool,
        policy_http: httpx2.AsyncClient,
        *,
        notifier: Notifier | None = None,
        clock: Callable[[], float] = time.monotonic,
        policy_wait: int | None = None,
    ) -> None:
        self.pool = pool
        self.notifier = notifier if notifier is not None else Notifier()
        self.clock = clock
        options = {"wait": policy_wait} if policy_wait is not None else {}
        self.policy = PolicyClient(policy_http, self._on_view, clock=clock, **options)
        # Made in the lifespan: an anyio event needs the loop it will be used on.
        self.first_view: anyio.Event | None = None
        self.stopping: anyio.Event | None = None
        pool.on_view_change = self._connection_changed
        self.server = ListChangedServer(
            "zoeymcp-gateway",
            version="1",
            on_list_tools=self._list_tools,
            on_call_tool=self._call_tool,
            on_subscriptions_listen=self._listen,
            get_tool_input_schema=self._input_schema,
        )
        self.server.middleware = [server_info_from_path]
        self.sessions = access.SessionBindings(idle_timeout=1800)
        self.counters = access.ClientCounters()
        self.manager: StreamableHTTPSessionManager | None = None
        self.security: TransportSecuritySettings | None = None
        self._started_limits: tuple[int, int] | None = None

    # --- the view ---------------------------------------------------------------------------

    def apply_view(self, gateway: ViewGateway) -> None:
        """A new view: hosts, origins and session timing take effect for the next request."""
        settings = security_settings(gateway)
        if self.security is None:
            self.security = settings
        else:  # the session manager holds this object
            self.security.allowed_hosts = settings.allowed_hosts
            self.security.allowed_origins = settings.allowed_origins
        self.sessions.idle_timeout = gateway.limits.session_idle_timeout
        started = self._started_limits
        if started is not None and started != (
            gateway.limits.max_request_bytes,
            gateway.limits.session_idle_timeout,
        ):
            logs.event("limits_change_needs_restart")

    def make_manager(self, gateway: ViewGateway) -> StreamableHTTPSessionManager:
        """The SDK's session manager, built from the first view. Its body limit and idle timeout
        are fixed from then on; the gateway's own checks follow every later view."""
        self.apply_view(gateway)
        limits = gateway.limits
        self._started_limits = (limits.max_request_bytes, limits.session_idle_timeout)
        self.manager = StreamableHTTPSessionManager(
            self.server,
            json_response=False,
            security_settings=self.security,
            max_request_body_size=limits.max_request_bytes,
            session_idle_timeout=limits.session_idle_timeout,
            max_sessions=SDK_MAX_SESSIONS,
        )
        return self.manager

    async def _on_view(self, snapshot: Snapshot, previous: Snapshot | None) -> None:
        """The policy client applied a new view (D.3)."""
        gateway = snapshot.view.gateway
        self.apply_view(gateway)
        self.pool.apply(gateway)
        if previous is None:
            keep = {
                pin
                for server in gateway.servers.values()
                if isinstance(server, ViewRemoteServer)
                for pin in server.review.values()
            }
            for server_name in self.pool.marks.servers():
                keep |= {pin for _, pin in self.pool.marks.for_server(server_name)}
            self.pool.defs.prune(keep)
            if self.first_view is not None:
                self.first_view.set()
            return
        old = previous.view.gateway
        for client, assigned in old.clients.items():
            if client not in gateway.clients:
                self.notifier.forget(client)
                continue
            for server_name in assigned.servers:
                if server_name not in gateway.clients[client].servers:
                    self.notifier.forget(client, server_name)
        for client, assigned in gateway.clients.items():
            for server_name in assigned.servers:
                before = old.servers.get(server_name)
                after = gateway.servers.get(server_name)
                was_assigned = client in old.clients and server_name in old.clients[client].servers
                if before != after or not was_assigned:
                    self.notifier.changed(client, server_name)

    def _connection_changed(self, connection: Any) -> None:
        """A connection's exposed view changed: tell the clients that see it (E.7)."""
        snapshot = self.policy.snapshot
        if snapshot is None:
            return
        holder = connection.key[1]
        clients = snapshot.view.gateway.clients
        if holder == "*":
            self.notifier.changed_for(
                (c for c, a in clients.items() if connection.server in a.servers), connection.server
            )
        elif holder in clients:
            self.notifier.changed(holder, connection.server)

    async def _run_manager(self, first_view: anyio.Event, stopping: anyio.Event) -> None:
        await first_view.wait()
        snapshot = self.policy.snapshot
        if snapshot is None:  # first_view is set only once a snapshot exists
            return
        manager = self.make_manager(snapshot.view.gateway)
        async with manager.run():
            logs.event("gateway_ready", digest=snapshot.view.digest)
            await stopping.wait()

    async def _watch_staleness(self) -> None:
        """With no contact with the vault for policy_max_stale, upstream connections close (D.2)."""
        stale = False
        while True:
            await anyio.sleep(STALE_CHECK)
            now_stale = self.policy.snapshot is not None and self.policy.fresh() is None
            if now_stale and not stale:
                self.pool.close_all("policy_stale")
            stale = now_stale

    async def lifespan(self, receive: Receive, send: Send) -> None:
        await receive()  # lifespan.startup
        self.first_view = first_view = anyio.Event()
        self.stopping = stopping = anyio.Event()
        try:
            async with anyio.create_task_group() as group:
                await group.start(self.pool.run)
                await group.start(self.notifier.run)
                group.start_soon(self.policy.run)
                group.start_soon(self._run_manager, first_view, stopping)
                group.start_soon(self._watch_staleness)
                await send({"type": "lifespan.startup.complete"})
                await receive()  # lifespan.shutdown
                stopping.set()
                await self.pool.aclose()
                group.cancel_scope.cancel()
        finally:
            self.manager = None
        await send({"type": "lifespan.shutdown.complete"})

    # --- ASGI ----------------------------------------------------------------------------------

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            await self.lifespan(receive, send)
            return
        if scope["type"] != "http":
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
            return
        path = scope.get("path", "")
        if path == HEALTH_PATH:
            fresh = self.policy.fresh() is not None and self.manager is not None
            await _send_plain(
                send,
                200 if fresh and scope["method"] == "GET" else 503,
                "ok" if fresh else "unavailable",
            )
            return
        await self._mcp(scope, receive, send)

    async def _refuse(
        self,
        send: Send,
        refusal: access.Refusal,
        reason: str,
        *,
        server: str | None = None,
        client: str | None = None,
        peer: str | None = None,
    ) -> None:
        logs.event(
            "auth_refused",
            reason=reason,
            detail=refusal.reason,
            status=refusal.status,
            server=server,
            client=client,
            peer=peer,
        )
        await _send_refusal(send, refusal)

    async def _mcp(self, scope: Scope, receive: Receive, send: Send) -> None:
        headers = Headers(scope=scope)
        peer = scope["client"][0] if scope.get("client") else None
        # 1. the path
        name = access.server_from_path(scope.get("path", ""))
        if name is None:
            await _send_refusal(send, access.Refusal(404, "path"))
            return
        # 2. a fresh view
        snapshot = self.policy.fresh()
        manager = self.manager
        if snapshot is None or manager is None:
            await self._refuse(send, access.Refusal(503, "no fresh view"), "stale", server=name)
            return
        gateway = snapshot.view.gateway
        # 3, 4, 5. Host, Origin, method
        if not access.host_allowed(headers.get("host"), gateway.hosts):
            await self._refuse(send, access.Refusal(421, "host"), "host", server=name, peer=peer)
            return
        if not access.origin_allowed(headers.get("origin"), gateway.origins):
            await self._refuse(
                send, access.Refusal(403, "origin"), "origin", server=name, peer=peer
            )
            return
        method = scope["method"]
        if not access.method_allowed(method):
            await self._refuse(send, access.Refusal(405, "method"), "method", server=name)
            return
        # 6. who: the bearer token, then source networks. The query string is never read.
        identity = access.authenticate(headers.getlist("authorization"), peer, gateway)
        if isinstance(identity, access.Refusal):
            reason = "source" if identity.reason == "source not allowed" else "bad_token"
            if identity.reason == "no usable bearer token":
                reason = "no_token"
            await self._refuse(send, identity, reason, server=name, peer=peer)
            return
        client = identity
        # 7. the server, for this client
        server = access.server_for(gateway, client, name)
        if isinstance(server, access.Refusal):
            await self._refuse(send, server, "unassigned", server=name, client=client)
            return
        # 8. the protocol version
        version_header = headers.get("mcp-protocol-version")
        version = access.check_version(version_header, method)
        if isinstance(version, access.Refusal):
            await self._refuse(send, version, "version", server=name, client=client)
            return
        modern = version_header == access.MODERN_VERSION
        # 9. the session, bound to this client and this server path
        session_id = headers.get("mcp-session-id")
        now = self.clock()
        if session_id is not None and not self.sessions.allowed(session_id, client, name, now):
            await self._refuse(
                send, access.Refusal(404, "session"), "session", server=name, client=client
            )
            return
        # 10. limits: the request counts before its body is read; a stream once it's known.
        limits = gateway.limits
        stream = method == "GET"
        if not self.counters.try_acquire(
            client,
            stream=stream,
            max_requests=limits.max_concurrent_per_client,
            max_streams=limits.max_streams_per_client,
        ):
            await self._refuse(
                send, access.too_many("concurrency"), "limit", server=name, client=client
            )
            return
        try:
            stream = await self._admitted(
                manager,
                scope,
                receive,
                send,
                headers,
                method,
                version,
                modern,
                session_id,
                RequestScope(
                    client, name, server, snapshot, "modern" if modern else "legacy", session_id
                ),
            )
        finally:
            self.counters.release(client, stream=stream)

    async def _admitted(
        self,
        manager: StreamableHTTPSessionManager,
        scope: Scope,
        receive: Receive,
        send: Send,
        headers: Headers,
        method: str,
        version: access.VersionCheck,
        modern: bool,
        session_id: str | None,
        request: RequestScope,
    ) -> bool:
        """Steps 10 to 12 for a request whose client and server are known, then the SDK.
        Returns whether the request took a stream slot."""
        client, name = request.client, request.server
        limits = request.snapshot.view.gateway.limits
        stream = method == "GET"
        # 11, 12. the body (POST)
        body = b""
        if method == "POST":
            refusal = access.check_content(
                headers.get("content-type"), headers.get("content-length"), limits.max_request_bytes
            )
            if refusal is not None:
                await self._refuse(send, refusal, "body", server=name, client=client)
                return stream
            try:
                body = await _read_body(receive, limits.max_request_bytes)
            except _TooLarge:
                await self._refuse(
                    send, access.Refusal(413, "body"), "body", server=name, client=client
                )
                return stream
            parsed = access.parse_message(body, limits.max_request_bytes)
            if isinstance(parsed, access.Refusal):
                reason = "batch" if parsed.rpc_code == -32600 else "body"
                await self._refuse(send, parsed, reason, server=name, client=client)
                return stream
            refusal = access.check_rpc(parsed, version, modern)
            if refusal is not None:
                await self._refuse(send, refusal, "method", server=name, client=client)
                return stream
            rpc = parsed.get("method")
            if rpc == "subscriptions/listen":
                if not self.counters.try_add_stream(
                    client, max_streams=limits.max_streams_per_client
                ):
                    await self._refuse(
                        send, access.too_many("streams"), "limit", server=name, client=client
                    )
                    return stream
                stream = True
            if (
                rpc == "initialize"
                and session_id is None
                and self.sessions.count(client, self.clock()) >= limits.max_sessions_per_client
            ):
                await self._refuse(
                    send, access.too_many("sessions"), "limit", server=name, client=client
                )
                return stream
        await self._serve(
            manager, scope, _replay(body, receive) if method == "POST" else receive, send, request
        )
        return stream

    async def _serve(
        self,
        manager: StreamableHTTPSessionManager,
        scope: Scope,
        receive: Receive,
        send: Send,
        request: RequestScope,
    ) -> None:
        # The SDK compares Host as an exact string; the gateway's check lowercased it.
        raw = [(key, value.lower() if key == b"host" else value) for key, value in scope["headers"]]
        sdk_scope = {
            **scope,
            "headers": raw,
            # Named after the client, never the token (E.2).
            "user": AuthenticatedUser(AccessToken(token="", client_id=request.client, scopes=[])),
        }
        session_id = request.session_id
        if session_id is not None:
            self.sessions.begin(session_id, self.clock())

        async def watched(message: Message) -> None:
            if message["type"] == "http.response.start":
                self._noted_response(scope["method"], message, request)
            await send(message)

        token = CURRENT.set(request)
        try:
            await manager.handle_request(sdk_scope, receive, watched)
        finally:
            CURRENT.reset(token)
            if session_id is not None:
                self.sessions.end(session_id, self.clock())

    def _noted_response(self, method: str, message: Message, request: RequestScope) -> None:
        status = message["status"]
        issued = None
        for key, value in message.get("headers", []):
            if key.lower() == b"mcp-session-id":
                issued = value.decode("latin-1")
        if issued is not None and request.session_id is None and 200 <= status < 300:
            self.sessions.bind(issued, request.client, request.server, self.clock())
            logs.event(
                "session_opened",
                client=request.client,
                server=request.server,
                side="client",
                era=request.era,
                session=_short(issued),
            )
        if method == "DELETE" and request.session_id is not None and 200 <= status < 300:
            self.sessions.drop(request.session_id)
            self.notifier.drop_session(request.client, request.server, request.session_id)
            logs.event(
                "session_closed",
                client=request.client,
                server=request.server,
                side="client",
                session=_short(request.session_id),
                reason="delete",
            )

    # --- handlers ------------------------------------------------------------------------------

    async def _list_tools(
        self, ctx: ServerRequestContext[Any], params: PaginatedRequestParams | None
    ) -> ListToolsResult:
        request = _scope()
        if params is not None and params.cursor is not None:
            raise MCPError(mcp_types.INVALID_PARAMS, "the listing has one page")
        self._register(ctx, request)
        try:
            connection = self.pool.connection(request.server, request.policy, request.client)
            evaluation = await self.pool.wait_ready(connection)
        except (NotAdmitted, UpstreamError) as exc:
            ref = pipeline.new_ref()
            logs.event(
                "request",
                client=request.client,
                server=request.server,
                rpc="tools/list",
                outcome="upstream_error",
                reason=str(exc),
                ref=ref,
            )
            raise MCPError(mcp_types.INTERNAL_ERROR, f"upstream unavailable (ref {ref})") from exc
        tools = []
        for name in sorted(evaluation.exposed):
            definition = dict(evaluation.exposed[name].definition)
            output = definition.get("outputSchema")
            if (
                request.era == "legacy"
                and isinstance(output, dict)
                and output.get("type") != "object"
            ):
                del definition["outputSchema"]
            tools.append(Tool.model_validate(definition))
        logs.event(
            "request",
            client=request.client,
            server=request.server,
            rpc="tools/list",
            era=request.era,
            outcome="ok",
            tools=len(tools),
        )
        if request.era == "modern":
            return ListToolsResult(tools=tools, ttl_ms=LISTING_TTL_MS, cache_scope="private")
        return ListToolsResult(tools=tools)

    async def _call_tool(
        self, ctx: ServerRequestContext[Any], params: CallToolRequestParams
    ) -> CallToolResult:
        request = _scope()
        self._register(ctx, request)
        call = pipeline.Call(
            request.client,
            request.server,
            request.policy,
            request.snapshot.view.gateway.limits,
            request.era,
        )

        async def progress(value: float, total: float | None) -> None:
            await ctx.session.report_progress(value, total)

        return await pipeline.call_tool(
            self.pool, call, params.name, params.arguments, progress=progress
        )

    async def _listen(
        self, ctx: ServerRequestContext[Any], params: SubscriptionsListenRequestParams
    ) -> SubscriptionsListenResult:
        request = _scope()
        handler = self.notifier.listen_handler(request.client, request.server)
        result: SubscriptionsListenResult = await handler(ctx, params)
        return result

    def _input_schema(self, name: str) -> dict[str, Any] | None:
        """The pinned input schema, so the SDK checks ``Mcp-Param-*`` headers against it."""
        request = CURRENT.get()
        if request is None:
            return None
        for connection in self.pool.connections():
            if connection.server != request.server or connection.key[1] not in (
                request.client,
                "*",
            ):
                continue
            evaluation = connection.state.evaluation
            exposed = evaluation.exposed.get(name) if evaluation is not None else None
            if exposed is not None:
                schema = exposed.definition.get("inputSchema")
                return dict(schema) if isinstance(schema, dict) else None
        return None

    def _register(self, ctx: ServerRequestContext[Any], request: RequestScope) -> None:
        if request.session_id is not None:
            self.notifier.register_session(
                request.client, request.server, request.session_id, ctx.session
            )


def _short(session_id: str) -> str:
    """Session ids are never logged: the first 8 hex digits of their SHA-256 instead."""
    return hashlib.sha256(session_id.encode()).hexdigest()[:8]
