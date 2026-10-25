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

The capabilities are computed per path, never copied from upstream (M6 design L.5):
``tools: {listChanged: true}``, and ``prompts`` and ``resources`` (``listChanged``, never
``subscribe``) and ``completions`` only for a path that serves them
(:func:`.capabilities.served`). The SDK derives its own from the handlers it was given, for
every path at once, so the gateway answers ``server/discover`` itself and rewrites the legacy
``initialize`` result's (:func:`capabilities_from_path`), which can't be replaced. The server is
named ``zoeymcp/<server>``, and no ``instructions`` are sent.

Prompts, resources and completions (L.6) are served from the connection's latest evaluation:
what is included, pinned, matching and unmarked of each kind, each answer rebuilt by
:mod:`.sanitize`, a read only of a URI :mod:`.resourcematch` allows.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable
from contextvars import ContextVar
from dataclasses import dataclass, replace
from typing import Any

import anyio
import httpx2
import mcp_types
import pydantic
from mcp import Client
from mcp.server import Server
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken
from mcp.server.context import CallNext, HandlerResult, ServerRequestContext
from mcp.server.lowlevel.server import NotificationOptions
from mcp.server.models import InitializationOptions
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.exceptions import MCPError
from mcp.shared.message import ServerMessageMetadata
from mcp.types import (
    CallToolRequestParams,
    CallToolResult,
    CompleteRequestParams,
    CompleteResult,
    DiscoverResult,
    GetPromptRequestParams,
    GetPromptResult,
    ListPromptsResult,
    ListResourcesResult,
    ListResourceTemplatesResult,
    ListToolsResult,
    PaginatedRequestParams,
    Prompt,
    PromptReference,
    ReadResourceRequestParams,
    ReadResourceResult,
    RequestParams,
    Resource,
    ResourceTemplate,
    ResourceTemplateReference,
    SubscriptionsListenRequestParams,
    SubscriptionsListenResult,
    Tool,
)
from mcp_types.version import MODERN_PROTOCOL_VERSIONS
from starlette.datastructures import Headers
from starlette.requests import Request
from starlette.types import Message, Receive, Scope, Send

from ..common import canonical
from ..common.pinhash import DefinitionKind
from ..common.policy.schema import GatewayLimits
from ..common.policy.view import ViewGateway, ViewRemoteServer, ViewToolkitServer
from . import access, capabilities, logs, pins, pipeline, resourcematch, sanitize
from .approvals import HANDLE_PATTERN, handle_sha256
from .approve import Approvals
from .committed import Committed
from .connstate import Era
from .ledger import Ledger
from .notify import Notifier
from .policyclient import PolicyClient, Snapshot, Witness
from .reporter import Reporter
from .reviewpoll import ReviewPoller
from .statuspush import Status, StatusPusher
from .toolkits import Toolkits
from .toolkitsource import ToolkitSource, ToolkitUnavailable
from .toolsource import RemoteSource, ServedServer, ToolSource
from .upstream import NotAdmitted, UpstreamError, UpstreamPool

HEALTH_PATH = "/healthz"
SDK_MAX_SESSIONS = 1024
LISTING_TTL_MS = 60_000
# The fixed refusals of a prompt or completion the path doesn't serve, or arguments it refuses;
# none echoes what the agent sent (M6 design L.6).
UNKNOWN_PROMPT = "Unknown prompt"
UNKNOWN_REFERENCE = "Unknown reference"
NOT_DECLARED = "arguments refused: not a declared argument"
TOO_LARGE = "arguments refused: too large"
NOT_PLAIN = "arguments refused: not plain JSON"


@dataclass(frozen=True)
class RequestScope:
    """Who is asking, set by the glue for one request and read by the handlers."""

    client: str
    server: str
    policy: ServedServer
    snapshot: Snapshot
    era: Era
    session_id: str | None
    # Set when a POST's client hangs up while its handler runs (M4 design D.4).
    disconnected: anyio.Event | None = None


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


async def capabilities_from_path(
    ctx: ServerRequestContext[Any], call_next: CallNext
) -> HandlerResult:
    """The legacy ``initialize`` result's capabilities, the path's own (M6 design L.5): the SDK
    states the ones its handlers give every path, and ``initialize`` can't be replaced (SDK
    contract 57). Every list it advertises with ``listChanged`` is one the gateway sends.

    It fails closed: with no request scope, or no result to rewrite, the SDK's set would name
    every path's kinds (Y22), so ``initialize`` is refused instead."""
    if ctx.method != "initialize":
        return await call_next(ctx)
    request = _scope()
    result = await call_next(ctx)
    if not isinstance(result, dict):  # SDK contract 57 pins a dict
        raise MCPError(mcp_types.INTERNAL_ERROR, "no initialize result")
    served = capabilities.advertised(capabilities.served(request.policy))
    result["capabilities"] = served.model_dump(by_alias=True, exclude_none=True, mode="json")
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


def _replay(body: bytes, receive: Receive, disconnected: anyio.Event | None = None) -> Receive:
    """The body already read, then the rest of the request's messages; a disconnect sets
    ``disconnected``, which a waiting legacy approval watches (M4 design D.4)."""
    sent = False

    async def replayed() -> Message:
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        message = await receive()
        if message["type"] == "http.disconnect" and disconnected is not None:
            disconnected.set()
        return message

    return replayed


class _AskSession:
    """The agent's session, as an approval asks through it (M4 design D.1, D.2)."""

    def __init__(self, ctx: ServerRequestContext[Any]) -> None:
        self._ctx = ctx

    @property
    def protocol_version(self) -> str:
        return self._ctx.session.protocol_version

    @property
    def can_send_request(self) -> bool:
        return self._ctx.session.can_send_request

    def elicitation(self) -> tuple[bool, bool, bool]:
        capabilities = self._ctx.session.client_capabilities
        found = capabilities.elicitation if capabilities is not None else None
        if found is None:
            return False, False, False
        return True, found.form is not None, found.url is not None

    async def elicit(self, text: str, schema: dict[str, Any], timeout: float) -> Any:
        # 2025-06-18 has no mode: model_construct with mode=None, which the dump drops.
        if self.protocol_version == "2025-06-18":
            params: Any = mcp_types.ElicitRequestFormParams.model_construct(
                mode=None,  # type: ignore[arg-type]  # deliberately: the dump then drops the key
                message=text,
                requested_schema=schema,
            )
        else:
            params = mcp_types.ElicitRequestFormParams(message=text, requested_schema=schema)
        request = mcp_types.ElicitRequest.model_construct(
            method="elicitation/create", params=params
        )
        return await self._ctx.session.send_request(
            request,
            mcp_types.ElicitResult,
            request_read_timeout_seconds=timeout,
            metadata=ServerMessageMetadata(related_request_id=self._ctx.request_id),
        )


STALE_CHECK = 1.0  # seconds between staleness checks
MAX_ANSWER_BYTES = 64 * 1024  # an agent's answer to a prompt (M4 design D.3)


class GatewayApp:
    """The gateway as one ASGI app. Its lifespan runs the pool, the notifier, the policy client,
    the ledger's reporter (with ``report_http``), the review poller (with ``review_http``, M7
    design F.3), the status pusher (with ``status_http`` and ``status``, which reads the app's
    status: ``server.pushed_status``; M6 design K.1) and, once the first view has arrived, the
    SDK's session manager. With ``witness``, the policy client hands it the head each view
    answer states (the restore witness, M6 design K.3). At shutdown it closes every client it
    holds on the vault link (D-166)."""

    def __init__(
        self,
        pool: UpstreamPool,
        policy_http: httpx2.AsyncClient,
        *,
        notifier: Notifier | None = None,
        clock: Callable[[], float] = time.monotonic,
        policy_wait: int | None = None,
        toolkits: Toolkits | None = None,
        report_http: httpx2.AsyncClient | None = None,
        review_http: httpx2.AsyncClient | None = None,
        status_http: httpx2.AsyncClient | None = None,
        status: Status | None = None,
        witness: Witness | None = None,
    ) -> None:
        self.pool = pool
        self.policy_http = policy_http
        # The ledger's reporter, made in the lifespan once the ledger is open (M5 design J.3).
        self.report_http = report_http
        self.reporter: Reporter | None = None
        # The review jobs the vault queues (M7 design F.3), polled for in the lifespan.
        self.review_http = review_http
        self.review_poller: ReviewPoller | None = None
        # The status report to the vault (M6 design K.1), pushed from the lifespan.
        self.status_http = status_http
        self.status = status
        self.status_pusher: StatusPusher | None = None
        # One review at a time, the admin socket's or a review job's (GR-12).
        self.reviewing = anyio.Lock()
        self.toolkits = toolkits or Toolkits(pool.link, pool.keys, pool.marks)
        self.notifier = notifier if notifier is not None else Notifier()
        self.clock = clock
        options = {"wait": policy_wait} if policy_wait is not None else {}
        self.policy = PolicyClient(
            policy_http, self._on_view, clock=clock, witness=witness, **options
        )
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
            on_list_prompts=self._list_prompts,
            on_get_prompt=self._get_prompt,
            on_list_resources=self._list_resources,
            on_list_resource_templates=self._list_templates,
            on_read_resource=self._read_resource,
            on_completion=self._complete,
            get_tool_input_schema=self._input_schema,
        )
        # The path's capabilities, never the SDK's for every path (L.5; SDK contract 57).
        self.server.add_request_handler("server/discover", RequestParams, self._discover)
        self.server.middleware = [
            server_info_from_path,
            capabilities_from_path,
            self._approval_retry_guard,
        ]
        self.sessions = access.SessionBindings(idle_timeout=1800)
        self.counters = access.ClientCounters()
        self.in_flight = pipeline.InFlight()
        self.remote = RemoteSource(pool)
        self.toolkit_source = ToolkitSource(self.toolkits, self._limits)
        # Approved calls past their accept; a shutdown waits for them first (M4 design B.6).
        self.committed = Committed()
        # Set by the stop signal, before uvicorn starts draining: new approvals are refused.
        self.stop_requested = False
        self.stop_hooks: list[Callable[[], None]] = []
        self.approvals = Approvals(
            ledger=None,
            committed=self.committed,
            fresh=self.policy.fresh,
            stopping=lambda: self.stop_requested,
            clock=clock,
        )
        self.manager: StreamableHTTPSessionManager | None = None
        self.security: TransportSecuritySettings | None = None
        self._started_limits: tuple[int, int] | None = None

    def _limits(self) -> GatewayLimits:
        snapshot = self.policy.snapshot
        return snapshot.view.gateway.limits if snapshot is not None else GatewayLimits()

    @property
    def ledger(self) -> Ledger | None:
        """The approval ledger, opened and recovered before the listener (M4 design F.5)."""
        return self.approvals.ledger

    @ledger.setter
    def ledger(self, ledger: Ledger | None) -> None:
        self.approvals.ledger = ledger

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
        if self.ledger is not None:
            self.ledger.max_bytes = gateway.limits.ledger_max_bytes
        if previous is not None:
            # Revocation is immediate: requests in flight stop, as the next one would be refused.
            for client, server in sorted(access.revoked(previous.view.gateway, gateway)):
                stopped = self.in_flight.stop(client, server)
                if stopped:
                    logs.event("requests_stopped", client=client, server=server, count=stopped)
        self.pool.apply(gateway)
        self.toolkits.apply(gateway)
        if previous is not None:
            withdrawn = await self.approvals.withdraw_unallowed(gateway)
            if withdrawn:
                logs.event("approvals_withdrawn", count=withdrawn)
        if previous is None:
            keep = {pin for server in gateway.servers.values() for pin in server.review.values()}
            # A remote server's prompts and resources are kept by their pins too (M6 L.4).
            for listed in gateway.servers.values():
                if isinstance(listed, ViewRemoteServer):
                    for kind in pins.enabled_kinds(listed.enable):
                        keep |= set(pins.entries(listed, kind).review.values())
            keep |= self.pool.marks.pins()
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
                    kinds = capabilities.notified(before, after)
                    self.notifier.changed(client, server_name, kinds)

    def _connection_changed(self, connection: Any, kinds: capabilities.ServedKinds) -> None:
        """A connection's exposed view changed, in the lists ``kinds`` names: tell the clients
        that see it (E.7; M6 design L.5)."""
        snapshot = self.policy.snapshot
        if snapshot is None:
            return
        holder = connection.key[1]
        clients = snapshot.view.gateway.clients
        if holder == "*":
            self.notifier.changed_for(
                (c for c, a in clients.items() if connection.server in a.servers),
                connection.server,
                kinds,
            )
        elif holder in clients:
            self.notifier.changed(holder, connection.server, kinds)

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

    def request_stop(self) -> None:
        """The stop signal arrived. Runs in the signal callback, so hooks only schedule work."""
        if self.stop_requested:
            return
        self.stop_requested = True
        for hook in self.stop_hooks:
            hook()

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
                if self.ledger is not None:
                    group.start_soon(self.ledger.retry_forever)
                    if self.report_http is not None:
                        # Apart from approvals: nothing they do waits for it (M5 design J.3).
                        self.reporter = Reporter(self.report_http, self.ledger)
                        group.start_soon(self.reporter.run)
                if self.review_http is not None:
                    self.review_poller = ReviewPoller(self, self.review_http)
                    group.start_soon(self._run_reviews, first_view, self.review_poller)
                if self.status_http is not None and self.status is not None:
                    self.status_pusher = StatusPusher(self, self.status_http, self.status)
                    group.start_soon(self._run_status, first_view, self.status_pusher)
                # Committed calls run in this group, out of reach of uvicorn's request cancels.
                self.committed.attach(group)
                group.start_soon(self.approvals.sweep_forever)

                def withdraw_on_stop() -> None:
                    group.start_soon(self.approvals.withdraw, lambda _: True, "shutdown")

                self.stop_hooks.append(withdraw_on_stop)
                await send({"type": "lifespan.startup.complete"})
                await receive()  # lifespan.shutdown
                # Approved calls finish, or reach their deadline, before anything else stops.
                cancelled = await self.committed.drain()
                if cancelled:
                    logs.event("shutdown_deadline_passed", cancelled=len(cancelled), level="error")
                stopping.set()
                await self.pool.aclose()
                await self.toolkits.aclose()
                group.cancel_scope.cancel()
        finally:
            self.committed.attach(None)
            self.manager = None
            with anyio.CancelScope(shield=True):
                await self._close_vault_clients()
        await send({"type": "lifespan.shutdown.complete"})

    async def _run_reviews(self, first_view: anyio.Event, poller: ReviewPoller) -> None:
        # A poll names the digest of the view the policy client holds: there is none before.
        await first_view.wait()
        await poller.run()

    async def _run_status(self, first_view: anyio.Event, pusher: StatusPusher) -> None:
        # The report names the view the policy client holds: there is none before.
        await first_view.wait()
        await pusher.run()

    async def _close_vault_clients(self) -> None:
        """The view's, the reporter's, the review poller's and the status pusher's clients
        (D-166); the pool and the toolkits close their own."""
        for http in (self.policy_http, self.report_http, self.review_http, self.status_http):
            if http is not None:
                await http.aclose()

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
        # At the cap, a POST on a session with a legacy prompt waiting may take that
        # prompt's reply slot: step 12 admits only an answer through it (M4 design D.3).
        limits = gateway.limits
        stream = method == "GET"
        reply: str | None = None
        if not self.counters.try_acquire(
            client,
            stream=stream,
            max_requests=limits.max_concurrent_per_client,
            max_streams=limits.max_streams_per_client,
        ):
            waiting, session_sha256 = 0, ""
            if method == "POST" and session_id is not None:
                session_sha256 = handle_sha256(session_id)
                waiting = self.approvals.table.legacy_waiting_count(session_sha256)
            if waiting and self.counters.try_acquire_reply(session_sha256, waiting=waiting):
                reply = session_sha256
            else:
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
                reply=reply is not None,
            )
        finally:
            if reply is not None:
                self.counters.release_reply(reply)
            else:
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
        *,
        reply: bool = False,
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
            answer_expected = (
                session_id is not None
                and len(body) <= MAX_ANSWER_BYTES
                and self.approvals.table.legacy_waiting(handle_sha256(session_id))
            )
            refusal = access.check_rpc(
                parsed,
                version,
                modern,
                answer_expected=answer_expected,
                served=capabilities.served(request.policy),
            )
            if refusal is not None:
                await self._refuse(send, refusal, "method", server=name, client=client)
                return stream
            if reply and not access.is_response(parsed):
                # A reply slot carries only answers.
                await self._refuse(
                    send, access.too_many("concurrency"), "limit", server=name, client=client
                )
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
        if method == "POST":
            disconnected = anyio.Event()
            receive = _replay(body, receive, disconnected)
            request = replace(request, disconnected=disconnected)
        await self._serve(manager, scope, receive, send, request, stream=stream)
        return stream

    async def _serve(
        self,
        manager: StreamableHTTPSessionManager,
        scope: Scope,
        receive: Receive,
        send: Send,
        request: RequestScope,
        *,
        stream: bool = False,
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
            if stream:
                # A long-lived stream ends when the client's access to the server does.
                with self.in_flight.track(request.client, request.server):
                    await manager.handle_request(sdk_scope, receive, watched)
            else:
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
            evaluation = await self.source(request.policy).exposed(
                request.client, request.server, request.policy
            )
        except ToolkitUnavailable as exc:
            ref = pipeline.new_ref()
            logs.event(
                "request",
                client=request.client,
                server=request.server,
                rpc="tools/list",
                outcome="toolkit_unavailable",
                reason=exc.reason,
                ref=ref,
            )
            raise MCPError(mcp_types.INTERNAL_ERROR, f"toolkit unavailable (ref {ref})") from exc
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
    ) -> CallToolResult | mcp_types.InputRequiredResult:
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

        approval = pipeline.Approval(
            approvals=self.approvals,
            session=_AskSession(ctx),
            gateway=request.snapshot.view.gateway,
            request_state=params.request_state,
            input_responses=params.input_responses,
            session_sha256=(
                handle_sha256(request.session_id) if request.session_id is not None else None
            ),
            disconnected=request.disconnected,
        )
        return await pipeline.call_tool(
            self.source(request.policy),
            call,
            params.name,
            params.arguments,
            progress=progress,
            in_flight=self.in_flight,
            approval=approval,
        )

    async def _approval_retry_guard(
        self, ctx: ServerRequestContext[Any], call_next: CallNext
    ) -> HandlerResult:
        """A modern retry whose answers fail the SDK's typed parse never reaches the handler:
        close its record, so the lock doesn't wait for expiry (M4 design D.7)."""
        state = ctx.params.get("requestState") if isinstance(ctx.params, dict) else None
        if (
            ctx.method != "tools/call"
            or not isinstance(state, str)
            or not HANDLE_PATTERN.fullmatch(state)
        ):
            return await call_next(ctx)
        try:
            return await call_next(ctx)
        except (pydantic.ValidationError, MCPError) as exc:
            if isinstance(exc, MCPError) and exc.error.code != mcp_types.INVALID_PARAMS:
                raise
            request = CURRENT.get()
            if request is not None:
                await self.approvals.close_unparsable(state, request.client, request.server)
            raise

    async def _listen(
        self, ctx: ServerRequestContext[Any], params: SubscriptionsListenRequestParams
    ) -> SubscriptionsListenResult:
        """An agent's listen stream, asking only for what this path sends (M6 design K.4): the
        SDK's handler acknowledges every kind it is asked for."""
        request = _scope()
        handler = self.notifier.listen_handler(request.client, request.server)
        asked = capabilities.honored(params, capabilities.served(request.policy))
        result: SubscriptionsListenResult = await handler(ctx, asked)
        return result

    async def _discover(
        self, ctx: ServerRequestContext[Any], params: RequestParams
    ) -> DiscoverResult:
        """``server/discover``, as the SDK's own answers it but with the path's capabilities
        (L.5; SDK contract 57)."""
        request = _scope()
        return DiscoverResult(
            supported_versions=list(MODERN_PROTOCOL_VERSIONS),
            capabilities=capabilities.advertised(capabilities.served(request.policy)),
            instructions=None,
        )

    # --- prompts, resources and completions (M6 design L.6) ---------------------------------

    async def _kinds(
        self, ctx: ServerRequestContext[Any], request: RequestScope, rpc: str
    ) -> tuple[ViewRemoteServer, pins.Evaluation]:
        """The path's remote server and its connection's latest evaluation, once there is one.
        Only a remote path serves these kinds: :func:`.access.check_rpc` refused the rest."""
        self._register(ctx, request)
        policy = request.policy
        assert isinstance(policy, ViewRemoteServer)  # noqa: S101 - see check_rpc
        try:
            evaluation = await self.remote.exposed(request.client, request.server, policy)
        except (NotAdmitted, UpstreamError) as exc:
            ref = pipeline.new_ref()
            logs.event(
                "request",
                client=request.client,
                server=request.server,
                rpc=rpc,
                outcome="upstream_error",
                reason=str(exc),
                ref=ref,
            )
            raise MCPError(mcp_types.INTERNAL_ERROR, f"upstream unavailable (ref {ref})") from exc
        return policy, evaluation

    def _entries(
        self, server: str, evaluation: pins.Evaluation, kind: DefinitionKind
    ) -> dict[str, pins.ExposedTool]:
        """What an evaluation serves of ``kind``: its exposed entries that no drift mark holds,
        since another connection may have marked one after this one listed."""
        found = evaluation.kinds.get(kind)
        if found is None:
            return {}
        marks = self.pool.marks.for_server(server, kind)
        return {
            name: exposed
            for name, exposed in found.exposed.items()
            if (name, exposed.pin) not in marks
        }

    def _readable(self, server: str, evaluation: pins.Evaluation) -> Callable[[str], bool]:
        """Whether a URI may be read: one of the served fixed resources, or one a served
        template names (:func:`.resourcematch.allowed`)."""
        fixed = self._entries(server, evaluation, "resource")
        templates = self._entries(server, evaluation, "resource_template")
        return lambda uri: resourcematch.allowed(uri, fixed, templates)

    def _served(
        self, server: str, kind: DefinitionKind, key: str, pin: str
    ) -> Callable[[pins.Evaluation], bool]:
        """Whether an evaluation still serves ``key`` of ``kind`` at ``pin``: a request goes out
        only on those terms (:meth:`.UpstreamPool.request`)."""

        def admitted(evaluation: pins.Evaluation) -> bool:
            found = self._entries(server, evaluation, kind).get(key)
            return found is not None and found.pin == pin

        return admitted

    def _logger(self, request: RequestScope, rpc: str, ref: str) -> Callable[..., None]:
        started = time.monotonic()

        def log(outcome: str, reason: str | None = None, **fields: Any) -> None:
            logs.event(
                "request",
                client=request.client,
                server=request.server,
                rpc=rpc,
                era=request.era,
                outcome=outcome,
                reason=reason,
                ref=ref,
                duration_ms=round((time.monotonic() - started) * 1000, 1),
                **fields,
            )

        return log

    @staticmethod
    def _failed(
        exc: NotAdmitted | UpstreamError, log: Callable[..., None], ref: str, *, not_found: int
    ) -> MCPError:
        """The agent's error for a request that went no further, with the fixed text
        :func:`.sanitize.kind_error` gives; never the upstream's message."""
        if isinstance(exc, NotAdmitted):
            log("refused", exc.reason)
            return MCPError(not_found, sanitize.NOT_FOUND)
        log("timeout" if exc.outcome == "timeout" else "upstream_error", exc.detail or exc.outcome)
        code, text = sanitize.kind_error(exc.outcome, exc.code, ref, not_found=not_found)
        return MCPError(code, text)

    async def _listed(
        self,
        ctx: ServerRequestContext[Any],
        params: PaginatedRequestParams | None,
        rpc: str,
        kind: DefinitionKind,
    ) -> tuple[RequestScope, list[dict[str, Any]]]:
        """One kind's list: the served entries' pinned projections, by name or URI."""
        request = _scope()
        if params is not None and params.cursor is not None:
            raise MCPError(mcp_types.INVALID_PARAMS, "the listing has one page")
        _, evaluation = await self._kinds(ctx, request, rpc)
        entries = self._entries(request.server, evaluation, kind)
        logs.event(
            "request",
            client=request.client,
            server=request.server,
            rpc=rpc,
            era=request.era,
            outcome="ok",
            entries=len(entries),
        )
        return request, [dict(entries[key].definition) for key in sorted(entries)]

    async def _list_prompts(
        self, ctx: ServerRequestContext[Any], params: PaginatedRequestParams | None
    ) -> ListPromptsResult:
        request, found = await self._listed(ctx, params, "prompts/list", "prompt")
        prompts = [Prompt.model_validate(definition) for definition in found]
        if request.era == "modern":
            return ListPromptsResult(prompts=prompts, ttl_ms=LISTING_TTL_MS, cache_scope="private")
        return ListPromptsResult(prompts=prompts)

    async def _list_templates(
        self, ctx: ServerRequestContext[Any], params: PaginatedRequestParams | None
    ) -> ListResourceTemplatesResult:
        rpc = "resources/templates/list"
        request, found = await self._listed(ctx, params, rpc, "resource_template")
        templates = [ResourceTemplate.model_validate(definition) for definition in found]
        if request.era == "modern":
            return ListResourceTemplatesResult(
                resource_templates=templates, ttl_ms=LISTING_TTL_MS, cache_scope="private"
            )
        return ListResourceTemplatesResult(resource_templates=templates)

    async def _list_resources(
        self, ctx: ServerRequestContext[Any], params: PaginatedRequestParams | None
    ) -> ListResourcesResult:
        # The upstream's own list is never relayed: only the reviewed fixed resources (L.6).
        request, found = await self._listed(ctx, params, "resources/list", "resource")
        resources = [Resource.model_validate(definition) for definition in found]
        if request.era == "modern":
            return ListResourcesResult(
                resources=resources, ttl_ms=LISTING_TTL_MS, cache_scope="private"
            )
        return ListResourcesResult(resources=resources)

    async def _get_prompt(
        self, ctx: ServerRequestContext[Any], params: GetPromptRequestParams
    ) -> GetPromptResult:
        request = _scope()
        ref = pipeline.new_ref()
        log = self._logger(request, "prompts/get", ref)
        policy, evaluation = await self._kinds(ctx, request, "prompts/get")
        name = params.name
        exposed = self._entries(request.server, evaluation, "prompt").get(name)
        if exposed is None:
            log("refused", "unknown_prompt")
            raise MCPError(mcp_types.INVALID_PARAMS, UNKNOWN_PROMPT)
        declared = [argument["name"] for argument in exposed.definition.get("arguments", ())]
        arguments = dict(params.arguments or {})
        limits = request.snapshot.view.gateway.limits
        problem = _arguments_problem(arguments, declared, arguments, limits)
        if problem is not None:
            log("refused", "arguments")
            raise MCPError(mcp_types.INVALID_PARAMS, problem)

        async def send(client: Client) -> GetPromptResult:
            return await client.get_prompt(name, arguments or None)

        try:
            raw = await self.pool.request(
                request.server,
                policy,
                request.client,
                send,
                admitted=self._served(request.server, "prompt", name, exposed.pin),
            )
        except (NotAdmitted, UpstreamError) as exc:
            raise self._failed(exc, log, ref, not_found=mcp_types.INVALID_PARAMS) from exc
        result = sanitize.sanitize_prompt(
            raw,
            assistant=name in policy.prompts.assistant,
            allowed=self._readable(request.server, evaluation),
            max_result_bytes=limits.max_result_bytes,
        )
        if result == "assistant":
            log("refused", "assistant")
            raise MCPError(mcp_types.INTERNAL_ERROR, sanitize.assistant_refused(name))
        if isinstance(result, str):
            log("refused", result)
            raise _too_large(ref)
        prompt, stats = result
        _log_sanitized(request.server, stats, ref, name=name)
        log("ok", messages=len(prompt.messages))
        if request.era == "modern":
            prompt.result_type = "complete"
        return prompt

    async def _read_resource(
        self, ctx: ServerRequestContext[Any], params: ReadResourceRequestParams
    ) -> ReadResourceResult:
        request = _scope()
        ref = pipeline.new_ref()
        log = self._logger(request, "resources/read", ref)
        # Not found, with the era's code, unless the URI may be read (SPEC-2, SPEC-4).
        not_found = sanitize.not_found_code(request.era)
        policy, evaluation = await self._kinds(ctx, request, "resources/read")
        uri = params.uri
        if not self._readable(request.server, evaluation)(uri):
            log("refused", "not_readable")
            raise MCPError(not_found, sanitize.NOT_FOUND)

        async def send(client: Client) -> ReadResourceResult:
            return await client.read_resource(uri)

        try:
            raw = await self.pool.request(
                request.server,
                policy,
                request.client,
                send,
                admitted=lambda found: self._readable(request.server, found)(uri),
            )
        except (NotAdmitted, UpstreamError) as exc:
            raise self._failed(exc, log, ref, not_found=not_found) from exc
        limits = request.snapshot.view.gateway.limits
        result = sanitize.sanitize_read(raw, uri=uri, max_result_bytes=limits.max_result_bytes)
        if result == "not_found":
            # Nothing of what was asked for is left: never an empty answer.
            log("refused", "nothing_left")
            raise MCPError(not_found, sanitize.NOT_FOUND)
        if isinstance(result, str):
            log("refused", result)
            raise _too_large(ref)
        read, stats = result
        _log_sanitized(request.server, stats, ref)
        log("ok", contents=len(read.contents))
        if request.era == "modern":
            # A read's contents are live: not cached (SPEC-3).
            read.ttl_ms = 0
            read.cache_scope = "private"
            read.result_type = "complete"
        return read

    async def _complete(
        self, ctx: ServerRequestContext[Any], params: CompleteRequestParams
    ) -> CompleteResult:
        request = _scope()
        ref = pipeline.new_ref()
        log = self._logger(request, "completion/complete", ref)
        policy, evaluation = await self._kinds(ctx, request, "completion/complete")
        asked = params.ref
        upstream_ref: PromptReference | ResourceTemplateReference
        if isinstance(asked, PromptReference):
            kind: DefinitionKind = "prompt"
            key = asked.name
            upstream_ref = PromptReference(type="ref/prompt", name=key)
        else:
            kind, key = "resource_template", asked.uri
            upstream_ref = ResourceTemplateReference(type="ref/resource", uri=key)
        exposed = self._entries(request.server, evaluation, kind).get(key)
        if exposed is None:
            log("refused", "unknown_reference")
            raise MCPError(mcp_types.INVALID_PARAMS, UNKNOWN_REFERENCE)
        if kind == "prompt":
            names = [argument["name"] for argument in exposed.definition.get("arguments", ())]
        else:
            names = list(resourcematch.variables(key))
        argument = params.argument
        context = dict(params.context.arguments or {}) if params.context is not None else {}
        sent = {"argument": {"name": argument.name, "value": argument.value}, "context": context}
        limits = request.snapshot.view.gateway.limits
        given = {argument.name: argument.value, **context}
        problem = _arguments_problem(given, names, sent, limits)
        if problem is not None:
            log("refused", "arguments")
            raise MCPError(mcp_types.INVALID_PARAMS, problem)

        async def send(client: Client) -> CompleteResult:
            value = {"name": argument.name, "value": argument.value}
            return await client.complete(upstream_ref, value, context or None)

        try:
            raw = await self.pool.request(
                request.server,
                policy,
                request.client,
                send,
                admitted=self._served(request.server, kind, key, exposed.pin),
            )
        except (NotAdmitted, UpstreamError) as exc:
            raise self._failed(exc, log, ref, not_found=mcp_types.INVALID_PARAMS) from exc
        completed, stats = sanitize.sanitize_completion(raw)
        log("ok", values=len(completed.completion.values), dropped=stats.dropped_blocks)
        if request.era == "modern":
            completed.result_type = "complete"
        return completed

    def _input_schema(self, name: str) -> dict[str, Any] | None:
        """The pinned input schema, so the SDK checks ``Mcp-Param-*`` headers against it."""
        request = CURRENT.get()
        if request is None:
            return None
        return self.source(request.policy).input_schema(request.client, request.server, name)

    def source(self, policy: ServedServer) -> ToolSource:
        """Where a server's tools come from: its kind's source."""
        if isinstance(policy, ViewToolkitServer):
            return self.toolkit_source
        return self.remote

    def _register(self, ctx: ServerRequestContext[Any], request: RequestScope) -> None:
        if request.session_id is not None:
            self.notifier.register_session(
                request.client, request.server, request.session_id, ctx.session
            )


def _arguments_problem(
    names: dict[str, str], declared: list[str], sent: object, limits: GatewayLimits
) -> str | None:
    """Why a prompt's or a completion's arguments are refused (L.6, SPEC-6): a name that isn't
    one the prompt declares or the template holds, or ``sent`` over ``max_argument_bytes``. The
    SDK's own parse already made every value a string."""
    if not set(names) <= set(declared):
        return NOT_DECLARED
    try:
        size = len(canonical.dumps_canonical(sent))
    except canonical.JSONRejected:
        return NOT_PLAIN
    return TOO_LARGE if size > limits.max_argument_bytes else None


def _too_large(ref: str) -> MCPError:
    return MCPError(mcp_types.INTERNAL_ERROR, f"{sanitize.MESSAGES['too_large']} (ref {ref})")


def _log_sanitized(server: str, stats: sanitize.Stats, ref: str, **fields: Any) -> None:
    logs.event(
        "result_sanitized",
        server=server,
        revealed=stats.revealed,
        dropped_blocks=stats.dropped_blocks,
        wrapped=stats.wrapped,
        ref=ref,
        **fields,
    )


def _short(session_id: str) -> str:
    """Session ids are never logged: the first 8 hex digits of their SHA-256 instead."""
    return hashlib.sha256(session_id.encode()).hexdigest()[:8]
