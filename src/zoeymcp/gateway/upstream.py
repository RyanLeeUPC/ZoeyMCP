"""Upstream connections: the pool, each connection's owner task, listings, drift and calls.

M3 design F.3 to F.7, G.3 and G.5. One connection per key from :func:`connstate.connection_key`.
Each is owned by one task, which enters and leaves the HTTP client, the transport and the SDK
``Client`` (anyio cancel scopes must be left by the task that entered them). Request tasks call
the open client directly, so cancelling a request cancels its SDK call.

The decisions live in pure modules: :mod:`.connstate` says whether a call may go out,
:mod:`.pins` evaluates each listing, :mod:`.egressrules` checks every request on the wire. This
module does the I/O around them:

- **connect** lazily, on the first request that needs the connection, then list and evaluate;
- **watch** for drift: ``list_changed`` on a legacy session's stream, a ``subscriptions/listen``
  stream on a modern one, a new session id in any answer, and a timer, since a hostile server
  won't announce its changes. Any change signal makes the connection ``STALE`` at once, and
  nothing is admitted until the listing has been compared again;
- **call** with the validated arguments registered with the egress filter first, under a hard
  deadline. A legacy session that expired is re-opened, and the call that hit the 404 is retried
  once if the tool is still admitted with the same pin. Nothing else is ever retried;
- **close** idle connections, the least recently used at the session limit, and those a policy
  change affects. A close cuts the connection's calls at once, except committed ones (approved
  calls, M4 design B.6): the session ends only after they finish, each within its deadline.
"""

from __future__ import annotations

import math
import random
import time
from collections.abc import Awaitable, Callable
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from typing import Any

import anyio
import mcp_types
from anyio.abc import TaskGroup
from mcp import Client, InputRequiredRoundsExceededError
from mcp.client.streamable_http import streamable_http_client
from mcp.client.subscriptions import ListenNotSupportedError, SubscriptionLost
from mcp.shared.dispatcher import ProgressFnT
from mcp.shared.exceptions import MCPError
from mcp.types import CallToolResult, Implementation, Tool
from pydantic import ValidationError

from ..common import canonical
from ..common.policy.schema import GatewayLimits
from ..common.policy.view import ViewGateway, ViewRemoteServer
from . import logs, pins
from .connstate import (
    ADMIT_WAIT,
    WAITING,
    Admit,
    ConnState,
    Era,
    Phase,
    Refuse,
    admit,
    connection_key,
    era_of,
    on_change,
    on_closed,
    on_connecting,
    on_list_failed,
    on_listed,
    on_session_expired,
    on_timer_failed,
    should_connect,
    supported_upstream_version,
)
from .defstore import DefinitionStore, changed_members
from .egressrules import CallRegistry
from .marks import DriftMarks
from .sanitize import Outcome
from .vaultlink import REFUSAL_HEADER, KeySource, Link, upstream_client, vault_refusal_code

CLIENT_INFO = Implementation(name="zoeymcp-gateway", version="1")
COALESCE = 5.0  # seconds between listings of one connection, at least
MIN_RELIST = 60.0  # the timer never re-lists more often than this
CLOSE_GRACE = 5.0  # seconds a closing connection may take, shielded
REAP_INTERVAL = 30.0
PROGRESS_INTERVAL = 0.1  # at most 10 progress notifications a second
LISTEN_BACKOFF_MAX = 300.0
REVIEW_KEY = "review"

Progress = Callable[[float, float | None], Awaitable[None]]


class UpstreamError(Exception):
    """A call or listing that didn't produce a result. ``outcome`` picks the agent's message."""

    def __init__(self, outcome: Outcome, detail: str = "") -> None:
        self.outcome = outcome
        self.detail = detail
        super().__init__(outcome)


class NotAdmitted(Exception):
    """The tool may not be called on this connection now (unknown, drifted, marked, blocked)."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class ListingFailed(Exception):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class _SessionExpired(Exception):
    """A legacy request got 404 for its session id."""


class _ConnectRefused(Exception):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def listing_bytes(tool: Tool) -> int:
    """The canonical size of one listed tool, for ``max_list_bytes``."""
    dumped = tool.model_dump(mode="json", by_alias=True, exclude_none=True)
    try:
        return len(canonical.dumps_canonical(dumped))
    except canonical.JSONRejected:
        return len(tool.model_dump_json(by_alias=True))


@dataclass
class _Listing:
    tools: list[Tool]
    pages: int
    size: int
    ttl_ms: int | None


class Connection:
    """One upstream connection and the task that owns it."""

    def __init__(
        self, pool: UpstreamPool, server: str, policy: ViewRemoteServer, key: tuple[str, str]
    ) -> None:
        self.pool = pool
        self.server = server
        self.policy = policy
        self.key = key
        self.state = ConnState()
        self.changed = anyio.Event()
        self.registry = CallRegistry()
        self.client: Client | None = None
        self.era: Era | None = None
        self.tools: list[Tool] = []
        self.instructions: str | None = None
        self.server_info: Implementation | None = None
        self.session_id: str | None = None
        # Why the connection failed, and the vault's last refusal (status, code), for review.
        self.failure: str | None = None
        self.vault_refusal: tuple[int, str | None] | None = None
        self.in_flight = 0
        self.holds = 0  # downstream listeners that keep this connection open
        # Each call's cancel scope, with its deadline if it is committed (None if not).
        self._calls: dict[anyio.CancelScope, float | None] = {}
        self.closing = False
        self.last_used = pool.clock()
        self.running = False
        self.done = anyio.Event()
        self._close = anyio.Event()
        self._end_session = anyio.Event()
        self._list_wanted = anyio.Event()
        self._list_trigger = "connect"
        self._last_listing = -math.inf
        self._ttl_ms: int | None = None
        self._expired = False

    # --- state --------------------------------------------------------------------------

    @property
    def label(self) -> str:
        return self.key[1]

    def _set(self, state: ConnState) -> None:
        old, self.state = self.state, state
        self.changed.set()
        self.changed = anyio.Event()
        # The first listing creates the view rather than changing it: nobody has seen another.
        if state.version != old.version and old.version > 0:
            self.pool.view_changed(self)

    def idle(self, now: float, timeout: float) -> bool:
        return self.in_flight == 0 and self.holds == 0 and now - self.last_used > timeout

    @property
    def committed(self) -> int:
        """Committed calls still running on this connection."""
        return sum(1 for deadline in self._calls.values() if deadline is not None)

    def committed_deadline(self) -> float | None:
        deadlines = [d for d in self._calls.values() if d is not None]
        return max(deadlines) if deadlines else None

    def request_close(self) -> None:
        """End the session. Uncommitted calls are cut now; committed ones finish first."""
        self.closing = True
        for scope, deadline in list(self._calls.items()):
            if deadline is None:
                scope.cancel()
        if self.committed:
            logs.event(
                "upstream_draining", server=self.server, key=self.label, committed=self.committed
            )
            return  # the last committed call ends the session
        self._end()

    def cancel_committed(self) -> int:
        """Past every deadline (shutdown's backstop): cut the committed calls too."""
        found = [scope for scope, deadline in self._calls.items() if deadline is not None]
        for scope in found:
            scope.cancel()
        return len(found)

    def _end(self) -> None:
        self._close.set()
        self._end_session.set()
        if not self.running:
            self._set(on_closed(self.state))
            self.done.set()

    def change(self, trigger: str) -> None:
        """A change signal: STALE at once, and a listing as soon as one may run."""
        if self.state.phase in (Phase.READY, Phase.STALE):
            self._set(on_change(self.state))
            self.want_listing(trigger)

    def want_listing(self, trigger: str) -> None:
        self._list_trigger = trigger
        self._list_wanted.set()

    # --- notes from the transport and the SDK -------------------------------------------------

    def noted(self, request: Any, response: Any) -> None:
        """Called by the egress transport for every answer."""
        if response.headers.get(REFUSAL_HEADER) == "refused":
            self.vault_refusal = (response.status_code, vault_refusal_code(response.content))
        session = response.headers.get("mcp-session-id")
        if session:
            if self.session_id is None:
                self.session_id = session
            elif session != self.session_id:
                self.session_id = session
                logs.event("upstream_session_changed", server=self.server, key=self.label)
                self.change("new_session")
        if response.status_code == 404 and request.headers.get("mcp-session-id"):
            self._expired = True
            if self.state.phase in (Phase.READY, Phase.STALE):
                self._set(on_session_expired(self.state))
                self._end_session.set()

    async def message(self, message: object) -> None:
        """The SDK's message handler: only ``tools/list_changed`` matters; the rest is dropped."""
        if getattr(message, "method", None) == "notifications/tools/list_changed":
            self.change("list_changed")

    # --- the owner task ---------------------------------------------------------------------

    async def own(self) -> None:
        self.running = True
        try:
            while not self._close.is_set():
                self._set(on_connecting(self.state))
                self._end_session = anyio.Event()
                self._expired = False
                self.session_id = None
                try:
                    await self._session()
                except Exception as exc:  # the connection's own failure; the pool goes on
                    if self._close.is_set() or self.state.phase is Phase.RECONNECTING:
                        # Leaving a session that was meant to end (closed, or expired upstream)
                        # may raise from the SDK's own shutdown; that is part of ending it.
                        continue
                    reason = (
                        exc.reason if isinstance(exc, _ConnectRefused | ListingFailed) else "error"
                    )
                    self.failure = reason if reason != "error" else type(_leaf(exc)).__name__
                    logs.event(
                        "upstream_closed",
                        server=self.server,
                        key=self.label,
                        reason=reason,
                        error_type=type(_leaf(exc)).__name__,
                    )
                    if self.state.phase is not Phase.FAILED:
                        self._set(on_list_failed(self.state, self.pool.clock()))
                    return
                if self.state.phase is not Phase.RECONNECTING:
                    return
        finally:
            self.client = None
            self.running = False
            if self._close.is_set() or self.state.phase is not Phase.FAILED:
                self._set(on_closed(self.state))
            self.pool.drained(self)
            self.done.set()

    async def _session(self) -> None:
        limits = self.pool.limits
        http = upstream_client(
            self.pool.link,
            self.pool.keys,
            server=self.server,
            vault_path=self.policy.vault_path,
            registry=self.registry,
            max_json_bytes=limits.max_upstream_message_bytes,
            on_response=self.noted,
            inner=self.pool.inner_transport(),
        )
        url = self.pool.link.base_url + self.policy.vault_path
        # One scope holds the whole session, so every context is left in the task and scope
        # that entered it. Its deadline bounds the connect and first listing (list_timeout), is
        # lifted while the session runs, and bounds the close (CLOSE_GRACE).
        scope = anyio.CancelScope(deadline=anyio.current_time() + limits.list_timeout)
        listed = False
        try:
            with scope:
                async with AsyncExitStack() as stack:
                    try:
                        await stack.enter_async_context(http)
                        transport = streamable_http_client(
                            url,
                            http_client=http,
                            terminate_on_close=True,
                            max_sse_event_size=limits.max_upstream_message_bytes,
                        )
                        client = Client(
                            transport,
                            mode="legacy" if self.policy.era == "legacy" else "auto",
                            client_info=CLIENT_INFO,
                            cache=None,
                            input_required_max_rounds=0,
                            message_handler=self.message,
                        )
                        client = await stack.enter_async_context(client)
                        self._connected(client)
                        await self._list("connect", timer=False)
                        listed = True
                        scope.deadline = math.inf
                        if self.state.phase is Phase.READY:
                            await self._watch()
                    finally:
                        self.client = None
                        scope.deadline = min(scope.deadline, anyio.current_time() + CLOSE_GRACE)
            if scope.cancelled_caught and not listed:
                raise ListingFailed("timeout")
        finally:
            logs.event(
                "upstream_closed",
                server=self.server,
                key=self.label,
                reason="session_expired" if self._expired else "closed",
            )

    async def _watch(self) -> None:
        """Watch for drift until the session should end."""
        async with anyio.create_task_group() as group:
            group.start_soon(self._lister)
            group.start_soon(self._timer)
            if self.era == "modern":
                group.start_soon(self._listen)
            await self._end_session.wait()
            group.cancel_scope.cancel()

    def _connected(self, client: Client) -> None:
        version = client.protocol_version
        if not supported_upstream_version(version):
            logs.event("upstream_version_unsupported", server=self.server, to=version)
            raise _ConnectRefused("version")
        era = era_of(version)
        if self.policy.era == "modern" and era == "legacy":
            logs.event("upstream_era_mismatch", server=self.server, **{"from": "modern", "to": era})
            raise _ConnectRefused("era")
        known = self.pool.eras.get(self.server)
        if known is not None and known != era:
            logs.event("upstream_era_changed", server=self.server, **{"from": known, "to": era})
        self.pool.eras[self.server] = era
        self.era = era
        self.client = client
        self.instructions = client.instructions
        self.server_info = client.server_info
        logs.event(
            "upstream_connected",
            server=self.server,
            key=self.label,
            era=era,
            protocol_version=version,
        )

    # --- listings ----------------------------------------------------------------------------

    async def _walk(self, client: Client) -> _Listing:
        limits = self.pool.limits
        tools: list[Tool] = []
        size = 0
        seen: set[str] = set()
        cursor: str | None = None
        ttl: int | None = None
        pages = 0
        while True:
            if pages >= limits.max_list_pages:
                raise ListingFailed("pages")
            page = await client.list_tools(cursor=cursor)
            pages += 1
            tools.extend(page.tools)
            size += sum(listing_bytes(tool) for tool in page.tools)
            if len(tools) > limits.max_tools_per_server:
                raise ListingFailed("tools")
            if size > limits.max_list_bytes:
                raise ListingFailed("bytes")
            page_ttl = getattr(page, "ttl_ms", None)
            if isinstance(page_ttl, int) and page_ttl > 0:
                ttl = page_ttl if ttl is None else min(ttl, page_ttl)
            cursor = page.next_cursor
            if cursor is None:
                return _Listing(tools, pages, size, ttl)
            if cursor in seen:
                raise ListingFailed("cursor_loop")
            seen.add(cursor)

    async def _list(self, trigger: str, *, timer: bool) -> None:
        client = self.client
        if client is None:
            return
        self._last_listing = self.pool.clock()
        try:
            with anyio.fail_after(self.pool.limits.list_timeout):
                listing = await self._walk(client)
        except (ListingFailed, MCPError, TimeoutError, ValidationError) as exc:
            reason = exc.reason if isinstance(exc, ListingFailed) else type(exc).__name__
            if isinstance(exc, TimeoutError):
                reason = "timeout"
            logs.event("server_list_failed", server=self.server, key=self.label, reason=reason)
            self.failure = reason
            now = self.pool.clock()
            interval = float(self.policy.drift_check_interval)
            failed = (
                on_timer_failed(self.state, now, interval)
                if timer
                else on_list_failed(self.state, now)
            )
            self._set(failed)
            if failed.phase is Phase.FAILED:
                self._end_session.set()
            return
        self.tools = listing.tools
        self._ttl_ms = listing.ttl_ms
        evaluation = self.pool.evaluate(self.server, self.policy, listing.tools)
        logs.event(
            "listing",
            server=self.server,
            key=self.label,
            trigger=trigger,
            pages=listing.pages,
            tools=len(listing.tools),
            bytes=listing.size,
            result="ok",
        )
        self._set(on_listed(self.state, evaluation, self.pool.clock()))

    def reevaluate(self, policy: ViewRemoteServer) -> None:
        """A policy change to include, review or on_drift: compare the last listing again."""
        self.policy = policy
        if self.state.evaluation is None or self.state.phase is not Phase.READY:
            return
        evaluation = self.pool.evaluate(self.server, policy, self.tools)
        self._set(on_listed(self.state, evaluation, self.state.verified_at or self.pool.clock()))

    async def _lister(self) -> None:
        """Runs wanted listings, at most one at a time and :data:`COALESCE` seconds apart."""
        while True:
            await self._list_wanted.wait()
            wait = self._last_listing + COALESCE - self.pool.clock()
            if wait > 0:
                await anyio.sleep(wait)
            self._list_wanted = anyio.Event()
            trigger = self._list_trigger
            await self._list(trigger, timer=trigger == "timer")

    def relist_interval(self) -> float:
        interval = float(self.policy.drift_check_interval)
        if self._ttl_ms is not None:
            interval = min(interval, self._ttl_ms / 1000)
        return max(MIN_RELIST, interval)

    async def _timer(self) -> None:
        while True:
            await anyio.sleep(self.relist_interval() * random.uniform(0.9, 1.1))  # noqa: S311
            if not self._list_wanted.is_set():
                self.want_listing("timer")

    async def _listen(self) -> None:
        client = self.client
        if client is None:
            return
        delay = 1.0
        while True:
            try:
                async with client.listen(tools_list_changed=True) as subscription:
                    delay = 1.0
                    async for _event in subscription:
                        self.change("list_changed")
            except ListenNotSupportedError:
                return
            except (SubscriptionLost, MCPError, TimeoutError, anyio.EndOfStream):
                # Nothing is replayed, so whatever happened meanwhile is unknown.
                self.change("subscription_lost")
            await anyio.sleep(delay * random.uniform(0.5, 1.5))  # noqa: S311
            delay = min(LISTEN_BACKOFF_MAX, delay * 2)

    # --- calls -------------------------------------------------------------------------------

    async def call(
        self,
        tool: str,
        arguments: dict[str, Any],
        *,
        timeout: float,
        progress: Progress | None = None,
        committed: bool = False,
    ) -> CallToolResult:
        """One call. A committed call (an approved one) keeps the session open until it ends:
        a close waits for it. Any other call is cut when the connection closes."""
        client = self.client
        if client is None or self.closing:
            raise UpstreamError("unavailable", "not connected")
        digest = canonical.digest(arguments)
        self.registry.register(tool, digest)
        self.in_flight += 1
        self.last_used = self.pool.clock()
        scope = anyio.CancelScope()
        self._calls[scope] = anyio.current_time() + timeout if committed else None
        try:
            with scope:
                try:
                    with anyio.fail_after(timeout):
                        result = await client.call_tool(
                            tool,
                            arguments,
                            progress_callback=_progress_relay(progress, self.pool.clock),
                        )
                except BaseException as exc:
                    # A registration that never went out is withdrawn. If it did go out and
                    # the call then failed, this may withdraw a concurrent identical call's
                    # registration, which then fails closed.
                    self.registry.withdraw(tool, digest)
                    raise self._call_error(exc) from exc
        finally:
            self.in_flight -= 1
            self.last_used = self.pool.clock()
            del self._calls[scope]
            if self.closing and committed and not self.committed:
                self._end()
        if scope.cancelled_caught:
            # The connection closed under the call: as M3 reported a session ended under it.
            raise UpstreamError("connection_lost", "closed")
        if result.result_type not in (None, "complete"):
            raise UpstreamError("unsupported_result", str(result.result_type))
        return result

    def _call_error(self, exc: BaseException) -> BaseException:
        if isinstance(exc, anyio.get_cancelled_exc_class()):
            return exc
        if isinstance(exc, TimeoutError):
            return UpstreamError("timeout")
        if isinstance(exc, InputRequiredRoundsExceededError):
            logs.event("upstream_input_required_refused", server=self.server)
            return UpstreamError("input_required")
        if isinstance(exc, MCPError):
            if self._expired:
                return _SessionExpired()
            if _sdk_closed(exc):
                return UpstreamError("connection_lost")
            logs.event(
                "upstream_error",
                server=self.server,
                code=exc.error.code,
                message_bytes=len(exc.error.message.encode()),
            )
            return UpstreamError("rpc_error")
        if isinstance(exc, ValidationError):
            return UpstreamError("unsupported_result", "invalid result")
        return UpstreamError("connection_lost", type(exc).__name__)


def _progress_relay(sink: Progress | None, clock: Callable[[], float]) -> ProgressFnT | None:
    """Numbers only, at most 10 a second: the upstream's free-text ``message`` is dropped."""
    if sink is None:
        return None
    last = -math.inf

    async def relay(progress: float, total: float | None, message: str | None) -> None:
        nonlocal last
        now = clock()
        if now - last < PROGRESS_INTERVAL:
            return
        last = now
        await sink(progress, total)

    return relay


def _sdk_closed(error: MCPError) -> bool:
    """The SDK's own "connection closed", not an upstream error that uses the same code.

    ``CONNECTION_CLOSED`` is -32000, the first implementation-defined server error code, which
    upstreams use for anything. An upstream that also copies the message only gets the more
    cautious "may or may not have run".
    """
    return (
        error.error.code == mcp_types.CONNECTION_CLOSED
        and error.error.message == "Connection closed"
        and error.error.data is None
    )


def _leaf(error: BaseException) -> BaseException:
    while isinstance(error, BaseExceptionGroup) and len(error.exceptions) == 1:
        error = error.exceptions[0]
    return error


@dataclass
class UpstreamPool:
    """Every upstream connection of one gateway process."""

    link: Link
    keys: KeySource | None
    marks: DriftMarks
    defs: DefinitionStore
    limits: GatewayLimits = field(default_factory=GatewayLimits)
    clock: Callable[[], float] = time.monotonic
    on_view_change: Callable[[Connection], None] | None = None
    # Tests swap in a transport that reaches the vault differently; None is the real one.
    transport_factory: Callable[[], Any] | None = None
    eras: dict[str, Era] = field(default_factory=dict)
    _connections: dict[tuple[str, str], Connection] = field(default_factory=dict)
    # Closed connections whose committed calls are still running (M4 design B.6).
    _draining: set[Connection] = field(default_factory=set)
    _group: TaskGroup | None = None
    _reported: set[tuple[str, str, str, str | None]] = field(default_factory=set)

    def inner_transport(self) -> Any:
        return self.transport_factory() if self.transport_factory is not None else None

    async def run(
        self, *, task_status: anyio.abc.TaskStatus[None] = anyio.TASK_STATUS_IGNORED
    ) -> None:
        """Hosts the owner tasks and the idle reaper until cancelled; then closes everything."""
        try:
            async with anyio.create_task_group() as group:
                self._group = group
                group.start_soon(self._reaper)
                task_status.started()
                await anyio.sleep_forever()
        finally:
            self._group = None

    async def aclose(self) -> None:
        """Close every connection, each within its grace period, after any committed calls
        finish within their deadlines; past those, cut them too."""
        connections = [*self._connections.values(), *self._draining]
        for connection in connections:
            connection.request_close()
        deadlines = [d for c in connections if (d := c.committed_deadline()) is not None]
        wait = max([0.0, *(d - anyio.current_time() for d in deadlines)]) + CLOSE_GRACE + 1
        with anyio.move_on_after(wait, shield=True):
            for connection in connections:
                await connection.done.wait()
        overdue = sum(c.cancel_committed() for c in connections if not c.done.is_set())
        if overdue:
            logs.event("upstream_close_overdue", cancelled=overdue, level="error")
            with anyio.move_on_after(CLOSE_GRACE + 1, shield=True):
                for connection in connections:
                    await connection.done.wait()
        self._connections.clear()
        self._draining.clear()

    def drained(self, connection: Connection) -> None:
        """A connection's owner task ended."""
        self._draining.discard(connection)

    # --- connections ---------------------------------------------------------------------------

    def connection(self, server: str, policy: ViewRemoteServer, client: str) -> Connection:
        """The connection a client's request to a server uses, connecting it if needed."""
        key = connection_key(server, policy, self.eras.get(server), client)
        found = self._connections.get(key)
        now = self.clock()
        if found is not None and found.state.phase is not Phase.CLOSED:
            if not found.running and should_connect(found.state, now):
                self._start(found)
            return found
        connection = Connection(self, server, policy, key)
        if found is not None:
            connection.state = ConnState(version=found.state.version, failures=found.state.failures)
        self._make_room(now)
        self._connections[key] = connection
        self._start(connection)
        return connection

    def review_connection(self, server: str, policy: ViewRemoteServer) -> Connection:
        """A fresh connection for ``review``, never shared and never pooled."""
        connection = Connection(self, server, policy, (server, REVIEW_KEY))
        self._start(connection)
        return connection

    def _start(self, connection: Connection) -> None:
        if self._group is None:
            raise UpstreamError("unavailable", "the pool isn't running")
        connection.done = anyio.Event()
        connection.running = True
        self._group.start_soon(connection.own)

    def _make_room(self, now: float) -> None:
        open_ = [c for c in self._connections.values() if c.state.phase is not Phase.CLOSED]
        if len(open_) + len(self._draining) < self.limits.max_upstream_sessions:
            return
        idle = sorted(
            (c for c in open_ if c.in_flight == 0 and c.holds == 0), key=lambda c: c.last_used
        )
        if not idle:
            raise UpstreamError("unavailable", "gateway busy")
        idle[0].request_close()
        self._connections.pop(idle[0].key, None)

    async def _reaper(self) -> None:
        while True:
            await anyio.sleep(REAP_INTERVAL)
            self.reap()

    def reap(self) -> None:
        now = self.clock()
        for key, connection in list(self._connections.items()):
            if connection.state.phase is Phase.CLOSED and not connection.running:
                self._connections.pop(key, None)
            elif connection.idle(now, self.limits.upstream_idle_timeout):
                logs.event("upstream_idle", server=connection.server, key=connection.label)
                connection.request_close()

    def connections(self) -> list[Connection]:
        return list(self._connections.values())

    # --- admission and calls -----------------------------------------------------------------

    async def wait_ready(self, connection: Connection) -> pins.Evaluation:
        """The connection's evaluation once READY, waiting up to :data:`ADMIT_WAIT` for it."""
        started = self.clock()
        while True:
            state = connection.state
            if state.phase is Phase.READY and state.evaluation is not None:
                return state.evaluation
            if state.phase not in WAITING:
                raise NotAdmitted(f"connection {state.phase.value}")
            await self._wait_change(connection, started)

    async def admit(self, connection: Connection, tool: str) -> str:
        """The pin a call to ``tool`` goes out under, or :class:`NotAdmitted`."""
        started = self.clock()
        while True:
            decision = admit(
                connection.state,
                self.marks.for_server(connection.server),
                tool,
                self.clock(),
                started,
            )
            if isinstance(decision, Admit):
                return decision.pin
            if isinstance(decision, Refuse):
                raise NotAdmitted(decision.reason)
            await self._wait_change(connection, started)

    async def _wait_change(self, connection: Connection, started: float) -> None:
        remaining = started + ADMIT_WAIT - self.clock()
        with anyio.move_on_after(max(0.0, remaining)):
            await connection.changed.wait()
        if self.clock() - started >= ADMIT_WAIT and connection.state.phase is not Phase.READY:
            raise NotAdmitted("upstream not ready in time")

    async def call(
        self,
        server: str,
        policy: ViewRemoteServer,
        client: str,
        tool: str,
        arguments: dict[str, Any],
        *,
        pin: str | None = None,
        progress: Progress | None = None,
        committed: bool = False,
        retry_expired: bool = True,
    ) -> CallToolResult:
        """Admit and call. A legacy session that expired is re-opened and the call retried once,
        if the tool is still admitted with the same pin.

        ``pin`` is the one the arguments were validated under: if the tool is admitted under
        another one now, nothing is sent. An approved call is ``committed`` (a close waits for
        it) and never retried (``retry_expired=False``): only the upstream's 404 says the first
        try never ran (M4 design B.6).
        """
        timeout = float(policy.call_timeout or self.limits.call_timeout)
        connection = self.connection(server, policy, client)
        admitted = await self.admit(connection, tool)
        if pin is not None and admitted != pin:
            raise NotAdmitted("pin changed after validation")
        pin = admitted
        try:
            return await connection.call(
                tool, arguments, timeout=timeout, progress=progress, committed=committed
            )
        except _SessionExpired as exc:
            if not retry_expired:
                raise UpstreamError("connection_lost", "session_expired") from exc
        connection = self.connection(server, policy, client)
        if await self.admit(connection, tool) != pin:
            raise NotAdmitted("pin changed after the session expired")
        try:
            return await connection.call(
                tool, arguments, timeout=timeout, progress=progress, committed=committed
            )
        except _SessionExpired as exc:
            raise UpstreamError("connection_lost", "session expired twice") from exc

    # --- evaluation and reports ----------------------------------------------------------------

    def evaluate(self, server: str, policy: ViewRemoteServer, tools: list[Tool]) -> pins.Evaluation:
        evaluation = pins.evaluate(tools, policy, self.marks.for_server(server), self.limits)
        added, removed = self.marks.replace(server, evaluation.marks)
        for tool, _ in sorted(added):
            logs.event("drift_marked", server=server, tool=tool)
        if removed:
            logs.event(
                "drift_cleared", server=server, tools=sorted(t for t, _ in removed), by="policy"
            )
        for exposed in evaluation.exposed.values():
            self.defs.put(exposed.pin, exposed.definition)
        for report in evaluation.reports:
            self._report(server, report)
        if evaluation.blocked:
            self._report(server, pins.Report("drift", "*", pin="blocked"), kind="server_blocked")
        return evaluation

    def _report(self, server: str, report: pins.Report, kind: str | None = None) -> None:
        """One log line per (server, tool, kind, observed pin) per process."""
        event = kind or f"tool_{report.kind}"
        key = (server, report.tool, event, report.pin)
        if key in self._reported:
            return
        self._reported.add(key)
        fields: dict[str, Any] = {"server": server}
        if event == "server_blocked":
            fields["reason"] = "on_drift"
        else:
            fields["tool"] = report.tool
        if report.kind == "drift" and event != "server_blocked":
            fields.update(pinned=report.pinned, observed=report.pin)
            old = self.defs.get(report.pinned) if report.pinned else None
            if old is not None:
                new = next(
                    (
                        pins.project_and_pin(tool).definition
                        for connection in self._connections.values()
                        for tool in connection.tools
                        if tool.name == report.tool
                    ),
                    None,
                )
                if new is not None:
                    fields["changed"] = changed_members(old, new)
        elif report.kind in ("unreviewed",):
            fields["observed"] = report.pin
        elif report.kind == "invalid":
            fields["reason"] = "projection" if report.pin is None else "rules"
        logs.event(event, **fields)

    def view_changed(self, connection: Connection) -> None:
        if self.on_view_change is not None:
            self.on_view_change(connection)

    # --- policy changes (D.3) ----------------------------------------------------------------

    def apply(self, gateway: ViewGateway) -> None:
        """A new view: close what it invalidates, and re-evaluate what it only re-pins."""
        self.limits = gateway.limits
        for key, connection in list(self._connections.items()):
            server, holder = key
            policy = gateway.servers.get(server)
            if not isinstance(policy, ViewRemoteServer) or _reopen(connection.policy, policy):
                self._close(key, connection, "policy")
                continue
            if holder not in ("*", REVIEW_KEY):
                client = gateway.clients.get(holder)
                if client is None or server not in client.servers:
                    self._close(key, connection, "policy")
                    continue
            if _repinned(connection.policy, policy):
                connection.reevaluate(policy)
            else:
                connection.policy = policy

    def _close(self, key: tuple[str, str], connection: Connection, reason: str) -> None:
        logs.event(
            "upstream_closing", server=connection.server, key=connection.label, reason=reason
        )
        connection.request_close()
        self._connections.pop(key, None)
        if connection.committed:
            self._draining.add(connection)

    def close_all(self, reason: str) -> None:
        for key, connection in list(self._connections.items()):
            self._close(key, connection, reason)


def _reopen(old: ViewRemoteServer, new: ViewRemoteServer) -> bool:
    """D.3: these changes close the server's connections; they reopen lazily."""
    return (
        old.vault_path != new.vault_path
        or old.era != new.era
        or old.shared_session != new.shared_session
        or old.call_timeout != new.call_timeout
        or old.drift_check_interval != new.drift_check_interval
    )


def _repinned(old: ViewRemoteServer, new: ViewRemoteServer) -> bool:
    return old.tools != new.tools or old.review != new.review or old.on_drift != new.on_drift
