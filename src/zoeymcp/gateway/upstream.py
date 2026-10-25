"""Upstream connections: the pool, each connection's owner task, listings, drift and calls.

M3 design F.3 to F.7, G.3 and G.5. One connection per key from :func:`connstate.connection_key`.
Each is owned by one task, which enters and leaves the HTTP client, the transport and the SDK
``Client`` (anyio cancel scopes must be left by the task that entered them). Request tasks call
the open client directly, so cancelling a request cancels its SDK call.

The decisions live in pure modules: :mod:`.connstate` says whether a call may go out,
:mod:`.pins` evaluates each listing, :mod:`.egressrules` checks every request on the wire. This
module does the I/O around them:

- **connect** lazily, on the first request that needs the connection, then list and evaluate,
  every kind the server enables after its tools (M6 design L.4): prompts, resource templates and
  fixed resources, each walk under its own caps and failing on its own, never the tools;
- **watch** for drift: ``list_changed`` on a legacy session's stream, a ``subscriptions/listen``
  stream on a modern one, a new session id in any answer, and a timer, since a hostile server
  won't announce its changes. Any change signal makes the connection ``STALE`` at once, and
  nothing is admitted until the listing has been compared again;
- **call** with the validated arguments registered with the egress filter first, under a hard
  deadline. A legacy session that expired is re-opened, and the call that hit the 404 is retried
  once if the tool is still admitted with the same pin. Nothing else is ever retried but the
  requests of the kinds beyond tools (M6 design L.6: ``prompts/get``, ``resources/read`` and
  ``completion/complete``), which change nothing, and are retried the same way;
- **close** idle connections, the least recently used at the session limit, and those a policy
  change affects. A close cuts the connection's calls at once, except committed ones (approved
  calls, M4 design B.6): the session ends only after they finish, each within its deadline.
"""

from __future__ import annotations

import math
import random
import time
from collections.abc import Awaitable, Callable, Mapping
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from typing import Any, Final, TypeVar

import anyio
import mcp_types
from anyio.abc import TaskGroup
from mcp import Client, InputRequiredRoundsExceededError
from mcp.client.streamable_http import streamable_http_client
from mcp.client.subscriptions import ListenNotSupportedError, SubscriptionLost
from mcp.shared.dispatcher import ProgressFnT
from mcp.shared.exceptions import MCPError
from mcp.types import CallToolResult, Implementation, Tool
from pydantic import BaseModel, ValidationError

from ..common import canonical
from ..common.policy.schema import GatewayLimits
from ..common.policy.view import ViewGateway, ViewRemoteServer
from . import logs, pins
from .capabilities import ServedKinds
from .connstate import (
    ADMIT_WAIT,
    WAITING,
    Admit,
    ConnState,
    Era,
    Phase,
    Refuse,
    admit,
    changed_kinds,
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
# A legacy session's list_changed for a kind beyond tools, by the enable entry that lists it.
LIST_CHANGED: Final[Mapping[str, str]] = {
    "notifications/prompts/list_changed": "prompts",
    "notifications/resources/list_changed": "resources",
}

Progress = Callable[[float, float | None], Awaitable[None]]
T = TypeVar("T")


class UpstreamError(Exception):
    """A call or listing that didn't produce a result. ``outcome`` picks the agent's message;
    ``code`` is an upstream JSON-RPC error's, which a prompt, resource or completion request
    maps to its own fixed answer (M6 design L.6), never the upstream's message."""

    def __init__(self, outcome: Outcome, detail: str = "", code: int | None = None) -> None:
        self.outcome = outcome
        self.detail = detail
        self.code = code
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


def listing_bytes(tool: BaseModel) -> int:
    """The canonical size of one listed tool, or prompt or resource, for ``max_list_bytes``."""
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
        # The latest listing of each kind beyond tools the server enables (L.4).
        self.listings: dict[pins.DefinitionKind, pins.KindListing] = {}
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
        # The session's scope, whose deadline bounds the connect and its first listing.
        self._scope: anyio.CancelScope | None = None

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
            self.pool.view_changed(self, changed_kinds(old.evaluation, state.evaluation))

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
        """The SDK's message handler: only ``tools/list_changed`` matters, and the prompts' and
        resources' when the server enables them; the rest is dropped."""
        method = getattr(message, "method", None)
        if method == "notifications/tools/list_changed" or (
            isinstance(method, str) and LIST_CHANGED.get(method) in self.policy.enable
        ):
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
            enabled=frozenset(self.policy.enable),
        )
        url = self.pool.link.base_url + self.policy.vault_path
        # One scope holds the whole session, so every context is left in the task and scope
        # that entered it. Its deadline bounds the connect and first listing (list_timeout), is
        # lifted while the session runs, and bounds the close (CLOSE_GRACE).
        scope = anyio.CancelScope(deadline=anyio.current_time() + limits.list_timeout)
        self._scope = scope
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

    async def _page(
        self, client: Client, kind: pins.DefinitionKind, cursor: str | None
    ) -> tuple[list[BaseModel], str | None]:
        """One page of a kind beyond tools."""
        if kind == "prompt":
            prompts = await client.list_prompts(cursor=cursor)
            return list(prompts.prompts), prompts.next_cursor
        if kind == "resource_template":
            templates = await client.list_resource_templates(cursor=cursor)
            return list(templates.resource_templates), templates.next_cursor
        resources = await client.list_resources(cursor=cursor)
        return list(resources.resources), resources.next_cursor

    async def _walk_kind(self, client: Client, kind: pins.DefinitionKind) -> pins.KindListing:
        """One kind's listing under ``max_list_pages``, ``max_list_bytes`` and a cap of
        ``max_tools_per_server``, counted apart from the tools (L.4). Over a cap it fails that
        kind, except ``resources/list``, which keeps what it listed by then, cut: a review's, so a
        fixed resource can be included at a pin the review learned (OPS-11), and to serve, so an
        included URI not seen by then is missing and the ones seen still match their pins. To
        serve, the ``resources/list`` walk stops once every included fixed URI is listed."""
        limits = self.pool.limits
        review = self.key[1] == REVIEW_KEY
        wanted = (
            set(self.policy.resources.fixed.include) if kind == "resource" and not review else None
        )
        items: list[BaseModel] = []
        size = 0
        seen: set[str] = set()
        cursor: str | None = None
        pages = 0
        while not (wanted is not None and not wanted):
            if pages >= limits.max_list_pages:
                return self._over(kind, items, "pages")
            page, cursor = await self._page(client, kind, cursor)
            pages += 1
            for item in page:
                more = listing_bytes(item)
                if len(items) >= limits.max_tools_per_server:
                    return self._over(kind, items, "entries")
                if size + more > limits.max_list_bytes:
                    return self._over(kind, items, "bytes")
                items.append(item)
                size += more
                if wanted is not None:
                    wanted.discard(pins.key_of(kind, item))
                    if not wanted:  # every included fixed URI is listed: enough to serve
                        break
            if cursor is None:
                break
            if cursor in seen:
                raise ListingFailed("cursor_loop")
            seen.add(cursor)
        return pins.KindListing(items)

    def _over(
        self, kind: pins.DefinitionKind, items: list[BaseModel], reason: str
    ) -> pins.KindListing:
        if kind == "resource":
            logs.event(
                "kind_list_cut",
                server=self.server,
                key=self.label,
                definition_kind=kind,
                reason=reason,
                listed=len(items),
            )
            return pins.KindListing(items, cut=True)
        raise ListingFailed(reason)

    async def _list_kinds(self, client: Client) -> dict[pins.DefinitionKind, pins.KindListing]:
        """Every kind beyond tools the server enables, each walk failing on its own (SPEC-7):
        a failed kind lists nothing, so its included entries are missing, and the tools stand."""
        listings: dict[pins.DefinitionKind, pins.KindListing] = {}
        for kind in pins.enabled_kinds(self.policy.enable):
            scope = self._scope
            if scope is not None and scope.deadline != math.inf:
                # The connect's deadline covers its tools; each kind's walk has its own, so a
                # slow kind fails alone instead of the connect.
                wanted = anyio.current_time() + self.pool.limits.list_timeout + CLOSE_GRACE
                scope.deadline = max(scope.deadline, wanted)
            try:
                with anyio.fail_after(self.pool.limits.list_timeout):
                    listings[kind] = await self._walk_kind(client, kind)
            except (ListingFailed, MCPError, TimeoutError, ValidationError) as exc:
                reason = exc.reason if isinstance(exc, ListingFailed) else type(exc).__name__
                if isinstance(exc, TimeoutError):
                    reason = "timeout"
                logs.event(
                    "kind_list_failed",
                    server=self.server,
                    key=self.label,
                    definition_kind=kind,
                    reason=reason,
                )
                listings[kind] = pins.KindListing(failure=reason)
        return listings

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
        listings = await self._list_kinds(client)
        self.tools = listing.tools
        self.listings = listings
        self._ttl_ms = listing.ttl_ms
        evaluation = self.pool.evaluate(self.server, self.policy, listing.tools, listings)
        logs.event(
            "listing",
            server=self.server,
            key=self.label,
            trigger=trigger,
            pages=listing.pages,
            tools=len(listing.tools),
            bytes=listing.size,
            result="ok",
            **{f"{kind}s": len(found.items) for kind, found in listings.items()},
        )
        self._set(on_listed(self.state, evaluation, self.pool.clock()))

    def reevaluate(self, policy: ViewRemoteServer) -> None:
        """A policy change to include, review or on_drift: compare the last listing again. The
        serving walk of ``resources/list`` stops at the URIs the old policy included, so a newly
        included one it didn't list wants a listing too, rather than waiting for the timer."""
        self.policy = policy
        if self.state.evaluation is None or self.state.phase is not Phase.READY:
            return
        evaluation = self.pool.evaluate(self.server, policy, self.tools, self.listings)
        self._set(on_listed(self.state, evaluation, self.state.verified_at or self.pool.clock()))
        found = self.listings.get("resource")
        if found is not None:
            listed = {pins.key_of("resource", item) for item in found.items}
            if not set(policy.resources.fixed.include) <= listed:
                self.want_listing("policy")

    async def _lister(self) -> None:
        """Runs wanted listings, at most one at a time and :data:`COALESCE` seconds apart."""
        while True:
            await self._list_wanted.wait()
            wait = self._last_listing + COALESCE - self.pool.clock()
            if wait > 0:
                await anyio.sleep(wait)
            self._list_wanted = anyio.Event()
            trigger = self._list_trigger
            # The timer's, a stream open's and a new include's listings are background re-lists:
            # a failure keeps a READY connection's grace (on_timer_failed) instead of failing it.
            await self._list(trigger, timer=trigger in ("timer", "subscribed", "policy"))

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
        enabled = self.policy.enable
        while True:
            try:
                async with client.listen(
                    tools_list_changed=True,
                    prompts_list_changed="prompts" in enabled,
                    resources_list_changed="resources" in enabled,
                ) as subscription:
                    delay = 1.0
                    # A change announced before the stream was acknowledged reached no stream:
                    # list once it is open, and on every reopen (D-46). Not change(), which
                    # would hold calls until the listing; a listing already wanted absorbs it
                    # and keeps its trigger.
                    if not self._list_wanted.is_set():
                        self.want_listing("subscribed")
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

    async def request(self, send: Callable[[Client], Awaitable[T]], *, timeout: float) -> T:
        """One request of a kind beyond tools (M6 design L.6): ``send`` asks the open client.
        Nothing is registered (the egress filter allows these methods by the server's
        ``enable``); a close cuts it, as it cuts an uncommitted call."""
        client = self.client
        if client is None or self.closing:
            raise UpstreamError("unavailable", "not connected")
        self.in_flight += 1
        self.last_used = self.pool.clock()
        scope = anyio.CancelScope()
        self._calls[scope] = None
        try:
            with scope:
                try:
                    with anyio.fail_after(timeout):
                        result = await send(client)
                except BaseException as exc:
                    raise self._call_error(exc) from exc
        finally:
            self.in_flight -= 1
            self.last_used = self.pool.clock()
            del self._calls[scope]
        if scope.cancelled_caught:
            raise UpstreamError("connection_lost", "closed")
        result_type = getattr(result, "result_type", None)
        if result_type not in (None, "complete"):
            raise UpstreamError("unsupported_result", str(result_type))
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
            return UpstreamError("rpc_error", code=exc.error.code)
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
    # A connection's exposed view changed, in the lists named (M6 design L.5).
    on_view_change: Callable[[Connection, ServedKinds], None] | None = None
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

    async def request(
        self,
        server: str,
        policy: ViewRemoteServer,
        client: str,
        send: Callable[[Client], Awaitable[T]],
        *,
        admitted: Callable[[pins.Evaluation], bool],
    ) -> T:
        """A prompt, resource or completion request (M6 design L.6) on the client's connection,
        once it is READY and ``admitted`` says its evaluation still serves what is asked for (a
        prompt, a URI, a reference); :class:`NotAdmitted` otherwise. A legacy session that
        expired is re-opened and the request sent once more, on the same terms."""
        timeout = float(policy.call_timeout or self.limits.call_timeout)
        for attempt in range(2):
            connection = self.connection(server, policy, client)
            if not admitted(await self.wait_ready(connection)):
                raise NotAdmitted("not served")
            try:
                return await connection.request(send, timeout=timeout)
            except _SessionExpired as exc:
                if attempt:
                    raise UpstreamError("connection_lost", "session expired twice") from exc
        raise UpstreamError("connection_lost", "session expired twice")  # never reached

    # --- evaluation and reports ----------------------------------------------------------------

    def evaluate(
        self,
        server: str,
        policy: ViewRemoteServer,
        tools: list[Tool],
        listings: Mapping[pins.DefinitionKind, pins.KindListing] | None = None,
    ) -> pins.Evaluation:
        """Every kind of one listing (L.4), with each kind's marks updated, its matching
        definitions kept, and its reports logged."""
        listings = listings or {}
        marks = {kind: self.marks.for_server(server, kind) for kind in ("tool", *listings)}
        evaluation = pins.evaluate_server(tools, listings, policy, marks, self.limits)
        evaluated: list[tuple[pins.DefinitionKind, pins.Evaluation]] = [("tool", evaluation)]
        for kind, found in [*evaluated, *evaluation.kinds.items()]:
            added, removed = self.marks.replace(server, found.marks, kind)
            for name, _ in sorted(added):
                # A tool's lines keep their M3 fields; another kind's name its kind too.
                named = (
                    {"tool": name} if kind == "tool" else {"definition_kind": kind, "name": name}
                )
                logs.event("drift_marked", server=server, **named)
            if removed:
                cleared = sorted(name for name, _ in removed)
                which: dict[str, Any] = (
                    {"tools": cleared}
                    if kind == "tool"
                    else {"definition_kind": kind, "names": cleared}
                )
                logs.event("drift_cleared", server=server, **which, by="policy")
            for exposed in found.exposed.values():
                self.defs.put(exposed.pin, exposed.definition, kind)
            for report in found.reports:
                if report.kind != "declined":  # the operator's own record: nothing to log
                    self._report(server, report, definition=kind)
        if evaluation.blocked:
            self._report(server, pins.Report("drift", "*", pin="blocked"), kind="server_blocked")
        return evaluation

    def _now_listed(
        self, server: str, kind: pins.DefinitionKind, name: str
    ) -> Mapping[str, Any] | None:
        """The projection of ``name`` as a live connection to ``server`` lists it now, if one
        does: another server's same name is another definition."""
        for connection in self._connections.values():
            if connection.server != server:
                continue
            found = connection.listings.get(kind)
            items = connection.tools if kind == "tool" else (found.items if found else ())
            for item in items:
                if pins.key_of(kind, item) == name:
                    try:
                        return pins.project_kind(kind, item).definition
                    except pins.ProjectionError:
                        continue
        return None

    def _report(
        self,
        server: str,
        report: pins.Report,
        kind: str | None = None,
        definition: pins.DefinitionKind = "tool",
    ) -> None:
        """One log line per (server, tool, kind, observed pin) per process. Another kind's line
        is ``<kind>_<report>`` (``prompt_drift``), with its name as ``name`` (L.4)."""
        event = kind or f"{definition}_{report.kind}"
        key = (server, report.tool, event, report.pin)
        if key in self._reported:
            return
        self._reported.add(key)
        fields: dict[str, Any] = {"server": server}
        if event == "server_blocked":
            fields["reason"] = "on_drift"
        elif definition == "tool":
            fields["tool"] = report.tool
        else:
            fields["name"] = report.tool
        if report.kind == "drift" and event != "server_blocked":
            fields.update(pinned=report.pinned, observed=report.pin)
            old = self.defs.get(report.pinned, definition) if report.pinned else None
            if old is not None:
                new = self._now_listed(server, definition, report.tool)
                if new is not None:
                    fields["changed"] = changed_members(old, new)
        elif report.kind in ("unreviewed",):
            fields["observed"] = report.pin
        elif report.kind == "invalid":
            fields["reason"] = "projection" if report.pin is None else "rules"
        logs.event(event, **fields)

    def view_changed(self, connection: Connection, kinds: ServedKinds) -> None:
        if self.on_view_change is not None:
            self.on_view_change(connection, kinds)

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
        # What is listed, and what the egress filter lets the connection ask for (L.4).
        or old.enable != new.enable
    )


def _repinned(old: ViewRemoteServer, new: ViewRemoteServer) -> bool:
    return (
        old.tools != new.tools
        or old.review != new.review
        or old.declined != new.declined
        or old.on_drift != new.on_drift
        or old.prompts != new.prompts
        or old.resources != new.resources
    )
