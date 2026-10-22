"""The vault's HTTP proxy (design §4.1).

For each request, in order: normalize the path, pick the route by prefix, identify the caller,
match a rule, apply query and header policy, inject the credential, forward through the egress
proxy, then filter and scrub the response. Every refusal is logged with its reason; the response
body never says which check failed. Only after identity and a rule matched may a 502 carry a stable
``code`` (such as ``oauth_reconsent_needed``), so a caller entitled to the route can tell what the
operator must do. Every answer the vault makes itself carries ``x-zoeymcp-vault: refused``; relayed
answers never do, since ``x-zoeymcp-*`` headers from upstreams are dropped (M3 design C.4).

Each request is tagged with the listener it arrived on. On the link socket the caller is the
gateway, proved by the kernel; on TCP it is whoever presents a placeholder or a gateway key, and
when the link socket is configured TCP refuses gateway keys altogether (M3 design C.1).

Paths under ``/_zoeymcp/`` are the vault's own and never reach a route (no route prefix can start
with ``_``). :mod:`.internal`'s table decides them. Four are for the gateway only: its policy
view, a long poll that a reload wakes (M3 design D.1, D.2); the report path, where it pushes its
ledger to the vault's copy (M5 design J.2); and the review job path (M7 design F.2), a long poll
of the review jobs queued at the view it holds and the path it posts each job's result to. The
fifth is the egress role's allowlists (M7 design G.2), for its key alone and never on the link
socket: a long poll that a reload or an onboarding's allowance change wakes (I.3). The vault
keeps when the role last fetched and the digest it holds, for health's
``egress_allowlist_stale`` (J) and for an onboarding through the role, which waits for it to
fetch a widened list (:meth:`VaultApp.role_fetched`). Whether ``egress_proxy`` is the role is
the startup policy's ``egress_proxy_kind``, never guessed from the fetches. The rest are 404.
:meth:`VaultApp.queue_review` and :meth:`VaultApp.review_job` queue and read the jobs for the
admin socket and the portal, on :mod:`.reviewjobs`' table.

OAuth routes get an access token from the :class:`TokenManager`. An upstream 401 that says the
token is bad drops it, and a request that's safe to repeat is sent once more with a new token
(design D.10). Neither HTTP client keeps cookies: an upstream's session cookie must never reach
another caller (N2).

Every HTTP client is :mod:`.netclient`'s, guarded (M7 design B.2): an upstream or token endpoint
whose name resolves to a non-global address is refused before anything is sent, unless the
running policy lists its ``host:port`` in ``egress_private``. A route then answers 502
``address_refused``, and the token manager keeps the refusal for health (J). An upstream's
``WWW-Authenticate`` never reaches the gateway: the vault reads it for health, and a
``resource_metadata`` must reach nothing that could start OAuth discovery (DD-12, X17).

Streams on stream routes are relayed as they arrive, scrubbed one SSE event or NDJSON line at a
time. Answers to the gateway are scrubbed at any size, and an upstream redirect becomes a 502 for
it. Once the body is read the vault watches the caller: if it leaves while the vault waits for
upstream headers or relays the answer, the upstream request is closed (M3 design F.6, J.2).

A connector route has no upstream: after identity and a rule matched, the vault answers it
itself through :mod:`.connectors.smtp`, and a send isn't cut when the caller leaves (M4 design J).
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hmac
import http.cookiejar
import ipaddress
import json
import math
import os
import re
import time
import urllib.request
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Final, Literal
from urllib.parse import quote, urlsplit

import httpx
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import Receive, Scope, Send

from ..common import canonical, egresslist, ledgerreport, reviewreport
from ..common.egresslist import Allowance
from ..common.policy.match import NormalizedPath
from ..common.policy.schema import (
    BasicCredential,
    EgressProxyKind,
    GatewayLimits,
    HeaderCredential,
    OAuth2Credential,
    PathCredential,
    PlaceholderCaller,
    Policy,
    QueryCredential,
    RemoteServer,
    Route,
    SMTPConnector,
    ToolkitServer,
    is_secret_ref,
)
from ..common.policy.view import build_view, dump_view
from . import internal, logs, netclient, secretops
from .connectors.smtp import Answer, SmtpConnectors
from .gatewaykeys import GatewayKeys
from .keys import KeySet
from .oauth.discovery import Challenge, parse_challenge
from .oauth.protocol import CREDENTIAL_UNAVAILABLE, OAUTH_UNAVAILABLE
from .oauth.tokens import UPSTREAM_INSUFFICIENT_SCOPE, Grant, OAuthUnavailable, TokenManager
from .reports import Refused as ReportRefused
from .reportstore import CopyUnavailable, ReportStore
from .request import (
    NDJSONScrubber,
    RequestRejected,
    SSEScrubber,
    StreamEventTooLarge,
    apply_query_policy,
    encode_query,
    filter_request_headers,
    filter_response_headers,
    find_rule,
    normalize_path,
    parse_query,
    scrub,
    scrub_headers,
    secret_variants,
)
from .reviewjobs import (
    Job,
    JobTable,
    Owner,
    Result,
    ReviewRefused,
    ServerKind,
    named_job,
    read_result,
)
from .store import Secret, SecretStore, SecretUnavailable, smtp_binding

GATEWAY_HEADER = "x-zoeymcp-gateway"
# The egress role's key, for the allowlists alone (M7 design G.3).
EGRESS_HEADER = "x-zoeymcp-egress"
# Marks a connector's replayed answer: the key was seen, nothing was sent again (M4 design J.2).
REPLAYED_HEADER = "x-zoeymcp-replayed"
# Marks an answer the vault made itself, so the gateway can tell it from an upstream's (C.4).
REFUSAL_HEADER = "x-zoeymcp-vault"
REFUSAL_MARKER = "refused"
# The scope key the listener wrapper sets: "gateway" on the link socket, "tcp" elsewhere.
LISTENER_SCOPE_KEY = "zoeymcp.listener"
Listener = Literal["gateway", "tcp"]
# The vault's own endpoints (M7 design G.1): the gateway's view (M3 design D.1), its report path
# (M5 J.2) and the review job path (M7 F.2).
INTERNAL_SEGMENT = internal.SEGMENT
VIEW_PATH = internal.VIEW.path
REPORT_PATH = internal.LEDGER.path
REVIEW_JOBS_PATH = internal.REVIEW_JOBS.path
REVIEW_REPORT_PATH = internal.REVIEW_REPORT.path
ALLOWLIST_PATH = internal.ALLOWLISTS.path
# A report's body is read within this many seconds (M5 design J.2).
REPORT_DEADLINE = 10.0
# The longest ``?wait=`` in seconds, and how many may wait at once (M3 design D.2).
VIEW_MAX_WAIT = internal.VIEW_MAX_WAIT
VIEW_MAX_WAITERS = internal.VIEW_MAX_WAITERS
# A waiting allowlist poll looks again when an allowance expires, at most this often (seconds).
RECHECK_MIN = 0.05
# A review report nests a tool's definition four levels down (the result, the report, its tools,
# an entry), and a definition's pin is only computed within canonical's default depth.
REVIEW_MAX_DEPTH = canonical.DEFAULT_MAX_DEPTH + 4
# One entity tag of If-None-Match, weak or strong; the tag itself is the group.
_ENTITY_TAG = re.compile(r'\s*(?:W/)?"([\x21\x23-\x7e]*)"\s*')
MAX_REQUEST_BYTES = 10 * 1024 * 1024
MAX_RESPONSE_BYTES = 32 * 1024 * 1024
# Buffered answers to other callers are scrubbed up to this size; the gateway's at any size.
MAX_SCRUB_BYTES = 1024 * 1024
CONNECT_TIMEOUT = 10.0
READ_TIMEOUT = 60.0
SSE_TYPE = "text/event-stream"
NDJSON_TYPE = "application/x-ndjson"
# Tells a proxy in front of the vault (Caddy, nginx) to pass each relayed chunk on at once.
NO_BUFFERING = (b"x-accel-buffering", b"no")
_STREAM_TYPES = (SSE_TYPE, NDJSON_TYPE)
# A 401 to these is answered by retrying once with a new token. POST and PATCH may have had an
# effect, so their 401 goes back to the caller and only the next request gets a new token.
_RETRY_METHODS: Final = frozenset({"GET", "HEAD", "OPTIONS", "PUT", "DELETE"})
# The error parameter of a WWW-Authenticate challenge. error_description and error_uri don't match.
_AUTH_ERROR = re.compile(r'(?:^|[\s,])error\s*=\s*"?([^",\s]*)', re.IGNORECASE)
_SCRUBBED_TYPES = (
    "text/",
    "application/json",
    "application/xml",
    "application/problem+json",
    "application/javascript",
    "application/x-www-form-urlencoded",
)


class Refused(Exception):
    """Stop handling a request with this status. ``reason`` goes to the log only.

    ``code`` is a stable code for the response body, set only after identity and a rule matched.
    ``retry_after`` (seconds) becomes a ``Retry-After`` header, and ``allow`` an ``Allow`` header.
    """

    def __init__(
        self,
        status: int,
        reason: str,
        *,
        code: str | None = None,
        retry_after: int | None = None,
        allow: str | None = None,
    ) -> None:
        self.status = status
        self.reason = reason
        self.code = code
        self.retry_after = retry_after
        self.allow = allow
        super().__init__(reason)


class CallerGone(Exception):
    """The caller left while the vault waited on the upstream. Nobody is left to answer.

    ``phase`` is ``headers`` while waiting for the upstream's status and headers, and ``relay``
    once they arrived.
    """

    def __init__(self, phase: Literal["headers", "relay"]) -> None:
        self.phase = phase
        super().__init__(f"the caller left during {phase}")


class Departure:
    """Watches the caller's ``receive()`` for a disconnect, once the request body has been read.

    Starlette listens for disconnects while streaming only on servers older than ASGI 2.4, and
    not at all while the vault waits for upstream headers. A silent upstream sends nothing that
    would show the caller has gone, so the vault watches for itself (M3 design F.6).
    """

    def __init__(self, receive: Receive) -> None:
        self._gone = asyncio.ensure_future(_disconnected(receive))

    async def race[T](self, work: Awaitable[T], *, phase: Literal["headers", "relay"]) -> T:
        """Await ``work``. If the caller leaves first, cancel it and raise :class:`CallerGone`."""
        task = asyncio.ensure_future(work)
        try:
            await asyncio.wait((task, self._gone), return_when=asyncio.FIRST_COMPLETED)
        finally:
            if not task.done():
                task.cancel()
                # Let it finish: a cancelled httpx request closes its upstream connection here.
                await asyncio.wait((task,))
        if task.cancelled():
            raise CallerGone(phase)
        return task.result()

    def close(self) -> None:
        """Stop watching."""
        # On a task that has already failed, cancel() also marks its error as retrieved, so
        # asyncio doesn't report it as never retrieved.
        self._gone.cancel()


class _DiscardingJar(http.cookiejar.CookieJar):
    """A cookie jar that keeps nothing (N2)."""

    def set_cookie(self, cookie: http.cookiejar.Cookie) -> None:
        pass

    def extract_cookies(self, response: Any, request: urllib.request.Request) -> None:
        pass


def without_cookies(client: httpx.AsyncClient) -> httpx.AsyncClient:
    """Give ``client`` a cookie jar that discards everything, and return it.

    httpx keeps a jar per client and sends its cookies on later requests to the same host, from
    any caller. The vault's clients must never do that.
    """
    client.cookies = _DiscardingJar()
    return client


_PUBLIC_MESSAGES = {
    400: "bad request",
    403: "forbidden",
    404: "not found",
    405: "method not allowed",
    408: "request timeout",
    411: "length required",
    413: "request too large",
    415: "unsupported media type",
    429: "too many requests",
    501: "not implemented",
    502: "upstream unavailable",
    503: "unavailable",
}


@dataclass(frozen=True)
class _ServedView:
    """The gateway's view of the running policy, as served."""

    digest: str
    body: bytes


@dataclass(frozen=True)
class _Caller:
    index: int
    placeholder: bytes
    location: Literal["bearer", "header", "query"]
    name: str
    networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]


@dataclass(frozen=True)
class _CompiledRoute:
    route: Route
    accepts_gateway: bool
    callers: tuple[_Caller, ...]


def _compile(policy: Policy) -> dict[str, _CompiledRoute]:
    table: dict[str, _CompiledRoute] = {}
    for route in policy.routes:
        callers = []
        for index, caller in enumerate(route.callers):
            if isinstance(caller, PlaceholderCaller):
                if caller.header is not None:
                    location: Literal["bearer", "header", "query"] = "header"
                    name = caller.header.lower()
                elif caller.query is not None:
                    location, name = "query", caller.query
                else:
                    location, name = "bearer", "authorization"
                networks = tuple(ipaddress.ip_network(s, strict=False) for s in caller.sources)
                callers.append(
                    _Caller(index, caller.placeholder.encode(), location, name, networks)
                )
        table[route.prefix.lstrip("/")] = _CompiledRoute(
            route=route, accepts_gateway="gateway" in route.callers, callers=tuple(callers)
        )
    return table


def _connector_response(answer: Answer, log: dict[str, Any]) -> Response:
    """A connector's answer. The vault makes every one, so all but a 200 carry the refusal
    marker (C.4)."""
    headers: dict[str, str] = {}
    if answer.status != 200:
        headers[REFUSAL_HEADER] = REFUSAL_MARKER
        log["code"] = answer.body.get("code")
    if answer.retry_after is not None:
        headers["retry-after"] = str(answer.retry_after)
    if answer.replayed:
        headers[REPLAYED_HEADER] = "1"
        log["replayed"] = True
    return JSONResponse(answer.body, status_code=answer.status, headers=headers)


def snapshot_env_secrets(policy: Policy, environ: Mapping[str, str]) -> dict[str, Secret]:
    """Read every ``env:`` secret once at startup, so later env changes can't affect the vault.

    A connector's username may come from the environment; its password never does (M4 Q12).
    """
    refs: set[str] = set()
    values = [v for cred in policy.credentials.values() for v in vars(cred).values()]
    values += [connector.username for connector in policy.connectors.values()]
    for value in values:
        if isinstance(value, str) and value.startswith("env:") and is_secret_ref(value):
            refs.add(value.removeprefix("env:"))
    return {name: Secret(environ[name]) for name in sorted(refs) if environ.get(name)}


class VaultApp:
    """ASGI app for the vault's proxy listener. Swap the policy with :meth:`reload`."""

    def __init__(
        self,
        policy: Policy,
        store: SecretStore,
        keys: KeySet,
        *,
        client: httpx.AsyncClient | None = None,
        token_client: httpx.AsyncClient | None = None,
        onboarding_client: httpx.AsyncClient | None = None,
        revocation_client: httpx.AsyncClient | None = None,
        tokens: TokenManager | None = None,
        environ: Mapping[str, str] | None = None,
        gateway_keys: GatewayKeys | None = None,
        gateway_link: bool = False,
        connectors: SmtpConnectors | None = None,
        reports: ReportStore | None = None,
        review_jobs: JobTable | None = None,
    ) -> None:
        """``client`` reaches upstreams and ``token_client`` token endpoints; both get a jar that
        keeps no cookies. By default both are :mod:`.netclient`'s guarded clients, with the
        running policy's ``egress_private`` as their exceptions (M7 design B.2). ``tokens``
        replaces the token manager (tests). It brings its own client, so ``token_client`` is then
        not used.

        ``onboarding_client`` reaches hosts learned from the network (discovery, registration;
        M7 design B.2), and ``revocation_client`` the revocation endpoint of a deleted refresh
        token (D.9), both guarded by :mod:`.netclient`, the second with the running policy's
        ``egress_private`` as its exceptions (TI-11). When ``client`` is given and either isn't,
        ``client`` serves that role too, so an injected client never falls back to a networked
        one. Every client, and the SMTP connectors' proxy, stays on the ``egress_proxy`` of
        ``policy``, the startup one: a reload never changes them (D-61). Its
        ``egress_proxy_kind`` is kept likewise.

        ``gateway_keys`` is the persisted ratchet the vault loaded at startup. Without one, the
        gateway keys are tracked in memory only (self-tests and unit tests).

        ``gateway_link`` says the link socket is configured: the gateway is then known by its
        socket only, and a gateway key on TCP is refused.

        ``connectors`` replaces the SMTP connectors (tests inject a transport and a TLS context).
        By default their journals live beside the store.

        ``reports`` is the copy of the gateway's ledger, recovered before the listeners open.
        Without one, the report path answers 503.

        ``review_jobs`` replaces the review job table (tests inject a clock). By default it is
        on the monotonic clock, started now.
        """
        self._gateway_link = gateway_link
        self._store = store
        self._keys = keys
        self._gateway_keys = gateway_keys or GatewayKeys.in_memory(
            keys, policy.gateway_key_generation
        )
        proxy = self._egress_proxy = policy.egress_proxy
        self._egress_proxy_kind: EgressProxyKind = policy.egress_proxy_kind
        injected = client is not None
        if client is None:
            timeout = httpx.Timeout(READ_TIMEOUT, connect=CONNECT_TIMEOUT)
            client = netclient.route_client(proxy, self._private, timeout=timeout)
        self._client = without_cookies(client)
        if onboarding_client is None and not injected:
            onboarding_client = netclient.onboarding_client(proxy)
        self._onboarding_client = without_cookies(onboarding_client or self._client)
        if revocation_client is None and not injected:
            revocation_client = netclient.revocation_client(proxy, self._private)
        self._revocation_client = without_cookies(revocation_client or self._client)
        self._token_client: httpx.AsyncClient | None = None
        if tokens is None:
            token_client = token_client or netclient.token_client(proxy, self._private)
            self._token_client = without_cookies(token_client)
            tokens = TokenManager(store, self._token_client)
        self._tokens = tokens
        self._revoker = secretops.Revoker(
            self._revocation_client, proxied=proxy is not None, refused=tokens.note_refused
        )
        # The last access token serial seen per credential, for the request log.
        self._serials: dict[str, int] = {}
        self._environ = os.environ if environ is None else environ
        self._connectors = connectors or SmtpConnectors(store.path.parent, keys)
        self._reports = reports
        # Long polls of the view wait on this event. Each install sets it and puts a new one in
        # its place, so every waiter wakes and looks at the view again.
        self._view_changed = asyncio.Event()
        self._view_waiters = 0
        self._view_stopping = False
        # Review jobs (M7 design F.2): every change sets this event and puts a new one in its
        # place, waking the gateway's poll and the socket's waits. One report is read at a time.
        self._reviews = JobTable(time.monotonic) if review_jobs is None else review_jobs
        self._reviews_changed = asyncio.Event()
        self._review_lock = asyncio.Lock()
        # The egress role's allowlists (M7 design G.2, I.3): their polls wait on this event,
        # which an install or an allowance change sets and replaces. The onboardings'
        # allowances come from use_allowances, with the seconds until the next of them expires.
        # The role's last fetch (monotonic) is for health, and so is its first request with an
        # egress key, admitted or not, so a role whose key is refused from the start is stale
        # too, and the vault's start, for a role the policy names that never asks; the digest it
        # holds, which it names in If-None-Match once it has applied the
        # lists, is for an onboarding through the role, which waits on _role_poll.
        self._allowances: Callable[[], Iterable[Allowance]] = lambda: ()
        self._allowances_expire: Callable[[], float | None] = lambda: None
        self._allowlist_changed = asyncio.Event()
        self._allowlist_waiters = 0
        self._role_fetched_at: float | None = None
        self._role_asked_at: float | None = None
        self._role_digest: str | None = None
        self._role_poll = asyncio.Event()
        self._started = time.monotonic()
        self._install(policy)

    def _install(self, policy: Policy) -> list[str]:
        # Built first: it can't fail for a policy that passed check, and if it did nothing would
        # have changed yet.
        view = build_view(policy)
        # Then the gateway key generation, written to disk before the policy takes effect. A
        # lower generation or a failed write raises GatewayKeyError, and the running policy stays.
        self._gateway_keys.advance(policy.gateway_key_generation)
        self._policy = policy
        self._routes = _compile(policy)
        self._env_secrets = snapshot_env_secrets(policy, self._environ)
        self._view = _ServedView(view.digest, dump_view(view))
        # A new generation retires the old egress key at once: there is no ratchet (G.3).
        self._egress_key = self._keys.egress_key(policy.egress_key_generation).encode()
        self._wake_view_waiters()
        self._wake_allowlist()
        return self._tokens.configure(policy, self._env_secrets)

    def _private(self) -> frozenset[str]:
        """The running policy's ``egress_private``: the guarded clients read it at each
        connection (M7 design B.2)."""
        return egresslist.private_exceptions(self._policy)

    def _wake_view_waiters(self) -> None:
        woken, self._view_changed = self._view_changed, asyncio.Event()
        woken.set()

    def _wake_reviews(self) -> None:
        woken, self._reviews_changed = self._reviews_changed, asyncio.Event()
        woken.set()

    def _wake_allowlist(self) -> None:
        woken, self._allowlist_changed = self._allowlist_changed, asyncio.Event()
        woken.set()

    @property
    def policy(self) -> Policy:
        return self._policy

    @property
    def tokens(self) -> TokenManager:
        return self._tokens

    @property
    def connectors(self) -> SmtpConnectors:
        return self._connectors

    @property
    def reports(self) -> ReportStore | None:
        return self._reports

    @property
    def egress_proxy(self) -> str | None:
        """The startup policy's ``egress_proxy``, which every client and connector uses."""
        return self._egress_proxy

    @property
    def egress_proxy_kind(self) -> EgressProxyKind:
        """The startup policy's ``egress_proxy_kind``: whether that proxy is the operator's own
        or the built-in egress role (I.3)."""
        return self._egress_proxy_kind

    @property
    def onboarding_client(self) -> httpx.AsyncClient:
        """The guarded client for hosts learned from the network (M7 design B.2)."""
        return self._onboarding_client

    @property
    def revoker(self) -> secretops.Revoker:
        """The revocations after a committed delete, on the revocation client (M7 design D.9).
        The socket and the portal share it."""
        return self._revoker

    @property
    def env_names(self) -> frozenset[str]:
        """The ``env:`` variables found set when the policy was loaded: names only."""
        return frozenset(self._env_secrets)

    @property
    def gateway_keys(self) -> GatewayKeys:
        return self._gateway_keys

    @property
    def view_digest(self) -> str:
        """The digest of the view the gateway is served now."""
        return self._view.digest

    @property
    def view_waiters(self) -> int:
        """How many long polls of the view are waiting."""
        return self._view_waiters

    @property
    def allowlist_waiters(self) -> int:
        """How many long polls of the allowlists are waiting."""
        return self._allowlist_waiters

    def stop_view_waits(self) -> None:
        """Answer every long poll of the view, of the review jobs and of the allowlists now, and
        the socket's review waits and an onboarding's wait for the egress role, and wait no
        more. For shutdown: the servers wait for requests in flight, and a long poll would hold
        them for up to 25 s."""
        self._view_stopping = True
        self._wake_view_waiters()
        self._wake_reviews()
        self._wake_allowlist()
        self._wake_role_poll()

    # --- the egress role's allowlists (M7 design G.2, I.3) --------------------------------------

    def use_allowances(
        self,
        allowances: Callable[[], Iterable[Allowance]],
        expire_in: Callable[[], float | None] = lambda: None,
    ) -> None:
        """Take the live onboardings' allowances from ``allowances`` (the onboarding service's)
        for the vault's list (I.3). ``expire_in`` is the seconds until the next of them expires
        (None: none will), when a waiting poll looks at the lists again, since an expiry sets
        no event."""
        self._allowances = allowances
        self._allowances_expire = expire_in
        self._wake_allowlist()

    def allowlist_document(self) -> dict[str, Any]:
        """The allowlist endpoint's answer now (G.2): the running policy's lists with the live
        allowances, as ``egresslist.document`` writes them."""
        return egresslist.document(egresslist.derive(self._policy, self._allowances()))

    def lists_changed(self) -> None:
        """An onboarding's allowance changed: every waiting allowlist poll looks again."""
        self._wake_allowlist()

    def allowlist_fetched_ago(self) -> float | None:
        """Seconds since the egress role last fetched its lists (health's
        ``egress_allowlist_stale``, J). A role that has asked since the vault started but was
        never admitted (a wrong or old key) is measured from its first request. When no request
        with an egress key has come since the vault started: from the start when the startup
        policy's ``egress_proxy`` is the role, which is expected then, else None."""
        since = self._role_fetched_at if self._role_fetched_at is not None else self._role_asked_at
        if since is None and self._egress_proxy is not None and self._egress_proxy_kind == "role":
            since = self._started
        if since is None:
            return None
        return max(0.0, time.monotonic() - since)

    async def role_fetched(self, wait: float) -> bool:
        """Wake every allowlist poll, then wait up to ``wait`` seconds for the egress role to
        hold the lists as they are now (I.3). The role names the digest it holds in
        ``If-None-Match``, and it polls again as soon as it has applied a 200, so a poll naming
        the current digest means the role allows what the lists do. False when it doesn't by
        then, at shutdown, or when no role has fetched since the vault started."""
        self._wake_allowlist()
        if self._role_fetched_at is None:
            return False
        deadline = time.monotonic() + wait
        while True:
            polled = self._role_poll
            if self._role_digest == self.allowlist_document()["digest"]:
                return True
            remaining = deadline - time.monotonic()
            if remaining <= 0 or self._view_stopping:
                return False
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(polled.wait(), remaining)

    def _role_holds(self, tags: frozenset[str]) -> None:
        """A poll of the role's named ``tags`` in ``If-None-Match``: the one digest it holds,
        or none known (its first poll names none)."""
        self._role_digest = next(iter(tags)) if len(tags) == 1 else None
        self._wake_role_poll()

    def _wake_role_poll(self) -> None:
        woken, self._role_poll = self._role_poll, asyncio.Event()
        woken.set()

    def reload(self, policy: Policy) -> list[str]:
        """Swap the policy. Returns the OAuth credentials whose cached tokens were reset.

        Raises :class:`~zoeymcp.vault.gatewaykeys.GatewayKeyError` for a gateway key generation
        that went backwards or can't be written; the running policy then stays.
        """
        return self._install(policy)

    async def aclose(self) -> None:
        """Wait for refreshes and revocations in flight, then close the clients (N5)."""
        try:
            try:
                await self._tokens.aclose()
            finally:
                await self._revoker.aclose()
        finally:
            await self._client.aclose()
            if self._token_client is not None and self._token_client is not self._client:
                await self._token_client.aclose()
            if self._onboarding_client is not self._client:
                await self._onboarding_client.aclose()
            if self._revocation_client is not self._client:
                await self._revocation_client.aclose()

    # --- ASGI ----------------------------------------------------------------------------------

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            return
        if scope["type"] != "http":
            raise RuntimeError(f"unsupported scope {scope['type']}")
        request = Request(scope, receive)
        started = time.monotonic()
        listener: Listener = "gateway" if scope.get(LISTENER_SCOPE_KEY) == "gateway" else "tcp"
        log: dict[str, Any] = {"method": request.method, "listener": listener}
        response: Response | None
        try:
            response = await self._handle(request, listener, log)
        except CallerGone as gone:
            log.update(outcome="cancelled", phase=gone.phase)
            response = None
        except Refused as refusal:
            log.update(status=refusal.status, reason=refusal.reason)
            body = {"error": _PUBLIC_MESSAGES.get(refusal.status, "error")}
            headers = {REFUSAL_HEADER: REFUSAL_MARKER}
            if refusal.code is not None:
                body["code"] = log["code"] = refusal.code
            if refusal.retry_after is not None:
                headers["retry-after"] = str(refusal.retry_after)
            if refusal.allow is not None:
                headers["allow"] = refusal.allow
            response = JSONResponse(body, status_code=refusal.status, headers=headers)
        else:
            log["status"] = response.status_code
        log["duration_ms"] = round((time.monotonic() - started) * 1000, 1)
        logs.event("request", **log)
        if response is not None:
            await response(scope, receive, send)

    # --- handling ------------------------------------------------------------------------------

    async def _handle(self, request: Request, listener: Listener, log: dict[str, Any]) -> Response:
        raw_path = request.scope.get("raw_path") or quote(request.scope["path"]).encode()
        try:
            path = normalize_path(raw_path)
        except RequestRejected as exc:
            raise Refused(400, exc.reason) from exc
        if path.segments[:1] == (INTERNAL_SEGMENT,):
            return await self._internal(request, path, listener, log)
        if not path.segments or (compiled := self._routes.get(path.segments[0])) is None:
            raise Refused(404, "no route for this prefix")
        route = compiled.route
        log["route"] = route.name

        query_raw: bytes = request.scope.get("query_string", b"")
        try:
            params = parse_query(query_raw)
        except RequestRejected as exc:
            raise Refused(400, exc.reason) from exc

        caller, used_query, used_header = self._identify(compiled, request, params, listener)
        log["caller"] = caller

        rest = path.without_first()
        rule_index = find_rule(route.rules, request.method, rest)
        if rule_index is None:
            raise Refused(403, "no rule allows this method and path")
        log["rule"] = rule_index

        if route.connector is not None:
            return await self._connector(request, route.connector, rest, log)
        assert route.upstream is not None  # noqa: S101 - guaranteed by the schema

        body = await self._read_body(request)
        upstream = urlsplit(route.upstream)
        base_path = upstream.path.rstrip("/")
        upstream_origin = f"{upstream.scheme}://{upstream.netloc}"
        headers = filter_request_headers(
            request.headers.items(), drop=[used_header] if used_header else ()
        )
        remove = [used_query] if used_query else []
        add: list[tuple[str, str]] = []
        variants: list[bytes] = []
        path_prefix = ""

        cred = self._policy.credentials.get(route.credential) if route.credential else None
        if cred is not None and not isinstance(cred, OAuth2Credential):
            value = self._resolve(cred.secret, route.upstream).reveal()
            if isinstance(cred, HeaderCredential):
                headers.append((cred.header, cred.format.replace("{secret}", value)))
                variants = secret_variants(value)
            elif isinstance(cred, QueryCredential):
                remove.append(cred.param)
                add.append((cred.param, value))
                variants = secret_variants(value)
            elif isinstance(cred, PathCredential):
                path_prefix = cred.template.replace("{secret}", quote(value, safe=""))
                variants = secret_variants(value)
            elif isinstance(cred, BasicCredential):
                user = cred.username
                if is_secret_ref(user):
                    user = self._resolve(user, route.upstream).reveal()
                token = base64.b64encode(f"{user}:{value}".encode()).decode()
                headers.append(("authorization", f"Basic {token}"))
                variants = secret_variants(value, basic_user=user)
            log["credential"] = route.credential

        try:
            query = apply_query_policy(params, route.query, remove=remove, add=add)
        except RequestRejected as exc:
            raise Refused(403, exc.reason) from exc

        # Last of all, as it may call the token endpoint: a request refused above causes none.
        grant: Grant | None = None
        if isinstance(cred, OAuth2Credential):
            assert route.credential is not None  # noqa: S101 - cred was found by this name
            grant = await self._grant(route.credential, route.upstream)
            # The caller's Authorization was dropped with the other caller credentials.
            headers.append(_bearer(grant))
            variants = list(grant.variants)
            log["credential"] = route.credential
            seen = self._serials.get(route.credential)
            log["oauth"] = "cached" if seen == grant.serial else "refreshed"
            self._serials[route.credential] = grant.serial

        url = upstream_origin + base_path + path_prefix + rest.encoded()
        if query:
            url += "?" + encode_query(query)
        departure = Departure(request.receive)
        try:
            upstream_response = await self._send(
                request.method, url, headers, body, route, departure
            )
            if grant is not None:
                assert route.credential is not None  # noqa: S101 - set for every OAuth route
                assert isinstance(cred, OAuth2Credential)  # noqa: S101 - grant implies it
                status = upstream_response.status_code
                if status in (401, 403):
                    self._note_challenge(route.credential, cred, upstream_response)
                if status == 401:
                    upstream_response, variants = await self._after_401(
                        upstream_response,
                        route=route,
                        credential=route.credential,
                        grant=grant,
                        method=request.method,
                        url=url,
                        headers=headers,
                        body=body,
                        variants=variants,
                        departure=departure,
                        log=log,
                    )
            response = await self._respond(
                upstream_response,
                route,
                variants,
                departure,
                log,
                gateway=caller == "gateway",
            )
        except BaseException:
            departure.close()
            raise
        if not isinstance(response, Relay):
            # Answered in full. A relay stops watching when its stream ends.
            departure.close()
        return response

    def _identify(
        self,
        compiled: _CompiledRoute,
        request: Request,
        params: list[tuple[str, str]],
        listener: Listener,
    ) -> tuple[str, str | None, str | None]:
        """Return ``(caller name, query param used, header used)`` or refuse with 403."""
        if listener == "gateway":
            # The kernel checked the peer's uid: the caller is the gateway and nothing else. No
            # key or placeholder is read here (M3 design C.1).
            if compiled.accepts_gateway:
                return "gateway", None, None
            raise Refused(403, "route doesn't accept the gateway")
        if self._gateway_key(request, accepted=compiled.accepts_gateway):
            return "gateway", None, None
        client_host = request.client.host if request.client else None
        for caller in compiled.callers:
            presented = self._presented(caller, request, params)
            if presented is None or not hmac.compare_digest(presented, caller.placeholder):
                continue
            if caller.networks and not self._source_allowed(client_host, caller.networks):
                raise Refused(403, f"caller {caller.index} from a source outside its pins")
            used_query = caller.name if caller.location == "query" else None
            used_header = caller.name if caller.location == "header" else None
            return f"callers[{caller.index}]", used_query, used_header
        raise Refused(403, "no accepted identity presented")

    def _gateway_key(self, request: Request, *, accepted: bool) -> bool:
        """Whether a TCP request presents a valid gateway key; False when it presents none.

        A key is refused when it isn't ``accepted`` here, when it isn't of an accepted generation
        (M3 design C.2), or when the link socket is configured. The first request made with the
        current key retires the previous one.
        """
        gateway = request.headers.getlist(GATEWAY_HEADER)
        if not gateway:
            return False
        if self._gateway_link:
            # The gateway has the link socket, so no gateway key exists in this tier.
            raise Refused(403, "gateway key refused on tcp")
        if accepted and len(gateway) == 1 and self._gateway_keys.authenticate(gateway[0].encode()):
            return True
        raise Refused(403, "gateway key refused")

    @staticmethod
    def _presented(
        caller: _Caller, request: Request, params: list[tuple[str, str]]
    ) -> bytes | None:
        if caller.location == "query":
            values = [v for k, v in params if k == caller.name]
            return values[0].encode() if len(values) == 1 else None
        values = request.headers.getlist(caller.name)
        if len(values) != 1:
            return None
        if caller.location == "header":
            return values[0].encode()
        scheme, _, token = values[0].partition(" ")
        if scheme.lower() != "bearer" or not token:
            return None
        return token.strip().encode()

    @staticmethod
    def _source_allowed(
        host: str | None,
        networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...],
    ) -> bool:
        if host is None:
            return False
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return False
        return any(address in network for network in networks)

    # --- the vault's own endpoints -------------------------------------------------------------

    async def _internal(
        self, request: Request, path: NormalizedPath, listener: Listener, log: dict[str, Any]
    ) -> Response:
        """The vault's own endpoints, as :func:`.internal.decide` admits them: the path (404),
        the gateway's identity (403; a gateway key is read only for a path in the table), then
        the method (405). Each handler checks the rest before any body byte is read."""
        endpoint = internal.find(path)
        if endpoint is None:
            raise Refused(404, "no such vault endpoint")
        log["endpoint"] = endpoint.name
        gateway = listener == "gateway" or self._gateway_key(request, accepted=True)
        if (
            listener == "tcp"
            and endpoint is internal.ALLOWLISTS
            and EGRESS_HEADER in request.headers
            and self._role_asked_at is None
        ):
            # A role asks, admitted or not: health measures a role never admitted from here.
            self._role_asked_at = time.monotonic()
        # The link socket's caller is the gateway: no egress key is read there (X21).
        egress = listener == "tcp" and self._egress_key_presented(request)
        if gateway and egress:
            raise Refused(403, "two identities presented")
        identity: internal.Identity | None = "gateway" if gateway else "egress" if egress else None
        if identity is not None:
            log["caller"] = identity
        decided = internal.decide(path, request.method, listener, identity)
        if isinstance(decided, internal.Refusal):
            raise Refused(decided.status, decided.reason, allow=decided.allow)
        if decided is internal.ALLOWLISTS:
            return await self._allowlists(request, log)
        if decided is internal.LEDGER:
            return await self._report(request, log)
        if decided is internal.REVIEW_JOBS:
            return await self._review_jobs(request, log)
        if decided is internal.REVIEW_REPORT:
            return await self._review_report(request, log)
        return await self._view_answer(request, log)

    def _egress_key_presented(self, request: Request) -> bool:
        """Whether a TCP request presents the egress key of the running generation (G.3);
        False when it presents none. Any other key, or two, is refused."""
        presented = request.headers.getlist(EGRESS_HEADER)
        if not presented:
            return False
        if len(presented) == 1 and hmac.compare_digest(presented[0].encode(), self._egress_key):
            return True
        raise Refused(403, "egress key refused")

    async def _allowlists(self, request: Request, log: dict[str, Any]) -> Response:
        """``GET /_zoeymcp/egress/v1/allowlists``: the egress role's lists (G.2), with their
        digest as the ``ETag``, or 304 while the digest is one the role named in
        ``If-None-Match``. With ``?wait=N`` a 304 waits up to N seconds (at most 25; two
        waiters) for a reload or an allowance change that changes the lists. The tag it names
        is the digest it holds (I.3), and each answer is a fetch, for health (J)."""
        try:
            wait = internal.allowlist_wait(parse_query(request.scope.get("query_string", b"")))
        except RequestRejected as exc:
            raise Refused(400, exc.reason) from exc
        tags = entity_tags(request.headers.getlist("if-none-match"))
        self._role_holds(tags)
        started = time.monotonic()
        document = self.allowlist_document()
        if wait and document["digest"] in tags and not self._view_stopping:
            await self._wait_for_allowlist(tags, started + wait, request.receive, log)
            document = self.allowlist_document()
        digest = document["digest"]
        if not log.get("disconnected"):
            self._role_fetched_at = time.monotonic()
        headers = {"etag": f'"{digest}"', "cache-control": "no-store"}
        if digest in tags:
            return Response(status_code=304, headers=headers)
        waited_ms = round((time.monotonic() - started) * 1000)
        logs.event("egress_allowlist_served", digest=digest, waited_ms=waited_ms)
        body = json.dumps(document).encode()
        return Response(body, media_type="application/json", headers=headers)

    async def _view_answer(self, request: Request, log: dict[str, Any]) -> Response:
        """``GET /_zoeymcp/gateway/v1/view``: the view with its digest as the ``ETag``, or 304
        while the digest is one the caller named in ``If-None-Match``. With ``?wait=N`` a 304
        waits up to N seconds for a reload that changes the view (M3 design D.2)."""
        try:
            wait = view_wait(parse_query(request.scope.get("query_string", b"")))
        except RequestRejected as exc:
            raise Refused(400, exc.reason) from exc
        tags = entity_tags(request.headers.getlist("if-none-match"))
        started = time.monotonic()
        if wait and self._view.digest in tags and not self._view_stopping:
            await self._wait_for_view(tags, started + wait, request.receive, log)
        view = self._view
        headers = {"etag": f'"{view.digest}"', "cache-control": "no-store"}
        if view.digest in tags:
            return Response(status_code=304, headers=headers)
        waited_ms = round((time.monotonic() - started) * 1000)
        logs.event("gateway_view_served", digest=view.digest, waited_ms=waited_ms)
        return Response(view.body, media_type="application/json", headers=headers)

    async def _report(self, request: Request, log: dict[str, Any]) -> Response:
        """``GET`` and ``POST`` of the report path (M5 design J.2), for the gateway only.

        Before any body byte is read: the gateway's identity (403), the method (405), no query
        (400), a copy that can be read (503), then for a ``POST`` exactly one ``Content-Type:
        application/json`` (415) and one ``Content-Length`` (411) of at most 1 MiB (413). Then,
        one report at a time (429 ``busy`` while one applies), the body is read within the cap
        and :data:`REPORT_DEADLINE` (408), parsed strictly, and decided and applied by the
        copy. ``GET`` answers the head; an accepted ``POST`` answers the same, a refused one its
        ``code`` with the head.
        """
        if request.scope.get("query_string"):
            raise Refused(400, "the report path takes no query")
        copy = self._reports
        if copy is None or not copy.available:
            raise Refused(503, "the reported copy is unavailable", code="unavailable")
        copy.contact()
        if request.method == "GET":
            return _head(copy)
        _report_headers(request)
        if copy.lock.locked():
            raise Refused(429, "a report is being applied", code="busy", retry_after=1)
        async with copy.lock:
            body = await _read_report(request)
            try:
                report = canonical.loads_strict(body, max_bytes=ledgerreport.MAX_BODY_BYTES)
            except ValueError as exc:
                raise Refused(400, "the report isn't strict JSON", code="bad_body") from exc
            try:
                result = await asyncio.to_thread(copy.report, report)
            except CopyUnavailable as exc:
                raise Refused(503, "the reported copy is unavailable", code="unavailable") from exc
        if isinstance(result, ReportRefused):
            log.update(reason=result.reason, code=result.reason)
            refusal: dict[str, Any] = {"error": result.message, "code": result.reason}
            if result.index is not None:
                refusal["index"] = result.index
            refusal.update(copy.head().to_json())
            headers = {REFUSAL_HEADER: REFUSAL_MARKER, "cache-control": "no-store"}
            return JSONResponse(refusal, status_code=result.status, headers=headers)
        return _head(copy)

    # --- review jobs (M7 design F.2) -----------------------------------------------------------

    async def _review_jobs(self, request: Request, log: dict[str, Any]) -> Response:
        """``GET /_zoeymcp/gateway/v1/review/jobs?wait=N&view=<digest>``: the jobs queued at the
        view digest the gateway's policy client holds, now ``sent``, once there are any, or
        none after N seconds (at most 25), at shutdown, or when the caller leaves. One poll
        waits at a time (429); while it waits the poller counts as seen (CR-15)."""
        try:
            wait, digest = internal.jobs_query(parse_query(request.scope.get("query_string", b"")))
        except RequestRejected as exc:
            raise Refused(400, exc.reason) from exc
        table = self._reviews
        if table.waiting >= internal.REVIEW_WAITERS:
            raise Refused(429, "a review poll is already waiting", retry_after=1)
        table.poll_began()
        # A queue call waiting for the first poll after the vault started goes on (OPS-20).
        self._wake_reviews()
        gone = asyncio.ensure_future(_disconnected(request.receive))
        left = False
        try:
            deadline = table.now() + wait
            while not table.offered(digest) and not self._view_stopping:
                remaining = deadline - table.now()
                if remaining <= 0:
                    break
                changed = asyncio.ensure_future(self._reviews_changed.wait())
                try:
                    await asyncio.wait(
                        (changed, gone), timeout=remaining, return_when=asyncio.FIRST_COMPLETED
                    )
                finally:
                    changed.cancel()
                if gone.done():
                    left = log["disconnected"] = True
                    break
        finally:
            table.poll_ended()
            # On a task that has already failed, cancel() also marks its error as retrieved.
            gone.cancel()
            self._log_review_ends()
        # A job is sent only to a poll that is still there to take it.
        claimed = () if left else table.claim(digest)
        if claimed:
            self._wake_reviews()
        log["jobs"] = len(claimed)
        jobs = [{"id": job.id, "server": job.server} for job in claimed]
        return JSONResponse({"v": 1, "jobs": jobs}, headers={"cache-control": "no-store"})

    async def _review_report(self, request: Request, log: dict[str, Any]) -> Response:
        """``POST /_zoeymcp/gateway/v1/report/review``: one job's result (F.2, F.4).

        Before any body byte is read: no query (400), exactly one ``Content-Type:
        application/json`` (415) and one ``Content-Length`` (411) of at most the report cap the
        limits give (413 ``review_too_large``). Then, one at a time (429 ``busy``), the body is
        read within the cap and 30 s (408) and parsed strictly (400 ``bad_body``). A result for
        no ``sent`` job is 409 ``job_unknown``; a report the vault refuses fails its job and is
        answered with its reason (``pin_mismatch`` logged at critical). An accepted result is
        answered with the job's state. A 413 names no job, so the gateway posts it back as its
        error ``review_too_large``, which fails the job with the cap (F.4)."""
        if request.scope.get("query_string"):
            raise Refused(400, "the review report path takes no query")
        limits = self._limits()
        most = reviewreport.report_max(limits)
        length = _json_length(request, kind="a review report")
        try:
            reviewreport.check_length(length, limits)
        except reviewreport.ReportRefused as exc:
            raise Refused(413, exc.detail, code=exc.reason) from exc
        if self._review_lock.locked():
            raise Refused(429, "a review report is being read", code="busy", retry_after=1)
        async with self._review_lock:
            too_large = (f"a review report is at most {most} bytes", "review_too_large")
            body = await _read_json_body(
                request, most, internal.REVIEW_READ_DEADLINE, too_large, kind="the review report"
            )
            try:
                data = await asyncio.to_thread(
                    canonical.loads_strict, body, max_bytes=most, max_depth=REVIEW_MAX_DEPTH
                )
            except ValueError as exc:
                raise Refused(400, "the review report isn't strict JSON", code="bad_body") from exc
            try:
                self._reviews.sent(named_job(data))
                # A large report is read off the event loop; its job is ended back on it, and a
                # job that timed out meanwhile is job_unknown then.
                result: Result = await asyncio.to_thread(read_result, data, limits)
                posted = self._reviews.post(result)
            except ReviewRefused as exc:
                logs.event("review_refused", reason=exc.reason)
                raise Refused(409, "no such review job was sent", code=exc.reason) from exc
            finally:
                self._log_review_ends()
        self._wake_reviews()
        job = posted.job
        event: dict[str, Any] = {"server": job.server, "job": job.hash8}
        log["server"] = job.server
        refused = posted.refused
        if refused is not None:
            event["reason"] = refused.reason
            if refused.reason == "pin_mismatch":
                event.update(tools=len(refused.tools), level="critical")
            logs.event("review_refused", **event)
            raise Refused(502, refused.detail, code=refused.reason)
        if job.report is not None:
            event["tools"] = len(job.report.tools)
        else:
            event.update(reason=job.failure, code=result.code)
        logs.event("review_reported", **event)
        answer = {"v": 1, "job": job.id, "state": job.state}
        return JSONResponse(answer, headers={"cache-control": "no-store"})

    def _limits(self) -> GatewayLimits:
        gateway = self._policy.gateway
        return GatewayLimits() if gateway is None else gateway.limits

    def _reviewable(self) -> dict[str, ServerKind]:
        """The running view's servers a review job may be for: remote (a bridge is one once it
        is an upstream, 18a) and toolkit (COV-1)."""
        gateway = self._policy.gateway
        servers: dict[str, ServerKind] = {}
        for name, server in ({} if gateway is None else gateway.servers).items():
            if isinstance(server, RemoteServer | ToolkitServer):
                servers[name] = server.kind
        return servers

    def _log_review_ends(self) -> None:
        """Log every job the clock ended since the last look (M.4)."""
        for ended in self._reviews.sweep():
            logs.event(ended.why, server=ended.job.server, job=ended.job.hash8)

    async def queue_review(self, server: str, owner: Owner, *, fresh: bool = False) -> Job:
        """Queue a review of ``server`` for the ``owner``'s surface at the running view's
        digest, or hand back that surface's ``done`` job at it unless ``fresh`` (OPS-11).
        Raises :class:`.reviewjobs.ReviewRefused`. In the first 45 s after the vault started,
        with no poll seen yet, it waits for the first one before it answers (OPS-20), unless
        the vault is stopping: no poll comes then, and it is ``review_unavailable`` at once."""
        table = self._reviews
        while True:
            changed = self._reviews_changed
            try:
                queued = table.queue(
                    server, owner, self._view.digest, self._reviewable(), fresh=fresh
                )
            except ReviewRefused as exc:
                if exc.reason == "review_unavailable":
                    logs.event("review_unavailable", server=server)
                raise
            finally:
                self._log_review_ends()
            if isinstance(queued, Job):
                break
            if self._view_stopping:
                logs.event("review_unavailable", server=server)
                raise ReviewRefused(
                    "review_unavailable", "the vault is stopping", detail="the vault is stopping"
                )
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(changed.wait(), max(0.0, queued.until - table.now()))
        reused = queued.state == "done"
        if not reused:
            self._wake_reviews()
        logs.event("review_requested", server=server, job=queued.hash8, owner=owner, reused=reused)
        return queued

    async def review_job(self, job_id: str, owner: Owner, *, wait: float = 0) -> Job:
        """The ``owner``'s surface's job, once it is ``done`` or ``failed``, after ``wait``
        seconds, or at shutdown. Raises :class:`.reviewjobs.ReviewRefused` (``job_unknown``)."""
        table = self._reviews
        deadline = table.now() + wait
        while True:
            changed = self._reviews_changed
            try:
                job = table.get(job_id, owner)
            finally:
                self._log_review_ends()
            ends = table.deadline(job)
            remaining = deadline - table.now()
            if ends is None or remaining <= 0 or self._view_stopping:
                return job
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(changed.wait(), min(remaining, ends - table.now()))

    async def _wait_for_view(
        self, tags: frozenset[str], deadline: float, receive: Receive, log: dict[str, Any]
    ) -> None:
        """Wait until the view's digest isn't in ``tags``, the deadline, shutdown, or the
        caller leaves. At most :data:`VIEW_MAX_WAITERS` wait; one more is refused with 429."""
        if self._view_waiters >= VIEW_MAX_WAITERS:
            raise Refused(429, "too many view waiters", retry_after=1)
        self._view_waiters += 1
        try:
            await self._until_changed(
                lambda: self._view.digest, lambda: self._view_changed, tags, deadline, receive, log
            )
        finally:
            self._view_waiters -= 1

    async def _wait_for_allowlist(
        self, tags: frozenset[str], deadline: float, receive: Receive, log: dict[str, Any]
    ) -> None:
        """As :meth:`_wait_for_view`, for the allowlists' digest: at most
        :data:`.internal.ALLOWLIST_WAITERS` wait; one more is refused with 429."""
        if self._allowlist_waiters >= internal.ALLOWLIST_WAITERS:
            raise Refused(429, "too many allowlist waiters", retry_after=1)
        self._allowlist_waiters += 1
        try:
            await self._until_changed(
                lambda: str(self.allowlist_document()["digest"]),
                lambda: self._allowlist_changed,
                tags,
                deadline,
                receive,
                log,
                recheck=self._allowances_expire,
            )
        finally:
            self._allowlist_waiters -= 1

    async def _until_changed(
        self,
        digest: Callable[[], str],
        changed: Callable[[], asyncio.Event],
        tags: frozenset[str],
        deadline: float,
        receive: Receive,
        log: dict[str, Any],
        *,
        recheck: Callable[[], float | None] = lambda: None,
    ) -> None:
        """Wait until ``digest()`` isn't in ``tags``, the deadline, shutdown, or the caller
        leaves, waking each time ``changed()``'s event is set, and after ``recheck()`` seconds
        when it names some (a change no event marks; at least :data:`RECHECK_MIN` apart)."""
        gone = asyncio.ensure_future(_disconnected(receive))
        try:
            while digest() in tags and not self._view_stopping:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return
                due = recheck()
                if due is not None:
                    remaining = min(remaining, max(due, RECHECK_MIN))
                woken = asyncio.ensure_future(changed().wait())
                try:
                    await asyncio.wait(
                        (woken, gone), timeout=remaining, return_when=asyncio.FIRST_COMPLETED
                    )
                finally:
                    woken.cancel()
                if gone.done():
                    log["disconnected"] = True
                    return
        finally:
            # On a task that has already failed, cancel() also marks its error as retrieved, so
            # asyncio doesn't report it as never retrieved.
            gone.cancel()

    async def _connector(
        self, request: Request, name: str, rest: NormalizedPath, log: dict[str, Any]
    ) -> Response:
        """``GET /config`` or ``POST /send`` of an SMTP connector (M4 design J). The policy check
        allows a connector route no other rule, so anything else is a 404."""
        connector = self._policy.connectors[name]
        log["connector"] = name
        endpoint = (request.method, rest.segments)
        if endpoint == ("GET", ("config",)):
            return _connector_response(self._connectors.config(name, connector), log)
        if endpoint != ("POST", ("send",)):
            raise Refused(404, "not a connector endpoint")
        body = await self._read_body(request)
        answer = await self._connectors.send(
            name,
            connector,
            key=request.headers.get("idempotency-key"),
            content_type=request.headers.get("content-type"),
            body=body,
            proxy=self._egress_proxy,  # the startup one, as every HTTP client's (D-61)
            credentials=lambda: self._connector_credentials(connector),
        )
        return _connector_response(answer, log)

    def _connector_credentials(self, connector: SMTPConnector) -> tuple[str, str]:
        """The username and password, if they were stored for exactly this connector's host,
        port, sender and recipients (J.6). Raises :class:`SecretUnavailable`."""
        binding = smtp_binding(connector.host, connector.port, connector.from_, connector.to)

        def resolve(ref: str) -> str:
            if ref.startswith("store:"):
                return self._store.get_for_binding(ref.removeprefix("store:"), binding).reveal()
            secret = self._env_secrets.get(ref.removeprefix("env:"))
            if secret is None:
                raise SecretUnavailable(ref, "env var not set when the policy was loaded")
            return secret.reveal()

        if not connector.password.startswith("store:"):
            raise SecretUnavailable(connector.password, "a connector password must be in the store")
        username = connector.username
        if is_secret_ref(username):
            username = resolve(username)
        return username, resolve(connector.password)

    def _resolve(self, ref: str, upstream: str) -> Secret:
        try:
            if ref.startswith("store:"):
                return self._store.get_for_origin(ref.removeprefix("store:"), upstream)
            if ref.startswith("env:"):
                secret = self._env_secrets.get(ref.removeprefix("env:"))
                if secret is None:
                    raise SecretUnavailable(ref, "env var not set when the policy was loaded")
                return secret
        except SecretUnavailable as exc:
            raise Refused(
                502, f"credential unavailable: {exc.reason}", code=CREDENTIAL_UNAVAILABLE
            ) from exc
        raise Refused(502, "credential reference not understood", code=CREDENTIAL_UNAVAILABLE)

    async def _grant(self, credential: str, upstream: str) -> Grant:
        """An access token for ``upstream``, or a 502 with the manager's stable code."""
        try:
            return await self._tokens.grant_for(credential, upstream)
        except OAuthUnavailable as exc:
            retry_after = None
            if exc.code == OAUTH_UNAVAILABLE:
                retry_after = max(1, math.ceil(exc.retry_after or 0))
            raise Refused(502, str(exc), code=exc.code, retry_after=retry_after) from exc

    def _note_challenge(
        self, credential: str, cred: OAuth2Credential, response: httpx.Response
    ) -> None:
        """What an upstream's 401 or 403 says about the token, kept for health (M7 design J,
        D.5). An ``insufficient_scope`` (a new token won't fix it: the operator may need to log
        in with more scopes), with the scope tokens its challenge asked for; and a 401 naming
        other ``resource_metadata`` than the credential's. Both parts are read with discovery's
        parser, bounded and cleaned, from the challenge whose ``error`` is read: one that doesn't
        parse gives neither, never half of one."""
        values = response.headers.get_list("www-authenticate")
        parsed = parse_challenge(values)
        challenge = parsed if isinstance(parsed, Challenge) else None
        if "insufficient_scope" in _challenge_errors(response):
            scopes: tuple[str, ...] = ()
            if challenge is not None and challenge.error == "insufficient_scope":
                scopes = challenge.scopes
            self._tokens.note_upstream(credential, UPSTREAM_INSUFFICIENT_SCOPE, scopes=scopes)
        if (
            response.status_code == 401
            and challenge is not None
            and challenge.resource_metadata is not None
            and cred.resource_metadata is not None
            and challenge.resource_metadata != cred.resource_metadata
        ):
            self._tokens.note_resource_metadata(credential, challenge.resource_metadata)

    async def _after_401(
        self,
        upstream: httpx.Response,
        *,
        route: Route,
        credential: str,
        grant: Grant,
        method: str,
        url: str,
        headers: list[tuple[str, str]],
        body: bytes,
        variants: list[bytes],
        departure: Departure,
        log: dict[str, Any],
    ) -> tuple[httpx.Response, list[bytes]]:
        """The upstream refused the access token (design D.10).

        The token is dropped unless it's younger than ``MIN_401_AGE``. A request that's safe to
        repeat is then sent once more with a new token; the second answer is final.
        """
        if not _token_refused(upstream):
            return upstream, variants
        action: str = self._tokens.rejected(credential, grant)
        try:
            if action == "suppressed" or method not in _RETRY_METHODS:
                return upstream, variants
            assert route.upstream is not None  # noqa: S101 - OAuth routes have an upstream
            # A refresh may take a while: don't hold the upstream connection meanwhile.
            await upstream.aclose()
            fresh = await self._grant(credential, route.upstream)
            if fresh.serial == grant.serial:
                # rejected() dropped that token or saw another, so this can't happen. The 401
                # is closed already, so answer as if no token could be had.
                raise Refused(
                    502, "no new access token after a 401", code=OAUTH_UNAVAILABLE, retry_after=1
                )
            retry = [h for h in headers if h[0] != "authorization"]
            retry.append(_bearer(fresh))
            upstream = await self._send(method, url, retry, body, route, departure)
            self._serials[credential] = fresh.serial
            action = log["oauth"] = "retried"
            return upstream, sorted({*variants, *fresh.variants}, key=len, reverse=True)
        finally:
            # Also when the refresh or the retry failed: those are the ones to look into.
            logs.event(
                "oauth_upstream_401",
                route=route.name,
                credential=credential,
                method=method,
                action=action,
                fresh_token=action == "suppressed",
            )

    @staticmethod
    async def _read_body(request: Request) -> bytes:
        declared = request.headers.get("content-length")
        if declared is not None and declared.isdigit() and int(declared) > MAX_REQUEST_BYTES:
            raise Refused(413, "request body over the limit")
        chunks: list[bytes] = []
        size = 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > MAX_REQUEST_BYTES:
                raise Refused(413, "request body over the limit")
            chunks.append(chunk)
        return b"".join(chunks)

    async def _send(
        self,
        method: str,
        url: str,
        headers: list[tuple[str, str]],
        body: bytes,
        route: Route,
        departure: Departure,
    ) -> httpx.Response:
        """Send the request upstream. Returns once the status line and headers arrived, or
        raises :class:`CallerGone` (and closes the request) if the caller leaves first."""
        timeout = httpx.Timeout(None if route.stream else READ_TIMEOUT, connect=CONNECT_TIMEOUT)
        outgoing = self._client.build_request(
            method, url, headers=headers, content=body, timeout=timeout
        )
        try:
            return await departure.race(self._client.send(outgoing, stream=True), phase="headers")
        except netclient.AddressRefused as exc:
            # Nothing was sent: the upstream's name resolves where the policy doesn't allow.
            reason = exc.verdict.reason
            logs.event(
                "address_refused", purpose="route", host=exc.host, port=exc.port, verdict=reason
            )
            self._tokens.note_refused("route", exc.host, exc.port, reason)
            hint = netclient.private_hint(netclient.guard_key(exc.host, exc.port))
            raise Refused(
                502, f"address refused ({reason}): {hint}", code=netclient.ADDRESS_REFUSED
            ) from exc
        except httpx.HTTPError as exc:
            raise Refused(502, f"upstream request failed: {type(exc).__name__}") from exc

    async def _respond(
        self,
        upstream: httpx.Response,
        route: Route,
        variants: list[bytes],
        departure: Departure,
        log: dict[str, Any],
        *,
        gateway: bool,
    ) -> Response:
        """Relay a stream as it arrives, or buffer and scrub everything else."""
        log["upstream_status"] = upstream.status_code
        if gateway and 300 <= upstream.status_code <= 399:
            # Following it could take the gateway to another route of the vault (M3 design G14).
            await upstream.aclose()
            raise Refused(502, "redirect refused")
        response_headers, header_hits = scrub_headers(
            filter_response_headers(upstream.headers.multi_items(), gateway=gateway), variants
        )

        # Only real streams are relayed as they arrive. Anything else on a stream route (JSON
        # errors especially, which is where upstreams echo keys) is buffered and scrubbed. A 401
        # is never relayed as a stream: it may echo the token it refused.
        content_type = upstream.headers.get("content-type", "")
        if route.stream and upstream.status_code != 401 and _is_stream(content_type):
            log.update(streamed=True, scrubbed=header_hits)
            relayed = [h for h in _raw(response_headers) if h[0] != NO_BUFFERING[0]]
            return Relay(
                upstream,
                route=route.name,
                headers=[*relayed, NO_BUFFERING],
                scrubber=_scrubber(content_type, variants),
                departure=departure,
                scrubbed=header_hits,
            )

        try:
            content = await departure.race(
                _read_limited(upstream, MAX_RESPONSE_BYTES), phase="relay"
            )
        except httpx.HTTPError as exc:
            raise Refused(502, f"upstream response failed: {type(exc).__name__}") from exc
        finally:
            await upstream.aclose()
        if content is None:
            raise Refused(502, "upstream response over the limit")

        body_hits = 0
        content_type = upstream.headers.get("content-type", "").lower()
        # The gateway passes what it gets on to agents, so its answers are scrubbed whatever
        # their size or type (M3 design J.2).
        if variants and (
            gateway
            or (len(content) <= MAX_SCRUB_BYTES and content_type.startswith(_SCRUBBED_TYPES))
        ):
            content, body_hits = scrub(content, variants)
        log.update(bytes_out=len(content), scrubbed=header_hits + body_hits)
        response = Response(content, status_code=upstream.status_code)
        response.raw_headers = [
            *_raw(response_headers),
            (b"content-length", str(len(content)).encode()),
        ]
        return response


def _head(copy: ReportStore) -> Response:
    return JSONResponse(copy.head().to_json(), headers={"cache-control": "no-store"})


def _report_headers(request: Request) -> None:
    """A report's ``Content-Type`` and ``Content-Length``, checked before its body is read."""
    if _json_length(request) > ledgerreport.MAX_BODY_BYTES:
        raise Refused(413, "a report is at most 1 MiB", code="too_large")


def _json_length(request: Request, *, kind: str = "a report") -> int:
    """The ``Content-Length`` of a body that must be one ``Content-Type: application/json``
    (415), with one plain ``Content-Length`` and no ``Transfer-Encoding`` (411), checked before
    the body is read. The caller compares it with its cap."""
    types = request.headers.getlist("content-type")
    if len(types) != 1 or _media_type(types[0]) != "application/json":
        raise Refused(415, f"{kind} is application/json", code="content_type")
    lengths = request.headers.getlist("content-length")
    if (
        request.headers.getlist("transfer-encoding")
        or len(lengths) != 1
        or not (lengths[0].isascii() and lengths[0].isdigit())
        or len(lengths[0]) > 12
    ):
        raise Refused(411, f"{kind} needs one Content-Length", code="length_required")
    return int(lengths[0])


async def _read_report(request: Request) -> bytes:
    """The body, within the cap and :data:`REPORT_DEADLINE`, and as long as it said."""
    too_large = ("a report is at most 1 MiB", "too_large")
    return await _read_json_body(request, ledgerreport.MAX_BODY_BYTES, REPORT_DEADLINE, too_large)


async def _read_json_body(
    request: Request,
    most: int,
    deadline: float,
    too_large: tuple[str, str],
    *,
    kind: str = "the report",
) -> bytes:
    """The body, within ``most`` bytes (413, with ``too_large``'s reason and code) and
    ``deadline`` seconds (408), and as long as its ``Content-Length`` said (400)."""
    chunks: list[bytes] = []
    size = 0
    try:
        async with asyncio.timeout(deadline):
            async for chunk in request.stream():
                size += len(chunk)
                if size > most:
                    raise Refused(413, too_large[0], code=too_large[1])
                chunks.append(chunk)
    except TimeoutError as exc:
        raise Refused(408, f"{kind} came too slowly", code="too_slow") from exc
    if size != int(request.headers["content-length"]):
        raise Refused(400, f"{kind} isn't as long as it said", code="bad_body")
    return b"".join(chunks)


def view_wait(params: list[tuple[str, str]]) -> int:
    """The seconds a view request may wait: ``?wait=N``, at most :data:`VIEW_MAX_WAIT`, or 0.

    Any other parameter, a repeated ``wait``, or a value that isn't plain digits is refused.
    """
    if not params:
        return 0
    if len(params) > 1 or params[0][0] != "wait":
        raise RequestRejected("the view takes one parameter, wait")
    return internal.wait_seconds(params[0][1], VIEW_MAX_WAIT)


def entity_tags(values: list[str]) -> frozenset[str]:
    """The entity tags named by ``If-None-Match`` headers, weak or strong, without quotes.

    A header that isn't a list of entity tags (``*`` included) names none, so the view is sent.
    """
    tags: set[str] = set()
    for value in values:
        for part in value.split(","):
            match = _ENTITY_TAG.fullmatch(part)
            if match is None:
                return frozenset()
            tags.add(match.group(1))
    return frozenset(tags)


async def _disconnected(receive: Receive) -> None:
    """Return once the caller has gone. A GET's body is empty, so nothing else is expected."""
    while (await receive())["type"] != "http.disconnect":
        pass


def _bearer(grant: Grant) -> tuple[str, str]:
    return ("authorization", "Bearer " + grant.token.reveal())


def _challenge_errors(response: httpx.Response) -> list[str]:
    """The ``error`` of each ``WWW-Authenticate`` challenge."""
    return [
        match.group(1)
        for value in response.headers.get_list("www-authenticate")
        for match in _AUTH_ERROR.finditer(value)
    ]


def _token_refused(response: httpx.Response) -> bool:
    """A 401 that a new token may fix: no error in the challenge, or ``invalid_token``.

    ``insufficient_scope`` and ``invalid_request`` won't change with a new token.
    """
    return all(error == "invalid_token" for error in _challenge_errors(response))


def _media_type(content_type: str) -> str:
    return content_type.lower().split(";", 1)[0].strip()


def _is_stream(content_type: str) -> bool:
    return _media_type(content_type) in _STREAM_TYPES


def _scrubber(content_type: str, variants: list[bytes]) -> SSEScrubber | NDJSONScrubber | None:
    """The scrubber for a stream of this type, or None when there is no secret to look for."""
    if not variants:
        return None
    if _media_type(content_type) == SSE_TYPE:
        return SSEScrubber(variants)
    return NDJSONScrubber(variants)


def _raw(headers: list[tuple[str, str]]) -> list[tuple[bytes, bytes]]:
    return [(name.lower().encode("latin-1"), value.encode("latin-1")) for name, value in headers]


class Relay(Response):
    """Relays an upstream stream as it arrives, through its scrubber if it has one.

    The stream ends when the upstream's does, when the caller leaves, when an event is over the
    limit, or when the upstream fails. Whichever it is, the upstream is closed in ``finally`` and
    ``stream_closed`` says which (M3 design F.6, J.2).
    """

    def __init__(
        self,
        upstream: httpx.Response,
        *,
        route: str,
        headers: list[tuple[bytes, bytes]],
        scrubber: SSEScrubber | NDJSONScrubber | None,
        departure: Departure,
        scrubbed: int,
    ) -> None:
        self.status_code = upstream.status_code
        self.raw_headers = headers
        self.background = None
        self._upstream = upstream
        self._route = route
        self._scrubber = scrubber
        self._departure = departure
        self._header_hits = scrubbed
        self._sent = 0

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        started = time.monotonic()
        # Also what a cancelled task (shutdown) logs.
        outcome = "cancelled"
        phase = "relay"
        try:
            await send(
                {
                    "type": "http.response.start",
                    "status": self.status_code,
                    "headers": self.raw_headers,
                }
            )
            try:
                await self._departure.race(self._pump(send), phase="relay")
                outcome = "ok"
            except StreamEventTooLarge:
                # Fail closed: the event is never sent, and neither is anything after it.
                outcome = "event_too_large"
                logs.event("stream_event_too_large", route=self._route)
            except httpx.HTTPError:
                outcome = "upstream_error"
            await send({"type": "http.response.body", "body": b"", "more_body": False})
        except CallerGone as gone:
            outcome = "cancelled"
            phase = gone.phase
        except OSError:
            # The caller left, seen by a failed write.
            outcome = "cancelled"
        finally:
            self._departure.close()
            await self._upstream.aclose()
            fields: dict[str, Any] = {
                "route": self._route,
                "bytes": self._sent,
                "scrubbed": self._header_hits + (self._scrubber.scrubbed if self._scrubber else 0),
                "duration_ms": round((time.monotonic() - started) * 1000, 1),
                "outcome": outcome,
            }
            if outcome == "cancelled":
                fields["phase"] = phase
            logs.event("stream_closed", **fields)

    async def _pump(self, send: Send) -> None:
        scrubber = self._scrubber
        async for chunk in self._upstream.aiter_bytes():
            await self._write(send, chunk if scrubber is None else scrubber.feed(chunk))
        if scrubber is not None:
            await self._write(send, scrubber.finish())

    async def _write(self, send: Send, data: bytes) -> None:
        if data:
            self._sent += len(data)
            await send({"type": "http.response.body", "body": data, "more_body": True})


async def _read_limited(upstream: httpx.Response, limit: int) -> bytes | None:
    chunks: list[bytes] = []
    size = 0
    async for chunk in upstream.aiter_bytes():
        size += len(chunk)
        if size > limit:
            return None
        chunks.append(chunk)
    return b"".join(chunks)
