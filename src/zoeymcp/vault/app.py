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
with ``_``). :mod:`.internal`'s table decides them. Five are for the gateway only: its policy
view, a long poll that a reload wakes (M3 design D.1, D.2); the report path, where it pushes its
ledger to the vault's copy (M5 design J.2); the review job path (M7 design F.2), a long poll
of the review jobs queued at the view it holds and the path it posts each job's result to; and
the status path (M6 design K.1), where it pushes a summary of its status, which the vault keeps
in memory for health and Home (:meth:`VaultApp.gateway_status`). The sixth is the egress role's
allowlists (M7 design G.2), for its key alone and never on the link
socket: a long poll that a reload or an onboarding's allowance change wakes (I.3). The vault
keeps when the role last fetched and the digest it holds, for health's
``egress_allowlist_stale`` (J) and for an onboarding through the role, which waits for it to
fetch a widened list (:meth:`VaultApp.role_fetched`). Whether ``egress_proxy`` is the role is
the startup policy's ``egress_proxy_kind``, never guessed from the fetches. The gateway's
approvals paths (M8 design E.2) collect a held call's result, poll for the endings of held calls,
withdraw a call the gateway abandoned and detach its blocking calls at its stop; each carries the
gateway's epoch, whose rule (G-15) withdraws what only an earlier gateway could use. The rest are
404.
:meth:`VaultApp.queue_review`, :meth:`VaultApp.queue_clear` and :meth:`VaultApp.review_job` queue
and read the jobs for the admin socket and the portal, on :mod:`.reviewjobs`' table; a clear job
(M6 design J.4) goes only to a poll that advertised it runs one.

OAuth routes get an access token from the :class:`TokenManager`. An upstream 401 that says the
token is bad drops it, and a request that's safe to repeat is sent once more with a new token
(design D.10). Neither HTTP client keeps cookies: an upstream's session cookie must never reach
another caller (N2).

Every HTTP client is :mod:`.netclient`'s, guarded (M7 design B.2): an upstream or token endpoint
whose name resolves to a non-global address is refused before anything is sent, unless the
running policy lists its ``host:port`` in ``egress_private``. A route then answers 502
``address_refused``, and the token manager keeps the refusal for health (J). A local MCP route
(a bridge's, A.2 row 9) goes on the local client instead, direct and only to loopback or private
addresses, and a ``unix:`` route on its bridge's socket client, picked by the bridge's name and
refused unless the launcher started that bridge and its socket's listener is the uid it was
given (Q46); neither ever goes through ``egress_proxy``. An upstream's
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
import hashlib
import hmac
import http.cookiejar
import ipaddress
import json
import math
import os
import re
import secrets
import time
import urllib.request
from collections import deque
from collections.abc import Awaitable, Callable, Coroutine, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any, Final, Literal, NoReturn
from urllib.parse import quote, urlsplit

import httpx
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import Receive, Scope, Send

from ..common import approvaltext, canonical, egresslist, envelope, ledgerreport, reviewreport
from ..common.approvaltext import ApprovalText, Header, Plan, Show, Write
from ..common.egresslist import Allowance
from ..common.mcpwire import VERSION_HEADER
from ..common.policy import fields
from ..common.policy.check import local_mcp_routes, secret_references
from ..common.policy.held import (
    HeldConnector,
    HeldMap,
    HeldRoute,
    HoldKey,
    held_map,
    lookup,
    path_key,
    same_hold,
)
from ..common.policy.match import NormalizedPath
from ..common.policy.schema import (
    Approvals,
    Approvers,
    BasicCredential,
    EgressProxyKind,
    GatewayLimits,
    HeaderCredential,
    OAuth2Credential,
    PathCredential,
    PlaceholderCaller,
    Policy,
    QueryCredential,
    Route,
    SMTPConnector,
    TelegramApprover,
    is_secret_ref,
)
from ..common.policy.view import MODE_HEADER, REVISION_HEADER, build_view, dump_view
from ..common.resultstore import (
    Collected,
    Full,
    PendingCall,
    ResultStore,
    Status,
    StoredResult,
)
from ..common.reviewreport import RemoteReport, ToolkitReport
from . import internal, logs, netclient, secretops, statusreport, telegramwire
from . import telegram as telegram_approver
from .approvers import (
    DECIDED_KEPT,
    EDIT_GRACE,
    ApproverHub,
    Closed,
    NotShown,
    PortalQueue,
    Shown,
    Unconfirmed,
    closed_of,
)
from .connectors.smtp import Answer, SmtpConnectors
from .gatewaykeys import GatewayKeys
from .health import TelegramState
from .heldcommit import OUTCOME_MARGIN, HeldCommits, read_answer
from .holds import (
    CapRefusal,
    Decided,
    DecideRefusal,
    Hold,
    HoldRequest,
    HoldTable,
    Limits,
    Via,
    from_earlier_epoch,
)
from .holds import toolkit_block as _toolkit_block
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
    Work,
    named_job,
    read_result,
)
from .store import Secret, SecretStore, SecretUnavailable, smtp_binding
from .vaultledger import ChainUnavailable, VaultLedger

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
# (M5 J.2), the review job path (M7 F.2) and its status path (M6 K.1).
INTERNAL_SEGMENT = internal.SEGMENT
VIEW_PATH = internal.VIEW.path
REPORT_PATH = internal.LEDGER.path
REVIEW_JOBS_PATH = internal.REVIEW_JOBS.path
REVIEW_REPORT_PATH = internal.REVIEW_REPORT.path
STATUS_PATH = internal.STATUS.path
ALLOWLIST_PATH = internal.ALLOWLISTS.path
# A report's body is read within this many seconds (M5 design J.2).
REPORT_DEADLINE = 10.0
# status_received and status_refused are logged at most this often (M6 design N.3).
STATUS_LOG_EVERY = 60.0
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
# The vault hold (M8 design B). The gateway's marker on an Elsewhere call (B.2 E14), and what the
# vault adds to its own answer to an approved held call (B.6, M.1).
MARKER_HEADER = envelope.MARKER_HEADER
APPROVAL_HEADER = "x-zoeymcp-approval"
HELD_REF_HEADER = "x-zoeymcp-held-ref"
# A held connector send's headers (B.3's admitted-set rule, B.7): what the gateway's toolkit
# transport sends (gateway/vaultlink.py), the key the hardened tier presents and the marker.
CONNECTOR_HEADERS: Final = frozenset(
    {
        "content-type",
        "accept",
        "idempotency-key",
        "content-length",
        "accept-encoding",
        "connection",
        "user-agent",
        "host",
        GATEWAY_HEADER,
        MARKER_HEADER,
    }
)
# A held send's Idempotency-Key: its call's ref and its write's number (B.7).
_HELD_KEY = re.compile(r"([0-9a-f]{16})\.([0-9]{1,6})")
# The chain's asked record names a client and a pin: a call with no marker has no reported client,
# and a connector send whose toolkit runs unpinned has no pin; these stand for none (no policy
# name is "-", and no definition hashes to all zeros).
UNREPORTED_CLIENT: Final = "-"
NO_PIN: Final = "sha256:" + "0" * 64
# A relay has no route the vault forwards on: its caps count it on a place of its server's own
# (D.3), which no route's name can be (a route's name has no colon).
RELAY_ROUTE: Final = "relay:"
# A relay's decision, as the gateway's ledger names it, for the hold states that end one (E.2).
_RELAY_DECISIONS: Final[Mapping[str, internal.RelayDecision]] = MappingProxyType(
    {"denied": "decline", "expired": "timeout", "withdrawn": "withdrawn"}
)
# How a hold that ended unforwarded is recorded (J.1): its state and detail to the decision and
# the outcome's detail, and the refusal its waiting request gets (M.2).
_ENDED_DECISIONS: Final[Mapping[str, tuple[str, str | None]]] = MappingProxyType(
    {
        "stream_lost": ("stream_lost", None),
        "shutdown": ("shutdown", "shutdown"),
        "changed": ("withdrawn", "changed"),
        # A host's withdraw is recorded as every withdrawal is (B.5); its own name stays on the
        # hold, for the gateway's text.
        "operator": ("withdrawn", "changed"),
    }
)
_ENDED_CODES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "denied": "approval_declined",
        "expired": "approval_expired",
        "withdrawn": "approval_withdrawn",
    }
)
# The reasons an approval_withdrawn names in its body (step 10's deviation 18), each its own text
# at the gateway: a closed set. A policy change, the host's withdraw, the vault's stop, the
# gateway's stop (a blocking call it detached, I.2) and a new gateway epoch (G-15). A withdrawal
# for any other reason names none.
WITHDRAWN_REASONS: Final = frozenset(
    {"changed", "operator", "shutdown", "gateway_stopped", "gateway_restarted"}
)
# A host's withdraw (K.3): the hold's detail, with via host.
OPERATOR: Final = "operator"
# How long the start's two findings last (K.1, OPS-8): approvals_withdrawn_at_start, unless the
# operator lists the approvals first, and approvals_outcome_unknown.
START_FINDINGS_SECONDS: Final = 24 * 3600.0
# How long an enrolment through the egress role waits for the role to fetch its allowance
# (onboarding's ALLOWANCE_WAIT, I.3).
ENROL_ALLOWANCE_WAIT: Final = 5.0


class Refused(Exception):
    """Stop handling a request with this status. ``reason`` goes to the log only.

    ``code`` is a stable code for the response body, set only after identity and a rule matched.
    ``retry_after`` (seconds) becomes a ``Retry-After`` header, and ``allow`` an ``Allow`` header.
    ``approved`` is the ref of the held call an approval forwarded, whose forward ended in this
    refusal: the answer carries the approval's headers too (M8 design B.6, C.2), and its body the
    forward's outcome on the chain, so the gateway records the call as approved, as it ended.
    """

    def __init__(
        self,
        status: int,
        reason: str,
        *,
        code: str | None = None,
        retry_after: int | None = None,
        allow: str | None = None,
        extra: Mapping[str, Any] | None = None,
        approved: str | None = None,
    ) -> None:
        self.status = status
        self.reason = reason
        self.code = code
        self.retry_after = retry_after
        self.allow = allow
        self.approved = approved
        # Fields the body carries beside the code: a held call's JSON pointer or deadline, or a
        # withdrawal's reason, never a value (M8 design B.2, B.6).
        self.extra = dict(extra or {})
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

    @property
    def gone(self) -> asyncio.Future[None]:
        """Done once the caller has left: what a held request's wait races (M8 design B.6)."""
        return self._gone

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


def _no_socket_client(_bridge: str) -> httpx.AsyncClient | None:
    """No bridge was started: every ``unix:`` route answers ``unknown_socket``."""
    return None


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
class _Authorized:
    """A request with its credential (B.3's ``_authorize``): the URL, the headers and the secret
    variants its answer is scrubbed for."""

    url: str
    headers: list[tuple[str, str]]
    variants: list[bytes]
    cred: Any
    grant: Grant | None


@dataclass(frozen=True, repr=False)
class _Done:
    """A held call's forward, ended: what the waiting request gets (an answer, or a refusal),
    the outcome the chain records, and what the result store keeps for a request that left."""

    response: Response | Refused
    outcome: str
    detail: str | None
    writes_sent: int
    writes_unknown: int
    stored: StoredResult


Forward = Callable[[Hold], Awaitable[_Done]]


@dataclass(frozen=True, repr=False)
class _Ask:
    """What a held call asks for, before its hold begins (B.3, B.7)."""

    route: str
    key: HoldKey
    server: str
    tool: str
    client: str | None  # the marker's, else not reported
    ref: str | None  # the marker's or the send's key's; None: the vault mints one
    epoch: str | None
    wait: Literal["block", "pending"]
    era: Literal["legacy", "modern"]
    legacy_session: bool
    # A dropped request stream is its cancel (2026-07-28, and a toolkit's send); at the earlier
    # eras a disconnect isn't, and the agent's cancel arrives as a notification (B.6).
    modern: bool
    arguments: canonical.JSONValue
    pin: str | None
    writes: int
    held_bytes: int
    block_seconds: float | None
    seconds: float  # the forward's deadline: call_timeout plus OUTCOME_MARGIN (B.8)
    render: Callable[[Header], ApprovalText]
    forward: Forward
    request_key: tuple[str, str | None, str] | None = None


@dataclass(eq=False)
class _Wait:
    """A hold's place and its delivery: the request waiting for it (if any) is woken through
    ``changed`` and answered through ``answer``."""

    key: HoldKey
    forward: Forward
    modern: bool
    seconds: float
    asked_ms: int
    deadline_ms: int
    answer: asyncio.Future[Response | Refused]
    changed: asyncio.Event = field(default_factory=asyncio.Event)
    request_key: tuple[str, str | None, str] | None = None
    # A legacy-era caller left while the call was held: its hold goes on, unanswered (B.6).
    left: bool = False


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


def _unread(reason: envelope.Reason) -> Refused:
    """A held request the vault can't read unambiguously (B.2's rules), code ``held_<reason>``."""
    return Refused(
        envelope.Refuse(reason).status,
        f"the vault can't read this request unambiguously ({reason})",
        code=f"held_{reason}",
    )


def _hold_limits(policy: Policy) -> Limits:
    """What the vault's own policy sets for every hold (I.1 step 3)."""
    approvers = policy.approvers or Approvers()
    approvals = Approvals() if policy.gateway is None else policy.gateway.approvals
    return Limits(
        timeout=float(approvers.timeout),
        block_seconds=float(approvers.block_seconds),
        cooldown=float(approvals.cooldown),
        max_prompts_per_hour=approvals.max_prompts_per_hour,
    )


def _result_times(policy: Policy) -> tuple[int, int]:
    """The result store's TTL (``approvers.result_ttl``) and its grace past a deadline: the
    longest forward, the longest effective call_timeout plus OUTCOME_MARGIN (F.2), in ms."""
    approvers = policy.approvers or Approvers()
    gateway = policy.gateway
    longest = 0 if gateway is None else gateway.limits.call_timeout
    for server in () if gateway is None else gateway.servers.values():
        longest = max(longest, server.call_timeout or 0)
    return approvers.result_ttl * 1000, int((longest + OUTCOME_MARGIN) * 1000)


def _approvers_kept(before: Approvers | None, after: Approvers | None) -> bool:
    """Z7: whether holds begun under ``before`` may stay under ``after``. Any change to the block
    withdraws them (its waits set their times, Z23, and a surface's settings where they are
    shown), except a surface switched on or off, which B.5's surface rule decides."""
    if before is None or after is None:
        return True  # no surface is left, or none was: B.5's surface rule decides
    for name in ("telegram", "portal"):
        old, new = getattr(before, name), getattr(after, name)
        if old is not None and new is not None and old != new:
            return False
    waits = ("timeout", "block_seconds", "result_ttl")
    return all(getattr(before, name) == getattr(after, name) for name in waits)


def _not_shown(shown: Sequence[Shown | NotShown | Unconfirmed]) -> NotShown | None:
    """The surfaces' answer that refuses a hold, or None: a text Telegram returned changed, as
    G.4 says, whatever the other surfaces answered (the operator would read something else);
    else every surface's own :class:`~.approvers.NotShown` (one that failed may still deliver
    it, G.3, so the hold waits on, to its deadline)."""
    refusals = [each for each in shown if isinstance(each, NotShown)]
    for each in refusals:
        if each.code == telegramwire.TextChanged.code:
            return each
    return refusals[0] if shown and len(refusals) == len(shown) else None


def _surfaces(policy: Policy) -> frozenset[Literal["telegram", "portal"]]:
    """The surfaces ``approvers`` enables (D.4)."""
    approvers = policy.approvers
    found: set[Literal["telegram", "portal"]] = set()
    if approvers is not None and approvers.telegram is not None:
        found.add("telegram")
    if approvers is not None and approvers.portal is not None:
        found.add("portal")
    return frozenset(found)


def _relayable(policy: Policy, client: str | None, server: str, tool: str) -> bool:
    """Whether ``policy`` has the gateway hold ``tool`` of ``server`` (in its ``approve`` list
    and not ``vault_approval``) for ``client``, which it assigns the server and lets raise
    out-of-band prompts, with a surface to ask on (E.1, Z11): the calls a relay is for (Z7)."""
    gateway = policy.gateway
    if gateway is None or client is None or not _surfaces(policy):
        return False
    known, served = gateway.clients.get(client), gateway.servers.get(server)
    if known is None or served is None or server not in known.servers:
        return False
    if known.approvals is None or not known.approvals.out_of_band:
        return False
    return tool in served.tools.approve and tool not in served.tools.vault_approval


def _request_key(
    route: str, session: str | None, request_id: str | int
) -> tuple[str, str | None, str]:
    """A held request's place for a cancel (B.1 step 5): its route, its ``Mcp-Session-Id`` and
    its JSON-RPC id, typed (the string "1" isn't the number 1)."""
    return route, session, json.dumps(request_id)


def _wall_ms() -> int:
    return int(time.time() * 1000)


def _iso_ms(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, UTC).isoformat(timespec="seconds")


def _waited(hold: Hold) -> int:
    decided = hold.decided_at if hold.decided_at is not None else hold.asked_at
    return max(0, round((decided - hold.asked_at) * 1000))


def _approved(ref: str) -> list[tuple[bytes, bytes]]:
    """What the vault adds to its answer to an approved held call (B.6, M.1)."""
    return [(APPROVAL_HEADER.encode(), b"approved"), (HELD_REF_HEADER.encode(), ref.encode())]


def _failed(refused: Refused, outcome: str) -> _Done:
    """A held forward that ended in the vault's own refusal, with its outcome on the chain."""
    return _Done(refused, outcome, None, 0, 0, _refusal_result(refused))


def _refusal_result(refused: Refused) -> StoredResult:
    """A refused forward's answer as the result store keeps it: the vault's refusal body."""
    body: dict[str, Any] = {"error": _PUBLIC_MESSAGES.get(refused.status, "error")}
    if refused.code is not None:
        body["code"] = refused.code
    return StoredResult(refused.status, "application/json", json.dumps(body).encode())


# A guard's refusal (netclient's AddressRefused, SocketRefused) is a ConnectError too.
_UNSENT = (httpx.ConnectError, httpx.ConnectTimeout)


def _not_sent(refused: Refused) -> bool:
    """Whether a forward refused on its way out never reached the upstream: refused before the
    request was built, or by a connection that didn't open."""
    cause = refused.__cause__
    return cause is None or isinstance(cause, _UNSENT)


def _send_outcome(answer: Answer) -> tuple[str, str | None, int, int]:
    """A held send's outcome on the chain, from the connector's answer (J.1, B.7): sent, its
    outcome unknown, refused by the mail server, or refused before anything was sent."""
    code = answer.body.get("code")
    if answer.status == 200:
        return "ok", "sent", 1, 0
    if code == "smtp_outcome_unknown":
        return "unknown", None, 0, 1
    if isinstance(code, str) and code.startswith("smtp_"):
        return "upstream_error", "smtp_refused" if code == "smtp_refused" else None, 0, 0
    return "refused", None, 0, 0


def _mail_plan(connector: str, value: Mapping[str, canonical.JSONValue]) -> Plan:
    """The vault's own plan of a held send (B.7): no toolkit layout is trusted (M4 Q5's
    ``pinning: off``), so the vault shows the expected addresses, the subject and the reply as
    lines and the body as a block."""
    show = [
        Show.line("From", "/expect_from"),
        Show.line("To", "/expect_to"),
        Show.line("Subject", "/subject"),
    ]
    if "in_reply_to" in value:
        show.append(Show.line("In reply to", "/in_reply_to"))
    show.append(Show.block("/body"))
    return Plan(f"Mail through {connector}", [Write.post("/send", value, show=show)])


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
        local_client: httpx.AsyncClient | None = None,
        socket_clients: Callable[[str], httpx.AsyncClient | None] | None = None,
        tokens: TokenManager | None = None,
        environ: Mapping[str, str] | None = None,
        gateway_keys: GatewayKeys | None = None,
        gateway_link: bool = False,
        connectors: SmtpConnectors | None = None,
        reports: ReportStore | None = None,
        review_jobs: JobTable | None = None,
        chain: VaultLedger | None = None,
        hub: ApproverHub | None = None,
        hold_clock: Callable[[], float] = time.monotonic,
        telegram: telegram_approver.Timings | Literal[False] | None = None,
        approver_client: httpx.AsyncClient | None = None,
        queue: bool | None = None,
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

        ``local_client`` reaches a local MCP route's upstream (M7 design A.2 row 9, B.2): by
        default :mod:`.netclient`'s, direct and only to loopback or private addresses.
        ``socket_clients`` gives a ``unix:`` route's client by the bridge's name, or None for a
        bridge the launcher didn't start (Q46); by default there is none, as in the hardened
        tier, and the server passes :class:`.netclient.SocketClients` for its ``--bridge`` list.
        When ``client`` is given and either isn't, ``client`` serves that role too, so a test or
        a self-test that injects a client never falls back to a networked one.

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

        ``chain`` is the vault's approval chain, recovered before the listeners open (M8 design
        J.1); without one (or :meth:`use_chain`), every held call is refused ``held_ledger_down``
        (no chain, no hold). ``hub`` holds the approver surfaces a hold is shown on (D.1), and
        ``hold_clock`` the monotonic clock the hold table runs on (tests inject one).

        ``telegram`` is the Telegram surface's timings (G.3, BP-10): each install starts, stops
        or restarts that surface in ``hub`` as ``approvers.telegram`` comes, goes or changes
        (B.5, I.4). None is :data:`.telegram.TIMINGS`, or, with ``hub`` given, ``False``: the
        test's hub holds its own surfaces. ``approver_client`` reaches the Bot API (G.2): by
        default :func:`.netclient.approver_client`, on the startup ``egress_proxy`` (D-61), or
        ``client`` when that is given.

        ``queue`` says whether this vault keeps the portal's Approvals queue (H.1), installed in
        ``hub`` while ``approvers.portal`` is set: None is True, or, with ``hub`` given, False, as
        for ``telegram``.
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
        if local_client is None and not injected:
            timeout = httpx.Timeout(READ_TIMEOUT, connect=CONNECT_TIMEOUT)
            local_client = netclient.local_client(timeout=timeout)
        self._local_client = without_cookies(local_client or self._client)
        if socket_clients is None:
            injected_client = self._client
            socket_clients = (lambda _name: injected_client) if injected else _no_socket_client
        self._socket_clients = socket_clients
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
        # The gateway's latest status report and its arrival (monotonic), for health and Home
        # (M6 design K.1); none since the vault started counts from the start. Reports are read
        # one at a time, at most one accepted per 5 s; status_received and status_refused are
        # logged at most once a minute each.
        self._status: tuple[statusreport.Report, float] | None = None
        self._status_watcher: Callable[[statusreport.Report], None] | None = None
        self._status_gate = internal.StatusGate()
        self._status_logged: dict[str, float] = {}
        self._started = time.monotonic()
        # A managed vault's head as its view answers state it (M6 design K.3); None: no header.
        self._head_stated: str | None = None
        # The vault hold (M8 design B): the routes held, the hold table on its clock with each
        # hold's place and delivery, the result store, the committed registry, the surfaces, and
        # the tasks that write a hold's ending. Every hold is in memory only (Z10).
        self._chain = chain
        self._hub = hub or ApproverHub()
        self._clock = hold_clock
        self._held: HeldMap = MappingProxyType({})
        self._holds = HoldTable(_hold_limits(policy))
        self._results = ResultStore(*_result_times(policy))
        self._commits = HeldCommits()
        self._waits: dict[str, _Wait] = {}
        # Each held request's place for a cancel, to the holds there (B.1 step 5).
        self._requests: dict[tuple[str, str | None, str], set[str]] = {}
        self._finishing: set[asyncio.Task[None]] = set()
        # Approved holds whose forward hasn't entered the registry yet (its decided accept is
        # being written), with that forward's deadline, and the event set as each enters.
        self._approving: dict[str, float] = {}
        self._entered = asyncio.Event()
        # The approvers block holds were begun under, for Z7's withdraw on its change.
        self._approvers: Approvers | None = None
        # The gateway's approvals paths (E.2): the gateway epochs seen (the epoch rule, G-15),
        # the vault's own epoch (one per start), the endings the decisions poll answers, the
        # event that wakes it (each ending sets it and puts a new one in its place), and how
        # many polls wait.
        self._epochs = internal.Epochs()
        self._vault_epoch = secrets.token_hex(6)
        self._feed = internal.Feed()
        self._feed_changed = asyncio.Event()
        self._decision_waiters = 0
        # The Telegram approver (G.2, I.4): its timings, or False when the hub's surfaces are a
        # test's; its client, built once from the startup policy (D-61); the surface the
        # installs start, stop and restart, whether the hub shows holds on it (not while its
        # token is shared, T-5), and whether serve() has started the surfaces' tasks.
        if telegram is None:
            telegram = False if hub is not None else telegram_approver.TIMINGS
        self._telegram_timings: telegram_approver.Timings | Literal[False] = telegram
        if approver_client is None and telegram is not False:
            approver_client = self._client if injected else netclient.approver_client(proxy)
        self._approver_client = approver_client
        self._telegram: telegram_approver.TelegramSurface | None = None
        self._telegram_shown = False
        # The endings the last surface that went remembered, for the next one (G.6).
        self._telegram_ended: dict[str, str] = {}
        self._approvers_running = False
        # The portal's queue (H.1), and the hold clock's offset from the wall clock, taken once,
        # so a time the queue shows and a plan holds is the same on every read (M5 9a).
        self._portal_queue = (
            PortalQueue(self._clock) if (hub is None if queue is None else queue) else None
        )
        self._wall_offset = time.time() - self._clock()
        # The last holds closed on any surface, newest first, for the host's approvals list
        # (K.3); the host's Telegram enrolment (G.8), open or not; and the secret an enrolment
        # found contested, for health (approver_contested) until the next one opens.
        self._closed: deque[Closed] = deque(maxlen=DECIDED_KEPT)
        self._enrolment: telegram_approver.Enrolment | None = None
        self._enrol_contested: str | None = None
        # When the chain's start was taken on the hold clock, and whether the operator has
        # listed the approvals since (approvals_withdrawn_at_start then clears, K.1).
        self._chain_at = self._clock()
        self._start_listed = False
        if chain is not None:
            chain.remember(self._holds, self._clock())
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
        # The routes the local and socket clients serve, from the running policy, so a reload
        # that adds a bridge's route needs no restart (M7 design B.2).
        self._local_routes = local_mcp_routes(policy)
        self._env_secrets = snapshot_env_secrets(policy, self._environ)
        self._view = _ServedView(view.digest, dump_view(view))
        # A new generation retires the old egress key at once: there is no ratchet (G.3).
        self._egress_key = self._keys.egress_key(policy.egress_key_generation).encode()
        withdrawn = self._install_holds(policy)
        self._install_telegram(policy, withdrawn)
        self._install_queue(policy)
        # B.5: a hold still shown on a surface left stays there alone (Z7).
        self._holds.narrow(_surfaces(policy))
        self._wake_view_waiters()
        self._wake_allowlist()
        return self._tokens.configure(policy, self._env_secrets)

    def _install_holds(self, policy: Policy) -> list[Hold]:
        """The held routes of ``policy``, its limits for new holds, and every undecided hold the
        change no longer holds as it was, withdrawn ``changed`` (M8 design B.5, Z7): all of them
        when the approvers block changed other than by a surface switched on or off. Returns
        the holds withdrawn."""
        old, self._held = self._held, held_map(policy)
        before, self._approvers = self._approvers, policy.approvers
        self._holds.configure(_hold_limits(policy))
        self._results.ttl_ms, self._results.grace_ms = _result_times(policy)
        if not len(self._holds):
            return []
        now = self._clock()
        kept = _approvers_kept(before, policy.approvers)
        withdrawn = self._holds.withdraw(
            now, lambda h: not kept or not self._still_held(h, old, self._held, policy), "changed"
        )
        for hold in withdrawn:
            self._spawn(self._ended(hold))
        return withdrawn

    def _install_queue(self, policy: Policy) -> None:
        """Show holds on the portal's queue while ``approvers.portal`` is set (H.1); a hold
        left with no surface when it goes is the install's to withdraw (B.5)."""
        if self._portal_queue is None:
            return
        if "portal" in _surfaces(policy):
            self._hub.install(self._portal_queue)
        else:
            self._hub.remove("portal")

    def _install_telegram(self, policy: Policy, withdrawn: Iterable[Hold]) -> None:
        """Start, stop or restart the Telegram surface as ``approvers.telegram`` comes, goes or
        changes (B.5, I.4), so a host import or a reload needs no restart. A surface that goes
        edits each message still open ("This approver was switched off.", or the ending of a
        hold this change withdrew), and its queued edits get :data:`.approvers.EDIT_GRACE`. A
        token another secret shares is never polled (``approver_token_shared``, T-5), at this
        install or a later one."""
        if self._telegram_timings is False:
            return
        approvers = policy.approvers
        settings = None if approvers is None else approvers.telegram
        old = self._telegram
        if old is not None and old.settings == settings:
            self._telegram_check(old)
            return
        if old is not None:
            old.retire({hold.id: hold for hold in withdrawn})
            # A late press on a message it closed still reads how that hold ended (G.6).
            self._telegram_ended = old.endings()
            self._telegram_hide(old)
            self._telegram = None
        if settings is None or self._approver_client is None:
            return
        self._telegram = surface = telegram_approver.TelegramSurface(
            settings,
            store=self._store,
            client=self._approver_client,
            decide=self.decide,
            shared=lambda token: self._token_shared(settings, token),
            clock=self._clock,
            timings=self._telegram_timings,
            ended=self._telegram_ended,
        )
        self._telegram_check(surface)

    def _telegram_check(self, surface: telegram_approver.TelegramSurface) -> None:
        """Show holds on ``surface``, running, unless another secret holds its token or bot."""
        shared = surface.token_shared()
        if shared:
            logs.event("approver_token_shared", surface="telegram", level="error")
            if self._telegram_shown:
                surface.retire({})
                self._telegram_hide(surface)
        elif not self._telegram_shown:
            self._hub.install(surface)
            self._telegram_shown = True
            if self._approvers_running:
                surface.start()

    def _telegram_hide(self, surface: telegram_approver.TelegramSurface) -> None:
        """No hold is shown on ``surface`` from now on; it stops once its queued edits went."""
        if self._telegram_shown:
            self._hub.remove("telegram")
            self._telegram_shown = False
        if surface.running:
            self._spawn(surface.stop(EDIT_GRACE))

    def _token_shared(self, settings: TelegramApprover, token: str) -> bool:
        """G.7, T-5: another store secret, or an ``env:`` secret the policy reads, holds the
        approver bot's token, a token of the same bot or the token's secret half; or a route to
        the Bot API sends a credential that carries the bot's id. Store values are compared
        inside the store; none is kept."""
        matches = telegram_approver.same_bot(token)
        if self._store.matching(telegram_approver.secret_name(settings) or "", matches):
            return True
        if any(matches(secret.reveal()) for secret in self._env_secrets.values()):
            return True
        return self._route_carries(token)

    def _route_carries(self, token: str) -> bool:
        """G.7's route clause: a route to ``api.telegram.org`` whose credential, as the route
        would send it (its template's text with its secret in place), carries the approver
        bot's id, ``<id>:``. A secret the route can't read counts as empty, so a template that
        names the id alone is enough (fail closed)."""
        bot = telegramwire.bot_id(token)
        if bot is None:
            return False
        host = urlsplit(telegramwire.API).hostname
        for route in self._policy.routes:
            upstream = route.upstream
            if upstream is None or route.credential is None:
                continue
            if upstream.startswith(fields.UNIX_PREFIX) or urlsplit(upstream).hostname != host:
                continue
            cred = self._policy.credentials.get(route.credential)
            if cred is None or isinstance(cred, OAuth2Credential):
                continue
            if f"{bot}:" in self._credential_sent(cred, upstream):
                return True
        return False

    def _credential_sent(
        self,
        cred: HeaderCredential | QueryCredential | PathCredential | BasicCredential,
        upstream: str,
    ) -> str:
        """What a static credential puts on a request to ``upstream`` (unencoded), for
        :meth:`_route_carries` alone; a secret it can't read is empty."""

        def value(ref: str) -> str:
            try:
                return self._resolve(ref, upstream).reveal()
            except Refused:
                return ""

        secret = value(cred.secret)
        if isinstance(cred, HeaderCredential):
            return cred.format.replace("{secret}", secret)
        if isinstance(cred, PathCredential):
            return cred.template.replace("{secret}", secret)
        if isinstance(cred, BasicCredential):
            user = value(cred.username) if is_secret_ref(cred.username) else cred.username
            return f"{user}:{secret}"
        return secret

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

    @property
    def decision_waiters(self) -> int:
        """How many decisions polls are waiting (M8 design E.2)."""
        return self._decision_waiters

    def stop_view_waits(self) -> None:
        """Answer every long poll of the view, of the review jobs and of the allowlists now, and
        the socket's review waits and an onboarding's wait for the egress role, and wait no
        more. For shutdown: the servers wait for requests in flight, and a long poll would hold
        them for up to 25 s. Every undecided hold is withdrawn too, and the decisions poll
        answered (M8 design I.2)."""
        self._view_stopping = True
        self.stop_holds()
        self._wake_decisions()
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
        allowances, an open Telegram enrolment's included (M8 design G.2), as
        ``egresslist.document`` writes them."""
        allowances = [*self._allowances()]
        if self._enrolment is not None and self._enrolment.open:
            allowances.append(egresslist.enrolment_allowance())  # G.2, Q43
        return egresslist.document(egresslist.derive(self._policy, allowances))

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

    def gateway_status(self) -> statusreport.GatewayStatus:
        """The gateway's latest status report and its age, for health and Home (K.1): the
        seconds since it arrived, or since the vault started when none has."""
        if self._status is None:
            return statusreport.GatewayStatus(None, max(0.0, time.monotonic() - self._started))
        report, at = self._status
        return statusreport.GatewayStatus(report, max(0.0, time.monotonic() - at))

    def keep_status(self, report: statusreport.Report) -> None:
        """Keep ``report`` as the gateway's latest, arrived now, and tell the watcher."""
        self._status = (report, time.monotonic())
        if self._status_watcher is not None:
            self._status_watcher(report)

    def watch_status(self, watcher: Callable[[statusreport.Report], None]) -> None:
        """Call ``watcher`` with each status report kept (a managed vault's restore witness,
        M6 design K.3)."""
        self._status_watcher = watcher

    def state_head(self, deployment: str, revision: int) -> None:
        """State ``revision`` of ``deployment`` beside every view answer from now on (M6 design
        K.3): a managed vault's running head. A declarative vault never states one."""
        self._head_stated = f"{deployment}.{revision}"

    async def role_fetched(self, wait: float) -> bool:
        """Wake every allowlist poll, then wait up to ``wait`` seconds for the egress role to
        hold the lists as they are now (I.3). The role names the digest it holds in
        ``If-None-Match``, and it polls again as soon as it has applied a 200, so a poll naming
        the current digest means the role allows what the lists do. A role not seen since the
        vault started is waited for the same way, so one still starting up (or back after a
        vault restart) is given its chance. False when it doesn't hold them by then, or at
        shutdown."""
        self._wake_allowlist()
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
            approver = self._approver_client
            if approver is not None and approver is not self._client:
                await approver.aclose()
            if self._token_client is not None and self._token_client is not self._client:
                await self._token_client.aclose()
            if self._onboarding_client is not self._client:
                await self._onboarding_client.aclose()
            if self._revocation_client is not self._client:
                await self._revocation_client.aclose()
            if self._local_client is not self._client:
                await self._local_client.aclose()
            if isinstance(self._socket_clients, netclient.SocketClients):
                await self._socket_clients.aclose()

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
            body.update({k: v for k, v in refusal.extra.items() if v is not None})
            if refusal.retry_after is not None:
                headers["retry-after"] = str(refusal.retry_after)
            if refusal.allow is not None:
                headers["allow"] = refusal.allow
            if refusal.approved is not None:
                headers.update((k.decode(), v.decode()) for k, v in _approved(refusal.approved))
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

        # M8 design B.1 step 2: held by route, never by path (T-1).
        hold = lookup(self._held, route.name)
        if isinstance(hold, HeldConnector) and route.connector is not None:
            return await self._held_connector(request, route.connector, hold, rest, log)
        if isinstance(hold, HeldRoute) and route.connector is None:
            return await self._held_route(
                request, route, hold, rest, params, (used_query, used_header), log
            )
        if hold is not None:  # a map built for another kind of route: fail closed
            raise Refused(404, "a held route answers its own paths only", code="held_path")
        if request.headers.getlist(MARKER_HEADER):
            # B.1 step 3: a held call's marker on a route that holds nothing (Z5).
            raise Refused(409, "a marked call on a route the vault doesn't hold", code="view_stale")
        if route.connector is not None:
            return await self._connector(request, route.connector, rest, log)
        body = await self._read_body(request)
        return await self._forward(
            request, route, rest, params, (used_query, used_header), body, caller, log
        )

    async def _authorize(
        self,
        route: Route,
        incoming: Iterable[tuple[str, str]],
        rest: NormalizedPath,
        params: list[tuple[str, str]],
        used: tuple[str | None, str | None],
        log: dict[str, Any],
    ) -> _Authorized:
        """The request as it goes upstream, with the route's credential (M8 design B.3, Z2): the
        plain path calls this at once, and a hold only after its approval. ``used`` is the
        caller's query parameter and header that held its placeholder, dropped."""
        assert route.upstream is not None  # noqa: S101 - guaranteed by the schema
        used_query, used_header = used
        if route.upstream.startswith(fields.UNIX_PREFIX):
            # A bridge's socket is the whole upstream: the server's path is the HTTP path, on
            # the request base every bridge shares (its client is picked by name, in _send).
            base_path, upstream_origin = "", netclient.BRIDGE_BASE
        else:
            upstream = urlsplit(route.upstream)
            base_path = upstream.path.rstrip("/")
            upstream_origin = f"{upstream.scheme}://{upstream.netloc}"
        headers = filter_request_headers(incoming, drop=[used_header] if used_header else ())
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
        return _Authorized(url, headers, variants, cred, grant)

    async def _forward(
        self,
        request: Request,
        route: Route,
        rest: NormalizedPath,
        params: list[tuple[str, str]],
        used: tuple[str | None, str | None],
        body: bytes,
        caller: str,
        log: dict[str, Any],
    ) -> Response:
        """Today's path (design §4.1): the credential at once, then the upstream, with the caller
        watched while the vault waits."""
        authorized = await self._authorize(route, request.headers.items(), rest, params, used, log)
        url, headers, variants = authorized.url, authorized.headers, authorized.variants
        cred, grant = authorized.cred, authorized.grant
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
        if decided is internal.STATUS:
            return await self._status_report(request, log)
        if decided is internal.COLLECT:
            return await self._collect(request, log)
        if decided is internal.DECISIONS:
            return await self._decisions(request, log)
        if decided is internal.WITHDRAW:
            return await self._withdraw(request, log)
        if decided is internal.DETACH:
            return await self._detach(request, log)
        if decided is internal.ASK:
            return await self._ask(request, log)
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
        waits up to N seconds for a reload that changes the view (M3 design D.2). Both carry the
        policy's mode, outside the view and its digest, and in managed mode the head the vault
        runs, for the gateway's restore witness (M6 design K.3)."""
        try:
            wait = view_wait(parse_query(request.scope.get("query_string", b"")))
        except RequestRejected as exc:
            raise Refused(400, exc.reason) from exc
        tags = entity_tags(request.headers.getlist("if-none-match"))
        started = time.monotonic()
        if wait and self._view.digest in tags and not self._view_stopping:
            await self._wait_for_view(tags, started + wait, request.receive, log)
        view = self._view
        headers = {
            "etag": f'"{view.digest}"',
            "cache-control": "no-store",
            MODE_HEADER: self._policy.mode,
        }
        if self._head_stated is not None:
            headers[REVISION_HEADER] = self._head_stated
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
        """``GET /_zoeymcp/gateway/v1/review/jobs?wait=N&view=<digest>&kinds=review,clear``: the
        jobs queued at the view digest the gateway's policy client holds, of the kinds it runs,
        now ``sent``, once there are any, or none after N seconds (at most 25), at shutdown, or
        when the caller leaves. One poll waits at a time (429); while it waits the poller counts
        as seen (CR-15). A review job is ``{"id", "server"}`` exactly, as an older gateway reads
        it, and a clear job adds ``"kind": "clear"``; a poll that advertises no kinds gets
        review jobs only (M6 design J.4, G-8).

        A poll at the view served when it began also ends, with none, once the view changes,
        so the gateway polls again at its new view and a review queued right after a reload
        doesn't wait out the poll (D-189, M6 design K.5). A poll at a view no longer served (a
        gateway still behind) waits as before, so a lagging gateway can't spin."""
        try:
            wait, digest, kinds = internal.jobs_query(
                parse_query(request.scope.get("query_string", b""))
            )
        except RequestRejected as exc:
            raise Refused(400, exc.reason) from exc
        table = self._reviews
        if table.waiting >= internal.REVIEW_WAITERS:
            raise Refused(429, "a review poll is already waiting", retry_after=1)
        table.poll_began(kinds)
        # A queue call waiting for the first poll after the vault started goes on (OPS-20).
        self._wake_reviews()
        gone = asyncio.ensure_future(_disconnected(request.receive))
        # Set by the next install, if this poll is at the view served now.
        view_changed = self._view_changed if digest == self._view.digest else None
        left = False
        try:
            deadline = table.now() + wait
            while not table.offered(digest, kinds) and not self._view_stopping:
                if view_changed is not None and view_changed.is_set():
                    if self._view.digest != digest:
                        break
                    view_changed = self._view_changed  # the same view installed again
                remaining = deadline - table.now()
                if remaining <= 0:
                    break
                changed = asyncio.ensure_future(self._reviews_changed.wait())
                waits = [changed, gone]
                if view_changed is not None:
                    waits.append(asyncio.ensure_future(view_changed.wait()))
                try:
                    await asyncio.wait(
                        waits, timeout=remaining, return_when=asyncio.FIRST_COMPLETED
                    )
                finally:
                    for waiting in waits:
                        if waiting is not gone:
                            waiting.cancel()
                if gone.done():
                    left = log["disconnected"] = True
                    break
        finally:
            table.poll_ended()
            # On a task that has already failed, cancel() also marks its error as retrieved.
            gone.cancel()
            self._log_review_ends()
        # A job is sent only to a poll that is still there to take it.
        claimed = () if left else table.claim(digest, kinds)
        if claimed:
            self._wake_reviews()
        log["jobs"] = len(claimed)
        jobs = [_job_wire(job) for job in claimed]
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
        if job.work == "clear":
            event["clear"] = True
        if job.report is None:
            event.update(reason=job.failure, code=result.code)
        else:
            event["tools"] = len(job.report.tools)
            if job.failure is not None:  # clear_not_clean keeps the review that found them (J.4)
                event["reason"] = job.failure
        logs.event("review_reported", **event)
        answer = {"v": 1, "job": job.id, "state": job.state}
        return JSONResponse(answer, headers={"cache-control": "no-store"})

    # --- the gateway's status report (M6 design K.1) -----------------------------------------

    async def _status_report(self, request: Request, log: dict[str, Any]) -> Response:
        """``POST /_zoeymcp/gateway/v1/report/status``: the gateway's status (K.1, FM-19).

        Before any body byte is read: no query (400), exactly one ``Content-Type:
        application/json`` (415) and one ``Content-Length`` (411) of at most 256 KiB (413
        ``too_large``). Then one report at a time, and at most one accepted per 5 s (429
        ``too_soon``, :class:`.internal.StatusGate`). The body is read within 256 KiB and 10 s
        (408) and parsed strictly; :func:`.statusreport.read` refuses a report whole (400
        ``invalid`` or ``witness_range``), or keeps it as the latest, its bad entries dropped.
        Refusals log ``status_refused`` and accepted reports ``status_received``, each at most
        once a minute."""
        if request.scope.get("query_string"):
            raise Refused(400, "the status path takes no query")
        most = internal.STATUS_MAX_BYTES
        try:
            if _json_length(request, kind="a status report") > most:
                raise Refused(413, "a status report is at most 256 KiB", code="too_large")
            refused = self._status_gate.begin(time.monotonic())
            if refused is not None:
                raise Refused(refused.status, refused.reason, code="too_soon", retry_after=1)
        except Refused as exc:
            self._status_refused(exc.code)
            raise
        accepted = False
        try:
            too_large = ("a status report is at most 256 KiB", "too_large")
            body = await _read_json_body(
                request, most, REPORT_DEADLINE, too_large, kind="the status report"
            )
            try:
                data = canonical.loads_strict(body, max_bytes=most)
            except ValueError as exc:
                raise Refused(400, "the status report isn't strict JSON", code="invalid") from exc
            try:
                report = statusreport.read(data, self._limits().max_tools_per_server)
            except statusreport.StatusRefused as exc:
                raise Refused(400, exc.detail, code=exc.reason) from exc
            self.keep_status(report)
            accepted = True
        except Refused as exc:
            self._status_refused(exc.code)
            raise
        finally:
            self._status_gate.end(time.monotonic(), accepted=accepted)
        log["servers"] = len(report.servers)
        if self._status_sparse("received"):
            logs.event("status_received", servers=len(report.servers), bytes=len(body))
        return JSONResponse({"v": 1}, headers={"cache-control": "no-store"})

    # --- collecting a held call's result (M8 design E.2, F.5) ---------------------------------

    async def _collect(self, request: Request, log: dict[str, Any]) -> Response:
        """``POST /_zoeymcp/gateway/v1/approvals/collect``: a held call's result, or its status,
        for the client the gateway reported and the server it was held for (E.2, F.5; T34).

        Before any body byte is read: no query (400), one ``Content-Type: application/json``
        (415) and one ``Content-Length`` (411) of at most 1 KiB (413 ``too_large``). The body is
        :func:`.internal.collect_body`'s (400 ``invalid``). The answer is always 200:

        - the result, once (``state: done``; its status, content type, the id of the request it
          answers, and its bytes in base64, as the forward's answer was kept, scrubbed: B.8),
          logged ``approval_collected``;
        - else the call's status (its state, outcome and deadline, whether it was collected
          already, why its result was lost; a withdrawal's reason);
        - else, for a ref the store doesn't hold but the start's recent endings do, from the same
          client, how it ended (``restarted``: F.5 step 4);
        - else ``state: unknown``, as for another client's ref (T34).

        With no ref, the client's own calls on the server (Q46): their statuses, never a
        result. The body's epoch is seen first (E.2's epoch rule)."""
        document = await _approvals_body(request, internal.COLLECT_MAX_BYTES, "collect", "1 KiB")
        try:
            asked = internal.collect_body(document)
        except RequestRejected as exc:
            raise Refused(400, exc.reason, code="invalid") from exc
        self._gateway_epoch(asked.epoch)
        now = _wall_ms()
        no_store = {"cache-control": "no-store"}
        if asked.ref is None:
            listed = self._results.list_for(now, asked.client, asked.server)
            calls = [self._collect_status(found) for found in listed]
            return JSONResponse({"v": 1, "calls": calls}, headers=no_store)
        ref = log["ref"] = asked.ref
        found = self._results.collect(now, ref, asked.client, asked.server)
        if isinstance(found, Collected):
            logs.event("approval_collected", ref=ref)
            status = self._results.peek(now, ref, asked.client, asked.server)
            answer: dict[str, Any] = {"ref": ref}
            if isinstance(status, Status):
                answer = self._collect_status(status)
            stored = found.result
            answer["result"] = {
                "status": stored.status,
                "content_type": stored.content_type,
                "request_id": stored.request_id,
                "body": base64.b64encode(stored.body).decode("ascii"),
            }
            return JSONResponse({"v": 1, **answer}, headers=no_store)
        if isinstance(found, Status):
            return JSONResponse({"v": 1, **self._collect_status(found)}, headers=no_store)
        ending = self._holds.ending(ref)
        if ending is not None and ending.id is None and ending.client == asked.client:
            # Rebuilt from the chain at start: whatever it held in memory is gone (F.5 step 4).
            ended = {"ref": ref, "state": ending.state, "detail": ending.detail}
            return JSONResponse({"v": 1, **ended, "restarted": True}, headers=no_store)
        return JSONResponse({"v": 1, "ref": ref, "state": "unknown"}, headers=no_store)

    def _collect_status(self, status: Status) -> dict[str, Any]:
        """A collect's answer for a record whose result it doesn't hand over: no result, no text
        (Q46). A withdrawn call names its reason, as its hold's ending recorded it."""
        ending = self._holds.ending(status.ref) if status.status == "withdrawn" else None
        return {
            "ref": status.ref,
            "tool": status.tool,
            "state": status.status,
            "outcome": status.outcome,
            "deadline": _iso_ms(status.deadline_ms),
            "collected": status.collected,
            "lost": status.lost,
            "detail": ending.detail if ending is not None else None,
        }

    # --- the gateway's epochs, endings, withdrawals and detaches (M8 design E.2) ---------------

    def _gateway_epoch(self, epoch: str) -> None:
        """E.2's epoch rule (G-15, I.3): the first request with a gateway epoch the vault hasn't
        seen makes it the current one, and withdraws (``gateway_restarted``) every relay and
        every undecided held call whose request carried a legacy ``Mcp-Session-Id``, from the
        earlier epochs: no gateway is left to forward those relays, and nobody keeps those
        sessions open. A modern held call stays, collectable through the new gateway."""
        previous = self._epochs.current
        if not self._epochs.arrive(epoch):
            return
        gone = self._holds.withdraw(self._clock(), from_earlier_epoch(epoch), "gateway_restarted")
        for hold in gone:
            self._spawn(self._ended(hold))
        if previous is not None:
            logs.event("gateway_epoch_changed", withdrawn=len(gone))

    def _endings_for(self, epoch: str, after: int) -> list[internal.Ended | internal.Relayed]:
        """The endings and relay decisions a decisions poll of ``epoch`` gets after ``after``:
        none for a gateway whose epoch isn't the current one."""
        return self._feed.since(epoch, after) if self._epochs.current == epoch else []

    def _feed_ending(self, hold: Hold, status: internal.EndedStatus, outcome: str) -> None:
        """A held call's ending, for the decisions poll of the gateway whose marker it carried
        (E.2, OPS-3): only a call that may answer pending, the one kind whose record the gateway
        keeps past its answer, so it can free its lock without the agent collecting."""
        if hold.kind != "held" or hold.epoch is None or hold.client is None:
            return
        if hold.wait != "pending":
            return
        self._feed.add(hold.epoch, hold.ref, status, outcome)
        self._wake_decisions()

    def _feed_relay(self, hold: Hold, decision: internal.RelayDecision) -> None:
        """A relay's decision, for the decisions poll of the gateway that asked it (E.2), with the
        digest of the text decided on (G-23): the gateway forwards an approved one itself."""
        if hold.kind != "relay" or hold.epoch is None:
            return
        self._feed.relay(
            hold.epoch, hold.ref, decision, hold.via or "none", _wall_ms(), hold.text_sha256
        )
        self._wake_decisions()

    def _wake_decisions(self) -> None:
        woken, self._feed_changed = self._feed_changed, asyncio.Event()
        woken.set()

    def _withdraw_one(self, hold_id: str, reason: str) -> None:
        """Withdraw hold ``hold_id`` if it is undecided, and write and tell its ending."""
        for gone in self._holds.withdraw(self._clock(), lambda h: h.id == hold_id, reason):
            self._spawn(self._ended(gone))

    async def _decisions(self, request: Request, log: dict[str, Any]) -> Response:
        """``GET /_zoeymcp/gateway/v1/approvals/decisions?epoch=<e>&after=<seq>&wait=N`` (E.2,
        X12): the endings of held calls whose marker carried the gateway's current epoch, after
        seq ``after``, as ``{"seq", "ref", "status", "outcome"}`` (never a result, which stays for
        collect), and the decisions on the relays it asked, as ``{"seq", "ref", "decision",
        "via", "decided_ms", "text_sha256"}`` (never a text), numbered together, once there are
        any, or none after N seconds (at most 25), at shutdown, or when the caller leaves; with
        the vault's own ``epoch``, one per start, so the gateway knows a restarted vault, whose
        relays are gone. The poll's epoch is seen first (the epoch rule). One poll waits at a
        time (429); a stopping vault answers a new one 503 ``stopping``, so the gateway backs
        off rather than poll again at once for as long as the vault drains."""
        try:
            epoch, after, wait = internal.decisions_query(
                parse_query(request.scope.get("query_string", b""))
            )
        except RequestRejected as exc:
            raise Refused(400, exc.reason, code="invalid") from exc
        self._gateway_epoch(epoch)
        if self._view_stopping:
            raise Refused(503, "the vault is stopping", code="stopping")
        if self._decision_waiters >= internal.DECISIONS_WAITERS:
            raise Refused(429, "a decisions poll is already waiting", retry_after=1)
        self._decision_waiters += 1
        gone = asyncio.ensure_future(_disconnected(request.receive))
        try:
            deadline = time.monotonic() + wait
            while not self._endings_for(epoch, after) and not self._view_stopping:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                woken = asyncio.ensure_future(self._feed_changed.wait())
                try:
                    await asyncio.wait(
                        (woken, gone), timeout=remaining, return_when=asyncio.FIRST_COMPLETED
                    )
                finally:
                    woken.cancel()
                if gone.done():
                    log["disconnected"] = True
                    break
        finally:
            self._decision_waiters -= 1
            # On a task that has already failed, cancel() also marks its error as retrieved.
            gone.cancel()
        found = self._endings_for(epoch, after)
        endings = [ended.wire() for ended in found if isinstance(ended, internal.Ended)]
        relays = [relayed.wire() for relayed in found if isinstance(relayed, internal.Relayed)]
        log["endings"], log["relays"] = len(endings), len(relays)
        return JSONResponse(
            {"v": 1, "epoch": self._vault_epoch, "endings": endings, "relays": relays},
            headers={"cache-control": "no-store"},
        )

    async def _withdraw(self, request: Request, log: dict[str, Any]) -> Response:
        """``POST /_zoeymcp/gateway/v1/approvals/withdraw`` (E.2, B.6; SC-1): the gateway
        abandoned an Elsewhere call (``caller_cancelled``), in any era. Read as a collect is,
        within 1 KiB (:func:`.internal.withdraw_body`). The undecided hold of that ref, for the
        client the gateway reported, is withdrawn: a blocking one's request is answered
        ``approval_withdrawn`` and a pending one's record says withdrawn; nothing is sent. An
        approved call is committed and runs on (Z9). The answer is the call's state now
        (``withdrawn``, or the state of a call it didn't withdraw, or how it ended), or
        ``unknown``, as for another client's ref (T34)."""
        document = await _approvals_body(request, internal.WITHDRAW_MAX_BYTES, "withdraw", "1 KiB")
        try:
            asked = internal.withdraw_body(document)
        except RequestRejected as exc:
            raise Refused(400, exc.reason, code="invalid") from exc
        self._gateway_epoch(asked.epoch)
        ref = log["ref"] = asked.ref
        hold, state = self._holds.by_ref(ref), "unknown"
        if hold is not None and hold.client == asked.client:
            self._withdraw_one(hold.id, asked.reason)
            current = self._holds.get(hold.id)
            state = "withdrawn" if current is None else current.state
        else:
            ending = self._holds.ending(ref)
            if ending is not None and ending.client == asked.client:
                state = ending.state
        log["held"] = state
        return JSONResponse(
            {"v": 1, "ref": ref, "state": state}, headers={"cache-control": "no-store"}
        )

    async def _detach(self, request: Request, log: dict[str, Any]) -> Response:
        """``POST /_zoeymcp/gateway/v1/approvals/detach`` (E.2, I.2; G-16, Q40): the gateway is
        stopping, and names its blocking held calls (at most 64, within 16 KiB), each by ref and
        the client it reported. An undecided one whose marker said ``wait=pending`` detaches: its
        request is answered ``approval_pending`` now, so the agent gets ``pending <ref>``, and the
        hold waits on, collectable (B.6). One that said ``wait=block`` is withdrawn
        (``gateway_stopped``). Any other call is left as it is: an approved one runs on, and its
        answer goes to its request, or to the result store if that leaves (FM-13). The answer
        names the refs it detached."""
        document = await _approvals_body(request, internal.DETACH_MAX_BYTES, "detach", "16 KiB")
        try:
            asked = internal.detach_body(document)
        except RequestRejected as exc:
            raise Refused(400, exc.reason, code="invalid") from exc
        self._gateway_epoch(asked.epoch)
        detached: list[str] = []
        for ref, client in asked.calls:
            hold = self._holds.by_ref(ref)
            if hold is None or hold.client != client or hold.kind != "held":
                continue
            if hold.state != "held" or hold.detached:
                continue
            if hold.wait != "pending":
                self._withdraw_one(hold.id, "gateway_stopped")
                continue
            self._holds.detach(self._clock(), hold.id)
            logs.event("approval_detached", ref=ref, reason="gateway_stop")
            self._wake(hold.id)
            detached.append(ref)
        log["detached"] = len(detached)
        return JSONResponse({"v": 1, "detached": detached}, headers={"cache-control": "no-store"})

    async def _ask(self, request: Request, log: dict[str, Any]) -> Response:
        """``POST /_zoeymcp/gateway/v1/approvals/ask`` (E.2, E.4; Q6 (B)): the gateway relays a
        prompt it holds itself to the operator's approvers. Read as a collect is, within 96 KiB
        (:func:`.internal.ask_body`, whose digest of the text must be the one named: 400
        ``invalid``). The body's epoch is seen first (the epoch rule), and an earlier gateway's
        is refused (409 ``view_stale``: no poll would get its decision, E.2). Then, in order: a
        stopping vault refuses (503 ``stopping``); no chain, no relay (503 ``held_ledger_down``,
        Z19); a ref is used once (409 ``held_ref_reused``, E19); the call must be one the vault's
        policy has the gateway hold, for a client it lets raise out-of-band prompts (409
        ``view_stale``: else the change would withdraw it at once, Z7); the text is checked again
        (plain, the budget) and a line imitating the relay line refused (422 ``text_refused``,
        E.5); the caps (D.3). The vault composes its relay line above the gateway's text (Z12),
        writes ``asked`` (``where: gateway``) to its chain and shows the whole on its surfaces.
        201 answers the approval's id and the digest of the text as composed, which is what a
        surface decides on; the decision comes back through the decisions poll. The vault never
        sees the call's arguments, and forwards nothing."""
        document = await _approvals_body(request, internal.ASK_MAX_BYTES, "ask", "96 KiB")
        try:
            asked = internal.ask_body(document)
        except RequestRejected as exc:
            raise Refused(400, exc.reason, code="invalid") from exc
        self._gateway_epoch(asked.epoch)
        if self._epochs.current != asked.epoch:
            # An earlier gateway's: its relays were withdrawn, and no poll would get its decision.
            raise Refused(409, "the ask is from an earlier gateway", code="view_stale")
        if self._view_stopping:
            raise Refused(503, "the vault is stopping", code="stopping")
        chain = self._chain
        if chain is None or not chain.writable():
            raise Refused(
                503, "the vault's approval chain can't be written", code="held_ledger_down"
            )
        ref = log["ref"] = asked.ref
        now, wall = self._clock(), time.time()
        self._sweep(now)
        if self._ref_used(ref):
            raise Refused(409, "the ref was used before", code="held_ref_reused")
        if not _relayable(self._policy, asked.client, asked.server, asked.tool):
            raise Refused(409, "the vault's policy doesn't relay this call", code="view_stale")
        received = approvaltext.received(asked.text)
        budget = self._budget(asked.client)
        if approvaltext.problems(received, budget=budget, renders="plain"):
            raise Refused(422, "the relayed text broke a text rule", code="text_refused")
        text = approvaltext.relayed(received)
        surfaces = _surfaces(self._policy)
        self._too_long(text, surfaces, ref, asked.server, asked.tool)
        digest = hashlib.sha256(text.value.encode("utf-8")).hexdigest()
        begun = self._holds.begin(
            now,
            HoldRequest(
                ref=ref,
                kind="relay",
                epoch=asked.epoch,
                legacy_session=False,
                route=RELAY_ROUTE + asked.server,
                server=asked.server,
                tool=asked.tool,
                client=asked.client,
                args_digest=chain.digest(None),  # the vault never sees a relay's arguments
                text=text,
                text_sha256=digest,
                surfaces=surfaces,
                wait=asked.wait,
                held_bytes=len(text.value.encode("utf-8")),
            ),
        )
        if isinstance(begun, CapRefusal):
            self._saturation(now)
            retry = begun.seconds_left or None
            raise Refused(begun.status, f"held: {begun.reason}", code=begun.code, retry_after=retry)
        hold = begun
        deadline_wall = wall + (hold.deadline - now)
        try:
            await chain.write(
                "asked",
                ref,
                critical=True,
                client=asked.client,
                server=asked.server,
                tool=asked.tool,
                where="gateway",
                era="modern",  # the ask names no era: the gateway's own chain has the call's
                args=hold.args_digest,
                pin=NO_PIN,
                text=chain.text_digest(text.value),
                chars=len(text.value),
                writes=0,
                expires=int(deadline_wall * 1000),
            )
        except ChainUnavailable as exc:
            # Nothing reached the chain or a surface; the ref stays used (E19).
            self._holds.withdraw(self._clock(), lambda h: h.id == hold.id, "ledger")
            raise Refused(
                503, "the vault's approval chain can't be written", code="held_ledger_down"
            ) from exc
        log["held"] = "relay"
        logs.event(
            "approval_relayed",
            ref=ref,
            server=asked.server,
            tool=asked.tool,
            surfaces=sorted(hold.surfaces),
            wait=hold.wait,
        )
        shown = await self._hub.show(hold) if self._holds.get(hold.id) is not None else []
        live = self._holds.get(hold.id)
        refusal = _not_shown(shown)
        if refusal is not None and live is not None and live.state == "held":
            for gone in self._holds.withdraw(self._clock(), lambda h: h.id == hold.id, "not_shown"):
                self._spawn(self._ended(gone))
            raise Refused(refusal.status, "no approver could show it", code=refusal.code)
        return JSONResponse(
            {"v": 1, "id": hold.id, "text_sha256": digest},
            status_code=201,
            headers={"cache-control": "no-store"},
        )

    def _status_refused(self, code: str | None) -> None:
        """``status_refused`` with N.3's reason, at most once a minute."""
        reason = code if code in ("too_large", "too_soon", "witness_range") else "invalid"
        if self._status_sparse("refused"):
            logs.event("status_refused", reason=reason, level="warning")

    def _status_sparse(self, kind: str) -> bool:
        """Whether a status event of ``kind`` may be logged now: at most once a minute."""
        now = time.monotonic()
        last = self._status_logged.get(kind)
        if last is not None and now - last < STATUS_LOG_EVERY:
            return False
        self._status_logged[kind] = now
        return True

    def _limits(self) -> GatewayLimits:
        gateway = self._policy.gateway
        return GatewayLimits() if gateway is None else gateway.limits

    def _reviewable(self) -> dict[str, ServerKind]:
        """The running view's servers a review job may be for: every one, remote (a bridge is
        one) or toolkit (COV-1)."""
        gateway = self._policy.gateway
        servers = {} if gateway is None else gateway.servers
        return {name: server.kind for name, server in servers.items()}

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
        return await self._queue(server, owner, fresh=fresh, work="review")

    async def queue_clear(self, server: str, owner: Owner) -> Job:
        """Queue a clear of ``server``'s drift marks for the ``owner``'s surface (M6 design
        J.4): the gateway lists the server again and clears them only if every included tool
        matches its pin. Always a new job; offered only to a poll that advertised it runs
        clears, and refused ``clear_unsupported`` while the polling gateway doesn't. Raises
        and waits as :meth:`queue_review` does."""
        return await self._queue(server, owner, fresh=True, work="clear")

    async def _queue(self, server: str, owner: Owner, *, fresh: bool, work: Work) -> Job:
        table = self._reviews
        while True:
            changed = self._reviews_changed
            try:
                queued = table.queue(
                    server, owner, self._view.digest, self._reviewable(), fresh=fresh, work=work
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
        clear = {"clear": True} if work == "clear" else {}
        logs.event(
            "review_requested", server=server, job=queued.hash8, owner=owner, reused=reused, **clear
        )
        return queued

    def held_reports(self, server: str) -> tuple[RemoteReport | ToolkitReport, ...]:
        """The reports the vault holds of ``server``'s done review jobs, newest first (M6 design
        J.4: the definition a move to allow shows)."""
        return self._reviews.reports(server)

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

    # --- the vault hold (M8 design B) ---------------------------------------------------------

    @property
    def chain(self) -> VaultLedger | None:
        """The vault's approval chain, or None: then no call is held (J.1, G-10)."""
        return self._chain

    def use_chain(self, chain: VaultLedger) -> None:
        """Hold calls on ``chain``, which the start recovered (J.1). Its recent endings go to the
        hold table, so each ref stays used (E19) and a late answer is told how it ended."""
        self._chain = chain
        self._chain_at = self._clock()
        chain.remember(self._holds, self._clock())

    def at_start(self) -> tuple[int, tuple[str, ...]]:
        """What the start's recovery closed (J.1, OPS-8), for health's two findings: how many
        waiting holds it withdrew (``approvals_withdrawn_at_start``, until the operator lists
        the approvals), and the refs of the approved calls it closed ``outcome unknown``
        (``approvals_outcome_unknown``), each for :data:`START_FINDINGS_SECONDS`."""
        chain = self._chain
        if chain is None or self._clock() - self._chain_at >= START_FINDINGS_SECONDS:
            return 0, ()
        start = chain.start
        return (0 if self._start_listed else start.withdrawn), start.outcome_unknown

    def approvals_listed(self) -> None:
        """The operator listed the approvals (the portal's Approvals page or ``zoeymcp
        approvals list``): the start's withdrawals are seen, so their finding clears (K.1)."""
        self._start_listed = True

    @property
    def hub(self) -> ApproverHub:
        """The approver surfaces holds are shown on (D.1)."""
        return self._hub

    @property
    def telegram(self) -> telegram_approver.TelegramSurface | None:
        """The Telegram surface ``approvers.telegram`` names, shown on or not (G.7)."""
        return self._telegram

    @property
    def queue(self) -> PortalQueue | None:
        """The portal's Approvals queue (H.1), shown on or not; None when this vault keeps none."""
        return self._portal_queue

    def queue_shown(self) -> bool:
        """Whether holds are shown on the portal's queue now (``approvers.portal`` is set)."""
        return self._portal_queue is not None and "portal" in self._hub.names

    def hold_now(self) -> float:
        """The hold table's clock now (the queue's plan checks a deadline on it)."""
        return self._clock()

    def hold_wall(self, at: float) -> float:
        """A time on the hold table's clock as wall-clock seconds, by one fixed offset."""
        return at + self._wall_offset

    def telegram_delivered(self, hold_id: str) -> bool:
        """Whether Telegram took hold ``hold_id``'s prompt (the queue's "not delivered to
        Telegram", G.3): never while the surface is off or its token shared."""
        surface = self._telegram
        return surface is not None and self._telegram_shown and surface.delivered(hold_id)

    def start_approvers(self) -> None:
        """Start the surfaces' own tasks, the Telegram poller and write queue (I.4): ``serve()``
        calls it once on its loop, after the first install; every later install starts, stops
        or restarts them itself."""
        self._approvers_running = True
        if self._telegram is not None and self._telegram_shown:
            self._telegram.start()

    async def stop_approvers(self) -> None:
        """The stop's last word to the surfaces (I.2): their queued edits get
        :data:`.approvers.EDIT_GRACE` in all, then the poller stops."""
        self._approvers_running = False
        if self._telegram is not None:
            await self._telegram.stop(EDIT_GRACE)

    def approver_state(self) -> TelegramState | None:
        """The Telegram approver for health (G.7), or None when the policy names none and no
        enrolment found the bot contested (G.8 step 3: ``approver_contested``). An enrolment of
        another bot than the approver's is named apart, so its token is the one revoked."""
        contested = self._enrol_contested
        surface = self._telegram
        if surface is None:
            return None if contested is None else TelegramState(secret=contested, contested=True)
        state = surface.state()
        if contested is None:
            return state
        if self._same_bot(contested, surface):
            return replace(state, contested=True)
        return replace(state, other_contested=contested)

    def _same_bot(self, secret: str, surface: telegram_approver.TelegramSurface) -> bool:
        """Whether store secret ``secret`` is the running surface's, or holds its bot."""
        if telegram_approver.secret_name(surface.settings) == secret:
            return True
        try:
            token = self._store.get_for_origin(secret, telegramwire.API).reveal()
        except SecretUnavailable:
            return False
        return telegram_approver.same_bot(token)(self._surface_token(surface))

    # --- the host's approvals and Telegram commands (M8 design K.3, G.8) ------------------------

    def closed(self) -> list[Closed]:
        """The last holds closed on any surface, newest first, without their texts (K.3)."""
        return list(self._closed)

    def withdraw_by_host(self, which: Callable[[Hold], bool]) -> list[Hold]:
        """``zoeymcp approvals withdraw`` (K.3, J15): every undecided hold ``which`` picks is
        withdrawn ``operator``, via ``host``; each ending is written, its messages edited and its
        agent told, as any withdrawal's (B.5). An approved one runs on (Z9)."""
        withdrawn = self._holds.withdraw(self._clock(), which, OPERATOR, via="host")
        for hold in withdrawn:
            self._spawn(self._ended(hold))
        return withdrawn

    async def probe_telegram(self) -> str | None:
        """``zoeymcp approver telegram test`` (G.8): None once Telegram took the probe, else
        the finding that says why not. Raises :class:`LookupError` when no Telegram approver
        runs here."""
        surface = self._telegram
        if surface is None:
            raise LookupError("no Telegram approver")
        if not self._telegram_shown or not surface.running:
            return "approver_token_shared" if surface.token_shared() else "approver_unreachable"
        return await surface.probe()

    @property
    def enrolment(self) -> telegram_approver.Enrolment | None:
        """The host's Telegram enrolment, open or the last one (G.8)."""
        return self._enrolment

    async def enrol(self, secret: str) -> tuple[telegram_approver.Enrolment, str]:
        """``zoeymcp approver telegram enrol --secret NAME`` (G.8 steps 1-2): the checks, the
        temporary egress allowance, the enrolment's own session and its one-time code. Returns
        the enrolment, polling, and its ``t.me`` link; raises
        :class:`.telegram.EnrolRefused`. One enrolment is open at a time."""
        if self._enrolment is not None and self._enrolment.open:
            raise telegram_approver.EnrolRefused("enrolment_busy")
        if self._approver_client is None:
            raise telegram_approver.EnrolRefused("enrolment_unreachable")
        try:
            token = self._store.get_for_origin(secret, telegramwire.API).reveal()
        except SecretUnavailable:
            raise telegram_approver.EnrolRefused("enrolment_secret") from None
        ref = telegram_approver.STORE_PREFIX + secret
        # A.2 row 9 against the running policy, and T-5: no credential, route or connector
        # uses the name, and no other secret holds the token or the same bot.
        used = any(found == ref for _, found, _ in secret_references(self._policy))
        settings = TelegramApprover.model_construct(bot_token=ref, user_id=1, chat_id=1)
        if used or self._token_shared(settings, token):
            raise telegram_approver.EnrolRefused("approver_token_shared")
        enrolment = telegram_approver.Enrolment(
            secret,
            store=self._store,
            client=self._approver_client,
            ended=self._enrolment_ended,
            timings=None if self._telegram_timings is False else self._telegram_timings,
            ttl=telegram_approver.ENROL_TTL,
        )
        self._enrolment, self._enrol_contested = enrolment, None
        surface = self._telegram
        try:
            same = surface is not None and telegram_approver.same_bot(token)(
                self._surface_token(surface)
            )
            await self._enrolment_allowed()
            if same and surface is not None:
                surface.pause()  # G.8 step 2: the two sessions never end each other's polls
            link = await enrolment.begin()
        except telegram_approver.EnrolRefused as refused:
            enrolment.end(refused.reason)
            raise
        except BaseException:  # the host left, or a failure: its allowance closes all the same
            enrolment.end("enrolment_unreachable")
            raise
        enrolment.start()
        logs.event("approver_enrolment_opened", bot=enrolment.username)
        return enrolment, link

    def _surface_token(self, surface: telegram_approver.TelegramSurface) -> str:
        """The running surface's token, or nothing it can match."""
        name = telegram_approver.secret_name(surface.settings)
        if name is None:
            return ""
        try:
            return self._store.get_for_origin(name, telegramwire.API).reveal()
        except SecretUnavailable:
            return ""

    async def _enrolment_allowed(self) -> None:
        """The enrolment's allowance is in the vault's list from now on (G.2): through the
        egress role, wait up to :data:`ENROL_ALLOWANCE_WAIT` for the role to fetch it, then go
        on either way (a refused tunnel is ``enrolment_unreachable``)."""
        if self._egress_proxy is not None and self._egress_proxy_kind == "role":
            await self.role_fetched(ENROL_ALLOWANCE_WAIT)
        else:
            self._wake_allowlist()

    def _enrolment_ended(self, enrolment: telegram_approver.Enrolment) -> None:
        """An enrolment ended (G.8 step 5): its allowance leaves the list, a surface it paused
        polls again, and a contested one raises ``approver_contested`` until the next."""
        self._wake_allowlist()
        if self._telegram is not None:
            self._telegram.resume()
        reason = enrolment.reason
        if reason == "enrolment_contested":
            self._enrol_contested = enrolment.secret
            logs.event("approver_contested", reason="enrolment", level="error")
        if enrolment.state == "confirmed":
            logs.event("approver_enrolled", bot=enrolment.username)
        elif reason is not None:
            logs.event("approver_enrolment_failed", reason=reason, level="warning")

    def waiting(self) -> int:
        """Holds waiting for a decision now (health: an unreachable approver is then an
        error)."""
        return sum(1 for hold in self._holds.holds() if hold.state == "held")

    @property
    def holds(self) -> HoldTable:
        return self._holds

    @property
    def results(self) -> ResultStore:
        """The results of held calls that answered pending, or whose caller left (F.2)."""
        return self._results

    @property
    def held_commits(self) -> HeldCommits:
        """The registry approved forwards run in (B.8), which the stop drains."""
        return self._commits

    def decide(
        self, id: str, decision: Literal["approve", "deny"], via: Via, text_sha256: str
    ) -> Decided | DecideRefusal:
        """A surface's decision on hold ``id`` (D.4): the first valid one wins, in one synchronous
        section with its transition (M4 build note 6c). An approved hold's forward starts once its
        ``decided accept`` is on disk (B.4); a refusal says what happened instead."""
        result = self._holds.decide(self._clock(), id, decision, via, text_sha256)
        if isinstance(result, Decided):
            hold = result.hold
            if hold.state == "approved":
                # Its forward isn't in the registry until decided accept is on disk; the stop's
                # drain waits for that too (I.2).
                wait = self._waits.get(hold.id)
                self._approving[hold.id] = 0.0 if wait is None else wait.seconds
                relay = hold.kind == "relay"
                self._spawn(self._relay_decided(hold) if relay else self._decided(hold))
            else:
                self._spawn(self._ended(hold))
            self._wake(hold.id)
        return result

    def saturated(self) -> int:
        """Holds a cap refused in the last saturation window (D.3), for health."""
        return self._holds.saturated(self._clock())

    def sweep_holds(self) -> int:
        """Expire every undecided hold past its end, and let each waiting request look at its
        hold again: the sweeper's tick (I.4). Returns how many expired."""
        expired = self._sweep(self._clock())
        for wait in self._waits.values():
            wait.changed.set()
        return expired

    def stop_holds(self) -> None:
        """The vault stops (I.2): no hold begins any more (503 ``stopping``), and every undecided
        one is withdrawn. An approved forward runs on; :meth:`drain_holds` waits for it."""
        for hold in self._holds.withdraw(self._clock(), lambda _hold: True, "shutdown"):
            self._spawn(self._ended(hold))

    async def drain_holds(self) -> None:
        """Wait for every approved forward up to its deadline (B.8), then for the endings'
        records and surface edits, at most :data:`.approvers.EDIT_GRACE` more. A forward
        approved just before the stop, whose ``decided accept`` is still being written, is
        waited for to enter the registry first (or end unsent), at most its own deadline."""
        if self._approving:
            with contextlib.suppress(TimeoutError):
                async with asyncio.timeout(max(self._approving.values())):
                    while self._approving:
                        await self._entered.wait()
        await self._commits.drain()
        if self._finishing:
            await asyncio.wait(set(self._finishing), timeout=EDIT_GRACE)

    async def settle(self) -> None:
        """Wait until every ending begun so far is written and told (tests)."""
        while self._finishing:
            await asyncio.wait(set(self._finishing))

    async def _held_route(
        self,
        request: Request,
        route: Route,
        hold: HeldRoute,
        rest: NormalizedPath,
        params: list[tuple[str, str]],
        used: tuple[str | None, str | None],
        log: dict[str, Any],
    ) -> Response:
        """B.1 step 5: a route that carries a vault-held server. Its servers' exact paths only;
        their ``GET`` and ``DELETE`` pass (F-48), and every ``POST`` is read whole by
        :func:`.envelope.admit` before anything goes upstream."""
        place = hold.paths.get(path_key(rest))
        marked = bool(request.headers.getlist(MARKER_HEADER))
        if place is None or request.method not in ("GET", "DELETE", "POST"):
            raise Refused(404, "not one of the held route's server paths", code="held_path")
        log["server"] = place.server
        if request.method != "POST":
            if marked:
                raise Refused(409, "a marked call that isn't a held call", code="view_stale")
            body = await self._read_body(request)
            return await self._forward(request, route, rest, params, used, body, "gateway", log)
        body = await self._read_held_body(request)
        headers = request.headers.items()
        session = request.headers.get("mcp-session-id")
        admitted = envelope.admit(
            body,
            headers,
            request.scope.get("query_string", b"").decode("latin-1"),
            place.tools,
            place.listed,
            hold.names,
            lambda request_id: _request_key(route.name, session, request_id) in self._requests,
            self._ref_used,
        )
        if isinstance(admitted, envelope.Refuse):
            raise Refused(
                admitted.status,
                f"the vault can't read this request unambiguously ({admitted.reason})",
                code=f"held_{admitted.reason}",
                extra={"pointer": admitted.pointer},
            )
        if isinstance(admitted, envelope.Pass):
            if admitted.marked:
                raise Refused(409, "a marked call that isn't a held call", code="view_stale")
            return await self._forward(request, route, rest, params, used, body, "gateway", log)
        if isinstance(admitted, envelope.Cancel):
            # B.1 step 5, F-54: consumed, never forwarded (the upstream never saw that id).
            found = self._requests.get(_request_key(route.name, session, admitted.request_id))
            for hold_id in sorted(found or ()):
                current = self._holds.get(hold_id)
                if current is not None and current.state == "held":
                    self._caller_left(current.id)
            log["held"] = "cancelled"
            return Response(status_code=202)
        call, marker = admitted.envelope, admitted.marker
        modern = request.headers.get(VERSION_HEADER) == envelope.MODERN_VERSION
        arguments: canonical.JSONValue = call.arguments
        ask = _Ask(
            route=route.name,
            key=(route.name, place.path),
            server=place.server,
            tool=call.name,
            client=None if marker is None else marker.client,
            ref=None if marker is None else marker.ref,
            epoch=None if marker is None else marker.epoch,
            wait="block" if marker is None else marker.wait,
            era="modern" if modern else "legacy",
            legacy_session=session is not None,
            modern=modern,
            arguments=arguments,
            pin=place.pins.get(call.name),
            writes=0,
            held_bytes=len(body),
            block_seconds=None,
            seconds=self._call_timeout(place.server) + OUTCOME_MARGIN,
            render=lambda header: approvaltext.render_call(header, arguments),
            forward=self._mcp_forward(route, call, headers, rest),
            request_key=_request_key(route.name, session, call.id),
        )
        return await self._hold(request, ask, log)

    async def _held_connector(
        self,
        request: Request,
        name: str,
        hold: HeldConnector,
        rest: NormalizedPath,
        log: dict[str, Any],
    ) -> Response:
        """B.7: a held connector holds every ``POST /send``. Its headers, query and marker are
        read as a held MCP call's are, its key names its call's ref, and the send is checked as
        today before a vault-made plan of it is held; on approval it runs exactly as today, in
        the committed registry."""
        connector = self._policy.connectors[name]
        log["connector"] = name
        marked = bool(request.headers.getlist(MARKER_HEADER))
        endpoint = (request.method, rest.segments)
        if endpoint != ("POST", ("send",)):
            if marked:
                raise Refused(409, "a marked call that isn't a held send", code="view_stale")
            return await self._connector(request, name, rest, log)
        headers = request.headers.items()
        for header, _value in headers:
            if header.lower() not in CONNECTOR_HEADERS:
                raise _unread("header_extra")
        if request.scope.get("query_string"):
            raise _unread("query")
        marker = envelope.marker(headers)
        if isinstance(marker, envelope.Refuse):
            raise _unread("marker")
        body = await self._read_held_body(request)
        key = request.headers.get("idempotency-key")
        content_type = request.headers.get("content-type")
        checked = self._connectors.check(
            name, connector, key=key, content_type=content_type, body=body
        )
        if isinstance(checked, Answer):
            return _connector_response(checked, log)
        found = _HELD_KEY.fullmatch(key or "")
        if found is None or (marker is not None and found.group(1) != marker.ref):
            raise _unread("marker")  # the key carries the call's ref, as the marker does
        ref, number = found.groups()
        if number != "1" or self._ref_used(ref):
            raise Refused(409, "one held write per call", code="held_second_write")
        if marker is not None and marker.wait != "block":
            raise _unread("marker")  # a toolkit's write blocks for as long as the tool may run
        servers = self._servers()
        writers = sorted(hold.writers, key=hold.writers.__getitem__)  # the longest timeout last
        # A send that names no toolkit tool is the connector's own, with no pin, and waits
        # approvers.block_seconds; its forward may run as long as the longest writer's.
        server, tool, block, seconds = name, "send", None, float(max(hold.writers.values()))
        pin = None
        if marker is not None and marker.tool is not None:
            writing = [w for w in writers if marker.tool in servers[w].tools.vault_approval]
            if not writing:
                raise _unread("marker")
            server, tool = writing[-1], marker.tool
            seconds = float(hold.writers[server])
            block = _toolkit_block(seconds)
            pin = servers[server].review.get(tool)
        value: dict[str, canonical.JSONValue] = canonical.loads_strict(
            body, max_bytes=len(body) + 1
        )
        plan = _mail_plan(name, value)
        ask = _Ask(
            route=hold.route,
            key=(hold.route, ()),
            server=server,
            tool=tool,
            client=None if marker is None else marker.client,
            ref=ref,
            epoch=None if marker is None else marker.epoch,
            wait="block",
            era="modern",
            legacy_session=False,
            modern=True,
            arguments=value,
            pin=pin,
            writes=1,
            held_bytes=len(body),
            block_seconds=block,
            seconds=seconds + OUTCOME_MARGIN,
            render=lambda header: approvaltext.render_plan(header, plan),
            forward=self._mail_forward(name, connector, key, content_type, body),
        )
        return await self._hold(request, ask, log)

    async def _hold(self, request: Request, ask: _Ask, log: dict[str, Any]) -> Response:
        """Hold one call (B.3-B.6): no chain, no hold; the vault's own text; the caps, and room
        for a ``wait=pending`` call's pending record (F.2); ``asked`` on disk; the surfaces
        asked; then the wait, with the caller watched. A marker's epoch is seen first (E.2's
        epoch rule)."""
        if self._view_stopping:
            raise Refused(503, "the vault is stopping", code="stopping")
        if ask.epoch is not None:
            self._gateway_epoch(ask.epoch)
        chain = self._chain
        if chain is None or not chain.writable():
            raise Refused(
                503, "the vault's approval chain can't be written", code="held_ledger_down"
            )
        now, wall = self._clock(), time.time()
        self._sweep(now)
        ref = ask.ref if ask.ref is not None else self._mint_ref()
        limits = self._holds.limits
        deadline_wall = wall + limits.timeout
        header = Header(
            ref,
            ask.client or "",
            ask.server,
            ask.tool,
            datetime.fromtimestamp(deadline_wall, UTC),
            asked_at=datetime.fromtimestamp(wall, UTC),
            rendered_by="vault",
            client_reported=ask.client is not None,
            pin=ask.pin,
            approver="out_of_band",
        )
        text = ask.render(header)
        problems = approvaltext.problems(text, budget=self._budget(ask.client), renders="plain")
        if problems:
            raise Refused(
                422,
                "the approval text broke a text rule",
                code="held_text_refused",
                extra={"pointer": problems[0].pointer},
            )
        surfaces = _surfaces(self._policy)
        self._too_long(text, surfaces, ref, ask.server, ask.tool)
        digest = hashlib.sha256(text.value.encode("utf-8")).hexdigest()
        begun = self._holds.begin(
            now,
            HoldRequest(
                ref=ref,
                kind="held",
                epoch=ask.epoch,
                legacy_session=ask.legacy_session,
                route=ask.route,
                server=ask.server,
                tool=ask.tool,
                client=ask.client,
                args_digest=chain.digest(ask.arguments),
                text=text,
                text_sha256=digest,
                surfaces=surfaces,
                wait=ask.wait,
                held_bytes=ask.held_bytes,
                block_seconds=ask.block_seconds,
            ),
        )
        if isinstance(begun, CapRefusal):
            self._saturation(now)
            retry = begun.seconds_left or None
            raise Refused(begun.status, f"held: {begun.reason}", code=begun.code, retry_after=retry)
        hold = begun
        # Its place first: an ending while asked is written (a sweep, a change) reaches it.
        wait = _Wait(
            key=ask.key,
            forward=ask.forward,
            modern=ask.modern,
            seconds=ask.seconds,
            asked_ms=int(wall * 1000),
            deadline_ms=int(deadline_wall * 1000),
            answer=asyncio.get_running_loop().create_future(),
            request_key=ask.request_key,
        )
        self._waits[hold.id] = wait
        if ask.request_key is not None:
            # Two held calls may share a place (no session, one id): a cancel names both.
            self._requests.setdefault(ask.request_key, set()).add(hold.id)
        if hold.wait == "pending" and hold.client is not None and not self._keep(hold, wait):
            # F.2: the store has no room for this client's pending record, so nobody is asked;
            # the ref stays used (E19), as when the chain refuses it below.
            self._holds.withdraw(self._clock(), lambda h: h.id == hold.id, "busy")
            busy = Refused(429, "the result store has no room for this client", code="held_busy")
            self._deliver(hold.id, busy)
            raise busy
        try:
            await chain.write(
                "asked",
                ref,
                critical=True,
                client=ask.client or UNREPORTED_CLIENT,
                server=ask.server,
                tool=ask.tool,
                where="vault",
                era=ask.era,
                args=hold.args_digest,
                pin=ask.pin or NO_PIN,
                text=chain.text_digest(text.value),
                chars=len(text.value),
                writes=ask.writes,
                expires=int(deadline_wall * 1000),
            )
        except ChainUnavailable as exc:
            # Nothing reached the chain or a surface; the ref stays used (E19).
            self._holds.withdraw(self._clock(), lambda h: h.id == hold.id, "ledger")
            self._deliver(hold.id, Refused(503, "no chain", code="held_ledger_down"))
            raise Refused(
                503, "the vault's approval chain can't be written", code="held_ledger_down"
            ) from exc
        log.update(ref=ref, held=hold.wait)
        logs.event(
            "approval_held",
            ref=ref,
            route=ask.route,
            server=ask.server,
            tool=ask.tool,
            surfaces=sorted(hold.surfaces),
            wait=hold.wait,
        )
        departure = Departure(request.receive)
        try:
            shown = await self._hub.show(hold) if self._holds.get(hold.id) is not None else []
            live = self._holds.get(hold.id)
            # Refused when every surface said it can't show it, or Telegram returned its text
            # changed (G.4); a surface that failed may still deliver it (G.3), so the hold
            # waits on, to its deadline.
            refusal = _not_shown(shown)
            if refusal is not None and live is not None and live.state == "held":
                for gone in self._holds.withdraw(
                    self._clock(), lambda h: h.id == hold.id, "not_shown"
                ):
                    self._spawn(self._ended(gone))
                raise Refused(refusal.status, "no approver could show it", code=refusal.code)
            return await self._wait_hold(hold.id, wait, departure, log)
        finally:
            departure.close()

    def _too_long(
        self, text: ApprovalText, surfaces: frozenset[str], ref: str, server: str, tool: str
    ) -> None:
        """G.4: a text Telegram can't carry, with no portal queue to take it, is refused before
        the hold begins: nobody is asked, the ref isn't used and no cap counts it."""
        if telegramwire.refused_too_long(text.value, surfaces):
            logs.event(
                "approval_refused_too_long", ref=ref, server=server, tool=tool, level="warning"
            )
            raise Refused(
                telegramwire.TooLong.status,
                "the approval text is too long for Telegram",
                code=telegramwire.TooLong.code,
            )

    async def _wait_hold(
        self, hold_id: str, wait: _Wait, departure: Departure, log: dict[str, Any]
    ) -> Response:
        """B.6: the first of a decision, the block's end, an ending, the gateway's stop detaching
        it (I.2), and the caller leaving."""
        watching = True
        while True:
            wait.changed.clear()
            hold = self._holds.get(hold_id)
            if hold is None or hold.state != "held":
                break
            if hold.detached:  # the gateway's stop detached it (approvals/detach)
                self._pending(hold, wait)
            now = self._clock()
            if now >= hold.block_until:
                self._block_over(hold, wait, now)
                continue
            changed = asyncio.ensure_future(wait.changed.wait())
            waits: set[asyncio.Future[Any]] = {changed}
            if watching:
                waits.add(departure.gone)
            try:
                await asyncio.wait(
                    waits, timeout=hold.block_until - now, return_when=asyncio.FIRST_COMPLETED
                )
            finally:
                changed.cancel()
            if watching and departure.gone.done():
                watching = False
                log["disconnected"] = True
                if wait.modern:
                    self._caller_left(hold_id)
                    raise CallerGone("headers")
                wait.left = True  # at the earlier eras a disconnect is not a cancel (B.6)
        if wait.left:
            self._caller_left(hold_id)
            raise CallerGone("relay")
        if not wait.answer.done():
            either: set[asyncio.Future[Any]] = {wait.answer, departure.gone}
            await asyncio.wait(either, return_when=asyncio.FIRST_COMPLETED)
        if not wait.answer.done():
            # Left after the approval: the forward finishes, and its answer is kept (FM-13).
            log["disconnected"] = True
            self._caller_left(hold_id)
            raise CallerGone("relay")
        answer = wait.answer.result()
        if isinstance(answer, Refused):
            raise answer
        return answer

    def _block_over(self, hold: Hold, wait: _Wait, now: float) -> None:
        """The block ended undecided (B.6): a ``wait=pending`` hold detaches and answers
        ``approval_pending`` (its pending record opened before it was asked); any other
        expires. A hold already past its deadline expires too: the clock can pass the block and
        the deadline before the sweeper's tick, and an expired hold is never detached."""
        if hold.wait != "pending" or hold.client is None or now >= hold.deadline:
            self._sweep(now)
            return
        self._holds.detach(now, hold.id)
        logs.event("approval_detached", ref=hold.ref, reason="block_over")
        self._pending(hold, wait)

    def _pending(self, hold: Hold, wait: _Wait) -> NoReturn:
        """A detached hold's request is answered ``approval_pending``, with the deadline (B.6);
        a legacy-era caller that left gets nothing."""
        if wait.left:
            raise CallerGone("headers")
        raise Refused(
            409,
            "the held call waits for its approval",
            code="approval_pending",
            extra={"ref": hold.ref, "deadline": _iso_ms(wait.deadline_ms)},
        )

    def _caller_left(self, hold_id: str) -> None:
        """The caller is gone (B.6): an undecided hold is withdrawn (``stream_lost``); an approved
        one detaches, and its answer goes to the result store."""
        hold, wait = self._holds.get(hold_id), self._waits.get(hold_id)
        if hold is None or wait is None:
            return
        gone = self._holds.caller_gone(self._clock(), hold_id)
        if gone is not None:
            self._spawn(self._ended(gone))
            return
        detached = self._holds.get(hold_id)
        if detached is not None and detached.detached:
            self._keep(detached, wait)

    def _keep(self, hold: Hold, wait: _Wait) -> bool:
        """Open the result store's record of ``hold`` (F.2), moved on to its state: a
        ``wait=pending`` hold's before it is asked (so a full store refuses it ``busy`` before
        anyone sees it), or a blocking one's whose caller left after the approval. Only a client
        the gateway reported can collect it."""
        if hold.client is None:
            return False
        if self._results.knows(hold.ref):
            return True
        call = PendingCall(
            ref=hold.ref,
            client=hold.client,
            server=hold.server,
            tool=hold.tool,
            holder="vault",
            args_digest=hold.args_digest,
            text_sha256=hold.text_sha256,
            surfaces=frozenset(hold.surfaces),
            asked_ms=wait.asked_ms,
            deadline_ms=wait.deadline_ms,
            status="pending",
        )
        opened = self._results.open(_wall_ms(), call)
        if isinstance(opened, Full):
            return False
        for evicted in opened:
            logs.event("approval_result_evicted", ref=evicted.ref, reason=evicted.reason)
        if hold.state in ("approved", "forwarding"):
            self._advance(hold.ref, "approved")
        if hold.state == "forwarding":
            self._advance(hold.ref, "forwarding")
        return True

    def _advance(
        self,
        ref: str,
        status: Literal["approved", "forwarding", "done", "denied", "expired", "withdrawn"],
        outcome: str | None = None,
        result: StoredResult | None = None,
    ) -> None:
        for evicted in self._results.advance(_wall_ms(), ref, status, outcome, result):
            logs.event("approval_result_evicted", ref=evicted.ref, reason=evicted.reason)

    async def _decided(self, hold: Hold) -> None:
        """An approved hold (B.4, B.8): ``decided accept`` fsynced first, then the forward in the
        committed registry, its outcome on the chain, and its answer to the waiting request or
        the result store. A forward whose ``decided`` can't be written is not sent (J.1)."""
        wait, chain = self._waits.get(hold.id), self._chain
        try:
            if wait is None or chain is None:  # pragma: no cover - a hold begins with both
                return
            try:
                await chain.write(
                    "decided",
                    hold.ref,
                    critical=True,
                    decision="accept",
                    waited_ms=_waited(hold),
                    via=hold.via or "none",
                )
            except ChainUnavailable:
                await self._ended(self._holds.unrecorded(self._clock(), hold.id))
                return
            logs.event(
                "approval_decided",
                ref=hold.ref,
                decision="accept",
                via=hold.via or "none",
                waited_ms=_waited(hold),
            )
            self._holds.forwarding(hold.id)
            self._advance(hold.ref, "approved")
            self._advance(hold.ref, "forwarding")
            self._spawn(self._hub.approved(hold))
        finally:
            # No await from here to the registry's entry, so the stop's drain sees it there.
            self._approving.pop(hold.id, None)
            entered, self._entered = self._entered, asyncio.Event()
            entered.set()
        forward = wait.forward
        try:
            done = await self._commits.run(hold.ref, wait.seconds, lambda: forward(hold))
        except Exception as exc:  # a forward that fails still ends its hold
            logs.event(
                "approval_forward_failed",
                ref=hold.ref,
                error_type=type(exc).__name__,
                level="error",
            )
            refused = Refused(502, "the held call's forward didn't finish")
            done = _Done(refused, "unknown", None, 0, 0, _refusal_result(refused))
        await chain.write(
            "outcome",
            hold.ref,
            critical=False,
            outcome=done.outcome,
            detail=done.detail,
            writes_sent=done.writes_sent,
            writes_unknown=done.writes_unknown,
        )
        logs.event("approval_forwarded", ref=hold.ref, outcome=done.outcome)
        if isinstance(done.response, Refused):
            # A forward that ended in the vault's own refusal was still approved (C.2): its answer
            # says so, with the approval's headers and the chain's outcome (never sent, may have
            # run, or the upstream's error), so the gateway's ledger records it as this one does.
            done.response.approved = hold.ref
            done.response.extra["outcome"] = done.outcome
        # One synchronous section: the caller is still waiting for this answer, or it left. A
        # pending record of a caller that got the answer itself keeps the outcome alone.
        current = self._holds.get(hold.id) or hold
        self._holds.done(self._clock(), hold.id, done.outcome)
        self._advance(hold.ref, "done", done.outcome, done.stored if current.detached else None)
        self._feed_ending(hold, "done", done.outcome)
        self._deliver(hold.id, done.response)
        await self._close(replace(current, state="done", detail=done.outcome), "done")

    async def _relay_decided(self, hold: Hold) -> None:
        """An approved relay (E.2, J.1): ``decided accept`` fsynced with the surface it came
        through, then the decision told to the gateway's decisions poll, which forwards the call
        itself; the vault's outcome is ``unknown``, detail ``relayed`` (the gateway's chain holds
        the real one). A relay whose ``decided`` can't be written is withdrawn, and the gateway
        told so: it is never sent."""
        chain = self._chain
        try:
            if chain is None:  # pragma: no cover - a relay begins with a chain
                return
            try:
                await chain.write(
                    "decided",
                    hold.ref,
                    critical=True,
                    decision="accept",
                    waited_ms=_waited(hold),
                    via=hold.via or "none",
                )
            except ChainUnavailable:
                await self._ended(self._holds.unrecorded(self._clock(), hold.id))
                return
            logs.event(
                "approval_decided",
                ref=hold.ref,
                decision="accept",
                via=hold.via or "none",
                waited_ms=_waited(hold),
            )
            self._holds.forwarding(hold.id)
            self._feed_relay(hold, "accept")
        finally:
            # Nothing of a relay's enters the registry: the stop's drain waits for this alone.
            self._approving.pop(hold.id, None)
            entered, self._entered = self._entered, asyncio.Event()
            entered.set()
        await chain.write(
            "outcome",
            hold.ref,
            critical=False,
            outcome="unknown",
            detail="relayed",
            writes_sent=0,
            writes_unknown=0,
        )
        current = self._holds.get(hold.id) or hold
        self._holds.done(self._clock(), hold.id, "relayed")
        await self._close(replace(current, state="done", detail="relayed"), "done")

    async def _ended(self, hold: Hold) -> None:
        """A hold that ended unforwarded (B.5, J.1): its decision and ``outcome not_sent`` on the
        chain, its pending record moved on, its surfaces closed and its request answered; a
        relay's decision told to the gateway that asked it."""
        try:
            detail = hold.detail
            if hold.state == "denied":
                decision, said = "decline", None
            elif hold.state == "expired":
                decision, said = "timeout", None
            else:
                decision, said = _ENDED_DECISIONS.get(detail or "", ("withdrawn", None))
            chain = self._chain
            if chain is not None:
                if detail != "ledger":  # else its decided accept is what couldn't be written
                    await chain.write(
                        "decided",
                        hold.ref,
                        critical=False,
                        decision=decision,
                        waited_ms=_waited(hold),
                        via=hold.via or "none",
                    )
                await chain.write(
                    "outcome",
                    hold.ref,
                    critical=False,
                    outcome="not_sent",
                    detail="ledger" if detail == "ledger" else said,
                    writes_sent=0,
                    writes_unknown=0,
                )
            if hold.state == "withdrawn":
                logs.event("approval_withdrawn", ref=hold.ref, reason=detail or "withdrawn")
            else:
                logs.event(
                    "approval_decided",
                    ref=hold.ref,
                    decision=decision,
                    via=hold.via or "none",
                    waited_ms=_waited(hold),
                )
            if hold.state in ("denied", "expired", "withdrawn"):
                self._advance(hold.ref, hold.state)
        finally:
            code = _ENDED_CODES.get(hold.state, "approval_withdrawn")
            if hold.state in ("denied", "expired", "withdrawn"):
                # Fed even when its records couldn't be written: the hold has ended all the same.
                self._feed_ending(hold, hold.state, "not_sent")
                self._feed_relay(hold, _RELAY_DECISIONS[hold.state])
            # A withdrawal names its reason when the gateway has a text of its own for it.
            named = hold.state == "withdrawn" and hold.detail in WITHDRAWN_REASONS
            extra = {"reason": hold.detail} if named else None
            ended = Refused(409, f"the held call ended {hold.state}", code=code, extra=extra)
            self._deliver(hold.id, ended)
        await self._close(hold, hold.state)

    async def _close(self, hold: Hold, outcome: str) -> None:
        """Close ``hold`` on its surfaces (G.6), kept for the host's list without its text."""
        self._closed.appendleft(closed_of(hold))
        await self._hub.close(hold, outcome)

    def _deliver(self, hold_id: str, answer: Response | Refused) -> None:
        """Hand ``answer`` to the request waiting for hold ``hold_id``, if one still is, and
        forget the hold's place."""
        wait = self._waits.pop(hold_id, None)
        if wait is None:
            return
        key = wait.request_key
        place = None if key is None else self._requests.get(key)
        if key is not None and place is not None:
            place.discard(hold_id)  # only its own: another hold may share the place
            if not place:
                del self._requests[key]
        if not wait.answer.done():
            wait.answer.set_result(answer)
        wait.changed.set()

    def _mcp_forward(
        self,
        route: Route,
        call: envelope.Envelope,
        incoming: list[tuple[str, str]],
        rest: NormalizedPath,
    ) -> Forward:
        """The forward of an approved held ``tools/call`` (B.3, B.8): ``call.canonical()``, with
        only the headers E16 admitted and the credential added now, read to its end."""

        async def forward(hold: Hold) -> _Done:
            log: dict[str, Any] = {}
            seconds = self._call_timeout(hold.server)
            try:
                authorized = await self._authorize(route, incoming, rest, [], (None, None), log)
            except Refused as unauthorized:
                return _failed(unauthorized, "not_sent")
            body = call.canonical()
            timeout = httpx.Timeout(seconds, connect=CONNECT_TIMEOUT)
            try:
                async with asyncio.timeout(seconds):
                    upstream = await self._send(
                        "POST",
                        authorized.url,
                        authorized.headers,
                        body,
                        route,
                        None,
                        timeout=timeout,
                    )
                    variants = await self._held_401(route, authorized, upstream, body, log)
                    if 300 <= upstream.status_code <= 399:
                        # Following it could take the gateway to another route (M3 design G14).
                        await upstream.aclose()
                        return _failed(Refused(502, "redirect refused"), "upstream_error")
                    answer = await read_answer(upstream, variants, call.id)
            except Refused as unsent:
                return _failed(unsent, "not_sent" if _not_sent(unsent) else "unknown")
            except (httpx.HTTPError, TimeoutError) as exc:
                failed = Refused(502, f"upstream response failed: {type(exc).__name__}")
                return _failed(failed, "unknown")
            if answer.too_large:
                stored = StoredResult(
                    answer.status, answer.content_type, lost="too_large", request_id=call.id
                )
                too_large = Refused(502, "the answer was over 4 MiB", code="held_result_too_large")
                return _Done(too_large, answer.outcome, None, 0, 0, stored)
            stored = StoredResult(
                answer.status, answer.content_type, answer.body, request_id=call.id
            )
            response = Response(answer.body, status_code=answer.status)
            response.raw_headers = [
                *_raw(list(answer.headers)),
                (b"content-length", str(len(answer.body)).encode()),
                *_approved(hold.ref),
            ]
            return _Done(response, answer.outcome, None, 0, 0, stored)

        return forward

    async def _held_401(
        self,
        route: Route,
        authorized: _Authorized,
        upstream: httpx.Response,
        body: bytes,
        log: dict[str, Any],
    ) -> list[bytes]:
        """An OAuth route's 401 or 403 to a held call, noted as today's are (D.10); a POST is
        never sent again, so only the next call gets a new token."""
        grant, cred = authorized.grant, authorized.cred
        if grant is None or route.credential is None or not isinstance(cred, OAuth2Credential):
            return authorized.variants
        if upstream.status_code in (401, 403):
            self._note_challenge(route.credential, cred, upstream)
        if upstream.status_code != 401:
            return authorized.variants
        _, variants = await self._after_401(
            upstream,
            route=route,
            credential=route.credential,
            grant=grant,
            method="POST",
            url=authorized.url,
            headers=authorized.headers,
            body=body,
            variants=authorized.variants,
            departure=None,
            log=log,
        )
        return variants

    def _mail_forward(
        self,
        name: str,
        connector: SMTPConnector,
        key: str | None,
        content_type: str | None,
        body: bytes,
    ) -> Forward:
        """The send of an approved held write (B.7): ``SmtpConnectors.send`` exactly as today
        (journal, limits, ``paused``), whose journal shares the ref through the key."""

        async def forward(hold: Hold) -> _Done:
            answer = await self._connectors.send(
                name,
                connector,
                key=key,
                content_type=content_type,
                body=body,
                proxy=self._egress_proxy,  # the startup one, as every HTTP client's (D-61)
                credentials=lambda: self._connector_credentials(connector),
            )
            outcome, detail, sent, unknown = _send_outcome(answer)
            response = _connector_response(answer, {})
            for header, value in _approved(hold.ref):
                response.headers.append(header.decode(), value.decode())
            stored = StoredResult(
                answer.status, "application/json", json.dumps(answer.body).encode()
            )
            return _Done(response, outcome, detail, sent, unknown, stored)

        return forward

    async def _read_held_body(self, request: Request) -> bytes:
        """A held call's body, within :data:`.envelope.MAX_HELD_BODY` (B.1 step 5: 413
        ``held_too_large``)."""
        most = envelope.MAX_HELD_BODY
        declared = request.headers.get("content-length")
        if declared is not None and declared.isdigit() and int(declared) > most:
            raise _unread("too_large")
        chunks: list[bytes] = []
        size = 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > most:
                raise _unread("too_large")
            chunks.append(chunk)
        return b"".join(chunks)

    def _spawn(self, work: Coroutine[Any, Any, None]) -> None:
        """Run ``work`` (a hold's decision or ending) in a task of its own, kept until it ends."""
        task = asyncio.ensure_future(work)
        self._finishing.add(task)
        task.add_done_callback(self._finished)

    def _finished(self, task: asyncio.Task[None]) -> None:
        self._finishing.discard(task)
        if not task.cancelled() and (error := task.exception()) is not None:
            logs.event("approval_hold_failed", error_type=type(error).__name__, level="error")

    def _wake(self, hold_id: str) -> None:
        wait = self._waits.get(hold_id)
        if wait is not None:
            wait.changed.set()

    def _sweep(self, now: float) -> int:
        expired = self._holds.sweep(now)
        for hold in expired:
            self._spawn(self._ended(hold))
        self._results.sweep(_wall_ms())
        return len(expired)

    def _saturation(self, now: float) -> None:
        """A cap refused a hold: at most once per window, the surfaces are told (D.3)."""
        count = self._holds.notice(now)
        if count is not None:
            logs.event("approvals_saturated", refused=count, level="error")
            self._spawn(self._hub.notice(count))

    def _ref_used(self, ref: str) -> bool:
        """E19: ``ref`` is in the hold table (live or a recent ending), the result store, or the
        chain's open refs (T-10)."""
        chain = self._chain
        return (
            self._holds.knows(ref)
            or self._results.knows(ref)
            or (chain is not None and ref in chain.open)
        )

    def _mint_ref(self) -> str:
        """A ref for a call with no marker (B.3): 8 random bytes, hex, never one in use."""
        while True:
            ref = secrets.token_hex(8)
            if not self._ref_used(ref):
                return ref

    def _servers(self) -> Mapping[str, Any]:
        gateway = self._policy.gateway
        return {} if gateway is None else gateway.servers

    def _call_timeout(self, server: str) -> float:
        """A held server's (or writer's) effective call_timeout, from the vault's policy (I.1)."""
        found = self._servers().get(server)
        own = None if found is None else found.call_timeout
        return float(own or self._limits().call_timeout)

    def _budget(self, client: str | None) -> int:
        """B.3: the gateway-wide ``budget_chars``, lowered by the reported client's own."""
        gateway = self._policy.gateway
        approvals = Approvals() if gateway is None else gateway.approvals
        known = None if gateway is None or client is None else gateway.clients.get(client)
        own = None if known is None or known.approvals is None else known.approvals.budget_chars
        return min(approvals.budget_chars, own or approvals.budget_chars)

    def _still_held(self, hold: Hold, old: HeldMap, new: HeldMap, policy: Policy) -> bool:
        """Z7: the same server on the same path still holds the tool at the same pin (a connector:
        the same writers), an enabled surface still shows it, and a reported client the policy has
        is still ``attended`` or ``out_of_band``. A relay: an enabled surface still shows it, and
        the policy still has the gateway hold its tool for its client, ``out_of_band``."""
        if hold.kind == "relay":
            # The surface rule, then the call's own: a relay is withdrawn when its client loses
            # out_of_band, or its tool leaves approve or goes to vault_approval (B.5, Z7).
            return bool(hold.surfaces & _surfaces(policy)) and _relayable(
                policy, hold.client, hold.server, hold.tool
            )
        wait = self._waits.get(hold.id)
        if wait is None:
            return False
        before, after = old.get(wait.key[0]), new.get(wait.key[0])
        if isinstance(before, HeldConnector) and hold.tool not in before.names:
            # A send with no toolkit tool named: held while the connector's writers are.
            if not isinstance(after, HeldConnector) or before.writers != after.writers:
                return False
        elif not same_hold(old, new, wait.key, hold.tool):
            return False
        if not hold.surfaces & _surfaces(policy):
            return False
        gateway = policy.gateway
        client = (
            None if gateway is None or hold.client is None else gateway.clients.get(hold.client)
        )
        if client is not None:
            own = client.approvals
            return own is not None and (own.attended or own.out_of_band)
        return True

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
        departure: Departure | None,
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
        departure: Departure | None,
        *,
        timeout: httpx.Timeout | None = None,
    ) -> httpx.Response:
        """Send the request upstream. Returns once the status line and headers arrived, or
        raises :class:`CallerGone` (and closes the request) if the caller leaves first. With no
        ``departure`` (a held call's committed forward, M8 design B.8) nobody is watched.

        A local MCP route of the running policy goes on the local client, a ``unix:`` one on its
        bridge's socket client, chosen by the bridge's name, and every other route on the
        ordinary client (M7 design B.2)."""
        if timeout is None:
            timeout = httpx.Timeout(None if route.stream else READ_TIMEOUT, connect=CONNECT_TIMEOUT)
        local = route.name in self._local_routes
        client = self._local_client if local else self._client
        if route.upstream is not None and route.upstream.startswith(fields.UNIX_PREFIX):
            # A bridge's socket goes on its socket client only, never on a networked one.
            bridge = fields.bridge_name(route.upstream)
            found = self._socket_clients(bridge)
            if found is None:
                # No bridge of that name was started (or none at all: the hardened tier).
                verdict = "unknown_socket"
                logs.event("address_refused", purpose="route", bridge=bridge, verdict=verdict)
                raise Refused(
                    502,
                    f"address refused ({verdict}): no bridge {bridge} was started",
                    code=netclient.ADDRESS_REFUSED,
                )
            client = without_cookies(found)
        outgoing = client.build_request(method, url, headers=headers, content=body, timeout=timeout)
        try:
            if departure is None:
                return await client.send(outgoing, stream=True)
            return await departure.race(client.send(outgoing, stream=True), phase="headers")
        except netclient.SocketRefused as exc:
            # Nothing was written: the socket's listener isn't the uid the launcher gave it.
            reason = exc.verdict.reason
            logs.event(
                "address_refused", purpose="route", bridge=exc.bridge, verdict=reason, uid=exc.uid
            )
            raise Refused(
                502,
                f"address refused ({reason}): bridge {exc.bridge}'s socket isn't its own",
                code=netclient.ADDRESS_REFUSED,
            ) from exc
        except netclient.AddressRefused as exc:
            # Nothing was sent: the upstream's name resolves where the policy doesn't allow.
            reason = exc.verdict.reason
            logs.event(
                "address_refused", purpose="route", host=exc.host, port=exc.port, verdict=reason
            )
            if local:
                # egress_private can't help a local route: its client takes loopback and
                # private addresses only, whatever the policy lists.
                raise Refused(
                    502,
                    f"address refused ({reason}): a local MCP route reaches only loopback or "
                    "private addresses",
                    code=netclient.ADDRESS_REFUSED,
                ) from exc
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


async def _approvals_body(request: Request, most: int, noun: str, size: str) -> object:
    """An approvals path's strict-JSON body (M8 design E.2), checked before any byte is read: no
    query (400), one ``Content-Type: application/json`` (415) and one ``Content-Length`` (411) of
    at most ``most`` bytes, ``size`` in words (413 ``too_large``); then read within
    :data:`REPORT_DEADLINE`, and parsed (400 ``invalid``)."""
    if request.scope.get("query_string"):
        raise Refused(400, f"the {noun} path takes no query")
    too_large = (f"a {noun} is at most {size}", "too_large")
    if _json_length(request, kind=f"a {noun}") > most:
        raise Refused(413, too_large[0], code=too_large[1])
    body = await _read_json_body(request, most, REPORT_DEADLINE, too_large, kind=f"the {noun}")
    try:
        return canonical.loads_strict(body, max_bytes=most)
    except ValueError as exc:
        raise Refused(400, f"the {noun} isn't strict JSON", code="invalid") from exc


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


def _job_wire(job: Job) -> dict[str, str]:
    """A claimed job as a poll's answer lists it: a review's ``{"id", "server"}`` exactly, the
    only shape an older gateway reads, and a clear's with ``"kind": "clear"`` (M6 design J.4)."""
    wire = {"id": job.id, "server": job.server}
    if job.work == "clear":
        wire["kind"] = "clear"
    return wire


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
