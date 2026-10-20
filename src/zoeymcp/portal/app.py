"""The portal's ASGI app: the shell that applies admission (M5 design B.3, C.2, C.3, M.1, M.4).

``portal/admission.py`` decides; this gathers each request's facts, asks in C.2's order, and
applies the answer:

- **Row 0**, the in-flight gate (:class:`~.limits.InFlight`): 503 ``busy`` with every header
  below, since uvicorn's own ``limit_concurrency`` answers without them.
- **Rows 1 to 7** (:func:`~.admission.admit`): a refusal, the 308 from a loopback literal, a
  static file, or an API request admitted so far.
- **Row 8 or rows 9 and 10**: an unauthenticated route takes one of the unauthenticated slots,
  then a token from the global bucket; any other route needs its session's two halves. **No body
  byte is read before**, so a slow body without a session holds an unauthenticated slot at most.
- **Rows 11 and 12**: the body, read up to the route's cap and one byte more within
  :data:`BODY_DEADLINE`, then parsed strictly. Then the handler.

Every answer carries C.3's headers (:data:`HEADERS`), and none carries an ``Access-Control-*``
header, an ``ETag`` or a 304. A body is read only when the route's checks have passed; one
refused unread is dropped by h11 as it arrives, within the head deadline, or, if larger than
any route takes, closes the connection.

The static files are loaded once, at start, into a fixed map (:func:`load_static`); a missing
one stops the start. The API's routes are ``routes.ROUTES``, each answered by a handler here
(M.1): logging in with a passkey, redeeming a setup code and enrolling with it (E, F.2), the
session and the session list, logout and ending the other sessions, the passkey list, and the
step-up path (F.4). Before any session lookup the expired sessions are ended and logged; a
login or a redeemed code ends the sessions whose cookie it replaces in that browser (one
signed-in tab per browser); and however a session ends, its ceremony and action are dropped and
its OAuth flows cancelled (H.2).

**Every change a full session makes is an action** (P6): ``POST /api/actions`` checks the body
against the registry (``actions.KINDS``) and runs the kind's plan (:meth:`PortalApp._kinds`),
which checks everything the change will check and changes nothing, so a mistake shows before the
passkey prompt; the vault holds the action with its plan and answers the summary and the step-up
options. ``POST /api/actions/{action}/confirm`` takes the action out of the table, verifies the
assertion against the action's challenge, plans again and answers ``409 changed`` with both
summaries if the plan moved; otherwise it applies the counter, runs what was held and answers
its result. The kinds built so far are the passkeys': ``passkey.enrol`` (its run begins an
enrolment ceremony for this session, finished at ``/api/passkeys/enrol/finish``),
``passkey.rename`` and ``passkey.remove`` (never the last passkey: host access is the recovery
path, Q26); and the secrets': ``secret.put`` and ``secret.delete``, which decide with
``vault/secretplan.py`` and write with ``vault/secretops.py``, as the admin socket's
``PUT/DELETE /secrets/{name}`` do (G, P10). The Secrets area is write-only: ``GET /api/secrets``
lists names and metadata, and no answer, summary or log line carries a value (P1, R61). A value
waits for its confirm in the action's held data, which hides it from ``repr`` and refuses to be
logged.

Health and OAuth connect (I, H): ``GET /api/health`` is the socket's ``GET /health`` report, fit
to show, with one checklist of every finding; ``GET /api/session`` carries its counts. ``GET
/api/oauth`` lists the oauth2 credentials. Connect is paste first (H.1): ``POST
/api/oauth/{credential}/start`` starts a login this session owns (a client_credentials start is
the test fetch), the operator approves in a new tab and pastes the address it lands on, and the
``oauth.complete`` action's plan checks the paste with ``LoginService.check_paste`` before any
passkey prompt; its confirm exchanges the code once and stores the grant. ``DELETE
/api/oauth/flows/{flow}`` cancels the session's own login, and ``oauth.reset`` clears a
credential's failure state. Flows are owned (H.2): another owner's flow answers as an unknown
one.

Logs (M.4): ``portal_request`` for each answer a handler gives; ``portal_refused`` for a refusal
before one, at most once per 10 s per reason with a count, never the refused ``Host`` or
``Origin``; a static file or the 308 as ``portal_request``, at most once per 10 s per path. The
handlers log ``portal_login``, ``portal_login_failed``, ``setup_code_redeemed``,
``setup_code_refused`` (at most once a minute, with a count), ``passkey_enrolled`` (a warning when
a setup code enrolled it, E.4), ``passkeys_reset``, ``portal_logout``, ``portal_session_ended``,
``step_up_confirmed``, ``step_up_refused``, ``action_changed``, ``passkey_renamed`` and
``passkey_removed``; ``secretops`` logs ``secret_set`` and ``secret_deleted`` with
``via: "portal"``; the logins log ``oauth_login_started``, ``oauth_login_completed``,
``oauth_login_failed`` and ``oauth_flow_replaced``, and a reset ``oauth_cache_reset``.
"""

from __future__ import annotations

import asyncio
import importlib.resources
import json
import time
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from importlib.resources.abc import Traversable
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Final, Literal, TypeGuard

from starlette.types import Receive, Scope, Send

from ..common.policy.schema import OAuth2Credential, split_scope
from ..vault import logs, secretops, secretplan
from ..vault.bindings import VAULT_PREFIX
from ..vault.oauth.login import LoginError
from ..vault.secretplan import PutPlan, SecretRefusal
from . import passkeys as passkey_file
from . import routes as api
from .actions import Action, ActionRefusal, Actions, changed, parse_request
from .admission import (
    Admitted,
    Origin,
    Redirect,
    Request,
    Static,
    admit,
    admit_session,
    admit_unauthenticated,
    origin_entries,
    parse_body,
    values,
)
from .display import NAME_LIMIT, SUMMARY_LIMIT, shown
from .limits import Bucket, InFlight, Sparse, Ticket
from .passkeys import ALGORITHM_NAMES, Passkey, PasskeyError
from .refusals import Refusal, enrolment, refusal, secret
from .refusals import login as login_refusal
from .routes import ROUTES, STATIC, Route
from .sessions import (
    SESSION_IDLE,
    Ceremonies,
    Ceremony,
    CeremonyKind,
    Ended,
    Full,
    Minted,
    Session,
    Sessions,
    SessionToken,
)
from .setupcode import Redeemed
from .webauthn import (
    MAX_PASSKEYS,
    WebAuthnError,
    creation_options,
    request_options,
    verify_assertion,
    verify_registration,
)

if TYPE_CHECKING:
    from ..common.policy.schema import Policy
    from ..vault.admin import SetupCodes
    from ..vault.oauth.login import LoginService
    from ..vault.oauth.tokens import TokenManager
    from ..vault.store import EntryMeta, SecretStore
    from .passkeys import Passkeys

BODY_DEADLINE: Final = 10.0  # seconds to receive a body, once the app starts reading it
# The largest body left unread on a kept connection (the largest route cap, M.1's 128 KiB).
DRAIN_LIMIT: Final = 128 * 1024
REFUSED_LOG_EVERY: Final = 10.0
SERVED_LOG_EVERY: Final = 10.0
# 503 busy and 429 rate_limited: when to try again. The bucket refills a token every 2 s.
RETRY_AFTER: Final[Mapping[str, bytes]] = MappingProxyType({"busy": b"1", "rate_limited": b"2"})
SETUP_HINT: Final = "run zoeymcp setup-code in the vault's container"
RESET_HINT: Final = "run zoeymcp setup-code --reset in the vault's container"
# setup_code_refused is logged at most once a minute, with a count (M.4).
SETUP_REFUSED_LOG_EVERY: Final = 60.0
# M5 refuses a managed policy at start (P9), so every portal is declarative for now.
MODE: Final = "declarative"
# A counter that went back shows as a banner for this long (I.1's passkey_counter).
REGRESSED_FOR: Final = 30 * 86_400
COUNTER_BANNER: Final = (
    "A passkey's signature counter went back in the last 30 days: the authenticator may have "
    "been copied. Check the passkeys with zoeymcp passkeys."
)
HEALTH_BANNER: Final = "{count} problem(s) need you: see the checklist on Home."
# How a credential gets a grant in the portal (H.1): a sign-in in the browser completed by
# paste, or for client_credentials a test fetch; neither for a refresh token set by other means.
CONNECT_BROWSER: Final = "browser"
CONNECT_TEST: Final = "test"
# What a health finding's action asks of the operator when the page has no button for it (I.1;
# the page's buttons: connect, reset, set_secret, delete_secret, add_passkey, review_passkeys).
ACTION_WORDS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "restart": "Set the environment variable, then restart the vault.",
        "fix_policy": "Fix the policy.",
        "wait": "Wait: the vault tries again after the backoff.",
        "check_volume": "Check the state volume: the vault can't write its files.",
        "check_mailbox": "Check the mailbox before sending again.",
        "reset_passkeys": "Run zoeymcp setup-code --reset with host access.",
        "check_gateway": "Check that the gateway is running and reporting.",
        "read_ledger": "Read it with zoeymcp ledger --vault.",
    }
)

CSP: Final = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
    "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; "
    "frame-ancestors 'none'; require-trusted-types-for 'script'; trusted-types 'none'"
)
# C.3: on every answer the portal makes. The CSP is a header, never a <meta>, since
# frame-ancestors is ignored there.
HEADERS: Final[tuple[tuple[bytes, bytes], ...]] = (
    (b"content-security-policy", CSP.encode()),
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),
    (b"cache-control", b"no-store"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"cross-origin-resource-policy", b"same-origin"),
    (b"x-frame-options", b"DENY"),
    (b"x-zoeymcp-vault", b"portal"),
)
JSON_TYPE: Final = b"application/json"
ALLOW: Final = b"GET, POST, DELETE"  # routes.METHODS, for the 405

Header = tuple[bytes, bytes]


class StaticMissing(Exception):
    """A static file the map names isn't in the package; the message names it."""


def load_static(root: Traversable | None = None) -> dict[str, bytes]:
    """Every file of the static map (M.1), read once from the package's ``static`` directory.
    Raises :class:`StaticMissing` naming the first one that can't be read."""
    folder = root if root is not None else importlib.resources.files("zoeymcp.portal") / "static"
    loaded = {}
    for path, file in STATIC.items():
        try:
            loaded[path] = folder.joinpath(file.name).read_bytes()
        except OSError as exc:
            raise StaticMissing(f"the portal's static file {file.name} can't be read") from exc
    return loaded


@dataclass(frozen=True)
class Call:
    """An admitted API request, as a handler sees it: its origin entry, route and path
    parameters, its raw query, the parsed body (None for a route without one), the session both
    halves found (None on an unauthenticated route), the connecting address, and every value of
    the session cookie the request carries (for :meth:`PortalApp._replace`)."""

    entry: Origin
    route: Route
    params: Mapping[str, str]
    query: bytes
    body: Mapping[str, Any] | None
    session: Session | None
    peer: str = ""  # for the login ceremonies' quota per peer (F.1)
    size: int = 0  # the body's length in bytes: an action's cap depends on its kind (M.1)
    cookies: tuple[str, ...] = field(default=(), repr=False)


@dataclass(frozen=True)
class Reply:
    """A handler's answer: a JSON object, its status, and any extra headers (``Set-Cookie``).
    ``reason`` is for the log, when the answer is a refusal with more than a refusal's fields
    (``409 changed`` shows both plans)."""

    body: Mapping[str, Any]
    status: int = 200
    headers: tuple[Header, ...] = field(default=(), repr=False)
    reason: str | None = None


Handler = Callable[[Call], Awaitable[Reply | Refusal]]


@dataclass(frozen=True)
class Plan:
    """What a kind's plan found (F.4): the summary the operator confirms, as label and value
    pairs (each value the vault's own text, or passed through :func:`~.display.shown`), and the
    facts it was made from. A confirm plans again and compares the two (``actions.changed``): a
    different summary or different facts is ``409 changed``. The facts leave out what moves
    without mattering to the change, such as a passkey's last-used day."""

    summary: tuple[tuple[str, str], ...]
    facts: tuple[Any, ...] = ()


@dataclass(frozen=True)
class Step:
    """Where an action is planned and run: the origin entry, the session and the passkey file."""

    entry: Origin
    session: Session
    holder: Passkeys


@dataclass(frozen=True)
class Secrets:
    """What the Secrets area works on (G), the same three the admin socket's ``/secrets`` does:
    the vault's store; its token manager, which writes and deletes a name an oauth2 credential
    uses once any refresh of it is done (None writes the store directly, as the socket without
    one); and the running policy, read at every plan, so a reload between prepare and confirm
    that moves a binding is ``409 changed``."""

    store: SecretStore
    tokens: TokenManager | None
    policy: Callable[[], Policy]


@dataclass(frozen=True)
class ActionKind:
    """One kind of action as the portal runs it: its plan, which changes nothing, and its run,
    given the data the vault held. The registry's shape checks (``actions.KINDS``) come first."""

    plan: Callable[[Mapping[str, Any], Step], Plan | Refusal]
    run: Callable[[Mapping[str, Any], Step], Awaitable[Reply | Refusal]]


class _Gone(Exception):
    """The caller went away while its body was being read."""


@dataclass
class _Exchange:
    """One request's state: how much of its body was read, so an answer knows to close."""

    scope: Scope
    receive: Receive
    send: Send
    route: str | None = None  # the template, for the log
    body_started: bool = False
    body_complete: bool = False
    answered: bool = False

    @property
    def must_close(self) -> bool:
        """The answer closes the connection: the app stopped reading a body part way (too slow,
        too large), or refused one it never read that is chunked or over :data:`DRAIN_LIMIT`.
        A smaller unread body is left for h11 to read and drop, within the head deadline, so
        the caller sees the answer: closing on unread bytes resets the connection, and the
        reset can overtake the answer."""
        if self.body_complete:
            return False
        if self.body_started:
            return True
        headers = self.scope["headers"]
        if values(headers, b"transfer-encoding"):
            return True
        lengths = values(headers, b"content-length")
        return any(not n.isdigit() or int(n) > DRAIN_LIMIT for n in lengths)


class PortalApp:
    """The portal on its listener. ``origins`` is ``admin.origins``; :meth:`reload` swaps them.

    ``setup``, ``passkeys``, ``login`` and ``secrets`` are the ones the vault shares with the
    admin socket; a secret route or action of a portal without ``secrets`` is a 500, and so is
    an OAuth route or action without ``login`` or ``secrets`` (whose policy and token manager it
    reads). ``health`` gives the report the socket's ``GET /health`` answers (I.1); without it,
    ``GET /api/health`` is a 500 and the session answer has no counts.
    ``routes`` and ``handlers`` are the API (M.1): by default :data:`~.routes.ROUTES` and this
    class's own handlers; a route without a handler answers 404. ``clock`` is monotonic (the
    limits); ``wall`` is the sessions' clock. ``body_deadline`` is :data:`BODY_DEADLINE` but for
    tests.

    The admin socket lists and ends the sessions through :meth:`session_list`, :meth:`end_all`
    and :meth:`end_credential`, on the same event loop.
    """

    def __init__(
        self,
        origins: Iterable[str],
        *,
        static: Mapping[str, bytes],
        setup: SetupCodes | None = None,
        passkeys: Passkeys | None = None,
        login: LoginService | None = None,
        secrets: Secrets | None = None,
        health: Callable[[], dict[str, Any]] | None = None,
        routes: Sequence[Route] = ROUTES,
        handlers: Mapping[Route, Handler] | None = None,
        clock: Callable[[], float] = time.monotonic,
        wall: Callable[[], float] = time.time,
        body_deadline: float = BODY_DEADLINE,
    ) -> None:
        self._entries = origin_entries(origins)
        self._static = dict(static)
        self.setup = setup
        self.passkeys = passkeys
        self.login = login
        self.secrets = secrets
        self.health = health
        self._routes = tuple(routes)
        self._handlers = dict(self._own_handlers() if handlers is None else handlers)
        self._clock = clock
        self._wall = wall
        self.body_deadline = body_deadline
        self.sessions = Sessions()
        self.ceremonies = Ceremonies()
        self.actions = Actions()
        self._kinds = self._own_kinds()
        self._gate = InFlight()
        self._bucket = Bucket()
        self._refused: Sparse[str] = Sparse(REFUSED_LOG_EVERY)
        self._served: Sparse[str] = Sparse(SERVED_LOG_EVERY)
        self._codes_refused: Sparse[str] = Sparse(SETUP_REFUSED_LOG_EVERY)

    @property
    def origins(self) -> tuple[str, ...]:
        return tuple(entry.origin for entry in self._entries)

    @property
    def action_kinds(self) -> frozenset[str]:
        """The kinds of action this portal plans and runs, each one in ``actions.KINDS``."""
        return frozenset(self._kinds)

    @property
    def in_flight(self) -> tuple[int, int]:
        """Requests in flight now: in all, and on the unauthenticated routes."""
        return self._gate.total, self._gate.unauthenticated

    def reload(self, origins: Iterable[str]) -> None:
        """``SIGHUP`` with ``admin.origins`` changed: the new list takes effect at once, and the
        sessions of an origin no longer listed end (B.3)."""
        self._entries = origin_entries(origins)
        self._finish(self.sessions.end_origins(self.origins))

    def setup_hint(self) -> str | None:
        """What ``setup_pending`` says at start when no passkey can sign in (E.1), or None."""
        if self.passkeys is None:
            return None
        if self.passkeys.unavailable:
            return RESET_HINT
        if not self.passkeys.document.credentials:
            return SETUP_HINT
        return None

    # --- ASGI ------------------------------------------------------------------------------------

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            return
        if scope["type"] != "http":
            raise RuntimeError(f"unsupported scope {scope['type']}")
        exchange = _Exchange(scope, receive, send)
        started = self._clock()
        ticket = self._gate.enter()
        if ticket is None:
            await self._refuse(exchange, refusal("busy"))
            return
        try:
            await self._handle(exchange, ticket, started)
        except _Gone:
            pass  # nobody to answer
        except Exception as exc:
            if exchange.answered:
                raise  # uvicorn closes the connection
            await self._fail(exchange, started, exc)
        finally:
            self._gate.leave(ticket)

    async def _handle(self, exchange: _Exchange, ticket: Ticket, started: float) -> None:
        scope = exchange.scope
        # The raw path, so a percent-encoded name never reaches a route or the static map.
        path = (scope.get("raw_path") or scope["path"].encode()).decode("latin-1")
        decision = admit(
            Request(scope["method"], path, scope["headers"]), self._entries, self._routes
        )
        if isinstance(decision, Refusal):
            await self._refuse(exchange, decision)
        elif isinstance(decision, Redirect):
            await self._send(exchange, 308, b"", None, ((b"location", decision.location.encode()),))
            self._served_line(scope["method"], "/", 308, started)
        elif isinstance(decision, Static):
            file = decision.file
            await self._send(exchange, 200, self._static[path], file.content_type.encode())
            self._served_line(scope["method"], path, 200, started)
        else:
            await self._api(exchange, ticket, decision, started)

    async def _api(
        self, exchange: _Exchange, ticket: Ticket, admitted: Admitted, started: float
    ) -> None:
        route = admitted.route
        exchange.route = route.path
        handler = self._handlers.get(route)
        if handler is None:
            # A route in the table but not built: as if it weren't there, before anything else.
            await self._refuse(exchange, refusal("not_found"))
            return
        session = None
        # Expired sessions end here, logged, before any lookup could find one (6b's sweep), and
        # expired actions drop the data they hold.
        self._finish(self.sessions.sweep(self._wall()))
        self.actions.sweep(self._wall())
        if route.unauthenticated:
            slot = self._gate.enter_unauthenticated(ticket)
            refused = admit_unauthenticated(slot=slot, token=slot and self._bucket.take(started))
        else:
            session = self._session(admitted)
            refused = admit_session(route, None if session is None else session.scope)
        if refused is not None:
            await self._refuse(exchange, refused)
            return
        body = None
        size = 0
        if route.cap:
            raw = await self._read_body(exchange, route.cap)
            parsed = raw if isinstance(raw, Refusal) else parse_body(route, raw)
            if isinstance(parsed, Refusal):
                await self._refuse(exchange, parsed)
                return
            body = parsed
            size = len(raw) if isinstance(raw, bytes) else 0  # always bytes here
        if session is not None:
            # The session may have ended while its body arrived (a second logout, end-others
            # from another tab): then this request is as one that came after, 401.
            session = self.sessions.touch(session.id, self._wall())
            if session is None:
                await self._refuse(exchange, refusal("no_session"))
                return
        query = exchange.scope.get("query_string", b"")
        client = exchange.scope.get("client")
        peer = str(client[0]) if client else ""
        call = Call(
            admitted.entry,
            route,
            admitted.params,
            query,
            body,
            session,
            peer,
            size,
            admitted.cookies,
        )
        answer = await handler(call)
        reason: str | None
        if isinstance(answer, Refusal):
            status, reason = answer.status, answer.reason
            await self._send_json(exchange, status, answer.body(), _refusal_headers(answer))
        else:
            status, reason = answer.status, answer.reason
            await self._send_json(exchange, status, answer.body, answer.headers)
        logs.event(
            "portal_request",
            method=exchange.scope["method"],
            route=route.path,
            status=status,
            reason=reason,
            session=None if session is None else session.fingerprint,
            ms=self._ms(started),
        )

    def _session(self, admitted: Admitted) -> Session | None:
        """Row 9's lookup: the live session of this origin both halves name, or None."""
        if admitted.token is None:
            return None
        return self.sessions.lookup(
            [SessionToken(cookie) for cookie in admitted.cookies],
            SessionToken(admitted.token),
            origin=admitted.entry.origin,
            now=self._wall(),
        )

    async def _read_body(self, exchange: _Exchange, cap: int) -> bytes | Refusal:
        """Row 11: the body, up to ``cap`` and one byte more, within the deadline."""
        body = bytearray()
        exchange.body_started = True
        try:
            async with asyncio.timeout(self.body_deadline):
                while True:
                    message = await exchange.receive()
                    if message["type"] == "http.disconnect":
                        raise _Gone
                    body += message.get("body", b"")
                    if len(body) > cap:
                        return bytes(body)
                    if not message.get("more_body", False):
                        exchange.body_complete = True
                        return bytes(body)
        except TimeoutError:
            return refusal("too_slow")

    # --- the admin socket's view of the sessions (M.3) -------------------------------------------

    def session_list(self) -> list[dict[str, Any]]:
        """Every live session, as ``zoeymcp sessions`` lists them."""
        return [_listed(session) for session in self.sessions.live(self._wall())]

    def end_all(self) -> int:
        """End every session (``zoeymcp sessions --end-all``). How many were live."""
        self._finish(self.sessions.sweep(self._wall()))
        ended = self.sessions.end_where(lambda session: True, "end_all")
        self._finish(ended)
        return len(ended)

    def end_credential(self, fingerprint: str) -> int:
        """End the sessions the removed passkey's logins made. How many."""
        ended = self.sessions.end_credential(fingerprint)
        self._finish(ended)
        return len(ended)

    def _finish(self, ended: Iterable[Ended]) -> None:
        """What every ending of a session needs: its enrolment ceremony and pending action go,
        its OAuth flows are cancelled (H.2), and the end is logged (M.4). ``ended`` is only what
        the table removed (``Sessions.end`` answers None for a session already gone), so each
        session's end is finished and logged once, by the request that ended it."""
        for item in ended:
            session = item.session
            self.ceremonies.drop_session(session.id)
            self.actions.drop_session(session.id)
            if self.login is not None:
                self.login.cancel_owner(session.owner)
            kind = "portal_logout" if item.why == "logout" else "portal_session_ended"
            logs.event(kind, session=session.fingerprint, why=item.why)

    # --- the API (M.1) ---------------------------------------------------------------------------

    def _own_handlers(self) -> dict[Route, Handler]:
        return {
            api.LOGIN_BEGIN: self._login_begin,
            api.LOGIN_FINISH: self._login_finish,
            api.SETUP_REDEEM: self._setup_redeem,
            api.SESSION: self._session_answer,
            api.LOGOUT: self._logout,
            api.SESSIONS: self._sessions,
            api.END_OTHERS: self._end_others,
            api.ENROL_BEGIN: self._enrol_begin,
            api.ENROL_FINISH: self._enrol_finish,
            api.PASSKEYS: self._passkeys,
            api.SECRETS: self._secret_list,
            api.HEALTH: self._health,
            api.OAUTH: self._oauth_list,
            api.OAUTH_START: self._oauth_start,
            api.FLOW_CANCEL: self._flow_cancel,
            api.ACTIONS: self._prepare,
            api.CONFIRM: self._confirm,
            api.CANCEL: self._cancel,
        }

    async def _login_begin(self, call: Call) -> Reply | Refusal:
        """A login ceremony (D.1): no credential is listed, so nothing about them reaches a
        caller without a session."""
        holder = self._holder()
        if isinstance(holder, Refusal):
            return holder
        entry = call.entry
        ceremony = self.ceremonies.begin_login(
            origin=entry.origin, peer=call.peer, now=self._wall()
        )
        if isinstance(ceremony, Full):
            # F.1 and P16 say 429 for a table full of other peers' ceremonies; M.2's reason for
            # 429 is rate_limited (busy is its 503).
            return refusal("rate_limited")
        options = request_options(challenge=ceremony.challenge, rp_id=entry.rp_id)
        return Reply({"ceremony": ceremony.id, "options": options})

    async def _login_finish(self, call: Call) -> Reply | Refusal:
        """Verify the assertion against a passkey of this origin's RP ID and mint a full session
        (F.2). Any refusal of the assertion is one answer, ``passkey_refused``; the log has the
        verifier's reason."""
        holder = self._holder()
        if isinstance(holder, Refusal):
            return holder
        ceremony = self._take(call, "login", None)
        if isinstance(ceremony, Refusal):
            return ceremony
        entry = call.entry
        try:
            asserted = verify_assertion(
                _body(call)["credential"],
                challenge=ceremony.challenge,
                origin=entry.origin,
                rp_id=entry.rp_id,
                credentials=holder.document.credentials,
                user_handle=holder.user_handle,
                login=True,
            )
        except WebAuthnError as exc:
            logs.event("portal_login_failed", rp_id=entry.rp_id, reason=exc.reason)
            return refusal("passkey_refused")
        holder.touch(asserted)
        fingerprint = holder.fingerprint(asserted.credential_id)
        self._replace(call)
        minted = self.sessions.mint(
            origin=entry.origin,
            rp_id=entry.rp_id,
            scope="full",
            now=self._wall(),
            credential=fingerprint,
        )
        self._finish(minted.ended)
        logs.event(
            "portal_login",
            credential=fingerprint,
            rp_id=entry.rp_id,
            session=minted.session.fingerprint,
        )
        return _minted(entry, minted, {"scope": "full", "idle": int(SESSION_IDLE)})

    async def _setup_redeem(self, call: Call) -> Reply | Refusal:
        """Spend a setup code and mint a setup session (E.1): one answer for every refusal."""
        entry = call.entry
        if self.setup is None:
            return self._setup_refused()
        try:
            decision = await self.setup.redeem(_body(call)["code"], origin=entry.origin)
        except OSError:
            # The record couldn't be removed, so the code isn't spent and no session opens.
            return refusal("not_written")
        if not isinstance(decision, Redeemed):
            return self._setup_refused()
        self._replace(call)
        minted = self.sessions.mint(
            origin=entry.origin,
            rp_id=entry.rp_id,
            scope="setup",
            now=self._wall(),
            reset=decision.reset,
        )
        self._finish(minted.ended)
        logs.event(
            "setup_code_redeemed",
            origin=entry.origin,
            reset=decision.reset,
            session=minted.session.fingerprint,
        )
        return _minted(entry, minted, {"scope": "setup", "reset": decision.reset})

    def _replace(self, call: Call) -> None:
        """Before a mint: one signed-in tab per browser (F.2). The answer's cookie replaces the
        one this browser holds, leaving its session unusable, so the sessions the request's
        cookies name end now, logged ``why: replaced``, instead of idling out. Only a browser
        holding a session's cookie can name it; ending first frees a place rather than evicting
        another browser's session."""
        cookies = [SessionToken(cookie) for cookie in call.cookies]
        self._finish(self.sessions.end_replaced(cookies, self._wall()))

    def _setup_refused(self) -> Refusal:
        count = self._codes_refused.note("setup_code_refused", self._clock())
        if count is not None:
            logs.event("setup_code_refused", count=count)
        return refusal("setup_code_refused")

    async def _session_answer(self, call: Call) -> Reply | Refusal:
        """What the page's header and banners show (K.3): never a token, a key or a full ID."""
        session = _session(call)
        holder = self.passkeys
        usable = holder is not None and not holder.unavailable
        signed_with = self._signed_with(session)
        here = 0
        if holder is not None and usable:
            here = sum(1 for c in holder.document.credentials if c.rp_id == session.rp_id)
        # Health's counts, shown on every page, and a banner for its errors: a full session's.
        counts = None
        if session.scope == "full" and self.health is not None:
            counts = dict(self.health()["summary"])
        banners = self._banners()
        if counts is not None and counts["error"]:
            text = HEALTH_BANNER.format(count=counts["error"])
            banners.append({"code": "health_errors", "text": text})
        answer = {
            "scope": session.scope,
            "origin": session.origin,
            "rp_id": session.rp_id,
            "mode": MODE,
            "idle": int(SESSION_IDLE) if session.scope == "full" else None,
            "expires_at": int(session.expires_at),
            "session": session.fingerprint,
            "credential": session.credential,
            "credential_name_shown": None
            if signed_with is None
            else shown(signed_with.name, NAME_LIMIT),
            "reset": session.reset,
            "passkeys_here": here,
            "banners": banners,
            "health_summary": counts,
        }
        return Reply(answer)

    async def _logout(self, call: Call) -> Reply | Refusal:
        """End this session, expire the cookie and clear the origin's ``sessionStorage``; never
        ``"cookies"``, which on ``localhost`` would clear every port's (F.2)."""
        ended = self.sessions.end(_session(call).id, "logout")
        if ended is None:
            return refusal("no_session")  # another request ended it first, and logged it
        self._finish((ended,))
        headers = (
            session_cookie(call.entry, "", expire=True),
            (b"clear-site-data", b'"storage"'),
        )
        return Reply({}, headers=headers)

    async def _sessions(self, call: Call) -> Reply | Refusal:
        """Every live session (F.2), this one marked."""
        this = _session(call).id
        listed = [_listed(s, this=this) for s in self.sessions.live(self._wall())]
        return Reply({"sessions": listed})

    async def _end_others(self, call: Call) -> Reply | Refusal:
        """End every other session: it only removes privilege, so no step-up (F.4)."""
        ended = self.sessions.end_others(_session(call).id)
        self._finish(ended)
        return Reply({"ended": len(ended)})

    async def _enrol_begin(self, call: Call) -> Reply | Refusal:
        """A setup session's one enrolment (the code was its step-up): the creation options,
        listing every credential of this RP ID unless the code was a ``--reset`` one (D.1)."""
        session = _session(call)
        name = _body(call)["name"]
        if not passkey_file.check_name(name):
            return refusal("bad_name")
        holder = self._enrolling(session)
        if isinstance(holder, Refusal):
            return holder
        existing = () if session.reset else holder.document.credentials
        if len(existing) >= MAX_PASSKEYS:
            return enrolment("too_many_passkeys")
        entry = call.entry
        ceremony = self.ceremonies.begin_enrol(
            origin=entry.origin, session=session.id, name=name, now=self._wall()
        )
        options = creation_options(
            challenge=ceremony.challenge,
            user_handle=holder.user_handle,
            rp_id=entry.rp_id,
            exclude=existing,
        )
        return Reply({"ceremony": ceremony.id, "options": options})

    async def _enrol_finish(self, call: Call) -> Reply | Refusal:
        """Verify the new credential and add it, written before it takes effect (D.4). A setup
        session ends after its one enrolment; with ``reset``, every other passkey and session
        goes first (E.1). The page then signs in with the new passkey."""
        session = _session(call)
        holder = self._enrolling(session)
        if isinstance(holder, Refusal):
            return holder
        ceremony = self._take(call, "enrol", session.id)
        if isinstance(ceremony, Refusal):
            return ceremony
        entry = call.entry
        reset = session.scope == "setup" and session.reset
        try:
            new = verify_registration(
                _body(call)["credential"],
                challenge=ceremony.challenge,
                origin=entry.origin,
                rp_id=entry.rp_id,
                enrolled=() if reset else holder.document.credentials,
            )
        except WebAuthnError as exc:
            return enrolment(exc.reason)
        name = ceremony.name or ""
        removed: tuple[Passkey, ...] = ()
        try:
            if reset:
                removed = holder.reset_with(new, name=name, origin=entry.origin)
                passkey = holder.document.credentials[-1]
            else:
                via: Literal["setup_code", "portal"] = (
                    "setup_code" if session.scope == "setup" else "portal"
                )
                passkey = holder.add(new, name=name, via=via, origin=entry.origin)
        except PasskeyError as exc:
            reason = exc.reason
            if reason == "duplicate_credential" or reason == "too_many_passkeys":
                return enrolment(reason)  # checked again against the file as it is now
            return refusal(reason)
        fingerprint = holder.fingerprint(passkey.id)
        level = {"level": "warning"} if passkey.via != "portal" else {}
        logs.event(
            "passkey_enrolled",
            **level,
            credential=fingerprint,
            rp_id=passkey.rp_id,
            alg=ALGORITHM_NAMES[passkey.alg],
            synced=passkey.backup_eligible,
            via=passkey.via,
            origin=passkey.origin,
        )
        if reset:
            logs.event("passkeys_reset", removed=len(removed))
            self._finish(self.sessions.end_where(lambda s: s.id != session.id, "reset"))
        if session.scope == "setup":
            ended = self.sessions.end(session.id, "enrolled")
            self._finish(() if ended is None else (ended,))
            if self.setup is not None:
                self.setup.enrolled(passkey_file.describe(passkey, fingerprint))
        if self.setup is not None and len(holder.document.credentials) == 1:
            self.setup.discard()  # the first passkey, by whatever path (E.1)
        return Reply({"passkey": _passkey_view(passkey, fingerprint)})

    # --- passkeys and the step-up path (D.5, F.4) ------------------------------------------------

    async def _passkeys(self, call: Call) -> Reply | Refusal:
        """Every passkey as D.5 shows it, with the one this session signed in with marked: never
        a key, a full ID or the user handle."""
        session = _session(call)
        holder = self._holder()
        if isinstance(holder, Refusal):
            return holder
        listed = []
        for passkey in holder.document.credentials:
            fingerprint = holder.fingerprint(passkey.id)
            view = _passkey_view(passkey, fingerprint)
            view["this"] = fingerprint == session.credential
            listed.append(view)
        return Reply({"passkeys": listed})

    async def _prepare(self, call: Call) -> Reply | Refusal:
        """F.4 step 1: check the request against the registry, run the kind's plan, and hold the
        action, replacing this session's earlier one. Nothing changes, and a refusal shows
        before any passkey prompt. The step-up options list this RP ID's passkeys."""
        session = _session(call)
        holder = self._holder()
        if isinstance(holder, Refusal):
            return holder
        request = parse_request(dict(_body(call)), call.size)
        if isinstance(request, ActionRefusal):
            return refusal(request.reason)
        kind = self._kinds.get(request.kind.name)
        if kind is None:
            return refusal("bad_body")  # a kind a later step builds
        entry = call.entry
        plan = kind.plan(request.data, Step(entry, session, holder))
        if isinstance(plan, Refusal):
            return plan
        action = self.actions.prepare(
            kind=request.kind.name,
            data=request.data,
            plan=plan,
            session=session.id,
            origin=entry.origin,
            now=self._wall(),
        )
        options = request_options(
            challenge=action.challenge, rp_id=entry.rp_id, allow=holder.document.credentials
        )
        answer = {
            "action": action.id,
            "kind": action.kind,
            "expires": int(action.expires),
            "summary": _summary(plan),
            "options": options,
        }
        return Reply(answer)

    async def _confirm(self, call: Call) -> Reply | Refusal:
        """F.4 step 3: take the action out of the table, verify the assertion against its
        challenge, plan again, and run exactly what was held. The action is spent whatever
        happens. Any refusal of the assertion is one answer, ``step_up_refused``, with the
        verifier's reason in the log; a plan that moved is ``409 changed`` with both summaries,
        and one that now refuses answers that refusal. The counter is applied only then (L3
        §7.2 step 24): a regression is flagged and the stored value never goes down (D10)."""
        session = _session(call)
        holder = self._holder()
        if isinstance(holder, Refusal):
            return holder
        entry = call.entry
        action = self.actions.take(
            call.params["action"], session=session.id, origin=entry.origin, now=self._wall()
        )
        if action is None:
            return refusal("action_unknown")
        try:
            asserted = verify_assertion(
                _body(call)["credential"],
                challenge=action.challenge,
                origin=entry.origin,
                rp_id=entry.rp_id,
                credentials=holder.document.credentials,
                user_handle=holder.user_handle,
                login=False,
            )
        except WebAuthnError as exc:
            logs.event("step_up_refused", action=action.kind, reason=exc.reason)
            return refusal("step_up_refused")
        credential = holder.fingerprint(asserted.credential_id)
        kind = self._kinds[action.kind]
        data = action.data.reveal()
        step = Step(entry, session, holder)
        plan = kind.plan(data, step)
        if isinstance(plan, Refusal) or changed(action, plan):
            reason = plan.reason if isinstance(plan, Refusal) else "changed"
            logs.event("action_changed", action=action.kind, credential=credential, reason=reason)
            return plan if isinstance(plan, Refusal) else _changed(action, plan)
        holder.touch(asserted)
        logs.event("step_up_confirmed", action=action.kind, credential=credential)
        return await kind.run(data, step)

    async def _cancel(self, call: Call) -> Reply | Refusal:
        """F.4 step 4: drop this session's pending action and the data it holds."""
        cancelled = self.actions.cancel(
            call.params["action"],
            session=_session(call).id,
            origin=call.entry.origin,
            now=self._wall(),
        )
        return Reply({"cancelled": cancelled})

    def _own_kinds(self) -> dict[str, ActionKind]:
        """The kinds this portal runs, each in ``actions.KINDS``; M6 and M8 add theirs here."""
        return {
            "passkey.enrol": ActionKind(self._plan_enrol, self._run_enrol),
            "passkey.rename": ActionKind(self._plan_rename, self._run_rename),
            "passkey.remove": ActionKind(self._plan_remove, self._run_remove),
            "secret.put": ActionKind(self._plan_put, self._run_put),
            "secret.delete": ActionKind(self._plan_delete, self._run_delete),
            "oauth.complete": ActionKind(self._plan_complete, self._run_complete),
            "oauth.reset": ActionKind(self._plan_reset, self._run_reset),
        }

    def _plan_enrol(self, data: Mapping[str, Any], step: Step) -> Plan | Refusal:
        """``passkey.enrol``: the name, the count, and the RP ID the new passkey will work on."""
        name = data["name"]
        if not passkey_file.check_name(name):
            return refusal("bad_name")
        count = len(step.holder.document.credentials)
        if count >= MAX_PASSKEYS:
            return enrolment("too_many_passkeys")
        rp_id = step.entry.rp_id
        summary = (
            ("Enrol a new passkey named", shown(name, NAME_LIMIT)),
            ("It works on", rp_id),
            ("Passkeys enrolled now", f"{count} of at most {MAX_PASSKEYS}"),
        )
        return Plan(summary, (name, rp_id, count))

    async def _run_enrol(self, data: Mapping[str, Any], step: Step) -> Reply | Refusal:
        """An enrolment ceremony for this session, as a setup code's would be: the page creates
        the passkey and finishes at ``/api/passkeys/enrol/finish``, which checks again."""
        entry, holder = step.entry, step.holder
        ceremony = self.ceremonies.begin_enrol(
            origin=entry.origin, session=step.session.id, name=data["name"], now=self._wall()
        )
        options = creation_options(
            challenge=ceremony.challenge,
            user_handle=holder.user_handle,
            rp_id=entry.rp_id,
            exclude=holder.document.credentials,
        )
        return Reply({"ceremony": ceremony.id, "options": options})

    def _plan_rename(self, data: Mapping[str, Any], step: Step) -> Plan | Refusal:
        """``passkey.rename``: the passkey exists, on any RP ID, and the name follows D.4's
        rules."""
        target = _target(step.holder, data["credential"])
        if isinstance(target, Refusal):
            return target
        fingerprint, passkey = target
        name = data["name"]
        if not passkey_file.check_name(name):
            return refusal("bad_name")
        summary = (
            ("Rename the passkey", fingerprint),
            ("Named now", shown(passkey.name, NAME_LIMIT)),
            ("New name", shown(name, NAME_LIMIT)),
            ("It works on", passkey.rp_id),
        )
        return Plan(summary, (fingerprint, passkey.name, name))

    async def _run_rename(self, data: Mapping[str, Any], step: Step) -> Reply | Refusal:
        fingerprint = data["credential"]
        try:
            renamed = step.holder.rename(fingerprint, data["name"])
        except PasskeyError as exc:
            return refusal(exc.reason)
        logs.event("passkey_renamed", credential=fingerprint, rp_id=renamed.rp_id)
        return Reply({"passkey": _passkey_view(renamed, fingerprint)})

    def _plan_remove(self, data: Mapping[str, Any], step: Step) -> Plan | Refusal:
        """``passkey.remove``: the passkey exists, it isn't the last (the portal never removes
        that one; the admin socket may, Q26), and which sessions end with it."""
        holder = step.holder
        target = _target(holder, data["credential"])
        if isinstance(target, Refusal):
            return target
        fingerprint, passkey = target
        if len(holder.document.credentials) == 1:
            return refusal("last_passkey")
        ending = tuple(
            sorted(
                session.fingerprint
                for session in self.sessions.live(self._wall())
                if session.credential == fingerprint
            )
        )
        summary = (
            ("Remove the passkey", fingerprint),
            ("Named", shown(passkey.name, NAME_LIMIT)),
            ("It works on", passkey.rp_id),
            ("Sessions that end", _ending(len(ending), step.session.credential == fingerprint)),
        )
        return Plan(summary, (fingerprint, passkey.name, ending))

    async def _run_remove(self, data: Mapping[str, Any], step: Step) -> Reply | Refusal:
        """Written before it takes effect; then the sessions its logins made end, this one too
        if it was one of them."""
        fingerprint = data["credential"]
        try:
            removed = step.holder.remove(fingerprint)  # allow_last stays False (Q26)
        except PasskeyError as exc:
            return refusal(exc.reason)
        ended = self.end_credential(fingerprint)
        remaining = len(step.holder.document.credentials)
        logs.event(
            "passkey_removed",
            credential=fingerprint,
            rp_id=removed.rp_id,
            origin=removed.origin,
            sessions_ended=ended,
            remaining=remaining,
        )
        answer = {
            "removed": _passkey_view(removed, fingerprint),
            "sessions_ended": ended,
            "remaining": remaining,
            "signed_out": step.session.credential == fingerprint,
        }
        return Reply(answer)

    # --- secrets (G): write-only ------------------------------------------------------------------

    async def _secret_list(self, call: Call) -> Reply | Refusal:
        """Every store entry by name, with its metadata: never a value, a length or a hash of
        one, and none of the clear ``meta`` anyone with the file can edit."""
        entries = self._secret_store().store.metadata()
        found = None if self.health is None else _secret_health(self.health())
        listed = []
        for entry in entries:
            view = _secret_view(entry)
            view["health"] = view["health_shown"] = None
            if found is not None:
                codes = found.get(entry.name, [])
                view["health"] = [{"code": code, "level": level} for code, level in codes]
                words = ", ".join(f"{code} ({level})" for code, level in codes)
                view["health_shown"] = words or "ok"
            listed.append(view)
        return Reply({"secrets": listed})

    def _plan_put(self, data: Mapping[str, Any], step: Step) -> Plan | Refusal:
        """``secret.put``: ``secretplan.plan_put``, the socket's checks and binding (P10, D-10:
        an OAuth secret takes the policy's binding and refuses origins), then what the write
        replaces, and the binding until now when it moves. The value is in the facts, so a
        confirm compares it, and never in the summary."""
        place = self._secret_store()
        plan = _put_plan(data, place)
        if isinstance(plan, Refusal):
            return plan
        name = plan.name
        entry = place.store.entry(name)
        summary = [("Store", shown(name, NAME_LIMIT)), ("Bound to", _binding_words(plan.binding))]
        if entry is None:
            summary.append(("Replaces", "nothing: no secret has this name yet"))
            return Plan(tuple(summary), (plan, None))
        summary.append(("Replaces", f"the value set at {_when(entry.updated)}"))
        if entry.binding != plan.binding:
            summary.append(("Bound until now", _binding_words(entry.binding)))
        return Plan(tuple(summary), (plan, entry.binding, entry.updated))

    async def _run_put(self, data: Mapping[str, Any], step: Step) -> Reply | Refusal:
        """The write, as the socket's: through the token manager for a name an oauth2 credential
        uses. A failed file write is kept in memory and answered ``not_written``."""
        place = self._secret_store()
        plan = _put_plan(data, place)  # the confirm planned the same a moment ago
        if isinstance(plan, Refusal):
            return plan
        written = await secretops.put(place.store, place.tokens, plan, via="portal")
        if isinstance(written, SecretRefusal):
            return secret(written, name=plan.name)
        entry = place.store.entry(plan.name)
        return Reply({"secret": None if entry is None else _secret_view(entry)})

    def _plan_delete(self, data: Mapping[str, Any], step: Step) -> Plan | Refusal:
        """``secret.delete``: a valid name, and not one the vault manages, so the portal never
        deletes a live slot (the socket may); then ``secretplan.plan_delete``, and the secret
        must exist."""
        place = self._secret_store()
        name = data["name"]
        if not isinstance(name, str):
            return refusal("bad_body")
        refused = secretplan.check_name(name)
        if refused is not None:
            return secret(refused, name=name)
        plan = secretplan.plan_delete(name, place.policy())
        entry = place.store.entry(name)
        if entry is None:
            return secret(secretplan.NOT_FOUND, name=name)
        summary = (
            ("Delete", shown(name, NAME_LIMIT)),
            ("Bound to", _binding_words(entry.binding)),
            ("Set at", _when(entry.updated)),
        )
        return Plan(summary, (plan, entry.binding, entry.updated))

    async def _run_delete(self, data: Mapping[str, Any], step: Step) -> Reply | Refusal:
        place = self._secret_store()
        name = data["name"]
        plan = secretplan.plan_delete(name, place.policy())
        refused = await secretops.delete(place.store, place.tokens, plan, via="portal")
        if refused is not None:
            return secret(refused, name=name)
        return Reply({"name": name, "deleted": True})

    # --- health (I) and OAuth connect by paste (H) -----------------------------------------------

    async def _health(self, call: Call) -> Reply | Refusal:
        """The I.1 report, fit to show (K.1): every finding's text and every name the policy gave
        passes :func:`~.display.shown`; each action stays structured, for the page's button."""
        if self.health is None:
            raise RuntimeError("this portal has no health reader")
        return Reply(_health_view(self.health()))

    async def _oauth_list(self, call: Call) -> Reply | Refusal:
        """Every oauth2 credential as the logins see it (``LoginService.status``), and what the
        operator can do about it: how it connects, the scopes asked for and expected, where its
        tokens go. The clear ``meta`` it shows is text anyone with the state file can edit."""
        policy = self._policy()
        listed = []
        for item in self._login_service().status():
            cred = policy.credentials.get(item["credential"])
            if isinstance(cred, OAuth2Credential):
                listed.append(_oauth_view(item, cred, policy))
        return Reply({"credentials": listed})

    async def _oauth_start(self, call: Call) -> Reply | Refusal:
        """H.1 step 1: a login owned by this session. The answer is the socket's, with the
        fields the dialog shows and ``replaced`` (where a login it replaced was started). For
        client_credentials it is the test fetch: it writes no grant and, when it works, clears
        the credential's failure state, the one route besides an action's confirm with that
        effect, and only after a fetch that just worked (F.4)."""
        session = _session(call)
        rebind = _body(call).get("rebind", False)
        if not isinstance(rebind, bool):
            return refusal("bad_body")
        credential = call.params["credential"]
        try:
            started = await self._login_service().start(
                credential, rebind=rebind, owner=session.owner
            )
        except LoginError as exc:
            return self._login_refused(exc, credential)
        if "flow" not in started:
            return Reply(_completed(credential, started))
        change = started["binding_change"]
        change_shown = None
        if change is not None:
            change_shown = {
                "old": _binding_words(change["old"]),
                "new": _binding_words(change["new"]),
            }
        answer = {
            **started,
            "credential": credential,
            "name_shown": shown(credential, NAME_LIMIT),
            "redirect_uri_shown": shown(started["redirect_uri"], SUMMARY_LIMIT),
            "requested_scopes_shown": _scopes(started["requested_scopes"]),
            "expected_scopes_shown": _scopes(started["expected_scopes"]),
            "binding_shown": _binding_words(started["binding"]),
            "binding_change_shown": change_shown,
        }
        return Reply(answer)

    async def _flow_cancel(self, call: Call) -> Reply | Refusal:
        """H.1 step 4: drop this session's pending login. Another owner's, or none, answers
        ``flow_unknown``, as an unknown one does, and that flow stays (P11)."""
        if not self._login_service().cancel(call.params["flow"], _session(call).owner):
            return refusal("flow_unknown")
        return Reply({"cancelled": True})

    def _plan_complete(self, data: Mapping[str, Any], step: Step) -> Plan | Refusal:
        """``oauth.complete`` by paste: ``check_paste`` reads the address against this
        session's flow for the credential without taking it, so a mistyped paste is refused
        here, before the passkey prompt, and can be fixed (a provider's error ends the flow).
        Then what completing stores: the binding, the one it replaces (which needs a start with
        rebind), and the scopes asked for and expected."""
        credential, flow, pasted = data["credential"], data["flow"], data["redirect_url"]
        if not all(isinstance(value, str) for value in (credential, flow, pasted)):
            return refusal("bad_body")
        try:
            checked = self._login_service().check_paste(
                credential, flow, pasted, step.session.owner
            )
        except LoginError as exc:
            return self._login_refused(exc, credential)
        change = checked["binding_change"]
        summary = [
            ("Connect", shown(credential, NAME_LIMIT)),
            ("With", "the address you pasted, checked: it is this sign-in's answer"),
            ("Its tokens go to", _binding_words(checked["binding"])),
        ]
        if change is not None:
            summary.append(("Bound until now", _binding_words(change["old"])))
        summary += [
            ("Scopes asked for", _scope_words(checked["requested_scopes"])),
            ("Scopes expected", _scope_words(checked["expected_scopes"])),
        ]
        return Plan(tuple(summary), (credential, flow, checked))

    async def _run_complete(self, data: Mapping[str, Any], step: Step) -> Reply | Refusal:
        """The exchange: ``LoginService.complete`` takes the flow (so any failure from here
        needs a new connect), exchanges the code once and stores the grant. Scopes outside the
        expected set are flagged, never refused."""
        credential = data["credential"]
        try:
            done = await self._login_service().complete(
                credential, data["flow"], data["redirect_url"], step.session.owner
            )
        except LoginError as exc:
            return self._login_refused(exc, credential)
        return Reply(_completed(credential, done))

    def _plan_reset(self, data: Mapping[str, Any], step: Step) -> Plan | Refusal:
        """``oauth.reset`` (D-22): an oauth2 credential the logins know, and its state now. The
        reset clears its failure state, so the next request that needs a token tries once."""
        credential = data["credential"]
        if not isinstance(credential, str):
            return refusal("bad_body")
        found = [i for i in self._login_service().status() if i["credential"] == credential]
        if not found:
            return refusal("not_oauth")
        state, code = found[0]["state"], found[0]["code"]
        summary = (
            ("Clear the failure state of", shown(credential, NAME_LIMIT)),
            ("Its state now", state if code is None else f"{state} ({code})"),
            ("Then", "the next request that needs a token tries once"),
        )
        return Plan(summary, (credential, state, code, found[0]["reason"]))

    async def _run_reset(self, data: Mapping[str, Any], step: Step) -> Reply | Refusal:
        """``TokenManager.reset``, as ``zoeymcp oauth reset`` runs it (it logs
        ``oauth_cache_reset``); the answer is the socket's."""
        tokens = self._secret_store().tokens
        credential = data["credential"]
        if tokens is None or not tokens.reset(credential):
            return refusal("not_oauth")
        return Reply({"credential": credential, "reset": True})

    def _login_refused(self, exc: LoginError, credential: str) -> Refusal:
        """A refused start, paste or exchange in the portal's words (H.3), with the status and
        reason the socket answers. A provider's description (cleaned and capped by the vault,
        then shown) and a ``binding_changed``'s two bindings go beside the text."""
        cred = self._policy().credentials.get(credential)
        redirect_uri = cred.redirect_uri if isinstance(cred, OAuth2Credential) else ""
        details = exc.details
        made = login_refusal(
            exc.reason,
            detail=str(exc),
            error=details.get("provider_error"),
            redirect_uri=redirect_uri,
        )
        more: tuple[tuple[str, Any], ...] = ()
        if exc.reason == "provider_error":
            description = details.get("description")
            more = (("description_shown", None if description is None else shown(description)),)
        elif exc.reason == "binding_changed":
            more = (
                ("old_shown", _binding_words(details.get("old"))),
                ("new_shown", _binding_words(details.get("new"))),
            )
        return replace(made, more=more)

    def _login_service(self) -> LoginService:
        if self.login is None:
            raise RuntimeError("this portal has no login service")
        return self.login

    def _policy(self) -> Policy:
        """The running policy, as the Secrets area reads it."""
        return self._secret_store().policy()

    def _secret_store(self) -> Secrets:
        if self.secrets is None:
            raise RuntimeError("this portal has no secret store")
        return self.secrets

    def _holder(self) -> Passkeys | Refusal:
        """The passkey file, unless it can't be verified (P19: 503 until a reset)."""
        holder = self.passkeys
        if holder is None or holder.unavailable:
            return refusal("unavailable")
        return holder

    def _enrolling(self, session: Session) -> Passkeys | Refusal:
        """The passkey file for an enrolment: a ``--reset`` setup session may replace one that
        can't be verified, which is the way out of that state."""
        holder = self.passkeys
        if holder is None or (holder.unavailable and not session.reset):
            return refusal("unavailable")
        return holder

    def _take(self, call: Call, kind: CeremonyKind, session: str | None) -> Ceremony | Refusal:
        """The ceremony the body names, taken out of the table before its answer is checked."""
        wanted = _body(call)["ceremony"]
        if not isinstance(wanted, str):
            return refusal("bad_body")
        ceremony = self.ceremonies.take(
            wanted, kind=kind, origin=call.entry.origin, now=self._wall(), session=session
        )
        return refusal("ceremony_unknown") if ceremony is None else ceremony

    def _signed_with(self, session: Session) -> Passkey | None:
        holder = self.passkeys
        if holder is None or session.credential is None:
            return None
        try:
            return holder.find(session.credential)
        except PasskeyError:
            return None  # removed since, or the file can't be verified

    def _banners(self) -> list[dict[str, str]]:
        """The banner lines every page shows (K.3); the ledger's and health's come in steps 14a
        and 15."""
        holder = self.passkeys
        if holder is None:
            return []
        if holder.unavailable:
            return [{"code": "passkeys_unavailable", "text": refusal("unavailable").error}]
        regressed = holder.document.last_regressed
        if regressed is not None and self._wall() - regressed < REGRESSED_FOR:
            return [{"code": "passkey_counter_regressed", "text": COUNTER_BANNER}]
        return []

    # --- answers ---------------------------------------------------------------------------------

    async def _refuse(self, exchange: _Exchange, refused: Refusal) -> None:
        await self._send_json(exchange, refused.status, refused.body(), _refusal_headers(refused))
        count = self._refused.note(refused.reason, self._clock())
        if count is not None:
            logs.event("portal_refused", reason=refused.reason, status=refused.status, count=count)

    async def _fail(self, exchange: _Exchange, started: float, exc: Exception) -> None:
        """A handler raised: 500 with every header, and the exception's type in the log."""
        failed = refusal("internal")
        await self._send_json(exchange, failed.status, failed.body(), ())
        logs.event(
            "portal_request",
            method=exchange.scope["method"],
            route=exchange.route,
            status=failed.status,
            reason=failed.reason,
            session=None,
            ms=self._ms(started),
            error_type=type(exc).__name__,
        )

    def _served_line(self, method: str, route: str, status: int, started: float) -> None:
        count = self._served.note(route, self._clock())
        if count is not None:
            logs.event(
                "portal_request",
                method=method,
                route=route,
                status=status,
                reason=None,
                session=None,
                ms=self._ms(started),
                count=count,
            )

    async def _send_json(
        self, exchange: _Exchange, status: int, body: Mapping[str, Any], headers: Iterable[Header]
    ) -> None:
        data = json.dumps(body, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
        await self._send(exchange, status, data.encode(), JSON_TYPE, headers)

    async def _send(
        self,
        exchange: _Exchange,
        status: int,
        body: bytes,
        content_type: bytes | None,
        extra: Iterable[Header] = (),
    ) -> None:
        headers = [*HEADERS, (b"content-length", str(len(body)).encode())]
        if content_type is not None:
            headers.append((b"content-type", content_type))
        headers.extend(extra)
        if exchange.must_close:
            headers.append((b"connection", b"close"))
        exchange.answered = True
        await exchange.send({"type": "http.response.start", "status": status, "headers": headers})
        await exchange.send({"type": "http.response.body", "body": body})

    def _ms(self, started: float) -> float:
        return round((self._clock() - started) * 1000, 1)


def session_cookie(entry: Origin, value: str, *, expire: bool = False) -> Header:
    """C.1's session cookie for ``entry``: ``HttpOnly``, ``SameSite=Strict``, ``Path=/``, and
    ``Secure`` on https; no ``Domain`` and no lifetime, so the server decides when it ends. At
    logout, the same name with ``Max-Age=0``."""
    parts = [f"{entry.cookie_name}={value}"]
    if entry.secure:
        parts.append("Secure")
    parts += ["HttpOnly", "SameSite=Strict", "Path=/"]
    if expire:
        parts.append("Max-Age=0")
    return b"set-cookie", "; ".join(parts).encode("latin-1")


def _minted(entry: Origin, minted: Minted, fields: Mapping[str, Any]) -> Reply:
    """The answer that mints a session: the header half in the body, the cookie half set; each
    is sent this once (F.2)."""
    body = {"token": minted.header.reveal(), **fields, "expires_at": int(minted.session.expires_at)}
    return Reply(body, headers=(session_cookie(entry, minted.cookie.reveal()),))


def _listed(session: Session, *, this: str | None = None) -> dict[str, Any]:
    """A session as the lists show it (F.2): its fingerprint, never its ID or either half."""
    listed: dict[str, Any] = {
        "fingerprint": session.fingerprint,
        "origin": session.origin,
        "scope": session.scope,
        "credential": session.credential,
        "created": int(session.created),
        "last_seen": int(session.last_seen),
        "expires_at": int(min(session.expires_at, session.idle_until)),
    }
    if this is not None:
        listed["this"] = session.id == this
    return listed


def _passkey_view(passkey: Passkey, fingerprint: str) -> dict[str, Any]:
    """D.5's fields of one passkey, its name as text the page may show (K.1)."""
    view = passkey_file.describe(passkey, fingerprint)
    view["name_shown"] = shown(view.pop("name"), NAME_LIMIT)
    return view


def _target(holder: Passkeys, wanted: object) -> tuple[str, Passkey] | Refusal:
    """The passkey an action names by its fingerprint, on any RP ID: 404 ``not_found``, or 409
    ``ambiguous_fingerprint`` when two share it, so a change never takes another than the one
    shown."""
    if not isinstance(wanted, str):
        return refusal("bad_body")
    try:
        return wanted, holder.find(wanted)
    except PasskeyError as exc:
        return refusal(exc.reason)


def _summary(plan: Plan) -> list[list[str]]:
    """A plan's summary as the answer carries it: ``[label, value]`` pairs, in order."""
    return [[label, value] for label, value in plan.summary]


def _changed(action: Action, plan: Plan) -> Reply:
    """409 ``changed``: the refusal, and the plan as prepared beside the plan as it is now."""
    body = {**refusal("changed").body(), "was": _summary(action.plan), "now": _summary(plan)}
    return Reply(body, status=409, reason="changed")


def _ending(count: int, this: bool) -> str:
    """How many sessions a removal ends, for its summary."""
    if count == 0:
        return "none"
    return f"{count}, this one included" if this else str(count)


def _put_plan(data: Mapping[str, Any], place: Secrets) -> PutPlan | Refusal:
    """``secretplan.plan_put`` over a ``secret.put``'s data (its keys checked by the registry),
    each refusal in the portal's words with the plan's status (G)."""
    name = data["name"]
    if not isinstance(name, str):
        return refusal("bad_body")
    body = {key: data[key] for key in ("value", "origins") if key in data}
    plan = secretplan.plan_put(name, body, place.policy())
    return secret(plan, name=name) if isinstance(plan, SecretRefusal) else plan


def _secret_view(entry: EntryMeta) -> dict[str, Any]:
    """A store entry as the Secrets list shows it (G). Only the name is checked by the store, so
    every other field, which anyone with the file can edit, is shown as text the page may show
    (K.1); the binding in words."""
    return {
        "name": entry.name,
        "name_shown": shown(entry.name, NAME_LIMIT),
        "binding_shown": _binding_words(entry.binding),
        "key_id": shown(str(entry.key_id), NAME_LIMIT),
        "created": _when(entry.created),
        "updated": _when(entry.updated),
        "live_slot": entry.name.startswith(VAULT_PREFIX),
    }


# A stored binding's verdict where the policy uses the secret (``health.judge``), as a finding.
_VERDICTS: Final[Mapping[str, tuple[str, str]]] = MappingProxyType(
    {"changed": ("binding_changed", "error"), "wider": ("binding_wider", "info")}
)


def _secret_health(report: Mapping[str, Any]) -> dict[str, list[tuple[str, str]]]:
    """Each store entry's health for the Secrets list (G, I.1), as codes and levels: the verdict
    on its binding wherever the policy uses it, a reason the policy can't bind it, and the
    store's own findings about it (nothing uses it; a live slot no credential keeps)."""
    found: dict[str, dict[tuple[str, str], None]] = {}
    for section in (*report["credentials"], *report["connectors"]):
        for row in section["refs"]:
            ref, verdict = row["ref"], row["binding"]
            if ref.startswith("store:") and verdict not in (None, "ok"):
                code = _VERDICTS.get(verdict, (verdict, "error"))
                found.setdefault(ref.removeprefix("store:"), {})[code] = None
    for finding in report["store"]["findings"]:
        name = (finding["action"] or {}).get("secret")
        if isinstance(name, str):
            found.setdefault(name, {})[(finding["code"], finding["level"])] = None
    return {name: list(codes) for name, codes in found.items()}


def _binding_words(binding: object) -> str:
    """What a binding lets the vault do with the secret, in words, every origin and host shown
    as text (K.1): "sent to https://api.example:443"; "token endpoint https://auth.example:443,
    its access tokens used at https://api.example:443"; "SMTP mail.example:465 from a@x to
    b@y"."""
    words = "a binding the vault doesn't recognize"
    if isinstance(binding, dict):
        origins, oauth, smtp = binding.get("origins"), binding.get("oauth"), binding.get("smtp")
        if _strings(origins):
            words = f"sent to {', '.join(origins)}"
        elif isinstance(oauth, dict) and isinstance(oauth.get("token"), str):
            resources = oauth.get("resources")
            used = (
                f", its access tokens used at {', '.join(resources)}" if _strings(resources) else ""
            )
            words = f"token endpoint {oauth['token']}{used}"
        elif isinstance(smtp, dict) and _strings(smtp.get("to")):
            words = f"SMTP {smtp.get('host')}:{smtp.get('port')} from {smtp.get('from')} to "
            words += ", ".join(smtp["to"])
    return shown(words, SUMMARY_LIMIT)


def _strings(value: object) -> TypeGuard[list[str]]:
    """A non-empty list of strings."""
    return isinstance(value, list) and bool(value) and all(isinstance(v, str) for v in value)


def _when(value: object) -> str:
    """A store time (ISO 8601, UTC) as the page shows it: ``2026-10-01 09:00 UTC``."""
    if isinstance(value, str):
        try:
            moment = datetime.fromisoformat(value)
        except ValueError:
            moment = None
        if moment is not None and moment.tzinfo is not None:
            return moment.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")
    return "an unknown time"


def _health_view(report: Mapping[str, Any]) -> dict[str, Any]:
    """The I.1 report as the page shows it (K.1): each section with its findings' text shown and
    each credential's and connector's name shown, and every finding again in one checklist,
    errors first, then warnings, then information (I.2). A finding keeps its ``action``."""
    checklist: list[dict[str, Any]] = []
    view: dict[str, Any] = {"summary": report["summary"]}
    for key, kind in (("credentials", "credential"), ("connectors", "connector")):
        view[key] = [_health_section(kind, item, checklist) for item in report[key]]
    for key in ("store", "passkeys", "ledger_copy"):
        if key in report:
            view[key] = _health_section(key, report[key], checklist)
    rank = {"error": 0, "warning": 1, "info": 2}
    view["checklist"] = sorted(checklist, key=lambda finding: rank[finding["level"]])
    return view


def _health_section(
    kind: str, section: Mapping[str, Any], checklist: list[dict[str, Any]]
) -> dict[str, Any]:
    """One section of the report fit to show, its findings added to ``checklist``. A secret
    reference's row stays out: the finding's text names it."""
    view = {key: value for key, value in section.items() if key not in ("findings", "refs")}
    name = section.get("name")
    name_shown = shown(name, NAME_LIMIT) if isinstance(name, str) else None
    if name_shown is not None:
        view["name_shown"] = name_shown
    if "routes" in section:
        view["routes"] = [shown(route, NAME_LIMIT) for route in section["routes"]]
    findings = []
    for finding in section["findings"]:
        shown_finding = {key: value for key, value in finding.items() if key != "text"}
        shown_finding["text_shown"] = shown(finding["text"], SUMMARY_LIMIT)
        action = finding["action"]
        shown_finding["todo"] = None if action is None else ACTION_WORDS.get(action["kind"])
        shown_finding["section"] = kind
        shown_finding["name_shown"] = name_shown
        findings.append(shown_finding)
    view["findings"] = findings
    checklist.extend(findings)
    return view


def _oauth_view(item: Mapping[str, Any], cred: OAuth2Credential, policy: Policy) -> dict[str, Any]:
    """One credential of ``GET /api/oauth``: the vault's own states, codes and times as they
    are; the provider's error code, the scopes, the upstreams and the clear ``meta`` shown."""
    name = item["credential"]
    meta = item["meta"] or {}
    consented = meta.get("consented_at")
    scopes = item["scopes"]
    connect = None
    if cred.grant == "client_credentials":
        connect = CONNECT_TEST
    elif cred.authorize_url is not None:
        connect = CONNECT_BROWSER
    used_at = sorted({r.upstream for r in policy.routes if r.credential == name and r.upstream})
    requested = split_scope(cred.scope, cred.scope_separator)
    error = None if item["error"] is None else shown(str(item["error"]))
    ago = item["last_ok_ago"]
    text = (
        f"OAuth: {item['state']}"
        + ("" if item["code"] is None else f" ({item['code']})")
        + ("" if error is None else f", the provider said {error}")
        + "; last worked "
        + ("not since the vault started" if ago is None else f"{round(ago / 60)} min ago")
        + f"; asks for {_scope_words(requested)}; its tokens go to "
        + (shown(", ".join(used_at), SUMMARY_LIMIT) or "no route")
        + "."
    )
    return {
        "credential": name,
        "name_shown": shown(name, NAME_LIMIT),
        "grant": item["grant"],
        "state": item["state"],
        "code": item["code"],
        "reason": item["reason"],
        "error_shown": error,
        "retry_in": item["retry_in"],
        "action": item["action"],
        "last_ok_ago": item["last_ok_ago"],
        "consented_at_shown": shown(consented) if isinstance(consented, str) else None,
        "reconsent_due": item["reconsent_due"],
        "last_failure": item["last_failure"],
        "idle": item["idle"],
        "unexpected_scopes_shown": None if scopes is None else _scopes(scopes["unexpected"]),
        "missing_scopes_shown": None if scopes is None else _scopes(scopes["missing"]),
        "persisted": item["persisted"],
        "connect": connect,
        "requested_scopes_shown": _scopes(requested),
        "expected_scopes_shown": _scopes(cred.effective_expected_scopes),
        "used_at_shown": [shown(upstream, SUMMARY_LIMIT) for upstream in used_at],
        "text_shown": text,
    }


def _completed(credential: str, done: Mapping[str, Any]) -> dict[str, Any]:
    """A completed connect or test fetch (H.1 step 3): the socket's answer, with the scopes, the
    binding and the seed note shown. Scopes outside the expected set are flagged, not refused."""
    note = None if done["seed_note"] is None else shown(done["seed_note"], SUMMARY_LIMIT)
    unexpected, missing = done["unexpected_scopes"], done["missing_scopes"]
    text = f"granted {_scope_words(done['granted_scopes'])}."
    if unexpected:
        text += f" Not expected: {_scope_words(unexpected)}."
    if missing:
        text += f" Expected, not granted: {_scope_words(missing)}."
    if done["grant_expires_at"] is not None:
        text += f" The grant ends at {done['grant_expires_at']}: connect again before then."
    if done["refresh_expires_at"] is not None:
        text += f" The refresh token expires at {done['refresh_expires_at']}."
    if not done["persisted"]:
        text += " Kept in memory, not written to disk: check the state volume."
    if note is not None:
        text += f" {note}"
    return {
        **done,
        "credential": credential,
        "name_shown": shown(credential, NAME_LIMIT),
        "binding_shown": _binding_words(done["binding"]),
        "granted_scopes_shown": _scopes(done["granted_scopes"]),
        "unexpected_scopes_shown": _scopes(unexpected),
        "missing_scopes_shown": _scopes(missing),
        "seed_note_shown": note,
        "text_shown": text,
    }


def _scopes(scopes: Iterable[str]) -> list[str]:
    return [shown(scope) for scope in scopes]


def _scope_words(scopes: Sequence[str]) -> str:
    """Scopes for a summary line, each shown, or ``none``."""
    return " ".join(_scopes(scopes)) if scopes else "none"


def _session(call: Call) -> Session:
    if call.session is None:
        raise RuntimeError(f"{call.route.path} needs a session")
    return call.session


def _body(call: Call) -> Mapping[str, Any]:
    if call.body is None:
        raise RuntimeError(f"{call.route.path} needs a body")
    return call.body


def _refusal_headers(refused: Refusal) -> tuple[Header, ...]:
    headers: list[Header] = []
    if refused.reason in RETRY_AFTER:
        headers.append((b"retry-after", RETRY_AFTER[refused.reason]))
    if refused.reason == "method":
        headers.append((b"allow", ALLOW))
    return tuple(headers)
