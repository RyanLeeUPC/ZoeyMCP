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
one stops the start. The API's routes and their handlers are given by the steps that build them
(none yet: every ``/api/`` path is 404).

Logs (M.4): ``portal_request`` for each answer a handler gives; ``portal_refused`` for a refusal
before one, at most once per 10 s per reason with a count, never the refused ``Host`` or
``Origin``; a static file or the 308 as ``portal_request``, at most once per 10 s per path.
"""

from __future__ import annotations

import asyncio
import importlib.resources
import json
import time
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from importlib.resources.abc import Traversable
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Final

from starlette.types import Receive, Scope, Send

from ..vault import logs
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
from .limits import Bucket, InFlight, Sparse, Ticket
from .refusals import Refusal, refusal
from .routes import ROUTES, STATIC, Route
from .sessions import Session, Sessions, SessionToken

if TYPE_CHECKING:
    from ..vault.admin import SetupCodes
    from ..vault.oauth.login import LoginService
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
    parameters, its raw query, the parsed body (None for a route without one), and the session
    both halves found (None on an unauthenticated route)."""

    entry: Origin
    route: Route
    params: Mapping[str, str]
    query: bytes
    body: Mapping[str, Any] | None
    session: Session | None


@dataclass(frozen=True)
class Reply:
    """A handler's answer: a JSON object, its status, and any extra headers (``Set-Cookie``)."""

    body: Mapping[str, Any]
    status: int = 200
    headers: tuple[Header, ...] = field(default=(), repr=False)


Handler = Callable[[Call], Awaitable[Reply | Refusal]]


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

    ``setup``, ``passkeys`` and ``login`` are the ones the vault shares with the admin socket.
    ``routes`` and ``handlers`` are the API (M.1): a route without a handler answers 404.
    ``clock`` is monotonic (the limits); ``wall`` is the sessions' clock. ``body_deadline`` is
    :data:`BODY_DEADLINE` but for tests.
    """

    def __init__(
        self,
        origins: Iterable[str],
        *,
        static: Mapping[str, bytes],
        setup: SetupCodes | None = None,
        passkeys: Passkeys | None = None,
        login: LoginService | None = None,
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
        self._routes = tuple(routes)
        self._handlers = dict(handlers or {})
        self._clock = clock
        self._wall = wall
        self.body_deadline = body_deadline
        self.sessions = Sessions()
        self._gate = InFlight()
        self._bucket = Bucket()
        self._refused: Sparse[str] = Sparse(REFUSED_LOG_EVERY)
        self._served: Sparse[str] = Sparse(SERVED_LOG_EVERY)

    @property
    def origins(self) -> tuple[str, ...]:
        return tuple(entry.origin for entry in self._entries)

    @property
    def in_flight(self) -> tuple[int, int]:
        """Requests in flight now: in all, and on the unauthenticated routes."""
        return self._gate.total, self._gate.unauthenticated

    def reload(self, origins: Iterable[str]) -> None:
        """``SIGHUP`` with ``admin.origins`` changed: the new list takes effect at once, and the
        sessions of an origin no longer listed end (B.3)."""
        self._entries = origin_entries(origins)
        for ended in self.sessions.end_origins(self.origins):
            logs.event("portal_session_ended", session=ended.session.fingerprint, why=ended.why)

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
        if route.cap:
            raw = await self._read_body(exchange, route.cap)
            parsed = raw if isinstance(raw, Refusal) else parse_body(route, raw)
            if isinstance(parsed, Refusal):
                await self._refuse(exchange, parsed)
                return
            body = parsed
        if session is not None:
            session = self.sessions.touch(session.id, self._wall()) or session
        query = exchange.scope.get("query_string", b"")
        answer = await handler(Call(admitted.entry, route, admitted.params, query, body, session))
        if isinstance(answer, Refusal):
            status, reason = answer.status, answer.reason
            await self._send_json(exchange, status, answer.body(), _refusal_headers(answer))
        else:
            status, reason = answer.status, None
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


def _refusal_headers(refused: Refusal) -> tuple[Header, ...]:
    headers: list[Header] = []
    if refused.reason in RETRY_AFTER:
        headers.append((b"retry-after", RETRY_AFTER[refused.reason]))
    if refused.reason == "method":
        headers.append((b"allow", ALLOW))
    return tuple(headers)
