"""A stateful fake OAuth authorization server and resource server (design G.1).

Unit tests reach it in process over ``httpx.ASGITransport``; acceptance tests serve it over TLS.
It keeps grants the way real providers do: refresh tokens rotate (or don't), a reused old token
revokes the whole family, codes are single use and bound to the PKCE challenge and the redirect
URI, and every client authentication method is enforced. Knobs make it misbehave the ways real
providers do.

Every value it issues is a deterministic fake (``<prefix>-at-1``, ``<prefix>-rt-2``), so tests can
look for them in logs and responses.

For the portal's OAuth callback (M5 design O.1), ``answer`` sets how ``/authorize`` answers an
approval: ``code`` (the default), ``error`` (``access_denied`` with ``error_description``, which
a test may make hostile), ``wrong_iss``, ``two_codes``, ``no_code`` or ``fragment`` (the answer
after a ``#``). Approving the same authorization URL again issues a second code for it, as an
attacker who consents there with their own account would get; :attr:`FakeAuthServer.exchanges`
counts the codes presented at ``/token``, so a test can show the callback exchanged nothing.

With ``consent`` on (register D-183), ``/authorize`` first serves an Approve page whose button
posts the request back, and the answer is a 302 from that post, so the return navigation starts
on the provider's own page, as a real provider's consent click does. It is off by default.

For onboarding by URL (M7 design O.1), a fake with an ``issuer`` publishes RFC 8414 metadata and
OIDC configuration at the well-known paths for that issuer, with or without a path
(``metadata_forms`` picks which candidates answer), and takes RFC 7591 registrations at
``/register`` as ``registration`` says (``open``, ``none``, ``confidential_only``, ``cimd_only``,
``needs_initial_token``). A registered client then works at ``/authorize`` and ``/token`` like
the configured one. ``iss_supported`` advertises RFC 9207's ``iss`` and puts it on error answers
too. :class:`AuthSwitch` turns on each hostile answer the vault must refuse, and the ``stall`` and
``trickle`` switches (FM-5, FM-6). :attr:`FakeAuthServer.seen` records every request, so a test
can show what reached the fake before a refusal.
"""

from __future__ import annotations

import asyncio
import base64
import enum
import hashlib
import html
import json
import threading
import time
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from typing import Any, Final, Literal
from urllib.parse import parse_qsl, unquote_plus, urlencode, urlsplit

import httpx
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import (
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response,
    StreamingResponse,
)
from starlette.routing import Mount, Route
from starlette.types import ASGIApp, Message, Receive, Scope, Send

Clock = Callable[[], float]
ClientAuth = Literal["basic", "post", "none"]
ErrorShape = Literal["rfc", "status_403", "status_200", "ok_false", "html", "form", "echo"]
Answer = Literal["code", "error", "wrong_iss", "two_codes", "no_code", "fragment"]
Registration = Literal["open", "none", "confidential_only", "cimd_only", "needs_initial_token"]
# The AS metadata candidates (M7 design D.3): RFC 8414's path insertion, OIDC Discovery's
# insertion, and OIDC's older appended form.
MetadataForm = Literal["oauth", "oidc", "oidc_appended"]


class _Missing(enum.Enum):
    MISSING = enum.auto()


MISSING: Final = _Missing.MISSING
"""A knob set to this leaves the field out of the token response."""

DEFAULT_REDIRECT: Final = "http://127.0.0.1/callback"
OTHER_ISSUER: Final = "https://other-issuer.example"
LATCH_TIMEOUT: Final = 30.0
INSUFFICIENT_SCOPE_PATH: Final = "/forbidden"

AS_WELL_KNOWN: Final = "/.well-known/oauth-authorization-server"
OIDC_WELL_KNOWN: Final = "/.well-known/openid-configuration"
# The registration modes that publish a registration endpoint.
REGISTERS: Final = frozenset({"open", "confidential_only", "needs_initial_token"})
AUTH_BY_METHOD: Final[dict[str, ClientAuth]] = {
    "none": "none",
    "client_secret_basic": "basic",
    "client_secret_post": "post",
}
# A stalled answer waits this long; the client's deadline, or the server's shutdown, ends it.
STALL_SECONDS: Final = 3600.0
# A trickled answer sends one byte, then waits this long.
TRICKLE_INTERVAL: Final = 0.5
# Over the vault's 64 KiB metadata cap (M7 design B.5).
OVERSIZED_PADDING: Final = 70 * 1024
# Hostile values. Hidden characters are written as escapes (the source must not contain them).
BIDI_OVERRIDE: Final = "\u202e"
LOOPBACK_ENDPOINT: Final = "https://127.0.0.1/token"
SINGLE_LABEL_ENDPOINT: Final = "https://intranet/token"
METADATA_ELSEWHERE: Final = "https://attacker.example/metadata"
CHANGED_REDIRECT: Final = "https://attacker.example/callback"
INJECTED_DESCRIPTION: Final = f"Bad metadata\r\nX-Injected: 1 {BIDI_OVERRIDE}<b>Approve</b>"
# Planted in a registration answer for the leak sweep to look for (M7 design O.5).
REGISTRATION_ACCESS_TOKEN: Final = "fake-registration-access-token-0001"
REGISTRATION_CLIENT_PATH: Final = "/register/fake-registration-client-0001"


class AuthSwitch(enum.StrEnum):
    """One hostile or slow answer for onboarding by URL (M7 design O.1)."""

    # metadata
    WRONG_ISSUER = "wrong_issuer"
    ENDPOINT_LOOPBACK = "endpoint_loopback"
    ENDPOINT_SINGLE_LABEL = "endpoint_single_label"
    PKCE_ABSENT = "pkce_absent"
    PKCE_PLAIN = "pkce_plain"
    METADATA_OVERSIZED = "metadata_oversized"
    METADATA_NOT_JSON = "metadata_not_json"
    METADATA_ARRAY = "metadata_array"
    METADATA_REDIRECT = "metadata_redirect"
    DPOP_ALGS = "dpop_algs"
    # registration answers
    DCR_REDIRECT_CHANGED = "dcr_redirect_changed"
    DCR_PRIVATE_KEY_JWT = "dcr_private_key_jwt"
    DCR_SECRET_FOR_NONE = "dcr_secret_for_none"
    DCR_CLIENT_ID_SPACE = "dcr_client_id_space"
    DCR_CLIENT_ID_BIDI = "dcr_client_id_bidi"
    DCR_ACCESS_TOKEN = "dcr_access_token"
    DCR_ERROR_INJECTED = "dcr_error_injected"
    # authorization answers (RFC 9207)
    ISS_MISSING = "iss_missing"
    ISS_WRONG_ON_ERROR = "iss_wrong_on_error"
    # time (FM-5, FM-6, FM-9)
    STALL = "stall"
    TRICKLE = "trickle"
    STALL_REGISTER = "stall_register"


CONSENT_PAGE: Final = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Fake provider</title></head>
<body><p>The fake provider asks: let <code>{client}</code> sign in?</p>
<form method="post" action="{action}">{fields}<button type="submit">Approve</button></form>
</body></html>
"""


class DroppedConnection(httpx.ReadError):
    """Raised by the app after it processed a request (``drop_after_processing``).

    Over ``ASGITransport`` it reaches the client as a read error: the request was handled, and
    the answer was lost.
    """


class _Dropped(Response):
    """Sends the status line and headers of ``response``, then drops the connection.

    Raising after the response started is how an ASGI app breaks a connection: a real server
    (uvicorn) closes it with the body missing, so the client gets a protocol error. Over
    ``ASGITransport`` the exception itself reaches the client.
    """

    def __init__(self, response: Response) -> None:
        self._response = response

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": self._response.status_code,
                "headers": self._response.raw_headers,
            }
        )
        raise DroppedConnection("connection reset after the token was issued")


@dataclass
class TokenCall:
    """One request to ``/token``, as the server saw it."""

    grant_type: str | None
    params: dict[str, str]
    headers: dict[str, str]
    auth: str
    status: int = 0

    @property
    def refresh_token(self) -> str | None:
        return self.params.get("refresh_token")


@dataclass
class _Family:
    """One grant: the refresh tokens it has had, and what it allows."""

    scopes: tuple[str, ...]
    consented_at: float
    refresh_token: str | None
    retired: list[str] = field(default_factory=list)
    replaced_at: float = 0.0
    last_successor: dict[str, Any] | None = None
    revoked: bool = False


@dataclass
class _Code:
    client_id: str
    redirect_uri: str
    challenge: str
    scopes: tuple[str, ...]
    offline: bool
    used: bool = False


@dataclass
class _Failure:
    remaining: int
    status: int
    retry_after: str | None


@dataclass(frozen=True)
class _Client:
    """A client the fake accepts: the configured one, or one ``/register`` issued."""

    client_id: str
    secret: str | None
    auth: ClientAuth
    redirects: tuple[str, ...]


@dataclass
class Seen:
    """One request to the fake, any path, as it arrived."""

    method: str
    path: str
    query: str
    headers: dict[str, str]
    body: bytes


class _Record:
    """Records every request in ``fake.seen`` before the routes see it, then replays the body."""

    def __init__(self, app: ASGIApp, fake: FakeAuthServer) -> None:
        self.app = app
        self.fake = fake

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        chunks: list[bytes] = []
        while True:
            message = await receive()
            if message["type"] != "http.request":
                break
            chunks.append(message.get("body", b""))
            if not message.get("more_body", False):
                break
        body = b"".join(chunks)
        headers = {
            bytes(k).decode("latin-1").lower(): bytes(v).decode("latin-1")
            for k, v in scope["headers"]
        }
        query = bytes(scope["query_string"]).decode("latin-1")
        self.fake.seen.append(Seen(scope["method"], scope["path"], query, headers, body))
        replayed = False

        async def replay() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.app(scope, replay, send)


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


class FakeAuthServer:
    """``GET /authorize``, ``POST /token`` and ``POST /revoke``; with ``consent``, ``POST
    /authorize``; and for onboarding, ``POST /register`` and the metadata's well-known paths.

    The knobs are plain attributes, so a test can change them between calls.
    """

    def __init__(
        self,
        clock: Clock = time.time,
        *,
        client_id: str,
        client_secret: str | None = None,
        auth: ClientAuth = "basic",
        rotate: bool = False,
        grace_seconds: float = 0.0,
        omit_refresh_every: int = 0,
        grant_lifetime: float | None = None,
        scopes: tuple[str, ...] = (),
        granted_scopes: tuple[str, ...] | None = None,
        expires_in: object = 3600,
        token_type: object = "Bearer",  # noqa: S107
        error_shape: ErrorShape = "rfc",
        require_offline: bool = False,
        registered_redirect: str = DEFAULT_REDIRECT,
        issuer: str | None = None,
        prefix: str = "fake",
        iss_supported: bool = False,
        registration: Registration = "open",
        consent: bool = False,
    ) -> None:
        self.clock = clock
        self.client_id = client_id
        self.client_secret = client_secret
        self.auth = auth
        self.rotate = rotate
        self.grace_seconds = grace_seconds
        self.omit_refresh_every = omit_refresh_every
        self.grant_lifetime = grant_lifetime
        self.scopes = scopes
        self.granted_scopes = granted_scopes
        self.expires_in = expires_in
        self.token_type = token_type
        self.error_shape: ErrorShape = error_shape
        self.require_offline = require_offline
        self.registered_redirect = registered_redirect
        self.issuer = issuer
        self.prefix = prefix
        # How /authorize answers an approval (the callback's cases), and whether a consent page
        # comes first (D-183).
        self.answer: Answer = "code"
        self.error_description = "The user denied the request"
        self.consent = consent
        # Discovery and registration (M7 design O.1). Metadata is published only with an issuer;
        # its endpoints are at the issuer's origin unless endpoint_base names another.
        self.iss_supported = iss_supported
        self.registration: Registration = registration
        self.metadata_forms: tuple[MetadataForm, ...] = ("oauth", "oidc")
        self.endpoint_base: str | None = None
        self.switches: set[AuthSwitch] = set()
        self.trickle_interval = TRICKLE_INTERVAL
        self.registered: dict[str, _Client] = {}
        # What a registered secret's client_secret_expires_at says (0: never).
        self.secret_expires_at = 0
        self.seen: list[Seen] = []
        # Hostile and flaky behavior.
        self.drop_after_processing = 0
        self.redirect_token: str | None = None
        self.huge_body = False
        self.crlf_token = False
        self.bad_refresh_token_shape = False
        self.delay = 0.0
        self.gate: asyncio.Event | None = None
        # Like ``gate``, for a test on another thread than the server's loop.
        self.latch: threading.Event | None = None
        self.calls: list[TokenCall] = []
        self.revocations: list[str] = []
        # /revoke (M7 design D.9): a status other than 200 revokes nothing (with
        # ``revoke_location`` as its Location), and with the gate set the answer waits for it.
        self.revoke_status = 200
        self.revoke_location: str | None = None
        self.revoke_gate: asyncio.Event | None = None
        self._failures: list[_Failure] = []
        self._force_rotation = 0
        self._rotations = 0
        self._counter = 0
        self._families: list[_Family] = []
        self._codes: dict[str, _Code] = {}
        self._access: dict[str, tuple[_Family | None, float]] = {}
        self._arrived = asyncio.Event()

    # --- test controls -------------------------------------------------------------------------

    def app(self) -> Starlette:
        endpoints = [
            Route("/authorize", self._authorize, methods=["GET", "POST"]),
            Route("/token", self._token, methods=["POST"]),
            Route("/revoke", self._revoke, methods=["POST"]),
            Route("/register", self._register, methods=["POST"]),
        ]
        # An endpoint_base with a path on this server serves the endpoints under it too.
        prefix = urlsplit(self.endpoint_base).path.rstrip("/") if self.endpoint_base else ""
        return Starlette(
            routes=[
                *endpoints,
                *([Mount(prefix, routes=endpoints)] if prefix else []),
                Route("/.well-known/{rest:path}", self._metadata, methods=["GET"]),
                Route("/{prefix:path}" + OIDC_WELL_KNOWN, self._metadata, methods=["GET"]),
            ],
            middleware=[Middleware(_Record, fake=self)],
        )

    def issue_grant(self, scopes: tuple[str, ...] | None = None) -> str:
        """A refresh token for a new grant, as if the operator had consented just now."""
        family = _Family(
            scopes=self.scopes if scopes is None else scopes,
            consented_at=self.clock(),
            refresh_token=self._new("rt"),
        )
        self._families.append(family)
        assert family.refresh_token is not None
        return family.refresh_token

    def fail_next(self, count: int, status: int = 503, retry_after: str | None = None) -> None:
        """Answer the next ``count`` token calls with ``status``, before looking at them."""
        self._failures.append(_Failure(count, status, retry_after))

    def rotate_next(self, count: int = 1) -> None:
        """Rotate on the next refreshes even when ``rotate`` is off."""
        self._force_rotation += count

    def revoke(self) -> None:
        """Revoke every grant, as the user removing the app's access does."""
        for family in self._families:
            family.revoked = True

    def drop_access_tokens(self) -> None:
        """Forget every access token issued so far; refresh tokens keep working.

        Providers do this on a password change or a key rotation: the resource server answers
        401 to a token that hasn't expired yet.
        """
        self._access.clear()

    def hold(self) -> asyncio.Event:
        """Make token calls wait until the returned event is set."""
        self.gate = asyncio.Event()
        self._arrived = asyncio.Event()
        return self.gate

    async def arrived(self) -> None:
        """Wait until a held token call has arrived."""
        await self._arrived.wait()

    def access_ok(self, token: str) -> bool:
        """The access token was issued here, isn't revoked and hasn't expired."""
        found = self._access.get(token)
        if found is None:
            return False
        family, expires_at = found
        if family is not None and family.revoked:
            return False
        return self.clock() < expires_at

    def active_refresh_token(self) -> str | None:
        """The current refresh token of the newest live grant."""
        for family in reversed(self._families):
            if not family.revoked:
                return family.refresh_token
        return None

    @property
    def refresh_calls(self) -> list[TokenCall]:
        return [c for c in self.calls if c.grant_type == "refresh_token"]

    @property
    def exchanges(self) -> int:
        """How many codes were presented at ``/token``."""
        return sum(1 for c in self.calls if c.grant_type == "authorization_code")

    @property
    def registrations(self) -> list[Seen]:
        """The registration requests, as they arrived."""
        return [s for s in self.seen if (s.method, s.path) == ("POST", "/register")]

    def metadata(self) -> dict[str, Any]:
        """The RFC 8414 document the metadata paths serve, as the switches shape it."""
        if self.issuer is None:
            raise ValueError("the fake has no issuer, so it publishes no metadata")
        on = self.switches
        base = self.endpoint_base or _origin(self.issuer)
        methods = self._auth_methods()
        document: dict[str, Any] = {
            "issuer": OTHER_ISSUER if AuthSwitch.WRONG_ISSUER in on else self.issuer,
            "authorization_endpoint": f"{base}/authorize",
            "token_endpoint": f"{base}/token",
            "revocation_endpoint": f"{base}/revoke",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": methods,
            "revocation_endpoint_auth_methods_supported": methods,
            "authorization_response_iss_parameter_supported": self.iss_supported,
        }
        if self.registration in REGISTERS:
            document["registration_endpoint"] = f"{base}/register"
        if self.registration == "cimd_only":
            document["client_id_metadata_document_supported"] = True
        if self.scopes:
            document["scopes_supported"] = list(self.scopes)
        if AuthSwitch.ENDPOINT_LOOPBACK in on:
            document["token_endpoint"] = LOOPBACK_ENDPOINT
        if AuthSwitch.ENDPOINT_SINGLE_LABEL in on:
            document["token_endpoint"] = SINGLE_LABEL_ENDPOINT
        if AuthSwitch.PKCE_ABSENT in on:
            del document["code_challenge_methods_supported"]
        elif AuthSwitch.PKCE_PLAIN in on:
            document["code_challenge_methods_supported"] = ["plain"]
        if AuthSwitch.DPOP_ALGS in on:
            document["dpop_signing_alg_values_supported"] = ["ES256"]
        return document

    def metadata_paths(self) -> list[str]:
        """Where the metadata answers for ``issuer``: one path per form in ``metadata_forms``."""
        if self.issuer is None:
            return []
        path = urlsplit(self.issuer).path.rstrip("/")
        where: dict[MetadataForm, str] = {
            "oauth": f"{AS_WELL_KNOWN}{path}",
            "oidc": f"{OIDC_WELL_KNOWN}{path}",
            "oidc_appended": f"{path}{OIDC_WELL_KNOWN}",
        }
        return [where[form] for form in self.metadata_forms]

    # --- /authorize ----------------------------------------------------------------------------

    async def _authorize(self, request: Request) -> Response:
        # With consent, the Approve page posts the request back; the answer comes from the post.
        if request.method == "POST":
            if not self.consent:
                return Response("method not allowed", status_code=405, headers={"allow": "GET"})
            params = await self._params(request)
        else:
            params = dict(request.query_params)
        redirect_uri = params.get("redirect_uri", "")
        client = self._client(params.get("client_id"))
        if client is None:
            return Response("unknown client", status_code=400)
        if not any(self._redirect_allowed(r, redirect_uri) for r in client.redirects):
            return Response("redirect_uri isn't registered", status_code=400)
        state = params.get("state")
        problems = [
            params.get("response_type") != "code",
            params.get("code_challenge_method") != "S256",
            not params.get("code_challenge"),
            not state,
        ]
        if any(problems):
            back = [("error", "invalid_request")]
            if state:
                back.append(("state", state))
            back += self._iss(error=True)
            return RedirectResponse(f"{redirect_uri}?{urlencode(back)}", status_code=302)
        if self.consent and request.method == "GET":
            return self._consent_page(request.url.path, params)
        if self.answer == "error":
            back = [
                ("error", "access_denied"),
                ("error_description", self.error_description),
                ("state", state or ""),
                *self._iss(error=True),
            ]
            return RedirectResponse(f"{redirect_uri}?{urlencode(back)}", status_code=302)
        codes = [self._code(params, redirect_uri)]
        if self.answer == "two_codes":
            codes.append(self._code(params, redirect_uri))
        answer: list[tuple[str, str]] = []
        if self.answer != "no_code":
            answer += [("code", code) for code in codes]
        answer.append(("state", state or ""))
        answer += self._iss(error=False)
        separator = "#" if self.answer == "fragment" else "?"
        return RedirectResponse(f"{redirect_uri}{separator}{urlencode(answer)}", status_code=302)

    def _iss(self, *, error: bool) -> list[tuple[str, str]]:
        """RFC 9207's ``iss`` for one answer: on a code answer whenever there is an issuer, and
        on an error answer only when it is advertised (``iss_supported``)."""
        on = self.switches
        if AuthSwitch.ISS_MISSING in on:
            return []
        if error:
            if AuthSwitch.ISS_WRONG_ON_ERROR in on:
                return [("iss", OTHER_ISSUER)]
            if not self.iss_supported or self.issuer is None:
                return []
            return [("iss", self.issuer)]
        if self.answer == "wrong_iss":
            return [("iss", OTHER_ISSUER)]
        return [] if self.issuer is None else [("iss", self.issuer)]

    @staticmethod
    def _consent_page(action: str, params: dict[str, str]) -> Response:
        """The Approve page: one button that posts the authorization request back."""
        fields = "".join(
            f'<input type="hidden" name="{html.escape(name)}" value="{html.escape(value)}">'
            for name, value in params.items()
        )
        page = CONSENT_PAGE.format(
            client=html.escape(params.get("client_id", "")),
            action=html.escape(action),
            fields=fields,
        )
        return HTMLResponse(page, headers={"cache-control": "no-store"})

    def _code(self, params: dict[str, str], redirect_uri: str) -> str:
        """A new code for the approved authorization request."""
        offline = params.get("access_type") == "offline" and params.get("prompt") == "consent"
        scope = params.get("scope")
        code = self._new("code")
        self._codes[code] = _Code(
            client_id=params["client_id"],
            redirect_uri=redirect_uri,
            challenge=params["code_challenge"],
            scopes=tuple(scope.split(" ")) if scope else self.scopes,
            offline=offline,
        )
        return code

    def _client(self, client_id: str | None) -> _Client | None:
        if client_id is None:
            return None
        if client_id == self.client_id:
            return _Client(
                self.client_id, self.client_secret, self.auth, (self.registered_redirect,)
            )
        return self.registered.get(client_id)

    @staticmethod
    def _redirect_allowed(registered_redirect: str, redirect_uri: str) -> bool:
        if redirect_uri == registered_redirect:
            return True
        # RFC 8252 section 7.3: a loopback redirect registered without a port takes any port.
        registered, given = urlsplit(registered_redirect), urlsplit(redirect_uri)
        try:
            given_port = given.port
        except ValueError:
            return False
        return (
            registered.hostname in ("127.0.0.1", "::1")
            and registered.port is None
            and given_port is not None
            and (registered.scheme, registered.hostname, registered.path)
            == (given.scheme, given.hostname, given.path)
            and not given.query
            and not given.fragment
        )

    # --- /token --------------------------------------------------------------------------------

    async def _token(self, request: Request) -> Response:
        params = await self._params(request)
        headers = {k.lower(): v for k, v in request.headers.items()}
        call = TokenCall(params.get("grant_type"), params, headers, self._auth_method(headers))
        self.calls.append(call)
        self._arrived.set()
        if self.gate is not None:
            await self.gate.wait()
        if self.latch is not None:
            await asyncio.to_thread(self.latch.wait, LATCH_TIMEOUT)
        if self.delay:
            await asyncio.sleep(self.delay)
        response = self._answer(call, params, headers)
        call.status = response.status_code
        if self.drop_after_processing:
            self.drop_after_processing -= 1
            return _Dropped(response)
        return response

    def _answer(self, call: TokenCall, params: dict[str, str], headers: dict[str, str]) -> Response:
        if self._failures:
            failure = self._failures[0]
            failure.remaining -= 1
            if failure.remaining <= 0:
                self._failures.pop(0)
            extra = {"retry-after": failure.retry_after} if failure.retry_after else None
            if failure.status == 429:
                return JSONResponse({"error": "rate_limited"}, status_code=429, headers=extra)
            return Response("unavailable", status_code=failure.status, headers=extra)
        if self.redirect_token is not None:
            return Response(status_code=307, headers={"location": self.redirect_token})
        client_id = self._authenticated(call.auth, headers, params)
        if client_id is None:
            extra = {"www-authenticate": 'Basic realm="fake"'} if call.auth == "basic" else None
            return JSONResponse({"error": "invalid_client"}, status_code=401, headers=extra)
        if call.grant_type == "refresh_token":
            return self._refresh(params)
        if call.grant_type == "authorization_code":
            return self._exchange(params, client_id)
        if call.grant_type == "client_credentials":
            return self._success(self._mint(None), None)
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)

    def _refresh(self, params: dict[str, str]) -> Response:
        presented = params.get("refresh_token", "")
        now = self.clock()
        for family in self._families:
            if presented == family.refresh_token:
                break
            if presented in family.retired:
                in_grace = (
                    self.grace_seconds > 0
                    and presented == family.retired[-1]
                    and now - family.replaced_at <= self.grace_seconds
                    and family.last_successor is not None
                    and not family.revoked
                )
                if in_grace:
                    return self._success(self._mint(family), family.refresh_token)
                # Strict reuse detection: the whole family dies.
                family.revoked = True
                return self._grant_error("Refresh token revoked", presented)
        else:
            return self._grant_error("Unknown refresh token", presented)
        if family.revoked:
            return self._grant_error("Token has been expired or revoked.", presented)
        if self.grant_lifetime is not None and now - family.consented_at >= self.grant_lifetime:
            return self._grant_error("The grant has expired", presented)
        if self.granted_scopes is not None:
            family.scopes = self.granted_scopes
        successor = None
        if self._rotates_now():
            successor = self._new("rt")
            if self.bad_refresh_token_shape:
                successor = f" {successor}"
            family.retired.append(presented)
            family.refresh_token = successor
            family.replaced_at = now
            family.last_successor = {"refresh_token": successor}
        return self._success(self._mint(family), successor)

    def _rotates_now(self) -> bool:
        if self._force_rotation:
            self._force_rotation -= 1
            return True
        if not self.rotate and self.token_type != "DPoP":
            return False
        self._rotations += 1
        return not (self.omit_refresh_every and self._rotations % self.omit_refresh_every == 0)

    def _exchange(self, params: dict[str, str], client_id: str) -> Response:
        # The "echo" error shape repeats the presented code, as a careless provider might.
        presented = params.get("code", "")
        code = self._codes.get(presented)
        if code is None or code.used:
            return self._grant_error("Invalid authorization code", presented)
        code.used = True
        if code.client_id != client_id:
            return self._grant_error("The code was issued to another client", presented)
        if params.get("redirect_uri") != code.redirect_uri:
            return self._grant_error("redirect_uri doesn't match", presented)
        verifier = params.get("code_verifier", "")
        digest = hashlib.sha256(verifier.encode("ascii", "replace")).digest()
        challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        if challenge != code.challenge:
            return self._grant_error("PKCE verification failed", verifier)
        family = _Family(
            scopes=code.scopes if self.granted_scopes is None else self.granted_scopes,
            consented_at=self.clock(),
            refresh_token=None,
        )
        if code.offline or not self.require_offline:
            family.refresh_token = self._new("rt")
        self._families.append(family)
        return self._success(self._mint(family), family.refresh_token)

    def _mint(self, family: _Family | None) -> str:
        token = self._new("at")
        if self.crlf_token:
            token += "\r\nx-injected: 1"
        lifetime = self.expires_in if type(self.expires_in) is int else 3600
        self._access[token] = (family, self.clock() + max(int(lifetime), 1))
        return token

    def _success(self, access_token: str, refresh_token: str | None) -> Response:
        body: dict[str, Any] = {"access_token": access_token}
        if self.token_type is not MISSING:
            body["token_type"] = self.token_type
        if self.expires_in is not MISSING:
            body["expires_in"] = self.expires_in
        if refresh_token is not None:
            body["refresh_token"] = refresh_token
        granted = self._access[access_token][0]
        if granted is not None:
            body["scope"] = " ".join(granted.scopes)
        if self.huge_body:
            body["padding"] = "x" * (70 * 1024)
        return JSONResponse(body)

    def _grant_error(self, description: str, presented: str | None) -> Response:
        error = "invalid_grant"
        if self.error_shape == "echo" and presented is not None:
            description = f"{description}: {presented}"
        body = {"error": error, "error_description": description}
        shape = self.error_shape
        if shape == "status_403":
            return JSONResponse(body, status_code=403)
        if shape == "status_200":
            return JSONResponse(body, status_code=200)
        if shape == "ok_false":
            return JSONResponse({"ok": False, "error": error}, status_code=200)
        if shape == "html":
            return Response(f"<html><body>{error}</body></html>", 400, media_type="text/html")
        if shape == "form":
            return Response(urlencode(body), 400, media_type="application/x-www-form-urlencoded")
        return JSONResponse(body, status_code=400)

    # --- /revoke -------------------------------------------------------------------------------

    async def _revoke(self, request: Request) -> Response:
        params = await self._params(request)
        token = params.get("token", "")
        self.revocations.append(token)
        if self.revoke_gate is not None:
            await self.revoke_gate.wait()
        if self.revoke_status != 200:
            moved = {} if self.revoke_location is None else {"location": self.revoke_location}
            return Response(status_code=self.revoke_status, headers=moved)
        for family in self._families:
            if token == family.refresh_token or token in family.retired:
                family.revoked = True
        found = self._access.get(token)
        if found is not None and found[0] is not None:
            found[0].revoked = True
        return Response(status_code=200)

    # --- helpers -------------------------------------------------------------------------------

    def _new(self, kind: str) -> str:
        self._counter += 1
        return f"{self.prefix}-{kind}-{self._counter}"

    @staticmethod
    async def _params(request: Request) -> dict[str, str]:
        body = await request.body()
        if request.headers.get("content-type", "").startswith("application/json"):
            data = json.loads(body)
            return {k: v if isinstance(v, str) else json.dumps(v) for k, v in data.items()}
        return dict(parse_qsl(body.decode("ascii"), keep_blank_values=True))

    @staticmethod
    def _auth_method(headers: dict[str, str]) -> str:
        if headers.get("authorization", "").lower().startswith("basic "):
            return "basic"
        return "header" if "authorization" in headers else "body"

    def _authenticated(
        self, method: str, headers: dict[str, str], params: dict[str, str]
    ) -> str | None:
        """The client the request authenticates as, by that client's own method, or None."""
        if method == "basic":
            try:
                decoded = base64.b64decode(headers["authorization"][6:], validate=True).decode()
            except ValueError:
                return None
            user, _, password = decoded.partition(":")
            client = self._client(unquote_plus(user))
            if client is None or client.auth != "basic" or "client_secret" in params:
                return None
            return client.client_id if unquote_plus(password) == client.secret else None
        if method != "body":
            return None
        client = self._client(params.get("client_id"))
        if client is None or client.auth == "basic":
            return None
        if client.auth == "post":
            ok = params.get("client_secret") == client.secret
        else:
            ok = "client_secret" not in params
        return client.client_id if ok else None

    def _auth_methods(self) -> list[str]:
        """``token_endpoint_auth_methods_supported``: no public clients if confidential only."""
        methods = list(AUTH_BY_METHOD)
        if self.registration == "confidential_only":
            methods.remove("none")
        return methods

    # --- metadata and /register ----------------------------------------------------------------

    async def _metadata(self, request: Request) -> Response:
        if request.url.path not in self.metadata_paths():
            return Response("not found", status_code=404)
        on = self.switches
        if AuthSwitch.STALL in on:
            await asyncio.sleep(STALL_SECONDS)
        if AuthSwitch.METADATA_REDIRECT in on:
            return RedirectResponse(METADATA_ELSEWHERE, status_code=302)
        if AuthSwitch.METADATA_NOT_JSON in on:
            return Response("<html><body>Sign in</body></html>", media_type="application/json")
        document: Any = self.metadata()
        if AuthSwitch.METADATA_OVERSIZED in on:
            document["padding"] = "x" * OVERSIZED_PADDING
        if AuthSwitch.METADATA_ARRAY in on:
            document = [document]
        body = json.dumps(document).encode()
        if AuthSwitch.TRICKLE in on:
            return StreamingResponse(self._trickle(body), media_type="application/json")
        return Response(body, media_type="application/json")

    async def _trickle(self, body: bytes) -> AsyncIterator[bytes]:
        for index in range(len(body)):
            yield body[index : index + 1]
            await asyncio.sleep(self.trickle_interval)

    async def _register(self, request: Request) -> Response:
        """RFC 7591 registration, as ``registration`` and the switches say."""
        if self.registration not in REGISTERS:
            return Response("not found", status_code=404)
        on = self.switches
        if AuthSwitch.STALL_REGISTER in on:
            await asyncio.sleep(STALL_SECONDS)
        bearer = request.headers.get("authorization", "").lower().startswith("bearer ")
        if self.registration == "needs_initial_token" and not bearer:
            return JSONResponse(
                {"error": "invalid_token"},
                status_code=401,
                headers={"www-authenticate": 'Bearer error="invalid_token"'},
            )
        if AuthSwitch.DCR_ERROR_INJECTED in on:
            return self._dcr_error("invalid_client_metadata", INJECTED_DESCRIPTION)
        try:
            asked = json.loads(await request.body())
        except ValueError:
            asked = None
        if not isinstance(asked, dict):
            return self._dcr_error("invalid_client_metadata", "the body isn't a JSON object")
        redirects = asked.get("redirect_uris")
        if (
            not isinstance(redirects, list)
            or not redirects
            or not all(isinstance(r, str) for r in redirects)
        ):
            return self._dcr_error("invalid_redirect_uri", "redirect_uris must list addresses")
        method = asked.get("token_endpoint_auth_method", "client_secret_basic")
        if not isinstance(method, str) or method not in self._auth_methods():
            return self._dcr_error("invalid_client_metadata", "that auth method isn't supported")
        client_id = self._new("client")
        if AuthSwitch.DCR_CLIENT_ID_SPACE in on:
            client_id = client_id.replace("-client-", "-client ")
        if AuthSwitch.DCR_CLIENT_ID_BIDI in on:
            client_id += BIDI_OVERRIDE
        secret = None if method == "none" else self._new("secret")
        self.registered[client_id] = _Client(
            client_id, secret, AUTH_BY_METHOD[method], tuple(redirects)
        )
        answer: dict[str, Any] = {
            "client_id": client_id,
            "client_id_issued_at": int(self.clock()),
            "redirect_uris": redirects,
            "token_endpoint_auth_method": method,
            "grant_types": asked.get("grant_types", ["authorization_code"]),
            "response_types": asked.get("response_types", ["code"]),
        }
        for member in ("client_name", "scope", "application_type"):
            if member in asked:
                answer[member] = asked[member]
        if secret is None and AuthSwitch.DCR_SECRET_FOR_NONE in on:
            secret = self._new("secret")
        if secret is not None:
            answer["client_secret"] = secret
            answer["client_secret_expires_at"] = self.secret_expires_at
        if AuthSwitch.DCR_REDIRECT_CHANGED in on:
            answer["redirect_uris"] = [CHANGED_REDIRECT]
        if AuthSwitch.DCR_PRIVATE_KEY_JWT in on:
            answer["token_endpoint_auth_method"] = "private_key_jwt"
        if AuthSwitch.DCR_ACCESS_TOKEN in on:
            answer["registration_access_token"] = REGISTRATION_ACCESS_TOKEN
            answer["registration_client_uri"] = (
                str(request.base_url).rstrip("/") + REGISTRATION_CLIENT_PATH
            )
        return JSONResponse(answer, status_code=201)

    @staticmethod
    def _dcr_error(error: str, description: str) -> Response:
        return JSONResponse({"error": error, "error_description": description}, status_code=400)


class FakeResourceServer:
    """An API that accepts the fake authorization server's live access tokens only."""

    def __init__(self, auth_server: FakeAuthServer) -> None:
        self.auth_server = auth_server
        self.always_401 = False
        self.echo_token = False
        self.received: list[tuple[str, str, dict[str, str]]] = []

    def app(self) -> Starlette:
        return Starlette(
            routes=[
                Route(
                    "/{path:path}",
                    self._handle,
                    methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
                )
            ]
        )

    async def _handle(self, request: Request) -> Response:
        headers = {k.lower(): v for k, v in request.headers.items()}
        self.received.append((request.method, request.url.path, headers))
        scheme, _, token = headers.get("authorization", "").partition(" ")
        if self.always_401 or scheme.lower() != "bearer" or not self.auth_server.access_ok(token):
            return JSONResponse(
                {"error": "invalid_token"},
                status_code=401,
                headers={"www-authenticate": 'Bearer error="invalid_token"'},
            )
        if request.url.path == INSUFFICIENT_SCOPE_PATH:
            return JSONResponse(
                {"error": "insufficient_scope"},
                status_code=403,
                headers={"www-authenticate": 'Bearer error="insufficient_scope"'},
            )
        body: dict[str, Any] = {"ok": True, "path": request.url.path}
        if self.echo_token:
            body["token"] = token
        return JSONResponse(body)


def google_style(clock: Clock = time.time, **knobs: Any) -> FakeAuthServer:
    """Confidential client with ``client_secret_post``; refresh tokens don't rotate.

    A refresh token is issued only with ``access_type=offline`` and ``prompt=consent``.
    """
    settings: dict[str, Any] = {
        "client_id": "000000000000-example.apps.googleusercontent.com",
        "client_secret": "fake-google-client-secret",
        "auth": "post",
        "rotate": False,
        "require_offline": True,
        "scopes": ("https://www.googleapis.com/auth/calendar.readonly",),
        "prefix": "fake-google",
    }
    settings.update(knobs)
    return FakeAuthServer(clock, **settings)


def spotify_style(clock: Clock = time.time, **knobs: Any) -> FakeAuthServer:
    """Public client with PKCE; refresh tokens rotate, and the grant ends 180 days after consent."""
    settings: dict[str, Any] = {
        "client_id": "0123456789abcdef0123456789abcdef",
        "auth": "none",
        "rotate": True,
        "grant_lifetime": 180 * 86400.0,
        "scopes": ("user-read-currently-playing", "user-top-read"),
        "prefix": "fake-spotify",
    }
    settings.update(knobs)
    return FakeAuthServer(clock, **settings)
