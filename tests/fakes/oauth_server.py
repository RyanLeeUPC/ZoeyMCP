"""A stateful fake OAuth authorization server and resource server (design G.1).

Unit tests reach it in process over ``httpx.ASGITransport``; acceptance tests serve it over TLS.
It keeps grants the way real providers do: refresh tokens rotate (or don't), a reused old token
revokes the whole family, codes are single use and bound to the PKCE challenge and the redirect
URI, and every client authentication method is enforced. Knobs make it misbehave the ways real
providers do.

Every value it issues is a deterministic fake (``<prefix>-at-1``, ``<prefix>-rt-2``), so tests can
look for them in logs and responses.
"""

from __future__ import annotations

import asyncio
import base64
import enum
import hashlib
import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Final, Literal
from urllib.parse import parse_qsl, unquote_plus, urlencode, urlsplit

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.routing import Route

Clock = Callable[[], float]
ClientAuth = Literal["basic", "post", "none"]
ErrorShape = Literal["rfc", "status_403", "status_200", "ok_false", "html", "form", "echo"]


class _Missing(enum.Enum):
    MISSING = enum.auto()


MISSING: Final = _Missing.MISSING
"""A knob set to this leaves the field out of the token response."""

DEFAULT_REDIRECT: Final = "http://127.0.0.1/callback"
INSUFFICIENT_SCOPE_PATH: Final = "/forbidden"


class DroppedConnection(httpx.ReadError):
    """Raised by the app after it processed a request (``drop_after_processing``).

    Over ``ASGITransport`` it reaches the client as a read error: the request was handled, and
    the answer was lost.
    """


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


class FakeAuthServer:
    """``GET /authorize``, ``POST /token`` and ``POST /revoke``.

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
        # Hostile and flaky behavior.
        self.drop_after_processing = 0
        self.redirect_token: str | None = None
        self.huge_body = False
        self.crlf_token = False
        self.bad_refresh_token_shape = False
        self.delay = 0.0
        self.gate: asyncio.Event | None = None
        self.calls: list[TokenCall] = []
        self.revocations: list[str] = []
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
        return Starlette(
            routes=[
                Route("/authorize", self._authorize, methods=["GET"]),
                Route("/token", self._token, methods=["POST"]),
                Route("/revoke", self._revoke, methods=["POST"]),
            ]
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

    # --- /authorize ----------------------------------------------------------------------------

    async def _authorize(self, request: Request) -> Response:
        params = dict(request.query_params)
        redirect_uri = params.get("redirect_uri", "")
        if params.get("client_id") != self.client_id:
            return Response("unknown client", status_code=400)
        if not self._redirect_allowed(redirect_uri):
            return Response("redirect_uri isn't registered", status_code=400)
        state = params.get("state")
        problems = [
            params.get("response_type") != "code",
            params.get("code_challenge_method") != "S256",
            not params.get("code_challenge"),
            not state,
        ]
        if any(problems):
            back = {"error": "invalid_request"}
            if state:
                back["state"] = state
            return RedirectResponse(f"{redirect_uri}?{urlencode(back)}", status_code=302)
        offline = params.get("access_type") == "offline" and params.get("prompt") == "consent"
        scope = params.get("scope")
        code = self._new("code")
        self._codes[code] = _Code(
            client_id=self.client_id,
            redirect_uri=redirect_uri,
            challenge=params["code_challenge"],
            scopes=tuple(scope.split(" ")) if scope else self.scopes,
            offline=offline,
        )
        answer = {"code": code, "state": state or ""}
        if self.issuer is not None:
            answer["iss"] = self.issuer
        return RedirectResponse(f"{redirect_uri}?{urlencode(answer)}", status_code=302)

    def _redirect_allowed(self, redirect_uri: str) -> bool:
        if redirect_uri == self.registered_redirect:
            return True
        # RFC 8252 section 7.3: a loopback redirect registered without a port takes any port.
        registered, given = urlsplit(self.registered_redirect), urlsplit(redirect_uri)
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
        if self.delay:
            await asyncio.sleep(self.delay)
        response = self._answer(call, params, headers)
        call.status = response.status_code
        if self.drop_after_processing:
            self.drop_after_processing -= 1
            raise DroppedConnection("connection reset after the token was issued")
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
        if not self._client_ok(call.auth, headers, params):
            extra = {"www-authenticate": 'Basic realm="fake"'} if call.auth == "basic" else None
            return JSONResponse({"error": "invalid_client"}, status_code=401, headers=extra)
        if call.grant_type == "refresh_token":
            return self._refresh(params)
        if call.grant_type == "authorization_code":
            return self._exchange(params)
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

    def _exchange(self, params: dict[str, str]) -> Response:
        # The "echo" error shape repeats the presented code, as a careless provider might.
        presented = params.get("code", "")
        code = self._codes.get(presented)
        if code is None or code.used:
            return self._grant_error("Invalid authorization code", presented)
        code.used = True
        if params.get("redirect_uri") != code.redirect_uri:
            return self._grant_error("redirect_uri doesn't match", presented)
        verifier = params.get("code_verifier", "")
        digest = hashlib.sha256(verifier.encode("ascii", "replace")).digest()
        challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        if challenge != code.challenge:
            return self._grant_error("PKCE verification failed", verifier)
        family = _Family(
            scopes=self.granted_scopes or code.scopes,
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

    def _client_ok(self, method: str, headers: dict[str, str], params: dict[str, str]) -> bool:
        if self.auth == "basic":
            if method != "basic" or "client_secret" in params:
                return False
            try:
                decoded = base64.b64decode(headers["authorization"][6:], validate=True).decode()
            except ValueError:
                return False
            user, _, password = decoded.partition(":")
            return (unquote_plus(user), unquote_plus(password)) == (
                self.client_id,
                self.client_secret,
            )
        if method != "body":
            return False
        if self.auth == "post":
            return (params.get("client_id"), params.get("client_secret")) == (
                self.client_id,
                self.client_secret,
            )
        return params.get("client_id") == self.client_id and "client_secret" not in params


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
