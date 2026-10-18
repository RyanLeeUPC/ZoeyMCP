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
with ``_``). The only one is the gateway's policy view, a long poll that a reload wakes (M3 design
D.1, D.2); the rest are 404.

OAuth routes get an access token from the :class:`TokenManager`. An upstream 401 that says the
token is bad drops it, and a request that's safe to repeat is sent once more with a new token
(design D.10). Neither HTTP client keeps cookies: an upstream's session cookie must never reach
another caller (N2).
"""

from __future__ import annotations

import asyncio
import base64
import hmac
import http.cookiejar
import ipaddress
import math
import os
import re
import time
import urllib.request
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass
from typing import Any, Final, Literal
from urllib.parse import quote, urlsplit

import httpx
from starlette.background import BackgroundTask
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.types import Receive, Scope, Send

from ..common.policy.match import NormalizedPath
from ..common.policy.schema import (
    BasicCredential,
    HeaderCredential,
    OAuth2Credential,
    PathCredential,
    PlaceholderCaller,
    Policy,
    QueryCredential,
    Route,
    is_secret_ref,
)
from ..common.policy.view import build_view, dump_view
from . import logs
from .gatewaykeys import GatewayKeys
from .keys import KeySet
from .oauth.protocol import ATTEMPT_DEADLINE, CREDENTIAL_UNAVAILABLE, OAUTH_UNAVAILABLE
from .oauth.protocol import CONNECT_TIMEOUT as TOKEN_CONNECT_TIMEOUT
from .oauth.tokens import UPSTREAM_INSUFFICIENT_SCOPE, Grant, OAuthUnavailable, TokenManager
from .request import (
    RequestRejected,
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
from .store import Secret, SecretStore, SecretUnavailable

GATEWAY_HEADER = "x-zoeymcp-gateway"
# Marks an answer the vault made itself, so the gateway can tell it from an upstream's (C.4).
REFUSAL_HEADER = "x-zoeymcp-vault"
REFUSAL_MARKER = "refused"
# The scope key the listener wrapper sets: "gateway" on the link socket, "tcp" elsewhere.
LISTENER_SCOPE_KEY = "zoeymcp.listener"
Listener = Literal["gateway", "tcp"]
# The vault's own endpoints. The gateway's view is the only one (M3 design D.1).
INTERNAL_SEGMENT = "_zoeymcp"
VIEW_PATH = NormalizedPath((INTERNAL_SEGMENT, "gateway", "v1", "view"))
# The longest ``?wait=`` in seconds, and how many may wait at once (M3 design D.2).
VIEW_MAX_WAIT = 25
VIEW_MAX_WAITERS = 4
# One entity tag of If-None-Match, weak or strong; the tag itself is the group.
_ENTITY_TAG = re.compile(r'\s*(?:W/)?"([\x21\x23-\x7e]*)"\s*')
MAX_REQUEST_BYTES = 10 * 1024 * 1024
MAX_RESPONSE_BYTES = 32 * 1024 * 1024
MAX_SCRUB_BYTES = 1024 * 1024
CONNECT_TIMEOUT = 10.0
READ_TIMEOUT = 60.0
_STREAM_TYPES = ("text/event-stream", "application/x-ndjson")
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
    413: "request too large",
    429: "too many requests",
    501: "not implemented",
    502: "upstream unavailable",
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


def snapshot_env_secrets(policy: Policy, environ: Mapping[str, str]) -> dict[str, Secret]:
    """Read every ``env:`` secret once at startup, so later env changes can't affect the vault."""
    refs: set[str] = set()
    for cred in policy.credentials.values():
        for value in vars(cred).values():
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
        tokens: TokenManager | None = None,
        environ: Mapping[str, str] | None = None,
        gateway_keys: GatewayKeys | None = None,
        gateway_link: bool = False,
    ) -> None:
        """``client`` reaches upstreams and ``token_client`` token endpoints; both get a jar that
        keeps no cookies. ``tokens`` replaces the token manager (tests). It brings its own client,
        so ``token_client`` is then not used.

        ``gateway_keys`` is the persisted ratchet the vault loaded at startup. Without one, the
        gateway keys are tracked in memory only (self-tests and unit tests).

        ``gateway_link`` says the link socket is configured: the gateway is then known by its
        socket only, and a gateway key on TCP is refused.
        """
        self._gateway_link = gateway_link
        self._store = store
        self._keys = keys
        self._gateway_keys = gateway_keys or GatewayKeys.in_memory(
            keys, policy.gateway_key_generation
        )
        self._client = without_cookies(client or _upstream_client(policy))
        self._token_client: httpx.AsyncClient | None = None
        if tokens is None:
            self._token_client = without_cookies(token_client or _token_client(policy))
            tokens = TokenManager(store, self._token_client)
        self._tokens = tokens
        # The last access token serial seen per credential, for the request log.
        self._serials: dict[str, int] = {}
        self._environ = os.environ if environ is None else environ
        # Long polls of the view wait on this event. Each install sets it and puts a new one in
        # its place, so every waiter wakes and looks at the view again.
        self._view_changed = asyncio.Event()
        self._view_waiters = 0
        self._view_stopping = False
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
        self._wake_view_waiters()
        return self._tokens.configure(policy, self._env_secrets)

    def _wake_view_waiters(self) -> None:
        woken, self._view_changed = self._view_changed, asyncio.Event()
        woken.set()

    @property
    def policy(self) -> Policy:
        return self._policy

    @property
    def tokens(self) -> TokenManager:
        return self._tokens

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

    def stop_view_waits(self) -> None:
        """Answer every long poll of the view now, and wait no more. For shutdown: the servers
        wait for requests in flight, and a long poll would hold them for up to 25 s."""
        self._view_stopping = True
        self._wake_view_waiters()

    def reload(self, policy: Policy) -> list[str]:
        """Swap the policy. Returns the OAuth credentials whose cached tokens were reset.

        Raises :class:`~zoeymcp.vault.gatewaykeys.GatewayKeyError` for a gateway key generation
        that went backwards or can't be written; the running policy then stays.
        """
        return self._install(policy)

    async def aclose(self) -> None:
        """Wait for refreshes in flight, then close the clients (N5)."""
        try:
            await self._tokens.aclose()
        finally:
            await self._client.aclose()
            if self._token_client is not None and self._token_client is not self._client:
                await self._token_client.aclose()

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
        try:
            response = await self._handle(request, listener, log)
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
            raise Refused(501, "connectors arrive in M4")
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
        upstream_response = await self._send(request.method, url, headers, body, route)
        if grant is not None:
            assert route.credential is not None  # noqa: S101 - set for every OAuth route
            status = upstream_response.status_code
            if status in (401, 403) and "insufficient_scope" in _challenge_errors(
                upstream_response
            ):
                # A new token won't fix that; the operator may need to log in with more scopes.
                self._tokens.note_upstream(route.credential, UPSTREAM_INSUFFICIENT_SCOPE)
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
                    log=log,
                )
        return await self._respond(upstream_response, route, variants, log)

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
        """``GET /_zoeymcp/gateway/v1/view`` for the gateway only; every other path here is 404.

        The answer is the view with its digest as the ``ETag``, or 304 while the digest is one
        the caller named in ``If-None-Match``. With ``?wait=N`` a 304 waits up to N seconds for
        a reload that changes the view (M3 design D.2).
        """
        if path != VIEW_PATH:
            raise Refused(404, "no such vault endpoint")
        log["endpoint"] = "gateway_view"
        if listener != "gateway" and not self._gateway_key(request, accepted=True):
            raise Refused(403, "the view is for the gateway only")
        log["caller"] = "gateway"
        if request.method != "GET":
            raise Refused(405, "the view takes GET only", allow="GET")
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

    async def _wait_for_view(
        self, tags: frozenset[str], deadline: float, receive: Receive, log: dict[str, Any]
    ) -> None:
        """Wait until the view's digest isn't in ``tags``, the deadline, shutdown, or the
        caller leaves. At most :data:`VIEW_MAX_WAITERS` wait; one more is refused with 429."""
        if self._view_waiters >= VIEW_MAX_WAITERS:
            raise Refused(429, "too many view waiters", retry_after=1)
        self._view_waiters += 1
        gone = asyncio.ensure_future(_disconnected(receive))
        try:
            while self._view.digest in tags and not self._view_stopping:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return
                changed = asyncio.ensure_future(self._view_changed.wait())
                try:
                    await asyncio.wait(
                        (changed, gone), timeout=remaining, return_when=asyncio.FIRST_COMPLETED
                    )
                finally:
                    changed.cancel()
                if gone.done():
                    log["disconnected"] = True
                    return
        finally:
            self._view_waiters -= 1
            # On a task that has already failed, cancel() also marks its error as retrieved, so
            # asyncio doesn't report it as never retrieved.
            gone.cancel()

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
            upstream = await self._send(method, url, retry, body, route)
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
    ) -> httpx.Response:
        """Send the request upstream. Returns once the status line and headers arrived."""
        timeout = httpx.Timeout(None if route.stream else READ_TIMEOUT, connect=CONNECT_TIMEOUT)
        outgoing = self._client.build_request(
            method, url, headers=headers, content=body, timeout=timeout
        )
        try:
            return await self._client.send(outgoing, stream=True)
        except httpx.HTTPError as exc:
            raise Refused(502, f"upstream request failed: {type(exc).__name__}") from exc

    async def _respond(
        self,
        upstream: httpx.Response,
        route: Route,
        variants: list[bytes],
        log: dict[str, Any],
    ) -> Response:
        """Relay a stream as it arrives, or buffer and scrub everything else."""
        response_headers, header_hits = scrub_headers(
            filter_response_headers(upstream.headers.multi_items()), variants
        )
        log["upstream_status"] = upstream.status_code

        # Only real streams are relayed as they arrive. Anything else on a stream route (JSON
        # errors especially, which is where upstreams echo keys) is buffered and scrubbed. A 401
        # is never relayed as a stream: it may echo the token it refused.
        content_type = upstream.headers.get("content-type", "")
        if route.stream and upstream.status_code != 401 and _is_stream(content_type):
            log.update(streamed=True, scrubbed=header_hits)
            streamed = StreamingResponse(
                _relay(upstream),
                status_code=upstream.status_code,
                background=BackgroundTask(upstream.aclose),
            )
            streamed.raw_headers = _raw(response_headers)
            return streamed

        try:
            content = await _read_limited(upstream, MAX_RESPONSE_BYTES)
        except httpx.HTTPError as exc:
            raise Refused(502, f"upstream response failed: {type(exc).__name__}") from exc
        finally:
            await upstream.aclose()
        if content is None:
            raise Refused(502, "upstream response over the limit")

        body_hits = 0
        content_type = upstream.headers.get("content-type", "").lower()
        if (
            variants
            and len(content) <= MAX_SCRUB_BYTES
            and content_type.startswith(_SCRUBBED_TYPES)
        ):
            content, body_hits = scrub(content, variants)
        log.update(bytes_out=len(content), scrubbed=header_hits + body_hits)
        response = Response(content, status_code=upstream.status_code)
        response.raw_headers = [
            *_raw(response_headers),
            (b"content-length", str(len(content)).encode()),
        ]
        return response


def view_wait(params: list[tuple[str, str]]) -> int:
    """The seconds a view request may wait: ``?wait=N``, at most :data:`VIEW_MAX_WAIT`, or 0.

    Any other parameter, a repeated ``wait``, or a value that isn't plain digits is refused.
    """
    if not params:
        return 0
    if len(params) > 1 or params[0][0] != "wait":
        raise RequestRejected("the view takes one parameter, wait")
    value = params[0][1]
    if not (value.isascii() and value.isdigit()):
        raise RequestRejected("wait must be a number of seconds")
    # Capped before int(), which refuses a string of thousands of digits.
    seconds = value.lstrip("0")
    if len(seconds) > len(str(VIEW_MAX_WAIT)):
        return VIEW_MAX_WAIT
    return min(int(seconds or "0"), VIEW_MAX_WAIT)


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


def _upstream_client(policy: Policy) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        proxy=policy.egress_proxy,
        trust_env=False,
        follow_redirects=False,
        timeout=httpx.Timeout(READ_TIMEOUT, connect=CONNECT_TIMEOUT),
    )


def _token_client(policy: Policy) -> httpx.AsyncClient:
    """The client for token endpoints (design D.14). A redirect would re-send secrets."""
    return httpx.AsyncClient(
        proxy=policy.egress_proxy,
        trust_env=False,
        follow_redirects=False,
        timeout=httpx.Timeout(ATTEMPT_DEADLINE, connect=TOKEN_CONNECT_TIMEOUT),
    )


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


def _is_stream(content_type: str) -> bool:
    return content_type.lower().split(";", 1)[0].strip() in _STREAM_TYPES


def _raw(headers: list[tuple[str, str]]) -> list[tuple[bytes, bytes]]:
    return [(name.lower().encode("latin-1"), value.encode("latin-1")) for name, value in headers]


async def _relay(upstream: httpx.Response) -> AsyncIterator[bytes]:
    async for chunk in upstream.aiter_bytes():
        yield chunk


async def _read_limited(upstream: httpx.Response, limit: int) -> bytes | None:
    chunks: list[bytes] = []
    size = 0
    async for chunk in upstream.aiter_bytes():
        size += len(chunk)
        if size > limit:
            return None
        chunks.append(chunk)
    return b"".join(chunks)
