"""The vault's HTTP proxy (design §4.1).

For each request, in order: normalize the path, pick the route by prefix, identify the caller,
match a rule, apply query and header policy, inject the credential, forward through the egress
proxy, then filter and scrub the response. Every refusal is logged with its reason; the response
body never says which check failed.
"""

from __future__ import annotations

import base64
import hmac
import ipaddress
import os
import time
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import quote, urlsplit

import httpx
from starlette.background import BackgroundTask
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.types import Receive, Scope, Send

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
from . import logs
from .keys import KeySet
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
MAX_REQUEST_BYTES = 10 * 1024 * 1024
MAX_RESPONSE_BYTES = 32 * 1024 * 1024
MAX_SCRUB_BYTES = 1024 * 1024
CONNECT_TIMEOUT = 10.0
READ_TIMEOUT = 60.0
_SCRUBBED_TYPES = (
    "text/",
    "application/json",
    "application/xml",
    "application/problem+json",
    "application/javascript",
    "application/x-www-form-urlencoded",
)


class Refused(Exception):
    """Stop handling a request with this status. ``reason`` goes to the log only."""

    def __init__(self, status: int, reason: str) -> None:
        self.status = status
        self.reason = reason
        super().__init__(reason)


_PUBLIC_MESSAGES = {
    400: "bad request",
    403: "forbidden",
    404: "not found",
    413: "request too large",
    501: "not implemented",
    502: "upstream unavailable",
}


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
        environ: Mapping[str, str] | None = None,
    ) -> None:
        self._store = store
        self._keys = keys
        self._client = client or httpx.AsyncClient(
            proxy=policy.egress_proxy,
            trust_env=False,
            follow_redirects=False,
            timeout=httpx.Timeout(READ_TIMEOUT, connect=CONNECT_TIMEOUT),
        )
        self._environ = os.environ if environ is None else environ
        self._install(policy)

    def _install(self, policy: Policy) -> None:
        self._policy = policy
        self._routes = _compile(policy)
        self._env_secrets = snapshot_env_secrets(policy, self._environ)
        self._gateway_key = self._keys.gateway_key(policy.gateway_key_generation).encode()

    @property
    def policy(self) -> Policy:
        return self._policy

    def reload(self, policy: Policy) -> None:
        self._install(policy)

    async def aclose(self) -> None:
        await self._client.aclose()

    # --- ASGI ----------------------------------------------------------------------------------

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            return
        if scope["type"] != "http":
            raise RuntimeError(f"unsupported scope {scope['type']}")
        request = Request(scope, receive)
        started = time.monotonic()
        log: dict[str, Any] = {"method": request.method}
        try:
            response = await self._handle(request, log)
        except Refused as refusal:
            log.update(status=refusal.status, reason=refusal.reason)
            response = JSONResponse(
                {"error": _PUBLIC_MESSAGES.get(refusal.status, "error")}, status_code=refusal.status
            )
        else:
            log["status"] = response.status_code
        log["duration_ms"] = round((time.monotonic() - started) * 1000, 1)
        logs.event("request", **log)
        await response(scope, receive, send)

    # --- handling ------------------------------------------------------------------------------

    async def _handle(self, request: Request, log: dict[str, Any]) -> Response:
        raw_path = request.scope.get("raw_path") or quote(request.scope["path"]).encode()
        try:
            path = normalize_path(raw_path)
        except RequestRejected as exc:
            raise Refused(400, exc.reason) from exc
        if not path.segments or (compiled := self._routes.get(path.segments[0])) is None:
            raise Refused(404, "no route for this prefix")
        route = compiled.route
        log["route"] = route.name

        query_raw: bytes = request.scope.get("query_string", b"")
        try:
            params = parse_query(query_raw)
        except RequestRejected as exc:
            raise Refused(400, exc.reason) from exc

        caller, used_query, used_header = self._identify(compiled, request, params)
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
        if isinstance(cred, OAuth2Credential):
            raise Refused(501, "OAuth credentials arrive in M2")
        if cred is not None:
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

        url = upstream_origin + base_path + path_prefix + rest.encoded()
        if query:
            url += "?" + encode_query(query)
        return await self._forward(request.method, url, headers, body, route, variants, log)

    def _identify(
        self, compiled: _CompiledRoute, request: Request, params: list[tuple[str, str]]
    ) -> tuple[str, str | None, str | None]:
        """Return ``(caller name, query param used, header used)`` or refuse with 403."""
        gateway = request.headers.getlist(GATEWAY_HEADER)
        if gateway:
            if (
                compiled.accepts_gateway
                and len(gateway) == 1
                and hmac.compare_digest(gateway[0].encode(), self._gateway_key)
            ):
                return "gateway", None, None
            raise Refused(403, "gateway key refused")
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
            raise Refused(502, f"credential unavailable: {exc.reason}") from exc
        raise Refused(502, "credential reference not understood")

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

    async def _forward(
        self,
        method: str,
        url: str,
        headers: list[tuple[str, str]],
        body: bytes,
        route: Route,
        variants: list[bytes],
        log: dict[str, Any],
    ) -> Response:
        timeout = httpx.Timeout(None if route.stream else READ_TIMEOUT, connect=CONNECT_TIMEOUT)
        outgoing = self._client.build_request(
            method, url, headers=headers, content=body, timeout=timeout
        )
        try:
            upstream = await self._client.send(outgoing, stream=True)
        except httpx.HTTPError as exc:
            raise Refused(502, f"upstream request failed: {type(exc).__name__}") from exc

        response_headers, header_hits = scrub_headers(
            filter_response_headers(upstream.headers.multi_items()), variants
        )
        log["upstream_status"] = upstream.status_code

        if route.stream:
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
