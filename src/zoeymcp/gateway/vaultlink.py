"""The gateway's link to the vault, and the egress filter on it (M3 design B.1, C.3, C.4, F.2).

Everything the gateway sends upstream goes through the vault, on one of two links:

- ``unix:<path>``, the standard tier: the vault's link socket, where the kernel vouches for the
  gateway's uid, so no key is sent;
- ``http://host:port``, the hardened tier: the vault's TCP listener, with the gateway key in one
  header. Only the request hook here ever touches the key, and its wrapper refuses to be logged.

Each upstream connection gets its own HTTP client, whose transport is the egress filter: every
request is checked against :mod:`.egressrules` before it is sent, a redirect ends the connection,
cookies are never kept, and a JSON response is cut off past the upstream message limit.
"""

from __future__ import annotations

import os
import re
import time
from collections.abc import AsyncIterator, Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from urllib.parse import parse_qsl, urlsplit

import httpx2

from ..common import canonical
from ..common.ledgerreport import PATH as REPORT_PATH
from ..common.logs import refuse_type
from ..common.policy.fields import VAULT_ONLY_ENV
from . import logs
from .egressrules import CallRegistry, Outgoing, Target, check

VIEW_PATH = "/_zoeymcp/gateway/v1/view"
GATEWAY_HEADER = "x-zoeymcp-gateway"
REFUSAL_HEADER = "x-zoeymcp-vault"
UNIX_BASE = "http://vault.invalid"
KEY_PATTERN = re.compile(r"zgw1-[A-Za-z0-9_-]{43}")
KEY_ENV = "ZOEYMCP_GATEWAY_KEY"
KEY_FILE_ENV = "ZOEYMCP_GATEWAY_KEY_FILE"
KEY_RELOAD_INTERVAL = 10.0  # at most one re-read of the key file per this, after a refusal
_CODE = re.compile(r"[a-z_]{1,64}")


class LinkError(ValueError):
    """A ``--vault`` value or gateway key the gateway can't use."""


@dataclass(frozen=True)
class Link:
    kind: Literal["unix", "http"]
    base_url: str
    scheme: str
    host: str
    port: int | None
    uds: str | None = None

    @property
    def hardened(self) -> bool:
        return self.kind == "http"

    def target(self, path: str) -> Target:
        return Target(self.scheme, self.host, self.port, path, hardened=self.hardened)


def parse_link(spec: str) -> Link:
    """``unix:/run/zoeymcp-link/vault.sock`` or ``http://vault:8080``."""
    if spec.startswith("unix:"):
        path = spec.removeprefix("unix:")
        if not path.startswith("/"):
            raise LinkError("a unix: link needs an absolute socket path")
        return Link("unix", UNIX_BASE, "http", "vault.invalid", None, uds=path)
    parts = urlsplit(spec)
    if parts.scheme != "http" or not parts.hostname:
        raise LinkError("the vault link is unix:<path> or http://host[:port]")
    if (
        parts.username
        or parts.password
        or parts.path not in ("", "/")
        or parts.query
        or parts.fragment
    ):
        raise LinkError("an http link is http://host[:port], with no path, query or user")
    try:
        port = parts.port
    except ValueError as exc:
        raise LinkError("the link's port is invalid") from exc
    host = parts.hostname
    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc += f":{port}"
    return Link("http", f"http://{netloc}", "http", host, port)


# --- the gateway key ----------------------------------------------------------------------------


class GatewayKey:
    """The hardened tier's gateway key. Its ``repr`` hides it, and logging it raises."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        if KEY_PATTERN.fullmatch(value) is None:
            raise LinkError("the gateway key isn't in the zgw1- format")
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "GatewayKey(***)"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, GatewayKey) and other._value == self._value

    def __hash__(self) -> int:
        return hash(self._value)


refuse_type(GatewayKey)


class KeySource:
    """Where the hardened gateway's key comes from: a value read once, or a file re-read on
    SIGHUP and after a vault refusal (at most once per :data:`KEY_RELOAD_INTERVAL`)."""

    def __init__(
        self,
        value: str | None = None,
        file: Path | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._file = file
        self._clock = clock
        self._last_reload: float | None = None
        self._key = GatewayKey(value) if value is not None else None
        if file is not None:
            self._key = self._read()

    @classmethod
    def from_environ(cls, environ: Mapping[str, str]) -> KeySource:
        file = environ.get(KEY_FILE_ENV)
        return cls(environ.get(KEY_ENV), Path(file) if file else None)

    @property
    def configured(self) -> bool:
        return self._key is not None or self._file is not None

    def current(self) -> GatewayKey | None:
        return self._key

    def _read(self) -> GatewayKey:
        if self._file is None:
            raise LinkError("no gateway key file is configured")
        try:
            text = self._file.read_text(encoding="ascii")
        except (OSError, UnicodeDecodeError) as exc:
            raise LinkError("the gateway key file can't be read") from exc
        return GatewayKey(text.strip())

    def reload(self) -> bool:
        """Re-read the key file now. Returns whether the key changed; a bad file keeps the old."""
        if self._file is None:
            return False
        self._last_reload = self._clock()
        try:
            key = self._read()
        except LinkError as exc:
            logs.event("gateway_key_unreadable", reason=str(exc))
            return False
        changed = key != self._key
        self._key = key
        return changed

    def after_refusal(self) -> bool:
        """The vault refused the key: re-read the file, unless that was done just now."""
        now = self._clock()
        if self._last_reload is not None and now - self._last_reload < KEY_RELOAD_INTERVAL:
            return False
        return self.reload()


# --- the egress filter --------------------------------------------------------------------------


class UpstreamBlocked(Exception):
    """The egress filter refused a request the SDK was about to send."""


class UpstreamRedirect(Exception):
    """The answer was a redirect, which the gateway never follows."""


class ResponseTooLarge(Exception):
    """A JSON answer went past the upstream message limit."""


class _Capped(httpx2.AsyncByteStream):
    def __init__(self, inner: httpx2.AsyncByteStream, limit: int) -> None:
        self._inner = inner
        self._limit = limit

    async def __aiter__(self) -> AsyncIterator[bytes]:
        total = 0
        async for chunk in self._inner:
            total += len(chunk)
            if total > self._limit:
                raise ResponseTooLarge
            yield chunk

    async def aclose(self) -> None:
        await self._inner.aclose()


ResponseNote = Callable[[httpx2.Request, httpx2.Response], None]


def is_redirect(status: int) -> bool:
    """Every 3xx but 304 Not Modified, which the view's long poll answers with."""
    return 300 <= status < 400 and status != 304


def vault_refusal_code(body: bytes) -> str | None:
    """The stable ``code`` in a vault refusal body, if it has a plain one."""
    try:
        document = canonical.loads_strict(body, max_bytes=65536)
    except canonical.JSONRejected:
        return None
    code = document.get("code") if isinstance(document, dict) else None
    return code if isinstance(code, str) and _CODE.fullmatch(code) else None


class EgressTransport(httpx2.AsyncBaseTransport):
    """Checks every request before it leaves, and every answer as it arrives."""

    def __init__(
        self,
        inner: httpx2.AsyncBaseTransport,
        target: Target,
        registry: CallRegistry,
        *,
        server: str,
        max_json_bytes: int,
        keys: KeySource | None = None,
        on_response: ResponseNote | None = None,
    ) -> None:
        self._inner = inner
        self._target = target
        self._registry = registry
        self._server = server
        self._max_json_bytes = max_json_bytes
        self._keys = keys
        self._on_response = on_response

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        body = await request.aread()
        url = request.url
        raw_path, _, _ = url.raw_path.partition(b"?")
        outgoing = Outgoing(
            method=request.method,
            scheme=url.scheme,
            host=url.host,
            port=url.port,
            path=raw_path.decode("ascii", "replace"),
            query=url.query.decode("ascii", "replace"),
            headers=list(request.headers.multi_items()),
            body=body,
        )
        verdict = check(outgoing, self._target, self._registry)
        if not verdict.allowed:
            logs.event("upstream_request_blocked", server=self._server, reason=verdict.reason)
            raise UpstreamBlocked(verdict.reason)
        if verdict.kind == "response" and b'"error"' in body:
            logs.event("upstream_request_refused", server=self._server)
        response = await self._inner.handle_async_request(request)
        if is_redirect(response.status_code):
            await response.aclose()
            logs.event(
                "upstream_redirect_refused", server=self._server, status=response.status_code
            )
            raise UpstreamRedirect(str(response.status_code))
        if "set-cookie" in response.headers:
            del response.headers["set-cookie"]
        if response.headers.get(REFUSAL_HEADER) == "refused":
            response = await self._vault_refused(request, response)
        elif response.headers.get("content-type", "").startswith("application/json"):
            response = httpx2.Response(
                response.status_code,
                headers=response.headers,
                stream=_Capped(response.stream, self._max_json_bytes),  # type: ignore[arg-type]
                extensions=response.extensions,
                request=request,
            )
        if self._on_response is not None:
            self._on_response(request, response)
        return response

    async def _vault_refused(
        self, request: httpx2.Request, response: httpx2.Response
    ) -> httpx2.Response:
        body = await response.aread()
        await response.aclose()
        logs.event(
            "vault_refused",
            server=self._server,
            status=response.status_code,
            code=vault_refusal_code(body),
        )
        if response.status_code == 403 and self._keys is not None:
            self._keys.after_refusal()
        return httpx2.Response(
            response.status_code,
            headers=response.headers,
            content=body,
            extensions=response.extensions,
            request=request,
        )

    async def aclose(self) -> None:
        await self._inner.aclose()


def _inner_transport(link: Link) -> httpx2.AsyncHTTPTransport:
    return httpx2.AsyncHTTPTransport(uds=link.uds, trust_env=False, retries=0)


def _key_hook(keys: KeySource) -> Callable[[httpx2.Request], object]:
    async def add_key(request: httpx2.Request) -> None:
        key = keys.current()
        if key is not None:
            request.headers[GATEWAY_HEADER] = key.reveal()

    return add_key


def _hooks(link: Link, keys: KeySource | None) -> dict[str, list[Callable[..., object]]]:
    return {"request": [_key_hook(keys)]} if link.hardened and keys is not None else {}


# Long upstream calls are bounded by anyio deadlines, not by httpx's 5 s default.
UPSTREAM_TIMEOUT = httpx2.Timeout(connect=10.0, read=None, write=30.0, pool=10.0)


def upstream_client(
    link: Link,
    keys: KeySource | None,
    *,
    server: str,
    vault_path: str,
    registry: CallRegistry,
    max_json_bytes: int,
    on_response: ResponseNote | None = None,
    inner: httpx2.AsyncBaseTransport | None = None,
) -> httpx2.AsyncClient:
    """The HTTP client for one upstream connection, behind its egress filter."""
    transport = EgressTransport(
        inner if inner is not None else _inner_transport(link),
        link.target(vault_path),
        registry,
        server=server,
        max_json_bytes=max_json_bytes,
        keys=keys,
        on_response=on_response,
    )
    return httpx2.AsyncClient(
        transport=transport,
        follow_redirects=False,
        max_redirects=0,
        trust_env=False,
        timeout=UPSTREAM_TIMEOUT,
        event_hooks=_hooks(link, keys),
    )


class _ViewOnly(httpx2.AsyncBaseTransport):
    """The policy client's transport: a GET of the view path and nothing else."""

    def __init__(self, inner: httpx2.AsyncBaseTransport, link: Link) -> None:
        self._inner = inner
        self._link = link

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        url = request.url
        raw_path = url.raw_path.partition(b"?")[0]
        if (
            request.method != "GET"
            or (url.scheme, url.host, url.port)
            != (self._link.scheme, self._link.host, self._link.port)
            or raw_path != VIEW_PATH.encode()
        ):
            raise UpstreamBlocked("the policy client only fetches the view")
        response = await self._inner.handle_async_request(request)
        if is_redirect(response.status_code):
            await response.aclose()
            raise UpstreamRedirect(str(response.status_code))
        return response

    async def aclose(self) -> None:
        await self._inner.aclose()


VIEW_TIMEOUT = httpx2.Timeout(connect=10.0, read=40.0, write=10.0, pool=10.0)


def view_client(
    link: Link, keys: KeySource | None, inner: httpx2.AsyncBaseTransport | None = None
) -> httpx2.AsyncClient:
    """The HTTP client that fetches the policy view."""
    return httpx2.AsyncClient(
        transport=_ViewOnly(inner if inner is not None else _inner_transport(link), link),
        base_url=link.base_url,
        follow_redirects=False,
        max_redirects=0,
        trust_env=False,
        timeout=VIEW_TIMEOUT,
        event_hooks=_hooks(link, keys),
    )


REPORT_MAX_ANSWER_BYTES = 4096  # the copy's head, or a refusal with it (M5 design J.3)


class _ReportOnly(httpx2.AsyncBaseTransport):
    """The reporter's transport: a GET or POST of exactly the report path, and nothing else.
    An answer is cut off past :data:`REPORT_MAX_ANSWER_BYTES`."""

    def __init__(self, inner: httpx2.AsyncBaseTransport, link: Link) -> None:
        self._inner = inner
        self._link = link

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        url = request.url
        if (
            request.method not in ("GET", "POST")
            or (url.scheme, url.host, url.port)
            != (self._link.scheme, self._link.host, self._link.port)
            or url.raw_path != REPORT_PATH.encode()
        ):
            raise UpstreamBlocked("the reporter only reaches the report path")
        response = await self._inner.handle_async_request(request)
        if is_redirect(response.status_code):
            await response.aclose()
            raise UpstreamRedirect(str(response.status_code))
        return httpx2.Response(
            response.status_code,
            headers=response.headers,
            stream=_Capped(response.stream, REPORT_MAX_ANSWER_BYTES),  # type: ignore[arg-type]
            extensions=response.extensions,
            request=request,
        )

    async def aclose(self) -> None:
        await self._inner.aclose()


# A report's body is read within 10 s by the vault; its answer is small.
REPORT_TIMEOUT = httpx2.Timeout(connect=10.0, read=30.0, write=30.0, pool=10.0)


def report_client(
    link: Link, keys: KeySource | None, inner: httpx2.AsyncBaseTransport | None = None
) -> httpx2.AsyncClient:
    """The HTTP client that reports the ledger to the vault's copy (M5 design J.3)."""
    return httpx2.AsyncClient(
        transport=_ReportOnly(inner if inner is not None else _inner_transport(link), link),
        base_url=link.base_url,
        follow_redirects=False,
        max_redirects=0,
        trust_env=False,
        timeout=REPORT_TIMEOUT,
        event_hooks=_hooks(link, keys),
    )


REVIEW_JOBS_PATH = "/_zoeymcp/gateway/v1/review/jobs"
REVIEW_REPORT_PATH = "/_zoeymcp/gateway/v1/report/review"
REVIEW_QUERY_KEYS = frozenset({"wait", "view"})
REVIEW_MAX_ANSWER_BYTES = 4096  # a list of jobs, a job's state, or a refusal (M7 design F.3)


def _jobs_query(query: bytes) -> bool:
    """A jobs poll's query: ``wait`` and ``view``, each at most once, and nothing else."""
    try:
        params = parse_qsl(query.decode("ascii"), keep_blank_values=True, strict_parsing=True)
    except (UnicodeDecodeError, ValueError):
        return False
    names = [name for name, _ in params]
    return len(set(names)) == len(names) and set(names) <= REVIEW_QUERY_KEYS


class _ReviewOnly(httpx2.AsyncBaseTransport):
    """The review poller's transport (M7 design F.3): a GET of exactly the jobs path, with only
    the ``wait`` and ``view`` query keys, or a POST of exactly the review report path, on the
    link's scheme, host and port, and nothing else. An answer is cut off past
    :data:`REVIEW_MAX_ANSWER_BYTES`."""

    def __init__(self, inner: httpx2.AsyncBaseTransport, link: Link) -> None:
        self._inner = inner
        self._link = link

    def _allowed(self, request: httpx2.Request) -> bool:
        url = request.url
        if (url.scheme, url.host, url.port) != (
            self._link.scheme,
            self._link.host,
            self._link.port,
        ):
            return False
        raw_path, question, query = url.raw_path.partition(b"?")
        if request.method == "GET" and raw_path == REVIEW_JOBS_PATH.encode():
            return not question or (bool(query) and _jobs_query(query))
        return request.method == "POST" and url.raw_path == REVIEW_REPORT_PATH.encode()

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        if not self._allowed(request):
            raise UpstreamBlocked("the review poller only reaches the review job path")
        response = await self._inner.handle_async_request(request)
        if is_redirect(response.status_code):
            await response.aclose()
            raise UpstreamRedirect(str(response.status_code))
        return httpx2.Response(
            response.status_code,
            headers=response.headers,
            stream=_Capped(response.stream, REVIEW_MAX_ANSWER_BYTES),  # type: ignore[arg-type]
            extensions=response.extensions,
            request=request,
        )

    async def aclose(self) -> None:
        await self._inner.aclose()


# A poll waits up to 25 s for a job; the vault reads a report within 30 s, then checks every pin
# in it before it answers, which for a large report takes a while.
REVIEW_TIMEOUT = httpx2.Timeout(connect=10.0, read=60.0, write=30.0, pool=10.0)


def review_client(
    link: Link, keys: KeySource | None, inner: httpx2.AsyncBaseTransport | None = None
) -> httpx2.AsyncClient:
    """The HTTP client that asks the vault for review jobs and posts their results (M7 design
    F.3), built like :func:`report_client`."""
    return httpx2.AsyncClient(
        transport=_ReviewOnly(inner if inner is not None else _inner_transport(link), link),
        base_url=link.base_url,
        follow_redirects=False,
        max_redirects=0,
        trust_env=False,
        timeout=REVIEW_TIMEOUT,
        event_hooks=_hooks(link, keys),
    )


def environ_has_no_secrets(environ: Mapping[str, str]) -> str | None:
    """G1: the variables that must never be in the gateway's environment, by name, or None."""
    for name in VAULT_ONLY_ENV:
        if name in environ:
            return name
    return None


def running_as_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


# --- toolkits (M4 design H.4) -------------------------------------------------------------------

TOOLKIT_MAX_REQUEST_BYTES = 2**20
TOOLKIT_MAX_ANSWER_BYTES = 4 * 2**20
# The SDK sets the first three; httpx adds the rest. Nothing else reaches the vault (G12).
_TOOLKIT_HEADERS = frozenset(
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
    }
)
ToolkitCheck = Callable[[str, str], str | None]


class ToolkitTransport(httpx2.AsyncBaseTransport):
    """A toolkit's requests to the vault: only to the link, only what ``check`` allows, with no
    header from anywhere but the gateway itself. Redirects end the request; a JSON answer is cut
    off past 4 MiB; a vault refusal reloads the gateway key, as for upstream connections."""

    def __init__(
        self,
        inner: httpx2.AsyncBaseTransport,
        link: Link,
        *,
        server: str,
        check: ToolkitCheck,
        keys: KeySource | None = None,
    ) -> None:
        self._inner = inner
        self._link = link
        self._server = server
        self._check = check
        self._keys = keys

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        url = request.url
        raw_path, _, _ = url.raw_path.partition(b"?")
        path = raw_path.decode("ascii", "replace")
        reason = None
        if (url.scheme, url.host, url.port) != (
            self._link.scheme,
            self._link.host,
            self._link.port,
        ):
            reason = "target"
        elif any(name.lower() not in _TOOLKIT_HEADERS for name in request.headers):
            reason = "header"
        else:
            body = await request.aread()
            if len(body) > TOOLKIT_MAX_REQUEST_BYTES:
                reason = "too_large"
            else:
                reason = self._check(request.method, path)
        if reason is not None:
            logs.event("toolkit_request_blocked", server=self._server, reason=reason)
            raise UpstreamBlocked(reason)
        response = await self._inner.handle_async_request(request)
        if is_redirect(response.status_code):
            await response.aclose()
            logs.event(
                "upstream_redirect_refused", server=self._server, status=response.status_code
            )
            raise UpstreamRedirect(str(response.status_code))
        if "set-cookie" in response.headers:
            del response.headers["set-cookie"]
        if response.headers.get(REFUSAL_HEADER) == "refused":
            body = await response.aread()
            await response.aclose()
            logs.event(
                "vault_refused",
                server=self._server,
                status=response.status_code,
                code=vault_refusal_code(body),
            )
            if response.status_code == 403 and self._keys is not None:
                self._keys.after_refusal()
            return httpx2.Response(
                response.status_code,
                headers=response.headers,
                content=body,
                extensions=response.extensions,
                request=request,
            )
        return httpx2.Response(
            response.status_code,
            headers=response.headers,
            stream=_Capped(response.stream, TOOLKIT_MAX_ANSWER_BYTES),  # type: ignore[arg-type]
            extensions=response.extensions,
            request=request,
        )

    async def aclose(self) -> None:
        await self._inner.aclose()


def toolkit_client(
    link: Link,
    keys: KeySource | None,
    *,
    server: str,
    check: ToolkitCheck,
    inner: httpx2.AsyncBaseTransport | None = None,
) -> httpx2.AsyncClient:
    """The HTTP client of one toolkit server: M3's link, key hook, redirect refusal and refusal
    handling, with ``check`` in place of the MCP egress rules (M4 design H.4)."""
    return httpx2.AsyncClient(
        transport=ToolkitTransport(
            inner if inner is not None else _inner_transport(link),
            link,
            server=server,
            check=check,
            keys=keys,
        ),
        base_url=link.base_url,
        follow_redirects=False,
        max_redirects=0,
        trust_env=False,
        timeout=UPSTREAM_TIMEOUT,
        event_hooks=_hooks(link, keys),
    )
