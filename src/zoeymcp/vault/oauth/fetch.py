"""Phase 1's requests to hosts learned from the network (M7 design B.5). I/O, not mutated.

A :class:`Fetcher` sends one discovery's requests on the onboarding client
(``vault/netclient.py``), and ``discovery.py`` decides what each answer means. Its rules:

- **Methods**: up to two fixed POSTs for the probe, GETs for metadata, one POST for a
  registration. Redirects are never followed: a 3xx on a well-known candidate is "not here",
  on any other request ``fetch_redirect``.
- **Headers**: ``Accept: application/json`` and ``User-Agent: zoeymcp/<version>`` (the probe's
  own, D.2, instead of the first), ``Accept-Encoding: identity``, and nothing else: no
  Authorization, no cookies (the client's jar keeps none), no proxy from the environment.
- **Size and type**: a metadata answer at most :data:`~.discovery.METADATA_MAX` bytes, a
  registration answer :data:`~.discovery.REGISTRATION_MAX`, both ``application/json`` and one
  JSON object by ``canonical.loads_strict``; the probe's body is never read, only its status
  and ``WWW-Authenticate`` values.
- **Time and count**: each request :data:`FETCH_TIMEOUT` seconds in all, so a host that
  trickles bytes is cut at the deadline, not per read; a whole discovery
  :data:`DISCOVERY_DEADLINE` seconds and :data:`DISCOVERY_FETCHES` requests; a registration
  :data:`REGISTRATION_TIMEOUT` seconds.
- **Errors**: a :class:`FetchError` carries M.2's reason, the host and port, and the status
  when there was one, never a body or a header value. A CONNECT an operator's own proxy refuses
  is :class:`ProxyRefused` (D.11): the onboarding blocks and resumes.

An onboarding that may reach a private server (``allow_private``) has its probe and metadata
requests carry ``netclient.ONBOARDING_EXTENSION``, which the guard honours only for that
server's own ``host:port`` (TI-10). Each request is reported as a :class:`FetchRecord` for
M.4's ``discovery_fetch`` line, which the caller writes.
"""

from __future__ import annotations

import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Final, Literal

import anyio
import httpx

from ... import __version__
from ...common.canonical import JSONRejected, loads_strict
from ..netclient import ONBOARDING_EXTENSION, PRIVATE_PURPOSES, AddressRefused, ResolveFailed
from .discovery import METADATA_MAX, REGISTRATION_MAX, Probe

FETCH_CONNECT: Final = 5.0
FETCH_TIMEOUT: Final = 10.0
DISCOVERY_DEADLINE: Final = 30.0
# 2 probes, 2 protected-resource candidates, 5 authorization server candidates (D.2a's).
DISCOVERY_FETCHES: Final = 9
REGISTRATION_TIMEOUT: Final = 15.0
USER_AGENT: Final = f"zoeymcp/{__version__}"
JSON_TYPE: Final = "application/json"
# What "not here" means for a metadata candidate (D.3); a 3xx too, for a well-known one.
NOT_HERE: Final = frozenset({404, 405, 410})

Kind = Literal["probe", "prm", "as", "register"]
Reason = Literal[
    "address_refused",
    "resolve_failed",
    "fetch_failed",
    "fetch_redirect",
    "fetch_too_large",
    "fetch_not_json",
]

# httpx's text for a refused CONNECT: the status line the proxy answered (contract 46).
_PROXY_STATUS = re.compile(r"([1-5][0-9]{2})(?: .*)?")


class FetchError(Exception):
    """A request that gave discovery nothing to use. ``why`` says more for ``fetch_failed``
    (``status``, ``timeout``, ``deadline``, ``too_many``, ``connect``) and is the guard's verdict
    for ``address_refused``."""

    def __init__(
        self, reason: Reason, host: str, port: int, *, status: int | None = None, why: str = ""
    ) -> None:
        self.reason: Reason = reason
        self.host, self.port, self.status, self.why = host, port, status, why
        super().__init__(f"{reason}: {host}:{port}" + (f" ({why})" if why else ""))


class ProxyRefused(Exception):
    """An operator's own proxy refused the CONNECT to ``host:port``; ``status`` is its answer's
    status, when its text gave one."""

    def __init__(self, host: str, port: int, status: int | None) -> None:
        self.host, self.port, self.status = host, port, status
        super().__init__(f"the proxy refused {host}:{port}")


@dataclass(frozen=True)
class ProbeAnswer:
    """A probe's status and its ``WWW-Authenticate`` values, for ``discovery.parse_challenge``."""

    status: int
    challenges: tuple[str, ...]


@dataclass(frozen=True)
class Fetched:
    """A metadata or registration answer: its status, and the JSON object when it was read."""

    status: int
    document: dict[str, Any] | None


@dataclass(frozen=True)
class FetchRecord:
    """One request, for M.4's ``discovery_fetch`` line: never a URL path, query or body."""

    kind: Kind
    host: str
    port: int
    status: int | None
    bytes: int
    ms: int
    via: Literal["direct", "proxy"]


def _ignore(record: FetchRecord) -> None:
    pass


def _is_json(response: httpx.Response) -> bool:
    media: str = response.headers.get("content-type", "")
    return media.partition(";")[0].strip().lower() == JSON_TYPE


class Fetcher:
    """One discovery's requests: at most :data:`DISCOVERY_FETCHES`, all within
    :data:`DISCOVERY_DEADLINE` seconds of its creation, and the registration after it.
    ``onboarding`` and ``private_target`` set the guard's per-request exception (B.2);
    ``proxied`` says the client goes through ``egress_proxy``; ``report`` is given each
    request's record."""

    def __init__(
        self,
        client: httpx.AsyncClient,
        *,
        proxied: bool = False,
        onboarding: str | None = None,
        private_target: str | None = None,
        clock: Callable[[], float] = time.monotonic,
        report: Callable[[FetchRecord], None] = _ignore,
    ) -> None:
        self._client = client
        self._via: Literal["direct", "proxy"] = "proxy" if proxied else "direct"
        self._onboarding = onboarding
        self._private_target = private_target
        self._clock = clock
        self._report = report
        self._deadline = clock() + DISCOVERY_DEADLINE
        self._count = 0

    async def probe(self, url: str, probe: Probe) -> ProbeAnswer:
        """One fixed probe (D.2): its headers, the User-Agent, and its body. The answer's body
        is never read; a 3xx is ``fetch_redirect``."""
        headers = [*probe.headers, ("User-Agent", USER_AGENT), ("Accept-Encoding", "identity")]

        async def read(response: httpx.Response) -> tuple[ProbeAnswer, int]:
            self._redirect(response, well_known=False)
            values = tuple(response.headers.get_list("www-authenticate"))
            return ProbeAnswer(response.status_code, values), 0

        return await self._discovery_request("probe", "POST", url, headers, probe.body, read)

    async def metadata(self, url: str, kind: Literal["prm", "as"], *, well_known: bool) -> Fetched:
        """A metadata document: a 2xx's JSON object, or a "not here" status (404, 405, 410,
        and a 3xx when ``well_known``) with no document, for the next candidate. Any other
        status is ``fetch_failed`` naming it."""
        headers = [
            ("Accept", JSON_TYPE),
            ("User-Agent", USER_AGENT),
            ("Accept-Encoding", "identity"),
        ]

        async def read(response: httpx.Response) -> tuple[Fetched, int]:
            status = response.status_code
            if 200 <= status < 300:
                document, size = await _json(response, METADATA_MAX)
                return Fetched(status, document), size
            self._redirect(response, well_known=well_known)
            if status in NOT_HERE or 300 <= status < 400:
                return Fetched(status, None), 0
            raise _failed(response, why="status")

        return await self._discovery_request(kind, "GET", url, headers, None, read)

    async def register(self, url: str, body: bytes) -> Fetched:
        """The one registration POST (D.4), within :data:`REGISTRATION_TIMEOUT` seconds and
        outside the discovery's count and deadline. A 2xx must be a JSON object; a 400's object
        is kept for its ``error``, and any other answer is its status alone."""
        headers = [
            ("Content-Type", JSON_TYPE),
            ("Accept", JSON_TYPE),
            ("User-Agent", USER_AGENT),
            ("Accept-Encoding", "identity"),
        ]

        async def read(response: httpx.Response) -> tuple[Fetched, int]:
            status = response.status_code
            self._redirect(response, well_known=False)
            if 200 <= status < 300:
                document, size = await _json(response, REGISTRATION_MAX)
                return Fetched(status, document), size
            if status == 400 and _is_json(response):
                try:
                    document, size = await _json(response, REGISTRATION_MAX)
                except FetchError:
                    return Fetched(status, None), 0
                return Fetched(status, document), size
            return Fetched(status, None), 0

        return await self._send("register", "POST", url, headers, body, REGISTRATION_TIMEOUT, read)

    def _redirect(self, response: httpx.Response, *, well_known: bool) -> None:
        if 300 <= response.status_code < 400 and not well_known:
            raise _error("fetch_redirect", response.request.url, status=response.status_code)

    async def _discovery_request[T](
        self,
        kind: Kind,
        method: str,
        url: str,
        headers: list[tuple[str, str]],
        body: bytes | None,
        read: Callable[[httpx.Response], Awaitable[tuple[T, int]]],
    ) -> T:
        """A request counted against the discovery's limits."""
        target = httpx.URL(url)
        if self._count >= DISCOVERY_FETCHES:
            raise _error("fetch_failed", target, why="too_many")
        budget = min(FETCH_TIMEOUT, self._deadline - self._clock())
        if budget <= 0:
            raise _error("fetch_failed", target, why="deadline")
        self._count += 1
        return await self._send(kind, method, url, headers, body, budget, read)

    async def _send[T](
        self,
        kind: Kind,
        method: str,
        url: str,
        headers: list[tuple[str, str]],
        body: bytes | None,
        budget: float,
        read: Callable[[httpx.Response], Awaitable[tuple[T, int]]],
    ) -> T:
        """Send one request and ``read`` its answer, all within ``budget`` seconds."""
        extensions: dict[str, Any] = {}
        if self._private_target is not None and kind in PRIVATE_PURPOSES:
            extensions[ONBOARDING_EXTENSION] = (self._onboarding, kind, self._private_target)
        request = self._client.build_request(
            method,
            url,
            headers=headers,
            content=body,
            timeout=httpx.Timeout(budget, connect=min(FETCH_CONNECT, budget)),
            extensions=extensions,
        )
        host, port = _host_port(request.url)
        status: int | None = None
        size = 0
        started = self._clock()
        try:
            with anyio.fail_after(budget):
                response = await self._client.send(request, stream=True, follow_redirects=False)
                try:
                    status = response.status_code
                    answer, size = await read(response)
                finally:
                    await response.aclose()
        except FetchError:
            raise
        except AddressRefused as exc:
            raise _error("address_refused", request.url, why=exc.verdict.reason) from None
        except ResolveFailed:
            raise _error("resolve_failed", request.url) from None
        except httpx.ProxyError as exc:
            match = _PROXY_STATUS.fullmatch(str(exc))
            raise ProxyRefused(host, port, int(match[1]) if match else None) from None
        except (TimeoutError, httpx.TimeoutException):
            raise _error("fetch_failed", request.url, status=status, why="timeout") from None
        except httpx.HTTPError:
            raise _error("fetch_failed", request.url, status=status, why="connect") from None
        finally:
            elapsed = int((self._clock() - started) * 1000)
            self._report(FetchRecord(kind, host, port, status, size, elapsed, self._via))
        return answer


def _host_port(url: httpx.URL) -> tuple[str, int]:
    """The host as the guard sees it (IDNA-encoded, lower case) and the port, written out."""
    return url.raw_host.decode("ascii").lower(), url.port or 443


def _error(
    reason: Reason, url: httpx.URL, *, status: int | None = None, why: str = ""
) -> FetchError:
    host, port = _host_port(url)
    return FetchError(reason, host, port, status=status, why=why)


def _failed(response: httpx.Response, *, why: str) -> FetchError:
    return _error("fetch_failed", response.request.url, status=response.status_code, why=why)


async def _json(response: httpx.Response, limit: int) -> tuple[dict[str, Any], int]:
    """The answer's one JSON object, read raw (no decoding) up to ``limit`` bytes: a larger one
    is ``fetch_too_large`` as soon as it shows, by its length or by what arrived."""
    url, status = response.request.url, response.status_code
    if not _is_json(response):
        raise _error("fetch_not_json", url, status=status, why="type")
    length = response.headers.get("content-length", "")
    if length.isdigit() and int(length) > limit:
        raise _error("fetch_too_large", url, status=status)
    chunks: list[bytes] = []
    size = 0
    async for chunk in response.aiter_raw():
        size += len(chunk)
        if size > limit:
            raise _error("fetch_too_large", url, status=status)
        chunks.append(chunk)
    try:
        document = loads_strict(b"".join(chunks), max_bytes=limit)
    except JSONRejected:
        raise _error("fetch_not_json", url, status=status, why="json") from None
    if not isinstance(document, dict):
        raise _error("fetch_not_json", url, status=status, why="object")
    return document, size
