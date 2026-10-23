"""The guarded HTTP clients (M7 design B.2, B.3, B.6). I/O, not mutated: the effect tests in
tests/unit/test_netclient.py and contracts 45 and 46 cover it.

Without ``egress_proxy`` a guarded client's transport is httpx's own over an
``httpcore.AsyncConnectionPool`` whose network backend is :class:`GuardedBackend`: each new
connection resolves its host once, asks :func:`~zoeymcp.common.netguard.addresses_allowed`, and
connects to the first address it allowed, never resolving again for that connection (X3). TLS is
httpcore's on that stream, with the URL's host as ``server_hostname``, so SNI and the certificate
check use the name. A refusal raises :class:`AddressRefused`, a name that doesn't resolve
:class:`ResolveFailed`; both subclass ``httpx.ConnectError``, so a caller that handles a failed
connect fails closed, and each caller maps them to its own answer.

With ``egress_proxy`` the proxy resolves the target and makes the address check (B.3): httpx sends
``CONNECT host:port`` by name and resolves nothing locally (contract 46). The guard never judges
the proxy, which is on an internal network by design.

A private destination is allowed only when its ``host:port`` is in the client's exception set,
read at each connection, or when the request carries :data:`ONBOARDING_EXTENSION` for that exact
``host:port`` (TI-10): an onboarding the operator ticked ``allow_private`` for sets it on its own
probe and PRM fetches. Such a request gets a connection of its own, closed with its answer, so no
other request, another onboarding's included, ever reuses a connection the exception allowed.

Every client verifies against certifi's roots, through one ``ssl_context`` per client built from
``certifi.where()`` (B.6, X23), as the SMTP connector's ``default_tls`` does. Each is built once,
at start, from the startup policy, so a reload that changes ``egress_proxy`` changes no client
(D-61). Every client the vault uses is built here: the onboarding client, the revocation client
(M7 design D.9), and the route and token clients (B.2's second stage). The last three read the
running policy's ``egress_private`` at each connection, so a reload that lists a destination
lets the next connection through without a restart.

A local MCP route (M7 design A.2 row 9) goes through :func:`local_client`, direct and never
proxied, whose backend allows a connection only when every address the name resolves to is
loopback or private (``netguard.local_only``), and reads no exception set: the egress lists never
name a local route, so a bridge is reached neither through the role nor through an operator's
proxy, and its name can't be steered to a global address. A ``unix:`` route (Q46) goes through
:class:`SocketClients`: one client per bridge the launcher named (``--bridge NAME=UID``), over a
pool on that bridge's socket, whose backend reads the listener's uid from the connected socket
(``SO_PEERCRED``) and closes the connection unless it is the uid the launcher gave that bridge
(``netguard.unix_peer``), so nothing is written to a socket another uid planted. Every bridge's
request base is :data:`BRIDGE_BASE`: the client is chosen by the bridge's name, never by host.

Tests answer names through :data:`HOOKS` (BP-1): a resolver that maps names to addresses reserved
for the run, and a ``dial`` that sends a checked address to the loopback port of the right fake,
so the guard runs unchanged on every test connection; ``socket_path`` puts a bridge's socket in a
test directory while the policy keeps the fixed form. Production never sets it.
"""

from __future__ import annotations

import socket
import ssl
from collections.abc import (
    AsyncIterator,
    Awaitable,
    Callable,
    Collection,
    Iterable,
    Mapping,
    Sequence,
)
from dataclasses import dataclass
from typing import Final

import anyio
import certifi
import httpcore
import httpx

from ..common import netguard
from ..common.netguard import AddressVerdict
from ..common.policy import fields
from .oauth.protocol import ATTEMPT_DEADLINE
from .oauth.protocol import CONNECT_TIMEOUT as TOKEN_CONNECT_TIMEOUT
from .peer import peer_uid

# One lookup's limit, in seconds (M.6).
RESOLVE_TIMEOUT: Final = 5.0
# The onboarding client's defaults, B.5's per-fetch numbers; vault/oauth/fetch.py bounds each
# whole fetch, and a discovery, on top of them.
ONBOARDING_TIMEOUT: Final = httpx.Timeout(10.0, connect=5.0)
# The revocation client's: the whole of one revocation is REVOKE_TIMEOUT (vault/secretops.py).
REVOCATION_TIMEOUT: Final = httpx.Timeout(10.0, connect=5.0)
# The token client's (design D.14); each call sets its own deadline (TokenManager.post).
TOKEN_TIMEOUT: Final = httpx.Timeout(ATTEMPT_DEADLINE, connect=TOKEN_CONNECT_TIMEOUT)
# A route's 502 code, a token call's failure reason, and the onboarding refusal (M7 design B.2).
ADDRESS_REFUSED: Final = "address_refused"
# The per-request exception (TI-10): (onboarding id, purpose, host:port).
ONBOARDING_EXTENSION: Final = "zoeymcp.onboarding"
# The fetches an onboarding's exception may cover: the probe of the server URL and its PRM. Never
# the AS metadata, registration or an endpoint.
PRIVATE_PURPOSES: Final = frozenset({"probe", "prm"})
# A unix: route's request base, the same for every bridge (M.6): its client is chosen by the
# bridge's name, so Host is never what picks a socket. The bridge ignores Host.
BRIDGE_BASE: Final = "http://bridge.invalid"
_DEFAULT_PORTS: Final = {"http": 80, "https": 443}

# A name and port to its addresses; raises OSError (or TimeoutError) when it doesn't resolve.
Resolver = Callable[[str, int], Awaitable[Sequence[str]]]
# A checked address and port to the address and port actually connected to.
Dial = Callable[[str, int], tuple[str, int]]
# A bridge's name to the path of its socket.
SocketPath = Callable[[str], str]


@dataclass(frozen=True)
class Hooks:
    """Test-only stand-ins for the resolver, the connect target and a bridge's socket (BP-1)."""

    resolver: Resolver | None = None
    dial: Dial | None = None
    socket_path: SocketPath | None = None


# Set only by tests: tests/acceptance/procs.py's launcher in an out-of-process vault, as it
# patches certifi.where, and in-process tests through monkeypatch. The builders read it.
HOOKS: Hooks | None = None


class AddressRefused(httpx.ConnectError):
    """The destination's name resolved to an address the guard refuses; nothing was sent."""

    def __init__(self, host: str, port: int, verdict: AddressVerdict) -> None:
        self.host, self.port, self.verdict = host, port, verdict
        super().__init__(f"{netguard.entry_key(host, port)}: address refused ({verdict.reason})")


class SocketRefused(httpx.ConnectError):
    """A bridge's socket was refused: its listener isn't the uid the launcher gave that bridge,
    or the kernel didn't say. The connection was closed with nothing written."""

    def __init__(self, bridge: str, verdict: AddressVerdict, uid: int | None) -> None:
        self.bridge, self.verdict, self.uid = bridge, verdict, uid
        super().__init__(f"bridge {bridge}: socket refused ({verdict.reason})")


class ResolveFailed(httpx.ConnectError):
    """The destination's name didn't resolve in time, or at all; nothing was sent."""

    def __init__(self, host: str, port: int) -> None:
        self.host, self.port = host, port
        super().__init__(f"{netguard.entry_key(host, port)}: the name didn't resolve")


def guard_key(host: str, port: int) -> str:
    """The ``egress_private`` entry that lists ``host``:``port`` as :class:`GuardedBackend` is
    given it, the URL's ``raw_host``: in lower case, without a trailing dot (``lan.example.``
    names ``lan.example``, and the schema takes no entry that ends in one)."""
    return netguard.entry_key(host.removesuffix("."), port)


def destination_key(url: str) -> str:
    """An http(s) URL's ``host:port`` as the guard sees it, so as ``egress_private`` must list
    it: the IDNA-encoded ``raw_host``, never httpx's decoded ``host`` (as for
    :func:`onboarding_target`), and the default port written out."""
    parsed = httpx.URL(url)
    port = parsed.port or _DEFAULT_PORTS.get(parsed.scheme, 443)
    return guard_key(parsed.raw_host.decode("ascii"), port)


def private_hint(key: str) -> str:
    """What an ``address_refused`` asks the operator to do about the ``host:port`` ``key``."""
    return f"list {key} in egress_private if this destination is meant to be private"


async def resolve(host: str, port: int) -> list[str]:
    """Every address ``host`` resolves to for a stream socket, in the resolver's order, once
    each; ``getaddrinfo`` runs in a worker thread, for at most :data:`RESOLVE_TIMEOUT` seconds."""
    with anyio.fail_after(RESOLVE_TIMEOUT):
        infos = await anyio.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(str(info[4][0]) for info in infos))


def _no_exceptions() -> Collection[str]:
    return frozenset()


class GuardedBackend(httpcore.AsyncNetworkBackend):
    """httpcore's network backend with X3's rule on every TCP connection. ``exceptions`` is
    read at each connection: the ``host:port`` entries allowed to resolve to non-global
    addresses. With ``local_only`` (a local MCP route's client) every address must be loopback
    or private instead, and no exception is read. With ``bridge`` and ``expected_uid`` (a
    bridge's socket client) a Unix socket connection is kept only when its peer is that uid.
    ``resolver`` and ``dial`` are for tests only (BP-1)."""

    def __init__(
        self,
        exceptions: Callable[[], Collection[str]] = _no_exceptions,
        *,
        resolver: Resolver | None = None,
        dial: Dial | None = None,
        local_only: bool = False,
        bridge: str = "",
        expected_uid: int | None = None,
    ) -> None:
        self._exceptions = exceptions
        self._resolver = resolver or resolve
        self._dial = dial
        self._local_only = local_only
        self._bridge, self._expected_uid = bridge, expected_uid
        self._backend = httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        try:
            addresses = await self._resolver(host, port)
        except (OSError, TimeoutError, UnicodeError) as exc:
            raise ResolveFailed(host, port) from exc
        if self._local_only:
            verdict = netguard.local_only(addresses)
        else:
            exceptions = self._exceptions()
            # The name exactly (an onboarding's exception), or as an entry writes it (guard_key).
            listed = netguard.listed(exceptions, host, port) or guard_key(host, port) in exceptions
            verdict = netguard.addresses_allowed(addresses, private_ok=listed)
        if not verdict.allowed or verdict.address is None:
            raise AddressRefused(host, port, verdict)
        # The checked addresses, never the name again: a second lookup could answer otherwise.
        # Each was checked, so the next is tried when one doesn't connect (an IPv6 address first
        # for a service that listens on IPv4 only), in the resolver's order.
        last = len(addresses) - 1
        for index, checked in enumerate(addresses):
            address, target_port = checked, port
            if self._dial is not None:
                address, target_port = self._dial(address, port)
            try:
                return await self._backend.connect_tcp(
                    address,
                    target_port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except (OSError, httpcore.ConnectError, httpcore.ConnectTimeout):
                if index == last:
                    raise
        raise ResolveFailed(host, port)  # unreachable: the verdict allowed a non-empty list

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        if self._expected_uid is None:  # no bridge of this name: never connect at all
            raise SocketRefused(self._bridge, netguard.unix_peer(None, None), None)
        stream = await self._backend.connect_unix_socket(
            path, timeout=timeout, socket_options=socket_options
        )
        # The listener's uid, from the connected socket, before a byte is written to it.
        uid = peer_uid(stream.get_extra_info("socket"))
        verdict = netguard.unix_peer(uid, self._expected_uid)
        if not verdict.allowed:
            await stream.aclose()
            raise SocketRefused(self._bridge, verdict, uid)
        return stream

    async def sleep(self, seconds: float) -> None:
        await self._backend.sleep(seconds)


def _pooled(
    context: ssl.SSLContext,
    backend: GuardedBackend,
    *,
    keepalive: bool,
    uds: str | None = None,
) -> httpx.AsyncHTTPTransport:
    """httpx's transport, for its request and error mapping, over a pool with ``backend``, on
    the Unix socket ``uds`` when given."""
    transport = httpx.AsyncHTTPTransport(verify=context, trust_env=False)
    limits = httpx.Limits() if keepalive else httpx.Limits(max_keepalive_connections=0)
    transport._pool = httpcore.AsyncConnectionPool(
        ssl_context=context,
        max_connections=limits.max_connections,
        max_keepalive_connections=limits.max_keepalive_connections,
        keepalive_expiry=limits.keepalive_expiry,
        uds=uds,
        network_backend=backend,
    )
    return transport


def onboarding_target(request: httpx.Request) -> str | None:
    """The ``host:port`` a request's :data:`ONBOARDING_EXTENSION` lifts the guard for: only an
    exception for a probe or PRM fetch, naming exactly the request's own ``host:port``. Anything
    else is no exception at all. The host is the one :class:`GuardedBackend` is given, the URL's
    ``raw_host`` (IDNA-encoded), never ``host``, which httpx decodes for an ``xn--`` name."""
    value = request.extensions.get(ONBOARDING_EXTENSION)
    if not (isinstance(value, tuple) and len(value) == 3):
        return None
    _, purpose, target = value
    port = request.url.port or _DEFAULT_PORTS.get(request.url.scheme)
    if purpose not in PRIVATE_PURPOSES or port is None:
        return None
    host = request.url.raw_host.decode("ascii")
    if not isinstance(target, str) or target != netguard.entry_key(host, port):
        return None
    return target


class _ClosingStream(httpx.AsyncByteStream):
    """An answer's body that closes the transport made for it once it is closed."""

    def __init__(self, stream: httpx.AsyncByteStream, transport: httpx.AsyncBaseTransport) -> None:
        self._stream, self._transport = stream, transport

    async def __aiter__(self) -> AsyncIterator[bytes]:
        async for chunk in self._stream:
            yield chunk

    async def aclose(self) -> None:
        try:
            await self._stream.aclose()
        finally:
            await self._transport.aclose()


class GuardedTransport(httpx.AsyncBaseTransport):
    """The transport of a guarded client without a proxy: one pool for every request, and a
    connection of its own for a request carrying an onboarding's exception (TI-10)."""

    def __init__(
        self,
        context: ssl.SSLContext,
        exceptions: Callable[[], Collection[str]] = _no_exceptions,
        *,
        resolver: Resolver | None = None,
        dial: Dial | None = None,
    ) -> None:
        self._context = context
        self._resolver, self._dial = resolver, dial
        backend = GuardedBackend(exceptions, resolver=resolver, dial=dial)
        self._shared = _pooled(context, backend, keepalive=True)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        target = onboarding_target(request)
        if target is None:
            return await self._shared.handle_async_request(request)
        backend = GuardedBackend(lambda: (target,), resolver=self._resolver, dial=self._dial)
        single = _pooled(self._context, backend, keepalive=False)
        try:
            response = await single.handle_async_request(request)
        except BaseException:
            await single.aclose()
            raise
        assert isinstance(response.stream, httpx.AsyncByteStream)  # noqa: S101 - httpx's own
        return httpx.Response(
            status_code=response.status_code,
            headers=response.headers,
            stream=_ClosingStream(response.stream, single),
            extensions=response.extensions,
        )

    async def aclose(self) -> None:
        await self._shared.aclose()


def ssl_context() -> ssl.SSLContext:
    """certifi's roots, names checked (B.6): every guarded client's, one per client."""
    return ssl.create_default_context(cafile=certifi.where())


def guarded_transport(
    egress_proxy: str | None, exceptions: Callable[[], Collection[str]] = _no_exceptions
) -> httpx.AsyncBaseTransport:
    """A guarded client's transport: through ``egress_proxy`` when it is set (B.3), else
    :class:`GuardedTransport` with ``exceptions``."""
    context = ssl_context()
    if egress_proxy is not None:
        # CONNECT by name: the proxy resolves the target and judges its address.
        return httpx.AsyncHTTPTransport(verify=context, proxy=egress_proxy, trust_env=False)
    hooks = HOOKS or Hooks()
    return GuardedTransport(context, exceptions, resolver=hooks.resolver, dial=hooks.dial)


def onboarding_client(egress_proxy: str | None) -> httpx.AsyncClient:
    """Discovery's and registration's client (B.2's first stage): hosts learned from the
    network. Its own exception set is empty; a typed server's private exception comes per
    request (:data:`ONBOARDING_EXTENSION`). No redirects, no proxy variables; the vault gives it
    a jar that keeps no cookies."""
    return httpx.AsyncClient(
        transport=guarded_transport(egress_proxy),
        trust_env=False,
        follow_redirects=False,
        timeout=ONBOARDING_TIMEOUT,
    )


def revocation_client(
    egress_proxy: str | None, exceptions: Callable[[], Collection[str]]
) -> httpx.AsyncClient:
    """The client a deleted refresh token's revocation is posted on (M7 design D.9). Its
    exception set is the running policy's ``egress_private``, read at each connection, as the
    token client's is, so a token origin listed there revokes as it refreshes (TI-11). No
    redirects, no proxy variables; the vault gives it a jar that keeps no cookies."""
    return httpx.AsyncClient(
        transport=guarded_transport(egress_proxy, exceptions),
        trust_env=False,
        follow_redirects=False,
        timeout=REVOCATION_TIMEOUT,
    )


def route_client(
    egress_proxy: str | None, exceptions: Callable[[], Collection[str]], *, timeout: httpx.Timeout
) -> httpx.AsyncClient:
    """The client every route's upstream is reached on (B.2's second stage). Its exception set
    is the running policy's ``egress_private``, read at each connection; each request sets its
    own timeout, ``timeout`` is the default. No redirects (the vault relays a 3xx as it is, or
    refuses it for the gateway), no proxy variables; the vault gives it a jar that keeps no
    cookies."""
    return httpx.AsyncClient(
        transport=guarded_transport(egress_proxy, exceptions),
        trust_env=False,
        follow_redirects=False,
        timeout=timeout,
    )


def token_client(
    egress_proxy: str | None, exceptions: Callable[[], Collection[str]]
) -> httpx.AsyncClient:
    """The client login, refresh and the code exchange post to token endpoints on (B.2's
    second stage, design D.14). Its exception set is the running policy's ``egress_private``,
    read at each connection, as the revocation client's is (TI-11). A redirect would re-send
    secrets, so none is followed; no proxy variables; the vault gives it a jar that keeps no
    cookies."""
    return httpx.AsyncClient(
        transport=guarded_transport(egress_proxy, exceptions),
        trust_env=False,
        follow_redirects=False,
        timeout=TOKEN_TIMEOUT,
    )


def local_client(*, timeout: httpx.Timeout) -> httpx.AsyncClient:
    """The client a local MCP route's upstream is reached on (M7 design B.2): direct, never
    proxied, whatever ``egress_proxy`` says, and only to loopback or private addresses
    (``netguard.local_only``), with no exception set. The vault picks it for a route that is a
    local MCP route in the running policy, so a reload that adds one needs no restart. No
    redirects, no proxy variables; the vault gives it a jar that keeps no cookies."""
    hooks = HOOKS or Hooks()
    backend = GuardedBackend(local_only=True, resolver=hooks.resolver, dial=hooks.dial)
    return httpx.AsyncClient(
        transport=_pooled(ssl_context(), backend, keepalive=True),
        trust_env=False,
        follow_redirects=False,
        timeout=timeout,
    )


class SocketClients:
    """The clients ``unix:`` routes are reached on (M7 design B.2, Q46): one per bridge the
    launcher named on the vault's command line (``--bridge NAME=UID``), built at start, each
    over a pool on that bridge's socket whose backend keeps a connection only when its listener
    is that uid. Called with a bridge's name, it gives that bridge's client, or None for a name
    the launcher didn't start (``unknown_socket``). Direct, never proxied, no redirects, no proxy
    variables; the vault gives each a jar that keeps no cookies."""

    def __init__(self, bridges: Mapping[str, int], *, timeout: httpx.Timeout) -> None:
        hooks = HOOKS or Hooks()
        where = hooks.socket_path or fields.bridge_socket
        self._clients: dict[str, httpx.AsyncClient] = {}
        for name, uid in bridges.items():
            backend = GuardedBackend(bridge=name, expected_uid=uid)
            self._clients[name] = httpx.AsyncClient(
                transport=_pooled(ssl_context(), backend, keepalive=True, uds=where(name)),
                trust_env=False,
                follow_redirects=False,
                timeout=timeout,
            )

    def __call__(self, name: str) -> httpx.AsyncClient | None:
        return self._clients.get(name)

    async def aclose(self) -> None:
        for client in self._clients.values():
            await client.aclose()
