"""The acceptance rig: real HTTPS fakes, the real vault on a real socket, shipped profiles."""

from __future__ import annotations

import asyncio
import json
import threading
import time
from collections.abc import Callable, Coroutine, Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any, TypeVar

import httpx
import pytest
import uvicorn
from starlette.types import ASGIApp, Receive, Scope, Send

from zoeymcp.common.policy import Policy, check_policy
from zoeymcp.common.yamlload import load_mapping
from zoeymcp.portal.app import Ledger, PortalApp, Secrets, load_static
from zoeymcp.portal.passkeys import Passkeys
from zoeymcp.portal.server import HEAD_LIMIT, portal_protocol
from zoeymcp.vault.admin import AdminApp, HealthReader, SetupCodes
from zoeymcp.vault.app import VaultApp, without_cookies
from zoeymcp.vault.bindings import derive_binding
from zoeymcp.vault.connectors.smtp import SmtpConnectors
from zoeymcp.vault.keys import KeySet, generate_master_key
from zoeymcp.vault.oauth.login import LoginService
from zoeymcp.vault.oauth.tokens import TokenManager
from zoeymcp.vault.peer import peer_checked
from zoeymcp.vault.reportstore import ReportStore
from zoeymcp.vault.server import ListenerTag
from zoeymcp.vault.store import SecretStore

from .procs import free_port
from .tls import ProviderCA, make_ca

PROFILES = Path(__file__).resolve().parents[2] / "profiles"
BASE: dict[str, Any] = {
    "version": 1,
    "mode": "declarative",
}
STARTUP_TIMEOUT = 10.0
# Responses still open when a server stops are cut after this many seconds.
SHUTDOWN_GRACE = 1
# Taken before any test patches httpx.HTTPTransport to reach the admin app.
_HTTPTransport = httpx.HTTPTransport

T = TypeVar("T")


@pytest.fixture(scope="session")
def ca(tmp_path_factory: pytest.TempPathFactory) -> ProviderCA:
    return make_ca(tmp_path_factory.mktemp("tls"))


class _Server(uvicorn.Server):
    def install_signal_handlers(self) -> None:
        pass


def _wait_started(servers: list[_Server], thread: threading.Thread) -> list[int]:
    deadline = time.monotonic() + STARTUP_TIMEOUT
    while not all(server.started for server in servers):
        if not thread.is_alive() or time.monotonic() > deadline:
            raise RuntimeError("server failed to start")
        time.sleep(0.01)
    return [server.servers[0].sockets[0].getsockname()[1] for server in servers]


@contextmanager
def serve_tls(app: ASGIApp, ca: ProviderCA, *, lifespan: bool = False) -> Iterator[str]:
    """``lifespan`` runs the app's ASGI lifespan (the fake MCP server needs it)."""
    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=0,
        ssl_certfile=str(ca.cert_file),
        ssl_keyfile=str(ca.key_file),
        log_level="warning",
        lifespan="on" if lifespan else "off",
        timeout_graceful_shutdown=SHUTDOWN_GRACE,
    )
    server = _Server(config)
    thread = threading.Thread(target=lambda: asyncio.run(server.serve()), daemon=True)
    thread.start()
    [port] = _wait_started([server], thread)
    try:
        yield f"https://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(STARTUP_TIMEOUT)


class Clock:
    """Time a test can move forward. The vault and the fakes read it, so they agree on it."""

    def __init__(self) -> None:
        self.offset = 0.0

    def monotonic(self) -> float:
        return time.monotonic() + self.offset

    def wall(self) -> float:
        return time.time() + self.offset

    def advance(self, seconds: float) -> None:
        self.offset += seconds


def tls_client(ca: ProviderCA) -> httpx.AsyncClient:
    """A vault client that trusts the test CA only.

    No keep-alive: the vault runs on a server thread whose loop stops before the fakes do, and
    an idle TLS connection left behind would stall the fake's shutdown.
    """
    return httpx.AsyncClient(
        verify=ca.client_context(),
        trust_env=False,
        follow_redirects=False,
        limits=httpx.Limits(max_keepalive_connections=0),
    )


class AdminTransport(httpx.BaseTransport):
    """The CLI's admin requests, sent to the admin app on a loopback port instead of a socket.

    Unix sockets don't exist on Windows; the requests and answers are the same.
    """

    def __init__(self, base_url: str) -> None:
        self._url = httpx.URL(base_url)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        request.url = request.url.copy_with(
            scheme=self._url.scheme, host=self._url.host, port=self._url.port
        )
        with _HTTPTransport() as transport:
            response = transport.handle_request(request)
            response.read()
        return response


class Deployment:
    """A shipped profile, with its upstream pointed at a fake, behind a real vault.

    The vault's proxy and admin apps share one event loop on a server thread, as in
    ``zoeymcp vault``. Its token client trusts the test CA, and its clocks are ``clock``.
    ``replace`` stays applied to every later ``load`` and ``restart``, so a profile's real
    provider endpoints never come back.

    With ``portal``, the vault also serves its portal (M5 design B) on a loopback port of its
    own, at :attr:`portal_origin`, sharing the admin app's setup codes, logins, store and token
    manager, as ``zoeymcp vault`` shares them; the sessions keep the real clock.

    With ``reports``, the vault keeps a copy of the gateway's ledger, which its report path
    writes and the portal's Ledger page and health read with the SMTP connectors' journals (M5
    design J). ``extra`` is a policy fragment merged into the profile's, its routes keeping
    their own upstreams (another profile, say). A policy with SMTP connectors gets connectors
    that trust the test CA.
    """

    def __init__(
        self,
        tmp_path: Path,
        profile: str,
        upstream: str,
        ca: ProviderCA,
        *,
        secrets: dict[str, str],
        replace: dict[str, str] | None = None,
        environ: Mapping[str, str] | None = None,
        clock: Clock | None = None,
        link_socket: Path | None = None,
        link_uid: int | None = None,
        portal: bool = False,
        reports: bool = False,
        extra: Mapping[str, Any] | None = None,
    ) -> None:
        self.state = tmp_path
        self.with_reports = reports
        self.extra = dict(extra or {})
        self.portal_port = free_port() if portal else None
        # The standard tier's link: the gateway's socket, and the uid allowed on it (Linux).
        self.link_socket = link_socket
        self.link_uid = link_uid
        self.ca = ca
        self.upstream = upstream
        self.clock = clock or Clock()
        self.text = (PROFILES / profile).read_text(encoding="utf-8")
        self.environ = dict(environ or {})
        self.replace = dict(replace or {})
        self.policy = self.load(check_env=environ is not None)
        self.keys = KeySet.from_text(generate_master_key())
        store = SecretStore(tmp_path, self.keys)
        store.load()
        for name, value in secrets.items():
            store.put(name, value, derive_binding(self.policy, name))
        self._build(store)
        # Empty for a route only the gateway may call.
        self.placeholder = next(
            (c.placeholder for c in self.policy.routes[0].callers if not isinstance(c, str)), ""
        )
        self.prefix = self.policy.routes[0].prefix
        self.admin_url: str | None = None
        self.arrived = 0  # requests that reached the vault's proxy app
        self._loop: asyncio.AbstractEventLoop | None = None

    def load(
        self,
        replace: dict[str, str] | None = None,
        *,
        upstream: str | None = None,
        check_env: bool = False,
    ) -> Policy:
        """The profile with the constructor's ``replace``, then this ``replace``, applied and its
        routes sent to the fake, checked.

        ``document`` becomes the whole policy as text, for a reload from a file.
        """
        text = self.text
        for old, new in {**self.replace, **(replace or {})}.items():
            assert old in text, f"{old!r} not in the profile"
            text = text.replace(old, new)
        fragment = load_mapping(text)
        for route in fragment["routes"]:
            route["upstream"] = upstream or self.upstream
        if self.extra:
            from .toolkits import _merge  # here: toolkits imports this module

            fragment = _merge(fragment, self.extra)
        self.document = json.dumps({**BASE, **fragment})
        policy = Policy.model_validate({**BASE, **fragment})
        findings = check_policy(policy, environ=self.environ if check_env else None)
        errors = [f for f in findings if f.level == "error"]
        assert errors == [], errors
        return policy

    def _build(self, store: SecretStore) -> None:
        self.store = store
        # Recovered before anything listens, as ``zoeymcp vault`` does (M5 design J.4).
        self.reports = ReportStore.open(self.state) if self.with_reports else None
        connectors = None
        if self.policy.connectors:
            connectors = SmtpConnectors(self.state, self.keys, tls=self.ca.client_context())
        self.token_client = without_cookies(tls_client(self.ca))
        self.tokens = TokenManager(
            store, self.token_client, clock=self.clock.monotonic, wall=self.clock.wall
        )
        self.app = VaultApp(
            self.policy,
            store,
            self.keys,
            client=tls_client(self.ca),
            tokens=self.tokens,
            environ=self.environ,
            gateway_link=self.link_socket is not None,
            connectors=connectors,
            reports=self.reports,
        )
        self.login = LoginService(self.tokens, clock=self.clock.monotonic, wall=self.clock.wall)
        self.setup = SetupCodes(self.state, self.keys.portal_key)
        self.admin = AdminApp(
            store,
            self.keys,
            lambda: self.app.policy,
            self.setup,
            self.tokens,
            self.login,
        )
        self.portal: PortalApp | None = None
        if self.portal_port is not None:
            passkeys = Passkeys.load(self.state, self.keys.portal_key)
            copy: dict[str, Any] = {}
            ledger = None
            if self.reports is not None:
                copy = {"reports": self.reports, "connectors": self.app.connectors}
                ledger = Ledger(self.reports, self.app.connectors)
            self.portal = PortalApp(
                [self.portal_origin],
                static=load_static(),
                setup=self.setup,
                passkeys=passkeys,
                login=self.login,
                secrets=Secrets(store, self.tokens, lambda: self.app.policy),
                health=HealthReader(
                    store, lambda: self.app.policy, self.login, passkeys=passkeys, **copy
                ).report,
                ledger=ledger,
            )

    @property
    def portal_origin(self) -> str:
        assert self.portal_port is not None, "this vault has no portal"
        return f"http://localhost:{self.portal_port}"

    def restart(
        self, *, environ: Mapping[str, str] | None = None, replace: dict[str, str] | None = None
    ) -> None:
        """A new vault process on the same state directory: only the store file carries over."""
        if environ is not None:
            self.environ = dict(environ)
        self.policy = self.load(replace, check_env=True)
        store = SecretStore(self.state, self.keys)
        store.load()
        self._build(store)

    def admin_transport(self) -> AdminTransport:
        assert self.admin_url is not None, "the vault isn't running"
        return AdminTransport(self.admin_url)

    def call(self, function: Callable[[], T]) -> T:
        """Run ``function`` on the vault's loop, as a signal handler would. Returns its result."""

        async def wrapper() -> T:
            return function()

        return self.run(wrapper())

    def run(self, coroutine: Coroutine[Any, Any, T]) -> T:
        """Run ``coroutine`` on the vault's loop and wait for it."""
        assert self._loop is not None, "the vault isn't running"
        return asyncio.run_coroutine_threadsafe(coroutine, self._loop).result(60)

    @contextmanager
    def running(self) -> Iterator[httpx.Client]:
        """Serve the vault and its admin app. Stopping drains refreshes in flight (N5)."""
        app, token_client = self.app, self.token_client

        async def counted(scope: Scope, receive: Receive, send: Send) -> None:
            if scope["type"] == "http":
                self.arrived += 1
            await app(scope, receive, send)

        servers = [
            _Server(
                uvicorn.Config(asgi, host="127.0.0.1", port=0, log_level="warning", lifespan="off")
            )
            for asgi in (ListenerTag(counted, "tcp"), self.admin.app)
        ]
        if self.link_socket is not None and self.link_uid is not None:
            link = _Server(
                uvicorn.Config(
                    ListenerTag(counted, "gateway"),
                    uds=str(self.link_socket),
                    http=peer_checked(self.link_uid),
                    log_level="warning",
                    lifespan="off",
                )
            )
        portals = []
        if self.portal is not None:
            portals.append(
                _Server(
                    uvicorn.Config(
                        self.portal,
                        host="127.0.0.1",
                        port=self.portal_port or 0,
                        log_level="warning",
                        lifespan="off",
                        http=portal_protocol(),
                        h11_max_incomplete_event_size=HEAD_LIMIT,
                        proxy_headers=False,
                    )
                )
            )
        loop = asyncio.new_event_loop()

        everything = [*servers, link] if self.link_socket is not None else [*servers]
        everything += portals

        async def main() -> None:
            try:
                await asyncio.gather(*(server.serve() for server in everything))
            finally:
                await app.aclose()
                await token_client.aclose()

        thread = threading.Thread(target=loop.run_until_complete, args=(main(),), daemon=True)
        thread.start()
        vault_port, admin_port = _wait_started(servers, thread)
        _wait_started(portals, thread)
        self._loop = loop
        self.admin_url = f"http://127.0.0.1:{admin_port}"
        try:
            with httpx.Client(base_url=f"http://127.0.0.1:{vault_port}", timeout=60) as client:
                yield client
        finally:
            for server in everything:
                server.should_exit = True
            thread.join(STARTUP_TIMEOUT * 6)
            self._loop = None
            self.admin_url = None
            if not thread.is_alive():
                loop.close()
