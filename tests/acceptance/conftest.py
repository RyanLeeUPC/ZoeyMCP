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
from zoeymcp.vault.admin import AdminApp, SetupCodes
from zoeymcp.vault.app import VaultApp, without_cookies
from zoeymcp.vault.bindings import derive_binding
from zoeymcp.vault.keys import KeySet, generate_master_key
from zoeymcp.vault.oauth.login import LoginService
from zoeymcp.vault.oauth.tokens import TokenManager
from zoeymcp.vault.store import SecretStore

from .tls import ProviderCA, make_ca

PROFILES = Path(__file__).resolve().parents[2] / "profiles"
BASE: dict[str, Any] = {
    "version": 1,
    "mode": "declarative",
    "admin": {"listen": "0.0.0.0:8081", "hosts": ["localhost"]},
}
STARTUP_TIMEOUT = 10.0
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
def serve_tls(app: ASGIApp, ca: ProviderCA) -> Iterator[str]:
    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=0,
        ssl_certfile=str(ca.cert_file),
        ssl_keyfile=str(ca.key_file),
        log_level="warning",
        lifespan="off",
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
    ) -> None:
        self.state = tmp_path
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
        self.placeholder = next(
            c.placeholder for c in self.policy.routes[0].callers if not isinstance(c, str)
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
        self.document = json.dumps({**BASE, **fragment})
        policy = Policy.model_validate({**BASE, **fragment})
        findings = check_policy(policy, environ=self.environ if check_env else None)
        errors = [f for f in findings if f.level == "error"]
        assert errors == [], errors
        return policy

    def _build(self, store: SecretStore) -> None:
        self.store = store
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
        )
        login = LoginService(self.tokens, clock=self.clock.monotonic, wall=self.clock.wall)
        self.admin = AdminApp(
            store, self.keys, lambda: self.app.policy, SetupCodes(self.state), self.tokens, login
        )

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
            for asgi in (counted, self.admin.app)
        ]
        loop = asyncio.new_event_loop()

        async def main() -> None:
            try:
                await asyncio.gather(*(server.serve() for server in servers))
            finally:
                await app.aclose()
                await token_client.aclose()

        thread = threading.Thread(target=loop.run_until_complete, args=(main(),), daemon=True)
        thread.start()
        vault_port, admin_port = _wait_started(servers, thread)
        self._loop = loop
        self.admin_url = f"http://127.0.0.1:{admin_port}"
        try:
            with httpx.Client(base_url=f"http://127.0.0.1:{vault_port}", timeout=60) as client:
                yield client
        finally:
            for server in servers:
                server.should_exit = True
            thread.join(STARTUP_TIMEOUT * 6)
            self._loop = None
            self.admin_url = None
            if not thread.is_alive():
                loop.close()


def wait_until(condition: Callable[[], bool], timeout: float = 10.0) -> None:
    """Poll ``condition`` from the test thread until it holds."""
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() > deadline:
            raise AssertionError("condition not met in time")
        time.sleep(0.01)
