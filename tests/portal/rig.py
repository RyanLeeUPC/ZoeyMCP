"""The portal rig: the real vault, its proxy and its portal, on loopback ports (M5 design O.1).

:func:`running` builds the vault as ``zoeymcp vault`` does (``server.build``: the store, the
portal's state files, the shared ``SetupCodes`` and ``LoginService``, the portal with its static
files) and serves it through ``server.serve``, with ``PortalH11``, on a server thread. Both
listeners' sockets are bound here first and handed to ``serve`` by its binder, so no port is
raced for and the policy names the portal's real port. The fake browser connects to that IP
literal and sends ``Host: localhost:<port>`` itself (verifier V49).

A test may give the portal routes and handlers of its own, shorter head and body deadlines, so
the slowloris cases take a second, not ten, a :class:`Clock` it can move forward, so the
idle limit or the rate bucket's refill takes no waiting, and an onboarding service of its own
over the vault's store and policy, whose client reaches its fakes in process (M7 design K).
"""

from __future__ import annotations

import asyncio
import io
import json
import socket
import threading
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from tests.fakes.browser import Browser, Engine, Slowloris, loopback
from zoeymcp.common import logs as common_logs
from zoeymcp.portal.app import BODY_DEADLINE, Handler, PortalApp, load_static
from zoeymcp.portal.routes import ROUTES, Route
from zoeymcp.portal.server import HEADER_DEADLINE
from zoeymcp.vault import server
from zoeymcp.vault.keys import generate_master_key
from zoeymcp.vault.onboard import OnboardService

STARTUP_TIMEOUT = 10.0


class Clock:
    """The portal's two clocks with an offset a test moves: the limits' monotonic one and the
    sessions' and ceremonies' wall clock."""

    def __init__(self) -> None:
        self.offset = 0.0

    def advance(self, seconds: float) -> None:
        self.offset += seconds

    def monotonic(self) -> float:
        return time.monotonic() + self.offset

    def wall(self) -> float:
        return time.time() + self.offset


class _Lines(io.StringIO):
    """The vault's log lines, written from the server thread and read from the test's."""

    def lines(self) -> list[dict[str, Any]]:
        return [json.loads(line) for line in self.getvalue().splitlines() if line]


@dataclass
class PortalRig:
    state: Path
    policy_file: Path
    environ: dict[str, str]
    portal_port: int
    proxy_port: int
    vault: server.Vault
    portal: server.Portal
    log: _Lines
    loop: asyncio.AbstractEventLoop
    browsers: list[Browser] = field(default_factory=list)

    @property
    def origin(self) -> str:
        return f"http://localhost:{self.portal_port}"

    @property
    def address(self) -> tuple[str, int]:
        return "127.0.0.1", self.portal_port

    @property
    def app(self) -> PortalApp:
        return self.portal.app

    def browser(self, engine: Engine = "chrome", *, every_name: bool = False) -> Browser:
        """A browser profile. ``every_name``: every host and port it opens is the portal, as
        another origin on the same listener or a TLS proxy in front of it would be (C.5)."""
        address = (lambda host, port: self.address) if every_name else loopback
        browser = Browser(engine=engine, address=address)
        self.browsers.append(browser)
        return browser

    def slowloris(self) -> Slowloris:
        return Slowloris(self.address)

    def lines(self, event: str | None = None) -> list[dict[str, Any]]:
        return [line for line in self.log.lines() if event is None or line["event"] == event]

    def logged(
        self, event: str, where: Callable[[dict[str, Any]], bool], timeout: float = 10.0
    ) -> list[dict[str, Any]]:
        """The ``event`` lines ``where`` picks, waiting until there is one. A request is logged
        once its answer is sent, so the client can read the answer before the line is written."""
        deadline = time.monotonic() + timeout
        while True:
            found = [line for line in self.lines(event) if where(line)]
            if found or time.monotonic() > deadline:
                return found
            time.sleep(0.01)

    def call(self, function: Callable[[], Any]) -> Any:
        """Run ``function`` on the vault's loop, as a signal handler would."""

        async def wrapper() -> Any:
            return function()

        return asyncio.run_coroutine_threadsafe(wrapper(), self.loop).result(30)

    def reload(self, document: Mapping[str, Any]) -> None:
        """``SIGHUP`` with ``document`` as the new policy file."""
        self.policy_file.write_text(json.dumps(document), encoding="utf-8")
        self.call(
            lambda: server.reload_policy(
                self.vault.app, str(self.policy_file), self.environ, portal=self.portal
            )
        )


def rig_policy(port: int, *, extra_origins: Sequence[str] = (), **more: Any) -> dict[str, Any]:
    return {
        "version": 1,
        "mode": "declarative",
        "admin": {
            "listen": f"127.0.0.1:{port}",
            "origins": [f"http://localhost:{port}", *extra_origins],
        },
        **more,
    }


def _bound() -> socket.socket:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    return sock


@contextmanager
def running(
    tmp_path: Path,
    *,
    extra_origins: Sequence[str] = (),
    policy: Mapping[str, Any] | Callable[[str], Mapping[str, Any]] | None = None,
    routes: Sequence[Route] = ROUTES,
    handlers: Mapping[Route, Handler] | None = None,
    header_deadline: float = HEADER_DEADLINE,
    body_deadline: float = BODY_DEADLINE,
    before_start: Callable[[Path], None] | None = None,
    clock: Clock | None = None,
    onboard: Callable[[server.Vault], OnboardService] | None = None,
) -> Iterator[PortalRig]:
    """The vault serving its proxy and portal until the block ends. ``policy`` adds to the rig's
    policy (routes, say), or makes what it adds from the portal's origin (a credential whose
    ``redirect_uri`` is a callback address there); ``before_start`` may change the state
    directory first; ``onboard`` makes the onboarding service the portal shares."""
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    portal_sock, proxy_sock = _bound(), _bound()
    portal_port = portal_sock.getsockname()[1]
    proxy_port = proxy_sock.getsockname()[1]
    policy_file = tmp_path / "policy.json"
    more = policy(f"http://localhost:{portal_port}") if callable(policy) else policy
    document = rig_policy(portal_port, extra_origins=extra_origins, **(more or {}))
    policy_file.write_text(json.dumps(document), encoding="utf-8")
    environ = {"ZOEYMCP_MASTER_KEY": generate_master_key()}
    if before_start is not None:
        before_start(state)
    log = _Lines()
    common_logs.set_stream(log)
    listens = [f"127.0.0.1:{proxy_port}"]
    prebound = {("127.0.0.1", portal_port): portal_sock, ("127.0.0.1", proxy_port): proxy_sock}
    try:
        vault = server.build(str(policy_file), listens, state, environ, None)
        assert vault.portal is not None
        app = vault.portal.app
        rebuilt = routes is not ROUTES or handlers is not None or body_deadline != BODY_DEADLINE
        if rebuilt or clock is not None or onboard is not None:
            clocks: dict[str, Callable[[], float]] = (
                {} if clock is None else {"clock": clock.monotonic, "wall": clock.wall}
            )
            app = PortalApp(
                app.origins,
                static=load_static(),
                setup=vault.setup,
                passkeys=vault.passkeys,
                login=vault.login,
                secrets=app.secrets,
                health=app.health,
                ledger=app.ledger,
                source=app.source,
                policy_header=app.policy_header,
                onboard=app.onboard if onboard is None else onboard(vault),
                reviews=app.reviews,
                managed=app.managed,
                routes=routes,
                handlers=handlers,
                body_deadline=body_deadline,
                **clocks,
            )
        portal = replace(vault.portal, app=app, header_deadline=header_deadline)
        stops: list[Callable[[], None]] = []
        loops: list[asyncio.AbstractEventLoop] = []

        def stopper(stop: Callable[[], None]) -> None:
            stops.append(stop)
            loops.append(asyncio.get_running_loop())

        def binder(host: str, port: int) -> list[socket.socket]:
            return [prebound.pop((host, port))]

        main = server.serve(
            vault.app,
            listens,
            config=str(policy_file),
            environ=environ,
            gateway_keys=vault.gateway_keys,
            portal=portal,
            binder=binder,
            stopper=stopper,
        )
        thread = threading.Thread(target=asyncio.run, args=(main,), daemon=True)
        thread.start()
        deadline = time.monotonic() + STARTUP_TIMEOUT
        while not any(line["event"] == "portal_listening" for line in log.lines()):
            if not thread.is_alive() or time.monotonic() > deadline:
                raise RuntimeError(f"the vault didn't start:\n{log.getvalue()}")
            time.sleep(0.01)
        rig = PortalRig(
            state,
            policy_file,
            environ,
            portal_port,
            proxy_port,
            vault,
            portal,
            log,
            loops[0],
        )
        try:
            yield rig
        finally:
            for browser in rig.browsers:
                browser.close()
            loops[0].call_soon_threadsafe(stops[0])
            thread.join(STARTUP_TIMEOUT * 3)
            assert not thread.is_alive(), "the vault didn't stop"
    finally:
        for sock in prebound.values():
            sock.close()
        common_logs.set_stream(None)
