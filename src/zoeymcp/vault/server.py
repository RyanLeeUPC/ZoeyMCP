"""Running the vault: ``zoeymcp vault`` (design §4, §4.6).

Startup refuses to run with a missing or malformed master key, a policy that fails ``check``, a
store written under an unknown key, a gateway key state that fails its MAC or would go backwards,
or a state directory another vault is using. ``SIGHUP`` reloads the policy; a policy that fails
validation, or whose gateway key generation went backwards or can't be written, is rejected and
the running one stays. Both read the policy through the one gate (``common/policy/gate.py``,
M6 design C), and a reload names what needs a restart from the restart classifier
(``common/policy/restart.py``, I.2).

In the standard tier (M3 design B.2, C.1) the vault also listens on the link socket, where only
the gateway's uid may connect, and may have no TCP listener at all (``--listen none``). The
launcher can't signal the vault's uid, so it writes ``HUP`` and ``TERM`` to a control pipe
instead; the end of that pipe stops the vault too. The launcher also names each bridge it starts
(``--bridge NAME=UID``, M7 design C.10): the vault reaches a ``unix:`` route's bridge only on that
bridge's socket, and only when its listener is that uid (B.2, Q46).

Every TCP listener's sockets are bound before any server starts (M5 design B.3, D17), so an
address in use is a ``StartupError`` that names it; uvicorn would otherwise call ``sys.exit``
inside the servers' gather, with no line of the vault's.

A policy with an ``admin`` block has a portal (M5 design B): its own listener on ``admin.listen``,
resolved to one address (:mod:`zoeymcp.portal.listen`) and bound with the others. The start is
refused when that address can't be resolved, clashes with a ``--listen`` address, or can't be
bound, and when a static file is missing; a portal state file that can't be read is logged and
shown in the portal, never a reason to refuse (P21).
"""

from __future__ import annotations

import asyncio
import contextlib
import errno
import os
import re
import signal
import socket
import stat
import sys
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

import httpx
import uvicorn
from starlette.types import ASGIApp, Receive, Scope, Send

from ..common import control as control_pipe
from ..common.control import CONTROL_LINE_LIMIT as CONTROL_LINE_LIMIT
from ..common.control import CONTROL_RELOAD as CONTROL_RELOAD
from ..common.control import CONTROL_STOP as CONTROL_STOP
from ..common.control import open_control as open_control
from ..common.policy import Policy, PolicyError, gate, read_source, restart
from ..entrypoint.env import holds_secret_env
from ..portal import listen as portal_listen
from ..portal.app import Ledger, PortalApp, Secrets, StaticMissing, load_static
from ..portal.listen import RESOLVE_EVERY, RESOLVE_FOR, Address, ListenError
from ..portal.passkeys import Passkeys
from ..portal.policyview import Source
from ..portal.server import HEAD_LIMIT, HEADER_DEADLINE, portal_protocol
from . import logs
from .admin import (
    AdminApp,
    AdminSocketError,
    HealthReader,
    ReviewQueue,
    SetupCodes,
    check_socket_dir,
    socket_supported,
)
from .app import CONNECT_TIMEOUT, LISTENER_SCOPE_KEY, READ_TIMEOUT, Listener, VaultApp
from .connectors.smtp import connector_names
from .gatewaykeys import GatewayKeyError, GatewayKeys
from .health import Bridges
from .keys import MASTER_KEY_ENV, PREVIOUS_MASTER_KEY_ENV, KeySet, MasterKeyError
from .netclient import SocketClients
from .oauth.login import LoginService
from .onboard import OnboardService, policy_source
from .peer import link_supported, peer_checked
from .reportstore import ReportStore
from .store import SecretStore, StoreError

if sys.platform != "win32":
    import fcntl

LOCK_FILE = "vault.lock"
# Binds a listen address's host and port: its sockets, bound and not yet listening.
Binder = Callable[[str, int], list[socket.socket]]
# A name's addresses (portal.listen.Lookup); raises OSError when it doesn't resolve.
Lookup = Callable[[str], Sequence[str]]
# How often the timer retires an expired previous gateway key, in seconds.
GATEWAY_KEY_TICK = 5.0
# The launcher's control pipe: one command per line.
# --bridge NAME=UID: the launcher's bridge name (C.10) and the uid it runs that bridge as.
_BRIDGE = re.compile(r"([a-z0-9]{1,16})=([0-9]{1,10})")


class StartupError(Exception):
    """The vault can't start; the message says why and is safe to print."""


def acquire_state_lock(state_dir: Path) -> int | None:
    """Take ``<state>/vault.lock``, so only one vault uses the state directory.

    Returns the lock's file descriptor. It is never closed, so the lock lasts as long as the
    process. A held lock and a filesystem without locks are refused with different messages.
    Windows has no ``flock``: there the lock is skipped (development only), with a log line, and
    ``None`` is returned.
    """
    path = state_dir / LOCK_FILE
    if sys.platform != "win32":
        try:
            state_dir.mkdir(parents=True, exist_ok=True)
            fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        except OSError as exc:
            raise StartupError(f"can't open {path}: {exc}") from exc
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            os.close(fd)
            raise StartupError(f"another vault is using this state directory ({path})") from exc
        except OSError as exc:
            # No lock support (ENOLCK, EOPNOTSUPP), as on some network filesystems.
            os.close(fd)
            raise StartupError(f"can't lock {path}: {exc}") from exc
        logs.event("state_locked", path=str(path))
        return fd
    logs.event("state_lock_unavailable", path=str(path), reason="no flock on this platform")
    return None


def check_link_dir(path: Path) -> None:
    """Create the link socket's directory if needed, refuse one others can reach, and remove a
    stale socket.

    The directory, not the socket, is the permission gate: uvicorn makes the socket ``0666``. In
    the image it is ``10001:10002 0750``, so the gateway's group may enter and nobody else may.
    The peer's uid is checked on every connection as well (:mod:`.peer`). Only a socket is
    removed: anything else at ``path`` (a mistyped path to the store, say) is refused and kept.
    """
    directory = path.parent
    try:
        directory.mkdir(mode=0o750, parents=True, exist_ok=True)
        info = directory.stat()
    except OSError as exc:
        raise StartupError(f"can't use {directory} for the gateway socket: {exc}") from exc
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise StartupError(f"{directory} must be owned by the vault's uid {os.getuid()}")
    if stat.S_IMODE(info.st_mode) & 0o007:
        raise StartupError(f"{directory} must not be accessible to others (0750)")
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return
    except OSError as exc:
        raise StartupError(f"can't check {path} for a stale gateway socket: {exc}") from exc
    if not stat.S_ISSOCK(mode):
        raise StartupError(f"{path} exists and is not a socket")
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise StartupError(f"can't remove the stale gateway socket {path}: {exc}") from exc


def check_link_options(
    listens: list[str], gateway_socket: Path | None, gateway_uid: int | None
) -> None:
    """Refuse a combination of listeners that can't work."""
    if (gateway_socket is None) != (gateway_uid is None):
        raise StartupError("--gateway-socket and --gateway-uid go together")
    if gateway_uid is not None and gateway_uid < 0:
        raise StartupError("--gateway-uid must be a uid (0 or more)")
    if gateway_socket is not None and not link_supported():
        raise StartupError("--gateway-socket needs Linux (SO_PEERCRED)")
    if not listens and gateway_socket is None:
        raise StartupError("--listen none leaves nothing to serve; it needs --gateway-socket")


def parse_bridges(values: Sequence[str]) -> dict[str, int]:
    """``--bridge NAME=UID``, repeatable: each bridge the launcher started, and its uid (M7
    design B.2, C.10). Linux only, like the link socket: the peer check needs ``SO_PEERCRED``.
    A name given twice and root are refused; so is any other form."""
    bridges: dict[str, int] = {}
    for value in values:
        found = _BRIDGE.fullmatch(value)
        if found is None:
            raise StartupError(
                f"--bridge {value}: write NAME=UID, NAME 1 to 16 lower-case letters or digits"
            )
        name, uid = found.group(1), int(found.group(2))
        if name in bridges:
            raise StartupError(f"--bridge {name} is given twice")
        if uid == 0:
            raise StartupError(f"--bridge {name}: a bridge never runs as root")
        bridges[name] = uid
    if bridges and not link_supported():
        raise StartupError("--bridge needs Linux (SO_PEERCRED)")
    return bridges


def check_control_fd(fd: int) -> None:
    """Refuse a control descriptor that isn't an open pipe or socket the vault can read."""
    if sys.platform == "win32":
        raise StartupError("--control-fd needs a POSIX platform")
    try:
        mode = os.fstat(fd).st_mode
    except OSError as exc:
        raise StartupError(f"--control-fd {fd} is not open: {exc}") from exc
    if not (stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode)):
        raise StartupError(f"--control-fd {fd} is not a pipe")
    # The platform test again only so mypy on Windows skips fcntl, which it lacks.
    readable = (os.O_RDONLY, os.O_RDWR)
    if sys.platform != "win32" and (fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE) not in readable:
        raise StartupError(f"--control-fd {fd} is not open for reading")


class ListenerTag:
    """Tags each request's scope with the listener it arrived on. ``VaultApp`` reads the tag,
    never a header, to know whether the caller is the gateway (M3 design C.1)."""

    def __init__(self, app: ASGIApp, listener: Listener) -> None:
        self.app = app
        self.listener = listener

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await self.app({**scope, LISTENER_SCOPE_KEY: self.listener}, receive, send)


@dataclass(frozen=True)
class Runtime:
    policy: Policy
    store: SecretStore
    keys: KeySet
    gateway_keys: GatewayKeys
    # The previous master key's, during a master-key rotation.
    previous: KeySet | None = None


def load_keys(environ: Mapping[str, str]) -> tuple[KeySet, KeySet | None]:
    text = environ.get(MASTER_KEY_ENV)
    if not text:
        raise StartupError(f"{MASTER_KEY_ENV} is not set; generate one with `zoeymcp keygen`")
    try:
        keys = KeySet.from_text(text)
        previous_text = environ.get(PREVIOUS_MASTER_KEY_ENV)
        previous = KeySet.from_text(previous_text) if previous_text else None
    except MasterKeyError as exc:
        raise StartupError(str(exc)) from exc
    return keys, previous


def load_policy(config: str | None, environ: Mapping[str, str]) -> Policy:
    """The declarative start's policy, through the gate (M6 design C.2). A source that can't be
    read, or none given, is refused with the gate's text but isn't the gate's refusal: F.1 keeps
    ``none`` apart from ``unreadable``."""
    try:
        text, source = read_source(config, environ)
    except PolicyError as exc:
        raise StartupError(gate.refused_text(exc.source, exc.findings)) from exc
    try:
        policy = gate.admit_text(text, source, environ=environ).policy
    except gate.GateRefused as exc:
        raise StartupError(str(exc)) from exc
    if policy.mode == "managed":
        raise StartupError("managed mode arrives in M6; use mode: declarative for now")
    return policy


def load_runtime(config: str | None, state_dir: Path, environ: Mapping[str, str]) -> Runtime:
    keys, previous = load_keys(environ)
    policy = load_policy(config, environ)
    store = SecretStore(state_dir, keys, previous)
    try:
        rotated = store.load()
    except StoreError as exc:
        raise StartupError(str(exc)) from exc
    if rotated:
        logs.event("store_rotated", entries=rotated, key_id=keys.key_id)
    try:
        gateway_keys = GatewayKeys.load(state_dir, keys, previous, policy.gateway_key_generation)
    except GatewayKeyError as exc:
        raise StartupError(str(exc)) from exc
    return Runtime(policy, store, keys, gateway_keys, previous)


class _Server(uvicorn.Server):
    """A uvicorn server that leaves signal handling to the vault."""

    def install_signal_handlers(self) -> None:
        pass

    @contextlib.contextmanager
    def capture_signals(self) -> Iterator[None]:
        yield


class _PortalServer(_Server):
    """The portal's server: says it listens once it does, and then whether setup is pending."""

    def __init__(self, config: uvicorn.Config, portal: Portal) -> None:
        super().__init__(config)
        self.portal = portal

    async def startup(self, sockets: list[socket.socket] | None = None) -> None:
        await super().startup(sockets)
        if not self.started:
            return
        portal = self.portal
        logs.event(
            "portal_listening",
            listen=portal.address.listen,
            address=portal.bound,
            origins=list(portal.app.origins),
        )
        hint = portal.app.setup_hint()
        if hint is not None:
            # Once per start, and never a code (E.1).
            logs.event("setup_pending", hint=hint)


def _split_listen(listen: str) -> tuple[str, int]:
    host, _, port = listen.rpartition(":")
    return host.strip("[]"), int(port)


def bind_tcp(host: str, port: int) -> list[socket.socket]:
    """Bind every address ``host`` resolves to, as asyncio's ``create_server`` does when uvicorn
    binds: a socket each, IPv6 ones ``IPV6_V6ONLY``, an address whose family isn't enabled
    skipped. ``SO_REUSEADDR`` is set on POSIX only, as asyncio does: on Windows it lets a socket
    share a port another one holds, rather than reuse a closed one's."""
    infos = socket.getaddrinfo(host or None, port, type=socket.SOCK_STREAM, flags=socket.AI_PASSIVE)
    bound: list[socket.socket] = []
    try:
        for family, kind, proto, _, address in dict.fromkeys(infos):
            try:
                sock = socket.socket(family, kind, proto)
            except OSError:
                continue  # a family this host can't make sockets of
            bound.append(sock)
            if sys.platform != "win32":
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET6:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            try:
                sock.bind(address)
            except OSError as exc:
                if exc.errno != errno.EADDRNOTAVAIL:
                    raise
                bound.pop().close()  # the family isn't enabled, as asyncio assumes
        if not bound:
            raise OSError(f"no address {host} resolves to can be bound")
    except BaseException:
        _close(bound)
        raise
    return bound


def _close(sockets: list[socket.socket]) -> None:
    for sock in sockets:
        sock.close()


def lookup_addresses(host: str) -> list[str]:
    """Every address ``host`` resolves to for a stream socket, as the binder would bind."""
    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return [str(info[4][0]) for info in infos]


def resolve_admin_listen(
    listen: str,
    lookup: Lookup = lookup_addresses,
    *,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> Address:
    """``admin.listen`` as the one address the portal binds (B.2). A name that doesn't resolve
    yet is tried again for ``RESOLVE_FOR`` seconds (a network alias appears once the container
    is on its network); one that resolves to no address or to several is refused at once."""
    deadline = clock() + RESOLVE_FOR
    while True:
        try:
            return portal_listen.resolve(listen, lookup)
        except ListenError as exc:
            raise StartupError(str(exc)) from exc
        except OSError as exc:
            if clock() >= deadline:
                host, _ = portal_listen.split(listen)
                raise StartupError(f"admin.listen's name {host} doesn't resolve: {exc}") from exc
        sleep(RESOLVE_EVERY)


def _quiet_lookup(lookup: Lookup) -> Lookup:
    def quiet(host: str) -> Sequence[str]:
        try:
            return lookup(host)
        except OSError:
            return []  # left to the proxy's own bind, which names it

    return quiet


@dataclass(frozen=True)
class Portal:
    """The portal to serve: its app, and the address ``admin.listen`` resolved to.
    ``header_deadline`` is :data:`~zoeymcp.portal.server.HEADER_DEADLINE` but for tests."""

    app: PortalApp
    address: Address
    header_deadline: float = HEADER_DEADLINE

    @property
    def bound(self) -> str:
        """The address it listens on, as a log line or a refusal names it."""
        host = self.address.address
        return f"[{host}]:{self.address.port}" if ":" in host else f"{host}:{self.address.port}"


def build_portal(
    policy: Policy,
    listens: Sequence[str],
    *,
    setup: SetupCodes,
    passkeys: Passkeys,
    login: LoginService,
    secrets: Secrets | None = None,
    health: HealthReader | None = None,
    ledger: Ledger | None = None,
    source: Source = "file",
    onboard: OnboardService | None = None,
    reviews: ReviewQueue | None = None,
    lookup: Lookup = lookup_addresses,
) -> Portal | None:
    """The portal for ``policy.admin``, or None (``portal_disabled``) without the block. Refused
    at start (B.3): a name that doesn't resolve to exactly one address, an address a ``--listen``
    has (or its port, with a wildcard on either side), a static file missing. A wildcard beside
    any ``--listen`` is warned about (``admin_listener_shared``). ``secrets`` is what its Secrets
    area writes through, the admin socket's store, token manager and policy; ``health`` what
    its health checklist reads, as the socket's ``GET /health`` does; ``ledger`` the reported
    copy and the send journals its Ledger page reads, as ``zoeymcp ledger --vault`` does;
    ``source`` where the policy came from, for its policy view; and ``onboard`` and ``reviews``
    the onboardings and review jobs its MCP servers section shares with the socket (M7 K)."""
    admin = policy.admin
    if admin is None:
        logs.event("portal_disabled")
        return None
    address = resolve_admin_listen(admin.listen, lookup)
    clash = portal_listen.conflict(address, listens, _quiet_lookup(lookup))
    if clash is not None:
        raise StartupError(f"can't listen on {admin.listen} for the portal: {clash}")
    if portal_listen.shared(address, listens):
        logs.event("admin_listener_shared", level="warning", listen=admin.listen, proxy=listens)
    try:
        static = load_static()
    except StaticMissing as exc:
        raise StartupError(str(exc)) from exc
    app = PortalApp(
        admin.origins,
        static=static,
        setup=setup,
        passkeys=passkeys,
        login=login,
        secrets=secrets,
        health=None if health is None else health.report,
        ledger=ledger,
        source=source,
        onboard=onboard,
        reviews=reviews,
    )
    return Portal(app, address)


def bind_listens(listens: list[str], binder: Binder) -> list[list[socket.socket]]:
    """Bind each ``--listen`` address with ``binder``; one that can't be bound closes the ones
    already bound and is a ``StartupError`` naming it."""
    bound: list[list[socket.socket]] = []
    for listen in listens:
        host, port = _split_listen(listen)
        try:
            bound.append(binder(host, port))
        except OSError as exc:
            for sockets in bound:
                _close(sockets)
            raise StartupError(f"can't listen on {listen} for the proxy: {exc}") from exc
    return bound


async def serve(
    app: VaultApp,
    listens: list[str],
    *,
    config: str | None,
    environ: Mapping[str, str],
    admin: AdminApp | None = None,
    admin_socket: Path | None = None,
    gateway_keys: GatewayKeys | None = None,
    gateway_socket: Path | None = None,
    gateway_uid: int | None = None,
    control_fd: int | None = None,
    portal: Portal | None = None,
    binder: Binder = bind_tcp,
    stopper: Callable[[Callable[[], None]], None] | None = None,
) -> None:
    """Serve every listener until a stop. ``stopper`` is for a caller off the main thread (tests):
    it is handed the stop function, and no signal handler is installed."""
    # Before any server starts, so an address in use stops the start with its name (B.3).
    bound = bind_listens(listens, binder)
    portal_sockets: list[socket.socket] | None = None
    if portal is not None:
        try:
            portal_sockets = binder(portal.address.address, portal.address.port)
        except OSError as exc:
            for sockets in bound:
                _close(sockets)
            raise StartupError(f"can't listen on {portal.bound} for the portal: {exc}") from exc
    servers: list[_Server] = []
    # Each TCP server's bound sockets; uvicorn serves them, and closes them when it stops.
    listening: dict[_Server, list[socket.socket]] = {}
    for listen, sockets in zip(listens, bound, strict=True):
        host, port = _split_listen(listen)
        tcp = _Server(
            uvicorn.Config(
                ListenerTag(app, "tcp"),
                host=host,  # unused with sockets given; kept so the config names its address
                port=port,
                proxy_headers=False,  # never trust X-Forwarded-For: callers can't spoof
                server_header=False,
                date_header=False,
                access_log=False,
                log_level="warning",
                lifespan="off",
            )
        )
        servers.append(tcp)
        listening[tcp] = sockets

    if gateway_socket is not None and gateway_uid is not None:
        servers.append(
            _Server(
                uvicorn.Config(
                    ListenerTag(app, "gateway"),
                    uds=str(gateway_socket),
                    http=peer_checked(gateway_uid),
                    proxy_headers=False,
                    server_header=False,
                    date_header=False,
                    access_log=False,
                    log_level="warning",
                    lifespan="off",
                )
            )
        )

    if admin is not None and admin_socket is not None:
        servers.append(
            _Server(
                uvicorn.Config(
                    admin.app,
                    uds=str(admin_socket),
                    server_header=False,
                    date_header=False,
                    access_log=False,
                    log_level="warning",
                    lifespan="off",
                )
            )
        )

    if portal is not None and portal_sockets is not None:
        web = _PortalServer(
            uvicorn.Config(
                portal.app,
                host=portal.address.address,  # unused with sockets given, as for the proxy
                port=portal.address.port,
                http=portal_protocol(header_deadline=portal.header_deadline),
                h11_max_incomplete_event_size=HEAD_LIMIT,
                ws="none",
                proxy_headers=False,  # the portal never reads X-Forwarded-* (C.5)
                server_header=False,
                date_header=False,
                access_log=False,
                log_level="warning",
                lifespan="off",
            ),
            portal,
        )
        servers.append(web)
        listening[web] = portal_sockets

    def stop() -> None:
        # Long polls first: the servers wait for every request in flight before they stop.
        app.stop_view_waits()
        for server in servers:
            server.should_exit = True

    def reload() -> None:
        reload_policy(app, config, environ, portal=portal)

    loop = asyncio.get_running_loop()
    if stopper is not None:
        stopper(stop)
    elif sys.platform != "win32":
        loop.add_signal_handler(signal.SIGTERM, stop)
        loop.add_signal_handler(signal.SIGINT, stop)
        loop.add_signal_handler(signal.SIGHUP, reload)
    tasks = []
    if gateway_keys is not None:
        tasks.append(asyncio.create_task(gateway_key_timer(gateway_keys, GATEWAY_KEY_TICK)))
    control = None
    try:
        if control_fd is not None:
            reader, control = await open_control(control_fd)
            tasks.append(asyncio.create_task(read_control(reader, reload=reload, stop=stop)))
        logs.event(
            "vault_started",
            listen=listens,
            admin_socket=str(admin_socket) if admin_socket else None,
        )
        if gateway_socket is not None and gateway_uid is not None:
            logs.event("gateway_socket_listening", path=str(gateway_socket), uid=gateway_uid)
        await asyncio.gather(*(server.serve(sockets=listening.get(server)) for server in servers))
    finally:
        # uvicorn closes a started server's sockets; these are the ones of a start cut short.
        for sockets in listening.values():
            _close(sockets)
        for task in tasks:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        if control is not None:
            control.close()
        # Refreshes in flight finish (and are saved) before the clients close (N5).
        await app.aclose()
        logs.event("vault_stopped")


async def gateway_key_timer(gateway_keys: GatewayKeys, interval: float) -> None:
    """Retire an expired previous gateway key without waiting for a request, and retry a write
    that failed."""
    while True:
        await asyncio.sleep(interval)
        gateway_keys.tick()


async def read_control(
    reader: asyncio.StreamReader, *, reload: Callable[[], None], stop: Callable[[], None]
) -> None:
    """Act on the launcher's commands (:func:`zoeymcp.common.control.read_control`), logging as
    the vault."""
    await control_pipe.read_control(reader, reload=reload, stop=stop, event=logs.event)


def reload_policy(
    app: VaultApp, config: str | None, environ: Mapping[str, str], *, portal: Portal | None = None
) -> None:
    """``SIGHUP``: load and check the policy again, and swap it in if it passes.

    Synchronous, like every writer of OAuth state: the token manager keeps its slots and tasks,
    so a reload never starts a second refresh (design D.13). A reload that takes effect wakes the
    gateway's long polls of the view (M3 design D.2). A policy whose ``egress_key_generation`` is
    below the running one's is refused, like a gateway key generation that goes backwards.

    The portal takes a changed ``admin.origins`` at once, ending the sessions of an origin that
    went away; its listener stays where it is until a restart (M5 design B.3).
    """
    try:
        policy = load_policy(config, environ)
    except StartupError as exc:
        logs.event("reload_refused", reason=str(exc))
        return
    # The egress role's key generation only goes up: a lower one is a key the vault retired. Only
    # against the running policy: no floor is kept across a restart.
    running = app.policy.egress_key_generation
    if policy.egress_key_generation < running:
        logs.event(
            "reload_refused",
            reason=f"egress_key_generation {policy.egress_key_generation} is below {running}, the "
            "running policy's: that would revive a retired key",
        )
        return
    # The changes a reload can't apply, from the restart classifier (M6 design I.2), against the
    # startup values, which every client, connector and onboarding keeps (M7 design B.2, D-61):
    # the proxy, and whether it is the egress role. Where the portal listens: its listener's
    # address, else the running policy's (none). A reload logs only the vault's own two lines,
    # so the bridges, which only a managed plan names, aren't passed.
    before = app.policy.admin
    if portal is not None:
        listening: str | None = portal.address.listen
    else:
        listening = None if before is None else before.listen
    started = restart.Started(
        egress_proxy=app.egress_proxy,
        egress_proxy_kind=app.egress_proxy_kind,
        admin_listen=listening,
        bridges=frozenset(),
    )
    effects = restart.classify(app.policy, policy, started)
    needs = {effect.path for effect in effects if effect.kind == "vault_restart"}
    try:
        # The gateway key generation moves first, and is written before the policy is used.
        reset = app.reload(policy)
    except GatewayKeyError as exc:
        logs.event("reload_refused", reason=str(exc))
        return
    if needs & {"egress_proxy", "egress_proxy_kind"}:
        # The HTTP clients were built with the startup proxy, and SMTP sends keep it too;
        # onboarding keeps the startup kind.
        logs.event("egress_proxy_change_needs_restart")
    if "admin.listen" in needs:
        logs.event("admin_listen_change_needs_restart")
    if portal is not None and policy.admin is not None:
        portal.app.reload(policy.admin.origins)
    logs.event("reload_ok", oauth_reset=reset)


@dataclass(frozen=True)
class Vault:
    """Everything :func:`run` serves, built in the start-up order of M5 design B.4."""

    app: VaultApp
    gateway_keys: GatewayKeys
    login: LoginService
    onboard: OnboardService
    setup: SetupCodes
    passkeys: Passkeys
    admin: AdminApp | None
    admin_socket: Path | None
    portal: Portal | None


def run(
    config: str | None,
    listens: list[str],
    state_dir: Path,
    environ: Mapping[str, str],
    admin_socket: Path | None,
    *,
    gateway_socket: Path | None = None,
    gateway_uid: int | None = None,
    control_fd: int | None = None,
    bridges: Sequence[str] = (),
) -> None:
    """Start the vault. ``listens`` may be empty (``--listen none``) when ``gateway_socket`` is
    set; ``gateway_socket`` and ``gateway_uid`` go together. ``bridges`` are the
    ``--bridge NAME=UID`` values."""
    check_link_options(listens, gateway_socket, gateway_uid)
    named = parse_bridges(bridges)
    if control_fd is not None:
        check_control_fd(control_fd)
    # Before loading the store, which may rewrite it (key rotation). Not in load_runtime: tests
    # call that twice on one directory in one process.
    acquire_state_lock(state_dir)
    vault = build(
        config,
        listens,
        state_dir,
        environ,
        admin_socket,
        gateway_socket=gateway_socket,
        bridges=named,
    )
    asyncio.run(
        serve(
            vault.app,
            listens,
            config=config,
            environ=environ,
            admin=vault.admin,
            admin_socket=vault.admin_socket,
            gateway_keys=vault.gateway_keys,
            gateway_socket=gateway_socket,
            gateway_uid=gateway_uid,
            control_fd=control_fd,
            portal=vault.portal,
        )
    )


def build(
    config: str | None,
    listens: list[str],
    state_dir: Path,
    environ: Mapping[str, str],
    admin_socket: Path | None,
    *,
    gateway_socket: Path | None = None,
    bridges: Mapping[str, int] | None = None,
) -> Vault:
    """With the state lock held: keys, policy, store, gateway keys, the link directory, the
    journals and the copy, the portal's state files, then the portal (M5 design B.4). Nothing
    listens yet. ``bridges`` are the bridges the launcher started, by name, with their uids."""
    runtime = load_runtime(config, state_dir, environ)
    if gateway_socket is not None:
        check_link_dir(gateway_socket)
    # Before any listener opens: a torn tail is cut and the head rebuilt from the lines (M5 J.4).
    # A copy that can't be read is unavailable, and the proxy runs anyway.
    reports = ReportStore.open(state_dir)
    # Its HTTP clients, every one guarded (routes, tokens, revocation, onboarding), are built here
    # from the startup policy and kept until the process ends; a reload changes none, though each
    # reads the running policy's egress_private at every connection (M7 design B.2, D-61). The
    # bridges' socket clients too: one per --bridge, none in the hardened tier (Q46).
    timeout = httpx.Timeout(READ_TIMEOUT, connect=CONNECT_TIMEOUT)
    app = VaultApp(
        runtime.policy,
        runtime.store,
        runtime.keys,
        socket_clients=SocketClients(bridges or {}, timeout=timeout),
        environ=environ,
        gateway_keys=runtime.gateway_keys,
        gateway_link=gateway_socket is not None,
        reports=reports,
    )
    # Before any listener opens: a send cut by a SIGKILL is closed unknown, never re-sent (J.3).
    try:
        app.connectors.recover(connector_names(runtime.policy.connectors))
    except OSError as exc:
        raise StartupError(f"can't recover the SMTP connectors' send journals: {exc}") from exc
    # One set of pending logins for every surface, so the flow limit is shared (M5 design H.2).
    login = LoginService(app.tokens)
    # Likewise one set of onboardings, so their limits and owners hold across surfaces (M7
    # design D.8): on the onboarding client, with the startup egress_proxy and its kind (B.2,
    # D-61). Their allowances are the egress role's, through the proxy listener's allowlists (I.3).
    onboard = OnboardService(
        runtime.store,
        app.tokens,
        lambda: app.policy,
        app.onboarding_client,
        egress_proxy=app.egress_proxy,
        egress_proxy_kind=app.egress_proxy_kind,
        egress=app,
        source=policy_source(config),
    )
    app.use_allowances(onboard.allowances, onboard.allowances_expire_in)
    # The portal's state files, one holder each for the socket and the portal. Built on every
    # platform: on Windows, or with --admin-socket none, the portal still redeems a code issued
    # offline with zoeymcp setup-code --state (M5 design E.2, verifier V12).
    portal_key = runtime.keys.portal_key
    previous = None if runtime.previous is None else runtime.previous.portal_key
    passkeys = Passkeys.load(state_dir, portal_key, previous)
    setup = SetupCodes(state_dir, portal_key)
    if admin_socket is not None and socket_supported():
        try:
            check_socket_dir(admin_socket)
        except AdminSocketError as exc:
            raise StartupError(str(exc)) from exc
    elif admin_socket is not None:
        logs.event("admin_socket_disabled", reason="Unix sockets aren't supported on this platform")
        admin_socket = None
    # The same SetupCodes, passkeys and logins as the socket's (verifier V12, M5 design H.2), and
    # the same store, token manager, running policy and revocations for secrets (M5 design G,
    # P10; M7 design D.9).
    secrets = Secrets(runtime.store, app.tokens, lambda: app.policy, app.revoker)
    # Health from the same sources as the socket's GET /health (M5 design I.2), with the tier
    # and the bridges this vault was started with (M7 design C.10, J).
    named = frozenset(bridges or ())
    tier = Bridges(
        link=gateway_socket is not None,
        named=named,
        secret_env=frozenset(name for name in named if holds_secret_env(environ, name)),
    )
    health = HealthReader(
        runtime.store,
        lambda: app.policy,
        login,
        connectors=app.connectors,
        env_names=lambda: app.env_names,
        reports=reports,
        passkeys=passkeys,
        egress_fetched_ago=app.allowlist_fetched_ago,
        bridges=tier,
        gateway_status=app.gateway_status,
    )
    # The Ledger page reads the copy the report path writes, with the connectors' journals
    # (M5 design J.5); the policy view says where the policy came from (L).
    source: Source = "stdin" if config == "-" else "env" if config is None else "file"
    portal = build_portal(
        runtime.policy,
        listens,
        setup=setup,
        passkeys=passkeys,
        login=login,
        secrets=secrets,
        health=health,
        ledger=Ledger(reports, app.connectors),
        source=source,
        # The same onboardings and review jobs as the socket's (M7 design D.8, F.2).
        onboard=onboard,
        reviews=app,
    )
    admin = None
    if admin_socket is not None:
        # The socket lists and ends the portal's sessions (zoeymcp sessions, passkeys --remove).
        admin = AdminApp(
            runtime.store,
            runtime.keys,
            lambda: app.policy,
            setup,
            app.tokens,
            login,
            gateway_keys=runtime.gateway_keys,
            connectors=app.connectors,
            env_names=lambda: app.env_names,
            reports=reports,
            passkeys=passkeys,
            portal=None if portal is None else portal.app,
            onboard=onboard,
            revoker=app.revoker,
            # The review jobs the gateway polls the proxy listener for (M7 design F.2).
            reviews=app,
            egress_fetched_ago=app.allowlist_fetched_ago,
            bridges=tier,
            gateway_status=app.gateway_status,
        )
    return Vault(
        app, runtime.gateway_keys, login, onboard, setup, passkeys, admin, admin_socket, portal
    )
