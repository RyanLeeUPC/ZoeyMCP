"""Running the vault: ``zoeymcp vault`` (design §4, §4.6).

Startup refuses to run with a missing or malformed master key, a policy that fails ``check``, a
store written under an unknown key, a gateway key state that fails its MAC or would go backwards,
or a state directory another vault is using. ``SIGHUP`` reloads the policy; a policy that fails
validation, or whose gateway key generation went backwards or can't be written, is rejected and
the running one stays.

In the standard tier (M3 design B.2, C.1) the vault also listens on the link socket, where only
the gateway's uid may connect, and may have no TCP listener at all (``--listen none``). The
launcher can't signal the vault's uid, so it writes ``HUP`` and ``TERM`` to a control pipe
instead; the end of that pipe stops the vault too.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import signal
import stat
import sys
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path

import uvicorn
from starlette.types import ASGIApp, Receive, Scope, Send

from ..common.policy import Policy, PolicyError, check_policy, parse_policy, read_source
from . import logs
from .admin import AdminApp, AdminSocketError, SetupCodes, check_socket_dir, socket_supported
from .app import LISTENER_SCOPE_KEY, Listener, VaultApp
from .gatewaykeys import GatewayKeyError, GatewayKeys
from .keys import MASTER_KEY_ENV, PREVIOUS_MASTER_KEY_ENV, KeySet, MasterKeyError
from .peer import link_supported, peer_checked
from .store import SecretStore, StoreError

if sys.platform != "win32":
    import fcntl

LOCK_FILE = "vault.lock"
# How often the timer retires an expired previous gateway key, in seconds.
GATEWAY_KEY_TICK = 5.0
# The launcher's control pipe: one command per line.
CONTROL_RELOAD = b"HUP"
CONTROL_STOP = b"TERM"
CONTROL_LINE_LIMIT = 1024


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
    try:
        text, source = read_source(config, environ)
        policy = parse_policy(text, source)
    except PolicyError as exc:
        details = "; ".join(f"{f.path}: {f.message}" for f in exc.findings[:5])
        raise StartupError(f"policy {exc.source} refused: {details}") from exc
    errors = [f for f in check_policy(policy, environ=environ) if f.level == "error"]
    if errors:
        details = "; ".join(f"{f.path}: {f.message}" for f in errors[:5])
        raise StartupError(f"policy {source} fails check ({len(errors)} error(s)): {details}")
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
    return Runtime(policy, store, keys, gateway_keys)


class _Server(uvicorn.Server):
    """A uvicorn server that leaves signal handling to the vault."""

    def install_signal_handlers(self) -> None:
        pass

    @contextlib.contextmanager
    def capture_signals(self) -> Iterator[None]:
        yield


def _split_listen(listen: str) -> tuple[str, int]:
    host, _, port = listen.rpartition(":")
    return host.strip("[]"), int(port)


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
) -> None:
    servers = []
    for listen in listens:
        host, port = _split_listen(listen)
        servers.append(
            _Server(
                uvicorn.Config(
                    ListenerTag(app, "tcp"),
                    host=host,
                    port=port,
                    proxy_headers=False,  # never trust X-Forwarded-For: callers can't spoof
                    server_header=False,
                    date_header=False,
                    access_log=False,
                    log_level="warning",
                    lifespan="off",
                )
            )
        )

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

    def stop() -> None:
        # Long polls first: the servers wait for every request in flight before they stop.
        app.stop_view_waits()
        for server in servers:
            server.should_exit = True

    def reload() -> None:
        reload_policy(app, config, environ)

    loop = asyncio.get_running_loop()
    if sys.platform != "win32":
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
        await asyncio.gather(*(server.serve() for server in servers))
    finally:
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


async def open_control(fd: int) -> tuple[asyncio.StreamReader, asyncio.BaseTransport]:
    """Read the control pipe ``fd`` without blocking the loop. The transport owns ``fd``."""
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader(limit=CONTROL_LINE_LIMIT)
    transport, _ = await loop.connect_read_pipe(
        lambda: asyncio.StreamReaderProtocol(reader), os.fdopen(fd, "rb", buffering=0)
    )
    return reader, transport


async def read_control(
    reader: asyncio.StreamReader, *, reload: Callable[[], None], stop: Callable[[], None]
) -> None:
    """Act on the launcher's commands: ``HUP`` reloads, ``TERM`` stops (M3 design B.2).

    The end of the pipe stops the vault too: the launcher is gone, and nothing would stop the
    vault any more. So does an error reading it. Anything else is logged by size and ignored.

    A line over :data:`CONTROL_LINE_LIMIT` is dropped up to the limit, and what follows it is
    read as the next line. Only the launcher holds the pipe, and it writes short lines.
    """
    while True:
        try:
            line = await reader.readline()
        except ValueError:
            logs.event("control_ignored", bytes=CONTROL_LINE_LIMIT)
            continue
        except OSError as exc:
            logs.event("control_failed", error_type=type(exc).__name__)
            stop()
            return
        if not line:
            logs.event("control_received", command="EOF")
            stop()
            return
        command = line.strip()
        if command == CONTROL_RELOAD:
            logs.event("control_received", command="HUP")
            reload()
        elif command == CONTROL_STOP:
            logs.event("control_received", command="TERM")
            stop()
        else:
            logs.event("control_ignored", bytes=len(line))


def reload_policy(app: VaultApp, config: str | None, environ: Mapping[str, str]) -> None:
    """``SIGHUP``: load and check the policy again, and swap it in if it passes.

    Synchronous, like every writer of OAuth state: the token manager keeps its slots and tasks,
    so a reload never starts a second refresh (design D.13). A reload that takes effect wakes the
    gateway's long polls of the view (M3 design D.2).
    """
    try:
        policy = load_policy(config, environ)
    except StartupError as exc:
        logs.event("reload_refused", reason=str(exc))
        return
    egress_changed = policy.egress_proxy != app.policy.egress_proxy
    try:
        # The gateway key generation moves first, and is written before the policy is used.
        reset = app.reload(policy)
    except GatewayKeyError as exc:
        logs.event("reload_refused", reason=str(exc))
        return
    if egress_changed:
        # The HTTP clients were built with the old proxy.
        logs.event("egress_proxy_change_needs_restart")
    logs.event("reload_ok", oauth_reset=reset)


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
) -> None:
    """Start the vault. ``listens`` may be empty (``--listen none``) when ``gateway_socket`` is
    set; ``gateway_socket`` and ``gateway_uid`` go together."""
    check_link_options(listens, gateway_socket, gateway_uid)
    if control_fd is not None:
        check_control_fd(control_fd)
    # Before loading the store, which may rewrite it (key rotation). Not in load_runtime: tests
    # call that twice on one directory in one process.
    acquire_state_lock(state_dir)
    runtime = load_runtime(config, state_dir, environ)
    if gateway_socket is not None:
        check_link_dir(gateway_socket)
    app = VaultApp(
        runtime.policy,
        runtime.store,
        runtime.keys,
        environ=environ,
        gateway_keys=runtime.gateway_keys,
        gateway_link=gateway_socket is not None,
    )
    admin = None
    if admin_socket is not None and socket_supported():
        try:
            check_socket_dir(admin_socket)
        except AdminSocketError as exc:
            raise StartupError(str(exc)) from exc
        admin = AdminApp(
            runtime.store,
            runtime.keys,
            lambda: app.policy,
            SetupCodes(state_dir),
            app.tokens,
            gateway_keys=runtime.gateway_keys,
        )
    elif admin_socket is not None:
        logs.event("admin_socket_disabled", reason="Unix sockets aren't supported on this platform")
        admin_socket = None
    asyncio.run(
        serve(
            app,
            listens,
            config=config,
            environ=environ,
            admin=admin,
            admin_socket=admin_socket,
            gateway_keys=runtime.gateway_keys,
            gateway_socket=gateway_socket,
            gateway_uid=gateway_uid,
            control_fd=control_fd,
        )
    )
