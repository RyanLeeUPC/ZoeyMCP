"""Running the vault: ``zoeymcp vault`` (design §4, §4.6).

Startup refuses to run with a missing or malformed master key, a policy that fails ``check``, a
store written under an unknown key, or a state directory another vault is using. ``SIGHUP``
reloads the policy; a policy that fails validation is rejected and the running one stays.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import signal
import sys
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path

import uvicorn

from ..common.policy import Policy, PolicyError, check_policy, parse_policy, read_source
from . import logs
from .admin import AdminApp, AdminSocketError, SetupCodes, check_socket_dir, socket_supported
from .app import VaultApp
from .keys import MASTER_KEY_ENV, PREVIOUS_MASTER_KEY_ENV, KeySet, MasterKeyError
from .store import SecretStore, StoreError

if sys.platform != "win32":
    import fcntl

LOCK_FILE = "vault.lock"


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


@dataclass(frozen=True)
class Runtime:
    policy: Policy
    store: SecretStore
    keys: KeySet


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
    return Runtime(policy, store, keys)


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
) -> None:
    servers = []
    for listen in listens:
        host, port = _split_listen(listen)
        servers.append(
            _Server(
                uvicorn.Config(
                    app,
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
        for server in servers:
            server.should_exit = True

    def reload() -> None:
        reload_policy(app, config, environ)

    loop = asyncio.get_running_loop()
    if sys.platform != "win32":
        loop.add_signal_handler(signal.SIGTERM, stop)
        loop.add_signal_handler(signal.SIGINT, stop)
        loop.add_signal_handler(signal.SIGHUP, reload)
    try:
        logs.event(
            "vault_started",
            listen=listens,
            admin_socket=str(admin_socket) if admin_socket else None,
        )
        await asyncio.gather(*(server.serve() for server in servers))
    finally:
        # Refreshes in flight finish (and are saved) before the clients close (N5).
        await app.aclose()
        logs.event("vault_stopped")


def reload_policy(app: VaultApp, config: str | None, environ: Mapping[str, str]) -> None:
    """``SIGHUP``: load and check the policy again, and swap it in if it passes.

    Synchronous, like every writer of OAuth state: the token manager keeps its slots and tasks,
    so a reload never starts a second refresh (design D.13).
    """
    try:
        policy = load_policy(config, environ)
    except StartupError as exc:
        logs.event("reload_refused", reason=str(exc))
        return
    if policy.egress_proxy != app.policy.egress_proxy:
        # The HTTP clients were built with the old proxy.
        logs.event("egress_proxy_change_needs_restart")
    reset = app.reload(policy)
    logs.event("reload_ok", oauth_reset=reset)


def run(
    config: str | None,
    listens: list[str],
    state_dir: Path,
    environ: Mapping[str, str],
    admin_socket: Path | None,
) -> None:
    # Before loading the store, which may rewrite it (key rotation). Not in load_runtime: tests
    # call that twice on one directory in one process.
    acquire_state_lock(state_dir)
    runtime = load_runtime(config, state_dir, environ)
    app = VaultApp(runtime.policy, runtime.store, runtime.keys, environ=environ)
    admin = None
    if admin_socket is not None and socket_supported():
        try:
            check_socket_dir(admin_socket)
        except AdminSocketError as exc:
            raise StartupError(str(exc)) from exc
        admin = AdminApp(
            runtime.store, runtime.keys, lambda: app.policy, SetupCodes(state_dir), app.tokens
        )
    elif admin_socket is not None:
        logs.event("admin_socket_disabled", reason="Unix sockets aren't supported on this platform")
        admin_socket = None
    asyncio.run(
        serve(app, listens, config=config, environ=environ, admin=admin, admin_socket=admin_socket)
    )
