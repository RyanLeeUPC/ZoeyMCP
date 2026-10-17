"""Running the vault: ``zoeymcp vault`` (design §4, §4.6).

Startup refuses to run with a missing or malformed master key, a policy that fails ``check``, or
a store written under an unknown key. ``SIGHUP`` reloads the policy; a policy that fails
validation is rejected and the running one stays.
"""

from __future__ import annotations

import asyncio
import contextlib
import signal
import sys
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path

import uvicorn

from ..common.policy import Policy, PolicyError, check_policy, parse_policy, read_source
from . import logs
from .app import VaultApp
from .keys import MASTER_KEY_ENV, PREVIOUS_MASTER_KEY_ENV, KeySet, MasterKeyError
from .store import SecretStore, StoreError


class StartupError(Exception):
    """The vault can't start; the message says why and is safe to print."""


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

    def stop() -> None:
        for server in servers:
            server.should_exit = True

    def reload() -> None:
        try:
            app.reload(load_policy(config, environ))
        except StartupError as exc:
            logs.event("reload_refused", reason=str(exc))
        else:
            logs.event("reload_ok")

    loop = asyncio.get_running_loop()
    if sys.platform != "win32":
        loop.add_signal_handler(signal.SIGTERM, stop)
        loop.add_signal_handler(signal.SIGINT, stop)
        loop.add_signal_handler(signal.SIGHUP, reload)
    try:
        logs.event("vault_started", listen=listens)
        await asyncio.gather(*(server.serve() for server in servers))
    finally:
        await app.aclose()
        logs.event("vault_stopped")


def run(
    config: str | None, listens: list[str], state_dir: Path, environ: Mapping[str, str]
) -> None:
    runtime = load_runtime(config, state_dir, environ)
    app = VaultApp(runtime.policy, runtime.store, runtime.keys, environ=environ)
    asyncio.run(serve(app, listens, config=config, environ=environ))
