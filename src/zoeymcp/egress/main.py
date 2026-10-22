"""``zoeymcp egress``: the egress role's process (M7 design I.4, N).

The role binds every listener before its first allowlist fetch, then enters one ``try`` that
owns them all (the shape D-167 asks of ``serve()``), so nothing it bound outlives it. It accepts
connections at once but opens no tunnel until it holds a fresh list. A listener whose name
doesn't resolve to exactly one address within 5 s isn't bound (fail closed); it is logged, and
tried again at each contact with the vault (FM-27), in a task of its own so the long poll never
waits on a lookup. It logs its listener map at start (``egress_started``). The poll runs for as
long as the role does; if it ever ends, the role stops rather than serve lists that go stale.

SIGTERM and SIGINT stop it: listeners close and open tunnels are cut (``result: stopped``).
SIGHUP re-reads the key file and fetches the lists at once.
"""

from __future__ import annotations

import asyncio
import contextlib
import signal
import socket
import sys
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from functools import partial

from . import connect, event, listen
from .allowlist import ALLOWLIST_WAIT, Allowlist, AllowlistError, KeySource
from .connect import Lists
from .tunnel import Dial, Handler, Resolve, Tunnels, direct, system_resolve

# A name's addresses, for a listener's alias; may raise OSError.
Lookup = Callable[[str], Awaitable[Sequence[str]]]
_CLOSE_WAIT = 5.0  # how long stopping waits for the listeners' connections to close


class StartupError(Exception):
    """The role can't start; the message says why and is safe to print."""


@dataclass(frozen=True)
class Options:
    vault: str
    listens: tuple[str, ...]
    max_tunnels: int = connect.TUNNELS_PER_LISTENER
    idle_timeout: float = connect.IDLE_TIMEOUT
    max_tunnel_seconds: float = connect.TUNNEL_MAX_SECONDS


async def system_lookup(host: str) -> list[str]:
    infos = await asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return [str(info[4][0]) for info in infos]


def _check(options: Options) -> tuple[listen.Listen, ...]:
    if not 0 < options.max_tunnels <= connect.TUNNELS_MAX:
        raise StartupError(f"--max-tunnels is 1 to {connect.TUNNELS_MAX}")
    if not options.idle_timeout > 0 or not options.max_tunnel_seconds > 0:
        raise StartupError("--idle-timeout and --max-tunnel-seconds are positive")
    try:
        return listen.parse_all(options.listens)
    except listen.ListenError as exc:
        raise StartupError(str(exc)) from exc


class Role:
    """The role: its listeners, its lists and its tunnels."""

    def __init__(
        self,
        options: Options,
        key: KeySource,
        *,
        resolve: Resolve = system_resolve,
        dial: Dial = direct,
        lookup: Lookup = system_lookup,
        clock: Callable[[], float] = time.monotonic,
        head_timeout: float = connect.HEAD_TIMEOUT,
        wait: int = ALLOWLIST_WAIT,
        jitter: Callable[[], float] | None = None,
    ) -> None:
        self.listens = _check(options)
        self._lookup = lookup
        self._key = key
        self.tunnels = Tunnels(per_listener=options.max_tunnels)
        try:
            self.allowlist = Allowlist(
                options.vault,
                key,
                clock=clock,
                wait=wait,
                on_apply=self._applied,
                on_contact=self._contacted,
                jitter=jitter,
            )
        except AllowlistError as exc:
            raise StartupError(str(exc)) from exc
        self.handler = Handler(
            self.allowlist.fresh,
            self.tunnels,
            resolve=resolve,
            dial=dial,
            idle_timeout=options.idle_timeout,
            max_seconds=options.max_tunnel_seconds,
            head_timeout=head_timeout,
        )
        # Each bound source's address and port; a source not here has no listener.
        self.bound: dict[str, tuple[str, int]] = {}
        self._servers: dict[str, asyncio.Server] = {}
        self._failed: dict[str, str] = {}
        self._retry: asyncio.Task[None] | None = None
        self._stop: asyncio.Event | None = None
        self._stopping = False
        self.started = False

    def _applied(self, lists: Lists) -> None:
        self.tunnels.prune(lists)

    async def _bind(self, spec: listen.Listen) -> None:
        """Bind ``spec``'s listener, or log why not (once per reason) and leave it unbound."""
        try:
            literal = listen.literal(spec.host)
            if literal is not None:
                found = [literal]
            else:
                async with asyncio.timeout(connect.RESOLVE_TIMEOUT):
                    found = list(await self._lookup(spec.host))
            address = listen.choose(spec, found)
            server = await asyncio.start_server(
                partial(self.handler.handle, spec.source), address, spec.port
            )
        # A name the IDNA codec refuses raises UnicodeError; a lookup out of time, TimeoutError.
        except (OSError, UnicodeError, listen.ListenError) as exc:
            reason = str(exc) or type(exc).__name__
            if self._failed.get(spec.source) != reason:
                self._failed[spec.source] = reason
                event("egress_listen_failed", source=spec.source, listen=spec.text, reason=reason)
            return
        self._servers[spec.source] = server
        self.bound[spec.source] = (address, server.sockets[0].getsockname()[1])
        if self._failed.pop(spec.source, None) is not None and self.started:
            event("egress_listen_bound", source=spec.source, address=self._shown(spec.source))

    def _shown(self, source: str) -> str | None:
        if source not in self.bound:
            return None
        address, port = self.bound[source]
        return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"

    async def _bind_missing(self) -> None:
        for spec in self.listens:
            if spec.source not in self._servers and not self._stopping:
                await self._bind(spec)

    def _contacted(self) -> None:
        """Contact with the vault: try the unbound listeners again, unless a try is running."""
        if self._failed and not self._stopping and (self._retry is None or self._retry.done()):
            self._retry = asyncio.create_task(self._bind_missing())

    async def serve(self) -> None:
        """Run until :meth:`stop`."""
        self._stop = asyncio.Event()
        if self._stopping:  # a signal before the loop got here
            self._stop.set()
        try:
            for spec in self.listens:
                await self._bind(spec)
        except BaseException:
            self._close()
            raise
        try:
            event(
                "egress_started",
                vault=self.allowlist.vault,
                listeners={spec.source: self._shown(spec.source) for spec in self.listens},
                max_tunnels=self.tunnels.per_listener,
            )
            self.started = True
            poll = asyncio.create_task(self.allowlist.run())
            stop = asyncio.create_task(self._stop.wait())
            try:
                await asyncio.wait((poll, stop), return_when=asyncio.FIRST_COMPLETED)
                if poll.done():
                    event("egress_allowlist_ended", error_type=_ended(poll))
            finally:
                self._stopping = True
                for task in (poll, stop, self._retry):
                    if task is not None:
                        task.cancel()
                        with contextlib.suppress(asyncio.CancelledError):
                            await task
        finally:
            self._close()
            self.tunnels.cut_all("stopped")
            self.handler.close_all()
            for server in self._servers.values():
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(server.wait_closed(), _CLOSE_WAIT)

    def _close(self) -> None:
        for server in self._servers.values():
            server.close()

    def stop(self) -> None:
        self._stopping = True
        if self._stop is not None:
            self._stop.set()

    def hangup(self) -> None:
        """SIGHUP: re-read the key file, and fetch the lists now."""
        if self._key.reload():
            event("egress_key_reloaded")
        self.allowlist.refresh()


def _ended(task: asyncio.Task[None]) -> str | None:
    """The name of the exception that ended ``task``, if one did."""
    if task.cancelled():
        return None
    error = task.exception()
    return None if error is None else type(error).__name__


def build(options: Options, environ: Mapping[str, str]) -> Role:
    """The role for ``options``, its key from ``environ``; :class:`StartupError` otherwise."""
    try:
        key = KeySource.from_environ(environ)
    except AllowlistError as exc:
        raise StartupError(str(exc)) from exc
    return Role(options, key)


async def _main(role: Role) -> None:
    loop = asyncio.get_running_loop()
    if sys.platform != "win32":
        loop.add_signal_handler(signal.SIGTERM, role.stop)
        loop.add_signal_handler(signal.SIGINT, role.stop)
        loop.add_signal_handler(signal.SIGHUP, role.hangup)
    await role.serve()


def run(options: Options, environ: Mapping[str, str]) -> None:
    asyncio.run(_main(build(options, environ)))
