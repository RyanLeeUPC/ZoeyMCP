"""``zoeymcp gateway``: the gateway process (M3 design B.1).

It refuses to start with a master key or ``ZOEYMCP_CONFIG`` in its environment (G1), or as root
(``--allow-root`` is for development). The ``http://`` link needs the gateway key; with
``unix:`` a key is ignored. ``SIGHUP`` (or ``HUP`` on the control pipe) fetches the view now
and re-reads the key file; ``SIGTERM`` (or ``TERM``, or the pipe's end) stops, giving calls in
flight 10 seconds. The admin socket answers ``GET /status``, ``POST /review/<server>`` and
``POST /review/<server>/clear`` (:mod:`.review`).

The SDK's own loggers are silenced: they log session ids and request headers (G20).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import re
import signal
import stat
import sys
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import anyio
import uvicorn
from starlette.types import Receive, Scope, Send

from ..common import control
from ..common.policy.view import ViewRemoteServer
from . import logs, review
from .app import GatewayApp
from .defstore import DefinitionStore
from .marks import DriftMarks, MarksError
from .upstream import UpstreamPool
from .vaultlink import (
    KeySource,
    Link,
    LinkError,
    environ_has_no_secrets,
    parse_link,
    running_as_root,
    view_client,
)

STOP_GRACE = 10
KEEP_ALIVE = 5
VERSION = "1"
_REVIEW_PATH = re.compile(r"/review/([a-z0-9][a-z0-9_-]{0,62})(/clear)?")


class StartupError(RuntimeError):
    """The gateway can't start; the message says why, with no secret in it."""


@dataclass(frozen=True)
class Options:
    vault: str
    listen: str = "0.0.0.0:8090"  # behind the Host and token checks
    state: Path = Path("/state-gateway")
    admin_socket: Path | None = Path("/run/zoeymcp-gateway/admin.sock")
    allow_root: bool = False
    control_fd: int | None = None


def quiet_sdk_loggers() -> None:
    """The SDK logs session ids, refused Origin values and redirect locations (SDK contract)."""
    for name in ("mcp", "httpx2", "httpcore2", "sse_starlette", "uvicorn.error"):
        logging.getLogger(name).setLevel(logging.CRITICAL + 1)


def check_private_dir(path: Path) -> None:
    """A state or socket directory: created 0700, owned by this uid, no access for others."""
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not hasattr(os, "geteuid"):
        return
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode):
        raise StartupError(f"{path} is not a directory")
    if info.st_uid != os.geteuid():
        raise StartupError(f"{path} belongs to another user")
    if info.st_mode & 0o077:
        raise StartupError(f"{path} is open to other users (chmod 700 it)")


def keys_for(link: Link, environ: Mapping[str, str]) -> KeySource | None:
    try:
        keys = KeySource.from_environ(environ)
    except LinkError as exc:
        raise StartupError(str(exc)) from exc
    if not link.hardened:
        if keys.configured:
            logs.event("gateway_key_unused")
        return None
    if not keys.configured:
        raise StartupError(
            "an http:// vault link needs ZOEYMCP_GATEWAY_KEY or ZOEYMCP_GATEWAY_KEY_FILE"
        )
    return keys


@dataclass
class Gateway:
    app: GatewayApp
    link: Link
    keys: KeySource | None


def prepare(options: Options, environ: Mapping[str, str]) -> Gateway:
    """Everything the process needs, or :class:`StartupError`."""
    leaked = environ_has_no_secrets(environ)
    if leaked is not None:
        raise StartupError(f"{leaked} is set: the gateway must never see the vault's secrets")
    if running_as_root() and not options.allow_root:
        raise StartupError("refusing to run as root (--allow-root is for development only)")
    try:
        link = parse_link(options.vault)
    except LinkError as exc:
        raise StartupError(str(exc)) from exc
    keys = keys_for(link, environ)
    check_private_dir(options.state)
    try:
        marks = DriftMarks.load(options.state)
    except MarksError as exc:
        raise StartupError(f"drift marks: {exc} (move the file aside to start over)") from exc
    pool = UpstreamPool(link, keys, marks, DefinitionStore(options.state))
    app = GatewayApp(pool, view_client(link, keys))
    return Gateway(app, link, keys)


def status(app: GatewayApp) -> dict[str, Any]:
    """G.5's status: per server, never definitions or token hashes."""
    snapshot = app.policy.snapshot
    servers: dict[str, Any] = {}
    if snapshot is not None:
        for name, server in snapshot.view.gateway.servers.items():
            if not isinstance(server, ViewRemoteServer):
                servers[name] = {"kind": server.kind, "state": "unsupported"}
                continue
            connections = [c for c in app.pool.connections() if c.server == name]
            phases = sorted({c.state.phase.value for c in connections})
            exposed = set()
            reports: dict[str, set[str]] = {}
            verified = [c.state.verified_at for c in connections if c.state.verified_at is not None]
            for connection in connections:
                evaluation = connection.state.evaluation
                if evaluation is not None:
                    exposed |= set(evaluation.exposed)
                    for report in evaluation.reports:
                        reports.setdefault(report.kind, set()).add(report.tool)
            servers[name] = {
                "kind": "remote",
                "state": phases or ["idle"],
                "era": app.pool.eras.get(name),
                "connections": len(connections),
                "included": len(server.tools.include),
                "exposed": len(exposed),
                "marked": sorted(tool for tool, _ in app.pool.marks.for_server(name)),
                "reports": {kind: sorted(tools) for kind, tools in sorted(reports.items())},
                "listed_s_ago": round(app.clock() - max(verified), 1) if verified else None,
            }
    return {
        "version": VERSION,
        "view": snapshot.view.digest if snapshot is not None else None,
        "fresh": app.policy.fresh() is not None,
        "servers": servers,
    }


class AdminApp:
    """The gateway's admin socket: ``GET /status``, and ``review`` (one at a time)."""

    def __init__(self, app: GatewayApp) -> None:
        self.app = app
        self.reviewing = anyio.Lock()

    async def answer(self, method: str, path: str) -> tuple[int, dict[str, Any]]:
        if (method, path) == ("GET", "/status"):
            return 200, status(self.app)
        found = _REVIEW_PATH.fullmatch(path)
        if found is None:
            return 404, {"error": "not found"}
        if method != "POST":
            return 405, {"error": "use POST"}
        async with self.reviewing:
            try:
                return 200, await review.review(
                    self.app, found.group(1), clear=found.group(2) is not None
                )
            except review.ReviewError as exc:
                return exc.status, exc.answer()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return
        code, data = await self.answer(scope["method"], scope["path"])
        body = json.dumps(data).encode()
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
        ]
        await send({"type": "http.response.start", "status": code, "headers": headers})
        await send({"type": "http.response.body", "body": body})


class _Server(uvicorn.Server):
    def install_signal_handlers(self) -> None:
        pass

    @contextlib.contextmanager
    def capture_signals(self) -> Iterator[None]:
        yield


def _split_listen(listen: str) -> tuple[str, int]:
    host, _, port = listen.rpartition(":")
    return host.strip("[]"), int(port)


async def serve(gateway: Gateway, options: Options) -> None:
    host, port = _split_listen(options.listen)
    servers = [
        _Server(
            uvicorn.Config(
                gateway.app,
                host=host,
                port=port,
                http="h11",
                proxy_headers=False,  # X-Forwarded-For is never trusted
                server_header=False,
                date_header=False,
                access_log=False,
                log_level="critical",
                lifespan="on",
                timeout_keep_alive=KEEP_ALIVE,
                timeout_graceful_shutdown=STOP_GRACE,
            )
        )
    ]
    if options.admin_socket is not None:
        check_private_dir(options.admin_socket.parent)
        with contextlib.suppress(FileNotFoundError):
            options.admin_socket.unlink()
        servers.append(
            _Server(
                uvicorn.Config(
                    AdminApp(gateway.app),
                    uds=str(options.admin_socket),
                    server_header=False,
                    date_header=False,
                    access_log=False,
                    log_level="critical",
                    lifespan="off",
                )
            )
        )

    def stop() -> None:
        for server in servers:
            server.should_exit = True

    def reload() -> None:
        gateway.app.policy.refresh()
        if gateway.keys is not None and gateway.keys.reload():
            logs.event("gateway_key_reloaded")

    loop = asyncio.get_running_loop()
    if sys.platform != "win32":
        loop.add_signal_handler(signal.SIGTERM, stop)
        loop.add_signal_handler(signal.SIGINT, stop)
        loop.add_signal_handler(signal.SIGHUP, reload)
    tasks = []
    transport = None
    try:
        if options.control_fd is not None:
            reader, transport = await control.open_control(options.control_fd)
            tasks.append(
                asyncio.create_task(
                    control.read_control(reader, reload=reload, stop=stop, event=logs.event)
                )
            )
        logs.event(
            "gateway_started",
            listen=options.listen,
            vault=gateway.link.kind,
            version=VERSION,
        )
        await asyncio.gather(*(server.serve() for server in servers))
    finally:
        for task in tasks:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        if transport is not None:
            transport.close()
        logs.event("gateway_stopped")


def run(options: Options, environ: Mapping[str, str]) -> None:
    """Start the gateway and serve until stopped. Raises :class:`StartupError`."""
    quiet_sdk_loggers()
    gateway = prepare(options, environ)
    asyncio.run(serve(gateway, options))
