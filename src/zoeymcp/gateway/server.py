"""``zoeymcp gateway``: the gateway process (M3 design B.1).

It refuses to start with a master key or ``ZOEYMCP_CONFIG`` in its environment (G1), or as root
(``--allow-root`` is for development). The ``http://`` link needs the gateway key; with
``unix:`` a key is ignored. ``SIGHUP`` (or ``HUP`` on the control pipe) fetches the view now
and re-reads the key file; ``SIGTERM`` (or ``TERM``, or the pipe's end) stops, giving calls in
flight 10 seconds. The admin socket answers ``GET /status``, ``POST /review/<server>`` and
``POST /review/<server>/clear`` (:mod:`.review`); the same reviews run for the vault's review
jobs, one at a time with the socket's (:mod:`.reviewpoll`, M7 design F.3). A summary of the
status is pushed to the vault (:mod:`.statuspush`, M6 design K.1), with what the restore witness
holds: the highest revision of each deployment the vault's view answers stated, kept in
``policy-seen.json`` beside the drift marks, and read again at every start (M6 design K.3,
FM-20); a file that can't be read stops the start. The status and every review
answer on the socket carry ``policy_mode``, the mode the vault last stated beside the view
(``unknown`` before the first), so the CLI in this container, which has no vault socket, knows
not to print a fragment for a managed deployment (M6 design G.9, E-7).

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
from urllib.parse import parse_qsl

import anyio
import uvicorn
from starlette.types import Receive, Scope, Send

from ..common import canonical, control
from ..common.policy.attention import Attention, attention, combined
from ..common.policy.schema import GatewayLimits
from ..common.policy.view import ViewRemoteServer, ViewToolkitServer
from . import logs, review
from .app import GatewayApp
from .defstore import DefinitionStore
from .ledger import Ledger
from .marks import DriftMarks, MarksError
from .pins import Entries, enabled_kinds, entries
from .policyclient import Witness
from .toolkits import Loaded, Toolkits
from .upstream import Connection, UpstreamPool
from .vaultlink import (
    KeySource,
    Link,
    LinkError,
    environ_has_no_secrets,
    parse_link,
    report_client,
    review_client,
    running_as_root,
    status_client,
    view_client,
)
from .witness import FILE as WITNESS_FILE
from .witness import WitnessError

STOP_GRACE = 10
KEEP_ALIVE = 5
VERSION = "1"
_REVIEW_PATH = re.compile(r"/review/([a-z0-9][a-z0-9_-]{0,62})(/clear)?")
_LEDGER_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_LEDGER_REF = re.compile(r"^[0-9a-f]{16}$")
MAX_ADMIN_BODY = 2**20


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
    allow_writable_toolkits: bool = False  # development and tests: skips H.2's origin check


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
    try:
        seen = Witness.load(options.state)
    except WitnessError as exc:
        raise StartupError(
            f"the restore witness: {exc} (move {WITNESS_FILE} aside to start over)"
        ) from exc
    pool = UpstreamPool(link, keys, marks, DefinitionStore(options.state))
    toolkits = Toolkits(link, keys, marks, allow_writable=options.allow_writable_toolkits)
    app = GatewayApp(
        pool,
        view_client(link, keys),
        toolkits=toolkits,
        report_http=report_client(link, keys),
        review_http=review_client(link, keys),
        status_http=status_client(link, keys),
        status=pushed_status,
        witness=seen,
    )
    try:
        # The view's limit applies once the first view arrives.
        app.ledger, _ = Ledger.open_at(options.state, max_bytes=GatewayLimits().ledger_max_bytes)
    except OSError as exc:
        raise StartupError(f"the approval ledger: {exc.strerror or exc}") from exc
    return Gateway(app, link, keys)


def status(app: GatewayApp, *, pins: bool = False) -> dict[str, Any]:
    """G.5's status: per server, never definitions or token hashes. The reports count
    ``unreviewed`` and ``declined`` tools apart, and ``attention`` is the attention decision for
    the server's latest listings (M6 design J.5), ``None`` before any listing; ``blocked`` is
    whether ``on_drift: fail`` stopped any of its connections (``pins.evaluate``). ``offered`` is
    what a remote upstream advertises beyond tools, ``None`` before a connection has one
    (fold-in 3.8). A remote server whose view enables prompts or resources also has ``kinds``:
    for each kind it enables (``pins.enabled_kinds``), the attention decision over that kind's
    listings, its block and its marks, combined across connections as the tools' is (M6 design
    K.1, Y29), names only; a server that enables neither has no ``kinds``. With ``pins``, each
    server's ``unreviewed_pins`` is the pin each of its unreviewed tools is listed at, for the
    status report (:func:`pushed_status`). ``policy_mode`` is the mode the vault last stated
    beside the view (M6 design K.3)."""
    snapshot = app.policy.snapshot
    servers: dict[str, Any] = {}
    if snapshot is not None:
        for name, server in snapshot.view.gateway.servers.items():
            if isinstance(server, ViewToolkitServer):
                servers[name] = _toolkit_status(app, name, server, pins=pins)
                continue
            connections = [c for c in app.pool.connections() if c.server == name]
            phases = sorted({c.state.phase.value for c in connections})
            exposed = set()
            reports: dict[str, set[str]] = {}
            verified = [c.state.verified_at for c in connections if c.state.verified_at is not None]
            marks = app.pool.marks.for_server(name)
            found = []
            listed: dict[str, str] = {}
            offers: list[dict[str, bool]] = []
            blocked = False
            for connection in connections:
                evaluation = connection.state.evaluation
                if evaluation is not None:
                    blocked = blocked or evaluation.blocked
                    exposed |= set(evaluation.exposed)
                    for report in evaluation.reports:
                        reports.setdefault(report.kind, set()).add(report.tool)
                    found.append(attention(evaluation.listed, server, marks))
                    for tool, pin in evaluation.listed.items():
                        if pin is not None:
                            listed.setdefault(tool, pin)
                if connection.client is not None:
                    offers.append(review.offered(connection.client.server_capabilities))
            decided = combined(found) if found else None
            servers[name] = {
                "kind": "remote",
                "state": phases or ["idle"],
                "era": app.pool.eras.get(name),
                "connections": len(connections),
                "included": len(server.tools.include),
                "exposed": len(exposed),
                "marked": sorted(tool for tool, _ in app.pool.marks.for_server(name)),
                "reports": {kind: sorted(tools) for kind, tools in sorted(reports.items())},
                "attention": decided.as_dict() if decided is not None else None,
                "blocked": blocked,
                "offered": (
                    {kind: any(offer[kind] for offer in offers) for kind in offers[0]}
                    if offers
                    else None
                ),
                "listed_s_ago": round(app.clock() - max(verified), 1) if verified else None,
            }
            kinds = _kinds_status(app, name, server, connections)
            if kinds:
                servers[name]["kinds"] = kinds
            if pins:
                servers[name]["unreviewed_pins"] = _pins_of(decided, listed)
    return {
        "version": VERSION,
        "view": snapshot.view.digest if snapshot is not None else None,
        "fresh": app.policy.fresh() is not None,
        "servers": servers,
        "policy_mode": app.policy.mode,
    }


@dataclass(frozen=True)
class _KindPolicy:
    """One kind's block of a remote server (``pins.entries``), as the attention decision reads
    a server's tools: its ``include`` in ``tools``, its pins and its declines."""

    tools: Entries
    review: Mapping[str, str]
    declined: Mapping[str, str]


def _kinds_status(
    app: GatewayApp, name: str, server: ViewRemoteServer, connections: list[Connection]
) -> dict[str, dict[str, list[str]]]:
    """Each kind beyond tools the server enables, with the attention decision over its
    connections' latest listings of it (empty lists before any), in ``pins.KINDS`` order."""
    found: dict[str, dict[str, list[str]]] = {}
    for kind in enabled_kinds(server.enable):
        block = entries(server, kind)
        policy = _KindPolicy(block, block.review, block.declined)
        marks = app.pool.marks.for_server(name, kind)
        decided = [
            attention(listing.listed, policy, marks)
            for connection in connections
            if connection.state.evaluation is not None
            and (listing := connection.state.evaluation.kinds.get(kind)) is not None
        ]
        found[kind] = combined(decided).as_dict()
    return found


def _toolkit_status(
    app: GatewayApp, name: str, server: ViewToolkitServer, *, pins: bool
) -> dict[str, Any]:
    found = app.toolkits.get(name)
    if not isinstance(found, Loaded):
        return {
            "kind": "toolkit",
            "state": "unavailable",
            "reason": found.reason if found is not None else "not_loaded",
        }
    reports: dict[str, set[str]] = {}
    for report in found.evaluation.reports:
        reports.setdefault(report.kind, set()).add(report.tool)
    marks = app.pool.marks.for_server(name)
    decided = attention(
        found.evaluation.listed, review.toolkit_reviewed(server, found.evaluation), marks
    )
    entry: dict[str, Any] = {
        "kind": "toolkit",
        "state": "loaded",
        "module": found.module,
        "distribution": found.distribution,
        "version": found.version,
        "pinning": server.pinning,
        "included": len(server.tools.include),
        "exposed": len(found.evaluation.exposed),
        "marked": sorted(tool for tool, _ in marks),
        "reports": {kind: sorted(tools) for kind, tools in sorted(reports.items())},
        "attention": decided.as_dict(),
        "blocked": found.evaluation.blocked,
    }
    if pins:
        entry["unreviewed_pins"] = _pins_of(decided, found.evaluation.listed)
    return entry


def pushed_status(app: GatewayApp) -> dict[str, Any]:
    """The status the gateway pushes to the vault is drawn from (M6 design K.1): :func:`status`
    with each unreviewed tool's pin, and the restore witness (K.3): the highest revision seen of
    each deployment, first seen first, and how many deployments it has recorded."""
    found = status(app, pins=True)
    held = app.policy.witness
    found["witness"] = {} if held is None else held.seen.report()
    found["deployments_seen"] = 0 if held is None else held.seen.counted
    return found


def _pins_of(decided: Attention | None, listed: Mapping[str, str | None]) -> dict[str, str]:
    """The pin each tool nobody reviewed is listed at, by name."""
    if decided is None:
        return {}
    return {tool: pin for tool in decided.unreviewed() if (pin := listed.get(tool)) is not None}


class AdminApp:
    """The gateway's admin socket: ``GET /status``, ``review`` (one at a time, on the gateway's
    ``reviewing`` lock, which the review poller shares), and the ledger: ``GET /ledger``,
    ``POST /ledger/verify`` and ``POST /ledger/check``."""

    def __init__(self, app: GatewayApp) -> None:
        self.app = app

    async def answer(
        self, method: str, path: str, query: str = "", body: bytes = b""
    ) -> tuple[int, dict[str, Any]]:
        if (method, path) == ("GET", "/status"):
            return 200, status(self.app)
        if path == "/ledger" or path.startswith("/ledger/"):
            return await self._ledger(method, path, query, body)
        found = _REVIEW_PATH.fullmatch(path)
        if found is None:
            return 404, {"error": "not found"}
        if method != "POST":
            return 405, {"error": "use POST"}
        async with self.app.reviewing:
            try:
                answer = await review.review(
                    self.app, found.group(1), clear=found.group(2) is not None
                )
            except review.ReviewError as exc:
                return exc.status, {**exc.answer(), "policy_mode": self.app.policy.mode}
        return 200, {**answer, "policy_mode": self.app.policy.mode}

    async def _ledger(
        self, method: str, path: str, query: str, body: bytes
    ) -> tuple[int, dict[str, Any]]:
        ledger = self.app.ledger
        if ledger is None:
            return 503, {"error": "no approval ledger"}
        if path == "/ledger":
            if method != "GET":
                return 405, {"error": "use GET"}
            options = _ledger_query(query)
            if isinstance(options, str):
                return 400, {"error": options}
            found = await anyio.to_thread.run_sync(lambda: ledger.read(**options))
            return 200, {"records": found, "head_seq": ledger.next_seq - 1}
        if method != "POST":
            return 405, {"error": "use POST"}
        if path == "/ledger/verify":
            return 200, await anyio.to_thread.run_sync(ledger.verify)
        if path == "/ledger/check":
            try:
                request = canonical.loads_strict(body, max_bytes=MAX_ADMIN_BODY)
            except (canonical.JSONRejected, ValueError):
                return 400, {"error": "the body must be a JSON object"}
            ref = request.get("ref") if isinstance(request, dict) else None
            if not isinstance(ref, str) or not _LEDGER_REF.fullmatch(ref) or "args" not in request:
                return 400, {"error": 'send {"ref": <16 hex>, "args": <the arguments>}'}
            args = request["args"]
            return 200, await anyio.to_thread.run_sync(lambda: ledger.check(ref, args))
        return 404, {"error": "not found"}

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return
        body = b""
        if scope["method"] == "POST":
            while True:
                message = await receive()
                body += message.get("body", b"")
                if len(body) > MAX_ADMIN_BODY or not message.get("more_body"):
                    break
        query = scope.get("query_string", b"").decode("latin-1")
        code, data = await self.answer(scope["method"], scope["path"], query, body)
        body = json.dumps(data).encode()
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
        ]
        await send({"type": "http.response.start", "status": code, "headers": headers})
        await send({"type": "http.response.body", "body": body})


def _ledger_query(query: str) -> dict[str, Any] | str:
    """``GET /ledger``'s options, or what's wrong with them."""
    options: dict[str, Any] = {}
    for name, value in parse_qsl(query, keep_blank_values=True):
        if name in ("after", "limit"):
            if not re.fullmatch(r"-?[0-9]{1,12}", value):
                return f"{name} must be a whole number"
            options[name] = int(value)
        elif name in ("client", "server", "tool"):
            if not _LEDGER_NAME.fullmatch(value):
                return f"{name} must be a policy name"
            options[name] = value
        else:
            return f"unknown option {name[:32]!r}"
    return options


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
        # First, so new approvals are refused while uvicorn drains (M4 design B.6).
        gateway.app.request_stop()
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
