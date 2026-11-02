"""A real vault that holds calls, an echo upstream behind it, and a scripted approver surface (M8
design step 9: J2-J3's vault half with a scripted surface).

The vault runs on the link given: ``tcp`` (uvicorn on a thread, with the gateway key, as the
hardened tier), ``unix`` (the link socket, Linux only) or ``asgi`` (in the test's own loop, for
the unit tests' leak sweep). Its upstream is an ASGI app on the vault's own HTTP client, which
records every request it gets and answers a JSON-RPC result. The SMTP connector's transport is a
recorder too. A :class:`Surface` records each hold it is shown and decides nothing until the test
says, through :meth:`HoldRig.decide`, which runs on the vault's own event loop.

Every wait is a condition the test waits for in a worker thread, bounded; nothing sleeps.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
import tempfile
import threading
import time
from collections.abc import AsyncIterator, Callable, Iterator
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import Any, Literal, TypeVar

import anyio
import httpx
import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

from tests.fakes.harness import serve
from tests.unit.test_peer import my_uid, serve_link
from zoeymcp.common import canonical, ledgerformat
from zoeymcp.common.policy import Policy
from zoeymcp.common.policy.schema import hash_token
from zoeymcp.vault.app import GATEWAY_HEADER, VaultApp
from zoeymcp.vault.approvers import ApproverHub, Shown, SurfaceName
from zoeymcp.vault.connectors.smtp import SendResult, SmtpConnectors
from zoeymcp.vault.holds import Hold
from zoeymcp.vault.keys import KeySet
from zoeymcp.vault.server import ListenerTag
from zoeymcp.vault.store import SecretStore, origin_binding, smtp_binding
from zoeymcp.vault.vaultledger import CHAIN_DIR, VaultLedger

T = TypeVar("T")
KEYS = KeySet.from_master(bytes(range(96, 128)))
BOUND = 30  # seconds: every wait's own bound
SECRET = "sk-live-hold-3f9c2a71d8e4"
MAIL_PASSWORD = "mail-pass-7c1e9b2f"
PIN = "sha256:" + "c" * 64
OTHER_PIN = "sha256:" + "d" * 64
EPOCH = "0123456789ab"
LEGACY = "2025-11-25"
MODERN = "2026-07-28"
SENDER = "Agent <agent@mail.example>"
TO = ["partner@mail.example"]
LINKS = ["tcp", pytest.param("unix", marks=pytest.mark.skipif(
    sys.platform != "linux", reason="the link socket's peer check is Linux only"
))]  # fmt: skip
Link = Literal["tcp", "unix", "asgi"]


def document(
    *,
    block_seconds: int = 120,
    timeout: int = 3600,
    surfaces: tuple[SurfaceName, ...] = ("portal",),
    attended: bool = True,
    out_of_band: bool = False,
    held: tuple[str, ...] = ("place_order",),
    pins: dict[str, str] | None = None,
    allow: tuple[str, ...] = ("list_items",),
    cooldown: int = 15,
    per_hour: int = 30,
    mail: bool = False,
) -> dict[str, Any]:
    """The rig's policy, as a document: route ``shop`` to the echo upstream, with server ``shop``
    on ``/mcp`` (``place_order`` held, ``cancel_order`` gateway-held, ``list_items`` allowed,
    ``refund`` declined) and ``notes`` on ``/notes`` (holding nothing); with ``mail``, the SMTP
    connector ``mail-out`` on route ``mail``, held for its writer, the toolkit ``mailer``."""
    approve = ["place_order", "cancel_order"]
    approve = [tool for tool in approve if tool not in allow]
    approvers: dict[str, Any] = {"timeout": timeout, "block_seconds": block_seconds}
    if "portal" in surfaces:
        approvers["portal"] = {}
    if "telegram" in surfaces:
        approvers["telegram"] = {"bot_token": "store:approver-bot", "user_id": 7, "chat_id": 7}
    servers: dict[str, Any] = {
        "shop": {
            "kind": "remote",
            "route": "shop",
            "path": "/mcp",
            "tools": {
                "include": ["place_order", "cancel_order", "list_items"],
                "allow": list(allow),
                "approve": approve,
                "vault_approval": list(held),
            },
            "review": pins or {"place_order": PIN, "cancel_order": PIN, "list_items": PIN},
            "declined": {"refund": PIN},
        },
        "notes": {
            "kind": "remote",
            "route": "shop",
            "path": "/notes",
            "tools": {"include": ["read_note"], "allow": ["read_note"]},
            "review": {"read_note": PIN},
        },
    }
    routes: list[dict[str, Any]] = [
        {
            "name": "shop",
            "prefix": "/shop",
            "upstream": "https://shop.example/base",
            "credential": "shop-key",
            "callers": ["gateway"],
            "rules": [{"methods": ["GET", "POST", "DELETE"], "paths": ["/**"]}],
        }
    ]
    connectors: dict[str, Any] = {}
    if mail:
        servers["mailer"] = {
            "kind": "toolkit",
            "module": "tests.toolkits.mailer",
            "call_timeout": 100,
            "tools": {
                "include": ["send_mail"],
                "approve": ["send_mail"],
                "vault_approval": ["send_mail"],
            },
            "review": {"send_mail": PIN},
            "slots": {
                "out": {
                    "route": "mail",
                    "rules": [{"methods": ["POST"], "paths": ["/send"], "approved": True}],
                }
            },
        }
        connectors["mail-out"] = {
            "kind": "smtp",
            "host": "mail.example",
            "port": 465,
            "username": "agent",
            "password": "store:mail-pass",
            "from": SENDER,
            "to": TO,
        }
        routes.append(
            {
                "name": "mail",
                "prefix": "/mail",
                "connector": "mail-out",
                "callers": ["gateway"],
                "rules": [
                    {"methods": ["GET"], "paths": ["/config"]},
                    {"methods": ["POST"], "paths": ["/send"]},
                ],
            }
        )
    own = {"attended": attended, "out_of_band": out_of_band, "renders": "plain"}
    return {
        "version": 1,
        "mode": "declarative",
        "credentials": {"shop-key": {"kind": "header", "secret": "store:shop-key"}},
        "connectors": connectors,
        "routes": routes,
        "approvers": approvers,
        "gateway": {
            "approvals": {"cooldown": cooldown, "max_prompts_per_hour": per_hour},
            "clients": {
                name: {
                    "token_sha256": hash_token(f"zgc1-{name}-token"),
                    "servers": ["shop", "notes", *(("mailer",) if mail else ())],
                    "approvals": own,
                }
                for name in ("agent1", "agent2")
            },
            "servers": servers,
        },
    }


def policy(**options: Any) -> Policy:
    return Policy.model_validate(document(**options))


def call(
    name: str = "place_order",
    arguments: Any = None,
    *,
    id: str | int = 1,
    method: str = "tools/call",
    meta: dict[str, Any] | None = None,
) -> bytes:
    """A JSON-RPC request's bytes, canonical."""
    params: dict[str, Any] = {"name": name, "arguments": {"item": "kettle", "qty": 2}}
    if arguments is not None:
        params["arguments"] = arguments
    if meta is not None:
        params["_meta"] = meta
    return canonical.dumps_canonical(
        {"jsonrpc": "2.0", "id": id, "method": method, "params": params}
    )


def marker(
    ref: str,
    *,
    client: str = "agent1",
    wait: str = "block",
    epoch: str = EPOCH,
    tool: str | None = None,
) -> str:
    """The gateway's ``x-zoeymcp-held`` header (B.2 E14)."""
    value = f"v1; ref={ref}; client={client}; wait={wait}; epoch={epoch}"
    return value if tool is None else f"{value}; tool={tool}"


def headers(*, version: str = LEGACY, held: str | None = None, **more: str) -> dict[str, str]:
    found = {"content-type": "application/json", "mcp-protocol-version": version, **more}
    if held is not None:
        found["x-zoeymcp-held"] = held
    return found


class Surface:
    """A scripted approver surface (D.1): records each hold it is shown, each approval it is
    told of, each close (and the hold as closed) and each notice, and decides only through the
    rig."""

    def __init__(self, name: SurfaceName) -> None:
        self._name: SurfaceName = name
        self.shown: list[Hold] = []
        self.approvals: list[Hold] = []
        self.closed: list[tuple[str, str]] = []
        self.ended: list[Hold] = []
        self.notices: list[str] = []
        self._changed = threading.Condition()

    @property
    def name(self) -> SurfaceName:
        return self._name

    async def show(self, hold: Hold) -> Shown:
        with self._changed:
            self.shown.append(hold)
            self._changed.notify_all()
        return Shown(self._name)

    async def approved(self, hold: Hold) -> None:
        with self._changed:
            self.approvals.append(hold)
            self._changed.notify_all()

    async def close(self, hold: Hold, outcome: str) -> None:
        with self._changed:
            self.closed.append((hold.id, outcome))
            self.ended.append(hold)
            self._changed.notify_all()

    async def notice(self, text: str) -> None:
        with self._changed:
            self.notices.append(text)
            self._changed.notify_all()

    async def until(self, ready: Callable[[], bool]) -> None:
        """Wait, in a worker thread, until ``ready()`` (bounded)."""

        def wait() -> None:
            with self._changed:
                if not self._changed.wait_for(ready, BOUND):
                    raise TimeoutError("the surface never saw it")

        await anyio.to_thread.run_sync(wait)

    async def holds(self, count: int) -> list[Hold]:
        await self.until(lambda: len(self.shown) >= count)
        return list(self.shown)


class Upstream:
    """The echo MCP upstream: records every request, and answers a ``tools/call`` with a result
    (that echoes the credential it was sent, with ``echo``). With ``gate`` set, a POST waits for
    it before it answers; with ``redirect``, a POST is answered a redirect, which the vault never
    follows (a forward that fails after its approval)."""

    def __init__(self) -> None:
        self.received: list[tuple[str, str, dict[str, str], bytes]] = []
        self.echo = False
        self.redirect = False
        self.gate: threading.Event | None = None
        self.answering = threading.Event()

    def app(self) -> Starlette:
        return Starlette(
            routes=[Route("/base/{rest:path}", self._mcp, methods=["GET", "POST", "DELETE"])]
        )

    async def _mcp(self, request: Request) -> Response:
        body = await request.body()
        self.received.append((request.method, request.url.path, dict(request.headers), body))
        if request.method != "POST":
            return Response(b"listening", media_type="text/plain")
        self.answering.set()
        if self.gate is not None:
            gate = self.gate
            await anyio.to_thread.run_sync(lambda: gate.wait(BOUND))
        if self.redirect:
            return Response(status_code=307, headers={"location": "https://elsewhere.example/"})
        message = json.loads(body)
        text = "done"
        if self.echo:
            text = f"you sent {request.headers.get('authorization')}"
        result = {"content": [{"type": "text", "text": text}], "isError": False}
        return JSONResponse({"jsonrpc": "2.0", "id": message.get("id"), "result": result})

    def posts(self) -> list[bytes]:
        return [body for method, _, _, body in self.received if method == "POST"]


class _LoopTag:
    """Records the vault's event loop on every request, so the rig can run code on it."""

    def __init__(self, app: ASGIApp, rig: HoldRig) -> None:
        self.app, self.rig = app, rig

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        self.rig.loop = asyncio.get_running_loop()
        await self.app(scope, receive, send)


class Clock:
    """The hold table's monotonic clock: real time, plus what the test adds."""

    def __init__(self) -> None:
        self.ahead = 0.0
        self._start = time.monotonic()

    def __call__(self) -> float:
        return time.monotonic() - self._start + 1000.0 + self.ahead


class HoldRig:
    """One vault holding calls on ``link``, with its upstream, its chain and its surfaces."""

    def __init__(
        self,
        tmp_path: Path,
        options: dict[str, Any] | None = None,
        *,
        link: str = "tcp",
        surfaces: tuple[SurfaceName, ...] = ("portal",),
    ) -> None:
        self.link: Link = "asgi" if link == "asgi" else "unix" if link == "unix" else "tcp"
        self.options = {"surfaces": surfaces, **(options or {})}
        self.state = tmp_path / "vault"
        tmp_path.mkdir(mode=0o700, exist_ok=True)
        self.state.mkdir(mode=0o700, exist_ok=True)
        self.store = SecretStore(self.state, KEYS)
        self.store.load()
        self.store.put("shop-key", SECRET, origin_binding(["https://shop.example"]))
        self.store.put("mail-pass", MAIL_PASSWORD, smtp_binding("mail.example", 465, SENDER, TO))
        self.upstream = Upstream()
        self.mail: list[dict[str, Any]] = []
        self.chain = VaultLedger.open_at(self.state, KEYS.chain_key)
        self.surfaces = {name: Surface(name) for name in surfaces}
        self.clock = Clock()
        self.loop: asyncio.AbstractEventLoop | None = None
        client = httpx.AsyncClient(transport=httpx.ASGITransport(app=self.upstream.app()))
        self.app = VaultApp(
            Policy.model_validate(document(**self.options)),
            self.store,
            KEYS,
            client=client,
            environ={},
            gateway_link=link == "unix",
            connectors=SmtpConnectors(self.state, KEYS, transport=self._send),
            chain=self.chain,
            hub=ApproverHub(self.surfaces.values()),
            hold_clock=self.clock,
        )

    @property
    def surface(self) -> Surface:
        return next(iter(self.surfaces.values()))

    @staticmethod
    def now_ms() -> int:
        """The wall clock in milliseconds, as the result store reads it."""
        return int(time.time() * 1000)

    def _send(self, connector: Any, **sent: Any) -> SendResult:
        self.mail.append({k: v for k, v in sent.items() if k != "tls"})
        return SendResult("final_reply", final_dot_written=True, reply_code=250)

    @asynccontextmanager
    async def running(self) -> AsyncIterator[httpx.AsyncClient]:
        """A client of the vault on the rig's link; the vault stops after it."""
        tagged = _LoopTag(self.app, self)
        if self.link == "asgi":
            transport = httpx.ASGITransport(app=ListenerTag(tagged, "gateway"))
            async with httpx.AsyncClient(transport=transport, base_url="http://vault") as http:
                yield http
        elif self.link == "tcp":
            with serve(tagged) as url:
                key = {GATEWAY_HEADER: KEYS.gateway_key(1)}
                async with httpx.AsyncClient(base_url=url, headers=key, timeout=BOUND) as http:
                    yield http
                await self.stop()
        else:
            with link_socket(ListenerTag(tagged, "gateway")) as path:
                socket = httpx.AsyncHTTPTransport(uds=path)
                async with httpx.AsyncClient(
                    transport=socket, base_url="http://vault", timeout=BOUND
                ) as http:
                    yield http
                await self.stop()
        await self.app.aclose()

    async def on_vault(self, work: Callable[[], T]) -> T:
        """Run ``work`` on the vault's event loop (in its own synchronous section)."""
        loop = self.loop
        assert loop is not None, "no request has reached the vault yet"

        async def run() -> T:
            return work()

        future = asyncio.run_coroutine_threadsafe(run(), loop)
        return await anyio.to_thread.run_sync(lambda: future.result(BOUND))

    async def settled(self) -> None:
        """Wait until every hold's ending is on the chain and told."""
        loop = self.loop
        if loop is None:
            return
        future = asyncio.run_coroutine_threadsafe(self.app.settle(), loop)
        await anyio.to_thread.run_sync(lambda: future.result(BOUND))

    async def stop(self) -> None:
        """The vault's stop (I.2): undecided holds withdrawn, forwards drained."""
        loop = self.loop
        if loop is None or loop.is_closed():
            return

        async def stop() -> None:
            self.app.stop_holds()
            await self.app.drain_holds()
            await self.app.settle()

        future = asyncio.run_coroutine_threadsafe(stop(), loop)
        await anyio.to_thread.run_sync(lambda: future.result(BOUND))

    async def decide(
        self,
        hold: Hold,
        decision: Literal["approve", "deny"] = "approve",
        via: SurfaceName | None = None,
        digest: str | None = None,
    ) -> Any:
        """A surface's decision on ``hold``, as ``VaultApp.decide`` answers it."""
        return await self.on_vault(
            lambda: self.app.decide(
                hold.id, decision, via or self.surface.name, digest or hold.text_sha256
            )
        )

    async def reload(self, **options: Any) -> None:
        """Install the rig's policy with ``options`` changed, as a reload does."""
        self.options = {**self.options, **options}
        changed = Policy.model_validate(document(**self.options))
        await self.on_vault(lambda: self.app.reload(changed))

    async def later(self, seconds: float) -> None:
        """Move the hold table's clock on, and run the sweeper's tick."""
        self.clock.ahead += seconds
        await self.on_vault(self.app.sweep_holds)

    def records(self) -> list[ledgerformat.Record]:
        found: list[ledgerformat.Record] = []
        for path in sorted((self.state / CHAIN_DIR).glob("*.jsonl")):
            found.extend(ledgerformat.parse(line) for line in path.read_bytes().splitlines())
        return found

    def kinds(self, ref: str) -> list[tuple[str, Any]]:
        """The chain's records for ``ref``: each kind, with its decision or outcome."""
        return [
            (r.kind, r.fields.get("decision") or r.fields.get("outcome"))
            for r in self.records()
            if r.ref == ref
        ]


@contextmanager
def link_socket(app: Any) -> Iterator[str]:
    """``app`` on a link socket with the peer check (Linux only)."""
    # A short path: AF_UNIX paths are limited to about 100 bytes.
    directory = Path(tempfile.mkdtemp(prefix="zm-", dir="/tmp"))
    os.chmod(directory, 0o700)
    try:
        path = str(directory / "vault.sock")
        with serve_link(app, path, my_uid()):
            yield path
    finally:
        shutil.rmtree(directory, ignore_errors=True)


class Answer:
    """A request sent in the background, and its answer once it came."""

    def __init__(self) -> None:
        self.response: httpx.Response | None = None
        self.error: BaseException | None = None
        self.done = anyio.Event()

    async def post(
        self, http: httpx.AsyncClient, path: str, body: bytes, sent: dict[str, str]
    ) -> None:
        try:
            self.response = await http.post(path, content=body, headers=sent)
        except BaseException as exc:  # a test reads it; a cancel is re-raised
            self.error = exc
            raise
        finally:
            self.done.set()

    def json(self) -> dict[str, Any]:
        assert self.response is not None, self.error
        found: dict[str, Any] = self.response.json()
        return found
