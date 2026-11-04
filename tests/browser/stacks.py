"""What the browser tests run against: thin wrappers over the rigs and fakes that exist (D-222).

:func:`portal` is ``tests.portal.rig.running``: the real vault and portal on a server thread,
sockets bound first, a :class:`Clock` the test moves. :class:`GatewayDeployment` (the vault and
gateway in process against the MCP fake) and :class:`ManagedVault` (a vault process) are the
acceptance rigs, for the later items. Two small servers of the harness's own, each on loopback
with its socket bound before the test names its port: :class:`Neighbour`, a page on another
``localhost`` port (manual item 10), and :class:`Forwarder`, a byte-for-byte forwarder from a
second port to the portal's listener, as an SSH tunnel is (item 12).

The Approvals queue's stacks (step 27b, items 25-30, 33 and 34): :func:`queue` is the portal rig
holding calls, as ``tests/portal/test_approvals_queue.py`` runs it, with the calls sent as the
gateway sends them (:class:`QueueStack`); :func:`gateway_queue` puts a real gateway and an agent in
front of it, as ``tests/acceptance/test_vault_approval_shapes.py``'s S20 does, for ``pending`` and
``check_approval``. Telegram is never reached: where an item has Telegram decide, the vault runs
its own Telegram surface against the fake Bot API (``tests/fakes/telegram.py``) in process, on an
ASGI transport with short timings, as ``tests/acceptance/test_telegram_approver.py`` runs it, and
the operator presses its buttons there (S20's own stack keeps its scripted surface).
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import http.server
import socket
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import TracebackType
from typing import Any, Self
from unittest import mock

import httpx
from anyio.from_thread import BlockingPortal, start_blocking_portal

from tests.acceptance.gateway import SERVER, GatewayDeployment
from tests.acceptance.procs import ManagedVault
from tests.acceptance.test_mcp_shapes import KEY, text
from tests.acceptance.test_vault_approval_shapes import gateway_on, queue_policy, ref_of
from tests.fakes.harness import serve
from tests.fakes.mcp_server import McpFake
from tests.fakes.telegram import BotApi, Person, Stored
from tests.gateway import holdrig
from tests.gateway.rig import agent, until
from tests.portal.rig import Clock, PortalRig
from tests.portal.rig import running as portal
from zoeymcp.common import approvaltext, canonical
from zoeymcp.common.policy.schema import hash_token
from zoeymcp.gateway import checkapproval
from zoeymcp.vault import netclient, telegramwire
from zoeymcp.vault import telegram as telegram_approver
from zoeymcp.vault.app import GATEWAY_HEADER
from zoeymcp.vault.holds import Hold
from zoeymcp.vault.store import origin_binding

__all__ = [
    "Clock",
    "Forwarder",
    "GatewayDeployment",
    "GatewayQueue",
    "ManagedVault",
    "Neighbour",
    "PortalRig",
    "QueueStack",
    "gateway_queue",
    "portal",
    "queue",
]

CHUNK = 65536
BOUND = 30.0  # seconds: a wait on the vault's loop, or an agent's call
# The queue's server: the vault holds each of these (its approve and vault_approval lists): four
# of them fill the route's 16 holds at four each (the per-tool cap), so a call to the fifth is
# refused by the route's cap alone ...
HELD_TOOLS = ("place_order", "refund", "restock", "void", "archive")
# ... and the gateway holds this one, relaying an out-of-band client's prompts to the vault.
RELAYED_TOOL = "cancel_order"
# The clients, each given the server: desk is attended, the others are asked out of band.
CLIENTS = {
    "desk": {"attended": True},
    "nightly": {"attended": False, "out_of_band": True},
    "ops": {"attended": False, "out_of_band": True},
    "audit": {"attended": False, "out_of_band": True},
}
SHOP = "/shop/mcp"
# The vault's Telegram surface on short timings (BP-10), and the fake Bot API's long poll: one
# second of a getUpdates timeout lasts 50 ms there (test_telegram_approver.py's).
TELEGRAM_TIMINGS = telegram_approver.Timings(
    send_spacing=0.05, contested_backoff=0.3, unreachable_after=0.6, backoff_max=0.2, poll_timeout=1
)
SECOND = 0.05
OPERATOR = Person(holdrig.OPERATOR_ID, "Operator", "operator_example")


def bound() -> socket.socket:
    """A listening socket on 127.0.0.1, so its port is known before anything starts."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen()
    return sock


class Neighbour:
    """Serves ``html`` at ``/<name>`` from 127.0.0.1, on the port it bound (``port``), until
    closed; any other path is a 404."""

    def __init__(self, name: str, html: str) -> None:
        body = html.encode("utf-8")
        path = f"/{name}"

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                found = self.path == path
                self.send_response(200 if found else 404)
                self.send_header("content-type", "text/html; charset=utf-8")
                self.send_header("content-length", str(len(body) if found else 0))
                self.end_headers()
                if found:
                    self.wfile.write(body)

            def log_message(self, format: str, *args: object) -> None:
                pass

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port: int = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def url(self, name: str) -> str:
        return f"http://localhost:{self.port}/{name}"

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(10)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        kind: type[BaseException] | None,
        error: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


class Forwarder:
    """Forwards each connection to ``port`` to ``target``, byte for byte in both directions, and
    keeps the browser's ``Host``. Bind it first (``Forwarder()``), name its port in the portal's
    origins, then :meth:`start` it once the target listens."""

    def __init__(self) -> None:
        self._sock = bound()
        self.port: int = self._sock.getsockname()[1]
        self._threads: list[threading.Thread] = []
        self._open: list[socket.socket] = []
        self._closed = False
        self._lock = threading.Lock()

    def start(self, target: tuple[str, int]) -> None:
        self._spawn(self._accept, target)

    def _spawn(self, run: Callable[..., None], *args: object) -> None:
        thread = threading.Thread(target=run, args=args, daemon=True)
        self._threads.append(thread)
        thread.start()

    def _accept(self, target: tuple[str, int]) -> None:
        while True:
            try:
                client, _ = self._sock.accept()
            except OSError:
                return  # closed
            try:
                upstream = socket.create_connection(target, timeout=10)
            except OSError:
                client.close()
                continue
            upstream.settimeout(None)
            with self._lock:
                if self._closed:  # accepted as close() ran: nothing pumps it
                    client.close()
                    upstream.close()
                    return
                self._open.extend((client, upstream))
            self._spawn(self._pump, client, upstream)
            self._spawn(self._pump, upstream, client)

    @staticmethod
    def _pump(source: socket.socket, sink: socket.socket) -> None:
        try:
            while chunk := source.recv(CHUNK):
                sink.sendall(chunk)
            sink.shutdown(socket.SHUT_WR)
        except OSError:
            pass  # either side closed

    def close(self) -> None:
        # Shut down before closing: on Linux a close from another thread doesn't wake a thread
        # blocked in accept() or recv(), a shutdown does.
        with self._lock:
            self._closed = True
            socks = [self._sock, *self._open]
        for sock in socks:
            with contextlib.suppress(OSError):  # not connected, or already shut
                sock.shutdown(socket.SHUT_RDWR)
            sock.close()
        for thread in self._threads:
            thread.join(10)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        kind: type[BaseException] | None,
        error: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


# --- the Approvals queue (step 27b) --------------------------------------------------------------


def queue_document(upstream: str, *, telegram: bool, timeout: int) -> dict[str, Any]:
    """The rig's policy beside its admin block: server ``shop`` on a local MCP route to the echo
    upstream with a credential, :data:`HELD_TOOLS` held by the vault and :data:`RELAYED_TOOL` by
    the gateway, each client of :data:`CLIENTS` given it; the portal's queue with no block (every
    held call answers pending and waits, detached) and ``timeout`` seconds to answer; with
    ``telegram`` the Telegram approver too, its bot the fake Bot API's."""
    operator = holdrig.OPERATOR_ID
    approvers: dict[str, Any] = {"portal": {}, "block_seconds": 0, "timeout": timeout}
    if telegram:
        approvers["telegram"] = {
            "bot_token": "store:approver-bot",
            "user_id": operator,
            "chat_id": operator,
        }
    tools = [*HELD_TOOLS, RELAYED_TOOL]
    return {
        "credentials": {"shop-key": {"kind": "header", "secret": "store:shop-key"}},
        "routes": [
            {
                "name": "shop",
                "prefix": "/shop",
                "upstream": f"{upstream}/base",
                "allow_insecure_upstream": True,
                "stream": True,
                "credential": "shop-key",
                "callers": ["gateway"],
                "rules": [{"methods": ["POST"], "paths": ["/mcp"]}],
            }
        ],
        "approvers": approvers,
        "gateway": {
            "clients": {
                name: {
                    "token_sha256": hash_token(f"zgc1-{name}-token"),
                    "servers": ["shop"],
                    "approvals": {**own, "renders": "plain"},
                }
                for name, own in CLIENTS.items()
            },
            "servers": {
                "shop": {
                    "kind": "remote",
                    "route": "shop",
                    "path": "/mcp",
                    "tools": {
                        "include": tools,
                        "approve": tools,
                        "vault_approval": list(HELD_TOOLS),
                    },
                    "review": dict.fromkeys(tools, holdrig.PIN),
                }
            },
        },
    }


class Ahead:
    """The hold table's clock: the vault's monotonic clock plus what a test adds, so a deadline
    passes with no waiting. It starts equal to the clock it replaces, so the vault's one fixed
    offset to the wall clock (``VaultApp.hold_wall``) still holds."""

    def __init__(self) -> None:
        self.offset = 0.0

    def __call__(self) -> float:
        return time.monotonic() + self.offset


@dataclass
class QueueStack:
    """The running rig, its echo upstream, the hold table's clock and, where Telegram decides,
    the fake Bot API the vault's Telegram surface talks to. Each call is sent to the vault's
    proxy listener as the gateway sends it: the gateway's key, and the held marker
    (``wait=pending``) or an ask."""

    rig: PortalRig
    upstream: holdrig.Upstream
    holds: Ahead
    bot: BotApi | None

    def _sent(self, more: dict[str, str]) -> dict[str, str]:
        return {**more, GATEWAY_HEADER: self.rig.vault.app._keys.gateway_key(1)}

    def held(
        self, ref: str, arguments: Any = None, *, client: str = "desk", tool: str = "place_order"
    ) -> httpx.Response:
        """A call to ``tool`` the vault holds, from ``client``: 409 pending once it waits."""
        sent = self._sent(holdrig.headers(held=holdrig.marker(ref, client=client, wait="pending")))
        url = f"http://127.0.0.1:{self.rig.proxy_port}{SHOP}"
        body = holdrig.call(tool, arguments)
        return httpx.post(url, content=body, headers=sent, timeout=BOUND)

    def relay(
        self,
        ref: str,
        arguments: Any = None,
        *,
        client: str = "nightly",
        text: str | None = None,
    ) -> httpx.Response:
        """A prompt the gateway holds for an out-of-band client, relayed to the vault as the
        gateway asks it (E.2): the gateway's own frame around ``arguments``, or ``text`` as
        given. 201 once it waits."""
        now = datetime.now(UTC)
        deadline = now + timedelta(hours=1)
        if text is None:
            header = approvaltext.Header(
                ref,
                client,
                "shop",
                RELAYED_TOOL,
                deadline,
                asked_at=now,
                rendered_by="gateway",
                client_reported=False,
                pin=None,
                approver="out_of_band",
            )
            text = approvaltext.render_call(header, arguments or {"order": 7}).value
        ask = {
            "v": 1,
            "epoch": holdrig.EPOCH,
            "ref": ref,
            "client": client,
            "server": "shop",
            "tool": RELAYED_TOOL,
            "text": text,
            "text_sha256": hashlib.sha256(text.encode()).hexdigest(),
            "deadline_ms": int(deadline.timestamp() * 1000),
            "wait": "pending",
        }
        url = f"http://127.0.0.1:{self.rig.proxy_port}/_zoeymcp/gateway/v1/approvals/ask"
        sent = self._sent({"content-type": "application/json"})
        return httpx.post(url, content=canonical.dumps_canonical(ask), headers=sent, timeout=BOUND)

    def hold(self, ref: str) -> Hold:
        """The vault's hold of ``ref``, read on its loop."""
        app = self.rig.vault.app
        found: Hold | None = self.rig.call(lambda: app.holds.by_ref(ref))
        assert found is not None, ref
        return found

    def text(self, ref: str) -> str:
        """The text the vault composed for ``ref``: what every surface shows, whole."""
        return self.hold(ref).text.value

    def until(self, ready: Callable[[], object]) -> None:
        """Wait, bounded, until ``ready()``, polled on the vault's loop as the Telegram tests
        poll the fake (``tests.gateway.rig.until``)."""
        asyncio.run_coroutine_threadsafe(until(ready, BOUND), self.rig.loop).result(BOUND + 5)

    def messages(self, ref: str) -> list[Stored]:
        """The bot's messages for ``ref`` in the operator's chat now (one, once Telegram took
        it), as the fake keeps them: a read that never waits, so an :meth:`until` may ask it."""
        bot = self.bot
        assert bot is not None, "no Telegram approver in this stack"
        head = f"Approval request {ref}"
        return [stored for stored in bot.operator.messages() if head in stored.text]

    def message(self, ref: str) -> Stored:
        """The bot's message for ``ref``, once Telegram took it."""
        self.until(lambda: self.messages(ref))
        [stored] = self.messages(ref)
        return stored

    def press(self, ref: str, label: str) -> None:
        """The operator presses ``label`` on ``ref``'s message; returns once the vault has
        decided on it (its ``approval_decided`` line)."""
        bot = self.bot
        assert bot is not None, "no Telegram approver in this stack"
        bot.operator.press(self.message(ref).message_id, label)
        self.until(lambda: any(line["ref"] == ref for line in self.rig.lines("approval_decided")))

    def later(self, seconds: float) -> int:
        """Move the hold table's clock on, and run the sweeper's tick: how many expired. Both on
        the vault's loop, in one step, so the vault's own sweeper can't take the tick between."""
        app = self.rig.vault.app

        def move() -> int:
            self.holds.offset += seconds
            return app.sweep_holds()

        expired: int = self.rig.call(move)
        return expired

    def settled(self) -> None:
        """Wait until every hold's ending is on the chain and told, its forward answered."""
        settle(self.rig)


def settle(rig: PortalRig) -> None:
    """``VaultApp.settle`` on the vault's loop: every ending written and told."""
    asyncio.run_coroutine_threadsafe(rig.vault.app.settle(), rig.loop).result(BOUND)


@contextlib.contextmanager
def queue(
    tmp_path: Path, *, clock: Clock | None = None, telegram: bool = False, timeout: int = 3600
) -> Iterator[QueueStack]:
    """The vault and its portal holding calls (:func:`queue_document`), the route's secret in
    its store, the hold table on a clock the test moves (:class:`Ahead`, set before any hold)
    and, with ``telegram``, the vault's own Telegram surface reaching the fake Bot API in
    process (the client the vault builds for the Bot API is an ASGI one, its timings short),
    the bot's token in the store. The portal's sessions run on ``clock``, if given."""
    upstream = holdrig.Upstream()
    bot = None
    with contextlib.ExitStack() as patches:
        if telegram:
            bot = BotApi(
                holdrig.BOT_TOKEN, second=SECOND, flood_interval=None, operator_account=OPERATOR
            )
            client = httpx.AsyncClient(transport=httpx.ASGITransport(app=bot.app()))
            patches.enter_context(
                mock.patch.object(netclient, "approver_client", return_value=client)
            )
            patches.enter_context(mock.patch.object(telegram_approver, "TIMINGS", TELEGRAM_TIMINGS))
        with serve(upstream.app()) as url:
            document = queue_document(url, telegram=telegram, timeout=timeout)
            with portal(tmp_path, policy=document, clock=clock) as rig:
                app = rig.vault.app
                secrets = rig.app.secrets
                assert secrets is not None
                binding = origin_binding([url])
                rig.call(lambda: secrets.store.put("shop-key", holdrig.SECRET, binding))
                if telegram:
                    api = origin_binding([telegramwire.API])
                    rig.call(lambda: secrets.store.put("approver-bot", holdrig.BOT_TOKEN, api))
                ahead = Ahead()
                rig.call(lambda: setattr(app, "_clock", ahead))
                yield QueueStack(rig, upstream, ahead, bot)


@dataclass
class GatewayQueue:
    """S20's stack running: the queue's rig behind a real gateway, the MCP fake its upstream, and
    an agent (the MCP SDK's client, as ``agent1``, attended) whose calls the test makes from its
    own thread, each on the blocking portal's event loop."""

    rig: PortalRig
    fake: McpFake
    session: Any
    loop: BlockingPortal

    def pending(self, arguments: dict[str, Any]) -> str:
        """The agent's call to ``echo``, held by the vault and answered ``pending <ref>``: the
        ref."""
        return ref_of(self.loop.call(self.session.call_tool, "echo", arguments))

    def check_approval(self, ref: str) -> str:
        """The gateway's ``check_approval`` for ``ref`` once the vault has settled it: the text
        it answered."""
        settle(self.rig)
        return text(self.loop.call(self.session.call_tool, checkapproval.NAME, {"id": ref}))


@contextlib.contextmanager
def gateway_queue(tmp_path: Path) -> Iterator[GatewayQueue]:
    """S20's stack (``test_vault_approval_shapes.test_queue``): the fake MCP server, the vault
    and its portal holding ``echo`` with the queue (each call answers pending), a real gateway
    on its proxy listener with the gateway key, and an agent session through it."""
    fake = McpFake()
    with serve(fake.app(), lifespan=True) as fake_url:
        policy = queue_policy(fake_url, fake)
        with portal(tmp_path, policy=policy) as rig:
            secrets = rig.app.secrets
            assert secrets is not None
            binding = origin_binding([fake_url])
            rig.call(lambda: secrets.store.put("notes-key", KEY, binding))
            # The policy's Telegram approver, scripted in its place: nothing reaches Telegram.
            hub = rig.vault.app.hub
            rig.call(lambda: hub.install(holdrig.Surface("telegram")))
            with (
                gateway_on(rig, tmp_path / "gateway") as running,
                start_blocking_portal() as loop,
                loop.wrap_async_context_manager(agent(running, server=SERVER)) as session,
            ):
                yield GatewayQueue(rig, fake, session, loop)
