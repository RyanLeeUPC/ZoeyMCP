"""The toolkit acceptance rig: the shipped SMTP and toolkit profiles, the real vault and the real
gateway (M4 design N.5).

Agent (SDK client) -> gateway (real socket) -> vault (real socket) -> the records API fake (real
TLS, verified against the test CA) and the SMTP fake (implicit TLS or STARTTLS, through the
CONNECT proxy fake). The profiles are used as shipped, with only the upstream, the mail server's
address, the egress proxy and the client token swapped. The example toolkits aren't installed:
their entry points go to the loader, which skips the origin check (``--allow-writable-toolkits``).

Two axes (M8 step 19, D-73's M8 part): the approval mode, the gateway's own (elicitation) or
``vault_approval`` on the mail toolkit's ``send_note``, where the vault holds the connector's
send and shows it on a scripted portal surface (``tests/gateway/holdrig.py``'s) that decides
only when the test says, on a hold clock the test can move past a hold's end; and the link,
TCP with the gateway key (the hardened tier) or the link socket with the peer check (the
standard tier, Linux only).

For S13/S14's failure matrix (the pre-main test-debt pass, D-73): ``direct`` leaves the egress
proxy out (S14's direct case), and :attr:`ToolkitDeployment.sent` records each connector send as
the gateway put it to the vault, so a test can put it again (a replay).

Every log line, CLI output and agent answer is recorded in :class:`Seen`, for the H14 sweep.
"""

from __future__ import annotations

import asyncio
import io
import os
import sys
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, TypeVar

import anyio
import httpx
import uvicorn
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from tests.fakes.connect_proxy import ConnectProxy, serve_proxy
from tests.fakes.records_api import SECRET as RECORDS_SECRET
from tests.fakes.records_api import RecordsApi
from tests.fakes.smtp_server import PASSWORD, SmtpFake, serve_smtp
from tests.gateway.holdrig import Clock as HoldClock
from tests.gateway.holdrig import Surface
from tests.gateway.rig import Running, WithAdmin, token_for
from tests.gateway.toolkit_rig import ENTRY_POINTS
from zoeymcp.cli.main import main
from zoeymcp.common import logs
from zoeymcp.common.policy import Policy, check_policy
from zoeymcp.common.policy.schema import hash_token
from zoeymcp.common.yamlload import load_mapping
from zoeymcp.gateway.app import GatewayApp
from zoeymcp.gateway.defstore import DefinitionStore
from zoeymcp.gateway.ledger import Ledger
from zoeymcp.gateway.marks import DriftMarks
from zoeymcp.gateway.toolkits import Toolkits
from zoeymcp.gateway.upstream import UpstreamPool
from zoeymcp.gateway.vaultlink import KeySource, parse_link, view_client
from zoeymcp.vault.app import VaultApp
from zoeymcp.vault.approvers import ApproverHub
from zoeymcp.vault.bindings import derive_binding
from zoeymcp.vault.connectors.smtp import SmtpConnectors
from zoeymcp.vault.holds import Hold
from zoeymcp.vault.keys import KeySet, generate_master_key
from zoeymcp.vault.peer import peer_checked
from zoeymcp.vault.server import ListenerTag
from zoeymcp.vault.store import SecretStore
from zoeymcp.vault.vaultledger import VaultLedger

from .conftest import BASE, PROFILES, _Server, _wait_started, serve_tls, tls_client
from .gateway import GatewayAdminTransport, wait_healthy
from .helpers import Seen
from .tls import ProviderCA

AGENT = "agent1"
Mode = Literal["implicit", "starttls"]
Approval = Literal["gateway", "vault_approval"]
Link = Literal["tcp", "unix"]
T = TypeVar("T")


def merged(*names: str) -> dict[str, Any]:
    """The profiles' fragments merged into one policy, as an operator would paste them."""
    document: dict[str, Any] = dict(BASE)
    for name in names:
        document = _merge(document, load_mapping((PROFILES / name).read_text(encoding="utf-8")))
    return document


def _merge(into: dict[str, Any], fragment: dict[str, Any]) -> dict[str, Any]:
    """Mappings merge key by key, at any depth; lists are joined; anything else is replaced."""
    merged_: dict[str, Any] = dict(into)
    for key, value in fragment.items():
        if isinstance(value, dict) and isinstance(merged_.get(key), dict):
            merged_[key] = _merge(merged_[key], value)
        elif isinstance(value, list) and isinstance(merged_.get(key), list):
            merged_[key] = [*merged_[key], *value]
        else:
            merged_[key] = value
    return merged_


class ToolkitDeployment:
    """The mail and records toolkits, from their profiles, on fakes behind a real vault, in
    ``approval`` mode over ``link``."""

    def __init__(
        self,
        tmp_path: Path,
        ca: ProviderCA,
        *,
        mode: Mode = "implicit",
        approval: Approval = "gateway",
        link: Link = "tcp",
        direct: bool = False,
    ) -> None:
        self.tmp_path, self.ca, self.mode = tmp_path, ca, mode
        self.approval, self.link, self.direct = approval, link, direct
        # Each connector send the gateway put to the vault, in order.
        self.sent: list[Sent] = []
        # The vault's approver, with vault_approval: it decides only through decide(), and its
        # holds end undecided only through expire().
        self.surface = Surface("portal")
        self.hold_clock = HoldClock()
        # The agent's own prompts' timeout in seconds, when a test shortens it (gateway mode).
        self.ask_timeout: int | None = None
        self._vault_loop: asyncio.AbstractEventLoop | None = None
        self.records = RecordsApi()
        self.smtp = SmtpFake(ca, mode=mode)
        self.proxy = ConnectProxy()
        self.seen = Seen()
        self.keys = KeySet.from_text(generate_master_key())
        self.state = tmp_path / "gateway"
        self.policy: Policy | None = None

    def build(self, records_url: str, smtp_port: int, proxy_url: str) -> Policy:
        smtp_profile = "smtp-implicit-tls.yaml" if self.mode == "implicit" else "smtp-starttls.yaml"
        raw = merged(smtp_profile, "toolkit-mail.yaml", "toolkit-records.yaml")
        raw["connectors"]["mail-out"].update(host="localhost", port=smtp_port)
        if not self.direct:
            raw["egress_proxy"] = proxy_url
        for route in raw["routes"]:
            if route["name"] == "records":
                route["upstream"] = records_url
        client = raw["gateway"]["clients"][AGENT]
        client.update(
            token_sha256=hash_token(token_for(AGENT)), sources=[], servers=["mail", "records"]
        )
        if self.ask_timeout is not None:
            client["approvals"] = {**client["approvals"], "timeout": self.ask_timeout}
        if self.approval == "vault_approval":
            raw["gateway"]["servers"]["mail"]["tools"]["vault_approval"] = ["send_note"]
            raw["approvers"] = {"portal": {}}
            raw["admin"] = {"listen": "127.0.0.1:8081", "origins": ["http://localhost:8081"]}
        policy = Policy.model_validate(raw)
        errors = [f for f in check_policy(policy) if f.level == "error"]
        assert errors == [], errors
        return policy

    @contextmanager
    def running(self) -> Iterator[Running]:
        logs.set_stream(self.seen.log)
        try:
            with (
                serve_tls(self.records, self.ca) as records_url,
                serve_smtp(self.smtp, self.tmp_path) as (_, smtp_port),
                serve_proxy(self.proxy) as proxy_url,
            ):
                self.policy = policy = self.build(records_url, smtp_port, proxy_url)
                store = SecretStore(self.tmp_path / "vault", self.keys)
                store.load()
                store.put("records-key", RECORDS_SECRET, derive_binding(policy, "records-key"))
                store.put("mail-pass", PASSWORD, derive_binding(policy, "mail-pass"))
                connectors = SmtpConnectors(
                    self.tmp_path / "vault", self.keys, tls=self.ca.client_context()
                )
                held: dict[str, Any] = {}
                if self.approval == "vault_approval":
                    chain = VaultLedger.open_at(self.tmp_path / "vault", self.keys.chain_key)
                    hub = ApproverHub([self.surface])
                    held = {"chain": chain, "hub": hub, "hold_clock": self.hold_clock}
                socket = None
                if self.link == "unix":
                    socket = self.tmp_path / "link" / "vault.sock"
                    socket.parent.mkdir(mode=0o700, exist_ok=True)
                self.vault_app = vault = VaultApp(
                    policy,
                    store,
                    self.keys,
                    client=tls_client(self.ca),
                    environ={},
                    connectors=connectors,
                    gateway_link=socket is not None,
                    **held,
                )
                with (
                    _serve_vault(vault, socket, self.sent) as (vault_url, self._vault_loop),
                    self._gateway(vault_url) as running,
                ):
                    yield running
        finally:
            logs.set_stream(None)

    @contextmanager
    def _gateway(self, vault_url: str) -> Iterator[Running]:
        from tests.fakes.harness import serve

        link = parse_link(vault_url)
        keys = None if self.link == "unix" else KeySource(self.keys.gateway_key(1))
        marks = DriftMarks.load(self.state)
        pool = UpstreamPool(link, keys, marks, DefinitionStore(self.state))
        toolkits = Toolkits(
            link, keys, marks, entry_points=lambda: ENTRY_POINTS, allow_writable=True
        )
        app = GatewayApp(pool, view_client(link, keys), policy_wait=1, toolkits=toolkits)
        app.ledger, _ = Ledger.open_at(self.state, max_bytes=2**20)
        with serve(WithAdmin(app), lifespan=True, proxy_headers=False) as url:
            running = Running(app, url)
            wait_healthy(running)
            yield running

    async def decide(self, hold: Hold, decision: Literal["approve", "deny"]) -> Any:
        """The portal surface's decision on ``hold``, in its own synchronous section on the
        vault's loop, as ``VaultApp.decide`` answers it."""
        app = self.vault_app
        return await self._on_vault(
            lambda: app.decide(hold.id, decision, "portal", hold.text_sha256)
        )

    async def expire(self) -> None:
        """Nobody decides: the hold clock moves past every hold's end (``approvers.timeout``,
        and a toolkit write's block, B.7), and the vault's sweeper runs."""
        self.hold_clock.ahead += 3601
        app = self.vault_app
        await self._on_vault(app.sweep_holds)

    async def settled(self) -> None:
        """Wait until every hold's ending is on the vault's chain and told."""
        loop = self._vault_loop
        assert loop is not None, "the vault isn't running"
        future = asyncio.run_coroutine_threadsafe(self.vault_app.settle(), loop)
        await anyio.to_thread.run_sync(lambda: future.result(30))

    async def _on_vault(self, work: Callable[[], T]) -> T:
        loop = self._vault_loop
        assert loop is not None, "the vault isn't running"

        async def run() -> T:
            return work()

        future = asyncio.run_coroutine_threadsafe(run(), loop)
        return await anyio.to_thread.run_sync(lambda: future.result(30))

    def cli(self, running: Running, *argv: str) -> tuple[int, str, str]:
        """``zoeymcp <argv>`` against the running gateway's admin app; output is recorded."""
        original = httpx.HTTPTransport
        httpx.HTTPTransport = lambda **_: GatewayAdminTransport(running.admin_url)  # type: ignore[assignment,misc]
        try:
            out, err = io.StringIO(), io.StringIO()
            code = main(list(argv), stdin=io.StringIO(), out=out, err=err)
        finally:
            httpx.HTTPTransport = original  # type: ignore[misc]
        self.seen.outputs += [out.getvalue(), err.getvalue()]
        return code, out.getvalue(), err.getvalue()


@dataclass(frozen=True)
class Sent:
    """A connector send as the gateway put it to the vault: its path, headers and body."""

    path: str
    headers: list[tuple[str, str]]
    body: bytes


class _Recorder:
    """The vault's app, recording into ``sent`` each POST whose path ends in ``/send``."""

    def __init__(self, app: ASGIApp, sent: list[Sent]) -> None:
        self.app, self.sent = app, sent

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        path = scope.get("path", "")
        if scope["type"] != "http" or scope["method"] != "POST" or not path.endswith("/send"):
            await self.app(scope, receive, send)
            return
        messages: list[Message] = []
        while True:
            message = await receive()
            messages.append(message)
            if message["type"] != "http.request" or not message.get("more_body"):
                break
        body = b"".join(m.get("body", b"") for m in messages)
        headers = [(k.decode("latin-1"), v.decode("latin-1")) for k, v in scope["headers"]]
        self.sent.append(Sent(path, headers, body))
        queued = list(messages)

        async def replayed() -> Message:
            return queued.pop(0) if queued else await receive()

        await self.app(scope, replayed, send)


def _own_uid() -> int:
    """The test's own uid, the only peer the link socket lets in (Linux)."""
    if sys.platform == "win32":
        return 0
    return os.getuid()


@contextmanager
def _serve_vault(
    vault: VaultApp, socket: Path | None = None, sent: list[Sent] | None = None
) -> Iterator[tuple[str, asyncio.AbstractEventLoop]]:
    """The vault's proxy app on its own loop and thread, as ``zoeymcp vault``: over TCP, or
    on the link socket ``socket`` with the peer check (the standard tier, Linux only), each
    connector send recorded into ``sent``. Yields the gateway's link to it, and its loop."""
    app: ASGIApp = vault if sent is None else _Recorder(vault, sent)
    if socket is None:
        config = uvicorn.Config(
            ListenerTag(app, "tcp"), host="127.0.0.1", port=0, log_level="warning", lifespan="off"
        )
    else:
        config = uvicorn.Config(
            ListenerTag(app, "gateway"),
            uds=str(socket),
            http=peer_checked(_own_uid()),
            log_level="warning",
            lifespan="off",
        )
    server = _Server(config)
    loop = asyncio.new_event_loop()

    async def run() -> None:
        try:
            await server.serve()
        finally:
            await vault.aclose()

    thread = threading.Thread(target=loop.run_until_complete, args=(run(),), daemon=True)
    thread.start()
    [port] = _wait_started([server], thread)
    try:
        yield (f"http://127.0.0.1:{port}" if socket is None else f"unix:{socket}"), loop
    finally:
        server.should_exit = True
        thread.join(30)
        if not thread.is_alive():
            loop.close()
        time.sleep(0)
