"""Held calls across stops and restarts, in real processes (M8 design I.2, I.3, J.1, N.2, N.3; J9,
J10; FM-18, FM-26, FM-27; Z9, Z10, Z23; step 17).

The vault runs as ``zoeymcp vault`` in its own process (``procs.py``), through the ``lit`` hook
(M8's policy fields are dark until step 18), with the Telegram approver as its one surface: the
fake Bot API (``tests/fakes/telegram.py``) is served over HTTPS in the test, and the process
reaches it, and the route's upstream, through the hooks file's fake name entries, with short
timings (BP-9, BP-10). The operator presses buttons in the fake; a kill is a real kill:

- **J9, Z9** (``test_stop_lets_the_forward_finish``): the vault stopped (``SIGTERM``) while one
  call waits and another, approved, is still at the upstream: the first is withdrawn and its
  message says the vault stopped; the second finishes, its outcome reaches the chain and its
  message says how it went, before the vault exits;
- **J10, FM-18, Z10** (``test_restart_drops_holds``): the vault killed with a call waiting and
  another approved and at the upstream, then started again: the chain's recovery closed the
  first (``abandoned``, ``not_sent``, ``restart``) and the second ``outcome unknown``, a later
  press on the first's message is refused and the message says the vault restarted, the collect
  ``check_approval`` reads says so to its own client (F.5 step 4), and another learns nothing;
  health (Home's checklist, ``zoeymcp health``) shows ``approvals_withdrawn_at_start`` until
  ``zoeymcp approvals list``, and ``approvals_outcome_unknown`` naming the second's ref (K.1);
- **FM-26, Z7** (``test_gateway_epoch``): a gateway restart, as the vault sees one (a new
  gateway epoch, E.2), with a relay, a held call that carried a legacy session and a held call
  that didn't: the first two are withdrawn and their messages say why; the third is approved
  later and collected through the new epoch. The test plays both gateways here;
- **FM-27, Z23, FM-39** (``test_gateway_stop_detaches``): a real gateway process stopped
  (``SIGTERM``) while its agent's call blocks at the vault: the agent gets ``pending <ref>``
  before its session closes, the hold goes on, is approved and runs, and the agent collects
  the result through the next gateway process, while another client learns nothing.

Linux only, as the process crash tests are (M6 design P.2): the vault and the gateway stop on
their ``SIGTERM`` handlers, which Windows doesn't have. Bounded by ``anyio.fail_after``,
sleeping only to poll another process.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import json
import sys
import threading
import time
from collections.abc import AsyncIterator, Iterator, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import anyio
import httpx
import pytest
from mcp.types import CallToolResult, TextContent
from starlette.types import ASGIApp

from tests.fakes.agent import agent
from tests.fakes.harness import serve
from tests.fakes.mcp_server import McpFake
from tests.fakes.telegram import BotApi, Person, Stored
from tests.gateway.holdrig import BOT_TOKEN, OPERATOR_ID, Upstream, call, headers, marker
from tests.gateway.rig import CLIENTS, raw_policy, token_for, until
from tests.gateway.test_upstream import review
from zoeymcp.cli.main import main
from zoeymcp.common import canonical, ledgerformat
from zoeymcp.common.approvaltext import Header, render_call
from zoeymcp.common.policy import Policy
from zoeymcp.gateway.checkapproval import NAME as CHECK_APPROVAL
from zoeymcp.gateway.ledger import LEDGER_DIR
from zoeymcp.vault.app import GATEWAY_HEADER
from zoeymcp.vault.bindings import derive_binding
from zoeymcp.vault.keys import KeySet, generate_master_key
from zoeymcp.vault.store import SecretStore, origin_binding
from zoeymcp.vault.telegram import RESTARTED
from zoeymcp.vault.telegramwire import NOT_PENDING
from zoeymcp.vault.vaultledger import CHAIN_DIR

from .procs import (
    TELEGRAM_HOST,
    Process,
    free_port,
    start,
    telegram_hooks,
    wait_file,
    wait_port,
)
from .tls import ProviderCA, issue_cert

pytestmark = [
    pytest.mark.anyio,
    pytest.mark.skipif(
        sys.platform != "linux", reason="the process crash tests run on Linux (M6 design P.2)"
    ),
]

BOUND = 90
# The Telegram surface's timings in the vault process (BP-10), and one second of a getUpdates
# timeout in the fake: a long poll lasts 200 ms.
TIMINGS: dict[str, float] = {
    "send_spacing": 0.05,
    "contested_backoff": 0.3,
    "unreachable_after": 5.0,
    "backoff_max": 0.2,
    "poll_timeout": 1,
}
SECOND = 0.2
OPERATOR = Person(OPERATOR_ID, "Operator", "operator_example")
TOOLS = ["echo", "add"]
PIN = "sha256:" + "c" * 64
SHOP_HOST = "shop.example"  # the hold rig's echo upstream, under /base
MCP_HOST = "mcp.example"  # the fake MCP server
SHOP_SECRET = "sk-live-crash-3f9c2a71d8e4"
HELD_PATH = "/notes/mcp"
APPROVALS = "/_zoeymcp/gateway/v1/approvals/"
# The gateway epochs the test plays: the one before a restart, and the restarted one's.
OLD = "0123456789ab"
NEW = "ba9876543210"
REF_A, REF_B, REF_C = "00000000000000a1", "00000000000000b2", "00000000000000c3"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def document(upstream: str, pins: dict[str, str], *, block_seconds: int) -> dict[str, Any]:
    """The rig's policy (``tests/gateway/rig.py``'s): server ``notes`` on route ``notes`` to
    ``upstream``, ``echo`` held by the vault and ``add`` by the gateway, both clients raising
    out-of-band prompts, and the Telegram approver alone, its token in the store."""
    raw = raw_policy(
        upstream,
        include=TOOLS,
        review=pins,
        approve=TOOLS,
        vault_approval=["echo"],
        approvals={name: {"attended": False, "out_of_band": True} for name in CLIENTS},
        approvers={
            "telegram": {
                "bot_token": "store:approver-bot",
                "user_id": OPERATOR_ID,
                "chat_id": OPERATOR_ID,
            },
            "block_seconds": block_seconds,
        },
    )
    del raw["routes"][0]["allow_insecure_upstream"]
    return raw


@dataclass
class World:
    """The vault process on ``tmp``'s state, the fake Bot API it reaches, and the gateway
    processes started beside it, each stopped at the end."""

    tmp: Path
    ca: ProviderCA
    api: BotApi
    hooks: Path
    config: Path
    master: str
    port: int = field(default_factory=free_port)
    vault: Process | None = None
    gateways: list[Process] = field(default_factory=list)

    @property
    def state(self) -> Path:
        return self.tmp / "vault"

    @property
    def keys(self) -> KeySet:
        return KeySet.from_text(self.master)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def socket(self) -> Path:
        """The vault's admin socket, which ``zoeymcp health`` and ``approvals`` reach."""
        return self.tmp / "admin" / "admin.sock"

    async def start(self) -> Process:
        """The vault, once it listens and its Telegram poller has skipped the backlog and
        polls."""
        polled = len(self.api.polls)
        argv = [
            "vault", "--config", str(self.config), "--listen", f"127.0.0.1:{self.port}",
            "--state", str(self.state), "--admin-socket", str(self.socket),
        ]  # fmt: skip
        self.vault = start(
            argv,
            env={"ZOEYMCP_MASTER_KEY": self.master},
            log=self.tmp / "vault.log",
            ca=self.ca.ca_file,
            hooks=self.hooks,
            lit=True,
        )
        await anyio.to_thread.run_sync(wait_port, self.port, self.vault)
        await anyio.to_thread.run_sync(wait_file, self.socket, self.vault)
        await until(lambda: len(self.api.polls) >= polled + 2, BOUND)
        return self.vault

    async def cli(self, *argv: str) -> tuple[int, str]:
        """``zoeymcp <argv>`` in this process, on the vault's admin socket: its exit code and
        what it printed."""
        out, err = io.StringIO(), io.StringIO()
        argv_ = [*argv, "--socket", str(self.socket)]
        code = await anyio.to_thread.run_sync(
            lambda: main(argv_, stdin=io.StringIO(), out=out, err=err)
        )
        assert not err.getvalue(), err.getvalue()
        return code, out.getvalue()

    def gateway(self, port: int) -> Process:
        """A gateway process on the vault, its state the one every gateway here shares."""
        argv = [
            "gateway", "--vault", self.url, "--listen", f"127.0.0.1:{port}",
            "--state", str(self.tmp / "gateway"), "--admin-socket", "none",
        ]  # fmt: skip
        log = self.tmp / f"gateway-{len(self.gateways)}.log"
        key = {"ZOEYMCP_GATEWAY_KEY": self.keys.gateway_key(1)}
        process = start(argv, env=key, log=log, lit=True)
        self.gateways.append(process)
        return process

    @asynccontextmanager
    async def link(self) -> AsyncIterator[httpx.AsyncClient]:
        """The vault, as a gateway reaches it: with the gateway key, on TCP."""
        sent = {GATEWAY_HEADER: self.keys.gateway_key(1)}
        async with httpx.AsyncClient(base_url=self.url, headers=sent, timeout=30) as http:
            yield http

    def records(self, ref: str) -> list[tuple[str, Any, Any]]:
        """The vault chain's records of ``ref``: each kind with its decision (and ``via``) or
        its outcome and detail."""
        found = [
            ledgerformat.parse(line)
            for path in sorted((self.state / CHAIN_DIR).glob("*.jsonl"))
            for line in path.read_bytes().splitlines()
        ]
        return [
            (
                r.kind,
                r.fields.get("decision") or r.fields.get("outcome"),
                r.fields.get("via") or r.fields.get("detail"),
            )
            for r in found
            if r.ref == ref
        ]

    def stop(self) -> None:
        for process in [*self.gateways, *([self.vault] if self.vault else [])]:
            process.stop()


@contextlib.contextmanager
def world(
    tmp_path: Path,
    ca: ProviderCA,
    upstream: ASGIApp,
    host: str,
    *,
    base: str = "",
    pins: Mapping[str, str] | None = None,
    secret: str = SHOP_SECRET,
    block_seconds: int = 0,
    lifespan: bool = False,
) -> Iterator[World]:
    """The fake Bot API and ``upstream`` served over HTTPS as ``api.telegram.org`` and
    ``host``, and a vault's state whose store holds the bot's token and the route's
    ``secret``; the vault isn't started."""
    api = BotApi(BOT_TOKEN, second=SECOND, flood_interval=None, operator_account=OPERATOR)
    certs = tmp_path / "certs"
    certs.mkdir(mode=0o700)
    with (
        serve(api.app(), tls=issue_cert(ca, TELEGRAM_HOST, certs)) as bot_url,
        serve(upstream, lifespan=lifespan, tls=issue_cert(ca, host, certs)) as upstream_url,
    ):
        hooks = telegram_hooks(
            tmp_path / "hooks.json",
            _port(bot_url),
            names={host: _port(upstream_url)},
            **TIMINGS,
        )
        reviewed = dict(pins or dict.fromkeys(TOOLS, PIN))
        raw = document(f"https://{host}{base}", reviewed, block_seconds=block_seconds)
        config = tmp_path / "policy.json"
        config.write_bytes(json.dumps(raw).encode())
        found = World(tmp_path, ca, api, hooks, config, generate_master_key())
        found.state.mkdir(mode=0o700)
        policy = Policy.model_validate(raw)
        store = SecretStore(found.state, found.keys)
        store.load()
        store.put("notes-key", secret, derive_binding(policy, "notes-key"))
        store.put("approver-bot", BOT_TOKEN, origin_binding([f"https://{TELEGRAM_HOST}"]))
        try:
            yield found
        finally:
            found.stop()


def _port(url: str) -> int:
    return int(url.rsplit(":", 1)[1])


async def held(
    http: httpx.AsyncClient, ref: str, client: str, *, epoch: str = OLD, **more: str
) -> httpx.Response:
    """``echo`` held for ``client``, marked ``wait=pending`` as a gateway at ``epoch`` marks it:
    with no block it answers ``approval_pending`` once it is shown."""
    sent = headers(held=marker(ref, client=client, wait="pending", epoch=epoch), **more)
    return await http.post(HELD_PATH, content=call("echo", {"text": f"held {ref}"}), headers=sent)


async def ask(http: httpx.AsyncClient, ref: str, client: str, *, epoch: str) -> httpx.Response:
    """A relay (E.2, E.4): ``add`` as the gateway holds and renders it, asked out of band."""
    now = datetime.now(UTC)
    header = Header(
        ref,
        client,
        "notes",
        "add",
        datetime.fromtimestamp(now.timestamp() + 3600, UTC),
        asked_at=now,
        rendered_by="gateway",
        client_reported=False,
        pin=None,
        approver="out_of_band",
    )
    text = render_call(header, {"a": 2, "b": 3}).value
    body = {
        "v": 1,
        "epoch": epoch,
        "ref": ref,
        "client": client,
        "server": "notes",
        "tool": "add",
        "text": text,
        "text_sha256": hashlib.sha256(text.encode()).hexdigest(),
        "deadline_ms": int(time.time() * 1000) + 3_600_000,
        "wait": "pending",
    }
    content = canonical.dumps_canonical(body)
    return await http.post(
        APPROVALS + "ask", content=content, headers={"content-type": "application/json"}
    )


async def collect(
    http: httpx.AsyncClient, ref: str, client: str, *, epoch: str = OLD
) -> dict[str, Any]:
    """The collect ``check_approval`` makes (F.5): the call's status, or its result once."""
    body = {"epoch": epoch, "ref": ref, "client": client, "server": "notes"}
    response = await http.post(
        APPROVALS + "collect",
        content=canonical.dumps_canonical(body),
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 200, response.text
    found: dict[str, Any] = response.json()
    return found


async def prompts(api: BotApi, *refs: str) -> dict[str, Stored]:
    """The operator's prompt of each of ``refs``, once each is in the chat."""

    def each() -> dict[str, Stored]:
        sent = api.operator.prompts()
        return {ref: s for ref in refs for s in sent if f"Approval request {ref}" in s.text}

    await until(lambda: len(each()) == len(refs), BOUND)
    return each()


def edits(api: BotApi) -> list[str]:
    """Every text the bot edited a message to and Telegram took, in order."""
    return [
        str(c.params["text"])
        for c in list(api.calls)
        if c.method == "editMessageText" and c.status == 200
    ]


def edited(api: BotApi, ref: str, said: str) -> bool:
    return any(text.startswith(f"Approval request {ref}: ") and said in text for text in edits(api))


async def exited(process: Process) -> int:
    code: int = await anyio.to_thread.run_sync(lambda: process.popen.wait(BOUND))
    return code


def events(process: Process, name: str) -> list[dict[str, Any]]:
    found = []
    for line in process.output().splitlines():
        if line.startswith("{"):
            record = json.loads(line)
            if record.get("event") == name:
                found.append(record)
    return found


def text(result: CallToolResult) -> str:
    block = result.content[0]
    assert isinstance(block, TextContent)
    return block.text


# --- the vault's stop and restart (I.2, I.3; J9, J10) --------------------------------------------


async def test_stop_lets_the_forward_finish(tmp_path: Path, ca: ProviderCA) -> None:
    """J9, I.2, Z9: one call waits and another, approved, is at the upstream when the vault is
    told to stop. The waiting one is withdrawn (``shutdown``), unsent, and its message says the
    vault stopped; the approved one finishes and its outcome reaches the chain, and its message
    says it was sent, before the vault exits cleanly."""
    upstream = Upstream()
    gate = upstream.gate = threading.Event()
    with world(tmp_path, ca, upstream.app(), SHOP_HOST, base="/base") as found:
        with anyio.fail_after(BOUND):
            vault = await found.start()
            async with found.link() as http:
                waiting = await held(http, REF_A, "agent1")
                running = await held(http, REF_B, "agent2")
            sent = await prompts(found.api, REF_A, REF_B)
            found.api.operator.press(sent[REF_B].message_id, "Approve")
            await anyio.to_thread.run_sync(lambda: upstream.answering.wait(BOUND))
            vault.popen.terminate()
            await until(lambda: edited(found.api, REF_A, "withdrawn: the vault stopped"), BOUND)
            assert vault.popen.poll() is None  # it waits for the forward still running
            gate.set()
            code = await exited(vault)
            await until(lambda: edited(found.api, REF_B, "Sent: the server answered ok."), BOUND)
    assert code == 0, vault.output()
    assert waiting.json()["code"] == running.json()["code"] == "approval_pending"
    assert found.records(REF_A) == [
        ("asked", None, None),
        ("decided", "shutdown", "none"),
        ("outcome", "not_sent", "shutdown"),
    ]
    assert found.records(REF_B) == [
        ("asked", None, None),
        ("decided", "accept", "telegram"),
        ("outcome", "ok", None),
    ]
    assert len(upstream.posts()) == 1
    assert events(vault, "vault_stopped")


async def test_restart_drops_holds(tmp_path: Path, ca: ProviderCA) -> None:
    """J10, FM-18, Z10, F.5 step 4, K.1: the vault killed while one call waits and another,
    approved, is at the upstream, then started again on its state. The chain's recovery closed
    the first (``abandoned``, ``not_sent``, ``restart``) and the second ``outcome unknown``; the
    operator's press on the first's old message is refused ("no longer pending") and the message
    says the vault restarted; the collect ``check_approval`` reads tells its own client how it
    ended (``restarted``: "ended when the vault restarted; nothing was sent"), and another client
    nothing. Health shows ``approvals_withdrawn_at_start`` until the host lists the approvals,
    and ``approvals_outcome_unknown`` naming the second, which may have run. Nothing of the first
    reached the upstream."""
    upstream = Upstream()
    gate = upstream.gate = threading.Event()
    with world(tmp_path, ca, upstream.app(), SHOP_HOST, base="/base") as found:
        with anyio.fail_after(BOUND):
            first = await found.start()
            async with found.link() as http:
                answered = await held(http, REF_A, "agent1")
                cut = await held(http, REF_B, "agent2")
            sent = await prompts(found.api, REF_A, REF_B)
            found.api.operator.press(sent[REF_B].message_id, "Approve")
            await anyio.to_thread.run_sync(lambda: upstream.answering.wait(BOUND))
            first.kill()
            gate.set()  # the killed forward's request ends at the upstream
            await found.start()
            found.api.operator.press(sent[REF_A].message_id, "Approve")
            await until(lambda: RESTARTED in edits(found.api), BOUND)
            async with found.link() as http:
                ended = await collect(http, REF_A, "agent1")
                stranger = await collect(http, REF_A, "agent2")
            _, before = await found.cli("health", "--json")
            listed, _ = await found.cli("approvals", "list")
            _, after = await found.cli("health", "--json")
    assert answered.json()["code"] == cut.json()["code"] == "approval_pending"
    assert found.api.answers[-1].text == NOT_PENDING
    assert listed == 0
    assert start_findings(before) == {
        "approvals_withdrawn_at_start": "the last vault start withdrew 1 approval(s) that were "
        "waiting (nothing was sent); see Decided recently",
        "approvals_outcome_unknown": f"1 approved call(s) may have run before the vault stopped "
        f"(refs {REF_B}); check each upstream; see the Ledger",
    }
    assert list(start_findings(after)) == ["approvals_outcome_unknown"]
    assert found.records(REF_B)[-1][:2] == ("outcome", "unknown")
    assert ended == {
        "v": 1,
        "ref": REF_A,
        "state": "withdrawn",
        "detail": "restart",
        "restarted": True,
    }
    assert stranger == {"v": 1, "ref": REF_A, "state": "unknown"}
    kinds = found.records(REF_A)
    assert kinds[0] == ("asked", None, None)
    assert kinds[1][:2] == ("decided", "abandoned")
    assert kinds[2] == ("outcome", "not_sent", "restart")
    assert len(upstream.posts()) == 1  # the second's
    assert all(f"held {REF_A}".encode() not in body for *_, body in upstream.received)


def start_findings(report: str) -> dict[str, str]:
    """The start's two findings in ``zoeymcp health --json``'s report, by code (K.1)."""
    found = json.loads(report)["approvals"]["findings"]
    return {f["code"]: f["text"] for f in found if f["code"].startswith("approvals_")}


# --- the gateway's restart and stop (E.2, I.2; FM-26, FM-27) -------------------------------------


async def test_gateway_epoch(tmp_path: Path, ca: ProviderCA) -> None:
    """FM-26, G-15, Z7: a relay, a held call that carried a legacy ``Mcp-Session-Id`` and one
    that didn't wait, all marked by one gateway; then a restarted gateway's first approvals
    request comes with its new epoch. The relay and the legacy session's call are withdrawn
    (``gateway_restarted``), unsent, and their messages say why: no gateway is left to forward
    the relay, and nobody keeps that session open. The third waits on, is approved, runs once,
    and its client collects the result through the new epoch; another client learns nothing."""
    upstream = Upstream()
    with world(tmp_path, ca, upstream.app(), SHOP_HOST, base="/base") as found:
        with anyio.fail_after(BOUND):
            await found.start()
            async with found.link() as http:
                relay = await ask(http, REF_A, "agent1", epoch=OLD)
                legacy = await held(http, REF_B, "agent1", **{"mcp-session-id": "s-1"})
                kept = await held(http, REF_C, "agent2")
                sent = await prompts(found.api, REF_A, REF_B, REF_C)
                query = {"epoch": NEW, "after": "0", "wait": "0"}
                restarted = await http.get(APPROVALS + "decisions", params=query)
                why = "withdrawn: the gateway restarted"
                await until(lambda: edited(found.api, REF_A, why), BOUND)
                await until(lambda: edited(found.api, REF_B, why), BOUND)
                gone = await collect(http, REF_B, "agent1", epoch=NEW)
                waiting = await collect(http, REF_C, "agent2", epoch=NEW)
                found.api.operator.press(sent[REF_C].message_id, "Approve")
                await until(lambda: ("outcome", "ok", None) in found.records(REF_C), BOUND)
                await until(lambda: edited(found.api, REF_C, "Sent:"), BOUND)
                collected = await collect(http, REF_C, "agent2", epoch=NEW)
                stranger = await collect(http, REF_C, "agent1", epoch=NEW)
    assert relay.status_code == 201, relay.text
    assert legacy.json()["code"] == kept.json()["code"] == "approval_pending"
    assert restarted.status_code == 200
    assert (restarted.json()["endings"], restarted.json()["relays"]) == ([], [])
    assert (gone["state"], gone["detail"]) == ("withdrawn", "gateway_restarted")
    assert waiting["state"] == "pending"
    assert collected["state"] == "done"
    assert b'"text":"done"' in base64.b64decode(collected["result"]["body"])
    assert stranger == {"v": 1, "ref": REF_C, "state": "unknown"}
    for ref in (REF_A, REF_B):
        assert found.records(ref)[1:] == [
            ("decided", "withdrawn", "none"),
            ("outcome", "not_sent", None),
        ]
    assert found.records(REF_C)[1:] == [
        ("decided", "accept", "telegram"),
        ("outcome", "ok", None),
    ]
    assert len(upstream.posts()) == 1


async def test_gateway_stop_detaches(tmp_path: Path, ca: ProviderCA) -> None:
    """FM-27, I.2 step 1, Q40, Z23: a gateway process told to stop while its agent's call blocks
    at the vault detaches it there, so the agent gets ``pending <ref>`` before its session
    closes; the hold goes on, its message untouched. Approved in Telegram, the vault runs it with
    nobody waiting, and the agent collects the result through the next gateway process, which
    holds no record of it (FM-39's process half); another client reads ``unknown or
    expired``. The first gateway's ledger has the call pending, closed at the restart."""
    fake = McpFake()
    pins = review(fake, TOOLS)
    with world(
        tmp_path, ca, fake.app(), MCP_HOST, pins=pins, secret=fake.secret, block_seconds=600,
        lifespan=True,
    ) as found:  # fmt: skip
        with anyio.fail_after(BOUND):
            vault = await found.start()
            port = free_port()
            first = found.gateway(port)
            await ready(port, first)
            url = f"http://127.0.0.1:{port}/s/notes/mcp"
            results: list[CallToolResult] = []

            async def blocking() -> None:
                with contextlib.suppress(Exception):  # the gateway goes as the client closes
                    async with agent(url, headers=bearer("agent1")) as client:
                        results.append(await client.call_tool("echo", {"text": "kept"}))

            async with anyio.create_task_group() as group:
                group.start_soon(blocking)
                await until(lambda: len(found.api.operator.prompts()) == 1, BOUND)
                first.popen.terminate()
            stopped = await exited(first)
            [result] = results
            ref = result_ref(result)
            [message] = found.api.operator.prompts()
            found.api.operator.press(message.message_id, "Approve")
            await until(lambda: any(c.name == "echo" for c in fake.calls), BOUND)
            await until(lambda: any("Sent:" in t for t in edits(found.api)), BOUND)
            second = found.gateway(port)
            await ready(port, second)
            async with agent(url, headers=bearer("agent2")) as other:
                crossed = await other.call_tool(CHECK_APPROVAL, {"id": ref})
            async with agent(url, headers=bearer("agent1")) as owner:
                collected = await owner.call_tool(CHECK_APPROVAL, {"id": ref})
    assert stopped == 0, first.output()
    assert text(result).startswith(f"pending {ref}: ")
    assert text(crossed) == f"unknown or expired (ref {ref})"
    assert not collected.is_error, text(collected)
    assert text(collected) == "kept"
    assert [c.arguments for c in fake.calls if c.name == "echo"] == [{"text": "kept"}]
    [detached] = events(first, "approvals_detached")
    assert (detached["asked"], detached["detached"]) == (1, 1)
    [vault_side] = events(vault, "approval_detached")
    assert (vault_side["ref"], vault_side["reason"]) == (ref, "gateway_stop")
    assert not any("withdrawn" in t for t in edits(found.api))
    ledger = gateway_ledger(found.tmp / "gateway", ref)
    assert ledger[:2] == [("asked", "vault"), ("decided", "pending")]
    assert ("outcome", "unknown") in ledger


def bearer(client: str) -> dict[str, str]:
    return {"authorization": f"Bearer {token_for(client)}"}


def result_ref(result: CallToolResult) -> str:
    said = text(result)
    assert said.startswith("pending "), said
    return said.split()[1].removesuffix(":")


async def ready(port: int, process: Process) -> None:
    """Until the gateway on ``port`` answers its health check (it has its view)."""
    await anyio.to_thread.run_sync(wait_port, port, process)

    def healthy() -> bool:
        with contextlib.suppress(httpx.HTTPError):
            return httpx.get(f"http://127.0.0.1:{port}/healthz", timeout=5).status_code == 200
        return False

    while not await anyio.to_thread.run_sync(healthy):
        assert process.popen.poll() is None, process.output()
        await anyio.sleep(0.1)


def gateway_ledger(state: Path, ref: str) -> list[tuple[str, Any]]:
    """The gateway ledger's records of ``ref``: each kind, with where it was asked, its
    decision or its outcome."""
    found = [
        ledgerformat.parse(line)
        for path in sorted((state / LEDGER_DIR).glob("*.jsonl"))
        for line in path.read_bytes().splitlines()
    ]
    return [
        (r.kind, r.fields.get("where") or r.fields.get("decision") or r.fields.get("outcome"))
        for r in found
        if r.ref == ref
    ]
