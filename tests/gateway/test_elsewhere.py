"""The gateway's Elsewhere: a call the vault holds, end to end (M8 design C.2-C.4, D.2; Z5, Z9,
Z27; J2 with a scripted surface; FM-8, FM-9, FM-12, FM-23), and (step 11) an approved forward that
failed, which the vault's answer says was approved (C.2; step 10's deviation 17).

A real vault with its chain and a scripted approver surface (:class:`tests.gateway.holdrig.
Surface`) routes the fake MCP server, and the whole gateway runs on it; the agent is the SDK
client. The tests decide through the surface on the vault's own event loop and move the hold
table's clock instead of waiting. Each answer C.2's table maps that the end-to-end tests can't
reach cheaply is driven through :func:`zoeymcp.gateway.elsewhere.settle` in process, on a real
ledger.
"""

from __future__ import annotations

import asyncio
import io
import json
import re
import threading
from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, TypeVar

import anyio
import httpx
import httpx2
import pytest
from anyio.abc import TaskGroup
from mcp.types import CallToolResult, TextContent
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from tests.fakes.agent import ACCEPT, Script, agent
from tests.fakes.mcp_server import McpFake
from tests.gateway.holdrig import Clock as HoldClock
from tests.gateway.holdrig import Surface
from tests.gateway.rig import (
    CLIENTS,
    KEYS,
    SERVER,
    Deployed,
    Running,
    deployment_with,
    gateway,
    token_for,
    until,
)
from tests.gateway.test_upstream import review
from tests.unit.plainid import plain_id
from zoeymcp.common import canonical, ledgerformat
from zoeymcp.common.approvaltext import Plan, Write
from zoeymcp.common.committed import Committed
from zoeymcp.common.envelope import MARKER_HEADER, Marker
from zoeymcp.common.policy import Policy
from zoeymcp.common.policy.view import ViewGateway, build_view
from zoeymcp.gateway import checkapproval, elsewhere, logs, statuspush
from zoeymcp.gateway.approvals import Key, Pending, Settings
from zoeymcp.gateway.approve import Approvals
from zoeymcp.gateway.egressrules import marker_header
from zoeymcp.gateway.elsewhere import HeldCall, Stale, settle
from zoeymcp.gateway.ledger import LEDGER_DIR, Ledger
from zoeymcp.gateway.pipeline import HEADER_PARAMS
from zoeymcp.gateway.server import status
from zoeymcp.gateway.upstream import UpstreamError
from zoeymcp.gateway.vaultlink import VIEW_PATH, HeldAnswer, held_answer
from zoeymcp.vault.app import WITHDRAWN_REASONS, Refused
from zoeymcp.vault.approvers import ApproverHub
from zoeymcp.vault.holds import Hold
from zoeymcp.vault.vaultledger import CHAIN_DIR, VaultLedger

pytestmark = pytest.mark.anyio
T = TypeVar("T")
BOUND = 30  # seconds: every test's own bound
TOOLS = ["echo", "add", "slow"]
REF = re.compile(r"\(ref ([0-9a-f]{16})\)$")
PENDING = re.compile(r"^pending ([0-9a-f]{16}): waiting for the operator's approval until ")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def text(result: CallToolResult) -> str:
    block = result.content[0]
    assert isinstance(block, TextContent)
    return block.text


def ref_of(result: CallToolResult) -> str:
    found = REF.search(text(result)) or PENDING.match(text(result))
    assert found is not None, text(result)
    return found.group(1)


def headers(client: str = CLIENTS[0]) -> dict[str, str]:
    return {"authorization": f"Bearer {token_for(client)}"}


# --- the rig ------------------------------------------------------------------------------------


class VaultLoop:
    """The vault's app as served: records its event loop, so the test can run code on it. With
    ``park``, the gateway's long polls of the view wait (until :attr:`released`) and answer
    304, so its view stays the one it first fetched while a fetch with no ``wait`` (the first,
    and C.3's) reaches the vault. With ``strip``, the vault's answers lose that header."""

    def __init__(self) -> None:
        self.app: ASGIApp | None = None
        self.loop: asyncio.AbstractEventLoop | None = None
        self.park = False
        self.released = threading.Event()
        self.strip: bytes | None = None

    def wrap(self, app: ASGIApp) -> VaultLoop:
        self.app = app
        return self

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        self.loop = asyncio.get_running_loop()
        assert self.app is not None
        if (
            self.park
            and scope["type"] == "http"
            and scope["path"] == VIEW_PATH
            and b"wait=" in scope.get("query_string", b"")
        ):
            released = await anyio.to_thread.run_sync(lambda: self.released.wait(BOUND))
            if not released:
                await send({"type": "http.response.start", "status": 304, "headers": []})
                await send({"type": "http.response.body", "body": b""})
                return
        await self.app(scope, receive, self._stripped(send))

    def _stripped(self, send: Send) -> Send:
        strip = self.strip
        if strip is None:
            return send

        async def stripped(message: Message) -> None:
            if message["type"] == "http.response.start":
                kept = [(k, v) for k, v in message["headers"] if k.lower() != strip]
                message = {**message, "headers": kept}
            await send(message)

        return stripped


@dataclass
class Vaulted:
    """A vault holding calls, its surface, its chain and its clock, and the gateway on it."""

    deployed: Deployed
    running: Running
    surface: Surface
    clock: HoldClock
    tag: VaultLoop
    chain_dir: Path

    async def on_vault(self, work: Callable[[], T]) -> T:
        loop = self.tag.loop
        assert loop is not None, "no request has reached the vault yet"

        async def run() -> T:
            return work()

        future = asyncio.run_coroutine_threadsafe(run(), loop)
        return await anyio.to_thread.run_sync(lambda: future.result(BOUND))

    async def decide(self, hold: Hold, decision: Literal["approve", "deny"] = "approve") -> Any:
        vault = self.deployed.vault
        assert vault is not None
        return await self.on_vault(
            lambda: vault.decide(hold.id, decision, "portal", hold.text_sha256)
        )

    async def later(self, seconds: float) -> None:
        """Move the hold table's clock on, and run the vault sweeper's tick."""
        vault = self.deployed.vault
        assert vault is not None
        self.clock.ahead += seconds
        await self.on_vault(vault.sweep_holds)

    async def settled(self) -> None:
        vault, loop = self.deployed.vault, self.tag.loop
        assert vault is not None
        assert loop is not None
        future = asyncio.run_coroutine_threadsafe(vault.settle(), loop)
        await anyio.to_thread.run_sync(lambda: future.result(BOUND))

    def chain(self, ref: str) -> list[tuple[str, Any]]:
        """The vault chain's records for ``ref``: each kind, with its decision or outcome."""
        found: list[ledgerformat.Record] = []
        for path in sorted((self.chain_dir / CHAIN_DIR).glob("*.jsonl")):
            found.extend(ledgerformat.parse(line) for line in path.read_bytes().splitlines())
        return [
            (r.kind, r.fields.get("decision") or r.fields.get("outcome"))
            for r in found
            if r.ref == ref
        ]

    def ledger(self, ref: str) -> list[tuple[str, Any]]:
        """The gateway ledger's records for ``ref``: each kind, with where it was asked, its
        decision or its outcome (and detail)."""
        found: list[ledgerformat.Record] = []
        for path in sorted((self.deployed.state / LEDGER_DIR).glob("*.jsonl")):
            found.extend(ledgerformat.parse(line) for line in path.read_bytes().splitlines())
        rows: list[tuple[str, Any]] = []
        for record in found:
            if record.ref != ref:
                continue
            fields = record.fields
            if record.kind == "asked":
                rows.append(("asked", fields["where"]))
            elif record.kind == "decided":
                rows.append(("decided", fields["decision"]))
            else:
                rows.append(("outcome", (fields["outcome"], fields["detail"])))
        return rows

    async def closed(self, ref: str) -> None:
        """The gateway closed ``ref``'s record: its lock freed and its ``outcome`` written. The
        lock frees as the ending is decided, before the records (D-250), so a test that reads
        the ledger waits for both."""
        table = self.running.app.approvals.table
        await until(
            lambda: table.get(ref) is None and any(k == "outcome" for k, _ in self.ledger(ref)),
            BOUND,
        )

    def calls(self, name: str = "echo") -> list[dict[str, Any]]:
        return [call.arguments for call in self.deployed.fake.calls if call.name == name]


@contextmanager
def holding(
    tmp_path: Path, fake: McpFake | None = None, *, park: bool = False, **options: Any
) -> Iterator[Vaulted]:
    """The fake behind a vault that holds ``echo`` and ``add`` (both approve tools) for agent1,
    attended, with the portal's queue as its surface, and the gateway on it."""
    fake = fake if fake is not None else McpFake()
    settings: dict[str, Any] = {
        "include": TOOLS,
        "review": review(fake),
        "approve": ["echo", "add"],
        "vault_approval": ["echo", "add"],
        "approvals": {CLIENTS[0]: {"attended": True}},
        "approvers": {"portal": {}},
        **options,
    }
    chain_dir = tmp_path / "chain"
    chain_dir.mkdir(mode=0o700)
    surface, clock, tag = Surface("portal"), HoldClock(), VaultLoop()
    vault = {
        "chain": VaultLedger.open_at(chain_dir, KEYS.chain_key),
        "hub": ApproverHub([surface]),
        "hold_clock": clock,
    }
    with deployment_with(tmp_path, fake, settings, wrap=tag.wrap, vault=vault) as deployed:
        tag.park = park
        try:
            with gateway(deployed) as running:
                yield Vaulted(deployed, running, surface, clock, tag, chain_dir)
        finally:
            tag.released.set()


async def call_in(
    group: TaskGroup, call: Callable[[], Awaitable[CallToolResult]]
) -> list[CallToolResult]:
    """Start ``call`` in ``group``; its answer lands in the list returned."""
    found: list[CallToolResult] = []

    async def run() -> None:
        found.append(await call())

    group.start_soon(run)
    return found


# --- J2 end to end ------------------------------------------------------------------------------


@pytest.mark.parametrize("version", ["modern", "2025-11-25"])
async def test_an_approved_call_runs_once_through_the_vault(tmp_path: Path, version: Any) -> None:
    """J2 with a scripted surface: the gateway asks no one; the vault holds the call with the
    gateway's ref and client, and once approved forwards it; the agent gets the result as a
    direct call's. The gateway writes ``approved_elsewhere`` only now (C.4), and the vault's
    chain ``accept``."""
    with anyio.fail_after(BOUND), holding(tmp_path) as rig:
        script = Script([ACCEPT])
        async with agent(
            rig.running.mcp(), version=version, script=script, headers=headers()
        ) as client:
            async with anyio.create_task_group() as group:
                answer = await call_in(group, lambda: client.call_tool("echo", {"text": "3pm"}))
                [hold] = await rig.surface.holds(1)
                assert (hold.client, hold.tool, hold.wait) == (CLIENTS[0], "echo", "pending")
                await rig.decide(hold)
            await rig.settled()
    [result] = answer
    assert not result.is_error
    assert "3pm" in text(result)
    assert script.prompts == []  # the gateway asked no one
    assert rig.calls() == [{"text": "3pm"}]
    ref = hold.ref
    assert rig.ledger(ref) == [
        ("asked", "vault"),
        ("decided", "approved_elsewhere"),
        ("outcome", ("ok", None)),
    ]
    assert [kind for kind, _ in rig.chain(ref)] == ["asked", "decided", "outcome"]
    assert rig.chain(ref)[1:] == [("decided", "accept"), ("outcome", "ok")]


@pytest.mark.parametrize(
    ("ending", "said", "decision"),
    [
        pytest.param("deny", "refused: the operator declined this call", "decline", id="deny"),
        pytest.param("expire", "refused: no answer before the deadline", "timeout", id="expire"),
        pytest.param(
            "withdraw", "refused: the policy changed; call the tool again", "withdrawn", id="change"
        ),
    ],
)
async def test_each_ending_is_the_vaults(
    tmp_path: Path, ending: str, said: str, decision: str
) -> None:
    """C.2's rows for a hold that ends unforwarded: each its own text and decision, nothing
    upstream, and the lock freed (a decline and an expiry start the cooldown, E.1)."""
    with anyio.fail_after(BOUND), holding(tmp_path) as rig:
        async with agent(rig.running.mcp(), headers=headers()) as client:
            async with anyio.create_task_group() as group:
                answer = await call_in(group, lambda: client.call_tool("echo", {"text": "hi"}))
                [hold] = await rig.surface.holds(1)
                if ending == "deny":
                    await rig.decide(hold, "deny")
                elif ending == "expire":
                    await rig.later(3601)
                else:  # a change to the approvers block withdraws every undecided hold (B.5)
                    await anyio.to_thread.run_sync(
                        lambda: rig.deployed.reload(approvers={"portal": {}, "timeout": 1800})
                    )
            await rig.settled()
            # A decline and an expiry start the gateway's own cooldown; a withdrawal doesn't.
            later = None
            if decision != "withdrawn":
                later = await client.call_tool("echo", {"text": "hi"})
    [result] = answer
    assert result.is_error
    assert text(result) == f"{said} (ref {hold.ref})"
    assert rig.calls() == []
    assert rig.ledger(hold.ref) == [
        ("asked", "vault"),
        ("decided", decision),
        ("outcome", ("not_sent", None)),
    ]
    assert rig.running.app.approvals.table.get(hold.ref) is None  # the lock is free
    if later is not None:
        assert "declined moments ago" in text(later)


# --- D.2: pending, an identical call, another call -----------------------------------------------


async def test_pending_then_the_same_ref_then_busy(tmp_path: Path) -> None:
    """F.1 and D.2: past ``block_seconds`` the agent gets the pending answer (an error result,
    no structuredContent); an identical call while it waits gets the same ref, with no second
    hold; another call to the tool is busy, naming the ref to collect; and the held call is
    forwarded once when approved, with nobody waiting."""
    approvers = {"portal": {}, "block_seconds": 0, "result_ttl": 1800}
    with anyio.fail_after(BOUND), holding(tmp_path, approvers=approvers) as rig:
        async with agent(rig.running.mcp(), headers=headers()) as client:
            first = await client.call_tool("echo", {"text": "hi"})
            again = await client.call_tool("echo", {"text": "hi"})
            other = await client.call_tool("echo", {"text": "bye"})
            [hold] = await rig.surface.holds(1)
            await rig.decide(hold)
            await rig.settled()
            # The vault's ending closes the record, with nobody collecting (step 12a, OPS-3).
            await rig.closed(hold.ref)
    ref = ref_of(first)
    assert ref == hold.ref
    assert first.is_error
    assert first.structured_content is None
    assert text(first).endswith(
        "UTC. It runs as soon as it is approved, whether or not you check. Do not call echo "
        f'again; call check_approval with {{"id": "{ref}"}} to get the result; it is kept for '
        "30 minutes after the call runs and given once. This is not a failure."
    )
    assert text(again) == text(first)
    assert text(other) == (
        f"refused: a call to this tool is waiting for approval (ref {ref}); "
        f'call check_approval with {{"id": "{ref}"}} (ref {ref_of(other)})'
    )
    assert len(rig.surface.shown) == 1
    assert rig.calls() == [{"text": "hi"}]
    assert rig.ledger(ref) == [
        ("asked", "vault"),
        ("decided", "pending"),
        ("decided", "approved_elsewhere"),
        ("outcome", ("ok", None)),
    ]
    assert rig.chain(ref)[-2:] == [("decided", "accept"), ("outcome", "ok")]


# --- FM-23: answers by ref ----------------------------------------------------------------------


async def test_answers_by_ref(tmp_path: Path) -> None:
    """FM-23, Z27: two held calls on one upstream connection, one approved while the other
    answers pending: each agent call gets its own answer, read by its ref, never through the
    connection's refusal slot."""
    with (
        anyio.fail_after(BOUND),
        holding(tmp_path, gateway_approvals={"max_pending_per_client": 2}) as rig,
    ):
        async with agent(rig.running.mcp(), headers=headers()) as client:
            async with anyio.create_task_group() as group:
                echoed = await call_in(group, lambda: client.call_tool("echo", {"text": "hi"}))
                await rig.surface.holds(1)
                added = await call_in(group, lambda: client.call_tool("add", {"a": 1, "b": 2}))
                holds = await rig.surface.holds(2)
                by_tool = {hold.tool: hold for hold in holds}
                await rig.decide(by_tool["echo"])
                await rig.later(121)  # add's block is over undecided: pending
            await rig.settled()
            # One connection carried both: agent1's (the other is the shared listing's).
            [connection] = [c for c in rig.running.app.pool.connections() if c.key[1] == CLIENTS[0]]
            assert connection.registry._flying == {}
    assert connection.held_answers == {}
    assert connection.vault_refusal is None
    [echo], [add] = echoed, added
    assert not echo.is_error
    assert "hi" in text(echo)
    assert PENDING.match(text(add))
    assert ref_of(add) == by_tool["add"].ref
    assert rig.ledger(by_tool["echo"].ref)[1:] == [
        ("decided", "approved_elsewhere"),
        ("outcome", ("ok", None)),
    ]
    assert rig.ledger(by_tool["add"].ref)[1:] == [("decided", "pending")]


# --- FM-8 and FM-9: view skew (Z5, C.3) ----------------------------------------------------------


async def test_view_skew(tmp_path: Path) -> None:
    """FM-8: a save turned ``vault_approval`` off while the gateway's view still holds the tool.
    The vault refuses the marked call ``view_stale``; the gateway fetches the view at once,
    decides once more and asks itself; the call runs once, approved on the agent's session."""
    script = Script([ACCEPT])
    with anyio.fail_after(BOUND), holding(tmp_path, park=True) as rig:
        await anyio.to_thread.run_sync(lambda: rig.deployed.reload(vault_approval=[]))
        async with agent(rig.running.mcp(), script=script, headers=headers()) as client:
            result = await client.call_tool("echo", {"text": "hi"})
    assert not result.is_error, text(result)
    assert "hi" in text(result)
    assert len(script.prompts) == 1
    assert rig.surface.shown == []
    assert rig.calls() == [{"text": "hi"}]
    vault_refusals = [e for e in rig.deployed.events("request") if e.get("code") == "view_stale"]
    assert len(vault_refusals) == 1
    ref = script.prompts[0].message.split("\n")[0].removeprefix("Approval request ")
    assert rig.ledger(ref) == [
        ("asked", "vault"),
        ("asked", "gateway"),
        ("decided", "accept"),
        ("outcome", ("ok", None)),
    ]


async def test_view_skew_that_asks_no_one_is_refused(tmp_path: Path) -> None:
    """C.3's other arm: the fresh view doesn't ask here either (the tool moved to allow), so the
    call is refused ``view_stale`` and its asked record closed; it never loops."""
    with anyio.fail_after(BOUND), holding(tmp_path, park=True) as rig:
        await anyio.to_thread.run_sync(
            lambda: rig.deployed.reload(vault_approval=[], approve=["add"])
        )
        async with agent(rig.running.mcp(), headers=headers()) as client:
            result = await client.call_tool("echo", {"text": "hi"})
    assert text(result) == f"{elsewhere.STALE} (ref {ref_of(result)})"
    assert rig.calls() == []
    assert rig.ledger(ref_of(result)) == [
        ("asked", "vault"),
        ("decided", "error"),
        ("outcome", ("not_sent", "changed")),
    ]


async def test_unmarked_is_held(tmp_path: Path) -> None:
    """FM-9: the reverse skew. The gateway's view allows the tool, the vault's policy holds it:
    the unmarked call is held anyway, with a ref the vault minted and no reported client, and
    runs only once approved there."""
    with (
        anyio.fail_after(BOUND),
        holding(tmp_path, park=True, approve=[], vault_approval=[]) as rig,
    ):
        await anyio.to_thread.run_sync(
            lambda: rig.deployed.reload(approve=["echo", "add"], vault_approval=["echo", "add"])
        )
        async with agent(rig.running.mcp(), headers=headers()) as client:
            async with anyio.create_task_group() as group:
                answer = await call_in(group, lambda: client.call_tool("echo", {"text": "hi"}))
                [hold] = await rig.surface.holds(1)
                assert rig.calls() == []  # nothing upstream until it is approved
                await rig.decide(hold)
            await rig.settled()
    [result] = answer
    assert not result.is_error
    assert hold.client is None
    assert hold.wait == "block"
    assert rig.calls() == [{"text": "hi"}]
    assert rig.chain(hold.ref)[1:] == [("decided", "accept"), ("outcome", "ok")]


# --- FM-12: no retry after an approved forward (Z9) -----------------------------------------------


async def test_no_404_retry(tmp_path: Path) -> None:
    """FM-12: the upstream answers the approved forward 404 (its session ended): the gateway
    never sends it again, and records ``upstream_error`` (F.6, D-228)."""
    fake = McpFake(session_404_after=1)
    with anyio.fail_after(BOUND), holding(tmp_path, fake, era="legacy") as rig:
        async with agent(rig.running.mcp(), headers=headers()) as client:
            assert text(await client.call_tool("slow", {"steps": 1, "interval": 0})) != ""
            async with anyio.create_task_group() as group:
                answer = await call_in(group, lambda: client.call_tool("echo", {"text": "hi"}))
                [hold] = await rig.surface.holds(1)
                await rig.decide(hold)
            await rig.settled()
    [result] = answer
    assert result.is_error
    echo_calls = [r for r in fake.requests("tools/call") if r.params.get("name") == "echo"]
    assert len(echo_calls) == 1
    assert rig.ledger(hold.ref)[1:] == [
        ("decided", "approved_elsewhere"),
        ("outcome", ("upstream_error", "session_expired")),
    ]


# --- an approved forward that failed (C.2; step 10's deviation 17) -------------------------------


async def _cut(*args: Any, **kwargs: Any) -> Any:
    raise httpx.ReadError("the upstream connection was cut")


async def _unauthorized(*args: Any, **kwargs: Any) -> Any:
    raise Refused(502, "the credential was refused")


@pytest.mark.parametrize(
    ("method", "failing", "outcome", "said"),
    [
        ("_send", _cut, "unknown", "upstream connection lost; the call may or may not have run"),
        ("_authorize", _unauthorized, "not_sent", "upstream unavailable"),
    ],
    ids=["cut", "never-sent"],
)
async def test_an_approved_forward_that_failed_is_the_forwards_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    failing: Callable[..., Awaitable[Any]],
    outcome: str,
    said: str,
) -> None:
    """The vault forwards the approved call, and the forward fails: its request upstream cut
    (it may have run), or its credential refused before anything was sent. The vault's 502
    carries the approval's headers and its chain's outcome, so the gateway writes
    ``approved_elsewhere`` and the same outcome, never "refused by the vault"."""
    with anyio.fail_after(BOUND), holding(tmp_path) as rig:
        async with agent(rig.running.mcp(), headers=headers()) as client:
            async with anyio.create_task_group() as group:
                answer = await call_in(group, lambda: client.call_tool("echo", {"text": "hi"}))
                [hold] = await rig.surface.holds(1)
                monkeypatch.setattr(rig.deployed.vault, method, failing)
                await rig.decide(hold)
            await rig.settled()
    [result] = answer
    assert result.is_error
    assert text(result) == f"{said} (ref {hold.ref})"
    assert rig.ledger(hold.ref)[1:] == [
        ("decided", "approved_elsewhere"),
        ("outcome", (outcome, None)),
    ]
    assert rig.chain(hold.ref)[1:] == [("decided", "accept"), ("outcome", outcome)]
    refusals = [e for e in rig.deployed.events("approval_refused") if e.get("ref") == hold.ref]
    assert refusals == []


# --- C.2's last row ---------------------------------------------------------------------------


async def test_an_answer_without_the_vaults_approval_is_withheld(tmp_path: Path) -> None:
    """C.2's last row: an upstream answer to a held call with neither the vault's approval nor
    its refusal is ``elsewhere_unheld``: an error-level log line, a count in the status report
    (K.1), and the result withheld from the agent."""
    with anyio.fail_after(BOUND), holding(tmp_path) as rig:
        rig.tag.strip = b"x-zoeymcp-approval"
        async with agent(rig.running.mcp(), headers=headers()) as client:
            async with anyio.create_task_group() as group:
                answer = await call_in(
                    group, lambda: client.call_tool("echo", {"text": "kettle-42"})
                )
                [hold] = await rig.surface.holds(1)
                await rig.decide(hold)
            await rig.settled()
        found = status(rig.running.app)
        sent = statuspush.content(found, started=1, max_tools=64)
    [result] = answer
    assert text(result) == f"{elsewhere.UNHELD} (ref {hold.ref})"
    assert "kettle-42" not in text(result)
    [unheld] = rig.deployed.events("elsewhere_unheld")
    assert (unheld["ref"], unheld["server"], unheld["level"]) == (hold.ref, SERVER, "error")
    assert found["servers"][SERVER]["held"] == {"elsewhere_unheld": 1}
    assert sent is not None
    assert sent["servers"][SERVER]["held"] == {"elsewhere_unheld": 1}
    assert rig.ledger(hold.ref)[1:] == [("decided", "error"), ("outcome", ("unknown", None))]


async def test_an_answer_after_its_call_ended_is_dropped(tmp_path: Path) -> None:
    """Z27: the vault's answer to a held call is kept only while that call is in flight. One that
    comes after the call ended (its caller cancelled while the SDK's writer kept the POST open,
    and the vault answered later) is dropped, logged by its ref and status only."""
    marker = Marker("0123456789abcdef", CLIENTS[0], "pending", "a1b2c3d4e5f6", None)
    digest = canonical.digest({"text": "hi"})
    request = httpx2.Request(
        "POST",
        "http://vault.invalid/notes/mcp",
        headers={MARKER_HEADER: marker_header(marker)},
    )
    refusal = httpx2.Response(
        409, headers={"x-zoeymcp-vault": "refused"}, content=b'{"code": "approval_declined"}'
    )
    with anyio.fail_after(BOUND), holding(tmp_path) as rig:
        async with agent(rig.running.mcp(), headers=headers()) as client:
            assert text(await client.call_tool("slow", {"steps": 1, "interval": 0})) != ""
        [connection] = [c for c in rig.running.app.pool.connections() if c.key[1] == CLIENTS[0]]
        connection.noted(request, refusal)  # its call ended: nobody reads it
        assert connection.held_answers == {}
        assert connection.registry.register("echo", digest, marker)
        assert connection.registry.claim("echo", digest) is not None
        connection.noted(request, refusal)  # in flight: kept for its call
        answer = connection.held_answers.pop(marker.ref)
        connection.registry.release("echo", digest, marker)
    assert answer.code == "approval_declined"
    [dropped] = rig.deployed.events("held_answer_dropped")
    assert (dropped["ref"], dropped["status"]) == (marker.ref, 409)


# --- C.2's table, in process ----------------------------------------------------------------------

VIEW_POLICY: dict[str, Any] = {
    "version": 1,
    "mode": "declarative",
    "approvers": {"portal": {}, "timeout": 3600, "block_seconds": 120, "result_ttl": 3600},
    "gateway": {
        "approvals": {"cooldown": 15},
        "clients": {"agent1": {"token_sha256": "sha256:" + "0" * 64, "servers": ["notes"]}},
        "servers": {
            "notes": {
                "kind": "remote",
                "route": "notes",
                "tools": {"include": ["echo"], "approve": ["echo"], "vault_approval": ["echo"]},
                "review": {"echo": "sha256:" + "1" * 64},
            }
        },
    },
    "credentials": {},
    "routes": [
        {
            "name": "notes",
            "prefix": "/notes",
            "upstream": "https://notes.example",
            "callers": ["gateway"],
            "rules": [{"methods": ["POST"], "paths": ["/mcp"]}],
        }
    ],
}


def view_gateway() -> ViewGateway:
    return build_view(Policy.model_validate(VIEW_POLICY)).gateway


def refused(code: str | None, status: int = 409, **fields: Any) -> HeldAnswer:
    return HeldAnswer(status, True, False, None, code, **fields)


def approved_refusal(code: str | None, outcome: str | None = None) -> HeldAnswer:
    """The vault's refusal of a forward that failed after its approval (B.6), which carries the
    approval's headers for the call's ref, and the forward's outcome on the vault's chain."""
    return HeldAnswer(502, True, True, "0123456789abcdef", code, outcome=outcome)


LOST = "upstream connection lost; the call may or may not have run"
APPROVED = {
    "x-zoeymcp-vault": "refused",
    "x-zoeymcp-approval": "approved",
    "x-zoeymcp-held-ref": "0123456789abcdef",
}
# Each answer the vault may give, the gateway's decision and outcome for it, and the agent's text
# (without its ref).
ROWS: list[Any] = [
    (
        refused("approval_declined"),
        "decline",
        "not_sent",
        "refused: the operator declined this call",
    ),
    (refused("approval_expired"), "timeout", "not_sent", "refused: no answer before the deadline"),
    (
        refused("approval_withdrawn"),
        "withdrawn",
        "not_sent",
        "refused: the policy changed; call the tool again",
    ),
    (
        refused("held_ref_reused"),
        "error",
        "not_sent",
        "refused: one held write per call; nothing was sent",
    ),
    (
        refused("held_second_write"),
        "error",
        "not_sent",
        "refused: one held write per call; nothing was sent",
    ),
    (
        refused("held_capacity", 429),
        "unavailable",
        "not_sent",
        "refused: the vault's approval queue is full",
    ),
    (
        refused("held_busy", 429),
        "unavailable",
        "not_sent",
        "refused: the vault's approval queue is full",
    ),
    (
        refused("held_hourly", 429),
        "unavailable",
        "not_sent",
        "refused: too many approval requests this hour",
    ),
    (
        refused("held_cooldown", 429, retry_after=12),
        "unavailable",
        "not_sent",
        "refused: declined moments ago; try again in 12 s",
    ),
    (
        refused("held_ledger_down", 503),
        "unavailable",
        "not_sent",
        "refused: the vault can't record approvals right now; nothing was sent",
    ),
    (
        refused("stopping", 503),
        "unavailable",
        "not_sent",
        "refused: the vault is restarting; nothing was sent; try again shortly",
    ),
    (
        refused("held_text_refused", 422, pointer="/arguments/text"),
        "error",
        "not_sent",
        "refused: the approval text broke a rule at /arguments/text; nothing was sent",
    ),
    (
        # A pointer the gateway's pattern refused: the text names no place.
        refused("held_text_refused", 422),
        "error",
        "not_sent",
        "refused: the approval text broke a rule; nothing was sent",
    ),
    (
        refused("telegram_too_long", 422),
        "error",
        "not_sent",
        "refused: too long to show in the operator's chat; nothing was sent",
    ),
    (
        refused("telegram_text_changed", 502),
        "error",
        "not_sent",
        "refused: the approval text can't be shown as sent; nothing was sent",
    ),
    (refused("held_result_too_large", 502), "error", "unknown", elsewhere.TOO_LARGE),
    (refused("held_batch", 400), "error", "not_sent", elsewhere.UNREAD),
    (refused("held_path", 404), "error", "not_sent", elsewhere.UNREAD),
    (refused("held_too_large", 413), "error", "not_sent", elsewhere.UNREAD),
    (refused("held_content_type", 415), "error", "not_sent", elsewhere.UNREAD),
    # Any other refusal is unknown: the vault's refusal of a forward that failed after its
    # approval carries the approval's headers, but one that lost them may have run too.
    (refused("something_new", 409), "error", "unknown", elsewhere.REFUSED_BY_VAULT),
    (refused(None, 403), "error", "unknown", elsewhere.REFUSED_BY_VAULT),
    (refused(None, 502), "error", "unknown", elsewhere.REFUSED_BY_VAULT),
    # The vault approved and forwarded it, and the forward failed: approved_elsewhere, and the
    # outcome the vault's chain records (never the SDK's error for the vault's 502); one it
    # doesn't name may have run.
    (
        approved_refusal(None, "not_sent"),
        "approved_elsewhere",
        "not_sent",
        "upstream unavailable",
    ),
    (approved_refusal(None, "unknown"), "approved_elsewhere", "unknown", LOST),
    (
        approved_refusal(None, "upstream_error"),
        "approved_elsewhere",
        "upstream_error",
        "upstream error",
    ),
    (approved_refusal(None), "approved_elsewhere", "unknown", LOST),
    (
        approved_refusal("held_result_too_large"),
        "approved_elsewhere",
        "unknown",
        elsewhere.TOO_LARGE,
    ),
    # Approved for another ref: never this call's approval.
    (
        HeldAnswer(502, True, True, "fedcba9876543210", None),
        "error",
        "unknown",
        elsewhere.REFUSED_BY_VAULT,
    ),
    (HeldAnswer(200, False, False), "error", "unknown", elsewhere.UNHELD),
    (HeldAnswer(200, False, True, "fedcba9876543210"), "error", "unknown", elsewhere.UNHELD),
    (None, "error", "unknown", elsewhere.UNHELD),
]


@dataclass
class InProcess:
    approvals: Approvals
    call: HeldCall
    record: Pending
    settings: Settings
    tmp_path: Path

    def records(self) -> list[tuple[str, Any]]:
        found: list[ledgerformat.Record] = []
        for path in sorted((self.tmp_path / LEDGER_DIR).glob("*.jsonl")):
            found.extend(ledgerformat.parse(line) for line in path.read_bytes().splitlines())
        return [
            (r.kind, r.fields.get("decision") or r.fields.get("outcome"))
            for r in found
            if r.ref == self.call.ref
        ]


async def in_process(tmp_path: Path) -> InProcess:
    ledger, _ = Ledger.open_at(tmp_path, max_bytes=2**20)
    approvals = Approvals(
        ledger=ledger, committed=Committed(), fresh=lambda: None, stopping=lambda: False
    )
    gateway = view_gateway()
    server = gateway.servers["notes"]

    async def forward(held: Any, grant: Any) -> CallToolResult:
        raise AssertionError("not forwarded here")

    call = HeldCall(
        ref="0123456789abcdef",
        client="agent1",
        server="notes",
        tool="echo",
        era="modern",
        policy=server,
        gateway=gateway,
        args={"text": "arg-sentinel-5e2b"},
        pin="sha256:" + "1" * 64,
        wait="pending",
        forward=forward,
        finish=lambda raw: raw,
    )
    settings = Settings(3600, 300, 15, 1, 30)
    record = approvals.table.begin(
        Key("agent1", "notes", "echo"),
        settings=settings,
        now=approvals.clock(),
        ref=call.ref,
        era="modern",
        args=call.args,
        args_digest="sha256:" + "2" * 64,
        pin=call.pin,
        text_sha256="t",
        how="elsewhere",
    )
    assert isinstance(record, Pending)
    await ledger.write(
        "asked",
        call.ref,
        critical=True,
        client="agent1",
        server="notes",
        tool="echo",
        where="vault",
        era="modern",
        args=ledger.digest(call.args),
        pin=call.pin,
        text=ledger.text_digest(""),
        chars=0,
        writes=0,
        expires=1,
    )
    return InProcess(approvals, call, record, settings, tmp_path)


@pytest.mark.parametrize(("answer", "decision", "outcome", "said"), ROWS, ids=plain_id)
async def test_each_vault_answer_maps_to_its_text(
    tmp_path: Path, answer: HeldAnswer | None, decision: str, outcome: str, said: str
) -> None:
    """C.2's table: every vault answer the gateway can be given, with the decision and outcome
    the gateway's ledger records, the text the agent reads, and the lock freed after it (the
    cooldown starting for a decline or an expiry, E.1)."""
    held = await in_process(tmp_path)
    raw = CallToolResult(content=[TextContent(type="text", text="secret result")], is_error=False)
    failure = UpstreamError("rpc_error") if answer is not None and answer.refused else None
    result = await settle(
        held.approvals,
        held.call,
        held.record,
        held.settings,
        answer,
        None if failure is not None else raw,
        failure,
        0.0,
    )
    assert isinstance(result, CallToolResult)
    assert result.is_error
    assert text(result) == f"{said} (ref {held.call.ref})"
    assert held.records() == [("asked", None), ("decided", decision), ("outcome", outcome)]
    assert held.approvals.table.get(held.call.ref) is None
    cooled = decision in ("decline", "timeout")
    assert (Key("agent1", "notes", "echo") in held.approvals.table._cooldowns) is cooled
    assert held.approvals.unheld["notes"] == (1 if said == elsewhere.UNHELD else 0)


POLICY_CHANGED = "refused: the policy changed; call the tool again"


@pytest.mark.parametrize(
    ("reason", "said"),
    [
        ("changed", POLICY_CHANGED),
        ("operator", "refused: the operator withdrew this call; nothing was sent"),
        ("shutdown", "refused: the vault stopped; nothing was sent; try again shortly"),
        (
            "gateway_stopped",
            "refused: the gateway is stopping; nothing was sent; try again shortly",
        ),
        (
            "gateway_restarted",
            "refused: the gateway restarted; nothing was sent; call the tool again",
        ),
        ("stream_lost", POLICY_CHANGED),
        (None, POLICY_CHANGED),
    ],
    ids=[
        "changed",
        "operator",
        "shutdown",
        "gateway-stopped",
        "gateway-restarted",
        "unnamed",
        "none",
    ],
)
async def test_a_withdrawal_says_why(tmp_path: Path, reason: str | None, said: str) -> None:
    """Step 10's deviation 18 (M8 steps 16 and 17): the vault's ``approval_withdrawn`` names
    its reason, and each named one has its own text: the operator's withdraw (K.3, J15), the
    vault's stop, the gateway's own stop (a blocking call its detach withdrew, I.2) and a new
    gateway epoch (G-15); a policy change, a reason the vault never names or none keeps "the
    policy changed". Each is recorded withdrawn, nothing sent."""
    held = await in_process(tmp_path)
    result = await settle(
        held.approvals,
        held.call,
        held.record,
        held.settings,
        refused("approval_withdrawn", reason=reason),
        None,
        UpstreamError("rpc_error"),
        0.0,
    )
    assert isinstance(result, CallToolResult)
    assert text(result) == f"{said} (ref {held.call.ref})"
    assert held.records() == [("asked", None), ("decided", "withdrawn"), ("outcome", "not_sent")]


@pytest.mark.parametrize(
    ("body", "reason"),
    [
        (b'{"error":"conflict","code":"approval_withdrawn","reason":"operator"}', "operator"),
        (b'{"error":"conflict","code":"approval_withdrawn","reason":"changed"}', "changed"),
        (
            b'{"error":"conflict","code":"approval_withdrawn","reason":"gateway_stopped"}',
            "gateway_stopped",
        ),
        (b'{"error":"conflict","code":"approval_withdrawn","reason":"Operator!"}', None),
        (b'{"error":"conflict","code":"approval_withdrawn","reason":1}', None),
        (b'{"error":"conflict","code":"approval_withdrawn"}', None),
    ],
    ids=["operator", "changed", "gateway-stopped", "not-a-name", "not-a-string", "none"],
)
def test_a_withdrawals_reason_is_read_as_a_name(body: bytes, reason: str | None) -> None:
    """``held_answer`` reads a refusal's ``reason`` only in a name's form (lowercase letters and
    underscores, at most 32): the gateway's own table gives it its text."""
    found = held_answer(409, httpx2.Headers({"x-zoeymcp-vault": "refused"}), body)
    assert (found.code, found.reason) == ("approval_withdrawn", reason)


def test_every_reason_the_vault_names_has_its_own_text() -> None:
    """The vault's closed set of withdrawal reasons (step 10's deviation 18, M8 steps 16 and 17)
    is the gateway's table, each in a name's form, and every one says nothing was sent but a
    policy change's, which asks for the call again; ``check_approval`` names each too."""
    assert set(elsewhere.WITHDRAWN) == WITHDRAWN_REASONS
    for reason, said in elsewhere.WITHDRAWN.items():
        assert re.fullmatch(r"[a-z_]{1,32}", reason)
        assert said.startswith("refused: ")
        assert reason in checkapproval.WITHDRAWN
    assert elsewhere.WITHDRAWN["changed"] == elsewhere.VAULT_ANSWERS["approval_withdrawn"][1]


@pytest.mark.parametrize(
    ("headers", "body", "outcome"),
    [
        (APPROVED, b'{"error":"bad gateway","outcome":"not_sent"}', "not_sent"),
        (APPROVED, b'{"error":"bad gateway","outcome":"upstream_error"}', "upstream_error"),
        (APPROVED, b'{"error":"bad gateway","outcome":"sent"}', None),
        (APPROVED, b'{"error":"bad gateway","outcome":1}', None),
        (APPROVED, b'{"error":"bad gateway"}', None),
        ({"x-zoeymcp-vault": "refused"}, b'{"error":"bad gateway","outcome":"not_sent"}', None),
    ],
    ids=["not-sent", "upstream-error", "not-an-outcome", "not-a-string", "none", "not-approved"],
)
def test_an_approved_refusal_names_the_forwards_outcome(
    headers: dict[str, str], body: bytes, outcome: str | None
) -> None:
    """The outcome is read only from a refusal that carries the approval's headers, and only
    as one of the ledger's outcomes."""
    found = held_answer(502, httpx2.Headers(headers), body)
    assert found.refused
    assert found.outcome == outcome


async def test_view_stale_is_left_to_the_pipeline(tmp_path: Path) -> None:
    held = await in_process(tmp_path)
    found = await settle(
        held.approvals,
        held.call,
        held.record,
        held.settings,
        refused("view_stale"),
        None,
        UpstreamError("rpc_error"),
        0.0,
    )
    assert isinstance(found, Stale)
    assert held.approvals.table.get(held.call.ref) is None  # released, with nothing decided
    assert held.records() == [("asked", None)]


async def test_a_pending_answer_keeps_the_lock_and_its_deadline(tmp_path: Path) -> None:
    held = await in_process(tmp_path)
    answer = refused("approval_pending", deadline="2026-11-02T13:05:00+00:00")
    result = await settle(
        held.approvals, held.call, held.record, held.settings, answer, None, None, 0.0
    )
    assert isinstance(result, CallToolResult)
    assert text(result).startswith(
        "pending 0123456789abcdef: waiting for the operator's approval until 2026-11-02 13:05 UTC."
    )
    assert "it is kept for 60 minutes" in text(result)
    record = held.approvals.table.get(held.call.ref)
    assert record is not None
    assert record.decision is None
    assert record.pending_until == datetime(2026, 11, 2, 13, 5, tzinfo=UTC).timestamp()
    assert held.records() == [("asked", None), ("decided", "pending")]


async def test_a_logged_answer_never_carries_a_value(tmp_path: Path) -> None:
    """The vault's refusals are logged by code and reason only; the call's arguments and its
    result never reach a log line."""
    captured = io.StringIO()
    logs.set_stream(captured)
    try:
        held = await in_process(tmp_path)
        await settle(
            held.approvals,
            held.call,
            held.record,
            held.settings,
            refused("something_new"),
            None,
            UpstreamError("rpc_error"),
            0.0,
        )
    finally:
        logs.set_stream(None)
    lines = [json.loads(line) for line in captured.getvalue().splitlines()]
    [refusal] = [line for line in lines if line["event"] == "approval_refused"]
    assert (refusal["reason"], refusal["code"], refusal["level"]) == (
        "vault_refused",
        "something_new",
        "warning",
    )
    assert "arg-sentinel-5e2b" not in captured.getvalue()


async def test_a_plan_of_more_than_one_write_is_refused(tmp_path: Path) -> None:
    """B.7, C.2 step 4: a toolkit's plan with more than one write to a held route is refused
    ``plan_multi_held`` after ``prepare``, before the lock or the ledger; nothing is sent."""
    held = await in_process(tmp_path)
    held.approvals.table.finish(held.record.key, held.call.ref, 0.0, settings_cooldown=0.0)
    writes = [Write.post("/send", {"n": 1}), Write.post("/send", {"n": 2})]

    async def prepare() -> Plan:
        return Plan("Mail twice", writes)

    call = replace(held.call, ref="00000000000000aa", prepare=prepare, wait="block")
    result = await elsewhere.run(held.approvals, call)
    assert isinstance(result, CallToolResult)
    assert text(result) == f"{elsewhere.PLAN_MULTI_HELD} (ref {call.ref})"
    assert held.approvals.table.get(call.ref) is None
    assert [r for r in held.records() if r[0] != "asked"] == []


async def test_a_toolkit_body_that_sent_no_held_write(tmp_path: Path) -> None:
    """A toolkit's body that sent nothing held (no answer names the call): nothing was asked,
    so the call is closed ``error``, ``not_sent``, and the body's own answer is the agent's."""
    held = await in_process(tmp_path)

    async def prepare() -> None:
        return None

    call = replace(held.call, prepare=prepare, wait="block")
    raw = CallToolResult(content=[TextContent(type="text", text="nothing to send")], is_error=True)
    result = await settle(held.approvals, call, held.record, held.settings, None, raw, None, 0.0)
    assert result is raw
    assert held.records() == [("asked", None), ("decided", "error"), ("outcome", "not_sent")]
    assert held.approvals.unheld["notes"] == 0


async def test_a_held_tool_that_mirrors_parameters_into_headers_is_refused(tmp_path: Path) -> None:
    """C.1 row 4 (Q27): a held tool whose pinned schema declares ``x-mcp-header`` is refused
    before anything is held or recorded, and the status report names it for health (K.1)."""
    fake = McpFake()
    names = [*TOOLS, "lookup"]
    options: dict[str, Any] = {
        "include": names,
        "review": review(fake, names),
        "approve": ["echo", "lookup"],
        "vault_approval": ["echo", "lookup"],
    }
    with anyio.fail_after(BOUND), holding(tmp_path, fake, **options) as rig:
        async with agent(rig.running.mcp(), headers=headers()) as client:
            result = await client.call_tool("lookup", {"region": "eu", "query": "q"})
        found = status(rig.running.app)
    assert text(result) == f"{HEADER_PARAMS} (ref {ref_of(result)})"
    assert rig.surface.shown == []
    assert rig.calls("lookup") == []
    assert rig.ledger(ref_of(result)) == []
    assert found["servers"][SERVER]["held"] == {"header_params": ["lookup"]}
