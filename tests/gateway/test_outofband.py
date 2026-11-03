"""Out-of-band approvals from the gateway's side (M8 design C.1 rows 2-7, E; Z11).

Built from step 10 on: an ``attended`` client's call to a ``vault_approval`` tool goes to the
vault, which asks the operator's approvers, while its other ``approve`` tools keep elicitation
(G-18); a client nobody answers for is refused. The rig is :mod:`tests.gateway.test_elsewhere`'s.

Step 12a adds the vault's other approvals paths (E.2) and the gateway's client of them
(:mod:`zoeymcp.gateway.outofband`, E.3):

- **withdraw** (B.6, SC-1): an abandoned call closes its blocking or pending hold, for the client
  the gateway reported only (T34), and never an approved one (Z9); the agent's abandoned call
  reaches it through the gateway;
- **detach** (I.2, G-16): a stopping gateway's blocking ``wait=pending`` call answers pending at
  once and waits on, collectable; a ``wait=block`` one is withdrawn;
- **decisions** (OPS-3): the endings of the calls a gateway marked, numbered, by its epoch, long
  polled one at a time, and the gateway's pending record closed by them without a collect, once;
- **the epoch rule** (G-15): a new gateway epoch withdraws an earlier epoch's legacy-session holds
  and keeps its modern ones collectable.

Step 12b adds the relay (E.1, E.3-E.5; Q6 (B), G-23, G-24): an ``out_of_band`` client's
gateway-held prompt is rendered by the gateway, asked through the vault's ask endpoint, shown on
the operator's surfaces below the vault's own relay line (Z12) and decided there; the decision
comes back through the decisions poll, numbered with the endings, and the gateway forwards the
call itself, only for an approval of the text it asked with (FM-28). A relay ends with its
decision, its caller leaving (``withdraw``), a change that takes its client's ``out_of_band``,
or a new gateway epoch; past its block it answers pending and is collected from the gateway's
own result store (S21's relay half is ``tests/acceptance/test_pending_shapes.py``'s). A client
nobody answers for is refused (Z11).

The vault-side tests run a real vault on both links (``tests/gateway/holdrig.py``; the link
socket on Linux only), the gateway-side ones the whole gateway on it.
"""

from __future__ import annotations

import hashlib
import io
import json
import threading
import time
from collections.abc import AsyncIterator, Iterator, Mapping
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import anyio
import httpx
import httpx2
import pytest
from mcp.types import CallToolResult

from tests.fakes.agent import ACCEPT, Script, agent
from tests.gateway.holdrig import EPOCH, LINKS, Answer, HoldRig, call, headers, marker
from tests.gateway.rig import CLIENTS, KEYS, until
from tests.gateway.test_checkapproval import LINK, Vault, checker, done, pend, result_body
from tests.gateway.test_elsewhere import (
    BOUND,
    PENDING,
    VIEW_POLICY,
    Vaulted,
    call_in,
    holding,
    in_process,
    ref_of,
    text,
)
from tests.gateway.test_elsewhere import headers as bearer
from zoeymcp.common import canonical, ledgerformat
from zoeymcp.common.approvaltext import RELAY_LINE, ApprovalText, Header, render_call
from zoeymcp.common.committed import Committed
from zoeymcp.common.policy import Policy
from zoeymcp.common.policy.view import build_view
from zoeymcp.gateway import checkapproval, elsewhere, pipeline, server
from zoeymcp.gateway import logs as gateway_logs
from zoeymcp.gateway.app import STOP_DETACH_WAIT
from zoeymcp.gateway.approvals import MAX_RECORDS, Key, Pending, Settings
from zoeymcp.gateway.approve import LEDGER_DOWN, RESULT_TTL_MAX, Approvals, Asking
from zoeymcp.gateway.approvers import (
    NO_APPROVALS,
    RELAY_MISMATCH,
    RELAY_UNREACHABLE,
    Asked,
    AskRefused,
    Decided,
    Relayed,
    RelayWait,
    Shown,
)
from zoeymcp.gateway.ledger import LEDGER_DIR, LedgerUnavailable
from zoeymcp.gateway.outofband import (
    IDLE_WAIT,
    ApprovalsFailed,
    Ending,
    OutOfBandClient,
    endings,
)
from zoeymcp.gateway.pipeline import NO_APPROVER, NO_OUT_OF_BAND
from zoeymcp.gateway.policyclient import Snapshot
from zoeymcp.gateway.vaultlink import KeySource, approvals_client, parse_link
from zoeymcp.vault import internal
from zoeymcp.vault import logs as vault_logs
from zoeymcp.vault.app import NO_PIN, RELAY_ROUTE
from zoeymcp.vault.holds import DecideRefusal

pytestmark = pytest.mark.anyio
REF_A, REF_B, REF_C, REF_D = (f"00000000000000c{n}" for n in "abcd")
SHOP = "/shop/mcp"
APPROVALS = "/_zoeymcp/gateway/v1/approvals/"
LATER = "ba9876543210"  # a restarted gateway's epoch
JSON = {"content-type": "application/json"}


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def log() -> Iterator[io.StringIO]:
    stream = io.StringIO()
    vault_logs.set_stream(stream)
    try:
        yield stream
    finally:
        vault_logs.set_stream(None)


def events(stream: io.StringIO, kind: str) -> list[dict[str, Any]]:
    lines = [json.loads(line) for line in stream.getvalue().splitlines() if line]
    return [line for line in lines if line["event"] == kind]


async def post(http: httpx.AsyncClient, name: str, body: dict[str, Any]) -> dict[str, Any]:
    response = await http.post(
        APPROVALS + name, content=canonical.dumps_canonical(body), headers=JSON
    )
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    found: dict[str, Any] = response.json()
    assert found["v"] == 1
    return found


async def withdraw(
    http: httpx.AsyncClient, ref: str, *, client: str = "agent1", epoch: str = EPOCH
) -> dict[str, Any]:
    body = {"epoch": epoch, "ref": ref, "client": client, "reason": "caller_cancelled"}
    return await post(http, "withdraw", body)


async def collect(
    http: httpx.AsyncClient, ref: str, *, client: str = "agent1", epoch: str = EPOCH
) -> dict[str, Any]:
    return await post(
        http, "collect", {"epoch": epoch, "ref": ref, "client": client, "server": "shop"}
    )


async def poll(
    http: httpx.AsyncClient, *, epoch: str = EPOCH, after: int = 0, wait: int = 0
) -> httpx.Response:
    query = {"epoch": epoch, "after": str(after), "wait": str(wait)}
    return await http.get(APPROVALS + "decisions", params=query)


def pending(ref: str, *, client: str = "agent1", **more: str) -> dict[str, str]:
    return headers(held=marker(ref, client=client, wait="pending"), **more)


# --- withdraw (E.2, B.6) --------------------------------------------------------------------------


@pytest.mark.parametrize("link", LINKS)
@pytest.mark.parametrize("wait", ["block", "pending"])
async def test_withdraw_closes_a_blocking_hold(
    tmp_path: Path, link: str, wait: str, log: io.StringIO
) -> None:
    """B.6, SC-1: the gateway's ``withdraw caller_cancelled`` closes a hold whose request still
    waits, in its block: the request is answered ``approval_withdrawn``, the chain closes it
    unsent, nothing goes upstream, and a ``wait=pending`` call's record says why. Another
    client's withdraw of the ref reads it as unknown and changes nothing (T34)."""
    rig = HoldRig(tmp_path, link=link)
    async with rig.running() as http:
        with anyio.fail_after(BOUND):
            answer = Answer()
            sent = headers(held=marker(REF_A, wait=wait))
            async with anyio.create_task_group() as group:
                group.start_soon(answer.post, http, SHOP, call(), sent)
                [hold] = await rig.surface.holds(1)
                other = await withdraw(http, REF_A, client="agent2")
                assert rig.app.holds.get(hold.id) is not None
                withdrawn = await withdraw(http, REF_A)
            await rig.settled()
            again = await withdraw(http, REF_A)
            unknown = await withdraw(http, REF_B)
            status = await collect(http, REF_A)
    assert other == {"v": 1, "ref": REF_A, "state": "unknown"}
    assert withdrawn == {"v": 1, "ref": REF_A, "state": "withdrawn"}
    assert again == withdrawn  # how it ended
    assert unknown == {"v": 1, "ref": REF_B, "state": "unknown"}
    assert answer.json()["code"] == "approval_withdrawn"
    assert rig.kinds(REF_A)[1:] == [("decided", "withdrawn"), ("outcome", "not_sent")]
    assert rig.upstream.received == []
    assert rig.surface.closed == [(hold.id, "withdrawn")]
    [event] = events(log, "approval_withdrawn")
    assert (event["ref"], event["reason"]) == (REF_A, "caller_cancelled")
    if wait == "pending":
        assert (status["state"], status["detail"]) == ("withdrawn", "caller_cancelled")
    else:
        assert status == {"v": 1, "ref": REF_A, "state": "unknown"}  # no record: it blocked


@pytest.mark.parametrize("link", LINKS)
async def test_an_approved_call_is_not_withdrawn(tmp_path: Path, link: str) -> None:
    """Z9: once approved, the call is committed: a withdraw while it is forwarded answers its
    state and changes nothing; the forward finishes and its caller gets the result."""
    rig = HoldRig(tmp_path, link=link)
    gate = rig.upstream.gate = threading.Event()
    async with rig.running() as http:
        with anyio.fail_after(BOUND):
            answer = Answer()
            async with anyio.create_task_group() as group:
                group.start_soon(answer.post, http, SHOP, call(), pending(REF_A))
                [hold] = await rig.surface.holds(1)
                await rig.decide(hold)
                await anyio.to_thread.run_sync(lambda: rig.upstream.answering.wait(BOUND))
                running = await withdraw(http, REF_A)
                gate.set()
            await rig.settled()
    assert running == {"v": 1, "ref": REF_A, "state": "forwarding"}
    assert answer.json()["result"]["isError"] is False
    assert rig.kinds(REF_A) == [("asked", None), ("decided", "accept"), ("outcome", "ok")]


# --- detach (E.2, I.2, G-16) ----------------------------------------------------------------------


@pytest.mark.parametrize("link", LINKS)
async def test_detach_answers_pending_now(tmp_path: Path, link: str, log: io.StringIO) -> None:
    """I.2, Q40: the stopping gateway's detach answers its blocking ``wait=pending`` call
    ``approval_pending`` at once, with its deadline, and the hold waits on: approved later, its
    result is collectable. Its ``wait=block`` call is withdrawn instead, a ref it doesn't hold is
    passed over, and another client's ref is left waiting (T34). The answer names the refs it
    detached."""
    rig = HoldRig(tmp_path, link=link)
    async with rig.running() as http:
        with anyio.fail_after(BOUND):
            waiting, blocking = Answer(), Answer()
            async with anyio.create_task_group() as group:
                group.start_soon(waiting.post, http, SHOP, call(), pending(REF_A))
                await rig.surface.holds(1)
                sent = headers(held=marker(REF_B, client="agent2"))
                group.start_soon(blocking.post, http, SHOP, call(), sent)
                held = {hold.ref: hold for hold in await rig.surface.holds(2)}
                foreign = {"epoch": EPOCH, "calls": [{"ref": REF_A, "client": "agent2"}]}
                passed = await post(http, "detach", foreign)
                assert not waiting.done.is_set()
                calls = [
                    {"ref": REF_A, "client": "agent1"},
                    {"ref": REF_B, "client": "agent2"},
                    {"ref": REF_C, "client": "agent1"},
                ]
                detached = await post(http, "detach", {"epoch": EPOCH, "calls": calls})
            await rig.settled()
            live = rig.app.holds.get(held[REF_A].id)
            await rig.decide(held[REF_A])
            await rig.settled()
            collected = await collect(http, REF_A)
    assert passed == {"v": 1, "detached": []}
    assert detached == {"v": 1, "detached": [REF_A]}
    answered = waiting.json()
    assert (answered["code"], answered["ref"]) == ("approval_pending", REF_A)
    assert answered["deadline"].endswith("+00:00")
    assert live is not None
    assert live.detached
    assert collected["state"] == "done"
    assert "result" in collected
    assert blocking.json()["code"] == "approval_withdrawn"
    assert blocking.json()["reason"] == "gateway_stopped"  # its own text at the gateway
    assert rig.kinds(REF_B)[1:] == [("decided", "withdrawn"), ("outcome", "not_sent")]
    assert rig.kinds(REF_A)[1:] == [("decided", "accept"), ("outcome", "ok")]
    assert len(rig.upstream.posts()) == 1
    [event] = events(log, "approval_detached")
    assert (event["ref"], event["reason"]) == (REF_A, "gateway_stop")
    [gone] = events(log, "approval_withdrawn")
    assert (gone["ref"], gone["reason"]) == (REF_B, "gateway_stopped")


# --- decisions (E.2, OPS-3) -----------------------------------------------------------------------


@pytest.mark.parametrize("link", LINKS)
async def test_the_decisions_poll(tmp_path: Path, link: str) -> None:
    """E.2: the endings of the calls the gateway marked ``wait=pending``, each numbered once, as
    status and outcome (never a result), after the seq the poll names; a long poll waits for one
    and wakes at it; a blocking call's ending isn't there (its request had the answer); one poll
    waits at a time; and the vault's epoch is the same in every answer of one vault start."""
    rig = HoldRig(tmp_path, {"block_seconds": 0, "cooldown": 0}, link=link)
    async with rig.running() as http:
        with anyio.fail_after(BOUND):
            first = await poll(http)
            denied = await http.post(SHOP, content=call(), headers=pending(REF_A))
            [hold] = await rig.surface.holds(1)
            waited: list[httpx.Response] = []

            async def long_poll() -> None:
                waited.append(await poll(http, wait=25))

            async with anyio.create_task_group() as group:
                group.start_soon(long_poll)
                await until(lambda: rig.app.decision_waiters == 1, BOUND)
                second = await poll(http, wait=25)
                await rig.decide(hold, "deny")
            await rig.settled()
            ran = await http.post(SHOP, content=call(), headers=pending(REF_B))
            [_, approved] = await rig.surface.holds(2)
            await rig.decide(approved)
            await rig.settled()
            after = await poll(http, after=1)
            # A blocking call ends at its block (here at once), and its request has the answer.
            blocking = await http.post(SHOP, content=call(), headers=headers(held=marker(REF_C)))
            await rig.settled()
            last = await poll(http, after=2)
    assert first.status_code == 200
    assert first.json()["endings"] == []
    epoch = first.json()["epoch"]
    assert len(epoch) == 12
    assert denied.json()["code"] == ran.json()["code"] == "approval_pending"
    assert second.status_code == 429  # one poll waits at a time
    [woken] = waited
    assert woken.json() == {
        "v": 1,
        "epoch": epoch,
        "endings": [{"seq": 1, "ref": REF_A, "status": "denied", "outcome": "not_sent"}],
        "relays": [],
    }
    assert after.json() == {
        "v": 1,
        "epoch": epoch,
        "endings": [{"seq": 2, "ref": REF_B, "status": "done", "outcome": "ok"}],
        "relays": [],
    }
    assert blocking.json()["code"] == "approval_expired"
    assert last.json() == {"v": 1, "epoch": epoch, "endings": [], "relays": []}


@pytest.mark.parametrize("link", LINKS)
async def test_a_stopping_vault_ends_the_poll(tmp_path: Path, link: str) -> None:
    """I.2: the vault's stop answers the waiting decisions poll at once, and a new one 503
    ``stopping``, so the gateway backs off while the vault drains instead of polling again."""
    rig = HoldRig(tmp_path, link=link)
    async with rig.running() as http:
        with anyio.fail_after(BOUND):
            await poll(http)
            waited: list[httpx.Response] = []

            async def long_poll() -> None:
                waited.append(await poll(http, wait=25))

            async with anyio.create_task_group() as group:
                group.start_soon(long_poll)
                await until(lambda: rig.app.decision_waiters == 1, BOUND)
                await rig.on_vault(rig.app.stop_view_waits)
            refused = await poll(http, wait=25)
    [answered] = waited
    assert (answered.status_code, answered.json()["endings"]) == (200, [])
    assert (refused.status_code, refused.json()["code"]) == (503, "stopping")


@pytest.mark.parametrize("link", LINKS)
@pytest.mark.parametrize(
    "query",
    [
        {},
        {"epoch": "x"},
        {"epoch": EPOCH, "after": "-1"},
        {"epoch": EPOCH, "ref": REF_A},
    ],
    ids=["no-epoch", "bad-epoch", "bad-after", "other"],
)
async def test_the_decisions_poll_refuses_a_query_it_cant_read(
    tmp_path: Path, link: str, query: dict[str, str]
) -> None:
    rig = HoldRig(tmp_path, link=link)
    async with rig.running() as http:
        with anyio.fail_after(BOUND):
            response = await http.get(APPROVALS + "decisions", params=query)
            posted = await http.post(APPROVALS + "decisions", content=b"{}", headers=JSON)
    assert (response.status_code, response.json()["code"]) == (400, "invalid")
    assert (posted.status_code, posted.headers["allow"]) == (405, "GET")


@pytest.mark.parametrize("link", LINKS)
@pytest.mark.parametrize(
    ("name", "body", "status", "code"),
    [
        ("withdraw", b"{}", 400, "invalid"),
        ("withdraw", b"[", 400, "invalid"),
        ("withdraw", b"{" + b" " * 1024 + b"}", 413, "too_large"),
        ("detach", b'{"epoch":"0123456789ab","calls":[]}', 400, "invalid"),
        ("detach", b"{" + b" " * 16 * 1024 + b"}", 413, "too_large"),
    ],
    ids=[
        "withdraw-empty",
        "withdraw-not-json",
        "withdraw-too-large",
        "detach-none",
        "detach-too-large",
    ],
)
async def test_withdraw_and_detach_refuse_a_body_they_cant_read(
    tmp_path: Path, link: str, name: str, body: bytes, status: int, code: str
) -> None:
    rig = HoldRig(tmp_path, link=link)
    async with rig.running() as http:
        with anyio.fail_after(BOUND):
            response = await http.post(APPROVALS + name, content=body, headers=JSON)
            queried = await http.post(APPROVALS + name + "?x=1", content=b"{}", headers=JSON)
            typed = await http.post(
                APPROVALS + name, content=b"{}", headers={"content-type": "text/plain"}
            )
    assert (response.status_code, response.json()["code"]) == (status, code)
    assert queried.status_code == 400
    assert typed.status_code == 415


# --- the epoch rule (E.2, G-15, I.3) --------------------------------------------------------------


@pytest.mark.parametrize("link", LINKS)
async def test_a_new_gateway_epoch_withdraws_legacy_sessions_only(
    tmp_path: Path, link: str, log: io.StringIO
) -> None:
    """G-15: the first request with a new gateway epoch withdraws the earlier epoch's held calls
    that carried a legacy ``Mcp-Session-Id`` (``gateway_restarted``): nobody keeps that session
    open. A held call without one stays, collectable through the new gateway. Its endings are no
    longer the old epoch's to poll, and a late request with that epoch changes nothing."""
    rig = HoldRig(tmp_path, {"block_seconds": 0}, link=link)
    async with rig.running() as http:
        with anyio.fail_after(BOUND):
            session = pending(REF_A, **{"mcp-session-id": "s-1"})
            legacy = await http.post(SHOP, content=call(), headers=session)
            kept = await http.post(SHOP, content=call(), headers=pending(REF_B, client="agent2"))
            await rig.surface.holds(2)
            same = await poll(http)
            await poll(http, epoch=LATER)
            await rig.settled()
            withdrawn = await collect(http, REF_A, epoch=LATER)
            waiting = await collect(http, REF_B, client="agent2", epoch=LATER)
            late = await poll(http)
            await rig.settled()
            still = await collect(http, REF_B, client="agent2", epoch=LATER)
    assert legacy.json()["code"] == kept.json()["code"] == "approval_pending"
    assert same.json()["endings"] == []
    assert (withdrawn["state"], withdrawn["detail"]) == ("withdrawn", "gateway_restarted")
    assert rig.kinds(REF_A)[1:] == [("decided", "withdrawn"), ("outcome", "not_sent")]
    assert waiting["state"] == still["state"] == "pending"
    assert late.json()["endings"] == []  # REF_A's ending was the earlier epoch's
    [changed] = events(log, "gateway_epoch_changed")
    assert changed["withdrawn"] == 1


# --- the gateway's side: endings, withdraw and detach through the gateway -------------------------


@asynccontextmanager
async def own_client(rig: Vaulted) -> AsyncIterator[OutOfBandClient]:
    """An approvals client on the test's loop, as the rig's gateway's: its link, its key and its
    epoch (the gateway's own runs on the gateway's loop)."""
    http = approvals_client(parse_link(rig.deployed.vault_url), KeySource(KEYS.gateway_key(1)))
    approvals = Approvals(
        ledger=None,
        committed=Committed(),
        fresh=lambda: None,
        stopping=lambda: False,
        epoch=rig.running.app.approvals.epoch,
    )
    try:
        yield OutOfBandClient(approvals, http)
    finally:
        await http.aclose()


@pytest.mark.parametrize("ending", ["approve", "deny", "expire"])
async def test_an_ending_closes_the_pending_record(tmp_path: Path, ending: str) -> None:
    """OPS-3, D.2: the agent's call answered pending; the vault ends it with nobody collecting,
    and the gateway's decisions poller writes its records and frees the lock (a decline and an
    expiry start the cooldown). A collect afterwards still gets the result, and writes nothing
    again: the record is closed once."""
    approvers = {"portal": {}, "block_seconds": 0, "result_ttl": 1800}
    with anyio.fail_after(BOUND), holding(tmp_path, approvers=approvers) as rig:
        async with agent(rig.running.mcp(), headers=bearer()) as client:
            first = await client.call_tool("echo", {"text": "hi"})
            ref = ref_of(first)
            [hold] = await rig.surface.holds(1)
            if ending == "approve":
                await rig.decide(hold)
            elif ending == "deny":
                await rig.decide(hold, "deny")
            else:
                await rig.later(3601)
            await rig.settled()
            await until(lambda: rig.running.app.approvals.table.get(ref) is None, BOUND)
            closed = rig.ledger(ref)
            collected = await client.call_tool("check_approval", {"id": ref})
            later = await client.call_tool("echo", {"text": "again"})
            assert rig.ledger(ref) == closed
    assert PENDING.match(text(first))
    decision, outcome = {
        "approve": ("approved_elsewhere", "ok"),
        "deny": ("decline", "not_sent"),
        "expire": ("timeout", "not_sent"),
    }[ending]
    assert closed == [
        ("asked", "vault"),
        ("decided", "pending"),
        ("decided", decision),
        ("outcome", (outcome, None)),
    ]
    if ending == "approve":
        assert text(collected) == "hi"
        assert rig.calls() == [{"text": "hi"}]
        assert PENDING.match(text(later))
    else:
        assert rig.calls() == []
        assert "declined moments ago" in text(later)


@pytest.mark.parametrize("version", ["modern", "2025-11-25"])
async def test_an_abandoned_call_is_withdrawn_at_the_vault(tmp_path: Path, version: Any) -> None:
    """B.6, SC-1 (step 10's deviation 3), FM-29's gateway half: the agent abandons a blocking
    held call; the gateway records it withdrawn, ``outcome unknown`` (the vault might have
    forwarded it), and tells the vault (``withdraw caller_cancelled``), whatever the era: the
    hold ends unsent, a later approval is refused, and nothing is sent. (The era's own cancel may
    reach the vault first: either way it ends withdrawn, and the withdraw is told.)"""
    with anyio.fail_after(BOUND), holding(tmp_path) as rig:
        async with agent(rig.running.mcp(), version=version, headers=bearer()) as client:
            async with anyio.create_task_group() as group:
                group.start_soon(lambda: client.call_tool("echo", {"text": "never"}))
                [hold] = await rig.surface.holds(1)
                group.cancel_scope.cancel()
            await until(lambda: rig.running.app.approvals.table.get(hold.ref) is None, BOUND)
            vault = rig.deployed.vault
            assert vault is not None
            await until(lambda: vault.holds.get(hold.id) is None, BOUND)
            await until(lambda: told(rig), BOUND)
            await rig.settled()
            late = await rig.decide(hold)
            await rig.settled()
    assert late == DecideRefusal("withdrawn")
    assert rig.calls() == []
    assert rig.ledger(hold.ref) == [
        ("asked", "vault"),
        ("decided", "withdrawn"),
        ("outcome", ("unknown", None)),
    ]
    assert rig.chain(hold.ref)[-1] == ("outcome", "not_sent")
    assert rig.chain(hold.ref)[1][1] in ("withdrawn", "stream_lost")
    [request] = told(rig)
    assert request["status"] == 200


async def test_endings_close_the_records_once_the_approvers_are_removed(tmp_path: Path) -> None:
    """OPS-3, Z7: two calls wait pending; the change that removes the approvers (and the held
    tools) withdraws both holds, and the gateway's view names no out-of-band approver any more.
    The poller still reads their endings, so both records close ``withdrawn``, ``not_sent``, long
    before their hard deadlines would close them ``unknown``."""
    options: dict[str, Any] = {
        "approvers": {"portal": {}, "block_seconds": 0},
        "gateway_approvals": {"max_pending_per_client": 2},
    }
    with anyio.fail_after(BOUND), holding(tmp_path, **options) as rig:
        async with agent(rig.running.mcp(), headers=bearer()) as client:
            first = await client.call_tool("echo", {"text": "hi"})
            second = await client.call_tool("add", {"a": 1, "b": 2})
            await rig.surface.holds(2)
            await anyio.to_thread.run_sync(
                lambda: rig.deployed.reload(vault_approval=[], approvers=None)
            )
            await rig.settled()
            approvals = rig.running.app.approvals
            refs = [ref_of(first), ref_of(second)]
            await until(lambda: all(approvals.table.get(ref) is None for ref in refs), BOUND)

            def unapproved() -> bool:
                snapshot = approvals.fresh()
                return snapshot is not None and snapshot.view.gateway.approvals.out_of_band is None

            await until(unapproved, BOUND)
    assert PENDING.match(text(first))
    assert PENDING.match(text(second))
    for ref in refs:
        assert rig.ledger(ref) == [
            ("asked", "vault"),
            ("decided", "pending"),
            ("decided", "withdrawn"),
            ("outcome", ("not_sent", None)),
        ]
        assert rig.chain(ref)[-1] == ("outcome", "not_sent")
    assert rig.calls() == []
    assert rig.calls("add") == []


def told(rig: Vaulted) -> list[dict[str, Any]]:
    """The vault's requests on its withdraw path."""
    return [e for e in rig.deployed.events("request") if e.get("endpoint") == "approvals_withdraw"]


async def test_a_detached_wait_answers_pending_and_runs_once_approved(tmp_path: Path) -> None:
    """I.2, G-16 (step 17's stop calls it): the gateway's detach answers the agent's blocking
    call ``pending <ref>`` at once, the hold waits on, and once approved the call runs once, its
    ending closes the gateway's record, and the agent collects the result."""
    with anyio.fail_after(BOUND), holding(tmp_path) as rig:
        async with agent(rig.running.mcp(), headers=bearer()) as client:
            async with anyio.create_task_group() as group:
                answer = await call_in(group, lambda: client.call_tool("echo", {"text": "kept"}))
                [hold] = await rig.surface.holds(1)
                async with own_client(rig) as vault:
                    detached = await vault.detach([(hold.ref, CLIENTS[0])])
            [result] = answer
            await rig.decide(hold)
            await rig.settled()
            await until(lambda: rig.running.app.approvals.table.get(hold.ref) is None, BOUND)
            collected = await client.call_tool("check_approval", {"id": hold.ref})
    assert detached == {hold.ref}
    assert PENDING.match(text(result))
    assert ref_of(result) == hold.ref
    assert text(collected) == "kept"
    assert rig.calls() == [{"text": "kept"}]
    assert rig.ledger(hold.ref) == [
        ("asked", "vault"),
        ("decided", "pending"),
        ("decided", "approved_elsewhere"),
        ("outcome", ("ok", None)),
    ]


async def test_the_gateways_stop_detaches_its_blocking_held_calls(tmp_path: Path) -> None:
    """I.2 step 1, Q40 (M8 step 17; FM-27 in one process, ``test_held_crash.py`` across
    processes): the stop signal names every Elsewhere call still blocking at the vault in one
    detach, so the agent's call answers ``pending <ref>`` before its session closes, and the
    hold goes on there: approved, it runs once and its ending closes the gateway's record."""
    with anyio.fail_after(BOUND), holding(tmp_path) as rig:
        async with agent(rig.running.mcp(), headers=bearer()) as client:
            async with anyio.create_task_group() as group:
                answer = await call_in(group, lambda: client.call_tool("echo", {"text": "kept"}))
                [hold] = await rig.surface.holds(1)
                app = rig.running.app
                await rig.running.request_stop()  # on the gateway's loop, as the signal's is
            [result] = answer
            await rig.decide(hold)
            await rig.settled()
            await until(lambda: app.approvals.table.get(hold.ref) is None, BOUND)
            [event] = rig.deployed.events("approvals_detached")
    assert PENDING.match(text(result))
    assert ref_of(result) == hold.ref
    assert rig.calls() == [{"text": "kept"}]
    assert rig.ledger(hold.ref) == [
        ("asked", "vault"),
        ("decided", "pending"),
        ("decided", "approved_elsewhere"),
        ("outcome", ("ok", None)),
    ]
    assert (event["asked"], event["detached"]) == (1, 1)


def test_the_stops_detach_ends_well_inside_the_requests_grace() -> None:
    """I.2 step 1, Q40: uvicorn cancels the requests in flight when its grace ends, so the stop's
    detach is bounded well inside it, and the vault's ``pending`` answers still reach the
    agents."""
    assert STOP_DETACH_WAIT <= server.STOP_GRACE / 2


async def test_attended_reaches_held_tool(tmp_path: Path) -> None:
    """Z11, G-18: agent1 is attended and not out of band. Its call to the held ``echo`` is
    asked on the vault's surface, never on its own session, and runs once approved there; its
    call to ``add``, an approve tool the vault doesn't hold, is elicited as before. agent2,
    whom nobody answers for, is refused before anything is held or sent."""
    script = Script([ACCEPT])
    options: dict[str, Any] = {"approve": ["echo", "add"], "vault_approval": ["echo"]}
    with anyio.fail_after(BOUND), holding(tmp_path, **options) as rig:
        async with agent(rig.running.mcp(), script=script, headers=bearer()) as client:
            async with anyio.create_task_group() as group:
                held = await call_in(group, lambda: client.call_tool("echo", {"text": "held"}))
                [hold] = await rig.surface.holds(1)
                assert script.prompts == []
                await rig.decide(hold)
            asked = await client.call_tool("add", {"a": 1, "b": 2})
        async with agent(rig.running.mcp(), headers=bearer(CLIENTS[1])) as other:
            refused = await other.call_tool("echo", {"text": "nobody"})
        await rig.settled()
    [result] = held
    assert not result.is_error
    assert "held" in text(result)
    assert hold.client == CLIENTS[0]
    assert not asked.is_error
    assert text(asked) == "3"
    assert len(script.prompts) == 1  # add's, on the agent's own session
    assert [shown.tool for shown in rig.surface.shown] == ["echo"]
    assert text(refused) == f"{NO_OUT_OF_BAND} (ref {ref_of(refused)})"
    assert rig.calls() == [{"text": "held"}]
    assert rig.calls("add") == [{"a": 1, "b": 2}]
    assert rig.ledger(hold.ref)[0] == ("asked", "vault")
    assert rig.ledger(ref_of(refused)) == []  # refused before anything was recorded


# --- the poller's reading, in process -------------------------------------------------------------


def test_a_poll_answer_is_read_exactly() -> None:
    """The decisions answer's shape (E.2): the vault's epoch, each ending and each relay decision
    exactly; an outcome the ledger doesn't know reads ``unknown``."""
    ending = {"seq": 3, "ref": REF_A, "status": "done", "outcome": "ok"}
    odd = {**ending, "seq": 4, "outcome": "exploded"}
    relay = {
        "seq": 5,
        "ref": REF_B,
        "decision": "accept",
        "via": "portal",
        "decided_ms": 0,
        "text_sha256": "e" * 64,
    }
    assert endings({"v": 1, "epoch": EPOCH, "endings": [ending, odd], "relays": [relay]}) == (
        EPOCH,
        [Ending(3, REF_A, "done", "ok"), Ending(4, REF_A, "done", "unknown")],
        [Relayed(5, REF_B, "accept", "portal", 0, "e" * 64)],
    )
    for decision in ("decline", "timeout", "withdrawn"):
        for via in ("telegram", "host", "none"):
            found = endings(
                {
                    "v": 1,
                    "epoch": EPOCH,
                    "endings": [],
                    "relays": [{**relay, "decision": decision, "via": via}],
                }
            )
            assert found[2] == [Relayed(5, REF_B, decision, via, 0, "e" * 64)]
    answer = {"v": 1, "epoch": EPOCH, "endings": [], "relays": []}
    bad: list[dict[str, Any]] = [
        {"v": 1, "epoch": EPOCH},
        {"v": 1, "epoch": EPOCH, "endings": []},  # an answer from before step 12b
        {"v": 1, "epoch": EPOCH, "endings": [], "decisions": []},
        {**answer, "decisions": []},
        {**answer, "epoch": "X"},
        {**answer, "endings": {}},
        {**answer, "relays": {}},
        {**answer, "endings": [{**ending, "extra": 1}]},
        {**answer, "endings": [{**ending, "seq": 0}]},
        {**answer, "endings": [{**ending, "seq": True}]},
        {**answer, "endings": [{**ending, "ref": "x"}]},
        {**answer, "endings": [{**ending, "status": 1}]},
        {**answer, "endings": [{**ending, "outcome": None}]},
        {**answer, "endings": [relay]},
        {**answer, "relays": [ending]},
        {**answer, "relays": [{**relay, "extra": 1}]},
        {**answer, "relays": [{**relay, "seq": 0}]},
        {**answer, "relays": [{**relay, "ref": "x"}]},
        {**answer, "relays": [{**relay, "decision": "approve"}]},
        {**answer, "relays": [{**relay, "decision": None}]},
        {**answer, "relays": [{**relay, "via": "mail"}]},
        {**answer, "relays": [{**relay, "decided_ms": -1}]},
        {**answer, "relays": [{**relay, "decided_ms": True}]},
        {**answer, "relays": [{**relay, "decided_ms": "0"}]},
        {**answer, "relays": [{**relay, "text_sha256": "E" * 64}]},
        {**answer, "relays": [{**relay, "text_sha256": "e" * 63}]},
        {**answer, "relays": [{**relay, "text_sha256": None}]},
    ]
    for value in bad:
        with pytest.raises(ApprovalsFailed):
            endings(value)


class Polled:
    """The decisions path as a mock transport: records each query, answers the next of
    ``answers`` (the vault's epoch and its endings), and once they ran out, the last epoch with
    no endings."""

    def __init__(self, *answers: tuple[str, list[dict[str, Any]]]) -> None:
        self.answers = list(answers)
        self.queries: list[dict[str, str]] = []
        self.epoch = EPOCH

    def handle(self, request: httpx2.Request) -> httpx2.Response:
        assert (request.method, request.url.path) == ("GET", APPROVALS + "decisions")
        self.queries.append(dict(request.url.params))
        epoch, listed = self.answers.pop(0) if self.answers else (self.epoch, [])
        self.epoch = epoch
        relays = [item for item in listed if "decision" in item]
        ended = [item for item in listed if "decision" not in item]
        return httpx2.Response(
            200, json={"v": 1, "epoch": epoch, "endings": ended, "relays": relays}
        )


def ended(seq: int, ref: str = "0123456789abcdef", status: str = "done") -> dict[str, Any]:
    return {"seq": seq, "ref": ref, "status": status, "outcome": "ok"}


async def test_a_restarted_vault_is_polled_from_the_start() -> None:
    """E.2: each poll names the gateway's epoch and the last seq it read; a vault with a new
    epoch numbers its endings from 1 again, so the poller starts over, and reads them then."""
    vault = Polled(
        ("aaaaaaaaaaaa", [ended(4), ended(5, REF_A)]),
        ("bbbbbbbbbbbb", [ended(1)]),
        ("bbbbbbbbbbbb", [ended(1)]),
    )
    approvals = Approvals(
        ledger=None, committed=Committed(), fresh=lambda: None, stopping=lambda: False
    )
    http = approvals_client(LINK, None, httpx2.MockTransport(vault.handle))
    poller = OutOfBandClient(approvals, http)
    with anyio.fail_after(BOUND):
        first = await poller.poll_once(25)
        after_first = poller.after
        restarted = await poller.poll_once(25)
        after_restart = poller.after
        again = await poller.poll_once(1)
    await http.aclose()
    assert [ending.seq for ending in first] == [4, 5]
    assert after_first == 5
    assert (restarted, after_restart) == ([], 0)
    assert [ending.seq for ending in again] == [1]
    assert poller.after == 1
    assert poller.vault_epoch == "bbbbbbbbbbbb"
    epoch = approvals.epoch
    assert vault.queries == [
        {"epoch": epoch, "after": "0", "wait": "25"},
        {"epoch": epoch, "after": "5", "wait": "25"},
        {"epoch": epoch, "after": "0", "wait": "1"},
    ]


async def test_an_ending_waits_for_its_pending_answer_and_closes_once(tmp_path: Path) -> None:
    """D.2: an ending that comes while its call's record hasn't had the vault's pending answer
    yet is kept for the next round; once the record waits pending, the ending writes its records
    and frees the lock, once: the same ending again, or a collect's, writes nothing more."""
    held = await in_process(tmp_path)
    ending = Ending(1, held.call.ref, "denied", "not_sent")
    async with httpx2.AsyncClient() as unused:  # an ending needs no request
        poller = OutOfBandClient(held.approvals, unused)
        with anyio.fail_after(BOUND):
            await poller.apply([ending], 15.0)
            early = list(poller.deferred)
            before = held.records()
            await pend(held)
            await poller.apply(list(poller.deferred.values()), 15.0)
            closed = held.records()
            await poller.apply([ending], 15.0)
            await elsewhere.collected(
                held.approvals, held.call.ref, "decline", "not_sent", None, 15
            )
    assert early == [held.call.ref]
    assert before == [("asked", None)]
    assert closed == [
        ("asked", None),
        ("decided", "pending"),
        ("decided", "decline"),
        ("outcome", "not_sent"),
    ]
    assert held.records() == closed
    assert held.approvals.table.get(held.call.ref) is None
    assert poller.deferred == {}


async def test_an_ending_that_isnt_one_leaves_the_record_waiting(tmp_path: Path) -> None:
    held = await in_process(tmp_path)
    await pend(held)
    async with httpx2.AsyncClient() as unused:
        poller = OutOfBandClient(held.approvals, unused)
        with anyio.fail_after(BOUND):
            await poller.apply([Ending(1, held.call.ref, "pending", "unknown")], 15.0)
            await poller.apply([Ending(2, "fedcba9876543210", "done", "ok")], 15.0)
    assert held.approvals.table.get(held.call.ref) is not None
    assert held.records()[-1] == ("decided", "pending")
    assert poller.deferred == {}


async def test_endings_are_polled_while_a_held_call_waits_with_no_approver(tmp_path: Path) -> None:
    """OPS-3, Z7, in process: the view names no out-of-band approver (the change that removed
    them withdrew every hold), but a held call of this gateway still waits pending, so the poller
    polls on: its ending closes the record ``withdrawn``, ``not_sent``. Only then, with nothing
    held, does it idle."""
    held = await in_process(tmp_path)
    await pend(held)
    document = json.loads(json.dumps(VIEW_POLICY))
    del document["approvers"]
    del document["gateway"]["servers"]["notes"]["tools"]["vault_approval"]
    snapshot = Snapshot(build_view(Policy.model_validate(document)), 0.0)
    held.approvals.fresh = lambda: snapshot
    vault = Polled((EPOCH, [ended(1, held.call.ref, "withdrawn")]))
    idled: list[bool] = []

    async def sleep(seconds: float) -> None:
        if seconds == IDLE_WAIT:
            idled.append(held.approvals.table.get(held.call.ref) is not None)
        await anyio.sleep(0.01)

    http = approvals_client(LINK, None, httpx2.MockTransport(vault.handle))
    poller = OutOfBandClient(held.approvals, http, sleep=sleep)
    with anyio.fail_after(BOUND):
        async with anyio.create_task_group() as group:
            group.start_soon(poller.run)
            await until(lambda: held.approvals.table.get(held.call.ref) is None, BOUND)
            await until(lambda: idled, BOUND)
            group.cancel_scope.cancel()
    await http.aclose()
    assert snapshot.view.gateway.approvals.out_of_band is None
    assert held.records() == [
        ("asked", None),
        ("decided", "pending"),
        ("decided", "withdrawn"),
        ("outcome", "not_sent"),
    ]
    assert vault.queries[0]["after"] == "0"
    assert not any(idled)  # never idle while the call waited


async def test_a_closed_records_result_is_checked_against_its_own_pin(tmp_path: Path) -> None:
    """Z17, F.5 step 6: the poller closed the record of a call the vault ran before the agent
    collected it, and the tool was re-pinned since. The result is still checked against the pin
    the call was made under, and delivered; another client still reads the ref as unknown, with
    the vault not asked (F.5 step 1)."""
    held = await in_process(tmp_path)
    await pend(held)
    ref = held.call.ref
    vault = Vault(done(result_body({"said": "hi"})))
    repinned = json.loads(json.dumps(VIEW_POLICY))
    repinned["gateway"]["servers"]["notes"]["review"]["echo"] = "sha256:" + "3" * 64
    now = build_view(Policy.model_validate(repinned)).gateway
    server = now.servers["notes"]
    async with httpx2.AsyncClient() as unused:
        poller = OutOfBandClient(held.approvals, unused)
        with anyio.fail_after(BOUND):
            await poller.apply([Ending(1, ref, "done", "ok")], 15.0)
            closed = held.approvals.table.get(ref)
            checks = await checker(held, vault)
            other = await checks.check(
                pipeline.Call("agent2", "notes", server, now.limits, "modern"), now, {"id": ref}
            )
            found = await checks.check(
                pipeline.Call("agent1", "notes", server, now.limits, "modern"), now, {"id": ref}
            )
    assert closed is None
    assert server.review["echo"] != held.call.pin
    assert not found.is_error, text(found)
    assert found.structured_content == {"said": "hi"}
    assert text(other) == f"{checkapproval.UNKNOWN} (ref {ref})"
    assert len(vault.bodies) == 1  # agent1's collect only
    assert held.records() == [
        ("asked", None),
        ("decided", "pending"),
        ("decided", "approved_elsewhere"),
        ("outcome", "ok"),
    ]


async def test_a_closed_calls_pin_is_kept_while_its_result_may_be(tmp_path: Path) -> None:
    """Z17: a closed call's pin is kept while the vault may keep its result (with no view, the
    longest ``result_ttl`` the policy allows, and the hard deadline's margin), and for the last
    1,024 calls only."""
    held = await in_process(tmp_path)
    now = [100.0]
    approvals = Approvals(
        ledger=None,
        committed=Committed(),
        fresh=lambda: None,
        stopping=lambda: False,
        clock=lambda: now[0],
    )
    approvals.keep_ran(held.record)
    kept = approvals.ran_call(held.call.ref)
    now[0] += RESULT_TTL_MAX + 29
    still = approvals.ran_call(held.call.ref)
    now[0] += 1
    gone = approvals.ran_call(held.call.ref)
    refs = [f"{n:016x}" for n in range(MAX_RECORDS + 1)]
    for ref in refs:
        approvals.keep_ran(replace(held.record, ref=ref))
    assert kept is not None
    assert (kept.key, kept.pin) == (held.record.key, held.call.pin)
    assert still == kept
    assert gone is None
    assert len(approvals.ran) == MAX_RECORDS
    assert approvals.ran_call(refs[0]) is None
    assert approvals.ran_call(refs[-1]) is not None


async def test_a_vault_slow_to_hear_a_withdraw_leaves_nothing_held(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """B.6, R44: the agent abandons a blocking held call and the vault never answers the
    withdraw. Telling it gets its own part of the grace (``approval_withdraw_failed``,
    ``timeout``), so the gateway's ``decided withdrawn`` and ``outcome unknown`` are still
    written and the lock freed."""
    monkeypatch.setattr(elsewhere, "FINISH_GRACE", 0.5)
    held = await in_process(tmp_path)
    held.approvals.table.finish(held.record.key, held.call.ref, 0.0, settings_cooldown=0.0)
    forwarded = anyio.Event()
    asked: list[tuple[str, str, str]] = []

    async def forward(marked: Any, grant: Any) -> CallToolResult:
        forwarded.set()
        await anyio.sleep_forever()
        raise AssertionError("never answered")

    async def unanswered(ref: str, client: str, reason: str) -> None:
        asked.append((ref, client, reason))
        await anyio.sleep_forever()

    held.approvals.tell_withdrawn = unanswered
    call = replace(held.call, ref="00000000000000ab", forward=forward, wait="block")
    captured = io.StringIO()
    gateway_logs.set_stream(captured)
    try:
        with anyio.fail_after(BOUND):
            async with anyio.create_task_group() as group:
                group.start_soon(elsewhere.run, held.approvals, call)
                await forwarded.wait()
                group.cancel_scope.cancel()
    finally:
        gateway_logs.set_stream(None)
    assert asked == [(call.ref, "agent1", "caller_cancelled")]
    assert replace(held, call=call).records() == [
        ("asked", None),
        ("decided", "withdrawn"),
        ("outcome", "unknown"),
    ]
    assert held.approvals.table.get(call.ref) is None
    [failed] = events(captured, "approval_withdraw_failed")
    assert (failed["ref"], failed["error_type"]) == (call.ref, "timeout")


async def test_a_call_the_gateways_stop_cuts_is_recorded_shutdown(tmp_path: Path) -> None:
    """I.2 step 4 (M8 step 17): a held call whose answer hadn't come when the gateway's stop cut
    it is told withdrawn at the vault as any abandoned call is, and recorded ``decided
    shutdown``, ``outcome unknown, detail shutdown``: the vault's chain has how it ended."""
    held = await in_process(tmp_path)
    held.approvals.table.finish(held.record.key, held.call.ref, 0.0, settings_cooldown=0.0)
    forwarded = anyio.Event()
    stopping = [False]
    told: list[tuple[str, str, str]] = []

    async def forward(marked: Any, grant: Any) -> CallToolResult:
        forwarded.set()
        await anyio.sleep_forever()
        raise AssertionError("never answered")

    async def tell(ref: str, client: str, reason: str) -> None:
        told.append((ref, client, reason))

    held.approvals.tell_withdrawn = tell
    held.approvals.stopping = lambda: stopping[0]
    call = replace(held.call, ref="00000000000000ac", forward=forward)
    with anyio.fail_after(BOUND):
        async with anyio.create_task_group() as group:
            group.start_soon(elsewhere.run, held.approvals, call)
            await forwarded.wait()
            stopping[0] = True  # the stop signal came; its grace ran out
            group.cancel_scope.cancel()
    assert told == [(call.ref, "agent1", "caller_cancelled")]
    records = [
        ledgerformat.parse(line)
        for path in sorted((tmp_path / LEDGER_DIR).glob("*.jsonl"))
        for line in path.read_bytes().splitlines()
    ]
    assert [
        (r.kind, r.fields.get("decision"), r.fields.get("outcome"), r.fields.get("detail"))
        for r in records
        if r.ref == call.ref
    ] == [
        ("asked", None, None, None),
        ("decided", "shutdown", None, None),
        ("outcome", None, "unknown", "shutdown"),
    ]
    assert held.approvals.table.get(call.ref) is None


# --- the ask, the vault's side (M8 step 12b; E.2, E.5) --------------------------------------------

RELAYING = {"out_of_band": True}  # both of the rig's clients may raise out-of-band prompts


def gateway_text(ref: str, tool: str = "cancel_order", client: str = "agent1") -> str:
    """A prompt as the gateway renders one it holds itself and relays (E.4): its own frame,
    the out-of-band instruction."""
    asked = datetime.now(UTC)
    header = Header(
        ref,
        client,
        "shop",
        tool,
        datetime.fromtimestamp(asked.timestamp() + 3600, UTC),
        asked_at=asked,
        rendered_by="gateway",
        client_reported=False,
        pin=None,
        approver="out_of_band",
    )
    return render_call(header, {"order": "A-1", "nested": {"a": {"b": [1, 2]}}}).value


async def ask(
    http: httpx.AsyncClient,
    ref: str,
    *,
    client: str = "agent1",
    tool: str = "cancel_order",
    server: str = "shop",
    text: str | None = None,
    epoch: str = EPOCH,
) -> httpx.Response:
    said = gateway_text(ref, tool, client) if text is None else text
    body = {
        "v": 1,
        "epoch": epoch,
        "ref": ref,
        "client": client,
        "server": server,
        "tool": tool,
        "text": said,
        "text_sha256": hashlib.sha256(said.encode()).hexdigest(),
        "deadline_ms": int(time.time() * 1000) + 3_600_000,
        "wait": "pending",
    }
    return await http.post(APPROVALS + "ask", content=canonical.dumps_canonical(body), headers=JSON)


@pytest.mark.parametrize("link", LINKS)
async def test_the_ask_relays_the_gateways_text(
    tmp_path: Path, link: str, log: io.StringIO
) -> None:
    """E.2, J6's vault half: the vault holds the gateway's prompt as a relay, shows it with its
    own relay line above the gateway's text, and answers its id and the digest of the whole
    composed text, which the surface decides on. Approved, its chain says ``accept`` with the
    surface, then ``outcome unknown, relayed``: the vault sends nothing, and the gateway's
    decisions poll gets the decision with that digest."""
    rig = HoldRig(tmp_path, RELAYING, link=link)
    said = gateway_text(REF_A)  # once: its deadline line names the minute it was rendered in
    async with rig.running() as http:
        with anyio.fail_after(BOUND):
            asked = await ask(http, REF_A, text=said)
            [hold] = await rig.surface.holds(1)
            await rig.decide(hold)
            await rig.settled()
            polled = await poll(http)
    answer = asked.json()
    assert asked.status_code == 201
    assert asked.headers["cache-control"] == "no-store"
    assert answer == {"v": 1, "id": hold.id, "text_sha256": hold.text_sha256}
    assert (hold.kind, hold.ref, hold.client, hold.server, hold.tool, hold.wait) == (
        "relay",
        REF_A,
        "agent1",
        "shop",
        "cancel_order",
        "pending",
    )
    assert hold.route == RELAY_ROUTE + "shop"
    assert hold.text.value == f"{RELAY_LINE}\n{said}"
    assert hold.text_sha256 == hashlib.sha256(hold.text.value.encode()).hexdigest()
    [record] = [r for r in rig.records() if r.ref == REF_A and r.kind == "asked"]
    assert (record.fields["where"], record.fields["pin"], record.fields["writes"]) == (
        "gateway",
        NO_PIN,
        0,
    )
    assert rig.kinds(REF_A) == [("asked", None), ("decided", "accept"), ("outcome", "unknown")]
    [outcome] = [r for r in rig.records() if r.ref == REF_A and r.kind == "outcome"]
    assert outcome.fields["detail"] == "relayed"
    [relayed] = polled.json()["relays"]
    assert relayed == {
        "seq": 1,
        "ref": REF_A,
        "decision": "accept",
        "via": "portal",
        "decided_ms": relayed["decided_ms"],
        "text_sha256": hold.text_sha256,
    }
    assert polled.json()["endings"] == []
    assert rig.upstream.received == []
    assert rig.surface.closed == [(hold.id, "done")]
    assert rig.surface.ended[0].detail == "relayed"
    [event] = events(log, "approval_relayed")
    assert (event["ref"], event["tool"], event["surfaces"], event["wait"]) == (
        REF_A,
        "cancel_order",
        ["portal"],
        "pending",
    )


@pytest.mark.parametrize("link", LINKS)
async def test_relay_line_is_the_vaults(tmp_path: Path, link: str) -> None:
    """Z12, E.5: the vault composes the relay line, and the digest every surface binds covers
    it: a decision on the gateway's text alone is refused. A text that writes the line itself,
    first or inside (indented too), is refused ``text_refused`` before anyone is asked or
    anything recorded; so is one that breaks a text rule."""
    rig = HoldRig(tmp_path, RELAYING, link=link)
    async with rig.running() as http:
        with anyio.fail_after(BOUND):
            said = gateway_text(REF_A)  # once, as the test above
            await ask(http, REF_A, text=said)
            [hold] = await rig.surface.holds(1)
            bare = hashlib.sha256(said.encode()).hexdigest()
            refused = await rig.decide(hold, digest=bare)
            forged = [
                await ask(http, REF_B, text=f"{RELAY_LINE}\n{gateway_text(REF_B)}"),
                await ask(http, REF_B, text=f"{gateway_text(REF_B)}\n  {RELAY_LINE}"),
                await ask(http, REF_B, text="Approval request x\nhidden" + "\u200b" + "text"),
            ]
            await rig.settled()
    assert hold.text.value.split("\n")[0] == RELAY_LINE
    assert refused == DecideRefusal("digest_changed")
    for response in forged:
        assert (response.status_code, response.json()["code"]) == (422, "text_refused")
    assert len(rig.surface.shown) == 1
    assert rig.kinds(REF_B) == []


@pytest.mark.parametrize("link", LINKS)
async def test_an_ask_the_vault_wont_relay_is_refused(tmp_path: Path, link: str) -> None:
    """E.2: a digest that isn't the text's, or a body it can't read, is 400 ``invalid``; a ref
    is used once (E19); and a call the vault's own policy doesn't have the gateway hold for an
    ``out_of_band`` client is ``view_stale`` (a vault-held tool, a client that isn't
    ``out_of_band``, a server it isn't assigned), as is an ask from an earlier gateway epoch,
    whose decision no poll would get; nothing is asked or recorded for any."""
    rig = HoldRig(tmp_path, {"out_of_band": True}, link=link)
    async with rig.running() as http:
        with anyio.fail_after(BOUND):
            said = gateway_text(REF_A)
            body = {
                "v": 1,
                "epoch": EPOCH,
                "ref": REF_A,
                "client": "agent1",
                "server": "shop",
                "tool": "cancel_order",
                "text": said,
                "text_sha256": "0" * 64,
                "deadline_ms": 1,
                "wait": "pending",
            }
            wrong = await http.post(
                APPROVALS + "ask", content=canonical.dumps_canonical(body), headers=JSON
            )
            large = await http.post(
                APPROVALS + "ask", content=b"{" + b" " * 96 * 1024 + b"}", headers=JSON
            )
            first = await ask(http, REF_A)
            again = await ask(http, REF_A)
            held = await ask(http, REF_B, tool="place_order")
            unknown = await ask(http, REF_B, server="nowhere")
            unlisted = await ask(http, REF_B, tool="refund")
            await poll(http, epoch=LATER)  # a restarted gateway: EPOCH is an earlier one now
            earlier = await ask(http, REF_D)
            await rig.reload(out_of_band=False)
            unrelayed = await ask(http, REF_C, epoch=LATER)
            await rig.settled()
    assert (wrong.status_code, wrong.json()["code"]) == (400, "invalid")
    assert (large.status_code, large.json()["code"]) == (413, "too_large")
    assert first.status_code == 201
    assert (again.status_code, again.json()["code"]) == (409, "held_ref_reused")
    for refused in (held, unknown, unlisted, earlier, unrelayed):
        assert (refused.status_code, refused.json()["code"]) == (409, "view_stale")
    assert len(rig.surface.shown) == 1
    assert rig.kinds(REF_B) == rig.kinds(REF_C) == rig.kinds(REF_D) == []


@pytest.mark.parametrize("link", LINKS)
@pytest.mark.parametrize("ending", ["deny", "expire", "withdraw", "out_of_band", "epoch"])
async def test_each_relay_ending_is_told_to_its_gateway(
    tmp_path: Path, link: str, ending: str
) -> None:
    """E.2, Z7: a relay denied, expired, withdrawn by its gateway, or left by a change that takes
    its client's ``out_of_band``, is closed on the chain, unsent, and its decision goes to the
    gateway that asked it; a new gateway epoch withdraws the earlier epoch's relays (G-15),
    which no gateway is left to forward, and the new one's poll doesn't name them."""
    rig = HoldRig(tmp_path, RELAYING, link=link)
    async with rig.running() as http:
        with anyio.fail_after(BOUND):
            await ask(http, REF_A)
            [hold] = await rig.surface.holds(1)
            if ending == "deny":
                await rig.decide(hold, "deny")
            elif ending == "expire":
                await rig.later(3601)
            elif ending == "withdraw":
                assert (await withdraw(http, REF_A))["state"] == "withdrawn"
            elif ending == "out_of_band":
                await rig.reload(out_of_band=False)
            else:
                await poll(http, epoch=LATER)
            await rig.settled()
            polled = await poll(http, epoch=LATER if ending == "epoch" else EPOCH)
    decision, state = {
        "deny": ("decline", "denied"),
        "expire": ("timeout", "expired"),
    }.get(ending, ("withdrawn", "withdrawn"))
    assert rig.kinds(REF_A)[1:] == [("decided", decision), ("outcome", "not_sent")]
    assert rig.surface.closed == [(hold.id, state)]
    assert rig.upstream.received == []
    if ending == "epoch":
        assert polled.json()["relays"] == []
        assert rig.surface.ended[0].detail == "gateway_restarted"
        return
    [relayed] = polled.json()["relays"]
    assert (relayed["ref"], relayed["decision"], relayed["text_sha256"]) == (
        REF_A,
        decision,
        hold.text_sha256,
    )
    assert relayed["via"] == ("portal" if ending == "deny" else "none")


# --- the relay, end to end through the gateway (J6; Z11, Z12, FM-28) ------------------------------

# agent1 raises out-of-band prompts and nobody watches its session; nothing is vault-held.
OUT_OF_BAND: dict[str, Any] = {
    "vault_approval": [],
    "approvals": {CLIENTS[0]: {"attended": False, "out_of_band": True}},
}


@pytest.mark.parametrize("version", ["modern", "2025-11-25"])
async def test_relay_end_to_end(tmp_path: Path, version: Any) -> None:
    """J6: an ``out_of_band`` client's call to an ordinary ``approve`` tool is shown on the
    operator's surface, the vault's line above the gateway's own prompt (its client, the
    out-of-band instruction), never on the agent's session; approved there, the gateway runs it
    once and the agent gets the result. The gateway's ledger has the call as one it asked
    itself (``where: gateway``), the vault's chain the decision and ``outcome unknown``."""
    script = Script([ACCEPT])
    with anyio.fail_after(BOUND), holding(tmp_path, **OUT_OF_BAND) as rig:
        async with agent(
            rig.running.mcp(), version=version, script=script, headers=bearer()
        ) as client:
            async with anyio.create_task_group() as group:
                answer = await call_in(group, lambda: client.call_tool("echo", {"text": "relayed"}))
                [hold] = await rig.surface.holds(1)
                assert rig.calls() == []  # nothing upstream until it is approved
                await rig.decide(hold)
            await rig.settled()
    [result] = answer
    assert not result.is_error, text(result)
    assert "relayed" in text(result)
    assert script.prompts == []  # asked out of band only
    lines = hold.text.value.split("\n")
    assert lines[0] == RELAY_LINE
    assert lines[1:3] == [f"Approval request {hold.ref}", f"Client: {CLIENTS[0]}"]
    assert lines[4].endswith("UTC. Approve runs this one call, exactly as shown.")
    assert (hold.kind, hold.client, hold.tool) == ("relay", CLIENTS[0], "echo")
    assert rig.calls() == [{"text": "relayed"}]
    assert rig.ledger(hold.ref) == [
        ("asked", "gateway"),
        ("decided", "accept"),
        ("outcome", ("ok", None)),
    ]
    assert rig.chain(hold.ref) == [("asked", None), ("decided", "accept"), ("outcome", "unknown")]


async def test_nobody_answers_is_refused(tmp_path: Path) -> None:
    """Z11: with no out-of-band approver, an ``out_of_band`` client's call to a gateway-held
    tool is refused ``no_approver``; a client neither ``attended`` nor ``out_of_band`` is
    refused as before. Nothing is recorded, asked or sent for either."""
    with anyio.fail_after(BOUND), holding(tmp_path, approvers=None, **OUT_OF_BAND) as rig:
        async with agent(rig.running.mcp(), headers=bearer()) as client:
            relayed = await client.call_tool("echo", {"text": "nobody"})
        async with agent(rig.running.mcp(), headers=bearer(CLIENTS[1])) as other:
            unattended = await other.call_tool("echo", {"text": "nobody"})
    assert text(relayed) == f"{NO_APPROVER} (ref {ref_of(relayed)})"
    assert text(unattended) == f"{NO_APPROVALS} (ref {ref_of(unattended)})"
    assert rig.ledger(ref_of(relayed)) == rig.ledger(ref_of(unattended)) == []
    assert rig.surface.shown == []
    assert rig.calls() == []


async def test_digest_mismatch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """FM-28, G-23: an approval whose digest isn't the one the vault answered the ask with (a
    decision on another text) is refused, logged ``relay_digest_mismatch`` and recorded
    ``decided error``; nothing is forwarded."""
    wire = internal.Relayed.wire

    def forged(relayed: internal.Relayed) -> dict[str, Any]:
        return {**wire(relayed), "text_sha256": "0" * 64}

    monkeypatch.setattr(internal.Relayed, "wire", forged)
    with anyio.fail_after(BOUND), holding(tmp_path, **OUT_OF_BAND) as rig:
        async with agent(rig.running.mcp(), headers=bearer()) as client:
            async with anyio.create_task_group() as group:
                answer = await call_in(group, lambda: client.call_tool("echo", {"text": "hi"}))
                [hold] = await rig.surface.holds(1)
                await rig.decide(hold)
            await rig.settled()
    [result] = answer
    assert text(result) == f"{RELAY_MISMATCH} (ref {hold.ref})"
    assert rig.calls() == []
    assert rig.ledger(hold.ref) == [
        ("asked", "gateway"),
        ("decided", "error"),
        ("outcome", ("not_sent", None)),
    ]
    [mismatch] = rig.deployed.events("relay_digest_mismatch")
    assert (mismatch["ref"], mismatch["tool"], mismatch["level"]) == (hold.ref, "echo", "error")


async def test_a_pending_relay_runs_once_approved_and_is_collected(tmp_path: Path) -> None:
    """F.1, F.2, D.2 for a relay: past its block the call answers ``pending <ref>``, and an
    identical call the same ref; approved later, with nobody waiting, the gateway runs it once
    and keeps the result in its own store, which ``check_approval`` gives once (the vault holds
    no result of a relay), and lists."""
    approvers = {"portal": {}, "block_seconds": 0, "result_ttl": 1800}
    with anyio.fail_after(BOUND), holding(tmp_path, approvers=approvers, **OUT_OF_BAND) as rig:
        async with agent(rig.running.mcp(), headers=bearer()) as client:
            first = await client.call_tool("echo", {"text": "later"})
            ref = ref_of(first)
            again = await client.call_tool("echo", {"text": "later"})
            waiting = await client.call_tool("check_approval", {"id": ref})
            [hold] = await rig.surface.holds(1)
            await rig.decide(hold)
            await rig.settled()
            await until(lambda: rig.running.app.approvals.table.get(ref) is None, BOUND)
            collected = await client.call_tool("check_approval", {"id": ref})
            twice = await client.call_tool("check_approval", {"id": ref})
            listed = await client.call_tool("check_approval", {})
    assert PENDING.match(text(first))
    assert text(again) == text(first)
    assert text(waiting).startswith("still pending: waiting for the operator's approval until ")
    assert not collected.is_error, text(collected)
    assert text(collected) == "later"
    assert text(twice) == f"{checkapproval.COLLECTED} (ref {ref})"
    assert f"{ref} (echo): collected" in text(listed)
    assert len(rig.surface.shown) == 1
    assert rig.calls() == [{"text": "later"}]
    assert rig.ledger(ref) == [
        ("asked", "gateway"),
        ("decided", "pending"),
        ("decided", "accept"),
        ("outcome", ("ok", None)),
    ]
    assert rig.chain(ref) == [("asked", None), ("decided", "accept"), ("outcome", "unknown")]


async def test_a_pending_relay_declined_says_so(tmp_path: Path) -> None:
    """A pending relay the operator declines closes its record ``decline`` (its cooldown
    started), sends nothing, and ``check_approval`` says it was declined."""
    approvers = {"portal": {}, "block_seconds": 0}
    with anyio.fail_after(BOUND), holding(tmp_path, approvers=approvers, **OUT_OF_BAND) as rig:
        async with agent(rig.running.mcp(), headers=bearer()) as client:
            ref = ref_of(await client.call_tool("echo", {"text": "no"}))
            [hold] = await rig.surface.holds(1)
            await rig.decide(hold, "deny")
            await rig.settled()
            await until(lambda: rig.running.app.approvals.table.get(ref) is None, BOUND)
            declined = await client.call_tool("check_approval", {"id": ref})
            later = await client.call_tool("echo", {"text": "no"})
    assert text(declined) == f"{checkapproval.DECLINED} (ref {ref})"
    assert "declined moments ago" in text(later)
    assert rig.calls() == []
    assert rig.ledger(ref)[1:] == [
        ("decided", "pending"),
        ("decided", "decline"),
        ("outcome", ("not_sent", None)),
    ]


@pytest.mark.parametrize("version", ["modern", "2025-11-25"])
async def test_an_abandoned_relay_is_withdrawn_at_the_vault(tmp_path: Path, version: Any) -> None:
    """B.6, E.4: the agent abandons a call waiting for its relayed approval: the gateway records
    it withdrawn and unsent (it forwards a relay itself, so nothing was) and tells the vault,
    whose relay ends withdrawn; a later approval is refused."""
    with anyio.fail_after(BOUND), holding(tmp_path, **OUT_OF_BAND) as rig:
        async with agent(rig.running.mcp(), version=version, headers=bearer()) as client:
            async with anyio.create_task_group() as group:
                group.start_soon(lambda: client.call_tool("echo", {"text": "never"}))
                [hold] = await rig.surface.holds(1)
                group.cancel_scope.cancel()
            await until(lambda: rig.running.app.approvals.table.get(hold.ref) is None, BOUND)
            vault = rig.deployed.vault
            assert vault is not None
            await until(lambda: vault.holds.get(hold.id) is None, BOUND)
            await rig.settled()
            late = await rig.decide(hold)
    assert late == DecideRefusal("withdrawn")
    assert rig.calls() == []
    assert rig.ledger(hold.ref) == [
        ("asked", "gateway"),
        ("decided", "withdrawn"),
        ("outcome", ("not_sent", None)),
    ]
    assert rig.chain(hold.ref)[1:] == [("decided", "withdrawn"), ("outcome", "not_sent")]
    [request] = told(rig)
    assert request["status"] == 200


async def test_losing_out_of_band_withdraws_the_relay(tmp_path: Path) -> None:
    """G-24, Z7: a change that takes the client's ``out_of_band`` withdraws its waiting relay on
    both sides; the agent is told the policy changed, nothing is sent, and a late approval is
    refused."""
    with anyio.fail_after(BOUND), holding(tmp_path, **OUT_OF_BAND) as rig:
        async with agent(rig.running.mcp(), headers=bearer()) as client:
            async with anyio.create_task_group() as group:
                answer = await call_in(group, lambda: client.call_tool("echo", {"text": "hi"}))
                [hold] = await rig.surface.holds(1)
                await anyio.to_thread.run_sync(
                    lambda: rig.deployed.reload(approvals={CLIENTS[0]: {"attended": False}})
                )
            await rig.settled()
            vault = rig.deployed.vault
            assert vault is not None
            await until(lambda: vault.holds.get(hold.id) is None, BOUND)
            late = await rig.decide(hold)
    [result] = answer
    assert text(result) == f"refused: the policy changed; call the tool again (ref {hold.ref})"
    assert late == DecideRefusal("withdrawn")
    assert rig.calls() == []
    assert rig.ledger(hold.ref) == [
        ("asked", "gateway"),
        ("decided", "withdrawn"),
        ("outcome", ("not_sent", None)),
    ]
    assert rig.chain(hold.ref)[1:] == [("decided", "withdrawn"), ("outcome", "not_sent")]


async def test_an_ask_that_fails_here_is_withdrawn_at_the_vault(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """E.2, D.3: an ask the vault took, but whose answer failed here (a malformed 201, a read
    timeout), is refused with nothing sent, and the vault is told: no relay is left there that
    nobody would forward, and the client's next identical call is asked, not refused
    ``held_busy`` by the vault's fairness cap."""
    real = OutOfBandClient.ask
    failures = [ApprovalsFailed("bad_answer")]

    async def failing(self: OutOfBandClient, body: Mapping[str, Any]) -> Asked | AskRefused:
        asked = await real(self, body)
        if failures:
            raise failures.pop()
        return asked

    monkeypatch.setattr(OutOfBandClient, "ask", failing)
    with anyio.fail_after(BOUND), holding(tmp_path, **OUT_OF_BAND) as rig:
        async with agent(rig.running.mcp(), headers=bearer()) as client:
            first = await client.call_tool("echo", {"text": "hi"})
            [lost] = await rig.surface.holds(1)
            vault = rig.deployed.vault
            assert vault is not None
            await until(lambda: vault.holds.get(lost.id) is None, BOUND)
            async with anyio.create_task_group() as group:
                answer = await call_in(group, lambda: client.call_tool("echo", {"text": "hi"}))
                [_, hold] = await rig.surface.holds(2)
                await rig.decide(hold)
            await rig.settled()
    [result] = answer
    assert text(first) == f"{RELAY_UNREACHABLE} (ref {lost.ref})"
    assert not result.is_error, text(result)
    assert rig.calls() == [{"text": "hi"}]
    assert rig.ledger(lost.ref) == [
        ("asked", "gateway"),
        ("decided", "unavailable"),
        ("outcome", ("not_sent", None)),
    ]
    assert rig.chain(lost.ref)[1:] == [("decided", "withdrawn"), ("outcome", "not_sent")]


async def test_a_pending_relay_the_ledger_refuses_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """F.5 step 7: a pending relay approved while the gateway's ledger refuses its ``decided
    accept`` sends nothing, and ``check_approval`` gives the refusal the call would have
    answered, once, never "already collected" for a result nobody had."""
    approvers = {"portal": {}, "block_seconds": 0}
    with anyio.fail_after(BOUND), holding(tmp_path, approvers=approvers, **OUT_OF_BAND) as rig:
        ledger = rig.running.app.approvals.ledger
        assert ledger is not None
        write = ledger.write

        async def refusing(kind: Any, ref: str | None, *, critical: bool, **fields: Any) -> Any:
            if kind == "decided" and fields.get("decision") == "accept":
                raise LedgerUnavailable("decided")
            return await write(kind, ref, critical=critical, **fields)

        monkeypatch.setattr(ledger, "write", refusing)
        async with agent(rig.running.mcp(), headers=bearer()) as client:
            ref = ref_of(await client.call_tool("echo", {"text": "unsent"}))
            [hold] = await rig.surface.holds(1)
            await rig.decide(hold)
            await rig.settled()
            await until(lambda: rig.running.app.approvals.table.get(ref) is None, BOUND)
            collected = await client.call_tool("check_approval", {"id": ref})
            twice = await client.call_tool("check_approval", {"id": ref})
    assert text(collected) == f"{LEDGER_DOWN} (ref {ref})"
    assert text(twice) == f"{checkapproval.COLLECTED} (ref {ref})"
    assert rig.calls() == []
    assert rig.ledger(ref) == [
        ("asked", "gateway"),
        ("decided", "pending"),
        ("outcome", ("not_sent", None)),
    ]


# --- the dispatcher, in process (E.3; Z10) --------------------------------------------------------

RELAY_KEY = Key("agent1", "notes", "echo")


def relay_record(approvals: Approvals, ref: str, client: str = "agent1") -> Pending:
    begun = approvals.table.begin(
        replace(RELAY_KEY, client=client),
        settings=Settings(3600, 300, 15, 1, 30),
        now=approvals.clock(),
        ref=ref,
        era="modern",
        args={"text": "hi"},
        args_digest="sha256:" + "2" * 64,
        pin="sha256:" + "1" * 64,
        text_sha256="t" * 64,
        how="relay",
    )
    assert isinstance(begun, Pending)
    return begun


def telling(approvals: Approvals) -> list[tuple[str, str, str]]:
    """What the gateway tells the vault it gave up, recorded in place of the vault."""
    told: list[tuple[str, str, str]] = []

    async def tell(ref: str, client: str, reason: str) -> None:
        told.append((ref, client, reason))

    approvals.relays.tell_withdrawn = tell
    return told


async def test_a_restarted_vault_withdraws_the_relays_here() -> None:
    """E.2, Z10: a decisions poll answering another vault epoch means the vault restarted, and
    every relay it had is gone: a call still in its block is woken withdrawn, and one that
    answered pending is closed withdrawn now, with nothing sent; the poll starts over."""
    approvals = Approvals(
        ledger=None, committed=Committed(), fresh=lambda: None, stopping=lambda: False
    )
    blocking, detached = relay_record(approvals, REF_A), relay_record(approvals, REF_B, "agent2")
    unused = cast(Asking, None)  # a withdrawn relay never runs its call
    waiting = RelayWait(unused, blocking, digest="d" * 64)
    pended = RelayWait(unused, detached, digest="d" * 64, detached=True)
    pended.answered.set()
    approvals.table.pend(REF_B, time.time() + 3600)
    approvals.relays.waiting.update({REF_A: waiting, REF_B: pended})
    told = telling(approvals)
    vault = Polled(("aaaaaaaaaaaa", []), ("bbbbbbbbbbbb", []))
    http = approvals_client(LINK, None, httpx2.MockTransport(vault.handle))
    poller = OutOfBandClient(approvals, http)
    with anyio.fail_after(BOUND):
        await poller.poll_once(25)
        first = poller.vault_restarted
        await poller.poll_once(25)
        restarted = poller.vault_restarted
        await poller.run_all(approvals.relays_lost())
    await http.aclose()
    assert (first, restarted) == (False, True)
    assert waiting.woken.is_set()
    assert waiting.decided is not None
    assert waiting.decided.decision == "withdrawn"
    assert approvals.relays.settled(waiting).decision == "withdrawn"
    assert approvals.table.get(REF_B) is None  # closed, its lock freed
    assert approvals.relays.waiting == {REF_A: waiting}  # the blocking one's handler pops it
    # The restarted vault may have been asked it anew: told (the blocking one's handler tells).
    assert told == [(REF_B, "agent2", "caller_cancelled")]


async def test_a_decision_wakes_its_call_once_and_only_its_own() -> None:
    """E.3: the dispatcher hands a decision to the relay it names, once: a second one, or one
    for a ref no relay waits on, changes nothing; ``_wanted`` polls while a relay waits."""
    approvals = Approvals(
        ledger=None, committed=Committed(), fresh=lambda: None, stopping=lambda: False
    )
    record = relay_record(approvals, REF_A)
    waiting = RelayWait(cast(Asking, None), record, digest="d" * 64)
    approvals.relays.waiting[REF_A] = waiting
    approve = Relayed(1, REF_A, "accept", "portal", 0, "d" * 64)
    async with httpx2.AsyncClient() as unused:
        poller = OutOfBandClient(approvals, unused)
        document = json.loads(json.dumps(VIEW_POLICY))
        del document["approvers"]
        del document["gateway"]["servers"]["notes"]["tools"]["vault_approval"]
        snapshot = Snapshot(build_view(Policy.model_validate(document)), 0.0)
        wanted = poller._wanted(snapshot)
        await poller.relayed([approve, replace(approve, seq=2, decision="decline")])
        await poller.relayed([replace(approve, ref=REF_B)])
    assert wanted
    assert waiting.decided == approve
    assert waiting.woken.is_set()
    assert approvals.relays.settled(waiting) == Decided(record, "accept")


def clocked(now: list[float]) -> Approvals:
    return Approvals(
        ledger=None,
        committed=Committed(),
        fresh=lambda: None,
        stopping=lambda: False,
        clock=lambda: now[0],
    )


async def test_a_block_that_lasts_to_the_deadline_times_out() -> None:
    """I.1 step 2, F.1: ``block_seconds`` may equal the timeout, and a block that lasted to the
    deadline undecided is ``timeout``, with the vault told, never a pending answer for a call
    that has already expired."""
    now = [0.0]
    approvals = clocked(now)
    told = telling(approvals)
    record = relay_record(approvals, REF_A)

    async def ask_vault(body: Mapping[str, Any]) -> Asked:
        now[0] = record.expires_at  # the whole block went by
        return Asked("a" * 32, "d" * 64)

    approvals.relays.ask_vault = ask_vault
    out = SimpleNamespace(block_seconds=3600)
    asking = SimpleNamespace(
        gateway=SimpleNamespace(approvals=SimpleNamespace(out_of_band=out)),
        client="agent1",
        server="notes",
        tool="echo",
    )
    settings = Settings(3600, 300, 15, 1, 30)
    shown = Shown(cast(ApprovalText, SimpleNamespace(value="x")), {}, settings, time.time())
    with anyio.fail_after(BOUND):
        found = await approvals.relays.ask(cast(Asking, asking), record, shown)
    assert found == Decided(record, "timeout")
    assert told == [(REF_A, "agent1", "caller_cancelled")]
    assert approvals.relays.waiting == {}


async def test_the_sweep_closes_a_pending_relay_once_answered_and_tells_the_vault() -> None:
    """F.1, E.2: a relay pending past its deadline with no decision is closed ``timeout`` by the
    sweep, only after its ``decided pending`` record is written, and the vault, whose own
    deadline may be later, is told."""
    now = [0.0]
    approvals = clocked(now)
    told = telling(approvals)
    record = relay_record(approvals, REF_A)
    wait = RelayWait(cast(Asking, None), record, digest="d" * 64, detached=True)
    approvals.relays.waiting[REF_A] = wait
    now[0] = record.expires_at + 1
    with anyio.fail_after(BOUND):
        await approvals.sweep()
        unanswered = (approvals.table.get(REF_A) is not None, list(told))
        wait.answered.set()
        await approvals.sweep()
    assert unanswered == (True, [])
    assert approvals.table.get(REF_A) is None
    assert approvals.relays.waiting == {}
    assert told == [(REF_A, "agent1", "caller_cancelled")]
