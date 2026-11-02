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

The vault-side tests run a real vault on both links (``tests/gateway/holdrig.py``; the link
socket on Linux only), the gateway-side ones the whole gateway on it.
"""

from __future__ import annotations

import io
import json
import threading
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from dataclasses import replace
from pathlib import Path
from typing import Any

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
from zoeymcp.common import canonical
from zoeymcp.common.committed import Committed
from zoeymcp.common.policy import Policy
from zoeymcp.common.policy.view import build_view
from zoeymcp.gateway import checkapproval, elsewhere, pipeline
from zoeymcp.gateway import logs as gateway_logs
from zoeymcp.gateway.approvals import MAX_RECORDS
from zoeymcp.gateway.approve import RESULT_TTL_MAX, Approvals
from zoeymcp.gateway.outofband import (
    IDLE_WAIT,
    ApprovalsFailed,
    Ending,
    OutOfBandClient,
    endings,
)
from zoeymcp.gateway.pipeline import NO_OUT_OF_BAND
from zoeymcp.gateway.policyclient import Snapshot
from zoeymcp.gateway.vaultlink import KeySource, approvals_client, parse_link
from zoeymcp.vault import logs as vault_logs
from zoeymcp.vault.holds import DecideRefusal

pytestmark = pytest.mark.anyio
REF_A, REF_B, REF_C = (f"00000000000000c{n}" for n in "abc")
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
    }
    assert after.json() == {
        "v": 1,
        "epoch": epoch,
        "endings": [{"seq": 2, "ref": REF_B, "status": "done", "outcome": "ok"}],
    }
    assert blocking.json()["code"] == "approval_expired"
    assert last.json() == {"v": 1, "epoch": epoch, "endings": []}


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
    """The decisions answer's shape (E.2): the vault's epoch and each ending exactly; an outcome
    the ledger doesn't know reads ``unknown``."""
    ending = {"seq": 3, "ref": REF_A, "status": "done", "outcome": "ok"}
    odd = {**ending, "seq": 4, "outcome": "exploded"}
    assert endings({"v": 1, "epoch": EPOCH, "endings": [ending, odd]}) == (
        EPOCH,
        [Ending(3, REF_A, "done", "ok"), Ending(4, REF_A, "done", "unknown")],
    )
    bad: list[dict[str, Any]] = [
        {"v": 1, "epoch": EPOCH},
        {"v": 1, "epoch": EPOCH, "endings": [], "decisions": []},
        {"v": 1, "epoch": "X", "endings": []},
        {"v": 1, "epoch": EPOCH, "endings": {}},
        {"v": 1, "epoch": EPOCH, "endings": [{**ending, "extra": 1}]},
        {"v": 1, "epoch": EPOCH, "endings": [{**ending, "seq": 0}]},
        {"v": 1, "epoch": EPOCH, "endings": [{**ending, "seq": True}]},
        {"v": 1, "epoch": EPOCH, "endings": [{**ending, "ref": "x"}]},
        {"v": 1, "epoch": EPOCH, "endings": [{**ending, "status": 1}]},
        {"v": 1, "epoch": EPOCH, "endings": [{**ending, "outcome": None}]},
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
        return httpx2.Response(200, json={"v": 1, "epoch": epoch, "endings": listed})


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
