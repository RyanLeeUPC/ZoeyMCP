"""A policy or upstream change while an approval waits (M6 design J.4's last bullet, Y28, FM-17;
D-76's M6 part, Q32 (b), CR-1).

The gateway, a real vault and the fake MCP server, as in :mod:`tests.gateway.test_approvals_remote`.
``echo`` and ``slow`` are ``approve``; the agent's human holds each prompt until the test has made
its change, then answers. Each case runs in both eras: a legacy prompt waits on the call's own
stream, and a modern one is answered by a retry carrying the prompt's handle.

- A **re-pin** (a ``tool.repin`` save's :class:`SetServerReview`) or an **upstream drift** while
  the prompt waits: nothing is sent. Legacy: the accept's re-check refuses the call ``changed``
  (B.5: the tool is admitted under another pin now, or not at all). Modern: the retry is the
  pipeline's own request, so it meets the change first: under the new pin its handle answers
  ``mismatch``, and a hidden tool is an unknown one (whose failed retry closes the prompt, D.7).
- **Approve->allow** while the prompt waits, by ``tool.allow`` (a :class:`MoveToAllow`) or inside a
  review save (a :class:`SetServerReview` moving two tools): the prompt is withdrawn, as a removed
  tool's is, since ``_still_allowed`` counts only ``approve`` (Q32 (b)). The record is decided
  ``withdrawn`` with nothing sent, so the client's pending slot and the tool's lock are free at
  once (another ``approve`` tool is asked, not refused ``pending_cap``). Legacy: the waiting call
  answers ``withdrawn``'s text, whatever the human answers. Modern: the human's answer comes back
  as a retry of what is now an ``allow`` tool, and a handle is good only for an ``approve`` one
  (D.6), so the pipeline refuses it with nothing sent. In both, the next call to the moved tool
  runs with no prompt.

Each move is the managed write's own candidate, ``change.apply(..., managed=True)``, served to the
running vault as a reload serves it: the gateway sees only the new view, whichever write made it.

- (M8 step 12b; G-24, E-6) A **relay** of an ``out_of_band`` client survives a view change that
  doesn't touch it: the rewritten rule asks a relayed record for ``out_of_band``, not
  ``attended``, so the operator's approval still runs the call, once.

D-76's last two rows (the pre-main test-debt pass), each in both eras, nothing sent:

- The **view goes stale** before the accept's re-check: no contact with the vault for
  ``policy_max_stale``, so the re-check has no fresh view and refuses ``changed``. The agent's
  answer is itself a request that needs a fresh view at the door, so the staleness lands
  between the door and the re-check: the policy client's last contact is moved back as the
  re-check starts.
- An **admit refusal inside pool.call**: the re-check admits the tool under its pin, then the
  upstream drifts and the gateway marks it before the forward, so the pool's own admission
  refuses (``NotAdmitted``): ``decided accept``, then ``outcome not_sent`` with detail
  ``changed``.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import anyio
import httpx
import mcp_types as types
import pytest
from mcp import Client
from mcp.shared.exceptions import MCPError
from mcp.types import CallToolResult

from tests.fakes.agent import ACCEPT, DECLINE, Script, Version, agent
from tests.fakes.mcp_server import McpFake
from tests.gateway.rig import (
    CLIENTS,
    RELOAD_PATH,
    SERVER,
    Deployed,
    Running,
    pin_of_fake,
    until,
)
from tests.gateway.test_approvals_remote import (
    TOOLS,
    approving,
    by_ref,
    headers,
    ledger_records,
    ref_of,
    text,
)
from tests.gateway.test_elsewhere import call_in, holding
from zoeymcp.common.policy import Policy
from zoeymcp.common.policy.change import MoveToAllow, PolicyChange, SetServerReview, apply
from zoeymcp.common.policy.schema import RemoteServer, Tools
from zoeymcp.gateway import upstream
from zoeymcp.gateway.approvals import Pending
from zoeymcp.gateway.approve import CHANGED, DECISION_TEXTS, Asking
from zoeymcp.gateway.pipeline import STATE_REFUSED, UNKNOWN_TOOL

pytestmark = pytest.mark.anyio

# One version per era: the approval's own path differs by era, not by legacy version.
ERAS: tuple[Version, ...] = ("modern", "2025-11-25")
MOVES = ("tool.allow", "policy.save")  # the kinds of the two writes that move a tool
BOUND = 60  # seconds for one case, start to end


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(autouse=True)
def quick(monkeypatch: pytest.MonkeyPatch) -> None:
    """Listings may follow each other at once, so an announced drift is listed at once."""
    monkeypatch.setattr(upstream, "COALESCE", 0.0)


@dataclass
class Held(Script):
    """The agent's human: notes each prompt as it arrives, and answers by the script only once
    ``go`` is set."""

    arrived: list[str] = field(default_factory=list)
    go: anyio.Event = field(default_factory=anyio.Event)

    async def __call__(
        self, context: Any, params: types.ElicitRequestParams
    ) -> types.ElicitResult | types.ErrorData:
        self.arrived.append(getattr(params, "message", ""))
        await self.go.wait()
        return await super().__call__(context, params)


Outcome = CallToolResult | MCPError


@contextmanager
def waiting(tmp_path: Path) -> Iterator[tuple[Deployed, Running, McpFake]]:
    fake = McpFake()
    with approving(tmp_path, fake) as (deployed, running):
        yield deployed, running, fake


async def call(client: Client, found: list[Outcome], name: str = "echo") -> None:
    try:
        found.append(await client.call_tool(name, {"text": "hi"}))
    except MCPError as exc:  # a modern retry the pipeline refuses as a protocol error
        found.append(exc)


def server_of(policy: Policy) -> RemoteServer:
    assert policy.gateway is not None
    server = policy.gateway.servers[SERVER]
    assert isinstance(server, RemoteServer)
    return server


def serve(deployed: Deployed, policy: Policy) -> None:
    """Install ``policy`` in the running vault, as a managed write's commit or a reload does."""
    body = policy.model_dump(mode="json", by_alias=True, exclude_defaults=True)
    answer = httpx.post(deployed.vault_url + RELOAD_PATH, json=body, timeout=10)
    assert answer.status_code == 204, answer.text
    deployed.policy = policy


def moved(deployed: Deployed, how: str) -> Policy:
    """``echo`` moved from ``approve`` to ``allow``, as each managed write makes the candidate:
    ``tool.allow``'s one move, or a review save that moves ``add`` the other way (a
    ``policy.save``). ``slow`` stays ``approve`` in both."""
    held = server_of(deployed.policy)
    if how == "tool.allow":
        op: MoveToAllow | SetServerReview = MoveToAllow(SERVER, "tool", "echo", held.review["echo"])
    else:
        tools = Tools(include=TOOLS, allow=["echo"], approve=["add", "slow"])
        op = SetServerReview(SERVER, tools, dict(held.review))
    return apply(deployed.policy, PolicyChange(f"{how} for {SERVER}", (op,)), managed=True)


def repinned(deployed: Deployed, pin: str) -> Policy:
    """``echo`` re-pinned to ``pin``, kept ``approve``: a ``tool.repin`` save's candidate."""
    held = server_of(deployed.policy)
    op = SetServerReview(SERVER, held.tools, {**held.review, "echo": pin})
    return apply(deployed.policy, PolicyChange(f"re-pin for {SERVER}", (op,)), managed=True)


async def applied(running: Running, check: Any) -> None:
    """Wait until the gateway runs a view whose ``notes`` entry passes ``check``."""

    def done() -> bool:
        snapshot = running.app.policy.snapshot
        return snapshot is not None and check(snapshot.view.gateway.servers[SERVER])

    await until(done)


async def drifted(fake: McpFake, running: Running) -> None:
    """``echo`` changes upstream and the gateway sees it: announced until it is marked (a lost
    announcement is only repeated; the fake lists the change from the next listing on)."""
    fake.change_tool("description")
    with anyio.fail_after(10):
        while not running.app.pool.marks.for_server(SERVER):
            await anyio.to_thread.run_sync(fake.announce)
            with anyio.move_on_after(2):
                await until(lambda: running.app.pool.marks.for_server(SERVER), timeout=3)


def refused_changed(found: Outcome, version: Version, *, modern: str | None) -> None:
    """The waiting call's answer: ``changed`` on a legacy stream; on a modern retry ``modern``,
    the text of its refusal, or ``None`` for the pipeline's unknown tool."""
    if version != "modern":
        assert isinstance(found, CallToolResult)
        assert text(found).startswith(f"{CHANGED} (ref ")
    elif modern is None:
        assert isinstance(found, MCPError)
        assert found.error.message == UNKNOWN_TOOL
    else:
        assert isinstance(found, CallToolResult)
        assert text(found).startswith(f"{modern} (ref ")


def ref_of_asked(deployed: Deployed) -> str:
    """The ref of the one prompt asked: a modern answer the pipeline refused carries none."""
    [asked] = deployed.events("approval_asked")
    ref: str = asked["ref"]
    return ref


# --- a re-pin or a drift while the prompt waits: nothing is sent ---------------------------------


@pytest.mark.parametrize("version", ERAS)
async def test_a_repin_while_waiting_refuses_the_call(tmp_path: Path, version: Version) -> None:
    """J.4, FM-17: the definition changes and the operator re-pins it while the prompt waits;
    the accept sends nothing, since the call was shown under the old pin."""
    script = Held()
    with waiting(tmp_path) as (deployed, running, fake), anyio.fail_after(BOUND):
        async with agent(
            running.mcp(), version=version, script=script, headers=headers()
        ) as client:
            found: list[Outcome] = []
            async with anyio.create_task_group() as group:
                group.start_soon(call, client, found)
                await until(lambda: script.arrived)
                await drifted(fake, running)
                new = pin_of_fake(fake, "echo")
                serve(deployed, repinned(deployed, new))
                await applied(running, lambda server: server.review["echo"] == new)
                script.go.set()
    [answer] = found
    refused_changed(answer, version, modern=DECISION_TEXTS["mismatch"])
    assert deployed.fake.calls == []
    assert deployed.events("approvals_withdrawn") == []
    assert isinstance(answer, CallToolResult)
    # Either way the record is decided, so the client's pending slot is free again.
    assert by_ref(deployed, ref_of(answer)) == [
        ("asked", "legacy" if version != "modern" else "modern"),
        ("decided", "changed" if version != "modern" else "mismatch"),
        ("outcome", "not_sent"),
    ]


@pytest.mark.parametrize("version", ERAS)
async def test_a_drift_while_waiting_refuses_the_call(tmp_path: Path, version: Version) -> None:
    """J.4, FM-17: the upstream changes ``echo`` while the prompt waits, and nobody re-pins; the
    tool is hidden, so the accept sends nothing."""
    script = Held()
    with waiting(tmp_path) as (deployed, running, fake), anyio.fail_after(BOUND):
        async with agent(
            running.mcp(), version=version, script=script, headers=headers()
        ) as client:
            found: list[Outcome] = []
            async with anyio.create_task_group() as group:
                group.start_soon(call, client, found)
                await until(lambda: script.arrived)
                await drifted(fake, running)
                script.go.set()
    [answer] = found
    refused_changed(answer, version, modern=None)
    assert deployed.fake.calls == []
    assert [event["tool"] for event in deployed.events("tool_drift")] == ["echo"]
    if version != "modern":
        assert isinstance(answer, CallToolResult)
        assert by_ref(deployed, ref_of(answer))[1] == ("decided", "changed")
    else:
        # The retry never reached the approval; the guard on a failed retry closed it (D.7).
        assert by_ref(deployed, ref_of_asked(deployed)) == [
            ("asked", "modern"),
            ("decided", "error"),
            ("outcome", "not_sent"),
        ]


# --- approve->allow while the prompt waits: the prompt is withdrawn -----------------------------


def asked_ref(deployed: Deployed, tool: str) -> str:
    """The ref of the one prompt asked for ``tool``."""
    [ref] = [event["ref"] for event in deployed.events("approval_asked") if event["tool"] == tool]
    found: str = ref
    return found


@pytest.mark.parametrize("version", ERAS)
@pytest.mark.parametrize("how", MOVES)
@pytest.mark.parametrize("answer", ["accept", "decline"])
async def test_approve_to_allow_while_waiting_withdraws_the_prompt(
    tmp_path: Path, version: Version, how: str, answer: str
) -> None:
    """J.4, Y28, FM-17 (CR-1), Q32 (b): whichever write made the move, it withdraws the waiting
    prompt, so the human's answer decides nothing and nothing is sent (legacy: the call answers
    ``withdrawn``; modern: the retry's handle no longer fits an ``allow`` tool). The record is
    decided, so the client's pending slot is free: ``slow``, still ``approve``, is asked. The next
    call to the moved tool runs with no prompt."""
    script = Held([ACCEPT if answer == "accept" else DECLINE])  # the last answer repeats
    with waiting(tmp_path) as (deployed, running, _fake), anyio.fail_after(BOUND):
        async with agent(
            running.mcp(), version=version, script=script, headers=headers()
        ) as client:
            found: list[Outcome] = []
            async with anyio.create_task_group() as group:
                group.start_soon(call, client, found)
                await until(lambda: script.arrived)
                serve(deployed, moved(deployed, how))
                await until(lambda: deployed.events("approvals_withdrawn"))
                script.go.set()
            sent = [c.arguments for c in deployed.fake.calls]
            other = await client.call_tool("slow", {"steps": 1})
            await call(client, found)
    first, second = found
    assert [event["count"] for event in deployed.events("approvals_withdrawn")] == [1]
    assert sent == []
    withdrawn = asked_ref(deployed, "echo")
    assert by_ref(deployed, withdrawn) == [
        ("asked", "legacy" if version != "modern" else "modern"),
        ("decided", "withdrawn"),
        ("outcome", "not_sent"),
    ]
    assert isinstance(first, CallToolResult)
    if version == "modern":
        assert text(first) == STATE_REFUSED
    else:
        assert text(first) == f"{DECISION_TEXTS['withdrawn']} (ref {withdrawn})"
    # The pending slot is free: ``slow`` is asked, and the human's answer decides it.
    assert len(script.arrived) == 2
    asked = asked_ref(deployed, "slow")
    if answer == "accept":
        assert text(other) == "done after 1 steps"
        assert by_ref(deployed, asked)[1] == ("decided", "accept")
    else:
        assert text(other) == f"{DECISION_TEXTS['decline']} (ref {asked})"
    # The next call is an allow call: no prompt, and it runs.
    assert isinstance(second, CallToolResult)
    assert text(second).endswith("hi")
    upstream = [(c.name, c.arguments) for c in deployed.fake.calls]
    assert upstream == [
        *([("slow", {"steps": 1})] if answer == "accept" else []),
        ("echo", {"text": "hi"}),
    ]


async def test_a_relay_survives_an_unrelated_view_change(tmp_path: Path) -> None:
    """G-24, E-6: agent1 is ``out_of_band`` and not attended; while its relayed ``echo`` waits,
    a change moves ``add`` to ``allow``. The gateway applies the new view and keeps the relay
    (the old rule withdrew any record of a client that isn't attended), the vault keeps it too,
    and the operator's approval runs the call once."""
    options: dict[str, Any] = {
        "vault_approval": [],
        "approvals": {CLIENTS[0]: {"attended": False, "out_of_band": True}},
    }
    with anyio.fail_after(BOUND), holding(tmp_path, **options) as rig:
        app = rig.running.app
        async with agent(rig.running.mcp(), headers=headers()) as client:
            async with anyio.create_task_group() as group:
                answer = await call_in(group, lambda: client.call_tool("echo", {"text": "kept"}))
                [hold] = await rig.surface.holds(1)
                await anyio.to_thread.run_sync(lambda: rig.deployed.reload(approve=["echo"]))

                def applied() -> bool:
                    snapshot = app.approvals.fresh()
                    return snapshot is not None and snapshot.view.gateway.servers[
                        SERVER
                    ].tools.approve == ["echo"]

                await until(applied)
                assert app.approvals.table.get(hold.ref) is not None
                await rig.decide(hold)
            await rig.settled()
    [result] = answer
    assert not result.is_error, text(result)
    assert text(result).endswith("kept")
    assert [c.arguments for c in rig.deployed.fake.calls] == [{"text": "kept"}]
    assert rig.ledger(hold.ref) == [
        ("asked", "gateway"),
        ("decided", "accept"),
        ("outcome", ("ok", None)),
    ]


# --- the view stale at the re-check, and an admit refusal inside pool.call (D-76) ---------------


Recheck = Callable[[Asking, Pending], Awaitable[bool]]


def outcome_detail(deployed: Deployed, ref: str) -> object:
    [outcome] = [r for r in ledger_records(deployed) if r.ref == ref and r.kind == "outcome"]
    return outcome.fields["detail"]


@pytest.mark.parametrize("version", ERAS)
async def test_a_view_gone_stale_at_the_recheck_refuses_the_call(
    tmp_path: Path, version: Version, monkeypatch: pytest.MonkeyPatch
) -> None:
    """B.5, D-76: the accept's re-check finds no fresh view (no contact with the vault for
    ``policy_max_stale``), so the call is refused ``changed`` and nothing is sent."""
    script = Script([ACCEPT])
    with waiting(tmp_path) as (deployed, running, _fake), anyio.fail_after(BOUND):
        app = running.app
        recheck: Recheck = app.approvals._changed
        rechecked: list[bool] = []

        async def stale_first(asking: Asking, record: Pending) -> bool:
            snapshot, last = app.policy.snapshot, app.policy.last_contact
            assert snapshot is not None
            assert last is not None
            # No await between this and the re-check's read: the long poll can't renew it first.
            app.policy.last_contact = last - snapshot.view.gateway.limits.policy_max_stale - 1
            rechecked.append(await recheck(asking, record))
            return rechecked[-1]

        monkeypatch.setattr(app.approvals, "_changed", stale_first)
        async with agent(
            running.mcp(), version=version, script=script, headers=headers()
        ) as client:
            answer = await client.call_tool("echo", {"text": "hi"})
    assert rechecked == [True]
    assert text(answer) == f"{CHANGED} (ref {ref_of(answer)})"
    assert len(script.prompts) == 1
    assert deployed.fake.calls == []
    assert deployed.events("policy_stale")
    ref = ref_of(answer)
    assert by_ref(deployed, ref) == [
        ("asked", "legacy" if version != "modern" else "modern"),
        ("decided", "changed"),
        ("outcome", "not_sent"),
    ]
    assert outcome_detail(deployed, ref) == "changed"


@pytest.mark.parametrize("version", ERAS)
async def test_an_admit_refusal_inside_the_forward_sends_nothing(
    tmp_path: Path, version: Version, monkeypatch: pytest.MonkeyPatch
) -> None:
    """B.5, B.6, D-76: the re-check admits ``echo`` under the pin it was asked with; then the
    upstream changes it and the gateway marks the drift before the forward, so the pool's own
    admission inside ``pool.call`` refuses. The accept is on the ledger, but nothing is sent:
    ``outcome not_sent``, detail ``changed``, and the agent reads ``changed``."""
    script = Script([ACCEPT])
    with waiting(tmp_path) as (deployed, running, fake), anyio.fail_after(BOUND):
        app = running.app
        recheck: Recheck = app.approvals._changed
        rechecked: list[bool] = []

        async def drift_after(asking: Asking, record: Pending) -> bool:
            rechecked.append(await recheck(asking, record))
            await drifted(fake, running)  # on the gateway's loop, before the forward
            return rechecked[-1]

        monkeypatch.setattr(app.approvals, "_changed", drift_after)
        async with agent(
            running.mcp(), version=version, script=script, headers=headers()
        ) as client:
            answer = await client.call_tool("echo", {"text": "hi"})
    assert rechecked == [False]  # the re-check passed: the refusal is the forward's own
    assert text(answer) == f"{CHANGED} (ref {ref_of(answer)})"
    assert deployed.fake.calls == []
    assert [event["tool"] for event in deployed.events("tool_drift")] == ["echo"]
    ref = ref_of(answer)
    assert by_ref(deployed, ref) == [
        ("asked", "legacy" if version != "modern" else "modern"),
        ("decided", "accept"),
        ("outcome", "not_sent"),
    ]
    assert outcome_detail(deployed, ref) == "changed"
    assert app.approvals.table.get(ref) is None  # the lock is free
