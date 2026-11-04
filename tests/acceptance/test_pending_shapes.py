"""Acceptance: S21, ``pending`` and ``check_approval``, the vault-held half (M8 design F, O.5; J5,
J10; FM-16, FM-39; Z17, Z18; step 11).

Agent (the SDK client, both eras) -> gateway -> vault -> the fake MCP server, on S10's shipped
profile, with ``echo`` and ``add`` ``approve`` tools the vault holds, both clients attended, and a
portal queue as the approver surface: the scripted one of ``tests/gateway/holdrig.py``, which
decides only when the test says, on the vault's own loop. ``approvers.block_seconds`` is 0, so a
held call answers ``pending <ref>`` at once; the vault forwards it as soon as it is approved, with
nobody waiting, and the agent collects it:

- the shape over both eras and both links: the tool listed with the view's ``result_ttl``; still
  pending; another client's collect ``unknown or expired`` (FM-16); the result once, finished as
  a direct call's; then ``already collected``; the client's own calls listed (Q46); the gateway's
  ledger closing the call as the vault decided it, and its lock freed (D.2); and, at the
  2025-11-25 era, the upstream's legacy session kept open for the vault's forward until then (F.6);
- FM-16 on its own (N.3's ``test_cross_client``): another client's ref, waiting and run, answers
  ``unknown or expired`` and takes nothing;
- an expired call, and a result evicted by the client's own bound (F.2);
- a vault restart: what ran says its result was lost, what waited says nothing was sent, and
  another client learns nothing (F.5 step 4, J10);
- a gateway restart: the new gateway holds no record, and still the owning client collects while
  another reads ``unknown or expired`` (FM-39).

The gateway-held relay half (M8 step 12b; E.4, F.2, F.5 step 2): the same tools gateway-held,
both clients ``out_of_band`` and nobody watching their sessions, so each call is relayed through
the vault to the same surface and, unanswered in its block, answers ``pending <ref>``; the
gateway runs it once approved and keeps its result in its own store, from which the owning
client collects it once and another client learns nothing. Completed in M8 step 19 (O.5's S21:
expired, evicted, after a restart): a relay nobody decided reads expired; a result past its
client's bound in the gateway's store is evicted, and says it wasn't kept; and a relay outlives
no gateway, since the next one's epoch withdraws it at the vault, so a late approval runs
nothing.

Every test ends with S10's sweep: the key, the tokens and the session ids reach no log, answer or
output.
"""

from __future__ import annotations

import contextlib
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Literal

import anyio
import pytest
from mcp.types import CallToolResult

from tests.dark import lit
from tests.fakes.mcp_server import McpFake, Mode
from tests.gateway.holdrig import Clock as HoldClock
from tests.gateway.holdrig import Surface
from tests.gateway.rig import Running, agent, until
from zoeymcp.common import ledgerformat, resultstore
from zoeymcp.gateway import checkapproval, elsewhere
from zoeymcp.gateway.ledger import LEDGER_DIR
from zoeymcp.vault.approvers import ApproverHub
from zoeymcp.vault.holds import DecideRefusal, Hold
from zoeymcp.vault.keys import KeySet
from zoeymcp.vault.vaultledger import VaultLedger

from .gateway import SERVER, GatewayDeployment
from .test_mcp_shapes import LINKS, deployed, text
from .tls import ProviderCA

pytestmark = pytest.mark.anyio
BOUND = 60
TOOLS = {"echo": "approve", "add": "approve"}
# The agent's era, and the fake's: at 2025-11-25 the upstream's is a legacy session too.
ERAS: dict[str, tuple[str, Mode]] = {"legacy": ("legacy", "legacy"), "modern": ("auto", "dual")}


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class Held:
    """What the vault holds calls with, made anew for each vault process (a restart opens the
    chain again): its chain, a scripted portal surface, and the hold table's clock."""

    def __init__(self) -> None:
        self.surfaces: list[Surface] = []
        self.clock = HoldClock()

    def __call__(self, state: Path, keys: KeySet) -> dict[str, Any]:
        surface = Surface("portal")
        self.surfaces.append(surface)
        return {
            "chain": VaultLedger.open_at(state, keys.chain_key),
            "hub": ApproverHub([surface]),
            "hold_clock": self.clock,
        }

    @property
    def surface(self) -> Surface:
        return self.surfaces[-1]


def extra(*, result_ttl: int = 1800, max_pending: int = 1, relay: bool = False) -> dict[str, Any]:
    """The policy beside S10's: the portal queue with no block (and the portal it is in), both
    tools held, both clients attended; with ``relay``, both tools gateway-held and relayed, both
    clients ``out_of_band`` and not attended."""
    own = {"attended": False, "out_of_band": True} if relay else {"attended": True}
    servers = {} if relay else {SERVER: {"tools": {"vault_approval": sorted(TOOLS)}}}
    return {
        "admin": {"listen": "127.0.0.1:8081", "origins": ["http://localhost:8081"]},
        "approvers": {"portal": {}, "block_seconds": 0, "result_ttl": result_ttl},
        "gateway": {
            "approvals": {"max_pending_per_client": max_pending},
            "clients": {"agent1": {"approvals": own}, "agent2": {"approvals": own}},
            "servers": servers,
        },
    }


@contextlib.contextmanager
def held_deployment(
    tmp_path: Path, ca: ProviderCA, fake: McpFake, held: Held, *, link: str = "tcp", **options: Any
) -> Iterator[GatewayDeployment]:
    with (
        lit(),
        deployed(
            tmp_path, ca, fake, link=link, tools=TOOLS, extra=extra(**options), held=held
        ) as gateway,
    ):
        yield gateway


async def decide(
    gateway: GatewayDeployment, hold: Hold, decision: Literal["approve", "deny"] = "approve"
) -> None:
    """A decision on the vault's queue, in its own synchronous section on its loop (D.4)."""
    vault = gateway.vault
    await anyio.to_thread.run_sync(
        lambda: vault.call(lambda: vault.app.decide(hold.id, decision, "portal", hold.text_sha256))
    )


async def settled(gateway: GatewayDeployment) -> None:
    vault = gateway.vault
    await anyio.to_thread.run_sync(lambda: vault.run(vault.app.settle()))


def ref_of(result: CallToolResult) -> str:
    said = text(result)
    assert said.startswith("pending "), said
    return said.split()[1].removesuffix(":")


def ledger(gateway: GatewayDeployment, ref: str) -> list[tuple[str, Any]]:
    """The gateway ledger's records for ``ref``: each kind, with its decision or outcome."""
    found: list[ledgerformat.Record] = []
    for path in sorted((gateway.state / LEDGER_DIR).glob("*.jsonl")):
        found.extend(ledgerformat.parse(line) for line in path.read_bytes().splitlines())
    return [
        (r.kind, r.fields.get("where") or r.fields.get("decision") or r.fields.get("outcome"))
        for r in found
        if r.ref == ref
    ]


async def closed(running: Running, gateway: GatewayDeployment, ref: str) -> None:
    """The gateway closed ``ref``'s record: its lock freed and its ``outcome`` written. The lock
    frees as the ending is decided, before the records (D-250), so a test that reads the ledger
    waits for both."""
    table = running.app.approvals.table
    await until(
        lambda: table.get(ref) is None and any(k == "outcome" for k, _ in ledger(gateway, ref)),
        BOUND,
    )


def connection_of(running: Running, client: str) -> Any:
    [found] = [c for c in running.app.pool.connections() if c.key[1] == client]
    return found


async def check(client: Any, ref: str | None = None) -> CallToolResult:
    arguments = {} if ref is None else {"id": ref}
    result: CallToolResult = await client.call_tool(checkapproval.NAME, arguments)
    return result


# --- S21: the shape -----------------------------------------------------------------------------


@pytest.mark.parametrize("link", LINKS)
@pytest.mark.parametrize("era", sorted(ERAS))
async def test_s21_pending_then_collected_once(
    tmp_path: Path, ca: ProviderCA, link: str, era: str
) -> None:
    agent_mode, fake_mode = ERAS[era]
    fake = McpFake(mode=fake_mode)
    held = Held()
    with (
        held_deployment(tmp_path, ca, fake, held, link=link) as gateway,
        gateway.running() as running,
    ):
        with anyio.fail_after(BOUND):
            async with (
                agent(running, mode=agent_mode) as owner,
                agent(running, "agent2", mode=agent_mode) as other,
            ):
                listed = await owner.list_tools()
                pending = await owner.call_tool("echo", {"text": "kettle at 3pm"})
                ref = ref_of(pending)
                kept = connection_of(running, "agent1").holds
                still = await check(owner, ref)
                crossed = await check(other, ref)
                [hold] = await held.surface.holds(1)
                await decide(gateway, hold)
                await settled(gateway)
                collected = await check(owner, ref)
                again = await check(owner, ref)
                mine = await check(owner)
                theirs = await check(other)
                released = connection_of(running, "agent1").holds
        gateway.seen.outputs += [text(r) for r in (pending, still, crossed, collected, again)]
        locked = running.app.approvals.table.get(ref)
    [tool] = [t for t in listed.tools if t.name == checkapproval.NAME]
    assert tool.description == (
        "Gets the result of a call that answered 'pending <id>'. The result is kept for 30 "
        "minutes after the call runs and is given once."
    )
    assert tool.annotations is not None
    assert tool.annotations.read_only_hint is True
    assert pending.is_error
    assert pending.structured_content is None
    assert "kept for 30 minutes after the call runs" in text(pending)
    assert text(still).startswith("still pending: waiting for the operator's approval until ")
    assert text(still).endswith(f" UTC (ref {ref})")
    assert text(crossed) == f"unknown or expired (ref {ref})"  # FM-16
    assert not collected.is_error
    assert text(collected) == "kettle at 3pm"
    assert text(again) == f"already collected (ref {ref})"
    assert not mine.is_error
    assert f"{ref} (echo): collected" in text(mine)
    assert text(theirs) == checkapproval.NONE_LISTED
    assert [call.arguments for call in fake.calls if call.name == "echo"] == [
        {"text": "kettle at 3pm"}
    ]
    assert ledger(gateway, ref) == [
        ("asked", "vault"),
        ("decided", "pending"),
        ("decided", "approved_elsewhere"),
        ("outcome", "ok"),
    ]
    assert locked is None  # the collect told the gateway how it ended (D.2)
    # F.6: the upstream's legacy session stayed open for the vault's forward, and no longer.
    assert (kept, released) == ((1, 0) if era == "legacy" else (0, 0))


@pytest.mark.parametrize("link", LINKS)
async def test_cross_client(tmp_path: Path, ca: ProviderCA, link: str) -> None:
    """FM-16: another client's ref answers ``unknown or expired``, while the call waits and once
    it ran, and takes nothing: its owner still collects the result. (With no gateway record,
    the vault's own binding to the client answers so too: FM-39's test.)"""
    fake = McpFake()
    held = Held()
    with (
        held_deployment(tmp_path, ca, fake, held, link=link) as gateway,
        gateway.running() as running,
    ):
        with anyio.fail_after(BOUND):
            async with agent(running) as owner, agent(running, "agent2") as other:
                ref = ref_of(await owner.call_tool("echo", {"text": "mine"}))
                waiting = await check(other, ref)
                [hold] = await held.surface.holds(1)
                await decide(gateway, hold)
                await settled(gateway)
                ran = await check(other, ref)
                collected = await check(owner, ref)
        gateway.seen.outputs += [text(r) for r in (waiting, ran, collected)]
    assert text(waiting) == f"unknown or expired (ref {ref})"
    assert text(ran) == text(waiting)
    assert not collected.is_error
    assert text(collected) == "mine"
    assert ledger(gateway, ref)[-2:] == [("decided", "approved_elsewhere"), ("outcome", "ok")]


async def test_an_expired_call_says_so(tmp_path: Path, ca: ProviderCA) -> None:
    fake = McpFake()
    held = Held()
    with held_deployment(tmp_path, ca, fake, held) as gateway, gateway.running() as running:
        with anyio.fail_after(BOUND):
            async with agent(running) as owner:
                ref = ref_of(await owner.call_tool("echo", {"text": "hi"}))
                await held.surface.holds(1)
                held.clock.ahead += 3601  # past approvers.timeout, undecided
                vault = gateway.vault
                await anyio.to_thread.run_sync(lambda: vault.call(vault.app.sweep_holds))
                await settled(gateway)
                expired = await check(owner, ref)
                later = await owner.call_tool("echo", {"text": "hi"})
    assert text(expired) == f"{checkapproval.EXPIRED} (ref {ref})"
    assert ledger(gateway, ref)[2:] == [("decided", "timeout"), ("outcome", "not_sent")]
    assert "declined moments ago" in text(later)  # an expiry starts the gateway's cooldown
    assert fake.calls == []


async def test_a_result_the_clients_bound_evicted_says_it_wasnt_kept(
    tmp_path: Path, ca: ProviderCA, monkeypatch: pytest.MonkeyPatch
) -> None:
    """F.2, Q44 (a): a client's second result past its own bound evicts its first, whose
    collect says the call ran and its result wasn't kept; the second is collected."""
    fake = McpFake()
    held = Held()
    with (
        held_deployment(tmp_path, ca, fake, held, max_pending=2) as gateway,
        gateway.running() as running,
    ):
        with anyio.fail_after(BOUND):
            async with agent(running) as owner:
                first = ref_of(await owner.call_tool("echo", {"text": "one"}))
                second = ref_of(await owner.call_tool("add", {"a": 2, "b": 3}))
                holds = {h.tool: h for h in await held.surface.holds(2)}
                await decide(gateway, holds["echo"])
                await settled(gateway)
                size = gateway.vault.app.results.total_bytes()
                assert size > 0
                # Room for one result: the next evicts the first (client_bound).
                monkeypatch.setattr(resultstore, "MAX_CLIENT_BYTES", size * 3 // 2)
                await decide(gateway, holds["add"])
                await settled(gateway)
                evicted = await check(owner, first)
                kept = await check(owner, second)
    assert text(evicted) == f"{checkapproval.NOT_KEPT} (ref {first})"
    assert not kept.is_error
    assert text(kept) == "5"
    evictions = [e for e in gateway.seen.events() if e.get("event") == "approval_result_evicted"]
    assert [(e["ref"], e["reason"]) for e in evictions] == [(first, "client_bound")]


# --- after a restart (F.5 step 4, J10; FM-39) -------------------------------------------------


async def test_a_vault_restart_says_how_each_call_ended(tmp_path: Path, ca: ProviderCA) -> None:
    """J10: the vault stopped (killed, its holds unwritten) with one call run and its result
    waiting, and another undecided; restarted, its chain's endings answer each call's own
    client, and nobody else."""
    fake = McpFake()
    held = Held()
    with held_deployment(tmp_path, ca, fake, held) as gateway:
        with gateway.running() as running, anyio.fail_after(BOUND):
            async with agent(running) as owner, agent(running, "agent2") as other:
                ran = ref_of(await owner.call_tool("echo", {"text": "hi"}))
                waited = ref_of(await other.call_tool("echo", {"text": "bye"}))
                holds = {h.ref: h for h in await held.surface.holds(2)}
                await decide(gateway, holds[ran])
                await settled(gateway)
        gateway.vault.restart()
        with gateway.running() as running, anyio.fail_after(BOUND):
            async with agent(running) as owner, agent(running, "agent2") as other:
                lost = await check(owner, ran)
                unsent = await check(other, waited)
                stranger = await check(other, ran)
    assert text(lost) == f"{checkapproval.RESTART_LOST} (ref {ran})"
    assert text(unsent) == f"{checkapproval.RESTART_NOT_SENT} (ref {waited})"
    assert text(stranger) == f"unknown or expired (ref {ran})"
    assert len([call for call in fake.calls if call.name == "echo"]) == 1


async def test_collect_after_a_gateway_restart(tmp_path: Path, ca: ProviderCA) -> None:
    """FM-39: the gateway that answered pending is gone and a new one holds no record of the
    call; the vault forwards it once approved, the owning client collects it through the new
    gateway, and another client reads ``unknown or expired`` (T34)."""
    fake = McpFake()
    held = Held()
    with held_deployment(tmp_path, ca, fake, held) as gateway, gateway.vault_running() as vault:
        with gateway.gateway(vault) as first, anyio.fail_after(BOUND):
            async with agent(first) as owner:
                ref = ref_of(await owner.call_tool("echo", {"text": "after the restart"}))
        with gateway.gateway(vault) as second, anyio.fail_after(BOUND):
            assert second.app.approvals.table.get(ref) is None
            [hold] = await held.surface.holds(1)
            await decide(gateway, hold)
            await settled(gateway)
            async with agent(second, "agent2") as other, agent(second) as owner:
                stranger = await check(other, ref)
                collected = await check(owner, ref)
    assert text(stranger) == f"unknown or expired (ref {ref})"
    assert not collected.is_error
    assert text(collected) == "after the restart"
    # The first gateway's ledger closed the call at its own restart (C.4): the vault may forward.
    assert ledger(gateway, ref)[:2] == [("asked", "vault"), ("decided", "pending")]
    assert ("outcome", "unknown") in ledger(gateway, ref)


# --- S21's relay half (M8 step 12b) -------------------------------------------------------------


@pytest.mark.parametrize("link", LINKS)
@pytest.mark.parametrize("era", sorted(ERAS))
async def test_s21_relayed_then_collected_once(
    tmp_path: Path, ca: ProviderCA, link: str, era: str
) -> None:
    """A gateway-held call relayed out of band (E.4) answers pending; approved on the vault's
    surface, the gateway runs it once with nobody waiting, and ``check_approval`` gives its
    result once from the gateway's own store (F.2, F.5 step 2), finished as a direct call's,
    then ``already collected``; another client's collect reads ``unknown or expired`` (FM-16)
    and takes nothing. The gateway's ledger has the call as one it asked itself."""
    agent_mode, fake_mode = ERAS[era]
    fake = McpFake(mode=fake_mode)
    held = Held()
    with (
        held_deployment(tmp_path, ca, fake, held, link=link, relay=True) as gateway,
        gateway.running() as running,
    ):
        with anyio.fail_after(BOUND):
            async with (
                agent(running, mode=agent_mode) as owner,
                agent(running, "agent2", mode=agent_mode) as other,
            ):
                pending = await owner.call_tool("echo", {"text": "relayed at 3pm"})
                ref = ref_of(pending)
                still = await check(owner, ref)
                crossed = await check(other, ref)
                [hold] = await held.surface.holds(1)
                await decide(gateway, hold)
                await settled(gateway)
                await closed(running, gateway, ref)
                ran = await check(other, ref)
                collected = await check(owner, ref)
                again = await check(owner, ref)
                mine = await check(owner)
        gateway.seen.outputs += [
            text(r) for r in (pending, still, crossed, ran, collected, again, mine)
        ]
    assert hold.kind == "relay"
    assert pending.is_error
    assert pending.structured_content is None
    assert text(still).startswith("still pending: waiting for the operator's approval until ")
    assert text(crossed) == text(ran) == f"unknown or expired (ref {ref})"  # FM-16
    assert not collected.is_error, text(collected)
    assert text(collected) == "relayed at 3pm"
    assert text(again) == f"already collected (ref {ref})"
    assert f"{ref} (echo): collected" in text(mine)
    assert [call.arguments for call in fake.calls if call.name == "echo"] == [
        {"text": "relayed at 3pm"}
    ]
    assert ledger(gateway, ref) == [
        ("asked", "gateway"),
        ("decided", "pending"),
        ("decided", "accept"),
        ("outcome", "ok"),
    ]


async def test_an_expired_relay_says_so(tmp_path: Path, ca: ProviderCA) -> None:
    """A relayed call nobody decided by the vault's deadline is closed at the gateway as the
    vault ended it: ``check_approval`` says it expired, and nothing was run."""
    fake = McpFake()
    held = Held()
    with (
        held_deployment(tmp_path, ca, fake, held, relay=True) as gateway,
        gateway.running() as running,
    ):
        with anyio.fail_after(BOUND):
            async with agent(running) as owner:
                ref = ref_of(await owner.call_tool("echo", {"text": "too late"}))
                [hold] = await held.surface.holds(1)
                held.clock.ahead += 3601  # past approvers.timeout, undecided
                vault = gateway.vault
                await anyio.to_thread.run_sync(lambda: vault.call(vault.app.sweep_holds))
                await settled(gateway)
                await closed(running, gateway, ref)
                expired = await check(owner, ref)
        gateway.seen.outputs.append(text(expired))
    assert hold.kind == "relay"
    assert text(expired) == f"{checkapproval.EXPIRED} (ref {ref})"
    assert ledger(gateway, ref)[2:] == [("decided", "timeout"), ("outcome", "not_sent")]
    assert fake.calls == []


async def test_a_relayed_result_the_clients_bound_evicted_says_it_wasnt_kept(
    tmp_path: Path, ca: ProviderCA, monkeypatch: pytest.MonkeyPatch
) -> None:
    """F.2, Q44 (a), in the gateway's own store: a client's second relayed result past its own
    bound evicts its first, whose collect says the call ran and its result wasn't kept; the
    second is collected."""
    fake = McpFake()
    held = Held()
    with (
        held_deployment(tmp_path, ca, fake, held, relay=True, max_pending=2) as gateway,
        gateway.running() as running,
    ):
        store = running.app.approvals.results
        with anyio.fail_after(BOUND):
            async with agent(running) as owner:
                first = ref_of(await owner.call_tool("echo", {"text": "one"}))
                second = ref_of(await owner.call_tool("add", {"a": 2, "b": 3}))
                holds = {h.tool: h for h in await held.surface.holds(2)}
                await decide(gateway, holds["echo"])
                await settled(gateway)
                await closed(running, gateway, first)
                size = store.total_bytes()
                assert size > 0
                # Room for one result: the next evicts the first (client_bound).
                monkeypatch.setattr(resultstore, "MAX_CLIENT_BYTES", size * 3 // 2)
                await decide(gateway, holds["add"])
                await settled(gateway)
                await closed(running, gateway, second)
                evicted = await check(owner, first)
                kept = await check(owner, second)
        gateway.seen.outputs += [text(evicted), text(kept)]
    assert text(evicted) == f"{checkapproval.NOT_KEPT} (ref {first})"
    assert not kept.is_error
    assert text(kept) == "5"
    evictions = [e for e in gateway.seen.events() if e.get("event") == "approval_result_evicted"]
    assert [(e["ref"], e["reason"]) for e in evictions] == [(first, "client_bound")]


async def test_a_gateway_restart_withdraws_a_waiting_relay(tmp_path: Path, ca: ProviderCA) -> None:
    """A relay lives in the gateway that asked it (E.4): the gateway gone, a new one's epoch
    withdraws it at the vault (G-15), so the operator's late approval runs nothing; the new
    gateway holds no record or result of it, and the vault none for a relay, so the owner's
    ``check_approval`` reads ``unknown or expired``."""
    fake = McpFake()
    held = Held()
    with (
        held_deployment(tmp_path, ca, fake, held, relay=True) as gateway,
        gateway.vault_running() as vault,
    ):
        with gateway.gateway(vault) as first, anyio.fail_after(BOUND):
            async with agent(first) as owner:
                ref = ref_of(await owner.call_tool("echo", {"text": "lost with its gateway"}))
        with gateway.gateway(vault) as second, anyio.fail_after(BOUND):
            [hold] = await held.surface.holds(1)
            await held.surface.until(lambda: bool(held.surface.closed))
            await settled(gateway)
            app = gateway.vault.app
            late = await anyio.to_thread.run_sync(
                lambda: gateway.vault.call(
                    lambda: app.decide(hold.id, "approve", "portal", hold.text_sha256)
                )
            )
            async with agent(second) as owner:
                gone = await check(owner, ref)
        gateway.seen.outputs.append(text(gone))
    assert held.surface.closed == [(hold.id, "withdrawn")]
    assert isinstance(late, DecideRefusal)
    assert late.reason == "withdrawn"
    assert gone.is_error
    assert text(gone) == f"{checkapproval.UNKNOWN} (ref {ref})"
    assert fake.calls == []
    assert ledger(gateway, ref)[:2] == [("asked", "gateway"), ("decided", "pending")]


def test_the_pending_text_names_the_tool_to_collect_with() -> None:
    """The pending answer (F.1) and the tool's name agree, and the busy text names it too."""
    assert checkapproval.NAME == "check_approval"
    assert checkapproval.NAME in json.dumps(checkapproval.DEFINITION)
    assert elsewhere.TOO_LARGE.startswith("the call ran")
