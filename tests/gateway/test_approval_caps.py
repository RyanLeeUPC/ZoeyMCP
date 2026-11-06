"""The approval table's refusals end to end, before anyone is asked (M4 design B.2 step 5.8, B.3;
D-77, the pre-main test-debt pass).

The pure table is unit-tested (tests/unit/test_approvals.py); these are its rows through the
gateway, a real vault and the fake MCP server, as in :mod:`tests.gateway.test_approvals_remote`.
Each refusal asks nobody, writes nothing to the ledger and sends nothing, and the lock or slot it
was refused for frees as the rule says:

- another ``approve`` tool of the same client while one waits: ``pending_cap``, naming the
  waiting prompt's ref (both eras);
- the 31st prompt of a client in an hour (``max_prompts_per_hour``'s default 30): ``hourly_cap``,
  while another client is still asked;
- the table at :data:`.approvals.MAX_RECORDS` (1,024) records: ``table_full``, and asked again
  once one frees;
- a read-only ledger directory: the ``asked`` record can't be written, so ``LEDGER_DOWN``, and
  the next call is asked once the directory is writable again (both eras; POSIX permissions and
  not root, so CI's Linux runs it).

The fifth row, ``ledger --verify`` intact after a restart while a prompt waits, is a real
process's kill and restart: tests/acceptance/test_crash_recovery.py.
"""

from __future__ import annotations

import asyncio
import os
import re
import sys
from collections.abc import Callable
from pathlib import Path

import anyio
import httpx
import pytest
from mcp.types import CallToolResult

from tests.fakes.agent import ACCEPT, RawAgent, Script, Version, agent
from tests.gateway.rig import CLIENTS, SERVER, Deployed, Running, until
from tests.gateway.test_approval_recheck import BOUND, ERAS, Held, Outcome, asked_ref, call
from tests.gateway.test_approvals_remote import (
    ATTENDED,
    answered,
    approving,
    by_ref,
    headers,
    ledger_records,
    ref_of,
    text,
)
from zoeymcp.gateway import approvals
from zoeymcp.gateway.approvals import Key, Pending, Settings
from zoeymcp.gateway.approve import LEDGER_DOWN
from zoeymcp.gateway.ledger import LEDGER_DIR

pytestmark = pytest.mark.anyio

HOURLY = "refused: too many approval requests this hour"
PER_HOUR = 30  # the policy's default max_prompts_per_hour
FULL = "refused: too many approvals are waiting"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def on_loop[T](running: Running, work: Callable[[], T]) -> T:
    """``work`` run on the gateway's own event loop, as its handlers touch the table."""
    loop = None if running.served is None else running.served.loop
    assert loop is not None, "the gateway isn't served by this rig"

    async def run() -> T:
        return work()

    return asyncio.run_coroutine_threadsafe(run(), loop).result(10)


def refused(found: Outcome, said: str) -> str:
    """The refusal's own ref, once its text is ``said`` and that ref."""
    assert isinstance(found, CallToolResult)
    ref = ref_of(found)
    assert text(found) == f"{said} (ref {ref})"
    return ref


# --- the pending cap ----------------------------------------------------------------------------


@pytest.mark.parametrize("version", ERAS)
async def test_another_approve_tool_while_one_waits_is_refused(
    tmp_path: Path, version: Version
) -> None:
    """B.3 ``pending_cap`` (``max_pending_per_client`` 1): while ``echo``'s prompt waits, a call
    to ``slow``, another ``approve`` tool of the same client, is refused naming the waiting ref.
    Nobody is asked for it and nothing is recorded; the waiting prompt is unaffected and runs."""
    script = Held()
    with approving(tmp_path) as (deployed, running), anyio.fail_after(BOUND):
        async with agent(
            running.mcp(), version=version, script=script, headers=headers()
        ) as client:
            found: list[Outcome] = []
            async with anyio.create_task_group() as group:
                group.start_soon(call, client, found)
                await until(lambda: script.arrived)
                other = await client.call_tool("slow", {"steps": 1})
                script.go.set()
    waiting = asked_ref(deployed, "echo")
    ref = refused(other, f"refused: an approval is already waiting for this client (ref {waiting})")
    assert len(script.arrived) == 1
    assert by_ref(deployed, ref) == []
    assert [(e["tool"], e["reason"]) for e in deployed.events("approval_refused")] == [
        ("slow", "pending_cap")
    ]
    [first] = found
    assert isinstance(first, CallToolResult)
    assert text(first).endswith("hi")
    assert [c.name for c in deployed.fake.calls] == ["echo"]


# --- the hourly cap -----------------------------------------------------------------------------


async def test_the_31st_prompt_in_an_hour_is_refused(tmp_path: Path) -> None:
    """B.3 ``hourly_cap`` at its default (``max_prompts_per_hour`` 30): agent1's 31st call in the
    hour is refused before anyone is asked, while agent2, counted apart, is still asked. (Modern
    raw requests on one connection, an accept each: the cheapest way to ask 30 times.)"""
    both = {CLIENTS[0]: ATTENDED, CLIENTS[1]: ATTENDED}
    with approving(tmp_path, approvals=both) as (deployed, running), anyio.fail_after(BOUND):
        async with httpx.AsyncClient(timeout=30) as http:
            raw = RawAgent(running.mcp(), headers=headers())
            for number in range(PER_HOUR):
                arguments = {"text": f"call {number}"}
                asked = await raw.modern_call("echo", arguments, http=http)
                state = asked["result"]["requestState"]
                done = await raw.modern_call(
                    "echo", arguments, request_state=state, input_responses=answered(), http=http
                )
                assert done["result"]["content"][0]["text"].endswith(f"call {number}")
            over = await raw.modern_call("echo", {"text": "one more"}, http=http)
            other = await RawAgent(running.mcp(), headers=headers(CLIENTS[1])).modern_call(
                "echo", {"text": "another client"}, http=http
            )
    said = over["result"]["content"][0]["text"]
    found = re.fullmatch(rf"{re.escape(HOURLY)} \(ref ([0-9a-f]{{16}})\)", said)
    assert found is not None, said
    assert over["result"].get("resultType") != "input_required"
    assert other["result"]["resultType"] == "input_required"
    assert by_ref(deployed, found.group(1)) == []
    assert len(deployed.events("approval_asked")) == PER_HOUR + 1  # agent2's one is the last
    assert [e["reason"] for e in deployed.events("approval_refused")] == ["hourly_cap"]
    assert len(deployed.fake.calls) == PER_HOUR


# --- the table's own bound ----------------------------------------------------------------------


def filled(running: Running) -> list[Pending]:
    """The table filled to :data:`.approvals.MAX_RECORDS` with other clients' waiting records,
    each its own lock, made on the gateway's loop."""
    table = running.app.approvals.table
    settings = Settings(
        timeout=600.0,
        call_timeout=300.0,
        cooldown=0.0,
        max_pending_per_client=1,
        max_prompts_per_hour=30,
    )
    made: list[Pending] = []
    now = running.app.approvals.clock()
    for number in range(approvals.MAX_RECORDS - len(table)):
        begun = table.begin(
            Key(f"filler{number}", SERVER, "echo"),
            settings=settings,
            now=now,
            ref=f"{number:016x}",
            era="modern",
            args={},
            args_digest="",
            pin="",
            text_sha256="",
        )
        assert isinstance(begun, Pending), begun
        made.append(begun)
    assert len(table) == approvals.MAX_RECORDS
    return made


async def test_a_full_table_refuses_until_a_record_frees(tmp_path: Path) -> None:
    """B.3 ``table_full``: with 1,024 records waiting (other clients' locks), agent1's call is
    refused before anyone is asked and nothing is recorded; once one record frees, the same call
    is asked and runs."""
    script = Script([ACCEPT])
    with approving(tmp_path) as (deployed, running), anyio.fail_after(BOUND):
        fillers = await anyio.to_thread.run_sync(lambda: on_loop(running, lambda: filled(running)))
        async with agent(running.mcp(), script=script, headers=headers()) as client:
            full = await client.call_tool("echo", {"text": "hi"})
            assert script.prompts == []
            table = running.app.approvals.table
            first = fillers[0]

            def free_one() -> bool:
                clock = running.app.approvals.clock
                return table.finish(first.key, first.ref, clock(), settings_cooldown=0.0)

            assert await anyio.to_thread.run_sync(lambda: on_loop(running, free_one))
            again = await client.call_tool("echo", {"text": "hi"})
    ref = refused(full, FULL)
    assert by_ref(deployed, ref) == []
    assert [e["reason"] for e in deployed.events("approval_refused")] == ["table_full"]
    assert len(script.prompts) == 1
    assert text(again).endswith("hi")
    assert by_ref(deployed, ref_of_asked(deployed)) == [
        ("asked", "modern"),
        ("decided", "accept"),
        ("outcome", "ok"),
    ]
    assert [c.arguments for c in deployed.fake.calls] == [{"text": "hi"}]


def ref_of_asked(deployed: Deployed) -> str:
    [asked] = deployed.events("approval_asked")
    ref: str = asked["ref"]
    return ref


# --- a ledger that can't be written -------------------------------------------------------------


def posix_user() -> bool:
    """Whether a read-only directory refuses this process: POSIX permissions, and not root."""
    if sys.platform == "win32":
        return False
    return os.geteuid() != 0


POSIX_USER = pytest.mark.skipif(
    not posix_user(), reason="a read-only directory needs POSIX permissions, which root ignores"
)


@POSIX_USER
@pytest.mark.parametrize("version", ERAS)
async def test_a_read_only_ledger_directory_refuses_before_asking(
    tmp_path: Path, version: Version
) -> None:
    """F.3, B.2 step 5.9: the ledger directory is read-only, so the ``asked`` record (a new
    file) can't be written: the call is refused ``LEDGER_DOWN`` with nobody asked and nothing
    sent, and the lock is freed. Writable again, the next call is asked and runs, and the chain
    verifies."""
    script = Script([ACCEPT])
    with approving(tmp_path) as (deployed, running), anyio.fail_after(BOUND):
        directory = deployed.state / LEDGER_DIR
        assert list(directory.glob("*.jsonl")) == []
        directory.chmod(0o500)
        try:
            async with agent(
                running.mcp(), version=version, script=script, headers=headers()
            ) as client:
                down = await client.call_tool("echo", {"text": "hi"})
                assert script.prompts == []
                directory.chmod(0o700)
                again = await client.call_tool("echo", {"text": "hi"})
        finally:
            directory.chmod(0o700)
        ledger = running.app.ledger
        assert ledger is not None
        verified = ledger.verify()
    ref = refused(down, LEDGER_DOWN)
    [failed] = deployed.events("ledger_write_failed")
    assert (failed["record_kind"], failed["level"]) == ("asked", "critical")
    [refusal] = deployed.events("approval_refused")
    assert (refusal["ref"], refusal["reason"]) == (ref, "ledger_unavailable")
    assert all(record.ref != ref for record in ledger_records(deployed))
    assert len(script.prompts) == 1
    assert text(again).endswith("hi")
    assert [c.arguments for c in deployed.fake.calls] == [{"text": "hi"}]
    assert verified["ok"] is True
