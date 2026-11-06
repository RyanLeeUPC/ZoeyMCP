"""H3 and H7 at the gateway point (M4 design H; D-78's gateway half, the pre-main test-debt pass).

The vault point (racing decisions on a held call) is tests/gateway/test_vault_hold.py's. Here the
gateway itself holds the prompt, with a real vault and the fake MCP server behind it, as in
:mod:`tests.gateway.test_approvals_remote`, and the agent is raw modern requests:

- **H3**: 20 retries carrying one handle and an accept, sent at once, forward the call exactly
  once (``consume`` is atomic on the gateway's loop); the other 19 read ``already used``, the
  ledger holds one ``asked``, one ``decided accept`` and one ``outcome``, and the lock is free.
- **H7**: hypothesis draws sequences of outcomes (accept, decline, cancel, a retry with no
  answer, changed arguments, an answer that fails the SDK's parse, a replayed handle, a busy
  second call) and plays each against the one running gateway. After every outcome the lock is
  free (the table is empty), each ``asked`` so far has exactly one ``outcome``, and the upstream
  saw exactly the accepted calls. :data:`EXAMPLES` sequences of at most :data:`LONGEST` outcomes
  keep it to a few seconds; the table's own invariants run far more examples in
  tests/unit/test_approvals.py.

The gateway's cooldown is 0 and its hourly cap the most the policy allows, so a decline or a long
run never refuses the next ask: what is checked is the lock alone.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any, Literal

import anyio
import httpx
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from tests.fakes.agent import RawAgent
from tests.gateway.rig import Deployed, Running, until
from tests.gateway.test_approvals_remote import (
    answered,
    approving,
    by_ref,
    headers,
    ledger_records,
)

USED = "refused: approval expired or already used"
BOUND = 60
EXAMPLES = 12
LONGEST = 4
QUICK = {"cooldown": 0, "max_prompts_per_hour": 1000}


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def said(answer: dict[str, Any]) -> str:
    text: str = answer["result"]["content"][0]["text"]
    return text


# --- H3 -----------------------------------------------------------------------------------------


@pytest.mark.anyio
async def test_twenty_concurrent_retries_with_one_handle_forward_once(tmp_path: Path) -> None:
    """H3: one handle, 20 accepts at once; exactly one forward, 19 ``already used``."""
    limits = {"max_concurrent_per_client": 32}  # all 20 in flight at once
    with approving(tmp_path, limits=limits) as (deployed, running), anyio.fail_after(BOUND):
        raw = RawAgent(running.mcp(), headers=headers())
        state = (await raw.modern_call("echo", {"text": "once"}))["result"]["requestState"]
        answers: list[dict[str, Any]] = []

        async def retry(http: httpx.AsyncClient) -> None:
            answers.append(
                await raw.modern_call(
                    "echo",
                    {"text": "once"},
                    request_state=state,
                    input_responses=answered(),
                    http=http,
                )
            )

        limit = httpx.Limits(max_connections=20)
        async with (
            httpx.AsyncClient(timeout=30, limits=limit) as http,
            anyio.create_task_group() as group,
        ):
            for _ in range(20):
                group.start_soon(retry, http)
        await until(lambda: len(running.app.approvals.table) == 0)
        again = await raw.modern_call("echo", {"text": "once"})  # the lock is free: asked anew
    assert len(answers) == 20
    texts = Counter(said(answer) for answer in answers)
    [ran] = [text for text in texts if text != USED]
    assert ran.endswith("once")
    assert texts == Counter({ran: 1, USED: 19})
    assert [c.arguments for c in deployed.fake.calls] == [{"text": "once"}]
    [asked, _again] = [event["ref"] for event in deployed.events("approval_asked")]
    assert by_ref(deployed, asked) == [
        ("asked", "modern"),
        ("decided", "accept"),
        ("outcome", "ok"),
    ]
    assert again["result"]["resultType"] == "input_required"


# --- H7 -----------------------------------------------------------------------------------------

Outcome = Literal["accept", "decline", "cancel", "reask", "mismatch", "malformed", "replay", "busy"]
OUTCOMES: tuple[Outcome, ...] = (
    "accept",
    "decline",
    "cancel",
    "reask",
    "mismatch",
    "malformed",
    "replay",
    "busy",
)


class Player:
    """Plays outcomes against one running gateway, counting what should reach the upstream."""

    def __init__(self, deployed: Deployed, running: Running) -> None:
        self.deployed = deployed
        self.running = running
        self.raw = RawAgent(running.mcp(), headers=headers())
        self.sent: list[dict[str, Any]] = []
        self.played = 0
        self.http: httpx.AsyncClient | None = None  # one per example's event loop

    async def ask(self, arguments: dict[str, Any]) -> str:
        asked = await self.raw.modern_call("echo", arguments, http=self.http)
        assert asked["result"]["resultType"] == "input_required", asked
        state: str = asked["result"]["requestState"]
        return state

    async def answer(
        self, arguments: dict[str, Any], state: str, responses: object
    ) -> dict[str, Any]:
        return await self.raw.modern_call(
            "echo", arguments, request_state=state, input_responses=responses, http=self.http
        )

    async def play(self, outcome: Outcome) -> None:
        self.played += 1
        arguments = {"text": f"call {self.played}"}
        state = await self.ask(arguments)
        if outcome == "accept":
            assert said(await self.answer(arguments, state, answered())).endswith(arguments["text"])
            self.sent.append(arguments)
        elif outcome in ("decline", "cancel"):
            done = await self.answer(arguments, state, answered(outcome))
            assert said(done).startswith("declined by operator (ref ")
        elif outcome == "reask":
            again = await self.answer(arguments, state, None)
            state = again["result"]["requestState"]
            assert said(await self.answer(arguments, state, answered("decline"))).startswith(
                "declined by operator"
            )
        elif outcome == "mismatch":
            other = {"text": "something else"}
            done = await self.answer(other, state, answered())
            assert said(done).startswith("refused: this approval belongs to a different call")
        elif outcome == "malformed":
            nested = {"zoeymcp-approval": {"action": "accept", "content": {"a": {"deep": 1}}}}
            assert (await self.answer(arguments, state, nested))["error"]["code"] == -32602
        elif outcome == "replay":
            assert said(await self.answer(arguments, state, answered())).endswith(arguments["text"])
            self.sent.append(arguments)
            assert said(await self.answer(arguments, state, answered())) == USED
        else:  # busy: a second call while the first waits, then the first declined
            busy = await self.raw.modern_call("echo", {"text": "while it waits"}, http=self.http)
            assert "waiting or running" in said(busy)
            await self.answer(arguments, state, answered("decline"))
        await self.freed()

    async def freed(self) -> None:
        """The lock is free, every ``asked`` has exactly one ``outcome``, and the upstream saw
        exactly the accepted calls."""
        await until(lambda: len(self.running.app.approvals.table) == 0)
        records = ledger_records(self.deployed)
        asked = Counter(r.ref for r in records if r.kind == "asked")
        closed = Counter(r.ref for r in records if r.kind == "outcome")
        assert asked == closed, (asked, closed)
        assert len(asked) == self.played
        assert [c.arguments for c in self.deployed.fake.calls] == self.sent


def test_outcome_sequences_always_free_the_lock(tmp_path: Path) -> None:
    """H7: whatever order outcomes come in, each frees the lock and closes its record once."""
    with approving(tmp_path, gateway_approvals=QUICK) as (deployed, running):
        player = Player(deployed, running)

        async def play(sequence: list[Outcome]) -> None:
            with anyio.fail_after(BOUND):
                async with httpx.AsyncClient(timeout=30) as http:
                    player.http = http
                    for outcome in sequence:
                        await player.play(outcome)

        @settings(
            max_examples=EXAMPLES,
            deadline=None,
            database=None,
            suppress_health_check=[HealthCheck.too_slow],
        )
        @given(st.lists(st.sampled_from(OUTCOMES), min_size=1, max_size=LONGEST))
        def sequences(sequence: list[Outcome]) -> None:
            anyio.run(play, sequence)

        sequences()
    assert player.played >= EXAMPLES
