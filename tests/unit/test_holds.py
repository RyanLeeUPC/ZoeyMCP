"""The vault's hold table (M8 design B.4, D.3; O.3 ``test_holds.py``; Z6, Z8, Z23, FM-36).

The transition table, exhaustively and through every method; the caps and their refusals; ref
reuse; the endings a late answer is told; the saturation notice; every ordered pair of two events
against one hold (G-20); and a state machine over every method with M4 E.2's table properties
ported (one undecided hold per key, the caps, the hourly count).
"""

from __future__ import annotations

import base64
import io
import itertools
import re
from typing import Any, get_args

import pytest
from hypothesis import settings as hypothesis_settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, initialize, invariant, rule

from zoeymcp.common import logs
from zoeymcp.common.approvaltext import ApprovalText
from zoeymcp.vault import holds
from zoeymcp.vault.holds import (
    ENDINGS_SECONDS,
    HOUR,
    HOURLY_GLOBAL,
    MAX_HELD_BYTES,
    MAX_HOLDS,
    MAX_PER_ROUTE,
    MAX_PER_TOOL,
    RECENT_ENDINGS,
    SATURATION_WINDOW,
    TERMINAL,
    TOOLKIT_HOLD_MARGIN,
    TRANSITIONS,
    CapRefusal,
    Decided,
    DecideRefusal,
    Ending,
    Hold,
    HoldRequest,
    HoldTable,
    Limits,
    State,
    TransitionError,
    from_earlier_epoch,
    may_move,
    new_id,
    toolkit_block,
)

LIMITS = Limits(timeout=3600, block_seconds=120, cooldown=15, max_prompts_per_hour=30)
# No hourly cap below the global one, and no cooldown: for tests of the other caps.
OPEN = Limits(timeout=3600, block_seconds=120, cooldown=0, max_prompts_per_hour=1000)
TEXT = ApprovalText("Approval request 0123456789abcdef", frozenset(), ((0, None),))
DIGEST = "a" * 64
OTHER_DIGEST = "b" * 64
BOTH: frozenset[Any] = frozenset({"telegram", "portal"})
EPOCH = "0123456789ab"
ID = re.compile(r"[A-Za-z0-9_-]{16}")


def ref(number: int) -> str:
    return f"{number:016x}"


def request(
    number: int = 1,
    *,
    kind: Any = "held",
    route: str = "mail",
    server: str = "mail",
    tool: str = "send",
    client: str | None = "agent",
    wait: Any = "pending",
    surfaces: frozenset[Any] = BOTH,
    held_bytes: int = 100,
    epoch: str | None = EPOCH,
    legacy: bool = False,
    block: float | None = None,
) -> HoldRequest:
    return HoldRequest(
        ref=ref(number),
        kind=kind,
        epoch=epoch,
        legacy_session=legacy,
        route=route,
        server=server,
        tool=tool,
        client=client,
        args_digest="sha256:" + "c" * 64,
        text=TEXT,
        text_sha256=DIGEST,
        surfaces=surfaces,
        wait=wait,
        held_bytes=held_bytes,
        block_seconds=block,
    )


def begun(table: HoldTable, now: float = 0.0, number: int = 1, **fields: Any) -> Hold:
    result = table.begin(now, request(number, **fields))
    assert isinstance(result, Hold), result
    return result


def refused(table: HoldTable, now: float = 0.0, number: int = 1, **fields: Any) -> CapRefusal:
    result = table.begin(now, request(number, **fields))
    assert isinstance(result, CapRefusal), result
    return result


def approve(table: HoldTable, hold: Hold, now: float = 10.0, via: Any = "telegram") -> Hold:
    result = table.decide(now, hold.id, "approve", via, DIGEST)
    assert isinstance(result, Decided), result
    return result.hold


# --- the transition table ------------------------------------------------------------------------

EXPECTED: dict[str, set[str]] = {
    "held": {"approved", "denied", "expired", "withdrawn"},
    "approved": {"forwarding", "withdrawn"},
    "forwarding": {"done"},
    "done": set(),
    "denied": set(),
    "expired": set(),
    "withdrawn": set(),
}
STATES: tuple[Any, ...] = get_args(State)


def test_the_transition_table_is_closed() -> None:
    assert set(TRANSITIONS) == set(STATES) == set(EXPECTED)
    assert {state: set(targets) for state, targets in TRANSITIONS.items()} == EXPECTED
    assert {state for state in STATES if not TRANSITIONS[state]} == TERMINAL
    assert {"done", "denied", "expired", "withdrawn"} == TERMINAL
    assert {"denied", "expired"} == holds.COOLDOWN_STATES


@pytest.mark.parametrize(("current", "to"), list(itertools.product(STATES, STATES)))
def test_may_move_is_the_table(current: Any, to: Any) -> None:
    assert may_move(current, to) is (to in EXPECTED[current])


def at(state: str) -> tuple[HoldTable, Hold]:
    """A table with one hold brought to ``state`` (the clock at 20)."""
    table = HoldTable(LIMITS)
    hold = begun(table, wait="pending")
    if state in {"approved", "forwarding", "done"}:
        hold = approve(table, hold)
    if state in {"forwarding", "done"}:
        table.forwarding(hold.id)
    if state == "done":
        table.done(20.0, hold.id, "ok")
    if state == "denied":
        assert isinstance(table.decide(10.0, hold.id, "deny", "portal", DIGEST), Decided)
    if state == "expired":
        assert table.sweep(hold.deadline) != []
    if state == "withdrawn":
        assert table.withdraw(10.0, lambda h: True, "changed") != []
    return table, hold


def apply(operation: str, table: HoldTable, hold: Hold) -> str:
    """What ``operation`` does to ``hold`` now: its state after, a refusal's reason, ``raises``
    or ``gone`` (it isn't in the table)."""
    decision: Any = operation
    try:
        if operation in {"approve", "deny"}:
            answer = table.decide(30.0, hold.id, decision, "telegram", DIGEST)
            if isinstance(answer, DecideRefusal):
                return answer.reason
            return answer.hold.state
        if operation == "forwarding":
            table.forwarding(hold.id)
        elif operation == "done":
            table.done(30.0, hold.id, "ok")
        elif operation == "unrecorded":
            table.unrecorded(30.0, hold.id)
        elif operation == "withdraw":
            table.withdraw(30.0, lambda h: True, "changed")
        elif operation == "caller_gone":
            table.caller_gone(30.0, hold.id)
        elif operation == "detach":
            table.detach(30.0, hold.id)
        elif operation == "sweep":
            table.sweep(hold.deadline + 1)
    except TransitionError:
        return "raises"
    live = table.get(hold.id)
    if live is not None:
        return live.state
    ending = table.ending(hold.ref)
    return ending.state if ending is not None else "gone"


OPERATIONS = (
    "approve",
    "deny",
    "forwarding",
    "done",
    "unrecorded",
    "withdraw",
    "caller_gone",
    "detach",
    "sweep",
)
# operation -> the outcome from held, approved and forwarding.
LIVE_OUTCOMES: dict[str, tuple[str, str, str]] = {
    "approve": ("approved", "already_decided", "already_decided"),
    "deny": ("denied", "already_decided", "already_decided"),
    "forwarding": ("raises", "forwarding", "raises"),
    "done": ("raises", "raises", "done"),
    "unrecorded": ("raises", "withdrawn", "raises"),
    "withdraw": ("withdrawn", "approved", "forwarding"),
    "caller_gone": ("withdrawn", "approved", "forwarding"),
    "detach": ("held", "approved", "forwarding"),
    "sweep": ("expired", "approved", "forwarding"),
}
# A decision on an ended hold is refused by how it ended; every other move on it raises or
# changes nothing.
ENDED_DECISION = {
    "done": "already_decided",
    "denied": "already_decided",
    "expired": "expired",
    "withdrawn": "withdrawn",
}


@pytest.mark.parametrize(("operation", "state"), list(itertools.product(OPERATIONS, STATES)))
def test_every_method_from_every_state(operation: str, state: str) -> None:
    table, hold = at(state)
    if state in ("held", "approved", "forwarding"):
        expected = LIVE_OUTCOMES[operation][("held", "approved", "forwarding").index(state)]
    elif operation in {"approve", "deny"}:
        expected = ENDED_DECISION[state]
    elif operation in {"forwarding", "done", "unrecorded"}:
        expected = "raises"
    else:
        expected = state
    assert apply(operation, table, hold) == expected


# --- begin ---------------------------------------------------------------------------------------


def test_begin_holds_the_call() -> None:
    table = HoldTable(LIMITS)
    hold = begun(table, 100.0, kind="relay", client="agent", wait="block", held_bytes=7)
    assert ID.fullmatch(hold.id)
    expected = request(kind="relay", wait="block", held_bytes=7)
    for name in (
        "ref",
        "kind",
        "epoch",
        "legacy_session",
        "route",
        "server",
        "tool",
        "client",
        "args_digest",
        "text",
        "text_sha256",
        "surfaces",
        "wait",
        "held_bytes",
    ):
        assert getattr(hold, name) == getattr(expected, name), name
    assert (hold.asked_at, hold.block_until, hold.deadline) == (100.0, 220.0, 3700.0)
    assert (hold.state, hold.via, hold.detached, hold.decided_at, hold.detail) == (
        "held",
        None,
        False,
        None,
        None,
    )
    assert table.get(hold.id) == hold
    assert table.by_ref(hold.ref) == hold
    assert table.by_ref(ref(2)) is None
    assert table.get("x" * 16) is None
    assert list(table.holds()) == [hold]
    assert len(table) == 1
    assert table.knows(hold.ref)
    assert not table.knows(ref(2))
    other = begun(table, 100.0, 2, legacy=True, epoch=None, client=None)
    assert (other.legacy_session, other.epoch, other.client) == (True, None, None)
    assert other.id != hold.id
    assert list(table.holds()) == [hold, other]


def test_new_ids_are_twelve_random_bytes() -> None:
    values = {new_id() for _ in range(200)}
    assert len(values) == 200
    for value in values:
        assert ID.fullmatch(value)
        assert len(base64.urlsafe_b64decode(value)) == holds.ID_BYTES == 12


def test_a_block_never_passes_the_deadline() -> None:
    table = HoldTable(Limits(timeout=100, block_seconds=120, cooldown=0, max_prompts_per_hour=9))
    hold = begun(table, 50.0)
    assert (hold.block_until, hold.deadline) == (150.0, 150.0)


def test_a_toolkit_write_blocks_for_its_own_time() -> None:
    assert TOOLKIT_HOLD_MARGIN == 30.0
    assert toolkit_block(300) == 270.0
    assert toolkit_block(30) == 0.0
    assert toolkit_block(10) == 0.0
    table = HoldTable(LIMITS)
    hold = begun(table, 0.0, wait="block", block=toolkit_block(300))
    assert (hold.block_until, hold.deadline) == (270.0, 3600.0)
    assert hold.ends_at == 270.0
    assert begun(table, 0.0, 2, client="b", block=0.0).block_until == 0.0


def test_ends_at_is_the_block_only_for_a_blocking_hold() -> None:
    table = HoldTable(LIMITS)
    assert begun(table, wait="block").ends_at == 120.0
    assert begun(table, number=2, client="b", wait="pending").ends_at == 3600.0


def test_new_limits_apply_to_the_next_hold_only() -> None:
    table = HoldTable(LIMITS)
    first = begun(table)
    new = Limits(timeout=600, block_seconds=60, cooldown=0, max_prompts_per_hour=30)
    table.configure(new)
    assert table.limits == new
    second = begun(table, 0.0, 2, client="b")
    assert (first.block_until, first.deadline) == (120.0, 3600.0)
    assert (second.block_until, second.deadline) == (60.0, 600.0)


# --- the caps (D.3) ------------------------------------------------------------------------------


def test_the_constants() -> None:
    assert (MAX_HOLDS, MAX_HELD_BYTES, MAX_PER_ROUTE, MAX_PER_TOOL) == (64, 16 * 1024**2, 16, 4)
    assert (HOURLY_GLOBAL, HOUR, SATURATION_WINDOW) == (300, 3600.0, 600.0)
    assert (RECENT_ENDINGS, ENDINGS_SECONDS) == (4096, 86400.0)


def test_refusal_codes_and_statuses() -> None:
    for reason in ("capacity", "busy", "hourly", "cooldown"):
        refusal = CapRefusal(reason)
        assert (refusal.code, refusal.status) == (f"held_{reason}", 429)
    assert (CapRefusal("ref_reused").code, CapRefusal("ref_reused").status) == (
        "held_ref_reused",
        409,
    )
    assert CapRefusal("busy").seconds_left == 0


def test_the_hold_count_is_capped() -> None:
    table = HoldTable(OPEN)
    first = begun(table, 0.0, 0, route="r0", tool="t0")
    for number in range(1, MAX_HOLDS):
        begun(table, 0.0, number, route=f"r{number % 16}", tool=f"t{number}")
    assert len(table) == MAX_HOLDS
    assert refused(table, 0.0, 100, route="other", tool="other").reason == "capacity"
    approve(table, first, 1.0)
    assert refused(table, 1.0, 100, route="other", tool="other").reason == "capacity"
    table.forwarding(first.id)
    table.done(2.0, first.id, "ok")
    begun(table, 2.0, 100, route="other", tool="other")


def test_held_bytes_are_capped() -> None:
    table = HoldTable(OPEN)
    first = begun(table, 0.0, 1, tool="a", held_bytes=MAX_HELD_BYTES - 10)
    begun(table, 0.0, 2, tool="b", held_bytes=10)
    assert refused(table, 0.0, 3, tool="c", held_bytes=1).reason == "capacity"
    table.withdraw(1.0, lambda h: h.id == first.id, "changed")
    begun(table, 1.0, 3, tool="c", held_bytes=MAX_HELD_BYTES - 10)
    assert refused(table, 1.0, 4, tool="d", held_bytes=1).reason == "capacity"
    begun(table, 1.0, 5, tool="d", held_bytes=0)


def test_holds_are_capped_per_route() -> None:
    table = HoldTable(OPEN)
    for number in range(MAX_PER_ROUTE):
        begun(table, 0.0, number, route="mail", tool=f"t{number}")
    assert refused(table, 0.0, 100, route="mail", tool="new").reason == "capacity"
    begun(table, 0.0, 101, route="other", tool="new")


def test_holds_are_capped_per_route_and_tool() -> None:
    table = HoldTable(OPEN)
    first = begun(table, 0.0, 0, client="c0")
    for number in range(1, MAX_PER_TOOL):
        begun(table, 0.0, number, client=f"c{number}")
    assert refused(table, 0.0, 100, client="new").reason == "capacity"
    begun(table, 0.0, 101, client="new", tool="other")
    begun(table, 0.0, 102, client="new", route="other", server="other")
    # An approved hold still counts until its forward is done.
    approve(table, first, 1.0)
    assert refused(table, 1.0, 103, client="new").reason == "capacity"
    table.forwarding(first.id)
    table.done(2.0, first.id, "ok")
    begun(table, 2.0, 103, client="new")


def test_one_undecided_hold_per_reported_client_server_and_tool() -> None:
    table = HoldTable(OPEN)
    first = begun(table, 0.0, 1)
    assert refused(table, 0.0, 2).reason == "busy"
    begun(table, 0.0, 3, client="other")
    begun(table, 0.0, 4, tool="other")
    begun(table, 0.0, 5, server="other")
    # A call with no reported client has no fairness key: the per-tool cap bounds those.
    begun(table, 0.0, 6, client=None, tool="third")
    begun(table, 0.0, 7, client=None, tool="third")
    # Fairness counts undecided holds only: once decided, the client may ask again.
    approve(table, first, 1.0)
    begun(table, 1.0, 8)


def test_the_hourly_cap_per_route_and_tool_is_rolling() -> None:
    table = HoldTable(Limits(timeout=3600, block_seconds=120, cooldown=0, max_prompts_per_hour=2))
    for number, now in ((1, 0.0), (2, 100.0)):
        begun(table, now, number)
        table.withdraw(now, lambda h: True, "changed")
    assert refused(table, 200.0, 3).reason == "hourly"
    assert refused(table, HOUR - 1, 3).reason == "hourly"
    begun(table, 200.0, 4, tool="other")
    begun(table, HOUR, 5, client="b")
    assert refused(table, HOUR, 6, client="c").reason == "hourly"
    begun(table, HOUR + 100, 7, client="c")


def test_the_global_hourly_cap() -> None:
    table = HoldTable(OPEN)
    for number in range(HOURLY_GLOBAL):
        begun(table, float(number), number, tool=f"t{number % 7}", route=f"r{number % 5}")
        table.withdraw(float(number), lambda h: True, "changed")
    assert refused(table, 400.0, 1000, tool="new", route="new").reason == "hourly"
    assert refused(table, HOUR - 1, 1000, tool="new", route="new").reason == "hourly"
    begun(table, HOUR, 1000, tool="new", route="new")
    assert refused(table, HOUR, 1001, tool="new2", route="new").reason == "hourly"


def test_a_deny_starts_the_cooldown_for_the_route_and_tool() -> None:
    table = HoldTable(LIMITS)
    hold = begun(table, 0.0)
    assert isinstance(table.decide(100.0, hold.id, "deny", "portal", DIGEST), Decided)
    refusal = refused(table, 100.0, 2, client="b")
    assert (refusal.reason, refusal.seconds_left) == ("cooldown", 15)
    assert refused(table, 100.5, 2, client="b").seconds_left == 15
    assert refused(table, 114.5, 2, client="b").seconds_left == 1
    assert refused(table, 114.99, 2, client="b").seconds_left == 1
    begun(table, 100.0, 3, tool="other")
    begun(table, 100.0, 4, route="other")
    begun(table, 115.0, 2, client="b")


def test_an_expiry_starts_the_cooldown() -> None:
    table = HoldTable(LIMITS)
    hold = begun(table, 0.0, wait="block")
    assert table.sweep(120.0) != []
    assert refused(table, 120.0, 2).reason == "cooldown"
    begun(table, 135.0, 2)
    assert hold.ends_at == 120.0


@pytest.mark.parametrize("ending", ["withdraw", "caller_gone", "done", "unrecorded"])
def test_other_endings_start_no_cooldown(ending: str) -> None:
    table = HoldTable(LIMITS)
    hold = begun(table, 0.0)
    if ending == "withdraw":
        table.withdraw(10.0, lambda h: True, "changed")
    elif ending == "caller_gone":
        table.caller_gone(10.0, hold.id)
    else:
        approve(table, hold)
        if ending == "done":
            table.forwarding(hold.id)
            table.done(10.0, hold.id, "tool_error")
        else:
            table.unrecorded(10.0, hold.id)
    assert not table.knows(ref(2))
    begun(table, 10.0, 2)


def test_no_cooldown_when_it_is_zero() -> None:
    table = HoldTable(OPEN)
    hold = begun(table, 0.0)
    assert isinstance(table.decide(10.0, hold.id, "deny", "portal", DIGEST), Decided)
    begun(table, 10.0, 2)


# --- ref reuse (E19, T-10) -----------------------------------------------------------------------


def test_ref_reused() -> None:
    """FM-36: a ref held, decided, ended or recovered from the chain is never held again, and
    the refusal isn't a cap's (it doesn't count towards saturation)."""
    table = HoldTable(LIMITS)
    hold = begun(table, 0.0, 1)
    refusal = refused(table, 0.0, 1, client="b", tool="other", route="other")
    assert (refusal.reason, refusal.code, refusal.status) == ("ref_reused", "held_ref_reused", 409)
    approve(table, hold)
    assert refused(table, 10.0, 1, client="b").reason == "ref_reused"
    table.forwarding(hold.id)
    table.done(20.0, hold.id, "ok")
    assert table.knows(ref(1))
    assert refused(table, 20.0, 1, client="b").reason == "ref_reused"
    table.remember(20.0, ref(9), "withdrawn", "abandoned", client="agent", ended_at=20.0)
    assert table.knows(ref(9))
    assert refused(table, 20.0, 9, client="b").reason == "ref_reused"
    assert table.saturated(20.0) == 0
    assert table.notice(20.0) is None
    # Past its day, the table forgets it (the chain's open-ref index is the caller's half).
    assert refused(table, 20.0 + ENDINGS_SECONDS - 1, 1, client="b").reason == "ref_reused"
    begun(table, 20.0 + ENDINGS_SECONDS, 1, client="b")


# --- endings -------------------------------------------------------------------------------------


def test_an_ending_says_how_the_hold_ended() -> None:
    table = HoldTable(OPEN)
    denied = begun(table, 0.0, 1)
    assert isinstance(table.decide(5.0, denied.id, "deny", "portal", DIGEST), Decided)
    assert table.ending(denied.ref) == Ending(
        denied.ref, denied.id, "agent", "denied", "portal", 5.0, None, 5.0
    )
    withdrawn = begun(table, 5.0, 2, client="b")
    table.withdraw(6.0, lambda h: True, "host", via="host")
    assert table.ending(withdrawn.ref) == Ending(
        withdrawn.ref, withdrawn.id, "b", "withdrawn", "host", 6.0, "host", 6.0
    )
    done = begun(table, 6.0, 3, client="c", tool="other")
    approve(table, done, 7.0)
    table.forwarding(done.id)
    table.done(9.0, done.id, "upstream_error")
    assert table.ending(done.ref) == Ending(
        done.ref, done.id, "c", "done", "telegram", 7.0, "upstream_error", 9.0
    )
    table.remember(10.0, ref(4), "done", None, client=None, ended_at=10.0)
    assert table.ending(ref(4)) == Ending(ref(4), None, None, "done", None, None, None, 10.0)
    assert table.ending(ref(5)) is None
    assert len(table) == 0


def test_endings_are_bounded() -> None:
    table = HoldTable(LIMITS)
    hold = begun(table, 0.0)
    assert isinstance(table.decide(1.0, hold.id, "deny", "portal", DIGEST), Decided)
    for number in range(2, RECENT_ENDINGS + 1):
        table.remember(2.0, ref(number), "withdrawn", client="agent", ended_at=2.0)
    assert table.knows(hold.ref)
    assert table.decide(2.0, hold.id, "approve", "portal", DIGEST) == DecideRefusal(
        "already_decided", "portal", 1.0
    )
    table.remember(2.0, ref(RECENT_ENDINGS + 1), "withdrawn", client="agent", ended_at=2.0)
    assert not table.knows(hold.ref)
    assert table.ending(hold.ref) is None
    assert table.knows(ref(2))
    assert table.decide(2.0, hold.id, "approve", "portal", DIGEST) == DecideRefusal("unknown")


def test_endings_last_a_day() -> None:
    table = HoldTable(LIMITS)
    hold = begun(table, 0.0)
    table.withdraw(100.0, lambda h: True, "changed")
    table.remember(200.0, ref(2), "withdrawn", client="agent", ended_at=200.0)
    table.sweep(100.0 + ENDINGS_SECONDS - 1)
    assert table.knows(hold.ref)
    table.sweep(100.0 + ENDINGS_SECONDS)
    assert not table.knows(hold.ref)
    assert table.knows(ref(2))
    assert table.decide(100.0 + ENDINGS_SECONDS, hold.id, "approve", "portal", DIGEST) == (
        DecideRefusal("unknown")
    )
    table.sweep(200.0 + ENDINGS_SECONDS)
    assert not table.knows(ref(2))


def test_endings_are_forgotten_oldest_first() -> None:
    """In the order they ended: a younger ending stops the pruning, whatever comes after it."""
    table = HoldTable(LIMITS)
    table.remember(100.0, ref(1), "withdrawn", client="agent", ended_at=100.0)
    table.remember(100.0, ref(2), "withdrawn", client="agent", ended_at=50.0)
    table.sweep(50.0 + ENDINGS_SECONDS)
    assert table.knows(ref(1))
    assert table.knows(ref(2))
    table.sweep(100.0 + ENDINGS_SECONDS)
    assert not table.knows(ref(1))
    assert not table.knows(ref(2))


def test_a_remembered_ending_keeps_its_client_and_its_own_time() -> None:
    """F.5 step 4: recovery gives the reported client and when the call ended, so the ending
    is told to that client only and lasts a day from its end, not from the restart."""
    table = HoldTable(LIMITS)
    table.remember(1000.0, ref(1), "withdrawn", "stream_lost", client="agent", ended_at=400.0)
    assert table.ending(ref(1)) == Ending(
        ref(1), None, "agent", "withdrawn", None, None, "stream_lost", 400.0
    )
    table.sweep(400.0 + ENDINGS_SECONDS - 1)
    assert table.knows(ref(1))
    table.sweep(400.0 + ENDINGS_SECONDS)
    assert not table.knows(ref(1))
    # One already a day old when recovery finds it isn't kept.
    table.remember(1000.0, ref(2), "done", "ok", client="agent", ended_at=1000.0 - ENDINGS_SECONDS)
    assert not table.knows(ref(2))
    table.remember(1000.0, ref(3), "done", "ok", client=None, ended_at=1001.0 - ENDINGS_SECONDS)
    assert table.ending(ref(3)) == Ending(
        ref(3), None, None, "done", None, None, "ok", 1001.0 - ENDINGS_SECONDS
    )


# --- decide --------------------------------------------------------------------------------------


def test_an_approval_is_taken_once() -> None:
    table = HoldTable(LIMITS)
    hold = begun(table, 0.0)
    answer = table.decide(10.0, hold.id, "approve", "telegram", DIGEST)
    assert isinstance(answer, Decided)
    assert (answer.hold.state, answer.hold.via, answer.hold.decided_at) == (
        "approved",
        "telegram",
        10.0,
    )
    assert table.get(hold.id) == answer.hold
    assert table.decide(11.0, hold.id, "approve", "portal", DIGEST) == DecideRefusal(
        "already_decided", "telegram", 10.0
    )
    assert table.decide(11.0, hold.id, "deny", "telegram", OTHER_DIGEST) == DecideRefusal(
        "already_decided", "telegram", 10.0
    )


def test_a_denial_ends_the_hold() -> None:
    table = HoldTable(LIMITS)
    hold = begun(table, 0.0)
    answer = table.decide(10.0, hold.id, "deny", "portal", DIGEST)
    assert isinstance(answer, Decided)
    assert (answer.hold.state, answer.hold.via, answer.hold.decided_at) == (
        "denied",
        "portal",
        10.0,
    )
    assert table.get(hold.id) is None
    assert len(table) == 0
    assert table.decide(11.0, hold.id, "approve", "telegram", DIGEST) == DecideRefusal(
        "already_decided", "portal", 10.0
    )


def test_a_decision_on_an_unknown_hold() -> None:
    table = HoldTable(LIMITS)
    assert table.decide(0.0, "x" * 16, "approve", "portal", DIGEST) == DecideRefusal("unknown")


@pytest.mark.parametrize("via", ["host", "none", "portal"])
def test_a_decision_from_a_surface_that_doesnt_show_it(via: Any) -> None:
    table = HoldTable(LIMITS)
    hold = begun(table, 0.0, surfaces=frozenset({"telegram"}))
    assert table.decide(1.0, hold.id, "approve", via, DIGEST) == DecideRefusal("unknown")
    assert table.get(hold.id) == hold


def test_a_decision_at_the_end_is_expired() -> None:
    table = HoldTable(LIMITS)
    blocking = begun(table, 0.0, 1, wait="block")
    pending = begun(table, 0.0, 2, client="b", wait="pending")
    assert table.decide(120.0, blocking.id, "approve", "portal", DIGEST) == DecideRefusal("expired")
    assert table.get(blocking.id) == blocking  # the sweeper ends it, not the decision
    assert isinstance(table.decide(3599.0, pending.id, "deny", "portal", DIGEST), Decided)
    third = begun(table, 0.0, 3, client="c", tool="x")
    assert table.decide(3600.0, third.id, "approve", "portal", DIGEST) == DecideRefusal("expired")
    fourth = begun(table, 0.0, 4, client="d", tool="y", wait="block")
    assert isinstance(table.decide(119.0, fourth.id, "approve", "portal", DIGEST), Decided)


def test_a_decision_on_another_text_is_digest_changed() -> None:
    table = HoldTable(LIMITS)
    hold = begun(table, 0.0)
    decisions: tuple[Any, ...] = ("approve", "deny")
    for decision in decisions:
        answer = table.decide(1.0, hold.id, decision, "portal", OTHER_DIGEST)
        assert answer == DecideRefusal("digest_changed")
    assert table.get(hold.id) == hold


def test_a_late_decision_is_told_what_happened() -> None:
    table = HoldTable(LIMITS)
    expired = begun(table, 0.0, 1, wait="block")
    table.sweep(120.0)
    assert table.decide(121.0, expired.id, "approve", "portal", DIGEST) == DecideRefusal("expired")
    withdrawn = begun(table, 200.0, 2, client="b")
    table.withdraw(201.0, lambda h: True, "changed")
    assert table.decide(202.0, withdrawn.id, "approve", "portal", DIGEST) == DecideRefusal(
        "withdrawn"
    )
    done = begun(table, 200.0, 3, client="c", tool="other")
    approve(table, done, 210.0, "portal")
    table.forwarding(done.id)
    table.done(220.0, done.id, "ok")
    assert table.decide(230.0, done.id, "approve", "telegram", DIGEST) == DecideRefusal(
        "already_decided", "portal", 210.0
    )


# --- the caller, detaching, the forward ----------------------------------------------------------


def test_a_caller_gone_withdraws_an_undecided_hold() -> None:
    table = HoldTable(LIMITS)
    hold = begun(table, 0.0, wait="pending")
    gone = table.caller_gone(5.0, hold.id)
    assert gone is not None
    assert (gone.state, gone.via, gone.detail, gone.decided_at) == (
        "withdrawn",
        "none",
        "stream_lost",
        5.0,
    )
    assert table.get(hold.id) is None
    assert table.caller_gone(6.0, hold.id) is None
    assert table.caller_gone(6.0, "x" * 16) is None


def test_a_caller_gone_after_approval_lets_the_forward_finish() -> None:
    table = HoldTable(LIMITS)
    hold = approve(table, begun(table, 0.0, wait="block"))
    assert table.caller_gone(11.0, hold.id) is None
    after = table.get(hold.id)
    assert after is not None
    assert (after.state, after.detached) == ("approved", True)
    assert table.caller_gone(12.0, hold.id) is None
    table.forwarding(hold.id)
    forwarding = table.get(hold.id)
    assert forwarding is not None
    assert (forwarding.state, forwarding.detached) == ("forwarding", True)


def test_a_detached_hold_has_no_caller_to_lose() -> None:
    table = HoldTable(LIMITS)
    hold = begun(table, 0.0, wait="pending")
    detached = table.detach(120.0, hold.id)
    assert detached is not None
    assert (detached.state, detached.detached) == ("held", True)
    assert table.get(hold.id) == detached
    assert table.caller_gone(121.0, hold.id) is None
    assert table.get(hold.id) == detached
    assert table.detach(122.0, hold.id) is None
    # It lives on to its deadline, not its block.
    assert table.sweep(3599.0) == []
    expired = table.sweep(3600.0)
    assert [h.id for h in expired] == [hold.id]


def test_a_blocking_only_hold_doesnt_detach() -> None:
    table = HoldTable(LIMITS)
    hold = begun(table, 0.0, wait="block")
    assert table.detach(10.0, hold.id) is None
    assert table.get(hold.id) == hold
    assert table.detach(10.0, "x" * 16) is None


def test_an_approved_hold_detaches() -> None:
    table = HoldTable(LIMITS)
    hold = approve(table, begun(table, 0.0, wait="pending"))
    detached = table.detach(11.0, hold.id)
    assert detached is not None
    assert (detached.state, detached.detached, detached.via) == ("approved", True, "telegram")


def test_the_forward_runs_once_and_records_its_outcome() -> None:
    table = HoldTable(LIMITS)
    hold = approve(table, begun(table, 0.0))
    with pytest.raises(TransitionError, match="approved -> done"):
        table.done(11.0, hold.id, "ok")
    table.forwarding(hold.id)
    forwarding = table.get(hold.id)
    assert forwarding is not None
    assert (forwarding.state, forwarding.decided_at) == ("forwarding", 10.0)
    with pytest.raises(TransitionError, match="forwarding -> forwarding"):
        table.forwarding(hold.id)
    table.done(30.0, hold.id, "tool_error")
    assert table.get(hold.id) is None
    ending = table.ending(hold.ref)
    assert ending is not None
    assert (ending.state, ending.detail, ending.via, ending.ended_at) == (
        "done",
        "tool_error",
        "telegram",
        30.0,
    )
    with pytest.raises(TransitionError, match="no live hold"):
        table.done(31.0, hold.id, "ok")
    with pytest.raises(TransitionError):
        table.forwarding(hold.id)


def test_an_unrecorded_approval_is_withdrawn_unsent() -> None:
    table = HoldTable(LIMITS)
    held = begun(table, 0.0)
    with pytest.raises(TransitionError, match="held -> withdrawn"):
        table.unrecorded(1.0, held.id)
    hold = approve(table, held)
    gone = table.unrecorded(12.0, hold.id)
    assert (gone.state, gone.detail, gone.via, gone.decided_at) == (
        "withdrawn",
        "ledger",
        "telegram",
        10.0,
    )
    assert table.get(hold.id) is None
    with pytest.raises(TransitionError):
        table.unrecorded(13.0, hold.id)


def test_withdraw_takes_only_the_undecided_holds_it_picks() -> None:
    table = HoldTable(LIMITS)
    picked = begun(table, 0.0, 1, tool="a")
    left = begun(table, 0.0, 2, tool="b")
    approved = approve(table, begun(table, 0.0, 3, tool="a", client="c"))
    gone = table.withdraw(5.0, lambda h: h.tool == "a", "changed")
    assert [(h.id, h.state, h.detail, h.via) for h in gone] == [
        (picked.id, "withdrawn", "changed", "none")
    ]
    assert table.get(left.id) == left
    assert table.get(approved.id) == approved
    assert table.withdraw(6.0, lambda h: False, "changed") == []
    by_host = table.withdraw(6.0, lambda h: True, "host", via="host")
    assert [(h.id, h.via, h.detail) for h in by_host] == [(left.id, "host", "host")]


def test_the_sweep_expires_undecided_holds_at_their_end() -> None:
    table = HoldTable(LIMITS)
    blocking = begun(table, 0.0, 1, wait="block")
    pending = begun(table, 0.0, 2, client="b", wait="pending")
    approved = approve(table, begun(table, 0.0, 3, client="c", wait="block"))
    assert table.sweep(119.0) == []
    expired = table.sweep(120.0)
    assert [(h.id, h.state, h.via, h.decided_at) for h in expired] == [
        (blocking.id, "expired", "none", 120.0)
    ]
    assert table.sweep(3599.0) == []
    assert [h.id for h in table.sweep(3600.0)] == [pending.id]
    assert table.get(approved.id) == approved
    assert table.sweep(99999.0) == []


@pytest.mark.parametrize(
    ("kind", "legacy", "epoch", "picked"),
    [
        ("relay", False, "aaaaaaaaaaaa", True),
        ("held", True, "aaaaaaaaaaaa", True),
        ("held", False, "aaaaaaaaaaaa", False),
        ("relay", True, EPOCH, False),
        ("held", True, EPOCH, False),
        ("relay", True, None, False),
    ],
)
def test_a_new_gateway_epoch_picks_relays_and_legacy_holds(
    kind: Any, legacy: bool, epoch: str | None, picked: bool
) -> None:
    table = HoldTable(LIMITS)
    hold = begun(table, kind=kind, legacy=legacy, epoch=epoch)
    assert from_earlier_epoch(EPOCH)(hold) is picked


# --- saturation ----------------------------------------------------------------------------------


def test_one_saturation_notice_per_window() -> None:
    table = HoldTable(OPEN)
    assert table.notice(0.0) is None
    begun(table, 0.0, 1)
    assert refused(table, 0.0, 2).reason == "busy"
    assert refused(table, 0.0, 3).reason == "busy"
    assert table.saturated(0.0) == 2
    assert table.notice(0.0) == 2
    assert refused(table, 300.0, 4).reason == "busy"
    assert table.notice(300.0) is None
    assert table.notice(599.0) is None
    assert table.saturated(599.0) == 3
    assert table.saturated(600.0) == 1
    assert table.notice(600.0) == 1
    assert table.notice(700.0) is None
    assert table.saturated(900.0) == 0
    assert table.notice(1300.0) is None


def test_refusals_are_pruned_without_a_reader() -> None:
    """Z8: a refusal flood is remembered for one window only, whoever polls ``saturated``."""
    table = HoldTable(OPEN)
    begun(table, 0.0, 1)
    for number in range(2, 202):
        assert refused(table, float(number * 6), number).reason == "busy"
    # A refusal every 6 s for 20 minutes, and no saturated() call: one window's worth is kept.
    assert len(table._refused) == SATURATION_WINDOW / 6
    table.sweep(1206.0 + SATURATION_WINDOW)
    assert len(table._refused) == 0


# --- secrets -------------------------------------------------------------------------------------


def test_holds_hide_their_text_and_refuse_to_be_logged() -> None:
    table = HoldTable(LIMITS)
    hold = begun(table)
    assert repr(hold) == f"Hold(id={hold.id}, ref={ref(1)}, state=held)"
    assert "Approval" not in repr(request())
    log = logs.Log("vault")
    stream = io.StringIO()
    logs.set_stream(stream)
    try:
        for value in (hold, request()):
            with pytest.raises(TypeError):
                log.event("probe", value=value)
    finally:
        logs.set_stream(None)
    assert stream.getvalue() == ""


# --- every ordered pair of two events (G-20) -----------------------------------------------------

EVENTS = (
    "press_approve",
    "press_deny",
    "portal_confirm",
    "portal_deny",
    "agent_withdraw",
    "caller_gone",
    "detach",
    "sweep_expiry",
    "policy_change",
    "stop",
    "new_epoch",
)


class Vault:
    """The vault's side of one hold, as the app drives the table: chain records before the
    forward, a forward only from an approved decision, and the forward run once both events
    have happened (so the second event meets an approved hold)."""

    def __init__(self) -> None:
        self.table = HoldTable(LIMITS)
        self.hold = begun(self.table, 0.0, wait="pending", legacy=True)
        self.now = 10.0
        self.chain: list[tuple[str, str]] = []
        self.sent = 0

    def decide(self, decision: Any, via: Any) -> None:
        answer = self.table.decide(self.now, self.hold.id, decision, via, DIGEST)
        if isinstance(answer, Decided):
            self.closed(answer.hold)

    def closed(self, hold: Hold) -> None:
        if hold.state == "approved":
            self.chain.append(("decided", "accept"))
            return
        decision = {"denied": "decline", "expired": "timeout"}.get(hold.state, "withdrawn")
        self.chain += [("decided", decision), ("outcome", "not_sent")]

    def event(self, name: str) -> None:
        if name == "press_approve":
            self.decide("approve", "telegram")
        elif name == "press_deny":
            self.decide("deny", "telegram")
        elif name == "portal_confirm":
            self.decide("approve", "portal")
        elif name == "portal_deny":
            self.decide("deny", "portal")
        elif name == "caller_gone":
            gone = self.table.caller_gone(self.now, self.hold.id)
            if gone is not None:
                self.closed(gone)
        elif name == "detach":
            self.table.detach(self.now, self.hold.id)
        elif name == "sweep_expiry":
            self.now = max(self.now, self.hold.deadline)
            for hold in self.table.sweep(self.now):
                self.closed(hold)
        else:
            which = {
                "agent_withdraw": lambda h: h.ref == self.hold.ref,
                "policy_change": lambda h: True,
                "stop": lambda h: True,
                "new_epoch": from_earlier_epoch("bbbbbbbbbbbb"),
            }[name]
            for hold in self.table.withdraw(self.now, which, name):
                self.closed(hold)
        self.now += 1

    def finish(self) -> None:
        """The approved forward runs; an undecided hold runs out its time."""
        live = self.table.get(self.hold.id)
        if live is not None and live.state == "approved":
            self.table.forwarding(live.id)
            self.sent += 1
            self.table.done(self.now, live.id, "ok")
            self.chain.append(("outcome", "ok"))
        elif live is not None:
            for hold in self.table.sweep(self.hold.deadline):
                self.closed(hold)


@pytest.mark.parametrize(("first", "second"), list(itertools.product(EVENTS, EVENTS)))
def test_every_pair_of_events_forwards_once_or_sends_nothing(first: str, second: str) -> None:
    vault = Vault()
    vault.event(first)
    vault.event(second)
    vault.finish()
    outcomes = [value for kind, value in vault.chain if kind == "outcome"]
    decisions = [value for kind, value in vault.chain if kind == "decided"]
    assert len(outcomes) == 1
    assert len(decisions) == 1
    if outcomes == ["ok"]:
        assert (vault.sent, decisions) == (1, ["accept"])
    else:
        assert outcomes == ["not_sent"]
        assert vault.sent == 0
        assert decisions != ["accept"]
    assert len(vault.table) == 0
    assert vault.table.knows(vault.hold.ref)
    # Approving first wins over everything after it; anything else that ends it first wins.
    if first in {"press_approve", "portal_confirm"}:
        assert vault.sent == 1


# --- the state machine (B.4; M4 E.2's properties ported) -----------------------------------------

ROUTES = ("mail", "broker")
TOOLS = ("send", "order")
CLIENTS = ("a", "b", None)
TIGHT = Limits(timeout=300, block_seconds=60, cooldown=20, max_prompts_per_hour=3)


class HoldMachine(RuleBasedStateMachine):
    @initialize()
    def start(self) -> None:
        self.table = HoldTable(TIGHT)
        self.now = 0.0
        self.count = 0
        self.ids: list[str] = []
        self.approved: set[str] = set()
        self.forwarded: set[str] = set()
        self.begins: list[tuple[float, str, str]] = []
        self.cooldowns: dict[tuple[str, str], float] = {}  # (route, tool) -> until

    @rule(
        route=st.sampled_from(ROUTES),
        tool=st.sampled_from(TOOLS),
        client=st.sampled_from(CLIENTS),
        wait=st.sampled_from(["block", "pending"]),
        legacy=st.booleans(),
    )
    def begin(self, route: str, tool: str, client: str | None, wait: str, legacy: bool) -> None:
        self.count += 1
        before = list(self.table.holds())
        result = self.table.begin(
            self.now,
            request(self.count, route=route, tool=tool, client=client, wait=wait, legacy=legacy),
        )
        if isinstance(result, Hold):
            # No hold begins while its (route, tool) cools down after a deny or an expiry.
            assert self.now >= self.cooldowns.get((route, tool), self.now)
            self.ids.append(result.id)
            self.begins.append((self.now, route, tool))
        elif result.reason == "busy":
            # The per-key lock is held only by an undecided hold of a reported client's key.
            assert client is not None
            assert any(
                h.state == "held" and (h.client, h.server, h.tool) == (client, "mail", tool)
                for h in before
            )

    @rule(
        data=st.data(),
        decision=st.sampled_from(["approve", "deny"]),
        via=st.sampled_from(["telegram", "portal"]),
        right=st.booleans(),
    )
    def decide(self, data: st.DataObject, decision: Any, via: Any, right: bool) -> None:
        if not self.ids:
            return
        id = data.draw(st.sampled_from(self.ids))
        before = self.table.get(id)
        answer = self.table.decide(self.now, id, decision, via, DIGEST if right else OTHER_DIGEST)
        if isinstance(answer, Decided):
            assert before is not None
            assert before.state == "held"
            assert right
            assert self.now < before.ends_at
            if answer.hold.state == "approved":
                assert id not in self.approved  # at most one approval per hold
                self.approved.add(id)
            else:
                self.cooled(answer.hold)
            return
        if before is None:
            # After any ending: told how it ended, or unknown once forgotten.
            assert answer.reason in {"already_decided", "expired", "withdrawn", "unknown"}
        elif before.state != "held":
            assert answer.reason == "already_decided"
        elif self.now >= before.ends_at:
            assert answer.reason == "expired"
        elif not right:
            assert answer.reason == "digest_changed"
        assert self.table.get(id) == before  # a refused decision changes nothing

    @rule(data=st.data())
    def forward(self, data: st.DataObject) -> None:
        if not self.ids:
            return
        id = data.draw(st.sampled_from(self.ids))
        before = self.table.get(id)
        try:
            self.table.forwarding(id)
        except TransitionError:
            # Never forwarded unless approved: not after a terminal non-approve.
            assert before is None or before.state != "approved"
            return
        assert before is not None
        assert before.state == "approved"
        assert id in self.approved
        assert id not in self.forwarded
        self.forwarded.add(id)
        self.table.done(self.now, id, "ok")

    @rule(data=st.data())
    def caller_gone(self, data: st.DataObject) -> None:
        if self.ids:
            self.table.caller_gone(self.now, data.draw(st.sampled_from(self.ids)))

    @rule(data=st.data())
    def detach(self, data: st.DataObject) -> None:
        if self.ids:
            self.table.detach(self.now, data.draw(st.sampled_from(self.ids)))

    @rule(tool=st.sampled_from(TOOLS))
    def withdraw(self, tool: str) -> None:
        for hold in self.table.withdraw(self.now, lambda h: h.tool == tool, "changed"):
            assert hold.state == "withdrawn"
            assert hold.id not in self.forwarded

    @rule()
    def new_epoch(self) -> None:
        self.table.withdraw(self.now, from_earlier_epoch("bbbbbbbbbbbb"), "gateway_restarted")

    @rule(seconds=st.integers(min_value=0, max_value=400))
    def wait(self, seconds: int) -> None:
        self.now += seconds

    def cooled(self, hold: Hold) -> None:
        self.cooldowns[(hold.route, hold.tool)] = self.now + TIGHT.cooldown

    @rule()
    def sweep(self) -> None:
        for expired in self.table.sweep(self.now):
            self.cooled(expired)
        for hold in self.table.holds():
            # Every undecided hold ends by its end.
            assert hold.state != "held" or hold.ends_at > self.now

    @invariant()
    def caps_hold(self) -> None:
        if not hasattr(self, "table"):
            return
        live = list(self.table.holds())
        assert len(live) <= MAX_HOLDS
        assert sum(h.held_bytes for h in live) <= MAX_HELD_BYTES
        for route in ROUTES:
            assert sum(1 for h in live if h.route == route) <= MAX_PER_ROUTE
            for tool in TOOLS:
                assert sum(1 for h in live if (h.route, h.tool) == (route, tool)) <= MAX_PER_TOOL
                recent = [t for t, r, o in self.begins if (r, o) == (route, tool)]
                assert len([t for t in recent if t > self.now - HOUR]) <= 3
        keys = [(h.client, h.server, h.tool) for h in live if h.state == "held" and h.client]
        assert len(keys) == len(set(keys))  # one undecided hold per reported client's key
        for hold in live:
            assert hold.state in {"held", "approved", "forwarding"}
            assert hold.id not in self.forwarded
            assert (hold.state == "held") is (hold.id not in self.approved)


TestHoldMachine = HoldMachine.TestCase
TestHoldMachine.settings = hypothesis_settings(
    max_examples=50, stateful_step_count=20, deadline=None
)
