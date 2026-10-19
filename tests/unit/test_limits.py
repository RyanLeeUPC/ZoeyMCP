"""The portal's bounds (M5 design F.1, B.3, C.2 rows 0 and 8, O.2): the bucket's refill, the
in-flight gate and its unauthenticated slots, the connection table's idle eviction, and a stateful
property that no sequence passes a cap."""

from __future__ import annotations

import pytest
from hypothesis import settings as hypothesis_settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, precondition, rule

from zoeymcp.portal.limits import (
    ADMIN_CONNECTIONS,
    IN_FLIGHT,
    IN_FLIGHT_UNAUTH,
    UNAUTH_BURST,
    UNAUTH_RATE,
    Bucket,
    Connections,
    InFlight,
    Opened,
    Ticket,
)

T0 = 1000.0


def test_the_constants_are_the_designs() -> None:
    assert (UNAUTH_RATE, UNAUTH_BURST) == (30, 10)
    assert (IN_FLIGHT, IN_FLIGHT_UNAUTH, ADMIN_CONNECTIONS) == (32, 8, 64)


# --- the bucket -----------------------------------------------------------------------------------


def drain(bucket: Bucket, now: float) -> int:
    """The tokens the bucket gives at ``now``, up to a bound, so a broken bucket fails."""
    for taken in range(100):
        if not bucket.take(now):
            return taken
    return 100


def test_the_bucket_starts_full_with_its_burst() -> None:
    bucket = Bucket()
    assert drain(bucket, T0) == UNAUTH_BURST


def test_the_bucket_refills_thirty_a_minute() -> None:
    bucket = Bucket()
    drain(bucket, T0)
    assert bucket.take(T0 + 1.999) is False
    assert bucket.take(T0 + 2.0)
    assert not bucket.take(T0 + 2.0)
    # A minute gives 30, but the bucket holds only its burst.
    assert drain(bucket, T0 + 62.0) == UNAUTH_BURST


def test_a_partial_token_carries_over() -> None:
    bucket = Bucket()
    drain(bucket, T0)
    assert not bucket.take(T0 + 1.0)
    assert bucket.take(T0 + 2.0)
    assert not bucket.take(T0 + 3.0)
    assert bucket.take(T0 + 4.0)


def test_a_clock_that_steps_back_refills_nothing() -> None:
    bucket = Bucket()
    drain(bucket, T0)
    assert not bucket.take(T0 - 100)
    assert not bucket.take(T0 + 1.0)
    assert bucket.take(T0 + 2.0)


def test_the_bucket_takes_its_rate_and_burst() -> None:
    bucket = Bucket(rate=1.0, burst=2)
    assert drain(bucket, T0) == 2
    assert bucket.take(T0 + 1.0)
    assert drain(bucket, T0 + 100) == 2
    assert not Bucket(rate=1.0, burst=0).take(T0)


# --- the in-flight gate ---------------------------------------------------------------------------


def test_the_gate_holds_thirty_two() -> None:
    gate = InFlight()
    tickets = [gate.enter() for _ in range(IN_FLIGHT)]
    assert all(isinstance(t, Ticket) for t in tickets)
    assert gate.enter() is None
    assert gate.total == IN_FLIGHT
    first = tickets[0]
    assert first is not None
    gate.leave(first)
    assert gate.total == IN_FLIGHT - 1
    assert gate.enter() is not None


def test_eight_slots_for_the_unauthenticated() -> None:
    gate = InFlight()
    tickets = []
    for _ in range(IN_FLIGHT_UNAUTH):
        ticket = gate.enter()
        assert ticket is not None
        assert gate.enter_unauthenticated(ticket)
        tickets.append(ticket)
    ninth = gate.enter()
    assert ninth is not None
    assert gate.enter_unauthenticated(ninth) is False
    assert not ninth.unauthenticated
    assert (gate.total, gate.unauthenticated) == (IN_FLIGHT_UNAUTH + 1, IN_FLIGHT_UNAUTH)
    gate.leave(tickets[0])
    assert (gate.total, gate.unauthenticated) == (IN_FLIGHT_UNAUTH, IN_FLIGHT_UNAUTH - 1)
    assert gate.enter_unauthenticated(ninth)


def test_the_unauthenticated_cant_take_the_operators_slots() -> None:
    gate = InFlight()
    for _ in range(IN_FLIGHT_UNAUTH):
        ticket = gate.enter()
        assert ticket is not None
        assert gate.enter_unauthenticated(ticket)
    for _ in range(IN_FLIGHT - IN_FLIGHT_UNAUTH):
        assert gate.enter() is not None
    assert gate.enter() is None


def test_one_ticket_takes_one_unauthenticated_slot() -> None:
    gate = InFlight()
    ticket = gate.enter()
    assert ticket is not None
    assert gate.enter_unauthenticated(ticket)
    assert gate.enter_unauthenticated(ticket)
    assert gate.unauthenticated == 1


def test_leaving_twice_gives_back_once() -> None:
    gate = InFlight()
    ticket, other = gate.enter(), gate.enter()
    assert ticket is not None
    assert other is not None
    gate.enter_unauthenticated(ticket)
    gate.enter_unauthenticated(other)
    gate.leave(ticket)
    gate.leave(ticket)
    assert (gate.total, gate.unauthenticated) == (1, 1)
    assert ticket.left
    with pytest.raises(ValueError, match=r"^this request has left the gate$"):
        gate.enter_unauthenticated(ticket)


def test_an_authenticated_request_leaves_the_unauthenticated_slots_alone() -> None:
    gate = InFlight()
    unauth, auth = gate.enter(), gate.enter()
    assert unauth is not None
    assert auth is not None
    gate.enter_unauthenticated(unauth)
    gate.leave(auth)
    assert (gate.total, gate.unauthenticated) == (1, 1)


# --- the connection table -------------------------------------------------------------------------


def fill(table: Connections[int], now: float = T0) -> None:
    for conn in range(ADMIN_CONNECTIONS):
        assert table.open(conn, now) == Opened(accepted=True)


def test_connections_up_to_the_cap_are_taken() -> None:
    table: Connections[int] = Connections()
    fill(table)
    assert len(table) == ADMIN_CONNECTIONS


def test_one_more_evicts_the_one_idle_longest() -> None:
    table: Connections[int] = Connections()
    for conn in range(ADMIN_CONNECTIONS):
        table.open(conn, T0 + conn)
    table.busy(0)
    table.idle(0, T0 + 100)  # idle again, but only since now
    assert table.open(100, T0 + 101) == Opened(accepted=True, evict=1)
    assert len(table) == ADMIN_CONNECTIONS
    assert table.open(101, T0 + 102) == Opened(accepted=True, evict=2)


def test_a_connection_with_a_request_in_flight_is_never_evicted() -> None:
    table: Connections[int] = Connections()
    fill(table)
    for conn in range(1, ADMIN_CONNECTIONS):
        table.busy(conn)
    assert table.open(100, T0 + 1) == Opened(accepted=True, evict=0)
    table.busy(100)
    assert table.open(101, T0 + 2) == Opened(accepted=False)
    assert len(table) == ADMIN_CONNECTIONS
    table.idle(5, T0 + 3)
    assert table.open(101, T0 + 4) == Opened(accepted=True, evict=5)


def test_a_tie_evicts_the_first_opened() -> None:
    table: Connections[int] = Connections()
    fill(table)
    assert table.open(100, T0) == Opened(accepted=True, evict=0)


def test_closing_frees_a_place() -> None:
    table: Connections[int] = Connections()
    fill(table)
    table.close(7)
    table.close(7)
    assert len(table) == ADMIN_CONNECTIONS - 1
    assert table.open(100, T0) == Opened(accepted=True)


def test_events_for_a_closed_connection_change_nothing() -> None:
    table: Connections[int] = Connections()
    table.open(1, T0)
    table.busy(2)
    table.idle(3, T0)
    assert len(table) == 1
    fill_rest = range(10, 10 + ADMIN_CONNECTIONS - 1)
    for conn in fill_rest:
        table.open(conn, T0 + 1)
    assert table.open(99, T0 + 2) == Opened(accepted=True, evict=1)


# --- the stateful property ------------------------------------------------------------------------


class LimitsMachine(RuleBasedStateMachine):
    """No sequence passes a cap: in flight, unauthenticated in flight, connections, and tokens
    taken against what the bucket can have refilled."""

    def __init__(self) -> None:
        super().__init__()
        self.gate = InFlight()
        self.tickets: list[Ticket] = []
        self.table: Connections[int] = Connections()
        self.open: set[int] = set()
        self.next_conn = 0
        self.bucket = Bucket()
        self.now = T0
        self.taken = 0

    @rule()
    def enter(self) -> None:
        ticket = self.gate.enter()
        assert (ticket is None) == (len(self.tickets) == IN_FLIGHT)
        if ticket is not None:
            self.tickets.append(ticket)

    @precondition(lambda self: bool(self.tickets))
    @rule(data=st.data())
    def unauthenticated(self, data: st.DataObject) -> None:
        ticket = data.draw(st.sampled_from(self.tickets))
        held = sum(t.unauthenticated for t in self.tickets)
        already = ticket.unauthenticated
        took = self.gate.enter_unauthenticated(ticket)
        assert took == (already or held < IN_FLIGHT_UNAUTH)
        assert ticket.unauthenticated == took

    @precondition(lambda self: bool(self.tickets))
    @rule(data=st.data())
    def leave(self, data: st.DataObject) -> None:
        ticket = data.draw(st.sampled_from(self.tickets))
        self.gate.leave(ticket)
        self.tickets.remove(ticket)

    @rule(busy=st.booleans())
    def connect(self, busy: bool) -> None:
        conn = self.next_conn
        self.next_conn += 1
        opened = self.table.open(conn, self.now)
        if opened.evict is not None:
            assert opened.evict in self.open
            self.open.discard(opened.evict)
        if opened.accepted:
            self.open.add(conn)
            if busy:
                self.table.busy(conn)

    @precondition(lambda self: bool(self.open))
    @rule(data=st.data(), action=st.sampled_from(["busy", "idle", "close"]))
    def connection_event(self, data: st.DataObject, action: str) -> None:
        conn = data.draw(st.sampled_from(sorted(self.open)))
        if action == "busy":
            self.table.busy(conn)
        elif action == "idle":
            self.table.idle(conn, self.now)
        else:
            self.table.close(conn)
            self.open.discard(conn)

    @rule()
    def take_token(self) -> None:
        if self.bucket.take(self.now):
            self.taken += 1

    @rule(step=st.sampled_from([0.001, 0.5, 2.0, 30.0]))
    def wait(self, step: float) -> None:
        self.now += step

    @invariant()
    def bounded(self) -> None:
        assert self.gate.total == len(self.tickets) <= IN_FLIGHT
        held = sum(t.unauthenticated for t in self.tickets)
        assert self.gate.unauthenticated == held <= IN_FLIGHT_UNAUTH
        assert len(self.table) == len(self.open) <= ADMIN_CONNECTIONS
        assert self.taken <= UNAUTH_BURST + (self.now - T0) * UNAUTH_RATE / 60


TestLimitsMachine = LimitsMachine.TestCase
TestLimitsMachine.settings = hypothesis_settings(
    max_examples=50, stateful_step_count=20, deadline=None
)
