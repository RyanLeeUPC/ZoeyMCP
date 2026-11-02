"""The pending record and the result store (M8 design F.2; O.3 ``test_resultstore.py``; Z17).

A result delivered once, ``peek`` beside it, every read bound to its client, records dropped
``ttl_ms`` after their outcome, and Q44 (a)'s bounds: the per-client byte bound evicting the
client's own oldest result, eviction only within the asking client, ``busy`` when the store is
full of other clients' results, and a result arriving at a full total evicting the asking
client's own oldest, else not kept.
"""

from __future__ import annotations

import io
import itertools
from dataclasses import replace
from typing import Any, get_args

import pytest

from zoeymcp.common import logs
from zoeymcp.common.resultstore import (
    ENDED,
    MAX_CLIENT_BYTES,
    MAX_CLIENT_RECORDS,
    MAX_RECORDS,
    MAX_RESULT_BYTES,
    MAX_TOTAL_BYTES,
    NEXT,
    CallStatus,
    Collected,
    Evicted,
    Full,
    PendingCall,
    ResultStore,
    Status,
    StoredResult,
    Unknown,
)

MIB = 1024 * 1024
TTL = 60_000
GRACE = 70_000  # a 60 s call_timeout and OUTCOME_MARGIN
ASKED = 1_000
DEADLINE = 3_601_000
# One body of each size, shared by every result that size, so the tests hold little memory.
_BODIES: dict[int, bytes] = {}


def ref(number: int) -> str:
    return f"{number:016x}"


def call(number: int = 1, *, client: str = "agent", server: str = "mail") -> PendingCall:
    return PendingCall(
        ref=ref(number),
        client=client,
        server=server,
        tool="send",
        holder="vault",
        args_digest="sha256:" + "c" * 64,
        text_sha256="a" * 64,
        surfaces=frozenset({"telegram"}),
        asked_ms=ASKED,
        deadline_ms=DEADLINE,
        status="pending",
    )


def answer(size: int = 10) -> StoredResult:
    body = _BODIES.setdefault(size, b"x" * size)
    return StoredResult(200, "application/json", body)


def opened(store: ResultStore, number: int = 1, **fields: Any) -> PendingCall:
    record = call(number, **fields)
    assert store.open(2_000, record) == []
    return record


def ran(
    store: ResultStore, number: int, size: int, *, client: str = "agent", now: int = 3_000
) -> list[Evicted]:
    """Open a record for ``client`` and bring it to ``done`` with a result of ``size`` bytes."""
    opened(store, number, client=client)
    return finish(store, number, size, now=now)


def finish(store: ResultStore, number: int, size: int, *, now: int = 3_000) -> list[Evicted]:
    """Bring an open record to ``done`` with a result of ``size`` bytes."""
    assert store.advance(now, ref(number), "approved") == []
    assert store.advance(now, ref(number), "forwarding") == []
    return store.advance(now, ref(number), "done", "ok", answer(size))


def lost(store: ResultStore, number: int, client: str = "agent") -> str | None:
    found = store.peek(5_000, ref(number), client)
    assert isinstance(found, Status), found
    return found.lost


def fill(store: ResultStore, clients: dict[str, list[int]], start: int = 100) -> None:
    """Results of the given sizes in MiB, client by client, in order."""
    number = start
    for client, sizes in clients.items():
        for size in sizes:
            assert ran(store, number, size * MIB, client=client) == []
            number += 1


# --- the shape -----------------------------------------------------------------------------------


def test_the_bounds() -> None:
    assert (MAX_RECORDS, MAX_CLIENT_RECORDS) == (256, 16)
    assert (MAX_RESULT_BYTES, MAX_CLIENT_BYTES, MAX_TOTAL_BYTES) == (4 * MIB, 16 * MIB, 64 * MIB)


EXPECTED_NEXT: dict[str, set[str]] = {
    "pending": {"approved", "denied", "expired", "withdrawn"},
    "approved": {"forwarding", "done", "withdrawn"},
    "forwarding": {"done"},
}
STATUSES: tuple[Any, ...] = get_args(CallStatus)


def test_a_record_follows_its_call_in_order() -> None:
    assert {status: set(targets) for status, targets in NEXT.items()} == EXPECTED_NEXT
    assert {"done", "denied", "expired", "withdrawn"} == ENDED
    assert set(STATUSES) == set(EXPECTED_NEXT) | ENDED


def reach(store: ResultStore, status: str) -> None:
    """Bring ``ref(1)`` to ``status`` along the call's way."""
    opened(store)
    path: list[Any] = {
        "pending": [],
        "approved": ["approved"],
        "forwarding": ["approved", "forwarding"],
        "done": ["approved", "forwarding", "done"],
    }.get(status, [status])
    for step in path:
        store.advance(3_000, ref(1), step)


@pytest.mark.parametrize(("current", "to"), list(itertools.product(STATUSES, STATUSES)))
def test_advance_moves_only_as_the_call_does(current: Any, to: Any) -> None:
    store = ResultStore(TTL, GRACE)
    reach(store, current)
    assert store.advance(4_000, ref(1), to) == []
    found = store.peek(4_000, ref(1), "agent")
    assert isinstance(found, Status)
    assert found.status == (to if to in EXPECTED_NEXT.get(current, set()) else current)


# --- delivery ------------------------------------------------------------------------------------


def test_a_result_is_collected_once() -> None:
    store = ResultStore(TTL, GRACE)
    assert ran(store, 1, 10) == []
    assert store.total_bytes() == 10
    status = Status(ref(1), "send", "done", "ok", DEADLINE, False, None)
    assert store.peek(4_000, ref(1), "agent") == status
    assert store.peek(4_000, ref(1), "agent") == status  # peek never consumes
    collected = store.collect(4_000, ref(1), "agent")
    assert isinstance(collected, Collected)
    assert collected.ref == ref(1)
    assert (collected.result.status, collected.result.content_type) == (200, "application/json")
    assert collected.result.body == answer(10).body
    assert collected.result.lost is None
    assert store.total_bytes() == 0
    again = Status(ref(1), "send", "done", "ok", DEADLINE, True, None)
    assert store.collect(4_001, ref(1), "agent") == again
    assert store.peek(4_001, ref(1), "agent") == again
    assert len(store) == 1


def test_a_status_before_the_result() -> None:
    store = ResultStore(TTL, GRACE)
    opened(store)
    pending = Status(ref(1), "send", "pending", None, DEADLINE, False, None)
    assert store.collect(2_000, ref(1), "agent") == pending
    store.advance(2_500, ref(1), "approved")
    store.advance(2_600, ref(1), "forwarding")
    assert store.collect(2_700, ref(1), "agent") == Status(
        ref(1), "send", "forwarding", None, DEADLINE, False, None
    )
    store.advance(2_800, ref(1), "done", "upstream_error")
    assert store.collect(2_900, ref(1), "agent") == Status(
        ref(1), "send", "done", "upstream_error", DEADLINE, False, None
    )
    opened(store, 2)
    store.advance(3_000, ref(2), "withdrawn", "changed")
    assert store.collect(3_000, ref(2), "agent") == Status(
        ref(2), "send", "withdrawn", "changed", DEADLINE, False, None
    )


def test_an_outcome_stays_until_another_is_given() -> None:
    store = ResultStore(TTL, GRACE)
    opened(store)
    store.advance(2_000, ref(1), "approved", "decided")
    store.advance(2_000, ref(1), "forwarding")
    found = store.peek(2_000, ref(1), "agent")
    assert isinstance(found, Status)
    assert found.outcome == "decided"


def test_another_clients_ref_reads_as_unknown() -> None:
    store = ResultStore(TTL, GRACE)
    assert ran(store, 1, 10) == []
    assert store.collect(4_000, ref(1), "other") == Unknown()
    assert store.peek(4_000, ref(1), "other") == Unknown()
    assert store.collect(4_000, ref(2), "agent") == Unknown()
    assert store.peek(4_000, ref(2), "agent") == Unknown()
    assert store.list_for(4_000, "other", "mail") == []
    assert store.total_bytes() == 10  # nothing was handed over


def test_a_read_naming_another_server_reads_as_unknown() -> None:
    """Z17: a result is collected on its own server's path, so a read that names another server
    finds nothing and hands nothing over; one naming its own, or none, finds it."""
    store = ResultStore(TTL, GRACE)
    assert ran(store, 1, 10) == []
    assert store.peek(4_000, ref(1), "agent", "other") == Unknown()
    assert store.collect(4_000, ref(1), "agent", "other") == Unknown()
    assert store.total_bytes() == 10
    found = store.peek(4_000, ref(1), "agent", "mail")
    assert isinstance(found, Status)
    assert found.status == "done"
    assert store.peek(4_000, ref(1), "agent") == found
    collected = store.collect(4_000, ref(1), "agent", "mail")
    assert isinstance(collected, Collected)
    assert collected.result.body == answer(10).body
    assert store.collect(4_000, ref(1), "other", "mail") == Unknown()


def test_a_result_keeps_the_id_of_the_request_it_answers() -> None:
    """F.5 step 5: the reader binds the result to the held request's JSON-RPC id."""
    store = ResultStore(TTL, GRACE)
    opened(store, 1)
    kept = StoredResult(200, "application/json", b"{}", request_id="r-7")
    assert store.advance(3_000, ref(1), "approved") == []
    assert store.advance(3_000, ref(1), "done", "ok", kept) == []
    collected = store.collect(4_000, ref(1), "agent")
    assert isinstance(collected, Collected)
    assert collected.result.request_id == "r-7"
    assert StoredResult(200, "application/json").request_id is None


def test_list_for_names_the_clients_own_records_on_the_server() -> None:
    store = ResultStore(TTL, GRACE)
    opened(store, 1)
    opened(store, 2, server="other")
    opened(store, 3, client="other")
    assert ran(store, 4, 10) == []
    assert store.list_for(4_000, "agent", "mail") == [
        Status(ref(1), "send", "pending", None, DEADLINE, False, None),
        Status(ref(4), "send", "done", "ok", DEADLINE, False, None),
    ]
    assert store.list_for(3_000 + TTL, "agent", "mail") == [
        Status(ref(1), "send", "pending", None, DEADLINE, False, None)
    ]
    assert store.total_bytes() == 10


def test_a_result_arrives_only_with_done() -> None:
    store = ResultStore(TTL, GRACE)
    opened(store)
    assert store.advance(2_000, ref(1), "approved", None, answer(10)) == []
    assert store.total_bytes() == 0
    found = store.collect(2_000, ref(1), "agent")
    assert isinstance(found, Status)
    assert found.status == "approved"
    store.advance(2_000, ref(1), "done", "ok")
    assert isinstance(store.collect(2_000, ref(1), "agent"), Status)


# --- time ----------------------------------------------------------------------------------------


def test_a_record_is_dropped_ttl_after_its_outcome() -> None:
    store = ResultStore(TTL, GRACE)
    assert ran(store, 1, 10, now=3_000) == []
    opened(store, 2)
    store.advance(3_000, ref(2), "approved")
    assert store.sweep(3_000 + TTL - 1) == []
    assert isinstance(store.peek(3_000 + TTL - 1, ref(1), "agent"), Status)
    # Past its time it reads as unknown before the sweeper drops it.
    assert store.peek(3_000 + TTL, ref(1), "agent") == Unknown()
    assert store.collect(3_000 + TTL, ref(1), "agent") == Unknown()
    assert store.knows(ref(1))
    assert store.sweep(3_000 + TTL) == [ref(1)]
    assert not store.knows(ref(1))
    assert store.total_bytes() == 0
    store.ttl_ms = 10
    store.advance(5_000, ref(2), "withdrawn", "changed")
    assert store.sweep(5_009) == []
    assert store.sweep(5_010) == [ref(2)]
    assert len(store) == 0


def test_a_record_whose_outcome_never_comes_ends_after_its_grace() -> None:
    """Its holder lost the call: it is taken to have ended ``grace_ms`` after its deadline (the
    latest an approved forward can end) and is dropped ``ttl_ms`` after that."""
    store = ResultStore(TTL, GRACE)
    opened(store, 1)
    opened(store, 2)
    store.advance(3_000, ref(2), "approved")
    end = DEADLINE + GRACE + TTL
    assert store.sweep(end - 1) == []
    found = store.peek(end - 1, ref(2), "agent")
    assert isinstance(found, Status)
    assert found.status == "approved"
    assert store.peek(end, ref(1), "agent") == Unknown()
    assert store.sweep(end) == [ref(1), ref(2)]
    assert len(store) == 0


# --- the bounds (Q44 (a)) ------------------------------------------------------------------------


def test_records_are_bounded_per_client_and_in_all() -> None:
    store = ResultStore(TTL, GRACE)
    for number in range(MAX_CLIENT_RECORDS):
        opened(store, number)
    assert store.open(2_000, call(100)) == Full()
    assert not store.knows(ref(100))
    for client in range(1, MAX_RECORDS // MAX_CLIENT_RECORDS):
        for number in range(MAX_CLIENT_RECORDS):
            opened(store, 1_000 * client + number, client=f"c{client}")
    assert len(store) == MAX_RECORDS
    assert store.open(2_000, call(200, client="new")) == Full()
    store.advance(2_000, ref(0), "withdrawn")
    assert store.open(2_000 + TTL - 1, call(200, client="new")) == Full()
    # A record past its time counts towards no bound, swept or not.
    assert store.open(2_000 + TTL, call(200, client="new")) == []
    assert not store.knows(ref(0))


def test_a_record_past_its_time_frees_its_clients_slot() -> None:
    store = ResultStore(TTL, GRACE)
    for number in range(MAX_CLIENT_RECORDS):
        opened(store, number)
    store.advance(2_000, ref(0), "withdrawn")
    assert store.open(2_000 + TTL - 1, call(100)) == Full()
    assert store.open(2_000 + TTL, call(100)) == []
    assert not store.knows(ref(0))
    assert len(store) == MAX_CLIENT_RECORDS


def test_a_result_past_its_time_frees_the_total() -> None:
    """Another client's result past its time no longer fills the store, swept or not."""
    store = ResultStore(TTL, GRACE)
    opened(store, 1, client="e")
    assert ran(store, 100, 4 * MIB, client="b", now=3_000) == []
    number = 101
    for client, count in (("b", 3), ("c", 4), ("d", 4), ("a", 4)):
        for _ in range(count):
            assert ran(store, number, 4 * MIB, client=client, now=10_000) == []
            number += 1
    assert store.total_bytes() == MAX_TOTAL_BYTES
    assert finish(store, 1, 4 * MIB, now=3_000 + TTL) == []
    assert lost(store, 1, "e") is None
    assert not store.knows(ref(100))
    assert [lost(store, n, "b") for n in (101, 102, 103)] == [None] * 3
    assert store.total_bytes() == MAX_TOTAL_BYTES


def test_a_ref_is_opened_once() -> None:
    store = ResultStore(TTL, GRACE)
    opened(store)
    assert store.knows(ref(1))
    assert not store.knows(ref(2))
    with pytest.raises(ValueError, match="once"):
        store.open(2_000, call(1, client="other"))


OPENED_WITH: dict[str, dict[str, Any]] = {
    "status": {"status": "approved"},
    "outcome": {"outcome": "ok"},
    "ended_ms": {"ended_ms": 2_000},
    "result": {"result": StoredResult(200, "application/json", b"x")},
    "collected": {"collected": True},
}


@pytest.mark.parametrize("field", list(OPENED_WITH))
def test_a_record_opens_pending_with_nothing_yet(field: str) -> None:
    """A record given an outcome or a result would skip every bound and the delivery rule."""
    store = ResultStore(TTL, GRACE)
    record = replace(call(), **OPENED_WITH[field])
    with pytest.raises(ValueError, match="opens"):
        store.open(2_000, record)
    assert not store.knows(ref(1))
    assert store.total_bytes() == 0


def test_a_result_over_four_mib_is_not_kept() -> None:
    store = ResultStore(TTL, GRACE)
    assert ran(store, 1, MAX_RESULT_BYTES + 1) == []
    assert store.total_bytes() == 0
    assert lost(store, 1) == "too_large"
    found = store.collect(5_000, ref(1), "agent")
    assert isinstance(found, Status)
    assert ran(store, 2, MAX_RESULT_BYTES) == []
    assert store.total_bytes() == MAX_RESULT_BYTES
    assert lost(store, 2) is None


def test_a_result_already_lost_keeps_no_bytes() -> None:
    store = ResultStore(TTL, GRACE)
    opened(store)
    store.advance(2_000, ref(1), "approved")
    given = StoredResult(502, "application/json", b"partial", lost="too_large")
    assert store.advance(2_000, ref(1), "done", "ok", given) == []
    assert store.total_bytes() == 0
    assert lost(store, 1) == "too_large"


def test_the_client_bound_evicts_the_clients_own_oldest_result() -> None:
    store = ResultStore(TTL, GRACE)
    fill(store, {"other": [4], "agent": [4, 4, 4, 4]})  # refs 100 and 101-104
    assert store.total_bytes() == 20 * MIB
    assert ran(store, 1, 1) == [Evicted(ref(101), "client_bound")]
    assert lost(store, 101) == "not_kept"
    assert [lost(store, n) for n in (102, 103, 104, 1)] == [None] * 4
    assert lost(store, 100, "other") is None
    assert store.total_bytes() == 16 * MIB + 1
    # Its collect says the call ran and its result wasn't kept.
    assert store.collect(5_000, ref(101), "agent") == Status(
        ref(101), "send", "done", "ok", DEADLINE, False, "not_kept"
    )


def test_a_collected_result_is_never_evicted() -> None:
    store = ResultStore(TTL, GRACE)
    fill(store, {"agent": [4, 4, 4, 4]})
    assert isinstance(store.collect(5_000, ref(100), "agent"), Collected)
    assert ran(store, 1, 4 * MIB) == []
    assert ran(store, 2, 1) == [Evicted(ref(101), "client_bound")]
    found = store.peek(5_000, ref(100), "agent")
    assert isinstance(found, Status)
    assert (found.collected, found.lost) == (True, None)


def test_open_at_a_full_total_evicts_the_asking_clients_own_results() -> None:
    store = ResultStore(TTL, GRACE)
    fill(store, {"a": [4, 4, 4, 4], "b": [4, 4, 4, 4], "c": [4, 4, 4, 4], "d": [4, 4, 4, 4]})
    assert store.total_bytes() == MAX_TOTAL_BYTES
    assert store.open(5_000, call(1, client="b")) == [Evicted(ref(104), "store_full")]
    assert lost(store, 104, "b") == "not_kept"
    assert store.total_bytes() == MAX_TOTAL_BYTES - 4 * MIB
    assert [lost(store, n, "a") for n in (100, 101, 102, 103)] == [None] * 4


def test_open_refuses_busy_when_others_fill_the_store() -> None:
    store = ResultStore(TTL, GRACE)
    fill(store, {"a": [4, 4, 4, 4], "b": [4, 4, 4, 4], "c": [4, 4, 4, 4], "d": [4, 4, 4, 4]})
    assert store.open(5_000, call(1, client="new")) == Full()
    assert not store.knows(ref(1))
    assert store.total_bytes() == MAX_TOTAL_BYTES


def test_open_below_a_full_total_evicts_nothing() -> None:
    store = ResultStore(TTL, GRACE)
    fill(store, {"a": [4, 4, 4, 4], "b": [4, 4, 4, 4], "c": [4, 4, 4, 4], "d": [4, 4, 4]})
    assert ran(store, 1, 4 * MIB - 1, client="d") == []
    assert store.total_bytes() == MAX_TOTAL_BYTES - 1
    assert store.open(5_000, call(2, client="new")) == []


def test_open_evicts_only_as_many_as_it_needs() -> None:
    store = ResultStore(TTL, GRACE)
    fill(store, {"a": [4, 4, 4, 4], "b": [4, 4, 4, 4], "c": [4, 4, 4, 4], "d": [2, 2, 4, 4, 4]})
    assert store.total_bytes() == MAX_TOTAL_BYTES
    assert store.open(5_000, call(1, client="d")) == [Evicted(ref(112), "store_full")]
    assert [lost(store, n, "d") for n in (113, 114, 115, 116)] == [None] * 4


def test_a_result_arriving_at_a_full_total_evicts_the_clients_own_oldest() -> None:
    store = ResultStore(TTL, GRACE)
    opened(store, 2, client="a")
    fill(store, {"b": [4, 4, 4, 4], "c": [4, 4, 4, 4], "d": [4, 4, 4, 4], "a": [4, 4]})
    assert store.total_bytes() == 56 * MIB
    fill(store, {"e": [4, 4]}, start=200)
    assert store.total_bytes() == MAX_TOTAL_BYTES
    assert finish(store, 2, 4 * MIB) == [Evicted(ref(112), "store_full")]
    assert lost(store, 112, "a") == "not_kept"
    assert lost(store, 113, "a") is None
    assert lost(store, 2, "a") is None
    assert [lost(store, n, "e") for n in (200, 201)] == [None, None]
    assert store.total_bytes() == MAX_TOTAL_BYTES


def test_a_result_with_no_room_is_not_kept_and_evicts_nothing() -> None:
    store = ResultStore(TTL, GRACE)
    opened(store, 1, client="a")
    opened(store, 2, client="f")
    fill(
        store,
        {"b": [4, 4, 4, 4], "c": [4, 4, 4, 4], "d": [4, 4, 4, 4], "e": [4, 4, 4, 3], "a": [1]},
    )
    assert store.total_bytes() == MAX_TOTAL_BYTES
    # Evicting the client's 1 MiB wouldn't make room for 2 MiB: neither is kept, nothing else.
    assert finish(store, 1, 2 * MIB) == [Evicted(ref(1), "store_full")]
    assert lost(store, 1, "a") == "not_kept"
    assert lost(store, 116, "a") is None
    assert store.total_bytes() == MAX_TOTAL_BYTES
    assert store.collect(5_000, ref(1), "a") == Status(
        ref(1), "send", "done", "ok", DEADLINE, False, "not_kept"
    )
    # A client with no results of its own: never another client's.
    assert finish(store, 2, 1) == [Evicted(ref(2), "store_full")]
    assert store.total_bytes() == MAX_TOTAL_BYTES


def test_a_result_fits_the_total_exactly() -> None:
    store = ResultStore(TTL, GRACE)
    fill(store, {"b": [4, 4, 4, 4], "c": [4, 4, 4, 4], "d": [4, 4, 4, 4], "a": [4, 4, 4]})
    assert ran(store, 1, 4 * MIB, client="a") == []
    assert store.total_bytes() == MAX_TOTAL_BYTES


def test_the_client_bound_then_the_total() -> None:
    store = ResultStore(TTL, GRACE)
    opened(store, 1, client="a")
    fill(store, {"b": [4, 4, 4, 4], "c": [4, 4, 4, 4], "d": [4, 4, 4, 4], "e": [2]})
    fill(store, {"a": [2, 4, 4, 4]}, start=200)
    assert store.total_bytes() == MAX_TOTAL_BYTES
    assert finish(store, 1, 4 * MIB) == [
        Evicted(ref(200), "client_bound"),
        Evicted(ref(201), "store_full"),
    ]
    assert [lost(store, n, "a") for n in (200, 201, 202, 203, 1)] == [
        "not_kept",
        "not_kept",
        None,
        None,
        None,
    ]
    assert store.total_bytes() == MAX_TOTAL_BYTES - 2 * MIB


# --- secrets -------------------------------------------------------------------------------------


def test_records_and_results_hide_their_bytes_and_refuse_to_be_logged() -> None:
    record = call()
    result = StoredResult(200, "application/json", b"the-result-bytes")
    assert repr(record) == f"PendingCall(ref={ref(1)}, status=pending)"
    assert repr(result) == "StoredResult(status=200, lost=None)"
    assert "the-result-bytes" not in repr(result)
    log = logs.Log("vault")
    stream = io.StringIO()
    logs.set_stream(stream)
    try:
        for value in (record, result):
            with pytest.raises(TypeError):
                log.event("probe", value=value)
    finally:
        logs.set_stream(None)
    assert stream.getvalue() == ""
