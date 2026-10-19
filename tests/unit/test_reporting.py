"""The reporter's choices: what to send next, the batch's bound, and the waits (M5 design J.3)."""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from tests.unit.report_model import GatewayModel
from zoeymcp.common import ledgerreport
from zoeymcp.common.ledgerformat import MAX_LINE_BYTES, line_hash
from zoeymcp.common.ledgerreport import MAX_BODY_BYTES, MAX_LINES, PATH, Head, encode
from zoeymcp.gateway.reporting import (
    FIRST_BACKOFF,
    IDLE_SECONDS,
    LOG_EVERY,
    MAX_BACKOFF,
    REFUSED_SECONDS,
    REPORT_BATCH_BYTES,
    ReportingError,
    Wait,
    backoff,
    batch,
    log_due,
    next_step,
    parse_head,
    pending,
    read_after,
)

HASH = "sha256:" + "a" * 64


def test_the_wire_constants() -> None:
    assert PATH == "/_zoeymcp/gateway/v1/report/ledger"
    assert (ledgerreport.VERSION, MAX_LINES, MAX_BODY_BYTES) == (1, 256, 2**20)
    assert {"ok", "fork", "gap", "full"} == ledgerreport.STATES
    assert REPORT_BATCH_BYTES == 960 * 1024 < MAX_BODY_BYTES
    assert encode([]) == b'{"lines":[],"v":1}'
    assert encode([b'{"a":"\\"x"}', b"{}"]) == b'{"lines":["{\\"a\\":\\"\\\\\\"x\\"}","{}"],"v":1}'


def test_a_head_as_json() -> None:
    assert Head(None, None).to_json() == {"head_seq": None, "head_hash": None, "state": "ok"}
    assert Head(4, HASH, "gap").to_json() == {"head_seq": 4, "head_hash": HASH, "state": "gap"}


# --- the vault's answer --------------------------------------------------------------------------


@pytest.mark.parametrize("state", ["ok", "fork", "gap", "full"])
def test_a_head_round_trips(state: Any) -> None:
    for head in [Head(None, None, state), Head(0, HASH, state), Head(1041, HASH, state)]:
        assert parse_head(head.to_json()) == head


@pytest.mark.parametrize(
    ("value", "message"),
    [
        (None, "not a head"),
        ([None, None, "ok"], "not a head"),
        ({"head_seq": None, "head_hash": None}, "not a head"),
        ({"head_seq": None, "head_hash": None, "state": "ok", "x": 1}, "not a head"),
        ({"head_seq": None, "head_hash": None, "state": "OK"}, "not a state"),
        ({"head_seq": None, "head_hash": None, "state": None}, "not a state"),
        ({"head_seq": None, "head_hash": None, "state": ["ok"]}, "not a state"),
        ({"head_seq": None, "head_hash": HASH, "state": "ok"}, "not a seq"),
        ({"head_seq": -1, "head_hash": HASH, "state": "ok"}, "not a seq"),
        ({"head_seq": True, "head_hash": HASH, "state": "ok"}, "not a seq"),
        ({"head_seq": 1.0, "head_hash": HASH, "state": "ok"}, "not a seq"),
        ({"head_seq": "1", "head_hash": HASH, "state": "ok"}, "not a seq"),
        ({"head_seq": 1, "head_hash": None, "state": "ok"}, "not a hash"),
        ({"head_seq": 1, "head_hash": HASH + "\n", "state": "ok"}, "not a hash"),
        ({"head_seq": 1, "head_hash": HASH.upper(), "state": "ok"}, "not a hash"),
        ({"head_seq": 1, "head_hash": "x" + HASH, "state": "ok"}, "not a hash"),
        ({"head_seq": 1, "head_hash": 7, "state": "ok"}, "not a hash"),
    ],
)
def test_anything_else_is_not_a_head(value: Any, message: str) -> None:
    with pytest.raises(ReportingError, match=f"^{message}$"):
        parse_head(value)


# --- what to read and send -----------------------------------------------------------------------


@pytest.mark.parametrize("state", ["fork", "gap", "full"])
def test_nothing_is_read_or_sent_while_the_copy_refuses(state: Any) -> None:
    head = Head(4, HASH, state)
    assert read_after(head, 10) is None
    assert pending(head, [b"{}"]) == ()


@pytest.mark.parametrize(
    ("head", "own", "after"),
    [
        (Head(None, None), -1, -1),  # no copy yet: everything
        (Head(None, None), 7, -1),
        (Head(4, HASH), 4, 3),  # from the copy's head itself
        (Head(4, HASH), 9, 3),
        (Head(0, HASH), 0, -1),
        (Head(4, HASH), 3, -1),  # this ledger is behind the copy: from its start
        (Head(4, HASH), -1, -1),
    ],
)
def test_where_the_read_starts(head: Head, own: int, after: int) -> None:
    assert read_after(head, own) == after


def gateway(count: int) -> GatewayModel:
    model = GatewayModel()
    model.append(count)
    return model


def test_the_copy_s_head_isn_t_sent_again() -> None:
    lines = gateway(6).read(-1)
    head = Head(2, line_hash(lines[2]))
    assert pending(head, lines[2:]) == tuple(lines[3:])
    assert pending(head, lines[2:3]) == ()
    assert pending(Head(None, None), lines) == tuple(lines)
    assert pending(Head(None, None), []) == ()
    assert pending(head, []) == ()


def test_another_record_at_the_head_is_sent_so_the_vault_sees_the_fork() -> None:
    lines, other = gateway(6).read(-1), GatewayModel(ticks=100)
    other.append(6)
    head = Head(2, line_hash(lines[2]))
    assert pending(head, other.read(1)) == tuple(other.read(1))
    assert pending(head, lines[3:]) == tuple(lines[3:])  # the head's record pruned: it extends


def test_pending_takes_one_batch() -> None:
    lines = gateway(6).read(-1)
    size = len(encode(lines[1:4]))
    assert pending(Head(0, line_hash(lines[0])), lines, max_bytes=size) == tuple(lines[1:4])
    assert pending(Head(None, None), lines, max_lines=2) == tuple(lines[:2])
    assert pending(Head(None, None), lines * 50) == tuple((lines * 50)[:MAX_LINES])


# --- the batch -----------------------------------------------------------------------------------


def test_the_batch_is_the_longest_prefix_that_fits() -> None:
    lines = [b"{}", b'{"a":"\\""}', b"[1]", b"{}"]
    for n in range(5):
        exact = len(encode(lines[:n]))
        assert batch(lines, max_bytes=exact) == n
        assert batch(lines, max_bytes=exact - 1) == max(n - 1, 0)
    assert batch(lines, max_bytes=10**6, max_lines=3) == 3
    assert batch(lines, max_bytes=10**6, max_lines=0) == 0
    assert batch([], max_bytes=0) == 0
    assert batch(lines[:1], max_bytes=len(encode([]))) == 0  # one line that doesn't fit


def test_a_maximum_size_line_always_fits() -> None:
    worst = b'"\\' * ((MAX_LINE_BYTES - 1) // 2)  # every byte escaped
    assert len(encode([worst])) > 2 * len(worst)
    assert batch([worst]) == 1
    assert batch([worst] * MAX_LINES) < MAX_LINES  # several batches


LINE = st.binary(min_size=0, max_size=MAX_LINE_BYTES - 1).map(
    lambda data: bytes(b if b < 0x80 else 0x22 for b in data)  # ASCII, quotes most escaped
)
WORST = st.sampled_from([b'"' * (MAX_LINE_BYTES - 1), b"\\" * (MAX_LINE_BYTES - 1)])


@settings(max_examples=40, deadline=None)
@given(lines=st.lists(st.one_of(LINE, WORST), max_size=MAX_LINES + 4))
def test_every_batch_stays_under_1_mib_and_is_as_long_as_it_can_be(lines: list[bytes]) -> None:
    n = batch(lines)
    assert len(encode(lines[:n])) <= REPORT_BATCH_BYTES < MAX_BODY_BYTES
    assert n == min(len(lines), MAX_LINES) or len(encode(lines[: n + 1])) > REPORT_BATCH_BYTES
    assert n >= min(len(lines), 1)


# --- the waits -----------------------------------------------------------------------------------


def test_the_wait_after_each_outcome() -> None:
    assert next_step("sent", failures=0, jitter=0.5) == Wait(0.0, False)
    assert next_step("idle", failures=0, jitter=0.5) == Wait(IDLE_SECONDS, True)
    assert next_step("refused", failures=3, jitter=0.5) == Wait(REFUSED_SECONDS, False)
    assert next_step("failed", failures=3, jitter=0.5) == Wait(backoff(3, 0.5), False)
    assert (IDLE_SECONDS, REFUSED_SECONDS) == (60.0, 300.0)


@pytest.mark.parametrize(
    ("failures", "jitter", "seconds"),
    [
        (1, 0.0, 2.5),
        (1, 1.0, 5.0),
        (1, 0.5, 3.75),
        (2, 0.0, 5.0),
        (2, 1.0, 10.0),
        (6, 1.0, 160.0),
        (7, 1.0, 300.0),  # 320, capped
        (7, 0.0, 150.0),
        (17, 1.0, 300.0),
        (10**9, 0.0, 150.0),
        (0, 1.0, 5.0),  # as the first
        (-3, 0.0, 2.5),
        (1, -1.0, 2.5),  # jitter outside [0, 1] is clamped
        (1, 2.0, 5.0),
    ],
)
def test_the_backoff(failures: int, jitter: float, seconds: float) -> None:
    assert backoff(failures, jitter) == seconds
    assert (FIRST_BACKOFF, MAX_BACKOFF) == (5.0, 300.0)


@settings(max_examples=50, deadline=None)
@given(failures=st.integers(-5, 10**6), jitter=st.floats(-1, 2))
def test_the_backoff_stays_within_its_bounds(failures: int, jitter: float) -> None:
    seconds = backoff(failures, jitter)
    assert FIRST_BACKOFF / 2 <= seconds <= MAX_BACKOFF
    assert backoff(failures + 1, jitter) >= seconds


def test_a_failure_is_logged_at_most_once_per_5_minutes() -> None:
    assert LOG_EVERY == 300.0
    assert log_due(None, 0.0)
    assert not log_due(1000.0, 1299.9)
    assert log_due(1000.0, 1300.0)
    assert log_due(1000.0, 5000.0)
