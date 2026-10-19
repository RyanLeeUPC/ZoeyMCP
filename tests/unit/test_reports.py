"""The vault's decision on a ledger report, and the copy's pruning and restart (M5 design J.2, J.4).

The stateful test drives :mod:`tests.unit.report_model`'s gateway and copy through appends,
reports, resends, prunes, restores, lost volumes, time and restarts.
"""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import settings as hypothesis_settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, initialize, invariant, rule

from tests.unit.report_model import T0, CopyModel, GatewayModel, asked_line, report_round
from zoeymcp.common import ledgerformat
from zoeymcp.common.ledgerformat import GENESIS, line_hash
from zoeymcp.common.ledgerreport import MAX_LINES, Head
from zoeymcp.vault.reports import (
    DAY_MS,
    KEEP_MS,
    REPORTED_ARCHIVE_MAX_BYTES,
    REPORTED_KEEP_DAYS,
    REPORTED_MAX_BYTES,
    Accepted,
    Epoch,
    Held,
    LiveFile,
    Refused,
    archive,
    decide,
    plan_restart,
)

NOW = T0 + 100 * DAY_MS
SIZE = 545  # one asked_line with its newline


def chain(count: int, *, seq: int = 0, prev: str = GENESIS, tick: int = 0) -> list[bytes]:
    """``count`` chained lines from ``seq`` after ``prev``, each without its newline."""
    lines = []
    for n in range(count):
        line = asked_line(seq + n, prev, tick + seq + n + 1)
        lines.append(line)
        prev = line_hash(line)
    return lines


def body(lines: list[bytes]) -> dict[str, Any]:
    return {"v": 1, "lines": [line.decode() for line in lines]}


LINES = chain(8)
HASHES = [line_hash(line) for line in LINES]


def holding(seq: int, *, files: tuple[LiveFile, ...] | None = None) -> Held:
    """A copy that holds ``LINES`` up to ``seq``."""
    found = files if files is not None else (LiveFile("000000000000.jsonl", 100, NOW),)
    return Held("ok", 0, seq, HASHES[seq], found)


def test_the_constants() -> None:
    assert REPORTED_MAX_BYTES == REPORTED_ARCHIVE_MAX_BYTES == 64 * 2**20
    assert REPORTED_KEEP_DAYS == 30
    assert KEEP_MS == 30 * 86_400_000
    assert len(LINES[0]) + 1 == SIZE


# --- row 1: a copy that refuses ------------------------------------------------------------------


@pytest.mark.parametrize("state", ["fork", "gap", "full"])
def test_a_copy_not_ok_refuses_every_report_until_a_restart(state: Any) -> None:
    held = Held(state, 0, 4, HASHES[4], (LiveFile("000000000000.jsonl", 100, NOW),))
    result = decide(held, body(LINES[5:]), now=NOW)
    assert result == Refused(
        409, "refused_until_restart", f"the copy is {state}; a restart of the chain is due"
    )
    assert decide(held, None, now=NOW) == result  # before the body is looked at


# --- row 2: the body and its lines ---------------------------------------------------------------

BAD_BODY = Refused(400, "bad_body", 'expected {"v": 1, "lines": [1 to 256 lines]}')


@pytest.mark.parametrize(
    "report",
    [
        None,
        [LINES[0].decode()],
        {"v": 1},
        {"lines": [LINES[0].decode()]},
        {"v": 1, "lines": [LINES[0].decode()], "more": 1},
        {"v": 2, "lines": [LINES[0].decode()]},
        {"v": True, "lines": [LINES[0].decode()]},
        {"v": 1.0, "lines": [LINES[0].decode()]},
        {"v": "1", "lines": [LINES[0].decode()]},
        {"v": 1, "lines": LINES[0].decode()},
        {"v": 1, "lines": (LINES[0].decode(),)},
        {"v": 1, "lines": []},
        {"v": 1, "lines": [LINES[0].decode()] * (MAX_LINES + 1)},
        {"v": 1, "lines": [LINES[0].decode(), 3]},
        {"v": 1, "lines": [LINES[0]]},
    ],
)
def test_a_body_of_another_shape_is_refused(report: Any) -> None:
    assert decide(Held(), report, now=NOW) == BAD_BODY


def test_256_lines_are_taken() -> None:
    lines = chain(MAX_LINES)
    result = decide(Held(), body(lines), now=NOW)
    assert isinstance(result, Accepted)
    assert len(result.lines) == MAX_LINES


def bad_line(index: int) -> Refused:
    return Refused(400, "bad_line", f"line {index} isn't a canonical v1 ledger record", index=index)


@pytest.mark.parametrize(
    ("change", "index"),
    [
        (lambda lines: [lines[0], "not json", *lines[2:]], 1),
        (lambda lines: [lines[0] + "\n", *lines[1:]], 0),  # parse() would take it
        (lambda lines: [*lines[:2], lines[2].replace(",", ", ", 1)], 2),  # not canonical
        (lambda lines: [lines[0].replace('"v":1', '"v":2'), *lines[1:]], 0),
        (lambda lines: [lines[0], "[]"], 1),
        (lambda lines: [lines[0], "\ud800"], 1),  # can't be UTF-8
        (lambda lines: [*lines[:2], '{"a":"' + "x" * 4096 + '"}'], 2),
    ],
)
def test_each_line_must_be_a_canonical_record(change: Any, index: int) -> None:
    lines = change([line.decode() for line in LINES[:3]])
    assert decide(Held(), {"v": 1, "lines": lines}, now=NOW) == bad_line(index)


def test_the_first_bad_line_is_named() -> None:
    lines = [LINES[0].decode(), "x", "y"]
    assert decide(Held(), {"v": 1, "lines": lines}, now=NOW) == bad_line(1)


# --- rows 3 and 4: the writer and the chain ------------------------------------------------------


def vault_line(seq: int, prev: str) -> bytes:
    line = ledgerformat.encode(
        "decided",
        seq=seq,
        prev=prev,
        ts=T0,
        ref="0" * 16,
        writer="vault",
        decision="approved_elsewhere",
        waited_ms=0,
    )
    return line[:-1]


@pytest.mark.parametrize("where", [0, 1, 2])
def test_a_report_can_t_carry_a_vault_record(where: int) -> None:
    lines = chain(3)
    lines[where] = vault_line(where, GENESIS if where == 0 else line_hash(lines[where - 1]))
    result = decide(Held(), body(lines[: where + 1]), now=NOW)
    assert result == Refused(400, "wrong_writer", "a report holds only records the gateway wrote")


def test_the_writer_is_checked_before_the_chain() -> None:
    lines = [LINES[0], vault_line(5, GENESIS)]  # neither chained nor the gateway's
    result = decide(Held(), body(lines), now=NOW)
    assert isinstance(result, Refused)
    assert result.reason == "wrong_writer"


NOT_A_CHAIN = Refused(400, "not_a_chain", "the lines don't chain")


@pytest.mark.parametrize(
    "lines",
    [
        [LINES[0], LINES[2]],  # a seq skipped
        [LINES[1], LINES[0]],
        [LINES[0], LINES[1], LINES[1]],
        [LINES[0], chain(2, tick=50)[1]],  # seq 1, after another seq 0
    ],
)
def test_the_lines_must_chain_among_themselves(lines: list[bytes]) -> None:
    assert decide(Held(), body(lines), now=NOW) == NOT_A_CHAIN


def test_the_chain_is_checked_from_the_first_line() -> None:
    lines = chain(3, seq=40, prev="sha256:" + "9" * 64)
    assert isinstance(decide(Held(), body(lines), now=NOW), Accepted)
    assert decide(Held(), body([lines[0], lines[2]]), now=NOW) == NOT_A_CHAIN


# --- rows 5 to 9: first use, extend, duplicates, gap, fork ---------------------------------------


def test_with_no_copy_any_start_is_taken_on_first_use() -> None:
    prev = "sha256:" + "9" * 64
    lines = chain(3, seq=40, prev=prev)
    assert decide(Held(), body(lines), now=NOW) == Accepted(
        tuple(lines), 0, Head(42, line_hash(lines[2])), (40, prev), (), 40
    )


def test_a_report_that_extends_the_head_is_taken() -> None:
    result = decide(holding(4), body(LINES[5:]), now=NOW)
    assert result == Accepted(tuple(LINES[5:]), 0, Head(7, HASHES[7]), None, (), 5)


@pytest.mark.parametrize(("start", "duplicates"), [(0, 5), (2, 3), (4, 1)])
def test_lines_up_to_the_held_head_are_duplicates(start: int, duplicates: int) -> None:
    result = decide(holding(4), body(LINES[start:]), now=NOW)
    assert result == Accepted(tuple(LINES[5:]), duplicates, Head(7, HASHES[7]), None, (), 5)


@pytest.mark.parametrize("start", [0, 3, 4])
def test_a_resend_of_held_lines_only_changes_nothing(start: int) -> None:
    held = holding(4)
    result = decide(held, body(LINES[start:5]), now=NOW)
    assert result == Accepted((), 5 - start, Head(4, HASHES[4]), None, (), None)


def test_a_duplicate_only_report_is_taken_even_when_full() -> None:
    held = holding(4, files=(LiveFile("a", 10_000, NOW),))
    result = decide(held, body(LINES[3:5]), now=NOW, max_bytes=100)
    assert isinstance(result, Accepted)
    assert result.lines == ()


def fork(offered: int) -> Refused:
    message = f"the report starts at seq {offered}, which doesn't extend the held head"
    return Refused(409, "fork", message, state="fork", offered_seq=offered)


def test_a_report_past_the_head_is_a_gap() -> None:
    message = "the report starts at seq 6, which doesn't extend the held head"
    assert decide(holding(4), body(LINES[6:]), now=NOW) == Refused(
        409, "gap", message, state="gap", offered_seq=6
    )


OTHER = chain(8, tick=1000)  # another history: the same seqs, other records


@pytest.mark.parametrize(
    ("lines", "offered"),
    [
        (OTHER[5:], 5),  # the next seq, another prev
        (OTHER[4:], 4),  # holds the head's seq with another hash
        (OTHER[0:7], 0),
        (LINES[0:3], 0),  # held lines, short of the head: nothing to check them against
        (LINES[1:4], 1),
        (OTHER[0:1], 0),  # a gateway that lost its volume
    ],
)
def test_anything_else_is_a_fork(lines: list[bytes], offered: int) -> None:
    assert decide(holding(4), body(lines), now=NOW) == fork(offered)


def test_the_next_seq_with_another_prev_is_a_fork_not_a_gap() -> None:
    other = chain(1, seq=5, prev=HASHES[3])
    assert decide(holding(4), body(other), now=NOW) == fork(5)


# --- row 10: the copy's bound and pruning --------------------------------------------------------


OLD = NOW - KEEP_MS - 1  # received more than 30 days ago
BOUNDARY = NOW - KEEP_MS  # received exactly 30 days ago: kept
NEW_BYTES = 3 * SIZE  # LINES[5:]


def full(offered: int = 5) -> Refused:
    message = "the copy is full and holds nothing received long enough ago to prune"
    return Refused(409, "full", message, state="full", offered_seq=offered)


def files(*specs: tuple[int, int]) -> tuple[LiveFile, ...]:
    return tuple(LiveFile(f"f{n}", size, at) for n, (size, at) in enumerate(specs))


def test_a_report_that_fits_exactly_is_taken() -> None:
    held = holding(4, files=files((1000, NOW), (500, NOW)))
    result = decide(held, body(LINES[5:]), now=NOW, max_bytes=1500 + NEW_BYTES)
    assert isinstance(result, Accepted)
    assert result.prune == ()


def test_a_byte_over_with_nothing_old_enough_is_full() -> None:
    held = holding(4, files=files((1000, BOUNDARY), (500, NOW)))
    result = decide(held, body(LINES[5:]), now=NOW, max_bytes=1500 + NEW_BYTES - 1)
    assert result == full()


def test_the_oldest_file_goes_once_received_more_than_30_days_ago() -> None:
    held = holding(4, files=files((1000, OLD), (500, NOW)))
    result = decide(held, body(LINES[5:]), now=NOW, max_bytes=1500 + NEW_BYTES - 1)
    assert isinstance(result, Accepted)
    assert result.prune == ("f0",)


def test_the_received_time_counts_not_the_records() -> None:
    held = holding(4, files=files((1000, OLD), (500, NOW)))
    result = decide(held, body(LINES[5:]), now=OLD + KEEP_MS, max_bytes=1500 + NEW_BYTES - 1)
    assert result == full()


def test_pruning_stops_once_the_report_fits() -> None:
    held = holding(4, files=files((1000, OLD), (1000, OLD), (1000, OLD), (10, NOW)))
    result = decide(held, body(LINES[5:]), now=NOW, max_bytes=2010 + NEW_BYTES)
    assert isinstance(result, Accepted)
    assert result.prune == ("f0",)
    result = decide(held, body(LINES[5:]), now=NOW, max_bytes=2010 + NEW_BYTES - 1)
    assert isinstance(result, Accepted)
    assert result.prune == ("f0", "f1")


def test_pruning_stops_at_the_first_recent_file() -> None:
    held = holding(4, files=files((1000, OLD), (1000, NOW), (1000, OLD), (10, NOW)))
    assert decide(held, body(LINES[5:]), now=NOW, max_bytes=1010 + NEW_BYTES) == full()


def test_the_newest_file_never_goes() -> None:
    held = holding(
        4,
        files=files(
            (1000, OLD),
        ),
    )
    assert decide(held, body(LINES[5:]), now=NOW, max_bytes=1000) == full()
    held = holding(4, files=files((1000, OLD), (1000, OLD)))
    assert decide(held, body(LINES[5:]), now=NOW, max_bytes=1000 + NEW_BYTES - 1) == full()


def test_nothing_is_pruned_when_pruning_can_t_make_room() -> None:
    held = holding(4, files=files((1000, OLD), (1000, OLD)))
    assert decide(held, body(LINES[5:]), now=NOW, max_bytes=NEW_BYTES) == full()


def test_first_use_counts_against_the_bound_too() -> None:
    assert decide(Held(), body(LINES[:3]), now=NOW, max_bytes=NEW_BYTES - 1) == full(0)
    assert isinstance(decide(Held(), body(LINES[:3]), now=NOW, max_bytes=NEW_BYTES), Accepted)


def test_only_lines_past_the_head_count() -> None:
    held = holding(
        4,
        files=files(
            (0, NOW),
        ),
    )
    assert isinstance(decide(held, body(LINES[2:]), now=NOW, max_bytes=NEW_BYTES), Accepted)
    assert decide(held, body(LINES[2:]), now=NOW, max_bytes=NEW_BYTES - 1) == full(2)


def test_the_default_bound_is_64_mib() -> None:
    big = holding(4, files=files((REPORTED_MAX_BYTES - NEW_BYTES, NOW), (0, NOW)))
    assert isinstance(decide(big, body(LINES[5:]), now=NOW), Accepted)
    big = holding(4, files=files((REPORTED_MAX_BYTES - NEW_BYTES + 1, NOW), (0, NOW)))
    assert decide(big, body(LINES[5:]), now=NOW) == full()
    old = NOW - REPORTED_KEEP_DAYS * DAY_MS - 1
    big = holding(4, files=files((REPORTED_MAX_BYTES, old), (0, NOW)))
    result = decide(big, body(LINES[5:]), now=NOW)
    assert isinstance(result, Accepted)
    assert result.prune == ("f0",)


# --- what the copy holds -------------------------------------------------------------------------


def test_held() -> None:
    assert Held().head == Head(None, None, "ok")
    assert Held().size == 0
    assert Held().received_ms is None
    held = Held("gap", 3, 9, HASHES[1], files((10, 7), (20, 30), (5, 12)))
    assert held.head == Head(9, HASHES[1], "gap")
    assert held.size == 35
    assert held.received_ms == 30


# --- the restart (J.4) ---------------------------------------------------------------------------


def test_the_live_chain_as_an_epoch() -> None:
    held = Held("full", 3, 9, HASHES[1], files((10, 7), (20, 30)))
    assert archive(held, "archive-1") == Epoch("archive-1", 3, 9, HASHES[1], 30, 30)
    assert archive(Held(), "archive-1") is None
    # A copy that holds no head, or no files, has nothing to archive.
    assert (
        archive(
            Held(
                "ok",
                3,
                None,
                None,
                files(
                    (10, 7),
                ),
            ),
            "a",
        )
        is None
    )
    assert (
        archive(
            Held(
                "ok",
                3,
                9,
                None,
                files(
                    (10, 7),
                ),
            ),
            "a",
        )
        is None
    )
    assert archive(Held("ok", 3, 9, HASHES[1], ()), "a") is None
    assert archive(
        Held(
            "ok",
            None,
            9,
            HASHES[1],
            files(
                (10, 7),
            ),
        ),
        "a",
    ) == Epoch("a", 9, 9, HASHES[1], 7, 10)


def epoch(name: str, size: int) -> Epoch:
    return Epoch(name, 0, 1, HASHES[1], 0, size)


def test_a_restart_drops_the_oldest_archives_until_they_fit() -> None:
    old, mid, live = epoch("a", 40), epoch("b", 30), epoch("c", 50)
    assert plan_restart([old, mid], live, max_bytes=120) == ()
    assert plan_restart([old, mid], live, max_bytes=119) == (old,)
    assert plan_restart([old, mid], live, max_bytes=80) == (old,)
    assert plan_restart([old, mid], live, max_bytes=79) == (old, mid)
    assert plan_restart([old, mid], live, max_bytes=49) == (old, mid, live)
    assert plan_restart([old, mid], None, max_bytes=70) == ()
    assert plan_restart([old, mid], None, max_bytes=69) == (old,)
    assert plan_restart([], None, max_bytes=0) == ()


def test_the_default_archive_bound_is_64_mib() -> None:
    old, live = epoch("a", 1), epoch("b", REPORTED_ARCHIVE_MAX_BYTES - 1)
    assert plan_restart([old], live) == ()
    assert plan_restart([old], epoch("b", REPORTED_ARCHIVE_MAX_BYTES)) == (old,)


def test_a_refusal_never_holds_a_line() -> None:
    marker = "0000000000000001"
    for result in [
        decide(holding(4), body(OTHER[5:]), now=NOW),
        decide(Held(), {"v": 1, "lines": [LINES[0].decode(), "x" + marker]}, now=NOW),
        decide(
            holding(
                4,
                files=files(
                    (10**9, NOW),
                ),
            ),
            body(LINES[5:]),
            now=NOW,
        ),
    ]:
        assert isinstance(result, Refused)
        assert marker not in result.message
        assert "sha256" not in result.message


# --- the stateful property -----------------------------------------------------------------------

MAX_BYTES = 4000
ROTATE_BYTES = 1200
ARCHIVE_MAX_BYTES = 6000
BATCH_BYTES = 2000  # a body's bytes count at least the lines it stores


class ReportMachine(RuleBasedStateMachine):
    """The reporter and the copy over any history: every record accepted is the gateway's, and
    is kept once; a fork or gap is refused and stays refused until a restart; a restart always
    makes room for the next honest report."""

    def __init__(self) -> None:
        super().__init__()
        self.gateway = GatewayModel()
        self.copy = CopyModel(
            max_bytes=MAX_BYTES, rotate_bytes=ROTATE_BYTES, archive_max_bytes=ARCHIVE_MAX_BYTES
        )
        self.now = NOW
        self.posted: list[bytes] = []

    def expected(self) -> str | None:
        """What the copy should make of the reporter's next round, from the model's truth:
        ``accept`` when the gateway's history holds the copy's head, else ``gap`` or ``fork``;
        None when there is nothing to send."""
        held, records = self.copy.held, self.gateway.records
        if held.state != "ok" or not records:
            return None
        if held.head_seq is None:
            return "accept"
        follows = any(
            seq == held.head_seq + 1 and ledgerformat.parse(line).prev == held.head_hash
            for seq, line in records
        )
        if follows or self.gateway.holds(held.head_seq, held.head_hash):
            return "accept" if records[-1][0] > held.head_seq else None
        return "gap" if records[0][0] > held.head_seq + 1 else "fork"

    def would_be_full(self, before: Held, posted: list[bytes]) -> bool:
        """Whether a report's new lines can't fit, after pruning what J.4 allows."""
        new = [
            line
            for line in posted
            if before.head_seq is None or ledgerformat.parse(line).seq > before.head_seq
        ]
        total = before.size + sum(len(line) + 1 for line in new)
        for file in before.files[:-1]:
            if total <= MAX_BYTES or self.now - file.received_ms <= KEEP_MS:
                break
            total -= file.size
        return total > MAX_BYTES

    def check_answer(self, before: Held, posted: list[bytes], result: Accepted | Refused) -> None:
        """A ``full`` refusal only when the lines can't fit; an accepted report prunes only files
        received more than 30 days ago, oldest first, never the newest, and holds only the
        gateway's own records at their seqs."""
        if isinstance(result, Refused):
            if result.reason == "full":
                assert self.would_be_full(before, posted)
            return
        assert not self.would_be_full(before, posted)
        assert result.prune == tuple(file.name for file in before.files[: len(result.prune)])
        assert len(result.prune) < max(len(before.files), 1)
        for file in before.files[: len(result.prune)]:
            assert self.now - file.received_ms > KEEP_MS
        start = result.from_seq
        for seq, line in enumerate(result.lines, start=0 if start is None else start):
            assert (seq, line) in self.gateway.records

    def check_round(self, expected: str | None, mark: int) -> None:
        """The reporter's round from ``history[mark]`` on, against the model's expectation."""
        posts = self.copy.history[mark:]
        if expected is None:
            assert posts == []
            return
        assert posts
        for n, (before, posted, result) in enumerate(posts):
            self.check_answer(before, posted, result)
            if isinstance(result, Refused):
                assert n == len(posts) - 1
                if expected == "accept" or n > 0:
                    assert result.reason == "full"
                else:
                    assert result.reason == expected
                assert self.copy.held.state == result.reason
                return
        assert expected == "accept"

    @initialize(count=st.integers(0, 10))
    def start(self, count: int) -> None:
        self.gateway.append(count)
        self.report()

    @rule(count=st.integers(1, 10), big=st.booleans(), then_report=st.booleans())
    def append(self, count: int, big: bool, then_report: bool) -> None:
        """Records written, and reported at once (the reporter wakes on an append) or not yet."""
        self.gateway.append(count, big=big)
        if then_report:
            self.report()

    @rule()
    def report(self) -> None:
        before, expected, mark = self.copy.held, self.expected(), len(self.copy.history)
        report_round(self.gateway, self.copy, self.now, max_bytes=BATCH_BYTES)
        self.check_round(expected, mark)
        if before.state != "ok":
            assert self.copy.held == before

    @rule(back=st.integers(1, 4))
    def resend(self, back: int) -> None:
        """A report sent again after its answer was lost, with what followed: the lines the copy
        holds are trimmed, the rest extend it."""
        held = self.copy.held
        if held.state != "ok" or held.head_seq is None:
            return
        if not self.gateway.holds(held.head_seq, held.head_hash):
            return
        start = max(held.head_seq - back + 1, self.gateway.records[0][0])
        lines = self.gateway.read(start - 1)[:MAX_LINES]
        result = self.copy.report(lines, self.now)
        self.check_answer(held, lines, result)
        if isinstance(result, Refused):
            assert result.reason == "full"
            return
        assert result.duplicates == held.head_seq - start + 1
        assert list(result.lines) == lines[result.duplicates :]

    @rule(count=st.integers(1, 12))
    def prune(self, count: int) -> None:
        self.gateway.prune(count)

    @rule(rounds=st.integers(1, 10), days=st.sampled_from([1, 5, 10]))
    def steady(self, rounds: int, days: int) -> None:
        """A record, reported, every few days: the copy fills over time, and the files it
        received long enough ago make room."""
        for _ in range(rounds):
            self.gateway.append(1)
            self.report()
            self.now += days * DAY_MS

    @rule(count=st.integers(1, 12), keep=st.integers(1, 4))
    def fall_behind(self, count: int, keep: int) -> None:
        """The gateway writes on while the vault can't take reports, and prunes beyond its
        bound: what it kept may start past the copy's head."""
        self.gateway.append(count)
        self.gateway.prune(len(self.gateway.records) - keep)

    @rule(count=st.integers(1, 4), then=st.integers(0, 4))
    def restore(self, count: int, then: int) -> None:
        """The gateway's volume restored from an older backup, then written to again."""
        self.gateway.rewind(count)
        self.gateway.append(then)

    @rule(then=st.integers(0, 4))
    def lose_volume(self, then: int) -> None:
        self.gateway.lose_volume()
        self.gateway.append(then)

    @rule(days=st.sampled_from([0, 1, 15, REPORTED_KEEP_DAYS, 40]), extra=st.integers(0, 1))
    def wait(self, days: int, extra: int) -> None:
        self.now += days * DAY_MS + extra

    @rule()
    def post_while_refusing(self) -> None:
        """Whatever a gateway sends while the copy refuses is refused, and changes nothing."""
        before = self.copy.held
        if before.state == "ok" or not self.gateway.records:
            return
        result = self.copy.report(self.gateway.read(-1)[:8], self.now)
        assert isinstance(result, Refused)
        assert result.reason == "refused_until_restart"
        assert self.copy.held == before

    @rule(writer_vault=st.booleans())
    def forged(self, writer_vault: bool) -> None:
        """A report that isn't a chain of gateway records changes nothing."""
        before = self.copy.held
        prev = GENESIS if before.head_hash is None else before.head_hash
        seq = 0 if before.head_seq is None else before.head_seq + 1
        lines = [vault_line(seq, prev)] if writer_vault else [*chain(1, seq=seq, prev=prev)] * 2
        result = self.copy.report(lines, self.now)
        assert isinstance(result, Refused)
        assert self.copy.held == before

    @rule()
    def restart(self) -> None:
        archived = self.copy.held.size
        self.copy.restart(self.now)
        assert self.copy.held == Held()
        assert sum(e.size for e, _ in self.copy.archives) <= ARCHIVE_MAX_BYTES
        if archived:
            assert self.copy.archives[-1][0].size == archived
        expected, mark = self.expected(), len(self.copy.history)
        results = report_round(self.gateway, self.copy, self.now, max_bytes=BATCH_BYTES)
        self.check_round(expected, mark)
        if self.gateway.records:
            assert isinstance(results[0], Accepted)  # the next honest report is taken

    @invariant()
    def nothing_lost_or_held_twice(self) -> None:
        live = self.copy.live()
        assert self.copy.accepted == self.copy.pruned + live
        held = self.copy.held
        assert held.size == sum(len(line) + 1 for line in live) <= MAX_BYTES
        if not live:
            assert held.head_seq is None
            return
        first = ledgerformat.parse(self.copy.accepted[0])
        verified = ledgerformat.verify(self.copy.accepted, prev=first.prev, seq=first.seq)
        assert verified.broken_at is None
        assert (verified.head_seq, verified.head_hash) == (held.head_seq, held.head_hash)
        assert held.start_seq == first.seq


TestReportMachine = ReportMachine.TestCase
TestReportMachine.settings = hypothesis_settings(
    max_examples=50, stateful_step_count=20, deadline=None
)
