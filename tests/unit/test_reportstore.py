"""The vault's copy of the gateway's ledger on disk (M5 design J.4, N.1, N.2).

The store applies :func:`zoeymcp.vault.reports.decide`'s answers to files: appends with rotation,
pruning by received time, ``head.json``, sticky refusals, recovery from a torn tail, a stale or
missing ``head.json`` and a broken chain, and the restart. A differential test runs the same
reports through :class:`tests.unit.report_model.CopyModel` and the store, and checks they agree.
"""

from __future__ import annotations

import io
import json
import os
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any

import pytest

from tests.unit.report_model import T0, CopyModel, GatewayModel, asked_line
from zoeymcp.common import canonical, ledgerreport
from zoeymcp.common import files as common_files
from zoeymcp.common.ledgerformat import GENESIS, line_hash
from zoeymcp.gateway import reporting
from zoeymcp.vault import logs, reportstore
from zoeymcp.vault.reports import DAY_MS, KEEP_MS, Accepted, Epoch, Held, LiveFile, Refused
from zoeymcp.vault.reportstore import (
    HEAD_FILE,
    REPORTED_DIR,
    CopyUnavailable,
    NotRestartable,
    PlanChanged,
    ReportStore,
)

SIZE = 545  # one asked_line with its newline


def chain(count: int, *, seq: int = 0, prev: str = GENESIS, tick: int = 0) -> list[bytes]:
    lines = []
    for n in range(count):
        line = asked_line(seq + n, prev, tick + seq + n + 1)
        lines.append(line)
        prev = line_hash(line)
    return lines


def body(lines: list[bytes]) -> Any:
    """The body as the endpoint parses it."""
    return canonical.loads_strict(ledgerreport.encode(lines))


LINES = chain(12)
OTHER = chain(12, tick=1000)  # another history from the same start: a fork


class Clock:
    def __init__(self, now: int = T0) -> None:
        self.now = now

    def __call__(self) -> int:
        return self.now


@pytest.fixture
def captured() -> Iterator[io.StringIO]:
    buffer = io.StringIO()
    logs.set_stream(buffer)
    try:
        yield buffer
    finally:
        logs.set_stream(None)


def events(buffer: io.StringIO, kind: str) -> list[dict[str, Any]]:
    parsed = [json.loads(line) for line in buffer.getvalue().splitlines()]
    return [line for line in parsed if line["event"] == kind]


def opened(state_dir: Path, clock: Clock | None = None, **options: Any) -> ReportStore:
    return ReportStore.open(state_dir, clock=clock or Clock(), **options)


def copy_dir(state_dir: Path) -> Path:
    return state_dir / REPORTED_DIR


def head_json(state_dir: Path) -> dict[str, Any]:
    value: dict[str, Any] = json.loads((copy_dir(state_dir) / HEAD_FILE).read_bytes())
    return value


def live(state_dir: Path) -> dict[str, bytes]:
    return {
        p.name: p.read_bytes()
        for p in sorted(copy_dir(state_dir).iterdir())
        if p.name.endswith(".jsonl")
    }


def joined(lines: list[bytes]) -> bytes:
    return b"".join(line + b"\n" for line in lines)


# --- reports -------------------------------------------------------------------------------------


def test_a_new_copy_is_empty_and_writes_its_head(tmp_path: Path) -> None:
    store = opened(tmp_path)
    assert (store.state, store.held, store.broken_at) == ("ok", Held(), None)
    assert stat_mode(copy_dir(tmp_path)) == 0o700 or os.name == "nt"
    assert head_json(tmp_path) == {
        "v": 1,
        "state": "ok",
        "start_seq": None,
        "start_prev": None,
        "head_seq": None,
        "head_hash": None,
        "refused": None,
        "files": {},
        "archives": [],
    }


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def test_the_first_report_is_kept_as_received(tmp_path: Path, captured: io.StringIO) -> None:
    store = opened(tmp_path)
    result = store.report(body(LINES[:3]))
    assert isinstance(result, Accepted)
    assert live(tmp_path) == {"000000000000.jsonl": joined(LINES[:3])}
    if os.name != "nt":
        assert stat_mode(copy_dir(tmp_path) / "000000000000.jsonl") == 0o600
    assert store.held == Held(
        "ok", 0, 2, line_hash(LINES[2]), (LiveFile("000000000000.jsonl", 3 * SIZE, T0),)
    )
    saved = head_json(tmp_path)
    assert (saved["start_seq"], saved["start_prev"]) == (0, GENESIS)
    assert (saved["head_seq"], saved["head_hash"]) == (2, line_hash(LINES[2]))
    assert saved["files"] == {"000000000000.jsonl": T0}
    [line] = events(captured, "ledger_report_accepted")
    assert line["from_seq"] == 0
    assert (line["head_seq"], line["head_hash"], line["pruned"]) == (2, line_hash(LINES[2]), 0)


def test_a_resend_is_trimmed_to_what_extends(tmp_path: Path) -> None:
    store = opened(tmp_path)
    store.report(body(LINES[:3]))
    result = store.report(body(LINES[2:5]))
    assert isinstance(result, Accepted)
    assert result.duplicates == 1
    assert live(tmp_path) == {"000000000000.jsonl": joined(LINES[:5])}
    before = live(tmp_path), head_json(tmp_path)
    duplicate = store.report(body(LINES[3:5]))
    assert isinstance(duplicate, Accepted)
    assert duplicate.from_seq is None
    assert (live(tmp_path), head_json(tmp_path)) == before


def test_a_new_file_starts_at_the_rotation_size(tmp_path: Path) -> None:
    store = opened(tmp_path, rotate_bytes=2 * SIZE)
    store.report(body(LINES[:5]))
    assert live(tmp_path) == {
        "000000000000.jsonl": joined(LINES[:2]),
        "000000000002.jsonl": joined(LINES[2:4]),
        "000000000004.jsonl": joined(LINES[4:5]),
    }
    store.report(body(LINES[5:6]))
    assert live(tmp_path)["000000000004.jsonl"] == joined(LINES[4:6])
    assert [f.size for f in store.held.files] == [2 * SIZE, 2 * SIZE, 2 * SIZE]


@pytest.mark.parametrize(("offered", "reason"), [(OTHER[3:5], "fork"), (LINES[5:7], "gap")])
def test_a_fork_or_gap_sticks_across_a_restart_of_the_vault(
    tmp_path: Path, captured: io.StringIO, offered: list[bytes], reason: str
) -> None:
    clock = Clock()
    store = opened(tmp_path, clock)
    store.report(body(LINES[:3]))
    clock.now += 5
    result = store.report(body(offered))
    assert isinstance(result, Refused)
    assert (result.status, result.reason) == (409, reason)
    assert store.state == reason
    refused = {
        "reason": reason,
        "held_seq": 2,
        "offered_seq": 3 if reason == "fork" else 5,
        "at": T0 + 5,
    }
    assert head_json(tmp_path)["refused"] == refused
    [line] = events(captured, "ledger_report_refused")
    assert line == {**line, "reason": reason, "held_seq": 2, "level": "critical"}
    again = opened(tmp_path, clock)
    assert (again.state, again.refused) == (reason, refused)
    sticky = again.report(body(LINES[3:5]))
    assert isinstance(sticky, Refused)
    assert sticky.reason == "refused_until_restart"
    assert live(tmp_path) == {"000000000000.jsonl": joined(LINES[:3])}


def test_old_files_are_pruned_by_when_the_vault_received_them(
    tmp_path: Path, captured: io.StringIO
) -> None:
    clock = Clock()
    store = opened(tmp_path, clock, max_bytes=4 * SIZE, rotate_bytes=2 * SIZE)
    store.report(body(LINES[:4]))
    clock.now += KEEP_MS
    full = store.report(body(LINES[4:5]))
    assert isinstance(full, Refused)
    assert full.reason == "full"
    assert store.state == "full"

    # Received more than 30 days ago: the oldest file goes, never by the records' ts.
    clock = Clock()
    store = opened(tmp_path / "b", clock, max_bytes=4 * SIZE, rotate_bytes=2 * SIZE)
    store.report(body(LINES[:4]))
    clock.now += KEEP_MS + 1
    result = store.report(body(LINES[4:5]))
    assert isinstance(result, Accepted)
    assert result.prune == ("000000000000.jsonl",)
    assert list(live(tmp_path / "b")) == ["000000000002.jsonl", "000000000004.jsonl"]
    assert head_json(tmp_path / "b")["files"] == {
        "000000000002.jsonl": T0,
        "000000000004.jsonl": T0 + KEEP_MS + 1,
    }
    # The chain's start is kept as first used.
    assert (store.held.start_seq, store.start_prev) == (0, GENESIS)
    assert events(captured, "ledger_report_accepted")[-1]["pruned"] == 1


def test_records_are_the_live_chain_as_json(tmp_path: Path) -> None:
    store = opened(tmp_path, rotate_bytes=2 * SIZE)
    assert store.records() == []
    store.report(body(LINES[:3]))
    assert store.records() == [json.loads(line) for line in LINES[:3]]


# --- recovery ------------------------------------------------------------------------------------


@pytest.mark.parametrize("tail", [b'{"v":1,"seq":3', b"not a record\n"])
def test_a_torn_tail_is_cut_and_kept_aside(
    tmp_path: Path, captured: io.StringIO, tail: bytes
) -> None:
    store = opened(tmp_path, rotate_bytes=2 * SIZE)
    store.report(body(LINES[:3]))
    newest = copy_dir(tmp_path) / "000000000002.jsonl"
    newest.write_bytes(newest.read_bytes() + tail)
    clock = Clock(T0 + 7)
    again = opened(tmp_path, clock, rotate_bytes=2 * SIZE)
    assert newest.read_bytes() == joined(LINES[2:3])
    assert (copy_dir(tmp_path) / f"torn-{T0 + 7}.bin").read_bytes() == tail
    assert (again.state, again.held.head_seq, again.broken_at) == ("ok", 2, None)
    [line] = events(captured, "ledger_reported_repaired")
    assert (line["torn_bytes"], line["head_rebuilt"]) == (len(tail), False)
    # The gateway's resend then extends it, each record once.
    again.report(body(LINES[2:5]))
    assert b"".join(live(tmp_path).values()) == joined(LINES[:5])


def test_a_head_json_behind_the_lines_is_rebuilt(tmp_path: Path, captured: io.StringIO) -> None:
    """A crash after the append and before head.json: the lines are the truth."""
    store = opened(tmp_path)
    store.report(body(LINES[:3]))
    stale = (copy_dir(tmp_path) / HEAD_FILE).read_bytes()
    store.report(body(LINES[3:5]))
    (copy_dir(tmp_path) / HEAD_FILE).write_bytes(stale)
    again = opened(tmp_path)
    assert (again.held.head_seq, again.held.head_hash) == (4, line_hash(LINES[4]))
    assert head_json(tmp_path)["head_seq"] == 4
    [line] = events(captured, "ledger_reported_repaired")
    assert (line["torn_bytes"], line["head_rebuilt"]) == (0, True)


@pytest.mark.parametrize("damage", [None, b"{}", b"not json", b'{"v": 2}'])
def test_a_missing_or_bad_head_json_is_rebuilt_from_the_lines(
    tmp_path: Path, damage: bytes | None
) -> None:
    store = opened(tmp_path, rotate_bytes=2 * SIZE)
    store.report(body(LINES[2:7]))
    path = copy_dir(tmp_path) / HEAD_FILE
    if damage is None:
        path.unlink()
    else:
        path.write_bytes(damage)
    again = opened(tmp_path, rotate_bytes=2 * SIZE)
    assert (again.held.start_seq, again.start_prev) == (2, line_hash(LINES[1]))
    assert (again.held.head_seq, again.state) == (6, "ok")
    assert [f.name for f in again.held.files] == list(live(tmp_path))
    assert head_json(tmp_path)["head_seq"] == 6


def test_a_break_inside_the_files_is_marked(tmp_path: Path, captured: io.StringIO) -> None:
    store = opened(tmp_path, rotate_bytes=2 * SIZE)
    store.report(body(LINES[:6]))
    middle = copy_dir(tmp_path) / "000000000002.jsonl"
    middle.write_bytes(joined([OTHER[2], LINES[3]]))
    again = opened(tmp_path, rotate_bytes=2 * SIZE)
    assert again.broken_at == 2
    assert (again.held.head_seq, again.held.head_hash) == (5, line_hash(LINES[5]))
    [line] = events(captured, "ledger_reported_broken")
    assert (line["seq"], line["level"]) == (2, "critical")
    # The copy goes on from its head.
    assert isinstance(again.report(body(LINES[6:7])), Accepted)


def test_an_unreadable_directory_makes_the_copy_unavailable(
    tmp_path: Path, captured: io.StringIO
) -> None:
    copy_dir(tmp_path).write_bytes(b"not a directory")
    store = opened(tmp_path)
    assert store.state == "unavailable"
    with pytest.raises(CopyUnavailable):
        store.report(body(LINES[:1]))
    with pytest.raises(CopyUnavailable):
        store.records()
    with pytest.raises(CopyUnavailable):
        store.records(f"archive-{T0:013d}")
    with pytest.raises(CopyUnavailable):
        store.plan_restart()
    [line] = events(captured, "ledger_reported_unavailable")
    assert line["level"] == "critical"


def test_a_failed_write_is_recovered_from_the_disk(
    tmp_path: Path, captured: io.StringIO, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = opened(tmp_path)
    store.report(body(LINES[:2]))
    real = reportstore._append

    def half(path: Path, data: bytes) -> None:
        real(path, data[: len(data) // 2])
        raise OSError("disk full")

    monkeypatch.setattr(reportstore, "_append", half)
    with pytest.raises(CopyUnavailable):
        store.report(body(LINES[2:5]))
    monkeypatch.setattr(reportstore, "_append", real)
    # Recovered: the half line was cut, a whole one kept, and the copy takes reports again.
    assert store.available
    assert events(captured, "ledger_reported_not_written")[0]["level"] == "critical"
    head = store.held.head_seq
    assert head is not None
    store.report(body(LINES[head - 1 : 6]))
    assert live(tmp_path) == {"000000000000.jsonl": joined(LINES[:6])}


def test_a_refusal_that_cant_be_written_still_holds(
    tmp_path: Path, captured: io.StringIO, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = opened(tmp_path)
    store.report(body(LINES[:2]))

    def broken(*args: Any, **kwargs: Any) -> None:
        raise OSError("read-only")

    monkeypatch.setattr(common_files, "write_atomic", broken)
    assert isinstance(store.report(body(OTHER[1:3])), Refused)
    assert store.state == "fork"
    assert events(captured, "ledger_reported_not_written")[0]["level"] == "error"


# --- the restart ---------------------------------------------------------------------------------


def forked(state_dir: Path, clock: Clock, **options: Any) -> ReportStore:
    store = opened(state_dir, clock, **options)
    store.report(body(LINES[:4]))
    store.report(body(OTHER[2:4]))
    assert store.state == "fork"
    return store


def test_a_copy_that_takes_reports_isnt_restarted(tmp_path: Path) -> None:
    store = opened(tmp_path)
    with pytest.raises(NotRestartable):
        store.plan_restart()
    with pytest.raises(NotRestartable):
        store.restart()


def test_a_restart_archives_the_chain_and_starts_again(
    tmp_path: Path, captured: io.StringIO
) -> None:
    clock = Clock()
    store = forked(tmp_path, clock, rotate_bytes=2 * SIZE)
    plan = store.plan_restart()
    clock.now += 10
    assert store.plan_restart() == plan
    live_epoch = Epoch("", 0, 3, line_hash(LINES[3]), T0, 4 * SIZE)
    assert (plan.state, plan.archive, plan.drop) == ("fork", live_epoch, ())
    assert plan.to_json()["archive"]["name"] is None
    done = store.restart(plan)
    name = f"archive-{T0 + 10:013d}"
    assert done.archive == Epoch(name, 0, 3, line_hash(LINES[3]), T0, 4 * SIZE)
    assert live(tmp_path) == {}
    assert sorted(p.name for p in (copy_dir(tmp_path) / name).iterdir()) == [
        "000000000000.jsonl",
        "000000000002.jsonl",
    ]
    assert (store.state, store.held, store.refused) == ("ok", Held(), None)
    saved = head_json(tmp_path)
    assert (saved["state"], saved["head_seq"], saved["refused"]) == ("ok", None, None)
    assert saved["archives"] == [
        {
            "name": name,
            "first_seq": 0,
            "head_seq": 3,
            "head_hash": line_hash(LINES[3]),
            "received_ms": T0,
            "size": 4 * SIZE,
            "dropped": False,
        }
    ]
    [line] = events(captured, "ledger_reported_restarted")
    assert line["lifted"] == "fork"
    assert line["archived"] == {
        "name": name,
        "first_seq": 0,
        "head_seq": 3,
        "head_hash": line_hash(LINES[3]),
    }
    # The next report starts a new chain on trust, the forked one included.
    assert isinstance(store.report(body(OTHER[:3])), Accepted)
    assert opened(tmp_path).archives() == store.archives()


def test_a_restart_refuses_a_plan_that_changed(tmp_path: Path) -> None:
    clock = Clock()
    store = forked(tmp_path, clock)
    plan = store.plan_restart()
    changed = type(plan)(plan.state, plan.refused, None, ())
    with pytest.raises(PlanChanged) as info:
        store.restart(changed)
    assert info.value.plan == plan
    assert store.state == "fork"


def test_a_restart_drops_the_oldest_archives_and_keeps_their_anchors(
    tmp_path: Path, captured: io.StringIO
) -> None:
    clock = Clock()
    store = forked(tmp_path, clock, archive_max_bytes=5 * SIZE)
    first = store.restart()
    assert first.drop == ()
    store.report(body(LINES[:2]))
    store.report(body(OTHER[1:2]))
    clock.now += 1
    plan = store.plan_restart()
    assert [epoch.name for epoch in plan.drop] == [first.archive.name]  # type: ignore[union-attr]
    second = store.restart(plan)
    assert not (copy_dir(tmp_path) / first.archive.name).exists()  # type: ignore[union-attr]
    archives = store.archives()
    assert [(a["name"], a["dropped"]) for a in archives] == [
        (first.archive.name, True),  # type: ignore[union-attr]
        (second.archive.name, False),  # type: ignore[union-attr]
    ]
    assert archives[0]["head_hash"] == line_hash(LINES[3])
    dropped = events(captured, "ledger_reported_restarted")[1]["dropped"]
    assert first.archive is not None
    assert dropped == [
        {
            "name": first.archive.name,
            "first_seq": 0,
            "head_seq": 3,
            "head_hash": line_hash(LINES[3]),
        }
    ]


def test_a_live_chain_over_the_archive_bound_is_dropped_too(tmp_path: Path) -> None:
    clock = Clock()
    store = forked(tmp_path, clock, archive_max_bytes=SIZE)
    done = store.restart()
    assert done.archive is not None
    assert done.drop == (done.archive,)
    assert not (copy_dir(tmp_path) / done.archive.name).exists()
    assert live(tmp_path) == {}
    assert store.archives()[0]["dropped"] is True


def test_a_full_copy_with_nothing_held_restarts(tmp_path: Path) -> None:
    store = opened(tmp_path, max_bytes=SIZE)
    assert isinstance(store.report(body(LINES[:2])), Refused)
    plan = store.restart()
    assert (plan.state, plan.archive) == ("full", None)
    assert isinstance(store.report(body(LINES[:1])), Accepted)


def test_an_archive_a_cut_restart_left_unlisted_is_found(tmp_path: Path) -> None:
    """A crash after the move and before head.json: the archive is listed at recovery."""
    store = forked(tmp_path, Clock())
    target = copy_dir(tmp_path) / f"archive-{T0:013d}"
    target.mkdir()
    for name in live(tmp_path):
        os.replace(copy_dir(tmp_path) / name, target / name)
    again = opened(tmp_path)
    assert again.state == "fork"  # head.json still says so: the operator restarts again
    assert again.archives() == [
        {
            "name": target.name,
            "first_seq": 0,
            "head_seq": 3,
            "head_hash": line_hash(LINES[3]),
            "received_ms": again.archived[0].epoch.received_ms,
            "size": 4 * SIZE,
            "dropped": False,
        }
    ]
    assert again.restart().archive is None
    assert store  # the first store is stale now


def test_an_archived_epoch_is_still_readable(tmp_path: Path) -> None:
    """J.4: the view reads an archived epoch's records, all of them, oldest first; a dropped one
    has only its anchor left, and a name the copy doesn't list is refused."""
    clock = Clock()
    store = forked(tmp_path, clock, rotate_bytes=2 * SIZE, archive_max_bytes=5 * SIZE)
    first = store.restart()
    assert first.archive is not None
    name = first.archive.name
    assert store.records(name) == [json.loads(line) for line in LINES[:4]]
    assert store.records() == []  # the live chain starts again
    store.report(body(LINES[:2]))
    (copy_dir(tmp_path) / name / "notes.txt").write_bytes(b"not a chain file")
    assert store.records(name) == [json.loads(line) for line in LINES[:4]]
    for unknown in ("archive-0000000000000", "000000000000.jsonl", "..", ""):
        with pytest.raises(KeyError):
            store.records(unknown)
    store.report(body(OTHER[1:2]))
    clock.now += 1
    second = store.restart()
    assert [epoch.name for epoch in second.drop] == [name]
    with pytest.raises(KeyError):
        store.records(name)  # dropped: its anchor is listed, its files are gone
    assert second.archive is not None
    assert store.records(second.archive.name) == [json.loads(line) for line in LINES[:2]]


def test_archive_names_never_repeat(tmp_path: Path) -> None:
    clock = Clock()
    store = forked(tmp_path, clock)
    first = store.restart()
    store.report(body(LINES[:2]))
    store.report(body(OTHER[1:2]))
    second = store.restart()
    assert first.archive is not None
    assert second.archive is not None
    assert second.archive.name == f"archive-{T0 + 1:013d}" != first.archive.name


# --- the store follows the model -----------------------------------------------------------------


def test_the_store_follows_the_copy_model(tmp_path: Path) -> None:
    """The same reports through :class:`CopyModel` and the store: the same answers, heads and
    files, across rotation, pruning, a fork, a restart and a restored gateway."""
    clock = Clock(T0)
    bounds = {"max_bytes": 12 * SIZE, "rotate_bytes": 3 * SIZE, "archive_max_bytes": 20 * SIZE}
    model = CopyModel(**bounds)  # type: ignore[arg-type]
    store = opened(tmp_path, clock, **bounds)
    gateway = GatewayModel()

    def both(lines: Sequence[bytes]) -> None:
        expected = model.report(lines, clock.now)
        assert store.report(body(list(lines))) == expected
        assert store.held == model.held
        assert live(tmp_path) == {name: joined(lines) for name, lines in model.files.items()}

    def round_() -> None:
        while True:
            head = store.held.head
            after = reporting.read_after(head, gateway.head_seq)
            if after is None:
                return
            lines = reporting.pending(head, gateway.read(after), max_bytes=4 * SIZE)
            if not lines:
                return
            both(lines)
            if store.state != "ok":
                return

    def state() -> str:
        return store.state

    def restart() -> None:
        model.restart(clock.now)
        store.restart()
        assert store.held == model.held == Held()

    gateway.append(7)
    round_()
    # Resends after a crash: held lines only, then held lines and new ones.
    both([line for seq, line in gateway.records if seq >= gateway.head_seq - 2])
    gateway.append(2)
    both([line for seq, line in gateway.records if seq >= gateway.head_seq - 3])
    clock.now += DAY_MS
    gateway.append(6)
    round_()
    assert state() == "full"
    restart()
    gateway.prune(5)
    round_()
    clock.now += 31 * DAY_MS
    gateway.append(5)
    round_()
    gateway.rewind(3)
    gateway.append(4)
    round_()
    assert state() == "fork"
    restart()
    gateway.prune(8)
    round_()
    assert state() == "ok"
    results = [result for _, _, result in model.history]
    reasons = {result.reason for result in results if isinstance(result, Refused)}
    assert reasons == {"full", "fork"}
    assert any(isinstance(result, Accepted) and result.prune for result in results)
    assert any(isinstance(result, Accepted) and result.duplicates for result in results)
