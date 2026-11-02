"""A ledger's file layer, for any writer's chain (M8 design J.1; M4 design F.3 to F.5).

On ``tmp_path``, synchronously, with no key and no role: appends that chain and rotate, the
open-ref index and its rebuild, a torn tail moved aside, recovery closing every open ref once,
pruning, and the reads. The gateway's own ledger tests (``tests/gateway/test_ledger.py``) are the
regression bar for the move; these pin the layer the vault's chain stands on.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from zoeymcp.common import ledgerformat
from zoeymcp.common.ledgerfile import INDEX_FILE, LedgerFile, Recovery

PIN = "sha256:" + "b" * 64
DIGEST = "hmac-sha256:" + "a" * 64
REF_A, REF_B, REF_C = "000000000000000a", "000000000000000b", "000000000000000c"


class Clock:
    def __init__(self) -> None:
        self.now = 1_767_276_000_000

    def __call__(self) -> int:
        self.now += 1
        return self.now


class Events:
    """The role's log, as the file layer calls it."""

    def __init__(self) -> None:
        self.seen: list[tuple[str, dict[str, Any]]] = []

    def __call__(self, kind: str, **fields: Any) -> None:
        self.seen.append((kind, fields))

    def named(self, kind: str) -> list[dict[str, Any]]:
        return [fields for name, fields in self.seen if name == kind]


def chain(
    directory: Path,
    events: Events | None = None,
    *,
    max_bytes: int = 2**26,
    rotate_bytes: int = 4 * 2**20,
    writer: str = "gateway",
    clock: Clock | None = None,
    keep_ms: int | None = None,
) -> LedgerFile:
    directory.mkdir(mode=0o700, exist_ok=True)
    return LedgerFile(
        directory,
        max_bytes=max_bytes,
        clock=clock or Clock(),
        event=events or Events(),
        rotate_bytes=rotate_bytes,
        writer=writer,
        keep_ms=keep_ms,
    )


def opened(directory: Path, events: Events | None = None, **options: Any) -> LedgerFile:
    """A chain recovered as start-up recovers it, its report checked by the caller."""
    found = chain(directory, events, **options)
    found.recover()
    return found


def asked(client: str = "agent1") -> dict[str, Any]:
    return {
        "client": client,
        "server": "mail",
        "tool": "send_note",
        "where": "gateway",
        "era": "legacy",
        "args": DIGEST,
        "pin": PIN,
        "text": DIGEST,
        "chars": 10,
        "writes": 1,
        "expires": 1,
    }


def call(
    found: LedgerFile,
    ref: str,
    *,
    decision: str | None = "accept",
    outcome: str | None = "ok",
    client: str = "agent1",
) -> None:
    found.append("asked", ref, asked(client))
    if decision is not None:
        found.append("decided", ref, {"decision": decision, "waited_ms": 5})
    if outcome is not None:
        done = {"outcome": outcome, "detail": None, "writes_sent": 1, "writes_unknown": 0}
        found.append("outcome", ref, done)


def stored(directory: Path) -> list[bytes]:
    lines: list[bytes] = []
    for path in sorted(directory.glob("*.jsonl")):
        lines.extend(path.read_bytes().splitlines())
    return lines


def records(directory: Path) -> list[ledgerformat.Record]:
    return [ledgerformat.parse(line) for line in stored(directory)]


# --- appending ----------------------------------------------------------------------------------


def test_a_fresh_chain(tmp_path: Path) -> None:
    found = chain(tmp_path / "ledger")
    assert found.recover() == Recovery(index_rebuilt=True)
    assert (found.next_seq, found.prev, found.open) == (0, ledgerformat.GENESIS, {})
    assert found.files() == []


def test_appends_chain_anchor_and_keep_the_index(tmp_path: Path) -> None:
    directory = tmp_path / "ledger"
    found = opened(directory)
    first = found.append("asked", REF_A, asked())
    assert (first.seq, found.next_seq, found.prev) == (0, 1, first.hash)
    assert json.loads((directory / INDEX_FILE).read_bytes()) == {
        "v": 1,
        "head_seq": 0,
        "refs": {REF_A: ["asked"]},
    }
    second = found.append("decided", REF_A, {"decision": "accept", "waited_ms": 3})
    assert found.open == {REF_A: ["asked", "decided"]}
    done = {"outcome": "ok", "detail": None, "writes_sent": 1, "writes_unknown": 0}
    third = found.append("outcome", REF_A, done)
    assert found.open == {}
    assert json.loads((directory / INDEX_FILE).read_bytes())["refs"] == {}
    written = records(directory)
    assert [r.seq for r in written] == [0, 1, 2]
    assert [r.prev for r in written] == [ledgerformat.GENESIS, first.hash, second.hash]
    assert third.hash == ledgerformat.line_hash(stored(directory)[-1])
    assert [p.name for p in found.files()] == ["000000000000.jsonl"]
    assert (directory / "000000000000.jsonl").stat().st_size == sum(
        len(line) + 1 for line in stored(directory)
    )


def test_each_record_names_the_chains_writer(tmp_path: Path) -> None:
    gateway = opened(tmp_path / "gateway")
    gateway.append("asked", REF_A, asked())
    assert json.loads(stored(tmp_path / "gateway")[0])["writer"] == "gateway"
    other = opened(tmp_path / "other", writer="vault")
    other.append("recovered", None, {"abandoned": 0, "not_sent": 0, "unknown": 0})
    assert json.loads(stored(tmp_path / "other")[0])["writer"] == "vault"


def test_a_failed_append_moves_nothing_on(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    directory = tmp_path / "ledger"
    found = opened(directory)
    found.append("asked", REF_A, asked())
    before = (found.next_seq, found.prev, dict(found.open))

    def refuse(*args: Any, **kwargs: Any) -> int:
        raise OSError(28, "No space left on device")

    with monkeypatch.context() as patched:
        patched.setattr("zoeymcp.common.ledgerfile.os.open", refuse)
        with pytest.raises(OSError, match="No space left"):
            found.append("decided", REF_A, {"decision": "accept", "waited_ms": 1})
    with pytest.raises(ledgerformat.LedgerFormatError):
        found.append("decided", REF_A, {"decision": "maybe", "waited_ms": 1})
    assert (found.next_seq, found.prev, found.open) == before
    assert len(stored(directory)) == 1


def test_a_short_write_is_an_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    found = opened(tmp_path / "ledger")
    monkeypatch.setattr("zoeymcp.common.ledgerfile.os.write", lambda fd, data: len(data) - 1)
    with pytest.raises(OSError, match="short write"):
        found.append("asked", REF_A, asked())
    assert found.next_seq == 0


# --- rotation and pruning -----------------------------------------------------------------------


def test_files_rotate_at_the_size_and_the_chain_crosses_them(tmp_path: Path) -> None:
    directory = tmp_path / "ledger"
    found = opened(directory, rotate_bytes=1200)
    for index in range(6):
        call(found, f"{index:016x}")
    names = [p.name for p in found.files()]
    assert len(names) > 2
    assert names[0] == "000000000000.jsonl"
    assert all(p.stat().st_size <= 1200 for p in found.files())
    written = records(directory)
    assert [r.seq for r in written] == list(range(18))
    assert all(written[int(name[:12])].seq == int(name[:12]) for name in names)
    assert found.verify()["ok"]
    again = chain(directory, rotate_bytes=1200)
    assert again.recover() == Recovery()
    assert (again.next_seq, again.prev) == (18, found.prev)


def test_a_record_alone_over_the_size_still_gets_a_file(tmp_path: Path) -> None:
    found = opened(tmp_path / "ledger", rotate_bytes=10)
    call(found, REF_A, decision=None, outcome=None)
    call(found, REF_B, decision=None, outcome=None)
    assert [p.name for p in found.files()] == ["000000000000.jsonl", "000000000001.jsonl"]


def test_old_files_are_pruned_and_noted(tmp_path: Path) -> None:
    directory = tmp_path / "ledger"
    events = Events()
    found = opened(directory, events, max_bytes=3000, rotate_bytes=1200)
    for index in range(10):
        call(found, f"{index:016x}")
    total = sum(p.stat().st_size for p in found.files())
    assert total <= 3000 + 1200
    pruned = events.named("ledger_pruned")
    assert pruned[0]["first_seq"] == 0
    assert all(p["last_seq"] >= p["first_seq"] for p in pruned)
    assert records(directory)[0].seq == pruned[-1]["last_seq"] + 1
    assert found.verify()["ok"]  # the chain starts where the oldest file left says it does
    assert records(directory)[-1].seq == 29
    assert found.size == total
    assert found.prunable_at is None


def test_with_keep_ms_a_file_goes_only_once_its_last_record_is_that_old(tmp_path: Path) -> None:
    """The vault's chain (M8 design J.1): over ``max_bytes``, a file whose last record is
    ``keep_ms`` old or less stays, and ``prunable_at`` says when it may go; past that, the next
    append prunes it."""
    directory = tmp_path / "ledger"
    events, clock = Events(), Clock()
    found = opened(
        directory, events, max_bytes=3000, rotate_bytes=1200, clock=clock, keep_ms=10_000
    )
    for index in range(10):
        call(found, f"{index:016x}")
    assert events.named("ledger_pruned") == []
    assert found.size == sum(p.stat().st_size for p in found.files()) > 3000
    oldest_end = ledgerformat.parse(found.files()[0].read_bytes().splitlines()[-1]).ts
    assert found.prunable_at == oldest_end + 10_000
    # The append's ts reads the clock once and the prune once more: exactly that old, it stays.
    clock.now = oldest_end + 10_000 - 2
    call(found, REF_A, decision=None, outcome=None)
    assert events.named("ledger_pruned") == []
    clock.now = oldest_end + 20_000  # every file is past it now, so pruning stops at the cap
    call(found, REF_B, decision=None, outcome=None)
    pruned = events.named("ledger_pruned")
    assert pruned[0]["first_seq"] == 0
    assert found.size == sum(p.stat().st_size for p in found.files()) <= 3000
    assert found.prunable_at is None
    assert found.verify()["ok"]


# --- the open-ref index -------------------------------------------------------------------------


def test_a_matching_index_is_read_and_not_rebuilt(tmp_path: Path) -> None:
    directory = tmp_path / "ledger"
    found = opened(directory)
    call(found, REF_A, decision="accept", outcome=None)
    call(found, REF_B)
    again = chain(directory)
    report = again.recover()
    assert not report.index_rebuilt
    assert report.closed == {"abandoned": 0, "not_sent": 0, "unknown": 1}


@pytest.mark.parametrize(
    "index",
    [
        None,
        b"not json",
        b"[]",
        json.dumps({"v": 2, "head_seq": 1, "refs": {}}).encode(),
        json.dumps({"v": 1, "head_seq": 0, "refs": {}}).encode(),
        json.dumps({"v": 1, "head_seq": 1, "refs": []}).encode(),
        json.dumps({"v": 1, "head_seq": 1, "refs": {REF_A: "asked"}}).encode(),
    ],
    ids=["missing", "not-json", "not-an-object", "version", "stale", "refs-list", "kinds-text"],
)
def test_an_index_that_doesnt_match_is_rebuilt_from_the_files(
    tmp_path: Path, index: bytes | None
) -> None:
    directory = tmp_path / "ledger"
    found = opened(directory)
    call(found, REF_A, decision="accept", outcome=None)
    if index is None:
        (directory / INDEX_FILE).unlink()
    else:
        (directory / INDEX_FILE).write_bytes(index)
    report = chain(directory).recover()
    assert report.index_rebuilt
    assert report.closed == {"abandoned": 0, "not_sent": 0, "unknown": 1}


def test_only_an_indexed_ref_whose_records_start_with_asked_is_closed(tmp_path: Path) -> None:
    """The index has only kinds: recovery reads the records back, and closes nothing for a ref
    with no records or whose first record isn't ``asked``."""
    directory = tmp_path / "ledger"
    found = opened(directory)
    call(found, REF_A)
    found.append("decided", REF_C, {"decision": "accept", "waited_ms": 1})
    assert found.open == {REF_C: ["decided"]}
    index = {"v": 1, "head_seq": 3, "refs": {REF_B: ["asked"], REF_C: ["decided"]}}
    (directory / INDEX_FILE).write_bytes(json.dumps(index).encode())
    again = chain(directory)
    report = again.recover()
    assert (report.index_rebuilt, report.closed) == (False, {})
    assert again.next_seq == 4


# --- recovery -----------------------------------------------------------------------------------


def test_a_torn_tail_is_moved_aside_and_repaired(tmp_path: Path) -> None:
    directory = tmp_path / "ledger"
    found = opened(directory)
    call(found, REF_A)
    newest = directory / "000000000000.jsonl"
    torn = b'{"v":1,"seq":3,"pre'
    with open(newest, "ab") as handle:
        handle.write(torn)
    events = Events()
    again = chain(directory, events)
    report = again.recover()
    assert report.torn_bytes == len(torn)
    [aside] = directory.glob("torn-*.bin")
    assert aside.read_bytes() == torn
    last = records(directory)[-1]
    assert (last.kind, last.seq, last.fields) == ("repaired", 3, {"torn_bytes": len(torn)})
    assert events.named("ledger_repaired") == [{"torn_bytes": len(torn)}]
    assert again.verify()["ok"]
    assert not newest.read_bytes().endswith(torn)


def test_a_last_line_that_doesnt_parse_is_torn_too(tmp_path: Path) -> None:
    directory = tmp_path / "ledger"
    found = opened(directory)
    call(found, REF_A)
    newest = directory / "000000000000.jsonl"
    newest.write_bytes(newest.read_bytes() + b"not a record\n")
    report = chain(directory).recover()
    assert report.torn_bytes == len(b"not a record\n")
    assert [r.kind for r in records(directory)] == ["asked", "decided", "outcome", "repaired"]


def test_recovery_closes_every_open_ref_once(tmp_path: Path) -> None:
    directory = tmp_path / "ledger"
    found = opened(directory)
    call(found, REF_A, decision=None, outcome=None)  # asked only
    call(found, REF_B, decision="accept", outcome=None)  # accepted, then the process died
    call(found, REF_C, decision="decline", outcome=None)
    events = Events()
    again = chain(directory, events)
    report = again.recover()
    assert report.closed == {"abandoned": 1, "not_sent": 2, "unknown": 1}
    tail = records(directory)[-5:]
    assert [(r.kind, r.ref, r.fields.get("outcome") or r.fields.get("decision")) for r in tail] == [
        ("decided", REF_A, "abandoned"),
        ("outcome", REF_A, "not_sent"),
        ("outcome", REF_B, "unknown"),
        ("outcome", REF_C, "not_sent"),
        ("recovered", None, None),
    ]
    assert again.open == {}
    assert events.named("ledger_recovered") == [report.closed]
    assert report.ended == {REF_A: "not_sent", REF_B: "unknown", REF_C: "not_sent"}
    third = chain(directory)
    rest = third.recover()
    assert (rest.closed, rest.ended) == ({}, {})  # nothing left to close
    assert third.next_seq == again.next_seq


def test_a_broken_chain_is_noted_and_the_next_record_starts_a_file(tmp_path: Path) -> None:
    directory = tmp_path / "ledger"
    found = opened(directory)
    call(found, REF_A)
    newest = directory / "000000000000.jsonl"
    lines = newest.read_bytes().splitlines(keepends=True)
    lines[1] = lines[1].replace(b'"accept"', b'"decline"')
    newest.write_bytes(b"".join(lines))
    events = Events()
    again = chain(directory, events)
    assert again.recover().chain_broken_at == 2
    assert events.named("ledger_chain_broken") == [{"seq": 2, "level": "critical"}]
    call(again, REF_B)
    assert [p.name for p in again.files()] == ["000000000000.jsonl", "000000000002.jsonl"]
    assert again.verify()["broken_at"] == 2


def test_a_newest_file_with_no_good_record_is_set_aside(tmp_path: Path) -> None:
    directory = tmp_path / "ledger"
    found = opened(directory, rotate_bytes=10)
    call(found, REF_A, decision=None, outcome=None)
    call(found, REF_B, decision=None, outcome=None)
    older = directory / "000000000000.jsonl"
    older.write_bytes(older.read_bytes().replace(b'"agent1"', b'"agent9"'))
    again = chain(directory, rotate_bytes=10)
    assert again.recover().chain_broken_at == 1
    assert [p.name for p in directory.glob("broken-*")] == [
        f"broken-{1_767_276_000_001}-000000000001.jsonl"
    ]


def test_the_chain_continues_from_the_file_before(tmp_path: Path) -> None:
    """The newest file's chain starts at the last hash of the file before it."""
    directory = tmp_path / "ledger"
    found = opened(directory, rotate_bytes=1200)
    for index in range(4):
        call(found, f"{index:016x}")
    older = found.files()[-2]
    older.write_bytes(older.read_bytes() + b"not a record\n")  # skipped back to the last good line
    again = chain(directory, rotate_bytes=1200)
    report = again.recover()
    assert (report.chain_broken_at, again.next_seq, again.prev) == (None, 12, found.prev)


# --- reading ------------------------------------------------------------------------------------


def test_records_skip_lines_that_dont_parse(tmp_path: Path) -> None:
    directory = tmp_path / "ledger"
    found = opened(directory)
    call(found, REF_A)
    newest = directory / "000000000000.jsonl"
    lines = newest.read_bytes().splitlines(keepends=True)
    newest.write_bytes(lines[0] + b"not a record\n" + b"".join(lines[1:]))
    assert [r.seq for r in found.records()] == [0, 1, 2]


def test_lines_are_the_stored_bytes_after_a_seq(tmp_path: Path) -> None:
    directory = tmp_path / "ledger"
    found = opened(directory, rotate_bytes=1200)
    for index in range(4):
        call(found, f"{index:016x}")
    lines = stored(directory)
    assert len(found.files()) > 2  # reads cross the files
    assert found.lines(-1, 256) == lines
    assert found.lines(4, 256) == lines[5:]
    assert found.lines(4, 3) == lines[5:8]
    assert found.lines(10, 256) == [lines[11]]
    assert found.lines(11, 256) == []
    found.next_seq -= 1  # an append under way in a worker thread
    assert found.lines(-1, 256) == lines[:-1]


def test_read_filters_by_the_asked_record_and_limits(tmp_path: Path) -> None:
    found = opened(tmp_path / "ledger")
    call(found, REF_A, client="agent1")
    call(found, REF_B, client="agent2")
    found.append("recovered", None, {"abandoned": 0, "not_sent": 0, "unknown": 0})
    assert [r["seq"] for r in found.read()] == list(range(7))
    assert [r["ref"] for r in found.read(client="agent2")] == [REF_B, REF_B, REF_B, None]
    assert [r["seq"] for r in found.read(after=3)] == [4, 5, 6]
    assert [r["seq"] for r in found.read(limit=2)] == [0, 1]
    assert [r["seq"] for r in found.read(limit=0)] == [0]
    assert [r["seq"] for r in found.read(tool="other")] == [6]
    assert found.read(server="mail", tool="send_note", client="agent1")[0]["ref"] == REF_A


def test_verify_walks_from_what_the_oldest_file_says(tmp_path: Path) -> None:
    directory = tmp_path / "ledger"
    found = opened(directory)
    assert found.verify() == {
        "records": 0,
        "head_seq": -1,
        "head_hash": ledgerformat.GENESIS,
        "broken_at": None,
        "ok": True,
    }
    call(found, REF_A)
    assert found.verify() == {
        "records": 3,
        "head_seq": 2,
        "head_hash": found.prev,
        "broken_at": None,
        "ok": True,
    }
