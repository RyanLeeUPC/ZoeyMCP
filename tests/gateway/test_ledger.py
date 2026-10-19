"""The approval ledger on disk: writing, chaining, recovery and reading (M4 design F)."""

from __future__ import annotations

import io
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from zoeymcp.common import canonical, ledgerformat, logs
from zoeymcp.gateway import ledger as ledger_module
from zoeymcp.gateway.ledger import (
    INDEX_FILE,
    KEY_FILE,
    LEDGER_DIR,
    Ledger,
    LedgerKey,
    LedgerUnavailable,
)

pytestmark = pytest.mark.anyio

MB = 2**20
PIN = "sha256:" + "b" * 64


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def log() -> Iterator[io.StringIO]:
    stream = io.StringIO()
    logs.set_stream(stream)
    try:
        yield stream
    finally:
        logs.set_stream(None)


def events(stream: io.StringIO, kind: str) -> list[dict[str, Any]]:
    lines = [json.loads(line) for line in stream.getvalue().splitlines() if line]
    return [line for line in lines if line["event"] == kind]


class Clock:
    def __init__(self) -> None:
        self.now = 1_767_276_000_000

    def __call__(self) -> int:
        self.now += 1
        return self.now


def opened(state: Path, max_bytes: int = 64 * MB) -> tuple[Ledger, ledger_module.Recovery]:
    return Ledger.open_at(state, max_bytes=max_bytes, clock=Clock())


def asked_fields(
    ledger: Ledger, args: Any, *, client: str = "agent1", tool: str = "send_note"
) -> dict[str, Any]:
    return {
        "client": client,
        "server": "mail",
        "tool": tool,
        "where": "gateway",
        "era": "legacy",
        "args": ledger.digest(args),
        "pin": PIN,
        "text": ledger.text_digest("the prompt"),
        "chars": 10,
        "writes": 1,
        "expires": 1,
    }


async def call(
    ledger: Ledger,
    ref: str,
    *,
    decision: str | None = "accept",
    outcome: str | None = "ok",
    args: Any = None,
    client: str = "agent1",
) -> None:
    await ledger.write(
        "asked", ref, critical=True, **asked_fields(ledger, args or {"n": ref}, client=client)
    )
    if decision is not None:
        await ledger.write(
            "decided", ref, critical=decision == "accept", decision=decision, waited_ms=5
        )
    if outcome is not None:
        await ledger.write(
            "outcome",
            ref,
            critical=False,
            outcome=outcome,
            detail=None,
            writes_sent=1,
            writes_unknown=0,
        )


def records(state: Path) -> list[ledgerformat.Record]:
    found: list[ledgerformat.Record] = []
    for path in sorted((state / LEDGER_DIR).glob("*.jsonl")):
        found.extend(ledgerformat.parse(line) for line in path.read_bytes().splitlines())
    return found


REF_A, REF_B, REF_C = "000000000000000a", "000000000000000b", "000000000000000c"


# --- writing and chaining -----------------------------------------------------------------------


async def test_a_fresh_ledger(tmp_path: Path) -> None:
    ledger, report = opened(tmp_path)
    assert len((tmp_path / KEY_FILE).read_bytes()) == 32
    assert (ledger.next_seq, ledger.prev) == (0, ledgerformat.GENESIS)
    assert report == ledger_module.Recovery(index_rebuilt=True)
    assert ledger.accepting


async def test_records_chain_and_anchor(tmp_path: Path) -> None:
    ledger, _ = opened(tmp_path)
    first = await ledger.write("asked", REF_A, critical=True, **asked_fields(ledger, {"a": 1}))
    assert first is not None
    assert first.seq == 0
    assert json.loads((tmp_path / LEDGER_DIR / INDEX_FILE).read_bytes())["refs"] == {
        REF_A: ["asked"]
    }
    second = await ledger.write("decided", REF_A, critical=True, decision="accept", waited_ms=3)
    third = await ledger.write(
        "outcome",
        REF_A,
        critical=False,
        outcome="ok",
        detail="sent",
        writes_sent=1,
        writes_unknown=0,
    )
    assert [a.seq for a in (first, second, third) if a] == [0, 1, 2]
    assert ledger.open == {}
    found = records(tmp_path)
    assert [r.kind for r in found] == ["asked", "decided", "outcome"]
    assert found[1].prev == first.hash
    assert ledger.verify() == {
        "records": 3,
        "head_seq": 2,
        "head_hash": third.hash if third else "",
        "broken_at": None,
        "ok": True,
    }
    assert [p.name for p in (tmp_path / LEDGER_DIR).glob("*.jsonl")] == ["000000000000.jsonl"]


async def test_reopening_continues_the_chain_with_the_same_key(tmp_path: Path) -> None:
    ledger, _ = opened(tmp_path)
    await call(ledger, REF_A, args={"amount": 5})
    digest = ledger.digest({"amount": 5})
    again, report = opened(tmp_path)
    assert report.closed == {}
    assert (again.next_seq, again.prev) == (ledger.next_seq, ledger.prev)
    assert again.digest({"amount": 5}) == digest
    await call(again, REF_B)
    assert again.verify()["ok"]
    assert again.verify()["records"] == 6


async def test_only_keyed_digests_reach_the_file(tmp_path: Path) -> None:
    ledger, _ = opened(tmp_path)
    await call(ledger, REF_A, args={"subject": "very-secret-subject"})
    data = b"".join(p.read_bytes() for p in (tmp_path / LEDGER_DIR).iterdir())
    assert b"very-secret-subject" not in data
    assert b"the prompt" not in data
    plain = canonical.digest({"subject": "very-secret-subject"}).removeprefix("sha256:")
    assert plain.encode() not in data  # not an unkeyed digest either
    assert ledger.digest({"subject": "very-secret-subject"}).encode() in data


async def test_check_proves_the_arguments(tmp_path: Path) -> None:
    ledger, _ = opened(tmp_path)
    await call(ledger, REF_A, args={"b": 2, "a": [1, "x"]})
    assert ledger.check(REF_A, {"a": [1, "x"], "b": 2}) == {
        "ref": REF_A,
        "found": True,
        "matches": True,
    }
    assert ledger.check(REF_A, {"a": [1, "x"], "b": 3})["matches"] is False
    assert ledger.check(REF_B, {}) == {"ref": REF_B, "found": False, "matches": False}


def test_the_key_never_shows(log: io.StringIO) -> None:
    key = LedgerKey(b"k" * 32)
    assert "k" * 8 not in repr(key)
    with pytest.raises(TypeError):
        logs.Log("gateway").event("probe", key=key)
    with pytest.raises(ValueError, match="32 bytes"):
        LedgerKey(b"short")


# --- recovery -----------------------------------------------------------------------------------


async def test_a_torn_tail_is_moved_aside_and_noted(tmp_path: Path, log: io.StringIO) -> None:
    ledger, _ = opened(tmp_path)
    await call(ledger, REF_A)
    newest = tmp_path / LEDGER_DIR / "000000000000.jsonl"
    with open(newest, "ab") as handle:
        handle.write(b'{"v":1,"seq":3,"pre')
    again, report = opened(tmp_path)
    assert report.torn_bytes == len(b'{"v":1,"seq":3,"pre')
    [aside] = (tmp_path / LEDGER_DIR).glob("torn-*.bin")
    assert aside.read_bytes() == b'{"v":1,"seq":3,"pre'
    assert [r.kind for r in records(tmp_path)][-1] == "repaired"
    assert records(tmp_path)[-1].fields == {"torn_bytes": report.torn_bytes}
    assert again.verify()["ok"]
    assert events(log, "ledger_repaired") == [
        {**events(log, "ledger_repaired")[0], "torn_bytes": report.torn_bytes}
    ]


async def test_recovery_closes_every_open_ref_once(tmp_path: Path, log: io.StringIO) -> None:
    ledger, _ = opened(tmp_path)
    await call(ledger, REF_A, decision=None, outcome=None)  # asked only
    await call(ledger, REF_B, decision="accept", outcome=None)  # accepted, then the process died
    await call(ledger, REF_C, decision="decline", outcome=None)
    again, report = opened(tmp_path)
    assert report.closed == {"abandoned": 1, "not_sent": 2, "unknown": 1}
    tail = records(tmp_path)[-5:]
    assert [(r.kind, r.ref, r.fields.get("outcome") or r.fields.get("decision")) for r in tail] == [
        ("decided", REF_A, "abandoned"),
        ("outcome", REF_A, "not_sent"),
        ("outcome", REF_B, "unknown"),
        ("outcome", REF_C, "not_sent"),
        ("recovered", None, None),
    ]
    assert again.open == {}
    assert again.verify()["ok"]
    assert events(log, "ledger_recovered")[0]["unknown"] == 1
    third, report = opened(tmp_path)
    assert report.closed == {}  # nothing left to close
    assert third.next_seq == again.next_seq


async def test_a_missing_index_is_rebuilt_from_the_files(tmp_path: Path) -> None:
    ledger, _ = opened(tmp_path)
    await call(ledger, REF_A, decision="accept", outcome=None)
    (tmp_path / LEDGER_DIR / INDEX_FILE).unlink()
    _, report = opened(tmp_path)
    assert report.index_rebuilt
    assert report.closed == {"abandoned": 0, "not_sent": 0, "unknown": 1}


async def test_a_stale_index_is_rebuilt(tmp_path: Path) -> None:
    ledger, _ = opened(tmp_path)
    await call(ledger, REF_A, decision="accept", outcome=None)
    index = tmp_path / LEDGER_DIR / INDEX_FILE
    index.write_bytes(json.dumps({"v": 1, "head_seq": 0, "refs": {}}).encode())
    _, report = opened(tmp_path)
    assert report.index_rebuilt
    assert report.closed["unknown"] == 1


async def test_a_broken_chain_is_reported_and_writing_goes_on(
    tmp_path: Path, log: io.StringIO
) -> None:
    ledger, _ = opened(tmp_path)
    await call(ledger, REF_A)
    newest = tmp_path / LEDGER_DIR / "000000000000.jsonl"
    lines = newest.read_bytes().splitlines(keepends=True)
    lines[1] = lines[1].replace(b'"accept"', b'"decline"')
    newest.write_bytes(b"".join(lines))
    again, report = opened(tmp_path)
    assert report.chain_broken_at == 2
    assert events(log, "ledger_chain_broken")[0]["seq"] == 2
    await call(again, REF_B)
    names = sorted(p.name for p in (tmp_path / LEDGER_DIR).glob("*.jsonl"))
    assert names == ["000000000000.jsonl", "000000000002.jsonl"]
    assert again.verify()["broken_at"] == 2


# --- rotation and pruning -----------------------------------------------------------------------


async def test_files_rotate_and_the_chain_crosses_them(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ledger_module, "ROTATE_BYTES", 1200)
    ledger, _ = opened(tmp_path)
    for index in range(6):
        await call(ledger, f"{index:016x}")
    names = sorted(p.name for p in (tmp_path / LEDGER_DIR).glob("*.jsonl"))
    assert len(names) > 2
    assert names[0] == "000000000000.jsonl"
    firsts = [int(n[:12]) for n in names]
    found = records(tmp_path)
    assert [r.seq for r in found] == list(range(18))
    assert all(found[f].seq == f for f in firsts)
    assert ledger.verify()["ok"]
    again, _ = opened(tmp_path)
    assert again.next_seq == 18


async def test_old_files_are_pruned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, log: io.StringIO
) -> None:
    monkeypatch.setattr(ledger_module, "ROTATE_BYTES", 1200)
    ledger, _ = opened(tmp_path, max_bytes=3000)
    for index in range(10):
        await call(ledger, f"{index:016x}")
    total = sum(p.stat().st_size for p in (tmp_path / LEDGER_DIR).glob("*.jsonl"))
    assert total <= 3000 + 1200
    pruned = events(log, "ledger_pruned")
    assert pruned
    assert pruned[0]["first_seq"] == 0
    assert ledger.verify()["ok"]  # the chain starts where the oldest file left says it does
    assert records(tmp_path)[-1].seq == 29


# --- failures -----------------------------------------------------------------------------------


def broken_disk(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: Any, **kwargs: Any) -> int:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr("zoeymcp.gateway.ledger.os.open", refuse)


async def test_a_critical_record_that_cant_be_written_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, log: io.StringIO
) -> None:
    ledger, _ = opened(tmp_path)
    broken_disk(monkeypatch)
    with pytest.raises(LedgerUnavailable):
        await ledger.write(
            "asked", REF_A, critical=True, **asked_fields(ledger, {"x": "do-not-log"})
        )
    [failed] = events(log, "ledger_write_failed")
    assert (failed["record_kind"], failed["error_type"], failed["level"]) == (
        "asked",
        "OSError",
        "critical",
    )
    assert "do-not-log" not in log.getvalue()
    assert ledger.next_seq == 0


async def test_other_records_queue_until_the_disk_comes_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ledger_module, "MAX_QUEUED", 2)
    ledger, _ = opened(tmp_path)
    await ledger.write("asked", REF_A, critical=True, **asked_fields(ledger, {}))
    with monkeypatch.context() as patched:
        broken_disk(patched)
        assert (
            await ledger.write("decided", REF_A, critical=False, decision="decline", waited_ms=1)
            is None
        )
        assert ledger.accepting
        outcome = {"outcome": "not_sent", "detail": None, "writes_sent": 0, "writes_unknown": 0}
        assert await ledger.write("outcome", REF_A, critical=False, **outcome) is None
        assert not ledger.accepting  # the queue is full: new approvals are refused
        assert await ledger.flush_queue() == 2
    assert await ledger.flush_queue() == 0
    assert [r.kind for r in records(tmp_path)] == ["asked", "decided", "outcome"]
    assert ledger.verify()["ok"]
    assert ledger.accepting


async def test_queued_records_keep_their_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger, _ = opened(tmp_path)
    await ledger.write("asked", REF_A, critical=True, **asked_fields(ledger, {}))
    with monkeypatch.context() as patched:
        broken_disk(patched)
        await ledger.write("decided", REF_A, critical=False, decision="timeout", waited_ms=1)
    # The disk is back, but a queued record goes first.
    outcome = {"outcome": "not_sent", "detail": None, "writes_sent": 0, "writes_unknown": 0}
    assert await ledger.write("outcome", REF_A, critical=False, **outcome) is None
    await ledger.flush_queue()
    assert [r.kind for r in records(tmp_path)] == ["asked", "decided", "outcome"]


# --- reading ------------------------------------------------------------------------------------


async def test_read_filters_by_the_asked_record(tmp_path: Path) -> None:
    ledger, _ = opened(tmp_path)
    await call(ledger, REF_A, client="agent1")
    await call(ledger, REF_B, client="agent2")
    everything = ledger.read()
    assert [r["seq"] for r in everything] == list(range(6))
    mine = ledger.read(client="agent2")
    assert {r["ref"] for r in mine} == {REF_B}
    assert len(mine) == 3
    assert [r["seq"] for r in ledger.read(after=3)] == [4, 5]
    assert [r["seq"] for r in ledger.read(limit=2)] == [0, 1]
    assert ledger.read(tool="other") == []
    assert ledger.read(server="mail", tool="send_note", client="agent1")[0]["ref"] == REF_A
