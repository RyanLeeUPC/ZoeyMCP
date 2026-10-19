"""The approval ledger's records joined by ref (M5 design J.5, J.6)."""

from __future__ import annotations

import dataclasses
from typing import Any

import pytest

from zoeymcp.common.ledgerjoin import Call, join

T = 1_767_276_000_000  # 2026-01-01 14:00:00Z
REF_A, REF_B, REF_C, REF_D, REF_E = (f"{n:016x}" for n in range(10, 15))


def record(
    seq: int, ts: int, ref: str | None, kind: Any, *, writer: str = "gateway", **fields: Any
) -> dict[str, Any]:
    common = {"v": 1, "seq": seq, "prev": "sha256:" + "0" * 64, "ts": ts, "ref": ref}
    return {**common, "kind": kind, "writer": writer, **fields}


def asked(
    seq: int,
    ts: int,
    ref: str,
    *,
    client: str = "agent1",
    tool: str = "send_note",
    era: str = "legacy",
) -> dict[str, Any]:
    return record(
        seq,
        ts,
        ref,
        "asked",
        client=client,
        server="mail",
        tool=tool,
        where="gateway",
        era=era,
        args="hmac-sha256:" + "1" * 64,
        pin="sha256:" + "2" * 64,
        text="hmac-sha256:" + "3" * 64,
        chars=10,
        writes=1,
        expires=1,
    )


def outcome(seq: int, ts: int, ref: str, result: str, detail: str | None) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "outcome": result,
        "detail": detail,
        "writes_sent": 0,
        "writes_unknown": 0,
    }
    return record(seq, ts, ref, "outcome", **fields)


# Every shape the join and its renderers meet: ledger-level records at either end, a call with an
# outcome detail, one without, one never decided, one decided by the vault (M8's writer, J.6) with
# no outcome, and an outcome whose ref was never asked. test_ledger_cli.py pins the CLI's text.
RECORDS = [
    record(0, T - 60_000, None, "repaired", torn_bytes=7),
    asked(1, T, REF_A),
    asked(2, T + 1_000, REF_B, client="agent2", era="modern"),
    record(3, T + 2_000, REF_A, "decided", decision="accept", waited_ms=8123),
    outcome(4, T + 3_000, REF_A, "ok", "sent"),
    record(5, T + 4_000, REF_B, "decided", decision="decline", waited_ms=5),
    outcome(6, T + 5_000, REF_B, "not_sent", None),
    asked(7, T + 61_000, REF_C, tool="list_notes"),
    asked(8, T + 3_600_000, REF_D),
    record(
        9,
        T + 3_600_001,
        REF_D,
        "decided",
        writer="vault",
        decision="approved_elsewhere",
        waited_ms=0,
    ),
    outcome(10, T + 3_600_002, REF_E, "unknown", "restart"),
    record(11, T + 86_400_000, None, "recovered", abandoned=1, not_sent=1, unknown=0),
]


def shape(entries: list[Call | Any]) -> list[Any]:
    """Each entry as (ref, [(kind, seq), ...]) for a call, or the seq of a ledger-level record."""
    return [
        (e.ref, [(kind, r["seq"]) for kind, r in e.records.items()])
        if isinstance(e, Call)
        else e["seq"]
        for e in entries
    ]


def test_one_entry_per_ref_in_asked_order() -> None:
    entries = join(RECORDS)
    assert shape(entries) == [
        0,
        (REF_A, [("asked", 1), ("decided", 3), ("outcome", 4)]),
        (REF_B, [("asked", 2), ("decided", 5), ("outcome", 6)]),
        (REF_C, [("asked", 7)]),
        (REF_D, [("asked", 8), ("decided", 9)]),
        11,
    ]
    assert entries[0] is RECORDS[0]  # a ledger-level record is its own entry, as it came
    assert entries[-1] is RECORDS[-1]
    first = entries[1]
    assert isinstance(first, Call)
    assert first.records["outcome"] is RECORDS[4]


def test_each_record_keeps_its_writer() -> None:
    call = join(RECORDS)[4]
    assert isinstance(call, Call)
    assert call.records["asked"]["writer"] == "gateway"
    assert call.records["decided"]["writer"] == "vault"
    assert call.records["decided"]["decision"] == "approved_elsewhere"


def test_no_records() -> None:
    assert join([]) == []
    assert join([], since=T) == []


@pytest.mark.parametrize(
    ("since", "kept"),
    [
        (None, [0, REF_A, REF_B, REF_C, REF_D, 11]),
        (T - 60_001, [0, REF_A, REF_B, REF_C, REF_D, 11]),
        (T - 60_000, [0, REF_A, REF_B, REF_C, REF_D, 11]),  # at since is kept
        (T - 59_999, [REF_A, REF_B, REF_C, REF_D, 11]),
        (T, [REF_A, REF_B, REF_C, REF_D, 11]),
        (T + 1, [REF_B, REF_C, REF_D, 11]),
        (T + 86_400_000, [11]),
        (T + 86_400_001, []),
    ],
)
def test_since(since: int | None, kept: list[Any]) -> None:
    entries = join(RECORDS, since=since)
    assert [e.ref if isinstance(e, Call) else e["seq"] for e in entries] == kept


def test_records_of_a_ref_asked_before_since_are_dropped() -> None:
    entries = join(RECORDS, since=T + 1)
    assert shape(entries)[0] == (REF_B, [("asked", 2), ("decided", 5), ("outcome", 6)])
    assert REF_A not in {e.ref for e in entries if isinstance(e, Call)}


def test_a_record_before_its_asked_is_dropped() -> None:
    early = record(0, T, REF_A, "decided", decision="accept", waited_ms=1)
    assert shape(join([early, asked(1, T, REF_A)])) == [(REF_A, [("asked", 1)])]


def test_a_record_with_no_kind_is_dropped() -> None:
    nameless = record(1, T, REF_A, None)
    numbered = record(2, T, REF_A, 3)
    assert shape(join([asked(0, T, REF_A), nameless, numbered])) == [(REF_A, [("asked", 0)])]


def test_a_later_record_of_a_kind_replaces_the_earlier() -> None:
    entries = join(
        [
            asked(0, T, REF_A),
            record(1, T, REF_A, "decided", decision="pending", waited_ms=0),
            record(2, T, REF_A, "decided", decision="accept", waited_ms=9),
        ]
    )
    assert shape(entries) == [(REF_A, [("asked", 0), ("decided", 2)])]


def test_a_ref_asked_twice_is_two_entries_with_its_latest_records() -> None:
    entries = join(
        [
            asked(0, T, REF_A),
            record(1, T, REF_A, "decided", decision="accept", waited_ms=1),
            asked(2, T + 1, REF_A, client="agent2"),
            outcome(3, T + 2, REF_A, "ok", None),
        ]
    )
    latest = (REF_A, [("asked", 2), ("outcome", 3)])
    assert shape(entries) == [latest, latest]


def test_an_asked_before_since_leaves_a_kept_one_alone() -> None:
    entries = join([asked(0, T + 5, REF_A), asked(1, T, REF_A)], since=T + 5)
    assert shape(entries) == [(REF_A, [("asked", 0)])]


def test_a_call_is_frozen() -> None:
    call = Call(REF_A, {})
    with pytest.raises(dataclasses.FrozenInstanceError):
        call.ref = REF_B  # type: ignore[misc]
