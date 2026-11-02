"""The approval ledger's records joined by ref (M5 design J.5, J.6; M8 design J.2).

From M8 a call's records are keyed by kind and writer: the vault's chain's records of a call join
the gateway's entry for it, whichever comes first, and one writer behaves as before (F-53).
"""

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
    writer: str = "gateway",
    where: str = "gateway",
) -> dict[str, Any]:
    return record(
        seq,
        ts,
        ref,
        "asked",
        writer=writer,
        client=client,
        server="mail",
        tool=tool,
        where=where,
        era=era,
        args="hmac-sha256:" + "1" * 64,
        pin="sha256:" + "2" * 64,
        text="hmac-sha256:" + "3" * 64,
        chars=10,
        writes=1,
        expires=1,
    )


def outcome(
    seq: int, ts: int, ref: str, result: str, detail: str | None, *, writer: str = "gateway"
) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "outcome": result,
        "detail": detail,
        "writes_sent": 0,
        "writes_unknown": 0,
    }
    return record(seq, ts, ref, "outcome", writer=writer, **fields)


# Every shape the join and its renderers meet: ledger-level records at either end, a call with an
# outcome detail, one without, one never decided, one the vault decided (M8's writer, J.6: its
# `accept`, with `via`; the gateway's own record of that is `approved_elsewhere`, C.4) with no
# outcome, and an outcome whose ref was never asked. test_ledger_cli.py pins the CLI's text.
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
        decision="accept",
        waited_ms=0,
        via="telegram",
    ),
    outcome(10, T + 3_600_002, REF_E, "unknown", "restart"),
    record(11, T + 86_400_000, None, "recovered", abandoned=1, not_sent=1, unknown=0),
]


def shape(entries: list[Call | Any]) -> list[Any]:
    """Each entry as (ref, [(kind, seq), ...]) for a call, or the seq of a ledger-level record."""
    return [
        (e.ref, [(kind, r["seq"]) for (kind, _), r in e.records.items()])
        if isinstance(e, Call)
        else e["seq"]
        for e in entries
    ]


def writers(entries: list[Call | Any]) -> list[Any]:
    """Each call as (ref, [(kind, writer, seq), ...])."""
    return [
        (e.ref, [(kind, writer, r["seq"]) for (kind, writer), r in e.records.items()])
        for e in entries
        if isinstance(e, Call)
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
    assert first.records[("outcome", "gateway")] is RECORDS[4]


def test_each_record_keeps_its_writer() -> None:
    call = join(RECORDS)[4]
    assert isinstance(call, Call)
    assert list(call.records) == [("asked", "gateway"), ("decided", "vault")]
    assert call.records[("asked", "gateway")]["writer"] == "gateway"
    assert call.records[("decided", "vault")]["writer"] == "vault"
    assert call.records[("decided", "vault")]["decision"] == "accept"


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


# --- two writers (M8 design J.2) -----------------------------------------------------------------


def decided(seq: int, ref: str, decision: str, *, writer: str = "gateway") -> dict[str, Any]:
    via = {"via": "telegram"} if writer == "vault" else {}
    return record(
        seq, T + seq, ref, "decided", writer=writer, decision=decision, waited_ms=1, **via
    )


# A held call, as the copy (seq from 0) and the vault's chain (seq from 40) record it: both ask,
# the vault decides and sends, the gateway records its own approved_elsewhere and outcome.
GATEWAY = [
    asked(0, T, REF_A, where="vault"),
    decided(1, REF_A, "approved_elsewhere"),
    outcome(2, T + 2, REF_A, "ok", None),
]
VAULT = [
    asked(40, T + 1, REF_A, writer="vault", where="vault"),
    decided(41, REF_A, "accept", writer="vault"),
    outcome(42, T + 3, REF_A, "ok", None, writer="vault"),
]


def test_the_other_writers_asked_joins_the_entry() -> None:
    """F-53's fix: the vault's ``asked`` for a ref the gateway asked is the same call, so one
    entry holds both writers' records, each under its own writer."""
    assert writers(join([*GATEWAY, *VAULT])) == [
        (
            REF_A,
            [
                ("asked", "gateway", 0),
                ("decided", "gateway", 1),
                ("outcome", "gateway", 2),
                ("asked", "vault", 40),
                ("decided", "vault", 41),
                ("outcome", "vault", 42),
            ],
        )
    ]


@pytest.mark.parametrize("vault_first", [True, False])
def test_the_two_chains_join_in_either_order(vault_first: bool) -> None:
    """Chains join by ref, not by order: the vault's records first make the same entry, which
    starts with the vault's ``asked``, and neither writer's records replace the other's."""
    first, second = (VAULT, GATEWAY) if vault_first else (GATEWAY, VAULT)
    [call] = join([*first, *second])
    assert isinstance(call, Call)
    assert next(iter(call.records)) == ("asked", "vault" if vault_first else "gateway")
    assert {key: r["seq"] for key, r in call.records.items()} == {
        ("asked", "gateway"): 0,
        ("decided", "gateway"): 1,
        ("outcome", "gateway"): 2,
        ("asked", "vault"): 40,
        ("decided", "vault"): 41,
        ("outcome", "vault"): 42,
    }


def test_interleaved_chains_join() -> None:
    records = [GATEWAY[0], VAULT[0], VAULT[1], GATEWAY[1], VAULT[2], GATEWAY[2]]
    assert writers(join(records)) == [
        (
            REF_A,
            [
                ("asked", "gateway", 0),
                ("asked", "vault", 40),
                ("decided", "vault", 41),
                ("decided", "gateway", 1),
                ("outcome", "vault", 42),
                ("outcome", "gateway", 2),
            ],
        )
    ]


def test_a_later_record_replaces_only_its_own_writers() -> None:
    entries = join(
        [
            asked(0, T, REF_A),
            decided(1, REF_A, "pending"),
            asked(40, T, REF_A, writer="vault"),
            decided(41, REF_A, "accept", writer="vault"),
            decided(2, REF_A, "approved_elsewhere"),
        ]
    )
    assert writers(entries) == [
        (
            REF_A,
            [
                ("asked", "gateway", 0),
                ("decided", "gateway", 2),
                ("asked", "vault", 40),
                ("decided", "vault", 41),
            ],
        )
    ]


def test_one_writers_second_asked_still_starts_a_new_entry() -> None:
    """One writer behaves as before: its second ``asked`` for a ref starts a new entry, dropping
    the first entry's records of both writers; the other writer's records after it join it."""
    entries = join(
        [
            asked(0, T, REF_A),
            asked(40, T, REF_A, writer="vault"),
            decided(41, REF_A, "accept", writer="vault"),
            asked(1, T + 1, REF_A, client="agent2"),
            asked(42, T + 1, REF_A, writer="vault"),
        ]
    )
    latest = (REF_A, [("asked", "gateway", 1), ("asked", "vault", 42)])
    assert writers(entries) == [latest, latest]
    vault_twice = join([asked(40, T, REF_A, writer="vault"), asked(41, T, REF_A, writer="vault")])
    assert writers(vault_twice) == [(REF_A, [("asked", "vault", 41)])] * 2


def test_a_record_with_no_writer_is_dropped() -> None:
    nameless = {**decided(1, REF_A, "accept"), "writer": None}
    numbered = {**asked(2, T, REF_B), "writer": 3}
    assert shape(join([asked(0, T, REF_A), nameless, numbered])) == [(REF_A, [("asked", 0)])]


def test_the_other_writers_asked_joins_whatever_its_time() -> None:
    """``since`` is read on the asked record that starts an entry: the vault's clock isn't the
    gateway's, so the other chain's ``asked`` joins a kept entry whatever its ``ts``."""
    entries = join([asked(0, T + 5, REF_A), asked(40, T, REF_A, writer="vault")], since=T + 5)
    assert writers(entries) == [(REF_A, [("asked", "gateway", 0), ("asked", "vault", 40)])]


def test_get_picks_by_writer() -> None:
    [call] = join([*VAULT, *GATEWAY])
    assert isinstance(call, Call)
    assert call.get("decided", "vault", "gateway") is VAULT[1]
    assert call.get("decided", "gateway", "vault") is GATEWAY[1]
    assert call.get("outcome", "gateway") is GATEWAY[2]
    assert call.get("decided") is VAULT[1]  # no writer named: the first written
    assert call.get("asked") is VAULT[0]
    [alone] = join(GATEWAY[:1])
    assert isinstance(alone, Call)
    assert alone.get("decided") is None
    assert alone.get("decided", "vault") is None
    assert alone.get("asked", "vault", "gateway") is GATEWAY[0]
    assert alone.get("asked", "vault") is None
