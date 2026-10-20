"""The ledger view: rows, pages, flags and the journal join (M5 design J.5, J.6).

The records are ``test_ledgerjoin``'s, which ``zoeymcp ledger`` is pinned against too: a vault
written ``approved_elsewhere`` and a ``pending`` decision are among them.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from tests.unit.test_ledgerjoin import RECORDS, REF_A, REF_B, REF_C, REF_D, T, asked, record
from zoeymcp.common.policy.schema import Policy
from zoeymcp.vault.ledgerview import (
    MAX_LIMIT,
    NAMED,
    Send,
    known,
    orphans,
    page,
    sends,
    state,
    when,
)
from zoeymcp.vault.reports import Held, LiveFile

HASH = "sha256:" + "f" * 64
NOW = T + 2 * 86_400_000
HELD = Held("ok", 0, 11, HASH, (LiveFile("000000000000.jsonl", 900, NOW - 12_345),))


def sending(ts: int, key: str) -> dict[str, Any]:
    return {
        "kind": "sending",
        "ts": ts,
        "key": key,
        "req_hmac": "hmac-sha256:" + "9" * 64,
        "key_id": "0" * 16,
        "subject_chars": 5,
        "body_chars": 9,
    }


def sent(ts: int, key: str, code: int = 250) -> dict[str, Any]:
    return {"kind": "sent", "ts": ts, "key": key, "message_id": "<a@b>", "smtp_code": code}


def failed(ts: int, key: str) -> dict[str, Any]:
    return {"kind": "failed", "ts": ts, "key": key, "phase": "data", "code": "x", "smtp_code": 554}


def unknown(ts: int, key: str) -> dict[str, Any]:
    return {"kind": "unknown", "ts": ts, "key": key, "phase": "data"}


def test_when() -> None:
    assert when(T) == "2026-01-01T14:00:00Z"
    assert when(T + 999) == "2026-01-01T14:00:00Z"
    assert when(T + 1000) == "2026-01-01T14:00:01Z"
    assert when(0) == "1970-01-01T00:00:00Z"


# --- the state line ------------------------------------------------------------------------------


def test_the_state_line() -> None:
    assert state(HELD, now=NOW) == {
        "state": "ok",
        "head_seq": 11,
        "head_hash": HASH,
        "start_seq": 0,
        "reported_ago": 12,
        "broken_at": None,
    }
    assert state(HELD, now=NOW, broken_at=7)["broken_at"] == 7
    assert state(HELD, now=NOW - 12_345 + 999)["reported_ago"] == 0
    assert state(HELD, now=NOW - 12_345 + 1000)["reported_ago"] == 1
    assert state(HELD, now=NOW - 20_000)["reported_ago"] == 0  # the clock went back
    assert state(Held(), now=NOW) == {
        "state": "ok",
        "head_seq": None,
        "head_hash": None,
        "start_seq": None,
        "reported_ago": None,
        "broken_at": None,
    }
    assert state(Held("fork"), now=NOW)["state"] == "fork"


# --- rows ----------------------------------------------------------------------------------------


def view(**kwargs: Any) -> dict[str, Any]:
    return page(RECORDS, held=HELD, journals=kwargs.pop("journals", {}), now=NOW, **kwargs)


def test_one_row_per_call_newest_first() -> None:
    rows = view()["rows"]
    assert [(row["kind"], row["seq"]) for row in rows] == [
        ("recovered", 11),
        ("call", 8),
        ("call", 7),
        ("call", 2),
        ("call", 1),
        ("repaired", 0),
    ]


def test_a_finished_call() -> None:
    row = view()["rows"][4]
    assert row == {
        "kind": "call",
        "seq": 1,
        "ref": REF_A,
        "at": "2026-01-01T14:00:00Z",
        "client": "agent1",
        "server": "mail",
        "tool": "send_note",
        "era": "legacy",
        "decision": "accept",
        "waited_ms": 8123,
        "outcome": "ok",
        "detail": "sent",
        "writes": 1,
        "writes_sent": 0,
        "writes_unknown": 0,
        "writers": {"asked": "gateway", "decided": "gateway", "outcome": "gateway"},
        "not_in_policy": [],
        "journal": [],
    }


def test_a_call_not_yet_decided() -> None:
    row = view()["rows"][2]
    assert (row["ref"], row["tool"]) == (REF_C, "list_notes")
    nothing = ("decision", "waited_ms", "outcome", "detail", "writes_sent", "writes_unknown")
    assert all(row[name] is None for name in nothing)
    assert row["writers"] == {"asked": "gateway"}


def test_a_decision_the_vault_wrote_says_so() -> None:
    row = view()["rows"][1]
    assert (row["ref"], row["decision"], row["waited_ms"]) == (REF_D, "approved_elsewhere", 0)
    assert row["writers"] == {"asked": "gateway", "decided": "vault"}


def test_a_pending_decision_renders() -> None:
    records = [asked(0, T, REF_A), record(1, T, REF_A, "decided", decision="pending", waited_ms=0)]
    row = page(records, held=HELD, journals={}, now=NOW)["rows"][0]
    assert (row["decision"], row["outcome"]) == ("pending", None)


def test_ledger_level_records_are_rows_of_their_own() -> None:
    rows = view()["rows"]
    assert rows[0] == {
        "kind": "recovered",
        "seq": 11,
        "at": "2026-01-02T14:00:00Z",
        "writer": "gateway",
        "fields": {"abandoned": 1, "not_sent": 1, "unknown": 0},
    }
    assert rows[-1]["fields"] == {"torn_bytes": 7}


def test_no_keyed_digest_or_pin_is_shown() -> None:
    text = json.dumps(view(journals={"mail": [sending(T, f"{REF_A}.1"), sent(T, f"{REF_A}.1")]}))
    for hidden in ("hmac-sha256", "sha256:2", '"args"', '"text"', '"pin"', "message_id", "<a@b>"):
        assert hidden not in text
    assert '"chars"' not in text
    assert '"where"' not in text
    assert '"expires"' not in text


def test_a_ref_asked_twice_is_one_row() -> None:
    records = [
        asked(0, T, REF_A),
        asked(1, T + 1, REF_A, client="agent2"),
        asked(2, T + 2, REF_B),
    ]
    rows = page(records, held=HELD, journals={}, now=NOW)["rows"]
    assert [(row["ref"], row["seq"], row["client"]) for row in rows] == [
        (REF_B, 2, "agent1"),
        (REF_A, 1, "agent2"),
    ]


# --- names the policy lacks ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("known", "missing"),
    [
        (None, []),
        ({}, []),
        ({"client": ["agent1"], "server": ["mail"], "tool": ["send_note"]}, []),
        ({"client": ["agent2"]}, ["client"]),
        ({"server": []}, ["server"]),
        ({"tool": {"other"}, "client": ()}, ["client", "tool"]),
        ({"client": [], "server": [], "tool": []}, ["client", "server", "tool"]),
        ({"era": []}, []),  # not a name a policy holds
    ],
)
def test_names_the_current_policy_lacks_are_listed(known: Any, missing: list[str]) -> None:
    assert NAMED == ("client", "server", "tool")
    assert view(known=known)["rows"][4]["not_in_policy"] == missing


def test_the_names_a_policy_knows() -> None:
    """Its clients and servers; never its tools, which a server needn't list."""
    base: dict[str, Any] = {"version": 1, "mode": "declarative"}
    assert known(Policy.model_validate(base)) == {"client": frozenset(), "server": frozenset()}
    gateway = {
        "clients": {
            "agent1": {"token_sha256": "sha256:" + "3" * 64, "servers": ["mail"]},
            "agent3": {"token_sha256": "sha256:" + "4" * 64},
        },
        "servers": {"mail": {"kind": "bridge", "url": "http://bridge.example:9000/mcp"}},
    }
    found = known(Policy.model_validate({**base, "gateway": gateway}))
    assert found == {"client": frozenset({"agent1", "agent3"}), "server": frozenset({"mail"})}
    rows = view(known=found)["rows"]
    assert [(row["client"], row["not_in_policy"]) for row in rows[3:5]] == [
        ("agent2", ["client"]),
        ("agent1", []),
    ]


# --- pages ---------------------------------------------------------------------------------------


def seqs(result: dict[str, Any]) -> list[int]:
    return [row["seq"] for row in result["rows"]]


def test_pages() -> None:
    first = view(limit=2)
    assert (seqs(first), first["next"]) == ([11, 8], 8)
    second = view(limit=2, before=first["next"])
    assert (seqs(second), second["next"]) == ([7, 2], 2)
    third = view(limit=2, before=second["next"])
    assert (seqs(third), third["next"]) == ([1, 0], None)  # exactly the last rows
    assert (seqs(view(limit=3, before=2)), view(limit=3, before=2)["next"]) == ([1, 0], None)
    assert seqs(view(before=0)) == []
    assert seqs(view(before=1)) == [0]
    assert view()["next"] is None


def test_the_limit_is_1_to_200() -> None:
    records = [asked(n, T + n, f"{n:016x}") for n in range(MAX_LIMIT + 5)]
    result = page(records, held=HELD, journals={}, now=NOW, limit=10**6)
    assert len(result["rows"]) == MAX_LIMIT == 200
    assert result["next"] == 5
    assert seqs(view(limit=0)) == [11]
    assert seqs(view(limit=-5)) == [11]
    assert len(page(records, held=HELD, journals={}, now=NOW)["rows"]) == MAX_LIMIT


# --- the journal join (D-25) ---------------------------------------------------------------------


def test_sends_by_key() -> None:
    journals = {
        "mail": [
            sending(T, f"{REF_A}.1"),
            sending(T + 5, f"{REF_A}.2"),
            sent(T + 9, f"{REF_A}.1", 251),
            failed(T + 10, f"{REF_A}.2"),
            unknown(T + 11, f"{REF_A}.2"),  # a second ending is ignored
            sent(T + 12, "beefbeefbeefbeef.1"),  # its sending pruned: shown as it is
        ],
        "notify": [sending(T + 20, f"{REF_A}.1")],
    }
    assert sends(journals) == [
        Send("mail", f"{REF_A}.1", "sent", 251, T, T + 9),
        Send("mail", f"{REF_A}.2", "failed", 554, T + 5, T + 10),
        Send("mail", "beefbeefbeefbeef.1", "sent", 250, T + 12, T + 12),
        Send("notify", f"{REF_A}.1", "sending", None, T + 20, T + 20),
    ]


def test_a_new_sending_starts_the_key_again() -> None:
    journals = {"mail": [sending(T, "k.1"), sent(T + 1, "k.1"), sending(T + 9, "k.1")]}
    assert sends(journals) == [Send("mail", "k.1", "sending", None, T + 9, T + 9)]
    journals = {"mail": [sending(T, "k.1"), unknown(T + 1, "k.1")]}
    assert sends(journals) == [Send("mail", "k.1", "unknown", None, T, T + 1)]


@pytest.mark.parametrize(
    ("key", "ref"),
    [(f"{REF_A}.1", REF_A), (f"{REF_A}.12", REF_A), ("a.b.3", "a.b"), ("nodots", ""), (".1", "")],
)
def test_the_ref_is_the_key_up_to_its_last_dot(key: str, ref: str) -> None:
    assert Send("mail", key, "sent", 250, T, T).ref == ref


def test_a_row_shows_its_sends() -> None:
    journals = {"mail": [sending(T, f"{REF_A}.1"), sent(T + 2000, f"{REF_A}.1"), sending(T, "x.1")]}
    row = view(journals=journals)["rows"][4]
    assert row["journal"] == [
        {"key": f"{REF_A}.1", "state": "sent", "smtp_code": 250, "at": "2026-01-01T14:00:02Z"}
    ]
    assert view(journals=journals)["rows"][3]["journal"] == []


def test_orphans() -> None:
    received = HELD.received_ms
    assert received is not None
    found = [
        Send("mail", "1111111111111111.1", "sent", 250, received - 1, received + 5),
        Send("mail", "2222222222222222.1", "sending", None, received, received),
        Send("mail", "3333333333333333.1", "unknown", None, received + 1, received + 1),
        Send("mail", f"{REF_A}.1", "sent", 250, received - 9, received - 9),
    ]
    assert orphans(found, {REF_A}, received) == [
        {
            "connector": "mail",
            "key": "3333333333333333.1",
            "state": "unknown",
            "at": when(received + 1),
            "flag": "not_yet_reported",
        },
        {
            "connector": "mail",
            "key": "2222222222222222.1",
            "state": "sending",
            "at": when(received),
            "flag": "not_yet_reported",  # received at the same moment: not after it
        },
        {
            "connector": "mail",
            "key": "1111111111111111.1",
            "state": "sent",
            "at": when(received + 5),
            "flag": "no_ledger_record",  # the copy received a report after it began
        },
    ]
    assert [o["flag"] for o in orphans(found, set(), None)] == ["not_yet_reported"] * 4


def test_any_record_of_a_ref_holds_it() -> None:
    records = [
        *RECORDS,
        record(
            12, T, "e" * 16, "outcome", outcome="ok", detail=None, writes_sent=0, writes_unknown=0
        ),
    ]
    journals = {"mail": [sending(T, "e" * 16 + ".1"), sending(T, "f" * 16 + ".1")]}
    result = page(records, held=HELD, journals=journals, now=NOW)
    assert [o["key"] for o in result["orphans"]] == ["f" * 16 + ".1"]


def test_orphans_are_on_the_first_page() -> None:
    journals = {"mail": [sending(T, "f" * 16 + ".1")]}
    assert len(view(journals=journals, limit=1)["orphans"]) == 1
    assert view(journals=journals, before=8)["orphans"] == []
    assert view(journals=journals)["orphans"][0]["flag"] == "no_ledger_record"
