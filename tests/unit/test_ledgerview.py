"""The ledger view: rows, pages, flags and the journal join (M5 design J.5, J.6; M8 J.2, J.3).

The records are ``test_ledgerjoin``'s, which ``zoeymcp ledger`` is pinned against too: a vault
written ``accept`` is among them, and a ``pending`` decision is shown its own. The vault's own
chain joins the copy's calls by ref (FM-42): one row per call, the right record of each kind
shown, the other chain's in ``others``, and a disagreement flagged; a call only the vault's
chain holds is listed in ``vault_only``. An orphan is judged against the live chain, the kept
archived epochs (their :class:`Coverage`) and the vault chain's accepted refs, each flag at its
boundaries, on the vault's clock (J.3), the span starting when the vault received the earliest
kept file's first line.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from tests.unit.test_ledgerjoin import (
    RECORDS,
    REF_A,
    REF_B,
    REF_C,
    REF_D,
    REF_E,
    T,
    asked,
    outcome,
    record,
)
from zoeymcp.common.policy.schema import Policy
from zoeymcp.vault.ledgerview import (
    MAX_LIMIT,
    NAMED,
    Coverage,
    Send,
    coverage,
    known,
    orphans,
    page,
    sends,
    state,
    verdict,
    when,
)
from zoeymcp.vault.reports import Held, LiveFile

HASH = "sha256:" + "f" * 64
NOW = T + 2 * 86_400_000
HELD = Held("ok", 0, 11, HASH, (LiveFile("000000000000.jsonl", 900, NOW - 12_345),))
RECEIVED = NOW - 12_345  # when the vault received HELD's file
LATER = "sha256:" + "a" * 64  # a prev that isn't the genesis hash: a chain taken partway through


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
        "where": "gateway",
        "decision": "accept",
        "via": None,
        "waited_ms": 8123,
        "outcome": "ok",
        "detail": "sent",
        "writes": 1,
        "writes_sent": 0,
        "writes_unknown": 0,
        "writers": {"asked": "gateway", "decided": "gateway", "outcome": "gateway"},
        "others": [],
        "disagree": False,
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
    """M8 design C.4: the vault's chain records ``decided accept``; ``approved_elsewhere`` is
    the gateway's own record of that."""
    row = view()["rows"][1]
    assert (row["ref"], row["decision"], row["waited_ms"]) == (REF_D, "accept", 0)
    assert row["writers"] == {"asked": "gateway", "decided": "vault"}
    assert (row["via"], row["others"], row["disagree"]) == ("telegram", [], False)


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
        "servers": {"mail": {"kind": "remote", "route": "x"}},
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
    assert orphans(found, Coverage(frozenset({REF_A}), received_ms=received)) == [
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
    assert [o["flag"] for o in orphans(found, Coverage())] == ["not_yet_reported"] * 4


def test_a_send_older_than_the_copy_cant_be_checked() -> None:
    """``older_than_copy``: reported since, but begun before the copy's earliest record (its
    call pruned, or its epoch dropped); one begun exactly then is in the span, and an orphan."""
    received = HELD.received_ms
    assert received is not None
    first = received - 100
    found = [
        Send("mail", "1111111111111111.1", "sent", 250, first, first + 1),
        Send("mail", "2222222222222222.1", "sent", 250, first - 1, first + 2),
        Send("mail", "3333333333333333.1", "failed", 554, first - 99, first - 98),
        Send("mail", f"{REF_A}.1", "sent", 250, first - 50, first - 49),  # its call is held
    ]
    covered = Coverage(frozenset({REF_A}), first, received)
    assert orphans(found, covered) == [
        {
            "connector": "mail",
            "key": "1111111111111111.1",
            "state": "sent",
            "at": when(first + 1),
            "flag": "no_ledger_record",  # exactly at the earliest record: checked
        },
        {
            "connector": "mail",
            "key": "2222222222222222.1",
            "state": "sent",
            "at": when(first + 2),
            "flag": "older_than_copy",
        },
        {
            "connector": "mail",
            "key": "3333333333333333.1",
            "state": "failed",
            "at": when(first - 98),
            "flag": "older_than_copy",
        },
    ]
    # Not reported since: not_yet_reported, however old.
    flags = [o["flag"] for o in orphans(found, Coverage(covered.refs, first, first - 1))]
    assert flags == ["not_yet_reported", "not_yet_reported", "older_than_copy"]
    unreported = Coverage(covered.refs, first)
    assert [o["flag"] for o in orphans(found, unreported)] == ["not_yet_reported"] * 3
    # A copy that holds no record has no span to be older than.
    nothing = Coverage(received_ms=received)
    assert [o["flag"] for o in orphans(found, nothing)] == ["no_ledger_record"] * 4


def taken(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """``records`` as a chain the copy took partway through: its first doesn't follow genesis."""
    return [{**records[0], "prev": LATER}, *records[1:]]


def test_coverage_is_the_refs_and_a_span_on_the_vaults_clock() -> None:
    """J.3 (C-9): the span starts on the vault's clock, never at a record's ``ts``: at 0 for a
    chain held from the gateway's first record (nothing came before it), else when the vault
    received the earliest file holding it; ``received_ms`` is when it last received any."""
    assert Coverage() == Coverage(frozenset(), None, None, None)
    assert coverage([]) == Coverage()
    assert coverage([], received_ms=5, first_received_ms=3) == Coverage()
    records = taken(
        [
            record(0, T + 5, None, "repaired", torn_bytes=1),
            asked(1, T + 2, REF_A),
            asked(2, T + 9, REF_B),
            record(3, T + 3, REF_A, "decided", decision="accept", waited_ms=1),
        ]
    )
    both = frozenset({REF_A, REF_B})
    assert coverage(records, received_ms=NOW, first_received_ms=NOW - 50) == Coverage(
        both, NOW - 50, NOW
    )
    assert coverage(records) == Coverage(both)  # no receipt times: no span
    only = coverage(records[:1], received_ms=NOW, first_received_ms=NOW - 50)
    assert only == Coverage(frozenset(), NOW - 50, NOW)  # a ledger-level record only
    # The records' own times move nothing: a gateway's clock can't push the span.
    shifted = [{**r, "ts": r["ts"] + 10**12} for r in records]
    assert coverage(shifted, received_ms=NOW, first_received_ms=NOW - 50).first_ms == NOW - 50
    # Held from the gateway's first record: the span is everything, whenever the file came.
    held = coverage(RECORDS, received_ms=NOW, first_received_ms=NOW - 50)
    assert held == Coverage(frozenset({REF_A, REF_B, REF_C, REF_D, REF_E}), 0, NOW)
    # Only the first record's prev counts.
    assert coverage([*records, *RECORDS], first_received_ms=7).first_ms == 7
    assert coverage([*RECORDS, *records], first_received_ms=7).first_ms == 0


@pytest.mark.parametrize(
    ("left", "right", "both"),
    [
        (Coverage(), Coverage(), Coverage()),
        (Coverage(frozenset("a"), 5, 9, 2), Coverage(), Coverage(frozenset("a"), 5, 9, 2)),
        (Coverage(), Coverage(frozenset("b"), 3, 4, 1), Coverage(frozenset("b"), 3, 4, 1)),
        (
            Coverage(frozenset("a"), 5, 9, 1),
            Coverage(frozenset("b"), 3, 4, 2),
            Coverage(frozenset("ab"), 3, 9, 2),
        ),
        (
            Coverage(frozenset("a"), 3, 4, 2),
            Coverage(frozenset("ab"), 5, 9, 1),
            Coverage(frozenset("ab"), 3, 9, 2),
        ),
        (Coverage(first_ms=0), Coverage(first_ms=5), Coverage(first_ms=0)),
        (Coverage(received_ms=0), Coverage(received_ms=5), Coverage(received_ms=5)),
        (Coverage(deleted_ms=0), Coverage(deleted_ms=5), Coverage(deleted_ms=5)),
    ],
)
def test_coverages_join(left: Coverage, right: Coverage, both: Coverage) -> None:
    """The refs together, the earliest span, the latest receipt, the latest deleted epoch."""
    assert left | right == both
    assert right | left == both


@pytest.mark.parametrize(
    ("first", "deleted", "start"),
    [
        (None, None, None),
        (None, 0, 0),
        (5, None, 5),
        (0, None, 0),
        (None, 5, 5),
        (0, 5, 5),
        (3, 5, 5),
        (5, 3, 5),
        (5, 5, 5),
    ],
)
def test_the_span_never_starts_before_a_deleted_epoch(
    first: int | None, deleted: int | None, start: int | None
) -> None:
    assert Coverage(first_ms=first, deleted_ms=deleted).start_ms == start


def test_nothing_before_a_deleted_epoch_can_be_checked() -> None:
    """A restart that deleted an archived epoch: a send begun before the vault last received a
    line of it can't be checked, even beside a chain held from the gateway's first record (the
    gateway's ledger may have started again)."""
    found = [
        Send("mail", "1111111111111111.1", "sent", 250, RECEIVED - 101, RECEIVED - 99),
        Send("mail", "2222222222222222.1", "sent", 250, RECEIVED - 100, RECEIVED - 98),
    ]
    covered = Coverage(frozenset(), 0, RECEIVED, deleted_ms=RECEIVED - 100)
    assert [(o["key"], o["flag"]) for o in orphans(found, covered)] == [
        ("2222222222222222.1", "no_ledger_record"),
        ("1111111111111111.1", "older_than_copy"),
    ]


def test_the_archives_are_part_of_the_copy() -> None:
    """A send whose call only an archived epoch holds isn't an orphan; the span starts at the
    earliest of the live chain's and the archives' (each on the vault's clock)."""
    archived, older, inside = "a" * 16, "b" * 16, "c" * 16
    journals = {
        "mail": [
            sending(RECEIVED - 90_000, f"{archived}.1"),
            sending(RECEIVED - 70_001, f"{older}.1"),
            sending(RECEIVED - 70_000, f"{inside}.1"),
        ]
    }
    live = taken(RECORDS)  # its span starts when the vault received its file: after all three

    def flags(**kwargs: Any) -> dict[str, str]:
        result = page(live, held=HELD, journals=journals, now=NOW, **kwargs)
        return {o["key"]: o["flag"] for o in result["orphans"]}

    assert flags() == {f"{key}.1": "older_than_copy" for key in (archived, older, inside)}
    held = Coverage(frozenset({archived}), RECEIVED - 70_000, RECEIVED - 60_000)
    assert flags(archived=held) == {
        f"{older}.1": "older_than_copy",
        f"{inside}.1": "no_ledger_record",
    }
    # The live chain's span starts the copy's when it is the earlier one.
    later = Coverage(frozenset({archived}), RECEIVED + 5, RECEIVED + 5)
    assert flags(archived=later) == {
        f"{older}.1": "older_than_copy",
        f"{inside}.1": "older_than_copy",
    }
    # A live chain held from the gateway's first record: every send can be checked.
    result = page(RECORDS, held=HELD, journals=journals, now=NOW)
    assert {o["flag"] for o in result["orphans"]} == {"no_ledger_record"}
    assert flags(archived=held, before=8) == {}


def test_a_report_into_an_archived_epoch_counts() -> None:
    """``not_yet_reported`` reads every chain the copy holds (D-165): right after a restart, with
    nothing in the new live chain, a send begun before the archived epoch's last report is judged
    against it."""
    journals = {"mail": [sending(RECEIVED - 1, "1111111111111111.1"), sending(RECEIVED, "x.1")]}
    archived = Coverage(frozenset(), 0, RECEIVED)
    result = page([], held=Held(), journals=journals, now=NOW, archived=archived)
    assert [(o["key"], o["flag"]) for o in result["orphans"]] == [
        ("x.1", "not_yet_reported"),
        ("1111111111111111.1", "no_ledger_record"),
    ]
    alone = page([], held=Held(), journals=journals, now=NOW)
    assert {o["flag"] for o in alone["orphans"]} == {"not_yet_reported"}


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


# --- the vault's own chain (M8 design J.2, J.3; FM-42) -------------------------------------------


def decided(seq: int, ref: str, decision: str, *, writer: str = "gateway", via: str = "") -> Any:
    fields: dict[str, Any] = {"decision": decision, "waited_ms": 5}
    if writer == "vault":
        fields["via"] = via or "telegram"
    return record(seq, T + seq, ref, "decided", writer=writer, **fields)


HELD_REF, RELAY_REF, DISPUTED, VAULT_ONLY = "1" * 16, "2" * 16, "3" * 16, "4" * 16
# A call the vault held, a relay, and a call the two chains disagree on, as the copy holds them.
COPY = [
    asked(0, T, HELD_REF, where="vault"),
    asked(1, T + 1, RELAY_REF),
    asked(2, T + 2, DISPUTED, where="vault"),
    decided(3, HELD_REF, "approved_elsewhere"),
    outcome(4, T + 4, HELD_REF, "ok", None),
    decided(5, RELAY_REF, "accept"),
    outcome(6, T + 6, RELAY_REF, "ok", "sent"),
    decided(7, DISPUTED, "decline"),
]
# The vault's chain, numbered on its own: it asked each before its surfaces, decided, and closed.
CHAIN = [
    record(0, T, None, "recovered", abandoned=0, not_sent=0, unknown=0, writer="vault"),
    asked(1, T + 1, HELD_REF, writer="vault", where="vault"),
    decided(2, HELD_REF, "accept", writer="vault"),
    outcome(3, T + 3, HELD_REF, "ok", None, writer="vault"),
    asked(4, T + 4, RELAY_REF, writer="vault"),
    decided(5, RELAY_REF, "accept", writer="vault", via="portal"),
    outcome(6, T + 6, RELAY_REF, "unknown", "relayed", writer="vault"),
    asked(7, T + 7, DISPUTED, writer="vault", where="vault"),
    decided(8, DISPUTED, "accept", writer="vault"),
    outcome(9, T + 9, DISPUTED, "ok", None, writer="vault"),
    asked(10, T + 10, VAULT_ONLY, writer="vault", where="vault"),
    decided(11, VAULT_ONLY, "accept", writer="vault"),
]


def joined(**kwargs: Any) -> dict[str, Any]:
    return page(
        COPY, held=HELD, journals=kwargs.pop("journals", {}), now=NOW, chain=CHAIN, **kwargs
    )


def test_a_held_call_and_a_relay_join_across_both_chains() -> None:
    """FM-42: one row per call, by ref: the vault's decision (with its surface), the vault's
    outcome for the call it held and the gateway's for the relay, who wrote each, and the other
    chain's records beside them. The chain's own ledger-level records aren't rows, and a call
    only the vault's chain holds isn't a row (the rows page by the copy's seqs): it is in
    ``vault_only``, with the vault chain's seq and records, flagged by when the vault asked it."""
    result = joined()
    rows = result["rows"]
    assert [row["ref"] for row in rows] == [DISPUTED, RELAY_REF, HELD_REF]
    [alone] = result["vault_only"]
    assert {key: alone[key] for key in ("ref", "seq", "where", "decision", "via", "flag")} == {
        "ref": VAULT_ONLY,
        "seq": 10,
        "where": "vault",
        "decision": "accept",
        "via": "telegram",
        "flag": "no_ledger_record",  # the copy, held from genesis, has had reports since
    }
    assert alone["writers"] == {"asked": "vault", "decided": "vault"}
    assert (alone["others"], alone["disagree"], result["vault_only_more"]) == ([], False, 0)
    assert (joined(before=8)["vault_only"], joined(before=8)["vault_only_more"]) == ([], 0)
    held = rows[2]
    assert {key: held[key] for key in ("seq", "where", "decision", "via", "waited_ms")} == {
        "seq": 0,
        "where": "vault",
        "decision": "accept",
        "via": "telegram",
        "waited_ms": 5,
    }
    assert (held["outcome"], held["detail"], held["disagree"]) == ("ok", None, False)
    assert held["writers"] == {"asked": "gateway", "decided": "vault", "outcome": "vault"}
    assert held["others"] == [
        {"kind": "decided", "writer": "gateway", "decision": "approved_elsewhere"},
        {"kind": "outcome", "writer": "gateway", "outcome": "ok", "detail": None},
    ]
    relay = rows[1]
    assert (relay["seq"], relay["where"], relay["decision"], relay["via"]) == (
        1,
        "gateway",
        "accept",
        "portal",
    )
    assert (relay["outcome"], relay["detail"], relay["disagree"]) == ("ok", "sent", False)
    assert relay["writers"] == {"asked": "gateway", "decided": "vault", "outcome": "gateway"}
    assert relay["others"] == [
        {"kind": "decided", "writer": "gateway", "decision": "accept"},
        {"kind": "outcome", "writer": "vault", "outcome": "unknown", "detail": "relayed"},
    ]


def test_the_chains_disagree_and_both_are_shown() -> None:
    """J.2: an accept in the vault and a decline at the gateway flag the row; both are in it."""
    row = joined()["rows"][0]
    assert (row["ref"], row["disagree"], row["decision"], row["via"]) == (
        DISPUTED,
        True,
        "accept",
        "telegram",
    )
    assert row["others"] == [{"kind": "decided", "writer": "gateway", "decision": "decline"}]
    assert row["outcome"] == "ok"  # the vault's: it held the call and sent it


def test_without_the_vault_chain_the_rows_are_the_copys() -> None:
    rows = page(COPY, held=HELD, journals={}, now=NOW)["rows"]
    held = rows[2]
    assert (held["decision"], held["via"], held["outcome"]) == ("approved_elsewhere", None, "ok")
    assert held["writers"] == {"asked": "gateway", "decided": "gateway", "outcome": "gateway"}
    assert (held["where"], held["others"], held["disagree"]) == ("vault", [], False)


def test_the_vault_chains_calls_alone() -> None:
    """K.3's ``ledger --vault --chain vault``: the rows of the calls the vault's chain holds,
    still joined against the whole copy, so a call the copy holds is a row and never one only
    the vault's chain holds, and a send whose call the copy holds is no orphan. The copy's other
    calls and its ledger-level records go; the rows still page by the copy's seqs."""
    gateways = "5" * 16
    recovered = record(9, T + 9, None, "recovered", abandoned=0, not_sent=0, unknown=0)
    records = [*COPY, asked(8, T + 8, gateways), recovered]
    journals = {"mail": [sending(RECEIVED - 1, f"{gateways}.1")]}

    def vault(**kwargs: Any) -> dict[str, Any]:
        return page(
            records, held=HELD, journals=journals, now=NOW, chain=CHAIN, vault_calls=True, **kwargs
        )

    result = vault()
    assert [row["ref"] for row in result["rows"]] == [DISPUTED, RELAY_REF, HELD_REF]
    assert [row["ref"] for row in result["vault_only"]] == [VAULT_ONLY]
    assert (result["orphans"], result["next"]) == ([], None)
    first = vault(limit=1)
    assert ([row["ref"] for row in first["rows"]], first["next"]) == ([DISPUTED], 2)
    assert [row["ref"] for row in vault(before=2)["rows"]] == [RELAY_REF, HELD_REF]
    both = page(records, held=HELD, journals=journals, now=NOW, chain=CHAIN)
    assert [row.get("ref") for row in both["rows"]] == [
        None,
        gateways,
        DISPUTED,
        RELAY_REF,
        HELD_REF,
    ]


def test_the_vaults_outcome_alone_is_shown() -> None:
    """A held call the gateway hasn't closed yet shows the vault's outcome; a relay the gateway
    hasn't closed shows the vault's ``unknown, relayed`` until it does."""
    records = [asked(0, T, HELD_REF, where="vault"), asked(1, T, RELAY_REF)]
    chain = [CHAIN[3], CHAIN[6]]
    rows = page(records, held=HELD, journals={}, now=NOW, chain=chain)["rows"]
    assert [(row["ref"], row["outcome"], row["detail"]) for row in rows] == [
        (RELAY_REF, "unknown", "relayed"),
        (HELD_REF, "ok", None),
    ]
    assert [row["writers"] for row in rows] == [{"asked": "gateway", "outcome": "vault"}] * 2


def test_the_vaults_asked_decides_where_the_call_was_held() -> None:
    records = [asked(0, T, HELD_REF)]
    chain = [asked(1, T, HELD_REF, writer="vault", where="vault")]
    [row] = page(records, held=HELD, journals={}, now=NOW, chain=chain)["rows"]
    assert row["where"] == "vault"
    assert row["writers"] == {"asked": "gateway"}


@pytest.mark.parametrize(
    ("vault", "gateway", "disagree"),
    [
        ("accept", "approved_elsewhere", False),
        ("accept", "pending", False),
        ("accept", "accept", False),
        ("accept", "decline", True),
        ("accept", "withdrawn", True),
        ("accept", "timeout", True),
        ("accept", "stream_lost", True),
        ("accept", "error", False),
        ("accept", "unavailable", False),
        ("accept", "abandoned", False),  # the gateway's restart: it never heard the decision
        ("accept", "shutdown", False),  # the gateway's stop cut the call before the answer came
        ("decline", "approved_elsewhere", True),
        ("timeout", "accept", True),
        ("abandoned", "approved_elsewhere", True),  # the vault's own: it never forwarded
        ("decline", "decline", False),
        ("timeout", "withdrawn", False),
        ("withdrawn", "error", False),
        ("accept", None, False),
        (None, "decline", False),
    ],
)
def test_which_decisions_disagree(vault: str | None, gateway: str | None, disagree: bool) -> None:
    records = [asked(0, T, HELD_REF, where="vault")]
    chain = [asked(1, T, HELD_REF, writer="vault", where="vault")]
    if gateway is not None:
        records.append(decided(2, HELD_REF, gateway))
    if vault is not None:
        chain.append(decided(3, HELD_REF, vault, writer="vault"))
    [row] = page(records, held=HELD, journals={}, now=NOW, chain=chain)["rows"]
    assert row["disagree"] is disagree


@pytest.mark.parametrize(
    ("decision", "writer", "says"),
    [
        (None, "vault", None),
        ("accept", "vault", True),
        ("approved_elsewhere", "gateway", True),
        ("pending", "gateway", None),
        ("error", "vault", None),
        ("unavailable", "gateway", None),
        ("abandoned", "gateway", None),
        ("abandoned", "vault", False),
        ("shutdown", "gateway", None),
        ("decline", "gateway", False),
        ("dismiss", "gateway", False),
        ("shutdown", "vault", False),
    ],
)
def test_a_decisions_verdict(decision: str | None, writer: str, says: bool | None) -> None:
    assert verdict(decision, writer) is says


def test_a_send_the_vault_accepted_is_no_orphan() -> None:
    """J.3: a send whose ref the vault's chain holds as ``decided accept`` isn't an orphan,
    whatever the copy says; one it declined, or only asked, still is."""
    declined, waiting = "5" * 16, "6" * 16
    chain = [
        *CHAIN,
        asked(12, T, declined, writer="vault", where="vault"),
        decided(13, declined, "decline", writer="vault"),
        asked(14, T, waiting, writer="vault", where="vault"),
    ]
    journals = {
        "mail": [
            sending(RECEIVED - 3, f"{VAULT_ONLY}.1"),
            sending(RECEIVED - 2, f"{declined}.1"),
            sending(RECEIVED - 1, f"{waiting}.1"),
        ]
    }
    result = page(COPY, held=HELD, journals=journals, now=NOW, chain=chain)
    assert [(o["key"], o["flag"]) for o in result["orphans"]] == [
        (f"{waiting}.1", "no_ledger_record"),
        (f"{declined}.1", "no_ledger_record"),
    ]
    # Each call is still shown: only the vault's chain holds them (F1 of step 8b's review).
    assert [
        (row["ref"], row["decision"], [send["key"] for send in row["journal"]])
        for row in result["vault_only"]
    ] == [
        (waiting, None, [f"{waiting}.1"]),
        (declined, "decline", [f"{declined}.1"]),
        (VAULT_ONLY, "accept", [f"{VAULT_ONLY}.1"]),
    ]
    alone = page(COPY, held=HELD, journals=journals, now=NOW)
    assert len(alone["orphans"]) == 3
    assert alone["vault_only"] == []


def test_a_call_only_the_vault_holds_is_flagged_by_when_it_was_asked() -> None:
    """Against a copy taken partway through, whose earliest file the vault began receiving at
    ``first``: asked before it, ``older_than_copy``; from it until the copy's last report,
    ``no_ledger_record``; after that, ``not_yet_reported``. A ref an archived epoch holds, or
    one the copy holds by any record, isn't the vault's alone."""
    first = RECEIVED - 1_000
    held = Held("ok", 0, 11, HASH, (LiveFile("000000000000.jsonl", 900, RECEIVED, first),))
    asks = {"7" * 16: first - 1, "8" * 16: first, "9" * 16: RECEIVED - 1, "a" * 16: RECEIVED}
    chain = [
        asked(seq, ts, ref, writer="vault", where="vault")
        for seq, (ref, ts) in enumerate(asks.items())
    ]
    chain.append(asked(9, RECEIVED, REF_A, writer="vault", where="vault"))  # the copy holds it
    result = page(taken(RECORDS), held=held, journals={}, now=NOW, chain=chain)
    assert [(row["ref"], row["flag"]) for row in result["vault_only"]] == [
        ("a" * 16, "not_yet_reported"),
        ("9" * 16, "no_ledger_record"),
        ("8" * 16, "no_ledger_record"),
        ("7" * 16, "older_than_copy"),
    ]
    archived = Coverage(frozenset({"7" * 16, "8" * 16}))
    result = page(taken(RECORDS), held=held, journals={}, now=NOW, chain=chain, archived=archived)
    assert [row["ref"] for row in result["vault_only"]] == ["a" * 16, "9" * 16]


def test_the_calls_only_the_vault_holds_are_bounded() -> None:
    """The newest :data:`MAX_LIMIT`, the rest counted."""
    chain = [asked(seq, T + seq, f"{seq + 1:016x}", writer="vault") for seq in range(MAX_LIMIT + 2)]
    result = page([], held=Held(), journals={}, now=NOW, chain=chain)
    assert [row["seq"] for row in result["vault_only"]] == list(range(MAX_LIMIT + 1, 1, -1))
    assert result["vault_only_more"] == 2
    exact = page([], held=Held(), journals={}, now=NOW, chain=chain[:MAX_LIMIT])
    assert (len(exact["vault_only"]), exact["vault_only_more"]) == (MAX_LIMIT, 0)


def test_the_vault_asking_a_ref_again_keeps_the_copys_row() -> None:
    """Each chain is read alone: the vault asking a ref again (a resend after its endings
    expired) starts that ref's vault records again, and never hides the copy's call."""
    chain = [*CHAIN[:4], asked(12, T + 12, HELD_REF, writer="vault", where="vault")]
    rows = page(COPY, held=HELD, journals={}, now=NOW, chain=chain)["rows"]
    assert [row["ref"] for row in rows] == [DISPUTED, RELAY_REF, HELD_REF]
    held = rows[2]
    assert (held["decision"], held["outcome"], held["others"]) == ("approved_elsewhere", "ok", [])
    assert held["writers"] == {"asked": "gateway", "decided": "gateway", "outcome": "gateway"}
    # The gateway asking it again, after the vault's records of it: still one row.
    again = [*COPY, asked(8, T + 8, HELD_REF, where="vault")]
    rows = page(again, held=HELD, journals={}, now=NOW, chain=CHAIN)["rows"]
    assert [(row["ref"], row["seq"]) for row in rows] == [
        (HELD_REF, 8),
        (DISPUTED, 2),
        (RELAY_REF, 1),
    ]
    assert (rows[0]["decision"], rows[0]["via"]) == ("accept", "telegram")


def test_a_partway_copys_span_starts_at_its_first_receipt() -> None:
    """J.3 with one live file still taking reports: the span starts when the vault received
    that file's first line, so a send begun since, with no call in the copy, is
    ``no_ledger_record``; without that time recorded, the span starts at its last receipt."""
    first = RECEIVED - 1_000
    held = Held("ok", 0, 11, HASH, (LiveFile("000000000000.jsonl", 900, RECEIVED, first),))
    journals = {
        "mail": [
            sending(first - 1, "1111111111111111.1"),
            sending(first, "2222222222222222.1"),
            sending(RECEIVED, "3333333333333333.1"),
        ]
    }
    result = page(taken(RECORDS), held=held, journals=journals, now=NOW)
    assert [(o["key"], o["flag"]) for o in result["orphans"]] == [
        ("3333333333333333.1", "not_yet_reported"),
        ("2222222222222222.1", "no_ledger_record"),
        ("1111111111111111.1", "older_than_copy"),
    ]
    unrecorded = page(taken(RECORDS), held=HELD, journals=journals, now=NOW)
    assert [o["flag"] for o in unrecorded["orphans"]] == [
        "not_yet_reported",
        "older_than_copy",
        "older_than_copy",
    ]
    # Only the earliest kept file's first receipt counts.
    later = LiveFile("000000000009.jsonl", 10, RECEIVED, RECEIVED - 1)
    two = Held("ok", 0, 11, HASH, (held.files[0], later))
    result = page(taken(RECORDS), held=two, journals=journals, now=NOW)
    assert [o["flag"] for o in result["orphans"]] == [
        "not_yet_reported",
        "no_ledger_record",
        "older_than_copy",
    ]
