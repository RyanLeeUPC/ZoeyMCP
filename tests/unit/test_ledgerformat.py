"""The approval ledger's record format, chain and recovery plan (M4 design F)."""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from zoeymcp.common import canonical
from zoeymcp.common.ledgerformat import (
    DECISIONS,
    DETAILS,
    GENESIS,
    MAX_LINE_BYTES,
    VIAS,
    LedgerFormatError,
    Record,
    Step,
    encode,
    line_hash,
    open_refs,
    parse,
    recovery_plan,
    torn_tail,
    verify,
)

REF = "3f9c0a17d2b84e65"
OTHER = "9b21e07c44d0aa13"
HMAC = "hmac-sha256:" + "a" * 64
PIN = "sha256:" + "b" * 64
ASKED: dict[str, Any] = {
    "client": "agent1",
    "server": "mail",
    "tool": "send_note",
    "where": "gateway",
    "era": "legacy",
    "args": HMAC,
    "pin": PIN,
    "text": HMAC,
    "chars": 412,
    "writes": 1,
    "expires": 1_767_276_300_000,
}
OUTCOME = {"outcome": "ok", "detail": "sent", "writes_sent": 1, "writes_unknown": 0}


class Chain:
    """Builds a valid chain of lines, all written by one writer."""

    def __init__(self, writer: str = "gateway") -> None:
        self.lines: list[bytes] = []
        self.prev = GENESIS
        self.writer = writer

    def add(self, kind: Any, ref: str | None, **fields: Any) -> bytes:
        line = encode(
            kind,
            seq=len(self.lines),
            prev=self.prev,
            ts=1000 + len(self.lines),
            ref=ref,
            writer=self.writer,
            **fields,
        )
        self.lines.append(line)
        self.prev = line_hash(line)
        return line

    def call(
        self,
        ref: str,
        decision: str | None = None,
        outcome: dict[str, Any] | None = None,
        *,
        where: str = "gateway",
    ) -> None:
        self.add("asked", ref, **{**ASKED, "where": where})
        if decision is not None:
            via = {"via": "telegram"} if self.writer == "vault" else {}
            self.add("decided", ref, decision=decision, waited_ms=10, **via)
        if outcome is not None:
            self.add("outcome", ref, **outcome)

    def records(self) -> list[Record]:
        return [parse(line) for line in self.lines]


# --- records -------------------------------------------------------------------------------------


def test_a_record_is_one_canonical_line() -> None:
    line = encode("asked", seq=0, prev=GENESIS, ts=1000, ref=REF, **ASKED)
    assert line.endswith(b"\n")
    assert line.count(b"\n") == 1
    assert line[:-1] == canonical.dumps_canonical(canonical.loads_strict(line[:-1]))
    record = parse(line)
    assert (record.seq, record.prev, record.ts, record.ref) == (0, GENESIS, 1000, REF)
    assert (record.kind, record.writer) == ("asked", "gateway")
    assert dict(record.fields) == ASKED
    assert record.hash == line_hash(line) == line_hash(line[:-1])
    assert parse(line[:-1]) == record


def test_every_kind_round_trips() -> None:
    chain = Chain()
    chain.call(REF, "accept", OUTCOME)
    chain.add("outcome", OTHER, outcome="unknown", detail=None, writes_sent=0, writes_unknown=1)
    chain.add("recovered", None, abandoned=1, not_sent=1, unknown=0)
    chain.add("repaired", None, torn_bytes=17)
    assert [r.kind for r in chain.records()] == [
        "asked",
        "decided",
        "outcome",
        "outcome",
        "recovered",
        "repaired",
    ]


def test_every_decision_is_accepted_including_m8s() -> None:
    for decision in sorted(DECISIONS):
        encode("decided", seq=0, prev=GENESIS, ts=1, ref=REF, decision=decision, waited_ms=0)
    assert {"approved_elsewhere", "pending"} <= DECISIONS


def test_the_vault_may_write_the_same_records() -> None:
    line = encode(
        "asked", seq=0, prev=GENESIS, ts=1, ref=REF, writer="vault", **{**ASKED, "where": "vault"}
    )
    assert parse(line).writer == "vault"


def vault_decided(**fields: Any) -> bytes:
    return encode("decided", seq=0, prev=GENESIS, ts=1, ref=REF, writer="vault", **fields)


def test_a_vault_decision_names_the_surface_it_came_through() -> None:
    """M8 design J.1: ``via`` is required on the vault's ``decided`` and absent on the
    gateway's; no other kind carries it."""
    decided: dict[str, Any] = {"decision": "accept", "waited_ms": 0}
    assert {"telegram", "portal", "host", "none"} == VIAS
    for via in sorted(VIAS):
        assert parse(vault_decided(via=via, **decided)).fields == {**decided, "via": via}
    for fields, message in [
        (decided, "wrong fields"),
        ({**decided, "via": "email"}, "bad via"),
        ({**decided, "via": None}, "bad via"),
    ]:
        with pytest.raises(LedgerFormatError, match=message):
            vault_decided(**fields)
    with pytest.raises(LedgerFormatError, match="wrong fields"):
        encode("decided", seq=0, prev=GENESIS, ts=1, ref=REF, via="telegram", **decided)
    with pytest.raises(LedgerFormatError, match="wrong fields"):
        encode("outcome", seq=0, prev=GENESIS, ts=1, ref=REF, writer="vault", via="none", **OUTCOME)
    # A line the vault wrote without its via doesn't parse either.
    line = vault_decided(via="host", **decided)
    with pytest.raises(LedgerFormatError, match="wrong fields"):
        parse(line.replace(b',"via":"host"', b""))


def test_a_relay_and_a_lost_ledger_are_outcome_details() -> None:
    """M8 design J.1: the vault's outcome for a relay, and a hold ended by its ledger."""
    assert {"relayed", "ledger"} <= DETAILS
    for detail in ("relayed", "ledger"):
        fields = {**OUTCOME, "outcome": "unknown", "detail": detail, "writes_sent": 0}
        line = encode("outcome", seq=0, prev=GENESIS, ts=1, ref=REF, writer="vault", **fields)
        assert parse(line).fields["detail"] == detail


@pytest.mark.parametrize(
    ("kind", "ref", "fields", "message"),
    [
        ("nope", REF, {}, "unknown kind"),
        ("asked", REF, {**ASKED, "args": "sha256:" + "a" * 64}, "bad args"),
        ("asked", REF, {**ASKED, "text": "do not log this"}, "bad text"),
        ("asked", REF, {**ASKED, "pin": "x"}, "bad pin"),
        ("asked", REF, {**ASKED, "client": "a b"}, "bad client"),
        ("asked", REF, {**ASKED, "era": "future"}, "bad era"),
        ("asked", REF, {**ASKED, "where": "elsewhere"}, "bad where"),
        ("asked", REF, {**ASKED, "chars": -1}, "bad chars"),
        ("asked", REF, {**ASKED, "chars": True}, "bad chars"),
        ("asked", REF, {**ASKED, "subject": "Hi"}, "wrong fields"),
        ("asked", REF, {k: v for k, v in ASKED.items() if k != "tool"}, "wrong fields"),
        ("asked", "XYZ", ASKED, "bad ref"),
        # A trailing newline must not slip past an anchored pattern.
        ("asked", REF + chr(10), ASKED, "bad ref"),
        ("asked", REF, {**ASKED, "client": "agent1" + chr(10)}, "bad client"),
        ("asked", REF, {**ASKED, "pin": PIN + chr(10)}, "bad pin"),
        ("asked", None, ASKED, "bad ref"),
        ("decided", REF, {"decision": "maybe", "waited_ms": 0}, "bad decision"),
        ("outcome", REF, {**OUTCOME, "outcome": "fine"}, "bad outcome"),
        ("outcome", REF, {**OUTCOME, "detail": "free text"}, "bad detail"),
        ("recovered", REF, {"abandoned": 0, "not_sent": 0, "unknown": 0}, "has no ref"),
        ("repaired", None, {"torn_bytes": "1"}, "bad torn_bytes"),
    ],
)
def test_bad_records_are_refused(
    kind: Any, ref: str | None, fields: dict[str, Any], message: str
) -> None:
    with pytest.raises(LedgerFormatError, match=message):
        encode(kind, seq=0, prev=GENESIS, ts=1, ref=ref, **fields)


def test_common_fields_are_checked() -> None:
    cases: list[tuple[dict[str, Any], str]] = [
        ({"seq": -1}, "bad seq"),
        ({"ts": 1.5}, "bad seq or ts"),
        ({"prev": "sha256:00"}, "bad prev"),
        ({"writer": "agent"}, "bad writer"),
    ]
    for changes, message in cases:
        kwargs: dict[str, Any] = {"seq": 0, "prev": GENESIS, "ts": 1, "ref": REF, **changes}
        with pytest.raises(LedgerFormatError, match=message):
            encode("decided", decision="accept", waited_ms=0, **kwargs)


def test_parse_refuses_what_encode_would_not_write() -> None:
    good = encode("decided", seq=0, prev=GENESIS, ts=1, ref=REF, decision="accept", waited_ms=0)
    value = canonical.loads_strict(good[:-1])
    for bad in (
        b"not json",
        b"[1]",
        good[:-1].replace(b'"v":1', b'"v":2'),
        b'{"v":1,  "kind":"decided"}',
        canonical.dumps_canonical(value).replace(b"{", b"{ ", 1),  # not canonical
        b"\xff",
    ):
        with pytest.raises(LedgerFormatError):
            parse(bad)


def test_lines_are_bounded() -> None:
    long_name = "x" * 128
    line = encode("asked", seq=0, prev=GENESIS, ts=1, ref=REF, **{**ASKED, "client": long_name})
    assert len(line) <= MAX_LINE_BYTES
    with pytest.raises(LedgerFormatError, match="longer than"):
        parse(b"{" + b" " * MAX_LINE_BYTES + b"}")


# --- the chain -----------------------------------------------------------------------------------


def test_a_valid_chain_verifies_to_its_head() -> None:
    chain = Chain()
    chain.call(REF, "decline", {**OUTCOME, "outcome": "not_sent", "detail": None, "writes_sent": 0})
    chain.call(OTHER, "accept", OUTCOME)
    result = verify(chain.lines)
    assert (result.head_seq, result.records, result.broken_at) == (5, 6, None)
    assert result.head_hash == chain.prev
    assert verify([]) == verify([], prev=GENESIS, seq=0)
    assert verify([]).head_seq == -1


def test_a_chain_can_continue_from_an_earlier_file() -> None:
    chain = Chain()
    chain.call(REF, "accept", OUTCOME)
    first, second = chain.lines[:2], chain.lines[2:]
    head = verify(first)
    assert verify(second, prev=head.head_hash, seq=head.head_seq + 1).broken_at is None
    assert verify(second).broken_at == 2  # without the earlier file, it doesn't chain


def test_breaks_are_found() -> None:
    chain = Chain()
    chain.call(REF, "accept", OUTCOME)
    lines = chain.lines
    edited = lines[1].replace(b'"accept"', b'"decline"')
    assert verify([lines[0], edited, lines[2]]).broken_at == 2  # line 2 no longer chains
    assert verify([lines[0], lines[2]]).broken_at == 2  # a removed record
    assert verify([lines[0], b"garbage\n", lines[2]]).broken_at == 1
    result = verify([lines[1], lines[2]])
    assert (result.broken_at, result.head_seq, result.head_hash) == (1, -1, GENESIS)


def test_torn_tails() -> None:
    chain = Chain()
    chain.call(REF, "accept", OUTCOME)
    data = b"".join(chain.lines)
    assert torn_tail(b"") == 0
    assert torn_tail(data) == 0
    assert torn_tail(data + b'{"v":1,"se') == len(b'{"v":1,"se')
    assert torn_tail(data + b"half a line\n") == len(b"half a line\n")
    assert torn_tail(data[:-1]) == len(chain.lines[-1]) - 1  # the newline never made it
    assert torn_tail(b"no newline at all") == len(b"no newline at all")


# --- recovery ------------------------------------------------------------------------------------


def test_open_refs() -> None:
    chain = Chain()
    chain.call("0000000000000001", "accept", OUTCOME)  # closed
    chain.call("0000000000000002")  # asked only
    chain.call("0000000000000003", "decline")  # decided, no outcome
    chain.call("0000000000000004", "accept")  # accepted, no outcome
    chain.add("recovered", None, abandoned=0, not_sent=0, unknown=0)
    found = open_refs(chain.records())
    assert sorted(found) == ["0000000000000002", "0000000000000003", "0000000000000004"]
    assert [r.kind for r in found["0000000000000004"]] == ["asked", "decided"]


def test_the_recovery_plan_closes_each_open_ref_once() -> None:
    chain = Chain()
    chain.call("0000000000000004", "accept")
    chain.call("0000000000000002")
    chain.call("0000000000000003", "timeout")
    steps = recovery_plan(open_refs(chain.records()))
    assert [(s.kind, s.ref, dict(s.fields)) for s in steps] == [
        ("decided", "0000000000000002", {"decision": "abandoned", "waited_ms": 0}),
        (
            "outcome",
            "0000000000000002",
            {"outcome": "not_sent", "detail": "restart", "writes_sent": 0, "writes_unknown": 0},
        ),
        (
            "outcome",
            "0000000000000003",
            {"outcome": "not_sent", "detail": "restart", "writes_sent": 0, "writes_unknown": 0},
        ),
        (
            "outcome",
            "0000000000000004",
            {"outcome": "unknown", "detail": "restart", "writes_sent": 0, "writes_unknown": 1},
        ),
        ("recovered", None, {"abandoned": 1, "not_sent": 2, "unknown": 1}),
    ]
    assert recovery_plan({}) == []


def test_recovery_steps_encode_and_close_everything() -> None:
    for writer in ("gateway", "vault"):
        chain = Chain(writer)
        chain.call(REF, "accept")
        chain.call(OTHER)
        for step in recovery_plan(open_refs(chain.records())):
            chain.add(step.kind, step.ref, **step.fields)
        assert open_refs(chain.records()) == {}
        assert verify(chain.lines).broken_at is None


def outcomes(steps: list[Step]) -> dict[str | None, tuple[str, int]]:
    """Each closed ref's outcome and its writes_unknown."""
    return {
        s.ref: (s.fields["outcome"], s.fields["writes_unknown"])
        for s in steps
        if s.kind == "outcome"
    }


def decided(steps: list[Step]) -> list[tuple[str | None, dict[str, Any]]]:
    return [(s.ref, dict(s.fields)) for s in steps if s.kind == "decided"]


def test_a_call_the_vault_may_have_forwarded_closes_unknown() -> None:
    """M8 design C.4: after the gateway's ``approved_elsewhere`` or ``pending``, or its
    ``asked`` with ``where: vault`` and no decision, the vault may have held the call, been
    approved and forwarded it."""
    refs = [f"{n:016x}" for n in range(1, 7)]
    chain = Chain()
    chain.call(refs[0], "approved_elsewhere", where="vault")
    chain.call(refs[1], "pending", where="vault")
    chain.call(refs[2], where="vault")
    chain.call(refs[3], "decline", where="vault")
    chain.call(refs[4], "pending")  # a relay's detached wait: the gateway may have run it
    chain.call(refs[5])
    steps = recovery_plan(open_refs(chain.records()))
    assert outcomes(steps) == {
        refs[0]: ("unknown", 1),
        refs[1]: ("unknown", 1),
        refs[2]: ("unknown", 1),
        refs[3]: ("not_sent", 0),
        refs[4]: ("unknown", 1),
        refs[5]: ("not_sent", 0),
    }
    abandoned = {"decision": "abandoned", "waited_ms": 0}
    assert decided(steps) == [(refs[2], abandoned), (refs[5], abandoned)]
    assert steps[-1].fields == {"abandoned": 2, "not_sent": 2, "unknown": 4}
    assert all(s.fields["detail"] == "restart" for s in steps if s.kind == "outcome")


def test_the_vault_chain_closes_a_hold_with_no_life_after_a_restart() -> None:
    """M8 design J.1: a vault ``asked`` with no decision, held or relayed, closes ``decided
    abandoned`` via ``none``, then ``not_sent``; a vault ``accept`` closes ``unknown``."""
    refs = [f"{n:016x}" for n in range(1, 4)]
    chain = Chain("vault")
    chain.call(refs[0], where="vault")
    chain.call(refs[1])  # a relay
    chain.call(refs[2], "accept", where="vault")
    steps = recovery_plan(open_refs(chain.records()))
    assert outcomes(steps) == {
        refs[0]: ("not_sent", 0),
        refs[1]: ("not_sent", 0),
        refs[2]: ("unknown", 1),
    }
    abandoned = {"decision": "abandoned", "waited_ms": 0, "via": "none"}
    assert decided(steps) == [(refs[0], abandoned), (refs[1], abandoned)]


def test_a_ref_with_no_asked_record_still_closes() -> None:
    """recovery_plan takes any open refs, not only open_refs': with no ``asked`` record it plans
    no writes, adds no via and reads no where."""
    accepted = encode("decided", seq=0, prev=GENESIS, ts=1, ref=REF, decision="accept", waited_ms=0)
    assert outcomes(recovery_plan({REF: [parse(accepted)]})) == {REF: ("unknown", 0)}
    pending = vault_decided(decision="pending", waited_ms=0, via="none")
    assert outcomes(recovery_plan({REF: [parse(pending)]})) == {REF: ("unknown", 0)}
    steps = recovery_plan({REF: []})
    assert decided(steps) == [(REF, {"decision": "abandoned", "waited_ms": 0})]
    assert outcomes(steps) == {REF: ("not_sent", 0)}


_decisions = st.sampled_from(sorted(DECISIONS))
_writers = st.sampled_from(["gateway", "vault"])
_MAY_HAVE_RUN = {"accept", "approved_elsewhere", "pending"}


@settings(max_examples=100, deadline=None)
@given(_writers, st.lists(st.tuples(_writers, st.none() | _decisions, st.booleans()), max_size=12))
def test_recovery_is_deterministic_and_complete(
    writer: str, calls: list[tuple[str, str | None, bool]]
) -> None:
    chain = Chain(writer)
    expected: dict[str | None, str] = {}
    for index, (where, decision, closed) in enumerate(calls):
        ref = f"{index:016x}"
        chain.call(ref, decision, OUTCOME if closed and decision else None, where=where)
        if not (closed and decision):
            unknown = decision in _MAY_HAVE_RUN or (
                decision is None and writer == "gateway" and where == "vault"
            )
            expected[ref] = "unknown" if unknown else "not_sent"
    before = open_refs(chain.records())
    steps = recovery_plan(before)
    assert steps == recovery_plan(open_refs(chain.records()))
    found = [s.ref or "" for s in steps if s.kind == "outcome"]
    assert sorted(found) == sorted(before)  # exactly one outcome per open ref
    assert {ref: result for ref, (result, _) in outcomes(steps).items()} == expected
    for step in steps:
        chain.add(step.kind, step.ref, **step.fields)  # the writer's own format takes each step
    assert open_refs(chain.records()) == {}
