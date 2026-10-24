"""Drafts: a managed review save held between the review screen and its step-up (M6 design G.4,
J.3; step 15a). Pure.

One draft per session, replaced by the next, live for 300 s, in memory only, and never logged;
another session's, an expired or an unknown one is None (``draft_unknown``). What a draft keeps
of its report is the planner's evidence (G.5), read the same at prepare and at confirm (Y8):
``facts`` refuses, as ``reviewchange.definitions`` does, an ``allow`` the review can't stand
behind.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from tests.unit.test_review import pin
from tests.unit.test_review_toolkits import reviewed as toolkit_reviewed
from tests.unit.test_reviewchange import (
    NEW_A,
    NEW_B,
    OLD_B,
    C,
    D,
    drifting,
    key,
    lines_of,
    op_of,
    pin_of,
)
from tests.unit.test_reviewview import held
from zoeymcp.common import logs
from zoeymcp.common.policy.change import Comment, PolicyChange, SetServerReview
from zoeymcp.common.policy.reviewchange import AllowRefused, Changes, fragment
from zoeymcp.common.policy.schema import Tools
from zoeymcp.portal import drafts
from zoeymcp.portal.drafts import (
    DRAFT_TTL,
    MAX_DRAFTS_PER_SESSION,
    Draft,
    Drafts,
    Facts,
    answer,
    facts,
    the_review,
)

T0 = 1_000.0
CHANGE = PolicyChange("t", (SetServerReview("notes", Tools(), {}),))


def scripted(*chunks: bytes) -> Any:
    found = list(chunks)

    def random(size: int) -> bytes:
        chunk = found.pop(0)
        assert len(chunk) == size
        return chunk

    return random


def hold(table: Drafts, session: str = "s1", now: float = T0, **more: Any) -> Draft:
    fields: dict[str, Any] = {
        "base": 4,
        "change": CHANGE,
        "job": "job-1",
        "report_digest": "sha256:" + "0" * 64,
        "kind": "policy.save",
        "facts": Facts(),
        **more,
    }
    return table.hold(session=session, now=now, **fields)


def test_the_constants_are_the_designs() -> None:
    assert (DRAFT_TTL, MAX_DRAFTS_PER_SESSION) == (300.0, 1)


def test_a_draft_is_held_by_its_session_until_it_expires() -> None:
    table = Drafts(scripted(b"\x11" * 16))
    draft = hold(table)
    assert (draft.id, draft.session, draft.base, draft.expires) == ("11" * 16, "s1", 4, T0 + 300)
    assert (draft.kind, draft.job, draft.change) == ("policy.save", "job-1", CHANGE)
    assert table.get(draft.id, session="s1", now=T0 + 299.5) == draft
    assert table.get(draft.id, session="s1", now=T0 + 300) is None
    assert len(table) == 1  # an expired one stays until it is swept or replaced


@pytest.mark.parametrize(("wanted", "session"), [("11" * 16, "s2"), ("22" * 16, "s1"), ("", "s1")])
def test_another_sessions_or_an_unknown_draft_is_none(wanted: str, session: str) -> None:
    table = Drafts(scripted(b"\x11" * 16))
    hold(table)
    assert table.get(wanted, session=session, now=T0) is None
    assert len(table) == 1


def test_one_per_session_the_next_replaces_it() -> None:
    table = Drafts(scripted(b"\x11" * 16, b"\x22" * 16, b"\x33" * 16))
    first = hold(table)
    other = hold(table, "s2")
    second = hold(table, kind="tool.repin")
    assert len(table) == 2
    assert table.get(first.id, session="s1", now=T0) is None
    assert table.get(second.id, session="s1", now=T0) == second
    assert table.get(other.id, session="s2", now=T0) == other


def test_drop_sweep_and_an_ended_session() -> None:
    table = Drafts(scripted(b"\x11" * 16, b"\x22" * 16, b"\x33" * 16))
    first = hold(table)
    late = hold(table, "s2", now=T0 + 100)
    table.drop("nope", session="s1")
    table.drop(first.id, session="s2")
    assert len(table) == 2
    table.drop(first.id, session="s1")
    assert table.get(first.id, session="s1", now=T0) is None
    third = hold(table, "s3")
    table.sweep(T0 + 300)
    assert table.get(third.id, session="s3", now=T0) is None
    assert table.get(late.id, session="s2", now=T0 + 399) == late
    table.drop_session("s2")
    table.drop_session("s9")
    assert len(table) == 0


def test_a_draft_is_never_logged() -> None:
    draft = hold(Drafts(scripted(b"\x11" * 16)))
    assert repr(draft) == f"Draft(kind=policy.save, base=4, expires={T0 + 300})"
    assert "notes" not in repr(draft)
    assert Draft in logs.refused_types()


def test_the_answer() -> None:
    draft = hold(Drafts(scripted(b"\x11" * 16)), kind="tool.allow")
    summary = [["Revision", "5, from 4"]]
    assert answer(draft, summary) == {
        "draft": "11" * 16,
        "base": 4,
        "kind": "tool.allow",
        "summary": summary,
    }


def test_the_review_a_change_holds() -> None:
    op = SetServerReview("notes", Tools(), {})
    assert the_review(PolicyChange("t", (Comment("added", "x", "y"), op))) is op
    assert the_review(PolicyChange("t", (Comment("added", "x", "y"),))) is None


# --- the evidence (G.5, J.3) ---------------------------------------------------------------------


def test_the_facts_a_review_save_rests_on() -> None:
    """``a`` re-pinned and kept allow, ``b`` moved to allow at its old pin: verified are the pins
    the report lists (``a``'s new one, ``c``'s and ``m``'s), drifted ``a`` and ``b``, a
    definition each for ``a`` (the new one) and ``b`` (the reviewed one), the suggestion only
    for the re-pinned ``a``, and ``m`` marked."""
    report = drifting()
    op = op_of(fragment(report, Changes(moved={"b": "allow"}, repin=frozenset({"a"}))))
    found = facts(report, op)
    assert found == Facts(
        verified=frozenset(
            {(key("a"), pin_of(NEW_A)), (key("c"), pin_of(C)), (key("m"), pin("m"))}
        ),
        drifted=frozenset({key("a"), key("b")}),
        definitions={key("a"): lines_of(NEW_A), key("b"): lines_of(OLD_B)},
        suggested={key("a"): "approve"},
        consequential=frozenset(),
        marked=frozenset({key("m")}),
    )


def test_a_repinned_tools_suggestion_is_its_new_definitions() -> None:
    report = drifting()
    op = op_of(fragment(report, Changes(repin=frozenset({"b"}))))
    found = facts(report, op)
    assert not isinstance(found, AllowRefused)
    assert found.suggested == {key("b"): None}
    assert found.verified >= {(key("b"), pin_of(NEW_B))}
    assert pin_of(D) not in {p for _, p in found.verified}


def test_facts_refuse_what_definitions_refuse() -> None:
    report = drifting(kept=False)
    moved = op_of(fragment(report, Changes(moved={"b": "allow"})))
    assert facts(report, moved) == AllowRefused("allow_needs_review", "b")
    marked = op_of(fragment(drifting(), Changes(moved={"m": "allow"})))
    assert facts(drifting(), marked) == AllowRefused("allow_marked", "m")


def test_a_toolkits_consequential_tools(tmp_path: Path, example_raw: dict[str, Any]) -> None:
    report = held(toolkit_reviewed(tmp_path, example_raw))
    found = facts(report, op_of(fragment(report, Changes())))
    assert not isinstance(found, AllowRefused)
    assert found.consequential == frozenset({("mail", "tool", "send_note")})
    assert drafts.Facts().definitions == {}
