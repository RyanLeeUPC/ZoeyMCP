"""The change a review makes (M6 design J.3, O.3; Q8, Q27): re-pin, the allow proposal and a kept
``allow``, declines, and a definition recorded for every name classified ``allow`` at a
(classification, pin) the policy doesn't hold, with ``allow_needs_review``, ``allow_marked`` and
``consequential_allow`` each refused by name.

The reports come from the gateway's own review code (``tests/unit/test_review.py``'s helpers), held
as the vault holds them; the CLI's snippet cases stay in ``test_review.py`` and
``test_review_choices.py``, which reach this module through ``cli/review.py``.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

from mcp.types import Tool

from tests.unit.test_review import pin, reviewed, tool, wire
from tests.unit.test_review_toolkits import reviewed as toolkit_reviewed
from tests.unit.test_reviewview import held
from zoeymcp.common.policy.change import PolicyChange, SetServerReview
from zoeymcp.common.policy.emit import emit
from zoeymcp.common.policy.reviewchange import (
    CHUNK,
    MOVED_TO_ALLOW,
    PROPOSED,
    AllowRefused,
    Changes,
    Choices,
    definition_lines,
    definitions,
    fragment,
    planned,
    proposed,
    the_rest,
    verified,
)
from zoeymcp.common.policy.view import ViewRemoteServer
from zoeymcp.gateway import pins

READ_ONLY = {"readOnlyHint": True}
WRITES = {"readOnlyHint": False, "destructiveHint": True}


def hinted(name: str, description: str, hints: dict[str, bool]) -> Tool:
    return Tool.model_validate({**wire(name, description), "annotations": hints})


def pin_of(found: Tool) -> str:
    return pins.project_and_pin(found).pin


def server(allow: list[str], approve: list[str], review: dict[str, str]) -> ViewRemoteServer:
    return ViewRemoteServer.model_validate(
        {
            "kind": "remote",
            "vault_path": "/notes/mcp",
            "tools": {"include": [*allow, *approve], "allow": allow, "approve": approve},
            "review": review,
            "on_drift": "hide",
            "shared_session": False,
            "wrap_results": False,
            "enable": [],
            "era": "auto",
            "drift_check_interval": 300,
            "call_timeout": None,
        }
    )


# notes includes ``a`` (allow, marked read-only), ``b`` and ``m`` (approve) and ``c`` (allow);
# ``a`` drifted to a definition that isn't read-only, ``b`` to a new description, ``m`` is marked
# (it flipped back), and ``d`` (read-only) and ``e`` are listed and not included.
OLD_A = hinted("a", "Reads a thing.", READ_ONLY)
NEW_A = hinted("a", "Reads a thing.", WRITES)
OLD_B, NEW_B = tool("b"), tool("b", "Does another thing.")
C = hinted("c", "Reads c.", READ_ONLY)
D = hinted("d", "Reads d.", READ_ONLY)


def drifting(*, kept: bool = True) -> dict[str, Any]:
    """The held report; without ``kept``, the gateway no longer holds the reviewed copies."""
    pins_ = {"a": pin_of(OLD_A), "b": pin_of(OLD_B), "c": pin_of(C), "m": pin("m")}
    policy = server(["a", "c"], ["b", "m"], pins_)
    defs = {}
    if kept:
        defs = {pin_of(OLD_A): definition(OLD_A), pin_of(OLD_B): definition(OLD_B)}
    listed = [NEW_A, NEW_B, C, tool("m"), D, tool("e")]
    return held(reviewed(listed, policy, marks=frozenset({("m", pin("m"))}), defs=defs))


def definition(found: Tool) -> dict[str, Any]:
    return dict(pins.project_and_pin(found).definition)


def entry(report: dict[str, Any], name: str) -> dict[str, Any]:
    found: dict[str, Any] = next(e for e in report["tools"] if e["name"] == name)
    return found


def op_of(change: PolicyChange) -> SetServerReview:
    [op] = [op for op in change.ops if isinstance(op, SetServerReview)]
    return op


def lines_of(found: Tool) -> tuple[tuple[str, ...], ...]:
    return tuple(tuple(chunks) for chunks in definition_lines(definition(found)))


def key(name: str) -> tuple[str, str, str]:
    return ("notes", "tool", name)


def test_the_states_the_report_shows() -> None:
    report = drifting()
    states = {e["name"]: e["state"] for e in report["tools"]}
    assert states == {
        "a": "drift",
        "b": "drift",
        "c": "ok",
        "m": "marked",
        "d": "unreviewed",
        "e": "unreviewed",
    }
    assert entry(report, "a")["reviewed"] == definition(OLD_A)
    assert "reviewed" not in entry(drifting(kept=False), "a")


def test_the_constants() -> None:
    assert CHUNK == 200
    assert PROPOSED == "the new definition isn't marked read-only: proposed approve"
    assert MOVED_TO_ALLOW == "approve -> allow: calls to {name} will run with no prompt"


# --- approve -> allow (J3, declarative; COV-3) ---------------------------------------------------


def test_a_move_from_approve_to_allow_says_what_it_allows() -> None:
    """Allow without asking in declarative mode: an included approve tool moved to allow gets
    the sentence as a comment, ahead of the other changes; a move to approve, or a tool
    already in allow, gets none, and a dropped tool isn't a move."""
    report = drifting()
    moved = emit(fragment(report, Changes(moved={"m": "allow", "b": "allow"})))
    lines = moved.splitlines()
    said = [line for line in lines if "will run with no prompt" in line]
    assert said == [
        "# changed: b (approve -> allow: calls to b will run with no prompt)",
        "# changed: m (approve -> allow: calls to m will run with no prompt)",
    ]
    assert lines.index(said[1]) < lines.index(next(x for x in lines if x.startswith("# kept: ")))
    assert sorted(op_of(fragment(report, Changes(moved={"m": "allow"}))).tools.allow) == [
        "a",
        "c",
        "m",
    ]
    for changes in (
        Changes(moved={"a": "approve"}),
        Changes(moved={"c": "allow"}),
        Changes(moved={"m": "allow"}, dropped=frozenset({"m"})),
    ):
        assert "will run with no prompt" not in emit(fragment(report, changes)), changes


# --- re-pin (J.3, Q8 (a)) ------------------------------------------------------------------------


def test_a_drifted_tool_keeps_its_pin_unless_it_is_repinned() -> None:
    report = drifting()
    kept = op_of(fragment(report, Changes()))
    assert (kept.review["a"], kept.review["b"]) == (pin_of(OLD_A), pin_of(OLD_B))
    taken = fragment(report, Changes(repin=frozenset({"b"})))
    op = op_of(taken)
    assert op.review["b"] == pin_of(NEW_B) == entry(report, "b")["pin"]
    assert op.review["a"] == pin_of(OLD_A)
    # The classification stays (Q8 (a)): b is approve before and after.
    assert (list(op.tools.allow), list(op.tools.approve)) == (["a", "c"], ["b", "m"])
    text = emit(taken)
    assert f"# changed: b (was {pin_of(OLD_B)})" in text
    assert "# kept: a (drift: the server lists" in text
    assert "# kept: b" not in text


def test_verified_names_every_pin_written_from_the_report() -> None:
    """A re-pin's new pin and a new include's pin are the report's (the vault recomputed both,
    X11); a pin kept for a drifted tool isn't one the report verified."""
    report = drifting()
    op = op_of(fragment(report, Changes(repin=frozenset({"b"}))))
    assert verified(report, op) == frozenset(
        {
            (key("b"), pin_of(NEW_B)),
            (key("c"), pin_of(C)),
            (key("m"), pin("m")),
        }
    )
    planned_ = planned(report, Choices(allow=("d",), repin=frozenset({"a"})))
    op = op_of(fragment(report, planned_))
    assert (key("d"), pin_of(D)) in verified(report, op)
    assert (key("a"), pin_of(NEW_A)) in verified(report, op)
    assert not any(name == key("b") for name, _ in verified(report, op))


def test_a_repinned_allow_tool_no_longer_read_only_is_proposed_approve() -> None:
    """Q8 (a): ``a``'s new definition isn't marked read-only, so a re-pin proposes approve; kept
    allow, the fragment says so in a comment, and chosen approve, it says nothing more."""
    report = drifting()
    assert proposed(entry(report, "a"))
    assert not proposed(entry(report, "b"))  # approve already
    assert not proposed(entry(report, "c"))  # not drifted
    read_only = {**entry(report, "a"), "definition": definition(OLD_A)}
    assert not proposed(read_only)  # a new definition still read-only keeps allow unasked
    writes = {**entry(report, "c"), "definition": definition(hinted("c", "Reads c.", WRITES))}
    assert not proposed(writes)  # an allow tool that didn't drift isn't asked about
    kept = emit(fragment(report, Changes(repin=frozenset({"a"}))))
    assert f"# kept: a (allow: {PROPOSED})" in kept
    moved = fragment(report, Changes(repin=frozenset({"a"}), moved={"a": "approve"}))
    assert "# kept: a (allow" not in emit(moved)
    assert "a" in op_of(moved).tools.approve


# --- declines (J.3, J.5) -------------------------------------------------------------------------


def test_the_rest_is_every_listed_pinnable_tool_left_out() -> None:
    report = drifting()
    assert the_rest(report, ["a", "b", "c", "m"]) == {"d": pin_of(D), "e": pin("e")}
    assert the_rest(report, ["a", "b", "c", "m", "d"]) == {"e": pin("e")}
    made = planned(report, Choices(decline_rest=True, allow=("d",)))
    assert made.declined == {"e": pin("e")}
    assert planned(report, Choices()).declined is None  # M7's snippet when nothing is declined


# --- definitions for every new allow (J.3, Q27) --------------------------------------------------


def test_a_kept_allow_records_the_new_definition() -> None:
    report = drifting()
    op = op_of(fragment(report, Changes(repin=frozenset({"a"}))))
    assert definitions(report, op) == {key("a"): lines_of(NEW_A)}


def test_moves_and_new_includes_record_the_definition_at_the_pin_written() -> None:
    """``b`` moved to allow without a re-pin keeps its old pin, so its reviewed definition is the
    one recorded; re-pinned, the listed one; ``d`` included as allow (a fresh include or a
    re-include: the report can't tell) records the listed one; ``c``, allow at its pin already,
    records nothing."""
    report = drifting()
    moved = op_of(fragment(report, Changes(moved={"b": "allow"})))
    assert definitions(report, moved) == {key("b"): lines_of(OLD_B)}
    repinned = Changes(moved={"b": "allow"}, repin=frozenset({"b"}))
    assert definitions(report, op_of(fragment(report, repinned))) == {key("b"): lines_of(NEW_B)}
    included = op_of(fragment(report, planned(report, Choices(allow=("d",)))))
    assert definitions(report, included) == {key("d"): lines_of(D)}
    assert definitions(report, op_of(fragment(report, Changes()))) == {}


def test_allow_needs_review_without_the_reviewed_copy() -> None:
    report = drifting(kept=False)
    moved = op_of(fragment(report, Changes(moved={"b": "allow"})))
    assert definitions(report, moved) == AllowRefused("allow_needs_review", "b")
    repinned = Changes(moved={"b": "allow"}, repin=frozenset({"b"}))
    assert definitions(report, op_of(fragment(report, repinned))) == {key("b"): lines_of(NEW_B)}


def test_a_name_the_server_no_longer_lists_needs_review() -> None:
    report = drifting()
    report["tools"] = [e for e in report["tools"] if e["name"] != "b"]
    moved = op_of(fragment(report, Changes(moved={"b": "allow"})))
    assert definitions(report, moved) == AllowRefused("allow_needs_review", "b")


def test_a_marked_tool_isnt_moved_to_allow() -> None:
    report = drifting()
    moved = op_of(fragment(report, Changes(moved={"m": "allow"})))
    assert definitions(report, moved) == AllowRefused("allow_marked", "m")


def test_the_first_refusal_by_name() -> None:
    report = drifting(kept=False)
    both = op_of(fragment(report, Changes(moved={"m": "allow", "b": "allow"})))
    assert definitions(report, both) == AllowRefused("allow_needs_review", "b")


def test_a_consequential_tool_isnt_moved_to_allow(
    tmp_path: Path, example_raw: dict[str, Any]
) -> None:
    report = held(toolkit_reviewed(tmp_path, example_raw))
    assert entry(report, "send_note")["consequential"] is True
    moved = op_of(fragment(report, Changes(moved={"send_note": "allow"})))
    assert definitions(report, moved) == AllowRefused("consequential_allow", "send_note")


def test_pinning_off_records_the_listed_definition(
    tmp_path: Path, example_raw: dict[str, Any]
) -> None:
    """A ``pinning: off`` toolkit has no pin to write, so a move records the listed definition;
    a tool it classifies allow already records nothing (Q27-6)."""
    raw = copy.deepcopy(example_raw)
    raw["gateway"]["servers"]["mail"].update(pinning="off", review={})
    report = held(toolkit_reviewed(tmp_path, raw))
    send = entry(report, "send_note")
    send["consequential"] = False  # a routine tool, as another toolkit's could be
    moved = op_of(fragment(report, Changes(moved={"send_note": "allow"})))
    assert dict(moved.review) == {}
    lines = tuple(tuple(chunks) for chunks in definition_lines(send["definition"]))
    assert definitions(report, moved) == {("mail", "tool", "send_note"): lines}
    report["policy"]["allow"] = ["send_note"]
    assert definitions(report, moved) == {}


def test_a_definition_in_chunks_with_nothing_cut() -> None:
    long = "x" * (CHUNK * 2 + 5)
    lines = definition_lines({"d": long})
    assert ["".join(chunks) for chunks in lines] == ["{", f'  "d": "{long}"', "}"]
    assert [len(chunk) for chunk in lines[1]] == [CHUNK, CHUNK, len(f'  "d": "{long}"') - 400]
    assert definition_lines({}) == [["{}"]]
