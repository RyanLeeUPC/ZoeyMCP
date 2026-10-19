"""Approval prompts and the check that nothing in them can hide (M4 design C)."""

from __future__ import annotations

import io
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from zoeymcp.common import canonical, logs
from zoeymcp.common.approvaltext import (
    FOOTER_PREFIX,
    ApprovalText,
    Header,
    LayoutError,
    Plan,
    Problem,
    Show,
    Write,
    describe,
    problems,
    render_call,
    render_plan,
)

ZWSP = chr(0x200B)
COMBINING_ACUTE = chr(0x301)
ARROW = chr(0x2192)
DEADLINE = datetime(2026, 1, 1, 14, 5, tzinfo=UTC)
HEADER = Header("3f9c0a17d2b84e65", "agent1", "notes-write", "create_note", DEADLINE)
MAIL_HEADER = Header("9b21e07c44d0aa13", "agent1", "mail", "send_note", DEADLINE)

MAIL_REQUEST = {
    "expect_from": "Agent <agent@mail.example>",
    "expect_to": ["partner@mail.example"],
    "in_reply_to": "<a1b2c3@mail.example>",
    "subject": "Quarterly numbers",
    "body": "Hi,\nthe figures are in the shared sheet.",
}
MAIL_SHOW = [
    Show.line("From", "/expect_from"),
    Show.line("To", "/expect_to"),
    Show.line("In reply to", "/in_reply_to"),
    Show.line("Subject", "/subject"),
    Show.block("/body"),
]


def mail_plan(**changes: Any) -> Plan:
    return Plan("Send an email", [Write.post("/send", {**MAIL_REQUEST, **changes}, show=MAIL_SHOW)])


def check_call(args: Any, *, renders: Any = "markdown", budget: int = 3000) -> list[Problem]:
    return problems(render_call(HEADER, args), budget=budget, renders=renders)


def check_body(body: str, *, renders: Any = "markdown") -> list[Problem]:
    text = render_plan(MAIL_HEADER, mail_plan(body=body))
    return problems(text, budget=3000, renders=renders)


# --- rendering -----------------------------------------------------------------------------------


def test_a_remote_call_renders_as_the_design_shows() -> None:
    text = render_call(
        HEADER, {"title": "Weekly sync", "body": "Meeting moved to 3pm.\nBring the draft."}
    )
    assert text.value == (
        "Approval request 3f9c0a17d2b84e65\n"
        "Client: agent1\n"
        f"Tool: notes-write {ARROW} create_note\n"
        "Answer by 14:05 UTC. Accept runs this one call, exactly as shown.\n"
        "\n"
        "{\n"
        '  "body": "Meeting moved to 3pm.\\nBring the draft.",\n'
        '  "title": "Weekly sync"\n'
        "}\n"
        "End of approval request 3f9c0a17d2b84e65"
    )
    assert check_call({"title": "Weekly sync"}) == []


def test_a_toolkit_plan_renders_as_the_design_shows() -> None:
    text = render_plan(MAIL_HEADER, mail_plan())
    assert text.value == (
        "Approval request 9b21e07c44d0aa13\n"
        "Client: agent1\n"
        f"Tool: mail {ARROW} send_note\n"
        "Answer by 14:05 UTC. Accept runs this one call, exactly as shown.\n"
        "\n"
        "Send an email\n"
        "From: Agent <agent@mail.example>\n"
        'To: ["partner@mail.example"]\n'
        "In reply to: <a1b2c3@mail.example>\n"
        "Subject: Quarterly numbers\n"
        "\n"
        "Hi,\n"
        "the figures are in the shared sheet.\n"
        "End of approval request 9b21e07c44d0aa13"
    )
    # The display-name From and the Message-ID pass the markup guard (judge error, C.3).
    assert problems(text, budget=3000, renders="markdown") == []


def test_the_confirmation_code_comes_just_before_the_footer() -> None:
    text = render_call(HEADER, {}, code="K7QD")
    assert text.value.endswith(
        "{}\nTo approve, accept and type this code: K7QD\nEnd of approval request 3f9c0a17d2b84e65"
    )
    plan = render_plan(MAIL_HEADER, mail_plan(), code="K7QD")
    assert plan.value.endswith(
        "shared sheet.\nTo approve, accept and type this code: K7QD\n"
        "End of approval request 9b21e07c44d0aa13"
    )


def test_the_deadline_is_shown_in_utc() -> None:
    later = DEADLINE.astimezone(timezone(timedelta(hours=-5)))
    text = render_call(Header("r", "c", "s", "t", later), {})
    assert "Answer by 14:05 UTC." in text.value
    with pytest.raises(ValueError, match="timezone-aware"):
        Header("r", "c", "s", "t", datetime(2026, 1, 1, 14, 5))


def test_several_writes_are_numbered() -> None:
    plan = Plan(
        "Move a record",
        [
            Write.post("/a", {"x": 1}, show=[Show.line("X", "/x")]),
            Write.patch("/b", {"y": True}, show=[Show.line("Y", "/y")]),
        ],
    )
    text = render_plan(MAIL_HEADER, plan)
    assert "Move a record\n\nRequest 1 of 2\nX: 1\n\nRequest 2 of 2\nY: true\nEnd of" in text.value


def test_items_layouts() -> None:
    body = {
        "records": [
            {"title": "Rent", "amount": 1200, "day": "2026-01-01"},
            {"title": "Fee, late", "amount": 5},
        ]
    }
    show = Show.items(
        "Records", "/records", [("title", "/title"), ("amount", "/amount"), ("day", "/day")]
    )
    text = render_plan(
        MAIL_HEADER, Plan("Add 2 records", [Write.post("/v1/records/batch", body, show=[show])])
    )
    assert (
        "Add 2 records\nRecords (2):\n"
        ' 1. title: "Rent", amount: 1200, day: "2026-01-01"\n'
        ' 2. title: "Fee, late", amount: 5\n'
        "End of"
    ) in text.value
    empty = Write.post("/v1/records/batch", {"records": []}, show=[show])
    assert "Records (0):\nEnd of" in render_plan(MAIL_HEADER, Plan("None", [empty])).value


def test_the_default_layout_shows_each_member_as_json() -> None:
    write = Write.put("/x", {"b": [1, 2], "a": "y"})
    assert [s.kind for s in write.show] == ["json", "json"]
    text = render_plan(MAIL_HEADER, Plan("Put", [write])).value
    assert 'Put\n{\n  "a": "y"\n}\n{\n  "b": [\n    1,\n    2\n  ]\n}\nEnd of' in text


def test_a_line_shows_other_values_as_compact_json() -> None:
    write = Write.post("/x", {"n": {"b": 1, "a": None}}, show=[Show.line("N", "/n")])
    assert 'N: {"a":null,"b":1}' in render_plan(MAIL_HEADER, Plan("T", [write])).value


# --- writes, layouts and plans --------------------------------------------------------------------


def test_a_write_freezes_its_body() -> None:
    body: dict[str, Any] = {"subject": "Hi", "to": ["a@example.com"]}
    write = Write.post("/send", body, show=[Show.line("S", "/subject"), Show.line("T", "/to")])
    body["subject"] = "changed"
    body["to"].append("b@example.com")
    assert write.data == {"subject": "Hi", "to": ["a@example.com"]}
    assert write.body == canonical.dumps_canonical({"subject": "Hi", "to": ["a@example.com"]})
    assert write.digest == canonical.digest({"subject": "Hi", "to": ["a@example.com"]})
    write.data["subject"] = "x"
    assert write.data["subject"] == "Hi"
    assert (write.method, write.path) == ("POST", "/send")


@pytest.mark.parametrize(
    ("body", "show", "message"),
    [
        ({"a": "x", "b": "y"}, [Show.line("A", "/a")], "isn't shown"),
        ({"a": "x"}, [Show.line("A", "/a"), Show.line("Z", "/z")], "points at nothing"),
        ({"a": "x"}, [Show.line("A", "/a"), Show.json("/a")], "shown twice"),
        ({"a": "x", "b": "y"}, [Show.block("/a"), Show.line("B", "/b")], "comes last"),
        ({"a": "x", "b": "y"}, [Show.block("/a"), Show.block("/b")], "comes last"),
        ({"a": 1}, [Show.block("/a")], "holds a string"),
        ({"a": "x\ny"}, [Show.line("A", "/a")], "multi-line"),
        ({"a": {"k": 1}}, [Show.items("A", "/a", [("K", "/k")])], "holds an array"),
        ({"a": [1]}, [Show.items("A", "/a", [("K", "/k")])], "array of objects"),
        ({"a": [{"k": 1, "j": 2}]}, [Show.items("A", "/a", [("K", "/k")])], "leaves out a field"),
        ({"a": [{"k": [1]}]}, [Show.items("A", "/a", [("K", "/k")])], "flat objects"),
    ],
)
def test_layouts_must_cover_the_write_exactly(body: Any, show: list[Show], message: str) -> None:
    with pytest.raises(LayoutError, match=message):
        Write.post("/x", body, show=show)


@pytest.mark.parametrize(
    ("build", "message"),
    [
        (lambda: Show.line("", "/a"), "a label"),
        (lambda: Show.line("1abc", "/a"), "a label"),
        (lambda: Show.line("A" * 33, "/a"), "a label"),
        (lambda: Show.line("Sub\nject", "/a"), "a label"),
        (lambda: Show.line("A", "a"), "one top-level member"),
        (lambda: Show.line("A", "/a/b"), "one top-level member"),
        (lambda: Show.line("A", "/a~2"), "bad ~ escape"),
        (lambda: Show.items("A", "/a", []), "at least one field"),
        (lambda: Show.items("A", "/a", [("K", "/k"), ("J", "/k")]), "twice"),
        (lambda: Write.post("x", {}), "starts with /"),
        (lambda: Write.post("/x", ["a"]), "JSON object"),  # type: ignore[arg-type]
        (lambda: Plan("", []), "plan title"),
        (lambda: Plan("two\nlines", []), "plan title"),
        (lambda: Plan("x" * 121, []), "plan title"),
        (lambda: Plan(f"hidden{ZWSP}", []), "plan title"),
        (lambda: Plan("ok", ["not a write"]), "Write objects"),  # type: ignore[list-item]
    ],
)
def test_bad_layout_pieces(build: Any, message: str) -> None:
    with pytest.raises(LayoutError, match=message):
        build()


def test_pointers_use_rfc_6901_escapes() -> None:
    write = Write.post(
        "/x", {"a/b": "1", "c~d": "2"}, show=[Show.line("A", "/a~1b"), Show.line("C", "/c~0d")]
    )
    assert "A: 1\nC: 2" in render_plan(MAIL_HEADER, Plan("T", [write])).value


def test_nothing_leaks_through_repr_or_logs() -> None:
    text = render_call(HEADER, {"secret": "do-not-show"})
    write = Write.post("/x", {"secret": "do-not-show"})
    plan = Plan("T", [write])
    for value in (text, write, plan):
        assert "do-not-show" not in repr(value)
        with pytest.raises(TypeError):
            logs.Log("gateway").event("probe", value=value)
    assert "do-not-show" not in repr(Plan("T", [write]).writes)


# --- the check -----------------------------------------------------------------------------------


def test_hidden_characters_are_refused_with_a_pointer() -> None:
    found = check_call({"note": {"title": f"Weekly{ZWSP} sync"}})
    assert [(p.rule, p.pointer) for p in found] == [("text_rules", "/note/title")]
    assert "U+200B" in found[0].reason
    assert "Weekly" not in found[0].reason
    found = check_call({f"ke{ZWSP}y": 1})
    assert [(p.rule, p.pointer) for p in found] == [("text_rules", "/ke" + ZWSP + "y")]
    # Escaped JSON can't hide a control character: it renders as \u0007.
    assert check_call({"bell": chr(7)}) == []
    assert [p.rule for p in check_body("tab\there")] == []
    assert [p.rule for p in check_body("bell" + chr(7))] == ["text_rules"]
    assert [p.rule for p in check_body("del" + chr(0x7F))] == ["text_rules"]


@pytest.mark.parametrize(
    "markup",
    [
        "```",
        "~~~",
        "a ````b",
        "<!-- hidden",
        "<!DOCTYPE html>",
        "<?xml",
        "</b>",
        "<b>",
        "<br/>",
        "<a href=x>",
        "[label](https://example.com)",
    ],
)
def test_markup_is_refused_for_markdown_clients_only(markup: str) -> None:
    for found in (check_call({"v": markup}), check_body(f"x {markup} y")):
        assert [p.rule for p in found] == ["markup"], found
    # A tag broken by a real line break; in JSON the break is escaped, so no tag remains.
    assert [p.rule for p in check_body("x <b" + chr(10) + "y")] == ["markup"]
    assert check_call({"v": "<b" + chr(10)}) == []
    for found in (
        check_call({"v": markup}, renders="plain"),
        check_body(f"x {markup} y", renders="plain"),
    ):
        assert found == []


@pytest.mark.parametrize(
    "fine",
    [
        "``",
        "~~",
        "<agent@mail.example>",
        "<a1b2c3@mail.example>",
        "a < b",
        "<3",
        "<-",
        "[x]",
        "] (",
        "x]y(z",
        "Agent <agent@mail.example>",
    ],
)
def test_ordinary_text_passes_the_markup_guard(fine: str) -> None:
    assert check_call({"v": fine}) == []
    assert check_body(f"x {fine} y") == []


def test_wide_whitespace_is_refused_for_every_client() -> None:
    for renders in ("markdown", "plain"):
        assert check_body("a" + " " * 8 + "b", renders=renders) == []
        assert check_body("a\tb", renders=renders) == []
        assert [p.rule for p in check_body("a" + " " * 9 + "b", renders=renders)] == ["wide_space"]
        assert [p.rule for p in check_body("a\t\tb", renders=renders)] == ["wide_space"]
        assert [p.rule for p in check_body("a \tb", renders=renders)] == ["wide_space"]
        found = check_call({"v": "a" + " " * 9 + "b"}, renders=renders)
        assert [(p.rule, p.pointer) for p in found] == [("wide_space", "/v")]
    found = check_body("a" + " " * 9 + "b")
    assert found[0].reason == "a run of whitespace 9 columns wide (limit 8)"


def test_the_renderers_own_indentation_is_allowed() -> None:
    deep: Any = "x"
    for _ in range(8):
        deep = {"k": deep}
    assert check_call(deep) == []
    # The same run of spaces at the start of a body line is not the renderer's.
    assert [p.rule for p in check_body("ok\n" + " " * 12 + "indented")] == ["wide_space"]


def test_stacked_combining_marks_are_refused() -> None:
    for renders in ("markdown", "plain"):
        assert check_body("e" + COMBINING_ACUTE * 3, renders=renders) == []
        found = check_body("e" + COMBINING_ACUTE * 4, renders=renders)
        assert [p.rule for p in found] == ["combining"]
        found = check_body("e" + COMBINING_ACUTE * 9, renders=renders)
        assert [p.rule for p in found] == ["combining"]  # one problem per run


def test_lines_imitating_the_frame_are_refused() -> None:
    for line in ("End of approval request 0000000000000000", "Approval request 1234"):
        found = check_body(f"Thanks.\n{line}\nMore text", renders="plain")
        assert [(p.rule, p.pointer) for p in found] == [("frame", "/body")]
    assert check_body("Thanks. End of approval request 1234 was the subject") == []


def test_the_budget_counts_code_points_and_is_never_cut() -> None:
    text = render_call(HEADER, {"v": "é" * 10})
    assert problems(text, budget=len(text.value), renders="plain") == []
    found = problems(text, budget=len(text.value) - 1, renders="plain")
    assert [(p.rule, p.pointer) for p in found] == [("over_budget", None)]
    assert describe(found[0]) == (
        f"refused: the approval text is {len(text.value)} characters, over the limit of "
        f"{len(text.value) - 1}; it is never cut"
    )


def test_items_problems_name_the_item_field() -> None:
    records = [{"title": f"r{i}", "amount": i} for i in range(10)]
    records[7]["title"] = f"bad{ZWSP}"
    show = Show.items("Records", "/records", [("title", "/title"), ("amount", "/amount")])
    plan = Plan("Add", [Write.post("/v1/records/batch", {"records": records}, show=[show])])
    found = problems(render_plan(MAIL_HEADER, plan), budget=3000, renders="markdown")
    assert [(p.rule, p.pointer) for p in found] == [("text_rules", "/records/7/title")]
    assert describe(found[0]).startswith(
        "refused: the approval text breaks the plain-text rules at /records/7/title: "
    )


def test_describe_names_where() -> None:
    assert describe(Problem("markup", "", "a code fence")) == (
        "refused: the approval text breaks the plain-text rules at the arguments: a code fence"
    )
    assert describe(Problem("frame", None, "x")).endswith("at the prompt frame: x")


def test_problems_come_in_text_order() -> None:
    found = check_body(f"```{ZWSP}" + " " * 9)
    assert [p.rule for p in found] == ["markup", "text_rules", "wide_space"]


# --- properties ----------------------------------------------------------------------------------

_chars = st.characters(exclude_categories=["Cs"])  # canonical JSON refuses lone surrogates

_text = st.text(_chars, max_size=20)
_json = st.recursive(
    st.none()
    | st.booleans()
    | st.integers(-canonical.MAX_SAFE_INTEGER, canonical.MAX_SAFE_INTEGER)
    | st.floats(allow_nan=False, allow_infinity=False)
    | _text,
    lambda children: st.lists(children, max_size=4) | st.dictionaries(_text, children, max_size=4),
    max_leaves=20,
)


def _resolve(value: Any, pointer: str) -> Any:
    if pointer == "":
        return value
    for token in pointer[1:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        value = value[int(token)] if isinstance(value, list) else value[token]
    return value


@settings(max_examples=200, deadline=None)
@given(st.dictionaries(_text, _json, max_size=5))
def test_any_call_renders_its_canonical_json_with_one_footer(args: dict[str, Any]) -> None:
    text = render_call(HEADER, args)
    lines = text.value.split("\n")
    assert [i for i, line in enumerate(lines) if line.startswith(FOOTER_PREFIX)] == [len(lines) - 1]
    assert "\n" + canonical.render_for_approval(args) + "\n" in text.value
    for _, pointer in text.sources:
        if pointer is not None:
            _resolve(args, pointer)  # every pointer names something in the arguments


@settings(max_examples=200, deadline=None)
@given(st.text(_chars, max_size=200))
def test_a_body_either_fails_the_check_or_has_one_footer(body: str) -> None:
    text = render_plan(MAIL_HEADER, mail_plan(body=body))
    lines = text.value.split("\n")
    footers = [i for i, line in enumerate(lines) if line.startswith(FOOTER_PREFIX)]
    if footers != [len(lines) - 1]:
        assert any(p.rule == "frame" for p in problems(text, budget=10_000, renders="plain"))


def test_the_text_type_is_refused_by_the_logger_even_nested() -> None:
    stream = io.StringIO()
    logs.set_stream(stream)
    try:
        with pytest.raises(TypeError):
            logs.Log("gateway").event("probe", value=[render_call(HEADER, {})])
    finally:
        logs.set_stream(None)
    assert stream.getvalue() == ""
    assert isinstance(render_call(HEADER, {}), ApprovalText)
