"""Approval prompts and the check that nothing in them can hide (M4 design C; M8 design E.5)."""

from __future__ import annotations

import dataclasses
import io
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from tests.unit.plainid import plain_id
from zoeymcp.common import canonical, logs
from zoeymcp.common.approvaltext import (
    FOOTER_PREFIX,
    INSTRUCTIONS,
    MAX_RECEIVED_INDENT,
    RELAY_LINE,
    ApprovalText,
    Header,
    LayoutError,
    Plan,
    Problem,
    Show,
    Write,
    describe,
    problems,
    received,
    relayed,
    render_call,
    render_plan,
)

ZWSP = chr(0x200B)
COMBINING_ACUTE = chr(0x301)
ARROW = chr(0x2192)
ELLIPSIS = chr(0x2026)
DEADLINE = datetime(2026, 1, 1, 14, 5, tzinfo=UTC)
ASKED_AT = datetime(2026, 1, 1, 14, 0, tzinfo=UTC)
PIN = "sha256:3f1c" + "0" * 58 + "e2"
# The gateway's own frame for an elicitation, as gateway/approve.py makes it.
GATEWAY: dict[str, Any] = {
    "asked_at": ASKED_AT,
    "rendered_by": "gateway",
    "client_reported": False,
    "pin": None,
    "approver": "elicitation",
}
# The vault's frame for a call it holds, its client reported by the gateway's marker (B.3).
VAULT: dict[str, Any] = {
    **GATEWAY,
    "rendered_by": "vault",
    "client_reported": True,
    "pin": PIN,
    "approver": "out_of_band",
}
HEADER = Header("3f9c0a17d2b84e65", "agent1", "notes-write", "create_note", DEADLINE, **GATEWAY)
MAIL_HEADER = Header("9b21e07c44d0aa13", "agent1", "mail", "send_note", DEADLINE, **GATEWAY)

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
    text = render_call(Header("r", "c", "s", "t", later, **GATEWAY), {})
    assert "Answer by 14:05 UTC." in text.value
    with pytest.raises(ValueError, match="timezone-aware"):
        Header("r", "c", "s", "t", datetime(2026, 1, 1, 14, 5), **GATEWAY)
    with pytest.raises(ValueError, match="timezone-aware"):
        Header("r", "c", "s", "t", DEADLINE, **{**GATEWAY, "asked_at": datetime(2026, 1, 1)})


def answer_line(deadline: datetime, asked_at: datetime) -> str:
    header = dataclasses.replace(HEADER, deadline=deadline, asked_at=asked_at)
    return render_call(header, {}).value.split("\n")[3]


def test_the_deadline_shows_its_date_when_the_utc_date_changes() -> None:
    """E.5: an elicitation that crosses midnight UTC says which day it ends."""
    late = datetime(2026, 11, 1, 23, 58, tzinfo=UTC)
    instruction = INSTRUCTIONS["elicitation"]
    assert answer_line(late + timedelta(minutes=1), late) == f"Answer by 23:59 UTC. {instruction}"
    assert answer_line(late + timedelta(minutes=2), late) == (
        f"Answer by 2026-11-02 00:00 UTC. {instruction}"
    )
    assert answer_line(late + timedelta(hours=9, minutes=17), late).startswith(
        "Answer by 2026-11-02 09:15 UTC."
    )
    # The dates compared are UTC's, whatever zone either time was given in.
    east = timezone(timedelta(hours=9))
    assert answer_line(DEADLINE.astimezone(east), ASKED_AT).startswith("Answer by 14:05 UTC.")
    west = timezone(timedelta(hours=-15))
    assert answer_line(DEADLINE, ASKED_AT.astimezone(west)).startswith("Answer by 14:05 UTC.")
    # A deadline before the asking date (a clock step) is dated too.
    assert answer_line(late - timedelta(days=1), late).startswith("Answer by 2026-10-31 23:58")


def test_the_vault_renders_its_own_frame() -> None:
    """E.5, B.3: the reported client, the pin from the vault's policy and the out-of-band
    instruction, in the frame the design shows."""
    header = Header("3f9c0a17b2d4e681", "desk", "broker", "place_order", DEADLINE, **VAULT)
    text = render_call(header, {"symbol": "XYZ", "side": "buy", "quantity": 1})
    assert text.value == (
        "Approval request 3f9c0a17b2d4e681\n"
        "Client (reported by the gateway): desk\n"
        f"Tool: broker {ARROW} place_order (pin sha256:3f1c{ELLIPSIS}e2, from the vault's policy)\n"
        "Answer by 14:05 UTC. Approve runs this one call, exactly as shown.\n"
        "\n"
        "{\n"
        '  "quantity": 1,\n'
        '  "side": "buy",\n'
        '  "symbol": "XYZ"\n'
        "}\n"
        "End of approval request 3f9c0a17b2d4e681"
    )
    assert problems(text, budget=3000, renders="plain") == []
    unreported = dataclasses.replace(header, client="", client_reported=False, pin=None)
    lines = render_call(unreported, {}).value.split("\n")
    assert lines[1:3] == ["Client (not reported)", f"Tool: broker {ARROW} place_order"]


def test_the_instruction_names_the_button() -> None:
    assert INSTRUCTIONS == {
        "elicitation": "Accept runs this one call, exactly as shown.",
        "out_of_band": "Approve runs this one call, exactly as shown.",
    }
    # A gateway prompt relayed out of band names the out-of-band surface's button.
    out_of_band = dataclasses.replace(HEADER, approver="out_of_band")
    lines = render_call(out_of_band, {}).value.split("\n")
    assert lines[1:4] == [
        "Client: agent1",
        f"Tool: notes-write {ARROW} create_note",
        "Answer by 14:05 UTC. Approve runs this one call, exactly as shown.",
    ]
    assert (
        render_plan(MAIL_HEADER, mail_plan())
        .value.split("\n")[3]
        .endswith(" Accept runs this one call, exactly as shown.")
    )


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"client_reported": True}, "only the vault's frame reports a client or names a pin"),
        ({"pin": PIN}, "only the vault's frame reports a client or names a pin"),
        ({**VAULT, "approver": "elicitation"}, "the vault asks only out of band"),
        ({**VAULT, "client_reported": False}, "a client the gateway didn't report has no name"),
        ({**VAULT, "pin": "sha256:" + "A" * 64}, "a pin is sha256: and 64 lowercase hex digits"),
        ({**VAULT, "pin": PIN + "0"}, "a pin is sha256: and 64 lowercase hex digits"),
        ({**VAULT, "pin": PIN + chr(10)}, "a pin is sha256: and 64 lowercase hex digits"),
        ({**VAULT, "pin": PIN[7:]}, "a pin is sha256: and 64 lowercase hex digits"),
        ({**VAULT, "pin": "x" + PIN}, "a pin is sha256: and 64 lowercase hex digits"),
    ],
    ids=[
        "gateway-reports",
        "gateway-pin",
        "vault-elicits",
        "vault-names-unreported",
        "pin-upper",
        "pin-long",
        "pin-newline",
        "pin-no-prefix",
        "pin-leading",
    ],
)
def test_a_frame_says_only_what_its_maker_knows(changes: dict[str, Any], message: str) -> None:
    with pytest.raises(ValueError, match=f"^{message}$"):
        Header("r", "agent1", "s", "t", DEADLINE, **{**GATEWAY, **changes})


def test_the_vault_frames_a_connector_send_without_a_pin() -> None:
    """B.7: a connector has no pin; the vault's frame then names none."""
    header = Header("r", "desk", "mail", "send", DEADLINE, **{**VAULT, "pin": None})
    assert render_call(header, {}).value.split("\n")[2] == f"Tool: mail {ARROW} send"


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
        (lambda: Show.line("Subject" + chr(10), "/a"), "a label"),
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
        assert found[0].reason == "a line imitating the frame"
        # Just before the real footer is still inside the prompt.
        found = check_body(f"Thanks.\n{line}", renders="plain")
        assert [(p.rule, p.pointer) for p in found] == [("frame", "/body")]
    assert check_body("Thanks. End of approval request 1234 was the subject") == []


def test_the_relay_line_is_composed_above_the_gateways_text() -> None:
    """E.5: the vault's line comes first, and every position keeps its pointer."""
    text = render_call(HEADER, {"note": "hi", "deep": {"k": {"k": {"k": {"k": "x"}}}}})
    composed = relayed(text)
    assert RELAY_LINE == (
        "Rendered by the gateway: the vault can't confirm this is the call the gateway will run."
    )
    assert composed.value == f"{RELAY_LINE}\n{text.value}"
    shift = len(RELAY_LINE) + 1
    assert composed.sources[0] == (0, None)
    assert composed.pointer_at(0) is None
    assert composed.pointer_at(shift - 1) is None
    for index in range(len(text.value)):
        assert composed.pointer_at(index + shift) == text.pointer_at(index)
    assert composed.indented_lines == {line + 1 for line in text.indented_lines}
    # The renderer's indentation stays allowed, one line down; the line itself is the vault's.
    found = problems(composed, budget=10_000, renders="plain")
    assert [(p.rule, p.pointer, p.reason) for p in found] == [
        ("frame", None, "a line imitating the relay line"),
        ("frame", None, "a line imitating the frame"),
    ]
    assert "ApprovalText(<" in repr(composed)


@pytest.mark.parametrize(
    "line",
    [RELAY_LINE, "Rendered by the gateway", "Rendered by the gateway: held by the vault."],
    ids=plain_id,
)
def test_lines_imitating_the_relay_line_are_refused(line: str) -> None:
    """E.5: inside the call, and anywhere in a text the gateway asks the vault to relay."""
    found = check_body(f"Thanks.\n{line}\nMore text", renders="plain")
    assert [(p.rule, p.pointer, p.reason) for p in found] == [
        ("frame", "/body", "a line imitating the relay line")
    ]
    title = Plan(line, [Write.post("/x", {"a": 1})])
    found = problems(render_plan(MAIL_HEADER, title), budget=3000, renders="plain")
    assert [(p.rule, p.pointer) for p in found] == [("frame", None)]
    for forged in (
        f"{line}\n{render_call(HEADER, {}).value}",
        f"{render_call(HEADER, {}).value}\n{line}",
    ):
        text = ApprovalText(forged, frozenset(), ((0, None),))
        found = problems(text, budget=10_000, renders="plain")
        assert "a line imitating the relay line" in [p.reason for p in found]
    assert check_body(f"Thanks. {line}") == []  # not at the start of a line
    # Indented, by spaces or a tab the whitespace rule allows, it still reads as the vault's.
    for indent in (" ", " " * 8, chr(9)):
        found = check_body(f"Thanks.\n{indent}{line}", renders="plain")
        assert [(p.rule, p.pointer, p.reason) for p in found] == [
            ("frame", "/body", "a line imitating the relay line")
        ]


# --- a text the vault receives to relay (M8 step 12b; E.2, E.4) ---------------------------------


def test_a_received_text_is_checked_as_its_renderer_checked_it() -> None:
    """The vault holds the gateway's words as one run with no pointer, and takes the renderer's
    own JSON indentation as indentation: a deeply nested call the gateway's check passed passes
    the vault's, and the relay line composes above it as it would above the gateway's own."""
    args = {"deep": {"k": {"k": {"k": {"k": {"k": "x"}}}}}}
    text = render_call(HEADER, args)
    assert problems(text, budget=10_000, renders="plain") == []
    found = received(text.value)
    assert found.value == text.value
    assert found.sources == ((0, None),)
    assert found.pointer_at(len(text.value) - 1) is None
    assert found.indented_lines == {
        n for n in text.indented_lines if text.value.split("\n")[n][:1] == " "
    }
    assert problems(found, budget=10_000, renders="plain") == []
    assert relayed(found).value == f"{RELAY_LINE}\n{text.value}"
    assert "ApprovalText(<" in repr(found)


@pytest.mark.parametrize(
    ("line", "indented"),
    [
        ("  x", True),
        (" " * 2 * MAX_RECEIVED_INDENT + "x", True),
        (" " * (2 * MAX_RECEIVED_INDENT + 2) + "x", False),
        (" x", False),
        ("   x", False),
        ("x", False),
        ("", False),
        ("  ", True),
        (chr(9) + "  x", False),
        ("  " + chr(9) + "x", False),
    ],
    ids=[
        "one",
        "deepest",
        "deeper",
        "half",
        "one-and-a-half",
        "none",
        "empty",
        "only",
        "tab",
        "space-tab",
    ],
)
def test_only_whole_indents_of_spaces_are_indentation(line: str, indented: bool) -> None:
    """A part of an indent, a tab, or more than the deepest nesting is never the renderer's: a
    wide run of it is refused as wide whitespace, as anywhere else."""
    found = received(f"first\n{line}\nlast")
    assert (1 in found.indented_lines) is indented
    assert found.indented_lines <= {1}
    assert received(line).indented_lines == (frozenset({0}) if indented else frozenset())


def test_a_wide_indent_the_renderer_never_makes_is_refused() -> None:
    wide = received("Approval request x\n" + " " * (2 * MAX_RECEIVED_INDENT + 2) + "x\nEnd")
    found = problems(wide, budget=10_000, renders="plain")
    assert [(p.rule, p.pointer) for p in found] == [("wide_space", None)]
    allowed = received("Approval request x\n" + " " * 2 * MAX_RECEIVED_INDENT + "x\nEnd")
    assert problems(allowed, budget=10_000, renders="plain") == []
    assert MAX_RECEIVED_INDENT == 33


def test_a_received_relay_line_is_refused() -> None:
    """Z12: the gateway can't write the vault's line itself, first line or not."""
    for forged in (f"{RELAY_LINE}\nApproval request x", f"Approval request x\n  {RELAY_LINE}"):
        found = problems(received(forged), budget=10_000, renders="plain")
        assert [(p.rule, p.reason) for p in found] == [("frame", "a line imitating the relay line")]


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


@settings(max_examples=50, deadline=None)
@given(st.dictionaries(_text, _json, max_size=5))
def test_a_relayed_text_keeps_every_pointer(args: dict[str, Any]) -> None:
    text = render_call(HEADER, args)
    composed = relayed(text)
    shift = len(RELAY_LINE) + 1
    assert composed.value[shift:] == text.value
    assert [(s - shift, p) for s, p in composed.sources[1:]] == list(text.sources)


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
