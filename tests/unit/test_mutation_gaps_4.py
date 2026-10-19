"""Killing tests for mutants that survived the M4 modules' first full mutation run (b65e3eb).

Each test names what it pins. Mutants left alive on purpose, as equivalent or unreachable:

- the field tables of ``ledgerformat`` and ``sendjournal`` are built at import time
  (``_member``, ``_optional``, ``_match``), where mutmut can't switch a mutant in;
- ``.encode("ASCII")`` for ``"ascii"``, ``split(..., 2)`` or no maxsplit where only part 0 is
  read, ``sorted(..., key=None)`` over tuples whose first items are unique, ``max_reported`` and a
  ``+ 2`` slack in ``max_bytes``: same result for every input;
- ``_escape`` in ``params`` (parameter names can't hold ``~`` or ``/``), and
  ``allow_tabs`` in ``params.description`` (``inspect.cleandoc`` expands tabs first).
"""

from __future__ import annotations

import stat
from datetime import UTC, datetime
from typing import Annotated, Any, Literal, Required, TypedDict

import pytest

from zoeymcp.common import approvaltext, canonical, ledgerformat
from zoeymcp.common.approvaltext import Header, LayoutError, Plan, Show, Write
from zoeymcp.common.ledgerformat import GENESIS, LedgerFormatError, encode, line_hash, parse
from zoeymcp.common.policy.match import RequestRejected
from zoeymcp.common.policy.schema import SMTPConnector
from zoeymcp.gateway import approvals
from zoeymcp.gateway.approvals import Key, Settings, Table, handle_sha256
from zoeymcp.toolkit import Batch, Range, Text, ToolContext, rules
from zoeymcp.toolkit import params as params_module
from zoeymcp.toolkit.params import check_arguments, description, parameters
from zoeymcp.vault.connectors import mailmsg, sendjournal, tunnel
from zoeymcp.vault.connectors.sendjournal import Journal, JournalError

HEADER = Header("3f9c0a17d2b84e65", "agent1", "mail", "send_note", datetime(2026, 1, 1, tzinfo=UTC))


# --- toolkit.rules ------------------------------------------------------------------------------


def test_join_says_why() -> None:
    with pytest.raises(RequestRejected) as raised:
        rules.join("/db", "v1")
    assert raised.value.reason == "a toolkit path starts with /"
    with pytest.raises(RequestRejected):  # a character the vault refuses, not an encoding error
        rules.join("/db", "/café")


def test_a_group_bit_counts_only_when_set() -> None:
    entry = rules.Entry("/p", 0o644, 0, 1000)
    assert rules.writable_problems([entry], uid=2000, gids=frozenset({1000})) == []
    entry = rules.Entry("/p", 0o664, 0, 1000)
    assert rules.writable_problems([entry], uid=2000, gids=frozenset({1000})) == ["/p"]
    assert stat.S_IWGRP == 0o020


# --- tunnel -------------------------------------------------------------------------------------


def test_a_head_of_exactly_the_limit_is_read() -> None:
    status = b"HTTP/1.1 200 Connection established\r\n"
    padding = b"X-Pad: " + b"x" * (tunnel.MAX_HEAD_BYTES - len(status) - 11) + b"\r\n"
    head = status + padding + b"\r\n"
    assert len(head) == tunnel.MAX_HEAD_BYTES
    assert tunnel.parse_connect_reply(head) == tunnel.Reply("open", 200)
    assert tunnel.parse_connect_reply(head[:-2] + b"x\r\n\r\n").kind == "broken"


# --- toolkit.params -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("build", "message"),
    [
        (lambda: Text(max=1, min=2), r"^Text needs 0 <= min <= max <= 100000$"),
        (
            lambda: Text(max=5, pattern="^a"),
            r"^a Text pattern matches the whole text; leave out \^ and \$$",
        ),
        (lambda: Range(ge=2, le=1), r"^Range needs ge <= le, both safe integers$"),
        (lambda: Batch(max=1001), r"^Batch needs 0 <= min <= max <= 1000$"),
        (
            lambda: params_module.tool_name("a b"),
            r"^'a b': a tool name is 1-128 of A-Z, a-z, 0-9, '_', '\.' or '-'$",
        ),
    ],
)
def test_marker_messages(build: Any, message: str) -> None:
    with pytest.raises(TypeError, match=message):
        build()


def test_a_range_of_one_value() -> None:
    assert Range(ge=1, le=1).le == 1


Leaf = Annotated[str, Text(max=5)]


async def _four_deep(
    ctx: ToolContext,
    x: Annotated[
        list[Annotated[list[Annotated[list[Leaf], Batch(max=1)]], Batch(max=1)]], Batch(max=1)
    ],
) -> str:
    return ""


class _Inner(TypedDict):
    leaf: Leaf


class _Middle(TypedDict):
    inner: _Inner


class _Outer(TypedDict):
    middle: _Middle


async def _objects_four_deep(ctx: ToolContext, x: _Outer) -> str:
    return ""


async def _optional_four_deep(ctx: ToolContext, x: _Outer | None = None) -> str:
    return ""


def test_nesting_exactly_at_the_limit_is_allowed() -> None:
    assert parameters(_four_deep).names == ("x",)
    assert parameters(_objects_four_deep).names == ("x",)
    assert parameters(_optional_four_deep).names == ("x",)


async def _batch_on_str(ctx: ToolContext, x: Annotated[str, Batch(max=1)]) -> str:
    return ""


async def _list_item_wrong(ctx: ToolContext, x: Annotated[list[float], Batch(max=1)]) -> str:
    return ""


class _Badly(TypedDict):
    Bad: Leaf


async def _bad_field(ctx: ToolContext, x: _Badly) -> str:
    return ""


async def _bad_field_type(
    ctx: ToolContext, x: _Middle | None = None, y: dict[str, str] | None = None
) -> str:
    return ""


@pytest.mark.parametrize(
    ("fn", "message"),
    [
        (_batch_on_str, r"^_batch_on_str\(x\): Batch doesn't fit this type$"),
        (_list_item_wrong, r"^_list_item_wrong\(x\)\[\]: unsupported type <class 'float'>$"),
        (_bad_field, r"^_bad_field\(x\)\.Bad: field names are lower-case identifiers$"),
        (_bad_field_type, r"^_bad_field_type\(y\): unsupported type"),
    ],
)
def test_where_a_type_error_points(fn: Any, message: str) -> None:
    with pytest.raises(TypeError, match=message):
        parameters(fn)


async def _big_literal(ctx: ToolContext, x: Literal[tuple(f"v{i}" for i in range(64))]) -> str:  # type: ignore[valid-type]
    return ""


def test_a_literal_of_the_most_values() -> None:
    assert len(parameters(_big_literal).root.fields[0][1].values) == 64  # type: ignore[union-attr]


class _Explicit(TypedDict):
    a: Required[Leaf]


async def _explicit(ctx: ToolContext, x: _Explicit) -> str:
    return ""


def test_an_explicitly_required_field_is_required() -> None:
    [(_, node, _)] = parameters(_explicit).root.fields
    assert node.fields == (("a", params_module.TextNode(Text(max=5)), True),)  # type: ignore[union-attr]


async def _optional_first(ctx: ToolContext, *, a: Leaf | None = None, b: Leaf) -> str:
    return ""


def test_every_parameter_after_an_optional_one_counts() -> None:
    assert parameters(_optional_first).names == ("a", "b")


def test_a_one_character_description() -> None:
    async def tool(ctx: ToolContext) -> str:
        """X"""
        return ""

    assert description(tool) == "X"


def test_a_batch_of_exactly_its_maximum() -> None:
    async def tool(ctx: ToolContext, x: Annotated[list[Leaf], Batch(max=2)]) -> str:
        return ""

    assert check_arguments(parameters(tool), {"x": ["a", "b"]}) == []


def test_a_tab_in_text_that_refuses_tabs() -> None:
    async def tool(ctx: ToolContext, x: Annotated[str, Text(max=9, allow_tabs=False)]) -> str:
        return ""

    assert [str(p) for p in check_arguments(parameters(tool), {"x": "a\tb"})] == ["/x: text_rules"]


# --- approvaltext -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("build", "message"),
    [
        (
            lambda: Header("r", "c", "s", "t", datetime(2026, 1, 1)),
            "the deadline must be timezone-aware",
        ),
    ],
)
def test_value_error_messages(build: Any, message: str) -> None:
    with pytest.raises(ValueError, match=f"^{message}$"):
        build()


@pytest.mark.parametrize(
    ("build", "message"),
    [
        (lambda: Show.items("Items", "/a", []), "an items layout needs at least one field"),
        (
            lambda: Show.items("Items", "/a", [("x", "/x"), ("y", "/x")]),
            "an items layout lists a field twice",
        ),
        (
            lambda: Show.line("bad!", "/a"),
            "a label is 1-32 ASCII letters, digits, spaces, '_' or '-'",
        ),
        (lambda: Show.json("a"), "a layout pointer names one top-level member, like /subject"),
        (lambda: Show.json("//a"), "a layout pointer names one top-level member, like /subject"),
        (lambda: Show.json("/a~2"), "a layout pointer has a bad ~ escape"),
        (lambda: Write.post("/x", ["a"]), "a write's body is a JSON object"),  # type: ignore[arg-type]
        (lambda: Write.post("x", {"a": 1}), "a write's path starts with /"),
        (
            lambda: Write.post("/x", {"a": 1}, show=[Show.json("/b")]),
            "a layout item points at nothing",
        ),
        (
            lambda: Write.post("/x", {"a": "1\n2"}, show=[Show.line("A", "/a")]),
            "a line layout holds a multi-line string",
        ),
        (
            lambda: Write.post("/x", {"a": 1}, show=[Show.block("/a")]),
            "a block layout holds a string",
        ),
        (
            lambda: Write.post("/x", {"a": "x", "b": 1}, show=[Show.block("/a"), Show.json("/b")]),
            "a block layout comes last",
        ),
        (
            lambda: Write.post("/x", {"a": 1}, show=[Show.json("/a"), Show.json("/a")]),
            "a member is shown twice",
        ),
        (
            lambda: Write.post("/x", {"a": 1, "b": 2}, show=[Show.json("/a")]),
            "a member of the write isn't shown",
        ),
        (
            lambda: Write.post("/x", {"a": 1}, show=[Show.items("A", "/a", [("x", "/x")])]),
            "an items layout holds an array",
        ),
        (
            lambda: Write.post("/x", {"a": [1]}, show=[Show.items("A", "/a", [("x", "/x")])]),
            "an items layout holds an array of objects",
        ),
        (
            lambda: Write.post(
                "/x", {"a": [{"y": 1}]}, show=[Show.items("A", "/a", [("x", "/x")])]
            ),
            "an items layout leaves out a field of an item",
        ),
        (
            lambda: Write.post(
                "/x", {"a": [{"x": [1]}]}, show=[Show.items("A", "/a", [("x", "/x")])]
            ),
            "an items layout holds flat objects only",
        ),
        (lambda: Plan("Title", ["not a write"]), "a plan holds Write objects"),  # type: ignore[list-item]
    ],
)
def test_layout_messages(build: Any, message: str) -> None:
    with pytest.raises(LayoutError) as raised:
        build()
    assert str(raised.value) == message


def test_put_and_patch_keep_their_method_and_layout() -> None:
    layout = [Show.line("Name", "/name")]
    put = Write.put("/r/1", {"name": "x"}, show=layout)
    patch = Write.patch("/r/1", {"name": "x"})
    assert (put.method, put.show) == ("PUT", tuple(layout))
    assert patch.method == "PATCH"


def test_the_default_layout_follows_canonical_key_order() -> None:
    body = {"ﬁ": 1, "\U0001f600": 2}  # UTF-16 order differs from code-point order here
    write = Write.post("/x", body)
    expected = sorted(body, key=canonical.key_order)
    assert [s.pointer for s in write.show] == ["/" + k for k in expected]
    assert expected != sorted(body)


def test_a_large_body_is_frozen() -> None:
    write = Write.post("/x", {"a": "x" * (2 * 2**20)}, show=[Show.block("/a")])
    assert len(write.data["a"]) == 2 * 2**20


def test_every_piece_of_a_json_value_knows_its_member() -> None:
    text = approvaltext.render_call(HEADER, {"a": {"b": 1}, "c": [1, 2], "d": {}})
    value = text.value

    def at(fragment: str, after: str) -> str | None:
        return text.pointer_at(value.index(fragment, value.index(after)))

    assert at(": ", '"a"') == ""  # a member's separator belongs to its object
    assert at("{", '"a"') == "/a"
    assert at(": ", '"b"') == "/a"
    assert at("}", '"b"') == "/a"
    assert at(",", '"c"') == "/c"
    assert at("{}", '"d"') == "/d"
    assert text.pointer_at(0) is None  # the frame is the gateway's
    first = text.sources[1][0]
    assert text.pointer_at(first) == text.sources[1][1]  # a run starts at its own offset


def test_indentation_lines_are_counted_from_zero() -> None:
    text = approvaltext.render_call(HEADER, {"a": 1})
    lines = text.value.split(chr(10))
    assert sorted(text.indented_lines) == [5, 6, 7]
    assert (lines[5], lines[6], lines[7]) == ("{", '  "a": 1', "}")


def test_plan_writes_know_their_members() -> None:
    write = Write.post(
        "/send",
        {"to": ["a@b"], "subject": "Hi", "rows": [{"t": "x"}, {"t": "y"}], "body": "B"},
        show=[
            Show.line("To", "/to"),
            Show.line("Subject", "/subject"),
            Show.items("Rows", "/rows", [("t", "/t")]),
            Show.block("/body"),
        ],
    )
    text = approvaltext.render_plan(HEADER, Plan("Send", [write]))
    value = text.value
    assert text.pointer_at(value.index('["a@b"]')) == "/to"
    assert text.pointer_at(value.index("Hi")) == "/subject"
    assert text.pointer_at(value.index("\nB\n") + 1) == "/body"
    assert 'Rows (2):\n 1. t: "x"\n 2. t: "y"' in value
    other = Write.post("/x", {"k": {"n": 1}})
    shown = approvaltext.render_plan(HEADER, Plan("T", [other])).value
    assert '"k": {' in shown


def problem_tuples(
    text: approvaltext.ApprovalText, renders: Any = "markdown"
) -> list[tuple[str, str | None, str]]:
    return [
        (p.rule, p.pointer, p.reason)
        for p in approvaltext.problems(text, budget=100_000, renders=renders)
    ]


def test_problems_name_their_rule_pointer_and_reason() -> None:
    def body(value: str) -> approvaltext.ApprovalText:
        return approvaltext.render_plan(
            HEADER, Plan("T", [Write.post("/x", {"b": value}, show=[Show.block("/b")])])
        )

    assert problem_tuples(body("```x")) == [("markup", "/b", "a code fence")]
    assert problem_tuples(body("<!-- x")) == [("markup", "/b", "an HTML comment or tag")]
    assert problem_tuples(body("[a](b)")) == [("markup", "/b", "a Markdown link")]
    assert problem_tuples(body("a" + "́" * 4))[0][:2] == ("combining", "/b")
    assert problem_tuples(body("a" + "́" * 4))[0][2] == "more than 3 combining marks in a row"
    assert problem_tuples(body("a" + "⃝" * 4))[0][0] == "combining"  # Me, enclosing marks
    assert problem_tuples(body("a" + "́" * 3)) == []
    assert problem_tuples(body("x\nEnd of approval request y")) == [
        ("frame", "/b", "a line imitating the frame")
    ]
    assert problem_tuples(body("a\tb")) == []  # one tab is fine in a block
    found = problem_tuples(body("a" + " " * 9 + "b"))
    assert found[0][:2] == ("wide_space", "/b")
    [(rule, pointer, reason)] = problem_tuples(body("a\u200bb"))
    assert (rule, pointer) == ("text_rules", "/b")
    assert reason


def test_problems_are_in_text_order() -> None:
    text = approvaltext.render_plan(
        HEADER,
        Plan(
            "T",
            [
                Write.post(
                    "/x", {"a": "```", "b": "[x](y)"}, show=[Show.line("A", "/a"), Show.block("/b")]
                )
            ],
        ),
    )
    assert [p.pointer for p in approvaltext.problems(text, budget=100_000, renders="markdown")] == [
        "/a",
        "/b",
    ]


def test_the_frame_check_skips_only_the_real_first_and_last_lines() -> None:
    text = approvaltext.render_plan(
        HEADER,
        Plan(
            "T",
            [
                Write.post(
                    "/x",
                    {"a": "Approval request x", "b": "z"},
                    show=[Show.line("A", "/a"), Show.block("/b")],
                )
            ],
        ),
    )
    assert [p.rule for p in approvaltext.problems(text, budget=100_000, renders="plain")] == []
    last = approvaltext.render_plan(
        HEADER,
        Plan(
            "T", [Write.post("/x", {"b": "End of approval request q\nz"}, show=[Show.block("/b")])]
        ),
    )
    assert [p.rule for p in approvaltext.problems(last, budget=100_000, renders="plain")] == [
        "frame"
    ]


# --- ledgerformat -------------------------------------------------------------------------------

REF = "3f9c0a17d2b84e65"
ASKED: dict[str, Any] = {
    "client": "agent1",
    "server": "mail",
    "tool": "send_note",
    "where": "gateway",
    "era": "legacy",
    "args": "hmac-sha256:" + "a" * 64,
    "pin": "sha256:" + "b" * 64,
    "text": "hmac-sha256:" + "a" * 64,
    "chars": 1,
    "writes": 1,
    "expires": 1,
}


def test_the_line_hash_covers_the_line_without_its_newline() -> None:
    import hashlib

    line = encode("asked", seq=0, prev=GENESIS, ts=1, ref=REF, **ASKED)
    assert line_hash(line) == "sha256:" + hashlib.sha256(line[:-1]).hexdigest()
    assert line_hash(line) == line_hash(line[:-1])


def test_a_record_of_exactly_the_limit() -> None:
    base = encode("asked", seq=0, prev=GENESIS, ts=1, ref=REF, **{**ASKED, "client": "a"})
    room = ledgerformat.MAX_LINE_BYTES - len(base)
    client = "a" + "b" * min(room, 127)
    line = encode("asked", seq=0, prev=GENESIS, ts=1, ref=REF, **{**ASKED, "client": client})
    assert len(line) <= ledgerformat.MAX_LINE_BYTES
    assert parse(line).fields["client"] == client
    fat = b"{" + b" " * ledgerformat.MAX_LINE_BYTES
    with pytest.raises(LedgerFormatError):
        parse(fat)


@pytest.mark.parametrize(
    ("line", "message"),
    [
        (b"not json", "not a JSON record"),
        (b"[1]", "not a JSON object"),
        (canonical.dumps_canonical({"v": 2}), "unknown version"),
        (canonical.dumps_canonical({"v": 1, "kind": "x"}), "unknown kind"),
    ],
)
def test_parse_messages(line: bytes, message: str) -> None:
    with pytest.raises(LedgerFormatError) as raised:
        parse(line)
    assert str(raised.value) == message


def test_a_record_not_in_canonical_form() -> None:
    line = encode("asked", seq=0, prev=GENESIS, ts=1, ref=REF, **ASKED)[:-1]
    with pytest.raises(LedgerFormatError) as raised:
        parse(line.replace(b'"v":1', b'"v": 1'))
    assert str(raised.value) == "not in canonical form"


def test_check_messages() -> None:
    good = {
        "v": 1,
        "seq": 0,
        "prev": GENESIS,
        "ts": 1,
        "ref": REF,
        "kind": "asked",
        "writer": "gateway",
        **ASKED,
    }
    cases: list[tuple[dict[str, Any], str]] = [
        ({"seq": -1}, "bad seq or ts"),
        ({"prev": "x"}, "bad prev"),
        ({"writer": "x"}, "bad writer"),
        ({"ref": "x"}, "bad ref"),
    ]
    for change, message in cases:
        with pytest.raises(LedgerFormatError) as raised:
            parse(canonical.dumps_canonical({**good, **change}))
        assert str(raised.value) == message


def test_a_parsed_record_keeps_its_line() -> None:
    line = encode("asked", seq=0, prev=GENESIS, ts=1, ref=REF, **ASKED)
    assert parse(line).line == line[:-1]


def test_verify_reports_the_head_it_reached() -> None:
    first = encode("asked", seq=0, prev=GENESIS, ts=1, ref=REF, **ASKED)
    found = ledgerformat.verify([first, b"garbage\n"])
    assert (found.head_seq, found.head_hash, found.records, found.broken_at) == (
        0,
        line_hash(first),
        1,
        1,
    )
    skipped = encode("asked", seq=5, prev=line_hash(first), ts=1, ref=REF, **ASKED)
    found = ledgerformat.verify([first, skipped])
    assert (found.records, found.broken_at) == (1, 5)


def test_a_torn_tail_after_the_first_line() -> None:
    first = encode("asked", seq=0, prev=GENESIS, ts=1, ref=REF, **ASKED)
    assert ledgerformat.torn_tail(first) == 0
    assert ledgerformat.torn_tail(first + b"x\n") == 2
    assert ledgerformat.torn_tail(b"\n" + first) == 0


def test_open_refs_read_past_records_with_no_ref() -> None:
    recovered = parse(
        encode("recovered", seq=1, prev=GENESIS, ts=1, ref=None, abandoned=0, not_sent=0, unknown=0)
    )
    asked = parse(encode("asked", seq=2, prev=GENESIS, ts=1, ref=REF, **ASKED))
    assert list(ledgerformat.open_refs([recovered, asked])) == [REF]


def test_recovery_counts_and_planned_writes() -> None:
    other = "9b21e07c44d0aa13"
    asked = parse(encode("asked", seq=0, prev=GENESIS, ts=1, ref=REF, **{**ASKED, "writes": 3}))
    second = parse(encode("asked", seq=1, prev=GENESIS, ts=1, ref=other, **ASKED))
    accepted = parse(
        encode("decided", seq=2, prev=GENESIS, ts=1, ref=REF, decision="accept", waited_ms=1)
    )
    steps = ledgerformat.recovery_plan({REF: [asked, accepted], other: [second]})
    outcome = next(s for s in steps if s.kind == "outcome" and s.ref == REF)
    assert outcome.fields["writes_unknown"] == 3
    summary = next(s for s in steps if s.kind == "recovered")
    assert summary.fields == {"abandoned": 1, "not_sent": 1, "unknown": 1}
    third = "1111111111111111"
    more = parse(encode("asked", seq=3, prev=GENESIS, ts=1, ref=third, **ASKED))
    steps = ledgerformat.recovery_plan({other: [second], third: [more]})
    assert next(s for s in steps if s.kind == "recovered").fields["abandoned"] == 2


# --- approvals ----------------------------------------------------------------------------------

SETTINGS = Settings(
    timeout=300, call_timeout=300, cooldown=15, max_pending_per_client=4, max_prompts_per_hour=30
)
KEY = Key("agent1", "mail", "send_note")


def begin(
    table: Table,
    key: Key = KEY,
    *,
    ref: str = "r1",
    handle: str | None = None,
    era: Any = "modern",
    now: float = 0.0,
    code: Any = None,
    plan: Any = None,
) -> Any:
    return table.begin(
        key,
        settings=SETTINGS,
        now=now,
        ref=ref,
        era=era,
        args={"subject": "Hi"},
        args_digest="sha256:" + "a" * 64,
        pin="sha256:" + "b" * 64,
        text_sha256="t",
        plan=plan,
        code=code,
        handle_sha256=handle_sha256(handle) if handle else None,
    )


def test_reprs_hide_secrets() -> None:
    assert repr(approvals.new_handle()) == "Handle(<hidden>)"
    assert repr(approvals.new_code()) == "ConfirmCode(<hidden>)"


def test_a_handle_is_43_characters_after_its_prefix() -> None:
    handle = approvals.new_handle().reveal()
    assert approvals.HANDLE_PATTERN.fullmatch(handle)
    assert "=" not in handle


def test_seconds_round_up_to_whole_seconds() -> None:
    assert approvals._seconds(1.2) == 2
    assert isinstance(approvals._seconds(1.2), int)
    assert approvals._seconds(0.0) == 1


def test_get_needs_a_ref() -> None:
    table = Table()
    begin(table)
    assert table.get("missing") is None


def test_begin_keeps_what_the_forward_needs() -> None:
    table = Table()
    code = approvals.new_code()
    record = begin(table, code=code, plan="the plan")
    assert (record.args, record.plan, record.code) == ({"subject": "Hi"}, "the plan", code)


def test_a_new_prompt_ends_its_keys_cooldown() -> None:
    table = Table()
    begin(table, handle="za1." + "a" * 43)
    table.decide("r1", "decline", 1.0)
    table.finish(KEY, "r1", 1.0, settings_cooldown=15)
    assert table._cooldowns[KEY] == 16.0
    other = Key("agent1", "mail", "other")
    begin(table, other, ref="r2")
    assert KEY in table._cooldowns  # only the asking key's cooldown ends


def test_a_reask_moves_the_handle() -> None:
    table = Table()
    first, second = "za1." + "a" * 43, "za1." + "b" * 43
    begin(table, handle=first)
    record = table.reask("r1", handle_sha256(second))
    assert record.handle_sha256 == handle_sha256(second)
    assert record.asks == 2
    assert table.lookup(handle_sha256(first), 0.0) is None
    assert table.lookup(handle_sha256(second), 0.0) == record
    table.consume(handle_sha256(second), 0.0)
    table.reask("r1", handle_sha256(first))  # a consumed record has no handle to drop
    assert table.lookup(handle_sha256(first), 0.0).ref == "r1"  # type: ignore[union-attr]


def test_a_decision_buries_the_handle_with_its_reason() -> None:
    table = Table()
    first, second = "za1." + "a" * 43, "za1." + "b" * 43
    begin(table, handle=first)
    begin(table, Key("agent1", "mail", "two"), ref="r2", handle=second)
    record = table.decide("r1", "decline", 1.0)
    assert record.handle_sha256 is None
    assert table.lookup(handle_sha256(first), 1.0) == approvals.Tombstone("used", 601.0)
    table.decide("r2", "timeout", 1.0)
    assert table.lookup(handle_sha256(second), 1.0) == approvals.Tombstone("expired", 601.0)


def test_finishing_an_undecided_call_decides_it() -> None:
    table = Table()
    handle = "za1." + "a" * 43
    begin(table, handle=handle)
    assert table.finish(KEY, "r1", 1.0, settings_cooldown=15) is True
    assert table.lookup(handle_sha256(handle), 1.0) == approvals.Tombstone("used", 601.0)
    assert KEY not in table._cooldowns  # an error starts no cooldown
    begin(table, ref="r2", now=20.0)
    table.decide("r2", "accept", 20.0)
    table.finish(KEY, "r2", 20.0, settings_cooldown=15)
    assert KEY not in table._cooldowns  # nor does an accept


def test_a_cooldown_of_one_second_and_of_none() -> None:
    table = Table()
    begin(table)
    table.decide("r1", "decline", 0.0)
    table.finish(KEY, "r1", 0.0, settings_cooldown=1)
    assert table._cooldowns[KEY] == 1.0
    begin(table, ref="r2", now=5.0)
    table.decide("r2", "decline", 5.0)
    table.finish(KEY, "r2", 5.0, settings_cooldown=0)
    assert KEY not in table._cooldowns


def test_sweeping_a_lock_past_its_deadline_buries_its_handle() -> None:
    table = Table()
    handle = "za1." + "a" * 43
    record = begin(table, handle=handle)
    swept = table.sweep(record.hard_deadline)
    assert [r.ref for r in swept.freed] == ["r1"]
    assert table.lookup(handle_sha256(handle), record.hard_deadline) == approvals.Tombstone(
        "expired", record.hard_deadline + approvals.TOMBSTONE_SECONDS
    )
    legacy = Table()
    begin(legacy, era="legacy")
    assert [r.ref for r in legacy.sweep(10**9).freed] == ["r1"]  # no handle to bury


def test_sweeping_forgets_quiet_clients_and_keeps_busy_ones() -> None:
    table = Table()
    begin(table)
    table.finish(KEY, "r1", 0.0, settings_cooldown=0)
    begin(table, Key("agent2", "mail", "t"), ref="r2", now=4000.0)
    table.sweep(4000.0)
    assert "agent1" not in table._asked
    assert list(table._asked["agent2"]) == [4000.0]


def test_require_names_the_ref() -> None:
    with pytest.raises(KeyError) as raised:
        Table()._require("r9")
    assert raised.value.args == ("r9",)


def test_a_reburied_handle_moves_to_the_end() -> None:
    table = Table()
    table._bury("h1", "used", 0.0)
    table._bury("h2", "used", 0.0)
    table._bury("h1", "expired", 5.0)
    assert list(table._tombstones) == ["h2", "h1"]
    assert table._tombstones["h1"].reason == "expired"


# --- mailmsg ------------------------------------------------------------------------------------

CONNECTOR = SMTPConnector.model_validate(
    {
        "kind": "smtp",
        "host": "smtp.mail.example",
        "port": 465,
        "username": "agent",
        "password": "store:mail-pass",
        "from": "Agent <agent@mail.example>",
        "to": ["partner@mail.example"],
    }
)


def test_a_rejection_answer() -> None:
    assert mailmsg.Rejection(400, "bad_request", "subject", "type").answer() == {
        "error": "bad_request",
        "code": "bad_request",
        "field": "subject",
        "rule": "type",
    }
    assert mailmsg.Rejection(409, "connector_constraints_differ").answer() == {
        "error": "connector_constraints_differ",
        "code": "connector_constraints_differ",
    }


def request(**changes: Any) -> bytes:
    value = {
        "expect_from": CONNECTOR.from_,
        "expect_to": list(CONNECTOR.to),
        "subject": "S",
        "body": "B",
        **changes,
    }
    return canonical.dumps_canonical(value)


def test_parse_limits_at_their_edges() -> None:
    padding = mailmsg.MAX_BODY_BYTES - len(request(body=""))
    exact = request(body="x" * padding)
    assert len(exact) == mailmsg.MAX_BODY_BYTES
    found = mailmsg.parse_send(exact, CONNECTOR.model_copy(update={"max_body_chars": 100_000}))
    assert isinstance(found, mailmsg.SendRequest)
    assert isinstance(mailmsg.parse_send(request(subject="a\tb"), CONNECTOR), mailmsg.Rejection)
    assert isinstance(mailmsg.parse_send(request(body="a\tb"), CONNECTOR), mailmsg.SendRequest)
    assert isinstance(mailmsg.parse_send(request(body="x"), CONNECTOR), mailmsg.SendRequest)
    longest = "<" + "a" * 124 + "@" + "b" * 123 + ">"
    assert len(longest) == mailmsg.MAX_MESSAGE_ID
    assert isinstance(
        mailmsg.parse_send(request(in_reply_to=longest), CONNECTOR), mailmsg.SendRequest
    )


def test_the_domain_is_after_the_last_at() -> None:
    assert mailmsg.domain_of('"a@b" <x@y.example>') == "y.example"


def test_message_id_message() -> None:
    with pytest.raises(ValueError, match=r"^a message id takes 32 lowercase hex digits$"):
        mailmsg.message_id(CONNECTOR, "XYZ")


def test_the_message_headers_as_written() -> None:
    found = mailmsg.parse_send(request(in_reply_to="<a@b>"), CONNECTOR)
    assert isinstance(found, mailmsg.SendRequest)
    message = mailmsg.build_message(
        found, CONNECTOR, message_id="<m@mail.example>", date=datetime(2026, 1, 1, tzinfo=UTC)
    )
    raw = message.as_bytes()
    for header in (
        b"From: ",
        b"To: ",
        b"Date: ",
        b"In-Reply-To: ",
        b"References: ",
        b"Auto-Submitted: ",
    ):
        assert b"\n" + header in b"\n" + raw
    assert b'Content-Type: text/plain; charset="utf-8"' in raw
    data = mailmsg.data_bytes(message)
    assert b"\r\n" in data
    assert b"\n" not in data.replace(b"\r\n", b"")


def test_data_bytes_of_a_message_without_a_final_newline() -> None:
    from email.message import EmailMessage
    from email.policy import SMTP

    message = EmailMessage(policy=SMTP)
    message["Subject"] = "x"
    assert mailmsg.data_bytes(message).endswith(b"\r\n.\r\n")


# --- sendjournal --------------------------------------------------------------------------------

KEY_ID = "0123456789abcdef"
JKEY = "key-0001-aaaaaaaaaaaa"


def test_counts_and_codes_at_their_edges() -> None:
    zero = {
        "ts": 0,
        "key": JKEY,
        "req_hmac": "hmac-sha256:" + "a" * 64,
        "key_id": KEY_ID,
        "subject_chars": 0,
        "body_chars": 0,
    }
    sendjournal.encode("sending", **zero)
    for code in (100, 599):
        sendjournal.encode("sent", ts=1, key=JKEY, message_id="<a@b>", smtp_code=code)
    for code in (99, 600):
        with pytest.raises(JournalError):
            sendjournal.encode("sent", ts=1, key=JKEY, message_id="<a@b>", smtp_code=code)


def test_journal_messages() -> None:
    for line, message in [
        (b"nope", "not a JSON record"),
        (b"[]", "not a JSON object"),
        (b'{"kind":"x"}', "unknown kind"),
        (b'{"kind":"unknown","key":"k"}', "a unknown record has the wrong fields"),
        (
            b'{"key":"short","kind":"unknown","phase":"tunnel","ts":1}',
            "bad key in a unknown record",
        ),
    ]:
        with pytest.raises(JournalError) as raised:
            sendjournal.parse(line)
        assert str(raised.value) == message
    with pytest.raises(JournalError) as raised:
        sendjournal.encode("unknown", ts=1, key=JKEY, phase="x" * 32 + "y")
    assert str(raised.value) == "bad phase in a unknown record"


def test_a_line_with_and_without_its_newline_parses() -> None:
    line = sendjournal.encode("unknown", ts=1, key=JKEY, phase="tunnel")
    assert sendjournal.parse(line) == sendjournal.parse(line[:-1])


def test_a_journal_line_of_exactly_the_limit() -> None:
    assert sendjournal.MAX_LINE_BYTES == 2048
    line = sendjournal.encode("unknown", ts=1, key=JKEY, phase="tunnel")
    assert len(line) < sendjournal.MAX_LINE_BYTES  # records can't reach it: the check is a guard


def test_old_keys_are_forgotten_after_thirty_days() -> None:
    journal = Journal()
    journal.apply(
        {"kind": "sending", "ts": 1000, "key": JKEY, "req_hmac": "hmac-sha256:" + "a" * 64}
    )
    journal.apply(
        {"kind": "sent", "ts": 1001, "key": JKEY, "message_id": "<a@b>", "smtp_code": 250}
    )
    horizon = 1000 + sendjournal.KEY_DAYS * sendjournal.DAY_MS
    journal.forget_old_keys(horizon)
    assert JKEY in journal.attempts  # exactly 30 days: still remembered
    journal.forget_old_keys(horizon + 1)
    assert JKEY not in journal.attempts


def test_rebuild_counts_every_bad_line() -> None:
    _, bad = sendjournal.rebuild([b"x\n", b"y\n", b"z\n"])
    assert bad == 3
