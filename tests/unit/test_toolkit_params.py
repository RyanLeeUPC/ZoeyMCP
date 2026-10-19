"""A toolkit tool's parameters: the generated schema and the check of a call (M4 design G.2)."""

from __future__ import annotations

from typing import Annotated, Any, Literal, NotRequired, TypedDict

import pytest
from hypothesis import given
from hypothesis import strategies as st

from zoeymcp.common.canonical import MAX_SAFE_INTEGER
from zoeymcp.toolkit import Batch, MessageId, Range, Text, ToolContext
from zoeymcp.toolkit.params import (
    ArgumentProblem,
    check_arguments,
    description,
    parameters,
    same_parameters,
    tool_name,
)

Subject = Annotated[str, Text(min=1, max=150, single_line=True)]
Body = Annotated[str, Text(min=1, max=2200)]
Amount = Annotated[int, Range(ge=0, le=1000)]
Day = Annotated[str, Text(min=10, max=10, ascii_only=True, pattern=r"\d{4}-\d{2}-\d{2}")]


class NewRecord(TypedDict):
    title: Subject
    amount: Amount
    day: NotRequired[Day]


async def send(
    ctx: ToolContext,
    subject: Subject,
    body: Body,
    urgent: bool,
    kind: Literal["note", "reply"],
    records: Annotated[list[NewRecord], Batch(max=3)],
    in_reply_to: MessageId | None = None,
) -> str:
    """Send a note."""
    return ""


def schema_of(fn: Any) -> dict[str, Any]:
    found: dict[str, Any] = parameters(fn).schema()
    return found


# --- the schema ---------------------------------------------------------------------------------


def test_every_supported_type() -> None:
    assert schema_of(send) == {
        "type": "object",
        "properties": {
            "body": {"type": "string", "maxLength": 2200, "minLength": 1},
            "in_reply_to": {
                "type": "string",
                "maxLength": 250,
                "pattern": r"^(?:<[!-;=?-~]{1,250}@[!-;=?-~]{1,250}>)$",
            },
            "kind": {"type": "string", "enum": ["note", "reply"]},
            "records": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "amount": {"type": "integer", "minimum": 0, "maximum": 1000},
                        "day": {
                            "type": "string",
                            "maxLength": 10,
                            "minLength": 10,
                            "pattern": r"^(?:\d{4}-\d{2}-\d{2})$",
                        },
                        "title": {"type": "string", "maxLength": 150, "minLength": 1},
                    },
                    "required": ["amount", "title"],
                    "additionalProperties": False,
                },
                "minItems": 1,
                "maxItems": 3,
            },
            "subject": {"type": "string", "maxLength": 150, "minLength": 1},
            "urgent": {"type": "boolean"},
        },
        "required": ["body", "kind", "records", "subject", "urgent"],
        "additionalProperties": False,
    }


def test_no_parameters() -> None:
    async def ping(ctx: ToolContext) -> str:
        """Ping."""
        return ""

    assert schema_of(ping) == {"type": "object", "properties": {}, "additionalProperties": False}


async def _bare_str(ctx: ToolContext, x: str) -> str:
    return ""


async def _bare_int(ctx: ToolContext, x: int) -> str:
    return ""


async def _bare_list(ctx: ToolContext, x: list[Subject]) -> str:
    return ""


async def _float(ctx: ToolContext, x: float) -> str:
    return ""


async def _dict(ctx: ToolContext, x: dict[str, str]) -> str:
    return ""


async def _wrong_marker(ctx: ToolContext, x: Annotated[str, Range(ge=0, le=1)]) -> str:
    return ""


async def _two_markers(ctx: ToolContext, x: Annotated[str, Text(max=1), Text(max=2)]) -> str:
    return ""


async def _default(ctx: ToolContext, x: Subject = "hi") -> str:
    return ""


async def _optional_without_none(ctx: ToolContext, x: Subject | None) -> str:
    return ""


async def _two_types(ctx: ToolContext, x: Subject | Amount | None = None) -> str:
    return ""


async def _args(ctx: ToolContext, *x: Subject) -> str:
    return ""


async def _kwargs(ctx: ToolContext, **x: Subject) -> str:
    return ""


async def _untyped(ctx, x) -> str:  # type: ignore[no-untyped-def]
    return ""


async def _int_literal(ctx: ToolContext, x: Literal[1, 2]) -> str:
    return ""


async def _upper(ctx: ToolContext, X: Subject) -> str:
    return ""


class _Partial(TypedDict, total=False):
    a: Subject


class _OptionalField(TypedDict):
    a: Subject | None


class _Empty(TypedDict):
    pass


async def _partial(ctx: ToolContext, x: Annotated[list[_Partial], Batch(max=1)]) -> str:
    return ""


async def _optional_field(ctx: ToolContext, x: _OptionalField) -> str:
    return ""


async def _empty(ctx: ToolContext, x: _Empty) -> str:
    return ""


Deep = Annotated[
    list[Annotated[list[Annotated[list[Subject], Batch(max=1)]], Batch(max=1)]], Batch(max=1)
]


async def _deep(ctx: ToolContext, x: Annotated[list[Deep], Batch(max=1)]) -> str:
    return ""


@pytest.mark.parametrize(
    ("fn", "says"),
    [
        (_bare_str, "Text"),
        (_bare_int, "Range"),
        (_bare_list, "Batch"),
        (_float, "unsupported"),
        (_dict, "unsupported"),
        (_wrong_marker, "doesn't fit"),
        (_two_markers, "exactly"),
        (_default, "only default"),
        (_optional_without_none, "default is None"),
        (_two_types, "one T"),
        (_args, r"no \*args"),
        (_kwargs, r"no \*args"),
        (_untyped, "needs a type"),
        (_int_literal, "Literal of"),
        (_upper, "lower-case"),
        (_partial, "total"),
        (_optional_field, "NotRequired"),
        (_empty, "no fields"),
        (_deep, "deeper"),
    ],
)
def test_what_isnt_supported(fn: Any, says: str) -> None:
    with pytest.raises(TypeError, match=says):
        parameters(fn)


def test_the_first_parameter_is_the_context() -> None:
    async def keyword_only(*, ctx: ToolContext) -> str:
        return ""

    with pytest.raises(TypeError, match="context"):
        parameters(keyword_only)


@pytest.mark.parametrize(
    "build",
    [
        lambda: Text(max=-1),
        lambda: Text(max=1, min=2),
        lambda: Text(max=100_001),
        lambda: Text(max=5, pattern="^a"),
        lambda: Text(max=5, pattern="a$"),
        lambda: Text(max=5, pattern="("),
        lambda: Range(ge=2, le=1),
        lambda: Range(ge=0, le=MAX_SAFE_INTEGER + 1),
        lambda: Batch(max=0, min=1),
        lambda: Batch(max=1001),
    ],
)
def test_marker_limits(build: Any) -> None:
    with pytest.raises((TypeError, Exception)):
        build()


def test_markers_at_their_limits() -> None:
    Text(max=100_000)
    Text(max=0)
    Range(ge=-MAX_SAFE_INTEGER, le=MAX_SAFE_INTEGER)
    Batch(max=1000, min=0)


def test_descriptions_and_names() -> None:
    async def documented(ctx: ToolContext) -> str:
        """
        Two lines,
          indented.
        """
        return ""

    assert description(documented) == "Two lines,\n  indented."

    async def bare(ctx: ToolContext) -> str:
        return ""

    with pytest.raises(TypeError, match="docstring"):
        description(bare)
    bare.__doc__ = "x" * 1000
    assert description(bare) == "x" * 1000
    bare.__doc__ = "x" * 1001
    with pytest.raises(TypeError, match="docstring"):
        description(bare)
    bare.__doc__ = "a\x07b"  # a control character (cleandoc expands tabs)
    with pytest.raises(TypeError, match="docstring"):
        description(bare)
    assert tool_name("send_note.v2-x") == "send_note.v2-x"
    for bad in ("", "a b", "x" * 129, "é"):
        with pytest.raises(TypeError):
            tool_name(bad)


def test_prepare_takes_the_tools_parameters() -> None:
    async def prepare(ctx: Any, subject: Subject, body: Body) -> Any: ...
    async def tool(ctx: Any, subject: Subject, body: Body) -> str:
        return ""

    async def other(ctx: Any, subject: Subject) -> str:
        return ""

    async def plain(ctx: Any, subject: str, body: str) -> Any: ...
    async def optional(ctx: Any, subject: str, body: str | None = None) -> Any: ...
    async def defaulted(ctx: Any, subject: str, body: str = "x") -> Any: ...
    async def extra(ctx: Any, subject: str, body: str, more: str) -> Any: ...
    async def starred(ctx: Any, subject: str, *body: str) -> Any: ...

    assert same_parameters(parameters(tool), prepare)
    assert same_parameters(parameters(tool), plain)  # plain types: the tool's are checked
    assert not same_parameters(parameters(other), prepare)
    assert not same_parameters(parameters(tool), optional)  # body is required in the tool
    assert not same_parameters(parameters(tool), defaulted)
    assert not same_parameters(parameters(tool), extra)
    assert not same_parameters(parameters(tool), starred)

    async def tool_optional(ctx: Any, subject: Subject, body: Body | None = None) -> str:
        return ""

    assert same_parameters(parameters(tool_optional), optional)
    assert not same_parameters(parameters(tool_optional), plain)


# --- checking a call ----------------------------------------------------------------------------

GOOD: dict[str, Any] = {
    "subject": "Hello",
    "body": "Line one\n\tindented",
    "urgent": False,
    "kind": "note",
    "records": [{"title": "t", "amount": 0}, {"title": "u", "amount": 1000, "day": "2026-01-01"}],
}


def problems(**changes: Any) -> list[ArgumentProblem]:
    arguments = {**GOOD, **changes}
    for key in [k for k, v in changes.items() if v is ...]:
        del arguments[key]
    return check_arguments(parameters(send), arguments)


def test_a_good_call() -> None:
    assert problems() == []
    assert problems(in_reply_to="<a.b@mail.example>") == []


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"subject": ...}, [("/subject", "missing")]),
        ({"subject": 5}, [("/subject", "type")]),
        ({"subject": ""}, [("/subject", "text_rules")]),
        ({"subject": "a\nb"}, [("/subject", "text_rules")]),
        ({"subject": "x" * 151}, [("/subject", "text_rules")]),
        ({"subject": "a\u202eb"}, [("/subject", "text_rules")]),
        ({"body": "a\rb"}, [("/body", "text_rules")]),
        ({"urgent": 1}, [("/urgent", "type")]),
        ({"kind": "other"}, [("/kind", "enum")]),
        ({"kind": 1}, [("/kind", "type")]),
        ({"records": []}, [("/records", "batch_size")]),
        ({"records": [{"title": "t", "amount": 0}] * 4}, [("/records", "batch_size")]),
        ({"records": {"title": "t"}}, [("/records", "type")]),
        ({"records": ["x"]}, [("/records/0", "type")]),
        ({"records": [{"title": "t"}]}, [("/records/0/amount", "missing")]),
        ({"records": [{"title": "t", "amount": True}]}, [("/records/0/amount", "type")]),
        ({"records": [{"title": "t", "amount": -1}]}, [("/records/0/amount", "range")]),
        ({"records": [{"title": "t", "amount": 1001}]}, [("/records/0/amount", "range")]),
        ({"records": [{"title": "t", "amount": 1, "x": 1}]}, [("/records/0", "unknown_key")]),
        (
            {"records": [{"title": "t", "amount": 1, "day": "2026-1-1xx"}]},
            [("/records/0/day", "text_rules")],
        ),
        (
            {"records": [{"title": "t", "amount": 1, "day": "\uff12\uff10\uff12\uff16-01-01"}]},
            [("/records/0/day", "text_rules")],
        ),
        ({"in_reply_to": None}, [("/in_reply_to", "type")]),
        ({"in_reply_to": "<a@b> "}, [("/in_reply_to", "text_rules")]),
        ({"in_reply_to": "a@b"}, [("/in_reply_to", "text_rules")]),
        ({"extra": 1}, [("", "unknown_key")]),
    ],
)
def test_refusals(changes: dict[str, Any], expected: list[tuple[str, str]]) -> None:
    assert [(p.pointer, p.rule) for p in problems(**changes)] == expected


def test_a_problem_never_holds_the_value() -> None:
    [found] = problems(subject="secret-value\n")
    assert "secret-value" not in str(found)
    assert str(found) == "/subject: text_rules"
    assert str(ArgumentProblem("", "unknown_key")) == "/: unknown_key"


def test_ascii_only_and_pattern_are_whole_text() -> None:
    async def tool(
        ctx: ToolContext, x: Annotated[str, Text(max=10, ascii_only=True, pattern="[a-z]+")]
    ) -> str:
        """T."""
        return ""

    params = parameters(tool)
    assert check_arguments(params, {"x": "abc"}) == []
    assert check_arguments(params, {"x": "abc1"}) != []  # the pattern matches the whole text
    assert check_arguments(params, {"x": "é"}) != []


@given(st.text(max_size=160))
def test_a_subject_passes_exactly_when_the_text_rules_pass(subject: str) -> None:
    from zoeymcp.common.textrules import find_violations

    expected = not find_violations(subject, max_chars=150, min_chars=1, single_line=True)
    assert (problems(subject=subject) == []) == expected
