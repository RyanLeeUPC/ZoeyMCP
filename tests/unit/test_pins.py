"""The pin projection, pins, definition text rules and listing evaluation (M3 design G, J.3), and
the same for prompts, resource templates and fixed resources (M6 design L.2, L.4)."""

from __future__ import annotations

import copy
from typing import Any, cast

import pytest
from hypothesis import given
from hypothesis import strategies as st
from mcp.types import Prompt, Resource, ResourceTemplate, Tool

from zoeymcp.common import canonical, pinhash
from zoeymcp.common.policy import fields
from zoeymcp.common.policy.attention import Attention, attention, quiet
from zoeymcp.common.policy.schema import GatewayLimits, Tools
from zoeymcp.common.policy.view import ViewRemoteServer
from zoeymcp.gateway import pins
from zoeymcp.gateway.pins import (
    Evaluation,
    ProjectionError,
    Report,
    evaluate,
    pin_of,
    project,
    project_and_pin,
    text_problems,
    tool_problems,
)
from zoeymcp.gateway.toolkits import SelfPinned

LIMITS = GatewayLimits()
PIN_X = "sha256:" + "a" * 64
PIN_Y = "sha256:" + "b" * 64

WIRE: dict[str, Any] = {
    "name": "get_note",
    "title": "Get a note",
    "description": "Returns one note.",
    "inputSchema": {
        "type": "object",
        "properties": {"id": {"type": "string", "x-mcp-header": "Note-Id"}},
        "required": ["id"],
    },
    "outputSchema": {"type": "object", "properties": {"text": {"type": "string"}}},
    "annotations": {
        "title": "Note",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
}


def tool(**changes: Any) -> Tool:
    wire = copy.deepcopy(WIRE)
    for key, value in changes.items():
        if value is ...:
            wire.pop(key, None)
        else:
            wire[key] = value
    return Tool.model_validate(wire)


def wire_pin(**changes: Any) -> str:
    return project_and_pin(tool(**changes)).pin


# --- the projection --------------------------------------------------------------------------


def test_every_member_is_projected() -> None:
    assert project(tool()) == WIRE


def test_unpinned_members_are_stripped() -> None:
    raw = Tool.model_validate(
        {
            **WIRE,
            "icons": [{"src": "https://tracker.example/pixel.png"}],
            "_meta": {"x": 1},
            "execution": {"taskSupport": "optional"},
            "unknown": "member",
        }
    )
    assert raw.icons
    assert raw.meta
    assert project(raw) == WIRE


def test_the_minimum_is_name_and_input_schema() -> None:
    raw = Tool.model_validate({"name": "a", "inputSchema": {"type": "object"}})
    assert project(raw) == {"name": "a", "inputSchema": {"type": "object"}}


@pytest.mark.parametrize("member", ["title", "description", "outputSchema", "annotations"])
def test_null_means_absent(member: str) -> None:
    expected = copy.deepcopy(WIRE)
    del expected[member]
    assert project(tool(**{member: None})) == expected
    assert wire_pin(**{member: None}) == wire_pin(**{member: ...})


def test_null_annotation_members_are_left_out() -> None:
    raw = tool(annotations={"title": None, "readOnlyHint": True, "openWorldHint": None})
    assert project(raw)["annotations"] == {"readOnlyHint": True}


def test_annotations_with_nothing_left_are_left_out() -> None:
    assert "annotations" not in project(tool(annotations={"title": None}))
    assert "annotations" not in project(tool(annotations={}))


def test_unknown_annotation_members_are_stripped() -> None:
    raw = tool(annotations={"readOnlyHint": False, "audience": ["user"], "priority": 1})
    assert project(raw)["annotations"] == {"readOnlyHint": False}


def test_false_hints_are_kept() -> None:
    hints = {member: False for member, _ in pins.HINTS}
    assert project(tool(annotations=hints))["annotations"] == hints


def test_inside_schemas_every_value_is_kept_as_is() -> None:
    schema = {
        "type": "object",
        "properties": {"a": {"default": None, "description": None, "examples": [1, 2.0, None]}},
        "x-vendor": {"nested": [None]},
    }
    assert project(tool(inputSchema=schema))["inputSchema"] == schema


def test_the_projection_is_a_copy() -> None:
    raw = tool()
    projection = project(raw)
    projection["inputSchema"]["properties"]["id"]["type"] = "integer"
    projection["outputSchema"]["type"] = "array"
    assert raw.input_schema["properties"]["id"]["type"] == "string"
    assert raw.output_schema is not None
    assert raw.output_schema["type"] == "object"


@pytest.mark.parametrize("name", ["", "a b", "a/b", "caf\u00e9", "x" * 129, "a\n"])
def test_an_invalid_name_is_refused(name: str) -> None:
    with pytest.raises(ProjectionError, match="name"):
        project(tool(name=name))


@pytest.mark.parametrize("name", ["a", "A-Z_0.9", "x" * 128])
def test_valid_names(name: str) -> None:
    assert project(tool(name=name))["name"] == name


@pytest.mark.parametrize(
    "schema", [{}, {"type": "array"}, {"type": ["object"]}, {"properties": {}}]
)
def test_the_input_root_must_be_an_object_schema(schema: dict[str, Any]) -> None:
    with pytest.raises(ProjectionError, match="inputSchema"):
        project(tool(inputSchema=schema))


def test_wrong_types_are_refused_even_when_the_sdk_lets_them_through() -> None:
    # model_construct skips validation, as a future SDK path might.
    base = tool()
    cases: list[tuple[dict[str, Any], str]] = [
        ({"name": 5}, "name"),
        ({"title": 5}, "title"),
        ({"description": ["x"]}, "description"),
        ({"input_schema": ["x"]}, "inputSchema"),
        ({"output_schema": ["x"]}, "outputSchema"),
    ]
    for changes, member in cases:
        broken = base.model_copy(update=changes)
        with pytest.raises(ProjectionError, match=member):
            project(broken)
    assert base.annotations is not None
    annotation_cases: list[tuple[dict[str, Any], str]] = [
        ({"title": 5}, "annotations.title"),
        ({"read_only_hint": "yes"}, "readOnlyHint"),
    ]
    for update, member in annotation_cases:
        broken = base.model_copy(update={"annotations": base.annotations.model_copy(update=update)})
        with pytest.raises(ProjectionError, match=member):
            project(broken)


# --- pins ------------------------------------------------------------------------------------


def test_the_pin_is_the_tagged_digest() -> None:
    projection = project(tool())
    assert pin_of(projection) == canonical.digest({"zoeymcp": "tool-pin/1", "tool": projection})
    assert pin_of(projection) != canonical.digest(projection)
    assert project_and_pin(tool()).definition == projection


def test_key_order_never_matters() -> None:
    reordered = dict(reversed(list(WIRE.items())))
    reordered["inputSchema"] = dict(reversed(list(WIRE["inputSchema"].items())))
    assert project_and_pin(Tool.model_validate(reordered)).pin == wire_pin()


def test_array_order_matters() -> None:
    a = {"type": "object", "properties": {"x": {"enum": ["a", "b"]}}, "required": ["x", "y"]}
    b = {"type": "object", "properties": {"x": {"enum": ["b", "a"]}}, "required": ["x", "y"]}
    c = {"type": "object", "properties": {"x": {"enum": ["a", "b"]}}, "required": ["y", "x"]}
    assert len({wire_pin(inputSchema=a), wire_pin(inputSchema=b), wire_pin(inputSchema=c)}) == 3


def test_an_integer_and_a_float_pin_differently() -> None:
    one = {"type": "object", "properties": {"x": {"maximum": 1}}}
    other = {"type": "object", "properties": {"x": {"maximum": 1.0}}}
    assert wire_pin(inputSchema=one) != wire_pin(inputSchema=other)


@pytest.mark.parametrize(
    "value",
    [2**53, "\ud800"],
)
def test_no_canonical_form_makes_the_tool_invalid(value: Any) -> None:
    raw = tool(inputSchema={"type": "object", "x": value})
    with pytest.raises(ProjectionError, match="canonical"):
        project_and_pin(raw)


def test_too_deep_for_the_encoder_is_invalid() -> None:
    deep: Any = {}
    for _ in range(70):
        deep = {"d": deep}
    with pytest.raises(ProjectionError, match="canonical"):
        project_and_pin(tool(inputSchema={"type": "object", "x": deep}))


_CHANGES: list[dict[str, Any]] = [
    {"name": "get_notes"},
    {"title": "Get a note!"},
    {"title": ...},
    {"description": "Returns one note. "},
    {"description": ...},
    {"inputSchema": {**WIRE["inputSchema"], "required": []}},
    {"inputSchema": {**WIRE["inputSchema"], "properties": {"id": {"type": "string"}}}},
    {"inputSchema": {**WIRE["inputSchema"], "properties": {"ID": {"type": "string"}}}},
    {"outputSchema": ...},
    {"outputSchema": {"type": "object"}},
    {"annotations": ...},
    {"annotations": {**WIRE["annotations"], "title": "Notes"}},
    *(
        {"annotations": {**WIRE["annotations"], member: not WIRE["annotations"][member]}}
        for member, _ in pins.HINTS
    ),
    *({"annotations": {**WIRE["annotations"], member: None}} for member, _ in pins.HINTS),
]


@pytest.mark.parametrize("changes", _CHANGES)
def test_a_change_to_any_member_changes_the_pin(changes: dict[str, Any]) -> None:
    assert wire_pin(**changes) != wire_pin()


_JSON = st.recursive(
    st.none() | st.booleans() | st.integers(-(2**53) + 1, 2**53 - 1) | st.text(max_size=8),
    lambda children: (
        st.lists(children, max_size=3) | st.dictionaries(st.text(max_size=5), children, max_size=3)
    ),
    max_leaves=10,
)


@given(key=st.text(min_size=1, max_size=8), value=_JSON)
def test_property_any_schema_change_changes_the_pin(key: str, value: Any) -> None:
    schema = copy.deepcopy(WIRE["inputSchema"])
    changed = {**schema, "x-" + key: value}
    assert wire_pin(inputSchema=changed) != wire_pin(inputSchema=schema)


# --- text rules (J.3) ------------------------------------------------------------------------


def problems_of(definition: dict[str, Any]) -> list[tuple[str, str]]:
    return [(problem.pointer, problem.violation.reason) for problem in text_problems(definition)]


def test_a_clean_definition_has_no_text_problems() -> None:
    assert text_problems(project(tool())) == []


def test_every_string_is_checked_values_and_keys() -> None:
    definition = project(tool())
    definition["inputSchema"]["properties"]["i\u200bd"] = {
        "enum": ["a\u202eb"],
        "default": "\u2066",
        "const": "x\u0007",
    }
    definition["inputSchema"]["examples"] = [{"k": "\u2028"}]
    assert problems_of(definition) == [
        ("/inputSchema/examples/0/k", "line separator"),
        ("/inputSchema/properties/i\u200bd", "format character (zero-width, bidi or tag)"),
        ("/inputSchema/properties/i\u200bd/const", "control character"),
        ("/inputSchema/properties/i\u200bd/default", "format character (zero-width, bidi or tag)"),
        ("/inputSchema/properties/i\u200bd/enum/0", "format character (zero-width, bidi or tag)"),
    ]


def test_top_level_text_is_checked() -> None:
    definition = project(tool())
    definition["description"] = "Returns\u00a0\u3164 one note."
    definition["annotations"]["title"] = "\ue000"
    assert problems_of(definition) == [
        ("/annotations/title", "private-use character"),
        ("/description", "invisible character"),
    ]


def test_tabs_are_allowed_but_not_in_single_line_fields() -> None:
    definition = project(tool())
    definition["description"] = "a\tb\nc"
    definition["inputSchema"]["properties"]["id"]["description"] = "a\tb\nc"
    assert text_problems(definition) == []
    definition["title"] = "a\tb"
    definition["annotations"]["title"] = "a\nb"
    assert problems_of(definition) == [
        ("/annotations/title", "line break in a single-line field"),
        ("/title", "tab not allowed here"),
    ]


@pytest.mark.parametrize(
    ("path", "limit"),
    [
        (("title",), pins.MAX_TITLE_CHARS),
        (("annotations", "title"), pins.MAX_TITLE_CHARS),
        (("description",), pins.MAX_DESCRIPTION_CHARS),
        (("inputSchema", "properties", "id", "description"), pins.MAX_SCHEMA_TEXT_CHARS),
        (("outputSchema", "title"), pins.MAX_SCHEMA_TEXT_CHARS),
    ],
)
def test_length_limits(path: tuple[str, ...], limit: int) -> None:
    def with_text(text: str) -> dict[str, Any]:
        definition = project(tool())
        node = definition
        for part in path[:-1]:
            node = node[part]
        node[path[-1]] = text
        return definition

    assert text_problems(with_text("x" * limit)) == []
    [problem] = text_problems(with_text("x" * (limit + 1)))
    assert problem.pointer == "/" + "/".join(path)
    assert "too long" in problem.violation.reason


def test_the_limits_are_the_design_values() -> None:
    assert (pins.MAX_NAME_CHARS, pins.MAX_TITLE_CHARS) == (128, 256)
    assert (pins.MAX_DESCRIPTION_CHARS, pins.MAX_SCHEMA_TEXT_CHARS) == (16_384, 4096)


def test_a_long_key_is_held_to_the_schema_limit() -> None:
    definition = project(tool())
    definition["inputSchema"]["properties"]["k" * 4097] = {}
    [problem] = text_problems(definition)
    assert "too long" in problem.violation.reason
    # A key named like a top-level field gets the schema limit, not that field's.
    definition = project(tool())
    definition["inputSchema"]["properties"] = {"description": {"title": "t" * 300}}
    assert text_problems(definition) == []


def test_a_text_problem_prints_its_pointer_revealed() -> None:
    definition = project(tool())
    definition["inputSchema"]["properties"]["a\u200b"] = {}
    [problem] = text_problems(definition)
    assert str(problem).startswith("/inputSchema/properties/a[U+200B]: ")
    assert "\u200b" not in str(problem)


def test_walk_strings_marks_keys() -> None:
    found = sorted(pins.walk_strings({"a": ["b", {"c": "d"}], "e": 1}))
    assert found == [
        (("a",), "a", True),
        (("a", 0), "b", False),
        (("a", 1, "c"), "c", True),
        (("a", 1, "c"), "d", False),
        (("e",), "e", True),
    ]


# --- tool problems ---------------------------------------------------------------------------


def test_tool_problems_cover_text_and_both_schemas() -> None:
    definition = project(tool())
    assert tool_problems(definition, LIMITS) == []
    definition["description"] = "\u200b"
    definition["inputSchema"]["$id"] = "https://x.example/s"
    definition["outputSchema"]["$ref"] = "https://x.example/s"
    assert tool_problems(definition, LIMITS) == [
        "/description: format character (zero-width, bidi or tag) U+200B (ZERO WIDTH SPACE) at "
        "position 0",
        "/inputSchema/$id: $id is not supported",
        "/outputSchema/$ref: $ref must be a local JSON pointer to a subschema of the same schema",
    ]


def test_an_output_schema_need_not_be_an_object_type() -> None:
    definition = project(tool(outputSchema={"type": "array"}))
    assert tool_problems(definition, LIMITS) == []


# --- evaluating a listing (G.2) --------------------------------------------------------------


def server(
    include: list[str],
    review: dict[str, str],
    on_drift: str = "hide",
    declined: dict[str, str] | None = None,
) -> ViewRemoteServer:
    return ViewRemoteServer.model_validate(
        {
            "kind": "remote",
            "vault_path": "/notes/mcp",
            "tools": {"include": include, "allow": include, "approve": []},
            "review": review,
            "declined": declined or {},
            "on_drift": on_drift,
            "shared_session": False,
            "wrap_results": False,
            "enable": [],
            "era": "auto",
            "drift_check_interval": 300,
            "call_timeout": None,
        }
    )


def named(name: str, **changes: Any) -> Tool:
    return tool(name=name, **changes)


def pin(name: str, **changes: Any) -> str:
    return wire_pin(name=name, **changes)


def kinds(evaluation: Evaluation) -> list[tuple[str, str]]:
    return [(report.kind, report.tool) for report in evaluation.reports]


def test_a_matching_included_tool_is_exposed() -> None:
    result = evaluate([named("a")], server(["a"], {"a": pin("a")}), set(), LIMITS)
    assert set(result.exposed) == {"a"}
    assert result.exposed["a"].pin == pin("a")
    assert result.exposed["a"].definition == project(named("a"))
    assert result.reports == ()
    assert result.marks == frozenset()
    assert result.blocked is False


def test_every_report_kind() -> None:
    bad = named("bad", description="\u200b")
    listing = [named("ok"), named("new"), named("dup"), named("dup"), named("changed"), bad]
    policy = server(
        ["ok", "dup", "changed", "bad", "gone"],
        {
            "ok": pin("ok"),
            "dup": pin("dup"),
            "changed": pin("changed", description="Old."),
            "bad": pin("bad"),
            "gone": pin("gone"),
        },
    )
    result = evaluate(listing, policy, set(), LIMITS)
    assert set(result.exposed) == {"ok"}
    assert kinds(result) == [
        ("unreviewed", "new"),
        ("duplicate", "dup"),
        ("drift", "changed"),
        ("invalid", "bad"),
        ("missing", "gone"),
    ]
    by_tool = {report.tool: report for report in result.reports}
    assert by_tool["new"] == Report("unreviewed", "new", pin=pin("new"))
    assert by_tool["dup"] == Report("duplicate", "dup")
    assert by_tool["changed"] == Report(
        "drift", "changed", pin=pin("changed"), pinned=pin("changed", description="Old.")
    )
    assert by_tool["bad"].pin == project_and_pin(bad).pin
    assert by_tool["bad"].reasons == (
        "/description: format character (zero-width, bidi or tag) U+200B (ZERO WIDTH SPACE) at "
        "position 0",
    )
    assert by_tool["gone"] == Report("missing", "gone", pinned=pin("gone"))
    assert result.marks == {("changed", pin("changed", description="Old."))}
    assert result.blocked is False


def test_an_unprojectable_tool_is_invalid() -> None:
    broken = named("a").model_copy(update={"input_schema": {"type": "array"}})
    result = evaluate([broken], server(["a"], {"a": pin("a")}), set(), LIMITS)
    [report] = result.reports
    assert (report.kind, report.tool, report.pin) == ("invalid", "a", None)
    assert report.reasons == ('inputSchema is not an object schema with "type": "object"',)
    assert result.exposed == {}


def test_a_non_string_name_is_reported_as_empty() -> None:
    broken = named("a").model_copy(update={"name": 5})
    [report] = evaluate([broken], server([], {}), set(), LIMITS).reports
    assert (report.kind, report.tool) == ("invalid", "")


def test_three_of_a_name_is_one_duplicate_report() -> None:
    result = evaluate([named("d")] * 3, server(["d"], {"d": pin("d")}), set(), LIMITS)
    assert kinds(result) == [("duplicate", "d")]
    assert result.exposed == {}


def test_an_included_tool_without_a_pin_is_unreviewed() -> None:
    result = evaluate([named("a")], server(["a"], {}), set(), LIMITS)
    assert kinds(result) == [("unreviewed", "a")]
    assert result.marks == frozenset()


def test_a_pin_without_include_is_unreviewed() -> None:
    result = evaluate([named("a")], server([], {"a": pin("a")}), set(), LIMITS)
    assert kinds(result) == [("unreviewed", "a")]
    assert result.exposed == {}


def test_a_tool_declined_at_its_pin_is_declined_and_hidden() -> None:
    """M6 design J.5: the operator saw it and left it out, at this pin."""
    result = evaluate(
        [named("a"), named("b")],
        server(["b"], {"b": pin("b")}, declined={"a": pin("a")}),
        set(),
        LIMITS,
    )
    assert result.reports == (Report("declined", "a", pin=pin("a")),)
    assert set(result.exposed) == {"b"}
    assert result.marks == frozenset()


def test_a_declined_tool_that_changed_is_unreviewed_again() -> None:
    old = pin("a", description="Old.")
    result = evaluate([named("a")], server([], {}, declined={"a": old}), set(), LIMITS)
    assert result.reports == (Report("unreviewed", "a", pin=pin("a")),)
    assert result.exposed == {}


def test_an_included_tool_isnt_declined() -> None:
    """Included and declined both (check refuses it): the include and its pin decide."""
    policy = server(["a"], {"a": pin("a")}, declined={"a": pin("a")})
    result = evaluate([named("a")], policy, set(), LIMITS)
    assert (set(result.exposed), result.reports) == ({"a"}, ())
    drifted = server(["a"], {"a": pin("a", description="Old.")}, declined={"a": pin("a")})
    assert kinds(evaluate([named("a")], drifted, set(), LIMITS)) == [("drift", "a")]


def test_a_declined_tool_that_cant_be_pinned_is_invalid() -> None:
    bad = named("a", description="\u200b")
    policy = server([], {}, declined={"a": project_and_pin(bad).pin})
    assert kinds(evaluate([bad], policy, set(), LIMITS)) == [("invalid", "a")]


def test_every_listed_name_with_its_pin() -> None:
    """What the attention decision reads: None for a tool that can't be pinned."""
    broken = named("x").model_copy(update={"input_schema": {"type": "array"}})
    listing = [named("a"), named("d"), named("d"), named("b", description="\u200b"), broken]
    result = evaluate(listing, server(["a"], {"a": pin("a")}), set(), LIMITS)
    assert result.listed == {"a": pin("a"), "d": None, "b": None, "x": None}
    assert evaluate([], server(["a"], {"a": pin("a")}), set(), LIMITS).listed == {}


@pytest.mark.parametrize("on_drift", ["hide", "fail"])
@pytest.mark.parametrize("bad", ["invalid", "duplicate"])
def test_an_included_tool_that_cant_be_pinned_needs_the_operator(on_drift: str, bad: str) -> None:
    """Hidden (or the server blocked), so the attention decision isn't quiet (J.5, Y29)."""
    listing = [named("a", description="\u200b")] if bad == "invalid" else [named("a")] * 2
    policy = server(["a"], {"a": pin("a")}, on_drift)
    result = evaluate(listing, policy, set(), LIMITS)
    assert (result.exposed, result.blocked) == ({}, on_drift == "fail")
    found = attention(result.listed, policy, result.marks)
    assert found == Attention(drifted=("a",))
    assert not quiet(found)


def test_a_drift_mark_is_sticky() -> None:
    old = pin("a", description="Old.")
    policy = server(["a"], {"a": old})
    first = evaluate([named("a")], policy, set(), LIMITS)
    assert first.marks == {("a", old)}
    # The upstream flips back to the reviewed definition: still hidden, mark still held.
    back = evaluate([named("a", description="Old.")], policy, first.marks, LIMITS)
    assert back.exposed == {}
    assert back.reports == ()
    assert back.marks == {("a", old)}


def test_a_mark_clears_when_the_policy_pin_changes() -> None:
    old = pin("a", description="Old.")
    repinned = server(["a"], {"a": pin("a")})
    result = evaluate([named("a")], repinned, {("a", old)}, LIMITS)
    assert set(result.exposed) == {"a"}
    assert result.marks == frozenset()


def test_marks_for_other_tools_are_kept_while_their_pins_hold() -> None:
    policy = server(["a", "b"], {"a": pin("a"), "b": pin("b")})
    result = evaluate([named("a"), named("b")], policy, {("b", pin("b"))}, LIMITS)
    assert set(result.exposed) == {"a"}
    assert result.marks == {("b", pin("b"))}
    # A mark for a tool with no pin at all has cleared.
    assert evaluate([], policy, {("c", pin("c"))}, LIMITS).marks == frozenset()


def test_missing_tools_are_reported_in_order() -> None:
    result = evaluate([], server(["b", "a"], {"a": pin("a"), "b": pin("b")}), set(), LIMITS)
    assert kinds(result) == [("missing", "a"), ("missing", "b")]


def test_an_invalid_tool_is_not_missing() -> None:
    bad = named("a", description="\u200b")
    result = evaluate([bad], server(["a"], {"a": pin("a")}), set(), LIMITS)
    assert kinds(result) == [("invalid", "a")]


def test_on_drift_fail_blocks_on_drift() -> None:
    policy = server(["a", "b"], {"a": pin("a"), "b": pin("b", description="Old.")}, "fail")
    result = evaluate([named("a"), named("b")], policy, set(), LIMITS)
    assert result.blocked is True
    assert result.exposed == {}
    assert kinds(result) == [("drift", "b")]


def test_on_drift_fail_blocks_on_a_held_mark() -> None:
    policy = server(["a", "b"], {"a": pin("a"), "b": pin("b")}, "fail")
    result = evaluate([named("a"), named("b")], policy, {("b", pin("b"))}, LIMITS)
    assert result.blocked is True
    assert result.exposed == {}


@pytest.mark.parametrize("listing_extra", ["invalid", "duplicate"])
def test_on_drift_fail_blocks_on_an_included_bad_tool(listing_extra: str) -> None:
    extra = [named("b", description="\u200b")] if listing_extra == "invalid" else [named("b")] * 2
    policy = server(["a", "b"], {"a": pin("a"), "b": pin("b")}, "fail")
    result = evaluate([named("a"), *extra], policy, set(), LIMITS)
    assert result.blocked is True
    assert result.exposed == {}


@pytest.mark.parametrize("listing_extra", ["invalid", "duplicate", "unreviewed", "missing"])
def test_on_drift_fail_ignores_tools_outside_include(listing_extra: str) -> None:
    extras = {
        "invalid": [named("b", description="\u200b")],
        "duplicate": [named("b")] * 2,
        "unreviewed": [named("b")],
        "missing": [],
    }
    include = ["a", "b"] if listing_extra == "missing" else ["a"]
    review = {"a": pin("a"), "b": pin("b")}
    listing = [named("a"), *extras[listing_extra]]
    result = evaluate(listing, server(include, review, "fail"), set(), LIMITS)
    assert result.blocked is False
    assert set(result.exposed) == {"a"}


def test_on_drift_hide_never_blocks() -> None:
    policy = server(["a", "b"], {"a": pin("a"), "b": pin("b", description="Old.")})
    result = evaluate([named("a"), named("b"), named("b", title="x")], policy, set(), LIMITS)
    assert result.blocked is False
    assert set(result.exposed) == {"a"}


def test_schema_limits_come_from_the_limits() -> None:
    policy = server(["a"], {"a": pin("a")})
    tight = GatewayLimits(max_schema_bytes=1024, max_subschemas=16, max_schema_depth=4)
    assert set(evaluate([named("a")], policy, set(), tight).exposed) == {"a"}
    deep = {"type": "object", "properties": {"x": {"properties": {"y": {"properties": {}}}}}}
    result = evaluate([named("a", inputSchema=deep)], server(["a"], {}), set(), tight)
    [report] = result.reports
    assert report.kind == "invalid"
    assert report.reasons == ("/inputSchema: nested 6 levels, limit 4",)


# --- prompts and resources: projections (M6 design L.2) -----------------------------------------

PROMPT_WIRE: dict[str, Any] = {
    "name": "summarize",
    "title": "Summarize",
    "description": "Summarizes a note.",
    "arguments": [
        {"name": "style", "title": "Style", "description": "How.", "required": False},
        {"name": "id", "required": True},
        {"name": "lang"},
    ],
}
TEMPLATE_WIRE: dict[str, Any] = {
    "uriTemplate": "notes://notes/{id}",
    "name": "note",
    "title": "A note",
    "description": "One note.",
    "mimeType": "text/markdown",
    "annotations": {"audience": ["assistant", "user"], "priority": 0.25},
}
RESOURCE_WIRE: dict[str, Any] = {
    "uri": "notes://index",
    "name": "index",
    "title": "Index",
    "description": "Every note.",
    "mimeType": "application/json",
    "annotations": {"audience": ["user"], "priority": 0.5},
}
UNPINNED = {"icons": [{"src": "https://icons.example/p.png"}], "_meta": {"k": "v"}, "x": 1}


def prompt(**changes: Any) -> Prompt:
    wire = copy.deepcopy(PROMPT_WIRE)
    wire.update(changes)
    return Prompt.model_validate({key: value for key, value in wire.items() if value is not ...})


def template(**changes: Any) -> ResourceTemplate:
    wire = copy.deepcopy(TEMPLATE_WIRE)
    wire.update(changes)
    return ResourceTemplate.model_validate(
        {key: value for key, value in wire.items() if value is not ...}
    )


def resource(**changes: Any) -> Resource:
    wire = copy.deepcopy(RESOURCE_WIRE)
    wire.update(changes)
    return Resource.model_validate({key: value for key, value in wire.items() if value is not ...})


def test_a_prompts_pinned_members_are_projected_in_listed_order() -> None:
    assert pins.project_prompt(prompt(**UNPINNED)) == PROMPT_WIRE
    assert pins.project_prompt(prompt(title=None, description=None, arguments=None)) == {
        "name": "summarize"
    }
    assert pins.project_prompt(prompt(arguments=[]))["arguments"] == []


def test_a_prompt_argument_drops_its_null_members_and_keeps_required_false() -> None:
    raw = prompt(arguments=[{"name": "a", "title": None, "description": None, "required": None}])
    assert pins.project_prompt(raw)["arguments"] == [{"name": "a"}]
    raw = prompt(arguments=[{"name": "a", "required": False}])
    assert pins.project_prompt(raw)["arguments"] == [{"name": "a", "required": False}]


@pytest.mark.parametrize(
    "name", ["", "a b", "x" * 129, "a\n"], ids=["empty", "space", "long", "line-break"]
)
def test_a_prompt_needs_a_prompt_name(name: str) -> None:
    with pytest.raises(ProjectionError) as caught:
        pins.project_prompt(prompt(name=name))
    assert str(caught.value) == "name is not a valid prompt name"
    with pytest.raises(ProjectionError):
        pins.project_prompt(prompt().model_copy(update={"name": 5}))


def test_a_prompt_whose_members_arent_what_the_sdk_parses_is_refused() -> None:
    raw = prompt()
    assert raw.arguments is not None
    cases = [
        (raw.model_copy(update={"title": 5}), "title is not a string"),
        (
            raw.model_copy(update={"arguments": [raw.arguments[0].model_copy(update={"name": 1})]}),
            "arguments[0].name is not a string",
        ),
        (
            raw.model_copy(
                update={
                    "arguments": [
                        *raw.arguments[:1],
                        raw.arguments[1].model_copy(update={"required": 1}),
                    ]
                }
            ),
            "arguments[1].required is not a boolean",
        ),
        (
            raw.model_copy(
                update={"arguments": [raw.arguments[0].model_copy(update={"title": 2})]}
            ),
            "title is not a string",
        ),
    ]
    for broken, message in cases:
        with pytest.raises(ProjectionError) as caught:
            pins.project_prompt(broken)
        assert str(caught.value) == message


def test_a_templates_pinned_members_are_projected() -> None:
    raw = template(**UNPINNED, annotations={**TEMPLATE_WIRE["annotations"], "lastModified": "x"})
    assert pins.project_template(raw) == TEMPLATE_WIRE
    minimal = template(title=None, description=None, mimeType=None, annotations=None)
    assert pins.project_template(minimal) == {"uriTemplate": "notes://notes/{id}", "name": "note"}


def test_a_fixed_resources_pinned_members_are_projected() -> None:
    raw = resource(**UNPINNED, size=12)
    assert pins.project_resource(raw) == RESOURCE_WIRE
    assert pins.project_resource(resource(annotations={"lastModified": "x"})) == {
        key: value for key, value in RESOURCE_WIRE.items() if key != "annotations"
    }


@pytest.mark.parametrize("make", [template, resource], ids=["template", "resource"])
def test_a_whole_priority_is_projected_as_the_float_the_sdk_parsed(make: Any) -> None:
    """Step 18's review S18-1: canonical JSON writes 1 and 1.0 apart, so the projection reads the
    parsed model's float, never the wire's number."""
    raw = make(annotations={"priority": 1})
    projected = pins.PROJECTIONS["resource" if make is resource else "resource_template"](raw)
    assert projected["annotations"] == {"priority": 1.0}
    assert type(projected["annotations"]["priority"]) is float
    assert b'"priority":1.0' in canonical.dumps_canonical(projected)
    forced = raw.model_copy(
        update={"annotations": raw.annotations.model_copy(update={"priority": 1})}
    )
    assert (
        type(
            pins.PROJECTIONS["resource" if make is resource else "resource_template"](forced)[
                "annotations"
            ]["priority"]
        )
        is float
    )


@pytest.mark.parametrize("value", [True, "1"])
def test_a_priority_that_isnt_a_number_is_refused(value: object) -> None:
    raw = resource()
    assert raw.annotations is not None
    broken = raw.model_copy(
        update={"annotations": raw.annotations.model_copy(update={"priority": value})}
    )
    with pytest.raises(ProjectionError) as caught:
        pins.project_resource(broken)
    assert str(caught.value) == "annotations.priority is not a number"


def test_an_audience_is_kept_in_its_order() -> None:
    assert pins.project_resource(resource(annotations={"audience": ["assistant", "user"]}))[
        "annotations"
    ] == {"audience": ["assistant", "user"]}


@pytest.mark.parametrize(
    "uri_template",
    ["notes://files/{+path}", "notes://n/{id}?q=1", "notes", "notes://n/x{id}", "notes://n/{a b}"],
)
def test_a_template_outside_the_level_1_form_is_refused(uri_template: str) -> None:
    with pytest.raises(ProjectionError) as caught:
        pins.project_template(template(uriTemplate=uri_template))
    assert str(caught.value).startswith("uriTemplate: a resource template here is ")
    assert uri_template not in str(caught.value)


@pytest.mark.parametrize("uri", ["notes://u@h/x", "notes://index#top", "index", "notes://in dex"])
def test_a_fixed_uri_outside_the_form_is_refused(uri: str) -> None:
    with pytest.raises(ProjectionError) as caught:
        pins.project_resource(resource(uri=uri))
    assert str(caught.value) == f"uri: {fields.RESOURCE_URI_FORM}"


def test_a_resource_whose_members_arent_strings_is_refused() -> None:
    cases = [
        (template().model_copy(update={"uri_template": 1}), "uriTemplate is not a string"),
        (resource().model_copy(update={"uri": 1}), "uri is not a string"),
        (resource().model_copy(update={"name": 1}), "name is not a string"),
        (template().model_copy(update={"name": None}), "name is not a string"),
        (resource().model_copy(update={"mime_type": 1}), "mimeType is not a string"),
    ]
    for broken, message in cases:
        kind: pins.DefinitionKind = (
            "resource_template" if isinstance(broken, ResourceTemplate) else "resource"
        )
        with pytest.raises(ProjectionError) as caught:
            pins.project_kind(kind, broken)
        assert str(caught.value) == message


def test_each_kind_pins_under_its_own_tag() -> None:
    cases: list[tuple[pins.DefinitionKind, Any, Any]] = [
        ("tool", tool(), pinhash.pin_of),
        ("prompt", prompt(), pinhash.prompt_pin_of),
        ("resource_template", template(), pinhash.template_pin_of),
        ("resource", resource(), pinhash.resource_pin_of),
    ]
    for kind, item, pin_of_kind in cases:
        projected = pins.project_kind(kind, item)
        assert projected.definition == pins.PROJECTIONS[kind](item)
        assert projected.pin == pin_of_kind(projected.definition)
        assert pinhash.pin_for(kind, projected.definition) == projected.pin


def test_the_key_of_each_kind() -> None:
    assert pins.key_of("tool", tool()) == "get_note"
    assert pins.key_of("prompt", prompt()) == "summarize"
    assert pins.key_of("resource_template", template()) == "notes://notes/{id}"
    assert pins.key_of("resource", resource()) == "notes://index"
    assert pins.key_of("resource", resource().model_copy(update={"uri": 5})) == ""
    assert pinhash.KEY_MEMBERS == {
        "tool": "name",
        "prompt": "name",
        "resource_template": "uriTemplate",
        "resource": "uri",
    }


def test_the_kinds_text_rules() -> None:
    """A prompt argument's name and title, and a mimeType, are single-line like a tool's name and
    title; an argument's description is held to the schema text limit."""
    definition = pins.project_prompt(prompt())
    definition["arguments"][0].update(
        name="a\tb", title="t" * 257, description="line\n" + "d" * (pins.MAX_SCHEMA_TEXT_CHARS - 5)
    )
    definition["arguments"][1]["name"] = "n" * 129
    assert problems_of(definition) == [
        ("/arguments/0/name", "tab not allowed here"),
        ("/arguments/0/title", f"too long: 257 characters, limit {pins.MAX_TITLE_CHARS}"),
        ("/arguments/1/name", f"too long: 129 characters, limit {pins.MAX_NAME_CHARS}"),
    ]
    definition = pins.project_prompt(prompt())
    definition["arguments"][0]["title"] = "a\nb"
    assert problems_of(definition) == [("/arguments/0/title", "line break in a single-line field")]
    resource_definition = pins.project_resource(resource())
    resource_definition["mimeType"] = "text/plain\n"
    assert problems_of(resource_definition) == [("/mimeType", "line break in a single-line field")]
    resource_definition["mimeType"] = "m" * 257
    [problem] = text_problems(resource_definition)
    assert "too long" in problem.violation.reason
    # Under an argument, a key named like a member gets the schema limit, not that member's.
    assert pins._text_limits(("arguments", 0, "name"), True) == (pins.MAX_SCHEMA_TEXT_CHARS, False)
    assert pins._text_limits(("arguments", 0, "description"), False) == (
        pins.MAX_SCHEMA_TEXT_CHARS,
        False,
    )
    assert pins._text_limits(("x", 0, "name"), False) == (pins.MAX_SCHEMA_TEXT_CHARS, False)
    assert pins._text_limits(("arguments", "name"), False) == (pins.MAX_SCHEMA_TEXT_CHARS, False)


def test_definition_problems_are_a_tools_or_the_text_rules() -> None:
    definition = project(tool(description="\u200b"))
    definition["inputSchema"]["$id"] = "https://x.example/s"
    assert pins.definition_problems("tool", definition, LIMITS) == tool_problems(definition, LIMITS)
    held = {"name": "a", "description": "\u200b", "inputSchema": {"$id": "x"}}
    assert pins.definition_problems("prompt", held, LIMITS) == [
        "/description: format character (zero-width, bidi or tag) U+200B (ZERO WIDTH SPACE) at "
        "position 0"
    ]


# --- prompts and resources: evaluating (M6 design L.4) ------------------------------------------


def kinds_server(
    on_drift: str = "hide",
    *,
    tools: tuple[list[str], dict[str, str]] = ([], {}),
    prompts: dict[str, Any] | None = None,
    templates: dict[str, Any] | None = None,
    fixed: dict[str, Any] | None = None,
    enable: list[str] | None = None,
) -> ViewRemoteServer:
    include, review = tools
    return ViewRemoteServer.model_validate(
        {
            "kind": "remote",
            "vault_path": "/notes/mcp",
            "tools": {"include": include, "allow": include, "approve": []},
            "review": review,
            "on_drift": on_drift,
            "shared_session": False,
            "wrap_results": False,
            "enable": ["prompts", "resources"] if enable is None else enable,
            "prompts": prompts or {},
            "resources": {"templates": templates or {}, "fixed": fixed or {}},
            "era": "auto",
            "drift_check_interval": 300,
            "call_timeout": None,
        }
    )


def named_prompt(name: str, **changes: Any) -> Prompt:
    return prompt(name=name, **changes)


def prompt_pin(name: str, **changes: Any) -> str:
    return pins.project_kind("prompt", named_prompt(name, **changes)).pin


def test_the_kinds_an_enable_lists() -> None:
    assert pins.enabled_kinds([]) == ()
    assert pins.enabled_kinds(["prompts"]) == ("prompt",)
    assert pins.enabled_kinds(["resources"]) == ("resource_template", "resource")
    assert pins.enabled_kinds(["completions", "resources", "prompts", "prompts"]) == (
        "prompt",
        "resource_template",
        "resource",
    )


def test_each_kinds_policy_entries() -> None:
    policy = kinds_server(
        tools=(["t"], {"t": PIN_X}),
        prompts={"include": ["p"], "review": {"p": PIN_X}, "declined": {"q": PIN_Y}},
        templates={"include": ["notes://n/{id}"], "review": {}, "declined": {}},
        fixed={"include": [], "review": {"notes://i": PIN_Y}},
    )
    assert pins.entries(policy) == pins.Entries(["t"], {"t": PIN_X}, {})
    assert pins.entries(policy, "prompt") == pins.Entries(["p"], {"p": PIN_X}, {"q": PIN_Y})
    assert pins.entries(policy, "resource_template") == pins.Entries(["notes://n/{id}"], {}, {})
    assert pins.entries(policy, "resource") == pins.Entries([], {"notes://i": PIN_Y}, {})


def test_only_a_remote_server_has_other_kinds() -> None:
    toolkit = SelfPinned(Tools(), {}, declined={})
    assert pins.entries(toolkit).include == []
    with pytest.raises(ValueError, match="only a remote server lists a prompt"):
        pins.entries(toolkit, "prompt")


def test_every_report_kind_for_prompts() -> None:
    bad = named_prompt("bad", description="\u200b")
    listing = [
        named_prompt("ok"),
        named_prompt("new"),
        named_prompt("dup"),
        named_prompt("dup"),
        named_prompt("changed"),
        bad,
        named_prompt("seen"),
    ]
    policy = kinds_server(
        prompts={
            "include": ["ok", "dup", "changed", "bad", "gone"],
            "review": {
                "ok": prompt_pin("ok"),
                "dup": prompt_pin("dup"),
                "changed": prompt_pin("changed", description="Old."),
                "bad": prompt_pin("bad"),
                "gone": prompt_pin("gone"),
            },
            "declined": {"seen": prompt_pin("seen")},
        }
    )
    result = evaluate(listing, policy, set(), LIMITS, "prompt")
    assert set(result.exposed) == {"ok"}
    assert result.exposed["ok"] == pins.ExposedTool(
        pins.project_prompt(named_prompt("ok")), prompt_pin("ok")
    )
    assert kinds(result) == [
        ("unreviewed", "new"),
        ("duplicate", "dup"),
        ("drift", "changed"),
        ("invalid", "bad"),
        ("declined", "seen"),
        ("missing", "gone"),
    ]
    assert result.marks == {("changed", prompt_pin("changed", description="Old."))}
    assert result.listed["ok"] == prompt_pin("ok")
    assert result.listed["bad"] is None
    assert result.blocked is False


def test_a_template_and_a_fixed_resource_are_evaluated_by_their_uris() -> None:
    held = template()
    pin_t = pins.project_kind("resource_template", held).pin
    fixed_one = resource()
    pin_r = pins.project_kind("resource", fixed_one).pin
    policy = kinds_server(
        templates={"include": ["notes://notes/{id}"], "review": {"notes://notes/{id}": pin_t}},
        fixed={"include": ["notes://index", "notes://gone"], "review": {"notes://index": pin_r}},
    )
    found = evaluate([held], policy, set(), LIMITS, "resource_template")
    assert set(found.exposed) == {"notes://notes/{id}"}
    found = evaluate([fixed_one], policy, set(), LIMITS, "resource")
    assert set(found.exposed) == {"notes://index"}
    assert kinds(found) == [("missing", "notes://gone")]
    operator = template(uriTemplate="notes://files/{+path}")
    report, missing = evaluate([operator], policy, set(), LIMITS, "resource_template").reports
    assert (report.kind, report.tool, report.pin) == ("invalid", "notes://files/{+path}", None)
    assert (missing.kind, missing.tool) == ("missing", "notes://notes/{id}")


def test_a_kinds_mark_is_sticky_and_clears_with_its_pin() -> None:
    old = prompt_pin("p", description="Old.")
    policy = kinds_server(prompts={"include": ["p"], "review": {"p": old}})
    first = evaluate([named_prompt("p")], policy, set(), LIMITS, "prompt")
    assert first.marks == {("p", old)}
    back = evaluate([named_prompt("p", description="Old.")], policy, first.marks, LIMITS, "prompt")
    assert back.exposed == {}
    assert back.marks == {("p", old)}
    repinned = kinds_server(prompts={"include": ["p"], "review": {"p": prompt_pin("p")}})
    cleared = evaluate([named_prompt("p")], repinned, {("p", old)}, LIMITS, "prompt")
    assert (set(cleared.exposed), cleared.marks) == ({"p"}, frozenset())


def listings(**items: Any) -> dict[pins.DefinitionKind, pins.KindListing]:
    return {
        cast(pins.DefinitionKind, kind): pins.KindListing(found) for kind, found in items.items()
    }


def test_a_server_with_no_other_kind_evaluates_as_its_tools() -> None:
    policy = server(["a"], {"a": pin("a")})
    whole = pins.evaluate_server([named("a")], {}, policy, {}, LIMITS)
    assert whole == evaluate([named("a")], policy, set(), LIMITS)
    assert whole.kinds == {}


def test_every_kind_is_evaluated_with_its_own_marks() -> None:
    old = prompt_pin("p", description="Old.")
    policy = kinds_server(
        tools=(["a"], {"a": pin("a")}),
        prompts={"include": ["p", "q"], "review": {"p": old, "q": prompt_pin("q")}},
    )
    marks: dict[pins.DefinitionKind, set[tuple[str, str]]] = {
        "tool": {("a", pin("a"))},
        "prompt": {("q", prompt_pin("q"))},
    }
    whole = pins.evaluate_server(
        [named("a")], listings(prompt=[named_prompt("p"), named_prompt("q")]), policy, marks, LIMITS
    )
    assert whole.exposed == {}
    assert whole.marks == {("a", pin("a"))}
    assert whole.blocked is False
    prompts = whole.kinds["prompt"]
    assert prompts.exposed == {}
    assert prompts.marks == {("p", old), ("q", prompt_pin("q"))}
    assert kinds(prompts) == [("drift", "p")]


def test_a_failed_kind_lists_nothing_so_its_entries_are_missing() -> None:
    """SPEC-7: the kind fails on its own; the tools are served."""
    policy = kinds_server(
        tools=(["a"], {"a": pin("a")}),
        fixed={"include": ["notes://index"], "review": {"notes://index": PIN_X}},
    )
    failed: dict[pins.DefinitionKind, pins.KindListing] = {
        "resource": pins.KindListing(failure="entries")
    }
    whole = pins.evaluate_server([named("a")], failed, policy, {}, LIMITS)
    assert set(whole.exposed) == {"a"}
    assert kinds(whole.kinds["resource"]) == [("missing", "notes://index")]


@pytest.mark.parametrize("drifted", ["tool", "prompt", "resource_template", "resource"])
def test_on_drift_fail_blocks_every_kind_when_any_kind_drifts(drifted: str) -> None:
    """Q20 (a): a server that rug-pulls one kind is no more trustworthy for the others."""
    old = "sha256:" + "0" * 64
    review = {
        "tool": {"a": pin("a")},
        "prompt": {"p": prompt_pin("p")},
        "resource_template": {
            "notes://notes/{id}": pins.project_kind("resource_template", template()).pin
        },
        "resource": {"notes://index": pins.project_kind("resource", resource()).pin},
    }
    key = next(iter(review[drifted]))
    review[drifted][key] = old
    for on_drift in ("fail", "hide"):
        policy = kinds_server(
            on_drift,
            tools=(["a"], review["tool"]),
            prompts={"include": ["p"], "review": review["prompt"]},
            templates={"include": ["notes://notes/{id}"], "review": review["resource_template"]},
            fixed={"include": ["notes://index"], "review": review["resource"]},
        )
        found = listings(
            prompt=[named_prompt("p")], resource_template=[template()], resource=[resource()]
        )
        whole = pins.evaluate_server([named("a")], found, policy, {}, LIMITS)
        evaluations = [whole, *whole.kinds.values()]
        if on_drift == "fail":
            assert all(e.blocked and e.exposed == {} for e in evaluations)
        else:
            assert not any(e.blocked for e in evaluations)
            assert sum(len(e.exposed) for e in evaluations) == 3
        assert {
            drifted_kind for drifted_kind, e in [("tool", whole), *whole.kinds.items()] if e.marks
        } == {drifted}


def test_on_drift_fail_blocks_every_kind_on_another_kinds_held_mark() -> None:
    p_pin = prompt_pin("p")
    policy = kinds_server(
        "fail", tools=(["a"], {"a": pin("a")}), prompts={"include": ["p"], "review": {"p": p_pin}}
    )
    whole = pins.evaluate_server(
        [named("a")],
        listings(prompt=[named_prompt("p")]),
        policy,
        {"prompt": {("p", p_pin)}},
        LIMITS,
    )
    assert (whole.blocked, whole.exposed) == (True, {})
    assert (whole.kinds["prompt"].blocked, whole.kinds["prompt"].exposed) == (True, {})
    assert whole.kinds["prompt"].reports == ()
