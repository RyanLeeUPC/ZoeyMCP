"""The pin projection, pins, definition text rules and listing evaluation (M3 design G, J.3)."""

from __future__ import annotations

import copy
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st
from mcp.types import Tool

from zoeymcp.common import canonical
from zoeymcp.common.policy.schema import GatewayLimits
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

LIMITS = GatewayLimits()

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
) -> ViewRemoteServer:
    return ViewRemoteServer.model_validate(
        {
            "kind": "remote",
            "vault_path": "/notes/mcp",
            "tools": {"include": include, "allow": include, "approve": []},
            "review": review,
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
