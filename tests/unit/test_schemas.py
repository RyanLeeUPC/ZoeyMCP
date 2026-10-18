"""Schema acceptance and validators (M3 design H.1, H.2)."""

from __future__ import annotations

import time
import urllib.request
from typing import Any

import pytest
from jsonschema import Draft7Validator, Draft202012Validator

from zoeymcp.common.policy.schema import GatewayLimits
from zoeymcp.gateway import schemas
from zoeymcp.gateway.schemas import (
    Budget,
    SchemaRefused,
    SchemaValidator,
    json_pointer,
    schema_problems,
    validator_for,
)

LIMITS = GatewayLimits()
DRAFT7 = "http://json-schema.org/draft-07/schema#"
SLOW = "(x+x+)+y"  # catastrophic backtracking on a long run of x


def problems(schema: Any, role: schemas.Role = "input", **limits: int) -> list[tuple[str, str]]:
    found = schema_problems(schema, role=role, limits=GatewayLimits(**limits) if limits else LIMITS)
    return [(problem.pointer, problem.code) for problem in found]


def obj(**members: Any) -> dict[str, Any]:
    return {"type": "object", **members}


def errors(schema: dict[str, Any], instance: Any, dialect: Any = Draft202012Validator) -> list[str]:
    return SchemaValidator(schema, dialect).errors(instance, Budget.start())


# --- json_pointer ----------------------------------------------------------------------------


def test_json_pointer_escapes() -> None:
    assert json_pointer([]) == ""
    assert json_pointer(["a", 0, "b/c", "d~e", ""]) == "/a/0/b~1c/d~0e/"


# --- the root and the caps -------------------------------------------------------------------


def test_a_plain_object_schema_is_accepted() -> None:
    assert problems(obj(properties={"a": {"type": "string"}})) == []


@pytest.mark.parametrize("schema", [None, [], "object", True])
def test_the_schema_must_be_an_object(schema: Any) -> None:
    assert problems(schema) == [("", "schema_not_object")]
    assert problems(schema, "output") == [("", "schema_not_object")]


@pytest.mark.parametrize("root_type", [None, "array", ["object"]])
def test_the_input_root_must_be_type_object(root_type: Any) -> None:
    schema = {} if root_type is None else {"type": root_type}
    assert ("", "schema_root_type") in problems(schema)


def test_the_output_root_may_be_any_type() -> None:
    assert problems({"type": "array"}, "output") == []
    assert problems({}, "output") == []


def test_no_canonical_form() -> None:
    assert problems(obj(x=2**53)) == [("", "schema_not_canonical")]


def test_the_size_cap_is_canonical_bytes() -> None:
    schema = obj(description="x" * 1000)
    size = len(b'{"description":"","type":"object"}') + 1000
    assert problems(schema, max_schema_bytes=size) == []
    assert problems(schema, max_schema_bytes=size - 1) == [("", "schema_too_large")]


def test_the_depth_cap() -> None:
    schema = obj(properties={"a": {"properties": {"b": {}}}})  # 5 levels
    assert schemas._depth(schema) == 5
    assert problems(schema, max_schema_depth=5) == []
    assert problems(schema, max_schema_depth=4) == [("", "schema_too_deep")]


def test_depth_counts_arrays_and_scalars() -> None:
    assert schemas._depth(1) == 0
    assert schemas._depth({}) == 1
    assert schemas._depth([[], {"a": [1]}]) == 3


def test_the_subschema_cap() -> None:
    schema = obj(properties={str(i): {} for i in range(15)})  # the root and 15 more
    assert problems(schema, max_subschemas=16) == []
    assert problems(schema, max_subschemas=16 - 0) == []
    schema["properties"]["15"] = {}
    assert problems(schema, max_subschemas=16) == [("", "schema_too_many_subschemas")]


def test_caps_are_checked_before_anything_else() -> None:
    schema = obj(**{"$id": "x"}, description="x" * 2000)
    assert problems(schema, max_schema_bytes=1024) == [("", "schema_too_large")]
    root = {"type": "array", "description": "x" * 2000}
    assert problems(root, max_schema_bytes=1024) == [
        ("", "schema_root_type"),
        ("", "schema_too_large"),
    ]


def test_cap_messages_name_numbers_only() -> None:
    [problem] = schema_problems(
        obj(description="x" * 2000), role="input", limits=GatewayLimits(max_schema_bytes=1024)
    )
    assert problem.message == "2034 bytes, limit 1024"


# --- the walk --------------------------------------------------------------------------------


def positions(schema: dict[str, Any]) -> set[tuple[str | int, ...]]:
    return {position.path for position in schemas._positions(schema)}


def test_every_subschema_keyword_is_walked() -> None:
    schema = {
        "properties": {"p": {}},
        "patternProperties": {"^x": {}},
        "additionalProperties": {},
        "propertyNames": {},
        "items": {},
        "prefixItems": [{}],
        "additionalItems": {},
        "contains": {},
        "allOf": [{}],
        "anyOf": [{}],
        "oneOf": [True],
        "not": {},
        "if": {},
        "then": {},
        "else": {},
        "unevaluatedItems": {},
        "unevaluatedProperties": False,
        "contentSchema": {},
        "$defs": {"d": {}},
        "definitions": {"e": {}},
        "dependentSchemas": {"f": {}},
        "dependencies": {"g": {}, "h": ["p"]},
    }
    assert positions(schema) == {
        (),
        ("properties", "p"),
        ("patternProperties", "^x"),
        ("additionalProperties",),
        ("propertyNames",),
        ("items",),
        ("prefixItems", 0),
        ("additionalItems",),
        ("contains",),
        ("allOf", 0),
        ("anyOf", 0),
        ("oneOf", 0),
        ("not",),
        ("if",),
        ("then",),
        ("else",),
        ("unevaluatedItems",),
        ("unevaluatedProperties",),
        ("contentSchema",),
        ("$defs", "d"),
        ("definitions", "e"),
        ("dependentSchemas", "f"),
        ("dependencies", "g"),
    }


def test_draft7_array_items_are_walked() -> None:
    assert positions({"items": [{}, True]}) == {(), ("items", 0), ("items", 1)}


def test_data_keywords_are_not_walked() -> None:
    schema = {
        "default": {"pattern": "("},
        "const": {"$id": "x"},
        "enum": [{"$ref": "https://x"}],
        "examples": [{}],
        "x-vendor": {"type": "object"},
        "properties": {"a": 5, "b": "s"},
        "allOf": [5],
        "not": 5,
        "$defs": {"c": 5},
    }
    assert positions(schema) == {()}


def test_positions_come_in_document_order() -> None:
    schema: dict[str, Any] = {"properties": {"b": {"allOf": [{}]}, "a": {}}, "not": {}}
    assert [position.path for position in schemas._positions(schema)] == [
        (),
        ("properties", "b"),
        ("properties", "b", "allOf", 0),
        ("properties", "a"),
        ("not",),
    ]


def test_the_properties_chain() -> None:
    schema = {
        "properties": {"a": {"properties": {"b": {}}}},
        "allOf": [{"properties": {"c": {}}}],
    }
    chains = {position.path: position.chain for position in schemas._positions(schema)}
    assert chains[()] == ()
    assert chains[("properties", "a")] == ("a",)
    assert chains[("properties", "a", "properties", "b")] == ("a", "b")
    assert chains[("allOf", 0)] is None
    assert chains[("allOf", 0, "properties", "c")] is None


# --- dialects --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("declared", "dialect"),
    [
        (None, Draft202012Validator),
        ("https://json-schema.org/draft/2020-12/schema", Draft202012Validator),
        ("http://json-schema.org/draft-07/schema", Draft7Validator),
        ("http://json-schema.org/draft-07/schema#", Draft7Validator),
    ],
)
def test_supported_dialects(declared: str | None, dialect: Any) -> None:
    schema = obj() if declared is None else obj(**{"$schema": declared})
    assert schemas.dialect_of(schema) is dialect
    assert problems(schema) == []


@pytest.mark.parametrize(
    "declared",
    [
        "https://json-schema.org/draft/2020-12/schema#",
        "http://json-schema.org/draft/2020-12/schema",
        "https://json-schema.org/draft-07/schema#",
        "http://json-schema.org/draft-04/schema#",
        "https://json-schema.org/draft/2019-09/schema",
        "https://evil.example/schema",
        "",
        5,
        None,
    ],
)
def test_other_dialects_are_refused(declared: Any) -> None:
    schema = obj(**{"$schema": declared})
    assert schemas.dialect_of(schema) is None
    assert problems(schema) == [("/$schema", "schema_dialect")]


def test_schema_only_at_the_root() -> None:
    schema = obj(properties={"a": {"$schema": "https://json-schema.org/draft/2020-12/schema"}})
    assert problems(schema) == [("/properties/a/$schema", "schema_dialect")]


@pytest.mark.parametrize("declared", ["https://json-schema.org/draft/2020-12/schema", DRAFT7])
def test_a_declared_dialect_never_switches_the_validator_class(declared: str) -> None:
    """``$ref: "#"`` re-enters a root that declares ``$schema``; jsonschema's ``evolve`` would
    then switch to its own class, which matches with ``re``, unbudgeted and Unicode-aware."""
    dialect = schemas.dialect_of({"$schema": declared})
    assert dialect is not None
    schema = obj(
        **{"$schema": declared},
        properties={"d": {"pattern": r"^\d$"}, "s": {"pattern": SLOW}, "again": {"$ref": "#"}},
    )
    assert problems(schema) == []
    validator = SchemaValidator(schema, dialect)
    assert validator.errors({"again": {"d": "\u0663"}}, Budget.start()) == ["/again/d: pattern"]
    with pytest.raises(SchemaRefused) as info:
        validator.errors({"again": {"s": "x" * 30_000}}, Budget.start())
    assert info.value.code == "schema_regex_timeout"


def test_validators_get_a_copy_without_dialects() -> None:
    schema = obj(**{"$schema": DRAFT7}, properties={"a": {"$schema": DRAFT7}})
    stripped = schemas._without_dialects(schema)
    assert stripped == obj(properties={"a": {}})
    assert schema["$schema"] == DRAFT7
    assert schema["properties"]["a"] == {"$schema": DRAFT7}


@pytest.mark.parametrize(
    "schema",
    [
        obj(minLength="x"),
        obj(properties={"a": {"type": "strin"}}),
        obj(required="a"),
        obj(properties={"a": {"pattern": 5}}),
    ],
)
def test_the_metaschema_must_pass(schema: dict[str, Any]) -> None:
    found = problems(schema)
    assert found
    assert {code for _, code in found} == {"schema_invalid"}


def test_a_metaschema_problem_names_the_keyword_and_location() -> None:
    [problem] = schema_problems(
        obj(properties={"a": {"type": "strin"}}), role="input", limits=LIMITS
    )
    assert problem.pointer == "/properties/a/type"
    assert "strin" not in problem.message


def test_draft7_items_arrays_pass_only_in_draft7() -> None:
    tuple_items = obj(properties={"a": {"items": [{"type": "string"}]}})
    assert problems({**tuple_items, "$schema": DRAFT7}) == []
    assert {code for _, code in problems(tuple_items)} == {"schema_invalid"}


def test_format_regex_is_not_checked_with_re() -> None:
    # \p{L} is valid for the regex module but not for re.
    assert problems(obj(properties={"a": {"pattern": r"^\p{L}+$"}})) == []


# --- references and identifiers --------------------------------------------------------------


@pytest.mark.parametrize(
    "ref",
    [
        "#",
        "#/$defs/a",
        "#/definitions/b",
        "#/properties/x",
        "#/allOf/0",
        "#/$defs/we~1ird~0name",
        "#/$defs/we%7E1ird~0name",
        "#/$defs/sp%20ace",
    ],
)
def test_local_pointers_to_subschemas_are_accepted(ref: str) -> None:
    schema = obj(
        properties={"x": {}, "r": {"$ref": ref}},
        allOf=[{}],
        **{"$defs": {"a": {}, "we/ird~name": {}, "sp ace": {}}},
        definitions={"b": {}},
    )
    assert problems(schema) == []


@pytest.mark.parametrize(
    "ref",
    [
        "https://evil.example/schema.json",
        "file:///etc/passwd",
        "other.json#/a",
        "//evil.example/x",
        "#a",  # a plain-name anchor
        "#/$defs/missing",
        "#/$defs",  # exists, but not a subschema
        "#/properties/x/type",  # exists, a data value
        "#/default",  # data
        "#/allOf/01",
        "#/allOf/-1",
        "#/allOf/+0",
        "#/allOf/1",
        "#/x-vendor",  # an unknown keyword's content is not a schema position
        "#%2F$defs%2Fa",  # %2F before the first segment: an anchor to referencing
        "",
    ],
)
def test_other_references_are_refused(ref: Any) -> None:
    schema = obj(
        properties={"x": {"type": "string"}, "r": {"$ref": ref}},
        allOf=[{}],
        default={},
        **{"$defs": {"a": {}}, "x-vendor": {"type": "string"}},
    )
    assert problems(schema) == [("/properties/r/$ref", "schema_ref")]


@pytest.mark.parametrize("ref", [5, None, ["#"]])
def test_a_reference_must_be_a_string(ref: Any) -> None:
    found = problems(obj(properties={"r": {"$ref": ref}}))
    assert ("/properties/r/$ref", "schema_ref") in found


def test_ref_targets_mirror_referencing() -> None:
    document: dict[str, Any] = {"a": [{"b/c": {"~": {}}}]}
    assert schemas._ref_target(document, "#/a/0/b~1c/~0") == ("a", 0, "b/c", "~")
    assert schemas._ref_target(document, "#/a/0/b%2Fc") is None  # %2F splits, as referencing does
    assert schemas._ref_target(document, "#/a/0/b~1c/~0/x") is None
    assert schemas._ref_target(document, "#/a/x") is None
    assert schemas._ref_target({"a": "str"}, "#/a/0") is None
    assert schemas._ref_target(document, "#") == ()


@pytest.mark.parametrize("keyword", schemas.REFUSED_KEYWORDS)
def test_identifier_keywords_are_refused_anywhere(keyword: str) -> None:
    assert problems(obj(**{keyword: "x"})) == [(f"/{keyword}", "schema_keyword")]
    nested = obj(properties={"a": {"allOf": [{keyword: "x"}]}})
    assert problems(nested) == [(f"/properties/a/allOf/0/{keyword}", "schema_keyword")]


def test_a_property_named_like_a_keyword_is_fine() -> None:
    schema = obj(properties={"$id": {}, "$ref": {}, "$schema": {}, "x-mcp-header": {}})
    assert problems(schema) == []


def test_no_network_or_file_access(monkeypatch: pytest.MonkeyPatch) -> None:
    # Recorded, not raised: referencing turns any retrieval error into "unresolvable", so a
    # raising stub would hide an attempt behind the same refusal.
    opened: list[object] = []

    def record(*args: object, **kwargs: object) -> None:
        opened.append(args)
        raise OSError("no network in tests")

    monkeypatch.setattr(urllib.request, "urlopen", record)
    for ref in ("https://evil.example/schema.json", "file:///etc/passwd", "other.json"):
        validator = SchemaValidator({"$ref": ref}, Draft202012Validator)
        with pytest.raises(SchemaRefused) as info:
            validator.errors({}, Budget.start())
        assert info.value.code == "schema_unresolvable"
    assert opened == []


# --- patterns --------------------------------------------------------------------------------


@pytest.mark.parametrize("pattern", ["(", "[a-", "a{2,1}", "(?<n", "\\"])
def test_a_pattern_must_compile(pattern: str) -> None:
    assert problems(obj(properties={"a": {"pattern": pattern}})) == [
        ("/properties/a/pattern", "schema_pattern")
    ]


def test_a_pattern_properties_key_must_compile() -> None:
    assert problems(obj(patternProperties={"(": {}, "^ok$": {}})) == [
        ("/patternProperties/(", "schema_pattern")
    ]


def test_compiles() -> None:
    assert schemas.compiles(r"^\d+$")
    assert not schemas.compiles("(")


def test_unevaluated_properties_with_pattern_properties_is_refused() -> None:
    assert problems(obj(unevaluatedProperties=False)) == []
    assert problems(obj(patternProperties={"^a": {}})) == []
    combined = obj(
        patternProperties={"^a": {}},
        allOf=[{"unevaluatedProperties": False}],
        unevaluatedProperties=False,
    )
    assert problems(combined) == [
        ("/allOf/0/unevaluatedProperties", "schema_unevaluated"),
        ("/unevaluatedProperties", "schema_unevaluated"),
    ]


def test_patterns_lists_every_pattern() -> None:
    schema = obj(
        properties={"a": {"pattern": "^a$"}, "pattern": {}},
        patternProperties={"^b": {"pattern": "c"}},
    )
    assert schemas.patterns(schema) == [
        ("/patternProperties/^b", "^b"),
        ("/patternProperties/^b/pattern", "c"),
        ("/properties/a/pattern", "^a$"),
    ]
    assert schemas.patterns(5) == []  # type: ignore[arg-type]


# --- x-mcp-header ----------------------------------------------------------------------------


def header(value: Any = "Region", prop_type: Any = "string") -> dict[str, Any]:
    return {"type": prop_type, "x-mcp-header": value}


@pytest.mark.parametrize("prop_type", ["string", "integer", "boolean"])
def test_a_valid_header(prop_type: str) -> None:
    schema = obj(properties={"r": header(prop_type=prop_type)})
    assert problems(schema) == []
    assert schemas.mcp_headers(schema) == [("/properties/r", "Region")]


def test_a_header_on_a_nested_property_is_valid() -> None:
    schema = obj(properties={"a": {"type": "object", "properties": {"b": header()}}})
    assert problems(schema) == []
    assert schemas.mcp_headers(schema) == [("/properties/a/properties/b", "Region")]


@pytest.mark.parametrize("prop_type", ["number", "array", "object", "null", ["string"], None])
def test_a_header_on_another_type_is_refused(prop_type: Any) -> None:
    prop = header() if prop_type is None else header(prop_type=prop_type)
    if prop_type is None:
        del prop["type"]
    schema = obj(properties={"r": prop})
    assert ("/properties/r/x-mcp-header", "schema_mcp_header") in problems(schema)


@pytest.mark.parametrize("value", ["", "Two words", "a:b", "caf\u00e9", "a\n", 5, None, ["a"]])
def test_a_header_must_be_a_token(value: Any) -> None:
    schema = obj(properties={"r": header(value)})
    assert problems(schema) == [("/properties/r/x-mcp-header", "schema_mcp_header")]


def test_every_token_character_is_accepted() -> None:
    schema = obj(properties={"r": header("!#$%&'*+-.^_`|~09AZaz")})
    assert problems(schema) == []


def test_headers_are_unique_ignoring_case() -> None:
    schema = obj(properties={"a": header("Region"), "b": header("REGION"), "c": header("Zone")})
    found = schema_problems(schema, role="input", limits=LIMITS)
    assert [(problem.pointer, problem.code) for problem in found] == [
        ("/properties/b/x-mcp-header", "schema_mcp_header")
    ]
    assert found[0].message == ("x-mcp-header names the same header as /properties/a/x-mcp-header")


@pytest.mark.parametrize(
    "schema",
    [
        {"type": "object", "x-mcp-header": "Root"},
        obj(allOf=[header()]),
        obj(properties={"a": {"items": header()}}),
        obj(**{"$defs": {"d": header()}}),
        obj(additionalProperties=header()),
        obj(patternProperties={"^a": header()}),
    ],
)
def test_a_header_off_the_properties_chain_is_refused(schema: dict[str, Any]) -> None:
    found = problems(schema)
    assert len(found) == 1
    assert found[0][1] == "schema_mcp_header"
    assert schemas.mcp_headers(schema) == []


def test_headers_are_only_checked_in_input_schemas() -> None:
    schema = obj(properties={"r": header(prop_type="array")})
    assert problems(schema, "output") == []


def test_mcp_headers_skips_non_strings() -> None:
    assert schemas.mcp_headers(obj(properties={"r": header(5)})) == []
    assert schemas.mcp_headers(5) == []  # type: ignore[arg-type]


# --- validators: the basics ------------------------------------------------------------------


def test_errors_name_pointer_and_keyword_never_the_value() -> None:
    schema = obj(
        properties={"a": {"type": "integer"}, "b": {"enum": ["x"]}},
        required=["c"],
        additionalProperties=False,
    )
    found = errors(schema, {"a": "secret-value-1", "b": "secret-value-2", "d": 1})
    assert sorted(found) == ["/: additionalProperties", "/: required", "/a: type", "/b: enum"]
    assert not any("secret" in error for error in found)


def test_errors_are_capped() -> None:
    schema = obj(additionalProperties={"type": "integer"})
    found = errors(schema, {str(i): "x" for i in range(50)})
    assert len(found) == schemas.MAX_ERRORS


def test_a_valid_instance_has_no_errors() -> None:
    assert errors(obj(properties={"a": {"type": "string"}}), {"a": "x"}) == []


def test_format_is_off() -> None:
    assert errors(obj(properties={"a": {"format": "email"}}), {"a": "not an email"}) == []


def test_local_refs_resolve_in_both_dialects() -> None:
    schema = obj(properties={"a": {"$ref": "#/$defs/n"}}, **{"$defs": {"n": {"type": "integer"}}})
    assert errors(schema, {"a": "x"}) == ["/a: type"]
    draft7 = obj(
        properties={"a": {"$ref": "#/definitions/n"}}, definitions={"n": {"type": "integer"}}
    )
    assert errors(draft7, {"a": "x"}, Draft7Validator) == ["/a: type"]


def test_a_ref_cycle_is_refused_not_crashed() -> None:
    with pytest.raises(SchemaRefused) as info:
        errors({"$ref": "#"}, 1)
    assert info.value.code == "schema_recursion"


# --- validators: patterns --------------------------------------------------------------------


def test_pattern_is_a_search() -> None:
    schema = obj(properties={"a": {"pattern": "b"}})
    assert errors(schema, {"a": "abc"}) == []
    assert errors(schema, {"a": "xyz"}) == ["/a: pattern"]
    assert errors(schema, {"a": 5}) == []


def test_the_ascii_flag() -> None:
    schema = obj(properties={"d": {"pattern": r"^\d+$"}, "w": {"pattern": r"^\w+$"}})
    assert errors(schema, {"d": "123", "w": "abc_1"}) == []
    found = sorted(errors(schema, {"d": "\u0663", "w": "caf\u00e9"}))
    assert found == ["/d: pattern", "/w: pattern"]


def test_pattern_properties_use_the_regex_module() -> None:
    schema = obj(patternProperties={r"^\d$": {"type": "string"}})
    assert errors(schema, {"3": 1}) == ["/3: type"]
    assert errors(schema, {"\u0663": 1}) == []  # not a digit under ASCII, so not matched
    assert errors(schema, [1]) == ["/: type"]


def test_additional_properties_agree_with_pattern_properties() -> None:
    # Under re, \d matches U+0663, so jsonschema's own version would call it matched, while the
    # regex patternProperties above call it unmatched: the key would escape both checks.
    schema = obj(patternProperties={r"^\d$": {"type": "string"}}, additionalProperties=False)
    assert errors(schema, {"\u0663": 1}) == ["/: additionalProperties"]
    assert errors(schema, {"3": "x"}) == []
    with_properties = {**schema, "properties": {"\u0663": {}}}
    assert errors(with_properties, {"\u0663": 1}) == []


def test_additional_properties_with_a_schema() -> None:
    schema = obj(properties={"a": {}}, additionalProperties={"type": "integer"})
    assert errors(schema, {"a": "x", "b": 1}) == []
    assert errors(schema, {"a": "x", "b": "y"}) == ["/b: type"]
    assert errors(obj(additionalProperties=True), {"b": "y"}) == []
    assert errors(obj(additionalProperties=False), {}) == []
    assert errors(obj(additionalProperties=False), "not an object") == ["/: type"]


@pytest.mark.parametrize(
    ("pattern", "dollar"),
    [
        ("^a$", True),
        ("a$b", True),
        (r"a\$", False),
        (r"a\\$", True),
        (r"a\\\$", False),
        ("[$]", True),  # fails closed: inside a class it's literal, but it is refused anyway
        ("abc", False),
    ],
)
def test_unescaped_dollar(pattern: str, dollar: bool) -> None:
    assert schemas._has_unescaped_dollar(pattern) is dollar


def test_the_dollar_rule() -> None:
    schema = obj(properties={"a": {"pattern": "^[a-z]+$"}, "b": {"pattern": "^[a-z]+"}})
    assert errors(schema, {"a": "abc"}) == []
    # Python's $ matches before a final newline; ECMA-262's doesn't. Refused, not passed.
    assert errors(schema, {"a": "abc\n"}) == ["/a: pattern"]
    assert errors(schema, {"b": "abc\n"}) == []
    assert errors(schema, {"a": "ab\nc"}) == ["/a: pattern"]


def test_the_dollar_rule_for_keys() -> None:
    keyed = obj(patternProperties={"^a$": {}})
    assert errors(keyed, {"a\n": 1}) == ["/: patternProperties"]
    assert errors(keyed, {"a": 1}) == []
    additional = obj(patternProperties={"^a$": {}}, additionalProperties=False)
    assert errors(additional, {"a\n": 1}) == ["/: additionalProperties"] or sorted(
        errors(additional, {"a\n": 1})
    ) == ["/: additionalProperties", "/: patternProperties"]


# --- validators: time ------------------------------------------------------------------------


def test_a_slow_match_times_out() -> None:
    validator = SchemaValidator(obj(properties={"s": {"pattern": SLOW}}), Draft202012Validator)
    started = time.monotonic()
    with pytest.raises(SchemaRefused) as info:
        validator.errors({"s": "x" * 30_000}, Budget.start())
    assert info.value.code == "schema_regex_timeout"
    assert time.monotonic() - started < 0.5


def test_the_regex_budget_is_per_call_across_matches() -> None:
    validator = SchemaValidator(obj(additionalProperties={"pattern": "^x"}), Draft202012Validator)
    budget = Budget.start(regex_seconds=0.0)
    with pytest.raises(SchemaRefused) as info:
        validator.errors({"a": "x"}, budget)
    assert info.value.code == "schema_regex_timeout"
    budget = Budget.start()
    assert validator.errors({"a": "x"}, budget) == []
    assert 0 < budget.regex_left <= schemas.REGEX_BUDGET


def test_one_budget_covers_every_match_in_a_call() -> None:
    validator = SchemaValidator(obj(properties={"s": {"pattern": SLOW}}), Draft202012Validator)
    budget = Budget.start()
    started = time.monotonic()
    attempts = 0
    while budget.regex_left > 0:
        with pytest.raises(SchemaRefused):
            validator.errors({"s": "x" * 30_000}, budget)
        attempts += 1
        assert attempts <= 10
    assert attempts >= 4  # 250 ms of 50 ms matches
    assert time.monotonic() - started < schemas.REGEX_BUDGET + 0.25
    # Spent: the next match is refused without running.
    started = time.monotonic()
    with pytest.raises(SchemaRefused) as info:
        validator.errors({"s": "x"}, budget)
    assert info.value.code == "schema_regex_timeout"
    assert time.monotonic() - started < 0.04


def test_the_call_budget_covers_every_keyword() -> None:
    validator = SchemaValidator(obj(properties={"a": {"type": "string"}}), Draft202012Validator)
    with pytest.raises(SchemaRefused) as info:
        validator.errors({"a": "x"}, Budget(deadline=time.monotonic() - 1, regex_left=1.0))
    assert info.value.code == "schema_budget_exhausted"


def test_validation_outside_a_budget_is_refused() -> None:
    validator = SchemaValidator(obj(properties={"a": {"type": "string"}}), Draft202012Validator)
    with pytest.raises(SchemaRefused):
        list(validator._validator.iter_errors({"a": "x"}))


def test_the_budget_is_released_after_a_call() -> None:
    validator = SchemaValidator(obj(properties={"a": {"type": "string"}}), Draft202012Validator)
    validator.errors({"a": "x"}, Budget.start())
    assert schemas._BUDGET.get() is None
    with pytest.raises(SchemaRefused):
        validator.errors({"a": "x"}, Budget(deadline=0, regex_left=0))
    assert schemas._BUDGET.get() is None


def test_the_design_numbers() -> None:
    assert (schemas.MATCH_TIMEOUT, schemas.REGEX_BUDGET) == (0.05, 0.25)
    assert schemas.VALIDATOR_CACHE_SIZE == 1024


# --- the validator cache ---------------------------------------------------------------------


def pin(n: int) -> str:
    return f"sha256:{n:064x}"


def test_validators_are_cached_by_pin_and_role(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(schemas, "_VALIDATORS", type(schemas._VALIDATORS)())
    schema = obj()
    first = validator_for(pin(1), "input", schema)
    assert validator_for(pin(1), "input", obj(properties={"x": {}})) is first
    assert validator_for(pin(1), "output", schema) is not first
    assert validator_for(pin(2), "input", schema) is not first


def test_the_cache_is_lru(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(schemas, "_VALIDATORS", type(schemas._VALIDATORS)())
    monkeypatch.setattr(schemas, "VALIDATOR_CACHE_SIZE", 2)
    schema = obj()
    one = validator_for(pin(1), "input", schema)
    validator_for(pin(2), "input", schema)
    assert validator_for(pin(1), "input", schema) is one  # 1 is now the most recent
    validator_for(pin(3), "input", schema)
    assert list(schemas._VALIDATORS) == [(pin(1), "input"), (pin(3), "input")]
    assert validator_for(pin(1), "input", schema) is one


def test_validator_for_refuses_another_dialect(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(schemas, "_VALIDATORS", type(schemas._VALIDATORS)())
    with pytest.raises(SchemaRefused) as info:
        validator_for(pin(1), "input", obj(**{"$schema": "https://evil.example/s"}))
    assert info.value.code == "schema_dialect"
    assert len(schemas._VALIDATORS) == 0


def test_a_cached_draft7_validator_uses_draft7() -> None:
    schema = obj(**{"$schema": DRAFT7}, properties={"a": {"items": [{"type": "string"}]}})
    validator = validator_for(pin(99), "input", schema)
    assert validator.errors({"a": [1]}, Budget.start()) == ["/a/0: type"]
