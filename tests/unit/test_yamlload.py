"""The strict YAML loader (M6 design B, O.3 ``test_yamlload.py``; D-196).

Every row of the M6 spec brief's probe table (8.3) is refused with its message, never a traceback;
both sides of the depth (B4) and digit (B5) bounds; every shipped policy loads as before; and any
document the loader accepts round-trips through the emitter's ``document``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
import yaml
from hypothesis import given, settings
from hypothesis import strategies as st

from zoeymcp.common.canonical import DEFAULT_MAX_DEPTH
from zoeymcp.common.policy.emit import document
from zoeymcp.common.yamlload import MAX_DEPTH, StrictLoader, YAMLRejected, load_mapping

ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILES = (
    "deploy/compose.yaml",
    "deploy/compose.hardened.yaml",
    "examples/existing-stack/compose.yaml",
)


def refusal(text: str, **options: int) -> str:
    with pytest.raises(YAMLRejected) as caught:
        load_mapping(text, **options)
    return str(caught.value)


def test_plain_document() -> None:
    assert load_mapping("a: 1\nb: [x, y]\nc: {d: true}\n") == {
        "a": 1,
        "b": ["x", "y"],
        "c": {"d": True},
    }


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("a: 1\na: 2\n", "duplicate key 'a'"),
        ("outer:\n  b: 1\n  b: 2\n", "duplicate key 'b'"),
        ("a: &x [1]\nb: *x\n", "aliases are not allowed"),
        ("base: &b {x: 1}\nderived:\n  <<: *b\n", "aliases are not allowed"),
        ("- 1\n- 2\n", "top level must be a mapping"),
        ("just a string\n", "top level must be a mapping"),
        ("a: 1\n---\nb: 2\n", "invalid YAML"),
        ("a: !!python/object:os.system x\n", r"tags are not allowed \(line 1\)"),
        ("a: [1\n", "invalid YAML"),
        ("1: x\n", "top-level key 1 is not a string"),
    ],
)
def test_rejected_documents(text: str, message: str) -> None:
    with pytest.raises(YAMLRejected, match=message):
        load_mapping(text)


# --- the probe table (M6 spec brief 8.3) ----------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("a: !!bool yes", "tags are not allowed (line 1)"),
        ("a: !!int 0755", "tags are not allowed (line 1)"),
        ("a: !!int 0x1F", "tags are not allowed (line 1)"),
        ("a: !!timestamp 2020-01-01", "tags are not allowed (line 1)"),
        ("a: !!binary aGVsbG8=", "tags are not allowed (line 1)"),
        ("a: !!set {x, y}", "tags are not allowed (line 1)"),
        ("a: !!omap [x: 1, y: 2]", "tags are not allowed (line 1)"),
        ("a: !!float .nan", "tags are not allowed (line 1)"),
        ("a: {1: x}", "key 1 at /a is not a string"),
        ("a: {~: x}", "key None at /a is not a string"),
        ("a: {true: x}", "key True at /a is not a string"),
        ("!foo x", "tags are not allowed (line 1)"),
        ("!!python/name:os.system x", "tags are not allowed (line 1)"),
        ("a: b\x85c: d", "U+0085, a YAML 1.1 line break, is not allowed (line 1)"),
        ("a: b\u2028c: d", "U+2028, a YAML 1.1 line break, is not allowed (line 1)"),
        ("a: b\u2029c: d", "U+2029, a YAML 1.1 line break, is not allowed (line 1)"),
        ("a: " + "[" * 5000, "nested deeper than 64 levels (line 1)"),
        ("a: " + "7" * 5000, "integer too long (line 1)"),
        ("a: 1e999", "non-finite numbers are not allowed (line 1)"),
    ],
)
def test_every_probe_row_is_refused(text: str, message: str) -> None:
    assert refusal(text) == message


@pytest.mark.parametrize(("scalar", "expected"), [(".nan", ".nan"), (".inf", ".inf")])
def test_the_probe_tables_plain_specials_stay_strings(scalar: str, expected: str) -> None:
    assert load_mapping(f"a: {scalar}") == {"a": expected}


def test_a_byte_order_mark_is_still_accepted() -> None:
    assert load_mapping("\ufeffa: b") == {"a": "b"}


# --- B1: no explicit tag ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "a: !!str x",
        'a: !!str "x"',
        "a: !!str",
        "a: ! x",
        "a: !local x",
        "a: !<tag:yaml.org,2002:str> x",
        "a: !!seq [1]",
        "a: !x [1]",
        "a: !!map {b: 1}",
        "a: !x {b: 1}",
        "a:\n  !!str b: 1",
        "!!map\na: 1",
    ],
)
def test_every_tag_is_refused(text: str) -> None:
    assert refusal(text).startswith("tags are not allowed (line ")


def test_a_tag_is_refused_on_its_line() -> None:
    assert refusal("a: 1\nb:\n  - x\n  - !!str y\n") == "tags are not allowed (line 4)"
    text = "%TAG !e! tag:example.com,2000:\n---\na: !e!x y\n"
    assert refusal(text) == "tags are not allowed (line 3)"


def test_an_alias_is_refused_on_its_line() -> None:
    assert refusal("a: &x 1\nb: *x\n") == "aliases are not allowed (line 2)"


# --- B2: no YAML 1.1 line breaks ------------------------------------------------------------------


@pytest.mark.parametrize("char", ["\x85", "\u2028", "\u2029"])
def test_a_yaml_1_1_line_break_is_refused_anywhere(char: str) -> None:
    point = f"U+{ord(char):04X}"
    expected = f"{point}, a YAML 1.1 line break, is not allowed"
    assert refusal(f"a: x{char}") == f"{expected} (line 1)"
    assert refusal(f'a: 1\nb: "x{char}y"\n') == f"{expected} (line 2)"
    assert refusal(f"a: 1\n\n# a comment{char}\n") == f"{expected} (line 3)"
    assert refusal(f"a{char}: 1") == f"{expected} (line 1)"
    assert refusal(f"\na: x{char}") == f"{expected} (line 2)"


def test_an_escaped_line_break_is_just_a_character() -> None:
    assert load_mapping('a: "\\x85\\u2028\\u2029"') == {"a": "\x85\u2028\u2029"}


# --- B3: string keys at every depth ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("1: x", "top-level key 1 is not a string"),
        ("~: x", "top-level key None is not a string"),
        ("1.5: x", "top-level key 1.5 is not a string"),
        ("? [a]\n: x", "top-level key (a sequence) is not a string"),
        ("? {b: 1}\n: x", "top-level key (a mapping) is not a string"),
        ("a:\n  b:\n    1: x", "key 1 at /a/b is not a string"),
        ("a: [x, {false: y}]", "key False at /a/1 is not a string"),
        ("a: [[{b: {2.5: x}}]]", "key 2.5 at /a/0/0/b is not a string"),
        ("a:\n  ? {1: x}\n  : y", "key (a mapping) at /a is not a string"),
        ("a:\n  - b: 1\n  - ? [c]\n    : 2", "key (a sequence) at /a/1 is not a string"),
    ],
)
def test_a_key_that_isnt_a_string_is_refused_with_its_place(text: str, message: str) -> None:
    assert refusal(text) == message


def test_a_top_level_sequence_is_checked_from_the_root() -> None:
    # Its items are constructed, and their keys checked, before the top level's type is.
    assert refusal("- {1: x}") == "key 1 at /0 is not a string"
    assert refusal("- a\n- [b, {2.5: c}]") == "key 2.5 at /1/1 is not a string"
    assert refusal("- 1\n- 2\n") == "the top level must be a mapping"


def test_the_shallowest_refusal_comes_first() -> None:
    # A collection's keys are all checked before anything inside its values is constructed.
    assert refusal("a: {b: {1: x}}\nc: {2: y}") == "key 2 at /c is not a string"
    assert refusal("a: [[{1: x}]]\nb: [{2: y}]") == "key 2 at /b/0 is not a string"


def test_deep_construction_is_passed_on() -> None:
    # A loader of its own for each, since a constructed node is kept and handed back.
    text = "a: {b: [1]}\nc: [[2], {d: 3}]\n"
    loader = StrictLoader(text)
    try:
        node = loader.get_single_node()
        assert isinstance(node, yaml.MappingNode)
        assert loader.construct_mapping(node, deep=True) == {"a": {"b": [1]}, "c": [[2], {"d": 3}]}
    finally:
        loader.dispose()
    loader = StrictLoader(text)
    try:
        node = loader.get_single_node()
        assert isinstance(node, yaml.MappingNode)
        sequence = node.value[1][1]
        assert isinstance(sequence, yaml.SequenceNode)
        assert loader.construct_sequence(sequence, deep=True) == [[2], {"d": 3}]
    finally:
        loader.dispose()


def test_a_key_is_checked_before_the_duplicate_rule() -> None:
    assert refusal("1: a\n1: b\n") == "top-level key 1 is not a string"
    assert refusal("a: x\nb:\n  c: 1\n  c: 2\n") == "duplicate key 'c' at line 4, column 3"


def test_string_keys_that_look_like_other_types_load() -> None:
    text = 'a:\n  "1": x\n  yes: y\n  "~": z\n  0755: w\n'
    assert load_mapping(text) == {"a": {"1": "x", "yes": "y", "~": "z", "0755": "w"}}


# --- B4: depth ----------------------------------------------------------------------------------


def depth(value: Any) -> int:
    if isinstance(value, dict):
        value = list(value.values())
    if isinstance(value, list):
        return 1 + max(map(depth, value), default=0)
    return 0


def test_the_depth_is_the_canonical_one() -> None:
    assert MAX_DEPTH == DEFAULT_MAX_DEPTH == 64


@pytest.mark.parametrize(
    ("opening", "closing"),
    [("[", "]"), ("{b: ", "}")],
)
def test_64_collections_deep_loads_and_65_is_refused(opening: str, closing: str) -> None:
    # The top-level mapping is the first of them.
    assert depth(load_mapping("a: " + opening * 63 + closing * 63)) == 64
    assert refusal("a: " + opening * 64 + closing * 64) == "nested deeper than 64 levels (line 1)"


def test_block_nesting_counts_as_flow_nesting_does() -> None:
    lines = [" " * i + f"k{i}:" for i in range(63)]
    assert load_mapping("\n".join([*lines, " " * 63 + "end: 1"]))
    lines.append(" " * 63 + "k63:")
    # A block mapping starts at its first key, on the 65th line.
    assert refusal("\n".join([*lines, " " * 64 + "end: 1"])) == (
        "nested deeper than 64 levels (line 65)"
    )


def test_siblings_dont_add_to_the_depth() -> None:
    sibling = "[" * 62 + "]" * 62
    text = "".join(f"k{i}: {sibling}\n" for i in range(100))
    assert len(load_mapping(text)) == 100


def test_the_depth_drops_back_one_level_as_a_collection_closes() -> None:
    # /a/0 closes at the third level, so its sibling /a/1 starts at the third level again.
    deep = "[" * 62 + "]" * 62
    assert depth(load_mapping(f"a: [[], {deep}]")) == 64
    assert refusal(f"a: [[], [{deep}]]") == "nested deeper than 64 levels (line 1)"
    assert refusal(f"a: {{}}\nb: [[{deep}]]") == "nested deeper than 64 levels (line 2)"


class Pathed(StrictLoader):
    """The strict loader with two path resolvers, which see each node's parent and index.

    The implicit resolvers type a plain scalar first, so the quoted ones show the path resolvers
    at work.
    """


Pathed.add_path_resolver("tag:yaml.org,2002:int", ["a"], str)
Pathed.add_path_resolver("tag:yaml.org,2002:int", ["b", "c"], str)


def test_a_nodes_parent_and_index_reach_the_path_resolvers() -> None:
    def load(text: str) -> Any:
        return yaml.load(text, Loader=Pathed)  # noqa: S506 - a StrictLoader

    assert load("a: '1'\nx: '1'\n") == {"a": 1, "x": "1"}
    text = "b: {c: '1', x: '1'}\nx: {c: '1'}\n"
    assert load(text) == {"b": {"c": 1, "x": "1"}, "x": {"c": "1"}}


def test_a_key_counts_toward_the_depth() -> None:
    assert refusal("? " + "[" * 64 + "]" * 64 + "\n: x") == "nested deeper than 64 levels (line 1)"


# --- B5: integers of at most 32 digits, finite floats ---------------------------------------------


@pytest.mark.parametrize("sign", ["", "-", "+"])
def test_32_digits_load_and_33_are_refused(sign: str) -> None:
    digits = "9" * 32
    assert load_mapping(f"a: {sign}{digits}") == {"a": int(sign + digits)}
    assert refusal(f"a: {sign}1{digits}") == "integer too long (line 1)"


def test_a_long_run_of_digits_is_refused_however_it_starts() -> None:
    assert refusal("a: 1\nb: " + "0" * 33) == "integer too long (line 2)"
    assert load_mapping("a: " + "0" * 32) == {"a": "0" * 32}  # like 0755, a string
    assert refusal("a: [1, " + "5" * 40 + "]") == "integer too long (line 1)"
    assert refusal("? " + "5" * 40 + "\n: x") == "integer too long (line 1)"


def test_a_quoted_or_mixed_run_of_digits_is_a_string() -> None:
    digits = "1" * 40
    assert load_mapping(f"a: '{digits}'\nb: \"{digits}\"\nc: x{digits}\nd: {digits}x\n") == {
        "a": digits,
        "b": digits,
        "c": "x" + digits,
        "d": digits + "x",
    }
    assert load_mapping(f"a: |\n  {digits}\n") == {"a": digits + "\n"}


@pytest.mark.parametrize("text", ["1e309", "-1e309", "1" * 400 + ".0", "-.5e400"])
def test_a_float_that_isnt_finite_is_refused(text: str) -> None:
    assert refusal(f"a: 1\nb: {text}") == "non-finite numbers are not allowed (line 2)"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("1e308", 1e308),
        ("-1e308", -1e308),
        ("1e-400", 0.0),
        ("1" * 40 + ".5", float("1" * 40 + ".5")),
    ],
)
def test_a_finite_float_loads(text: str, expected: float) -> None:
    assert load_mapping(f"a: {text}") == {"a": expected}


# --- B6: every parser exception is YAMLRejected ---------------------------------------------------


@pytest.mark.parametrize(
    "error",
    [
        RecursionError("maximum recursion depth exceeded"),
        ValueError("Exceeds the limit"),
        KeyError(),
    ],
)
def test_any_other_exception_is_rejected(monkeypatch: pytest.MonkeyPatch, error: Exception) -> None:
    def fails(loader: StrictLoader, node: yaml.ScalarNode) -> Any:
        raise error

    monkeypatch.setitem(StrictLoader.yaml_constructors, "tag:yaml.org,2002:int", fails)
    with pytest.raises(YAMLRejected) as caught:
        load_mapping("a: 1")
    assert str(caught.value) == f"invalid YAML: {type(error).__name__}"
    assert caught.value.__cause__ is not None


def test_the_loaders_own_refusal_isnt_wrapped() -> None:
    with pytest.raises(YAMLRejected) as caught:
        load_mapping("a: !!str x")
    assert caught.value.__cause__ is None


def test_safe_load_is_left_as_it_was() -> None:
    # The strict loader's float constructor is its own: SafeLoader's table is untouched.
    assert yaml.safe_load("a: 1.0e+999") == {"a": float("inf")}


# --- the rules that were already there ------------------------------------------------------------


def test_billion_laughs_is_refused_before_expansion() -> None:
    lines = ['a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]']
    for i in range(1, 9):
        prev, cur = chr(ord("a") + i - 1), chr(ord("a") + i)
        lines.append(f"{cur}: &{cur} [*{prev},*{prev},*{prev},*{prev},*{prev},*{prev},*{prev}]")
    with pytest.raises(YAMLRejected, match="aliases are not allowed"):
        load_mapping("\n".join(lines))


@pytest.mark.parametrize(
    ("scalar", "expected"),
    [
        ("yes", "yes"),
        ("no", "no"),
        ("on", "on"),
        ("off", "off"),
        ("y", "y"),
        ("0755", "0755"),
        ("0x1F", "0x1F"),
        ("12:30", "12:30"),
        ("2026-10-17", "2026-10-17"),
        (".inf", ".inf"),
        (".nan", ".nan"),
        ("1_000", "1_000"),
        ("true", True),
        ("False", False),
        ("42", 42),
        ("-7", -7),
        ("0", 0),
        ("1.5", 1.5),
        ("1e3", 1000.0),
        ("~", None),
        ("null", None),
    ],
)
def test_yaml_1_2_style_scalars(scalar: str, expected: object) -> None:
    value = load_mapping(f"v: {scalar}\n")["v"]
    assert value == expected
    assert type(value) is type(expected)


def test_merge_key_text_is_just_a_key() -> None:
    assert load_mapping("<<: 1\n") == {"<<": 1}


HINT = (
    " (hint: in an inline [a, b] list, {name} starts a mapping; "
    "put each path on its own '- ' line, or quote it)"
)


def test_braces_in_an_inline_list_get_a_hint() -> None:
    message = refusal("paths: [/docs/{doc}/rows]")
    # PyYAML's own message, then the hint once.
    assert message.startswith("invalid YAML: while parsing a flow sequence\n")
    assert "but got '{'\n" in message
    assert message.endswith("^" + HINT)
    assert message.count("(hint:") == 1


def test_an_inline_list_left_open_gets_no_hint() -> None:
    # A flow sequence, but no brace in the error.
    message = refusal("a: [1\n")
    assert message.startswith("invalid YAML: while parsing a flow sequence\n")
    assert "hint" not in message


def test_size_limit() -> None:
    assert refusal("a: " + "x" * 200, max_bytes=100) == "document is larger than 100 bytes"
    # The limit is in UTF-8 bytes, and a document of exactly the limit loads.
    assert load_mapping("a: b", max_bytes=4) == {"a": "b"}
    assert refusal("a: b", max_bytes=3) == "document is larger than 3 bytes"
    assert load_mapping("a: é", max_bytes=5) == {"a": "é"}
    assert refusal("a: é", max_bytes=4) == "document is larger than 4 bytes"


# --- every shipped policy loads as before ---------------------------------------------------------


class Before(yaml.SafeLoader):
    """The loader's implicit types as they stood before M6, frozen here, with none of its refusals.

    The table is written out rather than taken from ``StrictLoader``, so a later change to the
    loader's resolvers that alters a shipped policy shows up as a difference.
    """


_BEFORE_REPLACED = {
    "tag:yaml.org,2002:bool",
    "tag:yaml.org,2002:int",
    "tag:yaml.org,2002:float",
    "tag:yaml.org,2002:timestamp",
    "tag:yaml.org,2002:merge",
    "tag:yaml.org,2002:value",
}
Before.yaml_implicit_resolvers = {
    first: [(tag, regex) for tag, regex in resolvers if tag not in _BEFORE_REPLACED]
    for first, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
Before.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"),
    list("tTfF"),
)
Before.add_implicit_resolver(
    "tag:yaml.org,2002:int", re.compile(r"^[-+]?(?:0|[1-9][0-9]*)$"), list("-+0123456789")
)
Before.add_implicit_resolver(
    "tag:yaml.org,2002:float",
    re.compile(r"^[-+]?(?:(?:[0-9]+\.[0-9]*|\.[0-9]+)(?:[eE][-+]?[0-9]+)?|[0-9]+[eE][-+]?[0-9]+)$"),
    list("-+0123456789."),
)


def shipped() -> list[tuple[str, str]]:
    """Every policy document the repository ships: examples, profiles and compose-file policies."""
    found = [
        (str(path.relative_to(ROOT)), path.read_bytes().decode("utf-8"))
        for path in [
            ROOT / "examples" / "policy.yaml",
            ROOT / "examples" / "selftest-cases.yaml",
            *sorted((ROOT / "profiles").glob("*.yaml")),
        ]
    ]
    for compose in COMPOSE_FILES:
        services = yaml.safe_load((ROOT / compose).read_bytes())["services"]
        found += [
            (f"{compose} {name}", service["environment"]["ZOEYMCP_CONFIG"])
            for name, service in services.items()
            if "ZOEYMCP_CONFIG" in service.get("environment", {})
        ]
    return found


def test_every_shipped_policy_loads_as_before() -> None:
    documents = shipped()
    assert len(documents) >= 20
    for name, text in documents:
        before = yaml.load(text, Loader=Before)  # noqa: S506 - a SafeLoader
        assert json.dumps(load_mapping(text), sort_keys=True) == json.dumps(
            before, sort_keys=True
        ), name


# --- the emitter round trip -----------------------------------------------------------------------

SCALARS = (
    st.none()
    | st.booleans()
    | st.integers(min_value=-(10**40), max_value=10**40)
    | st.floats()
    | st.text(max_size=8)
)
VALUES = st.recursive(
    SCALARS,
    lambda inner: (
        st.lists(inner, max_size=3) | st.dictionaries(st.text(max_size=4), inner, max_size=3)
    ),
    max_leaves=12,
)
DUMPED = st.builds(
    lambda data, flow, unicode: yaml.safe_dump(
        data, default_flow_style=flow, allow_unicode=unicode, sort_keys=False
    ),
    st.dictionaries(st.text(max_size=6), VALUES, max_size=4),
    st.sampled_from([None, False, True]),
    st.booleans(),
)
RAW = st.text(alphabet=list("ab: -[]{},\n\t'\"#&*!?|>0123456789.e+~\\x\x85\u2028"), max_size=40)


@settings(max_examples=50, deadline=None)
@given(DUMPED | RAW)
def test_what_the_loader_accepts_round_trips_through_the_emitter(text: str) -> None:
    try:
        data = load_mapping(text)
    except YAMLRejected:
        return
    again = load_mapping(document(data))
    # By its JSON text, so 1, 1.0 and True don't compare equal.
    assert json.dumps(again, sort_keys=True) == json.dumps(data, sort_keys=True)
