from __future__ import annotations

import json
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from zoeymcp.common.canonical import (
    MAX_SAFE_INTEGER,
    JSONRejected,
    digest,
    dumps_canonical,
    encode_scalar,
    key_order,
    loads_strict,
    render_for_approval,
)


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ('{"a": 1, "a": 2}', "duplicate key 'a'"),
        ('{"x": {"b": 1, "b": 1}}', "duplicate key 'b'"),
        ("NaN", "NaN is not allowed"),
        ('{"a": Infinity}', "Infinity is not allowed"),
        ("[-Infinity]", "-Infinity is not allowed"),
        ("1e400", "overflows to infinity"),
        (str(MAX_SAFE_INTEGER + 1), "outside the safe range"),
        (str(-MAX_SAFE_INTEGER - 1), "outside the safe range"),
        ("1" * 30, "integer is too long"),
        ('"\\ud800"', "lone surrogate"),
        ('{"\\udc00": 1}', "lone surrogate in object key"),
        ("\ufeff{}", "byte order mark"),
        ("{", "invalid JSON"),
        ("[1,]", "invalid JSON"),
    ],
)
def test_loads_strict_rejects(text: str, message: str) -> None:
    with pytest.raises(JSONRejected, match=message):
        loads_strict(text)


def test_loads_strict_accepts_safe_integer_limits() -> None:
    assert loads_strict(f"[{MAX_SAFE_INTEGER}, {-MAX_SAFE_INTEGER}]") == [
        MAX_SAFE_INTEGER,
        -MAX_SAFE_INTEGER,
    ]


def test_unsafe_integers_allowed_when_asked() -> None:
    assert loads_strict(str(2**60), safe_integers=False) == 2**60


def test_depth_limit() -> None:
    assert loads_strict("[" * 64 + "]" * 64, max_depth=64) is not None
    with pytest.raises(JSONRejected, match="nested deeper"):
        loads_strict("[" * 65 + "]" * 65, max_depth=64)
    with pytest.raises(JSONRejected, match="nested deeper"):
        loads_strict("[" * 100_000 + "]" * 100_000, max_bytes=1_000_000)


def test_size_limit_bytes_and_str() -> None:
    with pytest.raises(JSONRejected, match="larger than"):
        loads_strict(b'"' + b"a" * 100 + b'"', max_bytes=50)
    with pytest.raises(JSONRejected, match="larger than"):
        loads_strict('"' + "é" * 30 + '"', max_bytes=50)  # 62 bytes in UTF-8


def test_invalid_utf8() -> None:
    with pytest.raises(JSONRejected, match="not valid UTF-8"):
        loads_strict(b'"\xff"')


def test_canonical_form_is_compact_and_sorted() -> None:
    value = {"b": [1, 2.5, None, True], "a": {"z": "é", "y": False}}
    assert dumps_canonical(value) == '{"a":{"y":false,"z":"é"},"b":[1,2.5,null,true]}'.encode()


def test_keys_sort_by_utf16_code_units() -> None:
    # U+1F600 (surrogate pair D83D DE00) sorts before U+FB01 in UTF-16, after it by code point.
    value = {"ﬁ": 1, "\U0001f600": 2}
    assert dumps_canonical(value).decode() == '{"\U0001f600":2,"ﬁ":1}'


def test_canonical_independent_of_insertion_order() -> None:
    assert dumps_canonical({"a": 1, "b": 2}) == dumps_canonical({"b": 2, "a": 1})


@pytest.mark.parametrize(
    "value",
    [
        float("nan"),
        float("inf"),
        {1: "x"},
        (1, 2),
        {"a": {1, 2}},
        b"bytes",
        "\udfff",
        MAX_SAFE_INTEGER + 1,
    ],
)
def test_dumps_rejects_non_json(value: Any) -> None:
    with pytest.raises(JSONRejected):
        dumps_canonical(value)


def test_digest_format_and_stability() -> None:
    first = digest({"name": "get_quote", "inputSchema": {"type": "object"}})
    second = digest({"inputSchema": {"type": "object"}, "name": "get_quote"})
    assert first == second
    assert first.startswith("sha256:")
    assert len(first) == len("sha256:") + 64


def test_render_for_approval_escapes_newlines() -> None:
    rendered = render_for_approval({"to": "a@example.com", "body": "line one\nfake: field"})
    assert rendered == '{\n  "body": "line one\\nfake: field",\n  "to": "a@example.com"\n}'
    assert rendered.count("\n") == 3


def test_render_keeps_format_characters_for_the_text_rules_to_refuse() -> None:
    assert "\u202e" in render_for_approval({"body": "abc\u202edef"})


def test_render_empty_containers() -> None:
    assert render_for_approval({"a": [], "b": {}}) == '{\n  "a": [],\n  "b": {}\n}'


_json = st.recursive(
    st.none()
    | st.booleans()
    | st.integers(min_value=-MAX_SAFE_INTEGER, max_value=MAX_SAFE_INTEGER)
    | st.floats(allow_nan=False, allow_infinity=False)
    | st.text(alphabet=st.characters(codec="utf-8")),
    lambda children: (
        st.lists(children, max_size=5)
        | st.dictionaries(
            st.text(alphabet=st.characters(codec="utf-8"), max_size=8), children, max_size=5
        )
    ),
    max_leaves=25,
)


@given(_json)
def test_property_round_trip(value: Any) -> None:
    encoded = dumps_canonical(value)
    assert loads_strict(encoded) == value
    assert dumps_canonical(loads_strict(encoded)) == encoded


@given(_json)
def test_property_canonical_matches_stdlib_parse(value: Any) -> None:
    assert json.loads(dumps_canonical(value)) == value


@given(_json)
def test_property_rendering_parses_to_the_same_value(value: Any) -> None:
    assert loads_strict(render_for_approval(value)) == value


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, "null"),
        (True, "true"),
        (False, "false"),
        (0, "0"),
        (-12, "-12"),
        (1.5, "1.5"),
        (1e20, "1e+20"),
        ('a"b', '"a\\"b"'),
        ("café", '"café"'),
    ],
)
def test_encode_scalar(value: Any, expected: str) -> None:
    assert encode_scalar(value) == expected
    assert dumps_canonical(value).decode() == expected


def test_encode_scalar_refuses_containers() -> None:
    containers: list[Any] = [[], {}, (1,)]
    for value in containers:
        with pytest.raises(JSONRejected, match="not a JSON scalar"):
            encode_scalar(value)


def test_key_order_is_utf16() -> None:
    # Above the BMP, UTF-16 surrogates (0xD83D...) sort before U+FF5E; code points wouldn't.
    emoji, high = chr(0x1F600), chr(0xFF5E)
    assert sorted([emoji, high, "b", "a"], key=key_order) == ["a", "b", emoji, high]
