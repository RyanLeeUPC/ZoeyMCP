from __future__ import annotations

import pytest

from zoeymcp.common.yamlload import YAMLRejected, load_mapping


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
        ("a: !!python/object:os.system x\n", "invalid YAML"),
        ("a: [1\n", "invalid YAML"),
        ("1: x\n", "top-level key 1 is not a string"),
    ],
)
def test_rejected_documents(text: str, message: str) -> None:
    with pytest.raises(YAMLRejected, match=message):
        load_mapping(text)


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


def test_size_limit() -> None:
    with pytest.raises(YAMLRejected, match="larger than"):
        load_mapping("a: " + "x" * 200, max_bytes=100)
