"""Which URIs an agent may read (M6 design L.6, SPEC-2): equal to a served fixed URI, or named
by a served template, each expression's value 1 to 128 characters of ``[A-Za-z0-9._~-]`` after
percent-decoding, never ``.`` or ``..``, never a ``/``, no percent-encoded unreserved character
at all, the scheme and authority equal byte for byte."""

from __future__ import annotations

import pytest

from zoeymcp.gateway import resourcematch
from zoeymcp.gateway.resourcematch import allowed, matches, value_allowed, variables

TEMPLATE = "notes://notes/{id}"
TWO = "notes://notes/{folder}/items/{id}"
FIXED = "notes://index"


@pytest.mark.parametrize(
    "uri",
    [
        "notes://notes/1",
        "notes://notes/a.b",
        "notes://notes/~x_y-z",
        "notes://notes/..a",
        "notes://notes/a..",
        "notes://notes/...",
        "notes://notes/" + "a" * 128,
    ],
)
def test_a_value_the_template_allows(uri: str) -> None:
    assert matches(uri, TEMPLATE)
    assert allowed(uri, (), [TEMPLATE])


REFUSED = [
    ("notes://notes/..", "a dot-segment"),
    ("notes://notes/.", "a dot-segment"),
    ("notes://notes/%2e%2e", "an encoded dot-segment"),
    ("notes://notes/%2E%2E", "an encoded dot-segment"),
    ("notes://notes/.%2e", "an encoded dot-segment"),
    ("notes://notes/.%2E", "an encoded dot-segment"),
    ("notes://notes/%2E", "an encoded dot"),
    ("notes://notes/%2e", "an encoded dot"),
    ("notes://notes/%41", "an encoded unreserved letter"),
    ("notes://notes/%7E", "an encoded tilde"),
    ("notes://notes/a%2Fb", "an encoded slash"),
    ("notes://notes/a%2fb", "an encoded slash"),
    ("notes://notes/a/b", "a slash in a value"),
    ("notes://notes/%C3%A9", "an encoded non-ASCII value"),
    ("notes://notes/%", "a broken escape"),
    ("notes://notes/", "an empty value"),
    ("notes://notes/1/", "a trailing slash"),
    ("notes://notes", "no value"),
    ("notes://notes/" + "a" * 129, "a 129-character value"),
    ("notes://other/1", "another authority"),
    ("notes://Notes/1", "another authority, by case"),
    ("notes://notes:80/1", "another authority, by port"),
    ("other://notes/1", "another scheme"),
    ("Notes://notes/1", "another scheme, by case"),
    ("notes://notes/1?x=1", "a query"),
    ("notes://notes/1#top", "a fragment"),
    ("notes://notes/a b", "a space"),
    ("notes://notes/a\u00e9", "a non-ASCII value"),
    ("notes:/notes/1", "no authority"),
    ("notes://notes/1/2", "another segment"),
]


@pytest.mark.parametrize(
    ("uri", "why"),
    REFUSED,
    # Plain IDs: a value with escapes or non-ASCII characters would not survive a rerun by ID.
    ids=[
        f"{index}-{why.replace(' ', '-').replace(',', '')}"
        for index, (_, why) in enumerate(REFUSED)
    ],
)
def test_a_value_the_template_refuses(uri: str, why: str) -> None:
    assert not matches(uri, TEMPLATE), why
    assert not allowed(uri, (), [TEMPLATE]), why


def test_literal_segments_are_equal_byte_for_byte() -> None:
    assert matches("notes://notes/a/items/b", TWO)
    assert not matches("notes://notes/a/Items/b", TWO)
    assert not matches("notes://notes/a/item/b", TWO)
    assert not matches("notes://notes/../items/b", TWO)
    assert not matches("notes://notes/a/items/..", TWO)


def test_a_template_without_an_expression_names_itself_only() -> None:
    assert matches("notes://h/a", "notes://h/a")
    assert not matches("notes://h/b", "notes://h/a")
    assert matches("notes://h", "notes://h")
    assert not matches("notes://h/", "notes://h")


def test_an_empty_authority_is_one_too() -> None:
    assert matches("file:///a", "file:///{name}")
    assert not matches("file://h/a", "file:///{name}")


def test_neither_side_without_a_scheme_and_authority_matches() -> None:
    assert not matches("notes:index", "notes:index")
    assert not matches("notes://notes/1", "notes/{id}")


def test_a_fixed_uri_is_allowed_only_exactly() -> None:
    assert allowed(FIXED, [FIXED], ())
    assert not allowed(FIXED + "/", [FIXED], ())
    assert not allowed("NOTES://index", [FIXED], ())
    assert not allowed(FIXED, (), ())
    assert not allowed(FIXED, (), [TEMPLATE])


def test_any_served_template_may_allow_a_uri() -> None:
    assert allowed("notes://notes/a/items/b", [FIXED], [TEMPLATE, TWO])
    assert allowed("notes://notes/a", [FIXED], [TWO, TEMPLATE])
    assert not allowed("notes://notes/a/b", [FIXED], [TEMPLATE, TWO])


@pytest.mark.parametrize(
    ("value", "allowed_"),
    [
        ("a", True),
        ("A-Z_0.9~", True),
        ("a" * 128, True),
        ("a" * 129, False),
        ("", False),
        (".", False),
        ("..", False),
        ("%2E", False),
        ("a/b", False),
    ],
    ids=["one", "every-class", "128", "129", "empty", "dot", "dot-dot", "encoded", "slash"],
)
def test_one_value(value: str, allowed_: bool) -> None:
    assert value_allowed(value) is allowed_


def test_the_value_limit() -> None:
    assert resourcematch.VALUE_MAX == 128
    assert {".", ".."} == resourcematch.DOT_SEGMENTS


@pytest.mark.parametrize(
    ("template", "names"),
    [
        (TEMPLATE, ("id",)),
        (TWO, ("folder", "id")),
        ("notes://h/a", ()),
        ("notes://h", ()),
        ("file:///{_n9}", ("_n9",)),
        ("notes", ()),
    ],
    ids=["one", "two", "none", "no-path", "empty-authority", "no-scheme"],
)
def test_a_templates_variables(template: str, names: tuple[str, ...]) -> None:
    assert variables(template) == names
