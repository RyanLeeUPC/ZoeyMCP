"""Untrusted text in the portal (M5 design K.1, O.2 ``display``): capped, then revealed.

Hidden characters are written with ``chr()`` so this file holds none (the hygiene test).
"""

from __future__ import annotations

import pytest

from zoeymcp.portal.display import (
    DEFAULT_LIMIT,
    HOST_LIMIT,
    NAME_LIMIT,
    SUMMARY_LIMIT,
    shown,
)

ELLIPSIS = chr(0x2026)


def test_the_limits_are_pinned() -> None:
    assert (DEFAULT_LIMIT, NAME_LIMIT, HOST_LIMIT, SUMMARY_LIMIT) == (200, 128, 254, 300)


@pytest.mark.parametrize(
    ("codepoint", "what"),
    [
        (0x202E, "bidi override"),
        (0x2066, "bidi isolate"),
        (0x200B, "zero-width space"),
        (0x200D, "zero-width joiner"),
        (0xFEFF, "byte order mark"),
        (0x0000, "C0 NUL"),
        (0x001B, "C0 escape"),
        (0x000D, "carriage return"),
        (0x007F, "delete"),
        (0x0085, "C1 next line"),
        (0x009B, "C1 control sequence introducer"),
        (0x2028, "line separator"),
        (0x2029, "paragraph separator"),
        (0xE000, "private use"),
        (0x10FFFD, "supplementary private use"),
        (0x0378, "unassigned"),
        (0x3164, "Hangul filler"),
        (0xD800, "lone surrogate"),
    ],
)
def test_a_hidden_character_is_revealed(codepoint: int, what: str) -> None:
    text = f"pay{chr(codepoint)}ee"
    assert shown(text) == f"pay[U+{codepoint:04X}]ee", what


def test_visible_text_is_unchanged() -> None:
    for text in ("", "notes-key", "caf" + chr(0xE9), "tab\there", "日本"):
        assert shown(text) == text


def test_markup_stays_text() -> None:
    # The page uses textContent, so nothing is escaped: the text is shown as written.
    text = "<script>alert(1)</script> &amp; <b onclick=x>"
    assert shown(text) == text


def test_a_line_break_shows_as_backslash_n_in_a_single_line_field() -> None:
    assert shown("one\ntwo") == "one\\ntwo"
    assert shown("one\ntwo", single_line=True) == "one\\ntwo"
    assert shown("one\ntwo", single_line=False) == "one\ntwo"
    assert shown("one\r\ntwo", single_line=False) == "one[U+000D]\ntwo"


def test_the_default_cap() -> None:
    assert shown("a" * 200) == "a" * 200
    assert shown("a" * 201) == "a" * 200 + f"{ELLIPSIS}[+1]"
    assert shown("a" * 1000) == "a" * 200 + f"{ELLIPSIS}[+800]"


@pytest.mark.parametrize("limit", [1, 128, 254, 300])
def test_the_cap_at_its_boundary(limit: int) -> None:
    assert shown("x" * limit, limit) == "x" * limit
    assert shown("x" * (limit + 1), limit) == "x" * limit + f"{ELLIPSIS}[+1]"
    assert shown("x" * (limit + 7), limit) == "x" * limit + f"{ELLIPSIS}[+7]"


def test_the_cap_counts_code_points_before_revealing() -> None:
    zwsp = chr(0x200B)
    # A hidden character inside the cap counts as one code point and is revealed whole.
    assert shown("ab" + zwsp, 3) == "ab[U+200B]"
    # One past the cap is cut and counted, never revealed.
    assert shown("abc" + zwsp, 3) == f"abc{ELLIPSIS}[+1]"
    # A line break counts as one too.
    assert shown("a\nbc", 3) == f"a\\nb{ELLIPSIS}[+1]"


def test_the_marker_counts_what_was_left_out_not_what_was_shown() -> None:
    zwsp = chr(0x200B)
    assert shown(zwsp * 5, 2) == f"[U+200B][U+200B]{ELLIPSIS}[+3]"
