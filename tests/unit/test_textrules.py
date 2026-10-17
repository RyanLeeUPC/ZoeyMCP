from __future__ import annotations

import unicodedata

import pytest
from hypothesis import given
from hypothesis import strategies as st

from zoeymcp.common.textrules import (
    INVISIBLE_CHARACTERS,
    TextRuleError,
    check_text,
    find_violations,
)


def reasons(text: str, **kwargs: object) -> list[str]:
    return [v.reason for v in find_violations(text, max_chars=1000, **kwargs)]  # type: ignore[arg-type]


def test_plain_text_passes() -> None:
    text = "Subject: hello\n\nTwo lines,\tone tab, and ünïcödé letters. 日本語 ✓"
    assert check_text(text, max_chars=1000) == text


@pytest.mark.parametrize(
    ("char", "reason"),
    [
        ("\u200b", "format character (zero-width, bidi or tag)"),  # ZERO WIDTH SPACE
        ("\u200d", "format character (zero-width, bidi or tag)"),  # ZERO WIDTH JOINER
        ("\u202e", "format character (zero-width, bidi or tag)"),  # RIGHT-TO-LEFT OVERRIDE
        ("\u2066", "format character (zero-width, bidi or tag)"),  # LEFT-TO-RIGHT ISOLATE
        ("\ufeff", "format character (zero-width, bidi or tag)"),  # BYTE ORDER MARK
        ("\U000e0041", "format character (zero-width, bidi or tag)"),  # TAG LATIN CAPITAL A
        ("\u00ad", "format character (zero-width, bidi or tag)"),  # SOFT HYPHEN
        ("\r", "control character"),
        ("\x00", "control character"),
        ("\x1b", "control character"),
        ("\x85", "control character"),  # NEXT LINE
        ("\u2028", "line separator"),
        ("\u2029", "paragraph separator"),
        ("\ue000", "private-use character"),
        ("\ud800", "surrogate code point"),
    ],
)
def test_rejected_characters(char: str, reason: str) -> None:
    assert reasons(f"before{char}after") == [reason]


@pytest.mark.parametrize("char", sorted(INVISIBLE_CHARACTERS))
def test_invisible_characters_rejected(char: str) -> None:
    assert reasons(f"a{char}b") == ["invisible character"]


def test_unassigned_code_point_rejected() -> None:
    unassigned = next(
        chr(cp) for cp in range(0x0378, 0x10FFFF) if unicodedata.category(chr(cp)) == "Cn"
    )
    assert reasons(unassigned) == ["unassigned code point"]


def test_single_line_rejects_newline_and_tab() -> None:
    assert reasons("a\nb", single_line=True) == ["line break in a single-line field"]
    assert reasons("a\tb", single_line=True) == ["tab not allowed here"]


def test_tabs_can_be_refused_in_multiline_text() -> None:
    assert reasons("a\tb", allow_tabs=False) == ["tab not allowed here"]
    assert reasons("a\nb", allow_tabs=False) == []


def test_length_limits_count_code_points() -> None:
    assert find_violations("é" * 10, max_chars=10) == []
    [too_long] = find_violations("é" * 11, max_chars=10)
    assert too_long.index == -1
    assert "11 characters, limit 10" in too_long.reason
    [too_short] = find_violations("", max_chars=10, min_chars=1)
    assert "too short" in too_short.reason


def test_violation_positions_and_names() -> None:
    [violation] = find_violations("ab\u202ecd", max_chars=100)
    assert violation.index == 2
    assert violation.codepoint == 0x202E
    assert "U+202E (RIGHT-TO-LEFT OVERRIDE) at position 2" in str(violation)


def test_report_is_bounded() -> None:
    assert len(find_violations("\u200b" * 500, max_chars=1000, max_reported=10)) == 10


def test_check_text_raises_with_all_violations() -> None:
    with pytest.raises(TextRuleError) as info:
        check_text("x\u200by\u2028z", max_chars=100)
    assert len(info.value.violations) == 2


_SAFE = st.characters(
    codec="utf-8",
    categories=(
        "Lu",
        "Ll",
        "Lt",
        "Lo",
        "Nd",
        "Nl",
        "No",
        "Pc",
        "Pd",
        "Ps",
        "Pe",
        "Pi",
        "Pf",
        "Po",
        "Sm",
        "Sc",
        "Sk",
        "So",
        "Zs",
    ),
    exclude_characters="".join(INVISIBLE_CHARACTERS),
)


@given(st.text(alphabet=st.one_of(_SAFE, st.just("\n")), max_size=200))
def test_property_visible_text_passes(text: str) -> None:
    assert find_violations(text, max_chars=200) == []


@given(
    st.text(alphabet=_SAFE, max_size=50),
    st.characters(categories=["Cf"]),
    st.text(alphabet=_SAFE, max_size=50),
)
def test_property_any_format_character_is_caught(before: str, hidden: str, after: str) -> None:
    violations = find_violations(before + hidden + after, max_chars=200)
    assert [v.index for v in violations] == [len(before)]
