from __future__ import annotations

import pytest

from zoeymcp.common.policy.paths import PathPatternError, Segment, parse_path_pattern


def test_parse_mixed_pattern() -> None:
    parsed = parse_path_pattern("/api/docs/{doc}/tables/*/rows/**")
    assert parsed.segments == (
        Segment("literal", "api"),
        Segment("literal", "docs"),
        Segment("capture", "doc"),
        Segment("literal", "tables"),
        Segment("star"),
        Segment("literal", "rows"),
        Segment("globstar"),
    )
    assert parsed.captures == ("doc",)


def test_root_pattern() -> None:
    assert parse_path_pattern("/").segments == ()


def test_trailing_slash_pattern() -> None:
    parsed = parse_path_pattern("/api/things/")
    assert parsed.segments == (Segment("literal", "api"), Segment("literal", "things"))
    assert parsed.trailing_slash is True
    assert parse_path_pattern("/api/things").trailing_slash is False


@pytest.mark.parametrize(
    "literal", ["v1", "2.0", "user@host", "a:b", "x-y_z~", "it's", "a+b", "a=b;c"]
)
def test_literal_characters(literal: str) -> None:
    assert parse_path_pattern(f"/{literal}").segments == (Segment("literal", literal),)


@pytest.mark.parametrize(
    ("pattern", "message"),
    [
        ("api", "must start with '/'"),
        ("/api//x", "empty segment"),
        ("/api//", "empty segment"),
        ("/api/**/", "already matches a trailing"),
        ("/**/x", "only allowed as the last segment"),
        ("/{Doc}", "invalid capture name"),
        ("/{}", "invalid capture name"),
        ("/{doc\n}", "invalid capture name"),
        ("/{a}/{a}", "appears twice"),
        ("/a/../b", "'..' segments are not allowed"),
        ("/./b", "'.' segments are not allowed"),
        ("/foo*", "partial wildcards"),
        ("/a%2Fb", "partial wildcards"),
        ("/a{b}", "partial wildcards"),
        ("/café", "partial wildcards"),
        ("/a b", "partial wildcards"),
        ("/v1\n", "partial wildcards"),
        ("/v1\n/x", "partial wildcards"),
        ("/a\\b", "partial wildcards"),
    ],
)
def test_invalid_patterns(pattern: str, message: str) -> None:
    with pytest.raises(PathPatternError, match=message):
        parse_path_pattern(pattern)
