"""Matching route rules against normalized request paths (design §4.2).

The vault uses this for every request, and ``check`` uses it to see which rules reach a gateway
server's path. Nothing here does I/O.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import quote, unquote_to_bytes

from .paths import SEGMENT_CHARS, PathPattern, parse_path_pattern
from .schema import RegexParam, Rule


@dataclass(frozen=True)
class NormalizedPath:
    segments: tuple[str, ...]
    trailing_slash: bool = False

    @property
    def text(self) -> str:
        """The decoded path, e.g. ``/2.0/user/``."""
        body = "/".join(self.segments)
        if not self.segments:
            return "/"
        return "/" + body + ("/" if self.trailing_slash else "")

    def encoded(self) -> str:
        """The path as sent upstream, each segment percent-encoded again."""
        if not self.segments:
            return "/"
        body = "/".join(quote(s, safe="!$&'()*+,;=:@~-._") for s in self.segments)
        return "/" + body + ("/" if self.trailing_slash else "")

    def without_first(self) -> NormalizedPath:
        rest = self.segments[1:]
        return NormalizedPath(rest, self.trailing_slash if rest else False)


MAX_PATH_BYTES = 4096
_PERCENT = re.compile(rb"%(?![0-9A-Fa-f]{2})")


class RequestRejected(ValueError):
    """A request ZoeyMCP refuses. ``reason`` is for logs, never for the response body."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def normalize_path(raw: bytes) -> NormalizedPath:
    """Normalize a raw (still percent-encoded) request path, or raise :class:`RequestRejected`.

    The path is split on ``/`` *before* decoding, so an encoded slash can never become a segment
    boundary. Each segment is then decoded exactly once, and anything ambiguous is refused:
    encoded slashes or backslashes, ``%`` left after decoding (double encoding), ``.``/``..``,
    empty segments, non-ASCII, and characters outside the allowed set.
    """
    if len(raw) > MAX_PATH_BYTES:
        raise RequestRejected("path too long")
    if not raw.startswith(b"/"):
        raise RequestRejected("path must start with '/'")
    if any(b < 0x21 or b > 0x7E for b in raw):
        raise RequestRejected("path has raw non-printable or non-ASCII bytes")
    if _PERCENT.search(raw):
        raise RequestRejected("malformed percent-encoding")
    if raw == b"/":
        return NormalizedPath(())
    body = raw[1:]
    trailing = body.endswith(b"/")
    if trailing:
        body = body[:-1]
    segments: list[str] = []
    for part in body.split(b"/"):
        if not part:
            raise RequestRejected("empty path segment")
        decoded = unquote_to_bytes(part)
        try:
            text = decoded.decode("ascii")
        except UnicodeDecodeError as exc:
            raise RequestRejected("non-ASCII path segment") from exc
        if "/" in text or "\\" in text:
            raise RequestRejected("slash or backslash inside a path segment")
        if "%" in text:
            raise RequestRejected("double percent-encoding")
        if text in (".", ".."):
            raise RequestRejected("dot segment in path")
        if not SEGMENT_CHARS.fullmatch(text):
            raise RequestRejected("path segment has characters that aren't allowed")
        segments.append(text)
    return NormalizedPath(tuple(segments), trailing)


def match_pattern(pattern: PathPattern, path: NormalizedPath) -> dict[str, str] | None:
    """Captures if ``pattern`` matches ``path``, else ``None``."""
    captures: dict[str, str] = {}
    segments = path.segments
    for index, segment in enumerate(pattern.segments):
        if segment.kind == "globstar":
            return captures
        if index >= len(segments):
            return None
        actual = segments[index]
        if segment.kind == "literal":
            if actual != segment.value:
                return None
        elif segment.kind == "capture":
            captures[segment.value] = actual
    if len(segments) != len(pattern.segments):
        return None
    if path.trailing_slash != pattern.trailing_slash:
        return None
    return captures


def _param_allows(constraint: list[str] | RegexParam, value: str) -> bool:
    if isinstance(constraint, RegexParam):
        return re.fullmatch(constraint.regex, value) is not None
    return value in constraint


def path_matches(rule: Rule, source: str, path: NormalizedPath) -> bool:
    """Whether ``source``, one of ``rule``'s path patterns, matches ``path`` under its params."""
    captures = match_pattern(parse_path_pattern(source), path)
    if captures is None:
        return False
    return all(
        _param_allows(rule.params[name], value)
        for name, value in captures.items()
        if name in rule.params
    )


def rule_matches(rule: Rule, method: str, path: NormalizedPath) -> bool:
    if method not in rule.methods:
        return False
    return any(path_matches(rule, source, path) for source in rule.paths)
