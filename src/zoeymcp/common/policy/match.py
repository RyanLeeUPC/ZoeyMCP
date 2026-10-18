"""Matching route rules against normalized request paths (design §4.2).

The vault uses this for every request, and ``check`` uses it to see which rules reach a gateway
server's path. Nothing here does I/O.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import quote

from .paths import PathPattern, parse_path_pattern
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
