"""Path patterns for route rules (design §4.2).

A pattern is matched segment by segment against an already-normalized request path:

- a literal segment matches itself exactly;
- ``*`` matches one segment;
- ``**`` matches the rest of the path (zero or more segments), and only in the last position;
- ``{name}`` captures one segment, constrained by the rule's ``params``;
- a trailing ``/`` means the request path must end with ``/`` too.

Partial wildcards (``foo*``) and percent-encoding are not supported: patterns describe decoded
paths, and the vault normalizes and refuses ambiguous paths before matching.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

CAPTURE_NAME = re.compile(r"^[a-z_][a-z0-9_]{0,31}$")
# Characters allowed in a path segment, both in patterns and in normalized request paths.
SEGMENT_CHARS = re.compile(r"^[A-Za-z0-9._~!$&'()+,;=:@-]+$")

SegmentKind = Literal["literal", "star", "globstar", "capture"]


@dataclass(frozen=True)
class Segment:
    kind: SegmentKind
    value: str = ""


@dataclass(frozen=True)
class PathPattern:
    source: str
    segments: tuple[Segment, ...]
    trailing_slash: bool = False

    @property
    def captures(self) -> tuple[str, ...]:
        return tuple(s.value for s in self.segments if s.kind == "capture")


class PathPatternError(ValueError):
    """Raised for a path pattern that isn't valid."""


def parse_path_pattern(pattern: str) -> PathPattern:
    """Parse and validate a path pattern such as ``/api/docs/{doc}/tables/**``."""
    if not pattern.startswith("/"):
        raise PathPatternError("must start with '/'")
    if pattern == "/":
        return PathPattern(pattern, ())
    body = pattern[1:]
    trailing = body.endswith("/")
    if trailing:
        body = body[:-1]
    parts = body.split("/")
    segments: list[Segment] = []
    seen: set[str] = set()
    for position, part in enumerate(parts):
        last = position == len(parts) - 1
        if part == "":
            raise PathPatternError("empty segment (a doubled '/')")
        if part == "**":
            if not last:
                raise PathPatternError("'**' is only allowed as the last segment")
            if trailing:
                raise PathPatternError("'**' already matches a trailing '/'")
            segments.append(Segment("globstar"))
        elif part == "*":
            segments.append(Segment("star"))
        elif part.startswith("{") and part.endswith("}"):
            name = part[1:-1]
            if not CAPTURE_NAME.fullmatch(name):
                raise PathPatternError(f"invalid capture name {name!r}")
            if name in seen:
                raise PathPatternError(f"capture {{{name}}} appears twice")
            seen.add(name)
            segments.append(Segment("capture", name))
        elif part in (".", ".."):
            raise PathPatternError(f"'{part}' segments are not allowed")
        elif SEGMENT_CHARS.fullmatch(part):
            segments.append(Segment("literal", part))
        else:
            raise PathPatternError(
                f"segment {part!r} has characters that aren't allowed "
                "(no partial wildcards, braces or percent-encoding)"
            )
    return PathPattern(pattern, tuple(segments), trailing)
