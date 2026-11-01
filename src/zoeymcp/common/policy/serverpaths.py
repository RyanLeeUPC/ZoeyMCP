"""Which vault paths a gateway server's requests take (M8 design A.3; CR-1, F-47).

A gateway server's ``path`` as the vault matches it, and whether a route rule's path lets a
request on it through. ``check`` uses these to tie each server to its route's rules, and the
vault's held-tool map (M8) to know which server a request on a route belongs to. They moved here
from ``check`` unchanged: they need :mod:`.match`, so they can't live in :mod:`.paths`, which
:mod:`.match` imports. Pure: the standard library and the policy package only.
"""

from __future__ import annotations

import re
from typing import Final

from .match import NormalizedPath, path_matches
from .paths import PathPatternError, parse_path_pattern
from .schema import Rule

MCP_SERVER_PATH: Final = re.compile(r"^/[A-Za-z0-9._~/-]*$")


def request_path(path: str) -> NormalizedPath | None:
    """A gateway server's ``path`` as the vault matches it, or ``None`` if the vault refuses it."""
    if not MCP_SERVER_PATH.fullmatch(path):
        return None
    try:
        # The pattern above leaves out '*' and braces, so every segment is a literal.
        parsed = parse_path_pattern(path)
    except PathPatternError:
        return None
    return NormalizedPath(tuple(s.value for s in parsed.segments), parsed.trailing_slash)


def reaches(rule: Rule, source: str, path: NormalizedPath) -> bool:
    """Whether the vault lets ``source`` (one of ``rule``'s paths) reach ``path``."""
    try:
        return path_matches(rule, source, path)
    except PathPatternError:
        return False  # reported with the route's rules
