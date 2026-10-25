"""Which URIs an agent may read through a server path (M6 design L.6, SPEC-2).

A URI is allowed when it equals a served fixed URI, or matches a served template. Templates are
L.1's level 1 (``fields.uri_template``): ``scheme://authority`` and then path segments, each a
literal or a whole-segment expression ``{name}``. A URI matches a template when its scheme and
authority equal the template's byte for byte, it has as many path segments, each literal segment
is equal byte for byte, and each expression's value is 1 to :data:`VALUE_MAX` characters of
``[A-Za-z0-9._~-]`` and neither ``.`` nor ``..``.

SPEC-2's rules, all of which that one character set keeps: a value is read after percent-decoding,
a ``/`` inside it is refused (a raw one splits the segment; ``%2F`` decodes to it), RFC 3986 3.3's
dot-segments are refused (a normalizing upstream would resolve ``..`` to another, unreviewed
resource), and no percent-encoding of an unreserved character is accepted (RFC 3986 6.2.2.2 makes
``%2E`` and ``.`` the same, so ``%2E``, ``%2e``, ``.%2E`` and ``%2E%2E`` are refused). Any ``%``
in a value decodes either to an unreserved character or to one outside the set, so a value is
accepted only with no ``%`` at all, and its length is the same before and after decoding.

Nothing here reads the upstream: the caller passes the fixed URIs and templates the path serves
(included, pinned and matching in the connection's latest evaluation). Pure.
"""

from __future__ import annotations

import re
from collections.abc import Collection
from typing import Final

VALUE_MAX: Final = 128
_VALUE = re.compile(rf"[A-Za-z0-9._~-]{{1,{VALUE_MAX}}}")
_EXPRESSION = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]{0,31})\}")
DOT_SEGMENTS: Final = frozenset({".", ".."})


def _split(text: str) -> tuple[str, str, list[str]] | None:
    """The scheme, the authority and the path's segments (none for no path), or None without
    ``://``."""
    scheme, separator, rest = text.partition("://")
    if not separator:
        return None
    authority, slash, path = rest.partition("/")
    return scheme, authority, path.split("/") if slash else []


def variables(template: str) -> tuple[str, ...]:
    """The names of a template's expressions, in order: what a completion of it may name."""
    found = _split(template)
    if found is None:
        return ()
    names = []
    for segment in found[2]:
        expression = _EXPRESSION.fullmatch(segment)
        if expression is not None:
            names.append(expression.group(1))
    return tuple(names)


def value_allowed(value: str) -> bool:
    """Whether one expression's value may be read (SPEC-2)."""
    return _VALUE.fullmatch(value) is not None and value not in DOT_SEGMENTS


def matches(uri: str, template: str) -> bool:
    """Whether ``uri`` is one of the URIs ``template`` names, under SPEC-2's rules."""
    wanted, given = _split(template), _split(uri)
    if wanted is None or given is None:
        return False
    if given[:2] != wanted[:2] or len(given[2]) != len(wanted[2]):
        return False
    for index, pattern in enumerate(wanted[2]):
        segment = given[2][index]
        if _EXPRESSION.fullmatch(pattern) is not None:
            if not value_allowed(segment):
                return False
        elif segment != pattern:
            return False
    return True


def allowed(uri: str, fixed: Collection[str], templates: Collection[str]) -> bool:
    """Whether an agent may read ``uri``: one of the ``fixed`` URIs, or one a template in
    ``templates`` names."""
    return uri in fixed or any(matches(uri, template) for template in templates)
