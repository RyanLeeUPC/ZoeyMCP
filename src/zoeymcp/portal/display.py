"""Text the portal didn't write, made fit to show (M5 design K.1). Pure, so each rule can be tested.

Every string from outside the portal's own code goes through :func:`shown` before it goes into
an answer: a provider's ``error`` and ``error_description``, scopes, store ``meta``, ledger and
journal fields, policy names, passkey and secret names, origins in bindings. The page then puts
it into the DOM through ``textContent`` or a property only (K.2), so markup stays text and nothing
here escapes HTML. What this guards against is text that hides or fakes content: it is capped,
and every character the text rules refuse (controls, bidi and zero-width format characters,
unassigned and private-use code points, line and paragraph separators) shows as ``[U+XXXX]``.
"""

from __future__ import annotations

from typing import Final

from ..common.textrules import reveal_hidden

# Caps in code points, by what the text is.
DEFAULT_LIMIT: Final = 200
NAME_LIMIT: Final = 128
HOST_LIMIT: Final = 254
SUMMARY_LIMIT: Final = 300


def shown(text: str, limit: int = DEFAULT_LIMIT, *, single_line: bool = True) -> str:
    """``text`` cut to ``limit`` code points, the cut marked ``…[+N]`` with the number left out,
    and every hidden character revealed. In a single-line field a line break shows as ``\\n``;
    a multi-line one keeps it."""
    left_out = len(text) - limit
    revealed = reveal_hidden(text[:limit])
    if single_line:
        revealed = revealed.replace("\n", "\\n")
    return f"{revealed}…[+{left_out}]" if left_out > 0 else revealed
