"""Plain-text rules for text a human must read whole (design R42, §5.2).

Approval prompts, and every field that feeds one, must not be able to hide or disguise content.
These rules reject anything that renders as nothing, renders differently from what it is, or can
fake a line break, rather than trying to sanitize it: a refused call is safe, and a cleaned-up
one is no longer exactly what was asked for.

Text that must still be read whole, such as tool results and ``review`` output, goes through
:func:`reveal_hidden` instead, which shows each refused character as a visible escape.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from functools import lru_cache

# Characters that render as nothing or as blank space without being format characters, so the
# category check alone would let them through.
INVISIBLE_CHARACTERS = frozenset(
    {
        "\u034f",  # COMBINING GRAPHEME JOINER
        "\u115f",  # HANGUL CHOSEONG FILLER
        "\u1160",  # HANGUL JUNGSEONG FILLER
        "\u17b4",  # KHMER VOWEL INHERENT AQ
        "\u17b5",  # KHMER VOWEL INHERENT AA
        "\u2800",  # BRAILLE PATTERN BLANK
        "\u3164",  # HANGUL FILLER
        "\uffa0",  # HALFWIDTH HANGUL FILLER
    }
)

REJECTED_CATEGORIES = {
    "Cc": "control character",
    "Cf": "format character (zero-width, bidi or tag)",
    "Cs": "surrogate code point",
    "Co": "private-use character",
    "Cn": "unassigned code point",
    "Zl": "line separator",
    "Zp": "paragraph separator",
}


@dataclass(frozen=True)
class TextViolation:
    """One reason a text was refused. ``index`` is a code-point offset, or -1 for the whole text."""

    index: int
    codepoint: int | None
    reason: str

    def __str__(self) -> str:
        if self.codepoint is None:
            return self.reason
        name = unicodedata.name(chr(self.codepoint), "unnamed")
        return f"{self.reason} U+{self.codepoint:04X} ({name}) at position {self.index}"


class TextRuleError(ValueError):
    """Raised when a text breaks the plain-text rules."""

    def __init__(self, violations: list[TextViolation]) -> None:
        self.violations = tuple(violations)
        super().__init__("; ".join(str(v) for v in self.violations))


def find_violations(
    text: str,
    *,
    max_chars: int,
    min_chars: int = 0,
    single_line: bool = False,
    allow_tabs: bool = True,
    max_reported: int = 10,
) -> list[TextViolation]:
    """Return the ways ``text`` breaks the plain-text rules (empty if it's acceptable).

    Lengths count code points. ``\\n`` is the only line break accepted, and only in multi-line
    text; ``\\r`` is a control character and always refused.
    """
    violations: list[TextViolation] = []
    length = len(text)
    if length > max_chars:
        violations.append(
            TextViolation(-1, None, f"too long: {length} characters, limit {max_chars}")
        )
    if length < min_chars:
        violations.append(
            TextViolation(-1, None, f"too short: {length} characters, minimum {min_chars}")
        )

    for index, char in enumerate(text):
        if len(violations) >= max_reported:
            break
        if char == "\n":
            if single_line:
                violations.append(
                    TextViolation(index, ord(char), "line break in a single-line field")
                )
            continue
        if char == "\t":
            if single_line or not allow_tabs:
                violations.append(TextViolation(index, ord(char), "tab not allowed here"))
            continue
        if char in INVISIBLE_CHARACTERS:
            violations.append(TextViolation(index, ord(char), "invisible character"))
            continue
        category = unicodedata.category(char)
        reason = REJECTED_CATEGORIES.get(category)
        if reason is not None:
            violations.append(TextViolation(index, ord(char), reason))
    return violations


def check_text(
    text: str,
    *,
    max_chars: int,
    min_chars: int = 0,
    single_line: bool = False,
    allow_tabs: bool = True,
) -> str:
    """Return ``text`` unchanged if it follows the rules; raise :class:`TextRuleError` if not."""
    violations = find_violations(
        text,
        max_chars=max_chars,
        min_chars=min_chars,
        single_line=single_line,
        allow_tabs=allow_tabs,
    )
    if violations:
        raise TextRuleError(violations)
    return text


# Everything but printable ASCII, \n and \t: the only characters reveal_hidden has to look at.
_MAYBE_HIDDEN = re.compile(r"[^\x20-\x7e\n\t]")


@lru_cache(maxsize=4096)
def _revealed(char: str) -> str:
    if char in INVISIBLE_CHARACTERS or unicodedata.category(char) in REJECTED_CATEGORIES:
        return f"[U+{ord(char):04X}]"
    return char


def reveal_hidden(text: str) -> str:
    """Return ``text`` with every character the rules refuse shown as ``[U+XXXX]``.

    ``\\n`` and ``\\t`` stay as they are. Every other refused character, ``\\r`` and C1 controls
    included, becomes visible to a model or a terminal instead of acting on it.
    """
    return _MAYBE_HIDDEN.sub(lambda match: _revealed(match.group()), text)
