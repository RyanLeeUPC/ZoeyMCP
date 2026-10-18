"""Review findings for one tool's definition (M3 design I).

Errors come from the rules that decide: the text rules (J.3) and schema acceptance (H.1). A tool
with an error is never exposed, and review prints no pin line for it. Warnings and notes are
heuristics for the person reading the definition; nothing here decides anything, and reading the
definition is the control. Every string in the projection is read, parameter names, enum values,
defaults, ``const`` and examples included.

Quoted text is cut short and passed through :func:`~zoeymcp.common.textrules.reveal_hidden`, so a
finding can't hide or fake anything on the reviewer's terminal.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

from ..common import textrules
from ..common.policy.schema import GatewayLimits
from . import pins, schemas

Level = Literal["error", "warning", "note"]
LEVEL_ORDER: Mapping[Level, int] = {"error": 0, "warning": 1, "note": 2}

MAX_DESCRIPTION_CHARS = 1000  # R38: longer descriptions are a warning
MAX_QUOTED_CHARS = 60

INSTRUCTION_LIKE = re.compile(
    r"ignore\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier)"
    r"|system\s+prompt"
    r"|(?:do\s+not|don(?:'|\u2019)t)\s+(?:tell|inform|mention|reveal|show|alert)"
    r"|before\s+using\s+this\s+tool"
    r"|<\s*/?\s*(?:important|system|instructions?|admin|secret|hidden)\b[^<>\n]{0,100}>"
    r"|~/\.ssh|\bid_rsa\b|(?<![\w.])\.env\b"
    r"|\bsend\b[^\n]{0,60}?\bto\b",
    re.IGNORECASE,
)
URL = re.compile(r"\b(?:https?|ftp|wss?|file)://|\b(?:data|javascript):|\bwww\.", re.IGNORECASE)
BASE64_RUN = re.compile(r"[A-Za-z0-9+/_-]{64,}={0,2}")


@dataclass(frozen=True)
class ReviewFinding:
    level: Level
    pointer: str  # into the projection
    message: str

    def sort_key(self) -> tuple[int, str, str]:
        return LEVEL_ORDER[self.level], self.pointer, self.message

    def as_dict(self) -> dict[str, str]:
        return {
            "level": self.level,
            "pointer": textrules.reveal_hidden(self.pointer),
            "message": self.message,
        }


def quoted(text: str) -> str:
    """``text`` as a finding quotes it: cut short, and with nothing hidden."""
    cut = text if len(text) <= MAX_QUOTED_CHARS else text[:MAX_QUOTED_CHARS] + "..."
    return '"' + textrules.reveal_hidden(cut) + '"'


def has_nested_quantifier(pattern: str) -> bool:
    """Whether ``pattern`` quantifies a group that has a quantifier inside, as in ``(a+)+``.

    That is the classic catastrophic-backtracking shape. A heuristic: escapes and character
    classes are skipped, and nothing else about the pattern is understood.
    """
    groups: list[bool] = []  # per open group: whether a quantifier is inside it
    escaped = in_class = after_quantified_group = False
    for char in pattern:
        closed_quantified = False
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif in_class:
            in_class = char != "]"
        elif char == "[":
            in_class = True
        elif char == "(":
            groups.append(False)
        elif char == ")":
            inner = groups.pop() if groups else False
            if inner and groups:
                groups[-1] = True
            closed_quantified = inner
        elif char in "*+{":
            if after_quantified_group:
                return True
            if groups:
                groups[-1] = True
        after_quantified_group = closed_quantified
    return False


def _suggested(annotations: Mapping[str, Any]) -> str | None:
    hints = [member for member, _ in pins.HINTS if member in annotations]
    if not hints:
        return None
    read_only = annotations.get("readOnlyHint") is True
    destructive = annotations.get("destructiveHint") is True
    classification = "allow" if read_only and not destructive else "approve"
    shown = ", ".join(f"{member}={str(annotations[member]).lower()}" for member in hints)
    return f"suggested by the server: {classification} ({shown})"


def _text_warnings(pointer: str, text: str) -> list[ReviewFinding]:
    found: list[ReviewFinding] = []
    instruction = INSTRUCTION_LIKE.search(text)
    if instruction is not None:
        found.append(
            ReviewFinding(
                "warning", pointer, f"instruction-like text {quoted(instruction.group())}"
            )
        )
    url = URL.search(text)
    if url is not None:
        found.append(ReviewFinding("warning", pointer, f"a URL {quoted(text[url.start() :])}"))
    run = BASE64_RUN.search(text)
    if run is not None:
        found.append(
            ReviewFinding("warning", pointer, f"a long base64-looking run {quoted(run.group())}")
        )
    return found


def tool_findings(definition: Mapping[str, Any], limits: GatewayLimits) -> list[ReviewFinding]:
    """Every finding for one projected tool, errors first."""
    found = [
        ReviewFinding("error", problem.pointer, str(problem.violation))
        for problem in pins.text_problems(definition)
    ]
    for role, member in schemas.MEMBERS:
        if member not in definition:
            continue
        schema = definition[member]
        problems = schemas.schema_problems(schema, role=role, limits=limits)
        found.extend(
            ReviewFinding("error", f"/{member}{problem.pointer}", problem.message)
            for problem in problems
        )
        for pointer, pattern in schemas.patterns(schema):
            if has_nested_quantifier(pattern):
                found.append(
                    ReviewFinding(
                        "warning",
                        f"/{member}{pointer}",
                        "a pattern with a nested quantifier, which can backtrack catastrophically",
                    )
                )
            found.append(
                ReviewFinding(
                    "note",
                    f"/{member}{pointer}",
                    r"a pattern: arguments are checked with the regex module (ASCII \d and "
                    r"\w), which differs from ECMA-262 in places",
                )
            )
        if role == "input":
            refused = {problem.pointer for problem in problems}
            found.extend(
                ReviewFinding(
                    "warning",
                    f"/{member}{pointer}/{schemas.HEADER_KEY}",
                    "this argument's value travels in an HTTP header",
                )
                for pointer, _ in schemas.mcp_headers(schema)
                if f"{pointer}/{schemas.HEADER_KEY}" not in refused
            )
    for path, text, _ in pins.walk_strings(dict(definition)):
        found.extend(_text_warnings(schemas.json_pointer(path), text))
    description = definition.get("description")
    if isinstance(description, str) and len(description) > MAX_DESCRIPTION_CHARS:
        found.append(
            ReviewFinding(
                "warning",
                "/description",
                f"the description is {len(description)} characters, over {MAX_DESCRIPTION_CHARS}",
            )
        )
    annotations = definition.get("annotations")
    if isinstance(annotations, Mapping):
        suggestion = _suggested(annotations)
        if suggestion is not None:
            found.append(ReviewFinding("note", "/annotations", suggestion))
    return sorted(found, key=ReviewFinding.sort_key)
