"""The pin projection of an upstream tool, its pin, and the evaluation of a listing (M3 design G).

A tool's projection is the part of its definition the gateway serves to agents. It is built from
the SDK's parsed ``Tool`` by explicit field reads, never ``model_dump``, so a member the SDK adds
later can't slip through: ``icons``, ``_meta``, ``execution`` and every unknown member are
stripped. Every member that is served is pinned, and every member that isn't pinned is stripped.

The pin is the canonical digest of the projection under a domain tag, so a later projection can
never produce a v1 pin. What is served is the projection itself: it hashed to the pin, so it is
the reviewed definition.

:func:`evaluate` decides from one connection's listing which tools are exposed. It is pure: drift
marks come in and go out as values, and the reports are returned for the caller to log.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterator, Mapping, Sequence, Set
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Literal

from mcp.types import Tool

from ..common import canonical, textrules
from ..common.policy.schema import GatewayLimits
from ..common.policy.view import ViewRemoteServer
from . import schemas

PIN_TAG = "tool-pin/1"
TOOL_NAME = re.compile(r"[A-Za-z0-9_.-]{1,128}")
# The annotation hints that are pinned and served: wire name, SDK attribute.
HINTS = (
    ("readOnlyHint", "read_only_hint"),
    ("destructiveHint", "destructive_hint"),
    ("idempotentHint", "idempotent_hint"),
    ("openWorldHint", "open_world_hint"),
)
# Text-rule limits (J.3), in code points.
MAX_NAME_CHARS = 128
MAX_TITLE_CHARS = 256
MAX_DESCRIPTION_CHARS = 16_384
MAX_SCHEMA_TEXT_CHARS = 4096

Path = tuple[str | int, ...]


class ProjectionError(ValueError):
    """A tool the gateway can't project or pin. The message names the member, never its value."""


@dataclass(frozen=True)
class Projected:
    definition: Mapping[str, Any]
    pin: str


def _optional_text(member: str, value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ProjectionError(f"{member} is not a string")
    return value


def _annotations(tool: Tool) -> dict[str, Any]:
    annotations = tool.annotations
    if annotations is None:
        return {}
    out: dict[str, Any] = {}
    title = _optional_text("annotations.title", annotations.title)
    if title is not None:
        out["title"] = title
    for member, attribute in HINTS:
        value = getattr(annotations, attribute)
        if value is None:
            continue
        if not isinstance(value, bool):
            raise ProjectionError(f"annotations.{member} is not a boolean")
        out[member] = value
    return out


def project(tool: Tool) -> dict[str, Any]:
    """The pin projection (v1) of ``tool``. Null top-level members count as absent."""
    name = tool.name
    if not isinstance(name, str) or TOOL_NAME.fullmatch(name) is None:
        raise ProjectionError("name is not a valid tool name")
    projection: dict[str, Any] = {"name": name}
    for member, value in (("title", tool.title), ("description", tool.description)):
        text = _optional_text(member, value)
        if text is not None:
            projection[member] = text
    input_schema = tool.input_schema
    if not isinstance(input_schema, dict) or input_schema.get("type") != "object":
        raise ProjectionError('inputSchema is not an object schema with "type": "object"')
    projection["inputSchema"] = deepcopy(input_schema)
    output_schema = tool.output_schema
    if output_schema is not None:
        if not isinstance(output_schema, dict):
            raise ProjectionError("outputSchema is not an object")
        projection["outputSchema"] = deepcopy(output_schema)
    annotations = _annotations(tool)
    if annotations:
        projection["annotations"] = annotations
    return projection


def pin_of(projection: Mapping[str, Any]) -> str:
    """The pin of a projection: ``sha256:`` and the hex digest of it under the domain tag."""
    try:
        return canonical.digest({"zoeymcp": PIN_TAG, "tool": projection})
    except canonical.JSONRejected as exc:
        raise ProjectionError(
            "the definition has no canonical form (an unsafe integer, a lone surrogate or too deep)"
        ) from exc


def project_and_pin(tool: Tool) -> Projected:
    projection = project(tool)
    return Projected(definition=projection, pin=pin_of(projection))


# --- text rules for definitions (J.3) ------------------------------------------------------------


def walk_strings(value: Any, path: Path = ()) -> Iterator[tuple[Path, str, bool]]:
    """Every string in ``value`` as ``(path, text, is_key)``; a key comes at its member's path."""
    stack: list[tuple[Path, Any]] = [(path, value)]
    while stack:
        here, item = stack.pop()
        if isinstance(item, str):
            yield here, item, False
        elif isinstance(item, list):
            stack.extend(((*here, index), child) for index, child in enumerate(item))
        elif isinstance(item, dict):
            for key, child in item.items():
                yield (*here, key), key, True
                stack.append(((*here, key), child))


def _text_limits(path: Path, is_key: bool) -> tuple[int, bool]:
    """The length limit for the string at ``path``, and whether it must be a single line."""
    if not is_key:
        if path == ("name",):
            return MAX_NAME_CHARS, True
        if path in (("title",), ("annotations", "title")):
            return MAX_TITLE_CHARS, True
        if path == ("description",):
            return MAX_DESCRIPTION_CHARS, False
    return MAX_SCHEMA_TEXT_CHARS, False


@dataclass(frozen=True)
class TextProblem:
    """A text-rule violation at a JSON pointer into the projection."""

    pointer: str
    violation: textrules.TextViolation

    def __str__(self) -> str:
        return f"{textrules.reveal_hidden(self.pointer)}: {self.violation}"


def text_problems(definition: Mapping[str, Any]) -> list[TextProblem]:
    """J.3: every string and schema key in the projection, checked against the text rules."""
    problems: list[TextProblem] = []
    for path, text, is_key in walk_strings(dict(definition)):
        max_chars, single_line = _text_limits(path, is_key)
        problems.extend(
            TextProblem(schemas.json_pointer(path), violation)
            for violation in textrules.find_violations(
                text, max_chars=max_chars, single_line=single_line, allow_tabs=True
            )
        )
    return sorted(problems, key=lambda problem: (problem.pointer, problem.violation.index))


# --- evaluating a listing (G.2) ------------------------------------------------------------------

ReportKind = Literal["drift", "unreviewed", "missing", "invalid", "duplicate"]
# (tool, the policy pin it drifted from). A mark hides the tool until that pin changes.
Mark = tuple[str, str]


@dataclass(frozen=True)
class Report:
    kind: ReportKind
    tool: str
    pin: str | None = None  # what the upstream listed
    pinned: str | None = None  # what the policy has
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class ExposedTool:
    definition: Mapping[str, Any]
    pin: str


@dataclass(frozen=True)
class Evaluation:
    exposed: Mapping[str, ExposedTool]
    reports: tuple[Report, ...]
    marks: frozenset[Mark]  # every mark that holds for the server after this listing
    blocked: bool  # on_drift: fail was triggered, so nothing is exposed


def tool_problems(definition: Mapping[str, Any], limits: GatewayLimits) -> list[str]:
    """Why a projected tool is invalid (J.3 text rules, H.1 schemas); empty if it's acceptable."""
    reasons = [str(problem) for problem in text_problems(definition)]
    for role, member in schemas.MEMBERS:
        if member in definition:
            reasons.extend(
                f"/{member}{problem}"
                for problem in schemas.schema_problems(definition[member], role=role, limits=limits)
            )
    return reasons


def _name(tool: Tool) -> str:
    return tool.name if isinstance(tool.name, str) else ""


def evaluate(
    listing: Sequence[Tool],
    server: ViewRemoteServer,
    marks: Set[Mark],
    limits: GatewayLimits,
) -> Evaluation:
    """Decide which of a listing's tools are exposed (G.2).

    ``marks`` are the server's drift marks so far. A mark whose pin is no longer the policy's pin
    for that tool has cleared, and isn't returned.
    """
    included = set(server.tools.include)
    review = server.review
    held = {(tool, pinned) for tool, pinned in marks if review.get(tool) == pinned}
    counts = Counter(_name(tool) for tool in listing)
    exposed: dict[str, ExposedTool] = {}
    reports: list[Report] = []
    for tool in listing:
        name = _name(tool)
        if counts[name] > 1:
            if not any(report.kind == "duplicate" and report.tool == name for report in reports):
                reports.append(Report("duplicate", name))
            continue
        try:
            projected = project_and_pin(tool)
        except ProjectionError as exc:
            reports.append(Report("invalid", name, reasons=(str(exc),)))
            continue
        problems = tool_problems(projected.definition, limits)
        if problems:
            reports.append(Report("invalid", name, pin=projected.pin, reasons=tuple(problems)))
            continue
        pinned = review.get(name)
        if name not in included or pinned is None:
            reports.append(Report("unreviewed", name, pin=projected.pin))
            continue
        if projected.pin != pinned:
            reports.append(Report("drift", name, pin=projected.pin, pinned=pinned))
            held.add((name, pinned))
            continue
        if (name, pinned) not in held:
            exposed[name] = ExposedTool(projected.definition, projected.pin)
    reports.extend(
        Report("missing", name, pinned=review.get(name)) for name in sorted(included - set(counts))
    )
    # Drift always leaves a held mark, so held covers it.
    blocked = server.on_drift == "fail" and (
        bool(held)
        or any(
            report.kind in ("invalid", "duplicate") and report.tool in included
            for report in reports
        )
    )
    return Evaluation(
        exposed={} if blocked else exposed,
        reports=tuple(reports),
        marks=frozenset(held),
        blocked=blocked,
    )
