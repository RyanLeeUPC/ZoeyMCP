"""The pin projection of an upstream tool, its pin, and the evaluation of a listing (M3 design G).

A tool's projection is the part of its definition the gateway serves to agents. It is built from
the SDK's parsed ``Tool`` by explicit field reads, never ``model_dump``, so a member the SDK adds
later can't slip through: ``icons``, ``_meta``, ``execution`` and every unknown member are
stripped. Every member that is served is pinned, and every member that isn't pinned is stripped.

The pin is the canonical digest of the projection under a domain tag, so a later projection can
never produce a v1 pin; :func:`pin_of`, ``PIN_TAG`` and :class:`ProjectionError` live in
:mod:`zoeymcp.common.pinhash`, since the vault recomputes reported pins too, and are re-exported
here. What is served is the projection itself: it hashed to the pin, so it is the reviewed
definition.

:func:`evaluate` decides from one connection's listing which tools are exposed. It is pure: drift
marks come in and go out as values, and the reports are returned for the caller to log.

M6 (design L.2, L.4) adds the kinds beyond tools a remote server may enable: prompts, resource
templates and fixed resources. Each has its projection (:func:`project_prompt`,
:func:`project_template`, :func:`project_resource`), read the same way from the SDK's parsed model
(a priority as the float the SDK parses, so a whole one pins as 1.0), its own pin tag, and the same
states from :func:`evaluate` given its kind. :func:`evaluate_server` evaluates every kind of one
listing, and ``on_drift: fail`` blocks every kind when any kind triggers it (Q20 (a)).
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Callable, Iterator, Mapping, Sequence, Set
from copy import deepcopy
from dataclasses import dataclass, field, replace
from typing import Any, Final, Literal, Protocol

from mcp.types import Annotations, Prompt, Resource, ResourceTemplate, Tool

from ..common import textrules
from ..common.pinhash import KINDS as KINDS
from ..common.pinhash import PIN_TAG as PIN_TAG
from ..common.pinhash import DefinitionKind as DefinitionKind
from ..common.pinhash import ProjectionError as ProjectionError
from ..common.pinhash import pin_for as pin_for
from ..common.pinhash import pin_of as pin_of
from ..common.policy import fields
from ..common.policy.schema import Capability, GatewayLimits, Tools
from ..common.policy.view import ViewRemoteServer
from . import schemas

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
# Each kind's key on the SDK's parsed model (pinhash.KEY_MEMBERS names it on the wire).
KEY_ATTRIBUTES: Final[Mapping[DefinitionKind, str]] = {
    "tool": "name",
    "prompt": "name",
    "resource_template": "uri_template",
    "resource": "uri",
}
# The kinds beyond tools each ``enable`` entry lists (L.4), in the order they are listed.
ENABLED_KINDS: Final[Mapping[Capability, tuple[DefinitionKind, ...]]] = {
    "prompts": ("prompt",),
    "resources": ("resource_template", "resource"),
}


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


def project_and_pin(tool: Tool) -> Projected:
    projection = project(tool)
    return Projected(definition=projection, pin=pin_of(projection))


# --- prompts and resources (M6 design L.2) -------------------------------------------------------


def _texts(projection: dict[str, Any], members: Sequence[tuple[str, object]]) -> None:
    """The optional text members, each in ``projection`` unless it is null."""
    for member, value in members:
        text = _optional_text(member, value)
        if text is not None:
            projection[member] = text


def project_prompt(prompt: Prompt) -> dict[str, Any]:
    """A prompt's projection (``prompt-pin/1``): its name, title and description, and each
    argument's name, title, description and ``required``, in the order listed. ``icons`` and
    ``_meta`` are stripped."""
    name = prompt.name
    if not isinstance(name, str) or TOOL_NAME.fullmatch(name) is None:
        raise ProjectionError("name is not a valid prompt name")
    projection: dict[str, Any] = {"name": name}
    _texts(projection, (("title", prompt.title), ("description", prompt.description)))
    if prompt.arguments is not None:
        arguments = []
        for index, argument in enumerate(prompt.arguments):
            if not isinstance(argument.name, str):
                raise ProjectionError(f"arguments[{index}].name is not a string")
            projected: dict[str, Any] = {"name": argument.name}
            _texts(projected, (("title", argument.title), ("description", argument.description)))
            if argument.required is not None:
                if not isinstance(argument.required, bool):
                    raise ProjectionError(f"arguments[{index}].required is not a boolean")
                projected["required"] = argument.required
            arguments.append(projected)
        projection["arguments"] = arguments
    return projection


def _resource_annotations(annotations: Annotations | None) -> dict[str, Any]:
    """``audience`` and ``priority``; ``lastModified`` is never pinned. The priority is the
    float the SDK parsed, never the wire's number: canonical JSON writes 1 and 1.0 apart, so a
    whole priority pins as 1.0 (step 18's review S18-1)."""
    if annotations is None:
        return {}
    out: dict[str, Any] = {}
    if annotations.audience is not None:
        out["audience"] = list(annotations.audience)
    priority = annotations.priority
    if priority is not None:
        if isinstance(priority, bool) or not isinstance(priority, int | float):
            raise ProjectionError("annotations.priority is not a number")
        out["priority"] = float(priority)
    return out


def _with_metadata(projection: dict[str, Any], item: Resource | ResourceTemplate) -> dict[str, Any]:
    """A template's or a fixed resource's ``name``, ``title``, ``description``, ``mimeType``
    and pinned annotations, after its URI or template."""
    if not isinstance(item.name, str):
        raise ProjectionError("name is not a string")
    projection["name"] = item.name
    _texts(
        projection,
        (("title", item.title), ("description", item.description), ("mimeType", item.mime_type)),
    )
    annotations = _resource_annotations(item.annotations)
    if annotations:
        projection["annotations"] = annotations
    return projection


def project_template(template: ResourceTemplate) -> dict[str, Any]:
    """A resource template's projection (``resource-template-pin/1``): ``uriTemplate``, in L.1's
    level-1 form, and its metadata. ``icons``, ``_meta`` and ``lastModified`` are stripped."""
    uri_template = template.uri_template
    if not isinstance(uri_template, str):
        raise ProjectionError("uriTemplate is not a string")
    try:
        fields.uri_template(uri_template)
    except ValueError as exc:
        raise ProjectionError(f"uriTemplate: {exc}") from None
    return _with_metadata({"uriTemplate": uri_template}, template)


def project_resource(resource: Resource) -> dict[str, Any]:
    """A fixed resource's projection (``resource-pin/1``): ``uri`` and its metadata. ``size``,
    ``lastModified``, ``icons`` and ``_meta`` are stripped."""
    uri = resource.uri
    if not isinstance(uri, str):
        raise ProjectionError("uri is not a string")
    try:
        fields.resource_uri(uri)
    except ValueError as exc:
        raise ProjectionError(f"uri: {exc}") from None
    return _with_metadata({"uri": uri}, resource)


PROJECTIONS: Final[Mapping[DefinitionKind, Callable[[Any], dict[str, Any]]]] = {
    "tool": project,
    "prompt": project_prompt,
    "resource_template": project_template,
    "resource": project_resource,
}


def project_kind(kind: DefinitionKind, item: Any) -> Projected:
    """The projection and pin of a listed definition of ``kind``, from its SDK model."""
    projection = PROJECTIONS[kind](item)
    return Projected(definition=projection, pin=pin_for(kind, projection))


def key_of(kind: DefinitionKind, item: Any) -> str:
    """The name, URI template or URI a definition is listed under; empty if it isn't a
    string."""
    key = getattr(item, KEY_ATTRIBUTES[kind], None)
    return key if isinstance(key, str) else ""


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
        if path in (("title",), ("annotations", "title"), ("mimeType",)):
            return MAX_TITLE_CHARS, True
        if path == ("description",):
            return MAX_DESCRIPTION_CHARS, False
        # A prompt's argument (L.2): its name and title as a tool's are.
        if len(path) == 3 and path[0] == "arguments":
            if path[2] == "name":
                return MAX_NAME_CHARS, True
            if path[2] == "title":
                return MAX_TITLE_CHARS, True
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

# declined: listed, not included, and declined at the pin it has now (M6 design J.5).
ReportKind = Literal["drift", "unreviewed", "declined", "missing", "invalid", "duplicate"]
# (tool, the policy pin it drifted from). A mark hides the tool until that pin changes. A mark on
# another kind is the same pair for that kind's name, URI template or URI (L.4).
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
    # Every name listed, with its pin; None for a tool reported invalid or duplicate, which
    # can't be pinned (what the attention decision reads, M6 design J.5).
    listed: Mapping[str, str | None] = field(default_factory=dict)
    # A tool evaluation's: the same listing's other kinds, each evaluated as its kind
    # (:func:`evaluate_server`); empty for a server that enables none (M6 design L.4).
    kinds: Mapping[DefinitionKind, Evaluation] = field(default_factory=dict)


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


def definition_problems(
    kind: DefinitionKind, definition: Mapping[str, Any], limits: GatewayLimits
) -> list[str]:
    """Why a projected definition of ``kind`` is invalid: a tool's :func:`tool_problems`, and the
    text rules for the kinds beyond tools, which hold no schema."""
    if kind == "tool":
        return tool_problems(definition, limits)
    return [str(problem) for problem in text_problems(definition)]


class Reviewed(Protocol):
    """What :func:`evaluate` reads of a server: a remote one, or a toolkit (M4 design H.2). The
    kinds beyond tools are a remote server's only."""

    @property
    def tools(self) -> Tools: ...

    @property
    def review(self) -> Mapping[str, str]: ...

    @property
    def declined(self) -> Mapping[str, str]: ...

    @property
    def on_drift(self) -> Literal["hide", "fail"]: ...


@dataclass(frozen=True)
class Entries:
    """One kind's part of a server's policy: what is included, the pins, the declines."""

    include: Sequence[str]
    review: Mapping[str, str]
    declined: Mapping[str, str]


def entries(server: Reviewed, kind: DefinitionKind = "tool") -> Entries:
    """The ``include``, ``review`` and ``declined`` of ``kind`` in ``server``: a tool's are the
    server's own, a prompt's its ``prompts`` block, a template's and a fixed resource's its
    ``resources`` block's ``templates`` and ``fixed`` (L.1)."""
    if kind == "tool":
        return Entries(server.tools.include, server.review, server.declined)
    if not isinstance(server, ViewRemoteServer):
        raise ValueError(f"only a remote server lists a {kind}")
    if kind == "prompt":
        block: Any = server.prompts
    elif kind == "resource_template":
        block = server.resources.templates
    else:
        block = server.resources.fixed
    return Entries(block.include, block.review, block.declined)


def enabled_kinds(enable: Sequence[Capability]) -> tuple[DefinitionKind, ...]:
    """The kinds beyond tools a server's ``enable`` lists (L.4), in :data:`KINDS` order."""
    wanted = {kind for entry in enable for kind in ENABLED_KINDS.get(entry, ())}
    return tuple(kind for kind in KINDS if kind in wanted)


def evaluate(
    listing: Sequence[Any],
    server: Reviewed,
    marks: Set[Mark],
    limits: GatewayLimits,
    kind: DefinitionKind = "tool",
) -> Evaluation:
    """Decide which of a listing's tools are exposed (G.2), or with ``kind`` the definitions of
    that kind (``listing`` its SDK models, M6 design L.4), with the same states.

    ``marks`` are the server's drift marks so far, of that kind. A mark whose pin is no longer the
    policy's pin for that tool has cleared, and isn't returned. A tool that isn't included is
    ``declined`` when the policy declined it at the pin it has now, else ``unreviewed`` (J.5).
    """
    policy = entries(server, kind)
    included = set(policy.include)
    review, declined = policy.review, policy.declined
    held = {(tool, pinned) for tool, pinned in marks if review.get(tool) == pinned}
    counts = Counter(key_of(kind, tool) for tool in listing)
    exposed: dict[str, ExposedTool] = {}
    reports: list[Report] = []
    listed: dict[str, str | None] = {}
    for tool in listing:
        name = key_of(kind, tool)
        listed[name] = None
        if counts[name] > 1:
            if not any(report.kind == "duplicate" and report.tool == name for report in reports):
                reports.append(Report("duplicate", name))
            continue
        try:
            projected = project_kind(kind, tool)
        except ProjectionError as exc:
            reports.append(Report("invalid", name, reasons=(str(exc),)))
            continue
        problems = definition_problems(kind, projected.definition, limits)
        if problems:
            reports.append(Report("invalid", name, pin=projected.pin, reasons=tuple(problems)))
            continue
        listed[name] = projected.pin
        pinned = review.get(name)
        if name not in included and declined.get(name) == projected.pin:
            reports.append(Report("declined", name, pin=projected.pin))
            continue
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
        listed=listed,
    )


@dataclass(frozen=True)
class KindListing:
    """One kind's listing beyond tools (L.4): its SDK models, or why its walk failed, which fails
    that kind alone (SPEC-7): nothing of it is listed, so every included entry is missing."""

    items: Sequence[Any] = ()
    failure: str | None = None
    # resources/list stopped at a cap: what was listed by then is reviewed (OPS-11) or served.
    cut: bool = False


def evaluate_server(
    tools: Sequence[Tool],
    listings: Mapping[DefinitionKind, KindListing],
    server: ViewRemoteServer,
    marks: Mapping[DefinitionKind, Set[Mark]],
    limits: GatewayLimits,
) -> Evaluation:
    """Every kind of one remote server's listing: the tool evaluation, carrying each other kind's
    in ``kinds``. ``on_drift: fail`` blocks the whole server, every kind, when any kind triggers
    it (Q20 (a)): a server that changes a prompt is no more trustworthy for its tools."""
    first = evaluate(tools, server, marks.get("tool", frozenset()), limits)
    others = {
        kind: evaluate(listing.items, server, marks.get(kind, frozenset()), limits, kind)
        for kind, listing in listings.items()
    }
    if not any(evaluation.blocked for evaluation in (first, *others.values())):
        return replace(first, kinds=others)
    return replace(
        first,
        exposed={},
        blocked=True,
        kinds={
            kind: replace(evaluation, exposed={}, blocked=True)
            for kind, evaluation in others.items()
        },
    )
