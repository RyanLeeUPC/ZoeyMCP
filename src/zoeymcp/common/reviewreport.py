"""A review report, as the vault accepts it from the gateway (M7 design F.4; D-29, COV-1). Pure.

A review job's result is the gateway's own review answer: ``review.report()``'s for a remote
server (a bridge reports as the remote server it is) or ``toolkit_report()``'s for a toolkit,
told apart by ``kind``. :data:`ReviewReport` is a strict model of both, keyed by definition kind
on each entry (``"kind": "tool"``, the only kind in M7; ``review.report()`` doesn't write it, so
an entry without one is a tool), so M6's drift review of any server kind reads the same shape.

M6 (design J.1) adds what a drift review needs: a drift entry's ``reviewed`` definition, the one
the policy's pin names, from the gateway's definition store; the policy block's ``review`` and
``declined`` maps, the server's pins and declines the review ran under; a remote report's
``offered``, what the upstream advertises beyond tools (fold-in 3.8); and both kinds'
``attention``, the attention decision for the listing (J.5), with the ``declined`` state for a
tool the policy declined at the pin it has. A clear job's report (J.4) says what it did: the tools
whose drift marks it ``cleared``, or the included tools that didn't match their pins
(``not_clean``, the gateway's refusal to clear). Each has a default, so a report from an M7
gateway, which writes none of them, still reads (CR-6).

A remote server that enables prompts or resources (M6 design L.4, L.7) is reported with entries of
those kinds beside its tools: ``kind`` is ``prompt``, ``resource_template`` or ``resource``, the
name is the prompt's name, the template or the URI, and each is pinned under its kind's tag. The
policy block then carries the server's ``prompts`` and ``resources`` blocks, and ``listings`` says
how each kind's walk went: why it failed, or the finding that a review's ``resources/list`` was
cut at a cap. Each kind is counted against the caps on its own.

:func:`read` takes one report under the running limits: the model, the caps that follow
``gateway.limits`` (GR-30), then the integrity check (fold-in C25, X11), which recomputes every
reported pin from the definition beside it, and the policy's pin from the reviewed definition,
which its entry's ``pinned`` must be too (Y10), and refuses the whole report if any differs: a
gateway can leave the old definition out, never fake it. A refusal is :class:`ReportRefused`,
whose ``reason`` is M.2's. Nothing in a report is trusted further than that: its findings and
states are shown labelled as the gateway's.

A genuine review can exceed those caps for one odd tool (a definition far over the schema limit, a
pattern on each of hundreds of properties, a name that isn't a tool name), and one tool mustn't
make a whole server unreviewable through the vault. So the gateway passes its answer through
:func:`fit` before posting it: what is over a cap is cut, or dropped and replaced by a finding
that says so, and ``read(fit(answer), limits)`` takes any answer the review code writes.

This module is pure: the vault reads reports with it, and the gateway's side is the review code
the model describes.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from typing import Annotated, Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError, model_validator

from . import canonical
from .pinhash import KEY_MEMBERS, KINDS, DefinitionKind, ProjectionError, pin_for
from .policy import fields
from .policy.findings import format_location
from .policy.schema import (
    GatewayLimits,
    ModulePath,
    Name,
    Pin,
    PromptsPolicy,
    ResourcesPolicy,
    SlotName,
    ToolName,
)
from .policy.view import VaultPath

Reason = Literal["review_invalid", "pin_mismatch", "review_too_large"]

# The body cap (M.6's REVIEW_REPORT_MAX): max_tools_per_server x 16 KiB, within 8 and 64 MiB.
REPORT_BYTES_PER_TOOL: Final = 16 * 1024
REPORT_BYTES_MIN: Final = 8 * 2**20
REPORT_BYTES_MAX: Final = 64 * 2**20
# max_tools_per_server's own ceiling (schema.py), which bounds every list of names a report holds.
NAMES_MAX: Final = 10_000
FINDINGS_MAX: Final = 64
POINTER_MAX: Final = 256
MESSAGE_MAX: Final = 1000
CHANGED_MAX: Final = 16
MEMBER_MAX: Final = 128
TEXT_MAX: Final = 16_384  # each of server_info's strings, and instructions
# review.report() cuts longer instructions to TEXT_MAX and marks the cut with "...".
INSTRUCTIONS_MAX: Final = TEXT_MAX + len("...")
DISTRIBUTION_MAX: Final = 256
# A listed tool's name, which is a ToolName unless the tool is reported invalid or duplicate.
LISTED_NAME_MAX: Final = 4096
CUT: Final = "..."
# A definition is at most max_schema_bytes x 4 in canonical form, with room in any case for the
# text a valid one may hold beside its two schemas: a 16,384-character description, a name and
# two titles (pins.py's limits), at 4 UTF-8 bytes a character.
DEFINITION_SCALE: Final = 4
DEFINITION_TEXT_BYTES: Final = 4 * (16_384 + 128 + 2 * 256) + 1024
# A drift diff holds both definitions, indented: its lines are bounded by this many times the
# definition cap, in characters.
DIFF_SCALE: Final = 16
# The protocol versions the gateway speaks (gateway/access.py, which common can't import).
PROTOCOL_VERSIONS: Final = ("2026-07-28", "2025-11-25", "2025-06-18")
# A tool name (schema.py's ToolName), and the only location key a refusal shows as it is.
_PLAIN_NAME = re.compile(r"[A-Za-z0-9_.-]{1,128}")
# The kinds beyond tools a remote report may list (L.4), and how the caps' refusals name each.
ListedKind = Literal["prompt", "resource_template", "resource"]
_NOUNS: Final[Mapping[DefinitionKind, str]] = {
    "tool": "",
    "prompt": " prompts",
    "resource_template": " resource templates",
    "resource": " resources",
}
_UNPINNABLE: Final = ("invalid", "duplicate")
_LEVELS: Final = ("error", "warning", "note")
_LOCATIONS_SHOWN = 5

State = Literal[
    "ok", "marked", "blocked", "drift", "unreviewed", "declined", "invalid", "duplicate", "missing"
]
ProtocolVersion = Literal["2026-07-28", "2025-11-25", "2025-06-18"]
Names = Annotated[list[ToolName], Field(max_length=NAMES_MAX)]
Text = Annotated[str, Field(max_length=TEXT_MAX)]
# A drift entry's changed top-level members (defstore.changed_members).
Members = Annotated[
    list[Annotated[str, Field(max_length=MEMBER_MAX)]], Field(max_length=CHANGED_MAX)
]


class ReportRefused(ValueError):
    """A report the vault doesn't take: ``review_too_large`` (over the body cap),
    ``review_invalid`` (not the gateway's review shape, or over a cap) or ``pin_mismatch`` (a
    reported pin that isn't its definition's, or a reviewed definition that isn't the one the
    policy's pin names; ``tools`` names each). ``detail`` names locations and limits, never a value
    from the report."""

    def __init__(self, reason: Reason, detail: str, tools: tuple[str, ...] = ()) -> None:
        self.reason: Reason = reason
        self.detail = detail
        self.tools = tools
        super().__init__(f"{reason}: {detail}")


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class Finding(_Model):
    level: Literal["error", "warning", "note"]
    pointer: Annotated[str, Field(max_length=POINTER_MAX)]
    message: Annotated[str, Field(max_length=MESSAGE_MAX)]


def _is_key(kind: DefinitionKind, name: str) -> bool:
    """Whether ``name`` is a key an entry of ``kind`` can be pinned under: a tool's or a prompt's
    name, a template or a fixed URI in the form the policy holds (L.1)."""
    if kind in ("tool", "prompt"):
        return _PLAIN_NAME.fullmatch(name) is not None
    rule = fields.uri_template if kind == "resource_template" else fields.resource_uri
    try:
        rule(name)
    except ValueError:
        return False
    return True


class ToolEntry(_Model):
    """One listed or included tool, as review.py's ``_tool_entry`` writes it, or a prompt or a
    resource (``kind``, M6 design L.4), which is never classified."""

    kind: DefinitionKind = "tool"
    name: Annotated[str, Field(max_length=LISTED_NAME_MAX)]
    state: State
    included: bool
    classification: Literal["allow", "approve"] | None  # null: not classified (F-56, CR-9)
    pin: Pin | None
    pinned: Pin | None
    definition: dict[str, Any] | None
    findings: Annotated[list[Finding], Field(max_length=FINDINGS_MAX)]
    changed: Members | None
    diff: list[str] | None
    # A drift entry's definition at its pinned pin, from the gateway's definition store; none when
    # the store doesn't hold it (pruned at a restart, F-41), for a toolkit, or from an M7 gateway.
    reviewed: dict[str, Any] | None = None

    @model_validator(mode="after")
    def _pinned_definition(self) -> ToolEntry:
        # A pin is only ever reported beside the definition it is checked against.
        key = KEY_MEMBERS[self.kind]
        if (self.pin is None) != (self.definition is None):
            raise ValueError("a pin and its definition come together")
        if self.definition is not None and self.definition.get(key) != self.name:
            raise ValueError("the definition is another tool's")
        if self.reviewed is not None:
            if self.state != "drift" or self.pinned is None:
                raise ValueError("a reviewed definition comes with a drift entry's pinned pin")
            if self.reviewed.get(key) != self.name:
                raise ValueError("the reviewed definition is another tool's")
        if self.kind != "tool" and self.classification is not None:
            raise ValueError("only a tool is classified")
        # review.py writes an entry under every name the server lists: one that isn't a tool
        # name can only be the invalid or duplicate tool it reports, with no definition.
        unpinnable = self.definition is None and self.state in _UNPINNABLE
        if not unpinnable and not _is_key(self.kind, self.name):
            raise ValueError("not a tool name")
        return self


class ToolkitEntry(ToolEntry):
    kind: Literal["tool"] = "tool"  # a toolkit lists tools only
    consequential: bool


class ReviewedPolicy(_Model):
    """The server's entry the review ran under (review.py's ``policy`` block)."""

    include: Names
    allow: Names
    approve: Names
    on_drift: Literal["hide", "fail"]
    # The server's pins and declines at review time (M6 J.1), which stale() compares (J.2).
    # Not capped at NAMES_MAX: a pin for a tool that isn't included is only a warning, so the
    # map isn't bounded by the tools; the body cap bounds it.
    review: dict[ToolName, Pin] = {}
    declined: dict[ToolName, Pin] = {}
    # A remote server's prompts and resources blocks, when it enables the kind (L.4).
    prompts: PromptsPolicy = PromptsPolicy()
    resources: ResourcesPolicy = ResourcesPolicy()


def _policy_of(policy: ReviewedPolicy, kind: DefinitionKind) -> tuple[list[str], dict[str, str]]:
    """The ``include`` and ``review`` of ``kind`` in the policy block."""
    if kind == "tool":
        return policy.include, policy.review
    block = (
        policy.prompts
        if kind == "prompt"
        else policy.resources.templates
        if kind == "resource_template"
        else policy.resources.fixed
    )
    return block.include, block.review


class KindListing(_Model):
    """How one kind's walk went (L.4): why it failed, so every included entry is missing
    (SPEC-7), or the finding that a review's ``resources/list`` stopped at a cap (OPS-11)."""

    failure: Annotated[str, Field(max_length=MEMBER_MAX)] | None = None
    findings: Annotated[list[Finding], Field(max_length=FINDINGS_MAX)] = []


class Offered(_Model):
    """What the upstream advertises beyond tools (fold-in 3.8): none of it is served until the
    kind is enabled (L), so the portal shows it as "offered, not served"."""

    prompts: bool
    resources: bool
    completions: bool
    logging: bool


class Attention(_Model):
    """The attention decision for the listing (``common/policy/attention.py``, J.5): the tools
    that drifted, are marked, are new, were declined at another pin, and are missing."""

    drifted: Names
    marked: Names
    new: Names
    changed_declined: Names
    missing: Names


class ServerInfo(_Model):
    name: Text
    version: Text
    title: Text | None = None


class RemoteReport(_Model):
    """``review.report()``'s answer: a remote server's, a bridge's included."""

    server: Name
    kind: Literal["remote"]
    vault_path: VaultPath
    era: Literal["modern", "legacy"] | None
    asserted_era: Literal["auto", "modern", "legacy"]
    policy: ReviewedPolicy
    protocol_version: ProtocolVersion | None
    server_info: ServerInfo | None
    instructions: Annotated[str, Field(max_length=INSTRUCTIONS_MAX)] | None
    blocked: bool
    marked: Names
    # Tools first, then the other kinds' entries (each kind its listing and its missing).
    tools: Annotated[list[ToolEntry], Field(max_length=2 * NAMES_MAX * len(KINDS))]
    clean: bool
    # Each enabled kind beyond tools: how its walk went (L.4). None for a tools-only server.
    listings: dict[ListedKind, KindListing] | None = None
    offered: Offered | None = None  # none when the gateway didn't see the handshake, or is M7's
    attention: Attention | None = None  # none from an M7 gateway
    # A clear job's outcome (M6 J.4): the marks it cleared, or the tools that don't match.
    cleared: Names | None = None
    not_clean: Names | None = None


class ToolkitReport(_Model):
    """``toolkit_report()``'s answer."""

    server: Name
    kind: Literal["toolkit"]
    module: ModulePath
    distribution: Annotated[str, Field(max_length=DISTRIBUTION_MAX)] | None
    version: Annotated[str, Field(max_length=DISTRIBUTION_MAX)] | None
    pinning: Literal["required", "off"]
    slots: Annotated[list[SlotName], Field(max_length=NAMES_MAX)]
    policy: ReviewedPolicy
    blocked: bool
    marked: Names
    tools: Annotated[list[ToolkitEntry], Field(max_length=2 * NAMES_MAX)]
    clean: bool
    attention: Attention | None = None  # none from an M7 gateway
    cleared: Names | None = None  # a clear job's outcome (M6 J.4), as a remote report's
    not_clean: Names | None = None


ReviewReport = Annotated[RemoteReport | ToolkitReport, Field(discriminator="kind")]
_REPORT: Final[TypeAdapter[RemoteReport | ToolkitReport]] = TypeAdapter(ReviewReport)


def report_max(limits: GatewayLimits) -> int:
    """The most bytes a report's body may have under ``limits`` (GR-30, F-47)."""
    wanted = limits.max_tools_per_server * REPORT_BYTES_PER_TOOL
    return min(max(wanted, REPORT_BYTES_MIN), REPORT_BYTES_MAX)


def definition_max(limits: GatewayLimits) -> int:
    """The most bytes one entry's definition may have in canonical form under ``limits``."""
    schema_bytes = limits.max_schema_bytes
    return max(DEFINITION_SCALE * schema_bytes, 2 * schema_bytes + DEFINITION_TEXT_BYTES)


def check_length(length: int, limits: GatewayLimits) -> None:
    """Refuse a body of ``length`` bytes over :func:`report_max`, before any of it is read."""
    most = report_max(limits)
    if length > most:
        raise ReportRefused(
            "review_too_large", f"a report is at most {most} bytes (gateway.limits)"
        )


def _location(location: Sequence[int | str]) -> str:
    """A pydantic location, with any key that isn't a short plain name replaced by "?"."""
    return format_location(
        [part if isinstance(part, int) or _PLAIN_NAME.fullmatch(part) else "?" for part in location]
    )


def _invalid(locations: Sequence[str]) -> ReportRefused:
    unique = sorted(set(locations))
    shown = ", ".join(unique[:_LOCATIONS_SHOWN])
    more = len(unique) - _LOCATIONS_SHOWN
    return ReportRefused(
        "review_invalid", f"at {shown}" + (f" and {more} more" if more > 0 else "")
    )


def _within(report: RemoteReport | ToolkitReport, limits: GatewayLimits) -> list[str]:
    """Where ``report`` exceeds what ``limits`` allow, or repeats a tool: each kind on its own."""
    over: list[str] = []
    for kind in KINDS:
        entries = [entry for entry in report.tools if entry.kind == kind]
        missing = sum(entry.state == "missing" for entry in entries)
        noun = _NOUNS[kind]
        if len(entries) - missing > limits.max_tools_per_server:
            over.append(f"tools (more than gateway.limits.max_tools_per_server{noun} listed)")
        if missing > len(_policy_of(report.policy, kind)[0]):
            over.append(f"tools (more missing{noun} than the policy includes)")
    if len({(entry.kind, entry.name) for entry in report.tools}) != len(report.tools):
        over.append("tools (a tool twice)")
    # review.py writes ``listings`` for exactly the kinds the server enables, so a tools-only (or
    # an M7) report holds tools alone: an entry of another kind there is refused, not read.
    listed = set(report.listings or {}) if isinstance(report, RemoteReport) else set()
    most = definition_max(limits)
    for index, entry in enumerate(report.tools):
        if entry.kind != "tool" and entry.kind not in listed:
            over.append(f"tools[{index}].kind (the server isn't listed for{_NOUNS[entry.kind]})")
        # The reviewed definition is capped like the listed one.
        for member, definition in (("definition", entry.definition), ("reviewed", entry.reviewed)):
            problem = _oversize(definition, most)
            if problem is not None:
                over.append(f"tools[{index}].{member} ({problem})")
        if entry.diff is not None and sum(map(len, entry.diff)) > DIFF_SCALE * most:
            over.append(f"tools[{index}].diff (over {DIFF_SCALE * most} characters)")
    return over


def _oversize(definition: dict[str, Any] | None, most: int) -> str | None:
    """Why ``definition`` is over :func:`definition_max` (``most``), or ``None``."""
    if definition is None:
        return None
    try:
        size = len(canonical.dumps_canonical(definition))
    except canonical.JSONRejected:
        return "no canonical form"
    return f"over {most} bytes" if size > most else None


def _differs(kind: DefinitionKind, definition: dict[str, Any] | None, pin: str | None) -> bool:
    """Whether ``pin`` isn't the pin of ``definition`` as ``kind``, when there is one."""
    if definition is None:
        return False
    try:
        return pin_for(kind, definition) != pin
    except ProjectionError:  # one the gateway couldn't have pinned either
        return True


def _mismatched(report: RemoteReport | ToolkitReport) -> tuple[str, ...]:
    """Every tool whose reported pin isn't its definition's (X11), or whose reviewed definition
    isn't the one the policy's pin names (Y10): its ``pinned`` is that pin, and its own. Each
    entry is pinned as its kind, against its kind's pins."""
    return tuple(
        entry.name
        for entry in report.tools
        if _differs(entry.kind, entry.definition, entry.pin)
        or _differs(entry.kind, entry.reviewed, entry.pinned)
        or (
            entry.reviewed is not None
            and entry.pinned != _policy_of(report.policy, entry.kind)[1].get(entry.name)
        )
    )


def read(data: object, limits: GatewayLimits) -> RemoteReport | ToolkitReport:
    """One report, from its parsed JSON, under the running ``limits``. Raises
    :class:`ReportRefused`: ``review_invalid`` for one that fails the model or a cap, then
    ``pin_mismatch`` if any reported pin isn't its definition's, or any reviewed definition
    isn't the one the policy's pin names, which refuses all of it."""
    try:
        report = _REPORT.validate_python(data)
    except ValidationError as exc:
        raise _invalid([_location(error["loc"]) for error in exc.errors()]) from exc
    over = _within(report, limits)
    if over:
        raise _invalid(over)
    mismatched = _mismatched(report)
    if mismatched:
        raise ReportRefused(
            "pin_mismatch", "a reported pin isn't the pin of its definition", mismatched
        )
    return report


# --- the gateway's side: fitting an answer to the caps ------------------------------------------


def _cut(text: str, most: int) -> str:
    """``text`` within ``most`` characters, a cut marked with "..."."""
    return text if len(text) <= most else text[: most - len(CUT)] + CUT


def _name(name: str) -> str:
    """A listed name within :data:`LISTED_NAME_MAX`: a cut one keeps the digest of the whole, so
    two names cut alike stay two tools."""
    if len(name) <= LISTED_NAME_MAX:
        return name
    digest = "sha256:" + hashlib.sha256(name.encode("utf-8", "surrogatepass")).hexdigest()
    return name[: LISTED_NAME_MAX - len(CUT) - len(digest)] + CUT + digest


def _finding(level: str, message: str) -> dict[str, str]:
    return {"level": level, "pointer": "", "message": message}


def _fit_entry(entry: Mapping[str, Any], most: int) -> dict[str, Any]:
    fitted = {**entry, "name": _name(entry["name"])}
    findings = [
        {
            "level": finding["level"],
            "pointer": _cut(finding["pointer"], POINTER_MAX),
            "message": _cut(finding["message"], MESSAGE_MAX),
        }
        for finding in entry["findings"]
    ]
    # The reviewed definition goes first: the listed one stays if it is within the cap.
    reviewed = entry.get("reviewed")
    if reviewed is not None and len(canonical.dumps_canonical(reviewed)) > most:
        fitted["reviewed"] = None
        findings.append(_finding("note", "the reviewed definition was too large to report"))
    definition = entry["definition"]
    if definition is not None and len(canonical.dumps_canonical(definition)) > most:
        fitted.update(definition=None, pin=None, diff=None)
        message = f"the definition is over {most} bytes, more than a review report carries"
        findings.insert(0, _finding("error", message))
    diff = fitted["diff"]
    if diff is not None and sum(map(len, diff)) > DIFF_SCALE * most:
        fitted["diff"] = None
        findings.append(
            _finding("note", f"the diff is over {DIFF_SCALE * most} characters, so not shown")
        )
    if len(findings) > FINDINGS_MAX:
        rest = findings[FINDINGS_MAX - 1 :]
        level = min((finding["level"] for finding in rest), key=_LEVELS.index)
        findings = findings[: FINDINGS_MAX - 1]
        findings.append(_finding(level, f"and {len(rest)} more findings, not shown"))
    fitted["findings"] = findings
    return fitted


def fit(answer: Mapping[str, Any], limits: GatewayLimits) -> dict[str, Any]:
    """The gateway's review ``answer`` (``review.report()``'s or ``toolkit_report()``'s) within
    the caps :func:`read` applies under ``limits``. Pure; ``answer`` itself isn't changed.

    Each finding's pointer and message are cut; a drift entry's reviewed definition over
    :func:`definition_max` goes, for a note that says so; a listed definition over the cap goes,
    with its pin and diff, for an error finding that says so (such a tool has an error finding
    already, so it could never be included); a diff over its cap goes, for a note; findings past
    the 63rd become one, at the most severe level among them; ``server_info``'s strings,
    ``instructions``, a toolkit's distribution and version, and a name that isn't a tool name are
    cut. Everything else is the gateway's as it is."""
    most = definition_max(limits)
    fitted = {**answer, "tools": [_fit_entry(entry, most) for entry in answer["tools"]]}
    info = answer.get("server_info")
    if info is not None:
        fitted["server_info"] = {
            member: value if value is None else _cut(value, TEXT_MAX)
            for member, value in info.items()
        }
    if answer.get("instructions") is not None:
        fitted["instructions"] = _cut(answer["instructions"], INSTRUCTIONS_MAX)
    for member in ("distribution", "version"):
        if answer.get(member) is not None:
            fitted[member] = _cut(answer[member], DISTRIBUTION_MAX)
    return fitted
