"""The portal's review data (M7 design F.6, K.1, K.5; CR-2, CR-3, TI-5, E-9). Pure, mutation-tested.

A review job's report is the gateway's own review (``common/reviewreport.py`` checked its shape and
every pin). :func:`rows` turns a done job's report into what the review screen renders as text
only: every string the vault didn't write passes :func:`.display.shown` and ends in ``_shown``
(D-120), and a tool's definition is ``json.dumps(definition, ensure_ascii=True, indent=2,
sort_keys=True)`` split into lines, so every character outside ASCII, a bidi control or a hidden
one among them, is already a visible ``\\uXXXX`` escape. Each line is split again into chunks of
:data:`CHUNK` code points with **nothing cut**: the pin covers the whole definition, a
16,384-character description included, so the screen shows all of it (CR-2, TI-5), and the chunks
of a line joined are the line. A tool's suggestion comes from the shared rule
(``common/suggest.py``, CR-3): ``allow`` only for one the server marks read-only and not
destructive, and ``approve`` otherwise, an unannotated tool and one a toolkit declares
consequential included. It is labelled as the server's, pre-fills an included tool's
classification on the page, and never includes a tool (E-9).

:func:`diff` builds fragment 2 (E.4) from the operator's choices, ``{"include", "allow",
"approve", "indent"?}``, as the CLI's choices file does: the same change (``cli/review.py``'s
:func:`~zoeymcp.cli.review.fragment`, its two blocks replacing the server's, and its ``declined``
block too once the server has one, M6 design J.5, its title then naming all three), checked
merged into the running policy, then written by the emitter. It refuses ``bad_body`` for choices
of the wrong shape, ``review_stale`` when the server's tools or declines in the running policy
aren't the ones the review ran under (a reload since, GR-11), and ``diff_invalid`` for an
unknown tool, a tool in both lists, an included tool left unclassified, a classified one not
included, an unpinnable tool newly included, a toolkit's consequential tool in ``allow``, or a
merged policy that fails ``check``.
Nothing is saved: declarative mode.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Any, Final

from ..cli.review import (
    TOOL_NAME,
    Added,
    Changes,
    Classification,
    declined_block,
    fragment,
    listed,
    pinnable,
    second_title,
)
from ..common.policy.change import ChangeRefused, validate
from ..common.policy.emit import COMPOSE_INDENT, INDENT_MAX, EmitRefused, Target, emit
from ..common.policy.findings import Finding
from ..common.policy.schema import Policy
from ..common.reviewreport import INSTRUCTIONS_MAX, MESSAGE_MAX, TEXT_MAX
from ..common.suggest import Suggestion, suggestion
from ..vault.onboarding import Listed, reviewed_next
from .display import DEFAULT_LIMIT, NAME_LIMIT, shown
from .refusals import Refusal, refusal

# A definition line's chunks are at most this many code points (F.6).
CHUNK: Final = 200
# Why each suggestion was made, labelled as the server's (E-9).
WHY_READ_ONLY: Final = "the server marks it read-only"
WHY_HINTED: Final = "the server's hints don't mark it read-only"
WHY_UNANNOTATED: Final = "the server doesn't annotate it"
WHY_CONSEQUENTIAL: Final = "the toolkit declares it consequential: approve, never allow"
# Why a tool can't be included.
GONE: Final = "the server no longer lists it"
ERROR_FINDING: Final = "it has an error finding"
NO_PIN: Final = "the server gave no definition the vault can pin"
# The choices a diff takes, and how many of each a findings detail names.
LISTS: Final = ("include", "allow", "approve")
DETAIL_FINDINGS: Final = 5


# --- the rows (F.6, K.1) -------------------------------------------------------------------------


def rows(report: Mapping[str, Any]) -> dict[str, Any]:
    """A done job's report as the review screen renders it: the server, what the review learned
    of it, the counts, and one row per tool."""
    tools = [_row(entry) for entry in report["tools"]]
    instructions = report.get("instructions")
    return {
        "state": "done",
        "server_shown": shown(report["server"], NAME_LIMIT),
        "kind": report["kind"],
        "era": report.get("era"),
        "protocol_version": report.get("protocol_version"),
        "server_info_shown": _info(report.get("server_info")),
        "instructions_shown": None
        if instructions is None
        else shown(instructions, INSTRUCTIONS_MAX, single_line=False),
        "notes": notes(report),
        "counts": counts(report),
        "tools": tools,
    }


def _info(info: Mapping[str, Any] | None) -> str | None:
    """The server's own name, version and title, as one line."""
    if info is None:
        return None
    text = f"{info['name']} {info['version']}"
    title = info.get("title")
    if title is not None:
        text += f" ({title})"
    return shown(text, DEFAULT_LIMIT)


def notes(report: Mapping[str, Any]) -> list[str]:
    """What the screen says of the server as a whole: ``blocked`` when a marked tool blocks it,
    and ``pinning_off`` for a toolkit served without pins."""
    found = []
    if report["blocked"]:
        found.append("blocked")
    if report.get("pinning") == "off":
        found.append("pinning_off")
    return found


def counts(report: Mapping[str, Any]) -> dict[str, int]:
    """K.1's counts over the tools the server lists: in all, marked read-only by the server,
    not annotated, with a warning finding, with an error finding, and included now. A note
    (the gateway's echo of the server's suggestion, say) isn't counted."""
    entries = list(listed(report).values())
    return {
        "tools": len(entries),
        "read_only": sum(_hinted(entry) == "allow" for entry in entries),
        "not_annotated": sum(_hinted(entry) is None for entry in entries),
        "with_findings": sum(_has(entry, "warning") for entry in entries),
        "with_errors": sum(_has(entry, "error") for entry in entries),
        "included": sum(bool(entry["included"]) for entry in entries),
    }


def _row(entry: Mapping[str, Any]) -> dict[str, Any]:
    definition = entry["definition"]
    name = entry["name"]
    suggested, why = suggested_for(entry)
    row: dict[str, Any] = {
        # The name the page posts: only a tool name, never one the server listed as invalid.
        "name": name if TOOL_NAME.fullmatch(name) else None,
        "name_shown": shown(name, NAME_LIMIT),
        "state": entry["state"],
        "included": entry["included"],
        "classification": entry["classification"],
        "suggested": suggested,
        "suggested_why": why,
        "pinnable": pinnable(entry),
        "not_pinnable": unpinnable(entry),
        "pin": entry["pin"],
        "title_shown": None,
        "description_shown": None,
        "definition_lines": [] if definition is None else definition_lines(definition),
        "findings": [
            {"level": finding["level"], "message_shown": shown(finding["message"], MESSAGE_MAX)}
            for finding in entry["findings"]
        ],
    }
    if definition is not None:
        title = _text(definition.get("title")) or _text(_annotations(entry).get("title"))
        description = _text(definition.get("description"))
        row["title_shown"] = None if title is None else shown(title, DEFAULT_LIMIT)
        row["description_shown"] = (
            None if description is None else shown(description, TEXT_MAX, single_line=False)
        )
    if "consequential" in entry:
        row["consequential"] = entry["consequential"]
    return row


def _text(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _annotations(entry: Mapping[str, Any]) -> Mapping[str, Any]:
    definition = entry["definition"]
    found = definition.get("annotations") if isinstance(definition, Mapping) else None
    return found if isinstance(found, Mapping) else {}


def _hinted(entry: Mapping[str, Any]) -> Suggestion | None:
    """What the tool's own annotations suggest (the shared rule), or None for no hint."""
    return suggestion(_annotations(entry))


def _has(entry: Mapping[str, Any], level: str) -> bool:
    return any(finding["level"] == level for finding in entry["findings"])


def suggested_for(entry: Mapping[str, Any]) -> tuple[Classification, str]:
    """The classification shown as the suggestion, and why: ``allow`` only for a tool the server
    marks read-only and not destructive, else ``approve``, an unannotated tool's and a toolkit's
    consequential tool's included (F.6)."""
    if entry.get("consequential") is True:
        return "approve", WHY_CONSEQUENTIAL
    hinted = _hinted(entry)
    if hinted == "allow":
        return "allow", WHY_READ_ONLY
    return "approve", WHY_UNANNOTATED if hinted is None else WHY_HINTED


def unpinnable(entry: Mapping[str, Any]) -> str | None:
    """Why the tool can't be included, or None when it can: the include box is absent then,
    with this reason (K.1)."""
    if pinnable(entry):
        return None
    if entry["state"] == "missing":
        return GONE
    return ERROR_FINDING if _has(entry, "error") else NO_PIN


def definition_lines(definition: Mapping[str, Any]) -> list[list[str]]:
    """The definition as ASCII JSON lines, each split into chunks of at most :data:`CHUNK` code
    points, nothing cut: joined, each line's chunks are the line, and the lines joined with
    line breaks are the ``json.dumps`` text."""
    text = json.dumps(definition, ensure_ascii=True, indent=2, sort_keys=True)
    return [
        [line[start : start + CHUNK] for start in range(0, len(line), CHUNK)] or [""]
        for line in text.split("\n")
    ]


# --- fragment 2 (F.6, E.4, H) --------------------------------------------------------------------


@dataclass(frozen=True)
class Choices:
    """What the operator chose: the tools to include, in order, those of them in ``allow`` and
    in ``approve``, and the fragment's indent (H.2)."""

    include: tuple[str, ...]
    allow: frozenset[str]
    approve: frozenset[str]
    indent: int = 0
    target: Target = "plain"

    def classified(self, name: str) -> Classification:
        return "allow" if name in self.allow else "approve"


def choices(body: Mapping[str, Any], most: int) -> Choices | Refusal:
    """The diff's body: each list a list of distinct tool names, at most ``most`` long
    (``max_tools_per_server``), and an indent of 0 to 16 or ``compose``. Its keys were checked
    against the route's."""
    lists: dict[str, list[str]] = {}
    for key in LISTS:
        value = body[key]
        if not isinstance(value, list) or not all(
            isinstance(name, str) and TOOL_NAME.fullmatch(name) for name in value
        ):
            return _bad_body(f"{key} is a list of tool names")
        if len(value) > most:
            return _bad_body(f"{key} names at most {most} tools (max_tools_per_server)")
        if len(set(value)) != len(value):
            return _bad_body(f"{key} names a tool twice")
        lists[key] = value
    indent = body.get("indent", 0)
    target: Target = "plain"
    if indent == "compose":
        indent, target = COMPOSE_INDENT, "compose"
    elif isinstance(indent, bool) or not isinstance(indent, int) or not 0 <= indent <= INDENT_MAX:
        return _bad_body(f"indent is 0 to {INDENT_MAX}, or compose")
    return Choices(
        tuple(lists["include"]),
        frozenset(lists["allow"]),
        frozenset(lists["approve"]),
        indent,
        target,
    )


def stale(report: Mapping[str, Any], server: Listed | None) -> bool:
    """Whether the running policy's entry for the server isn't the one the review ran under
    (GR-11): gone, of another kind, or other tools, classifications, ``on_drift`` or declines
    (fragment 2 writes the report's ``declined`` block, which would undo a later decline; M6
    design J.2, J.5; a report without the block ran under none)."""
    if server is None or server.kind != report["kind"]:
        return True
    ran, tools = report["policy"], server.tools
    return (
        sorted(tools.include) != sorted(ran["include"])
        or sorted(tools.allow) != sorted(ran["allow"])
        or sorted(tools.approve) != sorted(ran["approve"])
        or server.on_drift != ran["on_drift"]
        or dict(server.declined) != dict(ran.get("declined") or {})
    )


def changes(report: Mapping[str, Any], chosen: Choices) -> Changes | Refusal:
    """What ``chosen`` changes in the server's entry, or ``diff_invalid`` naming what can't be
    chosen. A tool the policy includes already keeps its pin, as the CLI's choices file keeps
    it; one newly included must be pinnable."""
    by_name = listed(report)
    ran = report["policy"]
    included: list[str] = ran["include"]
    named = [*chosen.include, *sorted(chosen.allow), *sorted(chosen.approve)]
    unknown = _names(n for n in named if n not in by_name and n not in included)
    if unknown:
        return _invalid(f"the server lists no tool {unknown}")
    both = _names(chosen.allow & chosen.approve)
    if both:
        return _invalid(f"{both} is in both allow and approve")
    picked = set(chosen.include)
    stray = _names((chosen.allow | chosen.approve) - picked)
    if stray:
        return _invalid(f"{stray} is classified but not included")
    open_ = _names(n for n in chosen.include if n not in chosen.allow | chosen.approve)
    if open_:
        return _invalid(f"{open_} is included but neither allowed nor approved")
    new = [name for name in chosen.include if name not in included]
    unpinned = _names(name for name in new if not pinnable(by_name[name]))
    if unpinned:
        return _invalid(f"{unpinned} can't be pinned, so it can't be included")
    declared = _names(n for n in chosen.allow if by_name.get(n, {}).get("consequential") is True)
    if declared:
        return _invalid(f"the toolkit declares {declared} consequential, so it can't be in allow")
    added = {
        name: Added(chosen.classified(name), f"{chosen.classified(name)}, chosen in the portal")
        for name in new
    }
    held = {name: kind for kind in ("allow", "approve") for name in ran[kind]}
    moved: dict[str, Classification] = {
        name: chosen.classified(name)
        for name in chosen.include
        if name in included and held.get(name) != chosen.classified(name)
    }
    dropped = frozenset(name for name in included if name not in picked)
    # The server's declined block, an included tool leaving it, as the CLI's snippet writes it
    # (M6 design J.5); none while the server has none, so the fragment stays M7's.
    declined = declined_block(report, {}, included=tuple(added))
    return Changes(added=added, dropped=dropped, moved=moved, declined=declined)


def diff(
    report: Mapping[str, Any],
    server: Listed | None,
    body: Mapping[str, Any],
    *,
    policy: Policy,
    most: int,
    source: str,
) -> dict[str, Any] | Refusal:
    """Fragment 2 for the operator's choices (M.1's answer: ``{diff: {yaml, check}, next}``),
    or the refusal. ``server`` is the running policy's entry for the report's server,
    ``source`` the policy's source label for the ``next`` list (E.5)."""
    chosen = choices(body, most)
    if isinstance(chosen, Refusal):
        return chosen
    if stale(report, server):
        return refusal("review_stale")
    made = changes(report, chosen)
    if isinstance(made, Refusal):
        return made
    name = report["server"]
    try:
        heading = second_title(name, declined=made.declined is not None)
        change = fragment(report, made, heading=heading)
        findings = validate(policy, change)
        text = emit(change, indent=chosen.indent, target=chosen.target)
    except ChangeRefused as exc:
        return _invalid("; ".join(exc.messages) or exc.path)
    except EmitRefused as exc:
        return _invalid(f"{exc.path}: {exc.reason}")
    errors = [finding for finding in findings if finding.level == "error"]
    if errors:
        detail = "; ".join(f"{f.path}: {f.message}" for f in errors[:DETAIL_FINDINGS])
        return replace(_invalid(detail), more=(("check", _found(findings)),))
    return {
        "diff": {"yaml": text, "check": _found(findings)},
        "next": [step.answer() for step in reviewed_next(name, source)],
    }


def _found(findings: list[Finding]) -> list[dict[str, str]]:
    return [finding.as_dict() for finding in findings]


def _names(names: Any) -> str:
    """Tool names for a refusal's detail: each once, in order, comma separated."""
    return ", ".join(dict.fromkeys(names))


def _bad_body(detail: str) -> Refusal:
    return replace(refusal("bad_body"), more=(("detail", detail),))


def _invalid(detail: str) -> Refusal:
    return refusal("diff_invalid", detail=detail)
