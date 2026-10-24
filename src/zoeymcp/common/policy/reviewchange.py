"""The change a review makes to one server's entry (M6 design J.3; D-153). Pure, mutation-tested.

``zoeymcp review``'s snippet and choices file and the portal's fragment 2 build the same change
here: :func:`planned` reads the CLI's options, the portal and the choices file build their own
:class:`Changes`, and :func:`fragment` writes the server's entry as a
:class:`~zoeymcp.common.policy.change.PolicyChange` for the emitter (M7 design H, DD-13). The
rules, from the report the vault checked (``common/reviewreport.py``):

- A drifted, included tool keeps its pin unless it is re-pinned (``repin``), which takes the
  report's pin, the one the vault recomputed itself (X11). :func:`verified` names every
  ``(DefKey, pin)`` the change writes from the report, a re-pin's among them.
- A re-pin keeps the classification (Q8 (a)): an ``allow`` tool whose new definition the shared
  rule (``common/suggest.py``) no longer suggests ``allow`` is proposed ``approve``
  (:data:`PROPOSED`), and kept ``allow``, the fragment says so in a comment line.
- An included ``approve`` tool moved to ``allow`` (**Allow without asking** in declarative mode,
  J3) gets the comment line :data:`MOVED_TO_ALLOW`: calls to it will run with no prompt.
- A tool the operator leaves out is recorded under the server's ``declined`` at the pin shown,
  one by one or the rest at once (J.5); an included tool leaves ``declined``. The block is written
  whole once the server has one or the change declines a tool, otherwise the change is M7's.
- :func:`definitions` records, for every name the change classifies ``allow`` at a
  (classification, pin) the policy the review ran under doesn't hold (a move, a re-include, a
  new include as ``allow``, a re-pinned ``allow`` tool), :func:`definition_lines` of the
  definition at the pin the change writes: the listed one for a tool listed at that pin, the
  ``reviewed`` one for a drifted tool kept at its old pin, the listed one on a ``pinning: off``
  toolkit, where no pin is written. It refuses ``allow_needs_review`` when the report doesn't hold
  that definition, ``allow_marked`` for a tool the report shows marked and
  ``consequential_allow`` for a toolkit's consequential tool (the planner checks them again).

A definition is shown as ``json.dumps(definition, ensure_ascii=True, indent=2, sort_keys=True)``
split into lines, each line split again into chunks of :data:`CHUNK` code points with **nothing
cut** (M7 F.6, CR-2, TI-5): every character outside ASCII, a bidi control or a hidden one among
them, is a visible ``\\uXXXX`` escape, and the chunks of a line joined are the line.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final, Literal

from ..suggest import Suggestion, suggestion
from .change import Comment, PolicyChange, SetServerReview
from .schema import Tools

TOOL_NAME = re.compile(r"[A-Za-z0-9_.-]{1,128}")
PIN = re.compile(r"sha256:[0-9a-f]{64}")
# A definition line's chunks are at most this many code points (M7 F.6).
CHUNK: Final = 200
# What a re-pinned allow tool whose new definition isn't suggested allow is labelled (Q8 (a)).
PROPOSED: Final = "the new definition isn't marked read-only: proposed approve"
# The sentence an included approve tool moved to allow carries (J3, G.7 row 2; COV-3).
MOVED_TO_ALLOW: Final = "approve -> allow: calls to {name} will run with no prompt"

Classification = Literal["allow", "approve"]
# An included tool in these states is listed as its pin holds it.
MATCHING_STATES: Final = ("ok", "marked", "blocked")
# A definition by (server, kind, name); kind: tool, and from step 19 prompt or resource (E.1).
DefKey = tuple[str, str, str]
# A definition's lines, each its chunks (:func:`definition_lines`), as the planner keeps them.
Lines = tuple[tuple[str, ...], ...]
AllowReason = Literal["allow_needs_review", "allow_marked", "consequential_allow"]


def pinnable(entry: Mapping[str, Any]) -> bool:
    """A pin line may be written: a valid name and pin, and no error finding."""
    pin = entry.get("pin")
    return (
        isinstance(pin, str)
        and PIN.fullmatch(pin) is not None
        and TOOL_NAME.fullmatch(entry["name"]) is not None
        and not any(finding["level"] == "error" for finding in entry["findings"])
    )


def listed(review: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """The tools the server lists, by name: every entry but a missing one."""
    return {entry["name"]: entry for entry in review["tools"] if entry["state"] != "missing"}


def suggested(entry: Mapping[str, Any]) -> Suggestion | None:
    """The classification a tool's own annotations suggest (the shared rule, CR-3)."""
    definition = entry.get("definition")
    return suggestion(definition.get("annotations") if isinstance(definition, dict) else None)


def suggested_words(entry: Mapping[str, Any]) -> str:
    """What the server's annotations suggest for a tool, labelled as the server's (E-9)."""
    if entry.get("consequential"):
        return "declared consequential by the toolkit: approve, never allow"
    found = suggested(entry)
    if found == "allow":
        return "read-only (the server's suggestion)"
    if found == "approve":
        return "not read-only (the server's hints): approve suggested if you include it"
    return "not annotated: approve suggested if you include it"


def read_only(review: Mapping[str, Any]) -> list[str]:
    """``--allow-read-only``'s tools: every listed, pinnable tool not yet included that the
    shared rule suggests ``allow`` for (``readOnlyHint`` and not ``destructiveHint``, F-52),
    never one a toolkit declares consequential. An unannotated tool is never one (PC-2)."""
    return [
        name
        for name, entry in listed(review).items()
        if not entry["included"]
        and pinnable(entry)
        and not entry.get("consequential")
        and suggested(entry) == "allow"
    ]


def proposed(entry: Mapping[str, Any]) -> bool:
    """Whether a drifted ``allow`` tool's new definition is one the shared rule no longer
    suggests ``allow`` for, so a re-pin proposes ``approve`` (Q8 (a))."""
    return (
        entry["state"] == "drift"
        and entry["classification"] == "allow"
        and suggested(entry) != "allow"
    )


def definition_lines(definition: Mapping[str, Any]) -> list[list[str]]:
    """The definition as ASCII JSON lines, each split into chunks of at most :data:`CHUNK` code
    points, nothing cut: joined, each line's chunks are the line, and the lines joined with
    line breaks are the ``json.dumps`` text."""
    text = json.dumps(definition, ensure_ascii=True, indent=2, sort_keys=True)
    return [
        [line[start : start + CHUNK] for start in range(0, len(line), CHUNK)] or [""]
        for line in text.split("\n")
    ]


# --- the change (M7 design F.5, H; M6 J.3) -------------------------------------------------------


@dataclass(frozen=True)
class Choices:
    """``zoeymcp review``'s options: what to show, and what the snippet changes."""

    tools: frozenset[str] = frozenset()  # show only these (empty: all)
    show: frozenset[str] = frozenset()  # print these definitions in full
    show_all: bool = False
    add: tuple[str, ...] = ()
    repin: frozenset[str] = field(default_factory=frozenset)
    allow: tuple[str, ...] = ()
    approve: tuple[str, ...] = ()
    allow_read_only: bool = False
    decline: tuple[str, ...] = ()
    decline_rest: bool = False


@dataclass(frozen=True)
class Added:
    """A tool the snippet includes: its classification (None leaves it to the operator, and
    ``check`` fails until it is given) and what its ``added`` comment says."""

    classification: Classification | None
    why: str


@dataclass(frozen=True)
class Changes:
    """What a snippet changes in the server's entry: ``added`` tools included, in order;
    ``dropped`` ones taken out; ``moved`` ones, included already, classified anew; ``repin``
    ones, drifted, given their new pin; ``declined``, the server's whole ``declined`` block
    (:func:`declined_block`), or ``None`` to leave it as it is. Every other tool stays as the
    policy has it."""

    added: Mapping[str, Added] = field(default_factory=dict)
    dropped: frozenset[str] = frozenset()
    moved: Mapping[str, Classification] = field(default_factory=dict)
    repin: frozenset[str] = frozenset()
    declined: Mapping[str, str] | None = None


def declined_block(
    review: Mapping[str, Any],
    declines: Mapping[str, str],
    *,
    undeclined: Sequence[str] = (),
    included: Sequence[str] = (),
) -> dict[str, str] | None:
    """The server's ``declined`` block once ``declines`` (tool, the pin shown) are recorded,
    ``undeclined`` tools taken out of it and ``included`` ones leave it (J.3), or ``None`` when
    the server has none and nothing is declined, so the snippet stays M7's."""
    before: Mapping[str, str] = review["policy"].get("declined") or {}
    if not before and not declines:
        return None
    block = {**before, **declines}
    for name in (*undeclined, *included):
        block.pop(name, None)
    return dict(sorted(block.items()))


def the_rest(review: Mapping[str, Any], included: Sequence[str]) -> dict[str, str]:
    """**Record the rest as declined** (J.3, G-19): every listed, pinnable tool not in
    ``included``, at the pin shown."""
    return {
        name: entry["pin"]
        for name, entry in listed(review).items()
        if name not in included and pinnable(entry)
    }


def planned(review: Mapping[str, Any], choices: Choices) -> Changes:
    """The changes the options ask for, once the CLI's ``check_choices`` accepts them."""
    by_name = listed(review)
    added: dict[str, Added] = {}
    for name in choices.add:
        if review.get("kind") == "toolkit" and by_name[name].get("consequential"):
            added[name] = Added("approve", "approve, declared by the toolkit")
        else:
            added[name] = Added(None, "put it in allow or approve; nothing is implied")
    for name in choices.allow:
        added[name] = Added("allow", "allow")
    for name in choices.approve:
        added[name] = Added("approve", "approve")
    if choices.allow_read_only:
        for name in read_only(review):
            if name not in choices.decline:
                added.setdefault(
                    name, Added("allow", "allowed because the server marks it read-only")
                )
    declines = {name: by_name[name]["pin"] for name in choices.decline}
    if choices.decline_rest:
        included = [n for n, entry in by_name.items() if entry["included"]]
        for name, pin in the_rest(review, [*included, *added]).items():
            declines.setdefault(name, pin)
    declined = declined_block(review, declines, included=tuple(added))
    return Changes(added=added, repin=choices.repin, declined=declined)


def _blocks(declined: bool) -> str:
    return "tools:, review: and declined: blocks" if declined else "tools: and review: blocks"


def title(server: str, *, declined: bool = False) -> str:
    """The snippet's title: what to do with it."""
    return f"review of {server}. Replace the {_blocks(declined)} of gateway.servers.{server}."


def second_title(server: str, *, declined: bool = False) -> str:
    """Fragment 2's title (E.4): the choices file's fragment, after onboarding's fragment 1."""
    return (
        f"review of {server} (2 of 2). Replace the {_blocks(declined)} of "
        f"gateway.servers.{server}, then assign {server} to its clients."
    )


def fragment(
    review: Mapping[str, Any], changes: Changes, *, heading: str | None = None
) -> PolicyChange:
    """The server's entry with ``changes`` made, as a change for the emitter: its ``tools`` and
    ``review`` replaced whole, its ``declined`` too when ``changes`` hold it, and its ``era``
    when the review learned it. A tool with an error finding gets no pin; a drifted, missing or
    unpinnable included tool keeps the pin it has, so it stays hidden; a re-pinned one kept in
    ``allow`` though its new definition isn't suggested ``allow`` says so (Q8 (a)), and an
    included ``approve`` tool moved to ``allow`` says calls to it will run with no prompt
    (:data:`MOVED_TO_ALLOW`, J3). Raises ``ValueError`` for a name the policy can't hold."""
    server, policy = review["server"], review["policy"]
    by_name = {e["name"]: e for e in review["tools"] if TOOL_NAME.fullmatch(e["name"])}
    dropped, moved, declined = changes.dropped, changes.moved, changes.declined
    include = [name for name in policy["include"] if name not in dropped]
    include += [name for name in changes.added if name not in include]
    classes: dict[Classification, list[str]] = {"allow": [], "approve": []}
    for kind, names in classes.items():
        names += [n for n in policy[kind] if n not in dropped and moved.get(n, kind) == kind]
    news = [*moved.items(), *((name, why.classification) for name, why in changes.added.items())]
    for name, chosen in news:
        if chosen is not None and name not in classes[chosen]:
            classes[chosen].append(name)
    pins: dict[str, str] = {}
    notes: list[Comment] = []
    for name, why in changes.added.items():
        notes.append(Comment("added", name, why.why))
        if why.classification is None:
            notes.append(Comment("suggested", name, suggested_words(by_name[name])))
    # A move from approve to allow says what it allows first (J3, COV-3).
    changed = [
        Comment("changed_was", name, MOVED_TO_ALLOW.format(name=name))
        for name, chosen in sorted(moved.items())
        if chosen == "allow" and name in policy["approve"] and name not in dropped
    ]
    kept: list[Comment] = []
    others: list[Comment] = []
    for name, entry in sorted(by_name.items()):
        state, pin, pinned = entry["state"], entry["pin"], entry["pinned"]
        if name in changes.added:
            pins[name] = pin
        elif entry["included"] and name not in dropped:
            if state in MATCHING_STATES and pinnable(entry):
                pins[name] = pin
            elif state == "drift" and name in changes.repin and pinnable(entry):
                pins[name] = pin
                changed.append(Comment("changed_was", name, f"was {pinned}"))
                if name in classes["allow"] and suggested(entry) != "allow":
                    changed.append(Comment("kept", name, f"allow: {PROPOSED}"))
            elif pinned is not None and PIN.fullmatch(pinned):
                pins[name] = pinned
                kept.append(Comment("kept", name, _kept_why(server, name, entry)))
        elif state != "missing":
            if not pinnable(entry):
                others.append(Comment("error_finding", name, f"review {server} --show {name}"))
            elif declined is not None and declined.get(name) == pin:
                others.append(Comment("declined", name, pin))
            else:
                others.append(Comment("not_included", name, f"{pin}; {suggested_words(entry)}"))
    notes += [*changed, *kept, *others]
    if review.get("kind") == "toolkit" and review.get("pinning") == "off":
        pins = {}
        notes.append(Comment("merge_hint", server, "pinning: off: definitions follow the image"))
    tools = Tools(include=include, allow=classes["allow"], approve=classes["approve"])
    era = review.get("era") if review.get("era") in ("modern", "legacy") else None
    op = SetServerReview(server, tools, pins, era=era, declined=declined)
    return PolicyChange(heading or title(server, declined=declined is not None), (*notes, op))


def _kept_why(server: str, name: str, entry: Mapping[str, Any]) -> str:
    state = entry["state"]
    if state == "drift":
        return f"drift: the server lists {entry['pin']}; review {server} --repin {name} takes it"
    if state == "missing":
        return "missing: the server doesn't list it"
    return f"{state}: not pinnable, kept hidden"


# --- what the change rests on (J.3; for the planner, G.5) ----------------------------------------


def _key(review: Mapping[str, Any], entry: Mapping[str, Any]) -> DefKey:
    return (review["server"], entry.get("kind", "tool"), entry["name"])


def verified(review: Mapping[str, Any], op: SetServerReview) -> frozenset[tuple[DefKey, str]]:
    """Every ``(DefKey, pin)`` the op writes that the report lists the tool at: a re-pin's and a
    new include's, each the vault's own recomputation (X11), never a pin it kept."""
    by_name = listed(review)
    return frozenset(
        (_key(review, by_name[name]), pin)
        for name, pin in op.review.items()
        if name in by_name and by_name[name]["pin"] == pin
    )


@dataclass(frozen=True)
class AllowRefused:
    """A name classified ``allow`` that the review can't stand behind (J.3, N.2)."""

    reason: AllowReason
    name: str


def definitions(
    review: Mapping[str, Any], op: SetServerReview
) -> dict[DefKey, Lines] | AllowRefused:
    """For every name ``op`` classifies ``allow`` at a (classification, pin) the policy the
    review ran under doesn't hold, the lines of the definition at the pin it writes (the listed
    one with ``pinning: off``, where it writes none); or the first refusal, by name."""
    ran = review["policy"]
    held: Mapping[str, str] = ran.get("review") or {}
    off = review.get("kind") == "toolkit" and review.get("pinning") == "off"
    by_name = listed(review)
    found: dict[DefKey, Lines] = {}
    for name in sorted(op.tools.allow):
        pin = op.review.get(name)
        if name in ran["allow"] and (off or held.get(name) == pin):
            continue  # held already: neither a move nor a kept allow
        entry = by_name.get(name)
        definition = None if entry is None else _definition_at(entry, pin, off)
        if entry is None or definition is None:
            return AllowRefused("allow_needs_review", name)
        if entry["state"] == "marked":
            return AllowRefused("allow_marked", name)
        if entry.get("consequential") is True:
            return AllowRefused("consequential_allow", name)
        lines = definition_lines(definition)
        found[_key(review, entry)] = tuple(tuple(chunks) for chunks in lines)
    return found


def _definition_at(entry: Mapping[str, Any], pin: str | None, off: bool) -> Any:
    """The tool's definition the report holds at ``pin``: the listed one, or the reviewed one a
    drift entry carries at its pinned pin; with pinning off, the listed one."""
    if off or (pin is not None and entry["pin"] == pin):
        return entry["definition"]
    if pin is not None and entry["pinned"] == pin:
        return entry.get("reviewed")
    return None
