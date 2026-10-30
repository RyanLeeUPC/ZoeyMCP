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
- A server that enables prompts or resources (M6 design L.7) has its ``prompts`` and
  ``resources`` blocks written whole, by the same rules per kind (:class:`KindChanges`): an entry
  included at the pin listed, a drifted one at its old pin unless re-pinned, the rest declined
  one by one or at once, and ``assistant`` kept for the prompts still included. A prompt or a
  resource is never classified. A kind the change doesn't name stays as the policy has it.
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

What an upstream offers beyond tools that the server's ``enable`` doesn't list is named on the
portal's server row and by ``zoeymcp review`` with J12's way to serve it (M6 design J12, D-216):
:func:`not_served_line` and :func:`serve_text`, which add ``completions`` only where ``check``
would take them (A.2 row 5c), the CLI and the vault building the same text here.
"""

from __future__ import annotations

import json
import re
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final, Literal

from ..suggest import Suggestion, suggestion
from . import fields
from .change import Comment, PolicyChange, SetServerReview
from .ratchet import DefKey
from .schema import Capability, PromptsPolicy, ResourceSet, ResourcesPolicy, Tools

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
# A definition's lines, each its chunks (:func:`definition_lines`), as the planner keeps them.
Lines = tuple[tuple[str, ...], ...]
AllowReason = Literal["allow_needs_review", "allow_marked", "consequential_allow"]
# The kinds a remote server's review lists beside its tools (M6 design L.4, L.7), in the order
# the report lists them; how a comment or a refusal names each; and where its block is in the
# server's entry (the policy block of a review), a tool's being the entry itself.
KINDS: Final = ("prompt", "resource_template", "resource")
NOUNS: Final[Mapping[str, str]] = {
    "tool": "tool",
    "prompt": "prompt",
    "resource_template": "resource template",
    "resource": "resource",
}
BLOCKS: Final[Mapping[str, tuple[str, ...]]] = {
    "tool": (),
    "prompt": ("prompts",),
    "resource_template": ("resources", "templates"),
    "resource": ("resources", "fixed"),
}


def kind_of(entry: Mapping[str, Any]) -> str:
    """An entry's definition kind: a tool unless it says otherwise (M7 F.4)."""
    kind: str = entry.get("kind", "tool")
    return kind


def is_key(kind: str, name: str) -> bool:
    """Whether ``name`` is one the policy can hold an entry of ``kind`` under: a tool's or a
    prompt's name, or a resource template or a fixed resource's URI in L.1's form."""
    if kind in ("tool", "prompt"):
        return TOOL_NAME.fullmatch(name) is not None
    rule = fields.uri_template if kind == "resource_template" else fields.resource_uri
    try:
        rule(name)
    except ValueError:
        return False
    return True


def block_of(review: Mapping[str, Any], kind: str) -> Mapping[str, Any]:
    """The policy's block for ``kind`` the review ran under: its ``include``, ``review`` and
    ``declined`` (a prompts block's ``assistant`` too), each member the report leaves out at its
    default (the vault holds a report as it was set, ``exclude_unset``), so every member is
    there, empty for a kind the server doesn't enable."""
    found: Mapping[str, Any] = review["policy"]
    for key in BLOCKS[kind]:
        found = found.get(key) or {}
    if kind == "tool":
        return found
    model = PromptsPolicy if kind == "prompt" else ResourceSet
    return {**model().model_dump(), **found}  # the defaults are plain lists and mappings


def enabled(review: Mapping[str, Any]) -> tuple[str, ...]:
    """The kinds beyond tools the review lists, as the server enables them: the policy block
    holds ``prompts`` and ``resources`` only for an enabled kind (L.4)."""
    return tuple(kind for kind in KINDS if BLOCKS[kind][0] in review["policy"])


def pinnable(entry: Mapping[str, Any]) -> bool:
    """A pin line may be written: a valid name (or URI, for a resource) and pin, and no error
    finding."""
    pin = entry.get("pin")
    return (
        isinstance(pin, str)
        and PIN.fullmatch(pin) is not None
        and is_key(kind_of(entry), entry["name"])
        and not any(finding["level"] == "error" for finding in entry["findings"])
    )


def listed(review: Mapping[str, Any], kind: str = "tool") -> dict[str, dict[str, Any]]:
    """The entries of ``kind`` the server lists, its tools unless named, by name: every entry
    of that kind but a missing one."""
    return {
        entry["name"]: entry
        for entry in review["tools"]
        if kind_of(entry) == kind and entry["state"] != "missing"
    }


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
class KindChanges:
    """What a review changes among one kind's entries beyond tools (M6 design L.7): ``include``,
    the kind's whole include list, in order; ``repin``, its drifted entries given their new
    pin; ``declined``, its whole ``declined`` block, or ``None`` for the policy's, less what
    ``include`` holds."""

    include: tuple[str, ...]
    repin: frozenset[str] = frozenset()
    declined: Mapping[str, str] | None = None


@dataclass(frozen=True)
class Changes:
    """What a snippet changes in the server's entry: ``added`` tools included, in order;
    ``dropped`` ones taken out; ``moved`` ones, included already, classified anew; ``repin``
    ones, drifted, given their new pin; ``declined``, the server's whole ``declined`` block
    (:func:`declined_block`), or ``None`` to leave it as it is; ``kinds``, each kind beyond
    tools the change makes (L.7). Every other tool, and every kind it doesn't name, stays as the
    policy has it."""

    added: Mapping[str, Added] = field(default_factory=dict)
    dropped: frozenset[str] = frozenset()
    moved: Mapping[str, Classification] = field(default_factory=dict)
    repin: frozenset[str] = frozenset()
    declined: Mapping[str, str] | None = None
    kinds: Mapping[str, KindChanges] = field(default_factory=dict)


def declined_block(
    review: Mapping[str, Any],
    declines: Mapping[str, str],
    *,
    undeclined: Sequence[str] = (),
    included: Sequence[str] = (),
    kind: str = "tool",
) -> dict[str, str] | None:
    """The ``declined`` block of the server (or of its ``kind``'s block) once ``declines``
    (name, the pin shown) are recorded, ``undeclined`` entries taken out of it and ``included``
    ones leave it (J.3), or ``None`` when it has none and nothing is declined, so the snippet
    stays M7's."""
    before: Mapping[str, str] = block_of(review, kind).get("declined") or {}
    if not before and not declines:
        return None
    block = {**before, **declines}
    for name in (*undeclined, *included):
        block.pop(name, None)
    return dict(sorted(block.items()))


def the_rest(
    review: Mapping[str, Any], included: Sequence[str], kind: str = "tool"
) -> dict[str, str]:
    """**Record the rest as declined** (J.3, G-19): every listed, pinnable entry of ``kind``
    (a tool unless named) not in ``included``, at the pin shown."""
    return {
        name: entry["pin"]
        for name, entry in listed(review, kind).items()
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


def kind_blocks(review: Mapping[str, Any]) -> tuple[str, ...]:
    """The server's blocks beyond its tools a review writes whole: ``prompts`` and
    ``resources``, each for an enabled kind (L.7)."""
    return tuple(block for block in ("prompts", "resources") if block in review["policy"])


def _blocks(declined: bool, kinds: Sequence[str]) -> str:
    names = ["tools", "review", *(["declined"] if declined else []), *kinds]
    return ", ".join(f"{name}:" for name in names[:-1]) + f" and {names[-1]}: blocks"


def title(server: str, *, declined: bool = False, kinds: Sequence[str] = ()) -> str:
    """The snippet's title: what to do with it."""
    blocks = _blocks(declined, kinds)
    return f"review of {server}. Replace the {blocks} of gateway.servers.{server}."


def second_title(server: str, *, declined: bool = False, kinds: Sequence[str] = ()) -> str:
    """Fragment 2's title (E.4): the choices file's fragment, after onboarding's fragment 1."""
    return (
        f"review of {server} (2 of 2). Replace the {_blocks(declined, kinds)} of "
        f"gateway.servers.{server}, then assign {server} to its clients."
    )


# The ``enable`` entries an upstream may offer that a row or a review names as not served (M6
# design J12), in this order: never ``logging``, which ``enable`` doesn't name.
OFFERABLE: Final[tuple[Capability, ...]] = ("prompts", "resources", "completions")
# J12's step when only completions are offered and ``check`` would refuse them (A.2 row 5c).
COMPLETIONS_NEED: Final = "completions need prompts enabled, or a resource template included"


def enableable(
    kinds: Sequence[str], enable: Collection[str], *, templates: bool
) -> tuple[str, ...]:
    """The ``kinds`` J12's step adds to ``enable``: ``completions`` only where ``check`` takes
    them once added (A.2 row 5c), with ``prompts`` enabled or ``resources`` enabled and a
    template included (``templates``)."""
    after = {*enable, *kinds}
    usable = "prompts" in after or ("resources" in after and templates)
    return tuple(kind for kind in kinds if kind != "completions" or usable)


def _listed(kinds: Sequence[str]) -> str:
    """``prompts``, ``prompts and resources``, ``prompts, resources and completions``."""
    return " and ".join(filter(None, (", ".join(kinds[:-1]), kinds[-1])))


def enable_text(server: str, kinds: Sequence[str], *, managed: bool) -> str:
    """J12's way to serve ``kinds`` of ``server``: in managed mode the host's export, edit and
    import (``enable`` is wider, so host-only), in declarative mode the policy and a reload."""
    entries = f"enable: [{', '.join(kinds)}]"
    if managed:
        return f"export, add {entries} to {server}, import"
    return f"add {entries} to {server} in your policy and reload"


def serve_text(
    server: str, kinds: Sequence[str], enable: Collection[str], *, templates: bool, managed: bool
) -> str:
    """J12's way to serve the offered ``kinds`` the server's ``enable`` doesn't list: the
    :func:`enableable` ones, or :data:`COMPLETIONS_NEED` when there are none."""
    adding = enableable(kinds, enable, templates=templates)
    return enable_text(server, adding, managed=managed) if adding else COMPLETIONS_NEED


def not_served_line(
    server: str, kinds: Sequence[str], enable: Collection[str], *, templates: bool, managed: bool
) -> str:
    """``zoeymcp review``'s line for what ``server`` offers and doesn't serve (J12)."""
    way = serve_text(server, kinds, enable, templates=templates, managed=managed)
    return f"{server} offers {_listed(kinds)}, not served: {way}"


def fragment(
    review: Mapping[str, Any], changes: Changes, *, heading: str | None = None
) -> PolicyChange:
    """The server's entry with ``changes`` made, as a change for the emitter: its ``tools`` and
    ``review`` replaced whole, its ``declined`` too when ``changes`` hold it, its ``prompts``
    and ``resources`` for each kind it enables (:func:`kind_block`, L.7), and its ``era`` when
    the review learned it. A tool with an error finding gets no pin; a drifted, missing or
    unpinnable included tool keeps the pin it has, so it stays hidden; a re-pinned one kept in
    ``allow`` though its new definition isn't suggested ``allow`` says so (Q8 (a)), and an
    included ``approve`` tool moved to ``allow`` says calls to it will run with no prompt
    (:data:`MOVED_TO_ALLOW`, J3). Raises ``ValueError`` for a name the policy can't hold."""
    server, policy = review["server"], review["policy"]
    by_name = {e["name"]: e for e in _entries(review, "tool")}
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
    blocks: dict[str, ResourceSet] = {}
    for other in enabled(review):  # a prompt or a resource (L.7)
        made = changes.kinds.get(other) or KindChanges(tuple(block_of(review, other)["include"]))
        blocks[other], said = kind_block(review, other, made)
        notes += said
    prompts = None
    if "prompt" in blocks:
        kept_prompts = blocks["prompt"].include
        held_assistant = block_of(review, "prompt")["assistant"]
        assistant = [name for name in held_assistant if name in kept_prompts]
        prompts = PromptsPolicy(**dict(blocks["prompt"]), assistant=assistant)
    resources = None
    if "resource_template" in blocks:
        resources = ResourcesPolicy(templates=blocks["resource_template"], fixed=blocks["resource"])
    tools = Tools(include=include, allow=classes["allow"], approve=classes["approve"])
    era = review.get("era") if review.get("era") in ("modern", "legacy") else None
    op = SetServerReview(
        server, tools, pins, era=era, declined=declined, prompts=prompts, resources=resources
    )
    heading = heading or title(server, declined=declined is not None, kinds=kind_blocks(review))
    return PolicyChange(heading, (*notes, op))


def kind_block(
    review: Mapping[str, Any], kind: str, made: KindChanges
) -> tuple[ResourceSet, list[Comment]]:
    """One kind's block with ``made`` (L.7), by :func:`fragment`'s rules for tools: an entry
    included anew, or included and listed as its pin holds it, at the pin listed; a drifted one
    re-pinned at its new pin; any other included one at the pin it has; its ``declined`` block
    whole; and the comments, each naming the kind. A prompts block's ``assistant`` is the
    caller's."""
    server, noun = review["server"], NOUNS[kind]
    old = block_of(review, kind)["include"]
    pins: dict[str, str] = {}
    notes: list[Comment] = []
    others: list[Comment] = []
    declined = made.declined
    if declined is None:
        declined = declined_block(review, {}, included=made.include, kind=kind) or {}
    for entry in sorted(_entries(review, kind), key=lambda found: str(found["name"])):
        name, state, pin, pinned = entry["name"], entry["state"], entry["pin"], entry["pinned"]
        if name in made.include and name not in old:
            pins[name] = pin
            notes.append(Comment("added", name, noun))
        elif name in made.include:
            if state in MATCHING_STATES and pinnable(entry):
                pins[name] = pin
            elif state == "drift" and name in made.repin and pinnable(entry):
                pins[name] = pin
                notes.append(Comment("changed_was", name, f"{noun}, was {pinned}"))
            elif pinned is not None and PIN.fullmatch(pinned):
                pins[name] = pinned
                notes.append(Comment("kept", name, f"{noun}; {_kept_why(server, name, entry)}"))
        elif state != "missing":
            if not pinnable(entry):
                others.append(Comment("error_finding", name, f"{noun}; review {server} shows why"))
            elif declined.get(name) == pin:
                others.append(Comment("declined", name, f"{noun}: {pin}"))
            else:
                others.append(Comment("not_included", name, f"{noun}: {pin}"))
    block = ResourceSet(include=list(made.include), review=pins, declined=dict(declined))
    return block, [*notes, *others]


def _entries(review: Mapping[str, Any], kind: str) -> list[Mapping[str, Any]]:
    """Every entry of ``kind`` the review reports, a missing one included, under a name the
    policy can hold."""
    return [e for e in review["tools"] if kind_of(e) == kind and is_key(kind, e["name"])]


def _kept_why(server: str, name: str, entry: Mapping[str, Any]) -> str:
    state = entry["state"]
    if state == "drift" and kind_of(entry) != "tool":  # accepted on the review screen (L.7)
        return f"drift: the server lists {entry['pin']}; accept its new definition to take it"
    if state == "drift":
        return f"drift: the server lists {entry['pin']}; review {server} --repin {name} takes it"
    if state == "missing":
        return "missing: the server doesn't list it"
    return f"{state}: not pinnable, kept hidden"


# --- what the change rests on (J.3; for the planner, G.5) ----------------------------------------


def _key(review: Mapping[str, Any], entry: Mapping[str, Any]) -> DefKey:
    return (review["server"], entry.get("kind", "tool"), entry["name"])


def verified(review: Mapping[str, Any], op: SetServerReview) -> frozenset[tuple[DefKey, str]]:
    """Every ``(DefKey, pin)`` the op writes that the report lists the tool, the prompt or the
    resource at: a re-pin's and a new include's, each the vault's own recomputation (X11), never
    a pin it kept."""
    written: list[tuple[str, Mapping[str, str]]] = [("tool", op.review)]
    if op.prompts is not None:
        written.append(("prompt", op.prompts.review))
    if op.resources is not None:
        written.append(("resource_template", op.resources.templates.review))
        written.append(("resource", op.resources.fixed.review))
    found: set[tuple[DefKey, str]] = set()
    for kind, written_pins in written:
        by_name = listed(review, kind)
        found |= {
            (_key(review, by_name[name]), pin)
            for name, pin in written_pins.items()
            if name in by_name and by_name[name]["pin"] == pin
        }
    return frozenset(found)


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
