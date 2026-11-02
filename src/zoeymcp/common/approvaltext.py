"""What a human is asked to approve, and the check that nothing in it can hide (M4 design C).

Whoever holds a call renders its prompt itself: the gateway for a call it holds, the vault (M8)
for a call it holds, from the bytes it holds. A prompt is a fixed frame (a per-call ref, the
client, the server and tool, an absolute deadline), then either the call's canonical arguments or
a toolkit's plan of exact writes, then a footer that repeats the ref. :func:`problems` then
refuses any text that could hide or disguise content; a refused text is never cut or cleaned,
because a cleaned text would no longer be the exact call. A gateway-held prompt asked out of band
reaches the human under the vault's relay line (:func:`relayed`, M8 design E.5).

A toolkit doesn't write free text. Its plan holds :class:`Write` objects, each an exact request
body frozen as canonical bytes when built, with a layout of :class:`Show` items that must cover
every top-level member of the body. Layout mistakes raise :class:`LayoutError` when the write is
built, before anyone is asked.

Every position in a rendered text knows where it came from, so a problem names a JSON pointer
into the arguments or the write body, never the value. Standard library only, so the vault can
reuse it (M8).
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import KW_ONLY, dataclass, field
from datetime import UTC, datetime
from typing import Any, Final, Literal

from . import canonical
from .canonical import JSONValue
from .logs import refuse_type
from .textrules import find_violations

ARROW = "\N{RIGHTWARDS ARROW}"
_ELLIPSIS = "\N{HORIZONTAL ELLIPSIS}"
HEADER_PREFIX = "Approval request "
FOOTER_PREFIX = "End of approval request "
CODE_LINE_PREFIX = "To approve, accept and type this code: "
RELAY_PREFIX = "Rendered by the gateway"
RELAY_LINE = f"{RELAY_PREFIX}: the vault can't confirm this is the call the gateway will run."
LABEL = re.compile(r"^[A-Za-z][A-Za-z0-9 _-]{0,31}$")
MAX_TITLE_CHARS = 120
# The renderer's own JSON indentation, which the whitespace rule leaves alone.
_INDENT = "  "
_MAX_COLUMNS = 8
_MAX_COMBINING = 3

Renders = Literal["markdown", "plain"]
Method = Literal["POST", "PUT", "PATCH"]
RenderedBy = Literal["gateway", "vault"]
Approver = Literal["elicitation", "out_of_band"]

# The instruction names the button the human presses: an elicitation's Accept, or an out-of-band
# surface's Approve (M8 design E.5).
INSTRUCTIONS: Final[Mapping[Approver, str]] = {
    "elicitation": "Accept runs this one call, exactly as shown.",
    "out_of_band": "Approve runs this one call, exactly as shown.",
}
_PIN = re.compile(r"^sha256:[0-9a-f]{64}$")


class LayoutError(ValueError):
    """A toolkit layout that doesn't cover its write exactly: a toolkit bug, never shown."""


# --- text with provenance ------------------------------------------------------------------------


@dataclass(frozen=True, repr=False)
class ApprovalText:
    """A rendered prompt. Its ``repr`` hides the text, and logging it raises."""

    value: str
    # Lines whose leading whitespace is the renderer's JSON indentation.
    indented_lines: frozenset[int]
    # (start offset, JSON pointer or None) for each run of the text, in order.
    sources: tuple[tuple[int, str | None], ...]

    def __repr__(self) -> str:
        return f"ApprovalText(<{len(self.value)} characters>)"

    def pointer_at(self, index: int) -> str | None:
        """The JSON pointer of the value at code-point ``index``, or None for frame text."""
        found: str | None = None
        for start, pointer in self.sources:
            if start > index:
                break
            found = pointer
        return found


refuse_type(ApprovalText)


class _Builder:
    def __init__(self) -> None:
        self._parts: list[str] = []
        self._sources: list[tuple[int, str | None]] = []
        self._length = 0
        self._line = 0
        self._indented: set[int] = set()

    def add(self, text: str, pointer: str | None = None) -> None:
        if not text:
            return
        if not self._sources or self._sources[-1][1] != pointer:
            self._sources.append((self._length, pointer))
        self._parts.append(text)
        self._length += len(text)
        self._line += text.count("\n")

    def newline(self) -> None:
        self.add("\n")

    def mark_indented(self) -> None:
        self._indented.add(self._line)

    def json(self, value: JSONValue, pointer: str) -> None:
        """Add ``value`` exactly as :func:`canonical.render_for_approval` renders it."""
        expected = canonical.render_for_approval(value)  # validates, and is the reference
        start = self._length
        self.mark_indented()
        _json_parts(value, pointer, 0, self)
        if "".join(self._parts)[start:] != expected:  # pragma: no cover - a renderer bug
            raise AssertionError("approval JSON differs from render_for_approval")

    def build(self) -> ApprovalText:
        return ApprovalText("".join(self._parts), frozenset(self._indented), tuple(self._sources))


def _escape(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def _json_parts(value: JSONValue, pointer: str, level: int, out: _Builder) -> None:
    """Mirror canonical's indented encoder, recording each value's pointer."""
    if isinstance(value, dict | list):
        if isinstance(value, dict):
            members = sorted(value.items(), key=lambda kv: canonical.key_order(kv[0]))
            items: list[tuple[str | None, Any]] = list(members)
            open_, close = "{", "}"
        else:
            items = [(None, child) for child in value]
            open_, close = "[", "]"
        if not items:
            out.add(open_ + close, pointer)
            return
        out.add(open_, pointer)
        for position, (key, child) in enumerate(items):
            child_pointer = f"{pointer}/{_escape(key) if key is not None else position}"
            if position:
                out.add(",", pointer)
            out.add("\n")
            out.mark_indented()
            out.add(_INDENT * (level + 1))
            if key is not None:
                out.add(canonical.encode_scalar(key), child_pointer)
                out.add(": ", pointer)
            _json_parts(child, child_pointer, level + 1, out)
        out.add("\n")
        out.mark_indented()
        out.add(_INDENT * level)
        out.add(close, pointer)
        return
    out.add(canonical.encode_scalar(value), pointer)


# --- the frame -----------------------------------------------------------------------------------


@dataclass(frozen=True)
class Header:
    """Everything outside the call that a prompt shows, made by whoever renders the prompt.

    The gateway makes it for a call it holds: the client is its own authenticated client, and it
    names no pin. The vault makes it for a call it holds (M8 design B.3, E.5) and asks only out of
    band: the client is only what the gateway's marker reported (``client_reported``; with no
    marker it is shown as not reported and has no name), and the pin is from the vault's own
    sealed policy. ``asked_at`` decides whether the deadline needs its date.
    """

    ref: str
    client: str
    server: str
    tool: str
    deadline: datetime  # aware; shown as HH:MM UTC, dated when not on asked_at's UTC date
    _: KW_ONLY
    asked_at: datetime  # aware
    rendered_by: RenderedBy
    client_reported: bool
    pin: str | None
    approver: Approver

    def __post_init__(self) -> None:
        if self.deadline.tzinfo is None or self.asked_at.tzinfo is None:
            raise ValueError("the deadline and asked_at must be timezone-aware")
        if self.rendered_by == "gateway":
            if self.client_reported or self.pin is not None:
                raise ValueError("only the vault's frame reports a client or names a pin")
        else:
            if self.approver != "out_of_band":
                raise ValueError("the vault asks only out of band")
            if not self.client_reported and self.client:
                raise ValueError("a client the gateway didn't report has no name")
        if self.pin is not None and not _PIN.fullmatch(self.pin):
            raise ValueError("a pin is sha256: and 64 lowercase hex digits")


def _deadline(header: Header) -> str:
    """``HH:MM``, or ``YYYY-MM-DD HH:MM`` when its UTC date isn't the UTC date it was asked on."""
    deadline = header.deadline.astimezone(UTC)
    if deadline.date() == header.asked_at.astimezone(UTC).date():
        return deadline.strftime("%H:%M")
    return deadline.strftime("%Y-%m-%d %H:%M")


def _client(header: Header) -> str:
    if header.rendered_by == "gateway":
        return f"Client: {header.client}"
    if header.client_reported:
        return f"Client (reported by the gateway): {header.client}"
    return "Client (not reported)"


def _tool(header: Header) -> str:
    line = f"Tool: {header.server} {ARROW} {header.tool}"
    if header.pin is not None:
        line += f" (pin {_short_pin(header.pin)}, from the vault's policy)"
    return line


def _short_pin(pin: str) -> str:
    """``sha256:3f1c…e2``: the digest's first four and last two hex digits, as E.5 shows it."""
    digest = pin.removeprefix("sha256:")
    return f"sha256:{digest[:4]}{_ELLIPSIS}{digest[-2:]}"


def _open(header: Header, out: _Builder) -> None:
    out.add(f"{HEADER_PREFIX}{header.ref}\n")
    out.add(f"{_client(header)}\n")
    out.add(f"{_tool(header)}\n")
    out.add(f"Answer by {_deadline(header)} UTC. {INSTRUCTIONS[header.approver]}\n")
    out.add("\n")


def _close(header: Header, code: str | None, out: _Builder) -> None:
    out.newline()
    if code is not None:
        out.add(f"{CODE_LINE_PREFIX}{code}\n")
    out.add(f"{FOOTER_PREFIX}{header.ref}")


def render_call(header: Header, args: JSONValue, *, code: str | None = None) -> ApprovalText:
    """A remote tool call: its canonical arguments, as indented JSON (M4 design C.1)."""
    out = _Builder()
    _open(header, out)
    out.json(args, "")
    _close(header, code, out)
    return out.build()


def relayed(text: ApprovalText) -> ApprovalText:
    """A gateway-rendered prompt as the vault shows it out of band: :data:`RELAY_LINE` above it.

    The vault composes the line (M8 design E.5), so a gateway can't drop it or write another, and
    the digest every surface binds is the digest of this whole text. Check the gateway's text with
    :func:`problems` before composing: the composed text starts with a line the check refuses.
    """
    shift = len(RELAY_LINE) + 1
    return ApprovalText(
        f"{RELAY_LINE}\n{text.value}",
        frozenset(line + 1 for line in text.indented_lines),
        ((0, None), *((start + shift, pointer) for start, pointer in text.sources)),
    )


# --- toolkit plans -------------------------------------------------------------------------------


@dataclass(frozen=True)
class Show:
    """One item of a write's layout. Build it with :meth:`line`, :meth:`block`, :meth:`items`
    or :meth:`json`."""

    kind: Literal["line", "block", "items", "json"]
    pointer: str
    label: str | None = None
    fields: tuple[tuple[str, str], ...] = ()

    @classmethod
    def line(cls, label: str, pointer: str) -> Show:
        """``Label: value``. A string must be single-line; anything else is compact JSON."""
        return cls("line", pointer, _label(label))

    @classmethod
    def block(cls, pointer: str) -> Show:
        """A blank line, then a string as it is. At most one per write, and it comes last."""
        return cls("block", pointer)

    @classmethod
    def items(cls, label: str, pointer: str, fields: Sequence[tuple[str, str]]) -> Show:
        """``Label (n):``, then one numbered line per object of an array of flat objects."""
        checked = tuple((_label(name), _member(path)) for name, path in fields)
        if not checked:
            raise LayoutError("an items layout needs at least one field")
        if len({path for _, path in checked}) != len(checked):
            raise LayoutError("an items layout lists a field twice")
        return cls("items", pointer, _label(label), checked)

    @classmethod
    def json(cls, pointer: str) -> Show:
        """The member as indented JSON, key included. The default layout."""
        return cls("json", pointer)

    def __post_init__(self) -> None:
        _member(self.pointer)


def _label(label: str) -> str:
    if not LABEL.fullmatch(label):
        raise LayoutError("a label is 1-32 ASCII letters, digits, spaces, '_' or '-'")
    return label


def _member(pointer: str) -> str:
    """The top-level member a pointer names: ``/name``, with RFC 6901 escapes."""
    if not pointer.startswith("/") or "/" in pointer[1:]:
        raise LayoutError("a layout pointer names one top-level member, like /subject")
    token = pointer[1:]
    if re.search(r"~(?![01])", token):
        raise LayoutError("a layout pointer has a bad ~ escape")
    return token.replace("~1", "/").replace("~0", "~")


@dataclass(frozen=True, repr=False)
class Write:
    """One exact vault write. The body is frozen as canonical bytes when the write is built."""

    method: Method
    path: str
    body: bytes
    digest: str
    show: tuple[Show, ...]

    @classmethod
    def post(
        cls, path: str, body: Mapping[str, JSONValue], *, show: Iterable[Show] | None = None
    ) -> Write:
        return cls._build("POST", path, body, show)

    @classmethod
    def put(
        cls, path: str, body: Mapping[str, JSONValue], *, show: Iterable[Show] | None = None
    ) -> Write:
        return cls._build("PUT", path, body, show)

    @classmethod
    def patch(
        cls, path: str, body: Mapping[str, JSONValue], *, show: Iterable[Show] | None = None
    ) -> Write:
        return cls._build("PATCH", path, body, show)

    @classmethod
    def _build(
        cls, method: Method, path: str, body: Mapping[str, JSONValue], show: Iterable[Show] | None
    ) -> Write:
        if not isinstance(body, Mapping):
            raise LayoutError("a write's body is a JSON object")
        if not path.startswith("/"):
            raise LayoutError("a write's path starts with /")
        value = dict(body)
        frozen = canonical.dumps_canonical(value)
        layout = (
            tuple(show)
            if show is not None
            else tuple(
                Show.json("/" + _escape(key)) for key in sorted(value, key=canonical.key_order)
            )
        )
        _check_coverage(canonical.loads_strict(frozen, max_bytes=len(frozen) + 1), layout)
        return cls(method, path, frozen, canonical.digest(value), layout)

    @property
    def data(self) -> dict[str, JSONValue]:
        """A fresh copy of the frozen body."""
        value: dict[str, JSONValue] = canonical.loads_strict(
            self.body, max_bytes=len(self.body) + 1
        )
        return value

    def __repr__(self) -> str:
        return f"Write({self.method} <{len(self.body)} bytes>)"


refuse_type(Write)


def _check_coverage(body: dict[str, JSONValue], layout: tuple[Show, ...]) -> None:
    covered: list[str] = []
    for index, show in enumerate(layout):
        member = _member(show.pointer)
        if member not in body:
            raise LayoutError("a layout item points at nothing")
        covered.append(member)
        value = body[member]
        if show.kind == "line" and isinstance(value, str) and "\n" in value:
            raise LayoutError("a line layout holds a multi-line string")
        if show.kind == "block":
            if not isinstance(value, str):
                raise LayoutError("a block layout holds a string")
            if index != len(layout) - 1:
                raise LayoutError("a block layout comes last")
        if show.kind == "items":
            _check_items(value, show)
    if len(set(covered)) != len(covered):
        raise LayoutError("a member is shown twice")
    if set(covered) != set(body):
        raise LayoutError("a member of the write isn't shown")


def _check_items(value: JSONValue, show: Show) -> None:
    if not isinstance(value, list):
        raise LayoutError("an items layout holds an array")
    listed = {path for _, path in show.fields}
    for item in value:
        if not isinstance(item, dict):
            raise LayoutError("an items layout holds an array of objects")
        if not set(item) <= listed:
            raise LayoutError("an items layout leaves out a field of an item")
        if any(isinstance(v, dict | list) for v in item.values()):
            raise LayoutError("an items layout holds flat objects only")


@dataclass(frozen=True, repr=False)
class Plan:
    """A title and the exact writes an accepted call may send, each at most once."""

    title: str
    writes: tuple[Write, ...] = field(default=())

    def __init__(self, title: str, writes: Iterable[Write]) -> None:
        object.__setattr__(self, "title", title)
        object.__setattr__(self, "writes", tuple(writes))
        if find_violations(title, max_chars=MAX_TITLE_CHARS, min_chars=1, single_line=True):
            raise LayoutError(f"a plan title is one line of 1-{MAX_TITLE_CHARS} plain characters")
        if not all(isinstance(w, Write) for w in self.writes):
            raise LayoutError("a plan holds Write objects")

    def __repr__(self) -> str:
        return f"Plan(<{len(self.writes)} writes>)"


refuse_type(Plan)


def render_plan(header: Header, plan: Plan, *, code: str | None = None) -> ApprovalText:
    """A toolkit call: the plan's title, then each write under its layout (M4 design C.2)."""
    out = _Builder()
    _open(header, out)
    out.add(plan.title + "\n")
    many = len(plan.writes) > 1
    for number, write in enumerate(plan.writes, start=1):
        if many:
            if number > 1:
                out.newline()
            out.add(f"\nRequest {number} of {len(plan.writes)}\n")
        _render_write(write, out)
    _close(header, code, out)
    return out.build()


def _render_write(write: Write, out: _Builder) -> None:
    body = write.data
    for position, show in enumerate(write.show):
        member = _member(show.pointer)
        value = body[member]
        pointer = "/" + _escape(member)
        if position:
            out.newline()
        if show.kind == "line":
            out.add(f"{show.label}: ")
            if isinstance(value, str):
                out.add(value, pointer)
            else:
                out.add(canonical.dumps_canonical(value).decode(), pointer)
        elif show.kind == "block":
            out.add("\n")
            out.add(value, pointer)
        elif show.kind == "items":
            out.add(f"{show.label} ({len(value)}):")
            for index, item in enumerate(value, start=1):
                out.add(f"\n {index}.")
                first = True
                for name, path in show.fields:
                    if path not in item:
                        continue
                    out.add(" " if first else ", ")
                    first = False
                    out.add(f"{name}: ")
                    out.add(
                        canonical.encode_scalar(item[path]),
                        f"{pointer}/{index - 1}/{_escape(path)}",
                    )
        else:
            out.json({member: value}, "")


# --- the check -----------------------------------------------------------------------------------


@dataclass(frozen=True)
class Problem:
    """Why a text was refused: a rule, where (a JSON pointer, or None for the whole text or the
    frame), and a reason that never holds the value."""

    rule: Literal["text_rules", "over_budget", "markup", "wide_space", "combining", "frame"]
    pointer: str | None
    reason: str


_FENCE = re.compile(r"`{3,}|~{3,}")
_HTML = re.compile(r"<!--|<![A-Za-z]|<\?|</[A-Za-z]|<[A-Za-z][A-Za-z0-9-]*[\s/>]")
_LINK = re.compile(r"\]\(")
_SPACE_RUN = re.compile(r"[ \t]+")


def problems(text: ApprovalText, *, budget: int, renders: Renders) -> list[Problem]:
    """Every reason ``text`` can't be shown, in text order; empty if it may be asked.

    R42's rules and the budget hold for every client. The Markdown rules (code fences, HTML,
    links) apply only to a client whose ``renders`` is ``markdown``; wide whitespace and stacked
    combining marks hide text in any display.
    """
    value = text.value
    found: list[tuple[int, Problem]] = []
    if len(value) > budget:
        found.append(
            (
                -1,
                Problem(
                    "over_budget",
                    None,
                    f"the approval text is {len(value)} characters, over the limit of {budget}",
                ),
            )
        )
    for violation in find_violations(value, max_chars=len(value), allow_tabs=True):
        found.append(
            (
                violation.index,
                Problem("text_rules", text.pointer_at(violation.index), str(violation)),
            )
        )
    if renders == "markdown":
        for pattern, reason in (
            (_FENCE, "a code fence"),
            (_HTML, "an HTML comment or tag"),
            (_LINK, "a Markdown link"),
        ):
            for match in pattern.finditer(value):
                found.append(
                    (match.start(), Problem("markup", text.pointer_at(match.start()), reason))
                )
    found.extend(_wide_space(text))
    found.extend(_combining(text))
    found.extend(_frame_imitations(text))
    found.sort(key=lambda item: item[0])
    return [problem for _, problem in found]


def _wide_space(text: ApprovalText) -> list[tuple[int, Problem]]:
    found = []
    offset = 0
    for number, line in enumerate(text.value.split("\n")):
        for match in _SPACE_RUN.finditer(line):
            if match.start() == 0 and number in text.indented_lines:
                continue  # the renderer's own JSON indentation
            run = match.group()
            columns = sum(_MAX_COLUMNS if char == "\t" else 1 for char in run)
            if columns > _MAX_COLUMNS:
                index = offset + match.start()
                found.append(
                    (
                        index,
                        Problem(
                            "wide_space",
                            text.pointer_at(index),
                            f"a run of whitespace {columns} columns wide (limit {_MAX_COLUMNS})",
                        ),
                    )
                )
        offset += len(line) + 1
    return found


def _combining(text: ApprovalText) -> list[tuple[int, Problem]]:
    found = []
    run = 0
    for index, char in enumerate(text.value):
        if unicodedata.category(char) in ("Mn", "Me"):
            run += 1
            if run == _MAX_COMBINING + 1:
                start = index - _MAX_COMBINING
                found.append(
                    (
                        start,
                        Problem(
                            "combining",
                            text.pointer_at(start),
                            f"more than {_MAX_COMBINING} combining marks in a row",
                        ),
                    )
                )
        else:
            run = 0
    return found


def _frame_imitations(text: ApprovalText) -> list[tuple[int, Problem]]:
    """A line inside the call that starts like the frame's first or last line could make a
    reader think one prompt ended and another began; the ref already makes it detectable.

    No line may start like the vault's relay line, the first included, even after leading
    whitespace: in a relayed text it could pass the gateway's words off as the vault's (M8 design
    E.5, Z12)."""
    found = []
    lines = text.value.split("\n")
    offset = 0
    for number, line in enumerate(lines):
        reason = None
        # Indented too: a line the whitespace rule lets through still reads as the vault's.
        if line.lstrip(" \t").startswith(RELAY_PREFIX):
            reason = "a line imitating the relay line"
        elif 0 < number < len(lines) - 1 and line.startswith((HEADER_PREFIX, FOOTER_PREFIX)):
            reason = "a line imitating the frame"
        if reason is not None:
            found.append((offset, Problem("frame", text.pointer_at(offset), reason)))
        offset += len(line) + 1
    return found


def describe(problem: Problem) -> str:
    """The agent's refusal text for one problem (M4 design B.2 step 5.7)."""
    if problem.rule == "over_budget":
        return f"refused: {problem.reason}; it is never cut"
    where = problem.pointer if problem.pointer is not None else "the prompt frame"
    if where == "":
        where = "the arguments"
    return f"refused: the approval text breaks the plain-text rules at {where}: {problem.reason}"
