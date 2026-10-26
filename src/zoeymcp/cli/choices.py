"""The choices file of ``zoeymcp review <server> --choose`` and ``--choices`` (M7 design F.5; GR-2).
Pure.

A hundred tools don't fit on a command line, so ``--choose`` writes one line per tool the server
lists, ``git rebase -i`` style, and ``--choices FILE`` reads the edited file back into the same
change the options make, which the emitter writes as fragment 2 (E.4):

    # zoeymcp review notes: 96 tools. Keep "skip", or write "allow", "approve" or "decline", ...
    # report 3f9c... sha256:aa41... policy sha256:5e07...
    allow    list_notes   sha256:6c1e...   # read-only (the server's suggestion)
    skip     delete_note  sha256:0b7d...   # not annotated: approve suggested if you include it

- The header names the report: the vault's job ID (``-`` for a review over the gateway's own
  socket), the digest of the report as the CLI read it, and the digest of the server's tools in
  the policy. Each line carries the tool's full pin (TI-6, OPS-21), so ``--choices`` emits
  exactly the pins in the file, and only after checking them against the report it reads then:
  the same report, or a newer listing, in which case a tool whose pin changed refuses
  ``choices_stale`` naming every such tool. A file written while the policy included other tools
  refuses ``choices_stale`` too: its ``skip`` lines would take out, and its ``allow`` lines put
  back, what the operator has changed since.
- Without ``--suggest`` every tool not yet included says ``skip``; with it, a tool the shared rule
  suggests ``allow`` for (read-only and not destructive) says ``allow``, and every other line stays
  ``skip`` with its suggestion in the comment, so an unedited file never includes an unannotated
  or destructive tool (OPS-12, PC-2). A tool the policy already includes says its classification,
  so an unedited file changes nothing; ``skip`` on it takes it out.
- ``decline`` leaves a tool out and records it under the server's ``declined`` at the line's pin
  (M6 design J.3, J.5), so ``review`` stays quiet about it until its definition changes; on an
  included tool it takes it out too. A tool the policy declined at the pin listed says
  ``decline``, so again an unedited file changes nothing, and ``skip`` on it takes it out of
  ``declined``.
- A tool with an error finding has no line, only a comment: it can't be pinned (design 7.5). An
  included tool whose listing isn't the one its pin holds (drifted, missing, invalid) has no line
  either and stays as the policy has it; ``review <server> --repin`` is how a drifted one's pin
  changes.
- Every comment's upstream text goes through :func:`.review.untrusted`, which escapes line breaks
  and tabs, so a description can't start a line of its own (TI-12); a tool name can't break the
  format (``TOOL_NAME``). Anything else, an unknown word, an unknown or repeated tool, a missing
  or malformed pin, an ``allow`` or ``approve`` line for a tool that can't be pinned, refuses
  ``choices_invalid`` naming the line. Both reasons are the CLI's own, outside
  ``portal/refusals.py`` (PC-22).
- The file never assigns clients (GR-D2): fragment 2 leaves that to the operator (E.4).
- A server that enables prompts or resources (M6 design L.7) has a ``prompt:`` line per prompt
  and a ``resource:`` line per resource template and fixed resource after its tools, each with
  ``skip``, ``include`` or ``decline``, its name or URI and its pin, by the same rules: a prompt
  or a resource is never classified. A ``resource:`` line's pin says which of the two it is,
  since one URI can name both. The policy digest covers the server's ``prompts`` and
  ``resources`` blocks too.

    resource: include  notes://notes/{id}  sha256:3d1a...   # resource template, in the policy
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final, Literal, cast, get_args

from ..common.policy.reviewchange import (
    MATCHING_STATES,
    NOUNS,
    PIN,
    TOOL_NAME,
    Added,
    Changes,
    Classification,
    KindChanges,
    block_of,
    declined_block,
    enabled,
    is_key,
    kind_blocks,
    kind_of,
    listed,
    pinnable,
    suggested,
    suggested_words,
)
from .review import untrusted

Word = Literal["skip", "allow", "approve", "decline"]
# A prompt's or a resource's words: it is included or not, never classified (M6 design L.7).
KindWord = Literal["skip", "include", "decline"]
Reason = Literal["choices_invalid", "choices_stale"]
WORDS: Final = get_args(Word)
KIND_WORDS: Final = get_args(KindWord)
# What starts a prompt's or a resource's line, and the kinds each may name.
PREFIXES: Final = {"prompt": "prompt:", "resource_template": "resource:", "resource": "resource:"}
_LINE_KINDS: Final = {"prompt:": ("prompt",), "resource:": ("resource_template", "resource")}
# The job ID of a review that ran over the gateway's own socket, which keeps no job.
NO_JOB: Final = "-"
# How much of a comment's upstream text is shown (F.5).
COMMENT_CHARS: Final = 100
# A file larger than this isn't read: 10,000 tools of lines and comments fit well within it.
FILE_MAX: Final = 16 * 2**20
_JOB = re.compile(r"[A-Za-z0-9_-]{1,64}")
_HEAD = re.compile(r"# zoeymcp review (?P<server>[a-z0-9][a-z0-9_-]{0,62}): .*")
_REPORT = re.compile(
    r"# report (?P<job>\S+) (?P<digest>sha256:[0-9a-f]{64}) policy (?P<policy>sha256:[0-9a-f]{64})"
)


class ChoicesRefused(ValueError):
    """A choices file ``--choices`` won't take: ``choices_invalid`` (the file is wrong) or
    ``choices_stale`` (``tools`` changed since ``--choose`` wrote it)."""

    def __init__(self, reason: Reason, message: str, tools: tuple[str, ...] = ()) -> None:
        self.reason: Reason = reason
        self.tools = tools
        super().__init__(message)


def _invalid(number: int, message: str) -> ChoicesRefused:
    return ChoicesRefused("choices_invalid", f"line {number}: {message}")


def report_digest(report: Mapping[str, Any]) -> str:
    """``sha256:<hex>`` of the report as the CLI read it, keys sorted, every character escaped."""
    text = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return "sha256:" + hashlib.sha256(text.encode("ascii")).hexdigest()


def policy_digest(report: Mapping[str, Any]) -> str:
    """The digest of the server's tools in the policy the report was made against: its
    ``include``, ``allow`` and ``approve``, each sorted, and its ``declined`` once it has one
    (so a file written before a decline can't undo it, and an M7 file's digest stays)."""
    policy = report["policy"]
    tools: dict[str, Any] = {kind: sorted(policy[kind]) for kind in ("include", "allow", "approve")}
    if policy.get("declined"):
        tools["declined"] = dict(policy["declined"])
    for block in kind_blocks(report):  # a server enabling prompts or resources (L.7)
        tools[block] = policy[block]
    return report_digest(tools)


def _lined(entry: Mapping[str, Any]) -> bool:
    """An entry the file has a line for: a pinnable one not yet included, or an included one
    the server lists as its pin holds it, a tool with a classification to show."""
    if not pinnable(entry):
        return False
    if not entry["included"]:
        return True
    classified = kind_of(entry) != "tool" or entry["classification"] in ("allow", "approve")
    return entry["state"] in MATCHING_STATES and classified


# --- writing the file ----------------------------------------------------------------------------


def render(report: Mapping[str, Any], job: str, *, suggest: bool) -> list[str]:
    """The choices file for ``report``, the review job ``job`` answered (:data:`NO_JOB` for
    none)."""
    server = report["server"]
    tools = listed(report)
    count = f"{len(tools)} tool{'' if len(tools) == 1 else 's'}"
    lines = [
        f'# zoeymcp review {server}: {count}. Keep "skip", or write "allow", "approve" or '
        '"decline", on each line.',
        f"# report {job} {report_digest(report)} policy {policy_digest(report)}",
        "# allow: agents call it with no prompt. approve: every call asks you first.",
        "# The suggestions are the server's own annotations, not a judgement by ZoeyMCP.",
    ]
    rows = [entry for entry in tools.values() if _lined(entry)]
    width = max((len(entry["name"]) for entry in rows), default=0)
    for name, entry in tools.items():
        if _lined(entry):
            word = _word(entry, suggest=suggest)
            lines.append(f"{word:<8} {name:<{width}}  {entry['pin']}   # {_comment(entry)}")
        elif entry["included"]:
            lines.append(f"# {_stays(server, entry)}")
        else:
            lines.append(_unpinnable(server, entry))
    return lines + _kind_lines(report)


def _kind_lines(report: Mapping[str, Any]) -> list[str]:
    """The file's lines for the server's prompts and resources (L.7), after its tools."""
    kinds = enabled(report)
    if not kinds:
        return []
    server = report["server"]
    lines = ['# prompt: and resource: lines: keep "skip", or write "include" or "decline".']
    entries = [entry for kind in kinds for entry in listed(report, kind).values()]
    width = max((len(entry["name"]) for entry in entries if _lined(entry)), default=0)
    for entry in entries:
        name, noun = entry["name"], NOUNS[kind_of(entry)]
        if _lined(entry):
            word = "include" if entry["included"] else "skip"
            word = "decline" if entry["state"] == "declined" else word
            words = noun + (", in the policy" if entry["included"] else "")
            words += ", declined in the policy" if entry["state"] == "declined" else ""
            lines.append(
                f"{PREFIXES[kind_of(entry)]:<9} {word:<8} {name:<{width}}  {entry['pin']}   "
                f"# {words}{_finding(entry)}"
            )
        elif entry["included"]:
            lines.append(f"# {noun} {_stays(server, entry)}")
        else:
            lines.append(f"# {noun} {_unpinnable(server, entry)[2:]}")
    return lines


def _word(entry: Mapping[str, Any], *, suggest: bool) -> Word:
    if entry["included"]:
        classification: Word = entry["classification"]
        return classification
    if entry["state"] == "declined":
        return "decline"
    if suggest and not entry.get("consequential") and suggested(entry) == "allow":
        return "allow"
    return "skip"


def _comment(entry: Mapping[str, Any]) -> str:
    words = suggested_words(entry)
    if entry["included"]:
        words = f"in the policy as {entry['classification']}; {words}"
    elif entry["state"] == "declined":
        words = f"declined in the policy; {words}"
    return words + _finding(entry)


def _finding(entry: Mapping[str, Any]) -> str:
    """An entry's first finding, and how many more, for its line's comment."""
    findings = [
        finding
        for finding in entry["findings"]
        if not (finding["pointer"] == "/annotations" and finding["message"].startswith("suggested"))
    ]
    if not findings:
        return ""
    words = f"; finding: {untrusted(findings[0]['message'], COMMENT_CHARS)}"
    if len(findings) > 1:
        words += f" (and {len(findings) - 1} more)"
    return words


def _stays(server: str, entry: Mapping[str, Any]) -> str:
    """Why an included tool has no line: only a drifted one, still pinnable, can be repinned."""
    name, state = untrusted(entry["name"], 128), entry["state"]
    said = f"{name} stays as the policy has it ({state}); review {server} shows why"
    if state == "drift" and pinnable(entry) and kind_of(entry) != "tool":
        return f"{said}, and the portal's review screen takes a new pin"
    if state == "drift" and pinnable(entry):
        return f"{said}, and review {server} --repin {name} takes a new pin"
    if not pinnable(entry):
        return f"{said}; it can't be pinned"
    return said


def _unpinnable(server: str, entry: Mapping[str, Any]) -> str:
    name = untrusted(entry["name"], 128)
    errors = [finding for finding in entry["findings"] if finding["level"] == "error"]
    if not errors:  # a name or a pin the policy can't hold
        return f"# {name} can't be included: it can't be pinned; review {server} --show {name}"
    why = untrusted(errors[0]["message"], COMMENT_CHARS)
    return f"# {name} can't be included: error finding ({why}); review {server} --show {name}"


# --- reading it back -----------------------------------------------------------------------------


@dataclass(frozen=True)
class Line:
    """One tool's choice, on line ``number`` of the file; or a prompt's or a resource's, by
    ``kind``, the line's prefix (``prompt:`` or ``resource:``)."""

    number: int
    word: Word | KindWord
    tool: str
    pin: str
    kind: str = "tool"


@dataclass(frozen=True)
class Parsed:
    """A choices file, read: the server, report and policy its header names, and its tools'
    lines."""

    server: str
    job: str
    digest: str
    policy: str
    lines: tuple[Line, ...]


def parse(text: str) -> Parsed:
    """Read a choices file. Raises :class:`ChoicesRefused` (``choices_invalid``)."""
    if len(text) > FILE_MAX:
        raise ChoicesRefused("choices_invalid", f"the file is over {FILE_MAX // 2**20} MiB")
    server: str | None = None
    report: tuple[str, str, str] | None = None
    lines: list[Line] = []
    seen: dict[str, int] = {}
    text = text.removeprefix("\ufeff")  # a byte order mark, as Windows editors save one
    for number, raw in enumerate(text.split("\n"), start=1):
        line = raw.strip()  # a CRLF file's too
        if line.startswith("#"):
            head = _HEAD.fullmatch(line)
            if head is not None and server is None:
                server = head["server"]
            found = _REPORT.fullmatch(line)
            if found is not None:
                if report is not None:
                    raise _invalid(number, "a second report line")
                if not _JOB.fullmatch(found["job"]):  # NO_JOB matches too
                    raise _invalid(number, "the report line's job isn't a job ID")
                report = (found["job"], found["digest"], found["policy"])
            continue
        if not line:
            continue
        lines.append(_line(number, line, seen))
    if server is None or report is None:
        raise ChoicesRefused(
            "choices_invalid",
            "the file has no zoeymcp review header and report line; write it with review "
            "<server> --choose",
        )
    return Parsed(server, *report, tuple(lines))


def _line(number: int, line: str, seen: dict[str, int]) -> Line:
    parts = line.split("#", 1)[0].split()
    if parts and parts[0] in _LINE_KINDS:
        return _kind_line(number, parts, seen)
    if len(parts) != 3:
        raise _invalid(number, "write a word, the tool's name and its pin")
    word, tool, pin = parts
    if word not in WORDS:
        raise _invalid(number, f'"{untrusted(word, 20)}" isn\'t skip, allow, approve or decline')
    if not TOOL_NAME.fullmatch(tool):
        raise _invalid(number, f"{untrusted(tool, 128)} isn't a tool name")
    if tool in seen:
        raise _invalid(number, f"{tool} is on line {seen[tool]} too")
    if not PIN.fullmatch(pin):
        raise _invalid(number, f"{tool}'s pin isn't sha256: and 64 hex digits")
    seen[tool] = number
    return Line(number, cast(Word, word), tool, pin)


def _kind_line(number: int, parts: list[str], seen: dict[str, int]) -> Line:
    """A ``prompt:`` or ``resource:`` line (L.7): its word, its name or URI and its pin."""
    prefix, rest = parts[0], parts[1:]
    if len(rest) != 3:
        raise _invalid(number, f"after {prefix} write a word, its name or URI and its pin")
    word, name, pin = rest
    if word not in KIND_WORDS:
        raise _invalid(number, f'"{untrusted(word, 20)}" isn\'t skip, include or decline')
    if not any(is_key(kind, name) for kind in _LINE_KINDS[prefix]):
        noun = "prompt name" if prefix == "prompt:" else "resource template or URI"
        raise _invalid(number, f"{untrusted(name, 128)} isn't a {noun}")
    # One URI can be a template and a fixed resource, each with a line: its pin tells them apart.
    key = f"{prefix} {name}" + (f" {pin}" if prefix == "resource:" else "")
    if key in seen:
        raise _invalid(number, f"{key} is on line {seen[key]} too")
    if not PIN.fullmatch(pin):
        raise _invalid(number, f"{name}'s pin isn't sha256: and 64 hex digits")
    seen[key] = number
    return Line(number, cast(KindWord, word), name, pin, prefix[:-1])


def decide(report: Mapping[str, Any], job: str, parsed: Parsed) -> Changes:
    """The changes ``parsed`` asks of ``report``'s server, the review job ``job`` answered: a
    line for a tool not yet included includes it, ``skip`` on an included one takes it out,
    another word on one classifies it anew, ``decline`` records the tool declined at its pin
    (taking it out if included), ``skip`` on a declined one takes it out of ``declined``, and a
    tool with no line stays as it is. Raises :class:`ChoicesRefused`."""
    server = report["server"]
    if parsed.server != server:
        raise ChoicesRefused(
            "choices_invalid", f"the file is for {parsed.server}, and this review is of {server}"
        )
    if parsed.policy != policy_digest(report):
        # skip would take out a tool included since, and allow put back one taken out since.
        raise ChoicesRefused(
            "choices_stale",
            f"the policy's tools for {server} changed since review --choose wrote the file; "
            f"write it again (review {server} --choose)",
        )
    # The report the file was written from: then a pin that differs is an edit, not a change.
    same = (parsed.job, parsed.digest) == (job, report_digest(report))
    tools = listed(report)
    added: dict[str, Added] = {}
    dropped: set[str] = set()
    moved: dict[str, Classification] = {}
    declines: dict[str, str] = {}
    undeclined: list[str] = []
    stale: list[str] = []
    for line in (line for line in parsed.lines if line.kind == "tool"):
        entry = tools.get(line.tool)
        if entry is None or entry["pin"] != line.pin:
            if same:
                raise _invalid(line.number, _unlisted(line.tool, entry))
            if line.word != "skip":
                stale.append(line.tool)
            elif entry is not None and entry["included"]:
                dropped.add(line.tool)  # taking a tool out needs no pin
            continue
        if line.word == "skip":
            if entry["included"]:
                dropped.add(line.tool)
            elif entry["state"] == "declined":
                undeclined.append(line.tool)
            continue
        if entry["included"] and not _lined(entry):
            raise _invalid(line.number, _stays(server, entry))
        if not _lined(entry):
            raise _invalid(line.number, f"{line.tool} has an error finding, so it can't be pinned")
        if line.word == "decline":
            declines[line.tool] = line.pin
            if entry["included"]:
                dropped.add(line.tool)
            continue
        if line.word == "allow" and entry.get("consequential"):
            raise _invalid(
                line.number,
                f"the toolkit declares {line.tool} consequential, so it can't be in allow",
            )
        chosen: Classification = "allow" if line.word == "allow" else "approve"
        if not entry["included"]:
            added[line.tool] = Added(chosen, f"{chosen}, from the choices file")
        elif chosen != entry["classification"]:
            moved[line.tool] = chosen
    kinds = _kinds(report, same, [line for line in parsed.lines if line.kind != "tool"], stale)
    if stale:
        names = sorted(stale)
        raise ChoicesRefused(
            "choices_stale",
            f"changed since review --choose wrote the file: {', '.join(names)}; read each again "
            f"(review {server} --show TOOL), then write the file again",
            tuple(names),
        )
    declined = declined_block(report, declines, undeclined=undeclined, included=tuple(added))
    return Changes(
        added=added, dropped=frozenset(dropped), moved=moved, declined=declined, kinds=kinds
    )


def _kinds(
    report: Mapping[str, Any], same: bool, lines: list[Line], stale: list[str]
) -> dict[str, KindChanges]:
    """What the ``prompt:`` and ``resource:`` lines ask of each kind the server enables (L.7),
    by :func:`decide`'s rules; a changed entry's name joins ``stale``."""
    server = report["server"]
    added: dict[str, list[str]] = {kind: [] for kind in enabled(report)}
    dropped: dict[str, set[str]] = {kind: set() for kind in added}
    declines: dict[str, dict[str, str]] = {kind: {} for kind in added}
    undeclined: dict[str, list[str]] = {kind: [] for kind in added}
    for line in lines:
        kind, entry = _kind_entry(report, line)
        if kind not in added or entry is None or entry["pin"] != line.pin:
            if same:
                raise _invalid(line.number, _unlisted(line.tool, entry, line.kind))
            if line.word != "skip":
                stale.append(line.tool)
            elif entry is not None and entry["included"]:
                dropped[kind].add(line.tool)
            continue
        if line.word == "skip":
            if entry["included"]:
                dropped[kind].add(line.tool)
            elif entry["state"] == "declined":
                undeclined[kind].append(line.tool)
            continue
        if entry["included"] and not _lined(entry):
            raise _invalid(line.number, _stays(server, entry))
        if not _lined(entry):
            raise _invalid(line.number, f"{line.tool} has an error finding, so it can't be pinned")
        if line.word == "decline":
            declines[kind][line.tool] = line.pin
            if entry["included"]:
                dropped[kind].add(line.tool)
        elif not entry["included"]:
            added[kind].append(line.tool)
    found = {}
    for kind, new in added.items():
        held: list[str] = block_of(report, kind)["include"]
        include = (*(name for name in held if name not in dropped[kind]), *new)
        declined = declined_block(
            report, declines[kind], undeclined=undeclined[kind], included=new, kind=kind
        )
        found[kind] = KindChanges(include, declined=declined)
    return found


def _kind_entry(report: Mapping[str, Any], line: Line) -> tuple[str, Mapping[str, Any] | None]:
    """The kind and the listed entry a ``prompt:`` or ``resource:`` line names: for a URI the
    server lists as a template and as a fixed resource, the one at the line's pin."""
    kinds = _LINE_KINDS[f"{line.kind}:"]
    found = [(kind, listed(report, kind).get(line.tool)) for kind in kinds]
    named = [(kind, entry) for kind, entry in found if entry is not None]
    for kind, entry in named:
        if entry["pin"] == line.pin:
            return kind, entry
    return named[0] if len(named) == 1 else (kinds[0], None)


def _unlisted(tool: str, entry: Mapping[str, Any] | None, kind: str = "tool") -> str:
    if entry is None:
        return f"the server lists no {kind} {tool}"
    return f"{tool}'s pin isn't the one the server lists"
