"""``zoeymcp review`` and ``zoeymcp gateway-status``: rendering the gateway's answers (M3 design I).

The gateway does the work: it lists the server on a fresh connection and evaluates it. This
module only prints, so it needs no SDK and runs in either environment.

Everything the upstream wrote is untrusted, and a terminal acts on control characters, so every
line goes through :func:`untrusted`, which shows each hidden character as ``[U+XXXX]`` and line
breaks as ``\\n``: an upstream's text can't move the cursor, hide itself, or fake a line of
output (a fake YAML snippet, for one). JSON output escapes everything outside ASCII.

The YAML snippet is for declarative mode, and the emitter writes it (M7 design H, DD-13): a
fragment whose header says it replaces the server's ``tools`` and ``review`` whole, which
``check --with`` merges as an operator does. By default it refreshes ``era`` and keeps every pin,
so a drifted tool stays hidden. ``--repin TOOL`` takes a drifted tool's new pin. ``--allow TOOL``
and ``--approve TOOL`` include a tool and classify it; ``--allow-read-only`` allows every tool
the server marks read-only and not destructive (the shared rule, CR-3), and nothing includes an
unannotated tool in bulk (PC-2). ``--add TOOL`` includes a tool, leaving its classification to the
operator: ``check`` fails until it is in ``allow`` or ``approve`` (nothing is implied). No pin
line is ever written for a tool with an error finding. The snippet's comments are the emitter's
fixed kinds, so no upstream text reaches it.

For a toolkit server (M4 design H.6), ``--add TOOL`` puts a tool its code declares consequential
into ``approve`` ("declared by the toolkit") and leaves a routine one to the operator, as for a
remote tool. With ``pinning: off`` the snippet has no pins, and every definition is printed, so an
image change can be read before or after it is deployed.

``--via`` says where the review runs (M7 design F.5): ``gateway`` over the gateway's admin socket,
or ``vault`` over the vault's, which queues a review job that the gateway's poller runs and
reports (F.2), so the vault's container reviews too; ``auto`` (the default) takes the gateway's
socket when the container has it. Through the vault the CLI's finished review of the server at
the current policy view is read again, so one report serves several runs, unless ``--fresh``
(OPS-11). Either way the answer is the gateway's review, printed alike.
"""

from __future__ import annotations

import json
import math
import os
import re
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import Any, Final, Literal, TextIO

from ..common.policy.change import Comment, PolicyChange, SetServerReview
from ..common.policy.emit import emit
from ..common.policy.schema import Tools
from ..common.suggest import Suggestion, suggestion
from ..common.textrules import reveal_hidden
from . import admin_client

EXIT_CLEAN = 0
EXIT_NEEDS_OPERATOR = 1
EXIT_COULD_NOT_RUN = 2

TOOL_NAME = re.compile(r"[A-Za-z0-9_.-]{1,128}")
PIN = re.compile(r"sha256:[0-9a-f]{64}")
MAX_SHOWN_CHARS = 2000
STATE_LABELS = {
    "ok": "ok",
    "marked": "MARKED",
    "blocked": "BLOCKED",
    "drift": "DRIFT",
    "unreviewed": "unreviewed",
    "invalid": "INVALID",
    "duplicate": "DUPLICATE",
    "missing": "MISSING",
}


class UsageError(ValueError):
    """An option that doesn't fit what the review found."""


def untrusted(text: object, limit: int = MAX_SHOWN_CHARS) -> str:
    """``text`` safe to print on one line: hidden characters and line breaks made visible."""
    value = str(text)
    if len(value) > limit:
        value = value[:limit] + "..."
    return reveal_hidden(value).replace("\n", "\\n").replace("\t", "\\t")


def short_pin(pin: str | None) -> str:
    return "(no pin)" if pin is None else pin[: len("sha256:") + 12] + "..."


def pinnable(entry: Mapping[str, Any]) -> bool:
    """A pin line may be written: a valid name and pin, and no error finding."""
    pin = entry.get("pin")
    return (
        isinstance(pin, str)
        and PIN.fullmatch(pin) is not None
        and TOOL_NAME.fullmatch(entry["name"]) is not None
        and not any(finding["level"] == "error" for finding in entry["findings"])
    )


@dataclass(frozen=True)
class Choices:
    tools: frozenset[str] = frozenset()  # show only these (empty: all)
    show: frozenset[str] = frozenset()  # print these definitions in full
    show_all: bool = False
    add: tuple[str, ...] = ()
    repin: frozenset[str] = field(default_factory=frozenset)
    allow: tuple[str, ...] = ()
    approve: tuple[str, ...] = ()
    allow_read_only: bool = False


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


def check_choices(review: dict[str, Any], choices: Choices) -> None:
    """Refuse an ``--add``, ``--allow``, ``--approve`` or ``--repin`` that the review doesn't
    allow."""
    by_name = {entry["name"]: entry for entry in review["tools"]}
    named = [*choices.add, *choices.allow, *choices.approve]
    twice = sorted({name for name in named if named.count(name) > 1})
    if twice:
        raise UsageError(f"{', '.join(twice)}: name it in one of --add, --allow and --approve")
    for option, names in (
        ("--add", choices.add),
        ("--allow", choices.allow),
        ("--approve", choices.approve),
    ):
        for name in names:
            _check_new(option, name, by_name.get(name))
    for name in choices.allow:
        if by_name[name].get("consequential"):
            raise UsageError(
                f"--allow {name}: the toolkit declares it consequential, so it can't be in allow"
            )
    for name in sorted(choices.repin):
        entry = by_name.get(name)
        if entry is None or entry["state"] != "drift":
            raise UsageError(f"--repin {name}: it hasn't drifted")
        if not pinnable(entry):
            raise UsageError(f"--repin {name}: it has error findings, so it can't be pinned")
    unknown = sorted((choices.tools | choices.show) - set(by_name))
    if unknown:
        raise UsageError(f"the server lists no tool named {', '.join(unknown)}")


def _check_new(option: str, name: str, entry: Mapping[str, Any] | None) -> None:
    if entry is None or entry["state"] == "missing":
        raise UsageError(f"{option} {name}: the server doesn't list it")
    if entry["included"]:
        raise UsageError(f"{option} {name}: it is already included")
    if not pinnable(entry):
        raise UsageError(f"{option} {name}: it has error findings, so it can't be pinned")


# --- the YAML snippet (M7 design F.5, H; DD-13) -------------------------------------------------

Classification = Literal["allow", "approve"]
# An included tool in these states is listed as its pin holds it.
MATCHING_STATES: Final = ("ok", "marked", "blocked")


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
    ones, drifted, given their new pin. Every other tool stays as the policy has it."""

    added: Mapping[str, Added] = field(default_factory=dict)
    dropped: frozenset[str] = frozenset()
    moved: Mapping[str, Classification] = field(default_factory=dict)
    repin: frozenset[str] = frozenset()


def planned(review: Mapping[str, Any], choices: Choices) -> Changes:
    """The changes the options ask for, once :func:`check_choices` accepts them."""
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
            added.setdefault(name, Added("allow", "allowed because the server marks it read-only"))
    return Changes(added=added, repin=choices.repin)


def title(server: str) -> str:
    """The snippet's title: what to do with it."""
    return f"review of {server}. Replace the tools: and review: blocks of gateway.servers.{server}."


def second_title(server: str) -> str:
    """Fragment 2's title (E.4): the choices file's fragment, after onboarding's fragment 1."""
    return (
        f"review of {server} (2 of 2). Replace the tools: and review: blocks of "
        f"gateway.servers.{server}, then assign {server} to its clients."
    )


def fragment(
    review: Mapping[str, Any], changes: Changes, *, heading: str | None = None
) -> PolicyChange:
    """The server's entry with ``changes`` made, as a change for the emitter: its ``tools`` and
    ``review`` replaced whole, and its ``era`` when the review learned it. A tool with an error
    finding gets no pin; a drifted, missing or unpinnable included tool keeps the pin it has, so
    it stays hidden. Raises ``ValueError`` for a name the policy can't hold."""
    server, policy = review["server"], review["policy"]
    by_name = {e["name"]: e for e in review["tools"] if TOOL_NAME.fullmatch(e["name"])}
    dropped, moved = changes.dropped, changes.moved
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
    changed: list[Comment] = []
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
            elif pinned is not None and PIN.fullmatch(pinned):
                pins[name] = pinned
                kept.append(Comment("kept", name, _kept_why(server, name, entry)))
        elif state != "missing":
            if pinnable(entry):
                others.append(Comment("not_included", name, f"{pin}; {suggested_words(entry)}"))
            else:
                others.append(Comment("error_finding", name, f"review {server} --show {name}"))
    notes += [*changed, *kept, *others]
    if review.get("kind") == "toolkit" and review.get("pinning") == "off":
        pins = {}
        notes.append(Comment("merge_hint", server, "pinning: off: definitions follow the image"))
    tools = Tools(include=include, allow=classes["allow"], approve=classes["approve"])
    era = review.get("era") if review.get("era") in ("modern", "legacy") else None
    op = SetServerReview(server, tools, pins, era=era)
    return PolicyChange(heading or title(server), (*notes, op))


def _kept_why(server: str, name: str, entry: Mapping[str, Any]) -> str:
    state = entry["state"]
    if state == "drift":
        return f"drift: the server lists {entry['pin']}; review {server} --repin {name} takes it"
    if state == "missing":
        return "missing: the server doesn't list it"
    return f"{state}: not pinnable, kept hidden"


def snippet(review: dict[str, Any], choices: Choices) -> list[str]:
    """The fragment to merge over the server's entry, written by the emitter (DD-13)."""
    return emit(fragment(review, planned(review, choices))).splitlines()


# --- text output ---------------------------------------------------------------------------------


def _tool_line(entry: dict[str, Any], width: int) -> str:
    state = entry["state"]
    label = STATE_LABELS.get(state, untrusted(state))
    name = untrusted(entry["name"], 128).ljust(width)
    if state == "missing":
        return f"  {name}  {label:<10}  pinned {short_pin(entry['pinned'])}"
    if state == "drift":
        changed = entry.get("changed")
        what = "changed: " + ", ".join(changed) if changed else "changed (no reviewed copy kept)"
        return f"  {name}  {label:<10}  {what}    hidden, marked"
    detail = short_pin(entry["pin"])
    if entry.get("consequential"):
        detail += "  consequential"
    if not entry["included"] and state == "unreviewed":
        detail += "  not included"
    elif state == "marked":
        detail += "  hidden: a drift mark holds (review --clear once it matches)"
    elif state == "blocked":
        detail += "  hidden: on_drift: fail blocked the server"
    return f"  {name}  {label:<10}  {detail}"


def render(review: dict[str, Any], choices: Choices) -> list[str]:
    """The text ``review <server>`` prints, before :func:`untrusted` is applied to each line."""
    era = " ".join(
        part
        for part in (review.get("era") or "era unknown", review.get("protocol_version"))
        if part
    )
    if review.get("kind") == "toolkit":
        version = f" {review['version']}" if review.get("version") else ""
        lines = [
            f"server {review['server']}  (toolkit {review['module']}, "
            f"{review.get('distribution') or 'unknown distribution'}{version}, "
            f"pinning {review['pinning']})"
        ]
        if review.get("pinning") == "off":
            choices = replace(choices, show_all=True)
    else:
        lines = [f"server {review['server']}  (remote, vault path {review['vault_path']}, {era})"]
    info = review.get("server_info")
    if info:
        described = " ".join(f'{key} "{untrusted(value, 200)}"' for key, value in info.items())
        lines.append(f"  serverInfo (never forwarded): {described}")
    if review.get("instructions"):
        lines.append(f'  instructions (never forwarded): "{untrusted(review["instructions"])}"')
    shown = [
        entry for entry in review["tools"] if not choices.tools or entry["name"] in choices.tools
    ]
    width = max((len(untrusted(entry["name"], 128)) for entry in shown), default=0)
    lines += [_tool_line(entry, width) for entry in shown]
    if review.get("cleared"):
        lines.append(f"cleared drift marks: {', '.join(review['cleared'])}")
    findings = [(entry["name"], finding) for entry in shown for finding in entry["findings"]]
    if findings:
        lines.append("findings (heuristics; reading the definition is the control):")
        for name, finding in findings:
            pointer = finding["pointer"] or "(definition)"
            lines.append(
                f"  {untrusted(name, 128)}: {finding['level']} {untrusted(pointer, 300)}: "
                f"{untrusted(finding['message'])}"
            )
    for entry in shown:
        if entry.get("diff"):
            lines.append(f"diff {untrusted(entry['name'], 128)}:")
            lines += [f"  {untrusted(line)}" for line in entry["diff"]]
    for entry in shown:
        if (choices.show_all or entry["name"] in choices.show) and entry["definition"]:
            lines.append(f"definition {untrusted(entry['name'], 128)} ({entry['pin']}):")
            rendered = json.dumps(entry["definition"], indent=2, sort_keys=True, ensure_ascii=False)
            lines += [f"  {untrusted(line, 1_000_000)}" for line in rendered.splitlines()]
    lines += ["", "# YAML to commit (declarative mode). Review the changes above first."]
    lines += snippet(review, choices)
    return lines


def exit_code(review: dict[str, Any]) -> int:
    return EXIT_CLEAN if review.get("clean") else EXIT_NEEDS_OPERATOR


def write_lines(lines: Sequence[str], out: TextIO) -> None:
    for line in lines:
        out.write(untrusted(line, 1_000_000) + "\n")


def write_json(data: Any, out: TextIO) -> None:
    json.dump(data, out, indent=2, sort_keys=True, ensure_ascii=True)
    out.write("\n")


# --- where the review runs (M7 design F.5) -----------------------------------------------------

Via = Literal["auto", "gateway", "vault"]
# Each read of a queued job waits at most this long (the vault's socket waits up to 30 s).
JOB_READ_WAIT: Final = 30
# A job the vault queued has ended by then: 60 s for the gateway to take it, 120 s to answer.
JOB_WAIT_MAX: Final = 60 + 120


class StillRunning(Exception):
    """The review job hadn't ended when the wait did. ``job`` is the vault's last answer."""

    def __init__(self, job: Mapping[str, Any]) -> None:
        self.job = dict(job)
        super().__init__("the review is still running")


def pick_via(
    via: Via, socket: str | None, exists: Callable[[str], bool] = os.path.exists
) -> Literal["gateway", "vault"]:
    """Where ``review`` runs. ``auto``: the gateway's admin socket when this container has it
    (today's path, and in the standard tier, where both run in one container), else the vault's
    when it has that one, else the gateway's, whose absence the error then names. A ``--socket``
    is the gateway's unless ``--via vault`` says otherwise."""
    if via != "auto":
        return via
    if socket is not None or exists(admin_client.gateway_socket_path(None)):
        return "gateway"
    return "vault" if exists(admin_client.socket_path(None)) else "gateway"


def vault_review(
    socket: str,
    server: str,
    *,
    fresh: bool,
    wait: float | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """A review of ``server`` through the vault's job path: queued, or the CLI's finished one
    handed back unless ``fresh``, then read until it is done or ``wait`` seconds pass (by
    default :data:`JOB_WAIT_MAX`). The job's answer, with its ``report``. Raises
    :class:`.admin_client.AdminUnavailable` for a refusal or a failed job, and
    :class:`StillRunning`."""
    job = admin_client.review_queue(socket, server, fresh=fresh)
    deadline = clock() + (JOB_WAIT_MAX if wait is None else wait)
    while job.get("state") != "done":
        left = deadline - clock()
        if left <= 0:
            raise StillRunning(job)
        seconds = min(JOB_READ_WAIT, math.ceil(left))
        job = admin_client.review_job(socket, job["job"], wait=seconds)
    return job


def report_counts(review: Mapping[str, Any]) -> dict[str, int]:
    """What a review found, by the tools the server lists: how many, how many the shared rule
    suggests ``allow`` for (marked read-only), ``approve`` for (marked otherwise) or nothing
    for (not annotated), and how many have an error finding."""
    counts = {"tools": 0, "read_only": 0, "marked_otherwise": 0, "not_annotated": 0, "errors": 0}
    for entry in review["tools"]:
        if entry["state"] == "missing":
            continue
        counts["tools"] += 1
        definition = entry.get("definition")
        found = suggestion(definition.get("annotations") if isinstance(definition, dict) else None)
        key = {"allow": "read_only", "approve": "marked_otherwise"}.get(
            found or "", "not_annotated"
        )
        counts[key] += 1
        if any(finding["level"] == "error" for finding in entry["findings"]):
            counts["errors"] += 1
    return counts


def counts_line(counts: Mapping[str, int]) -> str:
    """``96 tools (64 the server marks read-only, 32 not annotated, 1 with an error finding)``:
    the annotations are the server's claims, so the line says whose."""
    parts = [f"{counts['read_only']} the server marks read-only"]
    if counts["marked_otherwise"]:
        parts.append(f"{counts['marked_otherwise']} it marks otherwise")
    parts.append(f"{counts['not_annotated']} not annotated")
    if counts["errors"]:
        parts.append(f"{counts['errors']} with an error finding")
    tools = counts["tools"]
    return f"{tools} tool{'' if tools == 1 else 's'} ({', '.join(parts)})"


# --- the summary and gateway-status --------------------------------------------------------------


def summary(status: dict[str, Any]) -> tuple[list[str], int]:
    """``review`` with no server: one line per server, from the gateway's status."""
    lines: list[str] = []
    code = EXIT_CLEAN
    for name, server in sorted(status["servers"].items()):
        if server["kind"] == "toolkit":
            line, needs_operator = _toolkit_summary(name, server)
            lines.append(line)
            if needs_operator:
                code = EXIT_NEEDS_OPERATOR
            continue
        if server["kind"] != "remote":
            lines.append(f"{name}  {server['kind']}: not served by this version")
            continue
        reports = server.get("reports", {})
        counts = {kind: len(reports.get(kind, [])) for kind in ("drift", "missing", "invalid")}
        counts["unreviewed"] = len(reports.get("unreviewed", []))
        marked = len(server["marked"])
        if marked or counts["drift"] or counts["missing"] or counts["invalid"]:
            code = EXIT_NEEDS_OPERATOR
        ago = server["listed_s_ago"]
        listed = "never listed" if ago is None else f"listed {round(ago)} s ago"
        lines.append(
            f"{name}  {server['era'] or 'era unknown'}  exposed {server['exposed']}/"
            f"{server['included']}  drift {counts['drift']}  marked {marked}  missing "
            f"{counts['missing']}  unreviewed {counts['unreviewed']}  invalid {counts['invalid']}"
            f"  {listed}"
        )
    if not status["servers"]:
        lines.append("no gateway servers")
    if not status["fresh"]:
        lines.append("the gateway has no fresh view of the policy")
        code = EXIT_NEEDS_OPERATOR
    return lines, code


def _toolkit_summary(name: str, server: dict[str, Any]) -> tuple[str, bool]:
    """One summary line for a toolkit server, and whether it needs the operator."""
    if server["state"] != "loaded":
        return f"{name}  toolkit unavailable ({server.get('reason', 'unknown')})", True
    reports = server.get("reports", {})
    counts = {kind: len(reports.get(kind, [])) for kind in ("drift", "missing", "invalid")}
    marked = len(server["marked"])
    line = (
        f"{name}  toolkit {server['module']}  exposed {server['exposed']}/{server['included']}  "
        f"drift {counts['drift']}  marked {marked}  missing {counts['missing']}  "
        f"invalid {counts['invalid']}  pinning {server['pinning']}"
    )
    return line, bool(marked or any(counts.values()))


def _status_head(name: str, entry: dict[str, Any]) -> str | None:
    """A server's first ``gateway-status`` line; ``None`` if nothing more follows it."""
    if entry["kind"] == "toolkit":
        if entry["state"] != "loaded":
            return None
        version = f" {entry['version']}" if entry.get("version") else ""
        return (
            f"{name}  toolkit  {entry['module']}{version}  pinning {entry['pinning']}  "
            f"exposed {entry['exposed']}/{entry['included']}"
        )
    if entry["kind"] != "remote":
        return None
    return (
        f"{name}  remote  {','.join(entry['state'])}  era {entry['era'] or 'unknown'}  "
        f"connections {entry['connections']}  exposed {entry['exposed']}/{entry['included']}"
    )


def status_lines(status: dict[str, Any], server: str | None) -> list[str]:
    """``gateway-status``: the view, then each server's state and counts."""
    view = status["view"] or "none yet"
    lines = [f"view {view}  {'fresh' if status['fresh'] else 'NOT FRESH'}"]
    for name, entry in sorted(status["servers"].items()):
        if server is not None and name != server:
            continue
        head = _status_head(name, entry)
        if head is None:
            if entry["kind"] == "toolkit":
                lines.append(f"{name}  toolkit  unavailable ({entry.get('reason', 'unknown')})")
            else:
                lines.append(f"{name}  {entry['kind']}  unsupported")
            continue
        lines.append(head)
        if entry["marked"]:
            lines.append(f"  marked: {', '.join(entry['marked'])}")
        for kind, tools in sorted(entry.get("reports", {}).items()):
            if tools:
                lines.append(f"  {kind}: {', '.join(tools)}")
        if entry.get("listed_s_ago") is not None:
            lines.append(f"  last listing {round(entry['listed_s_ago'])} s ago")
    return lines
