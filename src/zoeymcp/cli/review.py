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
fixed kinds, so no upstream text reaches it. The change itself is built by
``common/policy/reviewchange.py`` (M6 design J.3), which the portal's fragment 2 shares: a
re-pinned ``allow`` tool whose new definition the server no longer marks read-only stays
``allow``, with a comment proposing ``approve`` (Q8).

``--decline TOOL`` records a listed tool the operator leaves out under the server's ``declined``
at the pin shown, and ``--decline-rest`` every listed tool the snippet doesn't include (M6 design
J.3, J.5; G-19), so the server ends quiet: a tool that is neither included nor declined at the
pin it has now is one nobody reviewed, and ``review`` exits 1 for it, naming it on a line of its
own ("3 listed that nobody reviewed: ..."), as for drift, a mark or a missing tool (the attention
decision, ``common/policy/attention.py``). A snippet writes ``declined`` whole once the server
has one or the options decline a tool, an included tool leaving it; otherwise it is M7's. When
the upstream offers prompts, resources or completions the server's ``enable`` doesn't list, a
line after the tools says so, with J12's way to serve them in the deployment's mode
(:func:`offered_line`).

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

In managed mode the policy isn't a file the operator commits, so the options that make a fragment
(``--add``, ``--allow``, ``--approve``, ``--allow-read-only``, ``--repin``, ``--decline``,
``--decline-rest`` and ``--choices``) refuse, naming the portal and the host's export and import
(M6 design G.9, Y25). Through the vault the CLI asks the vault's mode (``GET /policy``) before it
queues anything; over the gateway's socket, which is all the gateway's container has, the review
answer names the mode the vault last stated beside the view (``policy_mode``), and ``unknown``
before the gateway's first view refuses too. A read-only review works in either mode; in managed
mode it prints no snippet to commit, and the way on (the vault's ``next``, or over the gateway's
socket the same save, export and import) stands in its place. The mode is no part of the review:
it is left out of what is printed and of the choices file's digest.
"""

from __future__ import annotations

import json
import math
import os
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
from typing import Any, Final, Literal, TextIO

from ..common.policy import attention
from ..common.policy.emit import emit
from ..common.policy.reviewchange import NOUNS, OFFERABLE, kind_of, not_served_line, pinnable

# The change the snippet makes moved to a pure module (M6 design J.3), named here as before.
from ..common.policy.reviewchange import Added as Added
from ..common.policy.reviewchange import Changes as Changes
from ..common.policy.reviewchange import Choices as Choices
from ..common.policy.reviewchange import fragment as fragment
from ..common.policy.reviewchange import kind_blocks as kind_blocks
from ..common.policy.reviewchange import planned as planned
from ..common.policy.reviewchange import read_only as read_only
from ..common.policy.reviewchange import second_title as second_title
from ..common.policy.reviewchange import suggested_words as suggested_words
from ..common.policy.reviewchange import title as title
from ..common.suggest import suggestion
from ..common.textrules import reveal_hidden
from . import admin_client

EXIT_CLEAN = 0
EXIT_NEEDS_OPERATOR = 1
EXIT_COULD_NOT_RUN = 2

MAX_SHOWN_CHARS = 2000
STATE_LABELS = {
    "ok": "ok",
    "marked": "MARKED",
    "blocked": "BLOCKED",
    "drift": "DRIFT",
    "unreviewed": "unreviewed",
    "declined": "declined",
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


def check_choices(review: dict[str, Any], choices: Choices) -> None:
    """Refuse an ``--add``, ``--allow``, ``--approve``, ``--decline`` or ``--repin`` that the
    review doesn't allow. Each names a tool: a prompt or a resource of the name (M6 L.7) is a
    choices file's line, never checked in a tool's place; ``--tool`` and ``--show`` may name any
    kind."""
    by_name = {entry["name"]: entry for entry in review["tools"] if kind_of(entry) == "tool"}
    others = {entry["name"]: kind_of(entry) for entry in review["tools"]}
    named = [*choices.add, *choices.allow, *choices.approve]
    twice = sorted({name for name in named if named.count(name) > 1})
    if twice:
        raise UsageError(f"{', '.join(twice)}: name it in one of --add, --allow and --approve")
    both = sorted(set(choices.decline) & set(named))
    if both:
        raise UsageError(f"{', '.join(both)}: --decline leaves a tool out, so don't include it")
    for option, names in (
        ("--add", choices.add),
        ("--allow", choices.allow),
        ("--approve", choices.approve),
        ("--decline", choices.decline),
        ("--repin", sorted(choices.repin)),
    ):
        for name in names:
            if name not in by_name and name in others:
                noun = NOUNS[others[name]]
                raise UsageError(
                    f"{option} {name}: the server lists it as a {noun}: choose it in the file "
                    "--choose writes"
                )
    for option, names in (
        ("--add", choices.add),
        ("--allow", choices.allow),
        ("--approve", choices.approve),
        ("--decline", choices.decline),
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
    unknown = sorted((choices.tools | choices.show) - set(others))
    if unknown:
        raise UsageError(f"the server lists no tool named {', '.join(unknown)}")


def _check_new(option: str, name: str, entry: Mapping[str, Any] | None) -> None:
    if entry is None or entry["state"] == "missing":
        raise UsageError(f"{option} {name}: the server doesn't list it")
    if entry["included"]:
        raise UsageError(f"{option} {name}: it is already included")
    if not pinnable(entry):
        raise UsageError(f"{option} {name}: it has error findings, so it can't be pinned")


# --- the YAML snippet (M7 design F.5, H; DD-13) ------------------------------------------------


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
    if not entry["included"] and state in ("unreviewed", "declined"):
        detail += "  not included"
    elif state == "marked":
        detail += "  hidden: a drift mark holds (review --clear once it matches)"
    elif state == "blocked":
        detail += "  hidden: on_drift: fail blocked the server"
    return f"  {name}  {label:<10}  {detail}"


def render(review: dict[str, Any], choices: Choices, *, managed: bool = False) -> list[str]:
    """The text ``review <server>`` prints, before :func:`untrusted` is applied to each line;
    ``managed``, without the snippet to commit, which a managed policy has no use for (M6 design
    Y25): the way on, a save or an import, stands in its place."""
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
    unreviewed = unreviewed_line(review.get("attention"))
    if unreviewed is not None:
        lines.append(unreviewed)
    offered = offered_line(review, managed=managed)
    if offered is not None:
        lines.append(offered)
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
    if managed:
        return lines
    lines += ["", "# YAML to commit (declarative mode). Review the changes above first."]
    lines += snippet(review, choices)
    return lines


# The enable entry that lists each kind a review's ``listings`` names (M6 design L.4).
ENABLED_BY: Final = {"prompt": "prompts", "resource_template": "resources", "resource": "resources"}


def offered_line(review: Mapping[str, Any], *, managed: bool = False) -> str | None:
    """``notes offers prompts and resources, not served: <J12's way to serve them>`` (M6 design
    J12, D-216), or ``None``: what a remote server's upstream offers (``offered``) that its
    ``enable`` doesn't list, read from the report alone, whose policy block holds the server's
    ``enable`` once it lists any. A report without it, an older gateway's, tells what the server
    enables by its ``listings``, which name exactly the kinds it enables: completions can't be
    told there, so they are named only for a server that enables neither, where ``check``
    refuses them (A.2 row 5c). Completions join J12's way only where ``check`` takes them."""
    offered = review.get("offered")
    if review.get("kind") != "remote" or not offered:
        return None
    policy = review["policy"]
    if "enable" in policy:
        enable = set(policy["enable"])
    else:
        enable = {ENABLED_BY[kind] for kind in review.get("listings") or {} if kind in ENABLED_BY}
        if enable:
            enable.add("completions")
    kinds = [kind for kind in OFFERABLE if offered.get(kind) and kind not in enable]
    if not kinds:
        return None
    templates = bool(policy.get("resources", {}).get("templates", {}).get("include"))
    return not_served_line(review["server"], kinds, enable, templates=templates, managed=managed)


def _quiet(found: Mapping[str, Any] | None) -> bool:
    """The attention decision a review or status carries: quiet when there is none (an M7
    gateway's, or a server not listed yet)."""
    return found is None or attention.quiet(attention.loaded(found))


def unreviewed_line(found: Mapping[str, Any] | None) -> str | None:
    """``3 listed that nobody reviewed: a, b, c`` (J2), or ``None`` when there are none."""
    if found is None:
        return None
    names = attention.loaded(found).unreviewed()
    return f"{len(names)} listed that nobody reviewed: {', '.join(names)}" if names else None


def exit_code(review: dict[str, Any]) -> int:
    """0 when every included tool matches and the attention decision is quiet (J.5)."""
    clean = review.get("clean") and _quiet(review.get("attention"))
    return EXIT_CLEAN if clean else EXIT_NEEDS_OPERATOR


def write_lines(lines: Sequence[str], out: TextIO) -> None:
    for line in lines:
        out.write(untrusted(line, 1_000_000) + "\n")


def write_json(data: Any, out: TextIO) -> None:
    json.dump(data, out, indent=2, sort_keys=True, ensure_ascii=True)
    out.write("\n")


# --- the mode (M6 design G.9, E-7) -------------------------------------------------------------

MANAGED_REFUSED: Final = (
    "this deployment is managed: save it in the portal, or export, edit and import"
)
MODE_UNKNOWN: Final = "the gateway hasn't received the policy from the vault yet: try again"


def answered_mode(answer: Mapping[str, Any]) -> str:
    """The mode a gateway's status or review answer names (``policy_mode``): ``managed``,
    ``declarative`` or ``unknown``. An answer without one is from a gateway older than managed
    mode, which only a declarative vault runs; a value it doesn't know is ``unknown``. A gateway
    that lies can only make the CLI print a fragment nothing applies, or refuse (G.9)."""
    mode = answer.get("policy_mode", "declarative")
    return mode if mode in ("managed", "declarative") else "unknown"


def fragment_refused(mode: str) -> str | None:
    """Why a command that prints a fragment refuses in ``mode``, or None in declarative mode."""
    if mode == "declarative":
        return None
    return MANAGED_REFUSED if mode == "managed" else MODE_UNKNOWN


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
    clear: bool = False,
    wait: float | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """A review of ``server`` through the vault's job path: queued, or the CLI's finished one
    handed back unless ``fresh``; with ``clear``, a clear of its drift marks, always a new job
    (M6 design J.4). Then read until it is done or ``wait`` seconds pass (by default
    :data:`JOB_WAIT_MAX`). The job's answer, with its ``report``. Raises
    :class:`.admin_client.AdminUnavailable` for a refusal or a failed job (a clear the gateway
    refused is ``clear_not_clean``, with the review that found it), and :class:`StillRunning`."""
    if clear:
        job = admin_client.review_clear(socket, server)
    else:
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
    """``review`` with no server: one line per server, from the gateway's status, with the
    tools it lists that nobody reviewed under it. Exit 1 when any server needs the operator, the
    attention decision's not being quiet included (J.5)."""
    lines: list[str] = []
    code = EXIT_CLEAN
    for name, server in sorted(status["servers"].items()):
        unreviewed = unreviewed_line(server.get("attention"))
        if not _quiet(server.get("attention")):
            code = EXIT_NEEDS_OPERATOR
        if server["kind"] == "toolkit":
            line, needs_operator = _toolkit_summary(name, server)
            lines += [line] if unreviewed is None else [line, f"  {unreviewed}"]
            if needs_operator:
                code = EXIT_NEEDS_OPERATOR
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
        if unreviewed is not None:
            lines.append(f"  {unreviewed}")
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
    """A server's first ``gateway-status`` line; ``None`` for a toolkit that didn't load."""
    if entry["kind"] == "toolkit":
        if entry["state"] != "loaded":
            return None
        version = f" {entry['version']}" if entry.get("version") else ""
        return (
            f"{name}  toolkit  {entry['module']}{version}  pinning {entry['pinning']}  "
            f"exposed {entry['exposed']}/{entry['included']}"
        )
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
            lines.append(f"{name}  toolkit  unavailable ({entry.get('reason', 'unknown')})")
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
