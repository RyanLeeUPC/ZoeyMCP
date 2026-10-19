"""``zoeymcp review`` and ``zoeymcp gateway-status``: rendering the gateway's answers (M3 design I).

The gateway does the work: it lists the server on a fresh connection and evaluates it. This
module only prints, so it needs no SDK and runs in either environment.

Everything the upstream wrote is untrusted, and a terminal acts on control characters, so every
line goes through :func:`untrusted`, which shows each hidden character as ``[U+XXXX]`` and line
breaks as ``\\n``: an upstream's text can't move the cursor, hide itself, or fake a line of
output (a fake YAML snippet, for one). JSON output escapes everything outside ASCII.

The YAML snippet is for declarative mode: paste it over the server's entry. By default it
refreshes ``era`` and keeps every pin, so a drifted tool stays hidden. ``--repin TOOL`` takes a
drifted tool's new pin, and ``--add TOOL`` includes a tool, leaving its classification to the
operator: ``check`` fails until it is in ``allow`` or ``approve`` (nothing is implied). No pin
line is ever written for a tool with an error finding.

For a toolkit server (M4 design H.6), ``--add TOOL`` puts a tool its code declares consequential
into ``approve`` ("declared by the toolkit") and leaves a routine one to the operator, as for a
remote tool. With ``pinning: off`` the snippet has no pins, and every definition is printed, so an
image change can be read before or after it is deployed.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, TextIO

from ..common.textrules import reveal_hidden

EXIT_CLEAN = 0
EXIT_NEEDS_OPERATOR = 1
EXIT_COULD_NOT_RUN = 2

TOOL_NAME = re.compile(r"[A-Za-z0-9_.-]{1,128}")
PIN = re.compile(r"sha256:[0-9a-f]{64}")
_PLAIN_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*")
_YAML_WORDS = frozenset({"true", "false", "null", "yes", "no", "on", "off", "y", "n"})
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


def yaml_key(name: str) -> str:
    if _PLAIN_KEY.fullmatch(name) and name.lower() not in _YAML_WORDS:
        return name
    return json.dumps(name)


def yaml_list(names: Sequence[str]) -> str:
    return "[" + ", ".join(yaml_key(name) for name in names) + "]"


def pinnable(entry: dict[str, Any]) -> bool:
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


def check_choices(review: dict[str, Any], choices: Choices) -> None:
    """Refuse an ``--add`` or ``--repin`` that the review doesn't allow."""
    by_name = {entry["name"]: entry for entry in review["tools"]}
    for name in choices.add:
        entry = by_name.get(name)
        if entry is None or entry["state"] == "missing":
            raise UsageError(f"--add {name}: the server doesn't list it")
        if entry["included"]:
            raise UsageError(f"--add {name}: it is already included")
        if not pinnable(entry):
            raise UsageError(f"--add {name}: it has error findings, so it can't be pinned")
    for name in sorted(choices.repin):
        entry = by_name.get(name)
        if entry is None or entry["state"] != "drift":
            raise UsageError(f"--repin {name}: it hasn't drifted")
        if not pinnable(entry):
            raise UsageError(f"--repin {name}: it has error findings, so it can't be pinned")
    unknown = sorted((choices.tools | choices.show) - set(by_name))
    if unknown:
        raise UsageError(f"the server lists no tool named {', '.join(unknown)}")


# --- the YAML snippet ----------------------------------------------------------------------------


def _suggestion(entry: dict[str, Any]) -> str:
    for finding in entry["findings"]:
        if finding["pointer"] == "/annotations" and finding["message"].startswith("suggested"):
            return f"  ({untrusted(finding['message'])})"
    return ""


def snippet(review: dict[str, Any], choices: Choices) -> list[str]:
    """The YAML to paste over the server's entry."""
    policy_tools = review["policy"]
    entries = [entry for entry in review["tools"] if TOOL_NAME.fullmatch(entry["name"])]
    lines = [
        "# YAML to commit (declarative mode). Review the changes above first.",
        "gateway:",
        "  servers:",
        f"    {review['server']}:",
    ]
    era = review.get("era")
    if era in ("modern", "legacy"):
        lines.append(f"      era: {era}")
    toolkit = review.get("kind") == "toolkit"
    added = [name for name in choices.add if TOOL_NAME.fullmatch(name)]
    if added:
        by_name = {entry["name"]: entry for entry in entries}
        declared = [n for n in added if toolkit and by_name.get(n, {}).get("consequential")]
        include = [*policy_tools.get("include", []), *added]
        lines += [
            "      tools:",
            f"        include: {yaml_list(include)}",
            f"        allow: {yaml_list(policy_tools.get('allow', []))}",
            f"        approve: {yaml_list([*policy_tools.get('approve', []), *declared])}",
        ]
        lines += [f"        # {name}: approve, declared by the toolkit" for name in declared]
        lines += [
            f"        # {name}: put it in allow or approve; nothing is implied"
            for name in added
            if name not in declared
        ]
    if toolkit and review.get("pinning") == "off":
        return [*lines, "      review: {}  # pinning: off: definitions follow the image"]
    pin_lines: list[str] = []
    comments: list[str] = []
    for entry in sorted(entries, key=lambda entry: entry["name"]):
        name, state, pinned = entry["name"], entry["state"], entry["pinned"]
        key = yaml_key(name)
        if entry["included"]:
            if state in ("ok", "marked", "blocked") and pinnable(entry):
                pin_lines.append(f"        {key}: {entry['pin']}")
            elif state == "drift" and name in choices.repin and pinnable(entry):
                pin_lines.append(f"        {key}: {entry['pin']}  # CHANGED, was {pinned}")
            elif pinned is not None and PIN.fullmatch(pinned):
                why = {
                    "drift": f"DRIFT: the server lists {entry['pin']}; --repin {name} takes it",
                    "missing": "MISSING: the server doesn't list it",
                }.get(state, f"{state.upper()}: not pinnable, kept hidden")
                pin_lines.append(f"        {key}: {pinned}  # {why}")
        elif name in added:
            pin_lines.append(f"        {key}: {entry['pin']}  # ADDED")
        elif state != "missing":
            if pinnable(entry):
                comments.append(f"      # not included: {name}  {entry['pin']}{_suggestion(entry)}")
            else:
                comments.append(f"      # not included: {name}  (error findings: not pinnable)")
    lines.append("      review:" if pin_lines else "      review: {}")
    return lines + pin_lines + comments


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
            choices = Choices(choices.tools, choices.show, True, choices.add, choices.repin)
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
    lines.append("")
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
