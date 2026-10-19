"""What the gateway allows a toolkit, as pure decisions (M4 design H.2, H.4).

- :func:`check_call`: whether a toolkit's vault request may leave the gateway, by the call's
  phase and the slot's rules (H.4's table). The path is joined to the slot's prefix and
  normalized as the vault does; anything ambiguous is ``bad_path`` before any rule is matched.
- :func:`module_refused`, :func:`slot_mismatch`, :func:`classification_hidden`: the loader's
  decisions (H.2 steps 1, 5 and 7).
- :func:`writable_problems` and :func:`outside_roots`: "never loaded from a writable path"
  (H.2 step 3), over ``os.stat`` results the caller gathers.

The honest limit: this is the gateway enforcing on itself. It stops toolkit bugs and
model-driven misuse, not a compromised gateway.
"""

from __future__ import annotations

import stat
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Final, Literal

from ..common.policy.match import NormalizedPath, RequestRejected, match_pattern, normalize_path
from ..common.policy.paths import parse_path_pattern
from .plan import Claim

Phase = Literal["prepare", "allow", "approve", "closed"]
SlotKind = Literal["smtp", "http"]
Blocked = Literal[
    "closed",
    "bad_path",
    "prepare_upstream_read",
    "write_in_prepare",
    "no_rule",
    "needs_approval",
    "not_in_plan",
    "already_sent",
    "not_approved_rule",
]
METHODS: Final = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})
CONFIG_PATH: Final = "config"


@dataclass(frozen=True)
class SlotRule:
    """One of a slot's rules. ``paths`` are full patterns: the route's prefix and the rule's path,
    as the view holds them (A.3)."""

    methods: frozenset[str]
    paths: tuple[str, ...]
    approved: bool = False


@dataclass(frozen=True)
class Slot:
    """A slot as the gateway's view describes it."""

    prefix: str  # "/mail"
    connector: Literal["smtp"] | None  # the connector's kind; None for an HTTP route
    rules: tuple[SlotRule, ...]


def join(prefix: str, path: str) -> NormalizedPath:
    """``path`` (relative to the slot) under ``prefix``, normalized as the vault does. Raises
    :class:`RequestRejected` for anything the vault would refuse or read differently."""
    if not path.startswith("/"):
        raise RequestRejected("a toolkit path starts with /")
    return normalize_path((prefix + path).encode("ascii", errors="replace"))


def _matching(slot: Slot, method: str, path: NormalizedPath) -> list[SlotRule]:
    return [
        rule
        for rule in slot.rules
        if method in rule.methods
        and any(match_pattern(parse_path_pattern(p), path) is not None for p in rule.paths)
    ]


def check_call(
    slot: Slot, phase: Phase, method: str, path: str, *, plan_write: Claim | None = None
) -> Blocked | None:
    """Why this request may not leave the gateway, or ``None`` if it may.

    ``plan_write`` is set for ``send(write)`` only: the claim :class:`~.plan.SendLedger` made.
    """
    if phase == "closed":
        return "closed"
    try:
        full = join(slot.prefix, path)
    except (RequestRejected, UnicodeError):
        return "bad_path"
    if method not in METHODS:
        return "no_rule"
    writing = method != "GET"
    if phase == "prepare":
        if writing:
            return "write_in_prepare"
        if slot.connector != "smtp" or full.segments[1:] != (CONFIG_PATH,):
            return "prepare_upstream_read"
    matched = _matching(slot, method, full)
    if not matched:
        return "no_rule"
    if not writing:
        return None
    approved = any(rule.approved for rule in matched)
    if plan_write is not None:
        if phase != "approve":
            return "needs_approval"
        if not approved:
            return "not_approved_rule"
        return None if plan_write == "ok" else plan_write
    if approved:
        return "needs_approval" if phase == "allow" else "not_in_plan"
    return None


# --- loading ------------------------------------------------------------------------------------


def module_refused(module: str) -> bool:
    """The gateway never loads its own code as a toolkit (H.2 step 1)."""
    return module == "zoeymcp" or module.startswith("zoeymcp.")


def entry_module(value: str) -> str:
    """The module part of an entry point's value: ``pkg.mod`` of ``pkg.mod:attr``."""
    return value.partition(":")[0].strip()


def slot_mismatch(
    declared: Mapping[str, SlotKind], policy: Mapping[str, Literal["smtp"] | None]
) -> str | None:
    """The first slot whose name or kind differs between the code and the policy (H.2 step 5),
    or ``None``. An ``smtp`` slot needs an smtp connector route; an ``http`` slot a plain one."""
    for name in sorted(set(declared) | set(policy)):
        if name not in declared or name not in policy:
            return name
        wanted = "smtp" if declared[name] == "smtp" else None
        if policy[name] != wanted:
            return name
    return None


def classification_hidden(consequential: bool, policy_class: Literal["allow", "approve"]) -> bool:
    """A tool the code marks consequential is hidden if the policy allows it without asking
    (H.2 step 7). The policy may always be stricter."""
    return consequential and policy_class == "allow"


@dataclass(frozen=True)
class Entry:
    """What ``os.stat`` said about one path."""

    path: str
    mode: int
    uid: int
    gid: int


def writable_problems(entries: Iterable[Entry], *, uid: int, gids: frozenset[int]) -> list[str]:
    """Paths the gateway's uid could change: owned and owner-writable, group-writable with one of
    its groups, or writable by anyone. Root may write anything, so a gateway running as root is a
    problem for every path."""
    found: list[str] = []
    for entry in entries:
        if (
            uid == 0
            or entry.mode & stat.S_IWOTH
            or (entry.uid == uid and entry.mode & stat.S_IWUSR)
            or (entry.gid in gids and entry.mode & stat.S_IWGRP)
        ):
            found.append(entry.path)
    return found


def outside_roots(files: Iterable[str], roots: Iterable[str]) -> list[str]:
    """Resolved file paths that aren't under any of ``roots`` (``purelib``, ``platlib``)."""
    bases = [PurePosixPath(r) for r in roots]
    return [f for f in files if not any(PurePosixPath(f).is_relative_to(b) for b in bases)]
