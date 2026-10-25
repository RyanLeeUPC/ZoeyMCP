"""The gateway's status report, as the vault accepts it (M6 design K.1; D-29, Y21, T-4, T-7). Pure.

The gateway pushes a small summary of what its admin socket's ``GET /status`` shows, on the
status path (:data:`.internal.STATUS`): per server its kind, state, era, counts, and the names the
attention decision (``common/policy/attention.py``, J.5) sorted into its lists, never a
definition, a token hash or a client name. The vault keeps the latest in memory; health and Home
read it, labelled as the gateway's, and nothing in it drives a decision (Y21).

:func:`read` takes one parsed report under the running limits. The report's frame is strict:
``{"v": 1, "view", "started", "servers", "witness", "deployments_seen", "policy_mode"}``, each
of the right type, or the whole report is refused ``invalid`` (:class:`StatusRefused`). A witness
revision above :data:`REVISION_MAX`, the store's own bound (``policyseal``, D.2), refuses it
whole too, ``witness_range`` (T-4), so no number the gateway claims can reach the vault's own
revision counter. The witness keeps the order the gateway gives, the order it first saw each
deployment.

:func:`witnessed` compares the witness with this vault's head (K.3): the revision of this
deployment the gateway has seen above the head is ``policy_behind_witness`` (the whole ``/state``
put back from an older backup while the gateway's volume wasn't); another deployment the gateway
has seen at revision 2 or more, and at least at the head, is ``policy_deployment_changed`` when
this deployment was first seen after it or the head is revision 1 (a ``/state`` wiped and seeded
again, T-5). Either is cleared by ``zoeymcp policy acknowledge-restore``, which numbers its
revision :attr:`Witnessed.target`, one above the claim, so the counter passes it. The number is
the gateway's claim, and the host types it (T-4).

A server is judged on its own (T-7): one whose name isn't a policy name is counted, not named
(``unnamed_servers``); one whose entry isn't a server's (another key, such as a definition, a wrong
type, a list past ``max_tools_per_server``, a count past its schema ceiling) is named in
``refused_servers`` and its data dropped; a tool name that isn't a tool name, or an unreviewed tool
whose pin isn't a pin, drops that entry alone and counts it in the server's ``dropped``. The rest of
the report stays, so a hostile upstream whose tool names the gateway passed on can't blind drift or
the new-tool signal on another server. Health raises ``server_listing_invalid`` for each such
server.

Each server's lists are the attention decision's, under K.1's names: ``drift`` its ``drifted``,
``marked``, ``unreviewed`` (``Attention.unreviewed()``, each with its pin), ``declined_changed``
its ``changed_declined`` and ``missing``. :meth:`ServerStatus.attention` reads them back into the
one decision (``attention.loaded``), so the vault never decides attention itself. ``blocked`` is
the gateway's own word that ``on_drift: fail`` stopped the server (``pins.evaluate``), which a
held mark on a tool no longer listed, or an included tool listed invalid, can trigger too.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Final, Literal

from ..common.policy.attention import Attention, loaded
from ..common.policy.schema import NAME_PATTERN
from ..common.reviewreport import NAMES_MAX
from .policyseal import REVISION_MAX as REVISION_MAX

Reason = Literal["invalid", "witness_range"]

# How many deployments the gateway's witness keeps (K.3).
WITNESS_DEPLOYMENTS_MAX: Final = 8
# A count the report carries (deployments seen) is at most this.
COUNT_MAX: Final = 2**31 - 1
VERSION: Final = 1
FRAME: Final = frozenset(
    {"v", "view", "started", "servers", "witness", "deployments_seen", "policy_mode"}
)
SERVER_KEYS: Final = frozenset(
    {
        "kind",
        "state",
        "blocked",
        "era",
        "included",
        "exposed",
        "marked",
        "unreviewed",
        "declined_changed",
        "drift",
        "missing",
        "invalid",
        "invalid_unnamed",
        "duplicate_unnamed",
        "offered",
    }
)
# The name lists of a server entry, by K.1's names.
NAME_LISTS: Final = ("marked", "declined_changed", "drift", "missing", "invalid")
KINDS: Final = frozenset({"remote", "toolkit"})
ERAS: Final = frozenset({"legacy", "modern"})
MODES: Final = frozenset({"managed", "declarative", "unknown"})
# A remote server's connection phases (``idle`` with none), or a toolkit's state.
STATES: Final = frozenset(
    {
        "idle",
        "connecting",
        "ready",
        "stale",
        "reconnecting",
        "failed",
        "closed",
        "loaded",
        "unavailable",
    }
)
OFFERED: Final = frozenset({"prompts", "resources", "completions", "logging"})
_NAME: Final = re.compile(NAME_PATTERN)
_TOOL: Final = re.compile(r"[A-Za-z0-9_.-]{1,128}")
_DIGEST: Final = re.compile(r"sha256:[0-9a-f]{64}")
_DEPLOYMENT: Final = re.compile(r"[0-9a-f]{32}")


@dataclass(frozen=True)
class Witnessed:
    """What the gateway's witness says of this vault's head (K.3): ``claim``, the highest revision
    of this deployment it has seen (None: none), and when above the head, ``behind``; ``other``,
    another deployment (its 32 hex) and its revision, when it raises
    ``policy_deployment_changed``."""

    claim: int | None = None
    behind: bool = False
    other: tuple[str, int] | None = None

    @property
    def target(self) -> int | None:
        """The revision ``acknowledge-restore`` writes: one above the highest claim that raises a
        finding, or None when none does."""
        claims = [self.claim] if self.behind and self.claim is not None else []
        if self.other is not None:
            claims.append(self.other[1])
        return max(claims) + 1 if claims else None


def witnessed(witness: Mapping[str, int], deployment: str, head: int) -> Witnessed:
    """The witness (deployments first seen first) against this vault's ``deployment`` at revision
    ``head``."""
    claim = witness.get(deployment)
    others: list[tuple[str, int]] = []
    for name, revision in witness.items():
        # Past revision 1, only the deployments seen before this one count.
        if name == deployment and head > 1:
            break
        if name != deployment and revision >= max(2, head):
            others.append((name, revision))
    other = max(others, key=lambda found: found[1]) if others else None
    return Witnessed(claim, claim is not None and claim > head, other)


class StatusRefused(ValueError):
    """The whole report is refused: ``reason`` is the log's and the answer's code."""

    def __init__(self, reason: Reason, detail: str) -> None:
        super().__init__(detail)
        self.reason: Reason = reason
        self.detail = detail


class _Bad(Exception):
    """A server entry that isn't a server's: the server is refused, the report kept."""


@dataclass(frozen=True)
class ServerStatus:
    """One server as the gateway reports it. ``dropped`` counts the entries the vault left out
    because a name or a pin wasn't one (T-7)."""

    kind: str
    state: tuple[str, ...]
    era: str | None
    included: int
    exposed: int
    marked: tuple[str, ...] = ()
    unreviewed: tuple[tuple[str, str], ...] = ()
    declined_changed: tuple[str, ...] = ()
    drift: tuple[str, ...] = ()
    missing: tuple[str, ...] = ()
    invalid: tuple[str, ...] = ()
    invalid_unnamed: int = 0
    duplicate_unnamed: int = 0
    offered: Mapping[str, bool] | None = None
    dropped: int = 0
    blocked: bool = False

    def attention(self) -> Attention:
        """The gateway's attention decision for the server, as its status names it."""
        changed = set(self.declined_changed)
        return loaded(
            {
                "drifted": self.drift,
                "marked": self.marked,
                "new": [name for name, _ in self.unreviewed if name not in changed],
                "changed_declined": self.declined_changed,
                "missing": self.missing,
            }
        )

    @property
    def unnamed(self) -> int:
        """The tools the gateway listed that the report can't name: its own counts and the
        entries the vault dropped."""
        return self.invalid_unnamed + self.duplicate_unnamed + self.dropped


@dataclass(frozen=True)
class Report:
    """One accepted status report."""

    view: str
    started: int
    servers: Mapping[str, ServerStatus]
    witness: Mapping[str, int] = field(default_factory=dict)
    deployments_seen: int = 0
    policy_mode: str = "unknown"
    # Servers named in the report whose entry the vault refused, and how many had no valid name.
    refused_servers: tuple[str, ...] = ()
    unnamed_servers: int = 0


@dataclass(frozen=True)
class GatewayStatus:
    """What health reads: the latest accepted report, or None before the first since the vault
    started, and ``age``, the seconds since it arrived (or since the vault started)."""

    report: Report | None
    age: float


def read(data: Any, max_tools: int) -> Report:
    """``data``, a strictly parsed JSON value, as a report; every name list at most
    ``max_tools`` long (``max_tools_per_server``). Raises :class:`StatusRefused`."""
    if not isinstance(data, dict) or set(data) != FRAME:
        raise StatusRefused("invalid", f"a status report has exactly {', '.join(sorted(FRAME))}")
    if not _integer(data["v"]) or data["v"] != VERSION:
        raise StatusRefused("invalid", "the status report's version isn't 1")
    view = data["view"]
    if not isinstance(view, str) or _DIGEST.fullmatch(view) is None:
        raise StatusRefused("invalid", "view must be sha256: and 64 hex digits")
    started = data["started"]
    if not _integer(started) or started < 0:
        raise StatusRefused("invalid", "started must be a whole number of seconds")
    witness = _witness(data["witness"])
    seen = data["deployments_seen"]
    if not _integer(seen) or not 0 <= seen <= COUNT_MAX:
        raise StatusRefused("invalid", "deployments_seen must be a count")
    mode = data["policy_mode"]
    if not isinstance(mode, str) or mode not in MODES:
        raise StatusRefused("invalid", "policy_mode must be managed, declarative or unknown")
    entries = data["servers"]
    if not isinstance(entries, dict):
        raise StatusRefused("invalid", "servers must be an object")
    servers: dict[str, ServerStatus] = {}
    refused: list[str] = []
    unnamed = 0
    for name, entry in entries.items():
        if _NAME.fullmatch(name) is None:
            unnamed += 1
            continue
        try:
            servers[name] = _server(entry, max_tools)
        except _Bad:
            refused.append(name)
    return Report(
        view=view,
        started=started,
        servers=MappingProxyType(dict(sorted(servers.items()))),
        witness=MappingProxyType(witness),
        deployments_seen=seen,
        policy_mode=mode,
        refused_servers=tuple(sorted(refused)),
        unnamed_servers=unnamed,
    )


def _witness(value: Any) -> dict[str, int]:
    """The deployments the gateway has seen and the highest revision of each (K.3), in the order
    it first saw them: at most :data:`WITNESS_DEPLOYMENTS_MAX`, each revision from 1 to
    :data:`REVISION_MAX`."""
    if not isinstance(value, dict) or len(value) > WITNESS_DEPLOYMENTS_MAX:
        raise StatusRefused("invalid", "witness must be an object of at most 8 deployments")
    found: dict[str, int] = {}
    for deployment, revision in value.items():
        if _DEPLOYMENT.fullmatch(deployment) is None or not _integer(revision) or revision < 1:
            raise StatusRefused("invalid", "a witness maps a deployment to a revision")
        if revision > REVISION_MAX:
            raise StatusRefused("witness_range", "a witness revision is above 9,999,999,999")
        found[deployment] = revision
    return found


def _server(entry: Any, max_tools: int) -> ServerStatus:
    """One server's entry, or :class:`_Bad`. Its bad names and pins are dropped and counted."""
    if not isinstance(entry, dict) or set(entry) != SERVER_KEYS:
        raise _Bad
    kind, era = entry["kind"], entry["era"]
    if not isinstance(kind, str) or kind not in KINDS:
        raise _Bad
    if not (era is None or (isinstance(era, str) and era in ERAS)):
        raise _Bad
    if not isinstance(entry["blocked"], bool):
        raise _Bad
    state = entry["state"]
    if (
        not isinstance(state, list)
        or not state
        or len(state) > len(STATES)
        or not all(isinstance(phase, str) and phase in STATES for phase in state)
    ):
        raise _Bad
    # The include list isn't held to the running max_tools_per_server (an operator may lower it),
    # so the two tool counts are held to its schema ceiling; the unnamed counts are capped lists.
    tools = [entry["included"], entry["exposed"]]
    if not all(_integer(count) and 0 <= count <= NAMES_MAX for count in tools):
        raise _Bad
    unnamed = [entry["invalid_unnamed"], entry["duplicate_unnamed"]]
    if not all(_integer(count) and 0 <= count <= max_tools for count in unnamed):
        raise _Bad
    dropped = 0
    lists: dict[str, tuple[str, ...]] = {}
    for key in NAME_LISTS:
        names, bad = _names(entry[key], max_tools)
        lists[key] = names
        dropped += bad
    unreviewed, bad = _pinned(entry["unreviewed"], max_tools)
    return ServerStatus(
        kind=kind,
        state=tuple(sorted(set(state))),
        era=era,
        included=tools[0],
        exposed=tools[1],
        unreviewed=unreviewed,
        invalid_unnamed=unnamed[0],
        duplicate_unnamed=unnamed[1],
        offered=_offered(entry["offered"]),
        dropped=dropped + bad,
        marked=lists["marked"],
        declined_changed=lists["declined_changed"],
        drift=lists["drift"],
        missing=lists["missing"],
        invalid=lists["invalid"],
        blocked=entry["blocked"],
    )


def _names(value: Any, max_tools: int) -> tuple[tuple[str, ...], int]:
    """A list of tool names, sorted and without repeats, and how many entries weren't one."""
    if not isinstance(value, list) or len(value) > max_tools:
        raise _Bad
    names = {name for name in value if isinstance(name, str) and _TOOL.fullmatch(name)}
    bad = sum(not (isinstance(name, str) and _TOOL.fullmatch(name)) for name in value)
    return tuple(sorted(names)), bad


def _pinned(value: Any, max_tools: int) -> tuple[tuple[tuple[str, str], ...], int]:
    """The unreviewed tools as ``[name, pin]`` pairs, sorted, and how many pairs weren't one."""
    if not isinstance(value, list) or len(value) > max_tools:
        raise _Bad
    found: dict[str, str] = {}
    bad = 0
    for pair in value:
        if (
            isinstance(pair, list)
            and len(pair) == 2
            and isinstance(pair[0], str)
            and isinstance(pair[1], str)
            and _TOOL.fullmatch(pair[0])
            and _DIGEST.fullmatch(pair[1])
        ):
            found[pair[0]] = pair[1]
        else:
            bad += 1
    return tuple(sorted(found.items())), bad


def _offered(value: Any) -> Mapping[str, bool] | None:
    """What the upstream advertises beyond tools (fold-in 3.8), or None before a connection."""
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != OFFERED:
        raise _Bad
    if not all(isinstance(flag, bool) for flag in value.values()):
        raise _Bad
    return MappingProxyType(dict(sorted(value.items())))


def _integer(value: Any) -> bool:
    """A JSON integer: an ``int`` that isn't a ``bool``."""
    return isinstance(value, int) and not isinstance(value, bool)
