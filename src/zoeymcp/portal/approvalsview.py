"""The portal's Approvals queue (M8 design H.1-H.3; Z16, G-11; fold-in 2.30, 3.2, 3.3). Pure,
mutation-tested.

The queue reads the vault's hold table and the portal surface's endings; this turns them into what
the page shows, as text only, and decides what a portal decision may do:

- **Waiting** (:func:`queue`): every undecided hold shown on the portal, oldest first, each with
  its ref, server, tool, the client the gateway reported, held by the vault or relayed from the
  gateway, when it was asked and when it must be answered (absolute UTC, and the wall-clock
  seconds the page counts down from: no relative time is in an answer), its surfaces, and "not
  delivered to Telegram" while Telegram hasn't taken its prompt (G.3). **Decided recently**: the
  holds approved and still running, then the last endings the surface kept, newest first, at most
  :data:`DECIDED_SHOWN`, each with its outcome ("approved here 14:03 UTC; sent: ok", G-11).
- **One hold** (:func:`detail`): its row, its composed text whole with that text's SHA-256, which a
  decision is bound to, and the text again as lines in chunks of :data:`CHUNK` code points, nothing
  cut (``reviewview``'s rule), so no 200-character cap of ``display.shown`` cuts it. The text has
  passed the vault's text rules; each chunk is revealed all the same.
- **A decision** (:func:`check`, :func:`decide_plan`, H.3): the checks ``HoldTable.decide`` makes,
  in its order, each refused with its own reason: an unknown hold, or one not shown here,
  ``approval_unknown``; one decided, ``already_decided``, naming where, when and how; one past its
  end, ``expired``; one withdrawn, ``withdrawn``; a digest of another text, ``digest_changed``.
  An approval's plan is the whole text, the server, tool, reported client, when it was asked and
  its deadline, absolute, and :data:`APPROVE_SENTENCE`, so a re-plan at the confirm compares equal
  unless the hold moved (M5 build notes 6b, 9a). Deny is ``check`` alone: it can send nothing.
- **The turn-on lines** (:func:`turn_on_lines`, A.4, J2): what marking a tool ``vault_approval``
  changes for each client the server is given to, and whether its route holds a credential.

Every time comes through ``wall``, the vault's one mapping from the hold table's clock to the
wall clock, so the same hold reads the same on every call.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final, Literal, Protocol

from ..common.policy.fields import UNIX_PREFIX
from ..common.policy.schema import Client, Policy, RemoteServer, Route, ToolkitServer
from ..common.textrules import reveal_hidden
from ..vault.holds import Ending, Hold, Kind, State, Via
from .display import NAME_LIMIT, shown

# A time on the hold table's clock, as wall-clock seconds (``VaultApp.hold_wall``).
Wall = Callable[[float], float]
# The longest run of a line shown as one piece (``reviewview``'s CHUNK).
CHUNK: Final = 200
DECIDED_SHOWN: Final = 20
APPROVE_SENTENCE: Final = "Approve runs this one call, exactly as shown."
HOW: Final[Mapping[Kind, str]] = {"held": "Held by the vault", "relay": "Relayed from the gateway"}
NOT_DELIVERED: Final = "not delivered to Telegram"
# Where a decision was taken: in Decided recently ("here" is this queue), and in a refusal.
WHERE: Final[Mapping[str, str]] = {"portal": " here", "telegram": " in Telegram"}
DECIDED_WHERE: Final[Mapping[str, str]] = {"portal": "in the portal", "telegram": "in Telegram"}
NOTHING_SENT: Final = "nothing was sent"
# A forward's outcome, as Decided recently says it (G.6's words).
RESULTS: Final[Mapping[str, str]] = {
    "ok": "sent: ok",
    "tool_error": "sent: the server answered an error",
    "upstream_error": "sent: the server answered an error",
    "relayed": "the gateway runs it: see the Ledger",
    "refused": NOTHING_SENT,
    "not_sent": NOTHING_SENT,
}
UNKNOWN_RESULT: Final = "the outcome is unknown: see the Ledger"
# A withdrawal's reason (the hold's detail), as Decided recently says it.
WITHDRAWN: Final[Mapping[str, str]] = {
    "changed": "the policy changed",
    "shutdown": "the vault stopped",
    "stream_lost": "the agent cancelled",
    "caller_cancelled": "the agent cancelled",
    "gateway_restarted": "the gateway restarted",
    "gateway_stopped": "the gateway stopped",
    "ledger": "the vault couldn't record it",
    "not_shown": "no approver could show it",
    "busy": "the vault had no room for its result",
}
APPROVED: Final = frozenset({"approved", "forwarding"})
Reason = Literal[
    "bad_body", "approval_unknown", "already_decided", "expired", "withdrawn", "digest_changed"
]


class Closed(Protocol):
    """A hold the portal surface closed (``vault/approvers.py``'s :class:`Closed`)."""

    @property
    def id(self) -> str: ...
    @property
    def ref(self) -> str: ...
    @property
    def kind(self) -> Kind: ...
    @property
    def server(self) -> str: ...
    @property
    def tool(self) -> str: ...
    @property
    def client(self) -> str | None: ...
    @property
    def state(self) -> State: ...
    @property
    def via(self) -> Via | None: ...
    @property
    def decided_at(self) -> float | None: ...
    @property
    def detail(self) -> str | None: ...


@dataclass(frozen=True)
class Refused:
    """Why a portal decision isn't taken (H.3, M.2): the catalogue's reason, and the fields its
    text names (``already_decided``'s ``where``, ``at`` and ``decision``)."""

    reason: Reason
    fields: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class Planned:
    """``approval.decide``'s plan: its summary rows, and the hold and digest it decides."""

    summary: tuple[tuple[str, str], ...]
    facts: tuple[str, str]


def utc(wall: float) -> str:
    """``YYYY-MM-DD HH:MM UTC``."""
    return datetime.fromtimestamp(wall, UTC).strftime("%Y-%m-%d %H:%M UTC")


def clock(wall: float) -> str:
    """``HH:MM``, in UTC."""
    return datetime.fromtimestamp(wall, UTC).strftime("%H:%M")


def text_lines(text: str) -> list[list[str]]:
    """``text``'s lines, each in chunks of at most :data:`CHUNK` code points, nothing cut:
    joined, each line's chunks are the line, and the lines joined with line breaks the text."""
    return [
        [reveal_hidden(line[start : start + CHUNK]) for start in range(0, len(line), CHUNK)] or [""]
        for line in text.split("\n")
    ]


# --- the lists (H.1) ------------------------------------------------------------------------------


def waiting(holds: Iterable[Hold]) -> list[Hold]:
    """The undecided holds shown on the portal, oldest first."""
    found = [hold for hold in holds if hold.state == "held" and "portal" in hold.surfaces]
    return sorted(found, key=lambda hold: hold.asked_at)


def row(hold: Hold, wall: Wall, delivered: Callable[[str], bool]) -> dict[str, Any]:
    """One waiting hold, as the queue lists it. ``delivered`` says whether Telegram took a
    hold's prompt (by its approval id)."""
    asked, deadline = wall(hold.asked_at), wall(hold.ends_at)
    undelivered = "telegram" in hold.surfaces and not delivered(hold.id)
    return {
        **_names(hold),
        "asked": int(asked),
        "asked_shown": utc(asked),
        "deadline": int(deadline),
        "deadline_shown": utc(deadline),
        "surfaces": sorted(hold.surfaces),
        "telegram_shown": NOT_DELIVERED if undelivered else None,
    }


def queue(
    holds: Iterable[Hold],
    closed: Iterable[Closed],
    wall: Wall,
    delivered: Callable[[str], bool],
    *,
    enabled: bool,
    notice: str | None,
) -> dict[str, Any]:
    """``GET /api/approvals``: Waiting and Decided recently, whether the queue is enabled
    (``approvers.portal``), and the saturation notice while it lasts (D.3)."""
    live = list(holds)
    running = [hold for hold in live if hold.state in APPROVED and "portal" in hold.surfaces]
    running.sort(key=lambda hold: hold.decided_at or 0.0, reverse=True)
    decided = [_decided(hold, wall) for hold in running]
    decided += [_decided(hold, wall) for hold in closed]
    return {
        "enabled": enabled,
        "notice": notice,
        "waiting": [row(hold, wall, delivered) for hold in waiting(live)],
        "decided": decided[:DECIDED_SHOWN],
    }


def detail(hold: Hold, wall: Wall, delivered: Callable[[str], bool]) -> dict[str, Any]:
    """``GET /api/approvals/{approval}``: the hold's row, its state, and its text whole, with
    the digest a decision sends back."""
    return {
        **row(hold, wall, delivered),
        "state": "waiting" if hold.state == "held" else hold.state,
        "text": hold.text.value,
        "text_sha256": hold.text_sha256,
        "text_lines": text_lines(hold.text.value),
    }


def outcome(state: State, via: Via | None, detail: str | None, at: str) -> str:
    """How a decided hold went, in words: where and when it was decided, then what was sent."""
    where = WHERE.get(via or "", "")
    if state in APPROVED:
        return f"approved{where} {at} UTC; sending"
    if state == "done":
        return f"approved{where} {at} UTC; {RESULTS.get(detail or '', UNKNOWN_RESULT)}"
    if state == "denied":
        return f"denied{where} {at} UTC; {NOTHING_SENT}"
    if state == "expired":
        return f"expired {at} UTC; {NOTHING_SENT}"
    if via == "host":
        return f"withdrawn by the operator {at} UTC; {NOTHING_SENT}"
    reason = WITHDRAWN.get(detail or "")
    said = "" if reason is None else f": {reason}"
    return f"withdrawn {at} UTC{said}; {NOTHING_SENT}"


def _names(hold: Hold | Closed) -> dict[str, Any]:
    client = hold.client
    return {
        "approval": hold.id,
        "ref": hold.ref,
        "kind": hold.kind,
        "how_shown": HOW[hold.kind],
        "server_shown": shown(hold.server, NAME_LIMIT),
        "tool_shown": shown(hold.tool, NAME_LIMIT),
        "client_shown": None if client is None else shown(client, NAME_LIMIT),
    }


def _decided(hold: Hold | Closed, wall: Wall) -> dict[str, Any]:
    at = "" if hold.decided_at is None else clock(wall(hold.decided_at))
    return {
        **_names(hold),
        "state": hold.state,
        "outcome_shown": outcome(hold.state, hold.via, hold.detail, at),
    }


# --- a decision (H.3) -----------------------------------------------------------------------------


def gone(ending: Ending | None, wall: Wall) -> Refused:
    """A decision on a hold no longer in the table, by how it ended: unknown when its ending
    isn't kept (or a restart took its id)."""
    if ending is None:
        return Refused("approval_unknown")
    if ending.state == "expired":
        return Refused("expired")
    if ending.state == "withdrawn":
        return Refused("withdrawn")
    decision = "approved" if ending.state == "done" else "denied"
    return _already(ending.via, ending.decided_at, decision, wall)


def check(
    hold: Hold | None, ending: Ending | None, digest: str, *, now: float, wall: Wall
) -> Refused | None:
    """``HoldTable.decide``'s checks, in its order, for a decision through the portal on
    ``hold`` (or, gone, its ``ending``) bound to ``digest``: None when it would be taken."""
    if hold is None:
        return gone(ending, wall)
    if hold.state != "held":
        return _already(hold.via, hold.decided_at, "approved", wall)
    if "portal" not in hold.surfaces:
        return Refused("approval_unknown")
    if now >= hold.ends_at:
        return Refused("expired")
    if digest != hold.text_sha256:
        return Refused("digest_changed")
    return None


def decide_plan(
    data: Mapping[str, Any],
    hold: Hold | None,
    ending: Ending | None,
    *,
    now: float,
    wall: Wall,
) -> Planned | Refused:
    """``approval.decide``'s plan (H.3): ``data`` names the hold, the digest of the text the
    operator was shown, and ``decision``, only ever ``approve`` (deny has its own route)."""
    approval, digest = data["approval"], data["text_sha256"]
    if not isinstance(approval, str) or not isinstance(digest, str):
        return Refused("bad_body")
    if data["decision"] != "approve":
        return Refused("bad_body")
    refused = check(hold, ending, digest, now=now, wall=wall)
    if refused is not None:
        return refused
    assert hold is not None  # noqa: S101 - check refuses a hold that is gone
    client = "not reported" if hold.client is None else shown(hold.client, NAME_LIMIT)
    summary = (
        ("Approval request", hold.ref),
        ("How", HOW[hold.kind]),
        ("Server", shown(hold.server, NAME_LIMIT)),
        ("Tool", shown(hold.tool, NAME_LIMIT)),
        ("Client, as the gateway reports it", client),
        ("Asked", utc(wall(hold.asked_at))),
        ("Answer by", utc(wall(hold.ends_at))),
        ("The request, whole", hold.text.value),
        ("Approve", APPROVE_SENTENCE),
    )
    return Planned(summary, (hold.id, hold.text_sha256))


def _already(via: Via | None, at: float | None, decision: str, wall: Wall) -> Refused:
    where = DECIDED_WHERE.get(via or "", "elsewhere")
    when = "an unknown time" if at is None else clock(wall(at)) + " UTC"
    return Refused("already_decided", (("where", where), ("at", when), ("decision", decision)))


# --- the turn-on lines (A.4, J2) ------------------------------------------------------------------


def turn_on_lines(
    policy: Policy,
    server: str,
    tool: str,
    *,
    served: RemoteServer | ToolkitServer | None,
    clients: Mapping[str, Client],
) -> list[str]:
    """What holding ``tool`` of ``server`` in the vault changes (G-5): who is asked where, for
    each client the server is given to, and whether its route holds a credential (A.2 row 6's
    fact). ``served`` is the policy's server ``server`` (None: it has none, and nothing
    changes) and ``clients`` its clients, which the vault side reads: portal code names no part
    of the policy's gateway block (``test_no_secret_answers``); ``policy`` gives the routes and
    the approvers."""
    if served is None:
        return []
    lines = [
        f"{server}.{tool}: vault_approval on.",
        f"  The vault will hold every call to {tool} and ask you {_asked_on(policy)}. The "
        "gateway will no longer ask in the agent's own client.",
    ]
    for name, client in sorted(clients.items()):
        if server not in client.servers:
            continue
        own = client.approvals
        if own is not None and own.out_of_band:
            lines.append(f"  {name} (out of band): asked on your approvers, as before.")
        elif own is not None and own.attended:
            lines.append(f"  {name} (attended): asked on your approvers instead of in its client.")
        else:
            lines.append(
                f'  {name} (neither): refused, as before ("nobody answers for this client").'
            )
    routes = {route.name: route for route in policy.routes}
    if isinstance(served, RemoteServer):
        used = [served.route]
    else:
        used = sorted(
            {
                slot.route
                for slot in served.slots.values()
                if any(rule.approved for rule in slot.rules)
            }
        )
    lines += [_route_line(routes[name]) for name in used if name in routes]
    return lines


def _asked_on(policy: Policy) -> str:
    approvers = policy.approvers
    telegram = approvers is not None and approvers.telegram is not None
    portal = approvers is not None and approvers.portal is not None
    if telegram and portal:
        return "on Telegram or in the Approvals queue"
    if telegram:
        return "on Telegram"
    if portal:
        return "in the Approvals queue"
    return "on your approvers, once one is set up"


def _route_line(route: Route) -> str:
    if route.connector is not None:
        return (
            f"  Route {route.name} is connector {route.connector}'s: a compromised gateway can't "
            "send through it directly."
        )
    if route.credential is not None:
        return (
            f"  Route {route.name} holds a credential: a compromised gateway can't call the "
            "server directly."
        )
    if (route.upstream or "").startswith(UNIX_PREFIX):
        return (
            f"  Route {route.name} reaches a bridge's socket: a compromised gateway can't call "
            "the server directly."
        )
    return (
        f"  Route {route.name} holds no credential: in the standard tier the gateway shares the "
        "vault's network and can reach this upstream itself; vault_approval holds here only in "
        "the hardened tier."
    )
