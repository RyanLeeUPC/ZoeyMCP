"""The vault's hold table: every held and relayed call, from asked to its end (M8 design B.4,
D.3; Z6, Z8, Z23). Pure, mutation-tested.

Every method is synchronous and takes ``now`` (the monotonic clock), and nothing here does I/O, so
a check and its transition share one synchronous section on the vault's event loop (M4 build note
6c) and two answers can't interleave.

- **States.** A hold moves ``held -> approved -> forwarding -> done``, or ``held -> denied |
  expired | withdrawn``, by :data:`TRANSITIONS` and nothing else. The first valid decision wins,
  and a later one is refused by what happened (Z6). An approved hold whose ``decided accept``
  couldn't be written is not sent, and ends ``withdrawn`` (J.1).
- **Waiting** (B.6, Z23). A blocking hold whose caller is gone is withdrawn
  (:meth:`HoldTable.caller_gone`); past its block a ``wait=pending`` hold detaches
  (:meth:`HoldTable.detach`) and a ``wait=block`` one expires; an undecided hold expires at its
  deadline (:meth:`HoldTable.sweep`).
- **Caps** (D.3, Z8) count what the vault can verify: live holds and their bytes in all, per route
  and per (route, tool), an hourly count per (route, tool) and in all, and a cooldown after a deny
  or an expiry. The one cap keyed on the client the gateway reports (one undecided hold per
  reported client, server and tool) is fairness for an honest gateway only, and a call with no
  reported client has no fairness key. Each cap refusal counts towards
  the saturation notice, at most one per :data:`SATURATION_WINDOW` (:meth:`HoldTable.notice`).
- **Endings.** A hold that ends leaves the table, and its text with it; its ref and how it ended
  are kept as an :class:`Ending`, up to :data:`RECENT_ENDINGS` refs for :data:`ENDINGS_SECONDS`,
  so a ref is used once (E19, T-10) and a late answer is told what happened (G.6, I.3).
"""

from __future__ import annotations

import base64
import secrets
from collections import deque
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Final, Literal

from ..common.approvaltext import ApprovalText
from ..common.logs import refuse_type

State = Literal["held", "approved", "forwarding", "done", "denied", "expired", "withdrawn"]
Via = Literal["telegram", "portal", "host", "none"]  # host: a CLI withdraw
Surface = Literal["telegram", "portal"]
Kind = Literal["held", "relay"]
Wait = Literal["block", "pending"]

# The closed transition table (Z6). approved -> withdrawn: its decided record couldn't be written.
TRANSITIONS: Final[Mapping[State, frozenset[State]]] = MappingProxyType(
    {
        "held": frozenset({"approved", "denied", "expired", "withdrawn"}),
        "approved": frozenset({"forwarding", "withdrawn"}),
        "forwarding": frozenset({"done"}),
        "done": frozenset(),
        "denied": frozenset(),
        "expired": frozenset(),
        "withdrawn": frozenset(),
    }
)
TERMINAL: Final[frozenset[State]] = frozenset({"done", "denied", "expired", "withdrawn"})
# The endings that start the (route, tool) cooldown: a human's refusal, or nobody answering.
COOLDOWN_STATES: Final[frozenset[State]] = frozenset({"denied", "expired"})

MAX_HOLDS: Final = 64
MAX_HELD_BYTES: Final = 16 * 1024 * 1024
MAX_PER_ROUTE: Final = 16
MAX_PER_TOOL: Final = 4
HOURLY_GLOBAL: Final = 300
HOUR: Final = 3600.0
SATURATION_WINDOW: Final = 600.0
TOOLKIT_HOLD_MARGIN: Final = 30.0  # a toolkit write waits its call_timeout minus this (B.7)
RECENT_ENDINGS: Final = 4096
ENDINGS_SECONDS: Final = 24 * HOUR
ID_BYTES: Final = 12  # 16 base64url characters: the surfaces' handle


def new_id() -> str:
    """A hold's id: 12 random bytes, base64url (16 characters, no padding)."""
    return base64.urlsafe_b64encode(secrets.token_bytes(ID_BYTES)).decode()


def toolkit_block(call_timeout: float) -> float:
    """How long a toolkit write blocks: its toolkit server's ``call_timeout`` minus
    :data:`TOOLKIT_HOLD_MARGIN`, so the toolkit body has time to finish after the send (B.7)."""
    return max(call_timeout - TOOLKIT_HOLD_MARGIN, 0.0)


def _seconds(value: float) -> int:
    """Whole seconds, rounded up, never below 1: "cooling down for 0 s" would be false."""
    return max(1, int(-(-value // 1)))


# --- records -------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Limits:
    """What the vault's own policy sets for every hold (I.1 step 3): never a gateway header."""

    timeout: float  # approvers.timeout: every hold's deadline
    block_seconds: float  # approvers.block_seconds
    cooldown: float  # gateway.approvals.cooldown
    max_prompts_per_hour: int  # gateway.approvals.max_prompts_per_hour, per (route, tool)


@dataclass(frozen=True, repr=False)
class HoldRequest:
    """What the vault asks a hold for. Logging it raises: it holds the text."""

    ref: str  # the marker's or the ask's ref, or one the vault minted (B.3)
    kind: Kind
    epoch: str | None  # the gateway epoch from the marker or the ask (E.2)
    legacy_session: bool  # the held request carried an Mcp-Session-Id (E.2's epoch rule)
    route: str
    server: str
    tool: str
    client: str | None  # reported by the gateway
    args_digest: str  # HMAC under the chain key (J.1)
    text: ApprovalText
    text_sha256: str
    surfaces: frozenset[Surface]
    wait: Wait
    held_bytes: int
    # A toolkit write's own block (B.7, toolkit_block); None: approvers.block_seconds.
    block_seconds: float | None = None


@dataclass(frozen=True, repr=False)
class Hold:
    """One held or relayed call. Logging it raises: it holds the text (Z14)."""

    id: str  # 12 random bytes, base64url (16 chars): the surfaces' handle
    ref: str  # the gateway's ref, or minted
    kind: Kind
    epoch: str | None
    legacy_session: bool
    route: str
    server: str
    tool: str
    client: str | None  # reported by the gateway
    args_digest: str  # memory only
    text: ApprovalText  # memory only; refuses logging
    text_sha256: str
    surfaces: frozenset[Surface]
    wait: Wait
    asked_at: float
    block_until: float
    deadline: float
    held_bytes: int
    state: State = "held"
    via: Via | None = None
    # No request waits for it any more: detached as pending, or its caller left after approval.
    detached: bool = False
    decided_at: float | None = None  # when it was decided, or ended undecided
    detail: str | None = None  # a withdrawal's reason, or a forward's outcome

    def __repr__(self) -> str:
        return f"Hold(id={self.id}, ref={self.ref}, state={self.state})"

    @property
    def ends_at(self) -> float:
        """When it expires undecided: a blocking-only hold at its block, any other at its
        deadline (B.6)."""
        return self.block_until if self.wait == "block" else self.deadline


refuse_type(HoldRequest)
refuse_type(Hold)


@dataclass(frozen=True)
class Ending:
    """How a hold ended, kept after its text is gone. ``id`` is None for an ending rebuilt from
    the chain at start (J.1), whose approval id died with the process."""

    ref: str
    id: str | None
    client: str | None
    state: State
    via: Via | None
    decided_at: float | None
    detail: str | None
    ended_at: float


# --- answers -------------------------------------------------------------------------------------


@dataclass(frozen=True)
class CapRefusal:
    """Why a hold isn't begun (D.3), code ``held_<reason>``; nothing is asked."""

    reason: Literal["capacity", "busy", "hourly", "cooldown", "ref_reused"]
    seconds_left: int = 0  # a cooldown's

    @property
    def code(self) -> str:
        return f"held_{self.reason}"

    @property
    def status(self) -> int:
        return 409 if self.reason == "ref_reused" else 429


@dataclass(frozen=True)
class Decided:
    """The decision was taken: ``hold`` is now approved (start its forward) or denied."""

    hold: Hold


@dataclass(frozen=True)
class DecideRefusal:
    """Why a decision isn't taken (H.3, M.2); ``via`` and ``at`` name the decision that won."""

    reason: Literal["unknown", "already_decided", "expired", "withdrawn", "digest_changed"]
    via: Via | None = None
    at: float | None = None


class TransitionError(ValueError):
    """A move :data:`TRANSITIONS` doesn't allow: a vault bug, never an answer."""


def may_move(current: State, to: State) -> bool:
    return to in TRANSITIONS[current]


def from_earlier_epoch(epoch: str) -> Callable[[Hold], bool]:
    """The holds a gateway's new ``epoch`` withdraws (E.2): relays, and held calls whose request
    carried a legacy session, from another epoch. A modern held call stays collectable."""

    def picks(hold: Hold) -> bool:
        if hold.epoch is None or hold.epoch == epoch:
            return False
        return hold.kind == "relay" or hold.legacy_session

    return picks


# --- the table -----------------------------------------------------------------------------------


class HoldTable:
    """Every hold of one vault process (Z10: memory only)."""

    def __init__(self, limits: Limits) -> None:
        self.limits = limits
        self._live: dict[str, Hold] = {}  # id -> hold; insertion order is age order
        self._refs: dict[str, str] = {}  # ref -> id, live holds
        self._endings: dict[str, Ending] = {}  # ref -> ending; insertion order is age order
        self._ended_ids: dict[str, str] = {}  # id -> ref, endings that have one
        self._asked: dict[tuple[str, str], deque[float]] = {}  # (route, tool) -> begin times
        self._asked_all: deque[float] = deque()
        # (route, tool) -> until; one per held tool at most, so none is pruned.
        self._cooldowns: dict[tuple[str, str], float] = {}
        self._refused: deque[float] = deque()  # cap refusals in the saturation window
        self._noticed: float | None = None

    def configure(self, limits: Limits) -> None:
        """New limits from a newly installed policy; holds already begun keep their times."""
        self.limits = limits

    # --- reading ---------------------------------------------------------------------------

    def __len__(self) -> int:
        return len(self._live)

    def holds(self) -> Iterator[Hold]:
        return iter(list(self._live.values()))

    def get(self, id: str) -> Hold | None:
        return self._live.get(id)

    def by_ref(self, ref: str) -> Hold | None:
        id = self._refs.get(ref)
        return self._live.get(id) if id is not None else None

    def ending(self, ref: str) -> Ending | None:
        return self._endings.get(ref)

    def knows(self, ref: str) -> bool:
        """Whether ``ref`` is held or recently ended here (the table's half of E19)."""
        return ref in self._refs or ref in self._endings

    # --- writing ---------------------------------------------------------------------------

    def begin(self, now: float, request: HoldRequest) -> Hold | CapRefusal:
        """Hold a call, or say why not. A ref is used once; every other refusal is a cap's."""
        self._prune(now)
        if self.knows(request.ref):
            return CapRefusal("ref_reused")
        refused = self._capped(now, request)
        if refused is not None:
            self._refused.append(now)
            return refused
        deadline = now + self.limits.timeout
        block = request.block_seconds
        if block is None:
            block = self.limits.block_seconds
        hold = Hold(
            id=new_id(),
            ref=request.ref,
            kind=request.kind,
            epoch=request.epoch,
            legacy_session=request.legacy_session,
            route=request.route,
            server=request.server,
            tool=request.tool,
            client=request.client,
            args_digest=request.args_digest,
            text=request.text,
            text_sha256=request.text_sha256,
            surfaces=request.surfaces,
            wait=request.wait,
            asked_at=now,
            block_until=min(now + block, deadline),
            deadline=deadline,
            held_bytes=request.held_bytes,
        )
        self._live[hold.id] = hold
        self._refs[hold.ref] = hold.id
        self._asked.setdefault((hold.route, hold.tool), deque()).append(now)
        self._asked_all.append(now)
        return hold

    def decide(
        self, now: float, id: str, decision: Literal["approve", "deny"], via: Via, text_sha256: str
    ) -> Decided | DecideRefusal:
        """The first valid decision on a hold still held, unexpired, shown on ``via`` and with
        the text the surface showed. An approved hold's forward starts from this answer only."""
        hold = self._live.get(id)
        if hold is None:
            return self._refusal(id)
        if hold.state != "held":
            return DecideRefusal("already_decided", hold.via, hold.decided_at)
        if via not in hold.surfaces:
            return DecideRefusal("unknown")
        if now >= hold.ends_at:
            return DecideRefusal("expired")
        if text_sha256 != hold.text_sha256:
            return DecideRefusal("digest_changed")
        if decision == "approve":
            return Decided(self._move(hold, "approved", now, via=via))
        return Decided(self._move(hold, "denied", now, via=via))

    def caller_gone(self, now: float, id: str) -> Hold | None:
        """The blocking caller left (either era, B.6): an undecided hold is withdrawn
        (``stream_lost``) and returned; an approved one finishes, and its answer goes to the
        result store. A detached hold has no caller to lose."""
        hold = self._live.get(id)
        if hold is None or hold.detached:
            return None
        if hold.state == "held":
            return self._move(hold, "withdrawn", now, via="none", detail="stream_lost")
        self._live[id] = replace(hold, detached=True)
        return None

    def detach(self, now: float, id: str) -> Hold | None:
        """The block is over, or the gateway's stop detached it (I.2): a ``wait=pending`` hold
        lives on without its request, until its deadline. None for a ``wait=block`` hold (it
        expires or is withdrawn instead) or one already detached."""
        hold = self._live.get(id)
        if hold is None or hold.detached or hold.wait != "pending":
            return None
        detached = replace(hold, detached=True)
        self._live[id] = detached
        return detached

    def forwarding(self, id: str) -> None:
        """The approved forward starts, after ``decided accept`` is fsynced."""
        hold = self._require(id)
        if not may_move(hold.state, "forwarding"):
            raise TransitionError(f"{hold.state} -> forwarding")
        self._live[id] = replace(hold, state="forwarding")

    def done(self, now: float, id: str, outcome: str) -> None:
        """The forward ended with ``outcome`` (``ok``, ``tool_error``, ``upstream_error``, ...)."""
        self._move(self._require(id), "done", now, detail=outcome)

    def unrecorded(self, now: float, id: str) -> Hold:
        """An approved hold whose ``decided accept`` couldn't be written: not sent, withdrawn
        (J.1, detail ``ledger``)."""
        hold = self._require(id)
        if hold.state != "approved":
            raise TransitionError(f"{hold.state} -> withdrawn")
        return self._move(hold, "withdrawn", now, detail="ledger")

    def withdraw(
        self, now: float, which: Callable[[Hold], bool], reason: str, *, via: Via = "none"
    ) -> list[Hold]:
        """Withdraw every undecided hold ``which`` picks (a policy change, a new gateway epoch,
        a stop, a host's withdraw with ``via="host"``). An approved forward is committed and
        never withdrawn (Z9)."""
        found = [hold for hold in self._live.values() if hold.state == "held" and which(hold)]
        return [self._move(hold, "withdrawn", now, via=via, detail=reason) for hold in found]

    def sweep(self, now: float) -> list[Hold]:
        """Every undecided hold past its end, expired (the sweeper runs once a second)."""
        found = [h for h in self._live.values() if h.state == "held" and now >= h.ends_at]
        expired = [self._move(hold, "expired", now, via="none") for hold in found]
        self._prune(now)
        return expired

    def remember(
        self,
        now: float,
        ref: str,
        state: State,
        detail: str | None = None,
        *,
        client: str | None,
        ended_at: float,
    ) -> None:
        """An ending the chain's recovery found at start (J.1), so its ref stays used and its
        reported ``client`` is told how it ended (F.5 step 4). ``ended_at`` is when it ended, on
        this table's clock; recovery gives them oldest first, and one already a day old is not
        kept."""
        if ended_at > now - ENDINGS_SECONDS:
            self._end(Ending(ref, None, client, state, None, None, detail, ended_at))

    # --- saturation ------------------------------------------------------------------------

    def saturated(self, now: float) -> int:
        """Cap refusals in the last :data:`SATURATION_WINDOW` (``approvals_saturated``)."""
        self._prune(now)
        return len(self._refused)

    def notice(self, now: float) -> int | None:
        """The refusals to tell the surfaces of, at most once per window, or None."""
        count = self.saturated(now)
        if not count:
            return None
        if self._noticed is not None and now - self._noticed < SATURATION_WINDOW:
            return None
        self._noticed = now
        return count

    # --- helpers ---------------------------------------------------------------------------

    def _capped(self, now: float, request: HoldRequest) -> CapRefusal | None:
        live = list(self._live.values())
        if len(live) >= MAX_HOLDS:
            return CapRefusal("capacity")
        if sum(hold.held_bytes for hold in live) + request.held_bytes > MAX_HELD_BYTES:
            return CapRefusal("capacity")
        if sum(1 for hold in live if hold.route == request.route) >= MAX_PER_ROUTE:
            return CapRefusal("capacity")
        tool = (request.route, request.tool)
        if sum(1 for hold in live if (hold.route, hold.tool) == tool) >= MAX_PER_TOOL:
            return CapRefusal("capacity")
        # Fairness keys on a reported client only: an unreported one has no identity to share.
        key = (request.client, request.server, request.tool)
        if request.client is not None and any(
            h.state == "held" and (h.client, h.server, h.tool) == key for h in live
        ):
            return CapRefusal("busy")
        if len(self._asked.get(tool, ())) >= self.limits.max_prompts_per_hour:
            return CapRefusal("hourly")
        if len(self._asked_all) >= HOURLY_GLOBAL:
            return CapRefusal("hourly")
        until = self._cooldowns.get(tool)
        if until is not None and until > now:
            return CapRefusal("cooldown", _seconds(until - now))
        return None

    def _refusal(self, id: str) -> DecideRefusal:
        """A decision on a hold no longer in the table: what happened to it, when it's known."""
        ref = self._ended_ids.get(id)
        ending = self._endings.get(ref) if ref is not None else None
        if ending is None:
            return DecideRefusal("unknown")
        if ending.state == "expired":
            return DecideRefusal("expired")
        if ending.state == "withdrawn":
            return DecideRefusal("withdrawn")  # H.3's own reason, not FM-29's already_decided
        return DecideRefusal("already_decided", ending.via, ending.decided_at)

    def _require(self, id: str) -> Hold:
        hold = self._live.get(id)
        if hold is None:
            raise TransitionError(f"no live hold {id}")
        return hold

    def _move(
        self,
        hold: Hold,
        state: State,
        now: float,
        *,
        via: Via | None = None,
        detail: str | None = None,
    ) -> Hold:
        if not may_move(hold.state, state):
            raise TransitionError(f"{hold.state} -> {state}")
        moved = replace(
            hold,
            state=state,
            via=hold.via if via is None else via,
            decided_at=hold.decided_at if hold.decided_at is not None else now,
            detail=hold.detail if detail is None else detail,
        )
        if state not in TERMINAL:
            self._live[hold.id] = moved
            return moved
        del self._live[hold.id]
        del self._refs[hold.ref]
        self._end(
            Ending(
                moved.ref,
                moved.id,
                moved.client,
                state,
                moved.via,
                moved.decided_at,
                moved.detail,
                now,
            )
        )
        if state in COOLDOWN_STATES:
            self._cooldowns[(hold.route, hold.tool)] = now + self.limits.cooldown
        return moved

    def _end(self, ending: Ending) -> None:
        self._endings[ending.ref] = ending
        if ending.id is not None:
            self._ended_ids[ending.id] = ending.ref
        while len(self._endings) > RECENT_ENDINGS:
            self._forget(next(iter(self._endings)))

    def _forget(self, ref: str) -> None:
        ending = self._endings.pop(ref)
        if ending.id is not None:
            del self._ended_ids[ending.id]

    def _prune(self, now: float) -> None:
        for ref, ending in list(self._endings.items()):
            if ending.ended_at > now - ENDINGS_SECONDS:
                break
            self._forget(ref)
        for tool, times in list(self._asked.items()):
            while times and times[0] <= now - HOUR:
                times.popleft()
            if not times:
                del self._asked[tool]
        while self._asked_all and self._asked_all[0] <= now - HOUR:
            self._asked_all.popleft()
        while self._refused and self._refused[0] <= now - SATURATION_WINDOW:
            self._refused.popleft()
