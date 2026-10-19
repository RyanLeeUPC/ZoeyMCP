"""The approval core: the pending table, locks, rate limits, handles and decisions (M4 design E).

Pure and synchronous: every method takes ``now`` (the monotonic clock), and nothing here does
I/O, so :mod:`.approve` serializes calls with one lock and the rules can be tested exhaustively.

- **The lock** is per (client, server, tool), held from :meth:`Table.begin` through the forward
  to :meth:`Table.finish`, and only the record's own ref frees it, so a late ``finally`` can't free
  a newer call's lock. Every record has a hard deadline past which :meth:`Table.sweep` frees it.
- **Undecided prompts** count against the client's pending cap from ``begin`` to
  :meth:`Table.decide`; every ``begin`` counts against the client's rolling hourly cap.
- **The cooldown** starts at ``finish`` after a decision a human made against the call (or a
  timeout or mismatch), and refuses that tool for the client until it ends.
- **Handles** (modern) are single-use: the table keeps only their SHA-256, and a consumed or
  expired handle leaves a tombstone, so a replay reads "already used" or "no answer in time".
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
from collections import deque
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field, replace
from typing import Any, Final, Literal

from ..common.logs import refuse_type

Era = Literal["legacy", "modern"]
Decision = Literal[
    "accept",
    "decline",
    "dismiss",
    "code_mismatch",
    "timeout",
    "withdrawn",
    "stream_lost",
    "unavailable",
    "error",
    "mismatch",
    "changed",
    "shutdown",
]
# The one list of decisions that start a cooldown (E.1). The others weren't a human's refusal,
# and the hourly cap still bounds a cycle of ask and cancel.
COOLDOWN_DECISIONS: Final = frozenset(
    {"decline", "dismiss", "code_mismatch", "timeout", "mismatch"}
)

MAX_RECORDS: Final = 1024
MAX_TOMBSTONES: Final = 4096
TOMBSTONE_SECONDS: Final = 600.0
HARD_DEADLINE_MARGIN: Final = 30.0
HOUR: Final = 3600.0
MAX_ASKS: Final = 3  # a modern prompt is re-asked at most this many times in all

HANDLE_PREFIX: Final = "za1."
HANDLE_PATTERN: Final = re.compile(r"^za1\.[A-Za-z0-9_-]{43}$")
CODE_ALPHABET: Final = "ACDEFHJKMNPRTUVWXY3479"
CODE_LENGTH: Final = 4
INPUT_KEY: Final = "zoeymcp-approval"


# --- secrets that must never be logged ------------------------------------------------------------


class Handle:
    """A modern ``requestState`` this gateway minted. Its ``repr`` hides it; logging it raises."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        return self._value

    def sha256(self) -> str:
        return handle_sha256(self._value)

    def __repr__(self) -> str:
        return "Handle(<hidden>)"


class ConfirmCode:
    """A per-prompt confirmation code (C.4). Its ``repr`` hides it; logging it raises."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        return self._value

    def matches(self, answer: object) -> bool:
        """Whether an answer's ``code`` field, upper-cased and stripped, is this code."""
        if not isinstance(answer, str):
            return False
        return hmac.compare_digest(answer.strip().upper().encode(), self._value.encode())

    def __repr__(self) -> str:
        return "ConfirmCode(<hidden>)"


refuse_type(Handle)
refuse_type(ConfirmCode)


def new_handle() -> Handle:
    """32 random bytes, base64url without padding, after the ``za1.`` prefix."""
    raw = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    return Handle(HANDLE_PREFIX + raw)


def handle_sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def new_code() -> ConfirmCode:
    return ConfirmCode("".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LENGTH)))


# --- records -------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Key:
    client: str
    server: str
    tool: str


@dataclass(frozen=True)
class Settings:
    """The limits one ``begin`` uses: the client's effective timeout and the gateway's caps."""

    timeout: float
    call_timeout: float
    cooldown: float
    max_pending_per_client: int
    max_prompts_per_hour: int


@dataclass(frozen=True, repr=False)
class Pending:
    """One asked call, from ``begin`` to ``finish``. Logging it raises: it holds the arguments."""

    ref: str
    key: Key
    era: Era
    args: Any  # the canonical object shown; forwarded as is
    args_digest: str  # canonical.digest(args); memory only (H14)
    pin: str
    plan: Any  # toolkits: the frozen approvaltext.Plan; None for a remote tool
    text_sha256: str  # the exact text, for re-asks
    code: ConfirmCode | None
    session_sha256: str | None  # legacy
    handle_sha256: str | None  # modern; replaced on a re-ask, None once consumed
    asks: int
    asked_at: float
    expires_at: float
    hard_deadline: float
    decision: Decision | None = None

    def __repr__(self) -> str:
        return f"Pending(ref={self.ref}, decision={self.decision})"


refuse_type(Pending)


@dataclass(frozen=True)
class Tombstone:
    reason: Literal["used", "expired"]
    until: float


# --- refusals ------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Busy:
    """Another call to this tool is waiting or running."""

    holder_ref: str
    seconds_left: int


@dataclass(frozen=True)
class PendingCap:
    """An approval is already waiting for this client."""

    holder_ref: str


@dataclass(frozen=True)
class HourlyCap:
    pass


@dataclass(frozen=True)
class Cooldown:
    seconds_left: int


@dataclass(frozen=True)
class Full:
    pass


Refusal = Busy | PendingCap | HourlyCap | Cooldown | Full


def _seconds(value: float) -> int:
    """Whole seconds, rounded up, never below 1: "frees within 0 s" would be false."""
    return max(1, int(-(-value // 1)))


# --- the table -----------------------------------------------------------------------------------


@dataclass
class Sweep:
    expired: list[Pending] = field(default_factory=list)  # modern prompts past their deadline
    freed: list[Pending] = field(default_factory=list)  # locks past their hard deadline (a bug)


class Table:
    """Every asked call of one gateway process."""

    def __init__(self) -> None:
        self._by_key: dict[Key, Pending] = {}
        self._by_ref: dict[str, Key] = {}
        self._by_handle: dict[str, str] = {}  # handle_sha256 -> ref
        self._tombstones: dict[str, Tombstone] = {}  # insertion order is age order
        self._cooldowns: dict[Key, float] = {}
        self._asked: dict[str, deque[float]] = {}

    # --- reading ---------------------------------------------------------------------------

    def __len__(self) -> int:
        return len(self._by_key)

    def records(self) -> Iterator[Pending]:
        return iter(list(self._by_key.values()))

    def get(self, ref: str) -> Pending | None:
        key = self._by_ref.get(ref)
        return self._by_key.get(key) if key is not None else None

    def legacy_waiting(self, session_sha256: str) -> bool:
        """Whether a legacy prompt is waiting for an answer on this session (D.3)."""
        return self.legacy_waiting_count(session_sha256) > 0

    def legacy_waiting_count(self, session_sha256: str) -> int:
        """Legacy prompts waiting on this session: each reserves one reply slot (D.3)."""
        return sum(
            1
            for p in self._by_key.values()
            if p.era == "legacy" and p.decision is None and p.session_sha256 == session_sha256
        )

    def lookup(self, handle_sha256: str, now: float) -> Pending | Tombstone | None:
        """The live record a handle names, or its tombstone, without changing anything."""
        self._prune_tombstones(now)
        ref = self._by_handle.get(handle_sha256)
        if ref is not None:
            return self.get(ref)
        return self._tombstones.get(handle_sha256)

    # --- writing ---------------------------------------------------------------------------

    def begin(
        self,
        key: Key,
        *,
        settings: Settings,
        now: float,
        ref: str,
        era: Era,
        args: Any,
        args_digest: str,
        pin: str,
        text_sha256: str,
        plan: Any = None,
        code: ConfirmCode | None = None,
        session_sha256: str | None = None,
        handle_sha256: str | None = None,
    ) -> Pending | Refusal:
        """Take the lock for ``key`` and record the prompt, or say why not (B.2 step 5.8)."""
        holder = self._by_key.get(key)
        if holder is not None:
            return Busy(holder.ref, _seconds(holder.hard_deadline - now))
        waiting = [
            p for p in self._by_key.values() if p.key.client == key.client and p.decision is None
        ]
        if len(waiting) >= settings.max_pending_per_client:
            return PendingCap(min(waiting, key=lambda p: p.asked_at).ref)
        asked = self._asked_in_last_hour(key.client, now)
        if len(asked) >= settings.max_prompts_per_hour:
            return HourlyCap()
        until = self._cooldowns.get(key)
        if until is not None and until > now:
            return Cooldown(_seconds(until - now))
        if len(self._by_key) >= MAX_RECORDS:
            return Full()
        expires = now + settings.timeout
        record = Pending(
            ref=ref,
            key=key,
            era=era,
            args=args,
            args_digest=args_digest,
            pin=pin,
            plan=plan,
            text_sha256=text_sha256,
            code=code,
            session_sha256=session_sha256,
            handle_sha256=handle_sha256,
            asks=1,
            asked_at=now,
            expires_at=expires,
            hard_deadline=expires + settings.call_timeout + HARD_DEADLINE_MARGIN,
        )
        self._by_key[key] = record
        self._by_ref[ref] = key
        if handle_sha256 is not None:
            self._by_handle[handle_sha256] = ref
        asked.append(now)
        self._cooldowns.pop(key, None)
        return record

    def consume(self, handle_sha256: str, now: float) -> Pending:
        """Use a live handle up: from now on it reads "already used". The lock stays held."""
        ref = self._by_handle.pop(handle_sha256)
        self._bury(handle_sha256, "used", now)
        return self._update(ref, handle_sha256=None)

    def reask(self, ref: str, new_handle_sha256: str) -> Pending:
        """The same prompt under a new handle, after a retry that carried no answer (D.6 step 7)."""
        record = self._require(ref)
        if record.handle_sha256 is not None:
            self._by_handle.pop(record.handle_sha256, None)
        self._by_handle[new_handle_sha256] = ref
        return self._update(ref, handle_sha256=new_handle_sha256, asks=record.asks + 1)

    def decide(self, ref: str, decision: Decision, now: float) -> Pending:
        """Record the decision. The prompt stops counting against the pending cap; the lock stays
        held until :meth:`finish`. A record decided once keeps its first decision."""
        record = self._require(ref)
        if record.decision is not None:
            return record
        if record.handle_sha256 is not None:
            self._by_handle.pop(record.handle_sha256, None)
            reason: Literal["used", "expired"] = "expired" if decision == "timeout" else "used"
            self._bury(record.handle_sha256, reason, now)
        return self._update(ref, decision=decision, handle_sha256=None)

    def finish(self, key: Key, ref: str, now: float, *, settings_cooldown: float) -> bool:
        """Free ``key``'s lock if ``ref`` still holds it, and start the cooldown its decision
        calls for. A stranger's ref changes nothing."""
        record = self._by_key.get(key)
        if record is None or record.ref != ref:
            return False
        if record.decision is None:
            record = self.decide(ref, "error", now)
        del self._by_key[key]
        del self._by_ref[ref]
        if record.decision in COOLDOWN_DECISIONS and settings_cooldown > 0:
            self._cooldowns[key] = now + settings_cooldown
        return True

    def withdraw(
        self, matches: Callable[[Pending], bool], decision: Decision, now: float
    ) -> list[Pending]:
        """Decide every undecided record ``matches`` picks (a policy change, a shutdown).

        The caller writes their ledger records and calls :meth:`finish` for each; a legacy
        handler that is waiting wakes and does so itself.
        """
        found = [p for p in self._by_key.values() if p.decision is None and matches(p)]
        return [self.decide(p.ref, decision, now) for p in found]

    def sweep(self, now: float) -> Sweep:
        """Expired modern prompts (decided ``timeout``; the caller ledgers and finishes them), and
        any lock past its hard deadline, which is freed at once."""
        result = Sweep()
        self._prune_tombstones(now)
        for record in list(self._by_key.values()):
            if record.hard_deadline <= now:
                del self._by_key[record.key]
                del self._by_ref[record.ref]
                if record.handle_sha256 is not None:
                    self._by_handle.pop(record.handle_sha256, None)
                    self._bury(record.handle_sha256, "expired", now)
                result.freed.append(record)
            elif record.era == "modern" and record.decision is None and record.expires_at <= now:
                if record.handle_sha256 is not None:  # not mid-retry: no handler owns it
                    result.expired.append(self.decide(record.ref, "timeout", now))
        for key, until in list(self._cooldowns.items()):
            if until <= now:
                del self._cooldowns[key]
        for client, times in list(self._asked.items()):
            self._asked_in_last_hour(client, now)
            if not times:
                del self._asked[client]
        return result

    # --- helpers ---------------------------------------------------------------------------

    def _require(self, ref: str) -> Pending:
        record = self.get(ref)
        if record is None:
            raise KeyError(ref)
        return record

    def _update(self, ref: str, **changes: Any) -> Pending:
        record = replace(self._require(ref), **changes)
        self._by_key[record.key] = record
        return record

    def _asked_in_last_hour(self, client: str, now: float) -> deque[float]:
        times = self._asked.setdefault(client, deque())
        while times and times[0] <= now - HOUR:
            times.popleft()
        return times

    def _bury(self, handle_sha256: str, reason: Literal["used", "expired"], now: float) -> None:
        self._tombstones.pop(handle_sha256, None)
        self._tombstones[handle_sha256] = Tombstone(reason, now + TOMBSTONE_SECONDS)
        while len(self._tombstones) > MAX_TOMBSTONES:
            del self._tombstones[next(iter(self._tombstones))]

    def _prune_tombstones(self, now: float) -> None:
        for handle, stone in list(self._tombstones.items()):
            if stone.until <= now:
                del self._tombstones[handle]


# --- the modern retry (D.6 steps 1-6) ------------------------------------------------------------


@dataclass(frozen=True)
class Unknown:
    """A malformed, guessed or foreign handle: "approval expired or already used"."""


@dataclass(frozen=True)
class Foreign:
    """Another client's, server's or tool's live handle: answered like :class:`Unknown`, logged
    as ``approval_state_foreign``, and the record is left alone."""


@dataclass(frozen=True)
class Buried:
    """A handle already used or expired."""

    reason: Literal["used", "expired"]


@dataclass(frozen=True)
class Closed:
    """The handle was this caller's, but the retry fails: the record is decided, to finish."""

    record: Pending


@dataclass(frozen=True)
class Live:
    """The handle was this caller's and is now consumed; the lock passes to this handler."""

    record: Pending


RetryResult = Unknown | Foreign | Buried | Closed | Live


def retry(
    table: Table,
    request_state: object,
    *,
    key: Key,
    args_digest: str,
    pin: str,
    now: float,
) -> RetryResult:
    """D.6 steps 1-6, in order. A foreign presentation never changes the record (step 3)."""
    if not isinstance(request_state, str) or not HANDLE_PATTERN.fullmatch(request_state):
        return Unknown()
    digest = handle_sha256(request_state)
    found = table.lookup(digest, now)
    if found is None:
        return Unknown()
    if isinstance(found, Tombstone):
        return Buried(found.reason)
    if found.key != key:
        return Foreign()
    record = table.consume(digest, now)
    if record.args_digest != args_digest or record.pin != pin:
        return Closed(table.decide(record.ref, "mismatch", now))
    if now >= record.expires_at:
        return Closed(table.decide(record.ref, "timeout", now))
    return Live(record)


# --- the gate and the answer ---------------------------------------------------------------------


def can_ask(era: Era, *, declared: bool, form: bool, url: bool, can_send_request: bool) -> bool:
    """Whether this request's client can show a form-mode approval (D.1).

    ``declared`` says the client declared ``elicitation`` at all; ``form`` and ``url`` say which
    of its modes it named. An empty declaration means form mode (2025-11-25); URL-only doesn't
    count. A legacy request also needs a stateful session that can send requests.
    """
    if not declared or (url and not form):
        return False
    return era == "modern" or can_send_request


def decide_answer(action: object, content: object, code: ConfirmCode | None) -> Decision:
    """The decision an elicitation answer makes. Only an explicit ``accept`` counts, and with a
    confirmation code only with the right code."""
    if action == "accept":
        if code is None:
            return "accept"
        typed = content.get("code") if isinstance(content, dict) else None
        return "accept" if code.matches(typed) else "code_mismatch"
    if action == "decline":
        return "decline"
    if action == "cancel":
        return "dismiss"
    return "error"


def may_reask(record: Pending) -> bool:
    return record.asks < MAX_ASKS
