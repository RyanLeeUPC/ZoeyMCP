"""The pending record and the result store (M8 design F.2; Z17, F12). Pure, standard library
only, mutation-tested.

A call that answered ``pending <ref>`` keeps a :class:`PendingCall` here from that answer until
``ttl_ms`` (``approvers.result_ttl``) after its outcome, and its result once it ran. A record whose
outcome never comes (its holder lost the call) is taken to have ended ``grace_ms`` after its
deadline, the latest a forward approved at the deadline can end, so it can't keep a client's slot
for ever. The gateway keeps one for its relays and the vault one for its holds. Every method is
synchronous and takes ``now`` in milliseconds on the wall clock, the clock the deadlines are shown
in, and every write first drops the records past their time, so none of them counts towards a
bound.

- **Bound to its client.** Every read names the client; another client's ref reads exactly as an
  unknown one (T34).
- **Delivered once.** :meth:`ResultStore.collect` hands the result over and drops its bytes; a
  later read says it was collected. :meth:`ResultStore.peek` reads the status without consuming
  it (the tasks seam, D-239).
- **Bounded** (Q44 (a)): :data:`MAX_RECORDS` records, :data:`MAX_CLIENT_RECORDS` per client,
  :data:`MAX_RESULT_BYTES` per result, :data:`MAX_CLIENT_BYTES` per client and
  :data:`MAX_TOTAL_BYTES` in all. A record holds no bytes until its result arrives, so the total
  is enforced at both ends, and only ever by evicting the asking client's own oldest uncollected
  results: never another client's before its time. At :meth:`ResultStore.open` a full total
  evicts them until it is below, and with not enough of them refuses :class:`Full` (``busy``); at
  :meth:`ResultStore.advance` a result that would pass the client's bound or the total evicts
  them, and with not enough of them isn't kept. Nothing is evicted when that can't make room. An
  evicted result's record stays, and its ``collect`` says the call ran and its result wasn't kept.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Final, Literal

from .logs import refuse_type

CallStatus = Literal["pending", "approved", "forwarding", "done", "denied", "expired", "withdrawn"]
Lost = Literal["too_large", "not_kept"]
EvictReason = Literal["client_bound", "store_full"]

MAX_RECORDS: Final = 256
MAX_CLIENT_RECORDS: Final = 16
MAX_RESULT_BYTES: Final = 4 * 1024 * 1024
MAX_CLIENT_BYTES: Final = 16 * 1024 * 1024
MAX_TOTAL_BYTES: Final = 64 * 1024 * 1024

# How a record follows its call (B.4's states, held named pending); the last four are outcomes.
NEXT: Final[Mapping[CallStatus, frozenset[CallStatus]]] = MappingProxyType(
    {
        "pending": frozenset({"approved", "denied", "expired", "withdrawn"}),
        "approved": frozenset({"forwarding", "done", "withdrawn"}),
        "forwarding": frozenset({"done"}),
    }
)
ENDED: Final[frozenset[CallStatus]] = frozenset({"done", "denied", "expired", "withdrawn"})


@dataclass(frozen=True, repr=False)
class StoredResult:
    """A forwarded call's answer, already scrubbed (B.8): its HTTP status, content type and
    bytes. ``lost`` says why the bytes are gone: over :data:`MAX_RESULT_BYTES`, or not kept (an
    eviction, or a full store). Logging it raises."""

    status: int
    content_type: str
    body: bytes = b""
    lost: Lost | None = None

    def __repr__(self) -> str:
        return f"StoredResult(status={self.status}, lost={self.lost})"


@dataclass(frozen=True, repr=False)
class PendingCall:
    """One pending call and, once it ran, its result. Logging it raises."""

    ref: str
    client: str
    server: str
    tool: str
    holder: Literal["gateway", "vault"]
    args_digest: str
    text_sha256: str
    surfaces: frozenset[str]
    asked_ms: int
    deadline_ms: int
    status: CallStatus
    outcome: str | None = None
    result: StoredResult | None = None  # content type and bytes, too_large, or not_kept
    collected: bool = False
    ended_ms: int | None = None  # when it reached an outcome; dropped ttl_ms later

    def __repr__(self) -> str:
        return f"PendingCall(ref={self.ref}, status={self.status})"


refuse_type(StoredResult)
refuse_type(PendingCall)


@dataclass(frozen=True)
class Status:
    """What a read without the result says (Q46: no result, no text)."""

    ref: str
    tool: str
    status: CallStatus
    outcome: str | None
    deadline_ms: int
    collected: bool
    lost: Lost | None


@dataclass(frozen=True)
class Collected:
    """The result, handed over once."""

    ref: str
    result: StoredResult


@dataclass(frozen=True)
class Unknown:
    """No such ref for this client: unknown, another client's, or past its time."""


@dataclass(frozen=True)
class Full:
    """The store can't take another record for this client (``busy``)."""


@dataclass(frozen=True)
class Evicted:
    """A result not kept (``approval_result_evicted``): another of the client's to make room,
    or the arriving one when no room could be made."""

    ref: str
    reason: EvictReason


def _status(record: PendingCall) -> Status:
    lost = record.result.lost if record.result is not None else None
    return Status(
        record.ref,
        record.tool,
        record.status,
        record.outcome,
        record.deadline_ms,
        record.collected,
        lost,
    )


class ResultStore:
    def __init__(self, ttl_ms: int, grace_ms: int) -> None:
        self.ttl_ms = ttl_ms  # approvers.result_ttl, in milliseconds
        # The longest a forward may run past the deadline: call_timeout plus OUTCOME_MARGIN.
        self.grace_ms = grace_ms
        self._records: dict[str, PendingCall] = {}
        self._kept: dict[str, int] = {}  # ref -> bytes held; insertion order is arrival order

    # --- reading ---------------------------------------------------------------------------

    def __len__(self) -> int:
        return len(self._records)

    def knows(self, ref: str) -> bool:
        """Whether ``ref`` has a record here (the store's half of E19)."""
        return ref in self._records

    def total_bytes(self) -> int:
        """The bytes the store's records hold."""
        return sum(len(r.result.body) for r in self._records.values() if r.result is not None)

    def collect(self, now: int, ref: str, client: str) -> Collected | Status | Unknown:
        """The result once, then its status (Z17)."""
        record = self._find(now, ref, client)
        if record is None:
            return Unknown()
        result = record.result
        if record.collected or result is None or result.lost is not None:
            return _status(record)
        del self._kept[ref]
        self._records[ref] = replace(record, collected=True, result=replace(result, body=b""))
        return Collected(ref, result)

    def peek(self, now: int, ref: str, client: str) -> Status | Unknown:
        record = self._find(now, ref, client)
        return Unknown() if record is None else _status(record)

    def list_for(self, now: int, client: str, server: str) -> list[Status]:
        """The client's own records on ``server`` (Q46), oldest first."""
        return [
            _status(record)
            for record in self._records.values()
            if record.client == client and record.server == server and self._live(now, record)
        ]

    # --- writing ---------------------------------------------------------------------------

    def open(self, now: int, call: PendingCall) -> list[Evicted] | Full:
        """Keep a new pending record, or refuse ``busy``; the results evicted to make room."""
        self.sweep(now)
        if call.ref in self._records:
            raise ValueError("a ref is used once")
        if call.status != "pending" or call.outcome is not None or call.ended_ms is not None:
            raise ValueError("a record opens pending")
        if call.result is not None or call.collected:
            raise ValueError("a record opens with no result")
        if len(self._records) >= MAX_RECORDS:
            return Full()
        if sum(1 for r in self._records.values() if r.client == call.client) >= MAX_CLIENT_RECORDS:
            return Full()
        evict = self._room(call.client, self.total_bytes(), MAX_TOTAL_BYTES - 1, ())
        if evict is None:
            return Full()
        self._records[call.ref] = call
        return self._evict(evict, "store_full")

    def advance(
        self,
        now: int,
        ref: str,
        status: CallStatus,
        outcome: str | None = None,
        result: StoredResult | None = None,
    ) -> list[Evicted]:
        """Follow the call to ``status``, with its outcome and, at ``done``, its result; the
        results not kept. A move :data:`NEXT` doesn't allow (late, repeated, or for a ref gone)
        changes nothing."""
        self.sweep(now)
        record = self._records.get(ref)
        if record is None or status not in NEXT.get(record.status, frozenset()):
            return []
        evicted: list[Evicted] = []
        if result is not None and status == "done":
            result, evicted = self._keep(record.client, ref, result)
        else:
            result = None
        self._records[ref] = replace(
            record,
            status=status,
            outcome=record.outcome if outcome is None else outcome,
            result=record.result if result is None else result,
            ended_ms=now if status in ENDED else None,
        )
        return evicted

    def sweep(self, now: int) -> list[str]:
        """Drop every record ``ttl_ms`` after its outcome, or after its deadline and
        ``grace_ms`` when none came; the refs dropped."""
        dropped = [ref for ref, record in self._records.items() if not self._live(now, record)]
        for ref in dropped:
            del self._records[ref]
            self._kept.pop(ref, None)
        return dropped

    # --- helpers ---------------------------------------------------------------------------

    def _live(self, now: int, record: PendingCall) -> bool:
        ended = record.ended_ms
        if ended is None:
            ended = record.deadline_ms + self.grace_ms
        return now < ended + self.ttl_ms

    def _find(self, now: int, ref: str, client: str) -> PendingCall | None:
        record = self._records.get(ref)
        if record is None or record.client != client or not self._live(now, record):
            return None
        return record

    def _room(
        self, client: str, total: int, limit: int, spared: tuple[str, ...]
    ) -> list[str] | None:
        """The client's own oldest uncollected results (``spared`` aside) to evict so ``total``
        comes to at most ``limit``, or None when all of them aren't enough."""
        evict: list[str] = []
        for ref, size in self._kept.items():
            if total <= limit:
                break
            if self._records[ref].client == client and ref not in spared:
                evict.append(ref)
                total -= size
        return evict if total <= limit else None

    def _evict(self, refs: list[str], reason: EvictReason) -> list[Evicted]:
        for ref in refs:
            del self._kept[ref]
            record = self._records[ref]
            if record.result is not None:
                result = replace(record.result, body=b"", lost="not_kept")
                self._records[ref] = replace(record, result=result)
        return [Evicted(ref, reason) for ref in refs]

    def _keep(
        self, client: str, ref: str, result: StoredResult
    ) -> tuple[StoredResult, list[Evicted]]:
        """``result`` as kept, after making room within the client's bound and the total, or
        not kept; the results evicted, the arriving one included when it isn't kept."""
        if result.lost is not None:
            return replace(result, body=b""), []
        size = len(result.body)
        if size > MAX_RESULT_BYTES:
            return replace(result, body=b"", lost="too_large"), []
        own = sum(n for r, n in self._kept.items() if self._records[r].client == client)
        # Always room: a result fits a client's bound alone.
        bound = self._room(client, own + size, MAX_CLIENT_BYTES, ()) or []
        freed = sum(self._kept[r] for r in bound)
        full = self._room(client, self.total_bytes() - freed + size, MAX_TOTAL_BYTES, tuple(bound))
        if full is None:
            return replace(result, body=b"", lost="not_kept"), [Evicted(ref, "store_full")]
        evicted = self._evict(bound, "client_bound") + self._evict(full, "store_full")
        self._kept[ref] = size
        return result, evicted
