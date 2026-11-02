"""The vault's approval chain (M8 design J.1; Z19, G-10, G-22, OPS-8).

The vault writes its own hash-chained ledger of the calls it holds and relays, in the gateway's
record format (:mod:`zoeymcp.common.ledgerformat`, writer ``vault``) and on the same file layer
(:mod:`zoeymcp.common.ledgerfile`). This module wraps that layer with the vault's key and its
rules:

- **Files** ``/state/ledger-vault/<first seq, 12 digits>.jsonl``, 0600, each record fsynced before
  the call that needed it goes on. A new file starts at 4 MiB; beyond :data:`MAX_BYTES` a file is
  pruned only once its last record is :data:`~zoeymcp.vault.reports.KEEP_MS` old on the vault's
  clock, the rule of the vault's copy of the gateway's ledger, so a flood can't push out recent
  history.
- **The key** is an HKDF context of the master key (:attr:`~zoeymcp.vault.keys.KeySet.chain_key`):
  arguments and approval texts are recorded only as HMACs under it, never as values. It is never
  written anywhere.
- **No chain, no hold** (G-10). :meth:`VaultLedger.writable` is false after an append failed with
  an I/O error, while the queue of records waiting to be retried is full, or while the files are
  over :data:`MAX_BYTES` with nothing old enough to prune, until an append succeeds (or the oldest
  file comes of age). While it is false no new hold or relay begins; the holds already asked go on,
  and a record they must have on disk before going on (``critical``) raises
  :class:`ChainUnavailable` when it can't be written. Other records are queued and retried every
  :data:`RETRY_SECONDS`, in order.
- **Recovery** at start, before any listener (:meth:`VaultLedger.open_at`): a hold has no life
  after a restart, so an ``asked`` with no decision closes ``decided abandoned`` (``via: none``)
  then ``outcome not_sent``, and a ``decided accept`` with no outcome closes ``outcome unknown``.
  The same start reads the chain back for the recent endings (F.5 step 4: the last
  :data:`~zoeymcp.vault.holds.RECENT_ENDINGS` refs or 24 hours, whichever is smaller) and counts
  what it closed, for the two start findings (:class:`Start`).

Every method that touches files runs in a worker thread when awaited; :meth:`VaultLedger.open_at`
runs before the event loop starts.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

import anyio

from ..common import canonical, ledgerformat
from ..common.ledgerfile import ROTATE_BYTES, Anchor, LedgerFile, Recovery
from ..common.ledgerformat import GENESIS, Kind, LedgerFormatError, Record
from . import logs
from .holds import ENDINGS_SECONDS, RECENT_ENDINGS, HoldTable, State
from .keys import ChainKey
from .reports import KEEP_MS

CHAIN_DIR: Final = "ledger-vault"
MAX_BYTES: Final = 64 * 2**20
MAX_QUEUED: Final = 1024
RETRY_SECONDS: Final = 5.0
# A seq and a timestamp (ms) at least as wide as any the chain will write, so that a record which
# fits in a line with them fits wherever it lands.
_WIDEST: Final = 10**13 - 1

# How a vault decision ends a hold (holds.State), and the detail the hold would carry. An accept's
# detail is its outcome, or ``restart`` when recovery closed it; an abandon is recovery's. Any
# other decision ends it ``withdrawn``, with the decision as its detail.
_ENDINGS: Final[dict[str, tuple[State, str | None]]] = {
    "accept": ("done", None),
    "decline": ("denied", None),
    "timeout": ("expired", None),
    "withdrawn": ("withdrawn", None),
    "stream_lost": ("withdrawn", "stream_lost"),
    "shutdown": ("withdrawn", "shutdown"),
    "abandoned": ("withdrawn", "restart"),
}


class ChainUnavailable(RuntimeError):
    """A record that had to be on disk before the call goes on couldn't be written."""


def now_ms() -> int:
    return int(time.time() * 1000)


@dataclass(frozen=True)
class RecentEnding:
    """How a held or relayed call ended, read back from the chain at start (F.5 step 4): its ref,
    the client the gateway reported, the hold's end state and detail, and when its outcome was
    written (milliseconds on the vault's clock)."""

    ref: str
    client: str | None
    state: State
    detail: str | None
    ended_ms: int


@dataclass(frozen=True)
class Start:
    """What the start's recovery found and did (J.1, OPS-8)."""

    recovery: Recovery = field(default_factory=Recovery)
    # approvals_withdrawn_at_start: the holds (and relays) still waiting that this start closed
    # decided abandoned, then not_sent.
    withdrawn: int = 0
    # approvals_outcome_unknown: the refs of each decided accept this start closed unknown.
    outcome_unknown: tuple[str, ...] = ()
    # The recent endings, oldest first.
    endings: tuple[RecentEnding, ...] = ()


@dataclass
class _Queued:
    kind: Kind
    ref: str | None
    fields: dict[str, Any]


class VaultLedger:
    """The vault's chain in ``directory``, which must exist."""

    def __init__(
        self,
        directory: Path,
        key: ChainKey,
        *,
        clock: Callable[[], int] = now_ms,
        max_bytes: int = MAX_BYTES,
        keep_ms: int = KEEP_MS,
        rotate_bytes: int = ROTATE_BYTES,
    ) -> None:
        self.file = LedgerFile(
            directory,
            max_bytes=max_bytes,
            clock=clock,
            event=logs.event,
            writer="vault",
            rotate_bytes=rotate_bytes,
            keep_ms=keep_ms,
        )
        self.key = key
        self.start = Start()
        self.queue: list[_Queued] = []
        self.failed = False  # the last append failed with an I/O error
        self._lock = anyio.Lock()

    @property
    def open(self) -> dict[str, list[str]]:
        """The refs asked and not yet closed (E19's open-ref index), with their kinds so far."""
        return self.file.open

    # --- start-up ----------------------------------------------------------------------------

    @classmethod
    def open_at(
        cls, state_dir: Path, key: ChainKey, *, clock: Callable[[], int] = now_ms, **options: Any
    ) -> VaultLedger:
        """Open the chain in ``state_dir`` and recover it, before any listener (J.1). Raises
        ``OSError`` when it can't be read or written."""
        directory = state_dir / CHAIN_DIR
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        chain = cls(directory, key, clock=clock, **options)
        chain.recover()
        return chain

    def recover(self) -> Start:
        """Close every open ref (J.1), measure the files, and read back the recent endings."""
        recovery = self.file.recover()
        self.file.prune()
        self.start = Start(
            recovery,
            withdrawn=recovery.closed.get("abandoned", 0),
            outcome_unknown=tuple(
                sorted(ref for ref, outcome in recovery.ended.items() if outcome == "unknown")
            ),
            endings=tuple(recent_endings(self.file.records(), self.file.clock())),
        )
        return self.start

    def remember(self, table: HoldTable, now: float) -> None:
        """Give ``table`` the start's recent endings, so each ref stays used (E19) and its client
        is told how it ended (F.5 step 4). ``now`` is this moment on the table's clock, to which
        each ending's time is moved."""
        wall = self.file.clock()
        for ending in self.start.endings:
            table.remember(
                now,
                ending.ref,
                ending.state,
                ending.detail,
                client=ending.client,
                ended_at=now - (wall - ending.ended_ms) / 1000,
            )

    # --- writing ------------------------------------------------------------------------------

    def writable(self) -> bool:
        """Whether a new hold or relay may begin (no chain, no hold, G-10)."""
        if self.failed or len(self.queue) >= MAX_QUEUED:
            return False
        if self.file.size <= self.file.max_bytes:
            return True
        prunable_at = self.file.prunable_at
        return prunable_at is not None and self.file.clock() > prunable_at

    def digest(self, value: canonical.JSONValue) -> str:
        """The keyed digest of a JSON value's canonical bytes."""
        return self.key.digest(canonical.dumps_canonical(value))

    def text_digest(self, text: str) -> str:
        return self.key.digest(text.encode("utf-8"))

    async def write(
        self, kind: Kind, ref: str | None, *, critical: bool, **fields: Any
    ) -> Anchor | None:
        """Append one record and return its anchor for the log line that cites it. With
        ``critical``, failure raises :class:`ChainUnavailable`; otherwise the record is queued
        and retried, and None is returned. A record that isn't valid is never queued."""
        async with self._lock:
            try:
                _check(kind, ref, fields)
                if not critical and self.queue:
                    self.queue.append(_Queued(kind, ref, fields))  # keep the order
                    return None
                anchor = await anyio.to_thread.run_sync(self.file.append, kind, ref, fields)
            except (OSError, LedgerFormatError) as exc:
                io_error = isinstance(exc, OSError)
                self.failed = self.failed or io_error
                queued = io_error and not critical
                logs.event(
                    "ledger_write_failed",
                    record_kind=kind,
                    error_type=type(exc).__name__,
                    queued=len(self.queue) + queued,
                    level="critical",
                )
                if critical:
                    raise ChainUnavailable(kind) from exc
                if queued:
                    self.queue.append(_Queued(kind, ref, fields))
                return None
            self.failed = False
            return anchor

    async def flush_queue(self) -> int:
        """Retry queued records in order; returns how many are still queued."""
        async with self._lock:
            while self.queue:
                item = self.queue[0]
                try:
                    await anyio.to_thread.run_sync(
                        self.file.append, item.kind, item.ref, item.fields
                    )
                except OSError:
                    self.failed = True
                    break
                self.failed = False
                self.queue.pop(0)
            return len(self.queue)

    async def retry_forever(self) -> None:
        while True:
            await anyio.sleep(RETRY_SECONDS)
            if self.queue:
                await self.flush_queue()

    # --- reading ------------------------------------------------------------------------------

    def read(self, *, after: int = -1, limit: int = 1000) -> list[dict[str, Any]]:
        """Records after ``after``, oldest first, as JSON objects."""
        return self.file.read(after=after, limit=limit)

    def records(self) -> list[dict[str, Any]]:
        """Every record, oldest first, as JSON objects: the ledger view's second source (J.2).
        A line that doesn't parse is left out."""
        return [json.loads(record.line) for record in self.file.records()]

    def verify(self) -> dict[str, Any]:
        """Walk every file's chain in order, from what the oldest file says it follows."""
        return self.file.verify()


def _check(kind: Kind, ref: str | None, fields: dict[str, Any]) -> None:
    """Raise :class:`~zoeymcp.common.ledgerformat.LedgerFormatError` unless the record is valid
    from the vault wherever it lands in the chain (only its line's length can change there)."""
    ledgerformat.encode(
        kind, seq=_WIDEST, prev=GENESIS, ts=_WIDEST, ref=ref, writer="vault", **fields
    )


def recent_endings(records: Iterator[Record], now: int) -> list[RecentEnding]:
    """The calls a chain's ``records`` show ended, oldest outcome first: those whose outcome was
    written within :data:`~zoeymcp.vault.holds.ENDINGS_SECONDS` before ``now`` (ms), at most the
    last :data:`~zoeymcp.vault.holds.RECENT_ENDINGS`. Every ended ref is kept, so it stays used
    (E19): one with no decision left in the files ends ``withdrawn``."""
    clients: dict[str, str] = {}
    decisions: dict[str, str] = {}
    found: dict[str, RecentEnding] = {}
    since = now - int(ENDINGS_SECONDS * 1000)
    for record in records:
        ref = record.ref
        if ref is None:
            continue
        if record.kind == "asked":
            clients[ref] = record.fields["client"]
            decisions.pop(ref, None)
            found.pop(ref, None)
        elif record.kind == "decided":
            decisions[ref] = record.fields["decision"]
        elif record.kind == "outcome" and record.ts > since:
            state, detail = _ended(decisions.get(ref), record)
            found.pop(ref, None)  # its place is its outcome's
            found[ref] = RecentEnding(ref, clients.get(ref), state, detail, record.ts)
    return list(found.values())[-RECENT_ENDINGS:]


def _ended(decision: str | None, outcome: Record) -> tuple[State, str | None]:
    if outcome.fields["detail"] == "ledger":
        return "withdrawn", "ledger"  # its decided accept couldn't be written (J.1)
    if decision is None:
        return "withdrawn", None
    state, detail = _ENDINGS.get(decision, ("withdrawn", decision))
    if decision == "accept":
        restarted = outcome.fields["detail"] == "restart"
        detail = "restart" if restarted else outcome.fields["outcome"]
    return state, detail
