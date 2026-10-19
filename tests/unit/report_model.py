"""A model gateway ledger and vault copy for the report path's property tests (M5 design O.1).

- :class:`GatewayModel` holds chained records in memory as ``gateway/ledger.py`` writes them. It
  appends, prunes its oldest records, is restored from an older backup or loses its volume. Each
  record's ``ts`` is a counter that never goes back, so two histories share no record once they
  part.
- :class:`CopyModel` is the vault's copy as step 9b's store keeps it, in memory: it decides each
  report with :func:`zoeymcp.vault.reports.decide` and applies the answer (prune, append with
  rotation, the new head), and restarts with :func:`zoeymcp.vault.reports.plan_restart`. It keeps
  every line it accepted, so a test can check that none is lost or held twice.
- :func:`report_round` is one round of the reporter's loop (``gateway/reporting.py``): it reports
  until there is nothing more to send or the copy refuses.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field, replace

from zoeymcp.common import canonical, ledgerformat, ledgerreport
from zoeymcp.common.ledgerformat import GENESIS
from zoeymcp.gateway import reporting
from zoeymcp.vault import reports
from zoeymcp.vault.reports import Accepted, Epoch, Held, LiveFile, Refused

T0 = 1_767_276_000_000  # 2026-01-01 14:00:00Z
DIGEST = "hmac-sha256:" + "1" * 64
PIN = "sha256:" + "2" * 64
MAX_POSTS = 1000  # a round that posts more than this isn't making progress


def asked_line(seq: int, prev: str, tick: int, *, big: bool = False) -> bytes:
    """An ``asked`` record's line without its newline: 544 bytes, or 910 when ``big``."""
    name = ("n" * 127 if big else "agent") + "1"
    line = ledgerformat.encode(
        "asked",
        seq=seq,
        prev=prev,
        ts=T0 + tick,
        ref=f"{tick:016x}",
        client=name,
        server=name,
        tool=name,
        where="gateway",
        era="modern",
        args=DIGEST,
        pin=PIN,
        text=DIGEST,
        chars=1,
        writes=1,
        expires=1,
    )
    return line[:-1]


@dataclass
class GatewayModel:
    """The gateway's ledger: ``records`` are the kept ``(seq, line)`` pairs, oldest first."""

    records: list[tuple[int, bytes]] = field(default_factory=list)
    next_seq: int = 0
    prev: str = GENESIS
    ticks: int = 0

    @property
    def head_seq(self) -> int:
        return self.next_seq - 1

    def append(self, count: int = 1, *, big: bool = False) -> None:
        for _ in range(count):
            self.ticks += 1
            line = asked_line(self.next_seq, self.prev, self.ticks, big=big)
            self.records.append((self.next_seq, line))
            self.next_seq, self.prev = self.next_seq + 1, ledgerformat.line_hash(line)

    def prune(self, count: int) -> None:
        """Delete the oldest ``count`` records, as the ledger does beyond its size."""
        del self.records[:count]

    def rewind(self, count: int) -> None:
        """Go back ``count`` records, as a restore from an older backup does."""
        count = min(count, len(self.records))
        if count:
            removed = self.records[-count:]
            del self.records[-count:]
            self.next_seq = removed[0][0]
            self.prev = ledgerformat.parse(removed[0][1]).prev

    def lose_volume(self) -> None:
        self.records, self.next_seq, self.prev = [], 0, GENESIS

    def read(self, after: int, limit: int = ledgerreport.MAX_LINES) -> list[bytes]:
        """The stored lines after ``after``, oldest first, as ``Ledger.lines`` reads them."""
        return [line for seq, line in self.records if seq > after][:limit]

    def holds(self, seq: int, hash_: str | None) -> bool:
        return any(s == seq and ledgerformat.line_hash(line) == hash_ for s, line in self.records)


@dataclass
class CopyModel:
    """The vault's copy: live files by name, oldest first, each line without its newline."""

    max_bytes: int
    rotate_bytes: int
    archive_max_bytes: int
    keep_ms: int = reports.KEEP_MS
    held: Held = field(default_factory=Held)
    files: dict[str, list[bytes]] = field(default_factory=dict)
    accepted: list[bytes] = field(default_factory=list)  # since the last restart, in order
    pruned: list[bytes] = field(default_factory=list)  # since the last restart, in order
    archives: list[tuple[Epoch, list[bytes]]] = field(default_factory=list)
    anchors: list[Epoch] = field(default_factory=list)  # dropped epochs
    restarts: int = 0
    # Each report: what the copy held before it, its lines, and the answer.
    history: list[tuple[Held, list[bytes], Accepted | Refused]] = field(default_factory=list)

    def live(self) -> list[bytes]:
        return [line for lines in self.files.values() for line in lines]

    def report(self, lines: Sequence[bytes], now: int) -> Accepted | Refused:
        """Decide a report of ``lines`` as the endpoint does (the body encoded and parsed back),
        and apply the answer."""
        before = self.held
        body = canonical.loads_strict(ledgerreport.encode(lines))
        result = reports.decide(
            self.held, body, now=now, max_bytes=self.max_bytes, keep_ms=self.keep_ms
        )
        if isinstance(result, Refused):
            if result.state is not None:
                self.held = replace(self.held, state=result.state)
        else:
            self._apply(result, now)
        self.history.append((before, list(lines), result))
        return result

    def _apply(self, accepted: Accepted, now: int) -> None:
        for name in accepted.prune:
            self.pruned.extend(self.files.pop(name))
        if accepted.from_seq is None or accepted.head.seq is None:
            return
        sizes = {name: sum(len(line) + 1 for line in lines) for name, lines in self.files.items()}
        received = {f.name: f.received_ms for f in self.held.files if f.name in self.files}
        current = next(reversed(self.files), None)
        for seq, line in enumerate(accepted.lines, start=accepted.from_seq):
            size = len(line) + 1
            if current is None or (sizes[current] and sizes[current] + size > self.rotate_bytes):
                current = f"{seq:012d}.jsonl"
                self.files[current], sizes[current] = [], 0
            self.files[current].append(line)
            sizes[current] += size
            received[current] = now
        self.accepted.extend(accepted.lines)
        start = self.held.start_seq if accepted.start is None else accepted.start[0]
        live = tuple(LiveFile(name, sizes[name], received[name]) for name in self.files)
        self.held = Held("ok", start, accepted.head.seq, accepted.head.hash, live)

    def restart(self, now: int) -> tuple[Epoch, ...]:
        """``ledger.restart``: archive the live chain, drop what the archives can't keep, and
        start again with no copy."""
        self.restarts += 1
        live = reports.archive(self.held, f"archive-{now}-{self.restarts}")
        kept = [epoch for epoch, _ in self.archives]
        dropped = reports.plan_restart(kept, live, max_bytes=self.archive_max_bytes)
        if live is not None:
            self.archives.append((live, self.live()))
        self.archives = [(e, lines) for e, lines in self.archives if e not in dropped]
        self.anchors.extend(dropped)
        self.held, self.files, self.accepted, self.pruned = Held(), {}, [], []
        return dropped


def report_round(
    gateway: GatewayModel, copy: CopyModel, now: int, *, max_bytes: int
) -> list[Accepted | Refused]:
    """The reporter's round: report while there is something to send, stopping at a refusal.
    ``max_bytes`` caps each batch, as :data:`zoeymcp.gateway.reporting.REPORT_BATCH_BYTES` does."""
    results: list[Accepted | Refused] = []
    for _ in range(MAX_POSTS):
        head = copy.held.head
        after = reporting.read_after(head, gateway.head_seq)
        if after is None:
            return results
        lines = reporting.pending(head, gateway.read(after), max_bytes=max_bytes)
        if not lines:
            return results
        result = copy.report(lines, now)
        results.append(result)
        if isinstance(result, Refused):
            return results
        assert result.lines, "an accepted round always moves the head"
    raise AssertionError("the reporter made no progress")
