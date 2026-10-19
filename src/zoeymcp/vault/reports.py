"""The vault's decision on a ledger report, and the pruning of its copy (M5 design J.2, J.4).

Pure, so each row can be tested. The gateway pushes its ledger's records over the link; the vault
keeps an append-only copy whose held head the gateway can't rewrite afterwards. :func:`decide`
takes a report (the parsed body) against what the copy holds, in J.2's order:

1. the copy's state is ``ok``, else ``refused_until_restart`` and no change;
2. ``{"v": 1, "lines": [...]}`` with 1-256 lines, each a canonical v1 record;
3. every record written by the gateway: it can't claim a vault record (M8);
4. the lines chain among themselves;
5. no copy yet: accepted from any start (trust on first use);
6. the first record extends the held head;
7. the batch holds the held head: the lines up to it are duplicates (a resend), the rest extends;
8. otherwise a first record past the head is a ``gap``,
9. and anything else a ``fork``;
10. accepting must fit :data:`REPORTED_MAX_BYTES`, after pruning only files the vault
    received more than :data:`REPORTED_KEEP_DAYS` days ago (its own clock, never the records'
    ``ts``), else ``full``.

A ``gap``, ``fork`` or ``full`` refusal is sticky: its ``state`` is the copy's new state, and
every report is refused until a stepped-up restart (:func:`plan_restart`) archives the live chain.
A refusal's ``message`` never holds a line. Writing the copy, ``head.json`` and the log lines is
:mod:`.reportstore`'s.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Final, Literal

from ..common import ledgerformat
from ..common.ledgerformat import LedgerFormatError, Record
from ..common.ledgerreport import MAX_LINES, VERSION, Head, State

REPORTED_MAX_BYTES: Final = 64 * 2**20
REPORTED_ARCHIVE_MAX_BYTES: Final = 64 * 2**20
REPORTED_KEEP_DAYS: Final = 30
DAY_MS: Final = 24 * 3600 * 1000
KEEP_MS: Final = REPORTED_KEEP_DAYS * DAY_MS

Reason = Literal[
    "refused_until_restart",
    "bad_body",
    "bad_line",
    "wrong_writer",
    "not_a_chain",
    "gap",
    "fork",
    "full",
]


@dataclass(frozen=True)
class LiveFile:
    """One file of the live chain: its size, and when the vault received its last line (ms)."""

    name: str
    size: int
    received_ms: int


@dataclass(frozen=True)
class Held:
    """What the copy holds, as ``head.json`` records it. ``files`` are oldest first."""

    state: State = "ok"
    start_seq: int | None = None
    head_seq: int | None = None
    head_hash: str | None = None
    files: tuple[LiveFile, ...] = ()

    @property
    def head(self) -> Head:
        return Head(self.head_seq, self.head_hash, self.state)

    @property
    def size(self) -> int:
        return sum(file.size for file in self.files)

    @property
    def received_ms(self) -> int | None:
        """When the head last moved: the latest receipt of any live file, None with none."""
        return max((file.received_ms for file in self.files), default=None)


@dataclass(frozen=True)
class Accepted:
    """A report to apply: prune ``prune`` (oldest first), then append ``lines`` (each without
    its newline). ``duplicates`` leading lines were already held. ``start`` is the first record's
    ``seq`` and ``prev`` when this report starts the copy. ``head`` is the head after it."""

    lines: tuple[bytes, ...]
    duplicates: int
    head: Head
    start: tuple[int, str] | None
    prune: tuple[str, ...]
    from_seq: int | None  # the first appended record's, None when every line was a duplicate


@dataclass(frozen=True)
class Refused:
    """A refused report. ``index``: the bad line's. ``state``: the sticky state a ``gap``,
    ``fork`` or ``full`` sets. ``offered_seq``: the first offered record's seq, for the log."""

    status: int
    reason: Reason
    message: str
    index: int | None = None
    state: State | None = None
    offered_seq: int | None = None


def decide(
    held: Held,
    report: Any,
    *,
    now: int,
    max_bytes: int = REPORTED_MAX_BYTES,
    keep_ms: int = KEEP_MS,
) -> Accepted | Refused:
    """J.2's decision on ``report`` (the parsed body) at ``now`` (the vault's clock, ms)."""
    if held.state != "ok":
        return Refused(
            409, "refused_until_restart", f"the copy is {held.state}; a restart of the chain is due"
        )
    lines = _lines(report)
    if isinstance(lines, Refused):
        return lines
    records: list[Record] = []
    for index, line in enumerate(lines):
        # parse() takes one trailing newline; a report's line is the record alone.
        record = None if line.endswith(b"\n") else _parse(line)
        if record is None:
            return _bad_line(index)
        records.append(record)
    if any(record.writer != "gateway" for record in records):
        return Refused(400, "wrong_writer", "a report holds only records the gateway wrote")
    first = records[0]
    if ledgerformat.verify(lines, prev=first.prev, seq=first.seq).broken_at is not None:
        return Refused(400, "not_a_chain", "the lines don't chain")
    start: tuple[int, str] | None = None
    if held.head_seq is None:
        duplicates, start = 0, (first.seq, first.prev)
    else:
        found = _held_through(held.head_seq, held.head_hash, records)
        if found is None:
            reason: Literal["gap", "fork"] = "gap" if first.seq > held.head_seq + 1 else "fork"
            message = f"the report starts at seq {first.seq}, which doesn't extend the held head"
            return Refused(409, reason, message, state=reason, offered_seq=first.seq)
        duplicates = found
    new = records[duplicates:]
    if not new:
        return Accepted((), duplicates, held.head, None, (), None)
    prune = _room(held, sum(len(record.line) + 1 for record in new), now, max_bytes, keep_ms)
    if prune is None:
        message = "the copy is full and holds nothing received long enough ago to prune"
        return Refused(409, "full", message, state="full", offered_seq=first.seq)
    head = Head(new[-1].seq, new[-1].hash)
    return Accepted(tuple(r.line for r in new), duplicates, head, start, prune, new[0].seq)


def _parse(line: bytes) -> Record | None:
    try:
        return ledgerformat.parse(line)
    except LedgerFormatError:
        return None


def _bad_line(index: int) -> Refused:
    message = f"line {index} isn't a canonical v1 ledger record"
    return Refused(400, "bad_line", message, index=index)


def _lines(report: Any) -> list[bytes] | Refused:
    """Row 2's shape: the body's lines as bytes, or ``bad_body``."""
    refused = Refused(400, "bad_body", f'expected {{"v": 1, "lines": [1 to {MAX_LINES} lines]}}')
    if not isinstance(report, dict) or set(report) != {"v", "lines"}:
        return refused
    version, lines = report["v"], report["lines"]
    if type(version) is not int or version != VERSION or not isinstance(lines, list):
        return refused
    if not 1 <= len(lines) <= MAX_LINES or not all(isinstance(line, str) for line in lines):
        return refused
    found: list[bytes] = []
    for index, line in enumerate(lines):
        try:
            found.append(line.encode("utf-8"))
        except UnicodeEncodeError:
            return _bad_line(index)
    return found


def _held_through(seq: int, hash_: str | None, records: list[Record]) -> int | None:
    """Rows 6 and 7: how many leading records the copy already holds, when the rest extends its
    head at ``seq`` with ``hash_``: 0 when the first extends it, else up to the head's record if
    the batch holds it. None when neither (a gap or a fork)."""
    first = records[0]
    if first.seq == seq + 1 and first.prev == hash_:
        return 0
    index = seq - first.seq
    if 0 <= index < len(records) and records[index].hash == hash_:
        return index + 1
    return None


def _room(
    held: Held, adding: int, now: int, max_bytes: int, keep_ms: int
) -> tuple[str, ...] | None:
    """Row 10: the live files to prune, oldest first, so ``adding`` more bytes fit; None when they
    can't. A file goes only once the vault received its last line more than ``keep_ms`` ago, so a
    flood can't push out recent history; the newest file, which takes the next lines, never goes.
    """
    total = held.size + adding
    prune: list[str] = []
    for file in held.files[:-1]:
        if total <= max_bytes or now - file.received_ms <= keep_ms:
            break
        prune.append(file.name)
        total -= file.size
    return tuple(prune) if total <= max_bytes else None


# --- the restart (J.4) ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Epoch:
    """An archived chain: its seq range, when the vault last received a line of it (ms), its
    size. A dropped epoch's head stays in ``head.json`` and the log as an anchor."""

    name: str
    first_seq: int
    head_seq: int
    head_hash: str
    received_ms: int
    size: int


def archive(held: Held, name: str) -> Epoch | None:
    """The live chain as the epoch a restart moves to ``name``; None when the copy holds none."""
    if held.head_seq is None or held.head_hash is None or held.received_ms is None:
        return None
    first = held.head_seq if held.start_seq is None else held.start_seq
    return Epoch(name, first, held.head_seq, held.head_hash, held.received_ms, held.size)


def plan_restart(
    archives: Sequence[Epoch],
    live: Epoch | None,
    *,
    max_bytes: int = REPORTED_ARCHIVE_MAX_BYTES,
) -> tuple[Epoch, ...]:
    """The epochs a restart deletes, oldest first, so the archives (``archives``, oldest first,
    then ``live`` once archived) fit ``max_bytes``. The step-up summary lists each one, so the
    operator decides it. Since the live chain is kept within :data:`REPORTED_MAX_BYTES`, a restart
    always makes room: the copy is then empty and the next honest report is accepted.
    """
    epochs = [*archives, *([] if live is None else [live])]
    total = sum(epoch.size for epoch in epochs)
    dropped: list[Epoch] = []
    for epoch in epochs:
        if total <= max_bytes:
            break
        dropped.append(epoch)
        total -= epoch.size
    return tuple(dropped)
