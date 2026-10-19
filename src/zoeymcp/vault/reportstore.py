"""The vault's copy of the gateway's ledger, on disk (M5 design J.4, N).

The gateway pushes its ledger over the link (:data:`~zoeymcp.common.ledgerreport.PATH`); this
module keeps what :func:`.reports.decide` accepts, in ``/state/ledger-reported/``:

- **The live chain** ``<first seq, 12 digits>.jsonl``: each line as received, appended with
  ``O_APPEND``, mode 0600, one write and one fsync per file a report touches. A new file starts at
  4 MiB.
- **``head.json``**, through ``write_atomic`` after the lines: ``{"v": 1, "state", "start_seq",
  "start_prev", "head_seq", "head_hash", "refused", "files": {name: last received ms},
  "archives": [...]}``. The lines are the truth and ``head.json`` a cache, except for what only
  it holds: the sticky state, when the vault received each file, and the archived epochs (a
  dropped one stays listed as an anchor, ``dropped: true``).
- **Archives** ``archive-<ms>/``: the live files a restart set aside, still readable.
- **Torn tails** ``torn-<ms>.bin``: a last line that recovery cut.

**Order** (N.2): decide, append and fsync, prune, write ``head.json``, then answer, so an answer
never names a head that isn't on disk; a resend after a crash is a duplicate that ``decide``
trims. A write that fails runs recovery again, which reconciles memory with what reached the disk.

**Recovery**, before any listener opens: a torn last line is moved aside and cut
(``ledger_reported_repaired``), the chain is verified, a break inside the files is logged
(``ledger_reported_broken``, ``critical``) and kept for the view, and a ``head.json`` that
disagrees with the lines is rebuilt from them. A directory that can't be read makes the copy
``unavailable``: the report path answers 503 and the proxy is unaffected.

**Pruning** is by when the vault received a file's last line, on its own clock, never the
records' ``ts`` (``decide`` plans it). **A restart** (:meth:`ReportStore.restart`) archives the
live chain and drops the oldest archives beyond their bound, as :func:`.reports.plan_restart`
plans it; the next report starts a new chain on trust.

No log line holds a ledger line: only seqs, hashes, counts and reasons.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
import shutil
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Final, Literal, cast

from ..common import canonical, files, ledgerformat
from ..common.ledgerformat import LedgerFormatError, Record
from ..common.ledgerreport import STATES, Head, State
from . import logs, reports
from .reports import (
    KEEP_MS,
    REPORTED_ARCHIVE_MAX_BYTES,
    REPORTED_MAX_BYTES,
    Accepted,
    Epoch,
    Held,
    LiveFile,
    Refused,
)

REPORTED_DIR: Final = "ledger-reported"
HEAD_FILE: Final = "head.json"
HEAD_VERSION: Final = 1
ROTATE_BYTES: Final = 4 * 2**20
_FILE = re.compile(r"^(\d{12})\.jsonl$")
_ARCHIVE = re.compile(r"^archive-(\d{13})$")
# O_BINARY: without it, Windows turns each newline into CR LF (it is 0 elsewhere).
_APPEND_FLAGS: Final = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_BINARY", 0)
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")

CopyState = Literal["ok", "fork", "gap", "full", "unavailable"]


def now_ms() -> int:
    return int(time.time() * 1000)


class CopyUnavailable(Exception):
    """The copy's directory can't be read or written: reports get 503."""


class NotRestartable(Exception):
    """A restart only lifts a ``fork``, ``gap`` or ``full``."""


class PlanChanged(Exception):
    """The copy changed since the restart was planned. ``plan`` is the plan now."""

    def __init__(self, plan: RestartPlan) -> None:
        self.plan = plan
        super().__init__("the copy changed since the restart was planned")


@dataclass(frozen=True)
class Archived:
    """An archived epoch, and whether a later restart dropped its files (its head stays)."""

    epoch: Epoch
    dropped: bool = False


@dataclass(frozen=True)
class RestartPlan:
    """What a restart does: the state it lifts, the live chain it archives, and the epochs it
    deletes to keep the archives in bounds (the live one among them when it can't be kept).

    The live epoch's name is ``""`` until the restart runs, since its archive is named by the
    time: two plans of an unchanged copy are equal (F.4's re-plan compares them).
    """

    state: State
    refused: dict[str, Any] | None
    archive: Epoch | None
    drop: tuple[Epoch, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "refused": self.refused,
            "archive": None if self.archive is None else epoch_json(self.archive),
            "drop": [epoch_json(epoch) for epoch in self.drop],
        }


def epoch_json(epoch: Epoch) -> dict[str, Any]:
    return {
        "name": epoch.name or None,
        "first_seq": epoch.first_seq,
        "head_seq": epoch.head_seq,
        "head_hash": epoch.head_hash,
        "received_ms": epoch.received_ms,
        "size": epoch.size,
    }


@dataclass(frozen=True)
class _Saved:
    """What ``head.json`` said, when it parsed."""

    state: State
    start_seq: int | None
    start_prev: str | None
    head_seq: int | None
    head_hash: str | None
    refused: dict[str, Any] | None
    files: dict[str, int]
    archives: tuple[Archived, ...]


class ReportStore:
    """The copy. Methods that touch files are synchronous: the vault calls them from a worker
    thread, one at a time under :attr:`lock`."""

    def __init__(
        self,
        directory: Path,
        *,
        clock: Callable[[], int] = now_ms,
        max_bytes: int = REPORTED_MAX_BYTES,
        archive_max_bytes: int = REPORTED_ARCHIVE_MAX_BYTES,
        keep_ms: int = KEEP_MS,
        rotate_bytes: int = ROTATE_BYTES,
    ) -> None:
        self.directory = directory
        self.clock = clock
        self.max_bytes = max_bytes
        self.archive_max_bytes = archive_max_bytes
        self.keep_ms = keep_ms
        self.rotate_bytes = rotate_bytes
        # Unavailable until recovered.
        self.available = False
        self.held = Held()
        self.start_prev: str | None = None
        self.refused: dict[str, Any] | None = None
        self.broken_at: int | None = None
        self.archived: list[Archived] = []
        self.started_ms = clock()
        # When the gateway last asked for the head or reported, since the vault started.
        self.contact_ms: int | None = None
        # One report or restart at a time (N.4).
        self.lock = asyncio.Lock()

    @classmethod
    def open(cls, state_dir: Path, **options: Any) -> ReportStore:
        """The copy in ``state_dir``, recovered. Never raises: a copy that can't be read is
        ``unavailable``."""
        store = cls(state_dir / REPORTED_DIR, **options)
        store.recover()
        return store

    @property
    def state(self) -> CopyState:
        return self.held.state if self.available else "unavailable"

    def head(self) -> Head:
        return self.held.head

    def contact(self) -> None:
        """The gateway asked or reported just now."""
        self.contact_ms = self.clock()

    # --- recovery ------------------------------------------------------------------------------

    def recover(self) -> None:
        """Recover the copy from its files (J.4). On an ``OSError`` the copy is unavailable."""
        try:
            self._recover()
        except OSError as exc:
            self.available = False
            logs.event(
                "ledger_reported_unavailable", error_type=type(exc).__name__, level="critical"
            )
            return
        self.available = True

    def _recover(self) -> None:
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        saved = self._read_head()
        found = self._live_files()
        torn = 0
        if found:
            newest = found[-1]
            data = newest.read_bytes()
            torn = ledgerformat.torn_tail(data)
            if torn:
                aside = self.directory / f"torn-{self.clock()}.bin"
                aside.write_bytes(data[-torn:])
                os.chmod(aside, 0o600)
                with open(newest, "r+b") as handle:
                    handle.truncate(len(data) - torn)
                    handle.flush()
                    os.fsync(handle.fileno())
        lines: list[bytes] = []
        for path in found:
            lines.extend(path.read_bytes().splitlines(keepends=True))
        records = [record for record in map(_parse, lines) if record is not None]
        self.broken_at = None
        if records:
            first = records[0]
            verified = ledgerformat.verify(lines, prev=first.prev, seq=first.seq)
            self.broken_at = verified.broken_at
            if verified.broken_at is not None:
                logs.event("ledger_reported_broken", seq=verified.broken_at, level="critical")
        received = {} if saved is None else saved.files
        live = tuple(
            LiveFile(path.name, path.stat().st_size, received.get(path.name, _mtime_ms(path)))
            for path in found
        )
        state: State = "ok" if saved is None else saved.state
        self.refused = None if saved is None else saved.refused
        if records:
            first, last = records[0], records[-1]
            # Where the chain began (trust on first use): head.json's, unless the files say
            # otherwise; the oldest file's first record once that start was pruned.
            start_seq, self.start_prev = first.seq, first.prev
            if saved is not None and saved.start_seq is not None and saved.start_prev is not None:
                same = (saved.start_seq, saved.start_prev) == (first.seq, first.prev)
                if same or saved.start_seq < first.seq:
                    start_seq, self.start_prev = saved.start_seq, saved.start_prev
            self.held = Held(state, start_seq, last.seq, last.hash, live)
        else:
            self.start_prev = None
            self.held = Held(state, None, None, None, live)
        self.archived = self._archives(saved)
        rebuilt = bool(found) and (
            saved is None
            or (saved.head_seq, saved.head_hash) != (self.held.head_seq, self.held.head_hash)
            or set(saved.files) != {file.name for file in live}
        )
        if torn or rebuilt:
            logs.event("ledger_reported_repaired", torn_bytes=torn, head_rebuilt=rebuilt)
        if saved is None or saved != self._saved():
            self._write_head()

    def _live_files(self) -> list[Path]:
        return sorted(p for p in self.directory.iterdir() if _FILE.fullmatch(p.name))

    def _read_head(self) -> _Saved | None:
        try:
            data = (self.directory / HEAD_FILE).read_bytes()
        except FileNotFoundError:
            return None
        try:
            value = canonical.loads_strict(data)
        except ValueError:
            return None
        return _parse_head(value)

    def _archives(self, saved: _Saved | None) -> list[Archived]:
        """The archived epochs ``head.json`` lists, a listed one whose directory is gone marked
        dropped, and any archive directory it doesn't list (a restart cut short) added."""
        listed = list(() if saved is None else saved.archives)
        names = {item.epoch.name for item in listed}
        present = {p.name for p in self.directory.iterdir() if _ARCHIVE.fullmatch(p.name)}
        found = [
            item if item.dropped or item.epoch.name in present else replace(item, dropped=True)
            for item in listed
        ]
        for name in sorted(present - names):
            epoch = self._scan_archive(self.directory / name)
            if epoch is not None:
                found.append(Archived(epoch))
        return found

    def _scan_archive(self, directory: Path) -> Epoch | None:
        paths = sorted(p for p in directory.iterdir() if _FILE.fullmatch(p.name))
        records = [
            record
            for path in paths
            for record in map(_parse, path.read_bytes().splitlines())
            if record is not None
        ]
        if not records:
            return None
        size = sum(path.stat().st_size for path in paths)
        received = max(_mtime_ms(path) for path in paths)
        last = records[-1]
        return Epoch(directory.name, records[0].seq, last.seq, last.hash, received, size)

    # --- reports -------------------------------------------------------------------------------

    def report(self, body: Any) -> Accepted | Refused:
        """Decide a report (the parsed body) and apply it: J.2's rows, then N.2's order.

        Raises :class:`CopyUnavailable` when the copy can't be read, or a write failed (the copy
        is then recovered again from what reached the disk)."""
        if not self.available:
            raise CopyUnavailable
        now = self.clock()
        result = reports.decide(
            self.held, body, now=now, max_bytes=self.max_bytes, keep_ms=self.keep_ms
        )
        if isinstance(result, Refused):
            if result.state is not None:
                self._refuse(result, now)
            return result
        if result.from_seq is None:
            return result  # every line was a duplicate: nothing changes
        try:
            self._apply(result, now)
        except OSError as exc:
            logs.event(
                "ledger_reported_not_written", error_type=type(exc).__name__, level="critical"
            )
            self.recover()
            raise CopyUnavailable from exc
        return result

    def _refuse(self, refused: Refused, now: int) -> None:
        """Rows 8-10: the state sticks until a restart."""
        assert refused.state is not None  # noqa: S101 - only sticky refusals come here
        self.held = replace(self.held, state=refused.state)
        self.refused = {
            "reason": refused.reason,
            "held_seq": self.held.head_seq,
            "offered_seq": refused.offered_seq,
            "at": now,
        }
        logs.event(
            "ledger_report_refused",
            reason=refused.reason,
            held_seq=self.held.head_seq,
            offered_seq=refused.offered_seq,
            level="critical",
        )
        try:
            self._write_head()
        except OSError as exc:
            # The state holds in memory; a restart of the vault decides the report again.
            logs.event("ledger_reported_not_written", error_type=type(exc).__name__, level="error")

    def _apply(self, accepted: Accepted, now: int) -> None:
        assert accepted.from_seq is not None  # noqa: S101 - checked by report()
        kept = [file for file in self.held.files if file.name not in accepted.prune]
        sizes = {file.name: file.size for file in kept}
        received = {file.name: file.received_ms for file in kept}
        current = kept[-1].name if kept else None
        batches: dict[str, list[bytes]] = {}
        for seq, line in enumerate(accepted.lines, start=accepted.from_seq):
            size = len(line) + 1
            if current is None or (sizes[current] and sizes[current] + size > self.rotate_bytes):
                current = f"{seq:012d}.jsonl"
                sizes[current] = 0
            batches.setdefault(current, []).append(line + b"\n")
            sizes[current] += size
            received[current] = now
        for name, lines in batches.items():
            _append(self.directory / name, b"".join(lines))
        for name in accepted.prune:
            with contextlib.suppress(FileNotFoundError):
                (self.directory / name).unlink()
        if accepted.start is not None:
            start_seq: int | None = accepted.start[0]
            self.start_prev = accepted.start[1]
        else:
            start_seq = self.held.start_seq
        live = tuple(LiveFile(name, sizes[name], received[name]) for name in sorted(sizes))
        head = accepted.head
        self.held = Held("ok", start_seq, head.seq, head.hash, live)
        self._write_head()
        logs.event(
            "ledger_report_accepted",
            from_seq=accepted.from_seq,
            head_seq=head.seq,
            head_hash=head.hash,
            pruned=len(accepted.prune),
        )

    # --- the restart ---------------------------------------------------------------------------

    def plan_restart(self) -> RestartPlan:
        """What :meth:`restart` would do now. Raises :class:`NotRestartable` for a copy that
        takes reports, :class:`CopyUnavailable` for one that can't be read."""
        if not self.available:
            raise CopyUnavailable
        if self.held.state == "ok":
            raise NotRestartable
        live = reports.archive(self.held, "")
        kept = [item.epoch for item in self.archived if not item.dropped]
        drop = reports.plan_restart(kept, live, max_bytes=self.archive_max_bytes)
        return RestartPlan(self.held.state, self.refused, live, drop)

    def restart(self, expected: RestartPlan | None = None) -> RestartPlan:
        """``ledger.restart``: archive the live chain, delete the epochs the plan drops, and
        start again with no copy. With ``expected``, refuse (:class:`PlanChanged`) unless the
        plan is still that one. Returns the plan as run, the archive named."""
        plan = self.plan_restart()
        if expected is not None and expected != plan:
            raise PlanChanged(plan)
        archive = plan.archive
        if archive is not None:
            archive = replace(archive, name=self._archive_name())
            target = self.directory / archive.name
            keep = plan.archive not in plan.drop
            if keep:
                target.mkdir(mode=0o700)
            for file in self.held.files:
                path = self.directory / file.name
                if keep:
                    os.replace(path, target / file.name)
                else:
                    path.unlink(missing_ok=True)
        dropped = {epoch.name for epoch in plan.drop if epoch.name}
        for name in sorted(dropped):
            shutil.rmtree(self.directory / name, ignore_errors=True)
        self.archived = [
            replace(item, dropped=True) if item.epoch.name in dropped else item
            for item in self.archived
        ]
        if archive is not None:
            self.archived.append(Archived(archive, dropped=plan.archive in plan.drop))
        self.held, self.start_prev, self.refused, self.broken_at = Held(), None, None, None
        self._write_head()
        # The live epoch, if dropped, under the name it was archived as.
        drop = tuple(epoch if epoch.name or archive is None else archive for epoch in plan.drop)
        logs.event(
            "ledger_reported_restarted",
            lifted=plan.state,
            archived=None if archive is None else _anchor(archive),
            dropped=[_anchor(epoch) for epoch in drop],
        )
        return RestartPlan(plan.state, plan.refused, archive, drop)

    def _archive_name(self) -> str:
        """``archive-<ms>``, after every archive there is, even within one millisecond."""
        stamps = [_ARCHIVE.fullmatch(item.epoch.name) for item in self.archived]
        last = max((int(m.group(1)) for m in stamps if m is not None), default=-1)
        return f"archive-{max(self.clock(), last + 1):013d}"

    # --- reading -------------------------------------------------------------------------------

    def records(self) -> list[dict[str, Any]]:
        """The live chain's records up to the head, oldest first, as JSON objects (the view's
        input). A line that doesn't parse is left out; the view marks the break."""
        if not self.available:
            raise CopyUnavailable
        head = self.held.head_seq
        found: list[dict[str, Any]] = []
        if head is None:
            return found
        for file in self.held.files:
            try:
                data = (self.directory / file.name).read_bytes()
            except FileNotFoundError:
                continue  # pruned meanwhile
            for line in data.splitlines():
                record = _parse(line)
                if record is not None and record.seq <= head:
                    found.append(json.loads(record.line))
        return found

    def archives(self) -> list[dict[str, Any]]:
        """Every archived epoch, oldest first, a dropped one as its anchor."""
        return [{**epoch_json(item.epoch), "dropped": item.dropped} for item in self.archived]

    # --- head.json -----------------------------------------------------------------------------

    def _saved(self) -> _Saved:
        return _Saved(
            self.held.state,
            self.held.start_seq,
            self.start_prev,
            self.held.head_seq,
            self.held.head_hash,
            self.refused,
            {file.name: file.received_ms for file in self.held.files},
            tuple(self.archived),
        )

    def head_json(self) -> dict[str, Any]:
        held = self.held
        return {
            "v": HEAD_VERSION,
            "state": held.state,
            "start_seq": held.start_seq,
            "start_prev": self.start_prev,
            "head_seq": held.head_seq,
            "head_hash": held.head_hash,
            "refused": self.refused,
            "files": {file.name: file.received_ms for file in held.files},
            "archives": self.archives(),
        }

    def _write_head(self) -> None:
        data = canonical.dumps_canonical(self.head_json())
        files.write_atomic(self.directory / HEAD_FILE, data, prefix=".head-")


def _append(path: Path, data: bytes) -> None:
    descriptor = os.open(path, _APPEND_FLAGS, 0o600)
    try:
        if os.write(descriptor, data) != len(data):
            raise OSError("short write to the reported copy")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _parse(line: bytes) -> Record | None:
    try:
        return ledgerformat.parse(line)
    except LedgerFormatError:
        return None


def _mtime_ms(path: Path) -> int:
    return int(path.stat().st_mtime * 1000)


def _anchor(epoch: Epoch) -> dict[str, Any]:
    return {
        "name": epoch.name,
        "first_seq": epoch.first_seq,
        "head_seq": epoch.head_seq,
        "head_hash": epoch.head_hash,
    }


# --- parsing head.json ---------------------------------------------------------------------------


def _count(value: Any) -> bool:
    return type(value) is int and value >= 0


def _hash(value: Any) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _parse_head(value: Any) -> _Saved | None:
    """``head.json`` as written, or None for anything else (it is then rebuilt)."""
    keys = {"v", "state", "start_seq", "start_prev", "head_seq", "head_hash", "refused"}
    if not isinstance(value, dict) or set(value) != keys | {"files", "archives"}:
        return None
    if value["v"] != HEAD_VERSION or value["state"] not in STATES:
        return None
    for name in ("start_seq", "head_seq"):
        if value[name] is not None and not _count(value[name]):
            return None
    for name in ("start_prev", "head_hash"):
        if value[name] is not None and not _hash(value[name]):
            return None
    refused = value["refused"]
    if refused is not None and not isinstance(refused, dict):
        return None
    received = value["files"]
    if not isinstance(received, dict) or not all(
        _FILE.fullmatch(name) and _count(ms) for name, ms in received.items()
    ):
        return None
    archives = _parse_archives(value["archives"])
    if archives is None:
        return None
    return _Saved(
        cast(State, value["state"]),
        value["start_seq"],
        value["start_prev"],
        value["head_seq"],
        value["head_hash"],
        refused,
        received,
        archives,
    )


def _parse_archives(value: Any) -> tuple[Archived, ...] | None:
    if not isinstance(value, list):
        return None
    found: list[Archived] = []
    fields = {"name", "first_seq", "head_seq", "head_hash", "received_ms", "size", "dropped"}
    for item in value:
        if not isinstance(item, dict) or set(item) != fields:
            return None
        name = item["name"]
        if not (isinstance(name, str) and _ARCHIVE.fullmatch(name)):
            return None
        counts = ("first_seq", "head_seq", "received_ms", "size")
        if not all(_count(item[key]) for key in counts) or not _hash(item["head_hash"]):
            return None
        if not isinstance(item["dropped"], bool):
            return None
        epoch = Epoch(
            name,
            item["first_seq"],
            item["head_seq"],
            item["head_hash"],
            item["received_ms"],
            item["size"],
        )
        found.append(Archived(epoch, item["dropped"]))
    return tuple(found)
