"""An approval ledger's files (M4 design F.3 to F.5; M8 design J.1's file layer).

Records come from :mod:`.ledgerformat`; this module does the file I/O around them, for any
writer's chain. It moved here from the gateway's ledger without a change, so that the vault's
chain uses the same files; each role wraps it with its own key and its own failure rules
(:mod:`zoeymcp.gateway.ledger` for the gateway):

- **Files** ``<first seq, 12 digits>.jsonl`` in the chain's directory, mode 0600, one record per
  line, each written and fsynced before :meth:`LedgerFile.append` returns. A new file starts at
  ``rotate_bytes``; the oldest files are deleted beyond ``max_bytes``, and with ``keep_ms`` (the
  vault's chain, M8 design J.1) only once their last record is that old, so the files may stay
  over ``max_bytes`` until then.
- **The open-ref index** ``open.json`` lists refs with an ``asked`` record and no ``outcome``,
  rewritten atomically after each record, so start-up needn't read every file.
- **Recovery** before the listener opens: a torn last line is moved aside, the newest file's
  chain is checked, and every open ref is closed with exactly one ``outcome``; the report names
  each ref closed and its outcome.
- **Reading** back: the records, the stored lines after a seq (the report's), and the chain's
  walk.

Every method does blocking file I/O; a role's wrapper runs it in a worker thread. Standard
library only.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from . import canonical, files, ledgerformat
from .ledgerformat import GENESIS, Kind, LedgerFormatError, Record

INDEX_FILE: Final = "open.json"
ROTATE_BYTES: Final = 4 * 2**20
MAX_READ: Final = 10_000
_FILE = re.compile(r"^(\d{12})\.jsonl$")
# O_BINARY: without it, Windows turns each newline into CR LF (it is 0 elsewhere).
_APPEND_FLAGS: Final = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_BINARY", 0)


@dataclass(frozen=True)
class Anchor:
    """A written record's place in the chain, for the log line that cites it (F.2)."""

    seq: int
    hash: str


@dataclass
class Recovery:
    """What start-up found and did."""

    torn_bytes: int = 0
    chain_broken_at: int | None = None
    index_rebuilt: bool = False
    closed: dict[str, int] = field(default_factory=dict)  # recovered counts, when any were open
    ended: dict[str, str] = field(default_factory=dict)  # each ref closed -> its outcome


class LedgerFile:
    """One chain's files in ``directory``, which must exist. ``event`` writes the role's log
    lines; ``writer`` is the records' ``writer`` field. With ``keep_ms``, a file is pruned only
    once its last record's ``ts`` is more than that before ``clock()``."""

    def __init__(
        self,
        directory: Path,
        *,
        max_bytes: int,
        clock: Callable[[], int],
        event: Callable[..., None],
        writer: str,
        rotate_bytes: int = ROTATE_BYTES,
        keep_ms: int | None = None,
    ) -> None:
        self.dir = directory
        self.max_bytes = max_bytes
        self.clock = clock
        self.event = event
        self.rotate_bytes = rotate_bytes
        self.writer = writer
        self.keep_ms = keep_ms
        # After each prune: the files' bytes, and when the oldest file keep_ms held back from a
        # prune may go (on ``clock``), or None when none was held back.
        self.size = 0
        self.prunable_at: int | None = None
        self.next_seq = 0
        self.prev = GENESIS
        self.open: dict[str, list[str]] = {}  # ref -> kinds written so far
        self._current: Path | None = None
        self._current_size = 0

    # --- start-up ----------------------------------------------------------------------------

    def files(self) -> list[Path]:
        return sorted(p for p in self.dir.iterdir() if _FILE.fullmatch(p.name))

    def recover(self) -> Recovery:
        """Repair, check and close the chain (F.5), before the listener opens."""
        report = Recovery()
        found = self.files()
        if found:
            newest = found[-1]
            data = newest.read_bytes()
            torn = ledgerformat.torn_tail(data)
            if torn:
                aside = self.dir / f"torn-{self.clock()}.bin"
                aside.write_bytes(data[-torn:])
                os.chmod(aside, 0o600)
                with open(newest, "r+b") as handle:
                    handle.truncate(len(data) - torn)
                    handle.flush()
                    os.fsync(handle.fileno())
                data = data[:-torn]
                report.torn_bytes = torn
            lines = data.splitlines(keepends=True)
            start_seq = int(_FILE.fullmatch(newest.name).group(1))  # type: ignore[union-attr]
            start_prev = self._last_hash(found[-2]) if len(found) > 1 else None
            if start_prev is None:
                start_prev = self._first_prev(lines)
            verified = ledgerformat.verify(lines, prev=start_prev, seq=start_seq)
            self.next_seq, self.prev = verified.head_seq + 1, verified.head_hash
            if verified.broken_at is not None:
                report.chain_broken_at = verified.broken_at
                self.event("ledger_chain_broken", seq=verified.broken_at, level="critical")
                if verified.records == 0:
                    newest.rename(self.dir / f"broken-{self.clock()}-{newest.name}")
                self._current = None  # the next record starts a new file
            else:
                self._current, self._current_size = newest, len(data)
        # The index first: every record appended from here on rewrites it.
        self.open, report.index_rebuilt = self._load_index()
        if report.torn_bytes:
            self.append("repaired", None, {"torn_bytes": report.torn_bytes})
            self.event("ledger_repaired", torn_bytes=report.torn_bytes)
        open_records = self._open_records()
        steps = ledgerformat.recovery_plan(open_records)
        for step in steps:
            self.append(step.kind, step.ref, dict(step.fields))
        if steps:
            report.closed = dict(steps[-1].fields)
            report.ended = {
                step.ref: step.fields["outcome"]
                for step in steps
                if step.kind == "outcome" and step.ref is not None
            }
            self.event("ledger_recovered", **report.closed)
        return report

    def _last_hash(self, path: Path) -> str | None:
        lines = path.read_bytes().splitlines()
        for line in reversed(lines):
            try:
                return ledgerformat.parse(line).hash
            except LedgerFormatError:
                continue
        return None

    @staticmethod
    def _first_prev(lines: list[bytes]) -> str:
        """The chain's start when no earlier file is left: what the first record says."""
        if not lines:
            return GENESIS
        try:
            return ledgerformat.parse(lines[0]).prev
        except LedgerFormatError:
            return GENESIS

    def _load_index(self) -> tuple[dict[str, list[str]], bool]:
        """The open refs from the index if it matches the files, else from a full scan."""
        path = self.dir / INDEX_FILE
        try:
            index = json.loads(path.read_bytes())
            if index.get("v") == 1 and index.get("head_seq") == self.next_seq - 1:
                refs = index.get("refs")
                if isinstance(refs, dict) and all(isinstance(v, list) for v in refs.values()):
                    return {str(k): [str(x) for x in v] for k, v in refs.items()}, False
        except (OSError, ValueError, AttributeError):
            pass
        found = ledgerformat.open_refs(self.records())
        return {ref: [r.kind for r in records] for ref, records in found.items()}, True

    def _open_records(self) -> dict[str, list[Record]]:
        """The open refs' records, read back from the files (the index has only their kinds)."""
        if not self.open:
            return {}
        wanted = set(self.open)
        found: dict[str, list[Record]] = {}
        for record in self.records():
            if record.ref in wanted:
                found.setdefault(record.ref, []).append(record)
        return {ref: records for ref, records in found.items() if records[0].kind == "asked"}

    # --- writing ------------------------------------------------------------------------------

    def append(self, kind: Kind, ref: str | None, fields: dict[str, Any]) -> Anchor:
        """Write and fsync one record, then the index. Raises ``OSError`` or
        :class:`~.ledgerformat.LedgerFormatError`, and then nothing has moved on; once the record
        is on disk it doesn't raise, so a caller never writes it again (M8 design J.1)."""
        line = ledgerformat.encode(
            kind,
            seq=self.next_seq,
            prev=self.prev,
            ts=self.clock(),
            ref=ref,
            writer=self.writer,
            **fields,
        )
        if self._current is None or (
            self._current_size + len(line) > self.rotate_bytes and self._current_size
        ):
            self._current, self._current_size = self.dir / f"{self.next_seq:012d}.jsonl", 0
        descriptor = os.open(self._current, _APPEND_FLAGS, 0o600)
        try:
            written = os.write(descriptor, line)
            if written != len(line):
                raise OSError("short write to the ledger")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        anchor = Anchor(self.next_seq, ledgerformat.line_hash(line))
        self.next_seq, self.prev = anchor.seq + 1, anchor.hash
        self._current_size += len(line)
        if ref is not None:
            if kind == "outcome":
                self.open.pop(ref, None)
            else:
                self.open.setdefault(ref, []).append(kind)
        # The record is durable. An index that couldn't be rewritten is rebuilt at start (its
        # head_seq won't match), and the next append prunes again.
        with contextlib.suppress(OSError):
            self._write_index()
        with contextlib.suppress(OSError):
            self.prune()
        return anchor

    def _write_index(self) -> None:
        index = {"v": 1, "head_seq": self.next_seq - 1, "refs": self.open}
        files.write_atomic(self.dir / INDEX_FILE, canonical.dumps_canonical(index), prefix=".open-")

    def prune(self) -> None:
        """Delete the oldest files while the files are over ``max_bytes``, never the newest,
        which takes the next record; with ``keep_ms``, stop at a file whose last record is that
        recent. Each append ends with it."""
        found = self.files()
        sizes = {p: p.stat().st_size for p in found}
        total = sum(sizes.values())
        self.prunable_at = None
        for path in found[:-1]:
            if total <= self.max_bytes:
                break
            first = int(_FILE.fullmatch(path.name).group(1))  # type: ignore[union-attr]
            last = self._last_record(path)
            keep = self.keep_ms
            if keep is not None and last is not None and self.clock() - last.ts <= keep:
                self.prunable_at = last.ts + keep
                break
            with contextlib.suppress(OSError):
                path.unlink()
                total -= sizes[path]
                seq = None if last is None else last.seq
                self.event("ledger_pruned", first_seq=first, last_seq=seq)
        self.size = total

    def _last_record(self, path: Path) -> Record | None:
        for line in reversed(path.read_bytes().splitlines()):
            try:
                return ledgerformat.parse(line)
            except LedgerFormatError:
                continue
        return None

    # --- reading ------------------------------------------------------------------------------

    def records(self) -> Iterator[Record]:
        """Every record in the files, oldest first; a line that doesn't parse is left out, and
        so is a file pruned since it was listed (a reader in another thread, M8 design J.2)."""
        for path in self.files():
            try:
                data = path.read_bytes()
            except FileNotFoundError:
                continue  # pruned since it was listed
            for line in data.splitlines():
                try:
                    yield ledgerformat.parse(line)
                except LedgerFormatError:
                    continue

    def lines(self, after: int, limit: int) -> list[bytes]:
        """Up to ``limit`` stored lines with a seq above ``after``, oldest first, each as it is
        on disk without its newline: what the reporter sends (M5 design J.3). Only records whose
        append had returned when the read began are read, so each is whole and fsynced; a line
        that doesn't parse is left out, as :meth:`read` leaves it."""
        below = self.next_seq  # an append under way writes this seq, and is left for next time
        found: list[bytes] = []
        paths = self.files()
        starts = [int(_FILE.fullmatch(p.name).group(1)) for p in paths]  # type: ignore[union-attr]
        for index, path in enumerate(paths):
            if index + 1 < len(paths) and starts[index + 1] - 1 <= after:
                continue  # every record in this file is at or below ``after``
            try:
                data = path.read_bytes()
            except FileNotFoundError:
                continue  # pruned since it was listed
            for line in data.splitlines():
                try:
                    record = ledgerformat.parse(line)
                except LedgerFormatError:
                    continue
                if record.seq >= below:
                    return found
                if record.seq > after:
                    found.append(record.line)
                    if len(found) >= limit:
                        return found
        return found

    def read(
        self,
        *,
        after: int = -1,
        limit: int = 1000,
        client: str | None = None,
        server: str | None = None,
        tool: str | None = None,
    ) -> list[dict[str, Any]]:
        """Records after ``after``, oldest first, as JSON objects. The filters keep the records of
        refs whose ``asked`` record matches; ledger-level records always pass."""
        limit = max(1, min(limit, MAX_READ))
        wanted: dict[str, bool] = {}
        found: list[dict[str, Any]] = []
        for record in self.records():
            if record.kind == "asked":
                fields = record.fields
                wanted[record.ref or ""] = (
                    (client is None or fields["client"] == client)
                    and (server is None or fields["server"] == server)
                    and (tool is None or fields["tool"] == tool)
                )
            if record.seq <= after:
                continue
            if record.ref is not None and not wanted.get(
                record.ref, client is None and server is None and tool is None
            ):
                continue
            found.append(json.loads(record.line))
            if len(found) >= limit:
                break
        return found

    def verify(self) -> dict[str, Any]:
        """Walk every file's chain in order (F.2), from what the oldest file says it follows."""
        lines: list[bytes] = []
        for path in self.files():
            lines.extend(path.read_bytes().splitlines(keepends=True))
        start = self._first_prev(lines)
        first_seq = ledgerformat.parse(lines[0]).seq if lines else 0
        result = ledgerformat.verify(lines, prev=start, seq=first_seq)
        return {
            "records": result.records,
            "head_seq": result.head_seq,
            "head_hash": result.head_hash,
            "broken_at": result.broken_at,
            "ok": result.broken_at is None,
        }
