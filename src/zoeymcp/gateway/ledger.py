"""The approval ledger on disk (M4 design F.3 to F.5).

Records come from :mod:`zoeymcp.common.ledgerformat`; this module does the file I/O around them:

- **Files** ``ledger/<first seq, 12 digits>.jsonl``, mode 0600, one record per line, each written
  and fsynced before the call that needed it goes on. A new file starts at 4 MiB; the oldest files
  are deleted beyond ``limits.ledger_max_bytes``.
- **The key** ``ledger.key``: 32 random bytes made at first start. Arguments and prompt text are
  recorded only as HMACs under it, so a reader of the files can't test guesses of short values.
- **The open-ref index** ``ledger/open.json`` lists refs with an ``asked`` record and no
  ``outcome``, rewritten atomically after each record, so start-up needn't read every file.
- **Recovery** before the listener opens: a torn last line is moved aside, the newest file's
  chain is checked, and every open ref is closed with exactly one ``outcome``.
- **Failures**: an ``asked`` or ``decided accept`` that can't be written raises
  :class:`LedgerUnavailable`, so nothing is asked or forwarded. Other records are queued in memory
  and retried every 5 s; with 1,024 queued, :attr:`Ledger.accepting` is false and new approvals
  are refused.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

import anyio

from ..common import canonical, files, ledgerformat
from ..common.ledgerformat import GENESIS, Kind, LedgerFormatError, Record
from ..common.logs import refuse_type
from . import logs

LEDGER_DIR: Final = "ledger"
KEY_FILE: Final = "ledger.key"
INDEX_FILE: Final = "open.json"
ROTATE_BYTES: Final = 4 * 2**20
MAX_QUEUED: Final = 1024
RETRY_SECONDS: Final = 5.0
MAX_READ: Final = 10_000
_FILE = re.compile(r"^(\d{12})\.jsonl$")
# O_BINARY: without it, Windows turns each newline into CR LF (it is 0 elsewhere).
_APPEND_FLAGS: Final = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_BINARY", 0)


class LedgerUnavailable(RuntimeError):
    """A record that had to be on disk before the call goes on couldn't be written."""


class LedgerKey:
    """The ledger's HMAC key. Its ``repr`` hides it, and logging it raises."""

    __slots__ = ("_key",)

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("a ledger key is 32 bytes")
        self._key = key

    def digest(self, data: bytes) -> str:
        return "hmac-sha256:" + hmac.new(self._key, data, hashlib.sha256).hexdigest()

    def __repr__(self) -> str:
        return "LedgerKey(<hidden>)"


refuse_type(LedgerKey)


def load_key(path: Path) -> LedgerKey:
    """The key at ``path``, made (0600) if it isn't there yet."""
    try:
        return LedgerKey(path.read_bytes())
    except FileNotFoundError:
        files.write_atomic(path, secrets.token_bytes(32), prefix=".ledger-key-")
        return LedgerKey(path.read_bytes())


def now_ms() -> int:
    return int(time.time() * 1000)


@dataclass(frozen=True)
class Anchor:
    """A written record's place in the chain, for the log line that cites it (F.2)."""

    seq: int
    hash: str


@dataclass
class _Queued:
    kind: Kind
    ref: str | None
    fields: dict[str, Any]


@dataclass
class Recovery:
    """What start-up found and did."""

    torn_bytes: int = 0
    chain_broken_at: int | None = None
    index_rebuilt: bool = False
    closed: dict[str, int] = field(default_factory=dict)  # recovered counts, when any were open


class Ledger:
    """One gateway's ledger. Methods that touch files run in a worker thread when awaited."""

    def __init__(
        self, state_dir: Path, *, max_bytes: int, clock: Callable[[], int] = now_ms
    ) -> None:
        self.dir = state_dir / LEDGER_DIR
        self.key = load_key(state_dir / KEY_FILE)
        self.max_bytes = max_bytes
        self.clock = clock
        self.next_seq = 0
        self.prev = GENESIS
        self.open: dict[str, list[str]] = {}  # ref -> kinds written so far
        self.queue: list[_Queued] = []
        self._lock = anyio.Lock()
        self._current: Path | None = None
        self._current_size = 0

    # --- start-up ----------------------------------------------------------------------------

    @classmethod
    def open_at(
        cls, state_dir: Path, *, max_bytes: int, clock: Callable[[], int] = now_ms
    ) -> tuple[Ledger, Recovery]:
        """Open the ledger and recover it (F.5), before the listener opens."""
        state_dir.joinpath(LEDGER_DIR).mkdir(mode=0o700, parents=True, exist_ok=True)
        ledger = cls(state_dir, max_bytes=max_bytes, clock=clock)
        return ledger, ledger._recover()

    def _files(self) -> list[Path]:
        return sorted(p for p in self.dir.iterdir() if _FILE.match(p.name))

    def _recover(self) -> Recovery:
        report = Recovery()
        found = self._files()
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
            start_seq = int(_FILE.match(newest.name).group(1))  # type: ignore[union-attr]
            start_prev = self._last_hash(found[-2]) if len(found) > 1 else None
            if start_prev is None:
                start_prev = self._first_prev(lines)
            verified = ledgerformat.verify(lines, prev=start_prev, seq=start_seq)
            self.next_seq, self.prev = verified.head_seq + 1, verified.head_hash
            if verified.broken_at is not None:
                report.chain_broken_at = verified.broken_at
                logs.event("ledger_chain_broken", seq=verified.broken_at, level="critical")
                if verified.records == 0:
                    newest.rename(self.dir / f"broken-{self.clock()}-{newest.name}")
                self._current = None  # the next record starts a new file
            else:
                self._current, self._current_size = newest, len(data)
        # The index first: every record appended from here on rewrites it.
        self.open, report.index_rebuilt = self._load_index()
        if report.torn_bytes:
            self._append("repaired", None, {"torn_bytes": report.torn_bytes})
            logs.event("ledger_repaired", torn_bytes=report.torn_bytes)
        open_records = self._open_records()
        steps = ledgerformat.recovery_plan(open_records)
        for step in steps:
            self._append(step.kind, step.ref, dict(step.fields))
        if steps:
            report.closed = dict(steps[-1].fields)
            logs.event("ledger_recovered", **report.closed)
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
        found = ledgerformat.open_refs(self._records())
        return {ref: [r.kind for r in records] for ref, records in found.items()}, True

    def _open_records(self) -> dict[str, list[Record]]:
        """The open refs' records, read back from the files (the index has only their kinds)."""
        if not self.open:
            return {}
        wanted = set(self.open)
        found: dict[str, list[Record]] = {}
        for record in self._records():
            if record.ref in wanted:
                found.setdefault(record.ref, []).append(record)
        return {ref: records for ref, records in found.items() if records[0].kind == "asked"}

    # --- writing ------------------------------------------------------------------------------

    @property
    def accepting(self) -> bool:
        """Whether new approvals may start: false once the in-memory queue is full."""
        return len(self.queue) < MAX_QUEUED

    def digest(self, value: canonical.JSONValue) -> str:
        """The keyed digest of a JSON value's canonical bytes."""
        return self.key.digest(canonical.dumps_canonical(value))

    def text_digest(self, text: str) -> str:
        return self.key.digest(text.encode("utf-8"))

    async def write(
        self, kind: Kind, ref: str | None, *, critical: bool, **fields: Any
    ) -> Anchor | None:
        """Append one record. With ``critical``, failure raises :class:`LedgerUnavailable`;
        otherwise the record is queued and retried, and None is returned."""
        async with self._lock:
            if not critical and self.queue:
                self.queue.append(_Queued(kind, ref, fields))  # keep the order
                return None
            try:
                return await anyio.to_thread.run_sync(self._append, kind, ref, fields)
            except (OSError, LedgerFormatError) as exc:
                logs.event(
                    "ledger_write_failed",
                    record_kind=kind,
                    error_type=type(exc).__name__,
                    queued=len(self.queue) + (0 if critical else 1),
                    level="critical",
                )
                if critical:
                    raise LedgerUnavailable(kind) from exc
                self.queue.append(_Queued(kind, ref, fields))
                return None

    async def flush_queue(self) -> int:
        """Retry queued records in order; returns how many are still queued."""
        async with self._lock:
            while self.queue:
                item = self.queue[0]
                try:
                    await anyio.to_thread.run_sync(self._append, item.kind, item.ref, item.fields)
                except OSError:
                    break
                self.queue.pop(0)
            return len(self.queue)

    async def retry_forever(self) -> None:
        while True:
            await anyio.sleep(RETRY_SECONDS)
            if self.queue:
                await self.flush_queue()

    def _append(self, kind: Kind, ref: str | None, fields: dict[str, Any]) -> Anchor:
        line = ledgerformat.encode(
            kind, seq=self.next_seq, prev=self.prev, ts=self.clock(), ref=ref, **fields
        )
        if self._current is None or (
            self._current_size + len(line) > ROTATE_BYTES and self._current_size
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
        self._write_index()
        self._prune()
        return anchor

    def _write_index(self) -> None:
        index = {"v": 1, "head_seq": self.next_seq - 1, "refs": self.open}
        files.write_atomic(self.dir / INDEX_FILE, canonical.dumps_canonical(index), prefix=".open-")

    def _prune(self) -> None:
        found = self._files()
        sizes = {p: p.stat().st_size for p in found}
        total = sum(sizes.values())
        for path in found[:-1]:
            if total <= self.max_bytes:
                break
            first = int(_FILE.match(path.name).group(1))  # type: ignore[union-attr]
            last = self._last_seq(path)
            with contextlib.suppress(OSError):
                path.unlink()
                total -= sizes[path]
                logs.event("ledger_pruned", first_seq=first, last_seq=last)

    def _last_seq(self, path: Path) -> int | None:
        for line in reversed(path.read_bytes().splitlines()):
            try:
                return ledgerformat.parse(line).seq
            except LedgerFormatError:
                continue
        return None

    # --- reading ------------------------------------------------------------------------------

    def _records(self) -> Iterator[Record]:
        for path in self._files():
            for line in path.read_bytes().splitlines():
                try:
                    yield ledgerformat.parse(line)
                except LedgerFormatError:
                    continue

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
        for record in self._records():
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
        for path in self._files():
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

    def check(self, ref: str, args: canonical.JSONValue) -> dict[str, Any]:
        """Whether ``args`` are the arguments the ``asked`` record of ``ref`` was made for (F.4)."""
        for record in self._records():
            if record.ref == ref and record.kind == "asked":
                return {
                    "ref": ref,
                    "found": True,
                    "matches": hmac.compare_digest(record.fields["args"], self.digest(args)),
                }
        return {"ref": ref, "found": False, "matches": False}
