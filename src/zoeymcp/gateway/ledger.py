"""The approval ledger on disk (M4 design F.3 to F.5).

Records come from :mod:`zoeymcp.common.ledgerformat`, and :mod:`zoeymcp.common.ledgerfile` does
the file I/O around them (files, rotation, the open-ref index, recovery, reading back; M8 design
J.1). This module wraps that file layer with the gateway's key and its failure rules:

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
- **The report** (M5 design J.3): :meth:`Ledger.lines` reads stored lines back for the reporter,
  and :meth:`Ledger.wait_appended` wakes it after an append. Nothing here waits for it.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

import anyio

from ..common import canonical, files
from ..common.ledgerfile import INDEX_FILE as INDEX_FILE
from ..common.ledgerfile import ROTATE_BYTES as ROTATE_BYTES
from ..common.ledgerfile import Anchor as Anchor
from ..common.ledgerfile import LedgerFile
from ..common.ledgerfile import Recovery as Recovery
from ..common.ledgerformat import Kind, LedgerFormatError
from ..common.logs import refuse_type
from . import logs

LEDGER_DIR: Final = "ledger"
KEY_FILE: Final = "ledger.key"
MAX_QUEUED: Final = 1024
RETRY_SECONDS: Final = 5.0


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


@dataclass
class _Queued:
    kind: Kind
    ref: str | None
    fields: dict[str, Any]


class Ledger:
    """One gateway's ledger. Methods that touch files run in a worker thread when awaited."""

    def __init__(
        self, state_dir: Path, *, max_bytes: int, clock: Callable[[], int] = now_ms
    ) -> None:
        self.file = LedgerFile(
            state_dir / LEDGER_DIR,
            max_bytes=max_bytes,
            clock=clock,
            event=logs.event,
            writer="gateway",
            rotate_bytes=ROTATE_BYTES,
        )
        self.key = load_key(state_dir / KEY_FILE)
        self.queue: list[_Queued] = []
        self._lock = anyio.Lock()
        # Appends seen on the event loop, and the event the reporter waits on for the next one.
        # Both change only on the loop, after the worker thread's append returns (J.3).
        self.appended = 0
        self._appended_event: anyio.Event | None = None

    # The file layer's state, through the wrapper; the limit changes on a reload.

    @property
    def max_bytes(self) -> int:
        return self.file.max_bytes

    @max_bytes.setter
    def max_bytes(self, value: int) -> None:
        self.file.max_bytes = value

    @property
    def next_seq(self) -> int:
        return self.file.next_seq

    @next_seq.setter
    def next_seq(self, value: int) -> None:
        self.file.next_seq = value

    @property
    def prev(self) -> str:
        return self.file.prev

    @property
    def open(self) -> dict[str, list[str]]:
        return self.file.open

    # --- start-up ----------------------------------------------------------------------------

    @classmethod
    def open_at(
        cls, state_dir: Path, *, max_bytes: int, clock: Callable[[], int] = now_ms
    ) -> tuple[Ledger, Recovery]:
        """Open the ledger and recover it (F.5), before the listener opens."""
        state_dir.joinpath(LEDGER_DIR).mkdir(mode=0o700, parents=True, exist_ok=True)
        ledger = cls(state_dir, max_bytes=max_bytes, clock=clock)
        return ledger, ledger.file.recover()

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
            written = self.next_seq
            try:
                return await anyio.to_thread.run_sync(self.file.append, kind, ref, fields)
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
            finally:
                self._notify(written)

    async def flush_queue(self) -> int:
        """Retry queued records in order; returns how many are still queued."""
        async with self._lock:
            written = self.next_seq
            try:
                while self.queue:
                    item = self.queue[0]
                    try:
                        await anyio.to_thread.run_sync(
                            self.file.append, item.kind, item.ref, item.fields
                        )
                    except OSError:
                        break
                    self.queue.pop(0)
                return len(self.queue)
            finally:
                self._notify(written)

    def _notify(self, written: int) -> None:
        """Wake the reporter if records reached the disk since ``next_seq`` was ``written``.
        Called on the event loop only: the file layer's append runs in a worker thread and never
        touches the event (J.3)."""
        if self.next_seq == written:
            return
        self.appended += 1
        event, self._appended_event = self._appended_event, None
        if event is not None:
            event.set()

    async def wait_appended(self, seen: int, timeout: float) -> bool:
        """Wait up to ``timeout`` seconds for an append after :attr:`appended` was ``seen``.
        Take ``seen`` before reading, so an append between the read and the wait isn't missed.
        Returns whether one came."""
        with anyio.move_on_after(timeout):
            while self.appended == seen:
                if self._appended_event is None:
                    self._appended_event = anyio.Event()
                await self._appended_event.wait()
        return self.appended != seen

    async def retry_forever(self) -> None:
        while True:
            await anyio.sleep(RETRY_SECONDS)
            if self.queue:
                await self.flush_queue()

    # --- reading ------------------------------------------------------------------------------

    def lines(self, after: int, limit: int) -> list[bytes]:
        """The file layer's :meth:`~zoeymcp.common.ledgerfile.LedgerFile.lines`: what the
        reporter sends (J.3)."""
        return self.file.lines(after, limit)

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
        return self.file.read(after=after, limit=limit, client=client, server=server, tool=tool)

    def verify(self) -> dict[str, Any]:
        """Walk every file's chain in order (F.2), from what the oldest file says it follows."""
        return self.file.verify()

    def check(self, ref: str, args: canonical.JSONValue) -> dict[str, Any]:
        """Whether ``args`` are the arguments the ``asked`` record of ``ref`` was made for (F.4)."""
        for record in self.file.records():
            if record.ref == ref and record.kind == "asked":
                return {
                    "ref": ref,
                    "found": True,
                    "matches": hmac.compare_digest(record.fields["args"], self.digest(args)),
                }
        return {"ref": ref, "found": False, "matches": False}
