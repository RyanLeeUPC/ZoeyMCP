"""Reporting the ledger to the vault's copy (M5 design J.3): the I/O around :mod:`.reporting`.

One round asks the vault for its copy's head (``GET`` of the report path), reads the ledger's
stored lines from that head on, and ``POST``s the next batch the copy lacks. An accepted report
answers the new head, so the next round needn't ask again; a round with nothing to send waits for
an append or 60 s, so the vault hears from the gateway at least once a minute even when nothing
happens. A copy that refuses reports (``fork``, ``gap``, ``full``) is asked again every 300 s,
until the operator restarts its chain; any other failure backs off up to 300 s.

The reporter runs in the lifespan's task group, apart from approvals: nothing in the approval path
awaits it, and every error ends only its round. It logs ``ledger_report_failed{reason}`` at most
once per 5 minutes, and never a ledger line.
"""

from __future__ import annotations

import random
import time
from collections.abc import Callable
from typing import Any

import anyio
import httpx2

from ..common import canonical, ledgerreport
from ..common.ledgerreport import Head
from . import logs, reporting
from .ledger import Ledger
from .reporting import Outcome, ReportingError
from .vaultlink import REPORT_MAX_ANSWER_BYTES, vault_refusal_code

_HEAD_FIELDS = ("head_seq", "head_hash", "state")


class _Failed(Exception):
    """A round that failed for ``reason``: a stable code, never text from the vault."""


class Reporter:
    def __init__(
        self,
        http: httpx2.AsyncClient,
        ledger: Ledger,
        *,
        clock: Callable[[], float] = time.monotonic,
        jitter: Callable[[], float] = random.random,
    ) -> None:
        self._http = http
        self._ledger = ledger
        self._clock = clock
        self._jitter = jitter
        self.head: Head | None = None  # the copy's head, as the vault last answered it
        self._known: Head | None = None  # from an accepted report: the next round needn't ask
        self._failures = 0
        self._logged: float | None = None

    async def run(self) -> None:
        """Report for ever."""
        while True:
            seen = self._ledger.appended  # before the read, so no append is missed
            outcome = await self.report_once()
            self._failures = self._failures + 1 if outcome == "failed" else 0
            wait = reporting.next_step(outcome, failures=self._failures, jitter=self._jitter())
            if wait.wake:
                await self._ledger.wait_appended(seen, wait.seconds)
            else:
                await anyio.sleep(wait.seconds)

    async def report_once(self) -> Outcome:
        """One round: ``sent`` when the copy took a batch, ``idle`` when it holds every line,
        ``refused`` while it refuses reports, ``failed`` otherwise."""
        known, self._known = self._known, None
        try:
            head = known if known is not None else await self._ask()
            after = reporting.read_after(head, self._ledger.next_seq - 1)
            if after is None:
                return self._refused(head.state)
            lines = await anyio.to_thread.run_sync(
                self._ledger.lines, after, ledgerreport.MAX_LINES
            )
            batch = reporting.pending(head, lines)
            if not batch:
                return "idle"
            return await self._send(batch)
        except _Failed as failed:
            self._log(str(failed))
        except Exception as exc:  # every failure is the same to the loop (J.3)
            self._log(type(exc).__name__)
        return "failed"

    async def _ask(self) -> Head:
        response = await self._http.get(ledgerreport.PATH)
        body = await response.aread()
        if response.status_code != 200:
            raise _Failed(_reason(response.status_code, body))
        self.head = _head(body)
        return self.head

    async def _send(self, batch: tuple[bytes, ...]) -> Outcome:
        response = await self._http.post(
            ledgerreport.PATH,
            content=ledgerreport.encode(batch),
            headers={"content-type": "application/json"},
        )
        body = await response.aread()
        if response.status_code == 200:
            before, self.head = self.head, _head(body)
            if self.head == before:
                return "idle"  # nothing new was taken: don't send it again at once
            self._known = self.head
            return "sent"
        if response.status_code == 409:
            # A sticky refusal (fork, gap, full) answers the copy's head with its code.
            head = _head(body, refusal=True)
            if head.state != "ok":
                self.head = head
                return self._refused(vault_refusal_code(body) or head.state)
        raise _Failed(_reason(response.status_code, body))

    def _refused(self, reason: str) -> Outcome:
        self._log(reason)
        return "refused"

    def _log(self, reason: str) -> None:
        now = self._clock()
        if reporting.log_due(self._logged, now):
            self._logged = now
            logs.event("ledger_report_failed", reason=reason, level="warning")


def _head(body: bytes, *, refusal: bool = False) -> Head:
    """The copy's head in an answer; a refusal holds it beside its ``error`` and ``code``."""
    try:
        value: Any = canonical.loads_strict(body, max_bytes=REPORT_MAX_ANSWER_BYTES)
    except canonical.JSONRejected as exc:
        raise _Failed("bad_answer") from exc
    if refusal and isinstance(value, dict):
        value = {name: value[name] for name in _HEAD_FIELDS if name in value}
    try:
        return reporting.parse_head(value)
    except ReportingError as exc:
        raise _Failed("bad_answer") from exc


def _reason(status: int, body: bytes) -> str:
    """A failed answer's reason: the vault's stable code, or the status."""
    return vault_refusal_code(body) or f"status_{status}"
