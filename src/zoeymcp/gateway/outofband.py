"""The gateway's client of the vault's out-of-band approvals (M8 design E.2, E.3; G-15, G-16).
I/O, not mutated.

One locked client of the vault's approvals paths (:func:`.vaultlink.approvals_client`, which
``check_approval``'s collect shares), and one gateway epoch, made once per process
(:attr:`.approve.Approvals.epoch`), which every body and query here carries, as the held marker
does: the vault's epoch rule withdraws what only an earlier gateway could have used.

- **ask** (E.2, E.4; Q6 (B)): a gateway-held prompt of an ``out_of_band`` client, rendered here,
  relayed to the operator's approvers; bound as the relay transport's
  :attr:`.approvers.OutOfBand.ask_vault`.
- **withdraw** (B.6, SC-1): an Elsewhere call or a relay the gateway gave up, in any era, is
  withdrawn at the vault (``caller_cancelled``), which closes a blocking hold, a pending one and
  a relay alike; it is bound as :attr:`.approve.Approvals.tell_withdrawn` and the relay
  transport's.
- **detach** (I.2, G-16): the gateway's stop names its blocking held calls, at most 64 a request,
  so each that waits ``pending`` answers ``pending <ref>`` now and the operator's approval in
  progress isn't thrown away; the vault withdraws one that waits ``block``.
- **The decisions poller** (OPS-3): one task long-polls the endings of the held calls this gateway
  marked, and each closes the gateway's pending record of its call as the vault ended it
  (:func:`.approvalrules.ending_records`, :func:`.elsewhere.collected`): its ``decided`` and
  ``outcome`` records, the lock freed, and the legacy upstream session it kept let go (F.6),
  without waiting for the agent to collect. A record is closed once, whichever of the poller and
  a collect comes first. An ending that comes before its call's ``pending`` answer is processed
  is tried again on the next rounds, polled briefly while it waits. The poll runs while the view
  is fresh and has an out-of-band approver (nothing is held without one), or this gateway still
  waits on a held call: the change that removes the approvers withdraws every hold (Z7), and
  those endings still close their records. One that fails backs off from 1 s up to 30 s, logged
  at most once a minute (``approval_decisions_failed``). A new vault epoch (the vault restarted,
  its endings numbered from 1 again) starts the poll from the beginning.
- **The dispatcher** (E.3): the same poll answers the decisions on this gateway's relays, each
  naming the digest of the text it was taken on; each wakes its call, waiting within its block,
  or, for one that answered pending, runs the forward or closes the record in a task of its own
  (:meth:`.approve.Approvals.relay_decided`). A new vault epoch withdraws every relay this
  gateway had open there (Z10).

Nothing here carries an argument or a result: the ask carries the text the operator is shown,
and the vault's answers name a ref, a status, a decision and an outcome only.
"""

from __future__ import annotations

import random
import re
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

import anyio
import httpx2
from anyio.abc import TaskGroup

from ..common import canonical, ledgerformat
from . import approvalrules, elsewhere, logs
from .approve import FINISH_GRACE, Approvals, Work
from .approvers import Asked, AskRefused, Relayed
from .policyclient import Snapshot, backoff
from .vaultlink import (
    APPROVALS_DECISIONS,
    APPROVALS_MAX_ANSWER_BYTES,
    ASK_PATH,
    DETACH_PATH,
    WITHDRAW_PATH,
    vault_refusal_code,
)

WAIT: Final = 25  # the vault's DECISIONS_WAIT
# While an ending waits for its call's pending answer, the poll asks again this soon.
DEFERRED_WAIT: Final = 1
DEFERRED_MAX: Final = 64
IDLE_WAIT: Final = 1.0  # with no view, or nothing held and no out-of-band approver, no poll
LOG_EVERY: Final = 60.0  # approval_decisions_failed at most this often
DETACH_MAX_CALLS: Final = 64  # the vault's
_EPOCH: Final = re.compile(r"[0-9a-f]{12}")
_REF: Final = re.compile(r"[0-9a-f]{16}")
_ENDING_KEYS: Final = frozenset({"seq", "ref", "status", "outcome"})
_RELAY_KEYS: Final = frozenset({"seq", "ref", "decision", "via", "decided_ms", "text_sha256"})
_RELAY_DECISIONS: Final = frozenset({"accept", "decline", "timeout", "withdrawn"})
_VIAS: Final = frozenset({"telegram", "portal", "host", "none"})
_DIGEST: Final = re.compile(r"[0-9a-f]{64}")
_APPROVAL_ID: Final = re.compile(r"[A-Za-z0-9_-]{16}")
_JSON: Final = {"content-type": "application/json"}


class ApprovalsFailed(Exception):
    """The vault couldn't be asked, or its answer wasn't one: a stable reason, never text from
    the vault."""


@dataclass(frozen=True)
class Ending:
    """One held call's ending, as a decisions poll answered it (E.2)."""

    seq: int
    ref: str
    status: str
    outcome: str  # one the ledger knows, else unknown


def _answer(response: httpx2.Response) -> dict[str, Any]:
    """A 200 answer's JSON object, ``{"v": 1, ...}``; :class:`ApprovalsFailed` otherwise."""
    body = response.content
    if response.status_code != 200:
        raise ApprovalsFailed(vault_refusal_code(body) or f"status_{response.status_code}")
    try:
        value = canonical.loads_strict(body, max_bytes=APPROVALS_MAX_ANSWER_BYTES)
    except canonical.JSONRejected as exc:
        raise ApprovalsFailed("bad_answer") from exc
    if not isinstance(value, dict) or value.get("v") != 1:
        raise ApprovalsFailed("bad_answer")
    return value


def _seq_ref(item: object, keys: frozenset[str]) -> tuple[dict[str, Any], int, str]:
    """An ending or a relay decision, its keys exactly ``keys``, with its ``seq`` (from 1) and
    its ``ref``; :class:`ApprovalsFailed` otherwise."""
    if not isinstance(item, dict) or set(item) != keys:
        raise ApprovalsFailed("bad_answer")
    seq, ref = item["seq"], item["ref"]
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
        raise ApprovalsFailed("bad_answer")
    if not isinstance(ref, str) or _REF.fullmatch(ref) is None:
        raise ApprovalsFailed("bad_answer")
    return item, seq, ref


def endings(value: dict[str, Any]) -> tuple[str, list[Ending], list[Relayed]]:
    """A decisions poll's answer, ``{"v": 1, "epoch", "endings": [...], "relays": [...]}``: the
    vault's epoch, its endings, each ``{"seq", "ref", "status", "outcome"}`` exactly, and its
    decisions on this gateway's relays, each ``{"seq", "ref", "decision", "via", "decided_ms",
    "text_sha256"}`` exactly."""
    if set(value) != {"v", "epoch", "endings", "relays"}:
        raise ApprovalsFailed("bad_answer")
    epoch, listed, relays = value["epoch"], value["endings"], value["relays"]
    if not isinstance(epoch, str) or _EPOCH.fullmatch(epoch) is None:
        raise ApprovalsFailed("bad_answer")
    if not isinstance(listed, list) or not isinstance(relays, list):
        raise ApprovalsFailed("bad_answer")
    found: list[Ending] = []
    for listed_item in listed:
        item, seq, ref = _seq_ref(listed_item, _ENDING_KEYS)
        status, outcome = item["status"], item["outcome"]
        if not isinstance(status, str) or not isinstance(outcome, str):
            raise ApprovalsFailed("bad_answer")
        known = outcome if outcome in ledgerformat.OUTCOMES else "unknown"
        found.append(Ending(seq, ref, status, known))
    decided: list[Relayed] = []
    for relay_item in relays:
        item, seq, ref = _seq_ref(relay_item, _RELAY_KEYS)
        decision, via = item["decision"], item["via"]
        when, digest = item["decided_ms"], item["text_sha256"]
        if decision not in _RELAY_DECISIONS or via not in _VIAS:
            raise ApprovalsFailed("bad_answer")
        if not isinstance(when, int) or isinstance(when, bool) or when < 0:
            raise ApprovalsFailed("bad_answer")
        if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
            raise ApprovalsFailed("bad_answer")
        decided.append(Relayed(seq, ref, decision, via, when, digest))
    return epoch, found, decided


class OutOfBandClient:
    """The vault's approvals paths for one gateway (E.3): :meth:`withdraw`, :meth:`detach` and the
    decisions poller (:meth:`run`). ``sleep`` and ``jitter`` are the poller's (tests replace
    them)."""

    def __init__(
        self,
        approvals: Approvals,
        http: httpx2.AsyncClient,
        *,
        wait: int = WAIT,
        clock: Callable[[], float] = time.monotonic,
        jitter: Callable[[], float] = random.random,
        sleep: Callable[[float], Awaitable[None]] = anyio.sleep,
    ) -> None:
        self._approvals = approvals
        self._http = http
        self._wait = wait
        self._clock = clock
        self._jitter = jitter
        self._sleep = sleep
        # The seq of the last ending or relay decision polled, and the vault epoch it counts in;
        # whether the vault restarted since the poller last acted on it.
        self.after = 0
        self.vault_epoch: str | None = None
        self.vault_restarted = False
        # Endings whose call hasn't had its pending answer yet, by ref, oldest first.
        self.deferred: OrderedDict[str, Ending] = OrderedDict()
        self._failures = 0
        self._logged: float | None = None
        # Where a pending relay's work runs once its decision came: the poller's own group.
        self._group: TaskGroup | None = None

    # --- ask -----------------------------------------------------------------------------------

    async def ask(self, body: Mapping[str, Any]) -> Asked | AskRefused:
        """Ask the vault to relay a prompt (E.2): the approval id and the digest of the text as
        composed (201), or the vault's refusal. Raises :class:`ApprovalsFailed`, or the client's
        own error, when it couldn't be asked."""
        response = await self._http.post(
            ASK_PATH, content=canonical.dumps_canonical(dict(body)), headers=_JSON
        )
        if response.status_code != 201:
            retry = response.headers.get("retry-after", "")
            seconds = int(retry) if retry.isascii() and retry.isdigit() and len(retry) < 7 else None
            return AskRefused(response.status_code, vault_refusal_code(response.content), seconds)
        try:
            value = canonical.loads_strict(response.content, max_bytes=APPROVALS_MAX_ANSWER_BYTES)
        except canonical.JSONRejected as exc:
            raise ApprovalsFailed("bad_answer") from exc
        if not isinstance(value, dict) or set(value) != {"v", "id", "text_sha256"}:
            raise ApprovalsFailed("bad_answer")
        approval, digest = value["id"], value["text_sha256"]
        if value["v"] != 1 or not isinstance(approval, str) or not isinstance(digest, str):
            raise ApprovalsFailed("bad_answer")
        if _APPROVAL_ID.fullmatch(approval) is None or _DIGEST.fullmatch(digest) is None:
            raise ApprovalsFailed("bad_answer")
        return Asked(approval, digest)

    # --- withdraw and detach -------------------------------------------------------------------

    async def withdraw(self, ref: str, client: str, reason: str) -> None:
        """Tell the vault the gateway abandoned ``ref``, held for ``client`` (B.6). Raises
        :class:`ApprovalsFailed`, or the client's own error, when it couldn't be told."""
        body = {"epoch": self._approvals.epoch, "ref": ref, "client": client, "reason": reason}
        response = await self._http.post(
            WITHDRAW_PATH, content=canonical.dumps_canonical(body), headers=_JSON
        )
        _answer(response)

    async def detach(self, calls: Sequence[tuple[str, str]]) -> set[str]:
        """Ask the vault to answer each blocking held call, ``(ref, client)``, now (I.2): the
        refs it detached, to answer pending. Raises :class:`ApprovalsFailed`, or the client's
        own error, for a request it couldn't make."""
        detached: set[str] = set()
        for start in range(0, len(calls), DETACH_MAX_CALLS):
            chunk = calls[start : start + DETACH_MAX_CALLS]
            body = {
                "epoch": self._approvals.epoch,
                "calls": [{"ref": ref, "client": client} for ref, client in chunk],
            }
            response = await self._http.post(
                DETACH_PATH, content=canonical.dumps_canonical(body), headers=_JSON
            )
            value = _answer(response)
            listed = value.get("detached")
            if not isinstance(listed, list):
                raise ApprovalsFailed("bad_answer")
            asked = {ref for ref, _ in chunk}
            detached |= {ref for ref in listed if isinstance(ref, str) and ref in asked}
        return detached

    # --- the decisions poller ------------------------------------------------------------------

    async def run(self) -> None:
        """Poll for ever while the view is fresh and has an out-of-band approver, or a held call
        or a relay waits here: each ending closes its call's pending record, and each relay
        decision goes to its call; backoff while the path fails."""
        async with anyio.create_task_group() as group:
            self._group = group
            try:
                await self._poll_forever()
            finally:
                self._group = None

    async def _poll_forever(self) -> None:
        while True:
            snapshot = self._approvals.fresh()
            if snapshot is None or not self._wanted(snapshot):
                await self._sleep(IDLE_WAIT)
                continue
            cooldown = float(snapshot.view.gateway.approvals.cooldown)
            try:
                found = await self.poll_once(DEFERRED_WAIT if self.deferred else self._wait)
            except ApprovalsFailed as failed:
                reason = str(failed)
            except Exception as exc:  # every failure is the same to the loop
                reason = type(exc).__name__
            else:
                self._failures = 0
                if self.vault_restarted:
                    self.vault_restarted = False
                    await self.run_all(self._approvals.relays_lost())
                ended = [ending for ending in found if isinstance(ending, Ending)]
                await self.apply([*self.deferred.values(), *ended], cooldown)
                await self.relayed([relay for relay in found if isinstance(relay, Relayed)])
                continue
            self._failures += 1
            self._failed(reason)
            await self._sleep(backoff(self._failures, 0.5 + self._jitter()))

    async def poll_once(self, wait: int) -> list[Ending | Relayed]:
        """One poll after :attr:`after`: the endings and the relay decisions it answered, in
        their order. A vault with another epoch than the last poll's restarted
        (:attr:`vault_restarted`): its relays are gone, and it numbers from 1 again, so the next
        poll starts from the beginning and this one's answer is read then."""
        params = {"epoch": self._approvals.epoch, "after": str(self.after), "wait": str(wait)}
        response = await self._http.get(APPROVALS_DECISIONS, params=params)
        epoch, ended, decided = endings(_answer(response))
        if epoch != self.vault_epoch:
            restarted = self.vault_epoch is not None
            self.vault_epoch = epoch
            self.vault_restarted = self.vault_restarted or restarted
            if restarted and self.after:
                self.after = 0
                return []
        found: list[Ending | Relayed] = sorted([*ended, *decided], key=lambda item: item.seq)
        for item in found:
            self.after = max(self.after, item.seq)
        return found

    async def apply(self, found: Sequence[Ending], cooldown: float) -> None:
        """Close the pending record of each ending's call (D.2), once: a record already closed,
        by a collect or an earlier ending, or one of no held call here, is left; an ending of a
        call whose pending answer hasn't come yet waits for the next round."""
        table = self._approvals.table
        for ending in found:
            self.deferred.pop(ending.ref, None)
            record = table.get(ending.ref)
            if record is None or record.how != "elsewhere" or record.decision is not None:
                continue
            if record.pending_until is None:
                self.deferred[ending.ref] = ending
                while len(self.deferred) > DEFERRED_MAX:
                    self.deferred.popitem(last=False)
                continue
            records = approvalrules.ending_records(ending.status, ending.outcome)
            if records is None:
                continue
            decision, outcome, cools = records
            # Shielded, as an abandoned call's records are: a stop arriving now must not leave
            # the record claimed with its lock held, or its outcome unwritten.
            with anyio.CancelScope(shield=True), anyio.move_on_after(FINISH_GRACE * 2):
                await elsewhere.collected(
                    self._approvals, ending.ref, decision, outcome, None, cooldown if cools else 0.0
                )

    async def relayed(self, found: Sequence[Relayed]) -> None:
        """Hand each relay decision to its call (:meth:`.approve.Approvals.relay_decided`): a
        call still in its block is woken; one that answered pending is acted on in a task of
        its own, so a forward never holds up the poll."""
        works = [self._approvals.relay_decided(decided) for decided in found]
        await self.run_all([work for work in works if work is not None])

    async def run_all(self, works: Sequence[Work]) -> None:
        """Start each of ``works`` in the poller's group, or, with no poller running (a test),
        run them in turn."""
        group = self._group
        for work in works:
            if group is not None:
                group.start_soon(work)
            else:
                await work()

    def _wanted(self, snapshot: Snapshot) -> bool:
        """Whether there is anything to poll for: an out-of-band approver in the view, or a held
        call or a relay of this gateway still undecided, or an ending waiting for its call's
        answer."""
        if snapshot.view.gateway.approvals.out_of_band is not None or self.deferred:
            return True
        if self._approvals.relays.waiting:
            return True
        return any(
            record.how == "elsewhere" and record.decision is None
            for record in self._approvals.table.records()
        )

    def _failed(self, reason: str) -> None:
        now = self._clock()
        if self._logged is not None and now - self._logged < LOG_EVERY:
            return
        self._logged = now
        logs.event("approval_decisions_failed", reason=reason, level="warning")
