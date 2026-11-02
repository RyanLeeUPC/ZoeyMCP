"""The approval decision point: the I/O around :mod:`.approvals` (M4 design B, D).

A call to a tool the policy classifies ``approve`` reaches :meth:`Approvals.handle` after the
pipeline has admitted, shaped, canonicalized and validated it. In order (B.2):

5.1 a modern retry (``requestState``) goes to :meth:`Approvals._retry` (D.6);
5.2 the client must be attended (the pipeline's route, :mod:`.routing`), and the approver
    ``elicitation``;
5.3 the gateway must not be stopping;
5.4 the client must be able to show a form-mode prompt on this request (D.1);
5.6-5.7 the prompt is rendered by the gateway and checked; a text that could hide anything is
    refused, never cut;
5.8 the lock, the pending and hourly caps and the cooldown (:class:`.approvals.Table`);
5.9 the ``asked`` record, fsynced;
5.10 the question: ``elicitation/create`` on the call's own stream (legacy), or an
    ``InputRequiredResult`` whose ``requestState`` is a single-use handle (modern);
5.11-5.13 on ``accept``, the committed call (:mod:`.committed`): re-check, ``decided accept``
    fsynced, the forward, the outcome, the lock's release; any other answer declines.

Only an explicit ``accept`` runs the call. Every answer the agent sees ends with the ref the
prompt, the ledger and the logs share. The transports that ask live in :mod:`.approvers`, and the
rules for a waiting prompt after a policy change in :mod:`.approvalrules` (M8 design C.5). A call
the vault holds (:mod:`.elsewhere`) shares the table, the ledger and the caps, and is never
withdrawn here: the vault decides it (Z7).

While such a call blocks, the agent is sent progress (M8 design F.1, G-29; :func:`ticking`):
every :data:`PROGRESS_EVERY` seconds the seconds waited so far, strictly increasing, with no
total, never relied on to stretch the wait. The ticker stops in the synchronous section the
wait's answer comes back in, so nothing follows the answer or names its finished token.

An ``out_of_band`` client's call is relayed (:meth:`Approvals.relay`, M8 design E.4; Q6 (B)):
rendered and checked here as an elicitation is (plain, the out-of-band frame), its lock, caps
and ``asked`` record the same, then put to the operator's approvers through the vault
(:class:`.approvers.OutOfBand`), with progress while it blocks. An approval of the text asked
with runs today's committed forward, re-check first (B.5); past ``approvers.block_seconds`` the
call answers ``pending <ref>`` and runs once approved, its result kept in the gateway's result
store (F.2) for ``check_approval``. The caller's leaving withdraws the relay at the vault.
"""

from __future__ import annotations

import hashlib
import math
import secrets
import time
from collections import Counter, OrderedDict
from collections.abc import Awaitable, Callable, Coroutine, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Final, Literal, Protocol

import anyio
import mcp_types
from mcp.types import CallToolResult

from ..common import approvaltext, canonical
from ..common.approvaltext import Approver, Header, Plan
from ..common.committed import Committed, CommittedCancelled
from ..common.policy.schema import ClientApprovals
from ..common.policy.view import ViewGateway, ViewOutOfBand
from ..common.resultstore import CallStatus, Full, PendingCall, ResultStore, StoredResult
from . import approvalrules, approvals, logs
from .approvals import Decision, Key, Pending, Settings
from .approvers import CANT_SHOW as CANT_SHOW
from .approvers import CHANGED as CHANGED
from .approvers import DECISION_TEXTS as DECISION_TEXTS
from .approvers import EXPIRED as EXPIRED
from .approvers import (
    NO_APPROVALS,
    Decided,
    ElicitationLegacy,
    ElicitationModern,
    OutOfBand,
    Pended,
    Relayed,
    RelayWait,
    Shown,
    Unasked,
    lost,
    pending_answer,
)
from .approvers import TellWithdrawn as TellWithdrawn
from .approvers import refused as refused
from .approvers import with_ref as with_ref
from .ledger import Ledger, LedgerUnavailable
from .policyclient import Snapshot
from .sanitize import map_upstream
from .toolsource import Grant, ServedServer
from .upstream import NotAdmitted, UpstreamError

Era = Literal["legacy", "modern"]

EMPTY_SCHEMA: dict[str, Any] = {"type": "object", "properties": {}}
CODE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "code": {"type": "string", "title": "Code from the request", "minLength": 4, "maxLength": 4}
    },
    "required": ["code"],
}
OUTCOME_MARGIN = 10.0  # seconds after the forward's deadline for writing its outcome
SWEEP_INTERVAL = 1.0
FINISH_GRACE = 2.0  # seconds a cancelled handler gets to free its lock and record why
# A blocking out-of-band wait's progress (M8 design F.1, M.3): how often, and what it says.
PROGRESS_EVERY: Final = 15.0
PROGRESS_MESSAGE: Final = "waiting for the operator's approval"
# The longest ``approvers.result_ttl`` the policy allows: how long a closed pending held call's
# pin is kept with no view to read its own from (Z17).
RESULT_TTL_MAX: Final = 86400.0

STOPPING = "refused: the gateway is stopping; try again shortly"
LEDGER_DOWN = "refused: the approval ledger can't be written"
# A relayed call's pending record has no room in the result store (F.2, Q44 (a)): nobody is asked.
RESULTS_FULL = "refused: no room is left to keep this call's result; nothing was sent"


class AskSession(Protocol):
    """The parts of the agent's session an approval uses (the SDK's ``ServerSession``)."""

    @property
    def protocol_version(self) -> str: ...

    @property
    def can_send_request(self) -> bool: ...

    def elicitation(self) -> tuple[bool, bool, bool]:
        """(declared, form, url) from this request's client capabilities."""
        ...

    async def elicit(self, text: str, schema: dict[str, Any], timeout: float) -> Any:
        """``elicitation/create`` on the call's own stream; returns the parsed answer."""
        ...


Forward = Callable[[Grant], Awaitable[CallToolResult]]
# Sends the agent one progress notification: the seconds waited, and the message (F.1).
Tick = Callable[[float, str], Awaitable[None]]
# A detached relay's work once its decision came (:meth:`Approvals.relay_decided`), which the
# decisions poller runs in a task of its own.
Work = Callable[[], Coroutine[Any, Any, None]]


@dataclass
class Asking:
    """One ``approve`` call, as the pipeline hands it over."""

    ref: str
    client: str
    server: str
    tool: str
    era: Era
    policy: ServedServer
    gateway: ViewGateway  # the view the request started with
    args: dict[str, Any]  # canonical, validated
    pin: str
    session: AskSession
    forward: Forward  # steps 6 and 7 for the accepted call, committed
    admit: Callable[[], Awaitable[str]]  # the pin the tool is admitted under now (B.5)
    request_state: object = None
    input_responses: Mapping[str, Any] | None = None
    session_sha256: str | None = None
    disconnected: anyio.Event | None = None  # the legacy POST stream dropped (D.4)
    # A toolkit tool's prepare step (G.3): its plan, None without one, or the agent's failure.
    prepare: Callable[[], Awaitable[Plan | CallToolResult | None]] | None = None
    tick: Tick | None = None  # the agent's progress, while a relayed call blocks (F.1)

    @property
    def key(self) -> Key:
        return Key(self.client, self.server, self.tool)


@dataclass(frozen=True)
class Ran:
    """A pending held call whose record closed before the agent collected it (Z17, F.5 step 6):
    whose call it was, and the pin its result is checked against, until ``until`` (the clock's)."""

    key: Key
    pin: str
    until: float


@dataclass
class Approvals:
    """Every approval of one gateway process: the table, the prompts shown, the waits, and the
    two transports that ask (:mod:`.approvers`), which share them."""

    ledger: Ledger | None
    committed: Committed
    fresh: Callable[[], Snapshot | None]
    stopping: Callable[[], bool]
    clock: Callable[[], float] = time.monotonic
    wall: Callable[[], float] = time.time
    table: approvals.Table = field(default_factory=approvals.Table)
    # M8 (C.2, C.3): the view fetched at once, not by the long poll; the process's start id,
    # which every held call's marker carries (I.3); the vault told of an abandoned held call;
    # and per server, the held calls that came back without the vault's approval.
    refetch: Callable[[], Awaitable[Snapshot | None]] | None = None
    epoch: str = field(default_factory=lambda: secrets.token_hex(6))
    tell_withdrawn: TellWithdrawn | None = None
    unheld: Counter[str] = field(default_factory=Counter)
    # A pending held call's legacy upstream session, kept open for the vault's forward (F.6): by
    # ref, what lets it close again once the call's outcome is known.
    kept: dict[str, Callable[[], None]] = field(default_factory=dict)
    # A pending held call whose record closed before the agent collected its result: by ref,
    # what check_approval checks that result against while the vault keeps it (Z17).
    ran: OrderedDict[str, Ran] = field(default_factory=OrderedDict)
    # The pending records of relayed calls, and the results of those that ran with nobody
    # waiting (F.2): ``check_approval`` collects them here, never from the vault.
    results: ResultStore = field(default_factory=lambda: ResultStore(int(RESULT_TTL_MAX * 1000), 0))
    _shown: dict[str, Shown] = field(default_factory=dict)
    _waits: dict[str, anyio.CancelScope] = field(default_factory=dict)
    legacy: ElicitationLegacy = field(init=False)
    modern: ElicitationModern = field(init=False)
    relays: OutOfBand = field(init=False)

    def __post_init__(self) -> None:
        self.legacy = ElicitationLegacy(self.table, self._waits, self.clock, self._abandoned)
        self.modern = ElicitationModern(
            self.table, self._shown, self.clock, self._close, self._gate
        )
        self.relays = OutOfBand(self.table, self.clock, self.epoch, FINISH_GRACE)

    # --- the entry point ---------------------------------------------------------------------

    async def handle(self, asking: Asking) -> CallToolResult | mcp_types.InputRequiredResult:
        """A call the pipeline's route sent here (:mod:`.routing`): a legacy request carrying
        MRTR input never arrives, and an unattended client's call arrives only as a retry."""
        if asking.request_state is not None:
            return await self._retry(asking)
        if asking.input_responses:
            # Answers count only through a live handle (D.6): these are ignored, and asked anew.
            logs.event(
                "approval_unsolicited_answer",
                client=asking.client,
                server=asking.server,
                tool=asking.tool,
            )
        own = _client_settings(asking.gateway, asking.client)
        if own is None or not own.attended or asking.gateway.approvals.approver != "elicitation":
            # A backstop: the route asks only for an attended client, and check refuses any
            # approver but elicitation.
            return self._refuse(asking, "unattended", NO_APPROVALS)
        if self.stopping():
            return self._refuse(asking, "stopping", STOPPING)
        refusal = self._gate(asking)
        if refusal is not None:
            return refusal
        plan = None
        if asking.prepare is not None:  # step 5.5, before the lock (G.3)
            prepared = await asking.prepare()
            if isinstance(prepared, CallToolResult):
                return prepared
            plan = prepared
        settings = _settings(asking.gateway, own, asking.policy)
        code = approvals.new_code() if own.confirm_code else None
        asked_wall = self.wall()
        header = _header(asking, asked_wall, asked_wall + settings.timeout)
        shown_code = code.reveal() if code is not None else None
        if plan is not None:
            text = approvaltext.render_plan(header, plan, code=shown_code)
        else:
            text = approvaltext.render_call(header, asking.args, code=shown_code)
        found = approvaltext.problems(
            text, budget=_budget(asking.gateway, own), renders=own.renders
        )
        if found:
            reason = "markup" if found[0].rule == "markup" else found[0].rule
            if reason not in ("over_budget", "markup"):
                reason = "text_rules"
            return self._refuse(asking, reason, approvaltext.describe(found[0]))
        if self.ledger is None or not self.ledger.accepting:
            return self._refuse(asking, "ledger_unavailable", LEDGER_DOWN)
        handle = approvals.new_handle() if asking.era == "modern" else None
        now = self.clock()
        begun = self.table.begin(
            asking.key,
            settings=settings,
            now=now,
            ref=asking.ref,
            era=asking.era,
            args=asking.args,
            args_digest=canonical.digest(asking.args),
            pin=asking.pin,
            text_sha256=hashlib.sha256(text.value.encode()).hexdigest(),
            plan=plan,
            code=code,
            session_sha256=asking.session_sha256,
            handle_sha256=handle.sha256() if handle is not None else None,
        )
        if not isinstance(begun, Pending):
            return self._refuse_begin(asking, begun)
        schema = CODE_SCHEMA if code is not None else EMPTY_SCHEMA
        shown = Shown(text, schema, settings, asked_wall)
        self._shown[asking.ref] = shown
        try:
            await self.ledger.write(
                "asked",
                asking.ref,
                critical=True,
                client=asking.client,
                server=asking.server,
                tool=asking.tool,
                where="gateway",
                era=asking.era,
                args=self.ledger.digest(asking.args),
                pin=asking.pin,
                text=self.ledger.text_digest(text.value),
                chars=len(text.value),
                writes=len(plan.writes) if plan is not None else 0,
                expires=int((asked_wall + settings.timeout) * 1000),
            )
        except LedgerUnavailable:
            self._release(begun, "error")
            return self._refuse(asking, "ledger_unavailable", LEDGER_DOWN)
        logs.event(
            "approval_asked",
            client=asking.client,
            server=asking.server,
            tool=asking.tool,
            ref=asking.ref,
            era=asking.era,
            chars=len(text.value),
            writes=len(plan.writes) if plan is not None else 0,
            timeout_s=settings.timeout,
            code=code is not None,
        )
        if handle is not None:
            return self.modern.ask(shown, handle)
        decided = await self.legacy.ask(asking, begun, shown)
        return await self._decided(asking, decided.record, decided.decision)

    async def relay(self, asking: Asking) -> CallToolResult:
        """An ``out_of_band`` client's call, relayed to the operator's approvers through the vault
        (M8 design E.4; the pipeline's route, :mod:`.routing`'s row 6). An identical call while
        the record waits pending gets its ``pending <ref>`` again (D.2)."""
        gateway = asking.gateway
        out = gateway.approvals.out_of_band
        own = _client_settings(gateway, asking.client)
        if out is None or own is None or not own.out_of_band:
            # A backstop: the route relays only for an out_of_band client, with an approver.
            return self._refuse(asking, "no_approver", NO_APPROVALS)
        if self.stopping():
            return self._refuse(asking, "stopping", STOPPING)
        args_digest = canonical.digest(asking.args)
        same = self.table.lookup_identical(asking.key, args_digest)
        if same is not None and same.pending_until is not None:
            return pending_answer(same.ref, asking.tool, same.pending_until, out)
        plan = None
        if asking.prepare is not None:  # before the lock, as for an elicited plan (G.3)
            prepared = await asking.prepare()
            if isinstance(prepared, CallToolResult):
                return prepared
            plan = prepared
        settings = _settings(gateway, own, asking.policy, timeout=float(out.timeout))
        asked_wall = self.wall()
        header = _header(asking, asked_wall, asked_wall + settings.timeout, "out_of_band")
        if plan is not None:
            text = approvaltext.render_plan(header, plan)
        else:
            text = approvaltext.render_call(header, asking.args)
        found = approvaltext.problems(text, budget=_budget(gateway, own), renders="plain")
        if found:
            reason = found[0].rule if found[0].rule == "over_budget" else "text_rules"
            return self._refuse(asking, reason, approvaltext.describe(found[0]))
        if self.ledger is None or not self.ledger.accepting:
            return self._refuse(asking, "ledger_unavailable", LEDGER_DOWN)
        text_sha256 = hashlib.sha256(text.value.encode()).hexdigest()
        begun = self.table.begin(
            asking.key,
            settings=settings,
            now=self.clock(),
            ref=asking.ref,
            era=asking.era,
            args=asking.args,
            args_digest=args_digest,
            pin=asking.pin,
            text_sha256=text_sha256,
            plan=plan,
            session_sha256=asking.session_sha256,
            how="relay",
        )
        if not isinstance(begun, Pending):
            return self._refuse_begin(asking, begun)
        if not self._keep_result(asking, begun, asked_wall, settings, out.result_ttl):
            # F.2: no room for its pending record, so nobody is asked (Q44 (a)).
            self._release(begun, "error")
            return self._refuse(asking, "busy", RESULTS_FULL)
        shown = Shown(text, EMPTY_SCHEMA, settings, asked_wall)
        self._shown[asking.ref] = shown
        try:
            await self.ledger.write(
                "asked",
                asking.ref,
                critical=True,
                client=asking.client,
                server=asking.server,
                tool=asking.tool,
                where="gateway",
                era=asking.era,
                args=self.ledger.digest(asking.args),
                pin=asking.pin,
                text=self.ledger.text_digest(text.value),
                chars=len(text.value),
                writes=len(plan.writes) if plan is not None else 0,
                expires=int((asked_wall + settings.timeout) * 1000),
            )
        except LedgerUnavailable:
            self._release(begun, "error")
            self._store(begun, "error", "not_sent", None)
            return self._refuse(asking, "ledger_unavailable", LEDGER_DOWN)
        logs.event(
            "approval_asked",
            client=asking.client,
            server=asking.server,
            tool=asking.tool,
            ref=asking.ref,
            era=asking.era,
            approver="out_of_band",
            chars=len(text.value),
            writes=len(plan.writes) if plan is not None else 0,
            timeout_s=settings.timeout,
        )
        try:
            asked = await ticking(
                lambda: self.relays.ask(asking, begun, shown), asking.tick, self.clock
            )
        except anyio.get_cancelled_exc_class():
            # The agent left (B.6, E.4): the vault is told, and nothing is sent. Both shielded.
            await self.relays.withdraw(begun)
            await self._close(begun, "withdrawn")
            raise
        if isinstance(asked, Unasked):
            logs.event(
                "approval_refused",
                client=asking.client,
                server=asking.server,
                tool=asking.tool,
                ref=asking.ref,
                reason=asked.reason,
                code=asked.code,
            )
            await self._close(begun, asked.decision)
            return with_ref(asked.text, asking.ref)
        if isinstance(asked, Pended):
            return await self._pended(asking, asked, out)
        return await self._decided(asking, asked.record, asked.decision)

    async def _pended(self, asking: Asking, pended: Pended, out: ViewOutOfBand) -> CallToolResult:
        """The block is over undecided (F.1): ``decided pending`` on the ledger, the pending
        answer, and the relay waits on for its decision (:meth:`relay_decided`)."""
        record = pended.record
        wait = self.relays.waiting.get(record.ref)
        try:
            anchor = None
            if self.ledger is not None:
                anchor = await self.ledger.write(
                    "decided",
                    record.ref,
                    critical=False,
                    decision="pending",
                    waited_ms=self._waited(record),
                )
            self._log_decided(record, "pending", anchor)
        finally:
            if wait is not None:
                wait.answered.set()
        return pending_answer(record.ref, asking.tool, pended.until, out)

    # --- refusals before anyone is asked -------------------------------------------------------

    def _refuse(self, asking: Asking, reason: str, text: str) -> CallToolResult:
        logs.event(
            "approval_refused",
            client=asking.client,
            server=asking.server,
            tool=asking.tool,
            ref=asking.ref,
            reason=reason,
        )
        return with_ref(text, asking.ref)

    def _gate(self, asking: Asking) -> CallToolResult | None:
        declared, form, url = asking.session.elicitation()
        if approvals.can_ask(
            asking.era,
            declared=declared,
            form=form,
            url=url,
            can_send_request=asking.session.can_send_request,
        ):
            return None
        reason = "no_back_channel" if declared and form else "no_elicitation"
        return self._refuse(asking, reason, CANT_SHOW)

    def _refuse_begin(self, asking: Asking, refusal: approvals.Refusal) -> CallToolResult:
        return self._refuse(asking, *begin_refusal(refusal))

    # --- asking, through the transports ------------------------------------------------------

    async def _retry(self, asking: Asking) -> CallToolResult | mcp_types.InputRequiredResult:
        """D.6: a modern retry, through the modern transport; an answer is decided here."""
        found = await self.modern.retry(asking)
        if isinstance(found, Decided):
            return await self._decided(asking, found.record, found.decision)
        return found

    async def _abandoned(self, record: Pending) -> None:
        """A legacy wait the agent cancelled, or whose handler failed: nothing is sent."""
        with anyio.CancelScope(shield=True), anyio.move_on_after(FINISH_GRACE):
            await self._close(record, "withdrawn")

    # --- deciding ------------------------------------------------------------------------------

    async def _decided(self, asking: Asking, record: Pending, decision: Decision) -> CallToolResult:
        current = self.table.get(record.ref)
        if current is not None and current.decision is not None:
            decision = current.decision  # withdrawn meanwhile: a policy change, or a shutdown
        if decision != "accept":
            await self._close(record, decision)
            return with_ref(DECISION_TEXTS[decision], record.ref)
        shown = self._shown.get(record.ref)
        call_timeout = shown.settings.call_timeout if shown is not None else 300.0
        try:
            return await self.committed.run(
                record.ref, call_timeout + OUTCOME_MARGIN, lambda: self._commit(asking, record)
            )
        except CommittedCancelled:
            return with_ref(DECISION_TEXTS["shutdown"], record.ref)

    async def _commit(self, asking: Asking, record: Pending) -> CallToolResult:
        """B.5 and B.6, in the registry's own task: no cancel but the shutdown deadline's. The
        answer the agent gets is kept for a relayed call that answered pending (F.2)."""
        outcome: dict[str, Any] = {"outcome": "unknown", "detail": None}
        answer: CallToolResult | None = None
        try:
            if await self._changed(asking, record):
                await self._close(record, "changed", detail="changed")
                outcome = {}
                return with_ref(CHANGED, record.ref)
            self.table.decide(record.ref, "accept", self.clock())
            ledger = self.ledger
            try:
                if ledger is None:  # handle() refuses first; checked again
                    raise LedgerUnavailable("decided")
                anchor = await ledger.write(
                    "decided",
                    record.ref,
                    critical=True,
                    decision="accept",
                    waited_ms=self._waited(record),
                )
            except LedgerUnavailable:
                # Kept as the answer, so a relay that answered pending collects what happened.
                answer = with_ref(LEDGER_DOWN, record.ref)
                await self._outcome(record, "not_sent", None, answer)
                outcome = {}
                return answer
            self._log_decided(record, "accept", anchor)
            try:
                result = await asking.forward(Grant(record.ref, asking.args, record.plan))
            except NotAdmitted:
                outcome = {"outcome": "not_sent", "detail": "changed"}
                answer = with_ref(CHANGED, record.ref)
                return answer
            except UpstreamError as exc:
                outcome = _upstream_outcome(exc)
                answer = map_upstream(exc.outcome, record.ref)
                return answer
            outcome = {"outcome": "tool_error" if result.is_error else "ok", "detail": None}
            answer = result
            return result
        except anyio.get_cancelled_exc_class():
            outcome = {"outcome": "unknown", "detail": "shutdown"}
            raise
        finally:
            with anyio.CancelScope(shield=True), anyio.move_on_after(FINISH_GRACE * 2):
                if outcome:
                    await self._outcome(record, outcome["outcome"], outcome["detail"], answer)
                self._release(record, None)

    async def _changed(self, asking: Asking, record: Pending) -> bool:
        """B.5: the view is still fresh, still assigns the server and lists the tool in
        ``approve``, the client may still be asked as it was (attended, or ``out_of_band`` for a
        relay), and the tool is admitted under the same pin."""
        snapshot = self.fresh()
        if snapshot is None or not approvalrules.still_asked(
            snapshot.view.gateway, record.key, _asked_how(record)
        ):
            return True
        try:
            return await asking.admit() != record.pin
        except (NotAdmitted, UpstreamError):
            return True

    async def _close(
        self, record: Pending, decision: Decision, *, detail: str | None = None
    ) -> None:
        """A decision that doesn't run the call: ledger it, free the lock, start any cooldown.
        Shielded: a cancel arriving now must not leave the lock held."""
        with anyio.CancelScope(shield=True), anyio.move_on_after(FINISH_GRACE * 2):
            await self._close_now(record, decision, detail)

    async def _close_now(self, record: Pending, decision: Decision, detail: str | None) -> None:
        current = self.table.decide(record.ref, decision, self.clock())
        decision = current.decision or decision
        try:
            anchor = None
            if self.ledger is not None:
                anchor = await self.ledger.write(
                    "decided",
                    record.ref,
                    critical=False,
                    decision=decision,
                    waited_ms=self._waited(record),
                )
            self._log_decided(record, decision, anchor)
            await self._outcome(record, "not_sent", detail)
        finally:
            self._release(record, decision)

    async def _outcome(
        self,
        record: Pending,
        outcome: str,
        detail: str | None,
        answer: CallToolResult | None = None,
    ) -> None:
        current = self.table.get(record.ref)
        self._store(record, current.decision if current is not None else None, outcome, answer)
        anchor = None
        if self.ledger is not None:
            anchor = await self.ledger.write(
                "outcome",
                record.ref,
                critical=False,
                outcome=outcome,
                detail=detail,
                writes_sent=0,
                writes_unknown=0,
            )
        logs.event(
            "approval_outcome",
            ref=record.ref,
            outcome=outcome,
            detail=detail,
            ledger_seq=anchor.seq if anchor is not None else None,
            ledger_hash=anchor.hash if anchor is not None else None,
        )

    # --- a relayed call's pending record (F.2) ------------------------------------------------

    def _keep_result(
        self,
        asking: Asking,
        record: Pending,
        asked_wall: float,
        settings: Settings,
        result_ttl: int,
    ) -> bool:
        """Open the result store's record of a relayed call before anyone is asked, as the vault
        does for a call it holds (F.2): False when the store has no room for this client."""
        self.results.ttl_ms = result_ttl * 1000
        grace = int((settings.call_timeout + OUTCOME_MARGIN) * 1000)
        self.results.grace_ms = max(self.results.grace_ms, grace)
        call = PendingCall(
            ref=record.ref,
            client=asking.client,
            server=asking.server,
            tool=asking.tool,
            holder="gateway",
            args_digest=record.args_digest,
            text_sha256=record.text_sha256,
            surfaces=frozenset(),
            asked_ms=int(asked_wall * 1000),
            deadline_ms=int((asked_wall + settings.timeout) * 1000),
            status="pending",
        )
        opened = self.results.open(int(self.wall() * 1000), call)
        if isinstance(opened, Full):
            return False
        for evicted in opened:
            logs.event("approval_result_evicted", ref=evicted.ref, reason=evicted.reason)
        return True

    def _store(
        self,
        record: Pending,
        decision: Decision | None,
        outcome: str,
        answer: CallToolResult | None,
    ) -> None:
        """A relayed call's outcome, in its pending record: the answer itself only for a call
        that answered pending, whose agent collects it (F.2); one whose agent had its answer
        keeps the outcome alone."""
        if record.how != "relay" or not self.results.knows(record.ref):
            return
        now = int(self.wall() * 1000)
        if decision != "accept":
            status: CallStatus = "withdrawn"
            if decision == "decline":
                status = "denied"
            elif decision == "timeout":
                status = "expired"
            evicted = self.results.advance(now, record.ref, status, "not_sent")
        else:
            current = self.table.get(record.ref)
            pended = current is not None and current.pending_until is not None
            kept = None
            if pended and answer is not None:
                body = answer.model_dump_json(by_alias=True, exclude_none=True).encode()
                kept = StoredResult(200, "application/json", body)
            self.results.advance(now, record.ref, "approved")
            evicted = self.results.advance(now, record.ref, "done", outcome, kept)
        for gone in evicted:
            logs.event("approval_result_evicted", ref=gone.ref, reason=gone.reason)

    def _release(self, record: Pending, decision: Decision | None) -> None:
        shown = self._shown.pop(record.ref, None)
        cooldown = shown.settings.cooldown if shown is not None else 0.0
        self.table.finish(record.key, record.ref, self.clock(), settings_cooldown=cooldown)

    def _log_decided(self, record: Pending, decision: str, anchor: Any) -> None:
        logs.event(
            "approval_decided",
            client=record.key.client,
            server=record.key.server,
            tool=record.key.tool,
            ref=record.ref,
            decision=decision,
            waited_ms=self._waited(record),
            ledger_seq=anchor.seq if anchor is not None else None,
            ledger_hash=anchor.hash if anchor is not None else None,
        )

    def _waited(self, record: Pending) -> int:
        return max(0, round((self.clock() - record.asked_at) * 1000))

    # --- policy changes, shutdown and the sweeper ----------------------------------------------

    async def withdraw(self, matches: Callable[[Pending], bool], decision: Decision) -> int:
        """Decide every waiting prompt ``matches`` picks. A legacy handler wakes and records it;
        a modern record has no handler, so it is closed here."""
        retrying: set[str] = set()

        def picks(record: Pending) -> bool:
            picked, mid_retry = approvalrules.withdraw_picks(record, matches)
            if mid_retry:
                retrying.add(record.ref)
            return picked

        def gateway_held(record: Pending) -> bool:
            # A call the vault holds is the vault's to withdraw (Z7, C.5); its handler records
            # its own ending.
            return record.how != "elsewhere" and picks(record)

        found = self.table.withdraw(gateway_held, decision, self.clock())
        for record in found:
            if record.how == "relay":
                await self._relay_withdrawn(record, decision)
                continue
            wait = self._waits.get(record.ref)
            if wait is not None:
                wait.cancel()
            elif record.era == "modern" and record.ref in retrying:
                # Mid-retry: its handler sees the decision when it looks.
                continue
            elif record.era == "modern":
                await self._close(record, decision)
        return len(found)

    async def close_unparsable(self, state: str, client: str, server: str) -> bool:
        """A retry carrying this handle failed the SDK's typed parse (D.7): close its record as
        ``error``, if it is a live one of this client and server, so the lock is freed now."""
        digest = approvals.handle_sha256(state)
        now = self.clock()
        found = self.table.lookup(digest, now)
        if not isinstance(found, Pending) or (found.key.client, found.key.server) != (
            client,
            server,
        ):
            return False
        await self._close(self.table.consume(digest, now), "error")
        return True

    async def withdraw_unallowed(self, gateway: ViewGateway) -> int:
        """After a policy change: prompts whose tool left ``approve`` (removed, or moved to
        ``allow``: Q32 (b)), or whose assignment or attendance went (M3 D.3), and relays whose
        client lost ``out_of_band`` or whose approvers went (G-24): the vault is told."""
        return await self.withdraw(
            lambda p: not approvalrules.still_asked(gateway, p.key, _asked_how(p)), "withdrawn"
        )

    # --- relays the vault decided, or lost (E.2, E.3) -------------------------------------

    def relay_decided(self, decided: Relayed) -> Work | None:
        """The vault's decision on one of this gateway's relays, from its decisions poll: the
        call waiting for it is woken, and one that answered pending is acted on by the work
        returned, which the poller runs on its own. A decision on a relay no longer waiting here
        (decided, withdrawn, expired) changes nothing."""
        wait = self.relays.waiting.get(decided.ref)
        if wait is None or wait.decided is not None:
            return None
        wait.decided = decided
        if not wait.detached:
            wait.woken.set()
            return None
        del self.relays.waiting[decided.ref]
        return lambda: self._relay_detached(wait)

    def relays_lost(self) -> list[Work]:
        """The vault restarted (its decisions poll answered another epoch): every relay it had
        is gone (Z10), so each relay waiting here ends withdrawn, nothing sent; the restarted
        vault is told too, as one of them may have been asked of it before this poll."""
        found = [self.relay_decided(lost(ref)) for ref in list(self.relays.waiting)]
        return [work for work in found if work is not None]

    async def _relay_detached(self, wait: RelayWait) -> None:
        """A decision on a relay that answered pending: an approval of the text asked with runs
        the committed forward (its re-check first), whose result is kept for ``check_approval``;
        anything else closes the record. This work owns the record from the decision on (it left
        :attr:`.approvers.OutOfBand.waiting`): a withdrawal here meanwhile is told and recorded
        by it. Its records are written shielded, as every ending's (:meth:`_close`, the
        committed registry)."""
        with anyio.CancelScope(shield=True), anyio.move_on_after(FINISH_GRACE * 2):
            await wait.answered.wait()  # its pending answer's record first
        record = self.table.get(wait.record.ref)
        if record is None or record.how != "relay":
            return  # its lock was freed at its hard deadline: nothing is left to close
        if record.decision is not None:  # withdrawn here meanwhile (a change, a stop)
            await self.relays.withdraw(record)
            await self._close(record, record.decision)
            return
        settled = self.relays.settled(wait)
        if isinstance(settled, Unasked) or settled.decision != "accept":
            if wait.decided is not None and wait.decided.restarted:
                await self.relays.withdraw(record)  # the restarted vault may hold it anew
            await self._close(record, settled.decision)
            return
        try:
            await self._decided(wait.asking, record, "accept")
        except Exception as exc:  # its records are written in the commit's own finally
            logs.event("approval_relay_failed", ref=record.ref, error_type=type(exc).__name__)

    async def _relay_withdrawn(self, record: Pending, decision: Decision) -> None:
        """A relay a withdrawal here decided (a policy change, a stop), by who owns it: a call
        still waiting for it is woken, and its handler (or, not asked yet, the handler as it asks)
        tells the vault and records it; one that answered pending is told and recorded now; one
        whose decision came already is its decision's work's (:meth:`_relay_detached`)."""
        wait = self.relays.waiting.get(record.ref)
        if wait is None:
            return
        if not wait.detached:
            wait.woken.set()
            return
        del self.relays.waiting[record.ref]
        with anyio.CancelScope(shield=True), anyio.move_on_after(FINISH_GRACE * 2):
            await wait.answered.wait()
        await self.relays.withdraw(record)
        await self._close(record, decision)

    async def sweep(self) -> None:
        now = self.clock()
        for record in self.table.records():
            wait = self.relays.waiting.get(record.ref)
            if wait is None or not wait.detached or record.expires_at > now:
                continue
            if not wait.answered.is_set():
                continue  # its pending answer's record first: the next sweep closes it
            # Pending past its deadline, and no decision came from the vault: closed as nobody
            # answering, by its owner (:meth:`relay_decided`), and the vault told, since its own
            # deadline may be later than this one.
            del self.relays.waiting[record.ref]
            await self.relays.withdraw(record)
            await self._close(record, "timeout")
        self.results.sweep(int(self.wall() * 1000))
        swept = self.table.sweep(self.clock())
        for record in swept.expired:
            await self._close(record, "timeout")
        for record in swept.freed:
            self._shown.pop(record.ref, None)
            self.relays.waiting.pop(record.ref, None)  # a relay's decision would find no lock
            if record.how == "elsewhere" and record.pending_until is not None:
                # D.2: a pending held call's lock ends at its hard deadline at the latest; the
                # gateway learns how it ended sooner, from the vault's decisions poll
                # (:mod:`.outofband`) or the agent's collect (check_approval), and only one that
                # never came (the vault restarted, or couldn't be polled) ends here, unknown: the
                # vault's chain holds how it ended.
                self.release_kept(record.ref)
                self.keep_ran(record)
                await self._outcome(record, "unknown", None)
                continue
            logs.event("approval_lock_expired", ref=record.ref, level="error")

    async def sweep_forever(self) -> None:
        while True:
            await anyio.sleep(SWEEP_INTERVAL)
            await self.sweep()

    def release_kept(self, ref: str) -> None:
        """A pending held call ended, or its lock did: its upstream session may close (F.6)."""
        release = self.kept.pop(ref, None)
        if release is not None:
            release()

    def keep_ran(self, record: Pending) -> None:
        """Z17, F.5 step 6: a pending held call's record closed (its ending, or its hard
        deadline) before the agent collected its result, which is still checked against the pin
        the call was made under, not the view's of now. Kept while the vault keeps the result
        (``approvers.result_ttl``, the policy's longest with no view, and the hard deadline's
        margin), the last :data:`.approvals.MAX_RECORDS`."""
        now = self.clock()
        snapshot = self.fresh()
        out = None if snapshot is None else snapshot.view.gateway.approvals.out_of_band
        ttl = float(out.result_ttl) if out is not None else RESULT_TTL_MAX
        self.ran.pop(record.ref, None)
        self.ran[record.ref] = Ran(
            record.key, record.pin, now + ttl + approvals.HARD_DEADLINE_MARGIN
        )
        self._prune_ran(now)

    def ran_call(self, ref: str) -> Ran | None:
        """The closed pending held call ``ref`` (:meth:`keep_ran`), while its result may still
        be collected."""
        self._prune_ran(self.clock())
        return self.ran.get(ref)

    def _prune_ran(self, now: float) -> None:
        for ref in [ref for ref, ran in self.ran.items() if ran.until <= now]:
            del self.ran[ref]
        while len(self.ran) > approvals.MAX_RECORDS:
            self.ran.popitem(last=False)


# --- progress while a call blocks (M8 design F.1) ------------------------------------------------


class _Ticker:
    """The progress of one blocking wait, until it is :attr:`stopped`."""

    def __init__(self, tick: Tick, clock: Callable[[], float], every: float) -> None:
        self._tick = tick
        self._clock = clock
        self._every = every
        self._started = clock()
        self._last = 0
        self.stopped = False

    async def run(self) -> None:
        while True:
            await anyio.sleep(self._every)
            if self.stopped:
                return
            # Whole seconds waited, each notification more than the last (SC-9).
            self._last = max(self._last + 1, math.floor(self._clock() - self._started))
            try:
                await self._tick(float(self._last), PROGRESS_MESSAGE)
            except Exception:  # never relied on: a notification that fails ends the ticking
                return


async def ticking[T](
    work: Callable[[], Awaitable[T]],
    tick: Tick | None,
    clock: Callable[[], float],
    every: float = PROGRESS_EVERY,
) -> T:
    """``work``'s answer, with progress sent through ``tick`` while it runs (F.1). The ticker is
    stopped, and a notification it is sending cut, in the synchronous section ``work`` returns
    or raises in, before its answer goes anywhere."""
    if tick is None:
        return await work()
    ticker = _Ticker(tick, clock, every)
    failure: Exception | None = None
    async with anyio.create_task_group() as group:
        group.start_soon(ticker.run)
        try:
            result = await work()
        except Exception as exc:  # raised as it was, not inside the group's exception group
            failure = exc
        finally:
            ticker.stopped = True
            group.cancel_scope.cancel()
    if failure is not None:
        raise failure
    return result


# --- helpers --------------------------------------------------------------------------------------


def begin_refusal(refusal: approvals.Refusal) -> tuple[str, str]:
    """Why :meth:`.approvals.Table.begin` refused, as ``(reason, text)``: the log's reason and
    what the agent reads. A tool whose call waits out of band names the ref to collect (OPS-3)."""
    if isinstance(refusal, approvals.Busy):
        if refusal.pending:
            ref = refusal.holder_ref
            return (
                "busy",
                f"refused: a call to this tool is waiting for approval (ref {ref}); "
                f'call check_approval with {{"id": "{ref}"}}',
            )
        return (
            "busy",
            "refused: another call to this tool is waiting or running "
            f"(ref {refusal.holder_ref}, frees within {refusal.seconds_left} s)",
        )
    if isinstance(refusal, approvals.PendingCap):
        return (
            "pending_cap",
            f"refused: an approval is already waiting for this client (ref {refusal.holder_ref})",
        )
    if isinstance(refusal, approvals.HourlyCap):
        return "hourly_cap", "refused: too many approval requests this hour"
    if isinstance(refusal, approvals.Cooldown):
        return (
            "cooldown",
            f"refused: this tool was declined moments ago; try again in {refusal.seconds_left} s",
        )
    return "table_full", "refused: too many approvals are waiting"


def _client_settings(gateway: ViewGateway, client: str) -> ClientApprovals | None:
    found = gateway.clients.get(client)
    return found.approvals if found is not None else None


def _asked_how(record: Pending) -> Literal["elicitation", "relay"]:
    """How a record the gateway asks for itself was asked, for :func:`.approvalrules.still_asked`
    (a call the vault holds is never withdrawn here, Z7)."""
    return "relay" if record.how == "relay" else "elicitation"


def _settings(
    gateway: ViewGateway,
    own: ClientApprovals,
    policy: ServedServer,
    *,
    timeout: float | None = None,
) -> Settings:
    """The record's limits: the client's own timeout, or for a relay ``timeout``, the
    out-of-band deadline (``approvers.timeout``, D.2), and the gateway's caps."""
    approvals_ = gateway.approvals
    if timeout is None:
        timeout = float(own.timeout if own.timeout is not None else approvals_.timeout)
    return Settings(
        timeout=timeout,
        call_timeout=float(policy.call_timeout or gateway.limits.call_timeout),
        cooldown=float(approvals_.cooldown),
        max_pending_per_client=approvals_.max_pending_per_client,
        max_prompts_per_hour=approvals_.max_prompts_per_hour,
    )


def _budget(gateway: ViewGateway, own: ClientApprovals) -> int:
    return own.budget_chars if own.budget_chars is not None else gateway.approvals.budget_chars


def _header(
    asking: Asking,
    asked_wall: float,
    deadline_wall: float,
    approver: Approver = "elicitation",
) -> Header:
    """The gateway's own frame for a prompt it holds: its client, no pin, and the instruction
    for the elicitation's Accept or, relayed, the approvers' Approve (M8 design E.5)."""
    return Header(
        asking.ref,
        asking.client,
        asking.server,
        asking.tool,
        datetime.fromtimestamp(deadline_wall, UTC),
        asked_at=datetime.fromtimestamp(asked_wall, UTC),
        rendered_by="gateway",
        client_reported=False,
        pin=None,
        approver=approver,
    )


def _upstream_outcome(exc: UpstreamError) -> dict[str, Any]:
    """The ledger outcome of an upstream failure after ``decided accept``: unknown wherever the
    call may have run."""
    if exc.detail == "session_expired":
        return {"outcome": "unknown", "detail": "session_expired"}
    if exc.outcome == "unavailable":
        return {"outcome": "not_sent", "detail": None}
    if exc.outcome == "input_required":
        return {"outcome": "refused", "detail": "upstream_input_required"}
    if exc.outcome in ("rpc_error", "unsupported_result", "output_refused", "too_large"):
        return {"outcome": "upstream_error", "detail": None}
    return {"outcome": "unknown", "detail": None}
