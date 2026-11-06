"""A call the vault holds: the gateway's Elsewhere (M8 design C.2-C.4, D.2; Z27). I/O.

Step 5 of the pipeline routes a ``vault_approval`` tool here (:mod:`.routing`'s rows 2-5). The
gateway asks no one and renders nothing: the vault holds the call, renders its own text, asks the
operator's approvers and forwards it once approved. Here, after the pipeline's steps 1-4:

1. an identical call while this tool's record waits out of band is answered that record's
   ``pending <ref>`` again (D.2, ``Table.lookup_identical``); a toolkit's ``prepare`` runs, and a
   plan of more than one write is refused ``plan_multi_held`` with nothing sent (B.7);
2. ``Table.begin`` takes the same lock and caps as an elicited prompt (R44), and ``asked`` goes on
   the ledger with ``where: vault``, the arguments' keyed digest and the empty text's (the gateway
   showed nothing), fsynced;
3. the forward carries the marker (:class:`.upstream.Held`): committed, never retried, its read
   waiting out the vault's block (I.1), with progress sent while it blocks (F.1,
   :func:`.approve.ticking`). The egress transport adds the marker only after its filter
   consumed the call's held registration, and the vault's answer is kept by its ref for this call
   alone (Z27);
4. the answer is mapped (:func:`settle`, C.2's table): approved runs on as a direct call
   (sanitized, ``decided approved_elsewhere`` written only now, C.4), and an approved forward that
   failed is the forward's failure, as the vault's outcome of it says; ``approval_pending`` is
   the pending answer (F.1), the record waiting with its lock until it ends, and a legacy
   upstream session kept open for the vault's forward (F.6); the vault's refusals each get their
   fixed text; ``view_stale`` goes back to the pipeline (C.3, :class:`Stale`); and an answer that
   carries neither the vault's approval nor its refusal is ``elsewhere_unheld``, its result
   withheld.

A pending call's ending, once the gateway learns it (the vault's decisions poll, E.2, or
``check_approval``'s collect, F.5), closes its record as the vault decided it, once
(:func:`collected`).

An Elsewhere call the agent abandons (its handler cancelled) is withdrawn in the gateway's ledger,
``outcome unknown`` since the vault may still forward it, and the vault is told
(``withdraw caller_cancelled``, B.6) through :attr:`.approve.Approvals.tell_withdrawn`, which the
app binds to :meth:`.outofband.OutOfBandClient.withdraw`. Every answer ends with the call's ref.
"""

from __future__ import annotations

import hashlib
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Any, Final, Literal

import anyio
from mcp.types import CallToolResult

from ..common import canonical, ledgerformat
from ..common.approvaltext import Plan
from ..common.envelope import Marker
from ..common.policy.view import ViewGateway, ViewOutOfBand
from . import logs
from .approvals import Decision, Key, Pending, Settings
from .approve import (
    FINISH_GRACE,
    LEDGER_DOWN,
    OUTCOME_MARGIN,
    STOPPING,
    Approvals,
    Tick,
    begin_refusal,
    ticking,
)
from .approvers import pending_answer as pending_answer
from .approvers import with_ref
from .ledger import LedgerUnavailable
from .sanitize import map_upstream
from .toolkitsource import ToolkitUnavailable
from .toolsource import Grant, ServedServer
from .upstream import Connection, Held, HeldBusy, NotAdmitted, UpstreamError
from .vaultlink import HeldAnswer

Era = Literal["legacy", "modern"]

PLAN_MULTI_HELD: Final = "refused: a vault-approved tool sends one write per call; nothing was sent"
IDENTICAL_IN_FLIGHT: Final = "refused: an identical call is being sent; try again"
UNHELD: Final = "refused: the vault didn't hold this call, so its result is withheld"
TOOLKIT_UNAVAILABLE: Final = "toolkit unavailable"
# The vault's held-read refusals (B.2's held_<rule>): the rule is logged, never shown.
UNREAD: Final = "refused: the vault couldn't read this call unambiguously"
REFUSED_BY_VAULT: Final = "refused by the vault"
# C.2's table: a vault code, the gateway's decision, and the agent's text. The outcome is
# not_sent for each, the call having gone nowhere. A refusal the table doesn't name is unknown:
# the vault's refusal of a forward that failed after its approval carries the approval's headers
# (settle reads it as approved), but one that lost them may have run too.
VAULT_ANSWERS: Final[dict[str, tuple[Decision, str]]] = {
    "approval_declined": ("decline", "refused: the operator declined this call"),
    "approval_expired": ("timeout", "refused: no answer before the deadline"),
    "approval_withdrawn": ("withdrawn", "refused: the policy changed; call the tool again"),
    "held_ref_reused": ("error", "refused: one held write per call; nothing was sent"),
    "held_second_write": ("error", "refused: one held write per call; nothing was sent"),
    "held_capacity": ("unavailable", "refused: the vault's approval queue is full"),
    "held_busy": ("unavailable", "refused: the vault's approval queue is full"),
    "held_hourly": ("unavailable", "refused: too many approval requests this hour"),
    "held_ledger_down": (
        "unavailable",
        "refused: the vault can't record approvals right now; nothing was sent",
    ),
    "stopping": (
        "unavailable",
        "refused: the vault is restarting; nothing was sent; try again shortly",
    ),
    "telegram_too_long": (
        "error",
        "refused: too long to show in the operator's chat; nothing was sent",
    ),
    "telegram_text_changed": (
        "error",
        "refused: the approval text can't be shown as sent; nothing was sent",
    ),
}
# A withdrawal's text by the reason the vault names (step 10's deviation 18): the operator's
# withdraw (K.3, J15), the vault's stop, this gateway's own stop (a blocking call its stop
# detached, I.2) and a new gateway epoch (G-15) each their own; a policy change, or a reason not
# named, VAULT_ANSWERS's.
WITHDRAWN: Final[Mapping[str, str]] = MappingProxyType(
    {
        "changed": "refused: the policy changed; call the tool again",
        "operator": "refused: the operator withdrew this call; nothing was sent",
        "shutdown": "refused: the vault stopped; nothing was sent; try again shortly",
        "gateway_stopped": "refused: the gateway is stopping; nothing was sent; try again shortly",
        "gateway_restarted": (
            "refused: the gateway restarted; nothing was sent; call the tool again"
        ),
    }
)
TOO_LARGE: Final = "the call ran, but its answer was over 4 MiB and wasn't kept; see the Ledger"
STALE: Final = "refused: the policy is changing; call the tool again"
EMPTY_TEXT: Final = ""  # the gateway shows nothing: its asked record keys the empty text


@dataclass(frozen=True)
class Stale:
    """The vault holds the tool no longer (409 ``view_stale``, C.3): the record is released and
    nothing was decided, so the pipeline decides once more on a fresh view."""


# The call as the pipeline forwards it: with the marker and, for a toolkit, the plan; and the
# pipeline's own finishing of a result (sanitize, the pinned output schema, wrap).
Forward = Callable[[Held, Grant], Awaitable[CallToolResult]]
Finish = Callable[[CallToolResult], CallToolResult]


@dataclass
class HeldCall:
    """One Elsewhere call, as the pipeline hands it over."""

    ref: str
    client: str
    server: str
    tool: str
    era: Era
    policy: ServedServer
    gateway: ViewGateway  # the view the request started with
    args: dict[str, Any]  # canonical, validated
    pin: str
    wait: Literal["block", "pending"]
    forward: Forward
    finish: Finish
    prepare: Callable[[], Awaitable[Plan | CallToolResult | None]] | None = None
    tick: Tick | None = None  # the agent's progress, while the call blocks (F.1)

    @property
    def key(self) -> Key:
        return Key(self.client, self.server, self.tool)

    @property
    def toolkit(self) -> bool:
        return self.prepare is not None or self.policy.kind == "toolkit"


async def run(approvals: Approvals, call: HeldCall) -> CallToolResult | Stale:
    """C.2 for one call: the answer the agent gets, or :class:`Stale`."""
    out = call.gateway.approvals.out_of_band
    if out is None:  # the route reaches here only with an approver configured; checked again
        return _refuse(call, "no_approver", "refused: no out-of-band approver is configured")
    digest = canonical.digest(call.args)
    same = approvals.table.lookup_identical(call.key, digest)
    if same is not None and same.pending_until is not None:
        return pending_answer(same.ref, call.tool, same.pending_until, out)
    if approvals.stopping():
        return _refuse(call, "stopping", STOPPING)
    plan = None
    if call.prepare is not None:  # before the lock, as for an elicited plan (G.3)
        prepared = await call.prepare()
        if isinstance(prepared, CallToolResult):
            return prepared
        plan = prepared
        if plan is not None and len(plan.writes) > 1:
            return _refuse(call, "plan_multi_held", PLAN_MULTI_HELD)
    ledger = approvals.ledger
    if ledger is None or not ledger.accepting:
        return _refuse(call, "ledger_unavailable", LEDGER_DOWN)
    settings = _settings(call, out)
    asked_wall = approvals.wall()
    begun = approvals.table.begin(
        call.key,
        settings=settings,
        now=approvals.clock(),
        ref=call.ref,
        era=call.era,
        args=call.args,
        args_digest=digest,
        pin=call.pin,
        text_sha256=hashlib.sha256(EMPTY_TEXT.encode()).hexdigest(),
        plan=plan,
        how="elsewhere",
    )
    if not isinstance(begun, Pending):
        return _refuse(call, *begin_refusal(begun))
    writes = len(plan.writes) if plan is not None else 0
    try:
        await ledger.write(
            "asked",
            call.ref,
            critical=True,
            client=call.client,
            server=call.server,
            tool=call.tool,
            where="vault",
            era=call.era,
            args=ledger.digest(call.args),
            pin=call.pin,
            text=ledger.text_digest(EMPTY_TEXT),
            chars=0,
            writes=writes,
            expires=int((asked_wall + settings.timeout) * 1000),
        )
    except LedgerUnavailable:
        _release(approvals, begun, "error", settings.cooldown)
        return _refuse(call, "ledger_unavailable", LEDGER_DOWN)
    logs.event(
        "approval_asked",
        client=call.client,
        server=call.server,
        tool=call.tool,
        ref=call.ref,
        era=call.era,
        where="vault",
        wait=call.wait,
        writes=writes,
        timeout_s=settings.timeout,
    )
    marker = Marker(
        call.ref, call.client, call.wait, approvals.epoch, call.tool if call.toolkit else None
    )
    # A remote call's read waits out the vault's block, then the forward (I.1); a toolkit's
    # body runs under its own call_timeout, inside which the vault's block ends (B.7).
    held = Held(marker, 0.0 if call.toolkit else out.block_seconds + OUTCOME_MARGIN)
    failure: BaseException | None = None
    raw: CallToolResult | None = None
    grant = Grant(call.ref, call.args, plan)
    try:
        raw = await ticking(lambda: call.forward(held, grant), call.tick, approvals.clock)
    except HeldBusy:
        await _ended(approvals, begun, "error", "not_sent", settings)
        return _refuse(call, "identical_in_flight", IDENTICAL_IN_FLIGHT)
    except (NotAdmitted, UpstreamError, ToolkitUnavailable) as exc:
        failure = exc
    except anyio.get_cancelled_exc_class():
        with anyio.CancelScope(shield=True), anyio.move_on_after(FINISH_GRACE * 2):
            await _abandoned(approvals, call, begun, settings, held.answer)
        raise
    return await settle(
        approvals,
        call,
        begun,
        settings,
        held.answer,
        raw,
        failure,
        asked_wall,
        connection=held.connection,
    )


async def settle(
    approvals: Approvals,
    call: HeldCall,
    record: Pending,
    settings: Settings,
    answer: HeldAnswer | None,
    raw: CallToolResult | None,
    failure: BaseException | None,
    asked_wall: float,
    *,
    connection: Connection | None = None,
) -> CallToolResult | Stale:
    """C.2's table: the vault's answer to the call, with the ledger's records for it.
    ``connection`` is the upstream connection the call went out on, if it went out."""
    ref = call.ref
    approved = answer is not None and answer.approved and answer.ref == ref
    if answer is not None and answer.refused and not approved:
        return await _refused(approvals, call, record, settings, answer, asked_wall, connection)
    if answer is not None and approved:
        await _decided(approvals, record, "approved_elsewhere")
        if answer.refused and answer.code == "held_result_too_large":
            await _finish(approvals, record, "unknown", None, settings.cooldown, "accept")
            return with_ref(TOO_LARGE, ref)
        if answer.refused:
            # The vault forwarded it, and the forward failed: its own refusal, after the
            # approval, says how the forward ended on its chain (the SDK's error for it doesn't).
            outcome, detail, result = approved_failure(answer.outcome, ref)
            if call.toolkit and raw is not None:
                # A toolkit read the vault's refusal of its write and answered the call itself,
                # as it does when the gateway asks: the agent gets the toolkit's words, the
                # ledger the chain's outcome (D-258).
                result = call.finish(raw)
            await _finish(approvals, record, outcome, detail, settings.cooldown, "accept")
            return result
        if failure is not None:
            outcome, detail, result = _failed(failure, ref)
            await _finish(approvals, record, outcome, detail, settings.cooldown, "accept")
            return result
        assert raw is not None  # noqa: S101 - the forward returned, or it raised
        result = call.finish(raw)
        outcome = "tool_error" if result.is_error else "ok"
        await _finish(approvals, record, outcome, None, settings.cooldown, "accept")
        return result
    if answer is None and raw is None:
        # Nothing answered the call: it failed before the vault, or on the way back.
        assert failure is not None  # noqa: S101 - the forward returned, or it raised
        await _decided(approvals, record, "error")
        outcome, detail, result = _failed(failure, ref, sent=False)
        await _finish(approvals, record, outcome, detail, settings.cooldown, "error")
        return result
    if answer is None and call.toolkit:
        # The toolkit's body sent no held write: nothing was held, nothing asked.
        await _decided(approvals, record, "error")
        await _finish(approvals, record, "not_sent", None, settings.cooldown, "error")
        assert raw is not None  # noqa: S101 - no answer, and no failure
        return call.finish(raw)
    # An answer without the vault's approval or refusal, or none at all for a call that came
    # back: the vault didn't hold it (C.2's last row). Never shown to the agent.
    approvals.unheld[call.server] += 1
    logs.event(
        "elsewhere_unheld",
        client=call.client,
        server=call.server,
        tool=call.tool,
        ref=ref,
        status=answer.status if answer is not None else None,
        level="error",
    )
    await _decided(approvals, record, "error")
    await _finish(approvals, record, "unknown", None, settings.cooldown, "error")
    return with_ref(UNHELD, ref)


async def _refused(
    approvals: Approvals,
    call: HeldCall,
    record: Pending,
    settings: Settings,
    answer: HeldAnswer,
    asked_wall: float,
    connection: Connection | None,
) -> CallToolResult | Stale:
    """A refusal the vault made itself (``x-zoeymcp-vault: refused``) before any approval, by
    its code."""
    ref, code = call.ref, answer.code
    outcome = "not_sent"
    if code == "view_stale":
        approvals.table.finish(record.key, ref, approvals.clock(), settings_cooldown=0.0)
        return Stale()
    if code == "approval_pending":
        out = call.gateway.approvals.out_of_band
        assert out is not None  # noqa: S101 - run() checked it
        until = _deadline(answer.deadline, asked_wall + settings.timeout)
        current = approvals.table.pend(ref, until)
        if connection is not None and connection.era == "legacy":
            _keep(approvals, connection, ref, until, settings.call_timeout)
        await _decided(approvals, current, "pending")
        return pending_answer(ref, call.tool, until, out)
    if code == "held_result_too_large":
        await _decided(approvals, record, "error")
        await _finish(approvals, record, "unknown", None, settings.cooldown, "error")
        return with_ref(TOO_LARGE, ref)
    known = VAULT_ANSWERS.get(code or "")
    if known is not None:
        decision, text = known
        if code == "approval_withdrawn":
            text = WITHDRAWN.get(answer.reason or "", text)
    elif code == "held_cooldown":
        seconds = answer.retry_after or 1
        decision, text = "unavailable", f"refused: declined moments ago; try again in {seconds} s"
    elif code == "held_text_refused":
        # The place only for a pointer the gateway's pattern passed (vaultlink's _POINTER).
        where = f" at {answer.pointer}" if answer.pointer else ""
        decision = "error"
        text = f"refused: the approval text broke a rule{where}; nothing was sent"
    elif code is not None and code.startswith("held_") and answer.status in (400, 404, 413, 415):
        _log_refused(call, "vault_unread", code, "info")  # the rule is logged, never shown
        decision, text = "error", UNREAD
    else:
        _log_refused(call, "vault_refused", code, "warning")
        decision, text, outcome = "error", REFUSED_BY_VAULT, "unknown"
    await _decided(approvals, record, _ledgered(decision))
    await _finish(approvals, record, outcome, None, settings.cooldown, decision)
    return with_ref(text, ref)


def _keep(
    approvals: Approvals, connection: Connection, ref: str, until: float, call_timeout: float
) -> None:
    """F.6: a pending call's legacy upstream session stays open for the vault's forward, until
    its outcome is known or its deadline and ``call_timeout`` passed. A session that ends anyway
    fails that forward ``upstream_error session_expired``, never retried (D-228)."""
    left = max(0.0, until - approvals.wall()) + call_timeout
    connection.keep_for(ref, connection.pool.clock() + left)
    approvals.kept[ref] = lambda: connection.unkeep(ref)


async def collected(
    approvals: Approvals,
    ref: str,
    decision: LedgerDecision,
    outcome: str,
    detail: str | None,
    cooldown: float,
) -> None:
    """A pending held call's ending, as the gateway learned it from the vault (F.5, D.2): the
    lock freed at once, with the cooldown a decline or an expiry starts, its upstream session
    let go (F.6), then its own ``decided`` and ``outcome`` records. A call the vault ran keeps
    its pin for the agent's collect of its result (Z17, :meth:`.approve.Approvals.keep_ran`). A
    ref with no pending record of a held call here changes nothing."""
    record = approvals.table.get(ref)
    if (
        record is None
        or record.how != "elsewhere"
        or record.pending_until is None
        or record.decision is not None
    ):
        return
    table: Decision = "accept" if decision == "approved_elsewhere" else _undecided(decision)
    # Decided and the lock freed in this synchronous section (D-250): a second collect of the
    # same ending records nothing, and an agent told the ending may call the tool again at once
    # (with the cooldown a decline starts), before this gateway's own records are written.
    _release(approvals, record, table, cooldown)
    approvals.release_kept(ref)
    if decision == "approved_elsewhere":
        approvals.keep_ran(record)
    kept = detail if detail in ledgerformat.DETAILS else None
    await _decided(approvals, record, decision)
    await _outcome(approvals, record, outcome, kept)


def _undecided(decision: LedgerDecision) -> Decision:
    """The table's decision for an ending the vault decided against the call."""
    ended: dict[str, Decision] = {
        "decline": "decline",
        "timeout": "timeout",
        "withdrawn": "withdrawn",
    }
    return ended.get(decision, "error")


async def stale_refused(
    approvals: Approvals, ref: str, client: str, server: str, tool: str
) -> CallToolResult:
    """C.3's refusal: the vault holds the tool no longer and the fresh view doesn't ask for it
    here either. Its ``asked`` is closed: nothing was sent."""
    ledger = approvals.ledger
    if ledger is not None:
        try:
            await ledger.write("decided", ref, critical=False, decision="error", waited_ms=0)
            await ledger.write(
                "outcome",
                ref,
                critical=False,
                outcome="not_sent",
                detail="changed",
                writes_sent=0,
                writes_unknown=0,
            )
        except LedgerUnavailable:
            pass
    logs.event(
        "approval_refused", client=client, server=server, tool=tool, ref=ref, reason="view_stale"
    )
    return with_ref(STALE, ref)


async def _abandoned(
    approvals: Approvals,
    call: HeldCall,
    record: Pending,
    settings: Settings,
    answer: HeldAnswer | None,
) -> None:
    """The agent left (its handler cancelled): the vault is told, and the gateway's ledger says
    withdrawn, ``outcome unknown``, since the vault may have approved and forwarded it. Telling
    the vault gets :data:`.approve.FINISH_GRACE` of the grace, so a vault slow to answer never
    leaves the records unwritten or the lock held. Cut by the gateway's own stop (a call whose
    answer didn't come before the stop's grace ran out, I.2 step 4), it says ``shutdown``, and
    ``outcome unknown, detail shutdown``: the vault's chain has the real outcome."""
    stopped = approvals.stopping()
    if approvals.tell_withdrawn is not None and (answer is None or not answer.refused):
        with anyio.move_on_after(FINISH_GRACE) as telling:
            try:
                await approvals.tell_withdrawn(call.ref, call.client, "caller_cancelled")
            except Exception as exc:  # the vault's own cancel rules still apply (B.6)
                logs.event("approval_withdraw_failed", ref=call.ref, error_type=type(exc).__name__)
        if telling.cancelled_caught:
            logs.event("approval_withdraw_failed", ref=call.ref, error_type="timeout")
    if stopped:
        await _decided(approvals, record, "shutdown")
        await _finish(approvals, record, "unknown", "shutdown", settings.cooldown, "shutdown")
        return
    await _decided(approvals, record, "withdrawn")
    await _finish(approvals, record, "unknown", None, settings.cooldown, "withdrawn")


# --- the pending answer's deadline (F.1; the answer is :func:`.approvers.pending_answer`) -------


def _deadline(stated: str | None, fallback: float) -> float:
    """The vault's deadline for a pending call (its body's), else the gateway's own."""
    if stated is None:
        return fallback
    try:
        return datetime.fromisoformat(stated).timestamp()
    except ValueError:
        return fallback


# --- the ledger and the lock ----------------------------------------------------------------------


def _settings(call: HeldCall, out: ViewOutOfBand) -> Settings:
    """The record's limits: the out-of-band deadline (``approvers.timeout``), so the lock's hard
    deadline is ``deadline + call_timeout + 30`` (D.2), and the gateway's caps."""
    gateway = call.gateway
    return Settings(
        timeout=float(out.timeout),
        call_timeout=float(call.policy.call_timeout or gateway.limits.call_timeout),
        cooldown=float(gateway.approvals.cooldown),
        max_pending_per_client=gateway.approvals.max_pending_per_client,
        max_prompts_per_hour=gateway.approvals.max_prompts_per_hour,
    )


# The gateway's table keeps an approved held call as accept; the ledger says approved_elsewhere.
LedgerDecision = Literal[
    "approved_elsewhere",
    "pending",
    "decline",
    "timeout",
    "withdrawn",
    "error",
    "unavailable",
    "shutdown",
]


def _ledgered(decision: Decision) -> LedgerDecision:
    if decision in ("decline", "timeout", "withdrawn", "unavailable"):
        return decision
    return "error"


async def _decided(approvals: Approvals, record: Pending, decision: LedgerDecision) -> None:
    waited = max(0, round((approvals.clock() - record.asked_at) * 1000))
    anchor = None
    if approvals.ledger is not None:
        try:
            anchor = await approvals.ledger.write(
                "decided", record.ref, critical=False, decision=decision, waited_ms=waited
            )
        except LedgerUnavailable:
            anchor = None
    logs.event(
        "approval_decided",
        client=record.key.client,
        server=record.key.server,
        tool=record.key.tool,
        ref=record.ref,
        decision=decision,
        waited_ms=waited,
        ledger_seq=anchor.seq if anchor is not None else None,
        ledger_hash=anchor.hash if anchor is not None else None,
    )


async def _finish(
    approvals: Approvals,
    record: Pending,
    outcome: str,
    detail: str | None,
    cooldown: float,
    decision: Decision,
) -> None:
    """The call's outcome on the ledger, then the lock freed, with the cooldown its decision
    starts (a decline or an expiry, E.1)."""
    try:
        await _outcome(approvals, record, outcome, detail)
    finally:
        _release(approvals, record, decision, cooldown)


async def _outcome(approvals: Approvals, record: Pending, outcome: str, detail: str | None) -> None:
    """The call's ``outcome`` record on the ledger, and its log line."""
    anchor = None
    if approvals.ledger is not None:
        try:
            anchor = await approvals.ledger.write(
                "outcome",
                record.ref,
                critical=False,
                outcome=outcome,
                detail=detail,
                writes_sent=0,
                writes_unknown=0,
            )
        except LedgerUnavailable:
            anchor = None
    logs.event(
        "approval_outcome",
        ref=record.ref,
        outcome=outcome,
        detail=detail,
        ledger_seq=anchor.seq if anchor is not None else None,
        ledger_hash=anchor.hash if anchor is not None else None,
    )


async def _ended(
    approvals: Approvals, record: Pending, decision: Decision, outcome: str, settings: Settings
) -> None:
    await _decided(approvals, record, _ledgered(decision))
    await _finish(approvals, record, outcome, None, settings.cooldown, decision)


def _release(approvals: Approvals, record: Pending, decision: Decision, cooldown: float) -> None:
    """Decide the record as the vault did (the first decision stands) and free its lock."""
    now = approvals.clock()
    if approvals.table.get(record.ref) is not None:
        approvals.table.decide(record.ref, decision, now)
    approvals.table.finish(record.key, record.ref, now, settings_cooldown=cooldown)


# --- the agent's texts ----------------------------------------------------------------------------


def _log_refused(call: HeldCall, reason: str, code: str | None, level: str) -> None:
    logs.event(
        "approval_refused",
        client=call.client,
        server=call.server,
        tool=call.tool,
        ref=call.ref,
        reason=reason,
        code=code,
        level=level,
    )


def _refuse(call: HeldCall, reason: str, text: str) -> CallToolResult:
    logs.event(
        "approval_refused",
        client=call.client,
        server=call.server,
        tool=call.tool,
        ref=call.ref,
        reason=reason,
    )
    return with_ref(text, call.ref)


def approved_failure(
    outcome: object, ref: str, status: int | None = None
) -> tuple[str, str | None, CallToolResult]:
    """The ledger's outcome and the agent's answer for an approved held call whose forward
    failed, from the vault's outcome of it (B.8): never sent, or a connector's send refused
    before anything was sent (B.7, D-258); an upstream that answered with an error (with
    ``status`` 404, the session the forward went out on was gone: F.6, D-228); or one that may
    have run, as is any outcome the vault didn't name."""
    if outcome in ("not_sent", "refused"):
        return outcome, None, map_upstream("unavailable", ref)
    if outcome == "upstream_error" and status == 404:
        return "upstream_error", "session_expired", map_upstream("connection_lost", ref)
    if outcome == "upstream_error":
        return "upstream_error", None, map_upstream("rpc_error", ref)
    return "unknown", None, map_upstream("connection_lost", ref)


def _failed(
    failure: BaseException, ref: str, *, sent: bool = True
) -> tuple[str, str | None, CallToolResult]:
    """The ledger's outcome and the agent's answer for a forward that raised. After the vault's
    approval, an upstream that answered its session gone (404) didn't run it: ``upstream_error``,
    never retried (FM-12); anything else may have run."""
    if isinstance(failure, ToolkitUnavailable):
        return "not_sent", None, with_ref(TOOLKIT_UNAVAILABLE, ref)
    if isinstance(failure, NotAdmitted):
        return "not_sent", "changed", map_upstream("unavailable", ref)
    assert isinstance(failure, UpstreamError)  # noqa: S101 - the forward's three failures
    if failure.detail == "session_expired":
        return "upstream_error", "session_expired", map_upstream(failure.outcome, ref)
    if failure.outcome == "unavailable":
        return "not_sent", None, map_upstream(failure.outcome, ref)
    if failure.outcome in ("rpc_error", "unsupported_result", "output_refused", "too_large"):
        return ("upstream_error" if sent else "unknown"), None, map_upstream(failure.outcome, ref)
    return "unknown", None, map_upstream(failure.outcome, ref)
