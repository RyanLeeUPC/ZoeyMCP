"""The asking side of an approval: how a recorded call is put to a human (M8 design D.1, C.5).

:mod:`.approve` keeps the orchestration (the gate, the lock, the ledger, the committed forward);
a transport here only asks and says what was decided. The two transports of M4:

- :class:`ElicitationLegacy`: ``elicitation/create`` on the call's own stream (M4 design D.2,
  D.4), raced against the stream's loss and a withdrawal. It is an :class:`Approver`: the answer
  comes back within the call.
- :class:`ElicitationModern`: an ``InputRequiredResult`` whose ``requestState`` is a single-use
  handle, and the retry that answers it (D.6), so its decision comes back on a later request.

Both share the process's one table and two maps :class:`.approve.Approvals` keeps: what each
waiting prompt showed, and the cancel scope of each legacy wait.

M8 step 12b adds the third, :class:`OutOfBand` (E.3, E.4; Q6 (B)): the gateway's own rendered
prompt, for a client that is ``out_of_band``, relayed through the vault's ask endpoint to the
operator's approvers, which show it below the vault's relay line (E.5, Z12). The decision comes
back through the vault's decisions poll (:mod:`.outofband`'s dispatcher), which wakes the call
waiting here, within ``approvers.block_seconds``; past it, the call answers ``pending <ref>``
(:class:`Pended`) and a later decision is acted on without it. An approval counts only for the
text the gateway asked with (G-23).

The texts the agent sees for a decision live here, with the transports that produce most of them.
"""

from __future__ import annotations

import math
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Final, Protocol

import anyio
import mcp_types
import pydantic
from mcp.shared.exceptions import MCPError, NoBackChannelError
from mcp.types import CallToolResult, TextContent

from ..common import canonical
from ..common.approvaltext import ApprovalText
from ..common.policy.view import ViewOutOfBand
from . import approvals, logs
from .approvals import ConfirmCode, Decision, Pending, Settings

if TYPE_CHECKING:
    from .approve import Asking

# The one copy of the text for a call nobody answers for (M8 design C.1, F-46): the pipeline's
# route words it, and :mod:`.approve`'s backstop too, without importing the pipeline.
NO_APPROVALS = "refused: no approver for this client"
CANT_SHOW = "refused: this client can't show approvals"
EXPIRED = "refused: approval expired or already used"
CHANGED = "refused: the tool or policy changed while waiting for approval"
DECISION_TEXTS: Mapping[str, str] = {
    "decline": "declined by operator",
    "dismiss": "declined by operator",
    "code_mismatch": "declined: the confirmation code didn't match",
    "timeout": "no answer in time",
    "withdrawn": "refused: the policy changed; call the tool again",
    "stream_lost": "refused: the approval prompt's stream was lost",
    "unavailable": CANT_SHOW,
    "error": "refused: the approval request failed",
    "mismatch": "refused: this approval belongs to a different call",
    "changed": CHANGED,
    "shutdown": "refused: the gateway is stopping",
}


# A relay the vault didn't take (E.2's ask), or one decided on another text than the one asked
# with (G-23): nothing was sent. A vault code not named here is "refused by the vault".
RELAY_UNREACHABLE = "refused: the vault couldn't be asked to relay this approval; nothing was sent"
RELAY_MISMATCH = "refused: the approval was for another text than the one asked; nothing was sent"
RELAY_REFUSED = "refused by the vault; nothing was sent"
ASK_ANSWERS: Final[Mapping[str, tuple[Decision, str]]] = MappingProxyType(
    {
        "held_capacity": ("unavailable", "refused: the vault's approval queue is full"),
        # For a relay, only the vault's fairness cap (D.3): one of this tool is still held there.
        "held_busy": (
            "unavailable",
            "refused: an approval of this tool is already waiting at the vault; nothing was sent",
        ),
        "held_hourly": ("unavailable", "refused: too many approval requests this hour"),
        "held_ledger_down": (
            "unavailable",
            "refused: the vault can't record approvals right now; nothing was sent",
        ),
        "stopping": (
            "unavailable",
            "refused: the vault is restarting; nothing was sent; try again shortly",
        ),
        "held_ref_reused": ("error", "refused: this call's ref was used before; nothing was sent"),
        "text_refused": ("error", "refused: the approval text broke a rule; nothing was sent"),
        "view_stale": ("error", "refused: the policy is changing; call the tool again"),
        "telegram_too_long": (
            "error",
            "refused: too long to show in the operator's chat; nothing was sent",
        ),
        "telegram_text_changed": (
            "error",
            "refused: the approval text can't be shown as sent; nothing was sent",
        ),
    }
)
# The vault's decision on a relay (E.2) to the table's; an approval is checked first (G-23).
RELAY_ENDINGS: Final[Mapping[str, Decision]] = MappingProxyType(
    {"decline": "decline", "timeout": "timeout", "withdrawn": "withdrawn"}
)


def refused(text: str) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=text)], is_error=True)


def with_ref(text: str, ref: str) -> CallToolResult:
    return refused(f"{text} (ref {ref})")


def pending_answer(ref: str, tool: str, until: float, out: ViewOutOfBand) -> CallToolResult:
    """The pending answer (M8 design F.1): an error result with no ``structuredContent``, which
    says it is not a failure, so the agent collects the call instead of calling again. A call
    the vault holds and a relayed one answer the same."""
    when = datetime.fromtimestamp(until, UTC).strftime("%Y-%m-%d %H:%M")
    minutes = max(1, math.ceil(out.result_ttl / 60))
    text = (
        f"pending {ref}: waiting for the operator's approval until {when} UTC. It runs as soon "
        f"as it is approved, whether or not you check. Do not call {tool} again; call "
        f'check_approval with {{"id": "{ref}"}} to get the result; it is kept for {minutes} '
        "minutes after the call runs and given once. This is not a failure."
    )
    return CallToolResult(content=[TextContent(type="text", text=text)], is_error=True)


@dataclass
class Shown:
    """What a waiting prompt showed, kept so a modern re-ask is the same prompt."""

    text: ApprovalText
    schema: dict[str, Any]
    settings: Settings
    asked_wall: float


@dataclass(frozen=True)
class Decided:
    """What a transport learned about ``record``: the human's decision, or the table's when a
    withdrawal or a shutdown decided it first."""

    record: Pending
    decision: Decision


@dataclass(frozen=True)
class Pended:
    """D.1's ``Pended``: the out-of-band block is over undecided, and the call waits on until
    ``until`` (wall time), its lock held (D.2); the agent is answered ``pending <ref>``."""

    record: Pending
    until: float


@dataclass(frozen=True)
class Unasked:
    """A relay that ended with no human's decision on the call asked: the vault refused the
    ask, or couldn't be asked, or the approval was for another text (G-23). ``decision`` is the
    ledger's, ``reason`` the log's (with the vault's ``code``), ``text`` the agent's."""

    decision: Decision
    reason: str
    text: str
    code: str | None = None


# A decision that doesn't run the call, ledgered and its lock freed (Approvals._close); and why a
# client can't be asked on this request, or None (Approvals._gate, which logs the refusal).
Close = Callable[[Pending, Decision], Awaitable[None]]
Gate = Callable[["Asking"], CallToolResult | None]


class Approver(Protocol):
    """A transport that puts one recorded call to a human and answers within the call (D.1);
    the out-of-band one (:class:`OutOfBand`) may answer :class:`Pended` instead, or
    :class:`Unasked` when nobody could be asked."""

    async def ask(
        self, asking: Asking, record: Pending, shown: Shown
    ) -> Decided | Pended | Unasked: ...


@dataclass
class ElicitationLegacy:
    """The legacy era's prompt: on the call's own stream, the handler waiting for the answer."""

    table: approvals.Table
    waits: dict[str, anyio.CancelScope]
    clock: Callable[[], float]
    # The agent cancelled its call, or the handler failed: nothing is sent (bounded, shielded).
    abandoned: Callable[[Pending], Awaitable[None]]

    async def ask(self, asking: Asking, record: Pending, shown: Shown) -> Decided:
        """D.2 and D.4: the prompt on the call's stream, raced against the stream's loss and a
        withdrawal. An agent cancel cancels this handler: the decision is then ``withdrawn``."""
        found: list[Decision] = []

        async def ask() -> None:
            remaining = max(0.001, record.expires_at - self.clock())
            try:
                answer = await asking.session.elicit(shown.text.value, shown.schema, remaining)
            except NoBackChannelError:  # a subclass of MCPError: caught first
                found.append("unavailable")
            except MCPError as exc:
                found.append("timeout" if exc.error.code == mcp_types.REQUEST_TIMEOUT else "error")
            except pydantic.ValidationError:
                found.append("error")
            else:
                found.append(decide(answer, record.code))
            group.cancel_scope.cancel()

        async def watch(event: anyio.Event) -> None:
            await event.wait()
            found.append("stream_lost")
            group.cancel_scope.cancel()

        try:
            with anyio.CancelScope() as wait:
                self.waits[record.ref] = wait
                async with anyio.create_task_group() as group:
                    group.start_soon(ask)
                    if asking.disconnected is not None:
                        group.start_soon(watch, asking.disconnected)
        except BaseException:
            await self.abandoned(record)
            raise
        finally:
            self.waits.pop(record.ref, None)
        current = self.table.get(record.ref)
        if current is not None and current.decision is not None:
            return Decided(record, current.decision)  # withdrawn by a policy change, or a shutdown
        return Decided(record, found[0] if found else "error")


@dataclass
class ElicitationModern:
    """The modern era's prompt: an ``InputRequiredResult``, answered by a retry (D.6)."""

    table: approvals.Table
    shown: dict[str, Shown]
    clock: Callable[[], float]
    close: Close
    gate: Gate

    def ask(self, shown: Shown, handle: approvals.Handle) -> mcp_types.InputRequiredResult:
        """The first ask: the prompt, under the handle the record was begun with."""
        return input_required(shown.text, shown.schema, handle)

    async def retry(
        self, asking: Asking
    ) -> Decided | CallToolResult | mcp_types.InputRequiredResult:
        """D.6: a modern retry. Steps 1-6 are :func:`.approvals.retry`; 7-9 are here. An answer
        comes back :class:`Decided`, for the caller to act on; anything else is the reply."""
        result = approvals.retry(
            self.table,
            asking.request_state,
            key=asking.key,
            args_digest=canonical.digest(asking.args),
            pin=asking.pin,
            now=self.clock(),
        )
        if isinstance(result, approvals.Foreign):
            logs.event("approval_state_foreign", client=asking.client, server=asking.server)
            return refused(EXPIRED)
        if isinstance(result, approvals.Unknown):
            return refused(EXPIRED)
        if isinstance(result, approvals.Buried):
            return refused(DECISION_TEXTS["timeout"] if result.reason == "expired" else EXPIRED)
        if isinstance(result, approvals.Closed):
            record = result.record
            await self.close(record, record.decision or "error")
            return with_ref(DECISION_TEXTS[record.decision or "error"], record.ref)
        record = result.record
        responses = dict(asking.input_responses or {})
        answer = responses.pop(approvals.INPUT_KEY, None)
        if responses:
            logs.event("approval_unknown_answers", ref=record.ref, count=len(responses))
        if answer is None:
            return self._reask(asking, record)
        if not isinstance(answer, mcp_types.ElicitResult):
            return Decided(record, "error")
        return Decided(record, decide(answer, record.code))

    def _reask(self, asking: Asking, record: Pending) -> Decided | mcp_types.InputRequiredResult:
        """No answer came: ask again with a new handle, the same ref, text, code and expiry."""
        if self.gate(asking) is not None:
            return Decided(record, "unavailable")
        if not approvals.may_reask(record):
            return Decided(record, "error")
        shown = self.shown.get(record.ref)
        if shown is None:
            return Decided(record, "error")
        handle = approvals.new_handle()
        record = self.table.reask(record.ref, handle.sha256())
        logs.event("approval_reasked", ref=record.ref, asks=record.asks)
        return input_required(shown.text, shown.schema, handle)


# --- out of band (M8 design E.3, E.4) -------------------------------------------------------------

# Tells the vault a call it holds or relays was given up (ref, client, reason): its
# ``approvals/withdraw`` (E.2), bound to :meth:`.outofband.OutOfBandClient.withdraw` by the app.
TellWithdrawn = Callable[[str, str, str], Awaitable[None]]


@dataclass(frozen=True)
class Asked:
    """The vault relays the prompt (the ask's 201): its approval id, and the digest of the text
    as the vault composed it, its relay line included, which every surface decides on (E.5)."""

    id: str
    text_sha256: str


@dataclass(frozen=True)
class AskRefused:
    """The vault refused the ask: its status, its code, and a cooldown's seconds left."""

    status: int
    code: str | None
    retry_after: int | None = None


# Asks the vault to relay a prompt (the ask's body, E.2), bound to
# :meth:`.outofband.OutOfBandClient.ask` by the app; raises when the vault couldn't be asked.
AskVault = Callable[[Mapping[str, Any]], Awaitable[Asked | AskRefused]]


@dataclass(frozen=True)
class Relayed:
    """The vault's decision on a relay, as its decisions poll answered it (E.2): ``accept``,
    ``decline``, ``timeout`` or ``withdrawn``, the surface it came through, when, and the digest
    of the text it was taken on."""

    seq: int
    ref: str
    decision: str
    via: str
    decided_ms: int
    text_sha256: str

    @property
    def restarted(self) -> bool:
        """Whether this stands for a restarted vault (:func:`lost`), not a decision it sent: the
        restarted vault may hold the relay anew, so it is told the gateway gave it up."""
        return self.seq == 0


def lost(ref: str) -> Relayed:
    """The decision a restarted vault stands for: every relay it had is gone (Z10)."""
    return Relayed(0, ref, "withdrawn", "none", 0, "")


@dataclass
class RelayWait:
    """One relay, from the ask to its decision: the call as the pipeline handed it over, its
    record, the digest the vault answered the ask with, and the vault's decision once the
    decisions poll brought it. ``detached`` once the call answered pending; ``answered`` set
    once that answer's record is written, so a later decision is recorded after it."""

    asking: Asking
    record: Pending
    digest: str | None = None
    decided: Relayed | None = None
    detached: bool = False
    woken: anyio.Event = field(default_factory=anyio.Event)
    answered: anyio.Event = field(default_factory=anyio.Event)


@dataclass
class OutOfBand:
    """The out-of-band transport (E.3, E.4): the gateway-rendered prompt relayed through the
    vault's ask, then the wait for the decision, at most ``approvers.block_seconds`` from the
    ask; the caller's leaving, or a withdrawal here, is told to the vault (``withdraw``). The
    app binds :attr:`ask_vault` and :attr:`tell_withdrawn` to the vault's approvals client;
    unbound, nothing is relayed. ``grace`` bounds telling the vault, so a vault that doesn't
    answer never leaves the call's records unwritten."""

    table: approvals.Table
    clock: Callable[[], float]
    epoch: str
    grace: float
    ask_vault: AskVault | None = None
    tell_withdrawn: TellWithdrawn | None = None
    waiting: dict[str, RelayWait] = field(default_factory=dict)

    async def ask(
        self, asking: Asking, record: Pending, shown: Shown
    ) -> Decided | Pended | Unasked:
        """Relay ``record``'s prompt, and wait for the vault's decision, a withdrawal here, or
        the end of the block: a decision is acted on by the caller, past the block the call
        waits on (:class:`Pended`), and an ask the vault refused is :class:`Unasked`."""
        ask_vault = self.ask_vault
        out = asking.gateway.approvals.out_of_band
        if ask_vault is None or out is None:  # the route relays only with an approver; again
            return Unasked("unavailable", "vault_unreachable", RELAY_UNREACHABLE)
        until = shown.asked_wall + shown.settings.timeout
        current = self.table.get(record.ref)
        decided = current.decision if current is not None else "withdrawn"
        if decided is not None:
            # Withdrawn before it was asked (a change while its asked record was written).
            return Decided(record, decided)
        wait = RelayWait(asking, record)
        self.waiting[record.ref] = wait
        try:
            body = {
                "v": 1,
                "epoch": self.epoch,
                "ref": record.ref,
                "client": asking.client,
                "server": asking.server,
                "tool": asking.tool,
                "text": shown.text.value,
                "text_sha256": record.text_sha256,
                "deadline_ms": int(until * 1000),
                "wait": "pending",
            }
            try:
                answer = await ask_vault(body)
            except Exception as exc:  # every failure to ask is the same: nothing will be sent
                logs.event(
                    "approval_relay_failed",
                    ref=record.ref,
                    error_type=type(exc).__name__,
                    level="warning",
                )
                # The vault may have taken the ask before it failed here (a read timeout, a lost
                # or malformed 201): told, so no relay is left there that nobody will forward.
                await self.withdraw(record)
                return Unasked("unavailable", "vault_unreachable", RELAY_UNREACHABLE)
            if isinstance(answer, AskRefused):
                return _ask_refused(answer)
            wait.digest = answer.text_sha256
            with anyio.move_on_after(
                max(0.0, out.block_seconds - (self.clock() - record.asked_at))
            ):
                await wait.woken.wait()
            current = self.table.get(record.ref)
            if current is not None and current.decision is not None:
                # Withdrawn here meanwhile (a change, a stop): nobody will forward it.
                await self.withdraw(record)
                return Decided(record, current.decision)
            if wait.decided is not None:
                if wait.decided.restarted:
                    await self.withdraw(record)
                return self.settled(wait)
            if self.clock() >= record.expires_at:
                # The block lasted to the deadline (``block_seconds`` may equal the timeout, I.1
                # step 2): nobody answered in time, and the vault is told.
                await self.withdraw(record)
                return Decided(record, "timeout")
            # One synchronous section from here: a decision arriving now finds it detached.
            wait.detached = True
            return Pended(self.table.pend(record.ref, until), until)
        finally:
            if not wait.detached:
                self.waiting.pop(record.ref, None)

    def settled(self, wait: RelayWait) -> Decided | Unasked:
        """What the vault's decision on ``wait`` decides: an approval of the text the gateway
        asked with runs the call; one of any other text is refused, nothing sent (G-23)."""
        decided, record = wait.decided, wait.record
        assert decided is not None  # noqa: S101 - called once the decision came
        if decided.decision != "accept":
            return Decided(record, RELAY_ENDINGS.get(decided.decision, "withdrawn"))
        if decided.text_sha256 != wait.digest:
            logs.event(
                "relay_digest_mismatch",
                client=record.key.client,
                server=record.key.server,
                tool=record.key.tool,
                ref=record.ref,
                level="error",
            )
            return Unasked("error", "relay_digest_mismatch", RELAY_MISMATCH)
        return Decided(record, "accept")

    async def withdraw(self, record: Pending) -> None:
        """Tell the vault the gateway gave up ``record`` (``caller_cancelled``, E.2), within
        :attr:`grace` and shielded; a vault that can't be told withdraws it at its deadline."""
        tell = self.tell_withdrawn
        if tell is None:
            return
        with anyio.CancelScope(shield=True), anyio.move_on_after(self.grace) as telling:
            try:
                await tell(record.ref, record.key.client, "caller_cancelled")
            except Exception as exc:  # the vault's own rules still end it (B.5, E.2)
                logs.event(
                    "approval_withdraw_failed", ref=record.ref, error_type=type(exc).__name__
                )
        if telling.cancelled_caught:
            logs.event("approval_withdraw_failed", ref=record.ref, error_type="timeout")


def _ask_refused(answer: AskRefused) -> Unasked:
    """The agent's text for the vault's refusal of an ask, by its code; nothing was asked."""
    code = answer.code or ""
    if code == "held_cooldown":
        seconds = answer.retry_after or 1
        text = f"refused: declined moments ago; try again in {seconds} s"
        return Unasked("unavailable", "vault_refused", text, code)
    known = ASK_ANSWERS.get(code)
    if known is not None:
        return Unasked(known[0], "vault_refused", known[1], code)
    return Unasked("error", "vault_refused", RELAY_REFUSED, answer.code)


def decide(answer: Any, code: ConfirmCode | None) -> Decision:
    """The decision an elicitation answer makes; anything but a typed answer is ``error``."""
    if not isinstance(answer, mcp_types.ElicitResult):
        return "error"
    return approvals.decide_answer(answer.action, answer.content, code)


def input_required(
    text: ApprovalText, schema: dict[str, Any], handle: approvals.Handle
) -> mcp_types.InputRequiredResult:
    params = mcp_types.ElicitRequestFormParams(message=text.value, requested_schema=schema)
    return mcp_types.InputRequiredResult(
        input_requests={approvals.INPUT_KEY: mcp_types.ElicitRequest(params=params)},
        request_state=handle.reveal(),
    )
