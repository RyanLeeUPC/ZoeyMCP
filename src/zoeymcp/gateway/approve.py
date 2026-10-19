"""The approval decision point: the I/O around :mod:`.approvals` (M4 design B, D).

A call to a tool the policy classifies ``approve`` reaches :meth:`Approvals.handle` after the
pipeline has admitted, shaped, canonicalized and validated it. In order (B.2):

5.1 a modern retry (``requestState``) goes to :meth:`Approvals._retry` (D.6);
5.2 the client must be attended, and the approver ``elicitation``;
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
prompt, the ledger and the logs share.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal, Protocol

import anyio
import mcp_types
import pydantic
from mcp.shared.exceptions import MCPError, NoBackChannelError
from mcp.types import CallToolResult, TextContent

from ..common import approvaltext, canonical
from ..common.approvaltext import ApprovalText, Header
from ..common.policy.schema import ClientApprovals
from ..common.policy.view import ViewGateway
from . import approvals, logs
from .approvals import ConfirmCode, Decision, Key, Pending, Settings
from .committed import Committed, CommittedCancelled
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

NO_APPROVER = "refused: no approver for this client"
STOPPING = "refused: the gateway is stopping; try again shortly"
CANT_SHOW = "refused: this client can't show approvals"
UNEXPECTED_INPUT = "refused: unexpected input responses"
LEDGER_DOWN = "refused: the approval ledger can't be written"
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


def refused(text: str) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=text)], is_error=True)


def with_ref(text: str, ref: str) -> CallToolResult:
    return refused(f"{text} (ref {ref})")


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

    @property
    def key(self) -> Key:
        return Key(self.client, self.server, self.tool)


@dataclass
class _Shown:
    """What a waiting prompt showed, kept so a modern re-ask is the same prompt."""

    text: ApprovalText
    schema: dict[str, Any]
    settings: Settings
    asked_wall: float


@dataclass
class Approvals:
    """Every approval of one gateway process: the table, the prompts shown, the waits."""

    ledger: Ledger | None
    committed: Committed
    fresh: Callable[[], Snapshot | None]
    stopping: Callable[[], bool]
    clock: Callable[[], float] = time.monotonic
    wall: Callable[[], float] = time.time
    table: approvals.Table = field(default_factory=approvals.Table)
    _shown: dict[str, _Shown] = field(default_factory=dict)
    _waits: dict[str, anyio.CancelScope] = field(default_factory=dict)

    # --- the entry point ---------------------------------------------------------------------

    async def handle(self, asking: Asking) -> CallToolResult | mcp_types.InputRequiredResult:
        if asking.request_state is not None:
            if asking.era == "legacy":
                return self._refuse(asking, "unexpected_input", UNEXPECTED_INPUT)
            return await self._retry(asking)
        if asking.input_responses:
            if asking.era == "legacy":
                return self._refuse(asking, "unexpected_input", UNEXPECTED_INPUT)
            # Answers count only through a live handle (D.6): these are ignored, and asked anew.
            logs.event(
                "approval_unsolicited_answer",
                client=asking.client,
                server=asking.server,
                tool=asking.tool,
            )
        own = _client_settings(asking.gateway, asking.client)
        if own is None or not own.attended or asking.gateway.approvals.approver != "elicitation":
            return self._refuse(asking, "unattended", NO_APPROVER)
        if self.stopping():
            return self._refuse(asking, "stopping", STOPPING)
        refusal = self._gate(asking)
        if refusal is not None:
            return refusal
        settings = _settings(asking.gateway, own, asking.policy)
        code = approvals.new_code() if own.confirm_code else None
        asked_wall = self.wall()
        text = approvaltext.render_call(
            _header(asking, asked_wall + settings.timeout),
            asking.args,
            code=code.reveal() if code is not None else None,
        )
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
            code=code,
            session_sha256=asking.session_sha256,
            handle_sha256=handle.sha256() if handle is not None else None,
        )
        if not isinstance(begun, Pending):
            return self._refuse_begin(asking, begun)
        schema = CODE_SCHEMA if code is not None else EMPTY_SCHEMA
        self._shown[asking.ref] = _Shown(text, schema, settings, asked_wall)
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
                writes=0,
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
            writes=0,
            timeout_s=settings.timeout,
            code=code is not None,
        )
        if handle is not None:
            return _input_required(text, schema, handle)
        decision = await self._ask_legacy(asking, begun, text, schema)
        return await self._decided(asking, begun, decision)

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
        if isinstance(refusal, approvals.Busy):
            return self._refuse(
                asking,
                "busy",
                "refused: another call to this tool is waiting or running "
                f"(ref {refusal.holder_ref}, frees within {refusal.seconds_left} s)",
            )
        if isinstance(refusal, approvals.PendingCap):
            return self._refuse(
                asking,
                "pending_cap",
                "refused: an approval is already waiting for this client "
                f"(ref {refusal.holder_ref})",
            )
        if isinstance(refusal, approvals.HourlyCap):
            return self._refuse(
                asking, "hourly_cap", "refused: too many approval requests this hour"
            )
        if isinstance(refusal, approvals.Cooldown):
            return self._refuse(
                asking,
                "cooldown",
                "refused: this tool was declined moments ago; "
                f"try again in {refusal.seconds_left} s",
            )
        return self._refuse(asking, "table_full", "refused: too many approvals are waiting")

    # --- asking --------------------------------------------------------------------------------

    async def _ask_legacy(
        self, asking: Asking, record: Pending, text: ApprovalText, schema: dict[str, Any]
    ) -> Decision:
        """D.2 and D.4: the prompt on the call's stream, raced against the stream's loss and a
        withdrawal. An agent cancel cancels this handler: the decision is then ``withdrawn``."""
        found: list[Decision] = []

        async def ask() -> None:
            remaining = max(0.001, record.expires_at - self.clock())
            try:
                answer = await asking.session.elicit(text.value, schema, remaining)
            except NoBackChannelError:  # a subclass of MCPError: caught first
                found.append("unavailable")
            except MCPError as exc:
                found.append("timeout" if exc.error.code == mcp_types.REQUEST_TIMEOUT else "error")
            except pydantic.ValidationError:
                found.append("error")
            else:
                found.append(_decide(answer, record.code))
            group.cancel_scope.cancel()

        async def watch(event: anyio.Event) -> None:
            await event.wait()
            found.append("stream_lost")
            group.cancel_scope.cancel()

        try:
            with anyio.CancelScope() as wait:
                self._waits[record.ref] = wait
                async with anyio.create_task_group() as group:
                    group.start_soon(ask)
                    if asking.disconnected is not None:
                        group.start_soon(watch, asking.disconnected)
        except BaseException:
            # The agent cancelled its call, or the handler failed: nothing is sent.
            with anyio.CancelScope(shield=True), anyio.move_on_after(FINISH_GRACE):
                await self._close(record, "withdrawn")
            raise
        finally:
            self._waits.pop(record.ref, None)
        current = self.table.get(record.ref)
        if current is not None and current.decision is not None:
            return current.decision  # withdrawn by a policy change, or a shutdown
        return found[0] if found else "error"

    async def _retry(self, asking: Asking) -> CallToolResult | mcp_types.InputRequiredResult:
        """D.6: a modern retry. Steps 1-6 are :func:`.approvals.retry`; 7-9 are here."""
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
            await self._close(record, record.decision or "error")
            return with_ref(DECISION_TEXTS[record.decision or "error"], record.ref)
        record = result.record
        responses = dict(asking.input_responses or {})
        answer = responses.pop(approvals.INPUT_KEY, None)
        if responses:
            logs.event("approval_unknown_answers", ref=record.ref, count=len(responses))
        if answer is None:
            return await self._reask(asking, record)
        if not isinstance(answer, mcp_types.ElicitResult):
            return await self._decided(asking, record, "error")
        return await self._decided(asking, record, _decide(answer, record.code))

    async def _reask(
        self, asking: Asking, record: Pending
    ) -> CallToolResult | mcp_types.InputRequiredResult:
        """No answer came: ask again with a new handle, the same ref, text, code and expiry."""
        if self._gate(asking) is not None:
            return await self._decided(asking, record, "unavailable")
        if not approvals.may_reask(record):
            return await self._decided(asking, record, "error")
        shown = self._shown.get(record.ref)
        if shown is None:
            return await self._decided(asking, record, "error")
        handle = approvals.new_handle()
        record = self.table.reask(record.ref, handle.sha256())
        logs.event("approval_reasked", ref=record.ref, asks=record.asks)
        return _input_required(shown.text, shown.schema, handle)

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
        """B.5 and B.6, in the registry's own task: no cancel but the shutdown deadline's."""
        outcome: dict[str, Any] = {"outcome": "unknown", "detail": None}
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
                await self._outcome(record, "not_sent", None)
                outcome = {}
                return with_ref(LEDGER_DOWN, record.ref)
            self._log_decided(record, "accept", anchor)
            try:
                result = await asking.forward(Grant(record.ref, asking.args))
            except NotAdmitted:
                outcome = {"outcome": "not_sent", "detail": "changed"}
                return with_ref(CHANGED, record.ref)
            except UpstreamError as exc:
                outcome = _upstream_outcome(exc)
                return map_upstream(exc.outcome, record.ref)
            outcome = {"outcome": "tool_error" if result.is_error else "ok", "detail": None}
            return result
        except anyio.get_cancelled_exc_class():
            outcome = {"outcome": "unknown", "detail": "shutdown"}
            raise
        finally:
            with anyio.CancelScope(shield=True), anyio.move_on_after(FINISH_GRACE * 2):
                if outcome:
                    await self._outcome(record, outcome["outcome"], outcome["detail"])
                self._release(record, None)

    async def _changed(self, asking: Asking, record: Pending) -> bool:
        """B.5: the view is still fresh, still assigns the server and lists the tool in
        ``approve``, the client is still attended, and the tool is admitted under the same pin."""
        snapshot = self.fresh()
        if snapshot is None or not _still_allowed(snapshot.view.gateway, record.key):
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

    async def _outcome(self, record: Pending, outcome: str, detail: str | None) -> None:
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
        found = self.table.withdraw(matches, decision, self.clock())
        for record in found:
            wait = self._waits.get(record.ref)
            if wait is not None:
                wait.cancel()
            elif record.era == "modern" and record.handle_sha256 is None:
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
        """After a policy change: prompts whose tool, assignment or attendance went (M3 D.3)."""
        return await self.withdraw(lambda p: not _still_allowed(gateway, p.key), "withdrawn")

    async def sweep(self) -> None:
        swept = self.table.sweep(self.clock())
        for record in swept.expired:
            await self._close(record, "timeout")
        for record in swept.freed:
            self._shown.pop(record.ref, None)
            logs.event("approval_lock_expired", ref=record.ref, level="error")

    async def sweep_forever(self) -> None:
        while True:
            await anyio.sleep(SWEEP_INTERVAL)
            await self.sweep()


# --- helpers --------------------------------------------------------------------------------------


def _client_settings(gateway: ViewGateway, client: str) -> ClientApprovals | None:
    found = gateway.clients.get(client)
    return found.approvals if found is not None else None


def _settings(gateway: ViewGateway, own: ClientApprovals, policy: ServedServer) -> Settings:
    approvals_ = gateway.approvals
    return Settings(
        timeout=float(own.timeout if own.timeout is not None else approvals_.timeout),
        call_timeout=float(policy.call_timeout or gateway.limits.call_timeout),
        cooldown=float(approvals_.cooldown),
        max_pending_per_client=approvals_.max_pending_per_client,
        max_prompts_per_hour=approvals_.max_prompts_per_hour,
    )


def _budget(gateway: ViewGateway, own: ClientApprovals) -> int:
    return own.budget_chars if own.budget_chars is not None else gateway.approvals.budget_chars


def _header(asking: Asking, deadline_wall: float) -> Header:
    deadline = datetime.fromtimestamp(deadline_wall, UTC)
    return Header(asking.ref, asking.client, asking.server, asking.tool, deadline)


def _still_allowed(gateway: ViewGateway, key: Key) -> bool:
    client = gateway.clients.get(key.client)
    server = gateway.servers.get(key.server)
    if client is None or server is None or key.server not in client.servers:
        return False
    if client.approvals is None or not client.approvals.attended:
        return False
    tools = getattr(server, "tools", None)
    return tools is not None and (key.tool in tools.approve or key.tool in tools.allow)


def _decide(answer: Any, code: ConfirmCode | None) -> Decision:
    if not isinstance(answer, mcp_types.ElicitResult):
        return "error"
    return approvals.decide_answer(answer.action, answer.content, code)


def _input_required(
    text: ApprovalText, schema: dict[str, Any], handle: approvals.Handle
) -> mcp_types.InputRequiredResult:
    params = mcp_types.ElicitRequestFormParams(message=text.value, requested_schema=schema)
    return mcp_types.InputRequiredResult(
        input_requests={approvals.INPUT_KEY: mcp_types.ElicitRequest(params=params)},
        request_state=handle.reveal(),
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
