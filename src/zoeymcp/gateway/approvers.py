"""The asking side of an approval: how a recorded call is put to a human (M8 design D.1, C.5).

:mod:`.approve` keeps the orchestration (the gate, the lock, the ledger, the committed forward);
a transport here only asks and says what was decided. The two transports of M4:

- :class:`ElicitationLegacy`: ``elicitation/create`` on the call's own stream (M4 design D.2,
  D.4), raced against the stream's loss and a withdrawal. It is an :class:`Approver`: the answer
  comes back within the call.
- :class:`ElicitationModern`: an ``InputRequiredResult`` whose ``requestState`` is a single-use
  handle, and the retry that answers it (D.6), so its decision comes back on a later request.

Both share the process's one table and two maps :class:`.approve.Approvals` keeps: what each
waiting prompt showed, and the cancel scope of each legacy wait. The texts the agent sees for a
decision live here, with the transports that produce most of them.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol

import anyio
import mcp_types
import pydantic
from mcp.shared.exceptions import MCPError, NoBackChannelError
from mcp.types import CallToolResult, TextContent

from ..common import canonical
from ..common.approvaltext import ApprovalText
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


def refused(text: str) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=text)], is_error=True)


def with_ref(text: str, ref: str) -> CallToolResult:
    return refused(f"{text} (ref {ref})")


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


# A decision that doesn't run the call, ledgered and its lock freed (Approvals._close); and why a
# client can't be asked on this request, or None (Approvals._gate, which logs the refusal).
Close = Callable[[Pending, Decision], Awaitable[None]]
Gate = Callable[["Asking"], CallToolResult | None]


class Approver(Protocol):
    """A transport that puts one recorded call to a human and answers within the call (D.1).
    The out-of-band transport (M8 step 12b) widens the answer with ``Pended``."""

    async def ask(self, asking: Asking, record: Pending, shown: Shown) -> Decided: ...


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
