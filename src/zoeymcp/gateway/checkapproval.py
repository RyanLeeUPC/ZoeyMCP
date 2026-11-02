"""``check_approval``: the one tool the gateway makes itself (M8 design F; Q10 (a), Q46 (a); R33's
exception, Z17, Z18). I/O.

A call the vault holds past ``approvers.block_seconds`` answers ``pending <ref>`` (F.1), and runs
as soon as it is approved, whoever waits; the agent gets its result here, once.

- **Where it is served** (F.4, :func:`served`): on a server's own path only, when the server has
  an ``approve`` tool, to a client that may be asked out of band there (``out_of_band``, or
  ``attended`` while the server has a ``vault_approval`` tool), while the view says an
  out-of-band approver is configured. Both eras see the same definition; it is never pinned,
  reviewed, drift-checked or counted, and needs no approval, since it reads.
- **Delivery** (F.5): a ref of a call this gateway asked for another client, or on another
  server, answers ``unknown or expired``; any other ref is collected from the vault for the
  calling client, on this server (``approvals/collect``), which answers only for the client it
  held the call for, so another client's ref reads as an unknown one (T34), and a restarted
  gateway still collects a call it no longer knows. The result is read by
  :mod:`~zoeymcp.common.heldresult` (exactly one response, to the held request) and finished as
  a direct call's is (:func:`.pipeline.finished`: sanitized, the tool's pinned output schema,
  wrapped); a status answers a tool error that says what it is.
- **Endings.** A call's ending the collect shows closes this gateway's pending record of it as
  the vault decided (:func:`.elsewhere.collected`), freeing its lock (D.2).
- **No id** (Q46): the client's own calls on this server, by ref, tool, status and deadline;
  never a result or a text.
"""

from __future__ import annotations

import base64
import binascii
import math
import re
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

import httpx2
from mcp.types import CallToolResult, TextContent
from pydantic import ValidationError

from ..common import canonical, heldresult, ledgerformat
from ..common.policy.view import ViewGateway, ViewOutOfBand
from . import elsewhere, logs, pipeline
from .approve import Approvals
from .approvers import with_ref
from .pins import ExposedTool
from .sanitize import map_upstream
from .toolsource import ServedServer
from .vaultlink import COLLECT_PATH, ResponseTooLarge, UpstreamBlocked, UpstreamRedirect

NAME: Final = "check_approval"
DEFINITION: Final[Mapping[str, Any]] = {
    "name": NAME,
    "title": "Check an approval",
    "description": (
        "Gets the result of a call that answered 'pending <id>'. The result is kept for {ttl} "
        "minutes after the call runs and is given once."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {"id": {"type": "string", "pattern": "^[0-9a-f]{16}$"}},
        "additionalProperties": False,  # Q46: no id lists this client's own calls
    },
    "annotations": {"readOnlyHint": True},
}
_REF: Final = re.compile(r"[0-9a-f]{16}")

ARGUMENTS: Final = 'arguments refused: check_approval takes {"id": "<16 hex digits>"}, or nothing'
UNKNOWN: Final = "unknown or expired"
UNREACHABLE: Final = "refused: the vault couldn't be asked about this call; try again shortly"
RUNNING: Final = "approved: the call is running; call check_approval again shortly"
DECLINED: Final = "declined: the operator declined this call; nothing was sent"
EXPIRED: Final = "expired: no answer before the deadline; nothing was sent"
COLLECTED: Final = "already collected"
NOT_KEPT: Final = "the call ran, but its result wasn't kept; see the Ledger"
RESTART_NOT_SENT: Final = "ended when the vault restarted; nothing was sent"
RESTART_LOST: Final = (
    "the call was sent, but its result was lost when the vault restarted; see the Ledger"
)
NONE_LISTED: Final = "No call of yours on this server waits for an approval or to be collected."
# A withdrawal's reason, as the vault's ending records it (F.5 step 7).
WITHDRAWN: Final[Mapping[str, str]] = {
    "changed": "the policy changed",
    "shutdown": "the vault stopped",
    "restart": "the vault restarted",
    "stream_lost": "the call was cancelled",
    "caller_cancelled": "the call was cancelled",
}
_STATES: Final = frozenset(
    {"pending", "approved", "forwarding", "done", "denied", "expired", "withdrawn"}
)

# The definition of a tool by its pin, for the result's output schema: None if it is gone.
Definitions = Callable[[str, str], Awaitable[Mapping[str, Any] | None]]


def definition(out: ViewOutOfBand) -> dict[str, Any]:
    """The tool as listed, with the view's ``result_ttl`` in its description (F.3)."""
    minutes = max(1, math.ceil(out.result_ttl / 60))
    found = dict(DEFINITION)
    found["description"] = str(DEFINITION["description"]).format(ttl=minutes)
    return found


def served(gateway: ViewGateway, client: str, policy: ServedServer) -> bool:
    """F.4: whether this server's path serves ``check_approval`` to ``client``."""
    if gateway.approvals.out_of_band is None or not policy.tools.approve:
        return False
    found = gateway.clients.get(client)
    own = found.approvals if found is not None else None
    if own is None:
        return False
    return own.out_of_band or (own.attended and bool(policy.tools.vault_approval))


def _text(text: str, *, error: bool = True) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=text)], is_error=error)


def _when(deadline: object) -> str | None:
    """A vault deadline (ISO 8601, UTC) as the pending answer shows one."""
    if not isinstance(deadline, str):
        return None
    try:
        return datetime.fromisoformat(deadline).astimezone(UTC).strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return None


@dataclass
class Checker:
    """``check_approval`` for one gateway: its table and ledger (:class:`.approve.Approvals`),
    its client of the vault's approvals paths, and the pinned definitions of tools."""

    approvals: Approvals
    http: httpx2.AsyncClient
    definitions: Definitions

    async def check(
        self, call: pipeline.Call, gateway: ViewGateway, arguments: object
    ) -> CallToolResult:
        started = time.monotonic()
        ref: str | None = None

        def log(outcome: str, reason: str | None = None) -> None:
            logs.event(
                "request",
                client=call.client,
                server=call.server,
                rpc="tools/call",
                tool=NAME,
                era=call.era,
                outcome=outcome,
                reason=reason,
                ref=ref,
                duration_ms=round((time.monotonic() - started) * 1000, 1),
            )

        given = {} if arguments is None else arguments
        if not isinstance(given, dict) or not set(given) <= {"id"}:
            log("refused", "arguments")
            return _text(ARGUMENTS)
        asked = given.get("id")
        if asked is not None and not (isinstance(asked, str) and _REF.fullmatch(asked)):
            log("refused", "arguments")  # the id the agent sent is never logged
            return _text(ARGUMENTS)
        ref = asked
        if ref is None:
            answer = await self._collect(call, None)
            log("ok" if answer is not None else "upstream_error", "listed")
            return _listed(answer) if answer is not None else _text(UNREACHABLE)
        record = self.approvals.table.get(ref)
        if record is not None and (
            (record.key.client, record.key.server) != (call.client, call.server)
            or record.how != "elsewhere"
        ):
            log("refused", "unknown")  # another client's, or a prompt this gateway asks itself
            return with_ref(UNKNOWN, ref)
        answer = await self._collect(call, ref)
        if answer is None:
            log("upstream_error", "vault")
            return with_ref(UNREACHABLE, ref)
        result, reason = await self._answer(call, gateway, ref, answer, record)
        log("tool_error" if result.is_error else "ok", reason)
        return result

    async def _collect(self, call: pipeline.Call, ref: str | None) -> dict[str, Any] | None:
        """The vault's collect answer for the calling client on this server (E.2), or None
        when the vault couldn't be asked."""
        body: dict[str, str] = {
            "epoch": self.approvals.epoch,
            "client": call.client,
            "server": call.server,
        }
        if ref is not None:
            body["ref"] = ref
        try:
            response = await self.http.post(
                COLLECT_PATH,
                content=canonical.dumps_canonical(body),
                headers={"content-type": "application/json"},
            )
            data = response.content
        except (
            httpx2.HTTPError,
            OSError,
            UpstreamBlocked,  # the approvals client's own transport: its paths only (E.3),
            UpstreamRedirect,  # never a redirect,
            ResponseTooLarge,  # and an answer within its bound
        ) as exc:
            logs.event("approval_collect_failed", ref=ref, error_type=type(exc).__name__)
            return None
        if response.status_code != 200:
            logs.event("approval_collect_failed", ref=ref, status=response.status_code)
            return None
        try:
            found = canonical.loads_strict(data, max_bytes=len(data) + 1)
        except canonical.JSONRejected:
            found = None
        if not isinstance(found, dict) or found.get("v") != 1:
            logs.event("approval_collect_failed", ref=ref, error_type="answer")
            return None
        return found

    async def _answer(
        self,
        call: pipeline.Call,
        gateway: ViewGateway,
        ref: str,
        answer: Mapping[str, Any],
        record: Any,
    ) -> tuple[CallToolResult, str]:
        """The agent's answer for one call's collect, and the log's reason; an ending closes
        this gateway's record of it."""
        state = answer.get("state")
        if answer.get("ref") != ref or state not in _STATES:
            return with_ref(UNKNOWN, ref), "unknown"
        cooldown = float(gateway.approvals.cooldown)
        detail = answer.get("detail")
        outcome = answer.get("outcome")
        outcome = outcome if outcome in ledgerformat.OUTCOMES else "unknown"
        if state == "pending":
            when = _when(answer.get("deadline"))
            until = f" until {when} UTC" if when is not None else ""
            text = f"still pending: waiting for the operator's approval{until}"
            return with_ref(text, ref), "pending"
        if state in ("approved", "forwarding"):
            return with_ref(RUNNING, ref), "running"
        if state == "denied":
            await elsewhere.collected(self.approvals, ref, "decline", "not_sent", None, cooldown)
            return with_ref(DECLINED, ref), "declined"
        if state == "expired":
            await elsewhere.collected(self.approvals, ref, "timeout", "not_sent", None, cooldown)
            return with_ref(EXPIRED, ref), "expired"
        if state == "withdrawn":
            reason = detail if isinstance(detail, str) else None
            await elsewhere.collected(self.approvals, ref, "withdrawn", "not_sent", reason, 0.0)
            if answer.get("restarted") is True and reason == "restart":
                return with_ref(RESTART_NOT_SENT, ref), "restarted"
            said = WITHDRAWN.get(reason or "", "it was withdrawn")
            return with_ref(f"withdrawn: {said}; nothing was sent", ref), "withdrawn"
        # Done: it ran.
        if answer.get("restarted") is True:
            # The chain's ending names the outcome of a call that finished before the restart.
            known = isinstance(detail, str) and detail in ledgerformat.OUTCOMES
            ended, why = (str(detail), None) if known else ("unknown", "restart")
            await elsewhere.collected(self.approvals, ref, "approved_elsewhere", ended, why, 0.0)
            # An approved call whose forward never left (the chain says not_sent) wasn't sent.
            said = RESTART_NOT_SENT if ended == "not_sent" else RESTART_LOST
            return with_ref(said, ref), "restarted"
        stored = answer.get("result")
        status = stored.get("status") if isinstance(stored, dict) else None
        if isinstance(status, int) and not 200 <= status <= 299:
            # The forward failed after the approval: the vault's own refusal, or the upstream's
            # error status, as the vault's outcome of it says (B.8).
            outcome, why, failed = elsewhere.approved_failure(outcome, ref, status)
            await elsewhere.collected(self.approvals, ref, "approved_elsewhere", outcome, why, 0.0)
            return failed, "collected"
        await elsewhere.collected(self.approvals, ref, "approved_elsewhere", outcome, None, 0.0)
        if isinstance(stored, dict):
            return await self._result(call, ref, answer, stored, record), "collected"
        if answer.get("lost") == "too_large":
            return with_ref(elsewhere.TOO_LARGE, ref), "too_large"
        if answer.get("lost") is not None:
            return with_ref(NOT_KEPT, ref), "not_kept"
        return with_ref(COLLECTED, ref), "collected_before"

    async def _result(
        self,
        call: pipeline.Call,
        ref: str,
        answer: Mapping[str, Any],
        stored: Mapping[str, Any],
        record: Any,
    ) -> CallToolResult:
        """The collected result as the agent gets it (F.5 steps 5, 6): read as the one
        response to the held request, then finished as a direct call's result."""
        status, kind, request_id = (
            stored.get("status"),
            stored.get("content_type"),
            stored.get("request_id"),
        )
        try:
            body = base64.b64decode(str(stored.get("body", "")), validate=True)
        except (binascii.Error, ValueError):
            return map_upstream("unsupported_result", ref)
        if not isinstance(status, int) or not isinstance(kind, str):
            return map_upstream("unsupported_result", ref)
        if not isinstance(request_id, str | int) or isinstance(request_id, bool):
            return map_upstream("unsupported_result", ref)
        found = heldresult.read(status, kind, [body], request_id)
        if isinstance(found, heldresult.Unread):
            if found.reason == "upstream_input_required":
                return map_upstream("input_required", ref)
            return map_upstream("unsupported_result", ref)
        if found.result is None:
            return map_upstream("rpc_error", ref)
        try:
            raw = CallToolResult.model_validate(found.result)
        except ValidationError:
            return map_upstream("unsupported_result", ref)
        if raw.result_type not in (None, "complete"):
            return map_upstream("unsupported_result", ref)
        tool = record.key.tool if record is not None else answer.get("tool")
        if not isinstance(tool, str):
            return map_upstream("output_refused", ref)
        pin = record.pin if record is not None else call.policy.review.get(tool)
        found_definition = await self.definitions(tool, pin) if pin is not None else None
        if found_definition is None or pin is None:
            # The original tool's pinned output schema can't be checked: never delivered so.
            return map_upstream("output_refused", ref)
        exposed = ExposedTool(found_definition, pin)
        return pipeline.finished(raw, call, tool, exposed, ref)


def _listed(answer: Mapping[str, Any]) -> CallToolResult:
    """Q46: the client's own calls on this server, one line each."""
    lines: list[str] = []
    calls = answer.get("calls")
    for found in calls if isinstance(calls, list) else []:
        if not isinstance(found, dict):
            continue
        ref, tool, state = found.get("ref"), found.get("tool"), found.get("state")
        if not (isinstance(ref, str) and _REF.fullmatch(ref) and isinstance(tool, str)):
            continue
        lines.append(f"{ref} ({tool}): {_listed_state(state, found)}")
    if not lines:
        return _text(NONE_LISTED, error=False)
    heading = "Calls of yours on this server that answered pending (collect each by its id):"
    return _text("\n".join([heading, *lines]), error=False)


def _listed_state(state: object, found: Mapping[str, Any]) -> str:
    if state == "pending":
        when = _when(found.get("deadline"))
        return f"waiting for approval until {when} UTC" if when else "waiting for approval"
    if state in ("approved", "forwarding"):
        return "approved, running"
    if state == "done":
        if found.get("collected") is True:
            return "collected"
        return "ran; its result wasn't kept" if found.get("lost") else "ran; collect its result"
    if state == "denied":
        return "declined"
    return str(state) if state in ("expired", "withdrawn") else "unknown"
