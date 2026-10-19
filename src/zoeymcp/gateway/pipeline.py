"""The ``tools/call`` pipeline (M3 design E.6).

1. **Admit** on the client's upstream connection: an unknown, unincluded, unpinned, invalid,
   drifted, marked or blocked tool gets the same ``-32602`` "Unknown tool", which doesn't echo
   the name.
2. **Shape** the arguments: missing means ``{}``; within ``max_argument_bytes`` and 32 levels.
3. **Canonicalize** them, so the object validated is the object sent.
4. **Validate** against the pinned schema. The answer names the agent's own key and the
   keyword, never a value.
5. **Decide** from policy, never annotations: ``allow`` continues; ``approve`` goes to the
   approval decision point (:mod:`.approve`), which asks the human and runs the accepted call
   itself; anything unclassified is refused.
6. **Call** with the validated object, registered with the egress filter, under the pin it was
   validated under. A policy change that takes the client's access to the server away stops the
   call (M3 design D.3), which cancels it upstream too.
7. **Sanitize** the result (J.1).

Upstream error text is never forwarded or logged: each outcome gets a fixed message with a
reference that the log line also carries.
"""

from __future__ import annotations

import secrets
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

import anyio
import mcp_types
from mcp.shared.exceptions import MCPError
from mcp.types import CallToolResult, TextContent

from ..common import canonical
from ..common.approvaltext import Plan
from ..common.policy.schema import GatewayLimits
from ..common.policy.view import ViewGateway
from . import logs, schemas
from .approve import Approvals, Asking, AskSession
from .connstate import Era
from .sanitize import map_upstream, sanitize_result
from .toolkitsource import ToolkitSource, ToolkitUnavailable
from .toolsource import Grant, ServedServer, ToolSource
from .upstream import NotAdmitted, Progress, UpstreamError

MAX_ARGUMENT_DEPTH = 32
UNKNOWN_TOOL = "Unknown tool"
UNCLASSIFIED = "refused: this tool is not classified"
UNEXPECTED_INPUT = "refused: unexpected input responses"
STATE_REFUSED = "refused: approval expired or already used"
NO_APPROVALS = "refused: no approver for this client"
TOOLKIT_UNAVAILABLE = "toolkit unavailable"
REVOKED = (
    "refused: this client's access to the server changed while the call ran; "
    "it may or may not have run"
)


class InFlight:
    """Requests in flight per (client, server), so a policy change can stop them."""

    def __init__(self) -> None:
        self._scopes: dict[tuple[str, str], set[anyio.CancelScope]] = {}

    @contextmanager
    def track(self, client: str, server: str) -> Iterator[anyio.CancelScope]:
        """A cancel scope that :meth:`stop` cancels; enter and leave it in one task."""
        key = (client, server)
        scope = anyio.CancelScope()
        self._scopes.setdefault(key, set()).add(scope)
        try:
            with scope:
                yield scope
        finally:
            held = self._scopes.get(key, set())
            held.discard(scope)
            if not held:
                self._scopes.pop(key, None)

    def stop(self, client: str, server: str) -> int:
        """Cancel every request in flight for the pair. Returns how many there were."""
        scopes = self._scopes.pop((client, server), set())
        for scope in scopes:
            scope.cancel()
        return len(scopes)


@dataclass
class Approval:
    """What an ``approve`` call needs besides the call itself (M4 design B, D)."""

    approvals: Approvals
    session: AskSession
    gateway: ViewGateway  # the view the request started with
    request_state: object = None
    input_responses: Mapping[str, Any] | None = None
    session_sha256: str | None = None
    disconnected: anyio.Event | None = None


@dataclass(frozen=True)
class Call:
    """Who is calling what, from the request's admission."""

    client: str
    server: str
    policy: ServedServer
    limits: GatewayLimits
    era: Era  # the agent's


def new_ref() -> str:
    """8 random bytes in hex: in the agent's answer and in the log line, nothing else."""
    return secrets.token_hex(8)


def refused(text: str) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=text)], is_error=True)


def _shape(arguments: Any, limits: GatewayLimits) -> dict[str, Any] | str:
    """The canonical arguments, or why they're refused."""
    value = {} if arguments is None else arguments
    if not isinstance(value, dict):
        return "arguments refused: not an object"
    try:
        data = canonical.dumps_canonical(value)
    except canonical.JSONRejected:
        return "arguments refused: not plain JSON"
    if len(data) > limits.max_argument_bytes or schemas.depth(value) > MAX_ARGUMENT_DEPTH:
        return "arguments refused: too large"
    shaped: dict[str, Any] = canonical.loads_strict(data, max_bytes=len(data) + 1)
    return shaped


async def call_tool(
    source: ToolSource,
    call: Call,
    name: str,
    arguments: Any,
    *,
    progress: Progress | None = None,
    in_flight: InFlight | None = None,
    approval: Approval | None = None,
) -> CallToolResult | mcp_types.InputRequiredResult:
    started = time.monotonic()
    ref = new_ref()
    args_bytes = 0

    def log(outcome: str, reason: str | None = None, **fields: Any) -> None:
        logs.event(
            "request",
            client=call.client,
            server=call.server,
            rpc="tools/call",
            tool=name,
            era=call.era,
            outcome=outcome,
            reason=reason,
            ref=ref,
            args_bytes=args_bytes,
            duration_ms=round((time.monotonic() - started) * 1000, 1),
            **fields,
        )

    # 1. Admit
    try:
        exposed = await source.admit(call.client, call.server, call.policy, name)
        pin = exposed.pin
    except NotAdmitted as exc:
        log("refused", exc.reason)
        raise MCPError(mcp_types.INVALID_PARAMS, UNKNOWN_TOOL) from exc
    except UpstreamError as exc:
        log("upstream_error", exc.detail or exc.outcome)
        return map_upstream(exc.outcome, ref)
    except ToolkitUnavailable as exc:
        log("toolkit_unavailable", exc.reason)
        return refused(f"{TOOLKIT_UNAVAILABLE} (ref {ref})")
    # 2, 3. Shape and canonicalize
    shaped = _shape(arguments, call.limits)
    if isinstance(shaped, str):
        log("refused", "arguments")
        return refused(shaped)
    args_bytes = len(canonical.dumps_canonical(shaped))
    # 4. Validate against the pinned schema
    budget = schemas.Budget.start()
    try:
        validator = schemas.validator_for(pin, "input", exposed.definition["inputSchema"])
        errors = validator.errors(shaped, budget)
    except schemas.SchemaRefused as exc:
        logs.event("schema_refused", server=call.server, tool=name, keyword=exc.code, ref=ref)
        log("refused", exc.code)
        return refused("arguments refused: the schema check didn't finish")
    if errors:
        keyword = errors[0].rpartition(": ")[2]
        logs.event("schema_refused", server=call.server, tool=name, keyword=keyword, ref=ref)
        log("refused", "schema")
        return refused(f"arguments refused: at {errors[0]}")
    # 5. Decide, from policy only
    request_state = approval.request_state if approval is not None else None
    inputs = approval.input_responses if approval is not None else None
    if call.era == "legacy" and (request_state is not None or inputs):
        log("refused", "unexpected_input")
        return refused(f"{UNEXPECTED_INPUT} (ref {ref})")
    if name in call.policy.tools.approve:
        if approval is None:
            log("refused", "unattended")
            return refused(f"{NO_APPROVALS} (ref {ref})")
        return await _approve(source, call, name, shaped, exposed, ref, progress, approval, log)
    if request_state is not None:
        # A handle is good only for the approve tool it was issued for (D.6).
        log("refused", "unexpected_state")
        return refused(STATE_REFUSED)
    if name not in call.policy.tools.allow:
        log("refused", "unclassified")
        return refused(UNCLASSIFIED)
    # 6. Call
    with (in_flight or InFlight()).track(call.client, call.server) as scope:
        try:
            raw = await source.forward(
                call.client,
                call.server,
                call.policy,
                name,
                shaped,
                pin=pin,
                progress=progress,
                ref=ref,
            )
        except NotAdmitted as exc:
            log("upstream_error", exc.reason)
            return map_upstream("unavailable", ref)
        except UpstreamError as exc:
            log("timeout" if exc.outcome == "timeout" else "upstream_error", exc.outcome)
            return map_upstream(exc.outcome, ref)
        except ToolkitUnavailable as exc:
            log("toolkit_unavailable", exc.reason)
            return refused(f"{TOOLKIT_UNAVAILABLE} (ref {ref})")
    if scope.cancelled_caught:
        log("cancelled", "revoked")
        return refused(f"{REVOKED} (ref {ref})")
    # 7. Sanitize
    result = _sanitized(raw, call, name, exposed, ref, budget)
    result_bytes = sum(len(getattr(block, "text", "")) for block in result.content)
    log("tool_error" if result.is_error else "ok", result_bytes=result_bytes)
    return result


def _sanitized(
    raw: CallToolResult,
    call: Call,
    name: str,
    exposed: Any,
    ref: str,
    budget: schemas.Budget,
) -> CallToolResult:
    """Step 7: the result rebuilt, checked against the pinned output schema, and wrapped."""
    pin = exposed.pin
    output_schema = exposed.definition.get("outputSchema")
    output_check = None
    if isinstance(output_schema, dict):
        output_validator = schemas.validator_for(pin, "output", output_schema)

        def output_check(value: Any) -> list[str]:
            try:
                return output_validator.errors(value, budget)
            except schemas.SchemaRefused as exc:
                return [exc.code]

    result, stats = sanitize_result(
        raw,
        server=call.server,
        era=call.era,
        max_result_bytes=call.limits.max_result_bytes,
        wrap_results=call.policy.wrap_results,
        nonce=secrets.token_hex(8),
        ref=ref,
        output_check=output_check,
    )
    logs.event(
        "result_sanitized",
        server=call.server,
        tool=name,
        revealed=stats.revealed,
        dropped_blocks=stats.dropped_blocks,
        wrapped=stats.wrapped,
        ref=ref,
    )
    if call.era == "modern":
        result.result_type = "complete"
    return result


async def _approve(
    source: ToolSource,
    call: Call,
    name: str,
    shaped: dict[str, Any],
    exposed: Any,
    ref: str,
    progress: Progress | None,
    approval: Approval,
    log: Any,
) -> CallToolResult | mcp_types.InputRequiredResult:
    """Step 5 for an ``approve`` tool: the approval decision point asks, and on ``accept``
    forwards the stored canonical object itself, committed (M4 design B.2, B.6)."""
    budget = schemas.Budget.start()

    async def forward(grant: Grant) -> CallToolResult:
        raw = await source.forward(
            call.client,
            call.server,
            call.policy,
            name,
            grant.args,
            pin=exposed.pin,
            progress=progress,
            grant=grant,
            ref=ref,
        )
        return _sanitized(raw, call, name, exposed, ref, budget)

    async def admit() -> str:
        return (await source.admit(call.client, call.server, call.policy, name)).pin

    prepare = None
    if isinstance(source, ToolkitSource):
        toolkits = source

        async def prepare() -> Plan | CallToolResult | None:
            return await toolkits.prepare(call.client, call.server, name, shaped, ref)

    result = await approval.approvals.handle(
        Asking(
            ref=ref,
            client=call.client,
            server=call.server,
            tool=name,
            era=call.era,
            policy=call.policy,
            gateway=approval.gateway,
            args=shaped,
            pin=exposed.pin,
            session=approval.session,
            forward=forward,
            admit=admit,
            request_state=approval.request_state,
            input_responses=approval.input_responses,
            session_sha256=approval.session_sha256,
            disconnected=approval.disconnected,
            prepare=prepare,
        )
    )
    if isinstance(result, mcp_types.InputRequiredResult):
        log("input_required", "approval")
    else:
        log("tool_error" if result.is_error else "ok", "approval")
    return result
