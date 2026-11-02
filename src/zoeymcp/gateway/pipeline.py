"""The ``tools/call`` pipeline (M3 design E.6).

1. **Admit** on the client's upstream connection: an unknown, unincluded, unpinned, invalid,
   drifted, marked or blocked tool gets the same ``-32602`` "Unknown tool", which doesn't echo
   the name.
2. **Shape** the arguments: missing means ``{}``; within ``max_argument_bytes`` and 32 levels.
3. **Canonicalize** them, so the object validated is the object sent.
4. **Validate** against the pinned schema. The answer names the agent's own key and the
   keyword, never a value.
5. **Decide** from policy, never annotations (:func:`.routing.decide`): ``allow`` continues;
   ``approve`` goes to the approval decision point (:mod:`.approve`), which asks the human (on
   the agent's session, or for an ``out_of_band`` client relayed to the operator's approvers,
   M8 design E.4) and runs the accepted call itself; a ``vault_approval`` tool goes to the
   vault marked (:mod:`.elsewhere`), which holds it and asks the operator's approvers (C.2); a
   call nobody can approve, and anything unclassified, is refused. When the vault says it holds
   the tool no longer (``view_stale``), the view is fetched at once and the call decided once more
   (C.3): asked here if the tool left ``vault_approval``, else refused.
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
from . import elsewhere, logs, routing, schemas
from .approve import Approvals, Asking, AskSession, Tick
from .approvers import NO_APPROVALS as NO_APPROVALS
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
TOOLKIT_UNAVAILABLE = "toolkit unavailable"
REVOKED = (
    "refused: this client's access to the server changed while the call ran; "
    "it may or may not have run"
)
# M8 design C.1's texts for a vault_approval tool (G-9), so the agent and the operator can tell
# which setting is missing.
NO_OUT_OF_BAND = (
    "refused: this tool is approved out of band, and this client isn't allowed to raise "
    "out-of-band prompts"
)
NO_APPROVER = "refused: no out-of-band approver is configured for this call"
HEADER_PARAMS = (
    "refused: this tool sends parameters as headers, which a call the vault approves can't carry"
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
    tick: Tick | None = None  # progress while a held call blocks (M8 design F.1)


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
    if isinstance(source, ToolkitSource):
        # A toolkit's own checks, which a JSON schema can't express: the text rules (G.2).
        problem = source.argument_problem(call.server, name, shaped)
        if problem is not None:
            logs.event(
                "schema_refused", server=call.server, tool=name, keyword=problem.rule, ref=ref
            )
            log("refused", "arguments")
            return refused(f"arguments refused: at {problem}")
    # 5. Decide, from policy only
    route = _route(source, call, name, exposed, approval)
    if isinstance(route, routing.Elsewhere) and approval is not None:
        held = await _elsewhere(source, call, name, shaped, exposed, ref, route, approval, budget)
        if not isinstance(held, elsewhere.Stale):
            log("tool_error" if held.is_error else "ok", "elsewhere")
            return held
        return await _restale(source, call, name, shaped, exposed, ref, progress, approval, log)
    if isinstance(route, routing.AskElicitation) and approval is not None:
        return await _approve(source, call, name, shaped, exposed, ref, progress, approval, log)
    if isinstance(route, routing.AskOutOfBand) and approval is not None:
        return await _approve(
            source, call, name, shaped, exposed, ref, progress, approval, log, relay=True
        )
    if not isinstance(route, routing.Allow):
        # The route asks only with an approval context: it names the client, or carries a handle.
        reason = route.reason if isinstance(route, routing.Refuse) else "no_approvals"
        return _refused_route(reason, call, name, ref, log)
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


def _route(
    source: ToolSource, call: Call, name: str, exposed: Any, approval: Approval | None
) -> routing.Route:
    """Step 5's decision, from the view the request started with (or the one :func:`_restale`
    fetched): the tool lists, the client, the era, MRTR input, whether an out-of-band approver
    is configured and whether the pinned schema mirrors parameters into headers (Q27)."""
    gateway = approval.gateway if approval is not None else None
    schema = exposed.definition.get("inputSchema")
    held = name in call.policy.tools.vault_approval  # only a held tool's route reads the schema
    return routing.decide(
        tool=name,
        tools=call.policy.tools,
        client=gateway.clients.get(call.client) if gateway is not None else None,
        era=call.era,
        request_state=approval is not None and approval.request_state is not None,
        inputs=approval is not None and bool(approval.input_responses),
        out_of_band_configured=gateway is not None and gateway.approvals.out_of_band is not None,
        header_params=held and isinstance(schema, dict) and bool(schemas.mcp_headers(schema)),
        toolkit=isinstance(source, ToolkitSource),
    )


async def _elsewhere(
    source: ToolSource,
    call: Call,
    name: str,
    shaped: dict[str, Any],
    exposed: Any,
    ref: str,
    route: routing.Elsewhere,
    approval: Approval,
    budget: schemas.Budget,
) -> CallToolResult | elsewhere.Stale:
    """Step 5 for a ``vault_approval`` tool (M8 design C.2): forwarded marked, under the pin it
    was validated under; an approved answer is finished as a direct call's (step 7)."""

    async def forward(held: Any, grant: Grant) -> CallToolResult:
        return await source.forward(
            call.client,
            call.server,
            call.policy,
            name,
            grant.args,
            pin=exposed.pin,
            grant=grant,
            ref=ref,
            held=held,
        )

    prepare = None
    if isinstance(source, ToolkitSource):
        toolkits = source

        async def prepare() -> Plan | CallToolResult | None:
            return await toolkits.prepare(call.client, call.server, name, shaped, ref)

    return await elsewhere.run(
        approval.approvals,
        elsewhere.HeldCall(
            ref=ref,
            client=call.client,
            server=call.server,
            tool=name,
            era=call.era,
            policy=call.policy,
            gateway=approval.gateway,
            args=shaped,
            pin=exposed.pin,
            wait=route.wait,
            forward=forward,
            finish=lambda raw: _sanitized(raw, call, name, exposed, ref, budget),
            prepare=prepare,
            tick=approval.tick,
        ),
    )


async def _restale(
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
    """C.3: the vault holds the tool no longer. The view is fetched at once, and the call decided
    once more on it: asked here when the tool left ``vault_approval`` for ``approve``, else
    refused ``view_stale``. It never loops."""
    refetch = approval.approvals.refetch
    snapshot = await refetch() if refetch is not None else approval.approvals.fresh()
    gateway = snapshot.view.gateway if snapshot is not None else None
    policy = gateway.servers.get(call.server) if gateway is not None else None
    if gateway is not None and policy is not None and policy.kind == call.policy.kind:
        fresh_call = Call(call.client, call.server, policy, gateway.limits, call.era)
        fresh = Approval(
            approvals=approval.approvals,
            session=approval.session,
            gateway=gateway,
            session_sha256=approval.session_sha256,
            disconnected=approval.disconnected,
            tick=approval.tick,
        )
        route = _route(source, fresh_call, name, exposed, fresh)
        if isinstance(route, routing.AskElicitation | routing.AskOutOfBand):
            relay = isinstance(route, routing.AskOutOfBand)
            return await _approve(
                source, fresh_call, name, shaped, exposed, ref, progress, fresh, log, relay=relay
            )
    result = await elsewhere.stale_refused(approval.approvals, ref, call.client, call.server, name)
    log("refused", "view_stale")
    return result


def _refused_route(
    reason: routing.RefuseReason, call: Call, name: str, ref: str, log: Any
) -> CallToolResult:
    """Step 5's refusals, each worded and logged as before the route was its own module."""
    if reason == "unexpected_input":
        log("refused", "unexpected_input")
        return refused(f"{UNEXPECTED_INPUT} (ref {ref})")
    if reason == "unexpected_state":
        # A handle is good only for the approve tool it was issued for (D.6).
        log("refused", "unexpected_state")
        return refused(STATE_REFUSED)
    if reason in ("no_approvals", "no_out_of_band", "no_approver", "header_params"):
        why = "unattended" if reason == "no_approvals" else reason
        logs.event(
            "approval_refused",
            client=call.client,
            server=call.server,
            tool=name,
            ref=ref,
            reason=why,
        )
        log("refused", why)
        return refused(f"{_ROUTE_TEXTS[reason]} (ref {ref})")
    log("refused", "unclassified")
    return refused(UNCLASSIFIED)


_ROUTE_TEXTS = {
    "no_approvals": NO_APPROVALS,
    "no_out_of_band": NO_OUT_OF_BAND,
    "no_approver": NO_APPROVER,
    "header_params": HEADER_PARAMS,
}


def finished(raw: CallToolResult, call: Call, name: str, exposed: Any, ref: str) -> CallToolResult:
    """Step 7 for a held call's result that ``check_approval`` collected (M8 design F.5 step 6):
    sanitized, checked against the tool's pinned output schema and wrapped, as a direct call's
    result is; never forwarded again."""
    return _sanitized(raw, call, name, exposed, ref, schemas.Budget.start())


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
    *,
    relay: bool = False,
) -> CallToolResult | mcp_types.InputRequiredResult:
    """Step 5 for an ``approve`` tool: the approval decision point asks, on the agent's session
    or, with ``relay``, out of band (M8 design E.4), and on ``accept`` forwards the stored
    canonical object itself, committed (M4 design B.2, B.6). A relayed call may run after its
    request answered pending, so its forward relays no upstream progress."""
    budget = schemas.Budget.start()

    async def forward(grant: Grant) -> CallToolResult:
        raw = await source.forward(
            call.client,
            call.server,
            call.policy,
            name,
            grant.args,
            pin=exposed.pin,
            progress=None if relay else progress,
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

    asking = Asking(
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
        tick=approval.tick if relay else None,
    )
    if relay:
        relayed = await approval.approvals.relay(asking)
        log("tool_error" if relayed.is_error else "ok", "relay")
        return relayed
    result = await approval.approvals.handle(asking)
    if isinstance(result, mcp_types.InputRequiredResult):
        log("input_required", "approval")
    else:
        log("tool_error" if result.is_error else "ok", "approval")
    return result
