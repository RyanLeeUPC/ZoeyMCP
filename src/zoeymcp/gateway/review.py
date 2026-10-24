"""``zoeymcp review`` on the gateway's side (M3 design I).

The CLI asks the running gateway, over its admin socket, so the CLI never handles a key and never
runs the SDK. Each review opens a fresh connection of its own, ``(server, "review")``, lists every
page, and closes it again. Like every connection, it evaluates its own listing: drift it sees
marks the tool for every client, as drift seen anywhere does (G.3, G.4).

:func:`report` turns one listing into the answer: per tool, its state, its projection and pin,
the findings, and for drift the changed members and a diff against the reviewed definition from
the definition store, and that definition itself (``reviewed``, M6 design J.1), which the vault
checks against the policy's pin. The policy block carries the server's pins and declines, and
``offered`` what the upstream advertises beyond tools, none of it served. ``clean`` is about the
included tools; ``attention`` is the attention decision for the whole listing (M6 design J.5),
which also counts a tool nobody reviewed. The upstream's ``instructions`` and ``serverInfo`` are
included for display only; they are never forwarded to an agent.

``--clear`` lists again and, only if every included tool matches its pin, clears the server's
drift marks and re-evaluates the server's live connections, so the tools come back for agents,
and the answer names them (``cleared``). Otherwise it refuses ``not_clean``, and the review it
carries names the tools that don't match (``not_clean``), so a clear job's report says either
(M6 design J.4). A connection whose own last listing still shows drift marks the tool again. A
clear asked through the vault's job path, the portal's **Clear the marks** among them, logs
``drift_cleared`` with ``by: portal``.

A toolkit server is reviewed without any upstream call (M4 design H.6): its definitions are the
ones the loaded module generates, and the answer adds the distribution, its version, and each
tool's classification as the code declares it.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence, Set
from typing import Any, Literal

import anyio
from mcp.types import Implementation, ServerCapabilities, Tool

from ..common.policy.attention import attention
from ..common.policy.schema import GatewayLimits
from ..common.policy.view import ViewRemoteServer, ViewToolkitServer
from . import logs, pins
from .connstate import WAITING, Phase
from .defstore import changed_members, diff
from .findings import tool_findings
from .toolkits import Loaded, SelfPinned
from .upstream import CLOSE_GRACE, Connection, UpstreamError

MAX_INSTRUCTIONS_CHARS = 16_384
WAIT_EXTRA = 15.0  # seconds beyond list_timeout a review waits for its listing

# ok: exposed. marked: matches its pin, hidden by a drift mark. blocked: matches its pin, hidden
# because on_drift: fail blocked the server. The rest are G.2's report kinds, declined among them.
ToolState = Literal[
    "ok", "marked", "blocked", "drift", "unreviewed", "declined", "invalid", "duplicate", "missing"
]
MATCHING: frozenset[str] = frozenset({"ok", "marked", "blocked"})
# Who cleared a server's marks, as drift_cleared logs it: the admin socket's review, or a clear
# job the vault queued (M6 design J.4).
ClearedBy = Literal["review", "portal"]
# The reason a clear is refused while an included tool doesn't match its pin; the vault maps it
# to the portal's clear_not_clean (vault/reviewjobs.py, CR-8).
NOT_CLEAN = "not_clean"


class ReviewError(Exception):
    """The review couldn't run. ``reason`` is stable; ``data`` goes into the answer as is."""

    def __init__(self, status: int, reason: str, message: str, **data: Any) -> None:
        self.status = status
        self.reason = reason
        self.data = data
        super().__init__(message)

    def answer(self) -> dict[str, Any]:
        return {"error": str(self), "reason": self.reason, **self.data}


def offered(capabilities: ServerCapabilities) -> dict[str, bool]:
    """What the upstream advertises beyond tools (fold-in 3.8), none of which the gateway serves
    until the kind is enabled."""
    return {
        "prompts": capabilities.prompts is not None,
        "resources": capabilities.resources is not None,
        "completions": capabilities.completions is not None,
        "logging": capabilities.logging is not None,
    }


def classification(policy: pins.Reviewed, tool: str) -> str | None:
    if tool in policy.tools.allow:
        return "allow"
    if tool in policy.tools.approve:
        return "approve"
    return None


def _state(
    name: str,
    evaluation: pins.Evaluation,
    reports: Sequence[pins.Report],
    pin: str | None,
    policy: pins.Reviewed,
    marked: Set[str],
) -> ToolState:
    if name in evaluation.exposed:
        return "ok"
    kinds = {report.kind for report in reports}
    kind: ToolState
    for kind in ("duplicate", "invalid", "drift", "unreviewed", "declined"):
        if kind in kinds:
            return kind
    if pin is None or policy.review.get(name) != pin:
        return "unreviewed"
    if name in marked:
        return "marked"
    return "blocked" if evaluation.blocked else "unreviewed"


def _tool_entry(
    name: str,
    tool: Tool | None,
    state: ToolState,
    policy: pins.Reviewed,
    defs: Callable[[str], Mapping[str, Any] | None],
    limits: GatewayLimits,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "name": name,
        "state": state,
        "included": name in policy.tools.include,
        "classification": classification(policy, name),
        "pin": None,
        "pinned": policy.review.get(name),
        "definition": None,
        "findings": [],
        "changed": None,
        "diff": None,
    }
    if state == "missing":
        return entry
    if state == "duplicate":
        entry["findings"] = [
            {
                "level": "error",
                "pointer": "",
                "message": "the server lists this name more than once",
            }
        ]
        return entry
    if tool is None:  # only missing and duplicate entries have no single tool
        raise ValueError(f"no tool for a {state} entry")
    try:
        projected = pins.project_and_pin(tool)
    except pins.ProjectionError as exc:
        entry["findings"] = [{"level": "error", "pointer": "", "message": str(exc)}]
        return entry
    entry["pin"] = projected.pin
    entry["definition"] = dict(projected.definition)
    entry["findings"] = [
        finding.as_dict() for finding in tool_findings(projected.definition, limits)
    ]
    pinned = entry["pinned"]
    if state == "drift" and pinned is not None:
        old = defs(pinned)
        if old is not None:
            entry["changed"] = changed_members(old, projected.definition)
            entry["diff"] = diff(old, projected.definition)
            entry["reviewed"] = dict(old)
    return entry


def report(
    server: str,
    policy: ViewRemoteServer,
    tools: Sequence[Tool],
    evaluation: pins.Evaluation,
    *,
    marks: Set[pins.Mark],
    defs: Callable[[str], Mapping[str, Any] | None],
    limits: GatewayLimits,
    era: str | None,
    protocol_version: str | None,
    server_info: Implementation | None,
    instructions: str | None,
    offered: Mapping[str, bool] | None = None,
) -> dict[str, Any]:
    """The review of one listing (pure, apart from reading the definition store). ``offered``
    goes into the answer when the handshake was seen."""
    marked = {tool for tool, _ in marks}
    by_name: dict[str, list[Tool]] = {}
    for tool in tools:
        by_name.setdefault(tool.name if isinstance(tool.name, str) else "", []).append(tool)
    entries = []
    for name in sorted(by_name):
        reports = [r for r in evaluation.reports if r.tool == name]
        listed = by_name[name]
        pin = None
        if len(listed) == 1:
            try:
                pin = pins.project_and_pin(listed[0]).pin
            except pins.ProjectionError:
                pin = None
        state = _state(name, evaluation, reports, pin, policy, marked)
        single = listed[0] if len(listed) == 1 else None
        entries.append(_tool_entry(name, single, state, policy, defs, limits))
    for name in sorted(set(policy.tools.include) - set(by_name)):
        entries.append(_tool_entry(name, None, "missing", policy, defs, limits))
    info = None
    if server_info is not None:
        info = {"name": server_info.name, "version": server_info.version}
        if server_info.title is not None:
            info["title"] = server_info.title
    if instructions is not None and len(instructions) > MAX_INSTRUCTIONS_CHARS:
        instructions = instructions[:MAX_INSTRUCTIONS_CHARS] + "..."
    included = [entry for entry in entries if entry["included"]]
    answer: dict[str, Any] = {
        "server": server,
        "kind": "remote",
        "vault_path": policy.vault_path,
        "era": era,
        "asserted_era": policy.era,
        "policy": {
            "include": list(policy.tools.include),
            "allow": list(policy.tools.allow),
            "approve": list(policy.tools.approve),
            "on_drift": policy.on_drift,
            "review": dict(policy.review),
            "declined": dict(policy.declined),
        },
        "protocol_version": protocol_version,
        "server_info": info,
        "instructions": instructions,
        "blocked": evaluation.blocked,
        "marked": sorted(marked),
        "tools": entries,
        "clean": not marked and all(entry["state"] == "ok" for entry in included),
        "attention": attention(evaluation.listed, policy, marks).as_dict(),
    }
    if offered is not None:
        answer["offered"] = dict(offered)
    return answer


# --- running a review ---------------------------------------------------------------------------


def _policy(app: Any, server: str) -> tuple[ViewRemoteServer | ViewToolkitServer, GatewayLimits]:
    snapshot = app.policy.fresh()
    if snapshot is None:
        raise ReviewError(503, "no_view", "the gateway has no fresh view of the policy")
    gateway = snapshot.view.gateway
    policy = gateway.servers.get(server)
    if policy is None:
        raise ReviewError(404, "unknown_server", f"no gateway server named {server!r}")
    return policy, gateway.limits


async def _listed(app: Any, connection: Connection, limits: GatewayLimits) -> pins.Evaluation:
    """The review connection's evaluation once listed, or :class:`ReviewError`."""
    with anyio.move_on_after(limits.list_timeout + WAIT_EXTRA):
        while connection.state.phase in WAITING:
            await connection.changed.wait()
    state = connection.state
    if state.phase is Phase.READY and state.evaluation is not None:
        return state.evaluation
    data: dict[str, Any] = {"failure": connection.failure or state.phase.value}
    message = f"the review couldn't list the server's tools ({data['failure']})"
    if connection.vault_refusal is not None:
        status, code = connection.vault_refusal
        data["vault"] = {"status": status, "code": code}
        message += f"; the vault refused with {status}" + (f" {code}" if code else "")
    raise ReviewError(502, "upstream", message, **data)


async def _close(connection: Connection) -> None:
    connection.request_close()
    with anyio.move_on_after(CLOSE_GRACE + 1, shield=True):
        await connection.done.wait()


async def review(
    app: Any, server: str, *, clear: bool = False, by: ClearedBy = "review"
) -> dict[str, Any]:
    """Review ``server`` on a fresh connection; with ``clear``, also clear its drift marks if
    every included tool matches, logged as cleared ``by``. Raises :class:`ReviewError`."""
    policy, limits = _policy(app, server)
    if isinstance(policy, ViewToolkitServer):
        return review_toolkit(app, server, policy, limits, clear=clear, by=by)
    pool = app.pool
    try:
        connection = pool.review_connection(server, policy)
    except UpstreamError as exc:
        raise ReviewError(503, "not_running", "the gateway's upstream pool isn't running") from exc
    try:
        evaluation = await _listed(app, connection, limits)
        tools = list(connection.tools)
        era = connection.era
        client = connection.client
        version = client.protocol_version if client is not None else None
        advertised = offered(client.server_capabilities) if client is not None else None
        server_info, instructions = connection.server_info, connection.instructions
    finally:
        await _close(connection)

    def build(evaluation: pins.Evaluation) -> dict[str, Any]:
        return report(
            server,
            policy,
            tools,
            evaluation,
            marks=pool.marks.for_server(server),
            defs=pool.defs.get,
            limits=limits,
            era=era,
            protocol_version=version,
            server_info=server_info,
            instructions=instructions,
            offered=advertised,
        )

    answer = build(evaluation)
    logs.event("review", server=server, tools=len(tools), clean=answer["clean"], clear=clear)
    if not clear:
        return answer
    _refuse_unless_clean(answer)
    removed = pool.marks.replace(server, frozenset())[1]
    if removed:
        logs.event("drift_cleared", server=server, tools=sorted(t for t, _ in removed), by=by)
    for live in pool.connections():
        if live.server == server:
            live.reevaluate(live.policy)
    # The review's own listing, as it evaluates with the marks gone.
    answer = build(pins.evaluate(tools, policy, pool.marks.for_server(server), limits))
    answer["cleared"] = sorted(tool for tool, _ in removed)
    return answer


def _refuse_unless_clean(answer: dict[str, Any]) -> None:
    """Refuse a clear (``not_clean``, 409) while an included tool doesn't match its pin, the
    review that found them carrying their names."""
    unmatched = [
        entry["name"]
        for entry in answer["tools"]
        if entry["included"] and entry["state"] not in MATCHING
    ]
    if unmatched:
        answer["not_clean"] = unmatched
        raise ReviewError(
            409,
            NOT_CLEAN,
            "not every included tool matches its pin: " + ", ".join(unmatched),
            tools=unmatched,
            review=answer,
        )


# --- toolkits (M4 design H.6) -------------------------------------------------------------------


def _no_reviewed_copy(pin: str) -> Mapping[str, Any] | None:
    return None


def toolkit_reviewed(policy: ViewToolkitServer, evaluation: pins.Evaluation) -> pins.Reviewed:
    """The toolkit server as its review reads it: with ``pinning: off`` every exposed tool is
    pinned to its own definition."""
    if policy.pinning == "off":
        exposed = {name: tool.pin for name, tool in evaluation.exposed.items()}
        return SelfPinned(policy.tools, exposed, declined=policy.declined)
    return policy


def toolkit_report(
    server: str,
    loaded: Loaded,
    policy: ViewToolkitServer,
    *,
    marks: Set[pins.Mark],
    limits: GatewayLimits,
) -> dict[str, Any]:
    """The review of a loaded toolkit: its own definitions, no upstream involved."""
    marked = {tool for tool, _ in marks}
    evaluation: pins.Evaluation = loaded.evaluation
    reviewed = toolkit_reviewed(policy, evaluation)
    entries = []
    for name, spec in sorted(loaded.toolkit.tools.items()):
        tool = Tool.model_validate(spec.definition())
        reports = [r for r in evaluation.reports if r.tool == name]
        try:
            pin = pins.project_and_pin(tool).pin
        except pins.ProjectionError:
            pin = None
        floor = spec.consequential and name in policy.tools.allow
        state = _state(name, evaluation, reports, pin, reviewed, marked)
        if floor and name not in evaluation.exposed and not reports:
            state = "invalid"  # hidden by the classification floor (H.2 step 7)
        entry = _tool_entry(name, tool, state, reviewed, _no_reviewed_copy, limits)
        entry["consequential"] = spec.consequential
        if floor:
            entry["findings"].append(
                {
                    "level": "error",
                    "pointer": "",
                    "message": "consequential in the toolkit's code, so it can't be in allow",
                }
            )
        entries.append(entry)
    for name in sorted(set(policy.tools.include) - set(loaded.toolkit.tools)):
        entries.append(_tool_entry(name, None, "missing", reviewed, _no_reviewed_copy, limits))
    included = [entry for entry in entries if entry["included"]]
    return {
        "server": server,
        "kind": "toolkit",
        "module": loaded.module,
        "distribution": loaded.distribution,
        "version": loaded.version,
        "pinning": policy.pinning,
        "slots": sorted(loaded.toolkit.slots),
        "policy": {
            "include": list(policy.tools.include),
            "allow": list(policy.tools.allow),
            "approve": list(policy.tools.approve),
            "on_drift": policy.on_drift,
            "review": dict(policy.review),
            "declined": dict(policy.declined),
        },
        "blocked": evaluation.blocked,
        "marked": sorted(marked),
        "tools": entries,
        "clean": not marked and all(entry["state"] == "ok" for entry in included),
        "attention": attention(evaluation.listed, reviewed, marks).as_dict(),
    }


def review_toolkit(
    app: Any,
    server: str,
    policy: ViewToolkitServer,
    limits: GatewayLimits,
    *,
    clear: bool,
    by: ClearedBy = "review",
) -> dict[str, Any]:
    """Review a toolkit server; with ``clear``, clear its drift marks if every included tool
    matches, logged as cleared ``by``, and evaluate it again. Raises :class:`ReviewError`."""
    found = app.toolkits.get(server)
    if not isinstance(found, Loaded):
        reason = found.reason if found is not None else "not_loaded"
        raise ReviewError(
            409, "toolkit_unavailable", f"the toolkit isn't loaded ({reason})", unavailable=reason
        )
    marks = app.pool.marks
    answer = toolkit_report(server, found, policy, marks=marks.for_server(server), limits=limits)
    logs.event(
        "review", server=server, tools=len(found.toolkit.tools), clean=answer["clean"], clear=clear
    )
    if not clear:
        return answer
    _refuse_unless_clean(answer)
    removed = marks.replace(server, frozenset())[1]
    if removed:
        logs.event("drift_cleared", server=server, tools=sorted(t for t, _ in removed), by=by)
    snapshot = app.policy.fresh()
    if snapshot is not None:
        app.toolkits.apply(snapshot.view.gateway)
    reloaded = app.toolkits.get(server)
    if isinstance(reloaded, Loaded):
        answer = toolkit_report(
            server, reloaded, policy, marks=marks.for_server(server), limits=limits
        )
    answer["cleared"] = sorted(tool for tool, _ in removed)
    return answer
