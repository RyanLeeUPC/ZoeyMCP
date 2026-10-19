"""Tools from a toolkit, run in process (M4 design H.3).

The listing is the evaluation made when the toolkit loaded: it changes only with the image or
the policy, so there is no watcher. A call runs the tool's body under the server's
``call_timeout``, with slots bound to the call's phase (:mod:`.toolkitvault`); an approved call's
body gets the accepted plan and may send its writes once each. What the body raises becomes one of
G.7's fixed texts: an exception's message can hold argument values, so it is never shown or
logged.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import anyio
from mcp.types import CallToolResult, TextContent

from ..common.approvaltext import Plan
from ..common.policy.schema import GatewayLimits
from ..common.policy.view import ViewToolkitServer
from ..toolkit.context import PrepareContext, ToolContext
from ..toolkit.plan import SendLedger
from ..toolkit.results import failure, render
from ..toolkit.rules import Phase
from . import logs
from .pins import Evaluation, ExposedTool
from .toolkits import Loaded, Toolkits
from .toolkitvault import CallState
from .toolsource import Grant, ServedServer
from .upstream import NotAdmitted, Progress

PREPARE_TIMEOUT = 10.0


class ToolkitUnavailable(Exception):
    """The server's toolkit didn't load. ``reason`` is the loader's, never a message."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def _text(text: str, *, error: bool) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=text)], is_error=error)


class ToolkitSource:
    """Tools from the toolkits the view names."""

    def __init__(self, toolkits: Toolkits, limits: Callable[[], GatewayLimits]) -> None:
        self.toolkits = toolkits
        self.limits = limits

    def _loaded(self, server: str) -> Loaded:
        found = self.toolkits.get(server)
        if not isinstance(found, Loaded):
            raise ToolkitUnavailable(found.reason if found is not None else "not_loaded")
        return found

    async def exposed(self, client: str, server: str, policy: ServedServer) -> Evaluation:
        return self._loaded(server).evaluation

    async def admit(self, client: str, server: str, policy: ServedServer, tool: str) -> ExposedTool:
        exposed = self._loaded(server).evaluation.exposed.get(tool)
        if exposed is None:
            raise NotAdmitted("tool not exposed")
        return exposed

    def input_schema(self, client: str, server: str, tool: str) -> dict[str, Any] | None:
        found = self.toolkits.get(server)
        if not isinstance(found, Loaded):
            return None
        exposed = found.evaluation.exposed.get(tool)
        schema = exposed.definition.get("inputSchema") if exposed is not None else None
        return dict(schema) if isinstance(schema, dict) else None

    async def prepare(
        self, client: str, server: str, tool: str, arguments: dict[str, Any], ref: str
    ) -> Plan | CallToolResult | None:
        """The plan a consequential tool shows, ``None`` for a tool with no ``prepare`` step, or
        the failure the agent reads (G.3, G.7)."""
        loaded = self._loaded(server)
        spec = loaded.toolkit.tools[tool]
        if spec.prepare is None:
            return None
        state = CallState(tool, ref, "prepare", SendLedger(None))
        context = PrepareContext(client, server, ref, loaded.vault.bind(state))
        try:
            with anyio.fail_after(PREPARE_TIMEOUT):
                plan = await spec.prepare(context, **arguments)
            if not isinstance(plan, Plan):
                raise TypeError("prepare returns a Plan")
        except Exception as exc:  # G.7: a fixed text, never the message
            return self._failed(exc, server, tool, ref)
        finally:
            state.close()
        return plan

    async def forward(
        self,
        client: str,
        server: str,
        policy: ServedServer,
        tool: str,
        arguments: dict[str, Any],
        *,
        pin: str,
        progress: Progress | None = None,
        grant: Grant | None = None,
        ref: str | None = None,
    ) -> CallToolResult:
        loaded = self._loaded(server)
        exposed = loaded.evaluation.exposed.get(tool)
        if exposed is None or exposed.pin != pin:
            raise NotAdmitted("pin changed")
        spec = loaded.toolkit.tools[tool]
        call_ref = grant.ref if grant is not None else (ref or "-")
        plan = grant.plan if grant is not None and isinstance(grant.plan, Plan) else None
        phase: Phase = "approve" if grant is not None else "allow"
        state = CallState(tool, call_ref, phase, SendLedger(plan))

        async def report(done: int, total: int) -> None:
            if progress is not None:
                await progress(float(done), float(total))

        context = ToolContext(
            client,
            server,
            call_ref,
            plan,
            loaded.vault.bind(state),
            reporter=report if progress is not None else None,
        )
        assert isinstance(policy, ViewToolkitServer)  # noqa: S101 - this source serves toolkits
        timeout = policy.call_timeout or self.limits().call_timeout
        try:
            with anyio.fail_after(timeout):
                value = await spec.fn(context, **arguments)
            return _text(render(value), error=False)
        except Exception as exc:  # G.7: a fixed text, never the message
            return self._failed(exc, server, tool, call_ref)
        finally:
            state.close()

    @staticmethod
    def _failed(exc: BaseException, server: str, tool: str, ref: str) -> CallToolResult:
        found = failure(exc, ref)
        logs.event(found.event, server=server, tool=tool, ref=ref, **found.fields)
        return _text(found.text, error=True)
