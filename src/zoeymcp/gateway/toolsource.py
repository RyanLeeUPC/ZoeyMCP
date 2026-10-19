"""Where a server's tools come from (M3 design F.1, built in M4 step 6a; M4 design H.3).

The pipeline, ``tools/list`` and the ``Mcp-Param-*`` schema lookup reach tools only through a
:class:`ToolSource`, so approvals sit above it and work the same for every kind of server.
:class:`RemoteSource` speaks MCP to a vault path through the upstream pool; M4's
``ToolkitSource`` runs Python in process. Scoping, pins, validation, approvals and sanitizing stay
in the callers.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from mcp.types import CallToolResult

from ..common.policy.view import ViewRemoteServer, ViewToolkitServer
from .pins import Evaluation, ExposedTool
from .upstream import NotAdmitted, Progress, UpstreamPool

# The server kinds a source serves.
ServedServer = ViewRemoteServer | ViewToolkitServer


@dataclass(frozen=True, repr=False)
class Grant:
    """What an accepted approval hands the forward: the ref, and the stored arguments and plan
    the human saw."""

    ref: str
    args: dict[str, Any]
    plan: Any = None

    def __repr__(self) -> str:
        return f"Grant(ref={self.ref})"


class ToolSource(Protocol):
    async def exposed(self, client: str, server: str, policy: ServedServer) -> Evaluation:
        """The evaluated listing ``tools/list`` serves, waiting until there is one."""
        ...

    async def admit(self, client: str, server: str, policy: ServedServer, tool: str) -> ExposedTool:
        """The exposed definition a call to ``tool`` goes out under, or :class:`NotAdmitted`."""
        ...

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
        """Run the call, refusing (:class:`NotAdmitted`) if ``tool`` is no longer admitted under
        ``pin``. ``ref`` is the call's log reference (a toolkit's ``ctx.ref``)."""
        ...

    def input_schema(self, client: str, server: str, tool: str) -> dict[str, Any] | None:
        """The exposed input schema, for the SDK's ``Mcp-Param-*`` header check."""
        ...


class RemoteSource:
    """Tools from an upstream MCP server, through the vault, on the pool's connections."""

    def __init__(self, pool: UpstreamPool) -> None:
        self.pool = pool

    async def exposed(self, client: str, server: str, policy: ServedServer) -> Evaluation:
        assert isinstance(policy, ViewRemoteServer)  # noqa: S101 - this source serves remotes
        connection = self.pool.connection(server, policy, client)
        return await self.pool.wait_ready(connection)

    async def admit(self, client: str, server: str, policy: ServedServer, tool: str) -> ExposedTool:
        assert isinstance(policy, ViewRemoteServer)  # noqa: S101 - this source serves remotes
        connection = self.pool.connection(server, policy, client)
        pin = await self.pool.admit(connection, tool)
        evaluation = connection.state.evaluation
        exposed = evaluation.exposed.get(tool) if evaluation is not None else None
        if exposed is None or exposed.pin != pin:
            raise NotAdmitted("tool not exposed")
        return exposed

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
        assert isinstance(policy, ViewRemoteServer)  # noqa: S101 - this source serves remotes
        # An approved call is committed (a close waits for it) and never retried (B.6).
        approved = grant is not None
        return await self.pool.call(
            server,
            policy,
            client,
            tool,
            arguments,
            pin=pin,
            progress=progress,
            committed=approved,
            retry_expired=not approved,
        )

    def input_schema(self, client: str, server: str, tool: str) -> dict[str, Any] | None:
        for connection in self.pool.connections():
            if connection.server != server or connection.key[1] not in (client, "*"):
                continue
            evaluation = connection.state.evaluation
            exposed = evaluation.exposed.get(tool) if evaluation is not None else None
            if exposed is not None:
                schema = exposed.definition.get("inputSchema")
                return dict(schema) if isinstance(schema, dict) else None
        return None
