"""The ``tools/call`` pipeline reaches tools only through a ``ToolSource`` (M4 step 6a)."""

from __future__ import annotations

from typing import Any

import mcp_types
import pytest
from mcp.shared.exceptions import MCPError
from mcp.types import CallToolResult, TextContent

from zoeymcp.common.policy.schema import GatewayLimits
from zoeymcp.common.policy.view import ViewRemoteServer
from zoeymcp.gateway import pipeline
from zoeymcp.gateway.pins import Evaluation, ExposedTool
from zoeymcp.gateway.toolsource import Grant
from zoeymcp.gateway.upstream import NotAdmitted, Progress

pytestmark = pytest.mark.anyio

PIN = "sha256:" + "1" * 64
DEFINITION = {
    "name": "add",
    "description": "Add two numbers.",
    "inputSchema": {
        "type": "object",
        "properties": {"a": {"type": "number"}, "b": {"type": "number"}},
        "required": ["a", "b"],
        "additionalProperties": False,
    },
}


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def policy(allow: list[str], approve: list[str] | None = None) -> ViewRemoteServer:
    return ViewRemoteServer.model_validate(
        {
            "kind": "remote",
            "vault_path": "/notes/mcp",
            "tools": {"include": allow + (approve or []), "allow": allow, "approve": approve or []},
            "review": dict.fromkeys(allow + (approve or []), PIN),
            "on_drift": "hide",
            "shared_session": False,
            "wrap_results": False,
            "enable": [],
            "era": "modern",
            "drift_check_interval": 300,
            "call_timeout": None,
        }
    )


class FakeSource:
    """A source with one tool, recording what reached it."""

    def __init__(self, *, refuse_admit: bool = False, refuse_forward: bool = False) -> None:
        self.refuse_admit = refuse_admit
        self.refuse_forward = refuse_forward
        self.forwarded: list[tuple[str, str, str, dict[str, Any], str, Grant | None]] = []

    async def exposed(self, client: str, server: str, policy: ViewRemoteServer) -> Evaluation:
        return Evaluation(exposed={"add": ExposedTool(DEFINITION, PIN)})  # type: ignore[call-arg]

    async def admit(
        self, client: str, server: str, policy: ViewRemoteServer, tool: str
    ) -> ExposedTool:
        if self.refuse_admit or tool != "add":
            raise NotAdmitted("not exposed")
        return ExposedTool(DEFINITION, PIN)

    async def forward(
        self,
        client: str,
        server: str,
        policy: ViewRemoteServer,
        tool: str,
        arguments: dict[str, Any],
        *,
        pin: str,
        progress: Progress | None = None,
        grant: Grant | None = None,
    ) -> CallToolResult:
        if self.refuse_forward:
            raise NotAdmitted("pin changed after validation")
        self.forwarded.append((client, server, tool, arguments, pin, grant))
        return CallToolResult(content=[TextContent(type="text", text="3")])

    def input_schema(self, client: str, server: str, tool: str) -> dict[str, Any] | None:
        return dict(DEFINITION["inputSchema"])  # type: ignore[arg-type]


def call_for(server_policy: ViewRemoteServer) -> pipeline.Call:
    return pipeline.Call("agent1", "notes", server_policy, GatewayLimits(), "modern")


def text(result: CallToolResult) -> str:
    block = result.content[0]
    assert isinstance(block, TextContent)
    return block.text


async def test_an_allowed_call_goes_through_the_source() -> None:
    source = FakeSource()
    result = await pipeline.call_tool(source, call_for(policy(["add"])), "add", {"b": 2, "a": 1})
    assert text(result) == "3"
    assert source.forwarded == [("agent1", "notes", "add", {"a": 1, "b": 2}, PIN, None)]


async def test_an_unexposed_tool_is_unknown() -> None:
    for source, name in ((FakeSource(refuse_admit=True), "add"), (FakeSource(), "other")):
        with pytest.raises(MCPError) as raised:
            await pipeline.call_tool(source, call_for(policy(["add"])), name, {})
        assert raised.value.error.code == mcp_types.INVALID_PARAMS
        assert raised.value.error.message == pipeline.UNKNOWN_TOOL
        assert source.forwarded == []


async def test_invalid_arguments_never_reach_the_source() -> None:
    source = FakeSource()
    result = await pipeline.call_tool(source, call_for(policy(["add"])), "add", {"a": "x", "b": 1})
    assert result.is_error
    assert source.forwarded == []


async def test_an_approve_tool_is_still_refused_in_this_step() -> None:
    source = FakeSource()
    result = await pipeline.call_tool(
        source, call_for(policy([], ["add"])), "add", {"a": 1, "b": 2}
    )
    assert result.is_error
    assert text(result) == pipeline.APPROVAL_UNAVAILABLE
    assert source.forwarded == []


async def test_a_refusal_from_the_forward_is_an_upstream_error() -> None:
    source = FakeSource(refuse_forward=True)
    result = await pipeline.call_tool(source, call_for(policy(["add"])), "add", {"a": 1, "b": 2})
    assert result.is_error
    assert "ref " in text(result)
