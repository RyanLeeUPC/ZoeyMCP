"""The agent driver does what M4's tests rely on, in every protocol version."""

from __future__ import annotations

from typing import Any

import mcp_types as types
import pytest
from mcp.server.context import ServerRequestContext
from mcp.shared.exceptions import MCPError
from mcp.shared.message import ServerMessageMetadata

from tests.fakes.agent import (
    ACCEPT,
    CANCEL,
    DECLINE,
    INPUT_KEY,
    VERSIONS,
    Answer,
    RawAgent,
    Script,
    Version,
    agent,
)
from tests.sdk.test_elicitation_contract import Asker, done, gateway_form, running

pytestmark = pytest.mark.anyio

STATE = "za1." + "B" * 43
CODE_PROMPT = "Approve?\nTo approve, accept and type this code: K7QD\nEnd"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class Approver:
    """A server that asks once per call, as the gateway does: on the call's stream for legacy, by
    ``input_required`` for modern. It answers with what it got."""

    def __init__(self, message: str = "Approve?") -> None:
        self.message = message
        self.capabilities: list[Any] = []
        self.versions: list[str] = []
        self.retries: list[types.CallToolRequestParams] = []
        self.asker = Asker(self.handle)

    async def handle(
        self, ctx: ServerRequestContext[Any], params: types.CallToolRequestParams
    ) -> Any:
        capabilities = ctx.session.client_capabilities
        self.capabilities.append(capabilities.elicitation if capabilities is not None else None)
        self.versions.append(ctx.session.protocol_version)
        if ctx.session.protocol_version.startswith("2026"):
            if params.request_state is None:
                request = types.ElicitRequest(
                    params=types.ElicitRequestFormParams(
                        message=self.message, requested_schema={"type": "object", "properties": {}}
                    )
                )
                return types.InputRequiredResult(
                    input_requests={INPUT_KEY: request}, request_state=STATE
                )
            self.retries.append(params)
            result = (params.input_responses or {}).get(INPUT_KEY)
        else:
            request = gateway_form(ctx)
            request.params.message = self.message
            try:
                result = await ctx.session.send_request(
                    request,
                    types.ElicitResult,
                    request_read_timeout_seconds=10,
                    metadata=ServerMessageMetadata(related_request_id=ctx.request_id),
                )
            except MCPError:
                return done("error")
        assert isinstance(result, types.ElicitResult)
        code = (result.content or {}).get("code")
        return done(f"{result.action}{f' {code}' if code else ''}")


def text(result: types.CallToolResult) -> str:
    block = result.content[0]
    assert isinstance(block, types.TextContent)
    return block.text


@pytest.mark.parametrize("version", VERSIONS)
@pytest.mark.parametrize(
    ("answer", "expected"), [(ACCEPT, "accept"), (DECLINE, "decline"), (CANCEL, "cancel")]
)
async def test_every_version_answers_as_scripted(
    version: Version, answer: Answer, expected: str
) -> None:
    approver = Approver()
    script = Script([answer])
    with running(approver.asker) as url:
        async with agent(url, version=version, script=script) as client:
            assert text(await client.call_tool("send", {})) == expected
            assert client.protocol_version == ("2026-07-28" if version == "modern" else version)
    [prompt] = script.prompts
    assert prompt.message == "Approve?"
    # The SDK client fills the parsed default, so even 2025-06-18's mode-less wire params read
    # "form" here; contract test 21 pins the wire itself.
    assert prompt.mode == "form"
    assert approver.versions[-1] == ("2026-07-28" if version == "modern" else version)


@pytest.mark.parametrize("version", VERSIONS)
async def test_the_agent_types_the_code_it_was_shown(version: Version) -> None:
    approver = Approver(CODE_PROMPT)
    script = Script([Answer(type_code=True)])
    with running(approver.asker) as url:
        async with agent(url, version=version, script=script) as client:
            assert text(await client.call_tool("send", {})) == "accept K7QD"
    assert script.prompts[0].code == "K7QD"


@pytest.mark.parametrize("version", VERSIONS)
async def test_answers_follow_in_order_and_the_last_repeats(version: Version) -> None:
    approver = Approver()
    script = Script([DECLINE, Answer(content={"note": "x"})])
    with running(approver.asker) as url:
        async with agent(url, version=version, script=script) as client:
            results = [text(await client.call_tool("send", {})) for _ in range(3)]
    assert results == ["decline", "accept", "accept"]
    assert len(script.prompts) == 3


@pytest.mark.parametrize("fails", ["raise", "error"])
async def test_a_failing_callback(fails: Any) -> None:
    script = Script([Answer(fails=fails)])
    approver = Approver()
    with running(approver.asker) as url:
        async with agent(url, version="2025-11-25", script=script) as client:
            assert text(await client.call_tool("send", {})) == "error"  # the server got an error
        async with agent(url, version="modern", script=script) as client:
            with pytest.raises((MCPError, ExceptionGroup)):
                await client.call_tool("send", {})
    assert approver.retries == []  # the modern client never retried


@pytest.mark.parametrize("version", VERSIONS)
@pytest.mark.parametrize("declares", ["form", "url", "both", "bare", "none"])
async def test_the_declared_capability_is_rewritten(version: Version, declares: Any) -> None:
    approver = Approver()
    with running(approver.asker) as url:
        async with agent(
            url, version=version, declares=declares, script=Script([DECLINE])
        ) as client:
            # The server asks whatever was declared; the SDK client answers anything it gets.
            await client.call_tool("send", {})
    seen = approver.capabilities[0]
    if declares == "none":
        assert seen is None
    else:
        assert (seen.form is not None, seen.url is not None) == {
            "form": (True, False),
            "url": (False, True),
            "both": (True, True),
            "bare": (False, False),
        }[declares]


async def test_the_raw_agent_sends_what_the_sdk_wont() -> None:
    approver = Approver()
    with running(approver.asker) as url:
        raw = RawAgent(url)
        answer = await raw.modern_call(
            "send",
            {"a": 1},
            request_state=STATE,
            input_responses={INPUT_KEY: {"action": "decline"}},
        )
        assert answer["result"]["content"][0]["text"] == "decline"
        first = await raw.modern_call("send", {"a": 1})
        assert first["result"]["resultType"] == "input_required"
        session = await raw.legacy_session()
        stray = await raw.respond(session, 424242, {"action": "accept"})
        assert stray.status_code == 202
    [retry] = approver.retries
    assert retry.request_state == STATE
