"""Approvals for remote ``approve`` tools, in all three protocol versions (M4 design B, D; S15).

The agent is the SDK client (:mod:`tests.fakes.agent`), or raw requests where the SDK won't send
what a case needs. The gateway runs with a real vault, a real ledger and the fake MCP server.
"""

from __future__ import annotations

import contextlib
import json
import re
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import anyio
import httpx
import pytest
from mcp.shared.exceptions import MCPError
from mcp.types import CallToolResult, TextContent

from tests.fakes.agent import (
    ACCEPT,
    CANCEL,
    DECLINE,
    VERSIONS,
    Answer,
    RawAgent,
    Script,
    Version,
    agent,
)
from tests.fakes.mcp_server import McpFake
from tests.gateway.rig import (
    CLIENTS,
    SERVER,
    Deployed,
    Running,
    deployment,
    gateway,
    token_for,
    until,
)
from tests.gateway.test_upstream import review
from zoeymcp.common import ledgerformat
from zoeymcp.gateway.ledger import LEDGER_DIR

pytestmark = pytest.mark.anyio

TOOLS = ["echo", "add", "slow"]
REF = re.compile(r"\(ref ([0-9a-f]{16})\)$")
ATTENDED = {"attended": True}


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@contextmanager
def approving(
    tmp_path: Path,
    fake: McpFake | None = None,
    *,
    approve: list[str] | None = None,
    approvals: dict[str, dict[str, Any]] | None = None,
    gateway_approvals: dict[str, Any] | None = None,
    era: str = "auto",
) -> Iterator[tuple[Deployed, Running]]:
    fake = fake if fake is not None else McpFake()
    options: dict[str, Any] = {
        "include": TOOLS,
        "review": review(fake),
        "approve": approve if approve is not None else ["echo", "slow"],
        "approvals": approvals if approvals is not None else {CLIENTS[0]: ATTENDED},
        "era": era,
    }
    if gateway_approvals is not None:
        options["gateway_approvals"] = gateway_approvals
    with deployment(tmp_path, fake, **options) as deployed, gateway(deployed) as running:
        yield deployed, running


def headers(client: str = CLIENTS[0]) -> dict[str, str]:
    return {"authorization": f"Bearer {token_for(client)}"}


def text(result: CallToolResult) -> str:
    block = result.content[0]
    assert isinstance(block, TextContent)
    return block.text


def ref_of(result: CallToolResult) -> str:
    found = REF.search(text(result))
    assert found is not None, text(result)
    return found.group(1)


def ledger_records(deployed: Deployed) -> list[ledgerformat.Record]:
    found: list[ledgerformat.Record] = []
    for path in sorted((deployed.state / LEDGER_DIR).glob("*.jsonl")):
        found.extend(ledgerformat.parse(line) for line in path.read_bytes().splitlines())
    return found


def by_ref(deployed: Deployed, ref: str) -> list[tuple[str, Any]]:
    return [
        (r.kind, r.fields.get("decision") or r.fields.get("outcome") or r.fields.get("era"))
        for r in ledger_records(deployed)
        if r.ref == ref
    ]


# --- the happy path, and the plain declines ------------------------------------------------------


@pytest.mark.parametrize("version", VERSIONS)
async def test_accept_runs_exactly_the_shown_call(tmp_path: Path, version: Version) -> None:
    script = Script([ACCEPT])
    with approving(tmp_path) as (deployed, running):
        async with agent(
            running.mcp(), version=version, script=script, headers=headers()
        ) as client:
            result = await client.call_tool("echo", {"text": "Meeting moved to 3pm"})
    assert text(result).endswith("Meeting moved to 3pm")
    assert [(c.name, c.arguments) for c in deployed.fake.calls] == [
        ("echo", {"text": "Meeting moved to 3pm"})
    ]
    [prompt] = script.prompts
    lines = prompt.message.split("\n")
    assert lines[0].startswith("Approval request ")
    ref = lines[0].removeprefix("Approval request ")
    assert lines[1:3] == [f"Client: {CLIENTS[0]}", f"Tool: {SERVER} \N{RIGHTWARDS ARROW} echo"]
    assert lines[3].startswith("Answer by ")
    assert lines[3].endswith("UTC. Accept runs this one call, exactly as shown.")
    assert '  "text": "Meeting moved to 3pm"' in lines
    assert lines[-1] == f"End of approval request {ref}"
    era = "modern" if version == "modern" else "legacy"
    assert by_ref(deployed, ref) == [("asked", era), ("decided", "accept"), ("outcome", "ok")]
    [decided] = deployed.events("approval_decided")
    assert (decided["ref"], decided["decision"]) == (ref, "accept")
    assert decided["ledger_seq"] == 1


@pytest.mark.parametrize("version", VERSIONS)
@pytest.mark.parametrize(("answer", "decision"), [(DECLINE, "decline"), (CANCEL, "dismiss")])
async def test_a_decline_sends_nothing(
    tmp_path: Path, version: Version, answer: Answer, decision: str
) -> None:
    with approving(tmp_path) as (deployed, running):
        async with agent(
            running.mcp(), version=version, script=Script([answer]), headers=headers()
        ) as client:
            result = await client.call_tool("echo", {"text": "hi"})
    assert result.is_error
    assert text(result).startswith("declined by operator (ref ")
    assert deployed.fake.calls == []
    ref = ref_of(result)
    assert [kind for kind, _ in by_ref(deployed, ref)] == ["asked", "decided", "outcome"]
    assert by_ref(deployed, ref)[1] == ("decided", decision)


@pytest.mark.parametrize("version", VERSIONS)
async def test_allow_tools_never_ask(tmp_path: Path, version: Version) -> None:
    script = Script([DECLINE])
    with approving(tmp_path) as (deployed, running):
        async with agent(
            running.mcp(), version=version, script=script, headers=headers()
        ) as client:
            assert text(await client.call_tool("add", {"a": 1, "b": 2})) == "3"
    assert script.prompts == []
    assert ledger_records(deployed) == []


# --- who may be asked ---------------------------------------------------------------------------


@pytest.mark.parametrize("version", VERSIONS)
async def test_an_unattended_client_is_never_asked(tmp_path: Path, version: Version) -> None:
    script = Script([ACCEPT])
    with approving(tmp_path, approvals={}) as (deployed, running):
        async with agent(
            running.mcp(), version=version, script=script, headers=headers()
        ) as client:
            result = await client.call_tool("echo", {"text": "hi"})
    assert text(result).startswith("refused: no approver for this client (ref ")
    assert script.prompts == []
    assert deployed.fake.calls == []
    assert ledger_records(deployed) == []
    assert deployed.events("approval_refused")[0]["reason"] == "unattended"


@pytest.mark.parametrize("version", VERSIONS)
@pytest.mark.parametrize("declares", ["url", "none"])
async def test_a_client_that_cant_show_forms_is_refused(
    tmp_path: Path, version: Version, declares: Any
) -> None:
    script = Script([ACCEPT])
    with approving(tmp_path) as (deployed, running):
        async with agent(
            running.mcp(), version=version, script=script, declares=declares, headers=headers()
        ) as client:
            result = await client.call_tool("echo", {"text": "hi"})
    assert text(result).startswith("refused: this client can't show approvals (ref ")
    assert script.prompts == []
    assert ledger_records(deployed) == []


# --- what the human sees ------------------------------------------------------------------------


@pytest.mark.parametrize("version", VERSIONS)
async def test_markup_is_refused_before_anyone_is_asked(tmp_path: Path, version: Version) -> None:
    script = Script([ACCEPT])
    with approving(tmp_path) as (deployed, running):
        async with agent(
            running.mcp(), version=version, script=script, headers=headers()
        ) as client:
            fenced = await client.call_tool("echo", {"text": "```\nhidden"})
            spaced = await client.call_tool("echo", {"text": "a" + " " * 9 + "b"})
    assert text(fenced).startswith(
        "refused: the approval text breaks the plain-text rules at /text: a code fence (ref "
    )
    assert "whitespace 9 columns wide" in text(spaced)
    assert script.prompts == []
    assert deployed.fake.calls == []


async def test_a_plain_client_may_approve_a_code_fence(tmp_path: Path) -> None:
    script = Script([ACCEPT])
    plain = {CLIENTS[0]: {"attended": True, "renders": "plain"}}
    with approving(tmp_path, approvals=plain) as (_deployed, running):
        async with agent(running.mcp(), script=script, headers=headers()) as client:
            result = await client.call_tool("echo", {"text": "```\nshown"})
    assert not result.is_error
    assert len(script.prompts) == 1


@pytest.mark.parametrize("version", VERSIONS)
async def test_the_confirmation_code(tmp_path: Path, version: Version) -> None:
    coded = {CLIENTS[0]: {"attended": True, "confirm_code": True}}
    with approving(tmp_path, approvals=coded) as (deployed, running):
        right = Script([Answer(type_code=True)])
        async with agent(running.mcp(), version=version, script=right, headers=headers()) as client:
            assert not (await client.call_tool("echo", {"text": "hi"})).is_error
        wrong = Script([Answer(content={"code": "AAAA"})])
        async with agent(running.mcp(), version=version, script=wrong, headers=headers()) as client:
            result = await client.call_tool("add", {"a": 1, "b": 1})  # an allow tool: no prompt
            assert text(result) == "2"
            denied = await client.call_tool("echo", {"text": "again"})
    assert right.prompts[0].code is not None
    assert right.prompts[0].schema["required"] == ["code"]
    assert text(denied).startswith("declined: the confirmation code didn't match (ref ")
    assert [c.arguments for c in deployed.fake.calls if c.name == "echo"] == [{"text": "hi"}]


# --- locks, caps and cooldowns ------------------------------------------------------------------


@pytest.mark.parametrize("version", VERSIONS)
async def test_one_call_per_tool_while_one_waits(tmp_path: Path, version: Version) -> None:
    script = Script([Answer(delay=1.0)])
    with approving(tmp_path) as (_deployed, running):
        async with agent(
            running.mcp(), version=version, script=script, headers=headers()
        ) as client:
            results: list[CallToolResult] = []

            async def first() -> None:
                results.append(await client.call_tool("echo", {"text": "first"}))

            async with anyio.create_task_group() as group:
                group.start_soon(first)
                await until(lambda: len(script.prompts) == 1)
                second = await client.call_tool("echo", {"text": "second"})
    assert re.match(
        r"refused: another call to this tool is waiting or running \(ref [0-9a-f]{16}, "
        r"frees within \d+ s\) \(ref [0-9a-f]{16}\)$",
        text(second),
    )
    assert len(script.prompts) == 1
    assert not results[0].is_error


@pytest.mark.parametrize("version", VERSIONS)
async def test_a_decline_starts_a_cooldown(tmp_path: Path, version: Version) -> None:
    script = Script([DECLINE, ACCEPT])
    with approving(tmp_path) as (_deployed, running):
        async with agent(
            running.mcp(), version=version, script=script, headers=headers()
        ) as client:
            await client.call_tool("echo", {"text": "one"})
            again = await client.call_tool("echo", {"text": "two"})
    assert re.match(r"refused: this tool was declined moments ago; try again in \d+ s", text(again))
    assert len(script.prompts) == 1


# --- timeouts and failing clients ---------------------------------------------------------------


@pytest.mark.parametrize("version", ["2025-11-25", "2025-06-18"])
async def test_a_legacy_prompt_times_out(tmp_path: Path, version: Version) -> None:
    quick = {CLIENTS[0]: {"attended": True, "timeout": 1}}
    script = Script([Answer(delay=3.0)])
    with approving(tmp_path, approvals=quick) as (deployed, running):
        async with agent(
            running.mcp(), version=version, script=script, headers=headers()
        ) as client:
            result = await client.call_tool("echo", {"text": "hi"})
    assert text(result).startswith("no answer in time (ref ")
    assert deployed.fake.calls == []
    assert by_ref(deployed, ref_of(result))[1] == ("decided", "timeout")


async def test_a_late_modern_answer_is_a_timeout(tmp_path: Path) -> None:
    quick = {CLIENTS[0]: {"attended": True, "timeout": 1}}
    script = Script([Answer(delay=2.0)])
    with approving(tmp_path, approvals=quick) as (deployed, running):
        async with agent(running.mcp(), script=script, headers=headers()) as client:
            result = await client.call_tool("echo", {"text": "hi"})
    assert result.is_error
    assert deployed.fake.calls == []
    assert "no answer in time" in text(result)


async def test_a_raising_legacy_callback_is_an_error_at_once(tmp_path: Path) -> None:
    script = Script([Answer(fails="raise")])
    with approving(tmp_path) as (_deployed, running):
        async with agent(
            running.mcp(), version="2025-11-25", script=script, headers=headers()
        ) as c:
            result = await c.call_tool("echo", {"text": "hi"})
            assert text(result).startswith("refused: the approval request failed (ref ")
            # The lock is free at once.
            script.answers = [ACCEPT]
            assert not (await c.call_tool("echo", {"text": "again"})).is_error


async def test_a_modern_client_that_never_retries_holds_the_lock_until_the_deadline(
    tmp_path: Path,
) -> None:
    quick = {CLIENTS[0]: {"attended": True, "timeout": 1}}
    with approving(tmp_path, approvals=quick) as (deployed, running):
        raw = RawAgent(running.mcp(), headers=headers())
        first = await raw.modern_call("echo", {"text": "hi"})
        assert first["result"]["resultType"] == "input_required"
        busy = await raw.modern_call("echo", {"text": "hi"})
        assert "waiting or running" in busy["result"]["content"][0]["text"]
        await until(lambda: deployed.events("approval_decided"), timeout=5)
    [decided] = deployed.events("approval_decided")
    assert decided["decision"] == "timeout"
    assert deployed.fake.calls == []


# --- the modern handle --------------------------------------------------------------------------


def answered(decision: str = "accept", **content: Any) -> dict[str, Any]:
    answer: dict[str, Any] = {"action": decision}
    if content:
        answer["content"] = content
    return {"zoeymcp-approval": answer}


async def test_a_handle_is_single_use(tmp_path: Path) -> None:
    with approving(tmp_path) as (deployed, running):
        raw = RawAgent(running.mcp(), headers=headers())
        asked = await raw.modern_call("echo", {"text": "hi"})
        state = asked["result"]["requestState"]
        done = await raw.modern_call(
            "echo", {"text": "hi"}, request_state=state, input_responses=answered()
        )
        assert done["result"]["content"][0]["text"].endswith("hi")
        replay = await raw.modern_call(
            "echo", {"text": "hi"}, request_state=state, input_responses=answered()
        )
    assert replay["result"]["content"][0]["text"] == "refused: approval expired or already used"
    assert len(deployed.fake.calls) == 1


async def test_another_clients_handle_leaves_the_owners_approval(tmp_path: Path) -> None:
    both = {CLIENTS[0]: ATTENDED, CLIENTS[1]: ATTENDED}
    with approving(tmp_path, approvals=both) as (deployed, running):
        owner = RawAgent(running.mcp(), headers=headers(CLIENTS[0]))
        thief = RawAgent(running.mcp(), headers=headers(CLIENTS[1]))
        state = (await owner.modern_call("echo", {"text": "hi"}))["result"]["requestState"]
        stolen = await thief.modern_call(
            "echo", {"text": "hi"}, request_state=state, input_responses=answered()
        )
        assert stolen["result"]["content"][0]["text"] == "refused: approval expired or already used"
        mine = await owner.modern_call(
            "echo", {"text": "hi"}, request_state=state, input_responses=answered()
        )
    assert mine["result"]["content"][0]["text"].endswith("hi")
    assert deployed.events("approval_state_foreign")
    assert len(deployed.fake.calls) == 1


async def test_changed_arguments_close_the_approval(tmp_path: Path) -> None:
    with approving(tmp_path) as (deployed, running):
        raw = RawAgent(running.mcp(), headers=headers())
        state = (await raw.modern_call("echo", {"text": "shown"}))["result"]["requestState"]
        swapped = await raw.modern_call(
            "echo", {"text": "different"}, request_state=state, input_responses=answered()
        )
    assert swapped["result"]["content"][0]["text"].startswith(
        "refused: this approval belongs to a different call (ref "
    )
    assert deployed.fake.calls == []


async def test_a_pre_answered_first_call_is_asked_anyway(tmp_path: Path) -> None:
    with approving(tmp_path) as (deployed, running):
        raw = RawAgent(running.mcp(), headers=headers())
        first = await raw.modern_call("echo", {"text": "hi"}, input_responses=answered())
    assert first["result"]["resultType"] == "input_required"
    assert deployed.fake.calls == []
    assert deployed.events("approval_unsolicited_answer")


async def test_no_answer_is_asked_again_with_the_same_ref(tmp_path: Path) -> None:
    with approving(tmp_path) as (_deployed, running):
        raw = RawAgent(running.mcp(), headers=headers())
        first = (await raw.modern_call("echo", {"text": "hi"}))["result"]
        second = (
            await raw.modern_call("echo", {"text": "hi"}, request_state=first["requestState"])
        )["result"]
        message = first["inputRequests"]["zoeymcp-approval"]["params"]["message"]
        assert second["inputRequests"]["zoeymcp-approval"]["params"]["message"] == message
        assert second["requestState"] != first["requestState"]
        done = await raw.modern_call(
            "echo", {"text": "hi"}, request_state=second["requestState"], input_responses=answered()
        )
    assert done["result"]["content"][0]["text"].endswith("hi")


@pytest.mark.parametrize("state", ["za1.bad", "za1." + "A" * 43, 7])
async def test_bad_handles(tmp_path: Path, state: object) -> None:
    with approving(tmp_path) as (deployed, running):
        raw = RawAgent(running.mcp(), headers=headers())
        answer = await raw.modern_call(
            "echo", {"text": "hi"}, request_state=state, input_responses=answered()
        )
    text_or_error = json.dumps(answer)
    assert "refused: approval expired or already used" in text_or_error or "error" in answer
    assert deployed.fake.calls == []


async def test_a_handle_on_an_allow_tool_is_refused(tmp_path: Path) -> None:
    with approving(tmp_path) as (deployed, running):
        raw = RawAgent(running.mcp(), headers=headers())
        state = (await raw.modern_call("echo", {"text": "hi"}))["result"]["requestState"]
        answer = await raw.modern_call(
            "add", {"a": 1, "b": 2}, request_state=state, input_responses=answered()
        )
    assert answer["result"]["content"][0]["text"] == "refused: approval expired or already used"
    assert deployed.fake.calls == []


# --- committed calls finish ---------------------------------------------------------------------


@pytest.mark.parametrize("version", VERSIONS)
async def test_the_agent_leaving_during_an_accepted_forward_doesnt_stop_it(
    tmp_path: Path, version: Version
) -> None:
    script = Script([ACCEPT])
    with approving(tmp_path) as (deployed, running):
        async with agent(
            running.mcp(), version=version, script=script, headers=headers()
        ) as client:
            with anyio.move_on_after(1.5):  # the agent gives up mid-forward
                await client.call_tool("slow", {"steps": 30, "interval": 0.1})
        await until(lambda: deployed.events("approval_outcome"), timeout=10)
    [outcome] = deployed.events("approval_outcome")
    assert outcome["outcome"] == "ok"
    assert deployed.fake.cancellations == []


async def test_a_stop_withdraws_a_waiting_prompt(tmp_path: Path) -> None:
    script = Script([Answer(delay=5.0)])
    with approving(tmp_path) as (deployed, running):
        async with agent(
            running.mcp(), version="2025-11-25", script=script, headers=headers()
        ) as client:
            results: list[CallToolResult] = []

            async def call() -> None:
                results.append(await client.call_tool("echo", {"text": "hi"}))

            async with anyio.create_task_group() as group:
                group.start_soon(call)
                await until(lambda: len(script.prompts) == 1)
                running.app.request_stop()
    assert text(results[0]).startswith("refused: the gateway is stopping (ref ")
    assert deployed.fake.calls == []


# --- the legacy wire ----------------------------------------------------------------------------


def call_body(request_id: int, name: str = "echo", **arguments: Any) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments or {"text": "hi"}},
    }


async def sse(lines: Any) -> Any:
    async for line in lines:
        if line.startswith("data:") and line[5:].strip():
            yield json.loads(line[5:].strip())


async def test_a_dropped_legacy_stream_ends_the_wait(tmp_path: Path) -> None:
    with approving(tmp_path) as (deployed, running):
        raw = RawAgent(running.mcp(), headers=headers())
        session = await raw.legacy_session()
        async with (
            httpx.AsyncClient(timeout=10) as http,
            http.stream(
                "POST", raw.url, json=call_body(5), headers=raw.legacy_headers(session)
            ) as response,
        ):
            prompt = await anext(sse(response.aiter_lines()))
            assert prompt["method"] == "elicitation/create"
        await until(lambda: deployed.events("approval_decided"), timeout=3)
        [decided] = deployed.events("approval_decided")
        assert decided["decision"] == "stream_lost"
        # The lock is free: the next call is asked again.
        again = await raw.modern_call("echo", {"text": "hi"})
        assert again["result"]["resultType"] == "input_required"
    assert deployed.fake.calls == []


async def test_the_agents_cancel_withdraws_the_prompt(tmp_path: Path) -> None:
    with approving(tmp_path) as (deployed, running):
        raw = RawAgent(running.mcp(), headers=headers())
        session = await raw.legacy_session()
        async with (
            httpx.AsyncClient(timeout=10) as http,
            http.stream(
                "POST", raw.url, json=call_body(5), headers=raw.legacy_headers(session)
            ) as response,
        ):
            stream = sse(response.aiter_lines())
            prompt = await anext(stream)
            cancel = {
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": {"requestId": 5},
            }
            sent = await http.post(raw.url, json=cancel, headers=raw.legacy_headers(session))
            assert sent.status_code == 202
            rest = [message async for message in stream]
        await until(lambda: deployed.events("approval_decided"), timeout=3)
    assert [
        m["params"]["requestId"] for m in rest if m.get("method") == "notifications/cancelled"
    ] == [prompt["id"]]
    assert deployed.events("approval_decided")[0]["decision"] == "withdrawn"
    assert deployed.fake.calls == []


async def test_an_answer_takes_the_reply_slot_at_the_concurrency_cap(tmp_path: Path) -> None:
    fake = McpFake()
    with (
        deployment(
            tmp_path,
            fake,
            include=TOOLS,
            review=review(fake),
            approve=["echo"],
            approvals={CLIENTS[0]: ATTENDED},
            limits={"max_concurrent_per_client": 1},
        ) as deployed,
        gateway(deployed) as running,
    ):
        raw = RawAgent(running.mcp(), headers=headers())
        session = await raw.legacy_session()
        async with (
            httpx.AsyncClient(timeout=10) as http,
            http.stream(
                "POST", raw.url, json=call_body(5), headers=raw.legacy_headers(session)
            ) as response,
        ):
            stream = sse(response.aiter_lines())
            prompt = await anext(stream)
            # The waiting call holds the client's one slot.
            listed = await http.post(
                raw.url,
                json={"jsonrpc": "2.0", "id": 6, "method": "tools/list"},
                headers=raw.legacy_headers(session),
            )
            assert listed.status_code == 429
            answer = await raw.respond(session, prompt["id"], {"action": "accept"})
            assert answer.status_code == 202
            final = await anext(stream)
    assert final["result"]["content"][0]["text"].endswith("hi")
    assert [c.name for c in fake.calls] == ["echo"]


async def test_an_answer_on_another_session_is_refused(tmp_path: Path) -> None:
    with approving(tmp_path) as (deployed, running):
        raw = RawAgent(running.mcp(), headers=headers())
        mine, other = await raw.legacy_session(), await raw.legacy_session()
        async with (
            httpx.AsyncClient(timeout=10) as http,
            http.stream(
                "POST", raw.url, json=call_body(5), headers=raw.legacy_headers(mine)
            ) as response,
        ):
            stream = sse(response.aiter_lines())
            prompt = await anext(stream)
            forged = await raw.respond(other, prompt["id"], {"action": "accept"})
            assert forged.status_code == 400  # no prompt waits on that session
            await raw.respond(mine, prompt["id"], {"action": "decline"})
            final = await anext(stream)
    assert final["result"]["content"][0]["text"].startswith("declined by operator")
    assert deployed.fake.calls == []


async def test_unassigning_the_client_withdraws_its_prompt(tmp_path: Path) -> None:
    script = Script([Answer(delay=8.0)])
    with approving(tmp_path) as (deployed, running):
        async with agent(
            running.mcp(), version="2025-11-25", script=script, headers=headers()
        ) as client:
            results: list[CallToolResult] = []

            async def call() -> None:
                results.append(await client.call_tool("echo", {"text": "hi"}))

            async with anyio.create_task_group() as group:
                group.start_soon(call)
                await until(lambda: len(script.prompts) == 1)
                deployed.reload(approvals={})  # no longer attended
    assert text(results[0]).startswith("refused: the policy changed; call the tool again (ref ")
    assert deployed.fake.calls == []


async def test_a_retry_that_fails_parsing_frees_the_lock(tmp_path: Path) -> None:
    with approving(tmp_path) as (deployed, running):
        raw = RawAgent(running.mcp(), headers=headers())
        state = (await raw.modern_call("echo", {"text": "hi"}))["result"]["requestState"]
        nested = {"zoeymcp-approval": {"action": "accept", "content": {"a": {"deep": 1}}}}
        broken = await raw.modern_call(
            "echo", {"text": "hi"}, request_state=state, input_responses=nested
        )
        assert broken["error"]["code"] == -32602
        again = await raw.modern_call("echo", {"text": "hi"})
    assert again["result"]["resultType"] == "input_required"  # not "waiting or running"
    assert deployed.events("approval_decided")[0]["decision"] == "error"
    assert deployed.fake.calls == []


# --- S12, the approval side: an upstream can't ask during an approved call (M.1) -----------------


@pytest.mark.parametrize("version", VERSIONS)
@pytest.mark.parametrize(
    ("era", "stream"), [("auto", "call"), ("legacy", "call"), ("legacy", "get")]
)
async def test_an_upstream_asking_during_an_approved_call_never_reaches_the_agent(
    tmp_path: Path, version: Version, era: str, stream: Any
) -> None:
    fake = McpFake(back_channel="elicit_form", back_channel_stream=stream)
    script = Script([ACCEPT])
    with approving(tmp_path, fake, era=era) as (deployed, running):
        async with agent(
            running.mcp(), version=version, script=script, headers=headers()
        ) as client:
            result = await client.call_tool("echo", {"text": "hi"})
    # The agent saw exactly one prompt: the gateway's own.
    assert len(script.prompts) == 1
    assert script.prompts[0].message.startswith("Approval request ")
    [outcome] = deployed.events("approval_outcome")
    if era == "auto":  # a modern upstream returned input_required
        assert text(result).startswith(
            "refused: the server asked for input this gateway doesn't relay"
        )
        assert (outcome["outcome"], outcome["detail"]) == ("refused", "upstream_input_required")
    else:  # a legacy upstream's request got an error answer, and the call went on
        assert [answer.outcome.startswith("error") for answer in fake.answers] == [True]
        assert outcome["outcome"] == "ok"


@pytest.mark.parametrize("version", ["modern", "2025-11-25"])
async def test_unassigning_the_client_during_an_accepted_forward_lets_it_finish(
    tmp_path: Path, version: Version
) -> None:
    script = Script([ACCEPT])
    with approving(tmp_path) as (deployed, running):
        async with agent(
            running.mcp(), version=version, script=script, headers=headers()
        ) as client:

            async def call() -> None:
                # The SDK client may make a follow-up request, which an unassigned client is
                # refused; what H9 promises is that the accepted call itself runs to the end.
                with contextlib.suppress(MCPError):
                    await client.call_tool("slow", {"steps": 30, "interval": 0.1})

            async with anyio.create_task_group() as group:
                group.start_soon(call)
                await until(lambda: len(deployed.fake.calls) == 1, timeout=5)
                deployed.reload(assigned={CLIENTS[0]: []})
        await until(lambda: deployed.events("approval_outcome"), timeout=10)
    [outcome] = deployed.events("approval_outcome")
    assert outcome["outcome"] == "ok"
    assert deployed.fake.cancellations == []
    assert [c.name for c in deployed.fake.calls] == ["slow"]
