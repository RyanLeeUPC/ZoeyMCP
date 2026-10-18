"""The whole gateway, from an agent's SDK client to the fake upstream (M3 design E, L.3)."""

from __future__ import annotations

import contextlib
import json
from pathlib import Path
from typing import Any

import anyio
import httpx
import pytest
from mcp.shared.exceptions import MCPError
from mcp.types import TextContent, Tool

from tests.fakes.harness import serve
from tests.fakes.mcp_server import ZERO_WIDTH, Drift, McpFake, Switch, encoded_form
from tests.gateway.rig import (
    CLIENTS,
    KEYS,
    SERVER,
    Running,
    agent,
    deployment,
    gateway,
    pin_of_fake,
    token_for,
    until,
)
from zoeymcp.common.canonical import dumps_canonical
from zoeymcp.gateway import pipeline, upstream
from zoeymcp.gateway.app import GatewayApp
from zoeymcp.gateway.defstore import DefinitionStore
from zoeymcp.gateway.marks import DriftMarks
from zoeymcp.gateway.pins import project
from zoeymcp.gateway.server import status
from zoeymcp.gateway.upstream import UpstreamPool
from zoeymcp.gateway.vaultlink import KeySource, parse_link, view_client

pytestmark = pytest.mark.anyio

TOOLS = ["echo", "add", "slow"]


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def review(fake: McpFake, names: list[str] = TOOLS) -> dict[str, str]:
    return {name: pin_of_fake(fake, name) for name in names}


def text(result: object) -> str:
    content = result.content  # type: ignore[attr-defined]
    assert isinstance(content[0], TextContent)
    return content[0].text


@pytest.mark.parametrize("agent_mode", ["auto", "legacy"])
@pytest.mark.parametrize("upstream_era", ["auto", "legacy"])
async def test_an_agent_lists_and_calls_through_the_gateway(
    tmp_path: Path, agent_mode: str, upstream_era: str
) -> None:
    fake = McpFake()
    options = {"include": TOOLS, "review": review(fake), "era": upstream_era}
    with deployment(tmp_path, fake, **options) as deployed, gateway(deployed) as running:
        async with agent(running, mode=agent_mode) as client:
            listed = await client.list_tools()
            assert sorted(tool.name for tool in listed.tools) == sorted(TOOLS)
            assert text(await client.call_tool("echo", {"text": "hi"})) == "hi"
            assert client.server_info is None or client.server_info.name == "zoeymcp/notes"
    [call] = fake.calls
    assert (call.name, call.arguments) == ("echo", {"text": "hi"})


# --- G4: identity -----------------------------------------------------------------------------


def post(
    running: Running,
    body: object = None,
    *,
    server: str = SERVER,
    headers: dict[str, str] | None = None,
    client: str | None = CLIENTS[0],
    raw: bytes | None = None,
    query: str = "",
) -> httpx.Response:
    sent = {"accept": "application/json, text/event-stream", "content-type": "application/json"}
    if client is not None:
        sent["authorization"] = f"Bearer {token_for(client)}"
    sent.update(headers or {})
    content = raw if raw is not None else json.dumps(body or initialize()).encode()
    url = running.mcp(server) + query
    return httpx.post(url, content=content, headers=sent, timeout=30)


def initialize() -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "agent", "version": "1"},
        },
    }


async def test_every_identity_failure_is_the_same_401_and_reads_no_body(tmp_path: Path) -> None:
    fake = McpFake()
    sources = {"agent2": ["10.0.0.0/8"]}
    with (
        deployment(tmp_path, fake, include=TOOLS, review=review(fake), sources=sources) as deployed,
        gateway(deployed) as running,
    ):
        token = token_for(CLIENTS[0])
        cases = [
            post(running, client=None),
            post(running, client=None, headers={"authorization": "Bearer zgc1-wrong"}),
            post(running, client=None, query=f"?access_token={token}"),
            post(running, client=None, headers={"authorization": f"Basic {token}"}),
            # A source pin: agent2 only from 10/8. X-Forwarded-For doesn't count.
            post(running, client="agent2", headers={"x-forwarded-for": "10.1.2.3"}),
            # Garbage after a bad token: refused as identity, so the body was never parsed.
            post(
                running,
                client=None,
                headers={"authorization": "Bearer zgc1-wrong"},
                raw=b"{not json",
            ),
        ]
        two = httpx.post(
            running.mcp(),
            content=json.dumps(initialize()).encode(),
            headers=[
                ("accept", "application/json, text/event-stream"),
                ("content-type", "application/json"),
                ("authorization", f"Bearer {token}"),
                ("authorization", f"Bearer {token}"),
            ],
            timeout=30,
        )
        cases.append(two)
    assert [response.status_code for response in cases] == [401] * len(cases)
    assert len({response.content for response in cases}) == 1
    assert {response.headers["www-authenticate"] for response in cases} == {
        'Bearer realm="zoeymcp"'
    }
    assert fake.received == []


async def test_host_and_origin_come_before_the_token(tmp_path: Path) -> None:
    fake = McpFake()
    with (
        deployment(
            tmp_path, fake, include=TOOLS, review=review(fake), origins=["https://agent.example"]
        ) as deployed,
        gateway(deployed) as running,
    ):
        bad_host = post(running, client=None, headers={"host": "evil.example"})
        bad_origin = post(running, client=None, headers={"origin": "https://evil.example"})
        null_origin = post(running, headers={"origin": "null"})
        good_origin = post(running, headers={"origin": "https://agent.example"})
    assert (bad_host.status_code, bad_origin.status_code, null_origin.status_code) == (
        421,
        403,
        403,
    )
    assert good_origin.status_code == 200


async def test_only_the_mcp_path_and_health(tmp_path: Path) -> None:
    fake = McpFake()
    with (
        deployment(tmp_path, fake, include=TOOLS, review=review(fake)) as deployed,
        gateway(deployed) as running,
    ):
        health = httpx.get(f"{running.url}/healthz", timeout=10)
        discovery = httpx.get(f"{running.url}/.well-known/oauth-protected-resource", timeout=10)
        other = httpx.get(f"{running.url}/s/notes/sse", timeout=10)
        put = httpx.put(
            running.mcp(), headers={"authorization": f"Bearer {token_for(CLIENTS[0])}"}, timeout=10
        )
    assert (health.status_code, health.text) == (200, "ok")
    assert (discovery.status_code, other.status_code, put.status_code) == (404, 404, 405)


# --- G5: servers and sessions -------------------------------------------------------------------

TOOLKIT = {"mail": {"kind": "toolkit", "module": "example_toolkits.mail"}}


async def test_unknown_unassigned_and_toolkit_servers_are_one_404(tmp_path: Path) -> None:
    fake = McpFake()
    options = {
        "include": TOOLS,
        "review": review(fake),
        "clients": ("agent1", "agent2"),
        "servers": TOOLKIT,
        "assigned": {"agent1": [SERVER, "mail"], "agent2": []},
    }
    with deployment(tmp_path, fake, **options) as deployed, gateway(deployed) as running:
        unknown = post(running, server="nowhere")
        unassigned = post(running, client="agent2")
        toolkit = post(running, server="mail")
    assert {unknown.status_code, unassigned.status_code, toolkit.status_code} == {404}
    assert len({unknown.content, unassigned.content, toolkit.content}) == 1
    assert fake.received == []


async def test_a_session_works_only_for_its_client_and_server(tmp_path: Path) -> None:
    fake = McpFake()
    other = {
        "other": {
            "kind": "remote",
            "route": "notes",
            "path": "/mcp",
            "tools": {"include": [], "allow": []},
        }
    }
    options = {
        "include": TOOLS,
        "review": review(fake),
        "servers": other,
        "assigned": {"agent1": [SERVER, "other"], "agent2": [SERVER, "other"]},
    }
    with deployment(tmp_path, fake, **options) as deployed, gateway(deployed) as running:
        opened = post(running)
        session = opened.headers["mcp-session-id"]
        listing = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
        session_headers = {"mcp-session-id": session, "mcp-protocol-version": "2025-11-25"}
        stolen = post(running, listing, client="agent2", headers=session_headers)
        moved = post(running, listing, server="other", headers=session_headers)
        own = post(
            running,
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            headers=session_headers,
        )
    assert opened.status_code == 200
    assert (stolen.status_code, moved.status_code) == (404, 404)
    assert own.status_code == 202
    assert stolen.content == moved.content


# --- G6, G7: what is listed -----------------------------------------------------------------------


async def test_the_wire_listing_is_the_pinned_projections(tmp_path: Path) -> None:
    fake = McpFake(switches={Switch.TOOL_EXTRAS, Switch.INJECT_SERVER_INFO})
    pins = review(fake, ["add", "slow"])
    with (
        deployment(tmp_path, fake, include=["add", "slow"], review=pins) as deployed,
        gateway(deployed) as running,
    ):
        async with agent(running) as client:
            listed = await client.list_tools()
            assert client.instructions is None
            assert client.server_info is None or client.server_info.name == "zoeymcp/notes"
    expected = [
        project(Tool.model_validate(t))
        for t in fake.tools_for(None, 1)
        if t["name"] in ("add", "slow")
    ]
    wire = [tool.model_dump(mode="json", by_alias=True, exclude_none=True) for tool in listed.tools]
    assert wire == sorted(expected, key=lambda tool: tool["name"])


@pytest.mark.parametrize("agent_mode", ["auto", "legacy"])
async def test_unlisted_tools_get_one_refusal_and_nothing_goes_upstream(
    tmp_path: Path, agent_mode: str
) -> None:
    fake = McpFake(drift=Drift("description", after=0))
    pins = review(fake, ["add"])
    pins["slow"] = "sha256:" + "0" * 64  # a pin that doesn't match: drift
    with (
        deployment(tmp_path, fake, include=["add", "slow", "echo"], review=pins) as deployed,
        gateway(deployed) as running,
    ):
        async with agent(running, mode=agent_mode) as client:
            assert [tool.name for tool in (await client.list_tools()).tools] == ["add"]
            messages = []
            for name in ("echo", "slow", "counter", "nonexistent"):
                with pytest.raises(MCPError) as raised:
                    await client.call_tool(name, {})
                messages.append((raised.value.error.code, raised.value.error.message))
    assert set(messages) == {(-32602, "Unknown tool")}
    assert fake.calls == []


async def test_on_drift_fail_empties_the_list(tmp_path: Path) -> None:
    fake = McpFake()
    pins = review(fake)
    pins["slow"] = "sha256:" + "0" * 64
    with (
        deployment(tmp_path, fake, include=TOOLS, review=pins, on_drift="fail") as deployed,
        gateway(deployed) as running,
    ):
        async with agent(running) as client:
            assert (await client.list_tools()).tools == []
            with pytest.raises(MCPError):
                await client.call_tool("echo", {"text": "x"})
    assert fake.calls == []


# --- G9: arguments ------------------------------------------------------------------------------


async def test_invalid_arguments_are_refused_and_nothing_is_sent(tmp_path: Path) -> None:
    fake = McpFake()
    with (
        deployment(tmp_path, fake, include=TOOLS, review=review(fake)) as deployed,
        gateway(deployed) as running,
    ):
        async with agent(running) as client:
            wrong_type = await client.call_tool("add", {"a": "one", "b": 2})
            missing = await client.call_tool("add", {"a": 1})
            secret = "s3cret-value-in-arguments"
            enum = await client.call_tool("add", {"a": 1, "b": 2, "rounding": secret})
    assert [text(r) for r in (wrong_type, missing, enum)] == [
        "arguments refused: at /a: type",
        "arguments refused: at /: required",
        "arguments refused: at /rounding: enum",
    ]
    assert all(r.is_error for r in (wrong_type, missing, enum))
    assert fake.calls == []
    assert secret not in deployed.log.getvalue()


async def test_the_upstream_gets_the_canonical_object(tmp_path: Path) -> None:
    fake = McpFake()
    with (
        deployment(tmp_path, fake, include=TOOLS, review=review(fake)) as deployed,
        gateway(deployed) as running,
    ):
        async with agent(running) as client:
            await client.call_tool("add", {"b": 2.5, "a": 1, "rounding": "floor"})
    [call] = fake.calls
    assert call.arguments == {"a": 1, "b": 2.5, "rounding": "floor"}
    [sent] = fake.requests("tools/call")
    assert dumps_canonical(sent.params["arguments"]) == dumps_canonical(call.arguments)


async def test_oversized_arguments_are_refused(tmp_path: Path) -> None:
    fake = McpFake()
    limits = {"max_argument_bytes": 1024}
    with (
        deployment(tmp_path, fake, include=TOOLS, review=review(fake), limits=limits) as deployed,
        gateway(deployed) as running,
    ):
        async with agent(running) as client:
            result = await client.call_tool("echo", {"text": "x" * 2000})
    assert text(result) == "arguments refused: too large"
    assert fake.calls == []


@pytest.mark.parametrize(
    "switch",
    [Switch.SCHEMA_REMOTE_REF, Switch.SCHEMA_FILE_REF, Switch.SCHEMA_ID, Switch.SCHEMA_DIALECT],
)
async def test_an_unsafe_schema_is_never_served_or_fetched(tmp_path: Path, switch: Switch) -> None:
    fake = McpFake(switches={switch})
    pins = {**review(fake), switch.value: "sha256:" + "1" * 64}
    with (
        deployment(tmp_path, fake, include=[*TOOLS, switch.value], review=pins) as deployed,
        gateway(deployed) as running,
    ):
        async with agent(running) as client:
            names = [tool.name for tool in (await client.list_tools()).tools]
    assert switch.value not in names
    assert fake.schema_fetches == 0
    assert any(line["tool"] == switch.value for line in deployed.events("tool_invalid"))


async def test_a_schema_too_deep_to_parse_makes_the_server_unavailable(tmp_path: Path) -> None:
    """The SDK can't parse a 200-level schema at all, so the listing fails: closed, not open."""
    fake = McpFake(switches={Switch.SCHEMA_DEEP})
    with (
        deployment(tmp_path, fake, include=TOOLS, review=review(fake)) as deployed,
        gateway(deployed) as running,
    ):
        async with agent(running) as client:
            with pytest.raises(MCPError) as raised:
                await client.list_tools()
    assert raised.value.error.message.startswith("upstream unavailable (ref ")
    assert fake.calls == []


async def test_a_backtracking_pattern_answers_within_the_budget(tmp_path: Path) -> None:
    fake = McpFake(switches={Switch.SCHEMA_REDOS})
    names = [*TOOLS, "schema_redos"]
    with (
        deployment(tmp_path, fake, include=names, review=review(fake, names)) as deployed,
        gateway(deployed) as running,
    ):
        async with agent(running) as client:
            started = anyio.current_time()
            result = await client.call_tool("schema_redos", {"word": "a" * 40 + "!"})
            elapsed = anyio.current_time() - started
            # Another call is answered meanwhile as usual.
            assert text(await client.call_tool("echo", {"text": "fine"})) == "fine"
    assert result.is_error
    assert text(result).startswith("arguments refused")
    assert elapsed < 2
    assert [call.name for call in fake.calls] == ["echo"]


async def test_a_dollar_pattern_refuses_a_trailing_newline(tmp_path: Path) -> None:
    fake = McpFake(switches={Switch.SCHEMA_DOLLAR})
    names = [*TOOLS, "schema_dollar"]
    with (
        deployment(tmp_path, fake, include=names, review=review(fake, names)) as deployed,
        gateway(deployed) as running,
    ):
        async with agent(running) as client:
            refused = await client.call_tool("schema_dollar", {"code": "1234" + chr(10)})
            accepted = await client.call_tool("schema_dollar", {"code": "1234"})
    assert text(refused) == "arguments refused: at /code: pattern"
    assert accepted is not None  # the fake has no body for this tool, but the call went out
    assert [call.arguments for call in fake.calls] == [{"code": "1234"}]


# --- decisions ------------------------------------------------------------------------------------


async def test_an_approve_tool_is_refused_in_this_version(tmp_path: Path) -> None:
    fake = McpFake()
    with (
        deployment(
            tmp_path, fake, include=TOOLS, review=review(fake), approve=["echo"]
        ) as deployed,
        gateway(deployed) as running,
    ):
        async with agent(running) as client:
            result = await client.call_tool("echo", {"text": "hi"})
    assert result.is_error
    assert (
        text(result) == "refused: this tool needs an approval, and this version can't ask for one"
    )
    assert fake.calls == []
    assert deployed.events("approval_unavailable")


# --- G10, G11: what comes back -----------------------------------------------------------------


@pytest.mark.parametrize(("agent_mode", "era"), [("auto", "auto"), ("legacy", "legacy")])
async def test_a_back_channel_request_never_reaches_the_agent(
    tmp_path: Path, agent_mode: str, era: str
) -> None:
    fake = McpFake(back_channel="elicit_form")
    seen: list[object] = []

    async def elicitation(context: object, params: object) -> object:
        seen.append(params)
        raise AssertionError("the agent was asked")

    with (
        deployment(tmp_path, fake, include=TOOLS, review=review(fake), era=era) as deployed,
        gateway(deployed) as running,
    ):
        async with agent(running, mode=agent_mode, elicitation_callback=elicitation) as client:
            result = await client.call_tool("echo", {"text": "hi"})
    assert seen == []
    if era == "auto":  # modern upstream: input_required
        assert result.is_error
        assert text(result).startswith(
            "refused: the server asked for input this gateway doesn't relay"
        )
    assert "elicit" not in json.dumps(result.model_dump(mode="json"))


async def test_hostile_results_arrive_visible_and_reduced(tmp_path: Path) -> None:
    fake = McpFake(switches={Switch.INJECT_RESULTS})
    with (
        deployment(
            tmp_path, fake, include=TOOLS, review=review(fake), wrap_results=True
        ) as deployed,
        gateway(deployed) as running,
    ):
        async with agent(running) as client:
            result = await client.call_tool("echo", {"text": "x"})
    [first, *rest] = [block for block in result.content if isinstance(block, TextContent)]
    assert ZERO_WIDTH not in first.text
    assert "[U+200B]" in first.text
    assert "[U+202E]" in first.text
    # The fake's end marker sits inside the real markers, whose nonce it can't guess.
    lines = first.text.splitlines()
    assert lines[1].startswith("<<<zoeymcp-data ")
    nonce = lines[1].removeprefix("<<<zoeymcp-data ").removesuffix(">>>")
    assert nonce != "0000000000000000"
    assert lines[-1] == f"<<<end zoeymcp-data {nonce}>>>"
    assert [block.text for block in rest] == [
        "[image omitted by the gateway]",
        "[2 blocks omitted by the gateway]",
    ]
    assert result.structured_content is None  # no pinned outputSchema


@pytest.mark.parametrize(
    "switch",
    [Switch.INJECT_ERROR, Switch.INJECT_RPC_ERROR, Switch.INJECT_LOG, Switch.INJECT_PROGRESS],
)
async def test_upstream_text_never_reaches_the_agent(tmp_path: Path, switch: Switch) -> None:
    fake = McpFake(switches={switch})
    seen: list[tuple[float, float | None, str | None]] = []

    async def on_progress(progress: float, total: float | None, message: str | None) -> None:
        seen.append((progress, total, message))

    with (
        deployment(tmp_path, fake, include=TOOLS, review=review(fake)) as deployed,
        gateway(deployed) as running,
    ):
        async with agent(running) as client:
            tool, arguments = (
                ("slow", {"steps": 2, "interval": 0.2})
                if switch == Switch.INJECT_PROGRESS
                else ("echo", {"text": "x"})
            )
            result = await client.call_tool(tool, arguments, progress_callback=on_progress)
    dumped = json.dumps(result.model_dump(mode="json"), ensure_ascii=False)
    assert ZERO_WIDTH not in dumped
    if switch == Switch.INJECT_ERROR:
        # An isError result is still result content: shown, with nothing hidden.
        assert result.is_error
        assert "[U+200B]" in text(result)
    else:
        assert "IMPORTANT" not in dumped
    assert all(message is None for _, _, message in seen)
    if switch == Switch.INJECT_RPC_ERROR:
        assert result.is_error
        assert text(result).startswith("upstream error (ref ")
    assert "Plain words" not in deployed.log.getvalue()


# --- G12, G13: what the upstream sees, and what never comes back -------------------------------


async def test_the_upstream_never_sees_the_agents_identity_or_metadata(tmp_path: Path) -> None:
    fake = McpFake()
    origin = "https://agent.example"
    with (
        deployment(
            tmp_path, fake, include=TOOLS, review=review(fake), era="legacy", origins=[origin]
        ) as deployed,
        gateway(deployed) as running,
    ):
        headers = {
            "origin": origin,
            "cookie": "agent=1",
            "traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
        }
        async with agent(running, mode="legacy", headers=headers) as client:
            meta: Any = {"io.example/agent": "secret-meta"}
            await client.call_tool("echo", {"text": "hi"}, meta=meta)
            agent_session = (
                client.session.session_id if hasattr(client.session, "session_id") else None
            )
    token = token_for(CLIENTS[0])
    for item in fake.received:
        names = {key.lower() for key, _ in item.headers}
        values = " ".join(value for _, value in item.headers)
        assert token not in values
        assert not names & {"cookie", "origin", "traceparent", "tracestate", "baggage"}
        assert "io.example/agent" not in item.meta_keys
        assert "secret-meta" not in json.dumps(item.params)
        if agent_session is not None:
            assert item.session_id != agent_session
    [initialize] = fake.requests("initialize")
    assert initialize.params["clientInfo"] == {"name": "zoeymcp-gateway", "version": "1"}
    assert initialize.params["capabilities"] == {}


@pytest.mark.parametrize(
    "switch",
    [
        Switch.ECHO_ERROR_JSON,
        Switch.ECHO_ERROR_SSE,
        Switch.ECHO_BASE64,
        Switch.ECHO_JSON_ESCAPED,
        Switch.ECHO_HEADER,
    ],
)
async def test_an_echoed_key_reaches_neither_the_agent_nor_the_log(
    tmp_path: Path, switch: Switch
) -> None:
    fake = McpFake(switches={switch})
    with (
        deployment(tmp_path, fake, include=TOOLS, review=review(fake)) as deployed,
        gateway(deployed) as running,
    ):
        async with agent(running) as client:
            try:
                result: object = await client.call_tool("echo", {"text": "hi"})
            except MCPError as exc:
                result = exc
    received = (
        json.dumps(result.model_dump(mode="json")) if hasattr(result, "model_dump") else str(result)
    )
    forms = {fake.secret}
    with contextlib.suppress(ValueError):  # only the encoding switches have another form
        forms.add(encoded_form(fake.secret, switch))
    for form in forms:
        assert form not in received
        assert form not in deployed.log.getvalue()


# --- G15: cancellation ---------------------------------------------------------------------------


@pytest.mark.parametrize("agent_mode", ["auto", "legacy"])
async def test_an_agent_leaving_cancels_the_upstream_call(tmp_path: Path, agent_mode: str) -> None:
    fake = McpFake()
    with (
        deployment(tmp_path, fake, include=TOOLS, review=review(fake)) as deployed,
        gateway(deployed) as running,
    ):
        async with agent(running, mode=agent_mode) as client, anyio.create_task_group() as group:
            group.start_soon(client.call_tool, "slow", {"steps": 200, "interval": 0.05})
            await until(lambda: any(call.name == "slow" for call in fake.calls))
            group.cancel_scope.cancel()
        assert await anyio.to_thread.run_sync(fake.cancelled.wait, 5)


# --- G16: freshness and odd upstreams -------------------------------------------------------------


def test_before_the_first_view_everything_is_503(tmp_path: Path) -> None:
    link = parse_link("http://127.0.0.1:9")  # nothing listens there
    keys = KeySource(KEYS.gateway_key(1))
    pool = UpstreamPool(link, keys, DriftMarks.load(tmp_path), DefinitionStore(tmp_path))
    app = GatewayApp(pool, view_client(link, keys))
    with serve(app, lifespan=True, proxy_headers=False) as url:
        health = httpx.get(f"{url}/healthz", timeout=10)
        mcp = httpx.post(
            f"{url}/s/notes/mcp",
            json=initialize(),
            headers={"authorization": "Bearer x"},
            timeout=10,
        )
    assert (health.status_code, mcp.status_code) == (503, 503)


async def test_a_stale_view_is_503_and_closes_upstreams(tmp_path: Path) -> None:
    fake = McpFake()
    with (
        deployment(tmp_path, fake, include=TOOLS, review=review(fake), era="legacy") as deployed,
        gateway(deployed) as running,
    ):
        async with agent(running, mode="legacy") as client:
            await client.call_tool("echo", {"text": "hi"})
        policy = running.app.policy
        assert policy.snapshot is not None

        async def unreachable(wait: int | None = None) -> bool:
            await anyio.sleep(3600)
            return False

        # The vault stops answering, and the last contact is older than policy_max_stale.
        policy.fetch_once = unreachable  # type: ignore[method-assign]
        await anyio.sleep(1.5)  # the long poll in flight returns, and the next never does
        policy.last_contact = -10_000.0
        stale = post(running)
        await until(lambda: [item.method for item in fake.received].count("DELETE") == 1)
        assert httpx.get(f"{running.url}/healthz", timeout=10).status_code == 503
    assert stale.status_code == 503
    assert deployed.events("policy_stale")


async def test_a_task_result_is_refused(tmp_path: Path) -> None:
    fake = McpFake(switches={Switch.TASK_RESULT})
    with (
        deployment(tmp_path, fake, include=TOOLS, review=review(fake)) as deployed,
        gateway(deployed) as running,
    ):
        async with agent(running) as client:
            result = await client.call_tool("echo", {"text": "hi"})
    assert result.is_error
    assert text(result).startswith("upstream")


async def test_an_unsupported_upstream_version_lists_nothing(tmp_path: Path) -> None:
    fake = McpFake(switches={Switch.UNSUPPORTED_VERSION})
    with (
        deployment(tmp_path, fake, include=TOOLS, review=review(fake), era="legacy") as deployed,
        gateway(deployed) as running,
    ):
        async with agent(running) as client:
            with pytest.raises(MCPError) as raised:
                await client.list_tools()
    assert raised.value.error.message.startswith("upstream unavailable (ref ")


async def test_a_result_over_the_limit_is_refused(tmp_path: Path) -> None:
    fake = McpFake()
    limits = {"max_result_bytes": 65536}
    with (
        deployment(tmp_path, fake, include=TOOLS, review=review(fake), limits=limits) as deployed,
        gateway(deployed) as running,
    ):
        async with agent(running) as client:
            result = await client.call_tool("echo", {"text": "x" * 70_000})
    assert text(result).startswith("upstream result too large (ref ")


# --- G19: limits ---------------------------------------------------------------------------------


async def test_a_body_over_the_limit_is_413(tmp_path: Path) -> None:
    fake = McpFake()
    limits = {"max_request_bytes": 4096}
    with (
        deployment(tmp_path, fake, include=TOOLS, review=review(fake), limits=limits) as deployed,
        gateway(deployed) as running,
    ):
        declared = post(running, raw=b"{" + b" " * 5000 + b"}")
        body = initialize()
        body["params"]["padding"] = "x" * 5000  # type: ignore[index]
        streamed = post(running, body)
    assert (declared.status_code, streamed.status_code) == (413, 413)


async def test_the_ninth_concurrent_request_is_429(tmp_path: Path) -> None:
    fake = McpFake()
    with (
        deployment(tmp_path, fake, include=TOOLS, review=review(fake)) as deployed,
        gateway(deployed) as running,
    ):
        async with agent(running) as client, anyio.create_task_group() as group:
            for _ in range(8):
                group.start_soon(client.call_tool, "slow", {"steps": 40, "interval": 0.05})
            await until(lambda: [call.name for call in fake.calls].count("slow") == 8)
            ninth = post(
                running,
                {"jsonrpc": "2.0", "id": 9, "method": "server/discover", "params": {}},
                headers={"mcp-protocol-version": "2026-07-28"},
            )
            group.cancel_scope.cancel()
    assert ninth.status_code == 429
    assert ninth.headers["retry-after"] == "1"


async def test_the_seventeenth_session_is_429(tmp_path: Path) -> None:
    fake = McpFake()
    with (
        deployment(tmp_path, fake, include=TOOLS, review=review(fake)) as deployed,
        gateway(deployed) as running,
    ):
        statuses = [post(running).status_code for _ in range(17)]
    assert statuses == [200] * 16 + [429]


# --- E.7: list_changed to agents ------------------------------------------------------------------


@pytest.mark.parametrize("agent_mode", ["auto", "legacy"])
async def test_a_hidden_tool_is_announced_to_the_agent(
    tmp_path: Path, agent_mode: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(upstream, "COALESCE", 0.0)
    # The change comes once the agent is listening, announced by the upstream then.
    fake = McpFake(drift=Drift("description", after=1, notify=False))
    messages: list[object] = []

    async def handler(message: object) -> None:
        messages.append(getattr(message, "method", None))

    options = {"include": TOOLS, "review": review(fake), "era": "legacy"}
    with deployment(tmp_path, fake, **options) as deployed, gateway(deployed) as running:
        async with agent(running, mode=agent_mode, message_handler=handler) as client:
            assert "echo" in [tool.name for tool in (await client.list_tools()).tools]
            if agent_mode == "auto":
                async with client.listen(tools_list_changed=True) as events:
                    fake.announce()
                    with anyio.fail_after(10):
                        await events.__anext__()
            else:
                await anyio.sleep(0.5)  # the agent's GET stream is open by now
                fake.announce()
                await until(lambda: "notifications/tools/list_changed" in messages)
            assert "echo" not in [tool.name for tool in (await client.list_tools()).tools]
    assert deployed.events("tools_changed_sent")


# --- the admin status --------------------------------------------------------------------------


async def test_the_status_names_servers_and_counts_never_secrets(tmp_path: Path) -> None:
    fake = McpFake()
    with (
        deployment(tmp_path, fake, include=TOOLS, review=review(fake), servers=TOOLKIT) as deployed,
        gateway(deployed) as running,
    ):
        async with agent(running) as client:
            await client.list_tools()
        report = status(running.app)
    notes = report["servers"][SERVER]
    assert (notes["kind"], notes["included"], notes["exposed"], notes["marked"]) == (
        "remote",
        3,
        3,
        [],
    )
    assert report["servers"]["mail"] == {"kind": "toolkit", "state": "unsupported"}
    assert report["fresh"] is True
    dumped = json.dumps(report)
    assert "sha256:" not in dumped.replace(report["view"], "")


# --- D.3: revocation stops what is in flight ------------------------------------------------------


async def test_unassigning_a_client_stops_its_call_on_a_shared_connection(tmp_path: Path) -> None:
    fake = McpFake()
    options = {"include": TOOLS, "review": review(fake)}
    results: dict[str, Any] = {}
    with deployment(tmp_path, fake, **options) as deployed, gateway(deployed) as running:
        async with agent(running, CLIENTS[1]) as other, agent(running, CLIENTS[0]) as client:
            # The first listing learns the era: modern, so both calls share one connection.
            await other.list_tools()

            async def call(who: str, connected: Any, steps: int) -> None:
                arguments = {"steps": steps, "interval": 0.05}
                results[who] = await connected.call_tool("slow", arguments)

            async with anyio.create_task_group() as group:
                group.start_soon(call, "revoked", client, 400)
                group.start_soon(call, "kept", other, 60)
                await until(lambda: len([c for c in fake.calls if c.name == "slow"]) == 2)
                await anyio.to_thread.run_sync(lambda: deployed.reload(assigned={CLIENTS[0]: []}))
        assert await anyio.to_thread.run_sync(fake.cancelled.wait, 5)
    shared = [line for line in deployed.events("upstream_connected") if line["key"] == "*"]
    assert shared, "the calls didn't share a connection"
    assert text(results["revoked"]).startswith(pipeline.REVOKED)
    assert results["revoked"].is_error
    assert not results["kept"].is_error
    [stopped] = deployed.events("requests_stopped")
    assert (stopped["client"], stopped["server"], stopped["count"]) == (CLIENTS[0], SERVER, 1)


async def test_revoking_a_token_ends_its_legacy_stream(tmp_path: Path) -> None:
    fake = McpFake()
    options = {"include": TOOLS, "review": review(fake)}
    with deployment(tmp_path, fake, **options) as deployed, gateway(deployed) as running:
        async with agent(running, mode="legacy") as client:
            await client.list_tools()
            await anyio.sleep(0.5)  # the session's GET stream is open by now
            await anyio.to_thread.run_sync(lambda: deployed.reload(clients=(CLIENTS[1],)))
            await until(lambda: deployed.events("requests_stopped"))
            with pytest.raises(MCPError):
                await client.list_tools()
    stopped = deployed.events("requests_stopped")
    assert {(line["client"], line["server"]) for line in stopped} == {(CLIENTS[0], SERVER)}
