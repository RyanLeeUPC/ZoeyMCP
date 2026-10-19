"""Acceptance: S10 and S12, end to end over real sockets and real TLS (design §8.1, M3 L.4).

Agent (the SDK client, both eras) -> gateway -> vault -> the fake MCP server, using the shipped
``remote-mcp-static-key.yaml`` with only its upstream, tools, pins and clients filled in. The
fake runs in each of its three modes. Every test ends with the sweeps of G13 and G20: the key,
the client tokens and their hashes, the gateway key and the session ids appear nowhere an agent,
an operator or a log reader could see them.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import sys
import unicodedata
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import anyio
import pytest
from mcp.shared.exceptions import MCPError
from mcp.types import TextContent

from tests.fakes.mcp_server import (
    BACK_CHANNELS,
    DRIFT_MEMBERS,
    HOSTILE_PARAMETER,
    ZERO_WIDTH,
    Drift,
    McpFake,
    Mode,
    Switch,
    encoded_form,
)
from tests.gateway.rig import agent, pin_of_fake, token_for, until
from zoeymcp.common.policy.schema import hash_token
from zoeymcp.gateway import upstream as upstream_module

from .conftest import serve_tls
from .gateway import CLIENTS, SERVER, GatewayDeployment, Seen
from .tls import ProviderCA

pytestmark = pytest.mark.anyio

KEY = "notes-key/7f3e+9c1a="  # changes under percent-encoding, and has a "/"
TOOLS = {"echo": "allow", "add": "allow", "slow": "allow", "report": "allow", "lookup": "approve"}
LINKS = ["tcp", pytest.param("unix", marks=pytest.mark.skipif(
    sys.platform != "linux", reason="the link socket's peer check is Linux only"
))]  # fmt: skip


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def own_uid() -> int:
    if sys.platform == "win32":
        return 0
    return os.getuid()


def pins(fake: McpFake, names: list[str] | None = None) -> dict[str, str]:
    return {name: pin_of_fake(fake, name) for name in names or sorted(TOOLS)}


@contextlib.contextmanager
def deployed(
    tmp_path: Path, ca: ProviderCA, fake: McpFake, *, link: str = "tcp", **options: Any
) -> Iterator[GatewayDeployment]:
    with serve_tls(fake.app(), ca, lifespan=True) as upstream:
        gateway = GatewayDeployment(
            tmp_path,
            upstream,
            ca,
            key=KEY,
            tools=options.pop("tools", TOOLS),
            pins=options.pop("pins") if "pins" in options else pins(fake),
            link=link,  # type: ignore[arg-type]
            link_uid=own_uid() if link == "unix" else None,
            **options,
        )
        yield gateway
    sweep(gateway.seen, clients=gateway.clients, gateway_key=gateway.vault.keys.gateway_key(1),
          fake=fake)  # fmt: skip


def text(result: Any) -> str:
    block = result.content[0]
    assert isinstance(block, TextContent)
    return str(block.text)


def dumped(value: Any) -> str:
    """An answer as the agent got it (members it didn't get left out), for the sweep."""
    if hasattr(value, "model_dump"):
        return json.dumps(
            value.model_dump(mode="json", by_alias=True, exclude_none=True), ensure_ascii=False
        )
    return str(value)


def sweep(seen: Seen, *, clients: tuple[str, ...], gateway_key: str, fake: McpFake) -> None:
    """G13 and G20, over everything the test let anyone see."""
    everything = seen.everything()
    forbidden = {KEY: "the upstream key"}
    for switch in Switch:
        with contextlib.suppress(ValueError):  # only the echo switches have an encoded form
            forbidden[encoded_form(KEY, switch)] = f"the key, {switch}"
    forbidden[base64.b64encode(KEY.encode()).decode()] = "the key in base64"
    for client in clients:
        forbidden[token_for(client)] = f"{client}'s token"
        forbidden[hash_token(token_for(client))] = f"{client}'s token hash"
        forbidden[hash_token(token_for(client)).removeprefix("sha256:")] = f"{client}'s hash"
    forbidden[gateway_key] = "the gateway key"
    for item in fake.received:
        session = item.session_id
        if session:
            forbidden[session] = "an upstream session id"
    for value, what in forbidden.items():
        assert value not in everything, f"{what} reached a log, an answer or the CLI"
    for output in seen.outputs:
        for char in output:
            if char not in "\n\t":
                assert unicodedata.category(char) not in ("Cc", "Cf"), "a hidden character"


# --- S10 -----------------------------------------------------------------------------------------


@pytest.mark.parametrize("link", LINKS)
@pytest.mark.parametrize("fake_mode", ["dual", "legacy", "modern"])
@pytest.mark.parametrize("agent_mode", ["auto", "legacy"])
async def test_s10_list_call_and_refusals(
    tmp_path: Path, ca: ProviderCA, agent_mode: str, fake_mode: Mode, link: str
) -> None:
    fake = McpFake(mode=fake_mode, key=KEY, key_header="x-api-key")
    seen_progress: list[float] = []

    async def on_progress(progress: float, total: float | None, message: str | None) -> None:
        seen_progress.append(progress)

    with deployed(tmp_path, ca, fake, link=link) as gateway, gateway.running() as running:
        async with agent(running, mode=agent_mode) as client:
            listed = await client.list_tools()
            echoed = await client.call_tool("echo", {"text": "hello"})
            added = await client.call_tool("add", {"a": 2, "b": 3})
            report = await client.call_tool("report", {})
            slow = await client.call_tool(
                "slow", {"steps": 3, "interval": 0.15}, progress_callback=on_progress
            )
            invalid = await client.call_tool("add", {"a": "two", "b": 3})
            approve = await client.call_tool("lookup", {"region": "eu"})
            with pytest.raises(MCPError) as unknown:
                await client.call_tool("counter", {})
        gateway.seen.outputs += [dumped(x) for x in (listed, echoed, added, report, slow)]
    assert sorted(tool.name for tool in listed.tools) == sorted(TOOLS)
    assert text(echoed) == "hello"
    assert not added.is_error
    assert report.structured_content == {"total": 3, "items": ["alpha", "beta", "gamma"]}
    assert not slow.is_error
    assert seen_progress, "no progress reached the agent"
    assert invalid.is_error
    assert text(invalid).startswith("arguments refused: at /a: ")
    assert approve.is_error
    # The profile's client isn't attended, so it is never asked (M4 design D1).
    assert text(approve).startswith("refused: no approver for this client (ref ")
    assert unknown.value.error.code == -32602
    # Only the validated calls went upstream, each with the vault's key, never the agent's token.
    assert [call.name for call in fake.calls] == ["echo", "add", "report", "slow"]
    for item in fake.received:
        assert item.header("x-api-key") == KEY
        assert item.header("authorization") is None


@pytest.mark.parametrize("agent_mode", ["auto", "legacy"])
async def test_s10_an_agent_leaving_cancels_the_upstream_call(
    tmp_path: Path, ca: ProviderCA, agent_mode: str
) -> None:
    fake = McpFake(key=KEY, key_header="x-api-key")
    with deployed(tmp_path, ca, fake) as gateway, gateway.running() as running:
        async with agent(running, mode=agent_mode) as client, anyio.create_task_group() as group:
            group.start_soon(client.call_tool, "slow", {"steps": 200, "interval": 0.05})
            await until(lambda: any(call.name == "slow" for call in fake.calls))
            group.cancel_scope.cancel()
        assert await anyio.to_thread.run_sync(fake.cancelled.wait, 5)


async def test_s10_legacy_state_is_per_client(tmp_path: Path, ca: ProviderCA) -> None:
    fake = McpFake(mode="legacy", key=KEY, key_header="x-api-key")
    tools = {**TOOLS, "counter": "allow"}
    with (
        deployed(tmp_path, ca, fake, tools=tools, pins=pins(fake, sorted(tools))) as gateway,
        gateway.running() as running,
    ):
        async with agent(running, CLIENTS[0]) as first, agent(running, CLIENTS[1]) as second:
            counts = [
                text(await first.call_tool("counter", {})),
                text(await first.call_tool("counter", {})),
                text(await second.call_tool("counter", {})),
            ]
    assert counts == ["1", "2", "1"]
    assert len({item.session_id for item in fake.requests("tools/call")}) == 2


async def test_s10_an_expired_upstream_session_is_opened_again(
    tmp_path: Path, ca: ProviderCA
) -> None:
    fake = McpFake(mode="legacy", key=KEY, key_header="x-api-key", session_404_after=2)
    with deployed(tmp_path, ca, fake) as gateway, gateway.running() as running:
        async with agent(running) as client:
            answers = [text(await client.call_tool("echo", {"text": str(n)})) for n in range(4)]
    assert answers == ["0", "1", "2", "3"]
    assert len(fake.requests("initialize")) >= 2


async def test_s10_onboarding_with_review(tmp_path: Path, ca: ProviderCA) -> None:
    """Nothing is served until the operator reviews, adds, classifies and commits the pins."""
    fake = McpFake(key=KEY, key_header="x-api-key")
    with (
        deployed(tmp_path, ca, fake, tools={}, pins={}) as gateway,
        gateway.running() as running,
    ):
        async with agent(running) as client:
            assert (await client.list_tools()).tools == []
        code, out, _ = gateway.cli(running, "review", SERVER)
        assert code == 0
        assert "echo" in out
        code, out, _ = gateway.cli(
            running, "review", SERVER, "--add", "echo", "--add", "add", "--format", "json"
        )
        snippet = json.loads(out)["snippet"]
        added = {
            line.split(":")[0].strip(): line.split(":", 1)[1].split("#")[0].strip()
            for line in snippet
            if line.startswith("        ") and "sha256:" in line
        }
        assert sorted(added) == ["add", "echo"]
        gateway.reload({"echo": "allow", "add": "allow"}, added)
        await until(lambda: running.app.policy.snapshot is not None and "echo" in (
            running.app.policy.snapshot.view.gateway.servers[SERVER].tools.include  # type: ignore[union-attr]
        ))  # fmt: skip
        async with agent(running) as client:
            listed = sorted(tool.name for tool in (await client.list_tools()).tools)
            result = await client.call_tool("echo", {"text": "reviewed"})
        assert listed == ["add", "echo"]
        assert text(result) == "reviewed"
        code, out, _ = gateway.cli(running, "review", SERVER)
        assert code == 0


@pytest.mark.skipif(sys.platform != "linux", reason="the link socket's peer check is Linux only")
async def test_s10_another_uid_on_the_link_socket_is_cut(tmp_path: Path, ca: ProviderCA) -> None:
    fake = McpFake(key=KEY, key_header="x-api-key")
    with serve_tls(fake.app(), ca, lifespan=True) as upstream:
        gateway = GatewayDeployment(
            tmp_path, upstream, ca, key=KEY, link="unix", link_uid=own_uid() + 1
        )
        with gateway.running(ready=False) as running:
            await anyio.sleep(2)
            assert running.app.policy.snapshot is None
    assert gateway.seen.events("gateway_socket_refused")
    assert fake.received == []


# --- S12: a hostile server -------------------------------------------------------------------


def listings(gateway: GatewayDeployment) -> int:
    """How many listings the agent's upstream connection has made."""
    return len([line for line in gateway.seen.events("listing") if line["key"] == CLIENTS[0]])


@pytest.mark.parametrize("member", DRIFT_MEMBERS)
async def test_s12_a_changed_definition_is_hidden_and_stays_hidden(
    tmp_path: Path, ca: ProviderCA, member: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(upstream_module, "COALESCE", 0.0)
    # A legacy upstream keeps one connection per client. Listing 1 is clean, listing 2 shows
    # the change, listing 3 has undone it; each change is announced on the session's stream.
    fake = McpFake(
        mode="legacy",
        key=KEY,
        key_header="x-api-key",
        drift=Drift(member, after=1, flip_back_after=1),  # type: ignore[arg-type]
    )
    with deployed(tmp_path, ca, fake) as gateway, gateway.running() as running:
        async with agent(running) as client:
            before = {tool.name for tool in (await client.list_tools()).tools}
            await anyio.sleep(0.5)  # the gateway's stream from the upstream is open by now
            fake.announce()
            await until(lambda: listings(gateway) >= 2)
            changed = {tool.name for tool in (await client.list_tools()).tools}
            fake.announce()
            await until(lambda: listings(gateway) >= 3)
            undone = {tool.name for tool in (await client.list_tools()).tools}
        code, out, _ = gateway.cli(running, "review", SERVER)
    assert before == set(TOOLS)
    hidden = before - changed
    assert len(hidden) == 1, f"a {member} change hid {sorted(hidden)}"
    if member == "removed":
        # A missing tool comes back when it is listed again; there was nothing to mark.
        assert undone == before
        assert code == 0
    else:
        # The definition flipped back, but the mark holds until review --clear.
        assert undone == changed
        assert gateway.seen.events("tool_drift")
        assert code == 1
        [line] = [line for line in out.splitlines() if line.split()[:1] == sorted(hidden)]
        assert "MARKED" in line


@pytest.mark.parametrize("agent_mode", ["auto", "legacy"])
async def test_s12_hostile_definitions_and_results_arrive_visible(
    tmp_path: Path, ca: ProviderCA, agent_mode: str
) -> None:
    fake = McpFake(
        key=KEY,
        key_header="x-api-key",
        switches={
            Switch.INJECT_DEFINITIONS,
            Switch.INJECT_SERVER_INFO,
            Switch.INJECT_RESULTS,
            Switch.TOOL_EXTRAS,
        },
    )
    with deployed(tmp_path, ca, fake) as gateway, gateway.running() as running:
        async with agent(running, mode=agent_mode) as client:
            listed = await client.list_tools()
            result = await client.call_tool("echo", {"text": "x"})
            info = client.server_info
        code, out, _ = gateway.cli(running, "review", SERVER, "--all")
        gateway.seen.outputs += [dumped(listed), dumped(result)]
    wire = dumped(listed)
    for absent in ("icons", "attacker.example", "execution", "x-unknown", HOSTILE_PARAMETER):
        assert absent not in wire
    assert sorted(tool.name for tool in listed.tools) == sorted(TOOLS)
    assert info is None or info.name == "zoeymcp/notes"
    assert ZERO_WIDTH not in dumped(result)
    assert "[U+200B]" in dumped(result)
    assert code == 0  # the included tools match; the hostile ones stay unincluded
    assert "(error findings: not pinnable)" in out


@pytest.mark.parametrize(
    "switch",
    [
        Switch.ECHO_ERROR_JSON,
        Switch.ECHO_ERROR_SSE,
        Switch.ECHO_SPLIT,
        Switch.ECHO_PERCENT,
        Switch.ECHO_BASE64,
        Switch.ECHO_BASE64URL,
        Switch.ECHO_JSON_ESCAPED,
        Switch.ECHO_LARGE_JSON,
        Switch.ECHO_HEADER,
        Switch.ECHO_OVERSIZE_EVENT,
        Switch.INJECT_ERROR,
        Switch.INJECT_RPC_ERROR,
        Switch.INJECT_LOG,
        Switch.INJECT_PROGRESS,
    ],
)
async def test_s12_echoes_and_upstream_text_never_reach_the_agent(
    tmp_path: Path, ca: ProviderCA, switch: Switch
) -> None:
    fake = McpFake(key=KEY, key_header="x-api-key", switches={switch})
    with deployed(tmp_path, ca, fake) as gateway, gateway.running() as running:
        async with agent(running) as client:
            tool, arguments = (
                ("slow", {"steps": 2, "interval": 0.2})
                if switch == Switch.INJECT_PROGRESS
                else ("echo", {"text": "x"})
            )
            try:
                result: Any = await client.call_tool(tool, arguments)
            except MCPError as exc:
                result = exc
        gateway.seen.outputs.append(dumped(result))
    answer = dumped(result)
    assert "IMPORTANT" not in answer or switch == Switch.INJECT_ERROR
    assert ZERO_WIDTH not in answer
    # The sweep (in ``deployed``) checks the key in every form.


@pytest.mark.parametrize("kind", BACK_CHANNELS)
@pytest.mark.parametrize("fake_mode", ["legacy", "modern"])
async def test_s12_a_back_channel_never_reaches_the_agent(
    tmp_path: Path, ca: ProviderCA, kind: str, fake_mode: Mode
) -> None:
    if kind == "state_only" and fake_mode == "legacy":
        pytest.skip("requestState is modern only")
    fake = McpFake(mode=fake_mode, key=KEY, key_header="x-api-key", back_channel=kind)  # type: ignore[arg-type]
    asked: list[object] = []

    async def callback(*args: object) -> object:
        asked.append(args)
        raise AssertionError("the agent was asked")

    with deployed(tmp_path, ca, fake) as gateway, gateway.running() as running:
        async with agent(
            running, elicitation_callback=callback, sampling_callback=callback
        ) as client:
            result = await client.call_tool("echo", {"text": "x"})
        gateway.seen.outputs.append(dumped(result))
    assert asked == []
    if fake_mode == "modern":
        assert result.is_error
        assert text(result).startswith("refused: the server asked for input this gateway")
    # Legacy: the SDK answered the server's request with an error; nothing was relayed.
    assert all(answer.outcome.startswith("error") for answer in fake.answers)


@pytest.mark.parametrize(
    ("switch", "state"),
    [
        (Switch.SCHEMA_REMOTE_REF, "invalid"),
        (Switch.SCHEMA_FILE_REF, "invalid"),
        (Switch.SCHEMA_ID, "invalid"),
        (Switch.SCHEMA_DIALECT, "invalid"),
        (Switch.SCHEMA_REDOS, "unreviewed"),
    ],
)
async def test_s12_unsafe_schemas_are_refused_and_never_fetched(
    tmp_path: Path, ca: ProviderCA, switch: Switch, state: str
) -> None:
    fake = McpFake(key=KEY, key_header="x-api-key", switches={switch})
    with deployed(tmp_path, ca, fake) as gateway, gateway.running() as running:
        async with agent(running) as client:
            names = {tool.name for tool in (await client.list_tools()).tools}
        _, out, _ = gateway.cli(running, "review", SERVER, "--format", "json")
    assert names == set(TOOLS)
    [entry] = [tool for tool in json.loads(out)["tools"] if tool["name"] == switch.value]
    assert entry["state"] == state
    if state == "unreviewed":  # pinnable, with a warning to read it first
        assert any("nested quantifier" in f["message"] for f in entry["findings"])
    assert fake.schema_fetches == 0


@pytest.mark.parametrize(
    "switch", [Switch.ENDLESS_CURSOR, Switch.REPEAT_CURSOR, Switch.UNSUPPORTED_VERSION]
)
async def test_s12_a_broken_listing_exposes_nothing(
    tmp_path: Path, ca: ProviderCA, switch: Switch
) -> None:
    fake = McpFake(key=KEY, key_header="x-api-key", switches={switch})
    with deployed(tmp_path, ca, fake) as gateway, gateway.running() as running:
        async with agent(running) as client:
            with pytest.raises(MCPError) as raised:
                await client.list_tools()
        code, _, err = gateway.cli(running, "review", SERVER)
    assert raised.value.error.code == -32603
    assert code == 2
    assert "couldn't list the server's tools" in err


async def test_s12_a_redirect_to_another_route_is_refused(tmp_path: Path, ca: ProviderCA) -> None:
    fake = McpFake(key=KEY, key_header="x-api-key", redirect="/mail/send")
    with deployed(tmp_path, ca, fake) as gateway, gateway.running() as running:
        async with agent(running) as client:
            result = await client.call_tool("echo", {"text": "x"})
        gateway.seen.outputs.append(dumped(result))
    assert result.is_error
    assert "/mail/send" not in {item.path for item in fake.received}
    assert gateway.seen.events("upstream_redirect_refused") or [
        line for line in gateway.seen.events("request") if line.get("reason") == "redirect refused"
    ]


@pytest.mark.parametrize(
    ("leak", "what"),
    [
        (hashlib.sha256(token_for("agent1").encode()).hexdigest(), "agent1's hash"),
        (token_for("agent2"), "agent2's token"),
        ("zgw1-gateway", "the gateway key"),
        (KEY.replace("/", "\\/"), "the key, echo_json_escaped"),
        ("\u202e", "a hidden character"),
    ],
)
def test_the_sweep_sees_a_leak(leak: str, what: str) -> None:
    seen = Seen()
    seen.outputs.append(f"output {leak}")
    with pytest.raises(AssertionError, match=what):
        sweep(seen, clients=CLIENTS, gateway_key="zgw1-gateway", fake=McpFake())
