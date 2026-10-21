"""The fake MCP server: each mode and switch, observed with the SDK client or on the wire."""

from __future__ import annotations

import json
import time
from collections.abc import AsyncIterator, Callable, Iterator
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import Any, cast

import anyio
import httpx
import httpx2
import mcp_types as types
import pytest
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.server.session import ServerSession
from mcp.shared.exceptions import MCPError
from starlette.types import Message

from zoeymcp.common.policy.schema import GatewayLimits
from zoeymcp.gateway.findings import tool_findings
from zoeymcp.vault.request import MAX_STREAM_EVENT_BYTES, scrub, secret_variants

from . import run_mcp_server
from .harness import serve
from .mcp_server import (
    ANNOUNCE_DELAY,
    ANSI,
    AS_WELL_KNOWN,
    BACK_CHANNELS,
    BIDI_OVERRIDE,
    C1_CSI,
    DEFAULT_KEY,
    DRIFT_MEMBERS,
    EVENT_CAP,
    FAKE_END_MARKER,
    FILE_REF,
    HOSTILE,
    HOSTILE_PARAMETER,
    IMPORTANT,
    INVALID_NAME,
    LARGE_INVALID,
    LARGE_WARNED,
    MIB,
    MODERN_VERSION,
    OTHER_AS,
    PRIVATE_METADATA,
    PRM_WELL_KNOWN,
    REF_URL,
    REQUEST_STATE,
    SCHEMA_DEPTH,
    SCHEMA_PATH,
    TAG_TEXT,
    UNSUPPORTED_VERSION,
    ZERO_WIDTH,
    BackChannel,
    BackChannelAnswer,
    BackChannelStream,
    Drift,
    DriftMember,
    McpFake,
    Recorded,
    Switch,
    _read_body,
    apply_drift,
    base_tools,
    encoded_event,
    encoded_form,
)

pytestmark = pytest.mark.anyio

LEGACY_VERSION = "2025-11-25"
ACCEPT = {"accept": "application/json, text/event-stream"}
BASE_NAMES = ["echo", "add", "slow", "counter", "report", "lookup"]


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@contextmanager
def running(fake: McpFake) -> Iterator[str]:
    """The fake's MCP endpoint URL while it runs."""
    with serve(fake.app(), lifespan=True) as base:
        yield f"{base}{fake.path}"


@asynccontextmanager
async def connect(
    url: str, mode: str = "auto", headers: dict[str, str] | None = None, **options: Any
) -> AsyncIterator[Client]:
    """An SDK client with no response cache, so every listing reaches the fake."""
    timeout = httpx2.Timeout(10.0, read=30.0)
    async with (
        httpx2.AsyncClient(headers=headers, trust_env=False, timeout=timeout) as http,
        Client(
            streamable_http_client(url, http_client=http), mode=mode, cache=None, **options
        ) as client,
    ):
        yield client


def modern_post(
    url: str,
    method: str,
    params: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    """One raw 2026-07-28 request."""
    meta = {
        "io.modelcontextprotocol/protocolVersion": MODERN_VERSION,
        "io.modelcontextprotocol/clientCapabilities": {},
    }
    params = dict(params or {})
    wire = {
        **ACCEPT,
        "mcp-protocol-version": MODERN_VERSION,
        "mcp-method": method,
        **(headers or {}),
    }
    if "name" in params:
        wire["mcp-name"] = params["name"]
    body = {"jsonrpc": "2.0", "id": 7, "method": method, "params": {**params, "_meta": meta}}
    return httpx.post(url, json=body, headers=wire, timeout=30)


def echo_call(url: str) -> httpx.Response:
    return modern_post(url, "tools/call", {"name": "echo", "arguments": {"text": "hi"}})


def sse_messages(text: str) -> list[Any]:
    lines = [line[5:].strip() for line in text.splitlines() if line.startswith("data:")]
    return [json.loads(line) for line in lines if line]


def leaf(error: BaseException) -> BaseException:
    """The one exception inside nested single-member groups."""
    while isinstance(error, BaseExceptionGroup) and len(error.exceptions) == 1:
        error = error.exceptions[0]
    return error


async def until(condition: Callable[[], bool], timeout: float = 5.0) -> None:
    with anyio.fail_after(timeout):
        while not condition():
            await anyio.sleep(0.02)


def text_of(result: types.CallToolResult) -> str:
    block = result.content[0]
    assert isinstance(block, types.TextContent)
    return block.text


def wire_tools(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Definitions as the SDK client parses and dumps them."""
    return [_dump(types.Tool.model_validate(tool)) for tool in tools]


def _dump(tool: types.Tool) -> dict[str, Any]:
    return tool.model_dump(by_alias=True, exclude_none=True, mode="json")


def dumped(listing: types.ListToolsResult) -> list[dict[str, Any]]:
    return [_dump(tool) for tool in listing.tools]


class Notifications:
    """A message handler that keeps the notifications it is given."""

    def __init__(self) -> None:
        self.methods: list[str] = []

    async def __call__(self, message: object) -> None:
        if isinstance(message, types.ServerNotification):
            self.methods.append(message.method)

    def count(self, method: str) -> int:
        return self.methods.count(method)


# --- modes --------------------------------------------------------------------------------------


async def test_dual_mode_serves_both_eras() -> None:
    fake = McpFake()
    with running(fake) as url:
        async with connect(url) as client:
            assert client.protocol_version == MODERN_VERSION
            modern = await client.list_tools()
        async with connect(url, mode="legacy") as client:
            assert client.protocol_version == LEGACY_VERSION
            assert client.server_capabilities.tools == types.ToolsCapability(list_changed=True)
            legacy = await client.list_tools()
    assert [tool.name for tool in modern.tools] == BASE_NAMES
    assert dumped(modern) == dumped(legacy) == wire_tools(base_tools())
    issued = [item.issued_session_id for item in fake.received if item.issued_session_id]
    assert len(issued) == 1


async def test_legacy_mode_answers_modern_requests_with_an_unrecognized_400() -> None:
    fake = McpFake(mode="legacy")
    with running(fake) as url:
        response = modern_post(url, "server/discover")
        async with connect(url) as client:
            assert client.protocol_version == LEGACY_VERSION
            assert [tool.name for tool in (await client.list_tools()).tools] == BASE_NAMES
    assert response.status_code == 400
    assert response.text == "unrecognized request"
    assert [item.status for item in fake.requests("server/discover")] == [400, 400]


async def test_modern_mode_refuses_the_handshake_era_and_issues_no_sessions() -> None:
    fake = McpFake(mode="modern")
    with running(fake) as url:
        async with connect(url) as client:
            assert client.protocol_version == MODERN_VERSION
            assert text_of(await client.call_tool("echo", {"text": "hi"})) == "hi"
        with pytest.raises(BaseException) as refused:  # noqa: PT011
            async with connect(url, mode="legacy"):
                pass
        get = httpx.get(url, headers={"accept": "text/event-stream"})
        delete = httpx.delete(url)
    error = leaf(refused.value)
    assert isinstance(error, MCPError)
    assert error.error.code == types.UNSUPPORTED_PROTOCOL_VERSION
    assert error.error.data == {"supported": [MODERN_VERSION], "requested": LEGACY_VERSION}
    assert (get.status_code, delete.status_code) == (405, 405)
    assert get.headers["allow"] == "POST"
    assert [item.status for item in fake.requests("initialize")] == [400]
    assert all(item.issued_session_id is None for item in fake.received)


async def test_mode_can_change_while_running() -> None:
    """Modern at review, then legacy only."""
    fake = McpFake()
    with running(fake) as url:
        async with connect(url) as client:
            assert client.protocol_version == MODERN_VERSION
        fake.mode = "legacy"
        async with connect(url) as client:
            assert client.protocol_version == LEGACY_VERSION


async def test_legacy_version_is_what_initialize_answers() -> None:
    fake = McpFake(legacy_version="2025-06-18")
    with running(fake) as url:
        async with connect(url, mode="legacy") as client:
            assert client.protocol_version == "2025-06-18"
            assert text_of(await client.call_tool("echo", {"text": "hi"})) == "hi"
    [call] = fake.requests("tools/call")
    assert call.header("mcp-protocol-version") == "2025-06-18"


# --- recording ----------------------------------------------------------------------------------


async def test_every_request_is_recorded() -> None:
    fake = McpFake()
    with running(fake) as url:
        async with connect(url, mode="legacy") as client:
            await client.call_tool("echo", {"text": "hi"})
        async with connect(url) as client:
            await client.call_tool("add", {"a": 1, "b": 2})
    [initialize] = fake.requests("initialize")
    assert (initialize.method, initialize.path, initialize.status) == ("POST", "/mcp", 200)
    session = initialize.issued_session_id
    assert session is not None
    legacy_call, modern_call = fake.requests("tools/call")
    assert legacy_call.session_id == session
    assert legacy_call.params["arguments"] == {"text": "hi"}
    assert json.loads(legacy_call.body) == legacy_call.message
    assert legacy_call.header("MCP-Protocol-Version") == LEGACY_VERSION
    assert legacy_call.meta_keys == []
    assert modern_call.session_id is None
    assert "io.modelcontextprotocol/protocolVersion" in modern_call.meta_keys
    assert "io.modelcontextprotocol/clientCapabilities" in modern_call.meta_keys
    deletes = [item for item in fake.received if item.method == "DELETE"]
    assert [(item.session_id, item.status) for item in deletes] == [(session, 200)]
    assert not any(item.disconnected for item in fake.received if item.method == "POST")


async def test_other_paths_are_recorded_and_not_found() -> None:
    fake = McpFake()
    with running(fake) as url:
        response = httpx.post(url.replace("/mcp", "/mail/send"), json={"to": "x"})
    assert response.status_code == 404
    [item] = fake.received
    assert (item.path, item.message, item.status) == ("/mail/send", {"to": "x"}, 404)


# --- S10 ----------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("key_header", "form"), [("authorization", "Bearer {}"), ("x-api-key", "{}")]
)
async def test_a_static_key_is_required(key_header: str, form: str) -> None:
    fake = McpFake(key="fake-key-1", key_header=key_header)  # type: ignore[arg-type]
    with running(fake) as url:
        missing = echo_call(url)
        wrong = modern_post(
            url, "tools/call", {"name": "echo"}, headers={key_header: form.format("fake-wrong")}
        )
        async with connect(url, headers={key_header: form.format("fake-key-1")}) as client:
            result = await client.call_tool("echo", {"text": "hi"})
    assert (missing.status_code, wrong.status_code) == (401, 401)
    assert wrong.json() == {"error": "invalid_token"}
    assert wrong.headers["www-authenticate"] == 'Bearer error="invalid_token"'
    assert text_of(result) == "hi"
    assert [item.status for item in fake.requests("tools/call")] == [401, 401, 200]


@pytest.mark.parametrize(
    ("key_header", "headers"),
    [
        ("authorization", {"authorization": "fake-key-1"}),
        ("authorization", {"authorization": "Basic fake-key-1"}),
        ("authorization", {"authorization": "bearerfake-key-1"}),
        ("authorization", {"x-api-key": "fake-key-1"}),
        ("x-api-key", {"authorization": "Bearer fake-key-1"}),
        ("x-api-key", {"x-api-key": "Bearer fake-key-1"}),
    ],
)
async def test_the_key_in_the_wrong_form_is_refused(
    key_header: str, headers: dict[str, str]
) -> None:
    fake = McpFake(key="fake-key-1", key_header=key_header)  # type: ignore[arg-type]
    with running(fake) as url:
        response = modern_post(url, "tools/call", {"name": "echo"}, headers=headers)
    assert response.status_code == 401


async def test_a_401_can_echo_the_presented_value() -> None:
    fake = McpFake(key="fake-key-1", switches={Switch.ECHO_401})
    with running(fake) as url:
        wrong = modern_post(
            url, "tools/call", {"name": "echo"}, headers={"authorization": "Bearer fake-wrong"}
        )
        missing = echo_call(url)
        bare = modern_post(
            url, "tools/call", {"name": "echo"}, headers={"authorization": "fake-key-1"}
        )
    assert wrong.status_code == 401
    assert wrong.json()["error_description"] == "Unknown key: fake-wrong"
    assert missing.json() == {"error": "invalid_token"}
    assert bare.json()["error_description"] == "Unknown key: fake-key-1"


async def test_a_bearer_check_replaces_the_key() -> None:
    """Whatever ``authorize`` accepts now, in the bearer form only; the key no longer counts."""
    live = {"token-1"}
    fake = McpFake(key="fake-key-1", key_header="x-api-key", authorize=live.__contains__)
    with running(fake) as url:

        def call(headers: dict[str, str]) -> int:
            params = {"name": "echo", "arguments": {"text": "hi"}}
            return modern_post(url, "tools/call", params, headers=headers).status_code

        statuses = [
            call({"authorization": "Bearer token-1"}),
            call({"authorization": "token-1"}),
            call({"x-api-key": "fake-key-1"}),
            call({"authorization": "Bearer fake-key-1"}),
        ]
        live.clear()  # revoked
        statuses.append(call({"authorization": "Bearer token-1"}))
        live.add("token-2")  # refreshed
        async with connect(url, headers={"authorization": "Bearer token-2"}) as client:
            result = await client.call_tool("echo", {"text": "hi"})
    assert statuses == [200, 401, 401, 401, 401]
    assert text_of(result) == "hi"


@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_the_well_behaved_tools(mode: str) -> None:
    fake = McpFake()
    with running(fake) as url:
        async with connect(url, mode=mode) as client:
            await client.list_tools()
            echo = await client.call_tool("echo", {"text": "hello"})
            added = await client.call_tool("add", {"a": 1, "b": 2.5})
            report = await client.call_tool("report", {})
    assert text_of(echo) == "hello"
    assert text_of(added) == "3.5"
    assert report.structured_content == {"total": 3, "items": ["alpha", "beta", "gamma"]}
    assert not report.is_error


async def test_counter_keeps_state_per_legacy_session() -> None:
    fake = McpFake()
    with running(fake) as url:
        async with connect(url, mode="legacy") as first, connect(url, mode="legacy") as second:
            counts = [
                text_of(await first.call_tool("counter", {})),
                text_of(await first.call_tool("counter", {})),
                text_of(await second.call_tool("counter", {})),
            ]
    assert counts == ["1", "2", "1"]


async def test_lookup_has_a_valid_x_mcp_header() -> None:
    fake = McpFake()
    with running(fake) as url:
        async with connect(url) as client:
            await client.list_tools()
            modern = await client.call_tool("lookup", {"region": "eu", "query": "q"})
        async with connect(url, mode="legacy") as client:
            await client.list_tools()
            legacy = await client.call_tool("lookup", {"region": "eu"})
    assert text_of(modern) == "region=eu header=eu"
    assert text_of(legacy) == "region=eu header=None"
    modern_call, legacy_call = fake.requests("tools/call")
    assert modern_call.header("mcp-param-region") == "eu"
    assert legacy_call.header("mcp-param-region") is None


@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_slow_reports_progress_and_honours_cancellation(mode: str) -> None:
    fake = McpFake()
    values: list[float] = []
    scope = anyio.CancelScope()

    async def on_progress(progress: float, total: float | None, message: str | None) -> None:
        values.append(progress)
        if len(values) >= 3:
            scope.cancel()

    with running(fake) as url:
        async with connect(url, mode=mode) as client:
            with anyio.fail_after(20), scope:
                await client.call_tool(
                    "slow", {"steps": 100, "interval": 0.05}, progress_callback=on_progress
                )
            left = time.monotonic()
            assert scope.cancelled_caught
            assert await anyio.to_thread.run_sync(fake.cancelled.wait, 5)
    assert values[:3] == [0, 1, 2]
    [cancelled] = fake.cancellations
    assert cancelled - left < 2
    [call] = fake.requests("tools/call")
    if mode == "auto":
        assert call.disconnected
    else:
        [notification] = fake.requests("notifications/cancelled")
        assert notification.params["requestId"] == call.message["id"]


async def test_slow_finishes_when_left_alone() -> None:
    fake = McpFake()
    with running(fake) as url:
        async with connect(url) as client:
            result = await client.call_tool("slow", {"steps": 2, "interval": 0})
    assert text_of(result) == "done after 2 steps"
    assert not fake.cancelled.is_set()


async def test_an_unknown_tool_is_an_error() -> None:
    fake = McpFake()
    with running(fake) as url:
        response = modern_post(url, "tools/call", {"name": "missing", "arguments": {}})
    assert response.json()["error"]["code"] == types.INVALID_PARAMS
    assert response.json()["error"]["message"] == "Unknown tool: missing"


# --- drift --------------------------------------------------------------------------------------


MISSING = object()
# What each drift member changes: the tool, and each changed JSON path with its new value.
DRIFTS: dict[DriftMember, tuple[str, dict[tuple[str | int, ...], Any]]] = {
    "description": (
        "echo",
        {("description",): "Returns the text it is given, and keeps a copy."},
    ),
    "parameter": (
        "echo",
        {
            ("inputSchema", "properties", "text"): MISSING,
            ("inputSchema", "properties", "message"): {
                "type": "string",
                "description": "The text to return.",
            },
            ("inputSchema", "required", 0): "message",
        },
    ),
    "enum": ("add", {("inputSchema", "properties", "rounding", "enum", 1): "ceil"}),
    "default": ("add", {("inputSchema", "properties", "rounding", "default"): "floor"}),
    "nested_description": (
        "report",
        {
            (
                "inputSchema",
                "properties",
                "options",
                "properties",
                "verbose",
                "description",
            ): "Include every item and its owner."
        },
    ),
    "x_mcp_header": ("lookup", {("inputSchema", "properties", "region", "x-mcp-header"): "Zone"}),
    "annotations": (
        "echo",
        {("annotations", "readOnlyHint"): False, ("annotations", "destructiveHint"): True},
    ),
    "title": ("echo", {("title",): "Echo (new)"}),
    "output_schema": ("report", {("outputSchema", "properties", "total", "type"): "string"}),
}


def changes(
    old: Any, new: Any, path: tuple[str | int, ...] = ()
) -> dict[tuple[str | int, ...], Any]:
    """Each JSON path where ``new`` differs from ``old``, with its new value."""
    found: dict[tuple[str | int, ...], Any] = {}
    if isinstance(old, dict) and isinstance(new, dict):
        for key in old.keys() | new.keys():
            found.update(changes(old.get(key, MISSING), new.get(key, MISSING), (*path, key)))
        return found
    if isinstance(old, list) and isinstance(new, list) and len(old) == len(new):
        for index, (a, b) in enumerate(zip(old, new, strict=True)):
            found.update(changes(a, b, (*path, index)))
        return found
    return {} if old == new else {path: new}


@pytest.mark.parametrize("member", DRIFT_MEMBERS)
def test_apply_drift_changes_exactly_the_member_it_names(member: DriftMember) -> None:
    base = base_tools()
    changed = apply_drift(base, member)
    assert base == base_tools()
    if member == "removed":
        assert changed == [tool for tool in base if tool["name"] != "add"]
        return
    name, expected = DRIFTS[member]
    differing = {
        old["name"]: changes(old, new) for old, new in zip(base, changed, strict=True) if old != new
    }
    assert differing == {name: expected}


@pytest.mark.parametrize("member", DRIFT_MEMBERS)
async def test_drift_changes_a_member_after_n_lists(member: DriftMember) -> None:
    fake = McpFake(drift=Drift(member, after=2))
    with running(fake) as url:
        async with connect(url) as client:
            listings = [dumped(await client.list_tools()) for _ in range(3)]
    assert listings[0] == listings[1] == wire_tools(base_tools())
    assert listings[2] == wire_tools(apply_drift(base_tools(), member))
    assert listings[2] != listings[1]
    assert fake.lists == 3
    assert fake.announced == 0


async def test_drift_announced_on_the_legacy_get_stream() -> None:
    fake = McpFake(drift=Drift("description", after=1, notify=True))
    notifications = Notifications()
    with running(fake) as url:
        async with connect(url, mode="legacy", message_handler=notifications) as client:
            await until(lambda: any(r.method == "GET" and r.status == 200 for r in fake.received))
            before = dumped(await client.list_tools())
            await until(lambda: notifications.count("notifications/tools/list_changed") == 1)
            after = dumped(await client.list_tools())
    assert before == wire_tools(base_tools())
    assert after == wire_tools(apply_drift(base_tools(), "description"))
    assert fake.announced == 1


async def test_drift_announced_on_a_modern_listen_stream() -> None:
    fake = McpFake(drift=Drift("parameter", after=1, notify=True))
    with running(fake) as url:
        async with connect(url) as client, client.listen(tools_list_changed=True) as events:
            before = dumped(await client.list_tools())
            with anyio.fail_after(5):
                event = await events.__anext__()
            after = dumped(await client.list_tools())
    assert type(event).__name__ == "ToolsListChanged"
    assert before != after == wire_tools(apply_drift(base_tools(), "parameter"))


async def test_silent_drift_sends_nothing() -> None:
    fake = McpFake(drift=Drift("title", after=1))
    notifications = Notifications()
    with running(fake) as url:
        async with connect(url, mode="legacy", message_handler=notifications) as client:
            await client.list_tools()
            await anyio.sleep(0.3)
            changed = dumped(await client.list_tools())
    assert notifications.methods == []
    assert changed == wire_tools(apply_drift(base_tools(), "title"))


async def test_drift_flips_back_and_announces_both_changes() -> None:
    """Announced after the last unchanged listing (1) and the last changed one (3)."""
    fake = McpFake(drift=Drift("enum", after=1, notify=True, flip_back_after=2))
    listings: list[list[dict[str, Any]]] = []
    announced: list[int] = []
    with running(fake) as url:
        async with connect(url) as client:
            for expected in (1, 1, 2, 2):
                listings.append(dumped(await client.list_tools()))
                # Long enough for an announcement that isn't expected to show up too.
                await anyio.sleep(ANNOUNCE_DELAY * 4)

                def reached(count: int = expected) -> bool:
                    return fake.announced >= count

                await until(reached)
                announced.append(fake.announced)
    base, changed = wire_tools(base_tools()), wire_tools(apply_drift(base_tools(), "enum"))
    assert listings == [base, changed, changed, base]
    assert announced == [1, 1, 2, 2]


async def test_definitions_differ_per_legacy_session() -> None:
    fake = McpFake(switches={Switch.PER_SESSION})
    with running(fake) as url:
        async with connect(url, mode="legacy") as first, connect(url, mode="legacy") as second:
            one = (await first.list_tools()).tools[0].description
            two = (await second.list_tools()).tools[0].description
            again = (await first.list_tools()).tools[0].description
    assert one == again == "Returns the text it is given. Session 1."
    assert two == "Returns the text it is given. Session 2."


async def test_per_session_definitions_leave_modern_listings_alone() -> None:
    fake = McpFake(switches={Switch.PER_SESSION})
    with running(fake) as url:
        async with connect(url) as client:
            listing = dumped(await client.list_tools())
    assert listing == wire_tools(base_tools())


async def test_a_clean_list_for_the_first_session_only() -> None:
    fake = McpFake(switches={Switch.CLEAN_FIRST_SESSION})
    with running(fake) as url:
        async with connect(url, mode="legacy") as review:
            clean = dumped(await review.list_tools())
        async with connect(url, mode="legacy") as later:
            served = dumped(await later.list_tools())
        async with connect(url) as modern:
            modern_served = dumped(await modern.list_tools())
    assert clean == wire_tools(base_tools())
    assert served == modern_served == wire_tools(apply_drift(base_tools(), "description"))


async def test_a_duplicate_tool() -> None:
    fake = McpFake(switches={Switch.DUPLICATE_TOOL})
    with running(fake) as url:
        response = modern_post(url, "tools/list")
    tools = response.json()["result"]["tools"]
    assert [tool["name"] for tool in tools] == [*BASE_NAMES, "echo"]
    assert tools[0]["description"] != tools[-1]["description"]


# --- injection ----------------------------------------------------------------------------------


async def test_injected_definitions() -> None:
    fake = McpFake(switches={Switch.INJECT_DEFINITIONS})
    with running(fake) as url:
        async with connect(url) as client:
            listing = await client.list_tools()
    tool = listing.tools[-1]
    assert tool.name == "summarize"
    assert tool.description is not None
    assert IMPORTANT in tool.description
    assert ZERO_WIDTH in tool.description
    assert TAG_TEXT in tool.description
    assert tool.title == f"Summarize{ZERO_WIDTH}"
    properties = tool.input_schema["properties"]
    assert HOSTILE_PARAMETER in properties
    assert BIDI_OVERRIDE in properties["path"]["description"]
    enum = properties[f"mode{TAG_TEXT}"]["enum"]
    assert enum == ["short", f"long{ZERO_WIDTH}", f"{ANSI}all", f"{C1_CSI}x"]


async def test_an_invalid_tool_name() -> None:
    fake = McpFake(switches={Switch.INVALID_NAME})
    with running(fake) as url:
        response = modern_post(url, "tools/list")
    assert response.json()["result"]["tools"][-1]["name"] == INVALID_NAME


async def test_icons_meta_execution_and_unknown_fields_on_a_tool() -> None:
    fake = McpFake(switches={Switch.TOOL_EXTRAS})
    with running(fake) as url:
        response = modern_post(url, "tools/list")
        async with connect(url, mode="legacy") as client:
            parsed = (await client.list_tools()).tools[0]
    echo = response.json()["result"]["tools"][0]
    assert echo["icons"][0]["mimeType"] == "image/svg+xml"
    assert echo["_meta"] == {"io.example/hint": HOSTILE}
    assert echo["execution"] == {"taskSupport": "optional"}
    assert echo["x-unknown"] == {"instructions": HOSTILE}
    assert parsed.icons is not None
    assert parsed.meta == {"io.example/hint": HOSTILE}


@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_injected_instructions_and_server_info(mode: str) -> None:
    fake = McpFake(switches={Switch.INJECT_SERVER_INFO})
    with running(fake) as url:
        async with connect(url, mode=mode) as client:
            instructions = client.instructions
            info = client.server_info
            response = modern_post(url, "tools/list")
    assert instructions == HOSTILE
    assert info is not None
    assert (info.name, info.title, info.description) == (f"fake{ZERO_WIDTH}", HOSTILE, HOSTILE)
    stamp = response.json()["result"]["_meta"][types.SERVER_INFO_META_KEY]
    assert stamp["title"] == HOSTILE


async def test_the_hostile_stamp_is_on_modern_calls_and_not_legacy_listings() -> None:
    fake = McpFake(switches={Switch.INJECT_SERVER_INFO})
    with running(fake) as url:
        call = echo_call(url).json()["result"]
        async with connect(url, mode="legacy") as client:
            await client.list_tools()
    assert call["resultType"] == "complete"
    assert call["_meta"][types.SERVER_INFO_META_KEY]["title"] == HOSTILE
    [legacy_listing] = fake.requests("tools/list")
    [answer] = sse_messages(legacy_listing.response.decode())
    assert "_meta" not in answer["result"]


@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_injected_results(mode: str) -> None:
    fake = McpFake(switches={Switch.INJECT_RESULTS})
    with running(fake) as url:
        async with connect(url, mode=mode) as client:
            result = await client.call_tool("echo", {"text": "hi"})
    text, link, embedded, image = result.content
    assert isinstance(text, types.TextContent)
    assert HOSTILE in text.text
    assert FAKE_END_MARKER in text.text
    assert isinstance(link, types.ResourceLink)
    assert link.description == HOSTILE
    assert isinstance(embedded, types.EmbeddedResource)
    assert isinstance(image, types.ImageContent)
    assert image.mime_type == "image/svg+xml"
    assert result.structured_content == {"note": HOSTILE, "nested": {"items": [HOSTILE]}}


async def test_injected_error_text() -> None:
    fake = McpFake(switches={Switch.INJECT_ERROR})
    with running(fake) as url:
        async with connect(url) as client:
            result = await client.call_tool("echo", {"text": "hi"})
    assert result.is_error
    assert text_of(result) == HOSTILE


@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_injected_progress_and_log_messages(mode: str) -> None:
    fake = McpFake(switches={Switch.INJECT_PROGRESS, Switch.INJECT_LOG})
    messages: list[str | None] = []
    logged: list[Any] = []

    async def on_progress(progress: float, total: float | None, message: str | None) -> None:
        messages.append(message)

    async def on_log(params: types.LoggingMessageNotificationParams) -> None:
        logged.append(params.data)

    with running(fake) as url:
        async with connect(url, mode=mode, logging_callback=on_log) as client:
            await client.list_tools()
            result = await client.call_tool("echo", {"text": "hi"}, progress_callback=on_progress)
    assert text_of(result) == "hi"
    assert messages == [HOSTILE]
    assert logged == [HOSTILE]


@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_injected_json_rpc_error_text(mode: str) -> None:
    fake = McpFake(switches={Switch.INJECT_RPC_ERROR})
    with running(fake) as url:
        async with connect(url, mode=mode) as client:
            with pytest.raises(MCPError) as raised:
                await client.call_tool("echo", {"text": "hi"})
    assert raised.value.error.message == HOSTILE
    assert raised.value.error.data == {"hint": HOSTILE}


# --- back channel -------------------------------------------------------------------------------


@pytest.mark.parametrize("stream", ["call", "get"])
@pytest.mark.parametrize("kind", [kind for kind in BACK_CHANNELS if kind != "state_only"])
async def test_legacy_server_requests_get_error_answers(
    kind: BackChannel, stream: BackChannelStream
) -> None:
    fake = McpFake(back_channel=kind, back_channel_stream=stream)
    with running(fake) as url:
        async with connect(url, mode="legacy") as client:
            await client.list_tools()
            await until(lambda: any(r.method == "GET" and r.status == 200 for r in fake.received))
            result = await client.call_tool("echo", {"text": "hi"})
    assert text_of(result) == "hi"
    assert fake.answers == [BackChannelAnswer(kind, stream, "error -32600")]
    [initialize] = fake.requests("initialize")
    assert initialize.params["capabilities"] == {}
    answers = [item.message for item in fake.received if item.rpc_method is None and item.message]
    assert [answer["error"]["code"] for answer in answers] == [-32600]
    assert_sent_on(fake, kind, stream)


def assert_sent_on(fake: McpFake, kind: BackChannel, stream: BackChannelStream) -> None:
    """The server's request went out on ``stream`` and not on the other one."""
    [call] = fake.requests("tools/call")
    [get] = [item for item in fake.received if item.method == "GET" and item.status == 200]
    method = SERVER_METHODS[kind]
    on_call = method in sent_methods(call)
    on_get = method in sent_methods(get)
    assert (on_call, on_get) == (stream == "call", stream == "get")


SERVER_METHODS: dict[BackChannel, str] = {
    "sampling": "sampling/createMessage",
    "elicit_form": "elicitation/create",
    "elicit_url": "elicitation/create",
    "roots": "roots/list",
}


def sent_methods(record: Recorded) -> list[str]:
    """The JSON-RPC methods in the SSE events the fake sent in answer to ``record``."""
    return [str(m.get("method")) for m in sse_messages(record.response.decode()) if "method" in m]


async def answer_sampling(
    context: Any, params: types.CreateMessageRequestParams
) -> types.CreateMessageResult:
    content = types.TextContent(type="text", text="fake answer")
    return types.CreateMessageResult(role="assistant", content=content, model="fake-model")


async def answer_elicitation(context: Any, params: types.ElicitRequestParams) -> types.ElicitResult:
    return types.ElicitResult(action="decline")


async def answer_roots(context: Any) -> types.ListRootsResult:
    return types.ListRootsResult(roots=[])


CALLBACKS: dict[str, Any] = {
    "sampling_callback": answer_sampling,
    "elicitation_callback": answer_elicitation,
    "list_roots_callback": answer_roots,
}


@pytest.mark.parametrize("stream", ["call", "get"])
@pytest.mark.parametrize("kind", [kind for kind in BACK_CHANNELS if kind != "state_only"])
async def test_legacy_server_requests_answered_by_a_client_that_can(
    kind: BackChannel, stream: BackChannelStream
) -> None:
    fake = McpFake(back_channel=kind, back_channel_stream=stream)
    with running(fake) as url:
        async with connect(url, mode="legacy", **CALLBACKS) as client:
            await client.list_tools()
            await until(lambda: any(r.method == "GET" and r.status == 200 for r in fake.received))
            result = await client.call_tool("echo", {"text": "hi"})
    assert text_of(result) == "hi"
    assert fake.answers == [BackChannelAnswer(kind, stream, "answered")]
    [initialize] = fake.requests("initialize")
    assert initialize.params["capabilities"] != {}
    assert_sent_on(fake, kind, stream)


async def test_a_legacy_server_request_with_no_get_stream_times_out() -> None:
    """With no GET stream open, the SDK drops the request; the fake waits, then answers."""
    fake = McpFake(back_channel="roots", back_channel_stream="get", back_channel_timeout=0.3)
    with running(fake) as url:
        session = legacy_session(url)
        wire = {**ACCEPT, "mcp-session-id": session, "mcp-protocol-version": LEGACY_VERSION}
        body = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "echo", "arguments": {"text": "hi"}},
        }
        response = httpx.post(url, json=body, headers=wire, timeout=10)
    [message] = sse_messages(response.text)
    assert message["result"]["content"][0]["text"] == "hi"
    # The SDK reports the timeout as a JSON-RPC error.
    timeout = f"error {types.REQUEST_TIMEOUT}"
    assert fake.answers == [BackChannelAnswer("roots", "get", timeout)]
    assert types.REQUEST_TIMEOUT == -32001


def legacy_session(url: str) -> str:
    """A raw handshake-era session, with no GET stream. Returns its id."""
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": LEGACY_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "raw", "version": "1.0.0"},
        },
    }
    response = httpx.post(url, json=body, headers=ACCEPT, timeout=10)
    session = response.headers["mcp-session-id"]
    initialized = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    wire = {**ACCEPT, "mcp-session-id": session, "mcp-protocol-version": LEGACY_VERSION}
    assert httpx.post(url, json=initialized, headers=wire, timeout=10).status_code == 202
    return session


async def test_legacy_state_only_asks_nothing() -> None:
    fake = McpFake(back_channel="state_only")
    with running(fake) as url:
        async with connect(url, mode="legacy") as client:
            await client.list_tools()
            result = await client.call_tool("echo", {"text": "hi"})
    assert text_of(result) == "hi"
    assert fake.answers == []


@pytest.mark.parametrize("kind", [kind for kind in BACK_CHANNELS if kind != "state_only"])
async def test_modern_input_required_without_callbacks_is_not_retried(kind: BackChannel) -> None:
    fake = McpFake(back_channel=kind)
    with running(fake) as url:
        response = echo_call(url)
        async with connect(url) as client:
            await client.list_tools()
            with pytest.raises(MCPError):
                await client.call_tool("echo", {"text": "hi"})
    result = response.json()["result"]
    assert result["resultType"] == "input_required"
    assert result["requestState"] == REQUEST_STATE
    [request] = result["inputRequests"].values()
    assert request["method"] == SERVER_METHODS[kind]
    assert [call.retry for call in fake.calls] == [False, False]


@pytest.mark.parametrize("kind", [kind for kind in BACK_CHANNELS if kind != "state_only"])
async def test_modern_input_required_answered_by_a_client_that_can(kind: BackChannel) -> None:
    fake = McpFake(back_channel=kind)
    with running(fake) as url:
        async with connect(url, **CALLBACKS) as client:
            await client.list_tools()
            result = await client.call_tool("echo", {"text": "hi"})
    assert text_of(result) == "hi"
    assert [call.retry for call in fake.calls] == [False, True]
    retry = fake.requests("tools/call")[-1].params
    assert list(retry["inputResponses"]) == ["ask-1"]
    assert retry["requestState"] == REQUEST_STATE


async def test_input_responses_alone_make_a_retry() -> None:
    fake = McpFake(back_channel="roots")
    with running(fake) as url:
        response = modern_post(
            url,
            "tools/call",
            {
                "name": "echo",
                "arguments": {"text": "hi"},
                "inputResponses": {"ask-1": {"roots": []}},
            },
        )
    assert response.json()["result"]["content"][0]["text"] == "hi"
    assert [call.retry for call in fake.calls] == [True]


async def test_modern_input_required_with_only_request_state() -> None:
    fake = McpFake(back_channel="state_only")
    with running(fake) as url:
        response = echo_call(url)
        async with connect(url) as client:
            await client.list_tools()
            result = await client.call_tool("echo", {"text": "hi"})
    assert response.json()["result"] == {
        "resultType": "input_required",
        "requestState": REQUEST_STATE,
    }
    # The SDK has nothing to ask, so it retries with the state; the fake then answers.
    assert text_of(result) == "hi"
    assert [call.retry for call in fake.calls] == [False, False, True]
    assert fake.requests("tools/call")[-1].params["requestState"] == REQUEST_STATE


# --- secret echo --------------------------------------------------------------------------------


async def test_the_key_in_a_json_rpc_error_json_body() -> None:
    fake = McpFake(key="fake-key-1", switches={Switch.ECHO_ERROR_JSON})
    with running(fake) as url:
        response = modern_post(
            url, "tools/call", {"name": "echo"}, headers={"authorization": "Bearer fake-key-1"}
        )
    assert response.headers["content-type"] == "application/json"
    assert response.json()["error"] == {
        "code": -32000,
        "message": "Upstream refused key fake-key-1",
        "data": {"key": "fake-key-1"},
    }


async def test_the_key_in_a_json_rpc_error_sse_event() -> None:
    fake = McpFake(switches={Switch.ECHO_ERROR_SSE})
    with running(fake) as url:
        response = echo_call(url)
    assert response.headers["content-type"] == "text/event-stream"
    [message] = sse_messages(response.text)
    assert message["id"] == 7
    assert message["error"]["message"] == f"Upstream refused key {DEFAULT_KEY}"


async def test_the_key_in_result_text_split_across_writes() -> None:
    fake = McpFake(switches={Switch.ECHO_SPLIT})
    with running(fake) as url:
        meta = {
            "io.modelcontextprotocol/protocolVersion": MODERN_VERSION,
            "io.modelcontextprotocol/clientCapabilities": {},
        }
        body = {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {"name": "echo", "_meta": meta},
        }
        with httpx.stream("POST", url, json=body, headers=ACCEPT, timeout=10) as response:
            chunks = list(response.iter_raw())
    joined = b"".join(chunks)
    first = chunks[0]
    half = len(DEFAULT_KEY) // 2
    assert first.endswith(DEFAULT_KEY[:half].encode())
    assert DEFAULT_KEY.encode() not in first
    [message] = sse_messages(joined.decode())
    assert message["result"]["content"][0]["text"] == f"Your key is {DEFAULT_KEY}."


ENCODING_SWITCHES = [
    Switch.ECHO_PERCENT,
    Switch.ECHO_BASE64,
    Switch.ECHO_BASE64URL,
    Switch.ECHO_JSON_ESCAPED,
]


@pytest.mark.parametrize("switch", ENCODING_SWITCHES)
async def test_the_key_encoded(switch: Switch) -> None:
    fake = McpFake(switches={switch})
    with running(fake) as url:
        response = echo_call(url)
    form = encoded_form(DEFAULT_KEY, switch)
    assert form != DEFAULT_KEY
    assert form.encode() in response.content
    assert DEFAULT_KEY.encode() not in response.content
    [message] = sse_messages(response.text)
    text = message["result"]["content"][0]["text"]
    if switch == Switch.ECHO_JSON_ESCAPED:
        assert text == f"Your key is {DEFAULT_KEY}."
    else:
        assert text == f"Your key is {form}."


def test_encoded_forms() -> None:
    assert encoded_form("a/b+c=", Switch.ECHO_PERCENT) == "a%2Fb%2Bc%3D"
    assert encoded_form("a/b+c=", Switch.ECHO_BASE64) == "YS9iK2M9"
    assert encoded_form("ab?>", Switch.ECHO_BASE64URL) == "YWI_Pg"
    assert encoded_form('a/"b', Switch.ECHO_JSON_ESCAPED) == 'a\\/\\"b'
    assert encoded_form(DEFAULT_KEY, Switch.ECHO_JSON_ESCAPED) == "fake-key\\/0001+test="
    with pytest.raises(ValueError, match="not an encoding switch"):
        encoded_form("ab", Switch.ECHO_SPLIT)


@pytest.mark.parametrize("switch", ENCODING_SWITCHES)
def test_the_vault_scrubs_every_encoded_form(switch: Switch) -> None:
    """The fake and the vault agree on the forms (design J.2), so G13 can pass."""
    scrubbed, count = scrub(encoded_event(1, DEFAULT_KEY, switch), secret_variants(DEFAULT_KEY))
    assert count == 1
    assert encoded_form(DEFAULT_KEY, switch).encode() not in scrubbed


async def test_the_key_in_a_json_body_over_1_mib() -> None:
    fake = McpFake(switches={Switch.ECHO_LARGE_JSON})
    with running(fake) as url:
        response = echo_call(url)
    assert response.headers["content-type"] == "application/json"
    text = response.json()["result"]["content"][0]["text"]
    assert len(text) > MIB
    assert text.endswith(f" {DEFAULT_KEY}")


async def test_the_key_in_a_response_header() -> None:
    fake = McpFake(switches={Switch.ECHO_HEADER})
    with running(fake) as url:
        async with connect(url, mode="legacy") as client:
            await client.call_tool("echo", {"text": "hi"})
        response = modern_post(url, "tools/list")
        other = httpx.get(url.replace("/mcp", SCHEMA_PATH))
    assert response.headers["x-upstream-debug"] == f"key={DEFAULT_KEY}"
    assert "x-upstream-debug" not in other.headers
    assert all(item.status == 200 for item in fake.requests("tools/call"))


async def test_the_key_in_an_sse_event_over_the_cap() -> None:
    fake = McpFake(switches={Switch.ECHO_OVERSIZE_EVENT}, big_event_bytes=64 * 1024)
    with running(fake) as url:
        response = echo_call(url)
    [message] = sse_messages(response.text)
    text = message["result"]["content"][0]["text"]
    assert len(text) > 64 * 1024
    assert text.endswith(f" {DEFAULT_KEY}")
    assert EVENT_CAP == MAX_STREAM_EVENT_BYTES
    assert McpFake().big_event_bytes > EVENT_CAP


async def test_wire_switches_act_on_echo_only() -> None:
    fake = McpFake(switches={Switch.ECHO_ERROR_JSON})
    with running(fake) as url:
        async with connect(url) as client:
            added = await client.call_tool("add", {"a": 1, "b": 1})
    assert text_of(added) == "2"


async def test_a_redirect_comes_before_a_wire_switch() -> None:
    fake = McpFake(redirect="/mail/send", switches={Switch.ECHO_ERROR_JSON})
    with running(fake) as url:
        response = echo_call(url)
    assert response.status_code == 307


# --- protocol -----------------------------------------------------------------------------------


async def test_an_endless_cursor() -> None:
    fake = McpFake(switches={Switch.ENDLESS_CURSOR})
    cursors: list[str | None] = []
    pages: list[list[str]] = []
    with running(fake) as url:
        async with connect(url) as client:
            cursor = None
            for _ in range(4):
                page = await client.list_tools(cursor=cursor)
                cursor = page.next_cursor
                cursors.append(cursor)
                pages.append([tool.name for tool in page.tools])
    assert cursors == ["next-1", "next-2", "next-3", "next-4"]
    assert pages == [BASE_NAMES, [], [], []]
    assert fake.lists == 1


async def test_a_repeated_cursor() -> None:
    fake = McpFake(switches={Switch.REPEAT_CURSOR})
    with running(fake) as url:
        async with connect(url) as client:
            first = await client.list_tools()
            second = await client.list_tools(cursor=first.next_cursor)
    assert (first.next_cursor, second.next_cursor) == ("again", "again")
    assert [tool.name for tool in first.tools] == BASE_NAMES
    assert second.tools == []


async def test_a_thousand_pages() -> None:
    fake = McpFake(pages=1000)
    names: list[str] = []
    with running(fake) as url:
        async with connect(url) as client:
            cursor = None
            for _ in range(7):
                page = await client.list_tools(cursor=cursor)
                names.extend(tool.name for tool in page.tools)
                cursor = page.next_cursor
            assert cursor == "page-7"
            near_end = await client.list_tools(cursor="page-998")
            last = await client.list_tools(cursor="page-999")
    assert names == BASE_NAMES
    assert (near_end.tools, near_end.next_cursor) == ([], "page-999")
    assert (last.tools, last.next_cursor) == ([], None)


async def test_pages_spread_the_tools() -> None:
    fake = McpFake(pages=3)
    with running(fake) as url:
        async with connect(url) as client:
            first = await client.list_tools()
            second = await client.list_tools(cursor=first.next_cursor)
            third = await client.list_tools(cursor=second.next_cursor)
    assert [[tool.name for tool in page.tools] for page in (first, second, third)] == [
        ["echo"],
        ["add"],
        BASE_NAMES[2:],
    ]
    assert (first.next_cursor, second.next_cursor, third.next_cursor) == ("page-1", "page-2", None)


async def test_a_page_over_the_byte_cap() -> None:
    fake = McpFake(page_bytes=300_000)
    with running(fake) as url:
        first = modern_post(url, "tools/list")
    assert len(first.content) > 300_000
    assert first.json()["result"]["tools"][-1]["name"] == "bulky"


async def test_only_the_first_page_is_bulky() -> None:
    fake = McpFake(pages=2, page_bytes=1000)
    with running(fake) as url:
        async with connect(url) as client:
            first = await client.list_tools()
            second = await client.list_tools(cursor=first.next_cursor)
    assert [tool.name for tool in first.tools] == ["echo", "bulky"]
    assert first.tools[-1].description == "b" * 1000
    assert [tool.name for tool in second.tools] == BASE_NAMES[1:]
    assert second.next_cursor is None


async def test_a_session_expires_after_n_calls() -> None:
    fake = McpFake(session_404_after=2)
    with running(fake) as url:
        async with connect(url, mode="legacy") as client:
            await client.list_tools()
            await client.call_tool("echo", {"text": "1"})
            await client.call_tool("echo", {"text": "2"})
            with pytest.raises(MCPError):
                await client.call_tool("echo", {"text": "3"})
    assert [item.status for item in fake.requests("tools/call")] == [200, 200, 404]


async def test_a_list_changed_flood() -> None:
    fake = McpFake(flood=5)
    notifications = Notifications()
    with running(fake) as url:
        async with connect(url, mode="legacy", message_handler=notifications) as client:
            await until(lambda: any(r.method == "GET" and r.status == 200 for r in fake.received))
            await client.list_tools()
            await until(lambda: notifications.count("notifications/tools/list_changed") == 5)
    assert fake.announced == 5


async def test_announce_from_the_test_thread() -> None:
    fake = McpFake()
    notifications = Notifications()
    with running(fake) as url:
        async with connect(url, mode="legacy", message_handler=notifications) as client:
            await client.list_tools()
            await until(lambda: any(r.method == "GET" and r.status == 200 for r in fake.received))
            await anyio.to_thread.run_sync(fake.announce)
            await until(lambda: notifications.count("notifications/tools/list_changed") == 1)
    with pytest.raises(RuntimeError, match="not running"):
        McpFake().announce()


class DeadSession:
    async def send_tool_list_changed(self) -> None:
        raise anyio.ClosedResourceError


async def test_an_announcement_drops_a_dead_session() -> None:
    fake = McpFake()
    with running(fake):
        fake._sessions["dead"] = cast("ServerSession", DeadSession())
        await anyio.to_thread.run_sync(fake.announce)
    assert "dead" not in fake._sessions
    assert fake.announced == 1


async def test_a_client_that_leaves_during_the_body_is_noted() -> None:
    messages: list[Message] = [
        {"type": "http.request", "body": b"part", "more_body": True},
        {"type": "http.disconnect"},
    ]

    async def receive() -> Message:
        return messages.pop(0)

    assert await _read_body(receive) == (b"part", True)


async def test_a_redirect_to_another_route() -> None:
    fake = McpFake(redirect="/mail/send")
    with running(fake) as url:
        response = echo_call(url)
        async with connect(url) as client:
            await client.list_tools()
            with pytest.raises(MCPError):
                await client.call_tool("echo", {"text": "hi"})
    assert response.status_code == 307
    assert response.headers["location"] == "/mail/send"
    # The SDK follows a same-origin 307: the reason the gateway needs an egress filter.
    assert [item.path for item in fake.received if item.path != "/mcp"] == ["/mail/send"]


async def test_a_redirect_to_an_absolute_url() -> None:
    fake = McpFake(redirect="https://elsewhere.example/mcp")
    with running(fake) as url:
        response = echo_call(url)
    assert response.status_code == 307
    assert response.headers["location"] == "https://elsewhere.example/mcp"


@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_an_unsupported_version(mode: str) -> None:
    fake = McpFake(switches={Switch.UNSUPPORTED_VERSION})
    with running(fake) as url:
        discover = modern_post(url, "server/discover")
        async with connect(url, mode=mode) as client:
            version = client.protocol_version
    assert discover.json()["result"]["supportedVersions"] == [UNSUPPORTED_VERSION]
    assert version == UNSUPPORTED_VERSION


async def test_a_task_result() -> None:
    fake = McpFake(switches={Switch.TASK_RESULT})
    with running(fake) as url:
        response = echo_call(url)
    result = response.json()["result"]
    assert result["resultType"] == "task"
    assert result["task"]["status"] == "working"


async def test_malformed_json() -> None:
    fake = McpFake(switches={Switch.MALFORMED_JSON})
    with running(fake) as url:
        response = echo_call(url)
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    with pytest.raises(ValueError, match="Expecting value"):
        json.loads(response.content)


async def test_a_batch_response() -> None:
    fake = McpFake(switches={Switch.BATCH_RESPONSE})
    with running(fake) as url:
        response = echo_call(url)
    first, second = response.json()
    assert first["id"] == second["id"] == 7
    assert first["result"] != second["result"]


# --- schemas ------------------------------------------------------------------------------------

SCHEMA_SWITCHES = [
    Switch.SCHEMA_REMOTE_REF,
    Switch.SCHEMA_FILE_REF,
    Switch.SCHEMA_ID,
    Switch.SCHEMA_DIALECT,
    Switch.SCHEMA_DEEP,
    Switch.SCHEMA_REDOS,
    Switch.SCHEMA_DOLLAR,
]


def json_depth(value: Any) -> int:
    if isinstance(value, dict):
        return 1 + max((json_depth(item) for item in value.values()), default=0)
    if isinstance(value, list):
        return 1 + max((json_depth(item) for item in value), default=0)
    return 0


@pytest.mark.parametrize("switch", [s for s in SCHEMA_SWITCHES if s != Switch.SCHEMA_DEEP])
async def test_hostile_schemas(switch: Switch) -> None:
    fake = McpFake(switches={switch})
    with running(fake) as url:
        async with connect(url) as client:
            tools = (await client.list_tools()).tools
    assert [tool.name for tool in tools] == [*BASE_NAMES, switch.value]
    schema = tools[-1].input_schema
    expected: dict[Switch, Callable[[dict[str, Any]], bool]] = {
        Switch.SCHEMA_REMOTE_REF: lambda s: s["properties"]["item"] == {"$ref": REF_URL},
        Switch.SCHEMA_FILE_REF: lambda s: s["properties"]["item"] == {"$ref": FILE_REF},
        Switch.SCHEMA_ID: lambda s: s["$id"].startswith("https://attacker.example/"),
        Switch.SCHEMA_DIALECT: lambda s: s["$schema"] == "https://attacker.example/dialect",
        Switch.SCHEMA_REDOS: lambda s: s["properties"]["word"]["pattern"] == "^(a+)+$",
        Switch.SCHEMA_DOLLAR: lambda s: s["properties"]["code"]["pattern"].endswith("$"),
    }
    assert expected[switch](schema)
    assert fake.schema_fetches == 0


async def test_the_counting_schema_listener() -> None:
    fake = McpFake(switches={Switch.SCHEMA_REMOTE_REF})
    with running(fake) as url:
        fake.ref_url = url.replace("/mcp", SCHEMA_PATH)
        listed = modern_post(url, "tools/list").json()["result"]["tools"][-1]
        assert fake.schema_fetches == 0
        fetched = httpx.get(fake.ref_url)
    assert listed["inputSchema"]["properties"]["item"] == {"$ref": fake.ref_url}
    assert fetched.json() == {"type": "string"}
    assert fake.schema_fetches == 1


@pytest.mark.parametrize("version", [MODERN_VERSION, LEGACY_VERSION])
async def test_a_schema_200_levels_deep(version: str) -> None:
    fake = McpFake(switches={Switch.SCHEMA_DEEP})
    with running(fake) as url:
        response = modern_post(url, "tools/list", headers={"mcp-protocol-version": version})
        async with connect(url) as client:
            # The SDK can't parse it: pydantic stops near 100 nested levels.
            with pytest.raises(MCPError) as refused:
                await client.list_tools()
    assert refused.value.error.code == types.PARSE_ERROR
    result = response.json()["result"]
    assert ("resultType" in result) is (version == MODERN_VERSION)
    tools = result["tools"]
    assert [tool["name"] for tool in tools] == [*BASE_NAMES, "schema_deep"]
    assert json_depth(tools[-1]["inputSchema"]) == SCHEMA_DEPTH
    assert fake.lists == 2


# --- discovery (M7 design O.1) ------------------------------------------------------------------

ISSUER = "https://accounts.example"


def origin_of(url: str) -> str:
    return url.removesuffix("/mcp")


def legacy_probe(url: str, headers: dict[str, str] | None = None) -> httpx.Response:
    """The vault's second probe (M7 design D.2): a fixed legacy ``initialize``."""
    body = {
        "jsonrpc": "2.0",
        "id": 0,
        "method": "initialize",
        "params": {
            "protocolVersion": LEGACY_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "zoeymcp", "version": "0"},
        },
    }
    wire = {**ACCEPT, "mcp-protocol-version": LEGACY_VERSION, **(headers or {})}
    return httpx.post(url, json=body, headers=wire, timeout=30)


@pytest.mark.parametrize("form", ["path", "root"])
async def test_protected_resource_metadata_and_the_challenge(form: str) -> None:
    fake = McpFake(key="fake-key-1", authorization_servers=[ISSUER], scopes=("notes.read",))
    fake.prm = form  # type: ignore[assignment]
    with running(fake) as url:
        origin = origin_of(url)
        path_form = httpx.get(f"{origin}{PRM_WELL_KNOWN}/mcp")
        root_form = httpx.get(f"{origin}{PRM_WELL_KNOWN}")
        bare = modern_post(url, "server/discover")
        wrong = modern_post(url, "server/discover", headers={"authorization": "Bearer fake-no"})
    served, absent = (path_form, root_form) if form == "path" else (root_form, path_form)
    assert (served.status_code, absent.status_code) == (200, 404)
    assert served.json() == {
        "resource": url if form == "path" else origin,
        "authorization_servers": [ISSUER],
        "bearer_methods_supported": ["header"],
        "resource_name": "Fake MCP server",
        "scopes_supported": ["notes.read"],
    }
    where = f"{origin}{PRM_WELL_KNOWN}" + ("/mcp" if form == "path" else "")
    assert bare.status_code == 401
    assert bare.headers["www-authenticate"] == (
        f'Bearer resource_metadata="{where}", scope="notes.read"'
    )
    assert wrong.headers["www-authenticate"] == (
        f'Bearer error="invalid_token", resource_metadata="{where}", scope="notes.read"'
    )


async def test_a_challenge_without_the_metadata_address() -> None:
    fake = McpFake(key="fake-key-1", prm="path", authorization_servers=[ISSUER])
    fake.challenge_metadata = False
    with running(fake) as url:
        bare = modern_post(url, "server/discover")
    assert bare.headers["www-authenticate"] == "Bearer"


@pytest.mark.parametrize(
    ("switch", "member", "value"),
    [
        (Switch.PRM_RESOURCE_MISMATCH, "resource", "{origin}/other"),
        (Switch.PRM_TWO_SERVERS, "authorization_servers", [ISSUER, OTHER_AS]),
        (Switch.PRM_DPOP, "dpop_bound_access_tokens_required", True),
    ],
)
async def test_hostile_protected_resource_metadata(switch: Switch, member: str, value: Any) -> None:
    fake = McpFake(prm="path", authorization_servers=[ISSUER], switches={switch})
    with running(fake) as url:
        document = httpx.get(f"{origin_of(url)}{PRM_WELL_KNOWN}/mcp").json()
    if isinstance(value, str):
        value = value.format(origin=origin_of(url))
    assert document[member] == value


async def test_hostile_challenges() -> None:
    fake = McpFake(key="fake-key-1", prm="path", switches={Switch.PRIVATE_METADATA})
    with running(fake) as url:
        private = modern_post(url, "server/discover")
        fake.switches = {Switch.TWO_BEARER}
        two = modern_post(url, "server/discover")
    origin = origin_of(url)
    assert private.headers["www-authenticate"] == f'Bearer resource_metadata="{PRIVATE_METADATA}"'
    assert two.headers.get_list("www-authenticate") == [
        f'Bearer resource_metadata="{origin}{PRM_WELL_KNOWN}/mcp"',
        f'Bearer resource_metadata="{origin}{PRM_WELL_KNOWN}/other"',
    ]


async def test_no_protected_resource_metadata_but_as_metadata_at_the_server_url() -> None:
    """D.2a's case: the server URL itself is the issuer, with a path."""
    fake = McpFake(key="fake-key-1")
    with running(fake) as url:
        fake.as_metadata = lambda: {"issuer": url}
        origin = origin_of(url)
        statuses = [
            httpx.get(f"{origin}{PRM_WELL_KNOWN}/mcp").status_code,
            httpx.get(f"{origin}{PRM_WELL_KNOWN}").status_code,
            httpx.get(f"{origin}{AS_WELL_KNOWN}").status_code,
        ]
        found = httpx.get(f"{origin}{AS_WELL_KNOWN}/mcp")
        bare = modern_post(url, "server/discover")
    assert statuses == [404, 404, 404]
    assert found.json() == {"issuer": url}
    assert bare.headers["www-authenticate"] == 'Bearer error="invalid_token"'


async def test_a_server_without_a_key_is_not_protected() -> None:
    fake = McpFake()
    with running(fake) as url:
        probe = modern_post(url, "server/discover")
        metadata = httpx.get(f"{origin_of(url)}{PRM_WELL_KNOWN}/mcp")
    assert probe.status_code == 200
    assert metadata.status_code == 404


def probe_without_meta(url: str) -> httpx.Response:
    body = {"jsonrpc": "2.0", "id": 0, "method": "server/discover", "params": {}}
    wire = {**ACCEPT, "mcp-protocol-version": MODERN_VERSION, "mcp-method": "server/discover"}
    return httpx.post(url, json=body, headers=wire, timeout=30)


async def test_headers_checked_before_credentials() -> None:
    fake = McpFake(key="fake-key-1")
    with running(fake) as url:
        no_meta = probe_without_meta(url)
        fake.switches = {Switch.HEADERS_BEFORE_AUTH}
        checked = probe_without_meta(url)
        wrong_method = modern_post(url, "server/discover", headers={"mcp-method": "tools/list"})
        good = modern_post(url, "server/discover")
        legacy = legacy_probe(url)
        notification = httpx.post(
            url,
            json={"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {}},
            headers={**ACCEPT, "mcp-protocol-version": MODERN_VERSION},
            timeout=30,
        )
    # Credentials first by default; with the switch, a mismatch is refused before them.
    assert no_meta.status_code == 401
    for refused in (checked, wrong_method):
        assert refused.status_code == 400
        assert refused.json()["error"]["code"] == types.HEADER_MISMATCH
    assert (good.status_code, legacy.status_code) == (401, 401)
    # A notification carries no _meta, and the SDK acknowledges one before that check.
    assert notification.status_code == 401


async def test_a_legacy_server_refuses_the_modern_header_before_credentials() -> None:
    """SPEC-1: the modern probe earns a 400, and the legacy probe the 401."""
    fake = McpFake(mode="legacy", key="fake-key-1")
    with running(fake) as url:
        after = modern_post(url, "server/discover")
        fake.switches = {Switch.HEADERS_BEFORE_AUTH}
        before = modern_post(url, "server/discover")
        legacy = legacy_probe(url)
    assert after.status_code == 401
    assert (before.status_code, before.text) == (400, "unrecognized request")
    assert legacy.status_code == 401


async def test_server_discover_without_credentials() -> None:
    fake = McpFake(key="fake-key-1", switches={Switch.DISCOVER_WITHOUT_AUTH})
    with running(fake) as url:
        discover = modern_post(url, "server/discover")
        listing = modern_post(url, "tools/list")
    assert discover.status_code == 200
    assert "result" in discover.json()
    assert listing.status_code == 401


async def test_get_405_and_delete_400_in_any_mode() -> None:
    fake = McpFake(switches={Switch.GET_405_DELETE_400})
    with running(fake) as url:
        get = httpx.get(url, headers={"accept": "text/event-stream"})
        delete = httpx.delete(url, headers={"mcp-session-id": "fake-session"})
        async with connect(url, mode="legacy") as client:
            assert text_of(await client.call_tool("echo", {"text": "hi"})) == "hi"
    assert (get.status_code, delete.status_code) == (405, 400)
    deletes = [item for item in fake.received if item.method == "DELETE"]
    assert all(item.status == 400 for item in deletes)


async def test_large_lists_96_tools_for_review() -> None:
    fake = McpFake(switches={Switch.LARGE})
    with running(fake) as url:
        async with connect(url) as client:
            tools = (await client.list_tools()).tools
            called = text_of(await client.call_tool("read_05", {"id": "1"}))
    definitions = dumped(types.ListToolsResult(tools=tools))
    assert len(definitions) == 96
    read_only = [d for d in definitions if d.get("annotations", {}).get("readOnlyHint") is True]
    unannotated = [d for d in definitions if "annotations" not in d]
    assert (len(read_only), len(unannotated)) == (64, 32)
    assert called == "read_05 done"
    limits = GatewayLimits()
    levels = {d["name"]: {f.level for f in tool_findings(d, limits)} for d in definitions}
    assert [name for name, found in levels.items() if "error" in found] == [LARGE_INVALID]
    warned = {name for name, found in levels.items() if "warning" in found}
    assert set(LARGE_WARNED) <= warned
    assert LARGE_INVALID in {d["name"] for d in unannotated}


def test_the_runner_builds_the_fake_its_arguments_describe(tmp_path: Path) -> None:
    plain = run_mcp_server.fake_for(run_mcp_server.parse(["cert.pem", "key.pem"]))
    assert (plain.mode, plain.switches, plain.key, plain.prm) == ("dual", set(), None, "none")
    metadata = tmp_path / "as.json"
    metadata.write_bytes(b'{"issuer": "https://mcp.example/mcp"}\n')
    argv = ["cert.pem", "key.pem", "--mode", "legacy", "--static-key", "fake-key-1"]
    argv += ["--prm", "root", "--authorization-server", ISSUER, "--scope", "notes.read"]
    argv += ["--as-metadata", str(metadata), "--switch", "large", "--switch", "two_bearer"]
    args = run_mcp_server.parse(argv)
    fake = run_mcp_server.fake_for(args)
    assert (args.cert, args.key, args.port) == ("cert.pem", "key.pem", 9000)
    assert (fake.mode, fake.key, fake.prm) == ("legacy", "fake-key-1", "root")
    assert (fake.authorization_servers, fake.scopes) == ([ISSUER], ("notes.read",))
    assert fake.switches == {Switch.LARGE, Switch.TWO_BEARER}
    assert fake.as_metadata is not None
    assert fake.as_metadata() == {"issuer": "https://mcp.example/mcp"}
