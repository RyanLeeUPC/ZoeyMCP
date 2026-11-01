"""Contracts 62 to 68 and 70 (M8 design O.2): what M8's code relies on in the MCP SDK, ``httpx`` and
the standard library's ``json``. They land in step 1, before any code that leans on them (G-1);
contract 69 is the image's and runs in the smoke (step 24).

Contract 62 (F.1): the SDK client hands a gateway-made ``CallToolResult`` with ``isError: true``
and no ``structuredContent`` to its caller unchanged, in both eras, whether or not the tool has an
``outputSchema``: it validates only a result that isn't an error (F-41). The spec doesn't promise
this (SC-6); the ``pending <ref>`` answer relies on it. The server is shaped as the gateway's
client-facing side is (``test_server_contract.Shaped``).

Contract 63 (B.6, C.2): a 409 with ``x-zoeymcp-vault: refused`` on one ``tools/call`` raises for
that request only; a call in flight beside it still gets its answer, and the session goes on,
in both eras. The 409 comes from a stand-in for the vault in front of the fake upstream, in the
vault's refusal shape (``vault/app.py``'s ``Refused`` answer).

Contract 64 (C.1 row 4): the SDK client sends ``Mcp-Param-*`` headers for an ``x-mcp-header``
parameter in the modern era (and not in the legacy one), so a held tool with one would reach the
vault with them.

Contract 65 (F.1, fold-in 3.5): D-95's strict xfail read again: SDK 2.3.0 retries a state-only
``InputRequiredResult``, so the fact as stated ("doesn't retry") doesn't hold, and the named
fallback is taken: recorded, and the state-only long poll stays an option, not built. The xfail
flips when an SDK bump changes it.

Contract 66 (B.2 E11): the ``_meta`` keys the SDK puts in a modern ``tools/call`` are exactly
the egress filter's ``META_KEYS`` (``common/mcpwire.py`` since step 2, which
``gateway/egressrules.py`` imports); a legacy call carries only ``progressToken``.

Contract 67 (G.1): ``str()`` of the ``httpx.HTTPStatusError`` that ``raise_for_status`` raises
holds the request URL, so a Bot API token in the path would be printed. ``str()`` of a
``ConnectError`` holds only the socket's message today, so that half of the fact doesn't hold, and
its named fallback is "none needed": G.1 reduces every ``httpx.HTTPError`` to its type name
either way. The error still carries the request, URL included.

Contract 68 (B.2 E9): ``json.loads``'s ``parse_int`` and ``parse_float`` hooks are handed each
number token's text exactly as written, and ``httpx``'s ``json=`` (``httpx2``'s too, which the SDK
posts with) writes floats as ``repr`` does, so an honest SDK body passes E9's round-trip rule;
the body the SDK sent for a real call is checked by that rule.

Contract 70 (B.6, B.1's ``Cancel``): at 2025-06-18 and 2025-11-25 the SDK cancels an in-flight
call by POSTing ``notifications/cancelled`` naming it and leaves the call's POST open (the fake's
SDK server then ends it); at
2026-07-28 it aborts the POST and sends no frame (F-54).

They join D-95's re-run list: run again on every SDK bump, 67 and 68 on every ``httpx`` bump.
"""

from __future__ import annotations

import contextlib
import json
import socket
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

import anyio
import httpx
import httpx2
import mcp_types as types
import pytest
from mcp.server.context import ServerRequestContext
from mcp.shared.exceptions import MCPError
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from tests.fakes.harness import serve
from tests.fakes.mcp_server import PATH, McpFake, Recorded
from zoeymcp.common.mcpwire import META_KEYS

from .test_client_contract import LATEST_LEGACY, connect, text_of, until
from .test_server_contract import Shaped
from .test_server_contract import running as running_shaped

pytestmark = pytest.mark.anyio

# The gateway's pending answer (F.1), as it would read.
PENDING = (
    "pending 0123456789abcdef: waiting for the operator's approval until 2026-11-01 15:40 UTC. "
    "It runs as soon as it is approved, whether or not you check. Do not call report again; "
    'call check_approval with {"id": "0123456789abcdef"} to get the result; it is kept for 60 '
    "minutes after the call runs and given once. This is not a failure."
)
# The vault's refusal answer (vault/app.py's Refused), for a held call left pending (B.6).
REFUSAL_HEADERS = [
    (b"content-type", b"application/json"),
    (b"x-zoeymcp-vault", b"refused"),
]
REFUSAL_BODY = b'{"error":"conflict","code":"approval_pending"}'
REFUSED_TEXT = "refuse me"
# The eras: two legacy versions the fake can be pinned to, and the modern one.
LEGACY_ERAS = ["2025-06-18", LATEST_LEGACY]
SENTINEL = "123456789:AAH-contract-67-sentinel"
# Each SDK test bounds itself, client exit included, so a bump that makes one hang fails it.
LIMIT = 10


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@contextmanager
def running(app: ASGIApp) -> Iterator[str]:
    """The fake upstream's MCP URL while ``app`` (the fake, or what stands in front of it) runs."""
    with serve(app, lifespan=True) as base:
        yield f"{base}{PATH}"


# --- 62. an error result passes the client unchanged ----------------------------------------------


class ErrorShaped(Shaped):
    """The gateway's shape answering every call with the pending answer, or, with ``plain``, the
    same result as a success, which the client must validate."""

    def __init__(self, *, plain: bool = False) -> None:
        super().__init__()
        self.plain = plain

    async def _call(
        self, ctx: ServerRequestContext[Any], params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        self._note(ctx, "tools/call")
        content: list[types.ContentBlock] = [types.TextContent(type="text", text=PENDING)]
        return types.CallToolResult(content=content, is_error=not self.plain)


def has_output_schema(shaped: Shaped, name: str) -> bool:
    [projection] = [p for p in shaped.projections if p["name"] == name]
    return "outputSchema" in projection


@pytest.mark.parametrize("tool", ["report", "echo"])
@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_62_an_error_result_without_structured_content_reaches_the_caller(
    mode: str, tool: str
) -> None:
    shaped = ErrorShaped()
    assert has_output_schema(shaped, tool) == (tool == "report")
    with anyio.fail_after(LIMIT), running_shaped(shaped) as url:
        async with connect(url, mode) as client:
            await client.list_tools()
            result = await client.call_tool(tool, {})
    assert result.is_error is True
    assert result.structured_content is None
    assert text_of(result) == PENDING
    assert len(result.content) == 1
    assert [seen.method for seen in shaped.seen].count("tools/call") == 1


@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_62_the_same_result_as_a_success_is_validated(mode: str) -> None:
    """The control: the client does validate a success against the output schema (F-41)."""
    shaped = ErrorShaped(plain=True)
    with anyio.fail_after(LIMIT), running_shaped(shaped) as url:
        async with connect(url, mode) as client:
            await client.list_tools()
            with pytest.raises(RuntimeError, match="did not return structured content"):
                await client.call_tool("report", {})
            echoed = await client.call_tool("echo", {})
    assert echoed.is_error is False
    assert text_of(echoed) == PENDING


# --- 63. a vault 409 on one call ------------------------------------------------------------------


class VaultStandIn:
    """The vault in front of the fake: a ``tools/call`` of ``echo`` with ``REFUSED_TEXT`` gets the
    vault's 409 refusal; everything else reaches the fake unchanged."""

    def __init__(self, fake: McpFake) -> None:
        self.fake = fake
        self.app = fake.app()
        self.refused: list[Any] = []

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] != "POST":
            await self.app(scope, receive, send)
            return
        body = await read_body(receive)
        message = loads_or_none(body)
        params = message.get("params") if isinstance(message, dict) else None
        if (
            isinstance(params, dict)
            and message.get("method") == "tools/call"
            and params.get("arguments") == {"text": REFUSED_TEXT}
        ):
            self.refused.append(message.get("id"))
            await send({"type": "http.response.start", "status": 409, "headers": REFUSAL_HEADERS})
            await send({"type": "http.response.body", "body": REFUSAL_BODY})
            return
        await self.app(scope, replay(body, receive), send)


async def read_body(receive: Receive) -> bytes:
    chunks: list[bytes] = []
    while True:
        message = await receive()
        chunks.append(message.get("body", b""))
        if message["type"] != "http.request" or not message.get("more_body", False):
            return b"".join(chunks)


def replay(body: bytes, receive: Receive) -> Receive:
    """A ``receive`` that gives ``body`` once, then the real one's messages."""
    sent = False

    async def replayed() -> Message:
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return await receive()

    return replayed


def loads_or_none(body: bytes) -> Any:
    try:
        return json.loads(body) if body else None
    except ValueError:
        return None


@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_63_a_vault_409_raises_for_that_call_only(mode: str) -> None:
    fake = McpFake()
    vault = VaultStandIn(fake)
    outcomes: list[str] = []

    async def slow(client: Any) -> None:
        result = await client.call_tool("slow", {"steps": 10, "interval": 0.05})
        outcomes.append(text_of(result))

    with anyio.fail_after(LIMIT), running(vault) as url:
        async with connect(url, mode) as client:
            await client.list_tools()
            async with anyio.create_task_group() as group:
                group.start_soon(slow, client)
                await until(lambda: [call.name for call in fake.calls] == ["slow"])
                with pytest.raises(MCPError):
                    await client.call_tool("echo", {"text": REFUSED_TEXT})
            after = await client.call_tool("echo", {"text": "hi"})
    assert len(vault.refused) == 1
    assert outcomes == ["done after 10 steps"]
    assert text_of(after) == "hi"
    # The same session throughout: no second handshake, the refused call never reached the fake.
    assert [call.name for call in fake.calls] == ["slow", "echo"]
    if mode == "legacy":
        assert len(fake.requests("initialize")) == 1
        [*calls] = fake.requests("tools/call")
        assert len({call.session_id for call in calls}) == 1


# --- 64. Mcp-Param-* headers ----------------------------------------------------------------------


async def test_64_the_sdk_sends_param_headers_in_the_modern_era_only() -> None:
    fake = McpFake()
    with anyio.fail_after(LIMIT), running(fake.app()) as url:
        async with connect(url) as client:
            await client.list_tools()
            await client.call_tool("lookup", {"region": "eu", "query": "q"})
        async with connect(url, "legacy") as client:
            await client.list_tools()
            await client.call_tool("lookup", {"region": "eu", "query": "q"})
    modern, legacy = fake.requests("tools/call")
    assert modern.header("mcp-param-region") == "eu"
    assert param_headers(legacy) == []


def param_headers(record: Recorded) -> list[str]:
    return [name for name, _ in record.headers if name.lower().startswith("mcp-param-")]


# --- 65. a state-only input_required --------------------------------------------------------------


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason=(
        "SDK 2.3.0 retries a state-only input_required after a 50 ms backoff (D-95). Contract "
        "65's named fallback: recorded, and the state-only long poll (fold-in 3.5) stays an "
        "option, not built (M8 design F.1)."
    ),
)
async def test_65_a_state_only_input_required_is_not_retried() -> None:
    fake = McpFake(back_channel="state_only")
    with anyio.fail_after(LIMIT), running(fake.app()) as url:
        async with connect(url) as client:
            await client.list_tools()
            with contextlib.suppress(MCPError):
                await client.call_tool("echo", {"text": "hi"})
    assert [call.retry for call in fake.calls] == [False]


# --- 66. the _meta keys of a tools/call -----------------------------------------------------------


async def note_progress(progress: float, total: float | None, message: str | None) -> None:
    """A progress callback, so the SDK adds ``progressToken``."""


@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_66_the_meta_keys_of_a_call_are_the_egress_filters(mode: str) -> None:
    fake = McpFake()
    with anyio.fail_after(LIMIT), running(fake.app()) as url:
        async with connect(url, mode) as client:
            await client.list_tools()
            await client.call_tool("echo", {"text": "hi"}, progress_callback=note_progress)
            await client.call_tool("echo", {"text": "hi"})
    keys = [set(call.params.get("_meta", {})) for call in fake.requests("tools/call")]
    if mode == "auto":
        assert keys[0] == META_KEYS
        assert keys[1] == META_KEYS - {"progressToken"}
    else:
        assert keys == [{"progressToken"}, set()]


# --- 67. what httpx's errors say ------------------------------------------------------------------


def bot_url(origin: str) -> str:
    return f"{origin}/bot{SENTINEL}/getMe"


def test_67_a_status_error_names_the_url() -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"ok": False, "error_code": 401})

    with httpx.Client(transport=httpx.MockTransport(refuse)) as client:
        response = client.get(bot_url("https://api.telegram.example"))
    with pytest.raises(httpx.HTTPStatusError) as raised:
        response.raise_for_status()
    assert bot_url("https://api.telegram.example") in str(raised.value)
    assert SENTINEL in str(raised.value)


def closed_port() -> int:
    """A loopback port nothing listens on."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
    return port


def test_67_a_connect_error_carries_the_url_but_doesnt_say_it() -> None:
    url = bot_url(f"http://127.0.0.1:{closed_port()}")
    with httpx.Client(trust_env=False) as client, pytest.raises(httpx.ConnectError) as raised:
        client.get(url)
    assert SENTINEL not in str(raised.value)
    assert str(raised.value.request.url) == url


# --- 68. number tokens and float serialization ----------------------------------------------------

# Tokens E9 judges, each as written: the integers and floats that round-trip, and those that don't.
INTEGER_TOKENS = ["0", "-0", "7", "-12", "123456789012345678901234567890"]
FLOAT_TOKENS = ["0.1", "1.50", "1e5", "1E5", "1e+22", "-0.0", "1.0000000000000002", "2.5e-07"]
# Floats whose shortest repr has an exponent, a sign, many digits, or the smallest subnormal.
FLOATS = [0.1, 1.5, 1e22, 1e-7, -0.0, 5e-324, 2.0**0.5, 123456.789]


def tokens_of(text: str) -> tuple[list[str], list[str]]:
    """The integer and float token texts the hooks are handed, in order."""
    integers: list[str] = []
    floats: list[str] = []

    def on_int(token: str) -> int:
        integers.append(token)
        return int(token)

    def on_float(token: str) -> float:
        floats.append(token)
        return float(token)

    json.loads(text, parse_int=on_int, parse_float=on_float)
    return integers, floats


def round_trips(integers: list[str], floats: list[str]) -> bool:
    """E9's rule: each integer token is ``str(int(t))``, each float token ``repr(float(t))``."""
    return all(str(int(t)) == t for t in integers) and all(repr(float(t)) == t for t in floats)


def test_68_the_hooks_see_each_token_as_written() -> None:
    text = "[" + ", ".join(INTEGER_TOKENS + FLOAT_TOKENS) + ', {"a": [1.50, -0]}]'
    integers, floats = tokens_of(text)
    assert integers == [*INTEGER_TOKENS, "-0"]
    assert floats == [*FLOAT_TOKENS, "1.50"]
    # What E9 refuses among them, and only that.
    assert [t for t in integers if str(int(t)) != t] == ["-0", "-0"]
    assert [t for t in floats if repr(float(t)) != t] == ["1.50", "1e5", "1E5", "1.50"]


@pytest.mark.parametrize("module", ["httpx", "httpx2"])
def test_68_json_bodies_write_floats_as_repr(module: str) -> None:
    request_class: Callable[..., Any] = httpx.Request if module == "httpx" else httpx2.Request
    request = request_class("POST", "https://upstream.example/mcp", json={"values": FLOATS})
    integers, floats = tokens_of(request.content.decode())
    assert integers == []
    assert floats == [repr(value) for value in FLOATS]
    assert round_trips(integers, floats)


@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_68_an_sdk_call_body_passes_the_round_trip_rule(mode: str) -> None:
    fake = McpFake()
    with anyio.fail_after(LIMIT), running(fake.app()) as url:
        async with connect(url, mode) as client:
            await client.list_tools()
            result = await client.call_tool("add", {"a": 0.1, "b": 1e22})
            await client.call_tool("slow", {"steps": 1, "interval": 2.5e-7})
    assert text_of(result) == "1e+22"
    for call in fake.requests("tools/call"):
        integers, floats = tokens_of(call.body.decode())
        assert floats, call.body
        assert round_trips(integers, floats), call.body


# --- 70. how the SDK cancels, by era --------------------------------------------------------------


async def cancel_a_slow_call(client: Any, fake: McpFake) -> None:
    """Start a long ``slow`` call and cancel it once the fake runs it."""
    async with anyio.create_task_group() as group:
        group.start_soon(client.call_tool, "slow", {"steps": 400, "interval": 0.05})
        await until(lambda: [call.name for call in fake.calls] == ["slow"])
        group.cancel_scope.cancel()


@pytest.mark.parametrize("version", LEGACY_ERAS)
async def test_70_a_legacy_cancel_is_a_notification_and_the_post_stays_open(
    version: str,
) -> None:
    fake = McpFake(legacy_version=version)
    with anyio.fail_after(LIMIT), running(fake.app()) as url:
        async with connect(url, "legacy") as client:
            await client.list_tools()
            assert client.protocol_version == version
            await cancel_a_slow_call(client, fake)
            await until(lambda: bool(fake.requests("notifications/cancelled")))
            assert await anyio.to_thread.run_sync(fake.cancelled.wait, 5)
            # One more round trip, so a client that aborts the POST late has done so by now.
            after = await client.call_tool("echo", {"text": "after"})
            call, _ = fake.requests("tools/call")
            # The server ended the call's POST; had the client aborted it first, that would show.
            await until(lambda: call.finished or call.disconnected)
            assert call.finished
            assert not call.disconnected
    assert text_of(after) == "after"
    [cancelled] = fake.requests("notifications/cancelled")
    assert cancelled.params["requestId"] == call.message["id"]


async def test_70_a_modern_cancel_aborts_the_post_and_sends_no_frame() -> None:
    fake = McpFake()
    with anyio.fail_after(LIMIT), running(fake.app()) as url:
        async with connect(url) as client:
            await client.list_tools()
            assert client.protocol_version not in LEGACY_ERAS
            await cancel_a_slow_call(client, fake)
            [call] = fake.requests("tools/call")
            await until(lambda: call.disconnected)
            assert await anyio.to_thread.run_sync(fake.cancelled.wait, 5)
    # Nothing more was posted for it, before the client closed or after.
    assert fake.requests("notifications/cancelled") == []
    assert [item.rpc_method for item in fake.received if item.method == "POST"].count(
        "tools/call"
    ) == 1
