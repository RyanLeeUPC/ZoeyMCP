"""Contracts 47, 48, 49, 53 and 55 (M7 design O.3): what the bridge relies on in asyncio,
Starlette and uvicorn, in the SDK's stdio server (the fake's) and in its streamable HTTP client.

They join D-95's re-run list: run again on every SDK, Starlette or uvicorn bump.
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import subprocess
import sys
import threading
import time
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any

import anyio
import httpx
import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import StreamingResponse
from starlette.routing import Route
from starlette.types import Message, Receive, Scope, Send

from tests.fakes.harness import serve
from tests.fakes.test_stdio_server import META, child
from zoeymcp.bridge.framing import KEEPALIVE, next_line
from zoeymcp.common.policy import Policy
from zoeymcp.vault.app import LISTENER_SCOPE_KEY, VaultApp
from zoeymcp.vault.keys import KeySet
from zoeymcp.vault.store import SecretStore, origin_binding

from .test_client_contract import connect

pytestmark = pytest.mark.anyio

DEADLINE = 30
LEGACY = "2025-11-25"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


# --- 47: a StreamReader's limit -------------------------------------------------------------------


async def test_47_a_line_over_the_limit_raises_and_the_stream_is_then_unusable() -> None:
    """``readline`` raises ``ValueError`` on a longer line. With no newline in the limit, the
    rest of that line then reads as a line of its own, so nothing after it can be trusted: the
    bridge ends the child (``framing.next_line``'s ``too_long``)."""
    reader = asyncio.StreamReader(limit=10)
    reader.feed_data(b"y" * 25)
    with pytest.raises(ValueError, match="chunk exceed the limit"):
        await reader.readline()
    reader.feed_data(b"yyy\n")
    assert await reader.readline() == b"yyy\n"
    flood = asyncio.StreamReader(limit=10)
    flood.feed_data(b"x" * 20 + b"\n")
    assert await next_line(flood) == "too_long"


async def test_47_readline_at_eof() -> None:
    """At EOF ``readline`` gives ``b""``, and an unterminated last line as it is, without its
    newline: :func:`next_line` takes both as ``eof``."""
    reader = asyncio.StreamReader(limit=10)
    reader.feed_data(b"tail")
    reader.feed_eof()
    assert await reader.readline() == b"tail"
    assert await reader.readline() == b""
    ended = asyncio.StreamReader(limit=10)
    ended.feed_data(b"tail")
    ended.feed_eof()
    assert await next_line(ended) == "eof"


# --- 48: killpg reaches a grandchild --------------------------------------------------------------

GRANDPARENT = """
import subprocess, sys, time
child = subprocess.Popen([sys.executable, "-c", "import time\\nwhile True: time.sleep(1)"])
print(child.pid, flush=True)
while True:
    time.sleep(1)
"""


def gone(pid: int) -> bool:
    """Gone or a zombie waiting for its reaper (it runs no more)."""
    try:
        stat = Path(f"/proc/{pid}/stat").read_bytes().decode()
    except FileNotFoundError:
        return True
    return stat.rsplit(")", 1)[1].split()[0] == "Z"


def test_48_killpg_after_start_new_session_reaches_a_grandchild() -> None:
    if sys.platform == "win32":
        pytest.skip("process groups are POSIX")
    process = subprocess.Popen(  # noqa: S603 - our own interpreter
        [sys.executable, "-c", GRANDPARENT],
        stdout=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        assert process.stdout is not None
        grandchild = int(process.stdout.readline())
        assert os.getpgid(grandchild) == process.pid
        os.killpg(process.pid, signal.SIGKILL)
        assert process.wait(10) == -signal.SIGKILL
        deadline = time.monotonic() + 10
        while not gone(grandchild):
            assert time.monotonic() < deadline, "the grandchild outlived its group's kill"
            time.sleep(0.05)
    finally:
        if process.poll() is None:
            process.kill()


# --- 49: each SSE event leaves as it is sent ------------------------------------------------------


def starlette_stream(release: threading.Event) -> Starlette:
    async def events() -> AsyncIterator[bytes]:
        yield b"event: message\ndata: first\n\n"
        await asyncio.to_thread(release.wait, DEADLINE)
        yield b"event: message\ndata: second\n\n"

    async def endpoint(request: Request) -> StreamingResponse:
        return StreamingResponse(events(), media_type="text/event-stream")

    return Starlette(routes=[Route("/mcp", endpoint, methods=["GET"])])


def raw_stream(release: threading.Event) -> Callable[[Scope, Receive, Send], Any]:
    """The bridge's way: an ASGI app sending body parts with ``more_body``."""

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return
        headers = [(b"content-type", b"text/event-stream")]
        await send({"type": "http.response.start", "status": 200, "headers": headers})
        first: Message = {"type": "http.response.body", "body": KEEPALIVE, "more_body": True}
        await send(first)
        body = b"event: message\ndata: first\n\n"
        await send({"type": "http.response.body", "body": body, "more_body": True})
        await asyncio.to_thread(release.wait, DEADLINE)
        last = b"event: message\ndata: second\n\n"
        await send({"type": "http.response.body", "body": last, "more_body": False})

    return app


@pytest.mark.parametrize("build", [starlette_stream, raw_stream], ids=["starlette", "raw"])
async def test_49_each_event_arrives_before_the_next_is_sent(
    build: Callable[[threading.Event], Any],
) -> None:
    release = threading.Event()
    with serve(build(release)) as base:
        async with httpx.AsyncClient(base_url=base, timeout=DEADLINE) as client:
            seen = b""
            with anyio.fail_after(DEADLINE):
                async with client.stream("GET", "/mcp") as answer:
                    async for chunk in answer.aiter_raw():
                        seen += chunk
                        if not release.is_set() and b"data: first\n\n" in seen:
                            # The second event isn't sent until the first was received.
                            assert b"second" not in seen
                            release.set()
    assert seen.endswith(b"data: second\n\n")


# --- 53: the SDK's stdio server writes a line per message -----------------------------------------


@pytest.mark.parametrize("era", ["legacy", "modern"])
async def test_53_one_json_object_per_line_and_the_subscription_id(era: str) -> None:
    async with child(era=era) as running:
        if era == "modern":
            listen = {"_meta": META, "notifications": {"toolsListChanged": True}}
            await running.send(
                {"jsonrpc": "2.0", "id": 41, "method": "subscriptions/listen", "params": listen}
            )
            acknowledged = json.loads(await running.line())
        announce = {"name": "announce", "arguments": {}}
        if era == "modern":
            announce["_meta"] = META
        sent = await running.ask(42, "tools/call", announce)
    for line in running.lines:
        assert line.count(b"\n") == 1
        assert isinstance(json.loads(line), dict)
    changed = [m for m in sent if m.get("method") == "notifications/tools/list_changed"]
    assert len(changed) == 1
    if era == "modern":
        key = "io.modelcontextprotocol/subscriptionId"
        assert acknowledged["params"]["_meta"][key] == 41
        assert changed[0]["params"]["_meta"][key] == 41


# --- 55: keepalive comments, to the SDK's client and through the vault ----------------------------


async def keepalive_server(scope: Scope, receive: Receive, send: Send) -> None:
    """A legacy MCP server whose every answer starts with a ``: keepalive`` comment."""
    if scope["type"] != "http":
        return
    body = b""
    while True:
        message = await receive()
        body += message.get("body", b"")
        if not message.get("more_body"):
            break
    if scope["method"] != "POST":
        await send({"type": "http.response.start", "status": 405, "headers": []})
        await send({"type": "http.response.body", "body": b""})
        return
    request = json.loads(body)
    if "id" not in request:
        await send({"type": "http.response.start", "status": 202, "headers": []})
        await send({"type": "http.response.body", "body": b""})
        return
    results: dict[str, Any] = {
        "initialize": {
            "protocolVersion": LEGACY,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "keepalive", "version": "1"},
        },
        "tools/list": {"tools": [{"name": "kept", "inputSchema": {"type": "object"}}]},
    }
    answer = {"jsonrpc": "2.0", "id": request["id"], "result": results.get(request["method"], {})}
    headers = [(b"content-type", b"text/event-stream"), (b"mcp-session-id", b"keepalive-1")]
    await send({"type": "http.response.start", "status": 200, "headers": headers})
    await send({"type": "http.response.body", "body": KEEPALIVE, "more_body": True})
    event = b"event: message\ndata: " + json.dumps(answer).encode() + b"\n\n"
    await send({"type": "http.response.body", "body": event, "more_body": False})


async def test_55_the_sdk_client_takes_comment_lines_as_no_message() -> None:
    with serve(keepalive_server) as base:
        async with connect(f"{base}/mcp", "legacy") as client:
            listed = await client.list_tools()
    assert [tool.name for tool in listed.tools] == ["kept"]


class Held(httpx.AsyncByteStream):
    """An upstream's SSE body: a keepalive, then nothing until released, then an event."""

    def __init__(self) -> None:
        self.release = asyncio.Event()

    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield KEEPALIVE
        await self.release.wait()
        yield b"event: message\ndata: {}\n\n"


async def test_55_the_vaults_relay_passes_a_keepalive_unbuffered(tmp_path: Path) -> None:
    """A stream route's comment reaches the gateway while the upstream is still silent."""
    keys = KeySet.from_master(bytes(range(32)))
    store = SecretStore(tmp_path, keys)
    store.load()
    store.put("fetch-token", "token-fetch", origin_binding(["http://127.0.0.1:9000"]))
    policy = Policy.model_validate(
        {
            "version": 1,
            "mode": "declarative",
            "credentials": {"fetch": {"kind": "header", "secret": "store:fetch-token"}},
            "routes": [
                {
                    "name": "fetch",
                    "prefix": "/fetch",
                    "upstream": "http://127.0.0.1:9000",
                    "allow_insecure_upstream": True,
                    "credential": "fetch",
                    "callers": ["gateway"],
                    "stream": True,
                    "rules": [{"methods": ["POST"], "paths": ["/mcp"]}],
                }
            ],
            "gateway": {"servers": {"fetch": {"kind": "remote", "route": "fetch"}}},
        }
    )
    held = Held()
    sse = {"content-type": "text/event-stream"}
    upstream = httpx.MockTransport(lambda request: httpx.Response(200, headers=sse, stream=held))
    app = VaultApp(policy, store, keys, client=httpx.AsyncClient(transport=upstream), environ={})
    sent: list[bytes] = []
    read: list[bool] = []
    arrived = asyncio.Event()
    done = asyncio.Event()

    async def receive() -> Message:
        if not read:
            read.append(True)
            return {"type": "http.request", "body": b"{}", "more_body": False}
        await done.wait()
        return {"type": "http.disconnect"}

    async def send(message: Message) -> None:
        if message["type"] == "http.response.body":
            sent.append(message.get("body", b""))
            if KEEPALIVE in b"".join(sent):
                arrived.set()
            if not message.get("more_body", False):
                done.set()

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/fetch/mcp",
        "raw_path": b"/fetch/mcp",
        "query_string": b"",
        "root_path": "",
        "headers": [(b"host", b"vault"), (b"content-length", b"2")],
        "client": ("127.0.0.1", 40000),
        "server": ("vault", 80),
        LISTENER_SCOPE_KEY: "gateway",
    }
    try:
        with anyio.fail_after(DEADLINE):
            task = asyncio.create_task(app(scope, receive, send))
            await arrived.wait()
            assert b"data:" not in b"".join(sent)
            held.release.set()
            await done.wait()
            await task
    finally:
        await app.aclose()
    assert b"".join(sent) == KEEPALIVE + b"event: message\ndata: {}\n\n"
