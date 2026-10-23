"""The stdio fake's self-test (M7 design O.1): run as the bridge runs it, a script with pipes."""

from __future__ import annotations

import asyncio
import json
import sys
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import anyio
import pytest

from tests.fakes import stdio_server

pytestmark = pytest.mark.anyio

FAKE = Path(stdio_server.__file__)
LEGACY = "2025-11-25"
META = {
    "io.modelcontextprotocol/protocolVersion": stdio_server.MODERN,
    "io.modelcontextprotocol/clientInfo": {"name": "fake-test", "version": "1"},
    "io.modelcontextprotocol/clientCapabilities": {},
}
INITIALIZE = {
    "protocolVersion": LEGACY,
    "capabilities": {},
    "clientInfo": {"name": "t", "version": "1"},
}
DEADLINE = 30


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class Child:
    def __init__(self, process: asyncio.subprocess.Process) -> None:
        self.process = process
        self.seen: list[dict[str, Any]] = []
        self.lines: list[bytes] = []

    async def send(self, message: dict[str, Any]) -> None:
        assert self.process.stdin is not None
        self.process.stdin.write(json.dumps(message).encode() + b"\n")
        await self.process.stdin.drain()

    async def line(self) -> bytes:
        assert self.process.stdout is not None
        line = await self.process.stdout.readline()
        if not line.endswith(b"\n"):
            # The fake ended: what it said on its way out.
            assert self.process.stderr is not None
            said = await self.process.stderr.read()
            raise AssertionError(f"stdout ended at {line[:200]!r}; stderr: {said[-2000:]!r}")
        self.lines.append(line)
        return line

    async def until(self, rpc_id: Any) -> list[dict[str, Any]]:
        """Every message up to the answer to ``rpc_id`` (or a request with that id)."""
        found = []
        while True:
            message = json.loads(await self.line())
            found.append(message)
            if message.get("id") == rpc_id:
                return found

    async def ask(self, rpc_id: Any, method: str, params: dict[str, Any]) -> list[dict[str, Any]]:
        await self.send({"jsonrpc": "2.0", "id": rpc_id, "method": method, "params": params})
        return await self.until(rpc_id)


@asynccontextmanager
async def child(*options: str, era: str = "legacy") -> AsyncIterator[Child]:
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        str(FAKE),
        *options,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        limit=8 * 1024 * 1024,
    )
    running = Child(process)
    try:
        with anyio.fail_after(DEADLINE):
            if era == "legacy":
                await running.ask(0, "initialize", INITIALIZE)
                await running.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
            else:
                await running.ask(0, "server/discover", {"_meta": META})
            yield running
    finally:
        if process.returncode is None:
            process.kill()
        await process.wait()


def call(name: str, era: str = "legacy", **arguments: Any) -> dict[str, Any]:
    params: dict[str, Any] = {"name": name, "arguments": arguments}
    if era == "modern":
        params["_meta"] = META
    return params


def text_of(answer: dict[str, Any]) -> str:
    return str(answer["result"]["content"][0]["text"])


@pytest.mark.parametrize("era", ["legacy", "modern"])
async def test_both_eras_list_and_call(era: str) -> None:
    params = {"_meta": META} if era == "modern" else {}
    async with child(era=era) as running:
        listed = (await running.ask(1, "tools/list", params))[-1]
        echoed = (await running.ask(2, "tools/call", call("echo", era, text="hi")))[-1]
    names = [tool["name"] for tool in listed["result"]["tools"]]
    assert names == [tool.name for tool in stdio_server.TOOLS]
    assert text_of(echoed) == "hi"
    # One JSON object per line (contract 53).
    assert all(isinstance(json.loads(line), dict) for line in running.lines)


async def test_tools_toggle_per_start(tmp_path: Path) -> None:
    starts = tmp_path / "starts"
    found = []
    for _ in range(3):
        async with child("--starts", str(starts)) as running:
            listed = (await running.ask(1, "tools/list", {}))[-1]
        found.append("extra" in [tool["name"] for tool in listed["result"]["tools"]])
    assert found == [False, True, False]


async def test_a_changed_file_changes_a_pinned_tool(tmp_path: Path) -> None:
    changed = tmp_path / "changed"
    found = []
    for exists in (False, True, True, False):
        if exists:
            changed.write_bytes(b"")
        elif changed.exists():
            changed.unlink()
        async with child("--changed", str(changed)) as running:
            listed = (await running.ask(1, "tools/list", {}))[-1]
        tools = {tool["name"]: tool["description"] for tool in listed["result"]["tools"]}
        found.append((tools["time"], "extra" in tools))
    plain, changed_time = ("The current time.", False), ("The current time, in UTC.", True)
    assert found == [plain, changed_time, changed_time, plain]


async def test_slow_reports_each_step_before_it_answers() -> None:
    async with child() as running:
        params = {**call("slow", steps=2, interval=0.01), "_meta": {"progressToken": "s"}}
        sent = await running.ask(3, "tools/call", params)
    assert [m["params"]["progress"] for m in sent[:-1]] == [0, 1]
    assert text_of(sent[-1]) == "done after 2 steps"


async def test_progress_carries_the_requests_token() -> None:
    params = {**call("progress", steps=3), "_meta": {"progressToken": "tok"}}
    async with child() as running:
        sent = await running.ask(1, "tools/call", params)
    assert [m["params"]["progressToken"] for m in sent[:-1]] == ["tok"] * 3
    assert text_of(sent[-1]) == "done after 3 steps"


async def test_a_large_result_and_a_large_integer_pass() -> None:
    async with child(era="modern") as running:
        big = (await running.ask(1, "tools/call", call("big", "modern")))[-1]
        huge = (await running.ask(2, "tools/call", call("huge", "modern")))[-1]
    assert len(text_of(big)) == stdio_server.BIG_BYTES
    assert huge["result"]["structuredContent"]["value"] == 2**63


async def test_asking_the_client_keeps_its_answers_from_the_sdk() -> None:
    async with child() as running:
        await running.send(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": call("ask")}
        )
        asked = [json.loads(await running.line()) for _ in stdio_server.ASKED]
        for message in asked:
            await running.send({"jsonrpc": "2.0", "id": message["id"], "result": {"ok": True}})
        answer = (await running.until(1))[-1]
    assert [m["method"] for m in asked] == ["sampling/createMessage", "roots/list", "ping"]
    assert sorted(json.loads(text_of(answer))) == sorted(stdio_server.ASKED)


async def test_the_raw_lines() -> None:
    async with child() as running:
        await running.send(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": call("stray")}
        )
        stray = json.loads(await running.line())
        await running.until(1)
        await running.send(
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": call("garbage")}
        )
        garbage = await running.line()
        await running.until(2)
        await running.send(
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": call("batch")}
        )
        batch = json.loads(await running.line())
    assert stray["id"] == stdio_server.STRAY_ID
    assert garbage == b"this line isn't JSON\n"
    assert isinstance(batch, list)


async def test_crash_exits_and_print_env_prints(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FAKE_STDIO_VALUE", "printed-0001")
    async with child("--print-env", "FAKE_STDIO_VALUE") as running:
        await running.send(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": call("crash")}
        )
        code = await running.process.wait()
        assert running.process.stderr is not None
        stderr = await running.process.stderr.read()
    assert code == 3
    assert b"FAKE_STDIO_VALUE=printed-0001\n" in stderr


async def test_a_cancel_is_noted_on_stderr() -> None:
    async with child() as running:
        hang = {"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": call("hang")}
        await running.send(hang)
        cancel = {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 9}}
        await running.send(cancel)
        crash = {"jsonrpc": "2.0", "id": 10, "method": "tools/call", "params": call("crash")}
        await running.send(crash)
        assert await running.process.wait() == 3
        assert running.process.stderr is not None
        stderr = await running.process.stderr.read()
    assert b"hanging 9\n" in stderr
    assert b"cancelled 9\n" in stderr


def test_the_switches_are_tools() -> None:
    names: Sequence[str] = [tool.name for tool in stdio_server.TOOLS]
    for switch in ("flood", "stderr_flood", "crash", "hang", "ask", "stray", "batch", "garbage"):
        assert switch in names
    assert stdio_server.HUGE == 2**63
