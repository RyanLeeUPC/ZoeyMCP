"""A scriptable stdio MCP server, the child of the bridge's tests (M7 design O.1, C.3, C.4).

It runs the SDK's low-level ``Server`` over the SDK's stdio transport (``mcp.server.stdio``), which
serves both protocol eras: the first request decides, ``initialize`` the legacy era and a request
with ``_meta`` the modern one. It is run as a script, ``python tests/fakes/stdio_server.py
[options]``, from the bridge's empty working directory and environment, so it imports only the
SDK and the standard library.

The ordinary tools are ``time`` and ``fetch`` (fetch-like: it reaches no network), ``echo``,
``progress``, which reports progress against the request's own token before it answers (SPEC-3),
and ``slow``, which reports progress each step, ``interval`` seconds apart, then answers.
``--starts FILE`` counts the starts in FILE, and every second start adds the tool ``extra``: the
tools toggle per start, as a server upgraded between two runs. ``--changed FILE`` does the same
for each start while FILE exists, and changes ``time``'s description too, so a pinned tool drifts
(S11's restart row, where a legacy bridge's probe and every session each start a child).

The hostile switches are tools too, so one child can be well-behaved until a test asks: ``flood``
writes 100 MB with no newline; ``stderr_flood`` floods stderr; ``crash`` exits mid-call; ``hang``
never answers; ``ask`` sends ``sampling/createMessage``, ``roots/list`` and ``ping`` to its
client and answers with what came back; ``stray`` answers an id it wasn't sent; ``batch`` writes
a batch; ``garbage`` prints a line that isn't JSON; ``grandchild`` leaves a process in its group;
``big`` answers 2 MiB and ``huge`` an integer of 2^63, both of which must pass (CR-6);
``announce`` sends ``tools/list_changed`` (to a legacy session's client, or on each modern
listen stream). At start, ``--print-env NAME`` prints that variable to stderr (the leak sweep's
case) and ``--ignore-eof`` keeps running after stdin ends, ignoring SIGTERM. Each
``notifications/cancelled`` it is sent is noted on stderr as ``cancelled <requestId>``, so a test
run with ``--stderr text`` sees which request a cancel reached; ``hang`` notes its own as
``hanging <requestId>`` before it waits.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import signal
import subprocess
import sys
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any, Final

import anyio
import mcp_types as types
from mcp.server import Server
from mcp.server.context import ServerRequestContext
from mcp.server.lowlevel.server import NotificationOptions
from mcp.server.stdio import stdio_server
from mcp.server.subscriptions import InMemorySubscriptionBus, ListenHandler, ToolsListChanged
from mcp.shared.exceptions import MCPError

MIB: Final = 1024 * 1024
FLOOD_BYTES: Final = 100 * MIB
BIG_BYTES: Final = 2 * MIB
HUGE: Final = 2**63
STDERR_FLOOD_LINES: Final = 2000
# The ids of the requests ``ask`` sends its client; the answers to them never reach the SDK.
ASKED: Final = ("fake-ask-sampling", "fake-ask-roots", "fake-ask-ping")
STRAY_ID: Final = 987654321
MODERN: Final = "2026-07-28"
ASK_WAIT: Final = 5.0
CANCELLED: Final = "notifications/cancelled"


def tool(name: str, description: str, **properties: Any) -> types.Tool:
    schema = {"type": "object", "properties": properties}
    return types.Tool(name=name, description=description, input_schema=schema)


TOOLS: Final = (
    tool("time", "The current time."),
    tool("fetch", "Fetch a URL (the fake reaches no network).", url={"type": "string"}),
    tool("echo", "Echo the text.", text={"type": "string"}),
    tool("progress", "Report progress, then answer.", steps={"type": "integer"}),
    tool(
        "slow",
        "Report progress each step, a while apart, then answer.",
        steps={"type": "integer"},
        interval={"type": "number"},
    ),
    tool("flood", "Write 100 MB with no newline."),
    tool("stderr_flood", "Flood stderr, then answer."),
    tool("crash", "Exit mid-call."),
    tool("hang", "Never answer."),
    tool("ask", "Ask the client for sampling, roots and a ping."),
    tool("stray", "Answer an id never sent, then answer."),
    tool("batch", "Write a batch."),
    tool("garbage", "Print a line that isn't JSON."),
    tool("grandchild", "Leave a process in this one's group.", pidfile={"type": "string"}),
    tool("big", "Answer 2 MiB."),
    tool("huge", "Answer an integer of 2^63."),
    tool("announce", "Send tools/list_changed."),
)
EXTRA: Final = tool("extra", "Present on every second start.")
CHANGED_TIME: Final = tool("time", "The current time, in UTC.")


def err(line: str) -> None:
    """A line on stderr, as bytes (so the newline is one byte on every platform)."""
    sys.stderr.buffer.write(line.encode("utf-8"))
    sys.stderr.buffer.flush()


def text(value: str) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(type="text", text=value)])


class Wire:
    """Stdin and stdout, as the SDK's transport and the hostile tools share them: lines to the
    SDK, but answers to the requests ``ask`` sent kept here; and raw writes beside the SDK's."""

    def __init__(self) -> None:
        self.stdin = anyio.wrap_file(io.TextIOWrapper(sys.stdin.buffer, encoding="utf-8"))
        self.stdout = anyio.wrap_file(
            io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", newline="\n")
        )
        self.answers: dict[str, Any] = {}
        self.answered = anyio.Event()

    def __aiter__(self) -> AsyncIterator[str]:
        return self._lines()

    async def _lines(self) -> AsyncIterator[str]:
        async for line in self.stdin:
            try:
                message = json.loads(line)
            except ValueError:
                message = None
            if isinstance(message, dict) and message.get("id") in ASKED and "method" not in message:
                self.answers[message["id"]] = message
                if len(self.answers) == len(ASKED):
                    self.answered.set()
                continue
            if isinstance(message, dict) and message.get("method") == CANCELLED:
                params = message.get("params")
                request_id = params.get("requestId") if isinstance(params, dict) else None
                err(f"cancelled {json.dumps(request_id)}\n")
            yield line

    async def write(self, data: str) -> None:
        await self.stdout.write(data)
        await self.stdout.flush()


class Fake:
    def __init__(self, options: argparse.Namespace) -> None:
        self.options = options
        self.wire = Wire()
        self.bus = InMemorySubscriptionBus()
        self.tools = list(TOOLS)
        if options.starts is not None:
            path = Path(options.starts)
            starts = int(path.read_text(encoding="ascii")) if path.exists() else 0
            path.write_bytes(str(starts + 1).encode("ascii"))
            if starts % 2:
                self.tools.append(EXTRA)
        if options.changed is not None and Path(options.changed).exists():
            self.tools = [CHANGED_TIME if t.name == "time" else t for t in self.tools]
            if EXTRA not in self.tools:
                self.tools.append(EXTRA)
        self.server: Server[Any] = Server(
            "fake-stdio",
            version="1.0.0",
            on_list_tools=self.list_tools,
            on_call_tool=self.call_tool,
            on_subscriptions_listen=ListenHandler(self.bus),
        )

    async def list_tools(
        self, ctx: ServerRequestContext[Any], params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        return types.ListToolsResult(tools=self.tools)

    async def call_tool(
        self, ctx: ServerRequestContext[Any], params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        name = params.name
        arguments = dict(params.arguments or {})
        if name == "time":
            return text("12:00:00Z")
        if name == "fetch":
            return text(f"fetched {arguments.get('url', '')}")
        if name == "echo":
            return text(str(arguments.get("text", "")))
        if name == "progress":
            steps = int(arguments.get("steps", 3))
            for step in range(steps):
                await ctx.session.report_progress(step, steps, f"step {step}")
            return text(f"done after {steps} steps")
        if name == "slow":
            steps = int(arguments.get("steps", 3))
            interval = float(arguments.get("interval", 0.5))
            for step in range(steps):
                await ctx.session.report_progress(step, steps, f"step {step}")
                await anyio.sleep(interval)
            return text(f"done after {steps} steps")
        if name == "flood":
            chunk = "x" * MIB
            for _ in range(FLOOD_BYTES // MIB):
                await self.wire.write(chunk)
            return text("flooded")
        if name == "stderr_flood":
            # The long line first, so a --stderr text bridge shows how it is cut.
            err("z" * (64 * 1024) + "\n")
            for number in range(STDERR_FLOOD_LINES):
                err(f"stderr line {number} " + "y" * 100 + "\n")
            return text("flooded stderr")
        if name == "crash":
            os._exit(3)
        if name == "hang":
            err(f"hanging {json.dumps(ctx.request_id)}\n")
            await anyio.sleep_forever()
        if name == "ask":
            return await self.ask()
        if name == "stray":
            await self.wire.write(
                json.dumps({"jsonrpc": "2.0", "id": STRAY_ID, "result": {}}) + "\n"
            )
            return text("strayed")
        if name == "batch":
            note = {"jsonrpc": "2.0", "method": "notifications/message", "params": {}}
            await self.wire.write(json.dumps([note, note]) + "\n")
            return text("batched")
        if name == "garbage":
            await self.wire.write("this line isn't JSON\n")
            return text("garbled")
        if name == "grandchild":
            return text(str(self.grandchild(str(arguments.get("pidfile", "")))))
        if name == "big":
            return text("b" * BIG_BYTES)
        if name == "huge":
            result = text("huge")
            result.structured_content = {"value": HUGE}
            return result
        if name == "announce":
            if ctx.protocol_version == MODERN:
                await self.bus.publish(ToolsListChanged())
            else:
                await ctx.session.send_notification(types.ToolListChangedNotification())
            return text("announced")
        raise MCPError(types.INVALID_PARAMS, f"Unknown tool: {name}")

    async def ask(self) -> types.CallToolResult:
        requests: tuple[tuple[str, dict[str, Any]], ...] = (
            ("sampling/createMessage", {"messages": [], "maxTokens": 1}),
            ("roots/list", {}),
            ("ping", {}),
        )
        for request_id, (method, params) in zip(ASKED, requests, strict=True):
            message = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
            await self.wire.write(json.dumps(message) + "\n")
        with anyio.move_on_after(ASK_WAIT):
            await self.wire.answered.wait()
        return text(json.dumps(self.wire.answers, sort_keys=True))

    @staticmethod
    def grandchild(pidfile: str) -> int:
        """A process that outlives this one unless its group is killed; its pid in ``pidfile``."""
        code = "import time\nwhile True: time.sleep(1)\n"
        process = subprocess.Popen(  # noqa: S603 - our own interpreter
            [sys.executable, "-c", code],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if pidfile:
            Path(pidfile).write_bytes(str(process.pid).encode("ascii"))
        return process.pid

    async def run(self) -> None:
        options = self.server.create_initialization_options(NotificationOptions(tools_changed=True))
        async with stdio_server(self.wire, self.wire.stdout) as (read_stream, write_stream):  # type: ignore[arg-type]
            await self.server.run(read_stream, write_stream, options)
        if self.options.ignore_eof:
            await anyio.sleep_forever()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="stdio_server")
    parser.add_argument("--starts", metavar="FILE")
    parser.add_argument("--changed", metavar="FILE")
    parser.add_argument("--print-env", action="append", default=[], metavar="NAME")
    parser.add_argument("--ignore-eof", action="store_true")
    options = parser.parse_args(argv)
    if options.ignore_eof and sys.platform != "win32":
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    for name in options.print_env:
        err(f"{name}={os.environ.get(name, '')}\n")
    anyio.run(Fake(options).run)


if __name__ == "__main__":
    main()
