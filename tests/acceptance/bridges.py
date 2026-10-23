"""S11's rig: the shipped ``profiles/stdio-bridge.yaml`` behind the real vault and gateway, with
``zoeymcp bridge`` in a process of its own around the stdio fake (M7 design O.5, C.2).

Agent (the SDK client) -> gateway -> vault (the acceptance rig's, the gateway on the standard
tier's link socket) -> the bridge -> ``tests/fakes/stdio_server.py``. In B's shape (Q46) the
bridge listens on a Unix socket in a directory the test made, the route's upstream is
``unix:/run/zoeymcp-bridge-fetch/mcp.sock``, and the vault has the socket clients
``--bridge fetch=<the test's uid>`` builds, the ``socket_path`` hook mapping the name to the
test's directory (B.2). In C's shape (C.11) the bridge listens on loopback TCP behind a TLS front
the vault trusts. Every name, pin and the token come from the shipped profile and the fake as it
answers on the wire.
"""

from __future__ import annotations

import asyncio
import contextlib
import copy
import json
import os
import signal
import ssl
import sys
import threading
from collections.abc import AsyncIterator, Iterator, Sequence
from pathlib import Path
from typing import Any

import anyio
import httpx
import pytest
from mcp_types import Tool

from tests.bridge.test_bridge_process import (
    HASH,
    START,
    TOKEN,
    TOKEN_ENV,
    UID,
    Bridge,
    Caller,
    argv,
    messages,
    socket_dir,
)
from tests.fakes.resolver import sockets_in
from zoeymcp.gateway.pins import project_and_pin
from zoeymcp.vault import netclient

from .gateway import GatewayDeployment
from .procs import start
from .tls import ProviderCA

PROFILE = "stdio-bridge.yaml"
SERVER = "fetch"
# The route's upstream in B's shape: the launcher's socket for bridge "fetch" (C.10).
SOCKET_UPSTREAM = "unix:/run/zoeymcp-bridge-fetch/mcp.sock"
# The store name of the route's header credential, and what the profile asserts of the era.
TOKEN_NAME = "bridge-fetch-token"
ERA_LINE = "era: legacy"
# The tools S11 serves, each allowed: the call, progress, a call that never ends, and the one
# --changed alters.
TOOLS = {"echo": "allow", "slow": "allow", "hang": "allow", "time": "allow"}


def start_bridge(
    directory: Path,
    log: Path,
    *,
    era: str = "legacy",
    options: Sequence[str] = (),
    fake: Sequence[str] = (),
    listen: str | None = None,
) -> Bridge:
    """``zoeymcp bridge`` around the stdio fake, on ``<directory>/mcp.sock`` with the test's uid
    as its peer, or with ``listen`` (a loopback ``HOST:PORT``) on TCP; its work directory in
    ``directory``, which must exist."""
    words = argv(directory, era=era, options=options, fake=fake)
    if listen is not None:
        at = words.index("--listen")
        words[at + 1] = listen
        peer = words.index("--peer-uid")
        del words[peer : peer + 2]
    return Bridge(start(words, env={TOKEN_ENV: HASH}, log=log), directory, directory / "work")


async def ready(bridge: Bridge) -> None:
    """Until the bridge's readiness probe passed; fails if the bridge exits first."""
    with anyio.fail_after(START):
        while not bridge.events("bridge_ready"):
            assert bridge.process.popen.poll() is None, bridge.process.output()
            await anyio.sleep(0.05)


@contextlib.asynccontextmanager
async def socket_bridge(
    base: Path,
    *,
    era: str = "legacy",
    options: Sequence[str] = (),
    fake: Sequence[str] = (),
) -> AsyncIterator[Bridge]:
    """A ready bridge on ``<base>/zoeymcp-bridge-fetch/mcp.sock`` (B's shape), stopped after."""
    bridge = start_bridge(
        socket_dir(base), base / "bridge.log", era=era, options=options, fake=fake
    )
    try:
        await ready(bridge)
        yield bridge
    finally:
        await stop(bridge)


async def stop(bridge: Bridge) -> None:
    for client in bridge.extra:
        await client.aclose()
    bridge.extra.clear()
    bridge.process.stop()
    reap_children(bridge)


def reap_children(bridge: Bridge) -> None:
    """After the bridge was killed, kill every child it logged starting that outlived it: each
    leads a process group of its own (C.3). A bridge that stopped stopped its children itself."""
    if sys.platform == "win32" or (bridge.process.popen.returncode or 0) >= 0:
        return
    for started in bridge.events("bridge_child_started"):
        with contextlib.suppress(OSError):
            if os.getpgid(started["pid"]) == started["pid"]:
                os.killpg(started["pid"], signal.SIGKILL)


async def stderr_line(bridge: Bridge, prefix: str) -> str:
    """The first ``--stderr text`` line starting with ``prefix``, once the bridge logs it."""
    with anyio.fail_after(START):
        while True:
            for line in bridge.events("bridge_stderr"):
                if str(line.get("text", "")).startswith(prefix):
                    return str(line["text"]).strip()
            await anyio.sleep(0.05)


async def wire_pins(client: httpx.AsyncClient, era: str) -> dict[str, str]:
    """The pins of :data:`TOOLS` as the bridge lists them: one ``tools/list`` straight to it,
    as the gateway would make it (a legacy session is opened and ended around it)."""
    caller = Caller(client, era)
    await caller.open()
    listed = await caller.request("tools/list")
    if era == "legacy":
        assert (await caller.delete()).status_code == 204
    wire = messages(listed.text)[-1]["result"]["tools"]
    return {
        tool["name"]: project_and_pin(Tool.model_validate(copy.deepcopy(tool))).pin
        for tool in wire
        if tool["name"] in TOOLS
    }


def socket_clients(base: Path, monkeypatch: pytest.MonkeyPatch) -> netclient.SocketClients:
    """The vault's clients for ``--bridge fetch=<the test's uid>``, its socket found in
    ``base`` (B.2's ``socket_path`` hook, set before the clients are built)."""
    monkeypatch.setattr(netclient, "HOOKS", netclient.Hooks(socket_path=sockets_in(base)))
    return netclient.SocketClients({"fetch": UID}, timeout=httpx.Timeout(60.0, connect=10.0))


def deployment(
    tmp_path: Path,
    ca: ProviderCA,
    upstream: str,
    *,
    pins: dict[str, str],
    era: str = "legacy",
    sockets: netclient.SocketClients | None = None,
    link: str = "unix",
    guarded: bool = False,
    extra: dict[str, Any] | None = None,
) -> GatewayDeployment:
    """The shipped profile with ``upstream`` as its route's upstream, :data:`TOOLS` allowed under
    ``pins``, the server's era as given (``auto`` included), and the bridge's token stored;
    ``guarded`` and ``extra`` as :class:`GatewayDeployment` takes them."""
    return GatewayDeployment(
        tmp_path,
        upstream,
        ca,
        profile=PROFILE,
        server=SERVER,
        secrets={TOKEN_NAME: TOKEN},
        tools=TOOLS,
        pins=pins,
        link=link,  # type: ignore[arg-type]
        link_uid=UID if link == "unix" else None,
        replace={ERA_LINE: f"era: {era}"},
        socket_clients=sockets,
        guarded=guarded,
        extra=extra,
    )


def descriptors(pid: int) -> int:
    """How many file descriptors process ``pid`` holds."""
    return len(os.listdir(f"/proc/{pid}/fd"))


def children(pid: int) -> list[int]:
    """The live processes whose parent is ``pid``."""
    found = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/stat", encoding="ascii", errors="replace") as handle:
                fields = handle.read().rsplit(")", 1)[1].split()
        except OSError:
            continue
        if int(fields[1]) == pid and fields[0] != "Z":
            found.append(int(entry))
    return found


@contextlib.contextmanager
def tls_front(ca: ProviderCA, port: int) -> Iterator[int]:
    """A TLS front for a bridge on ``127.0.0.1:<port>``, as an operator's own proxy is (C.11): it
    terminates TLS with the test CA's certificate and passes the bytes on as they come, adding
    nothing and buffering nothing. It runs on a thread of its own, so a test that blocks its own
    loop doesn't stall it. Yields its port."""
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(str(ca.cert_file), str(ca.key_file))
    loop = asyncio.new_event_loop()
    started = threading.Event()
    stopping: asyncio.Event | None = None
    bound: list[int] = []

    async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()
        except OSError:
            pass
        finally:
            writer.close()

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            upstream = await asyncio.open_connection("127.0.0.1", port)
        except OSError:
            writer.close()
            return
        await asyncio.gather(pipe(reader, upstream[1]), pipe(upstream[0], writer))

    async def main() -> None:
        nonlocal stopping
        stopping = asyncio.Event()
        server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=context)
        bound.append(server.sockets[0].getsockname()[1])
        started.set()
        async with server:
            await stopping.wait()

    thread = threading.Thread(target=loop.run_until_complete, args=(main(),), daemon=True)
    thread.start()
    assert started.wait(10), "the TLS front didn't start"
    try:
        yield bound[0]
    finally:
        assert stopping is not None
        loop.call_soon_threadsafe(stopping.set)
        thread.join(10)
        if not thread.is_alive():
            loop.close()


def dumped(value: Any) -> str:
    """An answer as the agent got it, for the sweep."""
    if hasattr(value, "model_dump"):
        return json.dumps(value.model_dump(mode="json", by_alias=True, exclude_none=True))
    return str(value)
