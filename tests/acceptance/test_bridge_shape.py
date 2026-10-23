"""S11: a stdio MCP server behind a bridge, end to end (M7 design O.5, C.2, C.5, C.6, C.11, X13;
N.1's FM-24; J7's B and C shapes, as processes).

One policy shape for every placement, the shipped ``profiles/stdio-bridge.yaml``: a ``kind:
remote`` server on a vault route to the bridge, with the bridge's token as the route's header
credential (tests/acceptance/bridges.py). B's shape (Q46): the bridge on a Unix socket in a
directory the test made and a ``unix:`` route, both eras, each also under ``era: auto``, progress
unbuffered, a cancelled call cancelling the child's request, a legacy restart with changed tools
(``tool_drift``, then ``review --repin``), calls without the token refused, a call in flight
finishing while the vault stops (BP-14's dynamic half), and the soak (fold-in C5, D-83's bridge
half). C's shape: the same bridge on loopback TCP behind a TLS front and an ``https`` route, on
the vault's own guarded client (its address guard and ``egress_private``).

The container rows (A, and B's other uids and launcher) are the image smoke's. Linux only: the
bridge runs on Linux, and the vault never takes a bridge running as root. Every test bounds
itself with ``anyio.fail_after`` and sleeps only to poll.
"""

from __future__ import annotations

import contextlib
import json
import socket
import threading
import time
from pathlib import Path
from typing import Any

import anyio
import certifi
import httpx
import pytest
from mcp.shared.exceptions import MCPError
from mcp.types import TextContent

from tests.bridge.test_bridge_process import (
    HASH,
    INITIALIZE,
    LEGACY,
    TOKEN,
    UID,
    Caller,
    messages,
    socket_dir,
)
from tests.gateway.rig import agent, until
from zoeymcp.common.policy import Policy, check_policy
from zoeymcp.common.yamlload import load_mapping
from zoeymcp.vault.app import GATEWAY_HEADER

from .bridges import (
    PROFILE,
    SERVER,
    SOCKET_UPSTREAM,
    TOOLS,
    children,
    deployment,
    descriptors,
    dumped,
    ready,
    socket_bridge,
    socket_clients,
    start_bridge,
    stderr_line,
    stop,
    tls_front,
    wire_pins,
)
from .conftest import BASE, PROFILES
from .procs import free_port
from .tls import ProviderCA

pytestmark = [
    pytest.mark.anyio,
    pytest.mark.skipif(
        not hasattr(socket, "SO_PEERCRED"),
        reason="the bridge runs on Linux (SO_PEERCRED, process groups)",
    ),
    pytest.mark.skipif(UID <= 0, reason="the vault never takes a bridge running as root"),
]

DEADLINE = 90


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def short_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A short directory: a socket's path has at most 107 bytes."""
    return tmp_path_factory.mktemp("s11", numbered=True)


def text(result: Any) -> str:
    block = result.content[0]
    assert isinstance(block, TextContent)
    return str(block.text)


async def answered(client: Any) -> bool:
    """Whether ``echo`` answers through the bridge now."""
    try:
        return not (await client.call_tool("echo", {"text": "again"})).is_error
    except MCPError:
        return False


def unseen(*places: str) -> None:
    """The bridge's token and its hash appear nowhere a test looked (X14, M.4)."""
    for place in places:
        assert TOKEN not in place
        assert HASH not in place
        assert HASH.removeprefix("sha256:") not in place


# --- B's shape: a bridge on its socket, behind a unix: route ------------------------------------


@pytest.mark.parametrize("asserted", [True, False], ids=["asserted", "auto"])
@pytest.mark.parametrize("era", ["legacy", "modern"])
async def test_s11_lists_and_calls(
    short_dir: Path,
    tmp_path: Path,
    ca: ProviderCA,
    monkeypatch: pytest.MonkeyPatch,
    era: str,
    asserted: bool,
) -> None:
    """The gateway lists and calls a stdio server through the bridge as through any upstream, in
    the bridge's era whether the policy asserts it or says ``auto`` (C.5); a call's progress
    reaches the agent as the child sends it, not with the answer (R36)."""
    seen: list[float] = []

    async def on_progress(progress: float, total: float | None, message: str | None) -> None:
        seen.append(time.monotonic())

    with anyio.fail_after(DEADLINE):
        async with socket_bridge(short_dir, era=era) as bridge:
            pins = await wire_pins(bridge.client(), era)
            gateway = deployment(
                tmp_path,
                ca,
                SOCKET_UPSTREAM,
                pins=pins,
                era=era if asserted else "auto",
                sockets=socket_clients(short_dir, monkeypatch),
            )
            with gateway.running() as running:
                async with agent(running, server=SERVER) as client:
                    listed = await client.list_tools()
                    echoed = await client.call_tool("echo", {"text": "through the bridge"})
                    slow = await client.call_tool(
                        "slow", {"steps": 3, "interval": 0.5}, progress_callback=on_progress
                    )
                    answered = time.monotonic()
            gateway.seen.outputs += [dumped(listed), dumped(echoed), dumped(slow)]
            logged = bridge.process.output()
    assert sorted(tool.name for tool in listed.tools) == sorted(TOOLS)
    assert text(echoed) == "through the bridge"
    assert (slow.is_error, text(slow)) == (False, "done after 3 steps")
    assert len(seen) == 3
    # The first step's progress came a whole second before the answer: nothing held it back.
    assert answered - seen[0] >= 0.9
    connected = gateway.seen.events("upstream_connected")
    assert connected
    assert {line["era"] for line in connected} == {era}
    assert not gateway.seen.events("address_refused")
    unseen(gateway.seen.everything(), logged)


@pytest.mark.parametrize("era", ["legacy", "modern"])
async def test_s11_a_cancelled_call_cancels_the_childs_request(
    short_dir: Path,
    tmp_path: Path,
    ca: ProviderCA,
    monkeypatch: pytest.MonkeyPatch,
    era: str,
) -> None:
    """An agent that leaves a call cancels it in the child: the gateway's explicit cancel in the
    legacy era, the closed stream in the modern one, each reaching the child's own request id
    (C.4). The fake notes both on stderr, which ``--stderr text`` logs."""
    with anyio.fail_after(DEADLINE):
        async with socket_bridge(short_dir, era=era, options=("--stderr", "text")) as bridge:
            pins = await wire_pins(bridge.client(), era)
            gateway = deployment(
                tmp_path,
                ca,
                SOCKET_UPSTREAM,
                pins=pins,
                era=era,
                sockets=socket_clients(short_dir, monkeypatch),
            )
            with gateway.running() as running:
                async with agent(running, server=SERVER) as client:
                    async with anyio.create_task_group() as group:
                        group.start_soon(client.call_tool, "hang", {})
                        hanging = await stderr_line(bridge, "hanging ")
                        group.cancel_scope.cancel()
                    cancelled = await stderr_line(bridge, "cancelled ")
    assert cancelled.split(" ", 1)[1] == hanging.split(" ", 1)[1]


async def test_bridge_restart(
    short_dir: Path, tmp_path: Path, ca: ProviderCA, monkeypatch: pytest.MonkeyPatch
) -> None:
    """FM-24 (fold-in C7): a legacy bridge restarted with a changed program forgets its sessions;
    the gateway's next request gets 404, it opens a new one, lists and compares the pins: the
    changed tool is marked and hidden, and ``review --repin`` serves it again."""
    changed = short_dir / "changed"
    directory = socket_dir(short_dir)
    fake = ("--changed", str(changed))
    first = start_bridge(directory, short_dir / "first.log", fake=fake)
    second = None
    try:
        with anyio.fail_after(DEADLINE):
            await ready(first)
            pins = await wire_pins(first.client(), "legacy")
            gateway = deployment(
                tmp_path, ca, SOCKET_UPSTREAM, pins=pins, sockets=socket_clients(
                    short_dir, monkeypatch
                )
            )  # fmt: skip
            with gateway.running() as running:
                async with agent(running, server=SERVER) as client:
                    before = sorted(tool.name for tool in (await client.list_tools()).tools)
                    assert text(await client.call_tool("time", {})) == "12:00:00Z"
                    await stop(first)
                    changed.write_bytes(b"")
                    second = start_bridge(directory, short_dir / "second.log", fake=fake)
                    await ready(second)
                    # Until the gateway has opened its new session (a 502 while the socket was
                    # gone may have made it back off first).
                    while not await answered(client):
                        await anyio.sleep(0.2)
                    await until(lambda: bool(gateway.seen.events("tool_drift")), DEADLINE)
                    after = sorted(tool.name for tool in (await client.list_tools()).tools)
                code, out, _ = gateway.cli(running, "review", SERVER, "--format", "json",
                                           "--repin", "time")  # fmt: skip
                review = json.loads(out)
                repinned = load_mapping("\n".join(review["snippet"]))
                new = repinned["gateway"]["servers"][SERVER]["review"]
                gateway.reload(TOOLS, new)

                def served() -> bool:
                    snapshot = running.app.policy.snapshot
                    return snapshot is not None and (
                        snapshot.view.gateway.servers[SERVER].review.get("time") == new["time"]
                    )

                await until(served, DEADLINE)
                async with agent(running, server=SERVER) as client:
                    tools = {tool.name: tool for tool in (await client.list_tools()).tools}
    finally:
        await stop(first)
        if second is not None:
            await stop(second)
    assert before == sorted(TOOLS)
    assert after == sorted(set(TOOLS) - {"time"})
    assert code == 1
    assert review["marked"] == ["time"]
    assert new["time"] != pins["time"]
    assert {name: pin for name, pin in new.items() if name != "time"} == {
        name: pin for name, pin in pins.items() if name != "time"
    }
    assert sorted(tools) == sorted(TOOLS)
    assert tools["time"].description == "The current time, in UTC."
    # The new bridge opened a session of its own for the gateway: the old one was gone (404).
    assert second is not None
    assert second.events("bridge_session_started")


async def test_s11_calls_without_the_token_reach_nothing(short_dir: Path) -> None:
    """X13 in B's shape, with no uid in play: on the bridge's own socket, a call without the
    token, with a wrong one, or with an ``Origin`` is 403 with no body, and no child is started
    for it (the other uids' rows are the image smoke's)."""
    with anyio.fail_after(DEADLINE):
        async with socket_bridge(short_dir) as bridge:
            client = bridge.client()
            body = Caller(client, "legacy").body("initialize", INITIALIZE)
            plain = {"content-type": "application/json"}
            answers = [
                await client.post("/mcp", headers=plain, content=body),
                await client.post(
                    "/mcp", headers={**plain, "authorization": "Bearer wrong"}, content=body
                ),
                await client.post(
                    "/mcp",
                    headers={
                        **plain,
                        "authorization": f"Bearer {TOKEN}",
                        "origin": "https://evil.example",
                    },
                    content=body,
                ),
            ]
            refused = bridge.events("bridge_refused")
            sessions = bridge.events("bridge_child_started", purpose="session")
            logged = bridge.process.output()
    assert [(a.status_code, a.content) for a in answers] == [(403, b"")] * 3
    assert [line["status"] for line in refused] == [403, 403, 403]
    assert sessions == []
    unseen(logged)


async def test_s11_a_call_in_flight_finishes_while_the_vault_stops(
    short_dir: Path, tmp_path: Path, ca: ProviderCA, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BP-14's dynamic half, as the standard launcher orders a stop (C.10): the vault, told to
    stop with a call through the bridge in flight, finishes it before it exits, and only then is
    the bridge stopped. The vault's route is called as the gateway calls it."""
    with anyio.fail_after(DEADLINE):
        async with socket_bridge(short_dir) as bridge:
            pins = await wire_pins(bridge.client(), "legacy")
            vault = deployment(
                tmp_path,
                ca,
                SOCKET_UPSTREAM,
                pins=pins,
                sockets=socket_clients(short_dir, monkeypatch),
                link="tcp",
            ).vault
            # As the gateway sends them: its key, no token (the vault adds the bridge's).
            headers = {
                "content-type": "application/json",
                GATEWAY_HEADER: vault.keys.gateway_key(1),
            }
            seen: list[str] = []
            first_progress = threading.Event()

            def rpc(method: str, params: dict[str, Any], rpc_id: Any = None) -> bytes:
                message = {"jsonrpc": "2.0", "method": method, "params": params}
                if rpc_id is not None:
                    message["id"] = rpc_id
                return json.dumps(message).encode()

            def call(url: str, session: dict[str, str]) -> None:
                params = {"name": "slow", "arguments": {"steps": 3, "interval": 1}}
                params["_meta"] = {"progressToken": "stop"}
                with httpx.stream(
                    "POST",
                    url,
                    headers={**headers, **session},
                    content=rpc("tools/call", params, "in-flight"),
                    timeout=60,
                ) as answer:
                    seen.append(str(answer.status_code))
                    for line in answer.iter_lines():
                        seen.append(line)
                        if "notifications/progress" in line:
                            first_progress.set()

            with vault.running() as http:
                url = f"{str(http.base_url).rstrip('/')}{vault.prefix}/mcp"
                opened = http.post(url, headers=headers, content=rpc("initialize", INITIALIZE, 1))
                assert opened.status_code == 200, opened.text
                session = {
                    "mcp-session-id": opened.headers["mcp-session-id"],
                    "mcp-protocol-version": LEGACY,
                }
                initialized = rpc("notifications/initialized", {})
                notified = http.post(url, headers={**headers, **session}, content=initialized)
                assert notified.status_code == 202, notified.text
                worker = threading.Thread(target=call, args=(url, session))
                worker.start()
                assert await anyio.to_thread.run_sync(first_progress.wait, 30)
            # The vault has stopped; the call it was relaying had finished first.
            await anyio.to_thread.run_sync(worker.join, 30)
            assert bridge.process.popen.poll() is None
    assert seen[0] == "200"
    final = messages("\n".join(seen[1:]) + "\n")[-1]
    assert final["id"] == "in-flight"
    assert final["result"]["content"][0]["text"] == "done after 3 steps"


async def test_s11_the_bridge_soak_leaves_no_descriptor_or_child(short_dir: Path) -> None:
    """Fold-in C5, D-83's bridge half: twenty legacy sessions opened, called and deleted leave
    the bridge holding no more descriptors than after the first, and no child."""
    with anyio.fail_after(DEADLINE * 2):
        async with socket_bridge(short_dir) as bridge:
            pid = bridge.process.popen.pid
            client = bridge.client()

            async def session() -> None:
                caller = Caller(client, "legacy")
                await caller.open()
                assert (await caller.call("echo", text="soak")).status_code == 200
                assert (await caller.delete()).status_code == 204

            await session()
            while children(pid):
                await anyio.sleep(0.05)
            before = descriptors(pid)
            for _ in range(20):
                await session()
            while children(pid):
                await anyio.sleep(0.05)
            after = descriptors(pid)
            started = bridge.events("bridge_child_started", purpose="session")
            ended = bridge.events("bridge_session_ended", reason="deleted")
    assert after <= before + 2, (before, after)
    assert len(started) == len(ended) == 21


# --- C's shape: a remote bridge behind a TLS front ----------------------------------------------


async def test_s11_a_remote_bridge_behind_a_tls_front(
    short_dir: Path, tmp_path: Path, ca: ProviderCA, monkeypatch: pytest.MonkeyPatch
) -> None:
    """C.11: the bridge on loopback behind a TLS front, the route's upstream ``https://``, on
    the vault's own guarded route client, whose certifi roots are the test CA here (as
    ``procs.py``'s launcher patches them). The front's address isn't global, so the address
    guard refuses the route until its ``host:port`` is in ``egress_private``, as an operator
    lists it; then listed and called as in B. Through the front, a call without the token, with
    a wrong one or with an ``Origin`` is refused 403."""
    monkeypatch.setattr(certifi, "where", lambda: str(ca.ca_file))
    port = free_port()
    directory = socket_dir(short_dir)
    bridge = start_bridge(directory, short_dir / "bridge.log", listen=f"127.0.0.1:{port}")
    try:
        with anyio.fail_after(DEADLINE), tls_front(ca, port) as front:
            await ready(bridge)
            upstream = f"https://127.0.0.1:{front}"
            async with httpx.AsyncClient(
                base_url=upstream, verify=ca.client_context(), timeout=20
            ) as direct:
                pins = await wire_pins(direct, "legacy")
                body = Caller(direct, "legacy").body("initialize", INITIALIZE)
                plain = {"content-type": "application/json"}
                refused = [
                    await direct.post("/mcp", headers=plain, content=body),
                    await direct.post(
                        "/mcp", headers={**plain, "authorization": "Bearer x"}, content=body
                    ),
                    await direct.post(
                        "/mcp",
                        headers={
                            **plain,
                            "authorization": f"Bearer {TOKEN}",
                            "origin": "https://evil.example",
                        },
                        content=body,
                    ),
                ]
            unlisted, listed_at = tmp_path / "unlisted", tmp_path / "listed"
            unlisted.mkdir(mode=0o700)
            listed_at.mkdir(mode=0o700)
            guarded = deployment(unlisted, ca, upstream, pins=pins, guarded=True)
            with guarded.running() as running:
                async with agent(running, server=SERVER) as client:
                    with contextlib.suppress(MCPError):
                        await client.list_tools()
                    await until(lambda: guarded.seen.events("address_refused"))
            private = {"egress_private": [f"127.0.0.1:{front}"]}
            gateway = deployment(listed_at, ca, upstream, pins=pins, guarded=True, extra=private)
            with gateway.running() as running:
                async with agent(running, server=SERVER) as client:
                    listed = await client.list_tools()
                    echoed = await client.call_tool("echo", {"text": "remote"})
            logged = bridge.process.output()
    finally:
        await stop(bridge)
    [address] = {
        (line["purpose"], line["host"], line["port"], line["verdict"])
        for line in guarded.seen.events("address_refused")
    }
    assert address == ("route", "127.0.0.1", front, "loopback")
    assert sorted(tool.name for tool in listed.tools) == sorted(TOOLS)
    assert text(echoed) == "remote"
    assert not gateway.seen.events("address_refused")
    assert [answer.status_code for answer in refused] == [403, 403, 403]
    unseen(guarded.seen.everything(), gateway.seen.everything(), logged)


def test_s11_the_shipped_profile_loads_and_plain_http_beyond_the_lan_is_refused() -> None:
    """The profile passes check as shipped (the hardened tier's route); the same route over
    plain http to a public name is refused (A.2 row 9: https beyond a local target), while the
    socket and an https front pass."""
    fragment = load_mapping((PROFILES / PROFILE).read_text(encoding="utf-8"))

    def errors(upstream: str | None = None) -> list[str]:
        document = json.loads(json.dumps({**BASE, **fragment}))
        if upstream is not None:
            document["routes"][0]["upstream"] = upstream
        policy = Policy.model_validate(document)
        return [f"{f.path}: {f.message}" for f in check_policy(policy) if f.level == "error"]

    assert errors() == []
    assert errors(SOCKET_UPSTREAM) == []
    assert errors("https://fetch.bridges.example") == []
    refused = errors("http://fetch.bridges.example")
    assert any(
        "fetch.bridges.example isn't a loopback or private address" in error for error in refused
    ), refused
