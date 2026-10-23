"""A real bridge process around the stdio fake (M7 design C.3 to C.5, C.8; N.1's FM-18 to
FM-23, FM-19's and FM-30's bridge halves; X13's bridge half, X14, X17).

``zoeymcp bridge`` runs in its own interpreter (``procs.start``), on a Unix socket in a directory
the test made, with ``--peer-uid`` the test's own uid, around ``tests/fakes/stdio_server.py``
(its hostile switches are tools, so one child behaves until a test asks). The test talks to it
as the vault does: over the socket, with the route's token. ``--max-procs`` is the test uid's
own hard limit, since ``RLIMIT_NPROC`` counts every process of the uid, the test runner's
included (one below its own limits where the test reads the limit back). Every test bounds
itself with ``anyio.fail_after`` and never sleeps but to poll.

The acceptance row: a bridge served on a socket behind 18b's socket client answers
``tools/list`` through a real vault route.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
from collections.abc import AsyncIterator, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import anyio
import httpx
import pytest

from tests.acceptance.procs import LAUNCHER, PASSED, Process, free_port, start
from tests.fakes.resolver import sockets_in
from tests.unit.test_netclient import KEY, bridges_policy, bridges_vault
from zoeymcp.common.policy.schema import hash_token
from zoeymcp.vault import netclient
from zoeymcp.vault.app import GATEWAY_HEADER
from zoeymcp.vault.keys import KeySet

pytestmark = [
    pytest.mark.anyio,
    pytest.mark.skipif(
        not hasattr(socket, "SO_PEERCRED"),
        reason="the bridge runs on Linux (SO_PEERCRED, process groups)",
    ),
]

FAKE = Path(__file__).resolve().parents[1] / "fakes" / "stdio_server.py"
# The token tests/unit/test_netclient.py's bridges_vault stores for the route "fetch".
TOKEN = "token-fetch"
HASH = hash_token(TOKEN)
TOKEN_ENV = "ZOEYMCP_BRIDGE_TOKEN_SHA256"
UID = getattr(os, "getuid", lambda: -1)()
LEGACY = "2025-11-25"
MODERN = "2026-07-28"
META = {
    "io.modelcontextprotocol/protocolVersion": MODERN,
    "io.modelcontextprotocol/clientInfo": {"name": "bridge-test", "version": "1"},
    "io.modelcontextprotocol/clientCapabilities": {},
}
INITIALIZE = {
    "protocolVersion": LEGACY,
    "capabilities": {},
    "clientInfo": {"name": "bridge-test", "version": "1"},
}
START = 30


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def max_procs() -> int:
    """The test uid's own hard ``RLIMIT_NPROC``: the bridge may not raise it, and a lower one
    could leave it no room beside the runner's processes."""
    if sys.platform == "win32":
        pytest.skip("POSIX only")
    import resource

    _, hard = resource.getrlimit(resource.RLIMIT_NPROC)
    return 1 << 20 if hard == resource.RLIM_INFINITY else int(hard)


def lower_procs() -> int:
    """One below both of the test uid's own ``RLIMIT_NPROC`` limits: a value the child can't
    inherit, so only the bridge's own setting gives it, close enough to leave the runner room."""
    if sys.platform == "win32":
        pytest.skip("POSIX only")
    import resource

    limits = resource.getrlimit(resource.RLIMIT_NPROC)
    return min(1 << 20 if limit == resource.RLIM_INFINITY else int(limit) for limit in limits) - 1


# --- the rig --------------------------------------------------------------------------------------


@dataclass
class Bridge:
    process: Process
    directory: Path
    work: Path
    extra: list[httpx.AsyncClient] = field(default_factory=list)

    @property
    def socket(self) -> Path:
        return self.directory / "mcp.sock"

    def records(self) -> list[dict[str, Any]]:
        return [json.loads(line) for line in self.process.output().splitlines() if line[:1] == "{"]

    def events(self, kind: str, **match: Any) -> list[dict[str, Any]]:
        return [
            record
            for record in self.records()
            if record.get("event") == kind and all(record.get(k) == v for k, v in match.items())
        ]

    async def logged(self, kind: str, count: int = 1, **match: Any) -> list[dict[str, Any]]:
        """Waits until ``kind`` (with ``match``) was logged ``count`` times."""
        while len(found := self.events(kind, **match)) < count:
            await asyncio.sleep(0.05)
        return found

    def client(self) -> httpx.AsyncClient:
        client = httpx.AsyncClient(
            transport=httpx.AsyncHTTPTransport(uds=str(self.socket)),
            base_url="http://bridge.invalid",
            timeout=20,
        )
        self.extra.append(client)
        return client


@pytest.fixture
def short_dir() -> Iterator[Path]:
    """A short directory: a socket's path has at most 107 bytes."""
    directory = Path(tempfile.mkdtemp(prefix="zbp-"))
    try:
        yield directory
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def socket_dir(base: Path, mode: int = 0o700) -> Path:
    directory = base / "zoeymcp-bridge-fetch"
    directory.mkdir(mode=0o700)
    directory.chmod(mode)
    return directory


def argv(
    directory: Path,
    *,
    era: str = "legacy",
    options: Sequence[str] = (),
    fake: Sequence[str] = (),
    peer_uid: int = UID,
    procs: int | None = None,
) -> list[str]:
    return [
        "bridge",
        "--listen",
        f"unix:{directory / 'mcp.sock'}",
        "--peer-uid",
        str(peer_uid),
        "--era",
        era,
        "--work-dir",
        str(directory / "work"),
        "--max-procs",
        str(max_procs() if procs is None else procs),
        *options,
        "--",
        sys.executable,
        str(FAKE),
        *fake,
    ]


@contextlib.asynccontextmanager
async def running(
    base: Path,
    *,
    era: str = "legacy",
    options: Sequence[str] = (),
    fake: Sequence[str] = (),
    env: dict[str, str] | None = None,
    peer_uid: int = UID,
    ready: bool = True,
    procs: int | None = None,
) -> AsyncIterator[Bridge]:
    """A bridge on ``<base>/zoeymcp-bridge-fetch/mcp.sock``, ready unless ``ready`` is false."""
    directory = socket_dir(base)
    process = start(
        argv(directory, era=era, options=options, fake=fake, peer_uid=peer_uid, procs=procs),
        env={TOKEN_ENV: HASH, **(env or {})},
        log=base / "bridge.log",
    )
    bridge = Bridge(process, directory, directory / "work")
    try:
        if ready:
            with anyio.fail_after(START):
                await bridge.logged("bridge_ready")
        yield bridge
    finally:
        for client in bridge.extra:
            await client.aclose()
        process.stop()


def refused_start(base: Path, words: Sequence[str], env: dict[str, str] | None = None) -> str:
    """Runs ``zoeymcp <words>``, which must refuse to start (exit 2); its output."""
    process = start(words, env={TOKEN_ENV: HASH} if env is None else env, log=base / "start.log")
    try:
        assert process.popen.wait(30) == 2, process.output()
    finally:
        process.stop()
    return process.output()


def messages(text: str) -> list[dict[str, Any]]:
    """The JSON-RPC messages of an SSE answer, in order."""
    return [json.loads(line[6:]) for line in text.splitlines() if line.startswith("data: ")]


@dataclass
class Caller:
    """A client of one era, as the gateway's SDK client sends through the vault."""

    client: httpx.AsyncClient
    era: str
    session: str | None = None
    ids: int = 0

    def headers(self, method: str, name: str | None = None) -> dict[str, str]:
        headers = {"authorization": f"Bearer {TOKEN}", "content-type": "application/json"}
        if self.era == "modern":
            headers |= {"mcp-protocol-version": MODERN, "mcp-method": method}
            if name is not None:
                headers["mcp-name"] = name
        elif self.session is not None:
            headers |= {"mcp-session-id": self.session, "mcp-protocol-version": LEGACY}
        return headers

    def body(self, method: str, params: dict[str, Any], rpc_id: Any = None) -> bytes:
        if self.era == "modern":
            params = {**params, "_meta": {**params.get("_meta", {}), **META}}
        if rpc_id is None:
            self.ids += 1
            rpc_id = self.ids
        message = {"jsonrpc": "2.0", "id": rpc_id, "method": method, "params": params}
        return json.dumps(message).encode()

    async def request(
        self, method: str, params: dict[str, Any] | None = None, rpc_id: Any = None
    ) -> httpx.Response:
        name = (params or {}).get("name")
        return await self.client.post(
            "/mcp",
            headers=self.headers(method, name),
            content=self.body(method, params or {}, rpc_id),
        )

    async def call(self, tool: str, rpc_id: Any = None, **arguments: Any) -> httpx.Response:
        return await self.request("tools/call", {"name": tool, "arguments": arguments}, rpc_id)

    async def notify(self, method: str, params: dict[str, Any] | None = None) -> httpx.Response:
        message: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        return await self.client.post(
            "/mcp", headers=self.headers(method), content=json.dumps(message).encode()
        )

    async def open(self) -> None:
        """Legacy: initialize and ``notifications/initialized``; modern: ``server/discover``."""
        if self.era == "modern":
            found = await self.request("server/discover")
            assert found.status_code == 200, found.text
            return
        self.session = None  # an initialize is sent without one
        answer = await self.request("initialize", INITIALIZE)
        assert answer.status_code == 200, answer.text
        self.session = answer.headers["mcp-session-id"]
        assert (await self.notify("notifications/initialized")).status_code == 202

    async def delete(self) -> httpx.Response:
        return await self.client.delete("/mcp", headers=self.headers("DELETE"))


async def opened(bridge: Bridge, era: str = "legacy") -> Caller:
    caller = Caller(bridge.client(), era)
    await caller.open()
    return caller


def result_text(answer: httpx.Response) -> str:
    final = messages(answer.text)[-1]
    return str(final["result"]["content"][0]["text"])


# --- both eras, and the answers the bridge makes itself (C.4, C.5, X13, X17) ----------------------


async def test_a_legacy_bridge_relays_calls_and_their_progress(short_dir: Path) -> None:
    async with running(short_dir) as bridge:
        with anyio.fail_after(START):
            caller = await opened(bridge)
            listed = await caller.request("tools/list")
            meta = {"_meta": {"progressToken": "tok-5"}}
            progress = await caller.request(
                "tools/call", {"name": "progress", "arguments": {"steps": 2}, **meta}, "call-5"
            )
            echoed = await caller.call("echo", text="hello")
            stray = await caller.request("tools/list")
            gone = await caller.delete()
            after = await caller.request("tools/list")
    names = [tool["name"] for tool in messages(listed.text)[-1]["result"]["tools"]]
    assert {"time", "fetch", "echo", "hang"} <= set(names)
    assert progress.headers["content-type"] == "text/event-stream"
    sent = messages(progress.text)
    # The progress notifications carry the client's own token back, then the answer its id.
    assert [m["params"]["progressToken"] for m in sent[:-1]] == ["tok-5", "tok-5"]
    assert sent[-1]["id"] == "call-5"
    assert result_text(echoed) == "hello"
    assert stray.status_code == 200
    assert gone.status_code == 204
    assert after.status_code == 404
    [started] = bridge.events("bridge_session_started")
    assert len(started["session"]) == 8  # a hash8, never the id
    assert caller.session is not None
    assert caller.session not in bridge.process.output()


async def test_a_modern_bridge_serves_one_child_and_refuses_initialize(short_dir: Path) -> None:
    async with running(short_dir, era="modern") as bridge:
        with anyio.fail_after(START):
            caller = await opened(bridge, "modern")
            big = await caller.call("big")
            huge = await caller.call("huge")
            refused = await caller.request("initialize", INITIALIZE)
            get = await caller.client.get("/mcp", headers=caller.headers("GET"))
    # 2 MiB and an integer of 2^63 pass (CR-6), the integer as the child wrote it.
    assert len(result_text(big)) == 2 * 1024 * 1024
    assert '"value":9223372036854775808' in huge.text
    assert refused.status_code == 400
    assert refused.json()["error"]["data"]["supported"] == [MODERN]
    assert get.status_code == 405
    # The probe's child is the one child (C.5).
    assert [e["purpose"] for e in bridge.events("bridge_child_started")] == ["probe"]


async def test_unauthenticated_calls_reach_nothing(short_dir: Path) -> None:
    """X13's bridge half, and X17: no token, a wrong one, an ``Origin``: 403 with one empty
    body; no OAuth path is answered; the child sees nothing."""
    async with running(short_dir) as bridge:
        client = bridge.client()
        body = Caller(client, "legacy").body("initialize", INITIALIZE)
        json_type = {"content-type": "application/json"}
        with anyio.fail_after(START):
            answers = [
                await client.post("/mcp", headers=json_type, content=body),
                await client.post(
                    "/mcp", headers={**json_type, "authorization": "Bearer wrong"}, content=body
                ),
                await client.post(
                    "/mcp",
                    headers={**json_type, "authorization": f"Bearer {TOKEN}", "origin": "x"},
                    content=body,
                ),
            ]
            paths = [
                await client.get(path, headers={"authorization": f"Bearer {TOKEN}"})
                for path in ("/.well-known/oauth-authorization-server", "/register", "/token")
            ]
    assert [(a.status_code, a.content) for a in answers] == [(403, b"")] * 3
    assert [a.status_code for a in paths] == [404] * 3
    assert [e["purpose"] for e in bridge.events("bridge_child_started")] == ["probe"]


# --- N.1's bridge rows ----------------------------------------------------------------------------


@pytest.mark.parametrize("era", ["legacy", "modern"])
async def test_child_dies(short_dir: Path, era: str) -> None:
    """FM-18: the call in flight is 502; legacy, the session is then 404 and a new one works;
    modern, the next request gets a new child."""
    async with running(short_dir, era=era) as bridge:
        with anyio.fail_after(START):
            caller = await opened(bridge, era)
            crashed = await caller.call("crash")
            stale = await caller.request("tools/list")
            if era == "legacy":
                await caller.open()
                after = await caller.request("tools/list")
    assert crashed.status_code == 502
    purposes = [e["purpose"] for e in bridge.events("bridge_child_started")]
    if era == "legacy":
        assert stale.status_code == 404
        assert after.status_code == 200
        assert purposes == ["probe", "session", "session"]
    else:
        assert stale.status_code == 200
        assert purposes == ["probe", "shared"]
    [exited] = bridge.events("bridge_child_exited", code=3)
    assert exited["purpose"] == ("session" if era == "legacy" else "probe")


async def gives_up(caller: Caller, tool: str, rpc_id: Any) -> None:
    """A call the caller leaves after half a second, as the gateway's ``call_timeout`` does."""
    with pytest.raises(httpx.ReadTimeout):
        await caller.client.post(
            "/mcp",
            headers=caller.headers("tools/call", tool),
            content=caller.body("tools/call", {"name": tool, "arguments": {}}, rpc_id),
            timeout=0.5,
        )


async def test_child_hangs(short_dir: Path) -> None:
    """FM-20: the caller gives up and cancels, and the cancel reaches the child with the id
    the child was sent (the session's ``initialize`` was 1, the call 2); DELETE stops the child
    at once, and a session left idle is stopped at ``--idle-timeout``."""
    options = ["--idle-timeout", "1", "--stderr", "text"]
    async with running(short_dir, options=options) as bridge:
        with anyio.fail_after(START):
            first = await opened(bridge)
            await gives_up(first, "hang", 7)
            cancel = await first.notify("notifications/cancelled", {"requestId": 7})
            await bridge.logged("bridge_stderr", text="cancelled 2")
            deleted = await first.delete()
            await bridge.logged("bridge_session_ended", reason="deleted")
            second = await opened(bridge)
            await gives_up(second, "hang", 8)
            await bridge.logged("bridge_session_ended", reason="idle")
            await bridge.logged("bridge_child_exited", purpose="session", count=2)
            after = await second.request("tools/list")
    assert cancel.status_code == 202
    assert not bridge.events("bridge_stderr", text="cancelled 7")
    assert deleted.status_code == 204
    assert after.status_code == 404


async def test_silent_call_gets_keepalives(short_dir: Path) -> None:
    """FM-19's process half: a silent call's stream carries ``: keepalive`` comments."""
    async with running(short_dir, options=["--keepalive", "0.2"]) as bridge:
        with anyio.fail_after(START):
            caller = await opened(bridge)
            body = caller.body("tools/call", {"name": "hang", "arguments": {}})
            seen = b""
            async with caller.client.stream(
                "POST", "/mcp", headers=caller.headers("tools/call", "hang"), content=body
            ) as answer:
                async for chunk in answer.aiter_raw():
                    seen += chunk
                    if seen.count(b": keepalive\n\n") >= 2:
                        break
    assert answer.status_code == 200
    assert answer.headers["content-type"] == "text/event-stream"
    assert seen.startswith(b": keepalive\n\n")


async def data_until(lines: AsyncIterator[str], method: str) -> list[dict[str, Any]]:
    """The messages of an SSE stream up to and including the first with ``method``."""
    found: list[dict[str, Any]] = []
    async for line in lines:
        if line.startswith("data: "):
            found.append(json.loads(line[6:]))
            if found[-1].get("method") == method:
                return found
    raise AssertionError(f"the stream ended before {method}: {found}")


async def test_legacy_get_streams_take_the_unsolicited_notifications(short_dir: Path) -> None:
    """C.5 (SPEC-4): each GET is a stream of its own, each notification goes to the oldest open
    one, and the streams end with the session."""
    async with running(short_dir) as bridge:
        with anyio.fail_after(START):
            caller = await opened(bridge)
            headers = caller.headers("GET")
            async with (
                caller.client.stream("GET", "/mcp", headers=headers) as first,
                caller.client.stream("GET", "/mcp", headers=headers) as second,
            ):
                announced = await caller.call("announce")
                lines = first.aiter_lines()
                [note] = await data_until(lines, "notifications/tools/list_changed")
                deleted = await caller.delete()
                rest = [line async for line in lines]
                other = await second.aread()
    assert (first.status_code, second.status_code) == (200, 200)
    assert first.headers["content-type"] == "text/event-stream"
    assert result_text(announced) == "announced"
    assert "id" not in note
    assert deleted.status_code == 204
    assert not [line for line in rest if line.startswith("data: ")]
    assert b"data: " not in other


async def test_a_modern_listen_gets_its_own_notifications(short_dir: Path) -> None:
    """C.4: the child's notifications for a listen reach that listen's stream with the client's
    own id as ``subscriptionId``; closing the stream is its cancel, sent to the child for the id
    it was sent (the probe was 1, ``server/discover`` 2, the listen 3)."""
    subscription = "io.modelcontextprotocol/subscriptionId"
    async with running(short_dir, era="modern", options=["--stderr", "text"]) as bridge:
        with anyio.fail_after(START):
            caller = await opened(bridge, "modern")
            params = {"notifications": {"toolsListChanged": True}}
            body = caller.body("subscriptions/listen", params, "listen-1")
            headers = caller.headers("subscriptions/listen")
            async with caller.client.stream(
                "POST", "/mcp", headers=headers, content=body
            ) as listen:
                lines = listen.aiter_lines()
                acknowledged = await data_until(lines, "notifications/subscriptions/acknowledged")
                announced = await caller.call("announce")
                changed = await data_until(lines, "notifications/tools/list_changed")
            await bridge.logged("bridge_stderr", text="cancelled 3")
    assert listen.status_code == 200
    assert result_text(announced) == "announced"
    notes = [*acknowledged, *changed]
    assert [note["params"]["_meta"][subscription] for note in notes] == ["listen-1"] * 2


async def test_line_flood(short_dir: Path) -> None:
    """FM-21: 100 MB with no newline ends the child at ``--max-message-bytes``."""
    async with running(short_dir, options=["--max-message-bytes", "1048576"]) as bridge:
        with anyio.fail_after(START):
            caller = await opened(bridge)
            flooded = await caller.call("flood")
            await bridge.logged("bridge_child_exited", purpose="session")
    assert flooded.status_code == 502
    assert bridge.events("bridge_child_violation", reason="too_long")


STDERR_LINES = ["z" * 65536 + "\n"]
STDERR_LINES += [f"stderr line {n} " + "y" * 100 + "\n" for n in range(2000)]


@pytest.mark.parametrize("mode", ["counts", "text"])
async def test_stderr_flood(short_dir: Path, mode: str) -> None:
    """FM-22: counted by default, never shown; with ``--stderr text``, at most 50 lines a
    window, each cut at 2 KiB, then the count left out."""
    async with running(short_dir, options=["--stderr", mode]) as bridge:
        with anyio.fail_after(START):
            caller = await opened(bridge)
            flooded = await caller.call("stderr_flood")
            await caller.delete()
            await bridge.logged("bridge_child_exited", purpose="session")
    assert result_text(flooded) == "flooded stderr"
    pid = bridge.events("bridge_child_started", purpose="session")[0]["pid"]
    shown = bridge.events("bridge_stderr", pid=pid)
    if mode == "counts":
        assert [(line["lines"], line["bytes"]) for line in shown] == [
            (len(STDERR_LINES), sum(map(len, STDERR_LINES)))
        ]
        assert "text" not in shown[0]
        assert "stderr line" not in bridge.process.output()
    else:
        texts = [line["text"] for line in shown]
        assert texts[0] == "z" * 2048
        assert texts[1:] == [line.rstrip("\n") for line in STDERR_LINES[1:50]]
        [suppressed] = bridge.events("bridge_stderr_suppressed", pid=pid)
        assert suppressed["count"] == len(STDERR_LINES) - 50


async def test_child_ignores_eof(short_dir: Path) -> None:
    """FM-23: a child that ignores stdin's end and SIGTERM is killed, with its group, 4 s on."""
    async with running(short_dir, fake=["--ignore-eof"]) as bridge:
        with anyio.fail_after(START):
            caller = await opened(bridge)
            deleted = await caller.delete()
            [exited] = await bridge.logged("bridge_child_exited", purpose="session")
    assert deleted.status_code == 204
    assert exited["signal"] == 9


async def test_the_childs_requests_and_bad_lines(short_dir: Path) -> None:
    """X14: requests from the child are answered by the bridge (``ping``) or refused, never
    relayed; an answer to an id never sent is counted; a line that isn't JSON, or a batch,
    ends the child."""
    async with running(short_dir) as bridge:
        with anyio.fail_after(START):
            caller = await opened(bridge)
            asked = await caller.call("ask")
            strayed = await caller.call("stray")
            garbled = await caller.call("garbage")
            await caller.open()
            batched = await caller.call("batch")
            await bridge.logged("bridge_child_exited", purpose="session", count=2)
    answers = json.loads(result_text(asked))
    assert answers["fake-ask-ping"]["result"] == {}
    for refused in ("fake-ask-sampling", "fake-ask-roots"):
        assert answers[refused]["error"]["code"] == -32601
    methods = [e["method"] for e in bridge.events("bridge_client_request_refused")]
    assert methods == ["sampling/createMessage", "roots/list"]
    assert result_text(strayed) == "strayed"
    assert bridge.events("bridge_unmatched", count=1)
    assert (garbled.status_code, batched.status_code) == (502, 502)
    reasons = [e["reason"] for e in bridge.events("bridge_child_violation")]
    assert reasons == ["invalid_json", "batch"]


def process_state(pid: int) -> str | None:
    """A process's state letter from ``/proc``, or None once it is gone (a zombie is ``Z``)."""
    try:
        status = Path(f"/proc/{pid}/stat").read_bytes().decode()
    except FileNotFoundError:
        return None
    return status.rsplit(")", 1)[1].split()[0]


async def test_a_stopped_childs_group_goes_with_it(short_dir: Path) -> None:
    """Contract 48's effect: a grandchild the child left is killed with the child's group."""
    pidfile = short_dir / "grandchild.pid"
    async with running(short_dir) as bridge:
        with anyio.fail_after(START):
            caller = await opened(bridge)
            await caller.call("grandchild", pidfile=str(pidfile))
            pid = int(pidfile.read_bytes())
            assert process_state(pid) not in (None, "Z")
            await caller.delete()
            while process_state(pid) not in (None, "Z"):
                await asyncio.sleep(0.05)


async def test_the_childs_limits_and_environment(short_dir: Path) -> None:
    """C.3: the child inherits ``RLIMIT_NPROC`` (a value below the test's own limits, so the
    bridge set it) and ``oom_score_adj`` 1000, runs in ``<work>`` (made 0700), and has no
    ``ZOEYMCP_`` variable."""
    procs = lower_procs()
    async with running(short_dir, env={"ZOEYMCP_OTHER": "x"}, procs=procs) as bridge:
        with anyio.fail_after(START):
            await opened(bridge)
            pid = bridge.events("bridge_child_started", purpose="session")[0]["pid"]
            limits = Path(f"/proc/{pid}/limits").read_text(encoding="ascii")
            adjust = Path(f"/proc/{pid}/oom_score_adj").read_text(encoding="ascii")
            environ = Path(f"/proc/{pid}/environ").read_bytes().split(b"\0")
            cwd = os.readlink(f"/proc/{pid}/cwd")
    [line] = [row for row in limits.splitlines() if row.startswith("Max processes")]
    assert line.split()[2:4] == [str(procs)] * 2
    assert adjust.strip() == "1000"
    names = {item.split(b"=", 1)[0] for item in environ if item}
    assert not any(name.startswith(b"ZOEYMCP_") for name in names)
    assert names <= {b"PATH", b"HOME", b"TMPDIR", b"LANG", b"LC_ALL", b"TZ"}
    assert cwd == str(bridge.work / "work")
    assert (bridge.work.stat().st_mode & 0o777) == 0o700


# --- start and stop (C.8, FM-30) ------------------------------------------------------------------


@pytest.mark.parametrize("value", [None, "sha256:abc", "sha256:" + "A" * 64])
def test_no_token_hash(short_dir: Path, value: str | None) -> None:
    """FM-30's bridge half: unset or malformed, the start is refused before the socket exists."""
    directory = socket_dir(short_dir)
    env = {} if value is None else {TOKEN_ENV: value}
    output = refused_start(short_dir, argv(directory), env)
    assert TOKEN_ENV in output
    assert value is None or value not in output
    assert not (directory / "mcp.sock").exists()
    assert not (directory / "work").exists()


async def test_a_term_from_the_control_pipe_stops_it(short_dir: Path) -> None:
    directory = socket_dir(short_dir)
    read, write = os.pipe()
    log = short_dir / "bridge.log"
    environment = {name: os.environ[name] for name in PASSED if name in os.environ}
    words = argv(directory, options=["--control-fd", str(read)])
    with log.open("ab") as handle:
        popen = subprocess.Popen(  # noqa: S603 - our own interpreter and arguments
            [sys.executable, "-c", LAUNCHER, "", "", "", *words],
            env={**environment, TOKEN_ENV: HASH},
            stdout=handle,
            stderr=subprocess.STDOUT,
            pass_fds=(read,),
        )
    os.close(read)
    bridge = Bridge(Process(popen, log), directory, directory / "work")
    try:
        with anyio.fail_after(START):
            await bridge.logged("bridge_ready")
            await opened(bridge)
            os.write(write, b"TERM\n")
            while popen.poll() is None:
                await asyncio.sleep(0.05)
    finally:
        os.close(write)
        for client in bridge.extra:
            await client.aclose()
        bridge.process.stop()
    assert popen.returncode == 0
    assert bridge.events("control_received", command="TERM")
    assert {e["purpose"] for e in bridge.events("bridge_child_exited")} == {"probe", "session"}
    assert bridge.events("bridge_stopped")


async def test_another_peer_uid_is_cut_before_anything_is_read(short_dir: Path) -> None:
    async with running(short_dir, peer_uid=UID + 1, ready=False) as bridge:
        with anyio.fail_after(START):
            await bridge.logged("bridge_started")
            while not bridge.socket.exists():
                await asyncio.sleep(0.05)
            with pytest.raises(httpx.TransportError):
                await Caller(bridge.client(), "legacy").request("initialize", INITIALIZE)
            [refused] = await bridge.logged("bridge_peer_refused")
    assert refused["uid"] == UID
    assert not bridge.events("bridge_refused")


@pytest.mark.parametrize("mode", [0o720, 0o701, 0o704])
def test_a_socket_directory_others_can_use_is_refused(short_dir: Path, mode: int) -> None:
    directory = socket_dir(short_dir, mode)
    output = refused_start(short_dir, argv(directory))
    assert "the socket's directory" in output
    assert not (directory / "mcp.sock").exists()


@pytest.mark.skipif(UID != 0, reason="only root can make a directory another uid owns")
def test_a_socket_directory_another_uid_owns_is_refused(short_dir: Path) -> None:
    if sys.platform == "win32":
        pytest.skip("POSIX only")
    directory = socket_dir(short_dir)
    os.chown(directory, 12345, 12345)
    output = refused_start(short_dir, argv(directory))
    assert "is owned by uid 12345" in output


async def test_a_stale_socket_is_removed(short_dir: Path) -> None:
    if sys.platform == "win32":
        pytest.skip("POSIX only")
    directory = socket_dir(short_dir)
    stale = socket.socket(socket.AF_UNIX)
    stale.bind(str(directory / "mcp.sock"))
    stale.close()
    process = start(argv(directory), env={TOKEN_ENV: HASH}, log=short_dir / "bridge.log")
    bridge = Bridge(process, directory, directory / "work")
    try:
        with anyio.fail_after(START):
            await bridge.logged("bridge_ready")
            await opened(bridge)
    finally:
        for client in bridge.extra:
            await client.aclose()
        process.stop()


def test_another_entry_at_the_socket_path_is_refused(short_dir: Path) -> None:
    directory = socket_dir(short_dir)
    (directory / "mcp.sock").write_bytes(b"not a socket")
    output = refused_start(short_dir, argv(directory))
    assert "exists and is not a socket" in output
    assert (directory / "mcp.sock").read_bytes() == b"not a socket"


def test_peer_uid_goes_only_with_a_unix_listen(short_dir: Path) -> None:
    words = ["bridge", "--listen", f"127.0.0.1:{free_port()}", "--peer-uid", str(UID)]
    words += ["--era", "legacy", "--work-dir", str(short_dir / "work"), "--", "true"]
    assert "--peer-uid goes only with --listen unix:" in refused_start(short_dir, words)
    unix = ["bridge", "--listen", f"unix:{short_dir}/mcp.sock", "--era", "legacy", "--", "true"]
    assert "needs --peer-uid" in refused_start(short_dir, unix)


@pytest.mark.parametrize("repeat", ["--listen=127.0.0.1:9", "--work-dir=/tmp/elsewhere"])
def test_a_launcher_style_command_line_refuses_a_repeat(short_dir: Path, repeat: str) -> None:
    """C.10: the launcher's options come first; the operator's arguments can't repeat them."""
    directory = socket_dir(short_dir)
    words = argv(directory)
    words.insert(words.index("--"), repeat)
    output = refused_start(short_dir, words)
    assert "is given once" in output


def test_a_work_dir_not_its_own_0700_is_refused(short_dir: Path) -> None:
    directory = socket_dir(short_dir)
    (directory / "work").mkdir(mode=0o700)
    (directory / "work").chmod(0o755)
    output = refused_start(short_dir, argv(directory))
    assert "isn't this uid's own directory with mode 0700" in output


# --- acceptance: through a real vault route (18b's socket client) ---------------------------------


@pytest.mark.skipif(UID <= 0, reason="the vault never takes a bridge running as root")
async def test_tools_list_through_a_vault_route(
    short_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The vault started with ``--bridge fetch=<the test's uid>`` reaches the bridge on its
    socket (``socket_path`` maps the fixed path to the test's directory), injects the token,
    and the gateway's ``initialize`` and ``tools/list`` are answered (B.2, C.10, Q46)."""
    monkeypatch.setattr(netclient, "HOOKS", netclient.Hooks(socket_path=sockets_in(short_dir)))
    policy = bridges_policy({"fetch": "unix:/run/zoeymcp-bridge-fetch/mcp.sock"})
    async with running(short_dir) as bridge:
        app = bridges_vault(short_dir, policy, {"fetch": UID})
        transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 40000))
        gateway = {GATEWAY_HEADER: KeySet.from_text(KEY).gateway_key(1)}
        try:
            async with httpx.AsyncClient(transport=transport, base_url="http://vault") as vault:
                caller = Caller(vault, "legacy")
                with anyio.fail_after(START):
                    started = await vault.post(
                        "/fetch/mcp",
                        headers={**caller.headers("initialize"), **gateway},
                        content=caller.body("initialize", INITIALIZE),
                    )
                    caller.session = started.headers["mcp-session-id"]
                    listed = await vault.post(
                        "/fetch/mcp",
                        headers={**caller.headers("tools/list"), **gateway},
                        content=caller.body("tools/list", {}),
                    )
        finally:
            await app.aclose()
    assert started.status_code == 200, started.text
    names = [tool["name"] for tool in messages(listed.text)[-1]["result"]["tools"]]
    assert "time" in names
    assert not bridge.events("bridge_peer_refused")
