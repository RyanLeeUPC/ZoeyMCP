"""The ledger's reporter, the gateway side of the report path (M5 design J.3, O.4's P13).

- against a scripted vault: what each round asks, sends and decides, and what it logs;
- against the real vault app and its copy, over both links (TCP with the gateway key, and the
  link socket, which is Linux only): records arrive byte for byte, a restored or lost gateway
  ledger shows as a fork, and a restart of the chain lifts it;
- the whole gateway: an approval completes while the vault refuses or holds every report, and an
  approval's records reach the copy.
"""

from __future__ import annotations

import asyncio
import io
import json
import os
import shutil
import sys
import tempfile
import threading
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import Any

import anyio
import httpx
import httpx2
import pytest
from starlette.types import ASGIApp, Receive, Scope, Send

from tests.fakes.agent import ACCEPT, Script, agent
from tests.fakes.harness import serve
from tests.fakes.mcp_server import McpFake
from tests.gateway.rig import KEYS, deployment_with, gateway, raw_policy, until
from tests.gateway.test_approvals_remote import ATTENDED, TOOLS, by_ref, headers, text
from tests.gateway.test_ledger import REF_A, REF_B, REF_C, call, opened
from tests.gateway.test_upstream import review
from tests.unit.test_peer import my_uid, serve_link
from zoeymcp.common import ledgerformat, ledgerreport, logs
from zoeymcp.common.policy import Policy
from zoeymcp.gateway import reporting
from zoeymcp.gateway.ledger import LEDGER_DIR, Ledger
from zoeymcp.gateway.reporter import Reporter
from zoeymcp.gateway.vaultlink import KeySource, Link, parse_link, report_client
from zoeymcp.vault.app import VaultApp
from zoeymcp.vault.reportstore import REPORTED_DIR, ReportStore
from zoeymcp.vault.server import ListenerTag
from zoeymcp.vault.store import SecretStore

pytestmark = pytest.mark.anyio
PATH = ledgerreport.PATH
LINKS = ["tcp", pytest.param("unix", marks=pytest.mark.skipif(
    sys.platform != "linux", reason="the link socket's peer check is Linux only"
))]  # fmt: skip


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def log() -> Iterator[io.StringIO]:
    stream = io.StringIO()
    logs.set_stream(stream)
    try:
        yield stream
    finally:
        logs.set_stream(None)


def events(stream: io.StringIO, kind: str) -> list[dict[str, Any]]:
    lines = [json.loads(line) for line in stream.getvalue().splitlines() if line]
    return [line for line in lines if line["event"] == kind]


def stored(state: Path) -> list[bytes]:
    """The gateway ledger's lines, as on disk without their newlines."""
    found: list[bytes] = []
    for path in sorted((state / LEDGER_DIR).glob("*.jsonl")):
        found.extend(path.read_bytes().splitlines())
    return found


def head_of(line: bytes | None, state: str = "ok") -> dict[str, Any]:
    if line is None:
        return {"head_seq": None, "head_hash": None, "state": state}
    record = ledgerformat.parse(line)
    return {"head_seq": record.seq, "head_hash": record.hash, "state": state}


# --- against a scripted vault -------------------------------------------------------------------


class Vault:
    """Answers each report request with the next of ``answers``, and keeps the requests."""

    def __init__(self) -> None:
        self.answers: list[httpx2.Response | Exception] = []
        self.requests: list[httpx2.Request] = []

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer

    def posted(self, index: int = -1) -> list[bytes]:
        posts = [r for r in self.requests if r.method == "POST"]
        body = json.loads(posts[index].content)
        assert set(body) == {"v", "lines"}
        assert body["v"] == 1
        return [line.encode() for line in body["lines"]]


def answer(status: int, document: dict[str, Any]) -> httpx2.Response:
    return httpx2.Response(status, json=document)


def refusal(status: int, code: str, head: dict[str, Any] | None = None) -> httpx2.Response:
    return httpx2.Response(
        status,
        json={"error": "refused", "code": code, **(head or {})},
        headers={"x-zoeymcp-vault": "refused"},
    )


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def reporter_on(vault: Vault, ledger: Ledger, clock: Clock | None = None) -> Reporter:
    http = report_client(parse_link("unix:/run/v.sock"), None, inner=httpx2.MockTransport(vault))
    return Reporter(http, ledger, clock=clock or Clock(), jitter=lambda: 0.5)


async def test_the_first_report_sends_every_line_from_the_start(tmp_path: Path) -> None:
    ledger, _ = opened(tmp_path)
    await call(ledger, REF_A)
    lines = stored(tmp_path)
    vault = Vault()
    vault.answers = [answer(200, head_of(None)), answer(200, head_of(lines[-1]))]
    reporter = reporter_on(vault, ledger)
    assert await reporter.report_once() == "sent"
    [get, post] = vault.requests
    assert (get.method, get.url.raw_path, get.content) == ("GET", PATH.encode(), b"")
    assert (post.method, post.url.raw_path) == ("POST", PATH.encode())
    assert post.headers["content-type"] == "application/json"
    assert post.content == ledgerreport.encode(lines)
    assert vault.posted() == lines  # byte for byte
    # The accepted answer is the head: the next round reads from it without asking.
    assert await reporter.report_once() == "idle"
    assert len(vault.requests) == 2
    assert reporter.head is not None
    assert reporter.head.seq == 2


async def test_a_round_reads_from_the_copys_head_and_drops_it(tmp_path: Path) -> None:
    ledger, _ = opened(tmp_path)
    await call(ledger, REF_A)
    await call(ledger, REF_B)
    lines = stored(tmp_path)
    vault = Vault()
    vault.answers = [answer(200, head_of(lines[2])), answer(200, head_of(lines[-1]))]
    assert await reporter_on(vault, ledger).report_once() == "sent"
    assert vault.posted() == lines[3:]


async def test_caught_up_is_idle(tmp_path: Path) -> None:
    ledger, _ = opened(tmp_path)
    await call(ledger, REF_A)
    lines = stored(tmp_path)
    vault = Vault()
    vault.answers = [answer(200, head_of(lines[-1]))]
    assert await reporter_on(vault, ledger).report_once() == "idle"
    assert [r.method for r in vault.requests] == ["GET"]
    empty, _ = opened(tmp_path / "empty")
    vault.answers = [answer(200, head_of(None))]
    assert await reporter_on(vault, empty).report_once() == "idle"


async def test_a_ledger_behind_the_copy_sends_from_its_start(tmp_path: Path) -> None:
    """A restored or lost gateway volume: what it sends shows the vault a fork at once."""
    ledger, _ = opened(tmp_path)
    await call(ledger, REF_A)
    lines = stored(tmp_path)
    vault = Vault()
    far = {"head_seq": 40, "head_hash": "sha256:" + "c" * 64, "state": "ok"}
    vault.answers = [answer(200, far), refusal(409, "fork", {**far, "state": "fork"})]
    reporter = reporter_on(vault, ledger)
    assert await reporter.report_once() == "refused"
    assert vault.posted() == lines
    assert reporter.head is not None
    assert reporter.head.state == "fork"


@pytest.mark.parametrize("state", ["fork", "gap", "full"])
async def test_a_copy_that_refuses_is_asked_and_sent_nothing(
    tmp_path: Path, log: io.StringIO, state: str
) -> None:
    ledger, _ = opened(tmp_path)
    await call(ledger, REF_A)
    vault = Vault()
    vault.answers = [answer(200, head_of(stored(tmp_path)[0], state))]
    assert await reporter_on(vault, ledger).report_once() == "refused"
    assert [r.method for r in vault.requests] == ["GET"]
    [failed] = events(log, "ledger_report_failed")
    assert (failed["reason"], failed["level"]) == (state, "warning")
    assert reporting.next_step("refused", failures=0, jitter=0.5) == reporting.Wait(300.0, False)


@pytest.mark.parametrize(
    ("answers", "reason"),
    [
        ([httpx2.ConnectError("down")], "ConnectError"),
        ([httpx2.ReadTimeout("slow")], "ReadTimeout"),
        ([refusal(503, "unavailable")], "unavailable"),
        ([refusal(403, "x" * 65)], "status_403"),
        ([httpx2.Response(403, json={"error": "forbidden"})], "status_403"),
        ([httpx2.Response(200, content=b"not json")], "bad_answer"),
        ([answer(200, {"head_seq": 1, "head_hash": None, "state": "ok"})], "bad_answer"),
        ([answer(200, {"head_seq": None, "head_hash": None, "state": "odd"})], "bad_answer"),
        ([httpx2.Response(200, content=b" " * 5000)], "ResponseTooLarge"),
        ([httpx2.Response(307, headers={"location": "/"})], "UpstreamRedirect"),
        ([answer(200, head_of(None)), refusal(429, "busy")], "busy"),
        ([answer(200, head_of(None)), refusal(400, "not_a_chain")], "not_a_chain"),
        ([answer(200, head_of(None)), refusal(409, "fork", head_of(None))], "fork"),
        ([answer(200, head_of(None)), httpx2.Response(409, content=b"{")], "bad_answer"),
        ([answer(200, head_of(None)), httpx2.RemoteProtocolError("cut")], "RemoteProtocolError"),
    ],
)
async def test_failures_end_the_round(
    tmp_path: Path, log: io.StringIO, answers: list[Any], reason: str
) -> None:
    ledger, _ = opened(tmp_path)
    await call(ledger, REF_A)
    vault = Vault()
    vault.answers = answers
    assert await reporter_on(vault, ledger).report_once() == "failed"
    assert vault.answers == []
    [failed] = events(log, "ledger_report_failed")
    assert failed["reason"] == reason


async def test_a_ledger_that_cant_be_read_fails_the_round(
    tmp_path: Path, log: io.StringIO, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger, _ = opened(tmp_path)

    def unreadable(after: int, limit: int) -> list[bytes]:
        raise PermissionError(13, "denied")

    monkeypatch.setattr(ledger, "lines", unreadable)
    vault = Vault()
    vault.answers = [answer(200, head_of(None))]
    assert await reporter_on(vault, ledger).report_once() == "failed"
    assert events(log, "ledger_report_failed")[0]["reason"] == "PermissionError"


async def test_failures_are_logged_once_per_five_minutes(tmp_path: Path, log: io.StringIO) -> None:
    ledger, _ = opened(tmp_path)
    clock = Clock()
    vault = Vault()
    reporter = reporter_on(vault, ledger, clock)
    for advance in (0.0, 100.0, 199.0, 1.0, 10.0):
        clock.now += advance
        vault.answers = [httpx2.ConnectError("down")]
        assert await reporter.report_once() == "failed"
    assert len(events(log, "ledger_report_failed")) == 2  # at 0 s and at 300 s


async def test_a_long_ledger_goes_in_batches_of_at_most_256(tmp_path: Path) -> None:
    ledger, _ = opened(tmp_path)
    for index in range(100):
        await call(ledger, f"{index:016x}")  # 300 records
    lines = stored(tmp_path)
    vault = Vault()
    vault.answers = [
        answer(200, head_of(None)),
        answer(200, head_of(lines[255])),
        answer(200, head_of(lines[-1])),
    ]
    reporter = reporter_on(vault, ledger)
    assert [await reporter.report_once() for _ in range(3)] == ["sent", "sent", "idle"]
    assert vault.posted(0) == lines[:256]
    assert vault.posted(1) == lines[256:]
    assert all(len(r.content) <= reporting.REPORT_BATCH_BYTES for r in vault.requests)


async def test_an_accepted_report_that_takes_nothing_isnt_sent_again_at_once(
    tmp_path: Path,
) -> None:
    ledger, _ = opened(tmp_path)
    await call(ledger, REF_A)
    lines = stored(tmp_path)
    vault = Vault()
    vault.answers = [answer(200, head_of(lines[0])), answer(200, head_of(lines[0]))]
    assert await reporter_on(vault, ledger).report_once() == "idle"


async def test_no_ledger_line_reaches_the_log(tmp_path: Path, log: io.StringIO) -> None:
    ledger, _ = opened(tmp_path)
    await call(ledger, REF_A, args={"secret": "do-not-log"})
    vault = Vault()
    vault.answers = [answer(200, head_of(None)), refusal(400, "bad_line")]
    assert await reporter_on(vault, ledger).report_once() == "failed"
    text = log.getvalue()
    for line in stored(tmp_path):
        assert line.decode() not in text
        record = ledgerformat.parse(line)
        assert record.hash not in text
        for value in record.fields.values():
            if isinstance(value, str) and len(value) > 8:
                assert value not in text
    assert "do-not-log" not in text


async def test_the_loop_wakes_on_an_append_and_backs_off_on_failure(tmp_path: Path) -> None:
    ledger, _ = opened(tmp_path)
    vault = Vault()
    vault.answers = [answer(200, head_of(None))]
    reporter = reporter_on(vault, ledger)
    async with anyio.create_task_group() as group:
        group.start_soon(reporter.run)
        with anyio.fail_after(5):
            while len(vault.requests) < 1:
                await anyio.sleep(0.01)
            await anyio.sleep(0.05)
            assert len(vault.requests) == 1  # idle: waiting for an append, or 60 s
            await ledger.write("repaired", None, critical=True, torn_bytes=1)
            line = stored(tmp_path)[0]
            vault.answers = [answer(200, head_of(None)), httpx2.ConnectError("down")]
            while len(vault.requests) < 3:
                await anyio.sleep(0.01)
        await anyio.sleep(0.05)
        assert len(vault.requests) == 3  # backing off, 5 s and more
        group.cancel_scope.cancel()
    assert vault.posted() == [line]


# --- against the real vault, over both links ----------------------------------------------------


@contextmanager
def real_vault(tmp_path: Path, link: str) -> Iterator[tuple[Link, KeySource | None, ReportStore]]:
    """The vault app with its copy, on TCP with the gateway key or on the link socket."""
    policy = Policy.model_validate(raw_policy("http://127.0.0.1:9", include=[], review={}))
    store = SecretStore(tmp_path / "vault", KEYS)
    store.load()
    copy = ReportStore.open(tmp_path / "vault")
    app = VaultApp(
        policy,
        store,
        KEYS,
        client=httpx.AsyncClient(),
        environ={},
        gateway_link=link == "unix",
        reports=copy,
    )
    if link == "tcp":
        with serve(app) as url:
            yield parse_link(url), KeySource(KEYS.gateway_key(1)), copy
        return
    # A short path: AF_UNIX paths are limited to about 100 bytes.
    directory = Path(tempfile.mkdtemp(prefix="zm-", dir="/tmp"))
    os.chmod(directory, 0o700)
    try:
        socket = str(directory / "vault.sock")
        with serve_link(ListenerTag(app, "gateway"), socket, my_uid()):
            yield parse_link(f"unix:{socket}"), None, copy
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def copied(tmp_path: Path) -> list[bytes]:
    """The copy's live lines, as the vault holds them."""
    found: list[bytes] = []
    for path in sorted((tmp_path / "vault" / REPORTED_DIR).glob("*.jsonl")):
        found.extend(path.read_bytes().splitlines())
    return found


async def report_all(reporter: Reporter) -> str:
    """Rounds until the copy holds everything, or refuses."""
    with anyio.fail_after(30):
        while (outcome := await reporter.report_once()) == "sent":
            pass
    return outcome


@asynccontextmanager
async def reporting_to(
    link: Link, keys: KeySource | None, ledger: Ledger
) -> AsyncIterator[Reporter]:
    async with report_client(link, keys) as http:
        yield Reporter(http, ledger)


@pytest.mark.parametrize("link", LINKS)
async def test_records_arrive_in_the_copy_byte_for_byte(tmp_path: Path, link: str) -> None:
    state = tmp_path / "gateway"
    ledger, _ = opened(state)
    with real_vault(tmp_path, link) as (where, keys, copy):
        async with reporting_to(where, keys, ledger) as reporter:
            assert await report_all(reporter) == "idle"  # nothing yet
            assert copy.contact_ms is not None  # the vault heard from the gateway
            await call(ledger, REF_A)
            assert await report_all(reporter) == "idle"
            assert copied(tmp_path) == stored(state)
            for index in range(90):
                await call(ledger, f"{index:016x}")
            assert await report_all(reporter) == "idle"
    assert copied(tmp_path) == stored(state)
    assert len(copied(tmp_path)) == 273
    assert copy.head().seq == ledger.next_seq - 1
    assert copy.head().hash == ledger.prev
    assert copy.state == "ok"


@pytest.mark.parametrize("link", LINKS)
@pytest.mark.parametrize("volume", ["restored", "lost"])
async def test_a_restored_gateway_ledger_is_a_fork_until_a_restart(
    tmp_path: Path, log: io.StringIO, link: str, volume: str
) -> None:
    state = tmp_path / "gateway"
    ledger, _ = opened(state)
    await call(ledger, REF_A)
    backup = tmp_path / "backup"
    shutil.copytree(state / LEDGER_DIR, backup)
    await call(ledger, REF_B)
    with real_vault(tmp_path, link) as (where, keys, copy):
        async with reporting_to(where, keys, ledger) as reporter:
            assert await report_all(reporter) == "idle"
        assert copy.head().seq == 5
        # The gateway's volume comes back from the backup, or empty, and goes on writing.
        shutil.rmtree(state / LEDGER_DIR)
        if volume == "restored":
            shutil.copytree(backup, state / LEDGER_DIR)
        again, _ = opened(state)
        await call(again, REF_C)
        async with reporting_to(where, keys, again) as reporter:
            assert await report_all(reporter) == "refused"
            assert copy.state == "fork"
            assert copy.head().seq == 5  # nothing of the new history was taken
            [refused] = [e for e in events(log, "ledger_report_refused") if e["role"] == "vault"]
            assert refused["reason"] == "fork"
            assert await report_all(reporter) == "refused"  # sticky
            # The operator decides why, and restarts the chain: the next report is taken.
            copy.restart()
            assert await report_all(reporter) == "idle"
    assert copy.head().state == "ok"
    assert copied(tmp_path) == stored(state)
    assert copy.head().hash == again.prev


# --- the whole gateway --------------------------------------------------------------------------


class ReportGate:
    """The vault's report path as a test sets it: every request is held until ``release`` (with
    ``hold``), then refused with 503; everything else goes to the vault."""

    def __init__(self, *, hold: bool) -> None:
        self.hold = hold
        self.arrived = 0
        self.release = threading.Event()
        self.app: ASGIApp | None = None

    def wrap(self, app: ASGIApp) -> ASGIApp:
        self.app = app
        return self

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        assert self.app is not None
        if scope["type"] != "http" or scope["path"] != PATH:
            await self.app(scope, receive, send)
            return
        self.arrived += 1
        while self.hold and not self.release.is_set():
            await asyncio.sleep(0.02)
        body = b'{"code":"unavailable","error":"service unavailable"}'
        headers = [(b"content-type", b"application/json"), (b"x-zoeymcp-vault", b"refused")]
        await send({"type": "http.response.start", "status": 503, "headers": headers})
        await send({"type": "http.response.body", "body": body})


def options(fake: McpFake) -> dict[str, Any]:
    return {
        "include": TOOLS,
        "review": review(fake),
        "approve": ["echo"],
        "approvals": {"agent1": ATTENDED},
    }


@pytest.mark.parametrize("hold", [False, True], ids=["refused", "held"])
async def test_an_approval_completes_while_the_vault_refuses_every_report(
    tmp_path: Path, hold: bool
) -> None:
    fake = McpFake()
    gate = ReportGate(hold=hold)
    with deployment_with(tmp_path, fake, options(fake), wrap=gate.wrap) as deployed:
        try:
            with gateway(deployed, report=True) as running:
                await until(lambda: gate.arrived >= 1)
                if not hold:
                    await until(lambda: deployed.events("ledger_report_failed"))
                script = Script([ACCEPT])
                async with agent(
                    running.mcp(), version="modern", script=script, headers=headers()
                ) as client:
                    with anyio.fail_after(20):
                        result = await client.call_tool("echo", {"text": "sent anyway"})
                assert text(result).endswith("sent anyway")
                [prompt] = script.prompts
                ref = prompt.message.split("\n")[0].removeprefix("Approval request ")
                assert by_ref(deployed, ref) == [
                    ("asked", "modern"),
                    ("decided", "accept"),
                    ("outcome", "ok"),
                ]
                if hold:
                    assert gate.arrived == 1  # the reporter is still waiting on its first ask
        finally:
            gate.release.set()
    if not hold:
        [failed, *_] = deployed.events("ledger_report_failed")
        assert failed["reason"] == "unavailable"


async def test_an_approvals_records_reach_the_vaults_copy(tmp_path: Path) -> None:
    fake = McpFake()
    copy = ReportStore.open(tmp_path / "vault")
    with (
        deployment_with(tmp_path, fake, options(fake), reports=copy) as deployed,
        gateway(deployed, report=True) as running,
    ):
        await until(lambda: copy.contact_ms is not None)  # the reporter's first ask
        script = Script([ACCEPT])
        async with agent(
            running.mcp(), version="modern", script=script, headers=headers()
        ) as client:
            await client.call_tool("echo", {"text": "reported"})
        await until(lambda: copy.head().seq == 2)
        assert copied(tmp_path) == stored(deployed.state)
        assert [ledgerformat.parse(line).kind for line in copied(tmp_path)] == [
            "asked",
            "decided",
            "outcome",
        ]
    assert copy.state == "ok"
    assert deployed.events("ledger_report_failed") == []
