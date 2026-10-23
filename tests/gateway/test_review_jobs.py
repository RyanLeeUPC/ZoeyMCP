"""The gateway's side of the review job path (M7 design F.3, step 12b2; D-72's restated trigger).

- ``_ReviewOnly``: the review client reaches the jobs path and the report path, and nothing else;
- the poller against the real vault app over both links (TCP with the gateway key, and the link
  socket, which is Linux only), its review replaced: a queued job is claimed, run and reported;
- the poller against the vault app in process, on a clock the test moves: the review lock, the
  report fitted to the caps, a lying report refused whole, a report too large, the review's own
  error, a toolkit job, and FM-13, FM-14, FM-15 and FM-17;
- the whole gateway on a real upstream: ``review --via vault`` prints what ``review`` prints, and
  the gateway closes its vault-link clients at shutdown (D-166).

The log never names a job by its ID, only by hash8 (M.4).
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import time
from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import anyio
import httpx
import httpx2
import pytest
from mcp.types import Tool
from starlette.types import ASGIApp, Receive, Scope, Send

from tests.fakes.harness import serve
from tests.fakes.mcp_server import McpFake
from tests.gateway.rig import (
    KEYS,
    Clock,
    deployment,
    gateway,
    pin_of_fake,
    raw_policy,
    until,
)
from tests.gateway.toolkit_rig import ENTRY_POINTS, mail_server, toolkit_policy
from tests.unit.test_peer import my_uid, serve_link
from zoeymcp.cli.main import main
from zoeymcp.common import logs, pinhash, reviewreport
from zoeymcp.common.policy import Policy
from zoeymcp.common.policy.view import GatewayView, ViewRemoteServer, build_view
from zoeymcp.gateway import pins, review, reviewpoll
from zoeymcp.gateway.app import GatewayApp
from zoeymcp.gateway.defstore import DefinitionStore
from zoeymcp.gateway.marks import DriftMarks
from zoeymcp.gateway.policyclient import PolicyClient, Snapshot
from zoeymcp.gateway.reviewpoll import CLAIM_DEADLINE, Job, ReviewPoller
from zoeymcp.gateway.server import AdminApp as GatewayAdmin
from zoeymcp.gateway.toolkits import Toolkits
from zoeymcp.gateway.upstream import UpstreamPool
from zoeymcp.gateway.vaultlink import (
    REVIEW_JOBS_PATH,
    REVIEW_MAX_ANSWER_BYTES,
    REVIEW_REPORT_PATH,
    VIEW_PATH,
    KeySource,
    Link,
    ResponseTooLarge,
    UpstreamBlocked,
    UpstreamRedirect,
    parse_link,
    review_client,
    view_client,
)
from zoeymcp.vault import internal, reviewjobs
from zoeymcp.vault.admin import AdminApp, SetupCodes
from zoeymcp.vault.app import VaultApp
from zoeymcp.vault.reviewjobs import QUEUE_TTL, REVIEW_START_GRACE, JobTable
from zoeymcp.vault.server import ListenerTag
from zoeymcp.vault.store import SecretStore

pytestmark = pytest.mark.anyio
LINKS = ["tcp", pytest.param("unix", marks=pytest.mark.skipif(
    sys.platform != "linux", reason="the link socket's peer check is Linux only"
))]  # fmt: skip
LINK = "unix:/run/zoeymcp-link/vault.sock"
SENTINEL = "review-description-sentinel"
# FM-24: from a review queued right after a reload to its report (K.5).
STARTS_WITHIN = 2.0


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


def events(stream: io.StringIO, kind: str, role: str = "gateway") -> list[dict[str, Any]]:
    lines = [json.loads(line) for line in stream.getvalue().splitlines() if line]
    return [line for line in lines if line["event"] == kind and line["role"] == role]


def hash8(job: str) -> str:
    return hashlib.sha256(job.encode()).hexdigest()[:8]


def notes_policy() -> Policy:
    return Policy.model_validate(raw_policy("http://127.0.0.1:9", include=[], review={}))


def tool(name: str, description: str = "Does a thing.") -> Tool:
    return Tool.model_validate(
        {"name": name, "description": description, "inputSchema": {"type": "object"}}
    )


def answer_for(view: GatewayView, *names: str) -> dict[str, Any]:
    """The gateway's review of a listing of ``names`` (review.report(), as review.review answers
    it), the first one's description a sentinel."""
    served = view.gateway.servers["notes"]
    assert isinstance(served, ViewRemoteServer)
    limits = view.gateway.limits
    tools = [
        tool(name, SENTINEL if index == 0 else "Does a thing.") for index, name in enumerate(names)
    ]
    evaluation = pins.evaluate(tools, served, frozenset(), limits)
    return review.report(
        "notes",
        served,
        tools,
        evaluation,
        marks=frozenset(),
        defs=lambda pin: None,
        limits=limits,
        era="modern",
        protocol_version="2026-07-28",
        server_info=None,
        instructions=None,
    )


def wired(value: Any) -> Any:
    return json.loads(json.dumps(value))


@dataclass
class Stub:
    """The gateway as the poller reaches it: a policy client holding ``view``, the review lock
    it shares with the admin socket, and for a toolkit review the toolkits and the marks."""

    policy: PolicyClient
    reviewing: anyio.Lock = field(default_factory=anyio.Lock)
    toolkits: Toolkits | None = None
    pool: Any = None

    def hold(self, view: GatewayView) -> None:
        self.policy.snapshot = Snapshot(view, time.monotonic())
        self.policy.last_contact = time.monotonic()

    @property
    def snapshot(self) -> Snapshot:
        snapshot = self.policy.snapshot
        assert snapshot is not None
        return snapshot


async def never(snapshot: Snapshot, previous: Snapshot | None) -> None:
    raise AssertionError("the poller never fetches the view")


def stub(view: GatewayView) -> Stub:
    http = httpx2.AsyncClient(transport=httpx2.MockTransport(lambda request: httpx2.Response(500)))
    gateway = Stub(PolicyClient(http, never))
    gateway.hold(view)
    return gateway


class Sleeps:
    """The poller's sleep: records each, sleeps none, and stops the loop after ``stop`` of them."""

    def __init__(self, stop: int | None = None) -> None:
        self.seen: list[float] = []
        self.stop = stop

    async def __call__(self, seconds: float) -> None:
        self.seen.append(seconds)
        if self.stop is not None and len(self.seen) >= self.stop:
            raise Stop


class Stop(Exception):
    pass


def reviewing(answer: Callable[[], dict[str, Any]]) -> Callable[[Any, str], Awaitable[Any]]:
    async def run(app: Any, server: str) -> dict[str, Any]:
        return answer()

    return run


# --- _ReviewOnly ----------------------------------------------------------------------------------


def test_the_paths_are_the_vaults() -> None:
    assert internal.REVIEW_JOBS.path.text == REVIEW_JOBS_PATH
    assert internal.REVIEW_REPORT.path.text == REVIEW_REPORT_PATH


def test_the_pollers_timings_are_the_vaults() -> None:
    """The gateway can't import the vault: its copies of the poll's wait and the claim deadline
    are kept equal here, or it would retry a post past the vault's deadline."""
    assert reviewpoll.WAIT == internal.REVIEW_WAIT
    assert reviewpoll.CLAIM_DEADLINE == reviewjobs.CLAIM_DEADLINE


ALLOWED = [
    ("GET", f"{REVIEW_JOBS_PATH}?wait=25&view=sha256:{'a' * 64}"),
    ("GET", f"{REVIEW_JOBS_PATH}?view=x"),
    ("GET", REVIEW_JOBS_PATH),
    ("POST", REVIEW_REPORT_PATH),
]
REFUSED = [
    ("GET", VIEW_PATH),
    ("GET", "/_zoeymcp/gateway/v1/report/ledger"),
    ("POST", "/_zoeymcp/gateway/v1/report/ledger"),
    ("POST", REVIEW_JOBS_PATH),
    ("GET", REVIEW_REPORT_PATH),
    ("PUT", REVIEW_REPORT_PATH),
    ("DELETE", REVIEW_JOBS_PATH),
    ("POST", REVIEW_REPORT_PATH + "?x=1"),
    ("POST", REVIEW_REPORT_PATH + "/"),
    ("GET", REVIEW_JOBS_PATH + "/"),
    ("GET", f"{REVIEW_JOBS_PATH}?wait=1&x=1"),
    ("GET", f"{REVIEW_JOBS_PATH}?view=a&view=b"),
    ("GET", f"{REVIEW_JOBS_PATH}?wait"),
    ("GET", f"{REVIEW_JOBS_PATH}?"),
    ("GET", "/_zoeymcp/gateway/v1/review/jobs/x"),
    ("GET", "/s/notes/mcp"),
    ("GET", "http://elsewhere.invalid" + REVIEW_JOBS_PATH),
    ("GET", "http://vault.invalid:8080" + REVIEW_JOBS_PATH),
    ("GET", "https://vault.invalid" + REVIEW_JOBS_PATH),
]


async def test_the_review_client_reaches_the_review_job_path_only() -> None:
    seen: list[str] = []

    def vault(request: httpx2.Request) -> httpx2.Response:
        seen.append(request.url.raw_path.decode())
        return httpx2.Response(200, json={"v": 1, "jobs": []})

    async with review_client(parse_link(LINK), None, inner=httpx2.MockTransport(vault)) as http:
        for method, url in ALLOWED:
            assert (await http.request(method, url)).status_code == 200
        for method, url in REFUSED:
            with pytest.raises(UpstreamBlocked):
                await http.request(method, url)
    assert len(seen) == len(ALLOWED)


async def test_the_review_client_follows_no_redirect_and_caps_answers() -> None:
    def vault(request: httpx2.Request) -> httpx2.Response:
        if request.method == "GET":
            return httpx2.Response(307, headers={"location": REVIEW_JOBS_PATH})
        return httpx2.Response(200, content=b"x" * (REVIEW_MAX_ANSWER_BYTES + 1))

    async with review_client(parse_link(LINK), None, inner=httpx2.MockTransport(vault)) as http:
        with pytest.raises(UpstreamRedirect):
            await http.get(REVIEW_JOBS_PATH)
        with pytest.raises(ResponseTooLarge):
            await http.post(REVIEW_REPORT_PATH, content=b"{}")


async def test_the_gateway_key_goes_with_every_request_on_tcp() -> None:
    headers: list[str | None] = []

    def vault(request: httpx2.Request) -> httpx2.Response:
        headers.append(request.headers.get("x-zoeymcp-gateway"))
        return httpx2.Response(200, json={})

    keys = KeySource(KEYS.gateway_key(1))
    link = parse_link("http://vault:8080")
    async with review_client(link, keys, inner=httpx2.MockTransport(vault)) as http:
        await http.get(REVIEW_JOBS_PATH)
        await http.post(REVIEW_REPORT_PATH, content=b"{}")
    async with review_client(parse_link(LINK), None, inner=httpx2.MockTransport(vault)) as http:
        await http.get(REVIEW_JOBS_PATH)
    assert headers == [KEYS.gateway_key(1)] * 2 + [None]


# --- against the real vault, over both links -----------------------------------------------------


class Beside:
    """The vault app on its listener, and its admin socket app under ``/_test_admin``, on one
    loop, as the vault serves its socket."""

    def __init__(self, app: ASGIApp, admin: ASGIApp) -> None:
        self.app = app
        self.admin = admin

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        path = scope.get("path", "")
        if scope["type"] == "http" and path.startswith("/_test_admin"):
            await self.admin({**scope, "path": path.removeprefix("/_test_admin")}, receive, send)
            return
        await self.app(scope, receive, send)


@dataclass
class Real:
    link: Link
    keys: KeySource | None
    jobs: JobTable
    admin: httpx.Client


@contextmanager
def real_vault(tmp_path: Path, link: str) -> Iterator[Real]:
    """The vault app on TCP with the gateway key, or on the link socket, its admin app beside it."""
    policy = notes_policy()
    store = SecretStore(tmp_path / "vault", KEYS)
    store.load()
    jobs = JobTable(time.monotonic)
    app = VaultApp(
        policy,
        store,
        KEYS,
        client=httpx.AsyncClient(),
        environ={},
        gateway_link=link == "unix",
        review_jobs=jobs,
    )
    setup = SetupCodes(tmp_path / "vault", KEYS.portal_key)
    admin = AdminApp(store, KEYS, lambda: app.policy, setup, reviews=app)
    if link == "tcp":
        with serve(Beside(app, admin.app)) as url, httpx.Client(base_url=url, timeout=40) as http:
            yield Real(parse_link(url), KeySource(KEYS.gateway_key(1)), jobs, http)
        return
    # A short path: AF_UNIX paths are limited to about 100 bytes.
    directory = Path(tempfile.mkdtemp(prefix="zm-", dir="/tmp"))
    os.chmod(directory, 0o700)
    try:
        socket = str(directory / "vault.sock")
        served = Beside(ListenerTag(app, "gateway"), admin.app)
        with serve_link(served, socket, my_uid()):
            transport = httpx.HTTPTransport(uds=socket)
            with httpx.Client(transport=transport, base_url="http://vault", timeout=40) as http:
                yield Real(parse_link(f"unix:{socket}"), None, jobs, http)
    finally:
        shutil.rmtree(directory, ignore_errors=True)


@pytest.mark.parametrize("link", LINKS)
async def test_a_queued_review_is_run_and_reported_over_either_link(
    tmp_path: Path, link: str, log: io.StringIO
) -> None:
    view = build_view(notes_policy())
    answer = answer_for(view, "list_notes", "delete_note")
    with real_vault(tmp_path, link) as vault:
        async with review_client(vault.link, vault.keys) as http:
            poller = ReviewPoller(stub(view), http, run_review=reviewing(lambda: answer))
            with anyio.fail_after(30):
                async with anyio.create_task_group() as group:
                    group.start_soon(poller.run)
                    await until(lambda: vault.jobs.waiting == 1)

                    def queue_and_read() -> tuple[httpx.Response, httpx.Response]:
                        queued = vault.admin.post("/_test_admin/review/notes", json={})
                        job = queued.json()["job"]
                        return queued, vault.admin.get(f"/_test_admin/review/jobs/{job}?wait=20")

                    queued, read = await anyio.to_thread.run_sync(queue_and_read)
                    group.cancel_scope.cancel()
    assert queued.status_code == 200, queued.text
    assert read.status_code == 200, read.text
    done = read.json()
    assert done["state"] == "done"
    assert done["report"] == wired(reviewreport.fit(answer, view.gateway.limits))
    job = done["job"]
    [started] = events(log, "review_job_started")
    [finished] = events(log, "review_job_done")
    assert (started["server"], started["job"]) == ("notes", hash8(job))
    assert (finished["job"], finished["outcome"]) == (hash8(job), "done")
    assert job not in log.getvalue()
    assert SENTINEL not in log.getvalue()


# --- against the vault in process, on a test clock ------------------------------------------------


class InProcess:
    """The vault app and its admin app in the test's loop, its job table on a test clock with
    the start grace over, and the gateway's link to it through :meth:`client`, which records
    each request and reaches whichever vault :attr:`target` names (a restart replaces it)."""

    def __init__(self, tmp_path: Path, policy: Policy | None = None) -> None:
        self.tmp_path = tmp_path
        self.clock = Clock()
        self.requests: list[tuple[str, str]] = []
        self.fail_posts = False
        self.start(policy or notes_policy())

    def start(self, policy: Policy) -> None:
        self.jobs = JobTable(self.clock, started=self.clock() - REVIEW_START_GRACE)
        store = SecretStore(self.tmp_path / "vault", KEYS)
        store.load()
        client = httpx.AsyncClient(transport=httpx.MockTransport(self.unreachable))
        self.vault = VaultApp(policy, store, KEYS, client=client, environ={}, review_jobs=self.jobs)
        setup = SetupCodes(self.tmp_path / "vault", KEYS.portal_key)
        self.admin = AdminApp(store, KEYS, lambda: self.vault.policy, setup, reviews=self.vault)
        self.target: ASGIApp = ListenerTag(self.vault, "gateway")

    @staticmethod
    def unreachable(request: httpx.Request) -> httpx.Response:
        raise AssertionError("a review job never reaches an upstream from the vault")

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        self.requests.append((scope["method"], scope["path"]))
        if self.fail_posts and scope["method"] == "POST":
            raise httpx2.ConnectError("the report path is down")
        await self.target(scope, receive, send)

    def client(self) -> httpx2.AsyncClient:
        return review_client(parse_link(LINK), None, inner=httpx2.ASGITransport(app=self))

    @property
    def view(self) -> GatewayView:
        return build_view(self.vault.policy)

    def seen(self) -> None:
        """A poll that just ended: the vault counts the gateway as polling."""
        self.jobs.poll_began()
        self.jobs.poll_ended()

    async def socket(self, method: str, path: str, body: Any = None) -> httpx.Response:
        transport = httpx.ASGITransport(app=self.admin.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://admin") as client:
            return await client.request(method, path, json=body)

    async def queue(self, server: str = "notes") -> str:
        self.seen()
        queued = await self.socket("POST", f"/review/{server}", {"fresh": True})
        assert queued.status_code == 200, queued.text
        job: str = queued.json()["job"]
        return job

    async def read(self, job: str) -> httpx.Response:
        return await self.socket("GET", f"/review/jobs/{job}")

    def posts(self) -> int:
        return sum(method == "POST" for method, _ in self.requests)


@pytest.fixture
async def rig(tmp_path: Path) -> Any:
    found = InProcess(tmp_path)
    yield found
    await found.vault.aclose()


def poller_on(
    rig: InProcess,
    gateway: Stub,
    answer: Callable[[], dict[str, Any]] | None = None,
    *,
    sleeps: Sleeps | None = None,
    clock: Callable[[], float] | None = None,
) -> ReviewPoller:
    return ReviewPoller(
        gateway,
        rig.client(),
        wait=0,
        run_review=reviewing(answer) if answer is not None else None,
        sleep=sleeps or Sleeps(),
        clock=clock or rig.clock,
        jitter=lambda: 0.5,
    )


async def claim(rig: InProcess, poller: ReviewPoller, gateway: Stub) -> list[Job]:
    return list(await poller.poll_once(gateway.snapshot))


async def run_one(rig: InProcess, poller: ReviewPoller, gateway: Stub) -> Job:
    [job] = await claim(rig, poller, gateway)
    await poller.run_job(job, gateway.snapshot, rig.clock())
    return job


async def test_a_job_waits_for_the_review_lock_and_posts_the_fitted_report(
    rig: InProcess, log: io.StringIO
) -> None:
    """One review at a time: the job waits while the review lock is held. The report goes
    through fit(): a finding message over the vault's cap is cut, not refused."""
    gateway = stub(rig.view)
    answer = answer_for(rig.view, "list_notes", "delete_note")
    answer["tools"][1]["findings"].append(
        {"level": "note", "pointer": "", "message": "m" * (reviewreport.MESSAGE_MAX + 500)}
    )
    ran: list[str] = []

    def answered() -> dict[str, Any]:
        ran.append("review")
        return answer

    poller = poller_on(rig, gateway, answered)
    job_id = await rig.queue()
    [job] = await claim(rig, poller, gateway)
    with anyio.fail_after(5):
        async with anyio.create_task_group() as group:
            await gateway.reviewing.acquire()
            group.start_soon(poller.run_job, job, gateway.snapshot, rig.clock())
            for _ in range(20):
                await anyio.sleep(0)
            assert ran == []
            gateway.reviewing.release()
    assert ran == ["review"]
    read = await rig.read(job_id)
    assert read.status_code == 200, read.text
    message = read.json()["report"]["tools"][1]["findings"][-1]["message"]
    assert len(message) == reviewreport.MESSAGE_MAX
    assert message.endswith(reviewreport.CUT)
    assert read.json()["report"] == wired(reviewreport.fit(answer, rig.view.gateway.limits))
    assert events(log, "review_job_done")[0]["outcome"] == "done"
    assert job_id not in log.getvalue()


async def test_the_admin_socket_and_the_poller_take_the_gateways_one_lock(
    rig: InProcess, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """GR-12 on the real gateway app: the admin socket's review runs under the gateway's
    ``reviewing`` lock (the socket has none of its own), and a job waits until it ends."""
    state = tmp_path / "gateway"
    state.mkdir(mode=0o700)
    pool = UpstreamPool(parse_link(LINK), None, DriftMarks.load(state), DefinitionStore(state))
    http = httpx2.AsyncClient(transport=httpx2.MockTransport(lambda request: httpx2.Response(500)))
    app = GatewayApp(pool, http)
    admin = GatewayAdmin(app)
    assert not hasattr(admin, "reviewing")
    release = anyio.Event()
    ran: list[str] = []

    async def socket_review(gateway: Any, server: str, *, clear: bool = False) -> dict[str, Any]:
        ran.append("socket")
        assert gateway.reviewing.locked()
        await release.wait()
        return {"server": server}

    def job_review() -> dict[str, Any]:
        ran.append("job")
        return answer

    monkeypatch.setattr(review, "review", socket_review)
    answer = answer_for(rig.view, "list_notes")
    poller = ReviewPoller(
        app, rig.client(), wait=0, run_review=reviewing(job_review), clock=rig.clock
    )
    snapshot = Snapshot(rig.view, time.monotonic())
    job_id = await rig.queue()
    [job] = await poller.poll_once(snapshot)
    answered: list[tuple[int, dict[str, Any]]] = []

    async def ask() -> None:
        answered.append(await admin.answer("POST", "/review/notes"))

    with anyio.fail_after(5):
        async with anyio.create_task_group() as group:
            group.start_soon(ask)
            await until(lambda: ran == ["socket"])
            group.start_soon(poller.run_job, job, snapshot, rig.clock())
            for _ in range(20):
                await anyio.sleep(0)
            assert ran == ["socket"]
            release.set()
    await http.aclose()
    assert answered == [(200, {"server": "notes"})]
    assert ran == ["socket", "job"]
    assert (await rig.read(job_id)).status_code == 200


async def test_a_lying_report_is_refused_whole(rig: InProcess, log: io.StringIO) -> None:
    """X11: one pin that isn't its definition's fails the job pin_mismatch, nothing of the report
    kept; the gateway logs the vault's refusal at error."""
    gateway = stub(rig.view)
    answer = answer_for(rig.view, "list_notes", "delete_note")
    answer["tools"][0]["pin"] = "sha256:" + "0" * 64
    poller = poller_on(rig, gateway, lambda: answer)
    job_id = await rig.queue()
    await run_one(rig, poller, gateway)
    read = await rig.read(job_id)
    assert (read.status_code, read.json()["reason"]) == (502, "pin_mismatch")
    assert "report" not in read.json()
    assert "delete_note" in read.json()["error"]
    [done] = events(log, "review_job_done")
    assert (done["outcome"], done["level"]) == ("pin_mismatch", "error")
    assert [line["level"] for line in events(log, "review_refused", "vault")] == ["critical"]
    assert rig.posts() == 1


def huge_answer(view: GatewayView, count: int) -> dict[str, Any]:
    """A review whose definitions are each within the vault's per-definition cap, and whose
    report is over its body cap together."""
    answer = answer_for(view, *(f"tool_{index}" for index in range(count)))
    limits = view.gateway.limits
    filler = "x" * (reviewreport.definition_max(limits) - 1024)
    for entry in answer["tools"]:
        entry["definition"]["inputSchema"] = {"type": "object", "description": filler}
        entry["pin"] = pinhash.pin_of(entry["definition"])
    return answer


async def test_a_report_over_the_vaults_cap_fails_its_job_too_large(
    rig: InProcess, log: io.StringIO
) -> None:
    """F.4: the report isn't sent; the job's error names the vault's cap, so it fails at once
    rather than timing out."""
    limits = rig.view.gateway.limits
    most = reviewreport.report_max(limits)
    count = most // (reviewreport.definition_max(limits) - 2048) + 2
    gateway = stub(rig.view)
    answer = huge_answer(rig.view, count)
    poller = poller_on(rig, gateway, lambda: answer)
    job_id = await rig.queue()
    await run_one(rig, poller, gateway)
    read = await rig.read(job_id)
    assert (read.status_code, read.json()["reason"]) == (413, "review_too_large")
    assert f"a report is at most {most} bytes (gateway.limits)" in read.json()["error"]
    assert rig.posts() == 1
    [done] = events(log, "review_job_done")
    assert done["outcome"] == "failed"


async def test_a_413_from_the_vault_is_posted_back_as_the_jobs_error() -> None:
    """The vault's 413 names no job: the poller posts the job's own review_too_large error
    instead of retrying or dropping it."""
    view = build_view(notes_policy())
    bodies: list[dict[str, Any]] = []

    def vault(request: httpx2.Request) -> httpx2.Response:
        if request.method == "GET":
            return httpx2.Response(
                200, json={"v": 1, "jobs": [{"id": "j" * 43, "server": "notes"}]}
            )
        bodies.append(json.loads(request.content))
        if len(bodies) == 1:
            refusal = {"error": "request too large", "code": "review_too_large"}
            return httpx2.Response(413, json=refusal, headers={"x-zoeymcp-vault": "refused"})
        return httpx2.Response(200, json={"v": 1, "job": "j" * 43, "state": "failed"})

    http = review_client(parse_link(LINK), None, inner=httpx2.MockTransport(vault))
    answer = answer_for(view, "list_notes")
    gateway = stub(view)
    poller = ReviewPoller(
        gateway, http, wait=0, run_review=reviewing(lambda: answer), sleep=Sleeps()
    )
    [job] = await poller.poll_once(gateway.snapshot)
    await poller.run_job(job, gateway.snapshot, time.monotonic())
    assert [set(body) for body in bodies] == [
        {"v", "job", "server", "report"},
        {"v", "job", "error"},
    ]
    most = reviewreport.report_max(view.gateway.limits)
    assert bodies[1]["error"] == {
        "status": 413,
        "code": "review_too_large",
        "message": f"the review report is over the vault's cap ({most} bytes)",
    }


async def test_the_reviews_own_error_is_posted_with_its_fields(
    rig: InProcess, log: io.StringIO
) -> None:
    gateway = stub(rig.view)

    async def failing(app: Any, server: str) -> dict[str, Any]:
        raise review.ReviewError(502, "upstream", "the review couldn't list the server's tools")

    poller = ReviewPoller(gateway, rig.client(), wait=0, run_review=failing, sleep=Sleeps())
    job_id = await rig.queue()
    await run_one(rig, poller, gateway)
    read = await rig.read(job_id)
    assert (read.status_code, read.json()["reason"]) == (502, "review_failed")
    assert "(upstream)" in read.json()["error"]
    assert events(log, "review_job_done")[0]["outcome"] == "failed"
    [reported] = events(log, "review_reported", "vault")
    assert (reported["reason"], reported["code"]) == ("review_failed", "upstream")


async def test_a_review_that_raises_fails_its_job_and_not_the_poller(rig: InProcess) -> None:
    gateway = stub(rig.view)

    async def broken(app: Any, server: str) -> dict[str, Any]:
        raise RuntimeError("a bug, with words nobody should read")

    poller = ReviewPoller(gateway, rig.client(), wait=0, run_review=broken, sleep=Sleeps())
    job_id = await rig.queue()
    await run_one(rig, poller, gateway)
    read = await rig.read(job_id)
    assert (read.status_code, read.json()["reason"]) == (502, "review_failed")
    assert "(review_crashed)" in read.json()["error"]


async def test_a_job_for_a_server_outside_the_view_is_not_reviewed(log: io.StringIO) -> None:
    view = build_view(notes_policy())
    posted: list[dict[str, Any]] = []

    def vault(request: httpx2.Request) -> httpx2.Response:
        if request.method == "GET":
            jobs = [{"id": "a" * 43, "server": "other"}, {"id": "b" * 43, "server": "Bad Name"}]
            return httpx2.Response(200, json={"v": 1, "jobs": jobs})
        posted.append(json.loads(request.content))
        return httpx2.Response(200, json={"v": 1, "job": posted[-1]["job"], "state": "failed"})

    async def unreachable(app: Any, server: str) -> dict[str, Any]:
        raise AssertionError("not reviewed")

    http = review_client(parse_link(LINK), None, inner=httpx2.MockTransport(vault))
    gateway = stub(view)
    poller = ReviewPoller(gateway, http, wait=0, run_review=unreachable, sleep=Sleeps())
    for job in await poller.poll_once(gateway.snapshot):
        await poller.run_job(job, gateway.snapshot, time.monotonic())
    assert [body["error"]["code"] for body in posted] == ["unknown_server"] * 2
    assert [line["server"] for line in events(log, "review_job_done")] == [None, None]
    assert "Bad Name" not in log.getvalue()


async def test_a_toolkit_job(tmp_path: Path) -> None:
    """COV-1: a toolkit server's review runs with no upstream and reports its own shape."""
    from example_toolkits.mail import toolkit as mail

    raw = toolkit_policy("http://127.0.0.1:9", 9, servers={"mail": mail_server()})
    rig = InProcess(tmp_path, Policy.model_validate(raw))
    marks = DriftMarks.load(tmp_path / "gateway")
    toolkits = Toolkits(
        parse_link(LINK), None, marks, entry_points=lambda: ENTRY_POINTS, allow_writable=True
    )
    gateway = stub(rig.view)
    gateway.toolkits = toolkits
    gateway.pool = type("Pool", (), {"marks": marks})()
    toolkits.apply(rig.view.gateway)
    try:
        poller = ReviewPoller(gateway, rig.client(), wait=0, sleep=Sleeps())
        job_id = await rig.queue("mail")
        await run_one(rig, poller, gateway)
        read = await rig.read(job_id)
    finally:
        await toolkits.aclose()
        await rig.vault.aclose()
    assert read.status_code == 200, read.text
    report = read.json()["report"]
    assert (report["kind"], report["module"]) == ("toolkit", "example_toolkits.mail")
    assert [entry["name"] for entry in report["tools"]] == sorted(mail.tools)
    assert report["clean"] is True


# --- failure modes (N.1) -------------------------------------------------------------------------


async def test_gateway_restart(rig: InProcess, log: io.StringIO) -> None:
    """FM-13: a gateway that took a job and went away leaves it to time out after 120 s; the new
    gateway serves the next job."""
    gateway = stub(rig.view)
    answer = answer_for(rig.view, "list_notes")
    job_id = await rig.queue()
    assert len(await claim(rig, poller_on(rig, gateway, lambda: answer), gateway)) == 1
    rig.clock.advance(CLAIM_DEADLINE)
    read = await rig.read(job_id)
    assert (read.status_code, read.json()["reason"]) == (504, "review_timeout")
    fresh_gateway = stub(rig.view)
    restarted = poller_on(rig, fresh_gateway, lambda: answer)
    again = await rig.queue()
    await run_one(rig, restarted, fresh_gateway)
    assert (await rig.read(again)).json()["state"] == "done"
    assert [line["server"] for line in events(log, "review_timeout", "vault")] == ["notes"]


async def test_vault_restart(rig: InProcess, log: io.StringIO) -> None:
    """FM-14: the vault restarted with a job claimed: the post is answered 409 job_unknown,
    logged and dropped, never tried again."""
    gateway = stub(rig.view)
    poller = poller_on(rig, gateway, lambda: answer_for(rig.view, "list_notes"))
    await rig.queue()
    [job] = await claim(rig, poller, gateway)
    old = rig.vault
    rig.start(notes_policy())
    await old.aclose()
    await poller.run_job(job, gateway.snapshot, rig.clock())
    assert rig.posts() == 1
    [failed] = events(log, "review_job_post_failed")
    assert (failed["job"], failed["outcome"]) == (job.hash8, "job_unknown")
    assert events(log, "review_job_done") == []


async def test_stale_view_gets_no_job(rig: InProcess) -> None:
    """FM-15: a gateway holding an older view is offered nothing queued at the vault's; the job
    fails review_stale after 60 s, and once the gateway holds the vault's view it is served."""
    gateway = stub(rig.view)
    rig.vault.reload(
        Policy.model_validate(raw_policy("http://127.0.0.1:9", include=[], review={}, era="modern"))
    )
    assert rig.view.digest != gateway.snapshot.view.digest
    poller = poller_on(rig, gateway, lambda: answer_for(gateway.snapshot.view, "list_notes"))
    job_id = await rig.queue()
    assert await claim(rig, poller, gateway) == []
    rig.clock.advance(QUEUE_TTL)
    read = await rig.read(job_id)
    assert (read.status_code, read.json()["reason"]) == (409, "review_stale")
    gateway.hold(rig.view)
    poller = poller_on(rig, gateway, lambda: answer_for(rig.view, "list_notes"))
    again = await rig.queue()
    await run_one(rig, poller, gateway)
    assert (await rig.read(again)).json()["state"] == "done"


def policy_at(era: str) -> Policy:
    """The notes policy with ``era``: each one a view of its own."""
    return Policy.model_validate(raw_policy("http://127.0.0.1:9", include=[], review={}, era=era))


async def held(snapshot: Snapshot, previous: Snapshot | None) -> None:
    """The policy client's apply: the poller reads the snapshot it holds, nothing more."""


async def test_review_after_reload(rig: InProcess, log: io.StringIO) -> None:
    """FM-24 (D-189): a poll at the vault's view ends once a reload changes it, so a review
    queued right after starts within about a second, and not when the old poll's 25 s run out.
    The gateway's policy client fetches the new view over the same in-process link, after the
    poller has seen the poll end, so the poller's catch-up is what names the new view. A poll at
    a view the vault no longer serves still waits, through another change too, so a gateway
    behind the vault can't spin."""
    link = parse_link(LINK)
    views = view_client(link, None, inner=httpx2.ASGITransport(app=rig))
    gateway = Stub(PolicyClient(views, held))
    gateway.hold(rig.view)
    old = gateway.snapshot
    poller = ReviewPoller(
        gateway, rig.client(), run_review=reviewing(lambda: answer_for(rig.view, "list_notes"))
    )
    with anyio.fail_after(10):
        async with anyio.create_task_group() as group:
            # The poll waits before the view's long poll, so the vault answers it first and the
            # poller sees its answer before the policy client holds the new view.
            group.start_soon(poller.run)
            await until(lambda: rig.jobs.waiting == 1)
            group.start_soon(gateway.policy.run)
            await until(lambda: rig.vault.view_waiters == 1)
            rig.vault.reload(policy_at("modern"))
            job_id = await rig.queue()
            await until(lambda: events(log, "review_job_done"), timeout=STARTS_WITHIN)
            group.cancel_scope.cancel()
        assert (await rig.read(job_id)).json()["state"] == "done"
        assert gateway.snapshot.view.digest == rig.view.digest
        [done] = events(log, "review_job_done")
        assert (done["job"], done["outcome"]) == (hash8(job_id), "done")

        # A gateway still at the first view: its poll waits through the vault's next change.
        rig.vault.reload(policy_at("legacy"))
        behind = ReviewPoller(gateway, rig.client())
        async with anyio.create_task_group() as group:
            group.start_soon(behind.poll_once, old)
            await until(lambda: rig.jobs.waiting == 1)
            rig.vault.reload(policy_at("modern"))
            await anyio.wait_all_tasks_blocked()
            assert rig.jobs.waiting == 1
            group.cancel_scope.cancel()


async def test_a_poll_at_the_vaults_view_waits_through_the_same_view_again(
    rig: InProcess,
) -> None:
    """A reload that installs the view the poll names isn't a change: the poll goes on waiting,
    and ends with none at the next real change (D-189)."""
    gateway = stub(rig.view)
    poller = ReviewPoller(gateway, rig.client())
    with anyio.fail_after(10):
        async with anyio.create_task_group() as group:
            answered: list[tuple[Job, ...]] = []

            async def poll() -> None:
                answered.append(await poller.poll_once(gateway.snapshot))

            group.start_soon(poll)
            await until(lambda: rig.jobs.waiting == 1)
            rig.vault.reload(notes_policy())
            await anyio.wait_all_tasks_blocked()
            assert (rig.jobs.waiting, answered) == (1, [])
            rig.vault.reload(policy_at("modern"))
            await until(lambda: answered, timeout=STARTS_WITHIN)
    assert answered == [()]
    assert rig.jobs.waiting == 0


async def test_report_path_down(rig: InProcess, log: io.StringIO) -> None:
    """FM-17: a post that fails is tried twice more, backing off, then dropped; the job times
    out; and a poll that fails backs off from 1 s up to 30 s, logged once a minute."""
    gateway = stub(rig.view)
    sleeps = Sleeps()
    poller = poller_on(rig, gateway, lambda: answer_for(rig.view, "list_notes"), sleeps=sleeps)
    job_id = await rig.queue()
    [job] = await claim(rig, poller, gateway)
    rig.fail_posts = True
    await poller.run_job(job, gateway.snapshot, rig.clock())
    assert rig.posts() == 3
    assert sleeps.seen == [1.0, 2.0]
    [failed] = events(log, "review_job_post_failed")
    assert (failed["job"], failed["outcome"]) == (job.hash8, "ConnectError")
    rig.clock.advance(CLAIM_DEADLINE)
    read = await rig.read(job_id)
    assert (read.status_code, read.json()["reason"]) == (504, "review_timeout")
    # The jobs path down too: the loop backs off, and says so once a minute.
    rig.target = refusing
    looping = Sleeps(stop=7)
    poller = poller_on(rig, gateway, sleeps=looping)
    with pytest.raises(Stop):
        await poller.run()
    assert looping.seen == [1.0, 2.0, 4.0, 8.0, 16.0, 30.0, 30.0]
    assert [line["reason"] for line in events(log, "review_poll_failed")] == ["status_503"]


async def refusing(scope: Scope, receive: Receive, send: Send) -> None:
    headers = [(b"content-type", b"application/json"), (b"x-zoeymcp-vault", b"refused")]
    await send({"type": "http.response.start", "status": 503, "headers": headers})
    await send({"type": "http.response.body", "body": b'{"error": "unavailable"}'})


async def test_a_post_retries_within_the_claim_deadline_only(
    rig: InProcess, log: io.StringIO
) -> None:
    gateway = stub(rig.view)
    sleeps = Sleeps()
    poller = poller_on(rig, gateway, lambda: answer_for(rig.view, "list_notes"), sleeps=sleeps)
    await rig.queue()
    [job] = await claim(rig, poller, gateway)
    rig.fail_posts = True
    await poller.run_job(job, gateway.snapshot, rig.clock() - CLAIM_DEADLINE)
    assert (rig.posts(), sleeps.seen) == (1, [])
    assert events(log, "review_job_post_failed")[0]["outcome"] == "ConnectError"


# --- the whole gateway ---------------------------------------------------------------------------

TOOLS = ["echo", "add", "slow"]
REAL_TRANSPORT = httpx.HTTPTransport


def run_cli(monkeypatch: pytest.MonkeyPatch, base: str, *argv: str) -> tuple[int, str, str]:
    """``zoeymcp <argv>``, its admin socket forwarded to ``base``."""

    def handle(request: httpx.Request) -> httpx.Response:
        with httpx.Client(transport=REAL_TRANSPORT(), timeout=120) as client:
            answer = client.request(
                request.method, base + request.url.raw_path.decode(), content=request.content
            )
        return httpx.Response(answer.status_code, content=answer.content)

    monkeypatch.setattr(httpx, "HTTPTransport", lambda **_: httpx.MockTransport(handle))
    out, err = io.StringIO(), io.StringIO()
    code = main(list(argv), stdin=io.StringIO(), out=out, err=err)
    return code, out.getvalue(), err.getvalue()


def test_review_via_vault_prints_the_gateways_review(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The gateway's poller runs the same review as its admin socket, on a real upstream; the
    second read through the vault is the same report, and the gateway closes every vault-link
    client at shutdown (D-166)."""
    fake = McpFake()
    review_pins = {name: pin_of_fake(fake, name) for name in TOOLS}
    with (
        deployment(tmp_path, fake, include=TOOLS, review=review_pins) as deployed,
        gateway(deployed, review=True, report=True) as running,
    ):
        through_vault = run_cli(
            monkeypatch,
            deployed.vault_admin_url,
            "review",
            "notes",
            "--via",
            "vault",
            "--socket",
            "x",
        )
        again = run_cli(
            monkeypatch,
            deployed.vault_admin_url,
            "review",
            "notes",
            "--via",
            "vault",
            "--socket",
            "x",
        )
        direct = run_cli(
            monkeypatch, running.admin_url, "review", "notes", "--via", "gateway", "--socket", "x"
        )
        app = running.app
        text = deployed.log.getvalue()
    assert through_vault == direct
    assert through_vault[0] == 0
    assert again == through_vault
    assert text.count('"event":"review_job_done"') == 1
    assert '"event":"review_requested"' in text
    for http in (app.policy_http, app.report_http, app.review_http):
        assert http is not None
        assert http.is_closed
