"""The gateway's status report to the vault (M6 design K.1; D-29, D-72's rule, FM-19, FM-20).

- ``_StatusOnly``: the status client reaches the status path and nothing else;
- the report (:func:`statuspush.content`): the attention decision's lists from the status, names
  that aren't tool names counted, not named (T-7), every list capped;
- the pusher against a scripted vault: the first report at once, a change after the debounce,
  the same report again only after a minute, a 429 waiting the debounce, and a failure backing
  off, logged at most once a minute;
- against the real vault app over both links (TCP with the gateway key, and the link socket,
  which is Linux only): a pushed report is kept and read back; one sooner than 5 s after it is
  429, one over 256 KiB is 413, one with a witness above ``REVISION_MAX`` is refused whole, each
  refusal logged at most once a minute (FM-19); a query, another content type and a body that
  isn't a report are refused before anything is kept;
- the whole gateway: it pushes after its first view, the vault's health reads it, and a new
  gateway process pushes again within the minute (FM-20).
"""

from __future__ import annotations

import io
import json
import os
import shutil
import sys
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import anyio
import httpx
import httpx2
import pytest

from tests.fakes.harness import serve
from tests.fakes.mcp_server import McpFake, base_tools
from tests.gateway.rig import KEYS, deployment, gateway, pin_of_fake, raw_policy, until
from tests.unit.test_peer import my_uid, serve_link
from zoeymcp.common import logs
from zoeymcp.common.policy import Policy
from zoeymcp.common.policy.attention import Attention
from zoeymcp.common.policy.view import build_view
from zoeymcp.gateway import statuspush
from zoeymcp.gateway.statuspush import DEBOUNCE, EVERY, StatusPusher, content
from zoeymcp.gateway.vaultlink import (
    STATUS_MAX_ANSWER_BYTES,
    STATUS_PATH,
    KeySource,
    Link,
    ResponseTooLarge,
    UpstreamBlocked,
    UpstreamRedirect,
    parse_link,
    status_client,
)
from zoeymcp.vault import internal
from zoeymcp.vault.app import VaultApp
from zoeymcp.vault.server import ListenerTag
from zoeymcp.vault.store import SecretStore

pytestmark = pytest.mark.anyio
LINKS = ["tcp", pytest.param("unix", marks=pytest.mark.skipif(
    sys.platform != "linux", reason="the link socket's peer check is Linux only"
))]  # fmt: skip
LINK = "unix:/run/zoeymcp-link/vault.sock"
VIEW = "sha256:" + "ab" * 32
PIN = "sha256:" + "c" * 64


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


def remote(**fields: Any) -> dict[str, Any]:
    """A remote server's entry in the gateway's status (``server.status``)."""
    entry: dict[str, Any] = {
        "kind": "remote",
        "state": ["ready"],
        "era": "modern",
        "connections": 1,
        "included": 2,
        "exposed": 2,
        "marked": [],
        "reports": {},
        "attention": Attention().as_dict(),
        "blocked": False,
        "unreviewed_pins": {},
        "offered": None,
        "listed_s_ago": 1.0,
    }
    return {**entry, **fields}


def status_of(**servers: dict[str, Any]) -> dict[str, Any]:
    return {"version": "1", "view": VIEW, "fresh": True, "servers": servers}


# --- _StatusOnly --------------------------------------------------------------------------------


def test_the_path_and_timings_are_the_vaults() -> None:
    """The gateway can't import the vault: its copies are kept equal here."""
    assert internal.STATUS.path.text == STATUS_PATH
    assert statuspush.MAX_BYTES == internal.STATUS_MAX_BYTES
    assert statuspush.DEBOUNCE == internal.STATUS_MIN_INTERVAL
    assert (statuspush.EVERY, statuspush.LOG_EVERY) == (60.0, 60.0)


REFUSED = [
    ("GET", STATUS_PATH),
    ("PUT", STATUS_PATH),
    ("DELETE", STATUS_PATH),
    ("POST", STATUS_PATH + "?x=1"),
    ("POST", STATUS_PATH + "/"),
    ("POST", "/_zoeymcp/gateway/v1/report/review"),
    ("POST", "/_zoeymcp/gateway/v1/report/ledger"),
    ("GET", "/_zoeymcp/gateway/v1/view"),
    ("POST", "/_zoeymcp/gateway/v1/report/%73tatus"),
    ("POST", "/notes/mcp"),
    ("POST", "http://elsewhere.invalid" + STATUS_PATH),
    ("POST", "http://vault.invalid:8080" + STATUS_PATH),
    ("POST", "https://vault.invalid" + STATUS_PATH),
]


@pytest.mark.parametrize("spec", [LINK, "http://vault:8080"])
async def test_the_status_client_reaches_the_status_path_only(spec: str) -> None:
    seen: list[str] = []

    def vault(request: httpx2.Request) -> httpx2.Response:
        seen.append(request.url.raw_path.decode())
        return httpx2.Response(200, json={"v": 1})

    link = parse_link(spec)
    async with status_client(link, None, inner=httpx2.MockTransport(vault)) as http:
        assert (await http.post(STATUS_PATH, content=b"{}")).status_code == 200
        for method, url in REFUSED:
            if spec != LINK and url.startswith("http://vault.invalid"):
                url = url.replace("vault.invalid:8080", "vault:9999")
            with pytest.raises(UpstreamBlocked):
                await http.request(method, url, content=b"{}" if method != "GET" else None)
    assert seen == [STATUS_PATH]


async def test_the_status_client_follows_no_redirect_and_caps_answers() -> None:
    answers = [
        httpx2.Response(307, headers={"location": STATUS_PATH}),
        httpx2.Response(200, content=b" " * (STATUS_MAX_ANSWER_BYTES + 1)),
        httpx2.Response(429, content=b" " * STATUS_MAX_ANSWER_BYTES),
    ]

    def vault(request: httpx2.Request) -> httpx2.Response:
        return answers.pop(0)

    async with status_client(parse_link(LINK), None, inner=httpx2.MockTransport(vault)) as http:
        with pytest.raises(UpstreamRedirect):
            await http.post(STATUS_PATH, content=b"{}")
        with pytest.raises(ResponseTooLarge):
            await http.post(STATUS_PATH, content=b"{}")
        assert len((await http.post(STATUS_PATH, content=b"{}")).content) == 4096


async def test_the_gateway_key_goes_with_every_status_on_tcp() -> None:
    headers: list[str | None] = []

    def vault(request: httpx2.Request) -> httpx2.Response:
        headers.append(request.headers.get("x-zoeymcp-gateway"))
        return httpx2.Response(200, json={"v": 1})

    keys = KeySource(KEYS.gateway_key(1))
    async with status_client(
        parse_link("http://vault:8080"), keys, inner=httpx2.MockTransport(vault)
    ) as http:
        await http.post(STATUS_PATH, content=b"{}")
    async with status_client(parse_link(LINK), None, inner=httpx2.MockTransport(vault)) as http:
        await http.post(STATUS_PATH, content=b"{}")
    assert headers == [KEYS.gateway_key(1), None]


# --- the report ---------------------------------------------------------------------------------


def test_no_report_before_a_view() -> None:
    assert content({"view": None, "servers": {}}, started=1, max_tools=10) is None


def test_the_report_is_the_attention_decision_and_counts() -> None:
    decided = Attention(
        drifted=("d",), marked=("m",), new=("n",), changed_declined=("c",), missing=("x",)
    )
    status = status_of(
        notes=remote(
            attention=decided.as_dict(),
            unreviewed_pins={"n": PIN, "c": PIN},
            reports={"invalid": ["bad.one", "a b", "é"], "duplicate": ["dup", "x y"]},
            offered={"prompts": True, "resources": False, "completions": False, "logging": True},
            marked=["m", "old"],  # every mark the gateway holds; the decision's is "m"
            blocked=True,
        ),
        kit={"kind": "toolkit", "state": "unavailable", "reason": "not_loaded"},
    )
    assert content(status, started=7, max_tools=10) == {
        "v": 1,
        "view": VIEW,
        "started": 7,
        "servers": {
            "kit": {
                "kind": "toolkit",
                "state": ["unavailable"],
                "era": None,
                "blocked": False,
                "included": 0,
                "exposed": 0,
                "marked": [],
                "unreviewed": [],
                "declined_changed": [],
                "drift": [],
                "missing": [],
                "invalid": [],
                "invalid_unnamed": 0,
                "duplicate_unnamed": 0,
                "offered": None,
            },
            "notes": {
                "kind": "remote",
                "state": ["ready"],
                "era": "modern",
                "blocked": True,
                "included": 2,
                "exposed": 2,
                "marked": ["m"],
                "unreviewed": [["c", PIN], ["n", PIN]],
                "declined_changed": ["c"],
                "drift": ["d"],
                "missing": ["x"],
                "invalid": ["bad.one", "dup"],
                "invalid_unnamed": 2,
                "duplicate_unnamed": 1,
                "offered": {
                    "prompts": True,
                    "resources": False,
                    "completions": False,
                    "logging": True,
                },
            },
        },
        "witness": {},
        "deployments_seen": 0,
        "policy_mode": "unknown",
    }


def test_every_list_is_capped() -> None:
    names = [f"t{n}" for n in range(5)]
    decided = Attention(drifted=tuple(names), new=tuple(names))
    status = status_of(
        notes=remote(
            attention=decided.as_dict(),
            unreviewed_pins=dict.fromkeys(names, PIN),
            reports={"invalid": [*names, "a b", "c d", "e f"]},
        )
    )
    document = content(status, started=1, max_tools=3)
    assert document is not None
    entry = document["servers"]["notes"]
    assert entry["drift"] == ["t0", "t1", "t2"]
    assert entry["unreviewed"] == [["t0", PIN], ["t1", PIN], ["t2", PIN]]
    assert entry["invalid"] == ["t0", "t1", "t2"]
    assert entry["invalid_unnamed"] == 3
    capped = content(status, started=1, max_tools=2)
    assert capped is not None
    assert capped["servers"]["notes"]["invalid_unnamed"] == 2


def test_the_tool_counts_are_capped_at_the_schemas_ceiling() -> None:
    """The include list isn't held to the running limit, so its count goes as it is, up to
    max_tools_per_server's own ceiling, which the vault takes."""
    status = status_of(notes=remote(included=12, exposed=10_001))
    document = content(status, started=1, max_tools=3)
    assert document is not None
    assert (document["servers"]["notes"]["included"], document["servers"]["notes"]["exposed"]) == (
        12,
        10_000,
    )


def test_a_server_never_listed_reports_nothing_to_attend_to() -> None:
    document = content(status_of(notes=remote(attention=None)), started=1, max_tools=10)
    assert document is not None
    entry = document["servers"]["notes"]
    assert [entry[key] for key in ("marked", "unreviewed", "drift", "missing")] == [[]] * 4


def test_the_report_names_the_mode_the_gateway_last_saw() -> None:
    """``policy_mode`` is the status's, the mode the vault last stated beside the view (M6 design
    K.3); a status naming none reports ``unknown``."""
    for mode in ("managed", "declarative", "unknown"):
        document = content({**status_of(), "policy_mode": mode}, started=1, max_tools=10)
        assert document is not None
        assert document["policy_mode"] == mode
    document = content(status_of(), started=1, max_tools=10)
    assert document is not None
    assert document["policy_mode"] == "unknown"


# --- the pusher against a scripted vault --------------------------------------------------------


class Moment:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@dataclass
class Scripted:
    pusher: StatusPusher
    clock: Moment
    posted: list[dict[str, Any]]
    answers: list[httpx2.Response | Exception]
    status: dict[str, Any]


@contextmanager
def scripted() -> Iterator[Scripted]:
    clock = Moment()
    posted: list[dict[str, Any]] = []
    answers: list[httpx2.Response | Exception] = []

    def vault(request: httpx2.Request) -> httpx2.Response:
        posted.append(json.loads(request.content))
        answer = answers.pop(0) if answers else httpx2.Response(200, json={"v": 1})
        if isinstance(answer, Exception):
            raise answer
        return answer

    policy = Policy.model_validate(raw_policy("http://127.0.0.1:9", include=[], review={}))
    app = SimpleNamespace(policy=SimpleNamespace(snapshot=SimpleNamespace(view=build_view(policy))))
    status = status_of(notes=remote())
    http = httpx2.AsyncClient(transport=httpx2.MockTransport(vault), base_url="http://vault")
    pusher = StatusPusher(
        app, http, lambda _: status, clock=clock, wall=lambda: 1234.9, jitter=lambda: 0.5
    )
    yield Scripted(pusher, clock, posted, answers, status)


async def push_if_due(world: Scripted) -> bool:
    document = world.pusher.document()
    assert document is not None
    if not world.pusher.due(document, world.clock()):
        return False
    return await world.pusher.push_once(document)


async def test_the_first_report_at_once_then_on_change_or_each_minute() -> None:
    with scripted() as world:
        assert await push_if_due(world)
        assert world.posted[0]["started"] == 1234
        assert world.posted[0]["servers"]["notes"]["state"] == ["ready"]
        world.clock.now += EVERY - 0.1
        assert not await push_if_due(world)  # nothing changed
        world.clock.now += 0.1
        assert await push_if_due(world)  # a minute on: the same again
        world.status["servers"]["notes"]["exposed"] = 1
        world.clock.now += DEBOUNCE - 0.1
        assert not await push_if_due(world)  # changed, but within the debounce
        world.clock.now += 0.1
        assert await push_if_due(world)
        assert [post["servers"]["notes"]["exposed"] for post in world.posted] == [2, 2, 1]
        assert world.pusher.sent == world.posted[-1]


async def test_a_429_waits_the_debounce(log: io.StringIO) -> None:
    with scripted() as world:
        world.answers.append(httpx2.Response(429, json={"code": "too_soon"}))
        assert not await push_if_due(world)
        world.clock.now += DEBOUNCE - 0.1
        assert not await push_if_due(world)
        world.clock.now += 0.1
        assert await push_if_due(world)
        assert len(world.posted) == 2
    assert events(log, "status_push_failed") == []


async def test_a_failure_backs_off_and_is_logged_once_a_minute(log: io.StringIO) -> None:
    with scripted() as world:
        world.answers += [
            httpx2.ConnectError("down"),
            httpx2.Response(503, json={"code": "unavailable"}),
            httpx2.Response(400, json={"code": "invalid"}),
        ]
        # Backing off 1, 2, then 4 s (the jitter here is 1).
        for wait in (1.0, 2.0, 4.0):
            assert not await push_if_due(world)
            world.clock.now += wait - 0.1
            assert not await push_if_due(world)
            world.clock.now += 0.1
        assert await push_if_due(world)
        assert len(world.posted) == 4
    [failed] = events(log, "status_push_failed")
    assert (failed["reason"], failed["level"]) == ("ConnectError", "warning")


async def test_a_report_over_the_cap_isnt_sent(log: io.StringIO) -> None:
    with scripted() as world:
        assert not await world.pusher.push_once({"v": 1, "pad": "x" * statuspush.MAX_BYTES})
        assert world.posted == []
    [failed] = events(log, "status_push_failed")
    assert failed["reason"] == "too_large"


async def test_the_loop_pushes_after_each_step() -> None:
    steps: list[float] = []
    with scripted() as world:

        async def sleep(seconds: float) -> None:
            steps.append(seconds)
            if len(steps) == 3:
                raise anyio.get_cancelled_exc_class()
            world.clock.now += seconds

        world.pusher._sleep = sleep
        with pytest.raises(anyio.get_cancelled_exc_class()):
            await world.pusher.run()
        assert steps == [statuspush.STEP] * 3
        assert len(world.posted) == 1


async def test_a_status_that_cant_be_read_ends_only_its_round(log: io.StringIO) -> None:
    """Nothing the gateway serves waits for the pusher: a status that raises is a failed round,
    logged, and the loop pushes once its backoff ends."""
    steps: list[float] = []
    with scripted() as world:
        good = world.pusher._status
        calls = 0

        def status(app: Any) -> Any:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise KeyError("servers")
            return good(app)

        async def sleep(seconds: float) -> None:
            steps.append(seconds)
            if len(steps) == 3:
                raise anyio.get_cancelled_exc_class()
            world.clock.now += seconds

        world.pusher._status = status
        world.pusher._sleep = sleep
        with pytest.raises(anyio.get_cancelled_exc_class()):
            await world.pusher.run()
        assert steps == [statuspush.STEP] * 3
        assert len(world.posted) == 1  # the backoff (1 s here) passed by the third round
    [failed] = events(log, "status_push_failed")
    assert failed["reason"] == "KeyError"


# --- against the real vault, over both links ----------------------------------------------------


@dataclass
class Real:
    app: VaultApp
    link: Link
    keys: KeySource | None


@contextmanager
def real_vault(tmp_path: Path, link: str) -> Iterator[Real]:
    policy = Policy.model_validate(raw_policy("http://127.0.0.1:9", include=[], review={}))
    store = SecretStore(tmp_path / "vault", KEYS)
    store.load()
    app = VaultApp(
        policy, store, KEYS, client=httpx.AsyncClient(), environ={}, gateway_link=link == "unix"
    )
    if link == "tcp":
        with serve(app) as url:
            yield Real(app, parse_link(url), KeySource(KEYS.gateway_key(1)))
        return
    # A short path: AF_UNIX paths are limited to about 100 bytes.
    directory = Path(tempfile.mkdtemp(prefix="zm-", dir="/tmp"))
    os.chmod(directory, 0o700)
    try:
        socket = str(directory / "vault.sock")
        with serve_link(ListenerTag(app, "gateway"), socket, my_uid()):
            yield Real(app, parse_link(f"unix:{socket}"), None)
    finally:
        shutil.rmtree(directory, ignore_errors=True)


@pytest.mark.parametrize("link", LINKS)
async def test_a_report_is_kept_and_floods_are_refused_over_either_link(
    tmp_path: Path, link: str, log: io.StringIO
) -> None:
    """FM-19: the vault keeps the report and its attention decision; a second one at once is
    429, one over 256 KiB is 413 before its body is read, a witness of 10^10 refuses its report
    whole; status_refused is logged once in the minute."""
    decided = Attention(drifted=("list_notes",), new=("purge",))
    status = status_of(notes=remote(attention=decided.as_dict(), unreviewed_pins={"purge": PIN}))
    with real_vault(tmp_path, link) as vault:
        app = SimpleNamespace(
            policy=SimpleNamespace(snapshot=SimpleNamespace(view=build_view(vault.app.policy)))
        )
        async with status_client(vault.link, vault.keys) as http:
            pusher = StatusPusher(app, http, lambda _: status)
            with anyio.fail_after(10):
                document = pusher.document()
                assert document is not None
                assert vault.app.gateway_status().report is None
                assert await pusher.push_once(document)
                held = vault.app.gateway_status()
                assert held.report is not None
                assert held.report.view == VIEW
                assert held.report.servers["notes"].attention() == decided
                assert held.age < 5
                assert not await pusher.push_once(document)  # sooner than 5 s: 429
                big = await http.post(
                    STATUS_PATH,
                    content=b" " * (internal.STATUS_MAX_BYTES + 1),
                    headers={"content-type": "application/json"},
                )
                assert (big.status_code, big.json()["code"]) == (413, "too_large")
                vault.app._status_gate.accepted_at = None  # as if 5 s had passed
                claimed = {**document, "witness": {"0" * 32: 10**10}}
                answer = await http.post(
                    STATUS_PATH,
                    content=statuspush.encoded(claimed),
                    headers={"content-type": "application/json"},
                )
                assert (answer.status_code, answer.json()["code"]) == (400, "witness_range")
                assert vault.app.gateway_status().report is held.report
    [refused] = events(log, "status_refused")
    assert (refused["reason"], refused["level"]) == ("too_soon", "warning")
    [received] = events(log, "status_received")
    assert received["servers"] == 1
    assert received["bytes"] == len(statuspush.encoded(document))


# --- the whole gateway --------------------------------------------------------------------------


def health(deployed: Any) -> dict[str, Any]:
    answer = httpx.get(deployed.vault_admin_url + "/health", timeout=10)
    assert answer.status_code == 200, answer.text
    report: dict[str, Any] = answer.json()
    return report


async def test_restart(tmp_path: Path) -> None:
    """FM-20: the gateway pushes once it holds a view, and the vault's health reads it; a new
    gateway process pushes again within the minute (at most one debounce after the last)."""
    fake = McpFake()
    tools = [tool["name"] for tool in base_tools()]
    include = tools[:2]
    with deployment(
        tmp_path,
        fake,
        include=include,
        review={name: pin_of_fake(fake, name) for name in include},
    ) as deployed:
        vault = deployed.vault
        assert vault is not None
        with gateway(deployed, status_push=True):
            await until(lambda: vault.gateway_status().report is not None, timeout=20)
        first = vault.gateway_status().report
        assert first is not None
        assert "notes" in first.servers
        section = health(deployed)["gateway"]
        assert [row["name"] for row in section["servers"]] == ["notes"]
        started = time.monotonic()
        with gateway(deployed, status_push=True):
            await until(lambda: vault.gateway_status().report is not first, timeout=20)
        assert time.monotonic() - started < EVERY


async def test_the_status_path_checks_before_it_reads(tmp_path: Path, log: io.StringIO) -> None:
    """No query (400), one JSON content type (415), strict JSON in the frame (400 ``invalid``):
    each refused before the report is kept, and none of them starts the 5 s interval."""
    with real_vault(tmp_path, "tcp") as vault:
        assert vault.keys is not None
        key = vault.keys.current()
        assert key is not None
        headers = {"x-zoeymcp-gateway": key.reveal(), "content-type": "application/json"}
        base = vault.link.base_url
        async with httpx.AsyncClient(base_url=base, headers=headers, timeout=10) as http:
            with anyio.fail_after(10):
                query = await http.post(STATUS_PATH + "?x=1", content=b"{}")
                assert query.status_code == 400
                typed = await http.post(
                    STATUS_PATH, content=b"{}", headers={"content-type": "text/plain"}
                )
                assert typed.status_code == 415
                for body in (b"{", b'{"v": 1}', b"[]", b'{"v": 1, "v": 1}'):
                    answer = await http.post(STATUS_PATH, content=body)
                    assert (answer.status_code, answer.json()["code"]) == (400, "invalid")
                assert vault.app.gateway_status().report is None
                assert vault.app._status_gate.accepted_at is None
                anonymous = await http.post(
                    STATUS_PATH, content=b"{}", headers={"x-zoeymcp-gateway": ""}
                )
                assert anonymous.status_code == 403
    [refused] = events(log, "status_refused")
    assert refused["reason"] == "invalid"
