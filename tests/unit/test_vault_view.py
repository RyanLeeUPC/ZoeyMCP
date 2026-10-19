"""The gateway's view endpoint on the vault (M3 design D.1, D.2).

Only the gateway gets the view. Its digest is the ETag, a matching ``If-None-Match`` gets 304,
and ``?wait=N`` turns that into a long poll that a reload wakes. At most four wait at once.
Every other path under ``/_zoeymcp/`` is 404.
"""

from __future__ import annotations

import asyncio
import gc
import io
import json
import socket
import time
from collections.abc import AsyncIterator, Callable, Iterator
from pathlib import Path
from typing import Any, cast

import httpx
import pytest
from starlette.types import Message

from tests.fakes.harness import serve
from tests.unit.report_model import asked_line
from zoeymcp.common import ledgerreport
from zoeymcp.common.ledgerformat import GENESIS, line_hash
from zoeymcp.common.policy import Policy
from zoeymcp.common.policy.view import build_view, dump_view
from zoeymcp.vault import app as app_module
from zoeymcp.vault import logs, reportstore
from zoeymcp.vault.app import (
    GATEWAY_HEADER,
    LISTENER_SCOPE_KEY,
    REFUSAL_HEADER,
    REFUSAL_MARKER,
    REPORT_DEADLINE,
    REPORT_PATH,
    VIEW_MAX_WAIT,
    VIEW_MAX_WAITERS,
    VIEW_PATH,
    Listener,
    VaultApp,
    entity_tags,
    view_wait,
)
from zoeymcp.vault.gatewaykeys import GatewayKeyError
from zoeymcp.vault.keys import KeySet
from zoeymcp.vault.reportstore import ReportStore
from zoeymcp.vault.request import RequestRejected
from zoeymcp.vault.server import ListenerTag
from zoeymcp.vault.store import SecretStore

KEYS = KeySet.from_master(bytes(range(32)))
PH = "ph-agent1-direct-0001"
PIN = "sha256:" + "a" * 64
HASH = "sha256:" + "1" * 64
VIEW = "/_zoeymcp/gateway/v1/view"

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def captured() -> Iterator[io.StringIO]:
    buffer = io.StringIO()
    logs.set_stream(buffer)
    try:
        yield buffer
    finally:
        logs.set_stream(None)


def lines(buffer: io.StringIO, kind: str) -> list[dict[str, Any]]:
    parsed = [json.loads(line) for line in buffer.getvalue().splitlines()]
    return [line for line in parsed if line["event"] == kind]


def raw_policy(*, hosts: list[str] | None = None, generation: int = 1) -> dict[str, Any]:
    return {
        "version": 1,
        "mode": "declarative",
        "gateway_key_generation": generation,
        "credentials": {"notes-key": {"kind": "header", "secret": "store:notes-key"}},
        "routes": [
            {
                "name": "notes",
                "prefix": "/notes",
                "upstream": "https://mcp.notes.example",
                "credential": "notes-key",
                "callers": ["gateway", {"placeholder": PH}],
                "stream": True,
                "rules": [{"methods": ["POST"], "paths": ["/v1/mcp"]}],
            }
        ],
        "gateway": {
            "hosts": hosts or ["localhost"],
            "clients": {"agent1": {"token_sha256": HASH, "servers": ["notes-read"]}},
            "servers": {
                "notes-read": {
                    "kind": "remote",
                    "route": "notes",
                    "path": "/v1/mcp",
                    "tools": {"include": ["search"], "allow": ["search"]},
                    "review": {"search": PIN},
                }
            },
        },
    }


def make_policy(**kwargs: Any) -> Policy:
    return Policy.model_validate(raw_policy(**kwargs))


def unreachable(request: httpx.Request) -> httpx.Response:
    raise AssertionError("the view never reaches an upstream")


class Rig:
    def __init__(
        self,
        tmp_path: Path,
        pol: Policy,
        *,
        gateway_link: bool = False,
        reports: ReportStore | None = None,
    ) -> None:
        store = SecretStore(tmp_path, KEYS)
        store.load()
        client = httpx.AsyncClient(transport=httpx.MockTransport(unreachable))
        self.app = VaultApp(
            pol, store, KEYS, client=client, environ={}, gateway_link=gateway_link, reports=reports
        )

    async def call(
        self,
        path: str = VIEW,
        *,
        method: str = "GET",
        listener: str | None = "gateway",
        headers: dict[str, str] | list[tuple[str, str]] | None = None,
        content: bytes | None = None,
    ) -> httpx.Response:
        app: Any = self.app if listener is None else ListenerTag(self.app, cast(Listener, listener))
        transport = httpx.ASGITransport(app=app, client=("172.30.4.10", 40000))
        async with httpx.AsyncClient(transport=transport, base_url="http://vault") as client:
            return await client.request(method, path, headers=headers, content=content)

    def tag(self) -> dict[str, str]:
        return {"If-None-Match": f'"{self.app.view_digest}"'}


@pytest.fixture
async def rig(tmp_path: Path) -> AsyncIterator[Rig]:
    r = Rig(tmp_path, make_policy())
    yield r
    await r.app.aclose()


async def until(condition: Callable[[], object], what: str) -> None:
    """Waits up to 10 seconds for ``condition``, so a broken test fails instead of hanging."""
    for _ in range(1000):
        if condition():
            return
        await asyncio.sleep(0.01)
    raise AssertionError(what)


@pytest.fixture
async def reported() -> AsyncIterator[list[dict[str, Any]]]:
    """What reaches the loop's exception handler during the test."""
    contexts: list[dict[str, Any]] = []
    loop = asyncio.get_running_loop()
    loop.set_exception_handler(lambda loop, context: contexts.append(context))
    try:
        yield contexts
    finally:
        loop.set_exception_handler(None)


async def settle() -> None:
    """Let cancellations finish and collect what's gone, so a lost error would be reported."""
    await asyncio.sleep(0)
    gc.collect()
    await asyncio.sleep(0)


def left_over(before: set[asyncio.Task[Any]]) -> set[asyncio.Task[Any]]:
    """Tasks made since ``before`` that still run, besides the test's own."""
    return asyncio.all_tasks() - before - {cast(asyncio.Task[Any], asyncio.current_task())}


def never_waits(rig: Rig, monkeypatch: pytest.MonkeyPatch) -> None:
    """Make any long poll fail the test at once."""

    async def wait(*args: object) -> None:
        raise AssertionError("the request waited")

    monkeypatch.setattr(rig.app, "_wait_for_view", wait)


def key() -> dict[str, str]:
    return {GATEWAY_HEADER: KEYS.gateway_key(1)}


# --- serving the view ----------------------------------------------------------------------------


async def test_the_view_on_the_link(rig: Rig, captured: io.StringIO) -> None:
    view = build_view(make_policy())
    response = await rig.call()
    assert response.status_code == 200
    assert response.content == dump_view(view)
    assert response.headers["etag"] == f'"{view.digest}"'
    assert response.headers["content-type"] == "application/json"
    assert response.headers["cache-control"] == "no-store"
    assert REFUSAL_HEADER not in response.headers
    assert rig.app.view_digest == view.digest
    [served] = lines(captured, "gateway_view_served")
    assert {k: v for k, v in served.items() if k not in ("ts", "waited_ms")} == {
        "role": "vault",
        "event": "gateway_view_served",
        "digest": view.digest,
    }
    # A clock tick can fall between the two reads, so only a bound.
    assert isinstance(served["waited_ms"], int)
    assert 0 <= served["waited_ms"] < 1000
    [line] = lines(captured, "request")
    assert line["listener"] == "gateway"
    assert line["caller"] == "gateway"
    assert line["endpoint"] == "gateway_view"
    assert line["status"] == 200
    assert "route" not in line
    assert "reason" not in line


async def test_the_view_over_tcp_with_a_key(rig: Rig, captured: io.StringIO) -> None:
    response = await rig.call(listener="tcp", headers=key())
    assert response.status_code == 200
    assert response.content == dump_view(build_view(make_policy()))
    [line] = lines(captured, "request")
    assert (line["listener"], line["caller"], line["status"]) == ("tcp", "gateway", 200)


async def test_an_encoded_path_is_the_same_view(rig: Rig) -> None:
    response = await rig.call("/%5Fzoeymcp/gateway/v1/%76iew")
    assert response.status_code == 200
    assert response.headers["etag"] == f'"{rig.app.view_digest}"'


async def test_a_policy_without_a_gateway_section_has_the_default_view(tmp_path: Path) -> None:
    raw = raw_policy()
    del raw["gateway"]
    r = Rig(tmp_path, Policy.model_validate(raw))
    response = await r.call()
    assert response.status_code == 200
    assert json.loads(response.content)["gateway"]["servers"] == {}
    await r.app.aclose()


@pytest.mark.parametrize(
    ("listener", "headers", "reason"),
    [
        ("tcp", {}, "the view is for the gateway only"),
        (None, {}, "the view is for the gateway only"),
        ("tcp", {"Authorization": f"Bearer {PH}"}, "the view is for the gateway only"),
        ("tcp", {GATEWAY_HEADER: "zgw1-wrong"}, "gateway key refused"),
        ("tcp", {GATEWAY_HEADER: KEYS.gateway_key(2)}, "gateway key refused"),
        ("link", {}, "the view is for the gateway only"),
    ],
)
async def test_anyone_else_gets_the_bare_403(
    rig: Rig, captured: io.StringIO, listener: str | None, headers: dict[str, str], reason: str
) -> None:
    response = await rig.call(listener=listener, headers=headers)
    assert response.status_code == 403
    assert response.json() == {"error": "forbidden"}
    assert response.headers.get_list(REFUSAL_HEADER) == [REFUSAL_MARKER]
    assert "etag" not in response.headers
    [line] = lines(captured, "request")
    assert line["reason"] == reason
    assert line["endpoint"] == "gateway_view"
    assert "caller" not in line
    assert lines(captured, "gateway_view_served") == []


async def test_two_keys_are_refused(rig: Rig, captured: io.StringIO) -> None:
    good = KEYS.gateway_key(1)
    response = await rig.call(listener="tcp", headers=[(GATEWAY_HEADER, good)] * 2)
    assert response.status_code == 403
    assert [line["reason"] for line in lines(captured, "request")] == ["gateway key refused"]


async def test_tcp_refuses_a_valid_key_when_the_link_is_set(
    tmp_path: Path, captured: io.StringIO, monkeypatch: pytest.MonkeyPatch
) -> None:
    r = Rig(tmp_path, make_policy(), gateway_link=True)
    tried: list[bytes] = []
    monkeypatch.setattr(r.app.gateway_keys, "authenticate", tried.append)
    response = await r.call(listener="tcp", headers=key())
    assert response.status_code == 403
    assert response.headers[REFUSAL_HEADER] == REFUSAL_MARKER
    assert tried == []
    assert [line["reason"] for line in lines(captured, "request")] == ["gateway key refused on tcp"]
    # The link still gets it, and reads no key.
    assert (await r.call(headers=key())).status_code == 200
    assert tried == []
    await r.app.aclose()


async def test_tcp_without_a_key_when_the_link_is_set(
    tmp_path: Path, captured: io.StringIO
) -> None:
    r = Rig(tmp_path, make_policy(), gateway_link=True)
    response = await r.call(listener="tcp")
    assert response.status_code == 403
    assert response.headers[REFUSAL_HEADER] == REFUSAL_MARKER
    reasons = [line["reason"] for line in lines(captured, "request")]
    assert reasons == ["the view is for the gateway only"]
    await r.app.aclose()


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "HEAD", "OPTIONS"])
async def test_only_get(rig: Rig, captured: io.StringIO, method: str) -> None:
    response = await rig.call(method=method)
    assert response.status_code == 405
    assert response.headers["allow"] == "GET"
    assert response.headers[REFUSAL_HEADER] == REFUSAL_MARKER
    if method != "HEAD":
        assert response.json() == {"error": "method not allowed"}
    [line] = lines(captured, "request")
    assert (line["caller"], line["reason"]) == ("gateway", "the view takes GET only")


async def test_another_method_is_405_before_a_bad_query(rig: Rig, captured: io.StringIO) -> None:
    response = await rig.call(VIEW + "?wait=x", method="POST")
    assert response.status_code == 405
    assert [line["reason"] for line in lines(captured, "request")] == ["the view takes GET only"]


async def test_another_method_from_anyone_else_is_still_403(rig: Rig) -> None:
    response = await rig.call(method="POST", listener="tcp")
    assert response.status_code == 403
    assert "allow" not in response.headers


@pytest.mark.parametrize(
    ("query", "reason"),
    [
        ("?wait=x", "wait must be a number of seconds"),
        ("?other=1", "the view takes one parameter, wait"),
        ("?wait=1&wait=2", "the view takes one parameter, wait"),
        ("?wait=%zz", "malformed percent-encoding in query"),
    ],
)
async def test_a_bad_query_is_400(rig: Rig, captured: io.StringIO, query: str, reason: str) -> None:
    response = await rig.call(VIEW + query)
    assert response.status_code == 400
    assert response.json() == {"error": "bad request"}
    assert response.headers[REFUSAL_HEADER] == REFUSAL_MARKER
    [line] = lines(captured, "request")
    assert line["reason"] == reason


async def test_a_bad_query_from_anyone_else_is_403(rig: Rig) -> None:
    assert (await rig.call(VIEW + "?wait=x", listener="tcp")).status_code == 403


# --- other vault paths ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/_zoeymcp",
        "/_zoeymcp/",
        "/_zoeymcp/gateway",
        "/_zoeymcp/gateway/v1",
        "/_zoeymcp/gateway/v1/view/",
        "/_zoeymcp/gateway/v1/view/x",
        "/_zoeymcp/gateway/v2/view",
        "/_zoeymcp/gateway/v1/View",
        "/_zoeymcp/admin/v1/view",
        "/_zoeymcp/notes/v1/mcp",
    ],
)
@pytest.mark.parametrize(
    ("listener", "headers"), [("gateway", {}), ("tcp", key()), ("tcp", {}), (None, {})]
)
async def test_other_vault_paths_are_404(
    rig: Rig,
    captured: io.StringIO,
    path: str,
    listener: str | None,
    headers: dict[str, str],
) -> None:
    response = await rig.call(path, listener=listener, headers=headers)
    assert response.status_code == 404
    assert response.json() == {"error": "not found"}
    assert response.headers[REFUSAL_HEADER] == REFUSAL_MARKER
    [line] = lines(captured, "request")
    assert line["reason"] == "no such vault endpoint"
    assert "endpoint" not in line
    assert "caller" not in line


@pytest.mark.parametrize(
    ("path", "reason"),
    [
        ("/_zoeymcp/gateway/v1/%2e%2e/v1/view", "dot segment in path"),
        ("/_zoeymcp/gateway/v1/%2e/view", "dot segment in path"),
        ("/_zoeymcp//gateway/v1/view", "empty path segment"),
        ("/_zoeymcp/gateway/v1/view%2Fx", "slash or backslash inside a path segment"),
        ("/_zoeymcp/gateway/v1/%2576iew", "double percent-encoding"),
    ],
)
async def test_a_malformed_vault_path_is_400(
    rig: Rig, captured: io.StringIO, path: str, reason: str
) -> None:
    # The path is normalized before it's known to be the vault's own.
    response = await rig.call(path)
    assert response.status_code == 400
    assert response.headers[REFUSAL_HEADER] == REFUSAL_MARKER
    [line] = lines(captured, "request")
    assert line["reason"] == reason
    assert "endpoint" not in line


@pytest.mark.parametrize("prefix", ["/_zoeymcp", "/_x"])
def test_no_route_can_take_the_vault_path(prefix: str) -> None:
    # The vault's own paths are looked at before the routes, so a route there would be hidden.
    raw = raw_policy()
    raw["routes"][0]["prefix"] = prefix
    with pytest.raises(ValueError, match="prefix"):
        Policy.model_validate(raw)


async def test_a_post_elsewhere_under_the_vault_path_is_404(rig: Rig) -> None:
    assert (await rig.call("/_zoeymcp/gateway/v1/key", method="POST")).status_code == 404


def test_the_view_path() -> None:
    # A contract with the gateway, which can't import vault code.
    assert VIEW_PATH.text == VIEW
    assert (VIEW_MAX_WAIT, VIEW_MAX_WAITERS) == (25, 4)


# --- ETag and If-None-Match ----------------------------------------------------------------------


async def test_a_matching_tag_is_304(rig: Rig, captured: io.StringIO) -> None:
    response = await rig.call(headers=rig.tag())
    assert response.status_code == 304
    assert response.content == b""
    assert response.headers["etag"] == f'"{rig.app.view_digest}"'
    assert response.headers["cache-control"] == "no-store"
    assert REFUSAL_HEADER not in response.headers
    assert lines(captured, "gateway_view_served") == []
    [line] = lines(captured, "request")
    assert (line["status"], line["caller"]) == (304, "gateway")
    assert "disconnected" not in line


@pytest.mark.parametrize(
    "header",
    [
        'W/"{d}"',
        '"sha256:other", "{d}"',
        ' "{d}" ,W/"x"',
    ],
)
async def test_any_form_of_the_tag_is_304(rig: Rig, header: str) -> None:
    value = header.replace("{d}", rig.app.view_digest)
    assert (await rig.call(headers={"If-None-Match": value})).status_code == 304


async def test_the_tag_in_a_second_header_is_304(rig: Rig) -> None:
    headers = [("If-None-Match", '"sha256:other"'), ("If-None-Match", f'"{rig.app.view_digest}"')]
    assert (await rig.call(headers=headers)).status_code == 304


@pytest.mark.parametrize(
    "header",
    ['"sha256:other"', "{d}", "*", '"{d}" junk', '"{d}"x', '""', 'w/"{d}"', '"{d}",', ""],
)
async def test_anything_else_gets_the_view(rig: Rig, header: str) -> None:
    value = header.replace("{d}", rig.app.view_digest)
    response = await rig.call(VIEW + "?wait=25", headers={"If-None-Match": value})
    assert response.status_code == 200
    assert response.headers["etag"] == f'"{rig.app.view_digest}"'
    assert rig.app.view_waiters == 0


@pytest.mark.parametrize(
    ("values", "tags"),
    [
        ([], set()),
        (['"a"'], {"a"}),
        (['W/"a"'], {"a"}),
        (['"a", W/"b"'], {"a", "b"}),
        (['"a"', '"b"'], {"a", "b"}),
        ([' \t"a"\t '], {"a"}),
        (['""'], {""}),
        (['"!#~"'], {"!#~"}),
        (['"a"', "*"], set()),
        (["*"], set()),
        (["a"], set()),
        (['"a'], set()),
        (['a"'], set()),
        (['"a""b"'], set()),
        (['"a" "b"'], set()),
        (['"a b"'], set()),
        (['"a\\"b"'], set()),
        (['w/"a"'], set()),
        (['W"a"'], set()),
        (['W/ "a"'], set()),
        (['"a",'], set()),
        ([""], set()),
    ],
)
def test_entity_tags(values: list[str], tags: set[str]) -> None:
    assert entity_tags(values) == frozenset(tags)


# --- ?wait ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("params", "wait"),
    [
        ([], 0),
        ([("wait", "0")], 0),
        ([("wait", "1")], 1),
        ([("wait", "007")], 7),
        ([("wait", "24")], 24),
        ([("wait", "25")], 25),
        ([("wait", "26")], 25),
        ([("wait", "99")], 25),
        ([("wait", "100")], 25),
        ([("wait", "000")], 0),
        ([("wait", "00025")], 25),
        ([("wait", "99999999999999999999")], 25),
        # More digits than int() takes.
        ([("wait", "1" * 5000)], 25),
        ([("wait", "0" * 5000 + "7")], 7),
    ],
)
def test_view_wait(params: list[tuple[str, str]], wait: int) -> None:
    assert view_wait(params) == wait


@pytest.mark.parametrize(
    ("params", "reason"),
    [
        ([("wait", "")], "wait must be a number of seconds"),
        ([("wait", "-1")], "wait must be a number of seconds"),
        ([("wait", "+1")], "wait must be a number of seconds"),
        ([("wait", "1.5")], "wait must be a number of seconds"),
        ([("wait", " 1")], "wait must be a number of seconds"),
        ([("wait", "\u0661")], "wait must be a number of seconds"),
        ([("Wait", "1")], "the view takes one parameter, wait"),
        ([("other", "1")], "the view takes one parameter, wait"),
        ([("wait", "1"), ("wait", "1")], "the view takes one parameter, wait"),
        ([("wait", "1"), ("other", "1")], "the view takes one parameter, wait"),
    ],
)
def test_view_wait_refuses(params: list[tuple[str, str]], reason: str) -> None:
    with pytest.raises(RequestRejected) as caught:
        view_wait(params)
    assert caught.value.reason == reason


async def test_a_wait_of_many_digits_is_capped(rig: Rig, monkeypatch: pytest.MonkeyPatch) -> None:
    deadlines: list[float] = []

    async def wait(tags: object, deadline: float, *args: object) -> None:
        deadlines.append(deadline - time.monotonic())

    monkeypatch.setattr(rig.app, "_wait_for_view", wait)
    response = await rig.call(VIEW + "?wait=" + "1" * 5000, headers=rig.tag())
    assert response.status_code == 304
    [left] = deadlines
    assert VIEW_MAX_WAIT - 5 < left <= VIEW_MAX_WAIT


async def test_no_wait_answers_at_once(rig: Rig, monkeypatch: pytest.MonkeyPatch) -> None:
    never_waits(rig, monkeypatch)
    for query in ("", "?wait=0", "?wait=000"):
        assert (await rig.call(VIEW + query, headers=rig.tag())).status_code == 304
    assert rig.app.view_waiters == 0


async def test_a_wait_ends_with_304(
    rig: Rig, captured: io.StringIO, reported: list[dict[str, Any]]
) -> None:
    tasks = asyncio.all_tasks()
    started = time.monotonic()
    task = asyncio.create_task(rig.call(VIEW + "?wait=1", headers=rig.tag()))
    await until(lambda: rig.app.view_waiters == 1, "the request never waited")
    response = await asyncio.wait_for(task, 5)
    assert time.monotonic() - started >= 0.95
    assert response.status_code == 304
    assert response.headers["etag"] == f'"{rig.app.view_digest}"'
    assert rig.app.view_waiters == 0
    assert lines(captured, "gateway_view_served") == []
    # Nothing is left waiting on the view's event.
    await settle()
    assert left_over(tasks) == set()
    assert reported == []


async def test_a_reload_wakes_the_wait(
    rig: Rig, captured: io.StringIO, reported: list[dict[str, Any]]
) -> None:
    before = rig.app.view_digest
    tasks = asyncio.all_tasks()
    started = time.monotonic()
    task = asyncio.create_task(rig.call(VIEW + "?wait=25", headers=rig.tag()))
    await until(lambda: rig.app.view_waiters == 1, "the request never waited")
    await asyncio.sleep(0.1)
    changed = make_policy(hosts=["localhost", "gateway.example"])
    rig.app.reload(changed)
    response = await asyncio.wait_for(task, 2)
    assert time.monotonic() - started < 5
    assert response.status_code == 200
    view = build_view(changed)
    assert response.content == dump_view(view)
    assert response.headers["etag"] == f'"{view.digest}"'
    assert view.digest != before
    assert rig.app.view_waiters == 0
    [served] = lines(captured, "gateway_view_served")
    assert served["digest"] == view.digest
    assert 50 <= served["waited_ms"] < 5000
    await settle()
    assert left_over(tasks) == set()
    assert reported == []


async def test_a_reload_that_keeps_the_view_keeps_waiting(rig: Rig) -> None:
    before = rig.app.view_digest
    task = asyncio.create_task(rig.call(VIEW + "?wait=25", headers=rig.tag()))
    await until(lambda: rig.app.view_waiters == 1, "the request never waited")
    # A rule isn't part of the view.
    raw = raw_policy()
    raw["routes"][0]["rules"][0]["methods"] = ["POST", "GET"]
    rig.app.reload(Policy.model_validate(raw))
    assert rig.app.view_digest == before
    await asyncio.sleep(0.2)
    assert not task.done()
    assert rig.app.view_waiters == 1
    rig.app.reload(make_policy(hosts=["gateway.example"]))
    response = await asyncio.wait_for(task, 2)
    assert response.status_code == 200
    assert response.headers["etag"] != f'"{before}"'


async def test_a_wait_for_an_old_tag_answers_at_once(
    rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    old = rig.tag()
    rig.app.reload(make_policy(hosts=["gateway.example"]))
    never_waits(rig, monkeypatch)
    response = await rig.call(VIEW + "?wait=25", headers=old)
    assert response.status_code == 200
    assert rig.app.view_waiters == 0


async def test_a_refused_reload_keeps_the_view_and_the_wait(tmp_path: Path) -> None:
    r = Rig(tmp_path, make_policy(generation=2))
    before = r.app.view_digest
    task = asyncio.create_task(r.call(VIEW + "?wait=25", headers=r.tag()))
    await until(lambda: r.app.view_waiters == 1, "the request never waited")
    with pytest.raises(GatewayKeyError):
        r.app.reload(make_policy(hosts=["gateway.example"], generation=1))
    assert r.app.view_digest == before
    assert (await r.call()).content == dump_view(build_view(make_policy(generation=2)))
    await asyncio.sleep(0.1)
    assert not task.done()
    r.app.stop_view_waits()
    assert (await asyncio.wait_for(task, 2)).status_code == 304
    await r.app.aclose()


async def test_a_fifth_waiter_gets_429(rig: Rig, captured: io.StringIO) -> None:
    waits = [
        asyncio.create_task(rig.call(VIEW + "?wait=25", headers=rig.tag()))
        for _ in range(VIEW_MAX_WAITERS)
    ]
    await until(lambda: rig.app.view_waiters == 4, "four never waited")
    response = await rig.call(VIEW + "?wait=25", headers=rig.tag())
    assert response.status_code == 429
    assert response.json() == {"error": "too many requests"}
    assert response.headers["retry-after"] == "1"
    assert response.headers[REFUSAL_HEADER] == REFUSAL_MARKER
    refused = [line for line in lines(captured, "request") if line["status"] == 429]
    assert [(x["reason"], x["caller"]) for x in refused] == [("too many view waiters", "gateway")]
    # Requests that don't wait are still answered, ?wait or not.
    assert (await rig.call()).status_code == 200
    assert (await rig.call(headers=rig.tag())).status_code == 304
    assert (await rig.call(VIEW + "?wait=25")).status_code == 200
    stale = {"If-None-Match": '"sha256:other"'}
    assert (await rig.call(VIEW + "?wait=25", headers=stale)).status_code == 200
    assert rig.app.view_waiters == 4
    rig.app.reload(make_policy(hosts=["gateway.example"]))
    answers = await asyncio.wait_for(asyncio.gather(*waits), 2)
    assert [a.status_code for a in answers] == [200] * 4
    assert rig.app.view_waiters == 0
    # The places are free again.
    again = [
        asyncio.create_task(rig.call(VIEW + "?wait=25", headers=rig.tag()))
        for _ in range(VIEW_MAX_WAITERS)
    ]
    await until(lambda: rig.app.view_waiters == 4, "four never waited again")
    rig.app.stop_view_waits()
    answers = await asyncio.wait_for(asyncio.gather(*again), 2)
    assert [a.status_code for a in answers] == [304] * 4


async def test_stopping_answers_every_wait(rig: Rig, monkeypatch: pytest.MonkeyPatch) -> None:
    waits = [asyncio.create_task(rig.call(VIEW + "?wait=25", headers=rig.tag())) for _ in range(3)]
    await until(lambda: rig.app.view_waiters == 3, "three never waited")
    rig.app.stop_view_waits()
    answers = await asyncio.wait_for(asyncio.gather(*waits), 2)
    assert [a.status_code for a in answers] == [304] * 3
    assert rig.app.view_waiters == 0
    # A wait after that answers at once; one with an old tag still gets the view.
    never_waits(rig, monkeypatch)
    assert (await rig.call(VIEW + "?wait=25", headers=rig.tag())).status_code == 304
    assert rig.app.view_waiters == 0
    assert (await rig.call(VIEW + "?wait=25")).status_code == 200


async def test_a_cancelled_wait_frees_its_place(rig: Rig) -> None:
    task = asyncio.create_task(rig.call(VIEW + "?wait=25", headers=rig.tag()))
    await until(lambda: rig.app.view_waiters == 1, "the request never waited")
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert rig.app.view_waiters == 0


def _scope(digest: str) -> dict[str, Any]:
    return {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": VIEW,
        "raw_path": VIEW.encode(),
        "query_string": b"wait=25",
        "root_path": "",
        "headers": [(b"host", b"vault"), (b"if-none-match", f'"{digest}"'.encode())],
        "client": ("172.30.4.10", 40000),
        "server": ("vault", 80),
        LISTENER_SCOPE_KEY: "gateway",
    }


async def _call_raw(
    rig: Rig, receive: Callable[[], Any]
) -> tuple[asyncio.Task[None], list[Message]]:
    sent: list[Message] = []

    async def send(message: Message) -> None:
        sent.append(message)

    task = asyncio.create_task(rig.app(_scope(rig.app.view_digest), receive, send))
    await until(lambda: rig.app.view_waiters == 1, "the request never waited")
    return task, sent


async def test_an_answered_wait_stops_listening_for_the_caller(
    rig: Rig, reported: list[dict[str, Any]]
) -> None:
    tasks = asyncio.all_tasks()
    messages = [{"type": "http.request", "body": b"", "more_body": False}]

    async def receive() -> dict[str, Any]:
        if messages:
            return messages.pop(0)
        await asyncio.Event().wait()
        raise AssertionError("never")

    task, sent = await _call_raw(rig, receive)
    rig.app.reload(make_policy(hosts=["gateway.example"]))
    await asyncio.wait_for(task, 2)
    assert sent[0]["status"] == 200
    assert rig.app.view_waiters == 0
    await settle()
    assert left_over(tasks) == set()
    assert reported == []


async def test_a_caller_that_leaves_frees_its_place(
    rig: Rig, captured: io.StringIO, reported: list[dict[str, Any]]
) -> None:
    tasks = asyncio.all_tasks()
    left = asyncio.Event()
    messages = [{"type": "http.request", "body": b"", "more_body": False}]

    async def receive() -> dict[str, Any]:
        if messages:
            return messages.pop(0)
        await left.wait()
        return {"type": "http.disconnect"}

    task, sent = await _call_raw(rig, receive)
    await asyncio.sleep(0.05)
    assert not task.done()
    left.set()
    await asyncio.wait_for(task, 2)
    assert rig.app.view_waiters == 0
    assert sent[0]["status"] == 304
    [line] = lines(captured, "request")
    assert (line["status"], line["disconnected"]) == (304, True)
    await settle()
    assert left_over(tasks) == set()
    assert reported == []


async def test_a_receive_error_ends_the_wait_quietly(
    rig: Rig, captured: io.StringIO, reported: list[dict[str, Any]]
) -> None:
    failed = asyncio.Event()
    calls = 0

    async def receive() -> dict[str, Any]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return {"type": "http.request", "body": b"", "more_body": False}
        await failed.wait()
        raise OSError("connection reset")

    task, sent = await _call_raw(rig, receive)
    failed.set()
    await asyncio.wait_for(task, 2)
    assert sent[0]["status"] == 304
    assert rig.app.view_waiters == 0
    assert lines(captured, "request")[0]["disconnected"] is True
    await settle()
    assert reported == []


def test_a_closed_socket_frees_its_place(tmp_path: Path) -> None:
    """On a real server, a caller that closes its connection stops waiting at once."""
    app = Rig(tmp_path, make_policy()).app
    with serve(app) as base:
        host, port = base.removeprefix("http://").split(":")
        request = (
            f"GET {VIEW}?wait=25 HTTP/1.1\r\nHost: vault\r\n"
            f"{GATEWAY_HEADER}: {KEYS.gateway_key(1)}\r\n"
            f'If-None-Match: "{app.view_digest}"\r\n\r\n'
        ).encode()
        with socket.create_connection((host, int(port)), timeout=10) as conn:
            conn.sendall(request)
            deadline = time.monotonic() + 10
            while app.view_waiters != 1:
                assert time.monotonic() < deadline, "the request never waited"
                time.sleep(0.01)
        deadline = time.monotonic() + 5
        while app.view_waiters != 0:
            assert time.monotonic() < deadline, "the wait outlived its caller"
            time.sleep(0.01)
    asyncio.run(app.aclose())


# --- the report path (M5 design J.2) -------------------------------------------------------------

REPORT = "/_zoeymcp/gateway/v1/report/ledger"
JSON = {"Content-Type": "application/json"}


def report_lines(count: int, *, tick: int = 0) -> list[bytes]:
    lines: list[bytes] = []
    prev = GENESIS
    for n in range(count):
        lines.append(asked_line(n, prev, tick + n + 1))
        prev = line_hash(lines[-1])
    return lines


LEDGER = report_lines(6)
FORKED = report_lines(6, tick=1000)


@pytest.fixture
async def copy_rig(tmp_path: Path) -> AsyncIterator[Rig]:
    r = Rig(tmp_path, make_policy(), reports=ReportStore.open(tmp_path))
    yield r
    await r.app.aclose()


def held(rig: Rig) -> ReportStore:
    reports = rig.app.reports
    assert reports is not None
    return reports


async def post(rig: Rig, lines: list[bytes], **kwargs: Any) -> httpx.Response:
    headers = kwargs.pop("headers", JSON)
    return await rig.call(
        REPORT, method="POST", headers=headers, content=ledgerreport.encode(lines), **kwargs
    )


class Raw:
    """A raw ASGI request to the report path, counting the times the app asks for the body."""

    def __init__(self, *, hang: bool = False) -> None:
        self.receives = 0
        self.hang = hang
        self.status = 0
        self.headers: dict[bytes, bytes] = {}
        self.body = b""

    async def __call__(
        self,
        app: Any,
        *,
        method: str = "POST",
        headers: list[tuple[bytes, bytes]],
        chunks: list[bytes],
        listener: str = "gateway",
    ) -> Raw:
        async def receive() -> Message:
            self.receives += 1
            if self.hang:
                await asyncio.sleep(3600)
            if chunks:
                return {"type": "http.request", "body": chunks.pop(0), "more_body": bool(chunks)}
            return {"type": "http.disconnect"}

        async def send(message: Message) -> None:
            if message["type"] == "http.response.start":
                self.status = message["status"]
                self.headers = dict(message["headers"])
            else:
                self.body += message.get("body", b"")

        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": method,
            "scheme": "http",
            "path": REPORT,
            "raw_path": REPORT.encode(),
            "query_string": b"",
            "root_path": "",
            "headers": headers,
            "client": ("172.30.4.10", 40000),
            "server": ("vault", 80),
        }
        await ListenerTag(app, cast(Listener, listener))(scope, receive, send)
        return self


def raw_headers(
    length: int, content_type: bytes = b"application/json"
) -> list[tuple[bytes, bytes]]:
    return [(b"content-type", content_type), (b"content-length", str(length).encode())]


def test_the_report_path() -> None:
    # A contract with the gateway, which can't import vault code.
    assert REPORT_PATH.text == REPORT == ledgerreport.PATH
    assert REPORT_DEADLINE == 10.0


async def test_the_gateway_reads_the_head(copy_rig: Rig, captured: io.StringIO) -> None:
    response = await copy_rig.call(REPORT)
    assert response.status_code == 200
    assert response.json() == {"head_seq": None, "head_hash": None, "state": "ok"}
    assert response.headers["cache-control"] == "no-store"
    assert REFUSAL_HEADER not in response.headers
    assert held(copy_rig).contact_ms is not None
    [line] = lines(captured, "request")
    assert (line["endpoint"], line["caller"], line["status"]) == ("gateway_report", "gateway", 200)


async def test_the_gateway_reports_over_tcp_with_a_key(copy_rig: Rig) -> None:
    response = await post(copy_rig, LEDGER[:3], listener="tcp", headers={**JSON, **key()})
    assert response.status_code == 200
    assert response.json() == {"head_seq": 2, "head_hash": line_hash(LEDGER[2]), "state": "ok"}


@pytest.mark.parametrize(
    ("listener", "headers", "reason"),
    [
        ("tcp", {}, "the report path is for the gateway only"),
        (None, {}, "the report path is for the gateway only"),
        ("tcp", {"Authorization": f"Bearer {PH}"}, "the report path is for the gateway only"),
        ("tcp", {GATEWAY_HEADER: "zgw1-wrong"}, "gateway key refused"),
        ("tcp", {GATEWAY_HEADER: KEYS.gateway_key(2)}, "gateway key refused"),
        ("link", {}, "the report path is for the gateway only"),
    ],
)
@pytest.mark.parametrize("method", ["GET", "POST"])
async def test_anyone_else_gets_the_bare_403_for_reports(
    copy_rig: Rig,
    captured: io.StringIO,
    listener: str | None,
    headers: dict[str, str],
    reason: str,
    method: str,
) -> None:
    content = ledgerreport.encode(LEDGER[:1]) if method == "POST" else None
    response = await copy_rig.call(
        REPORT, method=method, listener=listener, headers={**JSON, **headers}, content=content
    )
    assert response.status_code == 403
    assert response.json() == {"error": "forbidden"}
    assert response.headers.get_list(REFUSAL_HEADER) == [REFUSAL_MARKER]
    [line] = lines(captured, "request")
    assert (line["reason"], line["endpoint"]) == (reason, "gateway_report")
    assert "caller" not in line
    assert held(copy_rig).contact_ms is None
    assert held(copy_rig).held.head_seq is None


async def test_a_refused_identity_never_reads_the_body(tmp_path: Path) -> None:
    rig = Rig(tmp_path, make_policy(), gateway_link=True, reports=ReportStore.open(tmp_path))
    body = ledgerreport.encode(LEDGER[:1])
    for listener, extra in [("tcp", []), ("tcp", [(GATEWAY_HEADER.encode(), b"zgw1-x")])]:
        raw = await Raw()(
            rig.app, headers=raw_headers(len(body)) + extra, chunks=[body], listener=listener
        )
        assert (raw.status, raw.receives) == (403, 0)
    await rig.app.aclose()


async def test_two_keys_are_refused_for_reports(copy_rig: Rig) -> None:
    good = KEYS.gateway_key(1)
    response = await copy_rig.call(REPORT, listener="tcp", headers=[(GATEWAY_HEADER, good)] * 2)
    assert response.status_code == 403


@pytest.mark.parametrize("method", ["PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def test_reports_take_get_or_post(copy_rig: Rig, captured: io.StringIO, method: str) -> None:
    raw = await Raw()(copy_rig.app, method=method, headers=raw_headers(2), chunks=[b"{}"])
    assert (raw.status, raw.receives) == (405, 0)
    assert raw.headers[b"allow"] == b"GET, POST"
    [line] = lines(captured, "request")
    assert (line["caller"], line["reason"]) == ("gateway", "the report path takes GET or POST")


async def test_another_method_from_anyone_else_is_403_on_the_report_path(copy_rig: Rig) -> None:
    response = await copy_rig.call(REPORT, method="PUT", listener="tcp")
    assert response.status_code == 403
    assert "allow" not in response.headers


async def test_the_report_path_takes_no_query(copy_rig: Rig) -> None:
    assert (await copy_rig.call(REPORT + "?wait=1")).status_code == 400


async def test_without_a_copy_reports_are_503(rig: Rig) -> None:
    response = await rig.call(REPORT)
    assert response.status_code == 503
    assert response.json() == {"error": "unavailable", "code": "unavailable"}
    assert (await rig.call(REPORT, listener="tcp")).status_code == 403


async def test_an_unreadable_copy_is_503_and_the_proxy_is_unaffected(tmp_path: Path) -> None:
    (tmp_path / "ledger-reported").write_bytes(b"not a directory")
    rig = Rig(tmp_path, make_policy(), reports=ReportStore.open(tmp_path))
    assert (await rig.call(REPORT)).status_code == 503
    assert (await post(rig, LEDGER[:1])).status_code == 503
    assert (await rig.call()).status_code == 200  # the view still serves
    await rig.app.aclose()


@pytest.mark.parametrize(
    ("headers", "status", "code"),
    [
        ([], 415, "content_type"),
        ([(b"content-type", b"text/plain")], 415, "content_type"),
        ([(b"content-type", b"application/json")] * 2, 415, "content_type"),
        ([(b"content-type", b"application/json")], 411, "length_required"),
        (
            [(b"content-type", b"application/json"), (b"transfer-encoding", b"chunked")],
            411,
            "length_required",
        ),
        ([*raw_headers(5), (b"content-length", b"5")], 411, "length_required"),
        ([*raw_headers(5)[:1], (b"content-length", b"+5")], 411, "length_required"),
        ([*raw_headers(5)[:1], (b"content-length", b"1" * 13)], 411, "length_required"),
        (raw_headers(ledgerreport.MAX_BODY_BYTES + 1), 413, "too_large"),
    ],
)
async def test_report_headers_are_checked_before_the_body(
    copy_rig: Rig, headers: list[tuple[bytes, bytes]], status: int, code: str
) -> None:
    raw = await Raw()(copy_rig.app, headers=headers, chunks=[b"{}"])
    assert (raw.status, raw.receives) == (status, 0)
    assert json.loads(raw.body) == {"error": json.loads(raw.body)["error"], "code": code}
    assert raw.headers[REFUSAL_HEADER.encode()] == REFUSAL_MARKER.encode()


async def test_a_body_of_1_mib_is_read(copy_rig: Rig) -> None:
    body = b" " * (ledgerreport.MAX_BODY_BYTES - 2) + b"{}"
    raw = await Raw()(copy_rig.app, headers=raw_headers(len(body)), chunks=[body])
    assert raw.status == 400  # read, then refused as a report: {} isn't one
    assert json.loads(raw.body)["code"] == "bad_body"


async def test_a_body_past_the_cap_is_cut_off(copy_rig: Rig) -> None:
    chunk = b" " * (ledgerreport.MAX_BODY_BYTES // 2 + 1)
    raw = await Raw()(copy_rig.app, headers=raw_headers(10), chunks=[chunk, chunk, chunk])
    assert raw.status == 413
    assert raw.receives == 2


async def test_a_body_unlike_its_length_is_refused(copy_rig: Rig) -> None:
    raw = await Raw()(copy_rig.app, headers=raw_headers(10), chunks=[b"{}"])
    assert raw.status == 400
    assert json.loads(raw.body)["code"] == "bad_body"


async def test_a_slow_body_is_408(copy_rig: Rig, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(app_module, "REPORT_DEADLINE", 0.05)
    raw = await Raw(hang=True)(copy_rig.app, headers=raw_headers(2), chunks=[b"{}"])
    assert raw.status == 408
    assert json.loads(raw.body) == {"error": "request timeout", "code": "too_slow"}
    assert not held(copy_rig).lock.locked()


async def test_one_report_at_a_time(copy_rig: Rig) -> None:
    async with held(copy_rig).lock:
        raw = await Raw()(copy_rig.app, headers=raw_headers(2), chunks=[b"{}"])
    assert (raw.status, raw.receives) == (429, 0)
    assert raw.headers[b"retry-after"] == b"1"
    assert json.loads(raw.body) == {"error": "too many requests", "code": "busy"}
    # A GET of the head doesn't wait for it.
    async with held(copy_rig).lock:
        assert (await copy_rig.call(REPORT)).status_code == 200


@pytest.mark.parametrize(
    "body", [b"not json", b'{"v": 1, "v": 1, "lines": []}', b"\xff", b"[1e400]"]
)
async def test_a_body_that_isnt_strict_json_is_400(copy_rig: Rig, body: bytes) -> None:
    response = await copy_rig.call(REPORT, method="POST", headers=JSON, content=body)
    assert response.status_code == 400
    assert response.json() == {"error": "bad request", "code": "bad_body"}


async def test_a_report_is_kept_and_answered_with_the_head(
    copy_rig: Rig, captured: io.StringIO, tmp_path: Path
) -> None:
    response = await post(copy_rig, LEDGER[:3])
    assert response.status_code == 200
    assert response.json() == {"head_seq": 2, "head_hash": line_hash(LEDGER[2]), "state": "ok"}
    copied = (tmp_path / "ledger-reported" / "000000000000.jsonl").read_bytes()
    assert copied == b"".join(line + b"\n" for line in LEDGER[:3])
    charset = {"Content-Type": "application/json; charset=utf-8"}
    assert (await post(copy_rig, LEDGER[2:5], headers=charset)).json()["head_seq"] == 4
    [first, _second] = lines(captured, "request")
    assert (first["endpoint"], first["status"]) == ("gateway_report", 200)
    # No line of the ledger is ever logged.
    for line in LEDGER:
        assert line.decode() not in captured.getvalue()
    assert "hmac-sha256" not in captured.getvalue()


async def test_a_refused_report_names_its_code_and_the_head(
    copy_rig: Rig, captured: io.StringIO
) -> None:
    await post(copy_rig, LEDGER[:3])
    response = await post(copy_rig, FORKED[2:4])
    assert response.status_code == 409
    assert response.headers[REFUSAL_HEADER] == REFUSAL_MARKER
    message = "the report starts at seq 2, which doesn't extend the held head"
    assert response.json() == {
        "error": message,
        "code": "fork",
        "head_seq": 2,
        "head_hash": line_hash(LEDGER[2]),
        "state": "fork",
    }
    request = lines(captured, "request")[-1]
    assert (request["status"], request["reason"], request["code"]) == (409, "fork", "fork")
    sticky = await post(copy_rig, LEDGER[3:4])
    assert (sticky.status_code, sticky.json()["code"]) == (409, "refused_until_restart")
    assert (await copy_rig.call(REPORT)).json()["state"] == "fork"


async def test_a_bad_line_names_its_index(copy_rig: Rig) -> None:
    content = json.dumps({"v": 1, "lines": [LEDGER[0].decode(), "x"]}).encode()
    response = await copy_rig.call(REPORT, method="POST", headers=JSON, content=content)
    assert response.status_code == 400
    assert (response.json()["code"], response.json()["index"]) == ("bad_line", 1)


async def test_a_failed_write_is_503(copy_rig: Rig, monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(path: Path, data: bytes) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(reportstore, "_append", broken)
    response = await post(copy_rig, LEDGER[:2])
    assert response.status_code == 503
    assert response.json()["code"] == "unavailable"
    assert not held(copy_rig).lock.locked()
