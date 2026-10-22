"""The vault's side of the egress role (M7 design G.2, G.3, I.3, X15, X21; step 17b).

``GET /_zoeymcp/egress/v1/allowlists`` answers the egress key alone, over TCP: the lists'
digest is the ``ETag``, a matching ``If-None-Match`` gets 304, and ``?wait=N`` turns that into a
long poll that a reload or an onboarding's allowance change wakes. The answer is
``egresslist.document`` of the running policy's lists with the live allowances, so the role's
parser reads the vault's real answer as it reads its test fake's (``tests/fakes/allowlist.py``).
The egress key reaches no other path, the gateway's key never reaches this one, and the link
socket never serves it. The vault keeps when the role last fetched and the digest it holds,
which an onboarding through the role waits for (:meth:`VaultApp.role_fetched`). With
``egress_proxy_kind: role`` the role is expected, so health measures a role that never asks from
the vault's start; with ``own`` only a role that asks is measured.
"""

from __future__ import annotations

import asyncio
import io
import json
import time
from collections.abc import AsyncIterator, Callable, Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import httpx
import pytest

from tests.fakes import allowlist as fake_allowlist
from tests.fakes.harness import serve
from zoeymcp.common import egresslist
from zoeymcp.common.egresslist import Allowance
from zoeymcp.common.policy import Policy
from zoeymcp.egress import allowlist as role_allowlist
from zoeymcp.egress.allowlist import Allowlist, KeySource, parse_document
from zoeymcp.vault import app as vault_app
from zoeymcp.vault import health, logs
from zoeymcp.vault.app import (
    ALLOWLIST_PATH,
    EGRESS_HEADER,
    GATEWAY_HEADER,
    REFUSAL_HEADER,
    REFUSAL_MARKER,
    Listener,
    VaultApp,
)
from zoeymcp.vault.internal import ALLOWLIST_WAITERS
from zoeymcp.vault.keys import KeySet
from zoeymcp.vault.onboarding import ONBOARDING_TTL, Names, OnboardingTable, Options
from zoeymcp.vault.server import ListenerTag
from zoeymcp.vault.store import SecretStore

KEYS = KeySet.from_master(bytes(range(32)))
PH = "ph-agent1-direct-0001"
ALLOWLISTS = "/_zoeymcp/egress/v1/allowlists"
SERVER = "https://mcp.newco.example/mcp"

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


def raw_policy(
    *, upstream: str = "https://api.notes.example/v1", generation: int = 1, **more: Any
) -> dict[str, Any]:
    return {
        "version": 1,
        "mode": "declarative",
        "egress_key_generation": generation,
        "credentials": {"notes-key": {"kind": "header", "secret": "store:notes-key"}},
        "routes": [
            {
                "name": "notes",
                "prefix": "/notes",
                "upstream": upstream,
                "credential": "notes-key",
                "callers": ["gateway", {"placeholder": PH}],
                "rules": [{"methods": ["GET"], "paths": ["/**"]}],
            }
        ],
        **more,
    }


def make_policy(**kwargs: Any) -> Policy:
    return Policy.model_validate(raw_policy(**kwargs))


def unreachable(request: httpx.Request) -> httpx.Response:
    raise AssertionError("the allowlists never reach an upstream")


class Rig:
    def __init__(self, tmp_path: Path, pol: Policy, *, gateway_link: bool = False) -> None:
        store = SecretStore(tmp_path, KEYS)
        store.load()
        client = httpx.AsyncClient(transport=httpx.MockTransport(unreachable))
        self.app = VaultApp(pol, store, KEYS, client=client, environ={}, gateway_link=gateway_link)
        self.allowances: list[Allowance] = []
        self.app.use_allowances(lambda: self.allowances)

    async def call(
        self,
        path: str = ALLOWLISTS,
        *,
        method: str = "GET",
        listener: str | None = "tcp",
        headers: dict[str, str] | list[tuple[str, str]] | None = None,
    ) -> httpx.Response:
        app: Any = self.app if listener is None else ListenerTag(self.app, cast(Listener, listener))
        transport = httpx.ASGITransport(app=app, client=("172.30.9.2", 40000))
        async with httpx.AsyncClient(transport=transport, base_url="http://vault") as client:
            return await client.request(method, path, headers=headers)

    async def fetch(self, query: str = "", tag: str | None = None) -> httpx.Response:
        """The role's request: its key, and the digest it holds."""
        headers = key()
        if tag is not None:
            headers["If-None-Match"] = f'"{tag}"'
        return await self.call(ALLOWLISTS + query, headers=headers)

    def digest(self) -> str:
        return str(self.app.allowlist_document()["digest"])


@pytest.fixture
async def rig(tmp_path: Path) -> AsyncIterator[Rig]:
    r = Rig(tmp_path, make_policy())
    yield r
    await r.app.aclose()


def key(generation: int = 1) -> dict[str, str]:
    return {EGRESS_HEADER: KEYS.egress_key(generation)}


async def until(condition: Callable[[], object], what: str) -> None:
    """Waits up to 10 seconds for ``condition``, so a broken test fails instead of hanging."""
    for _ in range(1000):
        if condition():
            return
        await asyncio.sleep(0.01)
    raise AssertionError(what)


def allowance(*pairs: tuple[str, int]) -> Allowance:
    return Allowance(frozenset(pairs))


# --- the answer -----------------------------------------------------------------------------------


async def test_the_role_gets_its_lists(rig: Rig, captured: io.StringIO) -> None:
    expected = egresslist.document(egresslist.derive(make_policy()))
    assert rig.app.allowlist_fetched_ago() is None
    response = await rig.fetch()
    assert response.status_code == 200
    assert response.json() == expected
    assert expected["sources"] == {
        "vault": [{"host": "api.notes.example", "port": 443, "private": False}]
    }
    assert response.headers["etag"] == f'"{expected["digest"]}"'
    assert response.headers["content-type"] == "application/json"
    assert response.headers["cache-control"] == "no-store"
    assert REFUSAL_HEADER not in response.headers
    # The fetch is recorded for health.
    ago = rig.app.allowlist_fetched_ago()
    assert ago is not None
    assert 0 <= ago < 5
    [served] = lines(captured, "egress_allowlist_served")
    assert served["digest"] == expected["digest"]
    assert 0 <= served["waited_ms"] < 1000
    [line] = lines(captured, "request")
    assert (line["listener"], line["caller"], line["endpoint"], line["status"]) == (
        "tcp",
        "egress",
        "egress_allowlists",
        200,
    )
    assert "route" not in line


async def test_the_answer_holds_host_names_and_ports_only(tmp_path: Path) -> None:
    """DD-11's least data: no route, credential, placeholder or policy field, and a private
    destination marked as egress_private marks it."""
    lan = "https://files.lan.example:8443/v1"
    r = Rig(tmp_path, make_policy(upstream=lan, egress_private=["files.lan.example:8443"]))
    text = (await r.fetch()).text
    assert json.loads(text)["sources"] == {
        "vault": [{"host": "files.lan.example", "port": 8443, "private": True}]
    }
    for value in ("notes", "notes-key", PH, "/v1", "store:", "egress_private", "gateway"):
        assert value not in text
    await r.app.aclose()


async def test_the_vault_answers_as_the_roles_fake_does(rig: Rig) -> None:
    """tests/fakes/allowlist.py serves the role's tests: its document and the vault's are the
    same bytes for the same lists, and the role's parser reads both alike."""
    rig.allowances.append(allowance(("auth.newco.example", 443)))
    body = (await rig.fetch()).content
    fake = fake_allowlist.document(
        {"vault": [("api.notes.example", 443), ("auth.newco.example", 443)]}
    )
    assert body == json.dumps(fake).encode()
    assert parse_document(body) == parse_document(json.dumps(fake).encode())
    digest, lists, skipped = parse_document(body)
    assert digest == rig.digest()
    assert lists == {"vault": {"api.notes.example:443": False, "auth.newco.example:443": False}}
    assert skipped == 0
    # The role's request and the vault's endpoint name the same path and header.
    assert (ALLOWLIST_PATH.text, EGRESS_HEADER) == (role_allowlist.PATH, role_allowlist.HEADER)
    assert (ALLOWLIST_PATH.text, EGRESS_HEADER) == (fake_allowlist.PATH, fake_allowlist.HEADER)


def test_the_roles_poll_reads_the_vaults_real_answer(tmp_path: Path) -> None:
    """The role's own client against the vault on a real socket: a 200 it applies, then its
    long poll's 304, which is contact (I.4)."""
    store = SecretStore(tmp_path, KEYS)
    store.load()
    app = VaultApp(make_policy(), store, KEYS, environ={})
    applied: list[object] = []

    async def poll(base: str) -> tuple[bool, bool]:
        role = Allowlist(base, KeySource(KEYS.egress_key(1)), wait=1, on_apply=applied.append)
        first = await asyncio.wait_for(role.fetch_once(), 10)
        assert role.digest == app.allowlist_document()["digest"]
        started = time.monotonic()
        second = await asyncio.wait_for(role.fetch_once(), 10)
        # The vault held the poll for its wait, then answered 304.
        assert time.monotonic() - started >= 0.9
        return first, second

    with serve(app) as base:
        assert asyncio.run(poll(base)) == (True, True)
    assert applied == [{"vault": {"api.notes.example:443": False}}]
    fetched = app.allowlist_fetched_ago()
    assert fetched is not None
    assert fetched < 5
    asyncio.run(app.aclose())


async def test_a_matching_tag_is_304(rig: Rig, captured: io.StringIO) -> None:
    response = await rig.fetch(tag=rig.digest())
    assert response.status_code == 304
    assert response.content == b""
    assert response.headers["etag"] == f'"{rig.digest()}"'
    assert response.headers["cache-control"] == "no-store"
    assert lines(captured, "egress_allowlist_served") == []
    # A 304 is a fetch too.
    assert rig.app.allowlist_fetched_ago() is not None


async def test_an_old_tag_gets_the_lists_at_once(rig: Rig) -> None:
    response = await rig.fetch("?wait=25", tag="sha256:" + "0" * 64)
    assert response.status_code == 200
    assert rig.app.allowlist_waiters == 0


@pytest.mark.parametrize(
    ("query", "reason"),
    [
        ("?wait=x", "wait must be a number of seconds"),
        ("?other=1", "the allowlist path takes one parameter, wait"),
        ("?wait=1&wait=2", "the allowlist path takes one parameter, wait"),
    ],
)
async def test_a_bad_query_is_400(rig: Rig, captured: io.StringIO, query: str, reason: str) -> None:
    response = await rig.fetch(query)
    assert response.status_code == 400
    assert response.headers[REFUSAL_HEADER] == REFUSAL_MARKER
    [line] = lines(captured, "request")
    assert line["reason"] == reason
    # Not a fetch: an onboarding through the role doesn't wait for it.
    started = time.monotonic()
    assert await rig.app.role_fetched(5) is False
    assert time.monotonic() - started < 1


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE"])
async def test_only_get(rig: Rig, captured: io.StringIO, method: str) -> None:
    response = await rig.call(method=method, headers=key())
    assert response.status_code == 405
    assert response.headers["allow"] == "GET"
    [line] = lines(captured, "request")
    assert (line["caller"], line["reason"]) == ("egress", "the allowlist path takes GET only")


# --- who may ask (G.3, X21) -----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("listener", "headers", "reason"),
    [
        ("tcp", {}, "the allowlist path is for the egress role only"),
        (None, {}, "the allowlist path is for the egress role only"),
        (
            "tcp",
            {"Authorization": f"Bearer {PH}"},
            "the allowlist path is for the egress role only",
        ),
        ("tcp", {EGRESS_HEADER: "zeg1-wrong"}, "egress key refused"),
        ("tcp", {EGRESS_HEADER: KEYS.egress_key(2)}, "egress key refused"),
        ("tcp", {EGRESS_HEADER: KEYS.gateway_key(1)}, "egress key refused"),
        ("tcp", [(EGRESS_HEADER, KEYS.egress_key(1))] * 2, "egress key refused"),
        # The gateway's key is the gateway's, and never reaches the allowlists.
        (
            "tcp",
            {GATEWAY_HEADER: KEYS.gateway_key(1)},
            "the allowlist path is for the egress role only",
        ),
        (
            "tcp",
            {GATEWAY_HEADER: KEYS.gateway_key(1), EGRESS_HEADER: KEYS.egress_key(1)},
            "two identities presented",
        ),
        # The link socket's caller is the gateway: the role's key isn't read there.
        ("gateway", key(), "the allowlist path isn't served on the gateway's link"),
        ("gateway", {}, "the allowlist path isn't served on the gateway's link"),
    ],
)
async def test_anyone_else_gets_the_bare_403(
    rig: Rig,
    captured: io.StringIO,
    listener: str | None,
    headers: dict[str, str] | list[tuple[str, str]],
    reason: str,
) -> None:
    response = await rig.call(listener=listener, headers=headers)
    assert response.status_code == 403
    assert response.json() == {"error": "forbidden"}
    assert response.headers.get_list(REFUSAL_HEADER) == [REFUSAL_MARKER]
    assert "etag" not in response.headers
    [line] = lines(captured, "request")
    assert line["reason"] == reason
    assert line["endpoint"] == "egress_allowlists"
    assert lines(captured, "egress_allowlist_served") == []
    # A request with an egress key over TCP is a role asking, admitted or not: health measures
    # it (COV-7). Nothing else is.
    asked = listener == "tcp" and EGRESS_HEADER in dict(headers)
    assert (rig.app.allowlist_fetched_ago() is not None) is asked


async def test_a_role_whose_key_is_refused_from_the_start_goes_stale(
    rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A role given a wrong key, or kept on the old one across a restart after a bump, is
    never admitted: health measures it from its first request, so after 300 s it warns
    (COV-7). An onboarding through it doesn't wait for a role never admitted (I.3)."""
    first = time.monotonic()
    assert (await rig.call(headers=key(2))).status_code == 403
    assert (await rig.call(headers=key(2))).status_code == 403
    started = time.monotonic()
    assert await rig.app.role_fetched(5) is False
    assert time.monotonic() - started < 1
    later = SimpleNamespace(monotonic=lambda: first + 301)
    monkeypatch.setattr(vault_app, "time", later)
    ago = rig.app.allowlist_fetched_ago()
    assert ago is not None
    assert 300 < ago <= 301
    inputs = health.Inputs(policy=rig.app.policy, entries=(), env_names=(), egress_fetched_ago=ago)
    assert [f["code"] for f in health.assess(inputs)["egress"]["findings"]] == [
        "egress_allowlist_stale"
    ]
    monkeypatch.undo()
    # Admitted at last: measured from that fetch.
    assert (await rig.fetch()).status_code == 200
    fetched = rig.app.allowlist_fetched_ago()
    assert fetched is not None
    assert fetched < 5


def stale(app: VaultApp) -> list[str]:
    """The egress section's finding codes, as health reports them from the app's measure."""
    inputs = health.Inputs(
        policy=app.policy, entries=(), env_names=(), egress_fetched_ago=app.allowlist_fetched_ago()
    )
    return [f["code"] for f in health.assess(inputs)["egress"]["findings"]]


async def test_a_role_the_policy_names_that_never_shows_up_goes_stale(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With egress_proxy_kind role the role is expected: until a request with an egress key
    arrives, health measures from the vault's start, so a role that never showed up warns
    after 300 s (COV-7). Once it fetches, its fetch is the measure, as for any role."""
    policy = make_policy(egress_proxy="http://egress-vault:3128", egress_proxy_kind="role")
    r = Rig(tmp_path, policy)
    start = time.monotonic()
    ago = r.app.allowlist_fetched_ago()
    assert ago is not None
    assert ago < 5
    assert stale(r.app) == []
    monkeypatch.setattr(vault_app, "time", SimpleNamespace(monotonic=lambda: start + 301))
    ago = r.app.allowlist_fetched_ago()
    assert ago is not None
    assert 300 < ago <= 302
    assert stale(r.app) == ["egress_allowlist_stale"]
    monkeypatch.undo()
    assert (await r.fetch()).status_code == 200
    fetched = r.app.allowlist_fetched_ago()
    assert fetched is not None
    assert fetched < 5
    assert stale(r.app) == []
    await r.app.aclose()


@pytest.mark.parametrize(
    "more",
    [
        {},
        {"egress_proxy": "http://proxy.stack.example:3128"},
        {"egress_proxy": "http://proxy.stack.example:3128", "egress_proxy_kind": "own"},
    ],
)
async def test_without_the_role_named_a_silent_vault_has_no_stale_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, more: dict[str, str]
) -> None:
    """With an operator's own proxy, or none, no role is expected: a vault no role has asked
    has nothing to measure however long it runs. A role that does fetch (one serving bridges,
    say) is measured all the same, whatever the kind."""
    r = Rig(tmp_path, make_policy(**more))
    start = time.monotonic()
    monkeypatch.setattr(vault_app, "time", SimpleNamespace(monotonic=lambda: start + 3600))
    assert r.app.allowlist_fetched_ago() is None
    assert stale(r.app) == []
    monkeypatch.undo()
    assert (await r.fetch()).status_code == 200
    fetched_at = time.monotonic()
    monkeypatch.setattr(vault_app, "time", SimpleNamespace(monotonic=lambda: fetched_at + 301))
    assert stale(r.app) == ["egress_allowlist_stale"]
    monkeypatch.undo()
    await r.app.aclose()


@pytest.mark.parametrize(
    ("path", "method", "reason"),
    [
        ("/_zoeymcp/gateway/v1/view", "GET", "the view is for the gateway only"),
        ("/_zoeymcp/gateway/v1/report/ledger", "GET", "the report path is for the gateway only"),
        (
            "/_zoeymcp/gateway/v1/review/jobs?view=sha256:" + "a" * 64,
            "GET",
            "the review jobs path is for the gateway only",
        ),
        (
            "/_zoeymcp/gateway/v1/report/review",
            "POST",
            "the review report path is for the gateway only",
        ),
        # A route takes its callers' identities, which the egress key isn't.
        ("/notes/v1/x", "GET", "no accepted identity presented"),
    ],
)
async def test_the_egress_key_reaches_nothing_else(
    rig: Rig, captured: io.StringIO, path: str, method: str, reason: str
) -> None:
    response = await rig.call(path, method=method, headers=key())
    assert response.status_code == 403
    [line] = lines(captured, "request")
    assert line["reason"] == reason


async def test_a_new_generation_retires_the_old_key_at_once(rig: Rig) -> None:
    """No ratchet (G.3, Q21): after a bump only the new key reads the lists."""
    assert (await rig.fetch()).status_code == 200
    rig.app.reload(make_policy(generation=2))
    assert (await rig.call(headers=key(1))).status_code == 403
    assert (await rig.call(headers=key(2))).status_code == 200


async def test_with_the_link_set_the_role_still_reads_over_tcp(tmp_path: Path) -> None:
    """The link refuses gateway keys on TCP; the egress key isn't one."""
    r = Rig(tmp_path, make_policy(), gateway_link=True)
    assert (await r.call(headers=key())).status_code == 200
    await r.app.aclose()


# --- the long poll --------------------------------------------------------------------------------


async def test_a_wait_ends_with_304(rig: Rig) -> None:
    started = time.monotonic()
    task = asyncio.create_task(rig.fetch("?wait=1", tag=rig.digest()))
    await until(lambda: rig.app.allowlist_waiters == 1, "the request never waited")
    response = await asyncio.wait_for(task, 5)
    assert time.monotonic() - started >= 0.95
    assert response.status_code == 304
    assert rig.app.allowlist_waiters == 0


async def test_an_allowance_wakes_the_wait(rig: Rig, captured: io.StringIO) -> None:
    before = rig.digest()
    task = asyncio.create_task(rig.fetch("?wait=25", tag=before))
    await until(lambda: rig.app.allowlist_waiters == 1, "the request never waited")
    rig.allowances.append(allowance(("mcp.newco.example", 443)))
    rig.app.lists_changed()
    response = await asyncio.wait_for(task, 2)
    assert response.status_code == 200
    assert response.headers["etag"] != f'"{before}"'
    hosts = [d["host"] for d in response.json()["sources"]["vault"]]
    assert hosts == ["api.notes.example", "mcp.newco.example"]
    [served] = lines(captured, "egress_allowlist_served")
    assert served["digest"] == rig.digest()


async def test_a_reload_wakes_the_wait(rig: Rig) -> None:
    task = asyncio.create_task(rig.fetch("?wait=25", tag=rig.digest()))
    await until(lambda: rig.app.allowlist_waiters == 1, "the request never waited")
    rig.app.reload(make_policy(upstream="https://api2.notes.example/v1"))
    response = await asyncio.wait_for(task, 2)
    assert response.status_code == 200
    assert response.json()["sources"]["vault"][0]["host"] == "api2.notes.example"


async def test_a_change_the_lists_dont_see_keeps_waiting(rig: Rig) -> None:
    """GR-20: a rule, a placeholder or a wake with nothing new answers nothing."""
    before = rig.digest()
    task = asyncio.create_task(rig.fetch("?wait=25", tag=before))
    await until(lambda: rig.app.allowlist_waiters == 1, "the request never waited")
    raw = raw_policy()
    raw["routes"][0]["rules"][0]["methods"] = ["GET", "POST"]
    rig.app.reload(Policy.model_validate(raw))
    rig.app.lists_changed()
    assert rig.digest() == before
    await asyncio.sleep(0.2)
    assert not task.done()
    rig.app.stop_view_waits()
    assert (await asyncio.wait_for(task, 2)).status_code == 304


async def test_a_third_waiter_gets_429(rig: Rig, captured: io.StringIO) -> None:
    waits = [
        asyncio.create_task(rig.fetch("?wait=25", tag=rig.digest()))
        for _ in range(ALLOWLIST_WAITERS)
    ]
    await until(lambda: rig.app.allowlist_waiters == 2, "two never waited")
    response = await rig.fetch("?wait=25", tag=rig.digest())
    assert response.status_code == 429
    assert response.headers["retry-after"] == "1"
    refused = [line for line in lines(captured, "request") if line["status"] == 429]
    assert [x["reason"] for x in refused] == ["too many allowlist waiters"]
    # The view's waiters are counted apart.
    assert rig.app.view_waiters == 0
    rig.app.stop_view_waits()
    answers = await asyncio.wait_for(asyncio.gather(*waits), 2)
    assert [a.status_code for a in answers] == [304] * 2
    assert rig.app.allowlist_waiters == 0


async def test_a_cancelled_wait_frees_its_place(rig: Rig) -> None:
    task = asyncio.create_task(rig.fetch("?wait=25", tag=rig.digest()))
    await until(lambda: rig.app.allowlist_waiters == 1, "the request never waited")
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert rig.app.allowlist_waiters == 0


# --- onboarding allowances (I.3) ------------------------------------------------------------------


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


async def test_allowances_appear_widen_and_expire(tmp_path: Path) -> None:
    """An onboarding's hosts reach the role's list as discovery learns them, never private
    even where egress_private lists them (TI-10), and leave it when it expires."""
    clock = Clock()
    table = OnboardingTable(clock)
    r = Rig(tmp_path, make_policy(egress_private=["auth.newco.example:443"]))
    r.app.use_allowances(table.allowances)

    def vault() -> list[tuple[str, int, bool]]:
        document = r.app.allowlist_document()
        return [(d["host"], d["port"], d["private"]) for d in document["sources"]["vault"]]

    base = vault()
    assert base == [("api.notes.example", 443, False)]
    record = table.start("cli", SERVER, Names("newco", "newco", "newco"), Options()).record
    assert vault() == [*base, ("mcp.newco.example", 443, False)]
    table.widen(record.id, "cli", [("auth.newco.example", 443)])
    widened = await r.fetch()
    assert [d["host"] for d in widened.json()["sources"]["vault"]] == [
        "api.notes.example",
        "auth.newco.example",
        "mcp.newco.example",
    ]
    assert all(not d["private"] for d in widened.json()["sources"]["vault"])
    # Expired: gone from the next answer, with nothing else changed.
    clock.now += ONBOARDING_TTL
    after = await r.fetch(tag=widened.headers["etag"].strip('"'))
    assert after.status_code == 200
    assert vault() == base
    assert after.json() == egresslist.document(egresslist.derive(r.app.policy))
    await r.app.aclose()


async def test_an_expiry_answers_a_waiting_poll(tmp_path: Path) -> None:
    """An expiry sets no event: a waiting poll looks again when the next allowance expires,
    so the role drops its hosts then rather than at its next poll (G.2, I.3)."""
    shift = [0.0]
    table = OnboardingTable(lambda: time.monotonic() + shift[0])
    r = Rig(tmp_path, make_policy())
    r.app.use_allowances(table.allowances, table.allowances_expire_in)
    table.start("cli", SERVER, Names("newco", "newco", "newco"), Options())
    due = table.allowances_expire_in()
    assert due is not None
    assert ONBOARDING_TTL - 5 < due <= ONBOARDING_TTL
    # Its expiry 0.3 s away.
    shift[0] = ONBOARDING_TTL - 0.3
    held = r.digest()
    started = time.monotonic()
    response = await asyncio.wait_for(r.fetch("?wait=25", tag=held), 5)
    assert 0.25 <= time.monotonic() - started < 5
    assert response.status_code == 200
    assert response.json() == egresslist.document(egresslist.derive(r.app.policy))
    assert table.allowances_expire_in() is None
    await r.app.aclose()


# --- the role holding the lists (I.3) -------------------------------------------------------------


async def test_without_a_role_nothing_waits(rig: Rig) -> None:
    started = time.monotonic()
    assert await rig.app.role_fetched(5) is False
    assert time.monotonic() - started < 1


async def test_the_role_holds_the_lists_once_it_names_their_digest(rig: Rig) -> None:
    """The vault learns what the role holds from its next poll's If-None-Match, which the
    role sends once it has applied a 200 (I.3)."""
    first = await rig.fetch()
    held = first.headers["etag"].strip('"')
    # A first poll names nothing: the role isn't known to hold the lists yet.
    assert await rig.app.role_fetched(0) is False
    assert (await rig.fetch(tag=held)).status_code == 304
    assert await rig.app.role_fetched(0) is True
    # Widened: the waiting poll is woken and answered, and once the role polls again naming
    # the new digest, the wait ends.
    poll = asyncio.create_task(rig.fetch("?wait=25", tag=held))
    await until(lambda: rig.app.allowlist_waiters == 1, "the role never waited")
    rig.allowances.append(allowance(("mcp.newco.example", 443)))
    waiting = asyncio.create_task(rig.app.role_fetched(5))
    answered = await asyncio.wait_for(poll, 2)
    assert answered.status_code == 200
    assert not waiting.done()
    again = asyncio.create_task(rig.fetch("?wait=25", tag=answered.headers["etag"].strip('"')))
    assert await asyncio.wait_for(waiting, 2) is True
    rig.app.stop_view_waits()
    await asyncio.wait_for(again, 2)


async def test_a_role_that_doesnt_fetch_in_time_is_waited_for_no_longer(rig: Rig) -> None:
    held = (await rig.fetch()).headers["etag"].strip('"')
    assert (await rig.fetch(tag=held)).status_code == 304
    rig.allowances.append(allowance(("mcp.newco.example", 443)))
    started = time.monotonic()
    assert await rig.app.role_fetched(0.3) is False
    assert 0.25 <= time.monotonic() - started < 2


async def test_stopping_ends_the_wait_for_the_role(rig: Rig) -> None:
    held = (await rig.fetch()).headers["etag"].strip('"')
    assert (await rig.fetch(tag=held)).status_code == 304
    rig.allowances.append(allowance(("mcp.newco.example", 443)))
    waiting = asyncio.create_task(rig.app.role_fetched(25))
    await asyncio.sleep(0.05)
    rig.app.stop_view_waits()
    assert await asyncio.wait_for(waiting, 2) is False
