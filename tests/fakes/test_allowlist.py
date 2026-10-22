"""Self-test of the allowlist fake (M7 design O.1, BP-7): the key, the document and its ETag,
the long poll's 304 and its wake on publish, a broken body, the ``down`` switch and the clock."""

from __future__ import annotations

import asyncio
import json

import anyio
import httpx
import pytest

from tests.fakes.allowlist import KEY, PATH, AllowlistFake, Clock, document, serve_allowlist
from zoeymcp.common import egresslist

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def keyed(key: str = KEY, **headers: str) -> dict[str, str]:
    return {"x-zoeymcp-egress": key, **headers}


async def test_the_key_the_document_and_its_etag() -> None:
    fake = AllowlistFake()
    async with serve_allowlist(fake) as url, httpx.AsyncClient(base_url=url) as client:
        with anyio.fail_after(10):
            before = await client.get(PATH, headers=keyed())
            digest = fake.publish({"vault": [("auth.example", 443), ("lan.example", 80, True)]})
            wrong = await client.get(PATH, headers=keyed("zeg1-" + "x" * 43))
            missing = await client.get(PATH)
            other = await client.get("/_zoeymcp/gateway/v1/view", headers=keyed())
            posted = await client.post(PATH, headers=keyed())
            got = await client.get(PATH, headers=keyed())
    assert before.status_code == 503
    assert [wrong.status_code, missing.status_code] == [403, 403]
    assert wrong.content == missing.content == b""
    assert [other.status_code, posted.status_code] == [404, 405]
    assert got.status_code == 200
    assert got.headers["etag"] == f'"{digest}"'
    body = got.json()
    assert body == document({"vault": [("lan.example", 80, True), ("auth.example", 443)]})
    assert body["sources"] == {
        "vault": [
            {"host": "auth.example", "port": 443, "private": False},
            {"host": "lan.example", "port": 80, "private": True},
        ]
    }
    lists = {
        "vault": (
            egresslist.Destination("auth.example", 443, False, frozenset({"token"})),
            egresslist.Destination("lan.example", 80, True, frozenset({"route"})),
        )
    }
    assert digest == egresslist.digest(lists)
    assert [s.key for s in fake.seen] == [KEY, "zeg1-" + "x" * 43, None, KEY, KEY, KEY]


async def test_a_long_poll_answers_304_or_wakes_on_publish() -> None:
    fake = AllowlistFake(max_wait=0.05)
    digest = fake.publish({"vault": [("auth.example", 443)]})
    async with serve_allowlist(fake) as url, httpx.AsyncClient(base_url=url) as client:
        with anyio.fail_after(10):
            current = keyed(**{"if-none-match": f'"{digest}"'})
            unchanged = await client.get(PATH, params={"wait": "25"}, headers=current)
            no_wait = await client.get(PATH, headers=current)
            fake.max_wait = 25.0
            waiting = asyncio.create_task(client.get(PATH, params={"wait": "25"}, headers=current))
            while len(fake.seen) < 3:
                await asyncio.sleep(0.01)
            newer = fake.publish({"vault": [("auth.example", 443), ("mcp.example", 443)]})
            woken = await waiting
    assert unchanged.status_code == 304
    assert unchanged.content == b""
    assert no_wait.status_code == 304  # no wait asked: at once
    assert woken.status_code == 200
    assert woken.json()["digest"] == newer != digest
    assert fake.seen[0].query == {"wait": "25"}
    assert fake.seen[0].if_none_match == f'"{digest}"'


async def test_a_raw_body_and_the_down_switch() -> None:
    fake = AllowlistFake()
    fake.publish_raw(b"{not json", "sha256:" + "0" * 64)
    async with serve_allowlist(fake) as url, httpx.AsyncClient(base_url=url) as client:
        with anyio.fail_after(10):
            broken = await client.get(PATH, headers=keyed())
            digest = fake.publish({"vault": []})
            waiting = asyncio.create_task(
                client.get(
                    PATH, params={"wait": "25"}, headers=keyed(**{"if-none-match": f'"{digest}"'})
                )
            )
            while len(fake.seen) < 2:
                await asyncio.sleep(0.01)
            fake.set_down(True)
            with pytest.raises(httpx.TransportError):
                await waiting  # dropped
            with pytest.raises(httpx.TransportError):
                await client.get(PATH, headers=keyed())
            fake.set_down(False)
            back = await client.get(PATH, headers=keyed())
    assert broken.content == b"{not json"
    assert json.loads(back.content)["sources"] == {"vault": []}


async def test_the_clock_moves_only_when_told() -> None:
    clock = Clock()
    start = clock()
    clock.advance(300.5)
    assert clock() == start + 300.5
