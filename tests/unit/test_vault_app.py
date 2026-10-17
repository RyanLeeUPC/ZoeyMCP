"""Effect tests for the vault's proxy: what reaches the upstream, and what never does.

The upstream is the echo provider, in process, so each test can assert exactly which method,
path, query, headers and credential arrived, or that nothing arrived at all.
"""

from __future__ import annotations

import base64
import io
import json
import socket
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from tests.fakes.echo import EchoProvider, Received
from tests.fakes.harness import serve
from zoeymcp.common.policy import Policy
from zoeymcp.vault import logs
from zoeymcp.vault.app import GATEWAY_HEADER, VaultApp
from zoeymcp.vault.keys import KeySet
from zoeymcp.vault.store import SecretStore, origin_binding

KEYS = KeySet.from_master(bytes(range(32)))
AGENT = "172.30.4.10"
PH = "ph-agent1-direct-0001"
SECRET = "sk-live-8f3c2a91d7e4"

BASE: dict[str, Any] = {
    "version": 1,
    "mode": "declarative",
    "admin": {"listen": "0.0.0.0:8081", "hosts": ["localhost"]},
}


def policy(routes: list[dict[str, Any]], credentials: dict[str, Any] | None = None) -> Policy:
    return Policy.model_validate({**BASE, "routes": routes, "credentials": credentials or {}})


def api_route(**overrides: Any) -> dict[str, Any]:
    route: dict[str, Any] = {
        "name": "api",
        "prefix": "/api",
        "upstream": "https://api.example/base",
        "credential": "api-key",
        "callers": [{"placeholder": PH}],
        "rules": [{"methods": ["GET", "POST"], "paths": ["/v1/**"]}],
    }
    route.update(overrides)
    return route


HEADER_CRED = {"api-key": {"kind": "header", "secret": "store:api-key"}}


class Rig:
    def __init__(self, tmp_path: Path, pol: Policy, environ: dict[str, str] | None = None) -> None:
        self.echo = EchoProvider()
        self.store = SecretStore(tmp_path, KEYS)
        self.store.load()
        upstream = httpx.AsyncClient(transport=httpx.ASGITransport(app=self.echo.app()))
        self.app = VaultApp(pol, self.store, KEYS, client=upstream, environ=environ or {})

    def put(self, name: str, value: str, origins: list[str]) -> None:
        self.store.put(name, value, origin_binding(origins))

    async def call(
        self,
        method: str,
        path: str,
        *,
        source: str = AGENT,
        headers: dict[str, str] | None = None,
        content: bytes = b"",
    ) -> httpx.Response:
        transport = httpx.ASGITransport(app=self.app, client=(source, 40000))
        async with httpx.AsyncClient(transport=transport, base_url="http://vault") as client:
            return await client.request(method, path, headers=headers, content=content)

    @property
    def last(self) -> Received:
        return self.echo.received[-1]


def bearer(token: str = PH) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
async def rig(tmp_path: Path) -> AsyncIterator[Rig]:
    r = Rig(tmp_path, policy([api_route()], HEADER_CRED))
    r.put("api-key", SECRET, ["https://api.example"])
    yield r
    await r.app.aclose()


pytestmark = pytest.mark.anyio


# --- the happy path ----------------------------------------------------------------------------


async def test_forwards_with_the_credential(rig: Rig) -> None:
    response = await rig.call("POST", "/api/v1/things?x=1", headers=bearer(), content=b"{}")
    assert response.status_code == 200
    assert rig.last.method == "POST"
    assert rig.last.path == "/base/v1/things"
    assert rig.last.query == [("x", "1")]
    assert rig.last.body == b"{}"
    assert rig.last.header("authorization") == f"Bearer {SECRET}"
    assert rig.last.header("accept-encoding") == "identity"


async def test_the_echoed_credential_is_scrubbed(rig: Rig) -> None:
    response = await rig.call("GET", "/api/v1/echo", headers=bearer())
    assert SECRET not in response.text
    assert "[REDACTED]" in response.text


async def test_the_placeholder_never_reaches_upstream(rig: Rig) -> None:
    await rig.call("GET", "/api/v1/x", headers={**bearer(), "X-Other": PH})
    sent = json.dumps(rig.last.headers)
    assert sent.count(PH) == 1  # only the unrelated header the caller chose to send
    assert rig.last.header("authorization") == f"Bearer {SECRET}"


async def test_log_contents(tmp_path: Path) -> None:
    buffer = io.StringIO()
    logs.set_stream(buffer)
    try:
        r = Rig(tmp_path, policy([api_route()], HEADER_CRED))
        r.put("api-key", SECRET, ["https://api.example"])
        await r.call("GET", "/api/v1/x?q=private-value", headers=bearer())
        await r.call("GET", "/api/v1/x", headers=bearer("wrong-placeholder-0000"))
        await r.app.aclose()
    finally:
        logs.set_stream(None)
    text = buffer.getvalue()
    for forbidden in (SECRET, PH, "private-value", "wrong-placeholder-0000"):
        assert forbidden not in text
    ok, refused = (json.loads(line) for line in text.splitlines())
    assert ok["status"] == 200
    assert ok["caller"] == "callers[0]"
    assert ok["credential"] == "api-key"
    assert refused["status"] == 403
    assert refused["reason"] == "no accepted identity presented"


# --- identity ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": "Bearer wrong-placeholder-0000"},
        {"Authorization": f"Basic {PH}"},
        {"Authorization": PH},
        {"X-ZoeyMCP-Gateway": KEYS.gateway_key(1)},  # route doesn't accept the gateway
    ],
)
async def test_identity_refusals_reach_nothing(rig: Rig, headers: dict[str, str]) -> None:
    response = await rig.call("GET", "/api/v1/x", headers=headers)
    assert response.status_code == 403
    assert response.json() == {"error": "forbidden"}
    assert rig.echo.received == []


async def test_source_pins(tmp_path: Path) -> None:
    pinned = api_route(callers=[{"placeholder": PH, "sources": ["172.30.4.0/24"]}])
    r = Rig(tmp_path, policy([pinned], HEADER_CRED))
    r.put("api-key", SECRET, ["https://api.example"])
    assert (
        await r.call("GET", "/api/v1/x", headers=bearer(), source="172.30.4.99")
    ).status_code == 200
    assert (
        await r.call("GET", "/api/v1/x", headers=bearer(), source="10.0.0.5")
    ).status_code == 403
    assert len(r.echo.received) == 1


async def test_gateway_identity(tmp_path: Path) -> None:
    route = api_route(callers=["gateway"])
    r = Rig(tmp_path, policy([route], HEADER_CRED))
    r.put("api-key", SECRET, ["https://api.example"])
    good = await r.call("GET", "/api/v1/x", headers={GATEWAY_HEADER: KEYS.gateway_key(1)})
    assert good.status_code == 200
    assert r.last.header(GATEWAY_HEADER) is None  # internal header never forwarded
    for key in (KEYS.gateway_key(2), KEYS.gateway_key(1)[:-1] + "A", "zgw1-nope"):
        bad = await r.call("GET", "/api/v1/x", headers={GATEWAY_HEADER: key})
        assert bad.status_code == 403
    assert (await r.call("GET", "/api/v1/x", headers=bearer())).status_code == 403
    assert len(r.echo.received) == 1


async def test_placeholder_in_header_or_query(tmp_path: Path) -> None:
    routes = [
        api_route(callers=[{"placeholder": PH, "header": "X-Api-Key"}]),
        api_route(name="q", prefix="/q", callers=[{"placeholder": PH, "query": "api_key"}]),
    ]
    r = Rig(tmp_path, policy(routes, HEADER_CRED))
    r.put("api-key", SECRET, ["https://api.example"])
    assert (await r.call("GET", "/api/v1/x", headers={"X-Api-Key": PH})).status_code == 200
    assert r.last.header("x-api-key") is None
    assert (await r.call("GET", f"/q/v1/x?api_key={PH}&m=1")).status_code == 200
    assert r.last.query == [("m", "1")]
    assert (await r.call("GET", f"/q/v1/x?api_key={PH}&api_key={PH}")).status_code == 403


# --- rules -------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("method", "path", "status"),
    [
        ("GET", "/api/v1/x", 200),
        ("DELETE", "/api/v1/x", 403),
        ("GET", "/api/v2/x", 403),
        ("GET", "/api/v1/a%2Fb", 400),
        ("GET", "/api/v1/a%252Fb", 400),
        ("GET", "/nothing/v1/x", 404),
        ("GET", "/", 404),
    ],
)
async def test_rules(rig: Rig, method: str, path: str, status: int) -> None:
    response = await rig.call(method, path, headers=bearer())
    assert response.status_code == status
    assert len(rig.echo.received) == (1 if status == 200 else 0)


async def test_query_policy_applied(tmp_path: Path) -> None:
    route = api_route(
        credential="lfm",
        query={"force": {"user": "alice"}, "strip": ["format"]},
    )
    creds = {"lfm": {"kind": "query", "param": "api_key", "secret": "store:lfm"}}
    r = Rig(tmp_path, policy([route], creds))
    r.put("lfm", SECRET, ["https://api.example"])
    response = await r.call(
        "GET", "/api/v1/?method=m&user=mallory&format=xml&api_key=guess", headers=bearer()
    )
    assert response.status_code == 200
    assert r.last.query == [("method", "m"), ("user", "alice"), ("api_key", SECRET)]
    assert SECRET not in response.text


async def test_query_allow_list(tmp_path: Path) -> None:
    route = api_route(query={"allow": ["page"]})
    r = Rig(tmp_path, policy([route], HEADER_CRED))
    r.put("api-key", SECRET, ["https://api.example"])
    assert (await r.call("GET", "/api/v1/x?page=2", headers=bearer())).status_code == 200
    assert (await r.call("GET", "/api/v1/x?other=1", headers=bearer())).status_code == 403
    assert len(r.echo.received) == 1


# --- credential kinds --------------------------------------------------------------------------


async def test_path_credential(tmp_path: Path) -> None:
    route = api_route(
        upstream="https://bot.example",
        credential="bot",
        rules=[{"methods": ["GET"], "paths": ["/getMe"]}],
    )
    creds = {"bot": {"kind": "path", "template": "/bot{secret}", "secret": "store:bot"}}
    r = Rig(tmp_path, policy([route], creds))
    r.put("bot", "123:ABC-def", ["https://bot.example"])
    response = await r.call("GET", "/api/getMe", headers=bearer())
    assert response.status_code == 200
    assert r.last.path == "/bot123:ABC-def/getMe"
    assert "123:ABC-def" not in response.text


async def test_basic_credential(tmp_path: Path) -> None:
    creds = {"jira": {"kind": "basic", "username": "bot@example.com", "secret": "store:jira"}}
    r = Rig(tmp_path, policy([api_route(credential="jira")], creds))
    r.put("jira", SECRET, ["https://api.example"])
    response = await r.call("GET", "/api/v1/x", headers=bearer())
    expected = base64.b64encode(f"bot@example.com:{SECRET}".encode()).decode()
    assert r.last.header("authorization") == f"Basic {expected}"
    assert expected not in response.text


async def test_env_credential_is_snapshotted(tmp_path: Path) -> None:
    creds = {"api-key": {"kind": "header", "secret": "env:API_KEY"}}
    environ = {"API_KEY": SECRET}
    r = Rig(tmp_path, policy([api_route()], creds), environ=environ)
    environ["API_KEY"] = "changed-later"
    await r.call("GET", "/api/v1/x", headers=bearer())
    assert r.last.header("authorization") == f"Bearer {SECRET}"


async def test_binding_blocks_a_redirected_upstream(tmp_path: Path) -> None:
    r = Rig(tmp_path, policy([api_route(upstream="https://evil.example")], HEADER_CRED))
    r.put("api-key", SECRET, ["https://api.example"])
    response = await r.call("GET", "/api/v1/x", headers=bearer())
    assert response.status_code == 502
    assert response.json() == {"error": "upstream unavailable"}
    assert r.echo.received == []


async def test_missing_secret(tmp_path: Path) -> None:
    r = Rig(tmp_path, policy([api_route()], HEADER_CRED))
    assert (await r.call("GET", "/api/v1/x", headers=bearer())).status_code == 502
    assert r.echo.received == []


async def test_unauthenticated_upstream(tmp_path: Path) -> None:
    route = api_route(credential=None)
    r = Rig(tmp_path, policy([route]))
    assert (await r.call("GET", "/api/v1/x", headers=bearer())).status_code == 200
    assert r.last.header("authorization") is None


async def test_oauth_and_connectors_not_yet(tmp_path: Path) -> None:
    creds = {
        "o": {
            "kind": "oauth2",
            "token_url": "https://t.example/token",
            "client_id": "c",
            "refresh_token": "store:o",
        }
    }
    r = Rig(tmp_path, policy([api_route(credential="o")], creds))
    assert (await r.call("GET", "/api/v1/x", headers=bearer())).status_code == 501
    assert r.echo.received == []


# --- headers and bodies ------------------------------------------------------------------------


async def test_caller_headers_filtered(rig: Rig) -> None:
    await rig.call(
        "GET",
        "/api/v1/x",
        headers={**bearer(), "Cookie": "c=1", "X-Forwarded-For": "1.2.3.4", "X-Keep": "yes"},
    )
    assert rig.last.header("cookie") is None
    assert rig.last.header("x-forwarded-for") is None
    assert rig.last.header("x-keep") == "yes"


async def test_request_size_limit(rig: Rig) -> None:
    big = b"x" * (10 * 1024 * 1024 + 1)
    response = await rig.call("POST", "/api/v1/x", headers=bearer(), content=big)
    assert response.status_code == 413
    assert rig.echo.received == []


# --- real sockets ------------------------------------------------------------------------------


def _raw_request(base: str, target: bytes) -> int:
    host, port = base.removeprefix("http://").split(":")
    with socket.create_connection((host, int(port)), timeout=5) as sock:
        sock.sendall(
            b"GET "
            + target
            + b" HTTP/1.1\r\nHost: v\r\nAuthorization: Bearer "
            + PH.encode()
            + b"\r\nConnection: close\r\n\r\n"
        )
        status_line = sock.recv(64)
    return int(status_line.split()[1])


async def test_raw_dot_segments_over_a_socket(tmp_path: Path) -> None:
    r = Rig(tmp_path, policy([api_route()], HEADER_CRED))
    r.put("api-key", SECRET, ["https://api.example"])
    with serve(r.app) as base:
        assert _raw_request(base, b"/api/v1/ok") == 200
        assert _raw_request(base, b"/api/v1/../../admin") == 400
        assert _raw_request(base, b"/api/v1/%2e%2e/x") == 400
        assert _raw_request(base, b"/api/v1//x") == 400
    assert [x.path for x in r.echo.received] == ["/base/v1/ok"]


async def test_streaming_route_relays_sse(tmp_path: Path) -> None:
    echo = EchoProvider(sse_delay=0.05)
    with serve(echo.app()) as upstream_base:
        route = api_route(
            upstream=upstream_base,
            credential=None,
            stream=True,
            allow_insecure_upstream=True,
            rules=[{"methods": ["GET"], "paths": ["/sse"]}],
        )
        store = SecretStore(tmp_path, KEYS)
        store.load()
        app = VaultApp(policy([route]), store, KEYS, environ={})
        with serve(app) as vault_base:
            async with (
                httpx.AsyncClient() as client,
                client.stream("GET", f"{vault_base}/api/sse?n=3", headers=bearer()) as response,
            ):
                assert response.status_code == 200
                events = [line async for line in response.aiter_lines() if line.startswith("data:")]
        # The app ran on the server thread's loop; its connections closed with that loop.
    assert events == ["data: event 0", "data: event 1", "data: event 2"]
