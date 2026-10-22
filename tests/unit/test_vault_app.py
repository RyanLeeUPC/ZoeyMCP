"""Effect tests for the vault's proxy: what reaches the upstream, and what never does.

The upstream is the echo provider, in process, so each test can assert exactly which method,
path, query, headers and credential arrived, or that nothing arrived at all.
"""

from __future__ import annotations

import asyncio
import base64
import io
import json
import socket
from collections.abc import AsyncIterator, Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any
from urllib.parse import quote_plus

import httpx
import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from tests.fakes.echo import EchoProvider, Received
from tests.fakes.harness import serve
from tests.fakes.oauth_server import FakeAuthServer, google_style, spotify_style
from zoeymcp.common.policy import Policy
from zoeymcp.vault import logs
from zoeymcp.vault.app import GATEWAY_HEADER, VaultApp
from zoeymcp.vault.bindings import oauth_binding
from zoeymcp.vault.keys import KeySet
from zoeymcp.vault.oauth.protocol import MIN_401_AGE, OAUTH_MISCONFIGURED, OAUTH_UNAVAILABLE
from zoeymcp.vault.oauth.tokens import Grant, OAuthUnavailable, TokenManager
from zoeymcp.vault.request import oauth_basic_credentials, secret_variants
from zoeymcp.vault.store import Secret, SecretStore, origin_binding

KEYS = KeySet.from_master(bytes(range(32)))
AGENT = "172.30.4.10"
PH = "ph-agent1-direct-0001"
SECRET = "sk-live-8f3c2a91d7e4"

BASE: dict[str, Any] = {
    "version": 1,
    "mode": "declarative",
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
    assert response.json() == {"error": "upstream unavailable", "code": "credential_unavailable"}
    assert "retry-after" not in response.headers
    assert r.echo.received == []


async def test_missing_secret(tmp_path: Path) -> None:
    r = Rig(tmp_path, policy([api_route()], HEADER_CRED))
    response = await r.call("GET", "/api/v1/x", headers=bearer())
    assert response.status_code == 502
    assert response.json() == {"error": "upstream unavailable", "code": "credential_unavailable"}
    assert r.echo.received == []


async def test_unset_env_secret_has_the_code(tmp_path: Path) -> None:
    creds = {"api-key": {"kind": "header", "secret": "env:API_KEY"}}
    r = Rig(tmp_path, policy([api_route()], creds), environ={})
    response = await r.call("GET", "/api/v1/x", headers=bearer())
    assert response.json() == {"error": "upstream unavailable", "code": "credential_unavailable"}
    assert r.echo.received == []


async def test_an_upstream_failure_has_no_code(tmp_path: Path) -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    store = SecretStore(tmp_path, KEYS)
    store.load()
    store.put("api-key", SECRET, origin_binding(["https://api.example"]))
    client = httpx.AsyncClient(transport=httpx.MockTransport(refuse))
    app = VaultApp(policy([api_route()], HEADER_CRED), store, KEYS, client=client, environ={})
    transport = httpx.ASGITransport(app=app, client=(AGENT, 40000))
    async with httpx.AsyncClient(transport=transport, base_url="http://vault") as caller:
        response = await caller.get("/api/v1/x", headers=bearer())
    await app.aclose()
    assert response.status_code == 502
    assert response.json() == {"error": "upstream unavailable"}


async def test_unauthenticated_upstream(tmp_path: Path) -> None:
    route = api_route(credential=None)
    r = Rig(tmp_path, policy([route]))
    assert (await r.call("GET", "/api/v1/x", headers=bearer())).status_code == 200
    assert r.last.header("authorization") is None


async def test_a_connector_route_answers_without_an_upstream(tmp_path: Path) -> None:
    """The connector answers itself: without an Idempotency-Key, a 400 naming the header."""
    route = {
        "name": "mail",
        "prefix": "/mail",
        "connector": "mail-out",
        "callers": [{"placeholder": PH}],
        "rules": [{"methods": ["POST"], "paths": ["/send"]}],
    }
    pol = Policy.model_validate(
        {
            **BASE,
            "routes": [route],
            "connectors": {
                "mail-out": {
                    "kind": "smtp",
                    "host": "smtp.mail.example",
                    "port": 465,
                    "username": "agent",
                    "password": "store:mail-pass",
                    "from": "agent@mail.example",
                    "to": ["partner@mail.example"],
                }
            },
        }
    )
    r = Rig(tmp_path, pol)
    response = await r.call("POST", "/mail/send", headers=bearer())
    assert response.status_code == 400
    assert response.json() == {
        "error": "bad_request",
        "code": "bad_request",
        "field": "Idempotency-Key",
        "rule": "format",
    }
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
        # The real route client is guarded: the loopback fake is listed (M7 design B.2).
        listed = policy([route]).model_copy(
            update={"egress_private": [upstream_base.removeprefix("http://")]}
        )
        app = VaultApp(listed, store, KEYS, environ={})
        with serve(app) as vault_base:
            async with (
                httpx.AsyncClient() as client,
                client.stream("GET", f"{vault_base}/api/sse?n=3", headers=bearer()) as response,
            ):
                assert response.status_code == 200
                events = [line async for line in response.aiter_lines() if line.startswith("data:")]
        # The app ran on the server thread's loop; its connections closed with that loop.
    assert events == ["data: event 0", "data: event 1", "data: event 2"]


# --- cookies (N2) ------------------------------------------------------------------------------


def set_cookie(app: Any, cookie: bytes) -> Any:
    """Wrap an ASGI app so every response sets ``cookie``."""

    async def wrapped(scope: Any, receive: Any, send: Any) -> None:
        async def sending(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                message = {**message, "headers": [*message["headers"], (b"set-cookie", cookie)]}
            await send(message)

        await app(scope, receive, sending)

    return wrapped


async def test_an_upstream_cookie_is_never_sent_again(tmp_path: Path) -> None:
    """M1 bug: httpx's jar re-sent an upstream's Set-Cookie on later requests, from any caller."""
    echo = EchoProvider()
    store = SecretStore(tmp_path, KEYS)
    store.load()
    store.put("api-key", SECRET, origin_binding(["https://api.example"]))
    app_with_cookie = set_cookie(echo.app(), b"session=upstream-session-1; Path=/")
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app_with_cookie))
    app = VaultApp(policy([api_route()], HEADER_CRED), store, KEYS, client=client, environ={})
    transport = httpx.ASGITransport(app=app, client=(AGENT, 40000))
    async with httpx.AsyncClient(transport=transport, base_url="http://vault") as caller:
        first = await caller.get("/api/v1/one", headers=bearer())
        second = await caller.get("/api/v1/two", headers=bearer())
    await app.aclose()
    assert first.status_code == second.status_code == 200
    assert "set-cookie" not in first.headers
    assert [r.header("cookie") for r in echo.received] == [None, None]
    assert len(client.cookies.jar) == 0


async def test_a_token_endpoint_cookie_is_never_sent_again(tmp_path: Path) -> None:
    server = spotify_style()
    store = SecretStore(tmp_path, KEYS)
    store.load()
    for name in ("a-refresh", "b-refresh"):
        store.put(name, server.issue_grant(), oauth_binding(TOKEN_URL, [API]))
    creds = {
        name: {**SPOTIFY_CRED, "refresh_token": f"store:{name}-refresh"} for name in ("a", "b")
    }
    routes = [
        oauth_route(name="a", prefix="/a", credential="a"),
        oauth_route(name="b", prefix="/b", credential="b"),
    ]
    api = ApiServer()
    token_app = set_cookie(server.app(), b"as-session=token-session-1; Path=/")
    app = VaultApp(
        policy(routes, creds),
        store,
        KEYS,
        client=httpx.AsyncClient(transport=httpx.ASGITransport(app=api.app())),
        token_client=httpx.AsyncClient(transport=httpx.ASGITransport(app=token_app)),
        environ={},
    )
    transport = httpx.ASGITransport(app=app, client=(AGENT, 40000))
    async with httpx.AsyncClient(transport=transport, base_url="http://vault") as caller:
        assert (await caller.get("/a/v1/x", headers=bearer())).status_code == 200
        assert (await caller.get("/b/v1/x", headers=bearer())).status_code == 200
    await app.aclose()
    assert len(server.calls) == 2
    assert [call.headers.get("cookie") for call in server.calls] == [None, None]


async def test_default_clients(tmp_path: Path) -> None:
    store = SecretStore(tmp_path, KEYS)
    store.load()
    app = VaultApp(policy([api_route()], HEADER_CRED), store, KEYS, environ={})
    upstream, token = app._client, app._token_client
    assert token is not None
    assert upstream is not token
    for client in (upstream, token):
        assert client.follow_redirects is False
        assert client.trust_env is False
        assert type(client.cookies.jar).__name__ == "_DiscardingJar"
    assert upstream.timeout == httpx.Timeout(60.0, connect=10.0)
    assert token.timeout == httpx.Timeout(20.0, connect=5.0)
    await app.aclose()
    assert upstream.is_closed
    assert token.is_closed


async def test_one_client_for_both_is_closed_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = SecretStore(tmp_path, KEYS)
    store.load()
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=EchoProvider().app()))
    closed: list[str] = []
    real = client.aclose

    async def aclose() -> None:
        closed.append("client")
        await real()

    monkeypatch.setattr(client, "aclose", aclose)
    app = VaultApp(
        policy([api_route()], HEADER_CRED), store, KEYS, client=client, token_client=client
    )
    await app.aclose()
    assert closed == ["client"]


# --- OAuth -------------------------------------------------------------------------------------

TOKEN_URL = "https://accounts.example/token"
API = "https://api.example"
SPOTIFY_ID = "0123456789abcdef0123456789abcdef"
SPOTIFY_CRED: dict[str, Any] = {
    "kind": "oauth2",
    "token_url": TOKEN_URL,
    "client_id": SPOTIFY_ID,
    "client_auth": "none",
    "rotates": True,
    "refresh_token": "store:music-refresh",
}
ALL_METHODS = ["GET", "HEAD", "OPTIONS", "PUT", "DELETE", "POST", "PATCH"]
INVALID_TOKEN = 'Bearer error="invalid_token"'


def oauth_route(**overrides: Any) -> dict[str, Any]:
    return api_route(
        **{
            "credential": "music",
            "rules": [{"methods": ALL_METHODS, "paths": ["/v1/**"]}],
            **overrides,
        }
    )


class FakeClock:
    def __init__(self) -> None:
        self.mono = 1000.0
        self.wall = 1_792_000_000.0

    def monotonic(self) -> float:
        return self.mono

    def time(self) -> float:
        return self.wall

    def advance(self, seconds: float) -> None:
        self.mono += seconds
        self.wall += seconds

    async def sleep(self, seconds: float) -> None:
        self.advance(seconds)


class ApiServer:
    """A resource server: refuses the tokens in ``reject`` with 401, else echoes what it got."""

    def __init__(self) -> None:
        self.reject: set[str] = set()
        self.reject_all = False
        self.challenges: list[str] = [INVALID_TOKEN]
        # The challenge of a 403 to a path ending /forbidden.
        self.forbidden = 'Bearer error="insufficient_scope"'
        self.echo: list[str] = []
        # Answer as server-sent events, refusals included.
        self.sse = False
        self.received: list[tuple[str, str | None]] = []
        # Everything else about each request: method, path, query, body and headers.
        self.requests: list[dict[str, Any]] = []

    def app(self) -> Starlette:
        return Starlette(routes=[Route("/{path:path}", self._handle, methods=ALL_METHODS)])

    async def _handle(self, request: Request) -> Response:
        authorization = request.headers.get("authorization")
        self.received.append((request.method, authorization))
        self.requests.append(
            {
                "method": request.method,
                "path": request.url.path,
                "query": request.url.query,
                "body": await request.body(),
                "headers": [(k, v) for k, v in request.headers.items() if k != "authorization"],
            }
        )
        token = (authorization or "").removeprefix("Bearer ")
        if self.reject_all or token in self.reject:
            headers = [(b"www-authenticate", c.encode()) for c in self.challenges]
            response: Response
            if self.sse:
                response = Response(
                    f"data: {token}\n\n", status_code=401, media_type="text/event-stream"
                )
            else:
                response = JSONResponse({"error": "invalid_token", "token": token}, 401)
            response.raw_headers += headers
            return response
        if self.sse:
            return Response(f"data: {token}\n\n", media_type="text/event-stream")
        if request.url.path.endswith("/denied"):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        if request.url.path.endswith("/forbidden"):
            return JSONResponse(
                {"error": "insufficient_scope"},
                status_code=403,
                headers={"www-authenticate": self.forbidden},
            )
        return JSONResponse(
            {"ok": True, "token": token, "echo": self.echo}, headers={"x-echo": token}
        )

    @property
    def tokens(self) -> list[str | None]:
        return [(a or "").removeprefix("Bearer ") for _, a in self.received]


class _Tracked(httpx.AsyncByteStream):
    """A response body that remembers whether it was closed."""

    def __init__(self, inner: httpx.AsyncByteStream) -> None:
        self.inner = inner
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        async for chunk in self.inner:
            yield chunk

    async def aclose(self) -> None:
        self.closed = True
        await self.inner.aclose()


class TrackingTransport(httpx.AsyncBaseTransport):
    """An in-process transport that keeps every response body, to check each was closed. With a
    real connection pool, one left open holds a connection."""

    def __init__(self, app: Starlette) -> None:
        self.inner = httpx.ASGITransport(app=app)
        self.streams: list[_Tracked] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        response = await self.inner.handle_async_request(request)
        assert isinstance(response.stream, httpx.AsyncByteStream)
        stream = _Tracked(response.stream)
        self.streams.append(stream)
        return httpx.Response(
            response.status_code,
            headers=response.headers,
            stream=stream,
            extensions=response.extensions,
        )

    @property
    def closed(self) -> list[bool]:
        return [stream.closed for stream in self.streams]


class OAuthRig:
    def __init__(
        self,
        tmp_path: Path,
        *,
        cred: dict[str, Any] | None = None,
        server: FakeAuthServer | None = None,
        routes: list[dict[str, Any]] | None = None,
    ) -> None:
        self.clock = FakeClock()
        self.server = server or spotify_style(self.clock.time)
        self.api = ApiServer()
        self.store = SecretStore(tmp_path, KEYS)
        self.store.load()
        self.policy = policy(routes or [oauth_route()], {"music": cred or SPOTIFY_CRED})
        self.token_client = httpx.AsyncClient(transport=httpx.ASGITransport(app=self.server.app()))
        self.tokens = TokenManager(
            self.store,
            self.token_client,
            clock=self.clock.monotonic,
            wall=self.clock.time,
            sleep=self.clock.sleep,
            uniform=lambda low, high: 1.0,
        )
        self.upstream = TrackingTransport(self.api.app())
        upstream = httpx.AsyncClient(transport=self.upstream)
        self.app = VaultApp(
            self.policy, self.store, KEYS, client=upstream, tokens=self.tokens, environ={}
        )

    def seed(self, resources: tuple[str, ...] = (API,)) -> str:
        token = self.server.issue_grant()
        self.store.put("music-refresh", token, oauth_binding(TOKEN_URL, resources))
        return token

    async def call(
        self,
        method: str,
        path: str = "/api/v1/x",
        headers: dict[str, str] | None = None,
        content: bytes = b"",
    ) -> httpx.Response:
        transport = httpx.ASGITransport(app=self.app, client=(AGENT, 40000))
        async with httpx.AsyncClient(transport=transport, base_url="http://vault") as client:
            return await client.request(
                method, path, headers=bearer() if headers is None else headers, content=content
            )

    @property
    def refreshes(self) -> int:
        return len(self.server.refresh_calls)

    async def aclose(self) -> None:
        await self.app.aclose()
        await self.token_client.aclose()


@pytest.fixture
async def oauth(tmp_path: Path) -> AsyncIterator[OAuthRig]:
    r = OAuthRig(tmp_path)
    yield r
    await r.aclose()


@pytest.fixture
def captured() -> Iterator[io.StringIO]:
    buffer = io.StringIO()
    logs.set_stream(buffer)
    try:
        yield buffer
    finally:
        logs.set_stream(None)


def events(buffer: io.StringIO, kind: str) -> list[dict[str, Any]]:
    lines = [json.loads(line) for line in buffer.getvalue().splitlines()]
    return [line for line in lines if line["event"] == kind]


async def test_oauth_injects_the_access_token(oauth: OAuthRig) -> None:
    oauth.seed()
    response = await oauth.call("GET")
    assert response.status_code == 200
    [(method, authorization)] = oauth.api.received
    assert method == "GET"
    assert authorization is not None
    token = authorization.removeprefix("Bearer ")
    assert oauth.server.access_ok(token)
    assert token != PH


async def test_the_callers_authorization_is_never_forwarded(tmp_path: Path) -> None:
    route = oauth_route(callers=[{"placeholder": PH, "header": "X-Api-Key"}])
    r = OAuthRig(tmp_path, routes=[route])
    r.seed()
    headers = {"X-Api-Key": PH, "Authorization": "Bearer caller-own-token-1234"}
    transport = httpx.ASGITransport(app=r.app, client=(AGENT, 40000))
    async with httpx.AsyncClient(transport=transport, base_url="http://vault") as client:
        response = await client.get("/api/v1/x", headers=headers)
    await r.aclose()
    assert response.status_code == 200
    [(_, authorization)] = r.api.received
    assert authorization is not None
    assert authorization != "Bearer caller-own-token-1234"
    assert r.server.access_ok(authorization.removeprefix("Bearer "))


async def test_identity_and_rules_come_before_any_token_call(oauth: OAuthRig) -> None:
    # No refresh token is stored: a request that got that far would be a 502 with a code.
    wrong = await oauth.call("GET", headers=bearer("guessed-placeholder-0000"))
    assert wrong.status_code == 403
    assert wrong.json() == {"error": "forbidden"}
    no_rule = await oauth.call("GET", "/api/v2/x")
    assert no_rule.status_code == 403
    assert no_rule.json() == {"error": "forbidden"}
    assert oauth.server.calls == []
    assert oauth.api.received == []
    entitled = await oauth.call("GET")
    assert entitled.json() == {"error": "upstream unavailable", "code": "credential_unavailable"}


async def test_a_query_policy_refusal_comes_before_any_token_call(tmp_path: Path) -> None:
    r = OAuthRig(tmp_path, routes=[oauth_route(query={"allow": ["page"]})])
    r.seed()
    refused = await r.call("GET", "/api/v1/x?other=1")
    assert refused.status_code == 403
    assert refused.json() == {"error": "forbidden"}
    assert r.server.calls == []
    assert r.api.received == []
    assert (await r.call("GET", "/api/v1/x?page=1")).status_code == 200
    assert r.refreshes == 1
    await r.aclose()


async def test_a_route_the_grant_isnt_bound_to_gets_nothing(oauth: OAuthRig) -> None:
    oauth.seed(resources=("https://other.example",))
    response = await oauth.call("GET")
    assert response.status_code == 502
    assert response.json() == {"error": "upstream unavailable", "code": "credential_unavailable"}
    assert "retry-after" not in response.headers
    assert oauth.server.calls == []
    assert oauth.api.received == []


async def test_a_changed_route_upstream_gets_nothing(oauth: OAuthRig) -> None:
    oauth.seed()
    assert (await oauth.call("GET")).status_code == 200
    moved = policy([oauth_route(upstream="https://moved.example")], {"music": SPOTIFY_CRED})
    assert oauth.app.reload(moved) == ["music"]
    response = await oauth.call("GET")
    assert response.json() == {"error": "upstream unavailable", "code": "credential_unavailable"}
    assert len(oauth.api.received) == 1
    assert oauth.refreshes == 1


async def test_every_secret_form_is_scrubbed(tmp_path: Path) -> None:
    secret = "fake secret/+=:client-01"
    server = google_style(client_secret=secret)
    cred = {
        **SPOTIFY_CRED,
        "client_id": server.client_id,
        "client_auth": "post",
        "client_secret": "store:google-secret",
        "rotates": False,
    }
    r = OAuthRig(tmp_path, cred=cred, server=server)
    r.store.put("google-secret", secret, oauth_binding(TOKEN_URL, [API]))
    refresh = r.seed()
    basic = oauth_basic_credentials(server.client_id, secret)
    r.api.echo = [refresh, secret, quote_plus(secret), basic]
    response = await r.call("GET")
    await r.aclose()
    assert response.status_code == 200
    token = r.api.tokens[0]
    assert token
    for value in (token, refresh, secret, quote_plus(secret), basic):
        assert value not in response.text
    assert response.headers["x-echo"] == "[REDACTED]"
    assert response.json()["echo"] == ["[REDACTED]"] * 4


@pytest.mark.parametrize(
    ("retry_after", "header"),
    [(None, "1"), (0.0, "1"), (0.2, "1"), (1.0, "1"), (5.01, "6"), (60.0, "60")],
)
async def test_oauth_unavailable_has_retry_after(
    oauth: OAuthRig, monkeypatch: pytest.MonkeyPatch, retry_after: float | None, header: str
) -> None:
    async def unavailable(credential: str, upstream: str) -> Grant:
        raise OAuthUnavailable(OAUTH_UNAVAILABLE, "backoff", retry_after=retry_after)

    monkeypatch.setattr(oauth.tokens, "grant_for", unavailable)
    response = await oauth.call("GET")
    assert response.status_code == 502
    assert response.json() == {"error": "upstream unavailable", "code": "oauth_unavailable"}
    assert response.headers["retry-after"] == header


async def test_other_codes_have_no_retry_after(
    oauth: OAuthRig, monkeypatch: pytest.MonkeyPatch, captured: io.StringIO
) -> None:
    async def misconfigured(credential: str, upstream: str) -> Grant:
        raise OAuthUnavailable(OAUTH_MISCONFIGURED, "request", retry_after=7.0)

    monkeypatch.setattr(oauth.tokens, "grant_for", misconfigured)
    response = await oauth.call("GET")
    assert response.json() == {"error": "upstream unavailable", "code": "oauth_misconfigured"}
    assert "retry-after" not in response.headers
    [line] = events(captured, "request")
    assert line["status"] == 502
    assert line["code"] == "oauth_misconfigured"
    assert line["reason"] == "oauth_misconfigured: request"


async def test_a_token_endpoint_outage_backs_off(oauth: OAuthRig) -> None:
    oauth.seed()
    oauth.server.fail_next(1, 503)
    response = await oauth.call("GET")
    assert response.status_code == 502
    assert response.json() == {"error": "upstream unavailable", "code": "oauth_unavailable"}
    assert response.headers["retry-after"] == "5"
    assert oauth.api.received == []
    oauth.clock.advance(5)
    assert (await oauth.call("GET")).status_code == 200


async def test_a_revoked_grant_needs_consent(oauth: OAuthRig) -> None:
    oauth.seed()
    oauth.server.revoke()
    for _ in range(3):
        response = await oauth.call("GET")
        assert response.status_code == 502
        assert response.json() == {
            "error": "upstream unavailable",
            "code": "oauth_reconsent_needed",
        }
        assert "retry-after" not in response.headers
    assert oauth.refreshes == 1
    assert oauth.api.received == []


async def test_oauth_request_log(oauth: OAuthRig, captured: io.StringIO) -> None:
    refresh = oauth.seed()
    await oauth.call("GET")
    await oauth.call("GET")
    first, second = events(captured, "request")
    assert (first["credential"], first["oauth"]) == ("music", "refreshed")
    assert (second["credential"], second["oauth"]) == ("music", "cached")
    for value in (refresh, oauth.api.tokens[0] or "", PH):
        assert value not in captured.getvalue()


# --- the 401 path (design D.10) ----------------------------------------------------------------


async def first_token(r: OAuthRig) -> str:
    assert (await r.call("GET")).status_code == 200
    token = r.api.tokens[-1]
    assert token
    return token


@pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS", "PUT", "DELETE"])
async def test_a_401_refreshes_and_retries_once(
    oauth: OAuthRig, captured: io.StringIO, method: str
) -> None:
    oauth.seed()
    old = await first_token(oauth)
    oauth.clock.advance(MIN_401_AGE)
    oauth.api.reject = {old}
    response = await oauth.call(
        method,
        "/api/v1/x?page=2&q=a%20b",
        headers={**bearer(), "content-type": "text/plain", "x-request-id": "r-1"},
        content=b"the same body",
    )
    assert response.status_code == 200
    assert oauth.refreshes == 2
    new = oauth.api.tokens[-1]
    assert oauth.api.tokens == [old, old, new]
    assert new
    assert new != old
    # The retry is the same request, apart from its token.
    first, second = oauth.api.requests[1:]
    assert first == second
    assert first["method"] == method
    assert (first["path"], first["query"]) == ("/base/v1/x", "page=2&q=a%20b")
    assert first["body"] == b"the same body"
    assert ("x-request-id", "r-1") in first["headers"]
    assert ("content-type", "text/plain") in first["headers"]
    # Neither token reaches the caller: the merged scrub set has the new one too.
    assert response.headers["x-echo"] == "[REDACTED]"
    if method != "HEAD":
        assert response.json()["token"] == "[REDACTED]"
        for value in (old, new):
            assert value not in response.text
    # The refused 401 was closed before the refresh, and the retry's answer after relaying it.
    assert oauth.upstream.closed == [True, True, True]
    [line] = events(captured, "oauth_upstream_401")
    assert line == {
        "ts": line["ts"],
        "role": "vault",
        "event": "oauth_upstream_401",
        "route": "api",
        "credential": "music",
        "method": method,
        "action": "retried",
        "fresh_token": False,
    }
    assert events(captured, "request")[-1]["oauth"] == "retried"
    # The new token is cached: no more refreshes.
    assert (await oauth.call("GET")).status_code == 200
    assert oauth.refreshes == 2
    assert oauth.api.tokens[-1] == new
    assert events(captured, "request")[-1]["oauth"] == "cached"


async def test_the_401_is_closed_before_waiting_for_the_refresh(oauth: OAuthRig) -> None:
    oauth.seed()
    old = await first_token(oauth)
    oauth.clock.advance(MIN_401_AGE)
    oauth.api.reject = {old}
    gate = oauth.server.hold()
    pending = asyncio.create_task(oauth.call("GET"))
    await oauth.server.arrived()
    # The refresh is at the token endpoint: the upstream connection is free already.
    assert oauth.upstream.closed == [True, True]
    gate.set()
    assert (await pending).status_code == 200


@pytest.mark.parametrize("method", ["POST", "PATCH"])
async def test_a_401_to_a_post_goes_back_to_the_caller(
    oauth: OAuthRig, captured: io.StringIO, method: str
) -> None:
    oauth.seed()
    old = await first_token(oauth)
    oauth.clock.advance(MIN_401_AGE)
    oauth.api.reject = {old}
    response = await oauth.call(method)
    assert response.status_code == 401
    assert old not in response.text
    assert oauth.refreshes == 1
    assert oauth.api.tokens == [old, old]
    [line] = events(captured, "oauth_upstream_401")
    assert (line["action"], line["fresh_token"]) == ("invalidated", False)
    request = events(captured, "request")[-1]
    assert (request["oauth"], request["upstream_status"], request["status"]) == ("cached", 401, 401)
    assert oauth.upstream.closed == [True, True]
    # The token was dropped: the next request gets a new one.
    assert (await oauth.call(method)).status_code == 200
    assert oauth.refreshes == 2
    assert oauth.api.tokens[-1] != old


async def test_a_401_to_a_fresh_token_is_suppressed(oauth: OAuthRig, captured: io.StringIO) -> None:
    oauth.seed()
    old = await first_token(oauth)
    oauth.clock.advance(MIN_401_AGE - 0.5)
    oauth.api.reject = {old}
    response = await oauth.call("GET")
    assert response.status_code == 401
    assert response.json() == {"error": "invalid_token", "token": "[REDACTED]"}
    assert oauth.refreshes == 1
    assert oauth.api.tokens == [old, old]
    [line] = events(captured, "oauth_upstream_401")
    assert (line["action"], line["fresh_token"]) == ("suppressed", True)
    request = events(captured, "request")[-1]
    assert (request["oauth"], request["upstream_status"], request["status"]) == ("cached", 401, 401)
    # Still cached: the next request uses it again.
    await oauth.call("GET")
    assert oauth.api.tokens == [old, old, old]


async def test_the_retry_is_final(oauth: OAuthRig) -> None:
    oauth.seed()
    await first_token(oauth)
    oauth.clock.advance(MIN_401_AGE)
    oauth.api.reject_all = True
    response = await oauth.call("GET")
    assert response.status_code == 401
    assert oauth.refreshes == 2
    assert len(oauth.api.received) == 3


@pytest.mark.parametrize(
    ("challenges", "retried"),
    [
        ([], True),
        (['Bearer realm="api"'], True),
        ([INVALID_TOKEN], True),
        (['Bearer realm="api", error="invalid_token", error_description="expired"'], True),
        (["Bearer realm=api,error=invalid_token"], True),
        (['Bearer error_description="insufficient_scope"'], True),
        (['Bearer error="insufficient_scope"'], False),
        (['Bearer error="invalid_request"'], False),
        (['Bearer error="INVALID_TOKEN"'], False),
        (['Bearer realm="api",error="insufficient_scope"'], False),
        ([INVALID_TOKEN, 'Bearer error="insufficient_scope"'], False),
    ],
)
async def test_which_401s_refresh(
    oauth: OAuthRig, captured: io.StringIO, challenges: list[str], retried: bool
) -> None:
    oauth.seed()
    old = await first_token(oauth)
    oauth.clock.advance(MIN_401_AGE)
    oauth.api.reject = {old}
    oauth.api.challenges = challenges
    response = await oauth.call("GET")
    assert response.status_code == (200 if retried else 401)
    assert oauth.refreshes == (2 if retried else 1)
    assert len(oauth.api.received) == (3 if retried else 2)
    assert len(events(captured, "oauth_upstream_401")) == (1 if retried else 0)
    request = events(captured, "request")[-1]
    assert request["oauth"] == ("retried" if retried else "cached")


async def test_a_403_never_refreshes(oauth: OAuthRig) -> None:
    oauth.seed()
    await first_token(oauth)
    oauth.clock.advance(MIN_401_AGE)
    response = await oauth.call("GET", "/api/v1/forbidden")
    assert response.status_code == 403
    assert oauth.refreshes == 1
    assert len(oauth.api.received) == 2


def upstream_said(r: OAuthRig) -> Any:
    return r.tokens.status()[0]["upstream"]


@pytest.mark.parametrize(
    ("path", "reject", "challenges", "recorded"),
    [
        ("/api/v1/forbidden", False, [], True),
        ("/api/v1/denied", False, [], False),
        ("/api/v1/x", True, ['Bearer error="insufficient_scope"'], True),
        ("/api/v1/x", True, ['Bearer realm="api", error="insufficient_scope"'], True),
        ("/api/v1/x", True, [INVALID_TOKEN], False),
        ("/api/v1/x", True, ['Bearer error_description="insufficient_scope"'], False),
        ("/api/v1/x", False, [], False),
    ],
)
async def test_an_insufficient_scope_is_recorded_for_status(
    oauth: OAuthRig, path: str, reject: bool, challenges: list[str], recorded: bool
) -> None:
    oauth.seed()
    old = await first_token(oauth)
    assert upstream_said(oauth) is None
    oauth.api.challenges = challenges
    if reject:
        oauth.api.reject = {old}
    await oauth.call("GET", path)
    found = upstream_said(oauth)
    assert (found["code"] if found else None) == (
        "upstream_insufficient_scope" if recorded else None
    )


@pytest.mark.parametrize(
    ("challenges", "scopes"),
    [
        (
            ['Bearer error="insufficient_scope", scope="playlist-read user-top-read"'],
            ["playlist-read", "user-top-read"],
        ),
        (['Bearer realm="api", error="insufficient_scope"'], None),
        # One that doesn't parse, or a token D.2's parser refuses: the finding without a scope.
        (['Bearer error="insufficient_scope", scope="playlist-read'], None),
        (['Bearer error="insufficient_scope", scope="pay$day"'], None),
        # The scope is read from the challenge whose error is read (the first Bearer one).
        ([INVALID_TOKEN, 'Bearer error="insufficient_scope", scope="extra"'], None),
    ],
)
async def test_an_insufficient_scope_keeps_the_scope_it_asked_for(
    oauth: OAuthRig, challenges: list[str], scopes: list[str] | None
) -> None:
    """M7 design D.5's step-up (SPEC-11): the challenge's cleaned scope tokens, for health's
    widen_scope fragment. The vault never asks for them itself."""
    oauth.seed()
    oauth.api.reject = {await first_token(oauth)}
    oauth.api.challenges = challenges
    await oauth.call("GET")
    found = upstream_said(oauth)
    assert found["code"] == "upstream_insufficient_scope"
    assert found.get("scopes") == scopes
    assert oauth.refreshes == 1


PRM = "https://api.example/.well-known/oauth-protected-resource"
OTHER_PRM = "https://auth.other.example/.well-known/oauth-protected-resource"


@pytest.mark.parametrize(
    ("pinned", "challenge", "noted"),
    [
        (PRM, f'Bearer resource_metadata="{OTHER_PRM}"', OTHER_PRM),
        (PRM, f'Bearer error="invalid_token", resource_metadata="{OTHER_PRM}"', OTHER_PRM),
        (PRM, f'Bearer resource_metadata="{PRM}"', None),
        (PRM, INVALID_TOKEN, None),
        # Not pinned (D.2a), or a URL D.2's parser refuses: nothing kept.
        (None, f'Bearer resource_metadata="{OTHER_PRM}"', None),
        (PRM, f'Bearer resource_metadata="{OTHER_PRM}?x=1"', None),
        (PRM, f'Bearer resource_metadata="{OTHER_PRM}", Bearer resource_metadata="{PRM}"', None),
    ],
)
async def test_a_401_naming_other_resource_metadata_is_kept_for_health(
    tmp_path: Path, pinned: str | None, challenge: str, noted: str | None
) -> None:
    cred = SPOTIFY_CRED if pinned is None else {**SPOTIFY_CRED, "resource_metadata": pinned}
    r = OAuthRig(tmp_path, cred=cred)
    try:
        r.seed()
        r.api.reject = {await first_token(r)}
        r.api.challenges = [challenge]
        await r.call("GET")
        found = r.tokens.status()[0]["resource_metadata"]
        assert (found["url"] if found else None) == noted
    finally:
        await r.aclose()


async def test_a_403_keeps_its_scope_but_not_its_resource_metadata(tmp_path: Path) -> None:
    """J: resource_metadata_changed is a 401's; a 403 is the step-up's (D.5)."""
    r = OAuthRig(tmp_path, cred={**SPOTIFY_CRED, "resource_metadata": PRM})
    try:
        r.seed()
        await first_token(r)
        r.api.forbidden = (
            f'Bearer error="insufficient_scope", scope="extra", resource_metadata="{OTHER_PRM}"'
        )
        assert (await r.call("GET", "/api/v1/forbidden")).status_code == 403
        assert r.tokens.status()[0]["resource_metadata"] is None
        assert upstream_said(r)["scopes"] == ["extra"]
    finally:
        await r.aclose()


async def test_a_failed_refresh_after_a_401_is_a_502_with_its_code(
    oauth: OAuthRig, captured: io.StringIO
) -> None:
    oauth.seed()
    old = await first_token(oauth)
    oauth.clock.advance(MIN_401_AGE)
    oauth.api.reject = {old}
    oauth.server.revoke()
    response = await oauth.call("GET")
    assert response.status_code == 502
    assert response.json() == {"error": "upstream unavailable", "code": "oauth_reconsent_needed"}
    assert len(oauth.api.received) == 2
    assert oauth.upstream.closed == [True, True]
    # The 401 that led to it is logged too.
    [line] = events(captured, "oauth_upstream_401")
    assert (line["method"], line["action"], line["fresh_token"]) == ("GET", "invalidated", False)
    request = events(captured, "request")[-1]
    assert (request["status"], request["code"]) == (502, "oauth_reconsent_needed")


async def test_a_failed_retry_is_a_502_and_logged(oauth: OAuthRig, captured: io.StringIO) -> None:
    oauth.seed()
    old = await first_token(oauth)
    oauth.clock.advance(MIN_401_AGE)
    oauth.api.reject = {old}
    real = oauth.upstream.handle_async_request

    async def fail_the_retry(request: httpx.Request) -> httpx.Response:
        if len(oauth.upstream.streams) == 2:
            raise httpx.ConnectError("simulated", request=request)
        return await real(request)

    oauth.upstream.handle_async_request = fail_the_retry  # type: ignore[method-assign]
    response = await oauth.call("GET")
    assert response.status_code == 502
    assert response.json() == {"error": "upstream unavailable"}
    assert oauth.upstream.closed == [True, True]
    [line] = events(captured, "oauth_upstream_401")
    assert line["action"] == "invalidated"


async def test_a_newer_token_is_used_without_a_refresh(
    oauth: OAuthRig, monkeypatch: pytest.MonkeyPatch, captured: io.StringIO
) -> None:
    """Another request already replaced the token: retry with it."""
    oauth.seed()
    old = await first_token(oauth)
    oauth.clock.advance(MIN_401_AGE)
    oauth.api.reject = {old}
    real = oauth.tokens.rejected

    # It contains the old token, so the old token's variants match part of it: the merged scrub
    # set must try the longest first.
    newer_token = old + "-newer"

    def rejected(credential: str, used: Grant) -> Any:
        # As if a concurrent request had refreshed meanwhile.
        newer = replace(
            used,
            serial=used.serial + 100,
            token=Secret(newer_token),
            variants=tuple(secret_variants(newer_token)),
        )
        oauth.tokens._cache[credential] = newer
        return real(credential, used)

    monkeypatch.setattr(oauth.tokens, "rejected", rejected)
    response = await oauth.call("GET")
    assert response.status_code == 200
    assert oauth.refreshes == 1
    assert oauth.api.tokens == [old, old, newer_token]
    [line] = events(captured, "oauth_upstream_401")
    assert line["action"] == "retried"
    assert response.headers["x-echo"] == "[REDACTED]"
    assert response.json()["token"] == "[REDACTED]"
    assert "newer" not in response.text


async def test_the_same_token_again_is_not_retried(
    oauth: OAuthRig, monkeypatch: pytest.MonkeyPatch, captured: io.StringIO
) -> None:
    oauth.seed()
    old = await first_token(oauth)
    oauth.clock.advance(MIN_401_AGE)
    oauth.api.reject = {old}
    grant = oauth.tokens._cache["music"]
    monkeypatch.setattr(oauth.tokens, "rejected", lambda credential, used: "reused_newer")
    real = oauth.tokens.grant_for
    calls: list[int] = []

    async def grant_for(credential: str, upstream: str) -> Grant:
        calls.append(1)
        if len(calls) > 1:
            return grant
        return await real(credential, upstream)

    monkeypatch.setattr(oauth.tokens, "grant_for", grant_for)
    response = await oauth.call("GET")
    # The 401 was closed before asking for a new token, so there is nothing to relay.
    assert response.status_code == 502
    assert response.json() == {"error": "upstream unavailable", "code": "oauth_unavailable"}
    assert response.headers["retry-after"] == "1"
    assert len(oauth.api.received) == 2
    assert oauth.upstream.closed == [True, True]
    [line] = events(captured, "oauth_upstream_401")
    assert line["action"] == "reused_newer"


async def test_a_401_on_a_static_credential_is_passed_through(tmp_path: Path) -> None:
    api = ApiServer()
    api.reject = {SECRET}
    store = SecretStore(tmp_path, KEYS)
    store.load()
    store.put("api-key", SECRET, origin_binding(["https://api.example"]))
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=api.app()))
    app = VaultApp(policy([api_route()], HEADER_CRED), store, KEYS, client=client, environ={})
    transport = httpx.ASGITransport(app=app, client=(AGENT, 40000))
    async with httpx.AsyncClient(transport=transport, base_url="http://vault") as caller:
        response = await caller.get("/api/v1/x", headers=bearer())
    await app.aclose()
    assert response.status_code == 401
    assert SECRET not in response.text
    assert len(api.received) == 1


# --- shutdown ----------------------------------------------------------------------------------


async def test_aclose_drains_refreshes_before_closing_the_clients(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    r = OAuthRig(tmp_path)
    r.seed()
    gate = r.server.hold()
    pending = asyncio.create_task(r.tokens.grant_for("music", API))
    await r.server.arrived()
    order: list[str] = []
    real_close = r.app._client.aclose

    async def close_client() -> None:
        order.append(f"client closed, refreshing={r.tokens.status()[0]['refreshing']}")
        await real_close()

    monkeypatch.setattr(r.app._client, "aclose", close_client)
    closing = asyncio.create_task(r.app.aclose())
    await asyncio.sleep(0)
    assert not closing.done()
    gate.set()
    await closing
    assert order == ["client closed, refreshing=False"]
    # The rotated refresh token was saved before the clients closed.
    assert r.store.get_for_oauth("music-refresh", token_url=TOKEN_URL)[0].reveal() == (
        r.server.active_refresh_token()
    )
    assert (await pending).token.reveal() != ""
    await r.token_client.aclose()


async def test_the_clients_close_even_if_the_drain_fails(tmp_path: Path) -> None:
    store = SecretStore(tmp_path, KEYS)
    store.load()
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=EchoProvider().app()))

    class Failing(TokenManager):
        async def aclose(self) -> None:
            raise OSError("simulated flush failure")

    tokens = Failing(store, client)
    app = VaultApp(policy([api_route()], HEADER_CRED), store, KEYS, client=client, tokens=tokens)
    with pytest.raises(OSError, match="simulated flush failure"):
        await app.aclose()
    assert client.is_closed

    default = VaultApp(policy([api_route()], HEADER_CRED), store, KEYS, environ={})
    token_client = default._token_client
    assert token_client is not None
    default._tokens = Failing(store, token_client)
    with pytest.raises(OSError, match="simulated flush failure"):
        await default.aclose()
    assert default._client.is_closed
    assert token_client.is_closed


async def test_a_401_is_never_relayed_as_a_stream(tmp_path: Path, captured: io.StringIO) -> None:
    r = OAuthRig(tmp_path, routes=[oauth_route(stream=True)])
    r.seed()
    r.api.sse = True
    ok = await r.call("POST")
    assert ok.status_code == 200
    token = r.api.tokens[-1]
    assert token
    r.clock.advance(MIN_401_AGE)
    r.api.reject = {token}
    refused = await r.call("POST")
    await r.aclose()
    assert refused.status_code == 401
    assert refused.text == "data: [REDACTED]\n\n"
    streamed = [line.get("streamed") for line in events(captured, "request")]
    assert streamed == [True, None]
