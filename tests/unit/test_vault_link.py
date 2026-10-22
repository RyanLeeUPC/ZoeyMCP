"""The vault's side of the gateway link (M3 design C.1, C.4).

Every answer the vault makes itself carries the refusal marker, and no relayed answer does. The
link listener's caller is the gateway and nothing else, and with a link configured TCP refuses
gateway keys.
"""

from __future__ import annotations

import io
import json
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any, cast

import httpx
import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from starlette.types import Receive, Scope, Send

from zoeymcp.common.policy import Policy
from zoeymcp.vault import logs
from zoeymcp.vault.app import (
    GATEWAY_HEADER,
    LISTENER_SCOPE_KEY,
    REFUSAL_HEADER,
    REFUSAL_MARKER,
    Listener,
    Refused,
    VaultApp,
)
from zoeymcp.vault.keys import KeySet
from zoeymcp.vault.server import ListenerTag
from zoeymcp.vault.store import SecretStore, origin_binding

KEYS = KeySet.from_master(bytes(range(32)))
PH = "ph-agent1-direct-0001"
SECRET = "sk-live-8f3c2a91d7e4"
CHALLENGE = 'Bearer resource_metadata="https://api.example/.well-known/oauth-protected-resource"'
CRED = {"api-key": {"kind": "header", "secret": "store:api-key"}}

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


def requests(buffer: io.StringIO) -> list[dict[str, Any]]:
    lines = [json.loads(line) for line in buffer.getvalue().splitlines()]
    return [line for line in lines if line["event"] == "request"]


def route(**overrides: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "name": "api",
        "prefix": "/api",
        "upstream": "https://api.example/base",
        "credential": "api-key",
        "callers": [{"placeholder": PH}],
        "rules": [{"methods": ["GET", "POST"], "paths": ["/v1/**"]}],
    }
    value.update(overrides)
    return value


def make_policy(*routes: dict[str, Any]) -> Policy:
    return Policy.model_validate(
        {
            "version": 1,
            "mode": "declarative",
            "routes": list(routes),
            "credentials": CRED,
        }
    )


class Upstream:
    """Answers ``/base/v1/status/<code>`` with that status, and ``/base/v1/sse`` with an event
    stream. Every answer carries a forged refusal marker."""

    def __init__(self) -> None:
        self.received: list[tuple[str, dict[str, str]]] = []

    def app(self) -> Starlette:
        return Starlette(
            routes=[
                Route("/base/v1/status/{code:int}", self._status, methods=["GET"]),
                Route("/base/v1/sse", self._sse, methods=["GET"]),
                Route("/base/v1/challenge", self._challenge, methods=["GET"]),
                Route("/base/v1/{rest:path}", self._ok, methods=["GET", "POST"]),
            ]
        )

    def _record(self, request: Request) -> None:
        self.received.append((request.url.path, dict(request.headers)))

    async def _status(self, request: Request) -> Response:
        self._record(request)
        code = request.path_params["code"]
        return JSONResponse({"upstream": code}, code, headers={REFUSAL_HEADER: REFUSAL_MARKER})

    async def _sse(self, request: Request) -> Response:
        self._record(request)
        return Response(
            "data: one\n\n",
            media_type="text/event-stream",
            headers={REFUSAL_HEADER: REFUSAL_MARKER},
        )

    async def _challenge(self, request: Request) -> Response:
        self._record(request)
        return JSONResponse(
            {"error": "invalid_token"}, 401, headers={"www-authenticate": CHALLENGE}
        )

    async def _ok(self, request: Request) -> Response:
        self._record(request)
        return JSONResponse({"ok": True}, headers={REFUSAL_HEADER: REFUSAL_MARKER})


class Rig:
    def __init__(self, tmp_path: Path, pol: Policy, *, gateway_link: bool = False) -> None:
        self.upstream = Upstream()
        self.store = SecretStore(tmp_path, KEYS)
        self.store.load()
        self.store.put("api-key", SECRET, origin_binding(["https://api.example"]))
        client = httpx.AsyncClient(transport=httpx.ASGITransport(app=self.upstream.app()))
        self.app = VaultApp(
            pol, self.store, KEYS, client=client, environ={}, gateway_link=gateway_link
        )

    async def call(
        self,
        method: str,
        path: str,
        *,
        listener: str | None = "tcp",
        headers: dict[str, str] | None = None,
        content: bytes = b"",
    ) -> httpx.Response:
        app: Any = self.app if listener is None else ListenerTag(self.app, cast(Listener, listener))
        transport = httpx.ASGITransport(app=app, client=("172.30.4.10", 40000))
        async with httpx.AsyncClient(transport=transport, base_url="http://vault") as client:
            return await client.request(method, path, headers=headers, content=content)


def bearer(token: str = PH) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
async def rig(tmp_path: Path) -> AsyncIterator[Rig]:
    r = Rig(tmp_path, make_policy(route(), route(name="gw", prefix="/gw", callers=["gateway"])))
    yield r
    await r.app.aclose()


# --- the refusal marker (C.4) --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("method", "path", "headers", "size", "status"),
    [
        ("GET", "/api/v1/a%2Fb", bearer(), 0, 400),
        ("GET", "/nowhere/v1/x", bearer(), 0, 404),
        ("GET", "/api/v1/x", {}, 0, 403),
        ("GET", "/api/v2/x", bearer(), 0, 403),
        ("GET", "/gw/v1/x", {GATEWAY_HEADER: "zgw1-wrong"}, 0, 403),
        ("POST", "/api/v1/x", bearer(), 10 * 1024 * 1024 + 1, 413),
    ],
)
async def test_every_refusal_is_marked(
    rig: Rig, method: str, path: str, headers: dict[str, str], size: int, status: int
) -> None:
    response = await rig.call(method, path, headers=headers, content=b"x" * size)
    assert response.status_code == status
    assert response.headers.get_list(REFUSAL_HEADER) == [REFUSAL_MARKER]
    assert rig.upstream.received == []


def test_the_wire_values() -> None:
    # A contract with the gateway, which can't import vault code (C.1, C.4).
    assert (REFUSAL_HEADER, REFUSAL_MARKER, LISTENER_SCOPE_KEY) == (
        "x-zoeymcp-vault",
        "refused",
        "zoeymcp.listener",
    )


async def test_the_marker_on_the_wire(rig: Rig) -> None:
    response = await rig.call("GET", "/nowhere/v1/x", headers=bearer())
    assert response.status_code == 404
    assert response.headers.get_list("x-zoeymcp-vault") == ["refused"]


async def test_an_upstreams_challenge_never_reaches_the_gateway(rig: Rig) -> None:
    """M7 design DD-12, X17: the vault reads an upstream's WWW-Authenticate for health; the
    gateway never gets it, so a resource_metadata reaches nothing that could start OAuth
    discovery. A placeholder caller still does."""
    gateway = await rig.call("GET", "/gw/v1/challenge", listener="gateway")
    assert gateway.status_code == 401
    assert gateway.headers.get_list("www-authenticate") == []
    direct = await rig.call("GET", "/api/v1/challenge", headers=bearer())
    assert direct.status_code == 401
    assert direct.headers.get_list("www-authenticate") == [CHALLENGE]
    assert [path for path, _ in rig.upstream.received] == ["/base/v1/challenge"] * 2


async def test_a_502_with_a_code_and_retry_after_is_marked(
    rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def refuse(*args: Any) -> Response:
        raise Refused(502, "simulated", code="oauth_unavailable", retry_after=3)

    monkeypatch.setattr(rig.app, "_handle", refuse)
    response = await rig.call("GET", "/api/v1/x", headers=bearer())
    assert response.status_code == 502
    assert response.json() == {"error": "upstream unavailable", "code": "oauth_unavailable"}
    assert response.headers[REFUSAL_HEADER] == REFUSAL_MARKER
    assert response.headers["retry-after"] == "3"


async def test_a_credential_or_upstream_failure_is_marked(tmp_path: Path) -> None:
    r = Rig(tmp_path, make_policy(route(upstream="https://other.example")))
    response = await r.call("GET", "/api/v1/x", headers=bearer())
    assert response.status_code == 502
    assert response.json()["code"] == "credential_unavailable"
    assert response.headers[REFUSAL_HEADER] == REFUSAL_MARKER
    await r.app.aclose()

    def fail(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    store = SecretStore(tmp_path / "s", KEYS)
    store.load()
    store.put("api-key", SECRET, origin_binding(["https://api.example"]))
    client = httpx.AsyncClient(transport=httpx.MockTransport(fail))
    app = VaultApp(make_policy(route()), store, KEYS, client=client, environ={})
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://vault") as caller:
        response = await caller.get("/api/v1/x", headers=bearer())
    await app.aclose()
    assert response.status_code == 502
    assert response.json() == {"error": "upstream unavailable"}
    assert response.headers[REFUSAL_HEADER] == REFUSAL_MARKER


async def test_a_connector_route_is_marked(tmp_path: Path) -> None:
    connector = {
        "name": "mail",
        "prefix": "/mail",
        "connector": "mail-out",
        "callers": [{"placeholder": PH}],
        "rules": [{"methods": ["POST"], "paths": ["/send"]}],
    }
    pol = Policy.model_validate(
        {
            "version": 1,
            "mode": "declarative",
            "routes": [connector],
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
    assert response.status_code == 400  # no Idempotency-Key: the connector's own refusal
    assert response.headers[REFUSAL_HEADER] == REFUSAL_MARKER
    await r.app.aclose()


@pytest.mark.parametrize("status", [200, 401, 403, 404, 413, 500, 502, 503])
async def test_relayed_answers_are_never_marked(rig: Rig, status: int) -> None:
    response = await rig.call("GET", f"/api/v1/status/{status}", headers=bearer())
    assert response.status_code == status
    assert response.json() == {"upstream": status}
    assert REFUSAL_HEADER not in response.headers
    assert len(rig.upstream.received) == 1


async def test_a_relayed_stream_is_never_marked(tmp_path: Path) -> None:
    r = Rig(tmp_path, make_policy(route(stream=True)))
    response = await r.call("GET", "/api/v1/sse", headers=bearer())
    assert response.status_code == 200
    assert response.text == "data: one\n\n"
    assert REFUSAL_HEADER not in response.headers
    await r.app.aclose()


# --- the listener branch (C.1) -------------------------------------------------------------------


async def test_the_link_listener_is_the_gateway(rig: Rig, captured: io.StringIO) -> None:
    response = await rig.call("GET", "/gw/v1/x", listener="gateway")
    assert response.status_code == 200
    assert REFUSAL_HEADER not in response.headers
    [line] = requests(captured)
    assert (line["listener"], line["caller"], line["status"]) == ("gateway", "gateway", 200)
    assert rig.upstream.received[0][1]["authorization"] == f"Bearer {SECRET}"


async def test_a_placeholder_is_refused_on_the_link(rig: Rig, captured: io.StringIO) -> None:
    response = await rig.call("GET", "/api/v1/x", listener="gateway", headers=bearer())
    assert response.status_code == 403
    assert response.json() == {"error": "forbidden"}
    assert response.headers[REFUSAL_HEADER] == REFUSAL_MARKER
    assert rig.upstream.received == []
    [line] = requests(captured)
    assert line["listener"] == "gateway"
    assert line["reason"] == "route doesn't accept the gateway"
    assert "caller" not in line


async def test_the_link_reads_no_key(rig: Rig, monkeypatch: pytest.MonkeyPatch) -> None:
    def authenticate(key: bytes) -> bool:
        raise AssertionError("the link listener must not try a key")

    monkeypatch.setattr(rig.app.gateway_keys, "authenticate", authenticate)
    for headers in ({}, {GATEWAY_HEADER: "zgw1-wrong"}, {GATEWAY_HEADER: KEYS.gateway_key(1)}):
        response = await rig.call("GET", "/gw/v1/x", listener="gateway", headers=headers)
        assert response.status_code == 200
    # The internal header is never forwarded.
    assert all(GATEWAY_HEADER not in headers for _, headers in rig.upstream.received)


async def test_a_route_for_both_sees_the_gateway_on_the_link(
    tmp_path: Path, captured: io.StringIO
) -> None:
    r = Rig(tmp_path, make_policy(route(callers=["gateway", {"placeholder": PH}])))
    assert (await r.call("GET", "/api/v1/x", listener="gateway", headers=bearer())).is_success
    assert (await r.call("GET", "/api/v1/x", headers=bearer())).is_success
    assert [(x["listener"], x["caller"]) for x in requests(captured)] == [
        ("gateway", "gateway"),
        ("tcp", "callers[1]"),
    ]
    await r.app.aclose()


async def test_tcp_refuses_a_valid_key_when_the_link_is_set(
    tmp_path: Path, captured: io.StringIO, monkeypatch: pytest.MonkeyPatch
) -> None:
    pol = make_policy(route(), route(name="gw", prefix="/gw", callers=["gateway"]))
    r = Rig(tmp_path, pol, gateway_link=True)
    tried: list[bytes] = []
    monkeypatch.setattr(r.app.gateway_keys, "authenticate", tried.append)
    for listener in ("tcp", None):
        response = await r.call(
            "GET", "/gw/v1/x", listener=listener, headers={GATEWAY_HEADER: KEYS.gateway_key(1)}
        )
        assert response.status_code == 403
        assert response.json() == {"error": "forbidden"}
        assert response.headers[REFUSAL_HEADER] == REFUSAL_MARKER
    # Also on a route that doesn't accept the gateway, and before any placeholder is tried.
    response = await r.call(
        "GET", "/api/v1/x", headers={**bearer(), GATEWAY_HEADER: KEYS.gateway_key(1)}
    )
    assert response.status_code == 403
    assert tried == []
    assert r.upstream.received == []
    assert [x["reason"] for x in requests(captured)] == ["gateway key refused on tcp"] * 3
    # Placeholders still work on TCP, and the gateway still works on the link.
    assert (await r.call("GET", "/api/v1/x", headers=bearer())).status_code == 200
    assert (await r.call("GET", "/gw/v1/x", listener="gateway")).status_code == 200
    await r.app.aclose()


async def test_tcp_accepts_a_valid_key_without_a_link(rig: Rig, captured: io.StringIO) -> None:
    response = await rig.call("GET", "/gw/v1/x", headers={GATEWAY_HEADER: KEYS.gateway_key(1)})
    assert response.status_code == 200
    [line] = requests(captured)
    assert (line["listener"], line["caller"]) == ("tcp", "gateway")


@pytest.mark.parametrize("tag", [None, "tcp", "Gateway", "gateway ", "link"])
async def test_only_the_exact_tag_is_the_link(
    rig: Rig, captured: io.StringIO, tag: str | None
) -> None:
    response = await rig.call("GET", "/gw/v1/x", listener=tag)
    assert response.status_code == 403
    assert rig.upstream.received == []
    [line] = requests(captured)
    assert line["listener"] == "tcp"
    assert line["reason"] == "no accepted identity presented"


async def test_the_tag_does_not_leak_into_the_wrapped_scope() -> None:
    seen: list[dict[str, Any]] = []

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        seen.append(dict(scope))

    original: dict[str, Any] = {"type": "http", "path": "/x"}
    tag = ListenerTag(app, "gateway")
    assert (tag.app, tag.listener) == (app, "gateway")
    await tag(original, _never, _never)
    assert seen == [{"type": "http", "path": "/x", LISTENER_SCOPE_KEY: "gateway"}]
    assert original == {"type": "http", "path": "/x"}


async def _never(*args: Any) -> Any:
    raise AssertionError("not used")
