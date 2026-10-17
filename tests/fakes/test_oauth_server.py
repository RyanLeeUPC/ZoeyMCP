"""The fake authorization server behaves like the providers it stands in for."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import threading
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from .oauth_server import (
    MISSING,
    DroppedConnection,
    FakeAuthServer,
    FakeResourceServer,
    google_style,
    spotify_style,
)

pytestmark = pytest.mark.anyio

VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class Clock:
    def __init__(self) -> None:
        self.now = 1_000_000.0

    def __call__(self) -> float:
        return self.now


def client(server: FakeAuthServer) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=server.app())
    return httpx.AsyncClient(transport=transport, base_url="https://accounts.example")


async def refresh(server: FakeAuthServer, token: str, **extra: str) -> httpx.Response:
    async with client(server) as http:
        return await http.post(
            "/token",
            data={"grant_type": "refresh_token", "refresh_token": token, **extra},
        )


async def authorize(server: FakeAuthServer, **params: str) -> httpx.Response:
    query = {
        "response_type": "code",
        "client_id": server.client_id,
        "redirect_uri": "http://127.0.0.1:8976/callback",
        "state": "fake-state",
        "code_challenge": CHALLENGE,
        "code_challenge_method": "S256",
        **params,
    }
    async with client(server) as http:
        return await http.get("/authorize", params=query)


def location_params(response: httpx.Response) -> dict[str, str]:
    query = parse_qs(urlsplit(response.headers["location"]).query)
    return {k: v[0] for k, v in query.items()}


def test_challenge_matches_rfc_7636() -> None:
    digest = hashlib.sha256(VERIFIER.encode()).digest()
    assert base64.urlsafe_b64encode(digest).rstrip(b"=").decode() == CHALLENGE


async def test_a_rotating_grant_detects_reuse() -> None:
    clock = Clock()
    server = spotify_style(clock)
    first = server.issue_grant()
    response = await refresh(server, first, client_id=server.client_id)
    body = response.json()
    second = body["refresh_token"]
    assert second != first
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == 3600
    assert body["scope"] == "user-read-currently-playing user-top-read"
    assert server.access_ok(body["access_token"])
    reused = await refresh(server, first, client_id=server.client_id)
    assert reused.status_code == 400
    assert reused.json()["error"] == "invalid_grant"
    # Reuse revoked the whole family, the active token included.
    assert (await refresh(server, second, client_id=server.client_id)).status_code == 400
    assert not server.access_ok(body["access_token"])


async def test_the_grace_window_returns_the_same_successor() -> None:
    clock = Clock()
    server = spotify_style(clock, grace_seconds=10)
    first = server.issue_grant()
    second = (await refresh(server, first, client_id=server.client_id)).json()["refresh_token"]
    clock.now += 10
    again = await refresh(server, first, client_id=server.client_id)
    assert again.json()["refresh_token"] == second
    clock.now += 0.001
    assert (await refresh(server, first, client_id=server.client_id)).status_code == 400


async def test_omitted_refresh_tokens_and_the_grant_lifetime() -> None:
    clock = Clock()
    server = spotify_style(clock, omit_refresh_every=2)
    token = server.issue_grant()
    one = (await refresh(server, token, client_id=server.client_id)).json()
    assert "refresh_token" in one
    two = (await refresh(server, one["refresh_token"], client_id=server.client_id)).json()
    assert "refresh_token" not in two
    clock.now += 180 * 86400
    expired = await refresh(server, one["refresh_token"], client_id=server.client_id)
    assert expired.status_code == 400


async def test_google_style_needs_offline_consent_for_a_refresh_token() -> None:
    server = google_style(Clock())
    online = location_params(await authorize(server))
    offline = location_params(await authorize(server, access_type="offline", prompt="consent"))
    async with client(server) as http:
        exchanged = []
        for code in (online["code"], offline["code"]):
            response = await http.post(
                "/token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": "http://127.0.0.1:8976/callback",
                    "code_verifier": VERIFIER,
                    "client_id": server.client_id,
                    "client_secret": "fake-google-client-secret",
                },
            )
            exchanged.append(response.json())
    assert "refresh_token" not in exchanged[0]
    assert "refresh_token" in exchanged[1]
    assert server.calls[-1].auth == "body"


async def test_a_code_is_single_use_and_checked() -> None:
    server = spotify_style(Clock())
    code = location_params(await authorize(server))["code"]
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": "http://127.0.0.1:8976/callback",
        "code_verifier": VERIFIER,
        "client_id": server.client_id,
    }
    async with client(server) as http:
        wrong = await http.post("/token", data={**form, "code_verifier": "x" * 43})
        assert wrong.status_code == 400
        # The failed attempt used the code up.
        assert (await http.post("/token", data=form)).status_code == 400
        fresh = location_params(await authorize(server))["code"]
        bad_redirect = {**form, "code": fresh, "redirect_uri": "http://127.0.0.1/callback"}
        assert (await http.post("/token", data=bad_redirect)).status_code == 400
        good = location_params(await authorize(server))["code"]
        assert (await http.post("/token", data={**form, "code": good})).status_code == 200


@pytest.mark.parametrize(
    ("params", "status"),
    [
        ({}, 302),
        ({"code_challenge_method": "plain"}, 302),
        ({"redirect_uri": "http://127.0.0.1/callback"}, 302),
        ({"redirect_uri": "http://localhost:8976/callback"}, 400),
        ({"redirect_uri": "http://127.0.0.1:8976/other"}, 400),
        ({"client_id": "someone-else"}, 400),
    ],
)
async def test_authorize_checks(params: dict[str, str], status: int) -> None:
    server = spotify_style(Clock(), issuer="https://accounts.example")
    response = await authorize(server, **params)
    assert response.status_code == status
    if status == 302:
        got = location_params(response)
        if params.get("code_challenge_method") == "plain":
            assert got == {"error": "invalid_request", "state": "fake-state"}
        else:
            assert set(got) == {"code", "state", "iss"}


@pytest.mark.parametrize(
    ("auth", "headers", "data", "ok"),
    [
        ("basic", {"authorization": "Basic YXBwOmZha2Utc2VjcmV0"}, {}, True),
        ("basic", {}, {"client_id": "app", "client_secret": "fake-secret"}, False),
        ("post", {}, {"client_id": "app", "client_secret": "fake-secret"}, True),
        ("post", {"authorization": "Basic YXBwOmZha2Utc2VjcmV0"}, {}, False),
        ("none", {}, {"client_id": "app"}, True),
        ("none", {}, {"client_id": "app", "client_secret": "fake-secret"}, False),
    ],
)
async def test_client_authentication_is_enforced(
    auth: Any, headers: dict[str, str], data: dict[str, str], ok: bool
) -> None:
    server = FakeAuthServer(Clock(), client_id="app", client_secret="fake-secret", auth=auth)
    async with client(server) as http:
        response = await http.post(
            "/token", data={"grant_type": "client_credentials", **data}, headers=headers
        )
    assert (response.status_code == 200) is ok
    if not ok:
        assert response.json() == {"error": "invalid_client"}
        has_challenge = "www-authenticate" in response.headers
        assert has_challenge is ("authorization" in headers)


async def test_hostile_knobs() -> None:
    server = spotify_style(Clock(), expires_in=MISSING, token_type=MISSING)
    token = server.issue_grant()
    body = (await refresh(server, token, client_id=server.client_id)).json()
    assert "expires_in" not in body
    assert "token_type" not in body
    server.fail_next(1, 429, retry_after="7")
    limited = await refresh(server, body["refresh_token"], client_id=server.client_id)
    assert (limited.status_code, limited.headers["retry-after"]) == (429, "7")
    server.redirect_token = "https://elsewhere.example/token"
    moved = await refresh(server, body["refresh_token"], client_id=server.client_id)
    assert moved.status_code == 307
    server.redirect_token = None
    server.drop_after_processing = 1
    with pytest.raises(DroppedConnection):
        await refresh(server, body["refresh_token"], client_id=server.client_id)


async def test_a_latch_holds_token_calls_until_another_thread_sets_it() -> None:
    server = spotify_style(Clock())
    server.latch = latch = threading.Event()
    call = asyncio.create_task(refresh(server, server.issue_grant(), client_id=server.client_id))
    await server.arrived()
    await asyncio.sleep(0.05)
    assert not call.done()
    assert server.calls[-1].status == 0
    await asyncio.to_thread(latch.set)
    assert (await call).status_code == 200


async def test_dropped_access_tokens_leave_the_refresh_token_working() -> None:
    server = spotify_style(Clock())
    body = (await refresh(server, server.issue_grant(), client_id=server.client_id)).json()
    server.drop_access_tokens()
    assert not server.access_ok(body["access_token"])
    again = await refresh(server, body["refresh_token"], client_id=server.client_id)
    assert again.status_code == 200
    assert server.access_ok(again.json()["access_token"])


async def test_revocation_and_the_resource_server() -> None:
    server = spotify_style(Clock())
    resource = FakeResourceServer(server)
    token = server.issue_grant()
    access = (await refresh(server, token, client_id=server.client_id)).json()["access_token"]
    transport = httpx.ASGITransport(app=resource.app())
    async with httpx.AsyncClient(transport=transport, base_url="https://api.example") as api:
        ok = await api.get("/v1/me", headers={"authorization": f"Bearer {access}"})
        assert ok.status_code == 200
        forbidden = await api.get("/forbidden", headers={"authorization": f"Bearer {access}"})
        assert forbidden.status_code == 403
        resource.echo_token = True
        echoed = await api.get("/v1/me", headers={"authorization": f"Bearer {access}"})
        assert echoed.json()["token"] == access
        async with client(server) as http:
            assert (await http.post("/revoke", data={"token": access})).status_code == 200
        denied = await api.get("/v1/me", headers={"authorization": f"Bearer {access}"})
        assert denied.status_code == 401
        assert denied.headers["www-authenticate"] == 'Bearer error="invalid_token"'
    assert len(resource.received) == 4
