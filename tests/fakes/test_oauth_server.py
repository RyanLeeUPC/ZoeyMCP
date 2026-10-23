"""The fake authorization server behaves like the providers it stands in for."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import html
import json
import re
import threading
from pathlib import Path
from typing import Any, get_args
from urllib.parse import parse_qs, urlsplit

import anyio
import httpx
import pytest

from zoeymcp.common.policy.load import parse_policy
from zoeymcp.vault import netclient

from . import run_oauth_server
from .harness import serve
from .oauth_server import (
    BIDI_OVERRIDE,
    CHANGED_REDIRECT,
    INJECTED_DESCRIPTION,
    LOOPBACK_ENDPOINT,
    METADATA_ELSEWHERE,
    MISSING,
    OTHER_ISSUER,
    REGISTRATION_ACCESS_TOKEN,
    REGISTRATION_CLIENT_PATH,
    SINGLE_LABEL_ENDPOINT,
    AuthSwitch,
    DroppedConnection,
    FakeAuthServer,
    FakeResourceServer,
    Registration,
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


async def test_the_callbacks_answers() -> None:
    """The answer switches for the portal's callback tests (M5 design O.1)."""
    server = FakeAuthServer(Clock(), client_id="app", issuer="https://accounts.example")
    plain = location_params(await authorize(server))
    assert set(plain) == {"code", "state", "iss"}
    server.answer = "error"
    server.error_description = "No" + chr(0x202E) + " thanks"
    denied = location_params(await authorize(server))
    assert denied == {
        "error": "access_denied",
        "error_description": "No" + chr(0x202E) + " thanks",
        "state": "fake-state",
    }
    server.answer = "wrong_iss"
    assert location_params(await authorize(server))["iss"] == "https://other-issuer.example"
    server.answer = "no_code"
    assert set(location_params(await authorize(server))) == {"state", "iss"}
    server.answer = "two_codes"
    response = await authorize(server)
    assert len(parse_qs(urlsplit(response.headers["location"]).query)["code"]) == 2
    server.answer = "fragment"
    location = (await authorize(server)).headers["location"]
    assert "?" not in location
    assert "#code=" in location
    # A second approval of the same request is another code for it; exchanges counts the codes
    # presented at /token.
    server.answer = "code"
    first = location_params(await authorize(server))["code"]
    second = location_params(await authorize(server))["code"]
    assert first != second
    assert server.exchanges == 0
    async with client(server) as http:
        await http.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": first,
                "redirect_uri": "http://127.0.0.1:8976/callback",
                "code_verifier": VERIFIER,
                "client_id": "app",
            },
        )
    assert server.exchanges == 1


# --- the consent page (D-183) -------------------------------------------------------------------

HIDDEN = re.compile(r'<input type="hidden" name="([^"]*)" value="([^"]*)">')


def form_fields(page: str) -> dict[str, str]:
    return {html.unescape(name): html.unescape(value) for name, value in HIDDEN.findall(page)}


async def test_a_consent_page_comes_before_the_answer() -> None:
    server = FakeAuthServer(Clock(), client_id="app", issuer="https://accounts.example")
    server.consent = True
    hostile = 'fake"><script>alert(1)</script>'
    page = await authorize(server, state=hostile, scope="notes.read")
    assert page.status_code == 200
    assert page.headers["content-type"].startswith("text/html")
    assert page.headers["cache-control"] == "no-store"
    assert '<form method="post" action="/authorize">' in page.text
    assert "<script>" not in page.text
    fields = form_fields(page.text)
    assert (fields["client_id"], fields["state"], fields["scope"]) == ("app", hostile, "notes.read")
    async with client(server) as http:
        approved = await http.post("/authorize", data=fields)
    assert approved.status_code == 302
    assert approved.headers["location"].startswith("http://127.0.0.1:8976/callback?")
    # The first value the fake issued: nothing was issued before the post.
    assert location_params(approved) == {
        "code": "fake-code-1",
        "state": hostile,
        "iss": "https://accounts.example",
    }


async def test_consent_is_off_by_default_and_the_checks_come_first() -> None:
    server = FakeAuthServer(Clock(), client_id="app")
    async with client(server) as http:
        refused = await http.post("/authorize", data={"client_id": "app"})
    assert refused.status_code == 405
    assert (await authorize(server)).status_code == 302
    server.consent = True
    assert (await authorize(server, client_id="someone-else")).status_code == 400
    invalid = await authorize(server, code_challenge_method="plain")
    assert invalid.status_code == 302
    assert location_params(invalid) == {"error": "invalid_request", "state": "fake-state"}


def test_the_runner_builds_the_fake_its_arguments_describe(tmp_path: Path) -> None:
    address = "http://localhost:8081/oauth/callback/notes"
    plain = run_oauth_server.parse(["--dir", str(tmp_path)])
    assert run_oauth_server.provider_of(plain) == "https://localhost:9443"
    named = run_oauth_server.parse(["--dir", str(tmp_path), "--host", "localtest.me"])
    assert run_oauth_server.provider_of(named) == "https://localtest.me:9443"
    fake = run_oauth_server.fake_for(plain, address)
    assert (fake.consent, fake.issuer, fake.iss_supported) == (False, None, False)
    assert (fake.registration, fake.switches, fake.registered_redirect) == ("open", set(), address)
    argv = ["--dir", str(tmp_path), "--consent", "--metadata", "--issuer-path", "/tenant"]
    argv += ["--iss", "--registration", "none", "--switch", "stall", "--switch", "wrong_issuer"]
    args = run_oauth_server.parse(argv)
    provider = run_oauth_server.provider_of(args)
    assert provider == "https://127.0.0.1:9443"
    fake = run_oauth_server.fake_for(args, address)
    assert (fake.consent, fake.issuer, fake.iss_supported) == (True, f"{provider}/tenant", True)
    assert fake.registration == "none"
    assert fake.switches == {AuthSwitch.STALL, AuthSwitch.WRONG_ISSUER}
    # The policy it writes loads, and lists the provider in egress_private as the vault's address
    # guard keys it (the provider is on loopback), on localhost and on 127.0.0.1.
    for origin in (run_oauth_server.provider_of(plain), provider):
        document = run_oauth_server.policy(origin, 8081, "notes")
        loaded = parse_policy(json.dumps(document), "policy.json")
        token_url = loaded.credentials["notes"].token_url  # type: ignore[union-attr]
        assert token_url == f"{origin}/token"
        assert loaded.egress_private == [netclient.destination_key(token_url)]


# --- metadata (M7 design O.1) -------------------------------------------------------------------

ISSUER = "https://accounts.example"
PUBLIC_REQUEST: dict[str, Any] = {
    "client_name": "ZoeyMCP (notes)",
    "redirect_uris": ["http://127.0.0.1/callback/notes"],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "none",
    "application_type": "native",
    "scope": "notes.read offline_access",
}
CANDIDATES = [
    "/.well-known/oauth-authorization-server/tenant",
    "/.well-known/openid-configuration/tenant",
    "/tenant/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/.well-known/openid-configuration",
]


async def get(server: FakeAuthServer, path: str) -> httpx.Response:
    async with client(server) as http:
        return await http.get(path)


async def register(
    server: FakeAuthServer, body: Any, headers: dict[str, str] | None = None
) -> httpx.Response:
    content = body if isinstance(body, bytes) else json.dumps(body).encode()
    async with client(server) as http:
        return await http.post(
            "/register",
            content=content,
            headers={"content-type": "application/json", **(headers or {})},
        )


async def test_metadata_at_the_root() -> None:
    server = FakeAuthServer(Clock(), client_id="app", issuer=ISSUER, scopes=("notes.read",))
    oauth = await get(server, "/.well-known/oauth-authorization-server")
    oidc = await get(server, "/.well-known/openid-configuration")
    assert (oauth.status_code, oidc.status_code) == (200, 200)
    assert oauth.headers["content-type"] == "application/json"
    assert oauth.json() == oidc.json() == server.metadata()
    methods = ["none", "client_secret_basic", "client_secret_post"]
    assert oauth.json() == {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/authorize",
        "token_endpoint": f"{ISSUER}/token",
        "revocation_endpoint": f"{ISSUER}/revoke",
        "registration_endpoint": f"{ISSUER}/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": methods,
        "revocation_endpoint_auth_methods_supported": methods,
        "authorization_response_iss_parameter_supported": False,
        "scopes_supported": ["notes.read"],
    }
    server.endpoint_base = "https://login.example"
    moved = (await get(server, "/.well-known/oauth-authorization-server")).json()
    assert (moved["issuer"], moved["token_endpoint"]) == (ISSUER, "https://login.example/token")


async def test_endpoints_under_a_path_of_this_server() -> None:
    """An endpoint_base with a path on the fake's own origin (``--endpoint-path``, manual check
    17's long URLs) serves the endpoints there, and still at the root."""
    server = FakeAuthServer(Clock(), client_id="app", issuer=ISSUER)
    server.endpoint_base = f"{ISSUER}/tenant/a"
    document = (await get(server, "/.well-known/oauth-authorization-server")).json()
    assert document["token_endpoint"] == f"{ISSUER}/tenant/a/token"
    async with client(server) as http:
        # A token request with no client: refused by the endpoint, the same way at both paths.
        answers = [
            (await http.post(path, data={"grant_type": "authorization_code"})).status_code
            for path in ("/tenant/a/token", "/token")
        ]
        assert answers[0] == answers[1] != 404, answers
        assert (await http.post("/tenant/b/token", data={})).status_code == 404


@pytest.mark.parametrize(
    ("forms", "answering"),
    [
        (("oauth", "oidc"), CANDIDATES[:2]),
        (("oidc_appended",), CANDIDATES[2:3]),
        (("oauth", "oidc", "oidc_appended"), CANDIDATES[:3]),
    ],
)
async def test_metadata_at_a_path_suffixed_issuer(forms: Any, answering: list[str]) -> None:
    server = FakeAuthServer(Clock(), client_id="app", issuer=f"{ISSUER}/tenant")
    server.metadata_forms = forms
    found = [path for path in CANDIDATES if (await get(server, path)).status_code == 200]
    assert found == answering
    assert (await get(server, answering[0])).json()["issuer"] == f"{ISSUER}/tenant"


async def test_no_issuer_no_metadata() -> None:
    server = FakeAuthServer(Clock(), client_id="app")
    assert [(await get(server, path)).status_code for path in CANDIDATES] == [404] * 5
    with pytest.raises(ValueError, match="no issuer"):
        server.metadata()


@pytest.mark.parametrize(
    ("switch", "check"),
    [
        (AuthSwitch.WRONG_ISSUER, lambda d: d["issuer"] == OTHER_ISSUER),
        (AuthSwitch.ENDPOINT_LOOPBACK, lambda d: d["token_endpoint"] == LOOPBACK_ENDPOINT),
        (
            AuthSwitch.ENDPOINT_SINGLE_LABEL,
            lambda d: d["token_endpoint"] == SINGLE_LABEL_ENDPOINT,
        ),
        (AuthSwitch.PKCE_ABSENT, lambda d: "code_challenge_methods_supported" not in d),
        (AuthSwitch.PKCE_PLAIN, lambda d: d["code_challenge_methods_supported"] == ["plain"]),
        (AuthSwitch.DPOP_ALGS, lambda d: d["dpop_signing_alg_values_supported"] == ["ES256"]),
    ],
)
async def test_hostile_metadata(switch: AuthSwitch, check: Any) -> None:
    server = FakeAuthServer(Clock(), client_id="app", issuer=ISSUER)
    server.switches = {switch}
    response = await get(server, "/.well-known/oauth-authorization-server")
    assert response.status_code == 200
    assert check(response.json())


async def test_metadata_that_isnt_a_document() -> None:
    server = FakeAuthServer(Clock(), client_id="app", issuer=ISSUER)
    path = "/.well-known/oauth-authorization-server"
    server.switches = {AuthSwitch.METADATA_NOT_JSON}
    not_json = await get(server, path)
    assert not_json.headers["content-type"] == "application/json"
    with pytest.raises(ValueError):  # noqa: PT011
        json.loads(not_json.content)
    server.switches = {AuthSwitch.METADATA_ARRAY}
    assert (await get(server, path)).json() == [server.metadata()]
    server.switches = {AuthSwitch.METADATA_OVERSIZED}
    assert len((await get(server, path)).content) > 64 * 1024
    server.switches = {AuthSwitch.METADATA_REDIRECT}
    moved = await get(server, path)
    assert (moved.status_code, moved.headers["location"]) == (302, METADATA_ELSEWHERE)


# --- registration (RFC 7591) --------------------------------------------------------------------


MODE_ROWS: list[tuple[Registration, bool, int]] = [
    ("open", True, 201),
    ("none", False, 404),
    ("confidential_only", True, 400),
    ("cimd_only", False, 404),
    ("needs_initial_token", True, 401),
]


@pytest.mark.parametrize(("mode", "endpoint", "status"), MODE_ROWS)
async def test_registration_modes(mode: Registration, endpoint: bool, status: int) -> None:
    server = FakeAuthServer(Clock(), client_id="app", issuer=ISSUER, registration=mode)
    document = server.metadata()
    assert ("registration_endpoint" in document) is endpoint
    assert ("client_id_metadata_document_supported" in document) is (mode == "cimd_only")
    methods = document["token_endpoint_auth_methods_supported"]
    assert ("none" in methods) is (mode != "confidential_only")
    assert (await register(server, PUBLIC_REQUEST)).status_code == status


def test_every_registration_mode_is_tested() -> None:
    modes = {row[0] for row in MODE_ROWS}
    assert modes == set(get_args(Registration)) == set(run_oauth_server.REGISTRATIONS)


async def test_an_initial_token_or_a_confidential_client_registers() -> None:
    server = FakeAuthServer(Clock(), client_id="app", issuer=ISSUER)
    server.registration = "needs_initial_token"
    bearer = {"authorization": "Bearer fake-initial-token"}
    assert (await register(server, PUBLIC_REQUEST, bearer)).status_code == 201
    server.registration = "confidential_only"
    confidential = {**PUBLIC_REQUEST, "token_endpoint_auth_method": "client_secret_post"}
    answer = (await register(server, confidential)).json()
    assert answer["token_endpoint_auth_method"] == "client_secret_post"
    assert answer["client_secret"].startswith("fake-secret-")
    assert answer["client_secret_expires_at"] == 0


async def test_a_registered_public_client_logs_in() -> None:
    server = FakeAuthServer(Clock(), client_id="app", auth="none", issuer=ISSUER)
    answer = (await register(server, PUBLIC_REQUEST)).json()
    assert answer == {
        "client_id": "fake-client-1",
        "client_id_issued_at": 1_000_000,
        "redirect_uris": ["http://127.0.0.1/callback/notes"],
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "client_name": "ZoeyMCP (notes)",
        "scope": "notes.read offline_access",
        "application_type": "native",
    }
    redirect = "http://127.0.0.1:8976/callback/notes"
    assert (await authorize(server, client_id="fake-client-1")).status_code == 400
    form = {
        "grant_type": "authorization_code",
        "redirect_uri": redirect,
        "code_verifier": VERIFIER,
        "client_id": "fake-client-1",
    }
    async with client(server) as http:
        first = location_params(
            await authorize(server, client_id="fake-client-1", redirect_uri=redirect)
        )
        # A code issued to one client isn't another client's.
        other = await http.post("/token", data={**form, "code": first["code"], "client_id": "app"})
        assert other.status_code == 400
        second = location_params(
            await authorize(server, client_id="fake-client-1", redirect_uri=redirect)
        )
        ok = await http.post("/token", data={**form, "code": second["code"]})
    assert ok.status_code == 200
    assert "refresh_token" in ok.json()


async def test_a_registered_confidential_client_authenticates_its_way() -> None:
    server = FakeAuthServer(Clock(), client_id="app", issuer=ISSUER)
    asked = {**PUBLIC_REQUEST, "token_endpoint_auth_method": "client_secret_basic"}
    answer = (await register(server, asked)).json()
    client_id, secret = answer["client_id"], answer["client_secret"]
    basic = base64.b64encode(f"{client_id}:{secret}".encode()).decode()
    async with client(server) as http:
        good = await http.post(
            "/token",
            data={"grant_type": "client_credentials"},
            headers={"authorization": f"Basic {basic}"},
        )
        in_body = await http.post(
            "/token",
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": secret,
            },
        )
    assert (good.status_code, in_body.status_code) == (200, 401)


@pytest.mark.parametrize(
    ("body", "error"),
    [
        (b"not json", "invalid_client_metadata"),
        (b"[]", "invalid_client_metadata"),
        ({**PUBLIC_REQUEST, "redirect_uris": []}, "invalid_redirect_uri"),
        ({**PUBLIC_REQUEST, "redirect_uris": [7]}, "invalid_redirect_uri"),
        (
            {**PUBLIC_REQUEST, "token_endpoint_auth_method": "private_key_jwt"},
            "invalid_client_metadata",
        ),
    ],
)
async def test_registration_refusals(body: Any, error: str) -> None:
    server = FakeAuthServer(Clock(), client_id="app", issuer=ISSUER)
    response = await register(server, body)
    assert response.status_code == 400
    assert response.json()["error"] == error
    assert server.registered == {}


@pytest.mark.parametrize(
    ("switch", "check"),
    [
        (AuthSwitch.DCR_REDIRECT_CHANGED, lambda a: a["redirect_uris"] == [CHANGED_REDIRECT]),
        (
            AuthSwitch.DCR_PRIVATE_KEY_JWT,
            lambda a: a["token_endpoint_auth_method"] == "private_key_jwt",
        ),
        (AuthSwitch.DCR_SECRET_FOR_NONE, lambda a: a["client_secret"] == "fake-secret-2"),
        (AuthSwitch.DCR_CLIENT_ID_SPACE, lambda a: a["client_id"] == "fake-client 1"),
        (
            AuthSwitch.DCR_CLIENT_ID_BIDI,
            lambda a: a["client_id"] == "fake-client-1" + BIDI_OVERRIDE,
        ),
        (
            AuthSwitch.DCR_ACCESS_TOKEN,
            lambda a: (
                (a["registration_access_token"], a["registration_client_uri"])
                == (REGISTRATION_ACCESS_TOKEN, ISSUER + REGISTRATION_CLIENT_PATH)
            ),
        ),
    ],
)
async def test_hostile_registration_answers(switch: AuthSwitch, check: Any) -> None:
    server = FakeAuthServer(Clock(), client_id="app", issuer=ISSUER)
    server.switches = {switch}
    response = await register(server, PUBLIC_REQUEST)
    assert response.status_code == 201
    assert check(response.json())


async def test_a_registration_error_with_injected_text() -> None:
    server = FakeAuthServer(Clock(), client_id="app", issuer=ISSUER)
    server.switches = {AuthSwitch.DCR_ERROR_INJECTED}
    response = await register(server, PUBLIC_REQUEST)
    assert response.status_code == 400
    description = response.json()["error_description"]
    assert description == INJECTED_DESCRIPTION
    assert "\r\n" in description
    assert BIDI_OVERRIDE in description
    assert "<b>" in description


# --- iss on every answer (RFC 9207) -------------------------------------------------------------


async def test_iss_on_error_answers_when_advertised() -> None:
    server = FakeAuthServer(Clock(), client_id="app", issuer=ISSUER, iss_supported=True)
    assert server.metadata()["authorization_response_iss_parameter_supported"] is True
    assert location_params(await authorize(server))["iss"] == ISSUER
    invalid = location_params(await authorize(server, code_challenge_method="plain"))
    assert invalid["iss"] == ISSUER
    server.answer = "error"
    assert location_params(await authorize(server))["iss"] == ISSUER
    server.switches = {AuthSwitch.ISS_WRONG_ON_ERROR}
    assert location_params(await authorize(server))["iss"] == OTHER_ISSUER
    server.switches = {AuthSwitch.ISS_MISSING}
    assert "iss" not in location_params(await authorize(server))
    server.answer = "code"
    assert "iss" not in location_params(await authorize(server))
    # Not advertised, an error answer carries no iss, as before.
    quiet = FakeAuthServer(Clock(), client_id="app", issuer=ISSUER)
    quiet.answer = "error"
    assert "iss" not in location_params(await authorize(quiet))


# --- stall and trickle (FM-5, FM-6, FM-9) -------------------------------------------------------


@pytest.mark.parametrize("switch", [AuthSwitch.STALL, AuthSwitch.STALL_REGISTER])
async def test_a_stall_holds_only_its_own_answer(switch: AuthSwitch) -> None:
    """STALL hangs the metadata (FM-5) and STALL_REGISTER the registration (FM-9); each
    leaves the other answering."""
    server = FakeAuthServer(Clock(), client_id="app", issuer="http://127.0.0.1")
    server.switches = {switch}
    timeout = httpx.Timeout(5.0, read=0.3)
    metadata = "/.well-known/oauth-authorization-server"
    with serve(server.app()) as base, anyio.fail_after(10):
        async with httpx.AsyncClient(base_url=base, timeout=timeout) as http:
            if switch == AuthSwitch.STALL:
                with pytest.raises(httpx.ReadTimeout):
                    await http.get(metadata)
                answered = await http.post("/register", json=PUBLIC_REQUEST)
                expected = 201
            else:
                with pytest.raises(httpx.ReadTimeout):
                    await http.post("/register", json=PUBLIC_REQUEST)
                answered = await http.get(metadata)
                expected = 200
            server.switches = set()
            after = await http.get(metadata)
    assert answered.status_code == expected
    assert after.status_code == 200


async def test_trickled_metadata_arrives_a_byte_at_a_time() -> None:
    """Each read finishes well inside a per-read timeout; only a total deadline ends it."""
    server = FakeAuthServer(Clock(), client_id="app", issuer="http://127.0.0.1")
    server.switches = {AuthSwitch.TRICKLE}
    server.trickle_interval = 0.05
    expected = json.dumps(server.metadata()).encode()
    chunks: list[bytes] = []
    timeout = httpx.Timeout(5.0, read=1.0)
    with serve(server.app()) as base, anyio.fail_after(10):
        async with (
            httpx.AsyncClient(base_url=base, timeout=timeout) as http,
            http.stream("GET", "/.well-known/oauth-authorization-server") as response,
        ):
            assert response.status_code == 200
            async for chunk in response.aiter_raw():
                chunks.append(chunk)
                if len(chunks) == 5:
                    break
    received = b"".join(chunks)
    assert received == expected[: len(received)]
    assert len(received) < 20 < len(expected)


async def test_every_request_is_seen() -> None:
    server = FakeAuthServer(Clock(), client_id="app", issuer=ISSUER)
    await get(server, "/.well-known/openid-configuration")
    await register(server, PUBLIC_REQUEST)
    await authorize(server)
    async with client(server) as http:
        await http.post("/nowhere", content=b"x")
    assert [(s.method, s.path) for s in server.seen] == [
        ("GET", "/.well-known/openid-configuration"),
        ("POST", "/register"),
        ("GET", "/authorize"),
        ("POST", "/nowhere"),
    ]
    [registration] = server.registrations
    assert json.loads(registration.body) == PUBLIC_REQUEST
    assert registration.headers["content-type"] == "application/json"
    assert "state=fake-state" in server.seen[2].query
    assert server.seen[3].body == b"x"
