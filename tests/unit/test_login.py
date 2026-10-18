"""Effect tests for ``zoeymcp login`` in the vault (design E.1-E.3, D.15).

The token endpoint is the stateful fake authorization server over ``ASGITransport``, and the
test plays the browser: it opens the authorization URL on the fake and pastes the address it is
redirected to. Flow IDs, ``state`` and verifiers come from a counter, so every value is known.
"""

from __future__ import annotations

import asyncio
import json
import math
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit

import httpx
import pytest

from tests.fakes.oauth_server import FakeAuthServer, google_style, spotify_style
from zoeymcp.common.policy import Policy
from zoeymcp.common.policy.schema import OAuth2Credential
from zoeymcp.vault import logs
from zoeymcp.vault.bindings import live_slot, oauth_binding
from zoeymcp.vault.oauth import login as login_module
from zoeymcp.vault.oauth.login import (
    CODE_HINT,
    NO_REFRESH_HINT,
    LoginError,
    LoginService,
    hint,
    reconsent_due,
    scope_health,
    seed_note,
)
from zoeymcp.vault.oauth.pkce import MAX_FLOWS, authorize_url, code_challenge
from zoeymcp.vault.oauth.protocol import (
    CREDENTIAL_UNAVAILABLE,
    OAUTH_CLIENT_REJECTED,
    OAUTH_MISCONFIGURED,
    OAUTH_RECONSENT_NEEDED,
    OAUTH_ROTATION_LOST,
    OAUTH_UNAVAILABLE,
    OAUTH_UNSUPPORTED,
    parse_envelope,
    seed_sha256,
)
from zoeymcp.vault.oauth.tokens import TokenManager
from zoeymcp.vault.store import Secret, SecretStore

from .test_oauth_tokens import KEYS, NOW, Captured, FailingWrites, FakeClock, raising

pytestmark = pytest.mark.anyio

TOKEN_URL = "https://accounts.example/token"
AUTHORIZE_URL = "https://accounts.example/authorize"
REDIRECT = "http://127.0.0.1/callback"
API = "https://api.example/v1"
API_ORIGIN = "https://api.example:443"
OTHER = "https://other.example/v2"
SPOTIFY_ID = "0123456789abcdef0123456789abcdef"
SPOTIFY_SCOPES = ["user-read-currently-playing", "user-top-read"]
GOOGLE_ID = "000000000000-example.apps.googleusercontent.com"
GOOGLE_SECRET = "fake-google-client-secret"
CALENDAR = "https://www.googleapis.com/auth/calendar.readonly"
BINDING = oauth_binding(TOKEN_URL, [API])
OTHER_BINDING = oauth_binding(TOKEN_URL, [OTHER])

# What the counter hands out: the flow ID, then state, then the verifier.
FLOW_ID = "fake01" + "x" * 16
STATE = "fake02" + "x" * 37
VERIFIER = "fake03" + "x" * 37

BASE: dict[str, Any] = {
    "version": 1,
    "mode": "declarative",
    "admin": {"listen": "0.0.0.0:8081", "hosts": ["localhost"]},
}


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def captured() -> Iterator[Captured]:
    capture = Captured()
    logs.set_stream(capture.stream)
    try:
        yield capture
    finally:
        logs.set_stream(None)


@pytest.fixture
def writes(monkeypatch: pytest.MonkeyPatch) -> FailingWrites:
    return FailingWrites(monkeypatch)


class Counter:
    """Stands in for ``secrets.token_urlsafe``: fake values of the same lengths, in order."""

    def __init__(self) -> None:
        self.issued: list[str] = []

    def __call__(self, nbytes: int) -> str:
        value = f"fake{len(self.issued) + 1:02d}".ljust(math.ceil(nbytes * 4 / 3), "x")
        self.issued.append(value)
        return value


def make_policy(
    credentials: Mapping[str, Mapping[str, Any]],
    routes: Mapping[str, tuple[str, ...]] | None = None,
) -> Policy:
    """Each credential gets a route per upstream; by default one, to ``API``."""
    route_list: list[dict[str, Any]] = []
    for name in credentials:
        for upstream in (routes or {}).get(name, (API,)):
            index = len(route_list)
            route_list.append(
                {
                    "name": f"r{index}",
                    "prefix": f"/r{index}",
                    "upstream": upstream,
                    "credential": name,
                    "callers": [{"placeholder": f"ph-agent{index}-direct-0001"}],
                    "rules": [{"methods": ["GET"], "paths": ["/**"]}],
                }
            )
    return Policy.model_validate({**BASE, "routes": route_list, "credentials": dict(credentials)})


def spotify(**fields: Any) -> dict[str, Any]:
    cred: dict[str, Any] = {
        "kind": "oauth2",
        "token_url": TOKEN_URL,
        "authorize_url": AUTHORIZE_URL,
        "client_id": SPOTIFY_ID,
        "client_auth": "none",
        "rotates": True,
        "refresh_token": "store:music-refresh",
        "scope": " ".join(SPOTIFY_SCOPES),
    }
    cred.update(fields)
    return cred


def google(**fields: Any) -> dict[str, Any]:
    cred: dict[str, Any] = {
        "kind": "oauth2",
        "token_url": TOKEN_URL,
        "authorize_url": AUTHORIZE_URL,
        "client_id": GOOGLE_ID,
        "client_secret": "store:google-secret",
        "client_auth": "post",
        "refresh_token": "store:music-refresh",
        "scope": CALENDAR,
        "authorize_params": {"access_type": "offline", "prompt": "consent"},
    }
    cred.update(fields)
    return cred


def machine(**fields: Any) -> dict[str, Any]:
    """A client_credentials credential."""
    cred: dict[str, Any] = {
        "kind": "oauth2",
        "token_url": TOKEN_URL,
        "grant": "client_credentials",
        "client_id": GOOGLE_ID,
        "client_secret": "store:google-secret",
        "client_auth": "post",
        "scope": "read write",
    }
    cred.update(fields)
    return cred


class Rig:
    def __init__(
        self,
        tmp_path: Path,
        clock: FakeClock,
        policy: Policy,
        server: FakeAuthServer | None = None,
        *,
        env: Mapping[str, str] | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.clock = clock
        self.server = server or spotify_style(clock.time)
        self.policy = policy
        self.store = SecretStore(tmp_path, KEYS)
        self.store.load()
        self.client = httpx.AsyncClient(
            transport=transport or httpx.ASGITransport(app=self.server.app())
        )
        self.env = {k: Secret(v) for k, v in (env or {}).items()}
        self.manager = TokenManager(
            self.store,
            self.client,
            clock=clock.monotonic,
            wall=clock.time,
            sleep=clock.sleep,
            uniform=lambda low, high: 1.0,
        )
        self.manager.configure(policy, self.env)
        self.counter = Counter()
        self.login = LoginService(
            self.manager, clock=clock.monotonic, wall=clock.time, token=self.counter
        )

    def reconfigure(self, policy: Policy) -> None:
        self.policy = policy
        self.manager.configure(policy, self.env)

    def put_client_secret(self, value: str = GOOGLE_SECRET) -> None:
        self.store.put("google-secret", value, BINDING)

    async def browse(self, url: str) -> str:
        """Play the browser: approve, and return the address the browser is sent to."""
        transport = httpx.ASGITransport(app=self.server.app())
        async with httpx.AsyncClient(transport=transport) as browser:
            response = await browser.get(url)
        assert response.status_code == 302, response.text
        return response.headers["location"]

    async def start(self, credential: str = "music", **kwargs: Any) -> dict[str, Any]:
        return await self.login.start(credential, **kwargs)

    async def approved(self, credential: str = "music", **kwargs: Any) -> tuple[str, str]:
        """Start a login and approve it: the flow ID and the address to paste."""
        started = await self.start(credential, **kwargs)
        return started["flow"], await self.browse(started["authorize_url"])

    async def login_once(self, credential: str = "music", **kwargs: Any) -> dict[str, Any]:
        flow, pasted = await self.approved(credential, **kwargs)
        return await self.login.complete(credential, flow, pasted)

    async def refused(self, call: Any) -> LoginError:
        with pytest.raises(LoginError) as caught:
            await call
        return caught.value

    def stored(self, name: str = "music-refresh") -> str:
        return self.store.get_for_oauth(name, token_url=TOKEN_URL)[0].reveal()


def spotify_rig(tmp_path: Path, clock: FakeClock, **fields: Any) -> Rig:
    return Rig(tmp_path, clock, make_policy({"music": spotify(**fields)}))


def google_rig(tmp_path: Path, clock: FakeClock, **fields: Any) -> Rig:
    rig = Rig(tmp_path, clock, make_policy({"music": google(**fields)}), google_style(clock.time))
    rig.put_client_secret()
    return rig


def with_query(url: str, **changes: str | None) -> str:
    """``url`` with query parameters replaced (or dropped, for None)."""
    parts = urlsplit(url)
    pairs = dict(parse_qsl(parts.query))
    for key, value in changes.items():
        if value is None:
            pairs.pop(key, None)
        else:
            pairs[key] = value
    return parts._replace(query=urlencode(pairs)).geturl()


def answer(**changes: Any) -> dict[str, Any]:
    """The answer to a completed spotify-style login."""
    done: dict[str, Any] = {
        "slot": "music-refresh",
        "binding": BINDING,
        "granted_scopes": SPOTIFY_SCOPES,
        "unexpected_scopes": [],
        "missing_scopes": [],
        "access_expires_in": 3600,
        "refresh_expires_at": None,
        "consented_at": "2026-10-17T09:00:00Z",
        "grant_expires_at": None,
        "persisted": True,
        "seed_note": None,
    }
    done.update(changes)
    return done


# --- start -------------------------------------------------------------------------------------


async def test_start_answers_with_the_authorization_request(
    tmp_path: Path, clock: FakeClock, captured: Captured
) -> None:
    rig = spotify_rig(tmp_path, clock)
    started = await rig.start()
    cred = rig.policy.credentials["music"]
    assert isinstance(cred, OAuth2Credential)
    expected_url = authorize_url(cred, state=Secret(STATE), challenge=code_challenge(VERIFIER))
    assert started == {
        "flow": FLOW_ID,
        "authorize_url": expected_url,
        "redirect_uri": REDIRECT,
        "expires": int(NOW) + 600,
        "requested_scopes": SPOTIFY_SCOPES,
        "expected_scopes": SPOTIFY_SCOPES,
        "client_auth": "none",
        "rotates": True,
        "binding": BINDING,
        "binding_change": None,
    }
    assert rig.counter.issued == [FLOW_ID, STATE, VERIFIER]
    assert [
        {k: v for k, v in e.items() if k not in ("ts", "role")}
        for e in captured.events("oauth_login_started")
    ] == [{"event": "oauth_login_started", "credential": "music"}]
    # The verifier never leaves the vault, and nothing went to the token endpoint.
    assert VERIFIER not in json.dumps(started)
    assert rig.server.calls == []


async def test_start_describes_a_confidential_client(tmp_path: Path, clock: FakeClock) -> None:
    rig = google_rig(tmp_path, clock, rotates=False, expected_scopes=[CALENDAR, "extra"])
    started = await rig.start()
    assert started["client_auth"] == "post"
    assert started["rotates"] is False
    assert started["requested_scopes"] == [CALENDAR]
    assert started["expected_scopes"] == [CALENDAR, "extra"]
    query = dict(parse_qsl(urlsplit(started["authorize_url"]).query))
    assert query["access_type"] == "offline"
    assert GOOGLE_SECRET not in started["authorize_url"]


async def test_start_splits_the_scope_by_its_separator(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock, scope="a,b", scope_separator=",")
    assert (await rig.start())["requested_scopes"] == ["a", "b"]


async def test_start_without_a_scope(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock, scope=None)
    started = await rig.start()
    assert started["requested_scopes"] == []
    assert started["expected_scopes"] == []


@pytest.mark.parametrize(
    ("name", "message"),
    [
        ("nope", "no oauth2 credential named 'nope'"),
        ("static", "no oauth2 credential named 'static'"),
    ],
)
async def test_start_refuses_what_is_not_oauth(
    tmp_path: Path, clock: FakeClock, captured: Captured, name: str, message: str
) -> None:
    policy = make_policy(
        {"music": spotify(), "static": {"kind": "header", "secret": "store:static-key"}}
    )
    rig = Rig(tmp_path, clock, policy)
    refused = await rig.refused(rig.start(name))
    assert (refused.reason, str(refused), refused.details) == ("not_oauth", message, {})
    failed = captured.events("oauth_login_failed")
    assert [{k: v for k, v in e.items() if k not in ("ts", "role")} for e in failed] == [
        {"event": "oauth_login_failed", "credential": name, "reason": "not_oauth"}
    ]
    assert captured.events("oauth_login_started") == []


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        ({}, "enter the refresh token with zoeymcp secret set music-refresh"),
        (
            {"refresh_token": "env:MUSIC_REFRESH"},
            "put a new refresh token in env MUSIC_REFRESH, delete oauth.music.live with "
            "zoeymcp secret delete (reseed: never keeps it), and restart the vault",
        ),
        (
            {"refresh_token": "env:MUSIC_REFRESH", "reseed": "on-change"},
            "put a new refresh token in env MUSIC_REFRESH and restart the vault "
            "(reseed: on-change)",
        ),
    ],
    ids=["store", "env-never", "env-on-change"],
)
async def test_start_needs_an_authorize_url(
    tmp_path: Path, clock: FakeClock, fields: dict[str, Any], message: str
) -> None:
    rig = spotify_rig(tmp_path, clock, authorize_url=None, **fields)
    refused = await rig.refused(rig.start())
    assert refused.reason == "no_authorize_url"
    assert str(refused) == f"'music' has no authorize_url; {message}"


async def test_start_needs_a_route(tmp_path: Path, clock: FakeClock) -> None:
    rig = Rig(tmp_path, clock, make_policy({"music": spotify()}, {"music": ()}))
    refused = await rig.refused(rig.start())
    assert refused.reason == "no_route"
    assert "no route uses" in str(refused)


async def test_start_of_a_seeded_credential_needs_a_route(tmp_path: Path, clock: FakeClock) -> None:
    cred = spotify(refresh_token="env:MUSIC_REFRESH")
    rig = Rig(tmp_path, clock, make_policy({"music": cred}, {"music": ()}))
    refused = await rig.refused(rig.start())
    assert refused.reason == "no_route"
    assert str(refused) == (
        "no route uses credential 'music'; there is nothing to bind its access tokens to"
    )


async def test_start_needs_a_usable_client_secret(tmp_path: Path, clock: FakeClock) -> None:
    rig = Rig(tmp_path, clock, make_policy({"music": google()}), google_style(clock.time))
    refused = await rig.refused(rig.start())
    assert refused.reason == "client_secret_unavailable"
    assert str(refused) == (
        "the client secret isn't set or isn't bound to the token endpoint; "
        "enter the client secret with zoeymcp secret set google-secret"
    )
    # Bound to another token endpoint: the same refusal.
    rig.store.put("google-secret", GOOGLE_SECRET, oauth_binding("https://elsewhere.example", [API]))
    assert (await rig.refused(rig.start())).reason == "client_secret_unavailable"
    rig.put_client_secret()
    assert (await rig.start())["flow"]


async def test_an_unset_env_client_secret_is_refused(tmp_path: Path, clock: FakeClock) -> None:
    rig = Rig(
        tmp_path,
        clock,
        make_policy({"music": google(client_secret="env:GOOGLE_SECRET")}),
        google_style(clock.time),
    )
    refused = await rig.refused(rig.start())
    assert refused.reason == "client_secret_unavailable"
    assert str(refused) == (
        "the client secret isn't set or isn't bound to the token endpoint; "
        "set the client secret in env GOOGLE_SECRET and restart the vault"
    )


async def test_a_changed_binding_needs_rebind(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.store.put("music-refresh", "fake-rt-old", OTHER_BINDING)
    refused = await rig.refused(rig.start())
    assert refused.reason == "binding_changed"
    assert str(refused) == "the policy binds this grant differently; pass --rebind to accept"
    assert refused.details == {"old": OTHER_BINDING, "new": BINDING}
    started = await rig.start(rebind=True)
    assert started["binding_change"] == {"old": OTHER_BINDING, "new": BINDING}
    pasted = await rig.browse(started["authorize_url"])
    done = await rig.login.complete("music", started["flow"], pasted)
    assert done["binding"] == BINDING
    assert rig.stored() == rig.server.active_refresh_token()
    assert rig.store.entry("music-refresh").binding == BINDING  # type: ignore[union-attr]


async def test_an_unchanged_binding_needs_no_rebind(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.store.put("music-refresh", "fake-rt-old", BINDING)
    assert (await rig.start())["binding_change"] is None
    assert (await rig.start(rebind=True))["binding_change"] is None


async def test_too_many_pending_logins(tmp_path: Path, clock: FakeClock) -> None:
    names = [f"c{i}" for i in range(MAX_FLOWS + 1)]
    creds = {name: spotify(refresh_token=f"store:{name}-refresh") for name in names}
    rig = Rig(tmp_path, clock, make_policy(creds))
    for name in names[:MAX_FLOWS]:
        await rig.start(name)
    refused = await rig.refused(rig.start(names[-1]))
    assert refused.reason == "too_many_flows"
    assert str(refused) == f"at most {MAX_FLOWS} logins can be pending"
    # A new login for a pending credential replaces its flow.
    await rig.start(names[0])


# --- complete ----------------------------------------------------------------------------------


async def test_a_login_stores_the_grant_and_caches_its_access_token(
    tmp_path: Path, clock: FakeClock, captured: Captured
) -> None:
    rig = spotify_rig(tmp_path, clock)
    flow, pasted = await rig.approved()
    clock.advance(5)
    done = await rig.login.complete("music", flow, pasted)
    assert done == answer(consented_at="2026-10-17T09:00:05Z")
    [exchange] = rig.server.calls
    assert exchange.grant_type == "authorization_code"
    assert exchange.params["redirect_uri"] == REDIRECT
    assert exchange.params["code_verifier"] == VERIFIER
    assert exchange.params["client_id"] == SPOTIFY_ID
    assert rig.stored() == rig.server.active_refresh_token()
    meta = rig.store.entry("music-refresh").meta  # type: ignore[union-attr]
    assert meta is not None
    assert meta["oauth"]["source"] == "login"
    # The access token from the exchange is cached: no refresh for the first request.
    grant = await rig.manager.grant_for("music", API)
    assert rig.server.access_ok(grant.token.reveal())
    assert grant.hard_expiry == clock.mono + 3600
    assert len(rig.server.calls) == 1
    [completed] = captured.events("oauth_login_completed")
    del completed["ts"], completed["role"]
    assert completed == {
        "event": "oauth_login_completed",
        "credential": "music",
        "slot": "music-refresh",
        "binding": BINDING,
        "granted": SPOTIFY_SCOPES,
        "unexpected": [],
        "missing": [],
        "persisted": True,
    }
    assert captured.events("oauth_login_failed") == []
    assert captured.events("oauth_scope_unexpected") == []
    assert captured.events("oauth_scope_narrowed") == []
    [call] = captured.events("oauth_refresh")
    del call["ts"], call["role"]
    assert call == {
        "event": "oauth_refresh",
        "credential": "music",
        "slot": "music-refresh",
        "grant": "authorization_code",
        "trigger": "login",
        "attempt": 1,
        "replayed": False,
        "http_status": 200,
        "outcome": "ok",
        "code": None,
        "error": None,
        "error_subtype": None,
        "failure_reason": None,
        "refresh_token_issued": True,
        "expires_in": 3600,
        "lifetime": 3600,
        "duration_ms": 0.0,
    }


async def test_a_refused_exchange_is_logged_without_its_description(
    tmp_path: Path, clock: FakeClock, captured: Captured
) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.server.error_shape = "echo"
    flow, pasted = await rig.approved()
    reused = dict(parse_qsl(urlsplit(pasted).query))["code"]
    await rig.login.complete("music", flow, pasted)
    flow, fresh = await rig.approved()
    real_post = rig.manager.post

    async def slow_post(request: Any, *, deadline: float | None = None) -> Any:
        clock.advance(0.25)
        return await real_post(request, deadline=deadline)

    rig.manager.post = slow_post  # type: ignore[method-assign]
    await rig.refused(rig.login.complete("music", flow, with_query(fresh, code=reused)))
    call = captured.events("oauth_refresh")[-1]
    del call["ts"], call["role"]
    assert call == {
        "event": "oauth_refresh",
        "credential": "music",
        "slot": "music-refresh",
        "grant": "authorization_code",
        "trigger": "login",
        "attempt": 1,
        "replayed": False,
        "http_status": 400,
        "outcome": "terminal",
        "code": OAUTH_RECONSENT_NEEDED,
        "error": "invalid_grant",
        "error_subtype": None,
        "failure_reason": "provider_error",
        "refresh_token_issued": False,
        "expires_in": None,
        "lifetime": None,
        "duration_ms": 250.0,
    }
    assert reused not in captured.text
    assert "Invalid authorization code" not in captured.text


async def test_no_answer_is_logged(tmp_path: Path, clock: FakeClock, captured: Captured) -> None:
    transport, _ = raising(httpx.ConnectError)
    rig = machine_rig(tmp_path, clock)
    rig = Rig(tmp_path / "b", clock, rig.policy, transport=transport)
    rig.put_client_secret()
    await rig.refused(rig.start())
    [call] = captured.events("oauth_refresh")
    assert (call["grant"], call["slot"], call["trigger"]) == (
        "client_credentials",
        "cc:music",
        "login",
    )
    assert (call["http_status"], call["outcome"], call["code"], call["failure_reason"]) == (
        None,
        "backoff",
        OAUTH_UNAVAILABLE,
        "no_response",
    )


async def test_the_access_token_lifetime_counts_from_the_exchange(
    tmp_path: Path, clock: FakeClock
) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.server.delay = 0.0
    flow, pasted = await rig.approved()
    sent = clock.mono

    real_post = rig.manager.post

    async def slow_post(request: Any, *, deadline: float | None = None) -> Any:
        assert deadline == 20.0
        response = await real_post(request, deadline=deadline)
        clock.advance(7)
        return response

    rig.manager.post = slow_post  # type: ignore[method-assign]
    await rig.login.complete("music", flow, pasted)
    grant = await rig.manager.grant_for("music", API)
    assert grant.hard_expiry == sent + 3600
    assert grant.minted_at == sent + 7


async def test_token_calls_have_the_exchange_deadline(
    tmp_path: Path, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(login_module, "EXCHANGE_DEADLINE", 33.0)
    deadlines: list[float | None] = []
    for rig in (spotify_rig(tmp_path / "a", clock), machine_rig(tmp_path / "b", clock)):
        real_post = rig.manager.post

        async def spy(request: Any, *, deadline: float | None = None, post: Any = real_post) -> Any:
            deadlines.append(deadline)
            return await post(request, deadline=deadline)

        rig.manager.post = spy  # type: ignore[method-assign]
        if rig.policy.credentials["music"].grant == "client_credentials":  # type: ignore[union-attr]
            await rig.start()
        else:
            await rig.login_once()
    assert deadlines == [33.0, 33.0]


async def test_a_flow_is_used_once(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock)
    flow, pasted = await rig.approved()
    await rig.login.complete("music", flow, pasted)
    refused = await rig.refused(rig.login.complete("music", flow, pasted))
    assert refused.reason == "flow_unknown"
    assert str(refused) == "no such login is pending (it expired or was used); run login again"
    assert len(rig.server.calls) == 1


async def test_unknown_expired_and_foreign_flows_get_one_answer(
    tmp_path: Path, clock: FakeClock, captured: Captured
) -> None:
    policy = make_policy(
        {"music": spotify(), "files": spotify(refresh_token="store:files-refresh")}
    )
    rig = Rig(tmp_path, clock, policy)
    flow, pasted = await rig.approved()
    unknown = await rig.refused(rig.login.complete("music", "nope", pasted))
    foreign = await rig.refused(rig.login.complete("files", flow, pasted))
    flow, pasted = await rig.approved()
    clock.advance(600)
    expired = await rig.refused(rig.login.complete("music", flow, pasted))
    assert {(e.reason, str(e)) for e in (unknown, foreign, expired)} == {
        ("flow_unknown", "no such login is pending (it expired or was used); run login again")
    }
    assert rig.server.calls == []
    reasons = [(e["credential"], e["reason"]) for e in captured.events("oauth_login_failed")]
    assert reasons == [
        ("music", "flow_unknown"),
        ("files", "flow_unknown"),
        ("music", "flow_unknown"),
    ]


async def test_a_flow_just_inside_its_lifetime_completes(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock)
    flow, pasted = await rig.approved()
    clock.advance(599)
    assert (await rig.login.complete("music", flow, pasted))["persisted"] is True


@pytest.mark.parametrize(
    ("change", "reason", "message"),
    [
        (
            lambda u: with_query(u, state="wrong"),
            "state_mismatch",
            "the address is for a different login",
        ),
        (
            lambda u: u.replace("127.0.0.1", "127.0.0.2"),
            "redirect_mismatch",
            "that isn't an address under http://127.0.0.1/callback; paste the full URL",
        ),
        (lambda u: u + "&code=again", "duplicate_param", "the address has more than one 'code'"),
        (
            lambda u: with_query(u, code=None),
            "no_code",
            "the address has no usable authorization code",
        ),
    ],
    ids=["state", "redirect", "duplicate", "no-code"],
)
async def test_a_bad_paste_ends_the_flow(
    tmp_path: Path,
    clock: FakeClock,
    change: Callable[[str], str],
    reason: str,
    message: str,
) -> None:
    rig = spotify_rig(tmp_path, clock)
    flow, pasted = await rig.approved()
    refused = await rig.refused(rig.login.complete("music", flow, change(pasted)))
    assert (refused.reason, str(refused), refused.details) == (reason, message, {})
    # The flow is gone: even the right address needs a new login now.
    again = await rig.refused(rig.login.complete("music", flow, pasted))
    assert again.reason == "flow_unknown"
    assert rig.server.calls == []


async def test_a_provider_error_goes_back_with_its_description(
    tmp_path: Path, clock: FakeClock, captured: Captured
) -> None:
    rig = spotify_rig(tmp_path, clock)
    flow, _ = await rig.approved()
    pasted = f"{REDIRECT}?" + urlencode(
        {"error": "access_denied", "error_description": "The user said no", "state": STATE}
    )
    refused = await rig.refused(rig.login.complete("music", flow, pasted))
    assert refused.reason == "provider_error"
    assert str(refused) == "the provider refused the authorization: access_denied"
    assert refused.details == {"provider_error": "access_denied", "description": "The user said no"}
    assert "The user said no" not in captured.text


async def test_a_different_issuer_is_refused(tmp_path: Path, clock: FakeClock) -> None:
    server = spotify_style(clock.time, issuer="https://evil.example")
    rig = Rig(
        tmp_path,
        clock,
        make_policy({"music": spotify(issuer="https://accounts.example")}),
        server,
    )
    flow, pasted = await rig.approved()
    refused = await rig.refused(rig.login.complete("music", flow, pasted))
    assert (refused.reason, str(refused)) == (
        "iss_mismatch",
        "the response came from a different issuer",
    )


async def test_the_right_issuer_is_accepted(tmp_path: Path, clock: FakeClock) -> None:
    server = spotify_style(clock.time, issuer="https://accounts.example")
    rig = Rig(
        tmp_path,
        clock,
        make_policy({"music": spotify(issuer="https://accounts.example")}),
        server,
    )
    assert (await rig.login_once())["persisted"] is True


# --- the exchange ------------------------------------------------------------------------------


async def test_a_used_code_gets_a_hint(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock)
    flow, pasted = await rig.approved()
    await rig.login.complete("music", flow, pasted)
    # A second login pasting the first code: the fake refuses it as used.
    flow, fresh = await rig.approved()
    reused = with_query(fresh, code=dict(parse_qsl(urlsplit(pasted).query))["code"])
    refused = await rig.refused(rig.login.complete("music", flow, reused))
    assert refused.reason == f"exchange_failed:{OAUTH_RECONSENT_NEEDED}"
    assert str(refused) == f"the token endpoint refused: invalid_grant (HTTP 400); {CODE_HINT}"
    assert CODE_HINT == "the code expired or was already used; run login again"
    assert refused.details == {"provider_error": "invalid_grant"}
    # Not replayed: a code is single use.
    assert len(rig.server.calls) == 2


async def test_a_rejected_client_gets_no_code_hint(tmp_path: Path, clock: FakeClock) -> None:
    rig = google_rig(tmp_path, clock)
    rig.put_client_secret("fake-wrong-secret")
    flow, pasted = await rig.approved()
    refused = await rig.refused(rig.login.complete("music", flow, pasted))
    assert refused.reason == f"exchange_failed:{OAUTH_CLIENT_REJECTED}"
    assert str(refused) == "the token endpoint refused: invalid_client (HTTP 401)"
    assert rig.store.entry("music-refresh") is None


async def test_an_unavailable_token_endpoint(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.server.fail_next(1, 503)
    flow, pasted = await rig.approved()
    refused = await rig.refused(rig.login.complete("music", flow, pasted))
    assert refused.reason == f"exchange_failed:{OAUTH_UNAVAILABLE}"
    assert str(refused) == "the token endpoint refused: http_status (HTTP 503)"
    assert refused.details == {"provider_error": None}
    assert len(rig.server.calls) == 1


@pytest.mark.parametrize("error", [httpx.ConnectError, httpx.ReadError, ConnectionResetError])
async def test_no_answer_is_not_replayed(
    tmp_path: Path, clock: FakeClock, error: type[Exception]
) -> None:
    transport, calls = raising(error)
    rig = Rig(tmp_path, clock, make_policy({"music": spotify()}), transport=transport)
    flow, pasted = await rig.approved()
    refused = await rig.refused(rig.login.complete("music", flow, pasted))
    assert refused.reason == f"exchange_failed:{OAUTH_UNAVAILABLE}"
    assert str(refused) == "no answer from the token endpoint; run login again"
    assert calls == [1]
    assert clock.sleeps == []


async def test_a_timeout_is_no_answer(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock)
    flow, pasted = await rig.approved()

    async def timing_out(request: Any, *, deadline: float | None = None) -> Any:
        raise TimeoutError

    rig.manager.post = timing_out  # type: ignore[method-assign]
    refused = await rig.refused(rig.login.complete("music", flow, pasted))
    assert refused.reason == f"exchange_failed:{OAUTH_UNAVAILABLE}"


async def test_a_redirect_from_the_token_endpoint_is_not_followed(
    tmp_path: Path, clock: FakeClock
) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.server.redirect_token = "https://evil.example/token"
    flow, pasted = await rig.approved()
    refused = await rig.refused(rig.login.complete("music", flow, pasted))
    assert refused.reason == f"exchange_failed:{OAUTH_MISCONFIGURED}"
    assert str(refused) == "the token endpoint refused: http_status (HTTP 307)"
    assert len(rig.server.calls) == 1


async def test_a_dpop_token_is_refused_and_nothing_is_stored(
    tmp_path: Path, clock: FakeClock
) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.server.token_type = "DPoP"
    flow, pasted = await rig.approved()
    refused = await rig.refused(rig.login.complete("music", flow, pasted))
    assert refused.reason == f"exchange_failed:{OAUTH_UNSUPPORTED}"
    assert str(refused) == "the token endpoint refused: token_type (HTTP 200)"
    assert rig.store.names() == []


async def test_no_refresh_token_is_refused(tmp_path: Path, clock: FakeClock) -> None:
    # Without access_type=offline and prompt=consent the Google-style fake issues none.
    rig = google_rig(tmp_path, clock, authorize_params={})
    flow, pasted = await rig.approved()
    refused = await rig.refused(rig.login.complete("music", flow, pasted))
    assert refused.reason == "no_refresh_token"
    assert str(refused) == f"the token endpoint issued no refresh token; {NO_REFRESH_HINT}"
    assert NO_REFRESH_HINT == (
        "for Google keep access_type: offline and prompt: consent; "
        "some providers need an offline_access scope"
    )
    assert rig.store.names() == ["google-secret"]
    assert rig.manager.status()[0]["state"] == "idle"


async def test_a_confidential_client_logs_in(tmp_path: Path, clock: FakeClock) -> None:
    rig = google_rig(tmp_path, clock)
    done = await rig.login_once()
    assert done["granted_scopes"] == [CALENDAR]
    [exchange] = rig.server.calls
    assert exchange.auth == "body"
    assert exchange.params["client_secret"] == GOOGLE_SECRET
    assert rig.stored() == rig.server.active_refresh_token()


async def test_an_exchange_the_policy_cannot_build(tmp_path: Path, clock: FakeClock) -> None:
    # check refuses a reserved extra_params name; the exchange refuses it again.
    rig = spotify_rig(tmp_path, clock, extra_params={"code": "x"})
    flow, pasted = await rig.approved()
    refused = await rig.refused(rig.login.complete("music", flow, pasted))
    assert refused.reason == f"exchange_failed:{OAUTH_MISCONFIGURED}"
    assert str(refused) == "the token request can't be built from the policy"
    assert rig.server.calls == []


# --- commit ------------------------------------------------------------------------------------


async def test_scopes_are_flagged_not_refused(
    tmp_path: Path, clock: FakeClock, captured: Captured
) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.server.granted_scopes = ("user-read-currently-playing", "playlist-modify")
    done = await rig.login_once()
    assert done["granted_scopes"] == ["user-read-currently-playing", "playlist-modify"]
    assert done["unexpected_scopes"] == ["playlist-modify"]
    assert done["missing_scopes"] == ["user-top-read"]
    assert done["persisted"] is True
    assert rig.stored() == rig.server.active_refresh_token()
    [unexpected] = captured.events("oauth_scope_unexpected")
    [narrowed] = captured.events("oauth_scope_narrowed")
    assert {k: v for k, v in unexpected.items() if k not in ("ts", "role")} == {
        "event": "oauth_scope_unexpected",
        "credential": "music",
        "scopes": ["playlist-modify"],
        "at": "login",
    }
    assert {k: v for k, v in narrowed.items() if k not in ("ts", "role")} == {
        "event": "oauth_scope_narrowed",
        "credential": "music",
        "scopes": ["user-top-read"],
        "at": "login",
    }
    [completed] = captured.events("oauth_login_completed")
    assert completed["unexpected"] == ["playlist-modify"]
    assert completed["missing"] == ["user-top-read"]
    # And status keeps flagging them.
    [status] = rig.login.status()
    assert status["scopes"] == {"unexpected": ["playlist-modify"], "missing": ["user-top-read"]}


async def test_no_expected_scopes_flags_nothing(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock, scope=None)
    rig.server.granted_scopes = ("anything",)
    done = await rig.login_once()
    assert (done["unexpected_scopes"], done["missing_scopes"]) == ([], [])


async def test_an_empty_scope_grants_nothing(
    tmp_path: Path, clock: FakeClock, captured: Captured
) -> None:
    """An empty ``scope`` in the token response means nothing was granted (design D.7)."""
    rig = spotify_rig(tmp_path, clock)
    rig.server.granted_scopes = ()
    done = await rig.login_once()
    assert (done["granted_scopes"], done["unexpected_scopes"]) == ([], [])
    assert done["missing_scopes"] == SPOTIFY_SCOPES
    [narrowed] = captured.events("oauth_scope_narrowed")
    assert narrowed["scopes"] == SPOTIFY_SCOPES


async def test_a_login_with_an_env_seed_supersedes_it(tmp_path: Path, clock: FakeClock) -> None:
    cred = spotify(refresh_token="env:MUSIC_REFRESH")
    rig = Rig(tmp_path, clock, make_policy({"music": cred}), env={"MUSIC_REFRESH": "fake-seed"})
    done = await rig.login_once()
    slot = live_slot("music")
    assert done["slot"] == slot
    assert done["seed_note"] == (
        "The env seed MUSIC_REFRESH is now ignored (reseed: never). You may remove it."
    )
    envelope = parse_envelope(Secret(rig.stored(slot)))
    assert envelope.rt.reveal() == rig.server.active_refresh_token()
    assert envelope.seed_sha256 == seed_sha256("fake-seed")


async def test_a_login_without_the_env_seed_has_no_note(tmp_path: Path, clock: FakeClock) -> None:
    cred = spotify(refresh_token="env:MUSIC_REFRESH")
    rig = Rig(tmp_path, clock, make_policy({"music": cred}))
    done = await rig.login_once()
    assert done["seed_note"] is None
    assert parse_envelope(Secret(rig.stored(live_slot("music")))).seed_sha256 is None


def test_seed_notes() -> None:
    def cred(**fields: Any) -> OAuth2Credential:
        found = make_policy({"music": spotify(**fields)}).credentials["music"]
        assert isinstance(found, OAuth2Credential)
        return found

    seeded = cred(refresh_token="env:MUSIC_REFRESH")
    assert seed_note(seeded, True) == (
        "The env seed MUSIC_REFRESH is now ignored (reseed: never). You may remove it."
    )
    assert seed_note(seeded, False) is None
    on_change = cred(refresh_token="env:MUSIC_REFRESH", reseed="on-change")
    assert seed_note(on_change, True) == (
        "The env seed MUSIC_REFRESH is now ignored until its value changes "
        "(reseed: on-change). You may remove it."
    )
    assert seed_note(cred(), True) is None
    assert seed_note(cred(refresh_token=None), True) is None


async def test_a_failed_write_still_activates_the_grant(
    tmp_path: Path, clock: FakeClock, writes: FailingWrites, captured: Captured
) -> None:
    rig = spotify_rig(tmp_path, clock)
    flow, pasted = await rig.approved()
    writes.failing = True
    done = await rig.login.complete("music", flow, pasted)
    assert done == answer(persisted=False)
    assert rig.stored() == rig.server.active_refresh_token()
    assert rig.store.dirty
    await rig.manager.grant_for("music", API)
    assert len(rig.server.calls) == 1
    [completed] = captured.events("oauth_login_completed")
    assert completed["persisted"] is False
    [status] = rig.login.status()
    assert status["persisted"] is False


async def test_lifetimes_are_reported(tmp_path: Path, clock: FakeClock) -> None:
    body = {
        "access_token": "fake-at-mock",
        "token_type": "Bearer",
        "expires_in": 30,
        "refresh_token": "fake-rt-mock",
        "refresh_token_expires_in": 86400,
        "scope": "user-top-read",
    }
    transport, _ = raising(httpx.Response(200, json=body))
    cred = spotify(grant_lifetime_days=180)
    rig = Rig(tmp_path, clock, make_policy({"music": cred}), transport=transport)
    started = await rig.start()
    pasted = f"{REDIRECT}?" + urlencode({"code": "fake-code-mock", "state": STATE})
    done = await rig.login.complete("music", started["flow"], pasted)
    assert done == answer(
        granted_scopes=["user-top-read"],
        missing_scopes=["user-read-currently-playing"],
        access_expires_in=60,
        refresh_expires_at="2026-10-18T09:00:00Z",
        grant_expires_at="2027-04-15T09:00:00Z",
    )


async def test_a_binding_changed_since_start_is_refused(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock)
    flow, pasted = await rig.approved()
    rig.store.put("music-refresh", "fake-rt-old", OTHER_BINDING)
    refused = await rig.refused(rig.login.complete("music", flow, pasted))
    assert refused.reason == "binding_changed"
    assert str(refused) == "the policy binds this grant differently; pass --rebind to accept"
    assert refused.details == {"old": OTHER_BINDING, "new": BINDING}
    assert rig.stored() == "fake-rt-old"


async def test_rebind_given_at_start_holds_at_commit(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock)
    flow, pasted = await rig.approved(rebind=True)
    rig.store.put("music-refresh", "fake-rt-old", OTHER_BINDING)
    await rig.login.complete("music", flow, pasted)
    assert rig.stored() == rig.server.active_refresh_token()


async def test_a_credential_removed_since_start(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock)
    flow, pasted = await rig.approved()
    rig.reconfigure(make_policy({"other": spotify(refresh_token="store:other-refresh")}))
    refused = await rig.refused(rig.login.complete("music", flow, pasted))
    assert (refused.reason, str(refused)) == ("not_oauth", "no oauth2 credential named 'music'")
    assert rig.server.calls == []


async def test_a_credential_switched_to_client_credentials_since_start(
    tmp_path: Path, clock: FakeClock
) -> None:
    rig = spotify_rig(tmp_path, clock)
    flow, pasted = await rig.approved()
    rig.reconfigure(make_policy({"music": machine()}))
    refused = await rig.refused(rig.login.complete("music", flow, pasted))
    assert (refused.reason, str(refused)) == (
        "not_oauth",
        "'music' no longer uses the refresh grant",
    )


async def test_a_route_removed_since_start(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock)
    flow, pasted = await rig.approved()
    rig.reconfigure(make_policy({"music": spotify()}, {"music": ()}))
    refused = await rig.refused(rig.login.complete("music", flow, pasted))
    assert refused.reason == "no_route"
    assert "no route uses" in str(refused)
    assert rig.store.names() == []


async def test_a_commit_the_manager_refuses(
    tmp_path: Path, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    rig = spotify_rig(tmp_path, clock)
    flow, pasted = await rig.approved()

    async def refuse(*args: Any, **kwargs: Any) -> Any:
        raise ValueError("'music' is not an oauth2 credential with a refresh grant")

    monkeypatch.setattr(rig.manager, "commit_login", refuse)
    refused = await rig.refused(rig.login.complete("music", flow, pasted))
    assert (refused.reason, str(refused)) == (
        "not_oauth",
        "'music' is not an oauth2 credential with a refresh grant",
    )


async def test_a_login_clears_a_terminal_state(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.store.put("music-refresh", "fake-rt-revoked", BINDING)
    with pytest.raises(Exception, match=OAUTH_RECONSENT_NEEDED):
        await rig.manager.grant_for("music", API)
    [before] = rig.login.status()
    assert before["hint"] == "run: zoeymcp login music"
    await rig.login_once()
    await rig.manager.grant_for("music", API)
    [after] = rig.login.status()
    assert (after["state"], after["code"], after["hint"]) == ("ok", None, None)


async def test_cancel(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock)
    flow, pasted = await rig.approved()
    assert rig.login.cancel(flow) is True
    assert rig.login.cancel(flow) is False
    assert (await rig.refused(rig.login.complete("music", flow, pasted))).reason == "flow_unknown"


# --- client_credentials ------------------------------------------------------------------------


def machine_rig(tmp_path: Path, clock: FakeClock, **fields: Any) -> Rig:
    server = FakeAuthServer(
        clock.time, client_id=GOOGLE_ID, client_secret=GOOGLE_SECRET, auth="post"
    )
    rig = Rig(tmp_path, clock, make_policy({"music": machine(**fields)}), server)
    rig.put_client_secret()
    return rig


async def test_client_credentials_login_is_a_test_fetch(
    tmp_path: Path, clock: FakeClock, captured: Captured
) -> None:
    rig = machine_rig(tmp_path, clock, expected_scopes=["read"])
    done = await rig.start()
    assert done == {
        "slot": "cc:music",
        "binding": BINDING,
        "granted_scopes": ["read", "write"],
        "unexpected_scopes": ["write"],
        "missing_scopes": [],
        "access_expires_in": 3600,
        "refresh_expires_at": None,
        "consented_at": None,
        "grant_expires_at": None,
        "persisted": True,
        "seed_note": None,
    }
    [call] = rig.server.calls
    assert call.grant_type == "client_credentials"
    assert call.params["scope"] == "read write"
    # The token is dropped: the next request fetches its own.
    assert rig.manager.status()[0]["state"] == "idle"
    assert rig.store.names() == ["google-secret"]
    started = [e["credential"] for e in captured.events("oauth_login_started")]
    assert started == ["music"]
    [completed] = captured.events("oauth_login_completed")
    del completed["ts"], completed["role"]
    assert completed == {
        "event": "oauth_login_completed",
        "credential": "music",
        "slot": "cc:music",
        "binding": BINDING,
        "granted": ["read", "write"],
        "unexpected": ["write"],
        "missing": [],
        "persisted": True,
    }
    resets = [e["reason"] for e in captured.events("oauth_cache_reset")]
    assert resets == ["login"]


async def test_a_test_fetch_flags_a_missing_scope(
    tmp_path: Path, clock: FakeClock, captured: Captured
) -> None:
    rig = machine_rig(tmp_path, clock, expected_scopes=["read", "write", "admin"])
    done = await rig.start()
    assert (done["unexpected_scopes"], done["missing_scopes"]) == ([], ["admin"])
    [completed] = captured.events("oauth_login_completed")
    assert (completed["unexpected"], completed["missing"]) == ([], ["admin"])


async def test_a_test_fetch_refused_with_invalid_grant_gets_no_code_hint(
    tmp_path: Path, clock: FakeClock
) -> None:
    transport, _ = raising(httpx.Response(400, json={"error": "invalid_grant"}))
    rig = Rig(tmp_path, clock, make_policy({"music": machine()}), transport=transport)
    rig.put_client_secret()
    refused = await rig.refused(rig.start())
    assert refused.reason == f"exchange_failed:{OAUTH_CLIENT_REJECTED}"
    assert str(refused) == "the token endpoint refused: invalid_grant (HTTP 400)"


async def test_a_working_test_fetch_clears_a_terminal_state(
    tmp_path: Path, clock: FakeClock
) -> None:
    rig = machine_rig(tmp_path, clock)
    rig.put_client_secret("fake-wrong-secret")
    with pytest.raises(Exception, match=OAUTH_CLIENT_REJECTED):
        await rig.manager.grant_for("music", API)
    refused = await rig.refused(rig.start())
    assert refused.reason == f"exchange_failed:{OAUTH_CLIENT_REJECTED}"
    assert str(refused) == "the token endpoint refused: invalid_client (HTTP 401)"
    assert rig.manager.status()[0]["state"] == "terminal"
    # The operator fixes the secret in the store directly, and logs in to check it.
    rig.put_client_secret()
    assert rig.manager.status()[0]["state"] == "terminal"
    await rig.start()
    assert rig.manager.status()[0]["state"] == "idle"
    await rig.manager.grant_for("music", API)


async def test_a_test_fetch_reports_the_requested_scopes_when_none_come_back(
    tmp_path: Path, clock: FakeClock
) -> None:
    body: dict[str, Any] = {"access_token": "fake-at-mock", "token_type": "Bearer"}
    for directory, scope, granted in (("a", None, ["read", "write"]), ("b", "read", ["read"])):
        answered = {**body, "expires_in": 600} if scope is None else {**body, "scope": scope}
        transport, _ = raising(httpx.Response(200, json=answered))
        policy = make_policy({"music": machine()})
        rig = Rig(tmp_path / directory, clock, policy, transport=transport)
        rig.put_client_secret()
        done = await rig.start()
        assert done["granted_scopes"] == granted
        assert done["access_expires_in"] == (600 if scope is None else 3600)


async def test_a_test_fetch_splits_the_requested_scope_by_its_separator(
    tmp_path: Path, clock: FakeClock
) -> None:
    body = {"access_token": "fake-at-mock", "token_type": "Bearer", "expires_in": 600}
    transport, _ = raising(httpx.Response(200, json=body))
    policy = make_policy({"music": machine(scope="read,write", scope_separator=",")})
    rig = Rig(tmp_path, clock, policy, transport=transport)
    rig.put_client_secret()
    assert (await rig.start())["granted_scopes"] == ["read", "write"]


async def test_a_test_fetch_with_an_env_secret_reports_the_policy_binding(
    tmp_path: Path, clock: FakeClock
) -> None:
    server = FakeAuthServer(
        clock.time, client_id=GOOGLE_ID, client_secret=GOOGLE_SECRET, auth="post"
    )
    policy = make_policy(
        {"music": machine(client_secret="env:MACHINE_SECRET")}, {"music": (API, OTHER)}
    )
    rig = Rig(tmp_path, clock, policy, server, env={"MACHINE_SECRET": GOOGLE_SECRET})
    done = await rig.start()
    assert done["binding"] == oauth_binding(TOKEN_URL, [API, OTHER])


async def test_a_test_fetch_takes_the_client_secret_binding(
    tmp_path: Path, clock: FakeClock
) -> None:
    rig = machine_rig(tmp_path, clock)
    narrower = oauth_binding(TOKEN_URL, [OTHER])
    rig.store.put("google-secret", GOOGLE_SECRET, narrower)
    assert (await rig.start())["binding"] == narrower


async def test_a_test_fetch_needs_a_route_and_a_secret(tmp_path: Path, clock: FakeClock) -> None:
    rig = Rig(tmp_path, clock, make_policy({"music": machine()}, {"music": ()}))
    rig.put_client_secret()
    assert (await rig.refused(rig.start())).reason == "no_route"
    rig = Rig(tmp_path / "b", clock, make_policy({"music": machine()}))
    refused = await rig.refused(rig.start())
    assert refused.reason == "client_secret_unavailable"


async def test_a_test_fetch_needs_a_resolvable_client_id(tmp_path: Path, clock: FakeClock) -> None:
    rig = Rig(tmp_path, clock, make_policy({"music": machine(client_id="env:MACHINE_ID")}))
    rig.put_client_secret()
    refused = await rig.refused(rig.start())
    assert refused.reason == "client_id_unavailable"
    assert str(refused) == (
        "the client ID isn't set or isn't bound to the token endpoint; "
        "set the client ID in env MACHINE_ID and restart the vault"
    )


async def test_a_test_fetch_the_policy_cannot_build(tmp_path: Path, clock: FakeClock) -> None:
    rig = machine_rig(tmp_path, clock, extra_params={"grant_type": "x"})
    refused = await rig.refused(rig.start())
    assert refused.reason == f"exchange_failed:{OAUTH_MISCONFIGURED}"
    assert rig.server.calls == []


async def test_a_client_the_manager_does_not_know(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.manager._configs.clear()
    refused = await rig.refused(rig.start())
    assert (refused.reason, str(refused)) == ("not_configured", "the client can't be identified")


# --- status ------------------------------------------------------------------------------------


async def test_status_adds_health(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock, grant_lifetime_days=20)
    [before] = rig.login.status()
    assert before["hint"] is None
    assert before["last_ok_ago"] is None
    assert before["reconsent_due"] is None
    assert before["scopes"] is None
    await rig.login_once()
    clock.advance(3600)
    [after] = rig.login.status()
    assert after["credential"] == "music"
    assert after["last_ok_ago"] == 3600
    assert after["reconsent_due"] is None
    assert after["scopes"] == {"unexpected": [], "missing": []}
    clock.advance(6 * 86400)
    # 20 days after consent is now under 14 days away.
    [later] = rig.login.status()
    assert later["reconsent_due"] == "2026-11-06T09:00:00Z"


async def test_status_survives_a_tampered_meta(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock, grant_lifetime_days=1)
    rig.store.put(
        "music-refresh",
        "fake-rt",
        BINDING,
        meta={"oauth": {"last_ok": "2099-01-01T00:00:00Z", "consented_at": 5, "granted_scope": 7}},
    )
    [status] = rig.login.status()
    assert status["last_ok_ago"] == 0
    assert status["reconsent_due"] is None
    assert status["scopes"] is None


def credential(**fields: Any) -> OAuth2Credential:
    found = make_policy({"music": spotify(**fields)}).credentials["music"]
    assert isinstance(found, OAuth2Credential)
    return found


@pytest.mark.parametrize(
    ("code", "fields", "text"),
    [
        (None, {}, None),
        (OAUTH_RECONSENT_NEEDED, {}, "run: zoeymcp login music"),
        (OAUTH_ROTATION_LOST, {}, "run: zoeymcp login music"),
        (CREDENTIAL_UNAVAILABLE, {}, "run: zoeymcp login music"),
        (
            OAUTH_RECONSENT_NEEDED,
            {"authorize_url": None},
            "enter the refresh token with zoeymcp secret set music-refresh",
        ),
        (
            OAUTH_ROTATION_LOST,
            {"authorize_url": None, "refresh_token": "env:MUSIC_REFRESH"},
            "put a new refresh token in env MUSIC_REFRESH, delete oauth.music.live with "
            "zoeymcp secret delete (reseed: never keeps it), and restart the vault",
        ),
        (
            CREDENTIAL_UNAVAILABLE,
            {"authorize_url": None, "refresh_token": "env:MUSIC_REFRESH", "reseed": "on-change"},
            "put a new refresh token in env MUSIC_REFRESH and restart the vault "
            "(reseed: on-change)",
        ),
        (
            OAUTH_CLIENT_REJECTED,
            {},
            "check the client ID and secret, then run: zoeymcp oauth reset music",
        ),
        (OAUTH_MISCONFIGURED, {}, "fix the policy, then run: zoeymcp oauth reset music"),
        (OAUTH_UNSUPPORTED, {}, "the provider's tokens aren't Bearer tokens the vault can use"),
        (
            OAUTH_UNAVAILABLE,
            {},
            "the token endpoint is unavailable; a request after the backoff tries again",
        ),
        ("something_new", {}, None),
    ],
)
def test_hints(code: str | None, fields: dict[str, Any], text: str | None) -> None:
    assert hint("music", credential(**fields), code) == text


@pytest.mark.parametrize(
    ("fields", "reason", "text"),
    [
        (
            {"client_secret": "store:music-secret", "client_auth": "post"},
            "client_secret_unavailable",
            "enter the client secret with zoeymcp secret set music-secret, "
            "then run: zoeymcp oauth reset music",
        ),
        (
            {"client_secret": "env:MUSIC_SECRET", "client_auth": "post"},
            "client_secret_unavailable",
            "set the client secret in env MUSIC_SECRET and restart the vault, "
            "then run: zoeymcp oauth reset music",
        ),
        (
            {"client_id": "env:MUSIC_ID", "authorize_url": None},
            "client_id_unavailable",
            "set the client ID in env MUSIC_ID and restart the vault, "
            "then run: zoeymcp oauth reset music",
        ),
        ({}, "no_route", "no route uses music; fix the policy"),
        ({}, "live_unusable", "run: zoeymcp login music"),
        ({}, None, "run: zoeymcp login music"),
    ],
)
def test_hints_by_reason(fields: dict[str, Any], reason: str | None, text: str) -> None:
    assert hint("music", credential(**fields), CREDENTIAL_UNAVAILABLE, reason) == text


def test_a_client_credentials_hint_never_says_login() -> None:
    found = make_policy({"music": machine()}).credentials["music"]
    assert isinstance(found, OAuth2Credential)
    for code in (CREDENTIAL_UNAVAILABLE, OAUTH_RECONSENT_NEEDED):
        assert hint("music", found, code) == (
            "check the client ID and secret, then run: zoeymcp oauth reset music"
        )
    assert hint("music", found, CREDENTIAL_UNAVAILABLE, "client_secret_unavailable") == (
        "enter the client secret with zoeymcp secret set google-secret, "
        "then run: zoeymcp oauth reset music"
    )


async def test_status_hints_from_the_failure_reason(tmp_path: Path, clock: FakeClock) -> None:
    rig = Rig(tmp_path, clock, make_policy({"music": google()}), google_style(clock.time))
    rig.store.put("music-refresh", "fake-rt-0001", BINDING)
    with pytest.raises(Exception, match=CREDENTIAL_UNAVAILABLE):
        await rig.manager.grant_for("music", API)
    [status] = rig.login.status()
    assert (status["code"], status["reason"]) == (
        CREDENTIAL_UNAVAILABLE,
        "client_secret_unavailable",
    )
    assert status["hint"] == (
        "enter the client secret with zoeymcp secret set google-secret, "
        "then run: zoeymcp oauth reset music"
    )


DAY = 86400.0
CONSENTED = "2026-10-17T09:00:00Z"


@pytest.mark.parametrize(
    ("fields", "meta", "now", "due"),
    [
        # 30-day grant: due 2026-11-16. Warned when under 14 days away.
        ({"grant_lifetime_days": 30}, {"consented_at": CONSENTED}, NOW + 16 * DAY, None),
        (
            {"grant_lifetime_days": 30},
            {"consented_at": CONSENTED},
            NOW + 16 * DAY + 1,
            "2026-11-16T09:00:00Z",
        ),
        # No lifetime in the policy: consent alone says nothing.
        ({}, {"consented_at": CONSENTED}, NOW + 1000 * DAY, None),
        # refresh_expires_at counts on its own, and the earlier date wins.
        ({}, {"refresh_expires_at": "2026-10-20T09:00:00Z"}, NOW, "2026-10-20T09:00:00Z"),
        (
            {"grant_lifetime_days": 2},
            {"consented_at": CONSENTED, "refresh_expires_at": "2026-10-20T09:00:00Z"},
            NOW,
            "2026-10-19T09:00:00Z",
        ),
        (
            {"grant_lifetime_days": 5},
            {"consented_at": CONSENTED, "refresh_expires_at": "2026-10-20T09:00:00Z"},
            NOW,
            "2026-10-20T09:00:00Z",
        ),
        # Already past: still shown.
        ({}, {"refresh_expires_at": "2026-10-01T09:00:00Z"}, NOW, "2026-10-01T09:00:00Z"),
        # Unusable values are ignored.
        ({}, {"refresh_expires_at": "2026-10-20T09:00:00"}, NOW, None),
        ({}, {"refresh_expires_at": "soon"}, NOW, None),
        # Times before 1970 are refused; the epoch itself is fine.
        ({}, {"refresh_expires_at": "0001-01-01T00:00:00+05:00"}, NOW, None),
        ({}, {"refresh_expires_at": "1969-12-31T23:59:59Z"}, NOW, None),
        ({}, {"refresh_expires_at": "1970-01-01T00:00:00Z"}, NOW, "1970-01-01T00:00:00Z"),
        (
            {"grant_lifetime_days": 1},
            {"consented_at": "1969-12-31T00:00:00Z"},
            NOW,
            None,
        ),
        ({"grant_lifetime_days": 1}, {"consented_at": 12}, NOW, None),
        ({}, {}, NOW, None),
    ],
)
def test_reconsent_due(
    fields: dict[str, Any], meta: dict[str, Any], now: float, due: str | None
) -> None:
    assert reconsent_due(credential(**fields), meta, now) == due


def test_scope_health() -> None:
    cred = credential()
    assert scope_health(cred, {}) is None
    assert scope_health(cred, {"granted_scope": None}) is None
    assert scope_health(cred, {"granted_scope": "user-top-read extra"}) == {
        "unexpected": ["extra"],
        "missing": ["user-read-currently-playing"],
    }
    assert scope_health(cred, {"granted_scope": ""}) == {
        "unexpected": [],
        "missing": SPOTIFY_SCOPES,
    }
    comma = credential(scope="a,b", scope_separator=",")
    assert scope_health(comma, {"granted_scope": "a,,b"}) == {"unexpected": [], "missing": []}


def test_login_error_details() -> None:
    error = LoginError("x", "message", details={"a": 1})
    assert error.details == {"a": 1}
    assert LoginError("x", "m").details == {}
    assert login_module.DAY == 86400


async def test_waiting_for_a_refresh_before_commit(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.store.put("music-refresh", rig.server.issue_grant(), BINDING)
    flow, pasted = await rig.approved()
    gate = rig.server.hold()
    refresh = asyncio.create_task(rig.manager.grant_for("music", API))
    await rig.server.arrived()
    gate.set()
    done = await rig.login.complete("music", flow, pasted)
    await refresh
    assert done["persisted"] is True
    # Login wrote last.
    assert rig.stored() == rig.server.active_refresh_token()


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        (
            {"client_id": "store:music-client-id"},
            "a client_id ref can't go in an authorization URL",
        ),
        (
            {"authorize_params": {"state": "x"}},
            "authorize_params can't set 'state'; the vault sets it",
        ),
    ],
    ids=["client-id-ref", "reserved-param"],
)
async def test_an_authorization_request_the_policy_cannot_build(
    tmp_path: Path, clock: FakeClock, fields: dict[str, Any], message: str
) -> None:
    rig = spotify_rig(tmp_path, clock, **fields)
    rig.store.put("music-client-id", SPOTIFY_ID, BINDING)
    refused = await rig.refused(rig.start())
    assert (refused.reason, str(refused)) == ("authorize_misconfigured", message)
    # The flow it started is gone again.
    assert len(rig.login._flows) == 0


# --- gaps found by mutation testing ------------------------------------------------------------


async def test_a_changed_live_slot_binding_needs_rebind(tmp_path: Path, clock: FakeClock) -> None:
    rig = Rig(tmp_path, clock, make_policy({"music": spotify(refresh_token="env:MUSIC_REFRESH")}))
    rig.store.put(live_slot("music"), "fake-envelope", OTHER_BINDING)
    refused = await rig.refused(rig.start())
    assert refused.reason == "binding_changed"
    assert refused.details == {"old": OTHER_BINDING, "new": BINDING}


async def test_a_client_secret_removed_since_start(tmp_path: Path, clock: FakeClock) -> None:
    rig = google_rig(tmp_path, clock)
    flow, pasted = await rig.approved()
    rig.store.delete("google-secret")
    refused = await rig.refused(rig.login.complete("music", flow, pasted))
    assert refused.reason == "client_secret_unavailable"
    assert str(refused) == (
        "the client secret isn't set or isn't bound to the token endpoint; "
        "enter the client secret with zoeymcp secret set google-secret"
    )
    assert rig.server.calls == []


async def test_a_test_fetch_logs_unexpected_scopes(
    tmp_path: Path, clock: FakeClock, captured: Captured
) -> None:
    rig = machine_rig(tmp_path, clock, expected_scopes=["read"])
    await rig.start()
    assert [
        {k: v for k, v in e.items() if k not in ("ts", "role")}
        for e in captured.events("oauth_scope_unexpected")
    ] == [
        {
            "event": "oauth_scope_unexpected",
            "credential": "music",
            "scopes": ["write"],
            "at": "login",
        }
    ]


async def test_a_retry_date_at_the_exchange_does_not_crash(
    tmp_path: Path, clock: FakeClock
) -> None:
    # Login never shows the parsed date; this pins the whole refusal around it.
    retry = httpx.Response(503, headers={"retry-after": "Sat, 17 Oct 2026 09:01:00 GMT"})
    transport, _ = raising(retry)
    rig = Rig(tmp_path, clock, make_policy({"music": spotify()}), transport=transport)
    flow, pasted = await rig.approved()
    refused = await rig.refused(rig.login.complete("music", flow, pasted))
    assert refused.reason == f"exchange_failed:{OAUTH_UNAVAILABLE}"
    assert str(refused) == "the token endpoint refused: http_status (HTTP 503)"
    assert refused.details == {"provider_error": None}


async def test_an_exchange_line_has_the_error_subtype(
    tmp_path: Path, clock: FakeClock, captured: Captured
) -> None:
    body = {"error": "invalid_grant", "error_subtype": "invalid_rapt"}
    transport, _ = raising(httpx.Response(400, json=body))
    rig = Rig(tmp_path, clock, make_policy({"music": spotify()}), transport=transport)
    flow, pasted = await rig.approved()
    await rig.refused(rig.login.complete("music", flow, pasted))
    [call] = captured.events("oauth_refresh")
    assert (call["error"], call["error_subtype"]) == ("invalid_grant", "invalid_rapt")


async def test_an_exchange_line_keeps_a_tenth_of_a_millisecond(
    tmp_path: Path, clock: FakeClock, captured: Captured
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        clock.advance(0.01234)
        body = {
            "access_token": "fake-at-login",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "fake-rt-login",
        }
        return httpx.Response(200, json=body)

    transport = httpx.MockTransport(handler)
    rig = Rig(tmp_path, clock, make_policy({"music": spotify()}), transport=transport)
    flow, pasted = await rig.approved()
    await rig.login.complete("music", flow, pasted)
    [call] = captured.events("oauth_refresh")
    assert call["duration_ms"] == 12.3
