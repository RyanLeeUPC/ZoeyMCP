"""Acceptance: the OAuth shapes S5 and S6, end to end over real HTTPS (design G.3).

Agent -> vault (real socket) -> fake API (real TLS), and the vault's token client -> fake
authorization server (real TLS, verified against the test CA), using the shipped profiles with
only their endpoints swapped. The operator side is the real CLI: ``zoeymcp login`` with the test
playing the browser, ``oauth status`` and ``secret delete``. Its admin requests reach the vault's
admin app over loopback, so this runs on Windows too.

The vault and the fakes read one clock, so a test can let an hour, or half a year, go by.
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import re
import threading
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

import httpx
import pytest
from starlette.requests import Request
from starlette.responses import Response

from tests.fakes.oauth_server import (
    MISSING,
    ErrorShape,
    FakeAuthServer,
    FakeResourceServer,
    google_style,
    spotify_style,
)
from zoeymcp.cli import admin_client
from zoeymcp.cli.main import main
from zoeymcp.common.policy import Policy, check_policy
from zoeymcp.common.policy.schema import OAuth2Credential
from zoeymcp.common.yamlload import load_mapping
from zoeymcp.vault import logs
from zoeymcp.vault.oauth.protocol import MIN_401_AGE, Envelope, parse_envelope
from zoeymcp.vault.server import reload_policy
from zoeymcp.vault.store import STORE_FILE, Secret, SecretStore

from .conftest import BASE, PROFILES, Clock, Deployment, serve_tls, wait_until
from .tls import ProviderCA

GOOGLE = "google-oauth.yaml"
SPOTIFY = "spotify-pkce.yaml"
GOOGLE_ENDPOINTS = {
    "https://oauth2.googleapis.com/token": "/token",
    "https://accounts.google.com/o/oauth2/v2/auth": "/authorize",
}
SPOTIFY_ENDPOINTS = {
    "https://accounts.spotify.com/api/token": "/token",
    "https://accounts.spotify.com/authorize": "/authorize",
}
GOOGLE_SECRET = "fake-google-client-secret"
CALENDAR_SCOPE = "https://www.googleapis.com/auth/calendar.readonly"
MAIL_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
CALENDARS = "/gcal/calendar/v3/users/me/calendarList"
EVENTS = "/gcal/calendar/v3/calendars/primary/events"
TOP = "/spotify/v1/me/top/artists"
PLAYING = "/spotify/v1/me/player/currently-playing"
REDIRECT = "http://127.0.0.1/callback"
SEED_VAR = "SPOTIFY_REFRESH"
SEEDED = {"refresh_token: store:spotify-refresh": f"refresh_token: env:{SEED_VAR}"}
LIVE = "oauth.spotify.live"
HOUR = 3600.0
DAY = 86400.0
PRINTED_URL = re.compile(r"^  (https://\S+)$", re.MULTILINE)
PRINTED_FLOW = re.compile(r"--flow=(\S+)")
SPOTIFY_SCOPE = "user-read-currently-playing user-top-read"
# Every token and code the fakes issue; none may reach a log line, the CLI or the store file.
ISSUED = re.compile(r"fake-(?:google|spotify)-(?:rt|at|code)-\d+")


def assert_no_secrets(text: str) -> None:
    assert ISSUED.search(text) is None
    assert GOOGLE_SECRET not in text


# --- the rig -----------------------------------------------------------------------------------


class Api(FakeResourceServer):
    """The provider's API. With ``disk`` set, each request also notes whether the store file
    already held the refresh token the authorization server considers current (I3)."""

    def __init__(self, auth_server: FakeAuthServer) -> None:
        super().__init__(auth_server)
        self.disk: Callable[[], str | None] | None = None
        self.persisted: list[bool] = []

    async def _handle(self, request: Request) -> Response:
        if self.disk is not None:
            self.persisted.append(self.disk() == self.auth_server.active_refresh_token())
        return await super()._handle(request)


def browse(url: str, ca: ProviderCA) -> str:
    """Play the browser: approve at the authorization server, return where it was sent."""
    with httpx.Client(verify=ca.client_context(), trust_env=False) as browser:
        response = browser.get(url)
    assert response.status_code == 302, response.text
    location: str = response.headers["location"]
    return location


class Browser(io.StringIO):
    """Stdin that approves the URL the CLI printed, then pastes the address it led to."""

    def __init__(self, out: io.StringIO, ca: ProviderCA) -> None:
        super().__init__()
        self.out = out
        self.ca = ca

    def readline(self, size: int = -1, /) -> str:  # type: ignore[override]
        [url] = PRINTED_URL.findall(self.out.getvalue())
        return browse(url, self.ca) + "\n"


class World:
    """One shape: the fakes, the deployment and, while it runs, the agent and the operator."""

    def __init__(
        self,
        d: Deployment,
        auth: FakeAuthServer,
        auth_url: str,
        api: Api,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        self.d = d
        self.auth = auth
        self.auth_url = auth_url
        self.api = api
        self.agent: httpx.Client | None = None
        self.said: list[str] = []  # everything the CLI wrote
        # The CLI reaches the admin app of whichever vault is running.
        monkeypatch.setattr(httpx, "HTTPTransport", lambda **_: d.admin_transport())

    @contextmanager
    def running(self) -> Iterator[None]:
        with self.d.running() as agent:
            self.agent = agent
            try:
                yield
            finally:
                self.agent = None

    def restart(
        self, *, environ: dict[str, str] | None = None, replace: dict[str, str] | None = None
    ) -> None:
        self.d.restart(environ=environ, replace=replace)

    # --- the agent -----------------------------------------------------------------------------

    def get(self, path: str) -> httpx.Response:
        return self.send("GET", path)

    def send(self, method: str, path: str, *, identified: bool = True) -> httpx.Response:
        assert self.agent is not None
        headers = {"Authorization": f"Bearer {self.d.placeholder}"} if identified else {}
        return self.agent.request(method, path, headers=headers)

    def get_many(self, path: str, count: int) -> list[int]:
        """``count`` requests at once, each on its own connection."""
        assert self.agent is not None
        base = str(self.agent.base_url)
        headers = {"Authorization": f"Bearer {self.d.placeholder}"}

        async def all_at_once() -> list[int]:
            async with httpx.AsyncClient(base_url=base, timeout=60) as client:
                answers = await asyncio.gather(
                    *(client.get(path, headers=headers) for _ in range(count))
                )
            return [answer.status_code for answer in answers]

        return asyncio.run(all_at_once())

    # --- the operator --------------------------------------------------------------------------

    def cli(self, argv: list[str], stdin: str = "") -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        code = main(argv, stdin=io.StringIO(stdin), out=out, err=err)
        self.said += [out.getvalue(), err.getvalue()]
        return code, out.getvalue(), err.getvalue()

    def login(self, credential: str) -> tuple[int, str, str]:
        """``zoeymcp login`` in one go: approve in the browser and paste the address."""
        out, err = io.StringIO(), io.StringIO()
        code = main(["login", credential], stdin=Browser(out, self.d.ca), out=out, err=err)
        self.said += [out.getvalue(), err.getvalue()]
        return code, out.getvalue(), err.getvalue()

    def status(self) -> dict[str, Any]:
        [entry] = admin_client.oauth_status("unused", self.d.admin_transport())["credentials"]
        assert isinstance(entry, dict)
        return entry

    # --- the state volume ----------------------------------------------------------------------

    def stored(self, name: str) -> Secret | None:
        """The entry in the store file, decrypted as a restarted vault would read it."""
        store = SecretStore(self.d.state, self.d.keys)
        store.load()
        if name not in store.names():
            return None
        [cred] = [c for c in self.d.policy.credentials.values() if isinstance(c, OAuth2Credential)]
        value, _ = store.get_for_oauth(name, token_url=cred.token_url)
        return value

    def envelope(self, name: str = LIVE) -> Envelope:
        value = self.stored(name)
        assert value is not None
        return parse_envelope(value)

    def on_disk(self, name: str) -> str | None:
        """The refresh token in the store file. A live slot's is inside its envelope."""
        if name.startswith("oauth."):
            return self.envelope(name).rt.reveal()
        value = self.stored(name)
        return None if value is None else value.reveal()


@contextmanager
def shape(
    tmp_path: Path,
    ca: ProviderCA,
    monkeypatch: pytest.MonkeyPatch,
    profile: str,
    auth: FakeAuthServer,
    clock: Clock,
    *,
    secrets: dict[str, str] | None = None,
    replace: dict[str, str] | None = None,
    environ: dict[str, str] | None = None,
) -> Iterator[World]:
    api = Api(auth)
    endpoints = GOOGLE_ENDPOINTS if profile == GOOGLE else SPOTIFY_ENDPOINTS
    with serve_tls(auth.app(), ca) as auth_url, serve_tls(api.app(), ca) as api_url:
        swap = {old: auth_url + path for old, path in endpoints.items()}
        swap.update(replace or {})
        d = Deployment(
            tmp_path,
            profile,
            api_url,
            ca,
            secrets=secrets or {},
            replace=swap,
            environ=environ,
            clock=clock,
        )
        world = World(d, auth, auth_url, api, monkeypatch)
        yield world
        for text in world.said:
            assert_no_secrets(text)
        store_file = d.state / STORE_FILE
        if store_file.exists():
            assert_no_secrets(store_file.read_text(encoding="utf-8"))


@pytest.fixture(autouse=True)
def log_lines() -> Iterator[io.StringIO]:
    """Every test's log lines, which must not hold anything the fakes issued."""
    buffer = io.StringIO()
    logs.set_stream(buffer)
    try:
        yield buffer
    finally:
        logs.set_stream(None)
    assert_no_secrets(buffer.getvalue())


def events(buffer: io.StringIO, kind: str) -> list[dict[str, Any]]:
    records = [json.loads(line) for line in buffer.getvalue().splitlines()]
    return [r for r in records if r["event"] == kind]


def refreshes(buffer: io.StringIO) -> list[dict[str, Any]]:
    """The token calls the vault made for a refresh (not login), in order."""
    return [e for e in events(buffer, "oauth_refresh") if e["trigger"] != "login"]


def unavailable(code: str) -> dict[str, str]:
    return {"error": "upstream unavailable", "code": code}


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


# --- the profiles ------------------------------------------------------------------------------


@pytest.mark.parametrize("profile", [GOOGLE, SPOTIFY])
def test_the_oauth_profiles_pass_check(profile: str) -> None:
    fragment = load_mapping((PROFILES / profile).read_text(encoding="utf-8"))
    out = io.StringIO()
    document = io.StringIO(json.dumps({**BASE, **fragment}))
    assert main(["check", "--config", "-"], stdin=document, out=out) == 0
    assert out.getvalue() == "<stdin>: ok (0 error(s), 0 warning(s))\n"


def test_the_oauth_profiles_say_what_the_providers_do() -> None:
    fragments = {
        profile: load_mapping((PROFILES / profile).read_text(encoding="utf-8"))
        for profile in (GOOGLE, SPOTIFY)
    }

    def credential(profile: str) -> OAuth2Credential:
        [cred] = Policy.model_validate({**BASE, **fragments[profile]}).credentials.values()
        assert isinstance(cred, OAuth2Credential)
        return cred

    google, spotify = credential(GOOGLE), credential(SPOTIFY)
    upstreams = {p: [r["upstream"] for r in f["routes"]] for p, f in fragments.items()}
    assert upstreams == {
        GOOGLE: ["https://www.googleapis.com"],
        SPOTIFY: ["https://api.spotify.com"],
    }
    # S5: a confidential client posting its secret; Google doesn't rotate refresh tokens.
    assert (google.effective_client_auth, google.rotates) == ("post", False)
    assert google.authorize_params == {"access_type": "offline", "prompt": "consent"}
    assert google.effective_expected_scopes == [CALENDAR_SCOPE]
    # The portless loopback default (K3), which the live smoke test checks against Google.
    assert google.redirect_uri == REDIRECT
    assert "redirect_uri" not in fragments[GOOGLE]["credentials"]["google-calendar"]
    # S6: a public client with rotating refresh tokens and a grant that ends.
    assert (spotify.effective_client_auth, spotify.rotates) == ("none", True)
    assert (spotify.client_secret, spotify.grant_lifetime_days) == (None, 180)
    assert spotify.scope == SPOTIFY_SCOPE
    assert spotify.redirect_uri == REDIRECT
    assert "redirect_uri" not in fragments[SPOTIFY]["credentials"]["spotify"]


@pytest.mark.parametrize(
    ("profile", "refused", "allowed"),
    [
        (
            GOOGLE,
            [
                ("GET", "/gcal/calendar/v3/calendars/someone@example.com/events"),
                ("POST", CALENDARS),
                ("POST", EVENTS),
                ("GET", "/gcal/calendar/v3/users/me/settings"),
            ],
            [CALENDARS, EVENTS],
        ),
        (
            SPOTIFY,
            [
                ("GET", "/spotify/v1/me/top/genres"),
                ("PUT", PLAYING),
                ("GET", "/spotify/v1/me/playlists"),
            ],
            [TOP, "/spotify/v1/me/top/tracks", PLAYING],
        ),
    ],
)
def test_the_oauth_profiles_refuse_what_their_rules_dont_allow(
    tmp_path: Path,
    ca: ProviderCA,
    monkeypatch: pytest.MonkeyPatch,
    profile: str,
    refused: list[tuple[str, str]],
    allowed: list[str],
) -> None:
    """The identity and rule checks come before any token call, and a refusal by them carries
    no code (K2)."""
    clock = Clock()
    if profile == GOOGLE:
        auth = google_style(clock.wall)
        secrets = {"google-client-secret": GOOGLE_SECRET, "google-refresh": auth.issue_grant()}
    else:
        auth = spotify_style(clock.wall)
        secrets = {"spotify-refresh": auth.issue_grant()}
    with shape(tmp_path, ca, monkeypatch, profile, auth, clock, secrets=secrets) as w, w.running():
        anonymous = w.send("GET", allowed[0], identified=False)
        assert (anonymous.status_code, anonymous.json()) == (403, {"error": "forbidden"})
        for method, path in refused:
            answer = w.send(method, path)
            assert (answer.status_code, answer.json()) == (403, {"error": "forbidden"}), path
        assert (auth.calls, w.api.received) == ([], [])
        for path in allowed:
            assert w.get(path).status_code == 200
        assert len(auth.calls) == 1


# --- S5: Google, a confidential client --------------------------------------------------------


def test_s5_login_then_refresh_on_expiry(
    tmp_path: Path, ca: ProviderCA, monkeypatch: pytest.MonkeyPatch, log_lines: io.StringIO
) -> None:
    clock = Clock()
    auth = google_style(clock.wall)
    secrets = {"google-client-secret": GOOGLE_SECRET}
    with (
        shape(tmp_path, ca, monkeypatch, GOOGLE, auth, clock, secrets=secrets) as w,
        w.running(),
    ):
        nothing = w.get(CALENDARS)
        assert (nothing.status_code, nothing.json()) == (502, unavailable("credential_unavailable"))
        assert (auth.calls, w.api.received) == ([], [])

        code, out, err = w.login("google-calendar")
        assert (code, err) == (0, "")
        assert "Stored the refresh token for google-calendar as google-refresh.\n" in out
        assert f"Granted: {CALENDAR_SCOPE}\n" in out
        [url] = PRINTED_URL.findall(out)
        query = dict(parse_qsl(urlsplit(url).query))
        assert query["redirect_uri"] == REDIRECT
        assert (query["access_type"], query["prompt"]) == ("offline", "consent")
        assert (query["code_challenge_method"], query["scope"]) == ("S256", CALENDAR_SCOPE)
        # client_secret_post: the secret is in the body, and there's no Basic header.
        [exchange] = auth.calls
        assert (exchange.grant_type, exchange.auth, exchange.status) == (
            "authorization_code",
            "body",
            200,
        )
        assert "authorization" not in exchange.headers
        assert exchange.params["client_secret"] == GOOGLE_SECRET
        assert exchange.params["redirect_uri"] == REDIRECT
        refresh_token = auth.active_refresh_token()
        assert refresh_token is not None
        assert w.on_disk("google-refresh") == refresh_token

        w.api.disk = lambda: w.on_disk("google-refresh")
        assert w.get(CALENDARS).status_code == 200
        assert w.get(EVENTS).status_code == 200
        assert len(auth.calls) == 1  # the login's access token is used

        # Expiry: one refresh. Google sends no refresh_token, so the current one stays.
        clock.advance(HOUR)
        assert w.get(CALENDARS).status_code == 200
        assert w.get(CALENDARS).status_code == 200
        [refresh] = auth.refresh_calls
        assert (refresh.refresh_token, refresh.auth, refresh.status) == (refresh_token, "body", 200)
        assert refresh.params["client_secret"] == GOOGLE_SECRET
        assert "scope" not in refresh.params
        assert w.on_disk("google-refresh") == refresh_token
        assert events(log_lines, "oauth_rotation_observed") == []

        # An unexpected rotation is saved before the new access token is used.
        auth.rotate_next()
        clock.advance(HOUR)
        assert w.get(CALENDARS).status_code == 200
        rotated = auth.active_refresh_token()
        assert rotated not in (None, refresh_token)
        assert w.on_disk("google-refresh") == rotated
        [observed] = events(log_lines, "oauth_rotation_observed")
        assert (observed["credential"], observed["slot"]) == ("google-calendar", "google-refresh")
        clock.advance(HOUR)
        assert w.get(CALENDARS).status_code == 200
        presented = [c.refresh_token for c in auth.refresh_calls]
        assert presented == [refresh_token, refresh_token, rotated]
        assert w.api.persisted == [True] * 6

        # Neither the refresh token nor the client secret ever reached the API.
        sent = json.dumps([headers for _, _, headers in w.api.received])
        for value in (refresh_token, rotated, GOOGLE_SECRET):
            assert value is not None
            assert value not in sent

    assert [(e["trigger"], e["token_source"], e["outcome"]) for e in refreshes(log_lines)] == [
        ("first_use", None, "terminal"),
        ("expiry", "store", "ok"),
        ("expiry", "store", "ok"),
        ("expiry", "store", "ok"),
    ]


def test_s5_scopes_narrower_and_wider(
    tmp_path: Path, ca: ProviderCA, monkeypatch: pytest.MonkeyPatch, log_lines: io.StringIO
) -> None:
    clock = Clock()
    auth = google_style(clock.wall, granted_scopes=())
    secrets = {"google-client-secret": GOOGLE_SECRET}
    with (
        shape(tmp_path, ca, monkeypatch, GOOGLE, auth, clock, secrets=secrets) as w,
        w.running(),
    ):
        code, out, err = w.login("google-calendar")
        assert code == 0
        assert "Granted: (no scopes)\n" in out
        assert err == f"missing: {CALENDAR_SCOPE}\n"

        # A wider grant is stored and flagged (K1).
        auth.granted_scopes = (CALENDAR_SCOPE, MAIL_SCOPE)
        code, out, err = w.login("google-calendar")
        assert code == 0
        assert err == f"UNEXPECTED: {MAIL_SCOPE}\n"
        assert w.status()["scopes"] == {"unexpected": [MAIL_SCOPE], "missing": []}
        code, out, _ = w.cli(["oauth", "status", "google-calendar"])
        assert f"  UNEXPECTED scopes: {MAIL_SCOPE}\n" in out

        # Refreshes compare with the last grant: narrower, then wider again.
        auth.granted_scopes = (CALENDAR_SCOPE,)
        clock.advance(HOUR)
        assert w.get(CALENDARS).status_code == 200
        auth.granted_scopes = (CALENDAR_SCOPE, MAIL_SCOPE)
        clock.advance(HOUR)
        assert w.get(CALENDARS).status_code == 200

    narrowed = events(log_lines, "oauth_scope_narrowed")
    assert [(e["scopes"], e["at"]) for e in narrowed] == [
        ([CALENDAR_SCOPE], "login"),
        ([MAIL_SCOPE], "refresh"),
    ]
    unexpected = events(log_lines, "oauth_scope_unexpected")
    assert [(e["scopes"], e["at"]) for e in unexpected] == [
        ([MAIL_SCOPE], "login"),
        ([MAIL_SCOPE], "refresh"),
    ]


@pytest.mark.parametrize("error_shape", ["rfc", "status_200", "status_403", "echo"])
def test_s5_a_revoked_grant_needs_reconsent(
    tmp_path: Path,
    ca: ProviderCA,
    monkeypatch: pytest.MonkeyPatch,
    log_lines: io.StringIO,
    error_shape: ErrorShape,
) -> None:
    """400, 200 and 403 all carry invalid_grant; an echoed refresh token is never shown."""
    clock = Clock()
    auth = google_style(clock.wall, error_shape=error_shape)
    seed = auth.issue_grant()
    secrets = {"google-client-secret": GOOGLE_SECRET, "google-refresh": seed}
    with (
        shape(tmp_path, ca, monkeypatch, GOOGLE, auth, clock, secrets=secrets) as w,
        w.running(),
    ):
        assert w.get(CALENDARS).status_code == 200
        auth.revoke()
        clock.advance(HOUR)
        before = len(w.api.received)
        refused = w.get(CALENDARS)
        assert (refused.status_code, refused.json()) == (502, unavailable("oauth_reconsent_needed"))
        assert [c.grant_type for c in auth.calls] == ["refresh_token"] * 2
        # Terminal: no more token calls until the operator acts.
        for _ in range(5):
            assert w.get(CALENDARS).json() == unavailable("oauth_reconsent_needed")
        assert len(auth.calls) == 2
        assert len(w.api.received) == before

        code, out, _ = w.cli(["oauth", "status"])
        assert code == 0
        assert seed not in out + refused.text
        assert out.startswith(
            "google-calendar: terminal oauth_reconsent_needed\n"
            "  hint: run: zoeymcp login google-calendar\n"
        )
        assert w.login("google-calendar")[0] == 0
        assert w.get(CALENDARS).status_code == 200

    assert seed not in log_lines.getvalue()
    [terminal] = [e for e in refreshes(log_lines) if e["outcome"] == "terminal"]
    assert (terminal["error"], terminal["code"]) == ("invalid_grant", "oauth_reconsent_needed")


def test_s5_an_upstream_401_refreshes_and_retries_once(
    tmp_path: Path, ca: ProviderCA, monkeypatch: pytest.MonkeyPatch, log_lines: io.StringIO
) -> None:
    clock = Clock()
    auth = google_style(clock.wall)
    secrets = {"google-client-secret": GOOGLE_SECRET, "google-refresh": auth.issue_grant()}
    with (
        shape(tmp_path, ca, monkeypatch, GOOGLE, auth, clock, secrets=secrets) as w,
        w.running(),
    ):
        assert w.get(CALENDARS).status_code == 200
        clock.advance(MIN_401_AGE)
        # The provider drops its access tokens long before they expire.
        auth.drop_access_tokens()
        assert w.get(CALENDARS).status_code == 200
        assert len(auth.refresh_calls) == 2
        refused, retried = (headers["authorization"] for _, _, headers in w.api.received[-2:])
        assert refused != retried

        # A token younger than MIN_401_AGE isn't refreshed again: the 401 goes to the caller.
        auth.drop_access_tokens()
        assert w.get(CALENDARS).status_code == 401
        assert len(auth.refresh_calls) == 2

    actions = [(e["action"], e["fresh_token"]) for e in events(log_lines, "oauth_upstream_401")]
    assert actions == [("retried", False), ("suppressed", True)]
    assert [e["trigger"] for e in refreshes(log_lines)] == ["first_use", "upstream_401"]


def test_s5_echoes_are_scrubbed_and_insufficient_scope_refreshes_nothing(
    tmp_path: Path, ca: ProviderCA, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = Clock()
    auth = google_style(clock.wall)
    secrets = {"google-client-secret": GOOGLE_SECRET, "google-refresh": auth.issue_grant()}
    paths = "          - /calendar/v3/users/me/calendarList\n"
    replace = {paths: paths + "          - /forbidden\n"}
    with (
        shape(
            tmp_path, ca, monkeypatch, GOOGLE, auth, clock, secrets=secrets, replace=replace
        ) as w,
        w.running(),
    ):
        w.api.echo_token = True
        echoed = w.get(CALENDARS)
        assert echoed.status_code == 200
        assert echoed.json()["token"] == "[REDACTED]"
        token = w.api.received[-1][2]["authorization"].removeprefix("Bearer ")
        assert token not in echoed.text

        forbidden = w.get("/gcal/forbidden")
        assert forbidden.status_code == 403
        assert len(auth.refresh_calls) == 1
        assert w.status()["upstream"]["code"] == "upstream_insufficient_scope"
        _, out, _ = w.cli(["oauth", "status"])
        assert "  WARNING an upstream said upstream_insufficient_scope at " in out


def test_s5_a_dpop_token_is_refused_and_its_successor_kept(
    tmp_path: Path, ca: ProviderCA, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = Clock()
    auth = google_style(clock.wall, token_type="DPoP")
    seed = auth.issue_grant()
    secrets = {"google-client-secret": GOOGLE_SECRET, "google-refresh": seed}
    with (
        shape(tmp_path, ca, monkeypatch, GOOGLE, auth, clock, secrets=secrets) as w,
        w.running(),
    ):
        refused = w.get(CALENDARS)
        assert (refused.status_code, refused.json()) == (502, unavailable("oauth_unsupported"))
        assert w.api.received == []
        # The provider rotated with that answer: the new refresh token is saved all the same.
        assert w.on_disk("google-refresh") == auth.active_refresh_token() != seed
        assert w.get(CALENDARS).json() == unavailable("oauth_unsupported")
        assert len(auth.calls) == 1
        assert w.status()["state"] == "terminal"


def test_s5_a_missing_expires_in_gets_the_default_lifetime(
    tmp_path: Path, ca: ProviderCA, monkeypatch: pytest.MonkeyPatch, log_lines: io.StringIO
) -> None:
    clock = Clock()
    auth = google_style(clock.wall, expires_in=MISSING)
    secrets = {"google-client-secret": GOOGLE_SECRET, "google-refresh": auth.issue_grant()}
    with (
        shape(tmp_path, ca, monkeypatch, GOOGLE, auth, clock, secrets=secrets) as w,
        w.running(),
    ):
        assert w.get(CALENDARS).status_code == 200
        assert 3500 < w.status()["access_expires_in"] <= 3600
    [refresh] = refreshes(log_lines)
    assert (refresh["expires_in"], refresh["lifetime"]) == (None, 3600)
    assert "expires_in_defaulted" in refresh["notes"]


def test_s5_a_route_moved_to_another_origin_gets_no_token(
    tmp_path: Path, ca: ProviderCA, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = Clock()
    auth = google_style(clock.wall)
    secrets = {"google-client-secret": GOOGLE_SECRET, "google-refresh": auth.issue_grant()}
    elsewhere = FakeResourceServer(auth)
    with (
        shape(tmp_path, ca, monkeypatch, GOOGLE, auth, clock, secrets=secrets) as w,
        serve_tls(elsewhere.app(), ca) as other,
        w.running(),
    ):
        assert w.get(CALENDARS).status_code == 200
        moved = w.d.load(upstream=other)
        w.d.call(lambda: w.d.app.reload(moved))
        refused = w.get(CALENDARS)
        assert (refused.status_code, refused.json()) == (502, unavailable("credential_unavailable"))
        assert elsewhere.received == []
        assert len(auth.calls) == 1


# --- S6: Spotify, a public client with rotating refresh tokens ---------------------------------


def test_s6_pkce_login_and_ten_rotations(
    tmp_path: Path, ca: ProviderCA, monkeypatch: pytest.MonkeyPatch, log_lines: io.StringIO
) -> None:
    clock = Clock()
    # Every fourth refresh answers without a new refresh token.
    auth = spotify_style(clock.wall, omit_refresh_every=4)
    with shape(tmp_path, ca, monkeypatch, SPOTIFY, auth, clock) as w, w.running():
        # The two-step login: --start prints the URL and the flow, --flow takes the paste.
        code, out, err = w.cli(["login", "spotify", "--start"])
        assert (code, err) == (0, "")
        assert "(public client, PKCE S256, rotating refresh tokens)" in out
        [url] = PRINTED_URL.findall(out)
        [flow] = PRINTED_FLOW.findall(out)
        query = dict(parse_qsl(urlsplit(url).query))
        assert (query["code_challenge_method"], query["redirect_uri"]) == ("S256", REDIRECT)
        assert query["scope"] == SPOTIFY_SCOPE
        assert "client_secret" not in query
        code, out, err = w.cli(["login", "spotify", f"--flow={flow}"], browse(url, ca) + "\n")
        assert (code, err) == (0, "")
        assert "The grant ends at " in out
        [exchange] = auth.calls
        assert (exchange.auth, exchange.status) == ("body", 200)
        assert exchange.params["client_id"] == auth.client_id
        assert "client_secret" not in exchange.params
        assert "authorization" not in exchange.headers
        assert len(exchange.params["code_verifier"]) >= 43

        # Each rotated token is in the store file before the access token from its response
        # reaches the API, and the next refresh presents it.
        w.api.disk = lambda: w.on_disk("spotify-refresh")
        current = auth.active_refresh_token()
        presented = []
        for _ in range(10):
            clock.advance(HOUR)
            assert w.get(TOP).status_code == 200
            presented.append(current)
            current = auth.active_refresh_token()
        assert w.get(PLAYING).status_code == 200
        assert [c.refresh_token for c in auth.refresh_calls] == presented
        assert [c.status for c in auth.calls] == [200] * 11  # no reuse, so nothing revoked
        assert w.api.persisted == [True] * 11
        assert w.on_disk("spotify-refresh") == current

    assert len(events(log_lines, "oauth_rotation_missing")) == 2
    assert [e["rotated"] for e in refreshes(log_lines)] == [True, True, True, False] * 2 + [
        True,
        True,
    ]


def test_s6_concurrent_requests_at_expiry_make_one_refresh(
    tmp_path: Path, ca: ProviderCA, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = Clock()
    auth = spotify_style(clock.wall)
    secrets = {"spotify-refresh": auth.issue_grant()}
    with shape(tmp_path, ca, monkeypatch, SPOTIFY, auth, clock, secrets=secrets) as w, w.running():
        assert w.get(TOP).status_code == 200
        clock.advance(HOUR)
        auth.latch = latch = threading.Event()
        before = w.d.arrived
        with ThreadPoolExecutor(1) as pool:
            answers = pool.submit(w.get_many, TOP, 20)
            # All 20 are in the vault while the one refresh is held.
            wait_until(lambda: w.d.arrived == before + 20 and len(auth.refresh_calls) == 2)
            assert w.status()["refreshing"] is True
            latch.set()
            assert answers.result() == [200] * 20
        assert len(auth.refresh_calls) == 2
        assert w.on_disk("spotify-refresh") == auth.active_refresh_token()


def test_s6_sighup_during_a_refresh(
    tmp_path: Path, ca: ProviderCA, monkeypatch: pytest.MonkeyPatch, log_lines: io.StringIO
) -> None:
    clock = Clock()
    auth = spotify_style(clock.wall)
    secrets = {"spotify-refresh": auth.issue_grant()}
    config = tmp_path / "policy.json"
    with (
        shape(tmp_path / "state", ca, monkeypatch, SPOTIFY, auth, clock, secrets=secrets) as w,
        w.running(),
        ThreadPoolExecutor(1) as pool,
    ):
        assert w.get(TOP).status_code == 200
        config.write_text(w.d.document, encoding="utf-8")

        def sighup() -> None:
            w.d.call(lambda: reload_policy(w.d.app, str(config), {}))

        # The same policy: the refresh in flight carries on, and it's the only one.
        clock.advance(HOUR)
        auth.latch = latch = threading.Event()
        waiting = pool.submit(w.get, TOP)
        wait_until(lambda: len(auth.refresh_calls) == 2)
        sighup()
        assert not waiting.done()
        assert w.status()["refreshing"] is True
        latch.set()
        assert waiting.result().status_code == 200
        assert len(auth.refresh_calls) == 2

        # A changed credential: the refresh in flight still saves its rotated token, but its
        # access token belongs to the old settings, so the waiting request gets a 502. The
        # next request refreshes with the saved token.
        w.d.load({"rotates: true": "rotates: true\n    refresh_skew: 300"})
        config.write_text(w.d.document, encoding="utf-8")
        clock.advance(HOUR)
        auth.latch = latch = threading.Event()
        waiting = pool.submit(w.get, TOP)
        wait_until(lambda: len(auth.refresh_calls) == 3)
        sighup()
        assert not waiting.done()
        latch.set()
        refused = waiting.result()
        assert (refused.status_code, refused.json()) == (502, unavailable("oauth_unavailable"))
        assert refused.headers["retry-after"] == "1"
        rotated = auth.active_refresh_token()
        assert w.on_disk("spotify-refresh") == rotated
        auth.latch = None
        assert w.get(TOP).status_code == 200
        assert auth.refresh_calls[-1].refresh_token == rotated
        assert [c.status for c in auth.calls] == [200] * 4

    assert [e["oauth_reset"] for e in events(log_lines, "reload_ok")] == [[], ["spotify"]]


def test_s6_a_restart_continues_with_the_saved_token(
    tmp_path: Path, ca: ProviderCA, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = Clock()
    auth = spotify_style(clock.wall)
    secrets = {"spotify-refresh": auth.issue_grant()}
    with shape(tmp_path, ca, monkeypatch, SPOTIFY, auth, clock, secrets=secrets) as w:
        with w.running():
            assert w.get(TOP).status_code == 200
            clock.advance(HOUR)
            assert w.get(TOP).status_code == 200
        saved = auth.active_refresh_token()
        w.restart()
        with w.running():
            assert w.get(TOP).status_code == 200
        assert auth.refresh_calls[-1].refresh_token == saved
        assert [c.status for c in auth.calls] == [200] * 3


def test_s6_env_seed_promotion_and_reseeding(
    tmp_path: Path, ca: ProviderCA, monkeypatch: pytest.MonkeyPatch, log_lines: io.StringIO
) -> None:
    clock = Clock()
    auth = spotify_style(clock.wall)
    first = auth.issue_grant()
    on_change = {**SEEDED, "rotates: true": "rotates: true\n    reseed: on-change"}

    def last_refresh() -> tuple[str, str]:
        refresh = refreshes(log_lines)[-1]
        return refresh["token_source"], refresh["reason"]

    with shape(
        tmp_path,
        ca,
        monkeypatch,
        SPOTIFY,
        auth,
        clock,
        replace=SEEDED,
        environ={SEED_VAR: first},
    ) as w:
        # The seed is used once and promoted: the live slot holds its successor.
        with w.running():
            assert w.get(TOP).status_code == 200
        assert last_refresh() == ("seed", "no_live")
        assert auth.refresh_calls[-1].refresh_token == first
        live = w.envelope()
        assert live.rt.reveal() == auth.active_refresh_token()
        assert live.seed_sha256 == sha256(first)
        assert w.stored("spotify-refresh") is None
        [promoted] = events(log_lines, "oauth_seed_promoted")
        assert (promoted["credential"], promoted["slot"]) == ("spotify", LIVE)

        # reseed: never ignores a changed env value.
        second = auth.issue_grant()
        w.restart(environ={SEED_VAR: second})
        with w.running():
            assert w.get(TOP).status_code == 200
            assert last_refresh() == ("live", "reseed_never")
            assert auth.refresh_calls[-1].refresh_token == live.rt.reveal()
            # Deleting the live slot re-seeds from the env value the vault started with.
            assert w.cli(["secret", "delete", LIVE]) == (0, f"deleted {LIVE}\n", "")
            assert w.get(TOP).status_code == 200
            assert last_refresh() == ("seed", "no_live")
            assert auth.refresh_calls[-1].refresh_token == second
        assert w.envelope().seed_sha256 == sha256(second)

        # reseed: on-change takes a new env value once, then keeps the live token.
        third = auth.issue_grant()
        w.restart(environ={SEED_VAR: third}, replace=on_change)
        with w.running():
            assert w.get(TOP).status_code == 200
        assert last_refresh() == ("seed", "seed_changed")
        assert auth.refresh_calls[-1].refresh_token == third
        assert w.envelope().seed_sha256 == sha256(third)
        w.restart(environ={SEED_VAR: third}, replace=on_change)
        with w.running():
            assert w.get(TOP).status_code == 200
        assert last_refresh() == ("live", "seed_unchanged")

        # The vault starts with the seed unset (N1), and uses the live token.
        live_now = w.on_disk(LIVE)
        w.restart(environ={}, replace=on_change)
        unset = [f for f in check_policy(w.d.policy, environ={}) if "is not set" in f.message]
        assert [f.level for f in unset] == ["warning"]
        with w.running():
            assert w.get(TOP).status_code == 200
        assert last_refresh() == ("live", "seed_absent")
        assert auth.refresh_calls[-1].refresh_token == live_now
        assert [c.status for c in auth.calls] == [200] * 6


def test_s6_a_failed_store_write_keeps_the_new_token(
    tmp_path: Path, ca: ProviderCA, monkeypatch: pytest.MonkeyPatch, log_lines: io.StringIO
) -> None:
    clock = Clock()
    auth = spotify_style(clock.wall)
    secrets = {"spotify-refresh": auth.issue_grant()}

    class DiskFull:
        def __init__(self, write: Callable[[], None]) -> None:
            self.write = write
            self.full = True

        def __call__(self) -> None:
            if self.full:
                raise OSError(28, "No space left on device")
            self.write()

    with shape(tmp_path, ca, monkeypatch, SPOTIFY, auth, clock, secrets=secrets) as w, w.running():
        assert w.get(TOP).status_code == 200
        saved = w.on_disk("spotify-refresh")
        disk = DiskFull(w.d.store._write)
        monkeypatch.setattr(w.d.store, "_write", disk)

        # The call succeeds; the new token is in memory only, and the next refresh presents it.
        clock.advance(HOUR)
        assert w.get(TOP).status_code == 200
        in_memory = auth.active_refresh_token()
        assert w.on_disk("spotify-refresh") == saved != in_memory
        assert w.status()["persisted"] is False
        _, out, _ = w.cli(["oauth", "status"])
        assert "degraded (not persisted)" in out
        clock.advance(HOUR)
        assert w.get(TOP).status_code == 200
        assert auth.refresh_calls[-1].refresh_token == in_memory

        # The disk comes back: the next refresh saves first, and nothing was reused.
        disk.full = False
        clock.advance(HOUR)
        assert w.get(TOP).status_code == 200
        assert w.on_disk("spotify-refresh") == auth.active_refresh_token()
        assert w.status()["persisted"] is True
        assert [c.status for c in auth.calls] == [200] * 4

    # The second refresh's save, the store-wide retry before the third, the third's save.
    failed = events(log_lines, "oauth_persist_failed")
    assert [(e.get("credential"), e["slot"], e["level"]) for e in failed] == [
        ("spotify", "spotify-refresh", "critical"),
        (None, None, "critical"),
        ("spotify", "spotify-refresh", "critical"),
    ]
    assert len(events(log_lines, "oauth_persist_recovered")) == 1


@pytest.mark.parametrize("grace_seconds", [0.0, 60.0])
def test_s6_a_lost_token_response_is_replayed_once(
    tmp_path: Path,
    ca: ProviderCA,
    monkeypatch: pytest.MonkeyPatch,
    log_lines: io.StringIO,
    grace_seconds: float,
) -> None:
    """The token endpoint rotates, then the connection drops before the body arrives.

    The vault can't know whether its token was used, so it presents it once more. A provider
    with a grace window answers with the same successor; a strict one has revoked the grant.
    """
    clock = Clock()
    auth = spotify_style(clock.wall, grace_seconds=grace_seconds)
    secrets = {"spotify-refresh": auth.issue_grant()}
    with shape(tmp_path, ca, monkeypatch, SPOTIFY, auth, clock, secrets=secrets) as w, w.running():
        assert w.get(TOP).status_code == 200
        presented = w.on_disk("spotify-refresh")
        auth.drop_after_processing = 1
        clock.advance(HOUR)
        answer = w.get(TOP)
        lost, replay = auth.refresh_calls[-2:]
        assert len(auth.refresh_calls) == 3
        assert lost.refresh_token == replay.refresh_token == presented
        if grace_seconds:
            assert answer.status_code == 200
            assert w.on_disk("spotify-refresh") == auth.active_refresh_token() != presented
        else:
            assert (answer.status_code, answer.json()) == (502, unavailable("oauth_rotation_lost"))
            assert replay.status == 400
            for _ in range(3):
                assert w.get(TOP).json() == unavailable("oauth_rotation_lost")
            assert len(auth.refresh_calls) == 3
            assert w.status()["hint"] == "run: zoeymcp login spotify"

    refresh = refreshes(log_lines)[-1]
    assert (refresh["attempt"], refresh["replayed"]) == (2, True)
    assert refresh["code"] == (None if grace_seconds else "oauth_rotation_lost")


def test_s6_a_reused_old_token_revokes_the_grant(
    tmp_path: Path, ca: ProviderCA, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = Clock()
    auth = spotify_style(clock.wall)
    stolen = auth.issue_grant()
    secrets = {"spotify-refresh": stolen}
    with shape(tmp_path, ca, monkeypatch, SPOTIFY, auth, clock, secrets=secrets) as w, w.running():
        assert w.get(TOP).status_code == 200
        # Someone presents the token the vault already rotated away: the family dies.
        with httpx.Client(verify=ca.client_context(), trust_env=False) as attacker:
            reused = attacker.post(
                f"{w.auth_url}/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": stolen,
                    "client_id": auth.client_id,
                },
            )
        assert reused.status_code == 400
        clock.advance(HOUR)
        refused = w.get(TOP)
        assert (refused.status_code, refused.json()) == (502, unavailable("oauth_reconsent_needed"))
        assert len(auth.refresh_calls) == 3  # one call: not a replay
        assert w.login("spotify")[0] == 0
        assert w.get(TOP).status_code == 200


def test_s6_the_grant_lifetime_is_warned_about_then_ends(
    tmp_path: Path, ca: ProviderCA, monkeypatch: pytest.MonkeyPatch, log_lines: io.StringIO
) -> None:
    clock = Clock()
    auth = spotify_style(clock.wall)
    with shape(tmp_path, ca, monkeypatch, SPOTIFY, auth, clock) as w, w.running():
        code, out, _ = w.login("spotify")
        assert code == 0
        [ends] = re.findall(r"^The grant ends at (\S+); run login again before then\.$", out, re.M)
        clock.advance(DAY)
        assert w.get(TOP).status_code == 200
        assert w.status()["reconsent_due"] is None

        # The warning counts from consent, not from the last refresh.
        clock.advance(169 * DAY)
        assert w.get(TOP).status_code == 200
        assert w.status()["reconsent_due"] == ends
        _, out, _ = w.cli(["oauth", "status", "spotify"])
        assert f"  WARNING re-consent due by {ends}\n" in out

        # The provider ends the grant with invalid_grant.
        clock.advance(11 * DAY)
        refused = w.get(TOP)
        assert (refused.status_code, refused.json()) == (502, unavailable("oauth_reconsent_needed"))
        assert [c.status for c in auth.refresh_calls] == [200, 200, 400]
        assert w.login("spotify")[0] == 0
        assert w.get(TOP).status_code == 200

    [terminal] = [e for e in refreshes(log_lines) if e["outcome"] == "terminal"]
    assert (terminal["error"], terminal["code"]) == ("invalid_grant", "oauth_reconsent_needed")
