"""Nothing secret leaves the vault (invariant I7; design G.4, R56, R61).

One run through the OAuth effect scenarios: logins from the CLI and over the admin app, seed
promotion, rotation, the upstream 401 path, a revoked grant whose token endpoint echoes the
refresh token in ``error_description``, bad pastes, a provider error, a reused code, and a
client_credentials test fetch with a rejected client, then the listings and health. Secrets are
written over the admin socket and through the portal's Secrets actions (M5 design G), one
refused and one left held by a pending action. The portal connects by paste too (M5 design H.1):
a paste for another login, a provider's refusal, and a connect confirmed with a passkey, then
its credential list and health. Every log line, admin answer, portal answer, CLI
output and proxied response is collected, and none may hold a token, code, verifier, ``state``,
client secret or ``error_description`` text from the fakes.

Two things are shown by design and are taken out before the sweep: the authorization URL (it
holds ``state`` and the PKCE challenge, useless without the verifier the vault keeps), and the
``error_description`` of a provider's redirect, which goes back to the operator only (the CLI,
or the portal's refused ``oauth.complete``).

The portal's own material is swept too (M5 design O.5, D-117, R56): its pages, every answer with
its ``Set-Cookie``, and every log line. A setup code redeemed in the portal, every challenge
(base64url and hex), every field an authenticator returned, the user handle, every pasted address
and both session halves never show, except where the design puts them: a challenge in the answer
that begins its ceremony, the user handle in the enrolment's options, and each session half in
the one answer that mints it.

The gateway's view of the policy gets its own sweep: built from a policy with every vault-side
value filled in, it may hold none of them (M3 design D.1, invariant G1).

A given confidential client's secret (M7 design D.7, X8, X19) is swept on its own: onboarded over
the admin socket, it reaches the store and nothing else, its fragment holding only the ref; so
is one a registration issued (D.4), whose answer's registration access token and URI reach
nothing at all. So is a deleted grant's revocation (D.9): the refresh token and the client
secret go to the revocation endpoint and nowhere else.

The review job path (M7 design F.2, M.4) is swept too: a job's ID reaches only the poll that
claims it and the queue and read answers, the log naming it by hash8 alone, and nothing from a
report (a tool's name or text, a pin) or a gateway's error message reaches the log. So is the
portal's MCP servers section (M7 design K, step 14a): a given client secret held by its
register action and one a registration issued reach the store alone, and a portal review job's
ID no log line.

The egress role's key (M7 design G.3, O.5, step 17b) reaches the socket's ``GET /egress-key``
answer, the key file and the role's own requests, and nothing else: no log line of the vault or
the role, no answer of the allowlist path or of a path it is refused on, and no health report;
neither does a retired generation's key, or a key file the role can't use.

A bridge's token (M7 design C.2, M.4, X14, step 18c2), made by ``secret set --generate``, reaches
the store and the requests the bridge checks, and no answer or log line; neither does its hash,
which only the generating answer shows. A ``--secret-env`` or ``--env`` value a child prints to
stderr reaches no log line in the default mode, which counts (TI-13).

Under the standard launcher (M7 design C.10, TI-B7, step 18d), a bridge's ``ENV_*`` secret
reaches that bridge's environment and the vault's, never the gateway's, another bridge's, a
command line or a log line; and ``launcher_bridge_refused`` holds no value from ARGS, a token
hash or an ``ENV_*`` variable, whatever shape refused it.
"""

from __future__ import annotations

import asyncio
import base64
import io
import json
import os
import re
import stat
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from urllib.parse import parse_qsl, urlencode, urlsplit

import anyio
import httpx
import pytest

from tests.fakes.authenticator import Assertion, Attestation, SoftAuthenticator, b64url_decode
from tests.fakes.harness import serve
from tests.fakes.oauth_server import (
    FakeAuthServer,
    FakeResourceServer,
    google_style,
    spotify_style,
)
from tests.unit import onboard_model
from tests.unit.report_model import DIGEST, PIN, asked_line
from zoeymcp.bridge.admit import BridgeTokenHash
from zoeymcp.bridge.child import Child, Spec
from zoeymcp.bridge.main import Options, StartupError, check_options
from zoeymcp.bridge.server import Bridge, Settings
from zoeymcp.cli import onboard as onboard_cli
from zoeymcp.cli.main import main
from zoeymcp.common import ledgerreport, pinhash
from zoeymcp.common.ledgerformat import GENESIS, line_hash
from zoeymcp.common.policy import Policy
from zoeymcp.common.policy.merge import Merged, merge, replace_paths
from zoeymcp.common.policy.schema import hash_token
from zoeymcp.common.policy.view import build_view, dump_view, parse_view
from zoeymcp.common.yamlload import load_mapping
from zoeymcp.egress.allowlist import Allowlist, KeySource
from zoeymcp.entrypoint import launcher
from zoeymcp.portal.app import Ledger, PortalApp, Secrets, load_static
from zoeymcp.portal.passkeys import Passkeys, new_file
from zoeymcp.portal.policyview import view as policy_view
from zoeymcp.portal.routes import STATIC
from zoeymcp.vault import logs, reviewjobs
from zoeymcp.vault.admin import AdminApp, HealthReader, SetupCodes
from zoeymcp.vault.app import EGRESS_HEADER, VaultApp
from zoeymcp.vault.oauth.login import LoginService
from zoeymcp.vault.oauth.tokens import TokenManager
from zoeymcp.vault.reportstore import ReportStore
from zoeymcp.vault.request import oauth_client_variants
from zoeymcp.vault.secretops import Revoker
from zoeymcp.vault.server import ListenerTag
from zoeymcp.vault.store import SecretStore

from .test_admin import KEYS as ADMIN_KEYS
from .test_admin import AdminRig, example_policy
from .test_cli import Reviews as CliReviews
from .test_netclient import bridges_policy
from .test_no_secret_answers import Recording, signed_in, step_up
from .test_no_secret_answers import Reviews as NoSecretReviews
from .test_oauth_tokens import KEYS, FakeClock
from .test_portal_wire import ORIGIN
from .test_reviewjobs import Rig as ReviewRig
from .test_reviewreport import unclassified

pytestmark = pytest.mark.anyio

AGENT = "172.30.4.10"
REDIRECT = "http://127.0.0.1/callback"
GOOGLE_SECRET = "fake-google-client-secret"
MACHINE_ID = "machine-client"
MACHINE_SECRET = "fake-machine-client-secret"
WRONG_SECRET = "fake-wrong-machine-secret"
SENTINEL = "provider-description-sentinel"
# Every error_description the fake authorization server writes.
DESCRIPTIONS = (
    "Refresh token revoked",
    "Unknown refresh token",
    "Token has been expired or revoked.",
    "The grant has expired",
    "Invalid authorization code",
    "redirect_uri doesn't match",
    "PKCE verification failed",
)
ISSUED = re.compile(r"fake-(?:spotify|google|machine|notes)-(?:at|rt|code)-\d+")
# A credential registered with the portal's callback address (M5 design A.5, H.6).
NOTES_ID = "example-notes-client"
CALLBACK = "http://localhost:8081/oauth/callback/notes"
PRINTED_URL = re.compile(r"^  (https://\S+)$", re.MULTILINE)

BASE: dict[str, Any] = {
    "version": 1,
    "mode": "declarative",
}


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def route(name: str, upstream: str) -> dict[str, Any]:
    return {
        "name": name,
        "prefix": f"/{name}",
        "upstream": upstream,
        "credential": name,
        "callers": [{"placeholder": f"ph-agent1-{name}-0001"}],
        "rules": [{"methods": ["GET"], "paths": ["/**"]}],
    }


def policy() -> Policy:
    credentials = {
        "music": {
            "kind": "oauth2",
            "token_url": "https://accounts.spotify.example/token",
            "authorize_url": "https://accounts.spotify.example/authorize",
            "client_id": "0123456789abcdef0123456789abcdef",
            "client_auth": "none",
            "rotates": True,
            "refresh_token": "store:music-refresh",
            "scope": "user-read-currently-playing user-top-read",
        },
        "calendar": {
            "kind": "oauth2",
            "token_url": "https://accounts.google.example/token",
            "authorize_url": "https://accounts.google.example/authorize",
            "client_id": "000000000000-example.apps.googleusercontent.com",
            "client_secret": "store:google-secret",
            "client_auth": "post",
            "refresh_token": "env:CALENDAR_REFRESH",
            "scope": "https://www.googleapis.com/auth/calendar.readonly",
            "authorize_params": {"access_type": "offline", "prompt": "consent"},
        },
        "machine": {
            "kind": "oauth2",
            "token_url": "https://auth.machine.example/token",
            "grant": "client_credentials",
            "client_id": MACHINE_ID,
            "client_secret": "store:machine-secret",
            "scope": "read",
        },
        "notes": {
            "kind": "oauth2",
            "token_url": "https://accounts.notes.example/token",
            "authorize_url": "https://accounts.notes.example/authorize",
            "client_id": NOTES_ID,
            "client_auth": "none",
            "rotates": True,
            "refresh_token": "store:notes-refresh",
            "redirect_uri": CALLBACK,
        },
    }
    routes = [
        route("music", "https://api.spotify.example/v1"),
        route("calendar", "https://api.google.example/v1"),
        route("machine", "https://api.machine.example/v1"),
        route("notes", "https://api.notes.example/v1"),
    ]
    admin = {"listen": "127.0.0.1:8081", "origins": ["http://localhost:8081"]}
    document = {**BASE, "admin": admin, "routes": routes, "credentials": credentials}
    return Policy.model_validate(document)


def by_host(apps: dict[str, Any]) -> Any:
    """One ASGI app that hands each request to the app for its host."""

    async def app(scope: Any, receive: Any, send: Any) -> None:
        host = dict(scope["headers"])[b"host"].decode().split(":")[0]
        await apps[host](scope, receive, send)

    return app


@dataclass
class KeptAuthenticator(SoftAuthenticator):
    """The operator's passkey, keeping everything it returned to the page."""

    made: list[Attestation | Assertion] = field(default_factory=list)

    def create(self, *args: Any, **kwargs: Any) -> Attestation:
        made = super().create(*args, **kwargs)
        self.made.append(made)
        return made

    def get(self, *args: Any, **kwargs: Any) -> Assertion:
        made = super().get(*args, **kwargs)
        self.made.append(made)
        return made


class Kept(Recording):
    """The portal's page, keeping each answer whole as well, for the halves and challenges."""

    def __init__(
        self, client: httpx.AsyncClient, answers: list[str], whole: list[httpx.Response]
    ) -> None:
        super().__init__(client, answers)
        self.whole = whole

    async def call(self, method: str, path: str, body: Any = None) -> httpx.Response:
        response = await super().call(method, path, body)
        self.whole.append(response)
        return response


class World:
    """The vault, its admin app and the CLI, against fake providers. Records every output."""

    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self.clock = FakeClock()
        self.spotify = spotify_style(self.clock.time)
        self.google = google_style(self.clock.time)
        self.machine = FakeAuthServer(
            self.clock.time,
            client_id=MACHINE_ID,
            client_secret=MACHINE_SECRET,
            prefix="fake-machine",
        )
        self.notes = FakeAuthServer(
            self.clock.time,
            client_id=NOTES_ID,
            auth="none",
            rotate=True,
            prefix="fake-notes",
            registered_redirect=CALLBACK,
        )
        self.servers = {
            "accounts.spotify.example": self.spotify,
            "accounts.google.example": self.google,
            "auth.machine.example": self.machine,
            "accounts.notes.example": self.notes,
        }
        self.apis = {
            "api.spotify.example": FakeResourceServer(self.spotify),
            "api.google.example": FakeResourceServer(self.google),
            "api.machine.example": FakeResourceServer(self.machine),
        }
        token_app = by_host({host: server.app() for host, server in self.servers.items()})
        api_app = by_host({host: api.app() for host, api in self.apis.items()})
        self.store = SecretStore(tmp_path, KEYS)
        self.store.load()
        self.policy = policy()
        self.seed = self.google.issue_grant()
        self.token_client = httpx.AsyncClient(transport=httpx.ASGITransport(app=token_app))
        self.tokens = TokenManager(
            self.store,
            self.token_client,
            clock=self.clock.monotonic,
            wall=self.clock.time,
            sleep=self.clock.sleep,
            uniform=lambda low, high: 1.0,
        )
        self.vault = VaultApp(
            self.policy,
            self.store,
            KEYS,
            client=httpx.AsyncClient(transport=httpx.ASGITransport(app=api_app)),
            tokens=self.tokens,
            environ={"CALENDAR_REFRESH": self.seed},
        )
        login = LoginService(self.tokens, clock=self.clock.monotonic, wall=self.clock.time)
        setup = SetupCodes(tmp_path, KEYS.portal_key)
        self.admin_app = AdminApp(
            self.store,
            KEYS,
            lambda: self.policy,
            setup,
            self.tokens,
            login,
            connectors=self.vault.connectors,
            env_names=lambda: self.vault.env_names,
        )
        # The portal, sharing the socket's store, token manager, policy and logins (M5 G), and
        # reading a copy of the gateway's ledger whose records carry keyed digests (M5 J.5).
        self.copy = ReportStore.open(tmp_path)
        (tmp_path / "portal").mkdir(mode=0o700)
        self.portal_app = PortalApp(
            [ORIGIN],
            static=load_static(),
            setup=setup,
            passkeys=Passkeys(new_file(bytes(32)), KEYS.portal_key, tmp_path / "portal" / "p.json"),
            login=login,
            secrets=Secrets(self.store, self.tokens, lambda: self.policy),
            health=HealthReader(
                self.store,
                lambda: self.policy,
                login,
                env_names=lambda: self.vault.env_names,
            ).report,
            ledger=Ledger(self.copy, self.vault.connectors),
        )
        self.passkey = KeptAuthenticator()
        self.page: Kept | None = None
        self.monkeypatch = monkeypatch
        # Everything that leaves the vault, by where it went.
        self.admin_answers: list[str] = []
        self.portal_answers: list[str] = []
        self.portal_whole: list[httpx.Response] = []
        self.portal_codes: list[str] = []  # setup codes redeemed in the portal
        self.pasted: list[str] = []  # every address pasted back, by any surface
        self.cli_outputs: list[str] = []
        self.proxied: list[str] = []
        self.authorize_urls: list[str] = []
        self.flows: list[str] = []

    # --- the operator --------------------------------------------------------------------------

    async def admin(self, method: str, path: str, body: Any = None) -> httpx.Response:
        transport = httpx.ASGITransport(app=self.admin_app.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://admin") as client:
            response = await client.request(method, path, json=body)
        self.admin_answers.append(response.text)
        if response.status_code == 200 and "authorize_url" in response.json():
            self.authorize_urls.append(response.json()["authorize_url"])
            self.flows.append(response.json()["flow"])
        return response

    async def portal_page(self) -> Kept:
        """The portal's page, signed in on first use as the page does it: a setup code, the
        enrolment, the login with the new passkey. Every answer is kept."""
        if self.page is None:
            transport = httpx.ASGITransport(app=self.portal_app)
            client = httpx.AsyncClient(transport=transport, base_url=ORIGIN)
            self.page = page = Kept(client, self.portal_answers, self.portal_whole)
            assert self.portal_app.setup is not None
            code, _ = self.portal_app.setup.issue()
            self.portal_codes.append(code.reveal())
            redeemed = await page.call("POST", "/api/setup/redeem", {"code": code.reveal()})
            assert redeemed.is_success, redeemed.text
            enrol = await page.call("POST", "/api/passkeys/enrol/begin", {"name": "laptop"})
            begun = enrol.json()
            body = {
                "ceremony": begun["ceremony"],
                "credential": self.passkey.create(begun["options"], ORIGIN).body(),
            }
            assert (await page.call("POST", "/api/passkeys/enrol/finish", body)).is_success
            page.token = page.cookie = None
            begun = (await page.call("POST", "/api/login/begin", {})).json()
            body = {
                "ceremony": begun["ceremony"],
                "credential": self.passkey.get(begun["options"], ORIGIN).body(),
            }
            assert (await page.call("POST", "/api/login/finish", body)).is_success
        return self.page

    async def portal(self, kind: str, data: dict[str, Any]) -> httpx.Response:
        """A step-up action, prepared and confirmed as the Secrets page does."""
        return await step_up(await self.portal_page(), self.passkey, kind, data)

    async def portal_start(self, credential: str) -> dict[str, Any]:
        """A connect started in the portal (H.1); its URL and flow are kept, as the admin's."""
        page = await self.portal_page()
        started = await page.call("POST", f"/api/oauth/{credential}/start", {})
        assert started.status_code == 200, started.text
        answer: dict[str, Any] = started.json()
        self.authorize_urls.append(answer["authorize_url"])
        self.flows.append(answer["flow"])
        return answer

    async def browse(self, url: str) -> str:
        """Play the browser: approve, and return the address the browser is sent to."""
        server = self.servers[urlsplit(url).hostname or ""]
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=server.app())) as browser:
            response = await browser.get(url)
        assert response.status_code == 302
        location: str = response.headers["location"]
        self.pasted.append(location)
        return location

    async def login(self, credential: str) -> dict[str, Any]:
        """A login over the admin app, as the M5 portal will do it."""
        started = (await self.admin("POST", f"/oauth/{credential}/login", {})).json()
        pasted = await self.browse(started["authorize_url"])
        body = {"flow": started["flow"], "redirect_url": pasted}
        done = await self.admin("POST", f"/oauth/{credential}/complete", body)
        assert done.status_code == 200, done.text
        answer: dict[str, Any] = done.json()
        return answer

    async def cli(
        self, argv: list[str], stdin: str = "", *, browse: bool = False
    ) -> tuple[int, str, str]:
        """Run the CLI in a thread; its admin requests go to the admin app on this loop."""
        loop = asyncio.get_running_loop()

        def handle(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content) if request.content else None
            call = self.admin(request.method, request.url.raw_path.decode(), body)
            answer = asyncio.run_coroutine_threadsafe(call, loop).result(timeout=60)
            return httpx.Response(answer.status_code, content=answer.content)

        self.monkeypatch.setattr(httpx, "HTTPTransport", lambda **_: httpx.MockTransport(handle))
        out, err = io.StringIO(), io.StringIO()
        world = self

        class Browser(io.StringIO):
            """Stdin that approves the URL the CLI printed and pastes where it led."""

            def readline(self, size: int = -1, /) -> str:  # type: ignore[override]
                [url] = PRINTED_URL.findall(out.getvalue())
                pasted = asyncio.run_coroutine_threadsafe(world.browse(url), loop)
                return pasted.result(timeout=60) + "\n"

        source = Browser() if browse else io.StringIO(stdin)
        code = await asyncio.to_thread(main, argv, stdin=source, out=out, err=err)
        self.cli_outputs += [out.getvalue(), err.getvalue()]
        return code, out.getvalue(), err.getvalue()

    # --- the agent -----------------------------------------------------------------------------

    async def proxy(self, name: str) -> httpx.Response:
        transport = httpx.ASGITransport(app=self.vault, client=(AGENT, 40000))
        async with httpx.AsyncClient(transport=transport, base_url="http://vault") as client:
            response = await client.get(
                f"/{name}/items", headers={"Authorization": f"Bearer ph-agent1-{name}-0001"}
            )
        self.proxied.append(json.dumps(dict(response.headers)) + response.text)
        return response

    # --- what must never show ------------------------------------------------------------------

    def verifiers(self) -> list[str]:
        return [
            call.params["code_verifier"]
            for server in self.servers.values()
            for call in server.calls
            if call.grant_type == "authorization_code"
        ]

    def states(self) -> list[str]:
        return [dict(parse_qsl(urlsplit(url).query))["state"] for url in self.authorize_urls]

    def issued(self) -> set[str]:
        """The fake-issued values that went back to the token endpoints."""
        return {
            value
            for server in self.servers.values()
            for call in server.calls
            for value in call.params.values()
            if ISSUED.fullmatch(value)
        }

    def secrets(self) -> list[str]:
        """Every value that must stay in the vault, apart from fake-issued ones."""
        values = [GOOGLE_SECRET, MACHINE_SECRET, WRONG_SECRET, *DESCRIPTIONS]
        for client_id, secret in (
            ("000000000000-example.apps.googleusercontent.com", GOOGLE_SECRET),
            (MACHINE_ID, MACHINE_SECRET),
            (MACHINE_ID, WRONG_SECRET),
        ):
            values += [v.decode() for v in oauth_client_variants(client_id, secret)]
        return [*values, *self.verifiers(), *self.states()]


def assert_portal_material(world: World, outputs: dict[str, list[str]]) -> None:
    """The portal's session halves, challenges, user handle, authenticator output and pasted
    addresses (M5 design O.5's "never appears", with its exceptions)."""
    answers = [r.json() for r in world.portal_whole if r.text.startswith("{")]
    tokens = [a["token"] for a in answers if "token" in a]
    cookies = [
        value
        for r in world.portal_whole
        for header in r.headers.get_list("set-cookie")
        if (value := header.split(";")[0].split("=", 1)[1])
    ]
    challenges = [a["options"]["challenge"] for a in answers if "options" in a]
    handles = {a["options"]["user"]["id"] for a in answers if "user" in a.get("options", {})}
    # Two sessions (the setup session and the login), and every ceremony and step-up.
    assert (len(tokens), len(cookies)) == (2, 2)
    assert len(challenges) == 5  # enrolment, login, three step-ups
    portal = outputs["portal"]
    elsewhere = [text for where, texts in outputs.items() if where != "portal" for text in texts]
    # A session half shows once, in the answer that mints it (the token in its body, the cookie
    # in its Set-Cookie); a challenge once, in the answer that begins its ceremony or step-up.
    for value in [*tokens, *cookies, *challenges]:
        assert sum(value in text for text in portal) == 1, value
        assert not any(value in text for text in elsewhere), value
    for challenge in challenges:
        hexed = b64url_decode(challenge).hex()
        assert not any(hexed in text for text in [*portal, *elsewhere]), hexed
    # The user handle, only in the enrolment's options: the authenticator's answer carries it
    # back, and nothing echoes it.
    [handle] = handles
    enrolments = [a for a in answers if "user" in a.get("options", {})]
    assert sum(handle in text for text in portal) == len(enrolments)
    assert not any(handle in text for text in elsewhere)
    # What the authenticator returned is sent, never echoed: client data, authenticator data
    # and signatures (credential IDs are named in the options' lists by design).
    sent = [
        value
        for made in world.passkey.made
        for name, value in made.body().items()
        if name in ("client_data_json", "authenticator_data", "signature")
    ]
    assert len(world.passkey.made) == len(challenges) - 1  # one step-up left held
    for value in sent:
        assert not any(value in text for text in [*portal, *elsewhere]), value
    # Every address pasted back, through the CLI, the socket or the portal.
    assert len(world.pasted) >= 10
    for address in world.pasted:
        assert not any(address in text for text in [*portal, *elsewhere]), address


def with_query(url: str, **changes: str) -> str:
    parts = urlsplit(url)
    pairs = dict(parse_qsl(parts.query))
    pairs.update(changes)
    return parts._replace(query=urlencode(pairs)).geturl()


@pytest.fixture
def log_lines() -> Iterator[io.StringIO]:
    buffer = io.StringIO()
    logs.set_stream(buffer)
    try:
        yield buffer
    finally:
        logs.set_stream(None)


async def test_nothing_secret_leaves_the_vault(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, log_lines: io.StringIO
) -> None:
    world = World(tmp_path, monkeypatch)
    put = await world.admin("PUT", "/secrets/google-secret", {"value": GOOGLE_SECRET})
    assert put.status_code == 200
    # The OAuth client secret through the portal (M5 design G): the token manager writes it.
    put = await world.portal("secret.put", {"name": "machine-secret", "value": MACHINE_SECRET})
    assert put.status_code == 200, put.text

    # music: an interactive CLI login, then use, rotation and the upstream 401 path.
    code, out, err = await world.cli(["login", "music"], browse=True)
    assert code == 0, err
    assert "Stored the refresh token for music as music-refresh." in out
    world.apis["api.spotify.example"].echo_token = True
    assert (await world.proxy("music")).status_code == 200
    world.clock.advance(3600)
    assert (await world.proxy("music")).status_code == 200
    assert len(world.spotify.refresh_calls) == 1
    world.apis["api.spotify.example"].always_401 = True
    world.clock.advance(60)
    assert (await world.proxy("music")).status_code == 401
    world.apis["api.spotify.example"].always_401 = False

    # music: --start and --flow with a paste for another login.
    code, out, _ = await world.cli(["login", "music", "--start"])
    assert code == 0
    [url] = PRINTED_URL.findall(out)
    flow = re.findall(r"--flow=(\S+)", out)[0]
    pasted = await world.browse(url)
    argv = ["login", "music", f"--flow={flow}"]
    world.pasted.append(with_query(pasted, state="another-login"))
    code, _, err = await world.cli(argv, world.pasted[-1] + "\n")
    assert (code, err) == (1, "zoeymcp login: the address is for a different login\n")

    # music: the provider refuses, with a description for the operator.
    started = (await world.admin("POST", "/oauth/music/login", {})).json()
    state = dict(parse_qsl(urlsplit(started["authorize_url"]).query))["state"]
    refused = f"{REDIRECT}?" + urlencode(
        {"error": "access_denied", "error_description": SENTINEL, "state": state}
    )
    world.pasted.append(refused)
    code, _, err = await world.cli(["login", "music", f"--flow={started['flow']}"], refused)
    assert code == 1
    assert f"the provider says: {SENTINEL}" in err

    # music: a code pasted twice.
    first = (await world.admin("POST", "/oauth/music/login", {})).json()
    used = await world.browse(first["authorize_url"])
    body = {"flow": first["flow"], "redirect_url": used}
    assert (await world.admin("POST", "/oauth/music/complete", body)).status_code == 200
    second = (await world.admin("POST", "/oauth/music/login", {})).json()
    second_state = dict(parse_qsl(urlsplit(second["authorize_url"]).query))["state"]
    body = {"flow": second["flow"], "redirect_url": with_query(used, state=second_state)}
    world.pasted.append(body["redirect_url"])
    # The token endpoint echoes the used code in error_description.
    world.spotify.error_shape = "echo"
    again = await world.admin("POST", "/oauth/music/complete", body)
    world.spotify.error_shape = "rfc"
    assert again.status_code == 400
    assert again.json()["reason"] == "exchange_failed:oauth_reconsent_needed"
    # The code itself is the sentinel: it matches ISSUED wherever it shows up.
    assert world.spotify.calls[-1].params["code"] == dict(parse_qsl(urlsplit(used).query))["code"]

    # music through the portal (M5 design H.1): a paste for another login and a provider's
    # refusal, both refused before any prompt, then a connect by paste after a step-up.
    page = await world.portal_page()
    begun = await world.portal_start("music")
    pasted = await world.browse(begun["authorize_url"])
    data = {"credential": "music", "flow": begun["flow"]}
    wrong = {**data, "redirect_url": with_query(pasted, state="another-login")}
    world.pasted.append(wrong["redirect_url"])
    other = await page.call("POST", "/api/actions", {"kind": "oauth.complete", "data": wrong})
    assert other.json()["reason"] == "state_mismatch"
    connected = await world.portal("oauth.complete", {**data, "redirect_url": pasted})
    assert connected.status_code == 200, connected.text
    begun = await world.portal_start("music")
    state = dict(parse_qsl(urlsplit(begun["authorize_url"]).query))["state"]
    refused = f"{REDIRECT}?" + urlencode(
        {"error": "access_denied", "error_description": SENTINEL, "state": state}
    )
    world.pasted.append(refused)
    data = {"credential": "music", "flow": begun["flow"], "redirect_url": refused}
    denied = await page.call("POST", "/api/actions", {"kind": "oauth.complete", "data": data})
    assert denied.json()["description_shown"] == SENTINEL
    await page.call("GET", "/api/oauth")

    # calendar: the env seed is promoted, then superseded by a login.
    assert (await world.proxy("calendar")).status_code == 200
    done = await world.login("calendar")
    assert done["seed_note"] is not None
    # Revoked, and the token endpoint echoes the refresh token in error_description.
    world.google.error_shape = "echo"
    world.google.revoke()
    world.clock.advance(3600)
    revoked = await world.proxy("calendar")
    assert revoked.status_code == 502
    assert revoked.json()["code"] == "oauth_reconsent_needed"
    code, out, _ = await world.cli(["oauth", "status", "calendar"])
    assert "hint: run: zoeymcp login calendar" in out
    code, out, err = await world.cli(["login", "calendar"], browse=True)
    assert code == 0, err
    assert (await world.proxy("calendar")).status_code == 200

    # machine: a test fetch, a rejected client, and a reset.
    code, out, err = await world.cli(["login", "machine"])
    assert code == 0, err
    assert (await world.proxy("machine")).status_code == 200
    put = await world.admin("PUT", "/secrets/machine-secret", {"value": WRONG_SECRET})
    assert put.status_code == 200
    code, _, err = await world.cli(["login", "machine"])
    assert code == 1
    assert "invalid_client" in err
    world.clock.advance(3600)
    assert (await world.proxy("machine")).status_code == 502
    assert (await world.cli(["oauth", "reset", "machine"]))[0] == 0

    # Setup codes over the socket and from the CLI: shown to the operator, never logged.
    issued = (await world.admin("POST", "/setup-code", {"reset": True})).json()["code"]
    code, out, _ = await world.cli(["setup-code"])
    assert code == 0
    setup_codes = [issued, out.strip()]
    await world.admin("GET", "/setup-code/status")

    # The portal: a refused write, a value left held by a pending action, and its list.
    page = await world.portal_page()
    data = {"name": "unreferenced", "value": GOOGLE_SECRET}
    unbound = await page.call("POST", "/api/actions", {"kind": "secret.put", "data": data})
    assert unbound.json()["reason"] == "unbound"
    data = {"name": "google-secret", "value": WRONG_SECRET}
    held = await page.call("POST", "/api/actions", {"kind": "secret.put", "data": data})
    assert held.status_code == 200, held.text
    assert [s["name"] for s in (await page.call("GET", "/api/secrets")).json()["secrets"]] == [
        "google-secret",
        "machine-secret",
        "music-refresh",
        "oauth.calendar.live",
    ]

    # Listings.
    await world.admin("GET", "/oauth")
    await world.admin("GET", "/secrets")
    await world.cli(["oauth", "status"])
    await world.cli(["secret", "list"])
    await world.admin("GET", "/health")
    await page.call("GET", "/api/health")
    await page.call("GET", "/api/oauth")
    await page.call("GET", "/api/sessions")
    await page.call("GET", "/api/passkeys")
    for path in STATIC:  # the pages themselves
        response = await page.client.get(path, headers={"Host": "localhost:8081"})
        world.portal_answers.append(response.text + repr(response.headers.multi_items()))
    # The policy and the ledger pages (M5 L, J.5): the reported records' keyed digests and pins
    # stay in the gateway's ledger (Q12).
    reported, prev = [], GENESIS
    for n in range(3):
        reported.append(asked_line(n, prev, n + 1))
        prev = line_hash(reported[-1])
    world.copy.report({"v": 1, "lines": [line.decode() for line in reported]})
    assert (await page.call("GET", "/api/policy")).is_success
    ledger = await page.call("GET", "/api/ledger")
    assert [row["seq"] for row in ledger.json()["rows"]] == [2, 1, 0]
    for text in world.portal_answers:
        for digest in (DIGEST, PIN, "hmac-sha256:"):
            assert digest not in text
    assert (await world.cli(["health"]))[1]
    assert (await world.cli(["health", "--json"]))[1]

    # --- the sweep -----------------------------------------------------------------------------
    log_text = log_lines.getvalue()
    assert log_text
    secrets = world.secrets()
    # Every kind of value was really in play: six code exchanges (one with a used code, one
    # from the portal), and codes and refresh tokens from all three kinds of grant.
    assert len(set(world.verifiers())) == 6
    assert len(set(world.states())) == len(world.authorize_urls) == 9
    kinds = {value.rsplit("-", 2)[1] for value in world.issued()}
    assert kinds == {"code", "rt"}
    assert any(c.status == 400 for c in world.google.calls if c.grant_type == "refresh_token")
    assert world.portal_answers
    outputs = {
        "admin": world.admin_answers,
        "portal": world.portal_answers,
        "cli": world.cli_outputs,
        "proxied": world.proxied,
        "logs": [log_text],
    }
    for where, texts in outputs.items():
        for text in texts:
            shown = text
            for url in world.authorize_urls:
                shown = shown.replace(url, "<authorize-url>")
            if where != "logs":
                # Shown to the operator by design (design E.2).
                shown = shown.replace(SENTINEL, "<description>")
            found = ISSUED.search(shown)
            assert found is None, f"{where}: {found and found.group()}"
            for secret in secrets:
                assert secret not in shown, f"{where}: {secret}"
    # Logs carry no flow ID, authorization URL or provider description at all.
    for value in [*world.flows, *world.authorize_urls, SENTINEL, flow]:
        assert value not in log_text
    # Nor a setup code, in any form the portal would take (M5 design E, M.4).
    assert '"event":"setup_code_issued"' in log_text
    for setup_code in setup_codes:
        raw = setup_code.replace("-", "")
        for form in (setup_code, raw, raw.lower(), *setup_code.split("-")):
            assert form not in log_text
    # Nor one redeemed in the portal, in any answer it made (R56, D-117).
    assert world.portal_codes
    for setup_code in [*world.portal_codes, *setup_codes]:
        raw = setup_code.replace("-", "")
        for form in (setup_code, raw, raw.lower(), *setup_code.split("-")):
            for text in world.portal_answers:
                assert form not in text
    assert_portal_material(world, outputs)
    # The description reached the operator, and only through the failed completion: one admin
    # answer and one portal answer.
    assert sum(SENTINEL in text for text in world.admin_answers) == 1
    assert sum(SENTINEL in text for text in world.portal_answers) == 1
    assert world.authorize_urls
    for url in world.authorize_urls:
        query = dict(parse_qsl(urlsplit(url).query))
        assert query["code_challenge_method"] == "S256"
        assert "client_secret" not in query

    await page.client.aclose()
    await world.vault.aclose()
    await world.token_client.aclose()


# --- the gateway view (M3 design D.1, invariant G1) ---------------------------------------------

LITERAL_TOKEN = "leak-client-token-literal-0001"
# Every value the vault holds that the gateway must not see, by where it sits in the policy.
VAULT_SIDE = {
    "egress proxy": "leak-proxy.example",
    "admin origin": "https://leak-admin.example",
    "idle expiry": '"idle_expiry_days":3333',
    "client token": LITERAL_TOKEN,
    "credential name": "leak-cred-",
    "secret reference": "leak-ref-",
    "header format": "LeakScheme",
    "credential header": "X-Leak-Credential",
    "query credential param": "leak_qparam",
    "path template": "/leak-template/",
    "basic username": "leak-basic-user",
    "oauth client id": "leak-client-id",
    "token url": "leak-token.example",
    "authorize url": "leak-authorize.example",
    "issuer": "leak-issuer.example",
    "redirect uri": "/leak-callback",
    "scope": "leak.scope",
    "extra param": "leak-extra-value",
    "token header": "leak-token-header-value",
    "authorize param": "leak-authorize-value",
    "smtp host": "leak-smtp.example",
    "smtp user": "leak-smtp-user",
    "smtp from": "leak-from@mail.example",
    "smtp to": "leak-to@mail.example",
    "connector name": "leak-connector",
    "route name": "leak-route-",
    "upstream url": "leak-upstream.example",
    "placeholder": "leak-placeholder-",
    "placeholder header": "X-Leak-Placeholder",
    "placeholder query": "leak_ph_param",
    "placeholder source": "192.0.2.77",
    "forced query": "leak-force-value",
    "rule path": "/leak-rule-path",
    "rule param": "leak-rule-value",
    # A route's program (M7 design A.3): routes never reach the view, so neither does it.
    "program egress": "leak-egress.example",
    "program private egress": "leak-egress-private.example",
    "local upstream": "leak-bridge-alias",
    "unix upstream": "zoeymcp-bridge-leaksock",
}
# What the gateway does need, though it sits beside vault-side values, and why.
GATEWAY_NEEDS = {
    "toolkit module": ("leakmodule", "the gateway imports it"),
    "toolkit slot rule": ("/mail/send", "a toolkit's own rules, written in the gateway section"),
}


def secret_heavy_policy() -> Policy:
    oauth = {
        "kind": "oauth2",
        "token_url": "https://leak-token.example/token",
        "authorize_url": "https://leak-authorize.example/authorize",
        "issuer": "https://leak-issuer.example",
        "redirect_uri": "http://127.0.0.1/leak-callback",
        "client_id": "leak-client-id",
        "client_secret": "store:leak-ref-oauth-client",
        "refresh_token": "env:LEAK_REF_REFRESH",
        "scope": "leak.scope",
        "extra_params": {"audience": "leak-extra-value"},
        "token_headers": {"X-Extra": "leak-token-header-value"},
        "authorize_params": {"prompt": "leak-authorize-value"},
        "idle_expiry_days": 3333,
    }
    credentials = {
        "leak-cred-header": {
            "kind": "header",
            "header": "X-Leak-Credential",
            "format": "LeakScheme {secret}",
            "secret": "store:leak-ref-header",
        },
        "leak-cred-query": {"kind": "query", "param": "leak_qparam", "secret": "env:LEAK_REF_Q"},
        "leak-cred-path": {
            "kind": "path",
            "template": "/leak-template/{secret}",
            "secret": "store:leak-ref-path",
        },
        "leak-cred-basic": {
            "kind": "basic",
            "username": "leak-basic-user",
            "secret": "store:leak-ref-basic",
        },
        "leak-cred-oauth": oauth,
    }
    connector = {
        "kind": "smtp",
        "host": "leak-smtp.example",
        "port": 465,
        "username": "leak-smtp-user",
        "password": "store:leak-ref-smtp",
        "from": "Leak <leak-from@mail.example>",
        "to": ["leak-to@mail.example"],
    }
    placeholders = [
        {"placeholder": "leak-placeholder-0001", "header": "X-Leak-Placeholder"},
        {"placeholder": "leak-placeholder-0002", "query": "leak_ph_param"},
        {"placeholder": "leak-placeholder-0003", "sources": ["192.0.2.77/32"]},
    ]
    routes = [
        {
            "name": "leak-route-mcp",
            "prefix": "/mcp-a",
            "upstream": "https://leak-upstream.example/base",
            "credential": "leak-cred-header",
            "callers": ["gateway"],
            "stream": True,
            "rules": [{"methods": ["POST", "GET", "DELETE"], "paths": ["/mcp"]}],
        },
        *(
            {
                "name": f"leak-route-{name.removeprefix('leak-cred-')}",
                "prefix": f"/r-{name.removeprefix('leak-cred-')}",
                "upstream": "https://leak-upstream.example/other",
                "credential": name,
                "callers": placeholders,
                "query": {"force": {"mode": "leak-force-value"}},
                "rules": [
                    {
                        "methods": ["GET"],
                        "paths": ["/leak-rule-path/{item}"],
                        "params": {"item": ["leak-rule-value"]},
                    }
                ],
            }
            for name in credentials
        ),
        {
            "name": "leak-route-mail",
            "prefix": "/mail",
            "connector": "leak-connector",
            "callers": ["gateway"],
            "rules": [{"methods": ["POST"], "paths": ["/send"]}],
        },
        # Two local MCP routes (M7 design A.2 rows 9 and 9b), each with a program holding all
        # three of its settings.
        *(
            {
                "name": f"leak-route-{kind}",
                "prefix": f"/{kind}",
                "upstream": upstream,
                "allow_insecure_upstream": kind == "bridge",
                "credential": "leak-cred-header",
                "callers": ["gateway"],
                "stream": True,
                "rules": [{"methods": ["POST", "GET", "DELETE"], "paths": ["/mcp"]}],
                "program": {
                    "egress": ["leak-egress.example:443", "leak-egress-private.example:443"],
                    "egress_private": ["leak-egress-private.example:443"],
                    "holds_secret": True,
                },
            }
            for kind, upstream in (
                ("bridge", "http://leak-bridge-alias:9000"),
                ("socket", "unix:/run/zoeymcp-bridge-leaksock/mcp.sock"),
            )
        ),
    ]
    gateway = {
        "clients": {
            "literal": {"token": LITERAL_TOKEN, "servers": ["srv-remote"]},
            "hashed": {
                "token_sha256": "sha256:" + "3" * 64,
                "servers": ["srv-remote", "srv-toolkit", "srv-bridge", "srv-socket"],
            },
        },
        "servers": {
            "srv-remote": {"kind": "remote", "route": "leak-route-mcp", "path": "/mcp"},
            "srv-bridge": {"kind": "remote", "route": "leak-route-bridge"},
            "srv-socket": {"kind": "remote", "route": "leak-route-socket"},
            "srv-toolkit": {
                "kind": "toolkit",
                "module": "zoeymcp.toolkits.leakmodule",
                "slots": {
                    "mail": {
                        "route": "leak-route-mail",
                        "rules": [{"methods": ["POST"], "paths": ["/send"], "approved": True}],
                    }
                },
            },
        },
    }
    return Policy.model_validate(
        {
            "version": 1,
            "mode": "managed",
            "egress_proxy": "http://leak-proxy.example:3128",
            "admin": {"listen": "127.0.0.1:8081", "origins": ["https://leak-admin.example"]},
            "credentials": credentials,
            "connectors": {"leak-connector": connector},
            "routes": routes,
            "gateway": gateway,
        }
    )


# What the portal's policy view hides of the same policy (M5 design L): the client token and its
# hash, every placeholder, account details and recipients, and the free text sent upstream.
POLICY_VIEW_HIDES = (
    "client token",
    "placeholder",
    "basic username",
    "smtp user",
    "smtp from",
    "smtp to",
    "token header",
    "forced query",
)


def test_the_portals_policy_view_hides_what_it_must() -> None:
    policy = secret_heavy_policy()
    served = json.dumps(policy_view(policy, "env"))
    for where in POLICY_VIEW_HIDES:
        assert VAULT_SIDE[where] not in served, where
    assert "sha256:" + "3" * 64 not in served  # nor the other client's token hash
    assert hash_token(LITERAL_TOKEN) not in served
    # Secret references show as written: they name a secret, never hold one.
    assert "store:leak-ref-oauth-client" in served


def test_the_gateway_view_holds_nothing_from_the_vault_side() -> None:
    policy = secret_heavy_policy()
    # Every sentinel is really in the policy.
    policy_text = policy.model_dump_json(by_alias=True)
    for where, value in VAULT_SIDE.items():
        assert value in policy_text, where
    view = build_view(policy)
    served = dump_view(view).decode()
    for where, value in VAULT_SIDE.items():
        assert value not in served, where
    for marker in (
        "store:",
        "env:",
        "https://",
        "http://",
        "unix:",
        "placeholder",
        "secret",
        "egress",
        "program",
    ):
        assert marker not in served, marker
    for where, (value, _why) in GATEWAY_NEEDS.items():
        assert value in served, where
    # A slot names its connector's kind, never the connector.
    slot = view.gateway.servers["srv-toolkit"].model_dump()["slots"]["mail"]
    assert (slot["prefix"], slot["connector"]) == ("/mail", "smtp")
    # What the gateway does get: the token's hash and the vault path.
    assert hash_token(LITERAL_TOKEN) in served
    assert view.gateway.servers["srv-remote"].model_dump()["vault_path"] == "/mcp-a/mcp"
    # A bridge is a remote server like any other: its route's prefix and the server's path.
    assert view.gateway.servers["srv-bridge"].model_dump()["vault_path"] == "/bridge/mcp"
    assert view.gateway.servers["srv-socket"].model_dump()["vault_path"] == "/socket/mcp"
    assert parse_view(served.encode()) == view


# --- the report path (M5 design J.2, J.4, M.4) ---------------------------------------------------


async def test_no_review_job_id_or_report_reaches_the_vault_logs(tmp_path: Path) -> None:
    """Jobs queued over the socket, claimed by a poll, and ended by a report, a lying report, a
    gateway's error and the clock: the log holds servers, hash8s, counts and reasons only."""
    sentinel = "review-description-sentinel"
    message = "gateway-message-sentinel"
    buffer = io.StringIO()
    logs.set_stream(buffer)
    try:
        rig = ReviewRig(tmp_path)
        rig.seen()
        texts: list[str] = []
        ids: list[str] = []
        for outcome in ("done", "pin_mismatch", "error", "stale"):
            queued = await rig.socket("POST", "/review/notes", {"fresh": True})
            texts.append(queued.text)
            job = queued.json()["job"]
            ids.append(job)
            if outcome == "stale":
                rig.clock.now += reviewjobs.QUEUE_TTL
                rig.seen()
            else:
                texts.append((await rig.poll()).text)
            data = unclassified("secret_tool")
            data["tools"][0]["definition"]["description"] = sentinel
            data["tools"][0]["pin"] = pinhash.pin_of(data["tools"][0]["definition"])
            if outcome == "pin_mismatch":
                data["tools"][0]["pin"] = PIN
            body: dict[str, Any] = {"v": 1, "job": job, "server": "notes", "report": data}
            if outcome == "error":
                error = {"status": 502, "code": "x", "message": message}
                body = {"v": 1, "job": job, "error": error}
            if outcome != "stale":
                texts.append((await rig.post(body)).text)
            texts.append((await rig.socket("GET", f"/review/jobs/{job}")).text)
        await rig.app.aclose()
    finally:
        logs.set_stream(None)
    text = buffer.getvalue()
    for event in ("review_requested", "review_reported", "review_refused", "review_stale"):
        assert f'"event":"{event}"' in text
    for secret in (*ids, sentinel, message, "secret_tool", PIN):
        assert secret not in text, secret
    # The report's text reaches the operator's read of the done job, and nothing else.
    assert sum(sentinel in answer for answer in texts) == 1
    assert all(message not in answer for answer in texts)


async def test_no_ledger_line_reaches_the_vault_logs(tmp_path: Path) -> None:
    """Reports accepted and refused, a torn tail, a broken chain and a restart: the log holds
    seqs, hashes and reasons, never a record, a keyed digest, a pin or a name from one."""

    def chain(count: int, tick: int) -> list[bytes]:
        lines: list[bytes] = []
        prev = GENESIS
        for n in range(count):
            lines.append(asked_line(n, prev, tick + n + 1, big=True))
            prev = line_hash(lines[-1])
        return lines

    buffer = io.StringIO()
    logs.set_stream(buffer)
    try:
        store = SecretStore(tmp_path, KEYS)
        store.load()
        copy = ReportStore.open(tmp_path, rotate_bytes=2000)
        app = VaultApp(policy(), store, KEYS, environ={}, reports=copy)
        transport = httpx.ASGITransport(app=ListenerTag(app, "gateway"))
        good, forked = chain(5, 0), chain(5, 100)
        async with httpx.AsyncClient(transport=transport, base_url="http://vault") as client:
            for lines in (good[:3], good[2:5], forked[1:3], good[:1]):
                await client.post(
                    ledgerreport.PATH,
                    content=ledgerreport.encode(lines),
                    headers={"content-type": "application/json"},
                )
            bad = json.dumps({"v": 1, "lines": [good[0].decode() + "x"]}).encode()
            await client.post(
                ledgerreport.PATH, content=bad, headers={"content-type": "application/json"}
            )
            await client.get(ledgerreport.PATH)
        copy.restart()
        copy.report({"v": 1, "lines": [line.decode() for line in good[:3]]})
        newest = sorted((tmp_path / "ledger-reported").glob("*.jsonl"))[-1]
        newest.write_bytes(newest.read_bytes() + good[3][:40])
        ReportStore.open(tmp_path)
        await app.aclose()
    finally:
        logs.set_stream(None)
    text = buffer.getvalue()
    for event in ("ledger_report_accepted", "ledger_report_refused", "ledger_reported_restarted"):
        assert f'"event":"{event}"' in text
    assert '"event":"ledger_reported_repaired"' in text
    for line in [*good, *forked]:
        assert line.decode() not in text
        assert line.decode()[:60] not in text
    for secret in (DIGEST, PIN, "n" * 127 + "1", "hmac-sha256:"):
        assert secret not in text


async def callback(world: World, url: str, binder: str | None) -> httpx.Response:
    """The provider's redirect, as the operator's browser follows it to the portal's callback (M5
    design C.7): a cross-site top-level GET, with the flow's binding cookie when given. The
    answer is kept with the portal's."""
    headers = {
        "Host": "localhost:8081",
        "Sec-Fetch-Site": "cross-site",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Dest": "document",
    }
    if binder is not None:
        headers["Cookie"] = f"zoeymcp-8081-cb={binder}"
    transport = httpx.ASGITransport(app=world.portal_app)
    async with httpx.AsyncClient(transport=transport, base_url=ORIGIN) as client:
        response = await client.get(url, headers=headers)
    world.portal_answers.append(response.text + repr(response.headers.multi_items()))
    return response


async def test_the_callback_shows_no_query_and_its_binder_only_in_its_cookie(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, log_lines: io.StringIO
) -> None:
    """The callback's query (code, state, error_description) reaches no answer and no log line;
    the binder is in its start answer's Set-Cookie and nowhere else (M5 design O.5, P1, P17). The
    one description shown is a failed callback's, to its owner's poll."""
    world = World(tmp_path, monkeypatch)
    page = await world.portal_page()
    binders = []
    for _ in range(2):
        started = await page.call("POST", "/api/oauth/notes/start", {})
        assert started.status_code == 200, started.text
        begun = started.json()
        world.authorize_urls.append(begun["authorize_url"])
        world.flows.append(begun["flow"])
        binders.append(started.headers["set-cookie"].split(";")[0].split("=", 1)[1])
        if len(binders) == 1:
            first = begun
            # Taken: the code is held, out of the address bar (303).
            location = await world.browse(begun["authorize_url"])
            assert (await callback(world, location, binders[0])).status_code == 303
            # Refused in place: no binder, with a provider's text in the query.
            state = dict(parse_qsl(urlsplit(location).query))["state"]
            hostile = f"{ORIGIN}/oauth/callback/notes?" + urlencode(
                {"error": "access_denied", "error_description": SENTINEL + "-x", "state": state}
            )
            assert (await callback(world, hostile, None)).status_code == 400
            status = await page.call("GET", f"/api/oauth/flows/{begun['flow']}")
            assert status.json()["stage"] == "returned"
            held = await world.portal("oauth.complete", {"credential": "notes", **_flow(begun)})
            assert held.status_code == 200, held.text
    # A provider's refusal through the callback: the flow fails, its text for the owner.
    world.notes.answer = "error"
    world.notes.error_description = SENTINEL
    location = await world.browse(world.authorize_urls[-1])
    assert (await callback(world, location, binders[1])).status_code == 303
    failed = await page.call("GET", f"/api/oauth/flows/{world.flows[-1]}")
    assert failed.json()["failure"]["description_shown"] == SENTINEL

    log_text = log_lines.getvalue()
    assert '"event":"oauth_callback_returned"' in log_text
    assert '"event":"oauth_callback_failed"' in log_text
    [code] = [c.params["code"] for c in world.notes.calls]
    for text in [*world.portal_answers, log_text]:
        shown = text
        for url in world.authorize_urls:
            shown = shown.replace(url, "<authorize-url>")
        for value in (code, SENTINEL + "-x", *world.states(), *world.verifiers()):
            assert value not in shown
    # The binder: once, in its start answer's Set-Cookie.
    for binder in binders:
        [where] = [text for text in world.portal_answers if binder in text]
        assert f"zoeymcp-8081-cb={binder}; Path=/oauth/callback/notes" in where
        assert binder not in log_text
    # The description, to the owner's poll only, and never logged.
    assert sum(SENTINEL in text for text in world.portal_answers) == 1
    assert SENTINEL not in log_text
    assert first["callback"] == ORIGIN
    await page.client.aclose()
    await world.vault.aclose()
    await world.token_client.aclose()


def _flow(begun: dict[str, Any]) -> dict[str, Any]:
    return {"flow": begun["flow"], "returned": True}


async def test_a_given_client_secret_reaches_the_store_and_nothing_else(
    tmp_path: Path, log_lines: io.StringIO
) -> None:
    """Every onboarding answer and log line, through a refused register, a draft run whose
    final check fails (the secret stored and deleted again, OPS-5), fragment 1 again at each
    indent and a resumed discovery."""
    rig = AdminRig(tmp_path, onboard=True)
    secret = {"client_secret": onboard_model.GIVEN_SECRET}
    texts: list[str] = []

    async def call(method: str, path: str, body: Any = None) -> httpx.Response:
        response = await rig.call(method, path, body)
        texts.append(response.text + repr(response.headers.multi_items()))
        return response

    plan = (await call("POST", "/onboard/discover", onboard_model.confidential())).json()
    onboarding = plan["onboarding"]
    refused = await call("POST", f"/onboard/{onboarding}/fragment", secret)
    assert refused.status_code == 400
    made = await call("POST", f"/onboard/{onboarding}/register", secret)
    assert made.status_code == 200
    for indent in (0, 4, "compose"):
        await call("POST", f"/onboard/{onboarding}/fragment", {"indent": indent})
    again = await call("POST", f"/onboard/{onboarding}/register", secret)
    assert again.status_code == 400
    await call("POST", "/onboard/discover", onboard_model.confidential())
    assert (await call("DELETE", f"/onboard/{onboarding}")).status_code == 204
    # A second client under other names, whose final check fails after its secret is written.
    second = {**onboard_model.confidential(), "name": "notes-b"}
    plan = (await call("POST", "/onboard/discover", second)).json()
    store_put = rig.store.put

    def put_then_clash(*args: Any, **kwargs: Any) -> None:
        store_put(*args, **kwargs)
        raw = rig.policy.model_dump(by_alias=True)
        clash = {**raw["routes"][0], "name": "clash", "prefix": "/notes-b"}
        rig.policy = Policy.model_validate({**raw, "routes": [*raw["routes"], clash]})

    rig.store.put = put_then_clash  # type: ignore[method-assign]
    failed = await call("POST", f"/onboard/{plan['onboarding']}/register", secret)
    assert failed.status_code == 422
    assert rig.store.entry("notes-b-client-secret") is None
    stored, _ = rig.store.get_for_oauth(
        onboard_model.SECRET_NAME, token_url=f"{onboard_model.ISSUER}/token"
    )
    assert stored.reveal() == onboard_model.GIVEN_SECRET
    assert '"store:notes-client-secret"' in made.json()["diff"]["yaml"]
    swept = "".join([*texts, log_lines.getvalue()])
    assert onboard_model.GIVEN_SECRET not in swept
    await rig.token_client.aclose()


async def test_a_reregistered_client_secret_reaches_the_store_and_nothing_else(
    tmp_path: Path, log_lines: io.StringIO
) -> None:
    """D.12 (step 8b): after fragment 1 is committed, the second run's comparison, and a
    re-registration whose new client secret replaces the stored one, fragment 1 again: neither
    secret in any answer or log line."""
    rig = AdminRig(tmp_path, onboard=True)
    replaced = "onboard-reregistered-secret-0002"
    texts: list[str] = []

    async def call(method: str, path: str, body: Any = None) -> httpx.Response:
        response = await rig.call(method, path, body)
        texts.append(response.text + repr(response.headers.multi_items()))
        return response

    secret = {"client_secret": onboard_model.GIVEN_SECRET}
    plan = (await call("POST", "/onboard/discover", onboard_model.confidential())).json()
    made = (await call("POST", f"/onboard/{plan['onboarding']}/register", secret)).json()
    raw = rig.policy.model_dump(mode="json", by_alias=True, exclude_defaults=True)
    merged = merge(raw, load_mapping(made["diff"]["yaml"]))
    assert isinstance(merged, Merged)
    rig.set_policy(Policy.model_validate(merged.data))
    compared = await call("POST", "/onboard/discover", onboard_model.confidential())
    assert compared.json()["stage"] == "committed"
    again = {**onboard_model.confidential(), "client_id": "notes-new-client", "reregister": True}
    plan = (await call("POST", "/onboard/discover", again)).json()
    redone = await call(
        "POST", f"/onboard/{plan['onboarding']}/register", {"client_secret": replaced}
    )
    assert redone.status_code == 200, redone.text
    await call("POST", f"/onboard/{plan['onboarding']}/fragment", {"indent": "compose"})
    stored, _ = rig.store.get_for_oauth(
        onboard_model.SECRET_NAME, token_url=f"{onboard_model.ISSUER}/token"
    )
    assert stored.reveal() == replaced
    swept = "".join([*texts, log_lines.getvalue()])
    assert onboard_model.GIVEN_SECRET not in swept
    assert replaced not in swept
    await rig.token_client.aclose()


async def test_a_registered_client_secret_reaches_the_store_and_nothing_else(
    tmp_path: Path, log_lines: io.StringIO
) -> None:
    """D.4, D.7, X19 (step 11): a registration whose answer carries a client secret, a
    registration access token and its URI. Through the plan, the register, fragment 1 at each
    indent, a resumed discovery and the second run after the commit, the secret reaches the
    store alone, and the token and the URI nowhere at all, the store's clear meta included."""
    rig = AdminRig(tmp_path, onboard=True, register=onboard_model.planted)
    texts: list[str] = []

    async def call(method: str, path: str, body: Any = None) -> httpx.Response:
        response = await rig.call(method, path, body)
        texts.append(response.text + repr(response.headers.multi_items()))
        return response

    body = {"url": onboard_model.SERVER_URL}
    plan = (await call("POST", "/onboard/discover", body)).json()
    assert plan["plan"]["registration"] == "dcr"
    made = await call("POST", f"/onboard/{plan['onboarding']}/register", {})
    assert made.status_code == 200, made.text
    for indent in (0, 4, "compose"):
        await call("POST", f"/onboard/{plan['onboarding']}/fragment", {"indent": indent})
    await call("POST", "/onboard/discover", body)
    raw = rig.policy.model_dump(mode="json", by_alias=True, exclude_defaults=True)
    merged = merge(raw, load_mapping(made.json()["diff"]["yaml"]))
    assert isinstance(merged, Merged)
    rig.set_policy(Policy.model_validate(merged.data))
    compared = await call("POST", "/onboard/discover", body)
    assert compared.json()["stage"] == "committed"
    stored, _ = rig.store.get_for_oauth(
        onboard_model.SECRET_NAME, token_url=f"{onboard_model.ISSUER}/token"
    )
    assert stored.reveal() == onboard_model.DCR_SECRET
    assert '"store:notes-client-secret"' in made.json()["diff"]["yaml"]
    swept = "".join([*texts, log_lines.getvalue()])
    assert onboard_model.DCR_SECRET not in swept
    held = rig.store.path.read_bytes().decode("utf-8")
    for planted in (onboard_model.REGISTRATION_TOKEN, onboard_model.REGISTRATION_URI):
        assert planted not in swept + held
    await rig.token_client.aclose()


async def test_a_revoked_grant_reaches_its_revocation_endpoint_and_nothing_else(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, log_lines: io.StringIO
) -> None:
    """M7 design D.9, X18, X19: a refresh token deleted through the portal and a live slot
    deleted over the socket are each revoked at their own token endpoint's origin, the
    confidential client's secret with it; neither token, nor the secret, shows in any answer,
    CLI output or log line."""
    world = World(tmp_path, monkeypatch)
    raw = world.policy.model_dump(mode="json", by_alias=True, exclude_defaults=True)
    raw["credentials"]["music"]["revocation_url"] = "https://accounts.spotify.example/revoke"
    raw["credentials"]["calendar"]["revocation_url"] = "https://accounts.google.example/revoke"
    world.policy = Policy.model_validate(raw)
    world.vault.reload(world.policy)
    # The socket and the portal share one revoker, on a client that reaches each fake by host.
    revoker = Revoker(world.token_client)
    world.admin_app = AdminApp(
        world.store,
        KEYS,
        lambda: world.policy,
        SetupCodes(tmp_path, KEYS.portal_key),
        world.tokens,
        revoker=revoker,
    )
    world.portal_app.secrets = Secrets(world.store, world.tokens, lambda: world.policy, revoker)
    put = await world.admin("PUT", "/secrets/google-secret", {"value": GOOGLE_SECRET})
    assert put.status_code == 200
    code, _, err = await world.cli(["login", "music"], browse=True)
    assert code == 0, err
    assert (await world.proxy("calendar")).status_code == 200  # the seed, promoted
    music = world.store.get_for_oauth(
        "music-refresh", token_url="https://accounts.spotify.example/token"
    )[0].reveal()
    deleted = await world.portal("secret.delete", {"name": "music-refresh"})
    assert deleted.json() == {"name": "music-refresh", "deleted": True, "revocation": "requested"}
    deleted = await world.admin("DELETE", "/secrets/oauth.calendar.live")
    assert deleted.json()["revocation"] == "requested"
    assert (await world.cli(["secret", "list"]))[0] == 0
    with anyio.fail_after(10):
        await revoker.wait()
    assert world.spotify.revocations == [music]
    [calendar] = world.google.revocations
    assert ISSUED.fullmatch(calendar)
    [sent] = [s for s in world.google.seen if s.path == "/revoke"]
    assert dict(parse_qsl(sent.body.decode()))["client_secret"] == GOOGLE_SECRET
    outcomes = [json.loads(line) for line in log_lines.getvalue().splitlines()]
    revoked = [(e["credential"], e["outcome"]) for e in outcomes if e["event"] == "oauth_revoked"]
    assert sorted(revoked) == [("calendar", "ok"), ("music", "ok")]
    # --- the sweep -----------------------------------------------------------------------------
    texts = [
        *world.admin_answers,
        *world.portal_answers,
        *world.cli_outputs,
        *world.proxied,
        log_lines.getvalue(),
    ]
    for text in texts:
        shown = text
        for url in world.authorize_urls:
            shown = shown.replace(url, "<authorize-url>")
        found = ISSUED.search(shown)
        assert found is None, found and found.group()
        for secret in [*world.secrets(), music, calendar]:
            assert secret not in shown, secret
    assert world.page is not None
    await world.page.client.aclose()
    await revoker.aclose()
    await world.vault.aclose()
    await world.token_client.aclose()


# --- the portal's MCP servers section (M7 design K, step 14a) -----------------------------------


async def test_the_portals_onboarding_and_review_leak_nothing(
    tmp_path: Path, log_lines: io.StringIO
) -> None:
    """K.3, D.7, X19: a given client secret held by ``onboard.register`` and stored, a refused
    register, fragment 1 again at each indent, a resumed discovery, a cancel, then a registration
    whose answer brings a client secret, a registration access token and a URI; and the review's
    rows and fragment 2. Every portal answer and log line: the secrets reach the store alone, the
    token and the URI nothing at all, and a review job's ID no log line."""
    rig = AdminRig(tmp_path)
    (tmp_path / "portal").mkdir(mode=0o700)
    passkeys = Passkeys(new_file(bytes(32)), KEYS.portal_key, tmp_path / "portal" / "p.json")
    reviews = NoSecretReviews()
    app = PortalApp(
        [ORIGIN],
        static=load_static(),
        setup=rig.setup,
        passkeys=passkeys,
        login=LoginService(rig.tokens),
        secrets=Secrets(rig.store, rig.tokens, lambda: rig.policy),
        onboard=onboard_model.onboard_service(
            rig.store, rig.tokens, lambda: rig.policy, register=onboard_model.planted
        ),
        reviews=reviews,
    )
    answers: list[str] = []
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ORIGIN)
    page = Recording(client, answers)
    authenticator = SoftAuthenticator()
    await signed_in(page, app, authenticator)
    given = {
        "url": onboard_model.SERVER_URL,
        "client_id": onboard_model.CLIENT_ID,
        "issuer": onboard_model.ISSUER,
        "client_auth": "basic",
    }
    onboarding = (await page.call("POST", "/api/onboard/discover", given)).json()["onboarding"]
    wrong = {"onboarding": onboarding, "client_secret": 7}
    refused = await page.call("POST", "/api/actions", {"kind": "onboard.register", "data": wrong})
    assert refused.status_code == 400
    data = {"onboarding": onboarding, "client_secret": onboard_model.GIVEN_SECRET}
    stored = await step_up(page, authenticator, "onboard.register", data)
    assert stored.status_code == 200, stored.text
    for indent in (0, 4, "compose"):
        await page.call("POST", f"/api/onboard/{onboarding}/fragment", {"indent": indent})
    await page.call("GET", f"/api/onboard/{onboarding}")
    await page.call("GET", "/api/servers")
    await page.call("POST", "/api/onboard/discover", given)
    assert (await page.call("DELETE", f"/api/onboard/{onboarding}")).status_code == 200
    # The registration then stores its own client's secret under the same name.
    assert rig.store.delete(onboard_model.SECRET_NAME)
    plan = await page.call("POST", "/api/onboard/discover", {"url": onboard_model.SERVER_URL})
    assert plan.json()["plan"]["registration"] == "dcr"
    registered = await step_up(
        page, authenticator, "onboard.register", {"onboarding": plan.json()["onboarding"]}
    )
    assert registered.status_code == 200, registered.text
    await page.call("POST", f"/api/onboard/{plan.json()['onboarding']}/fragment", {"indent": 2})
    job = reviews.portal_done.id
    await page.call("GET", f"/api/review/jobs/{job}")
    choices = {"include": ["list_notes"], "allow": ["list_notes"], "approve": []}
    await page.call("POST", f"/api/review/jobs/{job}/diff", choices)
    stored_secret, _ = rig.store.get_for_oauth(
        onboard_model.SECRET_NAME, token_url=f"{onboard_model.ISSUER}/token"
    )
    assert stored_secret.reveal() == onboard_model.DCR_SECRET
    swept = "".join([*answers, log_lines.getvalue()])
    for secret in (onboard_model.GIVEN_SECRET, onboard_model.DCR_SECRET):
        assert secret not in swept
    held = rig.store.path.read_bytes().decode("utf-8")
    for planted in (onboard_model.REGISTRATION_TOKEN, onboard_model.REGISTRATION_URI):
        assert planted not in swept + held
    assert job not in log_lines.getvalue()
    assert sum(job in answer for answer in answers) >= 1
    await client.aclose()
    await rig.token_client.aclose()


# --- one onboarding through the socket and the portal (M7 design O.5, step 15) ----------------


class Onboarding:
    """The vault's admin socket and portal over one store, token manager, logins, onboardings and
    review jobs, as ``zoeymcp vault`` shares them. The onboarding service's server registers a
    confidential client whose answer carries a secret, a registration access token and its URI
    (onboard_model's ``planted``, each request kept); the fake authorization server signs that
    client in. The gateway's side of a review is played at once (test_cli's ``Reviews``)."""

    def __init__(self, tmp_path: Path) -> None:
        self.auth = FakeAuthServer(
            client_id=onboard_model.DCR_CLIENT_ID,
            client_secret=onboard_model.DCR_SECRET,
            auth="basic",
            issuer=onboard_model.ISSUER,
            iss_supported=True,
            scopes=("notes.read", "offline_access"),
            registration="none",
            registered_redirect="http://127.0.0.1/callback/notes",
            prefix="fake-notes",
        )
        self.auth_app = self.auth.app()
        self.store = SecretStore(tmp_path, KEYS)
        self.store.load()
        self.policy = example_policy()
        self.token_client = httpx.AsyncClient(transport=httpx.ASGITransport(app=self.auth_app))
        self.tokens = TokenManager(self.store, self.token_client)
        self.tokens.configure(self.policy, {})
        # The registration requests the onboarding sent (X1).
        self.registrations: list[httpx.Request] = []
        onboard = onboard_model.onboard_service(
            self.store, self.tokens, lambda: self.policy, register=self.register
        )
        self.reviews = CliReviews(lambda: self.policy)
        login = LoginService(self.tokens)
        setup = SetupCodes(tmp_path, KEYS.portal_key)
        self.admin_app = AdminApp(
            self.store,
            KEYS,
            lambda: self.policy,
            setup,
            self.tokens,
            login,
            onboard=onboard,
            reviews=self.reviews,
        )
        (tmp_path / "portal").mkdir(mode=0o700)
        self.portal_app = PortalApp(
            [ORIGIN],
            static=load_static(),
            setup=setup,
            passkeys=Passkeys(new_file(bytes(32)), KEYS.portal_key, tmp_path / "portal" / "p.json"),
            login=login,
            secrets=Secrets(self.store, self.tokens, lambda: self.policy),
            onboard=onboard,
            reviews=self.reviews,
        )
        # Everything that left the vault, and every authorization URL it showed.
        self.texts: list[str] = []
        self.authorize_urls: list[str] = []

    async def register(self, request: httpx.Request) -> httpx.Response:
        """onboard_model's ``planted``, the request kept."""
        self.registrations.append(request)
        return await onboard_model.planted(request)

    def commit(self, fragment: str) -> None:
        """A fragment merged as ``check --with`` merges it, committed and reloaded."""
        base = self.policy.model_dump(mode="json", by_alias=True, exclude_defaults=True)
        merged = merge(base, load_mapping(fragment), replace=replace_paths(fragment))
        assert isinstance(merged, Merged)
        self.policy = Policy.model_validate(merged.data)
        self.tokens.configure(self.policy, {})

    async def admin(self, request: httpx.Request) -> httpx.Response:
        transport = httpx.ASGITransport(app=self.admin_app.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://admin") as client:
            answer = await client.request(
                request.method,
                request.url.raw_path.decode(),
                content=request.content,
                headers={"content-type": "application/json"} if request.content else {},
            )
        self.texts.append(answer.text + repr(answer.headers.multi_items()))
        return answer

    async def browse(self, url: str) -> str:
        """The operator's browser: approve, and return where the provider sent it."""
        self.authorize_urls.append(url)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=self.auth_app)) as browser:
            answer = await browser.get(url)
        assert answer.status_code == 302, answer.text
        location: str = answer.headers["location"]
        return location

    async def cli(
        self, monkeypatch: pytest.MonkeyPatch, argv: list[str], stdin: str | None = None
    ) -> tuple[int, str, str]:
        """The CLI in a thread, on the socket; without ``stdin``, reading the paste opens the
        URL it printed."""
        loop = asyncio.get_running_loop()

        def handle(request: httpx.Request) -> httpx.Response:
            answer = asyncio.run_coroutine_threadsafe(self.admin(request), loop).result(60)
            return httpx.Response(answer.status_code, content=answer.content)

        monkeypatch.setattr(httpx, "HTTPTransport", lambda **_: httpx.MockTransport(handle))
        out, err = io.StringIO(), io.StringIO()
        world = self

        class Paste(io.StringIO):
            def readline(self, size: int = -1, /) -> str:  # type: ignore[override]
                [url] = PRINTED_URL.findall(out.getvalue())
                pasted = asyncio.run_coroutine_threadsafe(world.browse(url), loop)
                return pasted.result(60) + "\n"

        source = Paste() if stdin is None else io.StringIO(stdin)
        code = await asyncio.to_thread(main, argv, stdin=source, out=out, err=err)
        self.texts += [out.getvalue(), err.getvalue()]
        return code, out.getvalue(), err.getvalue()


async def test_an_onboarding_through_the_socket_and_the_portal_leaks_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, log_lines: io.StringIO
) -> None:
    """R24's onboarding scenario: J1 with a client the vault registers, through the CLI on the
    socket (fragment 1, the commit, the second run's sign-in, the choices file), then in the
    portal (the server's row, the URL again, a Connect by paste, the review and fragment 2). The
    registered client's secret reaches the store alone; its registration access token and URI,
    every code and verifier exchanged and every token reach nothing at all; a login's ``state``
    shows only in its authorization URL."""
    for name in (onboard_cli.COMPOSE_CMD_ENV, onboard_cli.EXEC_SERVICE_ENV):
        monkeypatch.delenv(name, raising=False)
    world = Onboarding(tmp_path)
    with anyio.fail_after(120):
        j1 = ["login", "--mcp", onboard_model.SERVER_URL, "--name", "notes", "--socket", "x"]
        code, fragment, err = await world.cli(monkeypatch, [*j1, "--yes"], "")
        assert code == 0, err
        assert '"store:notes-client-secret"' in fragment
        # X1: before the commit nothing reached the authorization server, and the registration
        # carried no credentials and asked for nothing secret.
        assert world.auth.seen == []
        [registration] = world.registrations
        assert "authorization" not in registration.headers
        secret_fields = {"client_secret", "code", "code_verifier", "access_token", "refresh_token"}
        assert not secret_fields & set(json.loads(registration.content))
        world.commit(fragment)
        code, out, err = await world.cli(monkeypatch, j1)
        assert code == 0, err
        assert "Stored the refresh token for notes as notes-refresh.\n" in out
        review = ["review", "notes", "--via", "vault", "--socket", "x"]
        code, choices, err = await world.cli(monkeypatch, [*review, "--choose", "--suggest"], "")
        assert code == 0, err
        code, _, err = await world.cli(monkeypatch, [*review, "--choices", "-"], choices)
        assert code == 0, err
        # The portal: the row, the committed URL again, a Connect by paste and the review.
        answers: list[str] = []
        transport = httpx.ASGITransport(app=world.portal_app)
        client = httpx.AsyncClient(transport=transport, base_url=ORIGIN)
        page = Recording(client, answers)
        authenticator = SoftAuthenticator()
        await signed_in(page, world.portal_app, authenticator)
        await page.call("GET", "/api/servers")
        compared = await page.call(
            "POST", "/api/onboard/discover", {"url": onboard_model.SERVER_URL}
        )
        assert compared.json()["stage"] == "committed"
        started = (await page.call("POST", "/api/oauth/notes/start", {})).json()
        pasted = await world.browse(started["authorize_url"])
        data = {"credential": "notes", "flow": started["flow"], "redirect_url": pasted}
        connected = await step_up(page, authenticator, "oauth.complete", data)
        assert connected.status_code == 200, connected.text
        job = (await page.call("POST", "/api/review/notes", {})).json()["job"]
        await page.call("GET", f"/api/review/jobs/{job}")
        chosen = {"include": ["list_notes"], "allow": ["list_notes"], "approve": []}
        made = await page.call("POST", f"/api/review/jobs/{job}/diff", chosen)
        assert made.status_code == 200, made.text
        # The sweep.
        exchanges = [call for call in world.auth.calls if call.grant_type == "authorization_code"]
        assert len(exchanges) == 2  # the socket's sign-in and the portal's
        verifiers = [call.params["code_verifier"] for call in exchanges]
        states = [dict(parse_qsl(urlsplit(url).query))["state"] for url in world.authorize_urls]
        swept = [*world.texts, *answers, log_lines.getvalue()]
        held = world.store.path.read_bytes().decode("utf-8")
        for text in swept:
            for url in world.authorize_urls:
                text = text.replace(url, "<authorize-url>")
            found = ISSUED.search(text)
            assert found is None, found and found.group()
            for secret in (onboard_model.DCR_SECRET, *verifiers, *states):
                assert secret not in text, secret
        for planted in (onboard_model.REGISTRATION_TOKEN, onboard_model.REGISTRATION_URI):
            assert planted not in "".join(swept) + held
        stored, _ = world.store.get_for_oauth(
            onboard_model.SECRET_NAME, token_url=f"{onboard_model.ISSUER}/token"
        )
        assert stored.reveal() == onboard_model.DCR_SECRET
        await client.aclose()
        await world.token_client.aclose()


def test_the_egress_key_reaches_the_role_and_nothing_else(tmp_path: Path) -> None:
    """The role fetches with the key the socket printed, polls again, then meets a vault whose
    generation moved on (403) and a key file it can't use; the vault answers its lists, its
    refusals and health. Only the socket's answer holds a key."""
    old, new = KEYS.egress_key(1), KEYS.egress_key(2)
    buffer = io.StringIO()
    logs.set_stream(buffer)
    answers: list[str] = []
    try:
        (tmp_path / "admin").mkdir(mode=0o700)
        (tmp_path / "vault").mkdir(mode=0o700)
        rig = AdminRig(tmp_path / "admin")
        store = SecretStore(tmp_path / "vault", KEYS)
        store.load()
        first = VaultApp(rig.policy, store, KEYS, environ={})
        bumped = VaultApp(
            rig.policy.model_copy(update={"egress_key_generation": 2}), store, KEYS, environ={}
        )
        key_file = tmp_path / "egress.key"

        async def run(base: str, moved_on: str) -> str:
            shown = await rig.call("GET", "/egress-key")
            key_file.write_bytes(shown.json()["key"].encode() + b"\n")
            role = Allowlist(
                base, KeySource.from_environ({"ZOEYMCP_EGRESS_KEY_FILE": str(key_file)})
            )
            assert await role.fetch_once()
            # The bumped vault refuses it; the file read again holds the same key.
            source = KeySource(file=key_file)
            later = Allowlist(moved_on, source, wait=0)
            assert not await later.fetch_once()
            key_file.write_bytes(old.encode() + b"!\n")
            assert source.reload() is False
            for app, value in ((first, old), (bumped, old), (first, new), (bumped, new)):
                transport = httpx.ASGITransport(app=app, client=(AGENT, 40000))
                async with httpx.AsyncClient(transport=transport, base_url="http://vault") as c:
                    for path in (
                        "/_zoeymcp/egress/v1/allowlists",
                        "/_zoeymcp/egress/v1/allowlists?wait=x",
                        "/_zoeymcp/gateway/v1/view",
                        "/music/v1/me",
                    ):
                        got = await c.get(path, headers={EGRESS_HEADER: value})
                        answers.append(got.text + repr(got.headers.multi_items()))
            health = await rig.call("GET", "/health")
            answers.append(health.text)
            return shown.text

        with serve(first) as base, serve(bumped) as moved_on:
            shown = asyncio.run(run(base, moved_on))
        asyncio.run(first.aclose())
        asyncio.run(bumped.aclose())
        asyncio.run(rig.token_client.aclose())
    finally:
        logs.set_stream(None)
    text = buffer.getvalue()
    for event in ("egress_allowlist_served", "egress_allowlist_applied", "egress_allowlist_failed"):
        assert f'"event":"{event}"' in text, event
    assert '"event":"egress_key_unreadable"' in text
    assert '"reason":"egress key refused"' in text
    # The exception carries the running generation's key, and nothing else carries either.
    assert old in shown
    for key in (old, new, old[5:], new[5:]):
        assert key not in text, key
        assert [answer for answer in answers if key in answer] == []


# --- a bridge's token and its child's stderr (M7 design C.2, C.3, M.4, step 18c2) ----------------

BRIDGE_TOKEN_BYTES = b"leak-bridge-token-sentinel-00001"
SECRET_ENV_VALUE = "leak-secret-env-sentinel-0001"
ENV_VALUE = "leak-env-sentinel-0001"


async def test_a_bridge_token_reaches_the_store_and_its_bridge_and_nothing_else(
    tmp_path: Path, log_lines: io.StringIO
) -> None:
    rig = AdminRig(tmp_path)
    policy = bridges_policy({"fetch": "unix:/run/zoeymcp-bridge-fetch/mcp.sock"})
    rig.set_policy(policy)
    rig.admin = AdminApp(
        rig.store,
        ADMIN_KEYS,
        lambda: rig.policy,
        rig.setup,
        rig.tokens,
        random=lambda size: BRIDGE_TOKEN_BYTES[:size],
    )
    token = base64.urlsafe_b64encode(BRIDGE_TOKEN_BYTES).rstrip(b"=").decode()
    made = await rig.call("PUT", "/secrets/fetch-token", {"generate": True})
    digest = made.json()["sha256"]
    answers = [
        (await rig.call("GET", "/secrets")).text,
        (await rig.call("GET", "/health")).text,
    ]
    await rig.token_client.aclose()
    # The bridge, holding only the hash, as it would be started with it.
    settings = Settings(
        "legacy", Spec(("server",), {}, "/"), BridgeTokenHash(digest), str(tmp_path / "ready")
    )
    transport = httpx.ASGITransport(app=Bridge(settings))
    initialize = b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
    async with httpx.AsyncClient(transport=transport, base_url="http://bridge.invalid") as bridge:
        for headers in (
            {"authorization": f"Bearer {token}"},
            {"authorization": f"Bearer {token}x"},
            {"authorization": f"Bearer {token}", "origin": "https://elsewhere.example"},
            {"authorization": f"Bearer {digest}"},
        ):
            headers["content-type"] = "application/json"
            got = await bridge.post("/mcp", headers=headers, content=initialize)
            answers.append(got.text + repr(got.headers.multi_items()))
    text = log_lines.getvalue()
    assert '"event":"bridge_refused"' in text
    assert '"event":"secret_set"' in text
    for value in (token, digest, digest.removeprefix("sha256:")):
        assert value not in text, value
        assert [answer for answer in answers if value in answer] == []
    assert token not in made.text
    binding = {"origins": ["unix:/run/zoeymcp-bridge-fetch/mcp.sock"]}
    assert rig.store.get_for_binding("fetch-token", binding).reveal() == token


async def test_a_childs_stderr_shows_no_env_value_by_default(log_lines: io.StringIO) -> None:
    """The child's stderr through the bridge's own reader, in the default mode: counted, never
    shown. ``--stderr text`` is refused beside a ``--secret-env`` (TI-13)."""
    reader = asyncio.StreamReader()
    reader.feed_data(f"API_KEY={SECRET_ENV_VALUE}\nBASE={ENV_VALUE}\n".encode())
    reader.feed_data(b"x" * 5000 + ENV_VALUE.encode() + b"\n" + SECRET_ENV_VALUE.encode())
    reader.feed_eof()
    process = SimpleNamespace(pid=4242, stdin=None, stdout=None, stderr=reader, returncode=0)
    environment = {"API_KEY": SECRET_ENV_VALUE, "BASE": ENV_VALUE}
    child = Child(
        cast(Any, process),
        asyncio.Event(),
        Spec(("server",), environment, "/"),
        "legacy",
        "session",
        lambda: 0.0,
    )
    await child._read_stderr()
    child._finish()
    with pytest.raises(StartupError, match="logs stderr as counts only") as refused:
        check_options(
            Options(
                listen="127.0.0.1:9000",
                era="legacy",
                command=("server",),
                secret_env=("API_KEY",),
                stderr="text",
            )
        )
    text = log_lines.getvalue()
    assert '"event":"bridge_stderr","pid":4242,"lines":4,' in text
    assert '"event":"bridge_child_exited"' in text
    for value in (SECRET_ENV_VALUE, ENV_VALUE):
        assert value not in text
        assert value not in str(refused.value)
        assert value not in repr(child.spec)


# --- a standard-tier bridge's configuration (M7 design C.10, TI-B7, step 18d) -------------------

BRIDGE_ENV_SECRET = "leak-bridge-env-secret-sentinel-01"
BRIDGE_ARGS_SENTINEL = "leak-bridge-args-sentinel-01"


class Launched:
    """The launcher's children as a fake ``spawn`` records them, and its directory checks
    answered by a ``stat`` that gives each bridge's tmpfs the uid in ``uids``."""

    def __init__(self, uids: dict[str, int]) -> None:
        self.uids = uids
        self.children: list[tuple[str, list[str], dict[str, str]]] = []

    def spawn(
        self, name: str, argv: Callable[[int], list[str]], uid: int, environ: Mapping[str, str]
    ) -> launcher.Child:
        fd = 4 + len(self.children)
        self.children.append((name, argv(fd), dict(environ)))
        return launcher.Child(name, 100 + fd, fd)

    def stat(self, path: str) -> os.stat_result:
        uid = self.uids[path.removeprefix("/run/zoeymcp-bridge-")]
        return os.stat_result((stat.S_IFDIR | 0o750, 1, 1, 1, uid, 10001, 0, 0, 0, 0))


def test_a_bridges_env_secret_reaches_its_bridge_alone(log_lines: io.StringIO) -> None:
    """An ``ENV_*`` secret reaches its own bridge, under its plain name, and the vault, which gets
    the whole environment as it always has; never the gateway, another bridge, a command line
    (readable by every process in the container) or a log line."""
    environ = {
        "PATH": "/usr/bin",
        "ZOEYMCP_MASTER_KEY": "leak-master-key",
        "ZOEYMCP_BRIDGE_FETCH_ARGS": json.dumps(
            ["--era", "legacy", "--secret-env", "API_KEY", "--", "fetch-server"]
        ),
        "ZOEYMCP_BRIDGE_FETCH_ENV_API_KEY": BRIDGE_ENV_SECRET,
        "ZOEYMCP_BRIDGE_NOTES_ARGS": json.dumps(["--era", "modern", "--", "notes-server"]),
    }
    launched = Launched({"fetch": 10100, "notes": 10101})
    options = launcher.Options(bridges=("fetch", "notes"))
    launcher.start(options, environ, spawn=launched.spawn, stat_path=launched.stat)
    holders = []
    for name, argv, child_environ in launched.children:
        assert BRIDGE_ENV_SECRET not in " ".join(argv)
        if BRIDGE_ENV_SECRET in child_environ.values():
            holders.append(name)
    assert holders == ["vault", "bridge:fetch"]
    assert launched.children[2][2]["API_KEY"] == BRIDGE_ENV_SECRET
    assert "leak-master-key" not in launched.children[2][2].values()
    assert BRIDGE_ENV_SECRET not in log_lines.getvalue()


def test_no_args_value_reaches_a_refused_bridges_line(log_lines: io.StringIO) -> None:
    """``launcher_bridge_refused`` names a variable, a position or the directory, never what
    ARGS, the token hash or an ``ENV_*`` value hold (TI-B7): a sentinel in every refused shape."""
    sentinel = BRIDGE_ARGS_SENTINEL
    environ = {
        # Not JSON, holding the sentinel.
        "ZOEYMCP_BRIDGE_A_ARGS": f'["--era", "{sentinel}"',
        # Each launcher option, alone and with its value, and --egress-proxy.
        "ZOEYMCP_BRIDGE_B_ARGS": json.dumps(
            [
                f"--listen=unix:/{sentinel}",
                "--peer-uid",
                sentinel,
                f"--work-dir={sentinel}",
                "--control-fd",
                sentinel,
                f"--egress-proxy=http://{sentinel}:3128",
                sentinel,
            ]
        ),
        "ZOEYMCP_BRIDGE_B_TOKEN_SHA256": sentinel,
        "ZOEYMCP_BRIDGE_B_ENV_ZOEYMCP_TOKEN": sentinel,
        "ZOEYMCP_BRIDGE_B_ENV_": sentinel,
        # Well-formed, refused for its directory alone.
        "ZOEYMCP_BRIDGE_C_ARGS": json.dumps(["--era", sentinel, "--", sentinel, sentinel]),
        "ZOEYMCP_BRIDGE_C_TOKEN_SHA256": sentinel,
        "ZOEYMCP_BRIDGE_C_ENV_KEY": sentinel,
    }
    launched = Launched({"a": 10100, "b": 10101, "c": 0})
    options = launcher.Options(bridges=("a", "b", "c", f"{sentinel}!"))
    launcher.start(options, environ, spawn=launched.spawn, stat_path=launched.stat)
    assert [name for name, _, _ in launched.children] == ["vault", "gateway"]
    text = log_lines.getvalue()
    assert text.count('"event":"launcher_bridge_refused"') == 4
    assert sentinel not in text
