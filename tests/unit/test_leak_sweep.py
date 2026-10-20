"""Nothing secret leaves the vault (invariant I7; design G.4, R56, R61).

One run through the OAuth effect scenarios: logins from the CLI and over the admin app, seed
promotion, rotation, the upstream 401 path, a revoked grant whose token endpoint echoes the
refresh token in ``error_description``, bad pastes, a provider error, a reused code, and a
client_credentials test fetch with a rejected client, then the listings and health. Every log
line, admin answer, CLI output and proxied response is collected, and none may hold a token,
code, verifier, ``state``, client secret or ``error_description`` text from the fakes.

Two things are shown by design and are taken out before the sweep: the authorization URL (it
holds ``state`` and the PKCE challenge, useless without the verifier the vault keeps), and the
``error_description`` of a provider's redirect, which goes back to the operator's CLI only.

The gateway's view of the policy gets its own sweep: built from a policy with every vault-side
value filled in, it may hold none of them (M3 design D.1, invariant G1).
"""

from __future__ import annotations

import asyncio
import io
import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit

import httpx
import pytest

from tests.fakes.oauth_server import (
    FakeAuthServer,
    FakeResourceServer,
    google_style,
    spotify_style,
)
from tests.unit.report_model import DIGEST, PIN, asked_line
from zoeymcp.cli.main import main
from zoeymcp.common import ledgerreport
from zoeymcp.common.ledgerformat import GENESIS, line_hash
from zoeymcp.common.policy import Policy
from zoeymcp.common.policy.schema import hash_token
from zoeymcp.common.policy.view import build_view, dump_view, parse_view
from zoeymcp.vault import logs
from zoeymcp.vault.admin import AdminApp, SetupCodes
from zoeymcp.vault.app import VaultApp
from zoeymcp.vault.oauth.login import LoginService
from zoeymcp.vault.oauth.tokens import TokenManager
from zoeymcp.vault.reportstore import ReportStore
from zoeymcp.vault.request import oauth_client_variants
from zoeymcp.vault.server import ListenerTag
from zoeymcp.vault.store import SecretStore

from .test_oauth_tokens import KEYS, FakeClock

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
ISSUED = re.compile(r"fake-(?:spotify|google|machine)-(?:at|rt|code)-\d+")
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
    }
    routes = [
        route("music", "https://api.spotify.example/v1"),
        route("calendar", "https://api.google.example/v1"),
        route("machine", "https://api.machine.example/v1"),
    ]
    return Policy.model_validate({**BASE, "routes": routes, "credentials": credentials})


def by_host(apps: dict[str, Any]) -> Any:
    """One ASGI app that hands each request to the app for its host."""

    async def app(scope: Any, receive: Any, send: Any) -> None:
        host = dict(scope["headers"])[b"host"].decode().split(":")[0]
        await apps[host](scope, receive, send)

    return app


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
        self.servers = {
            "accounts.spotify.example": self.spotify,
            "accounts.google.example": self.google,
            "auth.machine.example": self.machine,
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
        self.admin_app = AdminApp(
            self.store,
            KEYS,
            lambda: self.policy,
            SetupCodes(tmp_path, KEYS.portal_key),
            self.tokens,
            login,
            connectors=self.vault.connectors,
            env_names=lambda: self.vault.env_names,
        )
        self.monkeypatch = monkeypatch
        # Everything that leaves the vault, by where it went.
        self.admin_answers: list[str] = []
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

    async def browse(self, url: str) -> str:
        """Play the browser: approve, and return the address the browser is sent to."""
        server = self.servers[urlsplit(url).hostname or ""]
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=server.app())) as browser:
            response = await browser.get(url)
        assert response.status_code == 302
        location: str = response.headers["location"]
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
    for name, value in (("google-secret", GOOGLE_SECRET), ("machine-secret", MACHINE_SECRET)):
        assert (await world.admin("PUT", f"/secrets/{name}", {"value": value})).status_code == 200

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
    code, _, err = await world.cli(argv, with_query(pasted, state="another-login") + "\n")
    assert (code, err) == (1, "zoeymcp login: the address is for a different login\n")

    # music: the provider refuses, with a description for the operator.
    started = (await world.admin("POST", "/oauth/music/login", {})).json()
    state = dict(parse_qsl(urlsplit(started["authorize_url"]).query))["state"]
    refused = f"{REDIRECT}?" + urlencode(
        {"error": "access_denied", "error_description": SENTINEL, "state": state}
    )
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
    # The token endpoint echoes the used code in error_description.
    world.spotify.error_shape = "echo"
    again = await world.admin("POST", "/oauth/music/complete", body)
    world.spotify.error_shape = "rfc"
    assert again.status_code == 400
    assert again.json()["reason"] == "exchange_failed:oauth_reconsent_needed"
    # The code itself is the sentinel: it matches ISSUED wherever it shows up.
    assert world.spotify.calls[-1].params["code"] == dict(parse_qsl(urlsplit(used).query))["code"]

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

    # Listings.
    await world.admin("GET", "/oauth")
    await world.admin("GET", "/secrets")
    await world.cli(["oauth", "status"])
    await world.cli(["secret", "list"])
    await world.admin("GET", "/health")
    assert (await world.cli(["health"]))[1]
    assert (await world.cli(["health", "--json"]))[1]

    # --- the sweep -----------------------------------------------------------------------------
    log_text = log_lines.getvalue()
    assert log_text
    secrets = world.secrets()
    # Every kind of value was really in play: five code exchanges (one with a used code), and
    # codes and refresh tokens from all three kinds of grant.
    assert len(set(world.verifiers())) == 5
    assert len(set(world.states())) == len(world.authorize_urls) == 7
    kinds = {value.rsplit("-", 2)[1] for value in world.issued()}
    assert kinds == {"code", "rt"}
    assert any(c.status == 400 for c in world.google.calls if c.grant_type == "refresh_token")
    outputs = {
        "admin": world.admin_answers,
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
    # The description reached the operator, and only through the failed completion.
    assert sum(SENTINEL in text for text in world.admin_answers) == 1
    assert world.authorize_urls
    for url in world.authorize_urls:
        query = dict(parse_qsl(urlsplit(url).query))
        assert query["code_challenge_method"] == "S256"
        assert "client_secret" not in query

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
    "bridge url": "leak-bridge.example",
    "bridge egress": "leak-egress.example",
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
    ]
    gateway = {
        "clients": {
            "literal": {"token": LITERAL_TOKEN, "servers": ["srv-remote"]},
            "hashed": {
                "token_sha256": "sha256:" + "3" * 64,
                "servers": ["srv-remote", "srv-bridge", "srv-toolkit"],
            },
        },
        "servers": {
            "srv-remote": {"kind": "remote", "route": "leak-route-mcp", "path": "/mcp"},
            "srv-bridge": {
                "kind": "bridge",
                "url": "http://leak-bridge.example:9000/mcp",
                "egress": ["leak-egress.example:443"],
            },
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
    for marker in ("store:", "env:", "https://", "http://", "placeholder", "secret"):
        assert marker not in served, marker
    for where, (value, _why) in GATEWAY_NEEDS.items():
        assert value in served, where
    # A slot names its connector's kind, never the connector.
    slot = view.gateway.servers["srv-toolkit"].model_dump()["slots"]["mail"]
    assert (slot["prefix"], slot["connector"]) == ("/mail", "smtp")
    # What the gateway does get: the token's hash and the vault path.
    assert hash_token(LITERAL_TOKEN) in served
    assert view.gateway.servers["srv-remote"].model_dump()["vault_path"] == "/mcp-a/mcp"
    assert parse_view(served.encode()) == view


# --- the report path (M5 design J.2, J.4, M.4) ---------------------------------------------------


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
