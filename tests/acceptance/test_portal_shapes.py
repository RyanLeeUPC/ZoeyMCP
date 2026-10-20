"""The portal's journey against a real ``zoeymcp vault`` process (M5 design O.5).

The first visit (a setup code issued with ``zoeymcp setup-code``, redeemed, a passkey enrolled,
the login with it), the session list and logout, and a restart, which ends every session while
the passkey still signs in; the S5 shape connected through the portal's callback; and the whole
journey behind a gateway on either link (the in-process rig, ``GatewayDeployment``, with its
reporter): secrets, S5 and S6 connected by paste, health before and after, S10 and S15 through
the gateway, and the Ledger page with a send's journal row and an orphan.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

import httpx
import pytest

from tests.fakes.agent import ACCEPT, DECLINE, Script, agent
from tests.fakes.authenticator import SoftAuthenticator
from tests.fakes.browser import SESSION_KEY, Browser, Page
from tests.fakes.mcp_server import McpFake
from tests.fakes.oauth_server import google_style, spotify_style
from tests.fakes.smtp_server import PASSWORD, SmtpFake, serve_smtp
from tests.gateway.rig import Running, pin_of_fake, token_for
from tests.portal.flows import connect_by_callback, enrol, login, redeem, step_up
from zoeymcp.common.policy.schema import hash_token
from zoeymcp.common.yamlload import load_mapping
from zoeymcp.vault.keys import generate_master_key

from .conftest import serve_tls
from .gateway import GatewayDeployment
from .procs import PASSED, Process, free_port, start, wait_port
from .test_mcp_shapes import LINKS, own_uid, text
from .test_oauth_shapes import browse
from .tls import ProviderCA
from .toolkits import AGENT, _merge

STARTUP_TIMEOUT = 30.0
PROFILES = Path(__file__).resolve().parents[2] / "profiles"


@contextmanager
def portal(tmp_path: Path) -> Iterator[tuple[str, Path, dict[str, str], Process]]:
    """A vault with an ``admin`` block and no admin socket, as on a host without one."""
    state = tmp_path / "state"
    if not state.exists():
        state.mkdir(mode=0o700)
    port_file = tmp_path / "ports.json"
    if port_file.exists():
        ports = json.loads(port_file.read_text(encoding="utf-8"))
    else:
        ports = {"portal": free_port(), "proxy": free_port()}
        port_file.write_text(json.dumps(ports), encoding="utf-8")
    origin = f"http://localhost:{ports['portal']}"
    policy = {
        "version": 1,
        "mode": "declarative",
        "admin": {"listen": f"127.0.0.1:{ports['portal']}", "origins": [origin]},
    }
    config = tmp_path / "policy.json"
    config.write_text(json.dumps(policy), encoding="utf-8")
    key_file = tmp_path / "master.key"
    if not key_file.exists():
        key_file.write_text(generate_master_key(), encoding="utf-8")
    env = {"ZOEYMCP_MASTER_KEY": key_file.read_text(encoding="utf-8")}
    argv = [
        "vault",
        "--config",
        str(config),
        "--listen",
        f"127.0.0.1:{ports['proxy']}",
        "--state",
        str(state),
        "--admin-socket",
        "none",
    ]
    log = tmp_path / f"vault-{len(list(tmp_path.glob('vault-*.log')))}.log"
    vault = start(argv, env=env, log=log)
    try:
        wait_port(ports["portal"], vault, STARTUP_TIMEOUT)
        yield origin, state, env, vault
    finally:
        vault.stop()


def setup_code(state: Path, env: dict[str, str]) -> str:
    """``zoeymcp setup-code --state DIR``, the offline form, in its own process."""
    environment = {name: os.environ[name] for name in PASSED if name in os.environ}
    environment.update(env)
    done = subprocess.run(  # noqa: S603 - our own interpreter and arguments
        [sys.executable, "-m", "zoeymcp.cli.main", "setup-code", "--state", str(state)],
        env=environment,
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )
    return done.stdout.strip()


def keep(page: Page, answer: dict[str, object]) -> None:
    page.storage[SESSION_KEY] = str(answer["token"])


def log_events(vault: Process, event: str) -> list[dict[str, object]]:
    lines = [line for line in vault.output().splitlines() if line.startswith("{")]
    return [entry for entry in map(json.loads, lines) if entry.get("event") == event]


def sign_in(page: Page, authenticator: SoftAuthenticator) -> None:
    begun = page.fetch("POST", "/api/login/begin", json={}).json()
    assertion = authenticator.get(begun["options"], page.origin)
    body = {"ceremony": begun["ceremony"], "credential": assertion.body()}
    finished = page.fetch("POST", "/api/login/finish", json=body)
    assert finished.status_code == 200, finished.text
    keep(page, finished.json())


def test_the_first_visit_and_a_restart(tmp_path: Path) -> None:
    authenticator = SoftAuthenticator()
    with Browser() as browser, portal(tmp_path) as (origin, state, env, vault):
        assert browser.navigate(origin + "/").status_code == 200
        assert [e["hint"] for e in log_events(vault, "setup_pending")] == [
            "run zoeymcp setup-code in the vault's container"
        ]
        page = browser.page(origin)
        code = setup_code(state, env)
        redeemed = page.fetch("POST", "/api/setup/redeem", json={"code": code})
        assert redeemed.status_code == 200, redeemed.text
        keep(page, redeemed.json())
        begun = page.fetch("POST", "/api/passkeys/enrol/begin", json={"name": "laptop"}).json()
        attestation = authenticator.create(begun["options"], origin)
        body = {"ceremony": begun["ceremony"], "credential": attestation.body()}
        enrolled = page.fetch("POST", "/api/passkeys/enrol/finish", json=body)
        assert enrolled.status_code == 200, enrolled.text
        fingerprint = enrolled.json()["passkey"]["fingerprint"]
        sign_in(page, authenticator)
        assert page.fetch("GET", "/api/session").json()["credential"] == fingerprint
        assert [s["this"] for s in page.fetch("GET", "/api/sessions").json()["sessions"]] == [True]
        deadline = time.monotonic() + 10
        while not log_events(vault, "passkey_enrolled"):
            assert time.monotonic() < deadline
            time.sleep(0.05)
        assert code not in vault.output()
        old_token = page.storage[SESSION_KEY]
    # A restart ends every session; the passkey file keeps the passkey.
    with Browser() as browser, portal(tmp_path) as (origin, state, env, vault):
        page = browser.page(origin)
        page.storage[SESSION_KEY] = old_token
        assert page.fetch("GET", "/api/session").status_code == 401
        assert log_events(vault, "setup_pending") == []  # a passkey can sign in
        sign_in(page, authenticator)
        assert page.fetch("GET", "/api/session").json()["credential"] == fingerprint
        out = page.fetch("POST", "/api/logout", json={})
        assert out.headers["clear-site-data"] == '"storage"'
        assert page.fetch("GET", "/api/session").status_code == 401


def test_an_s5_connect_through_the_callback(tmp_path: Path, ca: ProviderCA) -> None:
    """The S5 shape from the shipped Google profile, its redirect_uri set to the portal's
    callback address (a Web-application client, A.4): the client secret entered in the portal
    with a step-up, then a connect through the callback against the fake provider over TLS, the
    code held until the passkey confirms, and exchanged once with the posted secret (M5 step
    14b)."""
    fragment = load_mapping((PROFILES / "google-oauth.yaml").read_text(encoding="utf-8"))
    auth = google_style(time.time)
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    port, proxy = free_port(), free_port()
    origin = f"http://localhost:{port}"
    address = f"{origin}/oauth/callback/google-calendar"
    auth.registered_redirect = address
    env = {"ZOEYMCP_MASTER_KEY": generate_master_key()}
    with serve_tls(auth.app(), ca) as auth_url:
        cred = fragment["credentials"]["google-calendar"]
        cred.update(
            token_url=f"{auth_url}/token",
            authorize_url=f"{auth_url}/authorize",
            redirect_uri=address,
        )
        document = {
            "version": 1,
            "mode": "declarative",
            "admin": {"listen": f"127.0.0.1:{port}", "origins": [origin]},
            **fragment,
        }
        config = tmp_path / "policy.json"
        config.write_text(json.dumps(document), encoding="utf-8")
        argv = ["vault", "--config", str(config), "--listen", f"127.0.0.1:{proxy}"]
        argv += ["--state", str(state), "--admin-socket", "none"]
        vault = start(argv, env=env, log=tmp_path / "vault.log", ca=ca.ca_file)
        provider = httpx.Client(verify=ca.client_context(), trust_env=False)
        try:
            wait_port(port, vault, STARTUP_TIMEOUT)
            passkey = SoftAuthenticator()
            with Browser(remote={auth_url: provider}) as browser:
                page = browser.page(origin)
                assert redeem(page, setup_code(state, env)).status_code == 200
                assert enrol(page, passkey).status_code == 200
                assert login(page, passkey).status_code == 200
                secret = {"name": "google-client-secret", "value": "fake-google-client-secret"}
                assert step_up(page, passkey, "secret.put", secret).status_code == 200
                begun, done = connect_by_callback(page, passkey, "google-calendar")
                assert done.status_code == 200, done.text
                assert (done.json()["slot"], done.json()["persisted"]) == ("google-refresh", True)
            [exchange] = auth.calls
            assert exchange.params["client_secret"] == "fake-google-client-secret"
            assert exchange.params["redirect_uri"] == address
        finally:
            provider.close()
            vault.stop()
    output = vault.output()
    query = dict(parse_qsl(urlsplit(begun["authorize_url"]).query))
    for value in (query["state"], "fake-google-code-", "fake-google-rt-", begun["flow"]):
        assert value not in output


# --- the whole journey (O.5), over both links -----------------------------------------------------

NOTES_KEY = "journey-notes-key-7f3e"
GOOGLE_SECRET = "fake-google-client-secret"
SUBJECT = "Figures for the journey"
ORPHAN_KEY = "journey-orphan-0001-abcdef"
REF = re.compile(r"Approval request ([0-9a-f]{16})")
ISSUED = re.compile(r"fake-(?:google|spotify)-(?:rt|at|code)-\d+")
# What the journey connects and enters, by health's credential and connector names.
UNSET = {"notes-key", "google-calendar", "spotify", "mail-out"}


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def journey_fragment(smtp_port: int, google_url: str, spotify_url: str) -> dict[str, Any]:
    """S5, S6 and S15 from their shipped profiles, beside the rig's S10: the providers' endpoints
    and the mail server's address swapped for the fakes, the mail client merged into the rig's
    own (its token and sources are the rig's)."""
    google, spotify, smtp, mail = (
        load_mapping((PROFILES / name).read_text(encoding="utf-8"))
        for name in ("google-oauth.yaml", "spotify-pkce.yaml", "smtp-implicit-tls.yaml",
                     "toolkit-mail.yaml")
    )  # fmt: skip
    for fragment, url in ((google, google_url), (spotify, spotify_url)):
        for credential in fragment["credentials"].values():
            credential.update(token_url=f"{url}/token", authorize_url=f"{url}/authorize")
    smtp["connectors"]["mail-out"].update(host="localhost", port=smtp_port)
    client = mail["gateway"]["clients"][AGENT]
    del client["token_sha256"], client["sources"]
    merged: dict[str, Any] = {}
    for fragment in (google, spotify, smtp, mail):
        merged = _merge(merged, fragment)
    return merged


class Portal:
    """The operator's page, keeping every answer, each checked for C.3's headers."""

    def __init__(self, page: Page) -> None:
        self.page = page
        self.answers: list[httpx.Response] = []

    def keep(self, response: httpx.Response) -> httpx.Response:
        assert_c3_headers(response)
        self.answers.append(response)
        return response

    def fetch(self, method: str, path: str, body: Any = None) -> httpx.Response:
        return self.keep(self.page.fetch(method, path, json=body))

    def get(self, path: str) -> Any:
        answer = self.fetch("GET", path)
        assert answer.status_code == 200, answer.text
        return answer.json()

    def act(self, passkey: SoftAuthenticator, kind: str, data: dict[str, Any]) -> Any:
        """An action prepared, its passkey prompt answered and confirmed, as the page does."""
        held = self.fetch("POST", "/api/actions", {"kind": kind, "data": data})
        assert held.status_code == 200, held.text
        assertion = passkey.get(held.json()["options"], self.page.origin).body()
        path = f"/api/actions/{held.json()['action']}/confirm"
        done = self.fetch("POST", path, {"credential": assertion})
        assert done.status_code == 200, done.text
        return done.json()

    def connect_by_paste(self, passkey: SoftAuthenticator, credential: str, ca: ProviderCA) -> Any:
        """Connect (H.1): start, approve in the browser's new tab, paste, confirm."""
        started = self.fetch("POST", f"/api/oauth/{credential}/start", {})
        assert started.status_code == 200, started.text
        pasted = browse(started.json()["authorize_url"], ca)
        data = {"credential": credential, "flow": started.json()["flow"], "redirect_url": pasted}
        return self.act(passkey, "oauth.complete", data)


def assert_c3_headers(response: httpx.Response) -> None:
    """C.3's headers, as written there, on an answer of the real API (design.md §8.2)."""
    assert response.headers["content-security-policy"].startswith("default-src 'self'; ")
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    expected = {
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "cache-control": "no-store",
        "cross-origin-opener-policy": "same-origin",
        "cross-origin-resource-policy": "same-origin",
        "x-frame-options": "DENY",
        "x-zoeymcp-vault": "portal",
    }
    assert {name: response.headers.get(name) for name in expected} == expected
    assert not [name for name in response.headers if name.startswith("access-control-")]


def unhealthy(health: dict[str, Any]) -> dict[str, str]:
    """The credentials and connectors health finds an error with, by name."""
    return {
        item["name"]: item["level"]
        for section in ("credentials", "connectors")
        for item in health.get(section, [])
        if item["level"] == "error"
    }


def as_the_gateway(gateway: GatewayDeployment, running: Running) -> httpx.Response:
    """An SMTP send made straight to the vault's mail route as the gateway, outside any call, so
    no ledger record explains it: the gateway key over TCP, or the link socket's peer check."""
    request = {
        "expect_from": "Agent <agent@mail.example>",
        "expect_to": ["partner@mail.example"],
        "subject": SUBJECT,
        "body": "Sent with no call behind it.",
    }
    headers = {"idempotency-key": ORPHAN_KEY, "content-type": "application/json"}
    link = running.app.pool.link
    if link.uds is not None:
        transport = httpx.HTTPTransport(uds=link.uds)
        with httpx.Client(transport=transport, base_url="http://vault", timeout=60) as client:
            return client.post("/mail/send", headers=headers, content=json.dumps(request))
    headers["x-zoeymcp-gateway"] = gateway.vault.keys.gateway_key(1)
    url = f"{link.base_url}/mail/send"
    return httpx.post(url, headers=headers, content=json.dumps(request), timeout=60)


def both_closed(page: dict[str, Any]) -> bool:
    """The copy holds both calls, each with its outcome."""
    rows = page["rows"]
    return len(rows) == 2 and all(row["outcome"] is not None for row in rows)


def wait_for(read: Callable[[], Any], until: Callable[[Any], bool], timeout: float = 30) -> Any:
    deadline = time.monotonic() + timeout
    while True:
        value = read()
        if until(value):
            return value
        assert time.monotonic() < deadline, value
        time.sleep(0.1)


@pytest.mark.anyio
@pytest.mark.parametrize("link", LINKS)
async def test_the_operators_journey(tmp_path: Path, ca: ProviderCA, link: str) -> None:
    """The operator's journey through the portal, with the gateway on either link: setup, the
    enrolment and the login; health before; a static key (S10) and the mail password (S15)
    entered with a step-up and used; S5 and S6 connected by paste; health after; an approved
    and a declined send through the gateway, reported to the vault's copy by the gateway's
    reporter, and the Ledger page with the send's journal row and a send made as the gateway
    with no ledger record, an orphan; the policy, the sessions and logout. Every answer has
    C.3's headers, and nothing secret reaches a log, an answer or the CLI."""
    fake = McpFake(key=NOTES_KEY, key_header="x-api-key")
    smtp = SmtpFake(ca)
    google, spotify = google_style(time.time), spotify_style(time.time)
    passkey = SoftAuthenticator()
    with (
        serve_tls(fake.app(), ca, lifespan=True) as upstream,
        serve_tls(google.app(), ca) as google_url,
        serve_tls(spotify.app(), ca) as spotify_url,
        serve_smtp(smtp, tmp_path) as (_, smtp_port),
    ):
        gateway = GatewayDeployment(
            tmp_path,
            upstream,
            ca,
            tools={"echo": "allow"},
            pins={"echo": pin_of_fake(fake, "echo")},
            clients=(AGENT,),
            link=link,  # type: ignore[arg-type]
            link_uid=own_uid() if link == "unix" else None,
            portal=True,
            reporter=True,
            toolkits=True,
            extra=journey_fragment(smtp_port, google_url, spotify_url),
        )
        vault = gateway.vault
        with gateway.running() as running, Browser() as browser:
            portal = Portal(browser.page(vault.portal_origin))
            # The first visit: a code issued as the socket issues one, a passkey, the login.
            code, _ = vault.call(lambda: vault.setup.issue())
            assert portal.keep(redeem(portal.page, code.reveal())).status_code == 200
            assert portal.keep(enrol(portal.page, passkey)).status_code == 200
            assert portal.keep(login(portal.page, passkey)).status_code == 200
            before = unhealthy(portal.get("/api/health"))
            # Secrets, write-only, each with a step-up (G).
            for name, value in (
                ("notes-key", NOTES_KEY),
                ("mail-pass", PASSWORD),
                ("google-client-secret", GOOGLE_SECRET),
            ):
                assert portal.act(passkey, "secret.put", {"name": name, "value": value})
            # S5 and S6, connected by paste (H.1).
            for credential, slot in (
                ("google-calendar", "google-refresh"),
                ("spotify", "spotify-refresh"),
            ):
                done = portal.connect_by_paste(passkey, credential, ca)
                assert (done["slot"], done["persisted"]) == (slot, True)
            after = unhealthy(portal.get("/api/health"))
            listed = portal.get("/api/oauth")["credentials"]
            assert {c["credential"]: c["state"] for c in listed} == {
                "google-calendar": "ok",
                "spotify": "ok",
            }
            # The static key, used by its route through the gateway (S10).
            headers = {"authorization": f"Bearer {token_for(AGENT)}"}
            async with agent(f"{running.url}/s/notes/mcp", headers=headers) as client:
                echoed = await client.call_tool("echo", {"text": "hi"})
            assert text(echoed) == "hi"
            # S15, approved: the mail toolkit sends through the connector.
            accept = Script([ACCEPT])
            async with agent(f"{running.url}/s/mail/mcp", script=accept, headers=headers) as client:
                sent = await client.call_tool("send_note", {"subject": SUBJECT, "body": "Hi."})
            assert not sent.is_error, text(sent)
            [match] = REF.findall(accept.prompts[0].message)
            # A send made as the gateway, outside any call: no ledger record will explain it.
            orphan = as_the_gateway(gateway, running)
            assert orphan.status_code == 200, orphan.text
            # S15, declined: nothing sent, and its records reach the copy after the orphan.
            async with agent(
                f"{running.url}/s/mail/mcp", script=Script([DECLINE]), headers=headers
            ) as client:
                declined = await client.call_tool("send_note", {"subject": SUBJECT, "body": "No."})
            assert text(declined).startswith("declined by operator")
            shown = wait_for(lambda: portal.get("/api/ledger"), both_closed)
            policy = portal.get("/api/policy")
            sessions = portal.get("/api/sessions")["sessions"]
            out = portal.fetch("POST", "/api/logout", {})
            assert out.headers["clear-site-data"] == '"storage"'
            assert portal.fetch("GET", "/api/session").status_code == 401
            code_ledger, verified, _ = gateway.cli(running, "ledger", "--verify")
    assert set(before) >= UNSET, before
    assert not UNSET & set(after), after
    assert len(smtp.messages) == 2  # the approved send and the orphan; the decline sent nothing
    # The Ledger page: newest first, the approved call with its send, and the orphan flagged.
    declined_row, sent_row = shown["rows"]
    assert sent_row["ref"] == match
    assert [send["state"] for send in sent_row["journal"]] == ["sent"]
    assert (declined_row["decision"], declined_row["journal"]) == ("decline", [])
    assert (sent_row["decision"], sent_row["outcome"]) == ("accept", "ok")
    assert [(o["key_shown"], o["flag"]) for o in shown["orphans"]] == [
        (ORPHAN_KEY, "no_ledger_record")
    ]
    assert policy["mode"] == "declarative"
    assert [s["this"] for s in sessions] == [True]
    assert code_ledger == 0, verified
    # Nothing secret reached a log line, an answer or the CLI.
    seen = gateway.seen
    seen.outputs += [answer.text for answer in portal.answers]
    everything = seen.everything()
    token = token_for(AGENT)
    secret = (NOTES_KEY, PASSWORD, GOOGLE_SECRET, token, hash_token(token), code.reveal(), SUBJECT)
    for value in (*secret, vault.keys.gateway_key(1)):
        assert value not in everything
    leaked = ISSUED.search(everything)
    assert leaked is None, leaked.group(0)
