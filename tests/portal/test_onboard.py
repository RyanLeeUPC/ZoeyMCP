"""Onboarding by URL in the portal, over the real API (M7 design K.1-K.3, D.4, D.7, D.8; J2, J3).

The onboarding service is the vault's own, on a client that reaches its fakes in process: the MCP
server of ``tests/unit/onboard_model.py`` at ``mcp.notes.example``, and a stateful
``FakeAuthServer`` at ``auth.notes.example``, which publishes its metadata, registers clients
(RFC 7591) and signs them in. Every request the client sends is recorded, so a test can show
what a step sent, or that it sent nothing.

- **J2 (DCR)**, step 11's portal half: discovery's plan with the session's callback address as
  the redirect (D.4, Q35), the row ``needs_register``; ``onboard.register`` planned with nothing
  sent, then confirmed with a passkey, which registers once and makes fragment 1; the row
  ``needs_commit``, "Show fragment 1" first, and fragment 1 again at any indent (OPS-2); the
  commit and reload, the row ``needs_connect``; the URL again (D.12's comparison) writes
  nothing from the portal (K.2); Connect through the callback with the registered client; the row
  ``needs_review``.
- **J3**, a given confidential client: its secret only through the action, stored under the
  binding fragment 1 derives, never in an answer; a given public client's fragment 1 with no
  action, nothing sent or stored.
- **Owners** (D.8, X24): another session's onboarding answers as an unknown one, and a
  session's end cancels its own.
- **A private discovery** (TI-3) only through ``onboard.discover_private``: refused on the
  route, and nothing reaches the network before the passkey.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import pytest

from tests.fakes.authenticator import SoftAuthenticator
from tests.fakes.browser import Browser, Page, asgi_client, loopback
from tests.fakes.oauth_server import FakeAuthServer
from tests.unit import onboard_model
from tests.unit.test_portal_static import reads
from zoeymcp.common.policy.merge import Merged, merge, replace_paths
from zoeymcp.common.yamlload import load_mapping
from zoeymcp.vault import netclient, server
from zoeymcp.vault.onboard import OnboardService
from zoeymcp.vault.store import SecretStore

from .flows import connect_by_callback, prepared_action, set_up, status_reason, step_up
from .rig import PortalRig, running

SERVER_URL = onboard_model.SERVER_URL
ISSUER = onboard_model.ISSUER
AUTH = "auth.notes.example"
CLIENT_ID = onboard_model.CLIENT_ID
SECRET = onboard_model.GIVEN_SECRET
REGISTER = "Register and make the YAML"


class Hosts(httpx.AsyncBaseTransport):
    """The onboarding client's network: the authorization server's fake by its host, the MCP
    server's model for every other; each request recorded."""

    def __init__(self, auth: FakeAuthServer) -> None:
        self.auth = httpx.ASGITransport(app=auth.app())
        self.mcp = httpx.MockTransport(onboard_model.handler)
        self.sent: list[tuple[str, str]] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.sent.append((request.method, str(request.url)))
        if request.url.host == AUTH:
            return await self.auth.handle_async_request(request)
        return await self.mcp.handle_async_request(request)


@dataclass
class World:
    rig: PortalRig
    auth: FakeAuthServer
    hosts: Hosts
    page: Page
    passkey: SoftAuthenticator
    browser: Browser
    provider: httpx.Client
    others: list[Page] = field(default_factory=list)

    @property
    def store(self) -> SecretStore:
        secrets = self.rig.app.secrets
        assert secrets is not None
        return secrets.store

    @property
    def callback(self) -> str:
        return f"{self.rig.origin}/oauth/callback/notes"

    def servers(self, page: Page | None = None) -> list[dict[str, Any]]:
        answer = (page or self.page).fetch("GET", "/api/servers")
        assert answer.status_code == 200, answer.text
        rows: list[dict[str, Any]] = answer.json()["servers"]
        return rows

    def commit(self, fragment: str) -> None:
        """Fragment 1 merged into the policy file as ``check --with`` merges it, then reloaded."""
        base = load_mapping(self.rig.policy_file.read_bytes().decode("utf-8"))
        merged = merge(base, load_mapping(fragment), replace=replace_paths(fragment))
        assert isinstance(merged, Merged)
        self.rig.reload(merged.data)


def onboarding_service(hosts: Hosts) -> Callable[[server.Vault], OnboardService]:
    """The vault's service, as server.build makes it, on the in-process network."""

    def make(vault: server.Vault) -> OnboardService:
        assert vault.portal is not None
        secrets = vault.portal.app.secrets
        assert secrets is not None
        return OnboardService(
            secrets.store,
            secrets.tokens,
            lambda: vault.app.policy,
            httpx.AsyncClient(transport=hosts, trust_env=False),
            source=vault.onboard.source,
            resolver=onboard_model.resolve,
        )

    return make


@pytest.fixture
def world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[World]:
    auth = FakeAuthServer(
        time.time,
        client_id=CLIENT_ID,
        issuer=ISSUER,
        iss_supported=True,
        rotate=True,
        scopes=("notes.read", "offline_access"),
        registration="open",
        prefix="fake-notes",
    )
    hosts = Hosts(auth)
    monkeypatch.setattr(
        netclient,
        "token_client",
        lambda *_: httpx.AsyncClient(transport=httpx.ASGITransport(app=auth.app())),
    )
    with running(tmp_path, onboard=onboarding_service(hosts)) as rig:
        provider = asgi_client(auth.app(), ISSUER)
        browser = Browser(address=loopback, remote={ISSUER: provider})
        rig.browsers.append(browser)
        page = browser.page(rig.origin)
        passkey = SoftAuthenticator()
        set_up(rig, page, passkey)
        try:
            yield World(rig, auth, hosts, page, passkey, browser, provider)
        finally:
            provider.close()


def discovered(world: World, page: Page | None = None, **body: Any) -> dict[str, Any]:
    answer = (page or world.page).fetch("POST", "/api/onboard/discover", json=body)
    assert answer.status_code == 200, answer.text
    plan: dict[str, Any] = answer.json()
    return plan


def summary_of(held: dict[str, Any]) -> dict[str, str]:
    return dict(held["summary"])


# --- J2: a client the vault registers (D.4; step 11's portal half) ------------------------------


def test_j2_a_client_the_vault_registers_to_connect(world: World) -> None:
    """J2 (DCR) to the review: the plan, the register action, fragment 1 again, the commit, a
    Connect through the portal's callback with the registered client, and each row's state."""
    plan = discovered(world, url=SERVER_URL)
    shown = plan["plan"]
    assert (shown["registration"], shown["client_id_shown"], shown["client_auth"]) == (
        "dcr",
        None,
        "none",
    )
    assert (shown["redirect_uri"], shown["application_type"]) == (world.callback, "native")
    assert "backstop_off" not in shown["notes"]
    assert shown["resource_name_shown"] is None
    assert "rows" not in plan
    assert ["Redirect", f"{world.callback} (native)"] in plan["rows_shown"]
    assert plan["next"] == [{"do": "register", "label": REGISTER}]
    onboarding = plan["onboarding"]
    [row] = world.servers()
    assert (row["onboarding"], row["state"], row["name_shown"]) == (
        onboarding,
        "needs_register",
        "notes",
    )
    assert row["next"][0]["do"] == "register"
    # The plan sends nothing: the passkey confirms what the summary says first.
    held = prepared_action(world.page, "onboard.register", {"onboarding": onboarding})
    assert summary_of(held) == {
        "Onboard": SERVER_URL,
        "As": "notes, notes, notes",
        "Issuer": AUTH,
        "Register a client at": AUTH,
        "Redirect address": world.callback,
        "Stored": "its client ID, as notes-client-id, until the policy names it",
    }
    assert world.auth.registrations == []
    sent = len(world.hosts.sent)
    assertion = world.passkey.get(held["options"], world.page.origin).body()
    made = world.page.fetch(
        "POST", f"/api/actions/{held['action']}/confirm", json={"credential": assertion}
    )
    assert made.status_code == 200, made.text
    registered = made.json()
    assert world.hosts.sent[sent:] == [("POST", f"{ISSUER}/register")]
    [request] = world.auth.registrations
    asked = json.loads(request.body)
    assert (asked["redirect_uris"], asked["application_type"]) == ([world.callback], "native")
    client_id = registered["client_id_shown"]
    assert client_id in world.auth.registered
    assert (registered["stage"], registered["secret_stored"], registered["secret_name"]) == (
        "registered",
        False,
        None,
    )
    fragment = registered["diff"]["yaml"]
    credential = load_mapping(fragment)["credentials"]["notes"]
    assert (credential["client_id"], credential["redirect_uri"]) == (client_id, world.callback)
    [row] = world.servers()
    assert (row["state"], row["next"][0]) == (
        "needs_commit",
        {"do": "show_fragment", "label": "Show fragment 1"},
    )
    assert row["next"][1]["do"] == "check_fragment"
    # Fragment 1 again, at the compose indent, with nothing sent (OPS-2).
    again = world.page.fetch(
        "POST", f"/api/onboard/{onboarding}/fragment", json={"indent": "compose"}
    )
    assert again.status_code == 200, again.text
    assert load_mapping(again.json()["diff"]["yaml"].replace("$$", "$")) == load_mapping(fragment)
    # Registered, the action only shows fragment 1 again, and takes no secret.
    held = prepared_action(world.page, "onboard.register", {"onboarding": onboarding})
    assert summary_of(held) == {
        "Show fragment 1 again for": "notes, notes, notes",
        "Sent or stored": "nothing",
    }
    with_secret = {"onboarding": onboarding, "client_secret": SECRET}
    refused = world.page.fetch(
        "POST", "/api/actions", json={"kind": "onboard.register", "data": with_secret}
    )
    assert status_reason(refused) == (400, "bad_body")
    assert world.hosts.sent[sent:] == [("POST", f"{ISSUER}/register")]
    # The commit: the onboarding ends, and the server's row needs a Connect.
    world.commit(fragment)
    [row] = world.servers()
    assert (row["server"], row["state"], row["credential"]) == ("notes", "needs_connect", "notes")
    assert row["next"] == [
        {"do": "connect", "label": "Connect", "command": "zoeymcp login notes", "via": "exec"}
    ]
    assert status_reason(world.page.fetch("GET", f"/api/onboard/{onboarding}")) == (
        404,
        "onboarding_unknown",
    )
    # The committed URL again is D.12's comparison, and from the portal it stays memory only
    # (K.2, K.3): the client-id entry waits for the CLI's second run (D.8).
    assert world.store.entry("notes-client-id") is not None
    before = sorted((p.name, p.read_bytes()) for p in world.rig.state.rglob("*") if p.is_file())
    again_plan = world.page.fetch("POST", "/api/onboard/discover", json={"url": SERVER_URL})
    assert again_plan.status_code == 200, again_plan.text
    after = sorted((p.name, p.read_bytes()) for p in world.rig.state.rglob("*") if p.is_file())
    assert after == before
    assert world.store.entry("notes-client-id") is not None
    _, connected = connect_by_callback(world.page, world.passkey, "notes")
    assert connected.status_code == 200, connected.text
    [row] = world.servers()
    assert (row["state"], row["next"][0]["do"], row["tools"]) == ("needs_review", "review", 0)


def test_the_page_reads_what_the_vault_sends(world: World) -> None:
    """K.4's drift check of review.js against J2's answers: every field it reads of a row, a
    plan, its names, fragment 1 and a check finding is one the portal sends. A blocked
    onboarding's answer (D.11, vault/onboard.py's ``_stood``) adds ``blocked_on`` and
    ``server_url`` beside its names."""
    plan = discovered(world, url=SERVER_URL)
    onboarding = plan["onboarding"]
    [discovered_row] = world.servers()
    made = step_up(world.page, world.passkey, "onboard.register", {"onboarding": onboarding})
    assert made.status_code == 200, made.text
    registered = made.json()
    again = world.page.fetch("POST", f"/api/onboard/{onboarding}/fragment", json={})
    assert again.status_code == 200, again.text
    [registered_row] = world.servers()
    world.commit(registered["diff"]["yaml"])
    [server_row] = world.servers()
    rows = {*discovered_row, *registered_row, *server_row}
    assert reads("rowText", "row") | reads("listServers", "row") <= rows
    assert reads("showOnboarding", "answer") <= {*plan, "blocked_on", "server_url"}
    assert reads("showOnboarding", "plan") <= set(plan["plan"])
    assert reads("fillNames", "names") <= set(plan["names"])
    assert reads("showFragment", "answer") <= set(registered)
    assert {"diff", "next"} <= set(again.json())
    shown = {"level", "path", "message_shown"}
    assert reads("renderChecks", "finding") <= shown
    for found in [
        *plan["draft_check"],
        *registered["diff"]["check"],
        *again.json()["diff"]["check"],
    ]:
        assert set(found) == shown


def test_the_register_plan_refuses_before_the_passkey(world: World) -> None:
    """A registered client's secret comes from its server, not the operator; an unknown
    onboarding is refused; neither is held."""
    plan = discovered(world, url=SERVER_URL)
    data = {"onboarding": plan["onboarding"], "client_secret": SECRET}
    refused = world.page.fetch(
        "POST", "/api/actions", json={"kind": "onboard.register", "data": data}
    )
    assert status_reason(refused) == (400, "bad_body")
    unknown = {"onboarding": "0" * 16}
    gone = world.page.fetch(
        "POST", "/api/actions", json={"kind": "onboard.register", "data": unknown}
    )
    assert status_reason(gone) == (404, "onboarding_unknown")
    wrong = {"onboarding": 1}
    typed = world.page.fetch(
        "POST", "/api/actions", json={"kind": "onboard.register", "data": wrong}
    )
    assert status_reason(typed) == (400, "bad_body")
    assert len(world.rig.app.actions) == 0
    assert world.auth.registrations == []


# --- J3: a given client (D.4 order 1, D.7) ------------------------------------------------------


def test_j3_a_given_confidential_clients_secret_only_through_the_action(world: World) -> None:
    plan = discovered(
        world, url=SERVER_URL, client_id=CLIENT_ID, issuer=ISSUER, client_auth="basic"
    )
    shown = plan["plan"]
    assert (shown["registration"], shown["client_id_shown"], shown["secret_given"]) == (
        "given",
        CLIENT_ID,
        True,
    )
    assert plan["next"] == [{"do": "register", "label": "Store the secret and make the YAML"}]
    onboarding = plan["onboarding"]
    # Its fragment comes with the secret's register, never alone.
    alone = world.page.fetch("POST", f"/api/onboard/{onboarding}/fragment", json={})
    assert status_reason(alone) == (400, "bad_body")
    without = world.page.fetch(
        "POST",
        "/api/actions",
        json={"kind": "onboard.register", "data": {"onboarding": onboarding}},
    )
    assert status_reason(without) == (400, "bad_body")
    data = {"onboarding": onboarding, "client_secret": SECRET}
    held = prepared_action(world.page, "onboard.register", data)
    assert summary_of(held)["Client"] == f"{CLIENT_ID} (given)"
    assert summary_of(held)["Stored"] == (
        f"a client secret, as notes-client-secret, bound to {AUTH} and https://mcp.notes.example"
    )
    assert "Register a client at" not in summary_of(held)
    assert SECRET not in str(held)
    store = world.store
    assert store.entry("notes-client-secret") is None  # held, not stored, until the confirm
    assertion = world.passkey.get(held["options"], world.page.origin).body()
    made = world.page.fetch(
        "POST", f"/api/actions/{held['action']}/confirm", json={"credential": assertion}
    )
    assert made.status_code == 200, made.text
    assert (made.json()["secret_stored"], made.json()["secret_name"]) == (
        True,
        "notes-client-secret",
    )
    assert SECRET not in made.text
    assert '"store:notes-client-secret"' in made.json()["diff"]["yaml"]
    entry = store.entry("notes-client-secret")
    assert entry is not None
    assert entry.binding == {
        "oauth": {"token": f"{ISSUER}:443", "resources": ["https://mcp.notes.example:443"]}
    }
    assert world.auth.registrations == []
    assert SECRET not in world.rig.log.getvalue()


def test_j3_a_given_public_clients_fragment_needs_no_action(world: World) -> None:
    """K.1 item 2: nothing is sent or stored, so no passkey: the fragment route makes it."""
    plan = discovered(world, url=SERVER_URL, client_id=CLIENT_ID)
    assert plan["next"] == [{"do": "make_fragment", "label": "Make the YAML"}]
    assert plan["plan"]["redirect_uri"] == "http://127.0.0.1/callback"  # a given client's
    sent = len(world.hosts.sent)
    made = world.page.fetch("POST", f"/api/onboard/{plan['onboarding']}/fragment", json={})
    assert made.status_code == 200, made.text
    assert world.hosts.sent[sent:] == []
    assert load_mapping(made.json()["diff"]["yaml"])["credentials"]["notes"]["client_id"] == (
        CLIENT_ID
    )
    assert world.store.names() == []
    assert world.servers()[0]["state"] == "needs_commit"


# --- owners (D.8, X24) ---------------------------------------------------------------------------


def test_another_sessions_onboarding_is_unknown_and_an_ended_session_cancels_its_own(
    world: World,
) -> None:
    plan = discovered(world, url=SERVER_URL, client_id=CLIENT_ID)
    onboarding = plan["onboarding"]
    other = world.rig.browser().page(world.rig.origin)
    set_up(world.rig, other, SoftAuthenticator(), name="phone")
    for method, path in (
        ("GET", f"/api/onboard/{onboarding}"),
        ("DELETE", f"/api/onboard/{onboarding}"),
    ):
        assert status_reason(other.fetch(method, path)) == (404, "onboarding_unknown")
    fragment = other.fetch("POST", f"/api/onboard/{onboarding}/fragment", json={})
    assert status_reason(fragment) == (404, "onboarding_unknown")
    assert world.servers(other) == []  # its rows hold only its own onboarding
    read = world.page.fetch("GET", f"/api/onboard/{onboarding}")
    assert read.status_code == 200, read.text
    assert (read.json()["stage"], read.json()["onboarding"]) == ("discovered", onboarding)
    assert world.page.fetch("POST", "/api/logout", json={}).status_code == 200
    assert world.rig.app.onboard is not None
    assert len(world.rig.app.onboard._table) == 0
    assert [line["why"] for line in world.rig.lines("onboard_ended")] == ["owner_gone"]


def test_cancel(world: World) -> None:
    plan = discovered(world, url=SERVER_URL, client_id=CLIENT_ID)
    path = f"/api/onboard/{plan['onboarding']}"
    cancelled = world.page.fetch("DELETE", path)
    assert (cancelled.status_code, cancelled.json()) == (200, {"cancelled": True})
    assert status_reason(world.page.fetch("DELETE", path)) == (404, "onboarding_unknown")
    assert world.servers() == []


# --- a private discovery (TI-3) ------------------------------------------------------------------


def test_a_private_discovery_is_an_action(world: World) -> None:
    """The route refuses allow_private; the action's plan sends nothing; its confirm runs the
    discovery with the guard lifted for the typed host:port alone."""
    refused = world.page.fetch(
        "POST", "/api/onboard/discover", json={"url": SERVER_URL, "allow_private": True}
    )
    assert status_reason(refused) == (400, "bad_body")
    data = {"url": SERVER_URL, "allow_private": True, "client_id": CLIENT_ID}
    held = prepared_action(world.page, "onboard.discover_private", data)
    assert summary_of(held) == {
        "Discover": SERVER_URL,
        "The address guard is lifted for": "mcp.notes.example:443",
        "Names": "from the server's host name",
    }
    assert world.hosts.sent == []
    made = step_up(world.page, world.passkey, "onboard.discover_private", data)
    assert made.status_code == 200, made.text
    assert made.json()["stage"] == "discovered"
    assert world.hosts.sent
    assert (
        "egress_private"
        in world.page.fetch(
            "POST", f"/api/onboard/{made.json()['onboarding']}/fragment", json={}
        ).json()["diff"]["yaml"]
    )
    not_private = {"url": SERVER_URL, "allow_private": False}
    wrong = world.page.fetch(
        "POST", "/api/actions", json={"kind": "onboard.discover_private", "data": not_private}
    )
    assert status_reason(wrong) == (400, "bad_body")
    named = {**data, "credential": "notes-c", "server": "notes-s"}
    names = summary_of(prepared_action(world.page, "onboard.discover_private", named))["Names"]
    assert names == "notes-c, notes-s"
    bad_url = {"url": "http://mcp.notes.example/mcp", "allow_private": True}
    insecure = world.page.fetch(
        "POST", "/api/actions", json={"kind": "onboard.discover_private", "data": bad_url}
    )
    assert status_reason(insecure) == (400, "url_invalid")
