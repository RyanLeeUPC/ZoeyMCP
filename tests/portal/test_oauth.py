"""OAuth connect by paste and credential health, over the real API (M5 design H.1-H.4, I, P10-P12).

Connect is paste first: ``POST /api/oauth/{credential}/start`` starts a login this session owns,
the operator approves in a new tab and pastes the address the provider sent that tab to, and the
``oauth.complete`` action's plan checks the paste (``LoginService.check_paste``) before any
passkey prompt; only its confirm exchanges the code, once, and stores the grant. Every refusal
M2's login gives keeps its reason and status here (operations.md §2). Flows are owned (P11): the
CLI's, and another session's, answer as unknown ones, and a session that ends takes its flows
with it. A paste for a used, expired, foreign or other session's flow is refused (P12's paste
reading). ``oauth.reset`` clears a failure state after a step-up (D-22), and a client_credentials
start, the test fetch, clears it too, only when the fetch works.

The vault's token client is pointed at two ``FakeAuthServer`` apps by host; the test plays the
browser, approving at the fake's ``/authorize`` and pasting the address it redirects to.
"""

from __future__ import annotations

import asyncio
import re
import time
from collections.abc import Callable, Coroutine, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit

import httpx
import pytest

from tests.fakes.authenticator import SoftAuthenticator
from tests.fakes.browser import Page
from tests.fakes.oauth_server import FakeAuthServer
from zoeymcp.vault import app as vault_app
from zoeymcp.vault.bindings import derive_binding
from zoeymcp.vault.oauth.pkce import FLOW_TTL
from zoeymcp.vault.store import SecretStore

from .flows import set_up, status_reason
from .rig import PortalRig, running
from .test_stepup import ACTIONS, confirm, prepare, prepared, step_up

REDIRECT = "http://127.0.0.1/callback"
NOTES_ISSUER = "https://auth.notes.example"
NOTES_ID = "example-notes-client"
NOTES_SCOPES = ("notes.read", "notes.write")
MACHINE_ID = "machine-client"
MACHINE_SECRET = "fake-machine-secret-0001"
WRONG_SECRET = "fake-wrong-secret-0001"
NOTES_BINDING = {
    "oauth": {
        "token": "https://auth.notes.example:443",
        "resources": ["https://api.notes.example:443"],
    }
}
OTHER_BINDING = {
    "oauth": {
        "token": "https://auth.notes.example:443",
        "resources": ["https://old.notes.example:443"],
    }
}
NOTES_WORDS = "token endpoint https://auth.notes.example:443, its access tokens used at "
# A provider's description with markup, and one with a bidi override and a zero-width space,
# built from escapes.
PLAIN = "<b>No</b> thanks"
HOSTILE = "No" + chr(0x202E) + "thanks" + chr(0x200B)


def route(name: str, upstream: str) -> dict[str, Any]:
    return {
        "name": name,
        "prefix": f"/{name}",
        "upstream": upstream,
        "credential": name,
        "callers": [{"placeholder": f"ph-agent1-{name}-0001"}],
        "rules": [{"methods": ["GET"], "paths": ["/**"]}],
    }


def notes(**changes: Any) -> dict[str, Any]:
    """A public client with PKCE whose refresh tokens rotate (S5's shape)."""
    cred: dict[str, Any] = {
        "kind": "oauth2",
        "token_url": "https://auth.notes.example/token",
        "authorize_url": "https://auth.notes.example/authorize",
        "client_id": NOTES_ID,
        "client_auth": "none",
        "rotates": True,
        "refresh_token": "store:notes-refresh",
        "scope": " ".join(NOTES_SCOPES),
        "issuer": NOTES_ISSUER,
    }
    cred.update(changes)
    return {key: value for key, value in cred.items() if value is not None}


def policy(**more: dict[str, Any]) -> dict[str, Any]:
    """``notes`` (connect in the browser), ``machine`` (client_credentials) and ``seeded`` (a
    refresh token given another way, so it can't connect in a browser), plus ``more``."""
    credentials: dict[str, Any] = {
        "notes": notes(),
        "machine": {
            "kind": "oauth2",
            "token_url": "https://auth.machine.example/token",
            "grant": "client_credentials",
            "client_id": MACHINE_ID,
            "client_secret": "store:machine-secret",
            "scope": "read",
        },
        "seeded": notes(authorize_url=None, refresh_token="store:seeded-refresh"),
        **more,
    }
    upstreams = {"notes": "https://api.notes.example"}
    routes = [
        route(name, upstreams.get(name, f"https://api.{name}.example")) for name in credentials
    ]
    return {"credentials": credentials, "routes": routes}


@dataclass
class Providers:
    notes: FakeAuthServer
    machine: FakeAuthServer

    def app(self) -> Any:
        """One ASGI app that hands each token call to the fake for its host."""
        apps = {
            "auth.notes.example": self.notes.app(),
            "auth.machine.example": self.machine.app(),
        }

        async def by_host(scope: Any, receive: Any, send: Any) -> None:
            host = dict(scope["headers"])[b"host"].decode().split(":")[0]
            await apps[host](scope, receive, send)

        return by_host

    def approve(self, url: str) -> str:
        """Play the browser: approve at ``url``, and return the address it is sent to."""

        async def browse() -> str:
            transport = httpx.ASGITransport(app=self.notes.app())
            async with httpx.AsyncClient(transport=transport) as browser:
                response = await browser.get(url)
            assert response.status_code == 302, response.text
            location: str = response.headers["location"]
            return location

        return asyncio.run(browse())


def providers() -> Providers:
    return Providers(
        FakeAuthServer(
            time.time,
            client_id=NOTES_ID,
            auth="none",
            rotate=True,
            scopes=NOTES_SCOPES,
            issuer=NOTES_ISSUER,
            prefix="fake-notes",
        ),
        FakeAuthServer(
            time.time, client_id=MACHINE_ID, client_secret=MACHINE_SECRET, prefix="fake-machine"
        ),
    )


@dataclass
class World:
    rig: PortalRig
    fakes: Providers
    page: Page
    passkey: SoftAuthenticator


@pytest.fixture
def world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[World]:
    fakes = providers()
    monkeypatch.setattr(
        vault_app,
        "_token_client",
        lambda _: httpx.AsyncClient(transport=httpx.ASGITransport(app=fakes.app())),
    )
    with running(tmp_path, policy=policy()) as rig:
        passkey = SoftAuthenticator()
        page = rig.browser().page(rig.origin)
        set_up(rig, page, passkey)
        yield World(rig, fakes, page, passkey)


def store(rig: PortalRig) -> SecretStore:
    return rig.vault.app.tokens.store


def put(rig: PortalRig, name: str, value: str, binding: dict[str, Any] | None = None) -> None:
    """A secret written on the vault's loop, as the socket writes one."""
    given = binding or derive_binding(rig.vault.app.policy, name)
    rig.call(lambda: store(rig).put(name, value, given))


def on_loop[R](rig: PortalRig, coroutine: Coroutine[Any, Any, R]) -> R:
    return asyncio.run_coroutine_threadsafe(coroutine, rig.loop).result(30)


def start(page: Page, credential: str = "notes", **body: Any) -> httpx.Response:
    return page.fetch("POST", f"/api/oauth/{credential}/start", json=body)


def started(page: Page, credential: str = "notes", **body: Any) -> dict[str, Any]:
    answer = start(page, credential, **body)
    assert answer.status_code == 200, answer.text
    data: dict[str, Any] = answer.json()
    return data


def complete_data(flow: str, pasted: str, credential: str = "notes") -> dict[str, Any]:
    return {"credential": credential, "flow": flow, "redirect_url": pasted}


def with_query(url: str, **changes: str | None) -> str:
    parts = urlsplit(url)
    pairs = dict(parse_qsl(parts.query))
    for key, value in changes.items():
        if value is None:
            pairs.pop(key, None)
        else:
            pairs[key] = value
    return parts._replace(query=urlencode(pairs)).geturl()


def oauth_entry(page: Page, credential: str) -> dict[str, Any]:
    listed = page.fetch("GET", "/api/oauth")
    assert listed.status_code == 200, listed.text
    [entry] = [e for e in listed.json()["credentials"] if e["credential"] == credential]
    return dict(entry)


def no_secret_in(text: str, *values: str) -> None:
    for value in values:
        assert value not in text


# --- the credentials and health --------------------------------------------------------------


def test_the_credentials_and_what_each_can_do(world: World) -> None:
    page = world.page
    listed = page.fetch("GET", "/api/oauth").json()["credentials"]
    by_name = {entry["credential"]: entry for entry in listed}
    assert sorted(by_name) == ["machine", "notes", "seeded"]
    assert {name: entry["connect"] for name, entry in by_name.items()} == {
        "notes": "browser",
        "machine": "test",
        "seeded": None,
    }
    entry = by_name["notes"]
    assert (entry["state"], entry["code"], entry["requested_scopes_shown"]) == (
        "idle",
        None,
        list(NOTES_SCOPES),
    )
    assert entry["used_at_shown"] == ["https://api.notes.example"]
    assert entry["text_shown"] == (
        "OAuth: idle; last worked not since the vault started; asks for notes.read notes.write; "
        "its tokens go to https://api.notes.example."
    )
    assert "meta" not in entry  # the clear meta only as fields fit to show
    health = page.fetch("GET", "/api/health").json()
    assert health["summary"] == page.fetch("GET", "/api/session").json()["health_summary"]
    [notes_item] = [c for c in health["credentials"] if c["name"] == "notes"]
    assert (notes_item["name_shown"], notes_item["level"], notes_item["routes"]) == (
        "notes",
        "error",
        ["notes"],
    )
    [missing] = notes_item["findings"]
    assert (missing["code"], missing["action"], missing["todo"]) == (
        "missing",
        {"kind": "connect", "credential": "notes"},
        None,
    )
    assert missing["text_shown"] == "store:notes-refresh has no entry"
    # The checklist holds every finding, errors first.
    levels = [finding["level"] for finding in health["checklist"]]
    assert levels == sorted(levels, key=["error", "warning", "info"].index)
    assert len(levels) == sum(health["summary"].values())
    # Errors show as a banner on every page.
    banners = page.fetch("GET", "/api/session").json()["banners"]
    assert banners == [
        {
            "code": "health_errors",
            "text": f"{health['summary']['error']} problem(s) need you: see the checklist on Home.",
        }
    ]
    # An action the page has no button for is worded by the vault.
    machine = next(c for c in health["credentials"] if c["name"] == "machine")
    assert [f["action"]["kind"] for f in machine["findings"]] == ["set_secret"]


def test_health_is_the_sockets_report_fit_to_show(world: World) -> None:
    rig = world.rig
    assert rig.app.health is not None
    report = rig.call(rig.app.health)
    shown = world.page.fetch("GET", "/api/health").json()
    assert shown["summary"] == report["summary"]
    for raw, view in zip(report["credentials"], shown["credentials"], strict=True):
        assert [f["text"] for f in raw["findings"]] == [f["text_shown"] for f in view["findings"]]
        assert "refs" not in view
    assert "passkeys" in shown  # this vault has a portal
    assert [f["code"] for f in shown["passkeys"]["findings"]] == ["passkey_single"]
    assert shown["passkeys"]["findings"][0]["section"] == "passkeys"


def test_a_setup_session_reaches_neither_health_nor_the_oauth_routes(world: World) -> None:
    from .flows import issue, redeem

    page = world.rig.browser().page(world.rig.origin)
    assert redeem(page, issue(world.rig)).status_code == 200
    assert page.fetch("GET", "/api/session").json()["health_summary"] is None
    for method, path in (
        ("GET", "/api/health"),
        ("GET", "/api/oauth"),
        ("POST", "/api/oauth/notes/start"),
        ("DELETE", "/api/oauth/flows/0123456789abcdef"),
    ):
        body: dict[str, Any] | None = {} if method == "POST" else None
        assert status_reason(page.fetch(method, path, json=body)) == (403, "scope"), path


# --- connect by paste (H.1) ----------------------------------------------------------------


def test_connect_by_paste_stores_the_grant_after_a_step_up(world: World) -> None:
    rig, page, fakes = world.rig, world.page, world.fakes
    begun = started(page)
    assert begun["replaced"] is None
    assert begun["redirect_uri"] == begun["redirect_uri_shown"] == REDIRECT
    assert begun["binding"] == NOTES_BINDING
    assert begun["binding_shown"] == NOTES_WORDS + "https://api.notes.example:443"
    assert begun["binding_change"] is begun["binding_change_shown"] is None
    assert begun["requested_scopes_shown"] == list(NOTES_SCOPES)
    assert begun["name_shown"] == "notes"
    query = dict(parse_qsl(urlsplit(begun["authorize_url"]).query))
    assert (query["code_challenge_method"], query["redirect_uri"]) == ("S256", REDIRECT)
    pasted = fakes.approve(begun["authorize_url"])
    # The plan checks the paste and holds it: nothing is exchanged before the passkey.
    held = prepared(page, "oauth.complete", complete_data(begun["flow"], pasted))
    assert held["summary"] == [
        ["Connect", "notes"],
        ["With", "the address you pasted, checked: it is this sign-in's answer"],
        ["Its tokens go to", NOTES_WORDS + "https://api.notes.example:443"],
        ["Scopes asked for", "notes.read notes.write"],
        ["Scopes expected", "notes.read notes.write"],
    ]
    assert fakes.notes.calls == []
    assertion = world.passkey.get(held["options"], page.origin).body()
    done = confirm(page, held["action"], assertion)
    assert done.status_code == 200, done.text
    result = done.json()
    assert (result["credential"], result["slot"], result["persisted"]) == (
        "notes",
        "notes-refresh",
        True,
    )
    assert result["granted_scopes_shown"] == list(NOTES_SCOPES)
    assert result["text_shown"] == "granted notes.read notes.write."
    [exchange] = fakes.notes.calls
    assert exchange.grant_type == "authorization_code"
    stored, _ = store(rig).get_for_oauth("notes-refresh", token_url=NOTES_ISSUER + "/token")
    assert stored.reveal() == fakes.notes.active_refresh_token()
    assert store(rig).entry("notes-refresh").binding == NOTES_BINDING  # type: ignore[union-attr]
    assert oauth_entry(page, "notes")["state"] == "ok"
    assert rig.logged("step_up_confirmed", lambda line: line["action"] == "oauth.complete")
    assert rig.lines("oauth_login_completed")[-1]["credential"] == "notes"
    # The flow was spent: the same paste again is a login that no longer exists (P12).
    again = prepare(page, "oauth.complete", complete_data(begun["flow"], pasted))
    assert status_reason(again) == (404, "flow_unknown")
    no_secret_in(rig.log.getvalue(), begun["flow"], pasted, query["state"])


def test_scopes_outside_the_expected_set_are_flagged_not_refused(world: World) -> None:
    world.fakes.notes.granted_scopes = ("notes.read", "notes.admin")
    begun = started(world.page)
    pasted = world.fakes.approve(begun["authorize_url"])
    done = step_up(
        world.page, world.passkey, "oauth.complete", complete_data(begun["flow"], pasted)
    )
    assert done.status_code == 200, done.text
    result = done.json()
    assert (result["unexpected_scopes_shown"], result["missing_scopes_shown"]) == (
        ["notes.admin"],
        ["notes.write"],
    )
    assert result["text_shown"] == (
        "granted notes.read notes.admin. Not expected: notes.admin. "
        "Expected, not granted: notes.write."
    )


def test_the_result_says_when_the_grant_ends(world: World) -> None:
    rig = world.rig
    document = {
        **policy(),
        "admin": {"listen": f"127.0.0.1:{rig.portal_port}", "origins": [rig.origin]},
        "version": 1,
        "mode": "declarative",
    }
    document["credentials"]["notes"]["grant_lifetime_days"] = 180
    rig.reload(document)
    begun = started(world.page)
    pasted = world.fakes.approve(begun["authorize_url"])
    data = complete_data(begun["flow"], pasted)
    done = step_up(world.page, world.passkey, "oauth.complete", data)
    assert done.status_code == 200, done.text
    ends = done.json()["grant_expires_at"]
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", ends)
    assert done.json()["text_shown"] == (
        f"granted notes.read notes.write. The grant ends at {ends}: connect again before then."
    )


@pytest.mark.parametrize(
    ("change", "reason", "text"),
    [
        (
            lambda u: u.replace("127.0.0.1", "127.0.0.2"),
            "redirect_mismatch",
            "That isn't the address the provider sent you to; it starts with "
            "http://127.0.0.1/callback.",
        ),
        (
            lambda u: with_query(u, state="another-login"),
            "state_mismatch",
            "That address belongs to another login; use the tab this login opened.",
        ),
        (
            lambda u: u + "&code=again",
            "duplicate_param",
            "That address has a parameter twice. Copy it again from the address bar.",
        ),
        (
            lambda u: with_query(u, code=None),
            "no_code",
            "The provider's answer had no usable code. Connect again.",
        ),
        (
            lambda u: with_query(u, iss="https://other.example"),
            "iss_mismatch",
            "The answer came from a different issuer; nothing was stored. Connect again.",
        ),
    ],
    ids=["redirect", "state", "duplicate", "no-code", "iss"],
)
def test_a_bad_paste_is_refused_before_any_prompt_and_can_be_fixed(
    world: World, change: Callable[[str], str], reason: str, text: str
) -> None:
    page, fakes = world.page, world.fakes
    begun = started(page)
    pasted = fakes.approve(begun["authorize_url"])
    refused = prepare(page, "oauth.complete", complete_data(begun["flow"], change(pasted)))
    assert (refused.status_code, refused.json()) == (400, {"error": text, "reason": reason})
    assert len(world.rig.app.actions) == 0  # nothing held, so no prompt
    assert fakes.notes.calls == []
    # The flow is left for the corrected paste.
    done = step_up(page, world.passkey, "oauth.complete", complete_data(begun["flow"], pasted))
    assert done.status_code == 200, done.text


@pytest.mark.parametrize(
    ("description", "shown"),
    [
        (PLAIN, PLAIN),  # markup stays text: the page sets it with textContent
        (HOSTILE, None),  # hidden characters: the vault drops the text (M2), nothing to show
    ],
    ids=["plain", "hidden-characters"],
)
def test_a_provider_error_ends_the_flow_and_shows_its_text(
    world: World, description: str, shown: str | None
) -> None:
    page, rig = world.page, world.rig
    begun = started(page)
    state = dict(parse_qsl(urlsplit(begun["authorize_url"]).query))["state"]
    pasted = f"{REDIRECT}?" + urlencode(
        {"error": "access_denied", "error_description": description, "state": state}
    )
    refused = prepare(page, "oauth.complete", complete_data(begun["flow"], pasted))
    assert refused.status_code == 400
    assert refused.json() == {
        "error": "The answer said the provider refused: access_denied",
        "reason": "provider_error",
        "description_shown": shown,
    }
    # The provider's answer is final: the flow is gone.
    again = prepare(page, "oauth.complete", complete_data(begun["flow"], pasted))
    assert status_reason(again) == (404, "flow_unknown")
    assert "thanks" not in rig.log.getvalue()
    [failed] = rig.lines("oauth_login_failed")
    assert failed["reason"] == "provider_error"


def test_a_start_the_vault_refuses_keeps_m2s_reason_and_status(world: World) -> None:
    page = world.page
    for credential, status, reason in (
        ("nothing", 404, "not_oauth"),
        ("seeded", 409, "no_authorize_url"),
    ):
        assert status_reason(start(page, credential)) == (status, reason)
    assert status_reason(start(page, "notes", rebind="yes")) == (400, "bad_body")
    assert status_reason(start(page, "notes", other=True)) == (400, "bad_body")
    assert status_reason(start(page, "NOTES")) == (404, "not_found")  # outside the name pattern


def test_an_exchange_the_provider_refuses_needs_a_new_connect(world: World) -> None:
    page, fakes = world.page, world.fakes
    cases: tuple[tuple[Callable[[], object], str, str], ...] = (
        (
            lambda: fakes.notes.fail_next(1),
            "exchange_failed:oauth_unavailable",
            "The provider's token endpoint didn't take the sign-in (oauth_unavailable). "
            "Connect again.",
        ),
        (
            lambda: setattr(fakes.notes, "require_offline", True),
            "no_refresh_token",
            "The provider issued no refresh token. For Google keep access_type: offline and "
            "prompt: consent; some providers need an offline_access scope.",
        ),
    )
    for knob, reason, text in cases:
        begun = started(page)
        pasted = fakes.approve(begun["authorize_url"])
        knob()
        answer = step_up(
            page, world.passkey, "oauth.complete", complete_data(begun["flow"], pasted)
        )
        assert (answer.status_code, answer.json()) == (400, {"error": text, "reason": reason})
        # The exchange took the flow: the same paste is no longer a login.
        again = prepare(page, "oauth.complete", complete_data(begun["flow"], pasted))
        assert status_reason(again) == (404, "flow_unknown")
    assert store(world.rig).entry("notes-refresh") is None


def test_a_changed_binding_needs_a_connect_with_rebind(world: World) -> None:
    """P10's "rebind needed in both": a grant bound otherwise is refused at the start and at
    the paste's plan, before any prompt, until a start with rebind accepts the new binding."""
    rig, page, fakes = world.rig, world.page, world.fakes
    # The policy moved after the start: the plan refuses, nothing is exchanged.
    begun = started(page)
    pasted = fakes.approve(begun["authorize_url"])
    put(rig, "notes-refresh", "rt-bound-elsewhere", OTHER_BINDING)
    refused = prepare(page, "oauth.complete", complete_data(begun["flow"], pasted))
    old = NOTES_WORDS + "https://old.notes.example:443"
    new = NOTES_WORDS + "https://api.notes.example:443"
    assert refused.status_code == 409
    assert refused.json() == {
        "error": "The policy now binds this grant differently (shown below). Connect again "
        "and accept the new binding.",
        "reason": "binding_changed",
        "old_shown": old,
        "new_shown": new,
    }
    assert fakes.notes.calls == []
    # A start without rebind is refused the same way, with both bindings.
    assert start(page).json() == {**refused.json()}
    # With rebind: the change is shown before the prompt, and the grant is bound anew.
    rebound = started(page, rebind=True)
    assert rebound["binding_change_shown"] == {"old": old, "new": new}
    pasted = fakes.approve(rebound["authorize_url"])
    held = prepared(page, "oauth.complete", complete_data(rebound["flow"], pasted))
    assert ["Bound until now", old] in held["summary"]
    assertion = world.passkey.get(held["options"], page.origin).body()
    assert confirm(page, held["action"], assertion).status_code == 200
    assert store(rig).entry("notes-refresh").binding == NOTES_BINDING  # type: ignore[union-attr]


def test_a_reload_between_the_paste_and_the_confirm_is_changed(world: World) -> None:
    rig, page, fakes = world.rig, world.page, world.fakes
    begun = started(page)
    pasted = fakes.approve(begun["authorize_url"])
    held = prepared(page, "oauth.complete", complete_data(begun["flow"], pasted))
    document = {
        **policy(),
        "admin": {"listen": f"127.0.0.1:{rig.portal_port}", "origins": [rig.origin]},
        "version": 1,
        "mode": "declarative",
    }
    document["credentials"]["notes"]["scope"] = "notes.read"
    rig.reload(document)
    assertion = world.passkey.get(held["options"], page.origin).body()
    answer = confirm(page, held["action"], assertion)
    assert status_reason(answer) == (409, "changed")
    assert ["Scopes asked for", "notes.read"] in answer.json()["now"]
    assert fakes.notes.calls == []


# --- flows are owned (H.2, P11) ------------------------------------------------------------


def test_a_cli_flow_is_neither_completed_nor_cancelled_by_a_session(world: World) -> None:
    rig, page, fakes = world.rig, world.page, world.fakes
    cli = on_loop(rig, rig.vault.login.start("notes"))
    pasted = fakes.approve(cli["authorize_url"])
    refused = prepare(page, "oauth.complete", complete_data(cli["flow"], pasted))
    assert status_reason(refused) == (404, "flow_unknown")
    cancelled = page.fetch("DELETE", f"/api/oauth/flows/{cli['flow']}")
    assert status_reason(cancelled) == (404, "flow_unknown")
    # The CLI's paste still completes it.
    done = on_loop(rig, rig.vault.login.complete("notes", cli["flow"], pasted))
    assert done["persisted"] is True


def test_one_sessions_flow_is_unknown_to_another(world: World) -> None:
    rig, fakes = world.rig, world.fakes
    other_key = SoftAuthenticator()
    other = rig.browser().page(rig.origin)
    set_up(rig, other, other_key, name="phone")
    begun = started(world.page)
    pasted = fakes.approve(begun["authorize_url"])
    refused = prepare(other, "oauth.complete", complete_data(begun["flow"], pasted))
    assert status_reason(refused) == (404, "flow_unknown")
    assert status_reason(other.fetch("DELETE", f"/api/oauth/flows/{begun['flow']}")) == (
        404,
        "flow_unknown",
    )
    # A start from the other session replaces the login, and says where it was pending.
    assert started(other)["replaced"] == "portal"
    assert rig.lines("oauth_flow_replaced")[-1]["by"] == "portal"
    refused = prepare(world.page, "oauth.complete", complete_data(begun["flow"], pasted))
    assert status_reason(refused) == (404, "flow_unknown")
    # A start in the CLI replaces the portal's, and the portal's next start says so.
    on_loop(rig, rig.vault.login.start("notes"))
    assert started(world.page)["replaced"] == "cli"


def test_the_owner_cancels_and_an_ended_session_takes_its_flows(world: World) -> None:
    rig, page, fakes = world.rig, world.page, world.fakes
    begun = started(page)
    cancelled = page.fetch("DELETE", f"/api/oauth/flows/{begun['flow']}")
    assert (cancelled.status_code, cancelled.json()) == (200, {"cancelled": True})
    assert status_reason(page.fetch("DELETE", f"/api/oauth/flows/{begun['flow']}")) == (
        404,
        "flow_unknown",
    )
    begun = started(page)
    pasted = fakes.approve(begun["authorize_url"])
    assert page.fetch("POST", "/api/logout", json={}).status_code == 200
    # The session's flow went with it: the CLI can't take it over, nor a new session.
    with pytest.raises(Exception, match="no such login is pending"):
        on_loop(rig, rig.vault.login.complete("notes", begun["flow"], pasted))
    assert len(rig.vault.login._flows) == 0


def test_an_expired_flow_is_refused(world: World) -> None:
    rig, page, fakes = world.rig, world.page, world.fakes
    begun = started(page)
    pasted = fakes.approve(begun["authorize_url"])
    flows = rig.vault.login._flows
    flows._clock = lambda: time.monotonic() + FLOW_TTL
    refused = prepare(page, "oauth.complete", complete_data(begun["flow"], pasted))
    assert status_reason(refused) == (404, "flow_unknown")
    assert fakes.notes.calls == []


def test_a_pending_paste_is_spent_by_the_confirm_alone(world: World) -> None:
    """Only the confirm takes the flow: a prepared paste can be cancelled, and the flow is
    still there for the next one."""
    page, fakes = world.page, world.fakes
    begun = started(page)
    pasted = fakes.approve(begun["authorize_url"])
    held = prepared(page, "oauth.complete", complete_data(begun["flow"], pasted))
    assert page.fetch("DELETE", f"{ACTIONS}/{held['action']}").json() == {"cancelled": True}
    done = step_up(page, world.passkey, "oauth.complete", complete_data(begun["flow"], pasted))
    assert done.status_code == 200, done.text
    assert len(fakes.notes.calls) == 1


# --- client_credentials and reset (H.1, D-22) ----------------------------------------------


def machine_call(rig: PortalRig) -> int:
    """An agent's request on the machine route: the vault fetches a token first."""
    url = f"http://127.0.0.1:{rig.proxy_port}/machine/items"
    headers = {"Authorization": "Bearer ph-agent1-machine-0001"}
    return httpx.get(url, headers=headers, timeout=30).status_code


def test_a_test_fetch_and_a_reset_clear_a_failure(world: World) -> None:
    rig, page = world.rig, world.page
    put(rig, "machine-secret", WRONG_SECRET)
    assert machine_call(rig) == 502
    assert oauth_entry(page, "machine")["state"] == "terminal"
    # A test fetch that fails clears nothing.
    refused = start(page, "machine")
    assert status_reason(refused) == (400, "exchange_failed:oauth_client_rejected")
    assert oauth_entry(page, "machine")["state"] == "terminal"
    # One that works clears the failure state, with no step-up: it follows a fetch that worked.
    put(rig, "machine-secret", MACHINE_SECRET)
    tested = started(page, "machine")
    assert (tested["credential"], tested["granted_scopes_shown"]) == ("machine", ["read"])
    assert tested["text_shown"] == "granted read."
    assert oauth_entry(page, "machine")["state"] != "terminal"
    # oauth.reset: the state now in the summary, cleared after the step-up.
    put(rig, "machine-secret", WRONG_SECRET)
    assert machine_call(rig) == 502
    held = prepared(page, "oauth.reset", {"credential": "machine"})
    assert held["summary"] == [
        ["Clear the failure state of", "machine"],
        ["Its state now", "terminal (oauth_client_rejected)"],
        ["Then", "the next request that needs a token tries once"],
    ]
    assert oauth_entry(page, "machine")["state"] == "terminal"
    assertion = world.passkey.get(held["options"], page.origin).body()
    done = confirm(page, held["action"], assertion)
    assert (done.status_code, done.json()) == (200, {"credential": "machine", "reset": True})
    assert oauth_entry(page, "machine")["state"] == "idle"
    assert rig.lines("oauth_cache_reset")[-1]["reason"] == "reset"
    for data, status, reason in (
        ({"credential": "nothing"}, 404, "not_oauth"),
        ({"credential": 7}, 400, "bad_body"),
    ):
        assert status_reason(prepare(page, "oauth.reset", data)) == (status, reason)
    no_secret_in(rig.log.getvalue(), MACHINE_SECRET, WRONG_SECRET)


def test_the_completion_data_is_checked_before_the_flow(world: World) -> None:
    page = world.page
    for data in (
        {"credential": "notes", "flow": 7, "redirect_url": REDIRECT},
        {"credential": "notes", "flow": "x", "redirect_url": None},
        {"credential": ["notes"], "flow": "x", "redirect_url": REDIRECT},
        {"credential": "notes", "flow": "x"},
    ):
        assert status_reason(prepare(page, "oauth.complete", data)) == (400, "bad_body"), data
    # A paste is capped at 8 KiB (M.1).
    long = complete_data("x", REDIRECT + "?" + "a" * 8200)
    assert status_reason(prepare(page, "oauth.complete", long)) == (413, "too_large")


def test_too_many_pending_logins(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fakes = providers()
    monkeypatch.setattr(
        vault_app,
        "_token_client",
        lambda _: httpx.AsyncClient(transport=httpx.ASGITransport(app=fakes.app())),
    )
    spare = {f"spare{n}": notes(refresh_token=f"store:spare{n}-refresh") for n in range(8)}
    with running(tmp_path, policy=policy(**spare)) as rig:
        page = rig.browser().page(rig.origin)
        set_up(rig, page, SoftAuthenticator())
        for name in spare:
            started(page, name)
        answer = start(page, "notes")
        assert answer.status_code == 429
        assert answer.json()["reason"] == "too_many_flows"
        assert "retry-after" not in answer.headers
