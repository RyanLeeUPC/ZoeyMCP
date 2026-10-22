"""The OAuth callback over real sockets (M5 design C.7, H.6, P11, P12, P15, F.4).

``GET /oauth/callback/<credential>`` is the one route that takes a cross-site navigation. It
serves only a flow a portal session started for a credential whose ``redirect_uri`` is its
callback address on this origin, pending (or returned) and unexpired, named by the query's
``state`` and carrying the flow's binding cookie. It consumes the ``state``, makes the paste's
checks, and holds the code; nothing is exchanged or stored until the owner confirms
``oauth.complete`` with ``returned: true`` after a passkey. A different second answer, by
callback or paste, fails the flow (the conflict rule). Everything refused answers the fixed
refused page in place; a changed flow answers 303 to ``/callback/received``.

The fake browser follows ``FakeAuthServer``'s real redirect from ``/authorize`` to the callback as
one cross-site navigation (the provider is reached in process, as a remote origin of the
browser). The rig's clock refills the rate bucket between callbacks, so a test's count of
requests never meets the 429 it isn't about.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

import httpx
import pytest

from tests.fakes.authenticator import SoftAuthenticator
from tests.fakes.browser import Browser, Page, asgi_client, loopback
from zoeymcp.portal.routes import ROUTES, STATIC
from zoeymcp.vault import netclient
from zoeymcp.vault.oauth.pkce import FLOW_TTL

from .flows import filled, set_up, status_reason
from .rig import Clock, PortalRig, running
from .test_oauth import (
    NOTES_ISSUER,
    REDIRECT,
    Providers,
    complete_data,
    notes,
    on_loop,
    policy,
    providers,
    started,
    store,
)
from .test_shell import assert_portal_headers
from .test_stepup import confirm, prepare, prepared

STATIC_DIR = Path(__file__).resolve().parents[2] / "src" / "zoeymcp" / "portal" / "static"
REFUSED_PAGE = (STATIC_DIR / "callback-refused.html").read_bytes()
RECEIVED_PAGE = (STATIC_DIR / "callback-received.html").read_bytes()
EVIL = "https://evil.example"
# A provider's description with a bidi override and markup, built from escapes.
HOSTILE = "<i>No</i>" + chr(0x202E) + " thanks"
CONFLICT = "Two different answers came back for this sign-in. Nothing was stored. Connect again."
CHECK = (
    "Confirm only if you have just finished approving in the provider's tab; if you haven't, "
    "cancel."
)


def callback_policy(origin: str) -> dict[str, Any]:
    """test_oauth's credentials, ``notes`` registered with its callback address here, ``mail``
    with its own, and ``plain`` pasting to the default."""
    document = policy(
        mail=notes(redirect_uri=f"{origin}/oauth/callback/mail", refresh_token="store:mail-rt"),
        plain=notes(refresh_token="store:plain-rt"),
    )
    document["credentials"]["notes"]["redirect_uri"] = f"{origin}/oauth/callback/notes"
    return document


@dataclass
class World:
    rig: PortalRig
    fakes: Providers
    clock: Clock
    browser: Browser
    page: Page
    passkey: SoftAuthenticator
    provider: httpx.Client

    @property
    def address(self) -> str:
        return self.rig.origin + "/oauth/callback/notes"

    def browser_too(self) -> Browser:
        """Another browser profile: none of the first one's cookies."""
        browser = Browser(address=loopback, remote={NOTES_ISSUER: self.provider})
        self.rig.browsers.append(browser)
        return browser

    def follow(self, url: str, browser: Browser | None = None) -> httpx.Response:
        """The operator's tab: the authorization link opened from the portal's page, approved,
        and the provider's redirect followed to the callback, then wherever that sends it."""
        self.clock.advance(30)  # a full bucket for the callback
        return (browser or self.browser).navigate(url, initiator=self.rig.origin)

    def deliver(
        self, url: str, browser: Browser | None = None, *, initiator: str | None = EVIL
    ) -> httpx.Response:
        """A navigation straight to ``url`` (a code-bearing callback address), from a page of
        ``initiator`` or typed (None)."""
        self.clock.advance(30)
        return (browser or self.browser).navigate(url, initiator=initiator)

    def answer(self, authorize_url: str) -> str:
        """Where the provider sends an approval of ``authorize_url``, without following it: a
        second approval of the same link is another code for it (an attacker's answer)."""
        location: str = self.provider.get(authorize_url, follow_redirects=False).headers["location"]
        return location

    def binder(self, browser: Browser | None = None) -> str | None:
        found = [c for c in (browser or self.browser).cookies if c.name.endswith("-cb")]
        return found[-1].value if found else None


@pytest.fixture
def world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[World]:
    fakes = providers()
    monkeypatch.setattr(
        netclient,
        "token_client",
        lambda *_: httpx.AsyncClient(transport=httpx.ASGITransport(app=fakes.app())),
    )
    clock = Clock()
    with running(tmp_path, policy=callback_policy, clock=clock) as rig:
        fakes.notes.registered_redirect = rig.origin + "/oauth/callback/notes"
        provider = asgi_client(fakes.notes.app(), NOTES_ISSUER)
        browser = Browser(address=loopback, remote={NOTES_ISSUER: provider})
        rig.browsers.append(browser)
        page = browser.page(rig.origin)
        passkey = SoftAuthenticator()
        set_up(rig, page, passkey)
        try:
            yield World(rig, fakes, clock, browser, page, passkey, provider)
        finally:
            provider.close()


def state_of(url: str) -> str:
    return dict(parse_qsl(urlsplit(url).query))["state"]


def status_of(page: Page, flow: str) -> httpx.Response:
    return page.fetch("GET", f"/api/oauth/flows/{flow}")


def stage(page: Page, flow: str) -> str:
    answer = status_of(page, flow)
    assert answer.status_code == 200, answer.text
    found: str = answer.json()["stage"]
    return found


def returned_data(flow: str, credential: str = "notes") -> dict[str, Any]:
    return {"credential": credential, "flow": flow, "returned": True}


def refused_in_place(response: httpx.Response, status: int) -> None:
    """The fixed refused page, in place: no redirect, the address kept for a paste (C.7)."""
    assert response.status_code == status
    assert response.content == REFUSED_PAGE
    assert response.headers["content-type"] == "text/html; charset=utf-8"
    assert "location" not in response.headers
    assert_portal_headers(response)


def received(response: httpx.Response) -> None:
    """The 303 was followed: the tab ends on /callback/received, the code out of the bar."""
    assert response.status_code == 200
    assert response.content == RECEIVED_PAGE
    assert str(response.request.url).endswith("/callback/received")


def callback_hops(browser: Browser) -> list[tuple[str, httpx.Headers]]:
    return [(url, headers) for _, url, headers in browser.history if "/oauth/callback/" in url]


# --- the journey (P12) ----------------------------------------------------------------------------


def test_a_connect_through_the_callback(world: World) -> None:
    rig, page, fakes = world.rig, world.page, world.fakes
    answer = page.fetch("POST", "/api/oauth/notes/start", json={})
    assert answer.status_code == 200, answer.text
    begun = answer.json()
    assert (begun["callback"], begun["callback_address"]) == (rig.origin, True)
    assert begun["redirect_uri"] == world.address
    assert "binder" not in begun
    # The binding cookie, set by the start answer and nowhere else (C.7).
    [cookie] = answer.headers.get_list("set-cookie")
    binder = world.binder()
    assert binder is not None
    assert len(binder) == 43
    assert cookie == (
        f"zoeymcp-{rig.portal_port}-cb={binder}; Path=/oauth/callback/notes; HttpOnly; "
        "SameSite=Lax; Max-Age=600"
    )
    assert binder not in answer.text
    assert stage(page, begun["flow"]) == "pending"
    # The provider's redirect, followed as one cross-site navigation, ends on the received page.
    received(world.follow(begun["authorize_url"]))
    [(url, sent)] = callback_hops(world.browser)
    assert url.startswith(world.address + "?code=fake-notes-code-")
    assert (sent["sec-fetch-site"], sent["sec-fetch-mode"], sent["sec-fetch-dest"]) == (
        "cross-site",
        "navigate",
        "document",
    )
    assert "origin" not in sent
    # The binding cookie went with it, and no session cookie: a cross-site hop sends no Strict one.
    assert sent["cookie"] == f"zoeymcp-{rig.portal_port}-cb={binder}"
    # Held, not exchanged: nothing is stored until the owner confirms with a passkey.
    assert fakes.notes.exchanges == 0
    assert store(rig).entry("notes-refresh") is None
    status = status_of(page, begun["flow"]).json()
    assert (status["stage"], status["origin"], status["failure"]) == ("returned", rig.origin, None)
    assert isinstance(status["returned_at"], int)
    assert set(status) == {"stage", "expires", "origin", "returned_at", "failure"}
    held = prepared(page, "oauth.complete", returned_data(begun["flow"]))
    labels = [label for label, _ in held["summary"]]
    assert labels == [
        "Connect",
        "With",
        "It came back to",
        "Its tokens go to",
        "Scopes asked for",
        "Scopes expected",
        "Before you confirm",
    ]
    summary = dict(held["summary"])
    assert summary["With"] == "the sign-in the provider sent back to the portal"
    assert summary["It came back to"].startswith(rig.origin + " at ")
    assert summary["It came back to"].endswith(" UTC")
    assert summary["Before you confirm"] == CHECK
    assert fakes.notes.exchanges == 0
    assertion = world.passkey.get(held["options"], page.origin).body()
    done = confirm(page, held["action"], assertion)
    assert done.status_code == 200, done.text
    assert (done.json()["slot"], done.json()["persisted"]) == ("notes-refresh", True)
    # The confirm's answer expires the binding cookie.
    assert done.headers.get_list("set-cookie") == [
        f"zoeymcp-{rig.portal_port}-cb=; Path=/oauth/callback/notes; HttpOnly; SameSite=Lax; "
        "Max-Age=0"
    ]
    assert world.binder() is None
    assert fakes.notes.exchanges == 1
    stored, _ = store(rig).get_for_oauth("notes-refresh", token_url=NOTES_ISSUER + "/token")
    assert stored.reveal() == fakes.notes.active_refresh_token()
    # The flow is spent; its status is gone, and the same answer again is not taken.
    assert status_reason(status_of(page, begun["flow"])) == (404, "flow_unknown")
    refused_in_place(world.deliver(url), 400)
    # The logs name the route's template and never the query, the state or the binder.
    assert rig.logged("oauth_callback_returned", lambda line: line["credential"] == "notes")
    [served] = rig.logged("portal_request", lambda line: line["status"] == 303)
    assert served["route"] == "/oauth/callback/{credential}"
    assert rig.logged("step_up_confirmed", lambda line: line["action"] == "oauth.complete")
    log = rig.log.getvalue()
    for value in (state_of(begun["authorize_url"]), binder, begun["flow"], "fake-notes-code-"):
        assert value not in log


def test_the_modal_text_and_the_cli_answer_say_whether_the_callback_can_be_taken(
    world: World,
) -> None:
    """A start answers callback_address for every credential; callback only for a portal flow
    whose callback address is on the session's own origin, where the binding cookie lands. A
    CLI start never sets callback (R16)."""
    page, rig = world.page, world.rig
    plain = page.fetch("POST", "/api/oauth/plain/start", json={})
    assert (plain.json()["callback"], plain.json()["callback_address"]) == (None, False)
    assert plain.headers.get_list("set-cookie") == []
    cli = on_loop(rig, rig.vault.login.start("notes"))
    assert (cli["callback"], cli["callback_address"]) == (None, True)
    assert "binder" not in cli


# --- what is refused, in place (C.7, P12) -----------------------------------------------------


def test_a_callback_no_flow_takes_is_refused_in_place(world: World) -> None:
    """design.md §8.2's callback test: a reused, expired or foreign state, one for another
    credential's address, and one of a credential whose redirect_uri isn't a callback address:
    one answer for all, no flow touched."""
    rig, page = world.rig, world.page
    begun = started(page)
    flow, state = begun["flow"], state_of(begun["authorize_url"])
    good = world.answer(begun["authorize_url"])
    for url in (
        f"{world.address}?code=x&state=unknown-state",  # no such flow
        f"{world.address}?code=x",  # no state
        f"{world.address}?code=x&state=%C3%A9",  # not URL-safe ASCII
        f"{world.address}?code=x&state=" + "a" * 129,
        good.replace("/oauth/callback/notes", "/oauth/callback/mail"),  # another's address
        good.replace("/oauth/callback/notes", "/oauth/callback/plain"),  # paste only
    ):
        refused_in_place(world.deliver(url), 400)
    assert stage(page, flow) == "pending"
    # Expired.
    flows = rig.vault.login._flows
    real = flows._clock
    flows._clock = lambda: time.monotonic() + FLOW_TTL
    refused_in_place(world.deliver(good, initiator=NOTES_ISSUER), 400)
    flows._clock = real
    assert stage(page, flow) == "pending"
    # A foreign one: another session's flow, delivered through this browser.
    other = world.browser_too()
    other_page = other.page(rig.origin)
    set_up(rig, other_page, SoftAuthenticator(), name="phone")
    theirs = started(other_page)
    refused_in_place(world.deliver(world.answer(theirs["authorize_url"])), 400)
    assert stage(other_page, theirs["flow"]) == "pending"
    lines = rig.logged("oauth_callback_refused", lambda line: True)
    assert {(line["reason"], line["count"]) for line in lines} == {("callback_not_taken", 1)}
    assert state not in rig.log.getvalue()
    # At most once per 10 s per reason, with a count: three more at once log nothing, and the
    # next one after 10 s counts them.
    for _ in range(3):
        refused_in_place(world.browser.navigate(f"{world.address}?state=x", initiator=EVIL), 400)
    assert len(rig.lines("oauth_callback_refused")) == len(lines)
    refused_in_place(world.deliver(f"{world.address}?state=x"), 400)
    assert rig.logged("oauth_callback_refused", lambda line: line["count"] == 4)


def test_a_leaked_state_from_another_browser_touches_nothing(world: World) -> None:
    """RFC 9700 §4.7.1: a code bound to the vault's challenge with the live state, delivered
    from a browser without the binding cookie, isn't taken; the operator's own redirect then
    is."""
    begun = started(world.page)
    leaked = world.answer(begun["authorize_url"])
    second = world.browser_too()
    refused_in_place(world.deliver(leaked, second), 400)
    assert stage(world.page, begun["flow"]) == "pending"
    received(world.follow(begun["authorize_url"]))
    assert stage(world.page, begun["flow"]) == "returned"
    assert world.fakes.notes.exchanges == 0


def test_only_a_top_level_navigation_reaches_a_flow(world: World) -> None:
    """c1, c2: a fetch, a frame, an embed or an image aimed at the callback with a live state
    is 403 not_navigation and a POST form 404; a GET form at top level is a navigation, decided
    at the flow (an unknown state: not taken). The flow stays pending in each case."""
    rig, page = world.rig, world.page
    begun = started(page)
    good = world.answer(begun["authorize_url"])
    evil = world.browser.page(EVIL)
    for response in (
        evil.fetch("GET", good, session=False, mode="cors"),
        evil.fetch("GET", good, session=False, mode="no-cors"),
        evil.load(good, "iframe"),
        evil.load(good, "embed"),
        evil.load(good, "image"),
    ):
        world.clock.advance(30)
        refused_in_place(response, 403)
    world.clock.advance(30)
    posted = evil.form_post(world.address, dict(parse_qsl(urlsplit(good).query)))
    assert status_reason(posted) == (404, "not_found")
    world.clock.advance(30)
    refused_in_place(evil.link(f"{world.address}?code=x&state=unknown-state"), 400)
    assert stage(page, begun["flow"]) == "pending"
    reasons = {line["reason"] for line in rig.logged("oauth_callback_refused", lambda _: True)}
    assert reasons == {"not_navigation", "callback_not_taken"}


def test_the_callbacks_own_admission_rows(world: World) -> None:
    """c1, c2 and c4 for a non-browser, with the binding cookie and a live state: each header
    missing, doubled or wrong; an Origin; a body; a query over 4 KiB or not ASCII. None reaches
    the flow."""
    begun = started(world.page)
    good = world.answer(begun["authorize_url"])
    binder = world.binder()
    host = ("Host", f"localhost:{world.rig.portal_port}")
    cookie = ("Cookie", f"zoeymcp-{world.rig.portal_port}-cb={binder}")
    navigation = [
        ("Sec-Fetch-Site", "cross-site"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Dest", "document"),
    ]

    def sent(
        *,
        drop: str = "",
        extra: tuple[tuple[str, str], ...] = (),
        url: str = good,
        content: bytes | None = None,
    ) -> Any:
        world.clock.advance(30)
        headers = [h for h in navigation if h[0] != drop] + [host, cookie, *extra]
        return world.browser.forge("GET", url, headers, content)

    for name in ("Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest"):
        refused_in_place(sent(drop=name), 403)
    for name, value in navigation:
        refused_in_place(sent(extra=((name, value),)), 403)  # doubled
    refused_in_place(sent(drop="Sec-Fetch-Site", extra=(("Sec-Fetch-Site", "same-origin"),)), 403)
    refused_in_place(sent(drop="Sec-Fetch-Mode", extra=(("Sec-Fetch-Mode", "cors"),)), 403)
    refused_in_place(sent(extra=(("Origin", world.rig.origin),)), 403)
    refused_in_place(sent(extra=(("Origin", "null"),)), 403)
    refused_in_place(sent(content=b"{}"), 403)  # a body
    refused_in_place(sent(url=good + "&pad=" + "a" * 4096), 400)  # over 4 KiB
    assert stage(world.page, begun["flow"]) == "pending"
    # The same request as a navigation sends: taken. Content-Length 0 is no body.
    world.clock.advance(30)
    taken = world.browser.forge("GET", good, [*navigation, host, cookie, ("Content-Length", "0")])
    assert (taken.status_code, taken.headers["location"]) == (303, "/callback/received")
    assert taken.content == b""
    assert_portal_headers(taken)
    assert stage(world.page, begun["flow"]) == "returned"


def test_a_query_at_four_kib_is_read(world: World) -> None:
    begun = started(world.page)
    good = world.answer(begun["authorize_url"])
    pad = "&pad=" + "a" * (4096 - len(urlsplit(good).query) - len("&pad="))
    assert len(urlsplit(good + pad).query) == 4096
    received(world.deliver(good + pad, initiator=NOTES_ISSUER))


def test_a_typed_callback_address_is_a_navigation_too(world: World) -> None:
    """Typing or pasting the address gives Sec-Fetch-Site: none (manual item 14): admitted,
    and decided at the flow."""
    begun = started(world.page)
    received(world.deliver(world.answer(begun["authorize_url"]), initiator=None))
    assert world.browser.history[-2][2]["sec-fetch-site"] == "none"


def test_the_bucket_answers_the_callback_429_in_place(world: World) -> None:
    begun = started(world.page)
    good = world.answer(begun["authorize_url"])
    world.clock.advance(30)
    answers = [world.browser.navigate(good + "&x=1", initiator=EVIL) for _ in range(12)]
    assert answers[-1].status_code == 429
    refused_in_place(answers[-1], 429)
    assert answers[-1].headers["retry-after"] == "2"
    assert world.rig.logged("portal_refused", lambda line: line["reason"] == "rate_limited")


def test_a_loopback_literal_and_the_default_address_reach_no_callback(world: World) -> None:
    """A.5: 127.0.0.1 on the portal's port is 421 (row 1), and the portless default never
    reaches the vault at all."""
    begun = started(world.page)
    good = world.answer(begun["authorize_url"])
    literal = good.replace("localhost", "127.0.0.1")
    world.clock.advance(30)
    answer = world.browser.navigate(literal, initiator=NOTES_ISSUER)
    assert status_reason(answer) == (421, "wrong_host")
    assert stage(world.page, begun["flow"]) == "pending"
    assert not REDIRECT.startswith(world.rig.origin)


# --- the conflict rule (H.6) ------------------------------------------------------------------


def test_an_attackers_code_first_then_the_operators_answer_fails_the_flow(world: World) -> None:
    """R1: with a leaked authorization URL an attacker consents with their own account and
    makes the operator's browser deliver that code first; the flow holds it, and the operator's
    own answer then differs from it, so the flow fails and nothing is ever exchanged."""
    page, fakes = world.page, world.fakes
    begun = started(page)
    attackers = world.answer(begun["authorize_url"])
    received(world.deliver(attackers))  # through the operator's own browser, with its cookie
    assert stage(page, begun["flow"]) == "returned"
    received(world.follow(begun["authorize_url"]))  # the operator's own approval
    failure = status_of(page, begun["flow"]).json()["failure"]
    assert failure == {
        "reason": "conflict",
        "error_shown": None,
        "text_shown": CONFLICT,
        "description_shown": None,
    }
    refused = prepare(page, "oauth.complete", returned_data(begun["flow"]))
    assert status_reason(refused) == (404, "flow_unknown")
    assert fakes.notes.exchanges == 0
    assert world.rig.logged("oauth_callback_failed", lambda line: line["reason"] == "conflict")


def test_the_operators_paste_after_an_attackers_callback_fails_the_flow(world: World) -> None:
    page, fakes = world.page, world.fakes
    begun = started(page)
    received(world.deliver(world.answer(begun["authorize_url"])))
    own = world.answer(begun["authorize_url"])
    refused = prepare(page, "oauth.complete", complete_data(begun["flow"], own))
    assert refused.status_code == 409
    assert refused.json() == {"error": CONFLICT, "reason": "flow_conflict"}
    assert status_of(page, begun["flow"]).json()["failure"]["reason"] == "conflict"
    assert fakes.notes.exchanges == 0


def test_the_same_answer_twice_changes_nothing(world: World) -> None:
    """A replay of the code-bearing address (the browser's history, say) is not taken; the held
    code stays, and the paste of it is told to confirm the returned one."""
    page = world.page
    begun = started(page)
    received(world.follow(begun["authorize_url"]))
    [(url, _)] = callback_hops(world.browser)
    refused_in_place(world.deliver(url), 400)
    assert stage(page, begun["flow"]) == "returned"
    same = prepare(page, "oauth.complete", complete_data(begun["flow"], url))
    assert same.status_code == 409
    assert same.json()["reason"] == "flow_returned"
    assert stage(page, begun["flow"]) == "returned"
    # A paste that isn't this flow's answer is refused as for a pending flow, and changes
    # nothing.
    other = url.replace(state_of(url), "another-login")
    assert status_reason(prepare(page, "oauth.complete", complete_data(begun["flow"], other))) == (
        400,
        "state_mismatch",
    )
    twice = url + "&code=again"
    assert status_reason(prepare(page, "oauth.complete", complete_data(begun["flow"], twice))) == (
        400,
        "duplicate_param",
    )
    assert stage(page, begun["flow"]) == "returned"
    done = confirm_returned(world, begun["flow"])
    assert done.status_code == 200, done.text


def confirm_returned(world: World, flow: str) -> httpx.Response:
    held = prepared(world.page, "oauth.complete", returned_data(flow))
    assertion = world.passkey.get(held["options"], world.page.origin).body()
    return confirm(world.page, held["action"], assertion)


def test_a_paste_planned_then_the_callback_exchanges_nothing_unseen(world: World) -> None:
    """The paste's confirm plans again against the returned flow: the same code answers
    flow_returned, and the returned confirmation follows; nothing was exchanged meanwhile."""
    page, fakes = world.page, world.fakes
    begun = started(page)
    pasted = world.answer(begun["authorize_url"])
    held = prepared(page, "oauth.complete", complete_data(begun["flow"], pasted))
    received(world.deliver(pasted, initiator=NOTES_ISSUER))  # the same answer, by callback
    assertion = world.passkey.get(held["options"], page.origin).body()
    answer = confirm(page, held["action"], assertion)
    assert status_reason(answer) == (409, "flow_returned")
    assert fakes.notes.exchanges == 0
    assert confirm_returned(world, begun["flow"]).status_code == 200
    assert fakes.notes.exchanges == 1


def test_a_different_callback_after_a_planned_paste_fails_the_flow(world: World) -> None:
    page, fakes = world.page, world.fakes
    begun = started(page)
    pasted = world.answer(begun["authorize_url"])
    held = prepared(page, "oauth.complete", complete_data(begun["flow"], pasted))
    received(world.follow(begun["authorize_url"]))  # another code
    assertion = world.passkey.get(held["options"], page.origin).body()
    answer = confirm(page, held["action"], assertion)
    assert status_reason(answer) == (409, "flow_conflict")
    assert fakes.notes.exchanges == 0
    assert status_of(page, begun["flow"]).json()["failure"]["reason"] == "conflict"


def test_a_paste_confirmed_first_leaves_the_callback_nothing(world: World) -> None:
    page = world.page
    begun = started(page)
    pasted = world.answer(begun["authorize_url"])
    held = prepared(page, "oauth.complete", complete_data(begun["flow"], pasted))
    assertion = world.passkey.get(held["options"], page.origin).body()
    assert confirm(page, held["action"], assertion).status_code == 200
    refused_in_place(world.deliver(world.answer(begun["authorize_url"])), 400)


# --- a provider's refusal, shown to the owner only (H.6, P14) ---------------------------------


@pytest.mark.parametrize(
    ("answer", "reason", "text", "error"),
    [
        ("error", "provider_error", "The answer said the provider refused: access_denied", True),
        (
            "wrong_iss",
            "iss_mismatch",
            "The answer came from a different issuer; nothing was stored. Connect again.",
            False,
        ),
        ("no_code", "no_code", "The provider's answer had no usable code. Connect again.", False),
    ],
)
def test_a_failed_callback_ends_the_flow_and_tells_its_owner(
    world: World, answer: Any, reason: str, text: str, error: bool
) -> None:
    rig, page = world.rig, world.page
    world.fakes.notes.answer = answer
    world.fakes.notes.error_description = "<b>No</b> thanks"
    begun = started(page)
    received(world.follow(begun["authorize_url"]))
    failure = status_of(page, begun["flow"]).json()["failure"]
    assert (failure["reason"], failure["text_shown"]) == (reason, text)
    assert failure["error_shown"] == ("access_denied" if error else None)
    assert failure["description_shown"] == ("<b>No</b> thanks" if error else None)
    # Another session's poll learns nothing; the flow can't be confirmed.
    other = world.browser_too().page(rig.origin)
    set_up(rig, other, SoftAuthenticator(), name="phone")
    assert status_reason(status_of(other, begun["flow"])) == (404, "flow_unknown")
    refused = prepare(page, "oauth.complete", returned_data(begun["flow"]))
    assert status_reason(refused) == (404, "flow_unknown")
    [failed] = rig.logged("oauth_callback_failed", lambda line: line["reason"] == reason)
    assert failed["error"] == ("access_denied" if error else None)
    assert "thanks" not in rig.log.getvalue()
    assert world.fakes.notes.exchanges == 0


def test_a_hostile_description_is_dropped_and_its_markup_stays_text(world: World) -> None:
    world.fakes.notes.answer = "error"
    world.fakes.notes.error_description = HOSTILE
    begun = started(world.page)
    received(world.follow(begun["authorize_url"]))
    failure = status_of(world.page, begun["flow"]).json()["failure"]
    assert failure["description_shown"] is None  # hidden characters: the vault drops it (M2)


def test_an_answer_in_the_fragment_or_with_two_codes_is_refused_in_place(world: World) -> None:
    page = world.page
    world.fakes.notes.answer = "fragment"
    begun = started(page)
    refused_in_place(world.follow(begun["authorize_url"]), 400)  # the query never arrives
    world.fakes.notes.answer = "two_codes"
    refused_in_place(world.follow(begun["authorize_url"]), 400)
    assert world.rig.logged(
        "oauth_callback_refused", lambda line: line["reason"] == "duplicate_param"
    )
    assert stage(page, begun["flow"]) == "pending"


# --- flows are owned (P11) --------------------------------------------------------------------


def test_a_cli_flow_never_takes_a_callback(world: World) -> None:
    rig = world.rig
    cli = on_loop(rig, rig.vault.login.start("notes"))
    url = world.answer(cli["authorize_url"])
    refused_in_place(world.deliver(url, initiator=NOTES_ISSUER), 400)
    # The CLI's paste of that very address completes.
    done = on_loop(rig, rig.vault.login.complete("notes", cli["flow"], url))
    assert done["persisted"] is True


def test_one_session_cant_confirm_or_read_anothers_returned_flow(world: World) -> None:
    rig, page = world.rig, world.page
    begun = started(page)
    received(world.follow(begun["authorize_url"]))
    other = world.browser_too().page(rig.origin)
    set_up(rig, other, SoftAuthenticator(), name="phone")
    refused = prepare(other, "oauth.complete", returned_data(begun["flow"]))
    assert status_reason(refused) == (404, "flow_unknown")
    assert status_reason(status_of(other, begun["flow"])) == (404, "flow_unknown")
    assert stage(page, begun["flow"]) == "returned"


def test_a_session_that_ends_takes_its_held_code(world: World) -> None:
    page = world.page
    begun = started(page)
    received(world.follow(begun["authorize_url"]))
    assert page.fetch("POST", "/api/logout", json={}).status_code == 200
    assert len(world.rig.vault.login._flows) == 0
    refused_in_place(world.deliver(world.answer(begun["authorize_url"])), 400)


def test_cancel_drops_a_returned_flow_and_expires_the_cookie(world: World) -> None:
    page, rig = world.page, world.rig
    begun = started(page)
    received(world.follow(begun["authorize_url"]))
    cancelled = page.fetch("DELETE", f"/api/oauth/flows/{begun['flow']}")
    assert cancelled.json() == {"cancelled": True}
    assert cancelled.headers.get_list("set-cookie") == [
        f"zoeymcp-{rig.portal_port}-cb=; Path=/oauth/callback/notes; HttpOnly; SameSite=Lax; "
        "Max-Age=0"
    ]
    assert world.binder() is None
    # A paste-only login's cancel sets no cookie.
    plain = started(page, "plain")
    assert (
        page.fetch("DELETE", f"/api/oauth/flows/{plain['flow']}").headers.get_list("set-cookie")
        == []
    )


def test_a_reload_that_moves_the_address_ends_the_callback_not_the_paste(world: World) -> None:
    """A.5's reload rule: checked again at the callback against the policy then in force."""
    rig, page = world.rig, world.page
    begun = started(page)
    url = world.answer(begun["authorize_url"])
    document = {
        **callback_policy(rig.origin),
        "admin": {"listen": f"127.0.0.1:{rig.portal_port}", "origins": [rig.origin]},
        "version": 1,
        "mode": "declarative",
    }
    document["credentials"]["notes"]["redirect_uri"] = REDIRECT
    rig.reload(document)
    refused_in_place(world.deliver(url, initiator=NOTES_ISSUER), 400)
    assert stage(page, begun["flow"]) == "pending"
    held = prepared(page, "oauth.complete", complete_data(begun["flow"], url))
    assertion = world.passkey.get(held["options"], page.origin).body()
    assert confirm(page, held["action"], assertion).status_code == 200


# --- on an https origin (C.7's cookie) --------------------------------------------------------


def test_an_https_origin_sets_a_secure_binding_cookie(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """__Secure- and Secure on https (not __Host-, which needs Path=/), and a session on
    another listed origin gets no callback: the cookie would never reach the callback's
    origin."""
    tailnet = "https://zoeymcp.tailnet.example"
    fakes = providers()
    monkeypatch.setattr(
        netclient,
        "token_client",
        lambda *_: httpx.AsyncClient(transport=httpx.ASGITransport(app=fakes.app())),
    )
    document = policy()
    document["credentials"]["notes"]["redirect_uri"] = f"{tailnet}/oauth/callback/notes"
    with running(tmp_path, policy=document, extra_origins=[tailnet]) as rig:
        fakes.notes.registered_redirect = f"{tailnet}/oauth/callback/notes"
        browser = rig.browser(every_name=True)
        page = browser.page(tailnet)
        set_up(rig, page, SoftAuthenticator())
        answer = page.fetch("POST", "/api/oauth/notes/start", json={})
        assert answer.json()["callback"] == tailnet
        [cookie] = answer.headers.get_list("set-cookie")
        binder = cookie.split(";")[0].split("=", 1)[1]
        assert cookie == (
            f"__Secure-zoeymcp-cb={binder}; Path=/oauth/callback/notes; Secure; HttpOnly; "
            "SameSite=Lax; Max-Age=600"
        )
        local = rig.browser().page(rig.origin)
        set_up(rig, local, SoftAuthenticator(), name="phone")
        elsewhere = local.fetch("POST", "/api/oauth/notes/start", json={})
        assert (elsewhere.json()["callback"], elsewhere.json()["callback_address"]) == (None, True)
        assert elsewhere.headers.get_list("set-cookie") == []
        # The https flow was replaced; a navigation with its old answer isn't taken.
        old = state_of(answer.json()["authorize_url"])
        url = f"{tailnet}/oauth/callback/notes?code=x&state={old}"
        refused_in_place(browser.navigate(url, initiator=NOTES_ISSUER), 400)


# --- every other GET changes nothing (F.4) ----------------------------------------------------


def test_every_other_get_leaves_a_returned_flow_as_it_is(world: World) -> None:
    """The callback is the one GET with an effect: with a flow returned (its code held), every
    other GET, its own status poll included, and every static file leave the flow table, the
    sessions and the actions as they were."""
    rig, page = world.rig, world.page
    begun = started(page)
    received(world.follow(begun["authorize_url"]))
    flows = rig.vault.login._flows._flows

    def tables() -> object:
        app = rig.app
        live = app.sessions.live(world.clock.wall())
        held = [(f.id, f.stage, f.returned is not None, f.expires_at) for f in flows.values()]
        return sorted(s.id for s in live), len(app.actions), len(app.ceremonies), held

    before = tables()
    for route in ROUTES:
        if route.method == "GET":
            path = filled(route).replace("0123456789abcdef", begun["flow"])
            page.fetch("GET", path)
    for path in STATIC:
        page.fetch("GET", path)
        world.browser.navigate(rig.origin + path, initiator=EVIL)
    assert tables() == before
    assert stage(page, begun["flow"]) == "returned"
