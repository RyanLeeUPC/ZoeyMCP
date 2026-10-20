"""Sessions: listing, ending, logout and expiry, over the real API (M5 design F.2, P7, M.3).

A session ends at logout, at either limit, by end-others, when the passkey that made it is
removed, at a reset enrolment, and when its origin is dropped; each ending drops the session's
ceremony and action and cancels its OAuth flows (H.2). A cookie alone is never a session: a
neighbour on another localhost port receives it, and gets 401 everywhere.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

import pytest

from tests.fakes.authenticator import SoftAuthenticator, Switch
from tests.fakes.browser import SESSION_KEY, Cookie, Page, head
from zoeymcp.portal.app import PortalApp, load_static
from zoeymcp.portal.routes import ROUTES
from zoeymcp.portal.sessions import SESSION_IDLE, SESSION_MAX
from zoeymcp.vault.oauth.login import LoginService

from .flows import begin_enrol, filled, issue, login, redeem, set_up, status_reason
from .rig import Clock, PortalRig, running


@pytest.fixture
def rig(tmp_path: Path) -> Iterator[PortalRig]:
    with running(tmp_path) as portal:
        yield portal


def cookie_name(rig: PortalRig) -> str:
    return f"zoeymcp-{rig.portal_port}-session"


def test_the_session_list(rig: PortalRig) -> None:
    authenticator = SoftAuthenticator()
    first = rig.browser().page(rig.origin)
    passkey = set_up(rig, first, authenticator)
    second = rig.browser().page(rig.origin)
    assert login(second, authenticator).status_code == 200
    answer = first.fetch("GET", "/api/sessions")
    assert answer.status_code == 200
    listed = answer.json()["sessions"]
    assert [s["this"] for s in listed] == [True, False]
    assert {tuple(sorted(s)) for s in listed} == {
        (
            "created",
            "credential",
            "expires_at",
            "fingerprint",
            "last_seen",
            "origin",
            "scope",
            "this",
        )
    }
    assert {(s["origin"], s["scope"], s["credential"]) for s in listed} == {
        (rig.origin, "full", passkey["fingerprint"])
    }
    for session in rig.app.sessions.live(time.time()):
        assert session.id not in answer.text
    assert first.storage[SESSION_KEY] not in answer.text
    assert second.storage[SESSION_KEY] not in answer.text
    # The socket's list is the same, without "this" (zoeymcp sessions).
    socket = rig.call(rig.app.session_list)
    assert [s["fingerprint"] for s in socket] == [s["fingerprint"] for s in listed]
    assert all("this" not in s for s in socket)


def test_end_others_needs_no_step_up_and_keeps_this_one(rig: PortalRig) -> None:
    authenticator = SoftAuthenticator()
    first = rig.browser().page(rig.origin)
    set_up(rig, first, authenticator)
    others = [rig.browser().page(rig.origin) for _ in range(2)]
    for page in others:
        assert login(page, authenticator).status_code == 200
    ended = first.fetch("POST", "/api/sessions/end-others", json={})
    assert ended.json() == {"ended": 2}
    for page in others:
        assert status_reason(page.fetch("GET", "/api/session")) == (401, "no_session")
    assert first.fetch("GET", "/api/session").status_code == 200
    whys = [line["why"] for line in rig.lines("portal_session_ended")]
    assert whys[-2:] == ["end_others", "end_others"]


def test_logout(rig: PortalRig) -> None:
    browser = rig.browser()
    page = browser.page(rig.origin)
    set_up(rig, page, SoftAuthenticator())
    token = page.storage[SESSION_KEY]
    answer = page.fetch("POST", "/api/logout", json={})
    assert answer.status_code == 200
    assert answer.json() == {}
    # The storage directive only: "cookies" would clear every localhost port's (F.2).
    assert answer.headers.get_list("clear-site-data") == ['"storage"']
    assert answer.headers.get_list("set-cookie") == [
        f"{cookie_name(rig)}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"
    ]
    assert browser.cookies == []  # the browser dropped it
    [line] = rig.lines("portal_logout")
    assert line["why"] == "logout"
    page.storage[SESSION_KEY] = token
    assert status_reason(page.fetch("GET", "/api/session")) == (401, "no_session")
    assert len(rig.app.sessions) == 0


def test_two_logouts_at_once_end_the_session_once(rig: PortalRig) -> None:
    """The first logout has passed the lookup and waits for its body when the second ends the
    session: only the request that ended it answers 200 and logs it; the other finds it gone and
    answers as a later one would, 401 no_session."""
    browser = rig.browser()
    page = browser.page(rig.origin)
    set_up(rig, page, SoftAuthenticator())
    [cookie] = [c for c in browser.cookies if c.name == cookie_name(rig)]
    request = head(
        "POST /api/logout HTTP/1.1",
        f"Host: localhost:{rig.portal_port}",
        "Sec-Fetch-Site: same-origin",
        f"Origin: {rig.origin}",
        f"Cookie: {cookie.name}={cookie.value}",
        f"X-ZoeyMCP-Session: {page.storage[SESSION_KEY]}",
        "Content-Type: application/json",
        "Content-Length: 2",
        "Connection: close",
    )
    with rig.slowloris() as raw:
        first = raw.connect()
        first.sendall(request)  # the head alone: admitted, then waiting for the body
        deadline = time.monotonic() + 10
        while rig.call(lambda: rig.app.in_flight) != (1, 0):
            assert time.monotonic() < deadline
            time.sleep(0.01)
        second = page.fetch("POST", "/api/logout", json={})
        first.sendall(b"{}")
        answer = raw.answer(first)
    assert len(rig.lines("portal_logout")) == 1
    assert second.status_code == 200
    assert answer.startswith(b"HTTP/1.1 401 "), answer
    assert b'"reason":"no_session"' in answer
    assert len(rig.app.sessions) == 0


def test_a_setup_session_can_log_out(rig: PortalRig) -> None:
    page = rig.browser().page(rig.origin)
    assert redeem(page, issue(rig)).status_code == 200
    begin_enrol(page)
    assert len(rig.app.ceremonies) == 1
    assert page.fetch("POST", "/api/logout", json={}).status_code == 200
    assert len(rig.app.ceremonies) == 0  # its enrolment ceremony went with it


def test_the_idle_and_absolute_limits(tmp_path: Path) -> None:
    clock = Clock()
    with running(tmp_path, clock=clock) as rig:
        authenticator = SoftAuthenticator()
        page = rig.browser().page(rig.origin)
        set_up(rig, page, authenticator)
        # Use keeps a session alive, up to its absolute limit.
        step = SESSION_IDLE - 60
        used = 0.0
        while used + step < SESSION_MAX:
            clock.advance(step)
            used += step
            assert page.fetch("GET", "/api/session").status_code == 200
        clock.advance(SESSION_MAX - used)
        assert status_reason(page.fetch("GET", "/api/session")) == (401, "no_session")
        assert rig.lines("portal_session_ended")[-1]["why"] == "max"
        # Unused, it ends after 15 idle minutes.
        clock.advance(60)
        assert login(page, authenticator).status_code == 200
        clock.advance(SESSION_IDLE)
        assert status_reason(page.fetch("GET", "/api/sessions")) == (401, "no_session")
        assert rig.lines("portal_session_ended")[-1]["why"] == "idle"


def test_a_cookie_alone_is_no_session_anywhere(rig: PortalRig) -> None:
    """P7: a neighbour on another localhost port receives the cookie (cookies ignore ports) and
    has no header half; every route answers 401, GETs included, and no idle clock moves."""
    browser = rig.browser()
    page = browser.page(rig.origin)
    set_up(rig, page, SoftAuthenticator())
    [cookie] = [c for c in browser.cookies if c.name == cookie_name(rig)]
    [before] = [s.last_seen for s in rig.app.sessions.live(time.time())]
    neighbour = rig.browser()
    for route in ROUTES:
        if route.unauthenticated:
            continue
        headers = [
            ("Sec-Fetch-Site", "same-origin"),
            ("Origin", rig.origin),
            ("Cookie", f"{cookie.name}={cookie.value}"),
        ]
        body = None
        if route.cap:
            headers.append(("Content-Type", "application/json"))
            body = b"{}"
        answer = neighbour.forge(route.method, rig.origin + filled(route), headers, body)
        assert status_reason(answer) == (401, "no_session"), route.path
    assert [s.last_seen for s in rig.app.sessions.live(time.time())] == [before]
    # Its own page's fetch is same-site, refused before any lookup.
    other = neighbour.page(f"http://localhost:{rig.portal_port + 1}")
    answer = other.fetch("GET", rig.origin + "/api/session")
    assert status_reason(answer) == (403, "cross_site")


def test_a_planted_cookie_doesnt_sign_the_operator_out(rig: PortalRig) -> None:
    """A neighbour plants a cookie of our name at a longer path, with a long lifetime: the
    browser sends it first, the lookup tries it and ours, and only ours pairs (V24)."""
    browser = rig.browser()
    page = browser.page(rig.origin)
    set_up(rig, page, SoftAuthenticator())
    browser.plant(Cookie(cookie_name(rig), "planted", "localhost", "/api", False, False, "lax"))
    sent = page.fetch("GET", "/api/session")
    assert sent.status_code == 200
    assert sent.request.headers["cookie"].startswith(f"{cookie_name(rig)}=planted; ")


def test_removing_a_passkey_ends_its_sessions(rig: PortalRig) -> None:
    """The socket's DELETE /passkeys/{fp} ends the sessions that passkey's logins made."""
    first_key, second_key = SoftAuthenticator(), SoftAuthenticator()
    first = rig.browser().page(rig.origin)
    gone = set_up(rig, first, first_key)
    second = rig.browser().page(rig.origin)
    set_up(rig, second, second_key)
    assert rig.call(lambda: rig.app.end_credential(gone["fingerprint"])) == 1
    assert status_reason(first.fetch("GET", "/api/session")) == (401, "no_session")
    assert second.fetch("GET", "/api/session").status_code == 200
    assert rig.lines("portal_session_ended")[-1]["why"] == "passkey_removed"
    assert rig.call(rig.app.end_all) == 1
    assert status_reason(second.fetch("GET", "/api/session")) == (401, "no_session")
    assert rig.lines("portal_session_ended")[-1]["why"] == "end_all"


def ended_lines(rig: PortalRig) -> list[tuple[str, str]]:
    return [(line["session"], line["why"]) for line in rig.lines("portal_session_ended")]


def this_session(page: Page) -> str:
    answer = page.fetch("GET", "/api/session")
    assert answer.status_code == 200, answer.text
    fingerprint: str = answer.json()["session"]
    return fingerprint


def test_one_signed_in_tab_per_browser(rig: PortalRig) -> None:
    """Each tab keeps its own header half, but the browser holds one cookie: a sign-in in a second
    tab replaces it, so the first tab's session ends at once (why: replaced), with its action,
    rather than idling out unusable. Signing in there again ends the second's in turn."""
    authenticator = SoftAuthenticator()
    browser = rig.browser()
    tab_a, tab_b = browser.tab(rig.origin), browser.tab(rig.origin)
    set_up(rig, tab_a, authenticator)
    # The setup session ended with its enrolment, so its cookie replaced nothing at the login.
    assert [why for _, why in ended_lines(rig)] == ["enrolled"]
    first = this_session(tab_a)
    held = tab_a.fetch(
        "POST", "/api/actions", json={"kind": "passkey.enrol", "data": {"name": "x"}}
    )
    assert held.status_code == 200, held.text
    assert len(rig.app.actions) == 1

    assert login(tab_b, authenticator).status_code == 200
    assert tab_a.storage[SESSION_KEY] != tab_b.storage[SESSION_KEY]
    assert ended_lines(rig)[-1] == (first, "replaced")
    assert len(rig.app.actions) == 0  # its action went with it
    assert status_reason(tab_a.fetch("GET", "/api/session")) == (401, "no_session")
    second = this_session(tab_b)
    listed = tab_b.fetch("GET", "/api/sessions").json()["sessions"]
    assert [(s["fingerprint"], s["this"]) for s in listed] == [(second, True)]

    assert login(tab_a, authenticator).status_code == 200
    assert ended_lines(rig)[-1] == (second, "replaced")
    assert status_reason(tab_b.fetch("GET", "/api/session")) == (401, "no_session")
    listed = tab_a.fetch("GET", "/api/sessions").json()["sessions"]
    assert [(s["fingerprint"], s["this"]) for s in listed] == [(this_session(tab_a), True)]
    assert [why for _, why in ended_lines(rig)] == ["enrolled", "replaced", "replaced"]


def test_a_redeemed_code_replaces_the_browsers_full_session(rig: PortalRig) -> None:
    authenticator = SoftAuthenticator()
    elsewhere = rig.browser().page(rig.origin)
    set_up(rig, elsewhere, authenticator)
    browser = rig.browser()
    tab_a, tab_b = browser.tab(rig.origin), browser.tab(rig.origin)
    assert login(tab_a, authenticator).status_code == 200
    full = this_session(tab_a)
    # A refused code and a refused assertion mint nothing, so they end nothing.
    assert status_reason(redeem(tab_b, "wrong")) == (401, "setup_code_refused")
    assert login(tab_b, authenticator, switches={Switch.FLIP_SIGNATURE}).status_code == 401
    assert this_session(tab_a) == full
    assert redeem(tab_b, issue(rig)).status_code == 200
    assert ended_lines(rig)[-1] == (full, "replaced")
    assert status_reason(tab_a.fetch("GET", "/api/session")) == (401, "no_session")
    assert tab_b.fetch("GET", "/api/session").json()["scope"] == "setup"
    # The other browser's session is not this browser's to end.
    assert elsewhere.fetch("GET", "/api/session").status_code == 200
    assert len(rig.app.sessions) == 2


def test_a_cookie_of_no_live_session_ends_nothing(rig: PortalRig) -> None:
    authenticator = SoftAuthenticator()
    elsewhere = rig.browser().page(rig.origin)
    set_up(rig, elsewhere, authenticator)
    browser = rig.browser()
    page = browser.page(rig.origin)
    assert login(page, authenticator).status_code == 200
    assert elsewhere.fetch("POST", "/api/sessions/end-others", json={}).json() == {"ended": 1}
    # The browser still holds the ended session's cookie, and a planted one besides.
    browser.plant(Cookie(cookie_name(rig), "planted", "localhost", "/api", False, False, "lax"))
    assert len([c for c in browser.cookies if c.name == cookie_name(rig)]) == 2
    before = ended_lines(rig)
    assert login(page, authenticator).status_code == 200
    assert ended_lines(rig) == before
    assert elsewhere.fetch("GET", "/api/session").status_code == 200
    assert page.fetch("GET", "/api/session").status_code == 200
    assert len(rig.app.sessions) == 2


class FlowsSeen:
    """The part of ``LoginService`` an ending session uses: whose flows were cancelled."""

    def __init__(self) -> None:
        self.cancelled: list[str] = []

    def cancel_owner(self, owner: str) -> int:
        self.cancelled.append(owner)
        return 0


def test_every_ending_drops_the_sessions_ceremony_action_and_flows() -> None:
    """H.2: whatever ends a session ends what it started."""
    flows = FlowsSeen()
    app = PortalApp(
        ["http://localhost:8081", "http://localhost:9000"],
        static=load_static(),
        login=cast(LoginService, flows),
    )
    now = time.time()

    def started(origin: str = "http://localhost:8081") -> Any:
        session = app.sessions.mint(origin=origin, rp_id="localhost", scope="full", now=now)
        app.ceremonies.begin_enrol(origin=origin, session=session.session.id, name="n", now=now)
        app.actions.prepare(
            kind="ledger.restart",
            data={},
            plan=None,
            session=session.session.id,
            origin=origin,
            now=now,
        )
        return session.session

    sessions = [started(), started(), started("http://localhost:9000")]
    app.end_credential("nothing")
    assert flows.cancelled == []
    app.reload(["http://localhost:8081"])
    assert flows.cancelled == [sessions[2].owner]
    assert app.end_all() == 2
    assert flows.cancelled == [s.owner for s in (sessions[2], sessions[0], sessions[1])]
    assert (len(app.ceremonies), len(app.actions), len(app.sessions)) == (0, 0, 0)
