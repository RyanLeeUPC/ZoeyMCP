"""Enrolment, sessions, Fetch Metadata, the IP-literal redirect, a passkey's host name, a neighbour
port, Trusted Types and a second port, in a real browser: manual items 1 and 3 (the lines a
browser can run), 4, 6, 7 (its second origin through an in-process TLS front), 10, 11 and 12
(M8 design steps 27a and 27c; D-222).

The harness's own proof: each test drives the portal's real page with the browser's own
WebAuthn stack (a CDP virtual authenticator) against the real vault and portal on loopback
(``tests.portal.rig``), and its context's watch must stay clean (no Content Security Policy or
Trusted Types violation, page error, dialog, request off loopback, or console error the test
didn't allow). Each test's docstring names its item and the pass lines it checks;
``docs/manual-checks.md`` keeps the lines left by hand.
"""

from __future__ import annotations

import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
import pytest
from playwright.sync_api import BrowserContext, Error, Page, expect

from tests.portal.flows import ENROL_FINISH
from zoeymcp.portal.sessions import SESSION_IDLE

from .engines import FRONT
from .layout import assert_no_horizontal_overflow
from .passkeys import CdpAuthenticator
from .portal import (
    NOT_ALLOWED,
    asks_to_sign_in,
    open_portal,
    open_section,
    press,
    session_cookie,
    set_up,
    sign_in,
    sign_out,
    signed_in,
)
from .stacks import Clock, Forwarder, Neighbour, PortalRig, portal
from .watch import Watch

# A refused request's answer, which the browser itself reports on the console.
REFUSED_401 = r"status of 401"
# Item 10's page, word for word but for the portal's address.
NEIGHBOUR = """<!doctype html>
<script>
fetch("{origin}/api/session", {{credentials: "include"}})
  .then((r) => r.text()).then(console.log, console.error);
fetch("{origin}/api/logout", {{method: "POST", credentials: "include",
  mode: "no-cors", headers: {{"Content-Type": "text/plain"}}, body: "{{}}"}});
</script>
"""


@pytest.fixture
def rig(tmp_path: Path) -> Iterator[PortalRig]:
    with portal(tmp_path) as running:
        yield running


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def clocked(tmp_path: Path, clock: Clock) -> Iterator[PortalRig]:
    """The rig on a clock the test moves (the idle limit)."""
    with portal(tmp_path, clock=clock) as running:
        yield running


@pytest.fixture
def front(front_tls: tuple[Path, Path]) -> Iterator[Forwarder]:
    """Item 7's TLS front, for ``https://<FRONT>:<its port>``."""
    with Forwarder(tls=front_tls) as bound:
        yield bound


@pytest.fixture
def fronted(tmp_path: Path, front: Forwarder) -> Iterator[PortalRig]:
    """The portal with a second origin over https, the TLS front's, in its origins."""
    with portal(tmp_path, extra_origins=[f"https://{FRONT}:{front.port}"]) as running:
        front.start(running.address)
        yield running


@pytest.fixture
def forwarder() -> Iterator[Forwarder]:
    with Forwarder() as bound:
        yield bound


@pytest.fixture
def two_ports(tmp_path: Path, forwarder: Forwarder) -> Iterator[PortalRig]:
    """The portal with a second ``localhost`` origin, the forwarder's port, in its origins."""
    origin = f"http://localhost:{forwarder.port}"
    with portal(tmp_path, extra_origins=[origin]) as running:
        forwarder.start(running.address)
        yield running


def full_session(
    page: Page, other: BrowserContext, rig: PortalRig
) -> tuple[CdpAuthenticator, Page]:
    """Item 11's session: set up with a code, sign in with the new passkey, a second browser
    signed in with the same passkey, then **Sessions**, **End the other sessions** and **Sign
    out**. Returns the passkeys and the second browser's page."""
    passkeys = set_up(page, rig)
    elsewhere = other.new_page()
    open_portal(elsewhere, rig.origin)
    passkeys.copy_to(elsewhere)
    sign_in(elsewhere, rig.origin)
    open_section(page, "Sessions")
    expect(page.locator("#session-list li")).to_have_count(2)
    press(page, "End the other sessions")
    expect(page.get_by_text("Ended 1 other session(s).")).to_be_visible()
    expect(page.locator("#session-list li")).to_have_count(1)
    sign_out(page)
    return passkeys, elsewhere


def answers(context: BrowserContext, page: Page) -> Callable[[], dict[str, int]]:
    """The status of each answer ``page`` receives from now on, as ``"<method> <path>"``, from
    the DevTools protocol's raw response headers (sent for an answer CORS hides too)."""
    network = context.new_cdp_session(page)
    asked: dict[str, str] = {}
    statuses: dict[str, int] = {}

    def sent(event: dict[str, Any]) -> None:
        request = event["request"]
        asked[event["requestId"]] = f"{request['method']} {urlsplit(request['url']).path}"

    def received(event: dict[str, Any]) -> None:
        statuses[event["requestId"]] = event["statusCode"]

    network.on("Network.requestWillBeSent", sent)
    network.on("Network.responseReceivedExtraInfo", received)
    network.send("Network.enable")

    def read() -> dict[str, int]:
        network.send("Runtime.evaluate", {"expression": "0"})  # every earlier event is in
        return {asked[key]: status for key, status in statuses.items() if key in asked}

    return read


# --- item 1: the algorithm the enrolment chose -------------------------------------------------


def test_item_1_the_enrolment_answer_and_the_log_say_es256(rig: PortalRig, page: Page) -> None:
    """Item 1's lines a browser can run: "the enrolment answer (Network panel) and
    ``passkey_enrolled`` in the log show ``"alg": "ES256"``, and the prompt opened from the click
    (no ``NotAllowedError`` from a missing user gesture)". The virtual authenticator makes P-256
    keys only, so which algorithm a real platform authenticator or a security key picks stays by
    hand."""
    with page.expect_response(lambda answer: answer.url.endswith(ENROL_FINISH)) as finished:
        passkeys = set_up(page, rig)
    assert finished.value.status == 200
    assert finished.value.json()["passkey"]["alg"] == "ES256"
    [line] = rig.lines("passkey_enrolled")
    assert (line["alg"], line["rp_id"], line["via"]) == ("ES256", "localhost", "setup_code")
    assert [event for event, _ in passkeys.events] == ["credentialAdded", "credentialAsserted"]
    expect(page.locator("#error")).to_be_hidden()


# --- item 3: sessions across reloads and tabs ----------------------------------------------------


def test_item_3_a_reload_keeps_the_session_and_a_new_tab_or_browser_asks_to_sign_in(
    rig: PortalRig, page: Page, context: BrowserContext, other_context: BrowserContext
) -> None:
    """Item 3: "Sign in. Reload: still signed in. Open a new tab and type the portal's address:
    it asks to sign in", and a restarted browser asks too. (Reopening a closed tab stays by
    hand: no browser API reopens one.)"""
    set_up(page, rig)
    page.reload()
    signed_in(page, rig.origin)
    tab = context.new_page()
    open_portal(tab, rig.origin)
    asks_to_sign_in(tab)
    restarted = other_context.new_page()
    open_portal(restarted, rig.origin)
    asks_to_sign_in(restarted)
    # Neither ended the first tab's session: they had none to send.
    page.reload()
    signed_in(page, rig.origin)


def test_item_3_sign_out_empties_the_storage_and_drops_the_cookie(
    rig: PortalRig, page: Page, context: BrowserContext
) -> None:
    """Item 3: "Sign out, reopen: it asks again", and "After **Sign out**, the Application
    panel's ``sessionStorage`` for the origin is empty and the session cookie is gone"."""
    set_up(page, rig)
    assert page.evaluate("sessionStorage.length") == 1
    assert session_cookie(rig) in {cookie["name"] for cookie in context.cookies(rig.origin)}
    sign_out(page)
    assert page.evaluate("sessionStorage.length") == 0
    assert session_cookie(rig) not in {cookie["name"] for cookie in context.cookies(rig.origin)}
    [ended] = rig.lines("portal_logout")
    assert ended["why"] == "logout"
    open_portal(page, rig.origin)
    asks_to_sign_in(page)
    page.reload()
    asks_to_sign_in(page)


def test_item_3_fifteen_idle_minutes_end_the_session(
    clocked: PortalRig, clock: Clock, page: Page, watch: Watch
) -> None:
    """Item 3: "it asks again ... after 15 idle minutes without signing out" (the rig's clock,
    so in any browser and with no waiting). Each use starts the idle limit again: two minutes
    more takes the time since signing in past it, but not the time since the last use."""
    set_up(page, clocked)
    clock.advance(SESSION_IDLE - 60)
    page.reload()
    signed_in(page, clocked.origin)
    clock.advance(120)
    page.reload()
    signed_in(page, clocked.origin)  # 16 minutes since signing in, 2 since the last use
    clock.advance(SESSION_IDLE)  # the limit, to the second, since that use
    watch.allow(REFUSED_401, on=clocked.origin)  # the page's GET /api/session, refused
    page.reload()
    asks_to_sign_in(page)
    assert page.evaluate("sessionStorage.length") == 0  # the page drops the dead session's half


def test_item_3_signing_in_from_a_second_tab_ends_the_first_tabs_session(
    rig: PortalRig, page: Page, context: BrowserContext, watch: Watch
) -> None:
    """Item 3's finding, the owner's rule: one signed-in tab per browser. Signing in from a
    second tab replaces the first tab's session at once, so the first tab asks to sign in."""
    passkeys = set_up(page, rig)
    tab = context.new_page()
    open_portal(tab, rig.origin)
    passkeys.copy_to(tab)
    sign_in(tab, rig.origin)
    assert rig.logged("portal_session_ended", lambda line: line["why"] == "replaced")
    watch.allow(REFUSED_401, on=rig.origin)
    page.reload()
    asks_to_sign_in(page)
    tab.reload()
    signed_in(tab, rig.origin)


# --- item 4: Fetch Metadata and Origin -----------------------------------------------------------


def test_item_4_every_post_is_same_origin_and_carries_the_real_origin(
    rig: PortalRig, page: Page, other_context: BrowserContext, watch: Watch
) -> None:
    """Item 4: "On any ``POST`` the page makes (sign in, sign out, end the other sessions), the
    request headers show ``Sec-Fetch-Site: same-origin`` and the real ``Origin``, not ``null``,
    though the page sends no referrer. Pass: both, on every ``POST``." Read from the headers as
    the browser sent them."""
    full_session(page, other_context, rig)
    posts = watch.posts()
    paths = {urlsplit(request.url).path for request in posts}
    assert paths == {
        "/api/setup/redeem",
        "/api/passkeys/enrol/begin",
        "/api/passkeys/enrol/finish",
        "/api/login/begin",
        "/api/login/finish",
        "/api/sessions/end-others",
        "/api/logout",
    }
    for request in posts:
        headers = request.all_headers()
        assert headers["sec-fetch-site"] == "same-origin", request.url
        assert headers["origin"] == rig.origin, request.url
        assert "referer" not in headers, request.url


# --- item 6: the IP-literal redirect -------------------------------------------------------------


def test_item_6_a_loopback_literal_redirects_to_localhost(rig: PortalRig, page: Page) -> None:
    """Item 6: "Open ``http://127.0.0.1:8081/``. Pass: the browser lands on
    ``http://localhost:8081/`` (a 308), and the page loads"."""
    literal = f"http://127.0.0.1:{rig.portal_port}/"
    landed = page.goto(literal)
    assert landed is not None
    assert landed.status == 200
    assert page.url == f"{rig.origin}/"
    first = landed.request.redirected_from
    assert first is not None
    assert first.url == literal
    redirect = first.response()
    assert redirect is not None
    assert redirect.status == 308
    assert redirect.headers["location"] == f"{rig.origin}/"
    asks_to_sign_in(page)


# --- item 7: a passkey belongs to its host name --------------------------------------------------


def test_item_7_a_passkey_enrolled_on_localhost_isnt_offered_on_another_name(
    fronted: PortalRig, front: Forwarder, page: Page
) -> None:
    """Item 7: "With a passkey enrolled on ``http://localhost:8081``, open
    ``https://zoeymcp.tailnet.example/`` and choose **Sign in with a passkey**. Pass: the browser
    doesn't offer the ``localhost`` passkey (it offers none, or only ones enrolled on that
    name)", over an https origin the browser trusts (the TLS front, ``engines.FRONT``). The
    sign-in fails as a prompt with nothing to choose does, nothing is asserted, and a passkey
    enrolled on that name then signs in there, so the origin itself works. By hand: real LAN
    https with a certificate the machine trusts."""
    rig = fronted
    passkeys = set_up(page, rig)
    there = f"https://{FRONT}:{front.port}"
    open_portal(page, there)
    press(page, "Sign in with a passkey")
    expect(page.locator("#error")).to_have_text(NOT_ALLOWED)
    asks_to_sign_in(page)
    assert passkeys.asserted() == 1  # the localhost sign-in only
    set_up(page, rig, name="tailnet", origin=there, passkeys=passkeys)
    assert sorted(credential["rpId"] for credential in passkeys.credentials()) == [
        "localhost",
        FRONT,
    ]
    assert [line["rp_id"] for line in rig.lines("portal_login")] == ["localhost", FRONT]


# --- item 10: a neighbour on another localhost port ----------------------------------------------


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="the vault's stop hangs on Windows once a browser resets a refused connection "
    "(the proactor's connection-reset fault skips the server's detach; register D-142); "
    "CI's Linux job runs it",
)
def test_item_10_a_neighbour_port_gets_nothing_and_signs_nobody_out(
    rig: PortalRig, page: Page, context: BrowserContext, watch: Watch
) -> None:
    """Item 10: the neighbour page's read and sign-out, sent with the browser's cookies from
    another ``localhost`` port. "Pass: the console shows a CORS error, not the session; the
    vault's log shows both refused (``cross_site``), and the portal tab is still signed in."
    Then the portal's cookie replayed without the page's token: "``401`` with
    ``"reason":"no_session"``, and the portal tab is still signed in"."""
    set_up(page, rig)
    with Neighbour("neighbour.html", NEIGHBOUR.format(origin=rig.origin)) as neighbour:
        # The neighbour's own page: its CORS error, its failed loads and its unhandled refusal.
        watch.allow(r"CORS policy|Failed to fetch|Failed to load resource", on=neighbour.url(""))
        tab = context.new_page()
        said: list[tuple[str, str]] = []
        tab.on("console", lambda message: said.append((message.type, message.text)))
        # The status of each answer as the browser received it: neither reaches the page (the
        # read's by CORS, the sign-out's by the portal's Cross-Origin-Resource-Policy), so
        # Playwright reports both as failed, but each status line is in the raw headers.
        statuses = answers(context, tab)
        marked = len(rig.lines("portal_refused"))
        with (
            tab.expect_event("requestfailed", lambda r: r.url == f"{rig.origin}/api/session"),
            tab.expect_event("requestfailed", lambda r: r.url == f"{rig.origin}/api/logout"),
        ):
            tab.goto(neighbour.url("neighbour.html"))
        portal_answers = {key: status for key, status in statuses().items() if " /api/" in key}
        assert portal_answers == {"GET /api/session": 403, "POST /api/logout": 403}
        sent = [
            r
            for r in watch.requests
            if r.frame.page == tab and r.url.startswith(f"{rig.origin}/api/")
        ]
        assert [(r.method, urlsplit(r.url).path) for r in sent] == [
            ("GET", "/api/session"),
            ("POST", "/api/logout"),
        ]
        assert [text for _, text in said if "CORS policy" in text] != []
    refused = rig.logged("portal_refused", lambda line: line["reason"] == "cross_site")
    assert refused
    assert refused[0]["status"] == 403
    # Both for cross_site: a 403 for any other reason would log a line of its own (the log
    # keeps one line per reason every 10 s, so the second cross_site refusal has none).
    assert {line["reason"] for line in rig.lines("portal_refused")[marked:]} == {"cross_site"}
    assert rig.lines("portal_logout") == []
    # The read's answer never reached the page: its console.log never ran.
    assert [kind for kind, _ in said if kind != "error"] == []
    open_section(page, "Sessions")
    # The cookie alone, as the neighbour's own server could replay it.
    [cookie] = [c for c in context.cookies(rig.origin) if c["name"] == session_cookie(rig)]
    replayed = httpx.get(
        f"http://127.0.0.1:{rig.portal_port}/api/session",
        headers={
            "Host": f"localhost:{rig.portal_port}",
            "Sec-Fetch-Site": "same-origin",
            "Cookie": f"{cookie['name']}={cookie['value']}",
        },
    )
    assert replayed.status_code == 401
    assert replayed.json()["reason"] == "no_session"
    open_section(page, "Passkeys")


# --- item 11: Trusted Types ----------------------------------------------------------------------


def test_item_11_a_full_session_makes_no_violation(
    rig: PortalRig, page: Page, other_context: BrowserContext, watch: Watch
) -> None:
    """Item 11: "run a full session: set up with a code, sign in with the new passkey, open
    Sessions, end the other sessions, sign out. Pass: no Trusted Types or Content Security
    Policy violation in the console", with the page's policy in force (no ``bypass_csp``)."""
    answer = page.goto(f"{rig.origin}/")
    assert answer is not None
    policy = answer.headers["content-security-policy"]
    assert "require-trusted-types-for 'script'" in policy
    assert "trusted-types 'none'" in policy
    full_session(page, other_context, rig)
    assert_no_horizontal_overflow(page)
    watch.assert_clean()


def test_the_watch_sees_a_trusted_types_violation(rig: PortalRig, page: Page, watch: Watch) -> None:
    """The recorder item 11 leans on, shown failing: a string written to an HTML sink on the
    portal's page is refused by the browser, recorded as a violation and said on the console."""
    open_portal(page, rig.origin)
    asks_to_sign_in(page)
    with pytest.raises(Error, match="TrustedHTML"):
        page.evaluate("document.body.innerHTML = 'x'")
    assert [v["directive"] for v in watch.violations] == ["require-trusted-types-for"]
    assert [v["page"] for v in watch.violations] == [f"{rig.origin}/"]
    assert [text for _, text in watch.console if "TrustedHTML" in text] != []
    watch.violations.clear()
    watch.console.clear()


def test_the_browser_reaches_nothing_off_loopback(page: Page, watch: Watch) -> None:
    """The loopback-only rule, shown holding: a name that isn't a test name resolves to nothing
    (``engines.resolver_rules``), and the watch records the attempt as a stray request."""
    with pytest.raises(Error, match="ERR_NAME_NOT_RESOLVED"):
        page.goto("http://example.com/")
    assert watch.stray() == ["http://example.com/"]
    watch.requests.clear()


# --- item 12: two localhost ports ----------------------------------------------------------------


def test_item_12_a_passkey_enrolled_on_one_port_signs_in_on_another(
    two_ports: PortalRig, forwarder: Forwarder, page: Page, context: BrowserContext
) -> None:
    """Item 12: with a second ``localhost`` port in ``admin.origins`` forwarded to the portal's
    listener, keeping the browser's ``Host``: "a passkey enrolled through
    ``http://localhost:8081`` is offered and accepted on ``http://localhost:8082``", and the two
    ports keep separate cookies."""
    rig = two_ports
    passkeys = set_up(page, rig)
    second = f"http://localhost:{forwarder.port}"
    open_portal(page, second)
    sign_in(page, second)
    assert passkeys.asserted() == 2  # the one credential, asserted on both ports
    [enrolled] = passkeys.credentials()
    assert enrolled["rpId"] == "localhost"
    names = {cookie["name"] for cookie in context.cookies()}
    assert {session_cookie(rig), f"zoeymcp-{forwarder.port}-session"} <= names
    assert [line["rp_id"] for line in rig.lines("portal_login")] == ["localhost", "localhost"]
