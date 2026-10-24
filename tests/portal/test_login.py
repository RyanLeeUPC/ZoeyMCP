"""Logging in with a passkey, over the real API (M5 design D.1, D.3, F.1, F.2, P4, P5, P16).

Every refusal of an assertion is one answer, ``passkey_refused``, with the verifier's reason in
the log (P5). The cookie follows the origin's public scheme in every engine (C.1), and a passkey
belongs to its RP ID: another ``localhost`` port takes it, another name doesn't (E.3).
"""

from __future__ import annotations

import functools
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from tests.fakes.authenticator import SoftAuthenticator, Switch, creation_options
from tests.fakes.browser import SESSION_KEY, Engine
from tests.unit.test_webauthn import ACCEPTED, GET_SWITCHES
from zoeymcp.portal.limits import UNAUTH_BURST
from zoeymcp.portal.sessions import (
    MAX_LOGIN_CEREMONIES,
    MAX_LOGIN_CEREMONIES_PER_PEER,
    MAX_SESSIONS,
    SESSION_IDLE,
    SESSION_MAX,
)
from zoeymcp.portal.webauthn import b64url

from .flows import (
    LOGIN_FINISH,
    begin_login,
    enrol,
    finish_login,
    issue,
    login,
    redeem,
    set_up,
    status_reason,
)
from .rig import Clock, PortalRig, running

TAILNET = "https://zoeymcp.tailnet.example"


@pytest.fixture
def rig(tmp_path: Path) -> Iterator[PortalRig]:
    with running(tmp_path) as portal:
        yield portal


def enrolled(rig: PortalRig, **kwargs: object) -> SoftAuthenticator:
    """An authenticator with one passkey enrolled on the rig's origin, by another browser."""
    authenticator = SoftAuthenticator(**kwargs)  # type: ignore[arg-type]
    set_up(rig, rig.browser().page(rig.origin), authenticator)
    return authenticator


def test_a_login(rig: PortalRig) -> None:
    authenticator = enrolled(rig)
    page = rig.browser().page(rig.origin)
    begun = begin_login(page)
    options = begun["options"]
    # Nothing about the credentials reaches a caller without a session (D.1).
    assert options["allowCredentials"] == []
    assert (options["rpId"], options["userVerification"], options["timeout"]) == (
        "localhost",
        "required",
        300000,
    )
    assertion = authenticator.get(options, page.origin)
    answer = finish_login(page, begun["ceremony"], assertion.body())
    assert answer.status_code == 200
    body = answer.json()
    assert set(body) == {"token", "scope", "idle", "expires_at"}
    assert (body["scope"], body["idle"]) == ("full", SESSION_IDLE)
    assert abs(body["expires_at"] - (time.time() + SESSION_MAX)) < 5
    fingerprint = rig.vault.passkeys.fingerprint(assertion.id)
    line = rig.lines("portal_login")[-1]
    assert (line["credential"], line["rp_id"]) == (fingerprint, "localhost")
    session = page.fetch("GET", "/api/session").json()
    assert set(session) == {
        "scope",
        "origin",
        "rp_id",
        "mode",
        "revision",  # the head's in managed mode, None here (M6 design M.1, step 15a)
        "idle",
        "expires_at",
        "session",
        "credential",
        "credential_name_shown",
        "reset",
        "passkeys_here",
        "banners",
        "health_summary",
    }
    assert (session["mode"], session["revision"], session["banners"], session["credential"]) == (
        "declarative",
        None,
        [],
        fingerprint,
    )
    passkey = rig.vault.passkeys.document.credentials[0]
    assert passkey.last_used is not None
    # Neither half, the challenge nor the assertion reaches the log.
    log = rig.log.getvalue()
    for secret in (body["token"], begun["ceremony"], options["challenge"], b64url(assertion.id)):
        assert secret not in log


def test_two_logins_give_two_pairs(rig: PortalRig) -> None:
    authenticator = enrolled(rig)
    first, second = rig.browser().page(rig.origin), rig.browser().page(rig.origin)
    assert login(first, authenticator).status_code == 200
    assert login(second, authenticator).status_code == 200
    assert first.storage[SESSION_KEY] != second.storage[SESSION_KEY]
    assert first.fetch("GET", "/api/session").status_code == 200
    assert second.fetch("GET", "/api/session").status_code == 200
    assert len(rig.app.sessions) == 3  # the setup browser's login too


REFUSED = [s for s, reason in GET_SWITCHES.items() if reason != ACCEPTED]


def test_every_assertion_refusal_over_http(tmp_path: Path) -> None:
    """D.3's assertion rows: one answer for each, the reason logged (P5). Nothing is minted."""
    clock = Clock()
    with running(tmp_path, clock=clock) as rig:
        authenticator = enrolled(rig)
        page = rig.browser().page(rig.origin)
        sessions = len(rig.app.sessions)

        def refused(reason: str, ceremony: str, body: dict[str, Any]) -> None:
            answer = finish_login(page, ceremony, body)
            assert status_reason(answer) == (401, "passkey_refused"), reason
            assert answer.json()["error"].startswith("That passkey wasn't accepted here.")
            assert rig.lines("portal_login_failed")[-1]["reason"] == reason

        def begun() -> dict[str, Any]:
            clock.advance(10)  # the bucket refills a token every 2 s
            return begin_login(page)

        for switch in REFUSED:
            login = begun()
            body = authenticator.get(login["options"], page.origin, switches={switch}).body()
            refused(GET_SWITCHES[switch], login["ceremony"], body)
        login = begun()
        body = authenticator.get(login["options"], "http://localhost:1").body()
        refused("wrong_origin", login["ceremony"], body)
        other, login = begun(), begun()  # the answer to another ceremony's challenge
        refused(
            "wrong_challenge",
            login["ceremony"],
            authenticator.get(other["options"], page.origin).body(),
        )
        login = begun()
        good = authenticator.get(login["options"], page.origin).body()
        refused("user_handle", login["ceremony"], {**good, "user_handle": None})
        login = begun()
        good = authenticator.get(login["options"], page.origin).body()
        refused("bad_field", login["ceremony"], {**good, "extra": 1})
        # A passkey for this RP ID that the vault never enrolled.
        stranger = SoftAuthenticator()
        stranger.create(creation_options(bytes(32), bytes(32)), page.origin)
        login = begun()
        body = stranger.get(login["options"], page.origin).body()
        refused("unknown_credential", login["ceremony"], body)
        assert len(rig.app.sessions) == sessions
        assert SESSION_KEY not in page.storage


def test_a_ceremony_is_single_use_and_bound_to_its_origin(tmp_path: Path) -> None:
    with running(tmp_path, extra_origins=["http://localhost:9000"]) as rig:
        authenticator = enrolled(rig)
        page = rig.browser().page(rig.origin)
        begun = begin_login(page)
        body = authenticator.get(begun["options"], page.origin).body()
        # Finished on another origin of the same listener: unknown there, and still pending.
        neighbour = rig.browser(every_name=True).page("http://localhost:9000")
        answer = finish_login(neighbour, begun["ceremony"], body)
        assert status_reason(answer) == (404, "ceremony_unknown")
        assert finish_login(page, begun["ceremony"], body).status_code == 200
        replayed = finish_login(rig.browser().page(rig.origin), begun["ceremony"], body)
        assert status_reason(replayed) == (404, "ceremony_unknown")
        for ceremony in (1, None, {"x": 1}):
            answer = page.fetch(
                "POST", LOGIN_FINISH, json={"ceremony": ceremony, "credential": body}
            )
            assert status_reason(answer) == (400, "bad_body")


def test_a_ceremony_expires(tmp_path: Path) -> None:
    clock = Clock()
    with running(tmp_path, clock=clock) as rig:
        authenticator = enrolled(rig)
        page = rig.browser().page(rig.origin)
        begun = begin_login(page)
        body = authenticator.get(begun["options"], page.origin).body()
        clock.advance(300)
        assert status_reason(finish_login(page, begun["ceremony"], body)) == (
            404,
            "ceremony_unknown",
        )


def test_a_counter_that_goes_back_is_flagged_never_refused(rig: PortalRig) -> None:
    authenticator = enrolled(rig, backup_eligible=False, backup_state=False, counts=True)
    page = rig.browser().page(rig.origin)
    assert login(page, authenticator).status_code == 200
    stored = rig.vault.passkeys.document.credentials[0].sign_count
    assert login(page, authenticator, switches={Switch.COUNTER_BACK}).status_code == 200
    [line] = rig.lines("passkey_counter_regressed")
    assert line["level"] == "critical"
    assert rig.vault.passkeys.document.credentials[0].sign_count == stored  # never lowered
    banners = page.fetch("GET", "/api/session").json()["banners"]
    assert [b["code"] for b in banners] == ["passkey_counter_regressed"]


# --- the cookie, per engine (C.1, P7) -----------------------------------------------------------


@pytest.mark.parametrize("engine", ["chrome", "firefox", "safari"])
def test_the_cookie_on_http_localhost(rig: PortalRig, engine: Engine) -> None:
    """No Secure and no __Host- on http://localhost: Safari keeps no Secure cookie there, and
    Chrome refuses __Host- (C.1)."""
    authenticator = enrolled(rig)
    browser = rig.browser(engine)
    page = browser.page(rig.origin)
    answer = login(page, authenticator)
    [cookie] = answer.headers.get_list("set-cookie")
    assert cookie.startswith(f"zoeymcp-{rig.portal_port}-session=")
    assert cookie.endswith("; HttpOnly; SameSite=Strict; Path=/")
    assert [c.name for c in browser.cookies] == [f"zoeymcp-{rig.portal_port}-session"]
    assert page.fetch("GET", "/api/session").status_code == 200


@pytest.mark.parametrize("engine", ["chrome", "firefox", "safari"])
def test_the_cookie_on_an_https_origin(tmp_path: Path, engine: Engine) -> None:
    """Behind a TLS proxy that passes Host (C.5): __Host-, Secure, in every engine. A passkey
    belongs to its RP ID, so the https origin needs its own, from a setup code redeemed there."""
    with running(tmp_path, extra_origins=[TAILNET]) as rig:
        local = enrolled(rig)
        browser = rig.browser(engine, every_name=True)
        page = browser.page(TAILNET)
        # The localhost passkey isn't offered here, and isn't accepted if it were.
        begun = begin_login(page)
        assert begun["options"]["rpId"] == "zoeymcp.tailnet.example"
        body = local.get(begun["options"], TAILNET, rp_id="localhost").body()
        assert status_reason(finish_login(page, begun["ceremony"], body)) == (
            401,
            "passkey_refused",
        )
        assert rig.lines("portal_login_failed")[-1]["reason"] == "unknown_credential"
        # Its own passkey, from a code redeemed on this origin (E.3).
        authenticator = SoftAuthenticator()
        assert redeem(page, issue(rig)).status_code == 200
        enrolment = enrol(page, authenticator)
        assert enrolment.json()["passkey"]["rp_id"] == "zoeymcp.tailnet.example"
        answer = login(page, authenticator)
        [cookie] = answer.headers.get_list("set-cookie")
        assert cookie.startswith("__Host-zoeymcp-session=")
        assert cookie.endswith("; Secure; HttpOnly; SameSite=Strict; Path=/")
        assert page.fetch("GET", "/api/session").json()["origin"] == TAILNET


def test_a_second_localhost_port_takes_the_same_passkey(tmp_path: Path) -> None:
    """The RP ID localhost has no port: list the origin and sign in there (E.3, O.6 item 12).
    The session belongs to the origin it was made on."""
    with running(tmp_path, extra_origins=["http://localhost:9000"]) as rig:
        authenticator = enrolled(rig)
        browser = rig.browser(every_name=True)
        other = browser.page("http://localhost:9000")
        answer = login(other, authenticator)
        assert answer.status_code == 200
        assert answer.headers["set-cookie"].startswith("zoeymcp-9000-session=")
        assert other.fetch("GET", "/api/session").json()["origin"] == "http://localhost:9000"
        # Its halves, carried to the first origin, are no session there.
        first = browser.page(rig.origin)
        first.storage[SESSION_KEY] = other.storage[SESSION_KEY]
        assert status_reason(first.fetch("GET", "/api/session")) == (401, "no_session")


# --- the limits (F.1, P16) ----------------------------------------------------------------------


def test_a_fifth_ceremony_from_one_peer_evicts_its_oldest(rig: PortalRig) -> None:
    authenticator = enrolled(rig)
    page = rig.browser().page(rig.origin)
    begun = [begin_login(page) for _ in range(MAX_LOGIN_CEREMONIES_PER_PEER + 1)]
    assert rig.app.ceremonies.logins("127.0.0.1") == MAX_LOGIN_CEREMONIES_PER_PEER
    oldest, newest = begun[0], begun[-1]
    body = authenticator.get(oldest["options"], page.origin).body()
    assert status_reason(finish_login(page, oldest["ceremony"], body)) == (
        404,
        "ceremony_unknown",
    )
    body = authenticator.get(newest["options"], page.origin).body()
    assert finish_login(page, newest["ceremony"], body).status_code == 200


def test_a_full_table_refuses_and_keeps_the_ceremonies_in_progress(rig: PortalRig) -> None:
    authenticator = enrolled(rig)
    page = rig.browser().page(rig.origin)
    mine = begin_login(page)
    for n in range(MAX_LOGIN_CEREMONIES - 1):
        peer = f"192.0.2.{n // MAX_LOGIN_CEREMONIES_PER_PEER}"
        begin = rig.app.ceremonies.begin_login
        rig.call(functools.partial(begin, origin=rig.origin, peer=peer, now=time.time()))
    full = page.fetch("POST", "/api/login/begin", json={})
    # F.1 and P16: 429 (M.2's rate_limited), never evicting another peer's ceremony.
    assert status_reason(full) == (429, "rate_limited")
    assert full.headers["retry-after"] == "2"
    assert rig.app.ceremonies.logins() == MAX_LOGIN_CEREMONIES
    body = authenticator.get(mine["options"], page.origin).body()
    assert finish_login(page, mine["ceremony"], body).status_code == 200


def test_the_bucket_limits_logins(tmp_path: Path) -> None:
    clock = Clock()
    with running(tmp_path, clock=clock) as rig:
        page = rig.browser().page(rig.origin)
        answers = [page.fetch("POST", "/api/login/begin", json={}) for _ in range(UNAUTH_BURST)]
        assert {a.status_code for a in answers} == {200}
        assert status_reason(page.fetch("POST", "/api/login/begin", json={})) == (
            429,
            "rate_limited",
        )
        clock.advance(2)
        assert page.fetch("POST", "/api/login/begin", json={}).status_code == 200


def test_a_ninth_session_evicts_the_least_recently_used(rig: PortalRig) -> None:
    authenticator = enrolled(rig)
    for _ in range(MAX_SESSIONS - 1):
        rig.call(
            lambda: rig.app.sessions.mint(
                origin=rig.origin, rp_id="localhost", scope="full", now=time.time()
            )
        )
    first = rig.browser().page(rig.origin)  # the setup browser's session is the oldest used
    assert login(first, authenticator).status_code == 200
    assert len(rig.app.sessions) == MAX_SESSIONS
    assert [x["why"] for x in rig.lines("portal_session_ended")][-1] == "evicted"


def test_the_body_caps(rig: PortalRig) -> None:
    page = rig.browser().page(rig.origin)
    big = page.fetch("POST", "/api/login/begin", json={"x": "y" * 64})
    assert status_reason(big) == (413, "too_large")
    assert status_reason(page.fetch("POST", "/api/login/begin", json={"x": 1})) == (
        400,
        "bad_body",
    )
    huge = {"ceremony": "c", "credential": {"id": "x" * (16 * 1024)}}
    assert status_reason(page.fetch("POST", LOGIN_FINISH, json=huge)) == (413, "too_large")
