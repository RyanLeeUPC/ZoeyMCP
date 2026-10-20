"""Setup codes and the first passkey, over the real API (M5 design E, D.1, D.3, P4, P8, P19).

The page's journey: a code from ``zoeymcp setup-code``, a setup session, the enrolment with the
soft authenticator, then the login with the new passkey and its fingerprint. Every refusal of a
code is one answer; every refusal of a new credential has its own reason (D.3).
"""

from __future__ import annotations

import asyncio
import functools
import io
import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from tests.fakes.authenticator import InvalidStateError, Kind, SoftAuthenticator
from tests.fakes.browser import SESSION_KEY
from tests.unit.test_passkeys import credential
from tests.unit.test_webauthn import ACCEPTED, CREATE_SWITCHES
from zoeymcp.cli.main import main
from zoeymcp.common import files
from zoeymcp.portal import setupcode
from zoeymcp.portal.limits import UNAUTH_BURST
from zoeymcp.portal.passkeys import MAX_NAME
from zoeymcp.portal.sessions import SETUP_SESSION_MAX
from zoeymcp.portal.setupcode import SetupCode
from zoeymcp.portal.webauthn import MAX_PASSKEYS, b64url
from zoeymcp.vault.keys import KeySet, PortalKey

from .flows import (
    ENROL_FINISH,
    begin_enrol,
    enrol,
    finish_enrol,
    issue,
    login,
    redeem,
    set_up,
    status_reason,
)
from .rig import Clock, PortalRig, running

ZWSP = chr(0x200B)


@pytest.fixture
def rig(tmp_path: Path) -> Iterator[PortalRig]:
    with running(tmp_path) as portal:
        yield portal


def portal_key(rig: PortalRig) -> PortalKey:
    return KeySet.from_text(rig.environ["ZOEYMCP_MASTER_KEY"]).portal_key


# --- the journey (E.1, F.2) ---------------------------------------------------------------------


def test_the_first_visit(rig: PortalRig) -> None:
    page = rig.browser().page(rig.origin)
    code = issue(rig)
    redeemed = redeem(page, code)
    assert redeemed.status_code == 200
    answer = redeemed.json()
    assert set(answer) == {"token", "scope", "reset", "expires_at"}
    assert (answer["scope"], answer["reset"]) == ("setup", False)
    assert abs(answer["expires_at"] - (time.time() + SETUP_SESSION_MAX)) < 5
    [cookie] = redeemed.headers.get_list("set-cookie")
    name, _, rest = cookie.partition("=")
    value, _, attributes = rest.partition("; ")
    assert name == f"zoeymcp-{rig.portal_port}-session"
    assert attributes == "HttpOnly; SameSite=Strict; Path=/"  # no Secure, no lifetime (C.1)
    assert len(value) == 43
    assert value != answer["token"]
    assert not (rig.state / setupcode.FILE).exists()  # spent before the session was minted
    [redeemed_line] = rig.lines("setup_code_redeemed")
    assert (redeemed_line["origin"], redeemed_line["reset"]) == (rig.origin, False)

    session = page.fetch("GET", "/api/session").json()
    assert (session["scope"], session["credential"], session["idle"]) == ("setup", None, None)
    assert session["passkeys_here"] == 0

    authenticator = SoftAuthenticator()
    enrolled = enrol(page, authenticator, name="laptop")
    assert enrolled.status_code == 200
    passkey = enrolled.json()["passkey"]
    held = authenticator.held("localhost")[0]
    assert passkey == {
        "fingerprint": rig.vault.passkeys.fingerprint(held.id),
        "name_shown": "laptop",
        "rp_id": "localhost",
        "alg": "ES256",
        "synced": True,
        "transports": ["hybrid", "internal"],
        "via": "setup_code",
        "origin": rig.origin,
        "created": passkey["created"],
        "last_used": None,
    }
    [line] = rig.lines("passkey_enrolled")
    assert {k: line[k] for k in ("level", "credential", "rp_id", "alg", "synced", "via")} == {
        "level": "warning",  # E.4: watch for it
        "credential": passkey["fingerprint"],
        "rp_id": "localhost",
        "alg": "ES256",
        "synced": True,
        "via": "setup_code",
    }
    assert "laptop" not in rig.log.getvalue()  # passkey names are never logged
    assert [x["why"] for x in rig.lines("portal_session_ended")] == ["enrolled"]
    status = rig.call(rig.vault.setup.status)
    assert status["state"] == "enrolled"
    assert status["passkey"]["fingerprint"] == passkey["fingerprint"]

    # The page signs in with the new passkey at once and shows its fingerprint.
    signed_in = login(page, authenticator)
    assert signed_in.status_code == 200
    assert signed_in.json()["scope"] == "full"
    session = page.fetch("GET", "/api/session").json()
    assert session["credential"] == passkey["fingerprint"]
    assert session["credential_name_shown"] == "laptop"
    assert session["passkeys_here"] == 1


def test_a_setup_session_only_enrols(rig: PortalRig) -> None:
    page = rig.browser().page(rig.origin)
    assert redeem(page, issue(rig)).status_code == 200
    assert status_reason(page.fetch("GET", "/api/sessions")) == (403, "scope")
    end = page.fetch("POST", "/api/sessions/end-others", json={})
    assert status_reason(end) == (403, "scope")
    assert page.fetch("GET", "/api/session").status_code == 200
    # One enrolment: the session ends with it.
    token = page.storage[SESSION_KEY]
    assert enrol(page, SoftAuthenticator()).status_code == 200
    page.storage[SESSION_KEY] = token
    assert status_reason(page.fetch("GET", "/api/session")) == (401, "no_session")


def test_a_setup_session_ends_after_ten_minutes(tmp_path: Path) -> None:
    clock = Clock()
    with running(tmp_path, clock=clock) as rig:
        page = rig.browser().page(rig.origin)
        assert redeem(page, issue(rig)).status_code == 200
        begun = begin_enrol(page)
        clock.advance(SETUP_SESSION_MAX)
        attestation = SoftAuthenticator().create(begun["options"], page.origin)
        finished = finish_enrol(page, begun["ceremony"], attestation.body())
        assert status_reason(finished) == (401, "no_session")
        assert [x["why"] for x in rig.lines("portal_session_ended")] == ["max"]
        assert rig.vault.passkeys.document.credentials == ()


# --- the code (E.1, E.2, P8) ----------------------------------------------------------------------


def test_a_code_works_once(rig: PortalRig) -> None:
    code = issue(rig)
    first = rig.browser().page(rig.origin)
    assert redeem(first, code).status_code == 200
    second = rig.browser().page(rig.origin)
    assert status_reason(redeem(second, code)) == (401, "setup_code_refused")
    assert SESSION_KEY not in second.storage


@pytest.mark.parametrize(
    "typed",
    ["", "AAAAAA-AAAAAA-AAAAAA-AAAAAA", "not a code", 12345, None, ["x"], "A" * 65],
)
def test_every_wrong_code_gets_one_answer(rig: PortalRig, typed: object) -> None:
    issue(rig)
    response = redeem(rig.browser().page(rig.origin), typed)
    assert status_reason(response) == (401, "setup_code_refused")
    assert response.json()["error"].startswith("That setup code isn't valid.")
    assert len(rig.app.sessions) == 0


def test_the_code_is_typed_loosely(rig: PortalRig) -> None:
    """Upper or lower case, spaces or dashes: the same 24 characters (E.1)."""
    code = issue(rig)
    typed = " ".join(code.lower().split("-"))
    assert redeem(rig.browser().page(rig.origin), typed).status_code == 200


def test_no_code_and_an_expired_one_are_refused(rig: PortalRig) -> None:
    page = rig.browser().page(rig.origin)
    assert status_reason(redeem(page, "A" * 24)) == (401, "setup_code_refused")
    code = SetupCode("A" * 6 + "-" + "B" * 6 + "-" + "C" * 6 + "-" + "D" * 6)
    record = setupcode.new_record(code, now=time.time() - setupcode.TTL - 1, reset=False)
    files.write_atomic(
        rig.state / setupcode.FILE, setupcode.seal(record, portal_key(rig)), prefix=".setup-"
    )
    assert status_reason(redeem(page, code.reveal())) == (401, "setup_code_refused")


def test_a_planted_record_is_refused(rig: PortalRig) -> None:
    """A writer of /state without the master key can't plant a known code's hash (T16)."""
    code = SetupCode("A" * 6 + "-" + "B" * 6 + "-" + "C" * 6 + "-" + "D" * 6)
    record = setupcode.new_record(code, now=time.time(), reset=False)
    other = KeySet.from_master(bytes(range(32))).portal_key
    files.write_atomic(rig.state / setupcode.FILE, setupcode.seal(record, other), prefix=".setup-")
    assert status_reason(redeem(rig.browser().page(rig.origin), code.reveal())) == (
        401,
        "setup_code_refused",
    )


def test_refusals_are_logged_at_most_once_a_minute(rig: PortalRig) -> None:
    page = rig.browser().page(rig.origin)
    for _ in range(3):
        redeem(page, "wrong")
    assert [line["count"] for line in rig.lines("setup_code_refused")] == [1]
    assert "wrong" not in rig.log.getvalue()


def test_many_misses_never_lock_the_operator_out(tmp_path: Path) -> None:
    clock = Clock()
    with running(tmp_path, clock=clock) as rig:
        code = issue(rig)
        guesser = rig.browser().page(rig.origin)
        answers = [redeem(guesser, "X" * 24).status_code for _ in range(UNAUTH_BURST + 2)]
        assert answers[-1] == 429  # the bucket, never a counter on the code
        assert status_reason(redeem(guesser, code)) == (429, "rate_limited")
        clock.advance(60)
        assert redeem(rig.browser().page(rig.origin), code).status_code == 200


def test_two_redemptions_of_one_code_make_one_session(rig: PortalRig) -> None:
    code = issue(rig)
    pages = [rig.browser().page(rig.origin) for _ in range(2)]
    with ThreadPoolExecutor(2) as pool:
        answers = list(pool.map(lambda page: redeem(page, code).status_code, pages))
    assert sorted(answers) == [200, 401]
    assert len(rig.app.sessions) == 1


def test_the_first_enrolment_deletes_a_pending_code(rig: PortalRig) -> None:
    page = rig.browser().page(rig.origin)
    assert redeem(page, issue(rig)).status_code == 200
    later = issue(rig)  # issued while the setup session is open
    assert enrol(page, SoftAuthenticator()).status_code == 200
    assert not (rig.state / setupcode.FILE).exists()
    assert status_reason(redeem(rig.browser().page(rig.origin), later)) == (
        401,
        "setup_code_refused",
    )


def test_an_offline_code_is_redeemed_without_the_socket(
    rig: PortalRig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``zoeymcp setup-code --state DIR`` on a host without the admin socket (E.2, V12)."""
    monkeypatch.setenv("ZOEYMCP_MASTER_KEY", rig.environ["ZOEYMCP_MASTER_KEY"])
    out = io.StringIO()
    assert main(["setup-code", "--state", str(rig.state)], out=out, err=io.StringIO()) == 0
    page = rig.browser().page(rig.origin)
    assert redeem(page, out.getvalue().strip()).status_code == 200
    assert enrol(page, SoftAuthenticator()).status_code == 200


def test_wait_reports_the_enrolled_passkey(rig: PortalRig) -> None:
    """``zoeymcp setup-code --wait`` long-polls the status; it never carries the code (E.4)."""
    code = issue(rig)
    waiting = asyncio.run_coroutine_threadsafe(rig.vault.setup.wait_status(30), rig.loop)
    rig.call(lambda: None)  # the loop runs callbacks in order: the wait has begun
    page = rig.browser().page(rig.origin)
    assert redeem(page, code).status_code == 200
    assert waiting.result(30)["state"] == "redeemed"
    waiting = asyncio.run_coroutine_threadsafe(rig.vault.setup.wait_status(30), rig.loop)
    rig.call(lambda: None)
    enrolled = enrol(page, SoftAuthenticator(), name="desk key")
    status = waiting.result(30)
    assert status["state"] == "enrolled"
    assert (status["origin"], status["passkey"]["origin"]) == (rig.origin, rig.origin)
    assert status["passkey"]["fingerprint"] == enrolled.json()["passkey"]["fingerprint"]
    assert status["passkey"]["name"] == "desk key"
    assert code not in str(status)


# --- the new credential (D.1, D.3) --------------------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "alg"),
    [
        (Kind.ES256, "ES256"),
        (Kind.EDDSA, "EdDSA"),
        (Kind.RS256, "RS256"),
        (Kind.RS256_3072, "RS256"),
        (Kind.RS256_4096, "RS256"),
    ],
)
@pytest.mark.parametrize("engine", ["chrome", "safari"])
def test_every_algorithm_enrols_and_signs_in(
    rig: PortalRig, kind: Kind, alg: str, engine: str
) -> None:
    """Safari's getPublicKey() is null for EdDSA and RS256: the key comes from the template."""
    authenticator = SoftAuthenticator(browser=engine)  # type: ignore[arg-type]
    page = rig.browser().page(rig.origin)
    passkey = set_up(rig, page, authenticator, kind=kind)
    assert passkey["alg"] == alg
    assert page.fetch("GET", "/api/session").json()["credential"] == passkey["fingerprint"]


def test_the_creation_options(rig: PortalRig) -> None:
    """ES256 first; every credential of this RP ID excluded for a code without --reset (D.1)."""
    first = rig.browser().page(rig.origin)
    set_up(rig, first, SoftAuthenticator())
    page = rig.browser().page(rig.origin)
    assert redeem(page, issue(rig)).status_code == 200
    options = begin_enrol(page)["options"]
    held = rig.vault.passkeys.document.credentials[0]
    assert options["rp"] == {"id": "localhost", "name": "ZoeyMCP"}
    assert options["user"]["id"] == b64url(rig.vault.passkeys.user_handle)
    assert [p["alg"] for p in options["pubKeyCredParams"]] == [-7, -8, -257]
    assert options["excludeCredentials"] == [
        {"type": "public-key", "id": b64url(held.id), "transports": ["hybrid", "internal"]}
    ]
    assert options["authenticatorSelection"]["userVerification"] == "required"
    assert options["attestation"] == "none"
    assert options["timeout"] == 300000


def test_a_second_passkey_on_the_same_authenticator_is_refused_by_the_browser(
    rig: PortalRig,
) -> None:
    """With one user handle a second create() would replace the first: the browser refuses."""
    authenticator = SoftAuthenticator()
    set_up(rig, rig.browser().page(rig.origin), authenticator)
    page = rig.browser().page(rig.origin)
    assert redeem(page, issue(rig)).status_code == 200
    with pytest.raises(InvalidStateError):
        enrol(page, authenticator)


REFUSED_SWITCHES = [s for s, reason in CREATE_SWITCHES.items() if reason != ACCEPTED]


def test_every_enrolment_refusal_over_http(rig: PortalRig) -> None:
    """D.3's registration rows the authenticator's switches reach, then the ones a page or
    another origin reaches; the setup session survives each, so one code serves them all."""
    page = rig.browser().page(rig.origin)
    assert redeem(page, issue(rig)).status_code == 200
    authenticator = SoftAuthenticator()

    def refused(**create: object) -> tuple[int, str]:
        begun = begin_enrol(page)
        attestation = authenticator.create(begun["options"], **create)  # type: ignore[arg-type]
        return status_reason(finish_enrol(page, begun["ceremony"], attestation.body()))

    for switch in REFUSED_SWITCHES:
        assert refused(origin=page.origin, switches={switch}) == (400, CREATE_SWITCHES[switch])
    for kind in (Kind.RS256_1024, Kind.RS256_E3, Kind.ES256_P384):
        assert refused(origin=page.origin, kind=kind) == (400, "key_encoding")
    assert refused(origin="http://localhost:1") == (400, "wrong_origin")
    assert refused(origin=page.origin, rp_id="example.com") == (400, "wrong_rp")
    # The answer to one prompt posted for another.
    stale = begin_enrol(page)
    begun = begin_enrol(page)
    attestation = authenticator.create(stale["options"], page.origin)
    answer = finish_enrol(page, begun["ceremony"], attestation.body())
    assert status_reason(answer) == (400, "wrong_challenge")
    # A ceremony is single use, and an unknown one answers as an expired one.
    assert status_reason(finish_enrol(page, begun["ceremony"], attestation.body())) == (
        404,
        "ceremony_unknown",
    )
    # A body the verifier refuses: an extra field, a name beside the fields.
    begun = begin_enrol(page)
    body = authenticator.create(begun["options"], page.origin).body()
    answer = finish_enrol(page, begun["ceremony"], {**body, "name": "laptop"})
    assert status_reason(answer) == (400, "bad_field")
    for ceremony in (7, None, ["x"]):
        finish = page.fetch("POST", ENROL_FINISH, json={"ceremony": ceremony, "credential": body})
        assert status_reason(finish) == (400, "bad_body")
    assert rig.vault.passkeys.document.credentials == ()
    # The session is still a setup session, and a good answer still enrols.
    assert enrol(page, authenticator).status_code == 200


def test_a_duplicate_and_one_too_many(rig: PortalRig) -> None:
    authenticator = SoftAuthenticator()
    set_up(rig, rig.browser().page(rig.origin), authenticator)
    held = authenticator.held("localhost")[0]
    page = rig.browser().page(rig.origin)
    assert redeem(page, issue(rig)).status_code == 200
    begun = begin_enrol(page)
    other = SoftAuthenticator()
    attestation = other.create(begun["options"], page.origin, credential_id=held.id)
    answer = finish_enrol(page, begun["ceremony"], attestation.body())
    assert status_reason(answer) == (409, "duplicate_credential")
    # Fill the file to the cap from the vault's side.
    for n in range(2, MAX_PASSKEYS + 1):
        add = rig.vault.passkeys.add
        rig.call(
            functools.partial(add, credential(n), name=f"k{n}", via="portal", origin=rig.origin)
        )
    full = page.fetch("POST", "/api/passkeys/enrol/begin", json={"name": "one more"})
    assert status_reason(full) == (409, "too_many_passkeys")


@pytest.mark.parametrize("name", ["", "\t", "a\nb", f"a{ZWSP}b", "x" * (MAX_NAME + 1), 7, None])
def test_a_passkey_name_is_checked_before_the_prompt(rig: PortalRig, name: object) -> None:
    page = rig.browser().page(rig.origin)
    assert redeem(page, issue(rig)).status_code == 200
    response = page.fetch("POST", "/api/passkeys/enrol/begin", json={"name": name})
    assert status_reason(response) == (400, "bad_name")
    assert len(rig.app.ceremonies) == 0


def test_a_name_is_text(rig: PortalRig) -> None:
    """Markup in a name is only text: the answer carries it as typed, and the page sets it with
    textContent (K.2). A bidi override is refused outright (D.4)."""
    page = rig.browser().page(rig.origin)
    assert redeem(page, issue(rig)).status_code == 200
    override = "lap" + chr(0x202E) + "top"
    response = page.fetch("POST", "/api/passkeys/enrol/begin", json={"name": override})
    assert status_reason(response) == (400, "bad_name")
    name = "<img src=x>" + "x" * 53
    passkey = enrol(page, SoftAuthenticator(), name=name).json()["passkey"]
    assert passkey["name_shown"] == name


# --- recovery (E.3, P8, P19) --------------------------------------------------------------------


def test_reset_replaces_every_passkey_and_ends_every_session(rig: PortalRig) -> None:
    authenticator = SoftAuthenticator()
    old_page = rig.browser().page(rig.origin)
    old = set_up(rig, old_page, authenticator)
    page = rig.browser().page(rig.origin)
    redeemed = redeem(page, issue(rig, reset=True))
    assert redeemed.json()["reset"] is True
    options = begin_enrol(page)
    assert options["options"]["excludeCredentials"] == []  # so the old authenticator may answer
    attestation = authenticator.create(options["options"], page.origin)
    enrolled = finish_enrol(page, options["ceremony"], attestation.body())
    assert enrolled.status_code == 200
    new = enrolled.json()["passkey"]
    assert (new["via"], new["fingerprint"] != old["fingerprint"]) == ("setup_code_reset", True)
    assert [line["removed"] for line in rig.lines("passkeys_reset")] == [1]
    ends = [(x["why"]) for x in rig.lines("portal_session_ended")]
    assert ends == ["enrolled", "reset", "enrolled"]
    assert status_reason(old_page.fetch("GET", "/api/session")) == (401, "no_session")
    assert [
        rig.vault.passkeys.fingerprint(c.id) for c in rig.vault.passkeys.document.credentials
    ] == [new["fingerprint"]]
    # The authenticator overwrote its old credential, so the new one signs in.
    assert login(page, authenticator).status_code == 200


def test_an_unverifiable_passkey_file_needs_a_reset_code(tmp_path: Path) -> None:
    """P19: login and enrolment 503 while the proxy serves; a plain code can't enrol; a reset
    code moves the bad file aside and recovers."""

    def spoil(state: Path) -> None:
        (state / "portal").mkdir(mode=0o700)
        (state / "portal" / "passkeys.json").write_bytes(b'{"v": 1, "tampered": true}')

    with running(tmp_path, before_start=spoil) as rig:
        page = rig.browser().page(rig.origin)
        begun = page.fetch("POST", "/api/login/begin", json={})
        assert status_reason(begun) == (503, "unavailable")
        assert redeem(page, issue(rig)).status_code == 200
        enrol_begin = page.fetch("POST", "/api/passkeys/enrol/begin", json={"name": "laptop"})
        assert status_reason(enrol_begin) == (503, "unavailable")
        banners = page.fetch("GET", "/api/session").json()["banners"]
        assert [b["code"] for b in banners] == ["passkeys_unavailable"]
        reset_page = rig.browser().page(rig.origin)
        assert redeem(reset_page, issue(rig, reset=True)).status_code == 200
        authenticator = SoftAuthenticator()
        assert enrol(reset_page, authenticator).status_code == 200
        assert list((rig.state / "portal").glob("passkeys.rejected-*.json"))
        assert login(reset_page, authenticator).status_code == 200
        assert status_reason(page.fetch("GET", "/api/session")) == (401, "no_session")
