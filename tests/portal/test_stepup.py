"""Step-up actions and the passkeys area, over the real API (M5 design D.5, F.3, F.4, P6, Q26).

Every change a full session makes is an action: ``POST /api/actions`` plans it (every check, and
nothing changed, so a mistake shows before the passkey prompt) and holds it; the confirm takes it
out of the table, verifies an assertion whose challenge commits to that action, session, origin
and data, plans again and runs exactly what was held. So an assertion for another action, session
or origin, a stale or replayed one, or one from another RP ID's passkey changes nothing, and a
plan that moved in between is ``409 changed``. The portal never removes the last passkey (the
socket may: host access is the recovery path).

M7's MCP servers section (K.3, GR-13): registering a client and a private discovery are
actions; a discovery and a review are flow starts that hold only memory, fragment 1 and fragment 2
are renders that write nothing, and an onboarding's cancel is a cancel. A discovery with
``allow_private`` and no step-up reaches nothing, and every flow start and render leaves the
store, the passkeys and the policy as they were.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest

from tests.fakes.authenticator import InvalidStateError, SoftAuthenticator, Switch
from tests.fakes.browser import Page
from tests.unit import onboard_model
from zoeymcp.portal import passkeys as passkey_file
from zoeymcp.portal.actions import ACTION_TTL, KINDS
from zoeymcp.portal.routes import ROUTES, STATIC
from zoeymcp.portal.webauthn import b64url
from zoeymcp.vault import server
from zoeymcp.vault.onboard import OnboardService

from .flows import (
    ENROL_BEGIN,
    ENROL_FINISH,
    begin_login,
    enrol,
    filled,
    issue,
    login,
    redeem,
    set_up,
    status_reason,
)
from .rig import Clock, PortalRig, running
from .test_review import gateway_answers, notes_entries, poller

ACTIONS = "/api/actions"
OTHER = "http://localhost:9000"
TAILNET = "https://zoeymcp.tailnet.example"
TAILNET_RP = "zoeymcp.tailnet.example"
PASSKEY_KINDS = ("passkey.enrol", "passkey.rename", "passkey.remove")


@pytest.fixture
def rig(tmp_path: Path) -> Iterator[PortalRig]:
    with running(tmp_path) as portal:
        yield portal


def prepare(page: Page, kind: str, data: Any) -> httpx.Response:
    return page.fetch("POST", ACTIONS, json={"kind": kind, "data": data})


def prepared(page: Page, kind: str, data: Any) -> dict[str, Any]:
    answer = prepare(page, kind, data)
    assert answer.status_code == 200, answer.text
    held: dict[str, Any] = answer.json()
    return held


def confirm(page: Page, action: str, credential: Any) -> httpx.Response:
    return page.fetch("POST", f"{ACTIONS}/{action}/confirm", json={"credential": credential})


def step_up(
    page: Page, authenticator: SoftAuthenticator, kind: str, data: Any, **get: Any
) -> httpx.Response:
    """Prepare, answer the step-up prompt, and confirm, as the page's dialog does."""
    held = prepared(page, kind, data)
    assertion = authenticator.get(held["options"], page.origin, **get)
    return confirm(page, held["action"], assertion.body())


def listed(page: Page) -> list[dict[str, Any]]:
    answer = page.fetch("GET", "/api/passkeys")
    assert answer.status_code == 200, answer.text
    passkeys: list[dict[str, Any]] = answer.json()["passkeys"]
    return passkeys


@dataclass
class Two:
    """Two passkeys of ``localhost``, each with a signed-in browser of its own."""

    first: Page
    alpha: SoftAuthenticator
    a: str  # its fingerprint
    second: Page
    beta: SoftAuthenticator
    b: str


def two(rig: PortalRig, **kwargs: Any) -> Two:
    alpha, beta = SoftAuthenticator(**kwargs), SoftAuthenticator(**kwargs)
    first, second = rig.browser().page(rig.origin), rig.browser().page(rig.origin)
    a = set_up(rig, first, alpha, name="laptop")["fingerprint"]
    b = set_up(rig, second, beta, name="phone")["fingerprint"]
    return Two(first, alpha, a, second, beta, b)


def kind_data(kind: str, world: Two) -> dict[str, Any]:
    """The data of each passkey kind, aimed at the second passkey."""
    if kind == "passkey.enrol":
        return {"name": "tablet"}
    if kind == "passkey.rename":
        return {"credential": world.b, "name": "renamed"}
    return {"credential": world.b}


def names(rig: PortalRig) -> list[str]:
    return [c.name for c in rig.vault.passkeys.document.credentials]


# --- the list (D.5) -----------------------------------------------------------------------------


def test_the_passkey_list(rig: PortalRig) -> None:
    world = two(rig)
    passkeys = listed(world.first)
    assert [(p["fingerprint"], p["name_shown"], p["this"]) for p in passkeys] == [
        (world.a, "laptop", True),
        (world.b, "phone", False),
    ]
    assert {tuple(sorted(p)) for p in passkeys} == {
        (
            "alg",
            "created",
            "fingerprint",
            "last_used",
            "name_shown",
            "origin",
            "rp_id",
            "synced",
            "this",
            "transports",
            "via",
        )
    }
    first = passkeys[0]
    assert (first["rp_id"], first["alg"], first["synced"], first["via"]) == (
        "localhost",
        "ES256",
        True,
        "setup_code",
    )
    assert first["transports"] == ["hybrid", "internal"]
    # Never a key, a full ID or the user handle.
    text = world.first.fetch("GET", "/api/passkeys").text
    holder = rig.vault.passkeys
    for credential in holder.document.credentials:
        assert b64url(credential.id) not in text
        assert b64url(credential.spki) not in text
    assert b64url(holder.user_handle) not in text
    assert [p["this"] for p in listed(world.second)] == [False, True]


def test_a_setup_session_reaches_neither_the_list_nor_the_actions(rig: PortalRig) -> None:
    page = rig.browser().page(rig.origin)
    assert redeem(page, issue(rig)).status_code == 200
    assert status_reason(page.fetch("GET", "/api/passkeys")) == (403, "scope")
    assert status_reason(prepare(page, "passkey.enrol", {"name": "x"})) == (403, "scope")


# --- each kind ----------------------------------------------------------------------------------


def test_preparing_changes_nothing_and_shows_what_will_happen(rig: PortalRig) -> None:
    world = two(rig)
    before = rig.vault.passkeys.document
    held = prepared(world.first, "passkey.rename", {"credential": world.b, "name": "desk"})
    assert sorted(held) == ["action", "expires", "kind", "options", "summary"]
    assert held["kind"] == "passkey.rename"
    assert held["summary"] == [
        ["Rename the passkey", world.b],
        ["Named now", "phone"],
        ["New name", "desk"],
        ["It works on", "localhost"],
    ]
    options = held["options"]
    assert options["userVerification"] == "required"
    assert options["rpId"] == "localhost"
    assert options["timeout"] == 300_000
    assert len(options["allowCredentials"]) == 2  # this RP ID's passkeys
    assert time.time() < held["expires"] <= time.time() + ACTION_TTL
    assert rig.vault.passkeys.document == before
    assert len(rig.app.actions) == 1
    # Preparing again replaces it: one action per session (F.1).
    again = prepared(world.first, "passkey.rename", {"credential": world.b, "name": "desk"})
    assert len(rig.app.actions) == 1
    body = world.alpha.get(held["options"], world.first.origin).body()
    assert status_reason(confirm(world.first, held["action"], body)) == (404, "action_unknown")
    assert again["action"] != held["action"]


def test_rename(rig: PortalRig) -> None:
    world = two(rig)
    generation = rig.vault.passkeys.document.generation
    data = {"credential": world.b, "name": "desk phone"}
    answer = step_up(world.first, world.alpha, "passkey.rename", data)
    assert answer.status_code == 200, answer.text
    assert answer.json()["passkey"]["name_shown"] == "desk phone"
    assert answer.json()["passkey"]["fingerprint"] == world.b
    assert names(rig) == ["laptop", "desk phone"]
    assert rig.vault.passkeys.document.generation == generation + 1
    [confirmed] = rig.lines("step_up_confirmed")
    assert {k: confirmed[k] for k in ("action", "credential")} == {
        "action": "passkey.rename",
        "credential": world.a,
    }
    [renamed] = rig.lines("passkey_renamed")
    assert {k: renamed[k] for k in ("credential", "rp_id")} == {
        "credential": world.b,
        "rp_id": "localhost",
    }
    assert "desk phone" not in rig.log.getvalue()  # names are never logged (M.4)


def test_a_full_session_enrols_a_passkey_after_a_step_up(rig: PortalRig) -> None:
    alpha = SoftAuthenticator()
    first = rig.browser().page(rig.origin)
    set_up(rig, first, alpha)
    # Never without the step-up: the begin route is the setup code's.
    assert status_reason(first.fetch("POST", ENROL_BEGIN, json={"name": "x"})) == (403, "scope")
    held = prepared(first, "passkey.enrol", {"name": "tablet"})
    assert held["summary"] == [
        ["Enrol a new passkey named", "tablet"],
        ["It works on", "localhost"],
        ["Passkeys enrolled now", "1 of at most 32"],
    ]
    answer = confirm(first, held["action"], alpha.get(held["options"], first.origin).body())
    assert answer.status_code == 200, answer.text
    begun = answer.json()
    assert sorted(begun) == ["ceremony", "options"]
    [held_id] = [c.id for c in alpha.held("localhost")]
    assert [c["id"] for c in begun["options"]["excludeCredentials"]] == [b64url(held_id)]
    with pytest.raises(InvalidStateError):  # the browser refuses an authenticator already in
        alpha.create(begun["options"], first.origin)
    beta = SoftAuthenticator()
    body = {
        "ceremony": begun["ceremony"],
        "credential": beta.create(begun["options"], first.origin).body(),
    }
    # The ceremony is this session's.
    other = rig.browser().page(rig.origin)
    assert login(other, alpha).status_code == 200
    assert status_reason(other.fetch("POST", ENROL_FINISH, json=body)) == (
        404,
        "ceremony_unknown",
    )
    done = first.fetch("POST", ENROL_FINISH, json=body)
    assert done.status_code == 200, done.text
    passkey = done.json()["passkey"]
    assert (passkey["name_shown"], passkey["via"]) == ("tablet", "portal")
    line = rig.lines("passkey_enrolled")[-1]
    assert line["via"] == "portal"
    assert "level" not in line  # only a setup code's enrolment is a warning (E.4)
    # The session stays, and the new passkey signs in.
    assert first.fetch("GET", "/api/session").status_code == 200
    assert login(rig.browser().page(rig.origin), beta).status_code == 200


def test_remove_ends_that_passkeys_sessions(rig: PortalRig) -> None:
    world = two(rig)
    third = rig.browser().page(rig.origin)
    assert login(third, world.beta).status_code == 200
    held = prepared(world.first, "passkey.remove", {"credential": world.b})
    assert held["summary"] == [
        ["Remove the passkey", world.b],
        ["Named", "phone"],
        ["It works on", "localhost"],
        ["Sessions that end", "2"],
    ]
    body = world.alpha.get(held["options"], world.first.origin).body()
    answer = confirm(world.first, held["action"], body)
    assert answer.status_code == 200, answer.text
    removed = answer.json()
    assert (removed["sessions_ended"], removed["remaining"], removed["signed_out"]) == (2, 1, False)
    assert removed["removed"]["fingerprint"] == world.b
    assert names(rig) == ["laptop"]
    for page in (world.second, third):
        assert status_reason(page.fetch("GET", "/api/session")) == (401, "no_session")
    assert world.first.fetch("GET", "/api/session").status_code == 200
    [line] = rig.lines("passkey_removed")
    assert {k: line[k] for k in ("credential", "rp_id", "sessions_ended", "remaining")} == {
        "credential": world.b,
        "rp_id": "localhost",
        "sessions_ended": 2,
        "remaining": 1,
    }
    whys = [x["why"] for x in rig.lines("portal_session_ended")]
    assert whys[-2:] == ["passkey_removed", "passkey_removed"]
    # The removed passkey no longer signs in.
    page = rig.browser().page(rig.origin)
    assert status_reason(login(page, world.beta)) == (401, "passkey_refused")


def test_removing_this_sessions_passkey_signs_it_out(rig: PortalRig) -> None:
    world = two(rig)
    held = prepared(world.first, "passkey.remove", {"credential": world.a})
    assert held["summary"][-1] == ["Sessions that end", "1, this one included"]
    body = world.alpha.get(held["options"], world.first.origin).body()
    answer = confirm(world.first, held["action"], body)
    assert answer.status_code == 200, answer.text
    assert answer.json()["signed_out"] is True
    assert status_reason(world.first.fetch("GET", "/api/session")) == (401, "no_session")
    assert world.second.fetch("GET", "/api/session").status_code == 200


def test_the_portal_never_removes_the_last_passkey(rig: PortalRig) -> None:
    """Q26: refused at the plan, before any prompt; the socket's removal is the way out."""
    alpha = SoftAuthenticator()
    page = rig.browser().page(rig.origin)
    fingerprint = set_up(rig, page, alpha)["fingerprint"]
    answer = prepare(page, "passkey.remove", {"credential": fingerprint})
    assert status_reason(answer) == (409, "last_passkey")
    assert answer.json()["error"].startswith("This is the only passkey.")
    assert len(rig.app.actions) == 0
    assert len(rig.vault.passkeys.document.credentials) == 1


def test_the_last_passkey_is_checked_again_at_confirm(rig: PortalRig) -> None:
    world = two(rig)
    held = prepared(world.first, "passkey.remove", {"credential": world.a})
    # Meanwhile the other passkey goes, by its own session's step-up.
    gone = step_up(world.second, world.beta, "passkey.remove", {"credential": world.b})
    assert gone.status_code == 200, gone.text
    body = world.alpha.get(held["options"], world.first.origin).body()
    answer = confirm(world.first, held["action"], body)
    assert status_reason(answer) == (409, "last_passkey")
    assert names(rig) == ["laptop"]
    line = rig.lines("action_changed")[-1]
    assert {k: line[k] for k in ("action", "credential", "reason")} == {
        "action": "passkey.remove",
        "credential": world.a,
        "reason": "last_passkey",
    }


def test_cancel(rig: PortalRig) -> None:
    world = two(rig)
    held = prepared(world.first, "passkey.rename", {"credential": world.b, "name": "desk"})
    path = f"{ACTIONS}/{held['action']}"
    # Another session can't cancel it.
    assert world.second.fetch("DELETE", path).json() == {"cancelled": False}
    assert len(rig.app.actions) == 1
    answer = world.first.fetch("DELETE", path)
    assert answer.status_code == 200
    assert answer.json() == {"cancelled": True}
    assert len(rig.app.actions) == 0  # its data went with it
    assert world.first.fetch("DELETE", path).json() == {"cancelled": False}
    body = world.alpha.get(held["options"], world.first.origin).body()
    assert status_reason(confirm(world.first, held["action"], body)) == (404, "action_unknown")
    assert names(rig) == ["laptop", "phone"]


# --- what a plan refuses, before any prompt -----------------------------------------------------


def test_a_request_the_registry_or_the_plan_refuses(rig: PortalRig) -> None:
    world = two(rig)
    page = world.first

    def refused(kind: Any, data: Any) -> tuple[int, str]:
        answer = page.fetch("POST", ACTIONS, json={"kind": kind, "data": data})
        return status_reason(answer)

    assert refused("passkey.nothing", {"name": "x"}) == (400, "bad_body")
    assert refused(7, {"name": "x"}) == (400, "bad_body")
    assert refused("passkey.enrol", ["x"]) == (400, "bad_body")
    assert refused("passkey.enrol", {"name": "x", "extra": 1}) == (400, "bad_body")
    assert refused("passkey.rename", {"name": "x"}) == (400, "bad_body")
    # Every registered kind is built (ledger.restart was M5's last; M7's step 14a built
    # onboard.register and onboard.discover_private; M6's step 9, tool.clear; step 15a,
    # policy.save, tool.repin and tool.allow), so none answers bad_body for being a later
    # step's. A managed save in this declarative rig is policy_not_managed (M.3).
    assert rig.app.action_kinds == set(KINDS)
    assert refused("ledger.restart", {"x": 1}) == (400, "bad_body")
    assert refused("policy.save", {"draft": "x"}) == (400, "bad_body")
    assert refused("tool.allow", {"draft": "x", "base": 1, "extra": 1}) == (400, "bad_body")
    for kind in ("policy.save", "tool.repin"):
        assert refused(kind, {"draft": "x", "base": 1}) == (409, "policy_not_managed")
    assert refused("tool.allow", {"base": 1, "draft": "x"}) == (409, "policy_not_managed")
    assert refused("tool.clear", {}) == (400, "bad_body")
    assert refused("tool.clear", {"server": "notes", "kind": "tool"}) == (400, "bad_body")
    assert refused("tool.clear", {"server": ["notes"]}) == (400, "bad_body")
    # Each kind's cap: 4 KiB for a passkey's (M.1), within the route's 128 KiB.
    assert refused("passkey.enrol", {"name": "x" * 5000}) == (413, "too_large")
    assert refused("passkey.enrol", {"name": "a\tb"}) == (400, "bad_name")
    assert refused("passkey.enrol", {"name": ""}) == (400, "bad_name")
    assert refused("passkey.rename", {"credential": world.b, "name": "x\ny"}) == (
        400,
        "bad_name",
    )
    assert refused("passkey.rename", {"credential": "0" * 16, "name": "x"}) == (404, "not_found")
    assert refused("passkey.remove", {"credential": "0" * 16}) == (404, "not_found")
    assert refused("passkey.remove", {"credential": 7}) == (400, "bad_body")
    assert len(rig.app.actions) == 0  # nothing held, no prompt
    without = page.fetch("POST", ACTIONS, json={"kind": "passkey.enrol"})
    assert status_reason(without) == (400, "bad_body")


# --- P6: a confirm is bound to its action, session and origin -----------------------------------


@pytest.mark.parametrize("kind", PASSKEY_KINDS)
def test_a_confirm_is_bound_to_its_action_session_and_origin(tmp_path: Path, kind: str) -> None:
    clock = Clock()
    with running(tmp_path, clock=clock, extra_origins=[OTHER, TAILNET]) as rig:
        world = two(rig)
        first, alpha = world.first, world.alpha
        data = kind_data(kind, world)
        clock.advance(30)  # the unauthenticated bucket refills
        other = rig.browser(every_name=True).page(OTHER)
        assert login(other, alpha).status_code == 200
        # alpha also holds a passkey of another RP ID, enrolled there with a setup code.
        tailnet = rig.browser(every_name=True).page(TAILNET)
        assert redeem(tailnet, issue(rig)).status_code == 200
        assert enrol(tailnet, alpha).status_code == 200
        before = (rig.vault.passkeys.document, sorted(s.id for s in rig.app.sessions.live(0)))

        def unchanged() -> bool:
            sessions = sorted(s.id for s in rig.app.sessions.live(0))
            return (rig.vault.passkeys.document, sessions) == before

        def refused(answer: httpx.Response, reason: str) -> None:
            assert status_reason(answer) == (401, "step_up_refused"), answer.text
            line = rig.lines("step_up_refused")[-1]
            assert {k: line[k] for k in ("action", "reason")} == {"action": kind, "reason": reason}
            assert unchanged()

        # An assertion for another action: the first is replaced, and its answer doesn't
        # confirm the second, which is spent by the try.
        x = prepared(first, kind, data)
        y = prepared(first, kind, data)
        refused(
            confirm(first, y["action"], alpha.get(x["options"], first.origin).body()),
            "wrong_challenge",
        )
        good = alpha.get(y["options"], first.origin).body()
        assert status_reason(confirm(first, y["action"], good)) == (404, "action_unknown")
        # Another session's: its assertion over this one's challenge, and this one's ID.
        x = prepared(first, kind, data)
        y = prepared(world.second, kind, data)
        body = world.beta.get(x["options"], first.origin).body()
        refused(confirm(world.second, y["action"], body), "wrong_challenge")
        body = world.beta.get(x["options"], first.origin).body()
        assert status_reason(confirm(world.second, x["action"], body)) == (404, "action_unknown")
        [mine] = [
            s
            for s in rig.app.sessions.live(clock.wall())
            if s.credential == world.a and s.origin == rig.origin
        ]
        still = rig.app.actions.pending(mine.id, clock.wall())
        assert still is not None
        assert still.id == x["action"]  # still the first session's
        # Another origin's: a session on OTHER, answered for the first origin.
        z = prepared(other, kind, data)
        body = alpha.get(z["options"], first.origin).body()
        refused(confirm(other, z["action"], body), "wrong_origin")
        # Another RP ID's passkey (the options list only this RP ID's; the browser is lied to).
        x = prepared(first, kind, data)
        options = {**x["options"], "allowCredentials": []}
        body = alpha.get(options, first.origin, rp_id=TAILNET_RP).body()
        refused(confirm(first, x["action"], body), "unknown_credential")
        # No user verification.
        x = prepared(first, kind, data)
        body = alpha.get(x["options"], first.origin, switches={Switch.NO_UV}).body()
        refused(confirm(first, x["action"], body), "not_verified")
        # A confirm takes only the assertion: there is nothing to swap. The action stays.
        x = prepared(first, kind, data)
        good = alpha.get(x["options"], first.origin).body()
        swapped = {"credential": good, "data": {"name": "other"}}
        answer = first.fetch("POST", f"{ACTIONS}/{x['action']}/confirm", json=swapped)
        assert status_reason(answer) == (400, "bad_body")
        assert len(rig.app.actions) == 1
        # Stale: the action lived its 300 s.
        clock.advance(ACTION_TTL + 1)
        assert status_reason(confirm(first, x["action"], good)) == (404, "action_unknown")
        assert unchanged()
        assert rig.lines("step_up_confirmed") == []
        # The real one, then its replay.
        x = prepared(first, kind, data)
        good = alpha.get(x["options"], first.origin).body()
        assert confirm(first, x["action"], good).status_code == 200
        assert status_reason(confirm(first, x["action"], good)) == (404, "action_unknown")
        [line] = rig.lines("step_up_confirmed")
        assert (line["action"], line["credential"]) == (kind, world.a)


# --- changed, failed writes, counters -----------------------------------------------------------


def test_a_plan_that_moved_is_changed(rig: PortalRig) -> None:
    world = two(rig)
    held = prepared(world.first, "passkey.rename", {"credential": world.b, "name": "desk"})
    # Meanwhile the other session renames the same passkey.
    data = {"credential": world.b, "name": "pocket"}
    assert step_up(world.second, world.beta, "passkey.rename", data).status_code == 200
    body = world.alpha.get(held["options"], world.first.origin).body()
    answer = confirm(world.first, held["action"], body)
    assert status_reason(answer) == (409, "changed")
    shown = answer.json()
    assert shown["error"].startswith("Something changed since you prepared this")
    assert shown["was"] == held["summary"]
    assert ["Named now", "pocket"] in shown["now"]
    assert names(rig) == ["laptop", "pocket"]
    line = rig.lines("action_changed")[-1]
    assert {k: line[k] for k in ("action", "credential", "reason")} == {
        "action": "passkey.rename",
        "credential": world.a,
        "reason": "changed",
    }
    assert rig.logged("portal_request", lambda line: line["reason"] == "changed")
    # A removal whose sessions changed: another sign-in with that passkey in between.
    held = prepared(world.first, "passkey.remove", {"credential": world.b})
    assert login(rig.browser().page(rig.origin), world.beta).status_code == 200
    body = world.alpha.get(held["options"], world.first.origin).body()
    answer = confirm(world.first, held["action"], body)
    assert status_reason(answer) == (409, "changed")
    assert answer.json()["now"][-1] == ["Sessions that end", "2"]
    assert names(rig) == ["laptop", "pocket"]


def test_a_failed_write_changes_nothing(rig: PortalRig, monkeypatch: pytest.MonkeyPatch) -> None:
    world = two(rig)
    before = rig.vault.passkeys.document

    def refuse(path: Path, data: bytes) -> None:
        raise OSError("read-only file system")

    monkeypatch.setattr(passkey_file, "write_atomic", refuse)
    for kind, data in (
        ("passkey.rename", {"credential": world.b, "name": "desk"}),
        ("passkey.remove", {"credential": world.b}),
    ):
        answer = step_up(world.first, world.alpha, kind, data)
        assert status_reason(answer) == (500, "not_written"), kind
        assert (
            answer.json()["error"]
            == "Not written to disk; nothing changed; check the state volume."
        )
    assert rig.vault.passkeys.document == before
    assert world.second.fetch("GET", "/api/session").status_code == 200  # nothing ended
    assert len(rig.lines("portal_state_not_written")) == 2
    assert rig.lines("passkey_renamed") == rig.lines("passkey_removed") == []


def test_a_counter_regression_at_step_up_is_flagged_never_lowered(rig: PortalRig) -> None:
    """D10 (Q10): accepted, logged critical, shown as a banner; the stored value stays."""
    world = two(rig, backup_eligible=False, backup_state=False, counts=True)
    stored = rig.vault.passkeys.document.credentials[0].sign_count
    assert stored > 0
    data = {"credential": world.b, "name": "desk"}
    answer = step_up(
        world.first, world.alpha, "passkey.rename", data, switches={Switch.COUNTER_BACK}
    )
    assert answer.status_code == 200, answer.text
    [line] = rig.lines("passkey_counter_regressed")
    assert (line["level"], line["credential"]) == ("critical", world.a)
    assert rig.vault.passkeys.document.credentials[0].sign_count == stored
    banners = world.first.fetch("GET", "/api/session").json()["banners"]
    assert [b["code"] for b in banners] == ["passkey_counter_regressed"]


# --- every change is an action (F.4) ------------------------------------------------------------

# The unsafe routes that aren't an action, each for its reason (F.4's list); any other POST or
# DELETE fails the walk.
SESSION_LIFECYCLE = {
    ("POST", "/api/login/begin"),
    ("POST", "/api/login/finish"),
    ("POST", "/api/setup/redeem"),
    ("POST", "/api/logout"),
    ("POST", "/api/sessions/end-others"),
}
# A setup code's enrolment (the code was its step-up), or one a confirmed passkey.enrol began.
AUTHORIZED_ENROLMENT = {("POST", ENROL_BEGIN), ("POST", ENROL_FINISH)}
# The action's own routes: prepare (holds, changes nothing) and confirm (the step-up).
ACTION_ROUTES = {("POST", ACTIONS), ("POST", "/api/actions/{action}/confirm")}
# A flow start writes no grant. The client_credentials start, a test fetch, is the one such
# route that can clear a failure state, and only after a fetch that worked (F.4, H.1). A
# discovery and a review hold what they learn in memory only (M7 K.3).
FLOW_STARTS = {
    ("POST", "/api/oauth/{credential}/start"),
    ("POST", "/api/onboard/discover"),
    ("POST", "/api/review/{server}"),
}
CANCELS = {
    ("DELETE", "/api/actions/{action}"),
    ("DELETE", "/api/oauth/flows/{flow}"),
    ("DELETE", "/api/onboard/{onboarding}"),
}
# M7 K.3: fragment 1 (a given public client's, or a registered onboarding's again) and fragment
# 2, each rendered from what the vault holds, writing nothing.
RENDERS = {("POST", "/api/onboard/{onboarding}/fragment"), ("POST", "/api/review/jobs/{job}/diff")}
# An OAuth credential whose sign-in a session can start (no token call until a confirm).
OAUTH_POLICY: dict[str, Any] = {
    "credentials": {
        "notes": {
            "kind": "oauth2",
            "token_url": "https://auth.notes.example/token",
            "authorize_url": "https://auth.notes.example/authorize",
            "client_id": "example-notes-client",
            "client_auth": "none",
            "refresh_token": "store:notes-refresh",
        }
    },
    "routes": [
        {
            "name": "notes",
            "prefix": "/notes",
            "upstream": "https://api.notes.example",
            "credential": "notes",
            "callers": [{"placeholder": "ph-agent1-notes-0001"}],
            "rules": [{"methods": ["GET"], "paths": ["/**"]}],
        }
    ],
}
# The same, with a notes server as onboarding by URL leaves one: its own route for the gateway
# alone and a server including nothing, which a review can be queued for (M7 E.2, F.2). It is
# another host's, so discovering onboard_model's URL onboards it anew.
_NOTES = notes_entries()
SERVERS_POLICY: dict[str, Any] = {
    "credentials": OAUTH_POLICY["credentials"],
    "routes": [
        *OAUTH_POLICY["routes"],
        {
            **_NOTES["routes"][0],
            "name": "notes-mcp",
            "prefix": "/notes-mcp",
            "upstream": "https://mcp.tasks.example",
        },
    ],
    "gateway": {
        "servers": {"notes": {**_NOTES["gateway"]["servers"]["notes"], "route": "notes-mcp"}}
    },
}


def model_onboarding(vault: server.Vault) -> OnboardService:
    """The vault's onboarding service on tests/unit/onboard_model.py's in-process world."""
    assert vault.portal is not None
    secrets = vault.portal.app.secrets
    assert secrets is not None
    return onboard_model.onboard_service(secrets.store, secrets.tokens, lambda: vault.app.policy)


def test_every_change_is_an_action(tmp_path: Path) -> None:
    allowed = SESSION_LIFECYCLE | AUTHORIZED_ENROLMENT | ACTION_ROUTES | FLOW_STARTS | CANCELS
    allowed |= RENDERS
    unsafe = {(r.method, r.path) for r in ROUTES if r.method != "GET"}
    assert unsafe <= allowed, sorted(unsafe - allowed)
    assert allowed <= unsafe, sorted(allowed - unsafe)  # the lists name only built routes
    with running(tmp_path, policy=SERVERS_POLICY, onboard=model_onboarding) as rig:
        every_get_leaves_the_tables(rig)


def every_get_leaves_the_tables(rig: PortalRig) -> None:
    """Every GET, with a session of each scope it takes, leaves every table as it was (a
    session's idle clock aside): with an action pending, an enrolment, a login, an OAuth
    sign-in, an onboarding and a review job under way."""
    world = two(rig)
    setup = rig.browser().page(rig.origin)
    assert redeem(setup, issue(rig)).status_code == 200
    setup.fetch("POST", ENROL_BEGIN, json={"name": "x"})
    begin_login(rig.browser().page(rig.origin))
    prepared(world.first, "passkey.rename", {"credential": world.b, "name": "desk"})
    started = world.second.fetch("POST", "/api/oauth/notes/start", json={})
    assert started.status_code == 200, started.text
    discover = {"url": onboard_model.SERVER_URL, "client_id": onboard_model.CLIENT_ID}
    plan = world.first.fetch("POST", "/api/onboard/discover", json=discover)
    assert plan.status_code == 200, plan.text
    poller(rig)
    queued = world.first.fetch("POST", "/api/review/notes", json={})
    assert queued.status_code == 200, queued.text
    review = queued.json()["job"]
    gateway_answers(rig)
    owned = [f"/api/onboard/{plan.json()['onboarding']}", f"/api/review/jobs/{review}"]

    def tables() -> object:
        app = rig.app
        now = time.time()
        live = app.sessions.live(now)
        sessions = sorted((s.id, s.scope, s.origin, s.credential, s.created) for s in live)
        pending = sorted(a.id for s in live if (a := app.actions.pending(s.id, now)) is not None)
        counts = (len(app.sessions), len(app.ceremonies), len(app.actions))
        flows = rig.vault.login._flows._flows
        signing_in = sorted((f.id, f.credential, f.owner, f.expires_at) for f in flows.values())
        assert app.onboard is not None
        records = app.onboard._table._records.values()
        onboarding = sorted((r.id, r.owner, r.stage, r.expires_at) for r in records)
        jobs = rig.vault.app._reviews._jobs.values()
        reviews = sorted((j.id, j.owner, j.state, j.digest) for j in jobs)
        held = (signing_in, onboarding, reviews)
        return sessions, pending, counts, held, rig.vault.passkeys.document

    before = tables()
    gets = [r for r in ROUTES if r.method == "GET"]
    assert gets
    for route in gets:
        for page in (world.first, setup):
            page.fetch("GET", filled(route))
    for path in owned:
        assert world.first.fetch("GET", path).status_code == 200
    for path in STATIC:
        world.first.fetch("GET", path)
    assert tables() == before


# --- M7 K.3: a private discovery, and what the flow starts and renders leave ---------------------


def test_a_discovery_with_allow_private_and_no_step_up_reaches_nothing(tmp_path: Path) -> None:
    """TI-3: the route refuses the key, and the action's plan sends nothing and holds no
    onboarding; without its confirm nothing ever does."""
    sent: list[str] = []

    def recorded(vault: server.Vault) -> OnboardService:
        service = model_onboarding(vault)
        transport = service._client._transport
        assert isinstance(transport, httpx.MockTransport)
        handler = transport.handler

        def note(request: httpx.Request) -> Any:
            sent.append(str(request.url))
            return handler(request)

        service._client._transport = httpx.MockTransport(note)
        return service

    with running(tmp_path, onboard=recorded) as rig:
        page = rig.browser().page(rig.origin)
        passkey = SoftAuthenticator()
        set_up(rig, page, passkey)
        body = {
            "url": onboard_model.SERVER_URL,
            "allow_private": True,
            "client_id": onboard_model.CLIENT_ID,
        }
        refused = page.fetch("POST", "/api/onboard/discover", json=body)
        assert status_reason(refused) == (400, "bad_body")
        held = prepared(page, "onboard.discover_private", body)
        assert held["kind"] == "onboard.discover_private"
        assert page.fetch("DELETE", f"{ACTIONS}/{held['action']}").json() == {"cancelled": True}
        held = prepared(page, "onboard.discover_private", body)
        # A confirm without the passkey's assertion is refused, and spends the action.
        assert status_reason(confirm(page, held["action"], {})) == (401, "step_up_refused")
        assert rig.app.onboard is not None
        assert (sent, len(rig.app.onboard._table)) == ([], 0)
        assert rig.lines("onboard_started") == []
        # With the passkey it runs, and only then reaches the server.
        done = step_up(page, passkey, "onboard.discover_private", body)
        assert done.status_code == 200, done.text
        assert sent
        assert [line["allow_private"] for line in rig.lines("onboard_started")] == [True]


def test_every_flow_start_and_render_leaves_the_store_the_passkeys_and_the_policy(
    tmp_path: Path,
) -> None:
    """K.3's snapshot: a discovery, fragment 1 of a given public client and again, a review
    queued and fragment 2 made: none writes the store, the passkey file or the policy."""
    with running(tmp_path, policy=SERVERS_POLICY, onboard=model_onboarding) as rig:
        page = rig.browser().page(rig.origin)
        set_up(rig, page, SoftAuthenticator())
        poller(rig)

        def files() -> object:
            state = sorted((p.name, p.read_bytes()) for p in rig.state.rglob("*") if p.is_file())
            return state, rig.policy_file.read_bytes(), rig.vault.app.policy

        before = files()
        discover = {"url": onboard_model.SERVER_URL, "client_id": onboard_model.CLIENT_ID}
        plan = page.fetch("POST", "/api/onboard/discover", json=discover)
        assert plan.status_code == 200, plan.text
        fragment = f"/api/onboard/{plan.json()['onboarding']}/fragment"
        for indent in (0, "compose"):
            made = page.fetch("POST", fragment, json={"indent": indent})
            assert made.status_code == 200, made.text
        queued = page.fetch("POST", "/api/review/notes", json={})
        assert queued.status_code == 200, queued.text
        gateway_answers(rig)
        choices = {"include": ["echo"], "allow": ["echo"], "approve": []}
        diff = page.fetch("POST", f"/api/review/jobs/{queued.json()['job']}/diff", json=choices)
        assert diff.status_code == 200, diff.text
        assert files() == before
