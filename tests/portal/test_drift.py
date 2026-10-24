"""Drift on the review screen over the real API, in declarative mode (M6 design J.2, J1, J13).

The vault's review jobs are the real ones and the gateway is played on the vault's loop, as in
``test_review.py``, its reports straight from the gateway's review code: ``search``, included
and pinned, changed after the review. **Review again** asks for a fresh review, never the done
one handed back (a drift changes no policy); the rows show the definition the policy pinned
(which the vault checked against the pin) and the one listed, with the vault's diff; **Accept the
new definition** re-pins in fragment 2, which a later re-pin makes stale; a tool that flipped
back reads ``marked``, and **Clear the marks** is the ``tool.clear`` action, whose job the gateway
runs (J13, M6 design J.4): done with the marks cleared, ``clear_not_clean`` while a tool still
doesn't match (FM-28), ``clear_unsupported`` while only an older gateway polls (FM-29); hostile
text shows as text on both sides. The page's script isn't run here (``tests.fakes.browser.Page``
runs none): what it reads of these answers is pinned here and by
``tests/unit/test_portal_static.py``.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from tests.fakes.authenticator import SoftAuthenticator
from tests.unit.test_portal_static import code_of
from tests.unit.test_portal_static import read as static
from tests.unit.test_review import pin, reviewed, tool
from tests.unit.test_reviewchange import server as view_server
from zoeymcp.common.pinhash import pin_of
from zoeymcp.common.policy.schema import GatewayLimits
from zoeymcp.common.yamlload import load_mapping
from zoeymcp.gateway import pins
from zoeymcp.portal.app import CLEAR_WORDS
from zoeymcp.vault.reviewjobs import Work, read_result

from .flows import prepared_action, set_up, status_reason, step_up
from .rig import PortalRig, rig_policy, running
from .test_policy_managed import drafted, head, managed, saved, world_of
from .test_policy_managed import reviewed_job as managed_job
from .test_review import World, gateway_answers, notes_entries, poller

RLO = "\u202e"
ZWSP = "\u200b"
# Text that would be markup if a page parsed it, on both sides of the diff.
MARKUP = '<img src=x onerror=alert(1)> & "quoted"'
OLD = f"Finds notes. {MARKUP}"
NEW = f"Finds notes, and sends them on. {MARKUP}"


def projected(description: str, *, hidden: str = "") -> dict[str, Any]:
    """``search``'s definition as the gateway pins it, with ``hidden`` added to its description
    afterwards (a definition the gateway's own listing would report invalid)."""
    definition = dict(pins.project_and_pin(tool("search", description)).definition)
    definition["description"] += hidden
    return definition


def served(old: dict[str, Any]) -> dict[str, Any]:
    """The policy's notes entry: ``search`` included as allow, pinned at ``old``."""
    return {
        "tools": {"include": ["search"], "allow": ["search"]},
        "review": {"search": pin_of(old)},
    }


def drift_report(old: dict[str, Any], *, kept: bool = True, **marks: Any) -> dict[str, Any]:
    """The gateway's review of notes listing ``search`` changed, and ``other`` besides."""
    policy = view_server(["search"], [], {"search": pin_of(old)})
    defs = {pin_of(old): old} if kept else {}
    listed = [tool("search", NEW), tool("other")]
    return reviewed(listed, policy, defs=defs, **marks)


@pytest.fixture
def world(tmp_path: Path) -> Iterator[World]:
    with running(tmp_path, policy=notes_entries(**served(projected(OLD)))) as rig:
        page = rig.browser().page(rig.origin)
        set_up(rig, page, SoftAuthenticator())
        poller(rig)
        yield World(rig, page)


def review_again(world: World, report: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """**Review again**: a fresh review, answered with ``report``, read once done."""
    queued = world.page.fetch("POST", "/api/review/notes", json={"fresh": True})
    assert queued.status_code == 200, queued.text
    assert queued.json()["reused"] is False
    gateway_answers(world.rig, report)
    job: str = queued.json()["job"]
    answer = world.page.fetch("GET", f"/api/review/jobs/{job}")
    assert answer.status_code == 200, answer.text
    read: dict[str, Any] = answer.json()
    return job, read


def row(read: dict[str, Any], name: str) -> dict[str, Any]:
    found: dict[str, Any] = next(r for r in read["tools"] if r["name"] == name)
    return found


def diffed(world: World, job: str, **more: Any) -> dict[str, Any]:
    body = {"include": ["search"], "allow": ["search"], "approve": [], **more}
    answer = world.page.fetch("POST", f"/api/review/jobs/{job}/diff", json=body)
    assert answer.status_code == 200, answer.text
    made: dict[str, Any] = answer.json()
    return made


def test_a_server_changes_a_tool_after_review(world: World) -> None:
    """J1, declarative: Review again, the two columns and the diff, Accept the new definition,
    fragment 2 with the new pin; nothing is saved."""
    rig, page = world.rig, world.page
    old = projected(OLD)
    job, read = review_again(world, drift_report(old))
    search = row(read, "search")
    assert (search["state"], search["pinned"], search["pin"]) == (
        "drift",
        pin_of(old),
        pin_of(projected(NEW)),
    )
    reviewed_text = "\n".join("".join(chunks) for chunks in search["reviewed_lines"])
    assert json.loads(reviewed_text) == old
    assert search["reviewed_missing"] is False
    diff = ["".join(chunks) for chunks in search["diff_lines"]]
    assert diff[:2] == ["--- reviewed", "+++ now"]
    assert any(line.startswith("+") and "and sends them on" in line for line in diff)
    assert all(set(f) == {"level", "pointer_shown", "message_shown"} for f in search["findings"])
    assert search["prefill"] == "allow"
    before = rig.policy_file.read_bytes()
    made = diffed(world, job, repin=["search"])
    entry = load_mapping(made["diff"]["yaml"])["gateway"]["servers"]["notes"]
    assert entry["review"] == {"search": pin_of(projected(NEW))}
    assert entry["tools"] == {"include": ["search"], "allow": ["search"], "approve": []}
    assert f"# changed: search (was {pin_of(old)})" in made["diff"]["yaml"]
    assert not [f for f in made["diff"]["check"] if f["level"] == "error"]
    assert rig.policy_file.read_bytes() == before
    # Asked again at the same view, the portal's finished review is handed back unless fresh.
    again = page.fetch("POST", "/api/review/notes", json={}).json()
    assert (again["job"], again["reused"]) == (job, True)
    # Once a re-pin is committed and reloaded, fragment 2 from the old review would undo it.
    rig.reload(rig_policy(rig.portal_port, **notes_entries(**served(projected(NEW)))))
    stale = page.fetch(
        "POST",
        f"/api/review/jobs/{job}/diff",
        json={"include": ["search"], "allow": ["search"], "approve": [], "repin": ["search"]},
    )
    assert status_reason(stale) == (409, "review_stale")


def test_the_fresh_key_and_the_diffs_new_keys_are_checked(world: World) -> None:
    page = world.page
    for body in ({"fresh": "yes"}, {"fresh": 1}, {"fresh": True, "other": 1}):
        refused = page.fetch("POST", "/api/review/notes", json=body)
        assert status_reason(refused) == (400, "bad_body"), body
    job, _ = review_again(world, drift_report(projected(OLD)))
    path = f"/api/review/jobs/{job}/diff"
    base = {"include": ["search"], "allow": ["search"], "approve": []}
    for more, reason in (
        ({"repin": "search"}, (400, "bad_body")),
        ({"decline_rest": "yes"}, (400, "bad_body")),
        ({"repin": ["other"]}, (422, "diff_invalid")),
        ({"decline": ["search"]}, (422, "diff_invalid")),
    ):
        assert status_reason(page.fetch("POST", path, json={**base, **more})) == reason, more


def test_without_the_reviewed_copy_the_new_definition_is_shown_whole(world: World) -> None:
    _, read = review_again(world, drift_report(projected(OLD), kept=False))
    search = row(read, "search")
    assert (search["state"], search["reviewed_missing"]) == ("drift", True)
    assert (search["reviewed_lines"], search["diff_lines"]) == ([], [])
    assert search["definition_lines"]


def test_a_tool_that_flipped_back_reads_marked(world: World) -> None:
    """J13's screen half: the server lists the reviewed definition again and the mark holds; the
    row is ``marked``, nothing to re-pin (Clear the marks is step 9's)."""
    old = projected(OLD)
    policy = view_server(["search"], [], {"search": pin_of(old)})
    report = reviewed(
        [tool("search", OLD), tool("other")],
        policy,
        marks=frozenset({("search", pin_of(old))}),
    )
    job, read = review_again(world, report)
    search = row(read, "search")
    assert (search["state"], search["pin"], search["diff_lines"]) == ("marked", pin_of(old), [])
    refused = world.page.fetch(
        "POST",
        f"/api/review/jobs/{job}/diff",
        json={"include": ["search"], "allow": ["search"], "approve": [], "repin": ["search"]},
    )
    assert status_reason(refused) == (422, "diff_invalid")
    assert "search hasn't drifted" in refused.json()["error"]


# --- Clear the marks (J13, M6 design J.4) ---------------------------------------------------------

AGAIN = {
    "do": "review",
    "label": "Review again",
    "command": "zoeymcp review notes --via vault --fresh",
    "via": "exec",
}


def flipped_back(*, marked: bool = True) -> dict[str, Any]:
    """The gateway's review of notes with ``search`` listed at its pin again, still marked."""
    old = projected(OLD)
    policy = view_server(["search"], [], {"search": pin_of(old)})
    marks = frozenset({("search", pin_of(old))}) if marked else frozenset()
    return reviewed([tool("search", OLD), tool("other")], policy, marks=marks)


def advertise(rig: PortalRig, kinds: frozenset[Work]) -> None:
    """The gateway's poll waiting, advertising ``kinds``."""
    rig.call(lambda: rig.vault.app._reviews.poll_began(kinds))


def gateway_clears(rig: PortalRig, said: dict[str, list[str]]) -> None:
    """The gateway's side of a clear job, on the vault's loop: claimed by a poll that runs
    clears, and answered with the review after it and what it did (``cleared`` or
    ``not_clean``)."""
    marked = "not_clean" in said
    report = {**json.loads(json.dumps(flipped_back(marked=marked))), **said}

    def run() -> None:
        app = rig.vault.app
        table = app._reviews
        for job in table.claim(app.view_digest, frozenset({"review", "clear"})):
            body = {"v": 1, "job": job.id, "server": job.server, "report": report}
            table.post(read_result(body, GatewayLimits()))
        app._wake_reviews()

    rig.call(run)


def test_clear(tmp_path: Path) -> None:
    """J13: the tool flipped back reads marked; Clear the marks asks for a passkey (tool.clear),
    the vault queues a clear job, the gateway clears the marks once every included tool
    matches, and the page reads the job as a review: done, naming the marks cleared. While the
    tool still doesn't match, the job fails clear_not_clean, naming it, with a fresh review as
    the way on (FM-28)."""
    authenticator = SoftAuthenticator()
    with running(tmp_path, policy=notes_entries(**served(projected(OLD)))) as rig:
        page = rig.browser().page(rig.origin)
        set_up(rig, page, authenticator)
        advertise(rig, frozenset({"review", "clear"}))
        world = World(rig, page)
        _, read = review_again(world, flipped_back())
        assert row(read, "search")["state"] == "marked"
        held = prepared_action(page, "tool.clear", {"server": "notes"})
        assert held["summary"] == [
            ["Clear the drift marks of", "notes"],
            ["What happens", CLEAR_WORDS],
        ]
        before = rig.policy_file.read_bytes()
        confirmed = step_up(page, authenticator, "tool.clear", {"server": "notes"})
        assert confirmed.status_code == 200, confirmed.text
        job = confirmed.json()["job"]
        assert confirmed.json() == {"job": job, "server_shown": "notes", "state": "queued"}
        gateway_clears(rig, {"cleared": ["search"]})
        answer = page.fetch("GET", f"/api/review/jobs/{job}")
        assert answer.status_code == 200, answer.text
        done = answer.json()
        assert (done["state"], done["cleared_shown"], done["next"]) == ("done", ["search"], [])
        assert row(done, "search")["state"] == "ok"
        # What drift.js reads of a clear job's answer is what the portal sends.
        fields = set(re.findall(r"\bread\.([a-z_]+)", code_of(static("drift.js"))))
        assert fields <= set(done)
        assert {"state", "server_shown", "cleared_shown"} <= fields
        # FM-28: a clear while the tool still drifts; the vault's sentence names it.
        again = step_up(page, authenticator, "tool.clear", {"server": "notes"})
        gateway_clears(rig, {"not_clean": ["search"]})
        refused = page.fetch("GET", f"/api/review/jobs/{again.json()['job']}")
        assert status_reason(refused) == (409, "clear_not_clean")
        assert refused.json()["error"] == (
            "These still don't match their pins: search. No mark was cleared; review the server "
            "again."
        )
        assert refused.json()["next"] == [AGAIN]
        assert refused.json()["state"] == "failed"
        assert rig.policy_file.read_bytes() == before  # a clear never changes the policy
        assert rig.logged("step_up_confirmed", lambda line: line["action"] == "tool.clear")
        assert rig.logged(
            "review_requested", lambda line: line.get("clear") is True and line["owner"] == "portal"
        )


def test_clear_unsupported_and_unknown(tmp_path: Path) -> None:
    """FM-29 in the portal: while only an older gateway polls, the clear's run is refused
    clear_unsupported, with the gateway's own --clear as the way on, and nothing is queued; a
    server the policy doesn't have is refused at the plan, before any passkey."""
    authenticator = SoftAuthenticator()
    with running(tmp_path, policy=notes_entries(**served(projected(OLD)))) as rig:
        page = rig.browser().page(rig.origin)
        set_up(rig, page, authenticator)
        poller(rig)  # an older gateway's poll: it advertises nothing
        refused = step_up(page, authenticator, "tool.clear", {"server": "notes"})
        assert status_reason(refused) == (409, "clear_unsupported")
        assert (
            "run zoeymcp review notes --clear in the gateway's container" in refused.json()["error"]
        )
        assert refused.json()["next"] == [
            {
                "do": "clear",
                "label": "Clear the marks in the gateway's container",
                "command": "zoeymcp review notes --clear",
            }
        ]
        assert rig.call(lambda: len(rig.vault.app._reviews)) == 0
        unknown = page.fetch(
            "POST", "/api/actions", json={"kind": "tool.clear", "data": {"server": "other"}}
        )
        assert status_reason(unknown) == (404, "review_unknown_server")
        assert unknown.json()["next"] == []


def test_review_refusals_carry_next(world: World) -> None:
    """D-200 in the portal: a refusal about a server names its way on, which the page's refusal
    renders as a button (review.js's renderSteps): a busy server, a fresh review."""
    page = world.page
    assert page.fetch("POST", "/api/review/notes", json={"fresh": True}).status_code == 200
    busy = page.fetch("POST", "/api/review/notes", json={"fresh": True})
    assert status_reason(busy) == (409, "review_busy")
    assert busy.json()["next"] == [AGAIN]
    unknown = page.fetch("POST", "/api/review/other", json={})
    assert (status_reason(unknown), unknown.json()["next"]) == ((404, "review_unknown_server"), [])


def test_record_the_rest_as_declined(world: World) -> None:
    """J.3: every listed tool left out is written to declined at the pin shown."""
    job, _ = review_again(world, drift_report(projected(OLD)))
    made = diffed(world, job, decline_rest=True)
    entry = load_mapping(made["diff"]["yaml"])["gateway"]["servers"]["notes"]
    assert entry["declined"] == {"other": pin("other")}
    assert made["diff"]["yaml"].startswith(
        "# zoeymcp: review of notes (2 of 2). Replace the tools:, review: and declined: blocks"
    )


def test_hostile_text_on_both_sides(tmp_path: Path) -> None:
    """K.5 on both columns and the diff: markup is text, and a hidden or bidi character in the
    pinned copy or the listed one reaches the page as an escape, never as the character."""
    old = projected(OLD, hidden=RLO)
    with running(tmp_path, policy=notes_entries(**served(old))) as rig:
        page = rig.browser().page(rig.origin)
        set_up(rig, page, SoftAuthenticator())
        poller(rig)
        report = drift_report(old)
        [search] = [e for e in report["tools"] if e["name"] == "search"]
        search["definition"]["description"] += ZWSP
        search["pin"] = pin_of(search["definition"])
        _, read = review_again(World(rig, page), report)
    found = row(read, "search")
    text = json.dumps(found, ensure_ascii=False)
    assert RLO not in text
    assert ZWSP not in text
    for lines, escape in (
        (found["reviewed_lines"], "\\u202e"),
        (found["definition_lines"], "\\u200b"),
        (found["diff_lines"], "\\u202e"),
        (found["diff_lines"], "\\u200b"),
    ):
        assert any(escape in chunk for chunks in lines for chunk in chunks), escape
    assert any(MARKUP.replace('"', '\\"') in "".join(c) for c in found["reviewed_lines"])


# --- managed mode (step 15a): J1's re-pin and J2's declines are saves ---------------------------


def test_a_server_changes_a_tool_after_review_managed(tmp_path: Path) -> None:
    """J1, managed: **Accept the new definition** on the drifted row is a ``tool.repin`` draft
    whose plan names both pins (re-pinned: you read both definitions) and no restart; one
    passkey writes revision 2 with the new pin, logged ``tool_repinned``. The old review is then
    stale: a draft from it would undo the re-pin (J.2)."""
    entry = {**served(projected(OLD)), "era": "modern"}
    with world_of(tmp_path, managed(**entry)) as world:
        rig = world.rig
        old, new = projected(OLD), projected(NEW)
        job, read = managed_job(world, drift_report(old))
        assert row(read, "search")["state"] == "drift"
        draft = drafted(world, job, include=["search"], allow=["search"], repin=["search"])
        assert (draft["kind"], draft["base"]) == ("tool.repin", 1)
        summary = draft["summary"]
        changed = f"{pin_of(old)} -> {pin_of(new)} (re-pinned: you read both definitions)"
        assert ["gateway.servers.notes.review.search", changed] in summary
        assert summary[-1] == ["No restart needed", ""]
        done = saved(world, draft)
        assert done["revision"] == 2
        assert head(rig)["review"] == {"search": pin_of(new)}
        [line] = rig.lines("tool_repinned")
        assert (line["server"], line["name"], line["revision"]) == ("notes", "search", 2)
        body = {"include": ["search"], "allow": ["search"], "approve": [], "repin": ["search"]}
        stale = world.page.fetch("POST", f"/api/review/jobs/{job}/diff", json=body)
        assert status_reason(stale) == (409, "review_stale")


def test_new_tools_declined_in_a_save(tmp_path: Path) -> None:
    """J2, managed: **Record the rest as declined** writes every listed tool left out to
    ``declined`` at the pin shown, in a ``policy.save`` (a decline is a change of its own)."""
    entry = {**served(projected(OLD)), "era": "modern"}
    with world_of(tmp_path, managed(**entry)) as world:
        job, _ = managed_job(world, drift_report(projected(OLD)))
        draft = drafted(world, job, include=["search"], allow=["search"], decline_rest=True)
        assert draft["kind"] == "policy.save"
        assert ["gateway.servers.notes.declined.other", "added"] in draft["summary"]
        saved(world, draft)
        assert head(world.rig)["declined"] == {"other": pin("other")}
