"""Managed saves on the review screen over the real API (M6 design G.3-G.7, J.3, J.4, M.3; Y6-Y9,
Y11, Q8, Q27; FM-14, FM-18).

The vault starts managed: its policy file seeds revision 1 (F.3), and from then on the portal's
saves are revisions. The review jobs are the real ones, the gateway played on the vault's loop as
in ``test_review.py``. In managed mode the review diff route answers a draft (G.4): the change the
choices make, planned on the head, with the kind the planner requires and the summary the dialog
shows; the page prepares that kind with ``{draft, base}`` and confirms it with a passkey, and the
save runs through ``ManagedPolicy.write``. Each move to ``allow`` is its own row, first among the
weakenings, followed by every chunk of the definition it allows (G.7 row 2), and is logged
``tool_allowed``; **Select suggested** after **Clear** makes no move (its choices built here from
each row's ``prefill``, as ``review.js`` builds them: ``tests.fakes.browser.Page`` runs no
script); a re-pinned ``allow`` tool kept ``allow`` is its own row and logs ``kept=true``. Two
sessions on one base: the second's confirm is ``409 changed``, its first row the head that moved,
then the same save planned on the new head (FM-14, G.7). A gateway that doesn't take the view:
the answer says ``pending``, and health says so after the grace (FM-18). A revision the vault
saved and couldn't install is its own ``500 saved_not_running``, not a dialog's ``changed``
(N.2). What the portal can't widen is refused before any prompt, or at the confirm with a valid
assertion, with nothing written (Y6, Y7, Y11, Y17).

The Policy page (step 15b; H.1-H.4, J6): the history and a revision's diff, hostile text shown
revealed; a rollback that undoes an onboarding is the portal's, its unused store entry listed
first; one that brings back a removed client is ``rollback_revives``, and one per wider row of
H.2's table a rollback reaches is ``portal_widens`` (Y6); a target in quarantine is refused, in
the dialog at the confirm, while one whose parent is in quarantine is still a target; a head that
moved is worded for the Policy page; and a 400-row plan is confirmed whole, a 401st row refused
(Y9). The
host's revisions they start from are written as the admin socket writes an import.
"""

from __future__ import annotations

import copy
import json
import time
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import httpx
import pytest
from mcp.types import Tool

from tests.fakes.authenticator import SoftAuthenticator
from tests.fakes.browser import Page
from tests.unit.test_review import reviewed, tool
from tests.unit.test_reviewchange import READ_ONLY, WRITES, definition, hinted, pin_of
from tests.unit.test_reviewchange import server as view_server
from zoeymcp.common.policy.change import (
    AddCredential,
    AddRoute,
    PolicyChange,
    SetServerReview,
)
from zoeymcp.common.policy.plan import KEPT_ALLOW_TEXT, MOVE_TEXT, REINCLUDE_TEXT, document
from zoeymcp.common.policy.schema import OAuth2Credential, Policy, Route, Tools
from zoeymcp.portal import app as portal_app
from zoeymcp.portal.app import UNUSED_LABEL, UNUSED_ROLLBACK
from zoeymcp.portal.drafts import Facts
from zoeymcp.vault.bindings import derive_binding
from zoeymcp.vault.gatewaykeys import GatewayKeyError
from zoeymcp.vault.managed import (
    GATEWAY_APPLY_GRACE,
    Shaped,
    WriteRefused,
    Written,
    import_shaped,
    read_revision,
)
from zoeymcp.vault.policystart import revision_file
from zoeymcp.vault.statusreport import Report, ServerStatus

from .flows import login, set_up, status_reason
from .rig import PortalRig, running
from .test_review import gateway_answers, notes_entries, poller

VIEW = "sha256:" + "f" * 64
LIST = hinted("list", "Lists notes.", READ_ONLY)
GET = hinted("get", "Gets a note.", READ_ONLY)
OLD = hinted("old", "An old tool.", READ_ONLY)
WRITE = tool("write", "Writes a note.")


def managed(**server: Any) -> dict[str, Any]:
    """A managed deployment of notes: the rig's policy file seeds revision 1 (F.3)."""
    return {**notes_entries(**server), "mode": "managed"}


def entry(approve: Sequence[Tool], allow: Sequence[Tool] = ()) -> dict[str, Any]:
    """The policy's notes entry: these tools included, each pinned, its era the one the fake
    reviews report (an era learned is a change of its own: a save's, not a re-pin's, Y7)."""
    every = [*allow, *approve]
    return {
        "era": "modern",
        "tools": {
            "include": [t.name for t in every],
            "allow": [t.name for t in allow],
            "approve": [t.name for t in approve],
        },
        "review": {t.name: pin_of(t) for t in every},
    }


@dataclass
class World:
    rig: PortalRig
    page: Page
    passkey: SoftAuthenticator


@contextmanager
def world_of(tmp_path: Path, policy: dict[str, Any]) -> Iterator[World]:
    with running(tmp_path, policy=policy) as rig:
        page = rig.browser().page(rig.origin)
        passkey = SoftAuthenticator()
        set_up(rig, page, passkey)
        poller(rig)
        yield World(rig, page, passkey)


def report_of(
    listed: list[Tool], approve: Sequence[Tool], allow: Sequence[Tool] = ()
) -> dict[str, Any]:
    """The gateway's review of notes listing ``listed``, under a policy including ``allow`` and
    ``approve``."""
    included = [*allow, *approve]
    policy = view_server(
        [t.name for t in allow], [t.name for t in approve], {t.name: pin_of(t) for t in included}
    )
    return reviewed(listed, policy)


def reviewed_job(world: World, report: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """A fresh review of notes, answered with ``report``, read once done."""
    queued = world.page.fetch("POST", "/api/review/notes", json={"fresh": True})
    assert queued.status_code == 200, queued.text
    gateway_answers(world.rig, report)
    job: str = queued.json()["job"]
    read = world.page.fetch("GET", f"/api/review/jobs/{job}")
    assert read.status_code == 200, read.text
    answer: dict[str, Any] = read.json()
    assert answer["state"] == "done", answer
    return job, answer


def drafted(world: World, job: str, **body: Any) -> dict[str, Any]:
    """The review diff route in managed mode: the draft and its plan (G.4)."""
    choices = {"include": [], "allow": [], "approve": [], **body}
    made = world.page.fetch("POST", f"/api/review/jobs/{job}/diff", json=choices)
    assert made.status_code == 200, made.text
    answer: dict[str, Any] = made.json()
    assert set(answer) == {"draft", "base", "kind", "summary"}, answer
    return answer


def prepared(world: World, kind: str, data: dict[str, Any]) -> dict[str, Any]:
    answer = world.page.fetch("POST", "/api/actions", json={"kind": kind, "data": data})
    assert answer.status_code == 200, answer.text
    held: dict[str, Any] = answer.json()
    return held


def confirmed(world: World, held: dict[str, Any], page: Page | None = None) -> httpx.Response:
    page = page or world.page
    assertion = world.passkey.get(held["options"], page.origin).body()
    return page.fetch(
        "POST", f"/api/actions/{held['action']}/confirm", json={"credential": assertion}
    )


def saved(world: World, draft: dict[str, Any]) -> dict[str, Any]:
    """The draft prepared as the kind its answer names, and confirmed with the passkey."""
    held = prepared(world, draft["kind"], {"draft": draft["draft"], "base": draft["base"]})
    done = confirmed(world, held)
    assert done.status_code == 200, done.text
    answer: dict[str, Any] = done.json()
    return answer


def head(rig: PortalRig) -> dict[str, Any]:
    """The running policy's notes entry, as the vault runs it."""
    managed_ = rig.vault.managed
    assert managed_ is not None
    gateway = managed_.policy.gateway
    assert gateway is not None
    found: dict[str, Any] = gateway.servers["notes"].model_dump(mode="json", by_alias=True)
    return found


def revision(rig: PortalRig) -> int:
    assert rig.vault.managed is not None
    return rig.vault.managed.revision


def state_files(rig: PortalRig) -> object:
    return sorted((p.name, p.read_bytes()) for p in rig.state.rglob("*") if p.is_file())


def labels(summary: list[list[str]]) -> list[str]:
    return [label for label, _ in summary]


# --- Q27, Y7: a review save's moves to allow --------------------------------------------------


def test_review_save_moves_to_allow(tmp_path: Path) -> None:
    """Q27, Y7, J3: a save dropping ``old`` (approve) is revision 2; the next moving ``list`` and
    ``get`` from approve and re-including ``old`` as allow lists three move rows first, each
    followed by its definition, and one passkey writes exactly those three, each logged
    ``tool_allowed``. ``old`` starts at ``approve`` on the review (``prefill``: the ratchet's
    ``approved`` set, J.3). A confirm the gateway's status marks a moved tool for meanwhile is
    ``409 changed``, its first row ``allow_marked``, with nothing written."""
    with world_of(tmp_path, managed(**entry([LIST, GET, OLD]))) as world:
        rig = world.rig
        job, _ = reviewed_job(world, report_of([LIST, GET, OLD], [LIST, GET, OLD]))
        dropped = drafted(
            world, job, include=["list", "get"], approve=["list", "get"], decline_rest=False
        )
        assert (dropped["kind"], dropped["base"]) == ("policy.save", 1)
        assert saved(world, dropped)["revision"] == 2
        assert head(rig)["tools"]["include"] == ["list", "get"]
        job, read = reviewed_job(world, report_of([LIST, GET, OLD], [LIST, GET]))
        prefill = {row["name"]: row["prefill"] for row in read["tools"]}
        assert prefill == {"list": "approve", "get": "approve", "old": "approve"}
        every = ["list", "get", "old"]
        draft = drafted(world, job, include=every, allow=every, decline_rest=False)
        assert (draft["kind"], draft["base"]) == ("policy.save", 2)
        summary = draft["summary"]
        assert summary[0][0] == "Revision"
        assert summary[0][1].startswith("3, from 2 (by you, ")
        assert summary[0][1].endswith(": 2 is the head)")
        moves = [row for row in summary if row[0].startswith("notes.")]
        assert moves[:3] == [
            ["notes.get", MOVE_TEXT.format(name="get")],
            ["notes.list", MOVE_TEXT.format(name="list")],
            ["notes.old", REINCLUDE_TEXT.format(name="old")],
        ]
        # Each move row is followed by its definition, every chunk a row, the first naming the
        # pin it allows; the moves come before any other row but the revision.
        first = labels(summary).index("notes.get")
        assert first == 1
        assert summary[2] == [f"get, as pinned ({pin_of(GET)})", "{"]
        for name, found in (("get", GET), ("list", LIST), ("old", OLD)):
            at = labels(summary).index(f"notes.{name}")
            assert summary[at + 1][0] == f"{name}, as pinned ({pin_of(found)})"
        rows = labels(summary)
        assert rows.index("notes.old") < min(
            i
            for i, label in enumerate(rows)
            if label.startswith("gateway.") or label == "No restart needed"
        )
        # The gateway's status marks list meanwhile: the confirm's re-plan refuses the move.
        held = prepared(world, draft["kind"], {"draft": draft["draft"], "base": 2})
        marked = ServerStatus("remote", ("ready",), "modern", 3, 2, marked=("list",))
        rig.call(lambda: rig.vault.app.keep_status(Report(VIEW, 1, {"notes": marked})))
        before = state_files(rig)
        refused = confirmed(world, held)
        assert status_reason(refused) == (409, "changed")
        assert refused.json()["now"][0][0] == "Refused (allow_marked)"
        assert state_files(rig) == before
        assert revision(rig) == 2
        # The status says nothing is marked: the same draft saves, the three moves logged.
        quiet = ServerStatus("remote", ("ready",), "modern", 3, 2)
        rig.call(lambda: rig.vault.app.keep_status(Report(VIEW, 1, {"notes": quiet})))
        done = saved(world, draft)
        assert (done["revision"], done["already_saved"], done["gateway"]) == (3, False, "pending")
        tools = head(rig)["tools"]
        assert (sorted(tools["allow"]), tools["approve"]) == (sorted(every), [])
        allowed = rig.lines("tool_allowed")
        assert sorted(line["name"] for line in allowed) == sorted(every)
        assert {line["revision"] for line in allowed} == {3}
        [line] = [line for line in rig.lines("policy_saved") if line["revision"] == 3]
        assert (line["write_kind"], line["base"]) == ("policy.save", 2)


def test_a_lone_reinclude_is_a_save(tmp_path: Path) -> None:
    """G.5 rule 1 (owner pick 2): re-including a once-approved tool as allow, alone, is a
    ``policy.save`` whose row says so, never a ``tool.allow``: prepared as one it is
    ``kind_mismatch``."""
    with world_of(tmp_path, managed(**entry([LIST, OLD]))) as world:
        job, _ = reviewed_job(world, report_of([LIST, OLD], [LIST, OLD]))
        saved(world, drafted(world, job, include=["list"], approve=["list"], decline_rest=False))
        job, _ = reviewed_job(world, report_of([LIST, OLD], [LIST]))
        body = {"include": ["list", "old"], "approve": ["list"], "allow": ["old"]}
        draft = drafted(world, job, decline_rest=False, **body)
        assert draft["kind"] == "policy.save"
        assert ["notes.old", REINCLUDE_TEXT.format(name="old")] in draft["summary"]
        data = {"draft": draft["draft"], "base": draft["base"]}
        refused = world.page.fetch(
            "POST", "/api/actions", json={"kind": "tool.allow", "data": data}
        )
        assert status_reason(refused) == (400, "kind_mismatch")


def test_select_suggested_makes_no_move(tmp_path: Path) -> None:
    """Q27-1, D-180: after **Clear**, **Select suggested** ticks every pinnable tool the server
    marks read-only at its row's ``prefill``: ``list``, included as approve, stays approve, and
    ``old``, dropped in an earlier save and in the ratchet's ``approved`` set, comes back
    approve. The draft has no move row."""
    with world_of(tmp_path, managed(**entry([LIST, OLD]))) as world:
        job, _ = reviewed_job(world, report_of([LIST, OLD, WRITE], [LIST, OLD]))
        saved(world, drafted(world, job, include=["list"], approve=["list"], decline_rest=False))
        job, read = reviewed_job(world, report_of([LIST, OLD, WRITE], [LIST]))
        # Clear, then Select suggested (review.js's selectSuggested, at each row's prefill).
        picked = [
            row
            for row in read["tools"]
            if row["name"] is not None and row["pinnable"] and row["suggested"] == "allow"
        ]
        body: dict[str, list[str]] = {"include": [], "allow": [], "approve": []}
        for row in picked:
            body["include"].append(row["name"])
            body[row["prefill"]].append(row["name"])
        assert body == {"include": ["list", "old"], "allow": [], "approve": ["list", "old"]}
        draft = drafted(world, job, decline_rest=False, **body)
        words = [value for _, value in draft["summary"]]
        assert not [w for w in words if "no prompt" in w]
        assert draft["kind"] == "policy.save"


def test_kept_allow_is_logged(tmp_path: Path) -> None:
    """Q8, Q27: ``a`` is allow; its new definition isn't marked read-only, and the operator
    re-pins it and keeps it allow. The draft is a ``tool.repin`` whose kept-allow row is its own,
    with the new definition; the save logs ``tool_repinned`` and ``tool_allowed`` with
    ``kept``."""
    old_a = hinted("a", "Reads a thing.", READ_ONLY)
    new_a = hinted("a", "Reads a thing.", WRITES)
    with world_of(tmp_path, managed(**entry([], [old_a]))) as world:
        policy = view_server(["a"], [], {"a": pin_of(old_a)})
        report = reviewed([new_a], policy, defs={pin_of(old_a): definition(old_a)})
        job, read = reviewed_job(world, report)
        assert [(row["state"], row["proposed"]) for row in read["tools"]] == [("drift", True)]
        draft = drafted(world, job, include=["a"], allow=["a"], repin=["a"], decline_rest=False)
        assert draft["kind"] == "tool.repin"
        summary = draft["summary"]
        assert ["notes.a", KEPT_ALLOW_TEXT.format(name="a")] in summary
        at = labels(summary).index("notes.a")
        assert summary[at + 1][0] == f"a, as pinned ({pin_of(new_a)})"
        assert saved(world, draft)["revision"] == 2
        assert head(world.rig)["review"]["a"] == pin_of(new_a)
        [repinned] = world.rig.lines("tool_repinned")
        [kept] = world.rig.lines("tool_allowed")
        assert (repinned["name"], kept["name"], kept["kept"]) == ("a", "a", True)


# --- FM-14, FM-18 ------------------------------------------------------------------------------


def test_two_sessions(tmp_path: Path) -> None:
    """FM-14, G.10: two sessions save on revision 1. The first writes revision 2; the second's
    confirm is ``409 changed``, its first row the head that moved, worded for the portal
    (OPS-18), and nothing more is written."""
    with world_of(tmp_path, managed(**entry([LIST, GET]))) as world:
        rig = world.rig
        other = rig.browser().page(rig.origin)
        assert login(other, world.passkey).status_code == 200
        job, _ = reviewed_job(world, report_of([LIST, GET], [LIST, GET]))
        mine = drafted(world, job, include=["list"], approve=["list"], decline_rest=False)
        queued = other.fetch("POST", "/api/review/notes", json={})
        assert queued.status_code == 200, queued.text
        gateway_answers(rig, report_of([LIST, GET], [LIST, GET]))
        theirs_job = queued.json()["job"]
        assert other.fetch("GET", f"/api/review/jobs/{theirs_job}").json()["state"] == "done"
        body = {"include": ["get"], "allow": [], "approve": ["get"], "decline_rest": False}
        made = other.fetch("POST", f"/api/review/jobs/{theirs_job}/diff", json=body)
        assert made.status_code == 200, made.text
        theirs = made.json()
        data = {"draft": theirs["draft"], "base": theirs["base"]}
        answer = other.fetch("POST", "/api/actions", json={"kind": theirs["kind"], "data": data})
        held = answer.json()
        assert saved(world, mine)["revision"] == 2
        refused = confirmed(world, held, other)
        assert status_reason(refused) == (409, "changed")
        first = refused.json()["now"][0]
        assert first[0] == "Revision"
        assert first[1].startswith("The policy moved to revision 2, saved ")
        assert first[1].endswith("press Save again to plan it on revision 2.")
        # Then the same save planned on revision 2, as Save would plan it (G.7).
        assert refused.json()["now"][1][0] == "Revision"
        assert refused.json()["now"][1][1].startswith("3, from 2 (by you, ")
        assert revision(rig) == 2
        # Before any prompt, the same refusal is the dialog's text.
        again = other.fetch("POST", "/api/actions", json={"kind": theirs["kind"], "data": data})
        assert status_reason(again) == (409, "policy_moved")
        assert "rows" not in again.json()


def test_gateway_down(tmp_path: Path) -> None:
    """FM-18: with no gateway taking the view, the save is written and installed, and its
    answer says the gateway is ``pending`` and that it takes the view within seconds; past the
    grace health says the gateway is still on an older view (``gateway_view_behind``)."""
    with world_of(tmp_path, managed(**entry([LIST]))) as world:
        rig = world.rig
        job, _ = reviewed_job(world, report_of([LIST, GET], [LIST]))
        done = saved(
            world, drafted(world, job, include=["list"], approve=["list"], decline_rest=True)
        )
        assert (done["revision"], done["gateway"]) == (2, "pending")
        assert done["next"] == [
            {"do": "wait_gateway", "label": "The gateway takes the new view within seconds"}
        ]
        assert head(rig)["declined"] == {"get": pin_of(GET)}
        quiet = ServerStatus("remote", ("ready",), "modern", 1, 1)
        rig.call(lambda: rig.vault.app.keep_status(Report(VIEW, 1, {"notes": quiet})))

        def findings() -> list[str]:
            answer = world.page.fetch("GET", "/api/health")
            assert answer.status_code == 200, answer.text
            return [f["code"] for f in answer.json()["gateway"]["findings"]]

        assert "gateway_view_behind" not in findings()
        managed_ = rig.vault.managed
        assert managed_ is not None
        later = time.time() + GATEWAY_APPLY_GRACE + 1
        managed_._wall = lambda: later
        assert "gateway_view_behind" in findings()


# --- Y6, Y7, Y11: what the portal can't save ----------------------------------------------------


def _injected(world: World, change: PolicyChange, kind: str = "policy.save") -> dict[str, Any]:
    """A draft holding ``change``, as if the review diff route had built it: the planner, not
    the page or the route, holds the portal's bounds (Y6)."""
    session = (
        next(iter(world.rig.app.drafts._by_session)) if world.rig.app.drafts._by_session else None
    )
    assert session is not None
    draft = world.rig.app.drafts.hold(
        session=session,
        base=revision(world.rig),
        change=change,
        job="job",
        report_digest="sha256:" + "0" * 64,
        kind=kind,
        facts=Facts(),
        now=time.time(),
    )
    return {"draft": draft.id, "base": draft.base}


def test_portal_cannot_widen(tmp_path: Path) -> None:
    """Y6, Y7, Y11 for the review screen's kinds: a draft the route didn't build (a credential
    taking env:, a route reusing a credential, a pin no review verified, a kind that isn't its
    diff) is refused at prepare with its reason, before any prompt, and a draft swapped after
    prepare is ``409 changed`` at confirm; nothing is written."""
    with world_of(tmp_path, managed(**entry([LIST]))) as world:
        rig = world.rig
        job, _ = reviewed_job(world, report_of([LIST, GET], [LIST]))
        good = drafted(world, job, include=["list"], approve=["list"], decline_rest=True)
        before = state_files(rig)
        env = OAuth2Credential.model_validate(
            {
                "kind": "oauth2",
                "token_url": "https://auth.other.example/token",
                "client_id": "c",
                "client_secret": "env:OTHER_SECRET",
                "grant": "client_credentials",
            }
        )
        route = Route.model_validate(
            {
                "name": "other",
                "prefix": "/other",
                "upstream": "https://api.other.example",
                "credential": "notes",
                "callers": ["gateway"],
                "rules": [{"methods": ["GET"], "paths": ["/x"]}],
            }
        )
        tools = Tools(include=["list", "get"], approve=["list", "get"])
        unverified = SetServerReview(
            "notes", tools, {"list": pin_of(LIST), "get": pin_of(GET)}, declined={}
        )
        cases = [
            (PolicyChange("t", (AddCredential("other", env),)), "policy.save", "portal_env_ref"),
            (PolicyChange("t", (AddRoute(route),)), "policy.save", "route_reuses_credential"),
            (PolicyChange("t", (unverified,)), "policy.save", "review_stale"),
            (PolicyChange("t", (unverified,)), "tool.repin", "kind_mismatch"),
        ]
        for change, kind, reason in cases:
            data = _injected(world, change, kind)
            answer = world.page.fetch("POST", "/api/actions", json={"kind": kind, "data": data})
            assert answer.json()["reason"] == reason, (kind, answer.text)
            assert len(rig.app.actions) == 0
        # A draft that expired, or another session's, is unknown.
        stale = world.page.fetch(
            "POST",
            "/api/actions",
            json={"kind": "policy.save", "data": {"draft": "0" * 32, "base": 1}},
        )
        assert status_reason(stale) == (404, "draft_unknown")
        # Prepared on a draft the route built, then swapped: the confirm's plan differs.
        good = drafted(world, job, include=["list"], approve=["list"], decline_rest=True)
        held = prepared(world, good["kind"], {"draft": good["draft"], "base": good["base"]})
        [(session, draft)] = list(rig.app.drafts._by_session.items())
        swapped = PolicyChange("t", (unverified,))
        rig.app.drafts._by_session[session] = replace(draft, change=swapped)
        refused = confirmed(world, held)
        assert status_reason(refused) == (409, "changed")
        assert refused.json()["now"][0][0] == "Refused (review_stale)"
        assert state_files(rig) == before
        assert revision(rig) == 1


def test_the_diff_route_writes_nothing(tmp_path: Path) -> None:
    """M.2: the managed diff route holds a draft in memory and writes nothing: the store, the
    head and the passkey file are as they were."""
    with world_of(tmp_path, managed(**entry([LIST]))) as world:
        rig = world.rig
        job, _ = reviewed_job(world, report_of([LIST, GET], [LIST]))
        before = (state_files(rig), revision(rig), rig.vault.passkeys.document)
        drafted(world, job, include=["list", "get"], approve=["list", "get"])
        assert (state_files(rig), revision(rig), rig.vault.passkeys.document) == before
        assert len(rig.app.drafts) == 1


def test_a_managed_session_says_its_mode(tmp_path: Path) -> None:
    """M.1, M.7: the session answer names the mode and the head's revision, and a done review's
    way on is a save, or the host's export and import (``managed_next``, Y25)."""
    with world_of(tmp_path, managed(**entry([LIST]))) as world:
        session = world.page.fetch("GET", "/api/session").json()
        assert (session["mode"], session["revision"]) == ("managed", 1)
        _, read = reviewed_job(world, report_of([LIST], [LIST]))
        assert [step["do"] for step in read["next"]] == ["save", "export_policy", "import_policy"]


def test_managed_kinds_refuse_in_declarative_mode(tmp_path: Path) -> None:
    """M.3: a managed kind in declarative mode is ``policy_not_managed``; the session's mode is
    declarative and names no revision."""
    with world_of(tmp_path, notes_entries(**entry([LIST]))) as world:
        session = world.page.fetch("GET", "/api/session").json()
        assert (session["mode"], session["revision"]) == ("declarative", None)
        for kind in ("policy.save", "tool.repin"):
            data = {"draft": "0" * 32, "base": 1}
            answer = world.page.fetch("POST", "/api/actions", json={"kind": kind, "data": data})
            assert status_reason(answer) == (409, "policy_not_managed")


# --- N.2: a refusal of the vault's own is its own answer -----------------------------------------


def test_a_save_the_vault_cant_install(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """G.6 step 8, N.2 (FM-5 through the portal): the revision is committed, but the gateway-key
    state can't be written at the install. The confirm answers ``500 saved_not_running``, its
    catalogued text naming the revision, never a dialog's ``409 changed`` (which would say to
    prepare again); the next save is ``policy_not_running`` until the vault applies it."""
    with world_of(tmp_path, managed(**entry([LIST]))) as world:
        rig = world.rig
        job, _ = reviewed_job(world, report_of([LIST, GET], [LIST]))
        draft = drafted(world, job, include=["list"], approve=["list"], decline_rest=True)
        held = prepared(world, draft["kind"], {"draft": draft["draft"], "base": draft["base"]})

        def broken(policy: Policy) -> None:
            raise GatewayKeyError("the gateway key state can't be written")

        monkeypatch.setattr(rig.vault.app, "reload", broken)
        refused = confirmed(world, held)
        assert status_reason(refused) == (500, "saved_not_running")
        answer = refused.json()
        assert answer["error"].startswith("Saved as revision 2, but the vault couldn't apply it")
        assert "now" not in answer
        assert "rows" not in answer
        managed_ = rig.vault.managed
        assert managed_ is not None
        assert (managed_.revision, managed_.not_running) == (2, 2)
        again = world.page.fetch(
            "POST",
            f"/api/review/jobs/{job}/diff",
            json={"include": ["list"], "allow": ["list"], "approve": []},
        )
        assert status_reason(again) == (409, "policy_not_running")


# --- Y6, Y17: every widening of G.5 rule 2, through the portal's kinds ---------------------------

CLIENT_HASH = "sha256:" + "1" * 64


def guarded(**server: Any) -> dict[str, Any]:
    """A managed deployment with a client and a route of its own besides notes, so a widening
    can reach each (G.5 rule 2)."""
    policy = managed(**server)
    policy["gateway"]["clients"] = {"agent": {"token_sha256": CLIENT_HASH, "servers": ["notes"]}}
    api = {
        "name": "api",
        "prefix": "/api",
        "upstream": "https://api.other.example",
        "callers": ["gateway"],
        "rules": [{"methods": ["GET"], "paths": ["/x"]}],
    }
    policy["routes"] = [*policy["routes"], api]
    return policy


def _admin(data: dict[str, Any]) -> None:
    data["admin"]["origins"].append("https://other.example")


def _client(data: dict[str, Any]) -> None:
    data["gateway"]["clients"]["other"] = {"token_sha256": "sha256:" + "2" * 64}


def _token(data: dict[str, Any]) -> None:
    data["gateway"]["clients"]["agent"]["token_sha256"] = "sha256:" + "3" * 64


def _caller(data: dict[str, Any]) -> None:
    data["routes"][1]["callers"].append({"placeholder": "agent-placeholder-0001"})


def _limits(data: dict[str, Any]) -> None:
    data["gateway"].setdefault("limits", {})["call_timeout"] = 900


WIDENINGS = (
    pytest.param(_admin, "change admin.origins", id="admin"),
    pytest.param(_client, "add a client (gateway.clients.other)", id="client"),
    pytest.param(_token, "change the token of client agent", id="token"),
    pytest.param(_caller, "add a caller to route api", id="caller"),
    pytest.param(_limits, "change gateway.limits.call_timeout", id="limits"),
)


def widening(
    edit: Callable[[dict[str, Any]], None],
) -> Callable[[PolicyChange], Callable[[Policy], Policy]]:
    """The portal's candidate as a change the review couldn't make would build it: the
    change applied, then ``edit``; the planner, not the route, holds the bound (Y6)."""
    real = portal_app._candidate

    def candidate(change: PolicyChange) -> Callable[[Policy], Policy]:
        def candidate_of(policy: Policy) -> Policy:
            data = real(change)(policy).model_dump(mode="json", by_alias=True, exclude_unset=True)
            edit(data)
            return Policy.model_validate(data)

        return candidate_of

    return candidate


@pytest.mark.parametrize(("edit", "said"), WIDENINGS)
def test_the_portal_widens_nothing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    edit: Callable[[dict[str, Any]], None],
    said: str,
) -> None:
    """Y6, Y17 (G.5 rule 2): a save whose candidate changes ``admin``, adds a client, changes a
    token, adds a caller to a route or changes ``gateway.limits`` is ``403 portal_widens`` before
    any prompt, naming the host's export and import; prepared as the review built it and then
    swapped, the confirm with a valid assertion is ``409 changed``, its first row
    ``portal_widens``. Nothing is written either way."""
    with world_of(tmp_path, guarded(**entry([LIST]))) as world:
        rig = world.rig
        job, _ = reviewed_job(world, report_of([LIST, GET], [LIST]))
        before = state_files(rig)
        good = drafted(world, job, include=["list"], approve=["list"], decline_rest=True)
        data = {"draft": good["draft"], "base": good["base"]}
        with monkeypatch.context() as patched:
            patched.setattr(portal_app, "_candidate", widening(edit))
            refused = world.page.fetch(
                "POST", "/api/actions", json={"kind": good["kind"], "data": data}
            )
        assert status_reason(refused) == (403, "portal_widens")
        assert said in refused.json()["error"]
        assert [step["do"] for step in refused.json()["next"]] == [
            "export_policy",
            "import_policy",
        ]
        assert len(rig.app.actions) == 0
        held = prepared(world, good["kind"], data)
        monkeypatch.setattr(portal_app, "_candidate", widening(edit))
        swapped = confirmed(world, held)
        assert status_reason(swapped) == (409, "changed")
        assert swapped.json()["now"][0][0] == "Refused (portal_widens)"
        assert state_files(rig) == before
        assert revision(rig) == 1
        managed_ = rig.vault.managed
        assert managed_ is not None
        assert managed_.policy.admin is not None
        assert managed_.policy.admin.origins == [rig.origin]


# --- Y7: a kind is its diff ----------------------------------------------------------------------


def test_a_kind_is_its_diff(tmp_path: Path) -> None:
    """Y7 (O.4): a ``tool.allow`` prepared for a draft moving two tools, a ``tool.repin`` for a
    draft that also includes a tool, and a ``policy.save`` for a draft whose kind is
    ``tool.repin`` or ``tool.allow`` are each ``kind_mismatch``, before any prompt."""
    old_a = hinted("a", "Reads a thing.", READ_ONLY)
    new_a = hinted("a", "Reads a thing, and more.", READ_ONLY)
    with world_of(tmp_path, managed(**entry([LIST, GET, old_a]))) as world:
        policy = view_server(
            [], ["list", "get", "a"], {t.name: pin_of(t) for t in (LIST, GET, old_a)}
        )
        report = reviewed(
            [LIST, GET, new_a, WRITE], policy, defs={pin_of(old_a): definition(old_a)}
        )
        job, _ = reviewed_job(world, report)
        every = ["list", "get", "a"]
        cases = [
            (
                {"include": every, "allow": ["list", "get"], "approve": ["a"]},
                "policy.save",
                "tool.allow",
            ),
            (
                {"include": [*every, "write"], "approve": [*every, "write"], "repin": ["a"]},
                "policy.save",
                "tool.repin",
            ),
            ({"include": every, "approve": every, "repin": ["a"]}, "tool.repin", "policy.save"),
            (
                {"include": every, "allow": ["list"], "approve": ["get", "a"]},
                "tool.allow",
                "policy.save",
            ),
        ]
        for body, kind, prepared_as in cases:
            draft = drafted(world, job, decline_rest=False, **body)
            assert draft["kind"] == kind, body
            data = {"draft": draft["draft"], "base": draft["base"]}
            refused = world.page.fetch(
                "POST", "/api/actions", json={"kind": prepared_as, "data": data}
            )
            assert status_reason(refused) == (400, "kind_mismatch"), (body, prepared_as)
            assert len(world.rig.app.actions) == 0
        assert revision(world.rig) == 1


def test_a_confirm_whose_moves_changed(tmp_path: Path) -> None:
    """Y7, G.7 (O.4): this session plans moving ``list`` and ``get``; another session moves
    ``get`` alone meanwhile (revision 2). The confirm is ``409 changed``: the head that moved,
    then the save planned on revision 2, which moves ``list`` alone (its kind ``tool.allow``,
    as Save would plan it); the plan confirmed listed both. Nothing more is written."""
    with world_of(tmp_path, managed(**entry([LIST, GET]))) as world:
        rig = world.rig
        job, _ = reviewed_job(world, report_of([LIST, GET], [LIST, GET]))
        both = {"include": ["list", "get"], "allow": ["list", "get"], "approve": []}
        mine = drafted(world, job, decline_rest=False, **both)
        assert mine["kind"] == "policy.save"
        held = prepared(world, "policy.save", {"draft": mine["draft"], "base": 1})
        other = rig.browser().page(rig.origin)
        assert login(other, world.passkey).status_code == 200
        queued = other.fetch("POST", "/api/review/notes", json={"fresh": True})
        assert queued.status_code == 200, queued.text
        gateway_answers(rig, report_of([LIST, GET], [LIST, GET]))
        theirs_job = queued.json()["job"]
        assert other.fetch("GET", f"/api/review/jobs/{theirs_job}").json()["state"] == "done"
        one = {"include": ["list", "get"], "allow": ["get"], "approve": ["list"]}
        made = other.fetch(
            "POST", f"/api/review/jobs/{theirs_job}/diff", json={**one, "decline_rest": False}
        )
        assert made.status_code == 200, made.text
        theirs = made.json()
        assert theirs["kind"] == "tool.allow"
        data = {"draft": theirs["draft"], "base": 1}
        answer = other.fetch("POST", "/api/actions", json={"kind": "tool.allow", "data": data})
        assert answer.status_code == 200, answer.text
        assert confirmed(world, answer.json(), other).json()["revision"] == 2
        refused = confirmed(world, held)
        assert status_reason(refused) == (409, "changed")
        was, now = labels(refused.json()["was"]), labels(refused.json()["now"])
        assert {"notes.list", "notes.get"} <= set(was)
        assert now[:2] == ["Revision", "Revision"]
        assert "notes.list" in now
        assert "notes.get" not in now
        assert revision(rig) == 2
        assert head(rig)["tools"]["allow"] == ["get"]


# --- J6: history, diffs and rollback (M6 design H.1-H.4, M.1, M.2; step 15b) ---------------------

HOST = {"by": "host", "via": "socket"}
# Text a policy may hold that hides or fakes content: markup, and a bidi override (D-120).
HOSTILE = 'notes <img src=x onerror=alert(1)> & "q" \u202eevil'


def host_import(rig: PortalRig, edit: Callable[[dict[str, Any]], None], reason: str = "") -> int:
    """A host's import (H.5) as the admin socket writes one: the head's document with ``edit``
    made, planned on the head and written, on the vault's loop. Its revision."""
    managed_ = rig.vault.managed
    assert managed_ is not None

    def write() -> Written | WriteRefused:
        data = document(managed_.policy)
        edit(data)
        given = Policy.model_validate(data)
        shaped = import_shaped(managed_.store.seed_digest, managed_.policy, given)
        assert isinstance(shaped, Shaped), shaped
        return managed_.write(
            shaped.kind,
            "socket",
            managed_.revision,
            shaped.candidate_of,
            author=HOST,
            expected=None,
            evidence=shaped.evidence,
            reason=reason or None,
        )

    written = rig.call(write)
    assert isinstance(written, Written), written
    return written.revision


def as_given(given: dict[str, Any]) -> Callable[[dict[str, Any]], None]:
    """An edit that makes the document ``given``, whatever it was."""

    def edit(data: dict[str, Any]) -> None:
        data.clear()
        data.update(copy.deepcopy(given))

    return edit


def roll_back(world: World, target: int, base: int | None = None) -> httpx.Response:
    """**Roll back to this** prepared, on the head the page showed (``base``)."""
    data = {"base": revision(world.rig) if base is None else base, "revision": target}
    return world.page.fetch("POST", "/api/actions", json={"kind": "policy.rollback", "data": data})


def history(world: World, query: str = "") -> dict[str, Any]:
    answer = world.page.fetch("GET", "/api/policy/revisions" + query)
    assert answer.status_code == 200, answer.text
    page: dict[str, Any] = answer.json()
    return page


def test_history_and_a_diff_show_what_each_revision_did(tmp_path: Path) -> None:
    """H.1, H.2, M.1, J6, Y13 (D-120): the view names the head, the revision the gateway runs and
    the host's export command; the history lists each revision newest first (what made it, who
    and when, the host's reason shown), pages by ``before``
    and ``limit``, and a revision's diff from its parent shows a hostile value revealed and no
    client token hash. (A host's reason is printable text, so its markup is all it can hide.)"""
    with world_of(tmp_path, guarded(**entry([LIST]))) as world:
        rig = world.rig
        reason = 'rotate <b onclick="x()">now</b> & "q"'

        def hostile(data: dict[str, Any]) -> None:
            data["credentials"]["notes"]["client_id"] = HOSTILE

        assert host_import(rig, hostile, reason) == 2
        view = world.page.fetch("GET", "/api/policy").json()
        assert (view["mode"], view["revision"], view["not_running"]) == ("managed", 2, None)
        assert view["gateway"] == {"state": "unknown", "revision": None}
        assert view["export"]["do"] == "export_policy"
        assert view["export"]["label"] == "Export the policy"
        assert view["export"]["command"] == "zoeymcp policy export"
        page = history(world)
        assert set(page) == {"head", "revisions", "next"}
        assert (page["head"], page["next"]) == (2, None)
        newest, seed = page["revisions"]
        assert set(newest) == {
            "revision",
            "gap",
            "saved_shown",
            "origin",
            "kind",
            "base",
            "target",
            "jumped_from",
            "reason_shown",
        }
        assert (newest["revision"], newest["kind"], newest["base"]) == (2, "policy.import", 1)
        assert newest["saved_shown"].startswith("revision 2, saved ")
        assert newest["saved_shown"].endswith(" by the host (socket)")
        assert newest["reason_shown"] == reason
        assert (seed["revision"], seed["kind"], seed["reason_shown"]) == (1, "policy.seed", None)
        # A page of one, then the next below it.
        first = history(world, "?limit=1")
        assert ([e["revision"] for e in first["revisions"]], first["next"]) == ([2], 2)
        rest = history(world, "?before=2&limit=1")
        assert ([e["revision"] for e in rest["revisions"]], rest["next"]) == ([1], None)
        for query in ("?limit=51", "?limit=0", "?before=0", "?x=1", "?limit=1&limit=2", "?limit=a"):
            refused = world.page.fetch("GET", "/api/policy/revisions" + query)
            assert status_reason(refused) == (400, "bad_body"), query
        diffed = world.page.fetch("GET", "/api/policy/revisions/2")
        assert diffed.status_code == 200, diffed.text
        answer = diffed.json()
        assert set(answer) == {"revision", "against", "rows", "head"}
        assert (answer["revision"], answer["against"], answer["head"]) == (2, 1, 2)
        [row] = answer["rows"]
        assert row["path_shown"] == ["credentials", "notes", "client_id"]
        assert (row["op"], row["direction"], row["old"]) == ("changed", "wider", "notes-client")
        assert row["new"] == 'notes <img src=x onerror=alert(1)> & "q" [U+202E]evil'
        # The seed's diff from an empty policy: the client's token hash only as set (Y13).
        seeded = world.page.fetch("GET", "/api/policy/revisions/1?against=2").json()
        assert seeded["against"] == 2
        whole = world.page.fetch("GET", "/api/policy/revisions/1").json()
        assert whole["against"] is None
        assert CLIENT_HASH not in json.dumps(whole)
        assert "\u202e" not in diffed.text + json.dumps(page)
        unknown = world.page.fetch("GET", "/api/policy/revisions/7")
        assert status_reason(unknown) == (409, "revision_unknown")
        assert status_reason(world.page.fetch("GET", "/api/policy/revisions/1?against=x")) == (
            400,
            "bad_body",
        )


def test_rollback_undoes_onboarding(tmp_path: Path) -> None:
    """J6, Y6, G.7 rows 6-7, G.8: revision 2 onboarded notes (its credential, route and server)
    from the host; **Roll back to this** on revision 1 removes all three, a narrowing the portal
    may make. The dialog lists the stored refresh token it leaves unused first, then the revision
    row naming the target, and one passkey writes revision 3, logged ``policy_rolled_back`` with
    its target; the history says what made it, and its diff is every removal, narrower."""
    seed = {"mode": "managed", "gateway": {"clients": {"agent": {"token_sha256": CLIENT_HASH}}}}
    with world_of(tmp_path, seed) as world:
        rig = world.rig
        onboarded = copy.deepcopy(notes_entries(**entry([LIST])))

        def onboard(data: dict[str, Any]) -> None:
            data["credentials"] = onboarded["credentials"]
            data["routes"] = onboarded["routes"]
            data["gateway"]["servers"] = onboarded["gateway"]["servers"]

        assert host_import(rig, onboard) == 2
        managed_ = rig.vault.managed
        assert managed_ is not None
        secrets = rig.app.secrets
        assert secrets is not None
        binding = derive_binding(managed_.policy, "notes-refresh")
        rig.call(lambda: secrets.store.put("notes-refresh", "r" * 24, binding))
        prepared_ = roll_back(world, 1)
        assert prepared_.status_code == 200, prepared_.text
        held = prepared_.json()
        summary = held["summary"]
        assert summary[0][0] == "Revision"
        assert summary[0][1].startswith("3, from 2: the content of revision 1 (by the host ")
        assert summary[1] == [
            UNUSED_LABEL,
            UNUSED_ROLLBACK.format(name="notes-refresh"),
        ]
        removed = {label for label, value in summary if value == "removed"}
        assert {"credentials.notes", "routes.notes", "gateway.servers.notes"} <= removed
        assert not [label for label, value in summary if value.endswith("(wider)")]
        done = confirmed(world, held)
        assert done.status_code == 200, done.text
        assert (done.json()["revision"], revision(rig)) == (3, 3)
        assert managed_.policy.credentials == {}
        assert managed_.policy.routes == []
        [line] = rig.lines("policy_rolled_back")
        assert (line["revision"], line["write_kind"], line["base"], line["target"]) == (
            3,
            "policy.rollback",
            2,
            1,
        )
        [newest, *_] = history(world)["revisions"]
        assert (newest["kind"], newest["origin"], newest["target"]) == (
            "policy.rollback",
            "rollback",
            1,
        )
        rows = world.page.fetch("GET", "/api/policy/revisions/3").json()["rows"]
        assert rows
        assert {row["direction"] for row in rows} == {"narrower"}
        # The head itself is no target: nothing would change.
        assert status_reason(roll_back(world, 3)) == (400, "no_change")


def test_a_reviving_rollback_is_the_hosts(tmp_path: Path) -> None:
    """J6, E3, Y5, G.5 rule 1c (verifier C1): revision 2 gave client ci-runner a token, and
    revision 3 removed it. A portal rollback to revision 2 is ``rollback_revives``, naming the
    client and the revision that removed it, before any prompt (the ratchet's reason, not the
    direction rule's ``portal_widens``); nothing is written."""
    with world_of(tmp_path, managed(**entry([LIST]))) as world:
        rig = world.rig

        def add(data: dict[str, Any]) -> None:
            data["gateway"]["clients"] = {"ci-runner": {"token_sha256": CLIENT_HASH}}

        def remove(data: dict[str, Any]) -> None:
            del data["gateway"]["clients"]

        assert (host_import(rig, add), host_import(rig, remove)) == (2, 3)
        before = state_files(rig)
        refused = roll_back(world, 2)
        assert status_reason(refused) == (409, "rollback_revives")
        assert refused.json()["error"] == (
            "Rolling back to revision 2 brings back client ci-runner, removed in revision 3: "
            "only the host can, with zoeymcp policy rollback and --allow-revive."
        )
        assert refused.json()["subjects"] == ["client:ci-runner"]
        assert "rows" not in refused.json()
        assert len(rig.app.actions) == 0
        assert (state_files(rig), revision(rig)) == (before, 3)


def fenced() -> dict[str, Any]:
    """A managed deployment narrow in each place a rollback could widen (H.2's wider rows that a
    rollback reaches, O.4's Y6): a client pinned to its sources whose prompts need a confirmation
    code, a route allowing one query parameter and constraining a capture, an https route, a
    program with one egress entry, an MCP route no server uses, a toolkit slot of one unapproved
    GET, a server wrapping its results with a 30 s timeout, including list as approve and
    declining get (its review keeps the pins of get and old, so a rollback that includes either
    again meets the direction rule, not ``pin_retired``, E2), and a route with the first of two
    credentials."""
    policy = guarded(**entry([LIST]), call_timeout=30, wrap_results=True)
    notes = policy["gateway"]["servers"]["notes"]
    notes["declined"] = {"get": pin_of(GET)}
    notes["review"] |= {"get": pin_of(GET), "old": pin_of(OLD)}
    header = {"kind": "header", "header": "X-Key", "format": "{secret}"}
    policy["credentials"]["api-key"] = {**header, "secret": "store:api-key"}
    policy["credentials"]["api-key-2"] = {**header, "secret": "store:api-key-2"}
    notes = policy["routes"][0]
    notes["query"] = {"allow": ["q"]}
    notes["rules"][0]["paths"] = ["/mcp", "/other"]
    notes["rules"].append({"methods": ["GET"], "paths": ["/x/{id}"], "params": {"id": ["a"]}})
    api = policy["routes"][1]
    api["credential"] = "api-key"
    api["rules"] = [{"methods": ["GET", "POST"], "paths": ["/x"]}]
    get = [{"methods": ["GET"], "paths": ["/x"]}]
    policy["routes"] += [
        {
            "name": "plain",
            "prefix": "/plain",
            "upstream": "https://plain.example",
            "callers": ["gateway"],
            "rules": get,
        },
        {
            "name": "prog",
            "prefix": "/prog",
            "upstream": "http://prog:8080",
            "allow_insecure_upstream": True,
            "callers": ["gateway"],
            "rules": get,
            "program": {"egress": ["a.example:443"]},
        },
        {
            "name": "mirror",
            "prefix": "/mirror",
            "upstream": "https://mirror.example",
            "callers": ["gateway"],
            "stream": True,
            "rules": [{"methods": ["POST", "GET", "DELETE"], "paths": ["/mcp"]}],
        },
    ]
    agent = policy["gateway"]["clients"]["agent"]
    agent["sources"] = ["10.0.0.0/8"]
    agent["approvals"] = {"attended": False, "confirm_code": True}
    policy["gateway"]["servers"]["kit"] = {
        "kind": "toolkit",
        "module": "examples.toolkit",
        "slots": {"main": {"route": "api", "rules": get}},
    }
    return policy


def _route(data: dict[str, Any], name: str) -> dict[str, Any]:
    found: dict[str, Any] = next(route for route in data["routes"] if route["name"] == name)
    return found


def _sources(data: dict[str, Any]) -> None:
    del data["gateway"]["clients"]["agent"]["sources"]


def _query_allow(data: dict[str, Any]) -> None:
    del _route(data, "notes")["query"]


def _params(data: dict[str, Any]) -> None:
    del _route(data, "notes")["rules"][1]["params"]


def _confirm_code(data: dict[str, Any]) -> None:
    data["gateway"]["clients"]["agent"]["approvals"]["confirm_code"] = False


def _insecure(data: dict[str, Any]) -> None:
    _route(data, "plain").update(upstream="http://plain.example", allow_insecure_upstream=True)


def _shared_session(data: dict[str, Any]) -> None:
    data["gateway"]["servers"]["notes"]["shared_session"] = True


def _wrap_results(data: dict[str, Any]) -> None:
    data["gateway"]["servers"]["notes"]["wrap_results"] = False


def _egress(data: dict[str, Any]) -> None:
    _route(data, "prog")["program"]["egress"].append("b.example:443")


def _slots(data: dict[str, Any]) -> None:
    data["gateway"]["servers"]["kit"]["slots"]["main"]["rules"][0]["methods"].append("POST")


def _approved(data: dict[str, Any]) -> None:
    data["gateway"]["servers"]["kit"]["slots"]["main"]["rules"][0]["approved"] = True


def _path(data: dict[str, Any]) -> None:
    data["gateway"]["servers"]["notes"]["path"] = "/other"


def _credential(data: dict[str, Any]) -> None:
    _route(data, "api")["credential"] = "api-key-2"


def _timeout(data: dict[str, Any]) -> None:
    data["gateway"]["servers"]["notes"]["call_timeout"] = 60


def _route_repointed(data: dict[str, Any]) -> None:
    data["gateway"]["servers"]["notes"]["route"] = "mirror"


def _allow(data: dict[str, Any]) -> None:
    tools = data["gateway"]["servers"]["notes"]["tools"]
    tools["approve"].remove("list")
    tools.setdefault("allow", []).append("list")


def _include(data: dict[str, Any]) -> None:
    notes = data["gateway"]["servers"]["notes"]
    notes["tools"]["include"].append("old")
    notes["tools"]["approve"].append("old")


def _reinclude(data: dict[str, Any]) -> None:
    """get included again: the target includes what the head declines, so the rollback takes it
    out of ``declined`` (H.4), a row of its own."""
    notes = data["gateway"]["servers"]["notes"]
    notes["tools"]["include"].append("get")
    notes["tools"]["approve"].append("get")
    del notes["declined"]


# Each wider row of H.2's table a rollback can reach (O.4's Y6), and the path its refusal names.
ROLLBACK_WIDENINGS = (
    (_sources, "gateway.clients.agent.sources"),
    (_query_allow, "routes.notes.query.allow"),
    (_params, "routes.notes.rules.1.params.id"),
    (_confirm_code, "gateway.clients.agent.approvals.confirm_code"),
    (_insecure, "routes.plain.allow_insecure_upstream"),
    (_shared_session, "gateway.servers.notes.shared_session"),
    (_wrap_results, "gateway.servers.notes.wrap_results"),
    (_egress, "routes.prog.program.egress"),
    (_slots, "gateway.servers.kit.slots.main.rules.0.methods"),
    (_approved, "gateway.servers.kit.slots.main.rules.0.approved"),
    (_path, "gateway.servers.notes.path"),
    (_credential, "routes.api.credential"),
    (_timeout, "gateway.servers.notes.call_timeout"),
    (_route_repointed, "gateway.servers.notes.route"),
    (_allow, "gateway.servers.notes.tools.allow"),
    (_include, "gateway.servers.notes.tools.include"),
    (_reinclude, "gateway.servers.notes.declined.get"),
)


def test_no_portal_rollback_widens(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Y6, T-1, CR-4 (G.5 rule 2, H.4; 15a's deviation 13): for each wider row of H.2's table a
    rollback can reach, the host widens the policy (revision 2k), then narrows it back (2k+1);
    a portal rollback to the wider revision is ``403 portal_widens`` before any prompt, naming
    the path and the host's export and import, and nothing is written. Prepared on a narrowing
    target and confirmed with a valid assertion after the target's policy reads as a wider one,
    it is ``409 changed``, its first row ``portal_widens``."""
    with world_of(tmp_path, fenced()) as world:
        rig = world.rig
        managed_ = rig.vault.managed
        assert managed_ is not None
        narrow = document(managed_.policy)
        for edit, path in ROLLBACK_WIDENINGS:
            wide = host_import(rig, edit)
            assert host_import(rig, as_given(narrow)) == wide + 1
            before = state_files(rig)
            refused = roll_back(world, wide)
            assert status_reason(refused) == (403, "portal_widens"), path
            answer = refused.json()
            assert path in answer["subjects"], (path, answer["subjects"])
            assert "through a rollback" in answer["error"] or "change " in answer["error"]
            assert [step["do"] for step in answer["next"]] == ["export_policy", "import_policy"]
            assert len(rig.app.actions) == 0
            assert (state_files(rig), revision(rig)) == (before, wide + 1)
        # At the confirm: prepared on revision 1, a narrowing (the head added the toolkit's
        # POST), then read back as the wider policy the last row's import wrote.
        head = host_import(rig, _slots)
        held = roll_back(world, 1)
        assert held.status_code == 200, held.text
        wider = managed_.store.policy(head - 2)
        assert wider is not None
        real = read_revision
        monkeypatch.setattr(
            portal_app,
            "read_revision",
            lambda store, number: (real(store, number)[0], wider),  # type: ignore[index]
        )
        before = state_files(rig)
        swapped = confirmed(world, held.json())
        assert status_reason(swapped) == (409, "changed")
        assert swapped.json()["now"][0][0] == "Refused (portal_widens)"
        assert (state_files(rig), revision(rig)) == (before, head)


def test_a_target_in_quarantine_is_refused(tmp_path: Path) -> None:
    """H.3, FM-6: a kept revision that no longer verifies is a gap in the history and refused
    ``revision_unreadable``, by its diff and by a rollback before any prompt; prepared while it
    still verified, the confirm's dialog shows the refusal as its first row (G.7)."""
    with world_of(tmp_path, managed(**entry([LIST]))) as world:
        rig = world.rig

        def add(data: dict[str, Any]) -> None:
            data["gateway"]["servers"]["notes"] |= entry([LIST, GET])

        assert host_import(rig, add) == 2
        held = roll_back(world, 1)
        assert held.status_code == 200, held.text
        first = rig.state / revision_file(1)
        first.write_bytes(first.read_bytes().replace(b'"', b"'", 1))
        before = state_files(rig)
        refused = confirmed(world, held.json())
        assert status_reason(refused) == (409, "changed")
        assert refused.json()["now"][0][0] == "Refused (revision_unreadable)"
        assert history(world)["revisions"][1] == {"revision": 1, "gap": True}
        unreadable = world.page.fetch("GET", "/api/policy/revisions/1")
        assert status_reason(unreadable) == (409, "revision_unreadable")
        again = roll_back(world, 1)
        assert status_reason(again) == (409, "revision_unreadable")
        assert again.json()["error"] == (
            "Revision 1 is in quarantine: it can't be read, so it can't be used."
        )
        assert "rows" not in again.json()
        assert (state_files(rig), revision(rig)) == (before, 2)


def included(*tools: Tool) -> Callable[[dict[str, Any]], None]:
    """An edit that makes notes include list and ``tools``, as approve."""

    def edit(data: dict[str, Any]) -> None:
        data["gateway"]["servers"]["notes"] |= entry([LIST, *tools])

    return edit


def test_a_target_whose_parent_is_gone(tmp_path: Path) -> None:
    """D.8, H.3, M.1: a rollback needs no diff. Revision 2's parent is in quarantine, so its
    changes can't be shown (``revision_unreadable``, naming revision 1); it is still listed
    whole in the history, which ``policy.js`` draws **Roll back** from, and rolling back to it
    from revision 3 is planned and written."""
    with world_of(tmp_path, managed(**entry([LIST]))) as world:
        rig = world.rig
        assert (host_import(rig, included(GET)), host_import(rig, included(GET, OLD))) == (2, 3)
        first = rig.state / revision_file(1)
        first.write_bytes(first.read_bytes().replace(b'"', b"'", 1))
        page = history(world)
        assert [(e["revision"], e["gap"]) for e in page["revisions"]] == [
            (3, False),
            (2, False),
            (1, True),
        ]
        unshown = world.page.fetch("GET", "/api/policy/revisions/2")
        assert status_reason(unshown) == (409, "revision_unreadable")
        assert unshown.json()["error"].startswith("Revision 1 is in quarantine")
        held = roll_back(world, 2, base=page["head"])
        assert held.status_code == 200, held.text
        assert held.json()["summary"][0][1].startswith("4, from 3: the content of revision 2")
        done = confirmed(world, held.json())
        assert done.status_code == 200, done.text
        assert revision(rig) == 4
        assert head(rig)["tools"]["include"] == ["list", "get"]


def test_a_rollback_on_a_moved_head(tmp_path: Path) -> None:
    """G.7, N.2, Y8: a rollback prepared on revision 2 meets the host's import of revision 3 at
    the confirm: ``409 changed``, its first row the head that moved, worded for the Policy page
    ("press Roll back again"; it has no Save), then the same rollback planned on revision 3.
    Prepared again on revision 2, before any prompt, it is ``policy_moved`` in the same words;
    on revision 3, which the page shows once drawn again, it is written."""
    with world_of(tmp_path, managed(**entry([LIST]))) as world:
        rig = world.rig
        assert host_import(rig, included(GET)) == 2
        held = roll_back(world, 1)
        assert held.status_code == 200, held.text
        assert host_import(rig, included(GET, OLD)) == 3
        refused = confirmed(world, held.json())
        assert status_reason(refused) == (409, "changed")
        moved, *rest = refused.json()["now"]
        assert moved[0] == "Revision"
        assert moved[1].startswith("The policy moved to revision 3, saved ")
        assert moved[1].endswith("press Roll back again to plan it on revision 3.")
        assert "Save" not in moved[1]
        assert rest[0][1].startswith("4, from 3: the content of revision 1")
        assert revision(rig) == 3
        again = roll_back(world, 1, base=2)
        assert status_reason(again) == (409, "policy_moved")
        assert again.json()["error"].endswith("press Roll back again to plan it on revision 3.")
        assert history(world)["head"] == 3
        done = confirmed(world, roll_back(world, 1, base=3).json())
        assert done.status_code == 200, done.text
        assert revision(rig) == 4
        assert head(rig)["tools"]["include"] == ["list"]


def test_a_400_row_plan_is_confirmed_whole(tmp_path: Path) -> None:
    """Y9 (O.4, G.5 rule 5; 15a's deviation 14): a rollback whose plan has 400 rows (the
    revision, one removal per server, and no restart) is confirmed in the portal with every row
    shown, nothing cut; one row more is ``413 summary_too_large`` with the host's way, before any
    prompt."""
    with world_of(tmp_path, managed(**entry([LIST]))) as world:
        rig = world.rig

        def servers(count: int) -> Callable[[dict[str, Any]], None]:
            def edit(data: dict[str, Any]) -> None:
                extra = data["gateway"]["servers"]
                for name in [name for name in extra if name.startswith("s")]:
                    del extra[name]
                for index in range(count):
                    extra[f"s{index:03d}"] = {"kind": "remote", "route": "notes"}

            return edit

        assert host_import(rig, servers(399)) == 2
        too_long = roll_back(world, 1)
        assert status_reason(too_long) == (413, "summary_too_large")
        assert [step["do"] for step in too_long.json()["next"]] == [
            "export_policy",
            "import_policy",
        ]
        assert host_import(rig, servers(398)) == 3
        held = roll_back(world, 1)
        assert held.status_code == 200, held.text
        summary = held.json()["summary"]
        assert len(summary) == 400
        assert summary[0][1].startswith("4, from 3: the content of revision 1")
        assert [label for label, _ in summary[1:-1]] == [
            f"gateway.servers.s{index:03d}" for index in range(398)
        ]
        assert summary[-1][0] == "No restart needed"
        done = confirmed(world, held.json())
        assert done.status_code == 200, done.text
        assert revision(rig) == 4


def test_a_declarative_policy_has_no_history(tmp_path: Path) -> None:
    """M.2, M.3: in declarative mode the history, a diff and a rollback are
    ``policy_not_managed``, and the view names no revision."""
    with world_of(tmp_path, notes_entries(**entry([LIST]))) as world:
        for path in ("/api/policy/revisions", "/api/policy/revisions/1"):
            assert status_reason(world.page.fetch("GET", path)) == (409, "policy_not_managed")
        assert status_reason(roll_back(world, 1, base=1)) == (409, "policy_not_managed")
        view = world.page.fetch("GET", "/api/policy").json()
        assert view["mode"] == "declarative"
        assert "revision" not in view
