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
"""

from __future__ import annotations

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
from zoeymcp.common.policy.plan import KEPT_ALLOW_TEXT, MOVE_TEXT, REINCLUDE_TEXT
from zoeymcp.common.policy.schema import OAuth2Credential, Policy, Route, Tools
from zoeymcp.portal import app as portal_app
from zoeymcp.portal.drafts import Facts
from zoeymcp.vault.gatewaykeys import GatewayKeyError
from zoeymcp.vault.managed import GATEWAY_APPLY_GRACE
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
