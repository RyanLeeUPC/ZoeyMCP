"""``vault_approval`` in managed mode over the real API (M8 design A.4, J2's managed half, J11;
Z20, G-5, FM-20, FM-44).

The vault starts managed with the portal's queue as its approver (``approvers.portal``), and
notes' ``write`` an included ``approve`` tool. On the MCP servers page, **Hold in the vault** is a
one-change ``policy.save`` from the data (``{base, server, tool}``), a narrowing, whose plan
says before the passkey who is asked where (the turn-on lines); **Turn off vault approval** is
``tool.vault_approval_off``, its one sentence first among the weakenings, logged
``tool_vault_approval_off``, and written as a save of that kind. Anything else that would stop
the vault holding the tool is refused before any prompt, with nothing written: a review save
that unticks it or drops it from ``include`` (``vault_approval_off_needs_its_own_step``), a
rollback to before it was held or included (``rollback_drops_vault_approval``), so a drop
followed by a re-include can't reach an unheld ``approve`` through the portal. A held
connector's writers turn on and off together, one step-up each, the closed set included: two
toolkits write through ``mail``, one of them through ``post`` too. With no approver set, the
server rows and the review say so (the page shows the controls disabled, pinned in
``test_portal_static``) and a hold is refused (A.2 row 2). ``tests.fakes.browser.Page`` runs no
script, so the page's requests are made here as approvals.js makes them.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

from zoeymcp.common.policy.change import (
    AddCredential,
    AddRoute,
    AddServer,
    PolicyChange,
    SetServerReview,
)
from zoeymcp.common.policy.plan import VAULT_OFF_CONNECTOR_TEXT, VAULT_OFF_TEXT
from zoeymcp.common.policy.schema import OAuth2Credential, RemoteServer, Route, Tools

from .flows import status_reason
from .rig import PortalRig
from .test_policy_managed import (
    LIST,
    OLD,
    WRITE,
    World,
    _injected,
    confirmed,
    drafted,
    entry,
    head,
    host_import,
    managed,
    prepared,
    report_of,
    reviewed_job,
    revision,
    roll_back,
    state_files,
    world_of,
)
from .test_review import ISSUER

CLIENT_HASH = "sha256:" + "1" * 64
OFF_PATH = "gateway.servers.notes.tools.vault_approval"
NEEDS_STEP = (
    "The vault holds notes.write: turn that off on the server's page (one passkey per tool, or "
    "per held connector), then save again."
)


def policy(*, held: bool = False, approver: bool = True, write: bool = True) -> dict[str, Any]:
    """Notes with ``list`` allowed and ``write`` approved (none with ``write`` false), the client
    desk attended and given notes, and the portal's queue as the approver."""
    found = managed(**entry([WRITE] if write else [], [LIST]))
    found["gateway"]["clients"] = {
        "desk": {"token_sha256": CLIENT_HASH, "approvals": {"attended": True}, "servers": ["notes"]}
    }
    if approver:
        found["approvers"] = {"portal": {}}
    if held:
        found["gateway"]["servers"]["notes"]["tools"]["vault_approval"] = ["write"]
    return found


def notes_row(world: World) -> dict[str, Any]:
    answer = world.page.fetch("GET", "/api/servers")
    assert answer.status_code == 200, answer.text
    [row] = [row for row in answer.json()["servers"] if row.get("server") == "notes"]
    found: dict[str, Any] = row
    return found


def prepare(world: World, kind: str, data: dict[str, Any]) -> Any:
    return world.page.fetch("POST", "/api/actions", json={"kind": kind, "data": data})


def hold_write(world: World) -> int:
    """**Hold in the vault** on write's row, confirmed: the revision it wrote."""
    base = revision(world.rig)
    held = prepared(world, "policy.save", {"base": base, "server": "notes", "tool": "write"})
    done = confirmed(world, held)
    assert done.status_code == 200, done.text
    return revision(world.rig)


def test_hold_in_the_vault_then_turn_it_off(tmp_path: Path) -> None:
    """J2's managed half, J11 step 3, G-5: the row offers the hold with an approver set; the
    plan says before the passkey who is asked where; the save holds write. Turning it off is
    its own kind, one sentence, one passkey, logged; a form mixed or partial is ``bad_body`` and
    one that changes nothing ``no_change``."""
    with world_of(tmp_path, policy()) as world:
        rig = world.rig
        row = notes_row(world)
        assert (row["vault_approval"], row["approver"], row["connectors"]) == ([], True, [])
        held = prepared(world, "policy.save", {"base": 1, "server": "notes", "tool": "write"})
        assert held["kind"] == "policy.save"
        lines = [value for label, value in held["summary"] if label == "notes.write"]
        assert lines[:2] == [
            "notes.write: vault_approval on.",
            "  The vault will hold every call to write and ask you in the Approvals queue. The "
            "gateway will no longer ask in the agent's own client.",
        ]
        assert "  desk (attended): asked on your approvers instead of in its client." in lines
        done = confirmed(world, held)
        assert done.status_code == 200, done.text
        assert head(rig)["tools"]["vault_approval"] == ["write"]
        assert notes_row(world)["vault_approval"] == ["write"]
        again = prepare(world, "policy.save", {"base": 2, "server": "notes", "tool": "write"})
        assert status_reason(again) == (400, "no_change")
        for data in ({"base": 2, "server": "notes"}, {"base": 2, "tool": "write"}):
            assert status_reason(prepare(world, "tool.vault_approval_off", data)) == (
                400,
                "bad_body",
            )
        mixed = {"base": 2, "server": "notes", "tool": "write", "connector": "mail"}
        assert status_reason(prepare(world, "tool.vault_approval_off", mixed)) == (400, "bad_body")
        assert status_reason(prepare(world, "policy.save", mixed)) == (400, "bad_body")
        drafted = {"base": 2, "draft": "0" * 32, "server": "notes", "tool": "write"}
        assert status_reason(prepare(world, "policy.save", drafted)) == (400, "bad_body")
        before = state_files(rig)
        off = prepared(
            world, "tool.vault_approval_off", {"base": 2, "server": "notes", "tool": "write"}
        )
        assert off["kind"] == "tool.vault_approval_off"
        assert off["summary"][1] == [OFF_PATH, VAULT_OFF_TEXT.format(name="write")]
        assert state_files(rig) == before
        done = confirmed(world, off)
        assert done.status_code == 200, done.text
        assert (
            "vault_approval" not in head(rig)["tools"] or head(rig)["tools"]["vault_approval"] == []
        )
        assert rig.vault.managed is not None
        header = rig.vault.managed.store.header
        assert header is not None
        assert (header["revision"], header["kind"], header["origin"]) == (
            3,
            "tool.vault_approval_off",
            "save",
        )
        [line] = rig.lines("tool_vault_approval_off")
        assert {k: line[k] for k in ("level", "server", "name", "revision")} == {
            "level": "warning",
            "server": "notes",
            "name": "write",
            "revision": 3,
        }
        gone = prepare(
            world, "tool.vault_approval_off", {"base": 3, "server": "notes", "tool": "write"}
        )
        assert status_reason(gone) == (400, "no_change")


def _review_save(world: World, job: str, **body: Any) -> Any:
    choices = {"include": [], "allow": [], "approve": [], **body}
    return world.page.fetch("POST", f"/api/review/jobs/{job}/diff", json=choices)


def test_a_review_save_cant_turn_it_off(tmp_path: Path) -> None:
    """J11 step 1, FM-20: a review shows each tool's hold and whether an approver is set; a
    review save that unticks Hold in the vault, or drops the tool from include, or moves it to
    allow, is refused before the passkey with the step to take, and nothing is held as a
    draft or written. One that sends no held list keeps the policy's holds."""
    with world_of(tmp_path, policy(held=True)) as world:
        rig = world.rig
        job, read = reviewed_job(world, report_of([LIST, WRITE], [WRITE], [LIST]))
        assert (read["vault_approval"], read["approver"]) == (["write"], True)
        before = state_files(rig)
        kept = {"include": ["list", "write"], "allow": ["list"], "approve": ["write"]}
        for body in (
            {**kept, "held": []},
            {"include": ["list"], "allow": ["list"], "approve": [], "held": ["write"]},
            {"include": ["list", "write"], "allow": ["list", "write"], "approve": []},
        ):
            refused = _review_save(world, job, **body)
            assert status_reason(refused) == (409, "vault_approval_off_needs_its_own_step"), body
            assert refused.json()["error"] == NEEDS_STEP
        assert not rig.app.drafts._by_session
        assert state_files(rig) == before
        assert head(rig)["tools"]["vault_approval"] == ["write"]
        # Nothing unticked: the hold stays, so the save changes nothing.
        assert status_reason(_review_save(world, job, **kept)) == (400, "no_change")


def test_a_rollback_cant_drop_it_and_a_drop_cant_be_re_included_unheld(tmp_path: Path) -> None:
    """J11 step 2, FM-20, E-2: with write held, a rollback to before it was held and one to
    before it was included are each refused, naming it; dropping it from include is refused too
    (the review save above), so a later save can't include it again unheld. Once it is turned
    off by its kind, the rollback to before it was included plans and writes."""
    with world_of(tmp_path, policy(write=False)) as world:
        rig = world.rig

        def add_write(data: dict[str, Any]) -> None:
            notes = data["gateway"]["servers"]["notes"]
            notes["tools"]["include"].append("write")
            notes["tools"]["approve"] = ["write"]
            notes["review"]["write"] = entry([WRITE])["review"]["write"]

        assert host_import(rig, add_write) == 2
        assert hold_write(world) == 3
        before = state_files(rig)
        for target in (2, 1):
            refused = roll_back(world, target)
            assert status_reason(refused) == (409, "rollback_drops_vault_approval")
            assert refused.json()["error"] == (
                f"Rolling back to revision {target} would stop the vault holding notes.write. "
                "Turn each off first on the server's page (one passkey per tool, or per held "
                "connector), then roll back."
            )
        assert state_files(rig) == before
        off = prepared(
            world, "tool.vault_approval_off", {"base": 3, "server": "notes", "tool": "write"}
        )
        assert confirmed(world, off).status_code == 200
        rolled = roll_back(world, 1)
        assert rolled.status_code == 200, rolled.text
        assert confirmed(world, rolled.json()).status_code == 200
        assert head(rig)["tools"]["include"] == ["list"]


def test_a_parallel_route_to_the_held_upstream_is_refused(tmp_path: Path) -> None:
    """FM-44 (T-2), the route form: a save adding a route and a server to notes' upstream with
    the same store secret, listing write unheld, is refused before the passkey; the vault's
    check (A.2 rows 22-23, and the shared rotating token here) is the gate it meets first, so
    the answer is ``save_invalid`` and nothing is written (the server form meets check too:
    the next test)."""
    with world_of(tmp_path, policy(held=True)) as world:
        rig = world.rig
        job, _ = reviewed_job(world, report_of([LIST, WRITE, OLD], [WRITE], [LIST]))
        # A draft of this session's, which the injected one replaces (as the review route would).
        kept = {"include": ["list", "write"], "allow": ["list"], "approve": ["write"]}
        drafted(world, job, **kept, decline=["old"])
        credential = OAuth2Credential.model_validate(
            {
                "kind": "oauth2",
                "token_url": f"{ISSUER}/token",
                "client_id": "notes-two",
                "client_auth": "none",
                "refresh_token": "store:notes-refresh",
            }
        )
        route = Route.model_validate(
            {
                "name": "notes-two",
                "prefix": "/notes-two",
                "upstream": "https://mcp.notes.example",
                "credential": "notes-two",
                "callers": ["gateway"],
                "rules": [{"methods": ["POST"], "paths": ["/mcp"]}],
            }
        )
        server = RemoteServer.model_validate(
            {
                "kind": "remote",
                "route": "notes-two",
                "tools": {"include": ["write"], "approve": ["write"]},
                "review": dict(entry([WRITE])["review"]),
            }
        )
        change = PolicyChange(
            "t",
            (AddCredential("notes-two", credential), AddRoute(route), AddServer("notes2", server)),
        )
        before = state_files(rig)
        data = _injected(world, change)
        answer = prepare(world, "policy.save", data)
        assert status_reason(answer) == (422, "save_invalid"), answer.text
        assert "fails check" in answer.json()["error"]
        assert len(rig.app.actions) == 0
        assert state_files(rig) == before


def test_a_second_server_on_the_held_route_is_refused(tmp_path: Path) -> None:
    """FM-44 (T-2, A.4), the server form: notes2 sits on notes' own route at its own path
    (row 21 lets a held route's rules name each of its servers' exact paths), listing only
    list. A save adding write to notes2 unheld fails check's row 21 second-server form (a
    managed seed has no head for the planner's reach rule to compare, so check holds it in
    both modes): ``save_invalid`` before the passkey, naming the held tool; nothing is
    written. The planner's own reason for it is pinned in test_policy_plan."""
    found = policy(held=True)
    paths = ["/mcp", "/mcp2"]
    found["routes"][0]["rules"] = [{"methods": ["POST", "GET", "DELETE"], "paths": paths}]
    second = {"kind": "remote", "route": "notes", "path": "/mcp2", **entry([], [LIST])}
    found["gateway"]["servers"]["notes2"] = second
    with world_of(tmp_path, found) as world:
        rig = world.rig
        job, _ = reviewed_job(world, report_of([LIST, WRITE, OLD], [WRITE], [LIST]))
        # A draft of this session's, which the injected one replaces (as the review route would).
        kept = {"include": ["list", "write"], "allow": ["list"], "approve": ["write"]}
        drafted(world, job, **kept, decline=["old"])
        tools = Tools(include=["list", "write"], allow=["list"], approve=["write"])
        reach = SetServerReview("notes2", tools, entry([WRITE], [LIST])["review"], declined={})
        before = state_files(rig)
        data = _injected(world, PolicyChange("t", (reach,)))
        answer = prepare(world, "policy.save", data)
        assert status_reason(answer) == (422, "save_invalid"), answer.text
        assert "fails check" in answer.json()["error"]
        assert len(rig.app.actions) == 0
        assert state_files(rig) == before


def test_allow_without_asking_keeps_the_other_holds(tmp_path: Path) -> None:
    """A.4, FM-20: with write held and list an unheld approve tool, **Allow without asking** on
    list (``tool.allow``) plans and writes with write still held; on write itself it is refused
    with the step to take, before the passkey, and nothing is written."""
    found = policy(held=True)
    notes = found["gateway"]["servers"]["notes"]["tools"]
    notes["allow"], notes["approve"] = [], ["list", "write"]
    with world_of(tmp_path, found) as world:
        rig = world.rig
        reviewed_job(world, report_of([LIST, WRITE], [LIST, WRITE]))
        pins = {item["name"]: item["pin"] for item in notes_row(world)["approve"]}

        def allow(name: str) -> dict[str, Any]:
            return {"base": 1, "server": "notes", "kind": "tool", "name": name, "pin": pins[name]}

        before = state_files(rig)
        refused = prepare(world, "tool.allow", allow("write"))
        assert status_reason(refused) == (409, "vault_approval_off_needs_its_own_step")
        assert refused.json()["error"] == NEEDS_STEP
        assert state_files(rig) == before
        moved = prepared(world, "tool.allow", allow("list"))
        done = confirmed(world, moved)
        assert done.status_code == 200, done.text
        tools = head(rig)["tools"]
        assert (tools["allow"], tools["approve"], tools["vault_approval"]) == (
            ["list"],
            ["write"],
            ["write"],
        )


def _connector(name: str) -> dict[str, Any]:
    return {
        "kind": "smtp",
        "host": f"smtp.{name}.example",
        "port": 465,
        "username": "bot",
        "password": f"store:{name}-password",
        "from": f"bot@{name}.example",
        "to": [f"ops@{name}.example"],
    }


def _slot(route: str) -> dict[str, Any]:
    return {
        "route": route,
        "rules": [{"methods": ["POST"], "paths": ["/send"], "approved": True}],
    }


def mailing() -> dict[str, Any]:
    """Two toolkits writing through the mail connector, kit2 through post too, none held."""
    found = policy()
    found["connectors"] = {"mail": _connector("mail"), "post": _connector("post")}
    found["routes"] = [
        *found["routes"],
        *(
            {
                "name": f"{name}-send",
                "prefix": f"/{name}",
                "connector": name,
                "callers": ["gateway"],
                "rules": [{"methods": ["POST"], "paths": ["/send"]}],
            }
            for name in ("mail", "post")
        ),
    ]
    servers = found["gateway"]["servers"]
    servers["kit"] = {
        "kind": "toolkit",
        "module": "kits.mail",
        "pinning": "off",
        "tools": {"include": ["send"], "approve": ["send"]},
        "slots": {"mail": _slot("mail-send")},
    }
    servers["kit2"] = {
        "kind": "toolkit",
        "module": "kits.post",
        "pinning": "off",
        "tools": {"include": ["post", "reply"], "approve": ["post", "reply"]},
        "slots": {"mail": _slot("mail-send"), "post": _slot("post-send")},
    }
    return found


def _held(rig: PortalRig) -> dict[str, list[str]]:
    managed_ = rig.vault.managed
    assert managed_ is not None
    gateway = managed_.policy.gateway
    assert gateway is not None
    return {name: list(server.tools.vault_approval) for name, server in gateway.servers.items()}


def test_a_connectors_writers_turn_on_and_off_in_one_step_up_each(tmp_path: Path) -> None:
    """A.4, T-8 (the owner's connector form): a two-writer connector is held from either
    writer's row in one step-up, its closed set included (kit2 writes through post too, so
    post's writers come with it); turning it off from post is one step-up too, one sentence per
    tool, naming each connector it covers."""
    with world_of(tmp_path, mailing()) as world:
        rig = world.rig
        rows = {
            row["server"]: row
            for row in world.page.fetch("GET", "/api/servers").json()["servers"]
            if "server" in row
        }
        assert (rows["kit"]["connectors"], rows["kit2"]["connectors"]) == (
            ["mail"],
            ["mail", "post"],
        )
        held = prepared(world, "policy.save", {"base": 1, "connector": "mail"})
        assert confirmed(world, held).status_code == 200
        assert revision(rig) == 2
        assert {k: v for k, v in _held(rig).items() if v} == {
            "kit": ["send"],
            "kit2": ["post", "reply"],
        }
        off = prepared(world, "tool.vault_approval_off", {"base": 2, "connector": "post"})
        covers = VAULT_OFF_CONNECTOR_TEXT.format(servers="kit, kit2")
        assert off["summary"][1:6] == [
            ["gateway.servers.kit.tools.vault_approval", VAULT_OFF_TEXT.format(name="send")],
            ["gateway.servers.kit2.tools.vault_approval", VAULT_OFF_TEXT.format(name="post")],
            ["gateway.servers.kit2.tools.vault_approval", VAULT_OFF_TEXT.format(name="reply")],
            ["connector mail", covers],
            ["connector post", covers],
        ]
        assert confirmed(world, off).status_code == 200
        assert revision(rig) == 3
        assert not any(_held(rig).values())
        assert len(rig.lines("tool_vault_approval_off")) == 3


def test_with_no_approver_the_hold_is_disabled_and_refused(tmp_path: Path) -> None:
    """A.4: with no out-of-band approver the rows and the review say so, for approvals.js to
    show its controls disabled with its line; a hold prepared anyway fails check (A.2 row 2)
    before the passkey."""
    with world_of(tmp_path, policy(approver=False)) as world:
        assert notes_row(world)["approver"] is False
        _, read = reviewed_job(world, report_of([LIST, WRITE], [WRITE], [LIST]))
        assert (read["vault_approval"], read["approver"]) == ([], False)
        refused = prepare(world, "policy.save", {"base": 1, "server": "notes", "tool": "write"})
        assert status_reason(refused) == (422, "save_invalid"), refused.text
        assert len(world.rig.app.actions) == 0


def test_a_declarative_row_has_no_hold(tmp_path: Path) -> None:
    """Declarative: the change is a line beside approve, so the rows carry nothing of the hold
    and both kinds are policy_not_managed."""
    declarative = copy.deepcopy(policy())
    declarative["mode"] = "declarative"
    with world_of(tmp_path, declarative) as world:
        assert "vault_approval" not in notes_row(world)
        refused = prepare(
            world, "tool.vault_approval_off", {"base": 1, "server": "notes", "tool": "write"}
        )
        assert status_reason(refused)[1] == "policy_not_managed"
