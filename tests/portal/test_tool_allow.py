"""Allow without asking, in declarative mode (M6 design J3, J.4; COV-3), over the real API.

``notes`` includes ``search`` in ``approve``, pinned. Its row on **MCP servers** names it, for
the page's **Allow without asking**, which opens the review screen with that one tool moved to
``allow`` (drift.js's ``move()``; ``tests.fakes.browser.Page`` runs no script, so the page's side
is pinned by ``tests/unit/test_portal_static.py``). The review's row starts it at ``approve``
(its ``prefill``), so nothing but that button moves it; Generate's fragment 2 then carries the
move and says what it allows in a comment, nothing saved; a move is checked as any choice is.

In managed mode the button is ``tool.allow`` (J.4): the plan shows the definition at the head's
pin from a review the vault holds (the listed one, the reviewed side of a drift, or on a
``pinning: off`` toolkit the listed one with its fixed row); with none held, the row says so and
the page reviews the server first; a definition too long for the dialog is the host's.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from mcp.types import Tool

from tests.fakes.authenticator import SoftAuthenticator
from tests.unit.test_portal_static import code_of
from tests.unit.test_portal_static import read as static
from tests.unit.test_review import pin, reviewed, tool
from tests.unit.test_reviewchange import READ_ONLY, definition, hinted, pin_of
from tests.unit.test_reviewchange import server as view_server
from zoeymcp.common.policy.plan import MOVE_TEXT, PINNING_OFF_TEXT, SUMMARY_ROWS_MAX
from zoeymcp.common.policy.reviewchange import definition_lines
from zoeymcp.common.yamlload import load_mapping

from .flows import set_up, status_reason
from .rig import running
from .test_policy_managed import (
    confirmed,
    drafted,
    head,
    managed,
    prepared,
    saved,
    world_of,
)
from .test_policy_managed import reviewed_job as managed_job
from .test_review import World, gateway_answers, notes_entries, poller

SENTENCE = "# changed: search (approve -> allow: calls to search will run with no prompt)"


def served() -> dict[str, Any]:
    """The policy's notes entry: ``search`` included as approve, ``list`` as allow."""
    return {
        "tools": {"include": ["list", "search"], "allow": ["list"], "approve": ["search"]},
        "review": {"list": pin("list"), "search": pin("search")},
    }


def report() -> dict[str, Any]:
    """The gateway's review of notes: both included tools at their pins, ``other`` besides."""
    policy = view_server(["list"], ["search"], {"list": pin("list"), "search": pin("search")})
    return reviewed([tool("list"), tool("search"), tool("other")], policy)


@pytest.fixture
def world(tmp_path: Path) -> Iterator[World]:
    with running(tmp_path, policy=notes_entries(**served())) as rig:
        page = rig.browser().page(rig.origin)
        set_up(rig, page, SoftAuthenticator())
        poller(rig)
        yield World(rig, page)


def reviewed_job(world: World) -> tuple[str, dict[str, Any]]:
    """The review the button opens, done."""
    queued = world.page.fetch("POST", "/api/review/notes", json={})
    assert queued.status_code == 200, queued.text
    gateway_answers(world.rig, report())
    job: str = queued.json()["job"]
    answer = world.page.fetch("GET", f"/api/review/jobs/{job}")
    assert answer.status_code == 200, answer.text
    read: dict[str, Any] = answer.json()
    return job, read


def test_a_server_row_names_its_included_approve_tools(world: World) -> None:
    """J3: one Allow without asking per included approve tool, by the name the page moves on the
    review screen, shown; an allow tool has none. What drift.js reads of a row is what it is
    sent."""
    found = world.page.fetch("GET", "/api/servers")
    assert found.status_code == 200, found.text
    [notes] = [row for row in found.json()["servers"] if row.get("server") == "notes"]
    assert notes["approve"] == [
        {"name": "search", "name_shown": "search", "pin": pin("search"), "held": False}
    ]
    drift = code_of(static("drift.js"))
    assert set(re.findall(r"\bnamed\.([a-z_]+)", drift)) == set(notes["approve"][0])
    assert "row.approve" in drift


def test_allow_without_asking_moves_the_one_tool_in_fragment_2(world: World) -> None:
    """J3, declarative: the review's row for ``search`` is included as approve and starts at
    approve, so Select suggested can't move it; the button's move is the page's choice of allow
    on that row alone, and fragment 2 carries it with the sentence as a comment. Nothing is
    saved: the commit is the guard (DD-9)."""
    rig, page = world.rig, world.page
    job, read = reviewed_job(world)
    [search] = [entry for entry in read["tools"] if entry["name"] == "search"]
    assert (search["included"], search["classification"], search["prefill"]) == (
        True,
        "approve",
        "approve",
    )
    before = rig.policy_file.read_bytes()
    body = {"include": ["list", "search"], "allow": ["list", "search"], "approve": []}
    made = page.fetch("POST", f"/api/review/jobs/{job}/diff", json=body)
    assert made.status_code == 200, made.text
    text = made.json()["diff"]["yaml"]
    assert SENTENCE in text.splitlines()
    entry = load_mapping(text)["gateway"]["servers"]["notes"]
    assert entry["tools"] == {
        "include": ["list", "search"],
        "allow": ["list", "search"],
        "approve": [],
    }
    assert entry["review"] == {"list": pin("list"), "search": pin("search")}
    assert not [f for f in made.json()["diff"]["check"] if f["level"] == "error"]
    assert rig.policy_file.read_bytes() == before
    # Without the move, the same review's fragment says nothing of the kind.
    kept = {"include": ["list", "search"], "allow": ["list"], "approve": ["search"]}
    unmoved = page.fetch("POST", f"/api/review/jobs/{job}/diff", json=kept)
    assert unmoved.status_code == 200, unmoved.text
    assert "will run with no prompt" not in unmoved.json()["diff"]["yaml"]


def test_a_move_the_review_cant_hold_is_refused(world: World) -> None:
    """The move is checked as any choice is: a tool the server doesn't list can't be allowed."""
    job, _ = reviewed_job(world)
    body = {"include": ["list", "nope"], "allow": ["list", "nope"], "approve": []}
    refused = world.page.fetch("POST", f"/api/review/jobs/{job}/diff", json=body)
    assert status_reason(refused) == (422, "diff_invalid")


# --- managed mode: tool.allow (M6 design J3, J.4, M.3; step 15a) --------------------------------


def managed_world(tmp_path: Path) -> Any:
    """notes, managed: ``list`` allow, ``search`` and ``get`` approve, each pinned."""
    entry = {
        "era": "modern",
        "tools": {
            "include": ["list", "search", "get"],
            "allow": ["list"],
            "approve": ["search", "get"],
        },
        "review": {"list": pin("list"), "search": pin("search"), "get": pin("get")},
    }
    return world_of(tmp_path, managed(**entry))


def managed_report() -> dict[str, Any]:
    policy = view_server(
        ["list"], ["search", "get"], {name: pin(name) for name in ("list", "search", "get")}
    )
    return reviewed([tool("list"), tool("search"), tool("get")], policy)


def allow_data(name: str, base: int, found: str | None = None) -> dict[str, Any]:
    return {
        "base": base,
        "server": "notes",
        "kind": "tool",
        "name": name,
        "pin": found or pin(name),
    }


def approve_items(world: Any, server: str = "notes") -> list[dict[str, Any]]:
    """The server's row's Allow without asking items, as the page reads them."""
    found = world.page.fetch("GET", "/api/servers")
    assert found.status_code == 200, found.text
    [row] = [row for row in found.json()["servers"] if row.get("server") == server]
    items: list[dict[str, Any]] = row["approve"]
    return items


def chunks(summary: list[list[str]], name: str) -> list[str]:
    """The definition rows of ``name`` in a plan, in order."""
    return [value for label, value in summary if label.startswith(f"{name}, ")]


def test_managed_allow_from_a_servers_page(tmp_path: Path) -> None:
    """J3, J.4, managed: with no review held, **Allow without asking** is ``allow_needs_review``
    whose way on is a fresh review. With one, the plan reads the move and the definition pinned,
    one passkey writes it (``tool.allow``) and logs ``tool_allowed``; a second tool right after
    reuses the same review (OPS-13). A pin the head doesn't hold is refused."""
    with managed_world(tmp_path) as world:
        rig = world.rig
        # No review held: the row says so, and the page reviews the server first (J.4).
        assert [item["held"] for item in approve_items(world)] == [False, False]
        refused = world.page.fetch(
            "POST", "/api/actions", json={"kind": "tool.allow", "data": allow_data("search", 1)}
        )
        assert status_reason(refused) == (409, "allow_needs_review")
        assert refused.json()["next"] == [
            {
                "do": "review",
                "label": "Review again",
                "command": "zoeymcp review notes --via vault --fresh",
                "via": "exec",
            }
        ]
        managed_job(world, managed_report())
        assert [(item["pin"], item["held"]) for item in approve_items(world)] == [
            (pin("search"), True),
            (pin("get"), True),
        ]
        held = prepared(world, "tool.allow", allow_data("search", 1))
        summary = held["summary"]
        assert summary[1] == ["notes.search", MOVE_TEXT.format(name="search")]
        assert summary[2] == [f"search, as pinned ({pin('search')})", "{"]
        assert ["No restart needed", ""] in summary
        done = confirmed(world, held)
        assert done.status_code == 200, done.text
        assert done.json()["revision"] == 2
        [line] = rig.lines("tool_allowed")
        assert (line["server"], line["name"], line["revision"]) == ("notes", "search", 2)
        assert head(rig)["tools"]["approve"] == ["get"]
        # The same review shows get's definition at the head's pin: no review again.
        again = prepared(world, "tool.allow", allow_data("get", 2))
        assert confirmed(world, again).json()["revision"] == 3
        # A tool the head no longer holds in approve, or at another pin, is ``409 changed``
        # before any prompt (J.4); prepared, then moved by another save, the dialog says why.
        moved = world.page.fetch(
            "POST", "/api/actions", json={"kind": "tool.allow", "data": allow_data("get", 3)}
        )
        assert status_reason(moved) == (409, "changed")
        assert "rows" not in moved.json()
        wrong = {**allow_data("list", 3), "pin": "sha256:" + "0" * 64}
        bad = world.page.fetch("POST", "/api/actions", json={"kind": "tool.allow", "data": wrong})
        assert status_reason(bad) == (409, "changed")


def test_managed_allow_by_a_draft(tmp_path: Path) -> None:
    """J3, Y7, managed: a review save whose only change is one move of an included approve tool
    is a ``tool.allow`` draft, prepared by its ID; both forms of data mixed are a bad body."""
    with managed_world(tmp_path) as world:
        job, _ = managed_job(world, managed_report())
        every = ["list", "search", "get"]
        body = {"include": every, "allow": ["list", "search"], "approve": ["get"]}
        draft = drafted(world, job, decline_rest=False, **body)
        assert (draft["kind"], draft["base"]) == ("tool.allow", 1)
        assert draft["summary"][1] == ["notes.search", MOVE_TEXT.format(name="search")]
        mixed = {**allow_data("search", 1), "draft": draft["draft"]}
        answer = world.page.fetch(
            "POST", "/api/actions", json={"kind": "tool.allow", "data": mixed}
        )
        assert status_reason(answer) == (400, "bad_body")
        assert saved(world, draft)["revision"] == 2
        assert head(world.rig)["tools"]["allow"] == ["list", "search"]


def test_managed_allow_shows_the_reviewed_side_of_a_drift(tmp_path: Path) -> None:
    """J.4, T-11: the server lists a new definition of ``search``; the plan shows the one the
    head pins, the review's reviewed side, every chunk of it, never the listed one."""
    old = hinted("search", "Searches notes.", READ_ONLY)
    new = hinted("search", "Searches notes, and sends them on.", READ_ONLY)
    entry = {
        "era": "modern",
        "tools": {"include": ["search"], "allow": [], "approve": ["search"]},
        "review": {"search": pin_of(old)},
    }
    with world_of(tmp_path, managed(**entry)) as world:
        policy = view_server([], ["search"], {"search": pin_of(old)})
        report = reviewed([new], policy, defs={pin_of(old): definition(old)})
        _, read = managed_job(world, report)
        assert [row["state"] for row in read["tools"]] == ["drift"]
        assert [item["held"] for item in approve_items(world)] == [True]
        held = prepared(world, "tool.allow", allow_data("search", 1, pin_of(old)))
        summary = held["summary"]
        assert summary[1] == ["notes.search", MOVE_TEXT.format(name="search")]
        assert summary[2][0] == f"search, as pinned ({pin_of(old)})"
        lines = definition_lines(definition(old))
        assert chunks(summary, "search") == [chunk for line in lines for chunk in line]
        assert "sends them on" not in " ".join(chunks(summary, "search"))
        assert confirmed(world, held).json()["revision"] == 2
        assert head(world.rig)["tools"]["allow"] == ["search"]


def kit_report(found: Tool) -> dict[str, Any]:
    """The gateway's review of ``kit``, a ``pinning: off`` toolkit including ``found`` as
    approve: listed at its pin, which the policy can't hold."""
    listed = {
        "kind": "tool",
        "name": found.name,
        "state": "ok",
        "included": True,
        "classification": "approve",
        "pin": pin_of(found),
        "pinned": None,
        "definition": definition(found),
        "findings": [],
        "changed": None,
        "diff": None,
        "consequential": False,
    }
    reviewed_policy = {
        "include": [found.name],
        "allow": [],
        "approve": [found.name],
        "on_drift": "hide",
        "review": {},
        "declined": {},
    }
    return {
        "server": "kit",
        "kind": "toolkit",
        "module": "examples.kit",
        "distribution": None,
        "version": None,
        "pinning": "off",
        "slots": [],
        "policy": reviewed_policy,
        "blocked": False,
        "marked": [],
        "tools": [listed],
        "clean": True,
    }


def test_managed_allow_on_a_pinning_off_toolkit(tmp_path: Path) -> None:
    """J.4, G.7, owner pick 6: a ``pinning: off`` toolkit holds no pin, so its row names the pin
    the newest held review lists (none before a review), and the plan shows that listed
    definition, then the fixed "pinning is off" row; one passkey writes the move."""
    found = hinted("x", "Reads a thing.", READ_ONLY)
    policy = managed(era="modern")
    kit = {
        "kind": "toolkit",
        "module": "examples.kit",
        "pinning": "off",
        "tools": {"include": ["x"], "allow": [], "approve": ["x"]},
    }
    policy["gateway"]["servers"]["kit"] = kit
    with world_of(tmp_path, policy) as world:
        assert approve_items(world, "kit") == [
            {"name": "x", "name_shown": "x", "pin": None, "held": False}
        ]
        queued = world.page.fetch("POST", "/api/review/kit", json={"fresh": True})
        assert queued.status_code == 200, queued.text
        gateway_answers(world.rig, kit_report(found))
        assert approve_items(world, "kit") == [
            {"name": "x", "name_shown": "x", "pin": pin_of(found), "held": True}
        ]
        data = {"base": 1, "server": "kit", "kind": "tool", "name": "x", "pin": pin_of(found)}
        held = prepared(world, "tool.allow", data)
        summary = held["summary"]
        assert summary[1] == ["kit.x", MOVE_TEXT.format(name="x")]
        assert summary[2][0] == "x, as pinned"  # no pin to name
        lines = [chunk for line in definition_lines(definition(found)) for chunk in line]
        assert chunks(summary, "x") == lines
        after = 2 + len(lines)
        assert summary[after] == ["kit", PINNING_OFF_TEXT.format(server="kit")]
        assert confirmed(world, held).json()["revision"] == 2
        servers = world.rig.vault.managed.policy.gateway.servers  # type: ignore[union-attr]
        assert servers["kit"].tools.allow == ["x"]


def test_managed_allow_too_long_for_the_dialog(tmp_path: Path) -> None:
    """J.4, G.5 rule 5 (Y9): a tool whose definition alone is more than 400 rows is refused
    ``summary_too_large`` before any prompt, its way on the host's export and import."""
    properties = {f"p{index:03}": {"type": "string"} for index in range(150)}
    big = Tool.model_validate(
        {
            "name": "big",
            "description": "Takes many fields.",
            "inputSchema": {"type": "object", "properties": properties},
            "annotations": READ_ONLY,
        }
    )
    lines = definition_lines(definition(big))
    assert sum(len(line) for line in lines) > SUMMARY_ROWS_MAX
    entry = {
        "era": "modern",
        "tools": {"include": ["big"], "allow": [], "approve": ["big"]},
        "review": {"big": pin_of(big)},
    }
    with world_of(tmp_path, managed(**entry)) as world:
        managed_job(world, reviewed([big], view_server([], ["big"], {"big": pin_of(big)})))
        data = allow_data("big", 1, pin_of(big))
        refused = world.page.fetch(
            "POST", "/api/actions", json={"kind": "tool.allow", "data": data}
        )
        assert status_reason(refused) == (413, "summary_too_large")
        answer = refused.json()
        assert "zoeymcp policy export" in answer["error"]
        assert [step["do"] for step in answer["next"]] == ["export_policy", "import_policy"]
        assert len(world.rig.app.actions) == 0
