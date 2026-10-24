"""Allow without asking, in declarative mode (M6 design J3, J.4; COV-3), over the real API.

``notes`` includes ``search`` in ``approve``, pinned. Its row on **MCP servers** names it, for
the page's **Allow without asking**, which opens the review screen with that one tool moved to
``allow`` (drift.js's ``move()``; ``tests.fakes.browser.Page`` runs no script, so the page's side
is pinned by ``tests/unit/test_portal_static.py``). The review's row starts it at ``approve``
(its ``prefill``), so nothing but that button moves it; Generate's fragment 2 then carries the
move and says what it allows in a comment, nothing saved; a move is checked as any choice is.
"""

from __future__ import annotations

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
from zoeymcp.common.yamlload import load_mapping

from .flows import set_up, status_reason
from .rig import running
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
    assert notes["approve"] == [{"name": "search", "name_shown": "search"}]
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
