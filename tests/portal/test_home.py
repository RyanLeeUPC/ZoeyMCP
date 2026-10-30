"""Home's attention list and the gateway's health section, over the real API (M6 design M.7,
M.5, K.1; D-29, D-174's bridge half, Y29).

The gateway is played on the vault's loop: its status report is kept as the status path keeps
one. ``GET /api/attention`` lists, per server, what the gateway's attention decision says needs
the operator, each item with its one action, a review of the server; a bridge's state is an
item while it isn't ready; the list holds at most 64. ``GET /api/health``'s checklist carries
the same server's findings under the ``gateway`` section, which the page words (app.js's
``SECTION``), as it words every section the report has. A server enabling prompts or resources
(D-216) has the same items for each kind, ``subject`` naming what each counts, a marked prompt's
action a clear; and its MCP servers row says what its upstream offers and it doesn't serve, with
J12's way to serve it (``offered_not_served``).
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from tests.fakes.authenticator import SoftAuthenticator
from tests.fakes.browser import Page
from tests.unit.test_portal_static import code_of, read
from zoeymcp.common.policy.attention import Attention
from zoeymcp.common.policy.schema import Tools
from zoeymcp.portal import app as portal_app
from zoeymcp.vault.onboarding import Listed
from zoeymcp.vault.statusreport import Report, ServerStatus

from .flows import set_up, status_reason
from .rig import PortalRig, running

VIEW = "sha256:" + "ab" * 32
PIN = "sha256:" + "c" * 64
RULES = [{"methods": ["POST", "GET", "DELETE"], "paths": ["/mcp"]}]


def route(name: str, upstream: str) -> dict[str, Any]:
    return {
        "name": name,
        "prefix": f"/{name}",
        "upstream": upstream,
        "credential": name,
        "callers": ["gateway"],
        "stream": True,
        "rules": RULES,
    }


GATEWAY: dict[str, Any] = {
    "credentials": {
        "notes": {"kind": "header", "secret": "store:notes-key"},
        "fetch": {"kind": "header", "secret": "store:fetch-key"},
    },
    "routes": [
        route("notes", "https://mcp.notes.example"),
        route("fetch", "unix:/run/zoeymcp-bridge-fetch/mcp.sock"),
    ],
    "gateway": {
        "servers": {
            "notes": {"kind": "remote", "route": "notes", "on_drift": "fail"},
            "fetch": {"kind": "remote", "route": "fetch"},
        }
    },
}


def server(**fields: Any) -> ServerStatus:
    values: dict[str, Any] = {
        "kind": "remote",
        "state": ("ready",),
        "era": "modern",
        "included": 3,
        "exposed": 0,
    }
    return ServerStatus(**{**values, **fields})


def reported(rig: PortalRig, **servers: ServerStatus) -> None:
    """The gateway's status report, kept as the status path keeps one."""
    report = Report(view=VIEW, started=1, servers=servers)
    rig.call(lambda: rig.vault.app.keep_status(report))


@pytest.fixture
def home(tmp_path: Path) -> Iterator[tuple[PortalRig, Page]]:
    with running(tmp_path, policy=GATEWAY) as rig:
        page = rig.browser().page(rig.origin)
        set_up(rig, page, SoftAuthenticator())
        yield rig, page


def attention(page: Page) -> dict[str, Any]:
    answer = page.fetch("GET", "/api/attention")
    assert answer.status_code == 200, answer.text
    found: dict[str, Any] = answer.json()
    return found


def review(server: str) -> dict[str, str]:
    return {"kind": "review", "server": server}


def clear(server: str) -> dict[str, str]:
    return {"kind": "clear", "server": server}


def test_nothing_before_the_gateway_reports(home: tuple[PortalRig, Page]) -> None:
    _, page = home
    assert attention(page) == {"gateway": True, "items": [], "more": 0, "reported_ago": None}


def test_the_attention_list_one_action_each(home: tuple[PortalRig, Page]) -> None:
    """M.7: drifted, missing and marked tools, the tools nobody reviewed (a declined one that
    changed among them), a blocked server and a bridge's state, each with Review, or for marked
    tools Clear the marks (J.4, J13)."""
    rig, page = home
    reported(
        rig,
        notes=server(
            drift=("a",),
            missing=("b", "c"),
            marked=("d",),
            unreviewed=(("purge", PIN), ("share", PIN)),
            declined_changed=("share",),
            blocked=True,
        ),
        fetch=server(state=("failed", "ready")),
    )
    found = attention(page)
    assert (found["gateway"], found["more"]) == (True, 0)
    assert 0 <= found["reported_ago"] < 60
    assert [(item["kind"], item["count"], item["text_shown"]) for item in found["items"]] == [
        ("bridge", 1, "fetch (a bridge): failed, ready"),
        ("drifted", 1, "notes changed 1 included tool since the review"),
        ("missing", 2, "notes no longer lists 2 included tools"),
        ("marked", 1, "notes has 1 included tool hidden by a drift mark"),
        ("unreviewed", 2, "notes lists 2 tools nobody reviewed"),
        ("blocked", 1, "notes is blocked (on_drift: fail): it serves no tool"),
    ]
    assert [item["action"] for item in found["items"]] == [
        review("fetch"),
        review("notes"),
        review("notes"),
        clear("notes"),
        review("notes"),
        review("notes"),
    ]
    assert {item["server_shown"] for item in found["items"]} == {"fetch", "notes"}


def test_a_quiet_gateway_lists_nothing(home: tuple[PortalRig, Page]) -> None:
    """A ready bridge and a server whose decision is quiet are no item; Home and health agree."""
    rig, page = home
    reported(rig, notes=server(), fetch=server(state=("idle",)))
    assert attention(page)["items"] == []
    health = page.fetch("GET", "/api/health").json()
    assert health["gateway"]["findings"] == []
    assert "servers" not in health["gateway"]  # Home's list reads the rows, not the page


def test_the_checklist_carries_the_gateways_findings_in_words(
    home: tuple[PortalRig, Page],
) -> None:
    """The same server's findings in health's checklist, under the gateway section, each with
    its action; and every section the checklist names is worded by the page (Q14)."""
    rig, page = home
    reported(rig, notes=server(unreviewed=(("purge", PIN),), drift=("a",), blocked=True))
    health = page.fetch("GET", "/api/health").json()
    gateway = [f for f in health["checklist"] if f["section"] == "gateway"]
    assert [(f["code"], f["text_shown"], f["action"]) for f in gateway] == [
        ("tools_unreviewed", "notes lists 1 tool nobody reviewed", review("notes")),
        (
            "drift_marked",
            "notes: included tools 1 changed since the review (a)",
            review("notes"),
        ),
        (
            "server_blocked",
            "notes is blocked (on_drift: fail): none of its tools are served",
            review("notes"),
        ),
    ]
    assert all(f["todo"] is None for f in gateway)  # the page draws Review for it
    app = code_of(read("app.js"))
    section = app[app.index("const SECTION = {") :]
    worded = set(re.findall(r"(\w+): \"", section[: section.index("};")]))
    assert {f["section"] for f in health["checklist"]} <= worded
    assert {"gateway", "policy"} <= worded
    items = attention(page)["items"]
    assert [item["kind"] for item in items] == ["drifted", "unreviewed", "blocked"]


def test_only_a_full_session_reads_it(home: tuple[PortalRig, Page]) -> None:
    rig, _ = home
    anonymous = rig.browser().page(rig.origin)
    assert status_reason(anonymous.fetch("GET", "/api/attention")) == (401, "no_session")


def test_no_gateway_no_list(tmp_path: Path) -> None:
    with running(tmp_path) as rig:
        page = rig.browser().page(rig.origin)
        set_up(rig, page, SoftAuthenticator())
        assert attention(page) == {"gateway": False, "items": [], "more": 0, "reported_ago": None}


def row(name: str, **attention: list[str]) -> dict[str, Any]:
    found: dict[str, list[str]] = {
        "drifted": [],
        "marked": [],
        "new": [],
        "changed_declined": [],
        "missing": [],
    }
    return {
        "name": name,
        "kind": "remote",
        "bridge": False,
        "state": ["ready"],
        "era": "modern",
        "attention": {**found, **attention},
        "blocked": False,
        "invalid": [],
        "unnamed": 0,
    }


def test_at_most_64_items_and_how_many_more() -> None:
    rows = [row(f"s{n:02}", new=["a"], drifted=["b"]) for n in range(40)]
    found = portal_app.attention_items({"gateway": {"reported_ago": 3, "servers": rows}})
    assert len(found["items"]) == portal_app.ATTENTION_MAX == 64
    assert found["more"] == 80 - 64
    assert found["items"][-1]["server_shown"] == "s31"
    exactly = portal_app.attention_items({"gateway": {"reported_ago": 3, "servers": rows[:32]}})
    assert (len(exactly["items"]), exactly["more"]) == (64, 0)


def test_an_unreviewed_tool_counts_once() -> None:
    """A declined tool that changed is a tool nobody reviewed, counted once."""
    found = portal_app.attention_items(
        {
            "gateway": {
                "reported_ago": 0,
                "servers": [row("notes", new=["a", "b"], changed_declined=["b", "c"])],
            }
        }
    )
    [item] = found["items"]
    assert (item["kind"], item["count"]) == ("unreviewed", 3)


# --- prompts and resources (D-216, J12) ---------------------------------------------------------

TEMPLATE = "notes://notes/{id}"
KINDS: dict[str, Any] = {
    **GATEWAY,
    "gateway": {
        "servers": {
            "notes": {
                "kind": "remote",
                "route": "notes",
                "on_drift": "fail",
                "enable": ["prompts", "resources"],
            },
            "fetch": {"kind": "remote", "route": "fetch"},
        }
    },
}
OFFERS = {"prompts": True, "resources": True, "completions": True, "logging": True}


@pytest.fixture
def kinds_home(tmp_path: Path) -> Iterator[tuple[PortalRig, Page]]:
    with running(tmp_path, policy=KINDS) as rig:
        page = rig.browser().page(rig.origin)
        set_up(rig, page, SoftAuthenticator())
        yield rig, page


def test_each_kinds_items_name_it(kinds_home: tuple[PortalRig, Page]) -> None:
    """Each kind the gateway reports has the tools' items, after them, its words naming the kind
    and ``subject`` saying which; a marked prompt is cleared as a tool is (the clear job clears
    every kind); a blocked server serves no tool, prompt or resource (Q20 (a))."""
    rig, page = kinds_home
    kinds = {
        "prompt": Attention(drifted=("summarize",), marked=("brainstorm",), new=("a", "b")),
        "resource_template": Attention(drifted=(TEMPLATE,), missing=("notes://x/{y}",)),
        "resource": Attention(changed_declined=("notes://index",)),
    }
    reported(rig, notes=server(drift=("echo",), kinds=kinds, blocked=True))
    found = attention(page)["items"]
    assert [
        (item["kind"], item["subject"], item["count"], item["text_shown"]) for item in found
    ] == [
        ("drifted", "tool", 1, "notes changed 1 included tool since the review"),
        ("drifted", "prompt", 1, "notes changed 1 included prompt since the review"),
        ("marked", "prompt", 1, "notes has 1 included prompt hidden by a drift mark"),
        ("unreviewed", "prompt", 2, "notes lists 2 prompts nobody reviewed"),
        (
            "drifted",
            "resource_template",
            1,
            "notes changed 1 included resource template since the review",
        ),
        (
            "missing",
            "resource_template",
            1,
            "notes no longer lists 1 included resource template",
        ),
        ("unreviewed", "resource", 1, "notes lists 1 resource nobody reviewed"),
        (
            "blocked",
            "tool",
            1,
            "notes is blocked (on_drift: fail): it serves no tool, prompt or resource",
        ),
    ]
    marked = [item for item in found if item["kind"] == "marked"]
    assert [item["action"] for item in marked] == [clear("notes")]
    assert all(item["action"] == review("notes") for item in found if item not in marked)
    # Health's checklist names the same kinds (M.5): the same findings, Home's list the same.
    health = page.fetch("GET", "/api/health").json()
    texts = [f["text_shown"] for f in health["checklist"] if f["section"] == "gateway"]
    assert "notes lists 2 prompts nobody reviewed" in texts
    assert (
        "notes is blocked (on_drift: fail): none of its tools, prompts or resources are served"
        in texts
    )


def test_a_tools_only_items_subject_is_tool() -> None:
    found = portal_app.attention_items(
        {"gateway": {"reported_ago": 0, "servers": [row("notes", new=["a"], marked=["b"])]}}
    )
    assert [(item["kind"], item["subject"]) for item in found["items"]] == [
        ("marked", "tool"),
        ("unreviewed", "tool"),
    ]
    blocked = {**row("notes"), "blocked": True}
    [item] = portal_app.attention_items({"gateway": {"reported_ago": 0, "servers": [blocked]}})[
        "items"
    ]
    assert item["text_shown"] == "notes is blocked (on_drift: fail): it serves no tool"


def test_the_kinds_items_count_toward_the_cap() -> None:
    kinds = {"prompt": Attention(new=("a",)).as_dict()}
    rows = [{**row(f"s{n:02}", new=["a"]), "kinds": kinds} for n in range(40)]
    found = portal_app.attention_items({"gateway": {"reported_ago": 3, "servers": rows}})
    assert len(found["items"]) == portal_app.ATTENTION_MAX
    assert found["more"] == 80 - 64
    assert [item["subject"] for item in found["items"][:2]] == ["tool", "prompt"]


def servers_row(page: Page, name: str) -> dict[str, Any]:
    answer = page.fetch("GET", "/api/servers")
    assert answer.status_code == 200, answer.text
    [found] = [r for r in answer.json()["servers"] if r.get("server") == name]
    result: dict[str, Any] = found
    return result


def test_the_row_says_what_is_offered_and_not_served(home: tuple[PortalRig, Page]) -> None:
    """J12's row: before ``enable`` is added, the MCP servers row of a server whose upstream
    offers prompts, resources and completions names them (never logging), and its last step is
    the declarative way to serve them, text only; nothing before the gateway reports."""
    rig, page = home
    before = servers_row(page, "notes")
    assert before["offered_not_served"] == []
    assert all(step["do"] != "enable_kinds" for step in before["next"])
    reported(rig, notes=server(offered=OFFERS), fetch=server())
    row = servers_row(page, "notes")
    assert row["offered_not_served"] == ["prompts", "resources", "completions"]
    assert row["next"][-1] == {
        "do": "enable_kinds",
        "label": "Add enable: [prompts, resources, completions] to notes in your policy and reload",
    }
    assert servers_row(page, "fetch")["offered_not_served"] == []  # its status offered nothing


def test_the_row_names_only_what_enable_leaves_out(kinds_home: tuple[PortalRig, Page]) -> None:
    rig, page = kinds_home
    reported(rig, notes=server(offered=OFFERS))
    row = servers_row(page, "notes")
    assert row["offered_not_served"] == ["completions"]
    assert row["next"][-1]["label"] == (
        "Add enable: [completions] to notes in your policy and reload"
    )


def test_a_managed_row_says_export_and_import() -> None:
    """J12's managed text: ``enable`` is wider, so the host's export, edit and import."""
    listed = Listed("notes", "remote", Tools(), "hide")
    found = portal_app._server_row(listed, None, ["prompts", "logging"], managed=True)
    assert found["offered_not_served"] == ["prompts"]
    assert found["next"][-1] == {
        "do": "enable_kinds",
        "label": "Export, add enable: [prompts] to notes, import",
    }
    toolkit = Listed("kit", "toolkit", Tools(), "hide")
    assert "offered_not_served" not in portal_app._server_row(toolkit, None, ["prompts"])
