"""Drift on the review screen, and prompts and resources, in a real browser: manual items 19 and 24
(M8 design step 27c; D-222).

The real vault and portal on loopback (``tests.portal.rig``), declarative, ``notes`` connected and
reviewed: item 19's policy includes ``echo`` as allow and ``add``, ``slow`` and ``read_01`` as
approve, each pinned at the fake MCP server's definition with ``--switch large --switch
markup_echo``; item 24's enables prompts and resources. The gateway's side is played on the
vault's loop (``tests/portal/test_review.py``'s way), each report straight from the gateway's
review code over the fake's own definitions as it lists them after the change the item makes
(``--drift description``, ``--drift annotations``, ``--switch inject_definitions``, ``--switch
inject_kinds``, ``--change-kind``), with the gateway's reviewed copies (``defs/``) or without them,
as a gateway restarted on its state directory has them or one whose old copy was removed. The
page runs with the browser's own WebAuthn stack over a virtual authenticator, its Content
Security Policy and Trusted Types in force, every page watched (no violation, no dialog: the
markup's ``onerror`` never runs). Each test's docstring names its item and the lines it checks;
``docs/manual-checks.md`` keeps the lines left by hand.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest
from mcp.types import Prompt, Resource, ResourceTemplate, Tool
from playwright.sync_api import Page, Response, expect

from tests.fakes.mcp_server import (
    FIXED,
    HIDDEN_PROMPT,
    HOSTILE_FIXED,
    HOSTILE_PROMPT,
    HOSTILE_TEMPLATE,
    MARKUP,
    TEMPLATE,
    ListedKind,
    McpFake,
    Switch,
)
from tests.portal.rig import rig_policy
from tests.portal.test_home import OFFERS, reported
from tests.portal.test_home import server as status
from tests.portal.test_review import notes_entries, poller
from tests.unit.test_pins import kinds_server
from tests.unit.test_review import LIMITS, reviewed
from tests.unit.test_reviewchange import server as view_server
from zoeymcp.common.policy.attention import Attention
from zoeymcp.common.policy.plan import REPINNED_TEXT
from zoeymcp.common.yamlload import load_mapping
from zoeymcp.gateway import pins, review
from zoeymcp.portal.refusals import CATALOGUE
from zoeymcp.vault.bindings import derive_binding

from .portal import (
    confirm,
    confirm_dialog,
    held_review,
    open_section,
    outcome,
    press,
    server_row,
    set_up,
    summary,
)
from .stacks import PortalRig, listed, portal
from .watch import Watch

ALLOW = ["echo"]
APPROVE = ["add", "slow", "read_01"]
# drift.js's words.
MISSING = "The gateway no longer has the reviewed copy: the new definition is shown whole."
PROPOSED = (
    "The new definition isn't marked read-only: approve is proposed. Choose allow above to keep "
    "it, and the fragment says you kept it."
)
# A refused request's answer, which the browser itself reports on the console.
REFUSED_409 = r"status of 409"
ASSISTANT = "brainstorm"
KINDS: tuple[ListedKind, ...] = ("prompt", "resource_template", "resource")
MODELS: dict[ListedKind, Any] = {
    "prompt": Prompt,
    "resource_template": ResourceTemplate,
    "resource": Resource,
}


# --- the fake's definitions, as the gateway reviews them -----------------------------------------


OLD = listed(Switch.LARGE, Switch.MARKUP_ECHO)


def pinned(tools: list[Tool]) -> dict[str, pins.Projected]:
    return {found.name: pins.project_and_pin(found) for found in tools}


def entry_of(tools: list[Tool]) -> dict[str, Any]:
    """The policy's notes entry: item 19's tools included, each pinned at ``tools``'s."""
    held = pinned(tools)
    return {
        "tools": {"include": [*ALLOW, *APPROVE], "allow": ALLOW, "approve": APPROVE},
        "review": {name: held[name].pin for name in [*ALLOW, *APPROVE]},
    }


def drifted(tools: list[Tool], *, kept: bool = True) -> dict[str, Any]:
    """The gateway's review of notes listing ``tools`` under item 19's policy, holding the
    reviewed copies of the pinned definitions (``defs/``) when ``kept``."""
    held = pinned(OLD)
    included = [*ALLOW, *APPROVE]
    view = view_server(ALLOW, APPROVE, {name: held[name].pin for name in included})
    defs = {held[name].pin: dict(held[name].definition) for name in included} if kept else {}
    return reviewed(tools, view, defs=defs)


def kinds_of(fake: McpFake) -> dict[ListedKind, list[Any]]:
    return {
        kind: [MODELS[kind].model_validate(w) for w in fake.definitions(kind)] for kind in KINDS
    }


def kind_pins(found: dict[ListedKind, list[Any]]) -> dict[ListedKind, dict[str, pins.Projected]]:
    """Each listed entry's projection and pin, by its kind's key (a name, or a URI)."""
    keys = {"prompt": "name", "resource_template": "uri_template", "resource": "uri"}
    return {
        kind: {str(getattr(item, keys[kind])): pins.project_kind(kind, item) for item in items}
        for kind, items in found.items()
    }


# Item 24's included entries: two prompts, the template and the fixed resource.
INCLUDED_KINDS: dict[ListedKind, list[str]] = {
    "prompt": [ASSISTANT, HIDDEN_PROMPT],
    "resource_template": [TEMPLATE],
    "resource": [FIXED],
}
PLAIN_KINDS = kind_pins(kinds_of(McpFake(prompts=True, resources=True)))


def kinds_policy(included: bool) -> dict[str, Any]:
    """The policy's prompts and resources blocks: item 24's entries included at their pins, or
    nothing yet."""

    def block(kind: ListedKind) -> dict[str, Any]:
        names = INCLUDED_KINDS[kind] if included else []
        return {"include": names, "review": {n: PLAIN_KINDS[kind][n].pin for n in names}}

    return {
        "prompts": block("prompt"),
        "resources": {"templates": block("resource_template"), "fixed": block("resource")},
    }


def kinds_review(fake: McpFake, *, included: bool) -> dict[str, Any]:
    """The gateway's review of notes enabling prompts and resources, listing what ``fake``
    lists, under a policy including item 24's entries (or none), holding their reviewed
    copies."""
    blocks = kinds_policy(included)
    view = kinds_server(
        prompts=blocks["prompts"],
        templates=blocks["resources"]["templates"],
        fixed=blocks["resources"]["fixed"],
    )
    tools = [Tool.model_validate(wire) for wire in fake.tools_for(None, 1)]
    found: dict[pins.DefinitionKind, pins.KindListing] = {
        kind: pins.KindListing(items) for kind, items in kinds_of(fake).items()
    }
    evaluation = pins.evaluate_server(tools, found, view, {}, LIMITS)
    copies = {
        projected.pin: dict(projected.definition)
        for by_key in PLAIN_KINDS.values()
        for projected in by_key.values()
    }
    answer = review.report(
        "notes",
        view,
        tools,
        evaluation,
        marks=frozenset(),
        defs=lambda pin_: None,
        limits=LIMITS,
        era="modern",
        protocol_version="2026-07-28",
        server_info=None,
        instructions=None,
        kinds={kind: review.KindReview(listing) for kind, listing in found.items()},
        kind_defs=lambda pin_, kind: copies.get(pin_),
    )
    loaded: dict[str, Any] = json.loads(json.dumps(answer))  # as the vault receives it
    return loaded


# --- the rigs ------------------------------------------------------------------------------------


def connected(tmp_path: Path, entry: dict[str, Any]) -> Iterator[PortalRig]:
    """Notes with ``entry``, its refresh token stored, and a gateway's poll waiting."""
    with portal(tmp_path, policy=notes_entries(**entry)) as running:
        secrets = running.app.secrets
        assert secrets is not None
        binding = derive_binding(running.vault.app.policy, "notes-refresh")
        running.call(lambda: secrets.store.put("notes-refresh", "r" * 24, binding))
        poller(running)
        yield running


@pytest.fixture
def rig(tmp_path: Path) -> Iterator[PortalRig]:
    """Item 19's: item 16's setup, reviewed and committed at ``large`` with ``markup_echo``."""
    yield from connected(tmp_path, entry_of(OLD))


@pytest.fixture
def enabled(tmp_path: Path) -> Iterator[PortalRig]:
    """Item 24's: ``enable: [prompts, resources]`` added, nothing of them included yet."""
    entry = {"enable": ["prompts", "resources"], **kinds_policy(included=False)}
    yield from connected(tmp_path, entry)


@pytest.fixture
def included(tmp_path: Path) -> Iterator[PortalRig]:
    """Item 24's after fragment 2's commit: the four entries included at their pins."""
    entry = {"enable": ["prompts", "resources"], **kinds_policy(included=True)}
    yield from connected(tmp_path, entry)


@pytest.fixture
def managed_kinds(tmp_path: Path) -> Iterator[PortalRig]:
    """Item 24 in managed mode: item 20's vault with ``enable`` in its seed (the policy file
    seeds revision 1 here), nothing of the kinds included yet."""
    entry = {"era": "modern", "enable": ["prompts", "resources"], **kinds_policy(included=False)}
    with portal(tmp_path, policy={**notes_entries(**entry), "mode": "managed"}) as running:
        managed = running.vault.managed
        secrets = running.app.secrets
        assert managed is not None
        assert secrets is not None
        binding = derive_binding(managed.policy, "notes-refresh")
        running.call(lambda: secrets.store.put("notes-refresh", "r" * 24, binding))
        poller(running)
        yield running


# --- the page ------------------------------------------------------------------------------------


def review_again(page: Page, rig: PortalRig, report: dict[str, Any]) -> dict[str, Any]:
    """**Review again** on notes' row (**Review tools** while it includes no tool), under what
    the gateway reports: the review drawn."""
    open_section(page, "MCP servers")
    named = re.compile("^Review (again|tools)$")
    again = server_row(page, "notes (remote)").get_by_role("button", name=named)
    return held_review(page, rig, report, again.click)


def tool_entry(read: dict[str, Any], name: str) -> dict[str, Any]:
    found: dict[str, Any] = next(t for t in read["tools"] if t["name"] == name)
    return found


def joined(lines: list[list[str]]) -> str:
    """A definition's chunks, as the page's spans read together."""
    return "".join(chunk for line in lines for chunk in line)


def generated(page: Page) -> str:
    """**Generate**: fragment 2, as the vault answered it."""

    def diffed(answer: Response) -> bool:
        return answer.request.method == "POST" and answer.url.endswith("/diff")

    with page.expect_response(diffed) as made:
        page.locator("#review-generate").click()
    assert made.value.ok, made.value.text()
    yaml: str = made.value.json()["diff"]["yaml"]
    expect(page.locator("#fragment-title")).to_have_text("Fragment 2 of 2")
    return yaml


def notes_of(yaml: str) -> dict[str, Any]:
    entry: dict[str, Any] = load_mapping(yaml)["gateway"]["servers"]["notes"]
    return entry


# --- item 19: the drift review -------------------------------------------------------------------


def test_item_19_a_drifted_tool_shows_both_definitions_and_the_diff_as_text(
    rig: PortalRig, page: Page, watch: Watch
) -> None:
    """Item 19, restarted with ``--switch large --switch markup_echo --switch inject_definitions
    --drift description``, **Review again**: "no Trusted Types or Content Security Policy
    violation in the console, no alert, and no request for ``x``; ``echo`` reads ``drift``, with
    **Reviewed** and **Now** side by side, each the whole definition in marked chunks with
    nothing cut and the markup shown as text in both, and the vault's diff under them, its ``-``
    and ``+`` description lines each showing the markup as text; ``summarize``'s text shows as
    item 16 says"."""
    set_up(page, rig)
    tools = listed(Switch.LARGE, Switch.MARKUP_ECHO, Switch.INJECT_DEFINITIONS, drift="description")
    read = review_again(page, rig, drifted(tools))
    echo = tool_entry(read, "echo")
    assert echo["state"] == "drift"
    row = page.locator("#review-tools > li").nth(read["tools"].index(echo))
    expect(row.locator("b").first).to_have_text("echo")
    expect(row.locator(".badge").first).to_have_text("drift")
    block = row.locator("div.drift")
    expect(block.locator("div").nth(0)).to_have_text(f"Reviewed ({echo['pinned']})")
    expect(block.locator("div").nth(1)).to_have_text(f"Now ({echo['pin']})")
    reviewed_, now, diff = (block.locator("pre").nth(index) for index in range(3))
    assert reviewed_.text_content() == joined(echo["reviewed_lines"])
    assert now.text_content() == joined(echo["definition_lines"])
    assert diff.text_content() == joined(echo["diff_lines"])
    for shown in (reviewed_, now):
        assert MARKUP.split(" & ")[0] in (shown.text_content() or "")  # the markup, as text
    left, right = reviewed_.bounding_box(), now.bounding_box()
    assert left is not None
    assert right is not None
    assert right["x"] >= left["x"] + left["width"]  # side by side
    assert abs(right["y"] - left["y"]) < 1
    lines = ["".join(chunks) for chunks in echo["diff_lines"]]
    assert [line for line in lines if line.startswith("-") and "<img src=x" in line]
    assert [line for line in lines if line.startswith("+") and "<img src=x" in line]
    summarize = tool_entry(read, "summarize")
    row_said = page.locator("#review-tools > li").nth(read["tools"].index(summarize))
    expect(row_said.locator("p.description")).to_have_text(summarize["description_shown"])
    assert "[U+202E]" in summarize["description_shown"]
    tags: list[str] = page.locator("#review").evaluate(
        "(review) => Array.from(review.querySelectorAll('img, a, script, svg, iframe'),"
        " (element) => element.tagName)"
    )
    assert tags == []
    assert [r.url for r in watch.requests if urlsplit(r.url).path.endswith("/x")] == []


def test_item_19_accepting_a_definition_no_longer_read_only_proposes_approve(
    rig: PortalRig, page: Page
) -> None:
    """Item 19, restarted with ``--drift annotations``, **Review again**: "``echo`` now says it is
    destructive and not read-only (the markup as text in both columns again), and **Accept the
    new definition** on it says approve is proposed and sets its row to approve (unticking it
    puts allow back); **Generate** with **Accept** still ticked and the row's choice set back to
    allow gives the new pin under ``review:``, ``# changed: echo (was sha256:...)`` and ``# kept:
    echo (allow: ...)``, and with approve left as accepted, ``echo`` under ``approve:``"."""
    set_up(page, rig)
    tools = listed(Switch.LARGE, Switch.MARKUP_ECHO, drift="annotations")
    read = review_again(page, rig, drifted(tools))
    echo = tool_entry(read, "echo")
    row = page.locator("#review-tools > li").nth(read["tools"].index(echo))
    now = row.locator("div.drift pre").nth(1)
    assert '"destructiveHint": true' in (now.text_content() or "")
    assert '"readOnlyHint": false' in (now.text_content() or "")
    expect(row.get_by_text(PROPOSED, exact=True)).to_be_visible()
    accept = row.get_by_label("Accept the new definition")
    choice = row.locator("select")
    expect(choice).to_have_value("allow")
    accept.check()
    expect(choice).to_have_value("approve")
    accept.uncheck()
    expect(choice).to_have_value("allow")
    accept.check()
    choice.select_option("allow")
    kept = generated(page)
    assert f"# changed: echo (was {echo['pinned']})" in kept
    assert "# kept: echo (allow: " in kept
    assert notes_of(kept)["review"]["echo"] == echo["pin"]
    assert "echo" in notes_of(kept)["tools"]["allow"]
    choice.select_option("approve")
    approved = generated(page)
    assert "echo" in notes_of(approved)["tools"]["approve"]
    assert notes_of(approved)["review"]["echo"] == echo["pin"]


def test_item_19_without_the_reviewed_copy_the_new_definition_shows_whole(
    rig: PortalRig, page: Page
) -> None:
    """Item 19: "after a restart of the gateway and **Review again**, ``echo`` still shows both
    columns: the gateway keeps reviewed copies in its state directory (``defs/``) ... With the old
    copy removed ... and **Review again**, ``echo``'s row says the gateway no longer has the
    reviewed copy and shows the new definition whole". The gateway's side is the report with
    its copies (a restarted gateway on the same state) and then without them."""
    set_up(page, rig)
    tools = listed(Switch.LARGE, Switch.MARKUP_ECHO, drift="description")
    read = review_again(page, rig, drifted(tools))
    echo = tool_entry(read, "echo")
    row = page.locator("#review-tools > li").nth(read["tools"].index(echo))
    assert row.locator("div.drift pre").nth(0).text_content() == joined(echo["reviewed_lines"])
    read = review_again(page, rig, drifted(tools, kept=False))
    echo = tool_entry(read, "echo")
    assert echo["reviewed_missing"] is True
    row = page.locator("#review-tools > li").nth(read["tools"].index(echo))
    reviewed_, now = row.locator("div.drift pre").nth(0), row.locator("div.drift pre").nth(1)
    expect(reviewed_).to_have_text(MISSING)
    assert now.text_content() == joined(echo["definition_lines"])


def test_item_19_suggested_after_clear_declines_and_a_stale_review(
    rig: PortalRig, page: Page, watch: Watch
) -> None:
    """Item 19: "**Clear** then **Select suggested**: ``read_01`` comes back ticked at approve, its
    classification, the other read-only tools at allow, and **Generate** puts no tool the policy
    has in ``approve:`` under ``allow:``; with **Record the rest as declined** ticked,
    **Generate** writes every listed tool left out under ``declined:`` at its pin (not
    ``summarize``, which has an error finding); unticked, **Decline** on one tool adds that one
    alone ...; and after another fragment for the server is committed and reloaded, **Generate**
    on the old review is refused ``review_stale``" (the vault running: a reload here is
    ``SIGHUP``)."""
    set_up(page, rig)
    tools = listed(Switch.LARGE, Switch.MARKUP_ECHO, Switch.INJECT_DEFINITIONS)
    read = review_again(page, rig, drifted(tools))
    press(page, "Clear")
    press(page, "Select suggested")
    rows = page.locator("#review-tools > li")
    read_01 = rows.nth(read["tools"].index(tool_entry(read, "read_01")))
    expect(read_01.get_by_label("Include")).to_be_checked()
    expect(read_01.locator("select")).to_have_value("approve")
    read_02 = rows.nth(read["tools"].index(tool_entry(read, "read_02")))
    expect(read_02.locator("select")).to_have_value("allow")
    swept = generated(page)
    notes = notes_of(swept)
    assert not set(notes["tools"]["allow"]) & set(APPROVE)
    assert "read_01" in notes["tools"]["approve"]
    left_out = {
        t["name"]
        for t in read["tools"]
        if t["pinnable"] and t["name"] not in notes["tools"]["include"]
    }
    assert set(notes["declined"]) == left_out
    assert "summarize" not in notes["declined"]
    assert all(notes["declined"][name] == tool_entry(read, name)["pin"] for name in left_out)
    page.get_by_label("Record the rest as declined", exact=False).uncheck()
    write_01 = rows.nth(read["tools"].index(tool_entry(read, "write_01")))
    write_01.get_by_label("Decline: leave it out, recorded at this definition").check()
    one = notes_of(generated(page))
    assert one["declined"] == {"write_01": tool_entry(read, "write_01")["pin"]}
    rig.reload(rig_policy(rig.portal_port, **notes_entries(**entry_of(OLD), on_drift="fail")))
    watch.allow(REFUSED_409, on=rig.origin)
    page.locator("#review-generate").click()
    expect(outcome(page, "#review .z-actionbar")).to_contain_text(CATALOGUE["review_stale"].text)


# --- item 24: prompts and resources --------------------------------------------------------------


def test_item_24_prompts_and_resources_are_rows_of_their_own_and_hostile_ones_show_as_text(
    enabled: PortalRig, page: Page
) -> None:
    """Item 24, the fake with ``--prompts --resources --switch inject_kinds``, **Review again**:
    "after the tools, the rows sit under the headings **Prompts**, **Resource templates** and
    **Resources**, each row with its include box, **Show definition** and **Decline**, and no
    allow or approve control"; "the three hostile rows show every hidden character as the
    visible mark the vault gives it and ``<IMPORTANT>`` as text ... and can't be included (an
    error finding); **Show definition** shows each definition whole, every character outside
    ASCII as an escape"; "tick ``brainstorm``, ``summarize_note``, ``notes://notes/{id}`` and
    ``notes://index``, **Generate**: fragment 2's title names the ``prompts:`` and
    ``resources:`` blocks, its comments read ``# added: brainstorm (prompt)`` and so on, and
    ``# can't be included, error finding: hostile_prompt (prompt; ...)`` for each hostile
    entry"."""
    rig = enabled
    set_up(page, rig)
    fake = McpFake(prompts=True, resources=True, switches={Switch.INJECT_KINDS})
    read = review_again(page, rig, kinds_review(fake, included=False))
    rows = page.locator("#review-tools > li")
    headings = page.locator("#review-tools h3").all_text_contents()
    assert headings == ["Prompts", "Resource templates", "Resources"]
    for entry in read["tools"]:
        if entry["kind"] == "tool":
            continue
        row = rows.nth(read["tools"].index(entry))
        expect(row.locator("select")).to_have_count(0)  # no allow or approve
        if entry["pinnable"]:
            expect(row.get_by_label("Include")).to_be_visible()
            expect(row.get_by_label("Decline: leave it out", exact=False)).to_be_visible()
            continue
        assert entry["name"] in (HOSTILE_PROMPT, HOSTILE_TEMPLATE, HOSTILE_FIXED)
        expect(row).to_contain_text("Can't be included: ")
        expect(row).to_contain_text("<IMPORTANT>")
        assert "[U+200B]" in row.text_content()  # type: ignore[operator]
        row.get_by_role("button", name="Show definition", exact=True).click()
        shown = row.locator("pre.definition").text_content()
        assert shown == joined(entry["definition_lines"])
        assert shown.isascii()
    for kind, names in INCLUDED_KINDS.items():
        for name in names:
            entry = next(e for e in read["tools"] if e["kind"] == kind and e["name"] == name)
            rows.nth(read["tools"].index(entry)).get_by_label("Include").check()
    yaml = generated(page)
    title = yaml.splitlines()[0]
    assert "prompts:" in title
    assert "resources:" in title
    assert f"# added: {ASSISTANT} (prompt)" in yaml
    assert f"# added: {TEMPLATE} (resource template)" in yaml
    assert f"# can't be included, error finding: {HOSTILE_PROMPT} (prompt; " in yaml
    notes = notes_of(yaml)
    assert notes["prompts"]["include"] == INCLUDED_KINDS["prompt"]
    assert notes["resources"]["templates"]["include"] == [TEMPLATE]
    assert notes["resources"]["fixed"]["include"] == [FIXED]


def test_item_24_a_changed_prompt_and_template_read_drift_and_clear_unticks_every_kind(
    included: PortalRig, page: Page
) -> None:
    """Item 24, "restarted with ``--change-kind prompt --change-kind resource_template`` added,
    **Review again**: ``brainstorm`` and ``notes://notes/{id}`` read ``drift``, with **Reviewed**
    and **Now** side by side and the vault's diff under them, every string shown as text;
    **Accept the new definition** on both and **Generate**: the new pins under each block's
    ``review:``, each with a ``# changed:`` line; **Clear** unticks every kind's box as it does
    the tools'"."""
    rig = included
    set_up(page, rig)
    fake = McpFake(prompts=True, resources=True, changed_kinds={"prompt", "resource_template"})
    read = review_again(page, rig, kinds_review(fake, included=True))
    rows = page.locator("#review-tools > li")
    changed = [
        next(e for e in read["tools"] if e["kind"] == kind and e["name"] == name)
        for kind, name in (("prompt", ASSISTANT), ("resource_template", TEMPLATE))
    ]
    for entry in changed:
        assert entry["state"] == "drift"
        row = rows.nth(read["tools"].index(entry))
        pres = row.locator("div.drift pre")
        assert pres.nth(0).text_content() == joined(entry["reviewed_lines"])
        assert pres.nth(1).text_content() == joined(entry["definition_lines"])
        assert pres.nth(2).text_content() == joined(entry["diff_lines"])
        row.get_by_label("Accept the new definition").check()
    yaml = generated(page)
    notes = notes_of(yaml)
    assert notes["prompts"]["review"][ASSISTANT] == changed[0]["pin"]
    assert notes["resources"]["templates"]["review"][TEMPLATE] == changed[1]["pin"]
    assert f"# changed: {ASSISTANT} (prompt, was {changed[0]['pinned']})" in yaml
    assert yaml.count("# changed: ") == 2
    press(page, "Clear")
    boxes: list[bool] = page.locator("#review-tools input[type=checkbox]").evaluate_all(
        "(boxes) => boxes.filter((box) => !box.closest('label').textContent.includes('Accept')"
        " && !box.closest('label').textContent.includes('Decline')).map((box) => box.checked)"
    )
    assert boxes != []
    assert not any(boxes)


def test_item_24_the_row_and_home_say_what_the_gateway_reports(rig: PortalRig, page: Page) -> None:
    """Item 24: "Before ``enable`` is added, once an agent has listed the server's tools, the
    server's row on **MCP servers** reads 'offered, not served: prompts, resources, completions',
    its last step 'Add enable: [prompts, resources, completions] to notes in your policy and
    reload'"; and after the ``--change-kind`` restart, before the new pins are committed, "Home's
    list names 'notes changed 1 included prompt since the review' and 'notes changed 1 included
    resource template since the review', each with **Review**", from the gateway's status
    report (``tests/portal/test_home.py``'s way)."""
    set_up(page, rig)
    reported(rig, notes=status(offered=OFFERS))
    open_section(page, "MCP servers")
    row = server_row(page, "notes (remote)")
    expect(row).to_contain_text("; offered, not served: prompts, resources, completions.")
    expect(row.locator("ul.steps > li").last).to_have_text(
        "Add enable: [prompts, resources, completions] to notes in your policy and reload"
    )
    drift = {
        "prompt": Attention(drifted=(ASSISTANT,)),
        "resource_template": Attention(drifted=(TEMPLATE,)),
    }
    reported(rig, notes=status(kinds=drift))
    open_section(page, "Home")
    items = page.locator("#attention > li")
    for said in (
        "notes changed 1 included prompt since the review. ",
        "notes changed 1 included resource template since the review. ",
    ):
        item = items.filter(has_text=said)
        expect(item).to_have_count(1)
        expect(item.get_by_role("button", name="Review", exact=True)).to_be_visible()


def test_item_24_a_managed_save_names_each_kinds_paths_and_a_repin_shows_both_pins(
    managed_kinds: PortalRig, page: Page
) -> None:
    """Item 24 in managed mode: "the same review and **Save**: the dialog's rows name
    ``gateway.servers.notes.prompts.include`` and each kind's ``review`` pin, an accepted re-pin
    showing both pins and 're-pinned: you read both definitions'; confirmed with a passkey, the
    vault's log has ``step_up_confirmed`` with ``policy.save``". (An agent listing the included
    prompts through a gateway is S16's, ``tests/acceptance/test_prompts_resources_shape.py``.)"""
    rig = managed_kinds
    passkeys = set_up(page, rig)
    read = review_again(
        page, rig, kinds_review(McpFake(prompts=True, resources=True), included=False)
    )
    rows = page.locator("#review-tools > li")
    for kind, names in INCLUDED_KINDS.items():
        for name in names:
            entry = next(e for e in read["tools"] if e["kind"] == kind and e["name"] == name)
            rows.nth(read["tools"].index(entry)).get_by_label("Include").check()
    # This save is the kinds' alone: the tools left out stay undeclined.
    page.get_by_label("Record the rest as declined", exact=False).uncheck()
    press(page, "Save")
    labels = [label for label, _ in summary(page)]
    assert "gateway.servers.notes.prompts.include" in labels
    for name in (ASSISTANT, HIDDEN_PROMPT):
        assert f"gateway.servers.notes.prompts.review.{name}" in labels
    assert f"gateway.servers.notes.resources.templates.review.{TEMPLATE}" in labels
    assert f"gateway.servers.notes.resources.fixed.review.{FIXED}" in labels
    assert passkeys.asserted() == 1
    # Saved, the screen reviews the server again by itself: that review lists the changed prompt.
    fake = McpFake(prompts=True, resources=True, changed_kinds={"prompt"})
    read = held_review(page, rig, kinds_review(fake, included=True), lambda: confirm(page))
    expect(confirm_dialog(page)).to_be_hidden()
    assert rig.logged("step_up_confirmed", lambda line: line["action"] == "policy.save")
    brainstorm = next(e for e in read["tools"] if e["kind"] == "prompt" and e["name"] == ASSISTANT)
    assert brainstorm["state"] == "drift"
    rows.nth(read["tools"].index(brainstorm)).get_by_label("Accept the new definition").check()
    press(page, "Save")
    repin = REPINNED_TEXT.format(old=brainstorm["pinned"], new=brainstorm["pin"])
    assert (f"gateway.servers.notes.prompts.review.{ASSISTANT}", repin) in summary(page)
