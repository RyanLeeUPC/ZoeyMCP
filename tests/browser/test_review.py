"""The review screen and the fragments in a real browser: manual items 16 and 17 (M8 design step
27c; D-222).

Item 16 runs on the real vault and portal on loopback (``tests.portal.rig``), declarative, with
``notes`` connected and nothing included yet; the gateway's side is played on the vault's loop
(``tests/portal/test_review.py``'s way), its reports straight from the gateway's review code over
the fake MCP server's own definitions: ``large`` (96 tools), and ``inject_definitions``,
``inject_server_info`` and ``invalid_name`` (``tests/fakes/mcp_server.py``'s hostile text, the
same strings the item's fake serves). Item 17 runs on the onboarding world (``stacks.onboarding``):
the vault's own onboarding service in process, the provider registering clients. The page runs
with the browser's own WebAuthn stack over a virtual authenticator, its Content Security Policy
and Trusted Types in force, every page watched; the clipboard is the browser's, read back after
**Copy**. Each test's docstring names its item and the lines it checks; ``docs/manual-checks.md``
keeps the lines left by hand.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from mcp.types import Implementation, Tool
from playwright.sync_api import BrowserContext, Locator, Page, Response, expect

from tests.fakes.mcp_server import HOSTILE, McpFake, Switch
from tests.portal.test_review import notes_entries, poller
from tests.unit.test_review import reviewed
from tests.unit.test_review_choices import large
from tests.unit.test_reviewchange import server as view_server
from zoeymcp.vault.bindings import derive_binding

from .portal import (
    copied,
    fragment_text,
    held_review,
    open_section,
    press,
    register_by_url,
    server_row,
    set_up,
    shows,
)
from .stacks import Onboarding, PortalRig, onboarding, portal

# What the page makes on the review screen: anything else there came from a server string.
OWN_TAGS = {
    "B", "BUTTON", "DIV", "H3", "INPUT", "LABEL", "LI", "OPTION", "P", "PRE", "SELECT", "SPAN",
    "UL",
}  # fmt: skip
# Item 17: the longest authorization endpoint a policy takes.
LONGEST = 2_048


@pytest.fixture
def rig(tmp_path: Path) -> Iterator[PortalRig]:
    """Notes in the policy, its refresh token stored (connected), nothing included yet, and a
    gateway's poll waiting."""
    with portal(tmp_path, policy=notes_entries()) as running:
        secrets = running.app.secrets
        assert secrets is not None
        binding = derive_binding(running.vault.app.policy, "notes-refresh")
        running.call(lambda: secrets.store.put("notes-refresh", "r" * 24, binding))
        poller(running)
        yield running


@pytest.fixture
def boarding(tmp_path: Path, provider_tls: tuple[Path, Path]) -> Iterator[Onboarding]:
    """Item 17's provider: its authorization endpoint as long as a policy takes."""
    with onboarding(tmp_path, provider_tls, authorize_length=LONGEST) as found:
        yield found


def hostile() -> dict[str, Any]:
    """The gateway's review of the fake MCP server started with ``--switch inject_definitions
    --switch inject_server_info --switch invalid_name``: its tools as it lists them, its name and
    instructions as it says them, under a policy including nothing."""
    fake = McpFake(
        switches={Switch.INJECT_DEFINITIONS, Switch.INJECT_SERVER_INFO, Switch.INVALID_NAME}
    )
    tools = [Tool.model_validate(wire) for wire in fake.tools_for(None, 1)]
    about = Implementation.model_validate(fake._hostile_server_info())
    return reviewed(tools, view_server([], [], {}), server_info=about, instructions=HOSTILE)


def review_tools(page: Page, rig: PortalRig, report: dict[str, Any]) -> dict[str, Any]:
    """**Review tools** on notes' row, drawn from ``report``: the job's answer the page read."""
    open_section(page, "MCP servers")
    start = server_row(page, "notes (remote)").get_by_role("button", name="Review tools")
    return held_review(page, rig, report, start.click)


def visible_rows(page: Page) -> Locator:
    return page.locator("#review-tools > li:visible")


def generate(page: Page) -> Locator:
    return page.locator("#review-generate")


# --- item 16: the review screen with hostile text ------------------------------------------------


def test_item_16_a_large_server_counts_filters_and_selects_as_the_vault_says(
    rig: PortalRig, page: Page
) -> None:
    """Item 16 with ``--switch large``: "the counts read 96 tools, 64 the server marks read-only
    and 32 not annotated; the chips each keep those tools, the filter keeps the names holding its
    text, **Select suggested** includes the 64 as allow and no unannotated tool, **Clear**
    empties the selection, and **Generate** counts what is included"."""
    set_up(page, rig)
    read = review_tools(page, rig, large())
    tools = read["tools"]
    counts = page.locator("#review-counts")
    expect(counts).to_contain_text("96 tools: 64 the server marks read-only, 32 not annotated, ")
    expect(visible_rows(page)).to_have_count(96)
    page.get_by_label("Suggested read-only").check()
    expect(visible_rows(page)).to_have_count(64)
    page.get_by_label("Suggested read-only").uncheck()
    page.get_by_label("Not annotated").check()
    expect(visible_rows(page)).to_have_count(32)
    page.get_by_label("Not annotated").uncheck()
    page.get_by_label("Filter by name or title").fill("write_0")
    named = [t for t in tools if "write_0" in f"{t['name_shown']} {t['title_shown'] or ''}"]
    expect(visible_rows(page)).to_have_count(len(named))
    page.get_by_label("Filter by name or title").fill("")
    expect(visible_rows(page)).to_have_count(96)
    expect(generate(page)).to_have_text("Generate (0 tools: 0 allow, 0 approve)")
    press(page, "Select suggested")
    expect(generate(page)).to_have_text("Generate (64 tools: 64 allow, 0 approve)")
    ticked: list[str] = page.locator("#review-tools > li").evaluate_all(
        "(rows) => rows.filter((row) => row.querySelector('label.include input')?.checked)"
        ".map((row) => row.querySelector('b').textContent)"
    )
    suggested = {t["name_shown"] for t in tools if t["pinnable"] and t["suggested"] == "allow"}
    assert set(ticked) == suggested
    assert len(ticked) == 64
    assert not [t for t in tools if t["name_shown"] in ticked and not t["annotated"]]
    press(page, "Clear")
    expect(generate(page)).to_have_text("Generate (0 tools: 0 allow, 0 approve)")


def test_item_16_hostile_server_text_shows_as_text_under_trusted_types(
    rig: PortalRig, page: Page
) -> None:
    """Item 16 with ``--switch inject_definitions --switch inject_server_info --switch
    invalid_name``: "every string from the server (names, titles, descriptions, the server's
    name and instructions, findings, definitions) shows as text, exactly as the vault sent it:
    markup shows as its characters, nothing is bold, linked or laid out that the page didn't
    make, and a hidden or right-to-left character shows as the visible mark the vault gives it";
    "**Show definition** shows the whole definition ... with nothing cut, and every character
    outside ASCII as an escape"; no Trusted Types or Content Security Policy violation (the
    watch)."""
    set_up(page, rig)
    read = review_tools(page, rig, hostile())
    expect(page.locator("#review-info")).to_contain_text(read["server_info_shown"])
    expect(page.locator("#review-instructions")).to_have_text(
        f"Its instructions:\n{read['instructions_shown']}"
    )
    assert "[U+202E]" in read["instructions_shown"]
    rows = page.locator("#review-tools > li")
    names: list[str] = rows.evaluate_all(
        "(rows) => rows.map((row) => row.querySelector('b').textContent)"
    )
    assert names == [t["name_shown"] for t in read["tools"]]
    # Each title is the text after its name, a text node: no element is made of it.
    titles: list[list[Any]] = rows.evaluate_all(
        "(rows) => rows.map((row) => {"
        " const after = row.querySelector('b').nextSibling;"
        " return [after.nodeType, after.textContent]; })"
    )
    assert titles == [
        [3, f" {t['title_shown']}" if t["title_shown"] else ""] for t in read["tools"]
    ]
    said: list[str] = rows.locator("p.description").all_text_contents()
    assert said == [t["description_shown"] for t in read["tools"] if t["description_shown"]]
    findings: list[str] = rows.locator("ul > li").all_text_contents()
    assert findings == [
        f"{f['level']} at {f['pointer_shown']}: {f['message_shown']}"
        for t in read["tools"]
        for f in t["findings"]
    ]
    # The page's own help toggletip (its Learn more link) is markup, not the server's text.
    made: list[str] = page.locator("#review").evaluate(
        "(review) => Array.from(review.querySelectorAll('*'))"
        ".filter((element) => !element.closest('.z-help')).map((element) => element.tagName)"
    )
    assert set(made) <= OWN_TAGS, set(made) - OWN_TAGS
    [summarize] = [t for t in read["tools"] if t["name"] == "summarize"]
    assert "[U+200B]" in summarize["title_shown"]
    assert titles[read["tools"].index(summarize)][1] == f" {summarize['title_shown']}"
    assert not summarize["pinnable"]  # its error finding
    row = rows.filter(has=page.locator("b", has_text="summarize"))
    row.get_by_role("button", name="Show definition", exact=True).click()
    definition = row.locator("pre.definition")
    expect(definition).to_be_visible()
    whole = "".join(chunk for line in summarize["definition_lines"] for chunk in line)
    expect(definition).to_have_text(whole)
    shown = definition.text_content()
    assert shown is not None
    assert shown.isascii()
    assert "\\u200b" in shown
    assert definition.locator("span").count() == sum(
        len(line) for line in summarize["definition_lines"]
    )


# --- item 17: Copy is the exact fragment ---------------------------------------------------------


def test_item_17_copy_puts_exactly_the_shown_fragment_on_the_clipboard(
    boarding: Onboarding, page: Page, context: BrowserContext
) -> None:
    """Item 17: "On **MCP servers**, under **Add a server by URL**, enter
    ``https://mcp.notes.example:9444/mcp``, leave **This server is on my network** unticked and
    **Client ID** (under **More options**) empty, and choose **Discover**; the plan's **Register
    and make the YAML** (a passkey) makes fragment 1. Choose **Copy** and paste ... Pass: the
    pasted text is the shown text, line for line and character for character, the
    2,048-character URL whole on its line; the same after choosing the compose indent", the
    provider's authorization endpoint 2,048 characters long. Fragment 2's copy is item 18's
    test, after its review."""
    rig = boarding.rig
    context.grant_permissions(["clipboard-read", "clipboard-write"], origin=rig.origin)
    set_up(page, rig)
    yaml = register_by_url(page)
    endpoint = f"{boarding.endpoints}/authorize"
    assert len(endpoint) == LONGEST
    assert fragment_text(page) == yaml
    assert copied(page) == yaml
    assert f'authorize_url: "{endpoint}"' in [line.strip() for line in yaml.splitlines()]

    def fragment_route(answer: Response) -> bool:
        return answer.request.method == "POST" and answer.url.endswith("/fragment")

    with page.expect_response(fragment_route) as again:
        page.get_by_label("Indent").select_option("compose")
    compose: str = again.value.json()["diff"]["yaml"]
    assert compose != yaml
    shows(page, compose)
    assert copied(page) == compose
    assert f'authorize_url: "{endpoint}"' in [line.strip() for line in compose.splitlines()]
