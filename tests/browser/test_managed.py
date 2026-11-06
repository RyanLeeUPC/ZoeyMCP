"""Managed mode in a real browser: manual items 20-23 (saves, the Policy page's history and
rollback, a connector's pause and limits, onboarding and Give to clients) and 31-32 (**Hold in
the vault** and **Turn off vault approval**) (M8 design steps 27b and 27c, A.4, P.3; Z20, G-5).

The real vault and portal on loopback start managed (``tests/portal/rig.py``; the policy file
seeds revision 1). Items 31 and 32: notes' ``write`` an included ``approve`` tool, ``list``
allowed, the portal's queue as the approver and three clients given notes: ``desk`` attended,
``nightly`` out of band and ``batch`` neither. Its credential holds a refresh token, so notes' row
on the MCP servers page offers **Review again**, whose review the gateway's side answers on the
vault's loop (``tests/portal/test_review.py``'s way). The connector form runs on two toolkits
writing through a ``mail`` connector, one through ``post`` too. Items 20-22: notes reviewed from
the fake MCP server's own definitions (``--switch large --switch markup_echo``, then ``--drift
description``), each review made under the running head (``stacks.review_at_head``); the host's
imports written as the admin socket writes them (``tests/portal/test_policy_managed.py``'s
``host_import``); a second browser is a second context with its own copy of the passkey. Item 23
runs on the onboarding world (``stacks.onboarding``), managed. The page runs with the browser's own
WebAuthn stack over a virtual authenticator, its Content Security Policy and Trusted Types in
force, every page watched; each test's docstring names its item and the lines it checks, and
``docs/manual-checks.md`` keeps the lines left by hand. ``tests/portal/
test_vault_approval_managed.py`` and ``tests/portal/test_policy_managed.py`` hold the same rules
over the API.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from mcp.types import Tool
from playwright.sync_api import BrowserContext, Locator, Page, expect

from tests.fakes.mcp_server import Switch
from tests.portal.test_home import VIEW, reported
from tests.portal.test_home import server as status
from tests.portal.test_policy_managed import (
    LIST,
    MAIL,
    WRITE,
    entry,
    head,
    host_import,
    managed,
    report_of,
    revision,
)
from tests.portal.test_review import SERVER_URL, poller
from tests.portal.test_vault_approval_managed import mailing
from zoeymcp.common.policy.plan import (
    MOVE_TEXT,
    NO_RESTART,
    REPINNED_TEXT,
    VAULT_OFF_CONNECTOR_TEXT,
    VAULT_OFF_TEXT,
)
from zoeymcp.common.policy.schema import hash_token
from zoeymcp.gateway import pins
from zoeymcp.portal.refusals import CATALOGUE
from zoeymcp.vault.bindings import derive_binding
from zoeymcp.vault.managed import Written
from zoeymcp.vault.onboarding import GIVE_LABEL, SAVE_LABEL
from zoeymcp.vault.statusreport import Report

from .layout import assert_no_horizontal_overflow, line_count, width_share
from .portal import (
    close,
    confirm,
    confirm_dialog,
    dialog_refusal,
    held_review,
    open_portal,
    open_section,
    outcome,
    press,
    server_row,
    set_up,
    sign_in,
    summary,
    summary_value,
    tool_actions,
)
from .stacks import Onboarding, PortalRig, listed, onboarding, portal, review_at_head
from .watch import Watch

# A refused request's answer, which the browser itself reports on the console.
REFUSED_409 = r"status of 409"
NO_APPROVER = (
    "Set up an approver first (Telegram or the Approvals queue): a host step, operations.md §36.2"
)
# Item 31's plan, line for line: the tool, who is asked where (each client given notes, by
# name), and the route's credential sentence.
TURN_ON = [
    "notes.write: vault_approval on.",
    "  The vault will hold every call to write and ask you in the Approvals queue. The gateway "
    "will no longer ask in the agent's own client.",
    '  batch (neither): refused, as before ("nobody answers for this client").',
    "  desk (attended): asked on your approvers instead of in its client.",
    "  nightly (out of band): asked on your approvers, as before.",
    "  Route notes holds a credential: a compromised gateway can't call the server directly.",
]
OFF_PATH = "gateway.servers.notes.tools.vault_approval"
NEEDS_STEP = CATALOGUE["vault_approval_off_needs_its_own_step"].text.format(detail="notes.write")
# approvals.js's words once a hold is saved.
HELD_SAVED = "Saved: the vault holds those calls now and asks you on your approvers."


def policy(*, held: bool = False, approver: bool = True, write: bool = True) -> dict[str, Any]:
    """Notes managed, with ``list`` allowed and ``write`` approved (none with ``write`` false,
    held with ``held``), the three clients given notes and, with ``approver``, the portal's
    queue (without it no client may be out of band, so ``nightly`` is neither)."""
    found = managed(**entry([WRITE] if write else [], [LIST]))
    own: dict[str, dict[str, Any]] = {
        "desk": {"attended": True},
        "nightly": {"attended": False, "out_of_band": approver},
        "batch": {"attended": False},
    }
    found["gateway"]["clients"] = {
        name: {
            "token_sha256": hash_token(f"zgc1-{name}-token"),
            "approvals": approvals,
            "servers": ["notes"],
        }
        for name, approvals in own.items()
    }
    if approver:
        found["approvers"] = {"portal": {}}
    if held:
        found["gateway"]["servers"]["notes"]["tools"]["vault_approval"] = ["write"]
    return found


def running(tmp_path: Path, document: dict[str, Any]) -> Iterator[PortalRig]:
    with portal(tmp_path, policy=document) as rig:
        managed_ = rig.vault.managed
        secrets = rig.app.secrets
        assert managed_ is not None
        assert secrets is not None
        binding = derive_binding(managed_.policy, "notes-refresh")
        rig.call(lambda: secrets.store.put("notes-refresh", "r" * 24, binding))
        poller(rig)
        yield rig


@pytest.fixture
def rig(tmp_path: Path) -> Iterator[PortalRig]:
    yield from running(tmp_path, policy())


@pytest.fixture
def held(tmp_path: Path) -> Iterator[PortalRig]:
    """``write`` held by the vault."""
    yield from running(tmp_path, policy(held=True))


@pytest.fixture
def unapproved(tmp_path: Path) -> Iterator[PortalRig]:
    """No approver set."""
    yield from running(tmp_path, policy(approver=False))


@pytest.fixture
def unwritten(tmp_path: Path) -> Iterator[PortalRig]:
    """Notes without ``write`` yet."""
    yield from running(tmp_path, policy(write=False))


@pytest.fixture
def mail(tmp_path: Path) -> Iterator[PortalRig]:
    """Two toolkits writing through the ``mail`` connector, ``kit2`` through ``post`` too, none
    held (``test_vault_approval_managed.py``'s)."""
    yield from running(tmp_path, mailing())


def notes_row(page: Page) -> Locator:
    return server_row(page, "notes (remote)")


def notes_tools(page: Page) -> Locator:
    """Notes' per-tool buttons, under its card's Tool actions, opened."""
    return tool_actions(notes_row(page))


def held_tools(rig: PortalRig) -> dict[str, list[str]]:
    """Each server's tools the vault holds, where it holds any."""
    managed_ = rig.vault.managed
    assert managed_ is not None
    gateway = managed_.policy.gateway
    assert gateway is not None
    servers = gateway.servers.items()
    return {
        name: list(found.tools.vault_approval)
        for name, found in servers
        if found.tools.vault_approval
    }


def labelled(page: Page, label: str) -> list[str]:
    """The confirm dialog's values whose label is ``label``, in order."""
    return [value for name, value in summary(page) if name == label]


def review(page: Page, rig: PortalRig) -> Locator:
    """**Review again** on notes' row, and the review drawn by the review screen's first poll,
    held until the gateway's review is answered (``portal.held_review``): write's row."""
    open_section(page, "MCP servers")
    again = notes_row(page).get_by_role("button", name="Review again", exact=True)
    held_review(page, rig, report_of([LIST, WRITE], [WRITE], [LIST]), again.click)
    tool = page.locator("#review-tools > li").filter(has_text="Writes a note.")
    expect(tool).to_have_count(1)
    return tool


def hold_box(tool: Locator) -> Locator:
    return tool.get_by_label("Hold in the vault (approve only)")


# --- item 31: turning it on ----------------------------------------------------------------------


def test_item_31_hold_in_the_vault_shows_the_turn_on_plan_before_the_passkey(
    rig: PortalRig, page: Page
) -> None:
    """Item 31's first lines: "the server page's **Hold in the vault** on ``echo`` [here
    ``write``] shows, before any passkey prompt, the plan's lines ('fake.echo: vault_approval
    on.', one line for ``desk``, ``nightly`` and ``batch`` each, then the route's credential
    sentence); confirmed, ``echo`` is held"."""
    passkeys = set_up(page, rig)
    open_section(page, "MCP servers")
    hold = notes_tools(page).get_by_role("button", name="Hold in the vault: write", exact=True)
    expect(hold).to_be_enabled()
    hold.click()
    assert labelled(page, "notes.write") == TURN_ON
    assert passkeys.asserted() == 1  # sign-in's only: no prompt before the plan
    assert revision(rig) == 1
    confirm(page)
    expect(confirm_dialog(page)).to_be_hidden()
    off = notes_tools(page).get_by_role("button", name="Turn off vault approval: write")
    expect(off).to_be_visible()
    # The rows drawn again keep the save's words (the page shown again doesn't clear them).
    assert outcome(page, "#servers").text_content() == HELD_SAVED
    assert passkeys.asserted() == 2
    assert head(rig)["tools"]["vault_approval"] == ["write"]
    assert revision(rig) == 2


def test_item_31_the_review_screens_box_shows_the_same_plan(rig: PortalRig, page: Page) -> None:
    """Item 31: "The review screen's box of the same name shows the same lines in its save's
    plan": the box ticked on ``write`` and **Save**, the plan's lines before the passkey;
    confirmed, ``write`` is held."""
    passkeys = set_up(page, rig)
    tool = review(page, rig)
    box = hold_box(tool)
    expect(box).not_to_be_checked()
    expect(box).to_be_enabled()
    box.check()
    press(page, "Save")
    assert labelled(page, "notes.write") == TURN_ON
    assert passkeys.asserted() == 1
    confirm(page)
    expect(confirm_dialog(page)).to_be_hidden()
    expect(page.get_by_text("Saved as revision 2.")).to_be_visible()
    assert head(rig)["tools"]["vault_approval"] == ["write"]


def test_item_31_with_no_approver_both_controls_are_disabled(
    unapproved: PortalRig, page: Page
) -> None:
    """Item 31's last lines: "With ``approvers`` removed ..., both controls are disabled, with
    'Set up an approver first (Telegram or the Approvals queue): a host step, operations.md
    §36.2'"; nothing prompts and nothing is written."""
    rig = unapproved
    passkeys = set_up(page, rig)
    open_section(page, "MCP servers")
    row = notes_row(page)
    hold = tool_actions(row).get_by_role("button", name="Hold in the vault: write", exact=True)
    expect(hold).to_be_disabled()
    expect(row.get_by_text(NO_APPROVER, exact=True)).to_be_visible()
    tool = review(page, rig)
    expect(hold_box(tool)).to_be_disabled()
    expect(page.locator("#review-drift").get_by_text(NO_APPROVER, exact=True)).to_be_visible()
    assert passkeys.asserted() == 1
    assert revision(rig) == 1


# --- item 32: turning it off, and what can't --------------------------------------------------


def test_item_32_turn_off_shows_its_sentence_and_changes_one_tool(
    held: PortalRig, page: Page
) -> None:
    """Item 32's first lines: "**Turn off vault approval** prepares ``tool.vault_approval_off``,
    and the dialog shows 'echo [write]: vault_approval off. The gateway will ask instead of the
    vault; a compromised gateway could then skip the approval. Calls waiting now are
    withdrawn.' whole; one passkey changes that one tool, and the log has
    ``tool_vault_approval_off``"."""
    rig = held
    passkeys = set_up(page, rig)
    open_section(page, "MCP servers")
    notes_tools(page).get_by_role("button", name="Turn off vault approval: write").click()
    assert labelled(page, OFF_PATH) == [VAULT_OFF_TEXT.format(name="write")]
    assert passkeys.asserted() == 1
    confirm(page)
    expect(confirm_dialog(page)).to_be_hidden()
    hold = notes_tools(page).get_by_role("button", name="Hold in the vault: write", exact=True)
    expect(hold).to_be_enabled()
    assert passkeys.asserted() == 2
    assert head(rig)["tools"].get("vault_approval") in (None, [])
    assert head(rig)["tools"]["approve"] == ["write"]  # the one change: approve stays
    assert revision(rig) == 2
    [line] = rig.lines("tool_vault_approval_off")
    assert (line["server"], line["name"], line["revision"]) == ("notes", "write", 2)


def test_item_32_a_review_save_that_drops_the_hold_is_refused_before_the_passkey(
    held: PortalRig, page: Page, watch: Watch
) -> None:
    """Item 32: "a review save that unticks the box, and one that drops ``echo`` [``write``]
    from ``include``, are refused ``vault_approval_off_needs_its_own_step`` before any passkey
    prompt"; nothing is written."""
    rig = held
    passkeys = set_up(page, rig)
    tool = review(page, rig)
    box = hold_box(tool)
    expect(box).to_be_checked()
    watch.allow(REFUSED_409, on=rig.origin)
    error = outcome(page, "#review .z-actionbar")
    box.uncheck()
    press(page, "Save")
    expect(error).to_have_text(NEEDS_STEP)
    expect(confirm_dialog(page)).to_be_hidden()
    box.check()
    tool.get_by_label("Include").uncheck()
    press(page, "Save")
    expect(error).to_have_text(NEEDS_STEP)
    expect(confirm_dialog(page)).to_be_hidden()
    assert passkeys.asserted() == 1
    assert revision(rig) == 1
    assert head(rig)["tools"]["vault_approval"] == ["write"]


def test_item_32_a_rollback_that_drops_the_hold_is_refused_before_the_passkey(
    unwritten: PortalRig, page: Page, watch: Watch
) -> None:
    """Item 32's last line: "a rollback to a revision before ``echo`` [``write``] was held is
    refused ``rollback_drops_vault_approval``" before any passkey prompt; nothing is written.
    The history is the host's import adding ``write`` (2), then **Hold in the vault** (3)."""
    rig = unwritten

    def add_write(data: dict[str, Any]) -> None:
        notes = data["gateway"]["servers"]["notes"]
        notes["tools"]["include"].append("write")
        notes["tools"]["approve"] = ["write"]
        notes["review"]["write"] = entry([WRITE])["review"]["write"]

    assert host_import(rig, add_write) == 2
    passkeys = set_up(page, rig)
    open_section(page, "MCP servers")
    notes_tools(page).get_by_role("button", name="Hold in the vault: write", exact=True).click()
    confirm(page)
    off = notes_tools(page).get_by_role("button", name="Turn off vault approval: write")
    expect(off).to_be_visible()
    assert revision(rig) == 3
    open_section(page, "Policy")
    watch.allow(REFUSED_409, on=rig.origin)
    for target in (2, 1):
        page.get_by_role("button", name=f"Roll back to revision {target}", exact=True).click()
        said = CATALOGUE["rollback_drops_vault_approval"].text.format(
            detail=f"revision {target} would stop the vault holding notes.write"
        )
        expect(outcome(page, "section:has(> #policy-history)")).to_have_text(said)
        expect(confirm_dialog(page)).to_be_hidden()
    assert passkeys.asserted() == 2  # sign-in and the hold's
    assert revision(rig) == 3


def test_item_32_a_connectors_writers_turn_off_in_one_step_up(mail: PortalRig, page: Page) -> None:
    """Item 32's "(a connector's writers in one step-up)" (A.4, T-8): **Hold in the vault** on
    ``kit2``'s ``mail`` connector holds every writer of it and of ``post`` (the closed set) with
    one passkey; **Turn off vault approval** on ``post`` shows one sentence per tool and the
    connectors it covers before the passkey, and one passkey turns all three off."""
    rig = mail
    passkeys = set_up(page, rig)
    open_section(page, "MCP servers")
    kit2 = server_row(page, "kit2 (toolkit)")
    kit2.get_by_role("button", name="Hold in the vault: connector mail", exact=True).click()
    expect(confirm_dialog(page)).to_be_visible()
    assert passkeys.asserted() == 1
    confirm(page)
    expect(confirm_dialog(page)).to_be_hidden()
    assert held_tools(rig) == {"kit": ["send"], "kit2": ["post", "reply"]}
    assert passkeys.asserted() == 2
    off = kit2.get_by_role("button", name="Turn off vault approval: connector post", exact=True)
    off.click()
    covers = VAULT_OFF_CONNECTOR_TEXT.format(servers="kit, kit2")
    [(label, said), *rows] = summary(page)  # the whole plan: nothing else is changed
    assert label == "Revision"
    assert said.startswith("3, from 2 (by you, ")
    assert rows == [
        ("gateway.servers.kit.tools.vault_approval", VAULT_OFF_TEXT.format(name="send")),
        ("gateway.servers.kit2.tools.vault_approval", VAULT_OFF_TEXT.format(name="post")),
        ("gateway.servers.kit2.tools.vault_approval", VAULT_OFF_TEXT.format(name="reply")),
        ("connector mail", covers),
        ("connector post", covers),
        NO_RESTART,
    ]
    assert passkeys.asserted() == 2
    confirm(page)
    expect(confirm_dialog(page)).to_be_hidden()
    assert passkeys.asserted() == 3
    assert held_tools(rig) == {}
    assert revision(rig) == 3
    assert len(rig.lines("tool_vault_approval_off")) == 3


# --- items 20-23 (step 27c) ----------------------------------------------------------------------

INCLUDED = {"echo": "allow", "add": "approve", "slow": "approve", "read_01": "approve"}
INCLUDED_20 = {**INCLUDED, "read_02": "approve"}
OLD = listed(Switch.LARGE, Switch.MARKUP_ECHO)
DRIFTED = listed(Switch.LARGE, Switch.MARKUP_ECHO, drift="description")
MANAGED_WORDS = "Each save writes its change to the policy: it asks for your passkey"
# A refused request's answer, which the browser itself reports on the console.
REFUSED_400 = r"status of 400"
REFUSED_403 = r"status of 403"


def reviewed_entry(chosen: dict[str, str], tools: list[Tool] = OLD) -> dict[str, Any]:
    """Notes' entry with ``chosen`` included (name -> allow or approve), each pinned at its
    definition in ``tools``."""
    pinned = {t.name: pins.project_and_pin(t).pin for t in tools}
    return {
        "era": "modern",
        "tools": {
            "include": list(chosen),
            "allow": [name for name, kind in chosen.items() if kind == "allow"],
            "approve": [name for name, kind in chosen.items() if kind == "approve"],
        },
        "review": {name: pinned[name] for name in chosen},
    }


def at_head(rig: PortalRig, tools: list[Tool]) -> Callable[[], dict[str, Any]]:
    """The gateway's review of ``tools``, made when it answers, under the head then."""
    return lambda: review_at_head(rig, tools, [*OLD, *DRIFTED])


@pytest.fixture
def fresh(tmp_path: Path) -> Iterator[PortalRig]:
    """Item 20's start: managed, notes in the seed and nothing of it included yet."""
    yield from running(tmp_path, managed())


@pytest.fixture
def saved(tmp_path: Path) -> Iterator[PortalRig]:
    """Item 20 after its first save: item 19's tools and ``read_02`` included at their pins."""
    yield from running(tmp_path, managed(**reviewed_entry(INCLUDED_20)))


@pytest.fixture
def history_rig(tmp_path: Path) -> Iterator[PortalRig]:
    """Item 21's vault: ``echo`` allow and ``add`` and ``slow`` approve, a client ``agent1``;
    then the host's imports: ``ci-runner`` added (with a reason holding markup) and removed, and
    ``add`` and ``slow`` moved to allow."""
    document = managed(**reviewed_entry(INCLUDED))
    document["gateway"]["clients"] = {
        "agent1": {"token_sha256": hash_token("zgc1-agent1-token"), "servers": ["notes"]}
    }
    for rig in running(tmp_path, document):

        def add_runner(data: dict[str, Any]) -> None:
            data["gateway"]["clients"]["ci-runner"] = {
                "token_sha256": hash_token("zgc1-ci-runner-token"),
                "servers": [],
            }

        def remove_runner(data: dict[str, Any]) -> None:
            del data["gateway"]["clients"]["ci-runner"]

        def allow_both(data: dict[str, Any]) -> None:
            tools = data["gateway"]["servers"]["notes"]["tools"]
            tools["allow"] = ["echo", "add", "slow"]
            tools["approve"] = ["read_01"]

        assert host_import(rig, add_runner, REASON) == 2
        assert host_import(rig, remove_runner) == 3
        assert host_import(rig, allow_both) == 4
        yield rig


@pytest.fixture
def connector_rig(tmp_path: Path) -> Iterator[PortalRig]:
    """Item 22's vault: item 21's, given an SMTP connector ``mail`` by a host import."""
    for rig in running(tmp_path, managed(**reviewed_entry(INCLUDED))):

        def add_mail(data: dict[str, Any]) -> None:
            data["connectors"] = {"mail": dict(MAIL)}

        assert host_import(rig, add_mail) == 2
        yield rig


REASON = "add ci-runner <b>x</b>"


def review_notes(page: Page, rig: PortalRig, tools: list[Tool]) -> dict[str, Any]:
    """**Review tools** (or **Review again**) on notes' row, the review of ``tools``."""
    open_section(page, "MCP servers")
    named = re.compile("^Review (again|tools)$")
    start = notes_row(page).get_by_role("button", name=named)
    return held_review(page, rig, at_head(rig, tools), start.click)


def tool_row(page: Page, read: dict[str, Any], name: str) -> Locator:
    index = next(i for i, t in enumerate(read["tools"]) if t["name"] == name)
    return page.locator("#review-tools > li").nth(index)


def choose(page: Page, read: dict[str, Any], chosen: dict[str, str]) -> None:
    """Each tool of ``chosen`` included, at its classification."""
    for name, kind in chosen.items():
        row = tool_row(page, read, name)
        row.get_by_label("Include").check()
        row.locator("select").select_option(kind)


def first_row(page: Page) -> tuple[str, str]:
    return summary(page)[0]


def shown_words(page: Page) -> str:
    """Every word the page shows now (hidden blocks left out), in lower case."""
    return page.locator("main").inner_text().lower()


def laid_out(page: Page, label: str) -> None:
    """The confirm dialog's value for ``label`` laid out as item 20 once failed to (M6's label
    column, as wide as a label naming a pin, squeezed every value to a character a line and lost
    its JSON indentation): the value column more than half the dialog, each of its lines
    wrapped onto few, its spaces and line ends kept, nothing scrolling sideways."""
    value = summary_value(page, label)
    text = value.text_content()
    assert text is not None
    assert width_share(value, page.locator("#confirm-summary")) > 0.5
    assert line_count(value) <= text.count("\n") + 1 + len(text) // 20
    assert value.evaluate("(element) => getComputedStyle(element).whiteSpace") == "pre-wrap"
    assert value.inner_text() == text  # as laid out: no space or line end collapsed
    assert_no_horizontal_overflow(page, "#confirm-summary")


# --- item 20: managed saves ----------------------------------------------------------------------


def test_item_20_a_managed_review_is_saved_with_a_passkey_and_a_repin_says_so(
    fresh: PortalRig, page: Page
) -> None:
    """Item 20: "Review the server and include ``echo`` as allow and ``add``, ``slow``,
    ``read_01`` and ``read_02`` as approve, then **Save**: the dialog's first row reads
    'Revision 2, from 1 (by the seed, ...: 1 is the head)', and a passkey writes it"; "the
    page's texts say the policy is managed and each save asks for a passkey, and no text says to
    commit, reload or generate; **Generate** is gone and **Save** is there"; then, the fake
    restarted with ``--drift description``, "**Review again** and **Accept the new definition**
    on ``echo``, **Save**: the dialog's row shows both pins and 're-pinned: you read both
    definitions', and 'No restart needed'; confirmed, the vault's log line
    ``step_up_confirmed`` names the kind ``tool.repin``, the answer says the gateway takes the
    new view within seconds, and the server's row is ``reviewed`` again"; the re-pin's row laid
    out whole (``laid_out``)."""
    rig = fresh
    passkeys = set_up(page, rig)
    read = review_notes(page, rig, OLD)
    expect(page.get_by_text(MANAGED_WORDS, exact=False)).to_be_visible()
    expect(page.locator("#review-generate")).to_be_hidden()
    expect(page.locator("#review-save")).to_be_visible()
    words = shown_words(page)
    assert [word for word in ("commit", "reload", "generate") if word in words] == []
    choose(page, read, INCLUDED_20)
    press(page, "Save")
    label, said = first_row(page)
    assert (label, said.startswith("2, from 1 (by the seed, ")) == ("Revision", True)
    assert said.endswith(": 1 is the head)")
    assert passkeys.asserted() == 1
    # Confirmed, the screen reviews the server again by itself: the fake has drifted since.
    read = held_review(page, rig, at_head(rig, DRIFTED), lambda: confirm(page))
    assert revision(rig) == 2
    echo = tool_row(page, read, "echo")
    expect(echo.locator(".badge").first).to_have_text("drift")
    echo.get_by_label("Accept the new definition").check()
    press(page, "Save")
    entry = next(t for t in read["tools"] if t["name"] == "echo")
    repin = REPINNED_TEXT.format(old=entry["pinned"], new=entry["pin"])
    assert ("gateway.servers.notes.review.echo", repin) in summary(page)
    laid_out(page, "gateway.servers.notes.review.echo")
    assert NO_RESTART in summary(page)
    held_review(page, rig, at_head(rig, DRIFTED), lambda: confirm(page))
    assert rig.logged("step_up_confirmed", lambda line: line["action"] == "tool.repin")
    expect(outcome(page, "#review .z-actionbar")).to_contain_text(
        "The gateway takes the new view within seconds"
    )
    assert head(rig)["review"]["echo"] == entry["pin"]
    open_section(page, "MCP servers")
    expect(notes_row(page)).to_contain_text("notes (remote)Reviewed")


def test_item_20_moves_to_allow_come_first_and_close_writes_nothing(
    saved: PortalRig, page: Page
) -> None:
    """Item 20: "**Review again**, change ``add`` and ``slow`` from approve to allow, **Save**:
    the dialog lists the two moves first, each with 'approve -> allow. Calls to ... will run with
    no prompt' and every chunk of its definition below it (the first naming the pin), the markup
    in ``echo``'s shown as text if it is moved too; **Close** (a cancel) writes nothing ...;
    **Save** again and confirm: both are allow"; the dialog laid out whole, the label naming
    the pin squeezing no value (``laid_out``)."""
    rig = saved
    passkeys = set_up(page, rig)
    read = review_notes(page, rig, OLD)
    for name in ("add", "slow"):
        tool_row(page, read, name).locator("select").select_option("allow")
    press(page, "Save")
    rows = summary(page)
    assert rows[0][0] == "Revision"
    labels = [label for label, _ in rows]
    moves = [i for i, label in enumerate(labels) if label.startswith("notes.")]
    assert [rows[i] for i in moves] == [
        (f"notes.{name}", MOVE_TEXT.format(name=name)) for name in ("add", "slow")
    ]
    assert moves[0] == 1  # the moves come first
    for at, name in zip(moves, ("add", "slow"), strict=True):
        found = next(t for t in OLD if t.name == name)
        chunks = [value for _, value in rows[at + 1 :]]
        # The definition below the move, every chunk a row, the first naming the pin.
        assert rows[at + 1][0] == f"{name}, as pinned ({pins.project_and_pin(found).pin})"
        assert "".join(chunks).startswith("{")
    found = next(t for t in OLD if t.name == "add")
    laid_out(page, f"add, as pinned ({pins.project_and_pin(found).pin})")
    close(page)
    assert revision(rig) == 1
    assert passkeys.asserted() == 1
    press(page, "Save")
    expect(confirm_dialog(page)).to_be_visible()
    held_review(page, rig, at_head(rig, OLD), lambda: confirm(page))
    assert sorted(head(rig)["tools"]["allow"]) == ["add", "echo", "slow"]
    assert sorted(line["name"] for line in rig.lines("tool_allowed")) == ["add", "slow"]


def test_item_20_allow_without_asking_and_select_suggested_after_a_drop(
    saved: PortalRig, page: Page
) -> None:
    """Item 20: "on the MCP servers page, **Allow read_01 without asking**: the dialog shows
    read_01's move and its definition as pinned; confirmed, it is allow (``step_up_confirmed``
    names ``tool.allow``)"; and "**Review again**, untick ``read_02`` (approve, read-only),
    **Save** and confirm; then **Review again**, **Clear** and **Select suggested**: ``read_02``,
    dropped and once approve, comes back ticked at approve, every read-only tool the policy
    includes at its classification and the other read-only tools at allow (a tool the server
    doesn't mark read-only, such as ``add``, stays unticked, so the save drops it), and **Save**
    shows no 'approve -> allow' or 'was approve in an earlier revision' row"."""
    rig = saved
    set_up(page, rig)
    review_notes(page, rig, OLD)  # the vault holds a review showing read_01's definition
    open_section(page, "MCP servers")
    notes_tools(page).get_by_role("button", name="Allow read_01 without asking").click()
    rows = summary(page)
    assert rows[1] == ("notes.read_01", MOVE_TEXT.format(name="read_01"))
    read_01 = next(t for t in OLD if t.name == "read_01")
    assert rows[2][0] == f"read_01, as pinned ({pins.project_and_pin(read_01).pin})"
    confirm(page)
    expect(confirm_dialog(page)).to_be_hidden()
    assert rig.logged("step_up_confirmed", lambda line: line["action"] == "tool.allow")
    assert "read_01" in head(rig)["tools"]["allow"]
    read = review_notes(page, rig, OLD)
    tool_row(page, read, "read_02").get_by_label("Include").uncheck()
    press(page, "Save")
    read = held_review(page, rig, at_head(rig, OLD), lambda: confirm(page))
    assert "read_02" not in head(rig)["tools"]["include"]
    press(page, "Clear")
    press(page, "Select suggested")
    read_02 = tool_row(page, read, "read_02")
    expect(read_02.get_by_label("Include")).to_be_checked()
    expect(read_02.locator("select")).to_have_value("approve")
    expect(tool_row(page, read, "read_01").locator("select")).to_have_value("allow")
    expect(tool_row(page, read, "read_03").locator("select")).to_have_value("allow")
    expect(tool_row(page, read, "add").get_by_label("Include")).not_to_be_checked()
    press(page, "Save")
    values = [value for _, value in summary(page)]
    assert not [v for v in values if "approve -> allow" in v or "was approve in an earlier" in v]
    close(page)


def test_item_20_allow_without_asking_on_a_vault_holding_no_review_reviews_first(
    saved: PortalRig, page: Page
) -> None:
    """Item 20: "restart the vault (it holds reviews in memory only), sign in, and on the MCP
    servers page **Allow read_02 without asking**: the page reviews the server first, then opens
    the same dialog for read_02; **Close** writes nothing". A vault just started holds no review,
    as a restarted one does."""
    rig = saved
    passkeys = set_up(page, rig)
    open_section(page, "MCP servers")
    allow = notes_tools(page).get_by_role("button", name="Allow read_02 without asking")
    held_review(page, rig, at_head(rig, OLD), allow.click)  # the review first
    rows = summary(page)
    assert rows[1] == ("notes.read_02", MOVE_TEXT.format(name="read_02"))
    read_02 = next(t for t in OLD if t.name == "read_02")
    assert rows[2][0] == f"read_02, as pinned ({pins.project_and_pin(read_02).pin})"
    close(page)
    assert (revision(rig), passkeys.asserted()) == (1, 1)
    assert "read_02" in head(rig)["tools"]["approve"]


def test_item_20_a_second_browser_saving_first_changes_this_ones_confirm(
    saved: PortalRig, page: Page, other_context: BrowserContext, watch: Watch
) -> None:
    """Item 20's last line: "a second browser signed in on the same origin saves first: this
    browser's confirm shows 'Something changed since you prepared this (shown below)' and,
    under 'What the vault finds now', 'The policy moved to revision N ... press Save again' with
    the plan on revision N, and nothing is written"."""
    rig = saved
    passkeys = set_up(page, rig)
    read = review_notes(page, rig, OLD)
    tool_row(page, read, "add").locator("select").select_option("allow")
    press(page, "Save")
    expect(confirm_dialog(page)).to_be_visible()
    second = other_context.new_page()
    open_portal(second, rig.origin)
    passkeys.copy_to(second)
    sign_in(second, rig.origin)
    other = review_notes(second, rig, OLD)
    tool_row(second, other, "slow").locator("select").select_option("allow")
    press(second, "Save")
    held_review(second, rig, at_head(rig, OLD), lambda: confirm(second))
    assert revision(rig) == 2
    watch.allow(r"status of 409", on=rig.origin)
    confirm(page)
    expect(dialog_refusal(page)).to_have_text(CATALOGUE["changed"].text)
    expect(page.get_by_text("What the vault finds now:")).to_be_visible()
    now = page.locator("#confirm-now dd").first
    expect(now).to_contain_text("The policy moved to revision 2")
    expect(now).to_contain_text("press Save again")
    assert revision(rig) == 2
    assert "add" not in head(rig)["tools"]["allow"]


# --- item 21: history, a diff and a rollback -----------------------------------------------------


def history_rows(page: Page) -> Locator:
    return page.locator("#policy-history > li")


def test_item_21_the_policy_page_names_the_head_and_lists_the_history(
    history_rig: PortalRig, page: Page
) -> None:
    """Item 21: "the page names the head's revision and which revision the gateway runs, and
    'Export the policy' with its command, ``docker compose exec`` and ``-T``; no text says to
    commit, reload or generate; every revision but the head has **Roll back to revision N**";
    "**History** lists every revision newest first, each with when, by whom ... and what made it,
    the import's reason with its markup shown as text; **Show the changes** on the revision that
    moved ``add`` and ``slow`` lists those rows, each 'wider', and on the seed lists the whole
    policy from an empty one, the client's token hash only as ``(set)``"."""
    rig = history_rig
    set_up(page, rig)
    open_section(page, "Policy")
    expect(page.locator("#policy-head")).to_have_text("The head is revision 4.")
    expect(page.locator("#policy-gateway")).to_contain_text("The gateway hasn't reported")
    # The gateway reports the head's view: the page names the revision it runs.
    managed_ = rig.app.managed
    assert managed_ is not None
    head_ = managed_.store.head
    assert head_ is not None
    view = managed_.view_digests[4]
    claimed = {head_.deployment: 4}
    rig.call(lambda: rig.vault.app.keep_status(Report(view, 1, {}, witness=claimed)))
    open_section(page, "Home")
    open_section(page, "Policy")
    expect(page.locator("#policy-gateway")).to_have_text(
        "The gateway runs the head. Its view is revision 4's."
    )
    export = page.locator("#policy-export")
    expect(export).to_contain_text("Export the policy: zoeymcp policy export")
    expect(export).to_contain_text("docker compose exec")
    expect(export).to_contain_text("-T")
    words = page.locator("#policy").inner_text().lower()
    assert [word for word in ("commit", "reload", "generate") if word in words] == []
    rows = history_rows(page)
    expect(rows).to_have_count(4)
    said = rows.all_text_contents()
    assert [text.split(",")[0] for text in said] == [f"Revision {n}" for n in (4, 3, 2, 1)]
    assert "by the host (socket): an import" in said[2]
    assert said[2].split("Show the changes")[0].rstrip().endswith(f"Reason: {REASON}")
    assert "the seed" in said[3]
    for number in (3, 2, 1):
        expect(
            rows.nth(4 - number).get_by_role("button", name=f"Roll back to revision {number}")
        ).to_be_visible()
    expect(rows.nth(0).get_by_role("button", name="Roll back to revision 4")).to_have_count(0)
    rows.nth(0).get_by_role("button", name="Show the changes").click()
    expect(page.locator("#policy-diff-title")).to_contain_text("Revision 4, from revision 3: ")
    changes = page.locator("#policy-diff-rows > li").all_text_contents()
    assert [text for text in changes if "tools.allow" in text] == [
        f"gateway.servers.notes.tools.allow: added, wider: {name}" for name in ("add", "slow")
    ]
    rows.nth(3).get_by_role("button", name="Show the changes").click()
    expect(page.locator("#policy-diff-title")).to_contain_text("Revision 1, from an empty policy: ")
    seeded = page.locator("#policy-diff-rows > li").all_text_contents()
    [gateway] = [text for text in seeded if text.startswith("gateway: ")]
    assert gateway.startswith("gateway: changed, wider: null -> {")  # the whole of it, added
    assert '"agent1":{"token":null,"token_sha256":"(set)",' in gateway
    assert hash_token("zgc1-agent1-token") not in page.content()


def test_item_21_a_rollback_is_planned_closed_then_confirmed(
    history_rig: PortalRig, page: Page
) -> None:
    """Item 21: "**Roll back to revision N** on the revision before the moves to allow: the
    dialog's first row reads 'Revision M, from M-1: the content of revision N (by ..., ...: M-1 is
    the head)', the moves undone are listed and no row ends '(wider)'; **Close** writes nothing
    (the history is unchanged); again, and confirmed: ``add`` and ``slow`` are approve, the
    history's newest revision is the rollback with its target, and the vault's log has
    ``step_up_confirmed`` with ``policy.rollback`` and ``policy_rolled_back`` with ``target``"."""
    rig = history_rig
    passkeys = set_up(page, rig)
    open_section(page, "Policy")
    page.get_by_role("button", name="Roll back to revision 3", exact=True).click()
    rows = summary(page)
    assert rows[0][0] == "Revision"
    assert rows[0][1].startswith(
        "5, from 4: the content of revision 3 (by the host (socket), "
    )  # who wrote the head
    assert rows[0][1].endswith(": 4 is the head)")
    assert not [value for _, value in rows if value.endswith("(wider)")]
    close(page)
    assert revision(rig) == 4
    assert passkeys.asserted() == 1
    page.get_by_role("button", name="Roll back to revision 3", exact=True).click()
    confirm(page)
    expect(page.locator("#policy-head")).to_have_text("The head is revision 5.")
    expect(history_rows(page).first).to_contain_text("a rollback, the content of revision 3")
    assert sorted(head(rig)["tools"]["approve"]) == ["add", "read_01", "slow"]
    assert rig.logged("step_up_confirmed", lambda line: line["action"] == "policy.rollback")
    [line] = rig.lines("policy_rolled_back")
    assert line["target"] == 3


def test_item_21_a_rollback_that_revives_or_widens_is_refused_before_the_passkey(
    history_rig: PortalRig, page: Page, watch: Watch
) -> None:
    """Item 21: "**Roll back to revision N** on the revision that added ``ci-runner``: refused
    before any passkey prompt, 'Rolling back to revision N brings back client ci-runner, removed
    in revision M: only the host can, with zoeymcp policy rollback and --allow-revive.', and
    nothing is written"; and a rollback "now wider than the head: refused before any passkey
    prompt, 'The portal can't widen ... through a rollback', with the host's export and import,
    and nothing is written". The head here is the rollback to revision 3, so revision 4 (``add``
    and ``slow`` at allow) is wider."""
    rig = history_rig
    passkeys = set_up(page, rig)
    open_section(page, "Policy")
    page.get_by_role("button", name="Roll back to revision 3", exact=True).click()
    confirm(page)
    expect(page.locator("#policy-head")).to_have_text("The head is revision 5.")
    asserted = passkeys.asserted()
    watch.allow(r"status of 40[39]", on=rig.origin)
    page.get_by_role("button", name="Roll back to revision 2", exact=True).click()
    revives = CATALOGUE["rollback_revives"].text.format(
        detail="revision 2 brings back client ci-runner, removed in revision 3"
    )
    expect(outcome(page, "section:has(> #policy-history)")).to_have_text(revives)
    expect(confirm_dialog(page)).to_be_hidden()
    page.get_by_role("button", name="Roll back to revision 4", exact=True).click()
    expect(outcome(page, "section:has(> #policy-history)")).to_contain_text(
        "The portal can't widen "
    )
    expect(outcome(page, "section:has(> #policy-history)")).to_contain_text(
        " through a rollback: export, edit and import"
    )
    expect(confirm_dialog(page)).to_be_hidden()
    assert passkeys.asserted() == asserted
    assert revision(rig) == 5


# --- item 22: a connector's pause and limits -----------------------------------------------------


def connector_row(page: Page) -> Locator:
    return page.locator("#policy-connectors > li").filter(has_text="mail: ")


def test_item_22_pause_resume_and_limits_each_write_a_revision(
    connector_rig: PortalRig, page: Page, watch: Watch
) -> None:
    """Item 22: "**Connectors** lists ``mail: sending.`` with its three limits in fields (20
    sends a day, 150 subject characters, 2200 body characters), and nothing of its host, sender
    or recipients"; "**Pause**: the dialog's rows read 'Revision N, from N-1 (by you, ...: N-1 is
    the head)', ``connectors.mail.paused`` 'changed' and 'No restart needed'; confirmed, the row
    reads paused, the history's newest revision is 'a connector's limits', and the vault's log
    has ``step_up_confirmed`` with ``connector.limits`` and ``policy_saved`` with ``write_kind:
    connector.limits``"; "**Resume**: the dialog's row reads 'sends can go out again'; **Close**
    writes nothing ...; **Resume** again and confirm: sending"; "'Sends a day' set to 50, **Save
    limits**: the dialog's row reads '20 -> 50: raised'; confirmed, the field shows 50; with 0 in
    a field, **Save limits** is refused before any passkey prompt, and with the same values
    again, 'Nothing would change.'"."""
    rig = connector_rig
    passkeys = set_up(page, rig)
    open_section(page, "Policy")
    row = connector_row(page)
    expect(row).to_contain_text("mail: sending.")
    fields = row.locator("input[type=number]")
    assert [fields.nth(i).input_value() for i in range(3)] == ["20", "150", "2200"]
    for hidden in ("smtp.mail.example", "mail-account-user", "zoeymcp@mail.example"):
        assert hidden not in page.locator("#policy-connectors").inner_text()  # MAIL's
    assert "ops@mail.example" not in page.locator("#policy-connectors").inner_text()
    row.get_by_role("button", name="Pause", exact=True).click()
    rows = summary(page)
    assert rows[0][1].startswith("3, from 2 (by the host (socket), ")  # who wrote the head
    assert rows[1:] == [("connectors.mail.paused", "changed"), NO_RESTART]
    confirm(page)
    expect(connector_row(page)).to_contain_text("mail: paused: every send is refused.")
    expect(history_rows(page).first).to_contain_text("a connector's limits")
    assert rig.logged("step_up_confirmed", lambda line: line["action"] == "connector.limits")
    assert [line["write_kind"] for line in rig.lines("policy_saved")][-1] == "connector.limits"
    connector_row(page).get_by_role("button", name="Resume", exact=True).click()
    assert summary(page)[1] == ("connectors.mail.paused", "sends can go out again")
    close(page)
    expect(connector_row(page)).to_contain_text("paused")
    assert revision(rig) == 3
    connector_row(page).get_by_role("button", name="Resume", exact=True).click()
    confirm(page)
    expect(connector_row(page)).to_contain_text("mail: sending.")
    connector_row(page).locator("input[type=number]").first.fill("50")
    connector_row(page).get_by_role("button", name="Save limits", exact=True).click()
    assert summary(page)[1] == ("connectors.mail.max_per_day", "20 -> 50: raised")
    confirm(page)
    expect(page.locator("#policy-saved")).to_contain_text("Revision 5 written.")  # drawn again
    expect(connector_row(page).locator("input[type=number]").first).to_have_value("50")
    asserted, written = passkeys.asserted(), revision(rig)
    watch.allow(REFUSED_400, on=rig.origin)
    connector_row(page).locator("input[type=number]").first.fill("0")
    connector_row(page).get_by_role("button", name="Save limits", exact=True).click()
    expect(outcome(page, "section:has(> #policy-connectors)")).to_have_text(
        CATALOGUE["bad_body"].text
    )
    expect(confirm_dialog(page)).to_be_hidden()
    connector_row(page).locator("input[type=number]").first.fill("50")
    connector_row(page).get_by_role("button", name="Save limits", exact=True).click()
    expect(outcome(page, "section:has(> #policy-connectors)")).to_have_text("Nothing would change.")
    assert (passkeys.asserted(), revision(rig)) == (asserted, written)


def test_item_22_a_second_browser_pausing_first_draws_the_page_again(
    connector_rig: PortalRig, page: Page, other_context: BrowserContext
) -> None:
    """Item 22's last line: "a second browser signed in on the same origin pauses it first: this
    browser's **Resume** draws the page again, saying the policy moved to revision N since it
    showed revision M ('press the connector's button again'), and nothing more is written".
    This browser shows the connector sending, so its button is **Pause**: pressed after the
    other browser's pause, it draws the page again and plans nothing."""
    rig = connector_rig
    passkeys = set_up(page, rig)
    open_section(page, "Policy")
    expect(connector_row(page)).to_contain_text("mail: sending.")
    second = other_context.new_page()
    open_portal(second, rig.origin)
    passkeys.copy_to(second)
    sign_in(second, rig.origin)
    open_section(second, "Policy")
    connector_row(second).get_by_role("button", name="Pause", exact=True).click()
    confirm(second)
    expect(connector_row(second)).to_contain_text("paused")
    assert revision(rig) == 3
    connector_row(page).get_by_role("button", name="Pause", exact=True).click()
    expect(page.locator("#policy-saved")).to_have_text(
        "The policy moved to revision 3 since this page showed revision 2: it is drawn again, "
        "so press the connector's button again."
    )
    expect(confirm_dialog(page)).to_be_hidden()
    expect(connector_row(page)).to_contain_text("paused")
    assert revision(rig) == 3


# --- item 23: onboarding in managed mode, Give to clients, the restore banner ------------------


@pytest.fixture
def boarding(tmp_path: Path, provider_tls: tuple[Path, Path]) -> Iterator[Onboarding]:
    """Item 23's vault: managed on a fresh state, its policy giving a client ``agent1`` no
    server; onboarding by URL on the in-process network; a gateway's poll waiting."""
    with onboarding(tmp_path, provider_tls, policy=MANAGED_SEED) as found:
        poller(found.rig)
        yield found


@pytest.fixture
def giving(tmp_path: Path) -> Iterator[PortalRig]:
    """Item 23 after its review's save: notes reviewed, ``echo`` allow and ``add`` approve, and
    ``agent1`` given no server."""
    document = managed(**reviewed_entry({"echo": "allow", "add": "approve"}))
    document["gateway"]["clients"] = {"agent1": {"token_sha256": AGENT1, "servers": []}}
    yield from running(tmp_path, document)


AGENT1 = hash_token("zgc1-agent1-token")
MANAGED_SEED = {
    "mode": "managed",
    "gateway": {"clients": {"agent1": {"token_sha256": AGENT1, "servers": []}}},
}
GIVE = "agents holding client agent1's token can call notes's 2 included tools"


def discover(page: Page, client_id: str = "") -> None:
    """**Add a server by URL** with the notes server's URL, a client ID in **More options** when
    given (a public client: no secret), then **Discover**."""
    open_section(page, "MCP servers")
    page.get_by_label("The server's MCP URL").fill(SERVER_URL)
    if not page.locator("#add-more").evaluate("(details) => details.open"):
        page.get_by_text("More options", exact=True).click()
    page.get_by_label("Client ID", exact=True).fill(client_id)
    if client_id:
        page.get_by_label("Client authentication", exact=True).select_option("none")
    press(page, "Discover")
    expect(page.locator("#plan")).to_be_visible()


def gives(page: Page, row: Locator) -> Locator:
    """**Give to clients** on ``row``: its block of boxes, once drawn."""
    row.get_by_role("button", name="Give to clients", exact=True).click()
    block = row.locator("div").filter(has=page.get_by_role("checkbox"))
    expect(block.get_by_role("checkbox")).to_have_count(1)
    return block


def test_item_23_onboarding_in_managed_mode_takes_one_passkey_a_step(
    boarding: Onboarding, page: Page, context: BrowserContext, watch: Watch
) -> None:
    """Item 23: "**Add a server by URL** with ... client ID ``public-check`` and no secret (a
    public client): the row reads 'Discovered, nothing sent or stored yet', and the plan's one
    button, like the row's, is **Save**, with no registration and no passkey prompt before it;
    **Cancel** it (nothing is written)"; with no client ID, "the plan's one button is **Register
    its client**; registered with a passkey, the page shows no fragment, and the row reads
    ``needs_save`` with **Save**; no text says to commit, reload, generate or make a fragment";
    "**Save**: the dialog's first row reads 'Revision 2, from 1 (by the seed, ...: 1 is the
    head)', then ``credentials.notes``, ``routes.notes`` and ``gateway.servers.notes``, each
    'added (wider)', and 'No restart needed'; confirmed, the row reads ``needs_connect``";
    "**Connect**: the provider sends the tab back to the portal, a passkey confirms, and the page
    queues the server's review by itself; Home's attention list names the tools nobody reviewed,
    with **Review**; the row, not reviewed yet, already has **Give to clients**"; "the review,
    ``echo`` included as allow and ``add`` as approve, **Save**: the answer ends 'Then give notes
    to each client that should reach it: Give to clients, on the MCP servers page', and the row
    reads reviewed, served to no client yet; Home's list no longer names notes"; **Give to
    clients**, ``agent1`` ticked and saved: served to ``agent1``; and "the vault's log has
    ``step_up_confirmed`` with ``onboard.register``, ``policy.save``, ``oauth.complete``,
    ``policy.save`` and ``client.servers``, in that order"."""
    rig = boarding.rig
    passkeys = set_up(page, rig)
    discover(page, "public-check")
    expect(server_row(page, "notes (")).to_contain_text("Discovered, nothing sent or stored yet")
    plan_buttons = page.locator("#plan-next button")
    expect(plan_buttons).to_have_text([SAVE_LABEL])
    expect(server_row(page, "notes (").locator("ul.steps button")).to_have_text([SAVE_LABEL])
    assert boarding.auth.registrations == []
    press(page, "Cancel this onboarding")
    expect(outcome(page, "#servers")).to_have_text("Onboarding cancelled.")
    assert (revision(rig), passkeys.asserted()) == (1, 1)
    discover(page)
    expect(plan_buttons).to_have_text(["Register its client"])
    plan_buttons.click()
    confirm(page)
    expect(outcome(page, "#servers")).to_have_text(
        "Registered. Save on its row adds it to the policy, with your passkey."
    )
    expect(page.locator("#fragment")).to_be_hidden()
    row = server_row(page, "notes (")
    expect(row).to_contain_text("Registered, its credential, route and server not saved yet")
    words = shown_words(page)
    assert [w for w in ("commit", "reload", "generate", "fragment") if w in words] == []
    row.get_by_role("button", name=SAVE_LABEL).click()
    rows = summary(page)
    assert rows[0][0] == "Revision"
    assert rows[0][1].startswith("2, from 1 (by the seed, ")
    assert rows[1:] == [
        ("credentials.notes", "added (wider)"),
        ("routes.notes", "added (wider)"),
        ("gateway.servers.notes", "added (wider)"),
        NO_RESTART,
    ]
    confirm(page)
    expect(notes_row(page)).to_contain_text("In the policy, not connected yet")
    notes_row(page).get_by_role("button", name="Connect", exact=True).click()
    with context.expect_page() as opened:
        page.get_by_role("link", name="Open the provider's sign-in page in a new tab").click()
    opened.value.wait_for_url("**/callback/received")
    opened.value.close()
    page.clock.run_for(2_000)  # the connect dialog's poll finds the sign-in back
    expect(confirm_dialog(page)).to_be_visible()
    held_review(page, rig, at_head(rig, OLD), lambda: confirm(page))
    pinned = {t.name: pins.project_and_pin(t).pin for t in OLD}
    unreviewed = tuple((t.name, pinned[t.name]) for t in OLD[:2])
    reported(rig, notes=status(unreviewed=unreviewed))  # the gateway's next status report
    open_section(page, "Home")
    nobody = page.locator("#attention > li").filter(has_text="notes lists 2 tools nobody reviewed")
    expect(nobody.get_by_role("button", name="Review", exact=True)).to_be_visible()
    open_section(page, "MCP servers")
    expect(notes_row(page)).to_contain_text("Connected, its tools not reviewed yet")
    expect(notes_row(page).get_by_role("button", name="Give to clients")).to_be_visible()
    read = review_notes(page, rig, OLD)
    choose(page, read, {"echo": "allow", "add": "approve"})
    page.get_by_label("Record the rest as declined", exact=False).uncheck()
    press(page, "Save")
    held_review(page, rig, at_head(rig, OLD), lambda: confirm(page))
    expect(outcome(page, "#review .z-actionbar")).to_contain_text(
        GIVE_LABEL.format(server="notes") + "."
    )
    reported(rig, notes=status())  # reviewed: the gateway reports nothing about notes
    open_section(page, "Home")
    expect(page.locator("#attention > li").filter(has_text="notes ")).to_have_count(0)
    open_section(page, "MCP servers")
    expect(notes_row(page)).to_contain_text(
        "notes (remote)Reviewed2 tools served to no client yet."
    )
    block = gives(page, notes_row(page))
    box = block.get_by_label("agent1")
    expect(box).not_to_be_checked()
    box.check()
    block.get_by_role("button", name="Save", exact=True).click()
    assert summary(page)[1] == ("gateway.clients.agent1.servers", GIVE)
    confirm(page)
    expect(notes_row(page)).to_contain_text("served to agent1.")
    actions = [line["action"] for line in rig.lines("step_up_confirmed")]
    assert actions == [
        "onboard.register",
        "policy.save",
        "oauth.complete",
        "policy.save",
        "client.servers",
    ]


def test_item_23_give_to_clients_closes_takes_away_and_meets_a_second_browser(
    giving: PortalRig, page: Page, other_context: BrowserContext, watch: Watch
) -> None:
    """Item 23: "**Give to clients**: one box, ``agent1``, unticked; ticked, **Save**: the dialog's
    row reads 'agents holding client agent1's token can call notes's 2 included tools'; **Close**
    writes nothing; **Save** again and confirm: the row says served to agent1; unticked and saved
    again, the dialog shows ``notes removed`` and no row ending '(wider)'"; and "**Give to
    clients** with the boxes shown, while a second browser signed in on the same origin gives
    notes to ``agent1`` first: this browser's ``agent1`` ticked and **Save** is refused before any
    passkey prompt ('press Save again to plan it on revision N'), the boxes are drawn again with
    ``agent1`` ticked, and nothing more is written"."""
    rig = giving
    passkeys = set_up(page, rig)
    open_section(page, "MCP servers")
    block = gives(page, notes_row(page))
    box = block.get_by_label("agent1")
    expect(box).not_to_be_checked()
    box.check()
    block.get_by_role("button", name="Save", exact=True).click()
    assert summary(page)[1:] == [("gateway.clients.agent1.servers", GIVE), NO_RESTART]
    close(page)
    assert revision(rig) == 1
    block.get_by_role("button", name="Save", exact=True).click()
    confirm(page)
    expect(notes_row(page)).to_contain_text("served to agent1.")
    block = gives(page, notes_row(page))
    block.get_by_label("agent1").uncheck()
    block.get_by_role("button", name="Save", exact=True).click()
    rows = summary(page)
    assert rows[1] == ("gateway.clients.agent1.servers", "notes removed")
    assert not [value for _, value in rows if value.endswith("(wider)")]
    confirm(page)
    expect(notes_row(page)).to_contain_text("served to no client yet")
    assert revision(rig) == 3
    block = gives(page, notes_row(page))
    second = other_context.new_page()
    open_portal(second, rig.origin)
    passkeys.copy_to(second)
    sign_in(second, rig.origin)
    open_section(second, "MCP servers")
    theirs = gives(second, notes_row(second))
    theirs.get_by_label("agent1").check()
    theirs.get_by_role("button", name="Save", exact=True).click()
    confirm(second)
    expect(notes_row(second)).to_contain_text("served to agent1.")
    assert revision(rig) == 4
    asserted = passkeys.asserted()
    watch.allow(r"status of 409", on=rig.origin)
    block.get_by_label("agent1").check()
    block.get_by_role("button", name="Save", exact=True).click()
    expect(outcome(page, "#servers")).to_contain_text("press Save again to plan it on revision 4")
    expect(confirm_dialog(page)).to_be_hidden()
    expect(block.get_by_label("agent1")).to_be_checked()  # drawn again at the head
    assert (passkeys.asserted(), revision(rig)) == (asserted, 4)


def test_item_23_a_restored_state_shows_its_banner_on_every_page(
    giving: PortalRig, page: Page
) -> None:
    """Item 23's restore banner (``policy_behind_witness``): the gateway reports a newer revision
    than the vault holds (as after the state volume was put back). "every page, Home first, shows
    the banner 'the gateway has applied revision N; this vault holds 2. Was the state volume
    restored? ...' with N the last save's revision, as text, its command ...
    ``policy acknowledge-restore``; Home's count of problems includes it"; once acknowledged
    (``zoeymcp policy acknowledge-restore``, written here as the host writes it), "the banner is
    gone, and **Policy**'s history shows N + 1 straight after" the revision the vault held.
    (The host's own command, run with the vault stopped, stays by hand.)"""
    rig = giving
    set_up(page, rig)
    managed_ = rig.app.managed
    assert managed_ is not None
    head_ = managed_.store.head
    assert head_ is not None
    banners = page.locator("#banners > li")
    expect(banners).to_have_count(0)
    claimed = {head_.deployment: 6}
    rig.call(lambda: rig.vault.app.keep_status(Report(VIEW, 1, {}, witness=claimed)))
    open_section(page, "Home")
    restored = banners.filter(has_text="the gateway has applied revision 6; this vault holds 1.")
    expect(restored).to_have_count(1)
    expect(restored).to_contain_text("Was the state volume restored?")
    expect(restored).to_contain_text("policy acknowledge-restore")
    expect(
        banners.filter(has_text="problem(s) need you: see the checklist on Home.")
    ).to_have_count(1)
    for section in ("MCP servers", "Policy", "Passkeys"):
        open_section(page, section)
        expect(restored).to_have_count(1)
    written = rig.call(
        lambda: managed_.write(
            "policy.acknowledge",
            "socket",
            1,
            lambda policy: policy,
            author={"by": "host", "via": "socket"},
            expected=None,
            jumped_from=1,
            revision=7,
        )
    )
    assert isinstance(written, Written)
    open_section(page, "Home")
    expect(banners.filter(has_text="the gateway has applied revision")).to_have_count(0)
    # Policy's history: the acknowledgment straight after the revision the vault held.
    open_section(page, "Policy")
    rows = history_rows(page)
    expect(rows).to_have_count(2)
    expect(rows.nth(0)).to_contain_text("Revision 7, ")
    expect(rows.nth(0)).to_contain_text("after revision 1")
    expect(rows.nth(1)).to_contain_text("Revision 1, ")
