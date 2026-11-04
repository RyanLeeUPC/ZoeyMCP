"""Managed mode in a real browser: manual items 31 and 32, **Hold in the vault** and **Turn off
vault approval** (M8 design step 27b, A.4, P.3; Z20, G-5).

The real vault and portal on loopback start managed (``tests/portal/rig.py``; the policy file
seeds revision 1), with notes' ``write`` an included ``approve`` tool, ``list`` allowed, the
portal's queue as the approver and three clients given notes: ``desk`` attended, ``nightly`` out
of band and ``batch`` neither. Its credential holds a refresh token, so notes' row on the MCP
servers page offers **Review again**, whose review the gateway's side answers on the vault's
loop (``tests/portal/test_review.py``'s way). The connector form runs on two toolkits writing
through a ``mail`` connector, one through ``post`` too. The page runs with the browser's own
WebAuthn stack over a virtual authenticator, its Content Security Policy and Trusted Types in
force, every page watched; each test's docstring names its item and the lines it checks, and
``docs/manual-checks.md`` keeps the lines left by hand. ``tests/portal/
test_vault_approval_managed.py`` holds the same rules over the API.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from playwright.sync_api import Locator, Page, Route, expect

from tests.portal.test_policy_managed import (
    LIST,
    WRITE,
    entry,
    head,
    host_import,
    managed,
    report_of,
    revision,
)
from tests.portal.test_review import gateway_answers, poller
from tests.portal.test_vault_approval_managed import mailing
from zoeymcp.common.policy.plan import NO_RESTART, VAULT_OFF_CONNECTOR_TEXT, VAULT_OFF_TEXT
from zoeymcp.common.policy.schema import hash_token
from zoeymcp.portal.refusals import CATALOGUE
from zoeymcp.vault.bindings import derive_binding

from .portal import confirm, confirm_dialog, open_section, press, set_up, summary
from .stacks import PortalRig, portal
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


def server_row(page: Page, label: str) -> Locator:
    return page.locator("#server-list > li").filter(has_text=label)


def notes_row(page: Page) -> Locator:
    return server_row(page, "notes (remote)")


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
    held until the gateway's review is answered: write's row.

    The poll is held, not left to the screen's timer: review.js asks once right after queueing,
    and a tick that fires while that ask is still out is skipped, so a paused clock moved on
    once could leave the review undrawn (CI's Chromium did, on 6b9d45c)."""

    def answered(route: Route) -> None:
        gateway_answers(rig, report_of([LIST, WRITE], [WRITE], [LIST]))
        route.continue_()

    open_section(page, "MCP servers")
    page.route("**/api/review/jobs/*", answered, times=1)
    notes_row(page).get_by_role("button", name="Review again", exact=True).click()
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
    hold = notes_row(page).get_by_role("button", name="Hold in the vault: write", exact=True)
    expect(hold).to_be_enabled()
    hold.click()
    assert labelled(page, "notes.write") == TURN_ON
    assert passkeys.asserted() == 1  # sign-in's only: no prompt before the plan
    assert revision(rig) == 1
    confirm(page)
    expect(confirm_dialog(page)).to_be_hidden()
    off = notes_row(page).get_by_role("button", name="Turn off vault approval: write")
    expect(off).to_be_visible()
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
    expect(row.get_by_role("button", name="Hold in the vault: write", exact=True)).to_be_disabled()
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
    notes_row(page).get_by_role("button", name="Turn off vault approval: write").click()
    assert labelled(page, OFF_PATH) == [VAULT_OFF_TEXT.format(name="write")]
    assert passkeys.asserted() == 1
    confirm(page)
    expect(confirm_dialog(page)).to_be_hidden()
    hold = notes_row(page).get_by_role("button", name="Hold in the vault: write", exact=True)
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
    error = page.locator("#error")
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
    notes_row(page).get_by_role("button", name="Hold in the vault: write", exact=True).click()
    confirm(page)
    off = notes_row(page).get_by_role("button", name="Turn off vault approval: write")
    expect(off).to_be_visible()
    assert revision(rig) == 3
    open_section(page, "Policy")
    watch.allow(REFUSED_409, on=rig.origin)
    for target in (2, 1):
        page.get_by_role("button", name=f"Roll back to revision {target}", exact=True).click()
        said = CATALOGUE["rollback_drops_vault_approval"].text.format(
            detail=f"revision {target} would stop the vault holding notes.write"
        )
        expect(page.locator("#error")).to_have_text(said)
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
