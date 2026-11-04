"""The Approvals queue in a real browser: manual items 25-30, 33 and 34, and the queue's rows of
the D-222 brief's section 4 (M8 design step 27b, P.3, H; D-144's M8 part).

Each test drives the portal's real page with the browser's own WebAuthn stack (a CDP virtual
authenticator) against the real vault and portal on loopback, holding calls
(``stacks.queue``): each call is sent to the vault's proxy listener as the gateway sends it, and
waits in the queue (``block_seconds`` 0: it answers pending). Where an item has Telegram, the
vault's own Telegram surface runs against the fake Bot API in process and the operator presses
its buttons there; never a real bot. ``pending`` and ``check_approval`` run through a real
gateway and an agent
(``stacks.gateway_queue``). Page time is Playwright's paused clock, moved past a poll to fire it;
the vault's sessions run on the rig's ``Clock`` and its holds on the stack's ``Ahead``. Every
context's watch must stay clean: no Content Security Policy or Trusted Types violation, dialog,
page error, request off loopback or console error a test didn't allow. Each test's docstring names
its item and the lines it checks; ``docs/manual-checks.md`` keeps the lines left by hand.
"""

from __future__ import annotations

import re
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from playwright.sync_api import BrowserContext, Page, expect

from tests.fakes.mcp_server import BIDI_OVERRIDE, HOSTILE, ZERO_WIDTH
from tests.gateway import holdrig
from tests.portal.test_home import reported, server
from tests.portal.test_ledger import chain, report
from zoeymcp.common.approvaltext import RELAY_LINE
from zoeymcp.gateway import checkapproval
from zoeymcp.portal.app import REPLACED
from zoeymcp.portal.approvalsview import APPROVE_SENTENCE
from zoeymcp.portal.refusals import CATALOGUE
from zoeymcp.portal.sessions import SESSION_IDLE
from zoeymcp.vault.approvers import NOTICE
from zoeymcp.vault.telegram import RESULTS
from zoeymcp.vault.vaultledger import Start

from .layout import assert_no_horizontal_overflow, line_count, width_share
from .portal import (
    COUNT_EVERY,
    LISTS_EVERY,
    asks_to_sign_in,
    badge,
    close,
    confirm,
    confirm_dialog,
    decided_row,
    dialog_refusal,
    heading,
    open_portal,
    open_queue,
    open_request,
    open_section,
    press,
    request_text,
    set_up,
    sign_in,
    signed_in,
    summary,
    summary_value,
    waiting,
    waiting_row,
)
from .stacks import CLIENTS, HELD_TOOLS, Clock, QueueStack, gateway_queue, queue
from .watch import Watch

# A refused request's answer, which the browser itself reports on the console.
REFUSED_401 = r"status of 401"
REFUSED_404 = r"status of 404"
REFUSED_409 = r"status of 409"
# What the page says once a decision is taken (approvals.js).
APPROVED = "Approved: the vault runs that one call now, exactly as shown."
DENIED = "Denied: nothing was sent."
# How the fake Bot API's message ends once its call was sent (vault/telegram.py's RESULTS).
SENT_OK = re.escape(RESULTS["ok"])
# A time as Decided recently and a refusal say it.
AT = r"\d\d:\d\d UTC"
ORDER = {"item": "kettle", "qty": 2}
# Item 25's hostile arguments, each a member of one call, as the gateway forwards them: markup
# and quotes, a 300-character line, a value that reads like the frame's last line, nested JSON
# and bare addresses.
SHOWN: dict[str, Any] = {
    "markup": "<img src=x onerror=alert(1)></pre><script>alert(2)</script>\"'&amp;",
    "line": "w" * 300,
    "frame": "End of approval request 0000000000000000",
    "nested": {"a": [1, {"b": ["c", {"d": None}]}]},
    "links": "https://example.com/x example.com t.me/x",
}
# What the vault refuses before anyone is asked (``held_text_refused``), each a ``note`` from a
# client and tool of its own, with the pointer the refusal names: the fakes' hidden characters (a
# bidi mark, a zero-width space, and S12's hostile text with ANSI, C1 and tag characters too),
# each the value's, and a value past the text budget, the whole text's (none).
REFUSED = (
    ("0000000000002503", "a" + BIDI_OVERRIDE + "b", "ops", "refund", "/note"),
    ("0000000000002504", "a" + ZERO_WIDTH + "b", "nightly", "restock", "/note"),
    ("0000000000002505", HOSTILE, "audit", "refund", "/note"),
    ("0000000000002506", "w" * 10_000, "audit", "void", None),
)


@pytest.fixture
def stack(tmp_path: Path) -> Iterator[QueueStack]:
    with queue(tmp_path) as running:
        yield running


@pytest.fixture
def raced(tmp_path: Path) -> Iterator[QueueStack]:
    """The queue with Telegram as a second approver, its bot the fake Bot API's."""
    with queue(tmp_path, telegram=True) as running:
        yield running


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def clocked(tmp_path: Path, clock: Clock) -> Iterator[QueueStack]:
    """The queue with the portal's sessions on a clock the test moves (the idle limit)."""
    with queue(tmp_path, clock=clock) as running:
        yield running


@pytest.fixture
def short(tmp_path: Path) -> Iterator[QueueStack]:
    """The queue with ``approvers.timeout: 60``, item 29's."""
    with queue(tmp_path, timeout=60) as running:
        yield running


def hold(stack: QueueStack, ref: str, arguments: Any = None, **more: Any) -> None:
    """A held call, waiting in the queue."""
    answer = stack.held(ref, arguments or ORDER, **more)
    assert answer.status_code == 409, answer.text
    assert answer.json()["code"] == "approval_pending", answer.text


def shows_whole(page: Page, stack: QueueStack, ref: str) -> str:
    """``ref`` opened: its ``pre`` holds exactly the vault's text. Returns the text."""
    open_request(page, ref)
    composed = stack.text(ref)
    assert request_text(page).text_content() == composed
    return composed


def dialog_shows_whole(page: Page, composed: str, wrapped: int) -> None:
    """**Approve** on the opened request: the confirm dialog's summary, drawn by its own path,
    holds ``composed`` whole as text (no element made of it), in a value column the label
    doesn't squeeze (item 20's fault: a character a line), wrapped onto more than ``wrapped``
    lines beyond its own, nothing scrolling sideways; then **Close**, which confirms nothing."""
    press(page, "Approve")
    assert dict(summary(page))["The request, whole"] == composed
    assert page.locator("#confirm-summary img, #confirm-summary script").count() == 0
    value = summary_value(page, "The request, whole")
    assert width_share(value, page.locator("#confirm-summary")) > 0.5
    assert line_count(value) > composed.count("\n") + wrapped
    assert_no_horizontal_overflow(page, "#confirm-summary")
    close(page)


def poll(page: Page, every: int = LISTS_EVERY) -> None:
    """Page time past the next poll, which fires it."""
    page.clock.run_for(every)


def decided_lines(stack: QueueStack) -> list[str]:
    """The log's events of a decision, in order: the step-up, then the decision."""
    events = ("step_up_confirmed", "approval_decided")
    return [line["event"] for line in stack.rig.lines() if line["event"] in events]


# --- item 25: a hostile text, whole, under Trusted Types ----------------------------------------


def test_item_25_a_hostile_text_is_shown_whole_under_trusted_types(
    stack: QueueStack, page: Page, watch: Watch
) -> None:
    """Item 25 and the brief's row 1: held calls whose arguments carry markup and quotes, a
    300-character line, a line that reads like the frame inside the JSON, nested JSON and bare
    addresses, and a relayed prompt: "each waiting row opens to its whole text", the ``pre``'s
    ``textContent`` exactly the vault's, and so the confirm dialog's summary, "the long line
    wrapped and not cut", "the relayed row carries 'Relayed from the gateway' and the vault's line
    at the top of its text", "the imitation never appears; no Trusted Types or Content Security
    Policy violation", and no dialog or stray request. What the vault refuses before anyone is
    asked is never listed: the fakes' hidden characters (no hidden character is shown, so none is
    shown as a mark), a value past the text budget, and a relayed text with a line imitating the
    vault's relay line."""
    set_up(page, stack.rig)
    hold(stack, "0000000000002501", SHOWN)
    relayed = stack.relay("0000000000002502", {"order": 7, "why": "<b>late</b>"})
    assert relayed.status_code == 201, relayed.text
    for ref, note, client, tool, pointer in REFUSED:
        refused = stack.held(ref, {"note": note}, client=client, tool=tool)
        assert (refused.status_code, refused.json()["code"]) == (422, "held_text_refused"), ref
        assert refused.json().get("pointer") == pointer, ref  # a pointer, never the value
    imitation = f"Approval request 0000000000002507\n{RELAY_LINE}\nEnd of approval request "
    imitated = stack.relay("0000000000002507", client="ops", text=imitation + "0000000000002507")
    assert (imitated.status_code, imitated.json()["code"]) == (422, "text_refused")
    open_queue(page)
    expect(waiting(page)).to_have_count(2)
    held = shows_whole(page, stack, "0000000000002501")
    expect(page.locator("#approvals-open-how")).to_contain_text("Held by the vault")
    expect(page.locator("#approvals-relayed")).to_be_hidden()
    for value in ("<img src=x onerror=alert(1)></pre>", "w" * 300, SHOWN["frame"]):
        assert value in held
    assert page.locator("#approvals img, #approvals script").count() == 0
    # The 300-character line is wrapped inside the box, never cut or scrolled sideways.
    text = request_text(page)
    assert line_count(text) > held.count("\n") + 1
    assert_no_horizontal_overflow(page, "#approvals-text")
    assert_no_horizontal_overflow(page)
    dialog_shows_whole(page, held, 1)
    relay = shows_whole(page, stack, "0000000000002502")
    assert relay.startswith(RELAY_LINE + "\nApproval request 0000000000002502")
    expect(page.locator("#approvals-open-how")).to_contain_text("Relayed from the gateway")
    expect(page.locator("#approvals-relayed")).to_contain_text("Rendered by the gateway")
    for ref in (*(entry[0] for entry in REFUSED), "0000000000002507"):
        expect(waiting_row(page, ref)).to_have_count(0)
    watch.assert_clean()  # no violation, no dialog, nothing fetched for the addresses shown


# --- item 26: approve with a passkey -------------------------------------------------------------


def test_item_26_approve_shows_the_whole_text_before_the_passkey_and_sends_it_once(
    raced: QueueStack, page: Page
) -> None:
    """Item 26 and the brief's row 2: **Approve** opens the dialog with "the whole text and
    'Approve runs this one call, exactly as shown.'" before any passkey prompt (no
    ``credentialAsserted`` before the click); "one passkey prompt; the answer is 200"; the row
    "moves to **Decided
    recently** reading 'approved here HH:MM UTC; sent: ok'"; the upstream gets exactly the held
    bytes, once; "the log has ``step_up_confirmed`` with ``approval.decide``, then
    ``approval_decided`` with ``via: portal``"; "the fake's message for that ref becomes '...:
    decided in the portal' with no buttons" (the fake Bot API's message, edited); and the
    Ledger page lists the vault's records of the call, each written by the vault."""
    stack = raced
    passkeys = set_up(page, stack.rig)
    ref = "0000000000002601"
    hold(stack, ref)
    assert stack.message(ref).labels() == ["Deny", "Approve"]  # Telegram asks too
    open_queue(page)
    composed = shows_whole(page, stack, ref)
    before = passkeys.asserted()
    press(page, "Approve")
    rows = dict(summary(page))
    assert rows["Approval request"] == ref
    assert rows["The request, whole"] == composed
    assert rows["Approve"] == APPROVE_SENTENCE
    assert passkeys.asserted() == before  # the plan is shown, and no prompt has opened
    assert stack.upstream.posts() == []
    with page.expect_response(lambda answer: answer.url.endswith("/confirm")) as confirmed:
        confirm(page)
    assert confirmed.value.status == 200
    expect(page.get_by_text(APPROVED)).to_be_visible()
    expect(confirm_dialog(page)).to_be_hidden()
    assert passkeys.asserted() == before + 1
    stack.settled()
    poll(page)
    expect(decided_row(page, ref)).to_contain_text(re.compile(f"approved here {AT}; sent: ok"))
    expect(waiting_row(page, ref)).to_have_count(0)
    assert stack.upstream.posts() == [holdrig.call("place_order", ORDER)]
    assert decided_lines(stack) == ["step_up_confirmed", "approval_decided"]
    [stepped] = stack.rig.lines("step_up_confirmed")
    assert stepped["action"] == "approval.decide"
    [decided] = stack.rig.lines("approval_decided")
    assert decided["via"] == "portal"
    told = re.compile(f"^Approval request {ref}: approved {AT} in the portal\\. {SENT_OK}$")
    stack.until(lambda: any(told.match(stored.text) for stored in stack.messages(ref)))
    assert stack.message(ref).reply_markup is None
    open_section(page, "Ledger")
    vault_only = page.locator("#ledger-vault-only li").filter(has_text=ref)
    expect(vault_only).to_contain_text("decision accept via portal")
    expect(vault_only).to_contain_text("decided written by the vault")


# --- item 27: a cancelled passkey prompt ---------------------------------------------------------


def test_item_27_a_cancelled_passkey_prompt_decides_nothing(stack: QueueStack, page: Page) -> None:
    """Item 27 and the brief's row 3: **Approve**, then the passkey prompt cancelled (user
    verification off, so the browser's ceremony fails with ``NotAllowedError``, as a cancelled
    prompt does): "nothing is decided, the row stays under **Waiting**, no ``approval_decided``
    line" and no ``step_up_confirmed``; "**Approve** again works"."""
    passkeys = set_up(page, stack.rig)
    ref = "0000000000002701"
    hold(stack, ref)
    open_queue(page)
    open_request(page, ref)
    press(page, "Approve")
    passkeys.set_user_verified(False)
    confirm(page)
    expect(dialog_refusal(page)).to_contain_text("The passkey prompt was cancelled")
    assert passkeys.asserted() == 1  # sign-in's only
    assert decided_lines(stack) == []
    assert stack.hold(ref).state == "held"
    poll(page)
    expect(waiting_row(page, ref)).to_have_count(1)
    assert stack.upstream.posts() == []
    passkeys.set_user_verified(True)
    confirm(page)  # the action is still held: the same dialog confirms
    expect(page.get_by_text(APPROVED)).to_be_visible()
    stack.settled()
    assert len(stack.upstream.posts()) == 1


# --- item 28: a stale decision -------------------------------------------------------------------


def test_item_28_telegram_deciding_while_the_dialog_is_open_wins(
    raced: QueueStack, page: Page, watch: Watch
) -> None:
    """Item 28's first lines: with the confirm dialog open, **Approve** is pressed for the same
    call in the fake Bot API: "the confirm is refused 409 ``already_decided``, 'Already decided
    in Telegram at HH:MM: approved', and nothing more is sent" (the call runs once,
    Telegram's)."""
    stack = raced
    set_up(page, stack.rig)
    ref = "0000000000002801"
    hold(stack, ref)
    open_queue(page)
    open_request(page, ref)
    press(page, "Approve")
    expect(confirm_dialog(page)).to_be_visible()
    stack.press(ref, "Approve")
    watch.allow(REFUSED_409, on=stack.rig.origin)
    confirm(page)
    said = re.compile(f"^Already decided in Telegram at {AT}: approved\\.$")
    expect(dialog_refusal(page)).to_have_text(said)
    assert stack.rig.lines("approval_decided")[-1]["via"] == "telegram"
    stack.settled()
    assert stack.upstream.posts() == [holdrig.call("place_order", ORDER)]


def test_item_28_two_operators_the_second_is_refused(
    stack: QueueStack, page: Page, other_context: BrowserContext, watch: Watch
) -> None:
    """The brief's row 4, item 28's second browser: two operators in two browsers open the same
    call and press **Approve**; the first confirms; the second's confirm is refused
    ``already_decided`` naming the portal, and nothing is forwarded twice."""
    passkeys = set_up(page, stack.rig)
    other = other_context.new_page()
    open_portal(other, stack.rig.origin)
    passkeys.copy_to(other)
    sign_in(other, stack.rig.origin)
    ref = "0000000000002802"
    hold(stack, ref)
    for each in (page, other):
        open_queue(each)
        open_request(each, ref)
        press(each, "Approve")
        expect(confirm_dialog(each)).to_be_visible()
    confirm(page)
    expect(page.get_by_text(APPROVED)).to_be_visible()
    watch.allow(REFUSED_409, on=stack.rig.origin)
    confirm(other)
    said = re.compile(f"^Already decided in the portal at {AT}: approved\\.$")
    expect(dialog_refusal(other)).to_have_text(said)
    stack.settled()
    assert stack.upstream.posts() == [holdrig.call("place_order", ORDER)]
    assert [line["via"] for line in stack.rig.lines("approval_decided")] == ["portal"]


def test_item_28_an_approval_replaces_a_change_prepared_in_another_tab(
    stack: QueueStack, page: Page, context: BrowserContext, watch: Watch
) -> None:
    """Item 28's last lines (H.3, G-11): one prepared action per session. A duplicated tab
    carries the session (the browser copies ``sessionStorage`` into it; the harness copies the
    one key the page keeps) and prepares a change there (a passkey's rename); preparing an
    approval in the first tab says first "This replaces the <kind> you prepared in another
    tab; it was cancelled.", and the other tab's confirm is refused."""
    passkeys = set_up(page, stack.rig)
    ref = "0000000000002803"
    hold(stack, ref)
    duplicate = context.new_page()
    open_portal(duplicate, stack.rig.origin)
    asks_to_sign_in(duplicate)
    token = page.evaluate("sessionStorage.getItem('session')")
    duplicate.evaluate("(token) => sessionStorage.setItem('session', token)", token)
    duplicate.reload()
    signed_in(duplicate, stack.rig.origin)
    passkeys.copy_to(duplicate)
    open_section(duplicate, "Passkeys")
    duplicate.locator("#passkey-list li").get_by_role("button", name="Rename").click()
    duplicate.get_by_label("New name").fill("desk")
    duplicate.locator("#rename").get_by_role("button", name="Rename", exact=True).click()
    expect(confirm_dialog(duplicate)).to_be_visible()
    open_queue(page)
    open_request(page, ref)
    press(page, "Approve")
    rows = summary(page)
    assert rows[0] == ("Replaced", REPLACED.format(kind="passkey.rename"))
    assert rows[1] == ("Approval request", ref)
    watch.allow(REFUSED_404, on=stack.rig.origin)
    confirm(duplicate)
    expect(dialog_refusal(duplicate)).to_have_text(CATALOGUE["action_unknown"].text)
    assert stack.rig.lines("passkey_renamed") == []
    confirm(page)
    expect(page.get_by_text(APPROVED)).to_be_visible()


# --- item 29: deny, and an expired row -----------------------------------------------------------


def test_item_29_deny_needs_no_passkey_and_sends_nothing(stack: QueueStack, page: Page) -> None:
    """Item 29's first lines and the brief's row 3: **Deny** a waiting row: "no passkey
    prompt, the row moves to Decided recently as denied ... nothing reaches the fake
    upstream"."""
    passkeys = set_up(page, stack.rig)
    ref = "0000000000002901"
    hold(stack, ref)
    open_queue(page)
    open_request(page, ref)
    press(page, "Deny")
    expect(page.get_by_text(DENIED)).to_be_visible()
    stack.settled()  # the ending told to the queue
    poll(page)
    expect(decided_row(page, ref)).to_contain_text(
        re.compile(f"denied here {AT}; nothing was sent")
    )
    expect(waiting_row(page, ref)).to_have_count(0)
    assert passkeys.asserted() == 1  # sign-in's only
    assert stack.rig.lines("step_up_confirmed") == []
    assert [line["via"] for line in stack.rig.lines("approval_decided")] == ["portal"]
    assert stack.upstream.posts() == []


def test_item_29_a_row_past_its_deadline_cant_be_approved(
    short: QueueStack, page: Page, watch: Watch
) -> None:
    """Item 29's last lines and the brief's row 5: with ``approvers.timeout: 60``, the hold
    table's clock moves past the deadline while the confirm dialog is open: the confirm "is
    refused ``expired``", and the next poll drops the row, which "leaves **Waiting** as
    expired"."""
    stack = short
    set_up(page, stack.rig)
    ref = "0000000000002902"
    hold(stack, ref)
    open_queue(page)
    open_request(page, ref)
    press(page, "Approve")
    expect(confirm_dialog(page)).to_be_visible()
    assert stack.later(61) == 1
    watch.allow(REFUSED_409, on=stack.rig.origin)
    confirm(page)
    expect(dialog_refusal(page)).to_have_text(CATALOGUE["expired"].text)
    close(page)
    stack.settled()
    poll(page)
    expect(waiting_row(page, ref)).to_have_count(0)
    expect(decided_row(page, ref)).to_contain_text(re.compile(f"expired {AT}; nothing was sent"))
    expect(page.get_by_text("That approval no longer waits")).to_be_visible()
    assert stack.upstream.posts() == []


# --- item 30: the idle limit, and one tab per browser --------------------------------------------


def test_item_30_an_open_queue_doesnt_keep_the_session_alive(
    clocked: QueueStack, clock: Clock, page: Page, watch: Watch
) -> None:
    """Item 30 and the brief's row 9: the Approvals page left open while its polls run (every 5
    and 10 s of page time, fired here as the rig's clock moves on five minutes at a time): the
    polls don't count as activity, so once the session has idled its 15 minutes "the next action
    lands on the sign-in page" (the queue's own poll, refused, takes the page there)."""
    stack = clocked
    set_up(page, stack.rig)
    hold(stack, "0000000000003001")
    open_queue(page)
    for _ in range(2):  # ten minutes, with the queue's polls
        clock.advance(300)
        poll(page, COUNT_EVERY)
        expect(waiting(page)).to_have_count(1)
        heading(page, "Approvals")
    watch.allow(REFUSED_401, on=stack.rig.origin)  # the poll past the idle limit, refused
    clock.advance(SESSION_IDLE - 600)  # 15 minutes since the last use: signing in
    poll(page, COUNT_EVERY)
    asks_to_sign_in(page)
    assert stack.rig.logged("portal_session_ended", lambda line: line["why"] == "idle")


def test_a_decision_prepared_in_one_tab_ends_when_another_tab_signs_in(
    stack: QueueStack, page: Page, context: BrowserContext, watch: Watch
) -> None:
    """The brief's row 9's last line, with item 3's rule (one signed-in tab per browser): an
    approval prepared in one tab, then a second tab signs in, which ends the first tab's
    session: the first tab's confirm is refused and lands on the sign-in page, deciding
    nothing; the second tab decides it."""
    passkeys = set_up(page, stack.rig)
    ref = "0000000000003002"
    hold(stack, ref)
    open_queue(page)
    open_request(page, ref)
    press(page, "Approve")
    expect(confirm_dialog(page)).to_be_visible()
    tab = context.new_page()
    open_portal(tab, stack.rig.origin)
    passkeys.copy_to(tab)
    sign_in(tab, stack.rig.origin)
    watch.allow(REFUSED_401, on=stack.rig.origin)
    confirm(page)
    asks_to_sign_in(page)
    assert decided_lines(stack) == []
    assert stack.hold(ref).state == "held"
    open_queue(tab)
    open_request(tab, ref)
    press(tab, "Approve")
    confirm(tab)
    expect(tab.get_by_text(APPROVED)).to_be_visible()
    stack.settled()
    assert len(stack.upstream.posts()) == 1


# --- the brief's rows 6-8: an arrival, a long wait, a flood --------------------------------------


def test_an_arrival_shows_within_one_poll(stack: QueueStack, page: Page) -> None:
    """The brief's row 6: with the queue open, a new held call appears within one poll, with no
    reload; the nav's count and Home's attention list include it."""
    set_up(page, stack.rig)
    hold(stack, "0000000000003101")
    open_queue(page)
    expect(waiting(page)).to_have_count(1)
    expect(badge(page)).to_have_text("Approvals (1)")
    hold(stack, "0000000000003102", client="nightly")
    poll(page)
    expect(waiting(page)).to_have_count(2)
    expect(waiting_row(page, "0000000000003102")).to_contain_text("client nightly")
    expect(badge(page)).to_have_text("Approvals (2)")
    open_section(page, "Home")
    expect(page.locator("#attention-approvals")).to_contain_text("2 approvals waiting")


def test_pending_then_check_approval(tmp_path: Path, page: Page) -> None:
    """The brief's row 7 (S20 through a real gateway): the agent's call answers ``pending
    <ref>``, the operator approves it in the browser, and the agent's ``check_approval``
    returns the call's result, once; the fake server ran it once."""
    with gateway_queue(tmp_path) as stack:
        set_up(page, stack.rig)
        ref = stack.pending({"text": "approved in a browser"})
        open_queue(page)
        expect(waiting_row(page, ref)).to_contain_text("client agent1")
        open_request(page, ref)
        press(page, "Approve")
        confirm(page)
        expect(page.get_by_text(APPROVED)).to_be_visible()
        assert stack.check_approval(ref) == "approved in a browser"
        assert stack.check_approval(ref).startswith(checkapproval.COLLECTED)
        assert [call.arguments for call in stack.fake.calls if call.name == "echo"] == [
            {"text": "approved in a browser"}
        ]


def test_a_pending_call_denied_in_the_browser_is_collected_as_declined(
    tmp_path: Path, page: Page
) -> None:
    """Item 29's agent line through a real gateway: a pending call the operator denies in the
    browser is collected as declined, and never reaches the server. On its own stack: a second
    call to the same tool just after a collect can meet the lock not yet freed (D-250)."""
    with gateway_queue(tmp_path) as stack:
        set_up(page, stack.rig)
        denied = stack.pending({"text": "denied in a browser"})
        open_queue(page)
        open_request(page, denied)
        press(page, "Deny")
        expect(page.get_by_text(DENIED)).to_be_visible()
        assert stack.check_approval(denied) == f"{checkapproval.DECLINED} (ref {denied})"
        assert [call.arguments for call in stack.fake.calls if call.name == "echo"] == []


def test_a_flood_to_capacity_stays_usable(stack: QueueStack, page: Page) -> None:
    """The brief's row 8 (D-37: a flood "can only queue requests, which the operator sees and
    denies"): calls held up to the route's capacity (four tools from four clients, each text
    near the budget) and one past it, to a fifth tool under its own cap, refused by the route's;
    the page lists every one with the right counts and the vault's notice, its layout holds (no
    sideways scrolling, the text box the page's width, a long text wrapped, and so the confirm
    dialog's value), and **Deny** works on every row."""
    set_up(page, stack.rig)
    *filling, spare = HELD_TOOLS
    refs = []
    for number, (client, tool) in enumerate(
        ((client, tool) for tool in filling for client in CLIENTS), start=1
    ):
        ref = f"{0x3200 + number:016x}"
        hold(stack, ref, {"note": f"{client} {tool} " + "n" * 2400}, client=client, tool=tool)
        refs.append(ref)
    assert len(refs) == 16
    over = stack.held(f"{0x3300:016x}", ORDER, client="desk", tool=spare)
    assert (over.status_code, over.json()["code"]) == (429, "held_capacity")
    stack.settled()  # the surfaces told of the refusal
    open_queue(page)
    expect(page.locator("#approvals-notice")).to_have_text(NOTICE.format(count=1))
    expect(waiting(page)).to_have_count(16)
    expect(badge(page)).to_have_text("Approvals (16)")
    assert_no_horizontal_overflow(page)
    composed = shows_whole(page, stack, refs[-1])
    text = request_text(page)
    assert width_share(text, page.locator("#approvals")) > 0.9
    assert line_count(text) > composed.count("\n") + 5  # the long value, wrapped
    assert_no_horizontal_overflow(page, "#approvals-text")
    assert_no_horizontal_overflow(page)
    dialog_shows_whole(page, composed, 5)
    for left, ref in zip(range(15, -1, -1), refs, strict=True):
        open_request(page, ref)
        press(page, "Deny")
        expect(waiting(page)).to_have_count(max(left, 1))  # "Nothing waits" is a row too
    expect(waiting(page)).to_have_text(["Nothing waits for your approval."])
    expect(badge(page)).to_have_text("Approvals")
    stack.settled()
    assert stack.upstream.posts() == []
    assert len(stack.rig.lines("approval_decided")) == 16


# --- item 33: Home and the badge -----------------------------------------------------------------


def test_item_33_home_lists_the_waiting_calls_and_the_starts_findings(
    stack: QueueStack, page: Page
) -> None:
    """Item 33: "With two calls waiting, Home lists '2 approvals waiting: the oldest must be
    answered by HH:MM UTC' with **Open the queue**, and the nav's Approvals entry shows 2; with
    no gateway status report ... the item still shows", and with one (kept as the gateway's
    status path keeps it) the item stays. What a start's recovery closed
    (``approvals_withdrawn_at_start``, cleared by opening Approvals, and
    ``approvals_outcome_unknown`` naming the ref) shows on Home's checklist: the recovery's
    result set on the vault's chain stands in for a killed vault's, whose kill and restart
    ``tests/acceptance/test_held_crash.py`` runs (Linux, processes)."""
    set_up(page, stack.rig)
    hold(stack, "0000000000003301")
    hold(stack, "0000000000003302", client="nightly")
    chain = stack.rig.vault.app.chain
    assert chain is not None
    chain.start = Start(withdrawn=1, outcome_unknown=("0000000000003303",))
    open_section(page, "Home")
    item = page.locator("#attention-approvals li")
    expect(item).to_have_text(
        re.compile(f"^2 approvals waiting: the oldest must be answered by {AT}\\. Open the queue$")
    )
    unreported = page.get_by_text("The gateway hasn't reported its status")
    expect(unreported).to_be_visible()
    poll(page, COUNT_EVERY)
    expect(badge(page)).to_have_text("Approvals (2)")
    reported(stack.rig, shop=server())
    open_section(page, "Home")
    expect(unreported).to_have_count(0)
    expect(item).to_have_text(re.compile("^2 approvals waiting: "))
    checklist = page.locator("#checklist li")
    withdrawn = checklist.filter(has_text="the last vault start withdrew 1 approval(s)")
    expect(withdrawn).to_contain_text("Open the Approvals page: Decided recently lists them.")
    unknown = checklist.filter(has_text="0000000000003303")
    expect(unknown).to_contain_text("may have run before the vault stopped")
    item.get_by_role("button", name="Open the queue", exact=True).click()
    heading(page, "Approvals")
    expect(waiting(page)).to_have_count(2)
    open_section(page, "Home")
    expect(unknown).to_have_count(1)
    expect(withdrawn).to_have_count(0)


# --- item 34: the Ledger's two chains ------------------------------------------------------------


def gateway_asked(ref: str, *, client: str, tool: str, where: str) -> dict[str, Any]:
    """The gateway's ``asked`` record of a call, as it reports it to the vault."""
    digest = "hmac-sha256:" + "1" * 64
    return {
        "kind": "asked",
        "ref": ref,
        "client": client,
        "server": "shop",
        "tool": tool,
        "where": where,
        "era": "legacy",
        "args": digest,
        "pin": holdrig.PIN,
        "text": digest,
        "chars": 10,
        "writes": 1,
        "expires": 1,
    }


def test_item_34_the_ledger_joins_both_chains(raced: QueueStack, page: Page) -> None:
    """Item 34: after a held call approved in the portal and a relayed call approved in the
    fake Bot API, and the gateway's ledger reported: "the held call is one row with
    asked ..., decided accept via Telegram or the portal (written by the vault), the outcome
    and ``approved_elsewhere`` (the gateway's), each marked with its writer; the relayed call's
    row shows the gateway's outcome; no 'the chains disagree' flag"."""
    stack = raced
    set_up(page, stack.rig)
    held, relayed = "0000000000003401", "0000000000003402"
    hold(stack, held)
    assert stack.relay(relayed).status_code == 201
    open_queue(page)
    open_request(page, held)
    press(page, "Approve")
    confirm(page)
    expect(page.get_by_text(APPROVED)).to_be_visible()
    stack.press(relayed, "Approve")
    stack.settled()
    report(
        stack.rig,
        chain(
            [
                gateway_asked(held, client="desk", tool="place_order", where="vault"),
                gateway_asked(relayed, client="nightly", tool="cancel_order", where="gateway"),
                {"kind": "decided", "ref": held, "decision": "approved_elsewhere", "waited_ms": 9},
                gateway_outcome(held),
                {"kind": "decided", "ref": relayed, "decision": "accept", "waited_ms": 9},
                gateway_outcome(relayed),
            ],
            ts=int(time.time() * 1000) - 60_000,
        ),
    )
    open_section(page, "Ledger")
    rows = page.locator("#ledger-rows li")
    held_row = rows.filter(has_text=f"call {held}")
    expect(held_row).to_contain_text("decision accept via portal; outcome ok")
    expect(held_row).to_contain_text(
        "asked reported by the gateway, decided written by the vault, outcome written by the vault."
    )
    expect(held_row).to_contain_text("Also decided approved_elsewhere, reported by the gateway.")
    expect(held_row).to_contain_text("Also outcome ok (sent), reported by the gateway.")
    relay_row = rows.filter(has_text=f"call {relayed}")
    expect(relay_row).to_contain_text("decision accept via telegram")
    expect(relay_row).to_contain_text("outcome reported by the gateway")
    expect(relay_row).to_contain_text("Also outcome unknown (relayed), written by the vault.")
    expect(rows.filter(has_text="The chains disagree")).to_have_count(0)
    expect(page.locator("#ledger-vault-only li").filter(has_text=held)).to_have_count(0)


def gateway_outcome(ref: str) -> dict[str, Any]:
    fields = {"outcome": "ok", "detail": "sent", "writes_sent": 1, "writes_unknown": 0}
    return {"kind": "outcome", "ref": ref, **fields}
