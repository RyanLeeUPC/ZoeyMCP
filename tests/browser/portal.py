"""The portal's page driven as an operator drives it, in the manual items' words (D-222).

Every locator is a role or a label, read as the item reads ("Sign in with a passkey", "Setup
code"): the page ships no test hook. Each helper waits with a web-first assertion, never a
sleep. A setup code is issued as ``zoeymcp setup-code`` gets one, on the vault's loop.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Callable
from typing import Any

from playwright.sync_api import Locator, Page, Response, Route, expect

from tests.portal.flows import issue
from tests.portal.test_review import SERVER_URL, gateway_answers

from .passkeys import CdpAuthenticator
from .stacks import PortalRig

# What the page says when the browser's passkey prompt failed with NotAllowedError (app.js's
# BROWSER_TEXT): a cancelled prompt, or none for this address to choose.
NOT_ALLOWED = (
    "The passkey prompt was cancelled or timed out, or no passkey for this address was chosen. "
    "Try again."
)
# The Approvals page's own timers (approvals.js), in milliseconds of page time: its lists, read
# while it is open, and the nav's count, read while signed in.
LISTS_EVERY = 5_000
COUNT_EVERY = 10_000


def open_portal(page: Page, origin: str) -> None:
    """Type the portal's address."""
    page.goto(f"{origin}/")


def heading(page: Page, name: str) -> None:
    """The page shows the section headed ``name``."""
    expect(page.get_by_role("heading", name=name, exact=True)).to_be_visible()


def asks_to_sign_in(page: Page) -> None:
    heading(page, "Sign in")
    expect(page.get_by_role("button", name="Sign in with a passkey", exact=True)).to_be_visible()


def signed_in(page: Page, origin: str) -> None:
    """Home, signed in on ``origin``."""
    heading(page, "Home")
    expect(page.get_by_text(f"Signed in on {origin}.")).to_be_visible()


def press(page: Page, name: str) -> None:
    page.get_by_role("button", name=name, exact=True).click()


def set_up(
    page: Page,
    rig: PortalRig,
    *,
    name: str = "laptop",
    origin: str = "",
    passkeys: CdpAuthenticator | None = None,
) -> CdpAuthenticator:
    """The first visit, as item 11 runs it: **I have a setup code**, a fresh code, the passkey's
    name, **Create the passkey**, then **Sign in with the new passkey**; on the rig's origin
    unless ``origin`` names another of its origins, with a new authenticator unless ``passkeys``
    is the page's already. Returns the page's authenticator, which holds the new passkey."""
    passkeys = passkeys or CdpAuthenticator(page)
    origin = origin or rig.origin
    open_portal(page, origin)
    press(page, "I have a setup code")
    page.get_by_label("Setup code").fill(issue(rig))
    press(page, "Use this code")
    page.get_by_label("Name for this passkey").fill(name)
    press(page, "Create the passkey")
    expect(page.get_by_text("Passkey enrolled.")).to_be_visible()
    press(page, "Sign in with the new passkey")
    signed_in(page, origin)
    return passkeys


def sign_in(page: Page, origin: str) -> None:
    """**Sign in with a passkey** on the login page, answered by the page's authenticator."""
    asks_to_sign_in(page)
    press(page, "Sign in with a passkey")
    signed_in(page, origin)


def sign_out(page: Page) -> None:
    press(page, "Sign out")
    asks_to_sign_in(page)


def open_section(page: Page, name: str) -> None:
    """A nav button (**Sessions**, **Passkeys**, ...), then its page, read afresh.

    A page shows its section only once its reads are done (app.js ``visit``, ``enter``), so its
    heading appearing is the sign they are. A section already shown has its heading up before
    any read, and a click made while the reads are still out is undone when they finish and
    show the section again (CI's Chromium on a118d56: **Open the queue** pressed while Home was
    still being read, then Home shown again). So a section already shown is left for another
    first: **Sessions**, or **Home** when Sessions is the one shown."""
    if page.get_by_role("heading", name=name, exact=True).is_visible():
        _open(page, "Home" if name == "Sessions" else "Sessions")
    _open(page, name)


def _open(page: Page, name: str) -> None:
    page.get_by_role("navigation").get_by_role("button", name=name, exact=True).click()
    heading(page, name)


def session_cookie(rig: PortalRig) -> str:
    return f"zoeymcp-{rig.portal_port}-session"


# --- the review screen (steps 27b, 27c) ----------------------------------------------------------


def server_row(page: Page, label: str) -> Locator:
    """A row of **MCP servers**, by its words (``notes (remote)``, say)."""
    return page.locator("#server-list > li").filter(has_text=label)


def tool_actions(row: Locator) -> Locator:
    """A server card's per-tool buttons (**Allow ... without asking**, **Hold in the vault**),
    folded under **Tool actions (N)**: opened, and open still when the rows are drawn again."""
    folded = row.locator("details.z-tool-actions")
    expect(folded).to_be_visible()
    if folded.get_attribute("open") is None:
        folded.locator("summary").click()
    return folded


def held_review(
    page: Page,
    rig: PortalRig,
    report: dict[str, Any] | Callable[[], dict[str, Any]],
    start: Callable[[], None],
) -> dict[str, Any]:
    """``start`` queues a review (a row's **Review tools** or **Review again**, or a managed
    save's confirm, after which the screen reviews the server again), and the review screen's
    first poll is held until the gateway's side has answered it with ``report``
    (``tests/portal/test_review.py``'s way, on the vault's loop; made then, if it is a function,
    so a save's new head is in it), so that poll draws the review: the job's answer, as the page
    read it.

    The poll is held, not left to the screen's timer: review.js asks once right after queueing,
    and a tick that fires while that ask is still out is skipped, so a paused clock moved on
    once could leave the review undrawn (CI's Chromium did, on 6b9d45c)."""

    def answered(route: Route) -> None:
        gateway_answers(rig, report() if callable(report) else report)
        route.continue_()

    def polled(answer: Response) -> bool:
        return answer.request.method == "GET" and "/api/review/jobs/" in answer.url

    page.route("**/api/review/jobs/*", answered, times=1)
    with page.expect_response(polled) as first:
        start()
    expect(page.locator("#review-body")).to_be_visible()
    read: dict[str, Any] = first.value.json()
    assert read["state"] == "done", read
    return read


# --- fragments, the clipboard and onboarding by URL (step 27c) ---------------------------------


def clipboard(page: Page) -> str:
    """What the browser's clipboard holds now. Windows' clipboard keeps text with CRLF line ends,
    so a paste there is the text line for line; elsewhere it is the text as written."""
    text: str = page.evaluate("navigator.clipboard.readText()")
    return text.replace("\r\n", "\n") if sys.platform == "win32" else text


def confirmed(answer: Response) -> bool:
    return answer.request.method == "POST" and answer.url.endswith("/confirm")


def fragment_text(page: Page) -> str:
    """The fragment as the page shows it, character for character."""
    expect(page.locator("#fragment")).to_be_visible()
    shown = page.locator("#fragment-text").text_content()
    assert shown is not None
    return shown


def shows(page: Page, text: str) -> None:
    """Wait until the fragment shown is ``text`` exactly (``to_have_text`` folds whitespace,
    and two indents differ only in it)."""
    page.wait_for_function(
        "(text) => document.getElementById('fragment-text').textContent === text", arg=text
    )


def copied(page: Page) -> str:
    """**Copy**, then what the clipboard holds."""
    press(page, "Copy")
    expect(page.locator("#status")).to_have_text("Copied the fragment.")
    return clipboard(page)


def register_by_url(page: Page) -> str:
    """**Add a server by URL** with the notes server's URL ("This server is on my network"
    unticked, no client ID), **Discover**, then the plan's **Register and make the YAML** with
    the passkey: fragment 1, as the vault answered it."""
    open_section(page, "MCP servers")
    page.get_by_label("The server's MCP URL").fill(SERVER_URL)
    expect(page.get_by_label("This server is on my network", exact=False)).not_to_be_checked()
    press(page, "Discover")
    expect(page.locator("#plan-title")).to_have_text("What the vault found")
    page.locator("#plan-next").get_by_role("button", name="Register and make the YAML").click()
    expect(confirm_dialog(page)).to_be_visible()
    with page.expect_response(confirmed) as made:
        confirm(page)
    expect(confirm_dialog(page)).to_be_hidden()
    yaml: str = made.value.json()["diff"]["yaml"]
    return yaml


# --- the Approvals queue (step 27b) --------------------------------------------------------------


def open_queue(page: Page) -> None:
    """**Approvals** in the nav (its name carries the count while calls wait), then its page."""
    nav = page.get_by_role("navigation")
    nav.get_by_role("button", name=re.compile(r"^Approvals( \(\d+\))?$")).click()
    heading(page, "Approvals")


def badge(page: Page) -> Locator:
    """The nav's Approvals entry, which says how many calls wait."""
    return page.get_by_role("navigation").get_by_role("button", name=re.compile("^Approvals"))


def waiting(page: Page) -> Locator:
    """The rows under **Waiting**."""
    return page.locator("#approvals-waiting li")


def waiting_row(page: Page, ref: str) -> Locator:
    return waiting(page).filter(has_text=f"{ref}: ")


def decided_row(page: Page, ref: str) -> Locator:
    """``ref``'s row under **Decided recently**."""
    return page.locator("#approvals-decided li").filter(has_text=f"{ref}: ")


def open_request(page: Page, ref: str) -> None:
    """**Open** on ``ref``'s waiting row: the request, whole."""
    waiting_row(page, ref).get_by_role("button", name="Open", exact=True).click()
    title = f"Approval request {ref}: "
    expect(page.get_by_role("heading", name=re.compile("^" + re.escape(title)))).to_be_visible()


def request_text(page: Page) -> Locator:
    """The opened request's text, in its ``pre``."""
    return page.locator("#approvals-text")


def confirm_dialog(page: Page) -> Locator:
    return page.get_by_role("dialog", name="Confirm with your passkey")


def summary(page: Page) -> list[tuple[str, str]]:
    """The confirm dialog's rows, each label with its value, as the page drew them."""
    expect(confirm_dialog(page)).to_be_visible()
    pairs: list[list[str]] = page.locator("#confirm-summary").evaluate(
        "(list) => Array.from(list.querySelectorAll('dt'),"
        " (term) => [term.textContent, term.nextElementSibling.textContent])"
    )
    return [(label, value) for label, value in pairs]


def summary_value(page: Page, label: str) -> Locator:
    """The confirm dialog's value for ``label``: the ``dd`` the page drew after its ``dt``."""
    term = page.locator("#confirm-summary dt").filter(has_text=re.compile(f"^{re.escape(label)}$"))
    return term.locator("xpath=following-sibling::dd[1]")


def close(page: Page) -> None:
    """**Close**, in the dialog: the prepared action is dropped and nothing is confirmed."""
    confirm_dialog(page).get_by_role("button", name="Close", exact=True).click()
    expect(confirm_dialog(page)).to_be_hidden()


def confirm(page: Page) -> None:
    """**Confirm with your passkey**, in the dialog: the page's authenticator answers."""
    confirm_dialog(page).get_by_role("button", name="Confirm with your passkey", exact=True).click()


def dialog_refusal(page: Page) -> Locator:
    """What the dialog says when the vault refused its confirm, or the prompt failed."""
    return confirm_dialog(page).get_by_role("alert")
