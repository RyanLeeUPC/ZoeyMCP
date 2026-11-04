"""The portal's page driven as an operator drives it, in the manual items' words (D-222).

Every locator is a role or a label, read as the item reads ("Sign in with a passkey", "Setup
code"): the page ships no test hook. Each helper waits with a web-first assertion, never a
sleep. A setup code is issued as ``zoeymcp setup-code`` gets one, on the vault's loop.
"""

from __future__ import annotations

import re

from playwright.sync_api import Locator, Page, expect

from tests.portal.flows import issue

from .passkeys import CdpAuthenticator
from .stacks import PortalRig

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


def set_up(page: Page, rig: PortalRig, *, name: str = "laptop") -> CdpAuthenticator:
    """The first visit, as item 11 runs it: **I have a setup code**, a fresh code, the passkey's
    name, **Create the passkey**, then **Sign in with the new passkey**. Returns the page's
    authenticator, which holds the new passkey."""
    passkeys = CdpAuthenticator(page)
    open_portal(page, rig.origin)
    press(page, "I have a setup code")
    page.get_by_label("Setup code").fill(issue(rig))
    press(page, "Use this code")
    page.get_by_label("Name for this passkey").fill(name)
    press(page, "Create the passkey")
    expect(page.get_by_text("Passkey enrolled.")).to_be_visible()
    press(page, "Sign in with the new passkey")
    signed_in(page, rig.origin)
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
    """A nav button (**Sessions**, **Passkeys**, ...), then its page."""
    page.get_by_role("navigation").get_by_role("button", name=name, exact=True).click()
    heading(page, name)


def session_cookie(rig: PortalRig) -> str:
    return f"zoeymcp-{rig.portal_port}-session"


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
