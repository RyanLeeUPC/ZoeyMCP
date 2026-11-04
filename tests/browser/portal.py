"""The portal's page driven as an operator drives it, in the manual items' words (D-222).

Every locator is a role or a label, read as the item reads ("Sign in with a passkey", "Setup
code"): the page ships no test hook. Each helper waits with a web-first assertion, never a
sleep. A setup code is issued as ``zoeymcp setup-code`` gets one, on the vault's loop.
"""

from __future__ import annotations

from playwright.sync_api import Page, expect

from tests.portal.flows import issue

from .passkeys import CdpAuthenticator
from .stacks import PortalRig


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
