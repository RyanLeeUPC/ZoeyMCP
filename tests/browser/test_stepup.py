"""Step-up with its summary first, the authorization link and the secret field, in a real browser:
manual items 8, 9 and 15 (the lines a browser can run) (M8 design step 27c; D-222).

The real vault and portal on loopback (``tests.portal.rig``), the policy item 9 gives (``demo``,
an OAuth credential at ``example.com``, and its route), the page driven with the browser's own
WebAuthn stack over virtual authenticators, two of them where an item wants two passkeys, its
Content Security Policy and Trusted Types in force and every page watched. ``example.com`` is
never reached: the link's tab is answered by a route of the browser's context. Each test's
docstring names its item and the lines it checks; ``docs/manual-checks.md`` keeps the lines left
by hand.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from playwright.sync_api import BrowserContext, Locator, Page, Route, expect

from zoeymcp.portal.refusals import CATALOGUE

from .portal import (
    NOT_ALLOWED,
    close,
    confirm,
    confirm_dialog,
    dialog_refusal,
    open_section,
    press,
    set_up,
    summary,
)
from .stacks import PortalRig, portal
from .watch import Watch

# Item 9's policy, word for word.
DEMO = {
    "credentials": {
        "demo": {
            "kind": "oauth2",
            "token_url": "https://example.com/token",
            "authorize_url": "https://example.com/authorize",
            "client_id": "manual-check-client",
            "client_auth": "none",
            "rotates": True,
            "scope": "read",
            "refresh_token": "store:demo-refresh",
        }
    },
    "routes": [
        {
            "name": "demo",
            "prefix": "/demo",
            "upstream": "https://example.com",
            "credential": "demo",
            "callers": [{"placeholder": "ph-manual-demo-0001"}],
            "rules": [{"methods": ["GET"], "paths": ["/**"]}],
        }
    ],
}
# A refused request's answer, which the browser itself reports on the console.
REFUSED_400 = r"status of 400"
# Item 8's paste: the default callback address, with another login's state.
FOREIGN = "http://127.0.0.1/callback?code=x&state=wrong"
STATE_MISMATCH = CATALOGUE["state_mismatch"].text
# Item 15's value: a throwaway, so a copy of it anywhere in the page can be searched for.
VALUE = "browser-check-secret-value-0001"


@pytest.fixture
def rig(tmp_path: Path) -> Iterator[PortalRig]:
    with portal(tmp_path, policy=DEMO) as running:
        yield running


def passkey_row(page: Page, name: str) -> Locator:
    return page.locator("#passkey-list > li").filter(has_text=f"{name} (")


def credential_row(page: Page, name: str) -> Locator:
    return page.locator("#credential-list > li").filter(has_text=f"{name} (oauth2)")


def confirms(watch: Watch) -> list[str]:
    """Each step-up confirm the page sent the vault."""
    return [r.url for r in watch.posts() if r.url.endswith("/confirm")]


def connect_dialog(page: Page) -> Locator:
    return page.get_by_role("dialog", name="Connect")


def connect_demo(page: Page) -> None:
    """**Credentials**, then **Connect** on ``demo``: its dialog, with the provider's link. The
    row's own button comes first; its finding ("not connected yet") has one too."""
    open_section(page, "Credentials")
    row = credential_row(page, "demo")
    row.get_by_role("button", name="Connect", exact=True).first.click()
    expect(connect_dialog(page)).to_be_visible()


# --- item 8: step-up shows the summary first -----------------------------------------------------


def test_item_8_a_rename_shows_its_summary_first_and_a_cancelled_prompt_changes_nothing(
    rig: PortalRig, page: Page, watch: Watch
) -> None:
    """Item 8: "With two passkeys enrolled, open **Passkeys**, choose **Rename** on one and give a
    new name. Pass: the dialog shows what the vault will do (the passkey, its name now, the new
    name) before any passkey prompt; choose **Confirm with your passkey** and cancel the
    browser's prompt: the dialog says the prompt was cancelled, **Close** it, and the passkey
    keeps its name (no ``passkey_renamed`` in the log)." The second passkey is enrolled from the
    page on a second authenticator (D-144's "a second authenticator", in virtual form); the
    cancelled prompt is user verification turned off, which fails the browser's ceremony with
    ``NotAllowedError`` as a cancel does, and the page sends the vault no confirm."""
    passkeys = set_up(page, rig)
    laptop = passkeys.authenticator
    open_section(page, "Passkeys")
    page.get_by_label("Name for the new passkey").fill("phone")
    press(page, "Enrol a passkey")
    assert summary(page)[0] == ("Enrol a new passkey named", "phone")
    confirm(page)
    phone = passkeys.add_authenticator("usb")
    passkeys.answering(phone, [laptop])  # the new passkey lives on the second authenticator
    confirm_dialog(page).get_by_role("button", name="Create the new passkey", exact=True).click()
    expect(confirm_dialog(page)).to_be_hidden()
    expect(passkey_row(page, "phone")).to_have_count(1)
    assert len(passkeys.credentials(phone)) == 1
    passkeys.answering(laptop, [phone])
    asserted = passkeys.asserted()
    passkey_row(page, "phone").get_by_role("button", name="Rename", exact=True).click()
    page.get_by_label("New name").fill("tablet")
    page.locator("#rename").get_by_role("button", name="Rename", exact=True).click()
    fingerprint = rig.vault.passkeys.fingerprint(rig.vault.passkeys.document.credentials[1].id)
    assert summary(page) == [
        ("Rename the passkey", fingerprint),
        ("Named now", "phone"),
        ("New name", "tablet"),
        ("It works on", "localhost"),
    ]
    assert passkeys.asserted() == asserted  # no prompt before the summary
    sent = len(confirms(watch))  # the enrolment's
    passkeys.set_user_verified(False, laptop)
    confirm(page)
    expect(dialog_refusal(page)).to_have_text(NOT_ALLOWED)
    assert len(confirms(watch)) == sent  # the failed prompt sent the vault nothing
    close(page)
    open_section(page, "Passkeys")
    expect(passkey_row(page, "phone")).to_have_count(1)
    expect(passkey_row(page, "tablet")).to_have_count(0)
    assert [c.name for c in rig.vault.passkeys.document.credentials] == ["laptop", "phone"]
    assert rig.lines("passkey_renamed") == []


def test_item_8_a_mismatched_paste_is_refused_with_no_prompt(
    rig: PortalRig, page: Page, watch: Watch
) -> None:
    """Item 8's second part: "open **Credentials**, choose **Connect** on ``demo``, paste
    ``http://127.0.0.1/callback?code=x&state=wrong`` and choose **Check the address**. Pass: the
    dialog says the address belongs to another login, and no passkey prompt opens"."""
    passkeys = set_up(page, rig)
    connect_demo(page)
    watch.allow(REFUSED_400, on=rig.origin)  # the prepare's refusal, which the browser reports
    page.get_by_label("2. The address from that tab's address bar").fill(FOREIGN)
    press(page, "Check the address")
    expect(connect_dialog(page).get_by_role("alert")).to_have_text(STATE_MISMATCH)
    expect(confirm_dialog(page)).to_be_hidden()
    assert passkeys.asserted() == 1  # sign-in's only
    assert rig.lines("step_up_confirmed") == []


# --- item 9: the authorization link --------------------------------------------------------------


def test_item_9_the_link_opens_a_tab_with_no_opener_and_no_referrer(
    rig: PortalRig, page: Page, context: BrowserContext, watch: Watch
) -> None:
    """Item 9: "Open **Credentials** and choose **Connect** on ``demo``, then the dialog's link.
    Pass: it opens example.com in a new tab, and in that tab's console ``window.opener`` is
    ``null``; the Network panel shows the request to example.com without a ``Referer`` header.
    Close the tab and choose **Cancel** in the dialog." The provider's page is answered in the
    browser (a route), so nothing leaves the machine; the request is as the browser sent it."""

    def provider(route: Route) -> None:
        route.fulfill(status=200, content_type="text/html", body="<!doctype html><p>sign in</p>")

    watch.answered.add("example.com")
    context.route("https://example.com/**", provider)
    set_up(page, rig)
    connect_demo(page)
    link = page.get_by_role("link", name="Open the provider's sign-in page in a new tab")
    href = link.get_attribute("href")
    assert href is not None
    assert href.startswith("https://example.com/authorize?")
    with context.expect_page() as opened:
        link.click()
    tab = opened.value
    tab.wait_for_load_state()
    assert tab.url == href
    assert tab.evaluate("[window.opener, document.referrer]") == [None, ""]
    [asked] = [request for request in watch.requests if request.url == href]
    assert asked.is_navigation_request()
    assert "referer" not in asked.headers
    tab.close()
    with page.expect_response(lambda answer: answer.request.method == "DELETE") as cancelled:
        connect_dialog(page).get_by_role("button", name="Cancel", exact=True).click()
    assert cancelled.value.status == 200
    expect(connect_dialog(page)).to_be_hidden()
    login = rig.vault.login
    assert rig.call(lambda: login._flows.owner_of("demo")) is None  # the sign-in it started


# --- item 15: the secret field -------------------------------------------------------------------


def test_item_15_a_secret_is_masked_and_the_page_keeps_no_copy(rig: PortalRig, page: Page) -> None:
    """Item 15's lines a browser can run: "Sign in, open **Secrets**, enter a name and a value,
    choose **Set the secret**, confirm with the passkey. Pass: the value shows as dots while
    typed (in Chrome, Edge and Safari ...); after the confirm the value field is empty; the
    page's elements (developer tools, Elements) hold no copy of it." Whether a password manager
    offers to save it stays by hand: an automated browser shows no password manager."""
    passkeys = set_up(page, rig)
    open_section(page, "Secrets")
    field = page.get_by_label("Value (cleared from this page once sent, whatever the answer)")
    assert field.evaluate("(element) => getComputedStyle(element).webkitTextSecurity") == "disc"
    page.get_by_label("Name (NAME in the policy's store:NAME)").fill("browser-check")
    field.fill(VALUE)
    page.get_by_label("Origins it may be sent to", exact=False).fill("https://x.example")
    press(page, "Set the secret")
    expect(confirm_dialog(page)).to_be_visible()
    expect(field).to_have_value("")  # emptied once the prepare was sent, before any prompt
    assert passkeys.asserted() == 1
    confirm(page)
    expect(confirm_dialog(page)).to_be_hidden()
    expect(page.get_by_text("Secret stored, ")).to_be_visible()
    expect(field).to_have_value("")
    secrets = rig.app.secrets
    assert secrets is not None
    assert "browser-check" in secrets.store.names()
    assert VALUE not in page.content()
    held: list[str] = page.evaluate(
        "Array.from(document.querySelectorAll('input, textarea'), (field) => field.value)"
    )
    assert [value for value in held if VALUE in value] == []
    assert VALUE not in page.evaluate("JSON.stringify(Object.entries(sessionStorage))")
