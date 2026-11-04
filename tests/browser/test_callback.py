"""The OAuth callback in a real browser: manual items 13 and 14, and 18 (the callback of a client
the vault registered) (M8 design step 27c; D-222).

The real vault and portal on loopback (``tests.portal.rig``) with the policy of
``tests/portal/test_callback.py``: ``notes`` registered with its callback address on the
portal's origin. The fake provider (``FakeAuthServer``) is served over https on loopback as
``auth.notes.example`` (``engines.PROVIDER``, a certificate the browser trusts), a different site
from the portal's, so the authorization link opens the provider's own site and its redirect comes
back to the portal as one cross-site navigation, as a real provider's does; the vault's token
exchange reaches the same fake in process. The page runs with the browser's own WebAuthn stack
over a virtual authenticator, its Content Security Policy and Trusted Types in force, every page
watched; the callback's request headers are read as the browser sent them. Each test's docstring
names its item and the lines it checks; ``docs/manual-checks.md`` keeps the lines left by hand
(the history list's entry, and the https callback address, which needs a provider client of
one's own).
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
import pytest
from playwright.sync_api import BrowserContext, Locator, Page, Request, Response, expect

from tests.acceptance.tls import ProviderCA
from tests.fakes.harness import serve
from tests.portal.test_callback import CHECK, callback_policy
from tests.portal.test_oauth import Providers, providers, store
from tests.portal.test_review import poller
from tests.unit.test_review_choices import large
from zoeymcp.common.yamlload import load_mapping
from zoeymcp.portal.refusals import CATALOGUE
from zoeymcp.vault import netclient

from .engines import PROVIDER
from .portal import (
    confirm,
    confirm_dialog,
    copied,
    held_review,
    open_section,
    press,
    register_by_url,
    server_row,
    set_up,
    shows,
    summary,
)
from .stacks import Clock, Onboarding, PortalRig, onboarding, portal
from .watch import Watch

# The pages the callback answers (src/zoeymcp/portal/static/callback-*.html), by their words.
RECEIVED = "The provider sent this sign-in back to the portal. Nothing is stored yet."
REFUSED = CATALOGUE["callback_not_taken"].text
STATE_MISMATCH = CATALOGUE["state_mismatch"].text
# A refused request's answer, which the browser itself reports on the console.
REFUSED_400 = r"status of 400"
# The connect dialog's poll of its sign-in (app.js), in milliseconds of page time.
POLL_EVERY = 2_000


@dataclass
class World:
    rig: PortalRig
    fakes: Providers
    clock: Clock
    ca: ProviderCA
    provider: str  # the provider's origin, as the browser reaches it

    @property
    def address(self) -> str:
        return f"{self.rig.origin}/oauth/callback/notes"

    def answer_of(self, authorize_url: str) -> str:
        """Where the provider sends an approval of ``authorize_url``, not followed: the
        code-bearing callback address, as a second approval of the link gives it."""
        parts = urlsplit(authorize_url)
        with httpx.Client(verify=self.ca.client_context()) as client:
            got = client.get(
                f"https://127.0.0.1:{parts.port}{parts.path}?{parts.query}",
                headers={"host": parts.netloc},
                extensions={"sni_hostname": PROVIDER},
            )
        assert got.status_code == 302, got.text
        location: str = got.headers["location"]
        return location


def ported(provider: str) -> Callable[[str], dict[str, Any]]:
    """``tests/portal/test_callback.py``'s policy for the portal's origin, ``notes``'s
    endpoints at ``provider`` (its issuer as it was: the answers' ``iss``)."""

    def made(origin: str) -> dict[str, Any]:
        document = callback_policy(origin)
        notes = document["credentials"]["notes"]
        notes["authorize_url"] = f"{provider}/authorize"
        notes["token_url"] = f"{provider}/token"
        return document

    return made


@contextmanager
def a_world(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    ca: ProviderCA,
    tls: tuple[Path, Path],
    *,
    consent: bool = False,
) -> Iterator[World]:
    """The providers' fakes, ``notes``'s served over https at ``engines.PROVIDER`` for the
    browser (with ``consent``, its Approve page first) and reached in process by the vault's
    token client; the rig on a clock the test moves (the callback's rate bucket refills with
    it)."""
    fakes = providers()
    fakes.notes.consent = consent
    monkeypatch.setattr(
        netclient,
        "token_client",
        lambda *_: httpx.AsyncClient(transport=httpx.ASGITransport(app=fakes.app())),
    )
    clock = Clock()
    with serve(fakes.notes.app(), tls=tls) as served:
        provider = f"https://{PROVIDER}:{urlsplit(served).port}"
        with portal(tmp_path, policy=ported(provider), clock=clock) as rig:
            fakes.notes.registered_redirect = f"{rig.origin}/oauth/callback/notes"
            yield World(rig, fakes, clock, ca, provider)


@pytest.fixture
def world(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tls_ca: ProviderCA,
    provider_tls: tuple[Path, Path],
) -> Iterator[World]:
    with a_world(tmp_path, monkeypatch, tls_ca, provider_tls) as found:
        yield found


@pytest.fixture
def consenting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tls_ca: ProviderCA,
    provider_tls: tuple[Path, Path],
) -> Iterator[World]:
    with a_world(tmp_path, monkeypatch, tls_ca, provider_tls, consent=True) as found:
        yield found


@pytest.fixture
def boarding(tmp_path: Path, provider_tls: tuple[Path, Path]) -> Iterator[Onboarding]:
    """Item 17's stack: onboarding by URL, the provider registering clients; and a gateway's
    poll waiting, so a review can be queued."""
    with onboarding(tmp_path, provider_tls) as found:
        poller(found.rig)
        yield found


def connect_dialog(page: Page) -> Locator:
    return page.get_by_role("dialog", name="Connect")


def credential_row(page: Page, name: str) -> Locator:
    return page.locator("#credential-list > li").filter(has_text=f"{name} (oauth2)")


def connect(page: Page, name: str = "notes") -> Locator:
    """**Credentials**, then **Connect** on ``name`` (the row's own button, before its
    finding's): the dialog, and its link to the provider."""
    open_section(page, "Credentials")
    credential_row(page, name).get_by_role("button", name="Connect", exact=True).first.click()
    expect(connect_dialog(page)).to_be_visible()
    return page.get_by_role("link", name="Open the provider's sign-in page in a new tab")


def approved(context: BrowserContext, link: Locator, *, consent: bool = False) -> Page:
    """The link opened in a new tab, and (with ``consent``) **Approve** on the provider's page:
    the tab, once the provider sent it back to the portal and the portal moved it on."""
    with context.expect_page() as opened:
        link.click()
    tab = opened.value
    if consent:
        tab.get_by_role("button", name="Approve", exact=True).click()
    tab.wait_for_url("**/callback/received")
    expect(tab.get_by_text(RECEIVED)).to_be_visible()
    return tab


def callback_request(watch: Watch, world: World | Onboarding) -> Request:
    """The one request the browser sent to notes's callback address."""
    address = f"{world.rig.origin}/oauth/callback/notes?"
    [sent] = [r for r in watch.requests if r.url.startswith(address)]
    return sent


def cookies_sent(request: Request) -> dict[str, str]:
    """The cookies on ``request`` as the browser sent them, by name."""
    sent = request.all_headers().get("cookie", "")
    pairs = [part.strip().partition("=") for part in sent.split(";") if part.strip()]
    return {name: value for name, _, value in pairs}


def asked_back(page: Page) -> None:
    """The connect dialog's next poll (page time moved on once), which finds the sign-in back
    and prepares its confirm: the passkey's dialog. No poll is out before it: the page's clock
    hasn't moved since the dialog opened."""
    page.clock.run_for(POLL_EVERY)
    expect(confirm_dialog(page)).to_be_visible()


# --- item 13: the callback -----------------------------------------------------------------------


def test_item_13_the_provider_sends_the_tab_back_and_a_passkey_connects(
    world: World, page: Page, context: BrowserContext, watch: Watch
) -> None:
    """Item 13: "On **Credentials**, choose **Connect** on ``notes``: the dialog says the provider
    sends the tab back to the portal. Open the link and approve. Pass: the request to
    ``/oauth/callback/notes`` carries ``Sec-Fetch-Site: cross-site``, ``Sec-Fetch-Mode:
    navigate`` and ``Sec-Fetch-Dest: document``, the cookie ``zoeymcp-8081-cb``...; the tab ends
    on ``/callback/received``, and the back button doesn't return to the address that held the
    code ...; within a few seconds the portal's tab asks for the passkey, its summary saying where
    and when the sign-in came back and 'Confirm only if you have just finished approving in the
    provider's tab; if you haven't, cancel.'; confirm, and **Credentials** shows ``notes``
    connected." The provider answers at once (no consent page), so the session cookie's line is
    the consent test's."""
    rig = world.rig
    passkeys = set_up(page, rig)
    link = connect(page)
    expect(page.locator("#connect-callback-text")).to_be_visible()
    expect(page.locator("#connect-paste-text")).to_be_hidden()
    tab = approved(context, link)
    sent = callback_request(watch, world)
    assert "code=fake-notes-code-" in sent.url
    headers = sent.all_headers()
    assert (headers["sec-fetch-site"], headers["sec-fetch-mode"], headers["sec-fetch-dest"]) == (
        "cross-site",
        "navigate",
        "document",
    )
    assert f"zoeymcp-{rig.portal_port}-cb" in cookies_sent(sent)
    tab.go_back()
    assert "code=" not in tab.url  # the code's address was never an entry to go back to
    assert world.fakes.notes.exchanges == 0  # held, not exchanged, until the passkey
    asked_back(page)
    shown = dict(summary(page))
    assert shown["With"] == "the sign-in the provider sent back to the portal"
    assert shown["It came back to"].startswith(f"{rig.origin} at ")
    assert shown["Before you confirm"] == CHECK
    assert passkeys.asserted() == 1  # no prompt before the summary
    confirm(page)
    expect(confirm_dialog(page)).to_be_hidden()
    expect(page.get_by_text("Connected notes: ")).to_be_visible()
    expect(credential_row(page, "notes")).to_contain_text("notes (oauth2): ok")
    assert world.fakes.notes.exchanges == 1
    assert store(rig).entry("notes-refresh") is not None
    assert rig.logged("step_up_confirmed", lambda line: line["action"] == "oauth.complete")


def test_item_13_after_a_consent_page_the_callback_carries_no_session_cookie(
    consenting: World, page: Page, context: BrowserContext, watch: Watch
) -> None:
    """Item 13's ``--consent`` part: the provider shows an Approve page first, whose button posts
    and is answered with the redirect, as a real provider's consent screen is, so the navigation
    back starts on the provider's site. Pass: the callback request carries ``zoeymcp-8081-cb``
    and no ``zoeymcp-8081-session`` cookie, ``Sec-Fetch-Site: cross-site``; confirmed with the
    passkey, ``notes`` is connected."""
    world = consenting
    rig = world.rig
    set_up(page, rig)
    tab = approved(context, connect(page), consent=True)
    sent = callback_request(watch, world)
    assert sent.all_headers()["sec-fetch-site"] == "cross-site"
    assert set(cookies_sent(sent)) == {f"zoeymcp-{rig.portal_port}-cb"}
    tab.close()
    asked_back(page)
    confirm(page)
    expect(page.get_by_text("Connected notes: ")).to_be_visible()
    assert world.fakes.notes.exchanges == 1


def test_item_13_the_address_opened_in_another_browser_is_refused_while_the_dialog_waits(
    world: World, page: Page, other_context: BrowserContext, watch: Watch
) -> None:
    """Item 13's last part: "**Connect** again, approve, and before the tab is redirected copy the
    callback address ...; open that address in a second browser profile. Pass: the refused page
    ('The portal didn't take this sign-in.'), the address intact in that profile's address bar,
    and the first browser's dialog still waiting." The second profile has no binding cookie."""
    rig = world.rig
    set_up(page, rig)
    href = connect(page).get_attribute("href")
    assert href is not None
    address = world.answer_of(href)
    elsewhere = other_context.new_page()
    watch.allow(REFUSED_400, on=world.address)
    world.clock.advance(30)  # a full rate bucket for the callback
    landed = elsewhere.goto(address)
    assert landed is not None
    assert landed.status == 400
    expect(elsewhere.get_by_text(REFUSED)).to_be_visible()
    assert elsewhere.url == address
    # The dialog's next poll finds its sign-in still waiting: no alert, no passkey's dialog. No
    # poll is out before it: the page's clock hasn't moved since the dialog opened.
    with page.expect_response(
        lambda r: r.request.method == "GET" and "/api/oauth/flows/" in r.url
    ) as polled:
        page.clock.run_for(POLL_EVERY)
    assert polled.value.json()["stage"] == "pending"
    expect(connect_dialog(page)).to_be_visible()
    expect(connect_dialog(page).get_by_role("alert")).to_be_hidden()
    expect(confirm_dialog(page)).to_be_hidden()
    assert world.fakes.notes.exchanges == 0


# --- item 14: a stale callback address -----------------------------------------------------------


def test_item_14_a_stale_callback_address_is_refused_typed_or_pasted(
    world: World, page: Page, context: BrowserContext, watch: Watch
) -> None:
    """Item 14: "Take a callback address from item 13 whose login has ended (confirmed ...) and
    type or paste it into the address bar. Pass: the request carries ``Sec-Fetch-Site: none``;
    the refused page shows, with the address intact. Start a new **Connect** and paste that
    address into its dialog. Pass: refused as belonging to another login (``state_mismatch``)
    ..., with no passkey prompt"."""
    rig = world.rig
    passkeys = set_up(page, rig)
    approved(context, connect(page)).close()
    address = callback_request(watch, world).url
    asked_back(page)
    confirm(page)
    expect(page.get_by_text("Connected notes: ")).to_be_visible()
    asserted = passkeys.asserted()
    typed = context.new_page()
    watch.allow(REFUSED_400, on=rig.origin)
    world.clock.advance(30)  # a full rate bucket for the callback
    landed = typed.goto(address)  # what a typed address is: no initiator
    assert landed is not None
    assert landed.status == 400
    assert landed.request.all_headers()["sec-fetch-site"] == "none"
    expect(typed.get_by_text(REFUSED)).to_be_visible()
    assert typed.url == address
    typed.close()
    connect(page)
    page.get_by_label("2. The address from that tab's address bar").fill(address)
    page.get_by_role("button", name="Check the address", exact=True).click()
    expect(connect_dialog(page).get_by_role("alert")).to_have_text(STATE_MISMATCH)
    expect(confirm_dialog(page)).to_be_hidden()
    assert passkeys.asserted() == asserted
    assert world.fakes.notes.exchanges == 1  # the first connect's only


# --- item 18: the callback of a client the vault registered --------------------------------------


def test_item_18_a_registered_clients_callback_connects_and_the_review_queues_itself(
    boarding: Onboarding, page: Page, context: BrowserContext, watch: Watch
) -> None:
    """Item 18: item 17's onboarding, whose provider offers registration, "the plan's redirect
    address is this origin's ``/oauth/callback/<credential>``. Register (a passkey), commit
    fragment 1 ..., reload ..., then choose **Connect** on the server's row. Pass: as item 13's
    first part (the provider sends the tab back to the portal, which asks for the passkey), and
    once connected the page queues the server's review by itself" (a gateway's poll waits here,
    so the review runs). Then item 17's last line: **Generate**'s fragment 2, copied, is the
    shown text exactly."""
    rig = boarding.rig
    context.grant_permissions(["clipboard-read", "clipboard-write"], origin=rig.origin)
    passkeys = set_up(page, rig)
    fragment = register_by_url(page)
    notes = load_mapping(fragment)["credentials"]["notes"]
    assert notes["redirect_uri"] == f"{rig.origin}/oauth/callback/notes"
    assert [seen.path for seen in boarding.auth.registrations] == ["/register"]
    boarding.commit(fragment)
    open_section(page, "MCP servers")
    row = server_row(page, "notes (remote)")
    expect(row).to_contain_text("in the policy, not connected yet")
    row.get_by_role("button", name="Connect", exact=True).click()
    expect(connect_dialog(page)).to_be_visible()
    expect(page.locator("#connect-callback-text")).to_be_visible()
    link = page.get_by_role("link", name="Open the provider's sign-in page in a new tab")
    tab = approved(context, link)
    assert callback_request(watch, boarding).all_headers()["sec-fetch-site"] == "cross-site"
    tab.close()
    asked_back(page)
    assert dict(summary(page))["Before you confirm"] == CHECK
    asserted = passkeys.asserted()
    held_review(page, rig, large(), lambda: confirm(page))
    expect(page.locator("#review-title")).to_have_text("Review of notes (remote)")
    assert passkeys.asserted() == asserted + 1  # the connect's passkey; the review needs none
    [queued] = rig.lines("review_requested")
    assert (queued["server"], queued["owner"]) == ("notes", "portal")
    assert rig.logged("step_up_confirmed", lambda line: line["action"] == "oauth.complete")
    press(page, "Select suggested")

    def diffed(answer: Response) -> bool:
        return answer.request.method == "POST" and answer.url.endswith("/diff")

    with page.expect_response(diffed) as made:
        page.locator("#review-generate").click()
    second: str = made.value.json()["diff"]["yaml"]
    expect(page.locator("#fragment-title")).to_have_text("Fragment 2 of 2")
    shows(page, second)
    assert copied(page) == second
