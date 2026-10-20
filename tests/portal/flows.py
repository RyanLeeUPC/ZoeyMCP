"""The page's journeys as the portal's script makes them, for the portal tests (M5 design E, F.2).

Each helper sends what ``app.js`` and ``webauthn.js`` send: the same paths and bodies, the session's
header half kept in the page's ``sessionStorage``, the passkey prompts answered by
``tests/fakes/authenticator.py``. A setup code is issued as the socket issues it, on the vault's
loop.
"""

from __future__ import annotations

from collections.abc import Collection
from typing import Any

import httpx

from tests.fakes.authenticator import Kind, SoftAuthenticator, Switch
from tests.fakes.browser import SESSION_KEY, Page
from zoeymcp.portal.routes import Route

from .rig import PortalRig

# A value for each path parameter, so a walk of the route table can send every route.
SAMPLE_PARAMS = {"credential": "github", "flow": "0123456789abcdef", "action": "0123456789abcdef"}
LOGIN_BEGIN = "/api/login/begin"
LOGIN_FINISH = "/api/login/finish"
REDEEM = "/api/setup/redeem"
ENROL_BEGIN = "/api/passkeys/enrol/begin"
ENROL_FINISH = "/api/passkeys/enrol/finish"


def issue(rig: PortalRig, *, reset: bool = False) -> str:
    """A setup code, as ``zoeymcp setup-code [--reset]`` gets one over the socket."""
    code, _ = rig.call(lambda: rig.vault.setup.issue(reset=reset))
    return str(code.reveal())


def keep(page: Page, response: httpx.Response) -> httpx.Response:
    """What the page does with an answer that mints a session: keep its header half."""
    if response.status_code == 200 and "token" in response.json():
        page.storage[SESSION_KEY] = response.json()["token"]
    return response


def redeem(page: Page, code: object) -> httpx.Response:
    return keep(page, page.fetch("POST", REDEEM, json={"code": code}))


def begin_enrol(page: Page, name: str = "laptop") -> dict[str, Any]:
    begun = page.fetch("POST", ENROL_BEGIN, json={"name": name})
    assert begun.status_code == 200, begun.text
    answer: dict[str, Any] = begun.json()
    return answer


def finish_enrol(page: Page, ceremony: str, credential: dict[str, Any]) -> httpx.Response:
    body = {"ceremony": ceremony, "credential": credential}
    response = page.fetch("POST", ENROL_FINISH, json=body)
    if response.status_code == 200:
        page.storage.pop(SESSION_KEY, None)  # the setup session ended with its enrolment
    return response


def enrol(
    page: Page,
    authenticator: SoftAuthenticator,
    *,
    name: str = "laptop",
    kind: Kind | None = None,
    switches: Collection[Switch] = (),
) -> httpx.Response:
    """The setup page's name step: begin, ``create()``, finish."""
    begun = begin_enrol(page, name)
    attestation = authenticator.create(begun["options"], page.origin, kind=kind, switches=switches)
    return finish_enrol(page, begun["ceremony"], attestation.body())


def begin_login(page: Page) -> dict[str, Any]:
    begun = page.fetch("POST", LOGIN_BEGIN, json={})
    assert begun.status_code == 200, begun.text
    answer: dict[str, Any] = begun.json()
    return answer


def finish_login(page: Page, ceremony: str, credential: dict[str, Any]) -> httpx.Response:
    body = {"ceremony": ceremony, "credential": credential}
    return keep(page, page.fetch("POST", LOGIN_FINISH, json=body))


def login(
    page: Page,
    authenticator: SoftAuthenticator,
    *,
    switches: Collection[Switch] = (),
    rp_id: str | None = None,
) -> httpx.Response:
    """The login page's button: begin, ``get()``, finish."""
    begun = begin_login(page)
    assertion = authenticator.get(begun["options"], page.origin, switches=switches, rp_id=rp_id)
    return finish_login(page, begun["ceremony"], assertion.body())


def set_up(
    rig: PortalRig,
    page: Page,
    authenticator: SoftAuthenticator,
    *,
    name: str = "laptop",
    reset: bool = False,
    kind: Kind | None = None,
) -> dict[str, Any]:
    """The whole first visit: a code, its setup session, the enrolment, then the login with the
    new passkey. Returns the enrolled passkey as the enrolment answered it."""
    redeemed = redeem(page, issue(rig, reset=reset))
    assert redeemed.status_code == 200, redeemed.text
    enrolled = enrol(page, authenticator, name=name, kind=kind)
    assert enrolled.status_code == 200, enrolled.text
    signed_in = login(page, authenticator)
    assert signed_in.status_code == 200, signed_in.text
    passkey: dict[str, Any] = enrolled.json()["passkey"]
    return passkey


def prepared_action(page: Page, kind: str, data: dict[str, Any]) -> dict[str, Any]:
    """``POST /api/actions``: the plan's summary and the step-up options."""
    answer = page.fetch("POST", "/api/actions", json={"kind": kind, "data": data})
    assert answer.status_code == 200, answer.text
    held: dict[str, Any] = answer.json()
    return held


def step_up(
    page: Page, authenticator: SoftAuthenticator, kind: str, data: dict[str, Any]
) -> httpx.Response:
    """Prepare an action, answer its passkey prompt and confirm it, as the page's dialog does."""
    held = prepared_action(page, kind, data)
    assertion = authenticator.get(held["options"], page.origin).body()
    body = {"credential": assertion}
    return page.fetch("POST", f"/api/actions/{held['action']}/confirm", json=body)


def connect_by_callback(
    page: Page, authenticator: SoftAuthenticator, credential: str
) -> tuple[dict[str, Any], httpx.Response]:
    """Connect through the portal's callback (M5 design H.6), as the operator's browser does it:
    start (the browser keeps the binding cookie), open the authorization link from the page,
    which the provider sends back to the callback as one cross-site navigation, then the poll
    sees the code returned and the returned confirmation runs with a passkey. The page's
    browser must reach the provider as one of its ``remote`` origins. Returns the start's
    answer and the confirm's."""
    started = page.fetch("POST", f"/api/oauth/{credential}/start", json={})
    assert started.status_code == 200, started.text
    begun: dict[str, Any] = started.json()
    assert begun["callback"] == page.origin, begun
    landed = page.browser.navigate(begun["authorize_url"], initiator=page.origin)
    assert landed.status_code == 200, landed.text
    assert str(landed.request.url).endswith("/callback/received")
    status = page.fetch("GET", f"/api/oauth/flows/{begun['flow']}")
    assert status.json()["stage"] == "returned", status.text
    data = {"credential": credential, "flow": begun["flow"], "returned": True}
    return begun, step_up(page, authenticator, "oauth.complete", data)


def filled(route: Route) -> str:
    """The route's path with a sample value for each parameter."""
    return route.path.format(**SAMPLE_PARAMS)


def status_reason(response: httpx.Response) -> tuple[int, str]:
    return response.status_code, response.json().get("reason", "")
