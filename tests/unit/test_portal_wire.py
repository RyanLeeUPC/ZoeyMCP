"""What the page posts is what the API takes (M5 design K.4, D.1, M.1; M7 K.2, K.3).

The page parses nothing: it posts the raw WebAuthn fields, base64url-encoded, and fixed bodies.
These tests drive the portal's API in process with ``tests/fakes/authenticator.py``, whose
answers have exactly the fields ``webauthn.js`` posts, and read the bodies ``app.js`` and
``review.js`` send from the scripts themselves, so a field renamed on either side fails here
before any browser is involved.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from tests.fakes.authenticator import Assertion, Attestation, SoftAuthenticator
from zoeymcp.portal.actions import KINDS
from zoeymcp.portal.app import PortalApp, load_static
from zoeymcp.portal.passkeys import Passkeys, new_file
from zoeymcp.portal.routes import ONBOARD_DISCOVER, ROUTES
from zoeymcp.portal.webauthn import ASSERTION_FIELDS, REGISTRATION_FIELDS
from zoeymcp.vault.admin import SetupCodes
from zoeymcp.vault.keys import KeySet

from .test_portal_static import SCRIPTS

ORIGIN = "http://localhost:8081"
KEYS = KeySet.from_master(bytes(range(32)))
STATIC_DIR = Path(__file__).resolve().parents[2] / "src" / "zoeymcp" / "portal" / "static"
# api("POST", "/api/...", { key: value, ... }) in a script, the path a literal or a template
# filled in by fill("/api/...", { ... }).
POSTED = re.compile(
    r"api\(\s*\"POST\",\s*(?:fill\()?\"(/api/[^\"]+)\"(?:,\s*\{[^}]*\}\))?,\s*\{([^}]*)\}",
    re.DOTALL,
)
# prepare("kind", { key: value, ... }, ...) in a script: an action's data.
PREPARED = re.compile(r"prepare\(\s*\"([a-z._]+)\",\s*\{([^}]*)\}", re.DOTALL)
# The connect dialog's data, a paste (H.1) or a code the callback returned (H.6), handed to
# prepareConnect(), which posts it as one kind's.
CONNECTED = re.compile(r"prepareConnect\(\{([^}]*)\}\)")
CONNECT_KIND = re.compile(
    r"async function prepareConnect\(data\) \{.*?api\(\"POST\", \"/api/actions\", "
    r"\{ kind: \"([a-z.]+)\", data: data \}\)",
    re.DOTALL,
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class Page:
    """The portal's own page, as app.js calls the API: same-origin, the header half from
    sessionStorage, the cookie its browser keeps."""

    def __init__(self, client: httpx.AsyncClient) -> None:
        self.client = client
        self.token: str | None = None
        self.cookie: str | None = None

    async def call(self, method: str, path: str, body: Any = None) -> httpx.Response:
        headers = {"Sec-Fetch-Site": "same-origin", "Host": "localhost:8081"}
        if method != "GET":
            headers["Origin"] = ORIGIN
        if self.token is not None:
            headers["X-ZoeyMCP-Session"] = self.token
        if self.cookie is not None:
            headers["Cookie"] = self.cookie
        response = await self.client.request(method, path, json=body, headers=headers)
        # An answer that mints a session sets its cookie; a second run's comparison has a
        # ``token`` member too, its credential's token state (M7 design D.12).
        minted = response.json() if response.content and "set-cookie" in response.headers else {}
        if "token" in minted:
            self.token = response.json()["token"]
            self.cookie = response.headers["set-cookie"].split(";")[0]
        return response


@pytest.fixture
async def page(tmp_path: Path) -> AsyncIterator[tuple[Page, PortalApp]]:
    passkeys = Passkeys(new_file(bytes(32)), KEYS.portal_key, tmp_path / "portal" / "p.json")
    (tmp_path / "portal").mkdir(mode=0o700)
    setup = SetupCodes(tmp_path, KEYS.portal_key)
    app = PortalApp([ORIGIN], static=load_static(), setup=setup, passkeys=passkeys)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=ORIGIN) as client:
        yield Page(client), app


def scripts() -> str:
    return "".join((STATIC_DIR / name).read_bytes().decode("utf-8") for name in SCRIPTS)


def test_the_page_posts_exactly_each_routes_body() -> None:
    """Every POST the page makes sends the keys its route takes, no more and no fewer; M7 K.2's
    routes are review.js's."""
    posted = [(path, set(re.findall(r"(\w+):", keys))) for path, keys in POSTED.findall(scripts())]
    routes = {r.path: r for r in ROUTES if r.method == "POST"}
    assert {path for path, _ in posted} == set(routes)
    for path, keys in posted:
        route = routes[path]
        assert route.body <= keys <= route.body | route.optional, path


def test_the_page_prepares_each_kind_with_its_data(tmp_path: Path) -> None:
    """Every action the page prepares is a kind the portal runs, with the data keys the registry
    takes; and the page prepares every kind the portal runs, M7 K.3's in review.js, M6 J.4's
    tool.clear and step 15a's saves in drift.js, and step 15b's policy.rollback and step 15c's
    connector.limits and client.servers in policy.js (an onboarding's save is a draft's
    policy.save, drift.js's)."""
    script = scripts()
    prepared = PREPARED.findall(script)
    assert prepared
    assert CONNECT_KIND.findall(script) == ["oauth.complete"]
    checked = [("oauth.complete", keys) for keys in CONNECTED.findall(script)]
    shapes = {frozenset(re.findall(r"(\w+):", keys)) for _, keys in checked}
    assert shapes == {
        frozenset({"credential", "flow", "redirect_url"}),
        frozenset({"credential", "flow", "returned"}),
    }
    prepared += checked
    for kind, keys in prepared:
        data = set(re.findall(r"(\w+):", keys))
        assert KINDS[kind].required <= data <= KINDS[kind].required | KINDS[kind].optional, kind
    app = PortalApp([ORIGIN], static=load_static())
    assert {kind for kind, _ in prepared} == app.action_kinds
    assert app.action_kinds <= set(KINDS)
    # A private server's discovery sends what the plain one may, and the tick (TI-3).
    private = [keys for kind, keys in prepared if kind == "onboard.discover_private"]
    discover = ONBOARD_DISCOVER.body | ONBOARD_DISCOVER.optional
    assert [set(re.findall(r"(\w+):", keys)) for keys in private] == [discover | {"allow_private"}]


def test_the_fake_answers_with_the_fields_the_page_posts() -> None:
    authenticator = SoftAuthenticator()
    options = {
        "rp": {"id": "localhost", "name": "ZoeyMCP"},
        "user": {"id": "AAAA", "name": "zoeymcp", "displayName": "x"},
        "challenge": "AAAA",
        "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
        "excludeCredentials": [],
    }
    attestation: Attestation = authenticator.create(options, ORIGIN)
    assertion: Assertion = authenticator.get(
        {"challenge": "AAAA", "rpId": "localhost", "allowCredentials": []}, ORIGIN
    )
    assert set(attestation.body()) == REGISTRATION_FIELDS
    assert set(assertion.body()) == ASSERTION_FIELDS
    # The page's encoding: base64url without padding, as the vault decodes it.
    for value in (*attestation.body().values(), *assertion.body().values()):
        if isinstance(value, str):
            assert re.fullmatch(r"[A-Za-z0-9_-]*", value)


@pytest.mark.anyio
async def test_the_journey_over_the_wire(page: tuple[Page, PortalApp]) -> None:
    client, app = page
    assert app.setup is not None
    code, _ = app.setup.issue()
    redeemed = await client.call("POST", "/api/setup/redeem", {"code": code.reveal()})
    assert redeemed.status_code == 200
    begun = (await client.call("POST", "/api/passkeys/enrol/begin", {"name": "laptop"})).json()
    authenticator = SoftAuthenticator()
    attestation = authenticator.create(begun["options"], ORIGIN)
    body = {"ceremony": begun["ceremony"], "credential": attestation.body()}
    enrolled = await client.call("POST", "/api/passkeys/enrol/finish", body)
    assert enrolled.status_code == 200
    client.token = client.cookie = None  # the page drops the setup session's token
    begun = (await client.call("POST", "/api/login/begin", {})).json()
    assertion = authenticator.get(begun["options"], ORIGIN)
    body = {"ceremony": begun["ceremony"], "credential": assertion.body()}
    signed_in = await client.call("POST", "/api/login/finish", body)
    assert signed_in.status_code == 200
    session = (await client.call("GET", "/api/session")).json()
    fingerprint = enrolled.json()["passkey"]["fingerprint"]
    assert session["credential"] == fingerprint
    listed = (await client.call("GET", "/api/passkeys")).json()["passkeys"]
    assert [(p["fingerprint"], p["this"]) for p in listed] == [(fingerprint, True)]
    # A step-up: prepare, confirm with the assertion only, and cancel another.
    data = {"credential": fingerprint, "name": "desk"}
    prepared = await client.call("POST", "/api/actions", {"kind": "passkey.rename", "data": data})
    assert prepared.status_code == 200, prepared.text
    action = prepared.json()
    assertion = authenticator.get(action["options"], ORIGIN)
    path = f"/api/actions/{action['action']}/confirm"
    confirmed = await client.call("POST", path, {"credential": assertion.body()})
    assert confirmed.status_code == 200, confirmed.text
    assert confirmed.json()["passkey"]["name_shown"] == "desk"
    again = await client.call("POST", "/api/actions", {"kind": "passkey.rename", "data": data})
    cancelled = await client.call("DELETE", f"/api/actions/{again.json()['action']}")
    assert cancelled.json() == {"cancelled": True}
    listed = (await client.call("GET", "/api/sessions")).json()["sessions"]
    assert [s["this"] for s in listed] == [True]
    ended = await client.call("POST", "/api/sessions/end-others", {})
    assert ended.json() == {"ended": 0}
    out = await client.call("POST", "/api/logout", {})
    assert out.headers["clear-site-data"] == '"storage"'
    assert (await client.call("GET", "/api/session")).status_code == 401
