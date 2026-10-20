"""What the page posts is what the API takes (M5 design K.4, D.1, M.1).

The page parses nothing: it posts the raw WebAuthn fields, base64url-encoded, and fixed bodies.
These tests drive the portal's API in process with ``tests/fakes/authenticator.py``, whose
answers have exactly the fields ``webauthn.js`` posts, and read the bodies ``app.js`` sends from
the script itself, so a field renamed on either side fails here before any browser is involved.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from tests.fakes.authenticator import Assertion, Attestation, SoftAuthenticator
from zoeymcp.portal.app import PortalApp, load_static
from zoeymcp.portal.passkeys import Passkeys, new_file
from zoeymcp.portal.routes import ROUTES
from zoeymcp.portal.webauthn import ASSERTION_FIELDS, REGISTRATION_FIELDS
from zoeymcp.vault.admin import SetupCodes
from zoeymcp.vault.keys import KeySet

ORIGIN = "http://localhost:8081"
KEYS = KeySet.from_master(bytes(range(32)))
STATIC_DIR = Path(__file__).resolve().parents[2] / "src" / "zoeymcp" / "portal" / "static"
# api("POST", "/api/...", { key: value, ... }) in app.js.
POSTED = re.compile(r"api\(\"POST\",\s*\"(/api/[^\"]+)\",\s*\{([^}]*)\}", re.DOTALL)


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
        if "token" in (response.json() if response.content else {}):
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


def test_the_page_posts_exactly_each_routes_body() -> None:
    """Every POST app.js makes sends the keys its route takes, no more and no fewer."""
    script = (STATIC_DIR / "app.js").read_bytes().decode("utf-8")
    posted = {path: set(re.findall(r"(\w+):", keys)) for path, keys in POSTED.findall(script)}
    routes = {r.path: r for r in ROUTES if r.method == "POST"}
    assert set(posted) == set(routes)
    for path, keys in posted.items():
        route = routes[path]
        assert route.body <= keys <= route.body | route.optional, path


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
    assert session["credential"] == enrolled.json()["passkey"]["fingerprint"]
    listed = (await client.call("GET", "/api/sessions")).json()["sessions"]
    assert [s["this"] for s in listed] == [True]
    ended = await client.call("POST", "/api/sessions/end-others", {})
    assert ended.json() == {"ended": 0}
    out = await client.call("POST", "/api/logout", {})
    assert out.headers["clear-site-data"] == '"storage"'
    assert (await client.call("GET", "/api/session")).status_code == 401
