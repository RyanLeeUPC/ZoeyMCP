"""No endpoint returns a secret (invariant P1; R61 and its two scoped exceptions, D-115).

Each walk takes its routes from the route table, so a route added later is walked too:

- **The admin socket**: every route of ``AdminApp``'s table, with secrets stored and a setup code
  live. Only ``POST /setup-code`` (a new setup code) and ``GET /gateway-key`` (the gateway key)
  may carry a credential, each only its own: the two exceptions R61 records (Q23).
- **The portal**: every route of ``routes.ROUTES``, and the static files, with a full session, a
  setup session and none; with secrets stored through the portal (a static one and an OAuth one),
  a live slot, and a value held by a pending ``secret.put``. No answer carries a value, a setup
  code, the gateway key, or a session half beyond the one answer that mints it.
- **The portal's code**: an AST check finds no reference to ``SetupCodes.issue``, the gateway key
  or a store read of a value anywhere in ``portal/``, so no portal route can reach either
  exception. Under mutmut the source also holds every function's mutants, named with
  ``__mutmut_``; they are left out, as in ``test_refusals.py``.
"""

from __future__ import annotations

import ast
import importlib
import inspect
import pkgutil
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import httpx
import pytest
from starlette.routing import Route as StarletteRoute

import zoeymcp.portal
from tests.fakes.authenticator import SoftAuthenticator
from zoeymcp.portal.app import PortalApp, Secrets, load_static
from zoeymcp.portal.passkeys import Passkeys, new_file
from zoeymcp.portal.routes import ROUTES, STATIC, Route

from .test_admin import BROKER_BINDING, KEYS, AdminRig
from .test_portal_wire import ORIGIN, Page

pytestmark = pytest.mark.anyio

STATIC_VALUE = "p1-static-value-0001"
REFRESH_VALUE = "p1-refresh-value-0001"
CLIENT_ID_VALUE = "p1-client-id-value-0001"
MAIL_VALUE = "p1-mail-pass-value-0001"
LIVE_VALUE = "p1-live-slot-value-0001"
HELD_VALUE = "p1-held-value-0001"
VALUES = (STATIC_VALUE, REFRESH_VALUE, CLIENT_ID_VALUE, MAIL_VALUE, LIVE_VALUE, HELD_VALUE)
# The two answers that carry a credential, and only over the socket (R61, D-115).
EXCEPTIONS = {("POST", "/setup-code"): "setup code", ("GET", "/gateway-key"): "gateway key"}


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def store_values(rig: AdminRig) -> None:
    """A static secret, an OAuth refresh token and client ID, an SMTP password and a live slot."""
    rig.store.put("music-stats", STATIC_VALUE, {"origins": ["https://api.stats.example:443"]})
    rig.store.put("broker-refresh", REFRESH_VALUE, BROKER_BINDING)
    rig.store.put("broker-client-id", CLIENT_ID_VALUE, BROKER_BINDING)
    rig.store.put("mail-pass", MAIL_VALUE, {"smtp": {"host": "smtp.mail.example", "port": 465}})
    rig.store.put("oauth.broker-mcp.live", LIVE_VALUE, BROKER_BINDING)


def carried(text: str, credentials: dict[str, str]) -> set[str]:
    """The kinds of credential ``text`` holds."""
    return {kind for value, kind in credentials.items() if value in text}


# --- the admin socket ---------------------------------------------------------------------------

SOCKET_PARAMS = {
    "name": "music-stats",
    "fingerprint": "0" * 16,
    "flow": "0123456789abcdef",
    "credential": "broker-mcp",
}
SOCKET_BODIES: dict[tuple[str, str], Any] = {
    ("PUT", "/secrets/{name}"): {"value": STATIC_VALUE},
    ("POST", "/setup-code"): {},
    ("POST", "/oauth/{credential}/login"): {},
    ("POST", "/oauth/{credential}/complete"): {
        "flow": "0123456789abcdef",
        "redirect_url": "http://127.0.0.1/callback?code=c&state=s",
    },
    ("POST", "/ledger/reported/restart"): {"dry_run": True},
}


def socket_routes(rig: AdminRig) -> list[tuple[str, str]]:
    """Every method and path template of the socket's table, in its order."""
    walked = []
    for route in rig.admin.app.routes:
        assert isinstance(route, StarletteRoute)
        walked += [(method, route.path) for method in sorted((route.methods or set()) - {"HEAD"})]
    return walked


async def test_no_socket_answer_carries_a_credential_but_the_two_exceptions(
    tmp_path: Path,
) -> None:
    rig = AdminRig(tmp_path)
    store_values(rig)
    code, _ = rig.setup.issue()
    credentials = dict.fromkeys(VALUES, "secret value")
    credentials[code.reveal()] = "setup code"
    credentials[KEYS.gateway_key(1)] = "gateway key"
    answers: list[tuple[tuple[str, str], str]] = []
    walked = socket_routes(rig)
    assert len(walked) == len(set(walked)) >= 19
    for method, template in walked:
        path = template.format(**SOCKET_PARAMS)
        response = await rig.call(method, path, SOCKET_BODIES.get((method, template)))
        answers.append(((method, template), response.text + repr(dict(response.headers))))
        if (method, template) == ("POST", "/setup-code"):
            credentials[response.json()["code"]] = "setup code"
    found = {route: carried(text, credentials) for route, text in answers}
    # The exceptions carry their own credential and nothing else; every other answer none.
    assert {route: kinds for route, kinds in found.items() if kinds} == {
        route: {kind} for route, kind in EXCEPTIONS.items()
    }
    await rig.token_client.aclose()


# --- the portal ---------------------------------------------------------------------------------


class Recording(Page):
    """The page, keeping every answer it receives: body and headers."""

    def __init__(self, client: httpx.AsyncClient, answers: list[str]) -> None:
        super().__init__(client)
        self.answers = answers

    async def call(self, method: str, path: str, body: Any = None) -> httpx.Response:
        response = await super().call(method, path, body)
        self.answers.append(response.text + repr(response.headers.multi_items()))
        return response


async def signed_in(page: Page, app: PortalApp, authenticator: SoftAuthenticator) -> None:
    """The first visit as the page makes it: a code, the enrolment, the login."""
    assert app.setup is not None
    code, _ = app.setup.issue()
    assert (await page.call("POST", "/api/setup/redeem", {"code": code.reveal()})).is_success
    begun = (await page.call("POST", "/api/passkeys/enrol/begin", {"name": "laptop"})).json()
    attestation = authenticator.create(begun["options"], ORIGIN)
    body = {"ceremony": begun["ceremony"], "credential": attestation.body()}
    assert (await page.call("POST", "/api/passkeys/enrol/finish", body)).is_success
    page.token = page.cookie = None
    begun = (await page.call("POST", "/api/login/begin", {})).json()
    body = {
        "ceremony": begun["ceremony"],
        "credential": authenticator.get(begun["options"], ORIGIN).body(),
    }
    assert (await page.call("POST", "/api/login/finish", body)).is_success


async def step_up(
    page: Page, authenticator: SoftAuthenticator, kind: str, data: dict[str, Any]
) -> httpx.Response:
    prepared = await page.call("POST", "/api/actions", {"kind": kind, "data": data})
    assert prepared.is_success, prepared.text
    action = prepared.json()
    assertion = authenticator.get(action["options"], ORIGIN).body()
    path = f"/api/actions/{action['action']}/confirm"
    return await page.call("POST", path, {"credential": assertion})


PORTAL_PARAMS = {"credential": "broker-mcp", "flow": "0123456789abcdef", "action": "0" * 16}
PORTAL_BODIES: dict[str, Any] = {
    "/api/login/finish": {"ceremony": "0" * 16, "credential": {}},
    "/api/setup/redeem": {"code": "AAAA-BBBB-CCCC-DDDD"},
    "/api/passkeys/enrol/begin": {"name": "tablet"},
    "/api/passkeys/enrol/finish": {"ceremony": "0" * 16, "credential": {}},
    "/api/actions": {"kind": "secret.put", "data": {"name": "music-stats", "value": HELD_VALUE}},
    "/api/actions/{action}/confirm": {"credential": {}},
}
# Walked last: they end sessions.
ENDINGS = ("/api/sessions/end-others", "/api/logout")


async def walk(pages: Iterable[Page], routes: Iterable[Route]) -> None:
    for route in routes:
        path = route.path.format(**PORTAL_PARAMS)
        body = PORTAL_BODIES.get(route.path, {}) if route.method == "POST" else None
        for page in pages:
            await page.call(route.method, path, body)


async def test_no_portal_answer_carries_a_value_a_code_a_key_or_another_half(
    tmp_path: Path,
) -> None:
    rig = AdminRig(tmp_path)
    (tmp_path / "portal").mkdir(mode=0o700)
    passkeys = Passkeys(new_file(bytes(32)), KEYS.portal_key, tmp_path / "portal" / "p.json")
    app = PortalApp(
        [ORIGIN],
        static=load_static(),
        setup=rig.setup,
        passkeys=passkeys,
        login=None,
        secrets=Secrets(rig.store, rig.tokens, lambda: rig.policy),
    )
    answers: list[str] = []
    transport = httpx.ASGITransport(app=app)
    clients = [httpx.AsyncClient(transport=transport, base_url=ORIGIN) for _ in range(3)]
    full, setup, anonymous = (Recording(client, answers) for client in clients)
    authenticator = SoftAuthenticator()
    await signed_in(full, app, authenticator)
    # Secrets written through the portal, a live slot, and a value held by a pending action.
    put = await step_up(
        full, authenticator, "secret.put", {"name": "music-stats", "value": STATIC_VALUE}
    )
    assert put.is_success, put.text
    put = await step_up(
        full, authenticator, "secret.put", {"name": "broker-refresh", "value": REFRESH_VALUE}
    )
    assert put.is_success, put.text
    rig.store.put("oauth.broker-mcp.live", LIVE_VALUE, BROKER_BINDING)
    data = {"name": "broker-client-id", "value": HELD_VALUE}
    assert (
        await full.call("POST", "/api/actions", {"kind": "secret.put", "data": data})
    ).is_success
    code, _ = rig.setup.issue()
    assert (await setup.call("POST", "/api/setup/redeem", {"code": code.reveal()})).is_success
    halves = {
        "full": (full.token, full.cookie),
        "setup": (setup.token, setup.cookie),
    }
    # Every route, from every page; the static files; then the routes that end sessions.
    pages = (full, setup, anonymous)
    await walk(pages, [r for r in ROUTES if r.path not in ENDINGS])
    for path in STATIC:
        response = await full.client.get(path, headers={"Host": "localhost:8081"})
        answers.append(response.text + repr(response.headers.multi_items()))
    await walk(pages, [r for path in ENDINGS for r in ROUTES if r.path == path])
    assert len(answers) > 3 * len(ROUTES)
    credentials = dict.fromkeys(VALUES, "secret value")
    credentials[code.reveal()] = "setup code"
    credentials[KEYS.gateway_key(1)] = "gateway key"
    for text in answers:
        assert carried(text, credentials) == set()
    # Each session half is in the one answer that minted it, and in no other.
    for which, (token, cookie) in halves.items():
        assert token is not None
        assert cookie is not None
        value = cookie.split("=", 1)[1]
        assert sum(token in text for text in answers) == 1, which
        assert sum(value in text for text in answers) == 1, which
    for client in clients:
        await client.aclose()
    await rig.token_client.aclose()


# --- the portal's code (D-115) ------------------------------------------------------------------

# What would reach a credential: a setup code's issue, the gateway key or its ratchet, and a
# store or token manager read of a value.
FORBIDDEN_ATTRIBUTES = frozenset(
    {"issue", "gateway_key", "gateway_keys", "get_for_origin", "get_for_oauth", "grant_for"}
)
FORBIDDEN_PATHS = ("/setup-code", "/gateway-key")


def without_mutants(tree: ast.Module) -> ast.Module:
    """``tree`` with every function mutmut wrote (named with ``__mutmut_``) left out."""
    for parent in ast.walk(tree):
        body = getattr(parent, "body", None)
        if isinstance(body, list):
            parent.body = [  # type: ignore[attr-defined]
                child
                for child in body
                if not (
                    isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef)
                    and "__mutmut_" in child.name
                )
            ]
    return tree


def references(tree: ast.Module) -> list[str]:
    """Every reference in ``tree`` to a forbidden attribute, a name with ``gateway`` in it, or
    a string that is one of the two socket paths (a docstring may name them)."""
    found = []
    for node in ast.walk(tree):
        names: list[str] = []
        if isinstance(node, ast.Attribute):
            names.append(node.attr)
            if node.attr in FORBIDDEN_ATTRIBUTES:
                found.append(f".{node.attr}")
        elif isinstance(node, ast.Name):
            names.append(node.id)
        elif isinstance(node, ast.alias):
            names += [node.name, node.asname or ""]
        elif isinstance(node, ast.ImportFrom):
            names.append(node.module or "")
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            found += [path for path in FORBIDDEN_PATHS if node.value.startswith(path)]
        found += [name for name in names if "gateway" in name.lower()]
    return found


def portal_modules() -> list[str]:
    return sorted(
        f"zoeymcp.portal.{info.name}" for info in pkgutil.iter_modules(zoeymcp.portal.__path__)
    )


def test_the_reference_checker_catches_what_it_is_for() -> None:
    hostile = [
        "code, _ = self.setup.issue()",
        "key = keys.gateway_key(1)",
        "ratchet = vault.gateway_keys",
        "from ..vault.gatewaykeys import GatewayKeys",
        "from ..vault import gatewaykeys",
        "path = '/setup-code'",
        "url = f'/gateway-key?x={y}'",
        "secret = store.get_for_origin(name, url)",
        "secret, _ = store.get_for_oauth(name, token_url=url)",
        "grant = await tokens.grant_for(name, upstream)",
    ]
    for source in hostile:
        assert references(ast.parse(source)), source
    assert references(ast.parse("summary = shown(name)\nself.setup.redeem(code)")) == []
    mutated = "def x_f__mutmut_1():\n    return keys.gateway_key(1)\n"
    assert references(without_mutants(ast.parse(mutated))) == []


def test_no_portal_code_reaches_a_setup_code_issue_or_the_gateway_key() -> None:
    modules = portal_modules()
    assert {"zoeymcp.portal.app", "zoeymcp.portal.routes", "zoeymcp.portal.setupcode"} <= set(
        modules
    )
    for name in modules:
        source = inspect.getsource(importlib.import_module(name))
        assert references(without_mutants(ast.parse(source))) == [], name
    for route in ROUTES:
        assert "setup-code" not in route.path
        assert "gateway" not in route.path
