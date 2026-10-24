"""No endpoint returns a secret (invariant P1; R61 and its four scoped exceptions, D-115, DD-14,
DD-4).

Each walk takes its routes from the route table, so a route added later is walked too:

- **The admin socket**: every route of ``AdminApp``'s table, with secrets stored and a setup code
  live, a done review job (M7 F.2), and an onboarding whose given client secret was stored
  through the socket (M7 D.7);
  and again once a registration's answer brought a secret, a registration access token and a
  URI (D.4), which no answer carries.
  Only ``POST /setup-code`` (a new setup code), ``GET /gateway-key`` (the gateway key) and
  ``GET /egress-key`` (the egress role's key, M7 G.3) may carry a credential, each only its own:
  the exceptions R61 records (Q23, DD-14). A token ``secret set --generate`` made (M7 C.2) is in
  no answer, the one that made it included. With a managed policy (M6 design O.6, step 14a),
  every ``/policy`` route of the table is walked once a client's literal token was seeded and
  an import and its plan were made: the literal token is in no answer, and the token's hash and
  a caller's placeholder only in ``GET /policy/export``, R61's fourth scoped exception (DD-4).
- **The portal**: every route of ``routes.ROUTES``, and the static files, with a full session, a
  setup session and none; with secrets stored through the portal (a static one and an OAuth one),
  a live slot, a value held by a pending ``secret.put``, a given client secret stored through
  ``onboard.register`` (M7 K.3) and a done review job of the portal's (F.6). Its health,
  OAuth list, connect and policy routes read the same store, token manager, logins and policy,
  and its ledger a copy.
  No answer carries a value, a setup code, the gateway key, the egress key, or a session half
  beyond the one answer that mints it.
- **The portal's code**: an AST check finds no reference to ``SetupCodes.issue``, the gateway key,
  the egress key or a store read of a value anywhere in ``portal/``, so no portal route can reach
  an exception. Under mutmut the source also holds every function's mutants, named with
  ``__mutmut_``; they are left out, as in ``test_refusals.py``.
"""

from __future__ import annotations

import ast
import base64
import importlib
import inspect
import json
import pkgutil
from collections.abc import Iterable, Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final

import httpx
import pytest
from starlette.routing import Route as StarletteRoute

import zoeymcp.portal
from tests.fakes.authenticator import SoftAuthenticator
from tests.unit import onboard_model
from zoeymcp.common.policy.schema import GatewayLimits, hash_token
from zoeymcp.portal.app import Ledger, PortalApp, Secrets, load_static
from zoeymcp.portal.passkeys import Passkeys, new_file
from zoeymcp.portal.routes import ROUTES, STATIC, Route
from zoeymcp.vault.admin import AdminApp, HealthReader
from zoeymcp.vault.oauth.login import LoginService
from zoeymcp.vault.reportstore import ReportStore
from zoeymcp.vault.reviewjobs import Job, JobTable, Owner, ServerKind, read_result

from .test_admin import BROKER_BINDING, KEYS, AdminRig
from .test_admin_policy import YAML, PolicyRig
from .test_cli_policy import AGENT2, TOKEN, managed_text
from .test_portal_wire import ORIGIN, Page
from .test_reviewreport import unclassified

pytestmark = pytest.mark.anyio

STATIC_VALUE = "p1-static-value-0001"
REFRESH_VALUE = "p1-refresh-value-0001"
CLIENT_ID_VALUE = "p1-client-id-value-0001"
MAIL_VALUE = "p1-mail-pass-value-0001"
LIVE_VALUE = "p1-live-slot-value-0001"
HELD_VALUE = "p1-held-value-0001"
VALUES = (STATIC_VALUE, REFRESH_VALUE, CLIENT_ID_VALUE, MAIL_VALUE, LIVE_VALUE, HELD_VALUE)
# The answers that carry a credential, and only over the socket (R61, D-115, DD-14).
EXCEPTIONS = {
    ("POST", "/setup-code"): "setup code",
    ("GET", "/gateway-key"): "gateway key",
    ("GET", "/egress-key"): "egress key",
}
# The fourth: the host's export holds placeholders and client token hashes (M6 design H.6, DD-4).
POLICY_EXCEPTION = ("GET", "/policy/export")
# A caller's placeholder in the example policy's stats route.
PLACEHOLDER = "ph-agent1-stats-4c1f9b27"


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
    "server": "notes",
    "name": "music-stats",
    "fingerprint": "0" * 16,
    "flow": "0123456789abcdef",
    "credential": "broker-mcp",
    "revision": "1",
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
    ("POST", "/onboard/discover"): onboard_model.confidential(),
    ("POST", "/onboard/{onboarding}/register"): {},
    ("POST", "/onboard/{onboarding}/fragment"): {"indent": 2},
    ("POST", "/review/jobs/{job}/diff"): {"include": [], "allow": [], "approve": []},
}


class Reviews:
    """Review jobs with one done for the CLI and one for the portal, as the vault's own queue
    answers them: the review routes answer its report (M7 design F.2)."""

    DIGEST = "sha256:" + "d" * 64
    SERVERS: Final[Mapping[str, ServerKind]] = MappingProxyType({"notes": "remote"})

    def __init__(self) -> None:
        self.table = JobTable(lambda: 1000.0, started=0.0)
        self.table.poll_began(frozenset({"review", "clear"}))
        self.done = self.finished("cli")
        self.portal_done = self.finished("portal")

    def finished(self, owner: Owner) -> Job:
        queued = self.table.queue("notes", owner, self.DIGEST, self.SERVERS)
        assert isinstance(queued, Job)
        self.table.claim(self.DIGEST)
        body = {"v": 1, "job": queued.id, "server": "notes", "report": unclassified("list_notes")}
        return self.table.post(read_result(body, GatewayLimits())).job

    async def queue_review(self, server: str, owner: Owner, *, fresh: bool = False) -> Job:
        queued = self.table.queue(server, owner, self.DIGEST, self.SERVERS, fresh=fresh)
        assert isinstance(queued, Job)
        return queued

    async def queue_clear(self, server: str, owner: Owner) -> Job:
        queued = self.table.queue(server, owner, self.DIGEST, self.SERVERS, work="clear")
        assert isinstance(queued, Job)
        return queued

    async def review_job(self, job_id: str, owner: Owner, *, wait: float = 0) -> Job:
        return self.table.get(job_id, owner)


def socket_routes(rig: AdminRig | PolicyRig) -> list[tuple[str, str]]:
    """Every method and path template of the socket's table, in its order."""
    walked = []
    for route in rig.admin.app.routes:
        assert isinstance(route, StarletteRoute)
        walked += [(method, route.path) for method in sorted((route.methods or set()) - {"HEAD"})]
    return walked


async def test_no_socket_answer_carries_a_credential_but_the_exceptions(
    tmp_path: Path,
) -> None:
    reviews = Reviews()
    rig = AdminRig(tmp_path, onboard=True, reviews=reviews)
    store_values(rig)
    code, _ = rig.setup.issue()
    discovered = await rig.call("POST", "/onboard/discover", onboard_model.confidential())
    onboarding = discovered.json()["onboarding"]
    secret = {"client_secret": onboard_model.GIVEN_SECRET}
    stored = await rig.call("POST", f"/onboard/{onboarding}/register", secret)
    assert stored.status_code == 200, stored.text
    params = {**SOCKET_PARAMS, "onboarding": onboarding, "job": reviews.done.id}
    credentials = dict.fromkeys((*VALUES, onboard_model.GIVEN_SECRET), "secret value")
    credentials[code.reveal()] = "setup code"
    credentials[KEYS.gateway_key(1)] = "gateway key"
    credentials[KEYS.egress_key(1)] = "egress key"
    answers: list[tuple[tuple[str, str], str]] = []
    walked = socket_routes(rig)
    assert len(walked) == len(set(walked)) >= 24
    assert ("GET", "/egress-key") in walked
    assert ("DELETE", "/onboard/{onboarding}") in walked
    assert ("GET", "/review/jobs/{job}") in walked
    assert ("POST", "/review/jobs/{job}/diff") in walked
    for method, template in walked:
        path = template.format(**params)
        response = await rig.call(method, path, SOCKET_BODIES.get((method, template)))
        answers.append(((method, template), response.text + repr(dict(response.headers))))
        if (method, template) == ("POST", "/setup-code"):
            credentials[response.json()["code"]] = "setup code"
        if template.endswith("/clear"):
            # A clear job queued (M6 design J.4): its report comes once the gateway runs it.
            assert response.json()["state"] == "queued", response.text
        elif template.startswith("/review") and not template.endswith("/diff"):
            # The done job's report, answered whole (and handed back again on a queue call).
            assert response.json()["report"]["server"] == "notes", response.text
    answers.append((("POST", "/onboard/discover"), discovered.text + stored.text))
    found = {route: carried(text, credentials) for route, text in answers}
    # The exceptions carry their own credential and nothing else; every other answer none.
    assert {route: kinds for route, kinds in found.items() if kinds} == {
        route: {kind} for route, kind in EXCEPTIONS.items()
    }
    await rig.token_client.aclose()


async def test_no_socket_answer_carries_what_a_registration_issued(tmp_path: Path) -> None:
    """D.4, X19 (step 11): every route walked once a registration's answer brought a client
    secret, a registration access token and a URI: none carries any of them."""
    rig = AdminRig(tmp_path, onboard=True, register=onboard_model.planted)
    discovered = await rig.call("POST", "/onboard/discover", {"url": onboard_model.SERVER_URL})
    onboarding = discovered.json()["onboarding"]
    registered = await rig.call("POST", f"/onboard/{onboarding}/register", {})
    assert registered.status_code == 200, registered.text
    planted = (
        onboard_model.DCR_SECRET,
        onboard_model.REGISTRATION_TOKEN,
        onboard_model.REGISTRATION_URI,
    )
    credentials = dict.fromkeys(planted, "registration")
    answers = [discovered.text + registered.text]
    params = {**SOCKET_PARAMS, "onboarding": onboarding, "job": "unknown-job"}
    for method, template in socket_routes(rig):
        path = template.format(**params)
        response = await rig.call(method, path, SOCKET_BODIES.get((method, template)))
        answers.append(response.text + repr(dict(response.headers)))
    assert [text for text in answers if carried(text, credentials)] == []
    await rig.token_client.aclose()


GENERATED = b"p1-generated-bridge-token-000001"


def edited(first: str, data: Mapping[str, Any]) -> bytes:
    """An edited export: its header line, then the document (JSON is YAML)."""
    return (first + "\n" + json.dumps(data) + "\n").encode()


async def test_no_policy_answer_carries_a_policy_secret_but_the_export(tmp_path: Path) -> None:
    """O.6, DD-4: every /policy route of the socket's table, walked on a managed vault seeded
    with a literal client token, after an import that removed that client: no answer carries
    the literal token, and only the export (of revision 1, which has the client) carries its
    hash and a caller's placeholder. The import and the rollback are planned for real, each
    bringing the client back with its grant, so their plans are walked, not a refusal."""
    rig = PolicyRig(tmp_path, managed_text(), K="v")
    assert AGENT2 in managed_text()
    export = (await rig.call("GET", "/policy/export")).json()["export"]
    first = export.splitlines()[0]
    seeded = rig.document()
    data = rig.document()
    del data["gateway"]["clients"]["agent2"]
    _, done = await rig.write("/policy/import", body=edited(first, data), base=1)
    assert done is not None
    assert done.status_code == 200, done.text
    credentials = {
        TOKEN: "client token",
        hash_token(TOKEN): "token hash",
        PLACEHOLDER: "placeholder",
    }
    walked = [route for route in socket_routes(rig) if route[1].startswith("/policy")]
    assert len(walked) == 7
    answers: list[tuple[tuple[str, str], str]] = []
    for method, template in walked:
        path = template.format(revision="1")
        if method == "POST":
            # Revision 1's content again: agent2 comes back, with its token's hash.
            document = edited(first, seeded) if template == "/policy/import" else b""
            headers = YAML if document else {}
            grants = [("allow_revive", "client:agent2"), ("accept_widening", "1")]
            response = await rig.call(
                method, path, content=document, headers=headers, params=[("plan", "1"), *grants]
            )
            assert response.status_code == 200, (template, response.text)
            assert "digest" in response.json(), template
        else:
            params = [("revision", "1")] if template == "/policy/export" else []
            response = await rig.call(method, path, params=params)
            assert response.status_code == 200, (template, response.text)
        answers.append(((method, template), response.text + repr(dict(response.headers))))
    found = {route: carried(text, credentials) for route, text in answers}
    assert {route: kinds for route, kinds in found.items() if kinds} == {
        POLICY_EXCEPTION: {"token hash", "placeholder"}
    }
    await rig.aclose()


async def test_no_socket_answer_carries_a_generated_token(tmp_path: Path) -> None:
    """M7 C.2, GR-27: every route walked once ``secret set --generate`` made a token: none
    carries it, and the answer that made it holds only its ``sha256:`` form."""
    rig = AdminRig(tmp_path)
    store_values(rig)
    rig.admin = AdminApp(
        rig.store,
        KEYS,
        lambda: rig.policy,
        rig.setup,
        rig.tokens,
        random=lambda size: GENERATED[:size],
    )
    token = base64.urlsafe_b64encode(GENERATED).rstrip(b"=").decode()
    made = await rig.call("PUT", "/secrets/music-stats", {"generate": True})
    assert set(made.json()) == {"name", "binding", "sha256"}
    answers = [made.text + repr(dict(made.headers))]
    params = {**SOCKET_PARAMS, "onboarding": "unknown", "job": "unknown-job"}
    for method, template in socket_routes(rig):
        if (method, template) == ("PUT", "/secrets/{name}"):
            continue  # it would replace the token
        path = template.format(**params)
        response = await rig.call(method, path, SOCKET_BODIES.get((method, template)))
        answers.append(response.text + repr(dict(response.headers)))
    assert [text for text in answers if token in text] == []
    await rig.token_client.aclose()


async def test_the_egress_key_answers_its_running_generation_alone(tmp_path: Path) -> None:
    """R61's third exception (DD-14) carries the egress key of the running generation and no
    other: no previous key, since a bump retires it at once (G.3)."""
    rig = AdminRig(tmp_path)
    answer = await rig.call("GET", "/egress-key")
    assert answer.json() == {"key": KEYS.egress_key(1), "generation": 1}
    rig.set_policy(rig.policy.model_copy(update={"egress_key_generation": 3}))
    answer = await rig.call("GET", "/egress-key")
    assert answer.json() == {"key": KEYS.egress_key(3), "generation": 3}
    assert KEYS.egress_key(1) not in answer.text
    assert KEYS.gateway_key(1) not in answer.text
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


PORTAL_PARAMS = {
    "credential": "broker-mcp",
    "flow": "0123456789abcdef",
    "action": "0" * 16,
    "onboarding": "0" * 16,
    "job": "0" * 16,
    "server": "notes",
}
PORTAL_BODIES: dict[str, Any] = {
    "/api/onboard/discover": {"url": onboard_model.SERVER_URL},
    "/api/onboard/{onboarding}/fragment": {"indent": 2},
    "/api/review/jobs/{job}/diff": {"include": [], "allow": [], "approve": []},
    "/api/login/finish": {"ceremony": "0" * 16, "credential": {}},
    "/api/setup/redeem": {"code": "AAAA-BBBB-CCCC-DDDD"},
    "/api/passkeys/enrol/begin": {"name": "tablet"},
    "/api/passkeys/enrol/finish": {"ceremony": "0" * 16, "credential": {}},
    "/api/actions": {"kind": "secret.put", "data": {"name": "music-stats", "value": HELD_VALUE}},
    "/api/actions/{action}/confirm": {"credential": {}},
}
# Walked last: they end sessions.
ENDINGS = ("/api/sessions/end-others", "/api/logout")


async def walk(
    pages: Iterable[Page], routes: Iterable[Route], params: Mapping[str, str] = PORTAL_PARAMS
) -> None:
    for route in routes:
        path = route.path.format(**params)
        body = PORTAL_BODIES.get(route.path, {}) if route.method == "POST" else None
        for page in pages:
            await page.call(route.method, path, body)


async def test_no_portal_answer_carries_a_value_a_code_a_key_or_another_half(
    tmp_path: Path,
) -> None:
    rig = AdminRig(tmp_path)
    (tmp_path / "portal").mkdir(mode=0o700)
    passkeys = Passkeys(new_file(bytes(32)), KEYS.portal_key, tmp_path / "portal" / "p.json")
    reviews = Reviews()
    app = PortalApp(
        [ORIGIN],
        static=load_static(),
        setup=rig.setup,
        passkeys=passkeys,
        login=LoginService(rig.tokens),
        secrets=Secrets(rig.store, rig.tokens, lambda: rig.policy),
        health=HealthReader(rig.store, lambda: rig.policy, passkeys=passkeys).report,
        ledger=Ledger(ReportStore.open(tmp_path)),
        onboard=onboard_model.onboard_service(rig.store, rig.tokens, lambda: rig.policy),
        reviews=reviews,
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
    # A given confidential client's secret, stored through the portal's register action.
    given = {
        "url": onboard_model.SERVER_URL,
        "client_id": onboard_model.CLIENT_ID,
        "issuer": onboard_model.ISSUER,
        "client_auth": "basic",
    }
    plan = await full.call("POST", "/api/onboard/discover", given)
    assert plan.is_success, plan.text
    onboarding = plan.json()["onboarding"]
    secret = {"onboarding": onboarding, "client_secret": onboard_model.GIVEN_SECRET}
    stored = await step_up(full, authenticator, "onboard.register", secret)
    assert stored.is_success, stored.text
    code, _ = rig.setup.issue()
    assert (await setup.call("POST", "/api/setup/redeem", {"code": code.reveal()})).is_success
    halves = {
        "full": (full.token, full.cookie),
        "setup": (setup.token, setup.cookie),
    }
    # Every route, from every page; the static files; then the routes that end sessions.
    pages = (full, setup, anonymous)
    params = {**PORTAL_PARAMS, "onboarding": onboarding, "job": reviews.portal_done.id}
    await walk(pages, [r for r in ROUTES if r.path not in ENDINGS], params)
    for path in STATIC:
        response = await full.client.get(path, headers={"Host": "localhost:8081"})
        answers.append(response.text + repr(response.headers.multi_items()))
    await walk(pages, [r for path in ENDINGS for r in ROUTES if r.path == path])
    assert len(answers) > 3 * len(ROUTES)
    credentials = dict.fromkeys((*VALUES, onboard_model.GIVEN_SECRET), "secret value")
    credentials[code.reveal()] = "setup code"
    credentials[KEYS.gateway_key(1)] = "gateway key"
    credentials[KEYS.egress_key(1)] = "egress key"
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

# What would reach a credential: a setup code's issue, the gateway key or its ratchet, the
# egress key, and a store or token manager read of a value.
FORBIDDEN_ATTRIBUTES = frozenset(
    {
        "issue",
        "gateway_key",
        "gateway_keys",
        "egress_key",
        "get_for_origin",
        "get_for_oauth",
        "grant_for",
    }
)
FORBIDDEN_PATHS = ("/setup-code", "/gateway-key", "/egress-key")


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
    a string that is one of the socket paths (a docstring may name them)."""
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
        "key = keys.egress_key(1)",
        "path = '/egress-key'",
        "secret = store.get_for_origin(name, url)",
        "secret, _ = store.get_for_oauth(name, token_url=url)",
        "grant = await tokens.grant_for(name, upstream)",
    ]
    for source in hostile:
        assert references(ast.parse(source)), source
    assert references(ast.parse("summary = shown(name)\nself.setup.redeem(code)")) == []
    mutated = "def x_f__mutmut_1():\n    return keys.gateway_key(1)\n"
    assert references(without_mutants(ast.parse(mutated))) == []


def test_no_portal_code_reaches_a_setup_code_issue_or_a_key() -> None:
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
        assert "egress-key" not in route.path
