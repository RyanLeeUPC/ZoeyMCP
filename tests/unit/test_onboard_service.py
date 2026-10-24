"""Effect tests for onboarding by URL's phase 1 (M7 design D.1-D.4's given-client branch, D.7,
D.11, E.1-E.3, M.1, M.7; X24; FM-5 to FM-7, FM-11; step 8a2), the second run and a
re-registration (D.12, OPS-3, OPS-14, D-184; step 8b), and a client the vault registers (D.4's
DCR branch, X7, OPS-2; FM-9; step 11).

The fakes run over TLS on loopback (tests/fakes/harness.py), and every name reaches them through
the fake resolver's dial map (tests/fakes/resolver.py, BP-1), so the vault's guarded onboarding
client checks every address unchanged. The MCP fake serves ``mcp.notes.example`` (and, as a
private host, ``mcp.lan.example``), the OAuth fake ``auth.notes.example``, and a third host
answers every request with a redirect. Step 5's hostile switches each get a row here, the
registration answers and a stalled registration (FM-9) among them, except RFC 9207's ``iss``
(login's). Through the built-in egress role (I.3, step 17b), which the policy names with
``egress_proxy_kind: role``, an onboarding's hosts reach the role's list through the vault's real
allowlist endpoint, and no proxy is edited (J5's built-in variant); a refusal all the same is
``egress_refused``, and ``allow_private`` is refused. An ``egress_proxy`` of kind ``own`` is the
operator's proxy even while a role fetches the vault's lists.

FM-5 and FM-6 shorten the fetch limits for the test (``test_fetch.py`` pins their values), so
no test waits for long and none sleeps.
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import json
import time
from collections.abc import AsyncIterator, Callable, Iterator
from contextlib import ExitStack, asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import anyio
import certifi
import httpx
import pytest
from starlette.types import Receive, Scope, Send

from tests.acceptance.tls import ProviderCA, issue_cert, make_ca
from tests.fakes.connect_proxy import ConnectProxy, serve_proxy
from tests.fakes.harness import serve
from tests.fakes.mcp_server import OTHER_AS, McpFake, Switch
from tests.fakes.oauth_server import (
    BIDI_OVERRIDE,
    METADATA_ELSEWHERE,
    REGISTRATION_ACCESS_TOKEN,
    REGISTRATION_CLIENT_PATH,
    AuthSwitch,
    FakeAuthServer,
)
from tests.fakes.resolver import TIMEOUT, FakeResolver
from zoeymcp.common import egresslist
from zoeymcp.common.policy import Policy, check_policy, parse_policy
from zoeymcp.common.policy.merge import Merged, merge, replace_paths
from zoeymcp.common.policy.schema import EgressProxyKind, OAuth2Credential
from zoeymcp.common.yamlload import load_mapping
from zoeymcp.egress.allowlist import parse_document
from zoeymcp.portal.refusals import CATALOGUE
from zoeymcp.vault import logs, netclient, onboard, secretops
from zoeymcp.vault.app import ALLOWLIST_PATH, EGRESS_HEADER, VaultApp
from zoeymcp.vault.bindings import derive_binding, oauth_binding
from zoeymcp.vault.oauth import fetch
from zoeymcp.vault.oauth.pkce import CLI_OWNER
from zoeymcp.vault.onboard import (
    BACKSTOP_OFF,
    SHARED_REDIRECT,
    OnboardError,
    OnboardService,
    application_type,
    policy_source,
)
from zoeymcp.vault.onboarding import allow_hosts
from zoeymcp.vault.store import SecretStore

from .conftest import EXAMPLE_POLICY
from .test_deploy import compose, inline_policy
from .test_oauth_tokens import KEYS, FailingWrites

pytestmark = pytest.mark.anyio

MCP = "mcp.notes.example"
LAN = "mcp.lan.example"
AUTH = "auth.notes.example"
MOVED = "moved.notes.example"
TOKENS = "tokens.notes.example"
SERVER_URL = f"https://{MCP}/mcp"
LAN_URL = f"https://{LAN}/mcp"
ISSUER = f"https://{AUTH}"
PRM_URL = f"https://{MCP}/.well-known/oauth-protected-resource/mcp"
CLIENT_ID = "notes-given-client"
SECRET = "onboard-given-secret-0001"
SECRET_NAME = "notes-client-secret"
KEY = "fake-key-notes-0001"
SESSION = "session:" + "ab" * 16
PRIVATE = "10.0.0.5"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class Delegate:
    """An ASGI app that forwards to whichever app a test sets: the OAuth fake is fresh in each
    test, its listener the module's."""

    def __init__(self) -> None:
        self.app: Any = None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await self.app(scope, receive, send)


async def moved(scope: Scope, receive: Receive, send: Send) -> None:
    """Every request redirected elsewhere."""
    if scope["type"] != "http":
        return
    headers = [(b"location", b"https://attacker.example/mcp")]
    await send({"type": "http.response.start", "status": 307, "headers": headers})
    await send({"type": "http.response.body", "body": b""})


@dataclass
class World:
    ca: ProviderCA
    mcp: McpFake
    auth: Delegate
    ports: dict[str, int]


@pytest.fixture(scope="module")
def world(tmp_path_factory: pytest.TempPathFactory) -> Iterator[World]:
    directory = tmp_path_factory.mktemp("onboard-tls")
    ca = make_ca(directory)
    mcp, auth = McpFake(), Delegate()
    ports: dict[str, int] = {}
    with ExitStack() as stack:
        for name, app, lifespan in (
            (MCP, mcp.app(), True),
            (LAN, mcp.app(), True),
            (AUTH, auth, False),
            (MOVED, moved, False),
        ):
            tls = issue_cert(ca, name, directory)
            url = stack.enter_context(serve(app, lifespan=lifespan, tls=tls))
            ports[name] = int(str(urlsplit(url).port))
        yield World(ca, mcp, auth, ports)


@pytest.fixture
def mcp(world: World) -> McpFake:
    """The MCP fake as each test starts: a protected server publishing its metadata."""
    fake = world.mcp
    fake.mode = "dual"
    fake.switches = set()
    fake.key = KEY
    fake.prm = "path"
    fake.authorization_servers = [ISSUER]
    fake.scopes = ("notes.read",)
    fake.challenge_metadata = True
    fake.as_metadata = None
    fake.received.clear()
    return fake


@pytest.fixture
def auth(world: World) -> FakeAuthServer:
    fake = FakeAuthServer(
        client_id=CLIENT_ID,
        issuer=ISSUER,
        iss_supported=True,
        scopes=("notes.read", "offline_access"),
        registration="none",
        prefix="fake-notes",
    )
    world.auth.app = fake.app()
    return fake


@pytest.fixture
def names(world: World, monkeypatch: pytest.MonkeyPatch) -> FakeResolver:
    """The vault's names: each fake's host, and the test CA as certifi's bundle."""
    resolver = FakeResolver()
    for name, port in world.ports.items():
        resolver.serve(name, port, address=PRIVATE if name == LAN else None)
    monkeypatch.setattr(netclient, "HOOKS", resolver.hooks())
    monkeypatch.setattr(certifi, "where", lambda: str(world.ca.ca_file))
    return resolver


@pytest.fixture
def lines() -> Iterator[io.StringIO]:
    buffer = io.StringIO()
    logs.set_stream(buffer)
    try:
        yield buffer
    finally:
        logs.set_stream(None)


def records(buffer: io.StringIO) -> list[dict[str, Any]]:
    return [json.loads(line) for line in buffer.getvalue().splitlines()]


def events(buffer: io.StringIO) -> list[str]:
    return [record["event"] for record in records(buffer)]


def example_policy() -> Policy:
    return parse_policy(EXAMPLE_POLICY.read_text(encoding="utf-8"), "example")


class Rig:
    """The service on the vault's guarded onboarding client, the example policy, a store."""

    def __init__(
        self,
        tmp_path: Path,
        proxy: str | None = None,
        clock: Callable[[], float] = time.monotonic,
        egress: VaultApp | None = None,
        kind: EgressProxyKind = "own",
    ) -> None:
        state = tmp_path / "state"
        state.mkdir(mode=0o700)
        self.store = SecretStore(state, KEYS)
        self.store.load()
        self.policy = example_policy()
        self.client = netclient.onboarding_client(proxy)
        self.proxy = proxy
        self.clock = clock
        self.egress = egress
        self.kind: EgressProxyKind = kind
        self.restart()

    def restart(self) -> None:
        """A fresh service on the same store, as a vault restart leaves it: no onboarding."""
        self.service = OnboardService(
            self.store,
            None,
            lambda: self.policy,
            self.client,
            egress_proxy=self.proxy,
            egress_proxy_kind=self.kind,
            egress=self.egress,
            source="policy.yaml",
            clock=self.clock,
        )
        if self.egress is not None:
            self.egress.use_allowances(self.service.allowances, self.service.allowances_expire_in)

    async def discover(self, owner: str = CLI_OWNER, **body: Any) -> dict[str, Any]:
        with anyio.fail_after(20):
            return await self.service.discover(body, owner=owner)

    async def refused(self, owner: str = CLI_OWNER, **body: Any) -> tuple[int, dict[str, Any]]:
        with pytest.raises(OnboardError) as caught, anyio.fail_after(20):
            await self.service.discover(body, owner=owner)
        answer = caught.value.answer
        assert CATALOGUE[answer.reason].status == answer.status
        return answer.status, answer.body()

    def merged(self, fragment: str) -> Policy:
        """The policy with fragment 1 merged, as ``check --with`` merges it (H.4)."""
        base = self.policy.model_dump(mode="json", by_alias=True, exclude_defaults=True)
        result = merge(base, load_mapping(fragment), replace=replace_paths(fragment))
        assert isinstance(result, Merged)
        return Policy.model_validate(result.data)


@asynccontextmanager
async def running(
    tmp_path: Path,
    proxy: str | None = None,
    clock: Callable[[], float] = time.monotonic,
    egress: VaultApp | None = None,
    kind: EgressProxyKind = "own",
) -> AsyncIterator[Rig]:
    rig = Rig(tmp_path, proxy, clock, egress, kind)
    try:
        yield rig
    finally:
        await rig.client.aclose()


async def refusal_of(call: Any) -> tuple[int, dict[str, Any]]:
    with pytest.raises(OnboardError) as caught, anyio.fail_after(20):
        await call
    return caught.value.answer.status, caught.value.answer.body()


PUBLIC: dict[str, Any] = {"url": SERVER_URL, "client_id": CLIENT_ID}
CONFIDENTIAL: dict[str, Any] = {
    "url": SERVER_URL,
    "client_id": CLIENT_ID,
    "issuer": ISSUER,
    "secret_given": True,
}


# --- a given public client (D.4, E.2) ------------------------------------------------------------


@pytest.mark.usefixtures("names")
async def test_a_given_public_client(
    tmp_path: Path, mcp: McpFake, auth: FakeAuthServer, lines: io.StringIO
) -> None:
    async with running(tmp_path) as rig:
        plan = await rig.discover(**PUBLIC)
        assert (plan["stage"], plan["names"]) == (
            "discovered",
            {"credential": "notes", "route": "notes", "server": "notes", "source": "label"},
        )
        shown = plan["plan"]
        assert shown == {
            "server_url": SERVER_URL,
            "resource": SERVER_URL,
            "resource_metadata": PRM_URL,
            "resource_name": "Fake MCP server",
            "issuer": ISSUER,
            "issuer_source": "only",
            "metadata_url": f"{ISSUER}/.well-known/oauth-authorization-server",
            "authorization_endpoint": f"{ISSUER}/authorize",
            "token_endpoint": f"{ISSUER}/token",
            "registration_endpoint": None,
            "revocation_endpoint": f"{ISSUER}/revoke",
            "require_iss": True,
            "pkce": "S256",
            "registration": "given",
            "client_id": CLIENT_ID,
            "client_auth": "none",
            "secret_given": False,
            "redirect_uri": SHARED_REDIRECT,
            "application_type": "native",
            "scopes": ["notes.read", "offline_access"],
            "scope_source": "challenge",
            "offline_access_added": True,
            "hosts": [f"{MCP}:443", f"{AUTH}:443"],
            "notes": ["offline_access_added", "backstop_off"],
        }
        assert ["Note", BACKSTOP_OFF] in plan["rows"]
        assert ["Client", f"{CLIENT_ID} (given)"] in plan["rows"]
        assert plan["allowance"] == [f"{AUTH}:443", f"{MCP}:443"]
        assert [f["level"] for f in plan["draft_check"]] == ["warning", "warning"]
        assert plan["next"] == [{"do": "make_fragment", "label": "Make the YAML"}]
        assert 0 < plan["expires"] - time.time() <= 1800
        made = await rig.service.fragment(plan["onboarding"], {})
    # Nothing was registered or stored: the fragment holds what the operator typed.
    assert auth.registrations == []
    assert rig.store.names() == []
    assert (made["stage"], made["credential"], made["client_auth"]) == (
        "registered",
        "notes",
        "none",
    )
    assert (made["secret_stored"], made["secret_name"]) == (False, None)
    fragment = load_mapping(made["diff"]["yaml"])
    assert fragment["credentials"]["notes"] == {
        "kind": "oauth2",
        "token_url": f"{ISSUER}/token",
        "authorize_url": f"{ISSUER}/authorize",
        "issuer": ISSUER,
        "require_iss": True,
        "revocation_url": f"{ISSUER}/revoke",
        "resource_metadata": PRM_URL,
        "client_id": CLIENT_ID,
        "client_auth": "none",
        "refresh_token": "store:notes-refresh",
        "rotates": True,
        "redirect_uri": SHARED_REDIRECT,
        "scope": "notes.read offline_access",
        "extra_params": {"resource": SERVER_URL},
        "authorize_params": {"resource": SERVER_URL},
    }
    assert fragment["routes"] == [
        {
            "name": "notes",
            "prefix": "/notes",
            "upstream": f"https://{MCP}",
            "credential": "notes",
            "callers": ["gateway"],
            "stream": True,
            "rules": [{"methods": ["POST", "GET", "DELETE"], "paths": ["/mcp"]}],
        }
    ]
    assert fragment["gateway"] == {
        "servers": {
            "notes": {"kind": "remote", "route": "notes", "path": "/mcp", "tools": {"include": []}}
        }
    }
    assert "egress_private" not in fragment
    assert made["diff"]["yaml"].startswith(
        "# zoeymcp: onboarding notes (1 of 2). Merge into your policy; nothing here replaces a "
        "key you have.\n"
    )
    # The merged policy passes check: E.3's server, with no tool served.
    merged = rig.merged(made["diff"]["yaml"])
    assert not [f for f in check_policy(merged) if f.level == "error"]
    assert [step["do"] for step in made["next"]] == [
        "check_fragment",
        "commit_fragment",
        "check_policy",
        "reload",
        "connect",
    ]
    assert (
        made["next"][0]["command"]
        == "zoeymcp check --config policy.yaml --with onboard-notes-1.yaml"
    )
    assert made["next"][-1]["command"] == f"zoeymcp login --mcp {SERVER_URL} --name notes"
    # Every request was a fixed probe or a GET, each through the guard to a checked address.
    assert [(r.method, r.path) for r in mcp.received] == [
        ("POST", "/mcp"),
        ("GET", "/.well-known/oauth-protected-resource/mcp"),
    ]
    assert [(s.method, s.path) for s in auth.seen] == [
        ("GET", "/.well-known/oauth-authorization-server")
    ]
    assert events(lines) == [
        "onboard_started",
        "discovery_fetch",
        "discovery_fetch",
        "discovery_fetch",
        "onboard_planned",
        "onboard_registered",
    ]


@pytest.mark.usefixtures("names", "mcp", "auth")
async def test_a_registered_fragment_again_at_any_indent(tmp_path: Path) -> None:
    """OPS-2: fragment 1 again, rendered from the change, never a secret."""
    async with running(tmp_path) as rig:
        plan = await rig.discover(**PUBLIC)
        first = await rig.service.fragment(plan["onboarding"], {})
        again = await rig.service.fragment(plan["onboarding"], {"indent": 4})
        compose = await rig.service.fragment(plan["onboarding"], {"indent": "compose"})
        # A registered onboarding answers register with its fragment too.
        registered = await rig.service.register(plan["onboarding"], {})
        # The same run again carries on as it is, with no request.
        before = len(rig.service._table)
        resumed = await rig.discover(**PUBLIC)
        for body in ({"indent": 17}, {"indent": True}, {"indent": "4"}, {"other": 1}):
            status, refused = await refusal_of(rig.service.fragment(plan["onboarding"], body))
            assert (status, refused["reason"]) == (400, "bad_body")
    assert registered == first
    assert all(line.startswith("    ") for line in again["diff"]["yaml"].splitlines())
    assert load_mapping(again["diff"]["yaml"]) == load_mapping(first["diff"]["yaml"])
    assert all(line.startswith(" " * 8) for line in compose["diff"]["yaml"].splitlines())
    assert (resumed["onboarding"], resumed["stage"]) == (plan["onboarding"], "registered")
    assert len(rig.service._table) == before == 1


# --- a given confidential client (D.7, TI-15) -----------------------------------------------------


@pytest.mark.usefixtures("names", "mcp")
async def test_a_given_confidential_client_stores_its_secret_under_the_predicted_binding(
    tmp_path: Path, auth: FakeAuthServer, lines: io.StringIO
) -> None:
    async with running(tmp_path) as rig:
        plan = await rig.discover(**CONFIDENTIAL)
        assert plan["plan"]["client_auth"] == "basic"
        assert plan["plan"]["issuer_source"] == "chosen"
        assert plan["next"] == [{"do": "register", "label": "Store the secret and make the YAML"}]
        status, refused = await refusal_of(rig.service.register(plan["onboarding"], {}))
        assert (status, refused["reason"]) == (400, "bad_body")
        status, refused = await refusal_of(rig.service.fragment(plan["onboarding"], {}))
        assert (status, refused["reason"]) == (400, "bad_body")
        made = await rig.service.register(plan["onboarding"], {"client_secret": SECRET})
        status, refused = await refusal_of(
            rig.service.register(plan["onboarding"], {"client_secret": SECRET})
        )
        assert (status, refused["reason"]) == (400, "bad_body")
    assert (made["secret_stored"], made["secret_name"]) == (True, SECRET_NAME)
    assert made["client_secret_expires_at"] is None
    credential = load_mapping(made["diff"]["yaml"])["credentials"]["notes"]
    assert (credential["client_secret"], credential["client_auth"]) == (
        f"store:{SECRET_NAME}",
        "basic",
    )
    assert credential["rotates"] is False
    entry = rig.store.entry(SECRET_NAME)
    assert entry is not None
    # The binding derive_binding gives once fragment 1 is loaded (D.7 step 2).
    predicted = oauth_binding(f"{ISSUER}/token", [f"https://{MCP}"])
    assert (
        entry.binding == predicted == derive_binding(rig.merged(made["diff"]["yaml"]), SECRET_NAME)
    )
    assert entry.meta == {
        "onboarded": AUTH,
        "resource": SERVER_URL,
        "client_id": CLIENT_ID,
        "client_secret_expires_at": None,
    }
    secret, _ = rig.store.get_for_oauth(SECRET_NAME, token_url=f"{ISSUER}/token")
    assert secret.reveal() == SECRET
    assert auth.registrations == []
    # The secret is in no answer and no log line; secret_set says where it was stored.
    assert SECRET not in json.dumps(made) + lines.getvalue()
    [stored] = [r for r in records(lines) if r["event"] == "secret_set"]
    assert (stored["name"], stored["binding"], stored["via"]) == (SECRET_NAME, predicted, "socket")
    [registered] = [r for r in records(lines) if r["event"] == "onboard_registered"]
    assert registered == {
        **registered,
        "credential": "notes",
        "issuer": AUTH,
        "auth": "basic",
        "secret_stored": True,
    }


@pytest.mark.usefixtures("names")
async def test_a_given_secret_goes_only_to_the_issuer_the_operator_named(
    tmp_path: Path, mcp: McpFake, auth: FakeAuthServer
) -> None:
    """TI-15: without --issuer, or with a PRM naming another authorization server, as_unknown,
    before anything is fetched from it or stored."""
    async with running(tmp_path) as rig:
        unnamed = {key: value for key, value in CONFIDENTIAL.items() if key != "issuer"}
        status, body = await rig.refused(**unnamed)
        assert (status, body["reason"], body["issuers"]) == (400, "as_unknown", [ISSUER])
        mcp.authorization_servers = [OTHER_AS]
        status, body = await rig.refused(**CONFIDENTIAL)
        assert (status, body["reason"], body["issuers"]) == (400, "as_unknown", [OTHER_AS])
    assert auth.seen == []
    assert rig.store.names() == []


@pytest.mark.usefixtures("names", "mcp", "auth")
async def test_a_redirect_address_the_operator_gives(tmp_path: Path) -> None:
    own = "http://127.0.0.1/callback/notes"
    async with running(tmp_path) as rig:
        plan = await rig.discover(**PUBLIC, redirect_uri=own)
        made = await rig.service.fragment(plan["onboarding"], {})
        await rig.service.cancel(plan["onboarding"])
        for bad in ("https://notes.example/cb?x=1", "http://192.0.2.1/cb", "http://localhost/cb"):
            status, body = await rig.refused(**PUBLIC, redirect_uri=bad)
            assert (status, body["reason"]) == (400, "bad_body")
            assert body["detail"].startswith("redirect_uri: ")
    assert (plan["plan"]["redirect_uri"], plan["plan"]["application_type"]) == (own, "native")
    assert "backstop_off" not in plan["plan"]["notes"]
    assert load_mapping(made["diff"]["yaml"])["credentials"]["notes"]["redirect_uri"] == own


@pytest.mark.usefixtures("names", "mcp", "auth")
@pytest.mark.parametrize(
    ("name", "redirect"),
    [
        # The shared default, for a credential whose name starts its path ("/cal" in "/callback").
        ("cal", None),
        ("callback", None),
        ("callback", SHARED_REDIRECT),
        # Another credential's address, or one a segment longer.
        ("notes", "http://127.0.0.1/callback/notes-old"),
        ("notes", "http://127.0.0.1/callback/notes/x"),
    ],
)
async def test_a_redirect_address_that_isnt_the_credentials_own(
    tmp_path: Path, name: str, redirect: str | None
) -> None:
    """D.4, D.6: the backstop note unless the path ends in the credential's name."""
    given = {} if redirect is None else {"redirect_uri": redirect}
    async with running(tmp_path) as rig:
        plan = await rig.discover(**PUBLIC, name=name, **given)
    assert "backstop_off" in plan["plan"]["notes"]
    assert ["Note", BACKSTOP_OFF] in plan["rows"]


def test_application_type_follows_the_redirect_host() -> None:
    assert application_type("http://127.0.0.1/callback") == "native"
    assert application_type("http://[::1]:8000/callback") == "native"
    assert application_type("https://localhost:8443/oauth/callback/notes") == "native"
    assert application_type("https://zoeymcp.tailnet.example/oauth/callback/notes") == "web"
    assert application_type("https://10.0.0.1/cb") == "web"


def test_the_policy_source_names_where_check_reads_it() -> None:
    assert policy_source(None) == "$ZOEYMCP_CONFIG"
    assert policy_source("-") == "<stdin>"
    assert policy_source("/etc/zoeymcp/policy.yaml") == "/etc/zoeymcp/policy.yaml"


@pytest.mark.usefixtures("names", "mcp", "auth")
async def test_the_operators_scopes_replace_the_ones_found(tmp_path: Path) -> None:
    async with running(tmp_path) as rig:
        plan = await rig.discover(**PUBLIC, scope="notes.read notes.write")
        made = await rig.service.fragment(plan["onboarding"], {})
        await rig.service.cancel(plan["onboarding"])
        for bad in ("notes$read", "a  b", "x" * 300, " ".join(["s"] * 65), 'a"b'):
            status, body = await rig.refused(**PUBLIC, scope=bad)
            assert (status, body["reason"]) == (400, "bad_body")
    assert plan["plan"]["scopes"] == ["notes.read", "notes.write"]
    assert (plan["plan"]["scope_source"], plan["plan"]["offline_access_added"]) == ("given", False)
    assert ["Scopes", "notes.read notes.write (the scopes you gave)"] in plan["rows"]
    assert load_mapping(made["diff"]["yaml"])["credentials"]["notes"]["scope"] == (
        "notes.read notes.write"
    )


@pytest.mark.usefixtures("names", "mcp")
async def test_without_a_client_id_registration_is_unavailable(
    tmp_path: Path, auth: FakeAuthServer, lines: io.StringIO, monkeypatch: pytest.MonkeyPatch
) -> None:
    """D.4's order: no client ID, and no registration endpoint (or none with an authentication
    the vault speaks), refuses before the operator is asked anything (step 11: with one, the
    vault registers)."""
    assert auth.registration == "none"
    async with running(tmp_path) as rig:
        status, body = await rig.refused(url=SERVER_URL)
        # The refused onboarding is gone: the same command starts afresh.
        assert len(rig.service._table) == 0
        auth.registration = "cimd_only"
        cimd = await rig.refused(url=SERVER_URL)
        auth.registration = "open"
        monkeypatch.setattr(auth, "_auth_methods", lambda: ["private_key_jwt"])
        jwt = await rig.refused(url=SERVER_URL)
    assert (status, body["reason"]) == (409, "registration_unavailable")
    assert body["error"] == f"Register a client at {AUTH} and run again with its client ID."
    assert cimd == (409, {**cimd[1], "reason": "cimd_only"})
    assert cimd[1]["error"] == (
        "This server registers clients by metadata document, which ZoeyMCP doesn't support "
        f"yet. Register a client at {AUTH} and run again with its client ID."
    )
    assert (jwt[0], jwt[1]["reason"]) == (502, "dcr_auth_unsupported")
    assert auth.registrations == []
    refused = [r for r in records(lines) if r["event"] == "onboard_refused"]
    assert [r["reason"] for r in refused] == [
        "registration_unavailable",
        "cimd_only",
        "dcr_auth_unsupported",
    ]
    assert refused[0] == {**refused[0], "reason": "registration_unavailable", "host": MCP}


# --- a client the vault registers (D.4, D.7, D.8, X7; step 11) ------------------------------------

DCR_REDIRECT = "http://127.0.0.1/callback/notes"
CLIENT_ID_NAME = "notes-client-id"
PORTAL_ORIGIN = "https://zoeymcp.tailnet.example"


def predicted_binding() -> dict[str, Any]:
    return oauth_binding(f"{ISSUER}/token", [f"https://{MCP}"])


def dcr_meta(client_id: str, auth: str, expires: int | None = None) -> dict[str, Any]:
    """D.7 step 4's meta, with what a run after a restart takes on (D.7 step 6)."""
    return {
        "onboarded": AUTH,
        "resource": SERVER_URL,
        "client_id": client_id,
        "client_secret_expires_at": expires,
        "client_auth": auth,
        "redirect_uri": DCR_REDIRECT,
    }


@pytest.mark.usefixtures("names", "mcp")
async def test_a_public_client_the_vault_registers(
    tmp_path: Path, auth: FakeAuthServer, lines: io.StringIO
) -> None:
    """J1 (DCR) to the commit: no client ID and a registration endpoint allowing a public
    client. One POST of public metadata after the confirmation, its answer checked, the
    client's ID kept as notes-client-id under the predicted binding (OPS-2), and fragment 1
    with the credential's own redirect address (D.6's backstop on); the second run deletes the
    entry (D.8)."""
    auth.registration = "open"
    async with running(tmp_path) as rig:
        plan = await rig.discover(url=SERVER_URL)
        # Neither a fragment nor a secret before the registration: register makes them.
        status, refused = await refusal_of(rig.service.fragment(plan["onboarding"], {}))
        assert (status, refused["reason"]) == (400, "bad_body")
        status, refused = await refusal_of(
            rig.service.register(plan["onboarding"], {"client_secret": SECRET})
        )
        assert (status, refused["reason"]) == (400, "bad_body")
        assert auth.registrations == []
        made = await rig.service.register(plan["onboarding"], {})
        again = await rig.service.register(plan["onboarding"], {})
        indented = await rig.service.fragment(plan["onboarding"], {"indent": 4})
        rig.policy = rig.merged(made["diff"]["yaml"])
        names_before = rig.store.names()
        compared = await rig.discover(url=SERVER_URL)
    shown = plan["plan"]
    assert (shown["registration"], shown["client_id"], shown["client_auth"]) == (
        "dcr",
        None,
        "none",
    )
    assert (shown["redirect_uri"], shown["application_type"]) == (DCR_REDIRECT, "native")
    assert shown["registration_endpoint"] == f"{ISSUER}/register"
    assert "backstop_off" not in shown["notes"]
    assert [
        "Client",
        f"registered at {AUTH} once you confirm (dynamic client registration)",
    ] in plan["rows"]
    assert ["Client name", "ZoeyMCP (notes)"] in plan["rows"]
    assert plan["next"] == [{"do": "register", "label": "Register and make the YAML"}]
    assert not [f for f in plan["draft_check"] if f["level"] == "error"]
    [sent] = auth.registrations
    assert json.loads(sent.body) == {
        "client_name": "ZoeyMCP (notes)",
        "redirect_uris": [DCR_REDIRECT],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "application_type": "native",
        "scope": "notes.read offline_access",
    }
    assert "authorization" not in sent.headers
    assert sent.headers["content-type"] == "application/json"
    client_id = made["client_id"]
    assert client_id in auth.registered
    assert (made["client_auth"], made["secret_stored"], made["secret_name"]) == (
        "none",
        False,
        None,
    )
    assert (made["client_secret_expires_at"], made["notes"]) == (None, [])
    assert again == made
    credential = load_mapping(made["diff"]["yaml"])["credentials"]["notes"]
    assert credential == {
        "kind": "oauth2",
        "token_url": f"{ISSUER}/token",
        "authorize_url": f"{ISSUER}/authorize",
        "issuer": ISSUER,
        "require_iss": True,
        "revocation_url": f"{ISSUER}/revoke",
        "resource_metadata": PRM_URL,
        "client_id": client_id,
        "client_auth": "none",
        "refresh_token": "store:notes-refresh",
        "rotates": True,
        "redirect_uri": DCR_REDIRECT,
        "scope": "notes.read offline_access",
        "extra_params": {"resource": SERVER_URL},
        "authorize_params": {"resource": SERVER_URL},
    }
    assert load_mapping(indented["diff"]["yaml"]) == load_mapping(made["diff"]["yaml"])
    assert not [f for f in check_policy(rig.policy) if f.level == "error"]
    # The ID is kept for a restart before the commit (OPS-2): not a secret, under the binding.
    assert names_before == [CLIENT_ID_NAME]
    # The second run, once the policy names the credential, deletes it.
    assert compared["stage"] == "committed"
    assert rig.store.names() == []
    fetched = [r["fetch_kind"] for r in records(lines) if r["event"] == "discovery_fetch"]
    assert fetched[:4] == ["probe", "prm", "as", "register"]
    [planned, *_] = [r for r in records(lines) if r["event"] == "onboard_planned"]
    assert (planned["registration"], planned["auth"]) == ("dcr", "none")
    [registered] = [r for r in records(lines) if r["event"] == "onboard_registered"]
    assert (registered["auth"], registered["secret_stored"]) == ("none", False)
    assert [e for e in events(lines) if e.startswith("secret_")] == [
        "secret_set",
        "secret_deleted",
    ]


@pytest.mark.usefixtures("names", "mcp")
async def test_a_public_clients_id_entry(tmp_path: Path, auth: FakeAuthServer) -> None:
    auth.registration = "open"
    async with running(tmp_path) as rig:
        plan = await rig.discover(url=SERVER_URL)
        made = await rig.service.register(plan["onboarding"], {})
        entry = rig.store.entry(CLIENT_ID_NAME)
        value = rig.store.get_for_binding(CLIENT_ID_NAME, predicted_binding())
    assert entry is not None
    assert entry.binding == predicted_binding()
    assert entry.meta == dcr_meta(made["client_id"], "none")
    assert value.reveal() == made["client_id"]


@pytest.mark.usefixtures("names", "mcp")
async def test_a_confidential_client_the_vault_registers_and_stores_its_secret(
    tmp_path: Path, auth: FakeAuthServer, lines: io.StringIO
) -> None:
    """D.4, D.7: a server that takes no public client registers one with a secret, stored at
    once under the predicted binding, its expiry in the meta (J's expiry codes read it)."""
    auth.registration = "confidential_only"
    auth.secret_expires_at = 1_900_000_000
    async with running(tmp_path) as rig:
        plan = await rig.discover(url=SERVER_URL)
        made = await rig.service.register(plan["onboarding"], {})
        texts = json.dumps(plan) + json.dumps(made)
    assert (plan["plan"]["client_auth"], plan["plan"]["secret_given"]) == ("basic", True)
    [sent] = auth.registrations
    assert json.loads(sent.body)["token_endpoint_auth_method"] == "client_secret_basic"
    client_id = made["client_id"]
    secret = auth.registered[client_id].secret
    assert secret is not None
    assert (made["client_auth"], made["secret_stored"], made["secret_name"]) == (
        "basic",
        True,
        SECRET_NAME,
    )
    assert made["client_secret_expires_at"] == 1_900_000_000
    credential = load_mapping(made["diff"]["yaml"])["credentials"]["notes"]
    assert (credential["client_id"], credential["client_secret"]) == (
        client_id,
        f"store:{SECRET_NAME}",
    )
    assert (credential["client_auth"], credential["rotates"]) == ("basic", False)
    entry = rig.store.entry(SECRET_NAME)
    assert entry is not None
    assert entry.binding == predicted_binding()
    assert entry.binding == derive_binding(rig.merged(made["diff"]["yaml"]), SECRET_NAME)
    assert entry.meta == dcr_meta(client_id, "basic", 1_900_000_000)
    stored, _ = rig.store.get_for_oauth(SECRET_NAME, token_url=f"{ISSUER}/token")
    assert stored.reveal() == secret
    assert rig.store.names() == [SECRET_NAME]
    assert secret not in texts + lines.getvalue()
    [registered] = [r for r in records(lines) if r["event"] == "onboard_registered"]
    assert (registered["auth"], registered["secret_stored"]) == ("basic", True)


@pytest.mark.usefixtures("names", "mcp")
@pytest.mark.parametrize(
    ("switch", "reason"),
    [
        (AuthSwitch.DCR_REDIRECT_CHANGED, "dcr_redirect_changed"),
        (AuthSwitch.DCR_PRIVATE_KEY_JWT, "dcr_auth_unsupported"),
        (AuthSwitch.DCR_SECRET_FOR_NONE, "dcr_bad_secret"),
        (AuthSwitch.DCR_CLIENT_ID_SPACE, "dcr_bad_client_id"),
        (AuthSwitch.DCR_CLIENT_ID_BIDI, "dcr_bad_client_id"),
    ],
)
async def test_a_registration_answer_that_isnt_used(
    tmp_path: Path, auth: FakeAuthServer, switch: AuthSwitch, reason: str, lines: io.StringIO
) -> None:
    """X7: each hostile answer refused by name, nothing stored; the onboarding stays, so a run
    again registers anew."""
    auth.registration = "open"
    auth.switches = {switch}
    async with running(tmp_path) as rig:
        plan = await rig.discover(url=SERVER_URL)
        status, body = await refusal_of(rig.service.register(plan["onboarding"], {}))
        names = rig.store.names()
        auth.switches = set()
        made = await rig.service.register(plan["onboarding"], {})
    assert (status, body["reason"]) == (502, reason)
    assert body["error"] == CATALOGUE[reason].text
    assert names == []
    assert len(auth.registrations) == 2
    assert made["stage"] == "registered"
    assert events(lines).count("onboard_registered") == 1


@pytest.mark.usefixtures("names", "mcp")
async def test_the_servers_refusal_is_shown_to_the_operator_alone(
    tmp_path: Path, auth: FakeAuthServer, lines: io.StringIO
) -> None:
    """D.4: a 400's error code filtered, its description cleaned, capped and revealed, in the
    answer only; and a server that wants an initial access token is dcr_failed (D-179)."""
    auth.registration = "open"
    auth.switches = {AuthSwitch.DCR_ERROR_INJECTED}
    async with running(tmp_path) as rig:
        plan = await rig.discover(url=SERVER_URL)
        status, body = await refusal_of(rig.service.register(plan["onboarding"], {}))
        auth.switches = set()
        auth.registration = "needs_initial_token"
        failed = await refusal_of(rig.service.register(plan["onboarding"], {}))
    assert (status, body["reason"]) == (502, "dcr_refused")
    assert body["error"] == (
        "The authorization server refused the registration (invalid_client_metadata), so no "
        "client was registered."
    )
    said = body["description"]
    assert said.startswith("Bad metadata[U+000D] X-Injected: 1 [U+202E]<b>Approve</b>")
    assert BIDI_OVERRIDE not in said
    assert "Bad metadata" not in lines.getvalue()
    assert failed[0] == 502
    assert failed[1]["reason"] == "dcr_failed"
    assert "(HTTP 401)" in failed[1]["error"]
    assert rig.store.names() == []


@pytest.mark.usefixtures("names", "mcp")
async def test_a_registration_access_token_and_uri_are_never_kept(
    tmp_path: Path, auth: FakeAuthServer, lines: io.StringIO
) -> None:
    """D-148, X19: the answer's RFC 7592 token and URI are dropped unread: in no answer, line,
    entry or fragment."""
    auth.registration = "confidential_only"
    auth.switches = {AuthSwitch.DCR_ACCESS_TOKEN}
    async with running(tmp_path) as rig:
        plan = await rig.discover(url=SERVER_URL)
        made = await rig.service.register(plan["onboarding"], {})
        again = await rig.service.fragment(plan["onboarding"], {"indent": "compose"})
        entry = rig.store.entry(SECRET_NAME)
    assert entry is not None
    swept = json.dumps([plan, made, again, entry.meta]) + lines.getvalue()
    assert REGISTRATION_ACCESS_TOKEN not in swept
    assert REGISTRATION_CLIENT_PATH not in swept


@pytest.mark.usefixtures("names", "mcp")
async def test_registration_timeout(
    tmp_path: Path, auth: FakeAuthServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    """FM-9: dcr_failed at the registration's own limit; the server may have registered a
    client (D-155), and the run again registers anew."""
    auth.registration = "open"
    auth.switches = {AuthSwitch.STALL_REGISTER}
    monkeypatch.setattr(fetch, "REGISTRATION_TIMEOUT", 0.5)
    async with running(tmp_path) as rig:
        plan = await rig.discover(url=SERVER_URL)
        started = time.monotonic()
        status, body = await refusal_of(rig.service.register(plan["onboarding"], {}))
        took = time.monotonic() - started
        held = rig.store.names()
        auth.switches = set()
        made = await rig.service.register(plan["onboarding"], {})
    assert (status, body["reason"]) == (502, "dcr_failed")
    assert body["error"] == (
        "The authorization server didn't answer the registration as needed (timeout). It may "
        "have registered a client anyway; the next run registers a new one."
    )
    assert took < 5
    assert held == []
    assert len(auth.registrations) == 2
    assert made["stage"] == "registered"


@pytest.mark.usefixtures("names", "mcp")
async def test_the_redirect_a_registration_asks_for(tmp_path: Path, auth: FakeAuthServer) -> None:
    """D.4: --redirect-uri with a loopback port is registered exactly as given; a portal origin
    from admin.origins registers its callback, as a web client; an origin not listed, or one
    beside a given client or address, is refused."""
    auth.registration = "open"
    loopback = "http://127.0.0.1:8765/callback/notes"
    async with running(tmp_path) as rig:
        plan = await rig.discover(url=SERVER_URL, redirect_uri=loopback)
        made = await rig.service.register(plan["onboarding"], {})
        await rig.service.cancel(plan["onboarding"])
        portal = await rig.discover(url=SERVER_URL, callback_origin=PORTAL_ORIGIN, name="files")
        portal_made = await rig.service.register(portal["onboarding"], {})
        await rig.service.cancel(portal["onboarding"])
        unlisted = await rig.refused(url=SERVER_URL, callback_origin="https://other.example")
        given = await rig.refused(**PUBLIC, callback_origin=PORTAL_ORIGIN)
        both = await rig.refused(
            url=SERVER_URL, callback_origin=PORTAL_ORIGIN, redirect_uri=loopback
        )
    first, second = (json.loads(sent.body) for sent in auth.registrations)
    assert (first["redirect_uris"], first["application_type"]) == ([loopback], "native")
    assert (plan["plan"]["redirect_uri"], plan["plan"]["application_type"]) == (loopback, "native")
    assert "backstop_off" not in plan["plan"]["notes"]
    assert load_mapping(made["diff"]["yaml"])["credentials"]["notes"]["redirect_uri"] == loopback
    callback = f"{PORTAL_ORIGIN}/oauth/callback/files"
    assert (second["redirect_uris"], second["application_type"]) == ([callback], "web")
    assert (second["client_name"], portal["plan"]["application_type"]) == ("ZoeyMCP (files)", "web")
    fragment = load_mapping(portal_made["diff"]["yaml"])
    assert fragment["credentials"]["files"]["redirect_uri"] == callback
    assert not [
        f for f in check_policy(rig.merged(portal_made["diff"]["yaml"])) if f.level == "error"
    ]
    for status, body in (unlisted, given, both):
        assert (status, body["reason"]) == (400, "bad_body")
    assert "admin.origins" in unlisted[1]["detail"]
    assert len(auth.registrations) == 2


@pytest.mark.usefixtures("names", "mcp")
@pytest.mark.parametrize(
    ("mode", "name"), [("open", CLIENT_ID_NAME), ("confidential_only", SECRET_NAME)]
)
async def test_after_a_restart_a_registered_client_shows_fragment_1_again(
    tmp_path: Path, auth: FakeAuthServer, mode: str, name: str
) -> None:
    """D.7 step 6 for DCR (FM-2): the entry the registration wrote is found by its meta, its
    binding (and a public client's ID, its value) checked against a fresh discovery, and
    fragment 1 shown again with nothing registered or stored again."""
    auth.registration = mode  # type: ignore[assignment]
    async with running(tmp_path) as rig:
        plan = await rig.discover(url=SERVER_URL)
        made = await rig.service.register(plan["onboarding"], {})
        rig.restart()
        again = await rig.discover(url=SERVER_URL)
        shown = await rig.service.fragment(again["onboarding"], {})
        # Another redirect address isn't the registered client's: its names stay taken.
        rig.restart()
        moved = await rig.refused(
            url=SERVER_URL, name="notes", redirect_uri="http://127.0.0.1:8765/callback/notes"
        )
        assert (moved[0], moved[1]["reason"]) == (409, "name_taken")
        # A public client's ID entry whose value isn't the meta's: its names stay taken.
        if name == CLIENT_ID_NAME:
            entry = rig.store.entry(name)
            assert entry is not None
            rig.store.put(name, "another-client", entry.binding, meta=entry.meta)
            rig.restart()
            tampered = await rig.refused(url=SERVER_URL, name="notes")
            assert (tampered[0], tampered[1]["reason"]) == (409, "name_taken")
    assert again["stage"] == "registered"
    assert again["names"] == plan["names"]
    assert shown["diff"]["yaml"] == made["diff"]["yaml"]
    assert len(auth.registrations) == 1
    label = "Client secret" if name == SECRET_NAME else "Client ID entry"
    assert [
        label,
        f"{name}, stored by an earlier run; nothing is registered or stored again",
    ] in again["rows"]


@pytest.mark.usefixtures("names", "mcp")
async def test_a_reregistration_registers_a_new_client(
    tmp_path: Path, auth: FakeAuthServer
) -> None:
    """OPS-3 for DCR: --reregister with no client ID registers again under the committed names,
    replacing the credential's client and the stored client-ID entry."""
    auth.registration = "open"
    async with running(tmp_path) as rig:
        plan = await rig.discover(url=SERVER_URL)
        first = await rig.service.register(plan["onboarding"], {})
        rig.policy = rig.merged(first["diff"]["yaml"])
        plan = await rig.discover(url=SERVER_URL, reregister=True)
        made = await rig.service.register(plan["onboarding"], {})
        value = rig.store.get_for_binding(CLIENT_ID_NAME, predicted_binding())
    assert plan["plan"]["registration"] == "dcr"
    assert made["client_id"] != first["client_id"]
    assert "# changed: notes (client_id)" in made["diff"]["yaml"].splitlines()
    replaced = rig.merged(made["diff"]["yaml"]).credentials["notes"]
    assert isinstance(replaced, OAuth2Credential)
    assert (replaced.client_id, replaced.redirect_uri) == (made["client_id"], DCR_REDIRECT)
    assert value.reveal() == made["client_id"]
    assert len(auth.registrations) == 2


# --- the legacy server with no protected-resource metadata (D.2a) --------------------------------


@pytest.mark.usefixtures("names")
async def test_the_legacy_server_without_protected_resource_metadata(
    tmp_path: Path, mcp: McpFake, auth: FakeAuthServer
) -> None:
    mcp.prm = "none"
    mcp.as_metadata = lambda: {**auth.metadata(), "issuer": SERVER_URL}
    async with running(tmp_path) as rig:
        plan = await rig.discover(**PUBLIC)
        made = await rig.service.fragment(plan["onboarding"], {})
    shown = plan["plan"]
    assert (shown["issuer"], shown["issuer_source"]) == (SERVER_URL, "heuristic")
    assert (shown["resource"], shown["resource_metadata"]) == (SERVER_URL, None)
    assert shown["notes"][:2] == ["legacy", "heuristic"]
    assert shown["metadata_url"] == f"https://{MCP}/.well-known/oauth-authorization-server/mcp"
    credential = load_mapping(made["diff"]["yaml"])["credentials"]["notes"]
    assert "resource_metadata" not in credential
    assert credential["extra_params"] == {"resource": SERVER_URL}


@pytest.mark.usefixtures("names")
async def test_a_legacy_server_with_the_issuer_given(
    tmp_path: Path, mcp: McpFake, auth: FakeAuthServer
) -> None:
    mcp.prm = "none"
    async with running(tmp_path) as rig:
        plan = await rig.discover(**PUBLIC, issuer=ISSUER)
    assert (plan["plan"]["issuer"], plan["plan"]["issuer_source"]) == (ISSUER, "given")
    assert [s.path for s in auth.seen] == ["/.well-known/oauth-authorization-server"]


@pytest.mark.usefixtures("names", "auth")
async def test_no_metadata_anywhere(tmp_path: Path, mcp: McpFake) -> None:
    mcp.prm = "none"
    origin = f"https://{MCP}"
    async with running(tmp_path) as rig:
        status, body = await rig.refused(**PUBLIC)
        assert (status, body["reason"]) == (502, "prm_not_found")
        assert body["tried"] == [
            PRM_URL,
            f"{origin}/.well-known/oauth-protected-resource",
            f"{origin}/.well-known/oauth-authorization-server",
            f"{origin}/.well-known/openid-configuration",
            f"{origin}/.well-known/oauth-authorization-server/mcp",
            f"{origin}/.well-known/openid-configuration/mcp",
            f"{origin}/mcp/.well-known/openid-configuration",
        ]
        # A server that answers without a sign-in, with no metadata: add it by hand (SPEC-1).
        mcp.key = None
        status, body = await rig.refused(**PUBLIC)
        assert (status, body["reason"]) == (409, "not_protected")


# --- hostile metadata and challenges (step 5's switches) ------------------------------------------


@pytest.mark.parametrize(
    ("switch", "status", "reason", "fields"),
    [
        (Switch.PRM_RESOURCE_MISMATCH, 502, "prm_resource_mismatch", {}),
        (Switch.PRM_TWO_SERVERS, 409, "as_choice_needed", {"issuers": [ISSUER, OTHER_AS]}),
        (Switch.PRM_DPOP, 502, "dpop_required", {}),
        (Switch.PRIVATE_METADATA, 502, "endpoint_invalid", {}),
        (Switch.TWO_BEARER, 502, "challenge_ambiguous", {}),
    ],
)
@pytest.mark.usefixtures("auth")
async def test_hostile_protected_resource_metadata_or_challenges(
    tmp_path: Path,
    mcp: McpFake,
    names: FakeResolver,
    switch: Switch,
    status: int,
    reason: str,
    fields: dict[str, Any],
) -> None:
    mcp.switches = {switch}
    async with running(tmp_path) as rig:
        found = await rig.refused(**PUBLIC)
    assert found[0] == status
    assert found[1] == {**found[1], "reason": reason, **fields}
    # Nothing past the refusal, and no name but the fakes' was looked up.
    assert {host for host, _ in names.lookups} <= {MCP, AUTH}


@pytest.mark.parametrize(
    ("switch", "reason", "detail"),
    [
        (AuthSwitch.WRONG_ISSUER, "as_issuer_mismatch", None),
        (AuthSwitch.ENDPOINT_LOOPBACK, "endpoint_invalid", "token_endpoint"),
        (AuthSwitch.ENDPOINT_SINGLE_LABEL, "endpoint_invalid", "token_endpoint"),
        (AuthSwitch.PKCE_ABSENT, "pkce_unsupported", None),
        (AuthSwitch.PKCE_PLAIN, "pkce_unsupported", None),
        (AuthSwitch.METADATA_OVERSIZED, "fetch_too_large", AUTH),
        (AuthSwitch.METADATA_NOT_JSON, "fetch_not_json", AUTH),
        (AuthSwitch.METADATA_ARRAY, "fetch_not_json", AUTH),
    ],
)
@pytest.mark.usefixtures("mcp")
async def test_hostile_authorization_server_metadata(
    tmp_path: Path,
    auth: FakeAuthServer,
    names: FakeResolver,
    switch: AuthSwitch,
    reason: str,
    detail: str | None,
) -> None:
    """FM-7's oversized and not-JSON rows among them."""
    auth.switches = {switch}
    async with running(tmp_path) as rig:
        status, body = await rig.refused(**PUBLIC)
    assert (status, body["reason"]) == (502, reason)
    if detail is not None:
        assert detail in body["error"]
    assert {host for host, _ in names.lookups} <= {MCP, AUTH}


@pytest.mark.usefixtures("mcp")
async def test_a_metadata_redirect_is_never_followed(
    tmp_path: Path, auth: FakeAuthServer, names: FakeResolver
) -> None:
    """FM-7: a 3xx on a well-known candidate means "not here" (B.5), so every candidate moves
    on and none is followed; a redirect anywhere else is fetch_redirect."""
    auth.switches = {AuthSwitch.METADATA_REDIRECT}
    async with running(tmp_path) as rig:
        status, body = await rig.refused(**PUBLIC)
        assert (status, body["reason"]) == (502, "as_metadata_not_found")
        redirected = await rig.refused(url=f"https://{MOVED}/mcp", client_id=CLIENT_ID)
    assert redirected[0] == 502
    assert redirected[1]["reason"] == "fetch_redirect"
    assert MOVED in redirected[1]["error"]
    lookups = {host for host, _ in names.lookups}
    assert urlsplit(METADATA_ELSEWHERE).hostname not in lookups
    assert "attacker.example" not in lookups


@pytest.mark.parametrize(
    ("switch", "probes"),
    [
        (Switch.HEADERS_BEFORE_AUTH, 1),
        (Switch.DISCOVER_WITHOUT_AUTH, 1),
        (Switch.GET_405_DELETE_400, 1),
        (Switch.LARGE, 1),
    ],
)
@pytest.mark.usefixtures("names", "auth")
async def test_switches_a_good_discovery_passes(
    tmp_path: Path, mcp: McpFake, switch: Switch, probes: int
) -> None:
    """The probe is a well-formed modern request (SPEC-1): a server that checks headers first
    still answers 401, and one that answers server/discover openly has its metadata found at
    the well-known path."""
    mcp.switches = {switch}
    async with running(tmp_path) as rig:
        plan = await rig.discover(**PUBLIC)
    assert plan["stage"] == "discovered"
    assert sum(1 for r in mcp.received if r.method == "POST") == probes
    if switch == Switch.DISCOVER_WITHOUT_AUTH:
        assert plan["plan"]["scope_source"] == "prm"


@pytest.mark.usefixtures("names", "auth")
async def test_a_legacy_server_earns_one_legacy_probe(tmp_path: Path, mcp: McpFake) -> None:
    mcp.mode = "legacy"
    mcp.switches = {Switch.HEADERS_BEFORE_AUTH}
    async with running(tmp_path) as rig:
        plan = await rig.discover(**PUBLIC)
    assert plan["stage"] == "discovered"
    posts = [r for r in mcp.received if r.method == "POST"]
    assert [r.rpc_method for r in posts] == ["server/discover", "initialize"]


@pytest.mark.usefixtures("mcp")
async def test_an_offered_dpop_is_a_note(
    tmp_path: Path, auth: FakeAuthServer, names: FakeResolver
) -> None:
    auth.switches = {AuthSwitch.DPOP_ALGS}
    async with running(tmp_path) as rig:
        plan = await rig.discover(**PUBLIC)
    assert "dpop" in plan["plan"]["notes"]


# --- the endpoints' and the server's addresses (D.3, X3, Q4) --------------------------------------


@pytest.mark.usefixtures("mcp")
async def test_an_endpoint_on_a_private_address_fails_before_the_commit(
    tmp_path: Path, auth: FakeAuthServer, names: FakeResolver, lines: io.StringIO
) -> None:
    auth.endpoint_base = f"https://{TOKENS}"
    names.answer(TOKENS, ["10.1.2.3"])
    async with running(tmp_path) as rig:
        status, body = await rig.refused(**PUBLIC)
        assert (status, body["reason"]) == (502, "address_refused")
        assert TOKENS in body["error"]
        # Listed in egress_private, it may (A.1's exception).
        raw = rig.policy.model_dump(by_alias=True)
        raw["egress_private"] = [f"{TOKENS}:443"]
        rig.policy = Policy.model_validate(raw)
        plan = await rig.discover(**PUBLIC)
        assert plan["stage"] == "discovered"
        names.answer(TOKENS, TIMEOUT)
        rig.policy = example_policy()
        await rig.service.cancel(plan["onboarding"])
        status, body = await rig.refused(**PUBLIC)
        assert (status, body["reason"]) == (502, "resolve_failed")
    [refused] = [r for r in records(lines) if r["event"] == "address_refused"]
    assert refused == {
        **refused,
        "purpose": "discovery",
        "host": TOKENS,
        "port": 443,
        "verdict": "private",
    }


@pytest.mark.usefixtures("mcp", "auth")
async def test_a_private_server_needs_allow_private(
    tmp_path: Path, names: FakeResolver, lines: io.StringIO
) -> None:
    """Q4: only the typed server's host:port, and only its probe and protected-resource
    fetches; fragment 1 pins the choice in egress_private."""
    async with running(tmp_path) as rig:
        status, body = await rig.refused(url=LAN_URL, client_id=CLIENT_ID)
        assert (status, body["reason"]) == (502, "address_refused")
        plan = await rig.discover(url=LAN_URL, client_id=CLIENT_ID, allow_private=True)
        made = await rig.service.fragment(plan["onboarding"], {})
    assert plan["plan"]["resource"] == LAN_URL
    fragment = load_mapping(made["diff"]["yaml"])
    assert fragment["egress_private"] == [f"{LAN}:443"]
    assert made["next"][-1]["command"] == (
        f"zoeymcp login --mcp {LAN_URL} --name lan --allow-private"
    )
    started = [r for r in records(lines) if r["event"] == "onboard_started"]
    assert [r["allow_private"] for r in started] == [False, True]
    assert {r["host"] for r in started} == {LAN}


# --- an operator's own proxy (D.11, FM-11) --------------------------------------------------------


@pytest.mark.usefixtures("mcp", "auth")
async def test_an_own_proxy_refusal_and_its_resume(
    tmp_path: Path, world: World, names: FakeResolver, lines: io.StringIO
) -> None:
    beyond = FakeResolver()
    for name, port in world.ports.items():
        beyond.serve(name, port)
    proxy = ConnectProxy(refuse={AUTH}, names=beyond)
    with serve_proxy(proxy) as proxy_url:
        async with running(tmp_path, proxy_url) as rig:
            status, body = await rig.refused(**PUBLIC)
            again = await rig.refused(**PUBLIC, client_name="Other name")
            proxy.refuse.clear()
            plan = await rig.discover(**PUBLIC)
    assert (status, body["reason"]) == (502, "proxy_refused")
    # The example policy's emitted file defines zoeymcp_port_443 already.
    expected = allow_hosts([(AUTH, 443), (MCP, 443)], {}, emitted_ports=[443]).answer()
    assert body == {
        "host": AUTH,
        "port": 443,
        "status": 403,
        "next": [expected],
        "error": f"Your egress proxy refused the vault's connection to {AUTH}. Allow the hosts "
        "listed here in it for the vault, then run the same command again.",
        "reason": "proxy_refused",
    }
    assert expected["hosts"] == [f"{AUTH}:443", f"{MCP}:443"]
    assert len(expected["squid"]) == 4
    assert all("zoeymcp_src_vault" in line for line in expected["squid"][1::2])
    # A resume with other options is refused (OPS-8); with the same ones it carries on.
    assert (again[0], again[1]["reason"]) == (409, "onboarding_options_changed")
    assert plan["stage"] == "discovered"
    # Through a proxy nothing resolves here: the proxy judges every address (B.3).
    assert names.lookups == []
    assert proxy.targets[0] == f"{MCP}:443"
    assert f"{AUTH}:443" in proxy.targets
    [blocked] = [r for r in records(lines) if r["event"] == "onboard_blocked"]
    assert blocked == {**blocked, "host": AUTH, "port": 443, "needed": 2}
    fetched = [r for r in records(lines) if r["event"] == "discovery_fetch"]
    assert {r["via"] for r in fetched} == {"proxy"}


# --- the built-in egress role (I.3, TI-10; J5's built-in variant) --------------------------------


def unreachable(request: httpx.Request) -> httpx.Response:
    raise AssertionError("the vault's own clients aren't used here")


def role_vault(tmp_path: Path) -> VaultApp:
    """The vault whose allowlist endpoint the role polls, on the example policy."""
    state = tmp_path / "vault"
    state.mkdir(mode=0o700)
    store = SecretStore(state, KEYS)
    store.load()
    client = httpx.AsyncClient(transport=httpx.MockTransport(unreachable))
    return VaultApp(example_policy(), store, KEYS, client=client, environ={})


@asynccontextmanager
async def egress_role(
    vault: VaultApp, proxy: ConnectProxy, *, polls: bool = True, applying: float = 0.0
) -> AsyncIterator[list[str]]:
    """The role as the vault meets it: it long-polls the allowlists with its key and, on each
    200, lets through what the new list holds (the proxy's ``allow``, the role's own parser
    reading the vault's answer), then polls again naming the digest it holds (I.4). Applying a
    list takes ``applying`` seconds, so a vault that didn't wait for the role's next poll would
    CONNECT before the list changed. Without ``polls`` it fetches once and stops. Yields each
    digest it applied."""
    applied: list[str] = []
    transport = httpx.ASGITransport(app=vault, client=("172.30.9.2", 40000))

    async def poll(client: httpx.AsyncClient) -> None:
        held: str | None = None
        while True:
            headers = {EGRESS_HEADER: KEYS.egress_key(1)}
            path = ALLOWLIST_PATH.text
            if held is not None:
                headers["If-None-Match"] = f'"{held}"'
                path += "?wait=25"
            answer = await client.get(path, headers=headers)
            if answer.status_code == 200:
                held, lists, _ = parse_document(answer.content)
                await asyncio.sleep(applying)
                proxy.allow = set(lists[egresslist.VAULT])
                applied.append(held)
            if not polls:
                return

    async with httpx.AsyncClient(transport=transport, base_url="http://vault") as client:
        task = asyncio.create_task(poll(client))
        with anyio.fail_after(10):
            while not applied:
                await asyncio.sleep(0.01)
        try:
            yield applied
        finally:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
    await vault.aclose()


def proxy_through(world: World, **kwargs: Any) -> ConnectProxy:
    beyond = FakeResolver()
    for name, port in world.ports.items():
        beyond.serve(name, port)
    return ConnectProxy(names=beyond, **kwargs)


@pytest.mark.usefixtures("mcp", "auth")
async def test_through_the_role_an_onboarding_needs_no_proxy_edit(
    tmp_path: Path, world: World, names: FakeResolver, lines: io.StringIO
) -> None:
    """J5's built-in variant (I.3): each host joins the allowance before the vault connects to
    it, the role fetches the widened list, and the CONNECT passes. The role takes its time to
    apply each list, so the CONNECT passes only because the vault waits for the role's next
    poll to name the widened digest. Once the onboarding has its fragment, its hosts leave the
    list."""
    proxy = proxy_through(world, allow=set())
    vault = role_vault(tmp_path)
    with serve_proxy(proxy) as proxy_url:
        async with (
            egress_role(vault, proxy, applying=0.3) as applied,
            running(tmp_path, proxy_url, egress=vault, kind="role") as rig,
        ):
            started = len(applied)
            plan = await rig.discover(**PUBLIC)
            assert plan["stage"] == "discovered"
            widened = list(applied)
            made = await rig.service.fragment(plan["onboarding"], {})
            policy_only = egresslist.digest(egresslist.derive(rig.policy))
            with anyio.fail_after(5):
                while applied[-1] != policy_only:
                    await asyncio.sleep(0.01)
    # The server's host, then the authorization server's, each fetched before its CONNECT.
    assert len(widened) >= started + 2
    assert proxy.targets[0] == f"{MCP}:443"
    assert f"{AUTH}:443" in proxy.targets
    assert plan["allowance"] == [f"{AUTH}:443", f"{MCP}:443"]
    assert proxy.allow is not None
    assert f"{AUTH}:443" not in proxy.allow
    assert f"{MCP}:443" not in proxy.allow
    # No proxy round, and no proxy file to update after the commit.
    assert "onboard_blocked" not in events(lines)
    assert "update_proxy_allowlist" not in [step["do"] for step in made["next"]]
    # Through a proxy nothing resolves here: the role judges every address (B.3).
    assert names.lookups == []


@pytest.mark.usefixtures("mcp", "auth")
async def test_a_connect_the_role_refuses_is_egress_refused(
    tmp_path: Path,
    world: World,
    names: FakeResolver,
    lines: io.StringIO,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A role that stopped polling never fetches the widened list: after ALLOWANCE_WAIT the
    vault connects anyway, the role refuses, and the onboarding ends ``egress_refused``,
    naming the host, with no proxy lines to add (I.3)."""
    monkeypatch.setattr(onboard, "ALLOWANCE_WAIT", 0.2)
    proxy = proxy_through(world, allow=set())
    vault = role_vault(tmp_path)
    with serve_proxy(proxy) as proxy_url:
        async with (
            egress_role(vault, proxy, polls=False),
            running(tmp_path, proxy_url, egress=vault, kind="role") as rig,
        ):
            status, body = await rig.refused(**PUBLIC)
            assert rig.service.owned(CLI_OWNER) is None
    assert (status, body["reason"]) == (502, "egress_refused")
    # The role's own status: 403, a host its lists don't hold (I.4).
    assert (body["host"], body["port"], body["status"]) == (MCP, 443, 403)
    assert "next" not in body
    assert body["error"] == CATALOGUE["egress_refused"].text.format(host=MCP)
    assert proxy.targets == [f"{MCP}:443"]
    refused = [r for r in records(lines) if r["event"] == "onboard_refused"]
    assert [(r["reason"], r["host"]) for r in refused] == [("egress_refused", MCP)]
    assert "onboard_blocked" not in events(lines)


@pytest.mark.usefixtures("mcp", "auth")
async def test_allow_private_through_the_role_is_refused(
    tmp_path: Path, world: World, names: FakeResolver, lines: io.StringIO
) -> None:
    """TI-10: the role can't scope a private exception to one onboarding's requests, so the
    tick is refused before anything is sent; without the role it is the vault's own (B.2)."""
    proxy = proxy_through(world, allow=set())
    vault = role_vault(tmp_path)
    with serve_proxy(proxy) as proxy_url:
        async with (
            egress_role(vault, proxy),
            running(tmp_path, proxy_url, egress=vault, kind="role") as rig,
        ):
            status, body = await rig.refused(url=LAN_URL, client_id=CLIENT_ID, allow_private=True)
    assert (status, body["reason"]) == (409, "private_needs_direct")
    assert proxy.targets == []
    assert "onboard_started" not in events(lines)


@pytest.mark.usefixtures("mcp", "auth")
async def test_a_role_that_never_polled_is_egress_refused(
    tmp_path: Path,
    world: World,
    names: FakeResolver,
    lines: io.StringIO,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With egress_proxy_kind role the vault waits ALLOWANCE_WAIT for a role it hasn't seen
    (one still starting up), then connects: a role that never fetched its lists holds none,
    refuses the CONNECT, and the onboarding ends ``egress_refused``, with no Squid lines to add
    and nothing blocked (I.3)."""
    monkeypatch.setattr(onboard, "ALLOWANCE_WAIT", 0.2)
    proxy = proxy_through(world, allow=set())
    vault = role_vault(tmp_path)
    with serve_proxy(proxy) as proxy_url:
        async with running(tmp_path, proxy_url, egress=vault, kind="role") as rig:
            status, body = await rig.refused(**PUBLIC)
            assert rig.service.owned(CLI_OWNER) is None
    await vault.aclose()
    assert (status, body["reason"]) == (502, "egress_refused")
    assert (body["host"], body["port"], body["status"]) == (MCP, 443, 403)
    assert "next" not in body
    assert proxy.targets == [f"{MCP}:443"]
    assert "onboard_blocked" not in events(lines)


@pytest.mark.usefixtures("mcp", "auth")
async def test_an_own_proxy_stays_the_operators_while_a_role_polls(
    tmp_path: Path, world: World, names: FakeResolver, lines: io.StringIO
) -> None:
    """egress_proxy_kind own (the default) is the operator's proxy whatever fetches the vault's
    lists: with a role polling them (as one serving bridges would), the own proxy's refusal
    still blocks the onboarding with the Squid lines to add (D.11), and the vault never waits
    for the role."""
    own = proxy_through(world, refuse={AUTH})
    vault = role_vault(tmp_path)
    with serve_proxy(own) as proxy_url:
        async with (
            egress_role(vault, ConnectProxy()) as applied,
            running(tmp_path, proxy_url, egress=vault) as rig,
        ):
            status, body = await rig.refused(**PUBLIC)
            assert applied
    assert (status, body["reason"]) == (502, "proxy_refused")
    assert body["host"] == AUTH
    assert body["next"][0]["do"] == "allow_hosts"
    assert f"{AUTH}:443" in own.targets
    assert "onboard_blocked" in events(lines)


@pytest.mark.usefixtures("names")
async def test_an_own_proxy_refusal_on_a_port_the_emitted_file_lacks(
    tmp_path: Path, world: World, mcp: McpFake
) -> None:
    """8a1's note for D.11: the emitted file defines a port ACL only for the policy's ports,
    so the answer defines one for an authorization server on another port."""
    issuer = f"https://{AUTH}:8443"
    fake = FakeAuthServer(client_id=CLIENT_ID, issuer=issuer, registration="none")
    world.auth.app = fake.app()
    mcp.authorization_servers = [issuer]
    beyond = FakeResolver()
    for name, port in world.ports.items():
        beyond.serve(name, port)
    proxy = ConnectProxy(refuse={AUTH}, names=beyond)
    with serve_proxy(proxy) as proxy_url:
        async with running(tmp_path, proxy_url) as rig:
            status, body = await rig.refused(**PUBLIC)
    assert (status, body["reason"], body["port"]) == (502, "proxy_refused", 8443)
    [step] = body["next"]
    assert step["hosts"] == [f"{AUTH}:8443", f"{MCP}:443"]
    # The example policy's emitted file has zoeymcp_port_443 only.
    assert [line for line in step["squid"] if line.startswith("acl zoeymcp_port_")] == [
        "acl zoeymcp_port_8443 port 8443"
    ]
    assert step["squid"][0] == "acl zoeymcp_port_8443 port 8443"
    assert any(line.endswith("zoeymcp_port_8443 !zoeymcp_private_dst") for line in step["squid"])


# --- names, owners and the draft check (D.8, X24, OPS-5) ------------------------------------------


@pytest.mark.usefixtures("names", "mcp", "auth")
async def test_names_taken_by_the_policy_the_store_or_another_onboarding(tmp_path: Path) -> None:
    async with running(tmp_path) as rig:
        for given in ({"name": "broker-mcp"}, {"route": "stats"}, {"server": "mail"}):
            status, body = await rig.refused(**PUBLIC, **given)
            assert (status, body["reason"]) == (409, "name_taken")
        rig.store.put("notes-client-id", "x", {"origins": ["https://x.example:443"]})
        status, body = await rig.refused(**PUBLIC, name="notes")
        assert (status, body["reason"]) == (409, "name_taken")
        # Defaults skip what is taken (OPS-15).
        plan = await rig.discover(**PUBLIC)
        assert plan["names"] == {**plan["names"], "credential": "notes-2", "source": "label"}
        # FM-10 across owners: a portal session can't take the CLI's names.
        status, body = await rig.refused(SESSION, **PUBLIC, name="notes-2")
        assert (status, body["reason"]) == (409, "name_taken")
        for bad in ({"name": "Notes"}, {"credential": "a b"}):
            status, body = await rig.refused(**PUBLIC, **bad)
            assert (status, body["reason"]) == (400, "bad_body")


@pytest.mark.usefixtures("names", "mcp", "auth")
async def test_another_owners_onboarding_answers_as_an_unknown_one(tmp_path: Path) -> None:
    """X24."""
    async with running(tmp_path) as rig:
        plan = await rig.discover(SESSION, **PUBLIC)
        onboarding = plan["onboarding"]
        for call in (
            rig.service.register(onboarding, {}),
            rig.service.fragment(onboarding, {}),
            rig.service.cancel(onboarding),
            rig.service.fragment("no-such-onboarding", {}),
        ):
            status, body = await refusal_of(call)
            assert (status, body["reason"]) == (404, "onboarding_unknown")
        made = await rig.service.fragment(onboarding, {}, owner=SESSION)
        assert made["stage"] == "registered"
        rig.service.cancel_owner(SESSION)
        status, body = await refusal_of(rig.service.fragment(onboarding, {}, owner=SESSION))
        assert (status, body["reason"]) == (404, "onboarding_unknown")


@pytest.mark.usefixtures("names", "mcp", "auth")
async def test_a_draft_check_error_shows_before_registering(tmp_path: Path) -> None:
    """OPS-5: the plan shows the merged policy's error, and nothing is stored."""
    unlisted = "http://localhost:9999/oauth/callback/notes"
    async with running(tmp_path) as rig:
        plan = await rig.discover(**CONFIDENTIAL, redirect_uri=unlisted)
        status, body = await refusal_of(
            rig.service.register(plan["onboarding"], {"client_secret": SECRET})
        )
    errors = [f for f in plan["draft_check"] if f["level"] == "error"]
    assert errors
    assert plan["next"] == [
        {
            "do": "fix_policy",
            "label": f"Fix the policy first: check finds {len(errors)} error(s) with this server "
            "merged",
        }
    ]
    assert (status, body["reason"]) == (422, "diff_invalid")
    assert rig.store.names() == []


@pytest.mark.usefixtures("names", "mcp", "auth")
async def test_a_final_check_that_fails_deletes_the_secret_it_stored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, lines: io.StringIO
) -> None:
    """OPS-5: the policy changes between the draft check and the final one."""
    async with running(tmp_path) as rig:
        plan = await rig.discover(**CONFIDENTIAL)
        raw = rig.policy.model_dump(by_alias=True)
        clash = {**raw["routes"][0], "name": "clash", "prefix": "/notes"}
        moved_on = Policy.model_validate({**raw, "routes": [*raw["routes"], clash]})
        put = rig.store.put

        def put_then_reload(*args: Any, **kwargs: Any) -> None:
            put(*args, **kwargs)
            rig.policy = moved_on

        monkeypatch.setattr(rig.store, "put", put_then_reload)
        status, body = await refusal_of(
            rig.service.register(plan["onboarding"], {"client_secret": SECRET})
        )
    assert (status, body["reason"]) == (422, "diff_invalid")
    assert body["error"].endswith(
        "the client secret this run stored was deleted), so no fragment is shown."
    )
    assert rig.store.names() == []
    assert [e for e in events(lines) if e.startswith("secret_")] == ["secret_set", "secret_deleted"]


@pytest.mark.usefixtures("names", "mcp", "auth")
async def test_a_write_kept_only_in_memory_is_deleted_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """OPS-5: the store can't write its file, so register is refused, and the entry it kept in
    memory goes too: a retry doesn't meet name_taken on it."""
    writes = FailingWrites(monkeypatch)
    async with running(tmp_path) as rig:
        plan = await rig.discover(**CONFIDENTIAL)
        writes.failing = True
        status, body = await refusal_of(
            rig.service.register(plan["onboarding"], {"client_secret": SECRET})
        )
        held = rig.store.names()
        writes.failing = False
        made = await rig.service.register(plan["onboarding"], {"client_secret": SECRET})
    assert (status, body["reason"], body["secret_deleted"]) == (500, "not_written", True)
    assert body["error"] == CATALOGUE["not_written"].text
    assert held == []
    assert made["secret_stored"] is True
    assert rig.store.names() == [SECRET_NAME]
    assert not rig.store.dirty


@pytest.mark.usefixtures("names", "mcp", "auth")
async def test_an_onboarding_that_expires_while_its_secret_is_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, lines: io.StringIO
) -> None:
    """OPS-5: the onboarding ended during the write, so it can't be registered; the secret it
    wrote is deleted again, and the same command starts afresh."""
    now = [time.monotonic()]
    put = secretops.put
    late = [True]

    async def put_slowly(*args: Any, **kwargs: Any) -> Any:
        written = await put(*args, **kwargs)
        if late[0]:
            now[0] += 1801
        return written

    monkeypatch.setattr(secretops, "put", put_slowly)
    async with running(tmp_path, clock=lambda: now[0]) as rig:
        plan = await rig.discover(**CONFIDENTIAL)
        status, body = await refusal_of(
            rig.service.register(plan["onboarding"], {"client_secret": SECRET})
        )
        held = rig.store.names()
        late[0] = False
        again = await rig.discover(**CONFIDENTIAL)
        made = await rig.service.register(again["onboarding"], {"client_secret": SECRET})
    assert (status, body["reason"], body["secret_deleted"]) == (404, "onboarding_unknown", True)
    assert held == []
    assert (again["names"], made["secret_stored"]) == (plan["names"], True)
    assert rig.store.names() == [SECRET_NAME]
    assert [e for e in events(lines) if e.startswith("secret_")] == [
        "secret_set",
        "secret_deleted",
        "secret_set",
    ]


# --- after a restart (D.7 step 6, FM-2, MISS-14) --------------------------------------------------


@pytest.mark.usefixtures("names", "mcp")
async def test_after_a_restart_the_same_run_shows_fragment_1_again(
    tmp_path: Path, auth: FakeAuthServer, lines: io.StringIO
) -> None:
    """The onboarding is gone, and the secret it stored stays. The same command, or one naming
    the credential with no client ID, finds the entry by its meta, rediscovers, and answers
    fragment 1 again, registered at once: no second registration and no second write."""
    async with running(tmp_path) as rig:
        plan = await rig.discover(**CONFIDENTIAL)
        made = await rig.service.register(plan["onboarding"], {"client_secret": SECRET})
        rig.restart()
        again = await rig.discover(**CONFIDENTIAL)
        shown = await rig.service.fragment(again["onboarding"], {})
        # The same run once more carries on with it.
        resumed = await rig.discover(**CONFIDENTIAL)
        status, refused = await refusal_of(
            rig.service.register(again["onboarding"], {"client_secret": SECRET})
        )
        rig.restart()
        named = await rig.discover(url=SERVER_URL, name="notes")
        named_shown = await rig.service.fragment(named["onboarding"], {})
    assert (again["stage"], again["names"]) == ("registered", plan["names"])
    kept = [
        "Client secret",
        f"{SECRET_NAME}, stored by an earlier run; nothing is registered or stored again",
    ]
    assert kept in again["rows"]
    assert ["Client", f"{CLIENT_ID} (given)"] in again["rows"]
    assert again["next"][0]["do"] == "check_fragment"
    assert shown["diff"]["yaml"] == made["diff"]["yaml"]
    assert (shown["secret_stored"], shown["secret_name"]) == (True, SECRET_NAME)
    assert (resumed["onboarding"], resumed["stage"]) == (again["onboarding"], "registered")
    # Its secret is stored: register takes none.
    assert (status, refused["reason"]) == (400, "bad_body")
    # The client ID from the entry's meta, shown as such (D.7 step 6).
    assert named["stage"] == "registered"
    assert ["Client", f"{CLIENT_ID} (from the stored client secret's entry)"] in named["rows"]
    assert named_shown["diff"]["yaml"] == made["diff"]["yaml"]
    assert rig.store.names() == [SECRET_NAME]
    assert auth.registrations == []
    assert [e for e in events(lines) if e.startswith("secret_")] == ["secret_set"]
    registered = [r for r in records(lines) if r["event"] == "onboard_registered"]
    assert [r["secret_stored"] for r in registered] == [True, False, False]


@pytest.mark.usefixtures("names", "mcp", "auth")
async def test_a_kept_secret_bound_otherwise_keeps_its_names_taken(tmp_path: Path) -> None:
    """MISS-14: only the authenticated binding the fresh discovery predicts lets a run take a
    kept secret on; the clear meta only finds it."""
    meta = {
        "onboarded": AUTH,
        "resource": SERVER_URL,
        "client_id": CLIENT_ID,
        "client_secret_expires_at": None,
    }
    predicted = oauth_binding(f"{ISSUER}/token", [f"https://{MCP}"])
    elsewhere = oauth_binding("https://tokens.elsewhere.example/token", [f"https://{MCP}"])
    async with running(tmp_path) as rig:
        # Bound to another token endpoint.
        rig.store.put(SECRET_NAME, SECRET, elsewhere, meta=meta)
        given = await rig.refused(**CONFIDENTIAL, name="notes")
        default = await rig.refused(**CONFIDENTIAL)
        # Its clear binding edited to the predicted one: it fails authentication.
        document = json.loads(rig.store.path.read_bytes())
        document["entries"][SECRET_NAME]["binding"] = predicted
        rig.store.path.write_bytes(json.dumps(document).encode() + b"\n")
        rig.store.load()
        tampered = await rig.refused(**CONFIDENTIAL, name="notes")
        # A meta naming another resource, or a run giving another client ID: not this one's.
        rig.store.put(SECRET_NAME, SECRET, predicted, meta={**meta, "resource": LAN_URL})
        other_resource = await rig.refused(**CONFIDENTIAL, name="notes")
        defaulted = await rig.discover(**CONFIDENTIAL)
        await rig.service.cancel(defaulted["onboarding"])
        rig.store.put(SECRET_NAME, SECRET, predicted, meta=meta)
        other_client = await rig.refused(**{**CONFIDENTIAL, "client_id": "another"}, name="notes")
    for status, body in (given, default, tampered, other_resource, other_client):
        assert (status, body["reason"]) == (409, "name_taken")
        assert "notes" in body["error"]
    assert defaulted["names"]["credential"] == "notes-2"
    assert rig.store.names() == [SECRET_NAME]


# --- time limits (FM-5, FM-6) ---------------------------------------------------------------------


@pytest.mark.usefixtures("names", "mcp")
async def test_stalled_metadata(
    tmp_path: Path, auth: FakeAuthServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    """FM-5: one fetch ends at its own limit, and a whole discovery at the discovery's."""
    auth.switches = {AuthSwitch.STALL}
    monkeypatch.setattr(fetch, "FETCH_TIMEOUT", 0.5)
    async with running(tmp_path) as rig:
        started = time.monotonic()
        status, body = await rig.refused(**PUBLIC)
        took = time.monotonic() - started
        assert (status, body["reason"]) == (502, "fetch_failed")
        assert body["error"] == f"The host {AUTH} didn't answer as needed (timeout)."
        assert took < 5
        monkeypatch.setattr(fetch, "FETCH_TIMEOUT", 10.0)
        monkeypatch.setattr(fetch, "DISCOVERY_DEADLINE", 0.8)
        started = time.monotonic()
        status, body = await rig.refused(**PUBLIC)
        assert (status, body["reason"]) == (502, "fetch_failed")
        assert time.monotonic() - started < 5


@pytest.mark.usefixtures("names", "mcp")
async def test_trickling_metadata(
    tmp_path: Path, auth: FakeAuthServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    """FM-6: the per-fetch total deadline ends it, not a per-read timeout."""
    auth.switches = {AuthSwitch.TRICKLE}
    auth.trickle_interval = 0.05
    monkeypatch.setattr(fetch, "FETCH_TIMEOUT", 0.6)
    async with running(tmp_path) as rig:
        started = time.monotonic()
        status, body = await rig.refused(**PUBLIC)
    assert (status, body["reason"]) == (502, "fetch_failed")
    assert "timeout" in body["error"]
    assert time.monotonic() - started < 5


# --- the request and the table's ends -------------------------------------------------------------


@pytest.mark.parametrize(
    ("body", "reason"),
    [
        ({}, "bad_body"),
        ({"url": SERVER_URL, "extra": 1}, "bad_body"),
        ({"url": 1}, "bad_body"),
        ({"url": SERVER_URL, "allow_private": "yes"}, "bad_body"),
        ({"url": "http://mcp.notes.example/mcp"}, "url_invalid"),
        ({"url": f"{SERVER_URL}?a=1"}, "url_invalid"),
        ({"url": "https://10.0.0.1/mcp"}, "url_invalid"),
        ({"url": SERVER_URL, "issuer": "https://auth.notes.example/?x=1"}, "url_invalid"),
        ({"url": SERVER_URL, "client_id": "a b"}, "bad_body"),
        ({"url": SERVER_URL, "client_id": "a$b"}, "bad_body"),
        ({"url": SERVER_URL, "client_id": "x" * 513}, "bad_body"),
        ({"url": SERVER_URL, "client_auth": "jwt"}, "bad_body"),
        ({"url": SERVER_URL, "client_id": "c", "client_auth": "basic"}, "bad_body"),
        ({"url": SERVER_URL, "secret_given": True}, "bad_body"),
        ({"url": SERVER_URL, "client_name": ""}, "bad_body"),
        ({"url": SERVER_URL, "client_name": "x" * 65}, "bad_body"),
        ({"url": SERVER_URL, "redirect_uri": "http://127.0.0.1/cb/$x"}, "bad_body"),
    ],
)
async def test_a_request_that_cant_be_onboarded(
    tmp_path: Path, names: FakeResolver, body: dict[str, Any], reason: str
) -> None:
    async with running(tmp_path) as rig:
        status, answer = await refusal_of(rig.service.discover(body))
    assert (status, answer["reason"]) == (CATALOGUE[reason].status, reason)
    assert names.lookups == []
    assert len(rig.service._table) == 0


@pytest.mark.usefixtures("names", "mcp", "auth")
async def test_cancel_and_the_ends_logged(tmp_path: Path, lines: io.StringIO) -> None:
    async with running(tmp_path) as rig:
        plan = await rig.discover(**PUBLIC)
        await rig.service.cancel(plan["onboarding"])
        status, body = await refusal_of(rig.service.cancel(plan["onboarding"]))
        assert (status, body["reason"]) == (404, "onboarding_unknown")
        plan = await rig.discover(**PUBLIC)
        made = await rig.service.fragment(plan["onboarding"], {})
        # Committed: the next call finds the credential in the running policy (D.8).
        rig.policy = rig.merged(made["diff"]["yaml"])
        status, body = await refusal_of(rig.service.fragment(plan["onboarding"], {}))
        assert (status, body["reason"]) == (404, "onboarding_unknown")
    ended = [r["why"] for r in records(lines) if r["event"] == "onboard_ended"]
    assert ended == ["cancelled", "registered"]
    # The onboarding's ID is never logged (M.4).
    assert plan["onboarding"] not in lines.getvalue()


@pytest.mark.usefixtures("names", "mcp", "auth")
async def test_each_fetch_is_logged_without_a_path(tmp_path: Path, lines: io.StringIO) -> None:
    async with running(tmp_path) as rig:
        await rig.discover(**PUBLIC)
    fetched = [r for r in records(lines) if r["event"] == "discovery_fetch"]
    assert [(r["fetch_kind"], r["host"], r["port"], r["status"], r["via"]) for r in fetched] == [
        ("probe", MCP, 443, 401, "direct"),
        ("prm", MCP, 443, 200, "direct"),
        ("as", AUTH, 443, 200, "direct"),
    ]
    assert fetched[0]["bytes"] == 0
    assert all(r["bytes"] > 0 for r in fetched[1:])
    [planned] = [r for r in records(lines) if r["event"] == "onboard_planned"]
    assert planned == {
        **planned,
        "host": MCP,
        "issuer": AUTH,
        "require_iss": True,
        "registration": "given",
        "auth": "none",
        "scopes": 2,
    }
    assert "/.well-known" not in lines.getvalue()


# --- the second run (D.12, OPS-13, OPS-14) --------------------------------------------------------

NEW_CLIENT = "notes-new-client"
NEW_SECRET = "onboard-new-secret-0002"


async def committed_public(rig: Rig) -> dict[str, Any]:
    """J1 up to the commit: a given public client's fragment 1, merged into the policy."""
    plan = await rig.discover(**PUBLIC)
    made = await rig.service.fragment(plan["onboarding"], {})
    rig.policy = rig.merged(made["diff"]["yaml"])
    return made


def changed_lines(text: str) -> list[str]:
    """A re-registration fragment's comments naming each changed field."""
    return [line for line in text.splitlines() if line.startswith("# changed:")]


def with_credential(rig: Rig, **changes: Any) -> None:
    """The committed notes credential edited by hand, as the operator's policy holds it."""
    raw = rig.policy.model_dump(mode="json", by_alias=True, exclude_defaults=True)
    raw["credentials"]["notes"] = {**raw["credentials"]["notes"], **changes}
    rig.policy = Policy.model_validate(raw)


@pytest.mark.usefixtures("names", "mcp")
async def test_the_second_run_compares_and_stores_nothing(
    tmp_path: Path, auth: FakeAuthServer, lines: io.StringIO
) -> None:
    """D.12 steps 1 and 2: the URL a running oauth2 credential names starts no onboarding; it is
    rediscovered with the probe and GETs alone, compared, and answered with what is next."""
    async with running(tmp_path) as rig:
        await committed_public(rig)
        before = len(records(lines))
        again = await rig.discover(**PUBLIC)
        # A run naming nothing, or the same names, is the same second run.
        assert (await rig.discover(url=SERVER_URL, name="notes"))["stage"] == "committed"
        status, refused = await rig.refused(url=SERVER_URL, name="other")
        assert (status, refused["reason"]) == (400, "bad_body")
        assert "credential notes, route notes and server notes" in refused["detail"]
        # A refresh token already held: the second run doesn't sign in (OPS-13).
        slot = derive_binding(rig.policy, "notes-refresh")
        rig.store.put("notes-refresh", "rt-notes-0001", slot)
        held = await rig.discover(**PUBLIC)
        assert len(rig.service._table) == 0
    assert (again["stage"], again["names"]) == (
        "committed",
        {"credential": "notes", "route": "notes", "server": "notes", "source": "given"},
    )
    assert again["token"] == "none"
    assert again["plan"]["token_endpoint"] == f"{ISSUER}/token"
    assert again["plan"]["client_auth"] == "none"
    assert ["Token endpoint", f"{ISSUER}/token"] in again["rows"]
    review = [
        {
            "do": "choose",
            "label": "Choose its tools",
            "command": "zoeymcp review notes --via vault --choose --suggest",
            "via": "exec",
            "redirect": " > notes.choices",
        },
        {
            "do": "make_fragment",
            "label": "Edit notes.choices (skip, allow, approve or decline on each line; decline "
            "the tools you leave out), then make fragment 2",
            "command": "zoeymcp review notes --via vault --choices -",
            "via": "exec",
            "piped": True,
            "redirect": " < notes.choices > onboard-notes-2.yaml",
        },
    ]
    assert again["next"] == [
        {"do": "connect", "label": "Sign in", "command": "zoeymcp login notes", "via": "exec"},
        *review,
    ]
    assert (held["token"], held["next"]) == ("stored", review)
    assert auth.registrations == []
    assert rig.store.names() == ["notes-refresh"]
    later = records(lines)[before:]
    fetched = [r["fetch_kind"] for r in later if r["event"] == "discovery_fetch"]
    assert fetched[:3] == ["probe", "prm", "as"]
    # The first onboarding ends as its credential is found committed (D.8).
    ended = [r["why"] for r in later if r["event"] == "onboard_ended"]
    assert ended == ["registered", "compared", "compared", "compared"]
    assert "onboard_planned" not in [r["event"] for r in later]


@pytest.mark.usefixtures("names", "mcp", "auth")
async def test_the_second_run_rediscovers_over_an_earlier_plan(
    tmp_path: Path, lines: io.StringIO
) -> None:
    """D.12 step 1: the owner's --plan-only run of the URL from before the commit is no plan to
    compare against; it ends, and the second run discovers afresh."""
    async with running(tmp_path) as rig:
        await committed_public(rig)
        committed = rig.policy
        rig.restart()
        rig.policy = example_policy()
        planned = await rig.discover(**PUBLIC)
        rig.policy = committed
        before = len(records(lines))
        again = await rig.discover(**PUBLIC)
        assert len(rig.service._table) == 0
    assert (planned["stage"], again["stage"]) == ("discovered", "committed")
    later = records(lines)[before:]
    assert [(r["event"], r.get("why")) for r in later[:2]] == [
        ("onboard_ended", "cancelled"),
        ("onboard_started", None),
    ]
    fetched = [r["fetch_kind"] for r in later if r["event"] == "discovery_fetch"]
    assert fetched[:3] == ["probe", "prm", "as"]


@pytest.mark.usefixtures("names", "mcp", "auth")
async def test_a_committed_field_that_differs_is_named(tmp_path: Path, lines: io.StringIO) -> None:
    """GR-26: a hand edit between the commits is named by its field, never its value, and the
    answer says how to register again (OPS-3)."""
    async with running(tmp_path) as rig:
        await committed_public(rig)
        with_credential(rig, token_url=f"{ISSUER}/edited-token", require_iss=False)
        status, body = await rig.refused(**PUBLIC)
        assert len(rig.service._table) == 0
    assert (status, body["reason"]) == (409, "onboarding_mismatch")
    assert body["fields"] == ["credentials.notes.token_url", "credentials.notes.require_iss"]
    assert "credentials.notes.token_url, credentials.notes.require_iss" in body["error"]
    assert "edited-token" not in json.dumps(body)
    assert body["next"] == [
        {
            "do": "onboard_again",
            "label": "Register a new client",
            "command": f"zoeymcp login --mcp {SERVER_URL} --reregister",
            "via": "exec",
        }
    ]
    [refused] = [r for r in records(lines) if r["event"] == "onboard_refused"]
    assert (refused["reason"], refused["host"]) == ("onboarding_mismatch", MCP)


@pytest.mark.usefixtures("mcp", "auth")
@pytest.mark.parametrize("name", ["compose.hardened.yaml", "compose.yaml"])
async def test_the_shipped_static_key_notes_is_already_configured(
    tmp_path: Path, names: FakeResolver, name: str
) -> None:
    """OPS-14: J1 walked verbatim meets the compose files' example notes server, whose route has a
    static key; nothing is fetched."""
    async with running(tmp_path) as rig:
        rig.policy = inline_policy(compose(name), name)
        status, body = await rig.refused(**PUBLIC)
        assert len(rig.service._table) == 0
    assert (status, body["reason"]) == (409, "already_configured")
    assert (body["server"], body["route"], body["credential"], body["kind"]) == (
        "notes",
        "notes-mcp",
        "notes-key",
        "header",
    )
    assert "with a credential of kind header, not oauth2" in body["error"]
    assert body["next"] == [
        {
            "do": "fix_policy",
            "label": "Remove gateway.servers.notes, routes notes-mcp and credentials.notes-key "
            "from the policy, reload, then run this command again",
        }
    ]
    assert names.lookups == []


@pytest.mark.usefixtures("names", "mcp", "auth")
async def test_the_second_run_checks_a_stored_secrets_binding(tmp_path: Path) -> None:
    """D.12 step 2 runs D.7 step 5's check: a client secret stored under another binding than
    the committed policy derives is refused, with the command to register again."""
    async with running(tmp_path) as rig:
        plan = await rig.discover(**CONFIDENTIAL)
        made = await rig.service.register(plan["onboarding"], {"client_secret": SECRET})
        rig.policy = rig.merged(made["diff"]["yaml"])
        fine = await rig.discover(**CONFIDENTIAL)
        entry = rig.store.entry(SECRET_NAME)
        assert entry is not None
        elsewhere = oauth_binding("https://tokens.elsewhere.example/token", [f"https://{MCP}"])
        rig.store.put(SECRET_NAME, SECRET, elsewhere, meta=entry.meta)
        status, body = await rig.refused(**CONFIDENTIAL)
    assert (fine["stage"], fine["plan"]["client_auth"]) == ("committed", "basic")
    assert (status, body["reason"]) == (409, "client_secret_binding_changed")
    assert body["next"][0]["command"] == f"zoeymcp login --mcp {SERVER_URL} --reregister"


# --- a re-registration (D.12, OPS-3, D-184) -------------------------------------------------------


@pytest.mark.usefixtures("names", "mcp")
async def test_a_reregistration_replaces_the_credential_and_its_secret(
    tmp_path: Path, auth: FakeAuthServer, lines: io.StringIO
) -> None:
    """OPS-3: the committed names kept, fragment 1 replacing credentials.notes whole with the
    new client, each changed field named, what the operator set kept, and the stored secret
    replaced under the binding that fragment derives."""
    again = {**CONFIDENTIAL, "client_id": NEW_CLIENT, "reregister": True}
    async with running(tmp_path) as rig:
        plan = await rig.discover(**CONFIDENTIAL)
        made = await rig.service.register(plan["onboarding"], {"client_secret": SECRET})
        rig.policy = rig.merged(made["diff"]["yaml"])
        with_credential(rig, grant_lifetime_days=30)
        planned = await rig.discover(**again)
        redone = await rig.service.register(planned["onboarding"], {"client_secret": NEW_SECRET})
        # Until the policy holds the new credential, fragment 1 is there to show again.
        shown = await rig.service.fragment(planned["onboarding"], {})
        rig.policy = rig.merged(redone["diff"]["yaml"])
        status, gone = await refusal_of(rig.service.fragment(planned["onboarding"], {}))
        # Committed, the second run compares it as any other.
        compared = await rig.discover(**{**CONFIDENTIAL, "client_id": NEW_CLIENT})
    assert (planned["stage"], planned["names"]["credential"]) == ("discovered", "notes")
    assert [
        "Re-registration",
        "replaces credentials.notes and its stored client secret; its route and server stay",
    ] in planned["rows"]
    text = redone["diff"]["yaml"]
    assert text.splitlines()[:2] == [
        "# zoeymcp: re-registration of notes (1 of 2). Replace credentials.notes with this one; "
        "nothing else changes.",
        "# zoeymcp replace: credentials.notes",
    ]
    # Only the field that changed by value: the defaults the hand-kept policy leaves unwritten
    # (redirect_uri, say) and the fragment writes out are the same.
    assert changed_lines(text) == ["# changed: notes (client_id)"]
    fragment = load_mapping(text)
    assert list(fragment) == ["credentials"]
    credential = fragment["credentials"]["notes"]
    assert credential["client_id"] == NEW_CLIENT
    assert credential["client_secret"] == f"store:{SECRET_NAME}"
    assert credential["grant_lifetime_days"] == 30
    assert shown["diff"]["yaml"] == text
    assert (status, gone["reason"]) == (404, "onboarding_unknown")
    assert compared["stage"] == "committed"
    assert redone["next"][-1] == {
        "do": "connect",
        "label": "Then sign in with the new client",
        "command": "zoeymcp login notes --rebind",
        "via": "exec",
    }
    secret, _ = rig.store.get_for_oauth(SECRET_NAME, token_url=f"{ISSUER}/token")
    assert secret.reveal() == NEW_SECRET
    entry = rig.store.entry(SECRET_NAME)
    assert entry is not None
    assert entry.binding == derive_binding(rig.policy, SECRET_NAME)
    assert entry.meta is not None
    assert entry.meta["client_id"] == NEW_CLIENT
    assert auth.registrations == []
    assert NEW_SECRET not in json.dumps([planned, redone, shown]) + lines.getvalue()


@pytest.mark.usefixtures("names", "mcp", "auth")
async def test_a_reregistration_that_fails_after_its_write_puts_the_old_secret_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, lines: io.StringIO
) -> None:
    """OPS-3, OPS-5: the write replaced the secret the running credential still uses, so a final
    check that fails after it puts that secret back, with its binding and meta, rather than
    deleting it."""
    again = {**CONFIDENTIAL, "client_id": NEW_CLIENT, "reregister": True}
    async with running(tmp_path) as rig:
        plan = await rig.discover(**CONFIDENTIAL)
        made = await rig.service.register(plan["onboarding"], {"client_secret": SECRET})
        rig.policy = rig.merged(made["diff"]["yaml"])
        committed = rig.store.entry(SECRET_NAME)
        planned = await rig.discover(**again)
        raw = rig.policy.model_dump(by_alias=True)
        clash = {**raw["routes"][0], "name": "clash", "prefix": "/notes"}
        moved_on = Policy.model_validate({**raw, "routes": [*raw["routes"], clash]})
        put = rig.store.put
        reloads = [moved_on]

        def put_then_reload(*args: Any, **kwargs: Any) -> None:
            put(*args, **kwargs)
            if reloads:
                rig.policy = reloads.pop()

        monkeypatch.setattr(rig.store, "put", put_then_reload)
        before = len(records(lines))
        status, body = await refusal_of(
            rig.service.register(planned["onboarding"], {"client_secret": NEW_SECRET})
        )
    assert (status, body["reason"], body["secret_restored"]) == (422, "diff_invalid", True)
    assert "secret_deleted" not in body
    assert body["error"].endswith(
        "the client secret it replaced was put back), so no fragment is shown."
    )
    entry = rig.store.entry(SECRET_NAME)
    assert committed is not None
    assert entry is not None
    assert (entry.binding, entry.meta) == (committed.binding, committed.meta)
    assert rig.store.get_for_binding(SECRET_NAME, entry.binding).reveal() == SECRET
    later = [r["event"] for r in records(lines)[before:]]
    assert [e for e in later if e.startswith("secret_")] == ["secret_set", "secret_set"]
    assert NEW_SECRET not in json.dumps(body) + lines.getvalue()


@pytest.mark.usefixtures("names", "mcp", "auth")
async def test_a_reregistration_takes_a_scope_given_and_the_new_clients_rotation(
    tmp_path: Path,
) -> None:
    """A re-registration keeps the committed scopes unless --scope gives others, and a client
    that authenticates differently takes its own ``rotates``, as a first run's fragment does,
    so check has nothing to warn about."""
    async with running(tmp_path) as rig:
        await committed_public(rig)
        with_credential(rig, scope="notes.read kept.by.hand")
        texts: list[str] = []
        for body in (
            {**PUBLIC, "reregister": True},
            {**PUBLIC, "scope": "notes.read", "reregister": True},
            {**CONFIDENTIAL, "client_id": NEW_CLIENT, "reregister": True},
        ):
            planned = await rig.discover(**body)
            if body.get("secret_given"):
                made = await rig.service.register(planned["onboarding"], {"client_secret": SECRET})
            else:
                made = await rig.service.fragment(planned["onboarding"], {})
            texts.append(made["diff"]["yaml"])
    merged: list[OAuth2Credential] = []
    for text in texts:
        cred = rig.merged(text).credentials["notes"]
        assert isinstance(cred, OAuth2Credential)
        merged.append(cred)
    assert [changed_lines(text) for text in texts] == [
        [],
        ["# changed: notes (scope)"],
        [
            "# changed: notes (client_id)",
            "# changed: notes (client_secret)",
            "# changed: notes (client_auth)",
            "# changed: notes (rotates)",
        ],
    ]
    assert [cred.scope for cred in merged] == [
        "notes.read kept.by.hand",
        "notes.read",
        "notes.read kept.by.hand",
    ]
    assert [cred.rotates for cred in merged] == [True, True, False]
    assert [f for f in check_policy(rig.merged(texts[2])) if "rotates" in f.message] == []


@pytest.mark.usefixtures("names", "mcp", "auth")
@pytest.mark.parametrize(
    ("changes", "field", "why"),
    [
        ({"token_headers": {"X-Tenant": "notes"}}, "token_headers", "never holds its values"),
        (
            {"extra_params": {"resource": SERVER_URL, "audience": ["a", "b"]}},
            "extra_params.audience",
            "not a list",
        ),
        (
            {"authorize_params": {"resource": [SERVER_URL, f"{SERVER_URL}2"]}},
            "authorize_params.resource",
            "not a list",
        ),
    ],
)
async def test_what_a_fragment_cant_carry_is_refused_before_anything_is_stored(
    tmp_path: Path, changes: dict[str, Any], field: str, why: str
) -> None:
    """D-184: a re-registration replaces the credential whole, so a field its fragment can't
    write would be dropped: refused at discovery, before the operator confirms."""
    async with running(tmp_path) as rig:
        await committed_public(rig)
        with_credential(rig, **changes)
        status, body = await rig.refused(**PUBLIC, reregister=True)
        assert len(rig.service._table) == 0
    assert (status, body["reason"]) == (409, "reregister_by_hand")
    assert f"The credential notes sets {field}, " in body["error"]
    assert why in body["error"]
    assert rig.store.names() == []


@pytest.mark.usefixtures("names", "mcp", "auth")
async def test_a_reregistration_needs_the_committed_credential(tmp_path: Path) -> None:
    async with running(tmp_path) as rig:
        status, body = await rig.refused(**PUBLIC, reregister=True)
        assert (status, body["reason"]) == (400, "bad_body")
        assert body["detail"].endswith("run without --reregister")
        await committed_public(rig)
        status, body = await rig.refused(**PUBLIC, name="other", reregister=True)
        assert (status, body["reason"]) == (400, "bad_body")
        status, body = await rig.refused(**PUBLIC, reregister="yes")
        assert (status, body["reason"]) == (400, "bad_body")
