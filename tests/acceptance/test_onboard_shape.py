"""Acceptance: S9, a remote MCP server onboarded by its URL, end to end (M7 design O.5; J1-J5).

Agent (the SDK client, both eras) -> gateway -> vault -> the fake MCP server, which takes only the
fake authorization server's live access tokens. Both fakes serve real TLS under their own names,
``mcp.notes.example`` and ``auth.notes.example``, and every vault connection reaches them by name
through the fake resolver's dial map (tests/fakes/resolver.py, BP-1), the address guard unchanged
on every one of the vault's own guarded clients (M7 design B.2). The vault, the authorization
server and the MCP server read one clock, so a test can let an access token expire. The
gateway's review poll is the shipped 25 s one: the vault ends it when a reload changes the view,
so a review queued right after waits out no poll (M6 design K.5).

The operator starts from a policy with an agent and no server, and walks J1 with the real CLI:
``login --mcp`` (fragment 1), the fragment merged as ``check --with`` merges it, the reload,
``login --mcp`` again (the comparison, the paste, the review the gateway's poll runs), then the
commands its ``Next:`` list prints (``review --via vault --choose --suggest``, an edit, ``review
--via vault --choices -``: fragment 2), the merge, the server assigned to the agent, the reload.
Then the agent lists the tools and calls an allowed one and an approved one, and the vault
refreshes an expired access token, rotating the refresh token. Rows:

- a given public client, across the fake's modes (dual, legacy, modern), both agent eras and
  both vault links, with the 401 a refused access token earns (D-116's follow-on, fold-in C20);
- a given confidential client with a loopback-port ``--redirect-uri`` (J3);
- a public client the vault registers (DCR), whose fragment 1 is the shipped profile
  ``remote-mcp-oauth-discovered.yaml`` but for the client ID (fold-in R20);
- a confidential client the vault registers, its secret stored at registration and the commit
  applied by restarting the vault (FM-3);
- the older server with no protected-resource metadata (D.2a);
- J3 through the operator's own proxy, which refuses one host, then the other, the onboarding
  resumed each time from the printed command (J5, FM-11, OPS-8);
- a server that checks headers before credentials, and one that answers ``server/discover``
  without them (SPEC-1);
- the ``large`` server's 96 tools through the choices file (J4);
- J2 in the portal: a setup code and a passkey, **Add a server by URL**, the registration with a
  passkey, the commit, **Connect** through the callback, the review the page queues, **Select
  suggested** on the ``large`` server, fragment 2 and its commit; and a given public client's
  **Make the YAML** with no passkey, connected by paste;
- J14 in the portal of a managed vault (M6 design G.9, G.3; step 15c): its first policy seeds
  revision 1, and five passkey prompts, each for one thing (register, **Save**, **Connect**, the
  review's **Save**, **Give to clients**), take the server to the agent's calls with no fragment
  committed.

Every test ends with the sweep: no token, code or client secret the fakes issued, no given secret,
no client token or its hash and no gateway key reached a log line, an answer the operator or the
agent saw, or the CLI.
"""

from __future__ import annotations

import asyncio
import io
import json
import re
import shlex
import threading
from collections.abc import Callable, Iterator, Mapping
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import anyio
import certifi
import httpx
import pytest
import uvicorn

from tests.fakes.agent import ACCEPT, Script, Version, agent
from tests.fakes.authenticator import SoftAuthenticator
from tests.fakes.browser import Browser, Page, loopback
from tests.fakes.connect_proxy import ConnectProxy, serve_proxy
from tests.fakes.harness import serve
from tests.fakes.mcp_server import McpFake, Mode, Switch
from tests.fakes.oauth_server import ClientAuth, FakeAuthServer, Registration
from tests.fakes.resolver import FakeResolver
from tests.gateway.rig import Running, WithAdmin, token_for
from tests.portal.flows import connect_by_callback, enrol, login, redeem, step_up
from zoeymcp.cli import onboard as onboard_cli
from zoeymcp.cli.main import main
from zoeymcp.common import egresslist, logs
from zoeymcp.common.policy import Policy, check_policy, restart
from zoeymcp.common.policy.merge import Merged, merge, replace_paths
from zoeymcp.common.policy.schema import hash_token
from zoeymcp.common.policy.view import build_view
from zoeymcp.common.yamlload import load_mapping
from zoeymcp.gateway.app import GatewayApp
from zoeymcp.gateway.defstore import DefinitionStore
from zoeymcp.gateway.ledger import Ledger
from zoeymcp.gateway.marks import DriftMarks
from zoeymcp.gateway.upstream import UpstreamPool
from zoeymcp.gateway.vaultlink import KeySource, parse_link, review_client, view_client
from zoeymcp.portal.app import PortalApp, Secrets, load_static
from zoeymcp.portal.passkeys import Passkeys
from zoeymcp.portal.server import HEAD_LIMIT, portal_protocol
from zoeymcp.vault import netclient
from zoeymcp.vault.admin import AdminApp, HealthReader, SetupCodes
from zoeymcp.vault.app import VaultApp, without_cookies
from zoeymcp.vault.keys import KeySet, generate_master_key
from zoeymcp.vault.managed import ManagedPolicy
from zoeymcp.vault.oauth.discovery import ISSUER_LABELS, NOTES
from zoeymcp.vault.oauth.login import LoginService
from zoeymcp.vault.oauth.protocol import MIN_401_AGE
from zoeymcp.vault.oauth.tokens import TokenManager
from zoeymcp.vault.onboard import BACKSTOP_OFF, OnboardService
from zoeymcp.vault.peer import peer_checked
from zoeymcp.vault.policystore import PolicyStore
from zoeymcp.vault.server import ListenerTag, load_runtime
from zoeymcp.vault.store import STORE_FILE, SecretStore

from .conftest import (
    BASE,
    PROFILES,
    STARTUP_TIMEOUT,
    AdminTransport,
    Clock,
    _HTTPTransport,
    _Server,
    _wait_started,
)
from .gateway import wait_healthy
from .helpers import Seen, listening, mark, wait_for
from .procs import free_port
from .test_mcp_shapes import LINKS, own_uid, text
from .test_oauth_shapes import PRINTED_URL
from .tls import ProviderCA, issue_cert

pytestmark = pytest.mark.anyio

MCP = "mcp.notes.example"
AUTH = "auth.notes.example"
SERVER_URL = f"https://{MCP}/mcp"
ISSUER = f"https://{AUTH}"
SERVER = "notes"
SLOT = "notes-refresh"
CLIENT = "agent1"
CLIENT_ID = "notes-given-client"
# A given confidential client's secret, for the sweep to look for.
SECRET = "s9-given-client-secret-0001"
SCOPES = ("notes.read", "notes.write")
LOOPBACK_REDIRECT = "http://127.0.0.1:8765/callback"
PROFILE = "remote-mcp-oauth-discovered.yaml"
HOUR = 3600.0
# Every token, code and client secret the fake authorization server issues.
ISSUED = re.compile(r"fake-notes-(?:rt|at|code|secret)-\d+")
J1 = ["login", "--mcp", SERVER_URL, "--name", SERVER]
# The prefix every printed command starts with, for the shipped hardened compose file (M.7).
PREFIX = "docker compose -f deploy/compose.hardened.yaml exec "
# The tools the operator keeps: the one the server marks read-only, allowed as it suggests, and
# one it doesn't annotate, approved.
ALLOWED, APPROVED = "echo", "add"
# A large review: the 64 tools the server marks read-only (tests/fakes/mcp_server.py).
LARGE_ALLOWED = 64
# The bound on one agent session's calls (P.2's rules), far above the second or so each takes.
CALLS_TIMEOUT = 120
# What a registration request may never ask for or carry (X1).
SECRET_FIELDS = frozenset(
    {"client_secret", "code", "code_verifier", "access_token", "refresh_token"}
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(autouse=True)
def no_compose_variables(monkeypatch: pytest.MonkeyPatch) -> None:
    """The printed commands as the shipped hardened file gives them (M.7)."""
    for name in (onboard_cli.COMPOSE_CMD_ENV, onboard_cli.EXEC_SERVICE_ENV):
        monkeypatch.delenv(name, raising=False)


# --- the fakes, by name ------------------------------------------------------------------------


class ByName(httpx.BaseTransport):
    """The operator's browser at a fake: to its loopback port, the TLS name and ``Host`` its own,
    checked against the test CA."""

    def __init__(self, ports: Mapping[str, int], ca: ProviderCA) -> None:
        self.ports = ports
        self.ca = ca

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host
        request.extensions = {**request.extensions, "sni_hostname": host}
        request.url = request.url.copy_with(host="127.0.0.1", port=self.ports[host])
        with _HTTPTransport(verify=self.ca.client_context()) as transport:
            response = transport.handle_request(request)
            response.read()
        return response


@dataclass
class World:
    """The two fakes on their names, the clock they share with the vault, and the names the
    vault's guarded clients answer."""

    ca: ProviderCA
    clock: Clock
    auth: FakeAuthServer
    mcp: McpFake
    resolver: FakeResolver
    ports: dict[str, int]

    def provider(self) -> httpx.Client:
        """A client of the operator's browser for the authorization server's origin."""
        return httpx.Client(transport=ByName(self.ports, self.ca), base_url=ISSUER, trust_env=False)

    def browse(self, url: str) -> str:
        """Play the browser: approve at the authorization server, return where it was sent."""
        with self.provider() as browser:
            answer = browser.get(url)
        assert answer.status_code == 302, answer.text
        location: str = answer.headers["location"]
        return location


def fakes(
    clock: Clock,
    *,
    registration: Registration = "none",
    auth: ClientAuth = "none",
    client_secret: str | None = None,
    rotate: bool = True,
    mode: Mode = "dual",
    switches: frozenset[Switch] = frozenset(),
) -> tuple[FakeAuthServer, McpFake]:
    """The authorization server and the MCP server it guards: a 401 naming the server's
    protected-resource metadata and its scopes, the metadata naming the issuer. A public
    client's refresh tokens rotate; a confidential client's (``rotate`` off) don't."""
    server = FakeAuthServer(
        clock.wall,
        client_id=CLIENT_ID,
        client_secret=client_secret,
        auth=auth,
        rotate=rotate,
        issuer=ISSUER,
        iss_supported=True,
        scopes=(*SCOPES, "offline_access"),
        registration=registration,
        prefix="fake-notes",
    )
    mcp = McpFake(
        mode=mode,
        switches=set(switches),
        authorize=server.access_ok,
        prm="path",
        authorization_servers=[ISSUER],
        scopes=SCOPES,
    )
    return server, mcp


@contextmanager
def world(
    tmp_path: Path,
    ca: ProviderCA,
    monkeypatch: pytest.MonkeyPatch,
    made: tuple[FakeAuthServer, McpFake],
    clock: Clock,
) -> Iterator[World]:
    """The fakes over TLS on their names; the vault's guarded clients answer those names and
    trust the test CA (certifi's bundle, as procs.py's launcher sets it)."""
    auth, mcp = made
    certs = tmp_path / "certs"
    certs.mkdir(mode=0o700)
    resolver = FakeResolver()
    ports: dict[str, int] = {}
    with ExitStack() as stack:
        for name, app, lifespan in ((MCP, mcp.app(), True), (AUTH, auth.app(), False)):
            url = stack.enter_context(
                serve(app, lifespan=lifespan, tls=issue_cert(ca, name, certs))
            )
            ports[name] = int(str(urlsplit(url).port))
            resolver.serve(name, ports[name])
        monkeypatch.setattr(netclient, "HOOKS", resolver.hooks())
        monkeypatch.setattr(certifi, "where", lambda: str(ca.ca_file))
        yield World(ca, clock, auth, mcp, resolver, ports)


# --- the vault and the gateway ---------------------------------------------------------------


def base_policy(*, portal_port: int | None = None, proxy: str | None = None) -> dict[str, Any]:
    """The operator's policy before onboarding: an attended agent and no server; with a portal,
    its ``admin`` block; with ``proxy``, the operator's own egress proxy."""
    document: dict[str, Any] = {
        **BASE,
        "gateway": {
            "clients": {
                CLIENT: {
                    "token_sha256": hash_token(token_for(CLIENT)),
                    "servers": [],
                    "approvals": {"attended": True},
                }
            }
        },
    }
    if portal_port is not None:
        origin = f"http://localhost:{portal_port}"
        document["admin"] = {"listen": f"127.0.0.1:{portal_port}", "origins": [origin]}
    if proxy is not None:
        document["egress_proxy"] = proxy
    return document


def checked(document: Mapping[str, Any]) -> Policy:
    policy = Policy.model_validate(document)
    errors = [f for f in check_policy(policy) if f.level == "error"]
    assert errors == [], errors
    return policy


class Vault:
    """The vault as ``zoeymcp vault`` wires it (``server.build``): one store, token manager,
    logins, onboardings and review jobs for the admin socket and the portal, served here on
    loopback ports (the socket's routes on TCP, as conftest's ``Deployment`` serves them), and
    with ``link``, the gateway's link socket (Linux). The clocks are the world's. A policy that
    says ``mode: managed`` is read as a managed start reads it (``server.load_runtime``): its
    first start seeds revision 1, and the portal saves through the policy's holder (M6 design
    F.2, G.6)."""

    def __init__(
        self,
        state: Path,
        world: World,
        document: dict[str, Any],
        *,
        link: str = "tcp",
        portal_port: int | None = None,
    ) -> None:
        self.state = state
        self.world = world
        self.document = document
        self.master = generate_master_key()
        self.keys = KeySet.from_text(self.master)
        self.portal_port = portal_port
        self.link_socket: Path | None = None
        if link == "unix":
            self.link_socket = state.parent / "link" / "vault.sock"
            self.link_socket.parent.mkdir(mode=0o700)
        self.vault_url: str | None = None
        self.admin_url: str | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._build()

    def _build(self) -> None:
        """A new process on the same state directory: only the store carries over."""
        clock = self.world.clock
        runtime = None
        if self.document["mode"] == "managed":
            config = self.state.parent / "policy.json"
            config.write_bytes(json.dumps(self.document).encode())
            runtime = load_runtime(str(config), self.state, {"ZOEYMCP_MASTER_KEY": self.master})
            self.policy, self.store = runtime.policy, runtime.store
        else:
            self.policy = checked(self.document)
            self.store = SecretStore(self.state, self.keys)
            self.store.load()
        proxy = self.policy.egress_proxy
        # The token manager reads the world's clock, so it is made here, on the vault's own
        # token client (B.2); VaultApp builds its other clients itself.
        self.token_client = without_cookies(
            netclient.token_client(proxy, lambda: egresslist.private_exceptions(app.policy))
        )
        self.tokens = TokenManager(
            self.store, self.token_client, clock=clock.monotonic, wall=clock.wall
        )
        app = self.app = VaultApp(
            self.policy,
            self.store,
            self.keys,
            tokens=self.tokens,
            environ={},
            gateway_keys=None if runtime is None else runtime.gateway_keys,
            gateway_link=self.link_socket is not None,
        )
        self.managed: ManagedPolicy | None = None
        if runtime is not None:
            assert runtime.policy_store is not None
            assert runtime.ratchet is not None
            admin_block = runtime.policy.admin
            store_keys, previous = runtime.keys, runtime.previous
            self.managed = ManagedPolicy(
                runtime.policy_store,
                app,
                policy=runtime.policy,
                ratchet=runtime.ratchet,
                secrets=runtime.store,
                environ={},
                started=restart.Started(
                    app.egress_proxy,
                    app.egress_proxy_kind,
                    None if admin_block is None else admin_block.listen,
                    frozenset(),
                ),
                reopen=lambda: PolicyStore.open(self.state, store_keys, previous, strays=False),
            )
        self.login = LoginService(self.tokens, clock=clock.monotonic, wall=clock.wall)
        self.onboard = OnboardService(
            self.store,
            self.tokens,
            lambda: app.policy,
            app.onboarding_client,
            egress_proxy=app.egress_proxy,
        )
        self.setup = SetupCodes(self.state, self.keys.portal_key)
        passkeys = Passkeys.load(self.state, self.keys.portal_key)
        self.admin = AdminApp(
            self.store,
            self.keys,
            lambda: app.policy,
            self.setup,
            self.tokens,
            self.login,
            passkeys=passkeys,
            onboard=self.onboard,
            revoker=app.revoker,
            reviews=app,
        )
        self.portal: PortalApp | None = None
        if self.portal_port is not None:
            self.portal = PortalApp(
                [self.portal_origin],
                static=load_static(),
                setup=self.setup,
                passkeys=passkeys,
                login=self.login,
                secrets=Secrets(self.store, self.tokens, lambda: app.policy, app.revoker),
                health=HealthReader(
                    self.store, lambda: app.policy, self.login, passkeys=passkeys
                ).report,
                onboard=self.onboard,
                reviews=app,
                source="managed" if self.managed is not None else "env",
                policy_header=None if self.managed is None else self._header,
                managed=self.managed,
            )

    def _header(self) -> Mapping[str, Any] | None:
        assert self.managed is not None
        return self.managed.header

    @property
    def portal_origin(self) -> str:
        return f"http://localhost:{self.portal_port}"

    def restart(self) -> None:
        """A new vault on the same state directory and the current policy (F-13)."""
        assert self._loop is None, "stop it first"
        self._build()

    def reload(self, document: dict[str, Any]) -> None:
        """``SIGHUP`` with ``document`` as the new policy."""
        policy = checked(document)
        self.document = document
        self.call(lambda: self.app.reload(policy))
        self.policy = policy

    def call(self, function: Callable[[], Any]) -> Any:
        """Run ``function`` on the vault's loop, as a signal handler would."""
        assert self._loop is not None, "the vault isn't running"

        async def wrapper() -> Any:
            return function()

        return asyncio.run_coroutine_threadsafe(wrapper(), self._loop).result(60)

    def admin_transport(self) -> AdminTransport:
        assert self.admin_url is not None, "the vault isn't running"
        return AdminTransport(self.admin_url)

    @contextmanager
    def running(self) -> Iterator[None]:
        """The proxy listener, the admin app, the link socket and the portal on one loop."""
        app, token_client = self.app, self.token_client
        servers = [
            _Server(
                uvicorn.Config(asgi, host="127.0.0.1", port=0, log_level="warning", lifespan="off")
            )
            for asgi in (ListenerTag(app, "tcp"), self.admin.app)
        ]
        others = []
        if self.link_socket is not None:
            others.append(
                _Server(
                    uvicorn.Config(
                        ListenerTag(app, "gateway"),
                        uds=str(self.link_socket),
                        http=peer_checked(own_uid()),
                        log_level="warning",
                        lifespan="off",
                    )
                )
            )
        if self.portal is not None:
            others.append(
                _Server(
                    uvicorn.Config(
                        self.portal,
                        host="127.0.0.1",
                        port=self.portal_port or 0,
                        log_level="warning",
                        lifespan="off",
                        http=portal_protocol(),
                        h11_max_incomplete_event_size=HEAD_LIMIT,
                        proxy_headers=False,
                    )
                )
            )
        loop = asyncio.new_event_loop()
        everything = [*servers, *others]

        async def main() -> None:
            try:
                await asyncio.gather(*(server.serve() for server in everything))
            finally:
                await app.aclose()
                await token_client.aclose()

        thread = threading.Thread(target=loop.run_until_complete, args=(main(),), daemon=True)
        thread.start()
        vault_port, admin_port = _wait_started(servers, thread)
        _wait_started(others, thread)
        self._loop = loop
        self.vault_url = f"http://127.0.0.1:{vault_port}"
        self.admin_url = f"http://127.0.0.1:{admin_port}"
        try:
            yield
        finally:
            for server in everything:
                server.should_exit = True
            thread.join(STARTUP_TIMEOUT * 6)
            self._loop = None
            self.vault_url = self.admin_url = None
            if not thread.is_alive():
                loop.close()


@contextmanager
def gateway(vault: Vault, state: Path) -> Iterator[Running]:
    """The gateway on the vault, over TCP with the gateway key or over the link socket, polling
    the vault's view and its review jobs, as ``zoeymcp gateway`` does."""
    if vault.link_socket is not None:
        link, keys = parse_link(f"unix:{vault.link_socket}"), None
    else:
        assert vault.vault_url is not None
        link, keys = parse_link(vault.vault_url), KeySource(vault.keys.gateway_key(1))
    limits = build_view(vault.policy).gateway.limits
    marks = DriftMarks.load(state)
    pool = UpstreamPool(link, keys, marks, DefinitionStore(state), limits=limits)
    app = GatewayApp(
        pool, view_client(link, keys), policy_wait=1, review_http=review_client(link, keys)
    )
    app.ledger, _ = Ledger.open_at(state, max_bytes=limits.ledger_max_bytes)
    with serve(WithAdmin(app), lifespan=True, proxy_headers=False) as url:
        running = Running(app, url)
        wait_healthy(running)
        yield running


# --- the operator ----------------------------------------------------------------------------


@dataclass
class S9:
    """One deployment: the world, the vault, and while it runs, the gateway; everything shown."""

    world: World
    vault: Vault
    gateway_state: Path
    seen: Seen = field(default_factory=Seen)
    running: Running | None = None
    # The sign-in command fragment 1's Next: list prints, and the first run's stderr (the plan).
    again: list[str] = field(default_factory=list)
    plan: str = ""
    committed: bool = False

    @contextmanager
    def up(self) -> Iterator[Running]:
        """The vault, then the gateway on it."""
        logs.set_stream(self.seen.log)
        try:
            with self.vault.running(), gateway(self.vault, self.gateway_state) as running:
                self.running = running
                yield running
        finally:
            self.running = None
            logs.set_stream(None)

    def cli(self, argv: list[str], stdin: io.StringIO | None = None) -> tuple[int, str, str]:
        """``zoeymcp <argv>`` against the running vault's admin app; ``stdin`` may be a
        :class:`Paste`. Every output is kept for the sweep."""
        original = httpx.HTTPTransport
        httpx.HTTPTransport = lambda **_: self.vault.admin_transport()  # type: ignore[assignment,misc]
        out, err = io.StringIO(), io.StringIO()
        given = stdin if stdin is not None else io.StringIO()
        if isinstance(given, Paste):
            given.shown = out
        try:
            code = main(argv, stdin=given, out=out, err=err)
        finally:
            httpx.HTTPTransport = original  # type: ignore[misc]
        self.seen.outputs += [out.getvalue(), err.getvalue()]
        return code, out.getvalue(), err.getvalue()

    def commit(self, fragment: str, *, assign: bool = False, restart: bool = False) -> None:
        """``fragment`` merged into the running policy as ``check --with`` merges it, and with
        ``assign``, the server added to the agent's list by hand (Q33); then reloaded, or with
        ``restart``, the vault (stopped) started again on it, as a recreate does. Before the first
        commit, what reached the fakes is checked against X1."""
        if not self.committed:
            nothing_secret_yet(self.world)
            self.committed = True
        merged = merge(self.vault.document, load_mapping(fragment), replace=replace_paths(fragment))
        assert isinstance(merged, Merged), merged
        document = json.loads(json.dumps(merged.data))
        if assign:
            document["gateway"]["clients"][CLIENT]["servers"] = [SERVER]
        if restart:
            self.vault.document = document
            self.vault.restart()
            return
        self.vault.reload(document)
        self.applied()

    def applied(self) -> None:
        """The gateway on the vault's running view: after a reload, or a managed save the
        vault installed itself (M6 design G.6)."""
        assert self.running is not None
        digest = build_view(self.vault.app.policy).digest
        app = self.running.app
        wait_for(
            lambda: app.policy.snapshot is not None and app.policy.snapshot.view.digest,
            lambda found: found == digest,
            what="the gateway's view",
        )

    def store_text(self) -> str:
        return (self.vault.state / STORE_FILE).read_text(encoding="utf-8")


class Paste(io.StringIO):
    """The paste: reading it opens the authorization URL the CLI printed in the operator's
    browser, approves, and answers the address the browser was sent to."""

    def __init__(self, world: World) -> None:
        super().__init__()
        self.world = world
        self.shown = io.StringIO()
        self.visits = 0

    def readline(self, size: int = -1, /) -> str:  # type: ignore[override]  # as typeshed
        [url] = PRINTED_URL.findall(self.shown.getvalue())
        self.visits += 1
        return self.world.browse(url) + "\n"


def nothing_secret_yet(world: World) -> None:
    """X1: before the policy names the credential's token endpoint, the vault sent nothing
    secret. The authorization server saw only metadata fetches and the registration, nothing
    reached its token endpoint, no request to either fake carried credentials, an issued value or
    the given secret, and the registration asked for nothing secret."""
    auth = world.auth
    assert auth.calls == []
    paths = [(seen.method, seen.path) for seen in auth.seen]
    assert all(
        path.startswith("/.well-known/") or (method, path) == ("POST", "/register")
        for method, path in paths
    ), paths
    sent = [(seen.headers, seen.query.encode() + seen.body) for seen in auth.seen]
    sent += [(dict(item.headers), item.body) for item in world.mcp.received]
    for headers, body in sent:
        assert "authorization" not in headers, headers
        found = json.dumps(headers) + body.decode("latin-1")
        assert ISSUED.search(found) is None, found
        assert SECRET not in found, found
    for registration in auth.registrations:
        assert not SECRET_FIELDS & set(json.loads(registration.body)), registration.body


def printed(err: str) -> list[tuple[list[str], str | None, str | None]]:
    """The ``Next:`` list's commands for the vault's container, each as the operator runs it:
    its argv after ``zoeymcp``, the file it reads its stdin from and the file its stdout goes to
    (M.7)."""
    commands = []
    for line in err.splitlines():
        if not line.startswith("    " + PREFIX):
            continue
        words = shlex.split(line.strip().removeprefix(PREFIX))
        words = words[1:] if words[0] == "-T" else words
        assert words[:2] == ["vault", "zoeymcp"], line
        argv, source, target = words[2:], None, None
        if ">" in argv:
            target = argv[argv.index(">") + 1]
            argv = argv[: argv.index(">")]
        if "<" in argv:
            source = argv[argv.index("<") + 1]
            argv = argv[: argv.index("<")]
        commands.append((argv, source, target))
    return commands


def first_run(s9: S9, argv: list[str], stdin: str = "") -> str:
    """``login --mcp``: fragment 1 on stdout, and last on its ``Next:`` list, the same command
    to sign in once it is committed (kept as ``s9.again``, the plan as ``s9.plan``)."""
    code, fragment, err = s9.cli(argv, io.StringIO(stdin))
    assert code == 0, err
    s9.plan = err
    assert fragment.startswith(f"# zoeymcp: onboarding {SERVER} (1 of 2).")
    assert "Wrote fragment 1 of 2 to stdout.\n" in err
    [*_, (s9.again, _, target)] = printed(err)
    assert (s9.again[: len(J1)], target) == (J1, None)
    return fragment


def second_run(s9: S9) -> str:
    """The command fragment 1's list printed, once fragment 1 is committed: the comparison, the
    paste, the review the gateway's poll runs, its counts, then J1's choose and make_fragment
    pair."""
    paste = Paste(s9.world)
    code, out, err = s9.cli(s9.again, paste)
    assert code == 0, err
    assert paste.visits == 1
    assert f"Stored the refresh token for {SERVER} as {SLOT}.\n" in out
    assert err.startswith(
        f"{SERVER} is in the policy and matches what the server publishes ({SERVER_URL}).\n"
    )
    assert "Reviewing through the gateway: " in err
    return err


def review(s9: S9, err: str, edit: Callable[[str], str]) -> str:
    """The second run's ``Next:`` commands, as printed: the choices file, ``edit`` as the
    operator's, and fragment 2 from it. Both exit 1: until fragment 2 is committed, the server
    lists tools nobody reviewed (M6 design J.5)."""
    files: dict[str, str] = {}
    choose, make = [command for command in printed(err) if command[0][0] == "review"]
    for argv, source, target in (choose, make):
        assert argv[:4] == ["review", SERVER, "--via", "vault"], argv
        stdin = io.StringIO(files[source]) if source is not None else None
        code, out, problem = s9.cli(argv, stdin)
        assert code == 1, problem
        assert target is not None
        files[target] = edit(out) if target == f"{SERVER}.choices" else out
    assert (choose[2], make[1:]) == (
        f"{SERVER}.choices",
        (f"{SERVER}.choices", f"onboard-{SERVER}-2.yaml"),
    )
    fragment = files[f"onboard-{SERVER}-2.yaml"]
    assert fragment.startswith(f"# zoeymcp: review of {SERVER} (2 of 2).")
    return fragment


def plan_row(label: str, value: str) -> str:
    """One row of the plan as the CLI prints it (``cli/onboard.py``'s ``plan_lines``)."""
    return f"  {label:<23} {value}\n"


def reviewed_clean(s9: S9) -> None:
    """J1's last step: once fragment 2 is committed and the server assigned, ``review notes``
    exits 0, here through the vault's review jobs, the surface the vault's container has: the
    choices file declined the tools it left out (M6 design J.5)."""
    code, out, err = s9.cli(["review", SERVER, "--via", "vault", "--fresh"])
    assert code == 0, out + err


def approve(tool: str) -> Callable[[str], str]:
    """The operator's edit of a choices file: ``tool`` approved, the rest as suggested, and
    every tool left out declined, so the review is quiet once fragment 2 is committed (M6 design
    J.5)."""

    def edit(choices: str) -> str:
        edited, count = re.subn(rf"^skip(?=\s+{tool}\s)", "approve", choices, flags=re.M)
        assert count == 1, choices
        return re.sub(r"^skip(?=\s)", "decline", edited, flags=re.M)

    return edit


def bearer() -> dict[str, str]:
    return {"authorization": f"Bearer {token_for(CLIENT)}"}


async def the_calls(
    s9: S9,
    running: Running,
    tools: list[str],
    *,
    version: Version = "modern",
    refresh: bool = True,
    refused: bool = False,
) -> None:
    """The agent lists ``tools`` and calls the allowed one and the approved one, which its human
    accepts. With ``refresh``, the access token then expires: the next call refreshes it, and a
    rotating grant's refresh token is replaced. With ``refused``, the server then refuses a live
    access token: that call fails, nothing sends it again, and the next one gets a new token."""
    world = s9.world
    script = Script([ACCEPT])
    since = mark(s9.seen, world.mcp)
    session = agent(running.mcp(SERVER), version=version, script=script, headers=bearer())
    with anyio.fail_after(CALLS_TIMEOUT):
        async with session as c:
            listed = await c.list_tools()
            assert sorted(tool.name for tool in listed.tools) == sorted(tools)
            assert text(await c.call_tool(ALLOWED, {"text": "before"})) == "before"
            added = await c.call_tool(APPROVED, {"a": 2, "b": 3})
            assert (added.is_error, text(added)) == (False, "5")
            [prompt] = script.prompts
            assert f"Tool: {SERVER} \N{RIGHTWARDS ARROW} {APPROVED}" in prompt.message
            if refresh or refused:
                await listening(s9.seen, world.mcp, since)
            if refresh:
                first, calls = world.auth.active_refresh_token(), len(world.auth.refresh_calls)
                world.clock.advance(HOUR)
                assert text(await c.call_tool(ALLOWED, {"text": "refreshed"})) == "refreshed"
                assert len(world.auth.refresh_calls) == calls + 1
                if world.auth.rotate:
                    assert world.auth.active_refresh_token() not in (None, first)
                else:
                    assert world.auth.active_refresh_token() == first
            if refused:
                calls = len(world.auth.refresh_calls)
                world.clock.advance(MIN_401_AGE)
                world.auth.drop_access_tokens()
                failed = await c.call_tool(ALLOWED, {"text": "refused"})
                assert failed.is_error
                assert text(failed).startswith("upstream error (ref ")
                assert len(world.auth.refresh_calls) == calls
                assert text(await c.call_tool(ALLOWED, {"text": "after"})) == "after"
                assert len(world.auth.refresh_calls) == calls + 1
                s9.seen.outputs.append(text(failed))
    s9.seen.outputs += [json.dumps([tool.name for tool in listed.tools]), text(added)]
    if refused:
        # The refused call reached the server once, and was never sent again.
        sent = [item.params["arguments"] for item in world.mcp.requests("tools/call")]
        assert sent.count({"text": "refused"}) == 1


def sweep(s9: S9, *secrets: str) -> None:
    swept(s9.seen, s9.store_text(), s9.vault.keys.gateway_key(1), *secrets)


def swept(seen: Seen, store: str, gateway_key: str, *secrets: str) -> None:
    """No token, code or client secret the fakes issued, none of ``secrets``, no client token or
    its hash and no gateway key reached a log line, an answer, the CLI or the store file."""
    everything = seen.everything()
    for where, found in (("a log, an answer or the CLI", everything), ("the store", store)):
        leaked = ISSUED.search(found)
        assert leaked is None, f"{leaked.group(0)} reached {where}"
    for value in (*secrets, token_for(CLIENT), hash_token(token_for(CLIENT)), gateway_key):
        assert value not in everything + store, value


@contextmanager
def deployed(
    tmp_path: Path,
    ca: ProviderCA,
    monkeypatch: pytest.MonkeyPatch,
    *,
    link: str = "tcp",
    portal: bool = False,
    managed: bool = False,
    proxy: ConnectProxy | None = None,
    **options: Any,
) -> Iterator[S9]:
    """The fakes made by ``options``, and a vault on the operator's first policy, which with
    ``managed`` seeds a managed vault's revision 1."""
    clock = Clock()
    with (
        world(tmp_path, ca, monkeypatch, fakes(clock, **options), clock) as made,
        ExitStack() as stack,
    ):
        proxy_url = None
        if proxy is not None:
            # The proxy resolves names itself (B.3): through a map of its own.
            proxy.names = FakeResolver()
            for name, port in made.ports.items():
                proxy.names.serve(name, port)
            proxy_url = stack.enter_context(serve_proxy(proxy))
        portal_port = free_port() if portal else None
        state = tmp_path / "vault"
        state.mkdir(mode=0o700)
        document = base_policy(portal_port=portal_port, proxy=proxy_url)
        if managed:
            document["mode"] = "managed"
        vault = Vault(state, made, document, link=link, portal_port=portal_port)
        gateway_state = tmp_path / "gateway"
        gateway_state.mkdir(mode=0o700)
        yield S9(made, vault, gateway_state)


def onboarded_by_cli(s9: S9, first: list[str], stdin: str = "") -> str:
    """J1 up to the review: fragment 1, its commit and reload, the second run. Returns the
    second run's stderr."""
    s9.commit(first_run(s9, first, stdin))
    return second_run(s9)


# --- the profile -------------------------------------------------------------------------------


def as_shipped(fragment: str) -> dict[str, Any]:
    """Fragment 1 without the client ID, which the provider gives each registration."""
    mapping = load_mapping(fragment)
    del mapping["credentials"][SERVER]["client_id"]
    return mapping


def test_the_profile_passes_check() -> None:
    out = io.StringIO()
    shipped = load_mapping((PROFILES / PROFILE).read_text(encoding="utf-8"))
    document = io.StringIO(json.dumps({**BASE, **shipped}))
    assert main(["check", "--config", "-"], stdin=document, out=out) == 0
    # Fragment 1 assigns the server to no client (Q33): that is the operator's, after the review.
    assert out.getvalue() == (
        "warning gateway.servers.notes: not assigned to any client\n"
        "<stdin>: ok (0 error(s), 1 warning(s))\n"
    )


@pytest.mark.parametrize(
    ("leak", "where"),
    [
        ("fake-notes-at-7", "seen"),
        ("fake-notes-code-2", "seen"),
        ("fake-notes-secret-3", "seen"),
        ("fake-notes-rt-12", "store"),
        (SECRET, "store"),
        (token_for(CLIENT), "seen"),
        (hash_token(token_for(CLIENT)), "seen"),
        ("zgw1-gateway", "seen"),
    ],
)
def test_the_sweep_sees_a_leak(leak: str, where: str) -> None:
    seen = Seen()
    store = ""
    if where == "seen":
        seen.outputs.append(f"output {leak}")
    else:
        store = f'{{"value": "{leak}"}}'
    with pytest.raises(AssertionError):
        swept(seen, store, "zgw1-gateway", SECRET)


# --- J1 across the fake's modes, both agent eras and both links (D-116, C20) ---------------------


@pytest.mark.parametrize("link", LINKS)
@pytest.mark.parametrize("mode", ["dual", "legacy", "modern"])
async def test_j1_a_given_public_client(
    tmp_path: Path, ca: ProviderCA, monkeypatch: pytest.MonkeyPatch, mode: Mode, link: str
) -> None:
    """J1 for a client the provider registered for the operator, through each of the fake's
    modes and either link: the calls of an agent in each era, a refresh and a rotation, and an
    access token the server refuses before it expires."""
    with deployed(tmp_path, ca, monkeypatch, link=link, mode=mode) as s9:
        with s9.up() as running:
            err = onboarded_by_cli(s9, [*J1, "--client-id", CLIENT_ID, "--yes"])
            assert "Reviewing through the gateway: 6 tools (1 the server marks read-only" in err
            s9.commit(review(s9, err, approve(APPROVED)), assign=True)
            reviewed_clean(s9)
            await the_calls(s9, running, [ALLOWED, APPROVED], refused=True)
            # The other era's agent, on the same upstream connection.
            await the_calls(s9, running, [ALLOWED, APPROVED], version="2025-11-25", refresh=False)
        assert s9.world.auth.registrations == []
        assert s9.vault.store.names() == [SLOT]
        sweep(s9)


# --- J1's other clients, J3 and J5 -----------------------------------------------------------


async def test_j3_a_given_confidential_client(
    tmp_path: Path, ca: ProviderCA, monkeypatch: pytest.MonkeyPatch
) -> None:
    """J3: the plan first, which sends nothing past discovery, stores nothing and notes the
    redirect backstop off; then the secret piped with --yes and stored at once; the provider's
    redirect on record, a loopback port, in fragment 1; no registration."""
    options: dict[str, Any] = {"auth": "basic", "client_secret": SECRET, "rotate": False}
    with deployed(tmp_path, ca, monkeypatch, **options) as s9, s9.up() as running:
        argv = [*J1, "--issuer", ISSUER, "--client-id", CLIENT_ID, "--client-secret"]
        argv += ["--client-auth", "basic", "--redirect-uri", LOOPBACK_REDIRECT, "--yes"]
        code, out, err = s9.cli([*argv, "--plan-only"])
        assert (code, out) == (0, ""), err
        assert plan_row("Note", BACKSTOP_OFF) in err
        assert "Plan only: nothing was registered or stored." in err
        auth = s9.world.auth
        assert (s9.vault.store.names(), auth.calls, auth.registrations) == ([], [], [])
        fragment = first_run(s9, argv, SECRET + "\n")
        credential = load_mapping(fragment)["credentials"][SERVER]
        assert (credential["client_secret"], credential["redirect_uri"]) == (
            f"store:{SERVER}-client-secret",
            LOOPBACK_REDIRECT,
        )
        assert s9.vault.store.names() == [f"{SERVER}-client-secret"]
        s9.commit(fragment)
        err = second_run(s9)
        s9.commit(review(s9, err, approve(APPROVED)), assign=True)
        await the_calls(s9, running, [ALLOWED, APPROVED])
    [exchange] = [call for call in s9.world.auth.calls if call.grant_type == "authorization_code"]
    assert (exchange.auth, exchange.params["redirect_uri"]) == ("basic", LOOPBACK_REDIRECT)
    assert s9.world.auth.registrations == []
    sweep(s9, SECRET)


async def test_j1_a_public_client_the_vault_registers_is_the_shipped_profile(
    tmp_path: Path, ca: ProviderCA, monkeypatch: pytest.MonkeyPatch
) -> None:
    """J1 (DCR): one registration of a public client, its ID kept only until the second run;
    fragment 1 is ``remote-mcp-oauth-discovered.yaml`` but for that ID (fold-in R20)."""
    with deployed(tmp_path, ca, monkeypatch, registration="open") as s9, s9.up() as running:
        fragment = first_run(s9, [*J1, "--yes"])
        [client_id] = s9.world.auth.registered
        assert load_mapping(fragment)["credentials"][SERVER]["client_id"] == client_id
        shipped = (PROFILES / PROFILE).read_text(encoding="utf-8")
        assert as_shipped(fragment) == as_shipped(shipped)
        assert s9.vault.store.names() == [f"{SERVER}-client-id"]
        s9.commit(fragment)
        err = second_run(s9)
        assert s9.vault.store.names() == [SLOT]
        s9.commit(review(s9, err, approve(APPROVED)), assign=True)
        reviewed_clean(s9)
        await the_calls(s9, running, [ALLOWED, APPROVED])
    assert len(s9.world.auth.registrations) == 1
    sweep(s9)


async def test_j1_a_confidential_client_the_vault_registers_across_a_restart(
    tmp_path: Path, ca: ProviderCA, monkeypatch: pytest.MonkeyPatch
) -> None:
    """J1 (DCR) where the server registers confidential clients only: the secret stored at
    registration under the binding fragment 1 derives, and the commit applied by recreating the
    vault, which loses nothing (FM-3)."""
    options: dict[str, Any] = {"registration": "confidential_only", "rotate": False}
    with deployed(tmp_path, ca, monkeypatch, **options) as s9:
        with s9.up():
            fragment = first_run(s9, [*J1, "--yes"])
            assert 'client_secret: "store:notes-client-secret"' in fragment
            assert s9.vault.store.names() == [f"{SERVER}-client-secret"]
        s9.commit(fragment, restart=True)
        with s9.up() as running:
            err = second_run(s9)
            s9.commit(review(s9, err, approve(APPROVED)), assign=True)
            await the_calls(s9, running, [ALLOWED, APPROVED])
    [client_id] = s9.world.auth.registered
    secret = s9.world.auth.registered[client_id].secret
    assert secret is not None
    [exchange] = [call for call in s9.world.auth.calls if call.grant_type == "authorization_code"]
    assert exchange.auth == "basic"
    assert sorted(s9.vault.store.names()) == [f"{SERVER}-client-secret", SLOT]
    sweep(s9, secret)


async def test_j1_the_older_server_with_no_protected_resource_metadata(
    tmp_path: Path, ca: ProviderCA, monkeypatch: pytest.MonkeyPatch
) -> None:
    """D.2a: a legacy server publishing no protected-resource metadata, with its authorization
    server's metadata at its own URL: the plan says so and names the ZoeyMCP heuristic, and the
    resource sent is the server URL as typed."""
    with deployed(tmp_path, ca, monkeypatch, mode="legacy") as s9:
        auth, mcp = s9.world.auth, s9.world.mcp
        auth.issuer, auth.endpoint_base = SERVER_URL, ISSUER
        mcp.prm, mcp.as_metadata = "none", auth.metadata
        with s9.up() as running:
            fragment = first_run(s9, [*J1, "--client-id", CLIENT_ID, "--yes"])
            credential = load_mapping(fragment)["credentials"][SERVER]
            assert (credential["issuer"], "resource_metadata" in credential) == (SERVER_URL, False)
            resource = {"resource": SERVER_URL}
            assert credential["extra_params"] == credential["authorize_params"] == resource
            for label, value in (
                ("Resource metadata", "none (D.2a)"),
                ("Issuer", f"{SERVER_URL} ({ISSUER_LABELS['heuristic']})"),
                ("Note", NOTES["legacy"]),
                ("Note", NOTES["heuristic"]),
            ):
                assert plan_row(label, value) in s9.plan, (label, s9.plan)
            s9.commit(fragment)
            err = second_run(s9)
            s9.commit(review(s9, err, approve(APPROVED)), assign=True)
            await the_calls(s9, running, [ALLOWED, APPROVED])
    [exchange] = [call for call in s9.world.auth.calls if call.grant_type == "authorization_code"]
    assert exchange.params["resource"] == SERVER_URL
    sweep(s9)


async def test_j5_through_the_operators_proxy_resumed_from_the_printed_command(
    tmp_path: Path, ca: ProviderCA, monkeypatch: pytest.MonkeyPatch
) -> None:
    """J5 with J3's client (FM-11, OPS-8): the proxy refuses the server's host, then the
    authorization server's; each time the answer names the hosts and the command to run again,
    which carries on once the operator allows them. Then everything goes through the proxy."""
    proxy = ConnectProxy(refuse={MCP, AUTH})
    options: dict[str, Any] = {"auth": "basic", "client_secret": SECRET, "rotate": False}
    with deployed(tmp_path, ca, monkeypatch, proxy=proxy, **options) as s9, s9.up() as running:
        argv = [*J1, "--issuer", ISSUER, "--client-id", CLIENT_ID, "--client-secret"]
        argv += ["--client-auth", "basic", "--redirect-uri", LOOPBACK_REDIRECT, "--yes"]
        for refused, allowed in ((MCP, {AUTH}), (AUTH, set())):
            code, out, err = s9.cli(argv, io.StringIO(SECRET + "\n"))
            assert (code, out) == (1, ""), err
            assert f"refused the vault's connection to {refused}." in err
            # The hosts to allow and D.11's Squid lines for them, the refused one among them.
            for host in {MCP, refused}:
                assert f"    {host}:443\n" in err
                assert re.search(rf"^    acl zoeymcp_onboard_\d+ dstdomain -n {host}$", err, re.M)
            assert re.search(r"^    http_access allow \S+ CONNECT zoeymcp_onboard_\d+ ", err, re.M)
            [(argv, source, target)] = printed(err)
            assert (source, target) == (None, f"onboard-{SERVER}-1.yaml")
            assert "-T vault zoeymcp login --mcp" in err
            proxy.refuse = allowed
        fragment = first_run(s9, argv, SECRET + "\n")
        s9.commit(fragment)
        err = second_run(s9)
        s9.commit(review(s9, err, approve(APPROVED)), assign=True)
        await the_calls(s9, running, [ALLOWED, APPROVED])
    # The vault resolved nothing itself: the proxy judged every address (B.3).
    assert s9.world.resolver.lookups == []
    assert {f"{MCP}:443", f"{AUTH}:443"} <= set(proxy.targets)
    assert {line["via"] for line in s9.seen.events("discovery_fetch")} == {"proxy"}
    sweep(s9, SECRET)


@pytest.mark.parametrize("switch", [Switch.HEADERS_BEFORE_AUTH, Switch.DISCOVER_WITHOUT_AUTH])
async def test_j1_a_server_that_reads_the_request_before_the_token(
    tmp_path: Path, ca: ProviderCA, monkeypatch: pytest.MonkeyPatch, switch: Switch
) -> None:
    """SPEC-1: the probe is a well-formed request, so a server that checks headers first still
    answers 401, and one that answers ``server/discover`` openly has its metadata found."""
    switches = frozenset({switch})
    with deployed(tmp_path, ca, monkeypatch, switches=switches) as s9, s9.up() as running:
        err = onboarded_by_cli(s9, [*J1, "--client-id", CLIENT_ID, "--yes"])
        s9.commit(review(s9, err, approve(APPROVED)), assign=True)
        await the_calls(s9, running, [ALLOWED, APPROVED])
    sweep(s9)


async def test_j4_about_a_hundred_tools_through_the_choices_file(
    tmp_path: Path, ca: ProviderCA, monkeypatch: pytest.MonkeyPatch
) -> None:
    """J4 in the CLI: the counts, the suggested file unedited but for one approve, and the
    agent given exactly those tools."""
    switches = frozenset({Switch.LARGE})
    with deployed(tmp_path, ca, monkeypatch, switches=switches) as s9, s9.up() as running:
        err = onboarded_by_cli(s9, [*J1, "--client-id", CLIENT_ID, "--yes"])
        assert (
            "Reviewing through the gateway: 96 tools (64 the server marks read-only, 32 not "
            "annotated, 1 with an error finding).\n"
        ) in err
        fragment = review(s9, err, approve(APPROVED))
        tools = load_mapping(fragment)["gateway"]["servers"][SERVER]["tools"]
        assert (len(tools["allow"]), tools["approve"]) == (LARGE_ALLOWED, [APPROVED])
        s9.commit(fragment, assign=True)
        await the_calls(s9, running, tools["include"])
    sweep(s9)


# --- J2: the portal ----------------------------------------------------------------------------


def signed_in(s9: S9, passkey: SoftAuthenticator, browser: Browser) -> Page:
    """A setup code issued as the socket issues one, a passkey enrolled with it, and the
    sign-in with that passkey."""
    vault = s9.vault
    code, _ = vault.call(lambda: vault.setup.issue())
    page = browser.page(vault.portal_origin)
    assert redeem(page, code.reveal()).status_code == 200
    assert enrol(page, passkey).status_code == 200
    assert login(page, passkey).status_code == 200
    return page


def fetched(s9: S9, page: Page, method: str, path: str, body: Any = None) -> dict[str, Any]:
    """One answer of the portal's API, which must succeed; kept for the sweep."""
    answer = page.fetch(method, path, json=body)
    s9.seen.outputs.append(answer.text)
    assert answer.status_code == 200, answer.text
    found: dict[str, Any] = answer.json()
    return found


def row(s9: S9, page: Page) -> dict[str, Any]:
    """The MCP servers page's one row."""
    found: list[dict[str, Any]] = fetched(s9, page, "GET", "/api/servers")["servers"]
    [only] = found
    return only


def reviewed_in_the_portal(s9: S9, page: Page) -> tuple[str, dict[str, Any]]:
    """The review the page queues once Connect completes, polled until the gateway reports."""
    job: str = fetched(s9, page, "POST", f"/api/review/{SERVER}", {})["job"]
    wait_for(
        lambda: page.fetch("GET", f"/api/review/jobs/{job}").json()["state"],
        lambda state: state == "done",
        what="the portal's review",
        timeout=60,
    )
    return job, fetched(s9, page, "GET", f"/api/review/jobs/{job}")


async def test_j2_a_client_the_vault_registers_and_a_hundred_tools(
    tmp_path: Path, ca: ProviderCA, monkeypatch: pytest.MonkeyPatch
) -> None:
    """J2 (DCR) and J4 in the portal: two passkey prompts (register, connect), the provider's
    callback, the page's review, Select suggested and one approve, fragment 2 committed."""
    options: dict[str, Any] = {"registration": "open", "switches": frozenset({Switch.LARGE})}
    with deployed(tmp_path, ca, monkeypatch, portal=True, **options) as s9, s9.up() as running:
        passkey = SoftAuthenticator()
        with (
            s9.world.provider() as provider,
            Browser(address=loopback, remote={ISSUER: provider}) as browser,
        ):
            page = signed_in(s9, passkey, browser)
            callback = f"{s9.vault.portal_origin}/oauth/callback/{SERVER}"
            plan = fetched(s9, page, "POST", "/api/onboard/discover", {"url": SERVER_URL})
            assert (plan["plan"]["registration"], plan["plan"]["redirect_uri"]) == ("dcr", callback)
            assert row(s9, page)["state"] == "needs_register"
            data = {"onboarding": plan["onboarding"]}
            made = step_up(page, passkey, "onboard.register", data)
            assert made.status_code == 200, made.text
            s9.seen.outputs.append(made.text)
            assert row(s9, page)["state"] == "needs_commit"
            s9.commit(made.json()["diff"]["yaml"])
            assert row(s9, page)["state"] == "needs_connect"
            begun, connected = connect_by_callback(page, passkey, SERVER)
            assert connected.status_code == 200, connected.text
            s9.seen.outputs += [json.dumps(begun), connected.text]
            # Each confirm is logged once its answer is sent: wait for both lines.
            confirmed = s9.seen.events("step_up_confirmed", at_least=2)
            assert [line["action"] for line in confirmed] == ["onboard.register", "oauth.complete"]
            assert row(s9, page)["state"] == "needs_review"
            job, report = reviewed_in_the_portal(s9, page)
            assert (report["counts"]["tools"], report["counts"]["read_only"]) == (96, 64)
            suggested = [
                tool["name"]
                for tool in report["tools"]
                if tool["pinnable"] and tool["suggested"] == "allow"
            ]
            assert len(suggested) == LARGE_ALLOWED
            choices = {"include": [*suggested, APPROVED], "allow": suggested, "approve": [APPROVED]}
            fragment_2 = fetched(s9, page, "POST", f"/api/review/jobs/{job}/diff", choices)
            s9.commit(fragment_2["diff"]["yaml"], assign=True)
            assert row(s9, page)["state"] == "reviewed"
        await the_calls(s9, running, [*suggested, APPROVED])
    assert len(s9.world.auth.registrations) == 1
    sweep(s9)


async def test_j2_a_given_public_client_with_no_passkey_prompt_until_connect(
    tmp_path: Path, ca: ProviderCA, monkeypatch: pytest.MonkeyPatch
) -> None:
    """J2 for a given public client: Make the YAML sends and stores nothing, so it asks for no
    passkey; Connect by paste asks for one, at completion."""
    with deployed(tmp_path, ca, monkeypatch, portal=True) as s9, s9.up() as running:
        passkey = SoftAuthenticator()
        with Browser(address=loopback) as browser:
            page = signed_in(s9, passkey, browser)
            body = {"url": SERVER_URL, "client_id": CLIENT_ID}
            plan = fetched(s9, page, "POST", "/api/onboard/discover", body)
            assert plan["next"] == [{"do": "make_fragment", "label": "Make the YAML"}]
            made = fetched(s9, page, "POST", f"/api/onboard/{plan['onboarding']}/fragment", {})
            s9.commit(made["diff"]["yaml"])
            started = fetched(s9, page, "POST", f"/api/oauth/{SERVER}/start", {})
            pasted = s9.world.browse(started["authorize_url"])
            data = {"credential": SERVER, "flow": started["flow"], "redirect_url": pasted}
            connected = step_up(page, passkey, "oauth.complete", data)
            assert connected.status_code == 200, connected.text
            s9.seen.outputs.append(connected.text)
            [confirmed] = s9.seen.events("step_up_confirmed", at_least=1)
            assert confirmed["action"] == "oauth.complete"
            job, _ = reviewed_in_the_portal(s9, page)
            choices = {"include": [ALLOWED, APPROVED], "allow": [ALLOWED], "approve": [APPROVED]}
            fragment_2 = fetched(s9, page, "POST", f"/api/review/jobs/{job}/diff", choices)
            s9.commit(fragment_2["diff"]["yaml"], assign=True)
        await the_calls(s9, running, [ALLOWED, APPROVED])
    assert [line["action"] for line in s9.seen.events("step_up_confirmed")] == ["oauth.complete"]
    assert s9.world.auth.registrations == []
    sweep(s9)


async def test_j14_a_managed_vaults_portal_onboards_in_five_prompts(
    tmp_path: Path, ca: ProviderCA, monkeypatch: pytest.MonkeyPatch
) -> None:
    """J14h in the portal of a managed vault (M6 design G.9, G.3; D-147's obligation): register
    (prompt 1), Save of fragment 1's change, a draft the vault plans (prompt 2: nothing secret
    reached the fakes before it, X1), Connect through the callback (3), the review's Save (4,
    its way on Give to clients) and Give to clients (5); then the agent lists and calls the
    tools. No fragment is shown or committed: each change is a revision the vault installs."""
    options: dict[str, Any] = {"registration": "open"}
    with (
        deployed(tmp_path, ca, monkeypatch, portal=True, managed=True, **options) as s9,
        s9.up() as running,
    ):
        assert s9.vault.managed is not None
        assert s9.vault.managed.revision == 1
        passkey = SoftAuthenticator()
        with (
            s9.world.provider() as provider,
            Browser(address=loopback, remote={ISSUER: provider}) as browser,
        ):
            page = signed_in(s9, passkey, browser)
            plan = fetched(s9, page, "POST", "/api/onboard/discover", {"url": SERVER_URL})
            assert plan["next"] == [{"do": "register", "label": "Register its client"}]
            onboarding = plan["onboarding"]
            made = step_up(page, passkey, "onboard.register", {"onboarding": onboarding})
            assert made.status_code == 200, made.text
            s9.seen.outputs.append(made.text)
            assert "diff" not in made.json()
            assert (row(s9, page)["state"], made.json()["next"][0]["do"]) == ("needs_save", "save")
            nothing_secret_yet(s9.world)
            draft = fetched(s9, page, "POST", f"/api/onboard/{onboarding}/fragment", {})
            assert (draft["kind"], draft["base"]) == ("policy.save", 1)
            data = {"draft": draft["draft"], "base": 1}
            saved = step_up(page, passkey, "policy.save", data)
            assert saved.status_code == 200, saved.text
            s9.seen.outputs.append(saved.text)
            assert row(s9, page)["state"] == "needs_connect"
            s9.applied()
            begun, connected = connect_by_callback(page, passkey, SERVER)
            assert connected.status_code == 200, connected.text
            s9.seen.outputs += [json.dumps(begun), connected.text]
            assert row(s9, page)["state"] == "needs_review"
            job, _ = reviewed_in_the_portal(s9, page)
            choices = {
                "include": [ALLOWED, APPROVED],
                "allow": [ALLOWED],
                "approve": [APPROVED],
                "decline_rest": True,
            }
            draft = fetched(s9, page, "POST", f"/api/review/jobs/{job}/diff", choices)
            assert draft["kind"] == "policy.save"
            reviewed = step_up(page, passkey, "policy.save", {"draft": draft["draft"], "base": 2})
            assert reviewed.status_code == 200, reviewed.text
            s9.seen.outputs.append(reviewed.text)
            assert reviewed.json()["next"][-1]["do"] == "assign_clients"
            assert (row(s9, page)["state"], row(s9, page)["clients_shown"]) == ("reviewed", [])
            give = {"base": 3, "client": CLIENT, "servers": [SERVER]}
            given = step_up(page, passkey, "client.servers", give)
            assert given.status_code == 200, given.text
            s9.seen.outputs.append(given.text)
            assert row(s9, page)["clients_shown"] == [CLIENT]
            s9.applied()
            confirmed = s9.seen.events("step_up_confirmed", at_least=5)
            assert [line["action"] for line in confirmed] == [
                "onboard.register",
                "policy.save",
                "oauth.complete",
                "policy.save",
                "client.servers",
            ]
        await the_calls(s9, running, [ALLOWED, APPROVED])
    assert s9.vault.managed.revision == 4
    assert len(s9.world.auth.registrations) == 1
    sweep(s9)
