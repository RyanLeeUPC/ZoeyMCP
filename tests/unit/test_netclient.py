"""Effect tests for the vault's guarded clients (M7 design B.2, B.3, B.6; X3, X23, FM-8, TI-10),
through the real ``VaultApp`` constructor (F-2): the onboarding client (step 4), and the route and
token clients (step 16), whose refusals answer 502 ``address_refused``, fail a token call with the
reason ``address_refused``, and are logged and kept for health.

Names resolve through the fake resolver (tests/fakes/resolver.py): each answers an address
reserved for the run, and the dial map sends the address the guard checked to a TLS fake on
loopback. ``netguard`` itself runs unchanged on every connection. The fakes' certificates come
from a test CA, which certifi's bundle is patched to be, as tests/acceptance/procs.py's launcher
does, except in X23's row, which keeps the real bundle.
"""

from __future__ import annotations

import io
import json
import socket
import ssl
from collections.abc import AsyncIterator, Iterator, Sequence
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import anyio
import certifi
import httpx
import pytest

from tests.acceptance.tls import ProviderCA, issue_cert, make_ca
from tests.fakes.connect_proxy import ConnectProxy, ProxySwitch, serve_proxy
from tests.fakes.resolver import TIMEOUT, FakeResolver, serve_https
from zoeymcp.common.netguard import AddressVerdict
from zoeymcp.common.policy import Policy
from zoeymcp.vault import logs, netclient
from zoeymcp.vault.app import VaultApp
from zoeymcp.vault.keys import KeySet, generate_master_key
from zoeymcp.vault.netclient import ONBOARDING_EXTENSION, AddressRefused, ResolveFailed
from zoeymcp.vault.oauth.protocol import TokenRequest, TokenResponse
from zoeymcp.vault.server import load_runtime
from zoeymcp.vault.store import SecretStore

from .conftest import EXAMPLE_POLICY

NAME = "mcp.example.com"
LAN = "mcp.lan.example"
# A private name with a punycode label, and the name httpx decodes it to.
PUNY = "xn--fiqs8s.lan.example"
UNICODE = "\u4e2d\u56fd.lan.example"
KEY = generate_master_key()


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(scope="module")
def ca(tmp_path_factory: pytest.TempPathFactory) -> ProviderCA:
    return make_ca(tmp_path_factory.mktemp("netclient-ca"))


@pytest.fixture(scope="module")
def certs(ca: ProviderCA, tmp_path_factory: pytest.TempPathFactory) -> dict[str, tuple[Path, Path]]:
    directory = tmp_path_factory.mktemp("netclient-certs")
    return {name: issue_cert(ca, name, directory) for name in (NAME, LAN, PUNY)}


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> FakeResolver:
    resolver = FakeResolver()
    monkeypatch.setattr(netclient, "HOOKS", resolver.hooks())
    return resolver


@pytest.fixture
def trusted(ca: ProviderCA, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(certifi, "where", lambda: str(ca.ca_file))


pytestmark = pytest.mark.anyio


def vault(tmp_path: Path, *, proxy: str | None = None) -> VaultApp:
    """The real VaultApp, from the example policy (with ``egress_proxy`` when given)."""
    text = EXAMPLE_POLICY.read_text(encoding="utf-8")
    if proxy is not None:
        text = text.replace(
            "gateway_key_generation: 1", f"gateway_key_generation: 1\negress_proxy: {proxy}"
        )
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_bytes(text.encode())
    runtime = load_runtime(str(policy_file), tmp_path / "state", {"ZOEYMCP_MASTER_KEY": KEY})
    return VaultApp(runtime.policy, runtime.store, runtime.keys, environ={})


@asynccontextmanager
async def running(tmp_path: Path, *, proxy: str | None = None) -> AsyncIterator[httpx.AsyncClient]:
    app = vault(tmp_path, proxy=proxy)
    try:
        with anyio.fail_after(10):
            yield app.onboarding_client
    finally:
        await app.aclose()


def onboarding(purpose: str, target: str, onboarding_id: str = "onb-1") -> dict[str, Any]:
    return {ONBOARDING_EXTENSION: (onboarding_id, purpose, target)}


async def refused(client: httpx.AsyncClient, url: str, **kwargs: Any) -> AddressVerdict:
    with pytest.raises(AddressRefused) as caught:
        await client.get(url, **kwargs)
    return caught.value.verdict


def causes(exc: BaseException) -> Iterator[BaseException]:
    cause: BaseException | None = exc
    while cause is not None:
        yield cause
        cause = cause.__cause__ or cause.__context__


# --- X3: connect to the checked address ---------------------------------------------------------


@pytest.mark.usefixtures("trusted")
async def test_rebinding_between_connections(
    tmp_path: Path, fake: FakeResolver, certs: dict[str, tuple[Path, Path]]
) -> None:
    """FM-8: one lookup per connection, a connect to the address it checked, and the second
    connection, whose lookup answers private, refused before anything is sent."""
    async with serve_https(*certs[NAME]) as (port, seen), running(tmp_path) as client:
        public = fake.serve(NAME, port)
        fake.rebind(NAME, public, "10.0.0.1")
        first = await client.get(f"https://{NAME}/.well-known/oauth-protected-resource")
        assert (first.status_code, first.text) == (200, "ok")
        verdict = await refused(client, f"https://{NAME}/.well-known/oauth-protected-resource")
    assert verdict == AddressVerdict(allowed=False, reason="private", address="10.0.0.1")
    assert fake.lookups == [(NAME, 443), (NAME, 443)]
    assert fake.dialled == [(public, 443)]
    assert seen.connections == 1
    assert seen.names == [NAME]  # SNI is the URL's name, not the address dialled
    assert len(seen.heads) == 1
    assert seen.heads[0].startswith(b"GET /.well-known/oauth-protected-resource HTTP/1.1\r\n")


@pytest.mark.usefixtures("trusted")
async def test_a_kept_connection_is_reused_without_a_second_lookup(
    tmp_path: Path, fake: FakeResolver, certs: dict[str, tuple[Path, Path]]
) -> None:
    """The lookup belongs to the connection: a pooled one is reused as it was checked."""
    async with (
        serve_https(*certs[NAME], keep_alive=True) as (port, seen),
        running(tmp_path) as client,
    ):
        fake.serve(NAME, port)
        for _ in range(2):
            assert (await client.get(f"https://{NAME}/")).status_code == 200
    assert fake.lookups == [(NAME, 443)]
    assert seen.connections == 1


@pytest.mark.parametrize(
    ("answer", "reason", "address"),
    [
        (["PUBLIC", "192.168.1.1"], "private", "192.168.1.1"),  # mixed: refused whole
        (["192.168.1.1", "PUBLIC"], "private", "192.168.1.1"),
        (["PUBLIC", "::ffff:127.0.0.1"], "loopback", "::ffff:127.0.0.1"),
        (["169.254.169.254"], "link_local", "169.254.169.254"),
        (["64:ff9b::a9fe:a9fe"], "link_local", "64:ff9b::a9fe:a9fe"),
        (["100.64.0.1"], "cgnat", "100.64.0.1"),
        (["2002:7f00:1::1"], "embedded", "2002:7f00:1::1"),
        (["fe80::1%eth0"], "unparsable", "fe80::1%eth0"),
        ([], "no_address", None),
    ],
)
async def test_any_denied_address_refuses_the_name(
    tmp_path: Path, fake: FakeResolver, answer: list[str], reason: str, address: str | None
) -> None:
    public = fake.serve(NAME, 9)
    fake.answer(NAME, [public if a == "PUBLIC" else a for a in answer])
    async with running(tmp_path) as client:
        verdict = await refused(client, f"https://{NAME}/")
    assert verdict == AddressVerdict(allowed=False, reason=reason, address=address)
    assert fake.dialled == []


@pytest.mark.parametrize("answer", ["unknown", TIMEOUT])
async def test_a_name_that_doesnt_resolve(tmp_path: Path, fake: FakeResolver, answer: str) -> None:
    if answer == TIMEOUT:
        fake.answer(NAME, TIMEOUT)
    async with running(tmp_path) as client:
        with pytest.raises(
            ResolveFailed, match=r"^mcp\.example\.com:443: the name didn't resolve$"
        ):
            await client.get(f"https://{NAME}/")
    assert fake.dialled == []


async def test_the_real_resolver_answers_each_address_once() -> None:
    with anyio.fail_after(10):
        addresses = await netclient.resolve("localhost", 443)
    assert addresses
    assert len(set(addresses)) == len(addresses)
    assert set(addresses) <= {"127.0.0.1", "::1"}


async def test_the_real_resolver_gives_up_after_its_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def never(*args: object, **kwargs: object) -> list[Any]:
        await anyio.Event().wait()
        raise AssertionError("unreachable")

    monkeypatch.setattr(netclient, "RESOLVE_TIMEOUT", 0.05)
    monkeypatch.setattr(anyio, "getaddrinfo", never)
    with anyio.fail_after(5), pytest.raises(TimeoutError):
        await netclient.resolve(NAME, 443)


# --- TI-10: a typed server's private exception, per request -------------------------------------


@pytest.mark.usefixtures("trusted")
async def test_an_onboardings_exception_covers_its_own_probe_and_prm(
    tmp_path: Path, fake: FakeResolver, certs: dict[str, tuple[Path, Path]]
) -> None:
    """Each fetch makes its own connection and closes it with its answer, though the server
    would keep it."""
    async with (
        serve_https(*certs[LAN], keep_alive=True) as (port, seen),
        running(tmp_path) as client,
    ):
        fake.serve(LAN, port, address="10.0.0.5")
        for count, purpose in enumerate(("probe", "prm"), start=1):
            answer = await client.get(
                f"https://{LAN}/mcp", extensions=onboarding(purpose, f"{LAN}:443")
            )
            assert answer.status_code == 200
            await seen.until_left(count)
    assert seen.connections == 2
    assert seen.left == 2
    assert fake.dialled == [("10.0.0.5", 443), ("10.0.0.5", 443)]


@pytest.mark.parametrize(
    "extension",
    [
        None,
        onboarding("as", f"{LAN}:443"),  # AS metadata never gets it
        onboarding("register", f"{LAN}:443"),
        onboarding("probe", f"{LAN}:8443"),  # another port
        onboarding("probe", "other.lan.example:443"),  # another host
        onboarding("probe", "MCP.LAN.EXAMPLE:443"),  # not as entry_key writes it
        {ONBOARDING_EXTENSION: f"onb-1 probe {LAN}:443"},  # not the tuple
        {ONBOARDING_EXTENSION: ("onb-1", f"{LAN}:443")},
    ],
)
async def test_no_other_request_gets_the_exception(
    tmp_path: Path, fake: FakeResolver, extension: dict[str, Any] | None
) -> None:
    fake.serve(LAN, 9, address="10.0.0.5")
    async with running(tmp_path) as client:
        verdict = await refused(client, f"https://{LAN}/mcp", extensions=extension)
    assert verdict == AddressVerdict(allowed=False, reason="private", address="10.0.0.5")
    assert fake.dialled == []


@pytest.mark.usefixtures("trusted")
async def test_a_second_onboarding_is_refused_for_the_same_host_port(
    tmp_path: Path, fake: FakeResolver, certs: dict[str, tuple[Path, Path]]
) -> None:
    """The first onboarding's connection, though the server would keep it, is closed with its
    answer: the second onboarding's request makes its own, and the guard refuses it."""
    async with (
        serve_https(*certs[LAN], keep_alive=True) as (port, seen),
        running(tmp_path) as client,
    ):
        fake.serve(LAN, port, address="10.0.0.5")
        first = await client.get(f"https://{LAN}/mcp", extensions=onboarding("probe", f"{LAN}:443"))
        assert first.status_code == 200
        await seen.until_left(1)  # the client closed it; the server would have kept it
        verdict = await refused(client, f"https://{LAN}/mcp")
        assert verdict.reason == "private"
        verdict = await refused(
            client, f"https://{LAN}/mcp", extensions=onboarding("as", f"{LAN}:443", "onb-2")
        )
        assert verdict.reason == "private"
    assert fake.lookups == [(LAN, 443)] * 3
    assert seen.connections == 1
    assert seen.left == 1
    assert len(seen.heads) == 1


@pytest.mark.usefixtures("trusted")
async def test_a_punycode_names_exception_is_written_as_the_backend_sees_it(
    tmp_path: Path, fake: FakeResolver, certs: dict[str, tuple[Path, Path]]
) -> None:
    """The guard sees the IDNA-encoded name, whichever spelling the URL has, so the exception
    names that form: the decoded name is no exception at all."""
    async with serve_https(*certs[PUNY]) as (port, seen), running(tmp_path) as client:
        fake.serve(PUNY, port, address="10.0.0.6")
        for host in (PUNY, UNICODE):
            answer = await client.get(
                f"https://{host}/mcp", extensions=onboarding("probe", f"{PUNY}:443")
            )
            assert answer.status_code == 200
        for host in (PUNY, UNICODE):
            verdict = await refused(
                client, f"https://{host}/mcp", extensions=onboarding("probe", f"{UNICODE}:443")
            )
            assert verdict.reason == "private"
    assert fake.lookups == [(PUNY, 443)] * 4
    assert fake.dialled == [("10.0.0.6", 443)] * 2
    assert seen.names == [PUNY, PUNY]


# --- B.3: with egress_proxy, nothing is resolved locally ----------------------------------------


@pytest.fixture
def lookups(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    """Every host the process asks getaddrinfo about, as text: anyio, which httpcore's backend
    uses, passes a name as IDNA-encoded bytes."""
    seen: list[Any] = []
    real = socket.getaddrinfo

    def recording(host: Any, *args: Any, **kwargs: Any) -> Any:
        seen.append(host.decode() if isinstance(host, bytes) else host)
        return real(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", recording)
    return seen


async def test_nothing_resolves_locally_with_a_proxy(
    tmp_path: Path, fake: FakeResolver, lookups: list[Any]
) -> None:
    proxy = ConnectProxy({ProxySwitch.REFUSE_403})
    with serve_proxy(proxy) as url:
        async with running(tmp_path, proxy=url) as client:
            with pytest.raises(httpx.ProxyError, match=r"^403 Forbidden$"):
                await client.get(f"https://{NAME}/")
            # The proxy judges the address: an onboarding's exception changes nothing here.
            with pytest.raises(httpx.ProxyError):
                await client.get(f"https://{LAN}/mcp", extensions=onboarding("probe", f"{LAN}:443"))
    assert proxy.targets == [f"{NAME}:443", f"{LAN}:443"]
    assert fake.lookups == []
    assert set(lookups) <= {"127.0.0.1"}


# --- X23: certifi's roots, and no others --------------------------------------------------------


async def test_a_certificate_only_a_test_store_trusts_is_refused(
    tmp_path: Path, fake: FakeResolver, certs: dict[str, tuple[Path, Path]]
) -> None:
    async with serve_https(*certs[NAME]) as (port, seen), running(tmp_path) as client:
        fake.serve(NAME, port)
        with pytest.raises(httpx.ConnectError) as caught:
            await client.get(f"https://{NAME}/")
    assert any(isinstance(e, ssl.SSLCertVerificationError) for e in causes(caught.value))
    assert seen.heads == []


# --- how the vault holds it ---------------------------------------------------------------------


async def test_the_onboarding_client_is_built_once_from_the_startup_policy(
    tmp_path: Path,
) -> None:
    app = vault(tmp_path)
    try:
        client = app.onboarding_client
        assert client is not app._client
        assert isinstance(client._transport, netclient.GuardedTransport)
        assert client.follow_redirects is False
        assert client.trust_env is False
        assert type(client.cookies.jar).__name__ == "_DiscardingJar"
    finally:
        await app.aclose()
    assert client.is_closed
    (tmp_path / "proxied").mkdir(mode=0o700)
    proxied = vault(tmp_path / "proxied", proxy="http://proxy.example:3128")
    try:
        assert proxied.egress_proxy == "http://proxy.example:3128"
        assert isinstance(proxied.onboarding_client._transport, httpx.AsyncHTTPTransport)
    finally:
        await proxied.aclose()


async def test_an_injected_client_serves_onboarding_too(tmp_path: Path) -> None:
    """A test or self-test that injects a client never falls back to a networked one."""
    runtime = load_runtime(str(EXAMPLE_POLICY), tmp_path / "state", {"ZOEYMCP_MASTER_KEY": KEY})
    injected = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(204)))
    app = VaultApp(runtime.policy, runtime.store, runtime.keys, environ={}, client=injected)
    try:
        assert app.onboarding_client is injected
    finally:
        await app.aclose()
    assert injected.is_closed


# --- step 16: the route and token clients -------------------------------------------------------

AGENT = "172.30.4.10"
PH = "ph-agent1-direct-0001"
HINT = "list {} in egress_private if this destination is meant to be private"


@pytest.fixture
def events() -> Iterator[io.StringIO]:
    stream = io.StringIO()
    logs.set_stream(stream)
    try:
        yield stream
    finally:
        logs.set_stream(None)


def lines(stream: io.StringIO, kind: str) -> list[dict[str, Any]]:
    found = [json.loads(line) for line in stream.getvalue().splitlines()]
    return [line for line in found if line["event"] == kind]


def guarded_policy(
    upstream: str, *, private: Sequence[str] = (), proxy: str | None = None
) -> Policy:
    """One route to ``upstream`` for a placeholder caller, and ``egress_private``."""
    document: dict[str, Any] = {
        "version": 1,
        "mode": "declarative",
        "egress_private": list(private),
        "routes": [
            {
                "name": "api",
                "prefix": "/api",
                "upstream": upstream,
                "callers": [{"placeholder": PH}],
                "rules": [{"methods": ["GET"], "paths": ["/**"]}],
            }
        ],
    }
    if proxy is not None:
        document["egress_proxy"] = proxy
    return Policy.model_validate(document)


def guarded_vault(tmp_path: Path, policy: Policy) -> VaultApp:
    """The real VaultApp with no client injected: every client is netclient's."""
    keys = KeySet.from_text(KEY)
    store = SecretStore(tmp_path / "state", keys)
    store.load()
    return VaultApp(policy, store, keys, environ={})


async def through(app: VaultApp, path: str = "/api/x") -> httpx.Response:
    """A placeholder caller's GET through the vault's route."""
    transport = httpx.ASGITransport(app=app, client=(AGENT, 40000))
    async with httpx.AsyncClient(transport=transport, base_url="http://vault") as caller:
        return await caller.get(path, headers={"authorization": f"Bearer {PH}"})


async def token_call(app: VaultApp, url: str) -> TokenResponse:
    """One POST through the vault's token client, as login and refresh make it."""
    return await app.tokens.post(TokenRequest(url, (), b"grant_type=refresh_token"))


def kept(app: VaultApp) -> list[dict[str, Any]]:
    """The token manager's refusals, without the time each was seen."""
    return [{k: v for k, v in item.items() if k != "at"} for item in app.tokens.refused()]


def fields(line: dict[str, Any]) -> dict[str, Any]:
    return {k: line[k] for k in ("purpose", "host", "port", "verdict")}


@pytest.mark.usefixtures("trusted")
async def test_a_route_rebinding_between_connections_answers_address_refused(
    tmp_path: Path, fake: FakeResolver, certs: dict[str, tuple[Path, Path]], events: io.StringIO
) -> None:
    """FM-8 for routes: the first request reaches the upstream at the address checked; the
    second connection's lookup answers private, so the route answers 502 ``address_refused``
    with nothing sent, logged with the hint and kept for health."""
    app = guarded_vault(tmp_path, guarded_policy(f"https://{NAME}"))
    try:
        async with serve_https(*certs[NAME]) as (port, seen):
            public = fake.serve(NAME, port)
            fake.rebind(NAME, public, "10.0.0.1")
            with anyio.fail_after(10):
                first = await through(app)
                second = await through(app)
    finally:
        await app.aclose()
    assert (first.status_code, first.text) == (200, "ok")
    assert second.status_code == 502
    assert second.json() == {"error": "upstream unavailable", "code": "address_refused"}
    assert second.headers["x-zoeymcp-vault"] == "refused"
    assert fake.lookups == [(NAME, 443), (NAME, 443)]
    assert fake.dialled == [(public, 443)]
    assert len(seen.heads) == 1
    assert seen.heads[0].startswith(b"GET /x HTTP/1.1\r\n")
    [refused] = lines(events, "address_refused")
    assert fields(refused) == {"purpose": "route", "host": NAME, "port": 443, "verdict": "private"}
    request = lines(events, "request")[-1]
    assert (request["status"], request["code"]) == (502, "address_refused")
    assert request["reason"] == f"address refused (private): {HINT.format(f'{NAME}:443')}"
    assert kept(app) == [{"purpose": "route", "host": NAME, "port": 443, "verdict": "private"}]


@pytest.mark.usefixtures("trusted")
async def test_a_reload_that_lists_a_private_upstream_lets_the_next_request_through(
    tmp_path: Path, fake: FakeResolver, certs: dict[str, tuple[Path, Path]]
) -> None:
    """An unlisted LAN upstream is refused; the route client reads the running policy's
    egress_private at each connection, so a reload listing it needs no restart."""
    app = guarded_vault(tmp_path, guarded_policy(f"https://{LAN}"))
    try:
        async with serve_https(*certs[LAN]) as (port, seen):
            fake.serve(LAN, port, address="10.0.0.5")
            with anyio.fail_after(10):
                refused = await through(app)
                app.reload(guarded_policy(f"https://{LAN}", private=[f"{LAN}:443"]))
                listed = await through(app)
    finally:
        await app.aclose()
    assert (refused.status_code, refused.json()["code"]) == (502, "address_refused")
    assert (listed.status_code, listed.text) == (200, "ok")
    assert fake.dialled == [("10.0.0.5", 443)]
    assert len(seen.heads) == 1


@pytest.mark.usefixtures("trusted")
async def test_a_token_endpoint_rebinding_between_connections_is_refused_and_kept(
    tmp_path: Path, fake: FakeResolver, certs: dict[str, tuple[Path, Path]], events: io.StringIO
) -> None:
    """FM-8 for tokens: login, refresh and the code exchange post on one guarded client, which
    refuses the second connection once the name answers private, logs it and keeps it."""
    app = guarded_vault(tmp_path, guarded_policy(f"https://{NAME}"))
    try:
        async with serve_https(*certs[NAME]) as (port, seen):
            public = fake.serve(NAME, port)
            fake.rebind(NAME, public, "10.0.0.1")
            with anyio.fail_after(10):
                first = await token_call(app, f"https://{NAME}/token")
                with pytest.raises(AddressRefused) as caught:
                    await token_call(app, f"https://{NAME}/token")
    finally:
        await app.aclose()
    assert (first.status, first.body) == (200, b"ok")
    verdict = AddressVerdict(allowed=False, reason="private", address="10.0.0.1")
    assert caught.value.verdict == verdict
    assert fake.dialled == [(public, 443)]
    assert len(seen.heads) == 1
    assert seen.heads[0].startswith(b"POST /token HTTP/1.1\r\n")
    [refused] = lines(events, "address_refused")
    assert fields(refused) == {"purpose": "token", "host": NAME, "port": 443, "verdict": "private"}
    assert kept(app) == [{"purpose": "token", "host": NAME, "port": 443, "verdict": "private"}]


@pytest.mark.usefixtures("trusted")
async def test_a_listed_token_endpoint_is_reached_after_a_reload(
    tmp_path: Path, fake: FakeResolver, certs: dict[str, tuple[Path, Path]]
) -> None:
    """The token client reads the running policy's egress_private, as the revocation client
    does (TI-11): a LAN token endpoint is refused until a reload lists it."""
    app = guarded_vault(tmp_path, guarded_policy(f"https://{NAME}"))
    try:
        async with serve_https(*certs[LAN]) as (port, seen):
            fake.serve(LAN, port, address="10.0.0.5")
            with anyio.fail_after(10):
                with pytest.raises(AddressRefused):
                    await token_call(app, f"https://{LAN}/token")
                app.reload(guarded_policy(f"https://{NAME}", private=[f"{LAN}:443"]))
                answer = await token_call(app, f"https://{LAN}/token")
    finally:
        await app.aclose()
    assert (answer.status, answer.body) == (200, b"ok")
    assert len(seen.heads) == 1


async def test_route_and_token_clients_refuse_a_certificate_only_a_test_store_trusts(
    tmp_path: Path, fake: FakeResolver, certs: dict[str, tuple[Path, Path]]
) -> None:
    """X23 for both: certifi's roots, and no others. The route answers 502 with no code."""
    app = guarded_vault(tmp_path, guarded_policy(f"https://{NAME}"))
    try:
        async with serve_https(*certs[NAME]) as (port, seen):
            fake.serve(NAME, port)
            with anyio.fail_after(10):
                routed = await through(app)
                with pytest.raises(httpx.ConnectError) as caught:
                    await token_call(app, f"https://{NAME}/token")
    finally:
        await app.aclose()
    assert routed.status_code == 502
    assert "code" not in routed.json()
    assert any(isinstance(e, ssl.SSLCertVerificationError) for e in causes(caught.value))
    assert seen.heads == []
    assert app.tokens.refused() == []


async def test_with_a_proxy_routes_and_tokens_resolve_nothing_locally(
    tmp_path: Path, fake: FakeResolver, lookups: list[Any]
) -> None:
    """B.3: with egress_proxy set nothing changes for an existing stack: the proxy is asked
    for the name, and the guard judges nothing, an unlisted LAN name included."""
    proxy = ConnectProxy({ProxySwitch.REFUSE_403})
    with serve_proxy(proxy) as url:
        app = guarded_vault(tmp_path, guarded_policy(f"https://{LAN}", proxy=url))
        try:
            with anyio.fail_after(10):
                routed = await through(app)
                with pytest.raises(httpx.ProxyError):
                    await token_call(app, f"https://{NAME}/token")
        finally:
            await app.aclose()
    assert routed.status_code == 502
    assert "code" not in routed.json()
    assert proxy.targets == [f"{LAN}:443", f"{NAME}:443"]
    assert fake.lookups == []
    assert set(lookups) <= {"127.0.0.1"}
    assert app.tokens.refused() == []


async def test_the_route_and_token_clients_are_built_once_from_the_startup_policy(
    tmp_path: Path,
) -> None:
    app = guarded_vault(tmp_path, guarded_policy(f"https://{NAME}"))
    route, token = app._client, app._token_client
    try:
        assert token is not None
        for client in (route, token):
            assert isinstance(client._transport, netclient.GuardedTransport)
            assert client.follow_redirects is False
            assert client.trust_env is False
            assert type(client.cookies.jar).__name__ == "_DiscardingJar"
        assert route.timeout == httpx.Timeout(60.0, connect=10.0)
        assert token.timeout == netclient.TOKEN_TIMEOUT
        # A reload that sets egress_proxy changes neither client: that waits for a restart.
        app.reload(guarded_policy(f"https://{NAME}", proxy="http://proxy.example:3128"))
        assert app._client is route
        assert app._token_client is token
        assert isinstance(route._transport, netclient.GuardedTransport)
        assert isinstance(token._transport, netclient.GuardedTransport)
        assert app.egress_proxy is None
    finally:
        await app.aclose()
    assert route.is_closed
    assert token is not None
    assert token.is_closed
    (tmp_path / "proxied").mkdir(mode=0o700)
    proxied = guarded_vault(
        tmp_path / "proxied", guarded_policy(f"https://{NAME}", proxy="http://proxy.example:3128")
    )
    try:
        assert isinstance(proxied._client._transport, httpx.AsyncHTTPTransport)
        assert proxied._token_client is not None
        assert isinstance(proxied._token_client._transport, httpx.AsyncHTTPTransport)
    finally:
        await proxied.aclose()


def test_the_hint_and_the_destination_key() -> None:
    """The key is the guard's: the IDNA-encoded host, without a trailing dot, the port written
    out, an IPv6 address in brackets; each one an egress_private entry the schema takes."""
    assert netclient.private_hint("files.lan.example:443") == HINT.format("files.lan.example:443")
    assert netclient.destination_key("https://Files.LAN.example/x") == "files.lan.example:443"
    assert netclient.destination_key("http://files.lan.example/x") == "files.lan.example:80"
    assert netclient.destination_key("https://[fd00::5]:8443/token") == "[fd00::5]:8443"
    assert netclient.destination_key("https://[FD00::5]/token") == "[fd00::5]:443"
    assert netclient.destination_key(f"https://{UNICODE}/mcp") == f"{PUNY}:443"
    assert netclient.destination_key("https://lan.example.:8443/x") == "lan.example:8443"
    assert netclient.guard_key("Files.LAN.example.", 443) == "files.lan.example:443"
    assert netclient.guard_key("fd00::5", 8443) == "[fd00::5]:8443"
    keys = ["files.lan.example:8443", f"{PUNY}:443", "[fd00::5]:443"]
    assert Policy.model_validate({"version": 1, "mode": "declarative", "egress_private": keys})


async def test_a_trailing_dot_name_is_listed_by_its_entry_without_the_dot() -> None:
    """httpcore gives the guard the URL's host with its trailing dot; ``lan.example.`` names
    ``lan.example``, so the entry the schema takes lists it, as the exact name still does."""
    with socket.create_server(("127.0.0.1", 0)) as listener:
        port = listener.getsockname()[1]

        async def lan(_host: str, _port: int) -> list[str]:
            return ["10.0.0.5"]

        def dial(_address: str, _port: int) -> tuple[str, int]:
            return "127.0.0.1", port

        for entry in (f"{LAN}:443", f"{LAN}.:443"):

            def listed(entry: str = entry) -> set[str]:
                return {entry}

            backend = netclient.GuardedBackend(listed, resolver=lan, dial=dial)
            stream = await backend.connect_tcp(f"{LAN}.", 443)
            await stream.aclose()
        backend = netclient.GuardedBackend(lambda: {f"{NAME}:443"}, resolver=lan, dial=dial)
        with pytest.raises(AddressRefused) as caught:
            await backend.connect_tcp(f"{LAN}.", 443)
    assert caught.value.verdict.reason == "private"
