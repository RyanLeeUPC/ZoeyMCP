"""Carrying out secret plans (M5 design G), and an onboarding's client secret (M7 design D.7,
CR-12): the store branch writes the plan's ``meta``, and no refusal or injection reads it.

The meta helps find an entry; the binding alone decides where the secret may go, so an edited
meta changes no answer.

Revocation on delete (M7 design D.9, X18, TI-2, TI-11, CR-5): a deleted refresh token is revoked
at the fake authorization server after the delete, in a task the answer never waits for; a
failure, a timeout, a cross-origin endpoint and an address the guard refuses change nothing but
the log line. The guarded rows run the real revocation client against a TLS fake reached through
the fake resolver, its certificate from a test CA certifi's bundle is patched to be.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import anyio
import certifi
import httpx
import pytest

from tests.acceptance.tls import ProviderCA, issue_cert, make_ca
from tests.fakes.oauth_server import FakeAuthServer, google_style, spotify_style
from tests.fakes.resolver import FakeResolver, serve_https
from zoeymcp.common import egresslist
from zoeymcp.common.policy import Policy, parse_policy
from zoeymcp.vault import logs, netclient, secretops
from zoeymcp.vault.admin import AdminApp
from zoeymcp.vault.app import VaultApp
from zoeymcp.vault.bindings import oauth_binding
from zoeymcp.vault.secretplan import (
    NOT_WRITTEN_REFUSAL,
    OnboardPutPlan,
    SecretRefusal,
    plan_delete,
    plan_onboard_secret,
    plan_put,
)
from zoeymcp.vault.store import SecretStore, SecretUnavailable

from .conftest import EXAMPLE_POLICY
from .test_admin import BROKER_TOKEN_URL, BROKER_UPSTREAM, AdminRig, browse, login_policy
from .test_oauth_tokens import (
    API,
    KEYS,
    Captured,
    FailingWrites,
    FakeClock,
    Rig,
    google_cred,
    make_policy,
    spotify_cred,
)

pytestmark = pytest.mark.anyio

NAME = "notes-client-secret"
VALUE = "fake-notes-client-secret-0001"
TOKEN_URL = "https://auth.notes.example/token"
BINDING = {
    "oauth": {
        "token": "https://auth.notes.example:443",
        "resources": ["https://mcp.notes.example:443"],
    }
}
META = {
    "onboarded": "auth.notes.example",
    "resource": "https://mcp.notes.example/mcp",
    "client_id": "notes-client",
    "client_secret_expires_at": None,
}


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def captured() -> Iterator[Captured]:
    capture = Captured()
    logs.set_stream(capture.stream)
    try:
        yield capture
    finally:
        logs.set_stream(None)


@pytest.fixture
def store(tmp_path: Path) -> SecretStore:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    held = SecretStore(state, KEYS)
    held.load()
    return held


def example_policy() -> Policy:
    return parse_policy(EXAMPLE_POLICY.read_text(encoding="utf-8"), "example")


def planned(store: SecretStore) -> OnboardPutPlan:
    plan = plan_onboard_secret(NAME, VALUE, BINDING, META, store_names=store.names())
    assert isinstance(plan, OnboardPutPlan)
    return plan


async def test_an_onboarding_secret_is_written_with_its_meta(
    store: SecretStore, captured: Captured
) -> None:
    written = await secretops.put(store, None, planned(store), via="socket")
    assert written == BINDING
    entry = store.entry(NAME)
    assert entry is not None
    assert (entry.binding, entry.meta) == (BINDING, META)
    assert store.get_for_oauth(NAME, token_url=TOKEN_URL)[0].reveal() == VALUE
    [line] = captured.events("secret_set")
    assert line == {**line, "name": NAME, "binding": BINDING, "via": "socket"}
    assert VALUE not in captured.text
    # Survives a restart: the meta is part of the entry on disk.
    reloaded = SecretStore(store.path.parent, KEYS)
    reloaded.load()
    assert reloaded.entry(NAME) == entry


async def test_a_plain_write_keeps_the_meta(store: SecretStore) -> None:
    """``zoeymcp secret set`` of the same name later: its plan has no meta, so the entry keeps
    the one it had."""
    await secretops.put(store, None, planned(store), via="socket")
    plan = plan_put(
        NAME, {"value": "fake-new-value-0002", "origins": ["https://x.example"]}, example_policy()
    )
    assert not isinstance(plan, SecretRefusal)
    assert await secretops.put(store, None, plan, via="portal") == plan.binding
    entry = store.entry(NAME)
    assert entry is not None
    assert (entry.binding, entry.meta) == (plan.binding, META)


async def test_no_refusal_or_injection_reads_the_meta(store: SecretStore) -> None:
    """F-44: the meta is clear text anyone with the state file can edit. Edited to name
    another resource and client, it changes where the secret may go not at all."""
    await secretops.put(store, None, planned(store), via="socket")
    store.update_meta(
        NAME,
        {
            "onboarded": "attacker.example",
            "resource": "https://attacker.example/mcp",
            "client_id": "x",
        },
    )
    assert store.get_for_oauth(NAME, token_url=TOKEN_URL)[0].reveal() == VALUE
    with pytest.raises(SecretUnavailable):
        store.get_for_oauth(NAME, token_url="https://attacker.example/token")
    with pytest.raises(SecretUnavailable):
        store.get_for_origin(NAME, "https://attacker.example/mcp")
    # A second onboarding under the name is name_taken, whatever the meta says.
    again = plan_onboard_secret(NAME, VALUE, BINDING, META, store_names=store.names())
    assert again == SecretRefusal(409, "name_taken", f"the store already has {NAME}")


async def test_a_write_that_cant_be_persisted(
    store: SecretStore, monkeypatch: pytest.MonkeyPatch, captured: Captured
) -> None:
    plan = planned(store)
    writes = FailingWrites(monkeypatch)
    writes.failing = True
    assert await secretops.put(store, None, plan, via="socket") == NOT_WRITTEN_REFUSAL
    [line] = captured.events("secret_set")
    assert line == {**line, "name": NAME, "persisted": False, "via": "socket"}
    # Kept in memory, with its meta, as any write that failed on disk (B.4).
    entry = store.entry(NAME)
    assert entry is not None
    assert entry.meta == META


async def test_an_onboarding_secret_is_deleted_as_any_other(
    store: SecretStore, captured: Captured
) -> None:
    await secretops.put(store, None, planned(store), via="socket")
    assert (
        await secretops.delete(store, None, plan_delete(NAME, example_policy()), via="socket")
        == "none"
    )
    assert store.entry(NAME) is None
    assert [line["name"] for line in captured.events("secret_deleted")] == [NAME]


# --- revocation on delete (M7 design D.9, X18) --------------------------------------------------

REVOKE_URL = "https://accounts.example/revoke"
SLOT = "music-refresh"
LAN = "auth.lan.example"
LAN_TOKEN_URL = f"https://{LAN}/token"
# Long enough for an answer on loopback; the timeout row sets a short one.
WAIT = 10.0


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


class Revocations:
    """A token manager and a revoker, both against the spotify-like fake authorization server
    (a public client that rotates), unless ``transport`` or ``client`` takes the revocations
    elsewhere."""

    def __init__(
        self,
        tmp_path: Path,
        clock: FakeClock,
        *,
        policy: Policy | None = None,
        server: FakeAuthServer | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        client: httpx.AsyncClient | None = None,
        timeout: float = secretops.REVOKE_TIMEOUT,
    ) -> None:
        policy = policy or make_policy(spotify_cred(revocation_url=REVOKE_URL))
        self.server = server or spotify_style(clock.time)
        self.rig = Rig(tmp_path, clock, self.server, policy)
        revoking = transport or httpx.ASGITransport(app=self.server.app())
        self.client = client or httpx.AsyncClient(transport=revoking)
        self.revoker = secretops.Revoker(self.client, timeout=timeout)

    @property
    def store(self) -> SecretStore:
        return self.rig.store

    async def delete(self, name: str = SLOT) -> SecretRefusal | secretops.Revocation:
        plan = plan_delete(name, self.rig.policy)
        return await secretops.delete(
            self.store, self.rig.manager, plan, via="socket", revoker=self.revoker
        )

    async def settled(self) -> None:
        with anyio.fail_after(WAIT):
            await self.revoker.wait()

    async def aclose(self) -> None:
        await self.revoker.aclose()
        await self.client.aclose()
        await self.rig.client.aclose()


def revoked(captured: Captured) -> list[dict[str, Any]]:
    return [
        {key: line[key] for key in ("credential", "outcome", "status")}
        for line in captured.events("oauth_revoked")
    ]


async def test_a_deleted_refresh_token_is_revoked(
    tmp_path: Path, clock: FakeClock, captured: Captured
) -> None:
    """RFC 7009 2.1 at the credential's revocation_url, after the delete: the grant is dead."""
    held = Revocations(tmp_path, clock)
    token = held.rig.seed()
    assert await held.delete() == "requested"
    assert held.store.entry(SLOT) is None
    await held.settled()
    assert held.server.revocations == [token]
    [seen] = [s for s in held.server.seen if s.path == "/revoke"]
    assert seen.method == "POST"
    assert seen.headers["content-type"] == "application/x-www-form-urlencoded"
    assert held.server.active_refresh_token() is None
    assert revoked(captured) == [{"credential": "music", "outcome": "ok", "status": 200}]
    [fetch] = captured.events("discovery_fetch")
    assert fetch == {
        **fetch,
        "fetch_kind": "revoke",
        "host": "accounts.example",
        "port": 443,
        "status": 200,
        "via": "direct",
    }
    events = [json.loads(line)["event"] for line in captured.text.splitlines()]
    assert events.index("secret_deleted") < events.index("oauth_revoked")
    assert token not in captured.text
    await held.aclose()


async def test_the_deletes_answer_never_waits_for_the_revocation(
    tmp_path: Path, clock: FakeClock, captured: Captured
) -> None:
    held = Revocations(tmp_path, clock)
    held.rig.seed()
    gate = held.server.revoke_gate = asyncio.Event()
    with anyio.fail_after(WAIT):
        assert await held.delete() == "requested"
    assert captured.events("oauth_revoked") == []
    gate.set()
    await held.settled()
    assert revoked(captured) == [{"credential": "music", "outcome": "ok", "status": 200}]
    await held.aclose()


@pytest.mark.parametrize("status", [400, 503])
async def test_a_refused_revocation_changes_nothing(
    tmp_path: Path, clock: FakeClock, captured: Captured, status: int
) -> None:
    """A failure is only its log line."""
    held = Revocations(tmp_path, clock)
    token = held.rig.seed()
    held.server.revoke_status = status
    assert await held.delete() == "requested"
    await held.settled()
    assert held.store.entry(SLOT) is None
    assert held.server.revocations == [token]
    assert revoked(captured) == [{"credential": "music", "outcome": "failed", "status": status}]
    await held.aclose()


async def test_a_redirected_revocation_is_not_followed(
    tmp_path: Path, clock: FakeClock, captured: Captured
) -> None:
    """X18: the revoker follows no redirect, even on a client that would."""
    server = spotify_style(clock.time)
    following = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=server.app()), follow_redirects=True
    )
    held = Revocations(tmp_path, clock, server=server, client=following)
    token = held.rig.seed()
    server.revoke_status = 302
    server.revoke_location = "https://accounts.example/elsewhere"
    assert await held.delete() == "requested"
    await held.settled()
    assert held.store.entry(SLOT) is None
    assert server.revocations == [token]
    assert [s.path for s in server.seen if s.path in ("/revoke", "/elsewhere")] == ["/revoke"]
    assert revoked(captured) == [{"credential": "music", "outcome": "failed", "status": 302}]
    await held.aclose()


async def test_a_revocation_that_gets_no_answer_times_out(
    tmp_path: Path, clock: FakeClock, captured: Captured
) -> None:
    held = Revocations(tmp_path, clock, timeout=0.05)
    held.rig.seed()
    held.server.revoke_gate = asyncio.Event()  # never set
    assert await held.delete() == "requested"
    await held.settled()
    assert held.store.entry(SLOT) is None
    assert revoked(captured) == [{"credential": "music", "outcome": "timeout", "status": None}]
    # The attempt is logged as fetch.py's are, with no status.
    [fetch] = captured.events("discovery_fetch")
    assert fetch == {**fetch, "fetch_kind": "revoke", "host": "accounts.example", "status": None}
    await held.aclose()


async def test_a_revocation_that_cant_connect_fails(
    tmp_path: Path, clock: FakeClock, captured: Captured
) -> None:
    def unreachable(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    held = Revocations(tmp_path, clock, transport=httpx.MockTransport(unreachable))
    held.rig.seed()
    assert await held.delete() == "requested"
    await held.settled()
    assert revoked(captured) == [{"credential": "music", "outcome": "failed", "status": None}]
    await held.aclose()


async def test_no_endpoint_no_revocation(
    tmp_path: Path, clock: FakeClock, captured: Captured
) -> None:
    held = Revocations(tmp_path, clock, policy=make_policy(spotify_cred()))
    held.rig.seed()
    assert await held.delete() == "none"
    await held.settled()
    assert held.store.entry(SLOT) is None
    assert held.server.revocations == []
    assert captured.events("oauth_revoked") == []
    await held.aclose()


async def test_a_revocation_url_on_another_origin_sends_nothing(
    tmp_path: Path, clock: FakeClock, captured: Captured
) -> None:
    """TI-2: check refuses such a policy (A.2 row 4b); the send asserts the origin again."""
    sent: list[httpx.Request] = []

    def anywhere(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(200)

    cross = make_policy(spotify_cred(revocation_url="https://other.example/revoke"))
    held = Revocations(tmp_path, clock, policy=cross, transport=httpx.MockTransport(anywhere))
    token = held.rig.seed()
    assert await held.delete() == "requested"
    await held.settled()
    assert sent == []
    assert revoked(captured) == [{"credential": "music", "outcome": "refused", "status": None}]
    assert token not in captured.text
    await held.aclose()


async def test_a_rotation_during_the_wait_revokes_the_rotated_token(
    tmp_path: Path, clock: FakeClock, captured: Captured
) -> None:
    """CR-5: the delete waits for the refresh in flight, whose successor is the token revoked."""
    held = Revocations(tmp_path, clock)
    first = held.rig.seed()
    gate = held.server.hold()
    refresh = asyncio.create_task(held.rig.grant())
    await held.server.arrived()
    deleting = asyncio.create_task(held.delete())
    for _ in range(5):
        await asyncio.sleep(0)
    assert not deleting.done()
    gate.set()
    await refresh
    assert await deleting == "requested"
    await held.settled()
    [rotated] = held.server.revocations
    assert rotated != first
    assert held.server.active_refresh_token() is None
    assert revoked(captured) == [{"credential": "music", "outcome": "ok", "status": 200}]
    await held.aclose()


async def test_a_delete_the_store_cant_write_revokes_nothing(
    tmp_path: Path, clock: FakeClock, monkeypatch: pytest.MonkeyPatch, captured: Captured
) -> None:
    """N: a revocation starts only after the delete's write succeeded."""
    held = Revocations(tmp_path, clock)
    held.rig.seed()
    writes = FailingWrites(monkeypatch)
    writes.failing = True
    assert await held.delete() == NOT_WRITTEN_REFUSAL
    await held.settled()
    assert held.server.revocations == []
    assert captured.events("oauth_revoked") == []
    await held.aclose()


async def test_deleting_a_client_secret_revokes_nothing(
    tmp_path: Path, clock: FakeClock, captured: Captured
) -> None:
    policy = make_policy(google_cred(revocation_url=REVOKE_URL))
    held = Revocations(tmp_path, clock, policy=policy, server=google_style(clock.time))
    held.rig.put_client_secret()
    held.rig.seed()
    assert await held.delete("google-secret") == "none"
    await held.settled()
    assert held.server.revocations == []
    assert captured.events("oauth_revoked") == []
    await held.aclose()


# --- through the socket, after a login (10a's acceptance, in process) --------------------------


async def test_deleting_the_refresh_slot_after_a_login_revokes_once(
    tmp_path: Path, captured: Captured
) -> None:
    rig = AdminRig(tmp_path)
    raw = login_policy().model_dump(mode="json", by_alias=True, exclude_defaults=True)
    raw["credentials"]["broker-mcp"]["revocation_url"] = "https://auth.broker.example/revoke"
    rig.set_policy(Policy.model_validate(raw))
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=rig.server.app()))
    revoker = secretops.Revoker(client)
    rig.admin = AdminApp(
        rig.store, KEYS, lambda: rig.policy, rig.setup, rig.tokens, revoker=revoker
    )
    started = (await rig.call("POST", "/oauth/broker-mcp/login")).json()
    pasted = await browse(rig, started["authorize_url"])
    body = {"flow": started["flow"], "redirect_url": pasted}
    assert (await rig.call("POST", "/oauth/broker-mcp/complete", body)).status_code == 200
    stored = rig.store.get_for_oauth("broker-refresh", token_url=BROKER_TOKEN_URL)[0].reveal()
    await rig.tokens.grant_for("broker-mcp", BROKER_UPSTREAM)
    answer = await rig.call("DELETE", "/secrets/broker-refresh")
    assert answer.json() == {"name": "broker-refresh", "deleted": True, "revocation": "requested"}
    with anyio.fail_after(WAIT):
        await revoker.wait()
    assert rig.server.revocations == [stored]
    assert rig.server.active_refresh_token() is None
    assert revoked(captured) == [{"credential": "broker-mcp", "outcome": "ok", "status": 200}]
    # Deleting it again: nothing left, nothing revoked.
    assert (await rig.call("DELETE", "/secrets/broker-refresh")).status_code == 404
    assert len(rig.server.revocations) == 1
    await revoker.aclose()
    await client.aclose()
    await rig.token_client.aclose()


# --- the guarded client (TI-11, X3) -------------------------------------------------------------


@pytest.fixture(scope="module")
def ca(tmp_path_factory: pytest.TempPathFactory) -> ProviderCA:
    return make_ca(tmp_path_factory.mktemp("revocation-ca"))


@pytest.fixture(scope="module")
def lan_cert(ca: ProviderCA, tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    return issue_cert(ca, LAN, tmp_path_factory.mktemp("revocation-certs"))


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch, ca: ProviderCA) -> FakeResolver:
    resolver = FakeResolver()
    monkeypatch.setattr(netclient, "HOOKS", resolver.hooks())
    monkeypatch.setattr(certifi, "where", lambda: str(ca.ca_file))
    return resolver


def lan_policy(*, listed: bool) -> Policy:
    cred = spotify_cred(token_url=LAN_TOKEN_URL, revocation_url=f"https://{LAN}/revoke")
    policy = make_policy(cred)
    if listed:
        policy = policy.model_copy(update={"egress_private": [f"{LAN}:443"]})
    return policy


@pytest.mark.parametrize("listed", [True, False])
async def test_a_private_token_origin_revokes_only_when_listed(
    tmp_path: Path,
    clock: FakeClock,
    captured: Captured,
    fake: FakeResolver,
    lan_cert: tuple[Path, Path],
    listed: bool,
) -> None:
    """TI-11: the revocation client's exceptions are the running policy's egress_private, so a
    LAN token origin listed there revokes as it refreshes; an unlisted one is refused before any
    connection is made."""
    policy = lan_policy(listed=listed)
    async with serve_https(*lan_cert) as (port, seen):
        fake.serve(LAN, port, address="10.0.0.7")
        guarded = netclient.revocation_client(None, lambda: egresslist.private_exceptions(policy))
        held = Revocations(tmp_path, clock, policy=policy, client=guarded)
        held.store.put(SLOT, "fake-lan-refresh-token", oauth_binding(LAN_TOKEN_URL, [API]))
        assert await held.delete() == "requested"
        await held.settled()
        await held.aclose()
    if listed:
        assert revoked(captured) == [{"credential": "music", "outcome": "ok", "status": 200}]
        [head] = seen.heads
        assert head.startswith(b"POST /revoke HTTP/1.1\r\n")
        assert seen.names == [LAN]
        assert captured.events("address_refused") == []
    else:
        assert revoked(captured) == [{"credential": "music", "outcome": "refused", "status": None}]
        [line] = captured.events("address_refused")
        assert line == {
            **line,
            "purpose": "revocation",
            "host": LAN,
            "port": 443,
            "verdict": "private",
        }
        assert seen.connections == 0
        assert fake.dialled == []
    assert "fake-lan-refresh-token" not in captured.text


async def test_the_vaults_revocation_client_reads_the_running_policy(
    tmp_path: Path,
    clock: FakeClock,
    captured: Captured,
    fake: FakeResolver,
    lan_cert: tuple[Path, Path],
) -> None:
    """Through the real VaultApp constructor (F-2): its revocation client is built once, at
    start, and reads egress_private from the policy running at each connection, so a reload
    that lists the token origin lets the next revocation through."""
    held = Revocations(tmp_path, clock, policy=lan_policy(listed=False))
    app = VaultApp(held.rig.policy, held.store, KEYS, environ={}, tokens=held.rig.manager)
    async with serve_https(*lan_cert) as (port, seen):
        fake.serve(LAN, port, address="10.0.0.7")
        for listed in (False, True):
            app.reload(lan_policy(listed=listed))
            held.store.put(SLOT, "fake-lan-refresh-token", oauth_binding(LAN_TOKEN_URL, [API]))
            plan = plan_delete(SLOT, app.policy)
            done = await secretops.delete(
                held.store, app.tokens, plan, via="portal", revoker=app.revoker
            )
            assert done == "requested"
            with anyio.fail_after(WAIT):
                await app.revoker.wait()
        await app.aclose()
    assert [line["outcome"] for line in captured.events("oauth_revoked")] == ["refused", "ok"]
    assert len(seen.heads) == 1
    await held.aclose()
