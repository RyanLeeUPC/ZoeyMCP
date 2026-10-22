from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import json
import os
import stat
import sys
import tempfile
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Literal

import httpx
import pytest
import uvicorn

from tests.fakes.oauth_server import FakeAuthServer
from tests.unit import onboard_model
from tests.unit.report_model import T0, asked_line
from zoeymcp.cli.main import main
from zoeymcp.common import canonical, ledgerreport
from zoeymcp.common import files as common_files
from zoeymcp.common.ledgerformat import GENESIS, line_hash
from zoeymcp.common.policy import Policy, parse_policy
from zoeymcp.common.yamlload import load_mapping
from zoeymcp.portal import passkeys as passkey_module
from zoeymcp.portal import setupcode
from zoeymcp.portal.app import PortalApp, load_static
from zoeymcp.portal.passkeys import Passkeys, new_file
from zoeymcp.portal.refusals import CATALOGUE
from zoeymcp.portal.setupcode import Redeemed, Refused
from zoeymcp.portal.webauthn import Asserted
from zoeymcp.vault import admin as admin_module
from zoeymcp.vault import gatewaykeys, logs
from zoeymcp.vault.admin import (
    NO_GATEWAY_KEYS,
    NO_ONBOARDING,
    NO_TOKENS,
    NOT_WRITTEN,
    AdminApp,
    AdminSocketError,
    ReviewQueue,
    SetupCodes,
    check_socket_dir,
    json_safe,
)
from zoeymcp.vault.app import VaultApp
from zoeymcp.vault.connectors import sendjournal
from zoeymcp.vault.connectors.smtp import SmtpConnectors
from zoeymcp.vault.gatewaykeys import GatewayKeys
from zoeymcp.vault.keys import KeySet
from zoeymcp.vault.oauth.login import LoginError, LoginService
from zoeymcp.vault.oauth.pkce import CLI_OWNER
from zoeymcp.vault.oauth.protocol import CREDENTIAL_UNAVAILABLE
from zoeymcp.vault.oauth.tokens import OAuthUnavailable, TokenManager
from zoeymcp.vault.reportstore import ReportStore
from zoeymcp.vault.store import SecretStore

from .conftest import EXAMPLE_POLICY
from .test_passkeys import NOW, credential

KEYS = KeySet.from_master(bytes(range(32)))
PORTAL = KEYS.portal_key
ZWSP = chr(0x200B)
BROKER_BINDING = {
    "oauth": {
        "token": "https://auth.broker.example:443",
        "resources": ["https://mcp.broker.example:443"],
    }
}


def example_policy() -> Policy:
    return parse_policy(EXAMPLE_POLICY.read_text(encoding="utf-8"), "example")


# --- admin app (in process) --------------------------------------------------------------------


BROKER_TOKEN_URL = "https://auth.broker.example/oauth/token"
BROKER_UPSTREAM = "https://mcp.broker.example/mcp"
BROKER_CLIENT_ID = "broker-client-0001"


def broker_server() -> tuple[FakeAuthServer, Any]:
    """The broker's token endpoint: the fake AS, reached at the example policy's path."""
    server = FakeAuthServer(client_id=BROKER_CLIENT_ID, auth="none", rotate=True, prefix="broker")
    app = server.app()

    async def at_policy_path(scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] == "http" and scope["path"] == "/oauth/token":
            scope = {**scope, "path": "/token", "raw_path": b"/token"}
        await app(scope, receive, send)

    return server, at_policy_path


class AdminRig:
    """The admin app with the example policy and, as in the vault, a token manager; with
    ``onboard``, onboard_model's service, whose server registers clients by ``register``; with
    ``reviews``, those review jobs."""

    def __init__(
        self,
        tmp_path: Path,
        clock: list[float] | None = None,
        *,
        tokens: bool = True,
        passkeys: Passkeys | None = None,
        portal: PortalApp | None = None,
        onboard: bool = False,
        register: onboard_model.Register | None = None,
        reviews: ReviewQueue | None = None,
    ) -> None:
        self.policy = example_policy()
        self.store = SecretStore(tmp_path, KEYS)
        self.store.load()
        self.clock = clock or [1_000_000.0]
        self.setup = SetupCodes(tmp_path, PORTAL, clock=lambda: self.clock[0])
        self.server, token_app = broker_server()
        self.token_client = httpx.AsyncClient(transport=httpx.ASGITransport(app=token_app))
        self.tokens = TokenManager(self.store, self.token_client)
        self.tokens.configure(self.policy, {})
        self.admin = AdminApp(
            self.store,
            KEYS,
            lambda: self.policy,
            self.setup,
            self.tokens if tokens else None,
            passkeys=passkeys,
            portal=portal,
            onboard=onboard_model.onboard_service(
                self.store, self.tokens, lambda: self.policy, register=register
            )
            if onboard
            else None,
            reviews=reviews,
        )

    def set_policy(self, policy: Policy) -> None:
        """As a reload does: the admin and the token manager see the same policy."""
        self.policy = policy
        self.tokens.configure(policy, {})

    async def call(self, method: str, path: str, body: Any = None) -> httpx.Response:
        transport = httpx.ASGITransport(app=self.admin.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://admin") as client:
            return await client.request(method, path, json=body)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_set_list_delete(tmp_path: Path) -> None:
    rig = AdminRig(tmp_path)
    response = await rig.call("PUT", "/secrets/music-stats", {"value": "lfm-123456"})
    assert response.status_code == 200
    assert response.json()["binding"] == {"origins": ["https://api.stats.example:443"]}
    listing = await rig.call("GET", "/secrets")
    assert "lfm-123456" not in listing.text
    assert [s["name"] for s in listing.json()["secrets"]] == ["music-stats"]
    assert (await rig.call("DELETE", "/secrets/music-stats")).status_code == 200
    assert (await rig.call("DELETE", "/secrets/music-stats")).status_code == 404


@pytest.mark.anyio
async def test_explicit_origins(tmp_path: Path) -> None:
    rig = AdminRig(tmp_path)
    response = await rig.call(
        "PUT", "/secrets/extra", {"value": "v-123456", "origins": ["https://x.example"]}
    )
    assert response.json()["binding"] == {"origins": ["https://x.example:443"]}


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("body", "status", "message"),
    [
        ({"value": ""}, 400, "non-empty"),
        ({"value": "abc\ndef"}, 400, "line breaks"),
        ({"value": f"abc{ZWSP}def"}, 400, "invisible"),
        ({"value": "v", "extra": 1}, 400, "expected"),
        ({"value": "v", "origins": "https://x"}, 400, "list of URLs"),
        ({"value": "v-123456"}, 409, "pass --origin"),
    ],
)
async def test_put_refusals(tmp_path: Path, body: Any, status: int, message: str) -> None:
    rig = AdminRig(tmp_path)
    name = "unreferenced" if status == 409 else "music-stats"
    response = await rig.call("PUT", f"/secrets/{name}", body)
    assert response.status_code == status
    assert message in response.json()["error"]
    assert rig.store.names() == []


@pytest.mark.anyio
async def test_oauth_secrets_take_the_policy_binding(tmp_path: Path) -> None:
    rig = AdminRig(tmp_path)
    response = await rig.call("PUT", "/secrets/broker-refresh", {"value": "rt-123456"})
    assert response.status_code == 200
    assert response.json()["binding"] == BROKER_BINDING
    secret, binding = rig.store.get_for_oauth(
        "broker-refresh",
        token_url="https://auth.broker.example/oauth/token",
        resource_url="https://mcp.broker.example/mcp",
    )
    assert secret.reveal() == "rt-123456"
    assert binding == BROKER_BINDING


@pytest.mark.anyio
@pytest.mark.parametrize("name", ["broker-refresh", "broker-client-id"])
async def test_origin_on_an_oauth_secret_is_refused(tmp_path: Path, name: str) -> None:
    rig = AdminRig(tmp_path)
    body = {"value": "v-123456", "origins": ["https://auth.broker.example"]}
    response = await rig.call("PUT", f"/secrets/{name}", body)
    assert response.status_code == 409
    assert response.json() == {"error": "OAuth secrets are bound by the policy; drop --origin"}
    assert rig.store.names() == []


@pytest.mark.anyio
async def test_malformed_origins_on_an_oauth_secret_are_a_bad_request(tmp_path: Path) -> None:
    rig = AdminRig(tmp_path)
    body = {"value": "v-123456", "origins": "https://auth.broker.example"}
    response = await rig.call("PUT", "/secrets/broker-refresh", body)
    assert response.status_code == 400
    assert response.json() == {"error": "origins must be a list of URLs"}
    assert rig.store.names() == []


@pytest.mark.anyio
async def test_an_oauth_secret_with_no_route_is_refused(tmp_path: Path) -> None:
    rig = AdminRig(tmp_path)
    raw = rig.policy.model_dump(by_alias=True)
    raw["routes"] = [r for r in raw["routes"] if r["credential"] != "broker-mcp"]
    rig.set_policy(Policy.model_validate(raw))
    response = await rig.call("PUT", "/secrets/broker-refresh", {"value": "rt-123456"})
    assert response.status_code == 409
    assert response.json() == {
        "error": "no route uses broker-mcp; there is nothing to bind the access tokens minted "
        "with 'broker-refresh' to"
    }
    assert rig.store.names() == []


@pytest.mark.anyio
@pytest.mark.parametrize("body", [{"value": "rt-123456"}, "not an object"])
async def test_vault_managed_names_are_refused(tmp_path: Path, body: Any) -> None:
    rig = AdminRig(tmp_path)
    for name in ("oauth.broker-mcp.live", "oauth.anything"):
        response = await rig.call("PUT", f"/secrets/{name}", body)
        assert response.status_code == 409
        assert response.json() == {"error": "managed by the vault; use zoeymcp login"}
    assert rig.store.names() == []


@pytest.mark.anyio
async def test_names_that_only_look_vault_managed_are_not_refused(tmp_path: Path) -> None:
    rig = AdminRig(tmp_path)
    body = {"value": "v-123456", "origins": ["https://x.example"]}
    for name in ("oauth", "oauthx.live", "my.oauth.live"):
        assert (await rig.call("PUT", f"/secrets/{name}", body)).status_code == 200
    assert rig.store.names() == ["my.oauth.live", "oauth", "oauthx.live"]


@pytest.mark.anyio
async def test_a_live_slot_can_be_deleted(tmp_path: Path) -> None:
    rig = AdminRig(tmp_path)
    rig.store.put("oauth.broker-mcp.live", "rt-123456", BROKER_BINDING)
    response = await rig.call("DELETE", "/secrets/oauth.broker-mcp.live")
    assert response.status_code == 200
    assert rig.store.names() == []


@pytest.mark.anyio
async def test_bad_secret_names(tmp_path: Path) -> None:
    rig = AdminRig(tmp_path)
    assert (await rig.call("PUT", "/secrets/Bad Name", {"value": "v"})).status_code in (400, 404)
    assert (await rig.call("PUT", "/secrets/UPPER", {"value": "v"})).status_code == 400
    # The path parameter is decoded: %0A is a trailing line break, never part of a name.
    body = {"value": "lfm-123456"}
    assert (await rig.call("PUT", "/secrets/music-stats%0A", body)).status_code == 400
    assert rig.store.names() == []
    assert (await rig.call("PUT", "/secrets/music-stats", body)).status_code == 200


@pytest.mark.anyio
async def test_no_endpoint_returns_a_value(tmp_path: Path) -> None:
    rig = AdminRig(tmp_path)
    await rig.call("PUT", "/secrets/music-stats", {"value": "distinctive-value-42"})
    for method, path in [
        ("GET", "/secrets"),
        ("GET", "/secrets/music-stats"),
        ("GET", "/gateway-key"),
        ("POST", "/gateway-key/retire-previous"),
        ("POST", "/setup-code"),
    ]:
        response = await rig.call(method, path)
        assert "distinctive-value-42" not in response.text


@pytest.mark.anyio
async def test_gateway_key(tmp_path: Path) -> None:
    rig = AdminRig(tmp_path)
    data = (await rig.call("GET", "/gateway-key")).json()
    assert data == {"generation": 1, "key": KEYS.gateway_key(1), "previous": None}


@pytest.mark.anyio
async def test_admin_and_proxy_share_the_store(tmp_path: Path) -> None:
    from tests.fakes.echo import EchoProvider

    rig = AdminRig(tmp_path)
    echo = EchoProvider()
    vault = VaultApp(
        rig.policy,
        rig.store,
        KEYS,
        client=httpx.AsyncClient(transport=httpx.ASGITransport(app=echo.app())),
        environ={},
    )
    await rig.call("PUT", "/secrets/music-stats", {"value": "lfm-123456"})
    transport = httpx.ASGITransport(app=vault, client=("172.30.4.10", 1))
    async with httpx.AsyncClient(transport=transport, base_url="http://vault") as client:
        response = await client.get(
            "/stats/2.0/?method=x", headers={"Authorization": "Bearer ph-agent1-stats-4c1f9b27"}
        )
    assert response.status_code == 200
    assert ("api_key", "lfm-123456") in echo.received[-1].query
    await vault.aclose()


# --- the gateway key ratchet (M3 design C.2) ---------------------------------------------------


class _Clock:
    def __init__(self) -> None:
        self.now = 1_000_000.0

    def __call__(self) -> float:
        return self.now


def _with_ratchet(rig: AdminRig, ratchet: GatewayKeys) -> None:
    rig.admin = AdminApp(rig.store, KEYS, lambda: rig.policy, rig.setup, gateway_keys=ratchet)


@pytest.mark.anyio
async def test_gateway_key_shows_a_rotation(tmp_path: Path) -> None:
    rig = AdminRig(tmp_path)
    clock = _Clock()
    ratchet = GatewayKeys.load(tmp_path, KEYS, None, 1, clock=clock)
    _with_ratchet(rig, ratchet)
    data = (await rig.call("GET", "/gateway-key")).json()
    assert data == {"generation": 1, "key": KEYS.gateway_key(1), "previous": None}
    ratchet.advance(2)
    data = (await rig.call("GET", "/gateway-key")).json()
    assert data == {
        "generation": 2,
        "key": KEYS.gateway_key(2),
        "previous": {"generation": 1, "until": 1_000_300, "master_key": "current"},
    }


@pytest.mark.anyio
async def test_retire_previous(tmp_path: Path) -> None:
    rig = AdminRig(tmp_path)
    ratchet = GatewayKeys.load(tmp_path, KEYS, None, 1, clock=_Clock())
    _with_ratchet(rig, ratchet)
    ratchet.advance(2)
    response = await rig.call("POST", "/gateway-key/retire-previous")
    assert response.status_code == 200
    assert response.json() == {
        "retired": 1,
        "generation": 2,
        "key": KEYS.gateway_key(2),
        "previous": None,
    }
    assert ratchet.authenticate(KEYS.gateway_key(1).encode()) is False
    again = await rig.call("POST", "/gateway-key/retire-previous")
    assert again.json()["retired"] is None
    assert (await rig.call("GET", "/gateway-key/retire-previous")).status_code == 405


@pytest.mark.anyio
async def test_retire_previous_that_cant_be_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rig = AdminRig(tmp_path)
    ratchet = GatewayKeys.load(tmp_path, KEYS, None, 1, clock=_Clock())
    _with_ratchet(rig, ratchet)
    ratchet.advance(2)

    def broken(path: Path, data: bytes) -> None:
        raise OSError("read-only")

    monkeypatch.setattr(gatewaykeys, "write_atomic", broken)
    response = await rig.call("POST", "/gateway-key/retire-previous")
    assert response.status_code == 500
    assert response.json() == {"error": NOT_WRITTEN}
    # It took effect all the same.
    assert ratchet.authenticate(KEYS.gateway_key(1).encode()) is False


@pytest.mark.anyio
async def test_retire_previous_needs_the_ratchet(tmp_path: Path) -> None:
    rig = AdminRig(tmp_path)
    response = await rig.call("POST", "/gateway-key/retire-previous")
    assert response.status_code == 503
    assert response.json() == {"error": NO_GATEWAY_KEYS}
    assert NO_GATEWAY_KEYS == "the vault keeps no gateway key state"


# --- setup codes (M5 design E) ------------------------------------------------------------------

ORIGIN = "http://localhost:8081"


def redeem(codes: SetupCodes, typed: object, origin: str = ORIGIN) -> Redeemed | Refused:
    return asyncio.run(codes.redeem(typed, origin=origin))


def test_setup_codes_are_one_time_and_expire(tmp_path: Path) -> None:
    clock = [1_000_000.0]
    codes = SetupCodes(tmp_path, PORTAL, clock=lambda: clock[0])
    code, record = codes.issue()
    assert (record.expires, record.reset) == (1_000_000 + 15 * 60, False)
    assert code.reveal().encode() not in (tmp_path / "setup.json").read_bytes()
    assert redeem(codes, "WRONG-CODE") == Refused("wrong")
    assert redeem(codes, code.reveal().lower()) == Redeemed(record.expires, False)
    assert not (tmp_path / "setup.json").exists()
    assert redeem(codes, code.reveal()) == Refused("no_code")
    late, record = codes.issue()
    clock[0] = record.expires - 0.001
    assert codes.record() == record
    clock[0] = record.expires
    assert redeem(codes, late.reveal()) == Refused("expired")
    # Kept: only a redemption, a new code or the first passkey removes it.
    assert codes.record() == record


def test_a_new_code_replaces_the_old(tmp_path: Path) -> None:
    codes = SetupCodes(tmp_path, PORTAL)
    first, _ = codes.issue()
    second, record = codes.issue(reset=True)
    assert redeem(codes, first.reveal()) == Refused("wrong")
    assert redeem(codes, second.reveal()) == Redeemed(record.expires, True)


def test_setup_file_is_json(tmp_path: Path) -> None:
    _, record = SetupCodes(tmp_path, PORTAL).issue(reset=True)
    data = (tmp_path / "setup.json").read_bytes()
    stored = json.loads(data)
    assert set(stored) == {"v", "key_id", "sha256", "expires", "reset", "mac"}
    assert (stored["v"], stored["key_id"], stored["reset"]) == (1, KEYS.key_id, True)
    assert data == setupcode.seal(record, PORTAL)
    if sys.platform != "win32":
        assert stat.S_IMODE((tmp_path / "setup.json").stat().st_mode) == 0o600


def test_a_code_is_written_atomically(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[Path, str]] = []

    def recorded(path: Path, data: bytes, *, prefix: str) -> None:
        calls.append((path, prefix))

    monkeypatch.setattr(common_files, "write_atomic", recorded)
    SetupCodes(tmp_path, PORTAL).issue()
    assert calls == [(tmp_path / "setup.json", ".setup-")]


def test_a_record_that_doesnt_verify_is_no_code(tmp_path: Path) -> None:
    other = KeySet.from_master(bytes(range(1, 33))).portal_key
    code, _ = SetupCodes(tmp_path, other).issue()
    codes = SetupCodes(tmp_path, PORTAL)
    assert codes.record() is None
    assert redeem(codes, code.reveal()) == Refused("no_code")
    # An M1-era record (no MAC) and a directory in its place are no code either.
    digest = hashlib.sha256(code.reveal().encode()).hexdigest()
    old = '{"sha256":"' + digest + '","expires":2000000000}'
    (tmp_path / "setup.json").write_bytes(old.encode())
    assert codes.record() is None
    assert redeem(codes, code.reveal()) == Refused("no_code")
    (tmp_path / "setup.json").unlink()
    (tmp_path / "setup.json").mkdir(mode=0o700)
    assert codes.record() is None
    assert redeem(codes, code.reveal()) == Refused("no_code")


def test_a_redeemed_code_is_removed_before_the_answer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    codes = SetupCodes(tmp_path, PORTAL)
    code, record = codes.issue()
    removed: list[Path] = []
    real = admin_module._remove_synced

    def recorded(path: Path) -> None:
        real(path)
        removed.append(path)

    monkeypatch.setattr(admin_module, "_remove_synced", recorded)
    assert redeem(codes, code.reveal()) == Redeemed(record.expires, False)
    assert removed == [tmp_path / "setup.json"]
    # A refusal removes nothing.
    codes.issue()
    assert redeem(codes, code.reveal()) == Refused("wrong")
    assert removed == [tmp_path / "setup.json"]


def test_a_code_that_cant_be_removed_isnt_spent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    codes = SetupCodes(tmp_path, PORTAL)
    code, record = codes.issue()

    def broken(path: Path) -> None:
        raise OSError("read-only")

    with monkeypatch.context() as patched:
        patched.setattr(admin_module, "_remove_synced", broken)
        with pytest.raises(OSError, match="read-only"):
            redeem(codes, code.reveal())
    assert codes.status()["state"] == "pending"
    assert redeem(codes, code.reveal()) == Redeemed(record.expires, False)


PASSKEY = {"fingerprint": "ab" * 8, "origin": ORIGIN, "name": "laptop", "created": 1}


def test_the_status_follows_the_code(tmp_path: Path) -> None:
    clock = [1_000_000.0]
    codes = SetupCodes(tmp_path, PORTAL, clock=lambda: clock[0])
    nothing = {"state": "none", "expires": None, "reset": None, "origin": None, "passkey": None}
    assert codes.status() == nothing
    code, record = codes.issue(reset=True)
    pending = {
        "state": "pending",
        "expires": record.expires,
        "reset": True,
        "origin": None,
        "passkey": None,
    }
    assert codes.status() == pending
    codes.enrolled(PASSKEY)  # nothing redeemed yet
    assert codes.status() == pending
    redeem(codes, code.reveal(), "https://zoeymcp.tailnet.example")
    redeemed = {**pending, "state": "redeemed", "origin": "https://zoeymcp.tailnet.example"}
    assert codes.status() == redeemed
    # Past the code's own expiry: the setup session runs for 10 minutes from redemption.
    clock[0] += 599.9
    assert codes.status() == redeemed
    codes.enrolled(PASSKEY)
    assert codes.status() == {**redeemed, "state": "enrolled", "passkey": PASSKEY}
    clock[0] += 10**6
    assert codes.status()["state"] == "enrolled"
    codes.enrolled({**PASSKEY, "name": "again"})
    assert codes.status()["passkey"] == PASSKEY


def test_a_code_unused_in_time_expires(tmp_path: Path) -> None:
    clock = [1_000_000.0]
    codes = SetupCodes(tmp_path, PORTAL, clock=lambda: clock[0])
    _, record = codes.issue()
    clock[0] = record.expires - 0.001
    assert codes.status()["state"] == "pending"
    clock[0] = record.expires
    assert codes.status() == {
        "state": "expired",
        "expires": record.expires,
        "reset": False,
        "origin": None,
        "passkey": None,
    }


def test_a_setup_session_that_enrols_nothing_expires(tmp_path: Path) -> None:
    clock = [1_000_000.0]
    codes = SetupCodes(tmp_path, PORTAL, clock=lambda: clock[0])
    code, _ = codes.issue()
    clock[0] += 100
    redeem(codes, code.reveal())
    clock[0] += 599.999
    assert codes.status()["state"] == "redeemed"
    clock[0] += 0.001
    assert (codes.status()["state"], codes.status()["origin"]) == ("expired", ORIGIN)


def test_discard_removes_a_pending_code(tmp_path: Path) -> None:
    codes = SetupCodes(tmp_path, PORTAL)
    codes.discard()  # nothing to remove
    assert codes.status()["state"] == "none"
    code, _ = codes.issue()
    codes.discard()
    assert not (tmp_path / "setup.json").exists()
    assert codes.status()["state"] == "expired"
    assert redeem(codes, code.reveal()) == Refused("no_code")
    # A redeemed code's state is kept.
    code, _ = codes.issue()
    redeem(codes, code.reveal())
    codes.discard()
    assert codes.status()["state"] == "redeemed"


@pytest.mark.anyio
async def test_the_status_waits_for_a_change(tmp_path: Path) -> None:
    codes = SetupCodes(tmp_path, PORTAL)
    assert (await codes.wait_status(30))["state"] == "none"
    code, _ = codes.issue()
    assert (await codes.wait_status(0))["state"] == "pending"
    waiting = asyncio.create_task(codes.wait_status(30))
    for _ in range(5):
        await asyncio.sleep(0)
    assert not waiting.done()
    assert isinstance(await codes.redeem(code.reveal(), origin=ORIGIN), Redeemed)
    assert (await asyncio.wait_for(waiting, 5))["state"] == "redeemed"
    waiting = asyncio.create_task(codes.wait_status(30))
    await asyncio.sleep(0)
    codes.enrolled(PASSKEY)
    assert (await asyncio.wait_for(waiting, 5))["passkey"] == PASSKEY
    # Nothing left to change: at once.
    assert (await asyncio.wait_for(codes.wait_status(30), 5))["state"] == "enrolled"


@pytest.mark.anyio
async def test_the_status_wait_ends_when_time_changes_it(tmp_path: Path) -> None:
    now = [1_000_000.0]
    codes = SetupCodes(tmp_path, PORTAL, clock=lambda: now[0])
    _, record = codes.issue()
    now[0] = record.expires - 0.05
    started = time.monotonic()
    await asyncio.wait_for(codes.wait_status(30), 5)
    assert time.monotonic() - started < 5
    now[0] = record.expires
    assert (await asyncio.wait_for(codes.wait_status(30), 5))["state"] == "expired"


@pytest.fixture
def log_buffer() -> Iterator[io.StringIO]:
    buffer = io.StringIO()
    logs.set_stream(buffer)
    try:
        yield buffer
    finally:
        logs.set_stream(None)


def log_events(buffer: io.StringIO, event: str) -> list[dict[str, Any]]:
    found = [json.loads(line) for line in buffer.getvalue().splitlines()]
    return [line for line in found if line["event"] == event]


def without_ts(line: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in line.items() if key != "ts"}


@pytest.mark.anyio
async def test_the_setup_code_route(tmp_path: Path, log_buffer: io.StringIO) -> None:
    rig = AdminRig(tmp_path)
    response = await rig.call("POST", "/setup-code")
    assert response.status_code == 200
    data = response.json()
    assert data == {
        "code": data["code"],
        "expires": 1_000_000 + 900,
        "reset": False,
        "passkeys": 0,
        "origins": ["http://localhost:8081", "https://zoeymcp.tailnet.example"],
    }
    redeemed = await rig.setup.redeem(data["code"], origin=ORIGIN)
    assert redeemed == Redeemed(1_000_900, False)
    data = (await rig.call("POST", "/setup-code", {"reset": True})).json()
    record = rig.setup.record()
    assert record is not None
    assert (data["reset"], record.reset) == (True, True)
    data = (await rig.call("POST", "/setup-code", {"reset": False})).json()
    assert data["reset"] is False
    [*_, last] = log_events(log_buffer, "setup_code_issued")
    assert without_ts(last) == {
        "role": "vault",
        "event": "setup_code_issued",
        "expires": 1_000_900,
        "reset": False,
    }
    assert data["code"] not in log_buffer.getvalue()
    # Without an admin block there is no portal to name.
    rig.policy = rig.policy.model_copy(update={"admin": None})
    assert (await rig.call("POST", "/setup-code")).json()["origins"] == []
    await rig.token_client.aclose()


@pytest.mark.anyio
@pytest.mark.parametrize("body", [{"reset": "yes"}, {"reset": 1}, {"other": True}, [True], "x"])
async def test_the_setup_code_route_refuses_a_bad_body(tmp_path: Path, body: Any) -> None:
    rig = AdminRig(tmp_path)
    response = await rig.call("POST", "/setup-code", body)
    assert response.status_code == 400
    assert not (tmp_path / "setup.json").exists()
    big = await rig.call("POST", "/setup-code", {"reset": False, "x": "y" * 5000})
    assert big.status_code == 413
    await rig.token_client.aclose()


@pytest.mark.anyio
async def test_a_setup_code_that_cant_be_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, log_buffer: io.StringIO
) -> None:
    rig = AdminRig(tmp_path)
    code = (await rig.call("POST", "/setup-code")).json()["code"]

    def broken(*args: Any, **kwargs: Any) -> None:
        raise OSError("read-only")

    monkeypatch.setattr(common_files, "write_atomic", broken)
    response = await rig.call("POST", "/setup-code", {"reset": True})
    assert (response.status_code, response.json()["reason"]) == (500, "not_written")
    assert "code" not in response.json()
    assert len(log_events(log_buffer, "setup_code_issued")) == 1
    # The earlier code still works.
    assert isinstance(await rig.setup.redeem(code, origin=ORIGIN), Redeemed)
    await rig.token_client.aclose()


@pytest.mark.anyio
async def test_the_setup_code_status_route(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rig = AdminRig(tmp_path)
    response = await rig.call("GET", "/setup-code/status")
    assert response.json() == {
        "state": "none",
        "expires": None,
        "reset": None,
        "origin": None,
        "passkey": None,
    }
    code = (await rig.call("POST", "/setup-code")).json()["code"]
    response = await rig.call("GET", "/setup-code/status?wait=0")
    assert response.json()["state"] == "pending"
    assert code not in response.text
    assert code.replace("-", "") not in response.text
    for query in ("wait=x", "wait=-1", "wait=1.5", "wait=1&wait=2", "other=1", "wait=" + "9" * 16):
        response = await rig.call("GET", f"/setup-code/status?{query}")
        assert (response.status_code, response.json()["reason"]) == (400, "bad_query"), query
    waits: list[float] = []

    async def recorded(seconds: float) -> dict[str, Any]:
        waits.append(seconds)
        return {"state": "pending"}

    monkeypatch.setattr(rig.setup, "wait_status", recorded)
    for query in ("", "?wait=0", "?wait=59", "?wait=60", "?wait=61", "?wait=86400"):
        await rig.call("GET", f"/setup-code/status{query}")
    assert waits == [0, 0, 59, 60, 60, 60]
    await rig.token_client.aclose()


# --- passkeys and sessions over the socket (M5 design D.5, E.3, F.2) ----------------------------


def holder_with(tmp_path: Path, *ids: int) -> Passkeys:
    path = tmp_path / "portal" / "passkeys.json"
    holder = Passkeys(new_file(bytes(32)), PORTAL, path, clock=lambda: NOW)
    for n in ids:
        via: Literal["setup_code", "portal"] = "setup_code" if n == 1 else "portal"
        holder.add(credential(n), name=f"key {n}", via=via, origin=ORIGIN)
    return holder


def listed(holder: Passkeys, n: int) -> dict[str, Any]:
    return {
        "fingerprint": holder.fingerprint(credential(n).id),
        "name": f"key {n}",
        "rp_id": "localhost",
        "alg": "ES256",
        "synced": True,
        "transports": ["hybrid", "internal"],
        "via": "setup_code" if n == 1 else "portal",
        "origin": ORIGIN,
        "created": int(NOW),
        "last_used": None,
    }


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


@pytest.mark.anyio
async def test_the_passkeys_are_listed(tmp_path: Path) -> None:
    holder = holder_with(tmp_path, 1, 2)
    rig = AdminRig(tmp_path, passkeys=holder)
    response = await rig.call("GET", "/passkeys")
    assert response.status_code == 200
    assert response.json() == {"passkeys": [listed(holder, 1), listed(holder, 2)]}
    for n in (1, 2):
        assert b64(credential(n).id) not in response.text
        assert b64(credential(n).spki) not in response.text
    assert b64(bytes(32)) not in response.text
    assert (await rig.call("POST", "/setup-code")).json()["passkeys"] == 2
    await rig.token_client.aclose()


@pytest.mark.anyio
async def test_a_passkey_is_removed_by_its_fingerprint(
    tmp_path: Path, log_buffer: io.StringIO
) -> None:
    holder = holder_with(tmp_path, 1, 2)
    rig = AdminRig(tmp_path, passkeys=holder)
    first = holder.fingerprint(credential(1).id)
    response = await rig.call("DELETE", f"/passkeys/{first}")
    assert response.status_code == 200
    assert response.json() == {"removed": listed(holder, 1), "sessions_ended": 0, "remaining": 1}
    data = (tmp_path / "portal" / "passkeys.json").read_bytes()
    on_disk, _ = passkey_module.unseal(data, PORTAL)
    assert [c.id for c in on_disk.credentials] == [credential(2).id]
    [line] = log_events(log_buffer, "passkey_removed")
    assert without_ts(line) == {
        "role": "vault",
        "event": "passkey_removed",
        "credential": first,
        "rp_id": "localhost",
        "origin": ORIGIN,
        "sessions_ended": 0,
        "remaining": 1,
    }
    again = await rig.call("DELETE", f"/passkeys/{first}")
    assert (again.status_code, again.json()["reason"]) == (404, "not_found")
    # The last one too: host access is the recovery path.
    last = await rig.call("DELETE", f"/passkeys/{holder.fingerprint(credential(2).id)}")
    assert (last.status_code, last.json()["remaining"]) == (200, 0)
    assert holder.document.credentials == ()
    await rig.token_client.aclose()


@pytest.mark.anyio
@pytest.mark.parametrize("wanted", ["ABABABABABABABAB", "abab", "ab" * 9, "zz" * 8, "%20" * 4])
async def test_a_removal_needs_a_fingerprint(tmp_path: Path, wanted: str) -> None:
    holder = holder_with(tmp_path, 1)
    rig = AdminRig(tmp_path, passkeys=holder)
    response = await rig.call("DELETE", f"/passkeys/{wanted}")
    assert (response.status_code, response.json()["reason"]) == (400, "bad_fingerprint")
    assert len(holder.document.credentials) == 1
    await rig.token_client.aclose()


@pytest.mark.anyio
async def test_a_removal_that_cant_be_written_changes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, log_buffer: io.StringIO
) -> None:
    holder = holder_with(tmp_path, 1, 2)
    rig = AdminRig(tmp_path, passkeys=holder)

    def broken(path: Path, data: bytes) -> None:
        raise OSError("read-only")

    monkeypatch.setattr(passkey_module, "write_atomic", broken)
    response = await rig.call("DELETE", f"/passkeys/{holder.fingerprint(credential(1).id)}")
    assert response.status_code == 500
    assert response.json() == {
        "error": "not written to disk; nothing changed; check the state volume",
        "reason": "not_written",
    }
    assert len(holder.document.credentials) == 2
    assert log_events(log_buffer, "passkey_removed") == []
    await rig.token_client.aclose()


@pytest.mark.anyio
async def test_an_ambiguous_fingerprint_removes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    holder = holder_with(tmp_path, 1, 2)
    rig = AdminRig(tmp_path, passkeys=holder)
    monkeypatch.setattr(passkey_module, "fingerprint", lambda key, credential_id: "0" * 16)
    response = await rig.call("DELETE", "/passkeys/" + "0" * 16)
    assert (response.status_code, response.json()["reason"]) == (409, "ambiguous_fingerprint")
    assert len(holder.document.credentials) == 2
    await rig.token_client.aclose()


@pytest.mark.anyio
async def test_passkeys_without_a_usable_file(tmp_path: Path) -> None:
    rig = AdminRig(tmp_path)
    for method, path in (("GET", "/passkeys"), ("DELETE", "/passkeys/" + "0" * 16)):
        response = await rig.call(method, path)
        assert (response.status_code, response.json()) == (
            503,
            {"error": "the vault keeps no passkey state", "reason": "unavailable"},
        )
    await rig.token_client.aclose()
    unavailable = Passkeys(new_file(bytes(32)), PORTAL, tmp_path / "p.json", unavailable=True)
    rig = AdminRig(tmp_path, passkeys=unavailable)
    for method, path in (("GET", "/passkeys"), ("DELETE", "/passkeys/" + "0" * 16)):
        response = await rig.call(method, path)
        assert (response.status_code, response.json()) == (
            503,
            {
                "error": "the passkey file can't be verified (edited, or written under another "
                "master key); run zoeymcp setup-code --reset",
                "reason": "unavailable",
            },
        )
    assert (await rig.call("POST", "/setup-code")).json()["passkeys"] is None
    await rig.token_client.aclose()


@pytest.mark.anyio
async def test_without_a_portal_there_are_no_sessions(tmp_path: Path) -> None:
    rig = AdminRig(tmp_path)
    assert (await rig.call("GET", "/sessions")).json() == {"sessions": []}
    assert (await rig.call("DELETE", "/sessions")).json() == {"ended": 0}
    await rig.token_client.aclose()


def portal_with_sessions(*credentials: str | None) -> PortalApp:
    portal = PortalApp([ORIGIN], static=load_static())
    for credential_fp in credentials:
        portal.sessions.mint(
            origin=ORIGIN,
            rp_id="localhost",
            scope="full",
            now=time.time(),
            credential=credential_fp,
        )
    return portal


@pytest.mark.anyio
async def test_the_portals_sessions_are_listed_and_ended(
    tmp_path: Path, log_buffer: io.StringIO
) -> None:
    """``zoeymcp sessions [--end-all]``: fingerprints, never an ID or either half (F.2)."""
    portal = portal_with_sessions("a" * 16, None)
    rig = AdminRig(tmp_path, portal=portal)
    listed = (await rig.call("GET", "/sessions")).json()["sessions"]
    live = portal.sessions.live(time.time())
    assert [s["fingerprint"] for s in listed] == [s.fingerprint for s in live]
    assert [s["credential"] for s in listed] == ["a" * 16, None]
    assert set(listed[0]) == {
        "fingerprint",
        "origin",
        "scope",
        "credential",
        "created",
        "last_seen",
        "expires_at",
    }
    response = await rig.call("DELETE", "/sessions")
    assert response.json() == {"ended": 2}
    assert len(portal.sessions) == 0
    ended = log_events(log_buffer, "portal_session_ended")
    assert [line["why"] for line in ended] == ["end_all", "end_all"]
    await rig.token_client.aclose()


@pytest.mark.anyio
async def test_removing_a_passkey_ends_the_sessions_it_made(tmp_path: Path) -> None:
    holder = holder_with(tmp_path, 1, 2)
    first = holder.fingerprint(credential(1).id)
    second = holder.fingerprint(credential(2).id)
    portal = portal_with_sessions(first, first, second)
    rig = AdminRig(tmp_path, passkeys=holder, portal=portal)
    response = await rig.call("DELETE", f"/passkeys/{first}")
    assert (response.json()["sessions_ended"], response.json()["remaining"]) == (2, 1)
    assert [s.credential for s in portal.sessions.live(time.time())] == [second]
    await rig.token_client.aclose()


@pytest.mark.anyio
async def test_health_shows_the_passkeys(tmp_path: Path) -> None:
    holder = holder_with(tmp_path, 1)
    rig = AdminRig(tmp_path, passkeys=holder)
    section = (await rig.call("GET", "/health")).json()["passkeys"]
    assert (section["count"], [f["code"] for f in section["findings"]]) == (1, ["passkey_single"])
    holder.add(credential(2), name="key 2", via="portal", origin=ORIGIN)
    holder.touch(Asserted(credential(2).id, 0, True, True))
    section = (await rig.call("GET", "/health")).json()["passkeys"]
    assert (section["count"], [f["code"] for f in section["findings"]]) == (2, ["passkey_counter"])
    # Without an admin block there is no portal: no section.
    rig.policy = rig.policy.model_copy(update={"admin": None})
    assert "passkeys" not in (await rig.call("GET", "/health")).json()
    await rig.token_client.aclose()
    unavailable = Passkeys(new_file(bytes(32)), PORTAL, tmp_path / "p.json", unavailable=True)
    rig = AdminRig(tmp_path, passkeys=unavailable)
    section = (await rig.call("GET", "/health")).json()["passkeys"]
    assert (section["count"], [f["code"] for f in section["findings"]]) == (
        None,
        ["passkeys_unavailable"],
    )
    await rig.token_client.aclose()


# --- the real socket (POSIX) -------------------------------------------------------------------

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="Unix sockets")


class _Server(uvicorn.Server):
    def install_signal_handlers(self) -> None:
        pass


@contextmanager
def serve_uds(app: Any, path: str) -> Iterator[None]:
    server = _Server(uvicorn.Config(app, uds=path, log_level="warning", lifespan="off"))
    thread = threading.Thread(target=lambda: asyncio.run(server.serve()), daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        if time.monotonic() > deadline:
            raise RuntimeError("admin socket didn't start")
        time.sleep(0.01)
    try:
        yield
    finally:
        server.should_exit = True
        thread.join(10)


@pytest.fixture
def socket_dir() -> Path:
    # Short path: AF_UNIX paths are limited to about 100 bytes.
    path = Path(tempfile.mkdtemp(prefix="zm-", dir="/tmp"))
    os.chmod(path, 0o700)
    return path


def cli(argv: list[str], stdin: str = "") -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = main(argv, stdin=io.StringIO(stdin), out=out, err=err)
    return code, out.getvalue(), err.getvalue()


@posix_only
def test_cli_over_the_socket(tmp_path: Path, socket_dir: Path) -> None:
    rig = AdminRig(tmp_path)
    sock = str(socket_dir / "admin.sock")
    with serve_uds(rig.admin.app, sock):
        code, out, _ = cli(["secret", "set", "music-stats", "--socket", sock], stdin="lfm-9876\n")
        assert code == 0
        assert "bound to origins https://api.stats.example:443" in out
        assert rig.store.get_for_origin("music-stats", "https://api.stats.example").reveal() == (
            "lfm-9876"
        )
        code, out, _ = cli(["secret", "list", "--socket", sock])
        assert "music-stats" in out
        assert "lfm-9876" not in out
        code, out, _ = cli(["gateway-key", "--socket", sock])
        assert out.strip() == f"ZOEYMCP_GATEWAY_KEY={KEYS.gateway_key(1)}"
        code, out, err = cli(["setup-code", "--socket", sock])
        assert code == 0
        assert "Open http://localhost:8081 or https://zoeymcp.tailnet.example and choose" in err
        assert redeem(rig.setup, out.strip()) == Redeemed(int(rig.clock[0]) + 900, False)
        code, out, err = cli(["setup-code", "--reset", "--socket", sock])
        assert code == 0
        assert redeem(rig.setup, out.strip()) == Redeemed(int(rig.clock[0]) + 900, True)
        code, _, err = cli(["secret", "set", "nobody-uses", "--socket", sock], stdin="v-123456")
        assert code == 1
        assert "pass --origin" in err
        code, out, _ = cli(["secret", "set", "broker-refresh", "--socket", sock], stdin="rt-1")
        assert code == 0
        assert out == (
            "stored broker-refresh, bound to token endpoint https://auth.broker.example:443, "
            "access tokens to https://mcp.broker.example:443\n"
        )
        argv = ["secret", "set", "broker-refresh", "--origin", "https://x.example"]
        code, _, err = cli([*argv, "--socket", sock], stdin="rt-2")
        assert code == 1
        assert "drop --origin" in err
        assert cli(["secret", "delete", "music-stats", "--socket", sock])[0] == 0


def test_cli_secret_set_in_process(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The ``secret set`` output and refusals, with the socket swapped for the app in process."""
    rig = AdminRig(tmp_path)

    def handle(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        response = asyncio.run(rig.call(request.method, request.url.path, body))
        return httpx.Response(response.status_code, content=response.content)

    monkeypatch.setattr(httpx, "HTTPTransport", lambda **_: httpx.MockTransport(handle))
    code, out, _ = cli(["secret", "set", "broker-refresh", "--socket", "x"], stdin="rt-1\n")
    assert code == 0
    assert out == (
        "stored broker-refresh, bound to token endpoint https://auth.broker.example:443, "
        "access tokens to https://mcp.broker.example:443\n"
    )
    argv = ["secret", "set", "broker-client-id", "--origin", "https://x.example", "--socket", "x"]
    code, out, err = cli(argv, stdin="id-2")
    assert (code, out) == (1, "")
    assert err == "zoeymcp secret: OAuth secrets are bound by the policy; drop --origin\n"
    assert rig.store.names() == ["broker-refresh"]


def test_cli_reports_an_unreachable_socket(tmp_path: Path) -> None:
    code, _, err = cli(["secret", "list", "--socket", str(tmp_path / "absent.sock")])
    assert code == 1
    assert "can't reach the vault's admin socket" in err


@posix_only
def test_socket_dir_must_be_private(tmp_path: Path) -> None:
    open_dir = tmp_path / "open"
    open_dir.mkdir(mode=0o755)
    os.chmod(open_dir, 0o755)  # noqa: S103 - deliberately too open
    with pytest.raises(AdminSocketError, match="0700"):
        check_socket_dir(open_dir / "admin.sock")
    private = tmp_path / "private"
    check_socket_dir(private / "admin.sock")
    assert (private.stat().st_mode & 0o777) == 0o700


# --- OAuth secrets go through the token manager (design D.12) ----------------------------------


async def broker_ready(rig: AdminRig) -> str:
    """Set the broker's client ID and a refresh token through the admin app."""
    refresh = rig.server.issue_grant()
    for name, value in (("broker-client-id", BROKER_CLIENT_ID), ("broker-refresh", refresh)):
        response = await rig.call("PUT", f"/secrets/{name}", {"value": value})
        assert response.status_code == 200, response.text
        assert response.json() == {"name": name, "binding": BROKER_BINDING}
    return refresh


@pytest.mark.anyio
async def test_oauth_secret_set_waits_for_a_refresh_then_resets(tmp_path: Path) -> None:
    rig = AdminRig(tmp_path)
    await broker_ready(rig)
    gate = rig.server.hold()
    refresh = asyncio.create_task(rig.tokens.grant_for("broker-mcp", BROKER_UPSTREAM))
    await rig.server.arrived()
    replacement = rig.server.issue_grant()
    put = asyncio.create_task(rig.call("PUT", "/secrets/broker-refresh", {"value": replacement}))
    for _ in range(20):
        await asyncio.sleep(0)
    assert not put.done()
    gate.set()
    grant = await refresh
    assert (await put).status_code == 200
    # The operator's value, not the successor the refresh saved first.
    stored = rig.store.get_for_oauth("broker-refresh", token_url=BROKER_TOKEN_URL)[0]
    assert stored.reveal() == replacement
    entry = rig.store.entry("broker-refresh")
    assert entry is not None
    assert entry.meta == {
        "oauth": {"source": "operator", "consented_at": None, "credential": "broker-mcp"}
    }
    # The cached token was dropped: the next request refreshes with the new value.
    again = await rig.tokens.grant_for("broker-mcp", BROKER_UPSTREAM)
    assert again.serial != grant.serial
    assert rig.server.refresh_calls[-1].refresh_token == replacement
    await rig.token_client.aclose()


@pytest.mark.anyio
async def test_oauth_secret_delete_goes_through_the_manager(tmp_path: Path) -> None:
    rig = AdminRig(tmp_path)
    await broker_ready(rig)
    await rig.tokens.grant_for("broker-mcp", BROKER_UPSTREAM)
    response = await rig.call("DELETE", "/secrets/broker-refresh")
    assert response.status_code == 200
    # The broker names no revocation_url: nothing to revoke (M7 design D.9).
    assert response.json() == {"name": "broker-refresh", "deleted": True, "revocation": "none"}
    assert rig.store.names() == ["broker-client-id"]
    # The cache went with it: nothing is left to present.
    with pytest.raises(OAuthUnavailable) as caught:
        await rig.tokens.grant_for("broker-mcp", BROKER_UPSTREAM)
    assert caught.value.code == CREDENTIAL_UNAVAILABLE
    missing = await rig.call("DELETE", "/secrets/broker-refresh")
    assert missing.status_code == 404
    assert missing.json() == {"error": "no such secret"}
    await rig.token_client.aclose()


@pytest.mark.anyio
async def test_without_a_manager_oauth_secrets_go_to_the_store(tmp_path: Path) -> None:
    rig = AdminRig(tmp_path, tokens=False)
    response = await rig.call("PUT", "/secrets/broker-refresh", {"value": "rt-123456"})
    assert response.json() == {"name": "broker-refresh", "binding": BROKER_BINDING}
    entry = rig.store.entry("broker-refresh")
    assert entry is not None
    assert entry.meta is None
    assert (await rig.call("DELETE", "/secrets/broker-refresh")).status_code == 200
    assert rig.store.names() == []
    await rig.token_client.aclose()


@pytest.fixture
def failing_writes(monkeypatch: pytest.MonkeyPatch) -> list[bool]:
    """Set the flag to make the store's atomic rename fail."""
    failing = [False]
    real = os.replace

    def replace(src: str, dst: str | Path) -> None:
        if failing[0]:
            raise OSError(28, "No space left on device")
        real(src, dst)

    monkeypatch.setattr("zoeymcp.vault.store.os.replace", replace)
    return failing


@pytest.mark.anyio
@pytest.mark.parametrize("name", ["music-stats", "broker-refresh"])
async def test_a_failed_write_is_a_500_and_kept_in_memory(
    tmp_path: Path, failing_writes: list[bool], name: str
) -> None:
    rig = AdminRig(tmp_path)
    failing_writes[0] = True
    buffer = io.StringIO()
    logs.set_stream(buffer)
    try:
        response = await rig.call("PUT", f"/secrets/{name}", {"value": "v-123456"})
        kept = rig.store.names()
        deleted = await rig.call("DELETE", f"/secrets/{name}")
    finally:
        logs.set_stream(None)
    assert response.status_code == 500
    assert response.json() == {
        "error": "kept in memory, not written to disk; check the state volume"
    }
    assert response.json()["error"] == NOT_WRITTEN
    assert kept == [name]
    assert deleted.status_code == 500
    assert deleted.json() == {"error": NOT_WRITTEN}
    assert rig.store.names() == []
    assert rig.store.dirty
    lines = [json.loads(line) for line in buffer.getvalue().splitlines()]
    failed = [line for line in lines if line["event"] in ("secret_set", "secret_deleted")]
    assert failed == [
        {
            "ts": failed[0]["ts"],
            "role": "vault",
            "event": "secret_set",
            "name": name,
            "persisted": False,
            "error_type": "StoreWriteError",
            "via": "socket",
        },
        {
            "ts": failed[1]["ts"],
            "role": "vault",
            "event": "secret_deleted",
            "name": name,
            "persisted": False,
            "error_type": "StoreWriteError",
            "via": "socket",
        },
    ]
    assert "v-123456" not in buffer.getvalue()
    failing_writes[0] = False
    rig.store.flush()
    assert not rig.store.dirty
    await rig.token_client.aclose()


@pytest.mark.anyio
@pytest.mark.parametrize("name", ["music-stats", "broker-refresh"])
async def test_secret_logs_say_the_socket_asked(tmp_path: Path, name: str) -> None:
    rig = AdminRig(tmp_path)
    buffer = io.StringIO()
    logs.set_stream(buffer)
    try:
        put = await rig.call("PUT", f"/secrets/{name}", {"value": "v-123456"})
        assert (await rig.call("DELETE", f"/secrets/{name}")).status_code == 200
    finally:
        logs.set_stream(None)
    lines = [json.loads(line) for line in buffer.getvalue().splitlines()]
    events = [line for line in lines if line["event"] in ("secret_set", "secret_deleted")]
    assert [{k: v for k, v in line.items() if k != "ts"} for line in events] == [
        {
            "role": "vault",
            "event": "secret_set",
            "name": name,
            "binding": put.json()["binding"],
            "via": "socket",
        },
        {"role": "vault", "event": "secret_deleted", "name": name, "via": "socket"},
    ]
    await rig.token_client.aclose()


@pytest.mark.anyio
async def test_a_failed_live_slot_delete_is_a_500(
    tmp_path: Path, failing_writes: list[bool]
) -> None:
    rig = AdminRig(tmp_path)
    rig.store.put("oauth.broker-mcp.live", "rt-123456", BROKER_BINDING)
    failing_writes[0] = True
    response = await rig.call("DELETE", "/secrets/oauth.broker-mcp.live")
    assert response.status_code == 500
    assert response.json() == {"error": NOT_WRITTEN}
    await rig.token_client.aclose()


def test_json_safe() -> None:
    nan, inf = float("nan"), float("inf")
    assert json_safe({"a": nan, "b": [inf, -inf, 1.5, {"c": nan}], "d": "x", "e": 3}) == {
        "a": None,
        "b": [None, None, 1.5, {"c": None}],
        "d": "x",
        "e": 3,
    }
    assert json_safe(0.0) == 0.0
    assert json_safe(None) is None


@pytest.mark.anyio
async def test_a_tampered_meta_still_lists(tmp_path: Path) -> None:
    rig = AdminRig(tmp_path)
    rig.store.put("music-stats", "lfm-123456", {"origins": ["https://api.stats.example:443"]})
    document = json.loads(rig.store.path.read_text(encoding="utf-8"))
    document["entries"]["music-stats"]["meta"] = {
        "oauth": {"rotations": float("nan"), "seen": [float("inf")]}
    }
    tampered = json.dumps(document)
    assert "NaN" in tampered
    assert "Infinity" in tampered
    rig.store.path.write_text(tampered, encoding="utf-8")
    fresh = AdminRig(tmp_path)
    response = await fresh.call("GET", "/secrets")
    assert response.status_code == 200
    [entry] = response.json()["secrets"]
    assert entry["meta"] == {"oauth": {"rotations": None, "seen": [None]}}
    await rig.token_client.aclose()
    await fresh.token_client.aclose()


# --- OAuth login endpoints (design E.1) --------------------------------------------------------

BROKER_AUTHORIZE = "https://auth.broker.example/authorize"


def login_policy() -> Policy:
    """The example policy, with the broker's client ID written in and an authorize_url."""
    raw = load_mapping(EXAMPLE_POLICY.read_text(encoding="utf-8"))
    broker = raw["credentials"]["broker-mcp"]
    broker["client_id"] = BROKER_CLIENT_ID
    broker["authorize_url"] = BROKER_AUTHORIZE
    return Policy.model_validate(raw)


async def browse(rig: AdminRig, url: str) -> str:
    transport = httpx.ASGITransport(app=rig.server.app())
    async with httpx.AsyncClient(transport=transport) as browser:
        response = await browser.get(url)
    assert response.status_code == 302
    location: str = response.headers["location"]
    return location


@pytest.mark.anyio
async def test_oauth_login_through_the_admin_app(tmp_path: Path) -> None:
    rig = AdminRig(tmp_path)
    rig.set_policy(login_policy())
    started = await rig.call("POST", "/oauth/broker-mcp/login")
    assert started.status_code == 200, started.text
    data = started.json()
    assert set(data) == {
        "flow",
        "authorize_url",
        "redirect_uri",
        "expires",
        "requested_scopes",
        "expected_scopes",
        "client_auth",
        "rotates",
        "binding",
        "binding_change",
        "replaced",
        "callback",
        "callback_address",
    }
    assert (data["replaced"], data["callback"], data["callback_address"]) == (None, None, False)
    assert data["binding"] == BROKER_BINDING
    assert data["authorize_url"].startswith(BROKER_AUTHORIZE + "?response_type=code&")
    pasted = await browse(rig, data["authorize_url"])
    body = {"flow": data["flow"], "redirect_url": pasted}
    done = await rig.call("POST", "/oauth/broker-mcp/complete", body)
    assert done.status_code == 200, done.text
    assert done.json()["slot"] == "broker-refresh"
    assert done.json()["persisted"] is True
    stored = rig.store.get_for_oauth("broker-refresh", token_url=BROKER_TOKEN_URL)[0]
    assert stored.reveal() == rig.server.active_refresh_token()
    for value in (stored.reveal(), pasted, data["flow"]):
        assert value not in done.text
    listing = await rig.call("GET", "/oauth")
    assert listing.status_code == 200
    [status] = listing.json()["credentials"]
    assert (status["credential"], status["state"], status["hint"]) == ("broker-mcp", "ok", None)
    assert stored.reveal() not in listing.text
    reset = await rig.call("POST", "/oauth/broker-mcp/reset")
    assert (reset.status_code, reset.json()) == (200, {"credential": "broker-mcp", "reset": True})
    await rig.token_client.aclose()


@pytest.mark.anyio
async def test_oauth_errors_carry_a_reason(tmp_path: Path) -> None:
    rig = AdminRig(tmp_path)
    cases = [
        ("POST", "/oauth/broker-mcp/login", None, 409, "no_authorize_url"),
        ("POST", "/oauth/music-stats/login", None, 404, "not_oauth"),
        ("POST", "/oauth/nope/reset", None, 404, "not_oauth"),
        (
            "POST",
            "/oauth/broker-mcp/complete",
            {"flow": "nope", "redirect_url": "http://127.0.0.1/callback"},
            404,
            "flow_unknown",
        ),
    ]
    for method, path, body, status, reason in cases:
        response = await rig.call(method, path, body)
        assert (response.status_code, response.json()["reason"]) == (status, reason), path
        assert set(response.json()) == {"error", "reason"}
    rig.set_policy(login_policy())
    rig.store.put(
        "broker-refresh",
        "rt-123456",
        {"oauth": {"token": "https://x.example:443", "resources": ["https://x.example:443"]}},
    )
    login_bodies: list[dict[str, bool] | None] = [None, {}, {"rebind": False}]
    for login_body in login_bodies:
        changed = await rig.call("POST", "/oauth/broker-mcp/login", login_body)
        assert changed.status_code == 409, login_body
        assert changed.json()["reason"] == "binding_changed"
        assert changed.json()["new"] == BROKER_BINDING
    rebound = await rig.call("POST", "/oauth/broker-mcp/login", {"rebind": True})
    assert rebound.status_code == 200
    assert rebound.json()["binding_change"]["new"] == BROKER_BINDING
    await rig.token_client.aclose()


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("path", "content", "status", "message"),
    [
        ("/oauth/broker-mcp/login", b"[]", 400, "body must be a JSON object"),
        ("/oauth/broker-mcp/login", b"{", 400, "body must be JSON"),
        ("/oauth/broker-mcp/login", b'{"rebind": "yes"}', 400, "expected {rebind?: bool}"),
        ("/oauth/broker-mcp/login", b'{"other": 1}', 400, "expected {rebind?: bool}"),
        ("/oauth/broker-mcp/login", b" " * (128 * 1024 + 1), 413, "body too large"),
        ("/oauth/broker-mcp/complete", b"{}", 400, "expected {flow, redirect_url}"),
        ("/oauth/broker-mcp/complete", b'{"flow": "f"}', 400, "expected {flow, redirect_url}"),
        (
            "/oauth/broker-mcp/complete",
            b'{"flow": 1, "redirect_url": "x"}',
            400,
            "expected {flow, redirect_url}",
        ),
        (
            "/oauth/broker-mcp/complete",
            b'{"flow": "f", "redirect_url": "x", "more": 1}',
            400,
            "expected {flow, redirect_url}",
        ),
        ("/oauth/broker-mcp/complete", b" " * (8 * 1024 + 1), 413, "body too large"),
    ],
    ids=[
        "login-list",
        "login-not-json",
        "login-rebind-type",
        "login-other-key",
        "login-too-large",
        "complete-empty",
        "complete-no-url",
        "complete-flow-type",
        "complete-extra-key",
        "complete-too-large",
    ],
)
async def test_oauth_bodies_are_checked(
    tmp_path: Path, path: str, content: bytes, status: int, message: str
) -> None:
    rig = AdminRig(tmp_path)
    transport = httpx.ASGITransport(app=rig.admin.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://admin") as client:
        response = await client.post(path, content=content)
    assert (response.status_code, response.json()) == (status, {"error": message})
    await rig.token_client.aclose()


@pytest.mark.anyio
async def test_a_complete_body_of_8_kib_is_read(tmp_path: Path) -> None:
    rig = AdminRig(tmp_path)
    body = json.dumps({"flow": "nope", "redirect_url": "x"}).encode()
    body += b" " * (8 * 1024 - len(body))
    transport = httpx.ASGITransport(app=rig.admin.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://admin") as client:
        response = await client.post("/oauth/broker-mcp/complete", content=body)
    assert response.json()["reason"] == "flow_unknown"
    await rig.token_client.aclose()


@pytest.mark.anyio
async def test_a_login_body_of_128_kib_is_read(tmp_path: Path) -> None:
    rig = AdminRig(tmp_path)
    body = json.dumps({"rebind": False}).encode()
    body += b" " * (128 * 1024 - len(body))
    transport = httpx.ASGITransport(app=rig.admin.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://admin") as client:
        response = await client.post("/oauth/broker-mcp/login", content=body)
    assert (response.status_code, response.json()["reason"]) == (409, "no_authorize_url")
    await rig.token_client.aclose()


class RefusingLogin(LoginService):
    """Refuses every start and completion with one reason."""

    def __init__(self, tokens: TokenManager, error: LoginError) -> None:
        super().__init__(tokens)
        self.error = error

    async def start(
        self,
        credential: str,
        *,
        rebind: bool = False,
        owner: str = CLI_OWNER,
        origin: str | None = None,
    ) -> dict[str, Any]:
        raise self.error

    async def complete(
        self, credential: str, flow_id: str, redirect_url: str, owner: str = CLI_OWNER
    ) -> dict[str, Any]:
        raise self.error


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("reason", "status"),
    [
        ("not_oauth", 404),
        ("flow_unknown", 404),
        ("no_authorize_url", 409),
        ("no_route", 409),
        ("authorize_misconfigured", 409),
        ("binding_changed", 409),
        ("client_id_unavailable", 409),
        ("client_secret_unavailable", 409),
        ("too_many_flows", 429),
        ("redirect_mismatch", 400),
        ("provider_error", 400),
        ("no_refresh_token", 400),
        ("exchange_failed:oauth_unavailable", 400),
    ],
)
async def test_login_reasons_have_their_status(tmp_path: Path, reason: str, status: int) -> None:
    rig = AdminRig(tmp_path)
    details = {"provider_error": "access_denied", "description": "fake description"}
    error = LoginError(reason, "fake message", details=details)
    rig.admin = AdminApp(
        rig.store, KEYS, lambda: rig.policy, rig.setup, rig.tokens, RefusingLogin(rig.tokens, error)
    )
    expected = {"error": "fake message", "reason": reason, **details}
    login = await rig.call("POST", "/oauth/broker-mcp/login")
    assert (login.status_code, login.json()) == (status, expected)
    body = {"flow": "f", "redirect_url": "x"}
    complete = await rig.call("POST", "/oauth/broker-mcp/complete", body)
    assert (complete.status_code, complete.json()) == (status, expected)
    await rig.token_client.aclose()


@pytest.mark.anyio
async def test_a_paste_with_a_lone_surrogate_is_refused(tmp_path: Path) -> None:
    rig = AdminRig(tmp_path)
    rig.set_policy(login_policy())
    flow = (await rig.call("POST", "/oauth/broker-mcp/login")).json()["flow"]
    content = json.dumps({"flow": flow, "redirect_url": "http://127.0.0.1/callback?state=\ud800"})
    transport = httpx.ASGITransport(app=rig.admin.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://admin") as client:
        response = await client.post("/oauth/broker-mcp/complete", content=content)
    assert response.status_code == 400
    assert response.json() == {"error": "the address can't be read", "reason": "redirect_mismatch"}
    await rig.token_client.aclose()


@pytest.mark.anyio
async def test_oauth_needs_the_token_manager(tmp_path: Path) -> None:
    rig = AdminRig(tmp_path, tokens=False)
    for method, path in [
        ("GET", "/oauth"),
        ("POST", "/oauth/broker-mcp/login"),
        ("POST", "/oauth/broker-mcp/complete"),
        ("POST", "/oauth/broker-mcp/reset"),
        ("DELETE", "/oauth/flows/f"),
    ]:
        response = await rig.call(method, path)
        assert response.status_code == 503, path
        assert response.json() == {"error": NO_TOKENS}
    await rig.token_client.aclose()


@pytest.mark.anyio
async def test_oauth_cancel(tmp_path: Path) -> None:
    rig = AdminRig(tmp_path)
    rig.set_policy(login_policy())
    assert (await rig.call("DELETE", "/oauth/flows/nope")).json() == {"cancelled": False}
    flow = (await rig.call("POST", "/oauth/broker-mcp/login")).json()["flow"]
    assert (await rig.call("DELETE", f"/oauth/flows/{flow}")).json() == {"cancelled": True}
    await rig.token_client.aclose()


@pytest.mark.anyio
async def test_oauth_status_is_json_safe(tmp_path: Path) -> None:
    rig = AdminRig(tmp_path)
    rig.store.put(
        "broker-refresh",
        "rt-123456",
        BROKER_BINDING,
        meta={"oauth": {"rotations": 1, "granted_scope": "read"}},
    )
    document = json.loads(rig.store.path.read_text(encoding="utf-8"))
    document["entries"]["broker-refresh"]["meta"]["oauth"]["rotations"] = float("nan")
    rig.store.path.write_text(json.dumps(document), encoding="utf-8")
    fresh = AdminRig(tmp_path)
    response = await fresh.call("GET", "/oauth")
    assert response.status_code == 200
    [status] = response.json()["credentials"]
    assert status["meta"] == {"rotations": None, "granted_scope": "read"}
    assert status["scopes"] == {"unexpected": [], "missing": ["trade"]}
    assert "rt-123456" not in response.text
    await rig.token_client.aclose()
    await fresh.token_client.aclose()


# --- health (M5 design I) ----------------------------------------------------------------------

MAIL_BINDING = {
    "smtp": {
        "host": "smtp.mail.example",
        "port": 465,
        "from": "Agent <agent@mail.example>",
        "to": ["partner@mail.example"],
    }
}


def health_codes(report: dict[str, Any]) -> dict[str, list[str]]:
    items = [*report["credentials"], *report["connectors"], {"name": "store", **report["store"]}]
    return {item["name"]: [f["code"] for f in item["findings"]] for item in items}


@pytest.mark.anyio
async def test_health_reads_metadata_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rig = AdminRig(tmp_path)
    await rig.call("PUT", "/secrets/music-stats", {"value": "lfm-123456"})
    rig.store.put("broker-refresh", "rt-123456", BROKER_BINDING)
    rig.store.put("mail-pass", "pw-123456", MAIL_BINDING)
    rig.store.put("leftover", "old-123456", {"origins": ["https://old.example:443"]})

    def refuse(*args: Any) -> None:
        raise AssertionError("health decrypted a secret")

    monkeypatch.setattr(SecretStore, "_decrypt", refuse)
    response = await rig.call("GET", "/health")
    assert response.status_code == 200
    report = response.json()
    for value in ("lfm-123456", "rt-123456", "pw-123456", "old-123456"):
        assert value not in response.text
    assert health_codes(report) == {
        "music-stats": [],
        "broker-mcp": ["missing"],
        "mail-out": ["missing"],
        "store": ["unreferenced"],
    }
    assert report["summary"] == {"error": 2, "warning": 0, "info": 1}
    broker = report["credentials"][1]
    assert broker["oauth"]["state"] == "idle"
    # Without the connectors, no journal was read.
    assert report["connectors"][0]["sent_24h"] is None
    await rig.token_client.aclose()


@pytest.mark.anyio
async def test_health_sums_up_each_connector_and_knows_the_env(tmp_path: Path) -> None:
    rig = AdminRig(tmp_path)
    connectors = SmtpConnectors(tmp_path, KEYS, clock_ms=lambda: 1_790_000_000_000)
    policy = rig.policy.model_copy(
        update={
            "connectors": {
                "mail-out": rig.policy.connectors["mail-out"].model_copy(
                    update={"username": "env:MAIL_USER"}
                )
            }
        }
    )
    rig.set_policy(policy)
    rig.admin = AdminApp(
        rig.store,
        KEYS,
        lambda: rig.policy,
        rig.setup,
        rig.tokens,
        connectors=connectors,
        env_names=lambda: {"MAIL_USER"},
    )
    rig.store.put("mail-pass", "pw-123456", MAIL_BINDING)
    [mail] = (await rig.call("GET", "/health")).json()["connectors"]
    assert (mail["sent_24h"], mail["last"], mail["findings"]) == (0, None, [])
    assert mail["refs"][0] == {"ref": "env:MAIL_USER", "present": True, "binding": None}

    def unreadable(name: str) -> Any:
        raise PermissionError(13, "denied")

    connectors.journal = unreadable  # type: ignore[method-assign]
    [mail] = (await rig.call("GET", "/health")).json()["connectors"]
    assert mail["sent_24h"] is None
    await rig.token_client.aclose()


@pytest.mark.anyio
async def test_health_without_the_token_manager(tmp_path: Path) -> None:
    rig = AdminRig(tmp_path, tokens=False)
    response = await rig.call("GET", "/health")
    assert response.status_code == 200
    assert "oauth" not in response.json()["credentials"][1]
    await rig.token_client.aclose()


# --- the reported ledger (M5 design J.4, J.5) ----------------------------------------------------


def reported_rig(tmp_path: Path, clock: list[int] | None = None) -> tuple[AdminRig, ReportStore]:
    now = clock or [T0]
    copy = ReportStore.open(tmp_path, clock=lambda: now[0])
    connectors = SmtpConnectors(tmp_path, KEYS, clock_ms=lambda: now[0])
    rig = AdminRig(tmp_path)
    rig.admin = AdminApp(
        rig.store,
        KEYS,
        lambda: rig.policy,
        rig.setup,
        rig.tokens,
        connectors=connectors,
        reports=copy,
    )
    return rig, copy


def report(lines: list[bytes]) -> Any:
    return canonical.loads_strict(ledgerreport.encode(lines))


def chained(count: int, *, tick: int = 0) -> list[bytes]:
    lines: list[bytes] = []
    prev = GENESIS
    for n in range(count):
        lines.append(asked_line(n, prev, tick + n + 1))
        prev = line_hash(lines[-1])
    return lines


@pytest.mark.anyio
async def test_the_reported_copy_pages_newest_first(tmp_path: Path) -> None:
    rig, copy = reported_rig(tmp_path)
    copy.report(report(chained(5)))
    first = (await rig.call("GET", "/ledger/reported?limit=2")).json()
    assert [row["seq"] for row in first["rows"]] == [4, 3]
    assert first["next"] == 3
    assert (first["state"]["state"], first["state"]["head_seq"]) == ("ok", 4)
    assert (first["refused"], first["archives"]) == (None, [])
    rest = (await rig.call("GET", "/ledger/reported?before=3")).json()
    assert [row["seq"] for row in rest["rows"]] == [2, 1, 0]
    assert rest["next"] is None
    # Never a keyed digest or a pin.
    assert "hmac-sha256" not in json.dumps(first)
    await rig.token_client.aclose()


@pytest.mark.anyio
async def test_the_reported_copy_joins_the_send_journals(tmp_path: Path) -> None:
    rig, copy = reported_rig(tmp_path)
    journal = tmp_path / "connectors" / "mail-out"
    journal.mkdir(parents=True)
    sending = {
        "ts": T0 - 1,
        "key": "0000000000000001.1",
        "req_hmac": "hmac-sha256:" + "0" * 64,
        "key_id": "0" * 16,
        "subject_chars": 1,
        "body_chars": 1,
    }
    record = sendjournal.encode("sending", **sending)
    (journal / "journal-0000000000001.jsonl").write_bytes(record + b"not a record\n")
    copy.report(report(chained(2)))
    page = (await rig.call("GET", "/ledger/reported")).json()
    [row] = [row for row in page["rows"] if row["ref"] == "0000000000000001"]
    assert row["journal"] == [
        {
            "key": "0000000000000001.1",
            "state": "sending",
            "smtp_code": None,
            "at": row["journal"][0]["at"],
        }
    ]
    assert page["orphans"] == []
    await rig.token_client.aclose()


@pytest.mark.anyio
async def test_the_orphans_are_judged_against_the_kept_archives(tmp_path: Path) -> None:
    """J.5: after a restart, a send whose call is archived isn't an orphan; one begun before the
    earliest record kept is ``older_than_copy``; one inside that span no call explains is
    ``no_ledger_record``. Only the first page has orphans."""
    rig, copy = reported_rig(tmp_path, [T0 + 10_000])
    copy.report(report(chained(3)))
    copy.report(report(chained(3, tick=100)[1:]))
    copy.restart()
    copy.report(report(chained(2, tick=200)))
    journal = tmp_path / "connectors" / "mail-out"
    journal.mkdir(parents=True)
    common = {
        "req_hmac": "hmac-sha256:" + "0" * 64,
        "key_id": "0" * 16,
        "subject_chars": 1,
        "body_chars": 1,
    }
    sends = [("0000000000000001.1", T0 + 1), (f"{0xA1:016x}.1", T0), (f"{0xA2:016x}.1", T0 + 1)]
    lines = [sendjournal.encode("sending", ts=ts, key=key, **common) for key, ts in sends]
    (journal / "journal-0000000000001.jsonl").write_bytes(b"".join(lines))
    page = (await rig.call("GET", "/ledger/reported")).json()
    assert [(o["key"], o["flag"]) for o in page["orphans"]] == [
        (f"{0xA2:016x}.1", "no_ledger_record"),
        (f"{0xA1:016x}.1", "older_than_copy"),
    ]
    assert [row["seq"] for row in page["rows"]] == [1, 0]  # the live chain's rows only
    assert (await rig.call("GET", "/ledger/reported?before=1")).json()["orphans"] == []
    await rig.token_client.aclose()


@pytest.mark.anyio
@pytest.mark.parametrize(
    "query", ["?before=x", "?limit=-1", "?other=1", "?limit=1&limit=2", "?before=" + "9" * 16]
)
async def test_a_bad_page_query_is_400(tmp_path: Path, query: str) -> None:
    rig, _ = reported_rig(tmp_path)
    response = await rig.call("GET", "/ledger/reported" + query)
    assert response.status_code == 400
    assert response.json()["reason"] == "bad_query"
    await rig.token_client.aclose()


@pytest.mark.anyio
async def test_without_a_copy_the_ledger_routes_are_503(tmp_path: Path) -> None:
    rig = AdminRig(tmp_path)
    for method, path, body in [
        ("GET", "/ledger/reported", None),
        ("POST", "/ledger/reported/restart", {"dry_run": True}),
    ]:
        response = await rig.call(method, path, body)
        assert (response.status_code, response.json()["reason"]) == (503, "unavailable")
    await rig.token_client.aclose()


@pytest.mark.anyio
async def test_an_unreadable_copy_shows_as_unavailable(tmp_path: Path) -> None:
    (tmp_path / "ledger-reported").write_bytes(b"x")
    rig, _ = reported_rig(tmp_path)
    page = (await rig.call("GET", "/ledger/reported")).json()
    assert (page["state"]["state"], page["rows"]) == ("unavailable", [])
    restart = await rig.call("POST", "/ledger/reported/restart", {"dry_run": True})
    assert (restart.status_code, restart.json()["reason"]) == (503, "unavailable")
    health = (await rig.call("GET", "/health")).json()["ledger_copy"]
    assert [f["code"] for f in health["findings"]] == ["ledger_copy_unavailable"]
    await rig.token_client.aclose()


@pytest.mark.anyio
async def test_a_chain_restart_over_the_socket(tmp_path: Path) -> None:
    rig, copy = reported_rig(tmp_path)
    refused = await rig.call("POST", "/ledger/reported/restart", {"dry_run": True})
    assert (refused.status_code, refused.json()["reason"]) == (409, "not_restartable")
    copy.report(report(chained(3)))
    copy.report(report(chained(3, tick=100)[1:]))
    planned = (await rig.call("POST", "/ledger/reported/restart", {"dry_run": True})).json()
    plan = planned["plan"]
    assert (plan["state"], plan["drop"], plan["archive"]["name"]) == ("fork", [], None)
    assert copy.state == "fork"  # a dry run changes nothing

    stale = {**plan, "archive": {**plan["archive"], "size": 1}}
    changed = await rig.call("POST", "/ledger/reported/restart", {"plan": stale})
    assert changed.status_code == 409
    assert (changed.json()["reason"], changed.json()["plan"]) == ("changed", plan)

    done = await rig.call("POST", "/ledger/reported/restart", {"plan": plan})
    assert done.status_code == 200
    answer = done.json()
    assert answer["restarted"]["archive"]["name"] == f"archive-{T0:013d}"
    assert answer["head"] == {"head_seq": None, "head_hash": None, "state": "ok"}
    page = (await rig.call("GET", "/ledger/reported")).json()
    assert [a["name"] for a in page["archives"]] == [f"archive-{T0:013d}"]
    await rig.token_client.aclose()


@pytest.mark.anyio
@pytest.mark.parametrize("body", [{}, {"dry_run": False}, {"plan": 1}, {"plan": {}, "x": 1}])
async def test_a_restart_body_is_checked(tmp_path: Path, body: Any) -> None:
    rig, _ = reported_rig(tmp_path)
    response = await rig.call("POST", "/ledger/reported/restart", body)
    assert response.status_code == 400
    await rig.token_client.aclose()


@pytest.mark.anyio
async def test_a_restart_that_isnt_written_is_500(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rig, copy = reported_rig(tmp_path)
    copy.report(report(chained(3)))
    copy.report(report(chained(3, tick=100)[1:]))
    plan = (await rig.call("POST", "/ledger/reported/restart", {"dry_run": True})).json()["plan"]

    def broken(*args: Any, **kwargs: Any) -> None:
        raise OSError("read-only")

    monkeypatch.setattr(common_files, "write_atomic", broken)
    response = await rig.call("POST", "/ledger/reported/restart", {"plan": plan})
    assert (response.status_code, response.json()["reason"]) == (500, "not_written")
    await rig.token_client.aclose()


@pytest.mark.anyio
async def test_health_shows_the_reported_copy(tmp_path: Path) -> None:
    now = [T0]
    rig, copy = reported_rig(tmp_path, now)
    section = (await rig.call("GET", "/health")).json()["ledger_copy"]
    assert section == {
        "state": "ok",
        "head_seq": None,
        "reported_ago": None,
        "broken_at": None,
        "level": "info",
        "findings": [
            {
                "code": "ledger_copy_none",
                "level": "info",
                "advisory": False,
                "text": "no report from the gateway yet",
                "action": {"kind": "check_gateway"},
            }
        ],
    }
    now[0] += 301_000
    codes = (await rig.call("GET", "/health")).json()["ledger_copy"]["findings"]
    assert [f["code"] for f in codes] == ["ledger_copy_stale"]
    copy.contact()
    copy.report(report(chained(2)))
    now[0] += 12_000
    section = (await rig.call("GET", "/health")).json()["ledger_copy"]
    assert (section["head_seq"], section["reported_ago"], section["findings"]) == (1, 12, [])
    copy.report(report(chained(2, tick=50)))
    found = (await rig.call("GET", "/health")).json()
    assert [f["code"] for f in found["ledger_copy"]["findings"]] == ["ledger_copy_refused"]
    assert found["summary"]["error"] >= 1
    # Without a gateway in the policy, nothing reports: no section.
    rig.set_policy(rig.policy.model_copy(update={"gateway": None}))
    assert "ledger_copy" not in (await rig.call("GET", "/health")).json()
    await rig.token_client.aclose()


# --- onboarding by URL (M7 design M.1) ------------------------------------------------------------

ONBOARD_ROUTES = [
    ("POST", "/onboard/discover"),
    ("POST", "/onboard/x/register"),
    ("POST", "/onboard/x/fragment"),
    ("DELETE", "/onboard/x"),
]


@pytest.mark.anyio
async def test_without_an_onboarding_service_the_routes_are_503(tmp_path: Path) -> None:
    rig = AdminRig(tmp_path)
    for method, path in ONBOARD_ROUTES:
        response = await rig.call(method, path, {})
        assert response.status_code == 503
        assert response.json() == {"error": NO_ONBOARDING, "reason": "unavailable"}


@pytest.mark.anyio
async def test_onboarding_over_the_socket(tmp_path: Path, log_buffer: io.StringIO) -> None:
    """The CLI's phase 1 (M.1): the plan, the secret stored and fragment 1, fragment 1 again,
    and the cancel; the secret in no answer and no line."""
    rig = AdminRig(tmp_path, onboard=True)
    discovered = await rig.call("POST", "/onboard/discover", onboard_model.confidential())
    assert discovered.status_code == 200, discovered.text
    plan = discovered.json()
    assert (plan["stage"], plan["plan"]["issuer"]) == ("discovered", onboard_model.ISSUER)
    onboarding = plan["onboarding"]
    registered = await rig.call(
        "POST",
        f"/onboard/{onboarding}/register",
        {"client_secret": onboard_model.GIVEN_SECRET},
    )
    assert registered.status_code == 200, registered.text
    made = registered.json()
    assert (made["secret_stored"], made["secret_name"]) == (True, onboard_model.SECRET_NAME)
    fragment = load_mapping(made["diff"]["yaml"])
    assert fragment["credentials"]["notes"]["client_secret"] == "store:notes-client-secret"
    again = await rig.call("POST", f"/onboard/{onboarding}/fragment", {"indent": "compose"})
    assert again.status_code == 200
    assert again.json()["diff"]["yaml"].startswith(" " * 8 + "# zoeymcp: onboarding notes")
    assert (await rig.call("DELETE", f"/onboard/{onboarding}")).status_code == 204
    gone = await rig.call("DELETE", f"/onboard/{onboarding}")
    assert gone.status_code == 404
    assert gone.json()["reason"] == "onboarding_unknown"
    entry = rig.store.entry(onboard_model.SECRET_NAME)
    assert entry is not None
    assert entry.meta is not None
    assert entry.meta["client_id"] == onboard_model.CLIENT_ID
    seen = discovered.text + registered.text + again.text + gone.text + log_buffer.getvalue()
    assert onboard_model.GIVEN_SECRET not in seen
    assert onboarding not in log_buffer.getvalue()
    await rig.token_client.aclose()


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("body", "status", "reason"),
    [
        ({"url": onboard_model.SERVER_URL}, 409, "registration_unavailable"),
        ({"url": "http://mcp.notes.example/mcp"}, 400, "url_invalid"),
        ({"url": onboard_model.SERVER_URL, "name": "broker-mcp"}, 409, "name_taken"),
        ({"other": 1}, 400, "bad_body"),
    ],
)
async def test_a_refused_discovery_is_the_catalogues(
    tmp_path: Path, body: dict[str, Any], status: int, reason: str
) -> None:
    rig = AdminRig(tmp_path, onboard=True)
    response = await rig.call("POST", "/onboard/discover", body)
    assert response.status_code == status
    answer = response.json()
    assert answer["reason"] == reason
    assert CATALOGUE[reason].status == status
    assert answer["error"].endswith(".")
    await rig.token_client.aclose()


@pytest.mark.anyio
async def test_the_onboarding_bodies_are_capped(tmp_path: Path) -> None:
    rig = AdminRig(tmp_path, onboard=True)
    transport = httpx.ASGITransport(app=rig.admin.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://admin") as client:
        large = await client.post("/onboard/discover", content=b"{" + b" " * 5000 + b"}")
        broken = await client.post("/onboard/discover", content=b"{")
        listed = await client.post("/onboard/x/fragment", content=b"[]")
    assert (large.status_code, broken.status_code, listed.status_code) == (413, 400, 400)
    await rig.token_client.aclose()
