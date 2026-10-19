from __future__ import annotations

import asyncio
import io
import json
import os
import sys
import tempfile
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import httpx
import pytest
import uvicorn

from tests.fakes.oauth_server import FakeAuthServer
from zoeymcp.cli.main import main
from zoeymcp.common.policy import Policy, parse_policy
from zoeymcp.common.yamlload import load_mapping
from zoeymcp.vault import gatewaykeys, logs
from zoeymcp.vault.admin import (
    NO_GATEWAY_KEYS,
    NO_TOKENS,
    NOT_WRITTEN,
    AdminApp,
    AdminSocketError,
    SetupCodes,
    check_socket_dir,
    json_safe,
)
from zoeymcp.vault.app import VaultApp
from zoeymcp.vault.gatewaykeys import GatewayKeys
from zoeymcp.vault.keys import KeySet
from zoeymcp.vault.oauth.login import LoginError, LoginService
from zoeymcp.vault.oauth.protocol import CREDENTIAL_UNAVAILABLE
from zoeymcp.vault.oauth.tokens import OAuthUnavailable, TokenManager
from zoeymcp.vault.store import SecretStore

from .conftest import EXAMPLE_POLICY

KEYS = KeySet.from_master(bytes(range(32)))
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
    """The admin app with the example policy and, as in the vault, a token manager."""

    def __init__(
        self, tmp_path: Path, clock: list[float] | None = None, *, tokens: bool = True
    ) -> None:
        self.policy = example_policy()
        self.store = SecretStore(tmp_path, KEYS)
        self.store.load()
        self.clock = clock or [1_000_000.0]
        self.setup = SetupCodes(tmp_path, clock=lambda: self.clock[0])
        self.server, token_app = broker_server()
        self.token_client = httpx.AsyncClient(transport=httpx.ASGITransport(app=token_app))
        self.tokens = TokenManager(self.store, self.token_client)
        self.tokens.configure(self.policy, {})
        self.admin = AdminApp(
            self.store, KEYS, lambda: self.policy, self.setup, self.tokens if tokens else None
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


# --- setup codes -------------------------------------------------------------------------------


def test_setup_codes_are_one_time_and_expire(tmp_path: Path) -> None:
    clock = [1_000_000.0]
    codes = SetupCodes(tmp_path, clock=lambda: clock[0])
    code, expires = codes.issue()
    assert expires == 1_000_000 + 15 * 60
    assert code.encode() not in (tmp_path / "setup.json").read_bytes()
    assert codes.consume("WRONG-CODE") is False
    assert codes.consume(code) is True
    assert codes.consume(code) is False
    late, _ = codes.issue()
    clock[0] += 15 * 60 + 1
    assert codes.consume(late) is False


def test_a_new_code_replaces_the_old(tmp_path: Path) -> None:
    codes = SetupCodes(tmp_path)
    first, _ = codes.issue()
    second, _ = codes.issue()
    assert codes.consume(first) is False
    assert codes.consume(second) is True


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
        code, out, _ = cli(["setup-code", "--socket", sock])
        assert rig.setup.consume(out.strip()) is True
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


def test_setup_file_is_json(tmp_path: Path) -> None:
    SetupCodes(tmp_path).issue()
    record = json.loads((tmp_path / "setup.json").read_text(encoding="utf-8"))
    assert set(record) == {"sha256", "expires"}


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
    assert response.json() == {"name": "broker-refresh", "deleted": True}
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
    }
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

    async def start(self, credential: str, *, rebind: bool = False) -> dict[str, Any]:
        raise self.error

    async def complete(self, credential: str, flow_id: str, redirect_url: str) -> dict[str, Any]:
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
