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

from zoeymcp.cli.main import main
from zoeymcp.common.policy import Policy
from zoeymcp.vault.admin import AdminApp, AdminSocketError, SetupCodes, check_socket_dir
from zoeymcp.vault.app import VaultApp
from zoeymcp.vault.bindings import BindingError, derive_binding
from zoeymcp.vault.keys import KeySet
from zoeymcp.vault.store import SecretStore

from .conftest import EXAMPLE_POLICY

KEYS = KeySet.from_master(bytes(range(32)))
ZWSP = chr(0x200B)


def example_policy() -> Policy:
    from zoeymcp.common.policy import parse_policy

    return parse_policy(EXAMPLE_POLICY.read_text(encoding="utf-8"), "example")


# --- bindings ----------------------------------------------------------------------------------


def test_route_credential_binds_to_its_upstream() -> None:
    assert derive_binding(example_policy(), "music-stats") == {
        "origins": ["https://api.stats.example:443"]
    }


def test_oauth_secrets_bind_to_the_token_endpoint_only() -> None:
    policy = example_policy()
    for name in ("broker-refresh", "broker-client-id"):
        assert derive_binding(policy, name) == {"origins": ["https://auth.broker.example:443"]}


def test_smtp_password_binds_to_the_connector() -> None:
    assert derive_binding(example_policy(), "mail-pass") == {
        "smtp": {
            "host": "smtp.mail.example",
            "port": 465,
            "from": "Agent <agent@mail.example>",
            "to": ["partner@mail.example"],
        }
    }


def test_unreferenced_secret_needs_an_explicit_origin() -> None:
    with pytest.raises(BindingError, match="pass --origin"):
        derive_binding(example_policy(), "nobody-uses-this")


def test_conflicting_uses_are_refused() -> None:
    raw = example_policy().model_dump(by_alias=True)
    raw["credentials"]["music-stats"]["secret"] = "store:mail-pass"
    with pytest.raises(BindingError, match="both by a connector"):
        derive_binding(Policy.model_validate(raw), "mail-pass")


# --- admin app (in process) --------------------------------------------------------------------


class AdminRig:
    def __init__(self, tmp_path: Path, clock: list[float] | None = None) -> None:
        self.policy = example_policy()
        self.store = SecretStore(tmp_path, KEYS)
        self.store.load()
        self.clock = clock or [1_000_000.0]
        self.setup = SetupCodes(tmp_path, clock=lambda: self.clock[0])
        self.admin = AdminApp(self.store, KEYS, lambda: self.policy, self.setup)

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
async def test_bad_secret_names(tmp_path: Path) -> None:
    rig = AdminRig(tmp_path)
    assert (await rig.call("PUT", "/secrets/Bad Name", {"value": "v"})).status_code in (400, 404)
    assert (await rig.call("PUT", "/secrets/UPPER", {"value": "v"})).status_code == 400


@pytest.mark.anyio
async def test_no_endpoint_returns_a_value(tmp_path: Path) -> None:
    rig = AdminRig(tmp_path)
    await rig.call("PUT", "/secrets/music-stats", {"value": "distinctive-value-42"})
    for method, path in [
        ("GET", "/secrets"),
        ("GET", "/secrets/music-stats"),
        ("GET", "/gateway-key"),
        ("POST", "/setup-code"),
    ]:
        response = await rig.call(method, path)
        assert "distinctive-value-42" not in response.text


@pytest.mark.anyio
async def test_gateway_key(tmp_path: Path) -> None:
    rig = AdminRig(tmp_path)
    data = (await rig.call("GET", "/gateway-key")).json()
    assert data == {"generation": 1, "key": KEYS.gateway_key(1)}


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
        assert cli(["secret", "delete", "music-stats", "--socket", sock])[0] == 0


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
