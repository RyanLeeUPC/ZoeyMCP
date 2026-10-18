"""``zoeymcp gateway``: what stops it starting, and its CLI (M3 design B.1)."""

from __future__ import annotations

import io
import json
import logging
import os
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from zoeymcp.cli import main as cli
from zoeymcp.gateway import logs, server
from zoeymcp.gateway.marks import MARKS_FILE
from zoeymcp.gateway.server import Options, StartupError, check_private_dir, prepare

KEY = "zgw1-" + "A" * 43


@pytest.fixture
def captured() -> Iterator[io.StringIO]:
    buffer = io.StringIO()
    logs.set_stream(buffer)
    try:
        yield buffer
    finally:
        logs.set_stream(None)


@pytest.fixture(autouse=True)
def not_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server, "running_as_root", lambda: False)


def options(tmp_path: Path, **changes: Any) -> Options:
    base: dict[str, Any] = {
        "vault": "unix:/run/zoeymcp-link/vault.sock",
        "state": tmp_path / "state",
        "admin_socket": None,
    }
    base.update(changes)
    return Options(**base)


def test_a_unix_link_starts(tmp_path: Path) -> None:
    gateway = prepare(options(tmp_path), {})
    assert gateway.link.kind == "unix"
    assert gateway.keys is None
    assert (tmp_path / "state").is_dir()


def test_an_http_link_needs_the_key(tmp_path: Path) -> None:
    with pytest.raises(StartupError, match="ZOEYMCP_GATEWAY_KEY"):
        prepare(options(tmp_path, vault="http://vault:8080"), {})
    gateway = prepare(options(tmp_path, vault="http://vault:8080"), {"ZOEYMCP_GATEWAY_KEY": KEY})
    assert gateway.keys is not None
    assert gateway.keys.current() is not None


def test_a_key_with_a_unix_link_is_unused(tmp_path: Path, captured: io.StringIO) -> None:
    gateway = prepare(options(tmp_path), {"ZOEYMCP_GATEWAY_KEY": KEY})
    assert gateway.keys is None
    assert [json.loads(line)["event"] for line in captured.getvalue().splitlines()] == [
        "gateway_key_unused"
    ]


@pytest.mark.parametrize(
    "name", ["ZOEYMCP_MASTER_KEY", "ZOEYMCP_MASTER_KEY_PREVIOUS", "ZOEYMCP_CONFIG"]
)
def test_the_vaults_secrets_in_the_environment_stop_it(tmp_path: Path, name: str) -> None:
    with pytest.raises(StartupError, match=name) as raised:
        prepare(options(tmp_path), {name: "value-that-must-not-be-echoed"})
    assert "value-that-must-not-be-echoed" not in str(raised.value)


def test_root_is_refused_unless_allowed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server, "running_as_root", lambda: True)
    with pytest.raises(StartupError, match="root"):
        prepare(options(tmp_path), {})
    prepare(options(tmp_path, allow_root=True), {})


@pytest.mark.parametrize("vault", ["unix:relative", "https://vault", "vault:8080"])
def test_a_bad_link_is_refused(tmp_path: Path, vault: str) -> None:
    with pytest.raises(StartupError):
        prepare(options(tmp_path, vault=vault), {})


def test_a_bad_key_is_refused(tmp_path: Path) -> None:
    with pytest.raises(StartupError, match="zgw1-"):
        prepare(options(tmp_path, vault="http://vault:8080"), {"ZOEYMCP_GATEWAY_KEY": "short"})


def test_an_unreadable_marks_file_stops_it(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)  # as the gateway makes it; a plain mkdir is open to others
    (state / MARKS_FILE).write_bytes(b"{")
    with pytest.raises(StartupError, match="drift marks"):
        prepare(options(tmp_path), {})


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_a_state_dir_open_to_others_is_refused(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o755)
    state.chmod(0o755)
    with pytest.raises(StartupError, match="open to other users"):
        check_private_dir(state)
    state.chmod(0o700)
    check_private_dir(state)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX ownership")
def test_a_state_dir_owned_by_another_user_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    other = os.stat(tmp_path).st_uid + 1
    monkeypatch.setattr(os, "geteuid", lambda: other)
    with pytest.raises(StartupError, match="another user"):
        check_private_dir(tmp_path)


def test_the_sdk_loggers_are_silenced() -> None:
    server.quiet_sdk_loggers()
    for name in ("mcp", "httpx2", "uvicorn.error"):
        assert not logging.getLogger(name).isEnabledFor(logging.CRITICAL)


def test_listen_addresses() -> None:
    assert server._split_listen("127.0.0.1:8090") == ("127.0.0.1", 8090)
    assert server._split_listen("[::1]:8090") == ("::1", 8090)


# --- the CLI -------------------------------------------------------------------------------------


def test_the_cli_passes_its_options(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[Options] = []
    monkeypatch.setattr(cli, "exec_gateway_environment", lambda argv: None)
    monkeypatch.setattr(server, "run", lambda opts, environ: seen.append(opts))
    argv = [
        "gateway",
        "--vault",
        "http://vault:8080",
        "--listen",
        "127.0.0.1:9000",
        "--state",
        "/s",
        "--admin-socket",
        "none",
        "--control-fd",
        "5",
    ]
    assert cli.main(argv, out=io.StringIO(), err=io.StringIO()) == 0
    [opts] = seen
    assert opts == Options(
        vault="http://vault:8080",
        listen="127.0.0.1:9000",
        state=Path("/s"),
        admin_socket=None,
        allow_root=False,
        control_fd=5,
    )


def test_the_cli_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[Options] = []
    monkeypatch.setattr(cli, "exec_gateway_environment", lambda argv: None)
    monkeypatch.setattr(server, "run", lambda opts, environ: seen.append(opts))
    assert (
        cli.main(["gateway", "--vault", "unix:/run/v.sock"], out=io.StringIO(), err=io.StringIO())
        == 0
    )
    assert seen == [Options(vault="unix:/run/v.sock")]


def test_a_startup_error_is_one_line_and_exit_2(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "exec_gateway_environment", lambda argv: None)

    def refuse(opts: Options, environ: object) -> None:
        raise StartupError("refusing to run as root")

    monkeypatch.setattr(server, "run", refuse)
    err = io.StringIO()
    assert (
        cli.main(["gateway", "--vault", "unix:/run/v.sock"], out=io.StringIO(), err=err)
        == cli.EXIT_UNREADABLE
    )
    assert err.getvalue() == "zoeymcp gateway: refusing to run as root\n"


def test_the_vault_link_is_required() -> None:
    with pytest.raises(SystemExit):
        cli.main(["gateway"], out=io.StringIO(), err=io.StringIO())
