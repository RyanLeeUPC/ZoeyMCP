from __future__ import annotations

import asyncio
import errno
import io
import json
import os
import re
import socket
import stat
import sys
import types
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

import httpx
import pytest

from tests.unit.report_model import asked_line
from zoeymcp.common.ledgerformat import GENESIS
from zoeymcp.vault import gatewaykeys, logs, server
from zoeymcp.vault.admin import SetupCodes
from zoeymcp.vault.app import GATEWAY_HEADER, VaultApp
from zoeymcp.vault.connectors import sendjournal
from zoeymcp.vault.connectors.smtp import Answer, SmtpConnectors
from zoeymcp.vault.gatewaykeys import BACKWARDS, STATE_FILE, TAMPERED, State
from zoeymcp.vault.keys import KeySet, generate_master_key
from zoeymcp.vault.oauth.login import LoginService
from zoeymcp.vault.server import (
    LOCK_FILE,
    ListenerTag,
    StartupError,
    acquire_state_lock,
    load_runtime,
)
from zoeymcp.vault.store import SecretStore, origin_binding

from .conftest import EXAMPLE_POLICY


def env(**extra: str) -> dict[str, str]:
    return {"ZOEYMCP_MASTER_KEY": generate_master_key(), **extra}


def test_starts_with_the_example(tmp_path: Path) -> None:
    runtime = load_runtime(str(EXAMPLE_POLICY), tmp_path, env())
    assert runtime.policy.mode == "declarative"
    assert runtime.store.names() == []


def test_needs_a_master_key(tmp_path: Path) -> None:
    with pytest.raises(StartupError, match="ZOEYMCP_MASTER_KEY is not set"):
        load_runtime(str(EXAMPLE_POLICY), tmp_path, {})
    with pytest.raises(StartupError, match="32 bytes"):
        load_runtime(str(EXAMPLE_POLICY), tmp_path, {"ZOEYMCP_MASTER_KEY": "c2hvcnQ"})


def test_refuses_a_policy_that_fails_check(tmp_path: Path, example_text: str) -> None:
    bad = example_text.replace(
        "callers: [gateway] # the gateway only", "callers: [{placeholder: ph-sandbox-0123456789}]"
    )
    policy_file = tmp_path / "bad.yaml"
    policy_file.write_text(bad, encoding="utf-8")
    with pytest.raises(StartupError, match="fails check"):
        load_runtime(str(policy_file), tmp_path, env())


def test_refuses_managed_mode_for_now(tmp_path: Path, example_text: str) -> None:
    policy_file = tmp_path / "managed.yaml"
    policy_file.write_text(example_text.replace("mode: declarative", "mode: managed"), "utf-8")
    with pytest.raises(StartupError, match="managed mode arrives in M6"):
        load_runtime(str(policy_file), tmp_path, env())


def test_refuses_a_store_from_another_key(tmp_path: Path) -> None:
    old = generate_master_key()
    store = SecretStore(tmp_path, KeySet.from_text(old))
    store.load()
    store.put("x", "v", origin_binding(["https://api.example"]))
    with pytest.raises(StartupError, match="ZOEYMCP_MASTER_KEY_PREVIOUS"):
        load_runtime(str(EXAMPLE_POLICY), tmp_path, env())
    rotated = load_runtime(str(EXAMPLE_POLICY), tmp_path, env(ZOEYMCP_MASTER_KEY_PREVIOUS=old))
    assert rotated.store.names() == ["x"]


def test_load_runtime_twice_on_one_directory(tmp_path: Path) -> None:
    environ = env()
    first = load_runtime(str(EXAMPLE_POLICY), tmp_path, environ)
    first.store.put("x", "v", origin_binding(["https://api.example"]))
    second = load_runtime(str(EXAMPLE_POLICY), tmp_path, environ)
    assert second.store.names() == ["x"]


# --- the state lock ------------------------------------------------------------------------------


def _log_lines(buffer: io.StringIO) -> list[dict[str, Any]]:
    return [json.loads(line) for line in buffer.getvalue().splitlines()]


@pytest.fixture
def log_buffer() -> Iterator[io.StringIO]:
    buffer = io.StringIO()
    logs.set_stream(buffer)
    try:
        yield buffer
    finally:
        logs.set_stream(None)


@pytest.mark.skipif(sys.platform == "win32", reason="flock is POSIX only")
def test_state_lock_refuses_a_second_holder(tmp_path: Path, log_buffer: io.StringIO) -> None:
    state = tmp_path / "state"
    fd = acquire_state_lock(state)
    assert fd is not None
    try:
        assert (state / LOCK_FILE).is_file()
        assert stat.S_IMODE(os.stat(state / LOCK_FILE).st_mode) == 0o600
        lock_path = str(state / LOCK_FILE)
        assert _log_lines(log_buffer)[-1]["event"] == "state_locked"
        assert _log_lines(log_buffer)[-1]["path"] == lock_path
        with pytest.raises(StartupError) as caught:
            acquire_state_lock(state)
        assert str(caught.value) == f"another vault is using this state directory ({lock_path})"
    finally:
        os.close(fd)
    # Released when the holder's descriptor closes, as at process exit.
    again = acquire_state_lock(state)
    assert again is not None
    os.close(again)


@pytest.mark.skipif(sys.platform == "win32", reason="flock is POSIX only")
def test_state_lock_reports_an_unusable_directory(tmp_path: Path) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("x", encoding="utf-8")
    path = blocker / "state" / LOCK_FILE
    with pytest.raises(StartupError, match=rf"^can't open {re.escape(str(path))}: "):
        acquire_state_lock(blocker / "state")


@pytest.mark.skipif(sys.platform == "win32", reason="flock is POSIX only")
def test_run_keeps_the_lock(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    held: list[int | None] = []

    def lock(state_dir: Path) -> int | None:
        fd = acquire_state_lock(state_dir)
        held.append(fd)
        return fd

    def load(*args: object) -> None:
        raise StartupError("stop here")

    monkeypatch.setattr(server, "acquire_state_lock", lock)
    monkeypatch.setattr(server, "load_runtime", load)
    try:
        with pytest.raises(StartupError, match="stop here"):
            server.run(None, ["127.0.0.1:0"], tmp_path, env(), None)
        with pytest.raises(StartupError, match="another vault"):
            acquire_state_lock(tmp_path)
    finally:
        for fd in held:
            if fd is not None:
                os.close(fd)


class _FakeFcntl:
    """Stands in for ``fcntl``, so the POSIX branch runs on any platform."""

    LOCK_EX = 2
    LOCK_NB = 4

    def __init__(self) -> None:
        self.error: OSError | None = None
        self.calls: list[tuple[int, int]] = []

    def flock(self, fd: int, operation: int) -> None:
        self.calls.append((fd, operation))
        if self.error is not None:
            raise self.error


@pytest.fixture
def fake_fcntl(monkeypatch: pytest.MonkeyPatch) -> _FakeFcntl:
    fake = _FakeFcntl()
    monkeypatch.setattr(server, "sys", types.SimpleNamespace(platform="linux"))
    monkeypatch.setattr(server, "fcntl", fake, raising=False)
    return fake


def _is_closed(fd: int) -> bool:
    try:
        os.fstat(fd)
    except OSError:
        return True
    return False


def test_state_lock_takes_an_exclusive_lock(
    tmp_path: Path, fake_fcntl: _FakeFcntl, log_buffer: io.StringIO
) -> None:
    state = tmp_path / "state"
    fd = acquire_state_lock(state)
    assert fd is not None
    try:
        assert fake_fcntl.calls == [(fd, _FakeFcntl.LOCK_EX | _FakeFcntl.LOCK_NB)]
        assert (state / LOCK_FILE).is_file()
        line = _log_lines(log_buffer)[-1]
        assert line["event"] == "state_locked"
        assert line["path"] == str(state / LOCK_FILE)
    finally:
        os.close(fd)


def test_state_lock_held_elsewhere(tmp_path: Path, fake_fcntl: _FakeFcntl) -> None:
    fake_fcntl.error = BlockingIOError(errno.EAGAIN, "Resource temporarily unavailable")
    with pytest.raises(StartupError) as caught:
        acquire_state_lock(tmp_path)
    path = tmp_path / LOCK_FILE
    assert str(caught.value) == f"another vault is using this state directory ({path})"
    [(fd, _)] = fake_fcntl.calls
    assert _is_closed(fd)


def test_state_lock_without_lock_support(tmp_path: Path, fake_fcntl: _FakeFcntl) -> None:
    fake_fcntl.error = OSError(errno.ENOLCK, "No locks available")
    with pytest.raises(StartupError) as caught:
        acquire_state_lock(tmp_path)
    path = tmp_path / LOCK_FILE
    assert str(caught.value) == f"can't lock {path}: [Errno {errno.ENOLCK}] No locks available"
    [(fd, _)] = fake_fcntl.calls
    assert _is_closed(fd)


def test_state_lock_open_failure(tmp_path: Path, fake_fcntl: _FakeFcntl) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("x", encoding="utf-8")
    path = blocker / "state" / LOCK_FILE
    with pytest.raises(StartupError, match=rf"^can't open {re.escape(str(path))}: "):
        acquire_state_lock(blocker / "state")
    assert fake_fcntl.calls == []


@pytest.mark.skipif(sys.platform != "win32", reason="the Windows fallback")
def test_state_lock_is_skipped_on_windows(tmp_path: Path, log_buffer: io.StringIO) -> None:
    assert acquire_state_lock(tmp_path) is None
    assert acquire_state_lock(tmp_path) is None
    assert not (tmp_path / LOCK_FILE).exists()
    line = _log_lines(log_buffer)[-1]
    assert line["event"] == "state_lock_unavailable"
    assert line["path"] == str(tmp_path / LOCK_FILE)
    assert line["reason"] == "no flock on this platform"


def test_run_locks_the_state_directory_before_loading(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []

    def lock(state_dir: Path) -> int | None:
        assert state_dir == tmp_path
        calls.append("lock")
        raise StartupError("another vault is using this state directory")

    def load(*args: object) -> None:
        calls.append("load")
        raise StartupError("stop here")

    monkeypatch.setattr(server, "acquire_state_lock", lock)
    monkeypatch.setattr(server, "load_runtime", load)
    with pytest.raises(StartupError, match="another vault"):
        server.run(None, ["127.0.0.1:0"], tmp_path, env(), None)
    assert calls == ["lock"]

    monkeypatch.setattr(server, "acquire_state_lock", lambda state_dir: calls.append("lock"))
    with pytest.raises(StartupError, match="stop here"):
        server.run(None, ["127.0.0.1:0"], tmp_path, env(), None)
    assert calls == ["lock", "lock", "load"]


# --- reload and shutdown -------------------------------------------------------------------------


def _app(tmp_path: Path) -> VaultApp:
    runtime = load_runtime(str(EXAMPLE_POLICY), tmp_path / "state", env())
    return VaultApp(runtime.policy, runtime.store, runtime.keys, environ={})


def test_reload_reports_oauth_resets(
    tmp_path: Path, example_text: str, log_buffer: io.StringIO
) -> None:
    app = _app(tmp_path)
    same = tmp_path / "same.yaml"
    same.write_text(example_text, encoding="utf-8")
    server.reload_policy(app, str(same), env())
    assert _log_lines(log_buffer)[-1] == {
        "ts": _log_lines(log_buffer)[-1]["ts"],
        "role": "vault",
        "event": "reload_ok",
        "oauth_reset": [],
    }
    moved = tmp_path / "moved.yaml"
    moved.write_text(
        example_text.replace("https://mcp.broker.example\n", "https://mcp2.broker.example\n"),
        encoding="utf-8",
    )
    server.reload_policy(app, str(moved), env())
    events = [line["event"] for line in _log_lines(log_buffer)]
    assert "egress_proxy_change_needs_restart" not in events
    assert _log_lines(log_buffer)[-1]["oauth_reset"] == ["broker-mcp"]
    assert app.policy.routes[1].upstream == "https://mcp2.broker.example"
    asyncio.run(app.aclose())


def test_reload_refuses_a_bad_policy(
    tmp_path: Path, example_text: str, log_buffer: io.StringIO
) -> None:
    app = _app(tmp_path)
    before = app.policy
    bad = tmp_path / "bad.yaml"
    bad.write_text(example_text.replace("mode: declarative", "mode: managed"), encoding="utf-8")
    server.reload_policy(app, str(bad), env())
    line = _log_lines(log_buffer)[-1]
    assert line["event"] == "reload_refused"
    assert "managed mode arrives in M6" in line["reason"]
    assert app.policy is before
    asyncio.run(app.aclose())


def _with_proxy(example_text: str, proxy: str | None) -> str:
    if proxy is None:
        return example_text
    return example_text.replace(
        "gateway_key_generation: 1", f"gateway_key_generation: 1\negress_proxy: {proxy}"
    )


class _RecordingConnectors(SmtpConnectors):
    """Records the proxy each send is given, and sends nothing."""

    def __init__(self, state_dir: Path, keys: KeySet) -> None:
        super().__init__(state_dir, keys)
        self.proxies: list[str | None] = []

    async def send(self, name: str, connector: Any, **kwargs: Any) -> Answer:
        self.proxies.append(kwargs["proxy"])
        return Answer(200, {"status": "sent"})


@pytest.mark.parametrize(
    ("before", "after", "restart"),
    [
        (None, "http://proxy:3128", True),
        ("http://proxy:3128", None, True),
        ("http://proxy:3128", "http://other-proxy:3128", True),
        ("http://proxy:3128", "http://proxy:3128", False),
        (None, None, False),
    ],
)
def test_reload_says_an_egress_proxy_change_needs_a_restart(
    tmp_path: Path,
    example_text: str,
    log_buffer: io.StringIO,
    before: str | None,
    after: str | None,
    restart: bool,
) -> None:
    first = tmp_path / "first.yaml"
    first.write_bytes(_with_proxy(example_text, before).encode())
    runtime = load_runtime(str(first), tmp_path / "state", env())
    connectors = _RecordingConnectors(tmp_path / "state", runtime.keys)
    app = VaultApp(
        runtime.policy,
        runtime.store,
        runtime.keys,
        environ={},
        gateway_link=True,
        connectors=connectors,
    )
    assert app.policy.egress_proxy == before
    onboarding = app.onboarding_client
    second = tmp_path / "second.yaml"
    second.write_bytes(_with_proxy(example_text, after).encode())
    server.reload_policy(app, str(second), env())
    events = [line["event"] for line in _log_lines(log_buffer)]
    assert events[-1] == "reload_ok"
    assert ("egress_proxy_change_needs_restart" in events) is restart
    if restart:
        assert events[-2] == "egress_proxy_change_needs_restart"
    assert app.policy.egress_proxy == after
    # The clients and the connector keep the startup proxy until the restart (D-61).
    assert app.egress_proxy == before
    assert app.onboarding_client is onboarding

    async def send() -> httpx.Response:
        transport = httpx.ASGITransport(app=ListenerTag(app, "gateway"))
        async with httpx.AsyncClient(transport=transport, base_url="http://vault") as client:
            return await client.post(
                "/mail/send",
                headers={"idempotency-key": "k" * 32, "content-type": "application/json"},
                content=b"{}",
            )

    assert asyncio.run(send()).status_code == 200
    assert connectors.proxies == [before]
    asyncio.run(app.aclose())


def test_the_restart_note_compares_with_the_startup_proxy(
    tmp_path: Path, example_text: str, log_buffer: io.StringIO
) -> None:
    """The note compares the new policy with what the clients use, the startup value: it repeats
    on every reload until the restart, the same changed proxy again included, and a reload back
    to the startup value logs none."""
    runtime = load_runtime(str(EXAMPLE_POLICY), tmp_path / "state", env())
    app = VaultApp(runtime.policy, runtime.store, runtime.keys, environ={})
    changed = tmp_path / "changed.yaml"
    changed.write_bytes(_with_proxy(example_text, "http://proxy:3128").encode())
    back = tmp_path / "back.yaml"
    back.write_bytes(example_text.encode())
    noted: list[bool] = []
    for path in (changed, changed, back):
        server.reload_policy(app, str(path), env())
        events = [line["event"] for line in _log_lines(log_buffer)]
        assert events[-1] == "reload_ok"
        noted.append(events[-2] == "egress_proxy_change_needs_restart")
    assert noted == [True, True, False]
    events = [line["event"] for line in _log_lines(log_buffer)]
    assert events.count("egress_proxy_change_needs_restart") == 2
    asyncio.run(app.aclose())


def test_serve_closes_the_app_on_the_way_out(log_buffer: io.StringIO) -> None:
    calls: list[str] = []

    class App:
        async def aclose(self) -> None:
            calls.append("aclose")

    asyncio.run(server.serve(cast(VaultApp, App()), [], config=None, environ={}))
    assert calls == ["aclose"]
    assert _log_lines(log_buffer)[-1]["event"] == "vault_stopped"


# --- pre-bound listeners (M5 design B.3, D17) -----------------------------------------------------


# How the OS words "address already in use": WinError on Windows, where the errno is WSA's.
IN_USE = rf"\[(Errno|WinError) {errno.EADDRINUSE}\] "


def _occupied() -> socket.socket:
    """A loopback socket listening on a free port, as another process's would."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen()
    return sock


def test_a_listen_address_in_use_is_a_startup_error(
    monkeypatch: pytest.MonkeyPatch, log_buffer: io.StringIO
) -> None:
    bound: list[socket.socket] = []

    def binder(host: str, port: int) -> list[socket.socket]:
        sockets = server.bind_tcp(host, port)
        bound.extend(sockets)
        return sockets

    def no_server(config: Any) -> None:
        raise AssertionError("a server was built before every address was bound")

    class App:
        async def aclose(self) -> None:
            pass

    monkeypatch.setattr(server, "_Server", no_server)
    with _occupied() as occupied:
        port = occupied.getsockname()[1]
        listens = ["127.0.0.1:0", f"127.0.0.1:{port}"]
        refused = f"^can't listen on 127.0.0.1:{port} for the proxy: {IN_USE}"
        with pytest.raises(StartupError, match=refused):
            asyncio.run(
                server.serve(cast(VaultApp, App()), listens, config=None, environ={}, binder=binder)
            )
    # The address bound before the one in use is closed again, and the vault never started.
    assert len(bound) == 1
    assert bound[0].fileno() == -1
    assert "vault_started" not in log_buffer.getvalue()


def test_the_binder_sets_so_reuseaddr_on_posix_only() -> None:
    # As asyncio does: on Windows the option shares a port rather than reusing a closed one's.
    with _occupied() as occupied:
        port = occupied.getsockname()[1]
        with pytest.raises(OSError, match=f"^{IN_USE}"):
            server.bind_tcp("127.0.0.1", port)
    [sock] = server.bind_tcp("127.0.0.1", 0)
    with sock:
        assert sock.getsockname()[0] == "127.0.0.1"
        assert (sock.family, sock.type) == (socket.AF_INET, socket.SOCK_STREAM)
        reuse = sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR)
        assert bool(reuse) is (sys.platform != "win32")


def test_the_binder_keeps_ipv6_sockets_to_ipv6() -> None:
    try:
        sockets = server.bind_tcp("::1", 0)
    except OSError:
        pytest.skip("no IPv6 loopback here")
    [sock] = sockets
    with sock:
        assert sock.family == socket.AF_INET6
        assert sock.getsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY) == 1


def test_the_binder_skips_what_asyncio_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    unmakeable = (cast(socket.AddressFamily, 12345), socket.SOCK_STREAM, 0, "", ("x", 0))
    unavailable = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 0))  # TEST-NET-1
    loopback = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))
    infos = [unmakeable, unavailable, unavailable, loopback]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: infos)
    [sock] = server.bind_tcp("vault.example", 0)
    with sock:
        assert sock.getsockname()[0] == "127.0.0.1"
    infos = [unmakeable, unavailable]
    with pytest.raises(OSError, match=r"^no address vault\.example resolves to can be bound$"):
        server.bind_tcp("vault.example", 0)


def test_run_gives_the_admin_the_token_manager(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}

    async def serve(app: VaultApp, listens: list[str], **kwargs: Any) -> None:
        seen.update(app=app, **kwargs)
        await app.aclose()

    monkeypatch.setattr(server, "acquire_state_lock", lambda state_dir: None)
    monkeypatch.setattr(server, "socket_supported", lambda: True)
    monkeypatch.setattr(server, "check_socket_dir", lambda path: None)
    monkeypatch.setattr(server, "serve", serve)
    server.run(str(EXAMPLE_POLICY), ["127.0.0.1:0"], tmp_path, env(), tmp_path / "admin.sock")
    assert seen["admin"]._tokens is seen["app"].tokens


def test_run_builds_the_setup_codes_without_a_socket(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On Windows, or with --admin-socket none, the portal still redeems a code issued offline,
    so run builds its one SetupCodes outside the socket branch (M5 design E.2, verifier V12)."""
    built: list[SetupCodes] = []
    seen: dict[str, Any] = {}

    class Recorded(SetupCodes):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            built.append(self)

    async def serve(app: VaultApp, listens: list[str], **kwargs: Any) -> None:
        seen.update(kwargs)
        await app.aclose()

    environ = env()
    monkeypatch.setattr(server, "SetupCodes", Recorded)
    monkeypatch.setattr(server, "acquire_state_lock", lambda state_dir: None)
    monkeypatch.setattr(server, "socket_supported", lambda: False)
    monkeypatch.setattr(server, "serve", serve)
    server.run(str(EXAMPLE_POLICY), ["127.0.0.1:0"], tmp_path, environ, tmp_path / "admin.sock")
    assert seen["admin"] is None
    [setup] = built
    assert setup.path == tmp_path / "setup.json"
    # Under the master key's portal key: a code the CLI writes offline is one it reads.
    key = KeySet.from_text(environ["ZOEYMCP_MASTER_KEY"]).portal_key
    _, record = SetupCodes(tmp_path, key).issue()
    assert setup.record() == record


def test_run_gives_the_admin_the_setup_codes_and_passkeys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, log_buffer: io.StringIO
) -> None:
    seen: dict[str, Any] = {}

    async def serve(app: VaultApp, listens: list[str], **kwargs: Any) -> None:
        seen.update(kwargs)
        await app.aclose()

    environ = env()
    monkeypatch.setattr(server, "acquire_state_lock", lambda state_dir: None)
    monkeypatch.setattr(server, "socket_supported", lambda: True)
    monkeypatch.setattr(server, "check_socket_dir", lambda path: None)
    monkeypatch.setattr(server, "serve", serve)
    server.run(str(EXAMPLE_POLICY), ["127.0.0.1:0"], tmp_path, environ, tmp_path / "admin.sock")
    admin = seen["admin"]
    assert admin._setup.path == tmp_path / "setup.json"
    holder = admin._passkeys
    assert holder.document.credentials == ()
    assert not holder.unavailable
    lines = [line for line in _log_lines(log_buffer) if line["event"] == "passkeys_loaded"]
    assert [(line["count"], line["generation"]) for line in lines] == [(0, 0)]


def test_run_reseals_the_passkeys_under_the_new_master_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from zoeymcp.portal.passkeys import Passkeys, seal, unseal

    from .test_passkeys import made

    old, new = generate_master_key(), generate_master_key()
    old_key = KeySet.from_text(old).portal_key
    path = tmp_path / "portal" / "passkeys.json"
    path.parent.mkdir(mode=0o700)
    path.write_bytes(seal(made(1), old_key))
    seen: dict[str, Any] = {}

    async def serve(app: VaultApp, listens: list[str], **kwargs: Any) -> None:
        seen.update(kwargs)
        await app.aclose()

    monkeypatch.setattr(server, "acquire_state_lock", lambda state_dir: None)
    monkeypatch.setattr(server, "socket_supported", lambda: True)
    monkeypatch.setattr(server, "check_socket_dir", lambda path: None)
    monkeypatch.setattr(server, "serve", serve)
    environ = {"ZOEYMCP_MASTER_KEY": new, "ZOEYMCP_MASTER_KEY_PREVIOUS": old}
    server.run(str(EXAMPLE_POLICY), ["127.0.0.1:0"], tmp_path, environ, tmp_path / "admin.sock")
    holder: Passkeys = seen["admin"]._passkeys
    assert len(holder.document.credentials) == 1
    document, resealed = unseal(path.read_bytes(), KeySet.from_text(new).portal_key)
    assert (len(document.credentials), resealed) == (1, False)


def test_run_shares_one_login_service(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Every surface uses the one service run builds, so the pending logins and their limit are
    shared (M5 design H.2)."""
    built: list[LoginService] = []
    seen: dict[str, Any] = {}

    class Recorded(LoginService):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            built.append(self)

    async def serve(app: VaultApp, listens: list[str], **kwargs: Any) -> None:
        seen.update(app=app, **kwargs)
        await app.aclose()

    monkeypatch.setattr(server, "LoginService", Recorded)
    monkeypatch.setattr(server, "acquire_state_lock", lambda state_dir: None)
    monkeypatch.setattr(server, "socket_supported", lambda: True)
    monkeypatch.setattr(server, "check_socket_dir", lambda path: None)
    monkeypatch.setattr(server, "serve", serve)
    server.run(str(EXAMPLE_POLICY), ["127.0.0.1:0"], tmp_path, env(), tmp_path / "admin.sock")
    [login] = built
    assert seen["admin"]._login is login
    assert login._tokens is seen["app"].tokens


# --- the gateway key ratchet (M3 design C.2) -----------------------------------------------------


def _policy_file(
    tmp_path: Path, example_text: str, generation: int, proxy: str | None = None
) -> str:
    path = tmp_path / f"gen-{generation}{'-proxy' if proxy else ''}.yaml"
    text = _with_proxy(example_text, proxy)
    path.write_bytes(
        text.replace("gateway_key_generation: 1", f"gateway_key_generation: {generation}").encode()
    )
    return str(path)


def test_load_runtime_starts_the_ratchet(tmp_path: Path) -> None:
    runtime = load_runtime(str(EXAMPLE_POLICY), tmp_path, env())
    assert runtime.gateway_keys.state == State(runtime.keys.key_id, 1, 1)
    assert (tmp_path / STATE_FILE).is_file()


def test_load_runtime_refuses_a_tampered_ratchet(tmp_path: Path) -> None:
    environ = env()
    load_runtime(str(EXAMPLE_POLICY), tmp_path, environ)
    path = tmp_path / STATE_FILE
    path.write_bytes(path.read_bytes().replace(b'"floor":1', b'"floor":2'))
    with pytest.raises(StartupError) as caught:
        load_runtime(str(EXAMPLE_POLICY), tmp_path, environ)
    assert str(caught.value) == f"{path}: {TAMPERED}"


def test_load_runtime_refuses_a_generation_that_went_backwards(
    tmp_path: Path, example_text: str
) -> None:
    environ = env()
    load_runtime(_policy_file(tmp_path, example_text, 3), tmp_path, environ)
    with pytest.raises(StartupError) as caught:
        load_runtime(str(EXAMPLE_POLICY), tmp_path, environ)
    assert str(caught.value) == (
        f"{tmp_path / STATE_FILE}: gateway_key_generation 1 is below 3: {BACKWARDS}"
    )


def test_load_runtime_reads_the_ratchet_under_the_previous_master(tmp_path: Path) -> None:
    old = generate_master_key()
    first = load_runtime(str(EXAMPLE_POLICY), tmp_path, {"ZOEYMCP_MASTER_KEY": old})
    old_keys = first.keys
    assert (tmp_path / STATE_FILE).is_file()
    new = generate_master_key()
    with pytest.raises(StartupError, match="ZOEYMCP_MASTER_KEY_PREVIOUS"):
        load_runtime(str(EXAMPLE_POLICY), tmp_path, {"ZOEYMCP_MASTER_KEY": new})
    environ = {"ZOEYMCP_MASTER_KEY": new, "ZOEYMCP_MASTER_KEY_PREVIOUS": old}
    rotated = load_runtime(str(EXAMPLE_POLICY), tmp_path, environ)
    previous = rotated.gateway_keys.state.previous
    assert previous is not None
    assert previous.key_id == old_keys.key_id
    assert rotated.gateway_keys.authenticate(old_keys.gateway_key(1).encode()) is True


def _gateway_status(app: VaultApp, key: str) -> int:
    """A gateway-only route of the example. Its connector answers 200 once identity passed."""

    async def call() -> int:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://vault") as client:
            response = await client.get("/mail/config", headers={GATEWAY_HEADER: key})
            return response.status_code

    return asyncio.run(call())


def test_a_reload_starts_a_rotation(
    tmp_path: Path, example_text: str, log_buffer: io.StringIO
) -> None:
    environ = env()
    runtime = load_runtime(str(EXAMPLE_POLICY), tmp_path / "state", environ)
    app = VaultApp(
        runtime.policy, runtime.store, runtime.keys, environ={}, gateway_keys=runtime.gateway_keys
    )
    server.reload_policy(app, _policy_file(tmp_path, example_text, 2), environ)
    assert [line["event"] for line in _log_lines(log_buffer)][-2:] == [
        "gateway_key_rotation_started",
        "reload_ok",
    ]
    assert app.policy.gateway_key_generation == 2
    keys = runtime.keys
    assert _gateway_status(app, keys.gateway_key(1)) == 200
    assert _gateway_status(app, keys.gateway_key(2)) == 200
    assert _gateway_status(app, keys.gateway_key(1)) == 403
    asyncio.run(app.aclose())

    # The effect test (design §8.2): a retired generation stays retired across a restart.
    restarted = load_runtime(_policy_file(tmp_path, example_text, 2), tmp_path / "state", environ)
    app = VaultApp(
        restarted.policy,
        restarted.store,
        restarted.keys,
        environ={},
        gateway_keys=restarted.gateway_keys,
    )
    assert _gateway_status(app, keys.gateway_key(1)) == 403
    assert _gateway_status(app, keys.gateway_key(2)) == 200
    asyncio.run(app.aclose())


def test_a_reload_that_goes_backwards_is_refused(
    tmp_path: Path, example_text: str, log_buffer: io.StringIO
) -> None:
    environ = env()
    runtime = load_runtime(_policy_file(tmp_path, example_text, 2), tmp_path / "state", environ)
    app = VaultApp(
        runtime.policy, runtime.store, runtime.keys, environ={}, gateway_keys=runtime.gateway_keys
    )
    before = app.policy
    # The egress proxy changes too: a refused reload doesn't say it needs a restart.
    server.reload_policy(app, _policy_file(tmp_path, example_text, 1, PROXY), environ)
    line = _log_lines(log_buffer)[-1]
    assert line["event"] == "reload_refused"
    assert line["reason"] == f"gateway_key_generation 1 is below 2: {BACKWARDS}"
    events = [line["event"] for line in _log_lines(log_buffer)]
    assert "egress_proxy_change_needs_restart" not in events
    assert app.policy is before
    asyncio.run(app.aclose())


PROXY = "http://proxy:3128"


def test_a_bump_that_cant_be_written_is_refused(
    tmp_path: Path,
    example_text: str,
    log_buffer: io.StringIO,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environ = env()
    runtime = load_runtime(_policy_file(tmp_path, example_text, 1), tmp_path / "state", environ)
    app = VaultApp(
        runtime.policy, runtime.store, runtime.keys, environ={}, gateway_keys=runtime.gateway_keys
    )
    before = app.policy

    def broken(path: Path, data: bytes) -> None:
        raise OSError("read-only")

    monkeypatch.setattr(gatewaykeys, "write_atomic", broken)
    server.reload_policy(app, _policy_file(tmp_path, example_text, 2, PROXY), environ)
    events = [line["event"] for line in _log_lines(log_buffer)]
    assert events[-1] == "reload_refused"
    assert "egress_proxy_change_needs_restart" not in events
    assert "so the new generation can't be used: read-only" in _log_lines(log_buffer)[-1]["reason"]
    assert app.policy is before
    assert _gateway_status(app, runtime.keys.gateway_key(2)) == 403
    asyncio.run(app.aclose())


def test_the_gateway_key_timer_ticks() -> None:
    ticks: list[int] = []

    class Ratchet:
        def tick(self) -> None:
            ticks.append(1)

    async def main() -> None:
        timer = asyncio.create_task(
            server.gateway_key_timer(cast(gatewaykeys.GatewayKeys, Ratchet()), 0)
        )
        while len(ticks) < 3:
            await asyncio.sleep(0)
        timer.cancel()

    asyncio.run(main())
    assert len(ticks) >= 3
    assert server.GATEWAY_KEY_TICK == 5.0


def test_serve_runs_and_stops_the_gateway_key_timer(
    log_buffer: io.StringIO, monkeypatch: pytest.MonkeyPatch
) -> None:
    class App:
        async def aclose(self) -> None:
            pass

    ratchet = gatewaykeys.GatewayKeys.in_memory(KeySet.from_text(generate_master_key()), 1)
    calls: list[tuple[Any, float]] = []
    cancelled: list[bool] = []

    async def main() -> list[asyncio.Task[Any]]:
        running = asyncio.Event()

        async def timer(gateway_keys: Any, interval: float) -> None:
            calls.append((gateway_keys, interval))
            running.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                cancelled.append(True)
                raise

        class Server:
            """Serves until the timer runs."""

            def __init__(self, config: Any) -> None:
                pass

            async def serve(self, sockets: list[socket.socket] | None = None) -> None:
                await running.wait()

        monkeypatch.setattr(server, "gateway_key_timer", timer)
        monkeypatch.setattr(server, "_Server", Server)
        await server.serve(
            cast(VaultApp, App()),
            ["127.0.0.1:0"],
            config=None,
            environ={},
            gateway_keys=ratchet,
            binder=lambda host, port: [],  # binds nothing
        )
        return [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]

    assert asyncio.run(main()) == []
    assert calls == [(ratchet, 5.0)]
    assert cancelled == [True]
    assert _log_lines(log_buffer)[-1]["event"] == "vault_stopped"


def test_serve_without_a_ratchet_has_no_timer(monkeypatch: pytest.MonkeyPatch) -> None:
    class App:
        async def aclose(self) -> None:
            pass

    calls: list[Any] = []
    monkeypatch.setattr(server, "gateway_key_timer", lambda *args: calls.append(args))
    asyncio.run(server.serve(cast(VaultApp, App()), [], config=None, environ={}))
    assert calls == []


def test_run_shares_the_ratchet(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    async def serve(app: VaultApp, listens: list[str], **kwargs: Any) -> None:
        seen.update(app=app, **kwargs)
        await app.aclose()

    monkeypatch.setattr(server, "acquire_state_lock", lambda state_dir: None)
    monkeypatch.setattr(server, "socket_supported", lambda: True)
    monkeypatch.setattr(server, "check_socket_dir", lambda path: None)
    monkeypatch.setattr(server, "serve", serve)
    server.run(str(EXAMPLE_POLICY), ["127.0.0.1:0"], tmp_path, env(), tmp_path / "admin.sock")
    ratchet = seen["app"].gateway_keys
    assert (tmp_path / STATE_FILE).is_file()
    assert seen["gateway_keys"] is ratchet
    assert seen["admin"]._gateway_keys is ratchet


def test_run_closes_unfinished_sends_before_serving(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A send cut by a SIGKILL is closed unknown before any listener opens (M4 design J.3)."""
    journal = tmp_path / "connectors" / "mail-out"
    journal.mkdir(parents=True)
    sending = {
        "ts": 1,
        "key": "key-0001-aaaaaaaaaaaa",
        "req_hmac": "hmac-sha256:" + "0" * 64,
        "key_id": "0" * 16,
        "subject_chars": 1,
        "body_chars": 1,
    }
    (journal / "journal-0000000000001.jsonl").write_bytes(sendjournal.encode("sending", **sending))
    kinds: list[list[str]] = []

    async def serve(app: VaultApp, listens: list[str], **kwargs: Any) -> None:
        lines = (journal / "journal-0000000000001.jsonl").read_bytes().splitlines()
        kinds.append([sendjournal.parse(line)["kind"] for line in lines])
        await app.aclose()

    monkeypatch.setattr(server, "acquire_state_lock", lambda state_dir: None)
    monkeypatch.setattr(server, "serve", serve)
    server.run(str(EXAMPLE_POLICY), ["127.0.0.1:0"], tmp_path, env(), None)
    assert kinds == [["sending", "unknown"]]


def test_run_stops_when_the_journal_cant_be_recovered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(self: SmtpConnectors, names: list[str]) -> dict[str, int]:
        raise OSError("read-only file system")

    monkeypatch.setattr(server, "acquire_state_lock", lambda state_dir: None)
    monkeypatch.setattr(SmtpConnectors, "recover", broken)
    with pytest.raises(StartupError, match="send journals"):
        server.run(str(EXAMPLE_POLICY), ["127.0.0.1:0"], tmp_path, env(), None)


def test_run_recovers_the_reported_copy_before_serving(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A torn tail is cut before any listener opens, and the proxy and the socket share the copy
    (M5 design J.4)."""
    copy = tmp_path / "ledger-reported"
    copy.mkdir()
    line = asked_line(0, GENESIS, 1)
    (copy / "000000000000.jsonl").write_bytes(line + b"\n" + b'{"v":1,"se')
    seen: dict[str, Any] = {}

    async def serve(app: VaultApp, listens: list[str], **kwargs: Any) -> None:
        seen.update(app=app, data=(copy / "000000000000.jsonl").read_bytes(), **kwargs)
        await app.aclose()

    monkeypatch.setattr(server, "acquire_state_lock", lambda state_dir: None)
    monkeypatch.setattr(server, "socket_supported", lambda: True)
    monkeypatch.setattr(server, "check_socket_dir", lambda path: None)
    monkeypatch.setattr(server, "serve", serve)
    server.run(str(EXAMPLE_POLICY), ["127.0.0.1:0"], tmp_path, env(), tmp_path / "admin.sock")
    assert seen["data"] == line + b"\n"
    reports = seen["app"].reports
    assert (reports.state, reports.held.head_seq) == ("ok", 0)
    assert seen["admin"]._reports is reports


def test_run_serves_with_an_unreadable_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, log_buffer: io.StringIO
) -> None:
    (tmp_path / "ledger-reported").write_bytes(b"not a directory")
    seen: list[str] = []

    async def serve(app: VaultApp, listens: list[str], **kwargs: Any) -> None:
        assert app.reports is not None
        seen.append(app.reports.state)
        await app.aclose()

    monkeypatch.setattr(server, "acquire_state_lock", lambda state_dir: None)
    monkeypatch.setattr(server, "serve", serve)
    server.run(str(EXAMPLE_POLICY), ["127.0.0.1:0"], tmp_path, env(), None)
    assert seen == ["unavailable"]
    assert '"event":"ledger_reported_unavailable"' in log_buffer.getvalue()


# --- the portal's listener (M5 design B.2-B.4) ----------------------------------------------------


def _portal_pieces(tmp_path: Path) -> dict[str, Any]:
    from zoeymcp.portal.passkeys import Passkeys

    keys = KeySet.from_text(generate_master_key())
    return {
        "setup": SetupCodes(tmp_path, keys.portal_key),
        "passkeys": Passkeys.load(tmp_path, keys.portal_key),
        "login": LoginService(cast(Any, None)),
    }


def _admin_policy(example_text: str, listen: str) -> Any:
    from zoeymcp.common.policy import parse_policy

    return parse_policy(example_text.replace("listen: 127.0.0.1:8081", f"listen: {listen}"), "t")


def _without_admin(example_text: str) -> str:
    lines = example_text.splitlines(keepends=True)
    start = lines.index("admin:\n")
    text = "".join(lines[:start] + lines[start + 4 :])
    assert "admin" not in text.split("credentials:")[0]
    return text


def test_no_admin_block_no_portal(tmp_path: Path, log_buffer: io.StringIO) -> None:
    from zoeymcp.common.policy import Policy

    policy = Policy.model_validate({"version": 1, "mode": "declarative"})
    assert server.build_portal(policy, [], **_portal_pieces(tmp_path)) is None
    assert [line["event"] for line in _log_lines(log_buffer)][-1] == "portal_disabled"


def test_the_portal_shares_the_sockets_setup_codes_passkeys_and_logins(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}

    async def serve(app: VaultApp, listens: list[str], **kwargs: Any) -> None:
        seen.update(kwargs)
        await app.aclose()

    monkeypatch.setattr(server, "acquire_state_lock", lambda state_dir: None)
    monkeypatch.setattr(server, "socket_supported", lambda: True)
    monkeypatch.setattr(server, "check_socket_dir", lambda path: None)
    monkeypatch.setattr(server, "serve", serve)
    server.run(str(EXAMPLE_POLICY), ["127.0.0.1:8080"], tmp_path, env(), tmp_path / "admin.sock")
    portal, admin = seen["portal"], seen["admin"]
    assert portal.app.setup is admin._setup
    assert portal.app.passkeys is admin._passkeys
    assert portal.app.login is admin._login
    assert (portal.address.address, portal.address.port) == ("127.0.0.1", 8081)
    assert portal.app.origins == ("http://localhost:8081", "https://zoeymcp.tailnet.example")


def test_the_portal_is_built_without_the_socket_too(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}

    async def serve(app: VaultApp, listens: list[str], **kwargs: Any) -> None:
        seen.update(kwargs)
        await app.aclose()

    monkeypatch.setattr(server, "acquire_state_lock", lambda state_dir: None)
    monkeypatch.setattr(server, "socket_supported", lambda: False)
    monkeypatch.setattr(server, "serve", serve)
    server.run(str(EXAMPLE_POLICY), ["127.0.0.1:8080"], tmp_path, env(), None)
    assert seen["admin"] is None
    assert seen["portal"].app.setup.path == tmp_path / "setup.json"


@pytest.mark.parametrize(
    ("listen", "listens", "reason"),
    [
        ("127.0.0.1:8081", ["127.0.0.1:8081"], "is --listen 127.0.0.1:8081's address"),
        ("127.0.0.1:8080", ["0.0.0.0:8080", "[::]:8080"], "and --listen 0.0.0.0:8080 share"),
        ("0.0.0.0:8080", ["127.0.0.1:8080"], "and --listen 127.0.0.1:8080 share port 8080"),
    ],
)
def test_a_portal_on_the_proxys_address_is_refused(
    tmp_path: Path, example_text: str, listen: str, listens: list[str], reason: str
) -> None:
    policy = _admin_policy(example_text, listen)
    refused = f"^can't listen on {re.escape(listen)} for the portal: admin.listen "
    with pytest.raises(StartupError, match=refused + re.escape(f"{listen} {reason}")):
        server.build_portal(policy, listens, **_portal_pieces(tmp_path))


def test_a_wildcard_portal_beside_the_proxy_is_warned_about(
    tmp_path: Path, example_text: str, log_buffer: io.StringIO
) -> None:
    policy = _admin_policy(example_text, "0.0.0.0:8081")
    portal = server.build_portal(policy, ["127.0.0.1:8080"], **_portal_pieces(tmp_path))
    assert portal is not None
    assert portal.address.wildcard
    shared = [x for x in _log_lines(log_buffer) if x["event"] == "admin_listener_shared"]
    assert [(x["level"], x["listen"], x["proxy"]) for x in shared] == [
        ("warning", "0.0.0.0:8081", ["127.0.0.1:8080"])
    ]
    assert server.build_portal(policy, [], **_portal_pieces(tmp_path / "b")) is not None
    shared = [x for x in _log_lines(log_buffer) if x["event"] == "admin_listener_shared"]
    assert len(shared) == 1


def test_a_portal_name_must_resolve_to_one_address(tmp_path: Path, example_text: str) -> None:
    policy = _admin_policy(example_text, "vault-portal:8081")

    def two(host: str) -> list[str]:
        assert host == "vault-portal"
        return ["172.20.0.3", "172.21.0.3"]

    with pytest.raises(StartupError, match=r"^admin\.listen's name vault-portal resolves to 2 "):
        server.build_portal(policy, [], lookup=two, **_portal_pieces(tmp_path))
    portal = server.build_portal(
        policy, [], lookup=lambda host: ["172.20.0.3"], **_portal_pieces(tmp_path / "b")
    )
    assert portal is not None
    assert portal.bound == "172.20.0.3:8081"


def test_a_name_that_doesnt_resolve_yet_is_retried_for_ten_seconds() -> None:
    now = [0.0]
    slept: list[float] = []
    answers: list[list[str] | None] = [None, None, ["172.20.0.3"]]

    def lookup(host: str) -> list[str]:
        answer = answers.pop(0)
        if answer is None:
            raise socket.gaierror(-2, "Name or service not known")
        return answer

    def sleep(seconds: float) -> None:
        slept.append(seconds)
        now[0] += seconds

    found = server.resolve_admin_listen(
        "vault-portal:8081", lookup, sleep=sleep, clock=lambda: now[0]
    )
    assert (found.address, slept) == ("172.20.0.3", [0.5, 0.5])

    def never(host: str) -> list[str]:
        raise socket.gaierror(-2, "Name or service not known")

    slept.clear()
    now[0] = 0.0
    with pytest.raises(StartupError, match=r"^admin\.listen's name vault-portal doesn't resolve: "):
        server.resolve_admin_listen("vault-portal:8081", never, sleep=sleep, clock=lambda: now[0])
    assert len(slept) == 20
    assert now[0] == 10.0


def test_a_name_with_several_addresses_is_refused_at_once() -> None:
    slept: list[float] = []
    with pytest.raises(StartupError, match="resolves to 2 addresses"):
        server.resolve_admin_listen(
            "vault-portal:8081", lambda host: ["10.0.0.1", "10.0.0.2"], sleep=slept.append
        )
    assert slept == []


def test_the_real_lookup_answers_a_literal() -> None:
    assert set(server.lookup_addresses("127.0.0.1")) == {"127.0.0.1"}


def test_a_missing_static_file_stops_the_start(
    tmp_path: Path, example_text: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from zoeymcp.portal import app as portal_app

    static = tmp_path / "static"
    static.mkdir(mode=0o700)
    for name in ("index.html", "app.js", "app.css"):
        (static / name).write_bytes(b"")
    monkeypatch.setattr(server, "load_static", lambda: portal_app.load_static(static))
    policy = _admin_policy(example_text, "127.0.0.1:8081")
    with pytest.raises(
        StartupError, match=r"^the portal's static file webauthn\.js can't be read$"
    ):
        server.build_portal(policy, [], **_portal_pieces(tmp_path))


def test_the_packaged_static_files_load() -> None:
    from zoeymcp.portal.app import load_static
    from zoeymcp.portal.routes import STATIC

    loaded = load_static()
    assert set(loaded) == set(STATIC)
    assert loaded["/"].startswith(b"<!doctype html>")


def test_a_portal_address_in_use_is_a_startup_error(
    tmp_path: Path, example_text: str, monkeypatch: pytest.MonkeyPatch, log_buffer: io.StringIO
) -> None:
    bound: list[socket.socket] = []

    def binder(host: str, port: int) -> list[socket.socket]:
        sockets = server.bind_tcp(host, port)
        bound.extend(sockets)
        return sockets

    def no_server(*args: Any) -> None:
        raise AssertionError("a server was built before every address was bound")

    class App:
        async def aclose(self) -> None:
            pass

    monkeypatch.setattr(server, "_Server", no_server)
    monkeypatch.setattr(server, "_PortalServer", no_server)
    with _occupied() as occupied:
        port = occupied.getsockname()[1]
        policy = _admin_policy(example_text, f"127.0.0.1:{port}")
        portal = server.build_portal(policy, ["127.0.0.1:0"], **_portal_pieces(tmp_path))
        refused = f"^can't listen on 127.0.0.1:{port} for the portal: {IN_USE}"
        with pytest.raises(StartupError, match=refused):
            asyncio.run(
                server.serve(
                    cast(VaultApp, App()),
                    ["127.0.0.1:0"],
                    config=None,
                    environ={},
                    portal=portal,
                    binder=binder,
                )
            )
    # The proxy's socket, bound first, is closed again, and the vault never started.
    assert len(bound) == 1
    assert bound[0].fileno() == -1
    assert "vault_started" not in log_buffer.getvalue()


def test_the_portal_bound_address_is_bracketed_for_ipv6() -> None:
    from zoeymcp.portal.listen import resolve

    portal = server.Portal(cast(Any, None), resolve("[::1]:8081", lambda host: []))
    assert portal.bound == "[::1]:8081"
    assert portal.header_deadline == 10.0


def test_a_reload_moves_the_origins_and_names_a_listen_change(
    tmp_path: Path, example_text: str, log_buffer: io.StringIO
) -> None:
    app = _app(tmp_path)
    portal = server.build_portal(app.policy, [], **_portal_pieces(tmp_path))
    assert portal is not None

    def reload(text: str) -> list[str]:
        path = tmp_path / "next.yaml"
        path.write_text(text, encoding="utf-8")
        start = len(_log_lines(log_buffer))
        server.reload_policy(app, str(path), env(), portal=portal)
        return [line["event"] for line in _log_lines(log_buffer)[start:]]

    fewer = example_text.replace(", https://zoeymcp.tailnet.example]", "]")
    assert reload(fewer) == ["reload_ok"]
    assert portal.app.origins == ("http://localhost:8081",)
    moved = fewer.replace("listen: 127.0.0.1:8081", "listen: 127.0.0.1:8082")
    assert reload(moved) == ["admin_listen_change_needs_restart", "reload_ok"]
    # Removed: the listener stays, with the origins it had, until a restart.
    assert reload(_without_admin(example_text)) == [
        "admin_listen_change_needs_restart",
        "reload_ok",
    ]
    assert portal.app.origins == ("http://localhost:8081",)
    asyncio.run(app.aclose())


def test_a_reload_without_a_portal_names_an_added_block(
    tmp_path: Path, example_text: str, log_buffer: io.StringIO
) -> None:
    without = tmp_path / "without.yaml"
    without.write_text(_without_admin(example_text), encoding="utf-8")
    runtime = load_runtime(str(without), tmp_path / "state", env())
    app = VaultApp(runtime.policy, runtime.store, runtime.keys, environ={})
    server.reload_policy(app, str(without), env())
    assert "admin_listen_change_needs_restart" not in log_buffer.getvalue()
    added = tmp_path / "added.yaml"
    added.write_text(example_text, encoding="utf-8")
    server.reload_policy(app, str(added), env())
    events = [line["event"] for line in _log_lines(log_buffer)]
    assert events[-2:] == ["admin_listen_change_needs_restart", "reload_ok"]
    asyncio.run(app.aclose())
