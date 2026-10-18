from __future__ import annotations

import asyncio
import errno
import io
import json
import os
import re
import stat
import sys
import types
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

import httpx
import pytest

from zoeymcp.vault import gatewaykeys, logs, server
from zoeymcp.vault.app import GATEWAY_HEADER, VaultApp
from zoeymcp.vault.gatewaykeys import BACKWARDS, STATE_FILE, TAMPERED, State
from zoeymcp.vault.keys import KeySet, generate_master_key
from zoeymcp.vault.server import LOCK_FILE, StartupError, acquire_state_lock, load_runtime
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
    first.write_text(_with_proxy(example_text, before), encoding="utf-8")
    runtime = load_runtime(str(first), tmp_path / "state", env())
    app = VaultApp(runtime.policy, runtime.store, runtime.keys, environ={})
    assert app.policy.egress_proxy == before
    second = tmp_path / "second.yaml"
    second.write_text(_with_proxy(example_text, after), encoding="utf-8")
    server.reload_policy(app, str(second), env())
    events = [line["event"] for line in _log_lines(log_buffer)]
    assert events[-1] == "reload_ok"
    assert ("egress_proxy_change_needs_restart" in events) is restart
    if restart:
        assert events[-2] == "egress_proxy_change_needs_restart"
    assert app.policy.egress_proxy == after
    asyncio.run(app.aclose())


def test_serve_closes_the_app_on_the_way_out(log_buffer: io.StringIO) -> None:
    calls: list[str] = []

    class App:
        async def aclose(self) -> None:
            calls.append("aclose")

    asyncio.run(server.serve(cast(VaultApp, App()), [], config=None, environ={}))
    assert calls == ["aclose"]
    assert _log_lines(log_buffer)[-1]["event"] == "vault_stopped"


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
    """A gateway-only route of the example. Its connector answers 501 once identity passed."""

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
    assert _gateway_status(app, keys.gateway_key(1)) == 501
    assert _gateway_status(app, keys.gateway_key(2)) == 501
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
    assert _gateway_status(app, keys.gateway_key(2)) == 501
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

            async def serve(self) -> None:
                await running.wait()

        monkeypatch.setattr(server, "gateway_key_timer", timer)
        monkeypatch.setattr(server, "_Server", Server)
        await server.serve(
            cast(VaultApp, App()),
            ["127.0.0.1:0"],
            config=None,
            environ={},
            gateway_keys=ratchet,
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
