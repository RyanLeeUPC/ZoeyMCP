from __future__ import annotations

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
from typing import Any

import pytest

from zoeymcp.vault import logs, server
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
