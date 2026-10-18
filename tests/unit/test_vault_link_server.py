"""Running the vault with the link socket and the launcher's control pipe (M3 design B.2, C.1).

The option checks, the control reader and the wiring in ``serve`` and ``run`` run everywhere with
fakes. The real socket, peer check and pipe run on Linux only.
"""

from __future__ import annotations

import asyncio
import errno
import io
import json
import os
import shutil
import socket
import stat
import sys
import tempfile
import types
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, ClassVar, cast

import httpx
import pytest
from uvicorn.protocols.http.h11_impl import H11Protocol
from uvicorn.server import ServerState

from zoeymcp.cli.main import EXIT_OK, EXIT_UNREADABLE, main
from zoeymcp.vault import logs, server
from zoeymcp.vault.app import VaultApp
from zoeymcp.vault.keys import generate_master_key
from zoeymcp.vault.peer import UCRED
from zoeymcp.vault.server import (
    CONTROL_LINE_LIMIT,
    ListenerTag,
    StartupError,
    check_control_fd,
    check_link_dir,
    check_link_options,
    load_runtime,
    read_control,
)

from .conftest import EXAMPLE_POLICY
from .test_peer import LINUX_SO_PEERCRED, FakeSocket, FakeTransport

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")
linux_only = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="SO_PEERCRED")


def my_uid() -> int:
    """The test's own uid (the POSIX tests only)."""
    if sys.platform != "win32":
        return os.getuid()
    raise AssertionError("not on Windows")


def env() -> dict[str, str]:
    return {"ZOEYMCP_MASTER_KEY": generate_master_key()}


@pytest.fixture
def log_buffer() -> Iterator[io.StringIO]:
    buffer = io.StringIO()
    logs.set_stream(buffer)
    try:
        yield buffer
    finally:
        logs.set_stream(None)


def log_lines(buffer: io.StringIO) -> list[dict[str, Any]]:
    lines = [json.loads(line) for line in buffer.getvalue().splitlines()]
    for line in lines:
        del line["ts"]
    return lines


@pytest.fixture
def linux(monkeypatch: pytest.MonkeyPatch) -> None:
    """Makes the link look supported, as on Linux."""
    monkeypatch.setattr(server, "link_supported", lambda: True)


# --- the options -------------------------------------------------------------------------------


SOCK = Path("/run/zoeymcp-link/vault.sock")


@pytest.mark.parametrize(
    ("listens", "path", "uid"),
    [
        (["0.0.0.0:8080"], None, None),
        (["0.0.0.0:8080", "127.0.0.1:8081"], None, None),
        (["0.0.0.0:8080"], SOCK, 10002),
        ([], SOCK, 10002),
        ([], SOCK, 0),
    ],
)
def test_link_options_that_work(
    linux: None, listens: list[str], path: Path | None, uid: int | None
) -> None:
    check_link_options(listens, path, uid)


@pytest.mark.parametrize(
    ("listens", "path", "uid", "message"),
    [
        (["0.0.0.0:8080"], SOCK, None, "--gateway-socket and --gateway-uid go together"),
        (["0.0.0.0:8080"], None, 10002, "--gateway-socket and --gateway-uid go together"),
        ([], None, 10002, "--gateway-socket and --gateway-uid go together"),
        ([], SOCK, -1, "--gateway-uid must be a uid (0 or more)"),
        ([], None, None, "--listen none leaves nothing to serve; it needs --gateway-socket"),
    ],
)
def test_link_options_refused(
    linux: None, listens: list[str], path: Path | None, uid: int | None, message: str
) -> None:
    with pytest.raises(StartupError) as caught:
        check_link_options(listens, path, uid)
    assert str(caught.value) == message


def test_the_link_needs_so_peercred(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server, "link_supported", lambda: False)
    with pytest.raises(StartupError) as caught:
        check_link_options(["0.0.0.0:8080"], SOCK, 10002)
    assert str(caught.value) == "--gateway-socket needs Linux (SO_PEERCRED)"
    check_link_options(["0.0.0.0:8080"], None, None)


# --- the control descriptor --------------------------------------------------------------------


@pytest.fixture
def posix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server, "sys", types.SimpleNamespace(platform="linux"))


def test_control_fd_needs_posix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server, "sys", types.SimpleNamespace(platform="win32"))
    read, write = os.pipe()
    try:
        with pytest.raises(StartupError) as caught:
            check_control_fd(read)
        assert str(caught.value) == "--control-fd needs a POSIX platform"
    finally:
        os.close(read)
        os.close(write)


@posix_only
def test_control_fd_must_be_the_read_end(posix: None) -> None:
    read, write = os.pipe()
    try:
        check_control_fd(read)
        with pytest.raises(StartupError) as caught:
            check_control_fd(write)
        assert str(caught.value) == f"--control-fd {write} is not open for reading"
    finally:
        os.close(read)
        os.close(write)


@linux_only
def test_control_fd_accepts_a_socket(posix: None) -> None:
    left, right = socket.socketpair()
    with left, right:
        check_control_fd(left.fileno())


def test_control_fd_must_be_open(posix: None) -> None:
    # Far above anything a test opens, so no other thread can have it.
    fd = 999_999
    with pytest.raises(StartupError) as caught:
        check_control_fd(fd)
    assert str(caught.value).startswith(f"--control-fd {fd} is not open: ")


def test_control_fd_must_be_a_pipe(posix: None, tmp_path: Path) -> None:
    fd = os.open(tmp_path / "plain", os.O_RDWR | os.O_CREAT)
    try:
        with pytest.raises(StartupError) as caught:
            check_control_fd(fd)
        assert str(caught.value) == f"--control-fd {fd} is not a pipe"
    finally:
        os.close(fd)


# --- the link directory ------------------------------------------------------------------------


@pytest.fixture
def socket_dir() -> Iterator[Path]:
    # Short path: AF_UNIX paths are limited to about 100 bytes.
    path = Path(tempfile.mkdtemp(prefix="zm-", dir="/tmp"))
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def stale_socket(path: Path) -> None:
    """Leaves a socket file at ``path`` that nothing listens on, as a killed vault does."""
    sock = socket.socket(getattr(socket, "AF_UNIX"))  # noqa: B009 - absent on Windows
    with sock:
        sock.bind(str(path))
    assert stat.S_ISSOCK(path.lstat().st_mode)


@posix_only
@pytest.mark.parametrize("mode", [0o700, 0o750, 0o770])
def test_link_dir_accepted(socket_dir: Path, mode: int) -> None:
    os.chmod(socket_dir, mode)
    path = socket_dir / "vault.sock"
    check_link_dir(path)  # nothing to remove is fine
    assert sorted(socket_dir.iterdir()) == []


@posix_only
def test_a_stale_socket_is_removed(socket_dir: Path) -> None:
    os.chmod(socket_dir, 0o750)  # noqa: S103 - the link directory's mode in the image
    path = socket_dir / "vault.sock"
    stale_socket(path)
    check_link_dir(path)
    assert not os.path.lexists(path)


@posix_only
@pytest.mark.parametrize("kind", ["file", "directory", "symlink", "symlink to a socket"])
def test_anything_but_a_socket_is_refused_and_kept(socket_dir: Path, kind: str) -> None:
    os.chmod(socket_dir, 0o750)  # noqa: S103 - the link directory's mode in the image
    path = socket_dir / "vault.sock"
    if kind == "file":
        path.write_bytes(b"{}")
    elif kind == "directory":
        path.mkdir()
    elif kind == "symlink":
        (socket_dir / "store.json").write_bytes(b"{}")
        path.symlink_to(socket_dir / "store.json")
    else:
        stale_socket(socket_dir / "other.sock")
        path.symlink_to(socket_dir / "other.sock")
    with pytest.raises(StartupError) as caught:
        check_link_dir(path)
    assert str(caught.value) == f"{path} exists and is not a socket"
    assert os.path.lexists(path)
    if kind == "file":
        assert path.read_bytes() == b"{}"
    if kind.startswith("symlink"):
        assert path.is_symlink()
        assert os.path.lexists(os.readlink(path))


@posix_only
def test_a_stale_socket_that_cant_be_removed_is_refused(
    socket_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    os.chmod(socket_dir, 0o750)  # noqa: S103 - the link directory's mode in the image
    path = socket_dir / "vault.sock"
    stale_socket(path)

    def unlink(self: Path, missing_ok: bool = False) -> None:
        raise PermissionError(errno.EACCES, "Permission denied")

    monkeypatch.setattr(Path, "unlink", unlink)
    with pytest.raises(StartupError) as caught:
        check_link_dir(path)
    assert str(caught.value) == (
        f"can't remove the stale gateway socket {path}: [Errno 13] Permission denied"
    )


@posix_only
def test_a_stale_socket_that_vanishes_is_fine(
    socket_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    os.chmod(socket_dir, 0o750)  # noqa: S103 - the link directory's mode in the image
    path = socket_dir / "vault.sock"
    stale_socket(path)

    def unlink(self: Path, missing_ok: bool = False) -> None:
        raise FileNotFoundError(errno.ENOENT, "No such file or directory")

    monkeypatch.setattr(Path, "unlink", unlink)
    check_link_dir(path)


@posix_only
def test_a_path_that_cant_be_checked_is_refused(
    socket_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    os.chmod(socket_dir, 0o750)  # noqa: S103 - the link directory's mode in the image
    path = socket_dir / "vault.sock"

    def lstat(self: Path) -> os.stat_result:
        raise PermissionError(errno.EACCES, "Permission denied")

    monkeypatch.setattr(Path, "lstat", lstat)
    with pytest.raises(StartupError) as caught:
        check_link_dir(path)
    assert str(caught.value) == (
        f"can't check {path} for a stale gateway socket: [Errno 13] Permission denied"
    )


@posix_only
def test_link_dir_created(socket_dir: Path) -> None:
    path = socket_dir / "a" / "b" / "vault.sock"
    old = os.umask(0o022)
    try:
        check_link_dir(path)
    finally:
        os.umask(old)
    assert (socket_dir / "a").is_dir()
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o750
    assert not os.path.lexists(path)


@posix_only
@pytest.mark.parametrize("mode", [0o701, 0o702, 0o704, 0o751, 0o757, 0o772])
def test_link_dir_open_to_others_refused(socket_dir: Path, mode: int) -> None:
    os.chmod(socket_dir, mode)
    with pytest.raises(StartupError) as caught:
        check_link_dir(socket_dir / "vault.sock")
    assert str(caught.value) == f"{socket_dir} must not be accessible to others (0750)"


@posix_only
def test_link_dir_owned_by_another_uid_refused(
    socket_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    os.chmod(socket_dir, 0o750)  # noqa: S103 - the link directory's mode in the image
    other = my_uid() + 1
    monkeypatch.setattr(os, "getuid", lambda: other)
    with pytest.raises(StartupError) as caught:
        check_link_dir(socket_dir / "vault.sock")
    assert str(caught.value) == f"{socket_dir} must be owned by the vault's uid {other}"


def test_link_dir_that_is_a_file_refused(tmp_path: Path) -> None:
    blocker = tmp_path / "file"
    blocker.write_bytes(b"x")
    with pytest.raises(StartupError) as caught:
        check_link_dir(blocker / "vault.sock")
    assert str(caught.value).startswith(f"can't use {blocker} for the gateway socket: ")


# --- the control reader ------------------------------------------------------------------------


class Calls:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def reload(self) -> None:
        self.calls.append("reload")

    def stop(self) -> None:
        self.calls.append("stop")


def _read(data: bytes, *, eof: bool = True) -> list[str]:
    calls = Calls()

    async def main() -> None:
        reader = asyncio.StreamReader(limit=CONTROL_LINE_LIMIT)
        reader.feed_data(data)
        if eof:
            reader.feed_eof()
            await read_control(reader, reload=calls.reload, stop=calls.stop)
            return
        task = asyncio.create_task(read_control(reader, reload=calls.reload, stop=calls.stop))
        for _ in range(20):
            await asyncio.sleep(0)
        assert not task.done()
        task.cancel()

    asyncio.run(main())
    return calls.calls


def test_control_commands(log_buffer: io.StringIO) -> None:
    assert _read(b"HUP\nTERM\n", eof=False) == ["reload", "stop"]
    assert log_lines(log_buffer) == [
        {"role": "vault", "event": "control_received", "command": "HUP"},
        {"role": "vault", "event": "control_received", "command": "TERM"},
    ]


def test_control_eof_stops(log_buffer: io.StringIO) -> None:
    assert _read(b"") == ["stop"]
    assert log_lines(log_buffer) == [
        {"role": "vault", "event": "control_received", "command": "EOF"}
    ]


def test_control_whitespace_and_a_last_line_without_newline() -> None:
    assert _read(b"  HUP \r\nHUP\nTERM") == ["reload", "reload", "stop", "stop"]


@pytest.mark.parametrize("line", [b"hup\n", b"KILL\n", b"HUPTERM\n", b"\n", b"H UP\n"])
def test_control_ignores_other_lines(log_buffer: io.StringIO, line: bytes) -> None:
    assert _read(line + b"HUP\n") == ["reload", "stop"]
    assert log_lines(log_buffer)[0] == {
        "role": "vault",
        "event": "control_ignored",
        "bytes": len(line),
    }


def test_control_survives_an_overlong_line(log_buffer: io.StringIO) -> None:
    assert CONTROL_LINE_LIMIT == 1024
    assert _read(b"x" * 5000 + b"\nTERM\n") == ["stop", "stop"]
    lines = log_lines(log_buffer)
    assert lines[0] == {"role": "vault", "event": "control_ignored", "bytes": 1024}
    assert lines[-2:] == [
        {"role": "vault", "event": "control_received", "command": "TERM"},
        {"role": "vault", "event": "control_received", "command": "EOF"},
    ]


def test_an_overlong_line_in_pieces(log_buffer: io.StringIO) -> None:
    # Pinned (see read_control): the part past the limit is read as the next line.
    calls = Calls()

    async def main() -> None:
        reader = asyncio.StreamReader(limit=CONTROL_LINE_LIMIT)
        task = asyncio.create_task(read_control(reader, reload=calls.reload, stop=calls.stop))
        reader.feed_data(b"x" * 1100)
        for _ in range(20):
            await asyncio.sleep(0)
        assert calls.calls == []
        reader.feed_data(b"yHUP\nHUP\nTERM\n")
        for _ in range(20):
            await asyncio.sleep(0)
        assert not task.done()
        task.cancel()

    asyncio.run(main())
    assert calls.calls == ["reload", "stop"]
    assert log_lines(log_buffer) == [
        {"role": "vault", "event": "control_ignored", "bytes": 1024},
        {"role": "vault", "event": "control_ignored", "bytes": 5},
        {"role": "vault", "event": "control_received", "command": "HUP"},
        {"role": "vault", "event": "control_received", "command": "TERM"},
    ]


def test_a_control_read_error_stops(log_buffer: io.StringIO) -> None:
    calls = Calls()

    async def main() -> None:
        reader = asyncio.StreamReader(limit=CONTROL_LINE_LIMIT)
        reader.feed_data(b"HUP\n")
        reader.set_exception(OSError(errno.EBADF, "Bad file descriptor"))
        await asyncio.wait_for(read_control(reader, reload=calls.reload, stop=calls.stop), 10)

    asyncio.run(main())
    assert calls.calls == ["stop"]
    assert log_lines(log_buffer) == [
        {"role": "vault", "event": "control_failed", "error_type": "OSError"}
    ]


@posix_only
def test_the_real_control_pipe_keeps_the_line_limit(log_buffer: io.StringIO) -> None:
    calls = Calls()
    read, write = os.pipe()
    os.write(write, b"x" * 2000 + b"\nHUP\n")
    os.close(write)

    async def main() -> None:
        reader, transport = await server.open_control(read)
        await asyncio.wait_for(read_control(reader, reload=calls.reload, stop=calls.stop), 10)
        transport.close()
        for _ in range(20):
            await asyncio.sleep(0)
        with pytest.raises(OSError, match=rf"^\[Errno {errno.EBADF}\] "):
            os.fstat(read)

    asyncio.run(main())
    assert calls.calls == ["reload", "stop"]
    assert log_lines(log_buffer) == [
        {"role": "vault", "event": "control_ignored", "bytes": 1024},
        {"role": "vault", "event": "control_received", "command": "HUP"},
        {"role": "vault", "event": "control_received", "command": "EOF"},
    ]


def test_control_command_words() -> None:
    assert (server.CONTROL_RELOAD, server.CONTROL_STOP) == (b"HUP", b"TERM")


# --- serve -------------------------------------------------------------------------------------


class _App:
    async def aclose(self) -> None:
        pass


async def _until(condition: Callable[[], object], what: str) -> None:
    """Waits up to 10 seconds for ``condition``, so a broken test fails instead of hanging."""
    for _ in range(1000):
        if condition():
            return
        await asyncio.sleep(0.01)
    raise AssertionError(what)


class FakeServer:
    """Serves until told to exit, and keeps its config."""

    made: ClassVar[list[FakeServer]] = []

    def __init__(self, config: Any) -> None:
        self.config = config
        self.should_exit = False
        FakeServer.made.append(self)

    async def serve(self) -> None:
        while not self.should_exit:
            await asyncio.sleep(0.001)


@pytest.fixture
def fake_servers(monkeypatch: pytest.MonkeyPatch) -> list[FakeServer]:
    FakeServer.made = []
    monkeypatch.setattr(server, "_Server", FakeServer)
    return FakeServer.made


class FakePipe:
    def __init__(self) -> None:
        self.closed = 0

    def close(self) -> None:
        self.closed += 1


def _serve_with_control(
    monkeypatch: pytest.MonkeyPatch, feed: Callable[[asyncio.StreamReader], Any]
) -> tuple[list[Any], FakePipe]:
    pipe = FakePipe()
    reloads: list[Any] = []
    opened: list[int] = []

    async def open_control(fd: int) -> tuple[asyncio.StreamReader, FakePipe]:
        opened.append(fd)
        reader = asyncio.StreamReader()
        asyncio.get_running_loop().call_later(0.01, feed, reader)
        return reader, pipe

    monkeypatch.setattr(server, "open_control", open_control)
    monkeypatch.setattr(server, "reload_policy", lambda *args: reloads.append(args))

    async def main() -> list[asyncio.Task[Any]]:
        await server.serve(
            cast(VaultApp, app), ["127.0.0.1:0"], config="p.yaml", environ={"A": "1"}, control_fd=7
        )
        return [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]

    app = _App()
    assert asyncio.run(main()) == []
    assert opened == [7]
    return [(a is app, c, e) for a, c, e in reloads], pipe


def test_serve_reloads_and_stops_on_the_control_pipe(
    monkeypatch: pytest.MonkeyPatch, fake_servers: list[FakeServer]
) -> None:
    reloads, pipe = _serve_with_control(
        monkeypatch, lambda reader: reader.feed_data(b"HUP\nHUP\nTERM\n")
    )
    assert reloads == [(True, "p.yaml", {"A": "1"})] * 2
    assert pipe.closed == 1
    assert [s.should_exit for s in fake_servers] == [True]


def test_serve_stops_when_the_control_pipe_fails(
    monkeypatch: pytest.MonkeyPatch, fake_servers: list[FakeServer], log_buffer: io.StringIO
) -> None:
    reloads, pipe = _serve_with_control(
        monkeypatch, lambda reader: reader.set_exception(OSError(errno.EIO, "I/O error"))
    )
    assert reloads == []
    assert pipe.closed == 1
    assert [s.should_exit for s in fake_servers] == [True]
    events = [line["event"] for line in log_lines(log_buffer)]
    assert events == ["vault_started", "control_failed", "vault_stopped"]


def test_serve_stops_at_the_end_of_the_control_pipe(
    monkeypatch: pytest.MonkeyPatch, fake_servers: list[FakeServer], log_buffer: io.StringIO
) -> None:
    reloads, pipe = _serve_with_control(monkeypatch, lambda reader: reader.feed_eof())
    assert reloads == []
    assert pipe.closed == 1
    events = [line["event"] for line in log_lines(log_buffer)]
    assert events == ["vault_started", "control_received", "vault_stopped"]


def test_serve_listens_on_the_link(
    fake_servers: list[FakeServer], log_buffer: io.StringIO, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(socket, "SO_PEERCRED", LINUX_SO_PEERCRED, raising=False)

    async def main() -> None:
        app = _App()
        task = asyncio.create_task(
            server.serve(
                cast(VaultApp, app),
                ["127.0.0.1:8080"],
                config=None,
                environ={},
                gateway_socket=Path("/run/zoeymcp-link/vault.sock"),
                gateway_uid=10002,
            )
        )
        await _until(
            lambda: len(fake_servers) >= 2 and "gateway_socket_listening" in log_buffer.getvalue(),
            "serve never started both listeners",
        )
        tcp, link = fake_servers
        assert isinstance(tcp.config.app, ListenerTag)
        assert tcp.config.app.app is cast(Any, app)
        assert tcp.config.app.listener == "tcp"
        assert tcp.config.uds is None
        assert isinstance(link.config.app, ListenerTag)
        assert link.config.app.app is cast(Any, app)
        assert link.config.app.listener == "gateway"
        assert link.config.uds == str(Path("/run/zoeymcp-link/vault.sock"))
        assert issubclass(link.config.http, H11Protocol)
        assert link.config.http is not H11Protocol
        assert (link.config.server_header, link.config.date_header) == (False, False)
        assert (link.config.access_log, link.config.lifespan) == (False, "off")
        assert (link.config.proxy_headers, link.config.log_level) == (False, "warning")
        # The link's protocol admits exactly the configured gateway uid.
        loop = asyncio.get_running_loop()
        for uid, aborted in [(10002, 0), (10003, 1), (10001, 1)]:
            protocol = link.config.http(link.config, ServerState(), {}, _loop=loop)
            transport = FakeTransport(FakeSocket(UCRED.pack(99, uid, uid)))
            protocol.connection_made(transport)
            assert (uid, transport.aborted) == (uid, aborted)
            protocol.connection_lost(None)
        for each in fake_servers:
            each.should_exit = True
        await task

    asyncio.run(main())
    lines = log_lines(log_buffer)
    assert lines[1] == {
        "role": "vault",
        "event": "gateway_socket_listening",
        "path": str(Path("/run/zoeymcp-link/vault.sock")),
        "uid": 10002,
    }
    refused = [line for line in lines if line["event"] == "gateway_socket_refused"]
    assert [line["uid"] for line in refused] == [10003, 10001]


@pytest.mark.parametrize(
    ("path", "uid"), [(Path("/run/zoeymcp-link/vault.sock"), None), (None, 10002)]
)
def test_serve_needs_both_for_the_link(
    fake_servers: list[FakeServer], log_buffer: io.StringIO, path: Path | None, uid: int | None
) -> None:
    async def main() -> None:
        task = asyncio.create_task(
            server.serve(
                cast(VaultApp, _App()),
                ["127.0.0.1:8080"],
                config=None,
                environ={},
                gateway_socket=path,
                gateway_uid=uid,
            )
        )
        await _until(lambda: "vault_started" in log_buffer.getvalue(), "serve never started")
        for each in fake_servers:
            each.should_exit = True
        await task

    asyncio.run(main())
    assert [each.config.app.listener for each in fake_servers] == ["tcp"]
    assert "gateway_socket_listening" not in log_buffer.getvalue()


def test_serve_without_the_link_has_one_listener_each(
    fake_servers: list[FakeServer], log_buffer: io.StringIO
) -> None:
    async def main() -> None:
        task = asyncio.create_task(
            server.serve(cast(VaultApp, _App()), ["127.0.0.1:8080"], config=None, environ={})
        )
        await _until(lambda: fake_servers, "serve never started")
        fake_servers[0].should_exit = True
        await task

    asyncio.run(main())
    assert len(fake_servers) == 1
    assert fake_servers[0].config.app.listener == "tcp"
    assert "gateway_socket_listening" not in log_buffer.getvalue()


# --- run ---------------------------------------------------------------------------------------


@pytest.fixture
def captured_run(monkeypatch: pytest.MonkeyPatch, linux: None) -> dict[str, Any]:
    seen: dict[str, Any] = {"order": []}

    async def serve(app: VaultApp, listens: list[str], **kwargs: Any) -> None:
        seen.update(app=app, listens=listens, **kwargs)
        await app.aclose()

    monkeypatch.setattr(server, "acquire_state_lock", lambda d: seen["order"].append("lock"))
    monkeypatch.setattr(server, "check_link_dir", lambda p: seen["order"].append(("dir", p)))
    monkeypatch.setattr(server, "check_control_fd", lambda fd: seen["order"].append(("fd", fd)))
    monkeypatch.setattr(server, "serve", serve)
    return seen


def test_run_with_the_link(tmp_path: Path, captured_run: dict[str, Any]) -> None:
    sock = tmp_path / "link" / "vault.sock"
    server.run(
        str(EXAMPLE_POLICY),
        [],
        tmp_path,
        env(),
        None,
        gateway_socket=sock,
        gateway_uid=10002,
        control_fd=9,
    )
    assert captured_run["order"] == [("fd", 9), "lock", ("dir", sock)]
    assert captured_run["listens"] == []
    assert captured_run["gateway_socket"] == sock
    assert captured_run["gateway_uid"] == 10002
    assert captured_run["control_fd"] == 9
    assert captured_run["app"]._gateway_link is True


def test_run_without_the_link(tmp_path: Path, captured_run: dict[str, Any]) -> None:
    server.run(str(EXAMPLE_POLICY), ["127.0.0.1:0"], tmp_path, env(), None)
    assert captured_run["order"] == ["lock"]
    assert captured_run["gateway_socket"] is None
    assert captured_run["gateway_uid"] is None
    assert captured_run["control_fd"] is None
    assert captured_run["app"]._gateway_link is False


def test_run_checks_the_options_before_the_lock(
    tmp_path: Path, captured_run: dict[str, Any]
) -> None:
    with pytest.raises(StartupError, match="go together"):
        server.run(str(EXAMPLE_POLICY), [], tmp_path, env(), None, gateway_uid=10002)
    with pytest.raises(StartupError, match="leaves nothing to serve"):
        server.run(str(EXAMPLE_POLICY), [], tmp_path, env(), None)
    assert captured_run["order"] == []


def test_run_checks_the_link_dir_after_the_policy(
    tmp_path: Path, captured_run: dict[str, Any]
) -> None:
    with pytest.raises(StartupError, match="ZOEYMCP_MASTER_KEY is not set"):
        server.run(str(EXAMPLE_POLICY), [], tmp_path, {}, None, gateway_socket=SOCK, gateway_uid=1)
    assert captured_run["order"] == ["lock"]


# --- the CLI -----------------------------------------------------------------------------------


@pytest.fixture
def cli_run(monkeypatch: pytest.MonkeyPatch) -> list[tuple[Any, ...]]:
    calls: list[tuple[Any, ...]] = []

    def run(*args: Any, **kwargs: Any) -> None:
        calls.append((*args, kwargs))

    monkeypatch.setattr(server, "run", run)
    return calls


def test_cli_passes_the_link_options(cli_run: list[tuple[Any, ...]]) -> None:
    argv = [
        "vault",
        "--listen",
        "none",
        "--gateway-socket",
        "/run/zoeymcp-link/vault.sock",
        "--gateway-uid",
        "10002",
        "--control-fd",
        "5",
        "--admin-socket",
        "none",
    ]
    assert main(argv, err=io.StringIO()) == EXIT_OK
    [(config, listens, state, _environ, admin, kwargs)] = cli_run
    assert (config, listens, state, admin) == (None, [], Path("/state"), None)
    assert kwargs == {
        "gateway_socket": Path("/run/zoeymcp-link/vault.sock"),
        "gateway_uid": 10002,
        "control_fd": 5,
    }


def test_cli_defaults(cli_run: list[tuple[Any, ...]]) -> None:
    assert main(["vault", "--admin-socket", "none"], err=io.StringIO()) == EXIT_OK
    [(_, listens, _, _, _, kwargs)] = cli_run
    assert listens == ["0.0.0.0:8080"]
    assert kwargs == {"gateway_socket": None, "gateway_uid": None, "control_fd": None}


def test_cli_refuses_none_with_addresses(cli_run: list[tuple[Any, ...]]) -> None:
    err = io.StringIO()
    argv = ["vault", "--listen", "none", "--listen", "127.0.0.1:8080"]
    assert main(argv, err=err) == EXIT_UNREADABLE
    assert err.getvalue() == (
        "zoeymcp vault: --listen none can't be combined with other addresses\n"
    )
    assert cli_run == []


def test_cli_reports_a_startup_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def run(*args: Any, **kwargs: Any) -> None:
        raise StartupError("--gateway-socket and --gateway-uid go together")

    monkeypatch.setattr(server, "run", run)
    err = io.StringIO()
    argv = ["vault", "--gateway-uid", "10002", "--admin-socket", "none"]
    assert main(argv, err=err) == EXIT_UNREADABLE
    assert err.getvalue() == "zoeymcp vault: --gateway-socket and --gateway-uid go together\n"


# --- the real link and pipe (Linux) ------------------------------------------------------------


def _link_vault(tmp_path: Path) -> VaultApp:
    runtime = load_runtime(str(EXAMPLE_POLICY), tmp_path / "state", env())
    return VaultApp(runtime.policy, runtime.store, runtime.keys, environ={}, gateway_link=True)


async def _wait_for(path: Path) -> None:
    await _until(path.exists, f"{path} never appeared")


@linux_only
def test_the_real_link_and_control_pipe(
    tmp_path: Path, socket_dir: Path, log_buffer: io.StringIO, monkeypatch: pytest.MonkeyPatch
) -> None:
    os.chmod(socket_dir, 0o750)  # noqa: S103 - the link directory's mode in the image
    sock = socket_dir / "vault.sock"
    check_link_dir(sock)
    app = _link_vault(tmp_path)
    reloads: list[Any] = []
    monkeypatch.setattr(server, "reload_policy", lambda *args: reloads.append(args))
    read, write = os.pipe()

    async def main() -> list[int]:
        task = asyncio.create_task(
            server.serve(
                app,
                [],
                config=None,
                environ={},
                gateway_socket=sock,
                gateway_uid=my_uid(),
                control_fd=read,
            )
        )
        await _wait_for(sock)
        transport = httpx.AsyncHTTPTransport(uds=str(sock))
        async with httpx.AsyncClient(transport=transport, base_url="http://vault") as client:
            # A gateway-only route: identity passes, then the connector answers 501.
            gateway = (await client.get("/mail/config")).status_code
            # A placeholder-only route: the link's caller is the gateway, so 403.
            placeholder = (
                await client.get(
                    "/stats/2.0/x", headers={"Authorization": "Bearer ph-agent1-stats-4c1f9b27"}
                )
            ).status_code
        os.write(write, b"HUP\n")
        await _until(lambda: reloads, "HUP never reloaded")
        os.write(write, b"TERM\n")
        await asyncio.wait_for(task, 10)
        return [gateway, placeholder]

    try:
        assert asyncio.run(main()) == [501, 403]
    finally:
        os.close(write)
    assert len(reloads) == 1
    events = [line["event"] for line in log_lines(log_buffer)]
    assert "gateway_socket_listening" in events
    assert events[-1] == "vault_stopped"
    requests = [line for line in log_lines(log_buffer) if line["event"] == "request"]
    assert [(r["listener"], r["status"]) for r in requests] == [("gateway", 501), ("gateway", 403)]


@linux_only
def test_the_real_control_pipe_closing_stops_the_vault(
    tmp_path: Path, socket_dir: Path, log_buffer: io.StringIO
) -> None:
    os.chmod(socket_dir, 0o750)  # noqa: S103 - the link directory's mode in the image
    sock = socket_dir / "vault.sock"
    app = _link_vault(tmp_path)
    read, write = os.pipe()

    async def main() -> None:
        task = asyncio.create_task(
            server.serve(
                app,
                [],
                config=None,
                environ={},
                gateway_socket=sock,
                gateway_uid=my_uid(),
                control_fd=read,
            )
        )
        await _wait_for(sock)
        os.close(write)
        await asyncio.wait_for(task, 10)

    asyncio.run(main())
    lines = log_lines(log_buffer)
    assert {"role": "vault", "event": "control_received", "command": "EOF"} in lines
    assert lines[-1]["event"] == "vault_stopped"


@linux_only
def test_the_real_link_cuts_another_uid(
    tmp_path: Path, socket_dir: Path, log_buffer: io.StringIO
) -> None:
    os.chmod(socket_dir, 0o750)  # noqa: S103 - the link directory's mode in the image
    sock = socket_dir / "vault.sock"
    app = _link_vault(tmp_path)
    read, write = os.pipe()

    async def main() -> None:
        task = asyncio.create_task(
            server.serve(
                app,
                [],
                config=None,
                environ={},
                gateway_socket=sock,
                gateway_uid=my_uid() + 1,
                control_fd=read,
            )
        )
        await _wait_for(sock)
        transport = httpx.AsyncHTTPTransport(uds=str(sock))
        async with httpx.AsyncClient(transport=transport, base_url="http://vault") as client:
            with pytest.raises(httpx.TransportError):
                await client.get("/mail/config")
        os.write(write, b"TERM\n")
        await asyncio.wait_for(task, 10)

    try:
        asyncio.run(main())
    finally:
        os.close(write)
    lines = log_lines(log_buffer)
    assert [line for line in lines if line["event"] == "request"] == []
    refused = [line for line in lines if line["event"] == "gateway_socket_refused"]
    assert [line["uid"] for line in refused] == [my_uid()]
    assert lines[-1]["event"] == "vault_stopped"
