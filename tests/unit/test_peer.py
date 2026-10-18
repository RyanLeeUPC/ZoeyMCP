"""The link socket's peer check (M3 design C.1): ``vault/peer.py``.

The pure parts run everywhere with a fake socket. The real ``SO_PEERCRED`` tests need Linux.
"""

from __future__ import annotations

import asyncio
import io
import json
import os
import shutil
import socket
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
from starlette.types import Receive, Scope, Send
from uvicorn.protocols.http.h11_impl import H11Protocol
from uvicorn.server import ServerState

from zoeymcp.vault import logs
from zoeymcp.vault.peer import UCRED, link_supported, peer_allowed, peer_checked, peer_uid

LINUX_SO_PEERCRED = 17
linux_only = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="SO_PEERCRED")


def my_uid() -> int:
    """The test's own uid (the Linux tests only)."""
    if sys.platform != "win32":
        return os.getuid()
    raise AssertionError("not on Windows")


@pytest.fixture
def log_buffer() -> Iterator[io.StringIO]:
    buffer = io.StringIO()
    logs.set_stream(buffer)
    try:
        yield buffer
    finally:
        logs.set_stream(None)


def log_lines(buffer: io.StringIO) -> list[dict[str, Any]]:
    return [json.loads(line) for line in buffer.getvalue().splitlines()]


# --- peer_allowed --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("uid", "allowed", "result"),
    [
        (10002, 10002, True),
        (0, 0, True),
        (10001, 10002, False),
        (10003, 10002, False),
        (0, 10002, False),
        (None, 10002, False),
        (None, 0, False),
    ],
)
def test_peer_allowed(uid: int | None, allowed: int, result: bool) -> None:
    assert peer_allowed(uid, allowed) is result


# --- peer_uid ------------------------------------------------------------------------------------


class FakeSocket:
    """Answers ``getsockopt`` with ``answer``, or raises it."""

    def __init__(self, answer: Any, name: str = "/run/zoeymcp-link/vault.sock") -> None:
        self.answer = answer
        self.name = name
        self.calls: list[tuple[int, int, int]] = []

    def getsockopt(self, level: int, option: int, size: int) -> Any:
        self.calls.append((level, option, size))
        if isinstance(self.answer, BaseException):
            raise self.answer
        return self.answer

    def getsockname(self) -> str:
        return self.name

    def getpeername(self) -> str:
        return ""


@pytest.fixture
def peercred(monkeypatch: pytest.MonkeyPatch) -> int:
    """Makes ``socket.SO_PEERCRED`` exist, as on Linux."""
    monkeypatch.setattr(socket, "SO_PEERCRED", LINUX_SO_PEERCRED, raising=False)
    return LINUX_SO_PEERCRED


def test_ucred_layout() -> None:
    assert UCRED.size == 12
    # uid_t and gid_t are unsigned: a uid above 2**31 reads back as itself.
    assert UCRED.unpack(UCRED.pack(-1, 4294967294, 7)) == (-1, 4294967294, 7)
    assert UCRED.pack(1, 2, 3) == (1).to_bytes(4, sys.byteorder) + (2).to_bytes(
        4, sys.byteorder
    ) + (3).to_bytes(4, sys.byteorder)


def test_peer_uid_reads_ucred(peercred: int) -> None:
    sock = FakeSocket(UCRED.pack(4321, 10002, 10005))
    assert peer_uid(sock) == 10002
    assert sock.calls == [(socket.SOL_SOCKET, peercred, 12)]
    assert peer_uid(FakeSocket(UCRED.pack(1, 0, 0))) == 0
    assert peer_uid(FakeSocket(UCRED.pack(1, 4294967294, 0))) == 4294967294


@pytest.mark.parametrize(
    "answer",
    [
        OSError(95, "Operation not supported"),
        b"",
        UCRED.pack(1, 10002, 3)[:-1],
        UCRED.pack(1, 10002, 3) + b"\x00",
        bytearray(UCRED.pack(1, 10002, 3)),
        10002,
    ],
)
def test_peer_uid_unknown(peercred: int, answer: Any) -> None:
    sock = FakeSocket(answer)
    assert peer_uid(sock) is None
    assert sock.calls == [(socket.SOL_SOCKET, peercred, 12)]


def test_peer_uid_without_a_socket(peercred: int) -> None:
    assert peer_uid(None) is None


def test_peer_uid_without_so_peercred(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delattr(socket, "SO_PEERCRED", raising=False)
    sock = FakeSocket(UCRED.pack(1, 10002, 3))
    assert peer_uid(sock) is None
    assert sock.calls == []
    assert link_supported() is False


def test_link_supported(peercred: int) -> None:
    assert link_supported() is True


# --- the protocol, with a fake transport ---------------------------------------------------------


class FakeTransport:
    def __init__(self, sock: Any) -> None:
        self.sock = sock
        self.aborted = 0
        self.closed = 0

    def get_extra_info(self, name: str, default: Any = None) -> Any:
        return self.sock if name == "socket" else default

    def abort(self) -> None:
        self.aborted += 1

    def close(self) -> None:
        self.closed += 1

    def is_closing(self) -> bool:
        return bool(self.aborted or self.closed)


async def _app(scope: Scope, receive: Receive, send: Send) -> None:
    raise AssertionError("never reached")


def _protocol(allowed: int, loop: asyncio.AbstractEventLoop) -> Any:
    protocol_class = peer_checked(allowed)
    config = uvicorn.Config(_app, http=protocol_class, lifespan="off")
    return protocol_class(config, ServerState(), {}, _loop=loop)


@pytest.mark.parametrize(("uid", "allowed"), [(10002, 10002), (0, 0)])
def test_the_allowed_peer_stays(
    peercred: int, log_buffer: io.StringIO, uid: int, allowed: int
) -> None:
    loop = asyncio.new_event_loop()
    try:
        protocol = _protocol(allowed, loop)
        transport = FakeTransport(FakeSocket(UCRED.pack(99, uid, uid)))
        protocol.connection_made(transport)
        assert transport.aborted == 0
        assert protocol in protocol.connections
        assert protocol.transport is transport
        assert log_lines(log_buffer) == []
    finally:
        loop.close()


@pytest.mark.parametrize(
    ("answer", "allowed", "uid"),
    [
        (UCRED.pack(99, 10003, 10003), 10002, 10003),
        (UCRED.pack(99, 0, 0), 10002, 0),
        (UCRED.pack(99, 10002, 10002), 10001, 10002),
        (OSError(95, "Operation not supported"), 10002, None),
    ],
)
def test_another_peer_is_cut(
    peercred: int, log_buffer: io.StringIO, answer: Any, allowed: int, uid: int | None
) -> None:
    loop = asyncio.new_event_loop()
    try:
        protocol = _protocol(allowed, loop)
        transport = FakeTransport(FakeSocket(answer))
        protocol.connection_made(transport)
        assert transport.aborted == 1
        [line] = log_lines(log_buffer)
        assert line["event"] == "gateway_socket_refused"
        assert line["uid"] == uid
        assert set(line) == {"ts", "role", "event", "uid"}
        # uvicorn's own cleanup still works on the cut connection.
        protocol.connection_lost(None)
        assert protocol not in protocol.connections
    finally:
        loop.close()


def test_without_a_socket_the_peer_is_cut(peercred: int, log_buffer: io.StringIO) -> None:
    loop = asyncio.new_event_loop()
    try:
        protocol = _protocol(10002, loop)
        transport = FakeTransport(None)
        protocol.connection_made(transport)
        assert transport.aborted == 1
        assert log_lines(log_buffer)[-1]["uid"] is None
    finally:
        loop.close()


def test_each_protocol_has_its_own_uid(peercred: int) -> None:
    first, second = peer_checked(1), peer_checked(2)
    assert first is not second
    assert issubclass(first, H11Protocol)
    assert issubclass(second, H11Protocol)


# --- the real socket (Linux) ---------------------------------------------------------------------


class _Server(uvicorn.Server):
    def install_signal_handlers(self) -> None:
        pass


@contextmanager
def serve_link(app: Any, path: str, allowed: int) -> Iterator[None]:
    config = uvicorn.Config(
        app, uds=path, http=peer_checked(allowed), log_level="warning", lifespan="off"
    )
    server = _Server(config)
    thread = threading.Thread(target=lambda: asyncio.run(server.serve()), daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        if time.monotonic() > deadline:
            raise RuntimeError("link socket didn't start")
        time.sleep(0.01)
    try:
        yield
    finally:
        server.should_exit = True
        thread.join(10)


@pytest.fixture
def socket_dir() -> Iterator[Path]:
    # Short path: AF_UNIX paths are limited to about 100 bytes.
    path = Path(tempfile.mkdtemp(prefix="zm-", dir="/tmp"))
    os.chmod(path, 0o700)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


class Counting:
    def __init__(self) -> None:
        self.calls = 0

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        self.calls += 1
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})


@linux_only
def test_socketpair_reports_our_uid() -> None:
    left, right = socket.socketpair()  # AF_UNIX on Linux
    with left, right:
        assert peer_uid(left) == my_uid()
        assert peer_uid(right) == my_uid()
    assert link_supported() is True


@linux_only
def test_our_own_uid_is_served(socket_dir: Path, log_buffer: io.StringIO) -> None:
    app = Counting()
    path = str(socket_dir / "vault.sock")
    with (
        serve_link(app, path, my_uid()),
        httpx.Client(transport=httpx.HTTPTransport(uds=path)) as client,
    ):
        response = client.get("http://vault/x")
    assert (response.status_code, response.text) == (200, "ok")
    assert app.calls == 1
    assert "gateway_socket_refused" not in log_buffer.getvalue()


@linux_only
def test_another_uid_is_cut_before_a_byte(socket_dir: Path, log_buffer: io.StringIO) -> None:
    app = Counting()
    path = str(socket_dir / "vault.sock")
    with (
        serve_link(app, path, my_uid() + 1),
        httpx.Client(transport=httpx.HTTPTransport(uds=path)) as client,
        pytest.raises(httpx.TransportError),
    ):
        client.get("http://vault/x")
    assert app.calls == 0
    refused = [x for x in log_lines(log_buffer) if x["event"] == "gateway_socket_refused"]
    assert [x["uid"] for x in refused] == [my_uid()]
