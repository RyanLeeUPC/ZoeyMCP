"""Self-test of the fake resolver and its dial map (M7 design O.1): every switch, the saved map
that an out-of-process vault installs, and the TLS fake a dial reaches."""

from __future__ import annotations

import ssl
from pathlib import Path

import anyio
import anyio.abc
import pytest

from tests.acceptance import procs
from tests.acceptance.tls import ProviderCA, issue_cert, make_ca
from tests.fakes.resolver import TIMEOUT, FakeResolver, install, serve_https
from zoeymcp.common import netguard
from zoeymcp.vault import netclient


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(scope="module")
def ca(tmp_path_factory: pytest.TempPathFactory) -> ProviderCA:
    return make_ca(tmp_path_factory.mktemp("resolver-ca"))


pytestmark = pytest.mark.anyio


async def _until_closed(stream: anyio.abc.ByteStream) -> bytes:
    """Everything the peer sends before it closes the connection."""
    received = b""
    while True:
        try:
            received += await stream.receive()
        except (anyio.EndOfStream, anyio.BrokenResourceError):
            return received


async def test_a_served_name_answers_a_global_address_that_dials_the_fake() -> None:
    fake = FakeResolver()
    address = fake.serve("mcp.example.com", 4431)
    assert netguard.classify(address) == "global"
    assert await fake.resolve("mcp.example.com", 443) == [address]
    assert await fake.resolve("mcp.example.com", 443) == [address]  # the last answer repeats
    assert fake.dial(address, 443) == ("127.0.0.1", 4431)
    assert fake.lookups == [("mcp.example.com", 443), ("mcp.example.com", 443)]
    assert fake.dialled == [(address, 443)]


async def test_reserved_addresses_are_global_and_distinct() -> None:
    fake = FakeResolver()
    found = [fake.reserve(), fake.reserve(), fake.reserve(v6=True), fake.reserve(v6=True)]
    assert len(set(found)) == 4
    assert [netguard.classify(a) for a in found] == ["global"] * 4


async def test_rebinding_mixed_empty_and_timeout() -> None:
    fake = FakeResolver()
    fake.rebind("rebind.example.com", "11.9.9.9", "10.0.0.1")
    assert await fake.resolve("rebind.example.com", 443) == ["11.9.9.9"]
    assert await fake.resolve("rebind.example.com", 443) == ["10.0.0.1"]
    assert await fake.resolve("rebind.example.com", 443) == ["10.0.0.1"]
    fake.answer("mixed.example.com", ["11.9.9.9", "192.168.1.1"])
    assert await fake.resolve("mixed.example.com", 443) == ["11.9.9.9", "192.168.1.1"]
    fake.answer("empty.example.com", [])
    assert await fake.resolve("empty.example.com", 443) == []
    fake.answer("slow.example.com", TIMEOUT)
    with pytest.raises(TimeoutError):
        await fake.resolve("slow.example.com", 443)


async def test_unknown_names_and_addresses_are_refused_and_literals_answer_themselves() -> None:
    fake = FakeResolver()
    with pytest.raises(OSError, match="doesn't know"):
        await fake.resolve("nowhere.example.com", 443)
    assert await fake.resolve("10.0.0.5", 443) == ["10.0.0.5"]
    assert await fake.resolve("2001:db8::1", 443) == ["2001:db8::1"]
    # No fake there: never the real network.
    with pytest.raises(ConnectionRefusedError):
        fake.dial("8.8.8.8", 443)


async def test_hooks_are_the_resolver_and_the_dial() -> None:
    fake = FakeResolver()
    address = fake.serve("mcp.example.com", 4431)
    hooks = fake.hooks()
    assert hooks.resolver is not None
    assert hooks.dial is not None
    assert await hooks.resolver("mcp.example.com", 443) == [address]
    assert hooks.dial(address, 443) == ("127.0.0.1", 4431)


async def test_a_saved_map_installs_in_the_vaults_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeResolver()
    address = fake.serve("mcp.example.com", 4431)
    fake.rebind("rebind.example.com", "11.9.9.9", "10.0.0.1")  # saved as its first answer
    path = tmp_path / "hooks.json"
    fake.save(path)
    assert path.read_bytes().endswith(b"}\n")
    loaded = FakeResolver.load(path)
    assert await loaded.resolve("mcp.example.com", 443) == [address]
    assert await loaded.resolve("rebind.example.com", 443) == ["11.9.9.9"]
    assert loaded.dial(address, 443) == ("127.0.0.1", 4431)
    monkeypatch.setattr(netclient, "HOOKS", None)
    install(str(path))
    assert netclient.HOOKS is not None
    assert netclient.HOOKS.resolver is not None
    assert await netclient.HOOKS.resolver("mcp.example.com", 443) == [address]


def _launched(tmp_path: Path, hooks: Path) -> tuple[int, str]:
    """``zoeymcp --version`` through the launcher with ``hooks``: its exit status and output."""
    log = tmp_path / f"{hooks.stem}.log"
    process = procs.start(["--version"], env={}, log=log, hooks=hooks)
    try:
        status = process.popen.wait(60)
    finally:
        process.stop()
    return status, process.output()


def test_the_launcher_installs_the_hooks_before_zoeymcp_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A real child, started from a directory with no ``tests`` package in it: with a saved map
    it imports the fake from the repo and runs zoeymcp; with a missing one, the fake's install
    fails before zoeymcp runs at all."""
    fake = FakeResolver()
    fake.serve("mcp.example.com", 4431)
    saved = tmp_path / "hooks.json"
    fake.save(saved)
    (tmp_path / "elsewhere").mkdir(mode=0o700)
    monkeypatch.chdir(tmp_path / "elsewhere")
    status, output = _launched(tmp_path, saved)
    assert (status, output.split()[0]) == (0, "zoeymcp")
    status, output = _launched(tmp_path, tmp_path / "missing.json")
    assert status != 0
    assert "FileNotFoundError" in output
    assert str(Path("tests", "fakes", "resolver.py")) in output
    assert not output.startswith("zoeymcp ")


async def test_serve_https_records_the_name_and_the_head(ca: ProviderCA, tmp_path: Path) -> None:
    cert, key = issue_cert(ca, "mcp.example.com", tmp_path)
    with anyio.fail_after(10):
        async with serve_https(cert, key) as (port, seen):
            context = ssl.create_default_context(cafile=str(ca.ca_file))
            stream = await anyio.connect_tcp(
                "127.0.0.1", port, ssl_context=context, tls_hostname="mcp.example.com"
            )
            async with stream:
                await stream.send(b"GET / HTTP/1.1\r\nhost: mcp.example.com\r\n\r\n")
                answer = await _until_closed(stream)
    assert answer.startswith(b"HTTP/1.1 200 OK\r\n")
    assert answer.endswith(b"\r\n\r\nok")
    assert b"connection: close\r\n" in answer
    assert seen.connections == 1
    assert seen.left == 0  # the server closed it
    assert seen.names == ["mcp.example.com"]
    assert seen.heads == [b"GET / HTTP/1.1\r\nhost: mcp.example.com\r\n\r\n"]


async def test_serve_https_keeps_a_connection_alive_when_asked(
    ca: ProviderCA, tmp_path: Path
) -> None:
    cert, key = issue_cert(ca, "mcp.example.com", tmp_path)
    head = b"GET / HTTP/1.1\r\nhost: mcp.example.com\r\n\r\n"
    with anyio.fail_after(10):
        async with serve_https(cert, key, keep_alive=True) as (port, seen):
            context = ssl.create_default_context(cafile=str(ca.ca_file))
            stream = await anyio.connect_tcp(
                "127.0.0.1", port, ssl_context=context, tls_hostname="mcp.example.com"
            )
            async with stream:
                for _ in range(2):
                    await stream.send(head)
                    answer = await stream.receive()
                    assert answer.endswith(b"\r\n\r\nok")
                    assert b"connection: close" not in answer
            await seen.until_left(1)  # the client closed it
    assert seen.connections == 1
    assert seen.heads == [head, head]
