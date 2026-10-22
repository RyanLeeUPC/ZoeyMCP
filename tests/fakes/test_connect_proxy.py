"""The fake CONNECT proxy's onboarding switches (M7 design O.1): refusing chosen hosts, for
D.11's resume, and the fake resolver's name map, so a CONNECT by name reaches a loopback fake."""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

import anyio
import pytest

from .connect_proxy import ConnectProxy, serve_proxy
from .resolver import FakeResolver

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@asynccontextmanager
async def echo_server() -> AsyncIterator[int]:
    """A loopback listener that echoes what it reads; yields its port."""

    async def echo(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        with contextlib.suppress(OSError):
            writer.write(await reader.read(64))
            await writer.drain()
        writer.close()

    server = await asyncio.start_server(echo, "127.0.0.1", 0)
    try:
        yield server.sockets[0].getsockname()[1]
    finally:
        server.close()
        await server.wait_closed()


async def tunnel(proxy_url: str, target: str) -> tuple[bytes, bytes]:
    """CONNECT to ``target`` through the proxy; the reply head, and the echo of ``ping`` when the
    tunnel opened."""
    parts = urlsplit(proxy_url)
    assert parts.hostname is not None
    assert parts.port is not None
    reader, writer = await asyncio.open_connection(parts.hostname, parts.port)
    try:
        writer.write(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
        await writer.drain()
        head = await reader.readuntil(b"\r\n\r\n")
        echoed = b""
        if head.startswith(b"HTTP/1.1 200"):
            writer.write(b"ping")
            await writer.drain()
            echoed = await reader.read(64)
        return head, echoed
    finally:
        writer.close()


async def test_a_name_reaches_the_fake_it_stands_for() -> None:
    names = FakeResolver()
    proxy = ConnectProxy(names=names)
    with anyio.fail_after(10):
        async with echo_server() as port:
            address = names.serve("mcp.example", port)
            with serve_proxy(proxy) as url:
                head, echoed = await tunnel(url, "mcp.example:443")
    assert head.startswith(b"HTTP/1.1 200")
    assert echoed == b"ping"
    assert proxy.targets == ["mcp.example:443"]
    assert names.lookups == [("mcp.example", 443)]
    assert names.dialled == [(address, 443)]


async def test_a_name_the_map_doesnt_know_gets_502() -> None:
    names = FakeResolver()
    names.answer("empty.example", [])
    proxy = ConnectProxy(names=names)
    with anyio.fail_after(10), serve_proxy(proxy) as url:
        unknown, _ = await tunnel(url, "unknown.example:443")
        empty, _ = await tunnel(url, "empty.example:443")
    assert unknown.startswith(b"HTTP/1.1 502")
    assert empty.startswith(b"HTTP/1.1 502")
    assert names.dialled == []


async def test_chosen_hosts_are_refused_until_the_operator_allows_them() -> None:
    names = FakeResolver()
    proxy = ConnectProxy(refuse={"AS.example"}, names=names)
    with anyio.fail_after(10):
        async with echo_server() as port:
            names.serve("as.example", port)
            names.serve("mcp.example", port)
            with serve_proxy(proxy) as url:
                refused, _ = await tunnel(url, "as.example:443")
                allowed, _ = await tunnel(url, "mcp.example:443")
                lookups = list(names.lookups)
                proxy.refuse.clear()  # the operator adds the line; the same command resumes
                resumed, echoed = await tunnel(url, "as.example:443")
    assert refused == b"HTTP/1.1 403 Forbidden\r\n\r\n"
    assert allowed.startswith(b"HTTP/1.1 200")
    # Refused before any lookup or connection.
    assert lookups == [("mcp.example", 443)]
    assert resumed.startswith(b"HTTP/1.1 200")
    assert echoed == b"ping"
    assert proxy.targets == ["as.example:443", "mcp.example:443", "as.example:443"]


async def test_with_an_allow_list_only_its_targets_pass() -> None:
    """The egress role's list, as the onboarding rows through the role use it (M7 I.3)."""
    names = FakeResolver()
    proxy = ConnectProxy(allow={"mcp.example:443"}, names=names)
    with anyio.fail_after(10):
        async with echo_server() as port:
            names.serve("as.example", port)
            names.serve("mcp.example", port)
            with serve_proxy(proxy) as url:
                refused, _ = await tunnel(url, "as.example:443")
                port_refused, _ = await tunnel(url, "mcp.example:8443")
                allowed, _ = await tunnel(url, "mcp.example:443")
                lookups = list(names.lookups)
                proxy.allow = {"mcp.example:443", "as.example:443"}  # a new list
                widened, echoed = await tunnel(url, "as.example:443")
    assert refused == port_refused == b"HTTP/1.1 403 Forbidden\r\n\r\n"
    assert allowed.startswith(b"HTTP/1.1 200")
    assert lookups == [("mcp.example", 443)]
    assert widened.startswith(b"HTTP/1.1 200")
    assert echoed == b"ping"
