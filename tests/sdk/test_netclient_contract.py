"""Library contract for the vault's guarded clients: M7 design O.3, items 45 and 46.

vault/netclient.py rests on facts about httpcore and httpx that their documentation doesn't all
promise. 45: a network backend's ``connect_tcp`` gets the URL's host and port, so the guard sees
the name it must resolve; TLS on the stream the backend returns uses the URL's host for SNI and
for the certificate check, so the guard may connect to an address; the pool's ``ssl_context`` is
the one used, and httpx's transport sends through the pool it holds as ``_pool``. 46: with
``proxy=`` httpx sends ``CONNECT host:port`` by name and resolves nothing itself;
``trust_env=False`` ignores the proxy variables; a CONNECT the proxy refuses is an
``httpx.ProxyError`` carrying the status only in its text. 45's socket half (step 18b, Q46, Linux
only): a pool built with ``uds=`` calls the backend's ``connect_unix_socket`` with that path, and
the stream it returns gives the connected socket, from which ``SO_PEERCRED`` reads the listener's
uid; uvicorn's ``uds=`` leaves the socket ``0666``, so the directory is the gate.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import socket
import ssl
import stat
import struct
import sys
import tempfile
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

import anyio
import certifi
import httpcore
import httpx
import pytest
import uvicorn

from tests.acceptance.tls import ProviderCA, issue_cert, make_ca
from tests.fakes.connect_proxy import ConnectProxy, ProxySwitch, serve_proxy
from tests.fakes.resolver import serve_https

NAME = "mcp.example.com"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(scope="module")
def ca(tmp_path_factory: pytest.TempPathFactory) -> ProviderCA:
    return make_ca(tmp_path_factory.mktemp("netclient-contract-ca"))


@pytest.fixture(scope="module")
def certs(ca: ProviderCA, tmp_path_factory: pytest.TempPathFactory) -> dict[str, tuple[Path, Path]]:
    directory = tmp_path_factory.mktemp("netclient-contract-certs")
    return {name: issue_cert(ca, name, directory) for name in (NAME, "other.example.com")}


pytestmark = pytest.mark.anyio


class RecordingBackend(httpcore.AsyncNetworkBackend):
    """Records what ``connect_tcp`` is asked for, and connects to a loopback port instead."""

    def __init__(self, port: int) -> None:
        self.port = port
        self.calls: list[tuple[str, int]] = []
        self._backend = httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        self.calls.append((host, port))
        return await self._backend.connect_tcp("127.0.0.1", self.port, timeout=timeout)

    async def sleep(self, seconds: float) -> None:
        await self._backend.sleep(seconds)


def causes(exc: BaseException) -> Iterator[BaseException]:
    cause: BaseException | None = exc
    while cause is not None:
        yield cause
        cause = cause.__cause__ or cause.__context__


# --- 45. the backend gets the name; TLS checks the name; the pool's context is used -------------


@pytest.mark.parametrize(
    ("url", "port"), [(f"https://{NAME}/", 443), (f"https://{NAME}:8443/", 8443)]
)
async def test_connect_tcp_gets_the_urls_host_and_port_and_tls_uses_the_name(
    ca: ProviderCA, certs: dict[str, tuple[Path, Path]], url: str, port: int
) -> None:
    context = ca.client_context()
    with anyio.fail_after(10):
        async with serve_https(*certs[NAME]) as (fake_port, seen):
            backend = RecordingBackend(fake_port)
            async with httpcore.AsyncConnectionPool(
                ssl_context=context, network_backend=backend
            ) as pool:
                response = await pool.request("GET", url)
                ssl_object = response.extensions["network_stream"].get_extra_info("ssl_object")
                assert response.status == 200
                assert ssl_object.server_hostname == NAME
                assert ssl_object.context is context  # the pool's context, no other
    assert backend.calls == [(NAME, port)]
    assert seen.names == [NAME]


async def test_a_certificate_for_another_name_fails(
    ca: ProviderCA, certs: dict[str, tuple[Path, Path]]
) -> None:
    with anyio.fail_after(10):
        async with serve_https(*certs["other.example.com"]) as (fake_port, seen):
            backend = RecordingBackend(fake_port)
            async with httpcore.AsyncConnectionPool(
                ssl_context=ca.client_context(), network_backend=backend
            ) as pool:
                with pytest.raises(httpcore.ConnectError) as caught:
                    await pool.request("GET", f"https://{NAME}/")
    assert any(isinstance(e, ssl.SSLCertVerificationError) for e in causes(caught.value))
    assert seen.heads == []


async def test_a_certifi_context_refuses_a_ca_only_a_test_store_holds(
    certs: dict[str, tuple[Path, Path]],
) -> None:
    """CR-10, X23: the context built from certifi.where(), as netclient builds it."""
    context = ssl.create_default_context(cafile=certifi.where())
    with anyio.fail_after(10):
        async with serve_https(*certs[NAME]) as (fake_port, seen):
            backend = RecordingBackend(fake_port)
            async with httpcore.AsyncConnectionPool(
                ssl_context=context, network_backend=backend
            ) as pool:
                with pytest.raises(httpcore.ConnectError) as caught:
                    await pool.request("GET", f"https://{NAME}/")
    assert any(isinstance(e, ssl.SSLCertVerificationError) for e in causes(caught.value))
    assert seen.heads == []


async def test_httpx_takes_an_ssl_context_as_is_and_sends_through_its_pool(
    ca: ProviderCA, certs: dict[str, tuple[Path, Path]]
) -> None:
    context = ca.client_context()
    assert httpx.create_ssl_context(verify=context) is context
    with anyio.fail_after(10):
        async with serve_https(*certs[NAME]) as (fake_port, _):
            backend = RecordingBackend(fake_port)
            transport = httpx.AsyncHTTPTransport(verify=context, trust_env=False)
            assert isinstance(transport._pool, httpcore.AsyncConnectionPool)
            transport._pool = httpcore.AsyncConnectionPool(
                ssl_context=context, network_backend=backend
            )
            async with httpx.AsyncClient(transport=transport, trust_env=False) as client:
                response = await client.get(f"https://{NAME}/")
    assert (response.status_code, response.text) == (200, "ok")
    assert backend.calls == [(NAME, 443)]


# --- 46. CONNECT by name; trust_env=False; a refused CONNECT ------------------------------------


@pytest.fixture
def lookups(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    """Every host the process asks getaddrinfo about, as text: anyio, which httpcore's backend
    uses, passes a name as IDNA-encoded bytes."""
    seen: list[Any] = []
    real = socket.getaddrinfo

    def recording(host: Any, *args: Any, **kwargs: Any) -> Any:
        seen.append(host.decode() if isinstance(host, bytes) else host)
        return real(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", recording)
    return seen


async def test_a_proxy_gets_connect_by_name_and_nothing_resolves_locally(
    ca: ProviderCA, lookups: list[Any]
) -> None:
    proxy = ConnectProxy({ProxySwitch.REFUSE_403})
    with serve_proxy(proxy) as url, anyio.fail_after(10):
        async with httpx.AsyncClient(
            proxy=url, trust_env=False, verify=ca.client_context()
        ) as client:
            with pytest.raises(httpx.ProxyError):
                await client.get(f"https://{NAME}:8443/mcp")
    assert proxy.targets == [f"{NAME}:8443"]
    assert set(lookups) <= {"127.0.0.1"}


async def test_the_recorder_sees_a_lookup_made_through_anyio(lookups: list[Any]) -> None:
    """The control: the lookup httpcore's backend would make is one ``lookups`` records."""
    with anyio.fail_after(10):
        await anyio.getaddrinfo("localhost", 443)
    assert "localhost" in lookups


@pytest.mark.parametrize(
    ("switch", "text"),
    [
        (ProxySwitch.REFUSE_403, "403 Forbidden"),
        (ProxySwitch.REFUSE_407, "407 Proxy Authentication Required"),
    ],
)
async def test_a_refused_connect_is_a_proxy_error_with_the_status_in_its_text(
    ca: ProviderCA, switch: ProxySwitch, text: str
) -> None:
    """D.11: the status is known only from the text; there is no response to read."""
    with serve_proxy(ConnectProxy({switch})) as url, anyio.fail_after(10):
        async with httpx.AsyncClient(
            proxy=url, trust_env=False, verify=ca.client_context()
        ) as client:
            with pytest.raises(httpx.ProxyError) as caught:
                await client.get(f"https://{NAME}/")
    assert str(caught.value) == text
    assert not hasattr(caught.value, "response")
    assert caught.value.request.url == f"https://{NAME}/"


@pytest.mark.parametrize("trust_env", [False, True])
async def test_trust_env_false_ignores_the_proxy_variables(
    ca: ProviderCA, monkeypatch: pytest.MonkeyPatch, trust_env: bool
) -> None:
    proxy = ConnectProxy()
    for name in ("NO_PROXY", "no_proxy", "ALL_PROXY", "all_proxy", "HTTP_PROXY", "http_proxy"):
        monkeypatch.delenv(name, raising=False)
    with serve_proxy(proxy) as url, anyio.fail_after(10):
        monkeypatch.setenv("HTTPS_PROXY", url)
        monkeypatch.setenv("https_proxy", url)
        async with (
            serve_https(ca.cert_file, ca.key_file) as (port, seen),
            httpx.AsyncClient(trust_env=trust_env, verify=ca.client_context()) as client,
        ):
            response = await client.get(f"https://localhost:{port}/")
    assert response.status_code == 200
    assert len(seen.heads) == 1
    # The control: with trust_env the same variables send it through the proxy.
    assert proxy.targets == ([f"localhost:{port}"] if trust_env else [])


# --- 45, the socket half (step 18b, Q46; Linux): uds= reaches the backend; the peer's uid ---------

LINUX = pytest.mark.skipif(
    not hasattr(socket, "SO_PEERCRED"), reason="a socket's peer uid needs Linux (SO_PEERCRED)"
)


class RecordingUnixBackend(httpcore.AsyncNetworkBackend):
    """Records what ``connect_unix_socket`` is asked for, and what the stream it returned gives:
    the connected socket, and the peer's uid read from it while it is open, as
    ``GuardedBackend`` reads it (the pool closes the stream once the response is read)."""

    def __init__(self) -> None:
        self.paths: list[str] = []
        self.sockets: list[object] = []
        self.uids: list[int] = []
        self._backend = httpcore.AnyIOBackend()

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        self.paths.append(path)
        stream = await self._backend.connect_unix_socket(
            path, timeout=timeout, socket_options=socket_options
        )
        sock = stream.get_extra_info("socket")
        self.sockets.append(sock)
        if sys.platform != "win32" and isinstance(sock, socket.socket):
            raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("=iII"))
            self.uids.append(struct.unpack("=iII", raw)[1])
        return stream

    async def sleep(self, seconds: float) -> None:
        await self._backend.sleep(seconds)


@pytest.fixture
def short_dir() -> Iterator[Path]:
    """A directory with a short path: a Unix socket's path holds at most 107 bytes."""
    directory = Path(tempfile.mkdtemp(prefix="zc-"))
    try:
        yield directory
    finally:
        shutil.rmtree(directory, ignore_errors=True)


async def _ok(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    await reader.readuntil(b"\r\n\r\n")
    writer.write(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok")
    await writer.drain()
    writer.close()


@LINUX
async def test_a_uds_pool_connects_through_the_backend_and_the_stream_holds_the_socket(
    short_dir: Path,
) -> None:
    """vault/netclient.py's socket client: the pool calls the backend's connect_unix_socket
    with its path, and the stream it returns gives the connected socket, from which
    SO_PEERCRED reads the listener's uid (here the test's own)."""
    if sys.platform == "win32":
        raise RuntimeError("a Unix socket listener needs Linux here")
    path = str(short_dir / "mcp.sock")
    backend = RecordingUnixBackend()
    with anyio.fail_after(10):
        async with (
            await asyncio.start_unix_server(_ok, path=path),
            httpcore.AsyncConnectionPool(uds=path, network_backend=backend) as pool,
        ):
            response = await pool.request("GET", "http://bridge.invalid/mcp")
    assert response.status == 200
    assert backend.paths == [path]
    [sock] = backend.sockets
    assert isinstance(sock, socket.socket)
    assert backend.uids == [os.getuid()]


@LINUX
async def test_uvicorns_uds_leaves_the_socket_0666(short_dir: Path) -> None:
    """The directory is the gate, not the socket's mode (C.10's 0750 directory, Q46)."""
    path = short_dir / "mcp.sock"

    async def app(scope: Any, receive: Any, send: Any) -> None:
        raise AssertionError("never called")

    config = uvicorn.Config(app, uds=str(path), lifespan="off", log_config=None)
    config.load()
    server = uvicorn.Server(config)
    server.lifespan = config.lifespan_class(config)
    with anyio.fail_after(10):
        await server.startup()
        try:
            mode = stat.S_IMODE(os.stat(path).st_mode)
        finally:
            await server.shutdown()
    assert mode == 0o666
