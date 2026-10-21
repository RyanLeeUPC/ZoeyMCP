"""Library contract for the vault's guarded clients: M7 design O.3, items 45 and 46.

vault/netclient.py rests on facts about httpcore and httpx that their documentation doesn't all
promise. 45: a network backend's ``connect_tcp`` gets the URL's host and port, so the guard sees
the name it must resolve; TLS on the stream the backend returns uses the URL's host for SNI and
for the certificate check, so the guard may connect to an address; the pool's ``ssl_context`` is
the one used, and httpx's transport sends through the pool it holds as ``_pool``. 46: with
``proxy=`` httpx sends ``CONNECT host:port`` by name and resolves nothing itself;
``trust_env=False`` ignores the proxy variables; a CONNECT the proxy refuses is an
``httpx.ProxyError`` carrying the status only in its text.
"""

from __future__ import annotations

import socket
import ssl
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

import anyio
import certifi
import httpcore
import httpx
import pytest

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
