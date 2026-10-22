"""A fake resolver and dial map for the vault's guarded clients (M7 design O.1, BP-1).

Tests can't make a real name resolve to a global address, and a fake listens only on loopback,
which the guard refuses. So a test names its fakes: each name answers an address reserved for the
run (global to the guard), and the dial map sends that checked address to ``127.0.0.1:<port>`` of
the right fake. ``netguard`` then runs unchanged on every test connection. The answers can change
between lookups: rebinding (public, then private), mixed answers, an empty answer, a timeout. A
dial to an address no fake was given is refused, so no test reaches the real network.

:meth:`FakeResolver.hooks` is what :data:`zoeymcp.vault.netclient.HOOKS` takes in process;
:meth:`FakeResolver.save` and :func:`install` carry a fixed name map to an out-of-process vault
(tests/acceptance/procs.py's launcher), whose token client it also puts on the guarded transport
until step 16 builds it there. A saved map may also name a ``pause_after_put`` marker
file: that vault then holds every secret write once it returns, for a crash test to kill it
there (M7 design N).

:func:`serve_https` is the smallest fake a dial can reach: one TLS listener on loopback that
answers every request ``200 ok`` and closes the connection, recording the SNI name and the request
head of each, and how many connections the client closed.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import json
import ssl
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from zoeymcp.vault import netclient

# Addresses for the run: global to netguard, never connected to (the dial map replaces them).
_BASE_V4 = int(ipaddress.IPv4Address("11.0.0.1"))
_BASE_V6 = int(ipaddress.IPv6Address("2a00:5a00::1"))
# An answer that stands for a lookup that ran out of time.
TIMEOUT = "timeout"


@dataclass
class FakeResolver:
    """Names to answers, and checked addresses to fakes. Each name holds a list of answers:
    each lookup takes the next, and the last one repeats."""

    answers: dict[str, list[list[str] | str]] = field(default_factory=dict)
    dials: dict[str, int] = field(default_factory=dict)
    lookups: list[tuple[str, int]] = field(default_factory=list)
    dialled: list[tuple[str, int]] = field(default_factory=list)
    _reserved: int = 0

    def reserve(self, *, v6: bool = False) -> str:
        """A fresh global address for this run."""
        self._reserved += 1
        if v6:
            return str(ipaddress.IPv6Address(_BASE_V6 + self._reserved))
        return str(ipaddress.IPv4Address(_BASE_V4 + self._reserved))

    def serve(self, name: str, port: int, *, address: str | None = None) -> str:
        """``name`` answers one address (a reserved one unless given), and a dial to it reaches
        ``127.0.0.1:port``. Returns the address."""
        address = address or self.reserve()
        self.answers[name] = [[address]]
        self.dials[address] = port
        return address

    def answer(self, name: str, *answers: list[str] | str) -> None:
        """``name``'s lookups from now on: each takes the next answer, the last repeats. An
        answer is a list of addresses (empty for none) or :data:`TIMEOUT`."""
        self.answers[name] = list(answers)

    def rebind(self, name: str, public: str, private: str) -> None:
        """The first lookup answers ``public``, every later one ``private``."""
        self.answer(name, [public], [private])

    async def resolve(self, host: str, port: int) -> list[str]:
        self.lookups.append((host, port))
        with contextlib.suppress(ValueError):
            return [str(ipaddress.ip_address(host))]  # a literal answers itself, as getaddrinfo
        found = self.answers.get(host)
        if not found:
            raise OSError(f"the fake resolver doesn't know {host}")
        current = found.pop(0) if len(found) > 1 else found[0]
        if current == TIMEOUT:
            raise TimeoutError(f"the fake lookup of {host} timed out")
        return list(current)

    def dial(self, address: str, port: int) -> tuple[str, int]:
        self.dialled.append((address, port))
        target = self.dials.get(address)
        if target is None:
            raise ConnectionRefusedError(f"no fake at {address}")
        return "127.0.0.1", target

    def hooks(self) -> netclient.Hooks:
        return netclient.Hooks(resolver=self.resolve, dial=self.dial)

    def save(self, path: Path) -> None:
        """The current answers (the first of each) and dials, for :func:`install`."""
        names = {name: found[0] for name, found in self.answers.items() if found}
        document = {"names": names, "dials": self.dials}
        path.write_bytes(json.dumps(document, indent=2).encode() + b"\n")

    @classmethod
    def load(cls, path: Path) -> FakeResolver:
        document = json.loads(path.read_bytes())
        answers: dict[str, list[list[str] | str]] = {
            name: [found] for name, found in document["names"].items()
        }
        return cls(answers=answers, dials=dict(document["dials"]))


def install(path: str) -> None:
    """In a vault's own process, before it builds a client: answer names from ``path``, the
    token client's included, and hold secret writes if it names a ``pause_after_put`` marker."""
    netclient.HOOKS = FakeResolver.load(Path(path)).hooks()
    _guard_token_client()
    marker = json.loads(Path(path).read_bytes()).get("pause_after_put")
    if marker is not None:
        _pause_after_put(Path(marker))


def _guard_token_client() -> None:
    """The vault's token client on the guarded transport, so a login reaches a fake's token
    endpoint by name. Until M7 step 16 moves that client onto ``netclient``'s builder, it
    resolves through the system, which knows no fake's name. Its other settings are the
    vault's own (``vault/app.py``'s ``_token_client``)."""
    from zoeymcp.common.policy import Policy
    from zoeymcp.vault import app
    from zoeymcp.vault.oauth.protocol import ATTEMPT_DEADLINE, CONNECT_TIMEOUT

    def token_client(policy: Policy) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            transport=netclient.guarded_transport(policy.egress_proxy),
            trust_env=False,
            follow_redirects=False,
            timeout=httpx.Timeout(ATTEMPT_DEADLINE, connect=CONNECT_TIMEOUT),
        )

    app._token_client = token_client


def _pause_after_put(marker: Path) -> None:
    """Once a secret write returns, say so in ``marker`` and wait to be killed: the kill falls
    after the write and before the answer."""
    from zoeymcp.vault import secretops

    real = secretops.put

    async def put(*args: Any, **kwargs: Any) -> Any:
        written = await real(*args, **kwargs)
        marker.write_bytes(b"written\n")
        await asyncio.sleep(3600)
        return written

    secretops.put = put


@dataclass
class HttpsSeen:
    """What the fake TLS server saw: how many connections it accepted, the SNI name of each
    handshake, every request head, and how many connections the client closed (or dropped)
    while the server waited for a request."""

    connections: int = 0
    names: list[str | None] = field(default_factory=list)
    heads: list[bytes] = field(default_factory=list)
    left: int = 0

    async def until_left(self, count: int) -> None:
        """Until the client has closed ``count`` connections; the caller bounds the wait."""
        while self.left < count:
            await asyncio.sleep(0.01)


@asynccontextmanager
async def serve_https(
    cert: Path, key: Path, *, keep_alive: bool = False
) -> AsyncIterator[tuple[int, HttpsSeen]]:
    """A TLS listener on ``127.0.0.1`` with ``cert``: yields its port and what it saw. Each
    answer closes the connection, unless ``keep_alive``."""
    seen = HttpsSeen()
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(cert, key)

    def sni(_: ssl.SSLObject, name: str | None, __: ssl.SSLContext) -> None:
        seen.names.append(name)

    context.sni_callback = sni
    answer = b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 2\r\n"
    answer += b"\r\nok" if keep_alive else b"connection: close\r\n\r\nok"

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        seen.connections += 1
        try:
            while True:
                try:
                    head = await reader.readuntil(b"\r\n\r\n")
                except (OSError, asyncio.IncompleteReadError):
                    seen.left += 1  # the client closed it, or dropped it
                    break
                seen.heads.append(head)
                writer.write(answer)
                await writer.drain()
                if not keep_alive:
                    break
        except (OSError, asyncio.LimitOverrunError):
            pass  # a client that left mid-answer
        finally:
            writer.close()
            with contextlib.suppress(OSError, ssl.SSLError):
                await writer.wait_closed()

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=context)
    port: int = server.sockets[0].getsockname()[1]
    try:
        yield port, seen
    finally:
        server.close()
        await server.wait_closed()
