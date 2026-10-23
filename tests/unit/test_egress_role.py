"""The egress role in process (M7 design I.4, X15, X17, FM-26, FM-27; O.4's X15 row).

The role runs in the test's event loop against the allowlist fake (tests/fakes/allowlist.py),
answers names from the fake resolver, and reaches a loopback echo server by the addresses that
resolver reserved, so netguard judges every connection unchanged. The fake's clock makes the
300 s staleness a step, not a wait. Every test bounds itself with ``anyio.fail_after``.
"""

from __future__ import annotations

import asyncio
import io
import json
import socket
import time
from collections.abc import AsyncIterator, Iterator, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import anyio
import pytest

from tests.fakes.allowlist import KEY, AllowlistFake, Clock, Entry, serve_allowlist
from tests.fakes.resolver import TIMEOUT, FakeResolver
from zoeymcp.cli.main import main as cli_main
from zoeymcp.common import logs
from zoeymcp.common.policy.schema import NAME_PATTERN
from zoeymcp.egress import allowlist, connect, listen
from zoeymcp.egress.allowlist import (
    Allowlist,
    AllowlistError,
    DocumentError,
    EgressKey,
    KeySource,
    backoff,
    parse_document,
    parse_vault,
)
from zoeymcp.egress.main import Options, Role, StartupError, build
from zoeymcp.egress.tunnel import Resolve

pytestmark = pytest.mark.anyio

DIGEST = "sha256:" + "a" * 64
OAUTH_PATHS = (
    "/.well-known/oauth-authorization-server",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-protected-resource",
    "/register",
    "/token",
    "/authorize",
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def lines() -> Iterator[io.StringIO]:
    stream = io.StringIO()
    logs.set_stream(stream)
    try:
        yield stream
    finally:
        logs.set_stream(None)


def events(lines: io.StringIO, kind: str) -> list[dict[str, Any]]:
    found = [json.loads(line) for line in lines.getvalue().splitlines()]
    return [record for record in found if record["event"] == kind]


async def until(condition: Any, timeout: float = 10.0) -> None:
    with anyio.fail_after(timeout):
        while not condition():
            await asyncio.sleep(0.01)


# --- the rig --------------------------------------------------------------------------------------


@asynccontextmanager
async def echo_server() -> AsyncIterator[int]:
    """A loopback server that sends back what it receives; yields its port."""

    async def echo(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()
        except OSError:
            pass
        finally:
            writer.close()

    server = await asyncio.start_server(echo, "127.0.0.1", 0)
    try:
        yield server.sockets[0].getsockname()[1]
    finally:
        server.close()


class Names:
    """A listener alias lookup the test changes: name to addresses, or to an exception to
    raise. While ``hold`` is set, a lookup of a name in it waits for the event first."""

    def __init__(self, names: Mapping[str, Sequence[str] | Exception] | None = None) -> None:
        self.names = dict(names or {})
        self.hold: dict[str, asyncio.Event] = {}

    async def __call__(self, host: str) -> list[str]:
        if host in self.hold:
            await self.hold[host].wait()
        found = self.names.get(host, OSError(f"no such name {host}"))
        if isinstance(found, Exception):
            raise found
        return list(found)


@dataclass
class Rig:
    role: Role
    fake: AllowlistFake
    resolver: FakeResolver
    clock: Clock
    echo: int
    public: dict[str, str] = field(default_factory=dict)

    def port(self, source: str = "vault") -> int:
        return self.role.bound[source][1]

    def serve(self, name: str) -> str:
        """``name`` resolves to a fresh global address that reaches the echo server."""
        self.public[name] = self.resolver.serve(name, self.echo)
        return self.public[name]

    async def publish(self, sources: Mapping[str, list[Entry]]) -> None:
        digest = self.fake.publish(sources)
        await until(lambda: self.role.allowlist.digest == digest)


@asynccontextmanager
async def rig(
    *,
    listens: tuple[str, ...] = ("vault=127.0.0.1:0",),
    lists: Mapping[str, list[Entry]] | None = None,
    names: Names | None = None,
    slow: asyncio.Event | None = None,
    key: KeySource | None = None,
    fetched: bool = True,
    **options: Any,
) -> AsyncIterator[Rig]:
    fake, resolver, clock = AllowlistFake(), FakeResolver(), Clock()
    if lists is not None:
        fake.publish(lists)
    head_timeout = options.pop("head_timeout", 10.0)
    async with echo_server() as echo, serve_allowlist(fake) as url:
        role = Role(
            Options(url, listens, **options),
            key or KeySource(KEY),
            resolve=resolver.resolve if slow is None else gated(resolver, slow),
            dial=resolver.dial,
            lookup=names or Names(),
            clock=clock,
            head_timeout=head_timeout,
            jitter=lambda: 0.01,
        )
        task = asyncio.create_task(role.serve())
        try:
            await until(lambda: role.started)
            if lists is not None and fetched:
                await until(lambda: role.allowlist.digest == fake.digest)
            yield Rig(role, fake, resolver, clock, echo)
        finally:
            role.stop()
            with anyio.fail_after(10):
                await task


def gated(resolver: FakeResolver, gate: asyncio.Event) -> Resolve:
    """``resolver``'s lookups, each held until ``gate`` is set."""

    async def resolve(host: str, port: int) -> list[str]:
        await gate.wait()
        return await resolver.resolve(host, port)

    return resolve


def connect_head(target: str, *, method: str = "CONNECT") -> bytes:
    return f"{method} {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode()


async def ask(port: int, data: bytes) -> tuple[bytes, bytes]:
    """Send ``data``; the answer's head, and everything after it until the role closes."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(data)
        await writer.drain()
        answer = await reader.readuntil(b"\r\n\r\n")
        return answer, await reader.read()
    finally:
        writer.close()


async def refusal(port: int, target: str, *, method: str = "CONNECT") -> int:
    """The status of a refused request, checked to be an empty answer that carries no
    challenge (X17)."""
    with anyio.fail_after(10):
        answer, rest = await ask(port, connect_head(target, method=method))
    assert rest == b""
    head = answer.decode().lower()
    assert "content-length: 0\r\n" in head
    assert "www-authenticate" not in head
    assert "proxy-authenticate" not in head
    return int(head.split(" ")[1])


@asynccontextmanager
async def tunnel(
    port: int, target: str, early: bytes = b""
) -> AsyncIterator[tuple[asyncio.StreamReader, asyncio.StreamWriter]]:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(connect_head(target) + early)
        await writer.drain()
        assert await reader.readuntil(b"\r\n\r\n") == b"HTTP/1.1 200 Connection established\r\n\r\n"
        yield reader, writer
    finally:
        writer.close()


async def echoes(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> bool:
    writer.write(b"ping")
    await writer.drain()
    return await reader.readexactly(4) == b"ping"


def refused(lines: io.StringIO) -> list[tuple[str, str | None]]:
    return [(r["reason"], r.get("host")) for r in events(lines, "egress_refused")]


# --- the lists: none, fresh, stale ----------------------------------------------------------------


async def test_the_role_refuses_everything_until_its_first_list(lines: io.StringIO) -> None:
    """Acceptance: no tunnel before the first list; then the fake's lists serve; at 300 s
    without contact they go stale and every tunnel is refused (X15, Q25)."""
    with anyio.fail_after(30):
        async with rig() as r:
            r.serve("api.example")
            assert await refusal(r.port(), "api.example:443") == 503
            await r.publish({"vault": [("api.example", 443)]})
            async with tunnel(r.port(), "api.example:443") as (reader, writer):
                assert await echoes(reader, writer)
            # The fake holds the role's long poll: no contact from here on.
            r.clock.advance(300)
            async with tunnel(r.port(), "api.example:443") as (reader, writer):
                assert await echoes(reader, writer)
            await until(lambda: len(events(lines, "egress_tunnel")) == 2)
            r.clock.advance(0.5)
            assert await refusal(r.port(), "api.example:443") == 503
            assert await refusal(r.port(), "api.example:443") == 503
    assert refused(lines) == [("list_stale", "api.example")] * 3
    [stale] = events(lines, "egress_allowlist_stale")
    assert stale["digest"] == r.fake.digest
    [applied] = events(lines, "egress_allowlist_applied")
    assert applied["sources"] == {"vault": 1}
    assert [t["result"] for t in events(lines, "egress_tunnel")] == ["closed", "closed"]


async def test_the_role_sends_its_key_and_long_polls() -> None:
    with anyio.fail_after(30):
        async with rig(lists={"vault": [("api.example", 443)]}) as r:
            await until(lambda: len(r.fake.seen) >= 2)
    first, second = r.fake.seen[:2]
    assert (first.key, first.if_none_match, first.query) == (KEY, None, {})
    assert (second.key, second.if_none_match) == (KEY, f'"{r.fake.digest}"')
    assert second.query == {"wait": "25"}


async def test_vault_unreachable(lines: io.StringIO) -> None:
    """FM-26: the last lists serve until 300 s without contact, then every tunnel is refused;
    the vault's return is contact at once (the first request after a failure doesn't wait)."""
    with anyio.fail_after(30):
        async with rig(lists={"vault": [("api.example", 443)]}) as r:
            r.serve("api.example")
            r.fake.set_down(True)
            await until(lambda: events(lines, "egress_allowlist_failed"))
            r.clock.advance(299)
            async with tunnel(r.port(), "api.example:443") as (reader, writer):
                assert await echoes(reader, writer)
            r.clock.advance(2)
            assert await refusal(r.port(), "api.example:443") == 503
            r.fake.set_down(False)
            await until(lambda: r.role.allowlist.last_contact == r.clock())
            async with tunnel(r.port(), "api.example:443") as (reader, writer):
                assert await echoes(reader, writer)
    retried = [s for s in r.fake.seen if s.if_none_match is not None and not s.query]
    assert retried  # asked without a wait once the vault was back
    assert len(events(lines, "egress_allowlist_stale")) == 1


def test_the_backoff_is_1_to_30_seconds() -> None:
    """The role is back within 30 s of the vault's return (FM-26), jitter included."""
    assert [backoff(n, 1.0) for n in range(1, 8)] == [1.0, 2.0, 4.0, 8.0, 16.0, 30.0, 30.0]
    assert backoff(1, 0.5) == 0.5
    assert max(backoff(n, 1.5) for n in range(1, 2000)) == 30.0
    assert allowlist.ALLOWLIST_MAX_STALE == 300.0
    assert allowlist.ALLOWLIST_WAIT == 25


async def test_a_document_the_role_cant_parse_keeps_the_last_good_one(
    lines: io.StringIO,
) -> None:
    with anyio.fail_after(30):
        async with rig(lists={"vault": [("api.example", 443)]}) as r:
            r.serve("api.example")
            good = r.fake.digest
            r.fake.publish_raw(b'{"v": 2}', DIGEST)
            await until(lambda: events(lines, "egress_allowlist_failed"))
            assert r.role.allowlist.digest == good
            async with tunnel(r.port(), "api.example:443") as (reader, writer):
                assert await echoes(reader, writer)
    assert events(lines, "egress_allowlist_failed")[0]["reason"] == (
        "not a version 1 allowlist document"
    )


async def test_a_destination_no_connect_could_name_is_skipped(lines: io.StringIO) -> None:
    """F1: a route whose host IDNA refuses is in the vault's document as written (D-190); the
    role skips it and keeps every other destination and source."""
    lists: dict[str, list[Entry]] = {
        "vault": [("api.example", 443), ("\u2603.example", 443)],
        "bridge-fetch": [("docs.example", 443)],
    }
    with anyio.fail_after(30):
        async with rig(lists=lists, listens=("vault=127.0.0.1:0", "bridge-fetch=127.0.0.1:0")) as r:
            r.serve("api.example")
            r.serve("docs.example")
            async with tunnel(r.port(), "api.example:443") as (reader, writer):
                assert await echoes(reader, writer)
            async with tunnel(r.port("bridge-fetch"), "docs.example:443") as (reader, writer):
                assert await echoes(reader, writer)
            assert await refusal(r.port(), "\u2603.example:443") == 403
    [applied] = events(lines, "egress_allowlist_applied")
    assert (applied["sources"], applied["skipped"]) == ({"bridge-fetch": 1, "vault": 1}, 1)
    assert not events(lines, "egress_allowlist_failed")


async def test_a_poll_pass_that_raises_is_a_failure(
    lines: io.StringIO, monkeypatch: pytest.MonkeyPatch
) -> None:
    """F3: an error no rule foresaw fails that pass, logged, and the poll goes on."""
    real = allowlist.parse_document
    calls: list[int] = []

    def once(body: bytes) -> tuple[str, dict[str, dict[str, bool]], int]:
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("unforeseen")
        return real(body)

    monkeypatch.setattr(allowlist, "parse_document", once)
    with anyio.fail_after(30):
        async with rig(lists={"vault": [("api.example", 443)]}) as r:
            r.serve("api.example")
            async with tunnel(r.port(), "api.example:443") as (reader, writer):
                assert await echoes(reader, writer)
    assert events(lines, "egress_allowlist_failed")[0]["error_type"] == "RuntimeError"


async def test_a_nested_document_is_one_that_doesnt_parse() -> None:
    with pytest.raises(DocumentError, match="not JSON"):
        parse_document(b"[" * 100_000)


async def test_the_role_stops_if_its_poll_ends(
    lines: io.StringIO, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def ends(self: Allowlist) -> None:
        raise RuntimeError("the poll ended")

    monkeypatch.setattr(Allowlist, "run", ends)
    role = Role(Options("http://127.0.0.1:9", ("vault=127.0.0.1:0",)), KeySource(KEY))
    with anyio.fail_after(10), pytest.raises(RuntimeError, match="the poll ended"):
        await role.serve()
    [ended] = events(lines, "egress_allowlist_ended")
    assert ended["error_type"] == "RuntimeError"
    assert all(not server.is_serving() for server in role._servers.values())


async def test_a_vault_that_never_answers_the_connect(
    lines: io.StringIO, monkeypatch: pytest.MonkeyPatch
) -> None:
    """F4: the connect has its own timeout, not the long poll's 40 s."""

    async def hangs(*args: Any, **kwargs: Any) -> Any:
        await asyncio.Event().wait()

    monkeypatch.setattr(asyncio, "open_connection", hangs)
    monkeypatch.setattr(allowlist, "CONNECT_TIMEOUT", 0.05)
    poll = Allowlist("http://vault:8080", KeySource(KEY))
    with anyio.fail_after(5):
        assert await poll.fetch_once() is False
    assert events(lines, "egress_allowlist_failed")[0]["error_type"] == "TimeoutError"
    assert connect.CONNECT_TIMEOUT == 10.0


def test_the_held_poll_sends_keepalives() -> None:
    """F4: a vault that vanishes without closing the poll fails it within 15 s."""
    with socket.socket() as sock:
        allowlist._keepalive(sock)
        assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE) != 0
    assert allowlist.KEEPALIVE_LIMIT == 15


# --- X15's refusals -------------------------------------------------------------------------------


async def test_a_host_outside_the_list_and_plain_http_are_refused(lines: io.StringIO) -> None:
    with anyio.fail_after(30):
        async with rig(lists={"vault": [("api.example", 443)]}) as r:
            r.serve("api.example")
            r.serve("other.example")
            assert await refusal(r.port(), "other.example:443") == 403
            assert await refusal(r.port(), "api.example:8443") == 403
            assert await refusal(r.port(), "http://api.example/", method="GET") == 405
            assert await refusal(r.port(), "api.example:443", method="POST") == 405
            answer, _ = await ask(r.port(), connect_head("/", method="GET"))
    assert b"\r\nAllow: CONNECT\r\n" in answer
    assert r.resolver.lookups == []  # refused before any lookup
    assert [reason for reason, _ in refused(lines)] == ["not_allowed"] * 2 + ["not_connect"] * 3


async def test_a_name_that_resolves_private_is_refused_unless_marked_private(
    lines: io.StringIO,
) -> None:
    with anyio.fail_after(30):
        async with rig(lists={"vault": [("lan.example", 443), ("mixed.example", 443)]}) as r:
            r.resolver.answer("lan.example", ["10.0.0.5"])
            r.resolver.dials["10.0.0.5"] = r.echo
            r.resolver.answer("mixed.example", [r.resolver.reserve(), "192.168.1.9"])
            assert await refusal(r.port(), "lan.example:443") == 403
            assert await refusal(r.port(), "mixed.example:443") == 403
            await r.publish({"vault": [("lan.example", 443, True)]})
            async with tunnel(r.port(), "lan.example:443") as (reader, writer):
                assert await echoes(reader, writer)
    [lan, mixed] = events(lines, "egress_refused")
    assert (lan["reason"], lan["verdict"], mixed["verdict"]) == (
        "address_refused",
        "private",
        "private",
    )
    assert r.resolver.dialled == [("10.0.0.5", 443)]


async def test_a_name_that_rebinds_between_two_lookups(lines: io.StringIO) -> None:
    """One lookup per connection and a connect to the address it checked: the second
    connection sees the private answer and is refused."""
    with anyio.fail_after(30):
        async with rig(lists={"vault": [("api.example", 443)]}) as r:
            public = r.resolver.reserve()
            r.resolver.dials[public] = r.echo
            r.resolver.rebind("api.example", public, "127.0.0.1")
            async with tunnel(r.port(), "api.example:443") as (reader, writer):
                assert await echoes(reader, writer)
            assert await refusal(r.port(), "api.example:443") == 403
    assert r.resolver.lookups == [("api.example", 443)] * 2
    assert r.resolver.dialled == [(public, 443)]
    [tunnelled] = events(lines, "egress_tunnel")
    assert tunnelled["address"] == public
    assert refused(lines) == [("address_refused", "api.example")]


async def test_one_sources_destination_is_refused_on_anothers_listener(
    lines: io.StringIO,
) -> None:
    listens = ("vault=127.0.0.1:0", "bridge-fetch=127.0.0.1:0", "spare=127.0.0.1:0")
    lists: dict[str, list[Entry]] = {
        "vault": [("api.example", 443)],
        "bridge-fetch": [("docs.example", 443)],
    }
    with anyio.fail_after(30):
        async with rig(listens=listens, lists=lists) as r:
            r.serve("api.example")
            r.serve("docs.example")
            assert await refusal(r.port("vault"), "docs.example:443") == 403
            assert await refusal(r.port("bridge-fetch"), "api.example:443") == 403
            assert await refusal(r.port("spare"), "api.example:443") == 403
            async with tunnel(r.port("bridge-fetch"), "docs.example:443") as (reader, writer):
                assert await echoes(reader, writer)
    assert [(e["source"], e["reason"]) for e in events(lines, "egress_refused")] == [
        ("vault", "not_allowed"),
        ("bridge-fetch", "not_allowed"),
        ("spare", "no_list"),
    ]
    [tunnelled] = events(lines, "egress_tunnel")
    assert (tunnelled["source"], tunnelled["host"], tunnelled["port"]) == (
        "bridge-fetch",
        "docs.example",
        443,
    )


async def test_tunnels_to_a_removed_destination_are_closed(lines: io.StringIO) -> None:
    lists: dict[str, list[Entry]] = {"vault": [("api.example", 443), ("docs.example", 443)]}
    with anyio.fail_after(30):
        async with rig(lists=lists) as r:
            r.serve("api.example")
            r.serve("docs.example")
            async with (
                tunnel(r.port(), "api.example:443") as (gone, gone_writer),
                tunnel(r.port(), "docs.example:443") as (kept, kept_writer),
            ):
                assert await echoes(gone, gone_writer)
                await r.publish({"vault": [("docs.example", 443)]})
                assert await gone.read() == b""
                assert await echoes(kept, kept_writer)
            await until(lambda: len(events(lines, "egress_tunnel")) == 2)
    results = {t["host"]: t["result"] for t in events(lines, "egress_tunnel")}
    assert results == {"api.example": "removed", "docs.example": "closed"}


async def test_a_destination_removed_while_it_resolved_is_refused(lines: io.StringIO) -> None:
    gate = asyncio.Event()
    with anyio.fail_after(30):
        async with rig(lists={"vault": [("api.example", 443)]}, slow=gate) as r:
            address = r.serve("api.example")
            asked = asyncio.create_task(refusal(r.port(), "api.example:443"))
            await until(lambda: r.role.tunnels.counts.get("vault") == 1)
            await r.publish({"vault": [("docs.example", 443)]})
            gate.set()
            assert await asked == 403
    assert refused(lines) == [("not_allowed", "api.example")]
    assert events(lines, "egress_refused")[0]["address"] == address
    assert events(lines, "egress_tunnel") == []


async def test_resolve_and_connect_failures(lines: io.StringIO) -> None:
    lists: dict[str, list[Entry]] = {
        "vault": [("unknown.example", 443), ("slow.example", 443), ("nowhere.example", 443)]
    }
    with anyio.fail_after(30):
        async with rig(lists=lists) as r:
            r.resolver.answer("slow.example", TIMEOUT)
            r.resolver.answer("nowhere.example", [r.resolver.reserve()])  # no fake listens
            for name in ("unknown", "slow", "nowhere"):
                assert await refusal(r.port(), f"{name}.example:443") == 502
    assert [reason for reason, _ in refused(lines)] == [
        "resolve_failed",
        "resolve_failed",
        "connect_failed",
    ]
    assert "address" in events(lines, "egress_refused")[2]


def closed_port() -> int:
    """A loopback port nothing listens on, so a connect to it is refused."""
    with socket.socket() as spare:
        spare.bind(("127.0.0.1", 0))
        port: int = spare.getsockname()[1]
    return port


def blackhole(monkeypatch: pytest.MonkeyPatch) -> int:
    """A loopback port whose connects never answer, as a blackholed address's (a dropped
    SYN): ``asyncio.open_connection`` to it waits until it is cancelled. Every other connect
    is a real one. Called inside the rig, so no listener of the rig can take the port."""
    hole = closed_port()
    real = asyncio.open_connection

    async def held(
        host: Any = None, port: Any = None, **kwargs: Any
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        if port == hole:
            await asyncio.Event().wait()
        return await real(host, port, **kwargs)

    monkeypatch.setattr(asyncio, "open_connection", held)
    return hole


async def test_a_first_address_that_refuses_is_passed_over(lines: io.StringIO) -> None:
    """D-208: when the first checked address refuses (an AAAA record with no working IPv6
    route), the next is tried, in the resolver's order, with no second lookup; the tunnel
    names the address it reached."""
    with anyio.fail_after(30):
        async with rig(lists={"vault": [("api.example", 443)]}) as r:
            first, second = r.resolver.reserve(v6=True), r.resolver.reserve()
            r.resolver.dials.update({first: closed_port(), second: r.echo})
            r.resolver.answer("api.example", [first, second])
            async with tunnel(r.port(), "api.example:443") as (reader, writer):
                assert await echoes(reader, writer)
    assert r.resolver.lookups == [("api.example", 443)]
    assert r.resolver.dialled == [(first, 443), (second, 443)]
    [tunnelled] = events(lines, "egress_tunnel")
    assert tunnelled["address"] == second
    assert refused(lines) == []


async def test_a_blackholed_first_address_ends_at_the_deadline(
    lines: io.StringIO, monkeypatch: pytest.MonkeyPatch
) -> None:
    """D-207: a first address that never answers holds the connect until its one deadline,
    then the role answers 502 ``connect_failed`` naming it. The deadline is the connect's, not
    each address's, so the address after it isn't reached (Happy Eyeballs isn't built)."""
    monkeypatch.setattr(connect, "CONNECT_TIMEOUT", 0.3)
    with anyio.fail_after(30):
        async with rig(lists={"vault": [("api.example", 443)]}) as r:
            hole = blackhole(monkeypatch)
            first, second = r.resolver.reserve(), r.resolver.reserve()
            r.resolver.dials.update({first: hole, second: r.echo})
            r.resolver.answer("api.example", [first, second])
            started = time.monotonic()
            assert await refusal(r.port(), "api.example:443") == 502
            waited = time.monotonic() - started
    assert waited >= 0.25
    assert r.resolver.dialled == [(first, 443)]
    [failed] = events(lines, "egress_refused")
    assert (failed["reason"], failed["address"]) == ("connect_failed", first)
    assert events(lines, "egress_tunnel") == []


async def test_one_deadline_bounds_every_address(
    lines: io.StringIO, monkeypatch: pytest.MonkeyPatch
) -> None:
    """D-207: a refused first address, then two blackholed: the second spends what is left of
    the one deadline and the third is never dialled (a deadline per address would wait two and
    dial all three); the refusal names the address being tried when it passed."""
    monkeypatch.setattr(connect, "CONNECT_TIMEOUT", 0.3)
    with anyio.fail_after(30):
        async with rig(lists={"vault": [("api.example", 443)]}) as r:
            hole = blackhole(monkeypatch)
            refusing, second, third = (r.resolver.reserve() for _ in range(3))
            r.resolver.dials.update({second: hole, third: hole})  # no fake at the first
            r.resolver.answer("api.example", [refusing, second, third])
            assert await refusal(r.port(), "api.example:443") == 502
    assert r.resolver.dialled == [(refusing, 443), (second, 443)]
    [failed] = events(lines, "egress_refused")
    assert (failed["reason"], failed["address"]) == ("connect_failed", second)


async def test_bytes_sent_with_the_head_reach_the_destination(lines: io.StringIO) -> None:
    with anyio.fail_after(30):
        async with rig(lists={"vault": [("api.example", 443)]}) as r:
            r.serve("api.example")
            async with tunnel(r.port(), "api.example:443", b"early") as (reader, writer):
                assert await reader.readexactly(5) == b"early"
                assert await echoes(reader, writer)
    [tunnelled] = events(lines, "egress_tunnel")
    assert (tunnelled["bytes_up"], tunnelled["bytes_down"]) == (9, 9)
    assert set(tunnelled) == {
        "ts",
        "role",
        "event",
        "source",
        "host",
        "port",
        "address",
        "result",
        "bytes_up",
        "bytes_down",
        "ms",
    }
    assert tunnelled["role"] == "egress"


# --- the head and the caps ------------------------------------------------------------------------


async def test_a_head_too_large_too_slow_or_malformed(lines: io.StringIO) -> None:
    with anyio.fail_after(30):
        async with rig(lists={"vault": [("api.example", 443)]}, head_timeout=0.2) as r:
            # 8 KiB with no end to the head: all of it read, so the role's close is clean.
            large = b"CONNECT api.example:443 HTTP/1.1\r\nX: "
            large += b"y" * (8192 - len(large))
            assert (await ask(r.port(), large))[0].startswith(b"HTTP/1.1 431 ")
            assert (await ask(r.port(), b"CONNECT api.example:443 HTTP/1.1\r\n"))[0].startswith(
                b"HTTP/1.1 408 "
            )
            assert await refusal(r.port(), "api.example") == 400
            many = b"".join(b"X-%d: v\r\n" % n for n in range(65))
            assert (await ask(r.port(), b"CONNECT api.example:443 HTTP/1.1\r\n" + many + b"\r\n"))[
                0
            ].startswith(b"HTTP/1.1 400 ")
    assert [reason for reason, _ in refused(lines)] == [
        "head_too_large",
        "head_timeout",
        "bad_request",
        "bad_request",
    ]


async def test_the_tunnel_cap_per_listener(lines: io.StringIO) -> None:
    with anyio.fail_after(30):
        async with rig(lists={"vault": [("api.example", 443)]}, max_tunnels=1) as r:
            r.serve("api.example")
            async with tunnel(r.port(), "api.example:443") as (reader, writer):
                assert await echoes(reader, writer)
                assert await refusal(r.port(), "api.example:443") == 503
            await until(lambda: r.role.tunnels.counts["vault"] == 0)
            async with tunnel(r.port(), "api.example:443") as (reader, writer):
                assert await echoes(reader, writer)
    assert refused(lines) == [("busy", "api.example")]


async def test_an_idle_tunnel_is_closed(lines: io.StringIO) -> None:
    with anyio.fail_after(30):
        async with rig(lists={"vault": [("api.example", 443)]}, idle_timeout=0.2) as r:
            r.serve("api.example")
            async with tunnel(r.port(), "api.example:443") as (reader, _):
                assert await reader.read() == b""
    assert [t["result"] for t in events(lines, "egress_tunnel")] == ["idle"]


async def test_stopping_cuts_open_tunnels(lines: io.StringIO) -> None:
    with anyio.fail_after(30):
        async with rig(lists={"vault": [("api.example", 443)]}) as r:
            r.serve("api.example")
            reader, writer = await asyncio.open_connection("127.0.0.1", r.port())
            writer.write(connect_head("api.example:443"))
            await reader.readuntil(b"\r\n\r\n")
        assert await reader.read() == b""
        writer.close()
    assert [t["result"] for t in events(lines, "egress_tunnel")] == ["stopped"]


# --- X17: nothing that reads as OAuth -------------------------------------------------------------


async def test_the_role_offers_agents_no_oauth() -> None:
    """X17: every answer the role makes itself is empty, with no WWW-Authenticate and no
    Proxy-Authenticate; an OAuth path is a 405, before and after the first list."""
    with anyio.fail_after(30):
        async with rig() as r:
            before = [await refusal(r.port(), p, method="GET") for p in OAUTH_PATHS]
            stale = await refusal(r.port(), "auth.example:443")
            await r.publish({"vault": [("lan.example", 443)]})
            r.resolver.answer("lan.example", ["10.0.0.1"])
            after = [
                await refusal(r.port(), p, method=m) for p in OAUTH_PATHS for m in ("GET", "POST")
            ]
            others = [
                await refusal(r.port(), "auth.example:443"),
                await refusal(r.port(), "lan.example:443"),
                await refusal(r.port(), "auth.example"),
            ]
    assert set(before) == set(after) == {405}
    assert (stale, others) == (503, [403, 403, 400])


# --- the listeners (FM-27) ------------------------------------------------------------------------


async def test_unresolved_alias(lines: io.StringIO) -> None:
    """FM-27: a source's alias that doesn't resolve to exactly one address leaves that listener
    unbound (fail closed), logged, and tried again at the next contact."""
    names = Names({"egress-vault": ["127.0.0.1"], "egress-fetch": []})
    listens = ("vault=egress-vault:0", "bridge-fetch=egress-fetch:0")
    lists: dict[str, list[Entry]] = {
        "vault": [("api.example", 443)],
        "bridge-fetch": [("docs.example", 443)],
    }
    with anyio.fail_after(30):
        async with rig(listens=listens, lists=lists, names=names) as r:
            assert set(r.role.bound) == {"vault"}
            names.names["egress-fetch"] = ["127.0.0.1", "127.0.0.2"]
            await r.publish({**lists, "vault": [("api.example", 443), ("more.example", 443)]})
            await until(lambda: len(events(lines, "egress_listen_failed")) == 2)
            assert set(r.role.bound) == {"vault"}
            names.names["egress-fetch"] = ["127.0.0.1"]
            await r.publish(lists)
            await until(lambda: "bridge-fetch" in r.role.bound)
            r.serve("docs.example")
            async with tunnel(r.port("bridge-fetch"), "docs.example:443") as (reader, writer):
                assert await echoes(reader, writer)
    [started] = events(lines, "egress_started")
    assert started["listeners"] == {"vault": f"127.0.0.1:{r.port()}", "bridge-fetch": None}
    failed = events(lines, "egress_listen_failed")
    assert [f["source"] for f in failed] == ["bridge-fetch", "bridge-fetch"]
    assert "resolves to no address" in failed[0]["reason"]
    assert "resolves to 2 addresses" in failed[1]["reason"]
    assert failed[0]["listen"] == "bridge-fetch=egress-fetch:0"
    [bound] = events(lines, "egress_listen_bound")
    assert bound == {**bound, "source": "bridge-fetch"}


async def test_an_alias_lookup_that_raises_or_hangs(
    lines: io.StringIO, monkeypatch: pytest.MonkeyPatch
) -> None:
    """F2, F3: a lookup the IDNA codec refuses leaves the listener unbound, as does one out of
    time; the retry runs beside the long poll, which never waits on it."""
    monkeypatch.setattr(connect, "RESOLVE_TIMEOUT", 2.0)
    names = Names(
        {
            "egress-vault": ["127.0.0.1"],
            "egress-idna": UnicodeError("label empty or too long"),
            "egress-slow": ["127.0.0.1"],
        }
    )
    gate = asyncio.Event()
    names.hold["egress-slow"] = gate
    listens = ("vault=egress-vault:0", "a=egress-idna:0", "b=egress-slow:0")
    lists: dict[str, list[Entry]] = {"vault": [("api.example", 443)]}
    more: dict[str, list[Entry]] = {"vault": [("api.example", 443), ("more.example", 443)]}
    with anyio.fail_after(30):
        async with rig(listens=listens, lists=lists, names=names) as r:
            assert set(r.role.bound) == {"vault"}
            await r.publish(more)  # applied while a retry waits on the lookup
            await r.publish(lists)
            assert "b" not in r.role.bound
            await until(lambda: "b" in {f["source"] for f in events(lines, "egress_listen_failed")})
            del names.hold["egress-slow"]
            await until(lambda: r.role._retry is None or r.role._retry.done())
            await r.publish(more)
            await until(lambda: "b" in r.role.bound)
    reasons = {f["source"]: f["reason"] for f in events(lines, "egress_listen_failed")}
    assert reasons == {"a": "label empty or too long", "b": "TimeoutError"}
    assert "a" not in r.role.bound


@pytest.mark.parametrize(
    ("found", "message"),
    [
        ([], "resolves to no address"),
        (["10.0.1.2", "10.0.2.2"], "resolves to 2 addresses"),
        (["0.0.0.0"], "on every network"),  # noqa: S104 - the refused wildcard
        (["::"], "on every network"),
        (["not-an-address"], "didn't resolve to an address"),
    ],
)
def test_a_listener_binds_one_address_on_one_network(found: list[str], message: str) -> None:
    """MISS-7: a wildcard or a name on several networks would let one source's container
    reach another's listener."""
    spec = listen.parse("vault=egress-vault:3128")
    with pytest.raises(listen.ListenError, match=message):
        listen.choose(spec, found)
    assert listen.choose(spec, ["10.0.1.2", "10.0.1.2"]) == "10.0.1.2"
    assert listen.choose(spec, ["fd00::2"]) == "fd00::2"


def test_listen_values() -> None:
    assert listen.parse("vault=egress-vault:3128") == listen.Listen("vault", "egress-vault", 3128)
    assert listen.parse("bridge-fetch=[fd00::2]:0") == listen.Listen("bridge-fetch", "fd00::2", 0)
    assert listen.parse("bridge-fetch=[fd00::2]:0").text == "bridge-fetch=[fd00::2]:0"
    for bad in (
        "egress-vault:3128",
        "Vault=egress-vault:3128",
        "vault=:3128",
        "vault=egress-vault",
        "vault=egress-vault:70000",
        "vault=egress-vault:31x",
        "=egress-vault:3128",
        "vault=egress..vault:3128",
        "vault=.:3128",
        "vault=" + "a" * 64 + ".example:3128",
        "vault=" + "a." * 127 + "a:3128",
        "vault=b\u00fccher:3128",
        "vault=a b:3128",
    ):
        with pytest.raises(listen.ListenError):
            listen.parse(bad)
    for host in ("a" * 63 + ".example", "egress-vault.", "a." * 126 + "a", "a." * 126 + "a."):
        assert listen.parse(f"vault={host}:3128").host == host
    with pytest.raises(listen.ListenError, match="twice"):
        listen.parse_all(["vault=a:1", "vault=b:2"])
    with pytest.raises(listen.ListenError, match="at least one"):
        listen.parse_all([])
    # The schema's route name rule, copied since the role can't import it.
    assert listen.SOURCE.pattern == NAME_PATTERN.removeprefix("^").removesuffix("$")


def test_the_options_are_checked() -> None:
    key = KeySource(KEY)
    for options, message in [
        (Options("http://vault:8080", ("vault=a:1",), max_tunnels=0), "--max-tunnels"),
        (Options("http://vault:8080", ("vault=a:1",), max_tunnels=1025), "--max-tunnels"),
        (Options("http://vault:8080", ("vault=a:1",), idle_timeout=0), "positive"),
        (Options("http://vault:8080", ("vault=a:1",), max_tunnel_seconds=0), "positive"),
        (Options("http://vault:8080", ()), "at least one"),
        (Options("https://vault:8080", ("vault=a:1",)), "--vault"),
    ]:
        with pytest.raises(StartupError, match=message):
            Role(options, key)
    assert Role(Options("http://vault:8080", ("vault=a:1",), max_tunnels=1024), key)


def test_the_vault_link() -> None:
    assert parse_vault("http://vault:8080") == ("vault", 8080)
    assert parse_vault("http://vault") == ("vault", 80)
    assert parse_vault("http://[fd00::1]:8080/") == ("fd00::1", 8080)
    for bad in (
        "https://vault:8080",
        "vault:8080",
        "http://user@vault:8080",
        "http://vault:8080/x",
        "http://vault:8080?a",
        "http://vault:8080?",
        "http://vault:8080#",
        "http://vault:99999",
    ):
        with pytest.raises(AllowlistError):
            parse_vault(bad)


# --- the document ---------------------------------------------------------------------------------


def doc(**changes: Any) -> bytes:
    made: dict[str, Any] = {
        "v": 1,
        "digest": DIGEST,
        "sources": {
            "vault": [
                {"host": "Auth.Example", "port": 443, "private": False},
                {"host": "fd00::5", "port": 8443, "private": True},
            ],
            "bridge-fetch": [],
        },
    }
    made.update(changes)
    return json.dumps(made).encode()


def entry(**changes: Any) -> bytes:
    made = {"host": "auth.example", "port": 443, "private": False, **changes}
    return doc(sources={"vault": [made]})


def test_a_document_is_parsed_with_netguards_keys() -> None:
    assert parse_document(doc()) == (
        DIGEST,
        {"vault": {"auth.example:443": False, "[fd00::5]:8443": True}, "bridge-fetch": {}},
        0,
    )
    assert parse_document(entry(port=1))[1] == {"vault": {"auth.example:1": False}}
    assert parse_document(entry(port=65535))[1] == {"vault": {"auth.example:65535": False}}


@pytest.mark.parametrize(
    "body",
    [
        b"{",
        b"\xff",
        b"[]",
        doc(v=2),
        doc(v=True),
        doc(v="1"),
        doc(digest="sha256:" + "A" * 64),
        doc(digest="sha256:" + "a" * 63),
        doc(digest=None),
        doc(sources=[]),
        doc(sources={"Vault": []}),
        doc(sources={"vault": {}}),
        doc(sources={"vault": ["auth.example:443"]}),
        doc(sources={"vault": [{"host": "a.example", "port": 1, "private": False}] * 2}),
        entry(host=7),
        entry(host=None),
        entry(port=0),
        entry(port=65536),
        entry(port=True),
        entry(port="443"),
        entry(private=1),
        entry(private=None),
        json.dumps({"digest": DIGEST, "sources": {}}).encode(),
    ],
)
def test_a_document_that_doesnt_parse_is_refused(body: bytes) -> None:
    with pytest.raises(DocumentError):
        parse_document(body)


@pytest.mark.parametrize(
    "host",
    ["", "b\u00fccher.example", "\u2603.example", "[fd00::5]", "a b", "a" * 254, "a" * 253 + ".."],
)
def test_a_host_no_connect_could_name_is_skipped(host: str) -> None:
    """F1: a destination the role would refuse anyway costs no source its list."""
    body = doc(sources={"vault": [{"host": host, "port": 443, "private": False}], "b": []})
    assert parse_document(body) == (DIGEST, {"vault": {}, "b": {}}, 1)
    with pytest.raises(DocumentError, match="port"):
        parse_document(doc(sources={"vault": [{"host": host, "port": 0, "private": False}]}))


def test_a_253_character_name_with_a_trailing_dot_is_a_destination() -> None:
    name = "a" * 253 + "."
    assert parse_document(entry(host=name))[1] == {"vault": {f"{name}:443": False}}


# --- the key --------------------------------------------------------------------------------------


async def test_a_403_rereads_the_key_file_at_most_once_per_10_s(tmp_path: Path) -> None:
    folder = tmp_path / "key"
    folder.mkdir(mode=0o700)
    file = folder / "egress.key"
    file.write_bytes(("zeg1-" + "w" * 43 + "\n").encode())
    clock = Clock()
    key = KeySource(file=file, clock=clock)
    with anyio.fail_after(30):
        async with rig(lists={"vault": []}, key=key, fetched=False) as r:
            await until(lambda: len(r.fake.seen) >= 3)
            file.write_bytes(KEY.encode())
            await until(lambda: len(r.fake.seen) >= 6)
            assert r.role.allowlist.digest is None  # the first 403 re-read; later ones wait
            clock.advance(10)
            await until(lambda: r.role.allowlist.digest == r.fake.digest)
    assert r.fake.seen[-1].key == KEY


def test_the_role_refuses_to_start_without_a_key(monkeypatch: pytest.MonkeyPatch) -> None:
    options = Options("http://vault:8080", ("vault=egress-vault:3128",))
    for environ in ({}, {"ZOEYMCP_EGRESS_KEY": ""}):
        with pytest.raises(StartupError, match="zoeymcp egress-key"):
            build(options, environ)
    with pytest.raises(StartupError, match="zeg1- format"):
        build(options, {"ZOEYMCP_EGRESS_KEY": "zgw1-" + "a" * 43})
    with pytest.raises(StartupError, match="can't be read"):
        build(options, {"ZOEYMCP_EGRESS_KEY_FILE": "/nonexistent/egress.key"})
    assert build(options, {"ZOEYMCP_EGRESS_KEY": KEY}).listens[0].source == "vault"
    monkeypatch.delenv("ZOEYMCP_EGRESS_KEY", raising=False)
    monkeypatch.delenv("ZOEYMCP_EGRESS_KEY_FILE", raising=False)
    out, err = io.StringIO(), io.StringIO()
    argv = ["egress", "--vault", "http://vault:8080", "--listen", "vault=egress-vault:3128"]
    assert cli_main(argv, out=out, err=err) == 2
    assert err.getvalue().startswith("zoeymcp egress: no egress key: set ZOEYMCP_EGRESS_KEY")
    assert "zoeymcp egress-key" in err.getvalue()


async def test_the_key_is_never_logged(lines: io.StringIO) -> None:
    with anyio.fail_after(30):
        async with rig(lists={"vault": [("api.example", 443)]}) as r:
            r.serve("api.example")
            async with tunnel(r.port(), "api.example:443") as (reader, writer):
                assert await echoes(reader, writer)
            assert await refusal(r.port(), "other.example:443") == 403
    assert KEY not in lines.getvalue()
    assert KEY.removeprefix("zeg1-") not in lines.getvalue()
    key = EgressKey(KEY)
    assert KEY not in repr(key)
    with pytest.raises(TypeError, match="EgressKey"):
        logs.Log("egress").event("oops", nested={"key": [key]})
