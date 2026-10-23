"""Where the bridge listens (M7 design C.4, C.8, Q46): the three ``--listen`` forms, the alias
rule restated from ``portal/listen.py`` (exactly one address, never a wildcard), ``--peer-uid``
only with ``unix:``, the socket directory's owner and mode, and the peer's uid as
``SO_PEERCRED`` gives it. No socket is made here; the process tests bind them."""

from __future__ import annotations

import socket
import stat
from collections.abc import Callable, Sequence
from typing import Any

import pytest

from zoeymcp.bridge import listen
from zoeymcp.bridge.listen import (
    LISTEN_FORM,
    UCRED,
    ListenError,
    Tcp,
    Unix,
    check_peer_uid,
    choose,
    directory_refusal,
    parse,
    peer_uid,
    resolve,
)

ALIAS = Tcp("bridge-fetch-mcp", 9000)
ANY4 = "0.0.0.0"  # noqa: S104 - only resolved here, never bound


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def test_the_three_forms() -> None:
    assert parse("bridge-fetch-mcp:9000") == ALIAS
    assert parse("bridge-fetch-mcp.:1") == Tcp("bridge-fetch-mcp.", 1)
    assert parse("127.0.0.1:65535") == Tcp("127.0.0.1", 65535)
    assert parse("[::1]:9000") == Tcp("::1", 9000)
    assert parse("unix:/run/zoeymcp-bridge-fetch/mcp.sock") == Unix(
        "/run/zoeymcp-bridge-fetch/mcp.sock"
    )
    assert Tcp("::1", 9000).text == "[::1]:9000"
    assert ALIAS.text == "bridge-fetch-mcp:9000"
    assert Unix("/run/x.sock").text == "unix:/run/x.sock"


@pytest.mark.parametrize(
    "text",
    [
        "bridge-fetch-mcp",
        ":9000",
        "bridge-fetch-mcp:0",
        "bridge-fetch-mcp:65536",
        "bridge-fetch-mcp:123456",
        "bridge-fetch-mcp:-1",
        "bridge-fetch-mcp:9a",
        "bad name:9000",
        "a..b:9000",
        "a" * 64 + ":9000",
        "[127.0.0.1:9000",
    ],
)
def test_a_malformed_listen_is_refused(text: str) -> None:
    with pytest.raises(ListenError) as caught:
        parse(text)
    assert str(caught.value) == LISTEN_FORM


@pytest.mark.parametrize("text", ["10.0.0.1:9000", "[fd00::1]:9000", f"{ANY4}:9000", "[::]:9000"])
def test_a_literal_must_be_loopback(text: str) -> None:
    with pytest.raises(ListenError, match="is a loopback one"):
        parse(text)


@pytest.mark.parametrize(
    "text", ["unix:mcp.sock", "unix:/run/x/", "unix:/run/../x.sock", "unix:/run//x.sock", "unix:"]
)
def test_a_unix_path_is_absolute_and_normalized(text: str) -> None:
    with pytest.raises(ListenError, match="absolute, normalized path"):
        parse(text)


def test_peer_uid_goes_with_unix_and_only_with_it() -> None:
    check_peer_uid(Unix("/run/x.sock"), 10001)
    check_peer_uid(Unix("/run/x.sock"), 0)
    check_peer_uid(ALIAS, None)
    with pytest.raises(ListenError, match="needs --peer-uid"):
        check_peer_uid(Unix("/run/x.sock"), None)
    with pytest.raises(ListenError, match="only with --listen unix:"):
        check_peer_uid(ALIAS, 10001)
    with pytest.raises(ListenError, match="is a uid"):
        check_peer_uid(Unix("/run/x.sock"), -1)


def test_an_alias_takes_exactly_one_address() -> None:
    assert choose(ALIAS, ["172.30.9.2"]) == "172.30.9.2"
    # Duplicates (one per socket type or family entry) are one address.
    assert choose(ALIAS, ["172.30.9.2", "172.30.9.2"]) == "172.30.9.2"
    assert choose(ALIAS, ["fd00::2"]) == "fd00::2"
    with pytest.raises(ListenError, match="resolves to no address"):
        choose(ALIAS, [])
    with pytest.raises(ListenError, match="resolves to 2 addresses"):
        choose(ALIAS, ["172.30.9.2", "172.30.8.2"])
    with pytest.raises(ListenError, match="didn't resolve to an address"):
        choose(ALIAS, ["not-an-address"])


@pytest.mark.parametrize("wildcard", [ANY4, "::"])
def test_an_alias_never_takes_a_wildcard(wildcard: str) -> None:
    with pytest.raises(ListenError, match="resolves to every address"):
        choose(ALIAS, [wildcard])


def answers(*results: Sequence[str] | OSError) -> Callable[[str], Sequence[str]]:
    """A lookup giving each result in turn (raising an error), then the last one again."""
    left = list(results)

    def lookup(host: str) -> Sequence[str]:
        result = left.pop(0) if len(left) > 1 else left[0]
        if isinstance(result, OSError):
            raise result
        return result

    return lookup


def never(host: str) -> Sequence[str]:
    raise AssertionError(f"{host} was looked up")


@pytest.mark.anyio
async def test_resolve(monkeypatch: pytest.MonkeyPatch) -> None:
    # A literal is its own address, looked up nowhere.
    assert await resolve(Tcp("127.0.0.1", 9000), never) == "127.0.0.1"
    assert await resolve(Tcp("::1", 9000), never) == "::1"
    assert await resolve(ALIAS, answers(["172.30.9.2"])) == "172.30.9.2"
    monkeypatch.setattr(listen, "RESOLVE_EVERY", 0.0)
    # A name that appears later is tried again.
    found = await resolve(ALIAS, answers(OSError("not yet"), OSError("not yet"), ["172.30.9.2"]))
    assert found == "172.30.9.2"
    with pytest.raises(ListenError, match="resolves to 2 addresses"):
        await resolve(ALIAS, answers(["172.30.9.2", "172.30.8.2"]))
    monkeypatch.setattr(listen, "RESOLVE_FOR", 0.0)
    with pytest.raises(ListenError, match="doesn't resolve: gone"):
        await resolve(ALIAS, answers(OSError("gone")))


def test_the_constants() -> None:
    """M7 design C.8: the directory grants others nothing and its group no write."""
    assert (listen.DIRECTORY_MASK, listen.RESOLVE_FOR, listen.RESOLVE_EVERY) == (0o027, 10.0, 0.5)


@pytest.mark.parametrize("mode", [0o700, 0o750, 0o710, 0o740, 0o500])
def test_a_directory_only_its_owner_controls_is_taken(mode: int) -> None:
    assert directory_refusal(10101, stat.S_IFDIR | mode, 10101) is None


@pytest.mark.parametrize("mode", [0o720, 0o701, 0o702, 0o704, 0o770, 0o777, 0o1777])
def test_a_directory_others_can_use_is_refused(mode: int) -> None:
    refusal = directory_refusal(10101, stat.S_IFDIR | mode, 10101)
    assert refusal == f"is mode {mode:04o}; others may have no access, the group no write"


def test_a_directory_another_uid_owns_or_a_file_is_refused() -> None:
    assert (
        directory_refusal(0, stat.S_IFDIR | 0o700, 10101)
        == "is owned by uid 0, not the bridge's 10101"
    )
    assert directory_refusal(10101, stat.S_IFREG | 0o700, 10101) == "isn't a directory"


class Peer:
    """A connected socket as ``getsockopt`` sees it: ``raw`` is what ``SO_PEERCRED`` gives."""

    def __init__(self, raw: Any) -> None:
        self.raw = raw
        self.asked: list[tuple[int, int, int]] = []

    def getsockopt(self, level: int, option: int, size: int) -> Any:
        self.asked.append((level, option, size))
        if isinstance(self.raw, OSError):
            raise self.raw
        return self.raw


def test_the_peers_uid(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "SO_PEERCRED", 17, raising=False)
    peer = Peer(UCRED.pack(4242, 10001, 10001))
    assert peer_uid(peer) == 10001
    assert peer.asked == [(socket.SOL_SOCKET, 17, 12)]
    assert peer_uid(Peer(UCRED.pack(4242, 0, 0))) == 0
    assert peer_uid(None) is None
    assert peer_uid(Peer(OSError("not connected"))) is None
    assert peer_uid(Peer(b"\0" * 8)) is None
    assert peer_uid(Peer(0)) is None
    monkeypatch.delattr(socket, "SO_PEERCRED")
    assert peer_uid(Peer(UCRED.pack(4242, 10001, 10001))) is None
