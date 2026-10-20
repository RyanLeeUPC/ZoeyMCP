"""Where the portal listens (M5 design B.2, B.3, O.2 ``listen``; verifier V47): one, none and
several addresses, with name resolution injected; the clashes with ``--listen``; the warning."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence

import pytest

from zoeymcp.portal.listen import (
    RESOLVE_EVERY,
    RESOLVE_FOR,
    Address,
    ListenError,
    conflict,
    is_wildcard,
    literal,
    resolve,
    shared,
    split,
)

# The IPv4 wildcard, as a policy writes it: only resolved here, never bound.
ANY4 = "0.0.0.0"  # noqa: S104


def names(table: Mapping[str, Sequence[str]]) -> Callable[[str], Sequence[str]]:
    """A resolver that knows ``table`` and raises for any other name, as getaddrinfo does."""

    def lookup(host: str) -> Sequence[str]:
        if host not in table:
            raise OSError(f"unknown name {host}")
        return table[host]

    return lookup


def nothing(host: str) -> Sequence[str]:
    raise AssertionError(f"{host} was looked up")


def test_the_retry_constants() -> None:
    assert (RESOLVE_FOR, RESOLVE_EVERY) == (10.0, 0.5)


@pytest.mark.parametrize(
    ("listen", "host", "port"),
    [
        ("127.0.0.1:8081", "127.0.0.1", 8081),
        ("[::1]:8081", "::1", 8081),
        ("[::]:1", "::", 1),
        ("vault-portal:8081", "vault-portal", 8081),
        (":8081", "", 8081),
    ],
)
def test_split(listen: str, host: str, port: int) -> None:
    assert split(listen) == (host, port)


def test_literal_and_wildcard() -> None:
    assert str(literal("127.0.0.1")) == "127.0.0.1"
    assert str(literal("::1")) == "::1"
    assert literal("vault-portal") is None
    assert literal("") is None
    for host in (ANY4, "::", "0:0::0", ""):
        assert is_wildcard(host), host
    for host in ("127.0.0.1", "::1", "vault-portal", "0.0.0.1"):
        assert not is_wildcard(host), host


@pytest.mark.parametrize(
    ("listen", "address", "wildcard"),
    [
        ("127.0.0.1:8081", "127.0.0.1", False),
        ("172.20.0.3:8081", "172.20.0.3", False),
        ("0.0.0.0:8081", ANY4, True),
        ("[::]:8081", "::", True),
        ("[::1]:8081", "::1", False),
        ("[0:0::1]:8081", "::1", False),  # written another way, bound as itself
    ],
)
def test_an_ip_literal_binds_itself(listen: str, address: str, wildcard: bool) -> None:
    found = resolve(listen, nothing)
    host, port = split(listen)
    assert found == Address(listen, host, port, address, wildcard)


def test_a_name_with_one_address() -> None:
    found = resolve("vault-portal:8081", names({"vault-portal": ["172.20.0.3"]}))
    assert found == Address("vault-portal:8081", "vault-portal", 8081, "172.20.0.3", False)


def test_a_name_whose_answers_repeat_one_address() -> None:
    # getaddrinfo answers once per socket type and protocol; one address is one address.
    lookup = names({"vault-portal": ["172.20.0.3", "172.20.0.3"]})
    assert resolve("vault-portal:8081", lookup).address == "172.20.0.3"


def test_a_name_with_several_addresses_is_refused_naming_the_count() -> None:
    lookup = names(
        {"vault-portal": ["172.20.0.3", "172.21.0.4"], "localhost": ["::1", "127.0.0.1"]}
    )
    message = (
        "admin.listen's name vault-portal resolves to 2 addresses; give one address, or a name "
        "on one network"
    )
    with pytest.raises(ListenError) as refused:
        resolve("vault-portal:8081", lookup)
    assert str(refused.value) == message
    with pytest.raises(ListenError, match="name localhost resolves to 2 addresses"):
        resolve("localhost:8081", lookup)


def test_a_name_with_no_address_is_refused() -> None:
    with pytest.raises(
        ListenError, match=r"^admin\.listen's name vault-portal resolves to no address;"
    ):
        resolve("vault-portal:8081", names({"vault-portal": []}))


def test_a_name_that_doesnt_resolve_is_the_callers_to_retry() -> None:
    with pytest.raises(OSError, match="unknown name"):
        resolve("vault-portal:8081", names({}))


def test_a_name_that_resolves_to_a_wildcard_is_one() -> None:
    assert resolve("any:8081", names({"any": [ANY4]})).wildcard


# --- beside the proxy's --listen ---------------------------------------------------------------


def portal(listen: str, lookup: Callable[[str], Sequence[str]] = nothing) -> Address:
    return resolve(listen, lookup)


@pytest.mark.parametrize(
    ("admin", "listens", "reason"),
    [
        ("127.0.0.1:8081", ["127.0.0.1:8081"], "is --listen 127.0.0.1:8081's address"),
        ("[::1]:8081", ["[0::1]:8081"], "is --listen [0::1]:8081's address"),
        ("127.0.0.1:8081", ["0.0.0.0:8081"], "and --listen 0.0.0.0:8081 share port 8081"),
        ("127.0.0.1:8081", ["[::]:8081"], "and --listen [::]:8081 share port 8081"),
        ("127.0.0.1:8081", [":8081"], "and --listen :8081 share port 8081"),
        ("0.0.0.0:8080", ["127.0.0.1:8080"], "and --listen 127.0.0.1:8080 share port 8080"),
        ("[::]:8080", ["0.0.0.0:8080", "[::]:8080"], "and --listen 0.0.0.0:8080 share port 8080"),
    ],
)
def test_a_clash_with_the_proxy_is_refused(admin: str, listens: list[str], reason: str) -> None:
    assert conflict(portal(admin), listens, nothing) == f"admin.listen {admin} {reason}"


def test_a_proxy_name_is_resolved_for_the_comparison() -> None:
    lookup = names({"localhost": ["::1", "127.0.0.1"], "elsewhere": ["10.0.0.9"]})
    found = conflict(portal("127.0.0.1:8081"), ["localhost:8081"], lookup)
    assert found == "admin.listen 127.0.0.1:8081 is --listen localhost:8081's address"
    assert conflict(portal("127.0.0.1:8081"), ["elsewhere:8081"], lookup) is None
    # One that doesn't resolve is left to its own bind, which names it.
    assert conflict(portal("127.0.0.1:8081"), ["nowhere:8081"], lookup) is None
    junk = names({"junk": ["not an address"]})
    assert conflict(portal("127.0.0.1:8081"), ["junk:8081"], junk) is None


@pytest.mark.parametrize(
    ("admin", "listens"),
    [
        ("127.0.0.1:8081", []),
        ("127.0.0.1:8081", ["127.0.0.1:8080"]),
        ("127.0.0.1:8081", ["0.0.0.0:8080", "[::]:8080"]),  # the entrypoint's pair
        ("0.0.0.0:8081", ["0.0.0.0:8080", "[::]:8080"]),
        ("127.0.0.2:8080", ["127.0.0.1:8080"]),  # another address, the same port
    ],
)
def test_no_clash(admin: str, listens: list[str]) -> None:
    assert conflict(portal(admin), listens, nothing) is None


def test_a_wildcard_beside_the_proxy_is_shared() -> None:
    assert shared(portal("0.0.0.0:8081"), ["0.0.0.0:8080"])
    assert shared(portal("[::]:8081"), ["127.0.0.1:8080"])
    assert not shared(portal("0.0.0.0:8081"), [])
    assert not shared(portal("127.0.0.1:8081"), ["0.0.0.0:8080"])


def test_a_names_address_is_normalized() -> None:
    assert resolve("v6:8081", names({"v6": ["0:0::1"]})).address == "::1"
