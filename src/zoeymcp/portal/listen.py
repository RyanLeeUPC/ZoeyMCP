"""Where the portal listens (M5 design B.2, B.3, Q17). Pure: name resolution is passed in.

``admin.listen`` is an IP literal, which binds itself; a wildcard (``0.0.0.0`` or ``::``), which
binds every address; or a name, which must resolve to **exactly one** address. The hardened tier
names a network alias the vault has on ``egress`` only, so the listener lands on that one network
and on no other; a name on two networks would put the portal on both, so it is refused, naming
the count.

The portal can't share an address with the proxy's ``--listen``: an equal address, or the same
port with a wildcard on either side, is refused. On Linux two sockets with ``SO_REUSEADDR`` may
both bind one address and fail only when the second listens, inside uvicorn, so the check can't
be left to the bind. A wildcard ``admin.listen`` beside any ``--listen`` is allowed but warned
about (``admin_listener_shared``): the portal is then on every address the proxy is.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Final

# How long the vault retries a name that doesn't resolve yet (a network alias appears when the
# container joins its network), and how long it waits between tries, in seconds.
RESOLVE_FOR: Final = 10.0
RESOLVE_EVERY: Final = 0.5

# A name's addresses, as the resolver answers them; may raise OSError.
Lookup = Callable[[str], Sequence[str]]


class ListenError(Exception):
    """``admin.listen`` can't be used; the message says why and is safe to print."""


@dataclass(frozen=True)
class Address:
    """``admin.listen`` resolved: ``listen`` as the policy writes it, ``host`` without brackets,
    and ``address``, the one IP address to bind."""

    listen: str
    host: str
    port: int
    address: str
    wildcard: bool


def split(listen: str) -> tuple[str, int]:
    """``host:port`` or ``[ipv6]:port`` into the host, without brackets, and the port."""
    host, _, port = listen.rpartition(":")
    return host.removeprefix("[").removesuffix("]"), int(port)


def literal(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """The IP address ``host`` writes, or None for a name."""
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def is_wildcard(host: str) -> bool:
    """``0.0.0.0``, ``::`` (in any spelling), or no host at all: every address."""
    ip = literal(host)
    return host == "" or (ip is not None and ip.is_unspecified)


def resolve(listen: str, lookup: Lookup) -> Address:
    """``admin.listen`` as one address to bind. ``lookup`` answers a name's addresses; a name
    that resolves to none or to several is refused. A ``lookup`` that raises is the caller's to
    retry (:data:`RESOLVE_FOR`)."""
    host, port = split(listen)
    ip = literal(host)
    if ip is not None:
        return Address(listen, host, port, str(ip), ip.is_unspecified)
    found = list(dict.fromkeys(lookup(host)))
    if len(found) != 1:
        count = "no address" if not found else f"{len(found)} addresses"
        raise ListenError(
            f"admin.listen's name {host} resolves to {count}; give one address, or a name on "
            "one network"
        )
    address = str(ipaddress.ip_address(found[0]))
    return Address(listen, host, port, address, is_wildcard(address))


def conflict(portal: Address, listens: Sequence[str], lookup: Lookup) -> str | None:
    """Why the portal can't listen beside the proxy's ``listens``, or None. ``lookup`` answers a
    ``--listen`` name's addresses; one that can't be resolved is left to its bind."""
    for listen in listens:
        host, port = split(listen)
        if port != portal.port:
            continue
        if portal.wildcard or is_wildcard(host):
            return f"admin.listen {portal.listen} and --listen {listen} share port {port}"
        if portal.address in _addresses(host, lookup):
            return f"admin.listen {portal.listen} is --listen {listen}'s address"
    return None


def shared(portal: Address, listens: Sequence[str]) -> bool:
    """A wildcard portal beside the proxy's listeners: worth a warning, not a refusal."""
    return portal.wildcard and bool(listens)


def _addresses(host: str, lookup: Lookup) -> set[str]:
    ip = literal(host)
    if ip is not None:
        return {str(ip)}
    try:
        found = lookup(host)
    except OSError:
        return set()
    return {str(address) for address in (literal(a) for a in found) if address is not None}
