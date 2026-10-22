"""Where each of the egress role's listeners binds (M7 design I.4, MISS-7, FM-27).

``--listen SOURCE=NAME:PORT`` gives one source's listener. ``NAME`` is, in a deployment, the
role's network alias on that source's network; it must resolve to **exactly one** address, the
``portal/listen.py`` rule restated here (the role may import neither the portal nor the vault),
so the listener lands on that one network and a container on another source's network can't
reach it by address. A wildcard address would put it on every network, so it is refused, by
name or as a literal. A name that resolves to no address or to several leaves that listener
unbound, which refuses its source's tunnels (fail closed); the role tries it again at its next
contact with the vault.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Final

# A source is "vault" or a route's name: the schema's NAME_PATTERN, copied because the role may
# not import the policy code; test_egress_role.py pins them equal.
SOURCE = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}")
_PORT = re.compile(r"[0-9]{1,5}")
# One label of an alias: what a lookup takes without IDNA refusing it (1 to 63 ASCII characters).
_LABEL = re.compile(r"[A-Za-z0-9_-]{1,63}")
LISTEN_FORM: Final = "SOURCE=NAME:PORT"


class ListenError(ValueError):
    """A ``--listen`` value, or the address its name resolves to, can't be used. The message is
    safe to print and log."""


@dataclass(frozen=True)
class Listen:
    """One ``--listen``: the source, the host without brackets, and the port."""

    source: str
    host: str
    port: int

    @property
    def text(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.source}={host}:{self.port}"


def parse(text: str) -> Listen:
    """``SOURCE=NAME:PORT``; ``NAME`` is a host name a lookup takes, or an IP literal (an IPv6
    one in brackets)."""
    source, sep, rest = text.partition("=")
    if not sep or not SOURCE.fullmatch(source):
        raise ListenError(f"--listen is {LISTEN_FORM}, the source a vault or route name")
    host, sep, port = rest.rpartition(":")
    if not sep or not host or not _PORT.fullmatch(port) or int(port) > 65535:
        raise ListenError(f"--listen {source}= needs NAME:PORT, the port 0 to 65535")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if literal(host) is None and not _is_name(host):
        raise ListenError(f"--listen {source}= needs a host name or an IP address as NAME")
    return Listen(source, host, int(port))


def _is_name(host: str) -> bool:
    """A host name of at most 253 characters (and a trailing dot), each label 1 to 63."""
    name = host.removesuffix(".")
    return len(name) <= 253 and all(_LABEL.fullmatch(label) for label in name.split("."))


def parse_all(texts: Iterable[str]) -> tuple[Listen, ...]:
    """Every ``--listen``, each source once."""
    found: dict[str, Listen] = {}
    for text in texts:
        listen = parse(text)
        if listen.source in found:
            raise ListenError(f"--listen names the source {listen.source} twice")
        found[listen.source] = listen
    if not found:
        raise ListenError(f"give at least one --listen {LISTEN_FORM}")
    return tuple(found.values())


def literal(host: str) -> str | None:
    """The address ``host`` writes, or None for a name."""
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return None


def choose(listen: Listen, found: Sequence[str]) -> str:
    """The one address to bind, from what ``listen``'s name resolved to (its own address for a
    literal): exactly one, and not a wildcard."""
    addresses = list(dict.fromkeys(found))
    if len(addresses) != 1:
        count = "no address" if not addresses else f"{len(addresses)} addresses"
        raise ListenError(
            f"{listen.source}'s name {listen.host} resolves to {count}; give a name on one "
            "network, which resolves to one address"
        )
    address = literal(addresses[0])
    if address is None:
        raise ListenError(f"{listen.source}'s name {listen.host} didn't resolve to an address")
    if ipaddress.ip_address(address).is_unspecified:
        raise ListenError(
            f"{listen.source}'s listener would be on every network ({address}); give the "
            "role's address on that source's network"
        )
    return address
