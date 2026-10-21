"""Address and host decisions for every connection the vault makes to a place it learned or was
told about (M7 design B.1). Pure and mutation-tested; the egress role, the vault's guarded
transport and the allowlist emitter all ask this one module, so their answers can't drift.

- :func:`classify` and :func:`addresses_allowed`: the connect-time rule (X3). Every address a
  name resolves to must be global, unless the destination is listed in ``egress_private``; an
  empty answer, an unparsable one or any denied address refuses the whole name, so a resolver
  that mixes one global answer with one private answer gets nothing. IPv4-mapped and
  IPv4-compatible forms, and NAT64's ``64:ff9b::/96``, are judged by the IPv4 address they carry;
  6to4 and Teredo are refused whole.
- :func:`untrusted_host`: X2's host rules for a URL learned from the network, before any DNS.
- :func:`entry_key`, :func:`listed`: the ``host:port`` form every egress list compares as written.
  The function is ``listed``, not ``match``, so the source test that bans a call of that name
  (test_source_hygiene.py) never meets it.
- :func:`squid_private_dst`: the emitted ``zoeymcp_private_dst`` ACL, from the same tables.

The tables are explicit, so the decision doesn't move with the standard library's own; a global
address must also be ``is_global`` to it, a second, independent opinion. This module imports the
standard library only: the egress role may import nothing else. Every pattern is used with
``fullmatch``.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Collection, Sequence
from dataclasses import dataclass
from typing import Final, Literal

AddressClass = Literal[
    "global",
    "loopback",
    "private",
    "cgnat",
    "link_local",
    "multicast",
    "reserved",
    "unspecified",
    "documentation",
    "benchmark",
    "embedded",
]

_V4_CLASSES: Final[tuple[tuple[str, AddressClass], ...]] = (
    ("0.0.0.0/8", "unspecified"),
    ("10.0.0.0/8", "private"),
    ("100.64.0.0/10", "cgnat"),
    ("127.0.0.0/8", "loopback"),
    ("169.254.0.0/16", "link_local"),
    ("172.16.0.0/12", "private"),
    ("192.0.0.0/24", "reserved"),
    ("192.0.2.0/24", "documentation"),
    ("192.88.99.0/24", "reserved"),
    ("192.168.0.0/16", "private"),
    ("198.18.0.0/15", "benchmark"),
    ("198.51.100.0/24", "documentation"),
    ("203.0.113.0/24", "documentation"),
    ("224.0.0.0/4", "multicast"),
    ("240.0.0.0/4", "reserved"),
    ("255.255.255.255/32", "reserved"),
)
# The mapped and compatible rows are judged by their IPv4 address before this table is read. The
# compatible row is here for the emitted Squid rule, which refuses it whole; that rule leaves the
# mapped row out, since Squid holds every IPv4 address in that form (squid_private_dst).
_V6_CLASSES: Final[tuple[tuple[str, AddressClass], ...]] = (
    ("::/128", "unspecified"),
    ("::1/128", "loopback"),
    ("::ffff:0:0/96", "embedded"),
    ("::/96", "embedded"),
    ("64:ff9b:1::/48", "embedded"),
    ("100::/64", "reserved"),
    ("2001::/32", "embedded"),
    ("2001:db8::/32", "documentation"),
    ("2002::/16", "embedded"),
    ("fc00::/7", "private"),
    ("fe80::/10", "link_local"),
    ("fec0::/10", "private"),
    ("ff00::/8", "multicast"),
)
DENIED_V4: Final = tuple(net for net, _ in _V4_CLASSES)
DENIED_V6: Final = tuple(net for net, _ in _V6_CLASSES)
_V4_NETS: Final = tuple((ipaddress.IPv4Network(net), kind) for net, kind in _V4_CLASSES)
_V6_NETS: Final = tuple((ipaddress.IPv6Network(net), kind) for net, kind in _V6_CLASSES)
_COMPATIBLE: Final = ipaddress.IPv6Network("::/96")
_MAPPED: Final = ipaddress.IPv6Network("::ffff:0:0/96")
_NAT64: Final = ipaddress.IPv6Network("64:ff9b::/96")
# The (row, network) pairs squid_private_dst reads, built here so its body holds no `zip`
# whose `strict` a mutant could drop unseen: the tables always pair up. The mapped row is out.
_SQUID_V4_ROWS: Final = tuple((t, n) for t, (n, _) in zip(DENIED_V4, _V4_NETS, strict=True))
_SQUID_V6_ROWS: Final = tuple(
    (t, n) for t, (n, _) in zip(DENIED_V6, _V6_NETS, strict=True) if n != _MAPPED
)

# Names that only mean something inside a network (X2), each matched as the whole name or a
# suffix after a dot. Single-label names are refused on their own.
INTERNAL_SUFFIXES: Final = (
    "localhost",
    "local",
    "internal",
    "lan",
    "home.arpa",
    "corp",
    "intranet",
    "invalid",
    "test",
)
# The schema's host name syntax (schema._HOSTNAME) and numeric label (fields._NUMERIC_LABEL),
# copied because this module may import only the standard library; test_netguard.py pins them
# equal. A label browsers parse as a number is WHATWG URL's "ends in a number".
_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)
_NUMERIC_LABEL = re.compile(r"[0-9]+|0x[0-9a-f]*")


@dataclass(frozen=True)
class AddressVerdict:
    """``allowed``, and why: ``global`` or ``private_ok`` when allowed; ``no_address``,
    ``unparsable`` or the refused address's class when not. ``address`` is the first address when
    allowed (the one to connect to) and the one that refused otherwise."""

    allowed: bool
    reason: str
    address: str | None


@dataclass(frozen=True)
class HostVerdict:
    """``allowed``, and why not: ``not_ascii``, ``ip_literal``, ``syntax``, ``numeric_label``,
    ``single_label`` or ``internal_suffix``. ``host`` is the name in lower case."""

    allowed: bool
    reason: str
    host: str


def _embedded(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """The IPv4 address a mapped, compatible or NAT64 address carries."""
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip in _COMPATIBLE and int(ip) > 1:  # :: and ::1 are their own rows
        return ipaddress.IPv4Address(int(ip))
    if ip in _NAT64:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def _classify_v4(ip: ipaddress.IPv4Address) -> AddressClass:
    for net, kind in _V4_NETS:
        if ip in net:
            return kind
    return "global" if ip.is_global else "reserved"


def classify(address: str) -> AddressClass:
    """The class of one IP address; a ``ValueError`` for text that isn't one, a scoped IPv6
    address (``fe80::1%eth0``) included."""
    ip = ipaddress.ip_address(address)
    if isinstance(ip, ipaddress.IPv4Address):
        return _classify_v4(ip)
    if ip.scope_id is not None:
        raise ValueError(f"a scoped address: {address!r}")
    inner = _embedded(ip)
    if inner is not None:
        kind = _classify_v4(inner)
        return kind if kind != "global" or ip.is_global else "reserved"
    for net, found in _V6_NETS:
        if ip in net:
            return found
    return "global" if ip.is_global else "reserved"


def addresses_allowed(addresses: Sequence[str], *, private_ok: bool) -> AddressVerdict:
    """Whether a name whose resolver answered ``addresses`` may be connected to. Every address
    must be global, or ``private_ok`` (the destination is in ``egress_private``)."""
    if not addresses:
        return AddressVerdict(allowed=False, reason="no_address", address=None)
    reason = "global"
    for address in addresses:
        try:
            kind = classify(address)
        except ValueError:
            return AddressVerdict(allowed=False, reason="unparsable", address=address)
        if kind != "global":
            if not private_ok:
                return AddressVerdict(allowed=False, reason=kind, address=address)
            reason = "private_ok"
    return AddressVerdict(allowed=True, reason=reason, address=addresses[0])


def _is_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.removeprefix("[").removesuffix("]"))
    except ValueError:
        return False
    return True


def untrusted_host(host: str) -> HostVerdict:
    """X2's host rules for a URL learned from the network: an ASCII DNS name, in lower case, of
    at least two labels, whose last label isn't numeric, outside :data:`INTERNAL_SUFFIXES`, and
    not an IP literal."""
    if not host.isascii():
        return HostVerdict(allowed=False, reason="not_ascii", host=host)
    name = host.lower()
    if _is_literal(name):
        return HostVerdict(allowed=False, reason="ip_literal", host=name)
    if not _HOSTNAME.fullmatch(name):
        return HostVerdict(allowed=False, reason="syntax", host=name)
    labels = name.split(".")
    if _NUMERIC_LABEL.fullmatch(labels[-1]):
        return HostVerdict(allowed=False, reason="numeric_label", host=name)
    if len(labels) < 2:
        return HostVerdict(allowed=False, reason="single_label", host=name)
    if any(name == suffix or name.endswith("." + suffix) for suffix in INTERNAL_SUFFIXES):
        return HostVerdict(allowed=False, reason="internal_suffix", host=name)
    return HostVerdict(allowed=True, reason="allowed", host=name)


def entry_key(host: str, port: int) -> str:
    """``host:port`` as egress lists write it: the host (without brackets, as urlsplit gives it)
    in lower case, an IPv6 address in brackets."""
    host = host.lower()
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def listed(entries: Collection[str], host: str, port: int) -> bool:
    """Whether ``host:port`` is in ``entries``, compared as written: an IP literal is listed
    only literally, never by a name that resolves to it."""
    return entry_key(host, port) in entries


def squid_private_dst() -> tuple[str, ...]:
    """The entries of the emitted ``zoeymcp_private_dst`` ACL: both tables' rows as written, in
    table order, less two kinds. Squid holds an IPv4 address as IPv4-mapped (``::ffff:a.b.c.d``),
    so a ``dst`` entry for ``::ffff:0:0/96`` would match every IPv4 destination: it is left out,
    and the IPv4 rows, which Squid holds in that same form, judge a mapped answer by the IPv4
    address it carries, as :func:`classify` does. A row inside another row (``::1/128`` inside
    ``::/96``) is left out too: Squid would warn about it and ignore it. Those two rules are why
    no mapped or compatible form of an IPv4 row is written out either: Squid holds the first as
    the row itself, and ``::/96`` holds every one of the second."""
    return (*_outermost(_SQUID_V4_ROWS), *_outermost(_SQUID_V6_ROWS))


def _outermost[Net: (ipaddress.IPv4Network, ipaddress.IPv6Network)](
    rows: Sequence[tuple[str, Net]],
) -> list[str]:
    """The rows no other row holds."""
    return [text for text, net in rows if not any(o != net and net.subnet_of(o) for _, o in rows)]
