"""What the egress role decides about one connection (M7 design I.4, X15). Pure and
mutation-tested; :mod:`.tunnel` reads, resolves, connects and copies around these decisions.

1. the request head, at most :data:`HEAD_MAX` bytes, within :data:`HEAD_TIMEOUT`: else 431
   ``head_too_large`` or 408 ``head_timeout``;
2. ``CONNECT host:port HTTP/1.1`` exactly (or HTTP/1.0), headers ignored but counted: 405
   ``not_connect`` for another method, else 400 ``bad_request``;
3. the listener's source has a fresh list: 503 ``list_stale``, or 403 ``no_list`` when the
   vault's document doesn't name the source;
4. ``host:port`` is in it, as written (lower case, ASCII): 403 ``not_allowed``;
5. one lookup, every address allowed (netguard, with the entry's private mark): 502
   ``resolve_failed`` or 403 ``address_refused``;
6. a connect to the checked address: 502 ``connect_failed``;
7. ``200 Connection established``, within the tunnel caps: 503 ``busy``.

Every answer the role makes itself is :func:`answer`'s: ``Content-Length: 0``, no
``WWW-Authenticate``, no ``Proxy-Authenticate`` and no body, so nothing in it reads as OAuth
(X17). Every pattern is used with ``fullmatch``.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final, Literal

from ..common import netguard

# M7 design M.6.
HEAD_MAX: Final = 8 * 1024
HEAD_TIMEOUT: Final = 10.0
RESOLVE_TIMEOUT: Final = 5.0
CONNECT_TIMEOUT: Final = 10.0
HEADERS_MAX: Final = 64
TUNNELS_PER_LISTENER: Final = 256
TUNNELS_MAX: Final = 1024
IDLE_TIMEOUT: Final = 900.0
TUNNEL_MAX_SECONDS: Final = 86400.0

Reason = Literal[
    "head_too_large",
    "head_timeout",
    "not_connect",
    "bad_request",
    "list_stale",
    "no_list",
    "not_allowed",
    "resolve_failed",
    "address_refused",
    "connect_failed",
    "busy",
]
STATUS: Final[Mapping[Reason, int]] = {
    "head_too_large": 431,
    "head_timeout": 408,
    "not_connect": 405,
    "bad_request": 400,
    "list_stale": 503,
    "no_list": 403,
    "not_allowed": 403,
    "resolve_failed": 502,
    "address_refused": 403,
    "connect_failed": 502,
    "busy": 503,
}
_PHRASES: Final = {
    400: "Bad Request",
    403: "Forbidden",
    405: "Method Not Allowed",
    408: "Request Timeout",
    431: "Request Header Fields Too Large",
    502: "Bad Gateway",
    503: "Service Unavailable",
}
ESTABLISHED: Final = b"HTTP/1.1 200 Connection established\r\n\r\n"
_END: Final = b"\r\n\r\n"
_VERSIONS: Final = ("HTTP/1.1", "HTTP/1.0")
# RFC 9110 5.6.2's token: a method that isn't CONNECT is 405, anything else in its place is 400.
_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_PORT = re.compile(r"[0-9]{1,5}")
# An ASCII name as a CONNECT target writes it, 253 characters and a trailing dot at most. A
# non-ASCII one is step 4's (403), not a 400.
_NAME = re.compile(r"[A-Za-z0-9._-]{1,253}\.?")

# One source's list: each destination's netguard.entry_key, and whether it may be private.
SourceList = Mapping[str, bool]
Lists = Mapping[str, SourceList]


@dataclass(frozen=True)
class Refusal:
    """A connection refused at one of the steps; ``verdict`` is netguard's, for
    ``address_refused``."""

    reason: Reason
    verdict: str | None = None

    @property
    def status(self) -> int:
        return STATUS[self.reason]


@dataclass(frozen=True)
class Target:
    """A CONNECT's ``host:port``: the host without brackets, as the client wrote it."""

    host: str
    port: int

    @property
    def key(self) -> str:
        return netguard.entry_key(self.host, self.port)


def answer(status: int) -> bytes:
    """The whole answer for a refusal: a status line, ``Content-Length: 0``, ``Allow: CONNECT``
    on a 405, and nothing else."""
    lines = [f"HTTP/1.1 {status} {_PHRASES[status]}", "Content-Length: 0", "Connection: close"]
    if status == 405:
        lines.append("Allow: CONNECT")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")


def split_head(buffer: bytes) -> tuple[bytes, bytes] | Refusal | None:
    """The request head (through its blank line) and the bytes after it, once ``buffer`` holds
    a head of at most :data:`HEAD_MAX` bytes; ``head_too_large`` once it can't; else None (read
    more)."""
    end = buffer.find(_END, 0, HEAD_MAX)
    if end >= 0:
        return buffer[: end + len(_END)], buffer[end + len(_END) :]
    if len(buffer) >= HEAD_MAX:
        return Refusal("head_too_large")
    return None


def parse_head(head: bytes) -> Target | Refusal:
    """Step 2: ``CONNECT host:port HTTP/1.1``, one space apart, with at most
    :data:`HEADERS_MAX` header lines and no bare CR or LF anywhere."""
    lines = head.removesuffix(_END).decode("latin-1").split("\r\n")
    request, headers = lines[0], lines[1:]
    parts = request.split(" ")
    if parts[0] != "CONNECT":
        return Refusal("not_connect" if _TOKEN.fullmatch(parts[0]) else "bad_request")
    if len(parts) != 3 or parts[2] not in _VERSIONS or len(headers) > HEADERS_MAX:
        return Refusal("bad_request")
    if any("\r" in line or "\n" in line for line in lines):
        return Refusal("bad_request")
    return _target(parts[1])


def _target(text: str) -> Target | Refusal:
    """An authority-form target: ``name:port``, ``a.b.c.d:port`` or ``[v6]:port``."""
    host, sep, port = text.rpartition(":")
    if not sep or not _PORT.fullmatch(port) or not 0 < int(port) < 65536:
        return Refusal("bad_request")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
        try:
            ipaddress.IPv6Address(host)
        except ValueError:
            return Refusal("bad_request")
    elif host.isascii() and not _NAME.fullmatch(host):
        return Refusal("bad_request")
    return Target(host, int(port))


def admit(lists: Lists | None, source: str, target: Target) -> bool | Refusal:
    """Steps 3 and 4: the destination's private mark, or why it is refused. ``lists`` is None
    while there is no fresh list (none yet, or none fetched within the last 300 s)."""
    if lists is None:
        return Refusal("list_stale")
    entries = lists.get(source)
    if entries is None:
        return Refusal("no_list")
    if not target.host.isascii() or not netguard.listed(entries, target.host, target.port):
        return Refusal("not_allowed")
    return entries[target.key]


def address(addresses: Sequence[str], private: bool) -> str | Refusal:
    """Step 5: the address to connect to, if every address the lookup answered is allowed."""
    verdict = netguard.addresses_allowed(addresses, private_ok=private)
    if not verdict.allowed:
        return Refusal("address_refused", verdict.reason)
    return str(verdict.address)  # the first address: allowed, so there is one


def has_room(listener: int, total: int, per_listener: int) -> bool:
    """Whether one more tunnel fits: ``listener`` tunnels on this listener and ``total`` in all
    are open or being opened."""
    return listener < per_listener and total < TUNNELS_MAX


def still_listed(lists: Lists | None, source: str, key: str) -> bool:
    """Whether an open tunnel's destination is still in its source's list. A list gone stale
    keeps it: staleness refuses new tunnels only (X15)."""
    if lists is None:
        return True
    return key in lists.get(source, {})
