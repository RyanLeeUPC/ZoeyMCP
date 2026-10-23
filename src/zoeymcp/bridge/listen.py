"""Where the bridge listens (M7 design C.2, C.4, C.8, C.10, Q46).

``--listen`` is one of three forms:

- **an alias**, ``NAME:PORT``: the hardened tier's ``bridge-<name>-mcp`` alias, declared on the
  bridge's own network only. It must resolve to **exactly one** address, which is never a
  wildcard, so the listener lands on that one network (the rule of ``portal/listen.py``,
  restated here because the bridge may import neither the portal nor the vault);
- **a loopback literal**, ``127.0.0.1:PORT`` or ``[::1]:PORT``: a remote bridge behind the
  operator's own TLS front;
- **a Unix socket**, ``unix:<absolute path>``: the standard tier's
  ``/run/zoeymcp-bridge-<name>/mcp.sock``. ``--peer-uid`` is then required, and refused with any
  other form. The socket's directory must exist, be the bridge's own uid's, and grant others
  nothing and its group no write (``mode & 0o027 == 0``), since a directory another uid controls
  could hand the socket to someone else; a stale socket at the path is removed and any other
  entry refused. uvicorn's ``uds=`` makes the socket 0666, so the directory is the gate.

On the socket, every connection's peer uid (``SO_PEERCRED``) is checked before anything is read
(:func:`peer_checked`, as ``vault/peer.py`` does for the gateway): a connection from any uid but
``--peer-uid`` (the vault's) is aborted in ``connection_made`` and logged ``bridge_peer_refused``.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import posixpath
import re
import socket
import stat
import struct
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, Final

from uvicorn.protocols.http.h11_impl import H11Protocol

from . import event

UNIX_PREFIX: Final = "unix:"
# A refused directory: group write or any access for others (C.8).
DIRECTORY_MASK: Final = 0o027
# How long a name that doesn't resolve yet is tried again (an alias appears once the container is
# on its network), and the pause between tries, in seconds.
RESOLVE_FOR: Final = 10.0
RESOLVE_EVERY: Final = 0.5
LISTEN_FORM: Final = (
    "--listen is a network alias NAME:PORT, a loopback address such as 127.0.0.1:9000, or "
    "unix:<absolute path>"
)
# struct ucred on Linux: pid_t pid, uid_t uid, gid_t gid.
UCRED: Final = struct.Struct("=iII")

_PORT = re.compile(r"[0-9]{1,5}")
_LABEL = re.compile(r"[A-Za-z0-9_-]{1,63}")

# A name's addresses; may raise OSError.
Lookup = Callable[[str], Sequence[str]]


class ListenError(ValueError):
    """``--listen`` or ``--peer-uid`` can't be used; the message is safe to print and log."""


@dataclass(frozen=True)
class Tcp:
    """An alias or a loopback literal, with the host unbracketed."""

    host: str
    port: int

    @property
    def text(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}"


@dataclass(frozen=True)
class Unix:
    path: str

    @property
    def text(self) -> str:
        return f"{UNIX_PREFIX}{self.path}"


Listen = Tcp | Unix


def literal(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """The address ``host`` writes, or None for a name."""
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _is_name(host: str) -> bool:
    name = host.removesuffix(".")
    return len(name) <= 253 and all(_LABEL.fullmatch(label) for label in name.split("."))


def parse(text: str) -> Listen:
    """One ``--listen`` value, in one of the three forms."""
    if text.startswith(UNIX_PREFIX):
        path = text.removeprefix(UNIX_PREFIX)
        if not path.startswith("/") or path.endswith("/") or posixpath.normpath(path) != path:
            raise ListenError("--listen unix: needs an absolute, normalized path to the socket")
        return Unix(path)
    host, sep, port = text.rpartition(":")
    if not sep or not host or not _PORT.fullmatch(port) or not 0 < int(port) < 65536:
        raise ListenError(LISTEN_FORM)
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    address = literal(host)
    if address is None and not _is_name(host):
        raise ListenError(LISTEN_FORM)
    if address is not None and not address.is_loopback:
        raise ListenError(
            f"--listen {text}: an address the bridge listens on is a loopback one; on a network, "
            "give its alias there"
        )
    return Tcp(host, int(port))


def check_peer_uid(listen: Listen, peer_uid: int | None) -> None:
    """``--peer-uid`` goes with a ``unix:`` listen, and only with one."""
    if isinstance(listen, Unix) and peer_uid is None:
        raise ListenError("--listen unix: needs --peer-uid, the uid that may connect (the vault's)")
    if isinstance(listen, Tcp) and peer_uid is not None:
        raise ListenError("--peer-uid goes only with --listen unix:")
    if peer_uid is not None and peer_uid < 0:
        raise ListenError("--peer-uid is a uid (0 or more)")


def choose(listen: Tcp, found: Sequence[str]) -> str:
    """The one address to bind for an alias, from what it resolved to: exactly one, never a
    wildcard."""
    addresses = list(dict.fromkeys(found))
    if len(addresses) != 1:
        count = "no address" if not addresses else f"{len(addresses)} addresses"
        raise ListenError(
            f"--listen's name {listen.host} resolves to {count}; give a name on one network"
        )
    address = literal(addresses[0])
    if address is None:
        raise ListenError(f"--listen's name {listen.host} didn't resolve to an address")
    if address.is_unspecified:
        raise ListenError(f"--listen's name {listen.host} resolves to every address ({address})")
    return str(address)


def system_lookup(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return [str(info[4][0]) for info in infos]


async def resolve(listen: Tcp, lookup: Lookup = system_lookup) -> str:
    """The address to bind: a literal's own, or the one its alias resolves to. A name that
    doesn't resolve yet is tried again for :data:`RESOLVE_FOR` seconds."""
    if literal(listen.host) is not None:
        return str(literal(listen.host))
    loop = asyncio.get_running_loop()
    deadline = loop.time() + RESOLVE_FOR
    while True:
        try:
            found = await asyncio.to_thread(lookup, listen.host)
        except (OSError, UnicodeError) as exc:
            if loop.time() >= deadline:
                raise ListenError(f"--listen's name {listen.host} doesn't resolve: {exc}") from exc
            await asyncio.sleep(RESOLVE_EVERY)
            continue
        return choose(listen, found)


def bind_tcp(address: str, port: int) -> socket.socket:
    """A socket bound to the one address, not listening yet (uvicorn listens on it)."""
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        if os.name != "nt":
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((address, port))
    except OSError as exc:
        sock.close()
        raise ListenError(f"can't listen on {address}:{port}: {exc}") from exc
    return sock


def directory_refusal(uid: int, mode: int, own_uid: int) -> str | None:
    """Why the socket's directory, owned by ``uid`` with ``mode``, can't hold the socket."""
    if not stat.S_ISDIR(mode):
        return "isn't a directory"
    if uid != own_uid:
        return f"is owned by uid {uid}, not the bridge's {own_uid}"
    if stat.S_IMODE(mode) & DIRECTORY_MASK:
        return f"is mode {stat.S_IMODE(mode):04o}; others may have no access, the group no write"
    return None


def prepare_socket(listen: Unix) -> None:
    """Check the socket's directory and remove a stale socket at the path (C.8)."""
    if sys.platform == "win32" or not hasattr(socket, "SO_PEERCRED"):
        raise ListenError("--listen unix: needs Linux (SO_PEERCRED)")
    directory = posixpath.dirname(listen.path)
    try:
        info = os.stat(directory)
    except OSError as exc:
        raise ListenError(f"the socket's directory {directory} can't be used: {exc}") from exc
    refusal = directory_refusal(info.st_uid, info.st_mode, os.getuid())
    if refusal is not None:
        raise ListenError(f"the socket's directory {directory} {refusal}")
    try:
        mode = os.lstat(listen.path).st_mode
    except FileNotFoundError:
        return
    except OSError as exc:
        raise ListenError(f"can't check {listen.path} for a stale socket: {exc}") from exc
    if not stat.S_ISSOCK(mode):
        raise ListenError(f"{listen.path} exists and is not a socket")
    try:
        os.unlink(listen.path)
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise ListenError(f"can't remove the stale socket {listen.path}: {exc}") from exc


def peer_uid(sock: Any) -> int | None:
    """The peer's uid from ``SO_PEERCRED``, or None when the kernel doesn't say."""
    option = getattr(socket, "SO_PEERCRED", None)
    if sock is None or option is None:
        return None
    try:
        raw = sock.getsockopt(socket.SOL_SOCKET, option, UCRED.size)
    except OSError:
        return None
    if not isinstance(raw, bytes) or len(raw) != UCRED.size:
        return None
    _pid, uid, _gid = UCRED.unpack(raw)
    return int(uid)


def peer_checked(allowed_uid: int) -> type[H11Protocol]:
    """A uvicorn HTTP protocol that cuts every connection whose peer isn't ``allowed_uid``,
    in ``connection_made``, before the transport reads anything."""

    class PeerCheckedH11(H11Protocol):
        def connection_made(self, transport: asyncio.Transport) -> None:  # type: ignore[override]
            # First, so uvicorn's own cleanup in connection_lost finds what it expects.
            super().connection_made(transport)
            uid = peer_uid(transport.get_extra_info("socket"))
            if uid is None or uid != allowed_uid:
                event("bridge_peer_refused", uid=uid)
                transport.abort()

    return PeerCheckedH11
