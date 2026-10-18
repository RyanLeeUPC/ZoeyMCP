"""The link socket's peer check (M3 design C.1).

In the standard tier the gateway reaches the vault over a Unix socket. Its directory is the first
gate; the peer's uid, which the kernel reports with ``SO_PEERCRED``, is the identity. A connection
from any other uid is cut before the vault reads a byte of it.

:func:`peer_allowed` is the decision and :func:`peer_uid` reads the kernel's answer. Both are pure
enough to test anywhere. :func:`peer_checked` builds the uvicorn protocol that applies them to
every connection on the link socket.
"""

from __future__ import annotations

import asyncio
import socket
import struct
from typing import Any, Final

from uvicorn.protocols.http.h11_impl import H11Protocol

from . import logs

# struct ucred on Linux: pid_t pid, uid_t uid, gid_t gid.
UCRED: Final = struct.Struct("=iII")


def link_supported() -> bool:
    """True where the kernel reports a Unix socket peer's uid (Linux)."""
    return hasattr(socket, "SO_PEERCRED")


def peer_allowed(uid: int | None, allowed: int) -> bool:
    """True only for a known uid equal to ``allowed``."""
    return uid is not None and uid == allowed


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
    """A uvicorn HTTP protocol that cuts every connection whose peer isn't ``allowed_uid``.

    Pass it as ``uvicorn.Config(http=...)``. The check runs in ``connection_made``, before the
    transport reads anything, and a refused connection is aborted.
    """

    class PeerCheckedH11(H11Protocol):
        def connection_made(self, transport: asyncio.Transport) -> None:  # type: ignore[override]
            # First, so uvicorn's own cleanup in connection_lost finds what it expects.
            super().connection_made(transport)
            uid = peer_uid(transport.get_extra_info("socket"))
            if not peer_allowed(uid, allowed_uid):
                logs.event("gateway_socket_refused", uid=uid)
                transport.abort()

    return PeerCheckedH11
