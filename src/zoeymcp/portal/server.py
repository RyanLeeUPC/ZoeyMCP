"""The portal's connections (M5 design B.3): a head deadline and a connection cap.

:func:`portal_protocol` builds the uvicorn HTTP protocol for the admin listener, a subclass of
uvicorn's ``H11Protocol`` as :mod:`zoeymcp.vault.peer`'s is, with a table of its connections
(:class:`~.limits.Connections`) shared by every connection of that listener.

- **The head deadline** runs on a timer of the protocol's own. uvicorn's keep-alive timer can't
  carry it: ``data_received`` cancels that timer on any byte, before parsing (contract 40), so a
  head trickled a byte at a time would never time out. The timer is armed when the connection
  opens and again when a response completes (before uvicorn's own completion, which may parse a
  pipelined head that is already in), and cancelled only when h11 yields a request. On expiry a
  connection with no request running is closed. uvicorn's own 5 s keep-alive still runs after
  each response.
- **The cap**: a connection beyond :data:`~.limits.ADMIN_CONNECTIONS` closes the open one that
  has been idle longest (no request running), or is closed itself when every one has a request
  running. Evictions are logged at most once a minute, with a count.

The body has its own deadline, in the app (``portal/app.py``), which reads it only after the
session or bucket check.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import ClassVar, Final

from uvicorn.protocols.http.h11_impl import H11Protocol

from ..vault import logs
from .limits import Connections, Sparse

HEADER_DEADLINE: Final = 10.0  # seconds from a connection's opening, or a response, to a head
HEAD_LIMIT: Final = 16384  # bytes in a request head (h11_max_incomplete_event_size)
EVICTION_LOG_EVERY: Final = 60.0


@dataclass(frozen=True)
class Listener:
    """What every connection of one admin listener shares."""

    connections: Connections[PortalH11]
    evictions: Sparse[str]
    header_deadline: float
    clock: Callable[[], float]


class PortalH11(H11Protocol):
    """uvicorn's h11 protocol with the head deadline and the connection cap. Use
    :func:`portal_protocol`, which gives each listener its own table."""

    listener: ClassVar[Listener]
    _head_timer: asyncio.TimerHandle | None = None

    def connection_made(self, transport: asyncio.Transport) -> None:  # type: ignore[override]
        # First, so uvicorn's own cleanup in connection_lost finds what it expects.
        super().connection_made(transport)
        listener = self.listener
        opened = listener.connections.open(self, listener.clock())
        if not opened.accepted:
            transport.close()
            return
        if opened.evict is not None:
            opened.evict.transport.close()
            count = listener.evictions.note("evicted", listener.clock())
            if count is not None:
                logs.event("portal_connection_evicted", count=count)
        self._arm()

    def connection_lost(self, exc: Exception | None) -> None:
        self._disarm()
        self.listener.connections.close(self)
        super().connection_lost(exc)

    def handle_events(self) -> None:
        running = self.cycle
        super().handle_events()
        if self.cycle is not running:
            # h11 yielded a request: its head is in, and the app has it.
            self._disarm()
            self.listener.connections.busy(self)

    def on_response_complete(self) -> None:
        self.listener.connections.idle(self, self.listener.clock())
        # Before uvicorn's, which may start the next cycle from a pipelined head already in.
        self._arm()
        super().on_response_complete()

    def _arm(self) -> None:
        self._disarm()
        self._head_timer = self.loop.call_later(self.listener.header_deadline, self._head_expired)

    def _disarm(self) -> None:
        if self._head_timer is not None:
            self._head_timer.cancel()
            self._head_timer = None

    def _head_expired(self) -> None:
        self._head_timer = None
        idle = self.cycle is None or self.cycle.response_complete
        if idle and not self.transport.is_closing():
            self.transport.close()


def portal_protocol(
    *,
    header_deadline: float = HEADER_DEADLINE,
    clock: Callable[[], float] = time.monotonic,
) -> type[PortalH11]:
    """A protocol class for one admin listener: pass it as ``uvicorn.Config(http=...)``, with
    ``h11_max_incomplete_event_size=HEAD_LIMIT``. ``header_deadline`` and ``clock`` are for
    tests."""

    class ListenerH11(PortalH11):
        listener = Listener(Connections(), Sparse(EVICTION_LOG_EVERY), header_deadline, clock)

    return ListenerH11
