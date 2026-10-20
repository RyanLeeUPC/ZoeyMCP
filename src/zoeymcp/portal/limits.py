"""The portal's bounds against non-browser callers (M5 design F.1, B.3, C.2 rows 0 and 8, C.6).

Pure, so each bound can be tested: every method that needs time takes ``now`` (the monotonic
clock), and the shell applies the answers.

- **The rate bucket**: one global bucket of :data:`UNAUTH_RATE` a minute and a burst of
  :data:`UNAUTH_BURST`, for the three unauthenticated routes and the OAuth callback.
- **The in-flight gate**: at most :data:`IN_FLIGHT` requests in flight, of which at most
  :data:`IN_FLIGHT_UNAUTH` on the unauthenticated routes, so slow bodies sent without a session
  can't take the slots an operator's requests need (every other route is answered 401 before its
  body is read).
- **The connection table**: at most :data:`ADMIN_CONNECTIONS` open; a new one beyond it closes
  the one idle longest, or is closed itself when every one has a request in flight.
- **Sparse log lines**: a refusal or an eviction is logged at most once per interval per kind,
  with a count (M.4).
"""

from __future__ import annotations

from collections.abc import Hashable
from dataclasses import dataclass
from typing import Final

UNAUTH_RATE: Final = 30  # tokens a minute
UNAUTH_BURST: Final = 10
IN_FLIGHT: Final = 32
IN_FLIGHT_UNAUTH: Final = 8
ADMIN_CONNECTIONS: Final = 64


class Bucket:
    """A token bucket, full at the start. A clock that steps back refills nothing."""

    def __init__(self, *, rate: float = UNAUTH_RATE / 60, burst: int = UNAUTH_BURST) -> None:
        self._rate = rate  # tokens a second
        self._burst = burst
        self._tokens = float(burst)
        self._last: float | None = None

    def take(self, now: float) -> bool:
        """Spend one token if there is one (C.2 row 8; 429 ``rate_limited`` when not)."""
        if self._last is not None:
            elapsed = max(0.0, now - self._last)
            self._tokens = min(float(self._burst), self._tokens + elapsed * self._rate)
        self._last = now if self._last is None else max(self._last, now)
        if self._tokens < 1:
            return False
        self._tokens -= 1
        return True


@dataclass
class Ticket:
    """One request's place in the gate, given back by :meth:`InFlight.leave`."""

    unauthenticated: bool = False
    left: bool = False


class InFlight:
    """The in-app in-flight gate (B.3): uvicorn's own ``limit_concurrency`` answers without the
    portal's headers, so the app counts."""

    def __init__(self) -> None:
        self.total = 0
        self.unauthenticated = 0

    def enter(self) -> Ticket | None:
        """C.2 row 0: a place for any request, or None (503 ``busy``)."""
        if self.total >= IN_FLIGHT:
            return None
        self.total += 1
        return Ticket()

    def enter_unauthenticated(self, ticket: Ticket) -> bool:
        """C.2 row 8: one of the unauthenticated slots for a request already in, or False (503
        ``busy``). Asking twice for one ticket takes one slot."""
        if ticket.left:
            raise ValueError("this request has left the gate")
        if ticket.unauthenticated:
            return True
        if self.unauthenticated >= IN_FLIGHT_UNAUTH:
            return False
        self.unauthenticated += 1
        ticket.unauthenticated = True
        return True

    def leave(self, ticket: Ticket) -> None:
        """Give the places back when the answer is done. A second call changes nothing."""
        if ticket.left:
            return
        ticket.left = True
        self.total -= 1
        if ticket.unauthenticated:
            self.unauthenticated -= 1


@dataclass(frozen=True)
class Opened[K: Hashable]:
    """``accepted``: keep the new connection; ``evict``: the open one to close first."""

    accepted: bool
    evict: K | None = None


class Connections[K: Hashable]:
    """The open connections of the admin listener and when each became idle. A connection is
    idle from when it opens, or its last response completes, until a request starts on it."""

    def __init__(self) -> None:
        self._idle_since: dict[K, float | None] = {}  # None: a request in flight

    def __len__(self) -> int:
        return len(self._idle_since)

    def open(self, conn: K, now: float) -> Opened[K]:
        """Take a new connection. At the cap, the open one idle longest is evicted (its caller
        closes it); if none is idle, the new one is refused."""
        evict: K | None = None
        if len(self._idle_since) >= ADMIN_CONNECTIONS:
            idle = [(since, c) for c, since in self._idle_since.items() if since is not None]
            if not idle:
                return Opened(accepted=False)
            evict = min(idle, key=lambda item: item[0])[1]
            del self._idle_since[evict]
        self._idle_since[conn] = now
        return Opened(accepted=True, evict=evict)

    def busy(self, conn: K) -> None:
        """A request started on ``conn``."""
        if conn in self._idle_since:
            self._idle_since[conn] = None

    def idle(self, conn: K, now: float) -> None:
        """``conn``'s response completed."""
        if conn in self._idle_since:
            self._idle_since[conn] = now

    def close(self, conn: K) -> None:
        self._idle_since.pop(conn, None)


class Sparse[K: Hashable]:
    """At most one log line per key every ``interval`` seconds (M.4: ``portal_refused``,
    ``portal_connection_evicted``), each counting the events since the last line, so a flood
    can't flood the log. The first event of a key is logged at once."""

    def __init__(self, interval: float) -> None:
        self._interval = interval
        self._last: dict[K, float] = {}
        self._held: dict[K, int] = {}

    def note(self, key: K, now: float) -> int | None:
        """Count one event of ``key``: the count to log with it (this one and those held back
        since the last line), or None to hold it back."""
        held = self._held.get(key, 0) + 1
        last = self._last.get(key)
        if last is not None and now - last < self._interval:
            self._held[key] = held
            return None
        self._last[key] = now
        self._held[key] = 0
        return held
