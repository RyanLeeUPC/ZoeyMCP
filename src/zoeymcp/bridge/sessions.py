"""A legacy bridge's sessions (M7 design C.5, SPEC-4, G20). Pure and mutation-tested;
:mod:`.server` starts and stops the children around these decisions.

A legacy bridge runs one child per MCP session (``shared_session: true`` in the policy makes that
one session, so one child; a modern bridge has one child and no sessions). An ``initialize``
sent without ``Mcp-Session-Id`` reserves a place (:meth:`Sessions.reserve`; beyond
``--max-sessions``, :data:`SESSIONS_MAX` by default, 503 ``sessions_full``) and starts a child;
on the child's answer the session is established with a new 256-bit id (base64url), sent back
as ``Mcp-Session-Id``. An unknown or ended id is 404, so the gateway initializes again.

Ids are compared in constant time against every session, never logged (a log line carries
:func:`hash8`), and bound to nothing but the bridge: its only caller is the vault, carrying the
gateway's requests, and each gateway session is per client and server (G18). A session with no
request in flight and no GET stream open for ``--idle-timeout`` (:data:`IDLE_TIMEOUT`, the
gateway's ``upstream_idle_timeout``) is stopped. Each GET opens a stream of its own, and each
notification goes to exactly one stream, the oldest open one.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Callable, Iterator
from typing import Final

# M7 design C.5 and M.6.
SESSIONS_MAX: Final = 8
IDLE_TIMEOUT: Final = 600.0
ID_BYTES: Final = 32


def new_id() -> str:
    """A session id: 256 random bits, base64url without padding."""
    return secrets.token_urlsafe(ID_BYTES)


def hash8(session_id: str) -> str:
    """What a log line carries for a session: 8 hex digits of its id's SHA-256."""
    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:8]


class Session[C]:
    """One legacy session and its child. Its ``repr`` names only :attr:`hash8`."""

    def __init__(self, session_id: str, child: C, now: float) -> None:
        self.session_id = session_id
        self.child = child
        self.last_used = now
        self.requests = 0
        self._streams: list[int] = []
        self._next_stream = 0

    @property
    def hash8(self) -> str:
        return hash8(self.session_id)

    def matches(self, session_id: str) -> bool:
        """Whether ``session_id`` is this session's, compared in constant time."""
        return hmac.compare_digest(self.session_id.encode("utf-8"), session_id.encode("utf-8"))

    def begin(self, now: float) -> None:
        """A request on this session started."""
        self.requests += 1
        self.last_used = now

    def finish(self, now: float) -> None:
        """A request on this session ended."""
        self.requests -= 1
        self.last_used = now

    def open_stream(self) -> int:
        """A GET opened a stream: its number."""
        self._next_stream += 1
        self._streams.append(self._next_stream)
        return self._next_stream

    def close_stream(self, stream: int, now: float) -> None:
        if stream in self._streams:
            self._streams.remove(stream)
        self.last_used = now

    @property
    def stream(self) -> int | None:
        """The stream an unsolicited notification goes to: the oldest open one."""
        return self._streams[0] if self._streams else None

    def idle(self, now: float, timeout: float) -> bool:
        """Nothing in flight, no stream open, and nothing for ``timeout`` seconds."""
        return not self.requests and not self._streams and now - self.last_used >= timeout

    def __repr__(self) -> str:
        return f"Session({self.hash8})"


class Sessions[C]:
    """The table of a legacy bridge's sessions, and the places reserved for ones starting."""

    def __init__(
        self,
        limit: int = SESSIONS_MAX,
        idle_timeout: float = IDLE_TIMEOUT,
        new_id: Callable[[], str] = new_id,
    ) -> None:
        self.limit = limit
        self.idle_timeout = idle_timeout
        self._new_id = new_id
        self._sessions: list[Session[C]] = []
        self._starting = 0

    def __len__(self) -> int:
        return len(self._sessions)

    def __iter__(self) -> Iterator[Session[C]]:
        return iter(list(self._sessions))

    def reserve(self) -> bool:
        """Hold a place for an ``initialize`` whose child is starting; False when every place
        is taken, by a session or by another start (503 ``sessions_full``)."""
        if len(self._sessions) + self._starting >= self.limit:
            return False
        self._starting += 1
        return True

    def release(self) -> None:
        """Give back a reserved place: the start didn't become a session."""
        if self._starting:
            self._starting -= 1

    def establish(self, child: C, now: float) -> Session[C]:
        """The child answered ``initialize``: a session in the reserved place, with a new id."""
        if not self._starting:
            raise ValueError("no session is starting")
        session_id = self._new_id()
        while self.find(session_id) is not None:
            session_id = self._new_id()
        self._starting -= 1
        session = Session(session_id, child, now)
        self._sessions.append(session)
        return session

    def find(self, session_id: str) -> Session[C] | None:
        """The session with this id, compared against every session in constant time."""
        found = None
        for session in self._sessions:
            if session.matches(session_id):
                found = session
        return found

    def end(self, session: Session[C]) -> bool:
        """Forget a session (a DELETE, or its child exited): False if it was already gone."""
        if session not in self._sessions:
            return False
        self._sessions.remove(session)
        return True

    def idle(self, now: float) -> list[Session[C]]:
        """Forget and return every session idle for :attr:`idle_timeout`, to be stopped."""
        idle = [s for s in self._sessions if s.idle(now, self.idle_timeout)]
        for session in idle:
            self._sessions.remove(session)
        return idle
