"""Portal sessions and passkey ceremonies (M5 design F.1-F.3). Pure, so each rule can be tested.

Every method takes ``now`` (seconds; the portal passes the wall clock, which its answers show),
and the random bytes come from an injected function, so nothing here reads a clock or does I/O.

- **A session** is two bearer halves (Q11): a cookie and a header token the page keeps in
  ``sessionStorage``. The table keeps only their SHA-256s, and a request authenticates only with
  both, from the session's own origin, before either clock runs out (15 idle minutes, 4 hours in
  all; a setup session 10 minutes). Of several cookies of our name, at most
  :data:`MAX_SESSION_COOKIES` are tried, and only the one that pairs with the header counts, so a
  planted cookie changes nothing. A full table evicts the session used least recently.
- **A ceremony** is a login or an enrolment in progress. Its nonce never leaves the vault, and its
  challenge commits to what it is for (F.3). Login ceremonies are unauthenticated, so their table
  is bounded per peer and in all, and a full table refuses rather than evict another peer's.
  An enrolment ceremony belongs to one session, which holds at most one.

Ending a session is the caller's to finish: it cancels the session's flows (H.2) and drops its
ceremony and action (:meth:`Ceremonies.drop_session`, ``actions.Actions.drop_session``).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from collections.abc import Callable, Collection, Sequence
from dataclasses import dataclass, field, replace
from typing import Any, Final, Literal

from ..common.canonical import dumps_canonical
from ..common.logs import refuse_type

SESSION_IDLE: Final = 900.0
SESSION_MAX: Final = 14_400.0
SETUP_SESSION_MAX: Final = 600.0
MAX_SESSIONS: Final = 8
MAX_SESSION_COOKIES: Final = 4
CEREMONY_TTL: Final = 300.0
MAX_LOGIN_CEREMONIES: Final = 16
MAX_LOGIN_CEREMONIES_PER_PEER: Final = 4

TOKEN_BYTES: Final = 32  # each half: secrets.token_urlsafe(32)
ID_BYTES: Final = 16  # session and ceremony IDs, as hex
NONCE_BYTES: Final = 32

LOGIN_TAG: Final = b"zoeymcp/webauthn/login/v1\n"
ENROL_TAG: Final = b"zoeymcp/webauthn/enrol/v1\n"

Scope = Literal["setup", "full"]
# Why a session ended, as portal_session_ended logs it (M.4). "evicted": a new session took the
# least recently used one's place; "enrolled": a setup session after its one enrolment;
# "end_all": the admin socket's DELETE /sessions.
Why = Literal[
    "logout",
    "idle",
    "max",
    "end_others",
    "passkey_removed",
    "reset",
    "origin_removed",
    "evicted",
    "enrolled",
    "end_all",
]
CeremonyKind = Literal["login", "enrol"]

RandomBytes = Callable[[int], bytes]


# --- the challenge (F.3) -------------------------------------------------------------------------


def challenge(tag: bytes, nonce: bytes, binding: dict[str, Any]) -> bytes:
    """``SHA-256(tag ‖ nonce ‖ canonical(binding))``. The vault recomputes it from what it holds,
    never from what the client sends."""
    return hashlib.sha256(tag + nonce + dumps_canonical(binding)).digest()


def new_id(random: RandomBytes) -> str:
    """A session, ceremony or action ID: 16 random bytes as hex, so a session's flow owner is
    ``session:<hex>`` (H.2)."""
    return random(ID_BYTES).hex()


# --- secrets that must never be logged ------------------------------------------------------------


class SessionToken:
    """One half of a session's bearer, minted or presented. Its ``repr`` hides it; logging it
    raises."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        return self._value

    def sha256(self) -> bytes:
        return hashlib.sha256(self._value.encode("utf-8")).digest()

    def __repr__(self) -> str:
        return "SessionToken(<hidden>)"

    __str__ = __repr__


refuse_type(SessionToken)


def new_token(random: RandomBytes) -> SessionToken:
    """32 random bytes, base64url without padding, as ``secrets.token_urlsafe(32)`` gives."""
    return SessionToken(base64.urlsafe_b64encode(random(TOKEN_BYTES)).rstrip(b"=").decode())


# --- sessions (F.2) -------------------------------------------------------------------------------


@dataclass(frozen=True)
class Session:
    """A live session. ``credential``: the fingerprint of the passkey whose login made it (None
    for a setup session, which a setup code made); ``reset``: a setup session's code was a
    ``--reset`` one."""

    id: str
    cookie_hash: bytes = field(repr=False)
    header_hash: bytes = field(repr=False)
    origin: str
    rp_id: str
    scope: Scope
    reset: bool
    credential: str | None
    created: float
    last_seen: float

    @property
    def owner(self) -> str:
        """The owner of the flows this session starts (H.2)."""
        return "session:" + self.id

    @property
    def fingerprint(self) -> str:
        """What logs and the session list show: 16 hex characters, never the ID itself."""
        return hashlib.sha256(b"zoeymcp/session/v1\n" + self.id.encode()).hexdigest()[:16]

    @property
    def expires_at(self) -> float:
        """The absolute end: 4 hours from login, or 10 minutes for a setup session."""
        return self.created + (SETUP_SESSION_MAX if self.scope == "setup" else SESSION_MAX)

    @property
    def idle_until(self) -> float:
        return self.last_seen + SESSION_IDLE

    def ended_by(self, now: float) -> Literal["idle", "max"] | None:
        """Which clock has run out at ``now``, if either has: each ends at its second."""
        if now >= self.expires_at:
            return "max"
        if now >= self.idle_until:
            return "idle"
        return None


@dataclass(frozen=True)
class Ended:
    session: Session
    why: Why


@dataclass(frozen=True)
class Minted:
    """A new session and its two halves, which the answer that mints it hands out once (the
    cookie, and the header token in the body). ``ended``: the sessions that went first, expired
    or evicted, for the log."""

    session: Session
    cookie: SessionToken
    header: SessionToken
    ended: tuple[Ended, ...]


class Sessions:
    """Every session of one vault process, in memory only (P7, P22)."""

    def __init__(self, random: RandomBytes = secrets.token_bytes) -> None:
        self._random = random
        self._by_id: dict[str, Session] = {}

    def __len__(self) -> int:
        return len(self._by_id)

    def live(self, now: float) -> list[Session]:
        """Every session that would authenticate at ``now``, oldest first."""
        return [s for s in self._by_id.values() if s.ended_by(now) is None]

    def mint(
        self,
        *,
        origin: str,
        rp_id: str,
        scope: Scope,
        now: float,
        reset: bool = False,
        credential: str | None = None,
    ) -> Minted:
        """A new session: at login, at setup redemption, and at the login after a setup
        enrolment. Expired sessions go first; then, at :data:`MAX_SESSIONS`, the one used least
        recently."""
        ended = self.sweep(now)
        while len(self._by_id) >= MAX_SESSIONS:
            oldest = min(self._by_id.values(), key=lambda s: s.last_seen)
            del self._by_id[oldest.id]
            ended.append(Ended(oldest, "evicted"))
        cookie = new_token(self._random)
        header = new_token(self._random)
        session = Session(
            id=new_id(self._random),
            cookie_hash=cookie.sha256(),
            header_hash=header.sha256(),
            origin=origin,
            rp_id=rp_id,
            scope=scope,
            reset=reset,
            credential=credential,
            created=now,
            last_seen=now,
        )
        self._by_id[session.id] = session
        return Minted(session, cookie, header, tuple(ended))

    def lookup(
        self,
        cookies: Sequence[SessionToken],
        header: SessionToken,
        *,
        origin: str,
        now: float,
    ) -> Session | None:
        """The session both halves name (C.2 row 9), or None for every cause alike.

        ``cookies``: the values of the entry's cookie name, in the order the request carries
        them; only the first :data:`MAX_SESSION_COOKIES` are tried. Both hashes are compared in
        constant time. Nothing changes: the idle clock moves in :meth:`touch`, once the request
        has passed admission, and an expired session stays for :meth:`sweep` to end and log.
        """
        tried = [cookie.sha256() for cookie in cookies[:MAX_SESSION_COOKIES]]
        wanted = header.sha256()
        for session in self._by_id.values():
            if not hmac.compare_digest(session.header_hash, wanted):
                continue
            if not any(hmac.compare_digest(session.cookie_hash, h) for h in tried):
                continue
            if session.origin != origin or session.ended_by(now) is not None:
                return None
            return session
        return None

    def touch(self, session_id: str, now: float) -> Session | None:
        """Move a live session's idle clock to ``now`` (after C.2 row 12)."""
        session = self._by_id.get(session_id)
        if session is None or session.ended_by(now) is not None:
            return None
        session = replace(session, last_seen=max(session.last_seen, now))
        self._by_id[session_id] = session
        return session

    def end(self, session_id: str, why: Why) -> Ended | None:
        """End one session: at logout, or a setup session after its enrolment."""
        session = self._by_id.pop(session_id, None)
        return None if session is None else Ended(session, why)

    def end_where(self, matches: Callable[[Session], bool], why: Why) -> list[Ended]:
        """End every session ``matches`` picks."""
        found = [s for s in self._by_id.values() if matches(s)]
        for session in found:
            del self._by_id[session.id]
        return [Ended(s, why) for s in found]

    def end_others(self, session_id: str) -> list[Ended]:
        """Every session but this one (end-others): it only removes privilege."""
        return self.end_where(lambda s: s.id != session_id, "end_others")

    def end_credential(self, fingerprint: str) -> list[Ended]:
        """The sessions the removed passkey's logins made."""
        return self.end_where(lambda s: s.credential == fingerprint, "passkey_removed")

    def end_origins(self, kept: Collection[str]) -> list[Ended]:
        """After a reload: the sessions whose origin is no longer listed."""
        return self.end_where(lambda s: s.origin not in kept, "origin_removed")

    def sweep(self, now: float) -> list[Ended]:
        """End every session whose idle or absolute clock has run out."""
        ended = [(s, s.ended_by(now)) for s in self._by_id.values()]
        found = [Ended(s, why) for s, why in ended if why is not None]
        for item in found:
            del self._by_id[item.session.id]
        return found


# --- ceremonies (F.3) -----------------------------------------------------------------------------


@dataclass(frozen=True, repr=False)
class Ceremony:
    """A login or enrolment in progress. Its nonce never leaves the vault; logging it raises.

    A login ceremony has its ``peer`` (the connecting address, for the per-peer quota); an
    enrolment has its ``session`` and the passkey's ``name``.
    """

    id: str
    kind: CeremonyKind
    nonce: bytes
    origin: str
    expires: float
    peer: str | None = None
    session: str | None = None
    name: str | None = None

    def binding(self) -> dict[str, Any]:
        """F.3's binding, as canonical JSON will encode it."""
        if self.kind == "login":
            return {"ceremony": self.id, "origin": self.origin}
        return {
            "ceremony": self.id,
            "origin": self.origin,
            "session": self.session,
            "name": self.name,
        }

    @property
    def challenge(self) -> bytes:
        return challenge(
            LOGIN_TAG if self.kind == "login" else ENROL_TAG, self.nonce, self.binding()
        )

    def __repr__(self) -> str:
        return f"Ceremony(kind={self.kind}, expires={self.expires})"


refuse_type(Ceremony)


@dataclass(frozen=True)
class Full:
    """The login ceremony table is full of other peers' ceremonies: answered 429 (F.1)."""


class Ceremonies:
    """Every ceremony in progress, in memory only. Each is single use: :meth:`take` removes it
    before its assertion is checked."""

    def __init__(self, random: RandomBytes = secrets.token_bytes) -> None:
        self._random = random
        self._by_id: dict[str, Ceremony] = {}  # insertion order is age order

    def __len__(self) -> int:
        return len(self._by_id)

    def logins(self, peer: str | None = None) -> int:
        """Login ceremonies held, in all or by one peer."""
        return sum(
            1
            for c in self._by_id.values()
            if c.kind == "login" and (peer is None or c.peer == peer)
        )

    def begin_login(self, *, origin: str, peer: str, now: float) -> Ceremony | Full:
        """A new login ceremony. A peer holding its quota loses its own oldest; a table full of
        others' ceremonies refuses, so no peer can evict one in progress (F.1)."""
        self.sweep(now)
        if self.logins(peer) >= MAX_LOGIN_CEREMONIES_PER_PEER:
            oldest = next(c for c in self._by_id.values() if c.kind == "login" and c.peer == peer)
            del self._by_id[oldest.id]
        elif self.logins() >= MAX_LOGIN_CEREMONIES:
            return Full()
        return self._add(Ceremony(**self._new(origin, now), kind="login", peer=peer))

    def begin_enrol(self, *, origin: str, session: str, name: str, now: float) -> Ceremony:
        """A new enrolment ceremony for ``session``, replacing the one it held."""
        self.sweep(now)
        self.drop_session(session)
        return self._add(
            Ceremony(**self._new(origin, now), kind="enrol", session=session, name=name)
        )

    def take(
        self,
        ceremony_id: str,
        *,
        kind: CeremonyKind,
        origin: str,
        now: float,
        session: str | None = None,
    ) -> Ceremony | None:
        """Remove and return the ceremony, if it is live and belongs to this origin (and, for an
        enrolment, this session). A foreign one answers as an unknown one and stays."""
        ceremony = self._by_id.get(ceremony_id)
        if (
            ceremony is None
            or ceremony.kind != kind
            or ceremony.origin != origin
            or ceremony.session != session
        ):
            return None
        del self._by_id[ceremony_id]
        return ceremony if ceremony.expires > now else None

    def drop_session(self, session: str) -> None:
        """Drop the enrolment ceremony of a session that ended or begins another."""
        for ceremony in [c for c in self._by_id.values() if c.session == session]:
            del self._by_id[ceremony.id]

    def sweep(self, now: float) -> None:
        for ceremony in [c for c in self._by_id.values() if c.expires <= now]:
            del self._by_id[ceremony.id]

    def _new(self, origin: str, now: float) -> dict[str, Any]:
        return {
            "id": new_id(self._random),
            "nonce": self._random(NONCE_BYTES),
            "origin": origin,
            "expires": now + CEREMONY_TTL,
        }

    def _add(self, ceremony: Ceremony) -> Ceremony:
        self._by_id[ceremony.id] = ceremony
        return ceremony
