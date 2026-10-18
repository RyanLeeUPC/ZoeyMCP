"""Upstream connection keys and the connection state machine (M3 design F.3, F.4).

A connection is admitted to carry a call only when it is ``READY``: its latest listing was
evaluated, and the tool was exposed in that evaluation with no drift mark against its pin. Any
change signal (``list_changed``, a new session id, an era change, a reconnect) makes it ``STALE``
at once, and nothing is admitted until the listing has been compared again (G8). A call admitted
before the signal is already on the wire and finishes.

Everything here is pure: transitions take the current state and return the next one, and time is
passed in. ``upstream.py`` owns the tasks and the I/O.
"""

from __future__ import annotations

from collections.abc import Set
from dataclasses import dataclass, replace
from enum import Enum
from typing import Literal

from ..common.policy.view import ViewRemoteServer
from .access import SUPPORTED_VERSIONS
from .pins import Evaluation, Mark

Era = Literal["modern", "legacy"]
ADMIT_WAIT = 10.0  # seconds a call waits for a connection that is becoming READY
BACKOFF_START = 1.0
BACKOFF_MAX = 300.0


def connection_key(
    server_name: str, server: ViewRemoteServer, era: Era | None, client: str
) -> tuple[str, str]:
    """Which upstream connection a client's requests use (F.3).

    Until the era is known, each client gets its own. A modern upstream has no session, so
    clients share one connection; a legacy one is shared only with ``shared_session``.
    """
    if era == "modern" or (era == "legacy" and server.shared_session):
        return server_name, "*"
    return server_name, client


def supported_upstream_version(version: str | None) -> bool:
    """Whether a negotiated upstream protocol version is one the gateway speaks (F.2)."""
    return version in SUPPORTED_VERSIONS


def era_of(version: str) -> Era:
    return "modern" if version == "2026-07-28" else "legacy"


class Phase(Enum):
    CONNECTING = "connecting"
    READY = "ready"
    STALE = "stale"
    RECONNECTING = "reconnecting"
    FAILED = "failed"
    CLOSED = "closed"


WAITING = frozenset({Phase.CONNECTING, Phase.STALE, Phase.RECONNECTING})


@dataclass(frozen=True)
class ConnState:
    phase: Phase = Phase.CONNECTING
    evaluation: Evaluation | None = None  # from the latest successful listing
    version: int = 0  # bumped when the exposed view changes
    verified_at: float | None = None  # when a listing last succeeded
    failures: int = 0  # consecutive failed listings
    retry_at: float | None = None  # FAILED: no new connection before this


def _view(evaluation: Evaluation | None) -> tuple[frozenset[tuple[str, str]], bool]:
    if evaluation is None:
        return frozenset(), False
    pins = frozenset((name, tool.pin) for name, tool in evaluation.exposed.items())
    return pins, evaluation.blocked


def on_listed(state: ConnState, evaluation: Evaluation, now: float) -> ConnState:
    """A listing succeeded and was evaluated: ``READY`` with that view."""
    if state.phase is Phase.CLOSED:
        return state
    changed = _view(evaluation) != _view(state.evaluation)
    return ConnState(
        phase=Phase.READY,
        evaluation=evaluation,
        version=state.version + 1 if changed else state.version,
        verified_at=now,
    )


def backoff(failures: int) -> float:
    """Seconds before trying a failed connection again: 1 s doubling, at most 5 minutes."""
    return min(BACKOFF_MAX, BACKOFF_START * float(2 ** max(0, failures - 1)))


def on_list_failed(state: ConnState, now: float) -> ConnState:
    """A connect or listing failed, or went over a listing limit: ``FAILED``, nothing admitted."""
    if state.phase is Phase.CLOSED:
        return state
    failures = state.failures + 1
    return replace(state, phase=Phase.FAILED, failures=failures, retry_at=now + backoff(failures))


def on_change(state: ConnState) -> ConnState:
    """A change signal: ``list_changed``, a new session id, an era change or a reconnect."""
    if state.phase in (Phase.READY, Phase.STALE):
        return replace(state, phase=Phase.STALE)
    return state


def on_timer_failed(state: ConnState, now: float, interval: float) -> ConnState:
    """A background re-list failed. Not a change signal: ``READY`` holds for one more interval."""
    if state.phase is not Phase.READY:
        return state
    if state.verified_at is None or now - state.verified_at > 2 * interval:
        return on_list_failed(state, now)
    return state


def on_session_expired(state: ConnState) -> ConnState:
    """A legacy request with a session id got HTTP 404: start over with a fresh session."""
    if state.phase in (Phase.READY, Phase.STALE):
        return replace(state, phase=Phase.RECONNECTING)
    return state


def on_closed(state: ConnState) -> ConnState:
    """Idle, a policy change, the vault link lost, or shutdown."""
    return replace(state, phase=Phase.CLOSED)


def should_connect(state: ConnState, now: float) -> bool:
    """Whether a request may start a new connection attempt now."""
    if state.phase is Phase.FAILED:
        return state.retry_at is None or now >= state.retry_at
    return state.phase is Phase.CLOSED


def on_connecting(state: ConnState) -> ConnState:
    """A new connection attempt starts. Failures are kept, so backoff keeps growing."""
    return ConnState(phase=Phase.CONNECTING, version=state.version, failures=state.failures)


@dataclass(frozen=True)
class Admit:
    pin: str


@dataclass(frozen=True)
class Wait:
    until: float


@dataclass(frozen=True)
class Refuse:
    reason: str


def admit(
    state: ConnState,
    marks: Set[Mark],
    tool: str,
    now: float,
    waiting_since: float | None = None,
) -> Admit | Wait | Refuse:
    """Whether a call to ``tool`` may go out on this connection now.

    ``marks`` are the server's drift marks, which another connection may have set since this one
    listed. A caller told to ``Wait`` waits for a state change or ``until``, then asks again with
    the same ``waiting_since``.
    """
    if state.phase in WAITING:
        started = now if waiting_since is None else waiting_since
        if now - started >= ADMIT_WAIT:
            return Refuse("upstream not ready in time")
        return Wait(until=started + ADMIT_WAIT)
    if state.phase is not Phase.READY or state.evaluation is None:
        return Refuse(f"connection {state.phase.value}")
    exposed = state.evaluation.exposed.get(tool)
    if exposed is None:
        return Refuse("tool not exposed")
    if (tool, exposed.pin) in marks:
        return Refuse("tool marked")
    return Admit(exposed.pin)
