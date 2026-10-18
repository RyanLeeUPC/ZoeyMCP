"""The gateway key ratchet (design §4.5, M3 design C.2).

In the hardened tier the gateway proves itself with ``key(G)``, derived from the master key for
the policy's ``gateway_key_generation`` G. Raising G starts a rotation: the old key stays accepted
until the first request made with the new one, and for at most five minutes. It is then retired,
and a restart doesn't bring it back. A master-key rotation changes the gateway key too, and the
previous master's keys follow the same rule.

The state lives in ``<state>/gateway-key.json``, written atomically and MAC'd with ``K_config``.
It only moves forward: a lower generation is refused, and so is a file whose MAC doesn't verify.

The transitions are pure functions of a :class:`State`. :class:`GatewayKeys` holds the state,
writes it and logs.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import os
import re
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from ..common.canonical import JSONRejected, dumps_canonical, loads_strict
from . import logs
from .keys import KeySet

STATE_FILE = "gateway-key.json"
STATE_VERSION = 1
# How long a previous key stays accepted after a rotation, in seconds.
WINDOW = 300
# gateway_key_previous_used is logged at most this often, in seconds.
PREVIOUS_USED_INTERVAL = 60
MAX_STATE_BYTES = 4096
# Keeps this MAC apart from anything else K_config authenticates.
_MAC_CONTEXT: Final = b"zoeymcp/gateway-key-state/v1\n"
_KEY_ID = re.compile(r"[0-9a-f]{16}")
_FIELDS: Final = frozenset(
    {"v", "key_id", "current", "floor", "previous", "previous_key_id", "previous_until", "mac"}
)

TAMPERED = "gateway key state was tampered with, or written under another master key"
BACKWARDS = "the generation went backwards; that would revive a retired key"


class GatewayKeyError(Exception):
    """The state can't be used or changed. The message is safe to print."""


@dataclass(frozen=True)
class Previous:
    """The key a rotation replaced: its generation, its master key ID, and its deadline.

    When ``key_id`` isn't the state's (a master-key rotation), that master's ``key(current)`` is
    accepted until the same deadline too.
    """

    generation: int
    key_id: str
    until: int


@dataclass(frozen=True)
class State:
    """``key(current)`` under the master ``key_id``, and maybe a previous key still accepted.

    ``floor`` is the lowest generation that may still be accepted.
    """

    key_id: str
    current: int
    floor: int
    previous: Previous | None = None


@dataclass(frozen=True)
class Refusal:
    """A transition that must not happen. ``reason`` is safe to print."""

    reason: str


@dataclass(frozen=True)
class AcceptedKey:
    """One key the vault accepts now. ``current`` is false for a previous key."""

    generation: int
    key_id: str
    current: bool
    key: bytes = field(repr=False)


# --- the pure state machine ----------------------------------------------------------------------


def initial(key_id: str, generation: int) -> State:
    """The state when there is no file: only ``key(generation)``."""
    return State(key_id=key_id, current=generation, floor=generation)


def window_open(state: State, now: float) -> bool:
    return state.previous is not None and now < state.previous.until


def advance(state: State, generation: int, now: float) -> State | Refusal:
    """Move to the policy's ``generation``, on load and on every reload.

    A higher generation keeps the current key as the previous one for :data:`WINDOW` seconds.
    A key already kept that way is dropped: there is only one previous key.
    """
    if generation < state.current:
        return Refusal(f"gateway_key_generation {generation} is below {state.current}: {BACKWARDS}")
    if generation == state.current:
        return state
    previous = Previous(state.current, state.key_id, int(now) + WINDOW)
    return State(key_id=state.key_id, current=generation, floor=state.current, previous=previous)


def rekey(state: State, key_id: str, now: float) -> State:
    """The master key changed to ``key_id``.

    The previous master's ``key(current)`` stays accepted for :data:`WINDOW` seconds. If a window
    is open for that master's ``key(previous)`` (a bump not retired yet, or the master key and the
    generation changed in one restart), the gateway may hold either key. The window keeps its
    deadline, so a bump's old key still lives at most :data:`WINDOW` seconds, and both are
    accepted until then.
    """
    if key_id == state.key_id:
        return state
    previous_key_id = state.previous.key_id if state.previous is not None else None
    if previous_key_id == state.key_id and window_open(state, now):
        return replace(state, key_id=key_id)
    previous = Previous(state.current, state.key_id, int(now) + WINDOW)
    return State(key_id=key_id, current=state.current, floor=state.current, previous=previous)


def retire(state: State) -> State:
    """Accept only ``key(current)`` from now on."""
    return State(key_id=state.key_id, current=state.current, floor=state.current)


def expired(state: State, now: float) -> bool:
    """A previous key is kept, but its window is over."""
    return state.previous is not None and now >= state.previous.until


def _derive(
    key_id: str, generation: int, keys: KeySet, previous_keys: KeySet | None
) -> bytes | None:
    for keyset in (keys, previous_keys):
        if keyset is not None and keyset.key_id == key_id:
            return keyset.gateway_key(generation).encode()
    return None


def accepted_keys(
    state: State, keys: KeySet, previous_keys: KeySet | None, now: float
) -> list[AcceptedKey]:
    """``key(current)``, and while the window is open the previous key and, after a master-key
    rotation, the previous master's ``key(current)``.

    A key whose master isn't available (``ZOEYMCP_MASTER_KEY_PREVIOUS`` unset) is left out, and
    so is a previous generation below the floor.
    """
    accepted = []
    current = _derive(state.key_id, state.current, keys, previous_keys)
    if current is not None:
        accepted.append(AcceptedKey(state.current, state.key_id, True, current))
    previous = state.previous
    if previous is not None and window_open(state, now) and previous.generation >= state.floor:
        generations = [previous.generation]
        if previous.key_id != state.key_id and previous.generation != state.current:
            generations.append(state.current)
        for generation in generations:
            key = _derive(previous.key_id, generation, keys, previous_keys)
            if key is not None:
                accepted.append(AcceptedKey(generation, previous.key_id, False, key))
    return accepted


def matching(accepted: list[AcceptedKey], presented: bytes) -> AcceptedKey | None:
    """The accepted key ``presented`` equals. Every candidate is compared, in constant time."""
    found = [key for key in accepted if hmac.compare_digest(presented, key.key)]
    return found[0] if found else None


# --- the file ------------------------------------------------------------------------------------


def _document(state: State) -> dict[str, Any]:
    previous = state.previous
    return {
        "v": STATE_VERSION,
        "key_id": state.key_id,
        "current": state.current,
        "floor": state.floor,
        "previous": previous.generation if previous else None,
        "previous_key_id": previous.key_id if previous else None,
        "previous_until": previous.until if previous else None,
    }


def _mac(document: dict[str, Any], keys: KeySet) -> str:
    message = _MAC_CONTEXT + dumps_canonical(document)
    return hmac.new(keys.config_key, message, hashlib.sha256).hexdigest()


def seal(state: State, keys: KeySet) -> bytes:
    """The file's bytes: the state and its MAC under ``keys``, which must be the state's master."""
    if keys.key_id != state.key_id:
        raise ValueError("the state must be sealed under its own master key")
    document = _document(state)
    document["mac"] = _mac(document, keys)
    return dumps_canonical(document) + b"\n"


def _is_int(value: Any) -> bool:
    return type(value) is int


def _parse(document: dict[str, Any]) -> State | None:
    """The state a MAC-verified document holds, or ``None`` if it isn't consistent."""
    if document["v"] != STATE_VERSION or not _is_int(document["v"]):
        return None
    current, floor = document["current"], document["floor"]
    # The floor is at most current below, so this bounds both.
    if not (_is_int(current) and _is_int(floor) and floor >= 1):
        return None
    parts = (document["previous"], document["previous_key_id"], document["previous_until"])
    if parts == (None, None, None):
        return State(document["key_id"], current, floor) if floor == current else None
    generation, key_id, until = parts
    if not (_is_int(generation) and _is_int(until) and isinstance(key_id, str)):
        return None
    if not _KEY_ID.fullmatch(key_id) or floor != generation or generation > current:
        return None
    if generation == current and key_id == document["key_id"]:
        return None  # the same key twice
    return State(document["key_id"], current, floor, Previous(generation, key_id, until))


def unseal(data: bytes, keys: KeySet, previous_keys: KeySet | None) -> State:
    """Read the file's bytes, verifying the MAC under the master key that wrote them.

    That is ``keys``, or ``previous_keys`` during a master-key rotation. Raises
    :class:`GatewayKeyError` with a message for the operator.
    """
    try:
        document = loads_strict(data, max_bytes=MAX_STATE_BYTES)
    except JSONRejected as exc:
        raise GatewayKeyError(f"isn't a gateway key state: {exc}") from exc
    if not isinstance(document, dict) or set(document) != _FIELDS:
        raise GatewayKeyError(f"isn't a version-{STATE_VERSION} gateway key state")
    key_id, mac = document["key_id"], document["mac"]
    if not (isinstance(key_id, str) and _KEY_ID.fullmatch(key_id) and isinstance(mac, str)):
        raise GatewayKeyError(f"isn't a version-{STATE_VERSION} gateway key state")
    if key_id == keys.key_id:
        signer = keys
    elif previous_keys is not None and key_id == previous_keys.key_id:
        signer = previous_keys
    else:
        raise GatewayKeyError(
            f"was written under master key ID {key_id}, but the master key's ID is "
            f"{keys.key_id}. If you are rotating the master key, set ZOEYMCP_MASTER_KEY_PREVIOUS "
            "to the old key; deleting the file instead resets the generation floor."
        )
    rest = {name: value for name, value in document.items() if name != "mac"}
    if not hmac.compare_digest(mac.encode(), _mac(rest, signer).encode()):
        raise GatewayKeyError(TAMPERED)
    state = _parse(rest)
    if state is None:
        raise GatewayKeyError(f"isn't a consistent version-{STATE_VERSION} gateway key state")
    return state


def write_atomic(path: Path, data: bytes) -> None:
    """Replace ``path`` with ``data`` (mode 0600), so a crash leaves the old file or the new."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".gateway-key-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    if hasattr(os, "O_DIRECTORY"):
        dir_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)


def utc(timestamp: int) -> str:
    """A Unix time as ``2026-10-17T09:00:00Z``."""
    return datetime.fromtimestamp(timestamp, UTC).isoformat().replace("+00:00", "Z")


# --- the state in a running vault ----------------------------------------------------------------


class GatewayKeys:
    """The vault's ratchet: which gateway keys it accepts, kept on disk.

    A rotation is written before it takes effect; if it can't be, it is refused. A retirement
    takes effect at once: if it can't be written, memory keeps it, ``gateway_key_state_not_written``
    is logged as critical, and the next write (or :meth:`tick`) tries again.
    """

    def __init__(
        self,
        state: State,
        keys: KeySet,
        previous_keys: KeySet | None = None,
        *,
        path: Path | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        """``path`` None keeps the state in memory only (self-tests and unit tests)."""
        self._state = state
        self._keys = keys
        self._previous_keys = previous_keys
        self._path = path
        self._clock = clock
        self._lock = threading.Lock()
        self._dirty = False
        self._previous_logged: float | None = None

    @classmethod
    def in_memory(
        cls, keys: KeySet, generation: int, *, clock: Callable[[], float] = time.time
    ) -> GatewayKeys:
        return cls(initial(keys.key_id, generation), keys, clock=clock)

    @classmethod
    def load(
        cls,
        state_dir: Path,
        keys: KeySet,
        previous_keys: KeySet | None,
        generation: int,
        *,
        clock: Callable[[], float] = time.time,
    ) -> GatewayKeys:
        """Read ``<state>/gateway-key.json`` and move it to ``generation``, at startup.

        Every change is written before this returns. Raises :class:`GatewayKeyError` for a file
        that can't be read or verified, a lower generation, or a change that can't be written.
        """
        path = state_dir / STATE_FILE
        now = clock()
        loaded: State | None = None
        try:
            data = path.read_bytes()
        except FileNotFoundError:
            state = initial(keys.key_id, generation)
        except OSError as exc:
            raise GatewayKeyError(f"can't read {path}: {exc}") from exc
        else:
            try:
                loaded = unseal(data, keys, previous_keys)
            except GatewayKeyError as exc:
                raise GatewayKeyError(f"{path}: {exc}") from exc
            # A window that closed while the vault was down ends first, as expired.
            cleaned = retire(loaded) if expired(loaded, now) else loaded
            result = advance(cleaned, generation, now)
            if isinstance(result, Refusal):
                raise GatewayKeyError(f"{path}: {result.reason}")
            state = rekey(result, keys.key_id, now)
        if state != loaded:
            try:
                write_atomic(path, seal(state, keys))
            except OSError as exc:
                raise GatewayKeyError(f"can't write {path}: {exc}") from exc
        if loaded is not None:
            _log_changes(loaded, cleaned)
            _log_changes(cleaned, state)
        return cls(state, keys, previous_keys, path=path, clock=clock)

    @property
    def state(self) -> State:
        return self._state

    @property
    def dirty(self) -> bool:
        """Memory holds a retirement the file doesn't, because a write failed."""
        return self._dirty

    def advance(self, generation: int) -> bool:
        """Move to ``generation`` for a policy reload, written before it takes effect.

        Returns whether the generation changed. Raises :class:`GatewayKeyError`, leaving the
        generation as it was, for a lower generation or a change that can't be written. A window
        that is over is retired first, as expired.
        """
        with self._lock:
            now = self._clock()
            self._expire(now)
            result = advance(self._state, generation, now)
            if isinstance(result, Refusal):
                raise GatewayKeyError(result.reason)
            if result == self._state:
                return False
            if self._path is not None:
                try:
                    write_atomic(self._path, seal(result, self._keys))
                except OSError as exc:
                    raise GatewayKeyError(
                        f"can't write {self._path}, so the new generation can't be used: {exc}"
                    ) from exc
            before, self._state, self._dirty = self._state, result, False
        _log_changes(before, result)
        return True

    def authenticate(self, presented: bytes) -> bool:
        """Whether ``presented`` is an accepted key. Using ``key(current)`` retires the previous."""
        with self._lock:
            now = self._clock()
            self._expire(now)
            used = matching(
                accepted_keys(self._state, self._keys, self._previous_keys, now), presented
            )
            if used is None:
                return False
            if used.current:
                if self._state.previous is not None:
                    self._retire("new_key_used")
            elif self._previous_logged is None or (
                now - self._previous_logged >= PREVIOUS_USED_INTERVAL
            ):
                self._previous_logged = now
                logs.event("gateway_key_previous_used", generation=used.generation)
            return True

    def retire_previous(self) -> int | None:
        """Retire the previous key now (``--retire-previous``). Returns its generation, if any.

        Raises :class:`GatewayKeyError` if the retirement, which took effect, can't be written.
        """
        with self._lock:
            self._expire(self._clock())
            previous = self._state.previous
            if previous is None:
                return None
            if not self._retire("operator"):
                raise GatewayKeyError("the retirement is kept in memory, not written to disk")
            return previous.generation

    def tick(self) -> None:
        """Retire an expired previous key and retry a failed write (the vault's timer)."""
        with self._lock:
            if not self._expire(self._clock()) and self._dirty:
                self._save()

    def info(self) -> dict[str, Any]:
        """The current generation and key, and the previous key's window, for the admin.

        The window is shown only while a previous key is accepted: open, and its master loaded.
        """
        with self._lock:
            state = self._state
            accepted = accepted_keys(state, self._keys, self._previous_keys, self._clock())
        previous = state.previous if any(not key.current for key in accepted) else None
        return {
            "generation": state.current,
            "key": self._keys.gateway_key(state.current),
            "previous": None
            if previous is None
            else {
                "generation": previous.generation,
                "until": previous.until,
                "master_key": "current" if previous.key_id == state.key_id else "previous",
            },
        }

    # --- internals (call with the lock held) -----------------------------------------------------

    def _expire(self, now: float) -> bool:
        """Retire the previous key if its window is over. Returns whether it did."""
        if not expired(self._state, now):
            return False
        self._retire("expired")
        return True

    def _retire(self, reason: str) -> bool:
        """Retire the previous key and write the state. Returns whether the write worked."""
        previous = self._state.previous
        assert previous is not None  # noqa: S101 - callers check
        self._state = retire(self._state)
        logs.event("gateway_key_retired", generation=previous.generation, reason=reason)
        return self._save()

    def _save(self) -> bool:
        if self._path is None:
            return True
        try:
            write_atomic(self._path, seal(self._state, self._keys))
        except OSError as exc:
            self._dirty = True
            logs.event(
                "gateway_key_state_not_written",
                level="critical",
                path=str(self._path),
                error_type=type(exc).__name__,
            )
            return False
        self._dirty = False
        return True


def _log_changes(before: State, after: State) -> None:
    """Log what a load or an advance changed: a previous key dropped, a rotation started."""
    dropped = before.previous
    if dropped is not None and after.previous != dropped:
        reason = "expired" if after.previous is None else "superseded"
        logs.event("gateway_key_retired", generation=dropped.generation, reason=reason)
    started = after.previous
    rekeyed = after.key_id != before.key_id
    if started is not None and (started != before.previous or rekeyed):
        logs.event(
            "gateway_key_rotation_started",
            generation=after.current,
            previous_until=started.until,
            master_key_changed=rekeyed,
        )
