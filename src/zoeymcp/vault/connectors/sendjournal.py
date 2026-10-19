"""The SMTP connector's send journal: idempotency, the rolling limit, recovery (M4 design J.3).

Pure. One canonical JSON record per line, written by :mod:`.smtp`:

- ``sending`` before the connector connects: ``ts``, ``key``, ``req_hmac`` (the request's HMAC
  under the audit key, with its ``key_id``), ``subject_chars``, ``body_chars``;
- then exactly one of ``sent`` (``message_id``, ``smtp_code``), ``failed`` (``phase``, ``code``,
  ``smtp_code``) or ``unknown`` (``phase``).

A send happens only on a key never seen. The limit counts every ``sending`` in the last 24 hours,
failures included, so a failing or hostile server can't be used for unlimited tries with the real
password; it is rebuilt from the journal at start, so a restart doesn't reset it. No subject, body,
recipient or value of any kind is ever recorded: only lengths, codes and digests.
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Final, Literal

from ...common import canonical

DAY_MS: Final = 24 * 3600 * 1000
KEY_DAYS: Final = 30  # keys are remembered this long
RECORD_DAYS: Final = 400  # records older than this are pruned
MAX_LINE_BYTES: Final = 2048
_HMAC = re.compile(r"^hmac-sha256:[0-9a-f]{64}$")
_KEY = re.compile(r"^[A-Za-z0-9._-]{16,80}$")
_KEY_ID = re.compile(r"^[0-9a-f]{16}$")
_CODE = re.compile(r"^[a-z_]{1,64}$")
_PHASE = re.compile(r"^[a-z_]{1,32}$")
_MESSAGE_ID = re.compile(r"^<[!-;=?-~]{1,250}@[!-;=?-~]{1,250}>$")
Kind = Literal["sending", "sent", "failed", "unknown"]


class JournalError(ValueError):
    """A line that isn't a journal record. Never holds a value."""


def _count(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _smtp_code(value: Any) -> bool:
    return value is None or (_count(value) and 100 <= value <= 599)


def _match(pattern: re.Pattern[str]) -> Any:
    return lambda value: isinstance(value, str) and pattern.fullmatch(value) is not None


FIELDS: Final[dict[str, dict[str, Any]]] = {
    "sending": {
        "ts": _count,
        "key": _match(_KEY),
        "req_hmac": _match(_HMAC),
        "key_id": _match(_KEY_ID),
        "subject_chars": _count,
        "body_chars": _count,
    },
    "sent": {
        "ts": _count,
        "key": _match(_KEY),
        "message_id": _match(_MESSAGE_ID),
        "smtp_code": _smtp_code,
    },
    "failed": {
        "ts": _count,
        "key": _match(_KEY),
        "phase": _match(_PHASE),
        "code": _match(_CODE),
        "smtp_code": _smtp_code,
    },
    "unknown": {"ts": _count, "key": _match(_KEY), "phase": _match(_PHASE)},
}


def encode(kind: Kind, **fields: Any) -> bytes:
    record = {"kind": kind, **fields}
    _check(record)
    line = canonical.dumps_canonical(record) + b"\n"
    if len(line) > MAX_LINE_BYTES:
        raise JournalError("a journal record is too long")
    return line


def parse(line: bytes) -> dict[str, Any]:
    body = line[:-1] if line.endswith(b"\n") else line
    try:
        record = canonical.loads_strict(body, max_bytes=MAX_LINE_BYTES)
    except (canonical.JSONRejected, ValueError) as exc:
        raise JournalError("not a JSON record") from exc
    if not isinstance(record, dict):
        raise JournalError("not a JSON object")
    _check(record)
    return record


def _check(record: dict[str, Any]) -> None:
    kind = record.get("kind")
    if not isinstance(kind, str) or kind not in FIELDS:
        raise JournalError("unknown kind")
    checks = FIELDS[kind]
    if set(record) - {"kind"} != set(checks):
        raise JournalError(f"a {kind} record has the wrong fields")
    for name, check in checks.items():
        if not check(record[name]):
            raise JournalError(f"bad {name} in a {kind} record")


# --- the state the journal rebuilds -------------------------------------------------------------


@dataclass
class Attempt:
    ts: int
    req_hmac: str
    terminal: dict[str, Any] | None = None


@dataclass(frozen=True)
class New:
    """Send it: the key is new and the limit allows one more."""


@dataclass(frozen=True)
class Replay:
    """The key already finished: answer as it did, and send nothing."""

    terminal: dict[str, Any]


@dataclass(frozen=True)
class InProgress:
    """The key's send started and hasn't ended."""


@dataclass(frozen=True)
class KeyReused:
    """The key was used for another request."""


@dataclass(frozen=True)
class DailyLimit:
    retry_after_s: int


Decision = New | Replay | InProgress | KeyReused | DailyLimit


@dataclass
class Journal:
    """Keys and the times of recent attempts, rebuilt from the journal's records."""

    attempts: dict[str, Attempt] = field(default_factory=dict)
    recent: deque[int] = field(default_factory=deque)  # ``sending`` times, oldest first

    def apply(self, record: dict[str, Any]) -> None:
        kind, key = record["kind"], record["key"]
        if kind == "sending":
            self.attempts[key] = Attempt(record["ts"], record["req_hmac"])
            self.recent.append(record["ts"])
            return
        attempt = self.attempts.get(key)
        if attempt is not None and attempt.terminal is None:
            attempt.terminal = record

    def sent_24h(self, now_ms: int) -> int:
        self._expire(now_ms)
        return len(self.recent)

    def decide(self, key: str, req_hmac: str, now_ms: int, max_per_day: int) -> Decision:
        """J.2 rows 6 and 7, under the connector's lock."""
        attempt = self.attempts.get(key)
        if attempt is not None:
            if attempt.req_hmac != req_hmac:
                return KeyReused()
            if attempt.terminal is None:
                return InProgress()
            return Replay(attempt.terminal)
        self._expire(now_ms)
        if len(self.recent) >= max_per_day:
            leaves = self.recent[0] + DAY_MS - now_ms
            return DailyLimit(max(1, -(-leaves // 1000)))
        return New()

    def unfinished(self) -> list[str]:
        """Keys with a ``sending`` and no ending: recovery records each as ``unknown``."""
        return sorted(key for key, attempt in self.attempts.items() if attempt.terminal is None)

    def forget_old_keys(self, now_ms: int) -> None:
        """Keys are remembered for :data:`KEY_DAYS` days."""
        horizon = now_ms - KEY_DAYS * DAY_MS
        for key in [
            k for k, a in self.attempts.items() if a.ts < horizon and a.terminal is not None
        ]:
            del self.attempts[key]

    def _expire(self, now_ms: int) -> None:
        while self.recent and self.recent[0] <= now_ms - DAY_MS:
            self.recent.popleft()


def rebuild(lines: list[bytes]) -> tuple[Journal, int]:
    """The journal's state from its lines, and how many lines didn't parse (skipped)."""
    journal, bad = Journal(), 0
    for line in lines:
        try:
            journal.apply(parse(line))
        except JournalError:
            bad += 1
    return journal, bad


def answer(terminal: dict[str, Any], sent_24h: int) -> tuple[int, dict[str, Any]]:
    """The answer a finished key replays (J.5)."""
    kind = terminal["kind"]
    if kind == "sent":
        return 200, {"message_id": terminal["message_id"], "sent_24h": sent_24h}
    code = "smtp_outcome_unknown" if kind == "unknown" else terminal["code"]
    return 502, {"error": code, "code": code}
