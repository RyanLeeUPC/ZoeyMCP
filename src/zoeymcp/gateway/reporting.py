"""The reporter's choices: what to send the vault next, and how long to wait (M5 design J.3).

Pure, so each can be tested. :mod:`.reporter` does the I/O around them, in a loop:

1. ask the vault for its copy's head (:func:`parse_head` checks the answer);
2. read the ledger's stored lines after :func:`read_after`, at most 256;
3. ``POST`` :func:`pending`'s lines, the longest prefix whose body stays within
   :data:`REPORT_BATCH_BYTES` (:func:`batch`), and repeat while it sends something;
4. then wait as :func:`next_step` says.

The read starts at the copy's head itself, not after it, so a gateway whose records at the head
differ (its volume restored or lost) shows the vault a fork at once rather than once it has
written past the head; a gateway holding less than the copy sends from its oldest record, for the
same reason. A head the vault already holds isn't sent again.

Nothing in the approval path awaits the reporter, and a refusal or a failure only makes it wait.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Final, Literal, cast

from ..common import canonical, ledgerformat
from ..common.ledgerreport import MAX_LINES, STATES, Head, State, encode

# Under the vault's 1 MiB cap. A 4 KiB canonical line is at most 8 KiB as a JSON string, so one
# line always fits.
REPORT_BATCH_BYTES: Final = 960 * 1024
IDLE_SECONDS: Final = 60.0  # caught up: wait this long, or for an append
REFUSED_SECONDS: Final = 300.0  # the copy refuses until a restart: ask again this often
FIRST_BACKOFF: Final = 5.0
MAX_BACKOFF: Final = 300.0
LOG_EVERY: Final = 300.0  # ledger_report_failed at most this often
_FRAME: Final = len(encode([]))  # the body without lines
_SHA256: Final = re.compile(r"^sha256:[0-9a-f]{64}$")

Outcome = Literal["sent", "idle", "refused", "failed"]


class ReportingError(ValueError):
    """An answer from the vault that isn't a head. Never holds the answer."""


def parse_head(value: Any) -> Head:
    """The vault's answer to a ``GET`` or an accepted ``POST``: its copy's head."""
    if not isinstance(value, dict) or set(value) != {"head_seq", "head_hash", "state"}:
        raise ReportingError("not a head")
    seq, hash_, state = value["head_seq"], value["head_hash"], value["state"]
    if not isinstance(state, str) or state not in STATES:
        raise ReportingError("not a state")
    if seq is None and hash_ is None:
        return Head(None, None, cast(State, state))
    if type(seq) is not int or seq < 0:
        raise ReportingError("not a seq")
    if not isinstance(hash_, str) or not _SHA256.fullmatch(hash_):
        raise ReportingError("not a hash")
    return Head(seq, hash_, cast(State, state))


def read_after(head: Head, own_head_seq: int) -> int | None:
    """The seq to read the ledger's lines after, or None while the copy refuses reports.

    From the copy's head itself when this ledger reaches it; from the start when there is no copy
    yet, or when this ledger's own head (``own_head_seq``) is behind the copy's.
    """
    if head.state != "ok":
        return None
    if head.seq is None or own_head_seq < head.seq:
        return -1
    return head.seq - 1


def pending(
    head: Head,
    lines: Sequence[bytes],
    *,
    max_bytes: int = REPORT_BATCH_BYTES,
    max_lines: int = MAX_LINES,
) -> tuple[bytes, ...]:
    """The lines to report next, from ``lines`` read after :func:`read_after`: none when the
    copy refuses reports or holds them all. A first line that is the copy's head is dropped."""
    if head.state != "ok":
        return ()
    if lines and head.hash is not None and ledgerformat.line_hash(lines[0]) == head.hash:
        lines = lines[1:]
    return tuple(lines[: batch(lines, max_bytes=max_bytes, max_lines=max_lines)])


def batch(
    lines: Sequence[bytes], *, max_bytes: int = REPORT_BATCH_BYTES, max_lines: int = MAX_LINES
) -> int:
    """How many leading ``lines`` one report takes: at most ``max_lines``, with an encoded body
    (:func:`zoeymcp.common.ledgerreport.encode`) of at most ``max_bytes``."""
    size, count = _FRAME, 0
    for line in lines[:max_lines]:
        comma = 1 if count else 0
        size += len(canonical.encode_scalar(line.decode("utf-8")).encode("utf-8")) + comma
        if size > max_bytes:
            break
        count += 1
    return count


@dataclass(frozen=True)
class Wait:
    """How long to wait before the next round; ``wake``: an append ends the wait early."""

    seconds: float
    wake: bool


def next_step(outcome: Outcome, *, failures: int, jitter: float) -> Wait:
    """The wait after a round that ended with ``outcome``. ``failures``: rounds failed in a row,
    this one included; ``jitter``: a random number in [0, 1]."""
    if outcome == "sent":
        return Wait(0.0, False)
    if outcome == "idle":
        return Wait(IDLE_SECONDS, True)
    if outcome == "refused":
        return Wait(REFUSED_SECONDS, False)
    return Wait(backoff(failures, jitter), False)


def backoff(failures: int, jitter: float) -> float:
    """Doubling from :data:`FIRST_BACKOFF` up to :data:`MAX_BACKOFF`, each a random point in its
    upper half, so gateways restarted together don't retry together."""
    ceiling = min(MAX_BACKOFF, FIRST_BACKOFF * (1 << min(max(failures, 1) - 1, 16)))
    return ceiling * (1 + min(max(jitter, 0.0), 1.0)) / 2


def log_due(last: float | None, now: float) -> bool:
    """Whether a failure may be logged at ``now`` (seconds), the last logged at ``last``."""
    return last is None or now - last >= LOG_EVERY
